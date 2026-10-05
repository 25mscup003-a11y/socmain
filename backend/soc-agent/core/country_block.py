"""Reconcile scoped country policies into dedicated, reversible host firewall rules."""
import base64
import hashlib
import ipaddress
import json
import logging
import os
import platform
import re
import socket
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse

from . import fw_backend
from .security import signed_headers
from .secure_transport import secure_request

logger = logging.getLogger('soc-agent.country-block')
TABLE = 'soc_country_block'
PF_ANCHOR = 'com.soc.agent/country-block'
WINDOWS_GROUP = 'AJNAT Country Block'
DAY = 86400


def management_addresses(config):
    url = config.get('server_url') or f'http://{config.get("server_ip", "localhost")}'
    hostname = urlparse(url).hostname
    if not hostname:
        raise ValueError('SOC server address is missing')
    addresses = {ipaddress.ip_address(row[4][0].split('%')[0])
                 for row in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)}
    if not addresses:
        raise ValueError('SOC server address could not be resolved')
    return addresses


def compile_networks(policy, exclusions=()):
    """Union overlapping policies; exclude SOC management IPs to keep recovery reachable."""
    groups = {key: [] for key in ('in4', 'in6', 'out4', 'out6')}
    rules = policy.get('rules')
    if not isinstance(rules, list) or len(rules) > 1000:
        raise ValueError('Invalid country policy')
    for rule in rules:
        code = rule.get('countryCode', '')
        direction = rule.get('direction')
        if not re.fullmatch(r'[A-Z]{2}', code) or direction not in ('inbound', 'outbound', 'both'):
            raise ValueError('Invalid country or direction')
        data = policy.get('networks', {}).get(code, {})
        for family in (4, 6):
            entries = data.get(f'ipv{family}')
            if not isinstance(entries, list) or not entries or len(entries) > 100000:
                raise ValueError(f'Missing IPv{family} ranges for {code}')
            networks = []
            for entry in entries:
                network = ipaddress.ip_network(entry, strict=False)
                if network.version != family or network.prefixlen == 0 or not network.is_global:
                    raise ValueError('Country feed contains a non-public network')
                networks.append(network)
            for prefix in (('in', 'out') if direction == 'both' else ('in',) if direction == 'inbound' else ('out',)):
                groups[f'{prefix}{family}'].extend(networks)
    for key, networks in groups.items():
        merged = list(ipaddress.collapse_addresses(networks))
        for address in exclusions:
            remaining = []
            for network in merged:
                if address.version == network.version and address in network:
                    host = ipaddress.ip_network(f'{address}/{address.max_prefixlen}')
                    remaining.extend(network.address_exclude(host))
                else:
                    remaining.append(network)
            merged = remaining
        groups[key] = [str(network) for network in merged]
    return groups


def nft_script(groups, exists):
    lines = [f'delete table inet {TABLE}'] if exists else []
    if not any(groups.values()):
        return '\n'.join(lines) + ('\n' if lines else '')
    lines.append(f'table inet {TABLE} {{')
    for key, networks in groups.items():
        lines.append(f' set {key} {{ type ipv{key[-1]}_addr; flags interval;')
        if networks:
            lines.append('  elements = { ' + ', '.join(networks) + ' };')
        lines.append(' }')
    for chain, prefix, address in (('input', 'in', 'saddr'), ('output', 'out', 'daddr')):
        lines.append(f' chain {chain} {{ type filter hook {chain} priority -20; policy accept;')
        for family, protocol in ((4, 'ip'), (6, 'ip6')):
            lines.append(f'  {protocol} {address} @{prefix}{family} counter drop')
        lines.append(' }')
    lines.append('}')
    return '\n'.join(lines) + '\n'


def pf_script(groups):
    lines = []
    for key, networks in groups.items():
        if not networks:
            continue
        lines.append(f'table <{key}> persist {{ ' + ', '.join(networks) + ' }')
        direction = 'in' if key.startswith('in') else 'out'
        source, destination = (f'<{key}>', 'any') if direction == 'in' else ('any', f'<{key}>')
        lines.append(f'block drop {direction} quick from {source} to {destination}')
    return '\n'.join(lines) + '\n'


def apply_firewall(groups):
    system = platform.system()
    run = fw_backend._run
    if system == 'Linux':
        if not fw_backend._have('nft'):
            if not any(groups.values()):
                return
            raise RuntimeError('Country blocking requires nftables on this Linux system')
        exists = run(['nft', 'list', 'table', 'inet', TABLE]).returncode == 0
        script = nft_script(groups, exists)
        if script:
            result = run(['nft', '-f', '-'], stdin=script, timeout=90)
            if result.returncode:
                raise RuntimeError(f'nftables country rules failed: {result.stderr[:250]}')
    elif system == 'Windows':
        # Build the replacement first; on failure remove only the staging group.
        # Existing IP, isolation and application block rules are never touched.
        fd, filename = tempfile.mkstemp(prefix='ajnat-country-', suffix='.json')
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(groups, handle)
            literal_path = filename.replace("'", "''")
            script = f"""$ErrorActionPreference = 'Stop'
$groups = Get-Content -LiteralPath '{literal_path}' -Raw | ConvertFrom-Json
if ((@($groups.in4).Count + @($groups.in6).Count + @($groups.out4).Count + @($groups.out6).Count) -gt 0) {{
  if (@(Get-NetFirewallProfile | Where-Object {{ -not $_.Enabled }}).Count -gt 0) {{
    throw 'Windows Defender Firewall must be enabled for all profiles'
  }}
}}
$generation = [guid]::NewGuid().ToString('N')
$created = @()
try {{
  foreach ($key in @('in4','in6','out4','out6')) {{
    $addresses = @($groups.$key)
    $direction = if ($key.StartsWith('in')) {{ 'Inbound' }} else {{ 'Outbound' }}
    for ($i = 0; $i -lt $addresses.Count; $i += 200) {{
      $end = [Math]::Min($i + 199, $addresses.Count - 1)
      $name = 'AJNAT-Country-' + $generation + '-' + $key + '-' + $i
      New-NetFirewallRule -Name $name -DisplayName $name -Group '{WINDOWS_GROUP}' -Direction $direction -Action Block -Enabled True -Profile Any -RemoteAddress $addresses[$i..$end] | Out-Null
      $created += $name
    }}
  }}
}} catch {{
  foreach ($name in $created) {{ Remove-NetFirewallRule -Name $name -ErrorAction SilentlyContinue }}
  throw
}}
Get-NetFirewallRule -ErrorAction Stop | Where-Object {{ $_.Group -eq '{WINDOWS_GROUP}' -and $_.Name -notin $created }} | Remove-NetFirewallRule
"""
            encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
            result = run(['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded], timeout=180)
            if result.returncode:
                raise RuntimeError(f'Windows country rules failed: {result.stderr[:250]}')
        finally:
            os.unlink(filename)
    elif system == 'Darwin':
        # The installed parent anchor is already connected to the system PF ruleset.
        if not fw_backend._mac_pf_update_rule('country-block-anchor', 'anchor "country-block"'):
            raise RuntimeError('Could not attach the country blocking PF anchor')
        result = run(['pfctl', '-a', PF_ANCHOR, '-f', '-'], stdin=pf_script(groups), timeout=90)
        if result.returncode:
            raise RuntimeError(f'macOS country rules failed: {result.stderr[:250]}')
        result = run(['pfctl', '-s', 'info'])
        if result.returncode or 'Status: Enabled' not in result.stdout:
            result = run(['pfctl', '-E'])
            if result.returncode:
                raise RuntimeError('macOS PF could not be enabled')
    elif any(groups.values()):
        raise RuntimeError('Country blocking supports Linux, Windows and macOS')


class CountryBlockEnforcer:
    def __init__(self, config):
        self.config = config
        if platform.system() == 'Windows':
            root = Path(os.environ.get('ProgramData', 'C:/ProgramData')) / 'AJNAT' / 'state'
        elif platform.system() == 'Darwin':
            root = Path('/Library/Application Support/AJNAT/state')
        else:
            root = Path('/var/lib/soc-agent')
        self.path = Path(config.get('country_block_state_path') or root / 'country-block.json')
        self.identity = hashlib.sha256(str(config.get('agent_key', '')).encode()).hexdigest()
        self._lock = threading.Lock()
        self._desired = None
        self._running = False
        self._last_success = 0
        self._last_attempt = 0
        self._status = {'supported': platform.system() in ('Linux', 'Windows', 'Darwin'),
                        'state': 'pending', 'desiredRevision': '', 'appliedRevision': '', 'error': '', 'rangeCount': 0}

    def status(self):
        with self._lock:
            return dict(self._status)

    def start(self):
        """Restore the last downloaded policy after restart, even while offline."""
        try:
            saved = json.loads(self.path.read_text(encoding='utf-8'))
            if saved.get('identity') == self.identity:
                self.submit(saved['policy'], cached=saved['policy'])
        except FileNotFoundError:
            pass
        except (OSError, ValueError, KeyError) as exc:
            logger.warning('Country policy cache could not be read: %s', exc)

    def submit(self, policy, cached=None):
        if not isinstance(policy, dict) or not re.fullmatch(r'[a-f0-9]{64}', str(policy.get('revision', ''))):
            return
        with self._lock:
            self._desired = policy
            self._status['desiredRevision'] = policy['revision']
            if self._running:
                return
            changed = self._status['appliedRevision'] != policy['revision']
            if not changed and time.time() - self._last_success < DAY:
                return
            if time.time() - self._last_attempt < 55:
                return
            self._running = True
            self._last_attempt = time.time()
            self._status.update(state='pending', error='')
        threading.Thread(target=self._sync, args=(policy, cached), daemon=True, name='country-block').start()

    def _download(self):
        url = self.config.get('server_url') or f'http://{self.config.get("server_ip", "localhost")}:{self.config.get("server_port", 5000)}'
        payload = {'agent_key': self.config.get('agent_key', '')}
        response = secure_request(self.config, 'POST', url.rstrip('/') + '/api/agent/country-block-policy',
                                  json=payload, headers=signed_headers(self.config, payload), timeout=180)
        if response.status_code != 200:
            raise RuntimeError('Country IP ranges could not be downloaded; existing blocks retained')
        return response.json()

    def _save(self, policy):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix='.country-block-', dir=str(self.path.parent))
        try:
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump({'identity': self.identity, 'policy': policy}, handle)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, self.path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _sync(self, desired, cached=None):
        try:
            policy = cached or (self._download() if desired.get('rules') else {**desired, 'networks': {}})
            if policy.get('revision') != desired['revision']:
                raise RuntimeError('Country policy changed during download; retrying on next heartbeat')
            groups = compile_networks(policy, management_addresses(self.config) if policy.get('rules') else ())
            with self._lock:
                if self._desired['revision'] != desired['revision']:
                    return
            apply_firewall(groups)
            # Retain the last successful snapshot if a replacement fails.
            self._save(policy)
            with self._lock:
                self._status.update(state='applied', appliedRevision=policy['revision'], error='',
                                    rangeCount=sum(len(value) for value in groups.values()))
                # Recheck feeds on the next heartbeat after restoring an offline cache.
                self._last_success = 0 if cached else time.time()
        except Exception as exc:
            logger.error('Country blocking synchronization failed: %s', exc)
            with self._lock:
                self._status.update(state='error', error=str(exc)[:500])
        finally:
            with self._lock:
                self._running = False
