"""Deploy allow-listed SOC IDS policies to local Zeek and Suricata sensors.

Dashboard input is never rendered as sensor code.  Only policy identifiers known
to this agent are accepted, and generated files are atomically replaced after
the native sensor validates them.  A failed validation/reload restores the last
working files.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import tempfile
import threading
import platform
from pathlib import Path

logger = logging.getLogger('soc-agent.sensor-policy')


SURICATA_RULES = {
    'suricata-sqli': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC SQL Injection"; flow:established,to_server; http.uri; pcre:"/(union(?:%20|\\s)+select|select(?:%20|\\s)+.+from|or(?:%20|\\s)+1=1)/Ui"; classtype:web-application-attack; sid:9900001; rev:1;)',
    'suricata-xss': 'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC Cross-Site Scripting"; flow:established,to_server; http.uri; pcre:"/(<|%3c)(script|img|svg)|javascript:/Ui"; classtype:web-application-attack; sid:9900002; rev:1;)',
    'suricata-command-injection': r'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC Command Injection"; flow:established,to_server; http.uri; pcre:"/(\x3b|%3b|\||%7c|`|%60)(id|whoami|uname|cat|curl|wget)(?:%20|\s)/Ui"; classtype:web-application-attack; sid:9900003; rev:1;)',
    'suricata-exploit': r'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC RCE Exploit Indicator"; flow:established,to_server; http.uri; pcre:"/(cmd=|exec=|command=).*(powershell|cmd(?:\.exe)?|\/bin\/sh)/Ui"; classtype:attempted-admin; sid:9900004; rev:1;)',
    'suricata-exploit-kit': r'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SOC Exploit Kit Payload Pattern"; flow:established,to_server; http.uri; pcre:"/\.(?:jar|swf|hta)(?:\?|$)/Ui"; classtype:trojan-activity; sid:9900005; rev:1;)',
    'suricata-http-attacks': r'alert http $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC Suspicious HTTP Traversal"; flow:established,to_server; http.uri; pcre:"/(?:\.\.|%2e%2e)(?:\/|%2f|\\|%5c)/Ui"; classtype:web-application-attack; sid:9900006; rev:1;)',
    'suricata-malware': 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"SOC Suspicious Executable Download"; flow:established,to_client; fileext:"exe"; classtype:trojan-activity; sid:9900007; rev:1;)',
    'suricata-scan': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC TCP Port Scan"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 20, seconds 10; classtype:network-scan; sid:9900008; rev:1;)',
    'suricata-brute-force': 'alert tcp $EXTERNAL_NET any -> $HOME_NET [21,22,23,25,110,143,389,445,3389,5900] (msg:"SOC Authentication Brute Force"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 12, seconds 60; classtype:attempted-user; sid:9900009; rev:1;)',
    'suricata-ssh-brute-force': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"SOC SSH Brute Force"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 8, seconds 60; classtype:attempted-user; sid:9900010; rev:1;)',
    'suricata-rdp-brute-force': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"SOC RDP Brute Force"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 8, seconds 60; classtype:attempted-user; sid:9900011; rev:1;)',
    'suricata-smb-exploit': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SOC SMB Exploit Traffic"; flow:to_server,established; content:"|ff|SMB"; depth:4; classtype:attempted-admin; sid:9900012; rev:1;)',
    'suricata-ftp-attack': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"SOC FTP Brute Force"; flow:to_server,established; content:"USER "; nocase; threshold:type both, track by_src, count 10, seconds 60; classtype:attempted-user; sid:9900013; rev:1;)',
    'suricata-dos': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC TCP SYN Flood"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 150, seconds 10; classtype:attempted-dos; sid:9900014; rev:1;)',
    'suricata-ddos': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC Distributed Flood Indicator"; flags:S,12; flow:stateless; threshold:type both, track by_dst, count 1000, seconds 10; classtype:attempted-dos; sid:9900015; rev:1;)',
    'windivert-port-scan-guard': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC WinDivert Port Scan Guard"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 20, seconds 10; classtype:network-scan; sid:9900101; rev:1;)',
    'windivert-rdp-brute-force-guard': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 (msg:"SOC WinDivert RDP Brute Force Guard"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 8, seconds 60; classtype:attempted-user; sid:9900102; rev:1;)',
    'windivert-smb-exploit-guard': 'alert tcp $EXTERNAL_NET any -> $HOME_NET 445 (msg:"SOC WinDivert SMB Exploit Guard"; flow:to_server,established; content:"|ff|SMB"; depth:4; classtype:attempted-admin; sid:9900103; rev:1;)',
    'windivert-syn-flood-guard': 'alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"SOC WinDivert SYN Flood Guard"; flags:S,12; flow:stateless; threshold:type both, track by_src, count 150, seconds 10; classtype:attempted-dos; sid:9900104; rev:1;)',
    'windivert-c2-egress-guard': 'alert tcp $HOME_NET any -> $EXTERNAL_NET [4444,5555,6667,9001] (msg:"SOC WinDivert C2 Egress Guard"; flags:S,12; flow:stateless; classtype:trojan-activity; sid:9900105; rev:1;)',
}

ZEEK_IDS = {
    'zeek-notice', 'zeek-weird', 'zeek-dns-tunnel', 'zeek-c2',
    'zeek-beaconing', 'zeek-arp-spoofing', 'zeek-data-exfiltration',
    'zeek-tls', 'zeek-file',
}

DIRECT_WAF_PRESETS = (
    'suricata-sqli', 'suricata-xss', 'suricata-command-injection',
    'suricata-exploit', 'suricata-http-attacks',
)

WINDOWS_ONLY_PRESETS = {
    'windivert-port-scan-guard', 'windivert-rdp-brute-force-guard',
    'windivert-smb-exploit-guard', 'windivert-syn-flood-guard',
    'windivert-c2-egress-guard',
}


def _zeek_script(enabled):
    flags = {key.replace('zeek-', '').replace('-', '_'): key in enabled for key in ZEEK_IDS}
    zeek_bool = lambda value: 'T' if value else 'F'
    # ARP spoofing needs link-layer visibility and a site-specific MAC/IP baseline;
    # its flag is exported but no unsafe generic detector is invented here.
    return f'''# Generated by SOC Agent. Do not edit.
@load base/frameworks/notice
@load base/frameworks/files
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/ssl
@load base/protocols/ssh
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/smb
@load base/protocols/dhcp
@load policy/protocols/ssl/validate-certs

module SOC_IDS;

export {{
  redef enum Notice::Type += {{ DNS_Tunneling, Botnet_C2, Beaconing, Data_Exfiltration, Suspicious_TLS, Suspicious_File }};
}}

const dns_tunnel_enabled = {zeek_bool(flags['dns_tunnel'])} &redef;
const c2_enabled = {zeek_bool(flags['c2'])} &redef;
const beacon_enabled = {zeek_bool(flags['beaconing'])} &redef;
const exfil_enabled = {zeek_bool(flags['data_exfiltration'])} &redef;
const tls_enabled = {zeek_bool(flags['tls'])} &redef;
const file_enabled = {zeek_bool(flags['file'])} &redef;
const c2_ports: set[port] = {{ 4444/tcp, 5555/tcp, 6667/tcp, 9001/tcp }} &redef;

event DNS::log_dns(rec: DNS::Info)
  {{
  if ( dns_tunnel_enabled && rec?$query && |rec$query| >= 80 )
    NOTICE([$note=DNS_Tunneling, $msg=fmt("DNS tunnel indicator: long query %s", rec$query), $uid=rec$uid, $src=rec$id$orig_h, $dst=rec$id$resp_h]);
  }}

event Conn::log_conn(rec: Conn::Info)
  {{
  if ( c2_enabled && rec$id$resp_p in c2_ports )
    NOTICE([$note=Botnet_C2, $msg=fmt("C2 port connection to %s:%s", rec$id$resp_h, rec$id$resp_p), $uid=rec$uid, $src=rec$id$orig_h, $dst=rec$id$resp_h]);
  if ( beacon_enabled && rec?$duration && rec$duration > 1hr )
    NOTICE([$note=Beaconing, $msg="Long-lived connection beacon indicator", $uid=rec$uid, $src=rec$id$orig_h, $dst=rec$id$resp_h]);
  if ( exfil_enabled && rec?$orig_bytes && rec$orig_bytes >= 104857600 )
    NOTICE([$note=Data_Exfiltration, $msg=fmt("Large outbound transfer: %s bytes", rec$orig_bytes), $uid=rec$uid, $src=rec$id$orig_h, $dst=rec$id$resp_h]);
  }}

event SSL::log_ssl(rec: SSL::Info)
  {{
  if ( tls_enabled && rec?$validation_status && rec$validation_status != "ok" )
    NOTICE([$note=Suspicious_TLS, $msg=fmt("TLS validation status: %s", rec$validation_status), $uid=rec$uid]);
  }}

event Files::log_files(rec: Files::Info)
  {{
  if ( file_enabled && rec?$mime_type && (rec$mime_type == "application/x-dosexec" || rec$mime_type == "application/x-executable") )
    NOTICE([$note=Suspicious_File, $msg=fmt("Executable transfer: %s", rec$mime_type), $uid=rec$uid]);
  }}
'''


class SensorPolicyManager:
    def __init__(self, config):
        self.config = config
        if platform.system() == 'Windows':
            program_data = os.environ.get('ProgramData', r'C:\ProgramData')
            default_base = str(Path(program_data) / 'AJNAT' / 'state' / 'ids-policies')
        else:
            default_base = '/var/lib/soc-agent/ids-policies'
        base = Path(config.get('ids_policy_dir') or default_base)
        self.base = base
        self.suricata_config = Path(config.get('suricata_config') or '/etc/suricata/suricata.yaml')
        self.suricata_file = Path(config.get('suricata_soc_rules') or '/etc/suricata/rules/soc-managed.rules')
        self.suricata_executable = str(config.get('suricata_executable') or '')
        self.zeek_local = self._find_zeek_local(config.get('zeek_local_script'))
        self.zeek_file = Path(config.get('zeek_soc_script') or self.zeek_local.parent / 'soc-managed.zeek')
        self.state_file = Path(config.get('ids_policy_state') or base / 'state.json')
        self._lock = threading.Lock()

    @staticmethod
    def normalize(payload):
        policies = payload.get('policies', []) if isinstance(payload, dict) else []
        clean = []
        seen = set()
        current_platform = platform.system().strip().lower()
        current_platform = (
            'windows' if current_platform.startswith('win')
            else 'macos' if current_platform == 'darwin'
            else 'linux' if current_platform == 'linux'
            else current_platform
        )
        for item in policies[:64]:
            if not isinstance(item, dict):
                continue
            target_platform = str(item.get('targetPlatform') or 'all').strip().lower()
            if target_platform not in ('all', current_platform):
                continue
            preset_id = str(item.get('presetId', '')).strip()
            policy_id = preset_id or str(item.get('policyId', '')).strip()
            if not policy_id or policy_id in seen:
                continue
            if current_platform == 'windows' and (preset_id in ZEEK_IDS or str(item.get('sensor') or '').lower() == 'zeek'):
                continue
            if current_platform != 'windows' and preset_id in WINDOWS_ONLY_PRESETS:
                continue
            if preset_id not in SURICATA_RULES and preset_id not in ZEEK_IDS:
                if preset_id or str(item.get('sensor') or 'any').lower() == 'zeek':
                    continue
                if not any((item.get('attackPattern'), item.get('sourceIp'), item.get('destinationPort'))):
                    continue
            seen.add(policy_id)
            clean.append({
                'policyId': policy_id,
                'presetId': preset_id,
                'name': str(item.get('name') or 'Custom IDS policy')[:120],
                'sensor': str(item.get('sensor') or 'any').lower(),
                'mode': 'block' if item.get('mode') == 'block' else 'detect',
                'minimumSeverity': str(item.get('minimumSeverity') or 'medium').lower(),
                'attackPattern': str(item.get('attackPattern') or '')[:160],
                'protocol': str(item.get('protocol') or 'any').lower(),
                'sourceIp': str(item.get('sourceIp') or '').strip(),
                'destinationPort': item.get('destinationPort'),
                'targetPlatform': target_platform,
            })
        clean.sort(key=lambda value: value['policyId'])
        return clean

    @staticmethod
    def _custom_suricata_rules(item):
        """Compile structured dashboard fields without accepting raw rule code."""
        source = '$EXTERNAL_NET'
        if item.get('sourceIp'):
            try:
                source = str(ipaddress.ip_network(item['sourceIp'], strict=False))
            except ValueError:
                return []
        try:
            destination_port = int(item.get('destinationPort') or 0)
        except (TypeError, ValueError):
            return []
        if destination_port and not 1 <= destination_port <= 65535:
            return []

        protocol = item.get('protocol', 'any')
        protocol = {'https': 'tls', 'any': 'ip'}.get(protocol, protocol)
        if protocol not in ('ip', 'tcp', 'udp', 'http', 'tls', 'dns'):
            return []
        if destination_port and protocol == 'ip':
            protocol = 'tcp'
        port = str(destination_port) if destination_port else 'any'

        raw_patterns = [part.strip() for part in item.get('attackPattern', '').split('|') if part.strip()][:8]
        patterns = [re.sub(r'[^A-Za-z0-9 ._/@?&=%:+-]', '', value)[:80] for value in raw_patterns]
        patterns = [value for value in patterns if value]
        if not patterns and source == '$EXTERNAL_NET' and port == 'any':
            return []

        name = re.sub(r'[^A-Za-z0-9 ._:/+-]', '', item.get('name', 'Custom IDS policy'))[:80] or 'Custom IDS policy'
        action = 'drop' if item.get('mode') == 'block' else 'alert'
        base_id = 9910000 + int(hashlib.sha256(item['policyId'].encode()).hexdigest()[:8], 16) % 800000
        candidates = patterns or ['']
        rules = []
        for index, pattern_value in enumerate(candidates):
            options = [f'msg:"SOC Custom {name}"']
            if protocol in ('tcp', 'udp', 'http', 'tls', 'dns'):
                options.append('flow:to_server')
            if pattern_value:
                if protocol == 'http':
                    options.append('http.uri')
                options.extend([f'content:"{pattern_value}"', 'nocase'])
            options.extend(['classtype:misc-attack', f'sid:{base_id + index}', 'rev:1'])
            rules.append(f'{action} {protocol} {source} any -> $HOME_NET {port} (' + '; '.join(options) + ';)')
        return rules

    def apply(self, payload):
        policies = self.normalize(payload)
        direct_waf = self.config.get('waf_direct_block_enabled', True)
        revision_input = {'policies': policies, 'directWaf': direct_waf}
        revision = hashlib.sha256(json.dumps(revision_input, sort_keys=True).encode()).hexdigest()[:16]
        with self._lock:
            old = self._load_state()
            if old.get('revision') == revision:
                validation = old.get('validation') or {}
                enforced = not any('unavailable' in str(value).lower() for value in validation.values())
                if enforced:
                    return {'ok': True, 'changed': False, 'revision': revision, 'policies': len(policies), 'validation': validation}
                # A sensor binary/service may have been installed after the
                # previous sync. Retry validation/reload for the same policy
                # content instead of leaving deployment permanently failed.
            self.base.mkdir(parents=True, exist_ok=True)
            rules = ['# Generated by SOC Agent. Do not edit.']
            selected = {item['presetId']: item['mode'] for item in policies if item['presetId']}
            if direct_waf:
                # Explicit block mode must override the passive direct-WAF
                # default. Previously this branch emitted an alert and the
                # policy loop skipped the duplicate, silently losing "block".
                for preset in DIRECT_WAF_PRESETS:
                    if preset not in selected:
                        continue
                    rule = SURICATA_RULES[preset]
                    rules.append(('drop' + rule[5:]) if selected.get(preset) == 'block' else rule)
            for item in policies:
                rule = SURICATA_RULES.get(item['presetId'])
                if rule and (not direct_waf or item['presetId'] not in DIRECT_WAF_PRESETS):
                    # Inline IPS uses drop; passive IDS treats alert rules normally.
                    rules.append(('drop' + rule[5:]) if item['mode'] == 'block' else rule)
                elif not item['presetId']:
                    rules.extend(self._custom_suricata_rules(item))
            has_zeek = any(item['presetId'] in ZEEK_IDS for item in policies)
            files = {self.suricata_file: '\n'.join(rules) + '\n'}
            if platform.system() != 'Windows':
                files[self.zeek_file] = _zeek_script({item['presetId'] for item in policies})
            self._add_include_updates(files, include_zeek=platform.system() != 'Windows')
            backups = self._replace(files)
            try:
                validation = self._validate_and_reload(bool(rules[1:]), has_zeek)
            except Exception:
                self._restore(backups)
                raise
            state = {'revision': revision, 'policies': policies, 'validation': validation}
            self._atomic_write(self.state_file, json.dumps(state, indent=2) + '\n')
            enforced = not any('unavailable' in str(value).lower() for value in validation.values())
            return {'ok': enforced, 'changed': True, 'revision': revision, 'policies': len(policies), 'validation': validation}

    def _validate_and_reload(self, has_suricata, has_zeek):
        status = {}
        suricata = self.suricata_executable or shutil.which('suricata') or shutil.which('suricata.exe')
        if has_suricata and suricata:
            self._run([suricata, '-T', '-c', str(self.suricata_config)], 'Suricata validation')
            status['suricata'] = self._reload('suricata')
        elif has_suricata:
            status['suricata'] = 'rules-written; binary-unavailable'
        if has_zeek and shutil.which('zeek'):
            self._run(['zeek', '-b', str(self.zeek_file)], 'Zeek validation')
            status['zeek'] = self._reload('zeek')
        elif has_zeek:
            status['zeek'] = 'script-written; binary-unavailable'
        return status

    def _reload(self, service):
        if platform.system() == 'Windows' and service == 'suricata':
            proc = subprocess.run(
                [
                    'powershell.exe', '-NoProfile', '-NonInteractive', '-Command',
                    "$svc=Get-Service -Name 'Suricata' -ErrorAction Stop; "
                    "Restart-Service -InputObject $svc -Force -ErrorAction Stop; "
                    "$svc.WaitForStatus('Running',[TimeSpan]::FromSeconds(30))",
                ],
                capture_output=True, text=True, timeout=45, check=False,
            )
            if proc.returncode != 0:
                raise RuntimeError(f'{service} restart failed: {(proc.stderr or proc.stdout).strip()[:300]}')
            return 'restarted'
        if platform.system() == 'Darwin':
            if service == 'suricata':
                proc = subprocess.run(
                    ['pkill', '-USR2', 'suricata'],
                    capture_output=True, text=True, timeout=30, check=False,
                )
                if proc.returncode != 0:
                    raise RuntimeError(f'suricata reload failed: {(proc.stderr or proc.stdout or "process not running").strip()[:300]}')
                return 'reload-signalled'
            zeekctl = shutil.which('zeekctl')
            if not zeekctl:
                for candidate in ('/opt/homebrew/bin/zeekctl', '/usr/local/bin/zeekctl', '/opt/zeek/bin/zeekctl'):
                    if Path(candidate).exists():
                        zeekctl = candidate
                        break
            if zeekctl:
                proc = subprocess.run([zeekctl, 'deploy'], capture_output=True, text=True, timeout=90, check=False)
                if proc.returncode != 0:
                    raise RuntimeError(f'zeek deploy failed: {(proc.stderr or proc.stdout).strip()[:300]}')
                return 'deployed'
            return 'validated; service-manager-unavailable'
        if not shutil.which('systemctl'):
            return 'validated; systemctl-unavailable'
        proc = subprocess.run(['systemctl', 'reload', service], capture_output=True, text=True, timeout=30, check=False)
        if proc.returncode != 0:
            proc = subprocess.run(['systemctl', 'restart', service], capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f'{service} reload failed: {(proc.stderr or proc.stdout).strip()[:300]}')
        return 'reloaded'

    @staticmethod
    def _run(command, label):
        proc = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
        if proc.returncode != 0:
            raise RuntimeError(f'{label} failed: {(proc.stderr or proc.stdout).strip()[:500]}')

    def _replace(self, files):
        backups = {}
        try:
            for path, content in files.items():
                path.parent.mkdir(parents=True, exist_ok=True)
                backups[path] = path.read_bytes() if path.exists() else None
                self._atomic_write(path, content)
            return backups
        except Exception:
            self._restore(backups)
            raise

    @staticmethod
    def _find_zeek_local(configured):
        if configured:
            return Path(configured)
        candidates = (
            Path('/opt/zeek/share/zeek/site/local.zeek'),
            Path('/usr/local/zeek/share/zeek/site/local.zeek'),
            Path('/usr/share/zeek/site/local.zeek'),
        )
        return next((path for path in candidates if path.exists()), candidates[0])

    def _add_include_updates(self, files, include_zeek=True):
        if self.suricata_config.exists():
            yaml = self.suricata_config.read_text()
            if 'soc-managed.rules' not in yaml:
                updated, count = re.subn(
                    r'(?m)^(rule-files\s*:\s*)$',
                    rf'\1\n  - {self.suricata_file}',
                    yaml,
                    count=1,
                )
                if count != 1:
                    raise RuntimeError('Suricata rule-files section not found')
                files[self.suricata_config] = updated
        if not include_zeek:
            return
        if self.zeek_local.exists():
            local = self.zeek_local.read_text()
            include = f'@load {self.zeek_file}'
            if include not in local:
                files[self.zeek_local] = local.rstrip() + f'\n{include}\n'
        else:
            files[self.zeek_local] = f'@load {self.zeek_file}\n'

    @staticmethod
    def _restore(backups):
        for path, content in backups.items():
            if content is None:
                try:
                    path.unlink()
                except FileNotFoundError:
                    pass
            else:
                SensorPolicyManager._atomic_write(path, content)

    @staticmethod
    def _atomic_write(path, content):
        data = content.encode() if isinstance(content, str) else content
        fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
        try:
            with os.fdopen(fd, 'wb') as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary, 0o600)
            os.replace(temporary, path)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _load_state(self):
        try:
            return json.loads(self.state_file.read_text())
        except (OSError, ValueError):
            return {}
