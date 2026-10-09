"""
Network Collector — monitors active connections for suspicious IPs and ports.

FALSE POSITIVE FIX (2026-03-27):
  OLD: Any public IP on non-whitelist port → NET_SUSPICIOUS_CONNECTION (medium)
  NEW: VT results control the verdict:
    - VT clean (0 detections)   → skip alert (not suspicious)
    - VT not_found / no data    → low severity informational only (no alert by default)
    - VT suspicious (score 1-39) → medium alert
    - VT malicious (score ≥40)  → high/critical alert
    - VT unavailable + suspicious port → medium alert (fallback)
    - VT unavailable + normal port → skip (no alert)

CLASSIFICATION RULES:
  severity='critical' → VT malicious (score≥70) OR suspicious port + malicious VT
  severity='high'     → VT malicious (score 40-69) OR suspicious port
  severity='medium'   → VT suspicious (score 1-39) OR suspicious port + clean VT baseline
  severity='low'      → informational only (normal port, VT not_found)
  (suppressed)        → clean VT (detections=0, total>0) on non-suspicious port
"""

import time
import logging
import os
import platform
import threading
import socket
import struct
import ipaddress
import statistics
import hashlib
import json
import math
from urllib.parse import urlparse
from collections import Counter, deque
from datetime import datetime, timezone
from core.network_telemetry import PeerMetadataCache, linux_tcp_counters, normalized_ip, reverse_dns, socket_key

try:
    from core.geo_enrichment import lookup_ip
except Exception:  # pragma: no cover - optional in older agent bundles
    lookup_ip = None

try:
    from core.cache_poison_detector import DEFAULT_WATCH_DOMAINS
except Exception:  # pragma: no cover - optional in older agent bundles
    DEFAULT_WATCH_DOMAINS = [
        'google.com', 'microsoft.com', 'github.com',
        'cloudflare.com', 'amazon.com', 'apple.com',
    ]

logger = logging.getLogger('soc-agent.collector.network')
SYSTEM = platform.system()

POLL_INTERVAL   = 10    # seconds between connection scans
RESET_INTERVAL  = 3600  # seconds before resetting seen connections (1 hour)
DNS_QUERY_CACHE_SIZE = 200
VPN_INTERFACE_PREFIXES = ('tun', 'tap', 'wg', 'ppp', 'utun')
VPN_PROCESS_HINTS = (
    'protonvpn', 'proton-vpn', 'proton vpn', 'openvpn', 'wireguard',
    'wg-quick', 'strongswan', 'charon', 'ipsec', 'tailscale', 'zerotier',
    'nordvpn', 'expressvpn', 'surfshark', 'mullvad', 'anyconnect',
    'globalprotect', 'forticlient', 'openconnect',
)
VPN_PORTS = {1194, 51820, 500, 4500, 1701, 1723}

MFA_SSO_DOMAIN_HINTS = {
    'duosecurity.com': 'Duo MFA',
    'duo.com': 'Duo MFA',
    'okta.com': 'Okta MFA/SSO',
    'okta-emea.com': 'Okta MFA/SSO',
    'oktacdn.com': 'Okta MFA/SSO',
    'login.microsoftonline.com': 'Microsoft Entra MFA',
    'login.live.com': 'Microsoft Account MFA',
    'account.live.com': 'Microsoft Account MFA',
    'msauth.net': 'Microsoft Authenticator',
    'msftauth.net': 'Microsoft Authenticator',
    'accounts.google.com': 'Google MFA',
    'myaccount.google.com': 'Google MFA',
    'auth0.com': 'Auth0 MFA/SSO',
    'cloudflareaccess.com': 'Cloudflare Access',
    'onelogin.com': 'OneLogin MFA/SSO',
    'pingone.com': 'Ping Identity MFA/SSO',
    'pingidentity.com': 'Ping Identity MFA/SSO',
    'secureauth.com': 'SecureAuth MFA/SSO',
    'onelogin.com': 'OneLogin MFA/SSO',
    'jumpcloud.com': 'JumpCloud MFA/SSO',
    'lastpass.com': 'LastPass MFA',
    '1password.com': '1Password MFA',
    'hackerone.com': 'HackerOne Login',
    'proton.me': 'Proton Account MFA',
    'protonmail.com': 'Proton Account MFA',
}

# Known C2 / reverse-shell / RAT ports — always alert regardless of VT
SUSPICIOUS_PORTS = {
    4444, 4445, 4446, 5555, 6666, 6667, 6668, 6669,
    1337, 31337, 12345, 9999, 8888, 1234, 2222, 7777,
    1080, 9050, 9051,  # SOCKS / Tor
    4899,              # Radmin
    5900, 5901,        # VNC
}

# Ports that are routine business traffic — never alert unless VT says malicious
WHITELIST_PORTS = {
    80, 443, 53, 22, 25, 587, 465, 110, 995, 143, 993,
    3306, 5432, 27017, 6379,                  # databases
    5000, 8080, 8443, 3000, 3001, 4000,       # dev/API
    123, 389, 636, 88, 636,                   # NTP, LDAP, Kerberos
    1433, 1521,                               # MSSQL, Oracle
    11211, 9200, 9300,                        # Data and search services
    2049, 111,                                # NFS
    67, 68, 546, 547,                         # DHCP
}

# Minimum VT detections to trigger an alert (avoids 1-engine false positives)
MIN_VT_DETECTIONS_FOR_ALERT = 2

_PROCESS_IDENTITY_CACHE = {}
PROCESS_METADATA_CACHE_SECONDS = 300

# These values advance during observation even when the network is unchanged.
# Compare state, not elapsed time, traffic counters or OS enumeration order.
_OBSERVATION_FIELDS = frozenset({
    'timestamp', 'observed_at', 'observedAt', 'duration', 'duration_seconds',
    'bytes_sent', 'bytes_received', 'interval_seconds',
    'dns_query_count', 'query_type_counts',
    'start_time', 'end_time', 'first_seen', 'last_seen', 'firstSeen', 'lastSeen',
    'window_start', 'window_end', 'window_seconds',
    # Useful evidence, but unstable topology identifiers. Browsers and worker
    # processes recycle client ports/PIDs without changing the remote service.
    'pid', 'process_start_time', 'observed_local_port',
    'bytes_scope', 'bytes_source', 'socket_count', 'measured_socket_count',
})

_SOCKET_TELEMETRY_FIELDS = (
    'domain', 'domain_source', 'geo', 'bytes_sent', 'bytes_received',
    'bytes_scope', 'bytes_source', 'observed_at', 'start_time', 'end_time',
)


def _network_state_fingerprint(value):
    def canonical(item):
        if isinstance(item, dict):
            return {key: canonical(val) for key, val in item.items()
                    if key not in _OBSERVATION_FIELDS and not key.startswith('_')}
        if isinstance(item, (list, tuple)):
            return sorted((canonical(val) for val in item),
                          key=lambda val: json.dumps(val, sort_keys=True, separators=(',', ':')))
        return item

    encoded = json.dumps(canonical(value), sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(encoded.encode('utf-8')).hexdigest()


def _agent_server_endpoint(config) -> tuple:
    """Resolve the agent control-plane endpoint once for telemetry filtering."""
    raw = str(config.get('server_url') or '').strip()
    if raw:
        parsed = urlparse(raw if '://' in raw else f'//{raw}')
        host = str(parsed.hostname or '').split('%', 1)[0]
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)
    else:
        host = str(config.get('server_ip') or 'localhost').split('%', 1)[0]
        port = int(config.get('server_port') or 5000)
    addresses = {host} if host else set()
    try:
        addresses.update(
            str(item[4][0]).split('%', 1)[0]
            for item in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        )
    except (OSError, socket.gaierror):
        pass
    return addresses, int(port)


def _is_agent_control_plane_connection(connection, server_addresses, server_port,
                                       local_addresses=None, agent_pid=None) -> bool:
    """Exclude agent/API sockets that would otherwise create a feedback loop."""
    local_addresses = set(local_addresses or ())
    local_ip = str(connection.get('local_ip') or '').split('%', 1)[0]
    remote_ip = str(connection.get('remote_ip') or '').split('%', 1)[0]
    local_port = int(connection.get('local_port') or 0)
    remote_port = int(connection.get('remote_port') or 0)
    pid = connection.get('pid')

    # The agent's own HTTPS/Socket.IO connections are transport, not endpoint
    # activity. Excluding all sockets owned by this process also prevents an
    # alert delivery from recursively producing another network alert.
    if pid is not None and int(pid) == int(agent_pid if agent_pid is not None else os.getpid()):
        return True

    server_addresses = set(server_addresses or ())
    server_is_local = bool(server_addresses & local_addresses)
    if not server_is_local:
        try:
            server_is_local = any(ipaddress.ip_address(value).is_loopback for value in server_addresses)
        except ValueError:
            server_is_local = False

    # When server and agent share a host, psutil also sees the server half of
    # every agent request. Ignore that half on the configured API port.
    return bool(
        server_is_local
        and local_port == int(server_port)
        and (remote_ip in local_addresses or _is_loopback_bind(remote_ip))
    )


_SUMMARY_PROCESS_FIELDS = (
    'process_name', 'executable', 'username', 'parent_process',
    'process_hash', 'signature_status',
)


def _is_same_host_connection(connection, local_addresses) -> bool:
    """Return true for traffic whose two endpoints are this same machine."""
    local_addresses = set(local_addresses or ())
    local_ip = str(connection.get('local_ip') or '').split('%', 1)[0]
    remote_ip = str(connection.get('remote_ip') or '').split('%', 1)[0]

    def belongs_to_host(value):
        if value in local_addresses:
            return True
        try:
            return ipaddress.ip_address(value).is_loopback
        except ValueError:
            return False

    return bool(local_ip and remote_ip and belongs_to_host(local_ip) and belongs_to_host(remote_ip))


def _summary_connection_view(connection, listener_ports=None, local_addresses=None):
    """Build a stable flow identity for server-facing network summaries.

    Client source ports, PIDs and observation times are intentionally omitted:
    browsers and local services recycle them continuously without changing the
    endpoint's network topology. Inbound service ports remain significant.
    """
    if _is_same_host_connection(connection, local_addresses):
        return None
    protocol = str(connection.get('protocol') or 'tcp').lower()
    state = str(connection.get('state') or '').upper()
    # SYN/FIN/TIME_WAIT rows are short-lived kernel lifecycle details. The
    # stable ESTABLISHED appearance/disappearance already represents open and
    # close, so publishing every intermediate state only creates alert floods.
    if protocol == 'tcp' and state not in {'ESTABLISHED', 'CLOSE_WAIT', 'CLOSED'}:
        return None
    local_port = int(connection.get('local_port') or 0)
    remote_port = int(connection.get('remote_port') or 0)
    inbound = (protocol, local_port) in set(listener_ports or ())
    row = {
        'protocol': protocol,
        'state': state,
        'direction': 'inbound' if inbound else 'outbound',
        'local_ip': str(connection.get('local_ip') or '').split('%', 1)[0],
        'remote_ip': str(connection.get('remote_ip') or '').split('%', 1)[0],
        'local_port': local_port if inbound else 0,
        'observed_local_port': local_port,
        'remote_port': 0 if inbound else remote_port,
        'pid': connection.get('pid'),
        'ip_version': connection.get('ip_version'),
        'interface': connection.get('interface') or '',
    }
    for field in _SUMMARY_PROCESS_FIELDS:
        row[field] = connection.get(field) or ''
    for field in _SOCKET_TELEMETRY_FIELDS:
        if connection.get(field) is not None:
            row[field] = connection[field]
    return row


def _summary_connection_identity(connection, listener_ports=None, local_addresses=None):
    row = _summary_connection_view(connection, listener_ports, local_addresses)
    if row is None:
        return None
    row = {
        key: value for key, value in row.items()
        if key not in {'state', 'pid', 'observed_local_port', *_SOCKET_TELEMETRY_FIELDS}
    }
    return json.dumps(row, sort_keys=True, separators=(',', ':'))


def _summary_connection_inventory(connections, listeners=None, local_addresses=None):
    """Collapse parallel/ephemeral sockets into stable process/peer flows."""
    listener_ports = {
        (str(row.get('protocol') or 'tcp').lower(), int(row.get('local_port') or 0))
        for row in (listeners or [])
    }
    unique = {}
    for connection in connections or []:
        row = _summary_connection_view(connection, listener_ports, local_addresses)
        if row is None:
            continue
        key = _summary_connection_identity(connection, listener_ports, local_addresses)
        previous = unique.get(key)
        row['socket_count'] = 1 + (previous or {}).get('socket_count', 0)
        row['measured_socket_count'] = int(any(field in row for field in ('bytes_sent', 'bytes_received'))) + (previous or {}).get('measured_socket_count', 0)
        if previous:
            for field in ('bytes_sent', 'bytes_received'):
                if field in row or field in previous:
                    row[field] = row.get(field, 0) + previous.get(field, 0)
        if row['measured_socket_count']:
            row['bytes_scope'] = 'active_sockets'
        unique[key] = row
    return [unique[key] for key in sorted(unique)]


def _summary_listener_inventory(listeners):
    """Keep service/process changes while ignoring PID and observation churn."""
    fields = (
        'protocol', 'state', 'local_ip', 'local_port', 'pid', 'ip_version', 'interface',
        *_SUMMARY_PROCESS_FIELDS,
    )
    unique = {}
    for listener in listeners or []:
        row = {field: listener.get(field) for field in fields}
        key = _network_state_fingerprint(row)
        unique[key] = row
    return [unique[key] for key in sorted(unique)]


def _sha256_file(path: str) -> str:
    """Hash an executable once per mtime/size without adding polling overhead."""
    if not path or not os.path.isfile(path):
        return ''
    try:
        stat = os.stat(path)
        key = (path, int(stat.st_mtime_ns), int(stat.st_size))
        cached = _PROCESS_IDENTITY_CACHE.get(key)
        if cached:
            return cached
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(block)
        value = digest.hexdigest()
        if len(_PROCESS_IDENTITY_CACHE) > 2048:
            _PROCESS_IDENTITY_CACHE.clear()
        _PROCESS_IDENTITY_CACHE[key] = value
        return value
    except (OSError, PermissionError):
        return ''


def _interface_by_ip(psutil_module) -> dict:
    mapping = {}
    try:
        for name, rows in psutil_module.net_if_addrs().items():
            for row in rows:
                address = str(getattr(row, 'address', '') or '').split('%', 1)[0]
                if address:
                    mapping[address] = name
    except Exception:
        pass
    return mapping


def beacon_interval_metrics(timestamps) -> dict:
    """Return stable timing metrics without treating periodicity as malice."""
    ordered = sorted(float(value) for value in timestamps)
    intervals = [ordered[index] - ordered[index - 1] for index in range(1, len(ordered))]
    intervals = [value for value in intervals if value > 0]
    if not intervals:
        return {
            'count': len(ordered), 'average_interval': 0.0, 'median_interval': 0.0,
            'jitter_seconds': 0.0, 'interval_consistency': 0.0, 'periodicity_score': 0.0,
            'observation_seconds': 0.0,
        }
    average = statistics.fmean(intervals)
    median = statistics.median(intervals)
    jitter = statistics.pstdev(intervals) if len(intervals) > 1 else 0.0
    coefficient = jitter / max(average, 0.001)
    consistency = max(0.0, min(100.0, (1.0 - coefficient) * 100.0))
    return {
        'count': len(ordered),
        'average_interval': round(average, 3),
        'median_interval': round(median, 3),
        'jitter_seconds': round(jitter, 3),
        'interval_consistency': round(consistency, 2),
        'periodicity_score': round(consistency * 0.25, 2),
        'observation_seconds': round(max(ordered[-1] - ordered[0], 0.0), 3),
    }


def dns_anomaly_score(domain: str, query_count: int = 0, nxdomain_count: int = 0) -> dict:
    """Score DNS behavior using frequency, failures and name structure together."""
    value = str(domain or '').lower().rstrip('.')
    first_label = value.split('.', 1)[0]
    entropy = 0.0
    if first_label:
        counts = {char: first_label.count(char) for char in set(first_label)}
        entropy = -sum((count / len(first_label)) * math.log2(count / len(first_label)) for count in counts.values())
    score = 0
    reasons = []
    if query_count >= 50:
        score += 25
        reasons.append(f'high query frequency ({query_count}/minute)')
    failure_ratio = nxdomain_count / max(query_count, 1)
    if nxdomain_count >= 10 and failure_ratio >= 0.4:
        score += 30
        reasons.append(f'high NXDOMAIN ratio ({failure_ratio:.0%})')
    if len(first_label) >= 24 and entropy >= 3.5:
        score += 25
        reasons.append(f'high-entropy DNS label ({entropy:.2f})')
    if value.count('.') >= 4 and len(value) >= 40:
        score += 15
        reasons.append('deep, long subdomain structure')
    if len(first_label) >= 18 and sum(ch.isdigit() for ch in first_label) >= 6:
        score += 15
        reasons.append('randomized alphanumeric label')
    return {'risk_score': min(100, score), 'reasons': reasons, 'entropy': round(entropy, 3), 'failure_ratio': round(failure_ratio, 3)}


def _is_private(ip: str) -> bool:
    return ip.startswith((
        '127.', '10.', '192.168.',
        '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.',
        '172.24.', '172.25.', '172.26.', '172.27.',
        '172.28.', '172.29.', '172.30.', '172.31.',
        '::1', 'fe80:',
    ))


def _local_source_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.2)
        sock.connect(('8.8.8.8', 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return ''


def _local_username():
    try:
        import psutil
        users = [u.name for u in psutil.users() if getattr(u, 'name', '')]
        for name in users:
            if name and name not in ('root', 'SYSTEM', 'LocalSystem'):
                return name
        if users:
            return users[0]
    except Exception:
        pass
    return os.environ.get('SUDO_USER') or os.environ.get('USER') or os.environ.get('USERNAME') or ''


def _empty_process_identity():
    return {
        'process_name': '', 'executable': '', 'username': '',
        'command_line': '', 'parent_pid': None, 'parent_process': '',
        'process_hash': '', 'signature_status': 'unknown',
        'process_start_time': None,
    }


def _process_identity(psutil_module, pid, cache=None, now=None):
    """Resolve process evidence once and reuse it across socket scans.

    Entries expire so a recycled PID cannot retain stale identity forever.
    """
    if not pid:
        return _empty_process_identity()
    cache = cache if cache is not None else {}
    now = time.monotonic() if now is None else now
    cached = cache.get(pid)
    if cached and cached.get('checked_at') == now:
        return cached['value']
    value = _empty_process_identity()
    try:
        proc = psutil_module.Process(pid)
        def read(callback, default=''):
            try:
                return callback()
            except (psutil_module.NoSuchProcess, psutil_module.AccessDenied, OSError):
                return default
        started = read(proc.create_time, None)
        if cached and started is not None and started == cached['value'].get('process_start_time') and now < cached.get('expires_at', 0):
            cached['checked_at'] = now
            return cached['value']
        # Access to one protected field must not discard an accessible user/name.
        value.update({
            'process_name': read(proc.name) or '',
            'username': read(proc.username) or '',
            'executable': read(proc.exe) or '',
            'command_line': ' '.join(read(proc.cmdline, []) or [])[:2000],
            'parent_pid': read(proc.ppid, None),
            'process_start_time': started,
        })
        parent = read(proc.parent, None)
        value['parent_process'] = read(parent.name) if parent else ''
        value['process_hash'] = _sha256_file(value['executable'])
    except (psutil_module.NoSuchProcess, psutil_module.AccessDenied, OSError):
        pass
    cache[pid] = {
        'value': value,
        'checked_at': now,
        'expires_at': now + (PROCESS_METADATA_CACHE_SECONDS if value['username'] else 10),
    }
    if len(cache) > 4096:
        expired = [key for key, item in cache.items() if now >= item.get('expires_at', 0)]
        for key in expired:
            cache.pop(key, None)
    return value


def _get_connections(socket_rows=None, process_cache=None, psutil_module=None, interface_map=None):
    try:
        if psutil_module is None:
            import psutil as psutil_module
        conns = []
        process_cache = process_cache if process_cache is not None else {}
        interface_map = interface_map if interface_map is not None else _interface_by_ip(psutil_module)
        rows = socket_rows if socket_rows is not None else psutil_module.net_connections(kind='inet')
        now = time.monotonic()
        for c in rows:
            protocol = 'udp' if c.type == socket.SOCK_DGRAM else 'tcp'
            # Connected UDP sockets have no ESTABLISHED state. Retain every
            # remote peer and every TCP lifecycle state exposed by the OS.
            if c.raddr:
                process = _process_identity(psutil_module, c.pid, process_cache, now)
                local_ip = c.laddr.ip if c.laddr else ''
                conns.append({
                    'local_ip':    local_ip,
                    'local_port':  c.laddr.port if c.laddr else 0,
                    'remote_ip':   c.raddr.ip,
                    'remote_port': c.raddr.port,
                    'pid':         c.pid,
                    'protocol':    protocol,
                    'state':       str(c.status or ('ACTIVE' if protocol == 'udp' else 'UNKNOWN')).upper(),
                    'ip_version':  6 if c.family == socket.AF_INET6 else 4,
                    'interface':   interface_map.get(str(local_ip).split('%', 1)[0], ''),
                    **process,
                })
        return conns
    except Exception as e:
        logger.debug('Connection list error: %s', e)
        return []


def _get_listeners(socket_rows=None, process_cache=None, psutil_module=None, interface_map=None):
    try:
        if psutil_module is None:
            import psutil as psutil_module
        listeners = []
        process_cache = process_cache if process_cache is not None else {}
        interface_map = interface_map if interface_map is not None else _interface_by_ip(psutil_module)
        rows = socket_rows if socket_rows is not None else psutil_module.net_connections(kind='inet')
        now = time.monotonic()
        for c in rows:
            protocol = 'udp' if c.type == socket.SOCK_DGRAM else 'tcp'
            is_listener = c.status == 'LISTEN' if protocol == 'tcp' else bool(c.laddr and not c.raddr)
            if not is_listener or not c.laddr:
                continue
            process = _process_identity(psutil_module, c.pid, process_cache, now)
            local_ip = c.laddr.ip if c.laddr else ''
            listeners.append({
                'local_ip': local_ip,
                'local_port': c.laddr.port if c.laddr else 0,
                'remote_ip': '',
                'remote_port': 0,
                'pid': c.pid,
                'protocol': protocol,
                'state': 'LISTEN',
                'ip_version': 6 if c.family == socket.AF_INET6 else 4,
                'interface': interface_map.get(str(local_ip).split('%', 1)[0], ''),
                'listener': True,
                **process,
            })
        return listeners
    except Exception as e:
        logger.debug('Listener list error: %s', e)
        return []


def _is_loopback_bind(value: str) -> bool:
    try:
        return ipaddress.ip_address((value or '').split('%', 1)[0]).is_loopback
    except ValueError:
        return False


def _port_tokens(values) -> set:
    tokens = set()
    for value in values or []:
        text = str(value).strip().lower()
        if not text:
            continue
        if text.isdigit():
            tokens.add(f'any/{int(text)}')
            continue
        if '/' in text:
            protocol, port = text.split('/', 1)
            if protocol in ('tcp', 'udp') and port.isdigit():
                tokens.add(f'{protocol}/{int(port)}')
    return tokens


def evaluate_port_policy(listener: dict, config) -> dict:
    """Return a side-effect-free policy verdict for one local listener."""
    if not config.get('port_policy_enabled', True):
        return {'violation': False, 'reason': 'policy_disabled', 'exposed': False}
    local_ip = str(listener.get('local_ip') or '')
    exposed = not _is_loopback_bind(local_ip)
    if config.get('port_policy_exempt_loopback', True) and not exposed:
        return {'violation': False, 'reason': 'loopback_exempt', 'exposed': False}

    allowed = _port_tokens(config.get('allowed_listening_ports', []))
    # No allowlist means safe inventory mode, never "deny everything".
    if not allowed:
        return {'violation': False, 'reason': 'allowlist_not_configured', 'exposed': exposed}

    protocol = str(listener.get('protocol') or 'tcp').lower()
    port = int(listener.get('local_port') or 0)
    token = f'{protocol}/{port}'
    if token not in allowed and f'any/{port}' not in allowed:
        return {'violation': True, 'reason': 'port_not_allowed', 'exposed': exposed}

    restrictions = config.get('allowed_port_processes', {}) or {}
    expected = restrictions.get(token, restrictions.get(str(port), []))
    if isinstance(expected, str):
        expected = [expected]
    actual = str(listener.get('process_name') or '').lower()
    if expected and actual not in {str(name).lower() for name in expected}:
        return {'violation': True, 'reason': 'process_not_allowed', 'exposed': exposed}
    return {'violation': False, 'reason': 'allowed', 'exposed': exposed}


def _get_vpn_state(connections=None) -> dict:
    state = {
        'active': False,
        'interfaces': [],
        'processes': [],
        'ports': [],
        'remote_peers': [],
        'username': '',
        'method': '',
        'source_ip': '',
    }
    connections = connections or []
    try:
        import psutil
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, iface in stats.items():
            lname = name.lower()
            if not iface.isup:
                continue
            if lname.startswith(VPN_INTERFACE_PREFIXES) or any(h in lname for h in ('vpn', 'proton', 'wireguard')):
                ips = []
                for addr in addrs.get(name, []):
                    value = getattr(addr, 'address', '') or ''
                    if value and not value.startswith(('fe80:', '127.')):
                        ips.append(value)
                state['interfaces'].append({'name': name, 'addresses': ips[:4]})
                if ips and not state['source_ip']:
                    state['source_ip'] = ips[0]

        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username']):
            try:
                name = proc.info.get('name') or ''
                cmdline = ' '.join(proc.info.get('cmdline') or [])
                text = f'{name} {cmdline}'.lower()
                if any(h in text for h in VPN_PROCESS_HINTS):
                    item = {
                        'pid': proc.info.get('pid'),
                        'name': name,
                        'username': proc.info.get('username') or '',
                    }
                    state['processes'].append(item)
                    if item['username'] and not state['username']:
                        state['username'] = item['username']
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception as e:
        logger.debug('VPN state detection error: %s', e)

    for conn in connections:
        port = int(conn.get('remote_port') or 0)
        if port in VPN_PORTS:
            if port not in state['ports']:
                state['ports'].append(port)
            peer = conn.get('remote_ip')
            if peer and peer not in state['remote_peers']:
                state['remote_peers'].append(peer)

    process_names = ' '.join(p.get('name', '') for p in state['processes']).lower()
    interface_names = ' '.join(i.get('name', '') for i in state['interfaces']).lower()
    if 'proton' in process_names or 'proton' in interface_names:
        state['method'] = 'Proton VPN'
    elif 'wireguard' in process_names or 'wg' in interface_names:
        state['method'] = 'WireGuard VPN'
    elif 'openvpn' in process_names:
        state['method'] = 'OpenVPN'
    elif state['interfaces'] or (state['ports'] and state['processes']):
        state['method'] = 'VPN'
    # An installed/running VPN client is not proof that traffic is tunnelling.
    # Require a tunnel interface, or both a VPN process and VPN-port evidence.
    state['active'] = bool(state['interfaces'] or (state['ports'] and state['processes']))
    return state


def _dns_resolvers():
    resolvers = []
    search_domains = []
    try:
        with open('/etc/resolv.conf', 'r', encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) > 1:
                        resolvers.append(parts[1])
                elif line.startswith(('search ', 'domain ')):
                    search_domains.extend(line.split()[1:])
    except Exception:
        pass
    return resolvers[:5], search_domains[:10]


def _reverse_dns(ip: str) -> str:
    if not ip or _is_private(ip):
        return ''
    try:
        host = socket.gethostbyaddr(ip)[0]
        return host.rstrip('.')
    except Exception:
        return ''


def _geo_for_ip(ip: str) -> dict:
    if not ip or _is_private(ip) or lookup_ip is None:
        return {}
    try:
        geo = lookup_ip(ip) or {}
        return {
            'country': geo.get('country') or '',
            'countryCode': geo.get('countryCode') or '',
            'city': geo.get('city') or '',
            'isp': geo.get('isp') or '',
        }
    except Exception:
        return {}


def _read_dns_name(payload: bytes, offset: int, depth: int = 0):
    if depth > 8:
        return '', offset
    labels = []
    original_offset = offset
    jumped = False
    try:
        while offset < len(payload):
            length = payload[offset]
            offset += 1
            if length == 0:
                break
            if length & 0xC0:
                if offset >= len(payload):
                    return '', offset
                pointer = ((length & 0x3F) << 8) | payload[offset]
                offset += 1
                pointed, _ = _read_dns_name(payload, pointer, depth + 1)
                if pointed:
                    labels.extend(pointed.split('.'))
                jumped = True
                break
            if length > 63 or offset + length > len(payload):
                return '', offset
            label = payload[offset:offset + length].decode('ascii', errors='ignore')
            if not label:
                return '', offset
            labels.append(label)
            offset += length
        name = '.'.join(labels).strip('.').lower()
        return name, (offset if not jumped else original_offset + 2)
    except Exception:
        return '', offset


def _parse_dns_packet(payload: bytes) -> dict:
    result = {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
    if len(payload) < 13:
        return result
    try:
        flags = struct.unpack('!H', payload[2:4])[0]
        qdcount = struct.unpack('!H', payload[4:6])[0]
        ancount = struct.unpack('!H', payload[6:8])[0]
        is_response = bool(flags & 0x8000)
        result['is_response'] = is_response
        result['response_code'] = flags & 0x000F
        offset = 12
        query_names = []
        for _ in range(max(0, qdcount)):
            name, offset = _read_dns_name(payload, offset)
            if name and '.' in name:
                query_names.append(name)
            if offset + 4 <= len(payload):
                qtype = struct.unpack('!H', payload[offset:offset + 2])[0]
                result['query_types'].append({1: 'A', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 65: 'HTTPS'}.get(qtype, str(qtype)))
            offset += 4  # qtype + qclass
            if offset > len(payload):
                return result
        result['queries'] = list(dict.fromkeys(query_names))
        if not is_response:
            return result
        for _ in range(max(0, ancount)):
            name, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype, rclass, _ttl, rdlen = struct.unpack('!HHIH', payload[offset:offset + 10])
            offset += 10
            rdata = payload[offset:offset + rdlen]
            offset += rdlen
            if rclass != 1 or not name:
                continue
            ip = ''
            if rtype == 1 and len(rdata) == 4:
                ip = socket.inet_ntop(socket.AF_INET, rdata)
            elif rtype == 28 and len(rdata) == 16:
                ip = socket.inet_ntop(socket.AF_INET6, rdata)
            if ip:
                result['answers'].setdefault(name, [])
                if ip not in result['answers'][name]:
                    result['answers'][name].append(ip)
        return result
    except Exception:
        return result


def _extract_dns_from_packet(packet: bytes) -> dict:
    try:
        if len(packet) < 42:
            return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
        eth_type = struct.unpack('!H', packet[12:14])[0]
        ip_start = 14
        if eth_type == 0x0800:  # IPv4
            ihl = (packet[ip_start] & 0x0F) * 4
            protocol = packet[ip_start + 9]
            if protocol != 17:  # UDP
                return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
            udp_start = ip_start + ihl
        elif eth_type == 0x86DD:  # IPv6
            if len(packet) < ip_start + 48:
                return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
            next_header = packet[ip_start + 6]
            if next_header != 17:  # UDP; extension headers intentionally skipped
                return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
            udp_start = ip_start + 40
        else:
            return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
        if len(packet) < udp_start + 8:
            return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
        src_port, dst_port = struct.unpack('!HH', packet[udp_start:udp_start + 4])
        if dst_port != 53 and src_port != 53:
            return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}
        return _parse_dns_packet(packet[udp_start + 8:])
    except Exception:
        return {'queries': [], 'query_types': [], 'answers': {}, 'is_response': False, 'response_code': 0}


def _is_display_dns_domain(domain: str) -> bool:
    value = (domain or '').strip().lower()
    if not value or value in {'-', 'dns resolver'}:
        return False
    if value.endswith('.in-addr.arpa') or value.endswith('.ip6.arpa'):
        return False
    if value in {'dns.google'}:
        return False
    if value.endswith('.1e100.net') or value.endswith('.cloudfront.net'):
        return False
    if value.startswith(('ec2-', 'ip-', 'host-')):
        return False
    if '.compute' in value and value.endswith('.amazonaws.com'):
        return False
    return '.' in value


def _mfa_sso_hits(domains) -> list:
    hits = []
    seen = set()
    for domain in domains or []:
      value = (domain or '').strip().lower().rstrip('.')
      if not value:
          continue
      for suffix, provider in MFA_SSO_DOMAIN_HINTS.items():
          if value == suffix or value.endswith(f'.{suffix}'):
              key = (value, provider)
              if key not in seen:
                  hits.append({'domain': value, 'provider': provider})
                  seen.add(key)
              break
    return hits


def _peer_summary(conn: dict, include_geo: bool = True) -> dict:
    remote_ip = conn.get('remote_ip') or ''
    item = {
        'remote_ip': remote_ip,
        'remote_port': conn.get('remote_port'),
        'local_ip': conn.get('local_ip'),
        'local_port': conn.get('local_port'),
        'pid': conn.get('pid'),
    }
    host = conn.get('domain') or ''
    if host:
        item['host'] = host
        item['domain'] = host
    if include_geo:
        geo = conn.get('geo') or {}
        if geo:
            item.update(geo)
    return item


def _lookup_network_peer(ip):
    result = {}
    geo = {key: value for key, value in _geo_for_ip(ip).items() if value}
    if geo:
        result['geo'] = geo
    host = reverse_dns(ip)
    if host:
        result.update(domain=host, domain_source='reverse_dns')
    return result


class NetworkCollector:
    def __init__(self, sender, vt_scanner=None, config=None):
        self._sender    = sender
        self._vt        = vt_scanner
        self._config    = config or {}
        self._firewall  = None
        self._port_policy_seen = set()
        self._seen: set = set()
        self._last_reset = time.time()
        self._summary_fingerprints = {}
        self._summary_last_sent = {}
        self._last_observed_summary = None
        self._pending_closed_connections = {}
        self._pending_io_delta = {'interval_seconds': 0, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': {}}
        self._last_usage_emit = 0
        self._last_vpn_emit = 0
        self._last_mfa_portal_emit = 0
        self._dns_queries = deque(maxlen=DNS_QUERY_CACHE_SIZE)
        self._dns_query_interval_count = 0
        self._dns_query_types = Counter()
        # Process/DNS attribution is an identity event, not a polling sample.
        # Keep the identities for this agent runtime so a temporarily missing
        # socket (or a rotating CDN answer) cannot recreate the same event on
        # the next scan.  The bounded dict prevents unbounded growth on hosts
        # that run for months.
        self._dns_process_seen = {}
        self._dns_lock = threading.Lock()
        self._dns_behavior = {}
        self._dns_anomaly_alerted = {}
        self._connection_beacons = {}
        self._dns_beacons = {}
        self._previous_connection_instances = set()
        self._beacon_baseline_done = False
        self._beacon_alerted = {}
        self._beacon_lock = threading.Lock()
        self._active_connections = {}
        self._recent_connection_starts = deque(maxlen=4096)
        self._last_scan_alert = 0
        self._last_lateral_alert = 0
        self._last_transfer_alert = 0
        self._last_io_snapshot = None
        self._transfer_baseline = deque(maxlen=120)
        self._process_metadata_cache = {}
        self._peer_metadata = PeerMetadataCache(_lookup_network_peer)
        self._server_addresses, self._server_port = _agent_server_endpoint(self._config)
        self._thread    = threading.Thread(target=self._loop, daemon=True, name='net-monitor')
        self._dns_thread = threading.Thread(target=self._dns_sniffer_loop, daemon=True, name='dns-query-sniffer')

    def set_firewall(self, firewall):
        self._firewall = firewall
        # A scan can happen while the collector thread starts and before the
        # firewall module is wired. Re-evaluate those listeners immediately on
        # the next pass so block mode cannot silently degrade to audit mode.
        self._port_policy_seen.clear()

    def start(self):
        self._thread.start()
        if SYSTEM == 'Linux':
            self._dns_thread.start()

    def _remember_dns_query(self, domain: str, ips=None, query_type=''):
        if not domain:
            return
        ips = [ip for ip in (ips or []) if ip]
        with self._dns_lock:
            if not ips:
                self._dns_query_interval_count += 1
                if query_type:
                    self._dns_query_types[str(query_type).upper()] += 1
            if self._dns_queries and self._dns_queries[-1].get('domain') == domain and not ips:
                return
            self._dns_queries.append({'domain': domain, 'ips': ips, 'query_type': query_type, 'ts': time.time()})

    def _observe_dns_anomaly(self, domain, response_code=0, query_type=''):
        if self._config.get('dns_anomaly_detection_enabled', True) is False:
            return
        domain = str(domain or '').lower().rstrip('.')
        if not _is_display_dns_domain(domain):
            return
        now = time.time()
        state = self._dns_behavior.setdefault(domain, {'queries': deque(maxlen=512), 'nxdomain': deque(maxlen=512)})
        state['queries'].append(now)
        if int(response_code or 0) == 3:
            state['nxdomain'].append(now)
        cutoff = now - 60
        for values in state.values():
            while values and values[0] < cutoff:
                values.popleft()
        assessment = dns_anomaly_score(domain, len(state['queries']), len(state['nxdomain']))
        threshold = max(25, int(self._cfg_float('dns_anomaly_threshold', 45)))
        cooldown = max(60, int(self._cfg_float('dns_anomaly_cooldown_seconds', 1800)))
        if assessment['risk_score'] < threshold or now - self._dns_anomaly_alerted.get(domain, 0) < cooldown:
            return
        self._dns_anomaly_alerted[domain] = now
        score = assessment['risk_score']
        self._sender.enqueue({
            'rule_id': 'NET_DNS_ANOMALY', 'capabilityId': 3, 'capabilityIds': [3, 9],
            'category': 'network', 'subCategory': 'dns-anomaly', 'eventType': 'Suspicious DNS Activity',
            'severity': 'critical' if score >= 81 else 'high' if score >= 61 else 'medium',
            'risk_score': score, 'confidence_score': min(100, 50 + len(assessment['reasons']) * 15),
            'description': f'DNS anomaly for {domain}: {"; ".join(assessment["reasons"])}',
            'source': 'network', 'protocol': 'dns', 'domain': domain, 'dns_query': domain,
            'query_type': query_type, 'response_code': 'NXDOMAIN' if int(response_code or 0) == 3 else str(response_code or 0),
            'mitre_id': 'T1071.004', 'technique': 'Application Layer Protocol: DNS',
            'recommended_action': 'Review the querying process, DNS answers and correlated endpoint activity.',
            'raw': assessment,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _cfg_float(self, key, default):
        try:
            return float(self._config.get(key, default))
        except (TypeError, ValueError, AttributeError):
            return float(default)

    @staticmethod
    def _connection_key(connection):
        material = '|'.join(str(connection.get(field) or '') for field in (
            'protocol', 'pid', 'local_ip', 'local_port', 'remote_ip', 'remote_port',
        ))
        return hashlib.sha256(material.encode('utf-8', errors='ignore')).hexdigest()[:32]

    def _track_connection_lifecycle(self, connections):
        """Attach stable IDs/times and return newly closed socket evidence."""
        now_epoch = time.time()
        now_iso = datetime.now(timezone.utc).isoformat()
        current = {}
        started = []
        for item in connections:
            row = dict(item)
            key = self._connection_key(row)
            previous = self._active_connections.get(key)
            start_epoch = float((previous or {}).get('_start_epoch') or now_epoch)
            row.update({
                'connection_id': key,
                'start_time': (previous or {}).get('start_time') or now_iso,
                'end_time': None,
                'duration': round(max(0.0, now_epoch - start_epoch), 3),
                'observed_at': now_iso,
                '_start_epoch': start_epoch,
            })
            current[key] = row
            if previous is None:
                started.append(row)
                self._recent_connection_starts.append((now_epoch, row))

        closed = []
        for key, previous in self._active_connections.items():
            if key in current:
                continue
            row = {k: v for k, v in previous.items() if not k.startswith('_')}
            row.update({
                'state': 'CLOSED',
                'end_time': now_iso,
                'observed_at': now_iso,
                'duration': round(max(0.0, now_epoch - float(previous.get('_start_epoch') or now_epoch)), 3),
            })
            closed.append(row)
        self._active_connections = current
        return list(current.values()), closed, started

    def _network_io_delta(self):
        """Return adapter byte deltas. These are not misrepresented as per-flow bytes."""
        try:
            import psutil
            now = time.time()
            counters = psutil.net_io_counters(pernic=True)
            snapshot = {
                name: (int(value.bytes_sent), int(value.bytes_recv))
                for name, value in counters.items()
            }
            previous = self._last_io_snapshot
            self._last_io_snapshot = (now, snapshot)
            if not previous:
                return {'interval_seconds': 0, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': []}
            previous_at, previous_rows = previous
            rows = []
            for name, (sent, received) in snapshot.items():
                old_sent, old_received = previous_rows.get(name, (sent, received))
                rows.append({
                    'interface': name,
                    'bytes_sent': max(0, sent - old_sent),
                    'bytes_received': max(0, received - old_received),
                })
            return {
                'interval_seconds': round(max(0.0, now - previous_at), 3),
                'bytes_sent': sum(row['bytes_sent'] for row in rows),
                'bytes_received': sum(row['bytes_received'] for row in rows),
                'interfaces': rows,
            }
        except Exception as exc:
            logger.debug('Network byte counters unavailable: %s', exc)
            return {'interval_seconds': 0, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': []}

    def _detect_scan_and_lateral(self, started):
        now = time.time()
        window = max(10, int(self._cfg_float('network_behavior_window_seconds', 60)))
        while self._recent_connection_starts and self._recent_connection_starts[0][0] < now - window:
            self._recent_connection_starts.popleft()
        rows = [row for _, row in self._recent_connection_starts]
        ports = {int(row.get('remote_port') or 0) for row in rows if row.get('remote_port')}
        remote_hosts = {row.get('remote_ip') for row in rows if row.get('remote_ip')}
        internal_hosts = {ip for ip in remote_hosts if _is_private(ip)}
        scan_ports = max(5, int(self._cfg_float('port_scan_unique_ports', 20)))
        scan_hosts = max(5, int(self._cfg_float('host_scan_unique_hosts', 15)))
        cooldown = max(60, int(self._cfg_float('network_detection_cooldown_seconds', 900)))
        if (len(ports) >= scan_ports or len(remote_hosts) >= scan_hosts) and now - self._last_scan_alert >= cooldown:
            self._last_scan_alert = now
            risk = min(100, 45 + len(ports) + len(remote_hosts))
            self._sender.enqueue({
                'rule_id': 'NET_SCAN_BEHAVIOR', 'capabilityId': 3, 'capabilityIds': [3],
                'category': 'network', 'subCategory': 'network-scanning',
                'severity': 'high' if risk >= 70 else 'medium', 'risk_score': risk,
                'description': f'Network reconnaissance threshold crossed: {len(ports)} ports and {len(remote_hosts)} hosts in {window}s',
                'source': 'network', 'mitre_id': 'T1046', 'technique': 'Network Service Discovery',
                'recommended_action': 'Validate the initiating process and isolate only if reconnaissance is unauthorized.',
                'raw': {'unique_ports': sorted(ports), 'remote_hosts': sorted(remote_hosts), 'window_seconds': window, 'new_connections': started[:50]},
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

        lateral_ports = {22, 135, 139, 445, 3389, 5985, 5986}
        lateral_rows = [row for row in rows if _is_private(row.get('remote_ip') or '') and int(row.get('remote_port') or 0) in lateral_ports]
        lateral_hosts = {row.get('remote_ip') for row in lateral_rows}
        lateral_threshold = max(3, int(self._cfg_float('lateral_movement_unique_hosts', 8)))
        if len(lateral_hosts) >= lateral_threshold and now - self._last_lateral_alert >= cooldown:
            self._last_lateral_alert = now
            risk = min(100, 55 + len(lateral_hosts) * 4)
            self._sender.enqueue({
                'rule_id': 'NET_LATERAL_MOVEMENT_PATTERN', 'capabilityId': 3, 'capabilityIds': [3, 14],
                'category': 'network', 'subCategory': 'lateral-movement',
                'severity': 'critical' if risk >= 81 else 'high', 'risk_score': risk,
                'description': f'Remote administration activity reached {len(lateral_hosts)} internal hosts in {window}s',
                'source': 'network', 'mitre_id': 'T1021', 'technique': 'Remote Services',
                'recommended_action': 'Confirm the account, source process and administrative change window.',
                'raw': {'internal_hosts': sorted(lateral_hosts), 'connections': lateral_rows[:50], 'window_seconds': window},
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

    def _detect_transfer_anomaly(self, io_delta):
        sent = int(io_delta.get('bytes_sent') or 0)
        if io_delta.get('interval_seconds', 0) <= 0:
            return
        history = list(self._transfer_baseline)
        baseline = statistics.median(history) if history else 0
        self._transfer_baseline.append(sent)
        minimum = max(1024 * 1024, int(self._cfg_float('large_outbound_bytes', 100 * 1024 * 1024)))
        multiplier = max(1.5, self._cfg_float('transfer_anomaly_multiplier', 4.0))
        anomalous = sent >= minimum and (baseline <= 0 or sent >= baseline * multiplier)
        cooldown = max(60, int(self._cfg_float('network_detection_cooldown_seconds', 900)))
        if not anomalous or time.time() - self._last_transfer_alert < cooldown:
            return
        self._last_transfer_alert = time.time()
        ratio = round(sent / max(baseline, 1), 2) if baseline else None
        risk = min(100, 60 + (15 if ratio and ratio >= 8 else 0))
        self._sender.enqueue({
            'rule_id': 'NET_OUTBOUND_TRANSFER_ANOMALY', 'capabilityId': 3, 'capabilityIds': [3, 11],
            'category': 'network', 'subCategory': 'data-transfer-anomaly',
            'severity': 'high', 'risk_score': risk, 'bytes_sent': sent,
            'bytes_received': int(io_delta.get('bytes_received') or 0),
            'description': f'Outbound adapter traffic anomaly: {sent} bytes in {io_delta.get("interval_seconds")}s',
            'source': 'network', 'mitre_id': 'T1041', 'technique': 'Exfiltration Over C2 Channel',
            'recommended_action': 'Correlate adapter volume with process and destination evidence before containment.',
            'raw': {'adapter_delta': io_delta, 'baseline_bytes': baseline, 'baseline_multiplier': ratio},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _beacon_allowed(self, destination='', process_name='') -> bool:
        value = str(destination or '').lower().rstrip('.')
        process = str(process_name or '').lower()
        allowed_destinations = {
            str(item).lower().rstrip('.')
            for item in (self._config.get('beacon_allow_destinations', []) or [])
        }
        allowed_processes = {
            str(item).lower()
            for item in (self._config.get('beacon_allow_processes', []) or [])
        }
        destination_allowed = any(
            value == item or ('.' in item and value.endswith(f'.{item}'))
            for item in allowed_destinations if item
        )
        return destination_allowed or process in allowed_processes

    def _assess_beacon(self, timestamps, *, destination='', port=0, process_name='', executable=''):
        metrics = beacon_interval_metrics(timestamps)
        min_count = max(4, int(self._cfg_float('beacon_min_connections', 6)))
        min_period = max(1.0, self._cfg_float('beacon_min_interval_seconds', 5))
        max_period = max(min_period, self._cfg_float('beacon_max_interval_seconds', 3600))
        min_observation = max(0.0, self._cfg_float('beacon_min_observation_seconds', 60))
        consistency_required = min(100.0, max(0.0, self._cfg_float('beacon_consistency_threshold', 75)))
        if (
            metrics['count'] < min_count
            or metrics['average_interval'] < min_period
            or metrics['average_interval'] > max_period
            or metrics['observation_seconds'] < min_observation
            or metrics['interval_consistency'] < consistency_required
            or self._beacon_allowed(destination, process_name)
        ):
            return metrics, 0

        text = f'{process_name} {executable}'.lower().replace('\\', '/')
        process_risk = 15 if any(item in text for item in (
            'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32',
            'python', 'node', '/tmp/', '/var/tmp/', '/downloads/', '/appdata/local/temp/',
        )) else 0
        destination_risk = 20 if int(port or 0) in SUSPICIOUS_PORTS else 0
        nonstandard_risk = 10 if int(port or 0) not in WHITELIST_PORTS else 0
        is_dns = int(port or 0) == 53 and '.' in str(destination or '')
        first_label = str(destination or '').split('.', 1)[0]
        dns_risk = 20 if is_dns and (
            len(first_label) >= 18
            or str(destination or '').count('.') >= 4
            or (len(first_label) >= 12 and sum(ch.isdigit() for ch in first_label) >= 4)
        ) else 0
        unnamed_risk = 10 if destination and not is_dns and not _reverse_dns(destination) else 0
        duration_risk = 10 if metrics['observation_seconds'] >= max(300, min_observation) else 5
        risk = min(100, round(
            metrics['periodicity_score'] + process_risk + destination_risk
            + nonstandard_risk + dns_risk + unnamed_risk + duration_risk
        ))
        return metrics, risk

    def _matching_beacon_rules(self, metrics, connection, domain=''):
        enabled = set(self._config.get('beacon_enabled_rule_ids') or [
            'exact-periodic-callback', 'jittered-c2-beacon', 'low-and-slow-beacon',
            'dns-periodic-beacon', 'http-https-beacon', 'suspicious-process-beacon',
        ])
        port = int(connection.get('remote_port') or connection.get('dst_port') or 0)
        protocol = str(connection.get('protocol') or ('dns' if domain else 'tcp')).lower()
        process_text = '{} {}'.format(
            connection.get('process_name') or '', connection.get('executable') or '',
        ).lower().replace('\\', '/')
        matches = {
            'exact-periodic-callback': metrics['interval_consistency'] >= 90 and metrics['jitter_seconds'] <= 5,
            'jittered-c2-beacon': metrics['interval_consistency'] >= 65 and metrics['jitter_seconds'] <= 30,
            'low-and-slow-beacon': metrics['average_interval'] >= 300 and metrics['observation_seconds'] >= 1800,
            'dns-periodic-beacon': bool(domain) or protocol == 'dns' or port == 53,
            'http-https-beacon': protocol in ('http', 'https', 'tls') or port in (80, 443),
            'suspicious-process-beacon': any(item in process_text for item in (
                'powershell', 'pwsh', 'wscript', 'cscript', 'mshta', 'rundll32',
                'regsvr32', 'python', 'node', '/tmp/',
            )),
        }
        matched = [rule_id for rule_id in enabled if matches.get(rule_id)]
        evidence = {
            'beaconing': True,
            'connectionCount': metrics['count'],
            'averageInterval': metrics['average_interval'],
            'jitterSeconds': metrics['jitter_seconds'],
            'intervalConsistency': metrics['interval_consistency'],
            'observationSeconds': metrics['observation_seconds'],
            'destinationIp': connection.get('remote_ip') or connection.get('dst_ip') or '',
            'destinationPort': port,
            'protocol': protocol,
            'processName': connection.get('process_name') or '',
        }

        def condition_matches(condition):
            actual = evidence.get(condition.get('field'))
            expected = condition.get('value')
            operator = condition.get('operator')
            if operator in ('gt', 'gte', 'lt', 'lte'):
                try:
                    actual_number, expected_number = float(actual), float(expected)
                except (TypeError, ValueError):
                    return False
                return {
                    'gt': actual_number > expected_number,
                    'gte': actual_number >= expected_number,
                    'lt': actual_number < expected_number,
                    'lte': actual_number <= expected_number,
                }[operator]
            if operator in ('in', 'not_in'):
                values = expected if isinstance(expected, list) else [expected]
                result = str(actual).lower() in {str(value).lower() for value in values}
                return result if operator == 'in' else not result
            if operator == 'contains':
                return str(expected or '').lower() in str(actual or '').lower()
            result = str(actual).lower() == str(expected).lower()
            return result if operator == 'eq' else not result if operator == 'ne' else False

        for rule in self._config.get('beacon_custom_rules', []) or []:
            if not isinstance(rule, dict):
                continue
            conditions = rule.get('conditions') or []
            if conditions and all(condition_matches(condition) for condition in conditions):
                matched.append(str(rule.get('id') or rule.get('name') or 'custom-beacon-rule'))
        return matched

    def _emit_beacon(self, key, timestamps, connection, domain=''):
        if self._config.get('beacon_detection_enabled', True) is False:
            return
        destination = domain or connection.get('remote_ip') or ''
        metrics, risk = self._assess_beacon(
            timestamps, destination=destination,
            port=connection.get('remote_port') or 0,
            process_name=connection.get('process_name') or '',
            executable=connection.get('executable') or '',
        )
        matched_rules = self._matching_beacon_rules(metrics, connection, domain)
        if not matched_rules:
            return
        threat_intel = None
        cached_ip_lookup = getattr(self._vt, 'cached_ip', None) if self._vt else None
        if risk and cached_ip_lookup and not domain and destination and not _is_private(destination):
            try:
                # Detection runs in the collector loop; only consume cached
                # intelligence here so a provider timeout can never stall
                # endpoint network monitoring.
                threat_intel = cached_ip_lookup(destination)
                verdict = str((threat_intel or {}).get('verdict') or '').lower()
                if verdict == 'malicious':
                    risk = min(100, risk + 15)
                elif verdict == 'suspicious':
                    risk = min(100, risk + 8)
            except Exception as exc:
                logger.debug('Beacon destination reputation lookup failed: %s', exc)

        threshold_key = 'dns_beacon_alert_threshold' if domain else 'beacon_alert_threshold'
        threshold = min(100, max(25, int(self._cfg_float(threshold_key, 55 if domain else 70))))
        if risk < threshold:
            return
        now = time.time()
        cooldown = max(60, int(self._cfg_float('beacon_alert_cooldown_seconds', 1800)))
        if now - self._beacon_alerted.get(key, 0) < cooldown:
            return
        self._beacon_alerted[key] = now
        severity = 'critical' if risk >= 85 else 'high' if risk >= 70 else 'medium'
        protocol = 'dns' if domain else str(connection.get('protocol') or 'tcp').lower()
        self._sender.enqueue({
            'rule_id': 'BEACON_DNS_PERIODIC' if domain else 'BEACON_PERIODIC_CONNECTION',
            'capabilityId': 26, 'capabilityIds': [3, 9, 26] if domain else [1, 3, 26],
            'category': 'network', 'subCategory': 'beaconing-detection',
            'eventType': 'DNS Beaconing' if domain else 'Periodic Network Beacon',
            'severity': severity, 'risk_score': risk, 'confidence_score': metrics['interval_consistency'],
            'description': (
                f'Periodic {protocol.upper()} communication to {destination}'
                f': {metrics["count"]} observations, average interval '
                f'{metrics["average_interval"]:.1f}s, jitter {metrics["jitter_seconds"]:.1f}s'
            ),
            'source': 'beaconing', 'protocol': protocol,
            'src_ip': connection.get('local_ip'), 'src_port': connection.get('local_port'),
            'dst_ip': connection.get('remote_ip'), 'dst_port': connection.get('remote_port'),
            'domain': domain or None, 'process_name': connection.get('process_name'),
            'process_exe': connection.get('executable'), 'process_cmdline': connection.get('command_line'),
            'pid': connection.get('pid'), 'parent_pid': connection.get('parent_pid'),
            'parent_process_name': connection.get('parent_process'),
            'username': connection.get('username'),
            'executable_sha256': connection.get('process_hash'),
            'signature_status': connection.get('signature_status'),
            'process_create_time': connection.get('process_start_time'),
            'connection_state': connection.get('state'),
            'average_interval': metrics['average_interval'],
            'median_interval': metrics['median_interval'],
            'jitter_seconds': metrics['jitter_seconds'],
            'interval_consistency': metrics['interval_consistency'],
            'periodicity_score': metrics['periodicity_score'],
            'connection_count': metrics['count'],
            'observation_seconds': metrics['observation_seconds'],
            'virustotal': threat_intel,
            'ioc_matched': bool(threat_intel and threat_intel.get('verdict') in ('malicious', 'suspicious')),
            'threat_category': 'Known C2 / malicious destination' if threat_intel and threat_intel.get('verdict') == 'malicious' else 'Possible C2 Beaconing',
            'mitre_id': 'T1071.004' if domain else 'T1071',
            'technique': 'DNS' if domain else 'Application Layer Protocol',
            'recommended_action': 'Investigate the process and destination reputation before applying containment.',
            'matched_patterns': matched_rules,
            'raw': {**metrics, 'destination': destination, 'connection': connection, 'matched_rules': matched_rules},
            'raw_log': f'BEACON|destination={destination}|protocol={protocol}|risk={risk}|metrics={metrics}',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _observe_connection_beacons(self, connections):
        current = {
            (item.get('pid'), item.get('remote_ip'), item.get('remote_port'), item.get('local_port'))
            for item in connections
        }
        if not self._beacon_baseline_done:
            self._previous_connection_instances = current
            self._beacon_baseline_done = True
            return
        now = time.time()
        max_age = max(3600.0, self._cfg_float('beacon_history_seconds', 86400))
        by_instance = {
            (item.get('pid'), item.get('remote_ip'), item.get('remote_port'), item.get('local_port')): item
            for item in connections
        }
        for instance in current - self._previous_connection_instances:
            self._record_connection_beacon(by_instance[instance], now=now, max_age=max_age)
        self._previous_connection_instances = current

    def observe_network_connection(self, connection):
        """Accept exact OS-native connection events without packet payloads."""
        self._record_connection_beacon(connection or {})

    def _record_connection_beacon(self, connection, now=None, max_age=None):
        remote_ip = connection.get('remote_ip') or connection.get('dest_ip') or ''
        if not remote_ip or _is_private(remote_ip):
            return
        now = float(now if now is not None else time.time())
        max_age = max_age or max(3600.0, self._cfg_float('beacon_history_seconds', 86400))
        normalized = {
            **connection,
            'remote_ip': remote_ip,
            'remote_port': connection.get('remote_port') or connection.get('dst_port') or 0,
        }
        group = (
            normalized.get('pid'), normalized.get('remote_ip'),
            normalized.get('remote_port'), normalized.get('protocol'),
        )
        with self._beacon_lock:
            samples = self._connection_beacons.setdefault(group, deque(maxlen=256))
            # Sysmon and psutil can observe the same socket during one poll.
            if samples and now - samples[-1] < 1.0:
                return
            samples.append(now)
            while samples and samples[0] < now - max_age:
                samples.popleft()
            self._emit_beacon(('connection', group), list(samples), normalized)

    def observe_dns_query(self, domain, process=None):
        """Accept DNS metadata from OS-native collectors (for example Sysmon)."""
        process = process or {}
        answers = [normalized_ip(value.strip()) for value in str(process.get('query_results') or '').split(';')]
        self._remember_dns_query(domain, [value for value in answers if value])
        self._observe_dns_beacon(domain, process or {})

    def _observe_dns_beacon(self, domain, connection=None):
        if self._config.get('dns_beacon_detection_enabled', True) is False:
            return
        domain = str(domain or '').lower().rstrip('.')
        if not _is_display_dns_domain(domain) or self._beacon_allowed(domain):
            return
        now = time.time()
        max_age = max(3600.0, self._cfg_float('beacon_history_seconds', 86400))
        connection = connection or {}
        process_key = connection.get('pid') or connection.get('process_name') or ''
        group = (domain, process_key) if process_key else domain
        with self._beacon_lock:
            samples = self._dns_beacons.setdefault(group, deque(maxlen=256))
            if samples and now - samples[-1] < 1.0:
                return
            samples.append(now)
            while samples and samples[0] < now - max_age:
                samples.popleft()
            self._emit_beacon(
                ('dns', group), list(samples),
                {**connection, 'remote_port': 53, 'protocol': 'dns'},
                domain=domain,
            )

    def _recent_dns_queries(self, max_age=3600):
        cutoff = time.time() - max_age
        with self._dns_lock:
            recent = [item for item in self._dns_queries if item.get('ts', 0) >= cutoff]
        domains = []
        answers = {}
        for item in reversed(recent):
            domain = item.get('domain')
            if domain and domain not in domains:
                domains.append(domain)
            if domain and item.get('ips'):
                answers.setdefault(domain, [])
                for ip in item['ips']:
                    if ip not in answers[domain]:
                        answers[domain].append(ip)
        return domains[:30], answers

    def _emit_process_dns_attribution(self, connections, answer_map):
        """Correlate DNS answers to active process sockets on non-Windows hosts.

        This is explicitly marked as correlated evidence. Windows uses Sysmon
        Event 22 in windows_process_events.py, which provides exact attribution.
        """
        ip_domains = {}
        for domain, ips in (answer_map or {}).items():
            for ip in ips or []:
                ip_domains.setdefault(str(ip), []).append(domain)
        attributions = {}
        for conn in connections:
            remote_ip = str(conn.get('remote_ip') or '')
            pid = conn.get('pid')
            domains = ip_domains.get(remote_ip) or []
            if not pid or not domains:
                continue
            for domain in domains[:3]:
                # One DNS response commonly contains several A/AAAA answers.
                # They describe one process-to-domain relationship, not one
                # independent event per CDN/anycast address.
                key = (
                    pid,
                    str(conn.get('process_start_time') or ''),
                    str(conn.get('process_name') or ''),
                    domain,
                    int(conn.get('remote_port') or 0),
                )
                item = attributions.setdefault(key, {'connection': conn, 'ips': []})
                if remote_ip and remote_ip not in item['ips']:
                    item['ips'].append(remote_ip)
        for key, item in attributions.items():
            if key in self._dns_process_seen:
                continue
            pid, process_start_time, process_name, domain, remote_port = key
            conn = item['connection']
            destination_ips = sorted(item['ips'])
            primary_ip = str(conn.get('remote_ip') or '')
            # A deterministic transport id also makes the event idempotent
            # across agent restarts while the same OS process is alive.
            attribution_id = hashlib.sha256(
                ('proc-dns-attributed|' + '|'.join(map(str, key))).encode('utf-8')
            ).hexdigest()
            accepted = self._sender.enqueue({
                    'event_id': attribution_id,
                    'rule_id': 'PROC_DNS_ATTRIBUTED', 'capabilityId': 1, 'capabilityIds': [1, 3, 9],
                    'category': 'edr', 'severity': 'low', 'source': 'network',
                    'description': (
                        f'{process_name or "Process"} connected to {domain} '
                        f'({len(destination_ips)} resolved address(es))'
                    ),
                    'eventType': 'Process DNS Query', 'process_name': process_name,
                    'pid': pid, 'exe': conn.get('executable'), 'username': conn.get('username'),
                    'domain': domain, 'dnsQuery': domain, 'dest_ip': primary_ip,
                    'destination_ips': destination_ips, 'dst_port': remote_port,
                    'protocol': conn.get('protocol') or '',
                    'attribution_confidence': 'correlated',
                    'evidence_type': 'dns_answer_to_process_socket',
                    'raw': {'domain': domain, 'answer_ip': primary_ip, 'answer_ips': destination_ips, 'connection': conn},
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                })
            if accepted is not False:
                self._dns_process_seen[key] = time.time()
        while len(self._dns_process_seen) > 8192:
            self._dns_process_seen.pop(next(iter(self._dns_process_seen)))

    def _dns_sniffer_loop(self):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.settimeout(2)
            logger.info('DNS query sniffer started')
        except PermissionError:
            logger.warning('DNS query sniffer needs root/CAP_NET_RAW; live queried domains will be unavailable')
            return
        except Exception as e:
            logger.warning('DNS query sniffer unavailable: %s', e)
            return

        while True:
            try:
                packet = sock.recv(65535)
                dns = _extract_dns_from_packet(packet)
                query_types = dns.get('query_types', [])
                for index, domain in enumerate(dns.get('queries', [])):
                    query_type = query_types[index] if index < len(query_types) else ''
                    self._remember_dns_query(domain, query_type=query_type)
                    if not dns.get('is_response'):
                        self._observe_dns_beacon(domain)
                    self._observe_dns_anomaly(
                        domain,
                        dns.get('response_code', 0) if dns.get('is_response') else 0,
                        query_type,
                    )
                for domain, ips in dns.get('answers', {}).items():
                    self._remember_dns_query(domain, ips)
            except socket.timeout:
                continue
            except Exception as e:
                logger.debug('DNS sniffer error: %s', e)
                time.sleep(1)

    def _loop(self):
        logger.info('Network monitor started (false-positive-aware)')
        while True:
            try:
                if time.time() - self._last_reset > RESET_INTERVAL:
                    self._seen.clear()
                    self._last_reset = time.time()
                    logger.debug('Network seen-set reset')
                self._check()
            except Exception as e:
                logger.error('Network check error: %s', e)
            time.sleep(max(10.0, self._cfg_float('network_poll_interval_seconds', 20)))

    def _enrich_connection_telemetry(self, connections):
        counters = linux_tcp_counters()
        _, answers = self._recent_dns_queries()
        domains_by_ip = {}
        for domain, addresses in answers.items():
            for address in addresses:
                domains_by_ip.setdefault(normalized_ip(address), domain)
        for connection in connections:
            remote_ip = normalized_ip(connection.get('remote_ip'))
            connection.update(self._peer_metadata.get(remote_ip))
            if remote_ip in domains_by_ip:
                connection.update(domain=domains_by_ip[remote_ip], domain_source='dns_answer')
            if connection.get('protocol') == 'tcp':
                measured = counters.get(socket_key(connection['local_ip'], connection['local_port'], remote_ip, connection['remote_port']))
                if measured:
                    connection.update(measured, bytes_scope='connection', bytes_source='linux_tcp_info')
        return connections

    def _check(self):
        try:
            import psutil
            socket_rows = psutil.net_connections(kind='inet')
            interface_map = _interface_by_ip(psutil)
        except Exception as exc:
            logger.debug('Socket snapshot error: %s', exc)
            # An unreadable inventory is not evidence that every socket closed.
            return

        observed_connections = _get_connections(
            socket_rows=socket_rows,
            process_cache=self._process_metadata_cache,
            psutil_module=psutil,
            interface_map=interface_map,
        ) if psutil is not None else []
        observed_connections = [
            connection for connection in observed_connections
            if not _is_agent_control_plane_connection(
                connection,
                self._server_addresses,
                self._server_port,
                local_addresses=interface_map,
            )
        ]
        self._enrich_connection_telemetry(observed_connections)
        connections, closed_connections, started_connections = self._track_connection_lifecycle(observed_connections)
        listeners = _get_listeners(
            socket_rows=socket_rows,
            process_cache=self._process_metadata_cache,
            psutil_module=psutil,
            interface_map=interface_map,
        ) if psutil is not None else []
        io_delta = self._network_io_delta()
        self._observe_connection_beacons(connections)
        self._detect_scan_and_lateral(started_connections)
        self._detect_transfer_anomaly(io_delta)
        self._enforce_port_policy(listeners)
        self._send_summary(connections, listeners, closed_connections, io_delta, interface_map)
        for conn in connections:
            remote_ip   = conn['remote_ip']
            remote_port = conn['remote_port']
            key = (remote_ip, remote_port)

            if key in self._seen:
                continue

            is_suspicious_port = remote_port in SUSPICIOUS_PORTS
            is_private         = _is_private(remote_ip)

            # Skip all private-IP connections on normal ports
            if is_private and not is_suspicious_port:
                continue

            # Skip whitelisted ports unless it's a known suspicious port
            if remote_port in WHITELIST_PORTS and not is_suspicious_port:
                continue

            # ── VT enrichment ──────────────────────────────────────────────────
            vt_result  = None
            vt_verdict = 'unknown'
            vt_score   = 0
            vt_detections = 0
            vt_total   = 0

            if self._vt and not is_private:
                try:
                    vt_result = self._vt.scan_ip(remote_ip)
                    if vt_result:
                        vt_verdict    = vt_result.get('verdict', 'unknown')
                        vt_score      = vt_result.get('score', 0) or 0
                        vt_detections = vt_result.get('malicious', 0) + vt_result.get('suspicious', 0)
                        vt_total      = vt_result.get('total_engines', 0) or 0
                        # Fix not_found: if no engines returned, verdict is not_found not clean
                        if vt_total == 0:
                            vt_verdict = 'not_found'
                except Exception as e:
                    logger.debug('VT IP error: %s', e)

            # ── Decision logic: should we emit this alert? ─────────────────────
            # Rule 1: VT says clean (0 detections, has engine data) → suppress
            if vt_result and vt_total > 0 and vt_detections == 0 and not is_suspicious_port:
                logger.debug('Suppressing alert for %s:%s — VT clean (%s engines, 0 detections)',
                             remote_ip, remote_port, vt_total)
                self._seen.add(key)
                continue

            # Rule 2: VT says clean on suspicious port → downgrade to medium (port heuristic)
            if vt_result and vt_total > 0 and vt_detections == 0 and is_suspicious_port:
                logger.info('Suspicious port %s with clean VT — low severity', remote_port)
                vt_verdict = 'clean'

            # Rule 3: 1-engine false positives → suppress (too unreliable)
            if vt_detections > 0 and vt_detections < MIN_VT_DETECTIONS_FOR_ALERT and not is_suspicious_port:
                logger.debug('Suppressing %s:%s — only 1 VT engine flagged it (possible false positive)',
                             remote_ip, remote_port)
                self._seen.add(key)
                continue

            # ── Determine final severity ────────────────────────────────────────
            if vt_verdict == 'malicious' and vt_score >= 70:
                severity = 'critical'
            elif vt_verdict == 'malicious' and vt_score >= 40:
                severity = 'high'
            elif is_suspicious_port and vt_verdict not in ('clean',):
                severity = 'high'
            elif vt_verdict == 'suspicious' or vt_score >= 1:
                severity = 'medium'
            elif is_suspicious_port:
                severity = 'medium'
            elif vt_verdict in ('not_found', 'unknown') and not vt_result:
                # No VT data, non-standard port — informational only
                severity = 'low'
            else:
                # VT clean or low-confidence — skip
                self._seen.add(key)
                continue

            # ── Compose alert description ───────────────────────────────────────
            if vt_verdict == 'malicious':
                description = (
                    f'Malicious IP {remote_ip}:{remote_port} — '
                    f'{vt_detections}/{vt_total} engines detected'
                )
            elif vt_verdict == 'suspicious':
                description = (
                    f'Suspicious IP {remote_ip}:{remote_port} — '
                    f'{vt_detections}/{vt_total} engines flagged'
                )
            elif is_suspicious_port:
                description = (
                    f'Suspicious port connection to {remote_ip}:{remote_port}'
                    + (f' (VT: {vt_verdict})' if vt_result else ' (VT: N/A)')
                )
            else:
                description = f'Outbound connection to {remote_ip}:{remote_port}'

            self._seen.add(key)

            alert = {
                'rule_id':     'NET_SUSPICIOUS_CONNECTION',
                'capabilityId': 3,
                'capabilityIds': [3],
                'category':    'network',
                'subCategory': 'threat-intelligence',
                'eventType': 'Suspicious Network Connection',
                'severity':    severity,
                'risk_score':  max(int(vt_score or 0), 65 if is_suspicious_port else 25),
                'description': description,
                'src_ip':      conn.get('local_ip'),
                'src_port':    conn.get('local_port'),
                'dst_ip':      remote_ip,
                'dst_port':    remote_port,
                'protocol':    conn.get('protocol', 'tcp').lower(),
                'pid':         conn.get('pid'),
                'process_name': conn.get('process_name'),
                'process_exe': conn.get('executable'),
                'process_cmdline': conn.get('command_line'),
                'parent_pid': conn.get('parent_pid'),
                'parent_process_name': conn.get('parent_process'),
                'username': conn.get('username'),
                'executable_sha256': conn.get('process_hash'),
                'signature_status': conn.get('signature_status'),
                'process_create_time': conn.get('process_start_time'),
                'connection_state': conn.get('state'),
                'connection_start_time': conn.get('start_time'),
                'connection_duration': conn.get('duration'),
                'blocked':     False,
                'inbound':     False,
                'source':      'IDS',
                'module':      'IDS',
                'source_type': 'ids',
                'event_category': 'ids_alert',
                'type':        'IDS_ALERT',
                'attackType':  'Suspicious Network Traffic',
                'signatureName': 'NET_SUSPICIOUS_CONNECTION',
                'sensor':      'SOC Network IDS',
                'mitre_id':    'T1071',
                'technique':   'Application Layer Protocol',
                'recommended_action': 'Validate destination reputation and the owning process before containment.',
                'raw_log': (
                    f'NET:ESTABLISHED {conn["local_ip"]}:{conn["local_port"]}'
                    f' -> {remote_ip}:{remote_port}'
                    f' VT:{vt_verdict}({vt_detections}/{vt_total})'
                ),
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }
            peer = _peer_summary(conn)
            alert['raw'] = {'external_peers': [peer]}
            if peer.get('domain'):
                alert['domain'] = peer.get('domain')
            if peer.get('countryCode'):
                alert['geoCountry'] = peer.get('countryCode')
                alert['geoCity'] = peer.get('city')
                alert['geoISP'] = peer.get('isp')

            if vt_result:
                alert['virustotal'] = vt_result

            self._sender.enqueue(alert)

    def _enforce_port_policy(self, listeners):
        current = set()
        mode = str(self._config.get('port_policy_mode', 'audit')).strip().lower()
        for listener in listeners:
            verdict = evaluate_port_policy(listener, self._config)
            if not verdict['violation']:
                continue
            protocol = str(listener.get('protocol') or 'tcp').lower()
            port = int(listener.get('local_port') or 0)
            signature = (
                listener.get('local_ip'), port, protocol,
                listener.get('pid'), listener.get('process_name'), verdict['reason'],
            )
            if signature in self._port_policy_seen:
                current.add(signature)
                continue

            blocked = False
            if mode == 'block' and verdict['exposed'] and self._firewall is not None:
                try:
                    blocked = bool(self._firewall.close_port(port, protocol, direction='in'))
                except Exception as exc:
                    logger.warning('Port policy could not block %s/%s: %s', protocol, port, exc)

            # Failed/unavailable enforcement is retried on the next scan.
            if mode != 'block' or blocked:
                current.add(signature)

            process_name = listener.get('process_name') or 'unknown process'
            self._sender.enqueue({
                'rule_id': 'NET_UNAUTHORIZED_LISTENER',
                'category': 'network',
                'severity': 'high' if blocked else 'medium',
                'description': (
                    f'Unauthorized {protocol.upper()} listener {listener.get("local_ip")}:{port} '
                    f'owned by {process_name}' + (' was blocked' if blocked else ' requires review')
                ),
                'source': 'network',
                'protocol': protocol,
                'dst_port': port,
                'pid': listener.get('pid'),
                'process_name': listener.get('process_name'),
                'executable': listener.get('executable'),
                'username': listener.get('username'),
                'blocked': blocked,
                'inbound': True,
                'action_taken': 'Blocked' if blocked else 'Detected',
                'raw_log': (
                    f'NET:UNAUTHORIZED_LISTENER bind={listener.get("local_ip")}:{port} '
                    f'protocol={protocol} pid={listener.get("pid")} process={process_name} '
                    f'reason={verdict["reason"]} mode={mode}'
                ),
                'raw': {'listener': listener, 'policy_reason': verdict['reason'], 'policy_mode': mode},
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })
        # A closed listener may alert again if it genuinely reappears later.
        self._port_policy_seen = current

    def _enqueue_changed_summary(self, alert, state, force=False):
        """Remember state only after durable delivery; debounce noisy churn."""
        rule = alert['rule_id']
        fingerprint = _network_state_fingerprint(state)
        if not force and self._summary_fingerprints.get(rule) == fingerprint:
            return True
        min_interval = max(0.0, self._cfg_float('network_summary_min_interval_seconds', 120))
        last_sent = self._summary_last_sent.get(rule, 0)
        if last_sent and time.monotonic() - last_sent < min_interval:
            # Do not advance the fingerprint. The newest state will be retried
            # on a later scan and therefore cannot be lost during the debounce.
            return None
        alert.setdefault('raw', {})['reporting_mode'] = 'on_change'
        if self._sender.enqueue(alert) is False:
            return False
        self._summary_fingerprints[rule] = fingerprint
        self._summary_last_sent[rule] = time.monotonic()
        return True

    def _send_summary(self, connections, listeners, closed_connections=None, io_delta=None, interface_map=None):
        now = time.time()
        io_delta = io_delta or {'interval_seconds': 0, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': []}
        for key in ('interval_seconds', 'bytes_sent', 'bytes_received'):
            self._pending_io_delta[key] += max(0, io_delta.get(key) or 0)
        for row in io_delta.get('interfaces') or []:
            name = row.get('interface') or ''
            pending = self._pending_io_delta['interfaces'].setdefault(name, {'interface': name, 'bytes_sent': 0, 'bytes_received': 0})
            for key in ('bytes_sent', 'bytes_received'):
                pending[key] += max(0, row.get(key) or 0)
        io_delta = {**self._pending_io_delta, 'interfaces': list(self._pending_io_delta['interfaces'].values())}

        # Sort before sampling so shuffled OS rows cannot change sampled peers.
        connections = sorted(connections, key=self._connection_key)
        listeners = sorted(listeners, key=self._connection_key)
        local_addresses = set((interface_map or {}).keys())
        listener_ports = {
            (str(row.get('protocol') or 'tcp').lower(), int(row.get('local_port') or 0))
            for row in listeners
        }
        summary_connections = _summary_connection_inventory(connections, listeners, local_addresses)
        summary_listeners = _summary_listener_inventory(listeners)
        active_summary_identities = {
            identity for identity in (
                _summary_connection_identity(row, listener_ports, local_addresses)
                for row in connections
            ) if identity is not None
        }
        # A parallel browser socket closing is not a topology change while the
        # same process/peer flow remains active. Retain evidence only when the
        # last matching stable flow closes.
        for row in closed_connections or []:
            identity = _summary_connection_identity(row, listener_ports, local_addresses)
            if identity is None or identity in active_summary_identities:
                continue
            stable_closed = _summary_connection_view(row, listener_ports, local_addresses)
            stable_closed['state'] = 'CLOSED'
            self._pending_closed_connections[identity] = stable_closed
        vpn_state = _get_vpn_state(connections)
        resolvers, search_domains = _dns_resolvers()
        live_dns_queries, dns_answer_map = self._recent_dns_queries()
        network_state = {
            'connections': summary_connections, 'listeners': summary_listeners, 'vpn': vpn_state,
            'interface_addresses': interface_map or {},
            'dns_config': {'resolvers': resolvers, 'primary_resolver': resolvers[0] if resolvers else '', 'search_domains': search_domains},
        }
        observed_state = _network_state_fingerprint({
            'network': network_state, 'dns_queries': live_dns_queries, 'dns_answers': dns_answer_map,
        })
        pending_bytes = int(io_delta.get('bytes_sent') or 0) + int(io_delta.get('bytes_received') or 0)
        usage_interval = max(60.0, self._cfg_float('network_usage_report_interval_seconds', 60))
        has_socket_bytes = any(row.get('bytes_sent', 0) or row.get('bytes_received', 0) for row in summary_connections)
        usage_due = (pending_bytes > 0 or has_socket_bytes) and now - self._last_usage_emit >= usage_interval
        if self._last_observed_summary == observed_state and not self._pending_closed_connections and not usage_due:
            return
        max_closed = max(1, int(self._cfg_float('network_snapshot_max_closed', 250)))
        pending_closed = list(self._pending_closed_connections.items())[:max_closed]
        closed_connections = [row for _, row in pending_closed]
        accepted = []
        external = [c for c in summary_connections if c.get('remote_ip') and not _is_private(c['remote_ip'])]
        private = [c for c in summary_connections if c.get('remote_ip') and _is_private(c['remote_ip'])]
        ports = sorted({int(c.get('remote_port') or c.get('local_port') or 0) for c in summary_connections
                        if c.get('remote_port') or c.get('local_port')})
        top_ports = ports[:20]
        sample_external = external[:5]
        external_peer_rows = [_peer_summary(c) for c in sample_external]
        listening_ports = sorted({int(c.get('local_port') or 0) for c in listeners if c.get('local_port')})
        risky_listener_ports = [
            p for p in listening_ports
            if p in {21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017}
        ]
        dns_connections = [c for c in summary_connections if int(c.get('remote_port') or 0) == 53]
        dns_peer_rows = [_peer_summary(c, include_geo=False) for c in dns_connections[:10]]
        resolver_hosts = [host for host in (_reverse_dns(ip) for ip in resolvers) if host]
        display_dns_queries = [d for d in live_dns_queries if _is_display_dns_domain(d)]
        display_dns_answer_map = {
            domain: ips for domain, ips in dns_answer_map.items()
            if domain in display_dns_queries and ips
        }
        self._emit_process_dns_attribution(connections, display_dns_answer_map)
        dns_answer_ips = []
        for domain in display_dns_queries:
            for ip in display_dns_answer_map.get(domain, []):
                if ip not in dns_answer_ips:
                    dns_answer_ips.append(ip)
        dns_domains = list(dict.fromkeys(
            display_dns_queries
            + list(DEFAULT_WATCH_DOMAINS)
            + search_domains
            + [p.get('domain') for p in dns_peer_rows if p.get('domain')]
            + resolver_hosts
        ))
        dns_domains = [d for d in dns_domains if _is_display_dns_domain(d)]
        mfa_sso_hits = _mfa_sso_hits(display_dns_queries + dns_domains)

        alert = {
            'rule_id': 'NET_CONNECTION_SUMMARY',
            'category': 'network',
            'severity': 'low',
            'description': (
                f'Live network summary: {len(connections)} established, '
                f'{len(external)} external, {len(private)} internal connections, '
                f'VPN {"active" if vpn_state.get("active") else "inactive"}'
            ),
            'source': 'network',
            'capabilityId': 3,
            'capabilityIds': [3],
            'subCategory': 'connection-telemetry',
            'eventType': 'Network Connection Snapshot',
            'protocol': 'mixed',
            'connection_count': len(connections),
            'bytes_sent': int(io_delta.get('bytes_sent') or 0),
            'bytes_received': int(io_delta.get('bytes_received') or 0),
            'blocked': False,
            'inbound': False,
            'raw_log': (
                f'NET:SUMMARY established={len(connections)} '
                f'external={len(external)} internal={len(private)} '
                f'ports={top_ports} '
                f'vpn_active={vpn_state.get("active")} vpn_method={vpn_state.get("method")} '
                f'external_peers={[c.get("remote_ip") for c in sample_external]}'
            ),
            'raw': {
                'established_count': len(connections),
                'external_count': len(external),
                'internal_count': len(private),
                'ports': top_ports,
                'external_peers': external_peer_rows,
                'vpn': vpn_state,
                'interface_addresses': network_state['interface_addresses'],
                'dns_config': network_state['dns_config'],
                # Metadata only. Payload/content is never captured.
                'connections': summary_connections[:max(1, int(self._cfg_float('network_snapshot_max_connections', 500)))],
                'dns_answer_map': display_dns_answer_map,
                'listeners': summary_listeners[:max(1, int(self._cfg_float('network_snapshot_max_connections', 500)))],
                'closed_connections': closed_connections[:max(1, int(self._cfg_float('network_snapshot_max_closed', 250)))],
                'adapter_delta': io_delta,
                'collection_scope': {
                    'payload_capture': False,
                    'tcp': True,
                    'udp': True,
                    'ipv4': True,
                    'ipv6': True,
                    'platform': SYSTEM,
                },
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        if sample_external:
            alert['src_ip'] = sample_external[0].get('remote_ip')
            alert['dst_port'] = sample_external[0].get('remote_port')
        if external_peer_rows and external_peer_rows[0].get('countryCode'):
            alert['geoCountry'] = external_peer_rows[0].get('countryCode')
            alert['geoCity'] = external_peer_rows[0].get('city')
            alert['geoISP'] = external_peer_rows[0].get('isp')
        network_changed = (bool(closed_connections) or
                           self._summary_fingerprints.get('NET_CONNECTION_SUMMARY') != _network_state_fingerprint(network_state))
        network_accepted = self._enqueue_changed_summary(
            alert, network_state, force=bool(closed_connections) or usage_due
        )
        accepted.append(network_accepted)
        if (network_changed or usage_due) and network_accepted:
            for key, _ in pending_closed:
                self._pending_closed_connections.pop(key, None)
            self._pending_io_delta = {'interval_seconds': 0, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': {}}
            if usage_due:
                self._last_usage_emit = now

        if vpn_state.get('active') and now - self._last_vpn_emit >= 300:
            self._last_vpn_emit = now
            method = vpn_state.get('method') or 'VPN'
            self._sender.enqueue({
                'rule_id': 'AUTH_VPN_USAGE',
                'category': 'edr',
                'severity': 'low',
                'description': f'{method} usage detected on endpoint',
                'source': 'network',
                'src_ip': vpn_state.get('source_ip') or (vpn_state.get('remote_peers') or [''])[0],
                'username': vpn_state.get('username') or '',
                'user_action': 'remote_login',
                'raw_log': (
                    f'AUTH:VPN_USAGE active=true method={method} '
                    f'interfaces={vpn_state.get("interfaces")} processes={vpn_state.get("processes")} '
                    f'ports={vpn_state.get("ports")} peers={vpn_state.get("remote_peers")}'
                )[:500],
                'raw': {
                    'auth_method': method,
                    'auth_action': 'remote_login',
                    'log_type': 'authentication',
                    'vpn_active': True,
                    'vpn': vpn_state,
                },
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

        if mfa_sso_hits and now - self._last_mfa_portal_emit >= 300:
            self._last_mfa_portal_emit = now
            providers = list(dict.fromkeys(hit['provider'] for hit in mfa_sso_hits))
            domains = list(dict.fromkeys(hit['domain'] for hit in mfa_sso_hits))
            provider = providers[0] if providers else 'MFA/SSO provider'
            username = vpn_state.get('username') or _local_username()
            source_ip = vpn_state.get('source_ip') or _local_source_ip()
            self._sender.enqueue({
                'rule_id': 'AUTH_MFA_PORTAL_ACTIVITY',
                'category': 'edr',
                'severity': 'low',
                'description': f'{provider} portal activity observed from endpoint',
                'source': 'network',
                'username': username,
                'src_ip': source_ip,
                'source_ip': source_ip,
                'user_action': 'mfa_portal_activity',
                'domain': domains[0] if domains else '',
                'query': domains[0] if domains else '',
                'dnsQuery': domains[0] if domains else '',
                'raw_log': (
                    f'AUTH:MFA_PORTAL_ACTIVITY providers={providers} domains={domains} '
                    'result=observed_not_success_or_failure'
                )[:500],
                'raw': {
                    'auth_method': 'MFA',
                    'auth_action': 'mfa_portal_activity',
                    'log_type': 'authentication',
                    'mfa_portal_activity': True,
                    'mfa_result_known': False,
                    'username': username,
                    'src_ip': source_ip,
                    'source_ip': source_ip,
                    'providers': providers,
                    'domains': domains,
                    'note': 'DNS/web activity only; success/failure requires IdP or application audit logs.',
                },
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

        dns_alert = {
            'rule_id': 'NET_DNS_SUMMARY',
            'capabilityId': 9,
            'capabilityIds': [3, 9],
            'category': 'network',
            'severity': 'low',
            'description': (
                f'DNS monitor active: {len(display_dns_queries)} captured DNS query domain(s), '
                f'{len(dns_connections)} live DNS connections, '
                f'{len(resolvers)} configured resolver(s)'
            ),
            'source': 'network',
            'protocol': 'dns',
            'dst_port': 53,
            'query_type': self._dns_query_types.most_common(1)[0][0] if self._dns_query_types else '',
            'resolver': resolvers[0] if resolvers else '',
            'domain': dns_domains[0] if dns_domains else (resolvers[0] if resolvers else ''),
            'query': dns_domains[0] if dns_domains else (resolvers[0] if resolvers else ''),
            'dnsQuery': dns_domains[0] if dns_domains else (resolvers[0] if resolvers else ''),
            'dest_ip': dns_answer_ips[0] if dns_answer_ips else '',
            'dst_ip': dns_answer_ips[0] if dns_answer_ips else '',
            'blocked': False,
            'inbound': False,
            'raw_log': f'NET:DNS_SUMMARY captured_queries={display_dns_queries} live_dns={len(dns_connections)} resolvers={resolvers} domains={dns_domains}',
            'raw': {
                'captured_dns_queries': display_dns_queries,
                'dns_query_count': self._dns_query_interval_count,
                'query_type_counts': dict(self._dns_query_types),
                'dns_answer_map': display_dns_answer_map,
                'dns_answer_ips': dns_answer_ips[:50],
                'dns_connection_count': len(dns_connections),
                'resolvers': resolvers,
                'search_domains': search_domains,
                'resolver_hosts': resolver_hosts,
                'dns_domains': dns_domains,
                'dns_queries': dns_domains,
                'dns_peers': dns_peer_rows,
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        dns_accepted = self._enqueue_changed_summary(dns_alert, dns_alert['raw'])
        accepted.append(dns_accepted)
        if dns_accepted:
            with self._dns_lock:
                self._dns_query_interval_count = 0
                self._dns_query_types.clear()

        exposure_severity = 'medium' if risky_listener_ports else 'low'
        exposure_alert = {
            'rule_id': 'NET_EXPOSURE_SUMMARY',
            'category': 'network',
            'severity': exposure_severity,
            'description': (
                f'Network exposure scan: {len(listening_ports)} listening ports, '
                f'{len(risky_listener_ports)} review-worthy service port(s)'
            ),
            'source': 'network',
            'protocol': 'tcp',
            'dst_port': risky_listener_ports[0] if risky_listener_ports else (listening_ports[0] if listening_ports else None),
            'blocked': False,
            'inbound': True,
            'raw_log': f'NET:EXPOSURE_SUMMARY listening={listening_ports[:30]} risky={risky_listener_ports[:30]}',
            'raw': {
                'listening_ports': listening_ports[:50],
                'risky_ports': risky_listener_ports[:50],
                'listeners': listeners[:20],
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        accepted.append(self._enqueue_changed_summary(exposure_alert, {'listeners': summary_listeners}))

        suspicious_established = [
            c for c in summary_connections
            if int(c.get('remote_port') or 0) in SUSPICIOUS_PORTS
            or (c.get('remote_ip') and not _is_private(c['remote_ip']) and int(c.get('remote_port') or 0) not in WHITELIST_PORTS)
        ]
        threat_alert = {
            'rule_id': 'NET_THREAT_INTEL_SUMMARY',
            'capabilityId': 3,
            'capabilityIds': [3],
            'category': 'network',
            'subCategory': 'threat-intelligence-integration',
            'eventType': 'reputation_candidates',
            'severity': 'medium' if suspicious_established else 'low',
            'description': (
                f'Threat intelligence network scan: {len(suspicious_established)} connection(s) require reputation review'
            ),
            'source': 'network',
            'protocol': 'tcp',
            'src_ip': suspicious_established[0].get('remote_ip') if suspicious_established else None,
            'dst_port': suspicious_established[0].get('remote_port') if suspicious_established else None,
            'blocked': False,
            'inbound': False,
            'raw_log': (
                'NET:THREAT_INTEL_SUMMARY '
                f'candidates={[(c.get("remote_ip"), c.get("remote_port")) for c in suspicious_established[:10]]}'
            ),
            'raw': {
                'reputation_candidates': [_peer_summary(c) for c in suspicious_established[:20]],
            },
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        accepted.append(self._enqueue_changed_summary(threat_alert, {'connections': suspicious_established}))
        if all(accepted):
            self._last_observed_summary = observed_state
