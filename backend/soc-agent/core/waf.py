"""
WAF Module v2.0 — Smart Web Application Firewall
==================================================
Auto-detects ALL running web server ports on startup.
Starts a transparent HTTP proxy WAF for each detected port and inspects
requests for common web attacks (SQLi, XSS, RCE, path traversal, …).

Attacker IPs are blocked on THIS host's own firewall via the IPS module
(UFW / nftables on Linux, Windows Defender on Windows). The pfSense / OPNsense
IPS-webhook backend has been removed.
"""

import re
import time
import socket
import ssl
import logging
import platform
import threading
import subprocess
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request as _urllib_request, error as _urllib_error
from urllib.parse import parse_qsl, urlencode, unquote, urlsplit, urlunsplit

from . import fw_backend

logger = logging.getLogger('soc-agent.waf')
SYSTEM = platform.system()

# ── WAF Configuration ────────────────────────────────────────────────────────
WAF_PORT_OFFSET = 10000   # WAF proxy port = website port + 10000

# Ports to always EXCLUDE (not web apps — SSH, DB, DNS, mail, etc.)
_EXCLUDE_PORTS = frozenset([
    22, 23, 25, 53, 69, 110, 111, 143, 161, 162, 389,       # SSH, telnet, mail, DNS, SNMP, LDAP
    445, 465, 514, 587, 636, 993, 995, 1194, 1433, 1521,    # Samba, SMTP, syslog, MSSQL, Oracle
    1883, 2181, 3306, 3389, 4369, 5432, 5433,               # MQTT, Zookeeper, MySQL, RDP, RabbitMQ, Postgres
    5672, 6379, 7199, 9092, 9300, 11211,                    # RabbitMQ, Redis, Cassandra, Kafka, ES, Memcached
    27017, 27018,                                            # MongoDB wire protocol
])

# Fallback: scan these ports if dynamic discovery fails entirely
_FALLBACK_PORTS = [80, 443, 3000, 3001, 3002, 3003, 4000, 4200, 5000, 5050, 5173,
                   7000, 8000, 8008, 8080, 8081, 8082, 8083, 8084, 8085, 8086,
                   8088, 8090, 8100, 8200, 8300, 8400, 8443, 8500, 8600, 8700,
                   8800, 8888, 8889, 9000, 9001, 9090, 9091, 9200, 9300, 10000]

# ── Attack Detection Rules ────────────────────────────────────────────────────
_RULES = [
    # SQL Injection
    dict(id='WAF_SQLI', name='SQL Injection', sev='critical', attack_type='SQL Injection',
         pat=re.compile(
             r"('|\")(;|--|#|\*|\/\*|\bOR\b|\bAND\b|\bUNION\b|\bSELECT\b|\bDROP\b|\bINSERT\b|\bDELETE\b|\bUPDATE\b|\bEXEC\b|\bCAST\b|\bCONVERT\b)"
             r"|(\b(OR|AND)\s+\d+=\d+)"
             r"|(SLEEP\s*\(|BENCHMARK\s*\(|WAITFOR\s+DELAY|pg_sleep)"
             r"|(information_schema|sys\.tables|sysobjects)"
             r"|(--\s|;--|\bXP_|1=1|1\s*=\s*1)",
             re.IGNORECASE)),
    # XSS
    dict(id='WAF_XSS', name='Cross-Site Scripting (XSS)', sev='high', attack_type='XSS',
         pat=re.compile(
             r'<script[\s>]|</script>|javascript:|vbscript:|on(load|error|click|mouseover|focus|blur|submit|keydown|keyup|change|input|resize|scroll)\s*='
             r'|<iframe|<object|<embed|<link[^>]+href|<meta[^>]+http-equiv'
             r'|alert\s*\(|confirm\s*\(|prompt\s*\(|document\.cookie|document\.write|eval\s*\(',
             re.IGNORECASE)),
    # Command Injection
    dict(id='WAF_CMDI', name='Command Injection', sev='critical', attack_type='Command Injection',
         pat=re.compile(
             r'[;&|`$](\s*)(ls|cat|id|whoami|pwd|wget|curl|bash|sh|python|perl|php|nc|netcat|nmap|ping|echo|rm|mv|cp|chmod|chown|kill)\b'
            r'|(?:\|\||\&\&|;)\s*(?:ls|cat|id|whoami|pwd|wget|curl|bash|sh|python|perl|php|nc|netcat|nmap|ping|rm|chmod|chown|kill)\b'
             r'|`[^`]+`|\$\([^)]+\)',
             re.IGNORECASE)),
    # Path Traversal
    dict(id='WAF_PATH', name='Path Traversal', sev='high', attack_type='Directory Traversal',
         pat=re.compile(
             r'\.\./|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|%252e%252e|/etc/passwd|/etc/shadow|/windows/system32',
             re.IGNORECASE)),
    # XXE
    dict(id='WAF_XXE', name='XML External Entity (XXE)', sev='critical', attack_type='XXE',
         pat=re.compile(
             r'<!ENTITY|<!DOCTYPE[^>]*\[|SYSTEM\s+"[^"]*"',
             re.IGNORECASE)),
    # SSRF
    dict(id='WAF_SSRF', name='Server-Side Request Forgery (SSRF)', sev='high', attack_type='SSRF',
         pat=re.compile(
             r'(https?|ftp|file|gopher|dict|ldap)://(?:localhost|127\.0\.0\.|0\.0\.0\.0|169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)',
             re.IGNORECASE)),
    # Local / Remote File Inclusion
    dict(id='WAF_LFI', name='Local File Inclusion', sev='critical', attack_type='LFI',
         pat=re.compile(
             r'(?:file|php|zip|data|expect|phar)://|(?:/|%2f)(?:etc|proc|var|windows)(?:/|%2f)'
             r'|boot\.ini|win\.ini|/proc/self/(?:environ|fd)', re.IGNORECASE)),
    dict(id='WAF_RFI', name='Remote File Inclusion', sev='critical', attack_type='RFI',
         pat=re.compile(
             r'(?:include|require|template|page|file|path|url)\s*(?:=|%3d)\s*https?%?(?::|%3a)'
             r'|https?://[^\s&]+\.(?:php|phtml|phar|jsp|asp|aspx)(?:[?&#]|$)', re.IGNORECASE)),
    # Template injection / unsafe deserialization / web-shell uploads
    dict(id='WAF_SSTI', name='Server-Side Template Injection', sev='critical', attack_type='SSTI',
         pat=re.compile(r'\{\{[^}]{0,200}(?:config|class|mro|subclasses|system|popen)[^}]*\}\}|\$\{[^}]{0,200}\}', re.IGNORECASE)),
    dict(id='WAF_DESERIALIZE', name='Unsafe Deserialization', sev='critical', attack_type='Insecure Deserialization',
         pat=re.compile(r'(?:rO0AB|O:\d+:"[^"]+"|gASV[A-Za-z0-9+/]{8,}|aced0005)', re.IGNORECASE)),
    dict(id='WAF_WEBSHELL', name='Web Shell Upload', sev='critical', attack_type='Malicious File Upload',
         pat=re.compile(r'(?:filename\s*=\s*"?[^"]+\.(?:php\d?|phtml|phar|jsp|jspx|asp|aspx|ashx|cgi|pl|exe|dll))'
                        r'|<\?(?:php|=)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder\s*\(', re.IGNORECASE)),
    dict(id='WAF_CRLF', name='HTTP Response Splitting', sev='high', attack_type='CRLF Injection',
         pat=re.compile(r'(?:%0d|\\r)(?:%0a|\\n)(?:set-cookie|location|content-|x-[a-z-]+):', re.IGNORECASE)),
    # Log4Shell
    dict(id='WAF_LOG4J', name='Log4Shell', sev='critical', attack_type='Log4Shell',
         pat=re.compile(r'\$\{jndi:(ldap|rmi|dns|corba|iiop|nis|nds|http)s?://', re.IGNORECASE)),
    # Scanner / pentest UA
    dict(id='WAF_SCAN', name='Security Scanner', sev='medium', attack_type='Scanner',
         pat=re.compile(
             r'(sqlmap|nmap|nikto|masscan|nessus|acunetix|burpsuite|metasploit|nuclei|hydra|gobuster|dirbuster|wfuzz|ffuf)',
             re.IGNORECASE)),
]

def _scan_target(text: str, allowed_rule_ids=None):
    """Returns first matching rule or None."""
    for rule in _RULES:
        if allowed_rule_ids is not None and rule['id'] not in allowed_rule_ids:
            continue
        m = rule['pat'].search(text)
        if m:
            return rule, m.group(0)[:120]
    return None, None


class RequestPolicy:
    """Thread-safe Layer-7 limits used by every local WAF proxy."""

    def __init__(self, config=None):
        config = config or {}
        self.max_body = max(1024, int(config.get('waf_max_request_body_bytes', 10 * 1024 * 1024)))
        self.rate_limit = max(1, int(config.get('waf_rate_limit_per_minute', 300)))
        self.login_limit = max(1, int(config.get('waf_login_attempts_per_minute', 20)))
        self.allowed_methods = {str(v).upper() for v in config.get(
            'waf_allowed_methods', ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']
        )}
        self.blocked_extensions = {str(v).lower().lstrip('.') for v in config.get(
            'waf_blocked_upload_extensions',
            ['php', 'php3', 'php4', 'php5', 'phtml', 'phar', 'jsp', 'jspx', 'asp', 'aspx', 'ashx', 'cgi', 'pl', 'exe', 'dll'],
        )}
        self.login_pattern = re.compile(r'/(?:login|signin|auth|session|token)(?:[/?#]|$)', re.IGNORECASE)
        self._events = defaultdict(deque)
        self._lock = threading.Lock()

    def check(self, ip, method, path, headers, content_length):
        method = str(method).upper()
        if method not in self.allowed_methods:
            return ('WAF_METHOD', 'Disallowed HTTP Method', 'high', 'HTTP Method Violation', method, 405)
        if content_length > self.max_body:
            return ('WAF_SIZE', 'Oversized Request Body', 'high', 'Request Size Violation', str(content_length), 413)
        content_disposition = str(headers.get('Content-Disposition', ''))
        filename = re.search(r'filename\s*=\s*"?([^";]+)', content_disposition, re.IGNORECASE)
        if filename and filename.group(1).rsplit('.', 1)[-1].lower() in self.blocked_extensions:
            return ('WAF_UPLOAD', 'Dangerous File Upload', 'critical', 'Malicious File Upload', filename.group(1), 403)

        now = time.time()
        window = now - 60
        keys = [('all', ip, self.rate_limit)]
        if method == 'POST' and self.login_pattern.search(path):
            keys.append(('login', ip, self.login_limit))
        with self._lock:
            for kind, address, limit in keys:
                bucket = self._events[(kind, address)]
                while bucket and bucket[0] < window:
                    bucket.popleft()
                if len(bucket) >= limit:
                    name = 'Login Brute Force' if kind == 'login' else 'HTTP Rate Limit Exceeded'
                    attack = 'Credential Stuffing / Brute Force' if kind == 'login' else 'Layer-7 HTTP Flood'
                    return ('WAF_RATE', name, 'high', attack, f'{len(bucket)}/minute', 429)
            for kind, address, _ in keys:
                self._events[(kind, address)].append(now)
        return None

def _is_private(ip: str) -> bool:
    return ip.startswith((
        '10.', '192.168.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.',
        '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.',
        '127.', '::1', 'fc', 'fd', '169.254.',
    ))


_SENSITIVE_QUERY_KEYS = {
    'access_token', 'api_key', 'apikey', 'authorization', 'client_secret',
    'code', 'cookie', 'jwt', 'password', 'passwd', 'refresh_token', 'secret',
    'session', 'token',
}


def _sanitize_request_target(value: str) -> str:
    """Keep route evidence while preventing credentials in query strings."""
    try:
        parsed = urlsplit(str(value or '/'))
        query = urlencode([
            (key, '[REDACTED]' if key.lower().replace('-', '_') in _SENSITIVE_QUERY_KEYS else item)
            for key, item in parse_qsl(parsed.query, keep_blank_values=True)
        ])
        return urlunsplit(('', '', parsed.path or '/', query, ''))[:2000]
    except Exception:
        return str(value or '/').split('#', 1)[0][:2000]


# ── Dynamic port discovery helpers ───────────────────────────────────────────
def _port_from_netstat_endpoint(endpoint: str):
    """Extract a TCP port from Linux, Windows, or macOS netstat endpoints."""
    match = re.search(r'(?:\.|:)(\d+)$', (endpoint or '').strip())
    if not match:
        return None
    port = int(match.group(1))
    return port if 1 <= port <= 65535 else None


def _listening_ports_from_netstat(output: str) -> set:
    """Parse the local endpoint from native netstat LISTEN/LISTENING rows."""
    ports = set()
    for line in output.splitlines():
        fields = line.split()
        state_index = next(
            (index for index, field in enumerate(fields)
             if field.upper().startswith('LISTEN')),
            None,
        )
        # Linux, macOS, and Windows all place the local endpoint two columns
        # before the listening state: protocol, local, remote, state.
        if state_index is None or state_index < 2:
            continue
        port = _port_from_netstat_endpoint(fields[state_index - 2])
        if port:
            ports.add(port)
    return ports


def _get_all_listening_tcp_ports() -> list:
    """
    Discover ALL TCP ports currently listening on this machine.
    Strategy (fastest to most portable):
      1. `ss -tlnH`  — modern Linux (iproute2)
    2. native `netstat` — Linux, Windows, and macOS
      3. /proc/net/tcp + /proc/net/tcp6 — Linux kernel, no external tools needed
      4. Fallback sweep on _FALLBACK_PORTS
    Returns a sorted list of unique integer port numbers.
    """
    ports = set()

    # psutil is already an agent dependency and works consistently on Linux,
    # Windows and macOS, including systems without ss/netstat in PATH.
    try:
        import psutil
        ports.update(
            int(conn.laddr.port)
            for conn in psutil.net_connections(kind='tcp')
            if conn.status == 'LISTEN' and conn.laddr and conn.laddr.port
        )
        if ports:
            return sorted(ports)
    except Exception:
        pass

    # ── Method 1: ss ──────────────────────────────────────────────────────────
    try:
        out = subprocess.check_output(
            ['ss', '-tlnH'],
            stderr=subprocess.DEVNULL, timeout=5
        ).decode('utf-8', errors='replace')
        for line in out.splitlines():
            # Format: LISTEN 0  128  0.0.0.0:8080  0.0.0.0:*  ...
            parts = line.split()
            for part in parts:
                if ':' in part:
                    port_str = part.rsplit(':', 1)[-1]
                    if port_str.isdigit():
                        ports.add(int(port_str))
        if ports:
            logger.debug('[WAF] ss found %d listening ports', len(ports))
            return sorted(ports)
    except Exception:
        pass

    # ── Method 2: native netstat ─────────────────────────────────────────────
    netstat_commands = {
        'Windows': (['netstat', '-an', '-p', 'TCP'],),
        'Darwin': (['netstat', '-an', '-p', 'tcp'], ['netstat', '-an']),
    }.get(SYSTEM, (['netstat', '-tlnp'], ['netstat', '-an', '-p', 'tcp']))
    for command in netstat_commands:
        try:
            out = subprocess.check_output(
                command, stderr=subprocess.DEVNULL, timeout=5
            ).decode('utf-8', errors='replace')
            ports.update(_listening_ports_from_netstat(out))
            if ports:
                logger.debug('[WAF] netstat found %d listening ports', len(ports))
                return sorted(ports)
        except Exception:
            continue

    # ── Method 3: /proc/net/tcp + tcp6 (Linux only, no tools needed) ─────────
    try:
        if SYSTEM != 'Linux':
            raise FileNotFoundError('/proc/net/tcp is only available on Linux')
        for proc_file in ('/proc/net/tcp', '/proc/net/tcp6'):
            try:
                with open(proc_file, 'r') as f:
                    for line in f.readlines()[1:]:  # skip header
                        parts = line.strip().split()
                        if len(parts) < 4:
                            continue
                        # State 0A = LISTEN
                        if parts[3] != '0A':
                            continue
                        # local_address hex: 0100007F:1F90 → 127.0.0.1:8080
                        hex_port = parts[1].rsplit(':', 1)[-1]
                        ports.add(int(hex_port, 16))
            except FileNotFoundError:
                pass
        if ports:
            logger.debug('[WAF] /proc/net found %d listening ports', len(ports))
            return sorted(ports)
    except Exception:
        pass

    # ── Method 4: fallback sweep ──────────────────────────────────────────────
    logger.warning('[WAF] Dynamic discovery failed — using fallback port sweep')
    return list(_FALLBACK_PORTS)


def _local_probe_addresses():
    addresses = {(socket.AF_INET, '127.0.0.1'), (socket.AF_INET6, '::1')}
    try:
        import psutil
        for rows in psutil.net_if_addrs().values():
            for row in rows:
                if row.family in (socket.AF_INET, socket.AF_INET6):
                    address = str(row.address or '').split('%', 1)[0]
                    if address:
                        addresses.add((row.family, address))
    except Exception:
        pass
    return sorted(addresses, key=lambda item: (item[0], item[1]))


def _is_http_service(port: int, timeout: float = 1.2) -> bool:
    """
    Probe a port to confirm it speaks HTTP — PARALLEL IPv4 + IPv6 check.
    This handles:
      - Vite/React dev servers that ONLY listen on ::1 (IPv6)
      - Express/Node that listen on 0.0.0.0 (IPv4 + IPv6)
      - Traditional servers on IPv4 only
    Returns True if ANY stack (IPv4 or IPv6) returns a valid HTTP response.
    """
    result = [False]
    lock   = threading.Lock()

    def _probe(family, addr, use_tls=False):
        try:
            s = socket.socket(family, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((addr, port))
            if use_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                s = context.wrap_socket(s, server_hostname='localhost')
                s.settimeout(timeout)
            s.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\nConnection: close\r\n\r\n')
            raw = s.recv(512)
            s.close()
            r = raw.decode('utf-8', errors='replace').upper()
            # Match any valid HTTP response (200, 301, 302, 400, 401, 403, 404, 500 all OK)
            if (r.startswith('HTTP/') or 'SERVER:' in r
                    or 'CONTENT-TYPE:' in r or 'LOCATION:' in r
                    or 'WWW-AUTHENTICATE:' in r or 'X-POWERED-BY:' in r):
                with lock:
                    result[0] = True
        except Exception:
            pass

    probe_targets = _local_probe_addresses()
    # Try both application protocols: TLS is not limited to port 443 and HTTP
    # can run on any port. This also covers HTTPS on 8443/9443/custom ports.
    probes = [
        threading.Thread(target=_probe, args=(family, addr, use_tls), daemon=True)
        for family, addr in probe_targets
        for use_tls in (False, True)
    ]
    for t in probes: t.start()
    for t in probes: t.join(timeout=timeout + 0.3)
    return result[0]


def _monitored_service_inventory(ports) -> list:
    wanted = {int(port) for port in ports or []}
    rows = []
    process_cache = {}
    try:
        import psutil
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status != 'LISTEN' or not conn.laddr or int(conn.laddr.port) not in wanted:
                continue
            process = {'processName': '', 'executable': '', 'username': ''}
            if conn.pid:
                if conn.pid not in process_cache:
                    try:
                        proc = psutil.Process(conn.pid)
                        process_cache[conn.pid] = {
                            'processName': proc.name() or '',
                            'executable': proc.exe() or '',
                            'username': proc.username() or '',
                        }
                    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                        process_cache[conn.pid] = process
                process = process_cache[conn.pid]
            port = int(conn.laddr.port)
            rows.append({
                'port': port,
                'protocol': 'tcp',
                'scheme': 'https' if port in (443, 8443, 9443) else 'http',
                'bindAddress': conn.laddr.ip or '',
                'pid': conn.pid,
                **process,
            })
    except Exception as exc:
        logger.debug('[WAF] service inventory unavailable: %s', exc)
    return rows


# ── Per-port WAF proxy handler factory ───────────────────────────────────────
def _make_handler(target_host: str, target_port: int, on_detect, on_request=None, policy=None):
    """Create a WAFRequestHandler class bound to a specific backend."""

    class WAFRequestHandler(BaseHTTPRequestHandler):
        log_message = lambda *_: None  # suppress default logging

        def do_request(self, method):
            started_at = time.monotonic()
            src_ip = self.client_address[0]
            path   = _sanitize_request_target(self.path)

            # Read body (for POST/PUT)
            body = b''
            cl = self.headers.get('Content-Length')
            try:
                content_length = int(cl or 0)
            except ValueError:
                content_length = policy.max_body + 1 if policy else 0

            violation = policy.check(src_ip, method, path, self.headers, content_length) if policy else None
            if violation:
                rule_id, name, sev, attack_type, matched, status = violation
                on_detect({'src_ip': src_ip, 'rule_id': rule_id, 'name': name, 'sev': sev,
                           'attack_type': attack_type, 'surface': 'http', 'matched': matched,
                           'path': path, 'method': method}, path, method)
                response = f'<html><body><h1>{status} Blocked</h1></body></html>'.encode()
                self.send_response(status)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(response)))
                self.end_headers()
                self.wfile.write(response)
                return
            if cl:
                try:
                    body = self.rfile.read(int(cl))
                except Exception:
                    pass

            # ── INSPECT ──────────────────────────────────────────────────────
            request_targets = [unquote(path)]
            if body:
                try:
                    request_targets.append(body.decode('utf-8', errors='replace')[:2000])
                except Exception:
                    pass

            # SSRF belongs to user-controlled URL/body values. A normal browser
            # Referer such as http://localhost:<waf-port> must never trigger it.
            rule, matched = _scan_target(' '.join(request_targets))
            if not rule:
                user_agent = self.headers.get('User-Agent', '')
                rule, matched = _scan_target(user_agent, {'WAF_SCAN'})
            if not rule:
                cookie = self.headers.get('Cookie', '')
                rule, matched = _scan_target(cookie, {
                    'WAF_SQLI', 'WAF_XSS', 'WAF_CMDI', 'WAF_PATH', 'WAF_LOG4J'
                })

            if rule:
                on_detect({
                    'src_ip':      src_ip,
                    'rule_id':     rule['id'],
                    'name':        rule['name'],
                    'sev':         rule['sev'],
                    'attack_type': rule['attack_type'],
                    'surface':     'http',
                    'matched':     matched or '',
                    'path':        path,
                    'method':      method,
                }, path, method)
                # 403 response
                body403 = b'<html><body><h1>403 Forbidden</h1><p>Request blocked by SOC4 WAF.</p></body></html>'
                self.send_response(403)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(body403)))
                self.end_headers()
                self.wfile.write(body403)
                return

            # ── FORWARD to backend ────────────────────────────────────────────
            try:
                url = f'http://{target_host}:{target_port}{path}'
                req = _urllib_request.Request(url, data=body or None, method=method)
                for k, v in self.headers.items():
                    if k.lower() not in ('host', 'connection', 'content-length'):
                        req.add_header(k, v)
                req.add_header('X-Real-IP', src_ip)
                req.add_header('X-SOC4-WAF', '1')
                with _urllib_request.urlopen(req, timeout=30) as resp:
                    response_status = resp.status
                    self.send_response(resp.status)
                    for k, v in resp.headers.items():
                        if k.lower() not in ('transfer-encoding', 'connection'):
                            self.send_header(k, v)
                    resp_body = resp.read()
                    self.send_header('Content-Length', str(len(resp_body)))
                    self.end_headers()
                    self.wfile.write(resp_body)
                if on_request:
                    on_request({
                        'src_ip': src_ip, 'path': path, 'method': method,
                        'status_code': response_status,
                        'request_size': len(body), 'response_size': len(resp_body),
                        'response_time_ms': round((time.monotonic() - started_at) * 1000, 2),
                        'target_port': target_port,
                    })
            except _urllib_error.HTTPError as e:
                response_body = e.read() if hasattr(e, 'read') else b''
                self.send_response(e.code)
                for k, v in (e.headers.items() if e.headers else []):
                    if k.lower() not in ('transfer-encoding', 'connection', 'content-length'):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(response_body)))
                self.end_headers()
                if method != 'HEAD':
                    self.wfile.write(response_body)
                if on_request:
                    on_request({
                        'src_ip': src_ip, 'path': path, 'method': method,
                        'status_code': e.code,
                        'request_size': len(body), 'response_size': len(response_body),
                        'response_time_ms': round((time.monotonic() - started_at) * 1000, 2),
                        'target_port': target_port,
                    })
            except _urllib_error.URLError as e:
                err_body = f'<html><body><h1>502 Bad Gateway</h1><p>{e}</p></body></html>'.encode()
                self.send_response(502)
                self.send_header('Content-Type', 'text/html')
                self.send_header('Content-Length', str(len(err_body)))
                self.end_headers()
                self.wfile.write(err_body)
                if on_request:
                    on_request({
                        'src_ip': src_ip, 'path': path, 'method': method,
                        'status_code': 502,
                        'request_size': len(body), 'response_size': len(err_body),
                        'response_time_ms': round((time.monotonic() - started_at) * 1000, 2),
                        'target_port': target_port, 'backend_error': str(e)[:300],
                    })
            except Exception as e:
                logger.debug('[WAF] forward error: %s', e)

        def do_GET(self):     self.do_request('GET')
        def do_POST(self):    self.do_request('POST')
        def do_PUT(self):     self.do_request('PUT')
        def do_DELETE(self):  self.do_request('DELETE')
        def do_PATCH(self):   self.do_request('PATCH')
        def do_HEAD(self):    self.do_request('HEAD')
        def do_OPTIONS(self): self.do_request('OPTIONS')

    return WAFRequestHandler


# ── WAF Module ────────────────────────────────────────────────────────────────
class Module:
    """Smart WAF — auto-detects web ports, starts proxy for each."""

    def __init__(self, sender, ips=None, config=None):
        self._sender  = sender
        self._ips     = ips
        self._config  = config

        self._company_id    = config.get('company_id',    '') if config else ''
        self._department_id = config.get('department_id', '') if config else ''
        self._system_id     = config.get('system_id',     '') if config else ''
        # Discovery/monitoring and reverse-proxy enforcement are separate.
        # Configuring a monitored port must never create another listener.
        configured_ports = config.get('waf_monitor_ports', []) if config else []
        self._monitor_ports = {
            int(port) for port in configured_ports
            if str(port).isdigit() and 1 <= int(port) <= 65535
        }
        self._proxy_enabled = bool(config.get('waf_proxy_enabled', False)) if config else False
        self._intercept = bool(config.get('waf_intercept', False)) and self._proxy_enabled if config else False
        self._request_policy = RequestPolicy(config)

        self._proxies     = {}   # port → HTTPServer
        self._agent_ip    = ''   # detected on start()
        self._cooldown    = {}   # ip → last block time
        self._cooldown_lock = threading.Lock()
        self._detected_ports = []

    # ── Startup ───────────────────────────────────────────────────────────────
    def start(self):
        self._agent_ip = self._get_agent_ip()
        logger.info('[WAF] Starting smart WAF v2.0 — agent IP: %s — scanning ports…', self._agent_ip)
        self._detected_ports = self._find_web_ports()
        if self._config.get('waf_direct_block_enabled', True):
            fw_backend.ensure_suricata_nfqueue_ports(
                self._detected_ports,
                self._config.get('suricata_nfqueue', 0),
            )

        if not self._detected_ports:
            logger.warning('[WAF] No web services detected — WAF in standby. Re-scan every 5 min.')
        else:
            logger.info('[WAF] Detected web services on ports: %s', self._detected_ports)
            if self._proxy_enabled:
                for port in self._detected_ports:
                    self._start_proxy(port)
            else:
                # Remove redirects left by older agent versions. Monitoring
                # must observe the real service port without a shadow listener.
                for port in self._detected_ports:
                    fw_backend.remove_redirect(port)

        self._report_status('startup')

        # Background re-scan
        t = threading.Thread(target=self._rescan_loop, daemon=True, name='waf-rescan')
        t.start()

    def _find_web_ports(self) -> list:
        """
        Return every real TCP listening port for automatic AJNAT monitoring.
        Company-selected external WAF ports are tracked by the backend bridge.
        No HTTP proxy/listener is created.
        """
        all_listening = _get_all_listening_tcp_ports()
        logger.info('[WAF] System has %d total listening TCP ports: %s', len(all_listening), all_listening)

        if self._monitor_ports:
            result = sorted(port for port in all_listening if port in self._monitor_ports)
        else:
            candidates = [port for port in all_listening if port not in _EXCLUDE_PORTS]
            with ThreadPoolExecutor(max_workers=min(16, max(1, len(candidates)))) as pool:
                checks = dict(zip(candidates, pool.map(_is_http_service, candidates)))
            result = sorted(port for port, is_http in checks.items() if is_http)
        logger.info('[WAF] Monitoring %d real listening ports: %s', len(result), result)
        return result

    def _start_proxy(self, original_port: int):
        if original_port in self._proxies:
            return
        waf_port = original_port + WAF_PORT_OFFSET
        try:
            handler = _make_handler(
                '127.0.0.1', original_port, self.on_detection,
                self.on_request, self._request_policy,
            )
            server  = HTTPServer(('0.0.0.0', waf_port), handler)
            self._proxies[original_port] = server
            t = threading.Thread(
                target=server.serve_forever,
                daemon=True, name=f'waf-proxy-{original_port}'
            )
            t.start()
            logger.info('[WAF] Proxy started: port %d → WAF %d', original_port, waf_port)
            # Apply iptables redirect
            self._apply_iptables(original_port, waf_port)
        except Exception as e:
            logger.warning('[WAF] Cannot start proxy for port %d: %s', original_port, e)

    def _apply_iptables(self, original: int, waf: int):
        """Transparently redirect inbound traffic to the WAF proxy via nftables.
        Opt-in via config `waf_intercept: true`. When off, the WAF runs in
        detection mode and still blocks attacker IPs on the host firewall.
        """
        if not self._intercept:
            return
        fw_backend.remove_redirect(original)
        if fw_backend.redirect_port(original, waf):
            logger.info('[WAF] nftables redirect active: :%d → WAF :%d', original, waf)
        else:
            logger.warning('[WAF] could not install nftables redirect for :%d', original)

    def _remove_iptables(self, original: int):
        if self._intercept:
            fw_backend.remove_redirect(original)

    @staticmethod
    def _get_agent_ip() -> str:
        """Detect this agent's LAN IP — sent to IPS Server so pfSense/OPNsense
        can create NAT port forward: WAN:port → agentIP:wafPort.
        """
        try:
            # Connect to a known external address to find our outbound interface IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return socket.gethostbyname(socket.gethostname())

    def _rescan_loop(self):
        while True:
            interval = max(15, int(self._config.get('waf_rescan_interval_seconds', 60) or 60))
            time.sleep(interval)
            try:
                new_ports = self._find_web_ports()
                added = [p for p in new_ports if p not in self._detected_ports]
                if added and self._proxy_enabled:
                    logger.info('[WAF] New web services detected: %s', added)
                    for p in added:
                        self._start_proxy(p)
                self._detected_ports = new_ports
                if self._config.get('waf_direct_block_enabled', True):
                    fw_backend.ensure_suricata_nfqueue_ports(
                        self._detected_ports,
                        self._config.get('suricata_nfqueue', 0),
                    )
                self._report_status('heartbeat')
            except Exception as e:
                logger.debug('[WAF] rescan error: %s', e)

    def _report_status(self, action: str):
        """Register this installed agent with the company WAF dashboard."""
        self._sender.enqueue({
            'rule_id': 'WAF_AGENT_STATUS',
            'capabilityId': 20,
            'capabilityIds': [20, 24],
            'category': 'network',
            'severity': 'low',
            'description': 'AJNAT WAF {} — {} web service(s) detected'.format(
                action, len(self._detected_ports)
            ),
            'source': 'waf',
            'action': action,
            'agent_ip': self._agent_ip,
            'detected_ports': list(self._detected_ports),
            'monitored_services': _monitored_service_inventory(self._detected_ports),
            'waf_proxy_enabled': self._proxy_enabled,
            'waf_intercept': self._intercept,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': 'WAF_AGENT_STATUS',
        })

    def stop(self):
        for port, server in self._proxies.items():
            server.shutdown()
            fw_backend.remove_redirect(port)
        self._proxies.clear()
        logger.info('[WAF] Stopped all WAF proxies')

    # ── Detection callback ────────────────────────────────────────────────────
    def on_detection(self, finding: dict, request_path: str, method: str):
        src_ip      = finding.get('src_ip', '')
        rule_id     = finding.get('rule_id', 'WAF_UNKNOWN')
        name        = finding.get('name', 'Unknown Attack')
        sev         = finding.get('sev', 'high')
        attack_type = finding.get('attack_type', name)
        matched     = finding.get('matched', '')
        path        = finding.get('path', request_path)

        description = (
            f'WAF BLOCKED: {name} from {src_ip} — '
            f'{method} {path[:100]} (matched={matched[:60]})'
        )

        # Alert → SOC dashboard
        self._sender.enqueue({
            'rule_id':        rule_id,
            'capabilityId':   20,
            'capabilityIds':  [3, 20],
            'category':       'network',
            'severity':       sev,
            'description':    description,
            'src_ip':         src_ip,
            'blocked':        True,
            'attackType':     attack_type,
            'requestPath':    _sanitize_request_target(path),
            'url':            _sanitize_request_target(path),
            'method':         method,
            'httpMethod':     method,
            'matched':        matched,
            'statusCode':     int(finding.get('status_code') or 403),
            'responseTime':   finding.get('response_time_ms'),
            'userAction':     'web_attack',
            'mitreTechnique': 'T1190',
            'raw_log':        description,
            'timestamp':      datetime.now(timezone.utc).isoformat(),
            'type':           'WAF_ALERT',
            'company_id':     self._company_id,
            'department_id':  self._department_id,
            'system_id':      self._system_id,
        })

        # Cooldown per IP (60s)
        now = time.time()
        with self._cooldown_lock:
            if now - self._cooldown.get(src_ip, 0) < 60:
                return
            self._cooldown[src_ip] = now

        if src_ip and _is_private(src_ip):
            return

        # Block the attacker on the local host firewall via the IPS module
        if self._ips and src_ip:
            self._ips.block_ip(
                src_ip,
                reason=f'WAF auto-block: {name}',
                threat_level=sev,
                attack_type=attack_type,
            )
        elif src_ip:
            logger.warning('[WAF] No IPS module loaded — %s detected but not blocked', src_ip)

        logger.warning('[WAF] BLOCKED %s from %s — %s', attack_type, src_ip, path[:80])

    def on_request(self, event: dict):
        """Publish every request observed by the opt-in local reverse proxy."""
        path = _sanitize_request_target(event.get('path', '/'))
        status_code = int(event.get('status_code') or 0)
        latency = float(event.get('response_time_ms') or 0)
        severity = 'high' if status_code >= 500 else 'medium' if status_code in (401, 403, 429) else 'low'
        self._sender.enqueue({
            'rule_id': 'API_CALL_TELEMETRY',
            'capabilityId': 20,
            'capabilityIds': [20],
            'category': 'network',
            'eventType': 'api_request',
            'severity': severity,
            'description': '{} {} returned HTTP {} in {:.2f} ms'.format(
                event.get('method', 'UNKNOWN'), path, status_code, latency,
            ),
            'source': 'ajnat-waf-proxy',
            'src_ip': event.get('src_ip', ''),
            'url': path,
            'requestPath': path,
            'method': event.get('method', 'UNKNOWN'),
            'httpMethod': event.get('method', 'UNKNOWN'),
            'statusCode': status_code,
            'responseTime': latency,
            'requestSize': int(event.get('request_size') or 0),
            'responseSize': int(event.get('response_size') or 0),
            'dst_port': int(event.get('target_port') or 0),
            'backendError': event.get('backend_error'),
            'blocked': False,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type': 'API_CALL_TELEMETRY',
            'company_id': self._company_id,
            'department_id': self._department_id,
            'system_id': self._system_id,
        })
