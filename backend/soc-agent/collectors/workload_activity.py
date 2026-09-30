"""Low-volume activity monitoring for common web/application/database logs."""

from __future__ import annotations

import glob
import logging
import os
import platform
import re
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit

logger = logging.getLogger('soc-agent.collector.workload-activity')

LINUX_SOURCES = {
    'nginx': ['/var/log/nginx/access.log', '/var/log/nginx/error.log'],
    'apache': ['/var/log/apache2/access.log', '/var/log/apache2/error.log', '/var/log/httpd/access_log', '/var/log/httpd/error_log'],
    'tomcat': ['/var/log/tomcat*/catalina.out', '/opt/tomcat/logs/catalina.out'],
    'node': ['/var/log/nodejs/*.log', '/var/log/pm2/*.log'],
    'php': ['/var/log/php*-fpm.log', '/var/log/php-fpm/*.log'],
    'java': ['/var/log/java/*.log'],
    'mysql': ['/var/log/mysql/error.log', '/var/log/mysqld.log'],
    'postgresql': ['/var/log/postgresql/postgresql-*.log'],
    'mongodb': ['/var/log/mongodb/mongod.log'],
}

WINDOWS_SOURCES = {
    'iis': [r'C:\inetpub\logs\LogFiles\W3SVC*\u_ex*.log'],
    'mssql': [r'C:\Program Files\Microsoft SQL Server\MSSQL*\MSSQL\Log\ERRORLOG*'],
    'mysql': [r'C:\ProgramData\MySQL\MySQL Server *\Data\*.err'],
    'postgresql': [r'C:\Program Files\PostgreSQL\*\data\log\*.log'],
    'tomcat': [r'C:\Program Files\Apache Software Foundation\Tomcat *\logs\catalina*.log'],
}

MACOS_SOURCES = {
    'nginx': ['/usr/local/var/log/nginx/*.log', '/opt/homebrew/var/log/nginx/*.log'],
    'apache': ['/var/log/apache2/*.log'],
    'mysql': ['/usr/local/var/mysql/*.err', '/opt/homebrew/var/mysql/*.err'],
    'postgresql': ['/usr/local/var/log/postgresql*.log', '/opt/homebrew/var/log/postgresql*.log'],
}

WEB_ATTACK = re.compile(r'(?:\.\./|%2e%2e|union(?:\s|%20)+select|select(?:\s|%20)+.+from|<script|%3cscript|javascript:|/etc/passwd|cmd=|powershell|jndi:|/wp-admin|/\.env|/bin/(?:sh|bash)|\b(?:wget|curl)\b.+https?://|(?:upload|filename=).+\.(?:php|jsp|aspx|war))', re.I)
WEB_ERROR = re.compile(r'\s(?:4\d\d|5\d\d)\s')
DB_SECURITY = re.compile(r'authentication fail|password authentication failed|access denied for user|login failed|permission denied|role .* does not exist|deadlock|too many connections', re.I)
APP_ERROR = re.compile(r'\b(?:fatal|panic|critical|exception|stack trace|segmentation fault)\b', re.I)
COMBINED_LOG = re.compile(
    r'^(?P<src>\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(?P<method>[A-Z]+)\s+(?P<url>\S+)\s+[^\"]+"\s+'
    r'(?P<status>\d{3})\s+(?P<size>\S+)(?:\s+"(?P<referrer>[^\"]*)"\s+"(?P<user_agent>[^\"]*)")?'
)
SENSITIVE_QUERY_KEYS = {'access_token', 'api_key', 'apikey', 'authorization', 'client_secret', 'code', 'jwt', 'password', 'passwd', 'refresh_token', 'secret', 'session', 'token'}


def _safe_request_url(value):
    try:
        parsed = urlsplit(str(value or '/'))
        query = urlencode([(key, '[REDACTED]' if key.lower().replace('-', '_') in SENSITIVE_QUERY_KEYS else item) for key, item in parse_qsl(parsed.query, keep_blank_values=True)])
        return urlunsplit(('', '', parsed.path or '/', query, ''))[:2000]
    except Exception:
        return str(value or '/').split('#', 1)[0][:2000]


class WorkloadActivityCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._positions = {}
        self._counts = Counter()
        self._web_counts = Counter()
        self._web_methods = Counter()
        self._web_statuses = Counter()
        self._web_paths = Counter()
        self._web_sources = Counter()
        self._web_response_bytes = 0
        self._iis_fields = {}
        self._last_summary = 0.0
        self._thread = threading.Thread(target=self._loop, daemon=True, name='workload-logs')

    def start(self):
        self._thread.start()

    def _sources(self):
        system = platform.system()
        sources = WINDOWS_SOURCES if system == 'Windows' else MACOS_SOURCES if system == 'Darwin' else LINUX_SOURCES
        result = {role: list(patterns) for role, patterns in sources.items()}
        configured = self._config.get('web_log_paths') or []
        if isinstance(configured, str):
            configured = [configured]
        if configured:
            result.setdefault('web', []).extend(str(path) for path in configured if path)
        return result

    def _discover(self):
        found = []
        for role, patterns in self._sources().items():
            for pattern in patterns:
                for path in glob.glob(pattern):
                    if os.path.isfile(path):
                        found.append((role, path))
        return found

    def _read_new(self, path):
        try:
            size = os.path.getsize(path)
            if path not in self._positions:
                self._positions[path] = size
                return []
            position = self._positions[path]
            if size < position:
                position = 0
            with open(path, 'r', encoding='utf-8', errors='replace') as handle:
                handle.seek(position)
                lines = handle.readlines(1024 * 1024)
                self._positions[path] = handle.tell()
            return [line.rstrip()[:4000] for line in lines]
        except (OSError, PermissionError):
            return []

    def _parse_web_line(self, role, path, line):
        if role not in {'nginx', 'apache', 'iis', 'tomcat', 'node', 'nodejs', 'php', 'python', 'java', 'web'}:
            return None
        if role == 'iis':
            if line.startswith('#Fields:'):
                self._iis_fields[path] = line.partition(':')[2].strip().split()
                return None
            fields = self._iis_fields.get(path)
            if fields and line and not line.startswith('#'):
                values = line.split()
                row = dict(zip(fields, values))
                method = row.get('cs-method')
                target = row.get('cs-uri-stem')
                if method and target:
                    query = row.get('cs-uri-query')
                    return {
                        'source_ip': row.get('c-ip', ''), 'method': method,
                        'url': target + (f'?{query}' if query and query != '-' else ''),
                        'status': row.get('sc-status', ''), 'response_size': row.get('sc-bytes', ''),
                        'request_size': row.get('cs-bytes', ''), 'response_time': row.get('time-taken', ''),
                        'user_agent': str(row.get('cs(User-Agent)', '')).replace('+', ' '),
                        'referrer': row.get('cs(Referer)', ''), 'username': row.get('cs-username', ''),
                    }
            return None
        match = COMBINED_LOG.search(line)
        if not match:
            return None
        return {
            'source_ip': match.group('src'), 'method': match.group('method'),
            'url': match.group('url'), 'status': match.group('status'),
            'response_size': match.group('size'), 'request_size': '', 'response_time': '',
            'user_agent': match.group('user_agent') or '', 'referrer': match.group('referrer') or '',
            'username': '',
        }

    def _record_web_request(self, role, request):
        request['url'] = _safe_request_url(request.get('url'))
        self._web_counts[role] += 1
        self._web_methods[request.get('method') or 'UNKNOWN'] += 1
        self._web_statuses[request.get('status') or 'UNKNOWN'] += 1
        self._web_paths[request.get('url') or '/'] += 1
        if request.get('source_ip'):
            self._web_sources[request['source_ip']] += 1
        try:
            self._web_response_bytes += max(0, int(request.get('response_size') or 0))
        except (TypeError, ValueError):
            pass

    def _emit_api_request(self, role, path, request):
        """Send one normalized capability-20 event per access-log request."""
        target = _safe_request_url(request.get('url'))
        try:
            status_code = int(request.get('status') or 0)
        except (TypeError, ValueError):
            status_code = 0
        severity = 'high' if status_code >= 500 else 'medium' if status_code in (401, 403, 429) else 'low'
        self._sender.enqueue({
            'rule_id': 'API_CALL_TELEMETRY', 'capabilityId': 20, 'capabilityIds': [20],
            'category': 'network', 'severity': severity, 'source': f'{role}_access_log',
            'description': f"{request.get('method') or 'UNKNOWN'} {target} returned HTTP {status_code or 'unknown'}",
            'eventType': 'api_request', 'evidence_type': 'native_web_access_log',
            'source_path': path, 'src_ip': request.get('source_ip'), 'url': target,
            'requestPath': target, 'http_method': request.get('method'), 'statusCode': status_code,
            'response_time': request.get('response_time'), 'request_size': request.get('request_size'),
            'response_size': request.get('response_size'), 'user_agent': request.get('user_agent'),
            'referrer': _safe_request_url(request.get('referrer')) if request.get('referrer') else '',
            'username': request.get('username'), 'backendService': role,
            'raw': {'workload_type': role, 'source_path': path},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    @staticmethod
    def _web_threat(line):
        value = str(line or '')
        if re.search(r'union(?:\s|%20)+select|select(?:\s|%20)+.+from', value, re.I):
            return 'SQL Injection', 'T1190'
        if re.search(r'<script|%3cscript|javascript:', value, re.I):
            return 'Cross-Site Scripting', 'T1189'
        if re.search(r'\.\./|%2e%2e|/etc/passwd', value, re.I):
            return 'Path Traversal', 'T1190'
        if re.search(r'(?:upload|filename=).+\.(?:php|jsp|aspx|war)', value, re.I):
            return 'Web Shell Upload', 'T1505.003'
        if re.search(r'cmd=|powershell|/bin/(?:sh|bash)|\b(?:wget|curl)\b.+https?://', value, re.I):
            return 'Command Injection', 'T1059'
        return 'Suspicious Web Request', 'T1190'

    def _emit_alert(self, role, path, line, kind, request=None):
        if kind == 'attack':
            label, mitre = self._web_threat(line)
            rule, severity = 'PROC_WEB_ATTACK_ACTIVITY', 'high'
        elif kind == 'database':
            rule, severity, label, mitre = 'PROC_DATABASE_SECURITY_ACTIVITY', 'medium', 'Database authentication/security event', 'T1110'
        else:
            rule, severity, label, mitre = 'PROC_APPLICATION_ERROR_ACTIVITY', 'medium', 'Application error activity', 'T1499'
        web_role = role in {'nginx', 'apache', 'iis', 'tomcat', 'node', 'nodejs', 'php', 'python', 'java'}
        request = request or {}
        parsed_url = urlparse(request.get('url') or '')
        self._sender.enqueue({
            'rule_id': rule,
            'capabilityId': 9 if web_role else 1,
            'capabilityIds': [1, 9, 20] if web_role and kind == 'attack' else ([1, 9] if web_role else [1]),
            'category': 'network' if web_role else 'edr', 'severity': severity,
            'source': 'workload_log', 'description': f'{label} in {role}',
            'eventType': 'Application/Database Activity', 'workload_type': role,
            'source_path': path, 'evidence_type': 'native_application_log',
            'mitre_id': mitre, 'raw_log': line,
            'src_ip': request.get('source_ip'), 'url': request.get('url'),
            'domain': parsed_url.hostname or self._config.get('web_monitor_hostname') or '',
            'http_method': request.get('method'), 'response_code': request.get('status'),
            'response_time': request.get('response_time'), 'request_size': request.get('request_size'),
            'response_size': request.get('response_size'), 'user_agent': request.get('user_agent'),
            'referrer': request.get('referrer'), 'username': request.get('username'),
            'raw': {'workload_type': role, 'source_path': path, 'line': line, **request},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })

    def _emit_summary(self):
        now = time.time()
        if not self._counts or now - self._last_summary < 60:
            return
        counts = dict(self._counts)
        web_request_count = sum(self._web_counts.values())
        web_snapshot = {
            'web_request_count': web_request_count,
            'server_counts': dict(self._web_counts),
            'http_methods': dict(self._web_methods),
            'response_codes': dict(self._web_statuses),
            'top_urls': self._web_paths.most_common(20),
            'top_source_ips': self._web_sources.most_common(20),
            'response_bytes': self._web_response_bytes,
        }
        self._counts.clear()
        self._web_counts.clear()
        self._web_methods.clear()
        self._web_statuses.clear()
        self._web_paths.clear()
        self._web_sources.clear()
        self._web_response_bytes = 0
        self._last_summary = now
        self._sender.enqueue({
            'rule_id': 'PROC_WORKLOAD_ACTIVITY_SUMMARY', 'capabilityId': 1,
            'category': 'edr', 'severity': 'low', 'source': 'workload_log',
            'description': f'Application/database log activity: {sum(counts.values())} new line(s)',
            'eventType': 'Application/Database Activity', 'inventory_type': 'workload_activity',
            'workload_counts': counts, 'evidence_type': 'native_application_log',
            'raw': {'workload_counts': counts},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })
        if web_request_count:
            self._sender.enqueue({
                'rule_id': 'WEB_TRAFFIC_SUMMARY', 'capabilityId': 9, 'capabilityIds': [9],
                'category': 'network', 'severity': 'low', 'source': 'web_monitor',
                'description': f'Web server activity: {web_request_count} request(s) in the last interval',
                'eventType': 'Web Traffic Summary', 'protocol': 'http',
                'response_size': web_snapshot['response_bytes'],
                'raw': web_snapshot,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            })

    def _loop(self):
        interval = max(2.0, float(self._config.get('workload_log_poll_interval_seconds', 15)))
        while True:
            try:
                for role, path in self._discover():
                    lines = self._read_new(path)
                    if lines:
                        self._counts[role] += len(lines)
                    for line in lines:
                        request = self._parse_web_line(role, path, line)
                        if request:
                            self._record_web_request(role, request)
                            self._emit_api_request(role, path, request)
                        if WEB_ATTACK.search(line):
                            self._emit_alert(role, path, line, 'attack', request)
                        elif role in {'mysql', 'mssql', 'postgresql', 'oracle', 'mongodb'} and DB_SECURITY.search(line):
                            self._emit_alert(role, path, line, 'database')
                        elif APP_ERROR.search(line) or WEB_ERROR.search(line):
                            self._emit_alert(role, path, line, 'error', request)
                self._emit_summary()
            except Exception as exc:
                logger.warning('Workload activity monitor failed: %s', exc)
            time.sleep(interval)


Collector = WorkloadActivityCollector
