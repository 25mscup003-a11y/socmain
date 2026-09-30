"""Privacy-safe endpoint email and webmail telemetry collector.

The collector intentionally observes only OS process metadata, download file
metadata, and browser-history URL metadata.  It never reads mailbox contents,
cookies, passwords, browser form values, or message bodies.  Full sender,
recipient, authentication and mailbox-rule visibility must come from an
authorized Microsoft 365/Google Workspace/mail-gateway connector.
"""

import hashlib
import logging
import math
import os
import platform
import re
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

try:
    import psutil
except ImportError:  # pragma: no cover - the packaged agent installs psutil
    psutil = None

from .browser_activity import (
    _browser_identity,
    _history_paths,
    _profile_user,
    _read_chromium,
    _read_firefox,
    _safe_history_url,
    _user_home_roots,
)

logger = logging.getLogger('soc-agent.collector.email_threat')
SYSTEM = platform.system()

WEBMAIL_DOMAINS = {
    'mail.google.com': 'Google Workspace / Gmail',
    'outlook.office.com': 'Microsoft 365 Outlook',
    'outlook.office365.com': 'Microsoft 365 Outlook',
    'outlook.live.com': 'Outlook.com',
    'mail.yahoo.com': 'Yahoo Mail',
    'mail.proton.me': 'Proton Mail',
    'app.fastmail.com': 'Fastmail',
    'mail.zoho.com': 'Zoho Mail',
    'www.icloud.com': 'Apple iCloud Mail',
    'mail.aol.com': 'AOL Mail',
    'mail.gmx.com': 'GMX Mail',
    'mail.com': 'Mail.com',
    'mail.yandex.com': 'Yandex Mail',
    'mail.tutanota.com': 'Tuta Mail',
    'app.tuta.com': 'Tuta Mail',
    'mail.qq.com': 'QQ Mail',
    'mail.163.com': '163 Mail',
    'rediffmail.com': 'Rediffmail',
}
WEBMAIL_HOST_LABELS = {'mail', 'webmail', 'email', 'inbox', 'owa', 'roundcube'}
WEBMAIL_PATH_HINTS = (
    '/webmail', '/mail/', '/owa', '/roundcube', '/rainloop', '/snappymail',
    '/squirrelmail', '/horde', '/inbox',
)
WEBMAIL_PRODUCT_HINTS = (
    'webmail', 'roundcube', 'outlook web', 'open-xchange', 'squirrelmail',
    'snappymail', 'rainloop', 'horde mail', 'zimbra web client',
)
MAIL_CLIENTS = {
    'outlook.exe': 'Microsoft Outlook', 'olk.exe': 'Microsoft Outlook',
    'thunderbird.exe': 'Mozilla Thunderbird', 'thunderbird': 'Mozilla Thunderbird',
    'hxoutlook.exe': 'Windows Mail', 'hxtsr.exe': 'Windows Mail',
    'mail.exe': 'Windows Mail', 'wab.exe': 'Windows Mail',
    'mail': 'Apple Mail', 'mailspring': 'Mailspring', 'mailspring.exe': 'Mailspring',
    'evolution': 'Evolution', 'geary': 'Geary', 'kmail': 'KMail',
    'betterbird': 'Betterbird', 'betterbird.exe': 'Betterbird',
    'emclient.exe': 'eM Client', 'mailbird.exe': 'Mailbird',
    'spark.exe': 'Spark Mail', 'spark': 'Spark Mail',
    'bluemail.exe': 'BlueMail', 'bluemail': 'BlueMail',
    'postbox.exe': 'Postbox', 'postbox': 'Postbox',
    'thebat.exe': 'The Bat!', 'hclnotes.exe': 'HCL Notes', 'nlnotes.exe': 'HCL Notes',
    'protonmail-desktop.exe': 'Proton Mail', 'proton-mail.exe': 'Proton Mail',
    'protonmail-desktop': 'Proton Mail', 'zdesktop.exe': 'Zimbra Desktop',
    'gmail.exe': 'Google Workspace / Gmail', 'gmail': 'Google Workspace / Gmail',
    'gmail-desktop.exe': 'Google Workspace / Gmail',
}
MAIL_SERVERS = {
    'postfix', 'master', 'smtpd', 'dovecot', 'exim', 'exim4', 'sendmail',
    'qmail-smtpd', 'mailserver', 'exchange', 'msexchangefrontendtransport',
    'edgetransport.exe', 'msexchangefrontendtransport.exe', 'msexchangerepl.exe',
    'dovecot-auth', 'dovecot-lda', 'dovecot-imap', 'dovecot-pop3',
    'courier-imap', 'courier-pop3', 'haraka', 'stalwart-mail', 'mailcow',
}
MAIL_SERVER_PREFIXES = ('microsoft.exchange.', 'msexchange', 'postfix-', 'dovecot-')
DANGEROUS_CHILDREN = {
    'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
    'mshta.exe', 'regsvr32.exe', 'rundll32.exe', 'msbuild.exe',
    'installutil.exe', 'certutil.exe', 'bitsadmin.exe', 'bash', 'sh', 'zsh',
    'python.exe', 'python3', 'osascript',
}
SUSPICIOUS_TLDS = {
    'zip', 'mov', 'top', 'xyz', 'click', 'work', 'support', 'country', 'gq', 'tk', 'ml',
}
SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly',
}
ATTACHMENT_EXTENSIONS = {
    '.doc', '.docm', '.docx', '.xls', '.xlsm', '.xlsx', '.ppt', '.pptm', '.pptx',
    '.pdf', '.rtf', '.odt', '.ods', '.odp', '.csv', '.txt',
    '.zip', '.rar', '.7z', '.iso', '.img', '.lnk', '.html', '.htm', '.eml',
    '.msg', '.exe', '.msi', '.js', '.vbs', '.ps1', '.bat', '.cmd', '.scr',
}
MAIL_LOG_PATHS = ('/var/log/mail.log', '/var/log/maillog', '/var/log/mail.info')


def _utc(value=None):
    return datetime.fromtimestamp(value or time.time(), timezone.utc).isoformat()


def _webmail_provider(host, url='', title=''):
    """Identify known providers and privacy-safe custom webmail portals."""
    host = str(host or '').lower().strip('.')
    for suffix, provider in WEBMAIL_DOMAINS.items():
        if host == suffix or host.endswith('.' + suffix):
            return provider
    labels = {label for label in host.split('.') if label}
    try:
        path = (urlparse(url or '').path or '').lower()
    except (TypeError, ValueError):
        path = ''
    title_text = str(title or '').lower()
    if labels.intersection(WEBMAIL_HOST_LABELS) or any(hint in path for hint in WEBMAIL_PATH_HINTS) or any(hint in title_text for hint in WEBMAIL_PRODUCT_HINTS):
        return f'Webmail ({host})'
    return ''


def _url_risk(url, title=''):
    """Return deterministic URL risk without claiming a reputation verdict."""
    parsed = urlparse(url or '')
    host = (parsed.hostname or '').lower().strip('.')
    text = f'{host} {parsed.path or ""} {title or ""}'.lower()
    reasons = []
    if host.startswith('xn--') or '.xn--' in host:
        reasons.append('punycode-domain')
    if host in SHORTENERS:
        reasons.append('shortened-url')
    try:
        parts = host.split('.')
        if parts and all(part.isdigit() and 0 <= int(part) <= 255 for part in parts):
            reasons.append('ip-literal-host')
    except ValueError:
        pass
    if host.rsplit('.', 1)[-1] in SUSPICIOUS_TLDS:
        reasons.append('high-abuse-tld')
    if any(word in text for word in ('login', 'signin', 'verify', 'password', 'credential', 'account-update')):
        reasons.append('credential-themed-path')
    if parsed.scheme == 'http':
        reasons.append('plaintext-http')
    score = min(95, len(reasons) * 18)
    return score, reasons


def _is_soc_or_local_url(url, configured_server=''):
    """Exclude the local SOC console from webmail link correlation."""
    try:
        parsed = urlparse(url or '')
        host = (parsed.hostname or '').lower().strip('.')
        path = (parsed.path or '').lower()
        server_host = (urlparse(configured_server or '').hostname or '').lower().strip('.')
    except (TypeError, ValueError):
        return True
    if host in {'localhost', '127.0.0.1', '::1'}:
        return True
    if '/company-admin/edr' in path:
        return True
    return bool(server_host and host == server_host)


def _mail_component(name, cmdline=''):
    """Classify native clients, browser app-mode webmail, and mail services."""
    process_name = Path(str(name or '')).name.lower()
    if process_name in MAIL_CLIENTS:
        return MAIL_CLIENTS[process_name], 'client'
    command = str(cmdline or '').lower()
    if '--app=' in command or process_name in {'chrome_proxy.exe', 'msedge_proxy.exe'}:
        for domain, provider in WEBMAIL_DOMAINS.items():
            if domain in command:
                return provider, 'webmail_app'
    if process_name in MAIL_SERVERS or any(process_name.startswith(prefix) for prefix in MAIL_SERVER_PREFIXES):
        return f'Mail service {process_name}', 'server'
    return '', ''


def _entropy(path, max_bytes=1024 * 1024):
    try:
        data = Path(path).read_bytes()[:max_bytes]
    except (OSError, PermissionError):
        return None
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return round(-sum((n / length) * math.log2(n / length) for n in counts.values()), 3)


def _sha256(path, max_bytes=50 * 1024 * 1024):
    try:
        if Path(path).stat().st_size > max_bytes:
            return ''
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return ''


def _download_roots():
    roots = [home / 'Downloads' for home in _user_home_roots()]
    return [path for path in roots if path.exists() and path.is_dir()]


def _email_cache_roots():
    roots = []
    for home in _user_home_roots():
        if SYSTEM == 'Windows':
            roots.extend([
                home / 'AppData/Local/Microsoft/Windows/INetCache/Content.Outlook',
                home / 'AppData/Local/Microsoft/Olk/Attachments',
                home / 'AppData/Local/Packages/microsoft.windowscommunicationsapps_8wekyb3d8bbwe/LocalState/Files',
            ])
        elif SYSTEM == 'Darwin':
            roots.extend([
                home / 'Library/Containers/com.apple.mail/Data/Library/Mail Downloads',
                home / 'Library/Containers/com.microsoft.Outlook/Data/Library/Caches/TemporaryItems',
            ])
        else:
            roots.extend([
                home / '.cache/thunderbird',
                home / '.cache/evolution/mail',
            ])
    return [path for path in roots if path.exists() and path.is_dir()]


def _attachment_watch_roots():
    roots = [(path, 'downloads') for path in _download_roots()]
    roots.extend((path, 'mail_client_cache') for path in _email_cache_roots())
    return roots


def _iter_attachment_files(root, max_depth=4, max_entries=5000):
    """Yield bounded document candidates without following directory links."""
    root = Path(root)
    stack = [(root, 0)]
    examined = 0
    while stack and examined < max_entries:
        current, depth = stack.pop()
        try:
            entries = list(os.scandir(current))
        except (OSError, PermissionError):
            continue
        for entry in entries:
            examined += 1
            if examined > max_entries:
                break
            try:
                if entry.is_dir(follow_symlinks=False) and depth < max_depth:
                    stack.append((Path(entry.path), depth + 1))
                elif entry.is_file(follow_symlinks=False) and Path(entry.name).suffix.lower() in ATTACHMENT_EXTENSIONS:
                    yield Path(entry.path)
            except (OSError, PermissionError):
                continue


def _parse_mail_line(line):
    """Parse common Postfix/Exim metadata without retaining message content."""
    text = str(line or '').strip()
    queue = re.search(r'\b([A-F0-9]{6,20}):\s', text, re.I)
    sender = re.search(r'\bfrom=<([^>]*)>', text, re.I)
    recipient = re.search(r'\bto=<([^>]*)>', text, re.I)
    message_id = re.search(r'\bmessage-id=<([^>]*)>', text, re.I)
    status = re.search(r'\bstatus=([a-z_-]+)', text, re.I)
    client_ip = re.search(r'client=.*?\[([^\]]+)\]', text, re.I)
    auth = {}
    for method in ('spf', 'dkim', 'dmarc'):
        match = re.search(rf'\b{method}[=: ]+(pass|fail|softfail|neutral|none|reject)', text, re.I)
        if match:
            auth[method] = match.group(1).lower()
    if not any((queue, sender, recipient, message_id, status, auth)):
        return None
    return {
        'queue_id': queue.group(1) if queue else '',
        'sender': sender.group(1) if sender else '',
        'recipient': recipient.group(1) if recipient else '',
        'message_id': message_id.group(1) if message_id else '',
        'status': status.group(1).lower() if status else '',
        'src_ip': client_ip.group(1) if client_ip else '',
        'auth': auth,
    }


class EmailThreatCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._seen_history = set()
        self._seen_processes = set()
        self._mail_processes = {}
        self._seen_files = set()
        self._recent_webmail = {}
        self._recent_downloads = {}
        self._mail_log_offsets = {}
        self._mail_messages = {}
        self._process_baselined = False
        self._started_at = time.time()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='email-threat-monitor')

    def start(self):
        self._baseline_downloads()
        for name in MAIL_LOG_PATHS:
            try:
                self._mail_log_offsets[name] = Path(name).stat().st_size
            except OSError:
                pass
        self._thread.start()

    def _emit(self, **values):
        risk_score = int(values.get('risk_score') or 0)
        behavioral = risk_score >= 50
        event = {
            'capabilityId': 15,
            'capabilityIds': [11, 15] if behavioral else [15],
            'category': 'edr',
            'source': 'email',
            'timestamp': _utc(),
            **values,
        }
        if behavioral:
            event.update({
                'behavior_category': 'Email Behavior',
                'entity_type': 'user' if values.get('username') else 'endpoint',
                'entity_id': values.get('username') or values.get('email_recipient') or values.get('process_name'),
                'behavior_score': risk_score,
                'peer_deviation_score': risk_score,
                'ueba_confidence': 90,
                'ueba_risk_factors': [str(values.get('eventType') or values.get('rule_id') or 'email_behavior')],
                'baseline_window_days': 30,
            })
        self._sender.enqueue(event)

    def _scan_webmail(self):
        since = max(self._started_at - 120, time.time() - 600)
        for path in _history_paths():
            rows = _read_firefox(path, since) if path.name.lower() == 'places.sqlite' else _read_chromium(path, since)
            rows = sorted(rows, key=lambda row: row.get('visited') or 0)
            profile = str(path)
            for item in rows:
                url = item.get('url') or ''
                visited = item.get('visited') or 0
                safe_url = _safe_history_url(url)
                host = (urlparse(url).hostname or '').lower()
                key = f'{profile}|{safe_url}|{int(visited)}'
                if not safe_url or key in self._seen_history:
                    continue
                self._seen_history.add(key)
                browser, process_name = _browser_identity(path)
                username = _profile_user(path)
                provider = _webmail_provider(host, url, item.get('title') or '')
                if provider:
                    self._recent_webmail[profile] = {
                        'visited': visited,
                        'provider': provider,
                        'domain': host,
                        'url': safe_url,
                        'username': username,
                    }
                    self._emit(
                        rule_id='EMAIL_WEBMAIL_SESSION', severity='low',
                        eventType='webmail_session', threatCategory='webmail_activity', risk_score=5,
                        description=f'{provider} webmail activity observed in {browser}',
                        domain=host, url=safe_url, browser=browser, process_name=process_name,
                        username=username,
                        raw={
                            'provider': provider,
                            'webmail_provider': provider,
                            'mail_source_label': provider,
                            'monitored_user': username,
                            'collection_scope': 'URL/domain/title metadata only; query strings, cookies, credentials and message content excluded',
                        },
                        timestamp=_utc(visited),
                    )
                    continue
                recent = self._recent_webmail.get(profile)
                if not recent or visited < recent['visited'] or visited - recent['visited'] > 180:
                    continue
                if _is_soc_or_local_url(url, self._config.get('server_url')):
                    continue
                risk, reasons = _url_risk(url, item.get('title') or '')
                severity = 'high' if risk >= 54 else 'medium' if risk >= 36 else 'low'
                self._emit(
                    rule_id='EMAIL_WEBMAIL_LINK_OPEN', severity=severity,
                    eventType='email_link_open', threatCategory='suspicious_url' if reasons else 'email_url',
                    risk_score=max(10, risk), actionable=bool(reasons),
                    description=f'External link opened after {recent["provider"]} activity' + (f': {", ".join(reasons)}' if reasons else ''),
                    domain=host, url=safe_url, browser=browser, process_name=process_name,
                    username=username, referrer=recent['domain'],
                    mitre_id='T1204.001' if reasons else None,
                    technique='Malicious Link' if reasons else None,
                    mitre_tactic='Execution' if reasons else None,
                    raw={'correlation_window_seconds': 180, 'risk_reasons': reasons, 'webmail_provider': recent['provider'], 'attribution': 'temporal-correlation'},
                    timestamp=_utc(visited),
                )
        if len(self._seen_history) > 20000:
            self._seen_history = set(list(self._seen_history)[-10000:])

    def _scan_processes(self):
        if psutil is None:
            return
        current = set()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                pid = int(info.get('pid') or 0)
                name = str(info.get('name') or '').lower()
                current.add(pid)
                if pid in self._seen_processes:
                    continue
                self._seen_processes.add(pid)
                cmdline = ' '.join(info.get('cmdline') or [])[:2048]
                label, component_type = _mail_component(name, cmdline)
                if label:
                    initial_observation = not self._process_baselined
                    self._mail_processes[pid] = {
                        'name': name, 'label': label, 'started': info.get('create_time') or time.time(),
                        'username': info.get('username'), 'component_type': component_type,
                    }
                    self._emit(
                        rule_id='EMAIL_MAIL_COMPONENT_RUNNING' if initial_observation else 'EMAIL_MAIL_COMPONENT_STARTED',
                        severity='low', eventType='mail_component_running' if initial_observation else 'mail_component_started',
                        threatCategory='mail_client_activity', risk_score=5,
                        description=f'{label} is running' if initial_observation else f'{label} process started',
                        process_name=name, pid=pid,
                        process_exe=info.get('exe'), username=info.get('username'),
                        raw={
                            'component_type': component_type,
                            'process_state': 'running' if initial_observation else 'started',
                            'observed_process_create_time': _utc(info.get('create_time')),
                        },
                        # A process found on the first scan may predate agent
                        # installation. Its observation time is new evidence.
                        timestamp=_utc() if initial_observation else _utc(info.get('create_time')),
                    )
                parent = None
                try:
                    parent = proc.parent()
                except (psutil.Error, OSError):
                    pass
                parent_name = str(parent.name() if parent else '').lower()
                recent_attachment = next((p for p, seen in self._recent_downloads.items() if time.time() - seen < 3600 and p.lower() in cmdline.lower()), '')
                dangerous = name in DANGEROUS_CHILDREN and parent_name in MAIL_CLIENTS
                attachment_exec = bool(recent_attachment)
                if dangerous or attachment_exec:
                    self._emit(
                        rule_id='EMAIL_SUSPICIOUS_CHILD_PROCESS' if dangerous else 'EMAIL_ATTACHMENT_EXECUTED',
                        severity='critical' if dangerous else 'high', eventType='email_payload_execution',
                        threatCategory='attachment_malware', risk_score=95 if dangerous else 80, actionable=True,
                        description=f'Suspicious process {name} launched from email context',
                        process_name=name, pid=pid, parent_pid=info.get('ppid'), parent_process_name=parent_name,
                        process_cmdline=cmdline, process_exe=info.get('exe'), username=info.get('username'),
                        file_path=recent_attachment or None,
                        mitre_id='T1204.002', technique='Malicious File', mitre_tactic='Execution',
                        raw={'mail_parent': parent_name, 'correlated_attachment': recent_attachment},
                        timestamp=_utc(info.get('create_time')),
                    )
            except (psutil.Error, OSError, ValueError):
                continue
        for pid in set(self._mail_processes) - current:
            previous = self._mail_processes.pop(pid)
            lifetime = max(0, time.time() - float(previous['started'] or time.time()))
            suspected_crash = previous['component_type'] == 'client' and lifetime < 30
            self._emit(
                rule_id='EMAIL_MAIL_CLIENT_CRASH_SUSPECTED' if suspected_crash else 'EMAIL_MAIL_COMPONENT_STOPPED',
                severity='high' if suspected_crash else 'low',
                eventType='mail_client_crash_suspected' if suspected_crash else 'mail_component_stopped',
                threatCategory='mail_client_health', risk_score=65 if suspected_crash else 5,
                description=f'{previous["label"]} exited after {int(lifetime)} seconds',
                process_name=previous['name'], pid=pid, username=previous['username'],
                raw={'lifetime_seconds': round(lifetime, 2), 'crash_is_inferred': suspected_crash},
            )
        self._seen_processes.intersection_update(current)
        self._process_baselined = True

    def _baseline_downloads(self):
        for root, _source_kind in _attachment_watch_roots():
            for path in _iter_attachment_files(root):
                self._seen_files.add(str(path))

    def _scan_downloads(self):
        now = time.time()
        recent_webmail = max((item['visited'] for item in self._recent_webmail.values()), default=0)
        webmail_active = now - recent_webmail <= 600
        native_mail_active = any(item.get('component_type') in ('client', 'webmail_app') for item in self._mail_processes.values())
        latest_webmail = max(self._recent_webmail.values(), key=lambda item: item.get('visited') or 0, default={})
        active_mail_client = next((
            item for item in self._mail_processes.values()
            if item.get('component_type') in ('client', 'webmail_app')
        ), {})
        for root, source_kind in _attachment_watch_roots():
            # A general Downloads file is attributed to email only while a
            # webmail/native-mail session is active. Dedicated mail caches are
            # always in scope.
            if source_kind == 'downloads' and not (webmail_active or native_mail_active):
                continue
            for path in _iter_attachment_files(root):
                key = str(path)
                if key in self._seen_files:
                    continue
                self._seen_files.add(key)
                try:
                    stat = path.stat()
                except OSError:
                    continue
                if stat.st_mtime < self._started_at - 5:
                    continue
                self._recent_downloads[key] = now
                digest = _sha256(path)
                entropy = _entropy(path)
                risky = path.suffix.lower() in {'.exe', '.msi', '.js', '.vbs', '.ps1', '.bat', '.cmd', '.scr', '.lnk', '.iso', '.img', '.docm', '.xlsm', '.pptm'}
                mail_source = latest_webmail.get('provider') or active_mail_client.get('label') or 'Webmail / Mail Client'
                monitored_user = latest_webmail.get('username') or active_mail_client.get('username') or ''
                self._emit(
                    rule_id='EMAIL_ATTACHMENT_DOWNLOADED', severity='medium' if risky else 'low',
                    eventType='attachment_download', threatCategory='suspicious_attachment' if risky else 'email_attachment',
                    risk_score=65 if risky else 20, actionable=risky,
                    description=f'Potential email attachment downloaded: {path.name}',
                    file_path=key, file_name=path.name, file_size=stat.st_size, file_hash=digest,
                    extension=path.suffix.lower(), entropy=entropy, username=monitored_user,
                    url=latest_webmail.get('url') or None,
                    mitre_id='T1566.001' if risky else None,
                    technique='Spearphishing Attachment' if risky else None,
                    mitre_tactic='Initial Access' if risky else None,
                    raw={
                        'attribution': 'mail-client cache' if source_kind == 'mail_client_cache'
                            else 'download observed while webmail or a native mail client was active',
                        'attachment_source': source_kind,
                        'webmail_provider': latest_webmail.get('provider'),
                        'mail_source_label': mail_source,
                        'monitored_user': monitored_user,
                        'content_collected': False,
                    },
                    timestamp=_utc(stat.st_mtime),
                )

    def _scan_mail_logs(self):
        for name in MAIL_LOG_PATHS:
            path = Path(name)
            if not path.exists():
                continue
            try:
                size = path.stat().st_size
                offset = self._mail_log_offsets.get(name, size)
                if size < offset:  # log rotation
                    offset = 0
                with path.open('r', encoding='utf-8', errors='replace') as handle:
                    handle.seek(offset)
                    lines = handle.readlines(512 * 1024)
                    self._mail_log_offsets[name] = handle.tell()
            except (OSError, PermissionError):
                continue
            for line in lines:
                parsed = _parse_mail_line(line)
                if not parsed:
                    continue
                queue_id = parsed.pop('queue_id') or hashlib.sha256(line.encode('utf-8', errors='replace')).hexdigest()[:16]
                record = self._mail_messages.setdefault(queue_id, {})
                record.update({key: item for key, item in parsed.items() if item not in ('', {})})
                if not record.get('status'):
                    continue
                status = record['status']
                auth_failed = any(item in ('fail', 'softfail', 'reject') for item in record.get('auth', {}).values())
                rejected = status in ('bounced', 'deferred', 'reject', 'rejected')
                self._emit(
                    rule_id='EMAIL_GATEWAY_AUTH_FAILURE' if auth_failed else 'EMAIL_GATEWAY_MESSAGE',
                    severity='high' if auth_failed else 'medium' if rejected else 'low',
                    eventType='email_gateway_delivery', threatCategory='email_spoofing' if auth_failed else 'email_delivery',
                    risk_score=75 if auth_failed else 40 if rejected else 5, actionable=auth_failed,
                    description=f'Mail gateway message status={status}',
                    email_sender=record.get('sender'), email_recipient=record.get('recipient'),
                    email_message_id=record.get('message_id') or queue_id,
                    email_direction='outgoing' if record.get('sender') else 'incoming',
                    email_auth=record.get('auth', {}), src_ip=record.get('src_ip'),
                    action='rejected' if rejected else 'detected',
                    raw={'queue_id': queue_id, 'status': status, 'source_log': name, 'content_collected': False},
                )
                self._mail_messages.pop(queue_id, None)
        if len(self._mail_messages) > 5000:
            self._mail_messages.clear()

    def _loop(self):
        logger.info('Email threat monitor started (native mail, webmail URLs, downloads and child processes)')
        while True:
            try:
                self._scan_webmail()
                self._scan_processes()
                self._scan_downloads()
                self._scan_mail_logs()
            except Exception as exc:
                logger.debug('Email threat scan failed: %s', exc)
            time.sleep(max(10, int(self._config.get('email_monitor_interval_seconds', 30))))
