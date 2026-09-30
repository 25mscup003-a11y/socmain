"""
File Monitor v2.0 — Storage Control & False-Positive Prevention.

MASTER RULES (SOC Agent v2.0):
  ✔ Max 10,000 events (FIFO - oldest deleted first when limit reached)
  ✔ Store ONLY: .exe/.sh/.py, /tmp /dev/shm paths, USB files, VT-flagged
  ✔ Ignore: /usr /lib system dirs, duplicate spam
  ✔ Dedup rule: same event within 60s = skip
  ✔ Auto cleanup: delete events older than 24h
  ✔ INSTALL_TIME: only process events >= install_time
  ✔ VT=0 → NEVER malware (downgrade to LOW file event)
"""

import os
import time
import hashlib
import logging
import threading
import platform
import getpass
import re
from collections import OrderedDict
from datetime import datetime, timezone, timedelta
from pathlib import Path

logger = logging.getLogger('soc-agent.collector.file')
SYSTEM = platform.system()

# ── Storage limits (section 4 of master spec) ────────────────────────────────
MAX_FILE_EVENTS    = 10_000   # configurable — FIFO when exceeded
EVENT_TTL_HOURS    = 24       # auto-delete events older than 24h
DEDUP_WINDOW_SECS  = 60       # same event within 60s = skip

POLL_INTERVAL  = 10    # seconds between polling scans
MAX_POLL_FILES = 3000  # cap per poll cycle to avoid CPU spikes

# ── Directories to watch ─────────────────────────────────────────────────────
WATCH_DIRS = {
    'Linux': [
        # Temp trees are high-churn (browsers, package managers, sockets). YARA
        # scans these focused drop locations on a bounded interval instead of
        # feeding every transient write into the durable event queue.
        # Avoid recursive watches on /home, /root and /opt. Besides expensive
        # worktrees/caches, /opt contains this agent's SQLite spool: watching it
        # creates a write -> file event -> spool write feedback loop.
        '/etc', '/var/www', '/mnt', '/media',
    ],
    'Darwin': [
        '/tmp', '/private/tmp', '/etc',
        os.path.expanduser('~/Documents'),
        os.path.expanduser('~/Downloads'),
        os.path.expanduser('~/Desktop'),
    ],
    'SunOS': [
        '/etc', '/var/svc/manifest', '/var/adm',
    ],
    'Windows': [
        os.environ.get('TEMP', 'C:\\Windows\\Temp'),
        os.environ.get('TMP',  'C:\\Temp'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Downloads'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Desktop'),
        os.path.join(os.environ.get('USERPROFILE', 'C:\\Users\\Default'), 'Documents'),
        'C:\\Windows\\System32',
        'C:\\Windows\\SysWOW64',
    ],
}

# ── IGNORE: system dirs with no security value (§4 — storage control) ────────
SKIP_DIRS = {
    '/proc', '/sys', '/dev', '/run',
    '/usr', '/lib', '/lib64', '/lib32',     # §4: ignore /usr /lib
    '/snap', '/boot',
    '/opt/soc-agent',
    '/etc/soc-agent',
    'C:\\Windows\\WinSxS',
    '__pycache__',
}

AGENT_RUNTIME_PATH_PATTERNS = {
    '/opt/soc-agent',
    '/etc/soc-agent',
    '/var/log/soc-agent',
    '/tmp/node-compile-cache',
    '/tmp/codex-',
    '/tmp/.org.chromium.',
    '/home/chaudahry/.codex',
    '/home/chaudahry/.vscode/extensions/openai.',
}

# ── IGNORE: extensions with zero security value ───────────────────────────────
SKIP_EXT = {
    '.pyc', '.pyo', '.gif', '.jpg', '.jpeg', '.png', '.webp',
    '.mp4', '.mkv', '.mp3', '.tmp', '.lock', '.pid', '.cache',
    '.log',    # logs handled by log scanner
    '.so', '.a', '.o',   # compiled objects — no security value alone
}

SENSITIVE_EXT = {
    '.env', '.conf', '.cfg', '.ini', '.yaml', '.yml', '.json',
    '.pem', '.key', '.crt', '.cert', '.p12', '.jks',
    '.sql', '.bak', '.dump', '.db', '.sqlite',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv', '.txt', '.xml',
    '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.c', '.cpp', '.h', '.cs',
}

# ── STORE ONLY these extensions/paths (§4) ───────────────────────────────────
STORE_EXT = {
    # Executables
    '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.hta',
    '.sh', '.py', '.rb', '.pl', '.elf',
    # Malware markers
    '.locked', '.encrypted', '.crypt', '.wncry', '.ryuk', '.zzzzz',
    # Web shells
    '.php', '.asp', '.aspx', '.jsp',
}

SUSPICIOUS_PATHS = {'/tmp', '/var/tmp', '/dev/shm', 'Temp', 'TEMP'}
USB_PATH_HINTS = {'/media', '/mnt', '/run/media', 'Removable', 'USBSTOR'}

SENSITIVE_DIRS = {
    '/etc', '/root', '/usr/bin', '/usr/sbin',
    'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
}

PRIVATE_FILE_PATTERNS = [
    '.ssh/', 'id_rsa', 'id_ecdsa', 'id_ed25519',
    'authorized_keys', 'known_hosts',
    '/etc/passwd', '/etc/shadow', '/etc/sudoers',
    '.bash_history', '.zsh_history', '.netrc', '.pgpass',
    'id_token', 'access_token', '.aws/credentials',
    '.gnupg', '.pem', 'private_key', 'privatekey',
    'wallet.dat', 'keystore', '.env', 'secrets.', 'secret.key',
]

DLP_TEXT_EXTENSIONS = {'.txt', '.csv', '.json', '.xml', '.yaml', '.yml', '.ini', '.conf'}
DLP_CATEGORY_PATTERNS = (
    ('PAYMENT_CARD', re.compile(r'(?<!\d)(?:\d[ -]?){13,19}(?!\d)')),
    ('AADHAAR', re.compile(r'(?<!\d)[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}(?!\d)')),
    ('PAN', re.compile(r'\b[A-Z]{5}\d{4}[A-Z]\b')),
    ('PASSPORT', re.compile(r'\b[A-Z][1-9]\d{6}\b')),
    ('AWS_ACCESS_KEY', re.compile(r'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b')),
    ('JWT_TOKEN', re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b')),
    ('PRIVATE_KEY_MARKER', re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')),
)


def _is_private(path: str) -> bool:
    p = path.lower().replace('\\', '/')
    return any(pat in p for pat in PRIVATE_FILE_PATTERNS)


def _dlp_metadata(path: str, max_bytes: int = 512 * 1024) -> dict:
    """Inspect a bounded local text prefix and return category/count only."""
    if _is_private(path) or Path(path).suffix.lower() not in DLP_TEXT_EXTENSIONS:
        return {}
    try:
        if os.path.getsize(path) > max_bytes:
            return {}
        with open(path, 'r', encoding='utf-8', errors='ignore') as handle:
            text = handle.read(max_bytes)
    except (OSError, PermissionError, UnicodeError):
        return {}
    counts = [(category, len(pattern.findall(text))) for category, pattern in DLP_CATEGORY_PATTERNS]
    counts = [(category, count) for category, count in counts if count]
    if not counts:
        return {}
    counts.sort(key=lambda item: item[1], reverse=True)
    return {
        'dlp_pattern': counts[0][0],
        'dlp_match_count': sum(count for _, count in counts),
        'dlp_pattern_categories': [category for category, _ in counts],
        'collection_scope': 'local bounded pattern scan; matched values and file contents were not collected',
    }


def _in_skip_dir(path: str) -> bool:
    normalized = path.replace('\\', '/')
    if any(pattern in normalized for pattern in AGENT_RUNTIME_PATH_PATTERNS):
        return True
    if path.startswith('/usr/bin') or path.startswith('/usr/sbin'):
        return False
    for sd in SKIP_DIRS:
        if path.startswith(sd):
            return True
    return False


def _is_critical_system_file(path: str) -> bool:
    p = path.lower().replace('\\', '/')
    names = {
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/group',
        '/etc/ssh/sshd_config', '/etc/crontab',
    }
    if any(p.startswith(name) for name in names):
        return True
    return any(token in p for token in ['/usr/bin/', '/usr/sbin/', '/bin/', '/sbin/', 'c:/windows/system32'])


def _system_change_category(path: str, module_type: str = '') -> str:
    """Classify security-relevant FIM evidence for capability 7."""
    text = f'{path} {module_type}'.lower().replace('\\', '/')
    if any(token in text for token in ('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/sudoers')):
        return 'users_groups'
    if any(token in text for token in ('/etc/ssh/', 'authorized_keys', 'terminal server', 'fdenytsconnections')):
        return 'remote_access'
    if any(token in text for token in ('/etc/cron', '/systemd/', '/init.d/', '/startup/', '/launchagent', '/launchdaemon')):
        return 'scheduled_tasks_services'
    if any(token in text for token in ('/etc/hosts', '/etc/resolv.conf', '/etc/network/', '/etc/netplan/', 'proxy')):
        return 'network_configuration'
    if any(token in text for token in ('/etc/audit/', '/var/log/', 'defender', 'security', 'firewall')):
        return 'security_configuration'
    if module_type in ('permission', 'ownership'):
        return 'permissions'
    return 'critical_system_files'


def _configuration_category(path: str) -> str:
    """Classify Unix/Solaris configuration evidence for capability 6."""
    text = str(path or '').lower().replace('\\', '/')
    if any(token in text for token in ('/passwd', '/shadow', '/group', '/sudoers', '/user_attr', '/security/')):
        return 'user_authentication'
    if any(token in text for token in ('/cron', '/systemd/', '/init.d/', '/rc', '/profile', '/bashrc', 'ld.so.preload', '/svc/manifest')):
        return 'persistence'
    if any(token in text for token in ('/ssh/', '/pam.d/', '/audit/', '/selinux/', '/apparmor/', '/sysctl')):
        return 'security_configuration'
    if any(token in text for token in ('/hosts', '/resolv.conf', '/network/', '/netplan/', '/route', '/firewall', '/ipf/')):
        return 'network_configuration'
    if any(token in text for token in ('/apt/', '/yum', '/dnf', '/zypp/', '/pkg/', '/var/sadm/')):
        return 'software_configuration'
    return 'configuration_integrity'


def _is_configuration_path(path: str) -> bool:
    text = str(path or '').lower().replace('\\', '/')
    prefixes = (
        '/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers',
        '/etc/ssh/', '/etc/cron', '/var/spool/cron/', '/etc/systemd/',
        '/usr/lib/systemd/system/', '/etc/init.d/', '/etc/rc', '/etc/profile',
        '/etc/bash.bashrc', '/.bashrc', '/.profile', '/etc/ld.so.preload',
        '/etc/pam.d/', '/etc/audit/', '/etc/selinux/', '/etc/apparmor/',
        '/etc/sysctl', '/etc/hosts', '/etc/resolv.conf', '/etc/network/',
        '/etc/netplan/', '/etc/security/', '/etc/user_attr', '/var/svc/manifest/',
        '/etc/ipf/', '/etc/default/', '/etc/inet/',
    )
    return any(token in text for token in prefixes)


def _should_store(path: str) -> bool:
    """§4: Only store executables, suspicious paths, USB files, or VT-flagged."""
    p   = Path(path)
    ext = p.suffix.lower()
    par = str(p.parent)

    # Always store malware-class extensions
    if ext in STORE_EXT:
        return True
    # Always store sensitive extensions and names
    if ext in SENSITIVE_EXT or _sensitivity_type(path):
        return True
    # Always store files in suspicious paths
    if any(sp in par for sp in SUSPICIOUS_PATHS):
        return True
    if any(up in path for up in USB_PATH_HINTS):
        return True
    # Always store sensitive-dir writes
    for sd in SENSITIVE_DIRS:
        if path.startswith(sd):
            return True
    return False


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def _md5(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            return hashlib.md5(f.read(1024 * 1024)).hexdigest()
    except Exception:
        return ''


def _permission(path: str) -> str:
    try:
        return oct(os.stat(path).st_mode & 0o777)
    except Exception:
        return ''


def _owner_group(path: str):
    try:
        import grp
        import pwd
        st = os.stat(path)
        return pwd.getpwuid(st.st_uid).pw_name, grp.getgrgid(st.st_gid).gr_name
    except Exception:
        return '', ''


def _active_user() -> str:
    """Best-effort actor for local FIM changes.

    Linux inotify does not expose the process/user that changed file metadata,
    so keep this as the service/session actor and prefer explicit env context.
    """
    for key in ('SUDO_USER', 'LOGNAME', 'USER', 'USERNAME'):
        value = os.environ.get(key)
        if value and value.lower() not in {'root', 'system'}:
            return value
    try:
        return getpass.getuser() or 'system'
    except Exception:
        return 'system'


def _file_state(
    path: str,
    previous: dict = None,
    include_md5: bool = True,
    max_hash_bytes: int = 16 * 1024 * 1024,
) -> dict:
    """Return file metadata without re-reading unchanged file contents.

    Polling used to calculate SHA256 and MD5 for every file on every pass.  A
    cheap stat identity is enough to reuse the previous digests; content is
    read only for a new or changed, reasonably-sized file.
    """
    try:
        st = os.stat(path)
    except Exception:
        return {}

    identity = (
        int(getattr(st, 'st_mtime_ns', int(st.st_mtime * 1_000_000_000))),
        int(st.st_size), int(st.st_mode), int(st.st_uid), int(st.st_gid),
    )
    if previous and previous.get('_stat_identity') == identity:
        return dict(previous)

    try:
        import grp
        import pwd
        owner = pwd.getpwuid(st.st_uid).pw_name
        group = grp.getgrgid(st.st_gid).gr_name
    except Exception:
        owner, group = '', ''
    private = _is_private(path)
    should_hash = not private and int(st.st_size) <= max(0, int(max_hash_bytes))
    return {
        'mtime': st.st_mtime,
        'size': st.st_size,
        'permission': oct(st.st_mode & 0o777),
        'owner': owner,
        'group': group,
        'sha256': _sha256(path) if should_hash else '',
        'md5': _md5(path) if should_hash and include_md5 else '',
        '_stat_identity': identity,
        'hash_skipped': bool(not private and not should_hash),
    }


def _sensitivity_type(path: str) -> str:
    name = Path(path).name.lower()
    full = path.lower()
    if name in {'passwd', 'shadow', 'sudoers'} or '/etc/' in full:
        return 'system_identity_or_config'
    if any(token in name for token in ['password', 'credential', 'secret', 'token', '.env']):
        return 'credential_secret'
    if any(name.endswith(ext) for ext in ['.pem', '.key', '.crt', '.cert', '.p12', '.jks']) or 'authorized_keys' in name or 'id_rsa' in name:
        return 'key_or_certificate'
    if any(name.endswith(ext) for ext in ['.sql', '.bak', '.dump', '.db', '.sqlite']) or 'backup' in name:
        return 'database_backup'
    if any(name.endswith(ext) for ext in ['.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.c', '.cpp', '.h', '.cs', '.php']):
        return 'source_code'
    if any(name.endswith(ext) for ext in ['.conf', '.cfg', '.ini', '.yaml', '.yml', '.json']):
        return 'configuration'
    if any(name.endswith(ext) for ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.csv']):
        if any(token in full for token in ['finance', 'financial', 'hr', 'customer', 'pii', 'confidential']):
            return 'business_sensitive_document'
        return 'document'
    if any(up.lower() in full for up in USB_PATH_HINTS):
        return 'usb_file_activity'
    return ''


def _data_classification(path: str, sensitivity: str) -> str:
    text = f'{path} {sensitivity}'.lower().replace('\\', '/')
    if any(token in text for token in ('credential_secret', 'key_or_certificate', '/etc/shadow', 'private_key', 'id_rsa', '/secrets/')):
        return 'Secret'
    if any(token in text for token in ('database_backup', 'source_code', '/finance/', '/payroll/', '/customer/')):
        return 'Restricted'
    if sensitivity or any(token in text for token in ('/hr/', '/confidential/')):
        return 'Confidential'
    return 'Internal'


def _fim_module(path: str, event_type: str, reason: str, extra: dict = None) -> str:
    extra = extra or {}
    explicit = extra.get('module_type') or extra.get('moduleType') or extra.get('fim_module')
    if explicit:
        return str(explicit)
    action = str(event_type or '').lower()
    text = f'{path} {event_type} {reason} {extra}'.lower()
    if any(k in action for k in ['chmod', 'permission_changed', 'mode_changed', 'acl_changed', 'suid_changed', 'sgid_changed']) or extra.get('old_permission') or extra.get('permission_risk'):
        return 'permission'
    if any(k in action for k in ['chown', 'ownership_changed', 'owner_changed', 'group_changed']) or extra.get('old_owner') or extra.get('old_group'):
        return 'ownership'
    if any(k in text for k in ['ransom', 'encrypt', '.locked', '.encrypted', '.crypt', '.wncry', '.ryuk', 'mass rename', 'shadow copy', 'backup deletion', 'bulk file deletion']):
        return 'ransomware'
    if _sensitivity_type(path):
        return 'sensitive'
    if any(k in text for k in ['hash', 'integrity', 'baseline', 'checksum', 'content changed', 'critical system file', 'configuration changed', 'unexpected content']):
        return 'integrity'
    if action in {'created', 'modified', 'deleted', 'renamed', 'hash_changed'}:
        return 'integrity'
    return 'general'


def _permission_risk(permission: str) -> str:
    """Return the FIM permission risk marker that should be visible in the UI."""
    try:
        mode = int(str(permission).replace('0o', ''), 8)
    except Exception:
        return ''
    if mode & 0o002:
        return 'world-writable'
    if mode & 0o4000:
        return 'suid'
    if mode & 0o2000:
        return 'sgid'
    return ''


def _file_action_detail(path: str, event_type: str, module_type: str, sensitivity: str, extra: dict) -> str:
    if extra.get('action'):
        return str(extra.get('action'))
    if module_type == 'permission':
        return 'permission_change'
    if module_type == 'ownership':
        return 'ownership_change'
    if module_type == 'ransomware':
        return 'ransomware_indicator'
    if module_type == 'sensitive':
        if any(up.lower() in path.lower() for up in USB_PATH_HINTS):
            return 'usb_copy_activity'
        if event_type in {'created', 'modified', 'renamed', 'deleted'}:
            return f'sensitive_file_{event_type}'
        return 'sensitive_file_access'
    if event_type == 'hash_changed':
        return 'file_hash_change'
    return event_type


def _file_event_time(path: str, event_type: str) -> str:
    """
    Use the file's own mtime for create/modify events.
    This prevents a watcher restart from reporting old pre-install files as new events.
    Deleted files cannot be stat'ed, so they use the current event time.
    """
    if event_type != 'deleted':
        try:
            st = os.stat(path)
            return datetime.fromtimestamp(st.st_mtime, timezone.utc).isoformat()
        except Exception:
            pass
    return datetime.now(timezone.utc).isoformat()


def _classify(path: str, event_type: str):
    """
    Return (category, severity, is_malware_candidate, reason).
    NOTE: is_malware_candidate=True only means it MIGHT be malware.
    Final verdict requires VT confirmation. VT=0 → NOT malware.
    """
    p      = Path(path)
    ext    = p.suffix.lower()
    name   = p.name.lower()
    parent = str(p.parent)

    # Ransomware extensions (high confidence)
    if ext in {'.locked', '.encrypted', '.crypt', '.wncry', '.ryuk', '.zzzzz'}:
        return 'malware', 'critical', True, f'Ransomware extension: {ext}'

    # Ransom notes
    if any(kw in name for kw in ['ransom', 'decrypt_', 'how_to_', 'readme_to', 'restore_files']):
        return 'malware', 'critical', True, f'Potential ransom note: {p.name}'

    # Web shell in web directory
    if ext in {'.php', '.asp', '.aspx', '.jsp'} and event_type == 'created':
        if any(wd in parent for wd in ['/var/www', 'htdocs', 'wwwroot', 'public_html']):
            return 'malware', 'critical', True, f'Web shell dropped: {p.name}'

    # Executable in temp (suspicious — needs VT confirmation)
    if ext in {'.exe', '.sh', '.ps1', '.bat', '.cmd', '.py', '.rb', '.pl'} and event_type == 'created':
        if any(td in parent for td in ['/tmp', '/var/tmp', '/dev/shm', 'Temp', 'TEMP']):
            return 'malware', 'high', True, f'Executable in temp: {p.name} — awaiting VT'

    # Credential files
    cred = {'.bash_history', '.zsh_history', 'shadow', 'passwd', 'id_rsa',
            'id_ecdsa', 'credentials', '.netrc', '.aws'}
    if any(cn in name for cn in cred):
        return 'malware', 'high', True, f'Credential file accessed: {p.name}'

    # Sensitive system dirs
    for sd in SENSITIVE_DIRS:
        if path.startswith(sd):
            return 'file', 'medium', False, f'File {event_type} in sensitive dir: {p.name}'

    return 'file', 'low', False, f'File {event_type}: {p.name}'


class FileMonitorCollector:
    """
    File event collector with:
    - FIFO storage (max 10k events)
    - 60s dedup window
    - 24h auto-cleanup
    - Store-only filter (executables, suspicious paths)
    - VT override (VT=0 → NOT malware)
    - INSTALL_TIME baseline (via sender state)
    """

    def __init__(self, sender, config=None):
        self._sender  = sender
        self._config  = config
        self._thread  = threading.Thread(
            target=self._start, daemon=True, name='file-monitor')

        # ── In-memory event store (FIFO, max MAX_FILE_EVENTS) ────────────────
        # key: str(path), value: {'time': float, 'event': dict}
        self._event_store: OrderedDict = OrderedDict()
        self._store_lock  = threading.Lock()

        # ── 60-second local dedup (path+event_type → last_ts) ────────────────
        self._local_dedup: dict = {}
        self._dedup_lock  = threading.Lock()

        self._seen: dict = {}   # path → state dict (mtime, size, perm, owner/group, hashes)

        # Start background cleanup thread
        threading.Thread(target=self._cleanup_loop, daemon=True,
                         name='file-event-cleanup').start()

    def start(self):
        self._thread.start()

    def _cfg_bool(self, key: str, default: bool) -> bool:
        try:
            value = self._config.get(key, default) if self._config else default
        except Exception:
            value = default
        if isinstance(value, str):
            return value.strip().lower() not in ('0', 'false', 'no', 'off', '')
        return bool(value)

    def _cfg_int(self, key: str, default: int, minimum: int = 0) -> int:
        try:
            value = self._config.get(key, default) if self._config else default
            return max(minimum, int(value))
        except (TypeError, ValueError, AttributeError):
            return max(minimum, int(default))

    def _watch_dirs(self):
        """Return existing built-in and administrator-configured paths, bounded."""
        values = list(WATCH_DIRS.get(SYSTEM, []))
        if SYSTEM == 'Linux':
            try:
                for home in list(Path('/home').iterdir())[:32]:
                    if not home.is_dir():
                        continue
                    for folder in ('Documents', 'Desktop', 'Downloads'):
                        candidate = home / folder
                        if candidate.is_dir():
                            values.append(str(candidate))
            except (OSError, PermissionError):
                pass
        try:
            configured = []
            if self._config:
                for key in ('data_security_sensitive_paths', 'configuration_monitor_paths'):
                    raw_paths = self._config.get(key, []) or []
                    if isinstance(raw_paths, str):
                        raw_paths = [item.strip() for item in raw_paths.split(',') if item.strip()]
                    if isinstance(raw_paths, list):
                        configured.extend(raw_paths)
        except Exception:
            configured = []
        if isinstance(configured, list):
            values.extend(str(item).strip() for item in configured[:64] if str(item).strip())
        # Preserve order and cap watcher count to prevent configuration-driven
        # endpoint load spikes.
        normalized = []
        for item in values:
            candidate = Path(os.path.expanduser(item))
            if candidate.exists() and candidate.is_file():
                candidate = candidate.parent
            normalized.append(str(candidate))
        return list(dict.fromkeys(normalized))[:64]

    def _state(self, path: str, previous: dict = None) -> dict:
        return _file_state(
            path,
            previous=previous,
            include_md5=self._cfg_bool('file_monitor_md5_enabled', False),
            max_hash_bytes=self._cfg_int(
                'file_monitor_hash_max_bytes', 16 * 1024 * 1024, minimum=0
            ),
        )

    # ── Event store management (§4 storage control) ───────────────────────────
    def _store_event(self, path: str, event: dict):
        """Add to FIFO store. Delete oldest if over MAX_FILE_EVENTS."""
        with self._store_lock:
            # FIFO: remove oldest if at capacity
            while len(self._event_store) >= MAX_FILE_EVENTS:
                oldest_key, _ = next(iter(self._event_store.items()))
                del self._event_store[oldest_key]
                logger.debug('FIFO evict (store full): %s', oldest_key)

            store_key = f"{path}::{event.get('file_action')}::{time.time()}"
            self._event_store[store_key] = {
                'time':  time.time(),
                'event': event,
            }

    def _cleanup_loop(self):
        """Delete events older than 24h from the local store."""
        while True:
            time.sleep(3600)   # run hourly
            cutoff = time.time() - (EVENT_TTL_HOURS * 3600)
            with self._store_lock:
                expired = [k for k, v in self._event_store.items()
                           if v['time'] < cutoff]
                for k in expired:
                    del self._event_store[k]
            if expired:
                logger.debug('24h cleanup: removed %d old file events', len(expired))

    # ── 60-second local dedup ─────────────────────────────────────────────────
    def _is_local_dup(self, path: str, event_type: str) -> bool:
        """Return True if same path+event_type seen within DEDUP_WINDOW_SECS."""
        key = f'{path}::{event_type}'
        now = time.monotonic()
        with self._dedup_lock:
            last = self._local_dedup.get(key, 0)
            if now - last < DEDUP_WINDOW_SECS:
                return True
            self._local_dedup[key] = now
            # Prune old entries
            if len(self._local_dedup) > 5000:
                cutoff = now - DEDUP_WINDOW_SECS * 2
                self._local_dedup = {
                    k: v for k, v in self._local_dedup.items() if v > cutoff
                }
        return False

    # ── Emit ─────────────────────────────────────────────────────────────────
    def _emit(self, path: str, event_type: str, extra: dict = None):
        """Classify, filter, store, and enqueue a file event."""
        # §4: ignore /usr /lib system dirs
        if _in_skip_dir(path):
            return

        ext = Path(path).suffix.lower()
        if ext in SKIP_EXT:
            return

        # §4: store ONLY relevant files
        if not _should_store(path):
            return

        # 60-second local dedup
        if self._is_local_dup(path, event_type):
            logger.debug('Local 60s dup skip: %s [%s]', path, event_type)
            return

        event_time = _file_event_time(path, event_type)
        category, severity, is_malware_candidate, reason = _classify(path, event_type)

        # Compute hashes for FIM evidence (redact private files)
        file_hash = file_hash_sha1 = file_hash_md5 = ''
        trust = {}
        private   = _is_private(path)
        if event_type != 'deleted' and not private:
            if self._cfg_bool('hash_monitoring_enabled', True):
                try:
                    from collectors.hash_signature import ENGINE
                    executable = ext in {
                        '.exe', '.dll', '.sys', '.com', '.scr', '.cpl', '.msi',
                        '.ps1', '.bat', '.cmd', '.vbs', '.js', '.sh', '.py',
                        '.rb', '.pl', '.elf', '.so',
                    }
                    trust = ENGINE.inspect(
                        path,
                        include_sha1=self._cfg_bool('hash_sha1_enabled', True),
                        include_md5=self._cfg_bool('hash_md5_enabled', False),
                        signature=executable and self._cfg_bool('hash_signature_validation_enabled', True),
                    )
                    file_hash = trust.get('sha256') or ''
                    file_hash_sha1 = trust.get('sha1') or ''
                    file_hash_md5 = trust.get('md5') or ''
                except Exception as exc:
                    logger.debug('Hash/signature inspection failed for %s: %s', path, exc)
            if not file_hash:
                # FIM still requires a stable SHA-256 identity when the optional
                # Hash/Signature analysis policy is disabled or unavailable.
                file_hash = _sha256(path)

        file_user, file_group = _owner_group(path)
        permission = _permission(path)
        extra = extra or {}
        module_type = _fim_module(path, event_type, reason, extra)
        sensitivity = _sensitivity_type(path)
        dlp_metadata = _dlp_metadata(path) if event_type != 'deleted' else {}
        if dlp_metadata:
            module_type = 'sensitive'
            severity = 'high'
        permission_risk = _permission_risk(permission)
        if permission_risk and module_type in {'general', 'integrity'}:
            module_type = 'permission'
        if module_type == 'ransomware':
            severity = 'critical'
        elif event_type in {'deleted', 'hash_changed'} and _is_critical_system_file(path):
            severity = 'critical'
        elif module_type in {'permission', 'ownership'} and (_is_critical_system_file(path) or sensitivity):
            severity = 'high'
        elif module_type == 'sensitive':
            severity = 'high'
        elif permission_risk:
            severity = 'high'

        action_detail = _file_action_detail(path, event_type, module_type, sensitivity, extra)
        extension_changed = bool(
            extra.get('extension_changed')
            or extra.get('extensionChanged')
            or Path(path).suffix.lower() in {'.locked', '.encrypted', '.crypt', '.wncry', '.ryuk', '.zzzzz'}
        )
        encryption_indicator = bool(
            module_type == 'ransomware'
            or extension_changed
            or 'encrypt' in reason.lower()
            or 'ransom' in reason.lower()
        )

        import socket
        capability_ids = {2}
        if file_hash:
            capability_ids.add(25)
        if module_type in {'sensitive', 'permission', 'ownership', 'ransomware'}:
            capability_ids.add(12)
        if encryption_indicator:
            capability_ids.add(27)
        normalized_path = path.lower().replace('\\', '/')
        system_change_file = _is_critical_system_file(path) or any(token in normalized_path for token in (
            '/etc/ssh/', '/etc/hosts', '/etc/resolv.conf', '/etc/fstab', '/etc/crontab',
            '/etc/cron.', '/etc/systemd/', '/etc/pam.d/', '/etc/security/', '/etc/audit/',
            '/etc/sysctl', '/boot/grub', '/launchagents/', '/launchdaemons/',
            'c:/windows/system32', 'c:/windows/syswow64',
        )) or module_type in {'permission', 'ownership'}
        if system_change_file:
            capability_ids.add(7)
        configuration_file = _is_configuration_path(path)
        if configuration_file:
            capability_ids.add(6)
        persistence_file = any(token in normalized_path for token in (
            '/.ssh/authorized_keys', '/etc/ssh/sshd_config', '/etc/crontab', '/etc/cron.',
            '/etc/systemd/system/', '/etc/init.d/', '/etc/rc.local', '/launchagents/',
            '/launchdaemons/', '/startup/',
        ))
        if persistence_file:
            capability_ids.add(8)
        alert: dict = {
            'capabilityId':  2,
            'capabilityIds': sorted(capability_ids),
            'rule_id':       f'FILE_{event_type.upper()}',
            'category':      category,
            'severity':      severity,
            'description':   reason + (' [PRIVATE — hash redacted]' if private else ''),
            'file_path':     path if not private else '[redacted]',
            'file_name':     Path(path).name if not private else '[redacted]',
            'file_hash':     file_hash,
            'file_hash_sha1': file_hash_sha1,
            'file_hash_md5': file_hash_md5,
            'sha256':        file_hash,
            'sha1':          file_hash_sha1,
            'md5':           file_hash_md5,
            'signature_status': trust.get('signatureStatus'),
            'trust_status': trust.get('trustStatus'),
            'publisher': trust.get('publisher'),
            'certificate_subject': trust.get('certificateSubject'),
            'certificate_issuer': trust.get('certificateIssuer'),
            'certificate_serial': trust.get('certificateSerial'),
            'certificate_thumbprint': trust.get('certificateThumbprint'),
            'certificate_valid_from': trust.get('certificateValidFrom'),
            'certificate_valid_until': trust.get('certificateValidUntil'),
            'package_owner': trust.get('packageOwner'),
            'package_verification_status': trust.get('packageVerificationStatus'),
            'file_action':   event_type,
            'file_user':     file_user,
            'module_type':   module_type,
            'fim_module':    module_type,
            'old_hash':      extra.get('old_hash') or extra.get('oldHash') or '',
            'new_hash':      file_hash,
            'oldHash':       extra.get('oldHash') or extra.get('old_hash') or '',
            'newHash':       file_hash,
            'hash_algorithm': 'sha256',
            'hashAlgorithm':  'sha256',
            'change_type':   event_type,
            'old_permission': extra.get('old_permission') or extra.get('oldPermission') or '',
            'new_permission': extra.get('new_permission') or extra.get('newPermission') or permission,
            'permission_risk': permission_risk,
            'changed_by_user': extra.get('changed_by_user') or extra.get('changedByUser') or _active_user(),
            'old_owner':     extra.get('old_owner') or extra.get('oldOwner') or '',
            'new_owner':     file_user,
            'old_group':     extra.get('old_group') or extra.get('oldGroup') or '',
            'new_group':     file_group,
            'event_type':    event_type,
            'extension_changed': extension_changed,
            'mass_rename_count': extra.get('mass_rename_count') or extra.get('massRenameCount') or 0,
            'encryption_indicator': encryption_indicator,
            'process_name':  extra.get('process_name') or extra.get('processName') or '',
            'user':          file_user,
            'sensitivity_type': sensitivity,
            'data_event_type': f'file_{event_type}',
            'data_classification': 'Restricted' if dlp_metadata else _data_classification(path, sensitivity),
            'dlp_pattern': dlp_metadata.get('dlp_pattern'),
            'dlp_match_count': dlp_metadata.get('dlp_match_count', 0),
            'raw': {
                'dlp_pattern_categories': dlp_metadata.get('dlp_pattern_categories', []),
                'collection_scope': dlp_metadata.get('collection_scope', 'file metadata only; contents were not transmitted'),
            },
            'action':        action_detail,
            'accessed_by_user': file_user,
            'permission_status': permission,
            'source':        'file_watch',
            'hostname':      _safe_hostname(),
            'raw_log':       f'FILE:{event_type}|{"[private]" if private else path}',
            'timestamp':     event_time,
            'file_mtime':    event_time,
            # VT note: if is_malware_candidate=True but no VT data yet:
            # sender will mark UNDER_OBSERVATION until VT confirms
            '_awaiting_vt':  is_malware_candidate and bool(file_hash),
        }

        if system_change_file:
            risk_score = {
                'deleted': 82, 'hash_changed': 80, 'permission_changed': 72,
                'ownership_changed': 68, 'renamed': 62, 'modified': 58, 'created': 48,
            }.get(event_type, 45)
            if _is_critical_system_file(path):
                risk_score += 12
            if permission_risk:
                risk_score += 12
            risk_score = min(100, risk_score)
            alert.update({
                'system_change_category': _system_change_category(path, module_type),
                'system_change_type': event_type,
                'system_change_target': path if not private else '[redacted]',
                'previous_state': {
                    'hash': extra.get('old_hash') or extra.get('oldHash') or '',
                    'permission': extra.get('old_permission') or extra.get('oldPermission') or '',
                    'owner': extra.get('old_owner') or extra.get('oldOwner') or '',
                    'group': extra.get('old_group') or extra.get('oldGroup') or '',
                },
                'new_state': {
                    'hash': file_hash,
                    'permission': permission,
                    'owner': file_user,
                    'group': file_group,
                },
                'baseline_status': 'unexpected',
                'change_source': 'file_watch',
                'risk_score': risk_score,
                'detection_reason': reason,
                'confidence_score': 88 if _is_critical_system_file(path) else 72,
            })

        if configuration_file:
            configuration_category = _configuration_category(path)
            configuration_risk = {
                'deleted': 82, 'permission_changed': 76, 'ownership_changed': 72,
                'hash_changed': 68, 'modified': 58, 'created': 52, 'renamed': 50,
            }.get(event_type, 45)
            if configuration_category in {'user_authentication', 'security_configuration', 'persistence'}:
                configuration_risk = min(100, configuration_risk + 12)
            alert.update({
                'configuration_category': configuration_category,
                'configuration_operation': event_type,
                'configuration_object': path if not private else '[redacted]',
                'configuration_platform': 'solaris' if SYSTEM == 'SunOS' else SYSTEM.lower(),
                'configuration_baseline_status': 'unexpected',
                'configuration_policy_violation': configuration_risk >= 60,
                'configuration_risk_factors': [configuration_category, event_type],
                'old_value': alert.get('previous_state'),
                'new_value': alert.get('new_state'),
                'risk_score': max(int(alert.get('risk_score') or 0), configuration_risk),
                'detection_reason': reason,
            })

        if persistence_file:
            alert.update({
                'is_persistence': True,
                'persistence_type': (
                    'ssh_key' if 'authorized_keys' in normalized_path else
                    'cron' if '/cron' in normalized_path else
                    'systemd' if '/systemd/' in normalized_path else
                    'macos_launch_item' if '/launchagent' in normalized_path or '/launchdaemon' in normalized_path else
                    'startup'
                ),
                'persistence_location': path,
                'persistence_key': Path(path).name,
                'detection_reason': reason,
                'mitre_id': (
                    'T1098.004' if 'authorized_keys' in normalized_path else
                    'T1053.003' if '/cron' in normalized_path else 'T1547'
                ),
                'technique': (
                    'SSH Authorized Keys' if 'authorized_keys' in normalized_path else
                    'Scheduled Task/Job: Cron' if '/cron' in normalized_path else 'Boot or Logon Autostart Execution'
                ),
            })

        if is_malware_candidate:
            alert['malware_type'] = (
                'Ransomware' if 'Ransomware' in reason else
                'WebShell'   if 'Web shell'  in reason else
                'Suspicious'   # NOT "Generic Malware" — awaiting VT
            )

        if extra:
            alert.update(extra)

        # Store in local FIFO
        self._store_event(path, alert)

        # Hand to sender (sender applies VT rules + INSTALL_TIME check)
        self._sender.enqueue(alert)


    def _emit_state_delta(self, path: str, prev: dict, current: dict, event_type: str = 'modified'):
        """Emit the most specific FIM event for a file state change."""
        prev = prev or {}
        current = current or {}
        if prev.get('permission') and current.get('permission') and prev.get('permission') != current.get('permission'):
            self._emit(path, 'permission_changed', {
                'module_type': 'permission',
                'old_permission': prev.get('permission', ''),
                'new_permission': current.get('permission', ''),
                'changed_by_user': _active_user(),
                'file_user': current.get('owner', ''),
                'description': f'File permission changed: {Path(path).name}',
            })
            return
        if (
            (prev.get('owner') and current.get('owner') and prev.get('owner') != current.get('owner'))
            or (prev.get('group') and current.get('group') and prev.get('group') != current.get('group'))
        ):
            self._emit(path, 'ownership_changed', {
                'module_type': 'ownership',
                'old_owner': prev.get('owner', ''),
                'new_owner': current.get('owner', ''),
                'old_group': prev.get('group', ''),
                'new_group': current.get('group', ''),
                'changed_by_user': current.get('owner', ''),
                'description': f'File ownership changed: {Path(path).name}',
            })
            return
        if prev.get('sha256') and current.get('sha256') and prev.get('sha256') != current.get('sha256'):
            self._emit(path, 'hash_changed', {
                'module_type': 'integrity',
                'old_hash': prev.get('sha256', ''),
                'new_hash': current.get('sha256', ''),
                'hash_algorithm': 'sha256',
                'change_type': 'hash_changed',
                'description': f'File hash changed: {Path(path).name}',
            })
            return
        self._emit(path, event_type, {
            'module_type': 'integrity' if event_type in {'created', 'modified', 'deleted', 'renamed'} else 'general',
            'old_hash': prev.get('sha256', ''),
            'new_hash': current.get('sha256', ''),
            'hash_algorithm': 'sha256' if (prev.get('sha256') or current.get('sha256')) else '',
            'change_type': event_type,
        })

    # ── Watchdog (preferred) ──────────────────────────────────────────────────
    def _start(self):
        try:
            from watchdog.observers import Observer
            from watchdog.events    import FileSystemEventHandler

            agent = self

            class Handler(FileSystemEventHandler):
                def on_created(self, event):
                    if not event.is_directory:
                        if _in_skip_dir(event.src_path) or not _should_store(event.src_path):
                            return
                        current = agent._state(event.src_path)
                        agent._emit(event.src_path, 'created', {
                            'module_type': 'integrity',
                            'new_hash': current.get('sha256', ''),
                            'hash_algorithm': 'sha256' if current.get('sha256') else '',
                            'change_type': 'created',
                        })
                        agent._seen[event.src_path] = current

                def on_modified(self, event):
                    if not event.is_directory:
                        if _in_skip_dir(event.src_path) or not _should_store(event.src_path):
                            return
                        prev = agent._seen.get(event.src_path)
                        current = agent._state(event.src_path, previous=prev)
                        agent._emit_state_delta(event.src_path, prev, current, 'modified')
                        agent._seen[event.src_path] = current

                def on_deleted(self, event):
                    if not event.is_directory:
                        if _in_skip_dir(event.src_path) or not _should_store(event.src_path):
                            return
                        prev = agent._seen.pop(event.src_path, {})
                        agent._emit(event.src_path, 'deleted', {
                            'module_type': 'integrity',
                            'old_hash': prev.get('sha256', ''),
                            'hash_algorithm': 'sha256' if prev.get('sha256') else '',
                            'change_type': 'deleted',
                        })

                def on_moved(self, event):
                    if not event.is_directory:
                        if _in_skip_dir(event.dest_path) or not _should_store(event.dest_path):
                            return
                        prev = agent._seen.pop(event.src_path, {})
                        current = agent._state(event.dest_path)
                        agent._seen[event.dest_path] = current
                        agent._emit(event.dest_path, 'renamed',
                                    {
                                        'module_type': 'integrity',
                                        'old_hash': prev.get('sha256', ''),
                                        'new_hash': current.get('sha256', ''),
                                        'hash_algorithm': 'sha256' if (prev.get('sha256') or current.get('sha256')) else '',
                                        'change_type': 'renamed',
                                        'raw_log': f'FILE:moved|{event.src_path}→{event.dest_path}',
                                    })

            observer = Observer()
            handler  = Handler()
            dirs     = self._watch_dirs()
            watches = {}
            for d in dirs:
                if Path(d).exists():
                    try:
                        watches[d] = observer.schedule(handler, d, recursive=True)
                        logger.info('File monitor watching: %s', d)
                    except Exception as e:
                        logger.debug('Cannot watch %s: %s', d, e)

            if not watches:
                logger.warning('File monitor: no dirs — falling back to polling')
                self._poll()
                return

            observer.start()
            logger.info('File monitor started (watchdog native events) — %d dirs', len(watches))
            while observer.is_alive():
                time.sleep(30)
                desired = {path for path in self._watch_dirs() if Path(path).exists()}
                for removed in set(watches) - desired:
                    try:
                        observer.unschedule(watches.pop(removed))
                        logger.info('File monitor stopped watching: %s', removed)
                    except Exception as exc:
                        logger.debug('Cannot remove watch %s: %s', removed, exc)
                for added in desired - set(watches):
                    try:
                        watches[added] = observer.schedule(handler, added, recursive=True)
                        logger.info('File monitor now watching: %s', added)
                    except Exception as exc:
                        logger.debug('Cannot add watch %s: %s', added, exc)

        except ImportError:
            logger.info('watchdog not installed — using polling. pip3 install watchdog')
            self._poll()
        except Exception as e:
            logger.warning('File monitor watchdog error: %s — polling fallback', e)
            self._poll()

    # ── Polling fallback ──────────────────────────────────────────────────────
    def _poll(self):
        interval = self._cfg_int('file_monitor_poll_interval_seconds', 60, minimum=10)
        max_files = self._cfg_int('file_monitor_poll_max_files', MAX_POLL_FILES, minimum=100)
        logger.info('File monitor polling configured dirs every %ds (max %d files)', interval, max_files)
        first_run = True

        while True:
            dirs = self._watch_dirs()
            current: dict = {}
            file_count = 0

            for watch_dir in dirs:
                d = Path(watch_dir)
                if not d.exists():
                    continue
                try:
                    for f in d.rglob('*'):
                        if not f.is_file():
                            continue
                        if _in_skip_dir(str(f)):
                            continue
                        if not _should_store(str(f)):  # §4 filter
                            continue
                        file_count += 1
                        if file_count > max_files:
                            break
                        try:
                            path = str(f)
                            state = self._state(path, previous=self._seen.get(path))
                            if state:
                                current[path] = state
                        except OSError:
                            pass
                except PermissionError:
                    pass

            if not first_run:
                for path, state in current.items():
                    prev = self._seen.get(path)
                    if prev is None:
                        self._emit(path, 'created', {
                            'module_type': 'integrity',
                            'new_hash': state.get('sha256', ''),
                            'hash_algorithm': 'sha256' if state.get('sha256') else '',
                            'change_type': 'created',
                        })
                    elif (
                        prev.get('mtime') != state.get('mtime')
                        or prev.get('size') != state.get('size')
                        or prev.get('permission') != state.get('permission')
                        or prev.get('owner') != state.get('owner')
                        or prev.get('group') != state.get('group')
                        or prev.get('sha256') != state.get('sha256')
                    ):
                        self._emit_state_delta(path, prev, state, 'modified')

                for path in set(self._seen) - set(current):
                    prev = self._seen.get(path, {})
                    self._emit(path, 'deleted', {
                        'module_type': 'integrity',
                        'old_hash': prev.get('sha256', ''),
                        'hash_algorithm': 'sha256' if prev.get('sha256') else '',
                        'change_type': 'deleted',
                    })

            self._seen   = current
            first_run    = False
            time.sleep(interval)


def _safe_hostname() -> str:
    try:
        import socket
        return socket.gethostname()
    except Exception:
        return 'unknown'
