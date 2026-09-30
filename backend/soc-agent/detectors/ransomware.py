"""
Ransomware & Encryption Detector — Agent Module
Detects ransomware behavior in real-time:
  - Mass file encryption / modification
  - High entropy file detection
  - Ransom note creation
  - Shadow copy deletion
  - Backup tampering
  - Encryption process monitoring
"""

import os
import re
import math
import time
import logging
import platform
import threading
import hashlib
from datetime import datetime, timezone
from collections import defaultdict, deque
from pathlib import Path

logger = logging.getLogger('soc-agent.ransomware')
SYSTEM = platform.system()

# ── Known ransomware file extensions ────────────────────────────────────────
RANSOMWARE_EXTENSIONS = {
    '.locked', '.encrypted', '.crypt', '.crypted', '.enc',
    '.lockbit', '.ryuk', '.akira', '.blackcat', '.conti', '.clop',
    '.revil', '.sodinokibi', '.maze', '.egregor', '.netwalker',
    '.phobos', '.dharma', '.crysis', '.makop', '.stop',
    '.djvu', '.wannacry', '.wncry', '.wcry', '.petya',
    '.notpetya', '.badrabbit', '.cerber', '.locky', '.thor',
    '.zepto', '.osiris', '.zzzzz', '.micro', '.vvv',
    '.ccc', '.abc', '.xyz', '.aaa', '.bbb',
    '.pays', '.ransom', '.rdmk', '.corona',
}

# ── Ransom note filenames ────────────────────────────────────────────────────
RANSOM_NOTE_NAMES = {
    'readme.txt', 'readme!.txt', 'read_me.txt', 'read-me.txt',
    'how_to_decrypt.txt', 'how_to_decrypt.html', 'how_to_recover.txt',
    'recover_files.txt', 'recover_files.html', 'recover_data.txt',
    'decrypt_instructions.txt', 'decrypt_instructions.html',
    'files_encrypted.html', 'files_encrypted.txt',
    'attention.txt', 'your_files.txt', 'message.txt',
    '!!! all your files are encrypted !!!.txt',
    '_readme.txt', 'help_decrypt.html', 'help_your_files.html',
    'info.hta', 'decrypt.html', 'ransom.txt',
    'restore_files.txt', 'restore_your_files.txt',
    '#decrypt#.txt', '#help#.txt', '!readme!.txt',
}

# ── Sensitive directories to protect ────────────────────────────────────────
SENSITIVE_DIRS_LINUX = [
    Path.home() / 'Documents',
    Path.home() / 'Desktop',
    Path.home() / 'Downloads',
    Path.home() / 'Pictures',
    Path.home() / 'Videos',
    Path('/var/backups'),
    Path('/srv'),
    Path('/opt'),
]

SENSITIVE_DIRS_WINDOWS = [
    Path.home() / 'Documents',
    Path.home() / 'Desktop',
    Path.home() / 'Downloads',
    Path.home() / 'Pictures',
    Path.home() / 'Videos',
    Path('C:/Users/Public'),
]

# ── Shadow copy deletion patterns ────────────────────────────────────────────
SHADOW_DELETION_PATTERNS = [
    re.compile(r'vssadmin.*(delete|resize).*shadows', re.IGNORECASE),
    re.compile(r'wmic.*shadowcopy.*delete', re.IGNORECASE),
    re.compile(r'wbadmin.*delete.*catalog', re.IGNORECASE),
    re.compile(r'bcdedit.*(recoveryenabled|bootstatuspolicy)', re.IGNORECASE),
    re.compile(r'diskshadow.*/s.*\.txt', re.IGNORECASE),
    re.compile(r'powershell.*(Get-WmiObject.*Win32_ShadowCopy|Remove-WmiObject.*Win32_ShadowCopy)', re.IGNORECASE),
]

# ── Encryption process indicators ────────────────────────────────────────────
ENCRYPTION_PROC_PATTERNS = [
    re.compile(r'(openssl.*enc|gpg\s+--symmetric|gpg\s+-c\s)', re.IGNORECASE),
    re.compile(r'(python.*cryptography|python.*pycryptodome|python.*Fernet)', re.IGNORECASE),
    re.compile(r'(7z\s+a.*-p|winrar.*-p\S+|7zip.*-p)', re.IGNORECASE),
    re.compile(r'(cipher\s+/e|cipher\s+/d)', re.IGNORECASE),
]

# ── Backup tampering patterns ─────────────────────────────────────────────────
BACKUP_TAMPER_PATTERNS = [
    re.compile(r'(net\s+stop\s+(VSSVC|SQLAgent|MSSQLServer|backup|wbengine))', re.IGNORECASE),
    re.compile(r'(sc\s+stop|sc\s+delete).*(backup|vss|wbengine|MSExchange)', re.IGNORECASE),
    re.compile(r'(taskkill.*/f.*(backup|vss|acronis|veeam))', re.IGNORECASE),
    re.compile(r'(rm\s+-rf.*/var/lib/postgresql|rm\s+-rf.*backup)', re.IGNORECASE),
    re.compile(r'(del\s+/f.*/q.*backup|rmdir\s+/s.*/q.*backup)', re.IGNORECASE),
]


def _calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of byte data (0.0 - 8.0)."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    total = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _get_file_entropy(path: str, sample_size: int = 65536) -> float:
    """Get entropy of a file (samples first 64KB for performance)."""
    try:
        with open(path, 'rb') as f:
            data = f.read(sample_size)
        return _calculate_entropy(data)
    except Exception:
        return 0.0


class RansomwareDetector:
    """
    Real-time ransomware detection engine.
    Monitors filesystem events, process behavior, and system configuration.
    """

    def __init__(self, sender, config=None):
        self._sender    = sender
        self._config    = config or {}
        self._stop      = threading.Event()

        # Sliding-window counters for mass-operation detection
        self._window_secs = int(self._config.get('ransomware_window_secs', 30))
        self._file_events = deque()       # (timestamp, event_type, path)
        self._entropy_hits = []           # (timestamp, path, entropy)
        self._lock = threading.Lock()
        self._recent_suspicious_process = None

        # Thresholds
        self._mass_mod_threshold   = int(self._config.get('mass_mod_threshold', 50))
        self._mass_del_threshold   = int(self._config.get('mass_del_threshold', 30))
        self._entropy_threshold    = float(self._config.get('entropy_threshold', 7.0))
        self._entropy_file_trigger = int(self._config.get('entropy_file_trigger', 10))
        custom_extensions = self._config.get('ransomware_extensions', []) or []
        self._extensions = set(RANSOMWARE_EXTENSIONS)
        self._extensions.update(
            value if str(value).startswith('.') else f'.{value}'
            for value in (str(item).strip().lower() for item in custom_extensions)
            if value and len(value) <= 32
        )

        # Rate limiting for alerts
        self._alerted = {}  # alert_key → last_alert_time

        # Threads
        self._threads = []

    def _protected_directories(self):
        """Return existing, de-duplicated protected roots without scanning them."""
        defaults = list(SENSITIVE_DIRS_WINDOWS if SYSTEM == 'Windows' else SENSITIVE_DIRS_LINUX)
        if SYSTEM == 'Windows':
            users_root = Path(os.environ.get('SystemDrive', 'C:')) / 'Users'
            user_folders = ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos')
        else:
            users_root = Path('/home')
            user_folders = ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos')

        # Protect all local user profiles, not only the account running the
        # service. Directory enumeration is bounded to the immediate children.
        try:
            for profile in users_root.iterdir():
                if profile.is_dir():
                    defaults.extend(profile / folder for folder in user_folders)
        except OSError:
            pass

        configured = (
            self._config.get('ransomware_protected_dirs')
            or self._config.get('ransomware_sensitive_dirs')
            or []
        )
        if isinstance(configured, str):
            configured = [item.strip() for item in configured.split(',') if item.strip()]
        defaults.extend(Path(os.path.expandvars(os.path.expanduser(str(item)))) for item in configured)

        result = []
        seen = set()
        for item in defaults:
            try:
                normalized = str(item.resolve())
            except OSError:
                normalized = os.path.abspath(str(item))
            key = os.path.normcase(normalized)
            if key in seen or not os.path.isdir(normalized):
                continue
            seen.add(key)
            result.append(Path(normalized))
        return result

    @staticmethod
    def _hash_executable(path, max_bytes=256 * 1024 * 1024):
        """Hash only bounded executable files after a suspicious match."""
        if not path:
            return {}
        try:
            if not os.path.isfile(path) or os.path.getsize(path) > max_bytes:
                return {}
            sha256 = hashlib.sha256()
            md5 = hashlib.md5(usedforsecurity=False)
            with open(path, 'rb') as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                    sha256.update(chunk)
                    md5.update(chunk)
            return {'executable_sha256': sha256.hexdigest(), 'executable_md5': md5.hexdigest()}
        except (OSError, TypeError, ValueError):
            return {}

    def _process_evidence(self, proc):
        """Collect bounded forensic context only for a matched process."""
        evidence = {}
        try:
            exe = proc.exe()
            if exe:
                evidence['process_exe'] = exe
                evidence.update(self._hash_executable(exe))
        except Exception:
            pass
        try:
            evidence['memory_percent'] = round(float(proc.memory_percent()), 3)
            evidence['memory_mb'] = round(float(proc.memory_info().rss) / (1024 * 1024), 3)
        except Exception:
            pass
        try:
            io = proc.io_counters()
            evidence['disk_read_bytes'] = int(io.read_bytes)
            evidence['disk_write_bytes'] = int(io.write_bytes)
        except Exception:
            pass
        try:
            evidence['process_create_time'] = datetime.fromtimestamp(
                proc.create_time(), tz=timezone.utc
            ).isoformat()
        except Exception:
            pass
        try:
            parent = proc.parent()
            if parent:
                evidence['parent_pid'] = parent.pid
                evidence['parent_process_name'] = parent.name()
                evidence['parent_cmdline'] = ' '.join(parent.cmdline())[:500]
        except Exception:
            pass
        return evidence

    def _remember_suspicious_process(self, proc, name, pid, cmdline, username):
        evidence = {
            'process_name': name,
            'process_cmdline': cmdline[:500],
            'pid': pid,
            'username': username,
            'cpu_percent': proc.info.get('cpu_percent'),
            'process_attribution': 'matched_encryption_or_recovery_command',
            **self._process_evidence(proc),
        }
        with self._lock:
            self._recent_suspicious_process = (time.time(), evidence)
        return evidence

    def _recent_process_evidence(self):
        with self._lock:
            recent = self._recent_suspicious_process
        if not recent or time.time() - recent[0] > max(60, self._window_secs * 2):
            return {}
        return dict(recent[1])

    def _enqueue(self, alert):
        if self._config.get('ransomware_enabled', True) is False:
            return
        overrides = self._config.get('ransomware_rule_overrides', {}) or {}
        override = overrides.get(str(alert.get('rule_id') or ''), {})
        if override.get('enabled') is False:
            return
        if override.get('severity') in {'low', 'medium', 'high', 'critical'}:
            alert['severity'] = override['severity']
        alert.setdefault('capabilityId', 27)
        ids = {27, *(alert.get('capabilityIds') or [])}
        if alert.get('process_name') or alert.get('pid'):
            ids.add(1)
        if alert.get('file_path') or alert.get('affected_files'):
            ids.add(2)
        alert['capabilityIds'] = sorted(ids)
        alert.setdefault('subCategory', 'encryption-ransomware-detection')
        alert.setdefault('recommended_action', 'Preserve evidence and request approved endpoint isolation if encryption is confirmed.')
        self._sender.enqueue(alert)

    def start(self):
        monitors = [
            threading.Thread(target=self._monitor_filesystem,  daemon=True, name='ransom-fs'),
            threading.Thread(target=self._monitor_processes,   daemon=True, name='ransom-proc'),
            threading.Thread(target=self._monitor_shadow_copy, daemon=True, name='ransom-vss'),
            threading.Thread(target=self._window_sweeper,      daemon=True, name='ransom-sweep'),
        ]
        for t in monitors:
            t.start()
            self._threads.append(t)
        logger.info('Ransomware detector started')

    def stop(self):
        """Request a graceful stop and briefly join detector threads."""
        self._stop.set()
        for thread in self._threads:
            if thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=2)

    def _rate_limited(self, key: str, cooldown: int = 120) -> bool:
        """Return True if we should suppress this alert (already fired recently)."""
        configured_cooldown = int(self._config.get('ransomware_alert_cooldown_seconds', cooldown))
        cooldown = max(cooldown, configured_cooldown)
        now = time.time()
        last = self._alerted.get(key, 0)
        if now - last < cooldown:
            return True
        self._alerted[key] = now
        return False

    # ── Filesystem Monitor ────────────────────────────────────────────────────
    def _monitor_filesystem(self):
        """Watch sensitive directories for mass operations and ransom notes."""
        try:
            from watchdog.observers import Observer
            from watchdog.events import FileSystemEventHandler
        except ImportError:
            logger.warning('watchdog not installed — using polling filesystem monitor')
            self._poll_filesystem()
            return

        dirs = self._protected_directories()

        if not dirs:
            logger.warning('No sensitive directories found for monitoring')
            return

        detector = self

        class _Handler(FileSystemEventHandler):
            def on_modified(self, event):
                if not event.is_directory:
                    detector._handle_file_event('modified', event.src_path)

            def on_created(self, event):
                if not event.is_directory:
                    detector._handle_file_event('created', event.src_path)

            def on_deleted(self, event):
                if not event.is_directory:
                    detector._handle_file_event('deleted', event.src_path)

            def on_moved(self, event):
                if not event.is_directory:
                    detector._handle_file_event('renamed', event.dest_path)

        observer = Observer()
        handler  = _Handler()
        for d in dirs:
            try:
                observer.schedule(handler, str(d), recursive=True)
                logger.info('Ransomware: watching %s', d)
            except Exception as e:
                logger.debug('Cannot watch %s: %s', d, e)

        try:
            observer.start()
            while not self._stop.is_set():
                time.sleep(1)
            observer.stop()
            observer.join()
        except Exception as e:
            logger.warning('Filesystem observer error: %s', e)

    def _poll_filesystem(self):
        """Fallback polling monitor when watchdog is unavailable."""
        dirs = self._protected_directories()
        snapshots = {}  # path → mtime

        while not self._stop.is_set():
            for watch_dir in dirs:
                try:
                    for root, _, files in os.walk(str(watch_dir)):
                        for fname in files:
                            fpath = os.path.join(root, fname)
                            try:
                                mtime = os.path.getmtime(fpath)
                                if fpath in snapshots and snapshots[fpath] != mtime:
                                    self._handle_file_event('modified', fpath)
                                snapshots[fpath] = mtime
                            except Exception:
                                pass
                except Exception:
                    pass
            time.sleep(5)

    def _handle_file_event(self, event_type: str, path: str):
        """Process a single file event."""
        if self._config.get('ransomware_enabled', True) is False:
            return
        configured_extensions = self._config.get('ransomware_extensions', []) or []
        self._extensions.update(
            value if value.startswith('.') else f'.{value}'
            for value in (str(item).strip().lower() for item in configured_extensions)
            if value and len(value) <= 32
        )
        fname    = os.path.basename(path).lower()
        ext      = os.path.splitext(fname)[1].lower()
        now      = time.time()

        # ── Ransom note detection ──
        if fname in RANSOM_NOTE_NAMES:
            if not self._rate_limited(f'ransom_note:{path}', cooldown=300):
                self._enqueue({
                    'rule_id':     'RANSOMWARE_NOTE',
                    'category':    'malware',
                    'severity':    'critical',
                    'description': f'Ransom note detected: {fname}',
                    'source':      'ransomware',
                    'malware_type': 'Ransomware',
                    'file_path':   path,
                    'file_name':   os.path.basename(path),
                    'mitre_id':    'T1486',
                    'technique':   'Data Encrypted for Impact',
                    'raw_log':     f'RANSOM_NOTE|path={path}|event={event_type}',
                })
                logger.critical('[Ransomware] Ransom note created: %s', path)

        # ── Ransomware extension detection ──
        if ext in self._extensions:
            if not self._rate_limited(f'ransom_ext:{ext}', cooldown=60):
                self._enqueue({
                    'rule_id':     'RANSOMWARE_EXTENSION',
                    'category':    'malware',
                    'severity':    'critical',
                    'description': f'Ransomware file extension detected: {ext}',
                    'source':      'ransomware',
                    'malware_type': 'Ransomware',
                    'file_path':   path,
                    'file_name':   os.path.basename(path),
                    'extension':   ext,
                    'mitre_id':    'T1486',
                    'technique':   'Data Encrypted for Impact',
                    'raw_log':     f'RANSOM_EXT|ext={ext}|path={path}',
                })
                logger.critical('[Ransomware] Ransomware extension: %s at %s', ext, path)

        # ── High-entropy file detection ──
        if event_type in ('created', 'modified') and os.path.isfile(path):
            try:
                size = os.path.getsize(path)
                if 1024 < size < 100 * 1024 * 1024:  # 1KB - 100MB
                    entropy = _get_file_entropy(path)
                    if entropy >= self._entropy_threshold:
                        with self._lock:
                            self._entropy_hits.append((now, path, entropy))
            except Exception:
                pass

        # ── Track file events for mass-operation detection ──
        with self._lock:
            self._file_events.append((now, event_type, path))

    # ── Mass-operation window sweeper ─────────────────────────────────────────
    def _window_sweeper(self):
        """Periodically checks sliding window for mass file operations."""
        while not self._stop.is_set():
            time.sleep(5)
            self._check_mass_operations()

    def _check_mass_operations(self):
        # AgentConfig is updated in-place by heartbeat policy sync.
        self._window_secs = max(5, int(self._config.get('ransomware_window_secs', self._window_secs)))
        self._mass_mod_threshold = max(2, int(self._config.get('mass_mod_threshold', self._mass_mod_threshold)))
        self._mass_del_threshold = max(2, int(self._config.get('mass_del_threshold', self._mass_del_threshold)))
        self._entropy_threshold = min(8.0, max(0.0, float(self._config.get('entropy_threshold', self._entropy_threshold))))
        self._entropy_file_trigger = max(1, int(self._config.get('entropy_file_trigger', self._entropy_file_trigger)))
        now = time.time()
        cutoff = now - self._window_secs

        with self._lock:
            # Prune old events
            while self._file_events and self._file_events[0][0] < cutoff:
                self._file_events.popleft()

            modified = sum(1 for e in self._file_events if e[1] == 'modified')
            deleted  = sum(1 for e in self._file_events if e[1] == 'deleted')
            renamed  = sum(1 for e in self._file_events if e[1] == 'renamed')

            # Prune entropy hits
            self._entropy_hits = [(t, p, e) for t, p, e in self._entropy_hits if t >= cutoff]
            entropy_count = len(self._entropy_hits)

        # Mass modification alert
        # File churn alone (builds, browsers, package installs) is not proof of
        # encryption. Require multiple high-entropy writes in the same window.
        if modified + renamed >= self._mass_mod_threshold and entropy_count >= self._entropy_file_trigger:
            if not self._rate_limited('mass_modify', cooldown=120):
                affected_paths = [path for _, path, _ in self._entropy_hits]
                affected_directory = ''
                try:
                    affected_directory = os.path.commonpath(affected_paths) if affected_paths else ''
                except ValueError:
                    pass
                self._enqueue({
                    'rule_id':     'RANSOMWARE_MASS_ENCRYPTION',
                    'category':    'malware',
                    'severity':    'critical',
                    'actionable':  True,
                    'confidence_score': min(100, 70 + entropy_count),
                    'description': (
                        f'Mass file encryption detected: {modified + renamed} files '
                        f'modified/renamed in {self._window_secs}s with '
                        f'{entropy_count} high-entropy file(s)'
                    ),
                    'source':      'ransomware',
                    'malware_type': 'Ransomware',
                    'risk_score': min(100, 70 + entropy_count),
                    'affected_files': modified + renamed,
                    'affected_directory': affected_directory,
                    'entropy': round(
                        sum(e for _, _, e in self._entropy_hits) / max(entropy_count, 1), 3
                    ),
                    'encryption_speed': round((modified + renamed) / max(self._window_secs, 1), 3),
                    'modified_files_per_second': round(modified / max(self._window_secs, 1), 3),
                    'renamed_files_per_second': round(renamed / max(self._window_secs, 1), 3),
                    'deleted_files_per_second': round(deleted / max(self._window_secs, 1), 3),
                    'mitre_id':    'T1486',
                    'technique':   'Data Encrypted for Impact',
                    'raw_log': (
                        f'MASS_ENCRYPT|modified={modified}|renamed={renamed}|'
                        f'deleted={deleted}|entropy={entropy_count}|window={self._window_secs}s'
                    ),
                    **self._recent_process_evidence(),
                })
                logger.critical('[Ransomware] Mass encryption: %d files', modified + renamed)

        # Mass deletion alert
        if deleted >= self._mass_del_threshold:
            if not self._rate_limited('mass_delete', cooldown=120):
                self._enqueue({
                    'rule_id':     'RANSOMWARE_MASS_DELETION',
                    'category':    'malware',
                    'severity':    'critical',
                    'description': f'Mass file deletion detected: {deleted} files deleted in {self._window_secs}s',
                    'source':      'ransomware',
                    'malware_type': 'Ransomware',
                    'risk_score': min(100, 65 + deleted),
                    'affected_files': deleted,
                    'encryption_speed': round(deleted / max(self._window_secs, 1), 3),
                    'deleted_files_per_second': round(deleted / max(self._window_secs, 1), 3),
                    'mitre_id':    'T1485',
                    'technique':   'Data Destruction',
                    'raw_log':     f'MASS_DELETE|count={deleted}|window={self._window_secs}s',
                    **self._recent_process_evidence(),
                })
                logger.critical('[Ransomware] Mass deletion: %d files', deleted)

        # High entropy mass hit
        if entropy_count >= self._entropy_file_trigger:
            if not self._rate_limited('high_entropy_mass', cooldown=120):
                avg_entropy = sum(e for _, _, e in self._entropy_hits) / max(entropy_count, 1)
                affected_paths = [path for _, path, _ in self._entropy_hits]
                affected_directory = ''
                try:
                    affected_directory = os.path.commonpath(affected_paths) if affected_paths else ''
                except ValueError:
                    pass
                self._enqueue({
                    'rule_id':     'RANSOMWARE_HIGH_ENTROPY',
                    'category':    'malware',
                    'severity':    'critical',
                    'description': (
                        f'High-entropy file activity: {entropy_count} files with avg entropy '
                        f'{avg_entropy:.2f}/8.0 — possible encryption in progress'
                    ),
                    'source':      'ransomware',
                    'malware_type': 'Ransomware',
                    'risk_score': min(100, 70 + entropy_count),
                    'affected_files': entropy_count,
                    'affected_directory': affected_directory,
                    'entropy': round(avg_entropy, 3),
                    'mitre_id':    'T1486',
                    'technique':   'Data Encrypted for Impact',
                    'raw_log': (
                        f'HIGH_ENTROPY|count={entropy_count}|avg_entropy={avg_entropy:.2f}|'
                        f'window={self._window_secs}s'
                    ),
                    **self._recent_process_evidence(),
                })
                logger.critical('[Ransomware] High entropy mass activity: %d files', entropy_count)

    # ── Process Monitor ───────────────────────────────────────────────────────
    def _monitor_processes(self):
        """Watch for encryption-related processes."""
        try:
            import psutil
        except ImportError:
            return

        seen = set()
        while not self._stop.is_set():
            if self._config.get('ransomware_enabled', True) is False:
                self._stop.wait(5)
                continue
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'username', 'cpu_percent']):
                    try:
                        pid  = proc.info['pid']
                        name = (proc.info['name'] or '').lower()
                        cmdline_parts = proc.info.get('cmdline') or []
                        cmdline = ' '.join(cmdline_parts)
                        user    = proc.info.get('username') or ''

                        if pid in seen or not cmdline:
                            continue

                        process_evidence = None

                        # Check shadow copy deletion
                        for pat in SHADOW_DELETION_PATTERNS:
                            if pat.search(cmdline):
                                seen.add(pid)
                                if not self._rate_limited(f'shadow:{pid}', cooldown=300):
                                    process_evidence = process_evidence or self._remember_suspicious_process(proc, name, pid, cmdline, user)
                                    self._enqueue({
                                        'rule_id':     'RANSOMWARE_SHADOW_DELETE',
                                        'category':    'malware',
                                        'severity':    'critical',
                                        'description': f'Shadow copy deletion detected — ransomware pre-encryption step',
                                        'source':      'ransomware',
                                        'malware_type': 'Ransomware',
                                        'process_name': name,
                                        'process_cmdline': cmdline[:500],
                                        'pid':         pid,
                                        'username':    user,
                                        'cpu_percent': proc.info.get('cpu_percent'),
                                        'mitre_id':    'T1490',
                                        'technique':   'Inhibit System Recovery',
                                        'raw_log':     f'SHADOW_DELETE|proc={name}|pid={pid}|cmd={cmdline[:300]}',
                                        **process_evidence,
                                    })
                                    logger.critical('[Ransomware] Shadow delete: %s PID=%s', name, pid)
                                break

                        # Check encryption processes
                        for pat in ENCRYPTION_PROC_PATTERNS:
                            if pat.search(cmdline):
                                seen.add(pid)
                                if not self._rate_limited(f'enc_proc:{pid}', cooldown=60):
                                    process_evidence = process_evidence or self._remember_suspicious_process(proc, name, pid, cmdline, user)
                                    self._enqueue({
                                        'rule_id':     'RANSOMWARE_ENCRYPTION_PROC',
                                        'category':    'malware',
                                        'severity':    'high',
                                        'description': f'Encryption process detected: {name}',
                                        'source':      'ransomware',
                                        'malware_type': 'Ransomware',
                                        'process_name': name,
                                        'process_cmdline': cmdline[:500],
                                        'pid':         pid,
                                        'username':    user,
                                        'cpu_percent': proc.info.get('cpu_percent'),
                                        'mitre_id':    'T1486',
                                        'technique':   'Data Encrypted for Impact',
                                        'raw_log':     f'ENC_PROC|proc={name}|pid={pid}|cmd={cmdline[:300]}',
                                        **process_evidence,
                                    })
                                break

                        # Check backup tampering
                        for pat in BACKUP_TAMPER_PATTERNS:
                            if pat.search(cmdline):
                                seen.add(pid)
                                if not self._rate_limited(f'backup:{pid}', cooldown=300):
                                    process_evidence = process_evidence or self._remember_suspicious_process(proc, name, pid, cmdline, user)
                                    self._enqueue({
                                        'rule_id':     'RANSOMWARE_BACKUP_TAMPER',
                                        'category':    'malware',
                                        'severity':    'critical',
                                        'description': f'Backup service tampering detected: {name}',
                                        'source':      'ransomware',
                                        'malware_type': 'Ransomware',
                                        'process_name': name,
                                        'process_cmdline': cmdline[:500],
                                        'pid':         pid,
                                        'username':    user,
                                        'cpu_percent': proc.info.get('cpu_percent'),
                                        'mitre_id':    'T1490',
                                        'technique':   'Inhibit System Recovery',
                                        'raw_log':     f'BACKUP_TAMPER|proc={name}|pid={pid}|cmd={cmdline[:300]}',
                                        **process_evidence,
                                    })
                                break

                    except (Exception,):
                        continue

            except Exception as e:
                logger.debug('Process monitor error: %s', e)

            # Clean stale PIDs
            if len(seen) > 5000:
                seen.clear()

            time.sleep(5)

    # ── Shadow Copy Monitor (Windows) ─────────────────────────────────────────
    def _monitor_shadow_copy(self):
        """On Windows, watch VSS service and shadow copy count."""
        if SYSTEM != 'Windows':
            return

        baseline_count = None

        while not self._stop.is_set():
            try:
                import subprocess
                result = subprocess.run(
                    ['vssadmin', 'list', 'shadows'],
                    capture_output=True, text=True, timeout=10,
                )
                count = result.stdout.count('Shadow Copy ID')
                if baseline_count is None:
                    baseline_count = count
                elif count < baseline_count:
                    if not self._rate_limited('vss_decrease', cooldown=300):
                        self._enqueue({
                            'rule_id':     'RANSOMWARE_VSS_DELETED',
                            'category':    'malware',
                            'severity':    'critical',
                            'description': (
                                f'Volume Shadow Copies deleted: was {baseline_count}, '
                                f'now {count} — ransomware activity'
                            ),
                            'source':      'ransomware',
                            'malware_type': 'Ransomware',
                            'mitre_id':    'T1490',
                            'technique':   'Inhibit System Recovery',
                            'raw_log': (
                                f'VSS_DELETED|baseline={baseline_count}|current={count}|'
                                f'deleted={baseline_count - count}'
                            ),
                        })
                        logger.critical('[Ransomware] VSS deleted: %d → %d', baseline_count, count)
                    baseline_count = count
            except Exception as e:
                logger.debug('VSS monitor error: %s', e)

            time.sleep(60)


# Alias for agent.py _import_class discovery
Detector = RansomwareDetector
Monitor  = RansomwareDetector
