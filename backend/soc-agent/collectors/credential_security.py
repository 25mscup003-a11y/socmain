"""Privacy-safe, cross-platform credential-security telemetry collector.

Only process metadata and credential-store file metadata are collected. The
collector never reads passwords, tokens, cookies, private keys, browser login
databases, LSASS memory, Keychain contents, or credential file contents.
Authentication events are collected separately by the OS log collector and
tagged for capability 13 by the rule detector.
"""

import logging
import os
import platform
import re
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

logger = logging.getLogger('soc-agent.collector.credential_security')
SYSTEM = platform.system()

PROCESS_RULES = (
    (re.compile(r'\b(?:mimikatz|nanodump|pypykatz|lazagne|secretsdump)(?:\.exe|\.py)?\b|sekurlsa::|lsadump::', re.I),
     'CRED_DUMP_TOOL', 'Credential dumping tool execution', 'credential_theft', 'critical', 98, 'T1003'),
    (re.compile(r'\b(?:procdump|rundll32)(?:\.exe)?\b[^\r\n]*(?:lsass|comsvcs[^\r\n]*minidump)|\bcreatedump(?:\.exe)?\b[^\r\n]*lsass', re.I),
     'CRED_LSASS_DUMP', 'Attempt to dump LSASS process memory', 'lsass_access', 'critical', 99, 'T1003.001'),
    (re.compile(r'\breg(?:\.exe)?\s+save\s+(?:hklm\\)?(?:sam|security|system)\b|\b(?:secretsdump|samdump2|pwdump)(?:\.py|\.exe)?\b', re.I),
     'CRED_SAM_SECRETS_DUMP', 'SAM or LSA Secrets extraction attempt', 'sam_access', 'critical', 97, 'T1003.002'),
    (re.compile(r'\b(?:rubeus|kekeo)(?:\.exe)?\b|kerberoast|asreproast|golden.ticket|silver.ticket|pass.the.ticket', re.I),
     'CRED_KERBEROS_ABUSE', 'Kerberos ticket or roasting abuse detected', 'kerberos_abuse', 'critical', 96, 'T1558'),
    (re.compile(r'\b(?:pth-winexe|evil-winrm|crackmapexec|netexec)(?:\.exe|\.py)?\b|pass.the.hash|overpass.the.hash', re.I),
     'CRED_PASS_THE_HASH', 'Pass-the-Hash credential abuse detected', 'pass_the_hash', 'critical', 97, 'T1550.002'),
    (re.compile(r'\b(?:vaultcmd|cmdkey)(?:\.exe)?\b|\brundll32(?:\.exe)?\b[^\r\n]*(?:keymgr|krshowkeymgr)|\bGet-StoredCredential\b', re.I),
     'CRED_WINDOWS_VAULT_ACCESS', 'Windows Credential Manager or Vault access', 'secrets_access', 'high', 84, 'T1555'),
    (re.compile(r'\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)|\b(?:keychain_dumper|chainbreaker)\b', re.I),
     'CRED_MACOS_KEYCHAIN_ACCESS', 'macOS Keychain credential access', 'keychain_access', 'critical', 94, 'T1555.001'),
    (re.compile(r'\b(?:cat|cp|scp|tar|zip|7z|openssl)\b[^\r\n]*(?:/etc/(?:shadow|gshadow)|/\.ssh/(?:id_[a-z0-9]+|authorized_keys)|\.aws/credentials|\.config/gcloud/credentials)', re.I),
     'CRED_UNIX_SECRET_FILE_ACCESS', 'Credential or private-key file accessed by a process', 'secrets_access', 'high', 88, 'T1552.004'),
    (re.compile(r'(?:Login Data|logins\.json|key4\.db|Web Data|KeePass[^\s]*\.kdbx)', re.I),
     'CRED_BROWSER_PASSWORD_STORE_ACCESS', 'Browser or password-manager credential store referenced', 'browser_password_access', 'high', 86, 'T1555.003'),
    (re.compile(r'\b(?:runas|sudo|su)(?:\.exe)?\b|Start-Process[^\r\n]*-Credential', re.I),
     'CRED_EXPLICIT_PRIVILEGED_AUTH', 'Explicit privileged credential use', 'privileged_authentication', 'medium', 55, 'T1078'),
)


def _utc(value=None):
    return datetime.fromtimestamp(value or time.time(), timezone.utc).isoformat()


def _credential_paths():
    paths = [Path('/etc/shadow'), Path('/etc/gshadow')]
    homes = []
    if SYSTEM == 'Windows':
        root = Path(os.environ.get('SystemDrive', 'C:')) / 'Users'
    elif SYSTEM == 'Darwin':
        root = Path('/Users')
    else:
        root = Path('/home')
        homes.append(Path('/root'))
    try:
        if root.exists():
            homes.extend(path for path in root.iterdir() if path.is_dir())
    except (OSError, PermissionError):
        pass
    for home in homes:
        paths.extend((home / '.ssh' / 'authorized_keys', home / '.aws' / 'credentials'))
        if SYSTEM == 'Darwin':
            paths.append(home / 'Library' / 'Keychains' / 'login.keychain-db')
    return paths


def _match_process(name, cmdline):
    text = f'{name or ""} {cmdline or ""}'
    for pattern, rule_id, description, event_type, severity, risk, mitre in PROCESS_RULES:
        if pattern.search(text):
            return {
                'rule_id': rule_id, 'description': description,
                'credential_event_type': event_type, 'severity': severity,
                'risk_score': risk, 'mitre_id': mitre,
            }
    return None


class CredentialSecurityCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._seen_processes = set()
        self._file_state = {}
        self._thread = threading.Thread(target=self._loop, daemon=True, name='credential-security-monitor')

    def start(self):
        if psutil is None:
            logger.warning('psutil unavailable; credential security process monitor disabled')
            return
        try:
            self._seen_processes = {(proc.pid, float(proc.create_time())) for proc in psutil.process_iter(['pid', 'create_time'])}
        except (psutil.Error, OSError, ValueError):
            pass
        self._file_state = self._credential_file_state()
        self._thread.start()

    def _emit(self, **values):
        if not self._config.get('credential_security_monitoring_enabled', True):
            return
        rule_id = values.get('rule_id')
        enabled_rule_ids = self._config.get('credential_enabled_rule_ids', None)
        if enabled_rule_ids is not None and rule_id not in set(enabled_rule_ids or []):
            return
        if int(values.get('risk_score') or 0) < max(0, min(100, int(self._config.get('credential_minimum_risk_score', 50)))):
            return
        overrides = self._config.get('credential_rule_overrides', {}) or {}
        override = overrides.get(rule_id, {}) if isinstance(overrides, dict) else {}
        if isinstance(override, dict) and override.get('severity') in ('low', 'medium', 'high', 'critical'):
            values['severity'] = override['severity']
        event_type = str(values.get('credential_event_type') or values.get('eventType') or 'credential_security')
        risk_score = int(values.get('risk_score') or 0)
        self._sender.enqueue({
            'capabilityId': 13, 'capabilityIds': [11, 13], 'category': 'edr',
            'subCategory': 'credential-security', 'source': 'credential_security',
            'timestamp': _utc(), 'mitre_tactic': 'Credential Access',
            'confidence_score': 92, 'actionable': True,
            'behavior_category': 'Authentication' if 'auth' in event_type else 'Endpoint Behavior',
            'entity_type': 'user' if values.get('username') else 'endpoint',
            'entity_id': values.get('username') or values.get('process_name'),
            'behavior_score': risk_score, 'peer_deviation_score': risk_score,
            'ueba_confidence': 92, 'ueba_risk_factors': [event_type],
            'baseline_window_days': 30, **values,
        })

    def _credential_file_state(self):
        state = {}
        for path in _credential_paths():
            try:
                stat = path.stat()
                state[str(path)] = (stat.st_mtime_ns, stat.st_size, stat.st_mode & 0o777)
            except (OSError, PermissionError):
                continue
        return state

    def _scan_files(self):
        current = self._credential_file_state()
        for path, metadata in current.items():
            previous = self._file_state.get(path)
            if previous is None or previous == metadata:
                continue
            self._emit(
                rule_id='CRED_STORE_METADATA_CHANGED', eventType='credential_store_changed',
                credential_event_type='credential_store_change', severity='high', risk_score=82,
                description=f'Credential-store file metadata changed: {path}',
                file_path=path, file_size=metadata[1], mitre_id='T1556',
                raw={'previous_mtime_ns': previous[0], 'current_mtime_ns': metadata[0],
                     'previous_mode': oct(previous[2]), 'current_mode': oct(metadata[2]),
                     'collection_scope': 'file metadata only; credential contents were not read'},
            )
        self._file_state = current

    def _scan_processes(self):
        current = set()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                identity = (int(info.get('pid') or 0), float(info.get('create_time') or 0))
                current.add(identity)
                if identity in self._seen_processes:
                    continue
                cmdline = ' '.join(info.get('cmdline') or [])[:4000]
                finding = _match_process(info.get('name'), cmdline)
                if not finding:
                    continue
                parent = proc.parent()
                self._emit(
                    rule_id=finding['rule_id'], eventType='credential_process_execution',
                    credential_event_type=finding['credential_event_type'],
                    severity=finding['severity'], risk_score=finding['risk_score'],
                    description=f'{finding["description"]}: {info.get("name") or "unknown"}',
                    process_name=info.get('name'), process_exe=info.get('exe'), process_cmdline=cmdline,
                    pid=identity[0], parent_pid=info.get('ppid'),
                    parent_process_name=parent.name() if parent else '', username=info.get('username'),
                    credential_target='endpoint credential material', mitre_id=finding['mitre_id'],
                    technique=finding['description'], timestamp=_utc(identity[1]),
                    raw={'platform': SYSTEM, 'collection_scope': 'process metadata only; no credential values collected'},
                )
            except (psutil.Error, OSError, ValueError):
                continue
        self._seen_processes.intersection_update(current)
        self._seen_processes.update(current)

    def _loop(self):
        logger.info('Credential security monitor started (privacy-safe process and file metadata)')
        while True:
            try:
                if self._config.get('credential_security_monitoring_enabled', True):
                    if self._config.get('credential_monitor_processes_enabled', True):
                        self._scan_processes()
                    if self._config.get('credential_monitor_stores_enabled', True):
                        self._scan_files()
            except Exception as exc:
                logger.debug('Credential security scan failed: %s', exc)
            interval = max(10, min(3600, int(self._config.get('credential_monitor_interval_seconds', 20))))
            time.sleep(interval)


Collector = CredentialSecurityCollector
