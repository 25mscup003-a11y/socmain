"""Low-overhead, privacy-safe data-security telemetry collector.

The existing FIM, USB, network and ransomware collectors remain the primary
sources for file and transfer activity.  This collector adds the process-side
context needed to identify archive staging, database exports and outbound
transfer tools.  It never reads file, clipboard, email or credential content.
"""

import logging
import os
import platform
import re
import threading
import time
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


logger = logging.getLogger('soc-agent.collector.data_security')

PROCESS_RULES = (
    (re.compile(r'\b(?:7z|7za|zip|rar|winrar|tar)(?:\.exe)?\b[^\r\n]*(?:\s-a\b|\s-c\b|\.(?:zip|rar|7z|tar|tgz)\b)', re.I),
     'DATA_ARCHIVE_STAGING', 'Sensitive data may be staged in an archive', 'archive_staging', 'high', 78, 'T1560.001', 'archive'),
    (re.compile(r'\b(?:mysqldump|pg_dump|pg_dumpall|mongodump|sqlcmd|bcp|expdp|exp)(?:\.exe)?\b', re.I),
     'DATA_DATABASE_EXPORT', 'Database export or backup utility executed', 'database_export', 'high', 82, 'T1005', 'database'),
    (re.compile(r'\b(?:rclone|megacmd|megaput|dropbox|onedrive|gdrive)(?:\.exe)?\b[^\r\n]*(?:copy|sync|upload|put)', re.I),
     'DATA_CLOUD_UPLOAD', 'Cloud storage upload utility executed', 'cloud_upload', 'high', 85, 'T1567.002', 'cloud'),
    (re.compile(r'\b(?:curl|wget)(?:\.exe)?\b[^\r\n]*(?:--upload-file|-T\s|--post-file)|\bftp\b[^\r\n]*\bput\b|\b(?:scp|sftp)(?:\.exe)?\b[^\r\n]+', re.I),
     'DATA_NETWORK_TRANSFER', 'Outbound file-transfer command executed', 'network_transfer', 'high', 84, 'T1048', 'network'),
    (re.compile(r'\b(?:vssadmin|wmic)(?:\.exe)?\b[^\r\n]*(?:delete\s+shadows|shadowcopy\s+delete)|\bwbadmin(?:\.exe)?\b[^\r\n]*delete', re.I),
     'DATA_BACKUP_DELETION', 'Backup or shadow-copy deletion detected', 'ransomware', 'critical', 98, 'T1490', 'ransomware'),
)


def _utc(value=None):
    return datetime.fromtimestamp(value or time.time(), timezone.utc).isoformat()


def _classify_path(command_line):
    """Classify using names/paths only; content inspection is prohibited."""
    text = str(command_line or '').lower().replace('\\', '/')
    if any(token in text for token in ('private_key', 'id_rsa', '/.ssh/', '/etc/shadow', '.aws/credentials', 'secret')):
        return 'Secret'
    if any(token in text for token in ('finance', 'payroll', 'customer', 'aadhaar', 'passport', 'source code', '/src/', '/repos/')):
        return 'Restricted'
    if any(token in text for token in ('hr', 'confidential', '.sql', '.dump', '.bak', 'database')):
        return 'Confidential'
    return 'Internal'


def _match_process(name, command_line):
    text = f'{name or ""} {command_line or ""}'
    for pattern, rule_id, description, event_type, severity, risk, mitre, channel in PROCESS_RULES:
        if pattern.search(text):
            return {
                'rule_id': rule_id, 'description': description,
                'data_event_type': event_type, 'severity': severity,
                'risk_score': risk, 'mitre_id': mitre,
                'transfer_channel': channel,
                'data_classification': _classify_path(text),
            }
    return None


class DataSecurityCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._seen = set()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='data-security-monitor')

    def start(self):
        if psutil is None:
            logger.warning('psutil unavailable; data-security process context is disabled')
            return
        try:
            self._seen = {(proc.pid, float(proc.create_time())) for proc in psutil.process_iter(['pid', 'create_time'])}
        except (psutil.Error, OSError, ValueError):
            pass
        self._thread.start()

    def _emit(self, **values):
        if not self._config.get('data_security_monitoring_enabled', True):
            return
        event_type = str(values.get('data_event_type') or 'data_security')
        risk_score = int(values.get('risk_score') or 0)
        self._sender.enqueue({
            'capabilityId': 12, 'capabilityIds': [11, 12],
            'category': 'edr', 'subCategory': 'data-security',
            'source': 'data_security', 'eventType': event_type,
            'timestamp': _utc(), 'mitre_tactic': 'Exfiltration',
            'confidence_score': 90, 'actionable': True,
            'behavior_category': 'Data Access',
            'entity_type': 'user' if values.get('username') else 'endpoint',
            'entity_id': values.get('username') or values.get('process_name'),
            'behavior_score': risk_score, 'peer_deviation_score': risk_score,
            'ueba_confidence': 90, 'ueba_risk_factors': [event_type],
            'baseline_window_days': 30,
            'raw': {'platform': platform.system(), 'collection_scope': 'process and file metadata only; no file, clipboard, email or credential contents collected'},
            **values,
        })

    def _scan(self):
        current = set()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                identity = (int(info.get('pid') or 0), float(info.get('create_time') or 0))
                current.add(identity)
                if identity in self._seen:
                    continue
                command_line = ' '.join(info.get('cmdline') or [])[:4000]
                finding = _match_process(info.get('name'), command_line)
                if not finding:
                    continue
                parent = proc.parent()
                self._emit(
                    **finding, process_name=info.get('name'), process_exe=info.get('exe'),
                    process_cmdline=command_line, pid=identity[0], parent_pid=info.get('ppid'),
                    parent_process_name=parent.name() if parent else '', username=info.get('username'),
                    timestamp=_utc(identity[1]),
                )
            except (psutil.Error, OSError, ValueError):
                continue
        self._seen.intersection_update(current)
        self._seen.update(current)

    def _loop(self):
        logger.info('Data-security monitor started (bounded process metadata)')
        while True:
            try:
                if self._config.get('data_security_monitoring_enabled', True):
                    self._scan()
            except Exception as exc:
                logger.debug('Data-security scan failed: %s', exc)
            interval = max(10, min(3600, int(self._config.get('data_security_monitor_interval_seconds', 20))))
            time.sleep(interval)


Collector = DataSecurityCollector
