"""
core/registry_monitor.py
Registry Monitoring — CAP #6
Polls Windows registry persistence keys every 60 seconds.
Detects new Run/RunOnce entries, suspicious service installs,
and AppInit_DLLs modifications.

MITRE ATT&CK: T1547.001, T1060, T1546
"""

import platform
import logging
import time
import getpass
from typing import Dict, List

logger = logging.getLogger(__name__)

# Registry keys commonly abused for persistence
WATCH_KEYS = [
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',          'HKLM'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',      'HKLM'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',          'HKCU'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',      'HKCU'),
    (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon',  'HKLM'),
    (r'SYSTEM\CurrentControlSet\Services',                      'HKLM'),
    (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppInit_DLLs', 'HKLM'),
    (r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options', 'HKLM'),
    (r'SOFTWARE\Classes\CLSID',                                  'HKCU'),
    (r'SOFTWARE\Policies\Microsoft\Windows Defender',           'HKLM'),
    (r'SOFTWARE\Microsoft\Windows Defender',                     'HKLM'),
    (r'SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy', 'HKLM'),
    (r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'HKLM'),
    (r'SYSTEM\CurrentControlSet\Control\Lsa',                   'HKLM'),
    (r'SYSTEM\CurrentControlSet\Control\Terminal Server',       'HKLM'),
    (r'SOFTWARE\Policies\Microsoft\Windows\PowerShell',         'HKLM'),
    (r'SYSTEM\CurrentControlSet\Services\EventLog',             'HKLM'),
]

# Known-good baseline values (common Windows entries)
KNOWN_GOOD = {
    'SecurityHealth', 'OneDrive', 'MicrosoftEdgeAutoLaunch',
    'WindowsDefender', 'VirtualBox Guest Additions Tray',
}


class RegistryMonitor:
    """Polls registry persistence keys and detects changes."""

    def __init__(self, config=None, poll_interval: int = 60):
        self.config        = config
        self.poll_interval = poll_interval
        self.os_type       = platform.system().lower()
        self._snapshot: Dict[str, Dict] = {}
        self._running      = False

    def _watch_keys(self):
        """Return built-in and administrator-configured keys with a hard cap."""
        values = list(WATCH_KEYS)
        try:
            configured = self.config.get('registry_monitor_paths', []) if self.config else []
        except Exception:
            configured = []
        if isinstance(configured, str):
            configured = [item.strip() for item in configured.split(',') if item.strip()]
        for item in configured[:64] if isinstance(configured, list) else []:
            if isinstance(item, dict):
                hive = str(item.get('hive') or 'HKLM').upper()
                subkey = str(item.get('path') or item.get('key') or '').strip().lstrip('\\')
            else:
                value = str(item).strip()
                hive, _, subkey = value.partition('\\')
                hive = hive.upper()
            if hive in ('HKEY_LOCAL_MACHINE', 'HKLM'):
                hive = 'HKLM'
            elif hive in ('HKEY_CURRENT_USER', 'HKCU'):
                hive = 'HKCU'
            else:
                continue
            if subkey:
                values.append((subkey, hive))
        return list(dict.fromkeys(values))[:72]

    def _read_key(self, hive: str, subkey: str) -> Dict[str, Dict]:
        """Read bounded key values. Returns {name: {data, type}}."""
        if self.os_type != 'windows':
            return {}
        try:
            import winreg  # type: ignore
            root = winreg.HKEY_LOCAL_MACHINE if hive == 'HKLM' else winreg.HKEY_CURRENT_USER
            result = {}
            with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        name, data, value_type = winreg.EnumValue(key, i)
                        result[name] = {'data': str(data)[:4096], 'type': int(value_type)}
                        i += 1
                    except OSError:
                        break
            return result
        except Exception:
            return {}

    def _take_snapshot(self) -> Dict[str, Dict]:
        """Snapshot all watched keys."""
        snap = {}
        for subkey, hive in self._watch_keys():
            full_key = f'{hive}\\{subkey}'
            snap[full_key] = self._read_key(hive, subkey)
        return snap

    @staticmethod
    def _value(item):
        return item if isinstance(item, dict) else {'data': str(item), 'type': None}

    @staticmethod
    def _assessment(key_path: str, name: str, data: str, operation: str):
        text = f'{key_path} {name} {data}'.lower()
        category, severity, risk, mitre, technique = 'registry_integrity', 'medium', 48, 'T1112', 'Modify Registry'
        reasons = []
        if any(token in text for token in ('\\run', 'runonce', 'winlogon', 'userinit', 'appinit_dlls', 'image file execution options', '\\clsid')):
            category, severity, risk, mitre, technique = 'persistence', 'high', 78, 'T1547.001', 'Registry Run Keys / Startup Folder'
            reasons.append('persistence-sensitive registry location')
        if any(token in text for token in ('windows defender', 'disableantispyware', 'disablerealtimemonitoring', 'firewallpolicy', 'eventlog')):
            category, severity, risk, mitre, technique = 'security_configuration', 'critical', 90, 'T1562.001', 'Impair Defenses'
            reasons.append('security-control configuration changed')
        if any(token in text for token in ('\\lsa', 'authentication packages', 'security packages', 'credential provider')):
            category, severity, risk, mitre, technique = 'authentication_configuration', 'critical', 88, 'T1556', 'Modify Authentication Process'
            reasons.append('authentication configuration changed')
        if any(token in text for token in ('terminal server', 'fdenytsconnections', 'tcpip', 'internet settings', 'proxy')):
            category, severity, risk = 'network_configuration', 'high', 70
            reasons.append('remote-access or network configuration changed')
        if 'services' in text:
            category, severity, risk, mitre, technique = 'service_configuration', 'high', 72, 'T1543.003', 'Windows Service'
            reasons.append('service configuration changed')
        if operation == 'delete':
            risk = min(100, risk + 8)
            severity = 'critical' if risk >= 80 else 'high' if risk >= 60 else 'medium'
            reasons.append('registry value deleted')
        if any(token in text for token in ('powershell', 'cmd.exe', '\\temp\\', '\\appdata\\', '-encodedcommand')):
            risk = min(100, risk + 15)
            severity = 'critical' if risk >= 80 else 'high'
            reasons.append('suspicious executable or command value')
        return category, severity, risk, mitre, technique, reasons

    def _finding(self, key_path, name, operation, current=None, previous=None):
        new_item = self._value(current) if current is not None else {'data': '', 'type': None}
        old_item = self._value(previous) if previous is not None else {'data': '', 'type': None}
        data = new_item.get('data', '')
        category, severity, risk, mitre, technique, reasons = self._assessment(key_path, name, data, operation)
        known_good = name in KNOWN_GOOD and not any(token in str(data).lower() for token in ('powershell', 'cmd.exe', '\\temp\\', '\\appdata\\'))
        if known_good:
            severity, risk = 'low', min(risk, 25)
            reasons.append('known software value; retained as low-risk audit telemetry')
        return {
            'type': f'registry_{operation}', 'operation': operation,
            'key': key_path, 'value_name': name,
            'value_data': data, 'value_type': new_item.get('type'),
            'old_data': old_item.get('data', ''), 'old_type': old_item.get('type'),
            'severity': severity, 'risk_score': risk, 'mitre': mitre,
            'technique': technique, 'configuration_category': category,
            'baseline_status': 'known' if known_good else 'unexpected',
            'risk_factors': reasons,
            'description': f'Registry value {operation}: {key_path}\\{name}',
        }

    def _diff(self, old: Dict[str, Dict], new: Dict[str, Dict]) -> List[Dict]:
        """Compare snapshots and return create, modify, and delete events."""
        findings = []
        for key_path, new_vals in new.items():
            old_vals = old.get(key_path, {})
            for name, data in new_vals.items():
                if name not in old_vals:
                    findings.append(self._finding(key_path, name, 'create', current=data))
                elif old_vals[name] != data:
                    findings.append(self._finding(key_path, name, 'modify', current=data, previous=old_vals[name]))
            for name, data in old_vals.items():
                if name not in new_vals:
                    findings.append(self._finding(key_path, name, 'delete', previous=data))
        return findings

    def check_once(self) -> List[Dict]:
        """Take one snapshot, diff against baseline, update baseline."""
        if self.os_type != 'windows':
            return []
        current = self._take_snapshot()
        if not self._snapshot:
            self._snapshot = current
            logger.info('[RegistryMonitor] Baseline captured')
            return []
        findings = self._diff(self._snapshot, current)
        self._snapshot = current
        return findings

    def run_and_report(self, sender=None) -> List[Dict]:
        """Check registry once and send alerts for any changes."""
        findings = self.check_once()
        if findings and sender:
            for f in findings:
                try:
                    sender.send_alert({
                        'rule_id':        f'REG_{f["operation"].upper()}',
                        'category':       'registry',
                        'capabilityId':   6,
                        'capabilityIds':  [6, 7] + ([8] if f.get('configuration_category') == 'persistence' else []),
                        'is_persistence': f.get('configuration_category') == 'persistence',
                        'subCategory':    f.get('configuration_category'),
                        'eventType':      f.get('type', 'registry_change'),
                        'osType':         'Windows',
                        'severity':       f.get('severity', 'high'),
                        'description':    f['description'],
                        'source':          'registry_monitor',
                        'keyPath':         f.get('key'),
                        'oldValue':        f.get('old_data'),
                        'newValue':        f.get('value_data'),
                        'riskScore':       f.get('risk_score', 50),
                        'mitreId':         f.get('mitre', 'T1547.001'),
                        'technique':       f.get('technique'),
                        'persistence_type': 'registry_run_key' if f.get('configuration_category') == 'persistence' else None,
                        'persistence_location': f.get('key'),
                        'persistence_key': f.get('value_name'),
                        'system_change_category': 'registry_configuration',
                        'system_change_type': {
                            'create': 'created', 'modify': 'modified', 'delete': 'deleted',
                        }.get(f.get('operation'), 'modified'),
                        'system_change_target': f'{f.get("key", "")}\\{f.get("value_name", "")}',
                        'previous_state': f.get('old_data'),
                        'new_state': f.get('value_data'),
                        'baseline_status': f.get('baseline_status', 'unexpected'),
                        'change_source': 'registry_monitor',
                        'detection_reason': f['description'],
                        'configuration_category': f.get('configuration_category'),
                        'configuration_operation': f.get('operation'),
                        'configuration_object': f'{f.get("key", "")}\\{f.get("value_name", "")}',
                        'configuration_platform': 'windows',
                        'configuration_baseline_status': f.get('baseline_status'),
                        'configuration_policy_violation': f.get('risk_score', 0) >= 60,
                        'configuration_risk_factors': f.get('risk_factors', []),
                        'registry_hive': str(f.get('key', '')).split('\\', 1)[0],
                        'registry_value_name': f.get('value_name'),
                        'registry_value_type': f.get('value_type'),
                        'operation': f.get('operation'),
                        'username': None,
                        'process_attribution': 'unavailable_snapshot_polling',
                        'collector_interval_seconds': self.poll_interval,
                        'raw':            f,
                    })
                except Exception as e:
                    logger.error(f'[RegistryMonitor] Send error: {e}')
        if findings:
            logger.warning(f'[RegistryMonitor] {len(findings)} registry changes detected')
        return findings
