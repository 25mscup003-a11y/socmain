"""Cross-platform lateral-movement telemetry collector.

Collects new remote-administration sessions and suspicious process executions
from operating-system metadata. Credentials, packet payloads, keystrokes and
remote-session screen contents are never collected.
"""

import hashlib
import ipaddress
import logging
import os
import platform
import re
import socket
import threading
import time
from datetime import datetime, timezone

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

logger = logging.getLogger('soc-agent.collector.lateral_movement')
SYSTEM = platform.system()

REMOTE_PORTS = {
    22: ('SSH', 'T1021.004'), 88: ('Kerberos', 'T1558'),
    135: ('RPC / WMI', 'T1047'), 139: ('SMB / NetBIOS', 'T1021.002'),
    389: ('LDAP', 'T1087.002'), 445: ('SMB / Windows Admin Shares', 'T1021.002'),
    636: ('LDAPS', 'T1087.002'), 3389: ('RDP', 'T1021.001'),
    5900: ('VNC', 'T1021.005'), 5985: ('WinRM', 'T1021.006'),
    5986: ('WinRM TLS', 'T1021.006'),
}

PROCESS_RULES = (
    (re.compile(r'\b(?:psexec|psexesvc|paexec)(?:\.exe)?\b', re.I), 'LATERAL_PSEXEC_EXECUTION', 'PsExec / PAExec remote service execution', 'PsExec', 'critical', 95, 'T1021.002'),
    (re.compile(r'\b(?:wmic|wmiprvse)(?:\.exe)?\b.*(?:/node:|process\s+call\s+create)|\bwmiexec(?:\.py)?\b', re.I), 'LATERAL_WMI_EXECUTION', 'Remote WMI execution', 'WMI', 'critical', 92, 'T1047'),
    (re.compile(r'\b(?:winrs|evil-winrm)(?:\.exe|\.rb)?\b|invoke-command|enter-pssession|new-pssession', re.I), 'LATERAL_WINRM_EXECUTION', 'WinRM / PowerShell remoting execution', 'WinRM', 'high', 86, 'T1021.006'),
    (re.compile(r'\b(?:smbexec|atexec|dcomexec|crackmapexec|netexec)(?:\.py|\.exe)?\b', re.I), 'LATERAL_REMOTE_EXECUTION_TOOL', 'Remote execution toolkit observed', 'Remote Execution Toolkit', 'critical', 96, 'T1021.002'),
    (re.compile(r'\b(?:mimikatz|rubeus|lazagne)(?:\.exe)?\b|sekurlsa::|lsadump::|pass.the.hash|overpass.the.hash', re.I), 'LATERAL_CREDENTIAL_ABUSE_TOOL', 'Credential abuse associated with lateral movement', 'Credential Abuse', 'critical', 98, 'T1550.002'),
    (re.compile(r'\b(?:bloodhound|sharphound|adfind)(?:\.exe|\.ps1)?\b', re.I), 'LATERAL_DIRECTORY_DISCOVERY_TOOL', 'Active Directory discovery tool observed', 'Directory Discovery', 'high', 82, 'T1087.002'),
    (re.compile(r'\b(?:mstsc|xfreerdp|rdesktop)(?:\.exe)?\b', re.I), 'LATERAL_RDP_CLIENT', 'Remote Desktop client session initiated', 'RDP', 'medium', 45, 'T1021.001'),
    (re.compile(r'\b(?:ssh|plink)(?:\.exe)?\b[^\r\n]*(?:\s|^)(?:[^\s@]+@)?(?:\d{1,3}\.){3}\d{1,3}\b', re.I), 'LATERAL_SSH_CLIENT', 'SSH connection to an IP address initiated', 'SSH', 'medium', 45, 'T1021.004'),
    (re.compile(r'\\\\[^\\\s]+\\(?:ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL)|\bnet\s+use\b', re.I), 'LATERAL_ADMIN_SHARE_ACCESS', 'Remote administrative share access', 'SMB Admin Share', 'high', 84, 'T1021.002'),
    (re.compile(r'\b(?:sc|schtasks)(?:\.exe)?\b[^\r\n]*(?:\\\\|/s\s+|/computer:)', re.I), 'LATERAL_REMOTE_SERVICE_OR_TASK', 'Remote service or scheduled-task execution', 'Remote Service / Task', 'critical', 91, 'T1021'),
)


def _utc(value=None):
    return datetime.fromtimestamp(value or time.time(), timezone.utc).isoformat()


def _address(value):
    if not value:
        return '', 0
    try:
        return str(value.ip), int(value.port)
    except AttributeError:
        try:
            return str(value[0]), int(value[1])
        except (IndexError, TypeError, ValueError):
            return '', 0


def _internal_ip(value):
    try:
        address = ipaddress.ip_address(str(value or '').split('%', 1)[0])
        return address.is_private and not address.is_loopback and not address.is_link_local
    except ValueError:
        return False


def _sha256(path, max_bytes=50 * 1024 * 1024):
    try:
        if not path or not os.path.isfile(path) or os.path.getsize(path) > max_bytes:
            return ''
        digest = hashlib.sha256()
        with open(path, 'rb') as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, PermissionError):
        return ''


def _process_detection(name, cmdline):
    text = f'{name or ""} {cmdline or ""}'
    for pattern, rule_id, description, vector, severity, risk, mitre in PROCESS_RULES:
        if pattern.search(text):
            return {
                'rule_id': rule_id, 'description': description, 'vector': vector,
                'severity': severity, 'risk_score': risk, 'mitre_id': mitre,
            }
    return None


class LateralMovementCollector:
    def __init__(self, sender, config=None):
        self._sender = sender
        self._config = config or {}
        self._seen_processes = set()
        self._seen_connections = set()
        self._thread = threading.Thread(target=self._loop, daemon=True, name='lateral-movement-monitor')

    def start(self):
        if psutil is None:
            logger.warning('psutil unavailable; lateral movement monitor disabled')
            return
        try:
            self._seen_processes = {proc.pid for proc in psutil.process_iter(['pid'])}
            self._seen_connections = self._connection_keys()
        except (psutil.Error, OSError):
            pass
        self._thread.start()

    def _emit(self, **values):
        vector = str(values.get('lateral_vector') or values.get('vector') or 'remote_activity')
        risk_score = int(values.get('risk_score') or 0)
        self._sender.enqueue({
            'capabilityId': 14, 'capabilityIds': [11, 14], 'category': 'edr',
            'subCategory': 'lateral-movement', 'source': 'lateral_movement',
            'timestamp': _utc(), 'mitre_tactic': 'Lateral Movement',
            'behavior_category': 'Network Behavior',
            'entity_type': 'user' if values.get('username') else 'endpoint',
            'entity_id': values.get('username') or values.get('source_host') or values.get('process_name'),
            'behavior_score': risk_score, 'peer_deviation_score': risk_score,
            'ueba_confidence': 90, 'ueba_risk_factors': [vector],
            'baseline_window_days': 30, **values,
        })

    def _connection_keys(self):
        keys = set()
        if psutil is None:
            return keys
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.Error, OSError):
            return keys
        for connection in connections:
            local_ip, local_port = _address(connection.laddr)
            remote_ip, remote_port = _address(connection.raddr)
            status = str(connection.status or '').upper()
            service_port = remote_port if remote_port in REMOTE_PORTS else local_port if local_port in REMOTE_PORTS else 0
            if service_port and _internal_ip(remote_ip) and status not in ('LISTEN', 'NONE'):
                keys.add((int(connection.pid or 0), local_ip, local_port, remote_ip, remote_port, status))
        return keys

    def _scan_connections(self):
        if psutil is None:
            return
        try:
            connections = psutil.net_connections(kind='inet')
        except (psutil.Error, OSError):
            return
        current = set()
        for connection in connections:
            local_ip, local_port = _address(connection.laddr)
            remote_ip, remote_port = _address(connection.raddr)
            status = str(connection.status or '').upper()
            outbound = remote_port in REMOTE_PORTS
            service_port = remote_port if outbound else local_port if local_port in REMOTE_PORTS else 0
            if not service_port or not _internal_ip(remote_ip) or status in ('LISTEN', 'NONE'):
                continue
            pid = int(connection.pid or 0)
            key = (pid, local_ip, local_port, remote_ip, remote_port, status)
            current.add(key)
            if key in self._seen_connections:
                continue
            vector, mitre = REMOTE_PORTS[service_port]
            process = {'name': '', 'exe': '', 'cmdline': '', 'username': '', 'ppid': 0, 'parent_name': ''}
            if pid:
                try:
                    proc = psutil.Process(pid)
                    parent = proc.parent()
                    process = {
                        'name': proc.name(), 'exe': proc.exe(), 'cmdline': ' '.join(proc.cmdline())[:4000],
                        'username': proc.username(), 'ppid': proc.ppid(),
                        'parent_name': parent.name() if parent else '',
                    }
                except (psutil.Error, OSError):
                    pass
            finding = _process_detection(process['name'], process['cmdline'])
            suspicious = finding is not None
            severity = finding['severity'] if suspicious else ('medium' if vector in ('SMB / Windows Admin Shares', 'RPC / WMI', 'WinRM', 'WinRM TLS') else 'low')
            risk = finding['risk_score'] if suspicious else (45 if severity == 'medium' else 15)
            self._emit(
                rule_id=finding['rule_id'] if suspicious else f'LATERAL_REMOTE_SESSION_{vector.split()[0].upper().replace("/", "_")}',
                eventType='remote_session_started', threatCategory='remote_execution' if suspicious else 'remote_session',
                severity=severity, risk_score=risk, confidence_score=90 if suspicious else 70,
                actionable=suspicious,
                description=(f'New internal {vector} session to {remote_ip}:{remote_port}' if outbound else f'New internal {vector} session from {remote_ip}:{remote_port}') + (f' using {process["name"]}' if process['name'] else ''),
                lateral_vector=vector,
                source_host=socket.gethostname() if outbound else remote_ip,
                destination_host=remote_ip if outbound else socket.gethostname(),
                src_ip=local_ip if outbound else remote_ip,
                src_port=local_port if outbound else remote_port,
                dst_ip=remote_ip if outbound else local_ip,
                dst_port=remote_port if outbound else local_port,
                protocol='tcp', connection_state=status, session_state='active',
                process_name=process['name'], process_exe=process['exe'], process_cmdline=process['cmdline'],
                pid=pid, parent_pid=process['ppid'], parent_process_name=process['parent_name'],
                username=process['username'], file_hash=_sha256(process['exe']),
                mitre_id=finding['mitre_id'] if suspicious else mitre,
                technique=finding['description'] if suspicious else vector,
                raw={'collection_scope': 'connection and process metadata only; no credentials or packet payloads', 'platform': SYSTEM, 'direction': 'outbound' if outbound else 'inbound'},
            )
        self._seen_connections = current

    def _scan_processes(self):
        if psutil is None:
            return
        current = set()
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = proc.info
                pid = int(info.get('pid') or 0)
                current.add(pid)
                if pid in self._seen_processes:
                    continue
                cmdline = ' '.join(info.get('cmdline') or [])[:4000]
                finding = _process_detection(info.get('name'), cmdline)
                if not finding:
                    continue
                parent = proc.parent()
                exe = info.get('exe') or ''
                self._emit(
                    rule_id=finding['rule_id'], eventType='lateral_process_execution',
                    threatCategory='lateral_movement', severity=finding['severity'],
                    risk_score=finding['risk_score'], confidence_score=92, actionable=True,
                    description=f'{finding["description"]}: {info.get("name") or "unknown"}',
                    lateral_vector=finding['vector'], source_host=socket.gethostname(),
                    process_name=info.get('name'), process_exe=exe, process_cmdline=cmdline,
                    pid=pid, parent_pid=info.get('ppid'), parent_process_name=parent.name() if parent else '',
                    username=info.get('username'), file_hash=_sha256(exe),
                    mitre_id=finding['mitre_id'], technique=finding['description'],
                    raw={'platform': SYSTEM, 'process_create_time': info.get('create_time')},
                    timestamp=_utc(info.get('create_time')),
                )
            except (psutil.Error, OSError, ValueError):
                continue
        self._seen_processes.intersection_update(current)
        self._seen_processes.update(current)

    def _loop(self):
        logger.info('Lateral movement monitor started (remote sessions and execution tools)')
        while True:
            try:
                self._scan_processes()
                self._scan_connections()
            except Exception as exc:
                logger.debug('Lateral movement scan failed: %s', exc)
            time.sleep(max(5, int(self._config.get('lateral_monitor_interval_seconds', 15))))


Collector = LateralMovementCollector
