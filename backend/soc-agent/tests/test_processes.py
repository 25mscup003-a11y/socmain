import os
import sys
import unittest
from types import SimpleNamespace


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.processes import ProcessCollector
from detectors.lolbins import SUSPICIOUS_PATTERNS


class Sender:
    def __init__(self):
        self.alerts = []

    def enqueue(self, alert):
        self.alerts.append(alert)


class FakePsutil:
    class AccessDenied(Exception):
        pass

    def __init__(self, connections):
        self._connections = connections

    def net_connections(self, kind='inet'):
        assert kind == 'inet'
        return self._connections


def connection(pid, ip, port):
    return SimpleNamespace(pid=pid, raddr=SimpleNamespace(ip=ip, port=port))


class ProcessCollectorTests(unittest.TestCase):
    def setUp(self):
        self.sender = Sender()
        self.collector = ProcessCollector(self.sender, config={})

    def test_classifies_cross_platform_workloads_from_real_fields(self):
        tags = self.collector._classify_process(
            'powershell.exe',
            'powershell.exe -EncodedCommand ZQB4AGEAbQBwAGwAZQ== docker run image',
            r'C:\Users\Admin\Downloads\powershell.exe',
            r'NT AUTHORITY\SYSTEM',
        )
        self.assertIn('powershell', tags)
        self.assertIn('encoded_command', tags)
        self.assertIn('container_cloud', tags)
        self.assertIn('privileged_user', tags)

    def test_classifies_server_usb_and_network_workloads(self):
        tags = self.collector._classify_process(
            'postgres', 'postgres --config /media/usb/postgresql.conf',
            '/media/usb/postgres', 'root',
        )
        self.assertIn('database', tags)
        self.assertIn('usb_related', tags)
        self.assertIn('privileged_user', tags)

    def test_connection_snapshot_counts_external_and_private_hosts(self):
        psutil = FakePsutil([
            connection(41, '8.8.8.8', 443),
            connection(41, '10.0.0.4', 22),
            connection(41, '10.0.0.5', 22),
            connection(41, '127.0.0.1', 8080),
            connection(42, 'not-an-ip', 53),
        ])
        result = self.collector._connection_snapshot(psutil)
        self.assertEqual(result[41]['total'], 4)
        self.assertEqual(result[41]['external'], 1)
        self.assertEqual(result[41]['private_remote_ip_count'], 2)
        self.assertEqual(result[41]['unique_remote_ip_count'], 4)
        self.assertEqual(result[41]['unique_remote_port_count'], 3)
        self.assertEqual(result[42]['private_remote_ip_count'], 0)

    def test_disk_io_rate_uses_counter_delta(self):
        self.assertEqual(self.collector._disk_io_rate('p', 100, 200, 10.0), (0.0, 0.0))
        read_rate, write_rate = self.collector._disk_io_rate('p', 500, 1000, 12.0)
        self.assertEqual(read_rate, 200.0)
        self.assertEqual(write_rate, 400.0)

    def test_command_activity_detects_privilege_service_schedule_and_tamper(self):
        privilege = self.collector._command_activity('sudo', 'sudo chmod u+s /tmp/tool')
        self.assertEqual({item[0] for item in privilege}, {
            'PROC_PRIVILEGED_COMMAND', 'PROC_PRIVILEGE_ESCALATION',
        })
        service = self.collector._command_activity('systemctl', 'systemctl enable backup.timer')
        self.assertIn('PROC_SERVICE_CREATED', {item[0] for item in service})
        self.assertIn('PROC_SCHEDULED_TASK_CHANGE', {item[0] for item in service})
        tamper = self.collector._command_activity('systemctl', 'systemctl stop auditd')
        self.assertIn('PROC_SECURITY_TOOL_TAMPER', {item[0] for item in tamper})

    def test_trust_findings_are_evidence_based_and_deduplicated(self):
        item = {
            'pid': 10, 'ppid': 1, 'name': 'payload.exe', 'exe': r'C:\Temp\payload.exe',
            'cmdline': r'C:\Temp\payload.exe', 'cpu': 0, 'mem': 0,
        }
        trust = {
            'sha256': 'a' * 64, 'sha1': 'b' * 40, 'md5': 'c' * 32,
            'signatureStatus': 'UNSIGNED', 'trustStatus': 'UNSIGNED',
            'certificateIssuer': 'Test CA',
        }
        self.collector._emit_trust_finding(item, trust)
        self.collector._emit_trust_finding(item, trust)
        self.assertEqual(len(self.sender.alerts), 1)
        alert = self.sender.alerts[0]
        self.assertEqual(alert['rule_id'], 'PROC_UNSIGNED_EXECUTABLE')
        self.assertEqual(alert['executable_sha256'], 'a' * 64)
        self.assertEqual(alert['executable_sha1'], 'b' * 40)
        self.assertEqual(alert['executable_md5'], 'c' * 32)
        self.assertEqual(alert['signature_status'], 'UNSIGNED')
        self.assertEqual(alert['certificate_issuer'], 'Test CA')
        self.assertIn(25, alert['capabilityIds'])

    def test_unknown_linux_executable_only_alerts_from_untrusted_path(self):
        trust = {'sha256': 'b' * 64, 'signatureStatus': 'UNKNOWN', 'packageVerificationStatus': 'NOT_PACKAGE_MANAGED'}
        safe = {'pid': 1, 'name': 'tool', 'exe': '/opt/company/tool', 'cmdline': '', 'cpu': 0, 'mem': 0}
        unsafe = {'pid': 2, 'name': 'tool', 'exe': '/tmp/tool', 'cmdline': '', 'cpu': 0, 'mem': 0}
        self.collector._emit_trust_finding(safe, trust)
        self.collector._emit_trust_finding(unsafe, trust)
        self.assertEqual([alert['rule_id'] for alert in self.sender.alerts], ['PROC_UNKNOWN_EXECUTABLE'])

    def test_generic_session_argument_is_not_remote_powershell(self):
        command = '/usr/bin/dbus-daemon --session --address=unix:path=/run/user/1000/bus'
        descriptions = [desc for pattern, desc, _mitre, _severity in SUSPICIOUS_PATTERNS if pattern.search(command)]
        self.assertNotIn('Remote PowerShell execution', descriptions)


if __name__ == '__main__':
    unittest.main()
