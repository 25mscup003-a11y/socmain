import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from collectors.lateral_movement import LateralMovementCollector, _internal_ip, _process_detection


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class FakeProcess:
    def name(self): return 'mstsc.exe'
    def exe(self): return ''
    def cmdline(self): return ['mstsc.exe', '/v:10.20.30.40']
    def username(self): return 'analyst'
    def ppid(self): return 100
    def parent(self): return SimpleNamespace(name=lambda: 'explorer.exe')


class LateralMovementCollectorTests(unittest.TestCase):
    def test_internal_address_detection(self):
        self.assertTrue(_internal_ip('10.20.30.40'))
        self.assertTrue(_internal_ip('192.168.1.2'))
        self.assertFalse(_internal_ip('8.8.8.8'))
        self.assertFalse(_internal_ip('127.0.0.1'))

    def test_remote_tool_classification(self):
        psexec = _process_detection('PsExec.exe', r'PsExec.exe \\server cmd.exe')
        self.assertEqual(psexec['rule_id'], 'LATERAL_PSEXEC_EXECUTION')
        self.assertEqual(psexec['mitre_id'], 'T1021.002')
        self.assertEqual(psexec['severity'], 'critical')
        self.assertEqual(_process_detection('notepad.exe', 'notepad.exe notes.txt'), None)

    def test_internal_remote_session_emits_capability_14(self):
        sender = Sender()
        collector = LateralMovementCollector(sender, {})
        connection = SimpleNamespace(
            pid=321,
            laddr=SimpleNamespace(ip='10.20.30.10', port=51234),
            raddr=SimpleNamespace(ip='10.20.30.40', port=3389),
            status='ESTABLISHED',
        )
        with patch('collectors.lateral_movement.psutil.net_connections', return_value=[connection]), \
             patch('collectors.lateral_movement.psutil.Process', return_value=FakeProcess()):
            collector._scan_connections()
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['capabilityId'], 14)
        self.assertEqual(sender.events[0]['lateral_vector'], 'RDP')
        self.assertEqual(sender.events[0]['dst_ip'], '10.20.30.40')
        self.assertEqual(sender.events[0]['mitre_id'], 'T1021.001')

    def test_public_remote_session_is_not_emitted(self):
        sender = Sender()
        collector = LateralMovementCollector(sender, {})
        connection = SimpleNamespace(
            pid=0,
            laddr=SimpleNamespace(ip='10.20.30.10', port=51234),
            raddr=SimpleNamespace(ip='8.8.8.8', port=22),
            status='ESTABLISHED',
        )
        with patch('collectors.lateral_movement.psutil.net_connections', return_value=[connection]):
            collector._scan_connections()
        self.assertEqual(sender.events, [])

    def test_inbound_ssh_session_preserves_source_and_destination(self):
        sender = Sender()
        collector = LateralMovementCollector(sender, {})
        connection = SimpleNamespace(
            pid=321,
            laddr=SimpleNamespace(ip='10.20.30.10', port=22),
            raddr=SimpleNamespace(ip='10.20.30.40', port=51234),
            status='ESTABLISHED',
        )
        with patch('collectors.lateral_movement.psutil.net_connections', return_value=[connection]), \
             patch('collectors.lateral_movement.psutil.Process', return_value=FakeProcess()):
            collector._scan_connections()
        self.assertEqual(len(sender.events), 1)
        event = sender.events[0]
        self.assertEqual(event['lateral_vector'], 'SSH')
        self.assertEqual(event['src_ip'], '10.20.30.40')
        self.assertEqual(event['dst_ip'], '10.20.30.10')
        self.assertEqual(event['raw']['direction'], 'inbound')


if __name__ == '__main__':
    unittest.main()
