import os
import sys
import unittest


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.process_assets import ProcessAssetCollector


class Sender:
    def __init__(self):
        self.alerts = []

    def enqueue(self, alert):
        self.alerts.append(alert)


class ServiceMonitoringCollectorTests(unittest.TestCase):
    def setUp(self):
        self.sender = Sender()
        self.collector = ProcessAssetCollector(self.sender, config={})
        self.collector._system = 'Linux'

    def test_security_service_stop_is_high_risk_and_capability_24(self):
        previous = {'id': 'auditd.service', 'name': 'auditd.service', 'status': 'active', 'main_pid': 42}
        current = {'id': 'auditd.service', 'name': 'auditd.service', 'status': 'inactive', 'main_pid': 0}
        self.collector._emit_service_event('SERVICE_STOPPED', current, previous)

        alert = self.sender.alerts[-1]
        self.assertEqual(alert['rule_id'], 'SERVICE_STOPPED')
        self.assertEqual(alert['previous_status'], 'RUNNING')
        self.assertEqual(alert['current_status'], 'STOPPED')
        self.assertGreaterEqual(alert['risk_score'], 60)
        self.assertIn(24, alert['capabilityIds'])
        self.assertTrue(alert['security_service'])

    def test_inventory_diff_emits_canonical_create_change_and_delete_events(self):
        base = {'id': 'alpha.service', 'name': 'alpha.service', 'status': 'active', 'main_pid': 10}
        self.collector._diff('service', [base])
        self.assertEqual(self.sender.alerts[-1]['rule_id'], 'PROC_ASSET_INVENTORY')
        self.sender.alerts.clear()

        stopped = {**base, 'status': 'inactive', 'main_pid': 0}
        created = {'id': 'beta.service', 'name': 'beta.service', 'status': 'active', 'main_pid': 20}
        self.collector._diff('service', [stopped, created])
        rules = {alert['rule_id'] for alert in self.sender.alerts}
        self.assertIn('SERVICE_CREATED', rules)
        self.assertIn('SERVICE_STOPPED', rules)

        self.sender.alerts.clear()
        self.collector._diff('service', [stopped])
        self.assertEqual(self.sender.alerts[-1]['rule_id'], 'SERVICE_DELETED')


if __name__ == '__main__':
    unittest.main()
