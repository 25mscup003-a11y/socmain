import unittest

from core.cache_poison_detector import CachePoisonDetector
from core.dns_sinkhole import DNSSinkhole
from core.memory_overflow import MemoryOverflowDetector, calculate_risk_score, severity_from_risk


class FakeSender:
    def __init__(self):
        self.alerts = []

    def send_alert(self, alert):
        self.alerts.append(alert)


class AdvancedDetectorTelemetryTest(unittest.TestCase):
    def test_memory_overflow_emits_canonical_capability_29(self):
        detector = MemoryOverflowDetector()
        detector.scan_logs = lambda: [{
            'type': 'stack_smash', 'process': 'web', 'pid': 42,
            'severity': 'critical', 'mitre': 'T1190',
            'description': 'Stack smash detected',
        }]
        detector.scan_processes = lambda: []
        sender = FakeSender()

        detector.run_and_report(sender)

        event = sender.alerts[0]
        self.assertEqual(event['capabilityId'], 29)
        self.assertEqual(event['rule_id'], 'MEMORY_OVERFLOW_STACK_SMASH')
        self.assertEqual(event['category'], 'memory')
        self.assertEqual(event['process_name'], 'web')
        self.assertEqual(event['riskScore'], 95)
        self.assertEqual(event['detection_rule_id'], 'MEM-014')

    def test_memory_risk_scoring_and_severity_boundaries(self):
        self.assertEqual(severity_from_risk(0), 'low')
        self.assertEqual(severity_from_risk(40), 'medium')
        self.assertEqual(severity_from_risk(70), 'high')
        self.assertEqual(severity_from_risk(90), 'critical')
        sensitive = calculate_risk_score({
            'severity': 'high', 'confidence': 90, 'type': 'process_injection',
            'target_process': 'lsass.exe', 'crash_count': 3,
        })
        allowlisted = calculate_risk_score({
            'severity': 'high', 'confidence': 90, 'type': 'process_injection',
            'target_process': 'lsass.exe', 'crash_count': 3, 'allowlisted': True,
        })
        self.assertEqual(sensitive, 95)
        self.assertLess(allowlisted, sensitive)

    def test_memory_rule_disable_and_process_allowlist_suppress_findings(self):
        disabled = MemoryOverflowDetector({'memory_detection_rules': [{
            'rule_id': 'MEM-002', 'enabled': False,
        }]})
        self.assertFalse(disabled._rule_allows({'type': 'spike', 'process': 'worker'}))
        allowlisted = MemoryOverflowDetector({'memory_detection_rules': [{
            'rule_id': 'MEM-003', 'enabled': True, 'allowlist': ['java*'],
        }]})
        self.assertFalse(allowlisted._rule_allows({'type': 'leak', 'process': 'java'}))
        self.assertTrue(allowlisted._rule_allows({'type': 'leak', 'process': 'unknown-service'}))

    def test_memory_boolean_configuration_accepts_string_values(self):
        disabled = MemoryOverflowDetector({'memory_crash_correlation_enabled': 'false'})
        enabled = MemoryOverflowDetector({'memory_crash_correlation_enabled': 'yes'})

        self.assertFalse(disabled._cfg('memory_crash_correlation_enabled'))
        self.assertTrue(enabled._cfg('memory_crash_correlation_enabled'))

    def test_cache_poison_emits_canonical_capability_30(self):
        detector = CachePoisonDetector()
        detector.scan_all = lambda: [{
            'type': 'cache_poison_ttl_drop', 'domain': 'example.test',
            'old_ttl': 300, 'new_ttl': 5, 'ips': ['203.0.113.8'],
            'severity': 'high', 'mitre': 'T1557.003',
            'description': 'Suspicious TTL drop',
        }]
        sender = FakeSender()

        detector.run_and_report(sender)

        event = sender.alerts[0]
        self.assertEqual(event['capabilityId'], 30)
        self.assertEqual(event['domain'], 'example.test')
        self.assertEqual(event['ttl'], 5)
        self.assertEqual(event['previousTtl'], 300)

    def test_sinkhole_status_is_real_and_not_labeled_as_a_hit(self):
        sinkhole = DNSSinkhole()
        sender = FakeSender()

        events = sinkhole.run_and_report(sender)

        self.assertEqual(events[0]['action'], 'status')
        self.assertEqual(sender.alerts[0]['capabilityId'], 31)
        self.assertEqual(sender.alerts[0]['eventType'], 'sinkhole_status')
        self.assertFalse(sender.alerts[0]['blocked'])
        self.assertNotIn('HIT', sender.alerts[0]['rule_id'])
        self.assertEqual(sinkhole.run_and_report(sender), [])


if __name__ == '__main__':
    unittest.main()
