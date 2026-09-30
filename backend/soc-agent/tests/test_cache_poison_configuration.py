import unittest
from unittest.mock import patch

from core.cache_poison_detector import CachePoisonDetector


class CachePoisonConfigurationTest(unittest.TestCase):
    @patch.object(CachePoisonDetector, '_capture_file_baseline')
    def test_runtime_policy_is_applied(self, _baseline):
        detector = CachePoisonDetector(config={})
        status = detector.configure({
            'cache_poison_enabled': True,
            'cache_poison_telemetry_enabled': True,
            'cache_poison_watch_domains': ['portal.example'],
            'cache_poison_scan_interval_seconds': 90,
            'cache_poison_min_safe_ttl': 20,
            'cache_poison_policy_version': 7,
        })
        self.assertEqual(detector.scan_interval_seconds, 90)
        self.assertEqual(status['policyVersion'], 7)
        self.assertEqual(status['watchDomainCount'], 1)

    @patch.object(CachePoisonDetector, '_capture_file_baseline')
    def test_disabled_detector_does_not_scan(self, _baseline):
        detector = CachePoisonDetector(config={'cache_poison_enabled': False})
        with patch.object(detector, '_configuration_findings') as configuration_findings:
            self.assertEqual(detector.scan_all(), [])
            configuration_findings.assert_not_called()

    @patch.object(CachePoisonDetector, '_capture_file_baseline')
    def test_custom_rule_detects_unexpected_ip(self, _baseline):
        detector = CachePoisonDetector(config={})
        rule = {
            'id': 'custom-1', 'name': 'Portal allowlist', 'domain': 'portal.example',
            'queryType': 'A', 'expectedIps': ['203.0.113.10'], 'severity': 'critical', 'enabled': True,
        }
        with patch.object(detector, '_resolve', return_value=(['198.51.100.20'], 300)):
            findings = detector._check_custom_rule(rule)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['new_ip'], '198.51.100.20')
        self.assertEqual(findings[0]['old_ips'], ['203.0.113.10'])
        self.assertEqual(findings[0]['query_type'], 'A')


if __name__ == '__main__':
    unittest.main()
