import sys
import unittest
from pathlib import Path


AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from core.insider_threat import tag_insider_threat
from core.sender import AlertSender
from collectors.processes import ProcessCollector


class InsiderThreatTests(unittest.TestCase):
    def test_real_exfiltration_event_is_cross_tagged_without_losing_source(self):
        event = {
            'rule_id': 'NET_OUTBOUND_TRANSFER_ANOMALY',
            'capabilityId': 3,
            'capabilityIds': [3, 11],
            'severity': 'high',
            'bytes_sent': 150_000_000,
        }
        tagged = tag_insider_threat(event)
        self.assertEqual(tagged['capabilityId'], 3)
        self.assertEqual(tagged['capabilityIds'], [3, 11, 16])
        self.assertEqual(tagged['risk_score'], 75)
        self.assertEqual(tagged['raw']['insider_signal_type'], 'data_exfiltration')

    def test_unrelated_process_event_is_not_tagged(self):
        event = {'rule_id': 'PROC_STARTED', 'capabilityId': 1, 'capabilityIds': [1], 'severity': 'low'}
        tagged = tag_insider_threat(event)
        self.assertEqual(tagged['capabilityIds'], [1])
        self.assertNotIn('risk_score', tagged)

    def test_sensitive_usb_and_after_hours_events_are_tagged(self):
        usb = tag_insider_threat({'rule_id': 'USB_SENSITIVE_FILE_COPIED', 'capabilityId': 10, 'severity': 'high'})
        timed = tag_insider_threat({'rule_id': 'TIME_AFTER_HOURS_FILE', 'capabilityId': 22, 'after_hours': True, 'severity': 'medium'})
        self.assertIn(16, usb['capabilityIds'])
        self.assertEqual(usb['raw']['insider_signal_type'], 'removable_media_exfiltration')
        self.assertIn(16, timed['capabilityIds'])
        self.assertEqual(timed['raw']['insider_signal_type'], 'after_hours_activity')

    def test_process_collector_detects_log_clearing_and_archive_staging(self):
        rules = {finding[0] for finding in ProcessCollector._command_activity(
            'powershell.exe', 'powershell wevtutil cl Security; 7z a -psecret evidence.7z C:\\Sensitive'
        )}
        self.assertIn('PROC_SECURITY_LOG_CLEARED', rules)
        self.assertIn('PROC_ARCHIVE_STAGING', rules)

    def test_signal_type_survives_agent_transport_normalization(self):
        sender = AlertSender.__new__(AlertSender)
        sender.config = {
            'agent_key': 'test-agent',
            'company_id': 'company-1',
            'system_id': 'endpoint-1',
            'system_name': 'managed-host',
        }
        event = tag_insider_threat({
            'rule_id': 'PROC_SECURITY_LOG_CLEARED',
            'capabilityId': 1,
            'severity': 'critical',
        })
        payload = sender._build_payload(event)
        self.assertEqual(payload['insiderSignalType'], 'log_tampering')
        self.assertIn(16, payload['capabilityIds'])


if __name__ == '__main__':
    unittest.main()
