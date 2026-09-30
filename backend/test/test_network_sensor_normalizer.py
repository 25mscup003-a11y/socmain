import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'soc-agent'))
from core.network_sensor_normalizer import (
    is_suricata_informational_noise,
    is_zeek_informational_noise,
    normalize_suricata,
    normalize_zeek,
)


class NetworkSensorNormalizerTests(unittest.TestCase):
    def test_tor_feed_self_check_is_informational_noise(self):
        event = {
            'event_type': 'alert',
            'alert': {'signature_id': 2017926, 'signature': 'ET INFO check.torproject.org DNS lookup'},
            'dns': {'queries': [{'rrname': 'check.torproject.org'}]},
        }
        self.assertTrue(is_suricata_informational_noise(event))
        event['alert']['signature_id'] = 999999
        self.assertFalse(is_suricata_informational_noise(event))

    def test_ip_api_self_lookup_is_informational_noise(self):
        for signature_id in (2022082, 2054141):
            event = {
                'event_type': 'alert',
                'alert': {'signature_id': signature_id, 'signature': 'ET INFO External IP Lookup ip-api.com'},
                'http': {'hostname': 'ip-api.com'},
            }
            self.assertTrue(is_suricata_informational_noise(event))

    def test_harmless_stream_self_noise_is_suppressed(self):
        event = {
            'event_type': 'alert',
            'alert': {'signature_id': 2210054, 'signature': 'SURICATA STREAM harmless event ip-api.com'},
        }
        self.assertTrue(is_suricata_informational_noise(event))

    def test_repetitive_suricata_decoder_diagnostics_are_local_only(self):
        for signature_id in (2200003, 2210045, 2210046):
            event = {
                'event_type': 'alert',
                'alert': {'signature_id': signature_id, 'signature': 'SURICATA decoder diagnostic'},
            }
            self.assertTrue(is_suricata_informational_noise(event))

    def test_real_suricata_signature_is_not_suppressed(self):
        event = {
            'event_type': 'alert',
            'alert': {'signature_id': 2100498, 'signature': 'GPL ATTACK_RESPONSE id check returned root'},
        }
        self.assertFalse(is_suricata_informational_noise(event))

    def test_only_exact_zeek_truncated_payload_weird_is_suppressed(self):
        self.assertTrue(is_zeek_informational_noise({'name': 'truncated_tcp_payload'}, 'weird'))
        self.assertFalse(is_zeek_informational_noise({'name': 'possible_split_routing'}, 'weird'))
        self.assertFalse(is_zeek_informational_noise({'name': 'truncated_tcp_payload'}, 'notice'))

    def test_suricata_alert(self):
        event = {'timestamp': '2026-01-02T03:04:05Z', 'event_type': 'alert',
                 'src_ip': '203.0.113.7', 'src_port': 1234, 'dest_ip': '10.0.0.2',
                 'dest_port': 443, 'proto': 'TCP', 'community_id': '1:test',
                 'alert': {'severity': 2, 'signature_id': 42, 'signature': 'CVE-2025-1234 exploit', 'action': 'allowed'}}
        result = normalize_suricata(event, 'sensor-a')
        self.assertEqual(result['severity'], 'high')
        self.assertEqual(result['log_type'], 'alert')
        self.assertTrue(result['actionable'])
        self.assertEqual(result['community_id'], '1:test')
        self.assertEqual(json.loads(result['raw_event'])['alert']['signature_id'], 42)

    def test_suricata_dns_telemetry(self):
        result = normalize_suricata({'event_type': 'dns', 'dns': {'rrname': 'example.test'}})
        self.assertFalse(result['actionable'])
        self.assertEqual(result['hostname'], 'example.test')

    def test_all_requested_zeek_logs(self):
        for log_type in ('conn', 'dns', 'http', 'ssl', 'files', 'notice', 'weird', 'x509'):
            result = normalize_zeek({'ts': 1700000000, 'uid': f'u-{log_type}',
                                     'id.orig_h': '192.0.2.1', 'id.resp_h': '198.51.100.2'}, log_type)
            self.assertEqual(result['log_type'], log_type)
            self.assertTrue(result['event_id'].startswith('zeek:'))

    def test_rejects_invalid_input(self):
        with self.assertRaises(ValueError):
            normalize_suricata({'event_type': 'unknown'})
        with self.assertRaises(ValueError):
            normalize_zeek([], 'conn')


if __name__ == '__main__':
    unittest.main()
