import os
import sys
import io
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'soc-agent'))
from core.suricata_parser import Parser, SURICATA_LOG_PATHS


class SuricataParserFilterTests(unittest.TestCase):
    def test_windows_programdata_eve_path_is_a_default_candidate(self):
        normalized = [path.replace('/', '\\').lower() for path in SURICATA_LOG_PATHS]
        self.assertTrue(any(path.endswith(r'ajnAT\suricata\log\eve.json'.lower()) for path in normalized))

    def test_routine_dns_telemetry_is_dropped_by_default(self):
        parser = Parser(sender=None)
        self.assertTrue(parser._drop_suricata_event({'event_type': 'dns', 'dns': {}}))

    def test_all_routine_suricata_telemetry_is_dropped_by_default(self):
        parser = Parser(sender=None)
        for event_type in ('flow', 'dns', 'tls', 'http', 'stats', 'fileinfo'):
            self.assertTrue(parser._drop_suricata_event({'event_type': event_type}))

    def test_alerts_and_anomalies_are_preserved(self):
        parser = Parser(sender=None)
        self.assertFalse(parser._drop_suricata_event({'event_type': 'alert', 'alert': {'signature_id': 42}}))
        self.assertFalse(parser._drop_suricata_event({'event_type': 'anomaly', 'anomaly': {'event': 'test'}}))

    def test_routine_telemetry_can_be_enabled_explicitly(self):
        parser = Parser(sender=None, config={'send_ids_routine_telemetry': True})
        self.assertFalse(parser._drop_suricata_event({'event_type': 'flow'}))

    def test_dns_alert_is_never_dropped(self):
        parser = Parser(sender=None)
        event = {'event_type': 'alert', 'alert': {'signature_id': 42}, 'dns': {}}
        self.assertFalse(parser._drop_suricata_event(event))

    def test_ignored_public_dns_ips_are_dropped_in_both_directions(self):
        parser = Parser(sender=None)
        self.assertTrue(parser._drop_suricata_event({'event_type': 'flow', 'src_ip': '8.8.8.8'}))
        self.assertTrue(parser._drop_suricata_event({'event_type': 'alert', 'dest_ip': '1.1.1.1', 'alert': {}}))

    def test_ignored_ip_list_can_be_overridden(self):
        parser = Parser(sender=None, config={
            'ids_sensor_ignored_ips': ['9.9.9.9'],
            'send_ids_routine_telemetry': True,
        })
        self.assertFalse(parser._drop_suricata_event({'event_type': 'flow', 'src_ip': '8.8.8.8'}))
        self.assertTrue(parser._drop_suricata_event({'event_type': 'flow', 'dest_ip': '9.9.9.9'}))

    def test_dns_telemetry_can_be_enabled_explicitly(self):
        parser = Parser(sender=None, config={'send_suricata_dns_telemetry': True})
        self.assertFalse(parser._drop_suricata_event({'event_type': 'dns', 'dns': {}}))

    def test_semantic_duplicate_is_suppressed_after_successful_delivery(self):
        parser = Parser(sender=None, config={'ids_sensor_dedupe_seconds': 900})
        event = {
            'event_id': 'native-1', 'timestamp': '2026-01-01T00:00:00Z',
            'source': 'suricata', 'log_type': 'alert', 'signature_id': '42',
            'signature': 'Example exploit', 'src_ip': '203.0.113.10',
            'dest_ip': '10.0.0.5', 'dest_port': 443, 'protocol': 'tcp',
            'severity': 'high', 'action': 'observed',
        }
        self.assertFalse(parser._is_duplicate_normalized_event(event))
        parser._remember_normalized_event(event)

        repeated = {**event, 'event_id': 'native-2', 'timestamp': '2026-01-01T00:00:05Z'}
        self.assertTrue(parser._is_duplicate_normalized_event(repeated))

        escalated = {**repeated, 'severity': 'critical'}
        self.assertFalse(parser._is_duplicate_normalized_event(escalated))

    def test_failed_delivery_is_not_marked_as_duplicate(self):
        parser = Parser(sender=None)
        event = {'source': 'zeek', 'log_type': 'notice', 'signature': 'Scan::Port_Scan'}
        self.assertFalse(parser._is_duplicate_normalized_event(event))
        self.assertFalse(parser._is_duplicate_normalized_event(event))

    def test_zeek_tsv_fields_are_loaded_before_tailing(self):
        log = io.StringIO('#separator \\x09\n#fields\tts\tuid\tid.orig_h\n1.0\tC1\t10.0.0.1\n')
        self.assertEqual(Parser._read_zeek_fields(log), ['ts', 'uid', 'id.orig_h'])

    def test_zeek_public_dns_resolver_traffic_is_suppressed(self):
        sent = []
        parser = Parser(sender=None)
        parser._send_normalized = lambda event: sent.append(event) or True
        parser._process_zeek_event(
            {'id.orig_h': '192.168.1.10', 'id.resp_h': '8.8.8.8', 'id.resp_p': 53},
            '/var/log/zeek/current/conn.log',
        )
        self.assertEqual(sent, [])

    def test_zeek_truncated_payload_diagnostic_is_suppressed(self):
        sent = []
        parser = Parser(sender=None)
        parser._send_normalized = lambda event: sent.append(event) or True
        parser._process_zeek_event(
            {'name': 'truncated_tcp_payload', 'id.orig_h': '192.168.1.10', 'id.resp_h': '203.0.113.8'},
            '/var/log/zeek/current/weird.log',
        )
        self.assertEqual(sent, [])

    def test_other_zeek_weird_remains_actionable(self):
        sent = []
        parser = Parser(sender=None)
        parser._send_normalized = lambda event: sent.append(event) or True
        parser._process_zeek_event(
            {'name': 'possible_split_routing', 'id.orig_h': '192.168.1.10', 'id.resp_h': '203.0.113.8'},
            '/var/log/zeek/current/weird.log',
        )
        self.assertEqual(len(sent), 1)
        self.assertTrue(sent[0]['actionable'])


if __name__ == '__main__':
    unittest.main()
