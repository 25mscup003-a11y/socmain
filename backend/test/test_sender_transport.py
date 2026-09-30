import gzip
import json
import unittest
import threading
from queue import PriorityQueue
from unittest.mock import Mock, patch

from core.sender import AlertSender, _encode_transport_body, _redact_command_line
from core.security import canonicalize, signed_headers


class SenderTransportTest(unittest.TestCase):
    def test_priority_queue_sequence_never_reuses_refill_tiebreaker(self):
        sender = object.__new__(AlertSender)
        sender._q = PriorityQueue(maxsize=10)
        sender._q_counter = 0
        sender._q_lock = threading.Lock()
        sender._queued_ids = set()
        first = {'event_id': 'first', 'severity': 'low'}
        second = {'event_id': 'second', 'severity': 'low'}
        self.assertTrue(sender._queue_for_delivery(first))
        producer_sequence = sender._next_sequence()
        self.assertTrue(sender._queue_for_delivery(second, sequence=producer_sequence))
        self.assertEqual(sender._q.get_nowait()[2]['event_id'], 'first')
        self.assertEqual(sender._q.get_nowait()[2]['event_id'], 'second')

    def test_signing_matches_javascript_for_integer_valued_floats(self):
        self.assertEqual(canonicalize({'risk': 80.0, 'ratio': 1.5}), '{"ratio":1.5,"risk":80}')

    def test_supported_legacy_secret_is_forwarded_during_signed_rollout(self):
        headers = signed_headers({'agent_key': 'key', 'integration_secret': 'secret'}, {'value': 1})
        self.assertEqual(headers['x-integration-secret'], 'secret')
        self.assertIn('x-agent-signature', headers)

    def test_large_batch_is_gzipped_and_round_trips(self):
        payload = {'alerts': [{'event_id': str(i), 'message': 'x' * 200} for i in range(20)]}
        body, headers = _encode_transport_body(payload, gzip_min_bytes=100)
        self.assertEqual(headers['Content-Encoding'], 'gzip')
        self.assertEqual(json.loads(gzip.decompress(body)), payload)

    def test_small_payload_remains_plain_json(self):
        payload = {'alerts': [{'event_id': 'one'}]}
        body, headers = _encode_transport_body(payload, gzip_min_bytes=10000)
        self.assertNotIn('Content-Encoding', headers)
        self.assertEqual(json.loads(body), payload)

    def test_batch_uses_secure_json_transport_instead_of_unencrypted_data(self):
        sender = object.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent', 'system_id': 'system',
            'server_url': 'https://soc.example.test',
        }
        sender._build_payload = lambda alert: alert
        response = Mock(status_code=202)
        with patch('core.sender.secure_request', return_value=response) as request:
            self.assertTrue(sender._send_batch([
                {'event_id': 'one'}, {'event_id': 'two'},
            ]))
        kwargs = request.call_args.kwargs
        self.assertEqual(kwargs['json'], {
            'alerts': [{'event_id': 'one'}, {'event_id': 'two'}],
        })
        self.assertNotIn('data', kwargs)

    def test_sensitive_command_arguments_are_redacted(self):
        value = _redact_command_line('tool --token abc123 --password="secret" Authorization: Bearer jwt.value')
        self.assertNotIn('abc123', value)
        self.assertNotIn('secret', value)
        self.assertNotIn('jwt.value', value)
        self.assertIn('[REDACTED]', value)

    def test_fim_fields_survive_agent_payload_mapping(self):
        sender = object.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent', 'company_id': 'company', 'department_id': 'department',
            'system_id': 'system', 'system_name': 'host', 'agent_version': 'test',
        }
        payload = sender._build_payload({
            'rule_id': 'FILE_PERMISSION_CHANGED', 'category': 'file', 'capabilityId': 2,
            'module_type': 'permission', 'fim_module': 'permission',
            'old_permission': '0644', 'new_permission': '0777',
            'permission_risk': 'world-writable', 'changed_by_user': 'alice',
            'old_owner': 'root', 'new_owner': 'alice',
            'extension_changed': False, 'encryption_indicator': False,
        })
        self.assertEqual(payload['capabilityId'], 2)
        self.assertEqual(payload['module_type'], 'permission')
        self.assertEqual(payload['old_permission'], '0644')
        self.assertEqual(payload['new_permission'], '0777')
        self.assertEqual(payload['changed_by_user'], 'alice')
        self.assertEqual(payload['extension_changed'], False)
        self.assertEqual(payload['encryption_indicator'], False)

    def test_advanced_dns_fields_survive_agent_payload_mapping(self):
        sender = object.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent', 'company_id': 'company', 'department_id': 'department',
            'system_id': 'system', 'system_name': 'host', 'agent_version': 'test',
        }
        payload = sender._build_payload({
            'rule_id': 'DNS_CACHE_POISON_TTL_DROP', 'category': 'network',
            'capabilityId': 30, 'domain': 'example.test', 'query_type': 'A',
            'response_type': 'ttl_drop', 'new_ttl': 5, 'old_ttl': 300,
            'riskScore': 80,
        })
        self.assertEqual(payload['capabilityId'], 30)
        self.assertEqual(payload['domain'], 'example.test')
        self.assertEqual(payload['queryType'], 'A')
        self.assertEqual(payload['responseType'], 'ttl_drop')
        self.assertEqual(payload['ttl'], 5)
        self.assertEqual(payload['previousTtl'], 300)

    def test_native_gps_fields_survive_agent_payload_mapping(self):
        sender = object.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent', 'company_id': 'company', 'department_id': 'department',
            'system_id': 'system', 'system_name': 'host', 'agent_version': 'test',
        }
        payload = sender._build_payload({
            'rule_id': 'GPS_LOCATION_TELEMETRY', 'category': 'edr',
            'gpsLat': 0, 'gpsLon': 80.9231, 'gpsAccuracyMeters': 25000,
            'gpsAltitudeMeters': 120, 'gpsProvider': 'geoclue',
            'gpsStatus': 'available', 'gpsObservedAt': '2026-09-07T03:38:00Z',
        })
        self.assertEqual(payload['gpsLat'], 0)
        self.assertEqual(payload['gpsLon'], 80.9231)
        self.assertEqual(payload['gpsAccuracyMeters'], 25000)
        self.assertEqual(payload['gpsProvider'], 'geoclue')
        self.assertEqual(payload['gpsStatus'], 'available')

    def test_multi_capability_and_behavior_metrics_survive_payload_mapping(self):
        sender = object.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent', 'company_id': 'company', 'department_id': 'department',
            'system_id': 'system', 'system_name': 'host', 'agent_version': 'test',
        }
        payload = sender._build_payload({
            'rule_id': 'BEACON_PERIODIC_CONNECTION', 'category': 'network',
            'capabilityId': 26, 'capabilityIds': [1, 3, 26],
            'connection_count': 12, 'average_interval': 60.4,
            'median_interval': 60, 'jitter_seconds': 2.1,
            'interval_consistency': 96.5, 'periodicity_score': 24.1,
            'observation_seconds': 7200,
        })
        self.assertEqual(payload['capabilityIds'], [1, 3, 26])
        self.assertEqual(payload['connectionCount'], 12)
        self.assertEqual(payload['averageInterval'], 60.4)
        self.assertEqual(payload['jitterSeconds'], 2.1)


if __name__ == '__main__':
    unittest.main()
