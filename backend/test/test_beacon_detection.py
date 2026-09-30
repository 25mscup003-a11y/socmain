import unittest

from collectors.network import NetworkCollector, beacon_interval_metrics


class _Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)
        return True


class BeaconDetectionTest(unittest.TestCase):
    def test_exact_and_jittered_intervals_are_recognized(self):
        exact = beacon_interval_metrics([0, 60, 120, 180, 240, 300])
        jittered = beacon_interval_metrics([0, 60, 123, 180, 241, 300])
        self.assertEqual(exact['average_interval'], 60)
        self.assertEqual(exact['jitter_seconds'], 0)
        self.assertGreaterEqual(jittered['interval_consistency'], 95)

    def test_random_traffic_does_not_cross_consistency_threshold(self):
        metrics = beacon_interval_metrics([0, 8, 91, 109, 310, 319])
        self.assertLess(metrics['interval_consistency'], 75)

    def test_periodicity_alone_does_not_create_high_risk(self):
        collector = NetworkCollector(_Sender(), config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
        })
        _metrics, risk = collector._assess_beacon(
            [0, 60, 120, 180, 240, 300],
            destination='93.184.216.34', port=443,
            process_name='trusted-browser', executable='/usr/bin/trusted-browser',
        )
        self.assertLess(risk, 70)

    def test_periodicity_plus_risky_process_and_destination_crosses_threshold(self):
        collector = NetworkCollector(_Sender(), config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
        })
        _metrics, risk = collector._assess_beacon(
            [0, 60, 121, 180, 240, 301],
            destination='203.0.113.99', port=4444,
            process_name='powershell.exe', executable='C:/Users/a/AppData/Local/Temp/powershell.exe',
        )
        self.assertGreaterEqual(risk, 70)

    def test_allowlisted_destination_is_suppressed(self):
        collector = NetworkCollector(_Sender(), config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
            'beacon_allow_destinations': ['updates.example.com'],
        })
        _metrics, risk = collector._assess_beacon(
            [0, 60, 120, 180, 240, 300],
            destination='updates.example.com', port=4444,
            process_name='powershell.exe', executable='/tmp/powershell.exe',
        )
        self.assertEqual(risk, 0)

    def test_low_and_slow_beacon_remains_detectable(self):
        collector = NetworkCollector(_Sender(), config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 60,
            'beacon_max_interval_seconds': 3600,
        })
        metrics, risk = collector._assess_beacon(
            [0, 900, 1803, 2698, 3601, 4500],
            destination='203.0.113.99', port=4444,
            process_name='python3', executable='/tmp/worker',
        )
        self.assertGreaterEqual(metrics['average_interval'], 895)
        self.assertGreaterEqual(risk, 70)

    def test_emitted_event_preserves_process_network_and_timing_evidence(self):
        sender = _Sender()
        collector = NetworkCollector(sender, config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
            'beacon_alert_threshold': 70,
        })
        collector._emit_beacon(
            ('connection', 'sample'), [0, 60, 120, 180, 240, 300], {
                'local_ip': '10.0.0.4', 'local_port': 51000,
                'remote_ip': '203.0.113.99', 'remote_port': 4444,
                'protocol': 'tcp', 'state': 'ESTABLISHED',
                'process_name': 'powershell.exe', 'pid': 4820,
                'parent_pid': 100, 'parent_process': 'services.exe',
                'executable': 'C:/Temp/powershell.exe',
                'command_line': 'powershell.exe -nop', 'username': 'SYSTEM',
                'process_hash': 'a' * 64, 'signature_status': 'unknown',
                'process_start_time': 123.0,
            },
        )
        self.assertEqual(len(sender.events), 1)
        event = sender.events[0]
        self.assertEqual(event['capabilityId'], 26)
        self.assertEqual(event['process_cmdline'], 'powershell.exe -nop')
        self.assertEqual(event['dst_ip'], '203.0.113.99')
        self.assertEqual(event['parent_process_name'], 'services.exe')
        self.assertEqual(event['connection_count'], 6)
        self.assertIn('suspicious-process-beacon', event['matched_patterns'])

    def test_disabled_builtin_rule_does_not_emit_unrelated_channel(self):
        sender = _Sender()
        collector = NetworkCollector(sender, config={
            'beacon_detection_enabled': True,
            'beacon_enabled_rule_ids': ['dns-periodic-beacon'],
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
            'beacon_alert_threshold': 25,
        })
        collector._emit_beacon(
            ('connection', 'web-disabled'), [0, 60, 120, 180, 240, 300],
            {'remote_ip': '203.0.113.99', 'remote_port': 443, 'protocol': 'https', 'process_name': 'browser'},
        )
        self.assertEqual(sender.events, [])

    def test_custom_rule_from_heartbeat_is_enforced(self):
        sender = _Sender()
        collector = NetworkCollector(sender, config={
            'beacon_detection_enabled': True,
            'beacon_enabled_rule_ids': [],
            'beacon_custom_rules': [{
                'id': 'custom:1',
                'conditions': [
                    {'field': 'beaconing', 'operator': 'eq', 'value': True},
                    {'field': 'protocol', 'operator': 'eq', 'value': 'https'},
                    {'field': 'connectionCount', 'operator': 'gte', 'value': 6},
                ],
            }],
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
            'beacon_alert_threshold': 25,
        })
        collector._emit_beacon(
            ('connection', 'custom-web'), [0, 60, 120, 180, 240, 300],
            {'remote_ip': '203.0.113.99', 'remote_port': 443, 'protocol': 'https', 'process_name': 'browser'},
        )
        self.assertEqual(len(sender.events), 1)
        self.assertIn('custom:1', sender.events[0]['matched_patterns'])

    def test_disabled_beaconing_policy_emits_nothing(self):
        sender = _Sender()
        collector = NetworkCollector(sender, config={
            'beacon_detection_enabled': False,
            'beacon_min_observation_seconds': 0,
        })
        collector._emit_beacon(
            ('connection', 'disabled'), [0, 60, 120, 180, 240, 300],
            {'remote_ip': '203.0.113.99', 'remote_port': 4444, 'process_name': 'powershell.exe'},
        )
        self.assertEqual(sender.events, [])

    def test_os_native_connection_events_feed_the_same_detector(self):
        sender = _Sender()
        collector = NetworkCollector(sender, config={
            'beacon_min_connections': 6,
            'beacon_min_observation_seconds': 0,
            'beacon_alert_threshold': 70,
        })
        connection = {
            'remote_ip': '203.0.113.99', 'remote_port': 4444,
            'protocol': 'tcp', 'process_name': 'powershell.exe',
            'pid': 4820, 'executable': 'C:/Temp/powershell.exe',
        }
        for observed_at in [0, 60, 120, 180, 240, 300]:
            collector._record_connection_beacon(connection, now=observed_at, max_age=3600)
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['connection_count'], 6)


if __name__ == '__main__':
    unittest.main()
