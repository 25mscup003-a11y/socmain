import unittest

from collectors.network import NetworkCollector, dns_anomaly_score


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)
        return True


def connection(**overrides):
    row = {
        'protocol': 'tcp', 'pid': 100, 'local_ip': '10.0.0.10',
        'local_port': 50000, 'remote_ip': '8.8.8.8', 'remote_port': 443,
        'state': 'ESTABLISHED', 'process_name': 'browser', 'username': 'analyst',
    }
    row.update(overrides)
    return row


class NetworkActivityTest(unittest.TestCase):
    def test_connection_lifecycle_records_close_without_payload(self):
        collector = NetworkCollector(Sender(), config={})
        active, closed, started = collector._track_connection_lifecycle([connection()])
        self.assertEqual(len(active), 1)
        self.assertEqual(len(started), 1)
        self.assertEqual(closed, [])
        self.assertTrue(active[0]['connection_id'])
        self.assertIn('start_time', active[0])

        active, closed, started = collector._track_connection_lifecycle([])
        self.assertEqual(active, [])
        self.assertEqual(started, [])
        self.assertEqual(closed[0]['state'], 'CLOSED')
        self.assertNotIn('payload', closed[0])

    def test_dns_anomaly_needs_multiple_contextual_signals(self):
        normal = dns_anomaly_score('updates.example.com', query_count=60, nxdomain_count=0)
        suspicious = dns_anomaly_score(
            'a9f8e7d6c5b4a3f2e1d0c9b8a7.example.com',
            query_count=80,
            nxdomain_count=50,
        )
        self.assertLess(normal['risk_score'], 45)
        self.assertGreaterEqual(suspicious['risk_score'], 45)
        self.assertGreaterEqual(len(suspicious['reasons']), 2)

    def test_scan_detection_is_threshold_based_and_explainable(self):
        sender = Sender()
        collector = NetworkCollector(sender, config={
            'port_scan_unique_ports': 5,
            'host_scan_unique_hosts': 50,
            'network_behavior_window_seconds': 60,
        })
        rows = [connection(remote_port=port, local_port=50000 + port) for port in range(1000, 1005)]
        collector._track_connection_lifecycle(rows)
        collector._detect_scan_and_lateral(rows)
        event = next(item for item in sender.events if item['rule_id'] == 'NET_SCAN_BEHAVIOR')
        self.assertEqual(event['mitre_id'], 'T1046')
        self.assertIn('threshold crossed', event['description'])

    def test_unchanged_topology_still_reports_periodic_interface_usage(self):
        sender = Sender()
        collector = NetworkCollector(sender, config={
            'network_summary_min_interval_seconds': 0,
            'network_usage_report_interval_seconds': 60,
        })
        empty_delta = {'interval_seconds': 10, 'bytes_sent': 0, 'bytes_received': 0, 'interfaces': []}
        collector._send_summary([], [], io_delta=empty_delta, interface_map={})
        sender.events.clear()

        collector._send_summary([], [], io_delta={
            'interval_seconds': 10,
            'bytes_sent': 1500,
            'bytes_received': 2500,
            'interfaces': [{'interface': 'wg0', 'bytes_sent': 600, 'bytes_received': 900}],
        }, interface_map={})

        summary = next(item for item in sender.events if item['rule_id'] == 'NET_CONNECTION_SUMMARY')
        self.assertEqual(summary['bytes_sent'], 1500)
        self.assertEqual(summary['bytes_received'], 2500)
        self.assertEqual(summary['raw']['adapter_delta']['interfaces'][0]['interface'], 'wg0')


if __name__ == '__main__':
    unittest.main()
