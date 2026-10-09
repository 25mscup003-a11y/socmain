import os
import sys
import threading
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'soc-agent'))
from core.network_telemetry import PeerMetadataCache, parse_tcp_counters, socket_key
from collectors import network


def connection(**changes):
    return dict(protocol='tcp', local_ip='10.0.0.2', local_port=51000,
                remote_ip='8.8.8.8', remote_port=443, state='ESTABLISHED',
                process_name='browser', username='analyst', pid=42, **changes)


class NetworkTelemetryTests(unittest.TestCase):
    def test_tcp_counters_match_ipv4_and_ipv6_endpoints_not_queue_sizes(self):
        data = parse_tcp_counters('ESTAB 8192 4096 10.0.0.2:51000 8.8.8.8:443\n'
                                  '\t cubic bytes_sent:1234 bytes_received:5678 bytes_acked:1235\n'
                                  'ESTAB 0 0 [::ffff:10.0.0.2]:52000 [2606:4700::1111]:443\n'
                                  '\t cubic bytes_sent:0 bytes_received:9000\n'
                                  'ESTAB 42 99 10.0.0.2:53000 1.1.1.1:443\n\t cubic rtt:2/3\n')
        self.assertEqual(data[socket_key('10.0.0.2', 51000, '8.8.8.8', 443)], {'bytes_sent': 1234, 'bytes_received': 5678})
        self.assertEqual(data[socket_key('10.0.0.2', 52000, '2606:4700::1111', 443)]['bytes_sent'], 0)
        self.assertNotIn(socket_key('10.0.0.2', 53000, '1.1.1.1', 443), data)

    def test_process_username_survives_protected_executable_and_pid_reuse(self):
        class AccessDenied(Exception):
            pass
        psutil = Mock(AccessDenied=AccessDenied, NoSuchProcess=ProcessLookupError)
        proc = psutil.Process.return_value
        proc.create_time.return_value = 100
        proc.name.return_value = 'browser'
        proc.username.return_value = 'alice'
        proc.exe.side_effect = AccessDenied()
        proc.cmdline.return_value = []
        proc.ppid.return_value = 1
        proc.parent.return_value = None
        cache = {}
        self.assertEqual(network._process_identity(psutil, 42, cache, now=1)['username'], 'alice')
        proc.create_time.return_value = 200
        proc.username.return_value = 'bob'
        self.assertEqual(network._process_identity(psutil, 42, cache, now=2)['username'], 'bob')

    def test_metadata_lookup_is_nonblocking_deduplicated_and_skips_private_ips(self):
        entered, release = threading.Event(), threading.Event()
        def lookup(ip):
            entered.set()
            release.wait(2)
            return {'domain': 'dns.google', 'geo': {'country': 'United States'}}
        lookup = Mock(side_effect=lookup)
        cache = PeerMetadataCache(lookup, interval=0)
        self.addCleanup(cache.close)
        self.assertEqual(cache.get('10.0.0.2'), {})
        self.assertEqual(cache.get('8.8.8.8'), {})
        self.assertTrue(entered.wait(1))
        self.assertEqual(cache.get('8.8.8.8'), {})
        self.assertEqual(lookup.call_count, 1)
        release.set()
        cache.queue.join()
        self.assertEqual(cache.get('8.8.8.8')['domain'], 'dns.google')
        self.assertEqual(lookup.call_count, 1)

    def test_all_peers_receive_metadata_and_only_matching_tcp_sockets_receive_bytes(self):
        collector = network.NetworkCollector(Mock(), config={})
        collector._peer_metadata = Mock()
        collector._peer_metadata.get.return_value = {'domain': 'reverse.example', 'geo': {'country': 'India'}}
        collector._remember_dns_query('queried.example', ['8.8.8.8'])
        rows = [{**connection(), 'local_port': 51000 + n, 'protocol': 'udp' if n == 6 else 'tcp'} for n in range(8)]
        with patch.object(network, 'linux_tcp_counters', return_value={socket_key('10.0.0.2', 51000, '8.8.8.8', 443): {'bytes_sent': 1024, 'bytes_received': 2048}}):
            collector._enrich_connection_telemetry(rows)
        self.assertEqual(collector._peer_metadata.get.call_count, 8)
        self.assertTrue(all(row['domain'] == 'queried.example' and row['geo']['country'] == 'India' for row in rows))
        self.assertEqual(rows[0]['bytes_sent'], 1024)
        self.assertNotIn('bytes_sent', rows[6])

    def test_summary_preserves_and_sums_socket_evidence_without_counter_churn(self):
        rows = [dict(connection(), bytes_sent=100, bytes_received=200, bytes_source='linux_tcp_info', domain='example.test', geo={'country': 'India'})]
        first = network._summary_connection_inventory(rows)[0]
        rows.append({**rows[0], 'local_port': 52000, 'bytes_sent': 300, 'bytes_received': 400})
        combined = network._summary_connection_inventory(rows)[0]
        self.assertEqual(combined['bytes_sent'], 400)
        self.assertEqual(combined['bytes_received'], 600)
        self.assertEqual(combined['bytes_scope'], 'active_sockets')
        self.assertEqual(combined['socket_count'], 2)
        self.assertEqual(combined['username'], 'analyst')
        self.assertEqual(combined['domain'], 'example.test')
        self.assertEqual(combined['geo']['country'], 'India')
        self.assertEqual(network._network_state_fingerprint(first), network._network_state_fingerprint(combined))

    def test_windows_dns_answers_enter_the_connection_dns_cache(self):
        collector = network.NetworkCollector(Mock(), config={'dns_beacon_detection_enabled': False})
        collector.observe_dns_query('example.test', {'query_results': '8.8.8.8;::ffff:1.1.1.1;type:5 cname.test'})
        _, answers = collector._recent_dns_queries()
        self.assertEqual(answers['example.test'], ['8.8.8.8', '1.1.1.1'])


if __name__ == '__main__':
    unittest.main()
