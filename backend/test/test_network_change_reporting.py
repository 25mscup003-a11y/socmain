import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from collectors import network
from core.sender import AlertSender


def connection(**changes):
    return {
        'protocol': 'tcp', 'pid': 42, 'local_ip': '10.0.0.2', 'local_port': 51000,
        'remote_ip': '203.0.113.10', 'remote_port': 443, 'state': 'ESTABLISHED',
        'process_name': 'browser', 'process_start_time': 100, 'interface': 'eth0',
        **changes,
    }


class NetworkChangeReportingTests(unittest.TestCase):
    def setUp(self):
        self.sender = Mock()
        self.sender.enqueue.return_value = True
        self.collector = network.NetworkCollector(
            self.sender, config={'network_summary_min_interval_seconds': 0}
        )
        self.vpn = {'active': False, 'interfaces': [], 'processes': [], 'ports': [], 'remote_peers': []}
        for name, value in [
            ('_get_vpn_state', self.vpn), ('_dns_resolvers', (['10.0.0.1'], [])),
            ('_reverse_dns', ''), ('_mfa_sso_hits', []),
        ]:
            patcher = patch.object(network, name, return_value=value)
            setattr(self, name, patcher.start())
            self.addCleanup(patcher.stop)
        patcher = patch.object(network, '_peer_summary', side_effect=lambda row, **_: {
            key: row.get(key) for key in ('remote_ip', 'remote_port', 'local_ip', 'local_port', 'pid')
        })
        patcher.start()
        self.addCleanup(patcher.stop)
        self.collector._emit_process_dns_attribution = Mock()
        self.collector._recent_dns_queries = Mock(return_value=([], {}))

    def emit(self, connections=None, listeners=None, **options):
        self.collector._send_summary(connections or [], listeners or [], **options)

    def events(self, rule=None):
        events = [call.args[0] for call in self.sender.enqueue.call_args_list]
        return [event for event in events if not rule or event['rule_id'] == rule]

    def test_unchanged_inventory_does_not_resend_before_usage_interval(self):
        self.emit([connection(observed_at='2026-01-01', duration=0,
                              start_time='2026-01-01', end_time=None)])
        baseline = len(self.events())
        self.assertEqual(baseline, 4)
        baseline_time = network.time.time()
        self.collector._last_usage_emit = baseline_time
        for counter in range(1, 20):
            with patch.object(network.time, 'time', return_value=baseline_time + counter):
                self.emit([connection(observed_at=str(counter), duration=counter * 20,
                                      start_time=str(counter), end_time=str(counter + 1))], io_delta={
                    'interval_seconds': 20, 'bytes_sent': counter * 100, 'bytes_received': counter,
                    'interfaces': [{'interface': 'eth0', 'bytes_sent': counter * 100}],
                })
        self.assertEqual(len(self.events()), baseline)
        self.assertTrue(all(event['raw']['reporting_mode'] == 'on_change' for event in self.events()))

    def test_agent_and_same_host_server_control_plane_sockets_are_ignored(self):
        server_addresses = {'10.0.0.2'}
        self.assertTrue(network._is_agent_control_plane_connection(
            connection(pid=900, remote_ip='10.0.0.2', remote_port=5000),
            server_addresses, 5000, {'10.0.0.2'}, agent_pid=900,
        ))
        self.assertTrue(network._is_agent_control_plane_connection(
            connection(pid=901, local_ip='10.0.0.2', local_port=5000,
                       remote_ip='10.0.0.2', remote_port=51000),
            server_addresses, 5000, {'10.0.0.2'}, agent_pid=900,
        ))
        self.assertFalse(network._is_agent_control_plane_connection(
            connection(pid=901, remote_ip='203.0.113.10', remote_port=443),
            server_addresses, 5000, {'10.0.0.2'}, agent_pid=900,
        ))

    def test_os_enumeration_order_does_not_resend_sampled_peers(self):
        rows = [connection(local_port=51000 + index) for index in range(20)]
        self.emit(rows)
        self.sender.reset_mock()
        self.emit(list(reversed(rows)))
        self.sender.enqueue.assert_not_called()

    def test_connection_state_process_service_port_and_ip_changes_are_reported(self):
        current = connection()
        self.emit([current])
        for key, value in [('state', 'CLOSE_WAIT'), ('process_name', 'other-browser'),
                           ('remote_ip', '203.0.113.20'), ('remote_port', 8443)]:
            self.sender.reset_mock()
            current = {**current, key: value}
            self.emit([current])
            self.assertEqual(len(self.events('NET_CONNECTION_SUMMARY')), 1, key)
            self.assertEqual(len(self.events('NET_EXPOSURE_SUMMARY')), 0)

    def test_ephemeral_source_port_pid_and_parallel_socket_churn_do_not_resend(self):
        first = connection(local_port=51000, pid=42, process_start_time=100)
        self.emit([first])
        self.sender.reset_mock()
        second = connection(local_port=52000, pid=84, process_start_time=200)
        self.emit([second])
        self.sender.enqueue.assert_not_called()
        self.emit([first, second])
        self.sender.enqueue.assert_not_called()
        self.emit([second], closed_connections=[{**first, 'state': 'CLOSED'}])
        self.sender.enqueue.assert_not_called()

    def test_summary_payload_keeps_pid_and_observed_source_port_without_fingerprinting_them(self):
        self.emit([connection(local_port=51000, pid=42)])
        event = self.events('NET_CONNECTION_SUMMARY')[0]
        row = event['raw']['connections'][0]
        self.assertEqual(row['pid'], 42)
        self.assertEqual(row['observed_local_port'], 51000)
        self.sender.reset_mock()
        self.emit([connection(local_port=52000, pid=84)])
        self.sender.enqueue.assert_not_called()

    def test_same_host_application_churn_is_not_in_summary_state(self):
        local = connection(local_ip='10.0.0.2', remote_ip='10.0.0.2', remote_port=27017,
                           process_name='node')
        self.emit([], interface_map={'10.0.0.2': 'eth0'})
        self.sender.reset_mock()
        self.emit([local], interface_map={'10.0.0.2': 'eth0'})
        self.sender.enqueue.assert_not_called()

    def test_transient_tcp_kernel_states_do_not_create_extra_summaries(self):
        self.emit([])
        self.sender.reset_mock()
        for state in ('SYN_SENT', 'FIN_WAIT1', 'FIN_WAIT2', 'TIME_WAIT', 'LAST_ACK'):
            self.emit([connection(state=state)])
        self.sender.enqueue.assert_not_called()

    def test_summary_debounce_retains_latest_changed_state(self):
        collector = network.NetworkCollector(
            self.sender, config={'network_summary_min_interval_seconds': 120}
        )
        collector._emit_process_dns_attribution = Mock()
        collector._recent_dns_queries = Mock(return_value=([], {}))
        with patch.object(network, '_get_vpn_state', return_value=self.vpn), \
                patch.object(network, '_dns_resolvers', return_value=(['10.0.0.1'], [])), \
                patch.object(network, '_reverse_dns', return_value=''), \
                patch.object(network, '_mfa_sso_hits', return_value=[]), \
                patch.object(network.time, 'monotonic', return_value=100) as clock:
            collector._send_summary([connection()], [])
            baseline = self.sender.enqueue.call_count
            clock.return_value = 150
            collector._send_summary([connection(remote_ip='203.0.113.20')], [])
            self.assertEqual(self.sender.enqueue.call_count, baseline)
            clock.return_value = 221
            collector._send_summary([connection(remote_ip='203.0.113.20')], [])
            self.assertGreater(self.sender.enqueue.call_count, baseline)

    def test_connection_close_is_reported_immediately_once(self):
        tracked, _, _ = self.collector._track_connection_lifecycle([connection()])
        self.emit(tracked)
        active, closed, _ = self.collector._track_connection_lifecycle([])
        self.sender.reset_mock()
        self.emit(active, closed_connections=closed)
        event = self.events('NET_CONNECTION_SUMMARY')[0]
        self.assertEqual(event['raw']['closed_connections'][0]['state'], 'CLOSED')
        self.assertEqual(event['raw']['connections'], [])
        self.sender.reset_mock()
        self.emit([])
        self.sender.enqueue.assert_not_called()

    def test_listener_change_and_return_to_prior_state_are_not_suppressed(self):
        listener = connection(remote_ip='', remote_port=0, local_port=8080, listener=True, state='LISTEN')
        self.emit([])
        for listeners in ([listener], [], [listener]):
            self.sender.reset_mock()
            self.emit([], listeners)
            self.assertEqual(len(self.events('NET_CONNECTION_SUMMARY')), 1)
            self.assertEqual(len(self.events('NET_EXPOSURE_SUMMARY')), 1)

    def test_dns_answer_change_emits_dns_only_and_repeat_queries_do_not_resend(self):
        self.collector._recent_dns_queries.return_value = (['example.test'], {'example.test': ['203.0.113.1']})
        self.emit([connection()])
        self.sender.reset_mock()
        self.collector._dns_query_interval_count = 300
        self.collector._dns_query_types['A'] = 300
        self.emit([connection()])
        self.sender.enqueue.assert_not_called()
        self.collector._recent_dns_queries.return_value = (['example.test'], {'example.test': ['203.0.113.2']})
        self.emit([connection()])
        self.assertEqual([event['rule_id'] for event in self.events()], ['NET_DNS_SUMMARY'])

    def test_process_dns_attribution_groups_multiple_answers_for_one_domain(self):
        collector = network.NetworkCollector(self.sender, config={})
        rows = [connection(remote_ip=ip, remote_port=443) for ip in (
            '151.101.2.132', '151.101.66.132', '151.101.130.132', '151.101.194.132',
        )]
        answers = {'j.sni.global.fastly.net': [row['remote_ip'] for row in rows]}
        collector._emit_process_dns_attribution(rows, answers)
        events = [call.args[0] for call in self.sender.enqueue.call_args_list]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['rule_id'], 'PROC_DNS_ATTRIBUTED')
        self.assertEqual(len(events[0]['destination_ips']), 4)
        self.assertEqual(events[0]['protocol'], 'tcp')
        self.sender.reset_mock()
        collector._emit_process_dns_attribution(list(reversed(rows)), answers)
        self.sender.enqueue.assert_not_called()

    def test_process_dns_attribution_does_not_repeat_after_socket_temporarily_disappears(self):
        collector = network.NetworkCollector(self.sender, config={})
        rows = [connection(remote_ip='151.101.2.132', remote_port=443)]
        answers = {'j.sni.global.fastly.net': ['151.101.2.132']}
        collector._emit_process_dns_attribution(rows, answers)
        first = self.sender.enqueue.call_args.args[0]
        self.assertTrue(first['event_id'])
        self.sender.reset_mock()
        collector._emit_process_dns_attribution([], answers)
        collector._emit_process_dns_attribution(rows, answers)
        self.sender.enqueue.assert_not_called()

    def test_process_dns_attribution_changes_when_process_instance_changes(self):
        collector = network.NetworkCollector(self.sender, config={})
        answers = {'j.sni.global.fastly.net': ['151.101.2.132']}
        collector._emit_process_dns_attribution([
            connection(remote_ip='151.101.2.132', process_start_time=100),
        ], answers)
        first = self.sender.enqueue.call_args.args[0]
        self.sender.reset_mock()
        collector._emit_process_dns_attribution([
            connection(remote_ip='151.101.2.132', process_start_time=200),
        ], answers)
        second = self.sender.enqueue.call_args.args[0]
        self.assertNotEqual(first['event_id'], second['event_id'])

    def test_interface_dns_configuration_and_vpn_changes_are_reported(self):
        self.emit([connection()], interface_map={'10.0.0.2': 'eth0'})
        self.sender.reset_mock()
        self.emit([connection()], interface_map={'10.0.0.2': 'wlan0'})
        self.assertEqual(len(self.events('NET_CONNECTION_SUMMARY')), 1)
        self.sender.reset_mock()
        self._dns_resolvers.return_value = (['10.0.0.3'], ['example.test'])
        self.emit([connection()], interface_map={'10.0.0.2': 'wlan0'})
        self.assertEqual(len(self.events('NET_CONNECTION_SUMMARY')), 1)
        self.sender.reset_mock()
        self.vpn['active'] = True
        self.emit([connection()], interface_map={'10.0.0.2': 'wlan0'})
        self.assertEqual(len(self.events('NET_CONNECTION_SUMMARY')), 1)

    def test_rejected_enqueue_is_retried_with_closures_and_accumulated_bytes(self):
        tracked, _, _ = self.collector._track_connection_lifecycle([connection()])
        self.emit(tracked)
        self.collector._last_usage_emit = network.time.time()
        self.emit(tracked, io_delta={'interval_seconds': 20, 'bytes_sent': 30})
        active, closed, _ = self.collector._track_connection_lifecycle([])
        self.sender.enqueue.return_value = False
        self.emit(active, closed_connections=closed, io_delta={'interval_seconds': 20, 'bytes_sent': 40})
        self.assertEqual(len(self.collector._pending_closed_connections), 1)
        self.sender.reset_mock()
        self.sender.enqueue.return_value = True
        self.emit(active, io_delta={'interval_seconds': 20, 'bytes_sent': 50})
        event = self.events('NET_CONNECTION_SUMMARY')[0]
        self.assertEqual(len(event['raw']['closed_connections']), 1)
        self.assertEqual(event['bytes_sent'], 120)
        self.assertEqual(event['raw']['adapter_delta']['interval_seconds'], 60)
        self.assertEqual(self.collector._pending_closed_connections, {})

    def test_socket_counters_refresh_periodically_without_an_adapter_delta(self):
        with patch.object(network.time, 'time', return_value=1000) as clock:
            self.emit([connection(bytes_sent=100, bytes_received=200)])
            self.sender.reset_mock()
            clock.return_value = 1020
            self.emit([connection(bytes_sent=200, bytes_received=300)])
            self.sender.enqueue.assert_not_called()
            clock.return_value = 1061
            self.emit([connection(bytes_sent=300, bytes_received=400)])
        events = self.events('NET_CONNECTION_SUMMARY')
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['raw']['connections'][0]['bytes_sent'], 300)
        self.assertEqual(events[0]['raw']['connections'][0]['bytes_received'], 400)

    def test_closure_batches_are_drained_without_losing_rows(self):
        self.collector._config['network_snapshot_max_closed'] = 1
        tracked, _, _ = self.collector._track_connection_lifecycle([
            connection(), connection(local_port=52000, remote_ip='203.0.113.20')
        ])
        self.emit(tracked)
        active, closed, _ = self.collector._track_connection_lifecycle([])
        self.sender.reset_mock()
        self.emit(active, closed_connections=closed)
        self.emit(active)
        self.assertEqual(sum(len(event['raw']['closed_connections']) for event in self.events('NET_CONNECTION_SUMMARY')), 2)
        self.assertEqual(self.collector._pending_closed_connections, {})

    def test_socket_scan_failure_is_not_reported_as_all_connections_closed(self):
        self.collector._track_connection_lifecycle([connection()])
        with patch('psutil.net_connections', side_effect=PermissionError('access denied')):
            self.collector._check()
        self.assertEqual(len(self.collector._active_connections), 1)
        self.sender.enqueue.assert_not_called()

    def test_local_security_checks_continue_during_unchanged_scans(self):
        with patch('psutil.net_connections', return_value=[]), \
                patch.object(network, '_get_connections', side_effect=lambda **_: [connection()]), \
                patch.object(network, '_get_listeners', return_value=[]), \
                patch.object(network, '_interface_by_ip', return_value={}), \
                patch.object(self.collector, '_network_io_delta', return_value={}), \
                patch.object(self.collector, '_observe_connection_beacons') as beacon, \
                patch.object(self.collector, '_detect_scan_and_lateral') as scanning, \
                patch.object(self.collector, '_detect_transfer_anomaly') as transfer, \
                patch.object(self.collector, '_enforce_port_policy') as ports:
            self.collector._check()
            self.sender.reset_mock()
            self.collector._check()
        self.sender.enqueue.assert_not_called()
        for detector in (beacon, scanning, transfer, ports):
            self.assertEqual(detector.call_count, 2)


class NetworkChangeDeliveryTests(unittest.TestCase):
    def test_changes_survive_queue_pressure_restart_and_legacy_snapshot_cleanup(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch('core.sender.TimeAnomalyDetector', None), \
                patch('core.sender.tag_insider_threat', None):
            config = {'sender_spool_path': str(Path(directory) / 'spool.db'),
                      'storage_encryption_key': 'a' * 64, 'geo_enrichment_enabled': False, 'system_id': 'test'}
            state = Mock()
            state.event_is_after_install.return_value = True
            state.is_duplicate.return_value = True  # Collector owns change comparison.
            sender = AlertSender(config, state)
            sender._overload = True
            sender._queue_for_delivery = Mock(return_value=False)
            for rule in ('NET_CONNECTION_SUMMARY', 'NET_DNS_SUMMARY', 'NET_EXPOSURE_SUMMARY', 'NET_THREAT_INTEL_SUMMARY'):
                for index in range(2):
                    event = {'event_id': f'{rule}-{index}', 'rule_id': rule, 'category': 'network',
                             'severity': 'low', 'raw': {'reporting_mode': 'on_change', 'connections': []}}
                    self.assertTrue(sender.enqueue(copy.deepcopy(event)))
            self.assertEqual(sender._spool.counts()['pending'], 8)
            with patch.object(sender._spool, 'put', side_effect=OSError('disk full')):
                self.assertFalse(sender.enqueue(copy.deepcopy(event)))
            for index in range(2):
                sender._spool.put({'event_id': f'legacy-{index}', 'rule_id': 'NET_CONNECTION_SUMMARY',
                                   'severity': 'low', 'raw': {'connections': []}})
            sender._spool.close()
            restarted = AlertSender(config, state)
            self.assertEqual(restarted._spool.counts()['pending'], 9)
            self.assertEqual(sum(event['raw'].get('reporting_mode') == 'on_change'
                                 for event in restarted._spool.due()), 8)
            restarted._spool.close()


if __name__ == '__main__':
    unittest.main()
