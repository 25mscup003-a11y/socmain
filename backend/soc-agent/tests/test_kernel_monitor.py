import os
import sys
import threading
import unittest
from queue import PriorityQueue
from unittest.mock import patch

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.kernel_monitor import KernelMonitorCollector
from core.sender import AlertSender


class Sender:
    def __init__(self): self.events = []
    def enqueue(self, event): self.events.append(event)


class Spool:
    def __init__(self): self.events = []
    def put(self, event, coalesce_key=''): self.events.append((event, coalesce_key))


class KernelMonitorTests(unittest.TestCase):
    def test_initial_inventory_and_driver_change_are_capability_19(self):
        sender = Sender()
        collector = KernelMonitorCollector(sender, {'kernel_monitor_interval_seconds': 300})
        collector._system = 'Linux'
        first = [{'id': 'ext4', 'name': 'ext4', 'path': '/lib/ext4.ko', 'signature_status': 'not_reported'}]
        second = first + [{'id': 'evil', 'name': 'evil', 'path': '/tmp/evil.ko', 'signature_status': 'unsigned'}]
        with patch('collectors.kernel_monitor.linux_modules', side_effect=[first, second]), patch('collectors.kernel_monitor.linux_posture', return_value={'platform': 'Linux'}):
            collector.collect_once()
            collector.collect_once()
        self.assertEqual(sender.events[0]['rule_id'], 'KERNEL_INVENTORY_SNAPSHOT')
        loaded = sender.events[-1]
        self.assertEqual(loaded['rule_id'], 'KERNEL_DRIVER_LOADED')
        self.assertEqual(loaded['capabilityId'], 19)
        self.assertEqual(loaded['severity'], 'high')
        self.assertEqual(loaded['driver_name'], 'evil')

    def test_configured_vulnerable_hash_generates_byovd(self):
        digest = 'a' * 64
        sender = Sender()
        collector = KernelMonitorCollector(sender, {'kernel_vulnerable_driver_hashes': [digest]})
        collector._emit_change('KERNEL_DRIVER_LOADED', {'name': 'bad.sys', 'sha256': digest, 'signature_status': 'valid'})
        self.assertEqual(sender.events[-1]['rule_id'], 'KERNEL_BYOVD_DETECTED')
        self.assertEqual(sender.events[-1]['severity'], 'critical')
        self.assertTrue(sender.events[-1]['vulnerable_driver'])

    def test_large_inventory_uses_one_snapshot_id_across_all_batches(self):
        sender = Sender()
        collector = KernelMonitorCollector(sender, {'kernel_monitor_interval_seconds': 300})
        collector._system = 'Linux'
        modules = [
            {'id': f'module_{index}', 'name': f'module_{index}', 'signature_status': 'not_reported'}
            for index in range(205)
        ]
        with patch('collectors.kernel_monitor.linux_modules', return_value=modules), patch(
            'collectors.kernel_monitor.linux_posture', return_value={'platform': 'Linux'}
        ):
            collector.collect_once()

        self.assertEqual(len(sender.events), 3)
        self.assertEqual([len(event['inventory_items']) for event in sender.events], [100, 100, 5])
        self.assertEqual([event['inventory_batch_index'] for event in sender.events], [1, 2, 3])
        self.assertEqual({event['inventory_batch_count'] for event in sender.events}, {3})
        snapshot_ids = {event['inventory_snapshot_id'] for event in sender.events}
        self.assertEqual(len(snapshot_ids), 1)
        self.assertRegex(next(iter(snapshot_ids)), r'^[a-f0-9]{32}$')

    def test_sender_never_deduplicates_kernel_inventory_batches(self):
        sender = AlertSender.__new__(AlertSender)
        sender._time_anomaly = None
        sender._geo = None
        sender._event_is_after_effective_install = lambda _timestamp: True
        sender._is_rate_limited = lambda _alert: self.fail('kernel inventory must bypass rate limiting')
        sender.state = type('State', (), {
            'is_duplicate': lambda *_args: self.fail('kernel inventory must bypass deduplication'),
            'count_file_event': lambda *_args: None,
            'count_usb_event': lambda *_args: None,
            'count_edr_event': lambda *_args: None,
            'count_malware': lambda *_args: None,
            'count_dropped': lambda *_args: None,
        })()
        sender._apply_vt_rules = lambda alert: alert
        sender._overload = True
        sender._spool = Spool()
        sender._q = PriorityQueue()
        sender._q_counter = 0
        sender._q_lock = threading.Lock()
        sender._queue_for_delivery = lambda *_args, **_kwargs: True
        sender._inventory_coalesce_key = 'process'
        sender._waf_status_coalesce_key = 'waf'
        sender._exposure_coalesce_key = 'exposure'
        sender._network_snapshot_coalesce_key = 'network'
        sender._dns_summary_coalesce_key = 'dns'
        sender._web_summary_coalesce_key = 'web'
        sender._browser_summary_coalesce_key = 'browser'
        sender._gps_location_coalesce_key = 'gps'

        for batch in range(1, 4):
            sender.enqueue({
                'event_id': f'event-{batch}', 'rule_id': 'KERNEL_INVENTORY_SNAPSHOT',
                'severity': 'low',
                'inventory_snapshot_id': 'one-snapshot', 'inventory_batch_index': batch,
            })

        self.assertEqual(len(sender._spool.events), 3)
        self.assertEqual([coalesce for _event, coalesce in sender._spool.events], ['', '', ''])


if __name__ == '__main__':
    unittest.main()
