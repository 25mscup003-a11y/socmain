import sys
import threading
import unittest
from pathlib import Path
from queue import PriorityQueue


AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from collectors.patch_inventory import PatchInventoryCollector
from core.sender import AlertSender


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class Spool:
    def __init__(self):
        self.events = []

    def put(self, event, coalesce_key=''):
        self.events.append((event, coalesce_key))


class PatchInventoryTests(unittest.TestCase):
    def test_inventory_is_batched_tagged_and_deduplicated(self):
        sender = Sender()
        collector = PatchInventoryCollector(sender, {})
        collector._inventory = lambda: (
            [{'name': f'package-{index}', 'version': '1.0'} for index in range(205)],
            [{'name': 'openssl', 'candidateVersion': '3.0.1', 'source': 'local-cache'}],
        )

        result = collector.collect_once()
        self.assertEqual(result, {'installed': 205, 'installed_patches': 0, 'pending': 1})
        self.assertEqual(len(sender.events), 5)
        self.assertEqual([len(event['inventory_items']) for event in sender.events[:3]], [100, 100, 5])
        self.assertTrue(all(event['capabilityId'] == 17 for event in sender.events))
        self.assertTrue(all(17 in event['capabilityIds'] for event in sender.events))

        collector.collect_once()
        self.assertEqual(len(sender.events), 5)

    def test_pending_inventory_change_emits_new_snapshot(self):
        sender = Sender()
        collector = PatchInventoryCollector(sender, {})
        inventories = [
            ([{'name': 'openssl', 'version': '3.0'}], []),
            ([{'name': 'openssl', 'version': '3.0'}], [{'name': 'openssl', 'candidateVersion': '3.1'}]),
        ]
        collector._inventory = lambda: inventories.pop(0)

        collector.collect_once()
        sender.events.clear()
        collector.collect_once()

        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'PATCH_PENDING_UPDATES')
        self.assertEqual(sender.events[0]['inventory_count'], 1)

    def test_windows_hotfixes_are_not_classified_as_pending_updates(self):
        sender = Sender()
        collector = PatchInventoryCollector(sender, {})
        collector._inventory = lambda: (
            [{'name': 'Example App', 'version': '1.0'}],
            [{'id': 'KB5000001', 'installedOn': '2026-08-01', 'description': 'Security Update'}],
            [{'name': 'Security Update', 'kb': 'KB5000002', 'source': 'windows-update'}],
        )

        result = collector.collect_once()
        by_type = {event['inventory_type']: event for event in sender.events}

        self.assertEqual(result, {'installed': 1, 'installed_patches': 1, 'pending': 1})
        self.assertEqual(by_type['installed_patches']['inventory_items'][0]['id'], 'KB5000001')
        self.assertEqual(by_type['pending_updates']['inventory_items'][0]['kb'], 'KB5000002')
        self.assertNotEqual(
            by_type['installed_patches']['inventory_snapshot_id'],
            by_type['pending_updates']['inventory_snapshot_id'],
        )

    def test_periodic_forced_collection_refreshes_unchanged_snapshot(self):
        sender = Sender()
        collector = PatchInventoryCollector(sender, {})
        collector._inventory = lambda: ([{'name': 'openssl', 'version': '3.0'}], [], [])

        collector.collect_once()
        initial_count = len(sender.events)
        collector.collect_once(force=True)

        self.assertEqual(len(sender.events), initial_count * 2)

    def test_sender_delivers_every_patch_inventory_batch_without_throttling(self):
        sender = AlertSender.__new__(AlertSender)
        sender._time_anomaly = None
        sender._geo = None
        sender._event_is_after_effective_install = lambda _timestamp: True
        sender._is_rate_limited = lambda _alert: self.fail('patch inventory must bypass rate limiting')
        sender.state = type('State', (), {
            'is_duplicate': lambda *_args: self.fail('patch inventory must bypass deduplication'),
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
                'event_id': f'patch-event-{batch}',
                'rule_id': 'PATCH_SOFTWARE_INVENTORY',
                'severity': 'low',
                'inventory_snapshot_id': 'one-patch-snapshot',
                'inventory_batch_index': batch,
            })

        self.assertEqual(len(sender._spool.events), 3)
        self.assertEqual([coalesce for _event, coalesce in sender._spool.events], ['', '', ''])


if __name__ == '__main__':
    unittest.main()
