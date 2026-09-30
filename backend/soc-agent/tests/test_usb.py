import importlib.util
import os
import sys
import unittest
from unittest.mock import patch


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, 'collectors', 'usb.py')
spec = importlib.util.spec_from_file_location('usb_collector', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Sender:
    def __init__(self, policies=None):
        self.events = []
        self.config = {'usb_policies': policies or []}

    def enqueue(self, event):
        self.events.append(event)


class UsbCollectorTests(unittest.TestCase):
    def test_file_policy_matches_extension_and_size(self):
        sender = Sender([
            {'id': 'one', 'name': 'Scripts', 'rule_type': 'block_extensions', 'values': ['ps1'], 'action': 'block'},
            {'id': 'two', 'name': 'Large', 'rule_type': 'max_file_size', 'max_bytes': 100, 'action': 'audit'},
        ])
        collector = module.USBCollector(sender)
        self.assertEqual(collector._matching_file_policy('/media/a/run.ps1', 10, False)['name'], 'Scripts')
        self.assertEqual(collector._matching_file_policy('/media/a/report.txt', 101, False)['name'], 'Large')

    def test_failed_block_is_reported_as_failure_not_audit(self):
        sender = Sender([{
            'id': 'block-vendor', 'name': 'Block vendor', 'rule_type': 'block_vendor',
            'values': ['evilcorp'], 'action': 'block',
        }])
        collector = module.USBCollector(sender)
        with patch.object(module, '_block_usb_storage', return_value=False):
            collector._apply_connection_policies('Drive', 'EvilCorp', 'serial', '1234', '5678', 'USB Storage', '', 'alice')
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'USB_POLICY_ENFORCEMENT_FAILED')
        self.assertEqual(sender.events[0]['enforcement_status'], 'failed')
        self.assertEqual(sender.events[0]['action_taken'], 'Enforcement Failed')
        self.assertFalse(sender.events[0]['blocked'])

    def test_successful_block_records_enforced_result(self):
        sender = Sender([{
            'id': 'block-serial', 'name': 'Block serial', 'rule_type': 'block_serials',
            'values': ['abc'], 'action': 'block',
        }])
        collector = module.USBCollector(sender)
        with patch.object(module, '_block_usb_storage', return_value=True):
            collector._apply_connection_policies('Drive', 'Vendor', 'ABC', '1234', '5678', 'USB Storage', '', 'alice')
        self.assertEqual(sender.events[0]['rule_id'], 'USB_POLICY_BLOCKED')
        self.assertEqual(sender.events[0]['enforcement_status'], 'enforced')
        self.assertTrue(sender.events[0]['blocked'])

    def test_known_rubber_ducky_signature_emits_dedicated_detection(self):
        sender = Sender()
        collector = module.USBCollector(sender)
        collector._detect_hid_threat('USB Rubber Ducky', 'Hak5', 'abc', '1234', '5678', 'HID Device')
        self.assertEqual(sender.events[0]['rule_id'], 'USB_RUBBER_DUCKY_SUSPECTED')
        self.assertEqual(sender.events[0]['severity'], 'critical')

    def test_normal_keyboard_is_not_reported_as_an_attack(self):
        sender = Sender()
        collector = module.USBCollector(sender)
        collector._detect_hid_threat('Standard Keyboard', 'Vendor', 'abc', '1234', '5678', 'HID Device')
        self.assertEqual(sender.events, [])


if __name__ == '__main__':
    unittest.main()
