import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'soc-agent'))
from core.ids import IDSModule


class _Sender:
    def enqueue(self, _event):
        return None


class IDSNoiseSuppressionTests(unittest.TestCase):
    def test_same_fingerprint_uses_independent_cooldown(self):
        module = IDSModule(_Sender(), config={'ids_alert_cooldown_seconds': 900})
        self.assertTrue(module._should_emit('same-alert'))
        self.assertFalse(module._should_emit('same-alert'))
        self.assertTrue(module._should_emit('new-alert'))

        module._alerted['same-alert'] = time.monotonic() - 901
        self.assertTrue(module._should_emit('same-alert'))

    def test_thresholds_are_configurable_and_safely_bounded(self):
        module = IDSModule(_Sender(), config={
            'ids_port_scan_threshold': 45,
            'ids_brute_force_threshold': 25,
            'ids_alert_cooldown_seconds': 1,
        })
        self.assertEqual(module._port_scan_threshold, 45)
        self.assertEqual(module._brute_force_threshold, 25)
        self.assertEqual(module._alert_cooldown, 60)


if __name__ == '__main__':
    unittest.main()
