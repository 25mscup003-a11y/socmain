import importlib.util
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, 'detectors', 'anomaly.py')
spec = importlib.util.spec_from_file_location('ueba_anomaly_detector', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class FakePsutil:
    @staticmethod
    def cpu_percent(interval=1):
        return 90

    @staticmethod
    def virtual_memory():
        return type('Memory', (), {'percent': 20})()

    @staticmethod
    def net_connections():
        return []


class UebaDetectorTests(unittest.TestCase):
    def test_baseline_deviation_emits_normalized_capability_11_event(self):
        sender = Sender()
        detector = module.AnomalyDetector(sender, {'ueba_anomaly_multiplier': 2})
        detector._cpu.extend([10] * 10)
        detector._mem.extend([20] * 10)
        detector._conns.extend([0] * 10)
        previous = module.__dict__.get('psutil')
        module.psutil = FakePsutil
        try:
            detector._check()
        finally:
            if previous is None:
                module.__dict__.pop('psutil', None)
            else:
                module.psutil = previous
        self.assertEqual(len(sender.events), 1)
        event = sender.events[0]
        self.assertEqual(event['capabilityId'], 11)
        self.assertEqual(event['behavior_category'], 'Endpoint Behavior')
        self.assertGreaterEqual(event['risk_score'], 60)
        self.assertIn('ueba_confidence', event)
        self.assertNotIn('password', event)
        self.assertNotIn('clipboard', event)

    def test_server_policy_can_disable_collection(self):
        sender = Sender()
        detector = module.AnomalyDetector(sender, {'ueba_monitoring_enabled': False})
        detector._check()
        self.assertEqual(sender.events, [])


if __name__ == '__main__':
    unittest.main()

