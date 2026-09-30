import importlib.util
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(name, relative):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relative))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


files = load('system_change_files', os.path.join('collectors', 'file_monitor.py'))
assets = load('system_change_assets', os.path.join('collectors', 'process_assets.py'))


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class SystemChangeMonitoringTests(unittest.TestCase):
    def test_linux_identity_file_is_classified_as_system_change(self):
        self.assertEqual(files._system_change_category('/etc/passwd'), 'users_groups')
        self.assertEqual(files._system_change_category('/etc/ssh/sshd_config'), 'remote_access')

    def test_service_inventory_change_emits_capability_7_metadata(self):
        sender = Sender()
        collector = assets.ProcessAssetCollector(sender)
        collector._snapshots['service'] = {}
        collector._diff('service', [{'id': 'svc-1', 'name': 'svc-1', 'path': '/usr/bin/example'}])
        event = sender.events[0]
        self.assertIn(7, event['capabilityIds'])
        self.assertEqual(event['system_change_category'], 'services')
        self.assertEqual(event['baseline_status'], 'new')
        self.assertEqual(event['change_source'], 'native_inventory')


if __name__ == '__main__':
    unittest.main()
