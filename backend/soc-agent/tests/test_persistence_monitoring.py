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


assets = load('persistence_process_assets', os.path.join('collectors', 'process_assets.py'))
registry = load('persistence_registry_monitor', os.path.join('core', 'registry_monitor.py'))


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class PersistenceMonitoringTests(unittest.TestCase):
    def test_scheduled_task_change_is_capability_8_with_mitre_mapping(self):
        sender = Sender()
        collector = assets.ProcessAssetCollector(sender)
        collector._snapshots['scheduled_task'] = {}
        collector._diff('scheduled_task', [{'id': 'job-1', 'name': 'job-1'}])
        event = sender.events[0]
        self.assertEqual(event['capabilityId'], 8)
        self.assertIn(8, event['capabilityIds'])
        self.assertEqual(event['mitre_id'], 'T1053.003' if collector._system != 'Windows' else 'T1053.005')
        self.assertTrue(event['is_persistence'])

    def test_wmi_subscription_is_critical(self):
        sender = Sender()
        collector = assets.ProcessAssetCollector(sender)
        collector._snapshots['wmi_subscription'] = {}
        collector._diff('wmi_subscription', [{
            'id': 'CommandLineConsumer:test', 'name': 'test', 'location': 'root/subscription',
            'command': 'powershell.exe -EncodedCommand ZQB2AGkAbAA=',
        }])
        event = sender.events[0]
        self.assertEqual(event['severity'], 'critical')
        self.assertEqual(event['mitre_id'], 'T1546.003')

    def test_known_system_task_is_not_promoted_to_high_severity(self):
        sender = Sender()
        collector = assets.ProcessAssetCollector(sender)
        risk, severity, indicators = collector._persistence_assessment(
            'scheduled_task', {'name': 'Microsoft Update', 'command': r'C:\\Windows\\System32\\UsoClient.exe'},
        )
        self.assertLess(risk, 40)
        self.assertEqual(severity, 'low')
        self.assertEqual(indicators, [])

    def test_registry_change_routes_to_registry_and_persistence_capabilities(self):
        monitor = registry.RegistryMonitor()
        findings = monitor._diff(
            {'HKCU\\Run': {}},
            {'HKCU\\Run': {'UnknownUpdater': r'C:\\Temp\\unknown.exe'}},
        )
        self.assertEqual(findings[0]['mitre'], 'T1547.001')
        self.assertEqual(findings[0]['severity'], 'critical')


if __name__ == '__main__':
    unittest.main()
