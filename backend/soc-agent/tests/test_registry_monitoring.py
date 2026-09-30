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


registry = load('capability_6_registry_monitor', os.path.join('core', 'registry_monitor.py'))
files = load('capability_6_file_monitor', os.path.join('collectors', 'file_monitor.py'))
windows_events = load('capability_6_windows_events', os.path.join('collectors', 'windows_process_events.py'))


class RegistryConfigurationMonitoringTests(unittest.TestCase):
    def test_custom_registry_paths_are_bounded_and_normalized(self):
        monitor = registry.RegistryMonitor(config={
            'registry_monitor_paths': [
                r'HKEY_LOCAL_MACHINE\SOFTWARE\AJNAT',
                {'hive': 'HKCU', 'path': r'SOFTWARE\AJNAT\User'},
                r'HKCR\Ignored',
            ],
        })
        paths = monitor._watch_keys()
        self.assertIn((r'SOFTWARE\AJNAT', 'HKLM'), paths)
        self.assertIn((r'SOFTWARE\AJNAT\User', 'HKCU'), paths)
        self.assertNotIn((r'Ignored', 'HKCR'), paths)
        self.assertLessEqual(len(paths), 72)

    def test_registry_diff_reports_create_modify_and_delete(self):
        monitor = registry.RegistryMonitor()
        old = {'HKCU\\Run': {
            'Modified': {'data': 'old.exe', 'type': 1},
            'Deleted': {'data': 'removed.exe', 'type': 1},
        }}
        new = {'HKCU\\Run': {
            'Modified': {'data': r'C:\\Temp\\new.exe', 'type': 1},
            'Created': {'data': 'created.exe', 'type': 1},
        }}
        findings = monitor._diff(old, new)
        self.assertEqual({item['operation'] for item in findings}, {'create', 'modify', 'delete'})
        self.assertTrue(all(item['configuration_category'] == 'persistence' for item in findings))
        self.assertTrue(all(item['mitre'] == 'T1547.001' for item in findings))

    def test_linux_and_solaris_critical_paths_are_capability_6_configuration(self):
        self.assertTrue(files._is_configuration_path('/etc/ssh/sshd_config'))
        self.assertTrue(files._is_configuration_path('/etc/security/policy.conf'))
        self.assertEqual(files._configuration_category('/etc/sudoers'), 'user_authentication')
        self.assertEqual(files._configuration_category('/etc/systemd/system/example.service'), 'persistence')

    def test_sysmon_registry_event_preserves_exact_process_attribution(self):
        findings = windows_events.classify_windows_event(
            'Microsoft-Windows-Sysmon/Operational',
            {
                'event_id': 13,
                'record_id': 42,
                'computer': 'test-host',
                'timestamp': '2026-09-01T00:00:00Z',
                'data': {
                    'Image': r'C:\Windows\System32\reg.exe',
                    'ProcessId': '123',
                    'User': 'TEST\\analyst',
                    'TargetObject': r'HKLM\Software\Microsoft\Windows\CurrentVersion\Run\Updater',
                    'Details': r'C:\Program Files\Vendor\updater.exe',
                },
            },
        )
        self.assertEqual(len(findings), 1)
        event = findings[0]
        self.assertIn(6, event['capabilityIds'])
        self.assertIn(8, event['capabilityIds'])
        self.assertEqual(event['process_attribution'], 'sysmon_exact')
        self.assertEqual(event['configuration_category'], 'persistence')


if __name__ == '__main__':
    unittest.main()
