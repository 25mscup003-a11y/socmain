import os
import sys
import unittest
from unittest.mock import patch

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from core.heartbeat import _module_status, _sandbox_vm_status


class Config:
    def __init__(self, values=None):
        self.values = values or {}

    def get(self, key, default=None):
        return self.values.get(key, default)


class SandboxStatusTests(unittest.TestCase):
    @patch('core.heartbeat._advanced_process_sensor_status', return_value={})
    @patch('core.heartbeat._sensor_executable_available', return_value=False)
    def test_reports_real_runtime_state_without_endpoint_detonation(self, _sensor, _advanced):
        thread = lambda name: type('ThreadState', (), {'name': name, 'is_alive': lambda self: True})()
        with patch('core.heartbeat.threading.enumerate', return_value=[thread('file-monitor'), thread('yara-scanner')]):
            active = _module_status(Config())
            self.assertTrue(active['sandboxAnalysisEnabled'])
            self.assertEqual(active['sandboxAnalysisStatus']['collection'], 'active')
            self.assertEqual(active['sandboxAnalysisStatus']['detonation'], 'not-applicable')

        with patch('core.heartbeat.threading.enumerate', return_value=[thread('file-monitor')]):
            degraded = _module_status(Config())
            self.assertFalse(degraded['sandboxAnalysisEnabled'])
            self.assertEqual(degraded['sandboxAnalysisStatus']['collection'], 'degraded')

        disabled = _module_status(Config({'sandbox_analysis_enabled': False}))
        self.assertFalse(disabled['sandboxAnalysisEnabled'])
        self.assertEqual(disabled['sandboxAnalysisStatus']['collection'], 'disabled')

    def test_detects_only_active_vm_guest_processes(self):
        processes = [
            type('Process', (), {'info': {'pid': 101, 'name': 'vmware-vmx.exe', 'cmdline': ['vmware-vmx.exe', 'C:\\VMs\\Finance.vmx']}})(),
            type('Process', (), {'info': {'pid': 202, 'name': 'VirtualBox.exe', 'cmdline': ['VirtualBox.exe']}})(),
            type('Process', (), {'info': {'pid': 303, 'name': 'qemu-system-x86_64', 'cmdline': ['qemu-system-x86_64', '-name', 'ubuntu-prod']}})(),
        ]
        with patch('psutil.process_iter', return_value=processes):
            status = _sandbox_vm_status()
        self.assertEqual(status['state'], 'running')
        self.assertTrue(status['vmRunning'])
        self.assertEqual(status['vmCount'], 2)
        self.assertEqual(status['providers'], ['KVM/QEMU', 'VMware'])
        self.assertEqual(status['instances'][1]['name'], 'ubuntu-prod')

    def test_reports_idle_when_no_guest_vm_process_exists(self):
        process = type('Process', (), {'info': {'pid': 10, 'name': 'explorer.exe', 'cmdline': ['explorer.exe']}})()
        with patch('psutil.process_iter', return_value=[process]):
            status = _sandbox_vm_status()
        self.assertEqual(status['state'], 'idle')
        self.assertFalse(status['vmRunning'])
        self.assertEqual(status['vmCount'], 0)


if __name__ == '__main__':
    unittest.main()
