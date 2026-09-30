import importlib.util
import os
import unittest
from unittest.mock import patch


MODULE_PATH = os.path.join(os.path.dirname(__file__), '..', 'core', 'memory_scanner.py')
SPEC = importlib.util.spec_from_file_location('memory_activity_scanner', MODULE_PATH)
memory_scanner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(memory_scanner)


class MemoryInfo:
    rss = 512 * 1024 * 1024
    vms = 1024 * 1024 * 1024
    shared = 64 * 1024 * 1024


class Process:
    info = {
        'pid': 1200, 'ppid': 100, 'name': 'worker', 'username': 'analyst',
        'exe': '/usr/bin/worker', 'memory_percent': 12.5, 'memory_info': MemoryInfo(),
    }


class MemoryActivityScannerTests(unittest.TestCase):
    def setUp(self):
        self.scanner = memory_scanner.MemoryScanner(config={'memory_scanner_top_n': 5})

    def test_process_inventory_is_normalized_as_metric_not_alert(self):
        fake_psutil = type('Psutil', (), {'process_iter': staticmethod(lambda fields: [Process()])})
        with patch.object(memory_scanner, 'HAS_PSUTIL', True), patch.object(memory_scanner, 'psutil', fake_psutil):
            rows = self.scanner._scan_top_memory()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['capabilityId'], 5)
        self.assertEqual(rows[0]['memory_metric_type'], 'process')
        self.assertEqual(rows[0]['eventType'], 'memory.metric')
        self.assertEqual(rows[0]['process_rss_bytes'], 512 * 1024 * 1024)
        self.assertFalse(rows[0]['actionable'])

    def test_host_metric_is_emitted_even_without_pressure(self):
        vm = type('VM', (), {'total': 16 * 1024**3, 'used': 8 * 1024**3, 'available': 8 * 1024**3, 'percent': 50.0})()
        swap = type('Swap', (), {'total': 2 * 1024**3, 'used': 0, 'percent': 0.0})()
        fake_psutil = type('Psutil', (), {
            'virtual_memory': staticmethod(lambda: vm),
            'swap_memory': staticmethod(lambda: swap),
        })
        with patch.object(memory_scanner, 'HAS_PSUTIL', True), patch.object(memory_scanner, 'psutil', fake_psutil):
            rows = self.scanner._scan_host_memory()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['memory_metric_type'], 'host')
        self.assertEqual(rows[0]['memory_total_bytes'], 16 * 1024**3)
        self.assertEqual(rows[0]['memory_pressure'], 50.0)

    def test_pressure_emits_metric_and_detection(self):
        vm = type('VM', (), {'total': 16 * 1024**3, 'used': 15 * 1024**3, 'available': 1024**3, 'percent': 94.0})()
        swap = type('Swap', (), {'total': 2 * 1024**3, 'used': 1024**3, 'percent': 50.0})()
        fake_psutil = type('Psutil', (), {
            'virtual_memory': staticmethod(lambda: vm),
            'swap_memory': staticmethod(lambda: swap),
        })
        with patch.object(memory_scanner, 'HAS_PSUTIL', True), patch.object(memory_scanner, 'psutil', fake_psutil):
            rows = self.scanner._scan_host_memory()
        self.assertEqual([row['rule_id'] for row in rows], ['MEM_HOST_METRIC', 'MEM_HOST_PRESSURE'])
        self.assertIn(5, rows[1]['capabilityIds'])

    def test_threat_finding_keeps_capability_and_mitre(self):
        row = self.scanner._finding(rule_id='MEM_RWX_REGION', sub='RWX Memory', event='RWX Memory Region', severity='high', risk=80, mitre='T1055', name='worker', pid=12)
        self.assertEqual(row['capabilityId'], 5)
        self.assertEqual(row['mitreId'], 'T1055')
        self.assertEqual(row['riskScore'], 80)


if __name__ == '__main__':
    unittest.main()
