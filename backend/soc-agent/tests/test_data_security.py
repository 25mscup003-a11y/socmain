import importlib.util
import os
import sys
import unittest
import tempfile


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, 'collectors', 'data_security.py')
spec = importlib.util.spec_from_file_location('data_security_collector', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

FILE_MONITOR_PATH = os.path.join(ROOT, 'collectors', 'file_monitor.py')
file_spec = importlib.util.spec_from_file_location('data_security_file_monitor', FILE_MONITOR_PATH)
file_monitor = importlib.util.module_from_spec(file_spec)
sys.modules[file_spec.name] = file_monitor
file_spec.loader.exec_module(file_monitor)


class DataSecurityCollectorTests(unittest.TestCase):
    def test_detects_database_export(self):
        finding = module._match_process('pg_dump', 'pg_dump finance -f /tmp/finance.dump')
        self.assertEqual(finding['rule_id'], 'DATA_DATABASE_EXPORT')
        self.assertEqual(finding['data_classification'], 'Restricted')

    def test_detects_cloud_upload(self):
        finding = module._match_process('rclone', 'rclone copy /srv/hr remote:archive')
        self.assertEqual(finding['rule_id'], 'DATA_CLOUD_UPLOAD')
        self.assertEqual(finding['transfer_channel'], 'cloud')

    def test_detects_scp_transfer(self):
        finding = module._match_process('scp', 'scp /srv/confidential/report.csv user@example:/tmp/')
        self.assertEqual(finding['rule_id'], 'DATA_NETWORK_TRANSFER')

    def test_benign_process_is_ignored(self):
        self.assertIsNone(module._match_process('python3', 'python3 worker.py'))

    def test_emitted_event_contains_metadata_not_content(self):
        class Sender:
            def __init__(self): self.events = []
            def enqueue(self, event): self.events.append(event)
        sender = Sender()
        collector = module.DataSecurityCollector(sender, {})
        collector._emit(rule_id='DATA_ARCHIVE_STAGING', data_event_type='archive_staging', severity='high', risk_score=78)
        self.assertEqual(sender.events[0]['capabilityIds'], [11, 12])
        self.assertNotIn('file_content', sender.events[0])
        self.assertNotIn('clipboard_content', sender.events[0])

    def test_local_dlp_returns_categories_and_count_not_values(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as handle:
            handle.write('PAN ABCDE1234F and AWS key AKIAABCDEFGHIJKLMNOP')
            path = handle.name
        try:
            result = file_monitor._dlp_metadata(path)
            self.assertEqual(result['dlp_match_count'], 2)
            self.assertIn(result['dlp_pattern'], ('PAN', 'AWS_ACCESS_KEY'))
            self.assertNotIn('ABCDE1234F', str(result))
            self.assertNotIn('AKIAABCDEFGHIJKLMNOP', str(result))
        finally:
            os.unlink(path)


if __name__ == '__main__':
    unittest.main()
