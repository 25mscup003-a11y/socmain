import os
import sys
import tempfile
import unittest
from pathlib import Path


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from detectors.ransomware import RansomwareDetector


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class RansomwareDetectorTests(unittest.TestCase):
    def test_ransomware_note_and_custom_extension_emit_capability_27(self):
        sender = Sender()
        detector = RansomwareDetector(sender, {'ransomware_extensions': ['corpcrypt']})
        with tempfile.TemporaryDirectory() as directory:
            note = Path(directory) / 'HOW_TO_DECRYPT.txt'
            note.write_text('test', encoding='utf-8')
            encrypted = Path(directory) / 'report.docx.corpcrypt'
            encrypted.write_bytes(b'test')
            detector._handle_file_event('created', str(note))
            detector._handle_file_event('created', str(encrypted))

        self.assertEqual({event['rule_id'] for event in sender.events}, {
            'RANSOMWARE_NOTE', 'RANSOMWARE_EXTENSION',
        })
        for event in sender.events:
            self.assertEqual(event['capabilityId'], 27)
            self.assertIn(27, event['capabilityIds'])
            self.assertEqual(event['source'], 'ransomware')
        extension = next(event for event in sender.events if event['rule_id'] == 'RANSOMWARE_EXTENSION')
        self.assertEqual(extension['extension'], '.corpcrypt')

    def test_mass_encryption_includes_rates_and_affected_directory(self):
        sender = Sender()
        detector = RansomwareDetector(sender, {
            'ransomware_window_secs': 10,
            'mass_mod_threshold': 2,
            'entropy_file_trigger': 2,
        })
        now = __import__('time').time()
        detector._file_events.extend([
            (now, 'modified', '/data/a'), (now, 'renamed', '/data/b'),
        ])
        detector._entropy_hits.extend([
            (now, '/data/a', 7.8), (now, '/data/b', 7.9),
        ])
        detector._check_mass_operations()
        mass = next(event for event in sender.events if event['rule_id'] == 'RANSOMWARE_MASS_ENCRYPTION')
        self.assertEqual(mass['affected_files'], 2)
        self.assertEqual(mass['affected_directory'], '/data')
        self.assertEqual(mass['modified_files_per_second'], 0.1)
        self.assertEqual(mass['renamed_files_per_second'], 0.1)

    def test_executable_hashes_are_bounded_and_complete(self):
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'ransomware-test')
            handle.flush()
            hashes = RansomwareDetector._hash_executable(handle.name)
        self.assertEqual(len(hashes['executable_sha256']), 64)
        self.assertEqual(len(hashes['executable_md5']), 32)

    def test_disabled_runtime_policy_suppresses_alerts(self):
        sender = Sender()
        detector = RansomwareDetector(sender, {'ransomware_enabled': False})
        detector._enqueue({'rule_id': 'RANSOMWARE_NOTE', 'source': 'ransomware'})
        self.assertEqual(sender.events, [])

    def test_rule_override_controls_status_and_severity(self):
        sender = Sender()
        detector = RansomwareDetector(sender, {'ransomware_rule_overrides': {
            'RANSOMWARE_NOTE': {'enabled': False, 'severity': 'low'},
            'RANSOMWARE_EXTENSION': {'enabled': True, 'severity': 'high'},
        }})
        detector._enqueue({'rule_id': 'RANSOMWARE_NOTE', 'severity': 'critical'})
        detector._enqueue({'rule_id': 'RANSOMWARE_EXTENSION', 'severity': 'critical'})
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'RANSOMWARE_EXTENSION')
        self.assertEqual(sender.events[0]['severity'], 'high')

    def test_mass_event_includes_recent_matched_process_attribution(self):
        sender = Sender()
        detector = RansomwareDetector(sender, {
            'ransomware_window_secs': 10,
            'mass_mod_threshold': 2,
            'entropy_file_trigger': 2,
        })
        now = __import__('time').time()
        detector._recent_suspicious_process = (now, {
            'process_name': 'openssl', 'pid': 4242,
            'process_cmdline': 'openssl enc -aes-256-cbc -in data',
        })
        detector._file_events.extend([(now, 'modified', '/data/a'), (now, 'modified', '/data/b')])
        detector._entropy_hits.extend([(now, '/data/a', 7.8), (now, '/data/b', 7.9)])
        detector._check_mass_operations()
        event = next(item for item in sender.events if item['rule_id'] == 'RANSOMWARE_MASS_ENCRYPTION')
        self.assertEqual(event['process_name'], 'openssl')
        self.assertEqual(event['pid'], 4242)
        self.assertIn('openssl enc', event['process_cmdline'])


if __name__ == '__main__':
    unittest.main()
