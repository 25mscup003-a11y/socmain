import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from core.self_protection import collect_security_report


def manifest_for(files):
    hashes = {name: hashlib.sha256(content).hexdigest() for name, content in files.items()}
    aggregate = hashlib.sha256()
    for name in sorted(hashes):
        aggregate.update(f'{name}\0{hashes[name]}\n'.encode('utf-8'))
    return {'version': 1, 'algorithm': 'sha256', 'files': hashes, 'fleetSha256': aggregate.hexdigest()}


class SelfProtectionTests(unittest.TestCase):
    @patch('core.self_protection._running_analysis_tools', return_value=[])
    @patch('core.self_protection._debugger_attached', return_value=[])
    def test_valid_manifest_is_verified(self, _debugger, _tools):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b'print("trusted")\n'
            (root / 'agent.py').write_bytes(content)
            (root / 'agent.py').chmod(0o644)
            (root / 'integrity_manifest.json').write_text(
                json.dumps(manifest_for({'agent.py': content})), encoding='utf-8',
            )
            report = collect_security_report(root)
            self.assertEqual(report['integrityStatus'], 'verified')
            self.assertEqual(report['findings'], [])

    @patch('core.self_protection._running_analysis_tools', return_value=[])
    @patch('core.self_protection._debugger_attached', return_value=[])
    def test_installer_virtualenv_is_not_protected_agent_code(self, _debugger, _tools):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b'print("trusted")\n'
            (root / 'agent.py').write_bytes(content)
            (root / 'agent.py').chmod(0o644)
            dependency = root / 'venv' / 'lib' / 'python3.13' / 'site-packages' / 'dependency.py'
            dependency.parent.mkdir(parents=True)
            dependency.write_text('pass\n', encoding='utf-8')
            (root / 'integrity_manifest.json').write_text(
                json.dumps(manifest_for({'agent.py': content})), encoding='utf-8',
            )

            report = collect_security_report(root)

            self.assertEqual(report['integrityStatus'], 'verified')
            self.assertEqual(report['findings'], [])

    @patch('core.self_protection._running_analysis_tools', return_value=[])
    @patch('core.self_protection._debugger_attached', return_value=[])
    def test_unmanifested_python_outside_virtualenv_is_reported(self, _debugger, _tools):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            content = b'print("trusted")\n'
            (root / 'agent.py').write_bytes(content)
            (root / 'agent.py').chmod(0o644)
            unexpected = root / 'plugins' / 'injected.py'
            unexpected.parent.mkdir()
            unexpected.write_text('pass\n', encoding='utf-8')
            (root / 'integrity_manifest.json').write_text(
                json.dumps(manifest_for({'agent.py': content})), encoding='utf-8',
            )

            report = collect_security_report(root)

            self.assertEqual(report['integrityStatus'], 'mismatch')
            self.assertTrue(any(
                item['type'] == 'unexpected_file' and item['file'] == 'plugins/injected.py'
                for item in report['findings']
            ))

    @patch('core.self_protection._running_analysis_tools', return_value=[])
    @patch('core.self_protection._debugger_attached', return_value=[])
    def test_modified_code_is_reported(self, _debugger, _tools):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = b'print("trusted")\n'
            (root / 'agent.py').write_bytes(b'print("tampered")\n')
            (root / 'agent.py').chmod(0o644)
            (root / 'integrity_manifest.json').write_text(
                json.dumps(manifest_for({'agent.py': original})), encoding='utf-8',
            )
            report = collect_security_report(root)
            self.assertEqual(report['integrityStatus'], 'mismatch')
            self.assertTrue(any(item['type'] == 'hash_mismatch' for item in report['findings']))

    @patch('core.self_protection._running_analysis_tools', return_value=[])
    @patch('core.self_protection._debugger_attached', return_value=[])
    def test_missing_manifest_is_never_verified(self, _debugger, _tools):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'agent.py').write_text('pass\n', encoding='utf-8')
            (root / 'agent.py').chmod(0o644)
            report = collect_security_report(root)
            self.assertEqual(report['integrityStatus'], 'missing')


if __name__ == '__main__':
    unittest.main()
