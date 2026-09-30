import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.hash_signature import HashSignatureEngine


class HashSignatureEngineTests(unittest.TestCase):
    def test_sha256_sha1_md5_and_metadata_cache(self):
        engine = HashSignatureEngine(max_entries=10)
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'AJNAT EDR')
            handle.flush()
            first = engine.inspect(handle.name, include_sha1=True, include_md5=True, signature=False)
            second = engine.inspect(handle.name, include_sha1=True, include_md5=True, signature=False)
        self.assertEqual(len(first['sha256']), 64)
        self.assertEqual(len(first['sha1']), 40)
        self.assertEqual(len(first['md5']), 32)
        self.assertFalse(first['hashCached'])
        self.assertTrue(second['hashCached'])

    def test_modification_invalidates_cache(self):
        engine = HashSignatureEngine(max_entries=10)
        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b'one')
            handle.flush()
            first = engine.inspect(handle.name, signature=False)
            handle.seek(0)
            handle.write(b'two-two')
            handle.truncate()
            handle.flush()
            second = engine.inspect(handle.name, signature=False)
        self.assertNotEqual(first['sha256'], second['sha256'])
        self.assertFalse(second['hashCached'])

    @patch('collectors.hash_signature.subprocess.run')
    def test_macos_codesign_reports_valid_identity(self, run):
        run.side_effect = [
            SimpleNamespace(returncode=0, stdout='', stderr='valid on disk'),
            SimpleNamespace(returncode=0, stdout='', stderr='Authority=Example Corp\nTeamIdentifier=TEAM123'),
        ]
        result = HashSignatureEngine._macos_codesign_status('/Applications/example')
        self.assertEqual(result['signatureStatus'], 'VALID')
        self.assertEqual(result['trustStatus'], 'TRUSTED')
        self.assertEqual(result['publisher'], 'Example Corp')
        self.assertEqual(result['teamIdentifier'], 'TEAM123')

    @patch('collectors.hash_signature.subprocess.run')
    def test_macos_codesign_distinguishes_unsigned(self, run):
        run.side_effect = [
            SimpleNamespace(returncode=1, stdout='', stderr='code object is not signed at all'),
            SimpleNamespace(returncode=1, stdout='', stderr='code object is not signed at all'),
        ]
        result = HashSignatureEngine._macos_codesign_status('/tmp/example')
        self.assertEqual(result['signatureStatus'], 'UNSIGNED')

    @patch('builtins.open', side_effect=OSError('no metadata'))
    @patch('collectors.hash_signature.subprocess.run')
    @patch('collectors.hash_signature.shutil.which')
    def test_linux_verification_does_not_scan_an_entire_package(self, which, run, _open):
        which.side_effect = lambda name: '/usr/bin/dpkg-query' if name == 'dpkg-query' else None
        run.return_value = SimpleNamespace(returncode=0, stdout='example: /usr/bin/example\n', stderr='')
        result = HashSignatureEngine._linux_package_status('/usr/bin/example')
        self.assertEqual(result['packageVerificationStatus'], 'PACKAGE_OWNED_UNVERIFIED')
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0][:2], ['dpkg-query', '-S'])


if __name__ == '__main__':
    unittest.main()
