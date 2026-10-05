import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.file_open_protection import FileOpenProtection, _kernel_group, _METADATA, _RESPONSE, _OPEN_PERM, _ALLOW, _DENY
from core.heartbeat import HeartbeatService, _SECURITY_LOCKDOWN


class FileOpenProtectionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='ajnat-file-open-test-')
        self.root = Path(self.directory.name)
        self.source = self.root / 'sample.py'
        self.original = b'VALUE = "isolated fixture"\n'
        self.source.write_bytes(self.original)
        self.source.chmod(0o600)
        (self.root / 'integrity_manifest.json').write_text(json.dumps({
            'files': {'sample.py': hashlib.sha256(self.original).hexdigest()},
        }))
        self.guard = FileOpenProtection(self.root)

    def tearDown(self):
        self.guard.stop()
        self.directory.cleanup()
        _SECURITY_LOCKDOWN.clear()

    def arm_handler(self):
        self.guard._inventory = self.guard._protected_inventory()
        self.guard._state = 'enforced'

    def decision(self, path=None, pid=None, flags=os.O_RDWR):
        fd = os.open(path or self.source, flags)
        try:
            return self.guard._respond_to_open(fd, os.getpid() + 100000 if pid is None else pid)
        finally:
            os.close(fd)

    def test_external_open_clears_only_exact_source_and_denies_request(self):
        other = self.root / 'unrelated.txt'
        other.write_text('preserve')
        self.arm_handler()
        self.assertEqual(self.decision(), _DENY)
        self.assertEqual(self.source.read_bytes(), b'')
        self.assertEqual(other.read_text(), 'preserve')
        finding = self.guard.findings()[0]
        self.assertEqual(finding['type'], 'source_cleared_on_open')
        self.assertEqual(finding['file'], 'sample.py')

    def test_agent_reads_never_clear_data(self):
        self.arm_handler()
        self.assertEqual(self.decision(pid=os.getpid()), _ALLOW)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.guard.findings(), [])

    def test_unknown_reader_does_not_clear_data_and_records_error(self):
        self.arm_handler()
        self.assertEqual(self.decision(pid=0), _DENY)
        self.assertEqual(self.source.read_bytes(), self.original)
        self.assertEqual(self.guard.report({})['state'], 'error')

    def test_unprotected_inode_is_never_cleared(self):
        other = self.root / 'config.json'
        other.write_text('preserve')
        self.arm_handler()
        self.assertEqual(self.decision(other), _DENY)
        self.assertEqual(other.read_text(), 'preserve')

    def test_replaced_path_does_not_clear_original_or_replacement(self):
        self.arm_handler()
        fd = os.open(self.source, os.O_RDWR)
        old = self.root / 'old.py'
        self.source.rename(old)
        self.source.write_text('replacement')
        try:
            self.assertEqual(self.guard._respond_to_open(fd, os.getpid() + 100000), _DENY)
        finally:
            os.close(fd)
        self.assertEqual(old.read_bytes(), self.original)
        self.assertEqual(self.source.read_text(), 'replacement')

    def test_hardlink_created_after_arming_prevents_clearing(self):
        self.arm_handler()
        other = self.root / 'linked.py'
        os.link(self.source, other)
        self.assertEqual(self.decision(), _DENY)
        self.assertEqual(other.read_bytes(), self.original)

    def test_tampered_symlinked_and_writable_inventory_is_rejected(self):
        self.source.write_text('modified')
        with self.assertRaisesRegex(ValueError, 'manifest'):
            self.guard._protected_inventory()
        self.source.write_bytes(self.original)
        self.source.chmod(0o666)
        with self.assertRaisesRegex(ValueError, 'non-writable'):
            self.guard._protected_inventory()
        self.source.chmod(0o600)
        other = self.root / 'other.py'
        self.source.rename(other)
        self.source.symlink_to(other)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            self.guard._protected_inventory()
        self.assertEqual(other.read_bytes(), self.original)

    def test_no_permissions_means_unsupported_without_a_fallback(self):
        with patch('core.file_open_protection._kernel_group', side_effect=PermissionError('CAP_SYS_ADMIN unavailable')):
            self.guard.apply({'self_protection': True, 'erase_code_on_open': True})
        self.assertEqual(self.guard.report({'erase_code_on_open': True})['state'], 'unsupported')
        self.assertIsNone(self.guard._thread)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_default_off_master_off_and_maintenance_never_arm(self):
        self.guard._supported = True
        for config in ({}, {'erase_code_on_open': True, 'self_protection': False}, {'erase_code_on_open': True, 'maintenance_mode': True}):
            with self.subTest(config=config), patch.object(self.guard, '_protected_inventory') as inventory:
                self.guard.apply(config)
                inventory.assert_not_called()
                self.assertEqual(self.guard.report(config)['state'], 'disabled')
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_clearing_failure_denies_open_reports_error_and_disarms_clearing(self):
        self.arm_handler()
        self.assertEqual(self.decision(flags=os.O_RDONLY), _DENY)
        self.assertEqual(self.guard.report({})['state'], 'error')
        self.assertEqual(self.decision(), _DENY)
        self.assertEqual(self.source.read_bytes(), self.original)

    def test_permission_event_loop_responds_closes_event_fd_and_stops_for_update(self):
        self.guard._supported = True
        listener, kernel = socket.socketpair(type=socket.SOCK_SEQPACKET)
        kernel.settimeout(3)
        library = Mock()
        library.fanotify_mark.return_value = 0
        with kernel, patch('core.file_open_protection._kernel_group', return_value=(library, listener.detach())):
            self.guard.apply({'erase_code_on_open': True})
            self.assertEqual(self.guard.report({})['state'], 'enforced')
            fd = os.open(self.source, os.O_RDWR)
            kernel.send(_METADATA.pack(24, 3, 0, 24, _OPEN_PERM, fd, os.getpid() + 100000))
            self.assertEqual(_RESPONSE.unpack(kernel.recv(8)), (fd, _DENY))
            self.guard.suspend_for_update()
            with self.assertRaises(OSError):
                os.fstat(fd)
            self.assertIsNone(self.guard._thread)
            self.guard.apply({'erase_code_on_open': True})
            self.assertEqual(self.guard.report({})['state'], 'disabled')
        self.assertEqual(self.source.read_bytes(), b'')

    def test_open_event_reaches_heartbeat_findings_and_lockdown_even_with_cached_scan(self):
        class Config(dict):
            def update_runtime(self, changes, **kwargs):
                self.update(changes)
        heartbeat = HeartbeatService(Config(erase_code_on_open=True))
        heartbeat._runtime_security.file_open = self.guard
        self.arm_handler()
        self.decision()
        with patch('core.heartbeat.collect_security_report', return_value={'integrityStatus': 'verified', 'findings': []}), patch('core.heartbeat.certificate_status', return_value={}):
            report = heartbeat._refresh_security_report()
        self.assertEqual(report['integrityStatus'], 'mismatch')
        self.assertTrue(report['lockdownActive'])
        self.assertEqual(report['findings'][0]['type'], 'source_cleared_on_open')
        self.assertTrue(report['controls']['selfProtection']['fileOpen']['enabled'])

    def test_update_suspends_before_installer_and_only_rearms_when_launch_fails(self):
        heartbeat = HeartbeatService({})
        for fails in (False, True):
            with self.subTest(fails=fails), tempfile.NamedTemporaryFile(dir=self.root, delete=False) as artifact:
                sequence = []
                def install(*args):
                    sequence.append('install')
                    if fails:
                        raise OSError('installer unavailable')
                guard = heartbeat._runtime_security.file_open
                with patch.object(heartbeat, '_download_update_package', return_value=artifact.name), patch.object(heartbeat, '_report_update_status'), patch.object(heartbeat, '_install_update_package', side_effect=install), patch.object(guard, 'suspend_for_update', side_effect=lambda: sequence.append('suspend')), patch.object(guard, 'update_failed', side_effect=lambda config: sequence.append('rearm')):
                    heartbeat._perform_self_update({'type': 'deb', 'targetVersion': '0.1.13', 'id': 'test-update'})
                self.assertEqual(sequence, ['suspend', 'install', 'rearm'] if fails else ['suspend', 'install'])

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux kernel integration')
    def test_real_kernel_open_in_isolated_fixture_when_privileged(self):
        try:
            _, fd = _kernel_group()
            os.close(fd)
        except OSError as error:
            self.skipTest(str(error))
        import subprocess
        self.guard.apply({'erase_code_on_open': True})
        self.assertEqual(self.guard.report({})['state'], 'enforced')
        # Current-process integrity reads are allowed; a separate process is denied.
        self.assertEqual(self.source.read_bytes(), self.original)
        child = subprocess.run([sys.executable, '-c', 'import pathlib,sys; pathlib.Path(sys.argv[1]).read_bytes()', str(self.source)], capture_output=True, timeout=5)
        self.assertNotEqual(child.returncode, 0)
        self.assertEqual(self.source.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
