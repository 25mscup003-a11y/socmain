import unittest
from types import SimpleNamespace
from unittest.mock import patch
from core import fw_backend, firewall


def result(code=0, error=''):
    return SimpleNamespace(returncode=code, stdout='', stderr=error)


class IsolationBackendTests(unittest.TestCase):
    @patch.object(fw_backend, 'SYSTEM', 'Linux')
    @patch.object(fw_backend, '_have', return_value=True)
    @patch.object(fw_backend, '_run')
    def test_isolation_atomically_replaces_old_rules_and_blocks_existing_sessions(self, run, have):
        run.return_value = result()
        fw_backend.isolate('192.0.2.5', 443)
        script = run.call_args.kwargs['stdin']
        self.assertTrue(script.startswith('delete table inet soc_isolation\n'))
        self.assertNotIn('ct state established', script)
        self.assertIn('ip daddr 192.0.2.5 tcp dport 443 accept', script)
        self.assertEqual(script.count('    drop'), 2)
        self.assertNotIn(['nft', 'delete', 'table', 'inet', 'soc_isolation'], [call.args[0] for call in run.call_args_list])

    @patch.object(fw_backend, 'SYSTEM', 'Linux')
    @patch.object(fw_backend, '_have', return_value=True)
    @patch.object(fw_backend, '_run', return_value=result(1, 'Operation not permitted'))
    def test_restore_does_not_ack_permission_failure(self, run, have):
        with self.assertRaisesRegex(RuntimeError, 'reconnect failed'):
            fw_backend.restore()
        self.assertFalse(fw_backend._nft_set_element('delete', 'blk_in4', '203.0.113.9'))
        self.assertFalse(fw_backend._nft_set_element('add', 'blk_in4', '203.0.113.9'))

    @patch.object(fw_backend, 'SYSTEM', 'Linux')
    @patch.object(fw_backend, 'linux_backend', return_value='nft')
    @patch.object(fw_backend, '_run')
    def test_unblock_waits_for_success_from_both_directions(self, run, backend):
        run.side_effect = [result(), result(), result(1, 'Operation not permitted')]
        self.assertFalse(fw_backend.unblock_ip('203.0.113.9'))
        self.assertEqual(run.call_count, 3)

    @patch.object(fw_backend, 'SYSTEM', 'Linux')
    @patch.object(fw_backend, '_have', return_value=True)
    @patch.object(fw_backend, '_run', return_value=result(1, 'No such file or directory'))
    def test_restore_missing_isolation_is_idempotent(self, run, have):
        fw_backend.restore()

    @patch.object(fw_backend, 'unblock_ip', return_value=False)
    def test_firewall_module_retains_rules_on_failed_unblock(self, unblock):
        module = firewall.FirewallModule.__new__(firewall.FirewallModule)
        module._rules = [{'action': 'block_ip', 'ip': '203.0.113.9'}]
        self.assertFalse(module.unblock_ip('203.0.113.9'))
        self.assertEqual(len(module._rules), 1)

    @patch.object(fw_backend, 'SYSTEM', 'Windows')
    @patch.object(fw_backend, '_run')
    def test_windows_uses_verified_snapshot_restore_instead_of_default_policy(self, run):
        run.return_value = result()
        with self.assertRaisesRegex(RuntimeError, 'Windows isolation failed'):
            fw_backend.isolate('192.0.2.5', 443)
        run.return_value = SimpleNamespace(returncode=0, stdout='AJNAT isolation confirmed', stderr='')
        fw_backend.isolate('192.0.2.5', 443)
        script = run.call_args.args[0][-1]
        self.assertIn('Group Policy contains allow rules', script)
        self.assertLess(script.index('ConvertTo-Json'), script.index('-Enabled False'))
        self.assertIn('Effective Windows firewall policy did not apply isolation', script)
        run.return_value = SimpleNamespace(returncode=0, stdout='AJNAT reconnect confirmed', stderr='')
        fw_backend.restore()
        self.assertIn('$profile.DefaultOutboundAction', run.call_args.args[0][-1])
        self.assertNotIn('blockinbound,allowoutbound', run.call_args.args[0][-1])

    @patch.object(fw_backend, 'SYSTEM', 'Windows')
    @patch.object(fw_backend, '_run', return_value=result(1, 'Access denied'))
    def test_windows_does_not_ack_failed_policy_change(self, run):
        with self.assertRaises(RuntimeError):
            fw_backend.isolate('192.0.2.5', 443)
        with self.assertRaises(RuntimeError):
            fw_backend.restore()
        self.assertFalse(fw_backend.unblock_ip('203.0.113.9'))


if __name__ == '__main__':
    unittest.main()
