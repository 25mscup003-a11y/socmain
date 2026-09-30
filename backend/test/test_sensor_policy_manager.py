import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

AGENT_ROOT = Path(__file__).resolve().parents[1] / 'soc-agent'
sys.path.insert(0, str(AGENT_ROOT))

from core.sensor_policy_manager import SensorPolicyManager  # noqa: E402


class SensorPolicyManagerTests(unittest.TestCase):
    def make_manager(self, root):
        root = Path(root)
        suricata_config = root / 'suricata.yaml'
        suricata_config.write_text('default-rule-path: /tmp\nrule-files:\n  - suricata.rules\n')
        zeek_local = root / 'local.zeek'
        zeek_local.write_text('@load policy/misc/scan\n')
        return SensorPolicyManager({
            'ids_policy_dir': str(root / 'state'),
            'suricata_config': str(suricata_config),
            'suricata_soc_rules': str(root / 'soc-managed.rules'),
            'zeek_local_script': str(zeek_local),
            'zeek_soc_script': str(root / 'soc-managed.zeek'),
        })

    def test_allow_list_and_native_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            payload = {'policies': [
                {'presetId': 'suricata-sqli', 'mode': 'block'},
                {'presetId': 'zeek-dns-tunnel', 'mode': 'detect'},
                {'presetId': '../../arbitrary-rule', 'mode': 'block'},
            ]}
            with patch.object(manager, '_validate_and_reload', return_value={'suricata': 'validated', 'zeek': 'validated'}):
                result = manager.apply(payload)
            self.assertTrue(result['ok'])
            self.assertEqual(result['policies'], 2)
            self.assertIn('drop http', manager.suricata_file.read_text())
            self.assertNotIn('arbitrary', manager.suricata_file.read_text())
            self.assertIn('dns_tunnel_enabled = T', manager.zeek_file.read_text())
            self.assertIn('c2_enabled = F', manager.zeek_file.read_text())
            self.assertIn('@load policy/protocols/ssl/validate-certs', manager.zeek_file.read_text())
            self.assertIn('rec$mime_type == "application/x-dosexec"', manager.zeek_file.read_text())
            self.assertNotIn(' = true', manager.zeek_file.read_text())
            self.assertNotIn(' = false', manager.zeek_file.read_text())
            self.assertIn('soc-managed.rules', manager.suricata_config.read_text())
            self.assertIn('soc-managed.zeek', manager.zeek_local.read_text())
            self.assertEqual(len(json.loads(manager.state_file.read_text())['revision']), 16)

    def test_failed_validation_rolls_back_all_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            manager.suricata_file.write_text('old rules\n')
            old_yaml = manager.suricata_config.read_text()
            old_local = manager.zeek_local.read_text()
            with patch.object(manager, '_validate_and_reload', side_effect=RuntimeError('invalid native config')):
                with self.assertRaisesRegex(RuntimeError, 'invalid native config'):
                    manager.apply({'policies': [{'presetId': 'suricata-scan', 'mode': 'detect'}]})
            self.assertEqual(manager.suricata_file.read_text(), 'old rules\n')
            self.assertEqual(manager.suricata_config.read_text(), old_yaml)
            self.assertEqual(manager.zeek_local.read_text(), old_local)
            self.assertFalse(manager.state_file.exists())

    def test_binary_unavailable_is_not_reported_as_enforced(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            with patch.object(manager, '_validate_and_reload', return_value={'suricata': 'rules-written; binary-unavailable'}) as validate:
                result = manager.apply({'policies': [{'presetId': 'suricata-scan', 'mode': 'block'}]})
                second = manager.apply({'policies': [{'presetId': 'suricata-scan', 'mode': 'block'}]})
            self.assertFalse(second['ok'])
            self.assertFalse(result['ok'])
            self.assertEqual(validate.call_count, 2)

    def test_same_policy_retries_after_sensor_becomes_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            payload = {'policies': [{'presetId': 'suricata-scan', 'mode': 'block'}]}
            with patch.object(manager, '_validate_and_reload', side_effect=[
                {'suricata': 'rules-written; binary-unavailable'},
                {'suricata': 'reloaded'},
            ]) as validate:
                first = manager.apply(payload)
                second = manager.apply(payload)
            self.assertFalse(first['ok'])
            self.assertTrue(second['ok'])
            self.assertTrue(second['changed'])
            self.assertEqual(validate.call_count, 2)

    @patch('core.sensor_policy_manager.platform.system', return_value='Windows')
    def test_windows_target_compiles_safe_custom_suricata_rule(self, _system):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            payload = {'policies': [{
                'policyId': '66aa11bb22cc33dd44ee55ff',
                'presetId': '',
                'name': 'Block suspicious RDP source',
                'sensor': 'suricata',
                'targetPlatform': 'windows',
                'mode': 'block',
                'protocol': 'tcp',
                'sourceIp': '203.0.113.10',
                'destinationPort': 3389,
                'attackPattern': '',
            }]}
            with patch.object(manager, '_validate_and_reload', return_value={'suricata': 'restarted'}):
                result = manager.apply(payload)
            generated = manager.suricata_file.read_text()
            self.assertTrue(result['ok'])
            self.assertIn('drop tcp 203.0.113.10/32 any -> $HOME_NET 3389', generated)
            self.assertIn('SOC Custom Block suspicious RDP source', generated)

    @patch('core.sensor_policy_manager.platform.system', return_value='Windows')
    def test_windows_agent_ignores_linux_and_zeek_policies(self, _system):
        payload = {'policies': [
            {'presetId': 'suricata-scan', 'mode': 'block', 'targetPlatform': 'linux'},
            {'presetId': 'zeek-c2', 'mode': 'detect', 'targetPlatform': 'all'},
            {'presetId': 'suricata-rdp-brute-force', 'mode': 'block', 'targetPlatform': 'windows'},
        ]}
        normalized = SensorPolicyManager.normalize(payload)
        self.assertEqual([item['presetId'] for item in normalized], ['suricata-rdp-brute-force'])

    @patch('core.sensor_policy_manager.platform.system', return_value='Windows')
    def test_windows_agent_applies_prebuilt_windivert_policy(self, _system):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            payload = {'policies': [{
                'presetId': 'windivert-rdp-brute-force-guard',
                'mode': 'block',
                'targetPlatform': 'windows',
                'sensor': 'suricata',
            }]}
            with patch.object(manager, '_validate_and_reload', return_value={'suricata': 'restarted'}):
                result = manager.apply(payload)
            generated = manager.suricata_file.read_text()
            self.assertTrue(result['ok'])
            self.assertIn('drop tcp $EXTERNAL_NET any -> $HOME_NET 3389', generated)
            self.assertIn('SOC WinDivert RDP Brute Force Guard', generated)

    @patch('core.sensor_policy_manager.platform.system', return_value='Linux')
    def test_linux_agent_ignores_windivert_only_policy(self, _system):
        normalized = SensorPolicyManager.normalize({'policies': [{
            'presetId': 'windivert-port-scan-guard',
            'mode': 'block',
            'targetPlatform': 'all',
            'sensor': 'suricata',
        }]})
        self.assertEqual(normalized, [])

    def test_configured_windows_suricata_binary_is_used_for_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            manager.suricata_executable = r'C:\Program Files\Suricata\suricata.exe'
            with patch.object(manager, '_run') as run, patch.object(manager, '_reload', return_value='restarted'):
                result = manager._validate_and_reload(True, False)
            run.assert_called_once_with([
                manager.suricata_executable, '-T', '-c', str(manager.suricata_config),
            ], 'Suricata validation')
            self.assertEqual(result['suricata'], 'restarted')

    @patch('core.sensor_policy_manager.subprocess.run')
    @patch('core.sensor_policy_manager.platform.system', return_value='Windows')
    def test_windows_suricata_policy_reload_restarts_service(self, _system, run):
        run.return_value = SimpleNamespace(returncode=0, stdout='', stderr='')
        with tempfile.TemporaryDirectory() as tmp:
            manager = self.make_manager(tmp)
            self.assertEqual(manager._reload('suricata'), 'restarted')
        command = run.call_args.args[0]
        self.assertEqual(command[:3], ['powershell.exe', '-NoProfile', '-NonInteractive'])
        self.assertIn("Restart-Service -InputObject $svc", command[-1])


if __name__ == '__main__':
    unittest.main()
