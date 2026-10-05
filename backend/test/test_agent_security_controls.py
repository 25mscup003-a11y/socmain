import ctypes
import hashlib
import hmac
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from core.config import AgentConfig
from core.heartbeat import HeartbeatService, _MAINTENANCE_MODE, _SECURITY_LOCKDOWN, security_command_error
from core.security_controls import CONTROL_KEYS, RuntimeSecurity, normalize_policy
from core.secure_transport import secure_request
from core.self_protection import collect_security_report


def policy(**changes):
    return {**{wire: wire != 'maintenance_mode' for wire in CONTROL_KEYS.values()}, 'policy_version': 2, **changes}


class Config(dict):
    def update_runtime(self, values, **kwargs):
        changed = any(self.get(key) != value for key, value in values.items())
        self.update(values)
        return changed

    def is_configuration_encrypted(self):
        return True


class AgentSecurityControlTests(unittest.TestCase):
    def tearDown(self):
        _MAINTENANCE_MODE.clear()
        _SECURITY_LOCKDOWN.clear()

    def test_all_controls_validate_and_mandatory_controls_cannot_be_disabled(self):
        self.assertEqual(len(normalize_policy(policy())), 14)
        self.assertFalse(normalize_policy(policy())['erase_code_on_open'])
        with self.assertRaises(ValueError):
            normalize_policy(policy(erase_code_on_open='true'))
        for key in ('secure_communication', 'configuration_encryption', 'certificate_validation'):
            with self.subTest(key=key), self.assertRaises(ValueError):
                normalize_policy(policy(**{key: False}))
        with self.assertRaises(ValueError):
            normalize_policy(policy(anti_dump_protection='true'))

    def test_policy_persistence_failure_is_reported_instead_of_success(self):
        config = Config()
        config.update_runtime = Mock(side_effect=OSError('Disk full'))
        heartbeat = HeartbeatService(config)
        heartbeat._apply_security_policy(policy())
        self.assertEqual(heartbeat._security_policy_error, 'Disk full')
        self.assertFalse(_MAINTENANCE_MODE.is_set())

    def test_all_switches_reach_runtime_and_maintenance_resumes(self):
        config = Config(server_url='http://example.test')
        heartbeat = HeartbeatService(config)
        with patch.object(heartbeat._runtime_security, 'apply'):
            heartbeat._apply_security_policy(policy(maintenance_mode=True))
            self.assertTrue(_MAINTENANCE_MODE.is_set())
            self.assertIn('maintenance', security_command_error('delete_file'))
            self.assertEqual(security_command_error('verify-integrity'), '')
            heartbeat._apply_security_policy(policy(policy_version=3))
            self.assertFalse(_MAINTENANCE_MODE.is_set())
        for wire in CONTROL_KEYS.values():
            self.assertEqual(config[wire], wire != 'maintenance_mode')

    def test_periodic_scans_and_analysis_controls_follow_the_policy(self):
        config = Config(policy(self_protection=False))
        heartbeat = HeartbeatService(config)
        with patch('core.heartbeat.collect_security_report', return_value={'integrityStatus': 'unknown'}) as scan:
            report = heartbeat._refresh_security_report()
            self.assertFalse(scan.call_args.kwargs['check_integrity'])
            self.assertFalse(scan.call_args.kwargs['check_debugger'])
            self.assertFalse(scan.call_args.kwargs['check_tools'])
            self.assertEqual(report['controls']['selfProtection']['state'], 'disabled')
            self.assertEqual(report['controls']['secureCommunication']['state'], 'enforced')

    def test_disabled_analysis_sensors_do_not_report_incidents(self):
        with patch('core.self_protection._debugger_attached', return_value=['attached']) as debugger, patch('core.self_protection._running_analysis_tools', return_value=['gdb']) as tools:
            report = collect_security_report(check_integrity=False, check_debugger=False, check_tools=False)
            self.assertFalse(report['debuggerDetected']); self.assertEqual(report['analysisTools'], [])
            debugger.assert_not_called(); tools.assert_not_called()

    def test_runtime_labels_do_not_claim_python_reverse_engineering_prevention_or_http_certificates(self):
        runtime = RuntimeSecurity()
        report = runtime.report(Config(policy(), server_url='http://example.test'), {'integrityStatus': 'verified'}, {'configuration_encrypted': True}, False, False)
        self.assertEqual(len(report), 12)
        self.assertEqual(report['antiReverseEngineering']['state'], 'monitoring')
        self.assertEqual(report['certificateValidation']['state'], 'not_applicable')
        self.assertEqual(report['configurationEncryption']['state'], 'enforced')
        with patch('core.security_controls.sys.platform', 'win32'):
            runtime.apply(Config(policy()))
        self.assertEqual(runtime.dump_status['state'], 'unsupported')

    @unittest.skipUnless(sys.platform.startswith('linux'), 'Linux process hardening')
    def test_linux_anti_dump_actually_changes_process_flags_and_can_be_disabled(self):
        code = '''import ctypes, resource
from core.security_controls import RuntimeSecurity
r=RuntimeSecurity()
before=ctypes.CDLL(None).prctl(3,0,0,0,0)
r.apply({'self_protection':True,'anti_dump_protection':True})
assert r.dump_status['state']=='enforced', r.dump_status
assert ctypes.CDLL(None).prctl(3,0,0,0,0)==0
assert resource.getrlimit(resource.RLIMIT_CORE)[0]==0
r.apply({'self_protection':True,'anti_dump_protection':False})
assert ctypes.CDLL(None).prctl(3,0,0,0,0)==before
'''
        subprocess.run([sys.executable, '-c', code], check=True, capture_output=True, timeout=10)

    def test_lockdown_is_durable_and_duplicate_delivery_does_not_execute_again(self):
        config = Config()
        heartbeat = HeartbeatService(config)
        command = {'command': 'security-lockdown', 'auditId': 'audit-1'}
        heartbeat._execute_pending_commands([command])
        self.assertTrue(config['security_lockdown_active'])
        self.assertTrue(_SECURITY_LOCKDOWN.is_set())
        _SECURITY_LOCKDOWN.clear()
        heartbeat._execute_pending_commands([command])
        self.assertFalse(_SECURITY_LOCKDOWN.is_set())
        self.assertTrue(heartbeat._security_action_results[-1]['ok'])

    def test_unlock_refuses_unresolved_tampering(self):
        heartbeat = HeartbeatService(Config())
        _SECURITY_LOCKDOWN.set()
        with patch.object(heartbeat, '_refresh_security_report', return_value={'integrityStatus': 'mismatch'}):
            heartbeat._execute_pending_commands([{'command': 'security-unlock', 'auditId': 'unlock-1'}])
        self.assertTrue(_SECURITY_LOCKDOWN.is_set())
        self.assertFalse(heartbeat._security_action_results[-1]['ok'])

    def test_lockdown_guards_socket_and_automatic_response_paths(self):
        from core.command_listener import CommandListener
        from core.auto_response import AutoResponseEngine
        _SECURITY_LOCKDOWN.set()
        listener = object.__new__(CommandListener)
        engine = object.__new__(AutoResponseEngine)
        self.assertFalse(listener._dispatch('kill_process', {})['ok'])
        self.assertFalse(listener._apply_firewall_rule({})['ok'])
        self.assertFalse(engine.dispatch('delete_file', {})['ok'])

    def test_restart_acknowledges_recovery_once_after_integrity_scan(self):
        config = Config(security_recovery_audit='recover-1')
        heartbeat = HeartbeatService(config)
        with patch('core.heartbeat.collect_security_report', return_value={'integrityStatus': 'verified'}):
            heartbeat._refresh_security_report()
            heartbeat._refresh_security_report()
        self.assertEqual(len(heartbeat._security_action_results), 1)
        self.assertTrue(heartbeat._security_action_results[0]['ok'])
        self.assertEqual(config['security_recovery_audit'], '')

    def test_configuration_write_failure_propagates_for_protected_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps({'system_id': 'test', 'agent_key': 'test'}))
            config = AgentConfig(path)
            with patch('core.config.save_config', side_effect=OSError('Read-only disk')):
                with self.assertRaisesRegex(OSError, 'Read-only'):
                    config.update_runtime({'maintenance_mode': True}, strict=True)

    def test_plaintext_replayed_and_certificate_bypass_responses_are_rejected(self):
        config = {'system_id': 'test', 'agent_key': 'secret', 'require_tls': False}
        response = Mock(ok=True, status_code=200, headers={}, content=b'{"commands":[]}')
        with patch('core.secure_transport._session') as session:
            session.return_value.request.return_value = response
            with self.assertRaisesRegex(RuntimeError, 'signature'):
                secure_request(config, 'POST', 'http://example.test/api/agent/heartbeat', json={})
            digest = hashlib.sha256(response.content).hexdigest()
            signature = hmac.new(b'secret', f'AJNAT-RESPONSE-V1.old-nonce.200.{digest}'.encode(), hashlib.sha256).hexdigest()
            response.headers = {'X-AJNAT-Response-SHA256': digest, 'X-AJNAT-Response-Signature': signature}
            with self.assertRaisesRegex(RuntimeError, 'replayed'):
                secure_request(config, 'POST', 'http://example.test/api/agent/heartbeat', json={})
        with self.assertRaisesRegex(RuntimeError, 'certificate'):
            secure_request(config, 'POST', 'https://example.test/api/agent/heartbeat', json={}, verify=False)


if __name__ == '__main__':
    unittest.main()
