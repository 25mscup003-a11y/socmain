import unittest
from unittest.mock import patch

from core.heartbeat import (
    HeartbeatService, _SECURITY_LOCKDOWN, _module_status,
    _sensor_executable_available,
)


class ResponseHandler:
    def __init__(self, result=None):
        self.calls = []
        self.result = result or {'ok': True, 'result': 'IP blocked: 203.0.113.10'}

    def dispatch(self, command, payload):
        self.calls.append((command, payload))
        return self.result


class HeartbeatCommandTests(unittest.TestCase):
    def tearDown(self):
        _SECURITY_LOCKDOWN.clear()

    def test_lockdown_rejects_response_commands_and_allows_authorized_unlock(self):
        heartbeat = HeartbeatService({})
        handler = ResponseHandler()
        heartbeat.set_response_handler(handler)
        _SECURITY_LOCKDOWN.set()

        heartbeat._execute_pending_commands([{
            'id': 'blocked-command', 'command': 'delete_file', 'path': '/tmp/evidence',
        }])
        self.assertEqual(handler.calls, [])
        self.assertFalse(heartbeat._security_action_results[0]['ok'])
        self.assertIn('security lockdown', heartbeat._security_action_results[0]['message'])

        heartbeat._execute_pending_commands([{'command': 'security-unlock'}])
        self.assertFalse(_SECURITY_LOCKDOWN.is_set())

    def test_queued_ip_block_uses_response_handler_without_response_id(self):
        heartbeat = HeartbeatService({})
        handler = ResponseHandler()
        heartbeat.set_response_handler(handler)

        payload = {'command': 'block_ip', 'ip': '203.0.113.10'}
        heartbeat._execute_pending_commands([payload])

        self.assertEqual(handler.calls, [('block_ip', payload)])

    def test_failed_queued_command_records_failed_audit(self):
        heartbeat = HeartbeatService({})
        handler = ResponseHandler({'ok': False, 'result': 'firewall denied'})
        heartbeat.set_response_handler(handler)

        heartbeat._execute_pending_commands([
            {'command': 'block_ip', 'ip': '203.0.113.10', 'auditId': 'audit-1'},
        ])

        self.assertEqual(heartbeat._security_action_results, [{
            'auditId': 'audit-1', 'ok': False, 'message': 'firewall denied',
        }])

    def test_ips_command_reports_command_result_for_server_acknowledgement(self):
        heartbeat = HeartbeatService({})
        heartbeat.set_response_handler(ResponseHandler())

        heartbeat._execute_pending_commands([{
            'id': 'ips-command-1', 'command': 'block_ip', 'ip': '203.0.113.10',
        }])

        self.assertEqual(heartbeat._security_action_results, [{
            'commandId': 'ips-command-1', 'command': 'block_ip',
            'ip': '203.0.113.10', 'ok': True,
            'message': 'IP blocked: 203.0.113.10',
        }])

    def test_camel_case_command_id_is_acknowledged(self):
        heartbeat = HeartbeatService({})
        heartbeat.set_response_handler(ResponseHandler())

        heartbeat._execute_pending_commands([{
            'commandId': 'response-command-1', 'command': 'block_ip',
            'ip': '203.0.113.10',
        }])

        self.assertEqual(heartbeat._security_action_results[0]['commandId'], 'response-command-1')

    def test_server_isolation_is_reapplied_after_agent_restart(self):
        heartbeat = HeartbeatService({})
        handler = ResponseHandler({'ok': True, 'result': 'system isolated'})
        heartbeat.set_response_handler(handler)

        heartbeat._sync_isolation_state({'is_isolated': True})

        self.assertEqual(handler.calls, [('isolate', {'command': 'isolate'})])
        self.assertTrue(heartbeat._last_isolation_state)

    def test_server_reconnect_transition_is_applied(self):
        heartbeat = HeartbeatService({})
        handler = ResponseHandler({'ok': True, 'result': 'isolation removed'})
        heartbeat.set_response_handler(handler)
        heartbeat._last_isolation_state = True

        heartbeat._sync_isolation_state({'is_isolated': False})

        self.assertEqual(handler.calls, [('reconnect', {'command': 'reconnect'})])
        self.assertFalse(heartbeat._last_isolation_state)

    def test_unsupported_command_returns_failed_command_ack(self):
        heartbeat = HeartbeatService({})
        heartbeat._execute_pending_commands([{
            'id': 'bad-command-1', 'command': 'not_real',
        }])

        self.assertEqual(heartbeat._security_action_results, [{
            'commandId': 'bad-command-1', 'command': 'not_real',
            'ip': None, 'ok': False, 'message': 'Unsupported command: not_real',
        }])

    @patch('core.heartbeat.shutil.which')
    @patch('core.heartbeat.platform.system', return_value='Darwin')
    def test_macos_pf_reports_real_firewall_and_ips_capability(self, _system, which):
        which.side_effect = lambda name: '/sbin/pfctl' if name == 'pfctl' else None
        status = _module_status({})
        self.assertTrue(status['firewallEnabled'])
        self.assertTrue(status['ipsEnabled'])
        self.assertTrue(status['idsEnabled'])
        self.assertTrue(status['endpointIdsEnabled'])
        self.assertFalse(status['packetSensorAvailable'])

    @patch('core.heartbeat.shutil.which')
    @patch('core.heartbeat.platform.system', return_value='Linux')
    def test_linux_ufw_is_a_valid_firewall_backend(self, _system, which):
        which.side_effect = lambda name: '/usr/sbin/ufw' if name == 'ufw' else None
        status = _module_status({})
        self.assertTrue(status['firewallEnabled'])
        self.assertTrue(status['ipsEnabled'])

    @patch('core.heartbeat.shutil.which')
    @patch('core.heartbeat.platform.system', return_value='Windows')
    def test_windows_requires_netsh_before_claiming_firewall(self, _system, which):
        which.side_effect = lambda name: r'C:\\Windows\\System32\\netsh.exe' if name == 'netsh.exe' else None
        available = _module_status({})
        self.assertTrue(available['firewallEnabled'])
        self.assertTrue(available['ipsEnabled'])

        which.side_effect = lambda _name: None
        unavailable = _module_status({})
        self.assertFalse(unavailable['firewallEnabled'])
        self.assertFalse(unavailable['ipsEnabled'])

    @patch('core.heartbeat.shutil.which', return_value=None)
    @patch('core.heartbeat.platform.system', return_value='Windows')
    def test_windows_endpoint_ids_does_not_require_packet_sensor(self, _system, _which):
        status = _module_status({'ids_enabled': True})
        self.assertTrue(status['idsEnabled'])
        self.assertTrue(status['endpointIdsEnabled'])
        self.assertFalse(status['packetSensorAvailable'])

        disabled = _module_status({'ids_enabled': False})
        self.assertFalse(disabled['idsEnabled'])
        self.assertFalse(disabled['endpointIdsEnabled'])

    @patch('core.heartbeat.os.path.isfile')
    @patch('core.heartbeat.shutil.which', return_value=None)
    @patch('core.heartbeat.platform.system', return_value='Windows')
    def test_windows_suricata_is_found_outside_service_path(self, _system, _which, isfile):
        isfile.side_effect = lambda path: str(path).replace('/', '\\').lower().endswith(r'suricata\suricata.exe')
        self.assertTrue(_sensor_executable_available('suricata'))

    @patch('core.heartbeat.shutil.which', return_value=None)
    @patch('core.heartbeat.platform.system', return_value='SunOS')
    def test_solaris_does_not_claim_unsupported_response(self, _system, _which):
        status = _module_status({})
        self.assertFalse(status['firewallEnabled'])
        self.assertFalse(status['ipsEnabled'])
        self.assertFalse(status['responseEnabled'])

    @patch('subprocess.run')
    @patch('subprocess.Popen')
    @patch('core.heartbeat.platform.system', return_value='Windows')
    def test_windows_update_installer_is_detached_from_agent_service(
        self, _system, popen, run,
    ):
        heartbeat = HeartbeatService({})

        heartbeat._install_update_package('exe', r'C:\Windows\Temp\soc-agent-update.exe')

        popen.assert_called_once()
        args, kwargs = popen.call_args
        self.assertEqual(args[0], [r'C:\Windows\Temp\soc-agent-update.exe', '/S'])
        self.assertTrue(kwargs['close_fds'])
        self.assertIn('creationflags', kwargs)
        run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
