import copy
import hashlib
import hmac
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from core.network_verification import PROVIDERS, proof_valid, verify_network_action, automatic_network_error
from core.ips import IPSModule
from core.heartbeat import HeartbeatService
from core.command_listener import CommandListener
from core.auto_response import AutoResponseEngine
from core.security import canonicalize

IP = '45.77.1.23'
CONFIG = {'agent_key': 'unit-test-key', 'company_id': 'company', 'server_url': 'https://soc.example.test'}


def proof(action='block_ip'):
    now = time.time()
    iso = lambda value: datetime.fromtimestamp(value, timezone.utc).isoformat()
    return {'version': 2, 'policy': 'two-of-four', 'companyId': 'company', 'ip': IP, 'action': action,
            'checkedAt': iso(now - 1), 'expiresAt': iso(now + 29), 'providers': sorted(PROVIDERS),
            'matchedProviders': ['abuseipdb', 'otx']}


class NetworkVerificationTests(unittest.TestCase):
    def test_two_distinct_matches_and_correct_identity_are_required(self):
        valid = proof()
        self.assertTrue(proof_valid(valid, IP, 'block_ip', 'company'))
        for matched in [[], ['otx'], ['otx', 'otx'], ['otx', 'feodo'], 'otx,abuseipdb', None]:
            value = copy.deepcopy(valid)
            value['matchedProviders'] = matched
            self.assertFalse(proof_valid(value, IP, 'block_ip', 'company'))
        for matched in [['abuseipdb', 'otx'], ['virustotal', 'abuseipdb'], ['otx', 'virustotal']]:
            value = {**valid, 'matchedProviders': matched}
            self.assertTrue(proof_valid(value, IP, 'block_ip', 'company'))
        self.assertFalse(proof_valid({**valid, 'version': 1}, IP, 'block_ip', 'company'))
        self.assertFalse(proof_valid({**valid, 'policy': 'all-seven'}, IP, 'block_ip', 'company'))
        self.assertFalse(proof_valid(valid, '45.77.1.24', 'block_ip', 'company'))
        self.assertFalse(proof_valid(valid, IP, 'isolate', 'company'))
        self.assertFalse(proof_valid(valid, IP, 'block_ip', 'other-company'))
        valid['expiresAt'] = '2000-01-01T00:00:00+00:00'
        self.assertFalse(proof_valid(valid, IP, 'block_ip'))

    @patch('core.network_verification.secure_request')
    def test_local_verification_uses_authenticated_backend_and_rejects_missing_approval(self, request):
        response = Mock(status_code=200)
        response.json.return_value = {'allowed': True, 'verification': proof()}
        request.return_value = response
        self.assertTrue(verify_network_action(CONFIG, IP, 'block_ip'))
        self.assertEqual(request.call_args.args[2], 'https://soc.example.test/api/agent/network-response/check')
        self.assertIn('x-agent-signature', request.call_args.kwargs['headers'])
        self.assertEqual(set(request.call_args.kwargs['json']), {'agent_key', 'ip', 'action'})
        response.json.return_value = {'allowed': False, 'reason': 'OTX unavailable'}
        self.assertFalse(verify_network_action(CONFIG, IP, 'block_ip'))
        response.json.return_value = {'allowed': True}
        self.assertFalse(verify_network_action(CONFIG, IP, 'block_ip'))
        request.side_effect = RuntimeError('offline')
        self.assertFalse(verify_network_action(CONFIG, IP, 'block_ip'))

    @patch('core.network_verification.verify_network_action', return_value=False)
    @patch('core.ips.fw_backend.block_ip')
    def test_local_ids_waf_ip_block_never_reaches_firewall_without_verification(self, firewall, verify):
        ips = IPSModule(Mock(), CONFIG)
        for reason in ['IDS: Port Scan', 'Suricata: attack', 'WAF auto-block: SQLi']:
            self.assertFalse(ips.block_ip(IP, reason=reason))
        self.assertEqual(verify.call_count, 3)
        firewall.assert_not_called()
        verify.return_value = True
        firewall.return_value = True
        self.assertTrue(ips.block_ip(IP, reason='IDS: Port Scan'))
        firewall.assert_called_once()

    def test_agent_delivery_rejects_incomplete_automatic_block_and_isolation(self):
        heartbeat = HeartbeatService(CONFIG)
        handler = Mock()
        heartbeat.set_response_handler(handler)
        listener = CommandListener(CONFIG, Mock(), auto_response=handler)
        for action in ['block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint']:
            data = {'id': action, 'command': action, 'automatic': True, 'ip': IP}
            heartbeat._execute_pending_commands([data])
            self.assertFalse(heartbeat._security_action_results[-1]['ok'])
            self.assertFalse(listener._dispatch(action, data)['ok'])
        handler.dispatch.assert_not_called()

    def test_signed_soar_command_keeps_verification_inside_integrity_check(self):
        now = datetime.now(timezone.utc).isoformat()
        data = {'commandId': 'cmd', 'responseId': 'response', 'tenantId': '', 'agentId': '',
                'systemId': 'endpoint', 'command': 'block_ip', 'params': {'ip': IP},
                'createdAt': now, 'expiresAt': proof()['expiresAt'], 'retryCount': 0,
                'maxRetries': 0, 'correlationId': 'response', 'automatic': True, 'threatVerification': proof()}
        data['signature'] = hmac.new(CONFIG['agent_key'].encode(), canonicalize(data).encode(), hashlib.sha256).hexdigest()
        data['ip'] = IP
        ips = Mock()
        ips.block_ip.return_value = True
        engine = AutoResponseEngine(Mock(), CONFIG, ips=ips)
        result = engine.dispatch('block_ip', data)
        self.assertTrue(result['ok'], result)
        ips.block_ip.assert_called_once_with(IP, reason='auto-response', authorized_by_backend=True)
        forged = copy.deepcopy(data)
        forged['threatVerification']['companyId'] = 'foreign'
        self.assertFalse(engine.dispatch('block_ip', forged)['ok'])
        self.assertEqual(ips.block_ip.call_count, 1)

    def test_explicit_manual_actions_do_not_require_automatic_proof(self):
        self.assertIsNone(automatic_network_error('block_ip', {'command': 'block_ip', 'ip': IP, 'automatic': False}))
        self.assertIsNone(automatic_network_error('isolate', {'command': 'isolate'}))


if __name__ == '__main__':
    unittest.main()
