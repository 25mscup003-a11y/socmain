import copy
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import Mock, patch

from core.command_guard import automatic_isolation_error
from core.network_verification import PROVIDERS
from core.command_listener import CommandListener
from core.heartbeat import HeartbeatService


def iso(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat()


def automatic_command(now):
    return {'id': 'auto-isolate', 'command': 'isolate',
            'reason': 'Automatic IPS isolation: Port Scan', 'srcIp': '45.77.1.23',
            'threatVerification': {'version': 2, 'policy': 'two-of-four', 'matchedProviders': ['abuseipdb', 'otx'],
                                   'ip': '45.77.1.23', 'companyId': 'company', 'action': 'isolate',
                                   'checkedAt': iso(time.time() - 1), 'expiresAt': iso(time.time() + 29),
                                   'providers': list(PROVIDERS)},
            'autoIsolation': {'version': 1, 'incidentStartedAt': iso(now - 60),
                              'verifiedAt': iso(now - 1), 'expiresAt': iso(now + 29),
                              'threatAlertId': 'new-alert', 'requireUnconfirmedBlock': True}}


class AutomaticIsolationGuardTests(unittest.TestCase):
    def test_expired_missing_invalid_and_future_verification_is_rejected(self):
        now = 1791540000.0
        command = automatic_command(now)
        self.assertIsNone(automatic_isolation_error('isolate', command, now))
        for changes in ({'expiresAt': iso(now)}, {'expiresAt': iso(now + 300)},
                        {'verifiedAt': iso(now + 1)}, {'verifiedAt': 'bad'},
                        {'incidentStartedAt': iso(now)}, {'version': 2},
                        {'requireUnconfirmedBlock': 'false'}, {'threatAlertId': ''}):
            with self.subTest(changes=changes):
                modified = copy.deepcopy(command)
                modified['autoIsolation'].update(changes)
                self.assertIsNotNone(automatic_isolation_error('isolate', modified, now))
        del command['autoIsolation']
        self.assertIsNotNone(automatic_isolation_error('isolate', command, now))

    def test_heartbeat_does_not_execute_stale_automatic_isolation(self):
        heartbeat = HeartbeatService({})
        handler = Mock()
        heartbeat.set_response_handler(handler)
        command = automatic_command(time.time() - 120)
        heartbeat._execute_pending_commands([command])
        handler.dispatch.assert_not_called()
        ack = heartbeat._security_action_results[0]
        self.assertFalse(ack['ok'])
        self.assertEqual(ack['commandId'], command['id'])
        self.assertIn('Automatic isolation deferred:', ack['message'])

    def test_fresh_auto_manual_and_confirmed_state_reapply_work(self):
        heartbeat = HeartbeatService({})
        handler = Mock()
        handler.dispatch.return_value = {'ok': True, 'result': 'isolated'}
        heartbeat.set_response_handler(handler)
        for command in [automatic_command(time.time()),
                        {'id': 'manual', 'command': 'isolate', 'reason': 'Manual IPS isolation'},
                        {'command': 'isolate'}]:
            heartbeat._execute_pending_commands([command])
        self.assertEqual(handler.dispatch.call_count, 3)
        self.assertTrue(all(row['ok'] for row in heartbeat._security_action_results))

    def test_socket_dispatch_guards_both_response_engine_and_legacy_handlers(self):
        listener = CommandListener({}, Mock(), auto_response=Mock())
        listener._auto_response.dispatch.return_value = {'ok': True, 'result': 'isolated'}
        with patch.object(listener, '_isolate') as legacy:
            stale = automatic_command(time.time() - 120)
            self.assertFalse(listener._dispatch('isolate', stale)['ok'])
            listener._auto_response.dispatch.assert_not_called()
            legacy.assert_not_called()
            self.assertTrue(listener._dispatch('isolate', automatic_command(time.time()))['ok'])
            listener._auto_response = None
            self.assertFalse(listener._dispatch('isolate', stale)['ok'])
            legacy.assert_not_called()
            listener._dispatch('isolate', {'command': 'isolate', 'reason': 'Manual IPS isolation'})
            legacy.assert_called_once()


if __name__ == '__main__':
    unittest.main()
