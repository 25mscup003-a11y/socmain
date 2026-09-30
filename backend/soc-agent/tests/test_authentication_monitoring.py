import unittest

from detectors.rules import RuleDetector


class _Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class AuthenticationMonitoringTest(unittest.TestCase):
    def _events(self, line, source, config=None):
        sender = _Sender()
        RuleDetector(sender, config=config or {'time_anomaly_enabled': False}).analyze(line, source)
        return sender.events

    def test_windows_failed_logon_preserves_authentication_evidence(self):
        events = self._events(
            'EventID=4625 Account Name: SYSTEM\nAccount Name: alice\n'
            'Account Domain: AJNAT\nLogon Type: 3\nSource Network Address: 203.0.113.10\n'
            'Source Port: 51120\nFailure Reason: Unknown user name or bad password.',
            'windows/Security',
        )
        event = next(row for row in events if row.get('rule_id') == 'AUTH_FAIL')
        self.assertIn(4, event['capabilityIds'])
        self.assertEqual(event['username'], 'alice')
        self.assertEqual(event['auth_result'], 'failure')
        self.assertEqual(event['auth_type'], 'Windows Logon')
        self.assertEqual(event['windows_event_id'], 4625)
        self.assertEqual(event['source_port'], 51120)
        self.assertEqual(event['logon_type'], '3')
        self.assertEqual(event['domain'], 'AJNAT')
        self.assertEqual(event['src_ip'], '203.0.113.10')
        self.assertNotIn('mitre_id', event)
        self.assertFalse(any(row.get('auth_result') == 'success' for row in events))

    def test_linux_ssh_success_is_normalized(self):
        events = self._events(
            'Sep 1 10:20:30 host sshd[510]: Accepted publickey for bob from 198.51.100.8 port 44221 ssh2',
            '/var/log/auth.log',
        )
        event = next(row for row in events if row.get('rule_id') == 'AUTH_SUCCESS')
        self.assertEqual(event['username'], 'bob')
        self.assertEqual(event['auth_result'], 'success')
        self.assertEqual(event['auth_type'], 'SSH Key')
        self.assertEqual(event['source_port'], 44221)
        self.assertEqual(event['raw']['host_type'], 'linux')

    def test_ntlm_validation_uses_result_code(self):
        success = self._events(
            'EventID=4776 Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 '
            'Logon Account: alice Source Workstation: WS01 Error Code: 0x0',
            'windows/Security',
        )
        failure = self._events(
            'EventID=4776 Authentication Package: MICROSOFT_AUTHENTICATION_PACKAGE_V1_0 '
            'Logon Account: alice Source Workstation: WS01 Error Code: 0xC000006A',
            'windows/Security',
        )
        self.assertTrue(any(row.get('rule_id') == 'AUTH_SUCCESS' and row.get('auth_result') == 'success' for row in success))
        self.assertFalse(any(row.get('rule_id') == 'AUTH_SUCCESS' for row in failure))
        self.assertTrue(any(row.get('rule_id') == 'AUTH_FAIL' and row.get('auth_result') == 'failure' for row in failure))

    def test_password_spray_correlates_distinct_accounts_by_source(self):
        sender = _Sender()
        detector = RuleDetector(sender, config={
            'time_anomaly_enabled': True,
            'time_auth_failure_threshold': 100,
            'auth_password_spray_user_threshold': 3,
            'auth_password_spray_window_seconds': 300,
        })
        for username in ('alice', 'bob', 'carol'):
            detector.analyze(
                f'host sshd[500]: Failed password for {username} from 203.0.113.77 port 44000 ssh2',
                '/var/log/auth.log',
            )
        sprays = [row for row in sender.events if row.get('rule_id') == 'AUTH_PASSWORD_SPRAY']
        self.assertEqual(len(sprays), 1)
        self.assertEqual(sprays[0]['mitre_id'], 'T1110.003')
        self.assertEqual(sprays[0]['raw']['distinct_user_count'], 3)
        self.assertEqual(sprays[0]['related_users'], ['alice', 'bob', 'carol'])


if __name__ == '__main__':
    unittest.main()
