import unittest
from datetime import datetime, timezone
from unittest.mock import patch

from detectors.rules import RuleDetector, _auth_action, _is_routine_service_auth, _outside_working_hours
from core.time_anomaly import TimeAnomalyDetector


class _Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class _NightTime(datetime):
    @classmethod
    def now(cls, tz=None):
        value = cls(2026, 8, 31, 2, 15, tzinfo=timezone.utc)
        return value if tz else value.replace(tzinfo=None)


class AuthDetectorTest(unittest.TestCase):
    def test_failed_login_is_classified(self):
        self.assertEqual(
            _auth_action('AUTH_FAIL', 'sshd: Failed password for alice from 10.0.0.5'),
            'login_failed',
        )

    def test_account_lockout_takes_priority_over_generic_failure(self):
        self.assertEqual(
            _auth_action('AUTH_ACCOUNT_LOCK', 'too many failed login attempts; account locked'),
            'account_lockout',
        )

    def test_mfa_failure_keeps_mfa_semantics(self):
        self.assertEqual(
            _auth_action('AUTH_MFA_FAILURE', 'OTP invalid and MFA denied'),
            'mfa_failure',
        )

    def test_windows_failed_lock_screen_unlock_is_structured_once(self):
        sender = _Sender()
        detector = RuleDetector(sender, config={
            'credential_monitor_lock_screen_enabled': True,
            'credential_enabled_rule_ids': ['AUTH_SCREEN_UNLOCK_FAILURE'],
        })
        detector.analyze(
            '2026-08-31T12:00:00 [Security] EventID=4625 Account Name: SYSTEM\n'
            'Account Name: alice\nLogon Type: 7\nFailure Reason: Unknown user name or bad password.\n'
            'Status: 0xC000006D\nSub Status: 0xC000006A',
            'windows/Security',
        )
        events = [event for event in sender.events if event.get('rule_id') == 'AUTH_SCREEN_UNLOCK_FAILURE']
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['username'], 'alice')
        self.assertEqual(events[0]['credential_event_type'], 'screen_unlock_failed')
        self.assertEqual(events[0]['auth_result'], 'failure')
        self.assertEqual(events[0]['failure_reason'], 'Unknown user name or bad password.')
        self.assertNotIn('password_value', events[0])

    def test_windows_successful_unlock_is_recorded(self):
        sender = _Sender()
        detector = RuleDetector(sender, config={})
        detector.analyze(
            '2026-08-31T12:01:00 [Security] EventID=4801 Account Name: alice Workstation was unlocked',
            'windows/Security',
        )
        events = [event for event in sender.events if event.get('rule_id') == 'AUTH_SCREEN_UNLOCK_SUCCESS']
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]['auth_result'], 'success')

    def test_cron_pam_session_is_not_a_user_login(self):
        self.assertTrue(_is_routine_service_auth(
            'HOST CRON[87218]: pam_unix(cron:session): session opened for user root(uid=0)',
        ))
        self.assertFalse(_is_routine_service_auth(
            'HOST sshd[100]: Accepted password for alice from 10.0.0.5 port 52100 ssh2',
        ))

    def test_working_hour_window_supports_day_and_overnight_shifts(self):
        self.assertFalse(_outside_working_hours(datetime(2026, 1, 1, 10), 8, 20))
        self.assertTrue(_outside_working_hours(datetime(2026, 1, 1, 23), 8, 20))
        self.assertFalse(_outside_working_hours(datetime(2026, 1, 1, 23), 20, 8))
        self.assertTrue(_outside_working_hours(datetime(2026, 1, 1, 12), 20, 8))

    def test_correlated_privileged_remote_login_emits_structured_time_anomaly(self):
        sender = _Sender()
        detector = RuleDetector(sender, config={
            'time_anomaly_enabled': True,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [5, 6],
            'time_anomaly_risk_threshold': 45,
            'time_anomaly_cooldown_seconds': 300,
        })
        with patch('detectors.rules.datetime', _NightTime):
            detector._time_analytics('AUTH_REMOTE_ACCESS', 'RDP login accepted for Administrator', 'Windows/Security', 'Administrator', '203.0.113.5', 'edr', 'medium')
        self.assertEqual(len(sender.events), 1)
        event = sender.events[0]
        self.assertEqual(event['capabilityId'], 22)
        self.assertEqual(event['rule_id'], 'TIME_AFTER_HOURS_AUTH')
        self.assertIn('actual_time', event)
        self.assertIn('expected_time', event)
        self.assertGreaterEqual(event['risk_score'], 45)

    def test_low_context_after_hours_login_does_not_alert(self):
        sender = _Sender()
        detector = RuleDetector(sender, config={
            'time_anomaly_enabled': True,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
            'time_anomaly_risk_threshold': 45,
        })
        with patch('detectors.rules.datetime', _NightTime):
            detector._time_analytics('AUTH_SUCCESS', 'session opened for user alice', 'auth.log', 'alice', '', 'edr', 'low')
        self.assertEqual(sender.events, [])

    def test_cross_collector_high_risk_process_is_correlated_after_hours(self):
        detector = TimeAnomalyDetector({
            'time_anomaly_enabled': True,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
            'time_anomaly_risk_threshold': 45,
        })
        findings = detector.analyze({
            'rule_id': 'PROC_SUSPICIOUS_POWERSHELL',
            'category': 'edr',
            'capabilityId': 1,
            'severity': 'high',
            'description': 'PowerShell encoded command execution',
            'process_name': 'powershell.exe',
            'timestamp': '2026-08-31T22:15:00+05:30',
        })
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['capabilityId'], 22)
        self.assertIn(1, findings[0]['capabilityIds'])
        self.assertEqual(findings[0]['raw']['source_event'], 'PROC_SUSPICIOUS_POWERSHELL')

    def test_cross_collector_routine_low_event_does_not_alert(self):
        detector = TimeAnomalyDetector({
            'time_anomaly_enabled': True,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
        })
        findings = detector.analyze({
            'rule_id': 'FILE_ACCESSED',
            'category': 'file',
            'severity': 'low',
            'description': 'Routine file opened',
            'timestamp': '2026-08-31T22:15:00+05:30',
        })
        self.assertEqual(findings, [])

    def test_time_policy_user_exception_suppresses_finding(self):
        detector = TimeAnomalyDetector({
            'time_anomaly_enabled': True,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
            'time_anomaly_exceptions': [{'type': 'user', 'value': 'backup-user'}],
        })
        findings = detector.analyze({
            'rule_id': 'BACKUP_OUTSIDE_SCHEDULE',
            'category': 'system',
            'severity': 'high',
            'description': 'Backup process outside schedule',
            'username': 'backup-user',
            'timestamp': '2026-08-31T22:15:00+05:30',
        })
        self.assertEqual(findings, [])

    def test_active_agent_bypass_suppresses_all_time_anomaly_rules(self):
        bypass_until = datetime(2099, 1, 1, tzinfo=timezone.utc).isoformat()
        detector = TimeAnomalyDetector({
            'time_anomaly_enabled': True,
            'time_anomaly_bypass_active': True,
            'time_anomaly_bypass_until': bypass_until,
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
        })
        findings = detector.analyze({
            'rule_id': 'PROC_SUSPICIOUS_POWERSHELL',
            'category': 'edr',
            'severity': 'critical',
            'description': 'PowerShell credential theft after hours',
            'timestamp': '2026-08-31T22:15:00+05:30',
        })
        self.assertEqual(findings, [])

        sender = _Sender()
        rule_detector = RuleDetector(sender, config={
            'time_anomaly_enabled': True,
            'time_anomaly_bypass_active': True,
            'time_anomaly_bypass_until': bypass_until,
        })
        with patch('detectors.rules.datetime', _NightTime):
            rule_detector._time_analytics('AUTH_REMOTE_ACCESS', 'RDP login accepted for Administrator', 'Windows/Security', 'Administrator', '203.0.113.5', 'edr', 'critical')
        self.assertEqual(sender.events, [])

    def test_expired_agent_bypass_does_not_disable_time_anomaly_rules(self):
        detector = TimeAnomalyDetector({
            'time_anomaly_enabled': True,
            'time_anomaly_bypass_active': True,
            'time_anomaly_bypass_until': '2020-01-01T00:00:00Z',
            'working_hours_start': 8,
            'working_hours_end': 20,
            'time_anomaly_weekend_days': [],
            'time_anomaly_risk_threshold': 45,
        })
        findings = detector.analyze({
            'rule_id': 'PROC_SUSPICIOUS_POWERSHELL',
            'category': 'edr',
            'severity': 'high',
            'description': 'PowerShell encoded command execution',
            'timestamp': '2026-08-31T22:15:00+05:30',
        })
        self.assertEqual(len(findings), 1)


if __name__ == '__main__':
    unittest.main()
