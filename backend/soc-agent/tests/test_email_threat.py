import os
import sqlite3
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

AGENT_ROOT = Path(__file__).resolve().parents[1]
if str(AGENT_ROOT) not in sys.path:
    sys.path.insert(0, str(AGENT_ROOT))

from collectors.browser_activity import _history_paths, _read_chromium
from collectors.email_threat import EmailThreatCollector, _is_soc_or_local_url, _iter_attachment_files, _mail_component, _parse_mail_line, _sha256, _url_risk, _webmail_provider


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class EmailThreatCollectorTests(unittest.TestCase):
    def test_webmail_provider_matching(self):
        self.assertEqual(_webmail_provider('mail.google.com'), 'Google Workspace / Gmail')
        self.assertEqual(_webmail_provider('outlook.office.com'), 'Microsoft 365 Outlook')
        self.assertEqual(_webmail_provider('webmail.example.org'), 'Webmail (webmail.example.org)')
        self.assertEqual(_webmail_provider('portal.example.org', 'https://portal.example.org/roundcube/'), 'Webmail (portal.example.org)')
        self.assertEqual(_webmail_provider('portal.example.org', 'https://portal.example.org/', 'Roundcube Webmail'), 'Webmail (portal.example.org)')
        self.assertEqual(_webmail_provider('example.org'), '')

    def test_native_webmail_app_and_server_process_matching(self):
        self.assertEqual(_mail_component('olk.exe'), ('Microsoft Outlook', 'client'))
        self.assertEqual(_mail_component('gmail.exe'), ('Google Workspace / Gmail', 'client'))
        self.assertEqual(
            _mail_component('chrome_proxy.exe', '--app=https://mail.google.com/mail/u/0/'),
            ('Google Workspace / Gmail', 'webmail_app'),
        )
        self.assertEqual(_mail_component('Microsoft.Exchange.Store.Worker.exe'), ('Mail service microsoft.exchange.store.worker.exe', 'server'))
        self.assertEqual(_mail_component('calculator.exe'), ('', ''))

    def test_existing_mail_application_is_reported_as_running_on_first_scan(self):
        sender = Sender()
        collector = EmailThreatCollector(sender, {})

        class Process:
            info = {
                'pid': 42, 'ppid': 1, 'name': 'olk.exe', 'exe': 'C:/Program Files/WindowsApps/olk.exe',
                'cmdline': ['olk.exe'], 'username': 'analyst', 'create_time': time.time() - 3600,
            }

            @staticmethod
            def parent():
                return None

        fake_psutil = SimpleNamespace(process_iter=lambda _fields: [Process()], Error=Exception)
        with patch('collectors.email_threat.psutil', fake_psutil):
            collector._scan_processes()
            collector._scan_processes()
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'EMAIL_MAIL_COMPONENT_RUNNING')
        self.assertEqual(sender.events[0]['raw']['process_state'], 'running')
        self.assertGreater(sender.events[0]['timestamp'], sender.events[0]['raw']['observed_process_create_time'])

    def test_url_risk_is_deterministic_and_explained(self):
        score, reasons = _url_risk('http://login-check.example.zip/verify')
        self.assertGreaterEqual(score, 36)
        self.assertIn('high-abuse-tld', reasons)
        self.assertIn('credential-themed-path', reasons)

    def test_soc_dashboard_is_not_correlated_as_email_url(self):
        self.assertTrue(_is_soc_or_local_url('http://localhost:3000/company-admin/edr'))
        self.assertTrue(_is_soc_or_local_url('http://10.0.0.5:5000/api/health', 'http://10.0.0.5:5000'))
        self.assertFalse(_is_soc_or_local_url('https://example.test/article'))

    def test_file_hash(self):
        with tempfile.NamedTemporaryFile(delete=False) as handle:
            handle.write(b'ajnat-email-test')
            path = handle.name
        try:
            self.assertEqual(_sha256(path), '700c0e4a8412cf8a16836634c37fb3d0a600234854f85e91fd70d1963a23f6d3')
        finally:
            os.unlink(path)

    def test_nested_downloaded_documents_are_monitored(self):
        sender = Sender()
        collector = EmailThreatCollector(sender, {})
        collector._recent_webmail['profile'] = {
            'visited': time.time(), 'provider': 'Google Workspace / Gmail',
            'domain': 'mail.google.com', 'url': 'https://mail.google.com/mail/u/0/', 'username': 'analyst',
        }
        with tempfile.TemporaryDirectory() as root:
            nested = Path(root) / 'email-attachments' / 'invoice.docx'
            nested.parent.mkdir()
            nested.write_bytes(b'test document')
            with patch('collectors.email_threat._attachment_watch_roots', return_value=[(Path(root), 'downloads')]):
                collector._scan_downloads()
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'EMAIL_ATTACHMENT_DOWNLOADED')
        self.assertEqual(sender.events[0]['file_name'], 'invoice.docx')
        self.assertEqual(sender.events[0]['username'], 'analyst')
        self.assertEqual(sender.events[0]['raw']['webmail_provider'], 'Google Workspace / Gmail')
        self.assertEqual(sender.events[0]['raw']['mail_source_label'], 'Google Workspace / Gmail')
        self.assertEqual(sender.events[0]['url'], 'https://mail.google.com/mail/u/0/')
        self.assertFalse(sender.events[0]['raw']['content_collected'])

    def test_attachment_scan_is_recursive_and_ignores_untracked_types(self):
        with tempfile.TemporaryDirectory() as root:
            nested = Path(root) / 'one' / 'two'
            nested.mkdir(parents=True)
            document = nested / 'report.pdf'
            ignored = nested / 'photo.png'
            document.touch()
            ignored.touch()
            self.assertEqual(list(_iter_attachment_files(root)), [document])

    def test_postfix_metadata_parser(self):
        parsed = _parse_mail_line('postfix/smtp[12]: ABC123: from=<a@example.test>, to=<b@example.test>, status=bounced SPF=fail')
        self.assertEqual(parsed['queue_id'], 'ABC123')
        self.assertEqual(parsed['sender'], 'a@example.test')
        self.assertEqual(parsed['recipient'], 'b@example.test')
        self.assertEqual(parsed['status'], 'bounced')
        self.assertEqual(parsed['auth']['spf'], 'fail')

    def test_webmail_and_followed_link_emit_capability_15(self):
        sender = Sender()
        collector = EmailThreatCollector(sender, {})
        now = time.time()
        rows = [
            {'url': 'https://mail.google.com/mail/u/0/#inbox', 'title': 'Inbox', 'visited': now - 2},
            {'url': 'http://localhost:3000/company-admin/edr', 'title': 'SOC', 'visited': now - 1.5},
            {'url': 'http://login-check.example.zip/verify?token=secret', 'title': 'Verify account', 'visited': now - 1},
        ]
        with patch('collectors.email_threat._history_paths', return_value=[Path('/tmp/Profile/History')]), \
             patch('collectors.email_threat._read_chromium', return_value=rows), \
             patch('collectors.email_threat._profile_user', return_value='analyst'):
            collector._scan_webmail()
        self.assertEqual([item['rule_id'] for item in sender.events], ['EMAIL_WEBMAIL_SESSION', 'EMAIL_WEBMAIL_LINK_OPEN'])
        self.assertTrue(all(item['capabilityId'] == 15 for item in sender.events))
        self.assertEqual(sender.events[0]['raw']['mail_source_label'], 'Google Workspace / Gmail')
        self.assertEqual(sender.events[0]['raw']['monitored_user'], 'analyst')
        self.assertNotIn('token=secret', sender.events[1]['url'])
        self.assertTrue(sender.events[1]['actionable'])

    def test_custom_company_webmail_emits_capability_15(self):
        sender = Sender()
        collector = EmailThreatCollector(sender, {})
        rows = [{
            'url': 'https://webmail.example.org/roundcube/?session=private',
            'title': 'Roundcube Webmail',
            'visited': time.time(),
        }]
        with patch('collectors.email_threat._history_paths', return_value=[Path('/tmp/Profile/History')]), \
             patch('collectors.email_threat._read_chromium', return_value=rows), \
             patch('collectors.email_threat._profile_user', return_value='analyst'):
            collector._scan_webmail()
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'EMAIL_WEBMAIL_SESSION')
        self.assertEqual(sender.events[0]['capabilityId'], 15)
        self.assertEqual(sender.events[0]['raw']['provider'], 'Webmail (webmail.example.org)')
        self.assertNotIn('session=private', sender.events[0]['url'])

    def test_windows_service_discovers_interactive_user_browser_history(self):
        with tempfile.TemporaryDirectory() as root:
            home = Path(root) / 'analyst'
            history = home / 'AppData/Local/Google/Chrome/User Data/Default/History'
            history.parent.mkdir(parents=True)
            history.touch()
            self.assertEqual(_history_paths([home], 'Windows'), [history])

    def test_chromium_reader_includes_uncheckpointed_wal_visits(self):
        with tempfile.TemporaryDirectory() as root:
            history = Path(root) / 'History'
            conn = sqlite3.connect(history)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA wal_autocheckpoint=0')
            conn.execute('CREATE TABLE urls (url TEXT, title TEXT, last_visit_time INTEGER)')
            now = time.time()
            chromium_time = int((now + 11644473600) * 1000000)
            conn.execute('INSERT INTO urls VALUES (?, ?, ?)', ('https://mail.google.com/mail/u/0/#inbox', 'Inbox', chromium_time))
            conn.commit()
            try:
                rows = _read_chromium(history, now - 10)
            finally:
                conn.close()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['url'], 'https://mail.google.com/mail/u/0/#inbox')


if __name__ == '__main__':
    unittest.main()
