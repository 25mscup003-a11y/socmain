import importlib.util
import os
import sys
import unittest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE_PATH = os.path.join(ROOT, 'collectors', 'credential_security.py')
spec = importlib.util.spec_from_file_location('credential_security_collector', MODULE_PATH)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class CredentialSecurityCollectorTests(unittest.TestCase):
    def test_detects_lsass_dump_without_collecting_secrets(self):
        finding = module._match_process('procdump.exe', 'procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp')
        self.assertEqual(finding['rule_id'], 'CRED_LSASS_DUMP')
        self.assertEqual(finding['mitre_id'], 'T1003.001')

    def test_detects_linux_secret_file_command(self):
        finding = module._match_process('cat', 'cat /etc/shadow')
        self.assertEqual(finding['rule_id'], 'CRED_UNIX_SECRET_FILE_ACCESS')

    def test_benign_process_does_not_generate_finding(self):
        self.assertIsNone(module._match_process('python3', 'python3 worker.py'))

    def test_policy_can_disable_rule_and_override_severity(self):
        class Sender:
            def __init__(self):
                self.events = []

            def enqueue(self, event):
                self.events.append(event)

        sender = Sender()
        collector = module.CredentialSecurityCollector(sender, {
            'credential_enabled_rule_ids': ['CRED_LSASS_DUMP'],
            'credential_rule_overrides': {'CRED_LSASS_DUMP': {'severity': 'high'}},
            'credential_minimum_risk_score': 90,
        })
        collector._emit(rule_id='CRED_WINDOWS_VAULT_ACCESS', severity='high', risk_score=95)
        collector._emit(rule_id='CRED_LSASS_DUMP', severity='critical', risk_score=99)
        self.assertEqual(len(sender.events), 1)
        self.assertEqual(sender.events[0]['rule_id'], 'CRED_LSASS_DUMP')
        self.assertEqual(sender.events[0]['severity'], 'high')


if __name__ == '__main__':
    unittest.main()
