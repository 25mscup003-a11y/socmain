import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from core.config import AgentConfig
from core.config_protection import is_encrypted_config, key_path, load_config, save_config


class ConfigProtectionTests(unittest.TestCase):
    def test_plaintext_config_is_migrated_to_aes256_gcm(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'company_config.json'
            original = {
                'company_id': 'company-1',
                'system_id': 'system-1',
                'agent_key': 'top-secret-agent-key',
                'integration_secret': 'top-secret-integration-key',
                'server_url': 'https://soc.example.test:5000',
            }
            path.write_text(json.dumps(original), encoding='utf-8')

            config = AgentConfig(path)

            ciphertext = path.read_text(encoding='utf-8')
            self.assertTrue(is_encrypted_config(ciphertext))
            self.assertNotIn('top-secret-agent-key', ciphertext)
            self.assertNotIn('top-secret-integration-key', ciphertext)
            self.assertEqual(config.get('system_id'), 'system-1')
            self.assertEqual(load_config(path)['agent_key'], 'top-secret-agent-key')
            config.update_runtime({'agent_version': '9.9.9'})
            self.assertEqual(load_config(path)['agent_version'], '9.9.9')
            self.assertTrue(is_encrypted_config(path.read_text(encoding='utf-8')))
            self.assertTrue(key_path(path).exists())
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE(key_path(path).stat().st_mode), 0o600)

    def test_encrypted_config_round_trip_and_tamper_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'company_config.json'
            save_config(path, {'system_id': 'system-2', 'agent_key': 'secret-2'})
            self.assertEqual(load_config(path)['system_id'], 'system-2')

            ciphertext = path.read_text(encoding='utf-8')
            replacement = 'A' if ciphertext[-3] != 'A' else 'B'
            path.write_text(ciphertext[:-3] + replacement + ciphertext[-2:], encoding='utf-8')
            with self.assertRaises(Exception):
                load_config(path)
            with self.assertRaisesRegex(RuntimeError, 'authentication failed'):
                AgentConfig(path)


if __name__ == '__main__':
    unittest.main()
