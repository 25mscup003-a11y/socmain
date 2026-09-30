import logging
import tempfile
import unittest
from pathlib import Path

from core.encrypted_logging import EncryptedRotatingFileHandler
from core.secure_file import load_json, save_json


class SecureFileTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.key = 'test-key-material-' * 4

    def tearDown(self):
        self.temp.cleanup()

    def test_json_is_aes256_encrypted_and_round_trips(self):
        path = self.root / 'state.json'
        value = {'secret': 'sensitive-agent-data', 'count': 3}
        save_json(path, value, self.key, 'test-state')

        stored = path.read_text(encoding='utf-8')
        self.assertTrue(stored.startswith('enc:v1:'))
        self.assertNotIn('sensitive-agent-data', stored)
        self.assertEqual(load_json(path, self.key, 'test-state', {}), value)

    def test_legacy_plaintext_json_is_migrated_on_first_read(self):
        path = self.root / 'legacy.json'
        path.write_text('{"legacy":true}', encoding='utf-8')
        value = load_json(path, self.key, 'legacy-state', {})
        self.assertEqual(value, {'legacy': True})
        self.assertTrue(path.read_text(encoding='utf-8').startswith('enc:v1:'))

    def test_runtime_log_contains_no_plaintext(self):
        path = self.root / 'agent.log'
        handler = EncryptedRotatingFileHandler(path, self.key, maxBytes=4096, backupCount=1)
        handler.setFormatter(logging.Formatter('%(levelname)s %(message)s'))
        logger = logging.getLogger(f'encrypted-log-{id(self)}')
        logger.propagate = False
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.info('credential-like-sensitive-value')
        handler.close()

        stored = path.read_text(encoding='utf-8')
        self.assertTrue(stored.startswith('enc:v1:'))
        self.assertNotIn('credential-like-sensitive-value', stored)


if __name__ == '__main__':
    unittest.main()
