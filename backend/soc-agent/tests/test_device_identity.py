import os
import stat
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from core.config import AgentConfig
from core.device_identity import certificate_fingerprint, ensure_device_identity
from core.secure_transport import secure_session


class DeviceIdentityTests(unittest.TestCase):
    def test_unique_certificate_and_encrypted_private_key_are_persisted(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / 'company_config.json'
            config_path.write_text(
                '{"system_id":"0123456789abcdef01234567","agent_key":"secret",'
                '"server_url":"https://soc.example.test:5000"}',
                encoding='utf-8',
            )
            config = AgentConfig(config_path)

            identity = ensure_device_identity(config)
            private_path = Path(identity['mtls_client_key'])
            certificate_path = Path(identity['mtls_client_cert'])

            self.assertTrue(private_path.exists())
            self.assertTrue(certificate_path.exists())
            self.assertIn(b'BEGIN ENCRYPTED PRIVATE KEY', private_path.read_bytes())
            with self.assertRaises((TypeError, ValueError)):
                serialization.load_pem_private_key(private_path.read_bytes(), password=None)
            key = serialization.load_pem_private_key(
                private_path.read_bytes(),
                password=config.get('mtls_client_key_password').encode('utf-8'),
            )
            self.assertIsNotNone(key)
            self.assertEqual(identity['fingerprint256'], certificate_fingerprint(certificate_path))
            self.assertEqual(ensure_device_identity(config)['fingerprint256'], identity['fingerprint256'])
            session = secure_session(config)
            self.assertIsNotNone(session.get_adapter('https://')._ssl_context)
            session.close()
            if os.name != 'nt':
                self.assertEqual(stat.S_IMODE(private_path.stat().st_mode), 0o600)


if __name__ == '__main__':
    unittest.main()
