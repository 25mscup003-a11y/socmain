import base64
import json
import unittest

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.secure_transport import (
    _RESPONSE_AAD,
    _transport_key,
    certificate_status,
    decrypt_api_response,
    encrypt_api_payload,
)


class SecureTransportEncryptionTests(unittest.TestCase):
    AGENT_KEY = '0123456789abcdef' * 4

    def test_request_envelope_is_aes_256_gcm_and_hides_plaintext(self):
        payload = {'agent_key': self.AGENT_KEY, 'severity': 'critical', 'count': 7}
        envelope = encrypt_api_payload(payload, self.AGENT_KEY)

        self.assertEqual(len(_transport_key(self.AGENT_KEY)), 32)
        self.assertEqual(envelope['alg'], 'A256GCM')
        self.assertEqual(len(base64.b64decode(envelope['nonce'])), 12)
        self.assertEqual(len(base64.b64decode(envelope['tag'])), 16)
        self.assertNotIn('critical', json.dumps(envelope))

    def test_response_authentication_rejects_tampering(self):
        nonce = bytes(range(12))
        plaintext = b'{"active":true}'
        sealed = AESGCM(_transport_key(self.AGENT_KEY)).encrypt(
            nonce, plaintext, _RESPONSE_AAD,
        )
        envelope = {
            'v': 1,
            'alg': 'A256GCM',
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(sealed[:-16]).decode(),
            'tag': base64.b64encode(sealed[-16:]).decode(),
        }
        self.assertEqual(decrypt_api_response(envelope, self.AGENT_KEY), plaintext)
        envelope['tag'] = base64.b64encode(b'0' * 16).decode()
        with self.assertRaises(RuntimeError):
            decrypt_api_response(envelope, self.AGENT_KEY)

    def test_status_reports_runtime_encryption_capabilities(self):
        class Config(dict):
            @staticmethod
            def is_configuration_encrypted():
                return True

        status = certificate_status(Config(require_tls=False))

        self.assertFalse(status['tls_required'])
        self.assertTrue(status['configuration_encrypted'])
        self.assertEqual(status['api_payload_encryption'], 'aes-256-gcm-v1')


if __name__ == '__main__':
    unittest.main()
