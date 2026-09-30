"""AES-256-GCM helpers for sensitive agent data stored at rest."""

import base64
import hashlib
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PREFIX = 'enc:v1:'


class AES256GCM:
    """Authenticated AES-256 encryption with a purpose-separated key."""

    def __init__(self, secret: str, purpose: str):
        if not secret:
            raise ValueError('AES-256 encryption secret is required')
        self._purpose = purpose.encode('utf-8')
        # A full 32-byte key is derived without storing another plaintext key.
        self._key = hashlib.sha256(
            b'AJNAT-AES-256-GCM\x00' + self._purpose + b'\x00' + secret.encode('utf-8')
        ).digest()
        self._aes = AESGCM(self._key)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(12)  # NIST-recommended nonce size for GCM
        ciphertext = self._aes.encrypt(nonce, plaintext.encode('utf-8'), self._purpose)
        return PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode('ascii')

    def decrypt(self, value: str) -> str:
        if not value.startswith(PREFIX):
            return value  # legacy plaintext migration compatibility
        raw = base64.urlsafe_b64decode(value[len(PREFIX):].encode('ascii'))
        if len(raw) < 29:
            raise ValueError('invalid AES-256-GCM envelope')
        return self._aes.decrypt(raw[:12], raw[12:], self._purpose).decode('utf-8')
