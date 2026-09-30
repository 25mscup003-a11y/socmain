"""Line-oriented AES-256-GCM logging for the endpoint agent."""

import logging
import copy
from logging.handlers import RotatingFileHandler

from .aes256 import AES256GCM, PREFIX


class EncryptedRotatingFileHandler(RotatingFileHandler):
    """Write one authenticated AES envelope per log record."""

    def __init__(self, filename, encryption_key: str, maxBytes=0, backupCount=0):
        self._cipher = AES256GCM(encryption_key, 'agent-runtime-log')
        self._plaintext_formatter = logging.Formatter()
        self._migrate_plaintext(filename)
        super().__init__(filename, maxBytes=maxBytes, backupCount=backupCount, encoding='utf-8')

    def setFormatter(self, fmt):
        self._plaintext_formatter = fmt
        super().setFormatter(logging.Formatter('%(message)s'))

    def _migrate_plaintext(self, filename):
        try:
            with open(filename, encoding='utf-8', errors='replace') as handle:
                content = handle.read()
            if content and not all(line.startswith(PREFIX) for line in content.splitlines() if line):
                with open(filename, 'w', encoding='utf-8') as handle:
                    handle.write(self._cipher.encrypt(content))
                    handle.write('\n')
        except FileNotFoundError:
            pass

    def emit(self, record):
        try:
            encrypted_record = copy.copy(record)
            encrypted_record.msg = self._cipher.encrypt(
                self._plaintext_formatter.format(record)
            )
            encrypted_record.args = ()
            super().emit(encrypted_record)
        except Exception:
            self.handleError(record)
