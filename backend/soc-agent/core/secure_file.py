"""Atomic AES-256-GCM persistence for agent-owned JSON and text files."""

import json
import os
import tempfile
from pathlib import Path

from .aes256 import AES256GCM


def _cipher(encryption_key: str, purpose: str) -> AES256GCM:
    if not encryption_key:
        raise ValueError(f'AES-256 key is required for {purpose}')
    return AES256GCM(encryption_key, purpose)


def load_json(path, encryption_key: str, purpose: str, default):
    target = Path(path)
    if not target.exists():
        return default
    stored = target.read_text(encoding='utf-8').strip()
    plaintext = _cipher(encryption_key, purpose).decrypt(stored)
    value = json.loads(plaintext)
    # One-time in-place migration of legacy plaintext data. Subsequent reads
    # are authenticated and reject modified ciphertext.
    if stored and not stored.startswith('enc:v1:'):
        save_json(target, value, encryption_key, purpose)
    return value


def save_json(path, value, encryption_key: str, purpose: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    envelope = _cipher(encryption_key, purpose).encrypt(
        json.dumps(value, separators=(',', ':'), sort_keys=True, default=str)
    )
    fd, temporary = tempfile.mkstemp(prefix=f'.{target.name}.', dir=str(target.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(envelope)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, target)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
