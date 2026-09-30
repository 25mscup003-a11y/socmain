"""AES-256-GCM protection for the installed AJNAT enrollment configuration.

The encrypted configuration and its wrapping key are deliberately separate.
On Windows the wrapping key is protected with machine-scoped DPAPI. On POSIX
systems it is stored in a root-only sidecar file; full protection against a
root compromise additionally requires TPM-backed disk encryption.
"""

import base64
import ctypes
import json
import os
import platform
import tempfile
from pathlib import Path

from .aes256 import AES256GCM, PREFIX


PURPOSE = 'company-config'
KEY_PREFIX_RAW = 'raw:v1:'
KEY_PREFIX_DPAPI = 'dpapi-machine:v1:'


class _DataBlob(ctypes.Structure):
    _fields_ = [('cbData', ctypes.c_ulong), ('pbData', ctypes.POINTER(ctypes.c_ubyte))]


def _blob(value: bytes):
    buffer = ctypes.create_string_buffer(value)
    return _DataBlob(len(value), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_ubyte))), buffer


def _dpapi_protect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(b'AJNAT-CONFIG-KEY-V1')
    output = _DataBlob()
    # Keep buffers alive until CryptProtectData returns.
    _ = source_buffer, entropy_buffer
    ok = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(source), 'AJNAT agent configuration key', ctypes.byref(entropy),
        None, None, 0x1 | 0x4, ctypes.byref(output),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def _dpapi_unprotect(value: bytes) -> bytes:
    source, source_buffer = _blob(value)
    entropy, entropy_buffer = _blob(b'AJNAT-CONFIG-KEY-V1')
    output = _DataBlob()
    _ = source_buffer, entropy_buffer
    ok = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(source), None, ctypes.byref(entropy),
        None, None, 0x1, ctypes.byref(output),
    )
    if not ok:
        raise ctypes.WinError()
    try:
        return ctypes.string_at(output.pbData, output.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(output.pbData)


def key_path(config_path) -> Path:
    target = Path(config_path)
    return target.with_name(f'{target.name}.key')


def _encode_key(key: bytes) -> str:
    if platform.system() == 'Windows':
        return KEY_PREFIX_DPAPI + base64.b64encode(_dpapi_protect(key)).decode('ascii')
    return KEY_PREFIX_RAW + base64.b64encode(key).decode('ascii')


def _decode_key(stored: str) -> bytes:
    if stored.startswith(KEY_PREFIX_DPAPI):
        if platform.system() != 'Windows':
            raise RuntimeError('DPAPI-protected AJNAT config key can only be opened on Windows')
        key = _dpapi_unprotect(base64.b64decode(stored[len(KEY_PREFIX_DPAPI):], validate=True))
    elif stored.startswith(KEY_PREFIX_RAW):
        key = base64.b64decode(stored[len(KEY_PREFIX_RAW):], validate=True)
    else:
        raise RuntimeError('Unsupported AJNAT config key format')
    if len(key) != 32:
        raise RuntimeError('AJNAT config key is not AES-256')
    return key


def _atomic_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f'.{path.name}.', dir=str(path.parent))
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.chmod(temporary, mode)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _load_or_create_key(config_path) -> bytes:
    target = key_path(config_path)
    try:
        stored = target.read_text(encoding='utf-8').strip()
        return _decode_key(stored)
    except FileNotFoundError:
        pass

    key = os.urandom(32)
    encoded = _encode_key(key)
    target.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        return _decode_key(target.read_text(encoding='utf-8').strip())
    try:
        with os.fdopen(descriptor, 'w', encoding='utf-8') as handle:
            handle.write(encoded)
            handle.write('\n')
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            target.unlink()
        except FileNotFoundError:
            pass
        raise
    return key


def config_key_password(config_path) -> str:
    """Return a process-only password derived from the machine-bound key."""
    return base64.urlsafe_b64encode(_load_or_create_key(config_path)).decode('ascii')


def is_encrypted_config(content: str) -> bool:
    return str(content or '').strip().startswith(PREFIX)


def load_config(path) -> dict:
    target = Path(path)
    stored = target.read_text(encoding='utf-8').strip()
    if is_encrypted_config(stored):
        key = _load_or_create_key(target)
        secret = base64.b64encode(key).decode('ascii')
        stored = AES256GCM(secret, PURPOSE).decrypt(stored)
    value = json.loads(stored)
    if not isinstance(value, dict):
        raise ValueError('AJNAT company configuration must be a JSON object')
    return value


def save_config(path, value: dict) -> None:
    if not isinstance(value, dict):
        raise ValueError('AJNAT company configuration must be a dictionary')
    target = Path(path)
    key = _load_or_create_key(target)
    secret = base64.b64encode(key).decode('ascii')
    plaintext = json.dumps(value, separators=(',', ':'), sort_keys=True, default=str)
    _atomic_write(target, AES256GCM(secret, PURPOSE).encrypt(plaintext) + '\n')


def protect_config(path) -> bool:
    target = Path(path)
    stored = target.read_text(encoding='utf-8').strip()
    if is_encrypted_config(stored):
        # Authenticate it now so a damaged file is detected during install.
        load_config(target)
        return False
    save_config(target, json.loads(stored))
    return True
