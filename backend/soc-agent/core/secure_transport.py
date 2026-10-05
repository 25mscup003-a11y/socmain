"""Hardened TLS plus AES-256-GCM agent-to-server communication."""

import base64
import hashlib
import hmac
import json
import os
import threading
from urllib.parse import urlparse

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from requests.adapters import HTTPAdapter

from .security import signed_headers


_SESSIONS = {}
_LOCK = threading.Lock()
TRANSPORT_VERSION = 'aes-256-gcm-v1'
TRANSPORT_HEADER = 'x-ajnat-payload-encryption'
SYSTEM_HEADER = 'x-agent-system-id'
ORIGINAL_CONTENT_TYPE_HEADER = 'x-ajnat-original-content-type'
_KEY_DOMAIN = b'AJNAT-AGENT-API-AES-256-GCM-V1\x00'
_REQUEST_AAD = b'AJNAT-AGENT-API-REQUEST-V1'
_RESPONSE_AAD = b'AJNAT-AGENT-API-RESPONSE-V1'


def _transport_key(agent_key):
    secret = str(agent_key or '')
    if not secret:
        raise RuntimeError('AJNAT agent_key is required for encrypted API transport')
    return hashlib.sha256(_KEY_DOMAIN + secret.encode('utf-8')).digest()


def encrypt_api_payload(payload, agent_key):
    """Return the interoperable JSON envelope sent to the AJNAT API."""
    nonce = os.urandom(12)
    plaintext = json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode('utf-8')
    sealed = AESGCM(_transport_key(agent_key)).encrypt(nonce, plaintext, _REQUEST_AAD)
    return {
        'v': 1,
        'alg': 'A256GCM',
        'nonce': base64.b64encode(nonce).decode('ascii'),
        'ciphertext': base64.b64encode(sealed[:-16]).decode('ascii'),
        'tag': base64.b64encode(sealed[-16:]).decode('ascii'),
    }


def decrypt_api_response(envelope, agent_key):
    """Authenticate and decrypt an AJNAT API response envelope."""
    if not isinstance(envelope, dict) or envelope.get('v') != 1 or envelope.get('alg') != 'A256GCM':
        raise RuntimeError('Unsupported encrypted AJNAT API response')
    try:
        nonce = base64.b64decode(envelope['nonce'], validate=True)
        ciphertext = base64.b64decode(envelope['ciphertext'], validate=True)
        tag = base64.b64decode(envelope['tag'], validate=True)
    except (KeyError, ValueError, TypeError) as error:
        raise RuntimeError('Invalid encrypted AJNAT API response') from error
    if len(nonce) != 12 or len(tag) != 16:
        raise RuntimeError('Invalid encrypted AJNAT API nonce or tag')
    try:
        return AESGCM(_transport_key(agent_key)).decrypt(
            nonce, ciphertext + tag, _RESPONSE_AAD,
        )
    except Exception as error:
        raise RuntimeError('AJNAT API response authentication failed') from error


class FingerprintAdapter(HTTPAdapter):
    def __init__(self, fingerprint: str = '', ssl_context=None, *args, **kwargs):
        self._fingerprint = fingerprint.replace(':', '').lower()
        if self._fingerprint and (len(self._fingerprint) != 64 or any(c not in '0123456789abcdef' for c in self._fingerprint)):
            raise ValueError('tls_server_sha256 must be a SHA-256 certificate fingerprint')
        self._ssl_context = ssl_context
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        if self._fingerprint:
            kwargs['assert_fingerprint'] = self._fingerprint
        if self._ssl_context is not None:
            kwargs['ssl_context'] = self._ssl_context
        return super().init_poolmanager(*args, **kwargs)


def _file(config, key):
    value = str(config.get(key, '') or '').strip()
    if not value:
        return ''
    filename = os.path.abspath(os.path.expandvars(value))
    if not os.path.isfile(filename):
        raise RuntimeError(f'{key} does not reference a readable file')
    return filename


def _session(config):
    ca = _file(config, 'tls_ca_bundle') or True
    cert = _file(config, 'mtls_client_cert')
    key = _file(config, 'mtls_client_key')
    if bool(cert) != bool(key):
        raise RuntimeError('Both mtls_client_cert and mtls_client_key are required')
    pin = str(config.get('tls_server_sha256', '') or '').strip()
    cache_key = hashlib.sha256(f'{ca}|{cert}|{key}|{pin}'.encode()).hexdigest()
    with _LOCK:
        session = _SESSIONS.get(cache_key)
        if session is None:
            session = requests.Session()
            session.verify = ca
            if cert:
                import ssl
                context = ssl.create_default_context(cafile=ca if isinstance(ca, str) else None)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(
                    certfile=cert,
                    keyfile=key,
                    password=str(config.get('mtls_client_key_password', '') or '') or None,
                )
                session.mount('https://', FingerprintAdapter(
                    pin, ssl_context=context, pool_connections=4, pool_maxsize=8, max_retries=0,
                ))
            elif pin:
                session.mount('https://', FingerprintAdapter(pin, pool_connections=4, pool_maxsize=8, max_retries=0))
            _SESSIONS[cache_key] = session
        return session


def secure_request(config, method, url, **kwargs):
    parsed = urlparse(url)
    if config.get('require_tls', True) and parsed.scheme.lower() != 'https':
        raise RuntimeError('Refusing plaintext agent transport; HTTPS is required')
    if parsed.scheme.lower() not in ('https', 'http'):
        raise RuntimeError('Unsupported agent transport scheme')
    if kwargs.get('verify') is False:
        raise RuntimeError('TLS certificate verification cannot be disabled')

    # Protect all AJNAT API control-plane JSON independently of HTTP/TLS. TLS
    # remains required by default because it also hides URLs and headers.
    if parsed.path.startswith('/api/'):
        agent_key = str(config.get('agent_key', '') or '')
        system_id = str(config.get('system_id', '') or '')
        if not agent_key or not system_id:
            raise RuntimeError('agent_key and system_id are required for encrypted API transport')

        headers = dict(kwargs.pop('headers', {}) or {})
        # Encrypted, signed requests do not send the legacy fleet-wide secret.
        for name in list(headers):
            if name.lower() in ('x-integration-secret', 'content-length'):
                headers.pop(name, None)
        if 'json' in kwargs:
            envelope = encrypt_api_payload(kwargs['json'], agent_key)
            kwargs['json'] = envelope
            headers.update(signed_headers(config, envelope))
        else:
            headers.update(signed_headers(config, {}))
        headers.pop('x-integration-secret', None)
        headers[TRANSPORT_HEADER] = TRANSPORT_VERSION
        headers[SYSTEM_HEADER] = system_id
        kwargs['headers'] = headers
        kwargs['allow_redirects'] = False

        response = _session(config).request(method=method, url=url, **kwargs)
        encrypted_response = str(response.headers.get(TRANSPORT_HEADER, '')).lower() == TRANSPORT_VERSION
        if response.ok:
            digest = str(response.headers.get('X-AJNAT-Response-SHA256', ''))
            signature = str(response.headers.get('X-AJNAT-Response-Signature', ''))
            expected = hmac.new(agent_key.encode(), f"AJNAT-RESPONSE-V1.{headers['x-agent-nonce']}.{response.status_code}.{digest}".encode(), hashlib.sha256).hexdigest()
            if len(digest) != 64 or not hmac.compare_digest(expected, signature):
                raise RuntimeError('AJNAT response signature missing, invalid or replayed')
            if encrypted_response:
                if not hmac.compare_digest(hashlib.sha256(response.content).hexdigest(), digest):
                    raise RuntimeError('AJNAT response digest mismatch')
            elif not kwargs.get('stream') or response.headers.get('X-AJNAT-Artifact-SHA256') != digest:
                raise RuntimeError('Refusing unauthenticated plaintext API response')
        if encrypted_response:
            # Reading content here also safely supports callers that requested a
            # streamed response; encrypted JSON must authenticate before use.
            encrypted = json.loads(response.content.decode('utf-8'))
            response._content = decrypt_api_response(encrypted, agent_key)
            response._content_consumed = True
            original_type = response.headers.get(ORIGINAL_CONTENT_TYPE_HEADER)
            if original_type:
                response.headers['Content-Type'] = original_type
            response.headers['Content-Length'] = str(len(response._content))
        return response

    return _session(config).request(method=method, url=url, **kwargs)


def secure_session(config):
    """Return the pooled TLS/mTLS session for Socket.IO and streaming clients."""
    server_url = str(config.get('server_url', '') or '')
    if config.get('require_tls', True) and urlparse(server_url).scheme.lower() != 'https':
        raise RuntimeError('Refusing plaintext agent transport; HTTPS is required')
    return _session(config)


def certificate_status(config):
    cert = _file(config, 'mtls_client_cert')
    key = _file(config, 'mtls_client_key')
    encrypted_config_check = getattr(config, 'is_configuration_encrypted', None)
    configuration_encrypted = bool(
        callable(encrypted_config_check) and encrypted_config_check()
    )
    return {
        'tls_required': bool(config.get('require_tls', True)),
        'mtls_configured': bool(cert and key),
        'certificate_pinning': bool(config.get('tls_server_sha256', '')),
        'configuration_encrypted': configuration_encrypted,
        'api_payload_encryption': TRANSPORT_VERSION,
        # Automatic renewal is not implemented yet. Report the real state
        # instead of treating a configuration preference as proof it works.
        'renewal_managed': False,
    }
