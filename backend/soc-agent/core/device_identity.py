"""Unique client-certificate identity for AJNAT mTLS endpoints."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .config_protection import config_key_password
from .secure_transport import secure_request


def _identity_directory(config) -> Path:
    configured = str(config.get('mtls_identity_dir', '') or '').strip()
    if configured:
        return Path(os.path.expandvars(configured))
    config_path = Path(getattr(config, '_path', Path('config/company_config.json')))
    return config_path.parent / 'identity'


def _write_private(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        raise


def _write_public(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
    with os.fdopen(descriptor, 'wb') as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def certificate_fingerprint(path) -> str:
    certificate = x509.load_pem_x509_certificate(Path(path).read_bytes())
    return certificate.fingerprint(hashes.SHA256()).hex()


def ensure_device_identity(config) -> dict:
    """Create a unique EC client identity and persist only protected paths."""
    system_id = str(config.get('system_id', '') or '').strip()
    if not system_id:
        raise RuntimeError('system_id is required for mTLS identity enrollment')

    identity_dir = _identity_directory(config)
    private_path = identity_dir / 'agent-client-key.pem'
    certificate_path = identity_dir / 'agent-client-cert.pem'
    private_password = config_key_password(getattr(config, '_path', Path('config/company_config.json')))

    identity_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(identity_dir, 0o700)
    except OSError:
        pass

    if private_path.exists():
        private_key = serialization.load_pem_private_key(
            private_path.read_bytes(), password=private_password.encode('utf-8'),
        )
    else:
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(private_password.encode('utf-8')),
        )
        _write_private(private_path, private_pem)

    if not certificate_path.exists():
        now = datetime.now(timezone.utc)
        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'AJNAT SOC'),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, 'Endpoint Agent'),
            x509.NameAttribute(NameOID.COMMON_NAME, f'AJNAT-{system_id}'),
        ])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=True,
            )
            .add_extension(
                x509.UnrecognizedExtension(
                    x509.ObjectIdentifier('1.3.6.1.4.1.57264.1.1'),
                    system_id.encode('utf-8'),
                ),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )
        certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)
        _write_public(certificate_path, certificate_pem)

    certificate = x509.load_pem_x509_certificate(certificate_path.read_bytes())
    expected_cn = f'AJNAT-{system_id}'
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not common_names or common_names[0].value != expected_cn:
        raise RuntimeError('AJNAT client certificate identity does not match system_id')
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != private_public:
        raise RuntimeError('AJNAT client certificate/private key mismatch')

    updates = {
        'mtls_client_cert': str(certificate_path),
        'mtls_client_key': str(private_path),
        'mtls_client_key_password': private_password,
    }
    config.update_runtime(updates, persist=True)
    return {
        **updates,
        'fingerprint256': certificate.fingerprint(hashes.SHA256()).hex(),
        'serial': format(certificate.serial_number, 'x'),
        'expires_at': certificate.not_valid_after_utc.isoformat(),
    }


def enroll_device_certificate(config) -> dict:
    """Pin this endpoint's presented mTLS certificate to its System record."""
    server_url = str(config.get('server_url', '') or '').rstrip('/')
    if not server_url.lower().startswith('https://'):
        raise RuntimeError('mTLS enrollment requires an HTTPS AJNAT server URL')
    identity = ensure_device_identity(config)
    payload = {
        'agent_key': config.get('agent_key', ''),
        'system_id': config.get('system_id', ''),
        'certificate_fingerprint256': identity['fingerprint256'],
    }
    response = secure_request(
        config, 'POST', f'{server_url}/api/agent/certificate/enroll',
        json=payload, timeout=15,
    )
    response.raise_for_status()
    result = response.json()
    if str(result.get('fingerprint256', '')).lower() != identity['fingerprint256']:
        raise RuntimeError('Server confirmed a different AJNAT client certificate')
    return result
