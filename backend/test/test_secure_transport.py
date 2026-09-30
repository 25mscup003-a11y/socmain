import pytest

from core.secure_transport import FingerprintAdapter, certificate_status, secure_request, secure_session


def test_plaintext_transport_is_rejected_by_default():
    with pytest.raises(RuntimeError, match='HTTPS is required'):
        secure_request({}, 'GET', 'http://soc.example.test/api/agent/heartbeat')


def test_plaintext_session_is_rejected_when_tls_is_required():
    with pytest.raises(RuntimeError, match='HTTPS is required'):
        secure_session({'server_url': 'http://soc.example.test'})


def test_certificate_pin_must_be_sha256():
    with pytest.raises(ValueError, match='SHA-256'):
        FingerprintAdapter('not-a-valid-pin')
    FingerprintAdapter('ab' * 32).close()


def test_adapter_allows_client_ssl_context_without_server_pin():
    import ssl
    adapter = FingerprintAdapter('', ssl_context=ssl.create_default_context())
    adapter.close()


def test_transport_does_not_claim_certificate_renewal():
    status = certificate_status({'require_tls': True, 'mtls_auto_renew': True})
    assert status == {
        'tls_required': True,
        'mtls_configured': False,
        'certificate_pinning': False,
        'renewal_managed': False,
    }
