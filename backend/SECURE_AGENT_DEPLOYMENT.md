# AJNAT agent transport and storage security

Installed desktop agents migrate `config/company_config.json` to an
authenticated AES-256-GCM envelope on first start. The adjacent
`company_config.json.key` is mode `0600` on POSIX. On Windows its 256-bit key is
wrapped with machine-scoped DPAPI. Runtime logs, state, policy caches, and the
durable event spool are also AES-256-GCM protected.

Agent program files cannot remain encrypted while Python executes them. They
are protected by the signed installer, the packaged SHA-256 integrity manifest,
restricted installation permissions, and runtime integrity reporting. Use
BitLocker, LUKS, FileVault, or TPM-backed full-disk encryption when source-code
confidentiality against offline disk access is required.

## Enabling unique client certificates

mTLS requires HTTPS. Configure a server certificate first, then enable optional
certificate enrollment while existing agents upgrade:

```env
SERVER_PROTO=https
TLS_ENABLED=true
TLS_PRIVATE_KEY_FILE=/run/secrets/server-tls.key
TLS_CERTIFICATE_FILE=/run/secrets/server-tls.crt
AGENT_SERVER_CA_BUNDLE_FILE=/run/secrets/server-ca-chain.pem
AGENT_MTLS_ENABLED=true
AGENT_MTLS_REQUIRED=false
```

Download/install the current agent and wait for certificate enrollment. Every
endpoint creates its own encrypted EC private key and presents its unique
certificate. The API pins the SHA-256 fingerprint to that System record.

After the fleet has enrolled, enforce certificates:

```env
AGENT_MTLS_ENABLED=true
AGENT_MTLS_REQUIRED=true
```

Set `AGENT_MTLS_REQUIRE_CA_VALIDATION=true` only when client certificates are
issued by a CA configured through `TLS_CA_FILE`. The built-in enrollment model
uses unique self-signed certificates plus server-side fingerprint pinning.

A company administrator can immediately revoke an enrolled endpoint identity:

```text
POST /api/agent/:systemId/certificate/revoke
```

Revocation keeps the old fingerprint for audit and prevents a stolen agent key
from silently enrolling a replacement certificate.
