# Threat Model

## Assets

Tenant logs, alerts, endpoint identities, agent commands, KYC/payment documents,
API keys, sessions, detection rules and audit records.

| Threat | Required control |
|---|---|
| Cross-tenant IDOR/query | server-derived scope, mandatory tenant filter, negative authorization tests |
| Socket subscription theft | authenticated handshake and authorized rooms |
| Forged/replayed agent events | rotated per-agent credential or mTLS, timestamp, nonce and event ID |
| Global integration secret compromise | per-company hashed ingestion keys and source scopes |
| Payload/compression DoS | inflated-byte limit, event cap, rate limit and 413/429 shedding |
| SSRF | URL allowlist, DNS/IP validation, egress proxy, private-range denial |
| Command/path injection | structured process calls, allowlists, canonical containment |
| Document disclosure | authenticated object access or short-lived signed URLs |
| Token theft/XSS | CSP, encoding, short access token and secure refresh cookie |
| Insider alteration | append-only audit exported to immutable storage |

## Open P0 items

1. Private upload authorization.
2. Per-tenant integration credentials.
3. Shared replay/idempotency state across replicas.
4. Raw reusable agent key replacement and rotation.
