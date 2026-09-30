# Credential Security Monitoring (Capability 13)

Capability 13 extends the existing SOC with tenant-scoped credential and identity telemetry. It reuses JWT authentication, analyst/company-admin RBAC, the Alert collection, existing capability indexes, automated response approvals, audit logging, Socket.IO company rooms, and the endpoint sender's durable queue.

## Agent coverage

- Windows Security events and cross-platform authentication logs are parsed by the existing log collector and tagged with capabilities 4 and 13.
- The credential collector observes new process metadata for credential dumping, LSASS/SAM access, Kerberos abuse, Pass-the-Hash, Vault/Keychain access, browser-password-store references, and Unix secret-file commands.
- Credential-store monitoring compares file metadata only. Passwords, tokens, cookies, private keys, LSASS memory, browser databases and file contents are never collected.
- Cloud IAM, MFA and identity-provider events are accepted when forwarded through an authorized identity/audit-log integration; the endpoint agent does not impersonate a cloud connector.

## APIs and realtime

- `GET /api/credential-security/dashboard`
- `GET /api/credential-security/live`
- `GET /api/credential-security/logs`
- `GET /api/credential-security/log/:id`
- `GET /api/credential-security/reports`
- `POST /api/credential-security/respond`
- `POST /api/credential-security/export`
- Socket.IO event: `credential:event`

## Automatic monitoring

Capability 13 has no dashboard configuration dependency. Whenever EDR is enabled for an endpoint, all credential process telemetry, credential-store metadata monitoring, and lock-screen authentication rules are enabled automatically through the signed heartbeat policy. The server uses a bounded 20-second default collection interval (overrideable only by the deployment environment) and does not suppress events by risk score.

The agent records Windows workstation lock/unlock events (4800/4801), interactive unlock results (4624/4625 with Logon Type 7), supported Windows Hello/PIN/biometric provider results, Linux desktop PAM authentication, and macOS loginwindow/authentication events. Telemetry includes the reported user, host, timestamp, result, authentication method, session/logon ID and operating-system failure reason. Submitted passwords, PIN values and biometric material are never collected or transmitted.

The dashboard endpoint performs one bounded MongoDB facet query plus one agent-summary query. The frontend merges live events locally and uses a 60-second fallback poll.

## Response safety

Disruptive actions require company-admin RBAC, explicit confirmation, a reason, the existing automated-response approval flow, and a SOC audit record. Supported actions are disable user, lock account, terminate session, revoke token, block IP, kill process, isolate endpoint and create ticket.

## Deployment

Rebuild/redeploy the backend agent package so installed endpoints receive `collectors/credential_security.py`. No new MongoDB index is required; capability 13 uses the existing company/capability/time indexes.
