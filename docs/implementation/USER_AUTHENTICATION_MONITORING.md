# User & Authentication Monitoring

Capability 4 is integrated into the existing AJNAT EDR pipeline. It does not add a second application, database, authentication layer, or WebSocket server.

## Data flow

Endpoint authentication sources are collected by the existing agent log collector, normalized by the rule detector, queued by the existing sender, ingested into the shared `alerts` collection, and exposed to the existing company dashboard through REST and Socket.IO.

The dashboard retains its existing layout. KPI cards, charts, live tables, investigations, notes, and reports now use persisted tenant-scoped endpoint events rather than built-in sample records.

## Collection coverage

- Windows Security events: logon/logoff, failures, lockouts, explicit credentials, account lifecycle, group/privilege changes, Kerberos/NTLM, RDP, workstation lock/unlock, and audit-log clearing when present.
- Linux: available `auth.log`, `secure`, PAM, SSH, sudo, su, account lifecycle, and session events. On journald-only hosts, the agent follows the SSH/logind journal units without replaying historical records.
- macOS: authentication evidence available through the agent's existing unified-log collector.
- Remote access and identity-provider/MFA fields are retained only when the connected source supplies that evidence.

The agent never collects plaintext passwords, password hashes, private keys, or authentication secrets.

## Detection and risk

Normalized events include user, domain, endpoint, source IP/port, authentication method/result, Windows event ID, logon type, session, failure reason, severity, risk score, and supported MITRE evidence. The existing time/behavior engine correlates repeated failures and after-hours authentication. Password spraying is detected by distinct usernames attacked from one source inside a configurable window.

Default agent settings:

- `auth_password_spray_window_seconds`: `300`
- `auth_password_spray_user_threshold`: `5`
- Existing time-anomaly failure thresholds and trusted exceptions remain applicable.

## API and real-time events

All routes require the existing analyst authentication and company/department scope:

- `GET /api/authentication-monitoring/dashboard`
- `GET /api/authentication-monitoring/statistics`
- `GET /api/authentication-monitoring/events`
- `GET /api/authentication-monitoring/events/:id`
- `GET /api/authentication-monitoring/timeline`
- `GET /api/authentication-monitoring/risky-users`
- `GET /api/authentication-monitoring/users/:username`
- `POST /api/authentication-monitoring/events/:id/notes`
- `GET /api/dashboard/capability-report/4`

Existing authenticated Socket.IO rooms publish `auth:event`, `authentication_event`, and `authentication_alert`.

## Database

Authentication evidence remains in the shared `alerts` collection. Migration `027-authentication-monitoring-indexes.js` adds tenant/result/time, user/risk/time, and source/protocol/time indexes.

Run once after deployment:

```bash
cd backend
npm run migrate:authentication-monitoring
```

## Deployment and limitations

Rebuild and redeploy the agent and company frontend, then restart the existing backend. Windows coverage depends on Security Log access and enabled audit policy. Linux coverage depends on readable log or journal sources. MFA, device identity, geo-location/impossible-travel, AD/domain details, and cloud identity data are shown only if agents or authorized integrations provide them. Active sessions are an estimate based on observed session success and logout events within the selected window.
