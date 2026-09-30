# Lateral Movement Detection (Capability 14)

Capability 14 extends the existing agent, alert ingestion, correlation, RBAC, audit, response and Socket.IO infrastructure. It does not introduce a separate authentication or tenant model.

## Agent telemetry

The cross-platform collector is enabled by default with:

- `lateral_movement_monitoring_enabled`
- `lateral_monitor_interval_seconds` (minimum effective value: 5 seconds)

It reports new inbound and outbound internal RDP, SSH, SMB, RPC/WMI, WinRM, Kerberos, LDAP and VNC sessions, plus suspicious remote-execution processes and tools. Events use `capabilityId: 14` and include source/destination hosts and IPs, ports, process ancestry, command line, hash, user, risk, confidence and MITRE metadata when available.

Only OS connection/process metadata is collected. Passwords, tokens, keystrokes, packet payloads and remote-session screen content are not collected. The existing sender redaction, buffering, retry and authenticated ingestion flow remains in use.

## API and realtime contract

All routes are below `/api/lateral-movement` and require JWT authentication plus analyst access. Tenant and department scope are derived from the authenticated user.

- `GET /dashboard` — KPIs, timeline, vectors, paths and agent status
- `GET /live` — recent live events
- `GET /logs` and `GET /log/:id` — paginated events and forensic context
- `GET /reports` — filtered report dataset
- `POST /export` — CSV, PDF or JSON export
- `POST /respond` — audited, approval-aware endpoint response request (company admin)

New capability-14 events are published to the authenticated company room as `lateral:event`. The existing dashboard also listens to the normal alert lifecycle events.

## Correlation

The correlation service includes these multi-step chains:

- Failed authentication → successful remote session → remote command execution
- Administrative share → remote service creation → PsExec
- Kerberos abuse → LSASS/credential access → credential pivot

Correlated findings retain capability and MITRE coverage and continue through the existing incident, notification and alert workflows.

## Database and deployment

Run the additive MongoDB index migration once per environment:

```bash
npm run migrate:lateral-movement
```

Restart the backend and rebuild/redeploy the endpoint agent package so installed agents receive the new collector and configuration. Existing records and modules are unchanged.

## Verification

```bash
node --test test/lateralMovementIntegration.test.js
python3 -m unittest soc-agent/tests/test_lateral_movement.py
```
