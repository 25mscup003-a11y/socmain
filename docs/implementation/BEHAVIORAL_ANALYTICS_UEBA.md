# Behavioral Analytics (UEBA)

Capability 11 extends the existing SOC. It does not introduce a separate authentication, alert, response, or reporting stack.

## Data flow

1. The endpoint agent runs the bounded anomaly detector plus existing credential, data-security, email and lateral-movement collectors.
   It also runs a privacy-safe input-behavior collector that reports aggregate keyboard event rate, pointer speed, clicks, scrolling and active/idle percentage. Key values, typed text and cursor coordinates are never transmitted or stored.
2. Only security metadata is sent through the existing signed, buffered agent transport. Passwords, tokens, browser history, clipboard contents and file contents are not collected.
3. Alert ingestion normalizes UEBA entity, category, score, confidence, risk-factor and baseline fields and stores the event in the existing `alerts` collection.
4. `/api/ueba/dashboard`, `/api/ueba/logs` and `/api/ueba/log/:id` enforce JWT, analyst RBAC, company scope and optional department scope.
5. `/api/ueba/baseline` uses a server-enforced rolling 30-day window. It returns paginated agent cards and per-agent behavior, risk, severity, entity and monitoring-coverage aggregates; clients cannot request older baseline data.
6. `ueba:event` is emitted only to the matching company Socket.IO room. The dashboard batches event refreshes and uses a 60-second recovery poll.
7. Reports use the shared Capability Reports panel and `/api/dashboard/capability-report/11`, including PDF, CSV and print workflows.
8. Response requests use `/api/ueba/respond`, company-admin RBAC, explicit confirmation/reason, audit logging and the existing approval-backed response service.
9. A validated `UEBA_INPUT_PROFILE_MISMATCH` creates a deduplicated profile-lock event, emails the active company admin, scoped department admin and assigned SOC manager, and queues a signed endpoint account-lock command. Lock/unlock status follows endpoint acknowledgements rather than assuming success.
10. `/api/ueba/profile-locks`, `/api/ueba/profile-locks/:id` and `/api/ueba/profile-locks/:id/unlock` power the role-scoped Lock / Unlock workspace. Unlock requires explicit confirmation and an audit reason.

## Deterministic scoring

Explicit agent `riskScore` is preferred, then `behaviorScore`; otherwise severity maps to Critical 100, High 80, Medium 60, Low 30 and Informational 10. Dashboard aggregation is bounded to 500 event records while KPI facets are computed server-side across the selected time window.

## Configuration

Heartbeat policy automatically enables UEBA whenever EDR is enabled. Operators may set `UEBA_MONITOR_INTERVAL_SECONDS` (15–3600 seconds) and `UEBA_ANOMALY_MULTIPLIER` (1.5–10). No separate dashboard configuration is required.

Input activity summaries default to one report every six hours (minimum one hour), with anomaly cooldown. Optional server settings are `INPUT_BEHAVIOR_REPORT_INTERVAL_SECONDS`, `INPUT_BEHAVIOR_ANOMALY_COOLDOWN_SECONDS`, `INPUT_KEYBOARD_RATE_THRESHOLD`, and `INPUT_MOUSE_RATE_THRESHOLD`. Desktop-session permissions are required; unsupported/headless sessions report the sensor as unavailable instead of collecting content through unsafe fallbacks.

The encrypted endpoint state keeps only 30 daily aggregate input-rate buckets. After 30 distinct observed days, the local adaptive model compares keyboard rate, pointer speed, click rate and active-time percentage with the learned profile. Two consecutive windows must deviate on multiple features before a `UEBA_INPUT_PROFILE_MISMATCH` alert is emitted. This is a verification signal, not biometric identification: it never proves who the operator is. Per the configured security workflow, an automatic lock is allowed only when the agent resolves exactly one interactive, non-service account; `SYSTEM`, root, service and ambiguous multi-session users are never auto-locked. An administrator must verify identity before using the audited unlock action.

Run `npm run migrate:ueba-baseline` and `npm run migrate:ueba-profile-locks` from `backend/` during deployment. The alert-side agent/time index is reused when it already exists.
