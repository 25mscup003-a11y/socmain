# System Changes Monitoring (Capability 7)

Capability 7 extends the existing AJNAT agent, alert ingestion, MongoDB alert model, correlation engine, authenticated APIs, Socket.IO stream and company dashboard. It does not create a second application.

## Data flow

Endpoint collectors emit normalized `system_change_*` fields and Capability ID 7. The backend normalizes legacy snake/camel-case telemetry, assigns contextual risk and MITRE metadata, stores the event in `alerts`, evaluates correlation rules and emits `system-change:event` to the authenticated company room. The dashboard loads `/api/system-changes/summary` and merges live events without synthetic fallback rows.

## API

- `GET /api/system-changes`
- `GET /api/system-changes/:id`
- `GET /api/system-changes/summary`
- `GET /api/system-changes/timeline`
- `GET /api/system-changes/categories`
- `GET /api/system-changes/hosts`
- `GET /api/system-changes/critical`
- `GET /api/system-changes/risk`
- `GET /api/system-changes/baseline`
- `POST /api/system-changes/baseline/approve`
- `POST /api/system-changes/exception`
- `POST /api/system-changes/acknowledge`
- `POST /api/system-changes/investigate`
- `POST /api/system-changes/export`

All routes use existing JWT/RBAC and company/department scoping. Baseline/exception mutation requires company-admin privileges and analyst workflow changes are audit logged.

Saved baseline and exception controls are applied to both direct and batch ingestion through a bounded tenant/department cache. A matching control marks the event approved/excepted and lowers its risk without interrupting telemetry if the control store is temporarily unavailable. `SYSTEM_CHANGE_CONTROL_CACHE_TTL_MS` and `SYSTEM_CHANGE_CONTROL_CACHE_MAX` can tune this cache.

## Realtime events

- `system-change:event`
- `system-change:updated`
- `system-change:baseline-changed`

## Deployment

Run `npm run migrate:system-changes` from `backend/` once per environment to backfill concrete historic evidence and create indexes. Restart backend and rebuild/redeploy the company frontend. The migration is intentionally not run automatically.

## Platform limitations

Collection depends on native OS visibility and agent permissions. Windows registry/service auditing requires the relevant Windows audit sources, Linux/Unix coverage depends on audit/log access, and Solaris/macOS/container fields remain empty when their native telemetry is unavailable. The UI reports those fields as not reported; it does not synthesize evidence.
