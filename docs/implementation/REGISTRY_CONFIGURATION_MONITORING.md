# Registry & System Configuration Monitoring (Capability 6)

## Architecture

Capability 6 extends the existing AJNAT pipeline; it does not add a second application or transport:

`Windows registry snapshot / Linux-Solaris file events → agent queue → signed alert ingestion → normalization and policy evaluation → alerts collection → REST/WebSocket → existing EDR page`

Windows collection monitors bounded built-in registry locations plus administrator policy targets. Linux and Solaris use the existing native file watcher for critical configuration paths. Runtime policy targets are delivered through the existing signed heartbeat `config_update` payload.

Snapshot registry telemetry explicitly reports `processAttribution=unavailable_snapshot_polling`; the UI never invents a process, sensor state, hash, MITRE mapping, or analyst.

## Files and components

- Agent: `soc-agent/core/registry_monitor.py`, `soc-agent/collectors/file_monitor.py`, `soc-agent/core/config.py`, `soc-agent/agent.py`
- Ingestion/model: `src/routes/alert.routes.js`, `src/models/Alert.model.js`
- Policy: `src/models/RegistryConfigurationControl.model.js`, `src/services/registryConfigurationPolicy.service.js`
- API: `src/routes/registry-monitoring.routes.js`, mounted by `src/server.js`
- Agent policy delivery: `src/routes/agent.routes.js`
- Database migration: `migrations/026-registry-monitoring-indexes.js`
- Frontend: `company/src/pages/EDRDashboardDetails.jsx`, `company/src/pages/edrdashbordpage/Registry Monitoring.jsx`

## Normalized fields

Events retain the existing alert schema and add `configurationCategory`, `configurationOperation`, `configurationObject`, `configurationPlatform`, `configurationBaselineStatus`, `configurationPolicyId`, `configurationPolicyViolation`, `configurationRiskFactors`, registry value metadata, and process attribution. Every query is company-scoped and optionally department-scoped.

Risk bands are Low 0–29, Medium 30–59, High 60–79, and Critical 80–100. MITRE mapping is evidence-driven for Run/RunOnce, services, cron/tasks, account manipulation, defense impairment, authentication changes, and Windows registry modification.

## API and live events

Base path: `/api/registry-monitoring`

- `GET /dashboard`, `/events`, `/events/:id`, `/statistics`, `/timeline`
- `GET /policies`, `/baselines`
- `POST /policies`, `/baselines/approve`, `/exceptions`
- `PATCH /policies/:id`
- `POST /acknowledge`, `/investigate`, `/resolve`, `/export`

CSV and PDF exports are generated from tenant-filtered backend queries, up to 10,000 rows. Live updates use the existing authenticated company room with `registry:event`, `registry:event-updated`, `registry:policy-updated`, and `registry:baseline-updated`.

The Reports tab uses the shared SOC forensic report format with 24-hour, weekly, monthly and 90-day windows; persistence, security-control, identity, network, permission, policy-violation and critical-risk categories; eight live summary KPIs; severity distribution; and a detailed evidence table. PDF, CSV and JSON exports contain only the selected tenant-scoped report data. Registry and policy WebSocket events refresh an open report automatically.

## Deployment

1. Deploy the backend and company frontend together.
2. Run `cd backend && npm run migrate:registry-monitoring` once against the target database.
3. Build/redeploy the desktop agent so Windows gets the expanded registry collector and Unix/Solaris gets Capability 6 configuration tagging.
4. Confirm HTTPS/mTLS and the existing agent signing secret in production.

Optional environment settings: `REGISTRY_MONITOR_INTERVAL_SECONDS`, `REGISTRY_MONITOR_PATHS`, and `CONFIGURATION_MONITOR_PATHS`.

## Limitations

- Windows registry snapshot polling cannot identify the responsible process. The field is explicitly marked unavailable unless a native event provider supplies it.
- Linux/Solaris process attribution depends on metadata exposed by the native watcher/audit provider.
- macOS is not claimed by this Capability 6 implementation.
- The migration is provided but is not run automatically by application startup.
