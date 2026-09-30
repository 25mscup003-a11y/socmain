# Memory Activity Monitoring (Capability 5)

## Architecture

Capability 5 uses the existing AJNAT EDR pipeline and does not introduce a second agent, backend, database, WebSocket server, or dashboard:

`endpoint memory scanner / Windows Sysmon events -> existing signed agent queue -> alert ingestion and normalization -> MongoDB alerts -> tenant-scoped REST and WebSocket -> existing EDR Memory Activity page`

Routine host and process samples are stored as `memory.metric` telemetry. They update dashboard health and process widgets but are excluded from threat counts, automatic alert assignment, and forensic reports. Actionable memory findings remain normal alerts.

## Files and components

- Agent scanner: `backend/soc-agent/core/memory_scanner.py`
- Windows event enrichment: `backend/soc-agent/collectors/windows_process_events.py`
- Agent normalization and secure delivery: `backend/soc-agent/core/sender.py`
- Backend ingestion and live events: `backend/src/routes/alert.routes.js`
- Alert schema and indexes: `backend/src/models/Alert.model.js`, `backend/migrations/013-memory-overflow-indexes.js`
- Capability API: `backend/src/routes/memory-activity.routes.js`, mounted by `backend/src/server.js`
- Historical reporting: `backend/src/routes/dashboard.routes.js`
- Frontend integration: `company/src/pages/EDRDashboardDetails.jsx`, `company/src/pages/edrdashbordpage/Memory Activity Monitoring.jsx`
- Tests: `backend/soc-agent/tests/test_memory_activity.py`, `backend/test/memoryActivityIntegration.test.js`

## Collection and detection coverage

The lightweight cross-platform scanner reports:

- Host total, used and available RAM, memory pressure, total/used swap and commit charge.
- Top process PID/PPID, identity, executable, RSS, virtual/shared memory and memory percentage.
- Linux executable deleted-file or `memfd` mappings as fileless/reflective-loading evidence.
- Linux writable-and-executable file-backed mappings as injection/code-patching evidence.
- Credential-dumping and memory-injection tradecraft visible in process names or command lines.
- Windows LSASS-reference heuristics and Sysmon process-access/tampering evidence when the existing Windows telemetry provider supplies it.
- Memory pressure above the remotely configurable RAM/swap thresholds.

The agent tags memory telemetry with Capability 5 and the existing Memory Overflow capability where appropriate. Windows process-access and process-tampering detections are tagged with Capability 5 without changing their existing capability routing.

Current MITRE evidence mappings include T1055, T1055.012, T1003.001, T1620 and T1499. Mapping is attached only when the collected evidence supports it.

## Normalized telemetry

The existing alert schema stores memory-specific values such as `memoryMetricType`, `memoryTotalBytes`, `memoryUsedBytes`, `memoryAvailableBytes`, `memoryPressure`, swap values, process RSS/private/shared/virtual memory, source and target process metadata, access mask, call trace, memory protection, hashes, signatures, YARA/IOC matches, process tree and related forensic evidence.

Missing forensic evidence is returned as missing and rendered as `Not reported`; the frontend does not fabricate process names, addresses, hashes, users, analyst identities, YARA matches, memory dumps, or timelines.

Metrics receive the existing short telemetry retention through `expiresAt`. Actionable detections use normal alert retention. Existing memory indexes cover company/capability/time, event triage, host metrics, process identity, rules and incidents, so no new migration is required for Capability 5.

## REST API and live updates

Base path: `/api/memory-activity`

- `GET /dashboard` - summary, latest host/process samples, systems, threats, category breakdown and timeline.
- `GET /events` - paginated threat events with severity, host, user, process and search filters.
- `GET /events/:id` - one tenant-scoped forensic event.
- `GET /metrics` - host/process metric telemetry; `kind=host|process` is supported.
- `GET /timeline` - hourly threat counts by severity.
- `POST /events/:id/notes` - persist an analyst note and audit-history entry.

All routes require the existing analyst authentication, enforce company scope, optionally enforce department scope, exclude synthetic records, validate identifiers and bound result sizes.

Historical reports use `GET /api/dashboard/capability-report/5`. The report categories are injection, credential theft, fileless execution, executable memory, corruption/exploit, kernel/DLL and critical. Routine `memory.metric` rows are excluded from reports. CSV, JSON and print/PDF output use the existing reporting component.

Live UI updates use the authenticated company room and existing events:

- `memory:metric`
- `memory:alert`
- `memory:alert-updated`

The open dashboard refreshes through the existing authenticated Socket.IO client and buffered update path; no second WebSocket server or protocol is introduced.

## Response workflow

The detail view persists notes through the Capability 5 API. Process termination is offered only when a persisted event and the existing approved response handler are available; the module does not create a new arbitrary-command endpoint. Other response actions continue through AJNAT's existing RBAC, approval and audit workflow.

## Configuration and deployment

The scanner interval is delivered through the existing signed agent configuration. Relevant settings include:

- `memory_scanner_interval_seconds`
- `memory_scanner_maps_max`
- `memory_scanner_top_n`
- `memory_scanner_host_ram_pct`
- `memory_scanner_host_swap_pct`
- `memory_rwx_detection_enabled`

Deploy the backend and company frontend together, then rebuild/redeploy the existing endpoint agent. Run `npm run migrate:memory-overflow` only on installations that have not already applied migration 013. Keep the existing HTTPS/mTLS, agent signing, MongoDB and authenticated WebSocket configuration enabled.

## Platform limitations

- Windows deep memory access, remote-thread, handle and kernel tampering detection depends on the installed native/Sysmon telemetry provider. The Python scanner does not claim kernel-driver visibility.
- Linux deep inspection is limited to readable `/proc` metadata. Protected processes may require the agent's existing elevated service context.
- macOS receives portable process and host metrics, plus command-line detections where available; Mach memory-region inspection is not implemented in this collector.
- Container and Kubernetes memory is visible through host/process telemetry only unless the deployment provides container/pod identity through an existing workload collector. Capability 5 does not claim a Kubernetes admission, eBPF, cloud-provider, or global geolocation sensor.
- The module stores memory-dump metadata only when supplied by an authorized collector. It does not collect raw memory or transmit dump contents automatically.
- Behavioral/ML scores, YARA matches and threat-intelligence results are displayed only when produced by existing AJNAT engines; the UI does not synthesize them.
