# Memory Overflow and USB Device Control

This document covers capability 29 (Memory Overflow Detection) and capability 10 (Device Control/USB) in the existing AJNAT SOC architecture.

## Architecture and data flow

The Python endpoint agent collects bounded operating-system metadata and sends authenticated, signed, replay-protected telemetry through the existing alert transport. Express normalizes it into the MongoDB `alerts` collection, applies tenant and department ownership, and publishes Socket.IO events only to `company:<companyId>`. React consumes the same REST and Socket.IO contracts used by the other EDR dashboards.

Memory metrics are stored as non-actionable `memory.metric` records. They do not enter SOAR, automatic assignment, or the ordinary alert stream. Detection events remain actionable and can be acknowledged, resolved, assigned, correlated into an incident, annotated, filtered, or exported. USB policies are returned to eligible endpoints in the authenticated heartbeat response and are evaluated locally by the USB collector.

## Telemetry sources and permissions

- Windows: `psutil` performance metadata, Application Error/WER/Resource Exhaustion events, and optional Sysmon events 7, 8, 10 and 25 for image-load, remote-thread, process-access and process-tampering evidence.
- Linux: `psutil`, `/proc/vmstat`, `/proc/<pid>/maps`, cgroup v2 memory counters, and readable system/kernel logs.
- macOS: `psutil` plus readable system log metadata. Deep injection telemetry is not claimed without an approved native provider.
- USB: Windows device APIs/PowerShell metadata, Linux udev/sysfs/mount metadata, macOS system-profiler metadata, and bounded file-activity metadata where supported.

Normal collection does not read raw process memory, capture memory dumps, collect file contents, or require elevated access. Installing the service or reading protected OS logs may require administrator/root privileges. Missing Sysmon, auditd, event channels, procfs entries, or cgroup counters causes degraded coverage rather than collector failure.

## Memory detection rules

`GET /api/memory-overflow/rules` seeds tenant-scoped built-ins MEM-001 through MEM-015: sustained pressure, spike, leak, allocation anomaly, repeated crashes, RWX and executable-anonymous regions, cross-process access, correlated injection, LSASS access, OOM, agent tampering, protection changes, stack/heap corruption, and fileless indicators. Rules support enablement, OS and host-group scope, exclusions, allowlists, thresholds, windows, sample counts, cooldowns, severity, confidence, risk, grouping, suppression, maintenance windows, and audit history.

Risk is normalized to 0-100. Critical is 90-100, high 70-89, medium 40-69, and low 0-39. Optional kernel/provider evidence is displayed only when actually supplied by the endpoint.

## API

All routes require JWT authentication and analyst access. Rule mutation, assignment, resolution, incident creation, simulation, and USB policy mutation require manager access.

- `GET /api/memory-overflow/overview`
- `GET /api/memory-overflow/metrics`
- `GET /api/memory-overflow/events` and `/events/:id`
- `GET /api/memory-overflow/alerts`, `/processes`, `/hosts`, `/timeline`, `/severity-distribution`, `/top-processes`
- `GET|POST /api/memory-overflow/rules` and `PATCH /api/memory-overflow/rules/:id`
- `POST /api/memory-overflow/events/:id/acknowledge|assign|resolve|create-incident|notes`
- `GET /api/memory-overflow/export?format=json|csv`
- `POST /api/memory-overflow/simulate`
- `GET|POST /api/usb-policies`, `PATCH|DELETE /api/usb-policies/:id`
- `GET /api/usb-policies/violations`

Memory filters include ISO-8601 `from`/`to`, severity, status, host, process, event type, OS, rule, user, agent, risk range, assignee, search, page, limit, and allow-listed sorting.

Realtime event names are `memory:metric`, `memory:alert`, `memory:alert-updated`, `memory:incident-updated`, `memory:rule-updated`, `usb:event`, and `usb-policy:updated`.

## Configuration

See `backend/.env.production.example`. Agent-side values may also be placed in the generated `company_config.json`.

```env
MEMORY_MONITORING_ENABLED=true
MEMORY_COLLECTION_INTERVAL_SECONDS=30
MEMORY_HIGH_USAGE_THRESHOLD=90
MEMORY_HIGH_USAGE_DURATION_SECONDS=300
MEMORY_SPIKE_PERCENT_THRESHOLD=25
MEMORY_SPIKE_WINDOW_SECONDS=60
MEMORY_LEAK_WINDOW_MINUTES=30
MEMORY_LEAK_MIN_SAMPLES=10
MEMORY_LEAK_GROWTH_PERCENT=30
MEMORY_RWX_DETECTION_ENABLED=true
MEMORY_PROCESS_ACCESS_DETECTION_ENABLED=true
MEMORY_CRASH_CORRELATION_ENABLED=true
MEMORY_ALERT_COOLDOWN_SECONDS=300
MEMORY_METRIC_RETENTION_DAYS=30
MEMORY_EVENT_RETENTION_DAYS=180
MEMORY_SIMULATION_ENABLED=false
```

The collector caps process scans and top-process metrics, maintains bounded histories, deduplicates alerts, uses the existing bounded queue/durable spool, compresses sufficiently large batches, and retries transport with backoff.

## Deployment and verification

```bash
cd backend
npm install
npm run migrate:memory-overflow
npm start

cd ../company
npm install
npm run dev

cd ../backend
python3 -m pip install -r soc-agent/requirements.txt
python3 soc-agent/agent.py test
sudo python3 soc-agent/agent.py install
```

Run verification:

```bash
cd backend
npm test
PYTHONPATH=soc-agent python3 -m unittest discover -s test -p 'test_*.py'
PYTHONPATH=soc-agent python3 -m unittest discover -s soc-agent/tests -p 'test_*.py'
cd ../company && npm run build
```

Safe simulation is disabled by default. Enable `MEMORY_SIMULATION_ENABLED=true`, authenticate as a manager, then POST one of `gradual_leak`, `sudden_spike`, `sustained_pressure`, `segmentation_fault`, `rwx_region`, `lsass_access`, `injection_correlation`, `container_oom`, or `agent_tampering` to `/api/memory-overflow/simulate`. Every generated record is labeled synthetic and expires after 24 hours.

## Tuning and troubleshooting

- Allowlist known JIT runtimes or approved security/backup tools only after analyst review.
- Raise spike/leak sample windows before lowering severity when workloads are bursty.
- Confirm agent heartbeat policy payload contains `usb_policies` after a policy update.
- If Windows injection panels are empty, verify Sysmon is installed and its Operational channel includes events 7/8/10/25.
- If Linux RWX or crash coverage is empty, verify the service account can read the relevant `/proc` entries and OS logs; do not grant broad root access solely to populate a dashboard.
- Metrics expire through the shared `expiresAt` TTL index; MongoDB TTL removal is asynchronous.

Known limitations: allocation-rate telemetry is platform/provider dependent; macOS deep process-access visibility needs a separately approved Endpoint Security provider; Windows API names such as `ReadProcessMemory` are inferred only from verified Sysmon/process-access evidence, not from polling; full memory contents and dumps are intentionally excluded. Future work should add a native signed Windows ETW provider, macOS Endpoint Security integration, cgroup/container identity enrichment, and long-term metric rollups.
