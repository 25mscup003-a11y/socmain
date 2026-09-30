# AJNAT EDR Network Activity Monitoring

Capability 3 extends the existing AJNAT agent, Node.js API, MongoDB, Socket.IO rooms, alert engine, report service, and company dashboard. It does not introduce a separate application. The company dashboard and every `/api/network/*` read are restricted to the current rolling 24-hour window.

## Data path

1. `backend/soc-agent/collectors/network.py` collects connection metadata with `psutil`, maintains lifecycle state, and generates threshold-based DNS, scan, lateral-movement, beaconing, and transfer signals.
2. The existing authenticated/signed agent transport batches and durably spools telemetry during outages.
3. `NET_CONNECTION_SUMMARY` ingestion normalizes connection rows into `NetworkConnection`; the existing `Alert` collection remains the network alert store.
4. Contextual risk and enabled company policies are evaluated before deduplicated policy alerts are inserted.
5. Tenant-authorized REST reads and `company:<companyId>` Socket.IO rooms drive the existing React page.

Packet payloads are not collected by this capability. Adapter counters are identified as adapter-scoped and are not represented as per-flow byte counts.

## Network updates on change

The agent sends an initial baseline after startup, then compares network state on
each local scan (20 seconds by default). Connection, process, socket state,
listener, interface address, resolver, VPN, and observed DNS answer/domain changes
trigger the corresponding summaries. An unchanged inventory is monitored locally.
Observation timestamps, growing connection durations, byte counters, and reordered
OS rows do not trigger another copy of the same summary.

Connection, DNS, exposure, and reputation summaries are compared independently.
Local beacon, scan, lateral-movement, transfer, and port-policy checks continue on
every scan; agent health heartbeats and threat alerts continue through their
existing paths. Adapter byte totals accumulate until the next network state
update, so they are no longer a periodic traffic feed. The dashboard's existing
24-hour window still applies to the timestamps of reported observations.

Changed summaries carry `raw.reporting_mode: on_change`. They are retained as
individual durable events through network outages and agent restarts. Closed
connections remain pending until accepted by the sender; an unreadable socket
inventory is not treated as evidence that all connections closed.

Installed agents need a freshly generated agent package and a service restart to
load the updated `collectors/network.py`, `core/sender.py`, `core/durable_spool.py`,
and matching package integrity manifest. Editing the repository alone does not
update a running agent installed under `/opt/soc-agent`.

## Agent defaults

Defaults live in `backend/soc-agent/core/config.py` and can be overridden by the existing company agent configuration:

| Setting | Default | Purpose |
| --- | ---: | --- |
| `network_monitor_enabled` | `true` | Enables metadata collection |
| `network_poll_interval_seconds` | `20` | Local monitoring cadence; unchanged summaries are suppressed |
| `network_snapshot_max_connections` | `500` | Active rows per snapshot |
| `network_snapshot_max_closed` | `250` | Closed rows per snapshot |
| `network_behavior_window_seconds` | `60` | Scan/lateral correlation window |
| `port_scan_unique_ports` | `20` | Port-scan threshold |
| `host_scan_unique_hosts` | `15` | Host-scan threshold |
| `lateral_movement_unique_hosts` | `8` | Remote-admin fan-out threshold |
| `large_outbound_bytes` | `104857600` | Minimum adapter upload anomaly size |
| `transfer_anomaly_multiplier` | `4.0` | Learned median multiplier |
| `dns_anomaly_threshold` | `45` | DNS contextual risk threshold |
| `network_detection_cooldown_seconds` | `900` | Duplicate signal cooldown |

Beacon controls (`beacon_min_connections`, interval bounds, consistency, history, allowlists, and cooldown) are documented by their defaults in the same file.

Backend retention is controlled by `NETWORK_RETENTION_DAYS`, falling back to `LOG_RETENTION_DAYS` and then 30 days. Retention affects storage only; Capability 3 still displays and exposes no data older than 24 hours.

## Operating-system prerequisites

### Linux

- Run the existing AJNAT service account with permission to enumerate process sockets.
- DNS query metadata uses a raw socket when available. Grant only the installed Python binary or service the `CAP_NET_RAW` capability if DNS packet metadata is required. Without it, connection monitoring continues and DNS capture reports a degraded state.
- Do not grant broader root access solely for this module.

### Windows

- Run the existing AJNAT Agent service with permissions required to enumerate system TCP/UDP owners.
- Install the supplied `backend/soc-agent/sysmon-ajnat.xml` configuration when exact Windows connection and DNS attribution is required. Event ID 3 supplies network connection data and Event ID 22 supplies DNS query data.
- Connection-level collection does not require packet capture or WinPcap.

## API and authorization

Mounted under the existing authenticated backend:

- `GET /api/network/connections`
- `GET /api/network/alerts`
- `GET /api/network/dns`
- `GET /api/network/top-talkers`
- `GET /api/network/statistics`
- `GET /api/network/process/:pid`
- `GET /api/network/host/:id`
- `GET /api/network/server/:id`
- `GET /api/network/threat-intelligence`
- `GET /api/network/policies`
- `POST /api/network/policy`
- `PUT /api/network/policy/:id`

All reads require analyst access and company scope; policy mutations require manager access and create audit records. Company and department constraints are applied in MongoDB queries. Partner administrators are limited to companies owned by their partner. Blocking remains disabled unless explicitly approved in a policy request.

The detail modal uses the existing `POST /api/alerts/:id/notes`, `PATCH /api/alerts/:id`, and `POST /api/forensics/hunts` interfaces. Connection-only rows cannot masquerade as alert cases, so note controls remain disabled until an actual alert is selected.

## Deployment

1. Deploy the backend and company UI with the existing release process.
2. Restart the Node.js API so the `/api/network` router and models are loaded.
3. Update/restart the existing Windows and Linux AJNAT agents; do not install a second agent.
4. Confirm MongoDB has created the company/time, investigation, and TTL indexes from `NetworkConnection` and the company/name indexes from `NetworkPolicy`.
5. Open `/company-admin/edr?capabilityId=3&capability=network-activity-monitoring` with an authorized company account and verify the displayed window is `rolling 24H`.
6. Validate one Windows endpoint and one Linux endpoint by creating an approved TCP, UDP, listener, DNS, and closed-connection test event, then trace agent event ID to stored evidence and UI detail.

Recommended verification commands:

```bash
(cd backend && node --test test/networkMonitoring.test.js test/networkMonitoringContract.test.js)
(cd backend/soc-agent && python3 -m unittest discover -s tests -p 'test_network_activity.py')
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=backend/soc-agent python3 -m pytest backend/test/test_network_change_reporting.py -q
(cd company && npm run build)
```

## Rollback

Roll back the backend, company UI, and agent package together using the existing deployment artifacts. Disable `network_monitor_enabled` first if agents must stop emitting while backend rollback completes. Existing `NetworkConnection` and `NetworkPolicy` collections are additive and can remain in place; do not drop them during rollback. MongoDB TTL cleanup will remove expired connection documents according to policy.

## Production acceptance evidence

Automated tests verify normalization, lifecycle closure, DNS scoring, beaconing, contextual risk, policy conjunction, reputation aliasing, 24-hour clamping, API mounting, and UI production compilation. Release approval still requires live signed telemetry tests on supported Windows and Linux workstation/server builds, tenant-escape tests, sustained/burst load tests, reconnect/offline-spool tests, and a configured threat-intelligence/Velociraptor environment. Those environment-specific checks must not be replaced with fabricated UI data.
