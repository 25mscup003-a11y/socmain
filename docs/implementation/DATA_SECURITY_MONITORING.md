# Data Security Monitoring (Capability 12)

Capability 12 extends the existing AJNAT endpoint, alert ingestion, RBAC,
Socket.IO and reporting architecture. It does not introduce a parallel SOC.

## Telemetry sources

- `file_monitor.py`: sensitive-file lifecycle, integrity, permission,
  ownership and ransomware-related metadata.
- `usb.py`: removable-media copy metadata, device identity, byte count and
  policy result.
- `network.py` and `rules.py`: large/outbound transfer and exfiltration
  signals.
- `processes.py` and `data_security.py`: archive staging, database exports,
  cloud/file transfer tools and backup deletion process context.

Collection is automatic while EDR is enabled. The dedicated process collector
uses a bounded interval and only evaluates newly observed processes. Existing
sender deduplication, durable buffering, queue pressure controls, signed agent
requests and retry behavior remain in effect.

## Privacy boundary

The agent sends metadata such as path/name, size, hash (where allowed), user,
process, channel, classification, DLP pattern category/count and enforcement
result. It does not send file contents, clipboard contents, email bodies,
passwords, tokens, private keys or matched DLP values. File preview is disabled
by default in the forensic API.

## API and real time

Authenticated, tenant/department-scoped endpoints are mounted under
`/api/data-security`: `dashboard`, `live`, `logs`, `log/:id`, `reports`,
`export`, and administrator-only `respond`.

The dashboard endpoint uses one bounded MongoDB facet and existing capability
indexes. New events are published to the company-scoped
`data-security:event` Socket.IO room. The UI merges live events locally and
uses a 60-second visibility-aware fallback refresh instead of polling every
15 seconds.

## Reports and response

Capability 12 uses the shared enterprise report panel and server-side period
and category filtering. CSV, Excel-compatible, PDF and JSON exports are
available. Endpoint response actions use the existing approval-backed response
service and SOC audit trail.
