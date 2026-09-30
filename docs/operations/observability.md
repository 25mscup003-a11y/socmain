# Observability specification

## Service-level objectives

| Signal | Initial objective | Page when |
|---|---:|---:|
| Accepted ingestion availability | 99.9% over 30 days | <99.5% for 15 min |
| API p95 latency | <300 ms | >750 ms for 10 min |
| Agent batch acceptance p95 | <2 s | >5 s for 10 min |
| Event freshness p95 | <60 s | >5 min for 10 min |
| Durable queue loss | 0 | any confirmed loss |

## Required telemetry

- Structured JSON logs with `request_id`, route, status, latency, company/tenant IDs, actor type, and a redacted error class. Never log tokens, agent keys, event bodies, or integration credentials.
- RED metrics per HTTP route: request rate, error rate, and duration histogram.
- Ingestion metrics: accepted/rejected/duplicate events, bytes, batch size, decompression ratio, retry count, queue depth and oldest-event age.
- Storage metrics: Mongo/ClickHouse query p95/p99, replication lag, disk saturation, rejected inserts, part counts, merge backlog, and object-store failures.
- Socket metrics: authenticated connections, rejected handshakes/room joins, connection age, and emit failures.
- Traces spanning gateway, normalization, broker publish, processing, storage write, and detection; propagate a generated correlation ID, not secrets.

## Dashboard and alert ownership

- Platform on-call owns availability, latency, broker, database, disk, and saturation alerts.
- SOC engineering owns parsing failure, detection lag, rule execution, false-positive and event-freshness alerts.
- Security owns authentication anomalies, cross-tenant authorization denials, credential rotation and audit-log integrity.
- Every paging alert links to a runbook in `docs/operations/runbooks.md` and includes tenant-safe diagnostic labels.

The present Express service exposes liveness/readiness endpoints and structured application counters remain a Phase 3 implementation item. Prometheus/OpenTelemetry should be introduced before a production scale claim is made.
