# Operational Runbooks

## Broker unavailable

Alert when publish failure exceeds 1% for 2 minutes or oldest unsent batch is
over 60 seconds. Ingestion returns 503, agents spool/retry, operator checks
quorum/disk/network. Do not acknowledge undurable events.

## Consumer lag

Alert when lag age exceeds 2 minutes for normalization or 5 minutes for optional
enrichment. Check poison partitions, storage latency and throttled tenants.
Scale consumers only when partitions permit. Move poison events to DLQ.

## Storage unavailable

Pause consumers before retry storms. Keep broker retention headroom above the
documented recovery window. Restore storage, resume a canary consumer, compare
counts and then release the group.

## Suspected cross-tenant exposure

Disable affected route/subscription, preserve access/audit logs, rotate impacted
tokens, identify tenant/time range, notify incident commander and run negative
authorization tests before re-enable.

## Agent backlog

Alert at 70% local spool capacity and critical at 90%. Verify network, 429/503
rates and clock skew. Never delete high/critical events to make room without an
audited policy.

## DLQ growth

Alert on non-zero sustained growth for 10 minutes. Group by bounded reason code
and schema version, not tenant metric labels. Fix parser/schema, replay a sample,
then replay in bounded batches with idempotency.

## Database pool saturation

Alert above 80% utilization for 5 minutes. Find slow queries, cancel bounded
offenders and lower concurrency. Do not blindly increase every pod's pool.
