# Storage, Indexing and Retention

## Current

MongoDB stores users, billing, companies, systems, logs and alerts. Log/alert
TTL indexes delete at fixed 90 days. This cannot support legal hold or per-plan
retention and is not the 150-billion-event target store.

## Target

- MongoDB/PostgreSQL: identity, tenant, subscription, agent registry, cases and
  compact audit metadata.
- ClickHouse: normalized hot/warm events and detection facts.
- object storage: compressed immutable raw batches, archive and replay source.
- broker: short durable processing retention, not permanent truth.
- Redis: bounded rate limits, leases and replay cache only.

Recommended ClickHouse order:

    (tenant_id, event_date, agent_id, event_time, event_id)

Use skip/bloom indexes only after query traces justify them. Avoid
partition-per-tenant and indexing every field. Require query time range, maximum
scan bytes, result limit and cancellation.

Retention is policy-driven: hot to warm to cold to delete. Legal hold blocks
transition/deletion. Delete jobs write an audit manifest, support dry-run and
verify exact partitions/object prefixes.
