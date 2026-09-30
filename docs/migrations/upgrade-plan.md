# Incremental Upgrade Plan

1. Stabilize monolith P0 auth, isolation, limits, idempotency and tests.
2. Add versioned migration CLI with a lease; remove migrations from API startup.
3. Publish to broker in shadow mode while Mongo remains authoritative.
4. Add normalization workers and DLQ; reconcile counts/checksums.
5. Dual-write normalized events to ClickHouse and validate tenant/time queries.
6. Switch reads by tenant cohort behind an immediate rollback flag.
7. Move ingestion acknowledgement to broker quorum.
8. Archive raw batches and prove replay.
9. Stop Mongo raw-log writes after parity and recovery drills.
10. Migrate history in bounded time partitions.

Every step needs an owner, forward-fix script, count reconciliation and rollback
window. Never run an all-company migration from every API replica.
