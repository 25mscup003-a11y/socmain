# Implemented capability evidence

Date: 2026-07-19

| Capability | Evidence | State |
|---|---|---|
| Batched ingestion | Agent sender plus `POST /api/alerts/batch`; bounded batch validation | Implemented |
| Compressed ingestion | Agent gzip body transport; Express automatic request inflation | Implemented and round-trip tested |
| Durable agent delivery | SQLite WAL/full-sync pending spool | Implemented and restart tested |
| Durable broker | KafkaJS idempotent producer, quorum acknowledgement and provisioned topics | Implemented; external cluster required |
| Idempotency | Stable agent event IDs, Mongo unique migration, bulk upsert and ClickHouse v2 replacement key | Implemented for alert ingestion; replay smoke-tested |
| Backpressure/retries | Bounded agent queue/spool retries; broker retry topic and retry ceiling | Implemented |
| Dead-letter queue | Agent SQLite DLQ and broker DLQ topic | Implemented |
| Bulk writes | Mongo `insertMany`/`bulkWrite`, Kafka batches and ClickHouse JSONEachRow | Implemented |
| Tenant isolation | Server-derived scope, socket authorization, tenant-keyed broker records and worker revalidation | Implemented on primary alert/log paths |
| Time partitioning | ClickHouse monthly partitions and object archive tenant/date/hour keys | Implemented when configured |
| Retention/archive | Per-company expiry/legal hold, bucket provisioner and gzip NDJSON S3-compatible worker | Implemented and MinIO smoke-tested |
| Horizontal scaling | Stateless API mode, Redis Socket.IO adapter, distributed nonce store and independent workers | Implemented when configured |
| Graceful shutdown | API, broker producer, socket Redis, nonce Redis, consumers, archive and tracing shutdown | Implemented |
| Metrics/tracing/logs | Prometheus, OTLP bootstrap and structured request logs | Implemented |
| Load tests | Signed/gzipped HTTP driver (200/201/202 aware) and local codec benchmark | Implemented; full data-plane result pending cluster |

This evidence does not claim that an external broker, ClickHouse, Redis or object store is running in the user's production environment. The production-like compose file supplies a reproducible single-node validation topology; HA sizing still requires a controlled multi-node benchmark.
