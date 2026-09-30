# Scaling

## Signals

- ingestion pods: accepted bytes/s, p95 latency, 429/503 rate and CPU.
- normalization/detection: broker lag age, records/s and processing p99.
- query: concurrent queries, scan bytes, p95 latency and memory.
- storage: part count, merge backlog, disk/object growth and replication health.

Do not label Prometheus metrics with tenant IDs, agent IDs or IP addresses.
Put those in sampled structured logs/traces.

## Backpressure

1. reject over-count/over-byte batches with 413.
2. enforce token-bucket quotas per agent, company and source IP.
3. pause broker consumers when storage is degraded.
4. shed low-priority optional enrichment before core persistence.
5. return 429 with Retry-After for quota pressure and 503 for unavailable
   durability boundary.
6. agents retain batches in a bounded disk spool and retry with jitter.

Do not scale Mongo connection pools linearly with pod count. Set a global
connection budget and divide it across maximum replicas.
