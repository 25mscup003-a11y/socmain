# Local verification, 2026-10-04

Environment: i7-13620H, 16 available logical CPUs, approximately 32 GiB RAM shared
with the SOC application. Kafka 7.6.1 image (Kafka 3.6), one broker on loopback,
six partitions per alert topic and RF1. This is not the production topology.

`./scripts/manage.sh benchmark` results:

| Measurement | Result |
|---|---:|
| Logical agent keys | 30,000 |
| Events sent / unique events consumed | 30,000 / 30,000 |
| Duplicate deliveries observed | 0 |
| Raw serialized value bytes | 63,558,890 |
| Publish time | 12.56 s |
| Publish-to-consume completion time | 12.58 s |
| Observed completion rate | 2,385 events/s |

The generator creates random approximately 2 KiB values and gzip-compresses
batches in the same process that consumes the records. The result includes
generator CPU and is neither Kafka's maximum throughput nor an end-to-end SOC
capacity measurement. The temporary topic and consumer group were removed.
No benchmark records were written to the application's MongoDB alerts.

Also verified: health-topic round trip, Kafka UI health `UP`, Prometheus exporter
metrics, and an active `soc-alert-storage-v1` consumer group. At observation the
active alert partition's consumer lag was zero; unused partitions had no committed
offset. DLQ was empty before replacing unlimited retention with 30 days.
Final topic provisioning validation passed. All 26 targeted producer, storage
recovery, worker and production provisioning regression tests passed.

## Reliability and UI changes verified

- KafkaJS idempotent producer has its own effectively unlimited retry count;
  HTTP acknowledgement waits are bounded to 15 seconds. Late sends retain their
  queue/byte reservation until settlement; overload returns retryable 503.
- Worker subscriptions recover uncommitted partitions from earliest retained
  offsets. Mixed valid/invalid chunks cannot commit past unpersisted records.
  MongoDB connectivity failures retain offsets and heartbeat during backoff.
- Fatal consumer crashes exit for supervision. Local worker restarts use capped
  backoff and no permanent five-crash cutoff; production systemd template added.
- Main MongoDB already has `company_event_id_lookup`. The new additive
  `broker:provision-storage` command validated it without changing records or
  indexes. A first isolated full-worker load run lacked that index and timed
  out after four minutes; the fixture now provisions it explicitly. This is why
  production rollout must verify indexes instead of trusting auto-indexing.
  A subsequent indexed single-worker run also missed the four-minute load
  deadline (Kafka accepted all 30,000 in 9.72 seconds). It passed broker/MongoDB
  recovery and drained pending producer sends, but did not establish sufficient
  storage throughput. Worker replicas are required and tested separately;
  five-second offset commits now bound replay of partially processed batches.
- Kafbat UI v1.5.0: health UP, anonymous access denied, wrong password rejected,
  valid login and cluster/broker/topic/consumer-group/metrics APIs passed.
  Cluster `ajnat-local` is ONLINE. Credentials are generated once and kept in
  `kafka/.runtime-secrets/ui.env` with permissions 0600 inside a 0700 directory.
- Main broker health, durable health-topic round trip, topic provisioning and
  exporter at `http://localhost:19308/metrics` passed after deployment. UI is
  loopback-only at `http://localhost:18080`; broker JMX is private to Docker.

## Final isolated recovery and storage run

`kafka/tests/ha-check.js` passed with three broker/controllers, six partitions
per test topic, RF3/minimum ISR2, three actual ingestion-worker processes and
an isolated MongoDB. Each broker container was limited to 1.5 CPUs/1 GiB with
a 256 MiB heap; MongoDB to 1.5 CPUs/768 MiB. All shared the development host.

| Measurement/check | Result |
|---|---:|
| Logical agent IDs / generated load records | 30,000 / 30,000 |
| Kafka publish completion | 12.56 s |
| MongoDB persistence completion from load start | 125.35 s |
| Observed end-to-end stored rate | 239 events/s |
| Exact expected IDs reconciled | 30,000 load + 4 recovery fixtures |
| Missing / duplicate stored test records | 0 / 0 |
| DLQ records | 0 |
| One broker abruptly killed: quorum write and persistence | Pass |
| Two brokers unavailable: 503 instead of false acknowledgement | Pass |
| Quorum recovery, same-ID retry and pending-send queue drain | Pass |
| MongoDB stop/start: storage backoff and recovery | Pass |

The run checks every expected event ID and total row count, not only Kafka
offset totals. Synthetic routine events used an approximately 2 KiB body
repeated across records, so compression was favorable. MongoDB had the event-ID
lookup index, not the full SOC query-index set. It excludes agent enrollment,
encrypted HTTP ingestion, actionable detection/SOAR and production failure
domains. **239 events/s is the measured local result, not 30,000 events/s.**
Three replicas plus periodic commits met this bounded test; the earlier
single-worker timeout remains part of the evidence. No capacity claim is made
from agent count alone. All test worker processes were stopped; the isolated
Compose containers and temporary volumes were removed afterward.

The separately supplied production broker, worker and mTLS/read-only UI
templates are not deployed. Real hostnames, service accounts, certificates and
capacity validation are required. The legacy event-ID lookup is non-unique;
sequential replay tests do not prove concurrent database-wide exactly-once
processing. No unique-index migration or deletion of legacy duplicates was run.

Production acceptance at 30,000 sustained events/s, 90,000 burst events/s and
30,000 authenticated agents remains pending the separate infrastructure and
isolated full-pipeline load test described in `production/README.md`.
