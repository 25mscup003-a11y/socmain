# Verification and benchmark record

Date: 2026-07-19

## Reproducible checks completed

| Check | Result |
|---|---|
| Backend unit/security suite | 28/28 passing, including broker, retention, ClickHouse and tenant-isolation tests |
| Agent durability/transport suite | 4/4 passing (SQLite restart, retry/DLQ and gzip transport) |
| Company production build | Passed; main JavaScript 2,457.99 kB (611.34 kB gzip) |
| Superadmin production build | Passed; main JavaScript 750.83 kB (195.97 kB gzip) |
| Backend JavaScript syntax checks | Passed for server, alert/log routes and load driver |
| IPS backend baseline | 8/8 passing after isolating the webhook port and fixing tenant-scoped fixtures |
| IPS frontend baseline | Failed because no tests are present |

## Throughput status

No production-like throughput number is claimed. A benchmark without an isolated MongoDB dataset, representative indexes, storage latency, cardinality, retention policy and resource limits would be misleading.

The repository now contains `backend/scripts/load-alert-ingestion.js`. It produces stable event IDs, signed/gzipped batches, response-status counts, accepted events/second and p50/p95/p99 latency. Exact preparation and commands are in `load-testing.md`. Run it in an isolated environment and archive:

1. commit SHA and configuration;
2. CPU, memory, network and disk limits;
3. dataset/index state;
4. warm-up and measurement windows;
5. client and server metrics;
6. failure/retry/duplicate counts.

The before/after comparison is therefore intentionally marked **pending controlled environment**, not inferred from unit tests or frontend build time.

## Isolated data-plane integration result

The production-like Compose topology was exercised with MongoDB 8, Redis 7.4,
Redpanda 24.3, ClickHouse 24.8 and MinIO. This is a correctness smoke test, not
a throughput benchmark:

| Test | Result |
|---|---|
| Kafka topic provisioning | Main, retry and DLQ topics created with 3 partitions |
| Broker → worker → MongoDB/ClickHouse | Passed with tenant and company keys preserved |
| Same event published twice | Mongo count `1`; ClickHouse `FINAL` count `1` |
| Archive cycle | 1 old alert uploaded as a 188-byte gzip NDJSON object and marked archived |

The first run exposed and failed on incompatible ClickHouse timestamp formatting.
The second exposed an unstable replacement key. Both were corrected in the v2
table migration before the passing replay result above.

## Local codec benchmark

Command: `cd backend && npm run benchmark:codecs`

Measured on 2026-07-19 with 10,000 representative events in batches of 50:

| Path | Encoded bytes | Local encode time |
|---|---:|---:|
| Before: plain JSON | 5,329,180 | 47.287 ms |
| After: gzip JSON | 160,094 | 115.393 ms |

The measured byte reduction was 97%. Compression consumed more local CPU. This benchmark excludes network, broker, database and disk and is not an events/second production claim.
