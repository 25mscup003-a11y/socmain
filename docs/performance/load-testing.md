# Load Testing

No 100k/s claim has been made. The local environment was not used to generate
synthetic records in the user's live database.

## Current reproducible driver

Create a JSON array containing test-only enrolled agent keys outside the
repository, then run:

    cd backend
    AGENT_KEYS_FILE=/secure/test-agent-keys.json \
    TARGET_URL=http://127.0.0.1:5000/api/alerts/batch \
    TARGET_EPS=1000 BATCH_SIZE=20 DURATION_SECONDS=60 \
    node scripts/load-alert-ingestion.js

The driver uses gzip, HTTP keep-alive, signed requests, stable event IDs and
reports accepted EPS, compressed bytes/s, status counts and p50/p95/p99 latency.
It is intentionally bounded by MAX_INFLIGHT.

## Test ladder

1. correctness: duplicates, delayed timestamps, bad signature/schema and
   cross-tenant assertions.
2. local smoke: 100-1,000 events/s for 5 minutes.
3. staging step: 5k, 20k, 50k, 100k events/s, 15 minutes each.
4. sustained: 100k/s for at least 2 hours.
5. burst: 250k/s for 10 minutes with recovery observation.
6. soak: measured average load for 24 hours.
7. failure: broker leader loss, storage slowdown, worker kill and AZ isolation.

Use a distributed load generator for 100k/250k targets. Provision many logical
agents but only a realistic active subset; do not open one million simultaneous
connections.

## Report

Record accepted and durably stored events/s separately, end-to-end p50/p95/p99,
queue lag age, duplicates, loss, CPU/RSS/event-loop lag, storage insert/query
latency and recovery time. Reconcile:

    generated = rejected + accepted_unique + accepted_duplicate

In direct mode the script measures API acknowledgement after MongoDB insertion.
In broker mode HTTP 202 means Kafka has acknowledged the publish with `acks=-1`;
it does not mean the worker has persisted the event yet. Measure stored unique
events and consumer lag separately. HTTP 503 includes Retry-After for publisher
overload or failed broker acknowledgement; the real agent must retain and retry
the same event IDs. This load driver counts failures rather than retrying them.

For the 30,000-agent sizing assumptions, topology and acceptance criteria, see
`kafka/production/README.md`.
