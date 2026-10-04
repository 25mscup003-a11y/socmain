# AJNAT Kafka ingestion

This directory is the operational home for the Kafka layer used by AJNAT.
Agents **do not connect to Kafka directly**:

```text
AJNAT agent -> authenticated/encrypted Backend API -> Kafka -> ingestion worker -> MongoDB/ClickHouse
```

Keeping Kafka behind the Backend API preserves per-agent authentication,
AES-256-GCM payload validation, tenant scoping, schema validation, rate limits,
and the server's ability to revoke an endpoint identity.

## Local setup

Requirements: Docker Engine with Compose v2 and the existing backend dependencies.

```bash
cd kafka                               # from the repository root
cp -n .env.example .env                 # preserves existing settings
chmod +x scripts/*.sh
./scripts/manage.sh up
./scripts/configure-backend.sh          # safely backs up backend/.env first
cd ../backend
npm run broker:provision-storage       # additive MongoDB lookup index
npm start
```

The backend already starts its Kafka alert-consumer worker whenever
`INGESTION_MODE=broker`. Do not launch a second standalone worker on the same
machine unless that is intentional; replicas in the same consumer group divide
partitions safely.

Check the stack:

```bash
cd kafka                               # from the repository root
./scripts/manage.sh status
./scripts/manage.sh lag
./scripts/manage.sh smoke
```

Optional local operations UI and Prometheus exporter:

```bash
./scripts/manage.sh tools
# UI:      http://localhost:18080
# Metrics: http://localhost:19308/metrics
./scripts/manage.sh verify-ui
```

The maintained Kafbat UI v1.5.0 requires login. Username and randomly generated
password are in `kafka/.runtime-secrets/ui.env` (mode 0600). `manage.sh` generates
them once and preserves them on restart. Every login requires a fresh six-digit
email OTP after the password. Gmail SMTP settings come from `backend/.env`:
`SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS` and `SMTP_FROM`.
The recipient defaults to `SMTP_USER`; set `KAFKA_UI_OTP_EMAIL` in `kafka/.env`
to use another administrator mailbox. No authenticator or QR setup is needed.

`setup-ui.js` copies only these mail settings and the recipient into the ignored
`kafka/.runtime-secrets/ui-mail.json` (0600), mounted read-only by the OTP gateway.
After changing mail settings, run `manage.sh tools` to sync them and recreate
the gateway. The container runs as UID 1000, which must be able to read this
private file if you run the stack under another host account.

Codes expire after ten minutes and belong to one password-verified browser
challenge. Resend is limited to once per minute and three emails per challenge;
it invalidates the old code without resetting failed verification attempts.
SMTP failures prevent login. Codes are held as keyed hashes in memory, never
written to disk or returned to the browser. Logout, session expiry and gateway
restart require a new login and email OTP. Sessions expire after 30 idle minutes
or eight total hours.

The OTP gateway owns host port 18080. Kafbat itself has no published host port.
Both UI pages and APIs require a completed login, and upstream cookies stay
inside the gateway. `verify-ui` sends one OTP email and verifies password-only
API access is rejected; in a terminal it prompts for that email code before
checking authenticated APIs and logout. Noninteractive runs explicitly report
that authenticated API checks were not run. Run
`node --test kafka/tests/ui-auth.test.js` from the repository root for isolated
regression tests (install `kafka/ui-auth` dependencies first). The production
UI template has separate authentication settings.

Cluster/broker metrics, topics, message
browsing, consumer groups/lag and configuration views are available. JMX stays
inside the Docker network; neither it nor the UI is exposed publicly. The UI
has a 512 MiB heap, 1 GiB container limit, bounded message pages and rotated logs.
Use the production UI template below for a separate mTLS monitoring identity.

The local UI image is built from `KAFKA_UI_IMAGE` using [ui/Dockerfile](ui/Dockerfile).
Its header hides the GitHub, Discord and Product Hunt links. `manage.sh tools`
builds this customization so it persists when the UI container is recreated.
It also guards the topic ACL tab with the broker's advertised ACL capability.
The local broker has no ACL authorizer, so this tab explains that ACLs are not
enabled instead of calling Kafbat v1.5.0's unsupported endpoint and showing 500.
Clusters with ACL support still load the original ACL table. The build checks
the patched component and fails if an upstream upgrade changes its structure.

The scripts read `kafka/.env` using dotenv and use the same ports, topic names
and group ID when configuring the backend. Environment variables override the
file. `configure-backend.sh` updates Kafka-related settings only and stores a
private backup under `backend/.runtime-secrets/config-backups`.

## 30,000-agent deployment

See [the production sizing and rollout profile](production/README.md). It targets
30,000 events/s sustained and 90,000 events/s burst as a planning assumption,
with three brokers, RF3/minimum ISR2, 96 main partitions and separate API/worker
replicas. This local single-broker stack is not that production deployment.

`./scripts/manage.sh benchmark` sends one approximately 2 KiB event from each of
30,000 logical agents through a temporary six-partition topic and reconciles
unique consumption. It deletes its own test topic/group afterward and never
writes to the application alert database. It is a bounded broker-only check;
the production acceptance test must include authentication, storage, detection,
sustained load and failures.

## Topic contract

| Topic | Purpose | Default retention |
|---|---|---:|
| `soc.alerts.v1` | Validated security alerts awaiting persistence | 7 days |
| `soc.alerts.retry.v1` | Events retried after a storage failure | 7 days |
| `soc.alerts.dlq.v1` | Poison/invalid events for investigation | 30 days |
| `soc.health.v1` | Operational smoke checks only | 1 day |

The main topics use six partitions locally. Message keys contain
`tenant:company:system`, which keeps an endpoint's events ordered within its
partition. Producers use idempotence, `acks=-1`, and gzip compression. The
consumer upserts by `companyId + eventId` to deduplicate normal replay.

Producer retries retain KafkaJS idempotent sequencing. The API waits at most
`KAFKA_PUBLISH_WAIT_MS` (15 seconds by default), then returns retryable 503;
the underlying send can still complete. It keeps its place in the bounded
queue until it settles. Agents must preserve event IDs and their durable spool
entry until acknowledged. This is at-least-once delivery. The existing event-ID
lookup index is non-unique for legacy compatibility; replay checks pass, but
concurrent duplicate writes across partitions/consumers need a separately
reviewed unique-index migration before claiming database-wide exactly-once
behavior. No legacy records or indexes are deleted by the provisioning script.

Workers start new/uncommitted partitions from the earliest retained offset,
retain offsets during transient MongoDB outages, and commit mixed valid/invalid
chunks only after durable handling. Resolved offsets commit at five-second
intervals to bound replay on a crash. Fatal consumer crashes exit for supervision;
the backend restarts its local worker with capped backoff without a retry limit.

## Isolated recovery test

This test starts three disposable broker/controllers and a separate MongoDB,
kills test brokers, stops test MongoDB, then sends 30,000 logical-agent records
through three actual ingestion worker replicas. `HA_WORKER_COUNT=1` selects a
single-worker comparison. Ports 29092–29094 and 37017 must be free.
It creates its own tenant/company fixture and never writes application alerts.

```bash
# from repository root
docker compose -f kafka/tests/docker-compose.ha.yml up -d --wait --wait-timeout 180
node --disable-warning=TimeoutNegativeWarning kafka/tests/ha-check.js
docker compose -f kafka/tests/docker-compose.ha.yml down --volumes
```

Results: `/tmp/soc-kafka-ha-result.json`; final worker output:
`/tmp/soc-kafka-ha-worker.log`. Cleanup deletes only the isolated test project's
containers and volumes. This check uses the ingestion lookup index and routine
telemetry, not every SOC query index, enrichment or authenticated HTTP path.
See [recorded results](verification-2026-10-04.md) for scope and limitations.

## Daily operations

```bash
./scripts/manage.sh topics
./scripts/manage.sh describe
./scripts/manage.sh groups
./scripts/manage.sh lag
./scripts/manage.sh logs
./scripts/manage.sh down       # keeps data
./scripts/manage.sh reset      # destructive; requires typing DELETE
```

## Security model

- The host listener is bound to `127.0.0.1:19092`; it is not reachable by endpoint agents or other network hosts.
- The Docker listener is confined to the private Compose network.
- Kafka auto-topic creation is disabled; `kafka-init` creates only known topics.
- Never expose ports `9092` or `19092` publicly and never place Kafka credentials in an agent package.
- For a multi-host production cluster, use three or more brokers, TLS 1.3 where supported, SASL-SCRAM or mTLS, ACLs restricted by topic, and replication factor 3 with `min.insync.replicas=2`.
- Store TLS keys and SASL passwords in the deployment secret manager, not in `.env` or Git.

Backend TLS/SASL variables for an external secured Kafka cluster:

```env
INGESTION_MODE=broker
KAFKA_BROKERS=kafka-1.example:9093,kafka-2.example:9093,kafka-3.example:9093
KAFKA_SSL=true
KAFKA_SSL_CA_FILE=/run/secrets/kafka-ca.pem
KAFKA_SSL_CERT_FILE=/run/secrets/kafka-client.pem
KAFKA_SSL_KEY_FILE=/run/secrets/kafka-client-key.pem
# Or use SASL with TLS:
KAFKA_SASL_MECHANISM=scram-sha-512
KAFKA_SASL_USERNAME=ajnat-backend
KAFKA_SASL_PASSWORD=<secret-manager-injected-value>
KAFKA_REPLICATION_FACTOR=3
```

The local Compose stack deliberately uses plaintext only inside localhost/private
Docker networking. It is a development deployment, not a public production
broker cluster.
