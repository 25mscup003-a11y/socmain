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
cd /home/chaudahry/Desktop/soc/kafka
cp .env.example .env                    # optional overrides
chmod +x scripts/*.sh
./scripts/manage.sh up
./scripts/configure-backend.sh          # safely backs up backend/.env first
cd ../backend
npm start
```

The backend already starts its Kafka alert-consumer worker whenever
`INGESTION_MODE=broker`. Do not launch a second standalone worker on the same
machine unless that is intentional; replicas in the same consumer group divide
partitions safely.

Check the stack:

```bash
cd /home/chaudahry/Desktop/soc/kafka
./scripts/manage.sh status
./scripts/manage.sh lag
```

Optional local operations UI and Prometheus exporter:

```bash
./scripts/manage.sh tools
# UI:      http://localhost:18080
# Metrics: http://localhost:19308/metrics
```

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
consumer upserts by `companyId + eventId`, so replay does not duplicate alerts.

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
