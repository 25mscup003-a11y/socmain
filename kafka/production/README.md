# Kafka sizing for 30,000 agents

Planning assumption until measured: one event/agent/second sustained, three
events/agent/second for a five-minute burst, and 2 KiB/event before compression.
That is **30,000 events/s sustained and 90,000 events/s burst**. Registration
count alone does not establish throughput. These profiles have not been load
validated on a production cluster.

## Infrastructure starting point

| Component | Initial allocation | Scale signal |
|---|---|---|
| Kafka brokers | 3 separate hosts/zones, each 8 vCPU, 32 GiB RAM, 4 TB usable NVMe, 10 Gb/s network, 6 GiB JVM heap | Disk latency/utilization, ISR, network, producer p99 |
| KRaft controllers | 3 small separate hosts, each 2 vCPU, 4 GiB RAM, persistent SSD | Quorum health and controller latency |
| Ingestion API | 6 processes/replicas, initially 2 vCPU and 2 GiB each | Accepted EPS, 503 rate, event-loop lag |
| Alert workers | 12 processes/replicas, initially 2 vCPU and 2 GiB each | Lag age, stored EPS, storage latency |
| MongoDB | Separate replica set; size from the complete indexed workload | Bulk-write latency, IOPS, connection count |

The local Compose broker is a development instance. Three broker containers on
one laptop do not provide independent failure domains or this storage capacity.
API replicas also need the application's existing shared socket/rate-limit and
authentication infrastructure; this profile changes only ingestion settings.

At 2 KiB/event, ingress is 61.44 MB/s sustained and 184.32 MB/s at burst, before
replication. One day contains 5.31 TB raw. With RF3 it consumes about 3.98 TB
cluster-wide at measured 4:1 compression, or 15.93 TB without compression,
before segment/index overhead and free-space reserve. Three 4 TB disks are a
starting point only if compression is adequate; keep at least 30% free, measure
retained bytes/event and resize before accepting load. Retry and DLQ traffic
consume additional disk. Kafka retention is a replay window, not archival.

MongoDB can become the bottleneck before Kafka. The worker currently upserts
every alert and performs enrichment/correlation for actionable records. Simply
enabling ClickHouse-only mode changes application semantics; it is not enabled
by this profile. Validate the complete MongoDB-backed flow and queries before
claiming support for 30,000 agents.

## Deploy

1. Allocate real private hostnames, storage and server/client certificates from
   your CA. Certificates need matching DNS SANs. Use supported Kafka binaries
   and JVM for your chosen release; these property templates target KRaft Kafka
   3.6+ configuration. Set node IDs and racks per host. Broker IDs are 1/2/3;
   controller IDs are 101/102/103. Use a managed Kafka cluster as an alternative.
2. Install the broker/controller property files on the matching hosts. Mount the
   PEM certificates and unencrypted PKCS#8 keys as private service-readable
   files. Restrict 9093 to services and 9094 to the KRaft quorum/brokers. Match
   `super.users` to exact certificate subjects. Give all nodes the same new
   KRaft cluster ID when formatting **new, empty** storage; preserve existing
   metadata and IDs during an upgrade. Start controllers, then brokers.
3. Merge `backend-30k.env.example` into the full secured deployment environment;
   provide real endpoints/certificates and the existing application secrets.
   Keep the local `configure-backend.sh` away from production environments.
4. Use an admin certificate to run `npm run broker:provision` from `backend`.
   `DOTENV_CONFIG_PATH` can select a separate complete environment file. The
   provisioner checks available brokers, replica/partition layout, retention
   and minimum ISR. It refuses to silently alter an existing topic.
   Run `npm run broker:provision-storage` with the deployment database URI too;
   it adds the required company/event lookup if absent, preserving records and
   existing indexes. Do not depend on Mongoose auto-indexing during startup.
5. Grant the application certificate principal Write/Describe on the alert,
   retry and DLQ topics, Read on alert/retry, Read on the consumer group, and
   cluster IdempotentWrite for the idempotent producer. Grant monitoring its
   own read/describe principal; do not give application clients the admin key.
6. Start API replicas with `KAFKA_AUTO_START_WORKER=false`. Start **12 separate**
   `npm run worker:alerts` replicas with the same consumer group. Set a unique
   client ID per replica. Four concurrent partitions per worker gives 48 active
   processing slots initially; 96 main partitions leave growth room. Bound
   total MongoDB connections across all replicas.

For systemd hosts, `alert-worker@.service` supplies restart supervision, a
20-second graceful stop and a 2 GiB memory ceiling. Adjust `/opt/ajnat`, the
`ajnat` service account and Node binary path, then install the template in
`/etc/systemd/system`. Put the complete service environment in the private
`/etc/ajnat/backend.env`; enable the desired instances, e.g.
`systemctl enable --now alert-worker@1.service`. Distribute the planned 12
instances across worker hosts; do not allocate 24 GiB blindly on a shared host.
Each instance gets a unique hostname/instance client ID and the same group.

RF3 + minimum ISR2 + producer `acks=-1` permits one broker outage while retaining
quorum writes. With two replicas unavailable, writes must fail and agents retry.
The API returns 503 + Retry-After if its bounded producer queue is full or a
publish cannot be acknowledged. Agents must retain the same event IDs on retry.
Workers retain uncommitted Kafka offsets and heartbeat during transient storage
outages; invalid records still take the bounded retry/DLQ path.
The caller's 15-second deadline does not cancel an ambiguous publish; outstanding
deliveries keep counting against the queue and byte limits until settled.
The current event-ID lookup is non-unique for legacy compatibility. Plan and
verify an explicit duplicate audit and unique-index migration before promising
database-wide exactly-once results under concurrent replay.

## Production UI

Deploy `docker-compose.ui.yml` on a private operations host that resolves the
broker DNS names. Copy `ui-config.yml.example` to `ui-config.yml` and replace
the endpoints. Set `KAFKA_UI_TLS_DIR` to a private directory containing
`kafka-ca.pem` and `kafka-ui.pem` (UI certificate chain plus PKCS#8 private key).
Use a separate monitoring principal with Describe/DescribeConfigs and topic
Read plus consumer-group Describe permissions. No cluster administration key
is needed; the template sets the cluster read-only. PEM files must be readable
by the UI container's service UID and protected from other users.

Run `node kafka/scripts/setup-ui.js` from the repository root to generate the
private login, then run
`docker compose -f kafka/production/docker-compose.ui.yml up -d` on that host.
It listens on `127.0.0.1:18080`; access through an SSH tunnel or your authenticated
HTTPS reverse proxy. Keep the local and production UI on separate hosts or
assign different ports. Kafka transport uses certificate validation and mTLS;
real certificates/endpoints must be supplied before this template can run.
Local JMX is not forwarded to production. For production broker metrics use
your authenticated/private monitoring system rather than exposing raw JMX.

## Topic migration and acceptance

The production profile uses 96 main, 24 retry and 12 DLQ partitions, RF3,
24-hour main/retry retention and 72-hour DLQ retention. Local topics keep six
partitions, RF1 and their existing retention. Increasing partitions remaps keys;
drain/pause old producers and consumers or use versioned topics for migration.
Never reset consumer offsets or remove volumes as a scaling operation.

Use isolated tenant/agent credentials and an isolated database/cluster for the
load test in `docs/performance/load-testing.md`. Run 3k, 10k, 30k events/s for
15 minutes each; 30k/s for 2 hours; 90k/s for 5 minutes; then a 24-hour soak.
Send realistic payloads from 30,000 distinct logical agent keys. A broker-only
health check does not validate authentication, storage or detection capacity.

Pass criteria: accepted unique events reconcile with durably stored unique
events; no unexplained loss; no unbounded RSS/lag; API p95 under 500 ms and p99
under 2 s at sustained load; lag age under 30 s; burst backlog recovers within
10 minutes; one-broker failure maintains writes; MongoDB outage recovers without
moving all otherwise-valid records to DLQ. Record actual results and hardware.

Monitor under-replicated/offline partitions, disk free space, broker bytes in,
producer errors, consumer lag and DLQ growth. Use lag **age** as well as count;
event rate changes make a fixed message-count threshold insufficient.
