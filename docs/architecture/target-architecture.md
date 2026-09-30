# Target Enterprise Architecture

## Decision

Adopt a Kafka-compatible durable stream in phases. Redpanda is the preferred
initial option because it provides the Kafka protocol with a smaller operational
surface and tiered storage; managed Kafka/MSK remains compatible. Do not put it
in the request path until a real cluster, schema registry, quotas and failure
tests exist.

Keep MongoDB temporarily for transactional metadata while extracting immutable
events to ClickHouse. A later PostgreSQL migration may be evaluated for
billing/identity metadata. Archive raw batches in S3-compatible object storage.

    Agent disk spool
         │
    Load balancer
         │
    Stateless ingestion ──acks=all──> Kafka-compatible broker
                                      │
                         normalization/enrichment ──> tenant DLQ
                                      │
                         detection/correlation
                              │               │
                      ClickHouse hot/warm   Alerts/incidents
                              │               │
                      Object storage cold   notification/SOAR
                              │
                          Query API <── portals

## Durability

The ingestion API authenticates, validates envelope size/schema and checks
quota, then publishes with quorum acknowledgement and idempotent producer
semantics. It succeeds only after broker durability. Storage and detection are
asynchronous. Poison messages are isolated with bounded retries and DLQ reasons.

## Partitioning

- broker key: hash of tenant_id plus agent_id; large tenants receive dedicated
  partition groups.
- ClickHouse order: tenant_id, event_date, agent_id, event_time, event_id.
- use time partitions; never create a partition per tenant.
- object key: tenant/year/month/day/hour/schema-version/batch-id.

Agent enrollment, human identity, ingestion, query, workers and integrations are
separate principals. Tenant scope is server-derived and immutable.
