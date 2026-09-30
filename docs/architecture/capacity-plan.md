# Capacity Plan

## Workload

- 1,000,000 registered agents.
- 150,000 events/agent/90 days.
- 150 billion events/90 days; 1.67 billion/day; about 19,290/second average.
- target: 100,000/second sustained and 250,000/second burst.

At 1 KiB/event, average ingress is about 19.8 MB/s, sustained target about
102 MB/s and burst about 256 MB/s before protocol/replication overhead.

## Ninety-day sensitivity

| Average event | Raw | 4:1 compressed | RF3 plus 30% index/part overhead |
|---|---:|---:|---:|
| 0.5 KiB | 75 TB | 18.75 TB | 73.1 TB |
| 1.0 KiB | 150 TB | 37.5 TB | 146.3 TB |
| 2.0 KiB | 300 TB | 75 TB | 292.5 TB |

Cold object storage at compressed size plus 20% is approximately 22.5, 45 or
90 TB. Object-backed databases may avoid tripling every stored byte.

## Starting topology, subject to tests

- Development: single broker and local metadata DB; non-production only.
- Staging: 3 broker nodes/AZs, 3 ClickHouse nodes, metadata replica set, object
  storage and at least 3 ingestion/worker replicas.
- Production test: broker capacity at least 200 MB/s ingress RF3, 6-12 ingestion
  pods, 6+ normalization consumers, separate detection consumers and ClickHouse
  sized from measured compressed bytes/event.

Published Redpanda BYOC tiers list 200 MB/s at Tier 4 and 400 MB/s at Tier 5.
This is planning evidence, not a workload result.

## Estimated monthly cost, not a quote

- Development: USD 300-1,500.
- HA staging: USD 3,000-12,000.
- Average production with 45-150 TB searchable/object-backed: USD 25,000-120,000.
- sustained 100k/s, long hot retention and cross-region DR: USD 80,000-300,000+.

AWS states S3 Standard starts near USD 0.023/GB-month for the first 50 TB;
broker, ClickHouse compute, requests, backup and transfer are additional.
Recalculate with measured compression/query bytes and vendor calculators.

References:

- https://aws.amazon.com/s3/pricing/
- https://aws.amazon.com/msk/pricing/
- https://clickhouse.com/pricing
- https://docs.redpanda.com/cloud-data-platform/reference/tiers/byoc-tiers/
