# Disaster Recovery

## Objectives

Initial proposed objectives, pending business approval:

- metadata RPO <= 5 minutes, RTO <= 60 minutes.
- accepted event RPO 0 within broker quorum; regional disaster RPO <= 15 minutes
  after cross-region replication is enabled.
- event query RTO <= 4 hours from object storage replay/replica promotion.

## Procedures

- encrypted metadata snapshots plus point-in-time logs in another account/region.
- object versioning, retention lock where required and cross-region replication.
- broker topic/config backup and tested regional bootstrap.
- ClickHouse schema backup and restore from replicated object data.
- quarterly restore into an isolated account, with counts/checksums and timed RTO.
- retain deployment manifests, schema versions and encryption-key recovery.

Never call a backup successful until an automated restore and tenant-level
sample query pass.
