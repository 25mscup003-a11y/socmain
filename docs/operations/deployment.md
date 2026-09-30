# Production Deployment

## Deployment diagram

    Internet agents/users
          │ TLS + WAF/rate limits
    Public load balancer
          │
    ┌─────┴───────────────────────────┐
    │ stateless APIs / ingestion pods │  private subnets, non-root
    └─────┬───────────────────────────┘
          ├── broker (private, multi-AZ)
          ├── worker pools (private)
          ├── ClickHouse/query cluster (private)
          ├── metadata DB (private)
          └── object storage/private endpoint
                 │
          metrics/traces/logs (private)

## Required controls

- multi-stage pinned container builds, non-root UID, read-only root filesystem,
  dropped Linux capabilities and seccomp profile.
- separate API, ingestion and worker deployments.
- readiness, liveness and startup probes; graceful SIGTERM drain.
- resource requests/limits and PodDisruptionBudgets.
- horizontal scaling on CPU plus broker lag/ingestion latency.
- TLS everywhere; database, broker, metrics and admin endpoints private.
- secrets from a secret manager, not images/manifests.
- NetworkPolicies limiting each workload to required dependencies.
- migration Job runs once before rollout under a lease.
- canary/rolling release with schema compatibility and rollback gates.

## CI gates

Install from lockfiles, lint, tests, frontend builds, dependency audit, secret
scan, SAST, container scan, SBOM generation, signature and manifest validation.
No current CI/container implementation exists; these are Phase 6 deliverables.
