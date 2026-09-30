# Phase 1 Repository Audit

Date: 2026-07-19

## Scope and baseline

The repository contains four deployable applications:

- backend: Node.js/Express 4, Socket.IO and Mongoose 7 over MongoDB.
- company: React 18/Vite company, partner and analyst portal.
- superadmin: React 18/Vite privileged portal.
- ipsserver: separate Node.js webhook service and React dashboard.
- backend/soc-agent: Python endpoint agent; an Android Java agent is present.

Observed local runtime: Node.js 24.16.0, npm 11.16.0, Python 3.13.14 and MongoDB
8.0.26. The main backend does not pin Node. No Docker, Kubernetes or CI
configuration exists. Both Nginx configuration files are empty.

## Current architecture

The main backend is a stateful monolith. It accepts agent heartbeats and alert
batches over HTTP, writes alerts/logs directly to MongoDB, then starts
enrichment, correlation, SOAR and IPS work with in-process callbacks. Socket.IO
is used for browser live updates and agent commands. Scheduled jobs and mutable
caches live inside the API process.

## Baseline validation

| Check | Result |
|---|---|
| Company Vite production build | Passed; 2.46 MB main JS chunk warning |
| Superadmin Vite production build | Passed; 0.75 MB main JS chunk warning |
| Main backend tests before this phase | No test script or suite |
| IPS backend tests | 6 passed, 2 failed: fixtures omit required company_id; one open interval |
| IPS frontend tests | Failed: no tests found |
| Lint/type checks | Not configured for main backend or Vite portals |

The first IPS run was blocked by sandbox port policy. A permitted localhost run
confirmed the two real test failures.

## Risk register

| Priority | Evidence and impact | Status |
|---|---|---|
| P0 | Socket handshakes/room joins had no auth; clients could subscribe to another tenant or superadmin. | Fixed with JWT/agent auth and room authorization tests. |
| P0 | First boot created a privileged account with a hardcoded public password. | Fixed; explicit one-time credentials required. |
| P0 | Agent-controlled paths caused synchronous reads of backend-host files. | Fixed; only endpoint-supplied hash/permission telemetry accepted. |
| P0 | Agent sender removed failed batches, causing silent loss. | Partially fixed with stable event IDs, retry/jitter and dedup. A durable disk spool remains required. |
| P0 | Generic log routes trusted one global integration secret plus caller company ID. | Fixed by default with company-bound HMAC credentials/agent scope; legacy global auth is an explicit migration flag. |
| P0 | KYC documents and agreements use unauthenticated static URLs. | Open; migrate to authenticated/signed downloads. |
| P1 | MongoDB is transactional and high-volume event storage. | Target split documented. |
| P1 | No broker, DLQ or consumer checkpoint; work starts in API callbacks. | Target worker design documented. |
| P1 | Startup scanned all companies; cluster workers repeated initialization/migrations. | Legacy scans are now opt-in; a one-shot versioned migration job remains required. |
| P1 | Deep offset pagination and uncontrolled limits occur in many routes. | Primary alert/log routes bounded; cursor migration remains. |
| P1 | Global request body limit was 25 MB and errors exposed internals. | Fixed with route limits and safe production errors. |
| P1 | Custom Socket.IO cluster IPC has no standard shared adapter. | Open. |
| P1 | Replay nonce cache is process-local and not horizontally consistent. | Open. |
| P1 | Raw reusable agent keys are stored in MongoDB and agent packages. | Open; hash/rotate or use mTLS. |
| P2 | Browser tokens in localStorage amplify XSS impact. | Open. |
| P2 | Timers/retries are process-local and non-durable. | Open. |
| P2 | Large frontend bundles and non-virtualized live screens. | Open. |
| P2 | No structured metrics/tracing and incomplete immutable audit coverage. | Open. |
| P3 | Empty Nginx placeholders; no containers, SBOM, CI or infrastructure validation. | Open. |

## Data/query findings

- Log and Alert have company/time indexes, but fixed TTL cannot express plan
  retention or legal hold.
- Several global fraud/risk indexes omit tenant/company prefixes.
- regex, count and deep skip queries become expensive at large offsets.
- Mongoose hooks perform company lookups during writes.
- tenant filtering is application-level, so a missed helper can leak data.

## Implemented in the first safe P0 slice

1. Authenticated Socket.IO handshakes and tenant-authorized rooms.
2. Removed hardcoded bootstrap administrator password.
3. Removed backend filesystem access based on agent telemetry.
4. Added bounded body sizes, pagination and batch rejection.
5. Added event IDs, retry/backoff/jitter and alert deduplication.
6. Added company-bound integration credentials and disabled global credential auth by default.
7. Added Node tests for tenant rooms, telemetry safety, limits and integration scope.


These changes do not prove the requested 100,000 events/second target.
