# Persistence Mechanism Detection (Capability 8)

Capability 8 extends the existing AJNAT endpoint pipeline; it does not run a separate service or database.

## Data flow

1. `soc-agent` uses bounded native inventories and change detection for scheduled tasks/cron, services/systemd, startup locations, registry autoruns, SSH authorized keys, WMI subscriptions, browser extensions, drivers/modules and boot configuration.
2. The existing durable sender buffers, de-duplicates, redacts and batches events over the authenticated agent channel.
3. Alert ingestion normalizes persistence fields into the existing `alerts` collection, retains tenant/company/department scope, runs correlation/alert processing, and publishes `persistence:event` through the authenticated company Socket.IO room.
4. The existing Capability 8 dashboard reads `/api/persistence/events` and applies WebSocket events without a refresh. Its layout is unchanged and all cards/tables/charts are calculated from returned agent records.

## APIs

All endpoints require JWT authentication and an analyst-or-higher role. Company and department scope is derived from the authenticated user.

- `GET /api/persistence/events`
- `GET /api/persistence/events/:id`
- `GET /api/persistence/alerts`
- `GET /api/persistence/hosts`
- `GET /api/persistence/techniques`
- `GET /api/persistence/statistics`
- `GET /api/persistence/timeline`
- `GET /api/persistence/export/csv`
- `GET /api/persistence/export/pdf`

Common filters are `windowHours`, `from`, `to`, `severity`, `status`, `hostname`, `user`, `technique`, `type`, `search`, and `departmentId`. Event lists are paginated and capped.

## Deployment

Deploy the updated agent package and backend/frontend together. Apply the index/backfill migration once:

```bash
cd backend
npm run migrate:persistence-monitoring
```

The migration tags legacy records only when concrete persistence evidence exists and creates tenant-scoped indexes. It does not create synthetic alerts.

## Performance and privacy

- Known persistence paths are polled at the existing process-asset interval (default five minutes); no full-disk scan is added.
- File contents and SSH key material are not transmitted. Only artifact metadata and SHA-256 fingerprints are sent.
- Dashboard polling is a 60-second recovery path. Normal updates use `persistence:event`.
- APIs use bounded result limits, indexed filters and MongoDB query deadlines.
