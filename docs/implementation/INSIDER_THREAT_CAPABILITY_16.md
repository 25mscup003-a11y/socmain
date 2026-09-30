# Insider Threat Detection (Capability 16)

## Scope

Capability 16 reuses the existing AJNAT collectors, signed alert ingestion,
MongoDB `alerts` collection, tenant/department scope, Socket.IO company rooms,
correlation, assignment and SOAR workflows. It does not collect passwords,
message or file content, keystrokes, camera or microphone data.

## Real telemetry flow

1. Existing authentication, process, file, USB, network, time and geolocation
   collectors produce evidence-backed events.
2. `core/insider_threat.py` cross-tags only recognized insider-risk evidence
   with capability 16 and adds an explainable `insiderSignalType`.
3. `core/sender.py` redacts command-line secrets and sends the signed event.
4. The alert ingestion route validates agent/tenant scope, normalizes and
   persists the event, then emits `insider:event` to the company Socket.IO room.
5. The existing dashboard uses the tenant-scoped
   `/api/dashboard/capabilities/16/live` endpoint and refreshes on that event.

The live query uses the existing compound indexes
`{ companyId, capabilityId, createdAt }` and
`{ companyId, capabilityIds, createdAt }`; it does not use regex scans.

## Supported evidence

- Windows/Windows Server: Windows event-log authentication evidence, process
  and command metadata, USB metadata, file-change metadata and network
  metadata exposed by the installed agent.
- Linux/Linux Server: auth/audit log detections, process and command metadata,
  mounted removable-media file metadata, file-change metadata and network
  metadata.
- macOS: supported process, file, network and unified-log metadata from the
  current agent collectors.
- Android and Solaris: only metadata already exposed by their existing agent
  collectors is classified; unsupported endpoint controls are not simulated.
- Zeek/Suricata evidence remains available through the existing backend
  correlation path; no TLS interception is introduced.

## Deployment

From the backend directory run:

```bash
npm run migrate:insider-threat
```

The migration is idempotent and creates no alerts. It adds capability 16 and a
signal classification only to existing, non-synthetic events with verified
canonical rule IDs. Deploy/restart the updated AJNAT agent and backend, then
deploy the company frontend build.

## Verification

1. Open `/company-admin/edr?capabilityId=16&capability=insider-threat-detection`.
2. Generate an authorized test signal such as `sudo`, a blocked USB policy
   attempt or a controlled archive-staging command.
3. Confirm a single event appears with the actual user, endpoint, rule,
   severity, risk score and timestamp.
4. Confirm another tenant cannot retrieve the record.
5. Confirm the report endpoint returns only the authenticated company scope.

## Limits

- This integration classifies deterministic endpoint evidence; it does not
  claim that an employee is malicious from an anomaly alone.
- File read/access visibility depends on OS audit policy. The generic file
  watcher reliably reports create/change/delete/permission metadata.
- Adapter transfer anomalies are volume based unless process, Zeek or Suricata
  attribution exists.
- HR, IAM, badge and business/database audit context requires an authorized
  external integration and is not fabricated.
- Destructive response actions remain approval-gated by the existing SOAR
  workflow.

## Rollback

Roll back the listed capability-16 code files and redeploy the previous agent,
backend and frontend versions. The migration is additive; leaving its tags in
place is safe. If data rollback is required, first stop new ingestion and remove
capability 16 only from the canonical rule IDs listed in
`019-insider-threat-backfill.js`; do not run a tenant-wide unconditional pull.
