# Email Threat Monitoring (Capability 15)

## Data flow

The desktop agent emits signed capability-15 events through the existing durable alert queue. The existing `/api/alerts` and `/api/alerts/batch` ingestion paths apply tenant and endpoint identity, store the events in MongoDB, run alert/SOAR/correlation processing, and publish `email:event` to the tenant Socket.IO room.

The company UI at `/company-admin/edr?capabilityId=15&capability=email-threat-monitoring` reads the tenant-scoped `/api/email-threat/*` APIs and refreshes immediately when `email:event` arrives.

## Endpoint collection and privacy boundary

The agent monitors native mail-client and mail-server process starts, suspicious mail-client child processes, download metadata after webmail activity, and browser-history URL metadata for supported webmail providers. Query strings are removed. Cookies, credentials, form values, message bodies, and attachment contents are not uploaded.

Browser-only monitoring cannot reliably see sender, recipient, SPF, DKIM, DMARC, mailbox rules, OAuth grants, or message quarantine state because HTTPS and browser sandboxes intentionally protect that content. Configure an authorized Microsoft 365, Google Workspace, or mail-gateway connector to populate those fields. The Settings page reports which connectors are configured.

## Deployment

1. Apply indexes with `npm run migrate:email-threat` from `backend/`.
2. Rebuild/redeploy the desktop agent package so `collectors/email_threat.py` is installed.
3. Set `EMAIL_MONITOR_INTERVAL_SECONDS` if the default 30-second polling interval is unsuitable.
4. Configure relevant threat-intelligence and mail-platform credentials in the backend environment.

Quarantine and indicator-block actions use the existing signed automated-response pipeline and approval controls. CSV, Excel-compatible XML, PDF, and JSON exports honor the active report filters.
