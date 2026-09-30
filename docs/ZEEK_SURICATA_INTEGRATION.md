# Zeek and Suricata integration

## Architecture

Zeek JSON and Suricata EVE JSON are read by the existing SOC endpoint agent. Each record is validated and normalized, then sent to `POST /api/ids/events`. MongoDB's unique `{companyId,eventId}` index provides atomic duplicate protection. Actionable events enter the existing Socket.IO, threat-intelligence and IDS-to-IPS decision flow; informational protocol telemetry is retained without triggering blocks.

Existing `/api/ids/zeek`, `/api/ids/suricata`, `/api/ids/generic` and IPS webhook contracts remain supported.

## Zeek configuration

Enable JSON logs in Zeek's `local.zeek`:

```zeek
@load policy/tuning/json-logs.zeek
@load policy/protocols/conn/community-id-logging.zeek
```

The agent discovers `conn.log`, `dns.log`, `http.log`, `ssl.log`, `files.log`, `notice.log`, `weird.log`, and `x509.log` under `/opt/zeek/logs/current` and `/var/log/zeek/current`. Override with `zeek_log_paths` in `company_config.json`. The agent account requires read-only access to those files.

## Suricata configuration

Enable EVE JSON in `suricata.yaml`, including `alert`, `flow`, `dns`, `http`, `tls`, `stats`, `anomaly`, and `fileinfo`. Enable `community-id: true` and keep EVE output at `/var/log/suricata/eve.json`, or set `suricata_eve_path` in agent configuration.

For IPS mode, configure Suricata AF_PACKET/NFQUEUE separately and test rules with:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml
sudo suricata-update
```

Detection does not itself authorize blocking. Existing SOC IDS/IPS policies, severity gates, threat-intelligence verification and the IPS service remain authoritative.

## Native predefined-policy deployment

Selecting a predefined policy now creates the tenant policy and immediately broadcasts an allow-listed native bundle to connected agents. Agents also poll the signed `GET /api/ids/agent-policies/:agentKey` endpoint, so an offline endpoint converges after reconnect.

The agent writes dedicated managed files instead of replacing vendor rules:

- `/etc/suricata/rules/soc-managed.rules`
- `<Zeek site>/soc-managed.zeek`
- deployment state under `/var/lib/soc-agent/ids-policies/state.json`

It adds each managed file to the existing sensor configuration, writes atomically, runs `suricata -T` and `zeek -b`, then reloads the service. A validation or reload failure restores every changed file and reports a critical `IDS_POLICY_DEPLOY_FAILED` event. Dashboard text is never rendered as sensor code: only preset IDs built into the agent are accepted. Custom policies remain SOC correlation/matching policies.

Suricata `block` presets generate `drop` actions. Packet dropping requires a correctly configured inline AF_PACKET/NFQUEUE deployment; in passive IDS mode the SOC IPS path still enforces confirmed blocks through the webhook and endpoint firewall. Zeek remains a detection/telemetry sensor and does not drop packets directly.

The agent service needs permission to update sensor configuration and reload services. Override `ids_policy_dir`, `suricata_config`, `suricata_soc_rules`, `zeek_local_script`, or `zeek_soc_script` in `company_config.json` for nonstandard installations.

## Authentication and API

```http
POST /api/ids/events
X-Integration-Secret: <INTEGRATION_SECRET>
Content-Type: application/json

{"company_id":"...","events":[{"event_id":"suricata:...","timestamp":"...","source":"suricata","sensor":"edge-1","log_type":"alert","severity":"high","category":"Attempted Admin","src_ip":"203.0.113.10","src_port":4444,"dest_ip":"10.0.0.5","dest_port":443,"protocol":"tcp","action":"allowed","signature":"Example","signature_id":"1001","community_id":"1:...","hostname":"example.test","actionable":true,"raw_event":"{}"}]}
```

Limits: 500 events/request, 64 KiB raw event, bounded strings, validated IPs/ports/severity/source. Duplicate event IDs return as `duplicates` and are not persisted again.

## Docker and production

Sensors require host networking, packet-capture capabilities and access to the monitored interface. Run them on the sensor host rather than inside the application backend container. Mount logs read-only into the endpoint agent when containerizing it. For high volume set `INGESTION_MODE=broker` and provision the existing Kafka topics/worker; retain MongoDB indexes and retention policy.

## Troubleshooting

- No events: verify sensor process, log file permissions, JSON output, `company_id`, backend URL and integration secret.
- HTTP 401: agent and backend `INTEGRATION_SECRET` differ.
- HTTP 400: inspect the bounded validation message; malformed records are never trusted.
- Duplicates: expected retries are suppressed by `event_id`.
- No IPS action: only actionable events enter the policy/TI gate; telemetry never blocks directly. Check the IPS webhook health and secret. A database blocklist record is audit state and is no longer reported as successful firewall enforcement when the webhook is unavailable.
- Policy deployment failed: inspect the `IDS_POLICY_DEPLOY_FAILED` alert and agent log, then run `suricata -T -c /etc/suricata/suricata.yaml` and `zeek -b <Zeek site>/soc-managed.zeek`. The previous working configuration is restored automatically.
- Zeek rotations: the current watcher re-discovers created paths; restart the agent after a rotation if the distribution replaces the inode rather than appending to the current symlink.

## Security operations

Restrict sensor log and configuration permissions, rotate integration secrets, use TLS between remote sensors and the backend, restrict ingress to sensor networks, monitor rejected payloads, and never expose the health/API endpoints publicly without a reverse-proxy policy.
