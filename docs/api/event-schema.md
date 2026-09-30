# Security Event Envelope

Target schema version: soc.event.v1.

    {
      "schema_version": "soc.event.v1",
      "event_id": "stable-uuid-or-ulid",
      "batch_id": "uuid-or-ulid",
      "tenant_id": "server-derived",
      "company_id": "server-derived",
      "agent_id": "enrolled-agent-id",
      "sequence": 12345,
      "event_time": "2026-07-19T00:00:00.000Z",
      "received_time": "server-generated",
      "type": "process.started",
      "severity": "low",
      "source": "endpoint-agent",
      "host": { "name": "host-1", "os": "linux" },
      "network": { "source_ip": "192.0.2.1" },
      "process": { "name": "example", "pid": 123 },
      "message": "bounded summary",
      "attributes": {}
    }

## Batch contract

- JSON first; evaluate NDJSON/Protobuf using CPU/network benchmarks.

## Ingestion authentication

- User/API clients may send a scoped JWT in `Authorization: Bearer ...`.
- Company integrations send `x-company-id` and `x-company-integration-key`. The key is an HMAC-SHA256 of the company ID using `INTEGRATION_KEY_SECRET`; it cannot be reused for another company.
- Enrolled agents may authenticate with their assigned `agentKey`; the backend resolves and enforces the system's company.
- The former global `x-integration-secret` path is disabled by default. `ALLOW_LEGACY_GLOBAL_INTEGRATION_SECRET=true` exists only as a time-limited migration switch.
- gzip accepted with limit applied after decompression.
- default maximum 500 events and 5 MiB inflated body.
- every event belongs to one authenticated agent and schema version.
- event IDs stay stable across retries.
- success means configured durability boundary acknowledged.
- partial failure returns accepted/rejected IDs and reason codes.
- use 400 malformed, 401/403 identity, 409 replay, 413 size/count,
  422 schema, 429 quota/backpressure and 503 unavailable durability.

Consumers accept current and previous schema during rolling upgrades. Breaking
changes need a new version/topic and dual-write or translation window.
