const { createClient } = require('@clickhouse/client');

let client;
function identifier(value, fallback) {
  const selected = String(value || fallback);
  if (!/^[a-zA-Z_][a-zA-Z0-9_]*$/.test(selected)) throw new Error(`Invalid ClickHouse identifier: ${selected}`);
  return selected;
}

function settings() {
  return {
    database: identifier(process.env.CLICKHOUSE_DATABASE, 'soc'),
    table: identifier(process.env.CLICKHOUSE_ALERT_TABLE, 'alerts_v2'),
    retentionDays: Math.max(1, Math.min(3650, Number(process.env.CLICKHOUSE_RETENTION_DAYS || 90))),
  };
}

function getClient() {
  if (!client) {
    client = createClient({
      url: process.env.CLICKHOUSE_URL || 'http://127.0.0.1:8123',
      username: process.env.CLICKHOUSE_USERNAME || 'default',
      password: process.env.CLICKHOUSE_PASSWORD || '',
      request_timeout: Number(process.env.CLICKHOUSE_REQUEST_TIMEOUT_MS || 30000),
      compression: { request: true, response: true },
    });
  }
  return client;
}

function clickhouseEnabled() {
  return ['clickhouse', 'dual'].includes(process.env.HOT_EVENT_STORE);
}

function toClickHouseDateTime(value) {
  return new Date(value).toISOString().replace('T', ' ').replace('Z', '');
}

function mapAlertRow(document, now = Date.now()) {
  return {
    tenant_id: String(document.tenantId),
    company_id: String(document.companyId),
    event_id: String(document.eventId),
    event_time: toClickHouseDateTime(document.createdAt || now),
    received_at: toClickHouseDateTime(now),
    severity: String(document.severity || 'low'),
    category: String(document.eventCategory || 'other'),
    source: String(document.source || 'agent'),
    rule_id: String(document.ruleId || ''),
    system_id: String(document.systemId || ''),
    agent_name: String(document.agentName || ''),
    description: String(document.description || ''),
    src_ip: String(document.srcip || ''),
    raw_json: JSON.stringify(document.rawEvent || {}),
    version: now,
  };
}

async function migrateClickHouse() {
  const target = settings();
  const connection = getClient();
  await connection.command({ query: `CREATE DATABASE IF NOT EXISTS ${target.database}` });
  await connection.command({ query: `
    CREATE TABLE IF NOT EXISTS ${target.database}.${target.table} (
      tenant_id String,
      company_id String,
      event_id String,
      event_time DateTime64(3, 'UTC'),
      received_at DateTime64(3, 'UTC'),
      severity LowCardinality(String),
      category LowCardinality(String),
      source LowCardinality(String),
      rule_id String,
      system_id String,
      agent_name String,
      description String,
      src_ip String,
      raw_json String CODEC(ZSTD(3)),
      version UInt64
    ) ENGINE = ReplacingMergeTree(version)
    PARTITION BY toYYYYMM(event_time)
    ORDER BY (tenant_id, company_id, event_id)
    TTL toDateTime(event_time) + INTERVAL ${target.retentionDays} DAY DELETE
    SETTINGS index_granularity = 8192
  ` });
  return target;
}

async function insertAlerts(documents) {
  if (!documents.length) return { inserted: 0 };
  const target = settings();
  await getClient().insert({
    table: `${target.database}.${target.table}`,
    values: documents.map(document => mapAlertRow(document)),
    format: 'JSONEachRow',
  });
  return { inserted: documents.length };
}

async function closeClickHouse() {
  if (client) await client.close();
  client = null;
}

module.exports = { settings, clickhouseEnabled, toClickHouseDateTime, mapAlertRow, migrateClickHouse, insertAlerts, closeClickHouse };
