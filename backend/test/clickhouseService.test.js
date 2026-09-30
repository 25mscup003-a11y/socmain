const test = require('node:test');
const assert = require('node:assert/strict');
const { mapAlertRow } = require('../src/services/clickhouse.service');

test('ClickHouse rows preserve tenant key and stable event id', () => {
  const row = mapAlertRow({
    tenantId: 'tenant-a', companyId: 'company-a', eventId: 'event-a',
    createdAt: '2026-07-19T12:00:00.000Z', severity: 'high', rawEvent: { safe: true },
  }, 1000);
  assert.equal(row.tenant_id, 'tenant-a');
  assert.equal(row.company_id, 'company-a');
  assert.equal(row.event_id, 'event-a');
  assert.equal(row.event_time, '2026-07-19 12:00:00.000');
  assert.equal(row.raw_json, '{"safe":true}');
});

test('ClickHouse v2 replacement key excludes mutable event time', async () => {
  const source = require('node:fs').readFileSync(require.resolve('../src/services/clickhouse.service'), 'utf8');
  assert.match(source, /alerts_v2/);
  assert.match(source, /ORDER BY \(tenant_id, company_id, event_id\)/);
  assert.doesNotMatch(source, /ORDER BY \([^\n]*event_time/);
});
