const test = require('node:test');
const assert = require('node:assert/strict');
const {
  buildCapabilityQuery,
  capabilityEvidenceFilter,
  clampResultLimit,
  clampWindowHours,
  indicatorValue,
  indexedCapabilityFilter,
  summarizeCapabilityRows,
} = require('../src/utils/advancedCapability');

test('advanced capability filters support the three public advanced capabilities', () => {
  for (const id of [29, 30, 31]) assert.ok(capabilityEvidenceFilter(id));
  assert.equal(capabilityEvidenceFilter(3), null);
  assert.deepEqual(indexedCapabilityFilter(29), { $or: [{ capabilityId: 29 }, { capabilityIds: 29 }] });
});

test('capability query always contains company and time tenant boundaries', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const query = buildCapabilityQuery({ companyId: 'company-a', capabilityId: 29, since, departmentId: 'dept-a' });
  assert.deepEqual(query.$and[0], {
    companyId: 'company-a',
    createdAt: { $gte: since },
    departmentId: 'dept-a',
  });
  assert.throws(() => buildCapabilityQuery({ capabilityId: 29, since }), /companyId is required/);
  assert.throws(() => buildCapabilityQuery({ companyId: 'company-a', capabilityId: 3, since }), /Unsupported/);
});

test('DNS sinkhole live query requires real sinkhole evidence beyond old capability tags', () => {
  const since = new Date('2026-07-19T00:00:00.000Z');
  const query = buildCapabilityQuery({ companyId: 'company-a', capabilityId: 31, since });
  assert.equal(query.$and.length, 3);
  assert.deepEqual(query.$and[1], { $or: [{ capabilityId: 31 }, { capabilityIds: 31 }] });
  assert.ok(query.$and[2].$or.some(item => item.source));
  assert.ok(query.$and[2].$or.some(item => item.sinkholeIp));
});

test('window and row limits are bounded for predictable query cost', () => {
  assert.equal(clampWindowHours(0), 1);
  assert.equal(clampWindowHours(900), 24);
  assert.equal(clampWindowHours('bad'), 24);
  assert.equal(clampResultLimit(0), 1);
  assert.equal(clampResultLimit(9000), 500);
});

test('normalizes indicators from canonical and legacy raw telemetry', () => {
  assert.equal(indicatorValue({ tiDomain: 'evil.test' }, 'domain'), 'evil.test');
  assert.equal(indicatorValue({ rawEvent: { raw: { new_ip: '203.0.113.7' } } }, 'ip'), '203.0.113.7');
  assert.equal(indicatorValue({ rawEvent: { process: 'nginx' } }, 'process'), 'nginx');
});

test('summary uses exact database totals while deriving real breakdowns', () => {
  const alerts = [
    { severity: 'critical', hostname: 'host-a', rawEvent: { domain: 'bad.test', query_type: 'A' }, blocked: true },
    { severity: 'high', hostname: 'host-a', rawEvent: { domain: 'bad.test', query_type: 'A' } },
  ];
  const summary = summarizeCapabilityRows(alerts, [{ name: 'host-a', isOnline: true }], 31, {
    total: 12,
    affectedEndpoints: 4,
    severity: { critical: 3, high: 5, medium: 2, low: 2 },
  });
  assert.equal(summary.total, 12);
  assert.equal(summary.affectedEndpoints, 4);
  assert.equal(summary.critical, 3);
  assert.equal(summary.maliciousDomains, 1);
  assert.deepEqual(summary.breakdowns.domains[0], { label: 'bad.test', value: 2 });
});
