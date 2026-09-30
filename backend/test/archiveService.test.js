const test = require('node:test');
const assert = require('node:assert/strict');
const { archiveKey } = require('../src/services/archive.service');

test('archive keys are tenant and time partitioned', () => {
  const key = archiveKey({ tenantId: 't1', companyId: 'c1', kind: 'alert', date: '2026-07-19T12:30:00Z', batchId: 'b1' });
  assert.equal(key, 'tenant=t1/company=c1/kind=alert/year=2026/month=07/day=19/hour=12/b1.ndjson.gz');
});
