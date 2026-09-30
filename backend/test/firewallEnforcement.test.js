const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildApplicableRulesQuery,
  getIpsSyncFailure,
} = require('../src/routes/firewall.routes')._test;

test('pending firewall query keeps expiry and scope filters together', () => {
  const now = new Date('2026-01-01T00:00:00.000Z');
  const system = { _id: 'system-1', companyId: 'company-1', departmentId: 'department-1' };
  const query = buildApplicableRulesQuery(system, now);

  assert.equal(query.enabled, true);
  assert.equal(query.$and.length, 2);
  assert.equal(query.$and[0].$or[2].expiresAt.$gt, now);
  assert.deepEqual(query.$and[1].$or, [
    { level: 'global' },
    { companyId: 'company-1', level: 'company' },
    { companyId: 'company-1', level: 'department', departmentIds: 'department-1' },
    { companyId: 'company-1', level: 'system', systemId: 'system-1' },
  ]);
});

test('IPS sync accepts a successful endpoint-agent delegation', () => {
  const response = {
    status: 200,
    data: { ok: true, enforced: false, delegated: true, method: 'endpoint-agent' },
  };

  assert.equal(getIpsSyncFailure(response, 'block'), null);
  assert.equal(getIpsSyncFailure(response, 'unblock'), null);
});

test('IPS sync still rejects log-only and unconfirmed enforcement responses', () => {
  assert.match(getIpsSyncFailure({
    status: 200,
    data: { ok: true, enforced: false, method: 'log-only' },
  }, 'block'), /log-only mode/);

  assert.match(getIpsSyncFailure({
    status: 200,
    data: { ok: true, enforced: false },
  }, 'unblock'), /IPS unenforcement failed \(HTTP 200\)/);
});

test('IPS sync preserves explicit upstream errors', () => {
  const failure = getIpsSyncFailure({
    status: 503,
    data: { ok: false, error: 'endpoint queue unavailable' },
  }, 'block');

  assert.equal(failure, 'endpoint queue unavailable');
});
