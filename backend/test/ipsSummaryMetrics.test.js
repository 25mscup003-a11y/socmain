const test = require('node:test');
const assert = require('node:assert/strict');
const net = require('node:net');
const Alert = require('../src/models/Alert.model');
const System = require('../src/models/System.model');
const Audit = require('../src/models/IpsAuditEvent.model');
const Whitelist = require('../src/models/IpsWhitelist.model');
const Violation = require('../src/models/IdsPolicyViolation.model');
const { BlockedIP } = require('../src/services/ips.service');
const engine = require('../src/services/ipsEngine.service');
const router = require('../src/routes/idsips.routes');

const handler = router.stack.find(layer => layer.route?.path === '/idsips/summary').route.stack.at(-1).handle;
const companyId = '6a8efb532c942f67c29534cc';

function fixture(t, auditCount) {
  const filters = {};
  t.mock.method(net.Socket.prototype, 'connect', function () {
    queueMicrotask(() => this.emit('connect'));
    return this;
  });
  t.mock.method(Alert, 'aggregate', () => {
    const query = { hint() { return this; }, option() { return this; }, exec: async () => [] };
    return query;
  });
  for (const [model, key, count] of [
    [BlockedIP, 'blocks', 3], [Whitelist, 'whitelist', 2],
    [Violation, 'policy', 4], [Audit, 'audit', auditCount], [System, 'isolation', 1],
  ]) {
    t.mock.method(model, 'countDocuments', filter => {
      filters[key] = filter;
      return { maxTimeMS: () => Promise.resolve(count) };
    });
  }
  t.mock.method(Audit, 'find', filter => {
    filters.auditRows = filter;
    let limit = auditCount;
    return {
      sort() { return this; },
      limit(value) { limit = value; return this; },
      lean: async () => Array.from({ length: Math.min(limit, auditCount) }, (_, index) => ({
        _id: String(index), companyId, action: 'Attack Detected',
        ts: new Date('2025-01-01'), detail: 'Historical audit event',
      })),
    };
  });
  return filters;
}

async function summary() {
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  await handler({ user: { role: 'company_admin', companyId }, query: { companyId: 'foreign-company' } }, res);
  return res;
}

test('historical audit events count on both the top card and audit tab, with the same 500-event limit', async t => {
  for (const total of [0, 50, 640]) {
    await t.test(`${total} stored events`, async t => {
      const filters = fixture(t, total);
      const res = await summary();
      const rows = await engine.getAuditEvents(companyId, 500);
      assert.equal(res.statusCode, 200);
      assert.equal(res.body.ipsMetrics.audit, rows.length);
      assert.equal(res.body.ipsMetrics.audit, Math.min(total, 500));
      assert.equal(filters.audit.ts, undefined, 'audit history is not restricted to 24 hours');
      assert.equal(String(filters.audit.companyId), companyId);
      assert.equal(String(filters.auditRows.companyId), companyId);
    });
  }
});

test('IPS summary preserves per-company scope and excludes log-only block records', async t => {
  const filters = fixture(t, 50);
  const res = await summary();
  assert.equal(res.statusCode, 200);
  for (const filter of Object.values(filters)) assert.equal(String(filter.companyId), companyId);
  assert.deepEqual(filters.blocks.method, { $ne: 'log-only' });
  assert.equal(filters.blocks.reverted, false);
  assert.ok(filters.blocks.$or.some(item => item.expiresAt?.$gt instanceof Date));
  assert.ok(filters.policy.createdAt.$gte instanceof Date, 'policy card still counts 24-hour violations');
  assert.deepEqual(res.body.ipsMetrics, { whitelist: 2, policy: 4, audit: 50, isolationFlow: 1 });
});
