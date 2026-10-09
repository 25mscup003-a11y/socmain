const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../src/services/ipsEngine.service');
const service = require('../src/services/ips.service');
const System = require('../src/models/System.model');
const { requireManager } = require('../src/middleware/auth.middleware');
const engineRoutes = require('../src/routes/ips-engine.routes');
const systemRoutes = require('../src/routes/system.routes');

const companyId = '6a8efb532c942f67c29534cc';
const systemId = '6a8efb532c942f67c29534cd';
const user = { role: 'company_admin', companyId, email: 'admin@example.test' };
function response() {
  return { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
}
function handler(router, path, method) {
  const route = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]).route;
  assert.ok(route.stack.some(layer => layer.handle === requireManager));
  return route.stack.at(-1).handle;
}

test('manual engine endpoints distinguish ACK, queue, and failure', async t => {
  t.mock.method(System, 'exists', async () => ({ _id: systemId }));
  for (const [path, method, phases] of [['/isolate', 'manualIsolate', ['isolated', 'isolation_pending', 'isolation_failed']], ['/recover', 'manualRecover', ['recovered', 'recovery_pending', 'recovery_failed']]]) {
    const stub = t.mock.method(engine, method, async () => ({}));
    for (const [index, phase] of phases.entries()) {
      stub.mock.mockImplementation(async () => ({ phase, timers: [setTimeout(() => {}, 1)] }));
      const res = response();
      await handler(engineRoutes, path, 'post')({ user, body: { srcIp: '203.0.113.9', attackType: 'Port Scan', systemId } }, res);
      assert.equal(res.statusCode, [200, 202, 502][index]);
      assert.equal(res.body.ok, index === 0);
      assert.doesNotThrow(() => JSON.stringify(res.body));
    }
  }
});

test('foreign company endpoint cannot be isolated', async t => {
  t.mock.method(System, 'exists', async query => { assert.equal(query.companyId, companyId); return null; });
  t.mock.method(engine, 'manualIsolate', () => { throw new Error('must not dispatch'); });
  const res = response();
  await handler(engineRoutes, '/isolate', 'post')({ user, body: { srcIp: '203.0.113.9', attackType: 'Port Scan', systemId, companyId: 'foreign' } }, res);
  assert.equal(res.statusCode, 404);
});

test('direct system commands report failed delivery instead of queued success', async t => {
  t.mock.method(System, 'findOne', async () => ({ _id: systemId, name: 'Test endpoint' }));
  t.mock.method(System, 'findById', async () => ({ _id: systemId }));
  t.mock.method(service, 'queueEndpointCommand', async () => ({ confirmed: false, status: 'failed', message: 'Firewall permission denied' }));
  for (const method of ['post', 'delete']) {
    const res = response();
    await handler(systemRoutes, '/:id/isolate', method)({ user, params: { id: systemId }, body: {} }, res);
    assert.equal(res.statusCode, 502);
    assert.match(res.body.message, /permission denied/);
  }
});

test('IP-only override audit cannot implicitly reconnect the endpoint', async t => {
  let reconnects = 0;
  t.mock.method(service, 'queueEndpointCommand', async () => { reconnects++; });
  t.mock.method(engine, 'resolveAdminRecipients', async () => [user.email]);
  t.mock.method(engine, 'recordAuditEvent', async event => event);
  const res = response();
  await handler(engineRoutes, '/audit/manual', 'post')({ user, query: {}, body: { action: 'Manual Override Approved', systemId } }, res);
  assert.equal(reconnects, 0);
  assert.equal(res.statusCode, 201);
});

test('analysts cannot trigger response mutations', () => {
  const res = response();
  requireManager({ user: { role: 'analyst' } }, res, () => { throw new Error('must reject'); });
  assert.equal(res.statusCode, 403);
});

test('browser audit cannot manufacture an enforcement or email confirmation', async t => {
  t.mock.method(engine, 'resolveAdminRecipients', async () => [user.email]);
  t.mock.method(engine, 'recordAuditEvent', async event => event);
  for (const action of ['Server Restored', 'Isolation Completed', 'Email Sent']) {
    const res = response();
    await handler(engineRoutes, '/audit/manual', 'post')({ user, query: {}, body: { action } }, res);
    assert.equal(res.body.event.action, 'User Actions');
    assert.equal(res.body.event.metadata.reportedAction, action);
  }
});
