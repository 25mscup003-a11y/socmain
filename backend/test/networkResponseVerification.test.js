const test = require('node:test');
const assert = require('node:assert/strict');
process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED = 'false';
const decisionService = require('../src/services/networkResponseVerification.service');
const auth = require('../src/utils/agentRequestAuth');
const Company = require('../src/models/Company.model');

const companyId = '507f1f77bcf86cd799439011';
const system = { _id: '507f1f77bcf86cd799439012', companyId, isActive: true };
function response() {
  return { statusCode: 200, headers: {}, status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; }, setHeader(key, value) { this.headers[key] = value; } };
}
function handler(router, path) {
  return router.stack.find(layer => layer.route?.path === path && layer.route.methods.post).route.stack.at(-1).handle;
}

test('agent decision uses signed identity, rejects unauthenticated calls and ignores supplied tenant/system', async t => {
  let authenticated = false;
  t.mock.method(auth, 'verifySignedAgentRequest', async (req, options) => {
    assert.equal(options.agentKey, 'test-agent-key');
    return authenticated ? { ok: true, system } : { ok: false, status: 401, message: 'Unauthorized' };
  });
  const decide = t.mock.method(decisionService, 'checkNetworkResponse', async args => {
    assert.equal(args.companyId, companyId);
    assert.equal(args.system, system);
    assert.equal(args.ip, '45.77.1.23');
    return { allowed: true, matchedProviders: ['abuseipdb', 'otx'] };
  });
  const modulePath = require.resolve('../src/routes/agent.routes');
  delete require.cache[modulePath];
  t.after(() => { delete require.cache[modulePath]; });
  const route = handler(require(modulePath), '/network-response/check');
  const req = { body: { agent_key: 'test-agent-key', ip: '45.77.1.23', action: 'block_ip',
    companyId: 'foreign', systemId: 'foreign-system' } };
  let res = response();
  await route(req, res);
  assert.equal(res.statusCode, 401);
  assert.equal(decide.mock.callCount(), 0);
  authenticated = true;
  res = response();
  await route(req, res);
  assert.equal(res.body.allowed, true);
  assert.equal(res.headers['Cache-Control'], 'no-store');
});

test('standalone decision requires the shared secret and an existing scoped company', async t => {
  const oldSecret = process.env.IPS_WEBHOOK_SECRET;
  process.env.IPS_WEBHOOK_SECRET = 'test-only-secret';
  t.after(() => { if (oldSecret === undefined) delete process.env.IPS_WEBHOOK_SECRET; else process.env.IPS_WEBHOOK_SECRET = oldSecret; });
  let exists = true;
  t.mock.method(Company, 'exists', async query => { assert.equal(query._id, companyId); return exists; });
  const decide = t.mock.method(decisionService, 'checkNetworkResponse', async args => {
    assert.deepEqual(args, { companyId, ip: '45.77.1.23', action: 'block_ip' });
    return { allowed: true };
  });
  const route = handler(require('../src/routes/ips.routes'), '/verify-automatic');
  const req = { headers: { 'x-company-id': companyId }, body: { ip: '45.77.1.23', companyId: 'foreign', action: 'isolate' } };
  for (const secret of ['', 'wrong-secret']) {
    req.headers['x-webhook-secret'] = secret;
    const res = response();
    await route(req, res);
    assert.equal(res.statusCode, 401);
  }
  assert.equal(decide.mock.callCount(), 0);
  req.headers['x-webhook-secret'] = 'test-only-secret';
  exists = false;
  let res = response();
  await route(req, res);
  assert.equal(res.statusCode, 400);
  assert.equal(decide.mock.callCount(), 0);
  exists = true;
  res = response();
  await route(req, res);
  assert.equal(res.body.allowed, true);
  assert.equal(res.headers['Cache-Control'], 'no-store');
});
