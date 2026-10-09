// Node's test runner isolates this file, including configuration loaded on import.
process.env.IPS_ISOLATE_AFTER_SUCCESSFUL_BLOCK = 'true';
const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../src/services/ipsEngine.service');
const guard = require('../src/services/ipsIsolationGuard.service');
const service = require('../src/services/ips.service');
const System = require('../src/models/System.model');
const User = require('../src/models/User.model');
const Audit = require('../src/models/IpsAuditEvent.model');

test('five-minute escalation uses the same guard and can retry after a fresh detection', async t => {
  let timer;
  const originalTimeout = global.setTimeout;
  t.mock.method(global, 'setTimeout', (callback, delay, ...args) => {
    if (delay === engine.AUTO_ISOLATE_DELAY_MS) { timer = callback; return {}; }
    return originalTimeout(callback, delay, ...args);
  });
  t.mock.method(global, 'setInterval', () => ({}));
  t.mock.method(System, 'findOne', () => ({ select: () => ({ lean: async () => null }) }));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(Audit, 'updateOne', async () => ({}));
  t.mock.method(service, 'isWhitelistedForCompany', async () => false);
  t.mock.method(service, 'blockIP', async () => ({ agentConfirmed: true }));
  let fresh = false, queued = 0;
  t.mock.method(guard, 'checkAutoIsolation', async params => {
    assert.equal(params.requireUnconfirmedBlock, false);
    return fresh ? { allowed: true, autoIsolation: { threatAlertId: 'new-threat' } }
      : { allowed: false, reason: 'No fresh activity after the original alert' };
  });
  t.mock.method(service, 'queueEndpointCommand', async () => {
    queued++; return { queued: 1, status: 'pending', commandId: 'auto' };
  });
  const detection = { companyId: 'timer-company', systemId: 'timer-endpoint', srcIp: '203.0.113.10', attackType: 'Port Scan', severity: 'high' };
  const inc = await engine.handleDetection(detection);
  assert.equal(inc.phase, 'alerting');
  assert.equal(typeof timer, 'function');
  await timer();
  assert.equal(inc.phase, 'isolation_deferred');
  assert.equal(queued, 0);
  fresh = true;
  await engine.handleDetection(detection);
  assert.equal(inc.phase, 'isolation_pending');
  assert.equal(queued, 1);
});
