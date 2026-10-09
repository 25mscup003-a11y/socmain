const test = require('node:test');
const assert = require('node:assert/strict');
const engine = require('../src/services/ipsEngine.service');
const service = require('../src/services/ips.service');
const System = require('../src/models/System.model');
const User = require('../src/models/User.model');
const Audit = require('../src/models/IpsAuditEvent.model');

function fixture(t) {
  const audits = [];
  t.mock.method(service, 'isWhitelistedForCompany', async () => false);
  t.mock.method(System, 'findOne', () => ({ select: () => ({ lean: async () => null }) }));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(Audit, 'updateOne', async (query, update) => { audits.push(update.$setOnInsert); return {}; });
  return audits;
}
const detection = { companyId: 'audit-test', systemId: 'audit-system', srcIp: '203.0.113.19', attackType: 'Port Scan', severity: 'high' };

test('remote whitelist bypass never becomes isolation fallback', async t => {
  const audits = fixture(t);
  t.mock.method(service, 'blockIP', async () => ({ whitelisted: true, reason: 'whitelisted by IPS server' }));
  t.mock.method(service, 'queueEndpointCommand', () => { throw new Error('must not isolate'); });
  const incident = await engine.handleDetection(detection);
  assert.equal(incident.blockStatus, 'skipped');
  assert.equal(incident.phase, 'bypassed');
  assert.ok(audits.some(row => row.action === 'Block Bypassed'));
});

test('incomplete threat verification never starts enforcement retry or isolation fallback', async t => {
  const audits = fixture(t);
  let calls = 0;
  t.mock.method(service, 'blockIP', async () => { calls++; return { tiDeferred: true, reason: 'VirusTotal unavailable' }; });
  t.mock.method(service, 'queueEndpointCommand', () => { throw new Error('must not isolate'); });
  const incident = await engine.handleDetection(detection);
  assert.equal(calls, 1);
  assert.equal(incident.phase, 'verification_deferred');
  assert.equal(incident.blockStatus, 'skipped');
  await engine.handleDetection(detection);
  assert.equal(calls, 2, 'later detection can retry verification');
  assert.ok(audits.some(row => row.action === 'Threat Verification Deferred'));
});

test('expired successful incident does not suppress a new enforcement attempt', async t => {
  fixture(t);
  let attempts = 0;
  t.mock.method(service, 'blockIP', async () => { attempts++; return { ok: true, agentConfirmed: true, expiresAt: new Date(0) }; });
  await engine.handleDetection(detection);
  await engine.handleDetection(detection);
  assert.equal(attempts, 2);
  engine.releaseBlockedIncidents({ companyId: detection.companyId, ip: detection.srcIp });
});

test('in-flight automatic block cannot restart isolation after manual reconnect', async t => {
  const audits = fixture(t);
  let finishBlock, markStarted;
  const started = new Promise(resolve => { markStarted = resolve; });
  t.mock.method(service, 'blockIP', () => { markStarted(); return new Promise(resolve => { finishBlock = resolve; }); });
  t.mock.method(service, 'queueEndpointCommand', async () => ({ queued: 1, status: 'pending', commandId: 'reconnect' }));
  const pending = engine.handleDetection(detection);
  await started;
  const recovering = await engine.manualRecover(detection);
  assert.equal(recovering.phase, 'recovery_pending');
  finishBlock({ ok: true, agentConfirmed: true });
  await pending;
  assert.equal(recovering.phase, 'recovery_pending');
  assert.ok(!audits.some(row => row.action === 'Block Confirmed'));
});
