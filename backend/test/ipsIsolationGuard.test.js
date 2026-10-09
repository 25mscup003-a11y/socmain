const test = require('node:test');
const assert = require('node:assert/strict');
const sift = require('sift').default;
const guard = require('../src/services/ipsIsolationGuard.service');
const service = require('../src/services/ips.service');
const engine = require('../src/services/ipsEngine.service');
const System = require('../src/models/System.model');
const Alert = require('../src/models/Alert.model');
const Audit = require('../src/models/IpsAuditEvent.model');
const User = require('../src/models/User.model');
const threatGate = require('../src/services/ipsThreatGate.service');

const now = Date.parse('2026-10-09T10:00:00Z');
const scope = { companyId: 'company', systemId: 'endpoint', srcIp: '203.0.113.10', startedAt: now - 60000 };
const event = { _id: 'threat', companyId: scope.companyId, systemId: scope.systemId, srcip: scope.srcIp,
  severity: 'high', status: 'open', createdAt: new Date(now - 1000), receivedAt: new Date(now - 1000),
  eventTimestamp: new Date(now - 2000), sourceType: 'IDS', type: 'PORT_SCAN', dataOrigin: 'agent' };

function fixture(t) {
  t.mock.method(Date, 'now', () => now);
  t.mock.method(threatGate, 'verifyAutomaticNetworkAction', async ({ ip, companyId, action }) => ({ allowed: true,
    expiresAt: new Date(now + 60000).toISOString(), verification: { version: 2, policy: 'two-of-four', matchedProviders: ['abuseipdb', 'otx'], ip, companyId, action,
      checkedAt: new Date(now).toISOString(), expiresAt: new Date(now + 60000).toISOString(), providers: [...threatGate.PROVIDERS] } }));
  const state = { system: { _id: scope.systemId, companyId: scope.companyId, isActive: true,
    agentVersion: '1', lastSeen: new Date(now - 1000), blockedIps: [], pendingCommands: [] }, alerts: [event] };
  t.mock.method(System, 'findOne', query => {
    const value = state.system && sift(query)(state.system) ? state.system : null;
    return { then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
      select: () => ({ lean: async () => value }) };
  });
  t.mock.method(Alert, 'findOne', query => ({ sort: () => ({ select: () => ({
    lean: async () => state.alerts.filter(sift(query)).sort((a, b) => b.createdAt - a.createdAt)[0] || null,
  }) }) }));
  t.mock.method(service, 'isWhitelistedForCompany', async (ip, company, options) => {
    assert.equal(ip, scope.srcIp); assert.equal(company, scope.companyId);
    if (options) assert.equal(options.requireRemote, true);
    return false;
  });
  return state;
}

test('new active evidence with exact company, endpoint and IP produces a short-lived proof', async t => {
  fixture(t);
  const result = await guard.checkAutoIsolation(scope);
  assert.equal(result.allowed, true);
  assert.equal(result.autoIsolation.threatAlertId, 'threat');
  assert.equal(Date.parse(result.autoIsolation.expiresAt), now + 30000);
});

test('initial, stale, unrelated, resolved, synthetic and already prevented events never justify isolation', async t => {
  const state = fixture(t);
  for (const patch of [
    { companyId: 'foreign' }, { systemId: 'other-endpoint' }, { srcip: '203.0.113.11' },
    { createdAt: new Date(scope.startedAt) }, { eventTimestamp: new Date(scope.startedAt - 1) },
    { receivedAt: new Date(scope.startedAt - 1) }, { eventTimestamp: new Date(now + 1000) },
    { createdAt: new Date(now - 121000) }, { severity: 'medium' },
    ...['resolved', 'false_positive', 'under_observation'].map(status => ({ status })),
    { underObservation: true }, { isSynthetic: true }, { dataOrigin: 'synthetic' }, { dataOrigin: 'manual' },
    { blocked: true }, { quarantined: true }, { action: 'dropped' }, { actionTaken: 'Blocked' },
    { containmentStatus: 'isolated' }, { sourceType: 'IPS' }, { event_category: 'ips_action' },
    { type: 'IPS_BLOCK_FAILED' },
  ]) {
    state.alerts = [{ ...event, ...patch }];
    assert.equal((await guard.checkAutoIsolation(scope)).allowed, false, JSON.stringify(patch));
  }
  // Legacy records lacking a device timestamp can use a new server creation time.
  state.alerts = [{ ...event, eventTimestamp: null }];
  assert.equal((await guard.checkAutoIsolation(scope)).allowed, true);
});

test('offline, disabled, missing, recovering or already blocked endpoints defer isolation', async t => {
  const state = fixture(t);
  const original = state.system;
  for (const patch of [
    { lastSeen: null }, { lastSeen: new Date(now - 120000) }, { lastSeen: new Date(now + 1000) },
    { isActive: false }, { companyId: 'foreign' }, { agentVersion: '' },
    { ipsEnabled: false }, { responseEnabled: false }, { isIsolated: true },
    { isolationStatus: 'reconnecting' }, { pendingCommands: [{ command: 'reconnect' }] },
    { lastIpsCommand: { command: 'reconnect', completedAt: new Date(now - 1000) } },
    { blockedIps: [scope.srcIp] },
  ]) {
    state.system = { ...original, ...patch };
    assert.equal((await guard.checkAutoIsolation(scope)).allowed, false, JSON.stringify(patch));
  }
  state.system = { ...original, blockedIps: [scope.srcIp] };
  assert.equal((await guard.checkAutoIsolation({ ...scope, requireUnconfirmedBlock: false })).allowed, true);
  state.system = null;
  assert.equal((await guard.checkAutoIsolation(scope)).allowed, false);
});

test('new allow rule and any verification failure prevent automatic isolation', async t => {
  fixture(t);
  service.isWhitelistedForCompany.mock.mockImplementation(async () => true);
  assert.match((await guard.checkAutoIsolation(scope)).reason, /allow rule/);
  service.isWhitelistedForCompany.mock.mockImplementation(async () => { throw new Error('whitelist unavailable'); });
  assert.match((await guard.checkAutoIsolation(scope)).reason, /verification unavailable/);
  service.isWhitelistedForCompany.mock.mockImplementation(async () => false);
  Alert.findOne.mock.mockImplementation(() => { throw new Error('database unavailable'); });
  assert.equal((await guard.checkAutoIsolation(scope)).allowed, false);
});

test('proof expires no later than heartbeat and threat freshness', async t => {
  const state = fixture(t);
  state.system.lastSeen = new Date(now - 115000);
  const result = await guard.checkAutoIsolation(scope);
  assert.equal(Date.parse(result.autoIsolation.expiresAt), now + 5000);
});

test('delivery rechecks the original evidence and discards expired or legacy auto commands only', async t => {
  const state = fixture(t);
  const result = await guard.checkAutoIsolation(scope);
  const fresh = { id: 'fresh', command: 'isolate', srcIp: scope.srcIp, autoIsolation: result.autoIsolation,
    threatVerification: result.threatVerification };
  state.system.pendingCommands = [fresh];
  const cancelled = [];
  t.mock.method(service, 'recordAgentCommandResult', async value => { cancelled.push(value); });
  const deliver = commands => guard.filterDeliverableCommands({ ...scope, commands });
  const manual = { id: 'manual', command: 'isolate', reason: 'Manual IPS isolation' };
  const reconnect = { id: 'recover', command: 'reconnect' };
  assert.deepEqual(await deliver([fresh, manual, reconnect]), [fresh, manual, reconnect]);
  assert.equal(cancelled.length, 0);
  const expired = { ...fresh, id: 'expired', autoIsolation: { ...fresh.autoIsolation,
    verifiedAt: new Date(now - 31000), expiresAt: new Date(now - 1000) } };
  const legacy = { id: 'legacy', command: 'isolate', reason: 'Automatic IPS isolation: Port Scan' };
  assert.deepEqual(await deliver([expired, legacy, manual]), [manual]);
  assert.deepEqual(cancelled.map(row => row.commandId), ['expired', 'legacy']);
  state.alerts = [{ ...event, status: 'resolved' }, { ...event, _id: 'different-alert' }];
  assert.deepEqual(await deliver([fresh]), []);
  assert.equal(cancelled.at(-1).ok, false);
  assert.match(cancelled.at(-1).message, /^Automatic isolation deferred:/);
});

test('queue cannot supersede manual recovery even after the earlier isolation check passed', async t => {
  const state = fixture(t);
  const proof = (await guard.checkAutoIsolation(scope)).autoIsolation;
  state.system.pendingCommands = [{ id: 'manual-reconnect', command: 'reconnect' }];
  t.mock.method(System, 'updateOne', () => { throw new Error('must not mutate recovery'); });
  const result = await service.queueEndpointCommand({ ...scope, command: 'isolate', autoIsolation: proof });
  assert.equal(result.status, 'deferred');
  assert.match(result.message, /recovery/);
});

test('atomic queue check catches a block ACK or manual recovery racing verification', async t => {
  const state = fixture(t);
  const proof = (await guard.checkAutoIsolation(scope)).autoIsolation;
  for (const change of [{ blockedIps: [scope.srcIp] }, { pendingCommands: [{ command: 'reconnect' }] },
    { lastIpsCommand: { id: 'manual-restore', status: 'success' } }]) {
    const update = t.mock.method(System, 'updateOne', async query => {
      const { $expr, ...stateCheck } = query;
      assert.ok($expr);
      assert.equal(sift(stateCheck)(state.system), true, 'unchanged endpoint is eligible');
      assert.equal(sift(stateCheck)({ ...state.system, ...change }), false);
      return { modifiedCount: 0 };
    });
    const result = await service.queueEndpointCommand({ ...scope, command: 'isolate', autoIsolation: proof });
    assert.equal(result.status, 'deferred');
    update.mock.restore();
  }
});

test('deferred incident is checked again on new detection and manual recovery wins async verification', async t => {
  const state = fixture(t);
  t.mock.method(Audit, 'updateOne', async () => ({}));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(service, 'blockIP', async () => ({ ok: true, agentConfirmed: true }));
  const commands = [];
  t.mock.method(service, 'queueEndpointCommand', async payload => {
    commands.push(payload); return { queued: 1, status: 'pending', commandId: payload.command };
  });
  const detection = { ...scope, attackType: 'Port Scan', severity: 'high' };
  const inc = await engine.handleDetection(detection);
  inc.startedAt = scope.startedAt; inc.phase = 'alerting'; inc.blockStatus = 'failed';
  state.alerts = [];
  await engine._test.autoIsolate(inc.incidentId);
  assert.equal(inc.phase, 'isolation_deferred');
  assert.equal(commands.length, 0);
  state.alerts = [event];
  await engine.handleDetection(detection);
  assert.equal(inc.phase, 'isolation_pending');
  assert.equal(commands[0].autoIsolation.threatAlertId, 'threat');

  inc.phase = 'alerting';
  let finishCheck;
  t.mock.method(guard, 'checkAutoIsolation', () => new Promise(resolve => { finishCheck = resolve; }));
  const checking = engine._test.autoIsolate(inc.incidentId);
  await engine.manualRecover(detection);
  finishCheck({ allowed: true, autoIsolation: commands[0].autoIsolation });
  await checking;
  assert.equal(inc.phase, 'recovery_pending');
  assert.deepEqual(commands.map(row => row.command), ['isolate', 'reconnect']);
  await engine.handleAgentCommandResult({ ...scope, command: 'reconnect', commandId: 'reconnect', ok: true });
});

test('late block ACK is scoped to its IP and prevents unnecessary isolation', async t => {
  fixture(t);
  t.mock.method(Audit, 'updateOne', async () => ({}));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(service, 'blockIP', async () => ({ agentConfirmed: true }));
  t.mock.method(service, 'queueEndpointCommand', () => { throw new Error('must not isolate'); });
  const inc = await engine.handleDetection({ ...scope, attackType: 'Port Scan', severity: 'high' });
  inc.startedAt = scope.startedAt; inc.phase = 'alerting'; inc.blockStatus = 'failed';
  await engine.handleAgentCommandResult({ ...scope, command: 'block_ip', ok: true, srcIp: '203.0.113.99' });
  assert.equal(inc.agentBlockStatus, undefined);
  await engine.handleAgentCommandResult({ ...scope, command: 'block_ip', ok: true });
  await engine._test.autoIsolate(inc.incidentId);
  assert.equal(inc.phase, 'isolation_deferred');
  assert.match(inc.isolationDecision.reason, /block was confirmed/);
  inc.phase = 'blocked';
  engine.releaseBlockedIncidents({ companyId: scope.companyId, ip: scope.srcIp });
});

test('three unacknowledged blocks without a newer attack do not queue isolation', async t => {
  const state = fixture(t);
  t.mock.method(Audit, 'updateOne', async () => ({}));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  let attempts = 0;
  t.mock.method(service, 'blockIP', async () => {
    attempts++;
    if (attempts === 3) Date.now.mock.mockImplementation(() => now + 15000);
    throw new Error('Endpoint acknowledgement unavailable');
  });
  const originalTimeout = global.setTimeout;
  t.mock.method(global, 'setTimeout', (callback, delay, ...args) => originalTimeout(callback, delay === 5000 ? 0 : delay, ...args));
  t.mock.method(service, 'queueEndpointCommand', () => { throw new Error('must not isolate'); });
  state.alerts = [event]; // only the original event, before the incident began
  const inc = await engine.handleDetection({ ...scope, attackType: 'Port Scan', severity: 'high' });
  assert.equal(attempts, 3);
  assert.equal(inc.phase, 'isolation_deferred');
  assert.match(inc.isolationDecision.reason, /no new active/);
  inc.phase = 'blocked';
  engine.releaseBlockedIncidents({ companyId: scope.companyId, ip: scope.srcIp });
});

test('superseded automatic delivery cannot change a newer manual isolation to deferred', async t => {
  fixture(t);
  t.mock.method(Audit, 'updateOne', async () => ({}));
  t.mock.method(User, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(service, 'blockIP', async () => ({ agentConfirmed: true }));
  let finishAutomatic, reachedQueue;
  const startedQueue = new Promise(resolve => { reachedQueue = resolve; });
  t.mock.method(service, 'queueEndpointCommand', payload => {
    if (payload.autoIsolation) {
      reachedQueue();
      return new Promise(resolve => { finishAutomatic = resolve; });
    }
    return Promise.resolve({ queued: 1, status: 'pending', commandId: 'manual-isolate' });
  });
  const detection = { ...scope, attackType: 'Port Scan', severity: 'high' };
  const inc = await engine.handleDetection(detection);
  inc.startedAt = scope.startedAt; inc.phase = 'alerting'; inc.blockStatus = 'failed';
  const automatic = engine._test.autoIsolate(inc.incidentId);
  await startedQueue;
  await engine.manualIsolate(detection);
  finishAutomatic({ status: 'deferred', message: 'incident was superseded' });
  await automatic;
  assert.equal(inc.phase, 'isolation_pending');
  assert.equal(inc.manuallyIsolated, true);
  assert.equal(inc.isolationCommandId, 'manual-isolate');
  inc.phase = 'blocked';
  engine.releaseBlockedIncidents({ companyId: scope.companyId, ip: scope.srcIp });
});
