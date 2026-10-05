const test = require('node:test');
const assert = require('node:assert/strict');
const { CONTROL_KEYS, securityPolicySnapshot, sanitizeControlReport, securityPolicyPosture } = require('../src/utils/agentSecurityPolicy');
const System = require('../src/models/System.model');
const Audit = require('../src/models/AgentSecurityAudit.model');
const User = require('../src/models/User.model');
const router = require('../src/routes/superadmin.routes');
const id = '111111111111111111111111';
const now = new Date();
const system = { _id: id, companyId: id, os: 'linux', name: 'test-agent', agentVersion: '0.1.12', isActive: true, status: 'active', lastSeen: now, securityControls: { policyVersion: 3 } };
const controls = Object.fromEntries(Object.keys(CONTROL_KEYS).map(key => [key, { enabled: key !== 'maintenanceMode', state: key === 'maintenanceMode' ? 'disabled' : 'monitoring', detail: 'Reported evidence' }]));
const report = { version: 2, policyVersion: 3, controls };

test('all twelve controls require fresh exact-version evidence; legacy/offline reports never claim applied', () => {
  const saved = sanitizeControlReport(report, now);
  assert.equal(Object.keys(saved.controls).length, 12);
  assert.equal(securityPolicyPosture(system, +now).policySync.state, 'pending');
  assert.equal(securityPolicyPosture({ ...system, agentSecurityPolicyStatus: saved }, +now).policySync.state, 'applied');
  assert.equal(securityPolicyPosture({ ...system, agentSecurityPolicyStatus: { ...saved, version: 2 } }, +now).policySync.state, 'pending');
  assert.equal(securityPolicyPosture({ ...system, agentSecurityPolicyStatus: saved }, +now + 181000).policySync.state, 'stale');
  assert.equal(securityPolicyPosture({ ...system, status: 'offline', agentSecurityPolicyStatus: saved }, +now).policySync.state, 'stale');
  assert.equal(securityPolicyPosture({ ...system, agentType: 'phone' }, +now).policySync.state, 'unsupported');
  saved.controls.selfProtection.enabled = false;
  assert.equal(securityPolicyPosture({ ...system, agentSecurityPolicyStatus: saved }, +now).policySync.state, 'pending');
});

test('reports reject invalid booleans/states and mandatory protections stay enabled', () => {
  assert.equal(sanitizeControlReport({ ...report, policyVersion: '3' }), null);
  const saved = sanitizeControlReport({ ...report, controls: { selfProtection: { enabled: 'true', state: 'enforced' } } });
  assert.deepEqual(saved.controls, {});
  const policy = securityPolicySnapshot({ securityControls: { secureCommunication: false, configurationEncryption: false, certificateValidation: false } });
  assert.equal(policy.secure_communication, true);
  assert.equal(policy.configuration_encryption, true);
  assert.equal(policy.certificate_validation, true);
});

function response() { return { code: 200, set() { return this; }, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } }; }
const handler = (path, method) => router.stack.find(item => item.route?.path === path && item.route.methods[method]).route.stack.at(-1).handle;
const request = body => ({ params: { systemId: id }, body, activeUser: { _id: id, email: 'test@example.test' }, headers: {}, ip: '::ffff:192.0.2.10', app: { get: () => null } });

test('controls API rejects malformed IDs, unknown fields, non-booleans and disabling mandatory safeguards', async () => {
  for (const changes of [{ selfProtection: 'false' }, { unknown: true }, [], {}, { secureCommunication: false }, { certificateValidation: false }, { configurationEncryption: false }]) {
    const res = response(); await handler('/agent-security/:systemId/controls', 'patch')(request({ changes }), res);
    assert.ok([400, 409].includes(res.code));
  }
  const res = response(); const req = request({ changes: { selfProtection: true } }); req.params.systemId = 'invalid';
  await handler('/agent-security/:systemId/controls', 'patch')(req, res); assert.equal(res.code, 400);
});

test('policy change is queued for endpoint evidence and uses version compare-and-swap without replacing commands', async t => {
  t.mock.method(System, 'findById', async () => system);
  let audit, query, update;
  t.mock.method(Audit, 'create', async value => { audit = { _id: id, ...value }; return audit; });
  t.mock.method(System, 'findOneAndUpdate', (q, u) => { query = q; update = u; return { populate() { return this; }, lean: async () => ({ ...system, securityControls: { policyVersion: 4, antiDebugging: false } }) }; });
  const res = response(); await handler('/agent-security/:systemId/controls', 'patch')(request({ changes: { antiDebugging: false } }), res);
  assert.equal(res.code, 200); assert.equal(audit.result, 'queued'); assert.equal(audit.newValue.policyVersion, 4);
  assert.equal(update.$set['securityControls.antiDebugging'], false); assert.equal(update.$set.pendingCommands, undefined);
  assert.deepEqual(query.$or, [{ 'securityControls.policyVersion': 3 }]);
  assert.equal(audit.sourceIp, '192.0.2.10'); assert.equal(res.body.agent.policySync.state, 'pending');
});

test('security actions carry durable IDs and an atomic bounded queue update', async t => {
  t.mock.method(System, 'findById', () => ({ select: async () => system }));
  t.mock.method(Audit, 'create', async value => ({ _id: id, ...value }));
  let update, query;
  t.mock.method(System, 'updateOne', async (q, value) => { query = q; update = value; return { modifiedCount: 1 }; });
  const res = response(); await handler('/agent-security/:systemId/action', 'post')(request({ action: 'forceUpdate' }), res);
  assert.equal(res.code, 202); assert.equal(update.$push.pendingCommands.id, id); assert.equal(update.$push.pendingCommands.auditId, id);
  assert.equal(update.$push.pendingCommands.force, true); assert.equal(query['pendingCommands.command'].$ne, 'update');
});

test('audit inventory clamps pages, filters and resolves endpoint names without fabricating posture', async t => {
  const chain = value => ({ select() { return this; }, populate() { return this; }, sort() { return this; }, skip(n) { this.skipped = n; return this; }, limit() { return this; }, lean: async () => value });
  t.mock.method(System, 'find', () => chain([system]));
  let filter, cursor;
  t.mock.method(Audit, 'countDocuments', async q => { filter = q; return 12; });
  t.mock.method(Audit, 'find', () => { cursor = chain([{ _id: id, systemId: { name: 'test-agent' } }]); return cursor; });
  const res = response(); await handler('/agent-security', 'get')({ query: { auditPage: '900', auditSystemId: id, auditResult: 'queued' }, ip: '::1' }, res);
  assert.equal(res.code, 200); assert.equal(res.body.auditPagination.page, 2); assert.equal(cursor.skipped, 10);
  assert.deepEqual(filter, { systemId: id, result: 'queued' }); assert.equal(res.body.audits[0].systemId.name, 'test-agent');
  assert.equal(res.body.agents[0].integrityScore, null); assert.equal(res.body.agents[0].status, 'warning');
});

test('sensitive endpoints revalidate an active superadmin session', async t => {
  t.mock.method(User, 'findOne', () => ({ select() { return this; }, lean: async () => null }));
  const guard = router.stack.find(item => item.route?.path === '/agent-security').route.stack[0].handle;
  const res = response(); let next = false;
  await guard({ user: { id } }, res, () => { next = true; });
  assert.equal(res.code, 401); assert.equal(next, false);
});

test('source clearing defaults off and requires explicit matching endpoint evidence when enabled', () => {
  assert.equal(securityPolicySnapshot(system).erase_code_on_open, false);
  const enabled = { ...system, securityControls: { ...system.securityControls, eraseCodeOnOpen: true } };
  const saved = sanitizeControlReport(report, now);
  assert.equal(securityPolicyPosture({ ...enabled, agentSecurityPolicyStatus: saved }, +now).policySync.state, 'pending');
  const withOpen = sanitizeControlReport({ ...report, controls: { ...controls,
    selfProtection: { ...controls.selfProtection, fileOpen: { enabled: true, supported: true, state: 'enforced', detail: 'Armed', protectedFiles: 74 } },
  } }, now);
  const posture = securityPolicyPosture({ ...enabled, agentSecurityPolicyStatus: withOpen }, +now);
  assert.equal(posture.policySync.state, 'applied');
  assert.equal(posture.controlStatus.selfProtection.fileOpen.state, 'enforced');
  assert.equal(posture.controlStatus.selfProtection.fileOpen.protectedFiles, 74);
  assert.equal(securityPolicyPosture({ ...enabled, agentSecurityPolicyStatus: withOpen }, +now + 181000).controlStatus.selfProtection.fileOpen.state, 'stale');
  const failed = sanitizeControlReport({ ...report, controls: { ...controls, selfProtection: { ...controls.selfProtection, fileOpen: { enabled: true, supported: false, state: 'unsupported', detail: 'No kernel support' } } }, policyError: 'No kernel support' }, now);
  assert.equal(securityPolicyPosture({ ...enabled, agentSecurityPolicyStatus: failed }, +now).policySync.state, 'failed');
});

test('source clearing cannot arm without acknowledgement and fresh supported agent evidence', async t => {
  t.mock.method(System, 'findById', async () => system);
  for (const body of [{ changes: { eraseCodeOnOpen: true } }, { changes: { eraseCodeOnOpen: true }, acknowledgeSourceClearing: true }]) {
    const res = response();
    await handler('/agent-security/:systemId/controls', 'patch')(request(body), res);
    assert.equal(res.code, 409);
  }
});

test('acknowledged source clearing is queued and audited on supported agents, never enabled by ordinary self-protection changes', async t => {
  const saved = sanitizeControlReport({ ...report, controls: { ...controls, selfProtection: { ...controls.selfProtection,
    fileOpen: { enabled: false, supported: true, state: 'disabled', detail: 'Off' },
  } } }, now);
  const supported = { ...system, agentSecurityPolicyStatus: saved };
  t.mock.method(System, 'findById', async () => supported);
  let audit, update;
  t.mock.method(Audit, 'create', async value => { audit = { _id: id, ...value }; return audit; });
  t.mock.method(System, 'findOneAndUpdate', (q, value) => { update = value; return { populate() { return this; }, lean: async () => ({ ...supported, securityControls: { policyVersion: 4, eraseCodeOnOpen: true } }) }; });
  const res = response();
  await handler('/agent-security/:systemId/controls', 'patch')(request({ changes: { eraseCodeOnOpen: true }, acknowledgeSourceClearing: true }), res);
  assert.equal(res.code, 200);
  assert.equal(update.$set['securityControls.eraseCodeOnOpen'], true);
  assert.equal(audit.result, 'queued');
  assert.equal(audit.newValue.changes.eraseCodeOnOpen, true);
  assert.equal(res.body.agent.policySync.state, 'pending');
  await handler('/agent-security/:systemId/controls', 'patch')(request({ changes: { selfProtection: true } }), response());
  assert.equal(update.$set['securityControls.eraseCodeOnOpen'], undefined);
});

test('resuming maintenance with an armed destructive policy needs acknowledgement; disarming remains available', async t => {
  t.mock.method(System, 'findById', async () => ({ ...system, securityControls: { ...system.securityControls, eraseCodeOnOpen: true, maintenanceMode: true } }));
  const res = response();
  await handler('/agent-security/:systemId/controls', 'patch')(request({ changes: { maintenanceMode: false } }), res);
  assert.equal(res.code, 409);
  t.mock.method(Audit, 'create', async value => ({ _id: id, ...value }));
  let update;
  t.mock.method(System, 'findOneAndUpdate', (q, value) => { update = value; return { populate() { return this; }, lean: async () => system }; });
  const off = response();
  await handler('/agent-security/:systemId/controls', 'patch')(request({ changes: { eraseCodeOnOpen: false } }), off);
  assert.equal(off.code, 200);
  assert.equal(update.$set['securityControls.eraseCodeOnOpen'], false);
});
