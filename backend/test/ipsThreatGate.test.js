const test = require('node:test');
const assert = require('node:assert/strict');
// Tests never download public feeds or contact reputation providers.
process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED = 'false';
process.env.IPS_AUTO_BLOCK = 'true';
const intel = require('../src/services/threat-intel.service');
const gate = require('../src/services/ipsThreatGate.service');
const ipinfo = require('../src/services/ipinfo.service');
const enrichment = require('../src/services/ipEnrichmentService');
const vt = require('../src/services/virustotal.service');
const service = require('../src/services/ips.service');
const isolation = require('../src/services/ipsIsolationGuard.service');
const Audit = require('../src/models/IpsAuditEvent.model');
const Alert = require('../src/models/Alert.model');
const System = require('../src/models/System.model');
const Firewall = require('../src/models/Firewall.model');
const Whitelist = require('../src/models/IpsWhitelist.model');
const AutomatedResponse = require('../src/models/AutomatedResponse.model');
const responseService = require('../src/services/automatedResponse.service');

const scope = { ip: '45.77.1.23', companyId: 'company', systemId: 'endpoint' };
function fixture(t) {
  const now = Date.now();
  const state = {
    info: { countrySource: 'ipinfo', countryCheckedAt: new Date(now - 1000).toISOString(), countryCode: 'IN', organization: 'Example' },
    abuse: { checkedAt: new Date(now - 1000).toISOString(), abuseScore: 90 },
    otx: { checkedAt: new Date(now - 1000).toISOString(), pulseCount: 2 },
    virus: { scannedAt: new Date(now - 1000), verdict: 'clean', score: 0, detections: 0 },
    feeds: ['feodo', 'emergingThreats', 'tor'].map(provider => ({ provider, status: 'checked', checkedAt: new Date(now - 1000).toISOString(),
      expiresAt: new Date(now + 600000).toISOString(), matched: false })),
    calls: [], audits: [],
  };
  t.mock.method(ipinfo, 'lookupIpInfo', async (ip, options) => {
    assert.equal(ip, scope.ip); assert.equal(options.maxCacheAgeMs, 600000); state.calls.push('ipinfo'); return state.info;
  });
  t.mock.method(intel, 'queryAbuseIPDB', async () => { state.calls.push('abuseipdb'); return state.abuse; });
  t.mock.method(intel, 'queryOTX_IP', async () => { state.calls.push('otx'); return state.otx; });
  t.mock.method(vt, 'scanIp', async (ip, options) => {
    assert.equal(options.maxCacheAgeMs, 600000); state.calls.push('virustotal'); return state.virus;
  });
  t.mock.method(intel, 'publicFeedVerification', () => state.feeds);
  t.mock.method(intel, 'verifyPublicFeeds', () => { throw new Error('must not wait for optional feed downloads'); });
  t.mock.method(enrichment, 'isWhitelisted', () => false);
  t.mock.method(Audit, 'updateOne', async (query, update) => { state.audits.push(update.$setOnInsert); return {}; });
  t.mock.method(Alert, 'updateOne', async () => ({}));
  return state;
}

test('two distinct threat providers approve both block and isolation', async t => {
  const state = fixture(t);
  for (const action of ['block_ip', 'isolate']) {
    state.calls = [];
    const result = await gate.verifyAutomaticNetworkAction({ ...scope, action });
    assert.equal(result.allowed, true);
    assert.deepEqual(state.calls.sort(), ['ipinfo', 'abuseipdb', 'otx', 'virustotal'].sort());
    assert.deepEqual(result.checks.map(check => check.provider), [...gate.PROVIDERS]);
    assert.ok(result.checks.every(check => check.status === 'checked'));
    assert.equal(result.verification.action, action);
    assert.equal(result.verification.version, 2);
    assert.equal(result.verification.policy, 'two-of-four');
    assert.deepEqual(result.verification.matchedProviders, ['abuseipdb', 'otx']);
    assert.ok(Date.parse(result.verification.expiresAt) - Date.parse(result.verification.checkedAt) <= 60000);
  }
  assert.equal(state.audits.length, 2);
});

test('any two reputation providers suffice despite other providers being unavailable', async t => {
  const state = fixture(t);
  state.info = null;
  state.virus = { ...state.virus, verdict: 'malicious', detections: 4, score: 80 };
  for (const key of ['abuse', 'otx', 'virus']) {
    const original = state[key]; state[key] = null;
    for (const action of ['block_ip', 'isolate']) {
      const result = await gate.verifyAutomaticNetworkAction({ ...scope, action });
      assert.equal(result.allowed, true, key);
      assert.equal(result.matchedProviders.length, 2);
      assert.equal(result.checks.filter(check => check.status === 'unavailable').length, 2);
      assert.equal(gate.commandVerificationError({ command: action, ip: scope.ip, automatic: true,
        threatVerification: result.verification }, scope.companyId), null);
    }
    state[key] = original;
  }
});

test('unavailable public feeds cannot veto two API matches', async t => {
  const state = fixture(t);
  for (const feed of state.feeds) {
    for (const status of ['unavailable', 'stale', 'disabled']) {
      feed.status = status;
      const result = await gate.verifyAutomaticNetworkAction(scope);
      assert.equal(result.allowed, true);
    }
    feed.status = 'checked';
  }
});

test('stale, future, skipped and failed API results cannot contribute threat votes', async t => {
  const state = fixture(t);
  const original = state.abuse.checkedAt;
  state.abuse.checkedAt = new Date(Date.now() - 601000).toISOString();
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
  state.abuse.checkedAt = new Date(Date.now() + 60000).toISOString();
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
  state.abuse.checkedAt = original;
  state.otx.skipped = true;
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
  state.otx.skipped = false;
  intel.queryOTX_IP.mock.mockImplementation(async () => { throw new Error('timeout'); });
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
  state.virus.verdict = 'malicious';
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, true);
});

test('zero or one API match cannot be supplemented by public feeds or IPinfo geography/privacy', async t => {
  const state = fixture(t);
  state.abuse.abuseScore = 0;
  state.otx.pulseCount = 0;
  let result = await gate.verifyAutomaticNetworkAction(scope);
  assert.equal(result.allowed, false);
  assert.deepEqual(result.matchedProviders, []);
  state.virus.verdict = 'not_found';
  state.feeds.forEach(feed => { feed.matched = true; });
  state.info.privacy = { vpn: true, proxy: true, tor: true, hosting: true };
  state.abuse.abuseScore = 90;
  result = await gate.verifyAutomaticNetworkAction(scope);
  assert.equal(result.allowed, false);
  assert.deepEqual(result.matchedProviders, ['abuseipdb']);
  assert.equal(result.checks.find(check => check.provider === 'ipinfo').matched, false);
  state.info.countrySource = 'ip-api';
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
});

test('many VirusTotal detections count as one provider; thresholds require a second source', async t => {
  const state = fixture(t);
  state.abuse.abuseScore = 74;
  state.otx.pulseCount = 0;
  state.virus = { ...state.virus, verdict: 'malicious', detections: 20, score: 90 };
  const result = await gate.verifyAutomaticNetworkAction(scope);
  assert.equal(result.allowed, false);
  assert.deepEqual(result.matchedProviders, ['virustotal']);
  state.abuse.abuseScore = 75;
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, true);
});

test('nonmatching nearly stale evidence does not shorten a valid quorum proof', async t => {
  const state = fixture(t);
  state.virus.scannedAt = new Date(Date.now() - 599500);
  const result = await gate.verifyAutomaticNetworkAction(scope);
  assert.equal(result.allowed, true);
  assert.ok(Date.parse(result.verification.expiresAt) - Date.now() > 50000);
});

test('trusted organizations and audit failures cannot authorize automatic actions', async t => {
  fixture(t);
  enrichment.isWhitelisted.mock.mockImplementation(() => true);
  assert.equal((await gate.verifyAutomaticNetworkAction(scope)).allowed, false);
  enrichment.isWhitelisted.mock.mockImplementation(() => false);
  Audit.updateOne.mock.mockImplementation(async () => { throw new Error('DB unavailable'); });
  const result = await gate.verifyAutomaticNetworkAction(scope);
  assert.equal(result.allowed, false);
  assert.equal(result.verification, undefined);
});

test('concurrent decisions wait for every provider and share in-flight lookups', async t => {
  const state = fixture(t);
  let finish;
  vt.scanIp.mock.mockImplementation(() => new Promise(resolve => { finish = resolve; }));
  const first = gate.verifyAutomaticNetworkAction(scope);
  const second = gate.verifyAutomaticNetworkAction({ ...scope, action: 'isolate' });
  await Promise.resolve();
  assert.equal(state.audits.length, 0);
  finish(state.virus);
  const results = await Promise.all([first, second]);
  assert.ok(results.every(result => result.allowed));
  assert.equal(vt.scanIp.mock.callCount(), 1);
  assert.equal(state.audits.length, 2);
});

test('shared block service and generic alert path cannot write or dispatch before verification', async t => {
  fixture(t);
  t.mock.method(Firewall, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(Whitelist, 'find', () => ({ select: () => ({ lean: async () => [] }) }));
  t.mock.method(gate, 'verifyAutomaticNetworkAction', async () => ({ allowed: false, reason: 'OTX unavailable' }));
  t.mock.method(service.BlockedIP, 'findOneAndUpdate', () => { throw new Error('must not write block'); });
  t.mock.method(System, 'updateOne', () => { throw new Error('must not queue command'); });
  const direct = await service.blockIP(scope);
  assert.equal(direct.tiDeferred, true);
  // IPS_AUTO_BLOCK is read at import. Verify the shared service for both automatic caller types.
  const soar = await service.blockIP({ ...scope, blockedBy: 'soar' });
  assert.equal(soar.tiDeferred, true);
  const generic = await service.autoBlockFromAlert({ srcip: scope.ip, severity: 'high', eventCategory: 'network', systemId: scope.systemId }, scope.companyId);
  assert.equal(generic.tiDeferred, true);
});

test('SOAR automatic block and isolate fail without sending a command when quorum is missing', async t => {
  fixture(t);
  t.mock.method(Alert, 'findOne', () => ({ select: () => ({ lean: async () => ({ srcip: scope.ip }) }) }));
  t.mock.method(gate, 'verifyAutomaticNetworkAction', async () => ({ allowed: false, reason: 'Only 1/4 providers matched' }));
  t.mock.method(System, 'updateOne', () => { throw new Error('must not dispatch'); });
  for (const actionType of ['block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint']) {
    const response = { ...scope, _id: 'response', actionType, actionParams: { ip: scope.ip }, trigger: 'playbook',
      alertId: 'alert', auditTrail: [], save: async () => {} };
    await responseService.dispatchResponse(response, { _id: scope.systemId, isActive: true, responseEnabled: true }, null);
    assert.equal(response.status, 'failed');
    assert.match(response.errorDetail, /1\/4/);
  }
});

test('delayed delivery cancels invalid automatic proofs and preserves manual commands', async t => {
  fixture(t);
  const result = await gate.verifyAutomaticNetworkAction(scope);
  const command = { id: 'auto', command: 'block_ip', ip: scope.ip, automatic: true, threatVerification: result.verification };
  const manual = { id: 'manual', command: 'block_ip', ip: scope.ip, automatic: false };
  const cancelled = [];
  t.mock.method(service, 'recordAgentCommandResult', async input => { cancelled.push(input); });
  command.threatVerification = { ...result.verification, expiresAt: new Date(0).toISOString() };
  const output = await gate.filterNetworkCommands({ ...scope, commands: [command, manual] });
  assert.deepEqual(output, [manual]);
  assert.equal(cancelled[0].ok, false);
  command.threatVerification = { ...result.verification, companyId: 'foreign' };
  assert.ok(gate.commandVerificationError(command, scope.companyId));
});

test('fresh endpoint evidence still cannot isolate without two provider matches', async t => {
  fixture(t);
  const now = Date.now();
  t.mock.method(System, 'findOne', () => ({ select: () => ({ lean: async () => ({ isActive: true, agentVersion: '1', lastSeen: new Date(now), pendingCommands: [] }) }) }));
  t.mock.method(Alert, 'findOne', () => ({ sort: () => ({ select: () => ({ lean: async () => ({ _id: 'new-alert', createdAt: new Date(now - 1000) }) }) }) }));
  t.mock.method(service, 'isWhitelistedForCompany', async () => false);
  t.mock.method(gate, 'verifyAutomaticNetworkAction', async () => ({ allowed: false, reason: 'Only 1/4 providers matched' }));
  const result = await isolation.checkAutoIsolation({ ...scope, srcIp: scope.ip, startedAt: now - 60000 });
  assert.equal(result.allowed, false);
  assert.match(result.reason, /1\/4/);
});

test('old, duplicate, unknown and insufficient provider proofs cannot authorize delivery', async t => {
  fixture(t);
  const { verification } = await gate.verifyAutomaticNetworkAction(scope);
  const command = { command: 'block_ip', automatic: true, ip: scope.ip };
  for (const patch of [
    { version: 1 }, { policy: 'all-seven' }, { matchedProviders: [] },
    { matchedProviders: ['abuseipdb'] }, { matchedProviders: ['abuseipdb', 'abuseipdb'] },
    { matchedProviders: ['abuseipdb', 'feodo'] }, { matchedProviders: 'abuseipdb,otx' },
    { action: 'isolate' }, { ip: '45.77.1.24' },
  ]) {
    assert.ok(gate.commandVerificationError({ ...command, threatVerification: { ...verification, ...patch } }, scope.companyId));
  }
});

test('legacy SOAR queue requires a manual origin or current quorum proof', async t => {
  fixture(t);
  const cancelled = [];
  t.mock.method(AutomatedResponse, 'findOne', query => {
    assert.equal(query.companyId, scope.companyId);
    assert.equal(query.systemId, scope.systemId);
    return { select: () => ({ lean: async () => query._id === 'missing' ? null : { trigger: query._id } }) };
  });
  t.mock.method(responseService, 'recordAgentResult', async value => { cancelled.push(value); });
  t.mock.method(System, 'updateOne', async () => ({}));
  const commands = ['automatic', 'playbook', 'missing', 'manual'].map(responseId => ({
    command: 'block_ip', commandId: responseId, responseId, ip: scope.ip,
  }));
  const output = await gate.filterNetworkCommands({ ...scope, commands });
  assert.deepEqual(output, [commands[3]]);
  assert.equal(cancelled.length, 3);
});
