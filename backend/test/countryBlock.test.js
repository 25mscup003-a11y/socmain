const test = require('node:test');
const assert = require('node:assert/strict');
const { policyForSystem, getPolicy, enforcementStatus, parseNetworks, sanitizeReport } = require('../src/services/countryBlock.service');
const CountryBlockRule = require('../src/models/CountryBlockRule.model');
const Department = require('../src/models/Department.model');
const System = require('../src/models/System.model');
const router = require('../src/routes/country-block.routes');

const companyId = '111111111111111111111111';
const departmentId = '222222222222222222222222';
const systemId = '333333333333333333333333';
const otherId = '444444444444444444444444';
const user = { id: '555555555555555555555555', companyId, departmentId, role: 'company_admin' };
const system = { _id: systemId, companyId, departmentId, status: 'active', isActive: true, agentVersion: '0.1.10', lastSeen: new Date() };
const base = { companyId, departmentId, countryCode: 'IN', scope: 'department', direction: 'inbound', enabled: true };

test('country policies enforce tenant, department and system targeting including new systems', () => {
  const rules = [
    { ...base, _id: 'department' },
    { ...base, _id: 'system', scope: 'system', systemId, direction: 'outbound' },
    { ...base, _id: 'wrong-company', companyId: otherId },
    { ...base, _id: 'wrong-department', departmentId: otherId },
    { ...base, _id: 'wrong-system', scope: 'system', systemId: otherId },
    { ...base, _id: 'disabled', enabled: false },
  ];
  assert.deepEqual(policyForSystem(rules, system).rules.map(rule => rule.id), ['department', 'system']);
  assert.deepEqual(policyForSystem(rules.slice(0, 2), { ...system, _id: 'newly-enrolled' }).rules.map(rule => rule.id), ['department']);
  assert.deepEqual(policyForSystem(rules.slice(0, 2), { ...system, departmentId: otherId }).rules.map(rule => rule.id), ['system']);
});

test('policy revision is deterministic and changes when rules are removed or direction changes', () => {
  const rules = [{ ...base, _id: 'one' }, { ...base, _id: 'two', direction: 'both' }];
  const initial = policyForSystem(rules, system);
  assert.equal(policyForSystem([...rules].reverse(), system).revision, initial.revision);
  assert.notEqual(policyForSystem(rules.slice(0, 1), system).revision, initial.revision);
  assert.notEqual(policyForSystem([{ ...rules[0], direction: 'outbound' }, rules[1]], system).revision, initial.revision);
  assert.equal(policyForSystem([], system).rules.length, 0);
});

test('applied requires a recent endpoint acknowledgement for the exact current policy', () => {
  const expected = policyForSystem([{ ...base, _id: 'one' }], system);
  assert.equal(enforcementStatus(system, expected), 'pending');
  const report = sanitizeReport({ state: 'applied', appliedRevision: expected.revision, desiredRevision: expected.revision, supported: true });
  assert.equal(enforcementStatus({ ...system, countryBlockStatus: report }, expected), 'applied');
  assert.equal(enforcementStatus({ ...system, countryBlockStatus: { ...report, appliedRevision: 'old' } }, expected), 'pending');
  assert.equal(enforcementStatus({ ...system, countryBlockStatus: { ...report, state: 'error' } }, expected), 'failed');
  assert.equal(enforcementStatus({ ...system, countryBlockStatus: report, lastSeen: new Date(0) }, expected), 'offline');
  assert.equal(enforcementStatus({ ...system, countryBlockStatus: { ...report, checkedAt: new Date(0) } }, expected), 'pending');
  assert.equal(enforcementStatus({ ...system, agentType: 'phone' }, expected), 'unsupported');
});

test('an online agent without a country report remains pending instead of offline', () => {
  const now = Date.now();
  const expected = policyForSystem([{ ...base, _id: 'one' }], system);
  const online = { ...system, lastSeen: new Date(now - 4 * 60 * 1000) };
  assert.equal(enforcementStatus(online, expected, now), 'pending');
  const report = { state: 'applied', appliedRevision: expected.revision, checkedAt: new Date(now - 4 * 60 * 1000) };
  assert.equal(enforcementStatus({ ...online, countryBlockStatus: report }, expected, now), 'pending');
  assert.equal(enforcementStatus({ ...online, countryBlockStatus: { ...report, checkedAt: 'invalid' } }, expected, now), 'pending');
});

test('unconnected new systems wait for a heartbeat while disconnected systems wait to reconnect', () => {
  const expected = policyForSystem([], system);
  assert.equal(enforcementStatus({ ...system, status: 'pending', agentVersion: undefined, lastSeen: undefined }, expected), 'pending');
  assert.equal(enforcementStatus({ ...system, status: 'disconnected' }, expected), 'offline');
});

test('country network feed rejects malformed data, wrong IP families and catch-all ranges', () => {
  assert.deepEqual(parseNetworks('8.8.8.0/24\n8.8.8.0/24\n', 4), ['8.8.8.0/24']);
  assert.deepEqual(parseNetworks('2606:4700::/32', 6), ['2606:4700::/32']);
  for (const value of ['', '<html>error</html>', '8.8.8.0/99', '0.0.0.0/0', '8.8.8.0/24;drop', '8.8.8.0/24/1', '::/0']) {
    assert.throws(() => parseNetworks(value, 4));
  }
  assert.throws(() => parseNetworks('8.8.8.0/24', 6));
});

test('rule validation rejects invalid country, direction, target and forged department ownership', async t => {
  const { validateRule } = router._test;
  for (const invalid of [{ countryCode: 'ZZ' }, { direction: 'incoming' }, { scope: 'global' }, { enabled: 'false' }, { departmentId: { $ne: null } }]) {
    await assert.rejects(validateRule({ ...base, ...invalid }, { companyId }), error => error.status === 400);
  }
  let filter;
  t.mock.method(Department, 'findOne', query => { filter = query; return { lean: async () => null }; });
  await assert.rejects(validateRule(base, { companyId, departmentId: otherId }), error => error.status === 403);
  assert.equal(filter.companyId, companyId);
  assert.deepEqual(filter.$and, [{ _id: otherId }]);
  t.mock.method(System, 'findOne', query => { filter = query; return { lean: async () => null }; });
  await assert.rejects(validateRule({ ...base, scope: 'system', systemId: otherId }, { companyId, departmentId }), error => error.status === 403);
  assert.equal(filter.companyId, companyId);
  assert.equal(filter.departmentId, departmentId);
});

async function invoke(method, path, req) {
  const route = router.stack.find(layer => layer.route?.path === path && layer.route.methods[method]).route;
  const res = { code: 200, status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
  for (const layer of route.stack) {
    let proceed = false;
    await layer.handle(req, res, () => { proceed = true; });
    if (!proceed) break;
  }
  return res;
}

test('create API uses authenticated company and rejects analyst writes', async t => {
  t.mock.method(Department, 'findOne', () => ({ lean: async () => ({ _id: departmentId }) }));
  let saved;
  t.mock.method(CountryBlockRule, 'create', async values => { saved = values; return values; });
  const response = await invoke('post', '/country-blocks', { user, body: { ...base, companyId: otherId }, params: {} });
  assert.equal(response.code, 201);
  assert.equal(saved.companyId, companyId);
  assert.equal(saved.createdBy, user.id);
  const denied = await invoke('post', '/country-blocks', { user: { ...user, role: 'analyst' }, body: base });
  assert.equal(denied.code, 403);
});

test('department admins fail closed without a department; delete stays scoped to their company and department', async t => {
  await assert.rejects(router._test.authorizedScope({ ...user, role: 'department_admin', departmentId: undefined }), error => error.status === 403);
  let filter;
  t.mock.method(System, 'find', () => ({ distinct: async () => [systemId] }));
  t.mock.method(CountryBlockRule, 'findOneAndDelete', async query => { filter = query; return null; });
  const response = await invoke('delete', '/country-blocks/:id', { user: { ...user, role: 'department_admin' }, params: { id: otherId } });
  assert.equal(response.code, 404);
  assert.equal(filter.companyId, companyId);
  assert.deepEqual(filter.$or, [{ scope: 'department', departmentId }, { scope: 'system', systemId: { $in: [systemId] } }]);
});

test('company rules cover existing and future departments and systems without crossing tenants', () => {
  const companyRule = { ...base, _id: 'company', scope: 'company', departmentId: null, systemId: null };
  const rules = [companyRule, { ...base, _id: 'department' }, { ...companyRule, _id: 'other-company', companyId: otherId }];
  assert.deepEqual(policyForSystem(rules, system).rules.map(rule => rule.id), ['company', 'department']);
  assert.deepEqual(policyForSystem(rules, { ...system, _id: 'future-system', departmentId: 'future-department' }).rules.map(rule => rule.id), ['company']);
  assert.deepEqual(policyForSystem([companyRule], { ...system, companyId: otherId }).rules, []);
  assert.deepEqual(policyForSystem([{ ...companyRule, enabled: false }, rules[1]], system).rules.map(rule => rule.id), ['department']);
});

test('agent policy query includes company rules within the authenticated system company', async t => {
  let filter;
  const rule = { ...base, _id: 'company', scope: 'company', departmentId: null, systemId: null };
  t.mock.method(CountryBlockRule, 'find', query => { filter = query; return { lean: async () => [rule] }; });
  const policy = await getPolicy(system);
  assert.equal(filter.companyId, companyId);
  assert.ok(filter.$or.some(condition => condition.scope === 'company'));
  assert.deepEqual(policy.rules.map(item => item.id), ['company']);
});

test('company rules save without a department and normalize away narrower targets', async t => {
  let saved;
  t.mock.method(CountryBlockRule, 'create', async values => { saved = values; return values; });
  const response = await invoke('post', '/country-blocks', { user, body: { ...base, scope: 'company', companyId: otherId, systemId } });
  assert.equal(response.code, 201);
  assert.equal(saved.companyId, companyId);
  assert.equal(saved.departmentId, null);
  assert.equal(saved.systemId, null);
  assert.equal(new CountryBlockRule(saved).validateSync(), undefined);
  assert.ok(new CountryBlockRule({ ...saved, scope: 'department' }).validateSync()?.errors.departmentId);
});

test('department-scoped managers cannot create or broaden a rule to company level', async () => {
  const companyRule = { ...base, scope: 'company', departmentId: null };
  await assert.rejects(router._test.validateRule(companyRule, { companyId, departmentId }), error => error.status === 403);
  await assert.rejects(router._test.validateRule(companyRule, { companyId, departmentId: { $in: [departmentId] } }), error => error.status === 403);
  const response = await invoke('post', '/country-blocks', { user: { ...user, role: 'department_admin' }, body: companyRule });
  assert.equal(response.code, 403);
});

test('inherited company rules are included in department reads but excluded from writes', async t => {
  t.mock.method(System, 'find', () => ({ distinct: async () => [systemId] }));
  const query = { companyId, departmentId };
  const readFilter = await router._test.ruleScope(query, { includeCompany: true });
  const writeFilter = await router._test.ruleScope(query);
  assert.equal(readFilter.companyId, companyId);
  assert.ok(readFilter.$or.some(condition => condition.scope === 'company'));
  assert.equal(writeFilter.$or.some(condition => condition.scope === 'company'), false);
});

test('department view uses inherited company policy for acknowledgement and exposes it read only', async t => {
  const rule = { ...base, _id: 'company', scope: 'company', departmentId: null, systemId: null };
  const expected = policyForSystem([rule], system);
  const reportedSystem = { ...system, countryBlockStatus: sanitizeReport({ state: 'applied', desiredRevision: expected.revision, appliedRevision: expected.revision }) };
  t.mock.method(System, 'find', () => ({ distinct: async () => [systemId], select: fields => {
    assert.ok(fields.split(' ').includes('agentVersion'));
    assert.ok(fields.split(' ').includes('isActive'));
    return { lean: async () => [reportedSystem] };
  } }));
  t.mock.method(Department, 'find', () => ({ select: () => ({ sort: () => ({ lean: async () => [{ _id: departmentId, name: 'Engineering' }] }) }) }));
  t.mock.method(CountryBlockRule, 'find', () => ({ sort: () => ({ lean: async () => [rule] }) }));
  const response = await invoke('get', '/country-blocks', { user: { ...user, role: 'department_admin' } });
  assert.equal(response.code, 200);
  assert.equal(response.body.canManageCompany, false);
  assert.equal(response.body.rules[0].canEdit, false);
  assert.equal(response.body.rules[0].enforcement.applied, 1);
  assert.equal(response.body.systems[0].syncState, 'applied');
  assert.equal(response.body.systems[0].connectionState, 'online');
  assert.equal(response.body.systems[0].isOnline, true);
});
