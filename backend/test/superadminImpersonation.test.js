const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const User = require('../src/models/User.model');
const Tenant = require('../src/models/Tenant.model');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const LoginActivity = require('../src/models/LoginActivity.model');
const SuperadminLoginAudit = require('../src/models/SuperadminLoginAudit.model');
const router = require('../src/routes/superadmin.routes');
const authRouter = require('../src/routes/auth.routes');
const stytchConfig = require('../src/config/stytch.config');
const { authenticate } = require('../src/middleware/auth.middleware');
const monitoringRouter = require('express').Router();
monitoringRouter.use(authenticate, require('../src/routes/superadmin-monitoring.routes'));

const ACTOR = '600000000000000000000001';
const TARGET = '600000000000000000000002';
const SCOPE = '600000000000000000000003';

function setup(t, options = {}) {
  const previous = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'impersonation-test-secret';
  t.after(() => { if (previous === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previous; });
  const actor = new User({ _id: ACTOR, name: 'Superadmin', email: 'admin@example.test', password: 'secret', role: 'superadmin' });
  const target = new User({ _id: TARGET, name: 'Target', email: 'target@example.test', password: 'secret', role: options.role || 'analyst',
    tenantId: SCOPE, partnerId: SCOPE, companyId: SCOPE, departmentId: SCOPE,
    ...options.target });
  const audits = [];
  const logins = [];
  const legacyLogins = [];
  let userHistoryWrites = 0;
  t.mock.method(User, 'findOne', filter => {
    assert.equal(filter._id, ACTOR);
    assert.equal(filter.role, 'superadmin');
    assert.equal(filter.isActive, true);
    return { select: () => ({ lean: async () => options.inactiveActor ? null : actor }) };
  });
  t.mock.method(User, 'find', filter => {
    assert.deepEqual(filter, { role: 'superadmin' });
    return { select: () => ({ lean: async () => [actor] }) };
  });
  t.mock.method(User, 'findById', id => {
    const value = String(id) === TARGET ? target : String(id) === ACTOR ? actor : null;
    const promise = Promise.resolve(value);
    promise.select = () => promise;
    return promise;
  });
  t.mock.method(SuperadminLoginAudit, 'create', async record => { audits.push(record); return record; });
  t.mock.method(SuperadminLoginAudit, 'find', () => ({ sort: () => ({ limit: () => ({ lean: async () => audits }) }) }));
  t.mock.method(LoginActivity, 'create', async () => { userHistoryWrites++; });
  t.mock.method(LoginActivity, 'find', filter => {
    if (!filter.userId) {
      assert.deepEqual(filter.action.$in, ['superadmin_impersonation_started', 'superadmin_company_impersonation_started']);
      assert.equal(filter.success, true);
      assert.equal(filter.failReason.$regex, '^by:[a-f0-9]{24}(?:;|$)');
      return { select: () => ({ populate: () => ({ sort: () => ({ limit: () => ({ lean: async () => legacyLogins }) }) }) }) };
    }
    assert.deepEqual(filter.userId.$in.map(String), [ACTOR]);
    assert.deepEqual(filter.action, { $in: ['login_success', 'logout', 'auto_logout'] });
    assert.equal(filter.success, true);
    return { select: () => ({ sort: () => ({ lean: async () => logins, limit: () => ({ lean: async () => logins }) }) }) };
  });
  t.mock.method(LoginActivity, 'exists', async () => { throw new Error('Impersonation must not resume a target login'); });
  return { actor, target, audits, logins, legacyLogins, userHistoryWrites: () => userHistoryWrites };
}

function request({ role = 'superadmin', id = TARGET, claims = {}, path, token, handler = router, method = 'POST', body = { role: 'superadmin', companyId: 'attacker-company' } } = {}) {
  const authorization = token || (role ? jwt.sign({ id: ACTOR, role, ...claims }, process.env.JWT_SECRET) : null);
  return new Promise((resolve, reject) => {
    const req = { method, url: path || `/users/${id}/impersonate`, body, query: {}, app: { get: () => null },
      headers: { ...(authorization ? { authorization: `Bearer ${authorization}` } : {}), 'x-company-id': 'attacker-company' },
      ip: '127.0.0.1', get: () => 'Unit test' };
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, set() { return this; },
      json(data) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(data)) }); } };
    handler.handle(req, res, error => reject(error || new Error('Route not found')));
  });
}

test('only active superadmins can start support logins and view their audit records', async t => {
  const state = setup(t);
  for (const role of [null, ...User.schema.path('role').enumValues.filter(role => role !== 'superadmin')]) {
    assert.equal((await request({ role })).status, role ? 403 : 401);
    assert.equal((await request({ role, method: 'GET', path: '/user-login-audits' })).status, role ? 403 : 401);
  }
  assert.equal(state.audits.length, 0);
  assert.equal((await request({ method: 'GET', path: '/user-login-audits' })).status, 200);
});

test('inactive or stale superadmin credentials are rejected', async t => {
  const { actor } = setup(t, { inactiveActor: true });
  assert.equal((await request()).status, 401);
  t.mock.method(User, 'findOne', () => ({ select: () => ({ lean: async () => actor }) }));
  actor.passwordChangedAt = new Date(Date.now() + 1000);
  assert.equal((await request()).status, 401);
});

test('invalid, missing, inactive and nested targets never produce a login audit or token', async t => {
  const { target, audits } = setup(t);
  assert.equal((await request({ id: 'invalid' })).status, 400);
  assert.equal((await request({ id: '600000000000000000000099' })).status, 404);
  assert.equal((await request({ claims: { impersonatedBy: ACTOR } })).status, 403);
  target.isActive = false;
  assert.equal((await request()).status, 403);
  target.isActive = true;
  for (const status of ['invited', 'suspended', 'disabled', 'expired']) {
    target.accountStatus = status;
    assert.equal((await request()).status, 403);
  }
  assert.equal(audits.length, 0);
});

for (const role of User.schema.path('role').enumValues) {
  test(`login as ${role} keeps target permissions and writes only a superadmin audit`, async t => {
    const state = setup(t, { role });
    const result = await request();
    assert.equal(result.status, 200);
    const claims = jwt.verify(result.body.token, process.env.JWT_SECRET);
    assert.equal(claims.id, TARGET);
    assert.equal(claims.role, role);
    for (const scope of ['tenantId', 'partnerId', 'companyId', 'departmentId']) assert.equal(claims[scope], SCOPE);
    assert.equal(claims.impersonatedBy, ACTOR);
    assert.equal(claims.impersonatedByEmail, state.actor.email);
    assert.equal(claims.impersonationMode, 'user_login');
    assert.equal(state.audits[0].sessionId, claims.sessionId);
    assert.equal(claims.exp - claims.iat, 4 * 60 * 60);
    assert.equal(result.body.user.password, undefined);
    assert.equal(state.userHistoryWrites(), 0);
    assert.equal(state.audits.length, 1);
    assert.equal(String(state.audits[0].actorId), ACTOR);
    assert.equal(String(state.audits[0].targetUserId), TARGET);
    assert.equal(JSON.stringify(state.audits).includes(result.body.token), false);
    const history = await request({ method: 'GET', path: '/user-login-audits' });
    assert.equal(history.body[0].targetEmail, state.target.email);
    assert.equal(new URL(result.body.portalUrl).port, role === 'superadmin' ? '3001' : '3000');
  });
}

test('audit persistence failure does not issue a usable login response', async t => {
  setup(t);
  t.mock.method(SuperadminLoginAudit, 'create', async () => { throw new Error('Unavailable'); });
  const result = await request();
  assert.equal(result.status, 500);
  assert.equal(result.body.token, undefined);
});

test('audit history includes superadmin sign-ins with their matching logout times', async t => {
  const { actor, logins } = setup(t);
  logins.push(
    { _id: 'login', userId: ACTOR, email: actor.email, action: 'login_success', sessionId: 'session-one', createdAt: '2026-10-05T10:00:00Z', ipAddress: '127.0.0.1' },
    { _id: 'logout', userId: ACTOR, email: actor.email, action: 'logout', sessionId: 'session-one', createdAt: '2026-10-05T11:00:00Z' },
  );
  const result = await request({ method: 'GET', path: '/user-login-audits' });
  assert.equal(result.status, 200);
  assert.equal(result.body.length, 1);
  assert.equal(result.body[0].eventType, 'superadmin_login');
  assert.equal(result.body[0].loginAt, '2026-10-05T10:00:00Z');
  assert.equal(result.body[0].logoutAt, '2026-10-05T11:00:00Z');
  assert.equal(result.body[0].actorName, actor.name);
});

test('superadmin password login, token refresh and logout retain one session identifier', async t => {
  const { actor } = setup(t);
  const fraudEnabled = stytchConfig.fraudEnabled;
  stytchConfig.fraudEnabled = false;
  t.after(() => { stytchConfig.fraudEnabled = fraudEnabled; });
  const recorded = [];
  t.mock.method(User, 'findOne', async () => actor);
  t.mock.method(actor, 'comparePassword', async () => true);
  t.mock.method(User, 'findByIdAndUpdate', () => ({ select: async () => actor }));
  t.mock.method(Tenant, 'findOne', async () => ({ _id: SCOPE }));
  t.mock.method(LoginActivity, 'exists', async () => true);
  t.mock.method(LoginActivity, 'create', async record => { recorded.push(record); return record; });

  const login = await request({ handler: authRouter, path: '/login', body: { email: actor.email, password: 'test-password' } });
  assert.equal(login.status, 200);
  const claims = jwt.verify(login.body.token, process.env.JWT_SECRET);
  assert.ok(claims.sessionId);
  assert.equal(recorded[0].action, 'login_success');
  assert.equal(recorded[0].sessionId, claims.sessionId);
  const resumed = await request({ handler: authRouter, method: 'GET', path: '/me', token: login.body.token });
  assert.equal(resumed.status, 200);
  assert.equal(jwt.verify(resumed.body.token, process.env.JWT_SECRET).sessionId, claims.sessionId);
  const logout = await request({ handler: authRouter, path: '/logout', token: resumed.body.token });
  assert.equal(logout.status, 200);
  assert.equal(recorded[1].action, 'logout');
  assert.equal(recorded[1].sessionId, claims.sessionId);
});

test('ending a Login as User session records its logout only in the superadmin audit', async t => {
  const state = setup(t);
  const changes = [];
  t.mock.method(SuperadminLoginAudit, 'updateOne', async (filter, update) => { changes.push({ filter, update }); });
  const login = await request();
  const logout = await request({ handler: authRouter, path: '/logout', token: login.body.token });
  assert.equal(logout.status, 200);
  assert.equal(changes[0].filter.sessionId, state.audits[0].sessionId);
  assert.equal(changes[0].filter.actorId, ACTOR);
  assert.equal(changes[0].filter.targetUserId, TARGET);
  assert.equal(changes[0].filter.logoutAt, null);
  assert.ok(changes[0].update.$set.logoutAt instanceof Date);
  assert.equal(state.userHistoryWrites(), 0);
});

test('/auth/me preserves actor, restrictions and expiry across repeated session refreshes without user login logs', async t => {
  const state = setup(t);
  state.target.companyId = null;
  state.target.partnerId = null;
  state.target.tenantId = null;
  t.mock.method(Tenant, 'findOne', async () => null);
  let token = jwt.sign({ id: TARGET, role: 'analyst', impersonatedBy: ACTOR,
    impersonatedByRole: 'superadmin', impersonationMode: 'user_login' }, process.env.JWT_SECRET, { expiresIn: 200 });
  const original = token;
  for (let i = 0; i < 3; i++) {
    const result = await request({ handler: authRouter, method: 'GET', path: '/me', token });
    assert.equal(result.status, 200);
    assert.equal(result.body.token, original);
    assert.equal(result.body.impersonation.by, ACTOR);
    assert.match(result.body.impersonation.banner, /Target \(analyst\)/);
    token = result.body.token;
  }
  assert.equal(state.userHistoryWrites(), 0);
  state.actor.isActive = false;
  assert.equal((await request({ handler: authRouter, method: 'GET', path: '/me', token })).status, 401);
  state.actor.isActive = true;
  state.target.passwordChangedAt = new Date(Date.now() + 1000);
  assert.equal((await request({ handler: authRouter, method: 'GET', path: '/me', token })).status, 401);
});

for (const [entry, role, mode] of [
  ['partners', 'partner_admin', 'support_debug'],
  ['companies', 'company_admin', 'company_admin_login'],
  ['soc-managers', 'soc_manager', 'soc_manager_login'],
]) {
  test(`${entry} login buttons persist a private audit and connect their logout to the same session`, async t => {
    const state = setup(t, { role });
    const actorLookup = User.findOne;
    t.mock.method(User, 'findOne', filter => filter.role === 'superadmin' ? actorLookup(filter) : Promise.resolve(state.target));
    t.mock.method(Company, 'findById', async () => ({ _id: SCOPE, name: 'Example Company', email: state.target.email, tenantId: SCOPE }));
    t.mock.method(Partner, 'findById', () => ({ populate: () => ({ populate: async () => ({ _id: SCOPE, ownerUserId: state.target, tenantId: { _id: SCOPE } }) }) }));
    const handler = entry === 'soc-managers' ? monitoringRouter : router;
    const path = `/${entry}/${entry === 'soc-managers' ? TARGET : SCOPE}/impersonate`;
    const args = { handler, path };
    assert.equal((await request({ ...args, role: null })).status, 401);
    assert.equal((await request({ ...args, role: 'company_admin' })).status, 403);
    assert.equal((await request({ ...args, claims: { impersonatedBy: ACTOR } })).status, 403);
    state.target.isActive = false;
    assert.equal((await request(args)).status, 403);
    state.target.isActive = true;
    const login = await request(args);
    assert.equal(login.status, 200);
    const claims = jwt.verify(login.body.token, process.env.JWT_SECRET);
    assert.equal(claims.id, TARGET);
    assert.equal(claims.role, role);
    assert.equal(claims.impersonatedBy, ACTOR);
    assert.equal(claims.impersonationMode, mode);
    assert.equal(state.audits.length, 1);
    assert.equal(state.audits[0].sessionId, claims.sessionId);
    assert.equal(state.audits[0].targetRole, role);
    assert.equal(state.userHistoryWrites(), 0);
    const history = await request({ method: 'GET', path: '/user-login-audits' });
    assert.equal(history.body[0].targetEmail, state.target.email);
    const updates = [];
    t.mock.method(SuperadminLoginAudit, 'updateOne', async (filter, update) => { updates.push({ filter, update }); });
    assert.equal((await request({ handler: authRouter, path: '/logout', token: login.body.token })).status, 200);
    assert.equal(updates[0].filter.sessionId, claims.sessionId);
    assert.ok(updates[0].update.$set.logoutAt instanceof Date);
    assert.equal(state.userHistoryWrites(), 0);
    t.mock.method(SuperadminLoginAudit, 'create', async () => { throw new Error('Unavailable'); });
    assert.equal((await request(args)).status, 500);
  });
}

test('historical company and partner impersonations appear in the superadmin audit without backfilling records', async t => {
  const state = setup(t);
  state.legacyLogins.push({
    _id: 'old-company-login', userId: state.target, email: state.target.email,
    action: 'superadmin_company_impersonation_started', success: true,
    failReason: `by:${ACTOR}`, createdAt: '2026-10-05T10:00:00Z', ipAddress: '127.0.0.1',
  });
  const result = await request({ method: 'GET', path: '/user-login-audits' });
  assert.equal(result.status, 200);
  assert.equal(result.body[0].actorEmail, state.actor.email);
  assert.equal(result.body[0].targetEmail, state.target.email);
  assert.equal(result.body[0].loginAt, '2026-10-05T10:00:00Z');
  assert.equal(result.body[0].logoutAt, null);
  assert.equal(state.audits.length, 0);
  assert.equal(state.userHistoryWrites(), 0);
});
