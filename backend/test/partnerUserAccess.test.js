const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const User = require('../src/models/User.model');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const Token = require('../src/models/Token.model');
const LoginActivity = require('../src/models/LoginActivity.model');
const SocCompanyAssignment = require('../src/models/SocCompanyAssignment.model');
const router = require('../src/routes/partner.routes');
const authRouter = require('../src/routes/auth.routes');
const superadminRouter = require('../src/routes/superadmin.routes');
const { authenticate } = require('../src/middleware/auth.middleware');
const { MANAGED_ROLES } = require('../src/services/partnerUserAccess.service');

const id = value => Number(value).toString(16).padStart(24, '0');
const ACTOR = id(1), PARTNER = id(2), COMPANY = id(3), OTHER_PARTNER = id(4), OTHER_COMPANY = id(5), TARGET = id(6);
const PASSWORD = 'Partner updated password 42!';
const same = (a, b) => b == null ? a == null : String(a?._id || a) === String(b?._id || b);
function matches(row, filter) {
  return Object.entries(filter).every(([key, condition]) => {
    if (key === '$or') return condition.some(branch => matches(row, branch));
    const field = key.split('.').reduce((value, part) => value?.[part], row);
    if (condition?.$regex) return new RegExp(condition.$regex, condition.$options).test(field || '');
    if (condition?.$in) return condition.$in.some(value => same(field, value));
    if (condition?.$nin) return !condition.$nin.some(value => same(field, value));
    if (condition && Object.hasOwn(condition, '$ne')) return !same(field, condition.$ne);
    return same(field, condition);
  });
}
function query(value) {
  return { select() { return this; }, sort() { return this; }, lean: async () => value,
    then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
    distinct: async key => [...new Set(value.map(row => row[key]))] };
}

function setup(t, targetOverrides = {}) {
  const secret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'partner-user-access-test-secret';
  t.after(() => { if (secret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = secret; });
  const account = (userId, overrides = {}) => new User({ _id: userId, name: `User ${userId}`, email: `${userId}@example.test`, password: 'Original password', role: 'analyst', partnerId: PARTNER, ...overrides });
  const actor = account(ACTOR, { role: 'partner_admin' });
  const target = account(TARGET, targetOverrides);
  const extras = [
    ...MANAGED_ROLES.map((role, index) => account(id(20 + index), { role, companyId: COMPANY })),
    account(id(40), { partnerId: OTHER_PARTNER, companyId: OTHER_COMPANY }),
    account(id(41), { superadminManaged: true }),
    account(id(42), { socManagerPool: true }),
    account(id(43), { role: 'superadmin' }),
    account(id(44), { role: 'partner_admin' }),
    account(id(45), { partnerId: null, companyId: COMPANY }),
    account(id(46), { partnerId: null }),
    account(id(47), { partnerId: null }),
    account(id(48), { companyId: OTHER_COMPANY }),
    account(id(49)),
  ];
  const users = [actor, target, ...extras];
  const companies = [{ _id: COMPANY, partnerId: PARTNER, name: 'Own Company' }, { _id: OTHER_COMPANY, partnerId: OTHER_PARTNER, name: 'Other Company' }];
  const assignments = [
    { userId: id(46), companyId: COMPANY, active: true },
    { userId: id(47), companyId: COMPANY, active: false },
    { userId: id(49), companyId: COMPANY, active: true },
    { userId: id(49), companyId: OTHER_COMPANY, active: true },
  ];
  const audits = [], resets = [], saved = [], userFilters = [];
  const partner = { _id: PARTNER, name: 'First Partner', status: 'active', plan: { paymentStatus: 'paid', isActive: true } };
  t.mock.method(User, 'findById', userId => query(users.find(user => same(user._id, userId)) || null));
  t.mock.method(User, 'find', filter => { userFilters.push(filter); return query(users.filter(user => matches(user, filter))); });
  t.mock.method(Company, 'find', filter => query(companies.filter(company => matches(company, filter))));
  t.mock.method(Partner, 'findById', partnerId => query(same(partnerId, PARTNER) ? partner : null));
  t.mock.method(Partner, 'find', filter => query([partner, { _id: OTHER_PARTNER, name: 'Second Partner' }].filter(row => matches(row, filter))));
  t.mock.method(SocCompanyAssignment, 'find', filter => query(assignments.filter(assignment => matches(assignment, filter))));
  t.mock.method(LoginActivity, 'create', async row => {
    const record = { _id: id(1000 + audits.length), createdAt: new Date(), ...row };
    audits.push(record);
    return record;
  });
  t.mock.method(LoginActivity, 'countDocuments', async filter => audits.filter(row => matches(row, filter)).length);
  t.mock.method(LoginActivity, 'find', filter => {
    let rows = audits.filter(row => matches(row, filter));
    return {
      select() { return this; },
      sort(fields) {
        rows.sort((a, b) => {
          for (const [key, direction] of Object.entries(fields)) {
            if (a[key] < b[key]) return -direction;
            if (a[key] > b[key]) return direction;
          }
          return 0;
        });
        return this;
      },
      skip(count) { rows = rows.slice(count); return this; },
      limit(count) { rows = rows.slice(0, count); return this; },
      lean: async () => rows,
    };
  });
  t.mock.method(LoginActivity, 'exists', async filter => audits.some(row => matches(row, filter)));
  t.mock.method(Token, 'updateMany', async (filter, update) => { resets.push({ filter, update }); return { modifiedCount: 1 }; });
  t.mock.method(User.collection, 'insertOne', async row => { saved.push(row); return { acknowledged: true, insertedId: row._id }; });
  return { actor, target, users, companies, assignments, audits, resets, saved, partner, userFilters };
}

function request({ method = 'GET', path = '/user-accounts', body = {}, claims = {}, query: queryParams = {}, role = 'partner_admin', token, handler = router } = {}) {
  const authorization = token || (role ? jwt.sign({ id: ACTOR, role, partnerId: PARTNER, ...claims }, process.env.JWT_SECRET) : null);
  return new Promise((resolve, reject) => {
    const req = { method, url: path, body, query: { partnerId: OTHER_PARTNER, companyId: OTHER_COMPANY, ...queryParams },
      headers: { ...(authorization ? { authorization: `Bearer ${authorization}` } : {}), 'x-company-id': OTHER_COMPANY },
      app: { get: () => null }, ip: '127.0.0.1', get: () => 'Unit test' };
    const res = { statusCode: 200, headers: {}, status(code) { this.statusCode = code; return this; },
      set(key, value) { this.headers[key] = value; return this; },
      json(data) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(data)), headers: this.headers }); } };
    handler.handle(req, res, error => reject(error || new Error('User access route not found')));
  });
}

test('directory includes subordinate roles and legacy assignments, excluding foreign, privileged and shared accounts', async t => {
  setup(t);
  const result = await request();
  assert.equal(result.status, 200);
  assert.deepEqual(result.body.map(user => user._id), [TARGET, ...MANAGED_ROLES.map((_, index) => id(20 + index)), id(45), id(46)]);
  assert.equal(result.body.find(user => user._id === id(20)).companyName, 'Own Company');
  assert.equal(result.headers['Cache-Control'], 'no-store');
  for (const user of result.body) assert.equal(user.password, undefined);
});

test('authentication, original role, live actor, partner and credential version are required', async t => {
  const state = setup(t);
  assert.equal((await request({ role: null })).status, 401);
  for (const role of ['superadmin', 'company_admin', 'soc_manager', 'analyst']) assert.equal((await request({ role })).status, 403);
  assert.equal((await request({ claims: { impersonatedBy: id(99) } })).status, 403);
  assert.equal((await request({ claims: { partnerId: OTHER_PARTNER } })).status, 401);
  state.actor.isActive = false;
  assert.equal((await request()).status, 401);
  state.actor.isActive = true;
  state.actor.passwordChangedAt = new Date(Date.now() + 1000);
  assert.equal((await request()).status, 401);
  state.actor.passwordChangedAt = null;
  state.partner.status = 'suspended';
  assert.equal((await request()).status, 403);
  assert.equal(state.saved.length, 0);
});

test('password and login endpoints reject every out-of-scope account without writes', async t => {
  const state = setup(t);
  for (const userId of [ACTOR, ...[40, 41, 42, 43, 44, 47, 48, 49, 99].map(id)]) {
    for (const action of ['password', 'impersonate']) {
      const result = await request({ method: 'POST', path: `/user-accounts/${userId}/${action}`, body: { newPassword: PASSWORD } });
      assert.equal(result.status, 404, `${userId}/${action}`);
      assert.equal(result.body.token, undefined);
    }
  }
  assert.deepEqual(state.saved, []);
  assert.deepEqual(state.audits, []);
  assert.deepEqual(state.resets, []);
});

test('invalid IDs and passwords never mutate a user', async t => {
  const state = setup(t);
  for (const action of ['password', 'impersonate']) assert.equal((await request({ method: 'POST', path: `/user-accounts/invalid/${action}`, body: { newPassword: PASSWORD } })).status, 400);
  for (const newPassword of [null, 12345678, {}, [], '', 'short', 'x'.repeat(129)]) {
    assert.equal((await request({ method: 'POST', path: `/user-accounts/${TARGET}/password`, body: { newPassword } })).status, 400);
  }
  assert.deepEqual(state.saved, []);
});

test('password change hashes the password and retires reset links without changing role, status or MFA', async t => {
  const state = setup(t, { role: 'department_admin', isActive: false, accountStatus: 'suspended', twoFactorEnabled: true, forcePasswordReset: true });
  const result = await request({ method: 'POST', path: `/user-accounts/${TARGET}/password`, body: { newPassword: PASSWORD, role: 'superadmin', isActive: true, twoFactorEnabled: false } });
  assert.equal(result.status, 200);
  assert.match(state.saved[0].password, /^\$argon2id\$/);
  assert.equal(await argon2.verify(state.saved[0].password, PASSWORD), true);
  assert.equal(state.target.role, 'department_admin');
  assert.equal(state.target.isActive, false);
  assert.equal(state.target.accountStatus, 'suspended');
  assert.equal(state.target.twoFactorEnabled, true);
  assert.equal(state.target.forcePasswordReset, false);
  assert.equal(state.resets[0].filter.email, state.target.email);
  assert.deepEqual(state.resets[0].update, { $set: { used: true } });
  assert.equal(String(state.audits[0].userId), ACTOR);
  assert.ok(!JSON.stringify([result.body, state.audits]).includes(PASSWORD));
});

test('reset-link revocation failure leaves the password unchanged', async t => {
  const state = setup(t);
  t.mock.method(Token, 'updateMany', async () => { throw new Error('Unavailable'); });
  assert.equal((await request({ method: 'POST', path: `/user-accounts/${TARGET}/password`, body: { newPassword: PASSWORD } })).status, 500);
  assert.equal(state.target.password, 'Original password');
  assert.deepEqual(state.saved, []);
});

for (const role of MANAGED_ROLES) {
  test(`login as ${role} preserves target identity and records the actor without credentials`, async t => {
    const state = setup(t, { role, companyId: COMPANY, tenantId: id(70), departmentId: id(71) });
    const result = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate`, body: { role: 'superadmin', companyId: OTHER_COMPANY } });
    assert.equal(result.status, 200);
    const token = jwt.verify(result.body.token, process.env.JWT_SECRET);
    assert.equal(token.role, role);
    assert.equal(token.id, TARGET);
    assert.equal(token.companyId, COMPANY);
    assert.equal(token.partnerId, PARTNER);
    assert.equal(token.tenantId, id(70));
    assert.equal(token.departmentId, id(71));
    assert.equal(token.impersonatedBy, ACTOR);
    assert.equal(token.impersonatedByRole, 'partner_admin');
    assert.equal(token.exp - token.iat, 14400);
    assert.equal(state.audits[0].action, 'partner_impersonation_started');
    assert.equal(state.audits[0].sessionId, token.sessionId);
    assert.ok(!JSON.stringify(state.audits).includes(result.body.token));
    assert.equal(result.body.user.password, undefined);
  });
}

test('inactive targets and audit failures cannot issue usable tokens', async t => {
  const state = setup(t);
  for (const accountStatus of ['disabled', 'suspended', 'invited', 'expired']) {
    state.target.accountStatus = accountStatus;
    assert.equal((await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` })).status, 403);
  }
  state.target.accountStatus = 'active';
  t.mock.method(LoginActivity, 'create', async () => { throw new Error('Audit unavailable'); });
  const result = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  assert.equal(result.status, 500);
  assert.equal(result.body.token, undefined);
});

test('support refresh retains original token and banner; logout revokes the support session', async t => {
  const state = setup(t);
  const login = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  const refresh = await request({ handler: authRouter, path: '/me', token: login.body.token });
  assert.equal(refresh.status, 200);
  assert.equal(refresh.body.token, login.body.token);
  assert.match(refresh.body.impersonation.banner, /via Partner Admin/);
  assert.equal(refresh.body.impersonation.by, ACTOR);
  assert.equal((await request({ handler: authRouter, path: '/logout', method: 'POST', token: login.body.token })).status, 200);
  assert.equal(state.audits.at(-1).action, 'partner_impersonation_ended');
  assert.equal((await request({ handler: authRouter, path: '/me', token: login.body.token })).status, 401);
});

test('every authenticated support request rechecks actor, target assignments and password changes', async t => {
  const state = setup(t);
  const login = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  const checked = require('express').Router();
  checked.get('/check', authenticate, (req, res) => res.json({ role: req.user.role }));
  const check = () => request({ handler: checked, path: '/check', token: login.body.token });
  assert.equal((await check()).status, 200);
  state.assignments.push({ userId: TARGET, companyId: OTHER_COMPANY, active: true });
  assert.equal((await check()).status, 401);
  state.assignments.pop();
  state.actor.isActive = false;
  assert.equal((await check()).status, 401);
  state.actor.isActive = true;
  state.target.passwordChangedAt = new Date(Date.now() + 1000);
  assert.equal((await check()).status, 401);
});

test('audit exposes login, logout and password change identities without credentials', async t => {
  const state = setup(t);
  const login = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  assert.equal(login.status, 200);
  assert.equal((await request({ handler: authRouter, path: '/logout', method: 'POST', token: login.body.token })).status, 200);
  assert.equal((await request({ method: 'POST', path: `/user-accounts/${TARGET}/password`, body: { newPassword: PASSWORD } })).status, 200);
  const result = await request({ path: '/user-accounts/audit' });
  assert.equal(result.status, 200);
  assert.equal(result.headers['Cache-Control'], 'no-store');
  assert.equal(result.body.total, 3);
  assert.deepEqual(result.body.entries.map(row => row.action), ['password_changed', 'partner_impersonation_ended', 'partner_impersonation_started']);
  for (const row of result.body.entries) {
    assert.equal(row.actor._id, ACTOR);
    assert.equal(row.actor.name, state.actor.name);
    assert.equal(row.target._id, TARGET);
    assert.equal(row.target.name, state.target.name);
    assert.equal(row.target.email, state.target.email);
    assert.equal(row.target.role, state.target.role);
    assert.equal(row.ipAddress, '127.0.0.1');
    assert.equal(row.success, true);
    assert.ok(row.createdAt);
    assert.equal(row.failReason, undefined);
    assert.equal(row.sessionId, undefined);
  }
  for (const row of state.audits) assert.equal(new LoginActivity(row).validateSync(), undefined);
  assert.ok(!JSON.stringify(result.body).includes(PASSWORD));
  assert.ok(!JSON.stringify(result.body).includes(login.body.token));
});

test('audit requires the original live Partner Admin session', async t => {
  const state = setup(t);
  const path = '/user-accounts/audit';
  assert.equal((await request({ path, role: null })).status, 401);
  for (const role of ['superadmin', 'company_admin', 'analyst']) assert.equal((await request({ path, role })).status, 403);
  assert.equal((await request({ path, claims: { impersonatedBy: id(99) } })).status, 403);
  state.actor.isActive = false;
  assert.equal((await request({ path })).status, 401);
});

test('audit scopes structured and legacy records by historical partner, ignoring scope overrides', async t => {
  const state = setup(t);
  const base = { userId: ACTOR, email: state.actor.email, createdAt: new Date(), success: true,
    action: 'partner_impersonation_started', sessionToken: 'secret-token-hash', password: PASSWORD };
  state.audits.push(
    { ...base, _id: id(100), partnerAccess: { partnerId: PARTNER, targetUserId: TARGET, targetEmail: 'original@example.test', targetName: 'Original user', targetRole: 'analyst' } },
    { ...base, _id: id(101), failReason: `partner:${PARTNER};user:${TARGET}` },
    { ...base, _id: id(102), action: 'password_changed', failReason: `partner_password_change:partner:${PARTNER};user:${TARGET}` },
    { ...base, _id: id(103), action: 'partner_impersonation_blocked', success: false, partnerAccess: { partnerId: PARTNER, targetUserId: TARGET } },
    // The same actor may have previously belonged to a different partner.
    { ...base, _id: id(200), partnerAccess: { partnerId: OTHER_PARTNER, targetUserId: TARGET }, failReason: `partner:${PARTNER};user:${TARGET}` },
    { ...base, _id: id(201), failReason: `partner:${OTHER_PARTNER};user:${TARGET}` },
    { ...base, _id: id(202), action: 'password_changed', failReason: `partner_password_change:partner:${OTHER_PARTNER};user:${TARGET}` },
    { ...base, _id: id(203), action: 'password_changed' },
    { ...base, _id: id(204), action: 'login_success' },
    { ...base, _id: id(205), action: 'superadmin_impersonation_started', partnerAccess: { partnerId: PARTNER, targetUserId: TARGET } },
    // Old blocked events lack evidence of the historical partner.
    { ...base, _id: id(206), action: 'partner_impersonation_blocked', failReason: `user:${TARGET};DELETE /api/test` },
  );
  const result = await request({ path: '/user-accounts/audit', query: { userId: id(200), partnerId: OTHER_PARTNER, companyId: OTHER_COMPANY } });
  assert.equal(result.status, 200);
  assert.equal(result.body.total, 4);
  assert.deepEqual(result.body.entries.map(row => row._id), [103, 102, 101, 100].map(id));
  assert.equal(result.body.entries.find(row => row._id === id(101)).target.email, state.target.email);
  assert.equal(result.body.entries.find(row => row._id === id(100)).target.email, 'original@example.test');
  assert.ok(!JSON.stringify(result.body).includes('secret-token-hash'));
  assert.ok(!JSON.stringify(result.body).includes(PASSWORD));

  state.target.partnerId = OTHER_PARTNER;
  state.target.email = 'new-private-address@example.test';
  const moved = await request({ path: '/user-accounts/audit' });
  assert.equal(moved.body.total, 4);
  assert.equal(moved.body.entries.find(row => row._id === id(100)).target.email, 'original@example.test');
  assert.equal(moved.body.entries.find(row => row._id === id(101)).target._id, TARGET);
  assert.ok(!JSON.stringify(moved.body).includes(state.target.email));
});

test('audit pages six records at a time in stable newest-first order and filters actions', async t => {
  const state = setup(t);
  for (let index = 1; index <= 13; index++) {
    state.audits.push({ _id: id(100 + index), userId: ACTOR, email: state.actor.email, createdAt: new Date('2026-10-06T12:00:00Z'),
      action: index % 2 ? 'partner_impersonation_started' : 'password_changed', success: true,
      partnerAccess: { partnerId: PARTNER, targetUserId: TARGET, targetEmail: state.target.email },
    });
  }
  const pages = [];
  for (let page = 1; page <= 3; page++) {
    const result = await request({ path: '/user-accounts/audit', query: { page: String(page), pageSize: '1000' } });
    assert.equal(result.status, 200);
    assert.equal(result.body.page, page);
    assert.equal(result.body.pageSize, 6);
    assert.equal(result.body.total, 13);
    assert.equal(result.body.entries.length, page === 3 ? 1 : 6);
    pages.push(...result.body.entries.map(row => row._id));
  }
  assert.deepEqual(pages, Array.from({ length: 13 }, (_, index) => id(113 - index)));
  const pastEnd = await request({ path: '/user-accounts/audit', query: { page: '99' } });
  assert.equal(pastEnd.body.page, 3);
  const filtered = await request({ path: '/user-accounts/audit', query: { action: 'password_changed' } });
  assert.equal(filtered.body.total, 6);
  assert.ok(filtered.body.entries.every(row => row.action === 'password_changed'));
});

test('audit distinguishes empty history, invalid queries and database failures', async t => {
  setup(t);
  const empty = await request({ path: '/user-accounts/audit' });
  assert.deepEqual(empty.body, { page: 1, pageSize: 6, total: 0, entries: [] });
  for (const page of ['0', '-1', '1.5', 'NaN', 'Infinity']) {
    assert.equal((await request({ path: '/user-accounts/audit', query: { page } })).status, 400);
  }
  assert.equal((await request({ path: '/user-accounts/audit', query: { action: 'login_success' } })).status, 400);
  t.mock.method(LoginActivity, 'countDocuments', async () => { throw new Error('Database unavailable'); });
  const unavailable = await request({ path: '/user-accounts/audit' });
  assert.equal(unavailable.status, 503);
  assert.equal(unavailable.body.entries, undefined);
});

function setupSuperadmin(t, state) {
  const admin = new User({ _id: id(900), name: 'Superadmin', email: 'superadmin@example.test', role: 'superadmin', password: 'unused' });
  state.users.push(admin);
  t.mock.method(User, 'findOne', filter => query(state.users.find(user => same(user._id, filter._id)
    && user.role === filter.role && user.isActive === true && user.accountStatus === 'active') || null));
  return admin;
}
const superadminHistory = (options = {}) => request({
  path: '/partner-access-accounts', handler: superadminRouter, role: 'superadmin', claims: { id: id(900) }, ...options,
});

test('superadmin sees partner name, company and both session times for actual partner logins', async t => {
  const state = setup(t, { companyId: COMPANY, role: 'company_admin' });
  setupSuperadmin(t, state);
  const first = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  const second = await request({ method: 'POST', path: `/user-accounts/${TARGET}/impersonate` });
  assert.equal(first.status, 200);
  assert.equal(second.status, 200);
  const firstId = String(state.audits[0]._id), secondId = String(state.audits[1]._id);
  assert.equal((await request({ handler: authRouter, path: '/logout', method: 'POST', token: first.body.token })).status, 200);
  const result = await superadminHistory();
  assert.equal(result.status, 200);
  assert.equal(result.headers['Cache-Control'], 'no-store');
  assert.equal(result.body.total, 2);
  const ended = result.body.entries.find(row => row._id === firstId);
  const ongoing = result.body.entries.find(row => row._id === secondId);
  assert.equal(ended.partnerName, 'First Partner');
  assert.equal(ended.actorName, state.actor.name);
  assert.equal(ended.targetEmail, state.target.email);
  assert.equal(ended.companyName, 'Own Company');
  assert.equal(ended.targetRole, 'company_admin');
  assert.equal(ended.loginAt, state.audits[0].createdAt.toISOString());
  assert.equal(ended.logoutAt, state.audits[2].createdAt.toISOString());
  assert.equal(ongoing.logoutAt, null);
  assert.equal(ended.sessionId, undefined);
  assert.ok(!JSON.stringify(result.body).includes(first.body.token));
  assert.ok(!JSON.stringify(result.body).includes(second.body.token));

  // Names captured at access time survive later edits or deletion.
  state.partner.name = 'Renamed Partner';
  state.companies[0].name = 'Renamed Company';
  state.users.splice(state.users.indexOf(state.target), 1);
  const retained = await superadminHistory();
  assert.equal(retained.body.entries[0].partnerName, 'First Partner');
  assert.equal(retained.body.entries[0].companyName, 'Own Company');
  assert.equal(retained.body.entries[0].targetEmail, state.target.email);
});

test('partner access history is restricted to a live superadmin', async t => {
  const state = setup(t);
  const admin = setupSuperadmin(t, state);
  assert.equal((await superadminHistory({ role: null })).status, 401);
  for (const role of ['partner_admin', 'company_admin', 'analyst']) {
    assert.equal((await superadminHistory({ role, claims: {} })).status, 403);
  }
  admin.isActive = false;
  assert.equal((await superadminHistory()).status, 401);
  admin.isActive = true;
  admin.passwordChangedAt = new Date(Date.now() + 1000);
  assert.equal((await superadminHistory()).status, 401);
});

test('superadmin history includes all partners and pairs only matching session, actor, target and partner', async t => {
  const state = setup(t, { companyId: COMPANY });
  setupSuperadmin(t, state);
  const start = {
    _id: id(100), userId: ACTOR, email: state.actor.email, action: 'partner_impersonation_started', success: true,
    sessionId: 'session-a', createdAt: new Date('2026-10-06T10:00:00Z'), companyId: COMPANY,
    partnerAccess: { partnerId: PARTNER, targetUserId: TARGET, targetEmail: state.target.email },
    sessionToken: 'hidden-secret', failReason: 'private-internal-data',
  };
  const end = { ...start, _id: id(101), action: 'partner_impersonation_ended', createdAt: new Date('2026-10-06T11:00:00Z') };
  state.audits.push(start,
    { ...end, _id: id(102), sessionId: 'different-session' },
    { ...end, _id: id(103), userId: id(999) },
    { ...end, _id: id(104), partnerAccess: { partnerId: OTHER_PARTNER, targetUserId: TARGET } },
    { ...end, _id: id(105), partnerAccess: { partnerId: PARTNER, targetUserId: id(44) } },
    { ...end, _id: id(106), success: false },
    { ...end, _id: id(107), createdAt: new Date('2026-10-06T09:00:00Z') },
    { ...start, _id: id(108), sessionId: null, partnerAccess: undefined, failReason: `partner:${OTHER_PARTNER};user:${id(40)}` },
    { ...start, _id: id(109), action: 'superadmin_impersonation_started' },
    { ...start, _id: id(110), action: 'password_changed' },
    { ...start, _id: id(111), success: false },
  );
  let result = await superadminHistory();
  assert.equal(result.body.total, 2);
  assert.ok(result.body.entries.every(row => row.logoutAt === null));
  assert.equal(result.body.entries.find(row => row._id === id(108)).partnerName, 'Second Partner');
  assert.ok(!JSON.stringify(result.body).includes('hidden-secret'));
  assert.ok(!JSON.stringify(result.body).includes('private-internal-data'));
  state.audits.push(end);
  result = await superadminHistory();
  assert.equal(result.body.entries.find(row => row._id === id(100)).logoutAt, end.createdAt.toISOString());
  assert.equal(result.body.entries.find(row => row._id === id(108)).logoutAt, null);
});

test('superadmin session pagination is based on logins, with logout matching across pages', async t => {
  const state = setup(t);
  setupSuperadmin(t, state);
  for (let index = 1; index <= 13; index++) {
    const identity = { partnerId: PARTNER, targetUserId: TARGET, targetEmail: state.target.email };
    state.audits.push({ _id: id(100 + index), userId: ACTOR, email: state.actor.email, createdAt: new Date('2026-10-06T10:00:00Z'),
      action: 'partner_impersonation_started', success: true, sessionId: `s${index}`, partnerAccess: identity },
    { _id: id(200 + index), userId: ACTOR, email: state.actor.email, createdAt: new Date('2026-10-06T12:00:00Z'),
      action: 'partner_impersonation_ended', success: true, sessionId: `s${index}`, partnerAccess: identity });
  }
  const rows = [];
  for (let page = 1; page <= 3; page++) {
    const result = await superadminHistory({ query: { page: String(page), pageSize: '1000', partnerId: OTHER_PARTNER } });
    assert.equal(result.status, 200);
    assert.equal(result.body.total, 13);
    assert.equal(result.body.pageSize, 6);
    assert.equal(result.body.entries.length, page === 3 ? 1 : 6);
    assert.ok(result.body.entries.every(row => row.logoutAt === '2026-10-06T12:00:00.000Z'));
    rows.push(...result.body.entries.map(row => row._id));
  }
  assert.deepEqual(rows, Array.from({ length: 13 }, (_, index) => id(113 - index)));
  assert.equal((await superadminHistory({ query: { page: '99' } })).body.page, 3);
});

test('superadmin history returns empty, invalid-query and unavailable states correctly', async t => {
  const state = setup(t);
  setupSuperadmin(t, state);
  assert.deepEqual((await superadminHistory()).body, { page: 1, pageSize: 6, total: 0, entries: [] });
  for (const page of ['0', '-1', '1.5', 'NaN']) assert.equal((await superadminHistory({ query: { page } })).status, 400);
  t.mock.method(LoginActivity, 'countDocuments', async () => { throw new Error('Unavailable'); });
  const result = await superadminHistory();
  assert.equal(result.status, 503);
  assert.equal(result.body.entries, undefined);
});
