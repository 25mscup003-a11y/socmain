const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const User = require('../src/models/User.model');
const Token = require('../src/models/Token.model');
const LoginActivity = require('../src/models/LoginActivity.model');
const router = require('../src/routes/superadmin.routes');

const ACTOR_ID = '600000000000000000000001';
const TARGET_ID = '600000000000000000000002';
const PASSWORD = 'New account password 42!';

function setup(t, { active = true, changedAt = null, role = 'analyst' } = {}) {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'superadmin-password-unit-test-secret';
  t.after(() => {
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  });
  const actor = { _id: ACTOR_ID, email: 'admin@example.test', role: 'superadmin', passwordChangedAt: changedAt };
  const target = new User({
    _id: TARGET_ID, name: 'Target User', email: 'target@example.test', role,
    password: 'Previous password', forcePasswordReset: true,
    companyId: '600000000000000000000003',
    isActive: false, accountStatus: 'suspended', twoFactorEnabled: true,
  });
  const calls = { saved: [], resets: [], audits: [], lookups: [] };
  t.mock.method(User, 'findOne', filter => {
    assert.equal(filter.role, 'superadmin');
    assert.equal(filter.isActive, true);
    assert.deepEqual(filter.$or, [{ accountStatus: 'active' }, { accountStatus: { $exists: false } }]);
    return { select: () => ({ lean: async () => active ? actor : null }) };
  });
  t.mock.method(User, 'findById', async id => {
    calls.lookups.push(id);
    return id === TARGET_ID ? target : null;
  });
  // Exercise real Mongoose validation/save hooks, replacing only persistence.
  t.mock.method(User.collection, 'insertOne', async document => {
    calls.saved.push(document);
    return { acknowledged: true, insertedId: document._id };
  });
  t.mock.method(Token, 'updateMany', async (filter, update) => {
    calls.resets.push({ filter, update });
    return { modifiedCount: 1 };
  });
  t.mock.method(LoginActivity, 'create', async record => { calls.audits.push(record); return record; });
  return { target, calls };
}

function request({ tokenRole = 'superadmin', id = TARGET_ID, body = { newPassword: PASSWORD }, headers = {} } = {}) {
  const token = tokenRole ? jwt.sign({ id: ACTOR_ID, role: tokenRole }, process.env.JWT_SECRET) : null;
  return new Promise((resolve, reject) => {
    const req = {
      method: 'POST', url: `/users/${id}/password`, body, query: {},
      headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...headers },
      ip: '127.0.0.1', get: () => 'Unit test',
    };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(data) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(data)) }); },
    };
    router.handle(req, res, error => reject(error || new Error('Request did not match password route')));
  });
}

test('password changes require authentication and the superadmin role', async t => {
  const { calls } = setup(t);
  assert.equal((await request({ tokenRole: null })).status, 401);
  for (const role of User.schema.path('role').enumValues.filter(role => role !== 'superadmin')) {
    assert.equal((await request({ tokenRole: role })).status, 403, role);
  }
  assert.equal(calls.lookups.length, 0);
  assert.equal(calls.saved.length, 0);
});

test('inactive superadmin credentials cannot change passwords', async t => {
  const { calls } = setup(t, { active: false });
  assert.equal((await request()).status, 401);
  assert.equal(calls.lookups.length, 0);
});

test('a superadmin token issued before a password change is rejected', async t => {
  const { calls } = setup(t, { changedAt: new Date(Date.now() + 1000) });
  assert.equal((await request()).status, 401);
  assert.equal(calls.saved.length, 0);
});

test('invalid IDs and invalid passwords are rejected without writes', async t => {
  const { calls } = setup(t);
  assert.equal((await request({ id: 'invalid' })).status, 400);
  for (const newPassword of [undefined, null, 12345678, {}, [], '', 'short', 'a'.repeat(129)]) {
    assert.equal((await request({ body: { newPassword } })).status, 400);
  }
  assert.equal(calls.lookups.length, 0);
  assert.equal(calls.saved.length, 0);
  assert.equal(calls.resets.length, 0);
});

test('a missing account returns 404 without writes', async t => {
  const { calls } = setup(t);
  assert.equal((await request({ id: '600000000000000000000099' })).status, 404);
  assert.equal(calls.saved.length, 0);
  assert.equal(calls.resets.length, 0);
});

for (const role of User.schema.path('role').enumValues) {
  test(`superadmin can set a hashed password for ${role} without changing account access`, async t => {
    const { target, calls } = setup(t, { role });
    const result = await request({
      headers: { 'x-company-id': '600000000000000000000099' },
      body: { newPassword: PASSWORD, role: 'superadmin', isActive: true, twoFactorEnabled: false },
    });
    assert.equal(result.status, 200);
    assert.equal(result.body.userId, TARGET_ID);
    assert.ok(result.body.passwordChangedAt);
    assert.match(calls.saved[0].password, /^\$argon2id\$/);
    assert.equal(await target.comparePassword(PASSWORD), true);
    assert.equal(await argon2.verify(calls.saved[0].password, 'Previous password'), false);
    assert.equal(target.role, role);
    assert.equal(target.isActive, false);
    assert.equal(target.accountStatus, 'suspended');
    assert.equal(target.twoFactorEnabled, true);
    assert.equal(target.forcePasswordReset, false);
    assert.equal(calls.resets[0].filter.email, target.email);
    assert.equal(calls.resets[0].filter.type, 'password_reset');
    assert.equal(calls.resets[0].filter.used, false);
    assert.deepEqual(calls.resets[0].update, { $set: { used: true } });
    assert.equal(calls.audits[0].userId, ACTOR_ID);
    assert.ok(calls.audits[0].failReason.includes(TARGET_ID));
    const publicOutput = JSON.stringify([result.body, calls.audits]);
    assert.equal(publicOutput.includes(PASSWORD), false);
    assert.equal(publicOutput.includes('$argon2'), false);
  });
}

test('password is unchanged if reset-link revocation fails', async t => {
  const { target, calls } = setup(t);
  t.mock.method(Token, 'updateMany', async () => { throw new Error('Unavailable'); });
  assert.equal((await request()).status, 500);
  assert.equal(target.password, 'Previous password');
  assert.equal(calls.saved.length, 0);
});

test('audit failure does not misreport a successfully saved password', async t => {
  const { target } = setup(t);
  t.mock.method(LoginActivity, 'create', async () => { throw new Error('Unavailable'); });
  t.mock.method(console, 'error', () => {});
  assert.equal((await request()).status, 200);
  assert.equal(await target.comparePassword(PASSWORD), true);
});
