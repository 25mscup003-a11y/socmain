const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Partner = require('../src/models/Partner.model');
const User = require('../src/models/User.model');
const router = require('../src/routes/partner.routes');

function setup(t) {
  const previous = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'partner-profile-test';
  t.after(() => { if (previous === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previous; });
  const partnerId = '600000000000000000000001';
  const userId = '600000000000000000000002';
  const owner = { _id: userId, name: 'Partner Owner', email: 'owner@example.test', phone: '9876543210', role: 'partner_admin' };
  const partner = new Partner({ _id: partnerId, name: 'Profile Test', slug: 'profile-test', status: 'active', plan: { isActive: true, paymentStatus: 'paid' }, profile: { bankName: 'Existing Bank' } });
  const calls = { partner: [], user: [] };
  const query = value => ({
    then: (resolve, reject) => Promise.resolve(value).then(resolve, reject),
    select() { return this; },
    populate() { return this; },
    lean() { return Promise.resolve(value); },
  });
  t.mock.method(Partner, 'findById', () => query(partner));
  t.mock.method(User, 'findByIdAndUpdate', async (id, update) => {
    assert.equal(id, userId);
    calls.user.push(update);
    Object.assign(owner, update);
    return owner;
  });
  t.mock.method(Partner, 'findByIdAndUpdate', (id, update) => {
    assert.equal(id, partnerId);
    calls.partner.push(update);
    for (const [key, value] of Object.entries(update)) partner.set(key, value);
    return query({ ...partner.toObject(), ownerUserId: owner });
  });
  const request = body => new Promise((resolve, reject) => {
    const req = { method: 'PATCH', url: '/profile', body, query: {}, app: { get: () => null }, headers: {
      authorization: `Bearer ${jwt.sign({ id: userId, role: 'partner_admin', partnerId }, process.env.JWT_SECRET)}`,
    } };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(body)) }); },
    };
    router.handle(req, res, err => reject(err || new Error('Profile route not found')));
  });
  return { request, calls };
}

test('an individual owner field saves without needing unrelated partner fields', async t => {
  const { request, calls } = setup(t);
  const response = await request({ fullName: 'Updated Owner' });
  assert.equal(response.status, 200);
  assert.equal(response.body.ownerUserId.name, 'Updated Owner');
  assert.equal(response.body.ownerUserId.email, 'owner@example.test');
  assert.equal(response.body.name, 'Profile Test');
  assert.equal(response.body.profile.bankName, 'Existing Bank');
  assert.deepEqual(calls.user, [{ name: 'Updated Owner' }]);
  assert.ok(response.body.updatedAt);
});

test('personal preferences and optional contact details survive schema persistence without changing the role', async t => {
  const { request, calls } = setup(t);
  const values = { designation: 'Operations Lead', alternatePhone: '9123456789', language: 'Hindi', timezone: '(GMT +00:00) UTC' };
  const response = await request(values);
  assert.equal(response.status, 200);
  for (const [field, value] of Object.entries(values)) assert.equal(response.body.profile[field], value);
  assert.equal(response.body.ownerUserId.role, 'partner_admin');
  assert.equal(calls.user.length, 0);
  assert.equal((await request({ alternatePhone: '' })).body.profile.alternatePhone, '');
});

test('invalid preferences fail before any profile or user data is changed', async t => {
  const { request, calls } = setup(t);
  for (const fields of [{ language: 'unsupported' }, { timezone: 'invalid' }, { alternatePhone: 'abc' }]) {
    assert.equal((await request({ fullName: 'Must not change', ...fields })).status, 400);
  }
  assert.deepEqual(calls, { partner: [], user: [] });
});
