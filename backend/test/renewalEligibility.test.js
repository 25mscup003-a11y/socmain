const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const API = require('razorpay/dist/api');
const Company = require('../src/models/Company.model');
const Batch = require('../src/models/AddSystemSubscription.model');
const Pricing = require('../src/models/Pricing.model');
const payments = require('../src/routes/payment.routes');
const batches = require('../src/routes/add-system.routes');
const { hasExpired } = require('../src/utils/renewalEligibility');

function setup(t) {
  const state = { company: { _id: new mongoose.Types.ObjectId(), plan: { paymentStatus: 'paid', expiresAt: new Date(Date.now() + 60000) } }, batches: [], orders: [] };
  for (const key of ['RAZORPAY_KEY_ID', 'RAZORPAY_KEY_SECRET']) {
    const old = process.env[key]; process.env[key] = 'renewal_test_only';
    t.after(() => { if (old === undefined) delete process.env[key]; else process.env[key] = old; });
  }
  t.mock.method(Company, 'findById', () => ({ select() { return this; }, lean: async () => state.company }));
  t.mock.method(Batch, 'findOne', async filter => state.batches.find(batch => String(batch._id) === String(filter._id) && String(batch.companyId) === String(filter.companyId)));
  const pricing = {};
  for (const prefix of ['newUser', 'renewal']) for (const type of ['System', 'Server', 'Phone']) for (const cycle of ['Monthly', 'Yearly']) pricing[`${prefix}_pricePer${type}${cycle}`] = 100;
  t.mock.method(Pricing, 'findOne', () => ({ sort: async () => pricing }));
  t.mock.method(API.prototype, 'post', async ({ url, data }) => {
    assert.equal(url, '/orders');
    const order = { id: `order_test_${state.orders.length + 1}`, ...data };
    state.orders.push(order); return order;
  });
  state.call = async (router, path, body = {}, params = {}) => {
    const handler = router.stack.find(layer => layer.route?.path === path).route.stack.at(-1).handle;
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(value) { this.body = value; return this; } };
    await handler({ user: { companyId: state.company._id }, body, params }, res);
    return res;
  };
  return state;
}

test('renewal dates unlock exactly at expiry and unknown dates remain unavailable', () => {
  const expiry = new Date('2026-10-07T12:30:00Z');
  assert.equal(hasExpired(expiry, new Date(+expiry - 1)), false);
  assert.equal(hasExpired(expiry, expiry), true);
  for (const missing of [null, undefined, '', 'not-a-date']) assert.equal(hasExpired(missing, expiry), false);
});

test('base renewal blocks active plans even when the caller removes the renewal flag', async t => {
  const s = setup(t);
  for (const isUpgrade of [true, false]) {
    const response = await s.call(payments, '/create-order', { systemCount: 1, isUpgrade });
    assert.equal(response.statusCode, 409); assert.match(response.body.message, /after your base plan expires/);
  }
  s.company.plan.expiresAt = null;
  assert.equal((await s.call(payments, '/create-order', { systemCount: 1, isUpgrade: true })).statusCode, 409);
  assert.equal(s.orders.length, 0);
});

test('expired base renewals and initial unpaid activations can create a payment order', async t => {
  const s = setup(t);
  s.company.plan.expiresAt = new Date(Date.now() - 1);
  assert.equal((await s.call(payments, '/create-order', { systemCount: 1, isUpgrade: true })).statusCode, 200);
  s.company.plan = { paymentStatus: 'unpaid', expiresAt: new Date(Date.now() + 86400000) };
  assert.equal((await s.call(payments, '/create-order', { systemCount: 1 })).statusCode, 200);
  assert.equal(s.orders.length, 2); assert.equal(s.orders[0].amount, 10000);
});

test('batch renewal uses each purchased batch expiry, regardless of the base plan or stale batch status', async t => {
  const s = setup(t);
  const active = { _id: new mongoose.Types.ObjectId(), companyId: s.company._id, status: 'active', paymentStatus: 'paid', priceType: 'renewal', endDate: new Date(Date.now() + 86400000), addedSystemCount: 2, addedServerCount: 0 };
  const expired = { ...active, _id: new mongoose.Types.ObjectId(), endDate: new Date(Date.now() - 1) };
  s.batches = [active, expired];
  assert.equal((await s.call(batches, '/renew/:id', {}, { id: active._id })).statusCode, 409);
  assert.equal((await s.call(batches, '/renew/:id', {}, { id: expired._id })).statusCode, 200);
  assert.equal(s.orders.length, 1); assert.equal(s.orders[0].notes.batchId, String(expired._id));
  for (const change of [{ status: 'cancelled' }, { paymentStatus: 'unpaid' }, { endDate: null }]) {
    const original = { ...expired }; Object.assign(expired, change);
    assert.equal((await s.call(batches, '/renew/:id', {}, { id: expired._id })).statusCode, 409);
    Object.assign(expired, original);
  }
  assert.equal(s.orders.length, 1);
});
