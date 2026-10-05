const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Partner = require('../src/models/Partner.model');
const LoginActivity = require('../src/models/LoginActivity.model');
const { agentPriceForPlan, normalizeAgentPricingUpdate, licenseOrderDetails } = require('../src/utils/partnerAgentPricing');
const router = require('../src/routes/superadmin.routes');

const pricing = { system: { monthly: 100, yearly: 1000 }, server: { monthly: 500, yearly: 5000 }, android: { monthly: 50, yearly: 500 } };

test('each device uses its own monthly and yearly rates, with legacy fallback only when missing', () => {
  const partner = { agentPricing: { monthly: 70, yearly: 700, ...pricing } };
  assert.equal(agentPriceForPlan(partner, 'monthly', 'system'), 100);
  assert.equal(agentPriceForPlan(partner, 'monthly', 'server'), 500);
  assert.equal(agentPriceForPlan(partner, 'yearly', 'android'), 500);
  assert.equal(agentPriceForPlan({ agentPricing: { monthly: 70, server: { monthly: 0 } } }, 'monthly', 'server'), 0);
  assert.equal(agentPriceForPlan({ agentPricing: { yearly: 700 } }, 'yearly', 'android'), 700);
  assert.equal(agentPriceForPlan(partner, 'six_monthly', 'system'), 0);
});

test('checkout quotes each device rate and confirmation records the purchased type using the original order', async t => {
  const crypto = require('node:crypto');
  const Razorpay = require('razorpay');
  const PaymentHistory = require('../src/models/PaymentHistory.model');
  const paymentRouter = require('../src/routes/payment.routes');
  const env = { JWT_SECRET: 'pricing-jwt-test', RAZORPAY_KEY_ID: 'pricing-key-test', RAZORPAY_KEY_SECRET: 'pricing-secret-test' };
  const previous = Object.fromEntries(Object.keys(env).map(key => [key, process.env[key]]));
  Object.assign(process.env, env);
  t.after(() => { for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; } });
  const partner = new Partner({ _id: '600000000000000000000001', tenantId: '600000000000000000000002', name: 'Pricing Test', slug: 'pricing-test', agentPricing: pricing });
  let currentOrder;
  const history = [];
  t.mock.method(Partner, 'findById', async () => partner);
  t.mock.method(Partner.prototype, 'save', async function () { return this; });
  t.mock.method(PaymentHistory, 'create', async record => { history.push(record); return record; });
  t.mock.method(Razorpay.prototype, 'addResources', function () {
    this.orders = {
      create: async order => { currentOrder = { ...order, id: 'order_fixture' }; return currentOrder; },
      fetch: async () => currentOrder,
    };
    this.payments = { fetch: async () => ({ order_id: currentOrder.id, amount: currentOrder.amount, currency: 'INR', status: 'captured' }) };
  });
  const request = (path, body) => new Promise((resolve, reject) => {
    const req = { method: 'POST', url: path, query: {}, body, app: { get: () => null }, headers: {
      authorization: `Bearer ${jwt.sign({ role: 'partner_admin', partnerId: String(partner._id) }, process.env.JWT_SECRET)}`,
    } };
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(body)) }); } };
    paymentRouter.handle(req, res, err => reject(err || new Error('Payment route not found')));
  });
  for (const [agentType, rate] of [['system', 100], ['server', 500], ['android', 50]]) {
    const response = await request('/partner-agent-license/create-order', { agentType, agentQuantity: 2, planType: 'monthly', checkoutFees: false });
    assert.equal(response.status, 200);
    assert.equal(response.body.order.notes.agentType, agentType);
    assert.equal(response.body.pricePerAgent, rate);
    assert.equal(response.body.order.amount, rate * 2 * 100);
  }
  partner.agentPricing.android.monthly = 999; // A later admin edit must not reprice the paid order.
  const confirmation = {
    razorpay_order_id: 'order_fixture', razorpay_payment_id: 'payment_fixture',
    razorpay_signature: crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update('order_fixture|payment_fixture').digest('hex'),
    agentType: 'server', agentQuantity: 999, planType: 'yearly',
  };
  assert.equal((await request('/partner-agent-license/confirm', confirmation)).status, 200);
  assert.equal(partner.agentLicensePurchases[0].agentType, 'android');
  assert.equal(partner.agentLicensePurchases[0].agentQuantity, 2);
  assert.equal(partner.agentLicensePurchases[0].pricePerAgent, 50);
  assert.equal(history[0].phoneCount, 2);
  assert.equal(history[0].serverCount, 0);
  assert.equal(history[0].amountInr, 100);
  assert.equal((await request('/partner-agent-license/confirm', confirmation)).status, 200);
  assert.equal(partner.agentLicensePurchases.length, 1);
  assert.equal((await request('/partner-agent-license/create-order', { agentType: 'unknown', agentQuantity: 1 })).status, 400);
  assert.equal((await request('/partner-agent-license/create-order', { agentType: 'system', agentQuantity: 1, planType: 'six_monthly' })).status, 400);
});

test('invalid rates are rejected instead of overwriting valid prices', () => {
  for (const value of [-1, 'invalid', '', null, true, Infinity]) {
    assert.throws(() => normalizeAgentPricingUpdate({ server: { monthly: value } }));
  }
  assert.deepEqual(normalizeAgentPricingUpdate(pricing), pricing);
  assert.deepEqual(normalizeAgentPricingUpdate({ android: { monthly: '49.99' } }), { android: { monthly: 49.99 } });
});

test('order confirmation retains the server-quoted device, quantity and price after rates change', () => {
  const order = { amount: 120000, currency: 'INR', notes: { partnerId: 'partner-one', agentType: 'server', agentQuantity: '2', planType: 'monthly', pricePerAgent: '500', autoPay: 'false' } };
  const details = licenseOrderDetails(order, 'partner-one');
  assert.equal(details.agentType, 'server');
  assert.equal(details.agentQuantity, 2);
  assert.equal(details.pricePerAgent, 500);
  assert.equal(details.totalInr, 1200);
  assert.throws(() => licenseOrderDetails(order, 'partner-two'));
  assert.throws(() => licenseOrderDetails({ ...order, notes: { ...order.notes, agentQuantity: '1.5' } }, 'partner-one'));
});

function query(value) {
  const q = { then: (resolve, reject) => Promise.resolve(value).then(resolve, reject) };
  for (const method of ['populate', 'select']) q[method] = () => q;
  return q;
}

test('superadmin pricing saves all six device rates and leaves legacy billing records intact', async t => {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'pricing-route-test';
  t.after(() => { if (previousSecret === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previousSecret; });
  const partner = new Partner({ _id: '600000000000000000000001', tenantId: '600000000000000000000002', name: 'Pricing Test', slug: 'pricing-test', agentPricing: { monthly: 75, sixMonthly: 400, yearly: 750 } });
  let saves = 0;
  t.mock.method(Partner, 'findById', () => query(partner));
  t.mock.method(Partner.prototype, 'save', async function () { const err = this.validateSync(); if (err) throw err; saves++; return this; });
  t.mock.method(LoginActivity, 'create', async () => ({}));
  const request = body => new Promise((resolve, reject) => {
    const req = { method: 'PATCH', url: `/partners/${partner._id}`, body, query: {},
      headers: { authorization: `Bearer ${jwt.sign({ id: '600000000000000000000003', role: 'superadmin' }, process.env.JWT_SECRET)}` },
      app: { get: () => null }, get: () => '', connection: {},
    };
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(body)) }); } };
    router.handle(req, res, err => reject(err || new Error('Route not found')));
  });
  const response = await request({ agentPricing: pricing });
  assert.equal(response.status, 200, JSON.stringify(response.body));
  for (const device of ['system', 'server', 'android']) assert.deepEqual(response.body.agentPricing[device], pricing[device]);
  assert.equal(response.body.agentPricing.sixMonthly, 400);
  assert.equal(saves, 1);
  assert.equal((await request({ agentPricing: { server: { monthly: -1 } } })).status, 400);
  assert.equal(saves, 1);
});
