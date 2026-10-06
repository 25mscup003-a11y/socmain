const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const express = require('express');
const User = require('../src/models/User.model');
const Partner = require('../src/models/Partner.model');
const Company = require('../src/models/Company.model');
const Quote = require('../src/models/EnterpriseQuote.model');
const Order = require('../src/models/EnterpriseOrder.model');
const Addition = require('../src/models/EnterpriseAdditionOrder.model');
const PaymentHistory = require('../src/models/PaymentHistory.model');
const AddSystem = require('../src/models/AddSystemSubscription.model');
const { authenticate, requireSuperAdmin } = require('../src/middleware/auth.middleware');
const { requireActiveSuperadminSession } = require('../src/middleware/superadminSession.middleware');
const managerRouter = require('../src/routes/enterprise-management.routes');
const paymentRouter = require('../src/routes/enterprise-payment.routes');
const makePayments = require('../src/services/enterprisePayment.service');
const { enterpriseTotals } = require('../src/services/enterpriseQuote.service');

const id = n => Number(n).toString(16).padStart(24, '0');
const C = id(1), P = id(2), ADMIN = id(3), PA = id(4), SA = id(5), OTHER = id(6), DIRECT = id(7);
const same = (a, b) => b == null ? a == null : String(a?._id || a) === String(b?._id || b);
const valueAt = (row, key) => key.split('.').reduce((value, field) => value?.[field], row);
function matches(row, filter) {
  return !!row && Object.entries(filter).every(([key, expected]) => {
    if (key === '$or') return expected.some(branch => matches(row, branch));
    const actual = valueAt(row, key);
    if (expected?.$lte) return actual <= expected.$lte;
    if (expected?.$gt) return actual > expected.$gt;
    if (expected?.$in) return expected.$in.some(value => same(actual, value));
    if (expected && Object.hasOwn(expected, '$ne')) return !same(actual, expected.$ne);
    if (expected && Object.hasOwn(expected, '$exists')) return expected.$exists === (actual !== undefined);
    return same(actual, expected);
  });
}
function update(row, changes) {
  for (const [key, value] of Object.entries(changes.$set || {})) {
    const keys = key.split('.');
    const last = keys.pop();
    const target = keys.reduce((object, field) => object[field] ||= {}, row);
    target[last] = value;
  }
  for (const [key, value] of Object.entries(changes.$inc || {})) row[key] = (row[key] || 0) + value;
  return row;
}
function query(value) {
  return { select() { return this; }, sort() { return this; }, session() { return this; },
    lean: async () => value, then: (resolve, reject) => Promise.resolve(value).then(resolve, reject) };
}

function setup(t) {
  t.mock.method(require('../src/services/enterpriseNotification.service'), 'deliver', async () => {});
  const oldJwt = process.env.JWT_SECRET, oldKey = process.env.RAZORPAY_KEY_SECRET;
  process.env.JWT_SECRET = 'enterprise-jwt-test'; process.env.RAZORPAY_KEY_SECRET = 'enterprise-payment-test';
  t.after(() => {
    if (oldJwt === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = oldJwt;
    if (oldKey === undefined) delete process.env.RAZORPAY_KEY_SECRET; else process.env.RAZORPAY_KEY_SECRET = oldKey;
  });
  const state = {
    companies: [
      { _id: C, name: 'Partner Company', email: 'company@example.test', partnerId: P, tenantId: id(10), plan: {} },
      { _id: OTHER, name: 'Foreign Company', email: 'foreign@example.test', partnerId: id(99), plan: {} },
      { _id: DIRECT, name: 'Direct Company', email: 'direct@example.test', partnerId: null, plan: {} },
    ],
    users: [
      { _id: ADMIN, role: 'company_admin', companyId: C, isActive: true, accountStatus: 'active' },
      { _id: PA, role: 'partner_admin', partnerId: P, name: 'Partner admin', email: 'partner@example.test', isActive: true, accountStatus: 'active' },
      { _id: SA, role: 'superadmin', isActive: true, accountStatus: 'active' },
    ],
    quotes: [], orders: [], histories: [], allocations: [], stockChecks: [], settlements: [], gatewayOrders: new Map(), gatewayPayments: new Map(), batches: [], additionOrders: [],
  };
  t.mock.method(User, 'findById', key => query(state.users.find(row => same(row._id, key))));
  t.mock.method(User, 'findOne', filter => query(state.users.find(row => matches(row, filter))));
  t.mock.method(Partner, 'findById', key => query(same(key, P) ? { _id: P, name: 'Partner', status: 'active' } : null));
  t.mock.method(Company, 'find', filter => query(state.companies.filter(row => matches(row, filter))));
  t.mock.method(Company, 'findOne', filter => query(state.companies.find(row => matches(row, filter))));
  t.mock.method(Company, 'findById', key => query(state.companies.find(row => same(row._id, key))));
  t.mock.method(Company, 'updateOne', async (filter, changes) => { const row = state.companies.find(row => matches(row, filter)); if (row) update(row, changes); return {}; });
  t.mock.method(Quote, 'find', filter => query(state.quotes.filter(row => matches(row, filter))));
  t.mock.method(Quote, 'findOne', filter => query(state.quotes.find(row => matches(row, filter))));
  t.mock.method(Quote, 'create', async row => { const quote = { _id: id(100 + state.quotes.length), ...row }; state.quotes.push(quote); return quote; });
  t.mock.method(Quote, 'findOneAndUpdate', async (filter, changes) => { const row = state.quotes.find(row => matches(row, filter)); return row ? update(row, changes) : null; });
  t.mock.method(Quote, 'updateOne', async (filter, changes, options) => {
    const row = state.quotes.find(row => matches(row, filter)); if (row) update(row, changes);
    return { modifiedCount: row ? 1 : 0 };
  });
  for (const [Model, rows] of [[Order, state.orders], [Addition, state.additionOrders], [AddSystem, state.batches], [PaymentHistory, state.histories]]) {
    t.mock.method(Model, 'findOne', filter => query(rows.find(row => matches(row, filter))));
    t.mock.method(Model, 'findById', key => query(rows.find(row => same(row._id, key))));
    t.mock.method(Model, 'exists', async filter => rows.some(row => matches(row, filter)));
    t.mock.method(Model, 'create', async data => {
      const doc = new Model(data); assert.equal(doc.validateSync(), undefined);
      const row = doc.toObject(); rows.push(row); return row;
    });
    const apply = (filter, changes, options = {}) => {
      let row = rows.find(row => matches(row, filter));
      if (!row && options.upsert) {
        const doc = new Model({ ...filter, ...changes.$setOnInsert }); assert.equal(doc.validateSync(), undefined);
        row = doc.toObject(); rows.push(row);
      }
      if (row) update(row, changes);
      return row;
    };
    t.mock.method(Model, 'findOneAndUpdate', async (...args) => apply(...args));
    t.mock.method(Model, 'updateOne', async (...args) => {
      if (Model === PaymentHistory && state.failHistory) { state.failHistory = false; throw new Error('Temporary write failure'); }
      apply(...args); return {};
    });
  }
  const gateway = {
    orders: {
      create: async data => { const order = { id: `order_${state.gatewayOrders.size + 1}`, ...data }; state.gatewayOrders.set(order.id, order); return order; },
      fetch: async key => state.gatewayOrders.get(key),
    },
    payments: { fetch: async key => state.gatewayPayments.get(key) },
  };
  const service = makePayments({ getGateway: () => gateway,
    ensurePartnerLicenseStock: async (company, count, txn) => { state.stockChecks.push({ company, count, txn }); if (state.noStock) throw Object.assign(new Error('Insufficient license stock'), { status: 409 }); },
    allocateEnterpriseLicenses: async (company, order) => {
      if (state.noStock) throw Object.assign(new Error('Insufficient license stock'), { status: 409 });
      if (!state.allocations.some(a => same(a.orderId, order._id))) state.allocations.push({ company: company._id, orderId: order._id, count: order.systemCount + order.serverCount + order.phoneCount });
    },
    recalculateTotals: async key => {
      const company = state.companies.find(c => same(c._id, key));
      for (const type of ['System', 'Server', 'Phone']) company.plan[type.toLowerCase() + 'Count'] = (company.plan['base' + type + 'Count'] || 0) + state.batches.filter(b => same(b.companyId, key)).reduce((sum, b) => sum + b['added' + type + 'Count'], 0);
      return company;
    },
    createPartnerRouteTransfer: async data => { state.settlements.push(data); return { payoutStatus: 'processing', transferId: 'transfer_1' }; },
  });
  const partner = express.Router(); partner.use(authenticate, managerRouter('partner'));
  const superadmin = express.Router(); superadmin.use(authenticate, requireSuperAdmin, requireActiveSuperadminSession, managerRouter('superadmin'));
  const company = paymentRouter(service);
  const call = (role, path, body, options = {}) => new Promise((resolve, reject) => {
    const actor = role === 'partner' ? PA : role === 'superadmin' ? SA : ADMIN;
    const token = jwt.sign({ id: actor, role: role === 'partner' ? 'partner_admin' : role === 'superadmin' ? 'superadmin' : 'company_admin', partnerId: P, companyId: C, ...options.claims }, process.env.JWT_SECRET);
    const req = { method: options.method || (body ? path.endsWith('/request') || path.includes('order') || path === '/confirm' ? 'POST' : 'PUT' : 'GET'), url: path, body: body || {},
      query: { companyId: OTHER, partnerId: id(99) }, headers: { authorization: `Bearer ${token}`, 'x-company-id': OTHER }, app: { get: () => null } };
    const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, set() { return this; }, json(value) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(value)) }); } };
    (role === 'partner' ? partner : role === 'superadmin' ? superadmin : company).handle(req, res, error => reject(error || new Error('Route not found')));
  });
  const quoteBody = { systemCount: 10, serverCount: 2, phoneCount: 4, billingCycle: 'yearly', notes: 'Custom package', amountInr: 2500, revision: 0 };
  const approve = () => call('partner', `/${C}`, quoteBody);
  const checkout = () => call('company', '/create-order', { quoteId: state.quotes[0]._id, revision: state.quotes[0].revision, amountInr: 1, systemCount: 99999 });
  const capture = order => {
    const paymentId = `pay_${order.id}`;
    state.gatewayPayments.set(paymentId, { id: paymentId, status: 'captured', order_id: order.id, currency: 'INR', amount: order.amount });
    return { razorpay_order_id: order.id, razorpay_payment_id: paymentId,
      razorpay_signature: crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(`${order.id}|${paymentId}`).digest('hex') };
  };
  return { state, service, call, approve, checkout, capture, quoteBody };
}

test('Enterprise management scopes partner companies and lets superadmin price direct companies', async t => {
  const f = setup(t);
  assert.deepEqual((await f.call('partner', '/')).body.map(row => row._id), [C]);
  assert.equal((await f.call('partner', `/${OTHER}`, f.quoteBody)).status, 404);
  assert.equal((await f.call('partner', `/${DIRECT}`, f.quoteBody)).status, 404);
  assert.equal((await f.call('superadmin', '/')).body.length, 3);
  assert.equal((await f.call('superadmin', `/${DIRECT}`, f.quoteBody)).status, 200);
  assert.equal(f.state.companies[2].plan.type, undefined);
  assert.equal((await f.call('partner', '/', undefined, { claims: { impersonatedBy: SA } })).status, 403);
});

test('company requests and quotes use live company identity and reject privilege or scope overrides', async t => {
  const f = setup(t);
  const requested = await f.call('company', '/request', { ...f.quoteBody, companyId: OTHER, partnerId: id(99), status: 'quoted' });
  assert.equal(requested.status, 200); assert.equal(requested.body.quote.status, 'requested');
  assert.equal(requested.body.quote.amountInr, null); assert.equal(String(f.state.quotes[0].companyId), C);
  assert.equal((await f.call('company', '/', undefined, { claims: { role: 'department_admin' } })).status, 403);
  assert.equal((await f.call('company', '/', undefined, { claims: { impersonatedBy: SA } })).status, 403);
  f.state.users[0].isActive = false;
  assert.equal((await f.call('company', '/')).status, 401);
});

test('quotes reject invalid quantities, prices, periods and stale edits', async t => {
  const f = setup(t);
  for (const bad of [{ systemCount: -1 }, { phoneCount: 0.5 }, { systemCount: 'Infinity' }, { systemCount: 0, serverCount: 0, phoneCount: 0 }, { amountInr: 0 }, { amountInr: 'NaN' }, { amountInr: 1.001 }, { billingCycle: 'weekly' }, { notes: 'x'.repeat(2001) }]) {
    assert.equal((await f.call('partner', `/${C}`, { ...f.quoteBody, ...bad })).status, 400);
  }
  assert.equal((await f.approve()).status, 200);
  assert.equal((await f.approve()).status, 409);
  assert.equal((await f.call('partner', `/${C}`, { ...f.quoteBody, amountInr: 3000, revision: 1 })).body.revision, 2);
  assert.deepEqual(f.state.companies[0].plan, {});
  assert.deepEqual(enterpriseTotals(1.03), { baseInr: 1.03, gstInr: 0.19, feeInr: 0.02, totalInr: 1.24, totalPaise: 124 });
});

test('checkout freezes the saved quote and ignores client prices and counts', async t => {
  const f = setup(t); await f.approve();
  const checkout = await f.checkout(); assert.equal(checkout.status, 200);
  assert.equal(checkout.body.order.amount, 300000);
  assert.equal(f.state.orders[0].systemCount, 10);
  assert.equal(f.state.quotes[0].status, 'checkout');
  assert.equal((await f.call('partner', `/${C}`, { ...f.quoteBody, revision: 1 })).status, 409);
  assert.equal((await f.call('company', '/request', { ...f.quoteBody, revision: 1 })).status, 409);
  assert.equal((await f.checkout()).body.order.id, checkout.body.order.id);
  assert.equal(f.state.gatewayOrders.size, 1);
  assert.equal((await f.call('company', '/create-order', { quoteId: f.state.quotes[0]._id, revision: 2 })).status, 409);
});

test('verified Enterprise purchase adds to the existing base and fulfills only once', async t => {
  const f = setup(t);
  Object.assign(f.state.companies[0].plan, { paymentStatus: 'paid', baseSystemCount: 10, baseServerCount: 2, basePhoneCount: 1, amountPaid: 1500, expiresAt: '2027-01-15', billingCycle: 'monthly' });
  await f.approve(); const { body } = await f.checkout();
  const response = f.capture(body.order);
  const paid = await f.call('company', '/confirm', { ...response, systemCount: 90000, amountInr: 1 });
  assert.equal(paid.status, 200);
  assert.equal(paid.body.company.plan.type, undefined);
  assert.equal(paid.body.company.plan.expiresAt, '2027-01-15');
  assert.equal(paid.body.company.plan.billingCycle, 'monthly');
  assert.equal(paid.body.company.plan.baseSystemCount, 10);
  assert.equal(paid.body.company.plan.systemCount, 20);
  assert.equal(paid.body.company.plan.serverCount, 4);
  assert.equal(paid.body.company.plan.phoneCount, 5);
  assert.equal(paid.body.company.plan.amountPaid, 1500);
  assert.equal(f.state.batches[0].amountPaid, 3000);
  assert.equal(f.state.batches[0].billingCycle, 'yearly');
  assert.equal(f.state.allocations[0].count, 16);
  assert.equal(f.state.histories[0].planType, 'enterprise');
  assert.equal(f.state.histories[0].partnerId.toString(), P);
  assert.equal(f.state.quotes[0].status, 'paid');
  await f.service.fulfill(response.razorpay_order_id, response.razorpay_payment_id); // webhook replay
  assert.equal((await f.call('company', '/confirm', response)).status, 200);
  assert.equal(f.state.allocations.length, 1); assert.equal(f.state.histories.length, 1); assert.equal(f.state.settlements.length, 1);
});

test('wrong signatures, uncaptured payments, changed amounts and foreign orders never activate licenses', async t => {
  const f = setup(t); await f.approve(); const { body } = await f.checkout();
  const response = f.capture(body.order);
  assert.equal((await f.call('company', '/confirm', { ...response, razorpay_signature: '0'.repeat(64) })).status, 400);
  const payment = f.state.gatewayPayments.get(response.razorpay_payment_id);
  payment.status = 'authorized'; assert.equal((await f.call('company', '/confirm', response)).status, 409);
  payment.status = 'captured'; payment.amount = 100; assert.equal((await f.call('company', '/confirm', response)).status, 409);
  payment.amount = body.order.amount;
  f.state.users[0].companyId = OTHER;
  assert.equal((await f.call('company', '/confirm', response)).status, 403);
  assert.equal(f.state.allocations.length, 0); assert.equal(f.state.histories.length, 0);
});

test('stock shortages are checked before payment and before activation', async t => {
  const f = setup(t); await f.approve(); f.state.noStock = true;
  assert.equal((await f.checkout()).status, 409); assert.equal(f.state.gatewayOrders.size, 0);
  f.state.noStock = false; const { body } = await f.checkout(); const response = f.capture(body.order);
  f.state.noStock = true;
  assert.equal((await f.call('company', '/confirm', response)).status, 409);
  assert.equal(f.state.orders[0].status, 'created'); assert.equal(f.state.histories.length, 0);
});


test('Enterprise registration uses a separate primary subscription and resumes interrupted fulfillment', async t => {
  const f = setup(t); await f.approve(); const { body } = await f.checkout(); const response = f.capture(body.order);
  f.state.failHistory = true;
  assert.equal((await f.call('company', '/confirm', response)).status, 503);
  assert.equal(f.state.batches.length, 1);
  const result = await f.call('company', '/confirm', response);
  assert.equal(result.status, 200);
  assert.equal(result.body.company.plan.systemCount, 10);
  assert.equal(result.body.company.enterpriseSubscriptionId, String(f.state.batches[0]._id));
  assert.equal(f.state.allocations.length, 1); assert.equal(f.state.batches.length, 1);
  assert.equal(f.state.histories.length, 1); assert.equal(f.state.settlements.length, 1);
});

test('later Enterprise additions keep the plan cycle and full price but start on their purchase date', async t => {
  const f = setup(t); await f.approve(); const { body } = await f.checkout();
  const firstResponse = f.capture(body.order);
  f.state.gatewayPayments.get(firstResponse.razorpay_payment_id).created_at = Math.floor(Date.now() / 1000) - 15 * 86400;
  await f.call('company', '/confirm', firstResponse);
  const company = f.state.companies[0], parent = f.state.batches[0];
  const { getPeriodEnd } = require('../src/utils/billingPeriod');
  const { calculateAddition } = require('../src/services/enterpriseAddition.service');
  const counts = { systemCount: 16, serverCount: 0, phoneCount: 0, billingCycle: 'monthly' };
  const calc = await calculateAddition(company, counts);
  assert.equal(calc.billingCycle, 'yearly'); assert.ok(+calc.periodEnd > +parent.endDate);
  assert.equal(calc.totals.baseInr, 2500);
  const halfway = new Date((+parent.startDate + +parent.endDate) / 2);
  const later = await calculateAddition(company, counts, halfway);
  assert.equal(later.totalInr, 2500);
  assert.equal(+later.periodEnd, +getPeriodEnd('yearly', halfway));
  const payload = { ...counts, purchaseKey: crypto.randomUUID(), expectedPaise: calc.totals.totalPaise };
  const addition = await f.service.createAdditionOrder(company, payload);
  assert.equal((await f.service.createAdditionOrder(company, payload)).order.id, addition.order.id);
  const response = f.capture(addition.order);
  await f.call('company', '/confirm', response);
  await f.call('company', '/confirm', response);
  assert.equal(company.plan.systemCount, 26);
  assert.equal(f.state.batches.length, 2);
  assert.equal(+f.state.batches[1].endDate, +getPeriodEnd('yearly', f.state.batches[1].startDate));
  assert.ok(+f.state.batches[1].endDate > +parent.endDate);
  assert.equal(f.state.batches[1].billingCycle, 'yearly');
  assert.equal(String(f.state.batches[1].parentBatchId), String(parent._id));
  assert.equal(f.state.histories[1].planType, 'enterprise_addition');
  assert.equal(f.state.allocations.length, 2);
  const afterExpiry = await calculateAddition(company, counts, new Date(+parent.endDate + 1));
  assert.equal(afterExpiry.totalInr, 2500);
});


test('monthly Add Systems starts on gateway payment date, not checkout preparation or original renewal date', async t => {
  const f = setup(t); f.quoteBody.billingCycle = 'monthly';
  await f.approve(); const { body } = await f.checkout();
  const first = f.capture(body.order);
  f.state.gatewayPayments.get(first.razorpay_payment_id).created_at = Math.floor(Date.now() / 1000) - 20 * 86400;
  await f.call('company', '/confirm', first);
  const company = f.state.companies[0], parent = f.state.batches[0];
  const { calculateAddition } = require('../src/services/enterpriseAddition.service');
  const { getPeriodEnd } = require('../src/utils/billingPeriod');
  const counts = { systemCount: 8, serverCount: 0, phoneCount: 0, billingCycle: 'yearly' };
  const calc = await calculateAddition(company, counts);
  assert.equal(calc.billingCycle, 'monthly'); assert.equal(calc.totalInr, 1250);
  const { order } = await f.service.createAdditionOrder(company, { ...counts, purchaseKey: crypto.randomUUID(), expectedPaise: calc.totals.totalPaise });
  const response = f.capture(order);
  const paymentTime = Math.floor(Date.now() / 1000) - 86400;
  f.state.gatewayPayments.get(response.razorpay_payment_id).created_at = paymentTime;
  await f.call('company', '/confirm', response);
  const added = f.state.batches[1];
  assert.equal(+added.startDate, paymentTime * 1000);
  assert.equal(+added.endDate, +getPeriodEnd('monthly', added.startDate));
  assert.ok(+added.endDate > +parent.endDate);
  assert.equal(company.plan.systemCount, 18);
  assert.equal(added.amountPaid, 1500);
  await f.service.fulfill(order.id, response.razorpay_payment_id);
  assert.equal(f.state.batches.length, 2); assert.equal(+added.startDate, paymentTime * 1000);
});
