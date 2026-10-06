const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const System = require('../src/models/System.model');
const Agent = require('../src/models/Agent.model');
const PaymentHistory = require('../src/models/PaymentHistory.model');
const User = require('../src/models/User.model');
const Referral = require('../src/models/Referral.model');
const router = require('../src/routes/partner.routes');

const partnerId = '600000000000000000000001';
const otherPartnerId = '600000000000000000000002';
const ownCompany = { _id: '600000000000000000000003', partnerId, name: 'Own Company', status: 'active', plan: {} };
const otherCompany = { _id: '600000000000000000000004', partnerId: otherPartnerId, name: 'Other Company', status: 'active', plan: {} };

function query(value) {
  const result = { then: (resolve, reject) => Promise.resolve(value).then(resolve, reject), lean: async () => value };
  for (const method of ['select', 'sort', 'limit', 'populate']) result[method] = () => result;
  return result;
}

function setup(t) {
  const previous = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'partner-company-scope-test-secret';
  t.after(() => { if (previous === undefined) delete process.env.JWT_SECRET; else process.env.JWT_SECRET = previous; });
  const calls = { companies: [], related: [], partner: [] };
  t.mock.method(Partner, 'findById', id => {
    calls.partner.push(id);
    return query({ _id: id, status: 'active', plan: { paymentStatus: 'paid', isActive: true } });
  });
  t.mock.method(Company, 'find', filter => {
    calls.companies.push(filter);
    return query([ownCompany, otherCompany].filter(company => !filter.partnerId || company.partnerId === String(filter.partnerId)));
  });
  t.mock.method(Company, 'findOne', filter => {
    calls.companies.push(filter);
    return query([ownCompany, otherCompany].find(company => company._id === filter._id && company.partnerId === String(filter.partnerId)) || null);
  });
  for (const model of [Company, User, Referral, System]) {
    t.mock.method(model, 'countDocuments', filter => { calls.related.push(filter); return Promise.resolve(1); });
  }
  for (const model of [Company, System, Agent, PaymentHistory]) {
    t.mock.method(model, 'aggregate', pipeline => { calls.related.push(pipeline[0].$match); return Promise.resolve([]); });
  }
  t.mock.method(PaymentHistory, 'find', filter => { calls.related.push(filter); return query([]); });
  t.mock.method(PaymentHistory, 'findOne', filter => { calls.related.push(filter); return query(null); });
  return calls;
}

function request({ path = '/companies', scope = partnerId, extra = {} } = {}) {
  const token = jwt.sign({ role: 'partner_admin', partnerId: scope }, process.env.JWT_SECRET);
  return new Promise((resolve, reject) => {
    const req = { method: 'GET', url: path, query: extra, body: {}, headers: { authorization: `Bearer ${token}`, 'x-company-id': otherCompany._id } };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(body)) }); },
    };
    router.handle(req, res, error => reject(error || new Error('Partner route not found')));
  });
}

test('missing or invalid partner scope is rejected before any company or partner query', async t => {
  const calls = setup(t);
  for (const scope of [null, '', 'invalid', { $ne: null }]) {
    for (const path of ['/companies', '/dashboard', '/revenue/history']) {
      assert.equal((await request({ scope, path })).status, 403);
    }
  }
  assert.deepEqual(calls, { companies: [], related: [], partner: [] });
});

test('company summary only includes companies belonging to the authenticated partner', async t => {
  const calls = setup(t);
  const response = await request({ extra: { partnerId: otherPartnerId, companyId: otherCompany._id } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(company => company._id), [ownCompany._id]);
  assert.deepEqual(calls.companies.map(filter => ({ partnerId: String(filter.partnerId) })), [{ partnerId }]);
  for (const filter of calls.related) assert.deepEqual(filter.companyId, { $in: [ownCompany._id] });
});

test('dashboard totals are scoped to the authenticated partner despite query overrides', async t => {
  const calls = setup(t);
  const response = await request({ path: '/dashboard', extra: { partnerId: otherPartnerId } });
  assert.equal(response.status, 200);
  assert.equal(response.body.partial, undefined);
  assert.equal(response.body.companies, 1);
  assert.ok(calls.related.length > 0);
  for (const filter of calls.related) {
    if (filter.partnerId) assert.equal(String(filter.partnerId), partnerId);
    else assert.deepEqual(filter.companyId, { $in: [ownCompany._id] });
  }
});

test('a company belonging to another partner cannot be opened from a dashboard link', async t => {
  setup(t);
  assert.equal((await request({ path: `/companies/${otherCompany._id}` })).status, 404);
  const ownResponse = await request({ path: `/companies/${ownCompany._id}` });
  assert.equal(ownResponse.status, 200);
  assert.equal(ownResponse.body._id, ownCompany._id);
});

test('partner two receives only its own company records, even when asking for partner one', async t => {
  const calls = setup(t);
  const response = await request({ scope: otherPartnerId, extra: { partnerId } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(company => company._id), [otherCompany._id]);
  assert.deepEqual(calls.companies.map(filter => ({ partnerId: String(filter.partnerId) })), [{ partnerId: otherPartnerId }]);
  for (const filter of calls.related) assert.deepEqual(filter.companyId, { $in: [otherCompany._id] });
});

for (const [scope, company] of [[partnerId, ownCompany], [otherPartnerId, otherCompany]]) {
  test(`revenue history only contains current company payments for partner ${scope}`, async t => {
    setup(t);
    const payments = [
      { _id: 'own-payment', partnerId, companyId: ownCompany, amountInr: 1000, status: 'captured', source: 'checkout', planType: 'custom' },
      { _id: 'other-payment', partnerId: otherPartnerId, companyId: otherCompany, amountInr: 2000, status: 'captured', source: 'renewal', planType: 'custom' },
      { _id: 'foreign-company', partnerId: scope, companyId: scope === partnerId ? otherCompany : ownCompany, amountInr: 3000 },
      { _id: 'deleted-company', partnerId: scope, companyId: { _id: '600000000000000000000099' }, amountInr: 4000 },
      { _id: 'platform', partnerId: scope, companyId: company, source: 'partner_checkout', amountInr: 5000 },
      { _id: 'partner-licenses', partnerId: scope, companyId: company, source: 'partner_agent_license', amountInr: 6000 },
      { _id: 'enterprise-plan', partnerId: scope, companyId: company, planType: 'partner_enterprise', amountInr: 7000 },
      { _id: 'no-company', partnerId: scope, companyId: null, amountInr: 8000 },
    ];
    const same = (a, b) => String(a?._id || a) === String(b?._id || b);
    t.mock.method(PaymentHistory, 'find', filter => {
      assert.equal(String(filter.partnerId), scope);
      assert.deepEqual(filter.companyId, { $in: [company._id] });
      return query(payments.filter(payment => Object.entries(filter).every(([key, condition]) => {
        if (condition?.$in) return condition.$in.some(value => same(payment[key], value));
        if (condition?.$nin) return !condition.$nin.some(value => same(payment[key], value));
        if (condition && Object.hasOwn(condition, '$ne')) return !same(payment[key], condition.$ne);
        return same(payment[key], condition);
      })));
    });
    const response = await request({ path: '/revenue/history', scope, extra: { partnerId: scope === partnerId ? otherPartnerId : partnerId, companyId: otherCompany._id } });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.map(payment => payment.id), [scope === partnerId ? 'own-payment' : 'other-payment']);
    assert.equal(response.body[0].companyId, company._id);
    assert.equal(response.body[0].company, company.name);
  });
}

test('a partner without companies has no revenue history or company totals', async t => {
  const calls = setup(t);
  t.mock.method(Company, 'find', () => query([]));
  const history = await request({ path: '/revenue/history' });
  assert.equal(history.status, 200);
  assert.deepEqual(history.body, []);
  assert.deepEqual(calls.related, []);
  const dashboard = await request({ path: '/dashboard' });
  assert.equal(dashboard.status, 200);
  assert.equal(dashboard.body.companies, 0);
  assert.equal(dashboard.body.paidRevenue, 0);
  assert.equal(dashboard.body.pendingRevenue, 0);
});

test('revenue history query errors are not returned as an empty successful history', async t => {
  setup(t);
  t.mock.method(PaymentHistory, 'find', () => { throw new Error('Database unavailable'); });
  const response = await request({ path: '/revenue/history' });
  assert.equal(response.status, 500);
  assert.ok(response.body.message);
});

for (const status of ['created', 'failed']) {
  test(`${status} payments are not included in collected company revenue`, async t => {
    setup(t);
    t.mock.method(PaymentHistory, 'find', () => query([{ companyId: ownCompany._id, status, amountInr: 5000 }]));
    t.mock.method(PaymentHistory, 'aggregate', async () => [{ _id: ownCompany._id, paymentCount: 0, totalCollection: 0, pendingCollection: status === 'created' ? 5000 : 0 }]);
    const response = await request();
    assert.equal(response.status, 200);
    assert.equal(response.body[0].revenue, 0);
    assert.equal(response.body[0].pendingRevenue, status === 'created' ? 5000 : 0);
  });
}

test('captured payment totals take precedence over the latest pending payment', async t => {
  setup(t);
  t.mock.method(PaymentHistory, 'find', () => query([{ companyId: ownCompany._id, status: 'created', amountInr: 5000 }]));
  t.mock.method(PaymentHistory, 'aggregate', async () => [{ _id: ownCompany._id, paymentCount: 2, totalCollection: 12000, pendingCollection: 5000 }]);
  const response = await request();
  assert.equal(response.body[0].revenue, 12000);
  assert.equal(response.body[0].pendingRevenue, 5000);
});


test('purchased capacity never inflates installed or online agent totals', async t => {
  setup(t);
  t.mock.method(Company, 'find', () => query([{ ...ownCompany, agentLicenseAllocation: 100, plan: { systemCount: 80 } }]));
  t.mock.method(System, 'aggregate', async () => [{ _id: ownCompany._id, totalAgents: 3, active: 1 }]);
  const companies = await request();
  const dashboard = await request({ path: '/dashboard' });
  assert.equal(companies.body[0].totalAgents, 3);
  assert.equal(companies.body[0].inactiveAgents, 2);
  assert.equal(dashboard.body.totalAgents, 3);
  assert.equal(dashboard.body.activeAgents, 1);
  assert.equal(dashboard.body.offlineAgents, 2);
});

test('company revenue and dashboard revenue use the same captured payments and zero commission', async t => {
  setup(t);
  t.mock.method(PaymentHistory, 'aggregate', async pipeline => {
    const match = pipeline[0].$match;
    assert.equal(match.partnerId.constructor.name, 'ObjectId');
    assert.deepEqual(match.source.$nin, ['partner_checkout', 'partner_agent_license']);
    return [{ _id: ownCompany._id, totalCollection: 12000, pendingCollection: 5000, paymentCount: 2, platformCommission: 0, partnerPayout: 0 }];
  });
  const dashboard = await request({ path: '/dashboard' });
  assert.equal(dashboard.body.totalRevenue, 12000);
  assert.equal(dashboard.body.totalDue, 5000);
  assert.equal(dashboard.body.settlement.platformCommission, 0);
  assert.equal(dashboard.body.settlement.partnerPayout, 0);
});

test('dashboard failures are reported as unavailable instead of successful paid accounts with zero totals', async t => {
  setup(t);
  t.mock.method(System, 'aggregate', async () => { throw new Error('Database unavailable'); });
  const response = await request({ path: '/dashboard' });
  assert.equal(response.status, 503);
  assert.equal(response.body.partner, undefined);
  assert.equal(response.body.companies, undefined);
});

test('company and subscription totals are not truncated at fifty records and exclude expired plans', async t => {
  setup(t);
  const companies = Array.from({ length: 65 }, (_, i) => ({ ...ownCompany, _id: i.toString(16).padStart(24, '0'), plan: { isActive: true, expiresAt: i ? '2099-01-01' : '2020-01-01' } }));
  t.mock.method(Company, 'find', () => query(companies));
  const response = await request({ path: '/dashboard' });
  assert.equal(response.body.companies, 65);
  assert.equal(response.body.activePlans, 64);
  assert.equal(response.body.expiringPlans, 0);
});
