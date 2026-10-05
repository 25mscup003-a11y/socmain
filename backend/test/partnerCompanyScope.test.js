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
    return query([ownCompany, otherCompany].filter(company => !filter.partnerId || company.partnerId === filter.partnerId));
  });
  t.mock.method(Company, 'findOne', filter => {
    calls.companies.push(filter);
    return query([ownCompany, otherCompany].find(company => company._id === filter._id && company.partnerId === filter.partnerId) || null);
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
    for (const path of ['/companies', '/dashboard']) {
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
  assert.deepEqual(calls.companies, [{ partnerId }]);
  for (const filter of calls.related) assert.deepEqual(filter.companyId, { $in: [ownCompany._id] });
});

test('dashboard totals are scoped to the authenticated partner despite query overrides', async t => {
  const calls = setup(t);
  const response = await request({ path: '/dashboard', extra: { partnerId: otherPartnerId } });
  assert.equal(response.status, 200);
  assert.equal(response.body.partial, undefined);
  assert.equal(response.body.companies, 1);
  assert.ok(calls.related.length > 0);
  for (const filter of calls.related) assert.equal(filter.partnerId, partnerId);
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
  assert.deepEqual(calls.companies, [{ partnerId: otherPartnerId }]);
  for (const filter of calls.related) assert.deepEqual(filter.companyId, { $in: [otherCompany._id] });
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
