const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Company = require('../src/models/Company.model');
const Quote = require('../src/models/EnterpriseQuote.model');
const { authenticate } = require('../src/middleware/auth.middleware');
const { enterpriseLoginDestination } = require('../src/services/enterpriseLogin.service');

const companyId = '600000000000000000000001';
const user = { role: 'company_admin', companyId };

function setup(t, status = 'pending_payment') {
  t.mock.method(Company, 'findById', id => {
    assert.equal(id, companyId);
    return { select: () => ({ lean: async () => ({ status }) }) };
  });
  const oldSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'registration-payment-test';
  t.after(() => {
    if (oldSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = oldSecret;
  });
}

async function request(path, account = user, extra = {}) {
  const req = { headers: { authorization: `Bearer ${jwt.sign(account, process.env.JWT_SECRET)}` },
    query: {}, originalUrl: path, ...extra };
  const res = { statusCode: 200, status(code) { this.statusCode = code; return this; }, json(body) { this.body = body; return this; } };
  let allowed = false;
  await authenticate(req, res, () => { allowed = true; });
  return { allowed, status: res.statusCode, body: res.body };
}

test('unpaid first-time company cannot bypass registration with an existing JWT or another company ID', async t => {
  setup(t);
  for (const path of ['/api/company/overview', '/api/dashboard', '/api/system', '/api/users']) {
    const result = await request(path, user, { query: { companyId: '600000000000000000000002' } });
    assert.equal(result.allowed, false);
    assert.equal(result.status, 402);
    assert.equal(result.body.code, 'REGISTRATION_PAYMENT_REQUIRED');
    assert.equal(result.body.redirectUrl, '/register');
  }
});

test('email/auth session, pricing and both payment flows remain available before payment', async t => {
  setup(t);
  for (const path of ['/api/auth/me', '/api/auth/logout', '/api/auth/reset-temp-password', '/api/pricing',
    '/api/payment/status', '/api/payment/calculate', '/api/payment/create-order', '/api/payment/confirm',
    '/api/payment/enterprise/request', '/api/payment/enterprise/confirm']) {
    assert.equal((await request(path)).allowed, true, path);
  }
  assert.equal((await request('/api/payment-bypass')).allowed, false);
});

test('payment activation unlocks the same session, and renewal does not repeat registration', async t => {
  setup(t);
  let status = 'pending_payment';
  t.mock.method(Company, 'findById', () => ({ select: () => ({ lean: async () => ({ status, plan: { isActive: false, expiresAt: new Date(0) } }) }) }));
  assert.equal((await request('/api/company/overview')).allowed, false);
  status = 'active';
  assert.equal((await request('/api/company/overview')).allowed, true);
});

test('other roles and trial/suspended accounts retain their existing authorization flow', async t => {
  setup(t);
  for (const role of ['partner_admin', 'superadmin', 'department_admin', 'analyst']) {
    assert.equal((await request('/api/company/overview', { ...user, role })).allowed, true);
  }
  for (const status of ['trial', 'suspended']) {
    t.mock.method(Company, 'findById', () => ({ select: () => ({ lean: async () => ({ status }) }) }));
    assert.equal((await request('/api/company/overview')).allowed, true);
  }
});

test('payment status lookup failures neither grant dashboard access nor expire the login', async t => {
  setup(t);
  t.mock.method(Company, 'findById', () => { throw new Error('Database unavailable'); });
  const result = await request('/api/company/overview');
  assert.equal(result.allowed, false);
  assert.equal(result.status, 503);
});

test('login returns to initial plan selection until paid, including Enterprise quotes', async t => {
  let quoted = false;
  t.mock.method(Quote, 'exists', async () => quoted);
  const base = 'https://company.example.test';
  assert.equal(await enterpriseLoginDestination(user, base, { status: 'pending_payment' }), `${base}/register`);
  quoted = true;
  assert.equal(await enterpriseLoginDestination(user, base, { status: 'pending_payment' }), `${base}/register?plan=enterprise`);
  quoted = false;
  assert.equal(await enterpriseLoginDestination(user, base, { status: 'active' }), base);
});
