const test = require('node:test');
const assert = require('node:assert/strict');
const Company = require('../src/models/Company.model');
const User = require('../src/models/User.model');
const Tenant = require('../src/models/Tenant.model');
const Quote = require('../src/models/EnterpriseQuote.model');
const { createEnterpriseNotifications } = require('../src/services/enterpriseNotification.service');
const { enterpriseLoginDestination } = require('../src/services/enterpriseLogin.service');

const id = n => n.toString(16).padStart(24, '0');
const field = (row, key) => key.split('.').reduce((obj, part) => obj?.[part], row);
function matches(row, filter) {
  return !!row && Object.entries(filter).every(([key, expected]) => {
    if (key === '$or') return expected.some(branch => matches(row, branch));
    const value = field(row, key);
    if (expected?.$in) return expected.$in.includes(value);
    if (expected?.$lte) return value != null && +value <= +expected.$lte;
    if (expected && Object.hasOwn(expected, '$exists')) return (value !== undefined) === expected.$exists;
    return String(value ?? '') === String(expected ?? '');
  });
}
function update(row, changes) {
  for (const [op, values] of Object.entries(changes)) for (const [key, value] of Object.entries(values)) {
    const parts = key.split('.'), last = parts.pop();
    const target = parts.reduce((obj, part) => obj[part] ||= {}, row);
    if (op === '$set') target[last] = value;
    if (op === '$inc') target[last] = (target[last] || 0) + value;
    if (op === '$addToSet' && !(target[last] ||= []).includes(value)) target[last].push(value);
  }
  return row;
}
const query = value => ({ select() { return this; }, sort() { return this; }, limit() { return this; }, lean: async () => value,
  then: (resolve, reject) => Promise.resolve(value).then(resolve, reject) });

function setup(t, { partner = false, kind = 'request' } = {}) {
  const company = { _id: id(1), name: 'Example <Company>', email: 'company@example.test', partnerId: partner ? id(2) : null };
  const user = (n, role, scope = {}) => ({ _id: id(n), name: role, email: `${role}${n}@example.test`, role, isActive: true, accountStatus: 'active', ...scope });
  const users = [user(10, 'superadmin'), user(11, 'superadmin', { isActive: false }),
    user(12, 'partner_admin', { partnerId: id(2) }), user(13, 'partner_admin', { partnerId: id(3) }),
    user(14, 'company_admin', { companyId: id(1) }), user(15, 'company_admin', { companyId: id(4) }),
    user(16, 'analyst', { companyId: id(1) }), user(17, 'company_admin', { companyId: id(1), accountStatus: 'suspended' })];
  const quote = { _id: id(5), companyId: company._id, partnerId: company.partnerId, revision: 1,
    status: kind === 'request' ? 'requested' : 'quoted', systemCount: 10, serverCount: 2, phoneCount: 1, billingCycle: 'monthly', amountInr: 1200,
    notes: '<img src=x onerror=alert(1)>', notification: { kind, status: 'pending', attempts: 0, sentTo: [], nextAttemptAt: new Date(0) } };
  const sent = [];
  t.mock.method(Company, 'findById', key => query(String(key) === company._id ? company : null));
  t.mock.method(User, 'find', filter => query(users.filter(user => matches(user, filter))));
  t.mock.method(Tenant, 'findById', () => query(null));
  t.mock.method(Quote, 'findOneAndUpdate', async (filter, changes) => matches(quote, filter) ? update(quote, changes) : null);
  t.mock.method(Quote, 'updateOne', async (filter, changes) => { if (matches(quote, filter)) update(quote, changes); return {}; });
  t.mock.method(Quote, 'exists', async filter => matches(quote, filter));
  t.mock.method(Quote, 'find', filter => query(matches(quote, filter) ? [quote] : []));
  let failRecipient;
  const service = createEnterpriseNotifications({ sendMail: async message => {
    if (message.to === failRecipient) throw new Error('SMTP unavailable');
    sent.push(message); return { accepted: [message.to], rejected: [] };
  } });
  return { company, users, quote, sent, service, fail: email => { failRecipient = email; } };
}

test('direct company requests email active Superadmin, with company link and escaped content', async t => {
  const f = setup(t);
  await f.service.deliver(f.quote._id, 1);
  assert.deepEqual(f.sent.map(m => m.to), ['superadmin10@example.test']);
  assert.match(f.sent[0].text, /Set up Enterprise for this company/);
  assert.match(f.sent[0].text, /superadmin\/payment-management\?tab=enterprise&companyId=/);
  assert.match(f.sent[0].html, /Example &lt;Company&gt;/);
  assert.doesNotMatch(f.sent[0].html, /<img/);
  assert.equal(f.quote.notification.status, 'sent');
});

test('partner company requests email only admins of the owning partner', async t => {
  const f = setup(t, { partner: true });
  await Promise.all([f.service.deliver(f.quote._id, 1), f.service.deliver(f.quote._id, 1)]);
  assert.deepEqual(f.sent.map(m => m.to), ['partner_admin12@example.test']);
  assert.match(f.sent[0].text, /partner\/payment-control\?tab=enterprise&companyId=/);
  await f.service.deliver(f.quote._id, 1);
  assert.equal(f.sent.length, 1);
});

test('Enterprise setup emails only active company admins with a payment link', async t => {
  const f = setup(t, { partner: true, kind: 'ready' });
  await f.service.deliver(f.quote._id, 1);
  assert.deepEqual(f.sent.map(m => m.to), ['company_admin14@example.test']);
  assert.match(f.sent[0].text, /Enterprise setup is complete/);
  assert.match(f.sent[0].text, /company-admin\/payments\?tab=enterprise/);
  assert.match(f.sent[0].html, /Complete your payment/);
});

test('failed mail retries after restart without resending to successful recipients', async t => {
  const f = setup(t);
  f.users.push({ ...f.users[0], _id: id(20), email: 'second@example.test' });
  f.fail('second@example.test');
  await f.service.deliver(f.quote._id, 1);
  assert.equal(f.quote.notification.status, 'pending');
  assert.deepEqual(f.quote.notification.sentTo, ['superadmin10@example.test']);
  assert.ok(f.quote.notification.nextAttemptAt > new Date());
  f.fail(null); f.quote.notification.nextAttemptAt = new Date(0);
  await f.service.runPending();
  assert.deepEqual(f.sent.map(m => m.to), ['superadmin10@example.test', 'second@example.test']);
  assert.equal(f.quote.notification.status, 'sent');
});

test('superseded revisions and changed ownership never send stale notifications', async t => {
  const f = setup(t, { partner: true });
  await f.service.deliver(f.quote._id, 0);
  assert.equal(f.sent.length, 0);
  f.company.partnerId = id(99);
  await f.service.deliver(f.quote._id, 1);
  assert.equal(f.sent.length, 0);
  assert.equal(f.quote.notification.status, 'pending');
});

test('pending Enterprise payment controls company login destination until paid', async t => {
  const f = setup(t, { kind: 'ready' });
  const companyAdmin = f.users[4], base = 'https://tenant.example.test';
  assert.equal(await enterpriseLoginDestination(companyAdmin, base), base + '/company-admin/payments?tab=enterprise');
  f.quote.status = 'checkout';
  assert.equal(await enterpriseLoginDestination(companyAdmin, base), base + '/company-admin/payments?tab=enterprise');
  for (const status of ['requested', 'paid']) {
    f.quote.status = status;
    assert.equal(await enterpriseLoginDestination(companyAdmin, base), base);
  }
  f.quote.status = 'quoted';
  assert.equal(await enterpriseLoginDestination(f.users[5], base), base);
  assert.equal(await enterpriseLoginDestination(f.users[6], base), base);
});
