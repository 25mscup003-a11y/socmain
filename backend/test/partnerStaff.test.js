const test = require('node:test');
const assert = require('node:assert/strict');
const jwt = require('jsonwebtoken');
const Company = require('../src/models/Company.model');
const Partner = require('../src/models/Partner.model');
const User = require('../src/models/User.model');
const SocCompanyAssignment = require('../src/models/SocCompanyAssignment.model');
const router = require('../src/routes/partner.routes');

const partnerId = '600000000000000000000001';
const otherPartnerId = '600000000000000000000002';
const companyId = '600000000000000000000003';
const otherCompanyId = '600000000000000000000004';
const roles = ['soc_manager', 'analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const equals = (actual, expected) => expected == null ? actual == null : String(actual) === String(expected);

function matches(record, filter) {
  return Object.entries(filter).every(([key, condition]) => {
    if (key === '$or') return condition.some(branch => matches(record, branch));
    if (condition && Object.hasOwn(condition, '$in')) return condition.$in.some(value => equals(record[key], value));
    if (condition && Object.hasOwn(condition, '$ne')) return !equals(record[key], condition.$ne);
    return equals(record[key], condition);
  });
}

function query(rows) {
  return {
    select() { return this; },
    sort() { return this; },
    lean: async () => rows,
    then: (resolve, reject) => Promise.resolve(rows).then(resolve, reject),
    distinct: async field => [...new Set(rows.map(row => row[field]))],
  };
}

function setup(t, { companies, staff, assignments } = {}) {
  const previousSecret = process.env.JWT_SECRET;
  process.env.JWT_SECRET = 'partner-staff-test-secret';
  t.after(() => {
    if (previousSecret === undefined) delete process.env.JWT_SECRET;
    else process.env.JWT_SECRET = previousSecret;
  });
  const companyRows = companies ?? [{ _id: companyId, partnerId }, { _id: otherCompanyId, partnerId: otherPartnerId }];
  const staffRows = staff ?? [
    ...roles.map((role, index) => ({ _id: `own-${role}`, role, partnerId, name: role, email: `${role}@example.test`, isActive: index !== 2, accountStatus: index === 2 ? 'disabled' : 'active' })),
    { _id: 'legacy-company', role: 'analyst', companyId, partnerId: null },
    { _id: 'assigned', role: 'l2_analyst', partnerId: null },
    { _id: 'inactive-assignment', role: 'l2_analyst', partnerId: null },
    { _id: 'orphan', role: 'analyst', partnerId: null },
    { _id: 'foreign', role: 'soc_manager', partnerId: otherPartnerId, companyId: otherCompanyId },
    { _id: 'foreign-assigned', role: 'l1_analyst', partnerId: otherPartnerId },
    { _id: 'superadmin-managed', role: 'soc_manager', partnerId, superadminManaged: true },
    ...['partner_admin', 'company_admin', 'department_admin', 'superadmin'].map(role => ({ _id: role, role, partnerId })),
  ];
  const assignmentRows = assignments ?? [
    { userId: 'assigned', companyId, active: true },
    { userId: 'foreign-assigned', companyId, active: true },
    { userId: 'inactive-assignment', companyId, active: false },
    { userId: 'foreign', companyId: otherCompanyId, active: true },
  ];
  const calls = { companies: [], staff: [], assignments: [], selections: [] };
  t.mock.method(Partner, 'findById', id => query({ _id: id, status: 'active', plan: { paymentStatus: 'paid', isActive: true } }));
  t.mock.method(Company, 'find', filter => {
    calls.companies.push(filter);
    return query(companyRows.filter(row => matches(row, filter)));
  });
  t.mock.method(SocCompanyAssignment, 'find', filter => {
    calls.assignments.push(filter);
    return query(assignmentRows.filter(row => matches(row, filter)));
  });
  t.mock.method(User, 'find', filter => {
    calls.staff.push(filter);
    const result = query(staffRows.filter(row => matches(row, filter)));
    result.select = selection => { calls.selections.push(selection); return result; };
    return result;
  });
  return calls;
}

function request({ scope = partnerId, role = 'partner_admin', extra = {} } = {}) {
  const token = jwt.sign({ role, partnerId: scope }, process.env.JWT_SECRET);
  return new Promise((resolve, reject) => {
    const req = { method: 'GET', url: '/staff', query: extra, body: {}, headers: { authorization: `Bearer ${token}`, 'x-company-id': otherCompanyId } };
    const res = {
      statusCode: 200,
      status(code) { this.statusCode = code; return this; },
      json(body) { resolve({ status: this.statusCode, body }); },
    };
    router.handle(req, res, error => reject(error || new Error('Staff route not found')));
  });
}

test('partner staff includes all analyst tiers, legacy analysts, and managers while excluding admins and other partners', async t => {
  const calls = setup(t);
  const response = await request({ extra: { partnerId: otherPartnerId, companyId: otherCompanyId, role: 'superadmin' } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(user => user._id), [...roles.map(role => `own-${role}`), 'legacy-company', 'assigned']);
  assert.equal(response.body.find(user => user._id === 'own-l1_analyst').isActive, false);
  assert.deepEqual(calls.companies.map(filter => String(filter.partnerId)), [partnerId]);
  assert.deepEqual(calls.assignments, [{ companyId: { $in: [companyId] }, active: true }]);
  assert.deepEqual(calls.selections, ['name email role isActive accountStatus']);
});

test('another partner only receives its own staff despite scope overrides', async t => {
  setup(t);
  const response = await request({ scope: otherPartnerId, extra: { partnerId, companyId } });
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(user => user._id), ['foreign', 'foreign-assigned']);
});

test('partner with no companies can see its directly linked staff but no unassigned or foreign accounts', async t => {
  const calls = setup(t, { companies: [] });
  const response = await request();
  assert.equal(response.status, 200);
  assert.deepEqual(response.body.map(user => user._id), roles.map(role => `own-${role}`));
  assert.deepEqual(calls.assignments, []);
});

test('missing or invalid partner scope and non-partner roles cannot list partner staff', async t => {
  const calls = setup(t);
  for (const scope of [null, '', 'invalid', { $ne: null }]) {
    assert.equal((await request({ scope })).status, 403);
  }
  for (const role of ['company_admin', 'soc_manager', 'analyst', 'superadmin']) {
    assert.equal((await request({ role })).status, 403);
  }
  assert.deepEqual(calls.staff, []);
  assert.deepEqual(calls.companies, []);
});

test('empty staff is a successful empty list, while database failures are unavailable', async t => {
  setup(t, { staff: [] });
  const empty = await request();
  assert.equal(empty.status, 200);
  assert.deepEqual(empty.body, []);
  t.mock.method(User, 'find', () => { throw new Error('Database unavailable'); });
  const failure = await request();
  assert.equal(failure.status, 503);
  assert.match(failure.body.message, /could not be loaded/);
});
