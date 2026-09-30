const test = require('node:test');
const assert = require('node:assert/strict');
const {
  canJoinCompany,
  canJoinDepartment,
  canJoinPartner,
  canJoinSystem,
  canJoinGlobalFraud,
} = require('../src/security/socketAuthorization');
const { assertUserScope } = require('../src/utils/tenantScope');

test('company users cannot join another company room', () => {
  const user = { kind: 'user', role: 'company_admin', companyId: 'company-a' };
  assert.equal(canJoinCompany(user, { _id: 'company-a' }), true);
  assert.equal(canJoinCompany(user, { _id: 'company-b' }), false);
});

test('partner admins can only join companies owned by their partner', () => {
  const user = { kind: 'user', role: 'partner_admin', partnerId: 'partner-a' };
  assert.equal(canJoinCompany(user, { _id: 'company-a', partnerId: 'partner-a' }), true);
  assert.equal(canJoinCompany(user, { _id: 'company-b', partnerId: 'partner-b' }), false);
});

test('department admins cannot subscribe to sibling departments', () => {
  const user = {
    kind: 'user',
    role: 'department_admin',
    companyId: 'company-a',
    departmentId: 'department-a',
  };
  assert.equal(canJoinDepartment(user, { _id: 'department-a', companyId: 'company-a' }), true);
  assert.equal(canJoinDepartment(user, { _id: 'department-b', companyId: 'company-a' }), false);
  assert.equal(canJoinDepartment(user, { _id: 'department-a', companyId: 'company-b' }), false);
});

test('agents can only join their assigned system and company', () => {
  const agent = {
    kind: 'agent',
    systemId: 'system-a',
    companyId: 'company-a',
    departmentId: 'department-a',
  };
  assert.equal(canJoinSystem(agent, { _id: 'system-a', companyId: 'company-a' }), true);
  assert.equal(canJoinSystem(agent, { _id: 'system-b', companyId: 'company-a' }), false);
  assert.equal(canJoinCompany(agent, { _id: 'company-a' }), true);
  assert.equal(canJoinCompany(agent, { _id: 'company-b' }), false);
});

test('only superadmins can join global privileged streams', () => {
  const superadmin = { kind: 'user', role: 'superadmin' };
  const partner = { kind: 'user', role: 'partner_admin', partnerId: 'partner-a' };
  assert.equal(canJoinGlobalFraud(superadmin), true);
  assert.equal(canJoinGlobalFraud(partner), false);
  assert.equal(canJoinPartner(partner, 'partner-a'), true);
  assert.equal(canJoinPartner(partner, 'partner-b'), false);
});

test('JWT ingestion scope rejects a caller-selected company', () => {
  const user = {
    role: 'company_admin',
    tenantId: 'tenant-a',
    companyId: 'company-a',
  };
  assert.doesNotThrow(() => assertUserScope(user, {
    tenantId: 'tenant-a',
    companyId: 'company-a',
  }));
  assert.throws(() => assertUserScope(user, {
    tenantId: 'tenant-a',
    companyId: 'company-b',
  }), /Invalid company scope/);
});
