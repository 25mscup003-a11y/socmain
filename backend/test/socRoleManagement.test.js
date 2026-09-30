const test = require('node:test');
const assert = require('node:assert/strict');

const User = require('../src/models/User.model');
const SocInvitation = require('../src/models/SocInvitation.model');
const SocCompanyAssignment = require('../src/models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../src/models/SocDepartmentAssignment.model');
const SocEscalation = require('../src/models/SocEscalation.model');
const {
  SOC_ROLES,
  ANALYST_ROLES,
  socStaffVisibilityFilter,
  socInvitationVisibilityFilter,
  assertSocStaffOrigin,
  assertSocStaffManagementScope,
} = require('../src/services/socAccess.service');

test('SOC role hierarchy is additive and preserves the legacy analyst role', () => {
  const roles = User.schema.path('role').enumValues;
  assert.ok(roles.includes('analyst'));
  for (const role of ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst']) {
    assert.ok(roles.includes(role), `${role} must be a valid user role`);
  }
  assert.deepEqual(SOC_ROLES, ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst']);
  assert.deepEqual(ANALYST_ROLES, ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst']);
});

test('SOC invitations store only a hidden token hash and enforce lifecycle states', () => {
  assert.equal(SocInvitation.schema.path('tokenHash').options.select, false);
  const states = SocInvitation.schema.path('status').options.enum;
  assert.ok(states.includes('revoked'));
  assert.ok(states.includes('accepted'));
  assert.ok(SocInvitation.schema.path('role').options.enum.includes('soc_manager'));
  assert.equal(SocInvitation.schema.path('superadminManaged').options.default, false);
});

test('Partner Admin cannot manage Super Admin SOC staff or another partner staff', () => {
  const partnerAdmin = { id: 'partner-admin-a', role: 'partner_admin', partnerId: 'partner-a' };
  assert.throws(
    () => assertSocStaffOrigin(partnerAdmin, {
      role: 'soc_manager', partnerId: 'partner-a', superadminManaged: true,
    }),
    error => error.status === 403 && /different administration scope/i.test(error.message),
  );
  assert.throws(
    () => assertSocStaffOrigin(partnerAdmin, {
      role: 'soc_manager', partnerId: 'partner-b', superadminManaged: false,
    }),
    error => error.status === 403 && /another partner/i.test(error.message),
  );
  assert.doesNotThrow(() => assertSocStaffOrigin(partnerAdmin, {
    role: 'soc_manager', partnerId: 'partner-a', superadminManaged: false,
  }));
});

test('SOC Manager can manage only same-origin unclaimed or own analysts', () => {
  const partnerManager = {
    id: 'manager-a', role: 'soc_manager', partnerId: 'partner-a', superadminManaged: false,
  };
  assert.throws(
    () => assertSocStaffOrigin(partnerManager, {
      role: 'l1_analyst', partnerId: 'partner-a', superadminManaged: true,
    }),
    error => error.status === 403,
  );
  assert.throws(
    () => assertSocStaffOrigin(partnerManager, {
      role: 'l1_analyst', partnerId: 'partner-a', superadminManaged: false, socManagerId: 'manager-b',
    }),
    error => error.status === 403 && /another SOC Manager/i.test(error.message),
  );
  assert.doesNotThrow(() => assertSocStaffOrigin(partnerManager, {
    role: 'l1_analyst', partnerId: 'partner-a', superadminManaged: false, socManagerId: null,
  }));
});

test('SOC visibility filters keep Super Admin pool separate from partner staff', () => {
  assert.deepEqual(socStaffVisibilityFilter({ role: 'partner_admin' }), {
    superadminManaged: { $ne: true },
  });
  assert.deepEqual(socStaffVisibilityFilter({ role: 'soc_manager', superadminManaged: true }), {
    superadminManaged: true,
  });
  assert.deepEqual(socInvitationVisibilityFilter({ role: 'partner_admin' }), {
    superadminManaged: { $ne: true },
    socManagerPool: { $ne: true },
  });
});

test('staff mutation scope rejects a user carrying an assignment from another company scope', async () => {
  const originalFind = SocCompanyAssignment.find;
  SocCompanyAssignment.find = () => ({ distinct: async () => ['company-b'] });
  try {
    await assert.rejects(
      assertSocStaffManagementScope(
        {
          id: 'partner-admin-a', role: 'partner_admin', partnerId: 'partner-a',
          companyId: 'company-a', superadminManaged: false,
        },
        {
          _id: 'manager-b', role: 'soc_manager', partnerId: 'partner-a', superadminManaged: false,
        },
      ),
      error => error.status === 403 && /outside your administration scope/i.test(error.message),
    );
  } finally {
    SocCompanyAssignment.find = originalFind;
  }
});

test('normalized assignments prevent duplicate user scope records', () => {
  const companyIndexes = SocCompanyAssignment.schema.indexes();
  const departmentIndexes = SocDepartmentAssignment.schema.indexes();
  assert.ok(companyIndexes.some(([keys, options]) => keys.userId === 1 && keys.companyId === 1 && options.unique));
  assert.ok(departmentIndexes.some(([keys, options]) => keys.userId === 1 && keys.departmentId === 1 && options.unique));
});

test('SOC escalations enforce the L1 to L2 to L3 or manager workflow levels', () => {
  assert.deepEqual(SocEscalation.schema.path('fromLevel').enumValues, ['l1', 'l2', 'l3', 'manager']);
  assert.deepEqual(SocEscalation.schema.path('toLevel').enumValues, ['l2', 'l3', 'manager']);
  assert.ok(SocEscalation.schema.path('status').enumValues.includes('rejected'));
  assert.equal(SocEscalation.schema.path('reason').isRequired, true);
});
