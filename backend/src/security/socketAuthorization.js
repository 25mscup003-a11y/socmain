function id(value) {
  if (!value) return '';
  return String(value._id || value);
}

function isSuperAdmin(principal) {
  return principal?.kind === 'user' && principal.role === 'superadmin';
}

function canJoinCompany(principal, company) {
  if (!principal || !company) return false;
  if (isSuperAdmin(principal)) return true;
  if (principal.kind === 'agent') {
    return id(principal.companyId) === id(company._id);
  }
  if (principal.role === 'partner_admin') {
    return Boolean(principal.partnerId) && id(principal.partnerId) === id(company.partnerId);
  }
  return Boolean(principal.companyId) && id(principal.companyId) === id(company._id);
}

function canJoinDepartment(principal, department) {
  if (!principal || !department) return false;
  if (isSuperAdmin(principal)) return true;
  if (principal.kind === 'agent') {
    return id(principal.companyId) === id(department.companyId)
      && id(principal.departmentId) === id(department._id);
  }
  if (!principal.companyId || id(principal.companyId) !== id(department.companyId)) return false;
  if (principal.role === 'department_admin') {
    return id(principal.departmentId) === id(department._id)
      || (principal.departmentIds || []).some(value => id(value) === id(department._id));
  }
  return ['company_admin', 'analyst'].includes(principal.role);
}

function canJoinPartner(principal, partnerId) {
  if (!principal || !partnerId) return false;
  if (isSuperAdmin(principal)) return true;
  return principal.kind === 'user'
    && principal.role === 'partner_admin'
    && id(principal.partnerId) === id(partnerId);
}

function canJoinSystem(principal, system) {
  if (!principal || !system) return false;
  if (isSuperAdmin(principal)) return true;
  if (principal.kind === 'agent') return id(principal.systemId) === id(system._id);
  if (principal.role === 'partner_admin') {
    return Boolean(principal.partnerId) && id(principal.partnerId) === id(system.partnerId);
  }
  return Boolean(principal.companyId) && id(principal.companyId) === id(system.companyId);
}

function canJoinGlobalFraud(principal) {
  return isSuperAdmin(principal);
}

module.exports = {
  id,
  canJoinCompany,
  canJoinDepartment,
  canJoinPartner,
  canJoinSystem,
  canJoinGlobalFraud,
};
