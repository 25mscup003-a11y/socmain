const Company = require('../models/Company.model');

function id(value) {
  if (!value) return null;
  return String(value._id || value);
}

function sameId(a, b) {
  if (!a || !b) return false;
  return id(a) === id(b);
}

function assertIncomingScope(body = {}, scope = {}) {
  const checks = [
    ['companyId', body.companyId || body.company_id, scope.companyId],
    ['systemId', body.systemId || body.system_id, scope.systemId],
    ['tenantId', body.tenantId || body.tenant_id, scope.tenantId],
    ['partnerId', body.partnerId || body.partner_id, scope.partnerId],
  ];

  for (const [name, incoming, expected] of checks) {
    if (!incoming) continue;
    if (!expected || !sameId(incoming, expected)) {
      const err = new Error(`Invalid ${name} scope`);
      err.statusCode = 403;
      throw err;
    }
  }
}

function scopeForUser(user = {}, options = {}) {
  if (user.role === 'superadmin') return {};

  if (user.role === 'partner_admin') {
    return {
      tenantId: user.tenantId,
      partnerId: user.partnerId,
    };
  }

  const scope = { companyId: user.companyId };
  if (user.tenantId) scope.tenantId = user.tenantId;
  if (user.partnerId) scope.partnerId = user.partnerId;
  if (options.departmentScoped && user.role === 'department_admin') {
    scope.departmentId = user.departmentId;
  }
  return scope;
}

function assertUserScope(user, scope = {}) {
  if (!user || user.role === 'superadmin') return;
  if (user.tenantId && !sameId(user.tenantId, scope.tenantId)) {
    const err = new Error('Invalid tenant scope');
    err.statusCode = 403;
    throw err;
  }
  if (user.role === 'partner_admin') {
    if (!user.partnerId || !sameId(user.partnerId, scope.partnerId)) {
      const err = new Error('Invalid partner scope');
      err.statusCode = 403;
      throw err;
    }
    return;
  }
  if (!user.companyId || !sameId(user.companyId, scope.companyId)) {
    const err = new Error('Invalid company scope');
    err.statusCode = 403;
    throw err;
  }
  if (user.role === 'department_admin' && user.departmentId
      && scope.departmentId && !sameId(user.departmentId, scope.departmentId)) {
    const allowed = (user.departmentIds || []).some(value => sameId(value, scope.departmentId));
    if (!allowed) {
      const err = new Error('Invalid department scope');
      err.statusCode = 403;
      throw err;
    }
  }
}

async function resolveScope({ system = null, companyId = null, body = {}, requireSystem = false }) {
  let company = null;

  if (system) {
    company = await Company.findById(system.companyId).select('_id tenantId partnerId status').lean();
    if (!company) {
      const err = new Error('Company not found for agent system');
      err.statusCode = 404;
      throw err;
    }
  } else if (companyId) {
    company = await Company.findById(companyId).select('_id tenantId partnerId status').lean();
    if (!company) {
      const err = new Error('Company not found');
      err.statusCode = 404;
      throw err;
    }
  } else if (requireSystem) {
    const err = new Error('Valid agent system required');
    err.statusCode = 401;
    throw err;
  }

  if (!company) {
    const err = new Error('companyId required');
    err.statusCode = 400;
    throw err;
  }

  const scope = {
    company,
    companyId: company._id,
    tenantId: company.tenantId || null,
    partnerId: company.partnerId || null,
    systemId: system?._id || body.systemId || body.system_id || null,
    departmentId: system?.departmentId || body.departmentId || body.department_id || null,
  };

  assertIncomingScope(body, scope);
  return scope;
}

module.exports = {
  id,
  sameId,
  assertIncomingScope,
  assertUserScope,
  scopeForUser,
  resolveScope,
};
