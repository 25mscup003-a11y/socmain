const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const { allowedCompanyIds } = require('./socAccess.service');

async function resolveEncryptionScope(req, { requireCompany = false } = {}) {
  const requestedCompanyId = req.body?.companyId || req.query?.companyId || req.params?.companyId || null;
  const requestedTenantId = req.body?.tenantId || req.query?.tenantId || null;
  let companyId = requestedCompanyId ? String(requestedCompanyId) : (req.user.companyId ? String(req.user.companyId) : null);

  if (companyId && !mongoose.isValidObjectId(companyId)) {
    const error = new Error('Valid company scope is required');
    error.statusCode = 400;
    throw error;
  }

  if (req.user.role !== 'superadmin') {
    const allowed = await allowedCompanyIds(req.user);
    if (companyId && !allowed.includes(companyId)) {
      const error = new Error('Cross-company cryptographic access denied');
      error.statusCode = 403;
      throw error;
    }
    if (!companyId && allowed.length === 1) companyId = allowed[0];
    if (requireCompany && !companyId) {
      const error = new Error('An authorized company scope is required');
      error.statusCode = 400;
      throw error;
    }
  }

  let company = null;
  if (companyId) {
    company = await Company.findById(companyId).select('_id tenantId partnerId').lean();
    if (!company) {
      const error = new Error('Company not found');
      error.statusCode = 404;
      throw error;
    }
  }

  const tenantId = company?.tenantId || requestedTenantId || req.user.tenantId;
  if (!tenantId || !mongoose.isValidObjectId(tenantId)) {
    const error = new Error('Valid tenant scope is required');
    error.statusCode = 400;
    throw error;
  }
  if (req.user.role !== 'superadmin' && String(req.user.tenantId || '') !== String(tenantId)) {
    const error = new Error('Cross-tenant cryptographic access denied');
    error.statusCode = 403;
    throw error;
  }
  return { tenantId: String(tenantId), companyId: companyId || null, company };
}

module.exports = { resolveEncryptionScope };
