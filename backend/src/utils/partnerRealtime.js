const Company = require('../models/Company.model');

function emitPartnerUpdate(io, partnerId, type, companyId) {
  if (!io || !partnerId) return;
  const event = { partnerId: String(partnerId), type, ts: new Date().toISOString() };
  if (companyId) event.companyId = String(companyId);
  io.to(`partner:${partnerId}`).to('superadmin').emit('partner:update', event);
}

async function emitCompanyPartnerUpdate(io, companyId, type) {
  if (!io || !companyId) return;
  try {
    const company = await Company.findById(companyId).select('partnerId').lean();
    emitPartnerUpdate(io, company?.partnerId, type, companyId);
  } catch (err) {
    console.warn('[partner-realtime] Unable to resolve company:', err.message);
  }
}

module.exports = { emitPartnerUpdate, emitCompanyPartnerUpdate };
