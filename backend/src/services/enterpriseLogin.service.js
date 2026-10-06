const Quote = require('../models/EnterpriseQuote.model');

async function enterpriseLoginDestination(user, dashboardUrl, company = null) {
  if (user.role !== 'company_admin' || !user.companyId) return dashboardUrl;
  const pending = await Quote.exists({ companyId: user.companyId, status: { $in: ['quoted', 'checkout'] } });
  if (company?.status === 'pending_payment') {
    return new URL(pending ? '/register?plan=enterprise' : '/register', dashboardUrl).href;
  }
  return pending ? new URL('/company-admin/payments?tab=enterprise', dashboardUrl).href : dashboardUrl;
}

module.exports = { enterpriseLoginDestination };
