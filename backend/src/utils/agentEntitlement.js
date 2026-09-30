const Company = require('../models/Company.model');
const { getSubscriptionEntitlement } = require('./subscriptionEntitlement');

const { defaultCache } = require('./cache');

async function getCompanyIngestionStatus(companyOrId, forceRefresh = false) {
  const companyIdStr = String(companyOrId?._id || companyOrId?.id || companyOrId);
  const cacheKey = `ingestion_status:${companyIdStr}`;

  if (!forceRefresh) {
    const cached = defaultCache.get(cacheKey);
    if (cached) {
      return cached;
    }
  }

  const company = companyOrId?.plan
    ? companyOrId
    : await Company.findById(companyIdStr).select('name plan status').lean();

  if (!company) {
    const result = { allowed: false, code: 'COMPANY_NOT_FOUND', message: 'Company not found' };
    defaultCache.set(cacheKey, result, 15);
    return result;
  }

  const entitlement = await getSubscriptionEntitlement(company);
  const companyActive = company.status === 'active';
  const baseExpiresAt = company?.plan?.expiresAt ? new Date(company.plan.expiresAt) : null;
  const expiresAt = entitlement.baseActive
    ? baseExpiresAt
    : (entitlement.batchExpiresAt || baseExpiresAt);
  const expired = !entitlement.licenseActive && Boolean(expiresAt && new Date() > expiresAt);

  let result;
  if (!companyActive) {
    result = {
      allowed: false,
      code: 'COMPANY_INACTIVE',
      message: 'Company is not active. Agent monitoring is stopped.',
      company,
      entitlement,
      expiresAt,
    };
  } else if (!entitlement.licenseActive) {
    result = {
      allowed: false,
      code: expired ? 'SUBSCRIPTION_EXPIRED' : 'SUBSCRIPTION_INACTIVE',
      message: expired
        ? `Subscription expired on ${expiresAt?.toDateString()}. Agent telemetry is blocked until renewal.`
        : 'Subscription is not active. Agent telemetry is blocked until renewal.',
      company,
      entitlement,
      expiresAt,
    };
  } else {
    result = { allowed: true, company, entitlement, expiresAt };
  }

  // Cache for 15 seconds to mitigate DB aggregation load
  defaultCache.set(cacheKey, result, 15);
  return result;
}

function sendIngestionBlocked(res, status) {
  return res.status(402).json({
    ok: false,
    active: false,
    stop_monitoring: true,
    code: status.code || 'SUBSCRIPTION_INACTIVE',
    message: status.message || 'Subscription is not active. Agent telemetry is blocked until renewal.',
    plan_expires_at: status.expiresAt || null,
  });
}

module.exports = { getCompanyIngestionStatus, sendIngestionBlocked };
