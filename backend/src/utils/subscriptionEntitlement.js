const mongoose = require('mongoose');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');

const entitlementCache = new Map();
const entitlementInflight = new Map();
const CACHE_MS = Math.max(250, Number(process.env.SUBSCRIPTION_ENTITLEMENT_CACHE_MS || 5000));

function isBasePlanActive(plan = {}, now = new Date()) {
  if (plan.isActive !== true) return false;
  if (!plan.expiresAt) return true;
  return new Date(plan.expiresAt) > now;
}

async function getSubscriptionEntitlement(company, now = new Date()) {
  const companyId = company?._id || company?.id || company;
  const oid = companyId instanceof mongoose.Types.ObjectId
    ? companyId
    : new mongoose.Types.ObjectId(String(companyId));

  const cacheKey = String(oid);
  const cached = entitlementCache.get(cacheKey);
  if (cached?.expiresAt > Date.now()) return cached.value;
  if (entitlementInflight.has(cacheKey)) return entitlementInflight.get(cacheKey);

  const pending = calculateSubscriptionEntitlement(company, oid, now)
    .then(value => {
      entitlementCache.set(cacheKey, { value, expiresAt: Date.now() + CACHE_MS });
      return value;
    })
    .finally(() => entitlementInflight.delete(cacheKey));
  entitlementInflight.set(cacheKey, pending);
  return pending;
}

async function calculateSubscriptionEntitlement(company, oid, now) {

  await AddSystemSubscription.updateMany(
    { companyId: oid, status: 'active', endDate: { $lte: now } },
    { $set: { status: 'expired' } },
  );

  const [batchTotals] = await AddSystemSubscription.aggregate(activeBatchPipeline(oid, now));
  return summarizeEntitlement(company, batchTotals, now);
}

function activeBatchPipeline(companyId, now, groupId = null) {
  return [
    {
      $match: {
        companyId,
        status: 'active',
        endDate: { $gt: now },
        $or: [{ paymentStatus: 'paid' }, { paymentStatus: { $exists: false } }],
      },
    },
    {
      $group: {
        _id: groupId,
        batchCount: { $sum: 1 },
        systemCount: { $sum: '$addedSystemCount' },
        serverCount: { $sum: '$addedServerCount' },
        phoneCount: { $sum: '$addedPhoneCount' },
        expiresAt: { $max: '$endDate' },
      },
    },
  ];
}

// List pages need the same entitlement rules, without per-company queries or
// changing subscription records just to display their current status.
async function withSubscriptionEntitlements(companies, now = new Date()) {
  if (!companies.length) return [];
  const ids = companies.map(company => new mongoose.Types.ObjectId(String(company._id)));
  const totals = await AddSystemSubscription.aggregate(activeBatchPipeline({ $in: ids }, now, '$companyId'));
  const byCompany = new Map(totals.map(total => [String(total._id), total]));
  return companies.map(company => ({
    ...company,
    entitlement: summarizeEntitlement(company, byCompany.get(String(company._id)), now),
  }));
}

function summarizeEntitlement(company, batchTotals, now) {
  const baseActive = isBasePlanActive(company?.plan, now);
  const activeBatchCount = Number(batchTotals?.batchCount) || 0;
  const batchActive = activeBatchCount > 0;

  return {
    licenseActive: baseActive || batchActive,
    baseActive,
    batchActive,
    activeBatchCount,
    batchSystemCount: Number(batchTotals?.systemCount) || 0,
    batchServerCount: Number(batchTotals?.serverCount) || 0,
    batchPhoneCount: Number(batchTotals?.phoneCount) || 0,
    batchExpiresAt: batchTotals?.expiresAt || null,
  };
}

function invalidateSubscriptionEntitlement(companyId) {
  if (companyId == null) {
    entitlementCache.clear();
    entitlementInflight.clear();
    return;
  }
  const key = String(companyId);
  entitlementCache.delete(key);
  entitlementInflight.delete(key);
}

module.exports = { getSubscriptionEntitlement, withSubscriptionEntitlements, invalidateSubscriptionEntitlement, isBasePlanActive };
