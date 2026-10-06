const count = value => Math.max(0, Number(value) || 0);
const id = value => String(value?._id || value || '');

export function hasSubscriptionExpired(expiresAt, now = new Date()) {
  if (expiresAt == null || expiresAt === '') return false;
  const expiry = new Date(expiresAt).getTime();
  return Number.isFinite(expiry) && expiry <= +now;
}

export function canRenewBatch(batch, now = new Date()) {
  return ['active', 'expired'].includes(batch?.status)
    && (batch.paymentStatus === 'paid' || batch.paymentStatus == null)
    && hasSubscriptionExpired(batch.endDate, now);
}

export function isActivePaidBatch(batch, now = new Date()) {
  return batch?.status === 'active' && new Date(batch.endDate) > now
    && (batch.paymentStatus === 'paid' || batch.paymentStatus == null);
}

export function paymentSubscription(status = {}, batches = [], now = new Date()) {
  const plan = status?.plan || {};
  const primaryId = id(status?.enterpriseSubscriptionId);
  const embedded = status?.primaryEnterpriseSubscription;
  const enterprisePrimary = primaryId
    ? (id(embedded) === primaryId ? embedded : batches.find(batch => id(batch) === primaryId))
    : null;
  const enterpriseRegistration = Boolean(primaryId) && plan.paymentStatus !== 'paid';
  const uniqueBatches = new Map(batches.map(batch => [id(batch), batch]));
  if (enterprisePrimary) uniqueBatches.set(primaryId, { ...uniqueBatches.get(primaryId), ...enterprisePrimary });
  const activeBatches = [...uniqueBatches.values()].filter(batch => isActivePaidBatch(batch, now));
  const additionalBatches = activeBatches.filter(batch => !enterpriseRegistration || id(batch) !== primaryId);
  const additionalHistory = batches.filter(batch => !enterpriseRegistration || id(batch) !== primaryId);
  const purchasedForRenewal = batch => ['active', 'expired'].includes(batch.status)
    && (batch.paymentStatus === 'paid' || batch.paymentStatus == null);
  const enterpriseRenewalPlans = [...uniqueBatches.values()].filter(batch => purchasedForRenewal(batch)
    && (batch.priceType === 'enterprise' || id(batch) === primaryId));
  const baseActive = plan.isActive === true && (!plan.expiresAt || new Date(plan.expiresAt) > now);
  const result = {
    enterprisePrimary, enterpriseRegistration, activeBatches, additionalBatches, additionalHistory,
    enterpriseRenewalPlans,
    planActive: enterpriseRegistration ? isActivePaidBatch(enterprisePrimary, now) : baseActive,
  };
  for (const type of ['System', 'Server', 'Phone']) {
    const totalKey = `${type.toLowerCase()}Count`;
    const baseKey = `base${type}Count`;
    const batchKey = `added${type}Count`;
    const batchTotal = status?.entitlement?.[`batch${type}Count`]
      ?? activeBatches.reduce((sum, batch) => sum + count(batch[batchKey]), 0);
    const baseCount = enterpriseRegistration ? 0 : plan[baseKey] != null
      ? count(plan[baseKey]) : Math.max(0, count(plan[totalKey]) - count(batchTotal));
    result[baseKey] = baseCount;
    result[`currentPlan${type}s`] = enterpriseRegistration ? count(enterprisePrimary?.[batchKey]) : baseCount;
    result[`total${type}Count`] = (baseActive ? baseCount : 0) + count(batchTotal);
    result[batchKey] = additionalBatches.reduce((sum, batch) => sum + count(batch[batchKey]), 0);
  }
  return result;
}
