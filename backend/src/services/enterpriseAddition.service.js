const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const EnterpriseOrder = require('../models/EnterpriseOrder.model');
const { failure, requirements, enterpriseTotals, same } = require('./enterpriseQuote.service');
const { getPeriodEnd } = require('../utils/billingPeriod');
const { getEffectiveRenewalPriceSet, licenseSubtotals } = require('./renewalPricing.service');

async function calculateAddition(company, body, now = new Date()) {
  if (!company.enterpriseSubscriptionId) throw failure('This company does not have an Enterprise registration plan.', 409);
  const parent = await AddSystemSubscription.findOne({ _id: company.enterpriseSubscriptionId, companyId: company._id });
  if (!parent || parent.status === 'cancelled' || parent.paymentStatus !== 'paid') {
    throw failure('An Enterprise purchase is required before adding systems.', 409);
  }
  const original = await EnterpriseOrder.findById(parent.enterpriseOrderId);
  if (!original || !same(original.partnerId, company.partnerId)) throw failure('Request an updated Enterprise quote from your administrator.', 409);
  const counts = requirements(body);
  const pricing = await getEffectiveRenewalPriceSet(company._id);
  const subtotals = licenseSubtotals(pricing, counts, counts.billingCycle);
  const totals = enterpriseTotals(subtotals.totalInr);
  return {
    ...counts, enterprise: true, parentBatchId: parent._id, quoteId: original.quoteId, revision: original.revision,
    periodStart: now, periodEnd: getPeriodEnd(counts.billingCycle, now), pricingSource: 'dynamic', pricing,
    ...subtotals, totals,
  };
}

module.exports = { calculateAddition };
