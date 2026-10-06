const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const EnterpriseOrder = require('../models/EnterpriseOrder.model');
const { failure, requirements, enterpriseTotals, same } = require('./enterpriseQuote.service');
const { getPeriodEnd } = require('../utils/billingPeriod');

async function calculateAddition(company, body, now = new Date()) {
  if (!company.enterpriseSubscriptionId) throw failure('This company does not have an Enterprise registration plan.', 409);
  const parent = await AddSystemSubscription.findOne({ _id: company.enterpriseSubscriptionId, companyId: company._id });
  if (!parent || parent.status === 'cancelled' || parent.paymentStatus !== 'paid') {
    throw failure('An Enterprise purchase is required before adding systems.', 409);
  }
  const original = await EnterpriseOrder.findById(parent.enterpriseOrderId);
  if (!original || !same(original.partnerId, company.partnerId)) throw failure('Request an updated Enterprise quote from your administrator.', 409);
  const counts = requirements({ ...body, billingCycle: parent.billingCycle });
  const quantity = original.systemCount + original.serverCount + original.phoneCount;
  if (quantity <= 0 || !(original.baseInr > 0)) throw failure('Enterprise billing details are incomplete. Contact your administrator.', 409);
  const unitInr = original.baseInr / quantity;
  const subtotal = count => Math.round(count * unitInr * 100) / 100;
  const subtotalSystems = subtotal(counts.systemCount), subtotalServers = subtotal(counts.serverCount), subtotalPhones = subtotal(counts.phoneCount);
  const totals = enterpriseTotals(subtotalSystems + subtotalServers + subtotalPhones);
  return {
    ...counts, enterprise: true, parentBatchId: parent._id, quoteId: original.quoteId, revision: original.revision,
    periodStart: now, periodEnd: getPeriodEnd(parent.billingCycle, now), unitInr,
    subtotalSystems, subtotalServers, subtotalPhones, totalInr: totals.baseInr, totals,
  };
}

module.exports = { calculateAddition };
