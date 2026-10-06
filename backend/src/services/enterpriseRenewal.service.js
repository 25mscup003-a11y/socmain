const crypto = require('crypto');
const mongoose = require('mongoose');
const Batch = require('../models/AddSystemSubscription.model');
const Order = require('../models/EnterpriseOrder.model');
const Addition = require('../models/EnterpriseAdditionOrder.model');
const Quote = require('../models/EnterpriseQuote.model');
const Renewal = require('../models/EnterpriseRenewalOrder.model');
const { enterpriseTotals, failure, same } = require('./enterpriseQuote.service');
const { getPeriodEnd } = require('../utils/billingPeriod');
const { getEffectiveRenewalPriceSet, licenseSubtotals } = require('./renewalPricing.service');

async function calculateRenewal(company, body, now = new Date()) {
  if (!mongoose.isObjectIdOrHexString(body.batchId)) throw failure('Choose an Enterprise subscription.');
  const batch = await Batch.findOne({ _id: body.batchId, companyId: company._id });
  if (!batch || !(batch.priceType?.startsWith('enterprise') || (batch.priceType === 'renewal' && batch.enterpriseOrderId)) || !['active', 'expired'].includes(batch.status)
    || batch.paymentStatus !== 'paid') throw failure('A purchased Enterprise subscription is required.', 409);
  if (batch.lastEnterpriseRenewalOrderId && await Renewal.exists({ _id: batch.lastEnterpriseRenewalOrderId, status: { $ne: 'paid' } })) {
    throw failure('Your last renewal is still being verified. Please refresh shortly.', 409);
  }
  const original = (batch.lastEnterpriseRenewalOrderId && await Renewal.findById(batch.lastEnterpriseRenewalOrderId))
    || await Order.findById(batch.enterpriseOrderId) || await Addition.findById(batch.enterpriseOrderId);
  if (!original || !same(original.companyId, company._id) || !same(original.partnerId, company.partnerId)
    || !(original.baseInr > 0)) throw failure('Enterprise pricing is unavailable. Contact your administrator.', 409);
  const counts = { systemCount: batch.addedSystemCount, serverCount: batch.addedServerCount || 0, phoneCount: batch.addedPhoneCount || 0 };
  const isAddition = batch.priceType === 'enterprise_addition' || batch.priceType === 'renewal';
  const quote = await Quote.findOne({ _id: original.quoteId, companyId: company._id });
  // A later admin price applies only to this exact package. Unrelated new
  // requirements must not change the price or quantities of an existing plan.
  const matchingQuote = !isAddition && quote && ['quoted', 'checkout', 'paid'].includes(quote.status)
    && same(quote.partnerId, company.partnerId) && quote.billingCycle === batch.billingCycle
    && Object.entries(counts).every(([key, value]) => quote[key] === value) && quote.amountInr > 0;
  let totals = enterpriseTotals(matchingQuote ? quote.amountInr : original.baseInr);
  let pricingSource = isAddition ? 'dynamic' : 'enterprise';
  if (isAddition) {
    const pricing = await getEffectiveRenewalPriceSet(company._id);
    totals = enterpriseTotals(licenseSubtotals(pricing, counts, batch.billingCycle).totalInr);
  }
  const renewFrom = new Date(batch.endDate);
  if (!Number.isFinite(+renewFrom)) throw failure('Enterprise expiry is unavailable. Contact your administrator.', 409);
  let revision = matchingQuote ? quote.revision : original.revision;
  let priceKey = crypto.createHash('sha256').update(JSON.stringify({ batchId: String(batch._id), renewFrom,
    ...counts, billingCycle: batch.billingCycle, revision, amountPaise: totals.totalPaise })).digest('hex');
  // An already prepared checkout retains its agreed admin price. Display the
  // same snapshot on retry, even if an admin has since prepared a new quote.
  const pending = await Renewal.findOne({ companyId: company._id, renewalBatchId: batch._id, renewFrom, status: { $ne: 'paid' } });
  if (pending) {
    if (!same(pending.partnerId, company.partnerId)) throw failure('Company ownership changed. Contact your administrator.', 409);
    totals = { baseInr: pending.baseInr, gstInr: pending.gstInr, feeInr: pending.feeInr, totalInr: pending.amountPaise / 100, totalPaise: pending.amountPaise };
    revision = pending.revision; priceKey = pending.priceKey;
    pricingSource = pending.pricingSource || 'enterprise';
  }
  const periodStart = new Date(Math.max(+renewFrom, +now));
  return { ...counts, batchId: batch._id, billingCycle: batch.billingCycle, quoteId: original.quoteId, revision,
    renewFrom, renewalAvailable: +renewFrom <= +now, periodStart, periodEnd: getPeriodEnd(batch.billingCycle, periodStart), priceKey, pricingSource, totals };
}

module.exports = { calculateRenewal };
