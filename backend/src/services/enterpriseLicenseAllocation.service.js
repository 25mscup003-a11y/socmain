const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');
const { failure } = require('./enterpriseQuote.service');

// Consume stock and record the order in the same atomic Partner update. This
// also works on standalone MongoDB, and a retry never consumes stock twice.
module.exports = async function allocateEnterpriseLicenses(company, order) {
  if (!company.partnerId || !(company.company_type === 'PARTNER_MANAGED' || company.source === 'partner_referral')) return;
  const orderId = new mongoose.Types.ObjectId(String(order._id));
  const quantity = order.systemCount + order.serverCount + order.phoneCount;
  const now = new Date();
  const [legacy = {}] = await Company.aggregate([
    { $match: { partnerId: company.partnerId } },
    { $group: { _id: null, allocated: { $sum: { $ifNull: ['$agentLicenseAllocation', 0] } } } },
  ]);
  const available = item => ({ $cond: [
    { $and: [{ $eq: [`${item}.status`, 'active'] }, { $or: [
      { $eq: [{ $ifNull: [`${item}.expiryDate`, null] }, null] }, { $gt: [`${item}.expiryDate`, now] },
    ] }] },
    { $max: [{ $subtract: [{ $ifNull: [`${item}.agentQuantity`, 0] }, { $ifNull: [`${item}.consumedQuantity`, 0] }] }, 0] }, 0,
  ] });
  const stock = { $sum: { $map: { input: { $ifNull: ['$agentLicensePurchases', []] }, as: 'purchase', in: available('$$purchase') } } };
  const legacyStock = { $max: [{ $subtract: [Number(legacy.allocated || 0), { $ifNull: ['$enterpriseLegacyConsumed', 0] }] }, 0] };
  const partner = await Partner.findOneAndUpdate({
    _id: company.partnerId, 'enterpriseAllocations.orderId': { $ne: orderId },
    $expr: { $gte: [{ $add: [stock, legacyStock] }, quantity] },
  }, [
    { $set: { _enterpriseAllocation: { $reduce: {
      input: { $ifNull: ['$agentLicensePurchases', []] }, initialValue: { remaining: quantity, purchases: [] },
      in: { $let: { vars: { available: available('$$this') }, in: { $let: {
        vars: { used: { $min: ['$$value.remaining', '$$available'] } }, in: {
          remaining: { $subtract: ['$$value.remaining', '$$used'] },
          purchases: { $concatArrays: ['$$value.purchases', [{ $mergeObjects: ['$$this', {
            consumedQuantity: { $add: [{ $ifNull: ['$$this.consumedQuantity', 0] }, '$$used'] },
          }] }]] },
        },
      } } } },
    } } } },
    { $set: {
      agentLicensePurchases: '$_enterpriseAllocation.purchases',
      enterpriseLegacyConsumed: { $add: [{ $ifNull: ['$enterpriseLegacyConsumed', 0] }, '$_enterpriseAllocation.remaining'] },
      enterpriseAllocations: { $concatArrays: [{ $ifNull: ['$enterpriseAllocations', []] }, [{ orderId, quantity, allocatedAt: now }]] },
      updatedAt: now, __v: { $add: [{ $ifNull: ['$__v', 0] }, 1] },
    } },
    { $set: {
      'agentLicenseSummary.activeLicenses': stock, 'agentLicenseSummary.remainingLicenses': stock,
      'agentLicenseSummary.consumedLicenses': { $sum: { $map: { input: '$agentLicensePurchases', as: 'purchase', in: { $ifNull: ['$$purchase.consumedQuantity', 0] } } } },
      'capabilities.downloadAgent': { $gt: [stock, 0] },
    } },
    { $unset: '_enterpriseAllocation' },
  ], { new: true });
  if (partner) return;
  if (await Partner.exists({ _id: company.partnerId, 'enterpriseAllocations.orderId': orderId })) return;
  throw failure('Partner license stock is no longer sufficient. Contact your Partner Admin, then retry activation.', 409);
};
