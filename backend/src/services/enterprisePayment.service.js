const crypto = require('crypto');
const mongoose = require('mongoose');
const Razorpay = require('razorpay');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');
const EnterpriseQuote = require('../models/EnterpriseQuote.model');
const EnterpriseOrder = require('../models/EnterpriseOrder.model');
const EnterpriseAdditionOrder = require('../models/EnterpriseAdditionOrder.model');
const EnterpriseRenewalOrder = require('../models/EnterpriseRenewalOrder.model');
const { calculateAddition } = require('./enterpriseAddition.service');
const { calculateRenewal } = require('./enterpriseRenewal.service');
const PaymentHistory = require('../models/PaymentHistory.model');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const { invalidateSubscriptionEntitlement } = require('../utils/subscriptionEntitlement');
const { enterpriseTotals, failure, same } = require('./enterpriseQuote.service');
const { getPeriodEnd } = require('../utils/billingPeriod');

function defaultGateway() {
  if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) throw failure('Payment service is not configured.', 503);
  return new Razorpay({ key_id: process.env.RAZORPAY_KEY_ID, key_secret: process.env.RAZORPAY_KEY_SECRET });
}

module.exports = function enterprisePayments({
  ensurePartnerLicenseStock, createPartnerRouteTransfer, getGateway = defaultGateway,
  allocateEnterpriseLicenses = require('./enterpriseLicenseAllocation.service'),
  recalculateTotals = require('./recalculateLicenseTotals.service'),
}) {
  const isEnterpriseOrder = async orderId => orderId && (await EnterpriseOrder.exists({ razorpayOrderId: orderId }) || await EnterpriseAdditionOrder.exists({ razorpayOrderId: orderId }) || await EnterpriseRenewalOrder.exists({ razorpayOrderId: orderId }));

  async function createOrder(company, body) {
    if (!mongoose.isObjectIdOrHexString(body.quoteId) || !Number.isSafeInteger(Number(body.revision))) throw failure('Refresh your Enterprise quote before checkout.');
    const quote = await EnterpriseQuote.findOne({ _id: body.quoteId, companyId: company._id, revision: Number(body.revision) });
    if (!quote || !['quoted', 'checkout'].includes(quote.status)) throw failure('An approved Enterprise quote is required. Refresh the Enterprise page.', 409);
    if (!same(quote.partnerId, company.partnerId)) throw failure('Company ownership has changed. Request a new Enterprise quote.', 409);
    const locked = await EnterpriseQuote.findOneAndUpdate({ _id: quote._id, revision: quote.revision, status: { $in: ['quoted', 'checkout'] } },
      { $set: { status: 'checkout' } }, { new: true });
    if (!locked) throw failure('The Enterprise quote changed. Refresh before checkout.', 409);
    let saved = await EnterpriseOrder.findOne({ quoteId: quote._id, revision: quote.revision });
    if (!saved) {
      const partner = company.partnerId ? await Partner.findById(company.partnerId).select('name').lean() : null;
      const totals = enterpriseTotals(quote.amountInr);
      try {
        saved = await EnterpriseOrder.create({
          quoteId: quote._id, revision: quote.revision, companyId: company._id, partnerId: company.partnerId || null,
          companyName: company.name, partnerName: partner?.name || '',
          isPrimaryEnterprise: company.plan?.paymentStatus !== 'paid' && (!company.enterpriseSubscriptionId || !await AddSystemSubscription.exists({ _id: company.enterpriseSubscriptionId, status: 'active', endDate: { $gt: new Date() } })),
          systemCount: quote.systemCount, serverCount: quote.serverCount, phoneCount: quote.phoneCount,
          billingCycle: quote.billingCycle, baseInr: totals.baseInr, gstInr: totals.gstInr, feeInr: totals.feeInr,
          amountPaise: totals.totalPaise,
        });
      } catch (error) {
        if (error.code !== 11000) throw error;
        saved = await EnterpriseOrder.findOne({ quoteId: quote._id, revision: quote.revision });
      }
    }
    return prepareGatewayOrder(company, saved, EnterpriseOrder);
  }

  async function prepareGatewayOrder(company, saved, OrderModel) {
    const gateway = getGateway();
    if (saved.razorpayOrderId) return { order: await gateway.orders.fetch(saved.razorpayOrderId) };
    if (saved.kind !== 'renewal') await ensurePartnerLicenseStock(company._id, saved.systemCount + saved.serverCount + saved.phoneCount);
    const lease = crypto.randomUUID();
    const reserved = await OrderModel.findOneAndUpdate({
      _id: saved._id, razorpayOrderId: null,
      $or: [{ orderLeaseUntil: null }, { orderLeaseUntil: { $lte: new Date() } }],
    }, { $set: { orderLease: lease, orderLeaseUntil: new Date(Date.now() + 60000) } }, { new: true });
    if (!reserved) throw failure('Checkout is being prepared. Please retry shortly.', 409);
    try {
      const order = await gateway.orders.create({
        amount: saved.amountPaise, currency: 'INR', receipt: 'ent_' + saved._id,
        notes: { companyId: String(company._id), enterpriseOrderId: String(saved._id), planType: 'enterprise' },
      });
      const updated = await OrderModel.findOneAndUpdate({ _id: saved._id, orderLease: lease },
        { $set: { razorpayOrderId: order.id, status: 'created', orderLease: null, orderLeaseUntil: null } }, { new: true });
      if (!updated) throw failure('Checkout preparation expired. Please retry.', 409);
      return { order };
    } catch (error) {
      await OrderModel.updateOne({ _id: saved._id, orderLease: lease }, { $set: { orderLease: null, orderLeaseUntil: null } });
      throw error;
    }
  }

  async function createAdditionOrder(company, body) {
    if (!/^[a-f0-9-]{36}$/i.test(body.purchaseKey || '')) throw failure('Refresh checkout before adding systems.');
    let saved = await EnterpriseAdditionOrder.findOne({ companyId: company._id, purchaseKey: body.purchaseKey });
    if (!saved) {
      const calculation = await calculateAddition(company, body);
      if (calculation.totals.totalPaise < 100) throw failure('Minimum order is ₹1. Increase the license quantity.');
      if (body.expectedPaise !== calculation.totals.totalPaise) throw failure('Your Enterprise pricing changed. Refresh Add Systems before checkout.', 409);
      const partner = company.partnerId ? await Partner.findById(company.partnerId).select('name').lean() : null;
      try {
        saved = await EnterpriseAdditionOrder.create({
          ...calculation, kind: 'addition', purchaseKey: body.purchaseKey,
          companyId: company._id, partnerId: company.partnerId || null,
          companyName: company.name, partnerName: partner?.name || '',
          baseInr: calculation.totals.baseInr, gstInr: calculation.totals.gstInr,
          feeInr: calculation.totals.feeInr, amountPaise: calculation.totals.totalPaise,
        });
      } catch (error) {
        if (error.code !== 11000) throw error;
        saved = await EnterpriseAdditionOrder.findOne({ companyId: company._id, purchaseKey: body.purchaseKey });
      }
    }
    return prepareGatewayOrder(company, saved, EnterpriseAdditionOrder);
  }

  async function createRenewalOrder(company, body) {
    const calculation = await calculateRenewal(company, body);
    if (!calculation.renewalAvailable) throw failure('Renewal will be available after your Enterprise plan expires.', 409);
    if (calculation.totals.totalPaise < 100) throw failure('Minimum renewal is ₹1. Contact your administrator to check pricing.');
    if (body.priceKey !== calculation.priceKey || body.expectedPaise !== calculation.totals.totalPaise) {
      throw failure('Your Enterprise renewal price or expiry changed. Refresh the renewal details before checkout.', 409);
    }
    const filter = { companyId: company._id, renewalBatchId: calculation.batchId, renewFrom: calculation.renewFrom };
    let saved = await EnterpriseRenewalOrder.findOne(filter);
    if (!saved) {
      const partner = company.partnerId ? await Partner.findById(company.partnerId).select('name').lean() : null;
      try {
        saved = await EnterpriseRenewalOrder.create({
          ...filter, ...calculation, kind: 'renewal', partnerId: company.partnerId || null,
          companyName: company.name, partnerName: partner?.name || '',
          baseInr: calculation.totals.baseInr, gstInr: calculation.totals.gstInr,
          feeInr: calculation.totals.feeInr, amountPaise: calculation.totals.totalPaise,
        });
      } catch (error) {
        if (error.code !== 11000) throw error;
        saved = await EnterpriseRenewalOrder.findOne(filter);
      }
    }
    if (saved.priceKey !== calculation.priceKey || !same(saved.partnerId, company.partnerId)) {
      throw failure('An earlier renewal checkout is pending. Contact your administrator to reconcile its price.', 409);
    }
    return prepareGatewayOrder(company, saved, EnterpriseRenewalOrder);
  }

  async function settle(saved) {
    if (!saved.partnerId) return;
    // Claim the transfer before contacting Razorpay. Concurrent confirmations
    // and webhook retries cannot send the partner's payout twice.
    const history = await PaymentHistory.findOneAndUpdate({ paymentId: saved.paymentId, payoutStatus: 'pending' },
      { $set: { payoutStatus: 'processing' } }, { new: true });
    if (!history) return;
    const partner = await Partner.findById(saved.partnerId);
    if (!partner) {
      await PaymentHistory.updateOne({ paymentId: saved.paymentId }, { $set: { payoutStatus: 'failed', transferError: 'Partner account not found' } });
      return;
    }
    const settlement = await createPartnerRouteTransfer({ razorpay_payment_id: saved.paymentId, amountInr: saved.amountPaise / 100, partner });
    await PaymentHistory.updateOne({ paymentId: saved.paymentId }, { $set: settlement });
  }

  async function fulfill(orderId, paymentId, expectedCompanyId) {
    let OrderModel = EnterpriseOrder;
    let saved = await OrderModel.findOne({ razorpayOrderId: orderId });
    if (!saved) { OrderModel = EnterpriseAdditionOrder; saved = await OrderModel.findOne({ razorpayOrderId: orderId }); }
    if (!saved) { OrderModel = EnterpriseRenewalOrder; saved = await OrderModel.findOne({ razorpayOrderId: orderId }); }
    if (!saved || (expectedCompanyId && !same(saved.companyId, expectedCompanyId))) throw failure('Enterprise payment does not belong to this company.', 403);
    if (saved.status === 'paid') {
      if (saved.paymentId !== paymentId) throw failure('This Enterprise order has already been paid.', 409);
      await settle(saved);
      return { success: true, company: await Company.findById(saved.companyId) };
    }
    const gateway = getGateway();
    const [payment, order] = await Promise.all([gateway.payments.fetch(paymentId), gateway.orders.fetch(orderId)]);
    if (payment?.status !== 'captured' || payment.order_id !== orderId || payment.currency !== 'INR'
      || payment.amount !== saved.amountPaise || order?.amount !== saved.amountPaise || order.currency !== 'INR'
      || !same(order.notes?.enterpriseOrderId, saved._id) || !same(order.notes?.companyId, saved.companyId)) {
      throw failure('Enterprise payment is not captured or does not match the quoted order.', 409);
    }
    const paymentTime = Number(payment.captured_at || payment.created_at) * 1000;
    const paidAt = Number.isFinite(paymentTime) && paymentTime > 0 && paymentTime <= Date.now() + 300000 ? new Date(paymentTime) : new Date();
    const periodStart = saved.kind === 'renewal' ? new Date(Math.max(+new Date(saved.renewFrom), +paidAt)) : paidAt;
    const periodEnd = getPeriodEnd(saved.billingCycle, periodStart);
    // Bind the first verified payment and period once, before resumable work.
    saved = await OrderModel.findOneAndUpdate({ _id: saved._id, paymentId: null },
      { $set: { paymentId, paidAt, periodStart, periodEnd } }, { new: true })
      || await OrderModel.findById(saved._id);
    if (saved.paymentId !== paymentId) throw failure('This Enterprise order has already been paid.', 409);
    const company = await Company.findById(saved.companyId);
    if (!company || !same(company.partnerId, saved.partnerId)) throw failure('Company ownership changed. Contact your administrator to reconcile this payment.', 409);
    if (saved.kind !== 'renewal') await allocateEnterpriseLicenses(company, saved);
    // A unique batch adds licenses without replacing the existing base plan,
    // its expiry, or any other purchase. Upserts make interrupted work resumable.
    let batch;
    if (saved.kind === 'renewal') {
      // Compare the purchased expiry, then mark the order in the same write.
      // Confirmation/webhook retries cannot extend or count the renewal twice.
      batch = await AddSystemSubscription.findOneAndUpdate({
        _id: saved.renewalBatchId, companyId: company._id, endDate: saved.renewFrom,
        status: { $in: ['active', 'expired'] }, paymentStatus: 'paid',
        lastEnterpriseRenewalOrderId: { $ne: saved._id },
      }, { $set: {
        endDate: saved.periodEnd, status: 'active', paymentStatus: 'paid',
        orderId, paymentId, amountPaid: saved.amountPaise / 100, amountPaise: saved.amountPaise,
        lastEnterpriseRenewalOrderId: saved._id,
        ...(+saved.renewFrom <= +saved.paidAt ? { startDate: saved.periodStart } : {}),
      }, $inc: { renewalCount: 1 } }, { new: true, runValidators: true });
      if (!batch) batch = await AddSystemSubscription.findOne({ _id: saved.renewalBatchId, companyId: company._id, lastEnterpriseRenewalOrderId: saved._id });
      if (!batch) throw failure('The Enterprise subscription changed. Contact your administrator to reconcile this payment.', 409);
    } else {
    try {
      batch = await AddSystemSubscription.findOneAndUpdate({ enterpriseOrderId: saved._id }, { $setOnInsert: {
        enterpriseOrderId: saved._id, parentBatchId: saved.parentBatchId, companyId: company._id, companyName: saved.companyName,
        orderId, paymentId, addedSystemCount: saved.systemCount, addedServerCount: saved.serverCount, addedPhoneCount: saved.phoneCount,
        serverDetails: saved.kind === 'addition' ? 'Add Systems' : 'Enterprise plan', billingCycle: saved.billingCycle, amountPaid: saved.amountPaise / 100, amountPaise: saved.amountPaise,
        priceType: saved.kind === 'addition' ? (saved.pricingSource === 'dynamic' ? 'renewal' : 'enterprise_addition') : 'enterprise', addedDate: saved.paidAt, startDate: saved.periodStart, endDate: saved.periodEnd,
        autoPay: false, paymentStatus: 'paid', status: 'active',
      } }, { upsert: true, new: true, runValidators: true });
    } catch (error) {
      if (error.code !== 11000) throw error;
      batch = await AddSystemSubscription.findOne({ enterpriseOrderId: saved._id, paymentId });
      if (!batch) throw error;
    }
    }
    await PaymentHistory.updateOne({ paymentId }, { $setOnInsert: {
      companyId: company._id, tenantId: company.tenantId, partnerId: saved.partnerId,
      companyName: saved.companyName, partnerName: saved.partnerName, orderId, paymentId,
      planType: saved.kind === 'renewal' ? 'enterprise_renewal' : saved.kind === 'addition' ? (saved.pricingSource === 'dynamic' ? 'add_system' : 'enterprise_addition') : 'enterprise', systemCount: saved.systemCount, serverCount: saved.serverCount, phoneCount: saved.phoneCount,
      isUpgrade: saved.kind !== 'renewal', addedSystems: saved.kind === 'renewal' ? 0 : saved.systemCount, addedServers: saved.kind === 'renewal' ? 0 : saved.serverCount, addedPhones: saved.kind === 'renewal' ? 0 : saved.phoneCount,
      billingCycle: saved.billingCycle, amountPaise: saved.amountPaise, amountInr: saved.amountPaise / 100,
      currency: 'INR', status: 'captured', paidAt: saved.paidAt, periodStart: saved.periodStart, periodEnd: saved.periodEnd, source: saved.kind === 'renewal' ? 'renewal' : 'checkout',
      companyType: saved.partnerId ? 'PARTNER_MANAGED' : 'DIRECT', paymentReceiver: 'superadmin_razorpay',
      payoutStatus: saved.partnerId ? 'pending' : 'not_applicable',
      notes: { batchId: batch._id, enterpriseOrderId: saved._id, quoteId: saved.quoteId, revision: saved.revision, baseInr: saved.baseInr, gstInr: saved.gstInr, feeInr: saved.feeInr },
    } }, { upsert: true, runValidators: true });
    await Company.updateOne({ _id: company._id, status: { $in: ['pending_payment', 'trial'] } }, { $set: { status: 'active' } });
    if (saved.isPrimaryEnterprise) {
      await Company.updateOne({ _id: company._id }, { $set: { enterpriseSubscriptionId: batch._id } });
    }
    const resultCompany = await recalculateTotals(company._id);
    if (!saved.kind || saved.kind === 'plan') await EnterpriseQuote.updateOne({ _id: saved.quoteId, revision: saved.revision, status: 'checkout' }, { $set: { status: 'paid' } });
    await OrderModel.updateOne({ _id: saved._id, paymentId }, { $set: { status: 'paid' } });
    invalidateSubscriptionEntitlement(saved.companyId);
    await settle(saved);
    return { success: true, company: resultCompany };
  }

  async function confirm(company, body) {
    const { razorpay_order_id: orderId, razorpay_payment_id: paymentId, razorpay_signature: signature } = body;
    if (typeof orderId !== 'string' || typeof paymentId !== 'string' || !/^[a-f0-9]{64}$/i.test(signature || '')) throw failure('Invalid payment response.');
    if (!process.env.RAZORPAY_KEY_SECRET) throw failure('Payment service is not configured.', 503);
    const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET).update(orderId + '|' + paymentId).digest();
    if (!crypto.timingSafeEqual(expected, Buffer.from(signature, 'hex'))) throw failure('Payment verification failed.');
    return fulfill(orderId, paymentId, company._id);
  }

  return { createOrder, createAdditionOrder, createRenewalOrder, confirm, fulfill, isEnterpriseOrder };
};
