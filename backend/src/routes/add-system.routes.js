/**
 * add-system.routes.js
 *
 * Manages "Add Systems" batch subscriptions independently from the base registration plan.
 * Each new purchase creates an independent AddSystemSubscription document.
 * Renewals update that same batch so the customer keeps one visible batch record.
 *
 * Endpoints:
 *   POST /api/add-system/create-order     → Razorpay order for adding systems
 *   POST /api/add-system/confirm          → Verify payment + create batch entry
 *   GET  /api/add-system/list             → All batches for this company
 *   GET  /api/add-system/active-total     → Total active added systems
 *   POST /api/add-system/renew/:id        → Create order to renew a specific batch
 *   POST /api/add-system/renew-confirm/:id → Confirm renewal payment
 *   POST /api/add-system/autopay/:id      → Toggle AutoPay for a specific batch
 *   POST /api/add-system/autopay-order/:id → ₹1 order to enable AutoPay
 *   POST /api/add-system/autopay-confirm/:id → Confirm AutoPay activation payment
 */
const express  = require('express');
const router   = express.Router();
const crypto   = require('crypto');
const mongoose = require('mongoose');   // ✅ FIX: needed for ObjectId conversion in aggregates
const jwt      = require('jsonwebtoken');
const Razorpay = require('razorpay');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const recalculateTotals = require('../services/recalculateLicenseTotals.service');
const Company  = require('../models/Company.model');
const Partner  = require('../models/Partner.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const { getEffectiveRenewalPriceSet } = require('../services/renewalPricing.service');
const { authenticate, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { hasExpired } = require('../utils/renewalEligibility');
router.use(require('../middleware/enterprisePaymentIsolation'));
// Enterprise registrations add licenses through their server-priced checkout.
router.post(['/create-order', '/confirm'], authenticate, requireCompanyAdmin, async (req, res, next) => {
  try {
    const company = await require('../services/enterpriseQuote.service').companyForEnterprise(req.user);
    if (company.enterpriseSubscriptionId) return res.status(409).json({ message: 'Use Enterprise Add Systems for your company pricing and billing cycle.' });
    next();
  } catch (error) { res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to verify company billing.' }); }
});

function optionalAuthenticate(req, _res, next) {
  const header = req.headers.authorization;
  if (header?.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(header.split(' ')[1], process.env.JWT_SECRET);
    } catch {
      req.user = null;
    }
  }
  next();
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function calcTotal(priceSet, sysCount, srvCount, phoneCount, billingCycle) {
  if (billingCycle === 'yearly') {
    return (sysCount * priceSet.pricePerSystemYearly) + (phoneCount * priceSet.pricePerPhoneYearly) + (srvCount * priceSet.pricePerServerYearly);
  }
  return (sysCount * priceSet.pricePerSystemMonthly) + (phoneCount * priceSet.pricePerPhoneMonthly) + (srvCount * priceSet.pricePerServerMonthly);
}

function withCheckoutFees(baseInr, includeFees = false) {
  const base = Number(baseInr) || 0;
  if (!includeFees) {
    return { baseInr: base, gstInr: 0, feeInr: 0, totalInr: base, totalPaise: Math.round(base * 100) };
  }
  const gstInr = base * 0.18;
  const feeInr = base * 0.02;
  const totalInr = base + gstInr + feeInr;
  return {
    baseInr: base,
    gstInr,
    feeInr,
    totalInr,
    totalPaise: Math.round(totalInr * 100),
  };
}

const { getPeriodEnd } = require('../utils/billingPeriod');

function getRazorpay() {
  const keyId     = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) throw new Error('Razorpay keys missing in .env');
  return new Razorpay({ key_id: keyId, key_secret: keySecret });
}

function verifySubscriptionSignature(subscriptionId, paymentId, signature) {
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${paymentId}|${subscriptionId}`)
    .digest('hex');
  return expected === signature;
}

async function createAutoPaySubscription(razorpay, { amountInr, billingCycle = 'monthly', name, notes = {} }) {
  const amountPaise = Math.max(Math.round(Number(amountInr || 0) * 100), 100);
  const period = billingCycle === 'yearly' ? 'yearly' : 'monthly';
  const plan = await razorpay.plans.create({
    period,
    interval: 1,
    item: {
      name,
      amount: amountPaise,
      currency: 'INR',
      description: 'Recurring AutoPay mandate for SOC add-system subscription',
    },
    notes,
  });
  const subscription = await razorpay.subscriptions.create({
    plan_id: plan.id,
    total_count: period === 'yearly' ? 10 : 120,
    quantity: 1,
    customer_notify: 1,
    notes: { ...notes, planId: plan.id, amountInr: String(amountPaise / 100) },
  });
  return { plan, subscription, amountInr: amountPaise / 100 };
}

function verifySignature(orderId, paymentId, signature) {
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${orderId}|${paymentId}`)
    .digest('hex');
  return expected === signature;
}

const recalcAgentLicenses = (partner) => {
  const now = new Date();
  const purchases = Array.isArray(partner.agentLicensePurchases) ? partner.agentLicensePurchases : [];
  let totalPurchased = 0;
  let consumedLicenses = 0;
  let activeLicenses = 0;
  let inactiveLicenses = 0;
  let lastExpiryAt = null;

  purchases.forEach(item => {
    const qty = Number(item.agentQuantity || 0);
    const consumed = Number(item.consumedQuantity || 0);
    totalPurchased += qty;
    consumedLicenses += consumed;
    if (item.expiryDate && new Date(item.expiryDate) <= now) item.status = 'inactive';
    if (item.status === 'active') activeLicenses += Math.max(qty - consumed, 0);
    if (item.status !== 'active') inactiveLicenses += qty;
    if (item.expiryDate && (!lastExpiryAt || new Date(item.expiryDate) > new Date(lastExpiryAt))) lastExpiryAt = item.expiryDate;
  });

  partner.agentLicenseSummary = {
    totalPurchased,
    consumedLicenses,
    remainingLicenses: Math.max(activeLicenses, 0),
    activeLicenses,
    inactiveLicenses,
    lastExpiryAt,
  };
  partner.capabilities = partner.capabilities || {};
  partner.capabilities.downloadAgent = activeLicenses > 0;
  return partner.agentLicenseSummary;
};

async function getPartnerLicenseStock(companyId) {
  const company = await Company.findById(companyId).select('partnerId company_type source agentLicenseAllocation name');
  const partnerManaged = Boolean(company?.partnerId)
    && (company.company_type === 'PARTNER_MANAGED' || company.source === 'partner_referral');
  if (!partnerManaged) return { limited: false, company };
  const partner = await Partner.findById(company.partnerId);
  if (!partner) return { limited: true, company, available: 0 };
  recalcAgentLicenses(partner);
  await partner.save();
  const [legacyAllocation] = await Company.aggregate([
    { $match: { partnerId: partner._id } },
    { $group: { _id: '$partnerId', allocated: { $sum: { $ifNull: ['$agentLicenseAllocation', 0] } } } },
  ]);
  const activeStock = Number(partner.agentLicenseSummary?.activeLicenses || 0);
  const allocated = 0;
  const legacyCredit = Math.max(Number(legacyAllocation?.allocated || 0) - Number(partner.enterpriseLegacyConsumed || 0), 0);
  return { limited: true, company, partner, activeStock, allocated, available: Math.max(activeStock + legacyCredit, 0) };
}

async function ensurePartnerLicenseStock(companyId, requestedLicenses) {
  const requested = Math.max(Number(requestedLicenses || 0), 0);
  if (requested <= 0) return { limited: false };
  const stock = await getPartnerLicenseStock(companyId);
  if (!stock.limited) return stock;
  if (stock.available < requested) {
    const err = new Error(`Partner license stock not available. Available: ${stock.available}, required: ${requested}`);
    err.status = 409;
    throw err;
  }
  return stock;
}

async function allocatePartnerLicensesToCompany(companyId, qty) {
  const requested = Math.max(Number(qty || 0), 0);
  if (requested <= 0) return null;
  const stock = await getPartnerLicenseStock(companyId);
  if (!stock.limited) return null;
  let remaining = requested;
  const purchases = Array.isArray(stock.partner.agentLicensePurchases) ? stock.partner.agentLicensePurchases : [];
  purchases
    .filter(item => item.status === 'active' && (!item.expiryDate || new Date(item.expiryDate) > new Date()))
    .sort((a, b) => new Date(a.expiryDate || 0) - new Date(b.expiryDate || 0))
    .forEach(item => {
      if (remaining <= 0) return;
      const available = Math.max(Number(item.agentQuantity || 0) - Number(item.consumedQuantity || 0), 0);
      const use = Math.min(available, remaining);
      item.consumedQuantity = Number(item.consumedQuantity || 0) + use;
      remaining -= use;
    });
  recalcAgentLicenses(stock.partner);
  await stock.partner.save();
  return Company.findById(companyId);
}

// ── Auto-expire check (lightweight sweep on read) ─────────────────────────────
async function markExpiredBatches(companyId) {
  const now = new Date();
  await AddSystemSubscription.updateMany(
    { companyId, status: 'active', endDate: { $lt: now } },
    { $set: { status: 'expired' } }
  );
}

// ── KEY HELPER: Recalculate total system/server count and update Company ────────
// ── POST /api/add-system/create-order ─────────────────────────────────────────
router.post('/create-order', authenticate, requireCompanyAdmin, async (req, res) => {
	  const {
	    systemCount = 0, serverCount = 0, phoneCount = 0,
	    billingCycle = 'monthly', serverDetails = '', checkoutFees = false,
	  } = req.body;

	  const sys = Number(systemCount) || 0;
	  const srv = Number(serverCount) || 0;
	  const phn = Number(phoneCount) || 0;

	  if (sys <= 0 && srv <= 0 && phn <= 0) {
	    return res.status(400).json({ message: 'Add at least 1 system, server, or phone' });
	  }

  try {
    await ensurePartnerLicenseStock(req.user.companyId, sys + srv + phn);
    const priceSet = await getEffectiveRenewalPriceSet(req.user.companyId);
	    const baseInr  = calcTotal(priceSet, sys, srv, phn, billingCycle);
	    const totals   = withCheckoutFees(baseInr, checkoutFees);
	    const amount   = totals.totalPaise; // paise

    if (amount < 100) {
      return res.status(400).json({ message: 'Minimum order is ₹1' });
    }

    const razorpay = getRazorpay();
    const order = await razorpay.orders.create({
      amount,
      currency: 'INR',
      receipt:  `addsys_${req.user.companyId}_${Date.now()}`.slice(0, 40),
      notes: {
	        companyId:     req.user.companyId.toString(),
	        systemCount:   String(sys),
	        serverCount:   String(srv),
	        phoneCount:    String(phn),
	        serverDetails: serverDetails || '',
        billingCycle,
        type:          'add_system',
	        checkoutFees: String(!!checkoutFees),
      },
    });

	    console.log('[add-system] ✅ Order created:', order.id, '| sys:', sys, '| srv:', srv, '| phn:', phn, '| ₹', amount / 100);
    res.json({
      order,
	      systemCount: sys,
	      serverCount: srv,
	      phoneCount: phn,
      billingCycle,
      serverDetails,
	      amountInr: totals.totalInr,
	      baseInr: totals.baseInr,
	      gstInr: totals.gstInr,
	      feeInr: totals.feeInr,
      pricing: priceSet,
    });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ message: err.message });
    const detail = err?.error || err?.message || err;
    console.error('[add-system/create-order] ❌', detail);
    res.status(500).json({ message: 'Order creation failed', detail: String(detail?.description || detail) });
  }
});

// ── POST /api/add-system/confirm ──────────────────────────────────────────────
router.post('/confirm', authenticate, requireCompanyAdmin, async (req, res) => {
	  const {
	    razorpay_order_id, razorpay_payment_id, razorpay_signature,
	    systemCount = 0, serverCount = 0, phoneCount = 0,
	    billingCycle = 'monthly', serverDetails = '', checkoutFees = false,
	  } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Missing Razorpay payment fields' });
  }
  if (!verifySignature(razorpay_order_id, razorpay_payment_id, razorpay_signature)) {
    return res.status(400).json({ message: 'Payment verification failed — signature mismatch' });
  }

	  const sys = Number(systemCount) || 0;
	  const srv = Number(serverCount) || 0;
	  const phn = Number(phoneCount) || 0;

  try {
    await ensurePartnerLicenseStock(req.user.companyId, sys + srv + phn);
    const priceSet = await getEffectiveRenewalPriceSet(req.user.companyId);
	    const baseAmountInr = calcTotal(priceSet, sys, srv, phn, billingCycle);
	    const amountInr = withCheckoutFees(baseAmountInr, checkoutFees).totalInr;
    const startDate = new Date();
    const endDate   = getPeriodEnd(billingCycle, startDate);

    const company = await Company.findById(req.user.companyId).populate('partnerId', 'name');
    const partner = company?.partnerId || null;

    // ✅ KEY: Create a NEW independent batch — do NOT merge billing with base plan
    const batch = await AddSystemSubscription.create({
      companyId:    req.user.companyId,
      companyName:  company?.name || '',
      orderId:      razorpay_order_id,
      paymentId:    razorpay_payment_id,
      signature:    razorpay_signature,
	      addedSystemCount: sys,
	      addedServerCount: srv,
	      addedPhoneCount:  phn,
	      serverDetails:    serverDetails || '',
      billingCycle,
      amountPaid:   amountInr,
	      amountPaise:  amountInr * 100,
	      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
	      pricePerSystemYearly:  priceSet.pricePerSystemYearly,
	      pricePerPhoneMonthly:  priceSet.pricePerPhoneMonthly,
	      pricePerPhoneYearly:   priceSet.pricePerPhoneYearly,
	      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly:  priceSet.pricePerServerYearly,
      priceType:   'renewal',
      addedDate:   startDate,
      startDate,
      endDate,
      status:      'active',
      paymentStatus: 'paid',
      autoPay:     !!company?.plan?.autoPay,
      autoPayMethod: company?.plan?.autoPayMethod || '',
    });

    // ✅ FIX: Recalculate plan.systemCount = base + ALL active add-system batches
    // This updates the field used by Dashboard, SystemsPage, Layout, and everywhere else
    const updatedCompany = await recalculateTotals(req.user.companyId);
    await allocatePartnerLicensesToCompany(req.user.companyId, sys + srv + phn);
    // Record payment history for all companies (both Direct and Partner-managed)
    await PaymentHistory.create({
      companyId: req.user.companyId,
      companyName: company?.name || '',
      partnerId: partner?._id || null,
      partnerName: partner?.name || '',
      tenantId: company?.tenantId || null,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'add_system',
      systemCount: updatedCompany?.plan?.systemCount || sys,
      serverCount: updatedCompany?.plan?.serverCount || srv,
      phoneCount: updatedCompany?.plan?.phoneCount || phn,
      billingCycle,
      amountInr,
      amountPaise: Math.round(amountInr * 100),
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly: priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly: priceSet.pricePerServerYearly,
      isUpgrade: true,
      addedSystems: sys,
      addedServers: srv,
      addedPhones: phn,
      status: 'captured',
      paidAt: startDate,
      periodStart: startDate,
      periodEnd: endDate,
      source: 'upgrade',
      companyType: partner?._id ? 'PARTNER_MANAGED' : 'DIRECT',
      notes: { batchId: batch._id, type: 'add_system' },
    });
    console.log('[add-system/payment-history] revenue recorded', {
      partnerId: partner?._id ? String(partner._id) : null,
      companyId: String(req.user.companyId),
      amountInr,
      paymentId: razorpay_payment_id,
    });

    console.log('[add-system] ✅ Batch created:', batch._id, '| new plan.systemCount:', updatedCompany?.plan?.systemCount);
    res.json({ success: true, batch, company: updatedCompany });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ message: err.message });
    console.error('[add-system/confirm] ❌', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/add-system/list ───────────────────────────────────────────────────
router.get('/list', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    if (!targetCompanyId) return res.json([]);
    await markExpiredBatches(targetCompanyId);
    await recalculateTotals(targetCompanyId);
    const company = await Company.findById(targetCompanyId).select('plan.autoPay plan.autoPayMethod').lean();
    if (company?.plan?.autoPay) {
      await AddSystemSubscription.updateMany(
        { companyId: targetCompanyId, status: 'active', endDate: { $gt: new Date() }, autoPay: { $ne: true } },
        { autoPay: true, autoPayMethod: company.plan.autoPayMethod || '' }
      );
    } else {
      await AddSystemSubscription.updateMany(
        { companyId: targetCompanyId, status: 'active', endDate: { $gt: new Date() }, autoPay: { $ne: false } },
        { autoPay: false, autoPayMethod: '' }
      );
    }
    const batches = await AddSystemSubscription.find({ companyId: targetCompanyId })
      .sort({ addedDate: -1 })
      .lean();
    res.json(batches);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/add-system/active-total ──────────────────────────────────────────
// Returns total active added systems/servers/phones (for usage calculation)
router.get('/active-total', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    if (!targetCompanyId) return res.json({ totalSys: 0, totalSrv: 0, totalPhn: 0 });
    const companyOid = new mongoose.Types.ObjectId(targetCompanyId.toString());
    await markExpiredBatches(companyOid);
    await recalculateTotals(companyOid);
    const result = await AddSystemSubscription.aggregate([
      { $match: { companyId: companyOid, status: 'active' } },
      { $group: {
        _id: null,
	        totalSystems: { $sum: '$addedSystemCount' },
	        totalServers: { $sum: '$addedServerCount' },
	        totalPhones:  { $sum: '$addedPhoneCount' },
	        batchCount:   { $sum: 1 },
	      }},
	    ]);
	    const totals = result[0] || { totalSystems: 0, totalServers: 0, totalPhones: 0, batchCount: 0 };
    res.json(totals);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/add-system/renew/:id — Create order to renew a specific batch ───
router.post('/renew/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  const { billingCycle = 'monthly', checkoutFees = false } = req.body;
  try {
    const batch = await AddSystemSubscription.findOne({
      _id: req.params.id,
      companyId: req.user.companyId,
    });
    if (!batch) return res.status(404).json({ message: 'Batch not found' });
    if (batch.priceType === 'enterprise') return res.status(409).json({ message: 'Use Enterprise to renew your registration plan.' });
    if (!['active', 'expired'].includes(batch.status) || (batch.paymentStatus != null && batch.paymentStatus !== 'paid')) {
      return res.status(409).json({ message: 'A purchased, non-cancelled batch is required for renewal.' });
    }
    if (!hasExpired(batch.endDate)) return res.status(409).json({ message: 'Renewal is available after this batch expires.' });

    const priceSet = await getEffectiveRenewalPriceSet(req.user.companyId);
	    const baseInr  = calcTotal(priceSet, batch.addedSystemCount, batch.addedServerCount, batch.addedPhoneCount || 0, billingCycle);
	    const totals   = withCheckoutFees(baseInr, checkoutFees);
	    const amount   = totals.totalPaise;

    if (amount < 100) return res.status(400).json({ message: 'Minimum renewal is ₹1' });

    const razorpay = getRazorpay();
    const order = await razorpay.orders.create({
      amount,
      currency: 'INR',
      receipt:  `renew_${batch._id}_${Date.now()}`.slice(0, 40),
      notes: {
        companyId:     req.user.companyId.toString(),
        batchId:       batch._id.toString(),
	        systemCount:   String(batch.addedSystemCount),
	        serverCount:   String(batch.addedServerCount),
	        phoneCount:    String(batch.addedPhoneCount || 0),
        billingCycle,
        type:          'add_system_renewal',
	        checkoutFees: String(!!checkoutFees),
      },
    });

    res.json({
      order, batch, billingCycle,
	      amountInr: totals.totalInr,
	      baseInr: totals.baseInr,
	      gstInr: totals.gstInr,
	      feeInr: totals.feeInr,
      pricing: priceSet,
    });
  } catch (err) {
    const detail = err?.error || err?.message || err;
    res.status(500).json({ message: 'Renewal order failed', detail: String(detail?.description || detail) });
  }
});

// ── POST /api/add-system/renew-confirm/:id ────────────────────────────────────
router.post('/renew-confirm/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, billingCycle = 'monthly' } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Missing payment fields' });
  }
  if (!verifySignature(razorpay_order_id, razorpay_payment_id, razorpay_signature)) {
    return res.status(400).json({ message: 'Payment verification failed' });
  }

  try {
    const oldBatch = await AddSystemSubscription.findOne({
      _id: req.params.id,
      companyId: req.user.companyId,
    });
    if (!oldBatch) return res.status(404).json({ message: 'Batch not found' });
    if (oldBatch.priceType === 'enterprise') return res.status(409).json({ message: 'Use Enterprise to renew your registration plan.' });

    const priceSet = await getEffectiveRenewalPriceSet(req.user.companyId);
	    const baseAmountInr = calcTotal(priceSet, oldBatch.addedSystemCount, oldBatch.addedServerCount, oldBatch.addedPhoneCount || 0, billingCycle);
	    const amountInr = withCheckoutFees(baseAmountInr, req.body.checkoutFees).totalInr;
    const startDate = new Date();
    const endDate   = getPeriodEnd(billingCycle, startDate);
    const company   = await Company.findById(req.user.companyId).populate('partnerId', 'name');
    const partner   = company?.partnerId || null;

    // Renew the selected batch in place. This keeps one visible batch record and
    // prevents an old expired record plus a duplicate active record for one license set.
    const batch = await AddSystemSubscription.findByIdAndUpdate(oldBatch._id, {
      orderId:      razorpay_order_id,
      paymentId:    razorpay_payment_id,
      signature:    razorpay_signature,
      billingCycle,
      amountPaid:   amountInr,
	      amountPaise:  amountInr * 100,
	      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
	      pricePerSystemYearly:  priceSet.pricePerSystemYearly,
	      pricePerPhoneMonthly:  priceSet.pricePerPhoneMonthly,
	      pricePerPhoneYearly:   priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly:  priceSet.pricePerServerYearly,
      priceType:     'renewal',
      startDate,
      endDate,
      status:        'active',
      paymentStatus: 'paid',
      autoPay:       oldBatch.autoPay,   // carry forward autopay setting
      renewalCount:  (oldBatch.renewalCount || 0) + 1,
    }, { new: true });

    // ✅ FIX: Recalculate plan.systemCount after renewal
    const updatedCompany = await recalculateTotals(req.user.companyId);
    // Record payment history for all companies (both Direct and Partner-managed)
    await PaymentHistory.create({
      companyId: req.user.companyId,
      companyName: company?.name || '',
      partnerId: partner?._id || null,
      partnerName: partner?.name || '',
      tenantId: company?.tenantId || null,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'add_system_renewal',
      systemCount: updatedCompany?.plan?.systemCount || oldBatch.addedSystemCount,
      serverCount: updatedCompany?.plan?.serverCount || oldBatch.addedServerCount,
      phoneCount: updatedCompany?.plan?.phoneCount || oldBatch.addedPhoneCount || 0,
      billingCycle,
      amountInr,
      amountPaise: Math.round(amountInr * 100),
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly: priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly: priceSet.pricePerServerYearly,
      isUpgrade: true,
      addedSystems: oldBatch.addedSystemCount,
      addedServers: oldBatch.addedServerCount,
      addedPhones: oldBatch.addedPhoneCount || 0,
      status: 'captured',
      paidAt: startDate,
      periodStart: startDate,
      periodEnd: endDate,
      source: 'renewal',
      companyType: partner?._id ? 'PARTNER_MANAGED' : 'DIRECT',
      notes: { batchId: batch._id, type: 'add_system_renewal' },
    });
    console.log('[add-system/renew-payment-history] revenue recorded', {
      partnerId: partner?._id ? String(partner._id) : null,
      companyId: String(req.user.companyId),
      amountInr,
      paymentId: razorpay_payment_id,
    });

    console.log('[add-system/renew] ✅ Renewed batch in place:', batch._id, '| plan.systemCount:', updatedCompany?.plan?.systemCount);
    res.json({ success: true, batch, company: updatedCompany });
  } catch (err) {
    console.error('[add-system/renew-confirm] ❌', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/add-system/autopay/:id — Disable AutoPay (free) ─────────────────
router.post('/autopay/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  const { enabled } = req.body;

  // Free disable only — enable requires ₹1 payment
  if (enabled === true || enabled === 'true') {
    return res.status(400).json({
      message: 'To enable AutoPay, use /autopay-order first (mandatory ₹1 fee).',
      requiresPayment: true,
    });
  }

  try {
    const batch = await AddSystemSubscription.findOne({ _id: req.params.id, companyId: req.user.companyId });
    if (!batch) return res.status(404).json({ message: 'Batch not found' });
    if (batch.priceType?.startsWith('enterprise')) return res.status(409).json({ message: 'Use Enterprise to request your next plan quote.' });
    await Company.findByIdAndUpdate(req.user.companyId, {
      'plan.autoPay': false,
      'plan.autoPayMethod': '',
    });
    const result = await AddSystemSubscription.updateMany(
      { companyId: req.user.companyId, status: 'active', endDate: { $gt: new Date() } },
      { autoPay: false, autoPayMethod: '' }
    );
    const batches = await AddSystemSubscription.find({ companyId: req.user.companyId }).sort({ createdAt: -1 });
    res.json({ success: true, autoPay: false, batch, batches, disabledCount: result.modifiedCount });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/add-system/autopay-order/:id — ₹1 order to enable AutoPay ──────
router.post('/autopay-order/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const batch = await AddSystemSubscription.findOne({
      _id: req.params.id,
      companyId: req.user.companyId,
    });
    if (!batch) return res.status(404).json({ message: 'Batch not found' });
    if (batch.priceType?.startsWith('enterprise')) return res.status(409).json({ message: 'Use Enterprise to request your next plan quote.' });

    const razorpay = getRazorpay();
    const amountInr = Number(batch.amountPaid || 0);
    if (amountInr <= 0) return res.status(400).json({ message: 'Batch amount is required before enabling AutoPay.' });
    const { plan, subscription } = await createAutoPaySubscription(razorpay, {
      amountInr,
      billingCycle: batch.billingCycle || 'monthly',
      name: `SOC Add-System AutoPay ${batch._id}`,
      notes: {
        companyId: req.user.companyId.toString(),
        batchId: batch._id.toString(),
        purpose: 'add_system_autopay_mandate',
      },
    });

    res.json({ subscription, plan, amountInr, batchId: batch._id, purpose: 'add_system_autopay' });
  } catch (err) {
    const detail = err?.error || err?.message || err;
    res.status(500).json({ message: 'AutoPay order failed', detail: String(detail?.description || detail) });
  }
});

// ── POST /api/add-system/autopay-confirm/:id — Confirm AutoPay activation ────
// One successful Add-System AutoPay activation enables AutoPay for future company payments and active batches.
router.post('/autopay-confirm/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  const { razorpay_payment_id, razorpay_signature, razorpay_subscription_id } = req.body;

  if (!razorpay_payment_id || !razorpay_signature || !razorpay_subscription_id) {
    return res.status(400).json({ message: 'Missing payment fields' });
  }
  if (!verifySubscriptionSignature(razorpay_subscription_id, razorpay_payment_id, razorpay_signature)) {
    return res.status(400).json({ message: 'Payment verification failed' });
  }

  try {
    const batch = await AddSystemSubscription.findOne({ _id: req.params.id, companyId: req.user.companyId });
    if (!batch) return res.status(404).json({ message: 'Batch not found' });
    if (batch.priceType?.startsWith('enterprise')) return res.status(409).json({ message: 'Use Enterprise to request your next plan quote.' });

    const now = new Date();
    await Company.findByIdAndUpdate(req.user.companyId, {
      'plan.autoPay': true,
      'plan.autoPayMethod': razorpay_subscription_id,
    });
    const result = await AddSystemSubscription.updateMany(
      { companyId: req.user.companyId, status: 'active', endDate: { $gt: now } },
      { autoPay: true, autoPayMethod: razorpay_subscription_id }
    );
    const batches = await AddSystemSubscription.find({ companyId: req.user.companyId }).sort({ createdAt: -1 });

    console.log('[add-system/autopay] ✅ AutoPay enabled for company and active batches:', String(req.user.companyId), result.modifiedCount);
    res.json({ success: true, autoPay: true, batch, batches, enabledCount: result.modifiedCount });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/add-system/calculate — cost estimation ──────────────────────────
router.post('/calculate', optionalAuthenticate, async (req, res) => {
  const { systemCount = 0, serverCount = 0, phoneCount = 0, billingCycle = 'monthly' } = req.body;
  const sys = Number(systemCount) || 0;
  const srv = Number(serverCount) || 0;
  const phn = Number(phoneCount) || 0;
  if (sys <= 0 && srv <= 0 && phn <= 0) return res.status(400).json({ message: 'At least 1 system, server, or phone required' });

  try {
    const priceSet = await getEffectiveRenewalPriceSet(req.user?.companyId);
    const total    = calcTotal(priceSet, sys, srv, phn, billingCycle);
    res.json({
      systemCount: sys, serverCount: srv, phoneCount: phn, billingCycle,
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly:  priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly:  priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly:   priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly:  priceSet.pricePerServerYearly,
      subtotalSystems: billingCycle === 'yearly' ? sys * priceSet.pricePerSystemYearly : sys * priceSet.pricePerSystemMonthly,
      subtotalServers: billingCycle === 'yearly' ? srv * priceSet.pricePerServerYearly : srv * priceSet.pricePerServerMonthly,
      subtotalPhones:  billingCycle === 'yearly' ? phn * priceSet.pricePerPhoneYearly : phn * priceSet.pricePerPhoneMonthly,
      totalInr: total,
      totalPaise: total * 100,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/add-system/recalculate — manually trigger total recalculation ────
// Call this once to fix existing companies whose systemCount wasn't updated correctly
router.post('/recalculate', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    if (!targetCompanyId) return res.json({ success: true, message: 'No target company' });
    const updatedCompany = await recalculateTotals(targetCompanyId);
    res.json({
      success: true,
      systemCount: updatedCompany?.plan?.systemCount,
      serverCount: updatedCompany?.plan?.serverCount,
      baseSystemCount: updatedCompany?.plan?.baseSystemCount,
      baseServerCount: updatedCompany?.plan?.baseServerCount,
      message: `Total updated: ${updatedCompany?.plan?.systemCount} systems, ${updatedCompany?.plan?.serverCount} servers`,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
