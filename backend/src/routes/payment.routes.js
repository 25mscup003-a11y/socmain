/**
 * payment.routes.js — Dynamic Subscription & Payment System
 * 
 * Pricing controlled by Super Admin via /api/pricing
 * Company Admin customizes system/server count, no predefined plans
 */
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Razorpay = require('razorpay');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const Pricing = require('../models/Pricing.model');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const { getSubscriptionEntitlement } = require('../utils/subscriptionEntitlement');
const { authenticate, requireCompanyAdmin } = require('../middleware/auth.middleware');
const jwt = require('jsonwebtoken');

function requirePartnerAdmin(req, res, next) {
  if (req.user?.role !== 'partner_admin') {
    return res.status(403).json({ message: 'Partner admin access required' });
  }
  next();
}

const AGENT_PLAN_MONTHS = { monthly: 1, six_monthly: 6, yearly: 12 };
const AGENT_AUTO_PAY_FEE_INR = 5;
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

const agentPriceForPlan = (partner, planType) => {
  const pricing = partner.agentPricing || {};
  if (planType === 'six_monthly') return Number(pricing.sixMonthly || pricing.monthly || 0);
  if (planType === 'yearly') return Number(pricing.yearly || pricing.monthly || 0);
  return Number(pricing.monthly || 0);
};

async function getPartnerLicenseStock(companyId) {
  const company = await Company.findById(companyId).select('partnerId company_type source agentLicenseAllocation name');
  const partnerManaged = Boolean(company?.partnerId)
    && (company.company_type === 'PARTNER_MANAGED' || company.source === 'partner_referral');
  if (!partnerManaged) return { limited: false, company };
  const partner = await Partner.findById(company.partnerId);
  if (!partner) {
    return { limited: true, company, available: 0, message: 'Partner account not found for this company' };
  }
  recalcAgentLicenses(partner);
  await partner.save();
  const [legacyAllocation] = await Company.aggregate([
    { $match: { partnerId: partner._id } },
    { $group: { _id: '$partnerId', allocated: { $sum: { $ifNull: ['$agentLicenseAllocation', 0] } } } },
  ]);
  const activeStock = Number(partner.agentLicenseSummary?.activeLicenses || 0);
  const allocated = 0;
  const legacyCredit = Number(legacyAllocation?.allocated || 0);
  return {
    limited: true,
    company,
    partner,
    activeStock,
    allocated,
    available: Math.max(activeStock + legacyCredit, 0),
  };
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

function emitPartnerRealtime(req, partnerId, type, payload = {}) {
  const io = req.app.get('io');
  if (!io || !partnerId) return;
  const data = { type, partnerId: String(partnerId), ...payload, ts: new Date().toISOString() };
  io.to('superadmin').emit('partner:update', data);
  io.to(`partner:${partnerId}`).emit('partner:update', data);
}

const uploadPathExists = (relativePath) => {
  const cleanPath = String(relativePath || '').replace(/^\/+/, '');
  if (!cleanPath) return false;
  const uploadRoot = path.resolve(__dirname, '../../uploads');
  const uploadPath = path.resolve(uploadRoot, cleanPath);
  return uploadPath.startsWith(uploadRoot + path.sep) && fs.existsSync(uploadPath);
};

const sanitizePartnerAgreement = (partner) => {
  if (!partner?.agreementFilePath || uploadPathExists(partner.agreementFilePath)) return partner;
  partner.agreementFileName = '';
  partner.agreementFileType = '';
  partner.agreementFilePath = '';
  return partner;
};

// ── Helper: get current pricing (with migration + fallback) ──────────────────
async function getCurrentPricing() {
  let p = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 });
  if (!p) {
    p = await Pricing.create({
      newUser_pricePerSystemMonthly: 200, newUser_pricePerSystemYearly: 2000,
      newUser_pricePerPhoneMonthly: 200, newUser_pricePerPhoneYearly: 2000,
      newUser_pricePerServerMonthly: 500, newUser_pricePerServerYearly: 5000,
      renewal_pricePerSystemMonthly: 200, renewal_pricePerSystemYearly: 2000,
      renewal_pricePerPhoneMonthly: 200, renewal_pricePerPhoneYearly: 2000,
      renewal_pricePerServerMonthly: 500, renewal_pricePerServerYearly: 5000,
      pricePerSystemMonthly: 200, pricePerSystemYearly: 2000,
      pricePerPhoneMonthly: 200, pricePerPhoneYearly: 2000,
      pricePerServerMonthly: 500, pricePerServerYearly: 5000,
    });
  }
  // Back-fill new flat fields for legacy documents
  let dirty = false;
  if (!p.newUser_pricePerSystemMonthly) {
    p.newUser_pricePerSystemMonthly = p.pricePerSystemMonthly || 200;
    p.newUser_pricePerSystemYearly = p.pricePerSystemYearly || 2000;
    p.newUser_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.pricePerSystemMonthly || 200;
    p.newUser_pricePerPhoneYearly = p.pricePerPhoneYearly || p.pricePerSystemYearly || 2000;
    p.newUser_pricePerServerMonthly = p.pricePerServerMonthly || 500;
    p.newUser_pricePerServerYearly = p.pricePerServerYearly || 5000;
    dirty = true;
  }
  if (!p.renewal_pricePerSystemMonthly) {
    p.renewal_pricePerSystemMonthly = p.pricePerSystemMonthly || 200;
    p.renewal_pricePerSystemYearly = p.pricePerSystemYearly || 2000;
    p.renewal_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.pricePerSystemMonthly || 200;
    p.renewal_pricePerPhoneYearly = p.pricePerPhoneYearly || p.pricePerSystemYearly || 2000;
    p.renewal_pricePerServerMonthly = p.pricePerServerMonthly || 500;
    p.renewal_pricePerServerYearly = p.pricePerServerYearly || 5000;
    dirty = true;
  }
  if (!p.newUser_pricePerPhoneMonthly) {
    p.newUser_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.newUser_pricePerSystemMonthly || 200;
    p.newUser_pricePerPhoneYearly = p.pricePerPhoneYearly || p.newUser_pricePerSystemYearly || 2000;
    dirty = true;
  }
  if (!p.renewal_pricePerPhoneMonthly) {
    p.renewal_pricePerPhoneMonthly = p.pricePerPhoneMonthly || p.renewal_pricePerSystemMonthly || 200;
    p.renewal_pricePerPhoneYearly = p.pricePerPhoneYearly || p.renewal_pricePerSystemYearly || 2000;
    dirty = true;
  }
  if (dirty) await p.save();
  return p;
}

/** Returns the correct flat price set object for calculation */
function getPricingSet(p, isUpgrade = false) {
  const prefix = isUpgrade ? 'renewal' : 'newUser';
  return {
    pricePerSystemMonthly: p[`${prefix}_pricePerSystemMonthly`],
    pricePerSystemYearly: p[`${prefix}_pricePerSystemYearly`],
    pricePerPhoneMonthly: p[`${prefix}_pricePerPhoneMonthly`],
    pricePerPhoneYearly: p[`${prefix}_pricePerPhoneYearly`],
    pricePerServerMonthly: p[`${prefix}_pricePerServerMonthly`],
    pricePerServerYearly: p[`${prefix}_pricePerServerYearly`],
  };
}

const pricingKeys = [
  'pricePerSystemMonthly',
  'pricePerSystemYearly',
  'pricePerPhoneMonthly',
  'pricePerPhoneYearly',
  'pricePerServerMonthly',
  'pricePerServerYearly',
];

function hasPricingSet(set = {}) {
  return pricingKeys.some(key => Number(set?.[key] || 0) > 0);
}

async function getEffectiveCompanyPricing(companyId, isUpgrade = false) {
  const globalPricing = await getCurrentPricing();
  const globalSet = getPricingSet(globalPricing, isUpgrade);
  if (!companyId) return globalSet;
  const company = await Company.findById(companyId).select('partnerId').lean();
  if (!company?.partnerId) return globalSet;
  const partner = await Partner.findById(company.partnerId).select('companyPricing').lean();
  const setKey = isUpgrade ? 'renewal' : 'newUser';
  const partnerSet = partner?.companyPricing?.[setKey];
  if (!hasPricingSet(partnerSet)) return globalSet;
  return pricingKeys.reduce((acc, key) => ({ ...acc, [key]: Number(partnerSet[key] || globalSet[key] || 0) }), {});
}

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

// ── Helper: calculate total amount ──────────────────────────────────────────
function calcTotal(priceSet, systemCount, serverCount, phoneCount, billingCycle) {
  if (billingCycle === 'yearly') {
    return (systemCount * priceSet.pricePerSystemYearly) + (phoneCount * priceSet.pricePerPhoneYearly) + (serverCount * priceSet.pricePerServerYearly);
  }
  return (systemCount * priceSet.pricePerSystemMonthly) + (phoneCount * priceSet.pricePerPhoneMonthly) + (serverCount * priceSet.pricePerServerMonthly);
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
    baseInr,
    gstInr,
    feeInr,
    totalInr,
    totalPaise: Math.round(totalInr * 100),
  };
}

function addAgentAutoPayFee(totals, enabled = false) {
  const autoPayFeeInr = enabled ? AGENT_AUTO_PAY_FEE_INR : 0;
  const totalInr = Number(totals.totalInr || 0) + autoPayFeeInr;
  return {
    ...totals,
    autoPayFeeInr,
    totalInr,
    totalPaise: Math.round(totalInr * 100),
  };
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
      name: name || 'SOC AutoPay Subscription',
      amount: amountPaise,
      currency: 'INR',
      description: 'Recurring AutoPay mandate for SOC subscription',
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

function getPartnerCommissionPercent(partner) {
  const direct = Number(partner?.commissionPercent || 0);
  const requested = Number(partner?.resourceRequest?.proposedCommission || 0);
  const pct = Number.isFinite(direct) && direct > 0 ? direct : requested;
  return Number.isFinite(pct) && pct > 0 ? pct : 10;
}

async function createPartnerRouteTransfer({ razorpay_payment_id, amountInr, partner }) {
  const linkedAccountId = String(partner?.partner_linked_account_id || '').trim();
  const commissionPercent = getPartnerCommissionPercent(partner);
  const platformCommissionInr = Math.round((Number(amountInr || 0) * commissionPercent) / 100);
  const partnerPayoutInr = Math.max(Number(amountInr || 0) - platformCommissionInr, 0);
  const settlementDate = new Date(Date.now() + 24 * 60 * 60 * 1000);

  const settlement = {
    companyType: 'PARTNER_MANAGED',
    paymentReceiver: 'superadmin_razorpay',
    partnerLinkedAccountId: linkedAccountId,
    platformCommissionInr,
    partnerPayoutInr,
    payoutStatus: linkedAccountId ? 'pending' : 'failed',
    settlementDate,
    transferId: '',
    transferStatus: '',
    transferError: linkedAccountId ? '' : 'partner_linked_account_id is missing',
  };

  if (!linkedAccountId || !razorpay_payment_id || partnerPayoutInr <= 0) return settlement;

  try {
    const razorpay = new Razorpay({
      key_id: process.env.RAZORPAY_KEY_ID,
      key_secret: process.env.RAZORPAY_KEY_SECRET,
    });
    const transfer = await razorpay.payments.transfer(razorpay_payment_id, {
      transfers: [{
        account: linkedAccountId,
        amount: Math.round(partnerPayoutInr * 100),
        currency: 'INR',
        notes: {
          partnerId: String(partner._id),
          type: 'partner_payout',
        },
      }],
    });
    const firstTransfer = Array.isArray(transfer?.items) ? transfer.items[0] : transfer;
    settlement.payoutStatus = 'processing';
    settlement.transferId = firstTransfer?.id || transfer?.id || '';
    settlement.transferStatus = firstTransfer?.status || transfer?.status || 'created';
    settlement.transferError = '';
  } catch (err) {
    settlement.payoutStatus = 'failed';
    settlement.transferError = err?.error?.description || err?.message || 'Route transfer failed';
    console.error('[partner-transfer]', settlement.transferError);
  }

  return settlement;
}


// ── GET /api/payment/pricing — returns newUser prices (public, used by register) ─
router.get('/pricing', async (_req, res) => {
  try {
    const p = await getCurrentPricing();
    // Register page = new user, so return newUser pricing set
    res.json({
      pricePerSystemMonthly: p.newUser_pricePerSystemMonthly,
      pricePerSystemYearly: p.newUser_pricePerSystemYearly,
      pricePerPhoneMonthly: p.newUser_pricePerPhoneMonthly,
      pricePerPhoneYearly: p.newUser_pricePerPhoneYearly,
      pricePerServerMonthly: p.newUser_pricePerServerMonthly,
      pricePerServerYearly: p.newUser_pricePerServerYearly,
      updatedAt: p.updatedAt,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// ── POST /api/payment/calculate — calculate total for given config ────────────
router.post('/calculate', optionalAuthenticate, async (req, res) => {
  const { systemCount = 0, serverCount = 0, phoneCount = 0, billingCycle = 'monthly', isUpgrade = false } = req.body;

  const sysCount = Number(systemCount) || 0;
  const srvCount = Number(serverCount) || 0;
  const phnCount = Number(phoneCount) || 0;

  if (sysCount < 0 || srvCount < 0 || phnCount < 0) {
    return res.status(400).json({ message: 'systemCount, serverCount, and phoneCount must be >= 0' });
  }
  if (sysCount === 0 && srvCount === 0 && phnCount === 0) {
    return res.status(400).json({ message: 'At least one system, server, or phone must be added' });
  }

  try {
    if (req.user?.companyId) {
      await ensurePartnerLicenseStock(req.user.companyId, sysCount + srvCount + phnCount);
    }
    const priceSet = await getEffectiveCompanyPricing(req.user?.companyId, isUpgrade); // partner-scoped when applicable
    const total = calcTotal(priceSet, sysCount, srvCount, phnCount, billingCycle);

    res.json({
      systemCount: sysCount,
      serverCount: srvCount,
      phoneCount: phnCount,
      billingCycle,
      isUpgrade: !!isUpgrade,
      priceType: isUpgrade ? 'renewal' : 'new-user',
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly: priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly: priceSet.pricePerServerYearly,
      subtotalSystems: billingCycle === 'yearly'
        ? sysCount * priceSet.pricePerSystemYearly
        : sysCount * priceSet.pricePerSystemMonthly,
      subtotalServers: billingCycle === 'yearly'
        ? srvCount * priceSet.pricePerServerYearly
        : srvCount * priceSet.pricePerServerMonthly,
      subtotalPhones: billingCycle === 'yearly'
        ? phnCount * priceSet.pricePerPhoneYearly
        : phnCount * priceSet.pricePerPhoneMonthly,
      totalInr: total,
      totalPaise: total * 100,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── Partner enterprise request + payment: Superadmin quotes final price ──────
router.get('/partner-plan', authenticate, requirePartnerAdmin, async (req, res) => {
  try {
    const partner = await Partner.findById(req.user.partnerId)
      .select('name slug status plan razorpay commissionPercent agreementFileName agreementFileType agreementFilePath profileSetupComplete')
      .lean();
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    const pricing = await getCurrentPricing();
    const priceSet = getPricingSet(pricing, false);
    const request = partner.plan?.request || {};
    const quote = partner.plan?.quote || {};
    const platformAmountInr = Number(quote.amountInr || 0);
    const isPaid = partner.plan?.paymentStatus === 'paid' && partner.plan?.isActive;
    res.json({
      partner: sanitizePartnerAgreement(partner),
      pricing: priceSet,
      request,
      quote,
      requestStatus: partner.plan?.requestStatus || 'none',
      amountInr: platformAmountInr,
      billingCycle: quote.billingCycle || partner.plan?.billingCycle || 'monthly',
      isQuoted: platformAmountInr > 0,
      isPaid,
      // After first payment, partner must complete profile setup before dashboard access
      profileSetupComplete: isPaid ? Boolean(partner.profileSetupComplete) : false,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/partner-plan-request', authenticate, requirePartnerAdmin, async (req, res) => {
  const {
    companyCount = 0,
    systemCount = 0,
    serverCount = 0,
    phoneCount = 0,
    notes = '',
  } = req.body;

  const counts = {
    companyCount: Number(companyCount) || 0,
    systemCount: Number(systemCount) || 0,
    serverCount: Number(serverCount) || 0,
    phoneCount: Number(phoneCount) || 0,
  };
  if (counts.companyCount <= 0 || counts.systemCount <= 0) {
    return res.status(400).json({ message: 'Company count and agent/system count are required' });
  }
  if (Object.values(counts).some(v => v < 0)) {
    return res.status(400).json({ message: 'Requested counts cannot be negative' });
  }

  try {
    const partner = await Partner.findByIdAndUpdate(req.user.partnerId, {
      status: 'pending_quote',
      'plan.requestStatus': 'requested',
      'plan.paymentStatus': 'unpaid',
      'plan.isActive': false,
      'plan.request.companyCount': counts.companyCount,
      'plan.request.systemCount': counts.systemCount,
      'plan.request.serverCount': counts.serverCount,
      'plan.request.phoneCount': counts.phoneCount,
      'plan.request.notes': String(notes || '').trim(),
      'plan.request.requestedAt': new Date(),
      'plan.quote.amountInr': 0,
      'plan.quote.notes': '',
      'plan.quote.quotedBy': null,
      'plan.quote.quotedAt': null,
    }, { new: true }).select('name slug status plan razorpay');
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, partner._id, 'plan_requested', { partner });
    res.json({ success: true, partner });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.post('/partner-create-order', authenticate, requirePartnerAdmin, async (req, res) => {
  const { checkoutFees = true } = req.body;
  const durationMonths = [1, 6, 12].includes(Number(req.body.durationMonths)) ? Number(req.body.durationMonths) : 1;
  const partner = await Partner.findById(req.user.partnerId);
  if (!partner) return res.status(404).json({ message: 'Partner not found' });
  if (partner.plan?.paymentStatus === 'paid' && partner.plan?.isActive) {
    return res.status(400).json({ message: 'Partner plan already active' });
  }
  const quote = partner.plan?.quote || {};
  const request = partner.plan?.request || {};
  const platformAmountInr = Number(quote.amountInr || 0);
  if (!platformAmountInr) {
    return res.status(409).json({ message: 'Superadmin quote is required before payment', quoteRequired: true });
  }

  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) return res.status(500).json({ message: 'Razorpay keys missing in .env' });

  try {
    const totals = withCheckoutFees(platformAmountInr * durationMonths, checkoutFees);
    if (totals.totalPaise < 100) return res.status(400).json({ message: 'Minimum order amount is ₹1' });

    const razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });
    const order = await razorpay.orders.create({
      amount: totals.totalPaise,
      currency: 'INR',
      receipt: `ptr_${partner._id}_${Date.now()}`.slice(0, 40),
      notes: {
        partnerId: String(partner._id),
        tenantId: String(partner.tenantId),
        companyCount: String(request.companyCount || 0),
        systemCount: String(request.systemCount || 0),
        serverCount: String(request.serverCount || 0),
        phoneCount: String(request.phoneCount || 0),
        billingCycle: durationMonths === 12 ? 'yearly' : 'monthly',
        durationMonths: String(durationMonths),
        checkoutFees: String(!!checkoutFees),
      },
    });

    res.json({ order, amountInr: totals.totalInr, baseInr: totals.baseInr, gstInr: totals.gstInr, feeInr: totals.feeInr });
  } catch (err) {
    res.status(500).json({ message: 'Partner order creation failed', detail: err.message });
  }
});

router.post('/partner-confirm', authenticate, requirePartnerAdmin, async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    checkoutFees = true,
  } = req.body;
  const durationMonths = [1, 6, 12].includes(Number(req.body.durationMonths)) ? Number(req.body.durationMonths) : 1;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Missing Razorpay payment response fields' });
  }

  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');
  if (expected !== razorpay_signature) return res.status(400).json({ message: 'Payment verification failed' });

  try {
    const existingPartner = await Partner.findById(req.user.partnerId);
    if (!existingPartner) return res.status(404).json({ message: 'Partner not found' });
    const request = existingPartner.plan?.request || {};
    const quote = existingPartner.plan?.quote || {};
    const platformAmountInr = Number(quote.amountInr || 0);
    if (!platformAmountInr) {
      return res.status(409).json({ message: 'Superadmin quote is required before payment', quoteRequired: true });
    }

    const billingCycle = durationMonths === 12 ? 'yearly' : 'monthly';
    const baseAmountInr = platformAmountInr * durationMonths;
    const totals = withCheckoutFees(baseAmountInr, checkoutFees);
    const periodStart = new Date();
    const periodEnd = new Date();
    periodEnd.setMonth(periodEnd.getMonth() + durationMonths);

    const partner = await Partner.findByIdAndUpdate(req.user.partnerId, {
      status: 'active',
      'plan.type': 'enterprise',
      'plan.billingCycle': billingCycle,
      'plan.amountPaid': totals.totalInr,
      'plan.paymentStatus': 'paid',
      'plan.isActive': true,
      'plan.autoPay': true,
      'plan.autoPayMethod': razorpay_payment_id,
      'plan.requestStatus': 'paid',
      'plan.startDate': periodStart,
      'plan.expiresAt': periodEnd,
      'capabilities.createCompany': true,
      'capabilities.downloadAgent': true,
      'capabilities.subscriptionPurchase': true,
      'razorpay.orderId': razorpay_order_id,
      'razorpay.paymentId': razorpay_payment_id,
      'razorpay.signature': razorpay_signature,
      'razorpay.paidAt': new Date(),
    }, { new: true });

    await PaymentHistory.create({
      partnerId: partner._id,
      tenantId: partner.tenantId,
      partnerName: partner.name,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'partner_enterprise',
      systemCount: request.systemCount || 0,
      serverCount: request.serverCount || 0,
      phoneCount: request.phoneCount || 0,
      billingCycle,
      amountPaise: totals.totalPaise,
      amountInr: totals.totalInr,
      status: 'captured',
      paidAt: new Date(),
      periodStart,
      periodEnd,
      source: 'partner_checkout',
      autoPay: true,
      notes: { checkoutFees, durationMonths, companyCount: request.companyCount || 0, monthlyPlatformFeeInr: platformAmountInr, quotedAmountInr: baseAmountInr, autoPay: true },
    });

    emitPartnerRealtime(req, partner._id, 'plan_paid', { partner });
    res.json({ success: true, partner });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/partner-autopay', authenticate, requirePartnerAdmin, async (req, res) => {
  const enabled = req.body.enabled === true || req.body.enabled === 'true';
  if (enabled) {
    return res.status(400).json({ message: 'Partner AutoPay is enabled only during subscription payment checkout.' });
  }
  try {
    const partner = await Partner.findByIdAndUpdate(req.user.partnerId, {
      'plan.autoPay': false,
      'plan.autoPayMethod': '',
    }, { new: true });
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, partner._id, 'partner_autopay_disabled', { partner });
    res.json({ success: true, autoPay: false, partner });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/partner-agent-license/create-order', authenticate, requirePartnerAdmin, async (req, res) => {
  const agentQuantity = Math.max(Number(req.body.agentQuantity || 0), 0);
  const planType = AGENT_PLAN_MONTHS[req.body.planType] ? req.body.planType : 'monthly';
  const checkoutFees = req.body.checkoutFees !== false;
  const requestedAutoPay = req.body.autoPay === true || req.body.autoPay === 'true';
  if (agentQuantity <= 0) return res.status(400).json({ message: 'Agent quantity is required' });

  const partner = await Partner.findById(req.user.partnerId);
  if (!partner) return res.status(404).json({ message: 'Partner not found' });
  const autoPay = requestedAutoPay || Boolean(partner.agentLicenseAutoPay?.enabled);
  const pricePerAgent = agentPriceForPlan(partner, planType);
  if (pricePerAgent <= 0) return res.status(409).json({ message: 'Superadmin agent pricing is required before purchase' });
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) return res.status(500).json({ message: 'Razorpay keys missing in .env' });

  try {
    const baseInr = pricePerAgent * agentQuantity;
    const shouldChargeAutoPayFee = requestedAutoPay && !partner.agentLicenseAutoPay?.enabled;
    const totals = addAgentAutoPayFee(withCheckoutFees(baseInr, checkoutFees), shouldChargeAutoPayFee);
    const razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });
    const order = await razorpay.orders.create({
      amount: totals.totalPaise,
      currency: 'INR',
      receipt: `agt_${partner._id}_${Date.now()}`.slice(0, 40),
      notes: {
        partnerId: String(partner._id),
        tenantId: String(partner.tenantId),
        agentQuantity: String(agentQuantity),
        planType,
        pricePerAgent: String(pricePerAgent),
        autoPay: autoPay ? 'true' : 'false',
        autoPayFeeInr: String(totals.autoPayFeeInr),
      },
    });
    res.json({ order, amountInr: totals.totalInr, baseInr: totals.baseInr, gstInr: totals.gstInr, feeInr: totals.feeInr, autoPayFeeInr: totals.autoPayFeeInr, agentQuantity, planType, pricePerAgent, autoPay });
  } catch (err) {
    res.status(500).json({ message: 'Agent license order creation failed', detail: err.message });
  }
});

router.post('/partner-agent-license/autopay/create-order', authenticate, requirePartnerAdmin, async (req, res) => {
  const partner = await Partner.findById(req.user.partnerId);
  if (!partner) return res.status(404).json({ message: 'Partner not found' });
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !keySecret) return res.status(500).json({ message: 'Razorpay keys missing in .env' });

  try {
    const razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });
    const { plan, subscription } = await createAutoPaySubscription(razorpay, {
      amountInr: AGENT_AUTO_PAY_FEE_INR,
      billingCycle: 'monthly',
      name: `${partner.name || 'Partner'} Agent License AutoPay`,
      notes: {
        partnerId: String(partner._id),
        tenantId: String(partner.tenantId),
        purpose: 'agent_license_autopay_mandate',
      },
    });
    res.json({ subscription, plan, amountInr: AGENT_AUTO_PAY_FEE_INR, autoPayFeeInr: AGENT_AUTO_PAY_FEE_INR });
  } catch (err) {
    res.status(500).json({ message: 'Auto Pay order creation failed', detail: err.message });
  }
});

router.post('/partner-agent-license/autopay/confirm', authenticate, requirePartnerAdmin, async (req, res) => {
  const { razorpay_payment_id, razorpay_signature, razorpay_subscription_id } = req.body;
  if (!razorpay_payment_id || !razorpay_signature || !razorpay_subscription_id) {
    return res.status(400).json({ message: 'Missing Razorpay payment response fields' });
  }
  if (!verifySubscriptionSignature(razorpay_subscription_id, razorpay_payment_id, razorpay_signature)) return res.status(400).json({ message: 'Payment verification failed' });

  try {
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    const paidAt = new Date();
    partner.agentLicensePurchases = partner.agentLicensePurchases || [];
    partner.agentLicensePurchases.forEach(item => { item.autoPay = true; });
    partner.agentLicenseAutoPay = {
      enabled: true,
      paymentId: razorpay_subscription_id,
      enabledAt: paidAt,
      disabledAt: null,
      feeInr: AGENT_AUTO_PAY_FEE_INR,
    };
    recalcAgentLicenses(partner);
    await partner.save();

    await PaymentHistory.updateMany(
      { partnerId: partner._id, source: 'partner_agent_license' },
      { $set: { autoPay: true, 'notes.autoPay': true } }
    );
    await PaymentHistory.create({
      partnerId: partner._id,
      tenantId: partner.tenantId,
      partnerName: partner.name,
      orderId: razorpay_subscription_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'agent_license_autopay',
      billingCycle: 'monthly',
      amountPaise: AGENT_AUTO_PAY_FEE_INR * 100,
      amountInr: AGENT_AUTO_PAY_FEE_INR,
      autoPay: true,
      status: 'captured',
      paidAt,
      source: 'partner_agent_license',
      notes: { purpose: 'agent_license_autopay', autoPay: true, autoPayFeeInr: AGENT_AUTO_PAY_FEE_INR },
    });

    emitPartnerRealtime(req, partner._id, 'agent_license_autopay_enabled', { partner });
    res.json({ success: true, partner, autoPay: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/partner-agent-license/confirm', authenticate, requirePartnerAdmin, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;
  const agentQuantity = Math.max(Number(req.body.agentQuantity || 0), 0);
  const planType = AGENT_PLAN_MONTHS[req.body.planType] ? req.body.planType : 'monthly';
  const checkoutFees = req.body.checkoutFees !== false;
  const requestedAutoPay = req.body.autoPay === true || req.body.autoPay === 'true';
  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Missing Razorpay payment response fields' });
  }
  if (agentQuantity <= 0) return res.status(400).json({ message: 'Agent quantity is required' });
  const expected = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');
  if (expected !== razorpay_signature) return res.status(400).json({ message: 'Payment verification failed' });

  try {
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    const autoPay = requestedAutoPay || Boolean(partner.agentLicenseAutoPay?.enabled);
    const pricePerAgent = agentPriceForPlan(partner, planType);
    if (pricePerAgent <= 0) return res.status(409).json({ message: 'Superadmin agent pricing is required before purchase' });
    const shouldChargeAutoPayFee = requestedAutoPay && !partner.agentLicenseAutoPay?.enabled;
    const totals = addAgentAutoPayFee(withCheckoutFees(pricePerAgent * agentQuantity, checkoutFees), shouldChargeAutoPayFee);
    const buyDate = new Date();
    const expiryDate = new Date(buyDate);
    expiryDate.setMonth(expiryDate.getMonth() + AGENT_PLAN_MONTHS[planType]);
    const invoiceId = `INV-AGT-${Date.now().toString(36).toUpperCase()}`;

    partner.agentLicensePurchases = partner.agentLicensePurchases || [];
    if (autoPay) {
      partner.agentLicensePurchases.forEach(item => { item.autoPay = true; });
      partner.agentLicenseAutoPay = {
        enabled: true,
        paymentId: razorpay_payment_id,
        enabledAt: buyDate,
        disabledAt: null,
        feeInr: AGENT_AUTO_PAY_FEE_INR,
      };
    }
    partner.agentLicensePurchases.push({
      invoiceId,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      agentQuantity,
      consumedQuantity: 0,
      planType,
      pricePerAgent,
      amountInr: totals.totalInr,
      autoPay,
      autoPayFeeInr: totals.autoPayFeeInr,
      buyDate,
      expiryDate,
      status: 'active',
    });
    recalcAgentLicenses(partner);
    await partner.save();
    if (autoPay) {
      await PaymentHistory.updateMany(
        { partnerId: partner._id, source: 'partner_agent_license' },
        { $set: { autoPay: true, 'notes.autoPay': true } }
      );
    }

    await PaymentHistory.create({
      partnerId: partner._id,
      tenantId: partner.tenantId,
      partnerName: partner.name,
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'partner_agent_license',
      systemCount: agentQuantity,
      billingCycle: planType,
      amountPaise: totals.totalPaise,
      amountInr: totals.totalInr,
      autoPay,
      status: 'captured',
      paidAt: buyDate,
      periodStart: buyDate,
      periodEnd: expiryDate,
      source: 'partner_agent_license',
      notes: { invoiceId, agentQuantity, planType, pricePerAgent, checkoutFees, autoPay, autoPayFeeInr: totals.autoPayFeeInr },
    });

    emitPartnerRealtime(req, partner._id, 'agent_license_paid', { partner });
    res.json({ success: true, partner, invoiceId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/payment/create-order — create Razorpay order ───────────────────
router.post('/create-order', authenticate, requireCompanyAdmin, async (req, res) => {
  const { systemCount = 0, serverCount = 0, phoneCount = 0, billingCycle = 'monthly', isUpgrade = false, checkoutFees = false } = req.body;

  const sysCount = Number(systemCount) || 0;
  const srvCount = Number(serverCount) || 0;
  const phnCount = Number(phoneCount) || 0;

  if (sysCount < 0 || srvCount < 0 || phnCount < 0) {
    return res.status(400).json({ message: 'systemCount, serverCount, and phoneCount must be >= 0' });
  }
  if (sysCount === 0 && srvCount === 0 && phnCount === 0) {
    return res.status(400).json({ message: 'At least one system, server, or phone must be added' });
  }

  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;

  if (!keyId || !keySecret) {
    return res.status(500).json({
      message: 'Razorpay keys missing in .env (RAZORPAY_KEY_ID / RAZORPAY_KEY_SECRET)',
    });
  }

  try {
    const priceSet = await getEffectiveCompanyPricing(req.user.companyId, isUpgrade); // partner-scoped when applicable
    const baseInr = calcTotal(priceSet, sysCount, srvCount, phnCount, billingCycle);
    const totals = withCheckoutFees(baseInr, checkoutFees);
    const amount = totals.totalPaise; // paise

    if (amount < 100) {
      return res.status(400).json({ message: 'Minimum order amount is ₹1 (100 paise)' });
    }

    const razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });

    const order = await razorpay.orders.create({
      amount,
      currency: 'INR',
      receipt: `soc_${req.user.companyId}_${Date.now()}`.slice(0, 40),
      notes: {
        companyId: req.user.companyId.toString(),
        systemCount: String(sysCount),
        serverCount: String(srvCount),
        phoneCount: String(phnCount),
        billingCycle,
        isUpgrade: String(isUpgrade),
        priceType: isUpgrade ? 'renewal' : 'new-user',
        checkoutFees: String(!!checkoutFees),
      },
    });

    console.log('[payment] ✅ Order created:', order.id, '| priceType:', isUpgrade ? 'renewal' : 'new-user', '| amount:', amount, 'paise');
    res.json({
      order,
      systemCount: sysCount,
      serverCount: srvCount,
      phoneCount: phnCount,
      billingCycle,
      isUpgrade: !!isUpgrade,
      priceType: isUpgrade ? 'renewal' : 'new-user',
      amountInr: totals.totalInr,
      baseInr: totals.baseInr,
      gstInr: totals.gstInr,
      feeInr: totals.feeInr,
      pricing: {
        pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
        pricePerSystemYearly: priceSet.pricePerSystemYearly,
        pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
        pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
        pricePerServerMonthly: priceSet.pricePerServerMonthly,
        pricePerServerYearly: priceSet.pricePerServerYearly,
      },
    });

  } catch (err) {
    if (err.status) return res.status(err.status).json({ message: err.message });
    const detail = err?.error || err?.response?.data || err?.message || err;
    console.error('[payment] ❌ create-order failed:', JSON.stringify(detail, null, 2));
    res.status(500).json({
      message: 'Razorpay order creation failed',
      detail: typeof detail === 'object'
        ? (detail.description || detail.error?.description || JSON.stringify(detail))
        : String(detail),
    });
  }
});

// ── POST /api/payment/confirm — verify signature + activate plan ─────────────
router.post('/confirm', authenticate, requireCompanyAdmin, async (req, res) => {
  const {
    razorpay_order_id,
    razorpay_payment_id,
    razorpay_signature,
    systemCount,
    serverCount = 0,
    phoneCount = 0,
    billingCycle = 'monthly',
    isUpgrade = false,
    checkoutFees = false,
    addedSystems = 0,
    addedServers = 0,
    addedPhones = 0,
    autoPay = false,
  } = req.body;

  if (!razorpay_order_id || !razorpay_payment_id || !razorpay_signature) {
    return res.status(400).json({ message: 'Missing Razorpay payment response fields' });
  }

  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(`${razorpay_order_id}|${razorpay_payment_id}`)
    .digest('hex');

  if (expected !== razorpay_signature) {
    console.error('[payment] ❌ Signature mismatch');
    return res.status(400).json({ message: 'Payment verification failed' });
  }

  try {
    const requestedPartnerLicenses = (Number(systemCount) || 0) + (Number(serverCount) || 0) + (Number(phoneCount) || 0);
    await ensurePartnerLicenseStock(req.user.companyId, requestedPartnerLicenses);
    // ✅ Use the correct price set based on isUpgrade flag, scoped to this company partner if present
    const priceSet = await getEffectiveCompanyPricing(req.user.companyId, !!isUpgrade);
    const priceType = isUpgrade ? 'renewal' : 'new-user';
    const baseAmountInr = calcTotal(priceSet, Number(systemCount) || 0, Number(serverCount) || 0, Number(phoneCount) || 0, billingCycle);
    const totals = withCheckoutFees(baseAmountInr, checkoutFees);
    const amountInr = totals.totalInr;

    console.log(`[payment/confirm] 📋 priceType: ${priceType} | sys: ${systemCount} x ₹${priceSet.pricePerSystemMonthly}/mo | srv: ${serverCount} x ₹${priceSet.pricePerServerMonthly}/mo | phone: ${phoneCount} x ₹${priceSet.pricePerPhoneMonthly}/mo | total: ₹${amountInr}`);

    // Calculate expiry date
    const periodStart = new Date();
    const periodEnd = new Date();
    if (billingCycle === 'yearly') {
      periodEnd.setFullYear(periodEnd.getFullYear() + 1);
    } else {
      periodEnd.setMonth(periodEnd.getMonth() + 1);
    }

    const existingCompany = await Company.findById(req.user.companyId).select('plan');
    const inheritedAutoPay = Boolean(autoPay || existingCompany?.plan?.autoPay);
    const inheritedAutoPayMethod = autoPay
      ? razorpay_payment_id
      : (existingCompany?.plan?.autoPayMethod || '');

    // Handle renewal/upgrade: add to existing system/server count
    let finalSystemCount = Number(systemCount);
    let finalServerCount = Number(serverCount);
    let finalPhoneCount = Number(phoneCount);

    if (isUpgrade) {
      finalSystemCount = (existingCompany?.plan?.systemCount || 0) + Number(addedSystems || 0);
      finalServerCount = (existingCompany?.plan?.serverCount || 0) + Number(addedServers || 0);
      finalPhoneCount = (existingCompany?.plan?.phoneCount || 0) + Number(addedPhones || 0);
    }

    const company = await Company.findByIdAndUpdate(
      req.user.companyId,
      {
        'plan.systemCount': finalSystemCount,
        'plan.serverCount': finalServerCount,
        'plan.phoneCount': finalPhoneCount,
        'plan.systemLimit': finalSystemCount + finalServerCount + finalPhoneCount,  // total endpoints
        // ✅ Store base counts at registration time (never overwritten by add-system)
        // Only set if NOT an upgrade (isUpgrade = renewal, not initial registration)
        ...(!isUpgrade && {
          'plan.baseSystemCount': finalSystemCount,
          'plan.baseServerCount': finalServerCount,
          'plan.basePhoneCount': finalPhoneCount,
        }),
        'plan.type': 'custom',
        'plan.isActive': true,
        'plan.startDate': periodStart,
        'plan.expiresAt': periodEnd,
        'plan.billingCycle': billingCycle,
        'plan.amountPaid': amountInr,

        'plan.paymentStatus': 'paid',
        'plan.autoPay': inheritedAutoPay,
        'plan.autoPayMethod': inheritedAutoPay ? inheritedAutoPayMethod : '',
        // ✅ FIX: Store the CORRECT price set (new-user OR renewal) on the plan
        'plan.pricePerSystemMonthly': priceSet.pricePerSystemMonthly,
        'plan.pricePerSystemYearly': priceSet.pricePerSystemYearly,
        'plan.pricePerPhoneMonthly': priceSet.pricePerPhoneMonthly,
        'plan.pricePerPhoneYearly': priceSet.pricePerPhoneYearly,
        'plan.pricePerServerMonthly': priceSet.pricePerServerMonthly,
        'plan.pricePerServerYearly': priceSet.pricePerServerYearly,
        'plan.priceType': priceType,
        'razorpay.orderId': razorpay_order_id,
        'razorpay.paymentId': razorpay_payment_id,
        'razorpay.signature': razorpay_signature,
        'razorpay.paidAt': new Date(),
        status: 'active',
      },
      { new: true }
    );
    await allocatePartnerLicensesToCompany(req.user.companyId, requestedPartnerLicenses);

    const paymentCompany = await Company.findById(req.user.companyId).populate('partnerId');
    const partner = paymentCompany?.partnerId || null;
    const settlement = partner
      ? await createPartnerRouteTransfer({ razorpay_payment_id, amountInr, partner })
      : {
        companyType: 'DIRECT',
        paymentReceiver: 'superadmin_razorpay',
        payoutStatus: 'not_applicable',
        platformCommissionInr: 0,
        partnerPayoutInr: 0,
      };

    // Record payment in history
    PaymentHistory.create({
      companyId: req.user.companyId,
      companyName: company.name,
      partnerId: partner?._id || null,
      partnerName: partner?.name || '',
      orderId: razorpay_order_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'custom',
      systemCount: finalSystemCount,
      serverCount: finalServerCount,
      phoneCount: finalPhoneCount,
      billingCycle,
      amountPaise: amountInr * 100,
      amountInr,
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly: priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly: priceSet.pricePerServerYearly,
      priceType,
      isUpgrade: !!isUpgrade,
      addedSystems: Number(addedSystems || 0),
      addedServers: Number(addedServers || 0),
      addedPhones: Number(addedPhones || 0),
      autoPay: inheritedAutoPay,
      status: 'captured',
      paidAt: new Date(),
      periodStart,
      periodEnd,
      source: isUpgrade ? 'renewal' : 'checkout',
      ...settlement,
    }).catch(e => console.error('[payment/history]', e.message));

    console.log('[payment] ✅ Plan activated | priceType:', priceType, '| systems:', finalSystemCount, '| servers:', finalServerCount, '| company:', req.user.companyId);
    res.json({ success: true, company });
  } catch (err) {
    if (err.status) return res.status(err.status).json({ message: err.message });
    console.error('[payment] ❌ confirm error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/payment/webhook ─────────────────────────────────────────────────
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['x-razorpay-signature'];
  const body = req.body instanceof Buffer ? req.body : Buffer.from(JSON.stringify(req.body));
  const expected = crypto
    .createHmac('sha256', process.env.RAZORPAY_KEY_SECRET)
    .update(body)
    .digest('hex');

  if (sig !== expected) return res.status(400).send('Invalid signature');

  let event;
  try {
    event = typeof req.body === 'string' ? JSON.parse(req.body) : JSON.parse(req.body.toString());
  } catch {
    return res.status(400).send('Bad JSON');
  }

  if (event.event === 'payment.captured') {
    const notes = event.payload.payment.entity.notes || {};
    const companyId = notes.companyId;
    const systemCount = parseInt(notes.systemCount || '0');
    const serverCount = parseInt(notes.serverCount || '0');
    const phoneCount = parseInt(notes.phoneCount || '0');
    const billingCycle = notes.billingCycle || 'monthly';

    if (companyId && (systemCount > 0 || serverCount > 0 || phoneCount > 0)) {
      const periodEnd = new Date();
      if (billingCycle === 'yearly') {
        periodEnd.setFullYear(periodEnd.getFullYear() + 1);
      } else {
        periodEnd.setMonth(periodEnd.getMonth() + 1);
      }

      const pricing = await getCurrentPricing();
      await Company.findByIdAndUpdate(companyId, {
        'plan.systemCount': systemCount,
        'plan.serverCount': serverCount,
        'plan.phoneCount': phoneCount,
        'plan.systemLimit': systemCount + serverCount + phoneCount,
        'plan.type': 'custom',
        'plan.isActive': true,
        'plan.expiresAt': periodEnd,
        'plan.billingCycle': billingCycle,
        'razorpay.paymentId': event.payload.payment.entity.id,
        'razorpay.paidAt': new Date(),
        status: 'active',
      });
    }
  }
  res.json({ received: true });
});

// ── GET /api/payment/status — current plan status ────────────────────────────
router.get('/status', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    const company = await Company.findById(targetCompanyId)
      .select('plan razorpay status name phone partnerId company_type source agentLicenseAllocation');
    if (!company) return res.status(404).json({ message: 'Company not found' });
    const stock = await getPartnerLicenseStock(targetCompanyId);
    const data = company.toObject();
    data.entitlement = await getSubscriptionEntitlement(company);
    data.partnerLicenseStock = stock.limited ? {
      limited: true,
      activeStock: stock.activeStock || 0,
      allocated: stock.allocated || 0,
      available: stock.available || 0,
      companyAllocation: 0,
    } : { limited: false };
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/payment/history — payment history for company ───────────────────
router.get('/history', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    const payments = await PaymentHistory.find({
      companyId: targetCompanyId,
      status: 'captured',
    }).sort({ paidAt: -1 }).limit(20).lean();

    res.json(payments);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/payment/autopay — disable AutoPay only (enabling requires payment via /autopay-order) ──
// ✅ FIX: AutoPay can only be DISABLED freely. To enable, the company must pay the ₹1 mandate fee.
router.post('/autopay', authenticate, requireCompanyAdmin, async (req, res) => {
  const { enabled } = req.body;
  const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
  // Prevent free enabling — must go through /autopay-order + /autopay-confirm
  if (enabled === true || enabled === 'true') {
    return res.status(400).json({
      message: 'AutoPay can only be enabled after completing the ₹1 mandate payment. Use /autopay-order to initiate.',
      requiresPayment: true,
    });
  }
  try {
    const company = await Company.findByIdAndUpdate(
      targetCompanyId,
      { 'plan.autoPay': false },
      { new: true }
    ).select('plan status name');
    await AddSystemSubscription.updateMany(
      { companyId: targetCompanyId, status: 'active', endDate: { $gt: new Date() } },
      { autoPay: false, autoPayMethod: '' }
    );
    console.log('[autopay] ✅ AutoPay DISABLED for company:', targetCompanyId);
    res.json({ success: true, autoPay: false, company });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/payment/autopay-order — create ₹1 Razorpay order for AutoPay mandate ──
// ✅ FIX: AutoPay activation now requires a mandatory ₹1 fee (100 paise)
router.post('/autopay-order', authenticate, requireCompanyAdmin, async (req, res) => {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;

  if (!keyId || !keySecret) {
    return res.status(500).json({ message: 'Razorpay keys missing' });
  }

  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    const razorpay = new Razorpay({ key_id: keyId, key_secret: keySecret });
    const company = await Company.findById(targetCompanyId).select('name plan tenantId partnerId');
    if (!company) return res.status(404).json({ message: 'Company not found' });
    const amountInr = Number(company.plan?.amountPaid || 0);
    if (amountInr <= 0) return res.status(400).json({ message: 'Active paid base plan amount is required before enabling AutoPay.' });
    const { plan, subscription } = await createAutoPaySubscription(razorpay, {
      amountInr,
      billingCycle: company.plan?.billingCycle || 'monthly',
      name: `${company.name || 'Company'} Base Plan AutoPay`,
      notes: {
        companyId: String(targetCompanyId),
        tenantId: company.tenantId ? String(company.tenantId) : '',
        partnerId: company.partnerId ? String(company.partnerId) : '',
        purpose: 'base_plan_autopay_mandate',
      },
    });

    console.log('[autopay] ✅ subscription mandate created:', subscription.id);
    res.json({ subscription, plan, amountInr, purpose: 'autopay_subscription', note: 'Authorize AutoPay in your payment app.' });
  } catch (err) {
    const detail = err?.error || err?.message || err;
    console.error('[autopay-order] ❌', JSON.stringify(detail));
    res.status(500).json({ message: 'Failed to create AutoPay order', detail: String(detail?.description || detail) });
  }
});

// ── POST /api/payment/autopay-confirm — verify ₹1 payment and enable AutoPay ──
router.post('/autopay-confirm', authenticate, requireCompanyAdmin, async (req, res) => {
  const { razorpay_order_id, razorpay_payment_id, razorpay_signature, razorpay_subscription_id } = req.body;

  if (!razorpay_payment_id || !razorpay_signature || !razorpay_subscription_id) {
    return res.status(400).json({ message: 'Missing Razorpay payment fields' });
  }

  if (!verifySubscriptionSignature(razorpay_subscription_id, razorpay_payment_id, razorpay_signature)) {
    return res.status(400).json({ message: 'Payment verification failed' });
  }

  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    const company = await Company.findByIdAndUpdate(
      targetCompanyId,
      {
        'plan.autoPay': true,
        'plan.autoPayMethod': razorpay_subscription_id,
      },
      { new: true }
    ).select('plan status name partnerId tenantId');

    // Record the ₹1 AutoPay activation charge
    PaymentHistory.create({
      companyId: targetCompanyId,
      companyName: company.name,
      partnerId: company.partnerId || null,
      tenantId: company.tenantId || null,
      orderId: razorpay_subscription_id,
      paymentId: razorpay_payment_id,
      signature: razorpay_signature,
      planType: 'autopay_activation',
      amountPaise: Math.round(Number(company.plan?.amountPaid || 0) * 100),
      amountInr: Number(company.plan?.amountPaid || 0),
      status: 'captured',
      paidAt: new Date(),
      source: 'autopay',
      notes: { purpose: 'Base plan AutoPay mandate', razorpay_subscription_id },
    }).catch(e => console.error('[autopay-confirm/history]', e.message));

    console.log('[autopay] ✅ AutoPay enabled for company:', targetCompanyId, '| ₹1 fee charged');
    res.json({ success: true, autoPay: true, company });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/payment/renewal-pricing — returns renewal prices (for company dashboard) ─
// ✅ FIX: Separate endpoint so company dashboard shows RENEWAL pricing (not new-user pricing)
router.get('/renewal-pricing', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    const priceSet = await getEffectiveCompanyPricing(targetCompanyId, true);
    res.json({
      pricePerSystemMonthly: priceSet.pricePerSystemMonthly,
      pricePerSystemYearly: priceSet.pricePerSystemYearly,
      pricePerPhoneMonthly: priceSet.pricePerPhoneMonthly,
      pricePerPhoneYearly: priceSet.pricePerPhoneYearly,
      pricePerServerMonthly: priceSet.pricePerServerMonthly,
      pricePerServerYearly: priceSet.pricePerServerYearly,
      priceType: 'renewal',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/payment/test — diagnose Razorpay config ─────────────────────────
router.get('/test', authenticate, async (req, res) => {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const keySecret = process.env.RAZORPAY_KEY_SECRET;
  const info = {
    keyId_present: !!keyId,
    keySecret_present: !!keySecret,
    keyId_prefix: keyId ? keyId.slice(0, 12) + '...' : 'MISSING',
    keyId_mode: keyId?.startsWith('rzp_live') ? 'LIVE' : keyId?.startsWith('rzp_test') ? 'TEST' : 'UNKNOWN',
    razorpay_installed: false,
    order_test: null,
    error: null,
  };

  try {
    const Razorpay = require('razorpay');
    info.razorpay_installed = true;
    const rzp = new Razorpay({ key_id: keyId, key_secret: keySecret });
    const order = await rzp.orders.create({ amount: 100, currency: 'INR', receipt: 'test_' + Date.now() });
    info.order_test = { success: true, orderId: order.id };
  } catch (err) {
    info.error = err?.error || err?.message || String(err);
    info.razorpay_installed = true;
  }

  res.json(info);
});

module.exports = router;
