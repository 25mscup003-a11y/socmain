const router = require('express').Router();
const crypto = require('crypto');
const Company = require('../models/Company.model');
const { emitCompanySupport, validSupportId, supportText } = require('../utils/companySupport');
const Partner = require('../models/Partner.model');
const User = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const { SOC_ROLES } = require('../services/socAccess.service');
const Referral = require('../models/Referral.model');
const System = require('../models/System.model');
const { getPartnerCompanies, summarizePartnerCompanies, partnerScope, companyPaymentScope } = require('../services/partnerDashboard.service');
const Pricing = require('../models/Pricing.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const Department = require('../models/Department.model');
const Alert = require('../models/Alert.model');
const PartnerNotification = require('../models/PartnerNotification.model');
const PartnerSupportTicket = require('../models/PartnerSupportTicket.model');
const ipsEngine = require('../services/ipsEngine.service');
const { authenticate, requirePartnerAdmin } = require('../middleware/auth.middleware');
const { buildRegistrationUrl } = require('../utils/tenant');
const { registerPartner } = require('../controllers/partnerRegistration.controller');
const { partnerDocUpload, partnerAvatarUpload, UPLOAD_ROOT } = require('../middleware/upload.middleware');
const path = require('path');
const fs = require('fs');

const apiBase = process.env.API_BASE_URL || 'http://localhost:5000/api';
const serverBase = apiBase.replace(/\/api\/?$/, '');
const toFileUrl = (filePath) => filePath ? `${serverBase}/uploads/${filePath}` : '';
const titleStatus = value => String(value || 'pending').replace(/_/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
const pricingKeys = [
  'pricePerSystemMonthly',
  'pricePerSystemYearly',
  'pricePerPhoneMonthly',
  'pricePerPhoneYearly',
  'pricePerServerMonthly',
  'pricePerServerYearly',
];
const defaultCompanyPricing = {
  newUser: {
    pricePerSystemMonthly: 200,
    pricePerSystemYearly: 2000,
    pricePerPhoneMonthly: 200,
    pricePerPhoneYearly: 2000,
    pricePerServerMonthly: 500,
    pricePerServerYearly: 5000,
  },
  renewal: {
    pricePerSystemMonthly: 200,
    pricePerSystemYearly: 2000,
    pricePerPhoneMonthly: 200,
    pricePerPhoneYearly: 2000,
    pricePerServerMonthly: 500,
    pricePerServerYearly: 5000,
  },
};
const pricingSetFromGlobal = (pricing, key) => {
  const prefix = key === 'renewal' ? 'renewal' : 'newUser';
  return {
    pricePerSystemMonthly: Number(pricing?.[`${prefix}_pricePerSystemMonthly`] || defaultCompanyPricing[key].pricePerSystemMonthly),
    pricePerSystemYearly: Number(pricing?.[`${prefix}_pricePerSystemYearly`] || defaultCompanyPricing[key].pricePerSystemYearly),
    pricePerPhoneMonthly: Number(pricing?.[`${prefix}_pricePerPhoneMonthly`] || defaultCompanyPricing[key].pricePerPhoneMonthly),
    pricePerPhoneYearly: Number(pricing?.[`${prefix}_pricePerPhoneYearly`] || defaultCompanyPricing[key].pricePerPhoneYearly),
    pricePerServerMonthly: Number(pricing?.[`${prefix}_pricePerServerMonthly`] || defaultCompanyPricing[key].pricePerServerMonthly),
    pricePerServerYearly: Number(pricing?.[`${prefix}_pricePerServerYearly`] || defaultCompanyPricing[key].pricePerServerYearly),
  };
};
const hasPartnerPricingSet = (set = {}) => pricingKeys.some(key => Number(set?.[key] || 0) > 0);
async function ensurePartnerCompanyPricing(partner) {
  if (!partner) return null;
  const globalPricing = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 }).lean();
  partner.companyPricing = partner.companyPricing || {};
  if (!hasPartnerPricingSet(partner.companyPricing.newUser)) {
    partner.companyPricing.newUser = pricingSetFromGlobal(globalPricing, 'newUser');
  }
  if (!hasPartnerPricingSet(partner.companyPricing.renewal)) {
    partner.companyPricing.renewal = pricingSetFromGlobal(globalPricing, 'renewal');
  }
  partner.companyPricing.history = partner.companyPricing.history || [];
  return partner.companyPricing;
}
const partnerPricingResponse = partner => ({
  newUser: partner.companyPricing?.newUser || defaultCompanyPricing.newUser,
  renewal: partner.companyPricing?.renewal || defaultCompanyPricing.renewal,
  updatedAt: partner.companyPricing?.updatedAt || partner.updatedAt,
});
const KYC_DOC_TYPES = new Set(['gstCertificate', 'panCard', 'businessRegistration']);
const KYC_DOC_FIELDS = new Set([
  'gstCertificateName',
  'gstCertificateType',
  'gstCertificateFilePath',
  'gstCertificateDataUrl',
  'panCardName',
  'panCardType',
  'panCardFilePath',
  'panCardDataUrl',
  'businessRegistrationName',
  'businessRegistrationType',
  'businessRegistrationFilePath',
  'businessRegistrationDataUrl',
]);
const recalcAgentLicenses = (partner) => {
  if (!partner) return null;
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
const cleanOriginalName = value => String(value || '')
  .replace(/%0A/gi, ' ')
  .replace(/[\r\n]+/g, ' ')
  .replace(/\s+/g, ' ')
  .trim();
const uploadPathExists = (relativePath) => {
  const cleanPath = String(relativePath || '').replace(/^\/+/, '');
  if (!cleanPath) return false;
  const uploadRoot = path.resolve(UPLOAD_ROOT);
  const uploadPath = path.resolve(UPLOAD_ROOT, cleanPath);
  return uploadPath.startsWith(uploadRoot + path.sep) && fs.existsSync(uploadPath);
};
const sanitizePartnerKycDocuments = (partner) => {
  const docs = partner?.profile?.kycDocuments;
  if (!docs) return partner;
  KYC_DOC_TYPES.forEach(docType => {
    const nameKey = `${docType}Name`;
    const typeKey = `${docType}Type`;
    const pathKey = `${docType}FilePath`;
    const dataKey = `${docType}DataUrl`;
    const hasStoredFile = uploadPathExists(docs[pathKey]);
    if (hasStoredFile) return;
    docs[nameKey] = '';
    docs[typeKey] = '';
    docs[pathKey] = '';
    docs[dataKey] = '';
  });
  return partner;
};
const sanitizePartnerUploadedFiles = (partner) => {
  if (!partner) return partner;
  if (partner.agreementFilePath && !uploadPathExists(partner.agreementFilePath)) {
    partner.agreementFileName = '';
    partner.agreementFileType = '';
    partner.agreementFilePath = '';
  }
  return sanitizePartnerKycDocuments(partner);
};

router.post('/register', registerPartner);

router.use(authenticate, requirePartnerAdmin, (req, res, next) => {
  if (req.user.role === 'partner_admin' && !/^[a-f\d]{24}$/i.test(String(req.user.partnerId || ''))) {
    return res.status(403).json({ message: 'A linked partner account is required' });
  }
  next();
});

router.use('/user-accounts', require('./partner-user-access.routes'));
router.use('/enterprise-plans', require('./enterprise-management.routes')('partner'));

// ── POST /partner/upload-doc — KYC document upload (PDF/image) ─────────────
router.post('/upload-doc', partnerDocUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const filePath = `partner-docs/${req.file.filename}`;
    const fileUrl  = toFileUrl(filePath);
    const { docType } = req.body; // e.g. 'gstCertificate', 'panCard', 'businessRegistration'
    if (!KYC_DOC_TYPES.has(docType)) {
      return res.status(400).json({ message: 'Invalid KYC document type' });
    }
    const updatedPartner = await Partner.findByIdAndUpdate(req.user.partnerId, {
      $set: {
        [`profile.kycDocuments.${docType}Name`]: cleanOriginalName(req.file.originalname),
        [`profile.kycDocuments.${docType}Type`]: req.file.mimetype,
        [`profile.kycDocuments.${docType}FilePath`]: filePath,
        [`profile.kycDocuments.${docType}DataUrl`]: '',
        'profile.kycStatus': 'pending',
      },
    }, { new: true });
    if (!updatedPartner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, updatedPartner._id, 'profile_updated', { partner: updatedPartner });
    res.json({ success: true, filePath, fileUrl, originalName: cleanOriginalName(req.file.originalname), partner: updatedPartner });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /partner/upload-avatar — Profile image upload ─────────────────────
router.post('/upload-avatar', partnerAvatarUpload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: 'No file uploaded' });
    const filePath = `partner-avatars/${req.file.filename}`;
    const fileUrl  = toFileUrl(filePath);
    const partner = await Partner.findById(req.user.partnerId);
    let updatedPartner = null;
    if (partner) {
      partner.profile = partner.profile || {};
      partner.profile.avatarFileName = cleanOriginalName(req.file.originalname);
      partner.profile.avatarFilePath = filePath;
      partner.profile.avatarDataUrl   = ''; // clear old base64
      partner.markModified('profile');
      updatedPartner = await partner.save();
      emitPartnerRealtime(req, updatedPartner._id, 'profile_updated', { partner: updatedPartner });
    }
    res.json({ success: true, filePath, fileUrl, originalName: cleanOriginalName(req.file.originalname), partner: updatedPartner });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

function emitPartnerRealtime(req, partnerId, type, payload = {}) {
  const io = req.app.get('io');
  if (!io || !partnerId) return;
  const data = { type, partnerId: String(partnerId), ...payload, ts: new Date().toISOString() };
  io.to('superadmin').emit('partner:update', data);
  io.to(`partner:${partnerId}`).emit('partner:update', data);
}

function normalizeResourceRequestHistory(partner) {
  const history = Array.isArray(partner?.resourceRequestHistory) ? partner.resourceRequestHistory : [];
  const resource = partner?.resourceRequest || {};
  if (!resource.status || resource.status === 'none') return history;
  const current = {
    requestId: `REQ-${String(partner?._id || '000001').slice(-6).toUpperCase()}`,
    status: resource.status,
    numberOfCompanies: resource.numberOfCompanies || 0,
    numberOfAgents: resource.numberOfAgents || 0,
    expectedMonthlyVolume: resource.expectedMonthlyVolume || 0,
    proposedCommission: resource.proposedCommission || 0,
    additionalNotes: resource.additionalNotes || '',
    adminNote: resource.adminNote || '',
    requestedAt: resource.requestedAt || partner.createdAt,
    reviewedAt: resource.reviewedAt || null,
    reviewedBy: resource.reviewedBy || null,
  };
  if (!history.length) return [current];

  const currentRequestedAt = new Date(current.requestedAt || 0).getTime();
  const currentIndex = history.findIndex(item => (
    new Date(item.requestedAt || 0).getTime() === currentRequestedAt &&
    Number(item.numberOfCompanies || 0) === Number(current.numberOfCompanies || 0) &&
    Number(item.numberOfAgents || 0) === Number(current.numberOfAgents || 0)
  ));

  if (currentIndex >= 0) {
    return history.map((item, index) => (index === currentIndex ? { ...item, ...current, requestId: item.requestId || current.requestId } : item));
  }
  return [...history, current];
}

async function withTimeout(promise, fallback, ms = 10000) {
  let timer;
  try {
    return await Promise.race([promise, new Promise(resolve => { timer = setTimeout(() => resolve(fallback), ms); })]);
  } catch {
    return fallback;
  } finally {
    clearTimeout(timer);
  }
}

async function requireActivePartnerPlan(req, res, next) {
  if (req.user.role === 'superadmin') return next();
  const Partner = require('../models/Partner.model');
  const partner = await withTimeout(
    Partner.findById(req.user.partnerId).select('status plan').lean(),
    undefined,
    3000
  );
  if (partner === undefined) return res.status(503).json({ message: 'Partner account could not be verified. Please retry.' });
  if (!partner) return res.status(404).json({ message: 'Partner not found' });
  if (!['approved', 'pending_quote', 'pending_payment', 'active'].includes(partner.status)) {
    return res.status(403).json({
      message: 'Partner account is not approved yet',
      approvalRequired: true,
      partner,
    });
  }
  if (!(partner.plan?.paymentStatus === 'paid' && partner.plan?.isActive === true)) {
    return res.status(403).json({
      message: 'Platform Commission payment required before partner dashboard access',
      paymentRequired: true,
      partner,
    });
  }
  next();
}

async function requireApprovedPartner(req, res, next) {
  if (req.user.role === 'superadmin') return next();
  const Partner = require('../models/Partner.model');
  const partner = await withTimeout(
    Partner.findById(req.user.partnerId).select('status plan').lean(),
    undefined,
    3000
  );
  if (partner === undefined) return res.status(503).json({ message: 'Partner account could not be verified. Please retry.' });
  if (!partner) return res.status(404).json({ message: 'Partner not found' });
  if (!['approved', 'pending_quote', 'pending_payment', 'active'].includes(partner.status)) {
    return res.status(403).json({
      message: 'Partner account is not approved yet',
      approvalRequired: true,
      partner,
    });
  }
  next();
}

const ownPartnerFilter = (req) => {
  if (req.user.role === 'superadmin') return {};
  if (req.user.partnerId) return { partnerId: req.user.partnerId };
  return { _id: { $in: [] } };
};

router.get('/dashboard', requireApprovedPartner, async (req, res) => {
  try {
    const filter = partnerScope(req.user.partnerId);
    const partner = await Partner.findById(req.user.partnerId)
      .select('-profile.avatarDataUrl -profile.kycDocuments.gstCertificateDataUrl -profile.kycDocuments.panCardDataUrl -profile.kycDocuments.businessRegistrationDataUrl')
      .populate('ownerUserId', 'name email phone role forcePasswordReset').lean();
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    const [companies, users, referrals, platformPayments] = await Promise.all([
      getPartnerCompanies(req.user.partnerId),
      User.countDocuments(filter),
      Referral.countDocuments(filter),
      PaymentHistory.find({ ...filter, $or: [{ source: 'partner_checkout' }, { planType: 'partner_enterprise' }] })
        .sort({ paidAt: -1, createdAt: -1 }).limit(20).lean(),
    ]);
    const summary = summarizePartnerCompanies(companies);
    const latestSettlement = await PaymentHistory.findOne({
      ...companyPaymentScope(req.user.partnerId, companies.map(company => company._id)),
      status: 'captured', companyType: 'PARTNER_MANAGED',
    }).sort({ paidAt: -1, createdAt: -1 })
      .select('payoutStatus settlementDate transferId transferStatus transferError partnerLinkedAccountId').lean();
    recalcAgentLicenses(partner);
    const cleanPartner = sanitizePartnerUploadedFiles(partner);
    res.json({
      ...summary,
      partner: cleanPartner, capabilities: partner.capabilities || {},
      resourceRequest: partner.resourceRequest || {},
      resourceRequestHistory: normalizeResourceRequestHistory(cleanPartner),
      companies: summary.companyCount, users, referrals,
      monthlyRevenue: summary.paidRevenue,
      settlement: {
        totalCollection: summary.paidRevenue,
        platformCommission: summary.platformCommission,
        partnerPayout: summary.partnerProfit,
        payoutStatus: latestSettlement?.payoutStatus || 'not_applicable',
        settlementDate: latestSettlement?.settlementDate || null,
        transferId: latestSettlement?.transferId || '',
        transferStatus: latestSettlement?.transferStatus || '',
        transferError: latestSettlement?.transferError || '',
        partnerLinkedAccountId: latestSettlement?.partnerLinkedAccountId || partner.partner_linked_account_id || '',
      },
      platformPayments,
      agentLicenses: partner.agentLicensePurchases || [],
      agentLicenseSummary: partner.agentLicenseSummary || {},
      agentPricing: partner.agentPricing || {},
      updatedAt: new Date().toISOString(),
    });
  } catch (err) {
    res.status(503).json({ message: 'Partner dashboard could not be refreshed. Please retry.' });
  }
});

router.get('/pricing', authenticate, requirePartnerAdmin, async (req, res) => {
  try {
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    await ensurePartnerCompanyPricing(partner);
    await partner.save();
    res.json(partnerPricingResponse(partner));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.put('/pricing', authenticate, requirePartnerAdmin, async (req, res) => {
  const { note } = req.body;
  if (!['new-user', 'renewal-existing'].includes(note)) {
    return res.status(400).json({ message: 'note must be "new-user" or "renewal-existing"' });
  }
  for (const key of pricingKeys) {
    const value = req.body[key];
    if (value === undefined || value === '' || isNaN(Number(value)) || Number(value) < 0) {
      return res.status(400).json({ message: `${key} must be a valid non-negative number` });
    }
  }
  try {
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    await ensurePartnerCompanyPricing(partner);
    const setKey = note === 'renewal-existing' ? 'renewal' : 'newUser';
    const previous = partner.companyPricing[setKey] || {};
    partner.companyPricing.history = partner.companyPricing.history || [];
    partner.companyPricing.history.unshift({
      userType: note,
      ...pricingKeys.reduce((acc, key) => ({ ...acc, [key]: Number(previous[key] || 0) }), {}),
      changedAt: new Date(),
      changedBy: req.user.id,
      note,
    });
    partner.companyPricing.history = partner.companyPricing.history.slice(0, 20);
    partner.companyPricing[setKey] = pricingKeys.reduce((acc, key) => ({ ...acc, [key]: Number(req.body[key]) }), {});
    partner.companyPricing.updatedAt = new Date();
    partner.markModified('companyPricing');
    await partner.save();
    res.json({ success: true, note, pricing: partnerPricingResponse(partner) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/pricing/history', authenticate, requirePartnerAdmin, async (req, res) => {
  try {
    const partner = await Partner.findById(req.user.partnerId)
      .populate('companyPricing.history.changedBy', 'name email');
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    await ensurePartnerCompanyPricing(partner);
    res.json({ history: partner.companyPricing?.history || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.delete('/pricing/history/:index', authenticate, requirePartnerAdmin, async (req, res) => {
  const idx = parseInt(req.params.index, 10);
  try {
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    await ensurePartnerCompanyPricing(partner);
    const history = partner.companyPricing.history || [];
    if (idx < 0 || idx >= history.length) return res.status(400).json({ message: 'Invalid index' });
    history.splice(idx, 1);
    partner.companyPricing.history = history;
    partner.markModified('companyPricing');
    await partner.save();
    res.json({ success: true, history: partner.companyPricing.history || [] });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/revenue/history', requireActivePartnerPlan, async (req, res) => {
  try {
    const companies = await Company.find(partnerScope(req.user.partnerId)).select('_id').lean();
    if (!companies.length) return res.json([]);
    const payments = await PaymentHistory.find(companyPaymentScope(req.user.partnerId, companies.map(company => company._id)))
      .populate('companyId', 'name email plan.autoPay')
      .sort({ paidAt: -1, createdAt: -1 })
      .lean();

    res.json(payments.filter(payment => payment.companyId).map(payment => ({
      id: payment._id,
      companyId: payment.companyId._id,
      company: payment.companyName || payment.companyId?.name || 'Company',
      email: payment.companyId?.email || '',
      paymentId: payment.paymentId || payment.orderId || '-',
      amount: Number(payment.amountInr || 0),
      status: payment.status || 'unpaid',
      date: payment.paidAt || payment.createdAt,
      cycle: payment.billingCycle || 'monthly',
      autoPay: Boolean(payment.autoPay || payment.companyId?.plan?.autoPay),
      source: payment.source || '',
      planType: payment.planType || '',
    })));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/staff', requireActivePartnerPlan, async (req, res) => {
  if (req.user.role !== 'partner_admin') {
    return res.status(403).json({ message: 'A linked partner account is required' });
  }
  try {
    const scope = partnerScope(req.user.partnerId);
    const companyIds = await Company.find(scope).distinct('_id');
    const assignedUserIds = companyIds.length
      ? await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId')
      : [];
    const staff = await User.find({
      role: { $in: [...SOC_ROLES, 'analyst'] },
      superadminManaged: { $ne: true },
      partnerId: { $in: [scope.partnerId, null] },
      $or: [
        scope,
        { companyId: { $in: companyIds } },
        { _id: { $in: assignedUserIds } },
      ],
    }).select('name email role isActive accountStatus').sort({ role: 1, name: 1 }).lean();
    res.json(staff);
  } catch (err) {
    res.status(503).json({ message: 'Partner staff could not be loaded. Please retry.' });
  }
});

router.get('/companies', requireActivePartnerPlan, async (req, res) => {
  try {
    res.json(await getPartnerCompanies(req.user.partnerId));
  } catch (err) {
    res.status(503).json({ message: 'Partner companies could not be refreshed. Please retry.' });
  }
});

// ── GET /partner/companies/:companyId ──
router.get('/companies/:companyId', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const company = await Company.findOne({ _id: companyId, partnerId: req.user.partnerId }).lean();
    if (!company) return res.status(404).json({ message: 'Company not found under this partner' });
    res.json(company);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/departments ──
router.get('/companies/:companyId/departments', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const departments = await Department.find({ companyId, isActive: true }).sort({ name: 1 }).lean();
    res.json(departments);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/systems ──
router.get('/companies/:companyId/systems', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const systems = await System.find({ companyId }).sort({ hostname: 1 }).lean();
    res.json(systems);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/users ──
router.get('/companies/:companyId/users', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const users = await User.find({ companyId, superadminManaged: { $ne: true } }).select('-password').sort({ name: 1 }).lean();
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/alerts ──
router.get('/companies/:companyId/alerts', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const alerts = await Alert.find({ companyId }).sort({ createdAt: -1 }).limit(100).lean();
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/add-system-subscriptions ──
router.get('/companies/:companyId/add-system-subscriptions', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const AddSystemSubscription = require('../models/AddSystemSubscription.model');
    const list = await AddSystemSubscription.find({ companyId })
      .sort({ paidAt: -1, createdAt: -1 })
      .limit(100)
      .lean();
    res.json(list);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /partner/companies/:companyId/audit ──
router.get('/companies/:companyId/audit', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const companyExists = await Company.exists({ _id: companyId, partnerId: req.user.partnerId });
    if (!companyExists) return res.status(404).json({ message: 'Company not found under this partner' });
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit) || 300));
    const events = await ipsEngine.getAuditEvents(companyId, limit);
    res.json({ ok: true, events, count: events.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.patch('/companies/:companyId/payment', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const paymentStatus = String(req.body.paymentStatus || '').toLowerCase();
    const allowed = new Set(['paid', 'unpaid', 'failed']);
    if (!allowed.has(paymentStatus)) return res.status(400).json({ message: 'paymentStatus must be paid, unpaid, or failed' });

    const company = await Company.findOne({ _id: companyId, partnerId: req.user.partnerId });
    if (!company) {
      console.warn('[partner/payment-update] blocked scope mismatch', { partnerId: String(req.user.partnerId), companyId });
      return res.status(404).json({ message: 'Company not found under this partner' });
    }

    const amountPaid = Math.max(Number(req.body.amountPaid || company.plan?.amountPaid || 0), 0);
    if (paymentStatus === 'paid' && amountPaid <= 0) {
      return res.status(400).json({ message: 'Paid status ke liye amountPaid required hai' });
    }
    const now = new Date();
    const periodEnd = new Date(now);
    const billingCycle = req.body.billingCycle || company.plan?.billingCycle || 'monthly';
    if (billingCycle === 'yearly') periodEnd.setFullYear(periodEnd.getFullYear() + 1);
    else periodEnd.setMonth(periodEnd.getMonth() + 1);

    const update = {
      'plan.paymentStatus': paymentStatus,
      'plan.amountPaid': paymentStatus === 'paid' ? amountPaid : 0,
      'plan.isActive': paymentStatus === 'paid',
      'plan.billingCycle': billingCycle,
      status: paymentStatus === 'paid' ? 'active' : 'pending_payment',
    };
    if (paymentStatus === 'paid') {
      update['plan.startDate'] = company.plan?.startDate || now;
      update['plan.expiresAt'] = req.body.expiresAt ? new Date(req.body.expiresAt) : periodEnd;
      update['razorpay.paidAt'] = now;
    }

    const updatedCompany = await Company.findOneAndUpdate(
      { _id: companyId, partnerId: req.user.partnerId },
      update,
      { new: true }
    );

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: updatedCompany._id,
      email: req.user.email,
      action: 'company_payment_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const CompanyNotification = require('../models/CompanyNotification.model');
    await CompanyNotification.create({
      companyId: updatedCompany._id,
      title: 'Payment Status Updated',
      message: `Your company plan payment status has been updated to ${paymentStatus.toUpperCase()} by Partner Admin.`,
      source: 'partner'
    });

    let payment = null;
    if (paymentStatus === 'paid' && amountPaid > 0) {
      payment = await PaymentHistory.create({
        companyId: updatedCompany._id,
        companyName: updatedCompany.name,
        partnerId: req.user.partnerId,
        tenantId: req.user.tenantId,
        amountInr: amountPaid,
        amountPaise: Math.round(amountPaid * 100),
        billingCycle,
        status: 'captured',
        paidAt: now,
        periodStart: update['plan.startDate'],
        periodEnd: update['plan.expiresAt'],
        source: 'manual',
        planType: 'partner_manual_update',
        companyType: 'PARTNER_MANAGED',
        notes: {
          updatedBy: req.user.id,
          reason: String(req.body.reason || 'Partner admin payment update').trim(),
        },
      });
    }

    console.log('[partner/payment-update]', {
      partnerId: String(req.user.partnerId),
      companyId: String(updatedCompany._id),
      paymentStatus,
      amountPaid,
      createdHistory: Boolean(payment),
    });
    emitPartnerRealtime(req, req.user.partnerId, 'company_payment_updated', { company: updatedCompany, payment });
    res.json({ success: true, company: updatedCompany, payment });
  } catch (err) {
    console.error('[partner/payment-update] failed', err.message);
    res.status(500).json({ message: err.message });
  }
});

router.patch('/companies/:companyId/autopay', requireActivePartnerPlan, async (req, res) => {
  try {
    const { companyId } = req.params;
    const enabled = req.body.enabled === true || req.body.enabled === 'true';
    const company = await Company.findOne({ _id: companyId, partnerId: req.user.partnerId });
    if (!company) {
      console.warn('[partner/autopay-update] blocked scope mismatch', { partnerId: String(req.user.partnerId), companyId });
      return res.status(404).json({ message: 'Company not found under this partner' });
    }

    const updatedCompany = await Company.findOneAndUpdate(
      { _id: companyId, partnerId: req.user.partnerId },
      {
        'plan.autoPay': enabled,
        'plan.autoPayMethod': enabled ? 'partner_admin_control' : '',
      },
      { new: true }
    );

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: updatedCompany._id,
      email: req.user.email,
      action: 'company_autopay_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const CompanyNotification = require('../models/CompanyNotification.model');
    await CompanyNotification.create({
      companyId: updatedCompany._id,
      title: 'AutoPay Status Changed',
      message: `Your company AutoPay settings have been ${enabled ? 'ENABLED' : 'DISABLED'} by Partner Admin.`,
      source: 'partner'
    });

    await PaymentHistory.updateMany(
      { companyId: updatedCompany._id, partnerId: req.user.partnerId },
      { $set: { autoPay: enabled, 'notes.autoPay': enabled } }
    );

    console.log('[partner/autopay-update]', {
      partnerId: String(req.user.partnerId),
      companyId: String(updatedCompany._id),
      enabled,
    });
    emitPartnerRealtime(req, req.user.partnerId, 'company_autopay_updated', { company: updatedCompany, enabled });
    res.json({ success: true, autoPay: enabled, company: updatedCompany });
  } catch (err) {
    console.error('[partner/autopay-update] failed', err.message);
    res.status(500).json({ message: err.message });
  }
});

router.patch('/agent-license/allocation', requireActivePartnerPlan, async (req, res) => {
  try {
    const companyId = req.body.companyId;
    const allocation = Math.max(Number(req.body.allocation || 0), 0);
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    recalcAgentLicenses(partner);
    const companies = await Company.find({ partnerId: req.user.partnerId }).select('agentLicenseAllocation').lean();
    const currentTotal = companies.reduce((sum, company) => sum + Number(company.agentLicenseAllocation || 0), 0);
    const currentCompany = companies.find(company => String(company._id) === String(companyId));
    if (!currentCompany) return res.status(404).json({ message: 'Company not found under this partner' });
    const nextTotal = currentTotal - Number(currentCompany.agentLicenseAllocation || 0) + allocation;
    if (nextTotal > Number(partner.agentLicenseSummary?.totalPurchased || 0)) {
      return res.status(400).json({ message: 'Allocation exceeds total purchased agent licenses' });
    }
    const company = await Company.findOneAndUpdate({ _id: companyId, partnerId: req.user.partnerId }, { agentLicenseAllocation: allocation }, { new: true });
    emitPartnerRealtime(req, partner._id, 'agent_license_allocated', { partner });
    res.json({ success: true, company });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/agent-license/autopay/:purchaseId', requireActivePartnerPlan, async (req, res) => {
  try {
    const { purchaseId } = req.params;
    const enabled = req.body.enabled === true || req.body.enabled === 'true';
    const partner = await Partner.findById(req.user.partnerId);
    if (!partner) return res.status(404).json({ message: 'Partner not found' });

    const purchases = Array.isArray(partner.agentLicensePurchases) ? partner.agentLicensePurchases : [];
    const purchase = purchases.find(item => (
      String(item._id) === String(purchaseId) ||
      String(item.invoiceId || '') === String(purchaseId) ||
      String(item.paymentId || '') === String(purchaseId)
    ));
    if (!purchase) return res.status(404).json({ message: 'Agent license payment not found' });

    purchase.autoPay = enabled;
    if (!enabled && purchase.paymentId) {
      await PaymentHistory.updateOne(
        { partnerId: partner._id, paymentId: purchase.paymentId },
        { $set: { autoPay: false, 'notes.autoPay': false } }
      );
    }
    const anyEnabled = purchases.some(item => item.autoPay);
    partner.agentLicenseAutoPay = partner.agentLicenseAutoPay || {};
    partner.agentLicenseAutoPay.enabled = anyEnabled;
    if (!anyEnabled) partner.agentLicenseAutoPay.disabledAt = new Date();
    if (enabled) partner.agentLicenseAutoPay.enabledAt = partner.agentLicenseAutoPay.enabledAt || new Date();

    recalcAgentLicenses(partner);
    await partner.save();
    emitPartnerRealtime(req, partner._id, 'agent_license_autopay_updated', { partner });
    res.json({
      success: true,
      partner,
      agentLicenses: partner.agentLicensePurchases,
      agentLicenseSummary: partner.agentLicenseSummary,
      agentLicenseAutoPay: partner.agentLicenseAutoPay,
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.get('/agents', requireActivePartnerPlan, async (req, res) => {
  try {
    const users = await User.find({
      ...ownPartnerFilter(req),
      role: { $in: ['company_admin', 'department_admin', 'analyst'] },
    }).populate('companyId', 'name').sort({ createdAt: -1 });
    res.json(users);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/notifications', requireActivePartnerPlan, async (req, res) => {
  try {
    const filter = { partnerId: req.user.partnerId };
    const [items, unread] = await Promise.all([
      PartnerNotification.find(filter).sort({ createdAt: -1 }).limit(50).lean(),
      PartnerNotification.countDocuments({ ...filter, read: false }),
    ]);
    res.json({ items, unread });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.patch('/notifications/read', requireActivePartnerPlan, async (req, res) => {
  try {
    const ids = Array.isArray(req.body.ids) ? req.body.ids : [];
    const filter = { partnerId: req.user.partnerId };
    if (ids.length) filter._id = { $in: ids };
    await PartnerNotification.updateMany(filter, { read: true });
    const unread = await PartnerNotification.countDocuments({ partnerId: req.user.partnerId, read: false });
    res.json({ success: true, unread });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// GET /api/partner/company-support-tickets
router.get('/company-support-tickets', requireActivePartnerPlan, async (req, res) => {
  try {
    if (req.user.role !== 'partner_admin' || !validSupportId(String(req.user.partnerId || ''))) return res.status(403).json({ message: 'Partner account required for partner company support.' });
    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const companies = await Company.find({ partnerId: req.user.partnerId }).select('_id').lean();
    const companyIds = companies.map(c => c._id);

    const query = { companyId: { $in: companyIds } };
    if (req.query.companyId) {
      if (!validSupportId(req.query.companyId)) return res.status(400).json({ message: 'Invalid company ID' });
      if (!companyIds.some(id => String(id) === req.query.companyId)) return res.status(403).json({ message: 'Access denied' });
      query.companyId = req.query.companyId;
    }

    const tickets = await CompanySupportTicket.find(query)
      .populate('companyId', 'name')
      .sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/partner/company-support-tickets/:ticketId/messages
router.post('/company-support-tickets/:ticketId/messages', requireActivePartnerPlan, async (req, res) => {
  try {
    if (req.user.role !== 'partner_admin' || !validSupportId(String(req.user.partnerId || ''))) return res.status(403).json({ message: 'Partner account required for partner company support.' });
    if (!validSupportId(req.params.ticketId)) return res.status(400).json({ message: 'Invalid ticket ID' });
    const message = supportText(req.body.message, 10000);
    if (!message) return res.status(400).json({ message: 'Message must contain 1–10,000 characters.' });

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticket = await CompanySupportTicket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    const company = await Company.findOne({ _id: ticket.companyId, partnerId: req.user.partnerId });
    if (!company) return res.status(403).json({ message: 'Access denied' });

    if (ticket.status === 'Closed') return res.status(409).json({ message: 'Reopen this ticket before replying.' });
    ticket.messages.push({
      senderId: req.user.id,
      senderName: req.user.name || req.user.email,
      senderRole: req.user.role,
      message,
    });
    if (ticket.status === 'Open') {
      ticket.status = 'In Progress';
    }
    await ticket.save();

    emitCompanySupport(req, company, 'support:message_new', ticket);

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PATCH /api/partner/company-support-tickets/:ticketId/status
router.patch('/company-support-tickets/:ticketId/status', requireActivePartnerPlan, async (req, res) => {
  try {
    if (req.user.role !== 'partner_admin' || !validSupportId(String(req.user.partnerId || ''))) return res.status(403).json({ message: 'Partner account required for partner company support.' });
    if (!validSupportId(req.params.ticketId)) return res.status(400).json({ message: 'Invalid ticket ID' });
    const { status } = req.body;
    if (!status || !['Open', 'In Progress', 'Resolved', 'Closed'].includes(status)) {
      return res.status(400).json({ message: 'Valid status required' });
    }

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticket = await CompanySupportTicket.findById(req.params.ticketId);
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    const company = await Company.findOne({ _id: ticket.companyId, partnerId: req.user.partnerId });
    if (!company) return res.status(403).json({ message: 'Access denied' });

    ticket.status = status;
    await ticket.save();

    emitCompanySupport(req, company, 'support:ticket_updated', ticket);

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/support-tickets', requireActivePartnerPlan, async (req, res) => {
  try {
    const tickets = await PartnerSupportTicket.find({ partnerId: req.user.partnerId })
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/support-tickets', requireActivePartnerPlan, async (req, res) => {
  try {
    const subject = String(req.body.subject || '').trim();
    const description = String(req.body.description || '').trim();
    if (!subject || !description) return res.status(400).json({ message: 'Subject and description are required' });

    const ticket = await PartnerSupportTicket.create({
      ticketId: `TKT-${new Date().getFullYear()}-${Date.now().toString(36).toUpperCase()}`,
      tenantId: req.user.tenantId,
      partnerId: req.user.partnerId,
      createdBy: req.user.id,
      category: String(req.body.category || 'Other').trim(),
      priority: ['Low', 'Medium', 'High', 'Critical'].includes(req.body.priority) ? req.body.priority : 'Medium',
      subject,
      description,
      payment: {
        transactionId: String(req.body.transactionId || '').trim(),
        paymentDate: String(req.body.paymentDate || '').trim(),
        amount: Number(req.body.amount || 0),
        companyName: String(req.body.companyName || '').trim(),
      },
      attachments: {
        screenshot: String(req.body.screenshot || '').trim(),
        screenshotName: String(req.body.screenshotName || req.body.screenshot || '').trim(),
        screenshotDataUrl: String(req.body.screenshotDataUrl || '').trim(),
        invoice: String(req.body.invoice || '').trim(),
        documents: String(req.body.documents || '').trim(),
      },
    });

    emitPartnerRealtime(req, req.user.partnerId, 'support_ticket_created', { ticket });
    res.status(201).json(ticket);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// POST /api/partner/support-tickets/:ticketId/messages
router.post('/support-tickets/:ticketId/messages', requireActivePartnerPlan, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const ticket = await PartnerSupportTicket.findOne({ _id: req.params.ticketId, partnerId: req.user.partnerId });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.messages.push({
      senderId: req.user.id,
      senderName: req.user.name || req.user.email,
      senderRole: req.user.role,
      message,
    });
    if (ticket.status === 'Open') {
      ticket.status = 'In Progress';
    }
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:message_new', { ticketId: ticket.ticketId, ticket });
      io.to(`partner:${req.user.partnerId}`).emit('support:message_new', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PATCH /api/partner/support-tickets/:ticketId/status
router.patch('/support-tickets/:ticketId/status', requireActivePartnerPlan, async (req, res) => {
  try {
    const { status } = req.body;
    if (!status || !['Open', 'In Progress', 'Resolved', 'Closed'].includes(status)) {
      return res.status(400).json({ message: 'Valid status required' });
    }

    const ticket = await PartnerSupportTicket.findOne({ _id: req.params.ticketId, partnerId: req.user.partnerId });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.status = status;
    if (['Resolved', 'Closed'].includes(status)) {
      ticket.resolvedAt = new Date();
    }
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:ticket_updated', { ticketId: ticket.ticketId, ticket });
      io.to(`partner:${req.user.partnerId}`).emit('support:ticket_updated', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/activity', requireActivePartnerPlan, async (req, res) => {
  try {
    const partnerId = req.user.partnerId;
    const partner = await withTimeout(
      Partner.findById(partnerId)
        .select('name status createdAt updatedAt approvedAt rejectedAt resourceRequest resourceRequestHistory plan')
        .lean(),
      null
    );
    const filter = { partnerId };

    // Fetch all users associated with this partner
    const User = require('../models/User.model');
    const partnerUsers = await withTimeout(User.find({ partnerId }).select('_id').lean(), []);
    const userIds = [req.user.id, ...partnerUsers.map(u => u._id)];

    const LoginActivity = require('../models/LoginActivity.model');

    const [tickets, payments, companies, systems, loginLogs] = await Promise.all([
      withTimeout(PartnerSupportTicket.find(filter).sort({ updatedAt: -1 }).limit(20).lean(), []),
      withTimeout(PaymentHistory.find(filter).sort({ createdAt: -1 }).limit(20).lean(), []),
      withTimeout(Company.find(filter).select('name createdAt updatedAt status').sort({ createdAt: -1 }).limit(20).lean(), []),
      withTimeout(System.find(filter).select('name hostname createdAt updatedAt status').sort({ updatedAt: -1 }).limit(20).lean(), []),
      withTimeout(
        LoginActivity.find({
          action: { $nin: ['superadmin_impersonation_started', 'superadmin_company_impersonation_started',
            'superadmin_impersonation_blocked', 'superadmin_company_impersonation_blocked'] },
          $or: [
            { userId: { $in: userIds } },
            { email: req.user.email }
          ],
          createdAt: { $gte: new Date(Date.now() - 90 * 24 * 60 * 60 * 1000) }
        }).sort({ createdAt: -1 }).limit(100).lean(),
        []
      )
    ]);

    const resourceRequests = normalizeResourceRequestHistory(partner);
    const activity = [
      ...(partner ? [{
        activity: 'Partner Created',
        details: `${partner.name || 'Partner'} account created`,
        date: partner.createdAt,
      }, {
        activity: 'Partner Updated',
        details: `Current status: ${partner.status || 'unknown'}`,
        date: partner.updatedAt,
      }] : []),
      ...(partner?.approvedAt ? [{
        activity: 'Partner Approved',
        details: `${partner.name || 'Partner'} was approved`,
        date: partner.approvedAt,
      }] : []),
      ...(partner?.plan?.quote?.quotedAt ? [{
        activity: 'Platform Fee Quoted',
        details: `Amount ₹${Number(partner.plan.quote.amountInr || 0).toLocaleString('en-IN')}`,
        date: partner.plan.quote.quotedAt,
      }] : []),
      ...resourceRequests.map(item => ({
        activity: `Resource Request ${item.status || 'pending'}`,
        details: `${item.numberOfCompanies || 0} companies, ${item.numberOfAgents || 0} agents`,
        date: item.reviewedAt || item.requestedAt,
      })),
      ...tickets.map(item => ({
        activity: `Support Ticket ${item.status || 'Open'}`,
        details: `${item.ticketId}: ${item.subject || item.category}`,
        date: item.updatedAt || item.createdAt,
      })),
      ...payments.map(item => ({
        activity: item.status === 'captured' ? 'Payment Captured' : 'Payment Created',
        details: `₹${Number(item.amountInr || 0).toLocaleString('en-IN')} ${item.planName || item.planType || ''}`.trim(),
        date: item.paidAt || item.createdAt,
      })),
      ...companies.map(item => ({
        activity: 'Company Created',
        details: item.name,
        date: item.createdAt,
      })),
      ...systems.map(item => ({
        activity: 'Agent/System Updated',
        details: item.name || item.hostname || 'System',
        date: item.updatedAt || item.createdAt,
      })),
      ...loginLogs.map(log => ({
        activity: log.action?.replace(/_/g, ' ').toUpperCase() || 'LOGIN ACTIVITY',
        details: log.action === 'logout'
          ? `User ${log.email} logged out successfully`
          : log.success
            ? `User ${log.email} logged in successfully from IP ${log.ipAddress || 'unknown'}`
            : `Failed login attempt for user ${log.email}. Reason: ${log.failReason || 'unknown'}`,
        date: log.createdAt,
      })),
    ]
      .filter(item => item.date)
      .sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0))
      .slice(0, 100);

    res.json(activity);
  } catch (err) {
    res.json([]);
  }
});

router.get('/referrals', requireActivePartnerPlan, async (req, res) => {
  try {
    const filter = req.user.role === 'superadmin' ? {} : { tenantId: req.user.tenantId, partnerId: req.user.partnerId };
    const referrals = await Referral.find(filter).sort({ createdAt: -1 });
    res.json(referrals);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/invites', requireActivePartnerPlan, async (req, res) => {
  const { email, role = 'company_admin', companyId } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  try {
    const Invite = require('../models/Invite.model');
    const token = crypto.randomBytes(32).toString('hex');
    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
    const invite = await Invite.create({
      tenantId: req.user.tenantId,
      partnerId: req.user.partnerId,
      companyId: companyId || null,
      email: email.trim().toLowerCase(),
      role,
      tokenHash,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      createdBy: req.user.id,
    });

    res.status(201).json({
      invite,
      acceptUrl: `${process.env.COMPANY_ORIGIN || ''}/accept-invite?token=${token}`,
      registrationUrl: req.user.partnerId ? buildRegistrationUrl(req.user.partnerSlug || '') : null,
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ── POST /partner/invite-company — invite a new company ────────────────────
router.post('/invite-company', requireActivePartnerPlan, async (req, res) => {
  const { email, companyName, adminName, tempPassword } = req.body;
  const cleanEmail = String(email || '').trim().toLowerCase();
  const cleanCompany = String(companyName || '').trim();
  const cleanAdmin = String(adminName || '').trim();

  if (!cleanEmail || !cleanCompany) {
    return res.status(400).json({ message: 'Company name aur email required hain' });
  }

  try {
    const { sendMail } = require('../utils/email');
    const partner = await Partner.findById(req.user.partnerId).select('slug name').lean();
    const partnerSlug = partner?.slug || req.user.partnerSlug || '';
    const baseUrl = buildRegistrationUrl(partnerSlug);
    // Embed form data as query params for auto-fill
    const registrationParams = new URLSearchParams({
      company: cleanCompany,
      email: cleanEmail,
      ...(cleanAdmin ? { adminName: cleanAdmin } : {}),
    });
    const registrationUrl = `${baseUrl}?${registrationParams.toString()}`;
    const password = tempPassword || `Welcome${crypto.randomBytes(3).toString('hex').toUpperCase()}!`;

    const emailBody = [
      `<p>Aapko <b>${partner?.name || 'Partner Admin'}</b> ne <b>${cleanCompany}</b> ke liye SOC Platform par invite kiya hai.</p>`,
      `<p>Neeche diya link use karke register karo — isse aapka account automatically partner se link ho jaayega:</p>`,
      `<p><a href="${registrationUrl}" style="background:#4f46e5;color:#fff;padding:10px 24px;border-radius:8px;text-decoration:none;font-weight:bold;display:inline-block;margin:8px 0;">Register Now</a></p>`,
      `<p><b>Company Name:</b> ${cleanCompany}</p>`,
      cleanAdmin ? `<p><b>Admin Name:</b> ${cleanAdmin}</p>` : '',
      `<p><b>Email:</b> ${cleanEmail}</p>`,
      tempPassword ? `<p><b>Temporary Password:</b> ${password}</p>` : '',
      `<p style="color:#666;font-size:13px;">If button kaam na kare, directly yahan jaao: <a href="${registrationUrl}">${registrationUrl}</a></p>`,
    ].filter(Boolean).join('\n');

    await sendMail({
      to: cleanEmail,
      subject: `${partner?.name || 'Partner'} ne aapko SOC Platform par invite kiya hai`,
      text: `${cleanCompany} ke liye registration link: ${registrationUrl}`,
      html: emailBody,
    });

    res.status(201).json({
      success: true,
      email: cleanEmail,
      companyName: cleanCompany,
      registrationUrl,
      message: `Invitation ${cleanEmail} ko bhej diya gaya`,
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.post('/resource-request', requireActivePartnerPlan, async (req, res) => {
  const numberOfCompanies = Number(req.body.numberOfCompanies || 0);
  const numberOfAgents = Number(req.body.numberOfAgents || 0);
  const expectedMonthlyVolume = Number(req.body.expectedMonthlyVolume || 0);
  const proposedCommission = Number(req.body.proposedCommission || 0);

  if (numberOfCompanies <= 0 || numberOfAgents <= 0) {
    return res.status(400).json({ message: 'Number of companies and agents are required' });
  }

  try {
    const requestedAt = new Date();
    const requestId = `REQ-${Date.now().toString(36).toUpperCase()}`;
    const requestEntry = {
      requestId,
      status: 'pending',
      numberOfCompanies,
      numberOfAgents,
      expectedMonthlyVolume,
      proposedCommission,
      additionalNotes: String(req.body.additionalNotes || '').trim(),
      adminNote: '',
      requestedAt,
      reviewedAt: null,
      reviewedBy: null,
    };
    const partner = await Partner.findByIdAndUpdate(req.user.partnerId, {
      'resourceRequest.status': 'pending',
      'resourceRequest.numberOfCompanies': numberOfCompanies,
      'resourceRequest.numberOfAgents': numberOfAgents,
      'resourceRequest.expectedMonthlyVolume': expectedMonthlyVolume,
      'resourceRequest.proposedCommission': proposedCommission,
      'resourceRequest.additionalNotes': requestEntry.additionalNotes,
      'resourceRequest.adminNote': '',
      'resourceRequest.requestedAt': requestedAt,
      'resourceRequest.reviewedAt': null,
      'resourceRequest.reviewedBy': null,
      'capabilities.createCompany': false,
      'capabilities.downloadAgent': false,
      'capabilities.subscriptionPurchase': false,
      $push: { resourceRequestHistory: requestEntry },
    }, { new: true });
    emitPartnerRealtime(req, partner._id, 'resource_request', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/profile', requireActivePartnerPlan, async (req, res) => {
  try {
    const update = {};
    const setIfPresent = (key, value, transform = v => String(v || '').trim()) => {
      if (value !== undefined) update[key] = transform(value);
    };

    setIfPresent('profile.designation', req.body.designation);
    setIfPresent('profile.alternatePhone', req.body.alternatePhone);
    setIfPresent('profile.language', req.body.language);
    setIfPresent('profile.timezone', req.body.timezone);
    if (update['profile.alternatePhone'] && !/^[6-9]\d{9}$/.test(update['profile.alternatePhone'])) {
      return res.status(400).json({ message: 'Enter a valid alternate mobile number.' });
    }
    if (req.body.language !== undefined && !['English', 'Hindi'].includes(update['profile.language'])) {
      return res.status(400).json({ message: 'Select a supported language.' });
    }
    if (req.body.timezone !== undefined && !['(GMT +05:30) Asia/Kolkata', '(GMT +00:00) UTC'].includes(update['profile.timezone'])) {
      return res.status(400).json({ message: 'Select a supported time zone.' });
    }

    setIfPresent('partner_linked_account_id', req.body.partner_linked_account_id);
    setIfPresent('profile.razorpayKeyId', req.body.razorpayKeyId);
    setIfPresent('profile.razorpaySecret', req.body.razorpaySecret);
    setIfPresent('profile.bankAccount', req.body.bankAccount);
    setIfPresent('profile.accountHolderName', req.body.accountHolderName);
    setIfPresent('profile.bankName', req.body.bankName);
    setIfPresent('profile.accountNumber', req.body.accountNumber);
    setIfPresent('profile.ifscCode', req.body.ifscCode, v => String(v || '').trim().toUpperCase());
    setIfPresent('profile.branchName', req.body.branchName);
    setIfPresent('profile.gstNumber', req.body.gstNumber, v => String(v || '').trim().toUpperCase());
    setIfPresent('profile.panNumber', req.body.panNumber, v => String(v || '').trim().toUpperCase());
    if (req.body.name !== undefined) update.name = String(req.body.name || '').trim();
    if (req.body.mobile !== undefined || req.body.phone !== undefined) update.mobile = String(req.body.mobile || req.body.phone || '').trim();
    if (req.body.avatarFileName !== undefined) update['profile.avatarFileName'] = String(req.body.avatarFileName || '').trim();
    if (req.body.avatarFilePath !== undefined) update['profile.avatarFilePath'] = String(req.body.avatarFilePath || '').trim();
    if (req.body.avatarDataUrl !== undefined) update['profile.avatarDataUrl'] = String(req.body.avatarDataUrl || '').trim();
    if (req.body.kycDocuments) {
      Object.entries(req.body.kycDocuments).forEach(([key, value]) => {
        if (!KYC_DOC_FIELDS.has(key)) return;
        const cleanValue = String(value || '').trim();
        if (key.endsWith('FilePath')) {
          const cleanPath = cleanValue.replace(/^\/+/, '');
          const uploadPath = path.resolve(UPLOAD_ROOT, cleanPath);
          const uploadRoot = path.resolve(UPLOAD_ROOT);
          if (!cleanPath.startsWith('partner-docs/') || !uploadPath.startsWith(uploadRoot + path.sep) || !fs.existsSync(uploadPath)) return;
          update[`profile.kycDocuments.${key}`] = cleanPath;
          return;
        }
        if (cleanValue) update[`profile.kycDocuments.${key}`] = cleanValue;
      });
    }
    if (
      req.body.kycDocuments ||
      req.body.gstNumber !== undefined ||
      req.body.panNumber !== undefined ||
      req.body.bankAccount !== undefined ||
      req.body.accountNumber !== undefined
    ) {
      update['profile.kycStatus'] = 'pending';
    }

    if (req.body.fullName !== undefined || req.body.email !== undefined || req.body.phone !== undefined) {
      const userUpdate = {};
      if (req.body.fullName !== undefined) userUpdate.name = String(req.body.fullName || '').trim();
      if (req.body.email !== undefined) userUpdate.email = String(req.body.email || '').trim().toLowerCase();
      if (req.body.phone !== undefined) userUpdate.phone = String(req.body.phone || '').trim();
      if (Object.keys(userUpdate).length) await User.findByIdAndUpdate(req.user.id, userUpdate);
      // Owner-only edits must succeed and invalidate live partner snapshots too.
      update.updatedAt = new Date();
    }

    if (!Object.keys(update).length) return res.status(400).json({ message: 'No profile fields provided' });

    const partner = await Partner.findByIdAndUpdate(req.user.partnerId, update, { new: true }).populate('ownerUserId', 'name email phone role forcePasswordReset');
    emitPartnerRealtime(req, partner._id, 'profile_updated', { partner });
    res.json(partner);
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ── POST /partner/profile/setup-complete — mark first-time profile setup done ──
// Called by the frontend after the partner finishes the post-payment profile wizard.
// Uses requireActivePartnerPlan (payment must be confirmed first).
router.patch('/profile/setup-complete', requireActivePartnerPlan, async (req, res) => {
  try {
    const partner = await Partner.findByIdAndUpdate(
      req.user.partnerId,
      { profileSetupComplete: true },
      { new: true }
    ).populate('ownerUserId', 'name email phone role forcePasswordReset');
    if (!partner) return res.status(404).json({ message: 'Partner not found' });
    emitPartnerRealtime(req, partner._id, 'profile_setup_complete', { partner });
    res.json({ success: true, profileSetupComplete: true, partner });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

module.exports = router;
