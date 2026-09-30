const mongoose = require('mongoose');

const CompanySchema = new mongoose.Schema({
  name:    { type: String, required: true, trim: true },
  email:   { type: String, required: true, unique: true, lowercase: true },
  phone:   { type: String, default: '' },
  industry:    { type: String, default: '' },
  website:     { type: String, default: '' },
  companySize: { type: String, default: '' },
  country:     { type: String, default: '' },

  tenantId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  referralId: { type: mongoose.Schema.Types.ObjectId, ref: 'Referral', default: null },
  source:     { type: String, enum: ['public', 'partner_referral', 'admin_created'], default: 'public' },
  company_type: { type: String, enum: ['DIRECT', 'PARTNER_MANAGED'], default: 'DIRECT', index: true },
  agentLicenseAllocation: { type: Number, default: 0 },

  // Dynamic plan — no predefined tiers, fully customizable
  plan: {
	    // Custom purchased quantities
	    systemCount:   { type: Number, default: 0 },  // TOTAL = base + all active add-system batches
	    serverCount:   { type: Number, default: 0 },  // TOTAL = base + all active add-server batches
	    phoneCount:    { type: Number, default: 0 },  // Android + iPhone devices

	    // Base registration counts (locked at time of registration payment)
	    // Add-system batches are added ON TOP of these
	    baseSystemCount: { type: Number, default: 0 },
	    baseServerCount: { type: Number, default: 0 },
	    basePhoneCount:  { type: Number, default: 0 },

    // Legacy field (kept for backward compat)
    type:           { type: String, default: 'custom' },
    systemLimit:    { type: Number, default: 0 },
    isActive:       { type: Boolean, default: false },
    expiresAt:      { type: Date },
    startDate:      { type: Date },

    // Pricing snapshot at time of purchase
    pricePerSystemMonthly: { type: Number },
    pricePerSystemYearly:  { type: Number },
    pricePerPhoneMonthly:  { type: Number },
    pricePerPhoneYearly:   { type: Number },
    pricePerServerMonthly: { type: Number },
    pricePerServerYearly:  { type: Number },

    // Billing
    billingCycle:  { type: String, enum: ['monthly', 'yearly'], default: 'monthly' },
    amountPaid:    { type: Number, default: 0 },   // in ₹
    paymentStatus: { type: String, enum: ['paid', 'unpaid', 'failed'], default: 'unpaid' },

    // AutoPay
    autoPay:       { type: Boolean, default: false },
    autoPayMethod: { type: String, default: '' },   // e.g. 'razorpay_mandate'
  },

  // Latest Razorpay payment details
  razorpay: {
    orderId:    { type: String },
    paymentId:  { type: String },
    signature:  { type: String },
    paidAt:     { type: Date },
  },

  // 2FA / TOTP
  twoFactorSecret:  { type: String, default: null },
  twoFactorEnabled: { type: Boolean, default: false },

  // Unique company-level key (used for bulk operations)
  agentKey: { type: String },

  status: {
    type:    String,
    enum:    ['pending_payment', 'active', 'suspended', 'trial'],
    default: 'pending_payment',
  },

  riskScore: { type: Number, default: 0 },
  retentionPolicy: {
    hotDays: { type: Number, min: 1, max: 3650, default: 30 },
    totalDays: { type: Number, min: 1, max: 3650, default: 90 },
    archiveEnabled: { type: Boolean, default: false },
    legalHold: { type: Boolean, default: false },
  },
}, { timestamps: true });

CompanySchema.index({ tenantId: 1, status: 1 });
CompanySchema.index({ tenantId: 1, partnerId: 1 });

module.exports = mongoose.model('Company', CompanySchema);
