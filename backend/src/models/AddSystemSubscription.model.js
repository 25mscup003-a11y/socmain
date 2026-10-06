const mongoose = require('mongoose');

/**
 * AddSystemSubscription — tracks every "Add Systems" batch purchase independently.
 *
 * KEY DESIGN DECISIONS:
 * 1. Each purchase is a NEW document — never merged with base plan or other batches.
 * 2. Total usable systems = base plan + SUM(all active AddSystemSubscription.addedSystemCount)
 * 3. Billing stays separate: each batch has its own billing cycle, expiry, and AutoPay.
 * 4. Renewal updates the same batch. Payment history records each renewal separately.
 */
const AddSystemSubscriptionSchema = new mongoose.Schema({
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  companyName: { type: String },
  enterpriseOrderId: { type: mongoose.Schema.Types.ObjectId, ref: 'EnterpriseOrder', unique: true, sparse: true },
  parentBatchId: { type: mongoose.Schema.Types.ObjectId, ref: 'AddSystemSubscription' },

  // Razorpay payment details
  orderId:    { type: String, index: true },
  paymentId:  { type: String, unique: true, sparse: true },
  signature:  { type: String },

  // What was added in this batch
  addedSystemCount: { type: Number, default: 0, required: true },   // systems in this batch
  addedServerCount: { type: Number, default: 0 },                   // servers in this batch (optional)
  addedPhoneCount:  { type: Number, default: 0 },                   // Android + iPhone devices in this batch

  // Server details / notes (free text — e.g. "AWS-X", "On-premise")
  serverDetails: { type: String, default: '' },

  // Billing
  billingCycle: { type: String, enum: ['monthly', 'yearly'], default: 'monthly' },
  amountPaid:   { type: Number, default: 0 },   // in ₹
  amountPaise:  { type: Number, default: 0 },   // in paise

  // Pricing snapshot at time of purchase (from renewal pricing set)
  pricePerSystemMonthly: { type: Number },
  pricePerSystemYearly:  { type: Number },
  pricePerPhoneMonthly:  { type: Number },
  pricePerPhoneYearly:   { type: Number },
  pricePerServerMonthly: { type: Number },
  pricePerServerYearly:  { type: Number },
  priceType: { type: String, default: 'renewal' },   // always 'renewal' for add-system

  // Subscription period
  addedDate:  { type: Date, default: Date.now },   // when the payment was made
  startDate:  { type: Date },
  endDate:    { type: Date },   // expiry of this batch

  // AutoPay — each batch has its own autopay toggle
  autoPay:       { type: Boolean, default: false },
  autoPayMethod: { type: String, default: '' },

  // Status: 'active' | 'expired' | 'cancelled'
  status: { type: String, enum: ['active', 'expired', 'cancelled'], default: 'active' },

  // Renewal tracking
  renewedFromId: { type: mongoose.Schema.Types.ObjectId, ref: 'AddSystemSubscription', default: null },
  renewalCount:  { type: Number, default: 0 },   // how many times this batch has been renewed
  lastEnterpriseRenewalOrderId: { type: mongoose.Schema.Types.ObjectId, ref: 'EnterpriseRenewalOrder' },

  // Payment verification
  paymentStatus: { type: String, enum: ['paid', 'unpaid', 'failed'], default: 'paid' },
}, { timestamps: true });

// Indexes for fast queries
AddSystemSubscriptionSchema.index({ companyId: 1, status: 1 });
AddSystemSubscriptionSchema.index({ companyId: 1, addedDate: -1 });
AddSystemSubscriptionSchema.index({ endDate: 1, status: 1 });   // for expiry sweep

module.exports = mongoose.model('AddSystemSubscription', AddSystemSubscriptionSchema);
