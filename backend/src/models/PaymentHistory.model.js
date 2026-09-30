const mongoose = require('mongoose');

/**
 * PaymentHistory — per-payment records for revenue tracking.
 * Updated to support dynamic pricing model.
 */
const PaymentHistorySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  tenantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyName: { type: String },
  partnerName: { type: String },

  // Razorpay data
  orderId: { type: String, index: true },
  paymentId: { type: String, unique: true, sparse: true },
  signature: { type: String },

  // Plan details (dynamic)
  planType: { type: String, default: 'custom' },
  systemCount: { type: Number, default: 0 },   // systems purchased
  serverCount: { type: Number, default: 0 },   // servers purchased
  phoneCount: { type: Number, default: 0 },     // Android + iPhone devices purchased

  // Pricing at time of payment
  pricePerSystemMonthly: { type: Number },
  pricePerSystemYearly: { type: Number },
  pricePerPhoneMonthly: { type: Number },
  pricePerPhoneYearly: { type: Number },
  pricePerServerMonthly: { type: Number },
  pricePerServerYearly: { type: Number },

  // Billing
  billingCycle: { type: String, enum: ['monthly', 'six_monthly', 'yearly'], default: 'monthly' },
  amountPaise: { type: Number },    // amount in paise (₹ × 100)
  amountInr: { type: Number },    // amount in ₹
  currency: { type: String, default: 'INR' },

  // Flags
  isUpgrade: { type: Boolean, default: false },   // true if additional systems added
  addedSystems: { type: Number, default: 0 },         // how many extra systems added
  addedServers: { type: Number, default: 0 },         // how many extra servers added
  addedPhones: { type: Number, default: 0 },          // how many extra phones added

  // Status
  status: { type: String, enum: ['created', 'captured', 'failed', 'refunded'], default: 'created' },
  paidAt: { type: Date },
  periodStart: { type: Date },
  periodEnd: { type: Date },

  // AutoPay
  autoPay: { type: Boolean, default: false },

  // Partner settlement / route transfer
  companyType: { type: String, enum: ['DIRECT', 'PARTNER_MANAGED'], default: 'DIRECT', index: true },
  paymentReceiver: { type: String, enum: ['superadmin_razorpay', 'partner_razorpay', 'unknown'], default: 'unknown' },
  partnerLinkedAccountId: { type: String, default: '' },
  platformCommissionInr: { type: Number, default: 0 },
  partnerPayoutInr: { type: Number, default: 0 },
  payoutStatus: { type: String, enum: ['not_applicable', 'pending', 'processing', 'settled', 'failed'], default: 'not_applicable', index: true },
  settlementDate: { type: Date, default: null },
  transferId: { type: String, default: '' },
  transferStatus: { type: String, default: '' },
  transferError: { type: String, default: '' },

  // Source
  source: { type: String, enum: ['checkout', 'webhook', 'manual', 'autopay', 'upgrade', 'renewal', 'partner_checkout', 'partner_agent_license'], default: 'checkout' },
  notes: { type: mongoose.Schema.Types.Mixed },
}, { timestamps: true });

PaymentHistorySchema.index({ companyId: 1, paidAt: -1 });
PaymentHistorySchema.index({ paidAt: -1 });

module.exports = mongoose.model('PaymentHistory', PaymentHistorySchema);
