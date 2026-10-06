const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  quoteId: { type: mongoose.Schema.Types.ObjectId, ref: 'EnterpriseQuote', required: true },
  revision: { type: Number, required: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null },
  companyName: String,
  partnerName: String,
  isPrimaryEnterprise: { type: Boolean, default: false },
  parentBatchId: { type: mongoose.Schema.Types.ObjectId, ref: 'AddSystemSubscription' },
  purchaseKey: String,
  kind: { type: String, enum: ['plan', 'addition'], default: 'plan' },
  systemCount: { type: Number, required: true },
  serverCount: { type: Number, required: true },
  phoneCount: { type: Number, required: true },
  billingCycle: { type: String, enum: ['monthly', 'yearly'], required: true },
  baseInr: Number,
  gstInr: Number,
  feeInr: Number,
  amountPaise: { type: Number, required: true },
  razorpayOrderId: { type: String, unique: true, sparse: true },
  orderLease: String,
  orderLeaseUntil: Date,
  paymentId: String,
  status: { type: String, enum: ['preparing', 'created', 'paid'], default: 'preparing' },
  paidAt: Date,
  periodStart: Date,
  periodEnd: Date,
}, { timestamps: true });
schema.index({ quoteId: 1, revision: 1 }, { unique: true });

module.exports = mongoose.model('EnterpriseOrder', schema);
