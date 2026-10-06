const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, unique: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null },
  systemCount: { type: Number, required: true, min: 0 },
  serverCount: { type: Number, required: true, min: 0 },
  phoneCount: { type: Number, required: true, min: 0 },
  billingCycle: { type: String, enum: ['monthly', 'yearly'], required: true },
  amountInr: { type: Number, default: null },
  notes: { type: String, default: '', maxlength: 2000 },
  status: { type: String, enum: ['requested', 'quoted', 'checkout', 'paid'], required: true },
  revision: { type: Number, default: 1 },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  quotedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  quotedAt: Date,
  notification: {
    type: new mongoose.Schema({
      kind: { type: String, enum: ['request', 'ready'], required: true },
      status: { type: String, enum: ['pending', 'sending', 'sent'], default: 'pending' },
      attempts: { type: Number, default: 0 },
      sentTo: { type: [String], default: [] },
      nextAttemptAt: { type: Date, default: Date.now },
      leaseUntil: Date,
      leaseId: String,
      sentAt: Date,
    }, { _id: false }),
    default: undefined,
  },
}, { timestamps: true });
schema.index({ 'notification.status': 1, 'notification.nextAttemptAt': 1 });

module.exports = mongoose.model('EnterpriseQuote', schema);
