/**
 * FraudAlert Model
 * High-priority alerts raised for SOC analyst review.
 */
const mongoose = require('mongoose');

const FraudAlertSchema = new mongoose.Schema({
  fraudEventId:{ type: mongoose.Schema.Types.ObjectId, ref: 'FraudEvent', index: true },
  deviceId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:       { type: String },

  title:       { type: String, required: true },
  description: { type: String },
  category: {
    type: String,
    enum: ['brute_force', 'account_takeover', 'bot', 'impossible_travel', 'multi_account', 'new_device', 'high_risk', 'vpn', 'tor', 'proxy', 'velocity', 'manual'],
    default: 'high_risk', index: true,
  },
  severity:  { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high', index: true },

  ipAddress: { type: String },
  country:   { type: String },
  asn:       { type: String },
  isVpn:     { type: Boolean, default: false },
  isTor:     { type: Boolean, default: false },
  riskScore: { type: Number, default: 0 },
  decision:  { type: String },
  matchedRules: [{ type: String }],

  status: { type: String, enum: ['open', 'investigating', 'resolved', 'false_positive'], default: 'open', index: true },
  resolvedAt:  { type: Date },
  resolvedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  resolvedNote:{ type: String },
  simulatedData:{ type: Boolean, default: false },
}, { timestamps: true });

FraudAlertSchema.index({ createdAt: -1 });
FraudAlertSchema.index({ status: 1, severity: 1, createdAt: -1 });
FraudAlertSchema.index({ companyId: 1, status: 1 });

module.exports = mongoose.model('FraudAlert', FraudAlertSchema);
