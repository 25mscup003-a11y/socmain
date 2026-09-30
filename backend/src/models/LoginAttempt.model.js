/**
 * LoginAttempt Model
 * Fraud-annotated login attempt log.
 * Enriches the existing LoginActivity with fingerprint & risk data.
 */
const mongoose = require('mongoose');

const LoginAttemptSchema = new mongoose.Schema({
  // Actor
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:     { type: String, index: true },

  // Auth outcome
  action:  { type: String, default: 'login' },
  success: { type: Boolean, default: false },
  failReason:{ type: String },

  // Network
  ipAddress: { type: String },
  userAgent: { type: String },
  country:   { type: String },
  asn:       { type: String },

  // Fraud data (linked from FraudEvent)
  fraudEventId:       { type: mongoose.Schema.Types.ObjectId, ref: 'FraudEvent' },
  telemetryId:        { type: String },
  visitorId:          { type: String },
  browserId:          { type: String },
  deviceFingerprint:  { type: String },
  deviceId:           { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },

  // Risk
  riskScore: { type: Number, default: 0 },
  riskLevel: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  decision:  { type: String, enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW'], default: 'ALLOW' },
  matchedRules:[{ type: String }],
  isVpn:  { type: Boolean, default: false },
  isTor:  { type: Boolean, default: false },
  isProxy:{ type: Boolean, default: false },
}, { timestamps: true });

LoginAttemptSchema.index({ createdAt: -1 });
LoginAttemptSchema.index({ decision: 1, createdAt: -1 });

module.exports = mongoose.model('LoginAttempt', LoginAttemptSchema);
