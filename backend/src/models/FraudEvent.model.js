/**
 * FraudEvent Model
 * Full record of a single fraud analysis: Stytch API response +
 * rules engine matches + decision engine result per login/action.
 */
const mongoose = require('mongoose');

const FraudEventSchema = new mongoose.Schema({
  requestId: { type: String, unique: true, index: true },

  // Actor
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  email:     { type: String, index: true },
  evidenceSource: { type: String, enum: ['stytch', 'authentication_audit'], default: 'stytch', index: true },

  // Stytch identifiers
  telemetryId:        { type: String },
  visitorId:          { type: String, index: true },
  browserId:          { type: String },
  deviceFingerprint:  { type: String, index: true },
  browserFingerprint: { type: String },
  hardwareFingerprint:{ type: String },
  networkFingerprint: { type: String },

  // Network context
  ipAddress: { type: String, index: true },
  country:   { type: String },
  region:    { type: String },
  city:      { type: String },
  asn:       { type: String },
  isp:       { type: String },
  lat:       { type: Number },
  lon:       { type: Number },

  // Threat signals
  isVpn:  { type: Boolean, default: false },
  isTor:  { type: Boolean, default: false },
  isProxy:{ type: Boolean, default: false },
  isBot:  { type: Boolean, default: false },

  // Browser / device metadata
  browser:   { type: String },
  os:        { type: String },
  device:    { type: String },
  userAgent: { type: String },

  // Risk assessment
  riskScore: { type: Number, default: 0, index: true },
  riskLevel: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low', index: true },

  // Decision engine output
  decision: { type: String, enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW'], default: 'ALLOW', index: true },
  requiresMFA:        { type: Boolean, default: false },
  shouldLockAccount:  { type: Boolean, default: false },
  shouldBlockIP:      { type: Boolean, default: false },
  shouldBlockDevice:  { type: Boolean, default: false },
  shouldCreateAlert:  { type: Boolean, default: false },

  // Rules engine
  matchedRules: [{ type: String }],
  ruleActions:  [{ type: String }],

  // Action context
  action: { type: String, enum: ['login', 'signup', 'password_reset', 'mfa', 'email_verify', 'admin_login', 'password_change', 'manual_check'], default: 'login' },
  success:{ type: Boolean, default: true },

  // Raw API response (stored for audit)
  stytchResponse: { type: mongoose.Schema.Types.Mixed },
  simulatedData:  { type: Boolean, default: false }, // true if fallback mode

  // Device references
  deviceId: { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
}, { timestamps: true });

FraudEventSchema.index({ createdAt: -1 });
FraudEventSchema.index({ decision: 1, createdAt: -1 });
FraudEventSchema.index({ riskScore: -1, createdAt: -1 });
FraudEventSchema.index({ companyId: 1, createdAt: -1 });

module.exports = mongoose.model('FraudEvent', FraudEventSchema);
