/**
 * DeviceHistory Model
 * Per-device activity timeline — one record per login/action attempt.
 */
const mongoose = require('mongoose');

const DeviceHistorySchema = new mongoose.Schema({
  deviceId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Device', index: true },
  visitorId:   { type: String, index: true },
  browserId:   { type: String },

  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  email:       { type: String },

  // Action context
  action:      { type: String, enum: ['login', 'signup', 'password_reset', 'mfa', 'email_verify', 'admin_login', 'password_change', 'manual_check'], default: 'login' },
  ipAddress:   { type: String },
  country:     { type: String },
  city:        { type: String },
  asn:         { type: String },
  isp:         { type: String },
  userAgent:   { type: String },

  // Threat signals at time of event
  isVpn:  { type: Boolean, default: false },
  isTor:  { type: Boolean, default: false },
  isProxy:{ type: Boolean, default: false },

  // Risk & decision
  riskScore:  { type: Number, default: 0 },
  riskLevel:  { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  decision:   { type: String, enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW'], default: 'ALLOW' },
  matchedRules:[{ type: String }],
  requestId:  { type: String },
}, { timestamps: true });

DeviceHistorySchema.index({ deviceId: 1, createdAt: -1 });
DeviceHistorySchema.index({ userId: 1, createdAt: -1 });
DeviceHistorySchema.index({ email: 1, createdAt: -1 });

module.exports = mongoose.model('DeviceHistory', DeviceHistorySchema);
