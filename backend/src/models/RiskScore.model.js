/**
 * RiskScore Model
 * Historical risk score time-series for analytics and trending.
 */
const mongoose = require('mongoose');

const RiskScoreSchema = new mongoose.Schema({
  fraudEventId:{ type: mongoose.Schema.Types.ObjectId, ref: 'FraudEvent', index: true },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:       { type: String },
  deviceId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Device' },
  visitorId:   { type: String },
  ipAddress:   { type: String },
  score:       { type: Number, required: true, min: 0, max: 100, index: true },
  level:       { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  decision:    { type: String, enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW'] },
  action:      { type: String },
  matchedRules:[{ type: String }],
  factors:     [{ type: String }],
  country:     { type: String },
  isVpn:       { type: Boolean, default: false },
  isTor:       { type: Boolean, default: false },
}, { timestamps: true });

RiskScoreSchema.index({ createdAt: -1 });
RiskScoreSchema.index({ score: -1, createdAt: -1 });

module.exports = mongoose.model('RiskScore', RiskScoreSchema);
