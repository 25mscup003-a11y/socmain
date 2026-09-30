/**
 * VisitorProfile Model
 * Maps a Stytch visitor_id to multiple user accounts and sessions.
 * Detects multi-account activity from a single device.
 */
const mongoose = require('mongoose');

const VisitorProfileSchema = new mongoose.Schema({
  visitorId: { type: String, required: true, unique: true, index: true },
  browserId: { type: String, index: true },
  deviceFingerprint: { type: String },

  // All accounts seen using this visitor_id
  userIds:   [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  emails:    [{ type: String }],
  companyIds:[{ type: mongoose.Schema.Types.ObjectId, ref: 'Company' }],

  // Session tracking
  totalSessions:   { type: Number, default: 0 },
  totalAccounts:   { type: Number, default: 0 },
  firstSeenAt:     { type: Date, default: Date.now },
  lastSeenAt:      { type: Date, default: Date.now },
  lastIpAddress:   { type: String },
  lastCountry:     { type: String },

  // Anomaly flags
  multipleAccountsFlag: { type: Boolean, default: false },
  rapidSwitchingFlag:   { type: Boolean, default: false },
  impossibleTravelFlag: { type: Boolean, default: false },

  // Aggregate risk
  maxRiskScore:    { type: Number, default: 0 },
  avgRiskScore:    { type: Number, default: 0 },
}, { timestamps: true });

module.exports = mongoose.model('VisitorProfile', VisitorProfileSchema);
