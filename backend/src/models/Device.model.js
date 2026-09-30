/**
 * Device Model
 * Tracks unique devices identified by Stytch fingerprint hashes.
 * Each document represents one physical/virtual device.
 */
const mongoose = require('mongoose');

const DeviceSchema = new mongoose.Schema({
  // Stytch identifiers
  visitorId:         { type: String, index: true },
  browserId:         { type: String, index: true },
  deviceFingerprint: { type: String, index: true },
  identitySource: { type: String, enum: ['stytch', 'authentication_audit'], default: 'stytch', index: true },
  browserFingerprint:{ type: String },
  hardwareFingerprint:{ type: String },
  networkFingerprint:{ type: String },

  // First/last seen metadata
  firstSeenAt:  { type: Date, default: Date.now },
  lastSeenAt:   { type: Date, default: Date.now },
  firstSeenIp:  { type: String },
  lastSeenIp:   { type: String },
  firstSeenCountry: { type: String },
  lastSeenCountry:  { type: String },

  // Associated users (a device can be used by multiple accounts)
  userIds:   [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  emails:    [{ type: String }],
  companyIds:[{ type: mongoose.Schema.Types.ObjectId, ref: 'Company' }],

  // Device metadata (from Stytch or simulated)
  browser:   { type: String },
  os:        { type: String },
  device:    { type: String }, // desktop | mobile | tablet
  userAgent: { type: String },

  // Network / threat signals
  isVpn:     { type: Boolean, default: false },
  isTor:     { type: Boolean, default: false },
  isProxy:   { type: Boolean, default: false },
  isBot:     { type: Boolean, default: false },
  asn:       { type: String },
  isp:       { type: String },
  country:   { type: String },
  region:    { type: String },
  city:      { type: String },
  gpsLat:    { type: Number, min: -90, max: 90 },
  gpsLon:    { type: Number, min: -180, max: 180 },
  gpsAccuracyMeters: { type: Number, min: 0 },
  gpsCapturedAt: { type: Date },

  // Risk / decision history
  riskScoreAvg:  { type: Number, default: 0 },
  riskScoreLast: { type: Number, default: 0 },
  totalLogins:   { type: Number, default: 0 },
  totalBlocks:   { type: Number, default: 0 },
  totalChallenges:{ type: Number, default: 0 },

  // Status
  status: {
    type: String,
    enum: ['new', 'known', 'trusted', 'suspicious', 'blocked'],
    default: 'new',
    index: true,
  },
  statusReason:  { type: String },
  statusUpdatedAt:{ type: Date },
  simulatedData:{ type: Boolean, default: false },
}, { timestamps: true });

// Compound index for fast lookups
DeviceSchema.index({ deviceFingerprint: 1, status: 1 });
DeviceSchema.index({ visitorId: 1, lastSeenAt: -1 });

module.exports = mongoose.model('Device', DeviceSchema);
