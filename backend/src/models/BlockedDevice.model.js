/**
 * BlockedDevice Model
 * Blocklist for specific device fingerprint hashes.
 */
const mongoose = require('mongoose');

const BlockedDeviceSchema = new mongoose.Schema({
  deviceId:          { type: mongoose.Schema.Types.ObjectId, ref: 'Device', index: true },
  deviceFingerprint: { type: String, required: true, unique: true, index: true },
  visitorId:         { type: String },
  browserId:         { type: String },

  companyId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  blockedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reason:     { type: String, required: true },
  ruleId:     { type: mongoose.Schema.Types.ObjectId, ref: 'FraudRule' },
  fraudEventId:{ type: mongoose.Schema.Types.ObjectId, ref: 'FraudEvent' },

  // Optional TTL — null = permanent block
  expiresAt:  { type: Date, default: null },
  isActive:   { type: Boolean, default: true, index: true },
  unblockedAt:{ type: Date },
  unblockedBy:{ type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

BlockedDeviceSchema.index({ deviceFingerprint: 1, isActive: 1 });

module.exports = mongoose.model('BlockedDevice', BlockedDeviceSchema);
