/**
 * TrustedDevice Model
 * User-approved trusted devices that bypass CHALLENGE decisions.
 */
const mongoose = require('mongoose');

const TrustedDeviceSchema = new mongoose.Schema({
  userId:            { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  companyId:         { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:             { type: String },
  deviceId:          { type: mongoose.Schema.Types.ObjectId, ref: 'Device', index: true },
  deviceFingerprint: { type: String, required: true, index: true },
  visitorId:         { type: String },
  browserId:         { type: String },

  // Human-readable label (e.g. "My Work Laptop")
  label:       { type: String, default: 'Trusted Device' },
  browser:     { type: String },
  os:          { type: String },
  country:     { type: String },
  ipAddress:   { type: String },

  // Trust validity
  trustedAt:  { type: Date, default: Date.now },
  expiresAt:  { type: Date, default: null }, // null = permanent trust
  isActive:   { type: Boolean, default: true, index: true },
  revokedAt:  { type: Date },
  revokedBy:  { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

TrustedDeviceSchema.index({ userId: 1, deviceFingerprint: 1 });

module.exports = mongoose.model('TrustedDevice', TrustedDeviceSchema);
