const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, unique: true, index: true },
  enabled: { type: Boolean, default: true },
  sha256Enabled: { type: Boolean, default: true },
  sha1Enabled: { type: Boolean, default: true },
  md5Enabled: { type: Boolean, default: false },
  signatureValidationEnabled: { type: Boolean, default: true },
  threatIntelEnabled: { type: Boolean, default: true },
  baselineMonitoringEnabled: { type: Boolean, default: true },
  unsignedFileAlertEnabled: { type: Boolean, default: true },
  criticalFileMonitoringEnabled: { type: Boolean, default: true },
  riskThreshold: { type: Number, default: 30, min: 0, max: 100 },
  riskWeights: { type: Map, of: Number, default: {} },
  approvedHashes: [{ type: String, lowercase: true, match: /^[a-f0-9]{64}$/ }],
  approvedPublishers: [{ type: String, trim: true, maxlength: 500 }],
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

module.exports = mongoose.model('HashSignaturePolicy', schema);
