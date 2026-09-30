const mongoose = require('mongoose');

const RansomwareConfigSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, unique: true, index: true },
  enabled: { type: Boolean, default: true },
  windowSeconds: { type: Number, default: 30, min: 5, max: 300 },
  massModificationThreshold: { type: Number, default: 50, min: 2, max: 10000 },
  massDeletionThreshold: { type: Number, default: 30, min: 2, max: 10000 },
  entropyThreshold: { type: Number, default: 7, min: 0, max: 8 },
  entropyFileTrigger: { type: Number, default: 10, min: 1, max: 1000 },
  alertCooldownSeconds: { type: Number, default: 120, min: 10, max: 86400 },
  customExtensions: [{ type: String, trim: true, maxlength: 32 }],
  protectedDirectories: [{ type: String, trim: true, maxlength: 512 }],
  builtInRuleOverrides: { type: mongoose.Schema.Types.Mixed, default: {} },
  version: { type: Number, default: 1, min: 1 },
  lastDeployedAt: { type: Date, default: null },
  lastDeployedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true, versionKey: false });

RansomwareConfigSchema.index({ tenantId: 1, companyId: 1 });

module.exports = mongoose.models.RansomwareConfig
  || mongoose.model('RansomwareConfig', RansomwareConfigSchema);
