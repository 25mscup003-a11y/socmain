const mongoose = require('mongoose');

const ManualPolicySchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 80 },
  nameKey: { type: String, required: true, trim: true, maxlength: 80 },
  description: { type: String, trim: true, maxlength: 300, default: '' },
  settings: { type: mongoose.Schema.Types.Mixed, required: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
}, { _id: true, versionKey: false });

const CredentialSecurityConfigSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, unique: true },
  enabled: { type: Boolean, default: true },
  monitorProcesses: { type: Boolean, default: true },
  monitorCredentialStores: { type: Boolean, default: true },
  monitorLockScreen: { type: Boolean, default: true },
  scanIntervalSeconds: { type: Number, default: 20, min: 10, max: 3600 },
  minimumRiskScore: { type: Number, default: 50, min: 0, max: 100 },
  builtInRuleOverrides: { type: mongoose.Schema.Types.Mixed, default: {} },
  manualPolicies: { type: [ManualPolicySchema], default: [] },
  version: { type: Number, default: 1, min: 1 },
  lastDeployedAt: { type: Date, default: null },
  lastDeployedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true, versionKey: false });

module.exports = mongoose.models.CredentialSecurityConfig
  || mongoose.model('CredentialSecurityConfig', CredentialSecurityConfigSchema);
