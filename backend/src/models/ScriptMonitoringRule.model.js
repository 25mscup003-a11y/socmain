const mongoose = require('mongoose');

const ScriptMonitoringRuleSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  description: { type: String, default: '', maxlength: 1000 },
  enabled: { type: Boolean, default: true },
  priority: { type: Number, default: 100, min: 1, max: 10000 },
  systemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
  interpreters: [{ type: String, trim: true, maxlength: 64 }],
  trustedPaths: [{ type: String, trim: true, maxlength: 1000 }],
  trustedHashes: [{ type: String, lowercase: true, trim: true, match: /^[a-f0-9]{64}$/ }],
  trustedPublishers: [{ type: String, trim: true, maxlength: 300 }],
  riskThreshold: { type: Number, default: 30, min: 0, max: 100 },
  alertCooldownSeconds: { type: Number, default: 900, min: 60, max: 604800 },
  detectEncodedCommands: { type: Boolean, default: true },
  detectObfuscation: { type: Boolean, default: true },
  detectDownloadExecution: { type: Boolean, default: true },
  detectPersistence: { type: Boolean, default: true },
  detectExternalConnections: { type: Boolean, default: true },
  requireApprovalForResponse: { type: Boolean, default: true },
  riskWeights: { type: mongoose.Schema.Types.Mixed, default: {} },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

ScriptMonitoringRuleSchema.index({ companyId: 1, departmentId: 1, enabled: 1, priority: 1 });
ScriptMonitoringRuleSchema.index({ companyId: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('ScriptMonitoringRule', ScriptMonitoringRuleSchema);
