const mongoose = require('mongoose');

const RegistryConfigurationControlSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  kind: { type: String, enum: ['policy', 'baseline', 'exception'], default: 'policy', index: true },
  policyId: { type: String, trim: true, maxlength: 120, index: true },
  name: { type: String, required: true, trim: true, maxlength: 200 },
  category: { type: String, default: 'all', trim: true, maxlength: 120 },
  operation: { type: String, default: '', trim: true, maxlength: 80 },
  target: { type: String, default: '*', trim: true, maxlength: 2048 },
  expectedState: { type: mongoose.Schema.Types.Mixed, default: null },
  enabled: { type: Boolean, default: true, index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  riskThreshold: { type: Number, min: 0, max: 100, default: 50 },
  excludedHosts: [{ type: String }],
  excludedUsers: [{ type: String }],
  excludedProcesses: [{ type: String }],
  excludedPaths: [{ type: String }],
  allowedChanges: [{ type: String }],
  monitoringSchedule: { type: mongoose.Schema.Types.Mixed, default: null },
  alertAction: { type: String, default: 'alert', trim: true, maxlength: 80 },
  reason: { type: String, default: '', trim: true, maxlength: 1000 },
  ticketReference: { type: String, default: '', trim: true, maxlength: 160 },
  expiresAt: { type: Date, default: null, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

RegistryConfigurationControlSchema.index({ companyId: 1, departmentId: 1, kind: 1, enabled: 1, createdAt: -1 });
RegistryConfigurationControlSchema.index({ companyId: 1, departmentId: 1, policyId: 1 }, { unique: true, sparse: true });
RegistryConfigurationControlSchema.index({ companyId: 1, systemId: 1, target: 1, kind: 1, enabled: 1 });

module.exports = mongoose.model('RegistryConfigurationControl', RegistryConfigurationControlSchema);
