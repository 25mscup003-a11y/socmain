const mongoose = require('mongoose');

const ServiceMonitoringPolicySchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  enabled: { type: Boolean, default: true },
  eventTypes: [{ type: String, trim: true }],
  servicePatterns: [{ type: String, trim: true }],
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  riskScore: { type: Number, min: 0, max: 100, default: 50 },
  requireApproval: { type: Boolean, default: true },
  responseActions: [{ type: String, trim: true }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

ServiceMonitoringPolicySchema.index({ companyId: 1, departmentId: 1, enabled: 1 });
ServiceMonitoringPolicySchema.index({ companyId: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('ServiceMonitoringPolicy', ServiceMonitoringPolicySchema);
