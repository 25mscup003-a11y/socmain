const mongoose = require('mongoose');

const TimeAnomalyPolicySchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  description: { type: String, default: '', maxlength: 1000 },
  enabled: { type: Boolean, default: true },
  priority: { type: Number, default: 100, min: 1, max: 10000 },
  systemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
  workingHoursStart: { type: Number, default: 8, min: 0, max: 23 },
  workingHoursEnd: { type: Number, default: 20, min: 0, max: 23 },
  weekendDays: { type: [{ type: Number, min: 0, max: 6 }], default: [5, 6] },
  holidays: [{ type: String, trim: true, maxlength: 10 }],
  timezone: { type: String, default: 'endpoint-local', maxlength: 64 },
  authFailureWindowSeconds: { type: Number, default: 300, min: 30, max: 86400 },
  authFailureThreshold: { type: Number, default: 5, min: 3, max: 10000 },
  anomalyRiskThreshold: { type: Number, default: 45, min: 0, max: 100 },
  alertCooldownSeconds: { type: Number, default: 3600, min: 300, max: 604800 },
  baselineMinimumSamples: { type: Number, default: 20, min: 1, max: 10000 },
  exceptions: [{
    type: { type: String, enum: ['user', 'service_account', 'host', 'process', 'ip', 'maintenance_window'] },
    value: { type: String, trim: true, maxlength: 500 },
    reason: { type: String, trim: true, maxlength: 500 },
    expiresAt: { type: Date, default: null },
  }],
  requireApprovalForResponse: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

TimeAnomalyPolicySchema.index({ companyId: 1, departmentId: 1, enabled: 1, priority: 1 });
TimeAnomalyPolicySchema.index({ companyId: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('TimeAnomalyPolicy', TimeAnomalyPolicySchema);
