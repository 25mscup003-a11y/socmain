const mongoose = require('mongoose');

const SoarApprovalSchema = new mongoose.Schema({
  tenantId:        { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:       { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:       { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null },

  executionId:     { type: mongoose.Schema.Types.ObjectId, ref: 'SoarExecution', required: true, index: true },
  stepId:          { type: String, required: true },
  ruleId:          { type: mongoose.Schema.Types.ObjectId, ref: 'SoarRule', default: null },
  playbookId:      { type: mongoose.Schema.Types.ObjectId, ref: 'ResponsePlaybook', default: null },
  alertId:         { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null },

  requestedAction: { type: String, required: true },
  targetResource:  { type: String, default: '' },
  targetSummary:   { type: String, default: '' },
  reason:          { type: String, default: '' },
  riskLevel:       { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  requiredRole:    { type: String, default: 'soc_manager' },

  status:          { type: String, enum: ['pending', 'approved', 'rejected', 'expired', 'cancelled'], default: 'pending', index: true },

  requestedBy:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  resolvedBy:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  requestedAt:     { type: Date, default: Date.now },
  resolvedAt:      { type: Date },
  expiresAt:       { type: Date, required: true, index: true },
  notes:           { type: String, default: '' },
  evidence:        { type: mongoose.Schema.Types.Mixed, default: {} },
}, { timestamps: true });

SoarApprovalSchema.index({ companyId: 1, status: 1, createdAt: -1 });
SoarApprovalSchema.index(
  { companyId: 1, ruleId: 1, targetResource: 1 },
  { unique: true, partialFilterExpression: { status: 'pending' }, name: 'one_pending_approval_per_rule_target' },
);

module.exports = mongoose.model('SoarApproval', SoarApprovalSchema);
