const mongoose = require('mongoose');

/**
 * ResponsePlaybook — stores SOAR-style response playbooks with IF/THEN logic.
 * More powerful than SoarRule — supports multi-step chains, approvals, rollback.
 */

const PlaybookConditionSchema = new mongoose.Schema({
  field:    { type: String, required: true },   // e.g. 'severity', 'threatType', 'ruleId'
  operator: {
    type: String,
    enum: ['eq', 'neq', 'contains', 'not_contains', 'in', 'gt', 'gte', 'lt', 'lte'],
    required: true,
  },
  value:    { type: mongoose.Schema.Types.Mixed, required: true },
}, { _id: false });

const PlaybookStepSchema = new mongoose.Schema({
  order:          { type: Number, required: true },
  actionType:     { type: String, required: true },
  connectorId:    { type: mongoose.Schema.Types.ObjectId, ref: 'SoarConnector', default: null },
  actionParams:   { type: mongoose.Schema.Types.Mixed, default: {} },
  description:    { type: String, default: '' },
  requireApproval:{ type: Boolean, default: false },
  continueOnFail: { type: Boolean, default: true },
  delayMs:        { type: Number, default: 0 },   // delay before this step
}, { _id: false });

const ResponsePlaybookSchema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },

  builtInKey:    { type: String, default: null },
  isBuiltIn:     { type: Boolean, default: false, index: true },

  name:         { type: String, required: true },
  description:  { type: String, default: '' },
  enabled:      { type: Boolean, default: true },
  priority:     { type: Number, default: 100 },

  // Trigger conditions
  conditions:   { type: [PlaybookConditionSchema], default: [] },
  conditionLogic: {
    type: String,
    enum: ['AND', 'OR'],
    default: 'AND',
  },

  // Response steps (ordered)
  steps:        { type: [PlaybookStepSchema], default: [] },

  // Settings
  stopOnMatch:         { type: Boolean, default: false },
  requireGlobalApproval:{ type: Boolean, default: false },
  maxExecutionsPerHour:{ type: Number, default: 10 },
  executionMode: {
    type: String,
    enum: ['automatic', 'approval_required', 'manual_only', 'disabled'],
    default: 'approval_required',
  },
  timeoutMs:          { type: Number, default: 60_000 },
  retryCount:         { type: Number, default: 1 },
  cooldownMinutes:    { type: Number, default: 15 },
  rollbackEnabled:    { type: Boolean, default: true },
  dryRun:             { type: Boolean, default: false },
  simulationMode:     { type: Boolean, default: false },
  tags:         [{ type: String }],

  // Stats
  matchCount:   { type: Number, default: 0 },
  successCount: { type: Number, default: 0 },
  failCount:    { type: Number, default: 0 },
  lastMatchAt:  { type: Date },
  createdBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

ResponsePlaybookSchema.index({ companyId: 1, enabled: 1, priority: 1 });
ResponsePlaybookSchema.index({ companyId: 1, departmentId: 1, enabled: 1, priority: 1 });
ResponsePlaybookSchema.index(
  { companyId: 1, builtInKey: 1 },
  { unique: true, partialFilterExpression: { builtInKey: { $type: 'string' } } },
);

module.exports = mongoose.model('ResponsePlaybook', ResponsePlaybookSchema);
