const mongoose = require('mongoose');

const StepSchema = new mongoose.Schema({
  stepId:          { type: String },
  name:            { type: String },
  actionType:      { type: String },
  connectorId:     { type: mongoose.Schema.Types.ObjectId, ref: 'SoarConnector', default: null },
  status:          { type: String, enum: ['queued', 'running', 'waiting_for_approval', 'waiting_for_agent', 'waiting_for_retry', 'completed', 'failed', 'skipped', 'rolled_back'], default: 'queued' },
  automatedResponseId: { type: mongoose.Schema.Types.ObjectId, ref: 'AutomatedResponse', default: null, index: true },
  input:           { type: mongoose.Schema.Types.Mixed, default: {} },
  output:          { type: mongoose.Schema.Types.Mixed, default: {} },
  errorCode:       { type: String, default: '' },
  errorMessage:    { type: String, default: '' },
  retryCount:      { type: Number, default: 0 },
  startedAt:       { type: Date },
  completedAt:     { type: Date },
  durationMs:      { type: Number, default: 0 },
  rollbackStatus:  { type: String, default: 'none' },
}, { _id: true });

const SoarExecutionSchema = new mongoose.Schema({
  tenantId:       { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:      { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },

  ruleId:         { type: mongoose.Schema.Types.ObjectId, ref: 'SoarRule', default: null, index: true },
  playbookId:     { type: mongoose.Schema.Types.ObjectId, ref: 'ResponsePlaybook', default: null, index: true },
  alertId:        { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null, index: true },
  incidentId:     { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', default: null, index: true },
  ticketId:       { type: mongoose.Schema.Types.ObjectId, ref: 'CompanySupportTicket', default: null, index: true },
  socTicketAlertId:{ type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null, index: true },

  ruleName:       { type: String, default: '' },
  playbookName:   { type: String, default: '' },
  companyName:    { type: String, default: '' },

  triggerType:    { type: String, default: 'new_alert' },
  triggerPayload: { type: mongoose.Schema.Types.Mixed, default: {} },

  status: {
    type: String,
    enum: [
      'queued', 'running', 'waiting_for_approval', 'waiting_for_agent', 'waiting_for_retry',
      'completed', 'partially_completed', 'failed', 'cancelled',
      'timed_out', 'rollback_running', 'rolled_back', 'rollback_failed',
    ],
    default: 'queued',
    index: true,
  },

  currentStep:    { type: Number, default: 0 },
  currentStepName:{ type: String, default: '' },
  steps:          { type: [StepSchema], default: [] },
  variables:      { type: mongoose.Schema.Types.Mixed, default: {} },

  idempotencyKey: { type: String, required: true, unique: true, index: true },
  retryCount:     { type: Number, default: 0 },
  maxRetries:     { type: Number, default: 2 },
  successActions: { type: Number, default: 0 },
  failedActions:  { type: Number, default: 0 },

  errorCode:      { type: String, default: '' },
  errorMessage:   { type: String, default: '' },
  startedAt:      { type: Date, default: Date.now },
  completedAt:    { type: Date },
  durationMs:     { type: Number, default: 0 },

  executionType:  { type: String, enum: ['automatic', 'manual', 'dry_run', 'test'], default: 'automatic' },
  triggeredBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  assignedAnalyst:{ type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  correlationId:  { type: String, index: true },
  aiInvestigation: {
    status: { type: String, enum: ['not_required', 'queued', 'processing', 'completed', 'failed'], default: 'not_required' },
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'AiAnalysis', default: null },
    summary: { type: String, default: '', maxlength: 4000 },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    reasoning: { type: String, default: '', maxlength: 8000 },
    completedAt: { type: Date, default: null },
  },
}, { timestamps: true });

SoarExecutionSchema.index({ companyId: 1, status: 1, createdAt: -1 });
SoarExecutionSchema.index({ tenantId: 1, companyId: 1, createdAt: -1 });

module.exports = mongoose.model('SoarExecution', SoarExecutionSchema);
