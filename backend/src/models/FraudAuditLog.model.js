/**
 * FraudAuditLog Model
 * Immutable audit trail for every fraud engine execution.
 * Records timing, inputs, outputs, and errors for compliance.
 */
const mongoose = require('mongoose');

const FraudAuditLogSchema = new mongoose.Schema({
  requestId:   { type: String, index: true },
  fraudEventId:{ type: mongoose.Schema.Types.ObjectId, ref: 'FraudEvent' },
  userId:      { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:       { type: String },

  // Execution context
  action:      { type: String },
  ipAddress:   { type: String },
  telemetryId: { type: String },
  visitorId:   { type: String },

  // Engine stages — each stage records success/failure and timing
  stages: {
    stytchLookup: {
      success: Boolean,
      durationMs: Number,
      simulated: Boolean,
      error: String,
    },
    rulesEngine: {
      success: Boolean,
      durationMs: Number,
      rulesEvaluated: Number,
      rulesMatched: Number,
      matchedRuleNames: [String],
    },
    decisionEngine: {
      success: Boolean,
      durationMs: Number,
      decision: String,
      riskScore: Number,
    },
    dbSave: {
      success: Boolean,
      durationMs: Number,
      error: String,
    },
  },

  // Final outcome
  finalDecision: { type: String, enum: ['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW'] },
  riskScore:     { type: Number },
  totalDurationMs:{ type: Number },
  error:         { type: String }, // top-level error if the whole pipeline failed
}, { timestamps: true });

FraudAuditLogSchema.index({ createdAt: -1 });
FraudAuditLogSchema.index({ companyId: 1, createdAt: -1 });

module.exports = mongoose.model('FraudAuditLog', FraudAuditLogSchema);
