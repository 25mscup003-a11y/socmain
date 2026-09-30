const mongoose = require('mongoose');

const AiAnalysisSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  requestedByRole: { type: String, required: true },
  taskType: {
    type: String,
    enum: ['correlation_analysis', 'security_event_analysis', 'edr_incident_analysis', 'soar_execution_analysis', 'forensic_evidence_analysis', 'alert_investigation', 'threat_hunt_query'],
    required: true,
    index: true,
  },
  resourceType: { type: String, enum: ['CorrelationEvent', 'Alert', 'EdrIncident', 'SoarExecution', 'ForensicEvidence', 'Hunt'], required: true },
  resourceId: { type: mongoose.Schema.Types.ObjectId, default: null, index: true },
  cacheKey: { type: String, required: true, index: true },
  status: { type: String, enum: ['queued', 'processing', 'completed', 'failed'], default: 'queued', index: true },
  model: { type: String, default: '' },
  promptVersion: { type: String, default: 'v1' },
  inputSummary: { type: mongoose.Schema.Types.Mixed, default: {} },
  output: { type: mongoose.Schema.Types.Mixed, default: null },
  confidence: { type: Number, min: 0, max: 100, default: 0 },
  reasoning: { type: String, default: '', maxlength: 8000 },
  error: { type: String, default: '', maxlength: 1000 },
  sourceIp: { type: String, default: '' },
  startedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
}, { timestamps: true, versionKey: false });

AiAnalysisSchema.index({ companyId: 1, resourceId: 1, taskType: 1, createdAt: -1 });
AiAnalysisSchema.index({ cacheKey: 1, status: 1, completedAt: -1 });
AiAnalysisSchema.index({ createdAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.models.AiAnalysis || mongoose.model('AiAnalysis', AiAnalysisSchema);
