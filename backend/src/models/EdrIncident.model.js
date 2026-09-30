const mongoose = require('mongoose');

/**
 * EdrIncident — represents a correlated security incident composed of
 * multiple raw alerts. Managed by the SOC AI Agent correlation engine.
 */
const EdrIncidentSchema = new mongoose.Schema({
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company',   required: true, index: true },
  correlationId:{ type: mongoose.Schema.Types.ObjectId, ref: 'CorrelationEvent', default: null, index: true },
  systemId:     { type: mongoose.Schema.Types.ObjectId, ref: 'System',    index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
  incidentSource: { type: String, enum: ['edr', 'threat_intelligence'], default: 'edr', index: true },

  // Incident identity
  title:       { type: String, required: true },
  description: { type: String },
  severity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
    index: true,
  },
  status: {
    type: String,
    enum: ['open', 'investigating', 'contained', 'resolved', 'false_positive'],
    default: 'open',
    index: true,
  },

  // MITRE ATT&CK
  mitreTechnique:    { type: String },  // e.g. T1059.001
  mitreTactics:      [{ type: String }], // e.g. ['Execution', 'Persistence']
  mitreTechniqueName:{ type: String },  // e.g. 'PowerShell'

  // Source alerts that were correlated into this incident
  alertIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Alert' }],

  // Explicit network evidence retained only when network telemetry participated
  // in the deterministic incident correlation.
  networkInvolved: { type: Boolean, default: false, index: true },
  networkEvidenceAlertIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Alert' }],

  // Affected assets
  affectedEndpoint: { type: String },  // hostname or IP
  affectedUser:     { type: String },
  agentId:          { type: String },
  agentName:        { type: String },

  // IOCs extracted from alerts
  iocs: [{
    type:  { type: String }, // ip, domain, hash, file, process, registry
    value: { type: String },
    context: { type: String },
  }],

  // Threat category
  category: {
    type: String,
    enum: [
      'malware','ransomware','credential_dumping','lateral_movement',
      'c2_communication','data_exfiltration','privilege_escalation',
      'persistence','reconnaissance','defense_evasion','process_injection',
      'living_off_land','brute_force','phishing','insider_threat',
      'zero_day','usb_threat','network_anomaly','policy_violation','other'
    ],
    default: 'other',
  },

  // Correlation score (0-100) — confidence this is a real incident
  confidenceScore: { type: Number, default: 50 },

  // AI analysis output
  aiAnalysis: { type: String },
  aiInvestigation: {
    status: { type: String, enum: ['not_required', 'queued', 'processing', 'completed', 'failed'], default: 'not_required' },
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'AiAnalysis', default: null },
    summary: { type: String, default: '' },
    rootCause: { type: String, default: '' },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    reasoning: { type: String, default: '' },
    recommendedSteps: [{ type: String }],
    completedAt: { type: Date, default: null },
  },
  recommendedActions: [{ type: String }],

  // Response actions taken
  actionsLog: [{
    action:    { type: String },
    target:    { type: String },
    result:    { type: String },
    takenBy:   { type: String }, // 'auto' | userId
    takenAt:   { type: Date, default: Date.now },
  }],

  // Assignment
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  resolvedAt: { type: Date },
  closedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },

  notes: [{
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    text: String,
    at:   Date,
  }],

  // Source tracking
  sourceAlertCount: { type: Number, default: 1 },
  firstEventAt:     { type: Date },
  lastEventAt:      { type: Date },

  rawCorrelationData: { type: mongoose.Schema.Types.Mixed },
}, { timestamps: true });

EdrIncidentSchema.index({ companyId: 1, severity: 1, status: 1 });
EdrIncidentSchema.index({ companyId: 1, createdAt: -1 });
EdrIncidentSchema.index({ companyId: 1, category: 1 });
EdrIncidentSchema.index({ companyId: 1, incidentSource: 1, createdAt: -1 });
EdrIncidentSchema.index({ companyId: 1, assignedTo: 1, status: 1, createdAt: -1 });
EdrIncidentSchema.index({ companyId: 1, correlationId: 1 }, { unique: true, sparse: true });
// Auto-delete incidents older than 180 days
EdrIncidentSchema.index({ createdAt: 1 }, { expireAfterSeconds: 180 * 24 * 60 * 60 });

module.exports = mongoose.model('EdrIncident', EdrIncidentSchema);
