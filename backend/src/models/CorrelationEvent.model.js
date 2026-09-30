const mongoose = require('mongoose');

/**
 * CorrelationEvent — stores detected multi-step attack chains.
 * The correlation engine analyzes recent alerts and detects attack patterns.
 */
const CorrelationEventSchema = new mongoose.Schema({
  incidentId:   { type: String, default: () => `COR-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 7).toUpperCase()}`, index: true },
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', index: true },
  systemId:     { type: mongoose.Schema.Types.ObjectId, ref: 'System' },

  // Attack pattern that was matched
  patternId:    { type: String },   // e.g. 'USB_EXFIL', 'BRUTE_MALWARE', 'LATERAL_MOVE'
  patternName:  { type: String },   // Human-readable attack name
  incidentSource: { type: String, enum: ['edr', 'threat_intelligence'], default: 'edr', index: true },
  description:  { type: String },   // What the correlation detected

  // Alert IDs that form this chain
  alertIds:     [{ type: mongoose.Schema.Types.ObjectId, ref: 'Alert' }],
  relatedAlertIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Alert' }],
  agentName:    { type: String },

  // Risk assessment
  severity:     { type: String, enum: ['low','medium','high','critical'], default: 'high' },
  confidence:   { type: Number, min: 0, max: 100, default: 80 }, // % confidence
  riskScore:    { type: Number, min: 0, max: 100, default: 80 },
  mitreTechniques: [{ type: String }],
  mitreTactics: [{ type: String }],
  coveredCapabilityIds: [{ type: Number, min: 1, max: 38 }],
  iocs:         [{ type: String }],
  evidence:     [{ type: mongoose.Schema.Types.Mixed }],
  timeline:     [{
    alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert' },
    timestamp: Date,
    category: String,
    severity: String,
    description: String,
    source: String,
  }],
  eventCount:   { type: Number, default: 0 },
  occurrenceCount: { type: Number, default: 1 },
  lastMatchSignature: { type: String, default: '', maxlength: 500 },
  suppressedDuplicateCount: { type: Number, default: 0 },
  lastActivityAt: { type: Date, default: Date.now, index: true },
  lastNotifiedAt: { type: Date, default: null },

  // Status
  status:       { type: String, enum: ['open','investigating','resolved','false_positive','benign'], default: 'open' },
  verdict:      { type: String, enum: ['undetermined','true_positive','false_positive','benign'], default: 'undetermined', index: true },
  dispositionReason: { type: String, default: '', maxlength: 4000 },
  dispositionBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  dispositionAt: { type: Date, default: null },
  managerVisibleAt: { type: Date, default: Date.now, index: true },
  resolvedAt:   { type: Date },
  assignedTo:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  notes:        { type: String },
  resolutionHistory: [{
    status: String,
    notes: String,
    changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    changedAt: { type: Date, default: Date.now },
  }],

  // Time window in which all events occurred
  windowStart:  { type: Date },
  windowEnd:    { type: Date },

  // Auto-SOAR triggered?
  soarTriggered:{ type: Boolean, default: false },
  linkedIncidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', default: null, index: true },
}, { timestamps: true });

CorrelationEventSchema.index({ companyId: 1, severity: 1, createdAt: -1 });
CorrelationEventSchema.index({ companyId: 1, status: 1 });
CorrelationEventSchema.index({ companyId: 1, status: 1, lastActivityAt: -1 });
CorrelationEventSchema.index({ companyId: 1, assignedTo: 1, status: 1, lastActivityAt: -1 });
CorrelationEventSchema.index({ tenantId: 1, companyId: 1, lastActivityAt: -1 });
CorrelationEventSchema.index({ companyId: 1, systemId: 1, patternId: 1, lastActivityAt: -1 });
CorrelationEventSchema.index({ companyId: 1, agentName: 1, patternId: 1, lastActivityAt: -1 });
// Auto-delete after 90 days
CorrelationEventSchema.index({ createdAt: 1 }, { expireAfterSeconds: 90 * 24 * 60 * 60 });

module.exports = mongoose.model('CorrelationEvent', CorrelationEventSchema);
