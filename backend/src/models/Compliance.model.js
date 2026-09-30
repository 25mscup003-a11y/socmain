const mongoose = require('mongoose');

/**
 * ComplianceReport — stores automated compliance assessment snapshots.
 * Supports ISO 27001, PCI-DSS, GDPR, HIPAA frameworks.
 */
const ControlSchema = new mongoose.Schema({
  id:          { type: String },   // e.g. 'A.12.6.1'
  name:        { type: String },
  status:      { type: String, enum: ['pass', 'fail', 'partial', 'na'], default: 'na' },
  description: { type: String },
  evidence:    { type: String },   // what data was used
  score:       { type: Number, default: 0 }, // 0-100
}, { _id: false });

const FrameworkSchema = new mongoose.Schema({
  name:           { type: String },  // 'ISO_27001', 'PCI_DSS', 'GDPR', 'HIPAA'
  version:        { type: String },
  overallScore:   { type: Number, default: 0 },  // 0-100
  passCount:      { type: Number, default: 0 },
  failCount:      { type: Number, default: 0 },
  partialCount:   { type: Number, default: 0 },
  naCount:        { type: Number, default: 0 },
  controls:       [ControlSchema],
  status:         { type: String, enum: ['compliant','partial','non_compliant'], default: 'non_compliant' },
}, { _id: false });

const ComplianceReportSchema = new mongoose.Schema({
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', index: true },

  // When this report was generated (daily/weekly/monthly)
  reportType:   { type: String, enum: ['daily', 'weekly', 'monthly', 'manual'], default: 'daily' },
  periodStart:  { type: Date, required: true },
  periodEnd:    { type: Date, required: true },
  generatedAt:  { type: Date, default: Date.now },
  generatedBy:  { type: String, default: 'auto' }, // 'auto' | userId

  // Overall security score  (formula: 100 - violations*weights)
  securityScore: { type: Number, default: 100, min: 0, max: 100 },
  scoreBreakdown: {
    fileViolations:    { type: Number, default: 0 },
    usbViolations:     { type: Number, default: 0 },
    networkAttacks:    { type: Number, default: 0 },
    malwareEvents:     { type: Number, default: 0 },
    loginFailures:     { type: Number, default: 0 },
    unresolvedCritical:{ type: Number, default: 0 },
  },

  // Per-framework results
  frameworks: [FrameworkSchema],

  // Event summary for the period
  summary: {
    totalAlerts:          { type: Number, default: 0 },
    criticalAlerts:       { type: Number, default: 0 },
    highAlerts:           { type: Number, default: 0 },
    malwareEvents:        { type: Number, default: 0 },
    networkAttacks:       { type: Number, default: 0 },
    fileViolations:       { type: Number, default: 0 },
    usbEvents:            { type: Number, default: 0 },
    loginFailures:        { type: Number, default: 0 },
    activeSystems:        { type: Number, default: 0 },
    soarActionsExecuted:  { type: Number, default: 0 },
  },

  // Key violations (for PDF report)
  violations: [{ type: mongoose.Schema.Types.Mixed }],
}, { timestamps: true });

ComplianceReportSchema.index({ companyId: 1, reportType: 1, periodEnd: -1 });
// Auto-delete reports older than 1 year
ComplianceReportSchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

module.exports = mongoose.model('ComplianceReport', ComplianceReportSchema);
