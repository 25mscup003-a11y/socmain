const mongoose = require('mongoose');

const MemoryDetectionRuleSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  ruleId: { type: String, required: true, trim: true, maxlength: 40 },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  description: { type: String, default: '', maxlength: 1200 },
  builtIn: { type: Boolean, default: false },
  enabled: { type: Boolean, default: true, index: true },
  operatingSystems: [{ type: String, enum: ['windows', 'linux', 'darwin', 'container'] }],
  hostGroupIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'SystemGroup' }],
  processExclusions: [{ type: String, maxlength: 260 }],
  allowlist: [{ type: String, maxlength: 260 }],
  threshold: { type: Number, default: null },
  timeWindowSeconds: { type: Number, default: 60, min: 1, max: 2592000 },
  minimumSampleCount: { type: Number, default: 1, min: 1, max: 10000 },
  cooldownSeconds: { type: Number, default: 300, min: 0, max: 2592000 },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  confidence: { type: Number, min: 0, max: 100, default: 80 },
  riskScore: { type: Number, min: 0, max: 100, default: 70 },
  alertGrouping: { type: String, enum: ['host', 'process', 'rule', 'target_process', 'none'], default: 'process' },
  suppressionEnabled: { type: Boolean, default: true },
  maintenanceWindows: [{
    startsAt: Date,
    endsAt: Date,
    reason: { type: String, maxlength: 300 },
  }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  auditHistory: [{
    action: { type: String, required: true },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    at: { type: Date, default: Date.now },
    changes: { type: mongoose.Schema.Types.Mixed, default: {} },
  }],
}, { timestamps: true, versionKey: false });

MemoryDetectionRuleSchema.index({ companyId: 1, ruleId: 1 }, { unique: true });
MemoryDetectionRuleSchema.index({ companyId: 1, enabled: 1, severity: 1 });

module.exports = mongoose.models.MemoryDetectionRule
  || mongoose.model('MemoryDetectionRule', MemoryDetectionRuleSchema);
