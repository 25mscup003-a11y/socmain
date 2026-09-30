const mongoose = require('mongoose');

const ConditionSchema = new mongoose.Schema({
  field: { type: String, required: true, maxlength: 64 },
  operator: { type: String, enum: ['equals', 'contains', 'in', 'gte', 'exists'], default: 'equals' },
  value: { type: mongoose.Schema.Types.Mixed },
}, { _id: false });

const CorrelationRuleSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 200 },
  description: { type: String, default: '', maxlength: 2000 },
  enabled: { type: Boolean, default: true, index: true },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  riskScore: { type: Number, min: 0, max: 100, default: 70 },
  riskScoreMin: { type: Number, min: 0, max: 100, default: 60 },
  riskScoreMax: { type: Number, min: 0, max: 100, default: 70 },
  confidence: { type: Number, min: 0, max: 100, default: 75 },
  logic: { type: String, enum: ['AND', 'OR'], default: 'AND' },
  conditions: { type: [ConditionSchema], validate: value => value.length > 0 && value.length <= 20 },
  entityFields: [{ type: String, enum: ['systemId', 'endpointId', 'agentId', 'agentName', 'hostname', 'srcip', 'username'] }],
  threshold: { type: Number, min: 1, max: 1000, default: 1 },
  timeWindowSeconds: { type: Number, min: 60, max: 86400, default: 3600 },
  dataSources: [{ type: String, maxlength: 64 }],
  eventTypes: [{ type: String, maxlength: 128 }],
  mitreTactics: [{ type: String, maxlength: 100 }],
  mitreTechniques: [{ type: String, maxlength: 32 }],
  tags: [{ type: String, maxlength: 64 }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

CorrelationRuleSchema.index({ companyId: 1, enabled: 1, updatedAt: -1 });
CorrelationRuleSchema.index({ companyId: 1, departmentId: 1, enabled: 1 });
CorrelationRuleSchema.index({ companyId: 1, name: 1 }, { unique: true });

module.exports = mongoose.model('CorrelationRule', CorrelationRuleSchema);
