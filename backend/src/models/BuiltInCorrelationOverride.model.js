const mongoose = require('mongoose');

const BuiltInCorrelationOverrideSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  patternId: { type: String, required: true, trim: true, uppercase: true, maxlength: 100 },
  enabled: { type: Boolean, default: true },
  name: { type: String, default: '', trim: true, maxlength: 200 },
  description: { type: String, default: '', maxlength: 2000 },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  confidence: { type: Number, min: 0, max: 100, default: 75 },
  riskScore: { type: Number, min: 0, max: 100, default: 70 },
  riskScoreMin: { type: Number, min: 0, max: 100, default: 60 },
  riskScoreMax: { type: Number, min: 0, max: 100, default: 70 },
  timeWindowSeconds: { type: Number, min: 60, max: 86400, default: 3600 },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

BuiltInCorrelationOverrideSchema.index({ companyId: 1, patternId: 1 }, { unique: true });

module.exports = mongoose.model('BuiltInCorrelationOverride', BuiltInCorrelationOverrideSchema);
