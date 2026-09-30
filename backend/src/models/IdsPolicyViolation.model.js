const mongoose = require('mongoose');

const IdsPolicyViolationSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  policyId: { type: mongoose.Schema.Types.ObjectId, ref: 'IdsIpsPolicy', required: true, index: true },
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', required: true, index: true },
  policyName: String,
  policyRevision: { type: Number, default: 1 },
  mode: { type: String, enum: ['detect', 'block'], required: true },
  severity: String,
  source: String,
  srcip: String,
  destip: String,
  destPort: Number,
  protocol: String,
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null },
  agentName: String,
  description: String,
  blocked: { type: Boolean, default: false },
}, { timestamps: true });

IdsPolicyViolationSchema.index({ alertId: 1, policyId: 1 }, { unique: true });
IdsPolicyViolationSchema.index({ companyId: 1, createdAt: -1 });

module.exports = mongoose.models.IdsPolicyViolation
  || mongoose.model('IdsPolicyViolation', IdsPolicyViolationSchema);
