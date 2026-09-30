const mongoose = require('mongoose');

const AgentSecurityAuditSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  username: { type: String, required: true },
  role: { type: String, required: true },
  action: { type: String, required: true, maxlength: 80 },
  previousValue: { type: mongoose.Schema.Types.Mixed, default: null },
  newValue: { type: mongoose.Schema.Types.Mixed, default: null },
  sourceIp: { type: String, default: '' },
  device: { type: String, default: '' },
  result: { type: String, enum: ['queued', 'success', 'denied', 'failed'], required: true },
}, { timestamps: true, versionKey: false });

AgentSecurityAuditSchema.index({ createdAt: -1 });
AgentSecurityAuditSchema.index({ companyId: 1, createdAt: -1 });

module.exports = mongoose.models.AgentSecurityAudit
  || mongoose.model('AgentSecurityAudit', AgentSecurityAuditSchema);
