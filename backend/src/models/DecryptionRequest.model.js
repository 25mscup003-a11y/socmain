const mongoose = require('mongoose');

const DecryptionRequestSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  requestId: { type: String, required: true, unique: true, immutable: true, index: true },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  requestedByRole: { type: String, required: true },
  targetType: { type: String, required: true },
  targetId: { type: String, required: true },
  reason: { type: String, required: true, maxlength: 1000 },
  status: { type: String, enum: ['pending', 'approved', 'denied', 'consumed', 'expired'], default: 'pending', index: true },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt: { type: Date, default: null },
  deniedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  deniedAt: { type: Date, default: null },
  expiresAt: { type: Date, required: true, index: true },
  consumedAt: { type: Date, default: null },
  sourceIp: { type: String, default: '' },
  device: { type: String, default: '' },
}, { timestamps: true });

DecryptionRequestSchema.index({ tenantId: 1, companyId: 1, createdAt: -1 });

module.exports = mongoose.models.DecryptionRequest
  || mongoose.model('DecryptionRequest', DecryptionRequestSchema);
