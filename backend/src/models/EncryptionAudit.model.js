const mongoose = require('mongoose');

const EncryptionAuditSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true, immutable: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true, immutable: true },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true, immutable: true },
  actorRole: { type: String, default: 'system', immutable: true },
  action: { type: String, required: true, index: true, immutable: true },
  outcome: { type: String, enum: ['success', 'failure', 'denied'], required: true, index: true, immutable: true },
  targetType: { type: String, required: true, maxlength: 80, immutable: true },
  targetId: { type: String, default: '', maxlength: 160, immutable: true },
  keyId: { type: String, default: '', index: true, immutable: true },
  keyVersion: { type: Number, default: null, immutable: true },
  reason: { type: String, default: '', maxlength: 1000, immutable: true },
  ipAddress: { type: String, default: '', maxlength: 128, immutable: true },
  device: { type: String, default: '', maxlength: 500, immutable: true },
  requestId: { type: String, default: '', index: true, immutable: true },
  sequence: { type: Number, required: true, min: 1, immutable: true },
  riskScore: { type: Number, min: 0, max: 100, default: 0, immutable: true },
  riskSignals: [{ type: String, maxlength: 200 }],
  metadata: { type: mongoose.Schema.Types.Mixed, default: {}, immutable: true },
  previousHash: { type: String, required: true, immutable: true },
  entryHash: { type: String, required: true, unique: true, immutable: true, index: true },
  signature: { type: String, required: true, immutable: true },
}, { timestamps: { createdAt: true, updatedAt: false }, versionKey: false });

EncryptionAuditSchema.index({ tenantId: 1, createdAt: -1 });
EncryptionAuditSchema.index({ companyId: 1, createdAt: -1 });
EncryptionAuditSchema.index({ tenantId: 1, sequence: 1 }, { unique: true });
EncryptionAuditSchema.pre('save', function rejectExistingSave(next) {
  if (!this.isNew) return next(new Error('Encryption audit records are immutable and append-only'));
  next();
});
for (const operation of ['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete']) {
  EncryptionAuditSchema.pre(operation, function rejectMutation() {
    throw new Error('Encryption audit records are immutable and append-only');
  });
}

module.exports = mongoose.models.EncryptionAudit
  || mongoose.model('EncryptionAudit', EncryptionAuditSchema);
