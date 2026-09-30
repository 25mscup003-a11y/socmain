const mongoose = require('mongoose');

const EncryptionAuditCounterSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, unique: true, immutable: true },
  sequence: { type: Number, default: 0 },
}, { versionKey: false });

module.exports = mongoose.models.EncryptionAuditCounter
  || mongoose.model('EncryptionAuditCounter', EncryptionAuditCounterSchema);
