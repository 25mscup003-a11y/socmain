const mongoose = require('mongoose');

const EncryptedEnvelopeSchema = new mongoose.Schema({
  version: { type: Number, default: 1 },
  algorithm: { type: String, enum: ['AES-256-GCM'], required: true },
  keyId: { type: String, required: true, index: true },
  keyVersion: { type: Number, required: true },
  iv: { type: String, required: true },
  authTag: { type: String, required: true },
  ciphertext: { type: String, required: true },
  aadSha256: { type: String, required: true },
}, { _id: false });

const SecureRecordSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  category: {
    type: String,
    enum: ['api-key', 'oauth-token', 'jwt-refresh-token', 'smtp', 'ldap', 'threat-intelligence', 'cloud', 'security-policy', 'customer-secret', 'tenant-metadata', 'investigation-note', 'ioc-collection', 'case-data', 'configuration', 'backup-metadata', 'other'],
    required: true,
    index: true,
  },
  name: { type: String, required: true, trim: true, maxlength: 200 },
  encrypted: { type: EncryptedEnvelopeSchema, required: true, select: false },
  fingerprint: { type: String, required: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  lastDecryptedAt: { type: Date, default: null },
}, { timestamps: true });

SecureRecordSchema.index({ tenantId: 1, companyId: 1, category: 1, name: 1 }, { unique: true });
SecureRecordSchema.methods.toJSON = function () {
  const value = this.toObject();
  delete value.encrypted;
  value.encryptedAtRest = true;
  return value;
};

module.exports = mongoose.models.SecureRecord || mongoose.model('SecureRecord', SecureRecordSchema);
