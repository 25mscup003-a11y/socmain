const mongoose = require('mongoose');

const WrappedKeySchema = new mongoose.Schema({
  provider: { type: String, enum: ['local-file', 'aws-kms'], required: true },
  algorithm: { type: String, required: true },
  keyReference: { type: String, required: true },
  // The parent `wrappedKey` field is excluded from ordinary queries. Keeping
  // nested fields selectable is required when the parent is explicitly loaded
  // by the KMS service; nested select:false paths otherwise produce an
  // incomplete, undecryptable envelope.
  iv: { type: String, default: '' },
  authTag: { type: String, default: '' },
  ciphertext: { type: String, required: true },
  encryptionContext: { type: mongoose.Schema.Types.Mixed, default: {} },
}, { _id: false });

const TenantEncryptionKeySchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  keyId: { type: String, required: true, unique: true, immutable: true, index: true },
  version: { type: Number, required: true, min: 1, immutable: true },
  algorithm: { type: String, enum: ['AES-256-GCM'], default: 'AES-256-GCM', immutable: true },
  status: { type: String, enum: ['active', 'retired', 'revoked', 'expired'], default: 'active', index: true },
  wrappedKey: { type: WrappedKeySchema, required: true, select: false },
  activatedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true, index: true },
  retiredAt: { type: Date, default: null },
  revokedAt: { type: Date, default: null },
  revocationReason: { type: String, default: '', maxlength: 500 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  rotatedFromKeyId: { type: String, default: null },
}, { timestamps: true });

TenantEncryptionKeySchema.index({ tenantId: 1, version: 1 }, { unique: true });
TenantEncryptionKeySchema.index(
  { tenantId: 1, status: 1 },
  { unique: true, partialFilterExpression: { status: 'active' } },
);

module.exports = mongoose.models.TenantEncryptionKey
  || mongoose.model('TenantEncryptionKey', TenantEncryptionKeySchema);
