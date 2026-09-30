const mongoose = require('mongoose');

const EncryptionJobSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  operation: { type: String, enum: ['encrypt', 'decrypt', 'rotate', 'backup'], required: true, index: true },
  targetType: { type: String, required: true },
  targetId: { type: String, default: '' },
  status: { type: String, enum: ['queued', 'processing', 'completed', 'failed', 'cancelled'], default: 'queued', index: true },
  progress: { type: Number, min: 0, max: 100, default: 0 },
  bytesProcessed: { type: Number, min: 0, default: 0 },
  totalBytes: { type: Number, min: 0, default: 0 },
  chunksCompleted: { type: Number, min: 0, default: 0 },
  outputBytes: { type: Number, min: 0, default: 0 },
  keyId: { type: String, default: '' },
  keyVersion: { type: Number, default: null },
  sourcePath: { type: String, default: '', select: false },
  destinationPath: { type: String, default: '', select: false },
  originalName: { type: String, default: '', maxlength: 300 },
  mimeType: { type: String, default: 'application/octet-stream', maxlength: 160 },
  evidenceType: { type: String, default: 'Uploaded Evidence', maxlength: 80 },
  error: { type: String, default: '', maxlength: 2000 },
  startedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
}, { timestamps: true });

EncryptionJobSchema.index({ tenantId: 1, createdAt: -1 });
EncryptionJobSchema.index({ companyId: 1, status: 1, createdAt: -1 });

module.exports = mongoose.models.EncryptionJob || mongoose.model('EncryptionJob', EncryptionJobSchema);
