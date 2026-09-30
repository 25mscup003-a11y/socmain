const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  endpointId: { type: String, required: true, trim: true, maxlength: 256 },
  filePath: { type: String, required: true, trim: true, maxlength: 4096 },
  fileName: { type: String, trim: true, maxlength: 512 },
  sha256: { type: String, required: true, lowercase: true, match: /^[a-f0-9]{64}$/ },
  sha1: { type: String, lowercase: true, match: /^[a-f0-9]{40}$/ },
  md5: { type: String, lowercase: true, match: /^[a-f0-9]{32}$/ },
  fileSize: Number,
  signatureStatus: String,
  publisher: String,
  baselineVersion: { type: Number, default: 1, min: 1 },
  firstSeen: { type: Date, default: Date.now },
  lastSeen: { type: Date, default: Date.now },
  changedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  reason: { type: String, maxlength: 1000 },
}, { timestamps: true });

schema.index({ companyId: 1, endpointId: 1, filePath: 1 }, { unique: true });
schema.index({ companyId: 1, sha256: 1 });
module.exports = mongoose.model('HashSignatureBaseline', schema);

