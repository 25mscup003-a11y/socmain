const mongoose = require('mongoose');

const CustodyEventSchema = new mongoose.Schema({
  action: { type: String, required: true, maxlength: 80 },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  actorRole: { type: String, required: true },
  sourceIp: { type: String, default: '' },
  note: { type: String, default: '', maxlength: 1000 },
  at: { type: Date, default: Date.now },
}, { _id: false });

const ForensicEvidenceSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  huntId: { type: mongoose.Schema.Types.ObjectId, ref: 'ForensicHunt', default: null, index: true },
  evidenceId: { type: String, required: true, unique: true, index: true },
  name: { type: String, required: true, maxlength: 300 },
  type: { type: String, required: true, maxlength: 80 },
  sourceHost: { type: String, default: '', maxlength: 255 },
  artifactName: { type: String, default: '', maxlength: 240 },
  sizeBytes: { type: Number, default: 0, min: 0 },
  sha256: { type: String, required: true, match: /^[a-f0-9]{64}$/i },
  integrityStatus: { type: String, enum: ['verified', 'mismatch'], default: 'verified', index: true },
  storageState: { type: String, enum: ['metadata', 'secured', 'archived'], default: 'metadata' },
  encryption: {
    algorithm: { type: String, enum: ['AES-256-GCM', null], default: null },
    format: { type: String, enum: ['AJNAT-EVIDENCE-V1', null], default: null },
    keyId: { type: String, default: '', index: true },
    keyVersion: { type: Number, default: null },
    chunks: { type: Number, min: 0, default: 0 },
    encryptedAt: { type: Date, default: null },
    ciphertextSha256: { type: String, default: '', match: /^$|^[a-f0-9]{64}$/i },
  },
  storageLocator: { type: String, default: '', select: false },
  originalMimeType: { type: String, default: 'application/octet-stream', maxlength: 160 },
  tags: [{ type: String, maxlength: 80 }],
  collectedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  collectedAt: { type: Date, default: Date.now, index: true },
  custody: { type: [CustodyEventSchema], default: [] },
  aiAnalysis: {
    status: { type: String, enum: ['queued', 'processing', 'completed', 'failed'], default: 'queued', index: true },
    jobId: { type: mongoose.Schema.Types.ObjectId, ref: 'AiAnalysis', default: null },
    summary: { type: String, default: '', maxlength: 4000 },
    rootCause: { type: String, default: '', maxlength: 4000 },
    riskScore: { type: Number, min: 0, max: 100, default: 0 },
    confidence: { type: Number, min: 0, max: 100, default: 0 },
    recommendations: [{ type: String }],
    completedAt: { type: Date, default: null },
  },
}, { timestamps: true });

ForensicEvidenceSchema.index({ companyId: 1, collectedAt: -1 });
ForensicEvidenceSchema.index({ tenantId: 1, companyId: 1, integrityStatus: 1 });

ForensicEvidenceSchema.pre('validate', async function (next) {
  if (this.companyId && (!this.tenantId || this.isModified('companyId'))) {
    const Company = require('./Company.model');
    const company = await Company.findById(this.companyId).select('tenantId partnerId').lean();
    if (company) {
      this.tenantId = company.tenantId || null;
      this.partnerId = company.partnerId || null;
    }
  }
  next();
});

module.exports = mongoose.model('ForensicEvidence', ForensicEvidenceSchema);
