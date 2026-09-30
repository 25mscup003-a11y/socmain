const mongoose = require('mongoose');
const crypto = require('crypto');

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    if (value instanceof Date) return JSON.stringify(value.toISOString());
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value ?? null);
}

function hashPayload(document) {
  const value = document.toObject ? document.toObject({ depopulate: true }) : { ...document };
  delete value.__v; delete value.entryHash; delete value.previousHash; delete value.signature; delete value.createdAt; delete value.updatedAt;
  return canonicalize(value);
}

function signingKey() {
  const key = process.env.SOAR_AUDIT_SIGNING_KEY || process.env.SOAR_VAULT_SECRET || process.env.JWT_SECRET;
  if (!key) throw new Error('SOAR_AUDIT_SIGNING_KEY (or SOAR_VAULT_SECRET/JWT_SECRET fallback) is required');
  return key;
}

const SoarAuditLogSchema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null },

  user:         { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  userName:     { type: String, default: 'System' },
  userRole:     { type: String, default: 'system' },

  action:       { type: String, required: true, index: true },
  resourceType: { type: String, required: true, index: true },
  resourceId:   { type: String, default: null },

  previousValue:{ type: mongoose.Schema.Types.Mixed, default: null },
  newValue:     { type: mongoose.Schema.Types.Mixed, default: null },
  ipAddress:    { type: String, default: '' },
  userAgent:    { type: String, default: '' },
  correlationId:{ type: String, default: '' },
  result:       { type: String, enum: ['success', 'failure', 'denied'], default: 'success' },
  message:      { type: String, default: '' },
  previousHash: { type: String, default: 'GENESIS', immutable: true },
  entryHash:    { type: String, required: true, unique: true, sparse: true, immutable: true, index: true },
  signature:    { type: String, required: true, immutable: true },
}, { timestamps: true });

SoarAuditLogSchema.index({ companyId: 1, createdAt: -1 });

SoarAuditLogSchema.pre('validate', async function buildAuditHash() {
  if (!this.isNew || this.entryHash) return;
  const previous = await this.constructor.findOne({ companyId: this.companyId }).sort({ createdAt: -1, _id: -1 }).select('entryHash').lean();
  this.previousHash = previous?.entryHash || 'GENESIS';
  this.entryHash = crypto.createHash('sha256').update(`${this.previousHash}:${hashPayload(this)}`).digest('hex');
  this.signature = crypto.createHmac('sha256', signingKey()).update(this.entryHash).digest('hex');
});

for (const operation of ['updateOne', 'updateMany', 'findOneAndUpdate', 'replaceOne', 'deleteOne', 'deleteMany', 'findOneAndDelete']) {
  SoarAuditLogSchema.pre(operation, function rejectAuditMutation() {
    throw new Error('SOAR audit records are append-only and cannot be modified or deleted');
  });
}

SoarAuditLogSchema.statics.verifyCompanyChain = async function verifyCompanyChain(filter) {
  const records = await this.find(filter).sort({ createdAt: 1, _id: 1 }).lean();
  let expectedPrevious = 'GENESIS';
  let legacyRecords = 0;
  for (const record of records) {
    if (!record.entryHash) { legacyRecords += 1; expectedPrevious = 'GENESIS'; continue; }
    const expectedHash = crypto.createHash('sha256').update(`${record.previousHash}:${hashPayload(record)}`).digest('hex');
    const expectedSignature = crypto.createHmac('sha256', signingKey()).update(record.entryHash).digest('hex');
    if (record.previousHash !== expectedPrevious || record.entryHash !== expectedHash || record.signature !== expectedSignature) {
      return { valid: false, checked: records.length - legacyRecords, legacyRecords, brokenAt: String(record._id) };
    }
    expectedPrevious = record.entryHash;
  }
  return { valid: true, checked: records.length - legacyRecords, legacyRecords, headHash: expectedPrevious };
};

module.exports = mongoose.model('SoarAuditLog', SoarAuditLogSchema);
