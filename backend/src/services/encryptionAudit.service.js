const fs = require('fs');
const crypto = require('crypto');
const EncryptionAudit = require('../models/EncryptionAudit.model');
const EncryptionAuditCounter = require('../models/EncryptionAuditCounter.model');
const Alert = require('../models/Alert.model');
const { canonicalize, hmacSha256, sha256 } = require('../security/cryptoPrimitives');

function loadAuditKey() {
  const filename = process.env.ENCRYPTION_AUDIT_KEY_FILE || '';
  if (filename) {
    const stat = fs.statSync(filename);
    if (!stat.isFile()) throw new Error('ENCRYPTION_AUDIT_KEY_FILE must be a regular file');
    if (process.platform !== 'win32' && process.env.NODE_ENV === 'production' && (stat.mode & 0o077)) {
      throw new Error('Encryption audit signing key file permissions must be 0600 or stricter');
    }
    return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest();
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('ENCRYPTION_AUDIT_KEY_FILE is required in production');
  }
  const fallback = process.env.ENCRYPTION_AUDIT_KEY || process.env.KMS_MASTER_KEY_B64;
  if (!fallback) throw new Error('Encryption audit signing key is not configured');
  return crypto.createHash('sha256').update(String(fallback)).digest();
}

function requestMetadata(req = {}) {
  return {
    ipAddress: String(req.ip || req.socket?.remoteAddress || '').replace(/^::ffff:/, '').slice(0, 128),
    device: String(req.get?.('user-agent') || '').slice(0, 500),
  };
}

function hashable(entry) {
  return canonicalize({
    tenantId: String(entry.tenantId),
    companyId: entry.companyId ? String(entry.companyId) : null,
    actorId: entry.actorId ? String(entry.actorId) : null,
    actorRole: entry.actorRole,
    action: entry.action,
    outcome: entry.outcome,
    targetType: entry.targetType,
    targetId: entry.targetId,
    keyId: entry.keyId,
    keyVersion: entry.keyVersion,
    reason: entry.reason,
    ipAddress: entry.ipAddress,
    device: entry.device,
    requestId: entry.requestId,
    metadata: entry.metadata,
    sequence: entry.sequence,
    riskScore: entry.riskScore,
    riskSignals: entry.riskSignals,
    previousHash: entry.previousHash,
    createdAt: new Date(entry.createdAt).toISOString(),
  });
}

async function nextSequence(tenantId) {
  const counter = await EncryptionAuditCounter.findOneAndUpdate(
    { tenantId }, { $inc: { sequence: 1 } }, { upsert: true, new: true, setDefaultsOnInsert: true },
  ).lean();
  return counter.sequence;
}

async function waitForPrevious(tenantId, sequence) {
  if (sequence === 1) return null;
  for (let attempt = 0; attempt < 20; attempt += 1) {
    const previous = await EncryptionAudit.findOne({ tenantId, sequence: sequence - 1 }).select('entryHash').lean();
    if (previous) return previous;
    await new Promise(resolve => setTimeout(resolve, 10 * (attempt + 1)));
  }
  throw new Error('Unable to append encryption audit chain in sequence');
}

async function calculateRisk({ tenantId, actorId, action, outcome }) {
  const signals = [];
  let score = 0;
  if (outcome === 'failure' || outcome === 'denied') {
    score += 25;
    signals.push('failed-or-denied-operation');
  }
  if (/decrypt/i.test(action)) score += 10;
  if (/revoke|delete|export/i.test(action)) score += 20;
  if (actorId) {
    const failedRecently = await EncryptionAudit.countDocuments({
      tenantId, actorId, outcome: { $in: ['failure', 'denied'] },
      createdAt: { $gte: new Date(Date.now() - 15 * 60_000) },
    });
    if (failedRecently >= 3) {
      score += Math.min(45, failedRecently * 5);
      signals.push('multiple-recent-failures');
    }
    const tenants = await EncryptionAudit.distinct('tenantId', {
      actorId, action: /decrypt/i, createdAt: { $gte: new Date(Date.now() - 60 * 60_000) },
    });
    if (tenants.length > 1) {
      score += 35;
      signals.push('cross-tenant-decryption-pattern');
    }
  }
  return { riskScore: Math.min(100, score), riskSignals: signals };
}

async function appendEncryptionAudit(input, req = null) {
  const tenantId = input.tenantId;
  if (!tenantId) throw new Error('tenantId is required for encryption audit');
  const sequence = await nextSequence(tenantId);
  const previous = await waitForPrevious(tenantId, sequence);
  const observedAt = new Date();
  const request = req ? requestMetadata(req) : {};
  const risk = await calculateRisk({ tenantId, actorId: input.actorId, action: input.action, outcome: input.outcome });
  const entry = {
    tenantId,
    companyId: input.companyId || null,
    actorId: input.actorId || null,
    actorRole: input.actorRole || 'system',
    action: input.action,
    outcome: input.outcome || 'success',
    targetType: input.targetType || 'unknown',
    targetId: String(input.targetId || ''),
    keyId: String(input.keyId || ''),
    keyVersion: input.keyVersion ?? null,
    reason: String(input.reason || '').slice(0, 1000),
    ipAddress: input.ipAddress || request.ipAddress || '',
    device: input.device || request.device || '',
    requestId: String(input.requestId || ''),
    metadata: input.metadata || {},
    sequence,
    riskScore: risk.riskScore,
    riskSignals: risk.riskSignals,
    previousHash: previous?.entryHash || 'GENESIS',
    createdAt: observedAt,
  };
  // Hash the Mongoose-cast representation (ObjectIds, defaults and dates), so
  // verification of the persisted BSON produces byte-for-byte canonical data.
  const record = new EncryptionAudit(entry);
  entry.entryHash = sha256(`${entry.previousHash}:${hashable(record.toObject({ depopulate: true }))}`);
  const auditKey = loadAuditKey();
  try {
    entry.signature = hmacSha256(entry.entryHash, auditKey);
  } finally {
    auditKey.fill(0);
  }
  record.entryHash = entry.entryHash;
  record.signature = entry.signature;
  await record.save();
  if (record.riskScore >= Number(process.env.ENCRYPTION_ALERT_RISK_THRESHOLD || 70) && record.companyId) {
    await Alert.create({
      tenantId: record.tenantId,
      companyId: record.companyId,
      eventId: `crypto-${record.entryHash}`,
      eventFingerprint: `crypto-${record.entryHash}`,
      sourceType: 'IAM',
      sourceVendor: 'AJNAT KMS',
      normalizedEventType: 'encryption_security_anomaly',
      eventName: 'Suspicious encryption or decryption activity',
      eventTimestamp: observedAt,
      source: 'kms',
      type: 'ENCRYPTION_SECURITY_ANOMALY',
      eventCategory: 'system',
      category: 'encryption',
      severity: record.riskScore >= 90 ? 'critical' : 'high',
      riskScore: record.riskScore,
      actionable: true,
      description: `KMS risk signals: ${record.riskSignals.join(', ')}`,
      dataOrigin: 'manual',
      metadata: { encryptionAuditId: record._id, action: record.action },
    }).catch(error => {
      if (error?.code !== 11000) console.error('[encryption-audit-alert]', error.message);
    });
  }
  return record;
}

async function verifyAuditChain(tenantId) {
  const records = await EncryptionAudit.find({ tenantId }).sort({ sequence: 1 }).lean();
  const auditKey = loadAuditKey();
  let previousHash = 'GENESIS';
  try {
    for (const record of records) {
      const expectedHash = sha256(`${previousHash}:${hashable(record)}`);
      const expectedSignature = hmacSha256(record.entryHash, auditKey);
      if (record.previousHash !== previousHash) return { valid: false, checked: record.sequence - 1, brokenAt: String(record._id), reason: 'chain-link-mismatch' };
      if (record.entryHash !== expectedHash) return { valid: false, checked: record.sequence - 1, brokenAt: String(record._id), reason: 'entry-hash-mismatch' };
      if (record.signature !== expectedSignature) return { valid: false, checked: record.sequence - 1, brokenAt: String(record._id), reason: 'signature-mismatch' };
      previousHash = record.entryHash;
    }
    return { valid: true, checked: records.length, headHash: previousHash };
  } finally {
    auditKey.fill(0);
  }
}

module.exports = { appendEncryptionAudit, verifyAuditChain, requestMetadata, calculateRisk, _hashable: hashable };
