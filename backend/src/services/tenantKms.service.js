const crypto = require('crypto');
const TenantEncryptionKey = require('../models/TenantEncryptionKey.model');
const { getKeyProvider } = require('./keyProvider.service');
const { canonicalize, encryptAes256Gcm, decryptAes256Gcm, hmacSha256 } = require('../security/cryptoPrimitives');

const DEFAULT_ROTATION_DAYS = Math.max(1, Number(process.env.KMS_ROTATION_DAYS || 90));
const AUTO_ROTATE_BEFORE_DAYS = Math.max(0, Number(process.env.KMS_AUTO_ROTATE_BEFORE_DAYS || 7));
let rotationTimer = null;

function keyContext(tenantId, keyId, version) {
  return { tenantId: String(tenantId), keyId: String(keyId), version: String(version), purpose: 'tenant-dek' };
}

function dataContext({ tenantId, companyId = null, purpose, recordId = '' }) {
  if (!tenantId || !purpose) throw new Error('tenantId and purpose are required encryption context');
  return {
    tenantId: String(tenantId),
    companyId: companyId ? String(companyId) : '',
    purpose: String(purpose),
    recordId: String(recordId || ''),
  };
}

async function createTenantKey({ tenantId, actorId = null, expiresAt = null, rotatedFromKeyId = null }) {
  if (!tenantId) throw new Error('tenantId is required');
  const provider = getKeyProvider();
  const last = await TenantEncryptionKey.findOne({ tenantId }).sort({ version: -1 }).select('version').lean();
  const version = Number(last?.version || 0) + 1;
  const keyId = `dek-${crypto.randomUUID()}`;
  const dek = crypto.randomBytes(32);
  try {
    const wrappedKey = await provider.wrapKey(dek, keyContext(tenantId, keyId, version));
    return await TenantEncryptionKey.create({
      tenantId, keyId, version, wrappedKey, status: 'active', createdBy: actorId,
      rotatedFromKeyId,
      expiresAt: expiresAt || new Date(Date.now() + DEFAULT_ROTATION_DAYS * 86400_000),
    });
  } finally {
    dek.fill(0);
  }
}

async function activeTenantKey(tenantId, actorId = null) {
  let record = await TenantEncryptionKey.findOne({ tenantId, status: 'active' }).select('+wrappedKey');
  if (!record) {
    try {
      record = await createTenantKey({ tenantId, actorId });
      record = await TenantEncryptionKey.findById(record._id).select('+wrappedKey');
    } catch (error) {
      if (error?.code !== 11000) throw error;
      record = await TenantEncryptionKey.findOne({ tenantId, status: 'active' }).select('+wrappedKey');
    }
  }
  if (!record) throw new Error('Unable to establish an active tenant encryption key');
  if (record.expiresAt <= new Date()) throw new Error('Active tenant encryption key is expired and must be rotated');
  return record;
}

async function unwrapRecord(record) {
  if (!record?.wrappedKey) throw new Error('Wrapped key material was not loaded');
  if (record.status === 'revoked') throw new Error('Encryption key is revoked');
  return getKeyProvider().unwrapKey(record.wrappedKey.toObject ? record.wrappedKey.toObject() : record.wrappedKey,
    keyContext(record.tenantId, record.keyId, record.version));
}

async function encryptValue({ tenantId, companyId = null, purpose, recordId = '', value, actorId = null }) {
  const keyRecord = await activeTenantKey(tenantId, actorId);
  const dek = await unwrapRecord(keyRecord);
  const context = dataContext({ tenantId, companyId, purpose, recordId });
  try {
    const encoded = Buffer.from(JSON.stringify({ type: Buffer.isBuffer(value) ? 'buffer' : 'json', value: Buffer.isBuffer(value) ? value.toString('base64') : value }), 'utf8');
    const encrypted = encryptAes256Gcm(encoded, dek, context);
    return {
      version: 1,
      ...encrypted,
      keyId: keyRecord.keyId,
      keyVersion: keyRecord.version,
      fingerprint: hmacSha256(encoded, dek),
    };
  } finally {
    dek.fill(0);
  }
}

async function decryptValue({ tenantId, companyId = null, purpose, recordId = '', envelope }) {
  const keyRecord = await TenantEncryptionKey.findOne({ tenantId, keyId: envelope?.keyId }).select('+wrappedKey');
  if (!keyRecord) throw new Error('Encryption key is unavailable in this tenant');
  const dek = await unwrapRecord(keyRecord);
  const context = dataContext({ tenantId, companyId, purpose, recordId });
  try {
    const clear = decryptAes256Gcm(envelope, dek, context);
    const parsed = JSON.parse(clear.toString('utf8'));
    return parsed.type === 'buffer' ? Buffer.from(parsed.value, 'base64') : parsed.value;
  } finally {
    dek.fill(0);
  }
}

async function rotateTenantKey({ tenantId, actorId = null, expiresAt = null }) {
  const current = await TenantEncryptionKey.findOne({ tenantId, status: 'active' });
  if (!current) return createTenantKey({ tenantId, actorId, expiresAt });
  // Retire first to satisfy the unique active-key index. Existing ciphertext remains decryptable.
  current.status = 'retired';
  current.retiredAt = new Date();
  await current.save();
  try {
    return await createTenantKey({ tenantId, actorId, expiresAt, rotatedFromKeyId: current.keyId });
  } catch (error) {
    current.status = 'active';
    current.retiredAt = null;
    await current.save().catch(() => {});
    throw error;
  }
}

async function revokeTenantKey({ tenantId, keyId, reason }) {
  const record = await TenantEncryptionKey.findOne({ tenantId, keyId });
  if (!record) return null;
  if (record.status === 'active') throw new Error('Rotate the active key before revoking it');
  record.status = 'revoked';
  record.revokedAt = new Date();
  record.revocationReason = String(reason || '').slice(0, 500);
  return record.save();
}

async function listTenantKeys(tenantId) {
  return TenantEncryptionKey.find({ tenantId })
    .select('-wrappedKey')
    .sort({ version: -1 })
    .lean();
}

async function tenantFingerprint({ tenantId, companyId = null, purpose, value }) {
  const keyRecord = await activeTenantKey(tenantId);
  const dek = await unwrapRecord(keyRecord);
  try {
    return hmacSha256(canonicalize({ companyId: companyId ? String(companyId) : '', purpose, value }), dek);
  } finally {
    dek.fill(0);
  }
}

async function rotateDueTenantKeys({ io = null, now = new Date() } = {}) {
  const rotateBefore = new Date(now.getTime() + AUTO_ROTATE_BEFORE_DAYS * 86400_000);
  const due = await TenantEncryptionKey.find({ status: 'active', expiresAt: { $lte: rotateBefore } })
    .select('tenantId keyId version expiresAt')
    .limit(500)
    .lean();
  const results = [];
  for (const current of due) {
    try {
      const next = await rotateTenantKey({ tenantId: current.tenantId });
      await require('./encryptionAudit.service').appendEncryptionAudit({
        tenantId: current.tenantId,
        actorRole: 'system',
        action: 'key_auto_rotated',
        outcome: 'success',
        targetType: 'tenant-key',
        targetId: next.keyId,
        keyId: next.keyId,
        keyVersion: next.version,
        reason: `Active key ${current.keyId} entered the automatic rotation window`,
      });
      io?.to('superadmin').emit('encryption:key-updated', {
        tenantId: String(current.tenantId), action: 'auto-rotated', keyId: next.keyId, version: next.version,
      });
      results.push({ tenantId: String(current.tenantId), status: 'rotated', keyId: next.keyId });
    } catch (error) {
      await require('./encryptionAudit.service').appendEncryptionAudit({
        tenantId: current.tenantId,
        actorRole: 'system',
        action: 'key_auto_rotated',
        outcome: 'failure',
        targetType: 'tenant-key',
        targetId: current.keyId,
        keyId: current.keyId,
        keyVersion: current.version,
        reason: String(error.message || error),
      }).catch(() => {});
      results.push({ tenantId: String(current.tenantId), status: 'failed', error: error.message });
    }
  }
  return results;
}

function startKeyRotationScheduler(io = null) {
  if (rotationTimer) return rotationTimer;
  const intervalMs = Math.max(60_000, Number(process.env.KMS_ROTATION_CHECK_INTERVAL_MS || 60 * 60_000));
  const run = () => rotateDueTenantKeys({ io }).then(results => {
    const failed = results.filter(item => item.status === 'failed');
    if (failed.length) console.error(`[KMS] ${failed.length} automatic key rotation(s) failed`);
  }).catch(error => console.error('[KMS] automatic rotation check failed:', error.message));
  run();
  rotationTimer = setInterval(run, intervalMs);
  rotationTimer.unref?.();
  return rotationTimer;
}

module.exports = {
  DEFAULT_ROTATION_DAYS,
  dataContext,
  createTenantKey,
  activeTenantKey,
  encryptValue,
  decryptValue,
  rotateTenantKey,
  revokeTenantKey,
  listTenantKeys,
  tenantFingerprint,
  rotateDueTenantKeys,
  startKeyRotationScheduler,
  _unwrapRecord: unwrapRecord,
};
