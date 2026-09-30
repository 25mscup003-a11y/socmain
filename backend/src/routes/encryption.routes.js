const crypto = require('crypto');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const mongoose = require('mongoose');
const multer = require('multer');
const router = require('express').Router();

const { authenticate } = require('../middleware/auth.middleware');
const { requireEncryptionPermission, requireFreshMfa, cryptoRateLimit } = require('../middleware/encryptionAccess');
const { resolveEncryptionScope } = require('../services/encryptionScope.service');
const { getKeyProvider } = require('../services/keyProvider.service');
const {
  createTenantKey, rotateTenantKey, revokeTenantKey, listTenantKeys,
  encryptValue, decryptValue,
} = require('../services/tenantKms.service');
const { appendEncryptionAudit, verifyAuditChain } = require('../services/encryptionAudit.service');
const { sha256, sha512, timingSafeHexEqual, verifyPublicKeySignature } = require('../security/cryptoPrimitives');
const { encryptFile, decryptFileToWritable, hashFile } = require('../services/evidenceLocker.service');
const TenantEncryptionKey = require('../models/TenantEncryptionKey.model');
const EncryptionAudit = require('../models/EncryptionAudit.model');
const EncryptionJob = require('../models/EncryptionJob.model');
const DecryptionRequest = require('../models/DecryptionRequest.model');
const SecureRecord = require('../models/SecureRecord.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');

const uploadRoot = path.resolve(process.env.ENCRYPTION_UPLOAD_TMP_DIR || path.join(__dirname, '../../secure-data/upload-staging'));
const evidenceRoot = path.resolve(process.env.EVIDENCE_LOCKER_PATH || path.join(__dirname, '../../secure-data/evidence'));
fs.mkdirSync(uploadRoot, { recursive: true, mode: 0o700 });
fs.mkdirSync(evidenceRoot, { recursive: true, mode: 0o700 });

const upload = multer({
  dest: uploadRoot,
  limits: { fileSize: Math.max(1, Number(process.env.EVIDENCE_MAX_BYTES || 20 * 1024 * 1024 * 1024)), files: 1 },
});

router.use(authenticate, cryptoRateLimit);

function actor(req) {
  return { actorId: req.user.id, actorRole: req.user.role };
}

function emit(req, scope, event, payload) {
  const io = req.app.get('io');
  if (scope.companyId) io?.to(`company:${scope.companyId}`).emit(event, payload);
  io?.to('superadmin').emit(event, { tenantId: scope.tenantId, companyId: scope.companyId, ...payload });
}

async function audit(req, scope, values) {
  return appendEncryptionAudit({ ...scope, ...actor(req), ...values }, req);
}

function publicKeyRecord(record) {
  return {
    _id: record._id,
    tenantId: record.tenantId,
    keyId: record.keyId,
    version: record.version,
    algorithm: record.algorithm,
    status: record.status,
    activatedAt: record.activatedAt,
    expiresAt: record.expiresAt,
    retiredAt: record.retiredAt,
    revokedAt: record.revokedAt,
    createdAt: record.createdAt,
  };
}

async function consumeApproval({ requestId, scope, targetType, targetId, userId }) {
  const request = await DecryptionRequest.findOneAndUpdate({
    requestId,
    tenantId: scope.tenantId,
    companyId: scope.companyId,
    targetType,
    targetId: String(targetId),
    requestedBy: userId,
    status: 'approved',
    expiresAt: { $gt: new Date() },
  }, { $set: { status: 'consumed', consumedAt: new Date() } }, { new: true });
  if (!request) {
    const error = new Error('A valid approved, unexpired, single-use decryption request is required');
    error.statusCode = 403;
    throw error;
  }
  return request;
}

router.get('/overview', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    const providerHealth = await getKeyProvider().health();
    const match = { tenantId: new mongoose.Types.ObjectId(scope.tenantId) };
    if (scope.companyId) match.companyId = new mongoose.Types.ObjectId(scope.companyId);
    const [keys, evidence, requests, jobs, audits, encryptedRecords, trends] = await Promise.all([
      TenantEncryptionKey.aggregate([{ $match: { tenantId: match.tenantId } }, { $group: { _id: '$status', count: { $sum: 1 }, nextExpiry: { $min: '$expiresAt' } } }]),
      ForensicEvidence.aggregate([{ $match: { ...match, storageState: 'secured' } }, { $group: { _id: null, count: { $sum: 1 }, bytes: { $sum: '$sizeBytes' } } }]),
      DecryptionRequest.aggregate([{ $match: match }, { $group: { _id: '$status', count: { $sum: 1 } } }]),
      EncryptionJob.aggregate([{ $match: match }, { $group: { _id: '$status', count: { $sum: 1 } } }]),
      EncryptionAudit.aggregate([{ $match: match }, { $group: { _id: '$outcome', count: { $sum: 1 } } }]),
      SecureRecord.countDocuments(match),
      EncryptionAudit.aggregate([
        { $match: { ...match, createdAt: { $gte: new Date(Date.now() - 30 * 86400_000) } } },
        { $group: { _id: { day: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, action: '$action' }, count: { $sum: 1 } } },
        { $sort: { '_id.day': 1 } },
      ]),
    ]);
    const keyCounts = Object.fromEntries(keys.map(item => [item._id, item.count]));
    const requestCounts = Object.fromEntries(requests.map(item => [item._id, item.count]));
    const jobCounts = Object.fromEntries(jobs.map(item => [item._id, item.count]));
    const auditCounts = Object.fromEntries(audits.map(item => [item._id, item.count]));
    const transportEncrypted = req.secure || req.socket?.encrypted || String(req.headers['x-forwarded-proto'] || '').toLowerCase() === 'https';
    res.json({
      scope: { tenantId: scope.tenantId, companyId: scope.companyId },
      cards: {
        encryptionStatus: providerHealth.healthy && (keyCounts.active || 0) > 0 ? 'healthy' : 'attention',
        totalEncryptedEvidence: evidence[0]?.count || 0,
        encryptedEvidenceBytes: evidence[0]?.bytes || 0,
        totalDecryptionRequests: Object.values(requestCounts).reduce((sum, value) => sum + value, 0),
        failedDecryptionAttempts: auditCounts.failure || 0,
        activeEncryptionJobs: (jobCounts.queued || 0) + (jobCounts.processing || 0),
        activeKeys: keyCounts.active || 0,
        expiringKeys: keys.filter(item => item.nextExpiry && item.nextExpiry < new Date(Date.now() + 30 * 86400_000)).length,
        encryptedDatabaseRecords: encryptedRecords,
        databaseEncryption: encryptedRecords > 0 ? 'field-encryption-active' : 'ready',
        backupEncryption: process.env.ENCRYPTED_BACKUP_ENABLED === 'true' ? 'enabled' : 'not-configured',
        communicationEncryption: transportEncrypted ? 'tls-active' : 'tls-not-observed',
        configurationEncryption: 'aes-256-gcm',
      },
      requestStatus: requestCounts,
      jobStatus: jobCounts,
      trends: trends.map(item => ({ day: item._id.day, action: item._id.action, count: item.count })),
      provider: providerHealth,
    });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/keys', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    res.json({ keys: (await listTenantKeys(scope.tenantId)).map(publicKeyRecord) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/keys', requireEncryptionPermission('key_manage'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req);
    if (await TenantEncryptionKey.exists({ tenantId: scope.tenantId, status: 'active' })) {
      return res.status(409).json({ message: 'Tenant already has an active key; use rotation' });
    }
    const key = await createTenantKey({ tenantId: scope.tenantId, actorId: req.user.id });
    await audit(req, scope, { action: 'key_created', outcome: 'success', targetType: 'tenant-key', targetId: key.keyId, keyId: key.keyId, keyVersion: key.version, reason: req.body.reason });
    emit(req, scope, 'encryption:key-updated', { action: 'created', key: publicKeyRecord(key) });
    res.status(201).json({ key: publicKeyRecord(key) });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'key_created', outcome: 'failure', targetType: 'tenant-key', reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/keys/rotate', requireEncryptionPermission('key_manage'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req);
    const key = await rotateTenantKey({ tenantId: scope.tenantId, actorId: req.user.id });
    await audit(req, scope, { action: 'key_rotated', outcome: 'success', targetType: 'tenant-key', targetId: key.keyId, keyId: key.keyId, keyVersion: key.version, reason: req.body.reason });
    emit(req, scope, 'encryption:key-updated', { action: 'rotated', key: publicKeyRecord(key) });
    res.status(201).json({ key: publicKeyRecord(key), message: 'New writes use the rotated key; existing ciphertext remains readable by version' });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'key_rotated', outcome: 'failure', targetType: 'tenant-key', reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/keys/:keyId/revoke', requireEncryptionPermission('key_manage'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req);
    if (!String(req.body.reason || '').trim()) return res.status(400).json({ message: 'Revocation reason is required' });
    const key = await revokeTenantKey({ tenantId: scope.tenantId, keyId: req.params.keyId, reason: req.body.reason });
    if (!key) return res.status(404).json({ message: 'Key not found' });
    await audit(req, scope, { action: 'key_revoked', outcome: 'success', targetType: 'tenant-key', targetId: key.keyId, keyId: key.keyId, keyVersion: key.version, reason: req.body.reason });
    emit(req, scope, 'encryption:key-updated', { action: 'revoked', key: publicKeyRecord(key) });
    res.json({ key: publicKeyRecord(key) });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'key_revoked', outcome: 'failure', targetType: 'tenant-key', targetId: req.params.keyId, reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/records/encrypt', requireEncryptionPermission('encrypt'), async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    const name = String(req.body.name || '').trim();
    const category = String(req.body.category || 'other');
    if (!name || req.body.value === undefined) return res.status(400).json({ message: 'name and value are required' });
    const recordObjectId = new mongoose.Types.ObjectId();
    const envelope = await encryptValue({ ...scope, purpose: `secure-record:${category}`, recordId: String(recordObjectId), value: req.body.value, actorId: req.user.id });
    const record = await SecureRecord.create({
      _id: recordObjectId, tenantId: scope.tenantId, companyId: scope.companyId,
      category, name, encrypted: envelope, fingerprint: envelope.fingerprint, createdBy: req.user.id,
    });
    await audit(req, scope, { action: 'data_encrypted', outcome: 'success', targetType: 'secure-record', targetId: record._id, keyId: envelope.keyId, keyVersion: envelope.keyVersion, reason: req.body.reason });
    emit(req, scope, 'encryption:job-updated', { operation: 'encrypt', status: 'completed', targetId: record._id });
    res.status(201).json({ record });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'data_encrypted', outcome: 'failure', targetType: 'secure-record', reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/records', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req, { requireCompany: true });
    const records = await SecureRecord.find(scope).sort({ updatedAt: -1 }).limit(250);
    res.json({ records });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/decrypt/requests', requireEncryptionPermission('decrypt_request'), async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    const targetType = String(req.body.targetType || 'secure-record');
    const targetId = String(req.body.targetId || '');
    const reason = String(req.body.reason || '').trim();
    if (!targetId || reason.length < 8) return res.status(400).json({ message: 'targetId and a meaningful reason are required' });
    const request = await DecryptionRequest.create({
      ...scope, requestId: `DCR-${crypto.randomUUID()}`, requestedBy: req.user.id,
      requestedByRole: req.user.role, targetType, targetId, reason,
      expiresAt: new Date(Date.now() + Math.max(5, Number(process.env.DECRYPT_REQUEST_TTL_MINUTES || 30)) * 60_000),
      sourceIp: String(req.ip || ''), device: String(req.get('user-agent') || ''),
    });
    await audit(req, scope, { action: 'decryption_requested', outcome: 'success', targetType, targetId, requestId: request.requestId, reason });
    emit(req, scope, 'encryption:decryption-request', { requestId: request.requestId, status: request.status, targetType, targetId });
    res.status(201).json({ request });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'decryption_requested', outcome: 'failure', targetType: req.body.targetType || 'unknown', targetId: req.body.targetId, reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/decrypt/requests/:requestId/decision', requireEncryptionPermission('approve'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    const decision = String(req.body.decision || '').toLowerCase();
    if (!['approved', 'denied'].includes(decision)) return res.status(400).json({ message: 'decision must be approved or denied' });
    const request = await DecryptionRequest.findOne({ requestId: req.params.requestId, ...scope, status: 'pending', expiresAt: { $gt: new Date() } });
    if (!request) return res.status(404).json({ message: 'Pending decryption request not found' });
    if (String(request.requestedBy) === String(req.user.id) && process.env.ALLOW_SELF_DECRYPT_APPROVAL !== 'true') {
      await audit(req, scope, { action: 'decryption_approval', outcome: 'denied', targetType: request.targetType, targetId: request.targetId, requestId: request.requestId, reason: 'Separation of duties violation' });
      return res.status(403).json({ message: 'Requester cannot approve their own decryption request' });
    }
    request.status = decision;
    if (decision === 'approved') { request.approvedBy = req.user.id; request.approvedAt = new Date(); }
    else { request.deniedBy = req.user.id; request.deniedAt = new Date(); }
    await request.save();
    await audit(req, scope, { action: 'decryption_approval', outcome: decision === 'approved' ? 'success' : 'denied', targetType: request.targetType, targetId: request.targetId, requestId: request.requestId, reason: req.body.reason || decision });
    emit(req, scope, 'encryption:decryption-request', { requestId: request.requestId, status: request.status });
    res.json({ request });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'decryption_approval', outcome: 'failure', targetType: 'decryption-request', targetId: req.params.requestId, reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/records/:id/decrypt', requireEncryptionPermission('decrypt'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    const record = await SecureRecord.findOne({ _id: req.params.id, ...scope }).select('+encrypted');
    if (!record) return res.status(404).json({ message: 'Encrypted record not found' });
    const approval = await consumeApproval({ requestId: req.body.requestId, scope, targetType: 'secure-record', targetId: record._id, userId: req.user.id });
    const value = await decryptValue({ ...scope, purpose: `secure-record:${record.category}`, recordId: String(record._id), envelope: record.encrypted });
    record.lastDecryptedAt = new Date();
    await record.save();
    await audit(req, scope, { action: 'data_decrypted', outcome: 'success', targetType: 'secure-record', targetId: record._id, requestId: approval.requestId, keyId: record.encrypted.keyId, keyVersion: record.encrypted.keyVersion, reason: approval.reason });
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    res.json({ value });
  } catch (error) {
    if (scope) await audit(req, scope, { action: 'data_decrypted', outcome: error.statusCode === 403 ? 'denied' : 'failure', targetType: 'secure-record', targetId: req.params.id, requestId: req.body.requestId, reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

async function processEvidenceJob(jobId, io = null) {
  const job = await EncryptionJob.findById(jobId).select('+sourcePath +destinationPath');
  if (!job || ['completed', 'cancelled'].includes(job.status)) return;
  job.status = 'processing';
  job.startedAt ||= new Date();
  await job.save();
  try {
    const result = await encryptFile({
      sourcePath: job.sourcePath, destinationPath: job.destinationPath,
      tenantId: job.tenantId, companyId: job.companyId, evidenceId: job.targetId,
      actorId: job.requestedBy,
      resume: { bytesProcessed: job.bytesProcessed, outputBytes: job.outputBytes, chunksCompleted: job.chunksCompleted },
      onProgress: async progress => {
        Object.assign(job, progress);
        await job.save();
        io?.to(`company:${job.companyId}`).emit('encryption:job-updated', { jobId: job._id, ...progress, status: job.status });
      },
    });
    const evidence = await ForensicEvidence.create({
      tenantId: job.tenantId, companyId: job.companyId,
      evidenceId: job.targetId, name: job.originalName || job.targetId,
      type: job.evidenceType || 'Uploaded Evidence', artifactName: job.originalName || '',
      sizeBytes: result.sizeBytes, sha256: result.sha256, integrityStatus: 'verified', storageState: 'secured',
      storageLocator: job.destinationPath, originalMimeType: job.mimeType || 'application/octet-stream',
      encryption: { ...result, encryptedAt: new Date() }, collectedBy: job.requestedBy,
      custody: [{ action: 'encrypted_and_stored', actorId: job.requestedBy, actorRole: 'authorized-uploader', note: `Encryption job ${job._id}` }],
    });
    job.status = 'completed'; job.progress = 100; job.completedAt = new Date();
    job.keyId = result.keyId; job.keyVersion = result.keyVersion; job.targetId = String(evidence._id);
    await job.save();
    await appendEncryptionAudit({ tenantId: job.tenantId, companyId: job.companyId, actorId: job.requestedBy, actorRole: 'authorized-uploader', action: 'evidence_encrypted', outcome: 'success', targetType: 'forensic-evidence', targetId: evidence._id, keyId: result.keyId, keyVersion: result.keyVersion, metadata: { sizeBytes: result.sizeBytes, sha256: result.sha256, jobId: job._id } });
    io?.to(`company:${job.companyId}`).emit('encryption:job-updated', { jobId: job._id, evidenceId: evidence._id, progress: 100, status: 'completed' });
  } catch (error) {
    job.status = 'failed'; job.error = String(error.message || error).slice(0, 2000); job.completedAt = new Date();
    await job.save().catch(() => {});
    await appendEncryptionAudit({ tenantId: job.tenantId, companyId: job.companyId, actorId: job.requestedBy, actorRole: 'authorized-uploader', action: 'evidence_encrypted', outcome: 'failure', targetType: 'forensic-evidence', targetId: job.targetId, reason: job.error }).catch(() => {});
    io?.to(`company:${job.companyId}`).emit('encryption:job-updated', { jobId: job._id, status: 'failed', error: job.error });
  } finally {
    if (job.sourcePath) await fsp.unlink(job.sourcePath).catch(() => {});
  }
}

router.post('/evidence', requireEncryptionPermission('encrypt'), upload.single('file'), async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    if (!req.file) return res.status(400).json({ message: 'Evidence file is required' });
    const evidenceId = `EVD-${crypto.randomUUID()}`;
    const destinationPath = path.join(evidenceRoot, String(scope.tenantId), String(scope.companyId), `${evidenceId}.ajev`);
    const job = await EncryptionJob.create({
      ...scope, requestedBy: req.user.id, operation: 'encrypt', targetType: 'forensic-evidence', targetId: evidenceId,
      totalBytes: req.file.size, sourcePath: req.file.path, destinationPath,
      originalName: String(req.body.name || req.file.originalname || evidenceId).slice(0, 300),
      evidenceType: String(req.body.type || 'Uploaded Evidence').slice(0, 80),
      mimeType: String(req.file.mimetype || 'application/octet-stream').slice(0, 160),
    });
    const io = req.app.get('io');
    setImmediate(() => processEvidenceJob(job._id, io).catch(error => console.error('[evidence-encryption-job]', error.message)));
    await audit(req, scope, { action: 'evidence_encryption_queued', outcome: 'success', targetType: 'encryption-job', targetId: job._id, reason: req.body.reason, metadata: { sizeBytes: req.file.size } });
    res.status(202).json({ job });
  } catch (error) {
    if (req.file?.path) await fsp.unlink(req.file.path).catch(() => {});
    if (scope) await audit(req, scope, { action: 'evidence_encryption_queued', outcome: 'failure', targetType: 'forensic-evidence', reason: error.message }).catch(() => {});
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/evidence/:id/decrypt', requireEncryptionPermission('decrypt'), requireFreshMfa, async (req, res) => {
  let scope;
  try {
    scope = await resolveEncryptionScope(req, { requireCompany: true });
    const evidence = await ForensicEvidence.findOne({ _id: req.params.id, ...scope }).select('+storageLocator');
    if (!evidence?.storageLocator || evidence.storageState !== 'secured') return res.status(404).json({ message: 'Encrypted evidence not found' });
    const expectedCiphertextHash = String(evidence.encryption?.ciphertextSha256 || '');
    const actualCiphertextHash = await hashFile(evidence.storageLocator, 'sha256');
    if (!expectedCiphertextHash || !timingSafeHexEqual(expectedCiphertextHash, actualCiphertextHash)) {
      const integrityError = new Error('Encrypted evidence integrity verification failed');
      integrityError.statusCode = 409;
      throw integrityError;
    }
    const approval = await consumeApproval({ requestId: req.query.requestId, scope, targetType: 'forensic-evidence', targetId: evidence._id, userId: req.user.id });
    res.setHeader('Content-Type', evidence.originalMimeType || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${String(evidence.name || evidence.evidenceId).replace(/[^A-Za-z0-9_.-]/g, '_')}"`);
    res.setHeader('Cache-Control', 'no-store, max-age=0');
    await decryptFileToWritable({ sourcePath: evidence.storageLocator, writable: res, ...scope, evidenceId: evidence.evidenceId, keyId: evidence.encryption.keyId, expectedSha256: evidence.sha256 });
    res.end();
    evidence.custody.push({ action: 'authorized_decryption', actorId: req.user.id, actorRole: req.user.role, sourceIp: String(req.ip || ''), note: approval.reason });
    await evidence.save();
    await audit(req, scope, { action: 'evidence_decrypted', outcome: 'success', targetType: 'forensic-evidence', targetId: evidence._id, requestId: approval.requestId, keyId: evidence.encryption.keyId, keyVersion: evidence.encryption.keyVersion, reason: approval.reason });
  } catch (error) {
    if (!res.headersSent) res.status(error.statusCode || 500).json({ message: error.message });
    else res.destroy(error);
    if (scope) await audit(req, scope, { action: 'evidence_decrypted', outcome: error.statusCode === 403 ? 'denied' : 'failure', targetType: 'forensic-evidence', targetId: req.params.id, requestId: req.query.requestId, reason: error.message }).catch(() => {});
  }
});

router.get('/jobs', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    res.json({ jobs: await EncryptionJob.find(scope).sort({ createdAt: -1 }).limit(100).lean() });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/decrypt/requests', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    res.json({ requests: await DecryptionRequest.find(scope).populate('requestedBy approvedBy deniedBy', 'name email role').sort({ createdAt: -1 }).limit(100).lean() });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/audit', requireEncryptionPermission('view'), async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    const limit = Math.min(1000, Math.max(1, Number(req.query.limit || 200)));
    const records = await EncryptionAudit.find(scope).sort({ sequence: -1 }).limit(limit).lean();
    if (req.query.format === 'csv') {
      if (!(require('../middleware/encryptionAccess').ROLE_PERMISSIONS[req.user.role] || []).includes('audit_export')) return res.status(403).json({ message: 'Audit export permission required' });
      const quote = value => `"${String(value ?? '').replace(/"/g, '""')}"`;
      const header = ['sequence','createdAt','actorId','actorRole','action','outcome','targetType','targetId','keyId','requestId','riskScore','ipAddress'];
      const csv = [header.join(','), ...records.map(row => header.map(key => quote(row[key])).join(','))].join('\n');
      res.setHeader('Content-Type', 'text/csv; charset=utf-8');
      res.setHeader('Content-Disposition', 'attachment; filename="encryption-audit.csv"');
      return res.send(csv);
    }
    res.json({ audit: records });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/audit/verify', requireEncryptionPermission('key_manage'), requireFreshMfa, async (req, res) => {
  try {
    const scope = await resolveEncryptionScope(req);
    const result = await verifyAuditChain(scope.tenantId);
    res.status(result.valid ? 200 : 409).json(result);
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/hash', requireEncryptionPermission('encrypt'), (req, res) => {
  if (req.body.data === undefined) return res.status(400).json({ message: 'data is required' });
  const data = Buffer.from(typeof req.body.data === 'string' ? req.body.data : JSON.stringify(req.body.data), 'utf8');
  res.json({ sha256: sha256(data), sha512: sha512(data) });
});

router.post('/integrity/verify', requireEncryptionPermission('view'), (req, res) => {
  if (req.body.data === undefined || !req.body.sha256) return res.status(400).json({ message: 'data and sha256 are required' });
  const data = Buffer.from(typeof req.body.data === 'string' ? req.body.data : JSON.stringify(req.body.data), 'utf8');
  const actual = sha256(data);
  res.status(actual === String(req.body.sha256).toLowerCase() ? 200 : 409).json({ valid: actual === String(req.body.sha256).toLowerCase(), actual });
});

router.post('/signatures/validate', requireEncryptionPermission('view'), (req, res) => {
  try {
    const valid = verifyPublicKeySignature(req.body);
    res.status(valid ? 200 : 409).json({ valid, algorithm: req.body.algorithm || 'RSA-PSS-SHA512' });
  } catch (error) { res.status(400).json({ message: error.message }); }
});

async function resumePendingEvidenceJobs(io) {
  const jobs = await EncryptionJob.find({ operation: 'encrypt', targetType: 'forensic-evidence', status: { $in: ['queued', 'processing'] } }).select('+sourcePath +destinationPath');
  for (const job of jobs) setImmediate(() => processEvidenceJob(job._id, io).catch(error => console.error('[evidence-resume]', error.message)));
}

module.exports = router;
module.exports.resumePendingEvidenceJobs = resumePendingEvidenceJobs;
