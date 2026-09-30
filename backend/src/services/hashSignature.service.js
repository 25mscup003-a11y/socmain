const crypto = require('crypto');
const HashSignaturePolicy = require('../models/HashSignaturePolicy.model');
const HashSignatureBaseline = require('../models/HashSignatureBaseline.model');

const policyCache = new Map();
const policyInFlight = new Map();
const POLICY_CACHE_MS = Math.max(1000, Number(process.env.HASH_POLICY_CACHE_MS || 30000));
const POLICY_CACHE_MAX = Math.max(100, Number(process.env.HASH_POLICY_CACHE_MAX || 5000));

const SIGNATURE_STATUSES = new Set([
  'VALID', 'INVALID', 'UNSIGNED', 'EXPIRED', 'REVOKED', 'UNKNOWN',
  'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE',
]);

const WEIGHTS = Object.freeze({
  knownMaliciousHash: 50, ransomwareHash: 50, aptHash: 45,
  invalidSignature: 25, unsignedExecutable: 20, revokedCertificate: 30,
  criticalSystemFile: 25, hashMismatch: 20, suspiciousLocation: 15,
  suspiciousParent: 20, suspiciousNetwork: 20,
  trustedValidSignature: -15, knownGoodHash: -20,
});

function first(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function hash(value, length) {
  const normalized = String(value || '').trim().toLowerCase();
  return new RegExp(`^[a-f0-9]{${length}}$`).test(normalized) ? normalized : undefined;
}

function normalizeSignatureStatus(value) {
  const candidate = String(value || 'UNKNOWN').trim().toUpperCase().replace(/[ -]+/g, '_');
  const aliases = { NOT_SIGNED: 'UNSIGNED', HASH_MISMATCH: 'INVALID', NOT_TRUSTED: 'UNTRUSTED_PUBLISHER' };
  const normalized = aliases[candidate] || candidate;
  return SIGNATURE_STATUSES.has(normalized) ? normalized : 'UNKNOWN';
}

function isExecutablePath(path = '') {
  return /\.(?:exe|dll|sys|com|scr|cpl|msi|ps1|bat|cmd|vbs|js|sh|py|rb|pl|elf|so)(?:$|\?)/i.test(path)
    || /^\/(?:bin|sbin|usr\/bin|usr\/sbin)\//i.test(path);
}

function isCriticalPath(path = '') {
  return /(?:^|[\\/])(?:windows[\\/](?:system32|syswow64)|etc[\\/](?:passwd|shadow|sudoers)|usr[\\/](?:bin|sbin)|bin|sbin)(?:[\\/]|$)/i.test(path);
}

function isSuspiciousPath(path = '') {
  return /(?:^|[\\/])(?:tmp|temp|appdata[\\/]local[\\/]temp|downloads|dev[\\/]shm|var[\\/]tmp)(?:[\\/]|$)/i.test(path);
}

function riskToSeverity(score) {
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

function scoreHashSignature(signals = {}, weights = WEIGHTS) {
  let score = 0;
  const reasons = [];
  const add = (enabled, key, reason) => {
    if (!enabled) return;
    score += Number(weights[key] ?? WEIGHTS[key] ?? 0);
    reasons.push(reason);
  };
  add(signals.knownMaliciousHash, 'knownMaliciousHash', 'Known malicious hash');
  add(signals.ransomwareHash, 'ransomwareHash', 'Ransomware hash intelligence match');
  add(signals.aptHash, 'aptHash', 'APT-associated hash intelligence match');
  add(signals.invalidSignature, 'invalidSignature', 'Invalid digital signature');
  add(signals.unsignedExecutable, 'unsignedExecutable', 'Unsigned executable');
  add(signals.revokedCertificate, 'revokedCertificate', 'Revoked signing certificate');
  add(signals.criticalSystemFile, 'criticalSystemFile', 'Critical system file');
  add(signals.hashMismatch, 'hashMismatch', 'Baseline hash mismatch');
  add(signals.suspiciousLocation, 'suspiciousLocation', 'Suspicious file location');
  add(signals.suspiciousParent, 'suspiciousParent', 'Suspicious parent process');
  add(signals.suspiciousNetwork, 'suspiciousNetwork', 'Correlated suspicious network activity');
  add(signals.trustedValidSignature, 'trustedValidSignature', 'Trusted valid signature');
  add(signals.knownGoodHash, 'knownGoodHash', 'Known-good hash');
  score = Math.max(0, Math.min(100, score));
  return { riskScore: score, severity: riskToSeverity(score), riskReasons: reasons };
}

function detectionRule(signals, signatureStatus, intelText) {
  if (signals.ransomwareHash) return 'RANSOMWARE_HASH_MATCH';
  if (signals.aptHash) return 'APT_HASH_MATCH';
  if (signals.knownMaliciousHash) return 'KNOWN_MALICIOUS_HASH';
  if (signals.hashMismatch && signals.trustedValidSignature) return 'SIGNED_FILE_HASH_CHANGED';
  if (signals.hashMismatch && signals.criticalSystemFile) return 'CRITICAL_FILE_HASH_CHANGED';
  if (signals.hashMismatch) return 'HASH_MISMATCH';
  if (signatureStatus === 'REVOKED') return 'REVOKED_CERTIFICATE';
  if (signatureStatus === 'INVALID') return 'INVALID_SIGNATURE';
  if (signatureStatus === 'EXPIRED') return 'EXPIRED_CERTIFICATE';
  if (signatureStatus === 'CERTIFICATE_CHAIN_FAILURE') return 'CERTIFICATE_CHAIN_FAILURE';
  if (signatureStatus === 'UNTRUSTED_PUBLISHER') return 'UNTRUSTED_PUBLISHER';
  if (signals.unsignedExecutable) return 'UNSIGNED_EXECUTABLE';
  if (/suspicious/i.test(intelText)) return 'SUSPICIOUS_HASH';
  return 'HASH_SIGNATURE_OBSERVED';
}

async function getHashSignaturePolicy(companyId) {
  const key = String(companyId || '');
  if (!key) return {};
  const cached = policyCache.get(key);
  if (cached && cached.expiresAt > Date.now()) return cached.value;
  if (policyInFlight.has(key)) return policyInFlight.get(key);
  const load = HashSignaturePolicy.findOne({ companyId }).lean().then(value => value || {});
  policyInFlight.set(key, load);
  try {
    const value = await load;
    policyCache.delete(key);
    policyCache.set(key, { value, expiresAt: Date.now() + POLICY_CACHE_MS });
    while (policyCache.size > POLICY_CACHE_MAX) policyCache.delete(policyCache.keys().next().value);
    return value;
  } finally {
    policyInFlight.delete(key);
  }
}

function invalidateHashSignaturePolicy(companyId) {
  policyCache.delete(String(companyId || ''));
}

function normalizeHashSignatureEvent(body = {}, policy = {}) {
  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const vt = body.virustotal && typeof body.virustotal === 'object'
    ? body.virustotal
    : raw.virustotal && typeof raw.virustotal === 'object' ? raw.virustotal : {};
  const sha256 = hash(first(
    body.sha256, body.file_hash, body.fileHash, body.new_hash, body.newHash, body.hash,
    body.executable_sha256, body.processExecutableSha256,
    raw.sha256, raw.file_hash, raw.new_hash, raw.executable_sha256, raw.processExecutableSha256,
  ), 64);
  const sha1 = hash(first(
    body.sha1, body.file_hash_sha1, body.fileHashSha1,
    body.executable_sha1, body.processExecutableSha1,
    raw.sha1, raw.file_hash_sha1, raw.executable_sha1, raw.processExecutableSha1,
  ), 40);
  const md5 = hash(first(
    body.md5, body.file_hash_md5, body.fileHashMd5,
    body.executable_md5, body.processExecutableMd5,
    raw.md5, raw.file_hash_md5, raw.executable_md5, raw.processExecutableMd5,
  ), 32);
  const filePath = String(first(body.filePath, body.file_path, body.processExe, body.process_exe, body.exe, raw.filePath, raw.file_path, raw.process_exe, '') || '');
  const oldHash = hash(first(body.baselineHash, body.baseline_hash, body.oldHash, body.old_hash, body.previousHash, raw.baseline_hash, raw.old_hash), 64);
  const currentHash = sha256 || hash(first(body.currentHash, body.current_hash, body.newHash, body.new_hash, raw.current_hash, raw.new_hash), 64);
  const signatureStatus = normalizeSignatureStatus(first(body.signatureStatus, body.signature_status, raw.signatureStatus, raw.signature_status));
  const publisher = String(first(body.publisher, body.signer, raw.publisher, raw.signer, '') || '').slice(0, 500);
  const vtVerdict = first(body.vtVerdict, body.vt_verdict, vt.verdict, raw.vtVerdict, raw.vt_verdict);
  const intelText = `${vtVerdict || ''} ${body.reputation || raw.reputation || ''} ${body.malwareType || body.malware_type || raw.malware_type || ''} ${body.threatCategory || raw.threat_category || ''}`;
  const executable = isExecutablePath(filePath) || Boolean(first(
    body.executable_sha256, body.processExecutableSha256,
    raw.executable_sha256, raw.processExecutableSha256,
  ));
  const approvedHashes = new Set((policy.approvedHashes || []).map(value => String(value).toLowerCase()));
  const approvedPublishers = (policy.approvedPublishers || []).map(value => String(value).toLowerCase());
  const explicitlyApproved = approvedHashes.has(sha256) || approvedPublishers.some(value => value && publisher.toLowerCase() === value);
  const signals = {
    knownMaliciousHash: policy.threatIntelEnabled !== false && (body.iocMatched === true || body.threatIntelMatch === true || Number(vt.malicious || 0) > 0 || /malicious|malware|trojan|backdoor|worm/i.test(intelText)),
    ransomwareHash: /ransomware/i.test(intelText),
    aptHash: /\bapt\b/i.test(intelText),
    invalidSignature: policy.signatureValidationEnabled !== false && (signatureStatus === 'INVALID' || signatureStatus === 'CERTIFICATE_CHAIN_FAILURE' || signatureStatus === 'UNTRUSTED_PUBLISHER'),
    unsignedExecutable: policy.unsignedFileAlertEnabled !== false && executable && signatureStatus === 'UNSIGNED',
    revokedCertificate: policy.signatureValidationEnabled !== false && signatureStatus === 'REVOKED',
    criticalSystemFile: policy.criticalFileMonitoringEnabled !== false && isCriticalPath(filePath),
    hashMismatch: policy.baselineMonitoringEnabled !== false && Boolean(oldHash && currentHash && oldHash !== currentHash),
    suspiciousLocation: isSuspiciousPath(filePath),
    suspiciousParent: /powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32/i.test(String(first(body.parentProcessName, body.parent_process_name, raw.parent_process_name, ''))),
    suspiciousNetwork: body.suspiciousNetwork === true || body.suspicious_network === true,
    trustedValidSignature: signatureStatus === 'VALID' && Boolean(publisher),
    knownGoodHash: explicitlyApproved || (/known.?good|clean|trusted/i.test(intelText) && !/malicious|suspicious/i.test(intelText)),
  };
  const policyWeights = policy.riskWeights instanceof Map ? Object.fromEntries(policy.riskWeights) : policy.riskWeights;
  const scored = scoreHashSignature(signals, policyWeights || body.riskWeights || undefined);
  const rule = detectionRule(signals, signatureStatus, intelText);
  const hasEvidence = Boolean(sha256 || sha1 || md5 || signatureStatus !== 'UNKNOWN' || publisher || oldHash);
  if (!hasEvidence) return {};
  return {
    sha256, sha1, md5,
    signatureStatus,
    publisher: publisher || undefined,
    certificateSubject: first(body.certificateSubject, body.certificate_subject, raw.certificateSubject, raw.certificate_subject),
    certificateIssuer: first(body.certificateIssuer, body.certificate_issuer, raw.certificateIssuer, raw.certificate_issuer),
    certificateSerial: first(body.certificateSerial, body.certificate_serial, raw.certificateSerial, raw.certificate_serial),
    certificateThumbprint: first(body.certificateThumbprint, body.certificate_thumbprint, raw.certificateThumbprint, raw.certificate_thumbprint),
    certificateValidFrom: first(body.certificateValidFrom, body.certificate_valid_from, raw.certificateValidFrom, raw.certificate_valid_from),
    certificateValidUntil: first(body.certificateValidUntil, body.certificate_valid_until, body.certificateExpiry, raw.certificateValidUntil, raw.certificate_valid_until),
    certificateRevocationStatus: first(body.certificateRevocationStatus, body.revocationStatus, raw.certificateRevocationStatus, raw.revocation_status),
    trustStatus: first(body.trustStatus, body.trust_status, raw.trustStatus, raw.trust_status),
    packageOwner: first(body.packageOwner, body.package_owner, raw.packageOwner, raw.package_owner),
    packageVerificationStatus: first(body.packageVerificationStatus, body.package_verification_status, raw.packageVerificationStatus, raw.package_verification_status),
    baselineHash: oldHash, currentHash, hashMismatch: signals.hashMismatch,
    hashSignatureRule: rule, riskReasons: scored.riskReasons,
    hashSignatureRiskScore: scored.riskScore, hashSignatureSeverity: scored.severity,
    threatIntelMatch: signals.knownMaliciousHash || body.threatIntelMatch === true,
    threatIntelSource: first(body.threatIntelSource, body.threat_intel_source, raw.threat_intel_source, vt.source, Object.keys(vt).length ? 'VirusTotal' : undefined),
    reputation: first(body.reputation, raw.reputation, vtVerdict),
    malwareFamily: first(body.malwareFamily, body.malware_family, body.malwareType, body.malware_type, raw.malware_family, raw.malware_type),
    confidenceScore: Number(first(body.confidenceScore, body.confidence_score, raw.confidence_score, vt.score)) || undefined,
    allowlisted: explicitlyApproved,
  };
}

/**
 * Apply the tenant policy and immutable first-seen baseline before an alert is
 * persisted. Baselines are never silently replaced when a file drifts.
 */
async function enrichHashSignatureEvent(body = {}, context = {}) {
  const companyId = context.companyId;
  if (!companyId) return {};

  const policy = await getHashSignaturePolicy(companyId);
  let normalized = normalizeHashSignatureEvent(body, policy);
  if (!Object.keys(normalized).length) return {};

  const raw = body.raw && typeof body.raw === 'object' ? body.raw : {};
  const endpointId = String(first(
    context.endpointId, body.endpointId, body.endpoint_id, body.system_id,
    raw.endpointId, raw.endpoint_id, raw.system_id,
  ) || '').slice(0, 256);
  const filePath = String(first(
    context.filePath, body.filePath, body.file_path, body.processExe,
    body.process_exe, body.exe, raw.filePath, raw.file_path, raw.process_exe,
  ) || '').slice(0, 4096);

  if (policy.baselineMonitoringEnabled !== false && context.tenantId && normalized.sha256 && endpointId && filePath) {
    let baseline = await HashSignatureBaseline.findOne({ companyId, endpointId, filePath }).lean();
    if (!baseline) {
      try {
        baseline = await HashSignatureBaseline.create({
          tenantId: context.tenantId,
          companyId,
          departmentId: context.departmentId || null,
          endpointId,
          filePath,
          fileName: context.fileName || filePath.split(/[\\/]/).pop(),
          // If the endpoint supplied a trusted previous hash for this change,
          // preserve that as the initial baseline instead of blessing the
          // already-modified file.
          sha256: normalized.baselineHash || normalized.sha256,
          sha1: normalized.sha1,
          md5: normalized.md5,
          fileSize: Number(first(body.fileSize, body.file_size, raw.fileSize, raw.file_size)) || undefined,
          signatureStatus: normalized.signatureStatus,
          publisher: normalized.publisher,
          firstSeen: context.observedAt || new Date(),
          lastSeen: context.observedAt || new Date(),
        });
        baseline = baseline.toObject();
      } catch (error) {
        if (error?.code !== 11000) throw error;
        baseline = await HashSignatureBaseline.findOne({ companyId, endpointId, filePath }).lean();
      }
    } else {
      const observedAt = context.observedAt || new Date();
      if (!baseline.lastSeen || observedAt.getTime() - new Date(baseline.lastSeen).getTime() >= 300000) {
        HashSignatureBaseline.updateOne(
          { _id: baseline._id },
          { $set: { lastSeen: observedAt } },
        ).catch(() => {});
      }
    }

    if (baseline?.sha256) {
      normalized = normalizeHashSignatureEvent({
        ...body,
        baselineHash: baseline.sha256,
        currentHash: normalized.sha256,
      }, policy);
    }
  }

  const threshold = Math.min(100, Math.max(0, Number(policy.riskThreshold ?? 30)));
  return {
    ...normalized,
    hashSignatureMonitoringEnabled: policy.enabled !== false,
    hashSignatureThreatIntelEnabled: policy.threatIntelEnabled !== false,
    hashSignaturePolicyThreshold: threshold,
    hashSignatureAlertEligible: policy.enabled !== false
      && normalized.allowlisted !== true
      && Number(normalized.hashSignatureRiskScore || 0) >= threshold,
  };
}

function reportFingerprint(companyId, from, to) {
  return crypto.createHash('sha256').update(`${companyId}:${from}:${to}`).digest('hex').slice(0, 16);
}

module.exports = {
  SIGNATURE_STATUSES, WEIGHTS, getHashSignaturePolicy, invalidateHashSignaturePolicy,
  normalizeHashSignatureEvent, enrichHashSignatureEvent, normalizeSignatureStatus,
  riskToSeverity, scoreHashSignature, reportFingerprint,
};
