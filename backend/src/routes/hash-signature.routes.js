const router = require('express').Router();
const mongoose = require('mongoose');
const path = require('path');
const { once } = require('events');
const Alert = require('../models/Alert.model');
const Baseline = require('../models/HashSignatureBaseline.model');
const Policy = require('../models/HashSignaturePolicy.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');
const { reportFingerprint, invalidateHashSignaturePolicy } = require('../services/hashSignature.service');

router.use(authenticate, requireAnalyst);

const HASH_VALUE_EVIDENCE = {
  $or: [
    { sha256: { $exists: true, $ne: '' } }, { fileHash: { $exists: true, $ne: '' } },
    { processExecutableSha256: { $exists: true, $ne: '' } },
    { hash: { $exists: true, $ne: '' } }, { currentHash: { $exists: true, $ne: '' } },
    { newHash: { $exists: true, $ne: '' } }, { oldHash: { $exists: true, $ne: '' } },
    { signatureStatus: { $exists: true, $nin: ['', null] } },
    { 'rawEvent.sha256': { $exists: true, $ne: '' } },
    { 'rawEvent.file_hash': { $exists: true, $ne: '' } },
    { 'rawEvent.executable_sha256': { $exists: true, $ne: '' } },
    { 'rawEvent.current_hash': { $exists: true, $ne: '' } },
    { 'rawEvent.new_hash': { $exists: true, $ne: '' } },
    { 'rawEvent.old_hash': { $exists: true, $ne: '' } },
    { 'rawEvent.signatureStatus': { $exists: true, $nin: ['', null] } },
    { 'rawEvent.signature_status': { $exists: true, $nin: ['', null] } },
    { 'rawEvent.packageVerificationStatus': { $exists: true, $nin: ['', null] } },
    { 'rawEvent.package_verification_status': { $exists: true, $nin: ['', null] } },
    { 'rawEvent.raw.sha256': { $exists: true, $ne: '' } },
    { 'rawEvent.raw.file_hash': { $exists: true, $ne: '' } },
    { 'rawEvent.raw.signature_status': { $exists: true, $nin: ['', null] } },
  ],
};

const HASH_EVIDENCE = HASH_VALUE_EVIDENCE;

// Card 25 is populated by the canonical capability tag added during alert
// ingestion. This predicate uses the compound capability indexes and keeps the
// dashboard/report queries bounded; HASH_EVIDENCE remains available for direct
// lookup of older individual records.
const HASH_INDEXED_EVIDENCE = {
  $and: [
    { capabilityIds: 25 },
    HASH_VALUE_EVIDENCE,
  ],
};

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function userScope(req) {
  if (req.user.role === 'superadmin') {
    if (!mongoose.Types.ObjectId.isValid(req.query.companyId || req.body?.companyId)) {
      const error = new Error('companyId is required');
      error.statusCode = 400;
      throw error;
    }
    return { companyId: new mongoose.Types.ObjectId(req.query.companyId || req.body.companyId) };
  }
  const scope = scopeForUser(req.user, { departmentScoped: true });
  if (!scope.companyId) {
    const error = new Error('Company scope required');
    error.statusCode = 403;
    throw error;
  }
  return Object.fromEntries(Object.entries(scope).map(([key, value]) => {
    if (['tenantId', 'companyId', 'departmentId', 'partnerId'].includes(key)
      && mongoose.Types.ObjectId.isValid(value)) {
      return [key, new mongoose.Types.ObjectId(String(value))];
    }
    return [key, value];
  }));
}

function policyScope(req) {
  const scope = userScope(req);
  return Object.fromEntries(['tenantId', 'companyId'].filter(key => scope[key]).map(key => [key, scope[key]]));
}

function baselineScope(req) {
  const scope = userScope(req);
  return Object.fromEntries(['tenantId', 'companyId', 'departmentId'].filter(key => scope[key]).map(key => [key, scope[key]]));
}

function parseWindow(query = {}, fallbackDays = 30) {
  const to = query.to ? new Date(query.to) : new Date();
  const from = query.from ? new Date(query.from) : new Date(to.getTime() - fallbackDays * 86400000);
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from > to) {
    const error = new Error('Invalid time window');
    error.statusCode = 400;
    throw error;
  }
  if (to.getTime() - from.getTime() > 366 * 86400000) {
    const error = new Error('Time window cannot exceed 366 days');
    error.statusCode = 400;
    throw error;
  }
  return { from, to };
}

function eventQuery(req, extra = {}) {
  const scope = userScope(req);
  const { from, to } = parseWindow(req.query);
  const evidence = req.query.includeLegacy === 'true' ? HASH_EVIDENCE : HASH_INDEXED_EVIDENCE;
  const guards = [scope, evidence, { createdAt: { $gte: from, $lte: to } }, { isSynthetic: { $ne: true } }, extra];
  if (req.query.departmentId && req.user.role !== 'department_admin') {
    if (!mongoose.Types.ObjectId.isValid(req.query.departmentId)) {
      const error = new Error('Invalid departmentId');
      error.statusCode = 400;
      throw error;
    }
    guards.push({ departmentId: new mongoose.Types.ObjectId(req.query.departmentId) });
  }
  if (req.query.severity) guards.push({ severity: String(req.query.severity).toLowerCase() });
  if (req.query.eventType) guards.push({ hashSignatureRule: String(req.query.eventType).slice(0, 128) });
  if (req.query.endpointId) guards.push({ endpointId: String(req.query.endpointId).slice(0, 256) });
  if (req.query.signatureStatus) guards.push({ signatureStatus: String(req.query.signatureStatus).toUpperCase() });
  if (req.query.search) {
    const regex = new RegExp(escapeRegex(String(req.query.search).slice(0, 200)), 'i');
    guards.push({ $or: [{ fileName: regex }, { filePath: regex }, { sha256: regex }, { publisher: regex }, { hostname: regex }] });
  }
  return { query: { $and: guards.filter(value => Object.keys(value).length) }, scope, from, to };
}

function csvCell(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

const EVENT_CSV_HEADER = ['Timestamp', 'Tenant', 'Endpoint', 'File', 'Path', 'SHA256', 'SHA1', 'MD5', 'Signature', 'Publisher', 'Threat Intel', 'Risk', 'Severity', 'Event Type'];

function eventCsvValues(row) {
  return [
    row.createdAt?.toISOString?.() || row.createdAt, row.tenantId, row.endpointId || row.hostname || row.agentName,
    row.fileName, row.filePath, row.sha256 || row.fileHash, row.sha1, row.md5 || row.fileHashMd5,
    row.signatureStatus, row.publisher, row.reputation || row.vtVerdict || (row.threatIntelMatch ? 'MATCH' : 'NO_MATCH'),
    row.hashSignatureRiskScore ?? row.riskScore, row.hashSignatureSeverity || row.severity,
    row.hashSignatureRule || row.ruleId,
  ];
}

function eventCsv(rows) {
  return [EVENT_CSV_HEADER, ...rows.map(eventCsvValues)].map(values => values.map(csvCell).join(',')).join('\n');
}

async function writeWithBackpressure(res, chunk) {
  if (!res.write(chunk)) await once(res, 'drain');
}

function htmlEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
}

function firstValue(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function rawTelemetry(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function canonicalHashEvent(row = {}) {
  const raw = rawTelemetry(row);
  const vt = raw.virustotal && typeof raw.virustotal === 'object' ? raw.virustotal : {};
  const filePath = firstValue(row.filePath, row.sourcePath, row.processExe, raw.filePath, raw.file_path, raw.source_path, raw.process_exe, '');
  const sha256 = firstValue(row.sha256, row.fileHash, row.processExecutableSha256, row.hash, row.currentHash, row.newHash, raw.sha256, raw.file_hash, raw.executable_sha256, raw.processExecutableSha256, raw.hash, raw.current_hash, raw.new_hash, '');
  const baselineHash = firstValue(row.baselineHash, row.oldHash, raw.baseline_hash, raw.old_hash, '');
  const currentHash = firstValue(row.currentHash, row.newHash, sha256, raw.current_hash, raw.new_hash, '');
  const vtVerdict = firstValue(row.vtVerdict, raw.vtVerdict, raw.vt_verdict, vt.verdict, row.reputation, 'UNKNOWN');
  const signatureStatus = String(firstValue(row.signatureStatus, raw.signatureStatus, raw.signature_status, 'UNKNOWN')).toUpperCase();
  const threatIntelMatch = row.threatIntelMatch === true || row.iocMatched === true || raw.iocMatched === true
    || Number(vt.malicious || 0) > 0 || /^malicious$/i.test(String(vtVerdict));
  const normalized = {
    ...row,
    timestamp: firstValue(row.timestamp, raw.timestamp, row.createdAt),
    endpointId: firstValue(row.endpointId, raw.endpointId, raw.endpoint_id, raw.system_id),
    hostname: firstValue(row.hostname, raw.hostname, raw.system_name, row.agentName),
    username: firstValue(row.username, raw.username, raw.user, raw.file_user),
    filePath,
    fileName: firstValue(row.fileName, raw.fileName, raw.file_name, filePath ? path.basename(String(filePath)) : undefined),
    fileSize: firstValue(row.fileSize, raw.fileSize, raw.file_size),
    fileAction: firstValue(row.fileAction, raw.fileAction, raw.file_action, raw.change_type),
    fileCreatedAt: firstValue(row.fileCreatedAt, raw.fileCreatedAt, raw.file_created_at, raw.created_time, raw.ctime),
    fileModifiedAt: firstValue(row.fileModifiedAt, raw.fileModifiedAt, raw.file_modified_at, raw.modified_time, raw.mtime),
    fileAccessedAt: firstValue(row.fileAccessedAt, raw.fileAccessedAt, raw.file_accessed_at, raw.accessed_time, raw.atime),
    fileOwner: firstValue(row.fileOwner, raw.fileOwner, raw.file_owner, raw.owner),
    fileGroup: firstValue(row.fileGroup, raw.fileGroup, raw.file_group, raw.group),
    filePermissions: firstValue(row.filePermissions, raw.filePermissions, raw.file_permissions, raw.permissions, raw.mode),
    sha256,
    sha1: firstValue(row.sha1, raw.sha1, raw.file_hash_sha1, raw.executable_sha1),
    md5: firstValue(row.md5, row.fileHashMd5, row.processExecutableMd5, raw.md5, raw.file_hash_md5, raw.executable_md5),
    baselineHash,
    currentHash,
    hashMismatch: Boolean(row.hashMismatch || (baselineHash && currentHash && baselineHash !== currentHash)),
    signatureStatus,
    publisher: firstValue(row.publisher, raw.publisher, raw.signer),
    certificateSubject: firstValue(row.certificateSubject, raw.certificateSubject, raw.certificate_subject),
    certificateIssuer: firstValue(row.certificateIssuer, raw.certificateIssuer, raw.certificate_issuer),
    certificateSerial: firstValue(row.certificateSerial, raw.certificateSerial, raw.certificate_serial),
    certificateThumbprint: firstValue(row.certificateThumbprint, raw.certificateThumbprint, raw.certificate_thumbprint),
    certificateValidFrom: firstValue(row.certificateValidFrom, raw.certificateValidFrom, raw.certificate_valid_from),
    certificateValidUntil: firstValue(row.certificateValidUntil, raw.certificateValidUntil, raw.certificate_valid_until),
    certificateRevocationStatus: firstValue(row.certificateRevocationStatus, raw.certificateRevocationStatus, raw.revocation_status),
    trustStatus: firstValue(row.trustStatus, raw.trustStatus, raw.trust_status),
    packageOwner: firstValue(row.packageOwner, raw.packageOwner, raw.package_owner),
    packageVerificationStatus: firstValue(row.packageVerificationStatus, raw.packageVerificationStatus, raw.package_verification_status),
    processName: firstValue(row.processName, raw.processName, raw.process_name, raw.process),
    processExe: firstValue(row.processExe, raw.processExe, raw.process_exe, raw.exe, filePath),
    processCmdline: firstValue(row.processCmdline, raw.processCmdline, raw.process_cmdline, raw.cmdline, raw.command_line),
    pid: firstValue(row.pid, raw.pid),
    parentPid: firstValue(row.parentPid, raw.parentPid, raw.parent_pid),
    parentProcessName: firstValue(row.parentProcessName, raw.parentProcessName, raw.parent_process_name),
    processCreateTime: firstValue(row.processCreateTime, raw.processCreateTime, raw.process_create_time),
    threatIntelMatch,
    threatIntelSource: firstValue(row.threatIntelSource, raw.threatIntelSource, raw.threat_intel_source, Object.keys(vt).length ? 'VirusTotal' : undefined),
    reputation: firstValue(row.reputation, vtVerdict),
    malwareFamily: firstValue(row.malwareFamily, row.malwareType, raw.malware_family, raw.malware_type),
    confidenceScore: firstValue(row.confidenceScore, raw.confidenceScore, raw.confidence_score, vt.score),
    vtVerdict,
    vtScore: firstValue(row.vtScore, vt.score),
    vtDetections: firstValue(row.vtDetections, vt.malicious, vt.detections),
    vtTotal: firstValue(row.vtTotal, vt.total_engines, vt.total),
    vtDetectionRatio: firstValue(row.vtDetectionRatio, vt.detection_ratio, vt.ratio),
    yaraRules: row.yaraRules?.length ? row.yaraRules : raw.yara_rules,
  };
  normalized.evidenceAvailability = {
    hashes: Boolean(normalized.sha256 || normalized.sha1 || normalized.md5),
    signature: signatureStatus !== 'UNKNOWN' || Boolean(normalized.packageVerificationStatus),
    certificate: Boolean(normalized.publisher || normalized.certificateSubject || normalized.certificateThumbprint),
    process: Boolean(normalized.processName || normalized.pid || normalized.processCmdline),
    baseline: Boolean(normalized.baselineHash),
    threatIntel: Boolean(normalized.threatIntelSource || normalized.vtVerdict !== 'UNKNOWN'),
  };
  return normalized;
}

function coalesceAggregation(...fields) {
  return fields.reduceRight((fallback, field) => ({ $ifNull: [field, fallback] }), '');
}

function hashAggregationNormalization() {
  return {
    $set: {
      _hsSignatureStatus: {
        $toUpper: coalesceAggregation('$signatureStatus', '$rawEvent.signatureStatus', '$rawEvent.signature_status', '$rawEvent.raw.signatureStatus', '$rawEvent.raw.signature_status'),
      },
      _hsPackageVerification: {
        $toUpper: coalesceAggregation('$packageVerificationStatus', '$rawEvent.packageVerificationStatus', '$rawEvent.package_verification_status', '$rawEvent.raw.packageVerificationStatus', '$rawEvent.raw.package_verification_status'),
      },
      _hsVtVerdict: {
        $toLower: coalesceAggregation('$vtVerdict', '$rawEvent.vtVerdict', '$rawEvent.vt_verdict', '$rawEvent.virustotal.verdict', '$reputation'),
      },
      _hsReputation: {
        $toLower: coalesceAggregation('$reputation', '$rawEvent.reputation', '$rawEvent.virustotal.verdict'),
      },
      _hsThreatMatch: {
        $or: [
          { $eq: ['$threatIntelMatch', true] },
          { $eq: ['$iocMatched', true] },
          { $eq: ['$rawEvent.iocMatched', true] },
          { $gt: [{ $convert: { input: '$rawEvent.virustotal.malicious', to: 'double', onError: 0, onNull: 0 } }, 0] },
        ],
      },
      _hsRule: coalesceAggregation('$hashSignatureRule', '$ruleId', '$rawEvent.rule_id', '$rawEvent.event_type', 'HASH_SIGNATURE_OBSERVED'),
      _hsFileName: coalesceAggregation('$fileName', '$rawEvent.fileName', '$rawEvent.file_name'),
      _hsFilePath: coalesceAggregation('$filePath', '$sourcePath', '$processExe', '$rawEvent.filePath', '$rawEvent.file_path', '$rawEvent.process_exe'),
      _hsSha256: coalesceAggregation('$sha256', '$fileHash', '$processExecutableSha256', '$hash', '$currentHash', '$newHash', '$rawEvent.sha256', '$rawEvent.file_hash', '$rawEvent.executable_sha256', '$rawEvent.processExecutableSha256', '$rawEvent.hash', '$rawEvent.current_hash', '$rawEvent.new_hash', '$rawEvent.raw.sha256', '$rawEvent.raw.file_hash', '$rawEvent.raw.executable_sha256', '$rawEvent.raw.hash', '$rawEvent.raw.current_hash', '$rawEvent.raw.new_hash'),
      _hsPublisher: coalesceAggregation('$publisher', '$rawEvent.publisher', '$rawEvent.signer'),
      _hsThreatSource: coalesceAggregation('$threatIntelSource', '$rawEvent.threatIntelSource', '$rawEvent.threat_intel_source'),
      _hsProcessName: coalesceAggregation('$processName', '$rawEvent.processName', '$rawEvent.process_name', '$rawEvent.process'),
      _hsPid: coalesceAggregation('$pid', '$rawEvent.pid'),
      _hsBaselineHash: coalesceAggregation('$baselineHash', '$oldHash', '$rawEvent.baseline_hash', '$rawEvent.old_hash'),
      _hsMalwareFamily: coalesceAggregation('$malwareFamily', '$malwareType', '$rawEvent.malware_family', '$rawEvent.malware_type'),
      _hsOs: coalesceAggregation('$osType', '$rawEvent.osType', '$rawEvent.os_type', '$rawEvent.platform'),
    },
  };
}

async function generateHashReport(req, rowLimit = 500) {
  const { query, from, to, scope } = eventQuery(req);
  const rowQuery = rowLimit > 0
    ? Alert.find(query).sort({ createdAt: -1 }).limit(rowLimit).lean()
    : Promise.resolve([]);
  const [summaryRows, byDay, byRule, rows] = await Promise.all([
    Alert.aggregate([
      { $match: query },
      hashAggregationNormalization(),
      { $group: {
        _id: null, total: { $sum: 1 },
        critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
        high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
        medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
        low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
        mismatches: { $sum: { $cond: [{ $or: [{ $eq: ['$hashMismatch', true] }, { $eq: ['$rawEvent.hash_mismatch', true] }] }, 1, 0] } },
        malicious: { $sum: { $cond: [{ $or: ['$_hsThreatMatch', { $eq: ['$_hsVtVerdict', 'malicious'] }, { $eq: ['$_hsReputation', 'malicious'] }] }, 1, 0] } },
        unsigned: { $sum: { $cond: [{ $eq: ['$_hsSignatureStatus', 'UNSIGNED'] }, 1, 0] } },
        valid: { $sum: { $cond: [{ $or: [{ $eq: ['$_hsSignatureStatus', 'VALID'] }, { $eq: ['$_hsPackageVerification', 'VERIFIED'] }] }, 1, 0] } },
        signedEvaluated: { $sum: { $cond: [{ $or: [
          { $in: ['$_hsSignatureStatus', ['VALID', 'INVALID', 'EXPIRED', 'REVOKED', 'UNSIGNED', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE']] },
          { $gt: [{ $strLenCP: { $convert: { input: '$_hsPackageVerification', to: 'string', onError: '', onNull: '' } } }, 0] },
        ] }, 1, 0] } },
        signatureFailures: { $sum: { $cond: [{ $or: [{ $in: ['$_hsSignatureStatus', ['INVALID', 'EXPIRED', 'REVOKED', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE']] }, { $eq: ['$_hsPackageVerification', 'MODIFIED'] }] }, 1, 0] } },
      } },
    ]),
    Alert.aggregate([{ $match: query }, { $group: { _id: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }]),
    Alert.aggregate([{ $match: query }, hashAggregationNormalization(), { $group: { _id: '$_hsRule', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 12 }]),
    rowQuery,
  ]);
  const summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, mismatches: 0, malicious: 0, unsigned: 0, valid: 0, signedEvaluated: 0, signatureFailures: 0, ...(summaryRows[0] || {}) };
  delete summary._id;
  summary.signatureValidationPercent = summary.signedEvaluated
    ? Math.round((summary.valid / summary.signedEvaluated) * 1000) / 10
    : 0;
  return {
    meta: { from: from.toISOString(), to: to.toISOString(), generatedAt: new Date().toISOString(), reportId: reportFingerprint(scope.companyId, from.toISOString(), to.toISOString()), sampleLimited: summary.total > rows.length },
    summary, byDay: byDay.map(row => ({ date: row._id, count: row.count })),
    byRule: byRule.map(row => ({ rule: row._id || 'HASH_SIGNATURE_OBSERVED', count: row.count })), rows: rows.map(canonicalHashEvent),
  };
}

router.get('/events', async (req, res) => {
  try {
    const { query } = eventQuery(req);
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(250, Math.max(1, Number(req.query.limit) || 50));
    const sortField = ['createdAt', 'riskScore', 'hashSignatureRiskScore', 'severity', 'fileName'].includes(req.query.sort) ? req.query.sort : 'createdAt';
    const direction = String(req.query.order).toLowerCase() === 'asc' ? 1 : -1;
    const [events, total] = await Promise.all([
      Alert.find(query).sort({ [sortField]: direction, _id: -1 }).skip((page - 1) * limit).limit(limit).populate('systemId', 'name hostname os osType').lean(),
      Alert.countDocuments(query),
    ]);
    res.json({
      events: events.map(canonicalHashEvent), total, page, limit, pages: Math.ceil(total / limit),
      windowHours: 24, countMode: 'exact', countLimited: false, rowsPaginated: true,
    });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/statistics', async (req, res) => {
  try {
    const { query, from, to } = eventQuery(req);
    const malicious = { $or: ['$_hsThreatMatch', { $eq: ['$_hsVtVerdict', 'malicious'] }, { $eq: ['$_hsReputation', 'malicious'] }] };
    const signatureFailure = { $or: [
      { $in: ['$_hsSignatureStatus', ['INVALID', 'EXPIRED', 'REVOKED', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE']] },
      { $eq: ['$_hsPackageVerification', 'MODIFIED'] },
    ] };
    const hasText = field => ({ $gt: [{ $strLenCP: { $convert: { input: field, to: 'string', onError: '', onNull: '' } } }, 0] });
    const textMatch = (fields, regex) => ({ $regexMatch: { input: { $concat: fields.flatMap(field => [{ $convert: { input: field, to: 'string', onError: '', onNull: '' } }, ' ']) }, regex, options: 'i' } });
    const [facets = {}] = await Alert.aggregate([{ $match: query }, hashAggregationNormalization(), { $facet: {
      totals: [{ $group: {
        _id: null,
        total: { $sum: 1 },
        mismatches: { $sum: { $cond: [{ $or: [{ $eq: ['$hashMismatch', true] }, { $eq: ['$rawEvent.hash_mismatch', true] }] }, 1, 0] } },
        malicious: { $sum: { $cond: [malicious, 1, 0] } },
        unsigned: { $sum: { $cond: [{ $eq: ['$_hsSignatureStatus', 'UNSIGNED'] }, 1, 0] } },
        valid: { $sum: { $cond: [{ $or: [{ $eq: ['$_hsSignatureStatus', 'VALID'] }, { $eq: ['$_hsPackageVerification', 'VERIFIED'] }] }, 1, 0] } },
        signedEvaluated: { $sum: { $cond: [{ $or: [{ $in: ['$_hsSignatureStatus', ['VALID', 'INVALID', 'EXPIRED', 'REVOKED', 'UNSIGNED', 'UNTRUSTED_PUBLISHER', 'CERTIFICATE_CHAIN_FAILURE']] }, hasText('$_hsPackageVerification')] }, 1, 0] } },
        critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
        high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
        medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
        low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
        signatureFailures: { $sum: { $cond: [signatureFailure, 1, 0] } },
        invalidCertificates: { $sum: { $cond: [{ $in: ['$_hsSignatureStatus', ['INVALID', 'EXPIRED', 'REVOKED', 'CERTIFICATE_CHAIN_FAILURE']] }, 1, 0] } },
        untrustedPublishers: { $sum: { $cond: [{ $eq: ['$_hsSignatureStatus', 'UNTRUSTED_PUBLISHER'] }, 1, 0] } },
        moduleMemory: { $sum: { $cond: [textMatch(['$_hsRule', '$_hsFileName'], 'module|memory|dll'), 1, 0] } },
        scripts: { $sum: { $cond: [textMatch(['$_hsFileName', '$_hsFilePath'], '\\.(ps1|bat|cmd|vbs|js|sh|py)( |$)'), 1, 0] } },
        threatFeedMatches: { $sum: { $cond: [{ $or: [malicious, { $eq: ['$_hsVtVerdict', 'suspicious'] }, { $eq: ['$_hsReputation', 'suspicious'] }] }, 1, 0] } },
        quarantined: { $sum: { $cond: [{ $or: [{ $eq: ['$quarantined', true] }, { $eq: [{ $toLower: { $ifNull: ['$containmentStatus', ''] } }, 'quarantined'] }] }, 1, 0] } },
        windowsVerified: { $sum: { $cond: [{ $and: [{ $eq: ['$_hsSignatureStatus', 'VALID'] }, textMatch(['$_hsOs', '$_hsFilePath'], 'windows|\\.exe|\\.dll|\\.sys')] }, 1, 0] } },
        linuxVerified: { $sum: { $cond: [{ $eq: ['$_hsPackageVerification', 'VERIFIED'] }, 1, 0] } },
        unsignedDlls: { $sum: { $cond: [{ $and: [{ $eq: ['$_hsSignatureStatus', 'UNSIGNED'] }, textMatch(['$_hsFileName', '$_hsFilePath'], '\\.dll( |$)')] }, 1, 0] } },
        webIntegrity: { $sum: { $cond: [textMatch(['$_hsFilePath'], 'var[\\\\/]www|wwwroot|htdocs'), 1, 0] } },
        trustedCertificates: { $sum: { $cond: [{ $and: [{ $eq: ['$_hsSignatureStatus', 'VALID'] }, hasText('$_hsPublisher')] }, 1, 0] } },
        sha256Collected: { $sum: { $cond: [hasText('$_hsSha256'), 1, 0] } },
        sha1Collected: { $sum: { $cond: [hasText('$sha1'), 1, 0] } },
        md5Collected: { $sum: { $cond: [{ $or: [hasText('$md5'), hasText('$fileHashMd5')] }, 1, 0] } },
        processLinked: { $sum: { $cond: [{ $or: [hasText('$_hsProcessName'), hasText('$_hsPid')] }, 1, 0] } },
        baselined: { $sum: { $cond: [hasText('$_hsBaselineHash'), 1, 0] } },
        publisherCollected: { $sum: { $cond: [hasText('$_hsPublisher'), 1, 0] } },
      } }],
      signature: [{ $group: { _id: { $cond: [{ $not: [{ $in: ['$_hsSignatureStatus', ['', 'UNKNOWN']] }] }, '$_hsSignatureStatus', { $cond: [hasText('$_hsPackageVerification'), '$_hsPackageVerification', 'UNKNOWN'] }] }, count: { $sum: 1 } } }],
      reputation: [{ $group: { _id: { $cond: [malicious, 'Malicious', { $cond: [{ $eq: ['$_hsVtVerdict', 'suspicious'] }, 'Suspicious', { $cond: [{ $or: [{ $eq: ['$_hsSignatureStatus', 'VALID'] }, { $eq: ['$_hsPackageVerification', 'VERIFIED'] }] }, 'Verified / Trusted', 'Unknown'] }] }] }, count: { $sum: 1 } } }],
      categories: [{ $group: { _id: { $cond: [hasText('$_hsMalwareFamily'), '$_hsMalwareFamily', '$_hsRule'] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 12 }],
      changed: [{ $match: { hashMismatch: true } }, { $sort: { createdAt: -1 } }, { $limit: 10 }, { $project: { filePath: 1, fileName: 1, baselineHash: 1, currentHash: 1, createdAt: 1, riskScore: 1, hashSignatureRiskScore: 1, severity: 1 } }],
      recent: [{ $sort: { createdAt: -1 } }, { $limit: 20 }],
      endpointCount: [{ $project: { endpoint: { $ifNull: ['$endpointId', { $ifNull: ['$hostname', '$agentName'] }] } } }, { $match: { endpoint: { $nin: [null, ''] } } }, { $group: { _id: '$endpoint' } }, { $count: 'count' }],
      duplicateMalicious: [{ $match: { $expr: malicious } }, { $project: { hash: '$_hsSha256' } }, { $match: { hash: { $nin: [null, ''] } } }, { $group: { _id: '$hash', count: { $sum: 1 } } }, { $match: { count: { $gt: 1 } } }, { $count: 'count' }],
      timeline: [{ $group: { _id: { $dateToString: { format: '%Y-%m-%dT%H:00:00.000Z', date: '$createdAt', timezone: 'UTC' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }],
    } }]);
    const totals = facets.totals?.[0] || { total: 0, mismatches: 0, malicious: 0, unsigned: 0, valid: 0, signedEvaluated: 0, critical: 0, high: 0, medium: 0, low: 0 };
    totals.signatureValidationPercent = totals.signedEvaluated ? Math.round((totals.valid / totals.signedEvaluated) * 1000) / 10 : 0;
    totals.endpoints = Number(facets.endpointCount?.[0]?.count || 0);
    totals.duplicateMalicious = Number(facets.duplicateMalicious?.[0]?.count || 0);
    res.json({
      window: { from, to }, totals,
      windowHours: 24, countMode: 'exact', countLimited: false,
      signature: facets.signature || [], reputation: facets.reputation || [], categories: facets.categories || [],
      changed: (facets.changed || []).map(canonicalHashEvent), recent: (facets.recent || []).map(canonicalHashEvent),
      timeline: (facets.timeline || []).map(row => ({ hour: row._id, count: row.count })),
      fieldCoverage: {
        sha256: totals.sha256Collected || 0, sha1: totals.sha1Collected || 0, md5: totals.md5Collected || 0,
        signature: totals.signedEvaluated || 0, publisher: totals.publisherCollected || 0,
        process: totals.processLinked || 0, baseline: totals.baselined || 0,
      },
    });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/files/:sha256', async (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/i.test(req.params.sha256)) return res.status(400).json({ message: 'Invalid SHA-256' });
    const { query } = eventQuery(req, { $or: [{ sha256: req.params.sha256.toLowerCase() }, { fileHash: req.params.sha256.toLowerCase() }] });
    const [observations, total, endpoints] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).limit(250).lean(), Alert.countDocuments(query),
      Alert.distinct('endpointId', query),
    ]);
    res.json({ sha256: req.params.sha256.toLowerCase(), total, endpoints: endpoints.filter(Boolean), observations: observations.map(canonicalHashEvent) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/endpoints/:endpointId', async (req, res) => {
  try {
    const { query } = eventQuery(req, { endpointId: String(req.params.endpointId).slice(0, 256) });
    const events = await Alert.find(query).sort({ createdAt: -1 }).limit(250).lean();
    res.json({ endpointId: req.params.endpointId, events: events.map(canonicalHashEvent) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/threat-intel/:sha256', async (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/i.test(req.params.sha256)) return res.status(400).json({ message: 'Invalid SHA-256' });
    const { query } = eventQuery(req, { $or: [{ sha256: req.params.sha256.toLowerCase() }, { fileHash: req.params.sha256.toLowerCase() }] });
    const event = await Alert.findOne(query).sort({ createdAt: -1 }).select('sha256 fileHash threatIntelMatch threatIntelSource reputation malwareFamily confidenceScore vtVerdict vtScore vtDetections vtTotal vtScannedAt iocMatches').lean();
    res.json(event || { sha256: req.params.sha256.toLowerCase(), threatIntelMatch: false, reputation: 'UNKNOWN' });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/baseline', async (req, res) => {
  try {
    const scope = baselineScope(req);
    const query = { ...scope };
    if (req.query.endpointId) query.endpointId = String(req.query.endpointId).slice(0, 256);
    const rows = await Baseline.find(query).sort({ updatedAt: -1 }).limit(1000).lean();
    res.json({ baselines: rows });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/baseline', requireManager, async (req, res) => {
  try {
    const scope = baselineScope(req);
    if (!scope.tenantId) return res.status(400).json({ message: 'Tenant scope required for baseline changes' });
    const { endpointId, filePath, sha256 } = req.body || {};
    if (!endpointId || !filePath || !/^[a-f0-9]{64}$/i.test(String(sha256 || ''))) return res.status(400).json({ message: 'endpointId, filePath and valid SHA-256 are required' });
    const baseline = await Baseline.findOneAndUpdate(
      { ...scope, endpointId: String(endpointId).slice(0, 256), filePath: String(filePath).slice(0, 4096) },
      { $set: { ...scope, fileName: req.body.fileName, sha256: String(sha256).toLowerCase(), sha1: req.body.sha1, md5: req.body.md5, fileSize: req.body.fileSize, signatureStatus: req.body.signatureStatus, publisher: req.body.publisher, lastSeen: new Date(), changedBy: req.user.id, reason: req.body.reason }, $setOnInsert: { firstSeen: new Date() }, $inc: { baselineVersion: 1 } },
      { upsert: true, new: true, runValidators: true },
    );
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('hash:baseline-updated', { id: baseline._id, endpointId });
    res.status(201).json({ baseline });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/policy', async (req, res) => {
  try {
    const scope = policyScope(req);
    const policy = await Policy.findOne(scope).lean();
    res.json({ policy: policy || { ...scope, enabled: true, sha256Enabled: true, sha1Enabled: true, md5Enabled: false, signatureValidationEnabled: true, threatIntelEnabled: true, baselineMonitoringEnabled: true, riskThreshold: 30 } });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.patch('/policy', requireManager, async (req, res) => {
  try {
    const scope = policyScope(req);
    if (!scope.tenantId) return res.status(400).json({ message: 'Tenant scope required for policy changes' });
    const allowed = ['enabled', 'sha256Enabled', 'sha1Enabled', 'md5Enabled', 'signatureValidationEnabled', 'threatIntelEnabled', 'baselineMonitoringEnabled', 'unsignedFileAlertEnabled', 'criticalFileMonitoringEnabled', 'riskThreshold', 'riskWeights', 'approvedHashes', 'approvedPublishers'];
    const update = { updatedBy: req.user.id };
    allowed.forEach(key => { if (req.body[key] !== undefined) update[key] = req.body[key]; });
    const policy = await Policy.findOneAndUpdate(scope, { $set: { ...scope, ...update } }, { upsert: true, new: true, runValidators: true });
    invalidateHashSignaturePolicy(scope.companyId);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('hash:policy-updated', { policy });
    res.json({ policy });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/report', async (req, res) => {
  try { res.json(await generateHashReport(req, 500)); }
  catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/report/csv', async (req, res) => {
  try {
    const { query, from, to } = eventQuery(req);
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="hash-signature-${from.toISOString().slice(0, 10)}-${to.toISOString().slice(0, 10)}.csv"`);
    await writeWithBackpressure(res, `\uFEFF${EVENT_CSV_HEADER.map(csvCell).join(',')}\n`);
    const cursor = Alert.find(query).sort({ createdAt: -1 }).lean().cursor();
    for await (const rawRow of cursor) {
      if (res.destroyed) break;
      const row = canonicalHashEvent(rawRow);
      await writeWithBackpressure(res, `${eventCsvValues(row).map(csvCell).join(',')}\n`);
    }
    res.end();
  } catch (error) {
    if (res.headersSent) return res.end();
    return res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/report/pdf', async (req, res) => {
  try {
    const report = await generateHashReport(req, 0);
    const { query } = eventQuery(req);
    const s = report.summary;
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.setHeader('Content-Disposition', `inline; filename="hash-signature-${report.meta.from.slice(0, 10)}.html"`);
    await writeWithBackpressure(res, `<!doctype html><html><head><meta charset="utf-8"><title>AJNAT Hash & Signature Report</title><style>body{font:12px Arial;color:#172033;padding:28px}h1{color:#0f4c81}.meta{color:#667085}.cards{display:flex;gap:10px;flex-wrap:wrap;margin:20px 0}.card{border:1px solid #d7e0ea;border-radius:8px;padding:12px;min-width:120px}.n{font-size:24px;font-weight:800}table{width:100%;border-collapse:collapse}th,td{padding:7px;border-bottom:1px solid #e5e7eb;text-align:left}.hash{font:9px monospace;word-break:break-all}@media print{body{padding:10px}}</style></head><body><h1>AJNAT EDR — Hash & Signature Analysis</h1><div class="meta">Report ${htmlEscape(report.meta.reportId)} · ${htmlEscape(report.meta.from)} to ${htmlEscape(report.meta.to)} · Generated ${htmlEscape(report.meta.generatedAt)}</div><div class="cards"><div class="card"><div class="n">${s.total}</div>Total Events</div><div class="card"><div class="n">${s.malicious}</div>Malicious Matches</div><div class="card"><div class="n">${s.mismatches}</div>Hash Mismatches</div><div class="card"><div class="n">${s.signatureFailures}</div>Signature Failures</div><div class="card"><div class="n">${s.signatureValidationPercent}%</div>Signature Validation</div><div class="card"><div class="n">${s.critical}</div>Critical</div></div><h2>Detection Timeline</h2><p>${report.byDay.map(day => `${htmlEscape(day.date)}: <b>${day.count}</b>`).join(' · ') || 'No events'}</p><h2>Complete Evidence (${s.total} rows)</h2><table><thead><tr><th>Time</th><th>Endpoint</th><th>File</th><th>SHA-256</th><th>Signature</th><th>Risk</th><th>Severity</th></tr></thead><tbody>`);
    let exportedRows = 0;
    const cursor = Alert.find(query).sort({ createdAt: -1 }).lean().cursor();
    for await (const rawRow of cursor) {
      if (res.destroyed) break;
      const row = canonicalHashEvent(rawRow);
      exportedRows += 1;
      await writeWithBackpressure(res, `<tr><td>${htmlEscape(row.createdAt)}</td><td>${htmlEscape(row.endpointId || row.hostname)}</td><td>${htmlEscape(row.fileName)}</td><td class="hash">${htmlEscape(row.sha256 || row.fileHash)}</td><td>${htmlEscape(row.signatureStatus)}</td><td>${htmlEscape(row.hashSignatureRiskScore ?? row.riskScore)}</td><td>${htmlEscape(row.severity)}</td></tr>`);
    }
    if (!exportedRows) await writeWithBackpressure(res, '<tr><td colspan="7">No events in selected window</td></tr>');
    await writeWithBackpressure(res, '</tbody></table></body></html>');
    res.end();
  } catch (error) {
    if (res.headersSent) return res.end();
    return res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/events/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const scope = userScope(req);
    const event = await Alert.findOne({ ...scope, _id: req.params.id, ...HASH_EVIDENCE }).populate('systemId', 'name hostname os osType ip').lean();
    if (!event) return res.status(404).json({ message: 'Event not found' });
    res.json({ event: canonicalHashEvent(event) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

module.exports = router;
