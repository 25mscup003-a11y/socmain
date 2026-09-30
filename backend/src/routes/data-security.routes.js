const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { createResponse } = require('../services/automatedResponse.service');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');

const DATA_CAPABILITY_FILTER = { $or: [{ capabilityId: 12 }, { capabilityIds: 12 }] };
// Capability 12 used to be inferred from the schema default `Unknown`, which
// polluted this dashboard with generic IDS traffic. Require real data-security
// evidence as well as the canonical capability tag.
const DATA_EVIDENCE_FILTER = { $or: [
  { source: 'data_security' },
  { subCategory: /data[-_ ]security|\bdlp\b/i },
  { dataEventType: { $exists: true, $nin: ['', null] } },
  { dataClassification: { $in: ['Public', 'Internal', 'Confidential', 'Restricted', 'Secret'] } },
  { dlpPattern: { $exists: true, $nin: ['', null] } },
  { dlpMatchCount: { $gt: 0 } },
  { transferChannel: { $exists: true, $nin: ['', null] } },
  { filePath: { $exists: true, $nin: ['', null] } },
  { ruleId: /^(?:DLP_|FILE_SENSITIVE|NET_EXFIL|USB_(?:SENSITIVE_FILE_COPIED|FILE_TRANSFER)|DATA_)/i },
] };
const LEGACY_DATA_SECURITY_FILTER = { $and: [
  { $or: [{ capabilityId: { $in: [2, 10, 27] } }, { capabilityIds: { $in: [2, 10, 27] } }] },
  { $or: [
    { source: 'file_watch' },
    { fimModule: { $exists: true, $nin: ['', null] } },
    { eventCategory: 'file', filePath: { $exists: true, $nin: ['', null] } },
    { eventCategory: 'usb' },
    { ruleId: /^(?:FILE_(?:CREATED|MODIFIED|DELETED|RENAMED|MOVED|HASH_CHANGED|PERMISSION|OWNERSHIP|HIDDEN|SENSITIVE)|USB_|NET_EXFIL|DLP_|DATA_|RANSOMWARE_)/i },
  ] },
] };
const DATA_FILTER = {
  isSynthetic: { $ne: true },
  $and: [{ $or: [{ $and: [DATA_CAPABILITY_FILTER, DATA_EVIDENCE_FILTER] }, LEGACY_DATA_SECURITY_FILTER] }],
};
const ACTIONS = new Set(['isolate', 'kill_process', 'block_ip', 'block_domain', 'block_hash', 'quarantine_file']);
const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const numberExpr = field => ({ $convert: { input: field, to: 'double', onError: 0, onNull: 0 } });
const sumWhen = condition => ({ $sum: { $cond: [condition, 1, 0] } });

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(req.user.companyId?._id || req.user.companyId)),
    ...(departmentId ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) } : {}),
  };
}

function dataQuery(req, source = req.query) {
  const query = { ...companyScope(req, source.departmentId), ...DATA_FILTER };
  const hours = PERIOD_HOURS[String(source.period || '')] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const to = source.to ? new Date(source.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.classification) query.dataClassification = new RegExp(`^${escapeRegex(source.classification)}$`, 'i');
  if (source.eventType) query.dataEventType = new RegExp(escapeRegex(source.eventType).slice(0, 100), 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.status) query.status = source.status;
  if (source.search) {
    const search = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and.push({ $or: [
      { description: search }, { ruleId: search }, { hostname: search }, { username: search },
      { filePath: search }, { fileName: search }, { fileHash: search }, { transferChannel: search },
      { destinationDomain: search }, { destip: search }, { processName: search },
    ] });
  }
  return query;
}

const dataText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$dataEventType', ''] }, ' ',
  { $ifNull: ['$description', ''] }, ' ', { $ifNull: ['$transferChannel', ''] }, ' ',
  { $ifNull: ['$fileAction', ''] }, ' ', { $ifNull: ['$fimModule', ''] }, ' ',
  { $ifNull: ['$sensitivityType', ''] }, ' ', { $ifNull: ['$dataClassification', ''] }, ' ',
  { $ifNull: ['$dlpPattern', ''] }, ' ', { $ifNull: ['$actionTaken', ''] }, ' ',
  { $ifNull: ['$containmentStatus', ''] }, ' ', { $ifNull: ['$fileName', ''] }, ' ',
  { $ifNull: ['$filePath', ''] }, ' ', { $ifNull: ['$destinationDomain', ''] }, ' ',
  { $ifNull: ['$processName', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: '$_dataText', regex } });
const classificationIs = value => ({ $eq: [{ $toLower: { $ifNull: ['$dataClassification', 'unknown'] } }, value] });

function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function reportClassification(row = {}) {
  const reported = String(row.dataClassification || '').trim();
  if (reported && reported.toLowerCase() !== 'unknown') return reported;
  const evidence = `${row.sensitivityType || ''} ${row.filePath || ''}`.toLowerCase();
  if (/credential|secret|private.?key|ssh.?key|password/.test(evidence)) return 'Secret';
  if (/source.?code|database|backup|certificate|config/.test(evidence)) return 'Restricted';
  if (/finance|payroll|human.resources|\bhr\b|confidential|sensitive/.test(evidence)) return 'Confidential';
  return row.filePath ? 'Internal' : 'Unknown';
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No data-security records found']);
  const objects = []; const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index]; const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 30 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`;
  });
  let pdf = '%PDF-1.4\n'; const offsets = [0];
  for (let id = 1; id < objects.length; id += 1) { offsets[id] = Buffer.byteLength(pdf); pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`; }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

async function writeAudit(req, action, alert, metadata = {}) {
  const actorId = req.user.id || req.user._id;
  const tenantId = req.user.tenantId || alert?.tenantId;
  if (!actorId || !tenantId) return;
  await SocAuditEvent.create({
    tenantId, companyId: alert?.companyId || req.user.companyId, actorId,
    action, targetType: 'DataSecurityAlert', targetId: String(alert?._id || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const query = dataQuery(req);
    const eventLimit = integer(req.query.limit, 250, 1, 500);
    const activeSince = new Date(Date.now() - 5 * 60 * 1000);
    const [facets = {}, agentSummary = {}] = await Promise.all([
      Alert.aggregate([
        { $match: query }, { $set: { _dataText: dataText } },
        { $facet: {
          summary: [{ $group: {
            _id: null, total: { $sum: 1 },
            critical: sumWhen({ $eq: ['$severity', 'critical'] }), high: sumWhen({ $eq: ['$severity', 'high'] }),
            medium: sumWhen({ $eq: ['$severity', 'medium'] }), low: sumWhen({ $eq: ['$severity', 'low'] }),
            sensitiveFileAccess: sumWhen(matches('sensitive.file|file.sensitive|confidential|restricted|secret')),
            exfiltrationAttempts: sumWhen(matches('exfil|upload|transfer|ftp|sftp|scp')),
            blockedExfiltrationAttempts: sumWhen({ $and: [matches('exfil|upload|transfer|ftp|sftp|scp'), matches('block|deny|prevent|quarantin')] }),
            usbTransfers: sumWhen(matches('usb|removable')),
            cloudUploads: sumWhen(matches('cloud|google.drive|onedrive|dropbox|box|mega|icloud|s3|azure.blob|gcs')),
            dlpViolations: sumWhen(matches('dlp|pii|aadhaar|pan|passport|api.key|private.key|credential')),
            databaseExports: sumWhen(matches('database.export|database.dump|sql.dump|mysqldump|pg.dump|mongodump')),
            ransomwareEvents: sumWhen(matches('ransom|encrypt|mass.rename|mass.delete|shadow.copy|backup.deletion')),
            emailAttachmentViolations: sumWhen(matches('email|attachment|smtp')),
            sftpScpTransfers: sumWhen(matches('sftp|scp|ssh.transfer')),
            networkShareCopies: sumWhen(matches('smb|network.share|share.copy|nas.copy')),
            clipboardCopies: sumWhen(matches('clipboard|copy.paste')),
            secretEvents: sumWhen(classificationIs('secret')),
            restrictedEvents: sumWhen(classificationIs('restricted')),
            confidentialEvents: sumWhen(classificationIs('confidential')),
            protectedDataBytes: { $sum: numberExpr('$fileSize') },
          } }],
          timeline: [{ $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, count: { $sum: 1 }, bytes: { $sum: numberExpr('$bytesTransferred') } } }, { $sort: { _id: 1 } }],
          classifications: [{ $group: { _id: { $ifNull: ['$dataClassification', 'Unknown'] }, count: { $sum: 1 }, bytes: { $sum: numberExpr('$fileSize') } } }, { $sort: { count: -1 } }],
          topChannels: [{ $group: { _id: { $ifNull: ['$transferChannel', '$transferProtocol'] }, count: { $sum: 1 }, bytes: { $sum: numberExpr('$bytesTransferred') } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          topUsers: [{ $group: { _id: '$username', count: { $sum: 1 }, bytes: { $sum: numberExpr('$bytesTransferred') } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          topHosts: [{ $group: { _id: '$hostname', count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          events: [{ $sort: { createdAt: -1 } }, { $limit: eventLimit }],
        } },
      ]).option({ allowDiskUse: true, maxTimeMS: 15000 }).then(rows => rows[0] || {}),
      System.aggregate([
        { $match: companyScope(req) },
        { $set: { _osText: { $toLower: { $concat: [{ $ifNull: ['$os', ''] }, ' ', { $ifNull: ['$osType', ''] }, ' ', { $ifNull: ['$platform', ''] }] } } } },
        { $group: {
          _id: null, total: { $sum: 1 }, live: { $sum: { $cond: [{ $gte: ['$lastSeen', activeSince] }, 1, 0] } },
          windows: sumWhen({ $regexMatch: { input: '$_osText', regex: 'win' } }),
          linux: sumWhen({ $regexMatch: { input: '$_osText', regex: 'linux|ubuntu|debian|centos|rhel' } }),
          macos: sumWhen({ $regexMatch: { input: '$_osText', regex: 'mac|darwin|osx' } }),
        } },
      ]).option({ maxTimeMS: 5000 }).then(rows => rows[0] || {}),
    ]);
    const summary = facets.summary?.[0] || {};
    const totalAgents = Number(agentSummary.total || 0); const liveAgents = Number(agentSummary.live || 0);
    res.json({
      summary: {
        ...summary, _id: undefined, protectedEndpoints: totalAgents, liveAgents,
        offlineAgents: Math.max(0, totalAgents - liveAgents),
        windowsEndpoints: Number(agentSummary.windows || 0), linuxEndpoints: Number(agentSummary.linux || 0),
        macosEndpoints: Number(agentSummary.macos || 0),
      },
      timeline: facets.timeline || [], classifications: facets.classifications || [], topChannels: facets.topChannels || [],
      topUsers: facets.topUsers || [], topHosts: facets.topHosts || [], events: facets.events || [],
      generatedAt: new Date(), realtimeEvent: 'data-security:event',
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/live', async (req, res) => {
  try {
    const events = await Alert.find(dataQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 100, 1, 500)).lean();
    res.json({ events, total: events.length, realtimeEvent: 'data-security:event' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/logs', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000); const limit = integer(req.query.limit, 100, 1, 500);
    const query = dataQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/log/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...DATA_FILTER }).lean();
    if (!event) return res.status(404).json({ message: 'Data-security event not found' });
    const pivots = [
      event.systemId ? { systemId: event.systemId } : null,
      event.username ? { username: event.username } : null,
      event.fileHash ? { fileHash: event.fileHash } : null,
    ].filter(Boolean);
    const relatedEvents = pivots.length ? await Alert.find({
      ...companyScope(req), ...DATA_FILTER,
      createdAt: { $gte: new Date(new Date(event.createdAt).getTime() - 30 * 60000), $lte: new Date(new Date(event.createdAt).getTime() + 30 * 60000) },
      $and: [{ $or: pivots }],
    }).sort({ createdAt: 1 }).limit(100).lean() : [];
    res.json({ event, relatedEvents, filePreviewAvailable: false });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/reports', async (req, res) => {
  try {
    const events = await Alert.find(dataQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 5000, 1, 10000)).lean();
    res.json({ events, total: events.length, filters: req.query, generatedAt: new Date() });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/respond', requireCompanyAdmin, async (req, res) => {
  try {
    const actionType = String(req.body.actionType || '');
    if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
    if (!ACTIONS.has(actionType)) return res.status(400).json({ message: 'Unsupported response action' });
    if (!req.body.confirmed || !String(req.body.reason || '').trim()) return res.status(400).json({ message: 'confirmed=true and reason are required' });
    const alert = await Alert.findOne({ _id: req.body.alertId, ...companyScope(req), ...DATA_FILTER });
    if (!alert) return res.status(404).json({ message: 'Data-security event not found' });
    const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId }).lean();
    if (!system) return res.status(409).json({ message: 'Target endpoint is unavailable' });
    const actionParams = { ...(req.body.actionParams || {}) };
    if (actionType === 'kill_process' && !actionParams.pid) actionParams.pid = alert.pid;
    if (actionType === 'block_ip' && !actionParams.ip) actionParams.ip = alert.destip || alert.srcip;
    if (actionType === 'block_domain' && !actionParams.domain) actionParams.domain = alert.destinationDomain || alert.domain;
    if (actionType === 'block_hash' && !actionParams.hash) actionParams.hash = alert.fileHash;
    if (actionType === 'quarantine_file' && !actionParams.path) actionParams.path = alert.filePath;
    const response = await createResponse({ companyId: alert.companyId, tenantId: alert.tenantId, alert, system, actionType, actionParams, triggeredBy: req.user.id || req.user._id, trigger: 'manual', io: req.app.get('io'), forceApproval: true });
    await writeAudit(req, 'data-security.response.requested', alert, { actionType, reason: String(req.body.reason).slice(0, 500), responseId: response?._id });
    res.status(202).json({ response });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase();
    const events = await Alert.find(dataQuery(req, req.body.filters || {})).sort({ createdAt: -1 }).limit(10000).lean();
    if (format === 'json') return res.json({ events, total: events.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Hostname', 'Username', 'Event', 'Sensitive File Name', 'File Path', 'File Size', 'Hash', 'Classification', 'Destination / Channel', 'Protocol', 'Bytes', 'Process', 'Risk', 'Severity', 'MITRE', 'Action Executed', 'Status'];
    const rows = events.map(row => {
      const sensitiveFileName = row.fileName || String(row.filePath || '').split(/[/\\]/).pop();
      const destinationChannel = [...new Set([row.destinationDomain || row.destip, row.transferChannel || row.device || row.mountPath].filter(Boolean))].join(' / ');
      const responseAction = row.actionTaken && row.actionTaken !== 'None' ? row.actionTaken : null;
      const containmentAction = row.containmentStatus && row.containmentStatus !== 'none' ? row.containmentStatus : null;
      return [row.createdAt, row.hostname, row.username, row.dataEventType || row.ruleId, sensitiveFileName, row.filePath, row.fileSize, row.fileHash, reportClassification(row), destinationChannel || 'Local endpoint', row.transferProtocol || row.protocol, row.bytesTransferred, row.processName, row.riskScore, row.severity, row.mitreId || row.mitreTechnique, responseAction || containmentAction || row.fileAction || row.dataEventType || 'Observed', row.status];
    });
    const csv = [columns.map(csvCell).join(','), ...rows.map(row => row.map(csvCell).join(','))].join('\n');
    if (format === 'csv') return res.type('text/csv').attachment(`data-security-${Date.now()}.csv`).send(csv);
    if (format === 'xlsx' || format === 'excel') return res.type('application/vnd.ms-excel').attachment(`data-security-${Date.now()}.xls`).send(csv);
    if (format === 'pdf') return res.type('application/pdf').attachment(`data-security-${Date.now()}.pdf`).send(buildPdf(['AJNAT SOC - Data Security Report', `Generated: ${new Date().toISOString()}`, `Records: ${events.length}`, '', ...rows.map(row => row.map(value => String(value ?? '')).join(' | '))]));
    return res.status(400).json({ message: 'Supported formats: csv, excel, pdf, json' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
