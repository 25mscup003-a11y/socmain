const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SystemChangeControl = require('../models/SystemChangeControl.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');
const { invalidateSystemChangeControlCache } = require('../services/systemChangeControl.service');

const CAPABILITY_FILTER = {
  isSynthetic: { $ne: true },
  $or: [{ capabilityId: 7 }, { capabilityIds: 7 }],
  ruleId: { $nin: ['PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY'] },
  eventType: { $nin: ['Sensor Health', 'Inventory Snapshot'] },
};
const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const VALID_STATUS = new Set(['open', 'investigating', 'resolved', 'false_positive', 'under_observation']);
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const rawCompany = req.user.companyId?._id || req.user.companyId;
  if (!mongoose.Types.ObjectId.isValid(rawCompany)) throw Object.assign(new Error('Invalid tenant scope'), { status: 400 });
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(rawCompany)),
    ...(departmentId && mongoose.Types.ObjectId.isValid(departmentId)
      ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) }
      : {}),
  };
}

function changeQuery(req, source = req.query) {
  const query = { ...companyScope(req, source.departmentId), ...CAPABILITY_FILTER };
  const hours = PERIOD_HOURS[String(source.period || '')] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const to = source.to ? new Date(source.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.status && VALID_STATUS.has(source.status)) query.status = source.status;
  if (source.category) query.systemChangeCategory = new RegExp(`^${escapeRegex(source.category).slice(0, 120)}$`, 'i');
  if (source.changeType) query.systemChangeType = new RegExp(escapeRegex(source.changeType).slice(0, 120), 'i');
  if (source.baselineStatus) query.baselineStatus = new RegExp(`^${escapeRegex(source.baselineStatus).slice(0, 80)}$`, 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname).slice(0, 253)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.os) query.$and = [{ $or: [{ os: new RegExp(escapeRegex(source.os), 'i') }, { osType: new RegExp(escapeRegex(source.os), 'i') }] }];
  if (source.minRisk != null) query.riskScore = { $gte: integer(source.minRisk, 0, 0, 100) };
  if (source.search) {
    const value = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and = [...(query.$and || []), { $or: [
      { description: value }, { ruleId: value }, { hostname: value }, { username: value },
      { systemChangeCategory: value }, { systemChangeType: value }, { systemChangeTarget: value },
      { processName: value }, { processCmdline: value }, { mitreId: value },
    ] }];
  }
  return query;
}

const projection = [
  'eventId eventFingerprint tenantId companyId departmentId systemId agentId agentName endpointId hostname os osType platform agentVersion',
  'ruleId detectionRuleId description source eventCategory category subCategory eventType severity riskScore status username userSid',
  'systemChangeCategory systemChangeType systemChangeTarget previousState newState baselineStatus changeSource changeTicket maintenanceApproved systemChangeIndicators',
  'processName processExe processCmdline commandLine pid parentPid parentProcessName hash fileHash signatureStatus publisher',
  'filePath fileName fileAction inventoryType inventoryName inventoryItem oldInventoryItem changeType keyPath oldValue newValue',
  'serviceName serviceDisplayName serviceBinaryPath serviceAccount serviceStartupType',
  'srcip sourceIp destip destinationIp protocol mitreId mitreTechnique mitreTechniques mitreTactic detectionReason confidenceScore',
  'rawEvent processTree childProcesses networkConnections filesCreated filesModified filesDeleted assignedTo createdAt updatedAt firstSeen lastSeen',
].join(' ');

function csvCell(value) {
  let text = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No system-change records found']);
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
  const xref = Buffer.byteLength(pdf); pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

async function audit(req, action, targetId, metadata = {}) {
  const actorId = req.user.id || req.user._id; const tenantId = req.user.tenantId;
  if (!actorId || !tenantId) return;
  await SocAuditEvent.create({ tenantId, companyId: req.user.companyId?._id || req.user.companyId, actorId,
    action, targetType: 'SystemChange', targetId: String(targetId || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64) });
}

function emit(req, eventName, payload) {
  const companyId = req.user.companyId?._id || req.user.companyId;
  req.app.get('io')?.to(`company:${companyId}`).emit(eventName, payload);
}

router.use(authenticate, requireAnalyst);

router.get('/summary', async (req, res) => {
  try {
    const [facets = {}, agents = []] = await Promise.all([
      Alert.aggregate([{ $match: changeQuery(req) }, { $facet: {
        summary: [{ $group: { _id: null, total: { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
          medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
          low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
          baselineViolations: { $sum: { $cond: [{ $in: ['$baselineStatus', ['new', 'modified', 'unexpected', 'violation']] }, 1, 0] } },
          maximumRisk: { $max: '$riskScore' }, averageRisk: { $avg: '$riskScore' },
        } }],
        timeline: [{ $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, total: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } } } }, { $sort: { _id: 1 } }],
        categories: [{ $group: { _id: { $ifNull: ['$systemChangeCategory', 'Unclassified'] }, count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { count: -1 } }],
        hosts: [{ $group: { _id: { $ifNull: ['$hostname', '$agentName'] }, count: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 50 }],
        operatingSystems: [{ $group: { _id: { $ifNull: ['$osType', { $ifNull: ['$os', '$platform'] }] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }],
        changes: [{ $sort: { createdAt: -1 } }, { $limit: 250 }, { $project: Object.fromEntries(projection.split(' ').map(field => [field, 1])) }],
      } }]).option({ allowDiskUse: true, maxTimeMS: 12000 }).then(rows => rows[0] || {}),
      System.find(companyScope(req)).select('name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const summary = facets.summary?.[0] || {};
    res.json({ summary: { ...summary, _id: undefined, affectedSystems: facets.hosts?.length || 0 }, timeline: facets.timeline || [], categories: facets.categories || [], hosts: facets.hosts || [], operatingSystems: facets.operatingSystems || [], events: facets.changes || [], systems: agents, total: summary.total || 0, generatedAt: new Date(), realtimeEvent: 'system-change:event' });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'System-change summary could not be loaded' }); }
});

router.get('/timeline', async (req, res) => {
  try {
    const timeline = await Alert.aggregate([{ $match: changeQuery(req) }, { $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, total: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { _id: 1 } }]).option({ maxTimeMS: 5000 });
    res.json({ timeline });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Timeline could not be loaded' }); }
});

router.get('/categories', async (req, res) => {
  try { res.json({ categories: await Alert.aggregate([{ $match: changeQuery(req) }, { $group: { _id: '$systemChangeCategory', count: { $sum: 1 } } }, { $sort: { count: -1 } }]).option({ maxTimeMS: 5000 }) }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Categories could not be loaded' }); }
});

router.get('/hosts', async (req, res) => {
  try { res.json({ hosts: await Alert.aggregate([{ $match: changeQuery(req) }, { $group: { _id: '$hostname', count: { $sum: 1 }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 500 }]).option({ maxTimeMS: 5000 }) }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Hosts could not be loaded' }); }
});

router.get('/critical', async (req, res) => {
  try { const query = changeQuery(req); query.$and = [...(query.$and || []), { $or: [{ severity: 'critical' }, { riskScore: { $gte: 80 } }] }]; const events = await Alert.find(query).select(projection).sort({ createdAt: -1 }).limit(integer(req.query.limit, 100, 1, 500)).lean(); res.json({ events, total: events.length }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Critical changes could not be loaded' }); }
});

router.get('/risk', async (req, res) => {
  try { const risk = await Alert.aggregate([{ $match: changeQuery(req) }, { $bucket: { groupBy: { $ifNull: ['$riskScore', 0] }, boundaries: [0, 20, 40, 60, 80, 101], default: 'unknown', output: { count: { $sum: 1 } } } }]).option({ maxTimeMS: 5000 }); res.json({ risk }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Risk data could not be loaded' }); }
});

router.get('/baseline', async (req, res) => {
  try { const controls = await SystemChangeControl.find({ ...companyScope(req), kind: 'baseline', enabled: true, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] }).sort({ createdAt: -1 }).limit(1000).lean(); res.json({ baselines: controls, total: controls.length }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Baselines could not be loaded' }); }
});

router.get('/', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 1000000); const limit = integer(req.query.limit, 100, 1, 1000); const query = changeQuery(req);
    const [events, total] = await Promise.all([Alert.find(query).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).maxTimeMS(5000).lean(), Alert.countDocuments(query).maxTimeMS(5000)]);
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit), updatedAt: new Date().toISOString(), realtimeEvent: 'system-change:event' });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'System changes could not be loaded' }); }
});

router.get('/:id', async (req, res) => {
  try { if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid event id' }); const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...CAPABILITY_FILTER }).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').lean(); if (!event) return res.status(404).json({ message: 'System change not found' }); res.json({ event }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'System change could not be loaded' }); }
});

async function saveControl(req, res, kind) {
  const target = String(req.body.target || '').trim(); const reason = String(req.body.reason || '').trim();
  if (!target || !reason) return res.status(400).json({ message: 'target and reason are required' });
  const expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt) : null;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ message: 'Invalid expiresAt' });
  const actorId = req.user.id || req.user._id; const scope = companyScope(req, req.body.departmentId);
  const control = await SystemChangeControl.create({ tenantId: req.user.tenantId, ...scope, systemId: mongoose.isValidObjectId(req.body.systemId) ? req.body.systemId : null, kind, target: target.slice(0, 2048), category: String(req.body.category || '').slice(0, 120), changeType: String(req.body.changeType || '').slice(0, 120), processName: String(req.body.processName || '').slice(0, 260), expectedState: req.body.expectedState ?? null, reason: reason.slice(0, 1000), ticketReference: String(req.body.ticketReference || '').slice(0, 160), temporary: Boolean(expiresAt), expiresAt, createdBy: actorId, updatedBy: actorId });
  invalidateSystemChangeControlCache(scope.companyId);
  await audit(req, `system-change.${kind}.created`, control._id, { target, reason, expiresAt });
  emit(req, 'system-change:baseline-changed', { control });
  return res.status(201).json({ control });
}

router.post('/baseline/approve', requireCompanyAdmin, (req, res) => saveControl(req, res, 'baseline').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/exception', requireCompanyAdmin, (req, res) => saveControl(req, res, 'exception').catch(error => res.status(error.status || 500).json({ message: error.message })));

async function updateWorkflow(req, res, status, action) {
  if (!mongoose.Types.ObjectId.isValid(req.body.eventId)) return res.status(400).json({ message: 'Valid eventId is required' });
  const event = await Alert.findOne({ _id: req.body.eventId, ...companyScope(req, req.body.departmentId), ...CAPABILITY_FILTER });
  if (!event) return res.status(404).json({ message: 'System change not found' });
  event.status = status; if (status === 'investigating') event.assignedTo = req.user.id || req.user._id;
  await event.save(); await audit(req, action, event._id, { reason: String(req.body.reason || '').slice(0, 1000) });
  const payload = event.toObject(); emit(req, 'system-change:updated', payload); return res.json({ event: payload });
}
router.post('/acknowledge', (req, res) => updateWorkflow(req, res, 'under_observation', 'system-change.acknowledged').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/investigate', (req, res) => updateWorkflow(req, res, 'investigating', 'system-change.investigating').catch(error => res.status(error.status || 500).json({ message: error.message })));

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase(); const rows = await Alert.find(changeQuery(req, req.body.filters || {})).select(projection).sort({ createdAt: -1 }).limit(10000).maxTimeMS(10000).lean();
    if (format === 'json') return res.json({ events: rows, total: rows.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Company', 'Host', 'OS', 'User', 'Category', 'Change Type', 'Target', 'Previous State', 'New State', 'Process', 'Parent Process', 'Command Line', 'Severity', 'Risk Score', 'Baseline Status', 'Detection Reason', 'MITRE Technique', 'Status'];
    const values = rows.map(row => [row.createdAt, row.companyId, row.hostname || row.agentName, row.osType || row.os || row.platform, row.username, row.systemChangeCategory, row.systemChangeType, row.systemChangeTarget, row.previousState, row.newState, row.processName, row.parentProcessName, row.processCmdline || row.commandLine, row.severity, row.riskScore, row.baselineStatus, row.detectionReason || row.description, row.mitreId || row.mitreTechnique, row.status]);
    const csv = [columns, ...values].map(line => line.map(csvCell).join(',')).join('\n');
    if (format === 'csv') return res.type('text/csv').attachment(`system-changes-${Date.now()}.csv`).send(csv);
    if (format === 'xlsx' || format === 'excel') return res.type('application/vnd.ms-excel').attachment(`system-changes-${Date.now()}.xls`).send(csv);
    if (format === 'pdf') return res.type('application/pdf').attachment(`system-changes-${Date.now()}.pdf`).send(buildPdf(['AJNAT EDR - System Changes Monitoring Report', `Generated: ${new Date().toISOString()}`, `Records: ${rows.length}`, '', ...values.map(line => line.map(value => String(value ?? '')).join(' | '))]));
    return res.status(400).json({ message: 'Supported formats: csv, excel, pdf, json' });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'System-change export failed' }); }
});

module.exports = router;
