const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');

const PERSISTENCE_FILTER = {
  isSynthetic: { $ne: true },
  $or: [{ capabilityId: 8 }, { capabilityIds: 8 }],
  ruleId: { $nin: ['PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY'] },
};
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

function persistenceQuery(req, source = req.query) {
  const hours = integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const to = source.to ? new Date(source.to) : null;
  const query = { ...companyScope(req, source.departmentId), ...PERSISTENCE_FILTER };
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.status) query.status = String(source.status).slice(0, 40);
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname).slice(0, 253)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.technique) query.$and = [{ $or: [
    { mitreId: new RegExp(escapeRegex(source.technique).slice(0, 80), 'i') },
    { mitreTechnique: new RegExp(escapeRegex(source.technique).slice(0, 120), 'i') },
    { technique: new RegExp(escapeRegex(source.technique).slice(0, 120), 'i') },
  ] }];
  if (source.type) query.persistenceType = new RegExp(escapeRegex(source.type).slice(0, 100), 'i');
  if (source.search) {
    const value = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    const clause = { $or: [
      { description: value }, { ruleId: value }, { hostname: value }, { username: value },
      { persistenceType: value }, { persistenceLocation: value }, { persistenceKey: value },
      { processName: value }, { processCmdline: value }, { hash: value }, { newHash: value },
    ] };
    query.$and = [...(query.$and || []), clause];
  }
  return query;
}

const projection = [
  'eventId eventFingerprint companyId departmentId systemId agentId agentName endpointId hostname osType agentVersion',
  'ruleId detectionRuleId description source category subCategory eventType severity riskScore status username',
  'persistenceType persistenceLocation persistenceKey persistenceValue persistenceTrigger persistenceAction',
  'inventoryType inventoryName inventoryItem oldInventoryItem changeType keyPath oldValue newValue',
  'processName processExe processCmdline pid parentPid parentProcessName hash newHash fileHash signatureStatus publisher',
  'mitreId mitreTechnique mitreTechniques mitreTactic detectionReason confidenceScore',
  'srcip destip destPort processTree childProcesses networkConnections filesCreated filesModified filesDeleted',
  'rawEvent firstSeen lastSeen createdAt updatedAt',
].join(' ');

router.use(authenticate, requireAnalyst);

router.get('/events', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 1000000);
    const limit = integer(req.query.limit, 100, 1, 1000);
    const query = persistenceQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).select(projection).populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion')
        .sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).maxTimeMS(5000).lean(),
      Alert.countDocuments(query).maxTimeMS(5000),
    ]);
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit), updatedAt: new Date().toISOString() });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence events could not be loaded' });
  }
});

router.get('/events/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...PERSISTENCE_FILTER })
      .select(projection).populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').lean();
    if (!event) return res.status(404).json({ message: 'Persistence event not found' });
    res.json({ event });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence event could not be loaded' });
  }
});

router.get('/alerts', async (req, res) => {
  req.query.severity = req.query.severity || undefined;
  try {
    const query = persistenceQuery(req);
    query.$and = [...(query.$and || []), { $or: [
      { severity: { $in: ['critical', 'high', 'medium'] } }, { riskScore: { $gte: 40 } },
    ] }];
    const limit = integer(req.query.limit, 100, 1, 500);
    const events = await Alert.find(query).select(projection).sort({ createdAt: -1 }).limit(limit).maxTimeMS(5000).lean();
    res.json({ alerts: events, total: events.length, updatedAt: new Date().toISOString() });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence alerts could not be loaded' });
  }
});

router.get('/hosts', async (req, res) => {
  try {
    const hosts = await Alert.aggregate([
      { $match: persistenceQuery(req) },
      { $group: { _id: { $ifNull: ['$hostname', '$agentName'] }, events: { $sum: 1 }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } },
      { $match: { _id: { $nin: [null, ''] } } }, { $sort: { events: -1 } }, { $limit: 500 },
    ]).option({ maxTimeMS: 5000 });
    res.json({ hosts });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence hosts could not be loaded' }); }
});

router.get('/techniques', async (req, res) => {
  try {
    const techniques = await Alert.aggregate([
      { $match: persistenceQuery(req) },
      { $project: { technique: { $ifNull: ['$mitreId', { $ifNull: ['$mitreTechnique', '$technique'] }] }, severity: 1, riskScore: 1 } },
      { $match: { technique: { $nin: [null, ''] } } },
      { $group: { _id: '$technique', count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { count: -1 } },
    ]).option({ maxTimeMS: 5000 });
    res.json({ techniques });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence techniques could not be loaded' }); }
});

router.get('/statistics', async (req, res) => {
  try {
    const result = await Alert.aggregate([{ $match: persistenceQuery(req) }, { $facet: {
      total: [{ $count: 'value' }],
      severity: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
      types: [{ $group: { _id: { $ifNull: ['$persistenceType', '$inventoryType'] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }],
      endpoints: [{ $group: { _id: { $ifNull: ['$systemId', '$hostname'] } } }, { $count: 'value' }],
      risk: [{ $group: { _id: null, average: { $avg: '$riskScore' }, maximum: { $max: '$riskScore' } } }],
    } }]).option({ maxTimeMS: 5000 });
    const value = result[0] || {};
    res.json({ total: value.total?.[0]?.value || 0, severity: value.severity || [], types: value.types || [],
      affectedEndpoints: value.endpoints?.[0]?.value || 0, risk: value.risk?.[0] || { average: 0, maximum: 0 } });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence statistics could not be loaded' }); }
});

router.get('/timeline', async (req, res) => {
  try {
    const rows = await Alert.aggregate([
      { $match: persistenceQuery(req) },
      { $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, total: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } },
      { $sort: { _id: 1 } }, { $limit: 8760 },
    ]).option({ maxTimeMS: 5000 });
    res.json({ timeline: rows.map(row => ({ timestamp: row._id, total: row.total, maxRisk: row.maxRisk || 0 })) });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Persistence timeline could not be loaded' }); }
});

function csvCell(value) {
  let text = String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No persistence records found']);
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

async function reportRows(req) {
  return Alert.find(persistenceQuery(req)).select(projection).sort({ createdAt: -1 }).limit(10000).maxTimeMS(10000).lean();
}

router.get('/export/csv', async (req, res) => {
  try {
    const rows = await reportRows(req);
    const header = ['Timestamp', 'Company', 'Host', 'User', 'Persistence Type', 'Location', 'MITRE Technique', 'Severity', 'Risk Score', 'Process', 'Hash', 'Detection Reason', 'Status'];
    const csv = [header, ...rows.map(row => [row.createdAt, row.companyId, row.hostname || row.agentName, row.username,
      row.persistenceType || row.inventoryType, row.persistenceLocation || row.keyPath, row.mitreId || row.mitreTechnique || row.technique,
      row.severity, row.riskScore, row.processName, row.hash || row.newHash || row.fileHash, row.detectionReason || row.description, row.status])]
      .map(values => values.map(csvCell).join(',')).join('\n');
    res.set({ 'Content-Type': 'text/csv; charset=utf-8', 'Content-Disposition': 'attachment; filename="persistence-events.csv"' }).send(csv);
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'CSV export failed' }); }
});

router.get('/export/pdf', async (req, res) => {
  try {
    const rows = await reportRows(req);
    const severity = rows.reduce((out, row) => ({ ...out, [row.severity || 'unknown']: (out[row.severity || 'unknown'] || 0) + 1 }), {});
    const lines = ['AJNAT EDR - Persistence Mechanism Detection Report', `Generated: ${new Date().toISOString()}`,
      `Events: ${rows.length} | Critical: ${severity.critical || 0} | High: ${severity.high || 0}`, '',
      ...rows.flatMap(row => [`${row.createdAt?.toISOString?.() || row.createdAt} | ${(row.severity || '').toUpperCase()} | ${row.hostname || row.agentName || '-'} | ${row.persistenceType || row.inventoryType || row.technique || '-'}`,
        `  ${row.mitreId || row.mitreTechnique || '-'} | risk ${row.riskScore || 0} | ${row.description || ''}`])];
    const pdf = buildPdf(lines);
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="persistence-events.pdf"', 'Content-Length': pdf.length }).send(pdf);
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'PDF export failed' }); }
});

module.exports = router;
