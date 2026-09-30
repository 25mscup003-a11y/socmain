const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { createResponse } = require('../services/automatedResponse.service');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');

const LATERAL_FILTER = {
  isSynthetic: { $ne: true },
  $or: [
    { capabilityId: 14 }, { capabilityIds: 14 },
  ],
};
const ACTIONS = new Set(['isolate', 'kill_process', 'disable_user', 'block_ip', 'block_domain', 'block_hash', 'block_port', 'force_logoff', 'quarantine_file']);
const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const companyScope = (req, requestedDepartmentId = req.query?.departmentId) => {
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(req.user.companyId?._id || req.user.companyId)),
    ...(departmentId ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) } : {}),
    ...(req.query?.systemId && mongoose.isValidObjectId(req.query.systemId)
      ? { systemId: new mongoose.Types.ObjectId(String(req.query.systemId)) }
      : {}),
  };
};
const periodStart = value => new Date(Date.now() - integer(value, 24, 1, 24 * 365) * 3600000);
const classificationText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$lateralVector', ''] }, ' ',
  { $ifNull: ['$description', ''] }, ' ', { $ifNull: ['$eventType', ''] }, ' ',
  { $ifNull: ['$processName', ''] }, ' ', { $ifNull: ['$processCmdline', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: '$_lateralText', regex } });
const sumWhen = condition => ({ $sum: { $cond: [condition, 1, 0] } });
const csvCell = value => {
  let text = String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
};

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No lateral movement records found']);
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
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

function lateralQuery(req, source = req.query) {
  const query = { ...companyScope(req, source.departmentId), ...LATERAL_FILTER };
  const period = String(source.period || '');
  const hours = PERIOD_HOURS[period] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : periodStart(hours);
  const to = source.to ? new Date(source.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? periodStart(24) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.vector) query.lateralVector = new RegExp(escapeRegex(source.vector).slice(0, 100), 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.search) {
    const search = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and = [{ $or: [{ description: search }, { ruleId: search }, { hostname: search }, { username: search }, { sourceHost: search }, { destinationHost: search }, { srcip: search }, { destip: search }, { processName: search }, { processCmdline: search }] }];
  }
  return query;
}

async function writeAudit(req, action, alert, metadata = {}) {
  const actorId = req.user.id || req.user._id;
  const tenantId = req.user.tenantId || alert?.tenantId;
  if (!actorId || !tenantId) return;
  await SocAuditEvent.create({
    tenantId, companyId: alert?.companyId || req.user.companyId, actorId,
    action, targetType: 'LateralMovementAlert', targetId: String(alert?._id || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const query = lateralQuery(req);
    const eventLimit = integer(req.query.limit, 250, 1, 500);
    const systemQuery = companyScope(req);
    const activeSince = new Date(Date.now() - 5 * 60 * 1000);
    const [facets = {}, agentSummary = {}] = await Promise.all([
      Alert.aggregate([
        { $match: query },
        { $set: { _lateralText: classificationText } },
        { $facet: {
          summary: [{ $group: {
            _id: null, total: { $sum: 1 }, critical: sumWhen({ $eq: ['$severity', 'critical'] }),
            high: sumWhen({ $eq: ['$severity', 'high'] }), medium: sumWhen({ $eq: ['$severity', 'medium'] }),
            low: sumWhen({ $eq: ['$severity', 'low'] }),
            activeRemoteSessions: sumWhen({ $eq: ['$sessionState', 'active'] }),
            rdpSessions: sumWhen(matches('rdp|3389')), sshSessions: sumWhen(matches('ssh|22')),
            smbSessions: sumWhen(matches('smb|admin\\$|445')), wmiExecutions: sumWhen(matches('wmi|wmic|1047')),
            psexecActivities: sumWhen(matches('psexec|paexec')), powershellRemoteSessions: sumWhen(matches('powershell remoting|invoke.command|pssession|winrm')),
            credentialAbuseEvents: sumWhen(matches('pass.the.hash|pass.the.ticket|golden.ticket|silver.ticket|mimikatz|rubeus|lsass|credential')),
            averageRiskScore: { $avg: { $ifNull: ['$riskScore', 0] } },
          } }],
          timeline: [{ $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, count: { $sum: 1 } } }, { $sort: { _id: 1 } }],
          topVectors: [{ $group: { _id: { $ifNull: ['$lateralVector', '$ruleId'] }, count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          topSources: [{ $group: { _id: { $ifNull: ['$sourceHost', '$srcip'] }, count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          topDestinations: [{ $group: { _id: { $ifNull: ['$destinationHost', '$destip'] }, count: { $sum: 1 } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          attackPaths: [{ $group: { _id: { source: { $ifNull: ['$sourceHost', '$srcip'] }, destination: { $ifNull: ['$destinationHost', '$destip'] } }, events: { $sum: 1 }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } }, { $match: { '_id.source': { $nin: [null, ''] }, '_id.destination': { $nin: [null, ''] } } }, { $sort: { maxRisk: -1, events: -1 } }, { $limit: 50 }],
          events: [
            { $sort: { createdAt: -1 } }, { $limit: eventLimit },
            { $project: {
              _id: 1, tenantId: 1, companyId: 1, departmentId: 1, systemId: 1,
              createdAt: 1, timestamp: 1, eventTimestamp: 1, capabilityId: 1, capabilityIds: 1,
              eventId: 1, agentId: 1, agentName: 1, hostname: 1, username: 1, user: 1,
              ruleId: 1, description: 1, source: 1, type: 1, eventType: 1, eventCategory: 1,
              subCategory: 1, severity: 1, status: 1, actionable: 1, action: 1, actionTaken: 1,
              srcip: 1, sourcePort: 1, srcPort: 1, destip: 1, destPort: 1, port: 1, protocol: 1,
              lateralVector: 1, sourceHost: 1, destinationHost: 1, authProtocol: 1, shareName: 1,
              sessionState: 1, windowsEventId: 1, attackPathId: 1, relatedEventIds: 1,
              riskScore: 1, confidenceScore: 1, processName: 1, processCmdline: 1, processExe: 1,
              pid: 1, parentPid: 1, parentProcessName: 1, fileHash: 1, os: 1, platform: 1,
              mitreId: 1, mitreTechnique: 1, mitreTechniques: 1, mitreTactic: 1, technique: 1,
              threatIntel: 1, iocMatches: 1, ioc: 1,
            } },
          ],
        } },
      ]).option({ allowDiskUse: true, maxTimeMS: 15000 }).then(rows => rows[0] || {}),
      System.aggregate([
        { $match: systemQuery },
        { $group: { _id: null, total: { $sum: 1 }, live: { $sum: { $cond: [{ $gte: ['$lastSeen', activeSince] }, 1, 0] } } } },
      ]).option({ maxTimeMS: 5000 }).then(rows => rows[0] || {}),
    ]);
    const summary = facets.summary?.[0] || {};
    const paths = facets.attackPaths || [];
    const totalAgents = Number(agentSummary.total || 0);
    const liveAgents = Number(agentSummary.live || 0);
    res.json({
      summary: { ...summary, _id: undefined, activeAttackPaths: paths.length, protectedEndpoints: totalAgents, liveAgents, offlineAgents: Math.max(0, totalAgents - liveAgents) },
      timeline: facets.timeline || [], topVectors: facets.topVectors || [], topSources: facets.topSources || [],
      topDestinations: facets.topDestinations || [], attackPaths: paths, events: facets.events || [],
      generatedAt: new Date(), realtimeEvent: 'lateral:event',
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/live', async (req, res) => {
  try {
    const events = await Alert.find(lateralQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 100, 1, 500)).lean();
    res.json({ events, total: events.length, realtimeEvent: 'lateral:event' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/logs', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000); const limit = integer(req.query.limit, 100, 1, 500);
    const query = lateralQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(), Alert.countDocuments(query),
    ]);
    res.json({ events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/log/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...LATERAL_FILTER }).lean();
    if (!event) return res.status(404).json({ message: 'Lateral movement event not found' });
    const pivotValues = [event.sourceHost, event.destinationHost, event.srcip, event.destip].filter(Boolean);
    const relatedEvents = pivotValues.length ? await Alert.find({
      ...companyScope(req), ...LATERAL_FILTER,
      createdAt: { $gte: new Date(new Date(event.createdAt).getTime() - 30 * 60000), $lte: new Date(new Date(event.createdAt).getTime() + 30 * 60000) },
      $and: [{ $or: [{ sourceHost: { $in: pivotValues } }, { destinationHost: { $in: pivotValues } }, { srcip: { $in: pivotValues } }, { destip: { $in: pivotValues } }] }],
    }).sort({ createdAt: 1 }).limit(100).lean() : [];
    res.json({ event, relatedEvents });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/reports', async (req, res) => {
  try {
    const events = await Alert.find(lateralQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 5000, 1, 10000)).lean();
    res.json({ events, total: events.length, filters: req.query, generatedAt: new Date() });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/respond', requireCompanyAdmin, async (req, res) => {
  try {
    const actionType = String(req.body.actionType || '');
    if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
    if (!ACTIONS.has(actionType)) return res.status(400).json({ message: 'Unsupported response action' });
    if (!req.body.confirmed || !String(req.body.reason || '').trim()) return res.status(400).json({ message: 'confirmed=true and reason are required' });
    const alert = await Alert.findOne({ _id: req.body.alertId, ...companyScope(req), ...LATERAL_FILTER });
    if (!alert) return res.status(404).json({ message: 'Lateral movement event not found' });
    const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId }).lean();
    if (!system) return res.status(409).json({ message: 'Target endpoint is unavailable' });
    const actionParams = { ...(req.body.actionParams || {}) };
    if (actionType === 'kill_process' && !actionParams.pid) actionParams.pid = alert.pid;
    if (actionType === 'block_ip' && !actionParams.ip) actionParams.ip = alert.destip || alert.srcip;
    if (actionType === 'block_domain' && !actionParams.domain) actionParams.domain = alert.domain;
    if (actionType === 'block_hash' && !actionParams.hash) actionParams.hash = alert.fileHash || alert.processExecutableSha256;
    if (actionType === 'disable_user' && !actionParams.username) actionParams.username = alert.username;
    const response = await createResponse({ companyId: alert.companyId, tenantId: alert.tenantId, alert, system, actionType, actionParams, triggeredBy: req.user.id || req.user._id, trigger: 'manual', io: req.app.get('io'), forceApproval: true });
    await writeAudit(req, 'lateral-movement.response.requested', alert, { actionType, reason: String(req.body.reason).slice(0, 500), responseId: response?._id });
    res.status(202).json({ response });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase();
    const events = await Alert.find(lateralQuery(req, req.body.filters || {})).sort({ createdAt: -1 }).limit(10000).lean();
    if (format === 'json') return res.json({ events, total: events.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Hostname', 'Username', 'Source Host', 'Destination Host', 'Source IP', 'Destination IP', 'Vector', 'Process', 'Command Line', 'Risk Score', 'Severity', 'MITRE', 'Status'];
    const rows = events.map(row => [row.createdAt, row.hostname, row.username, row.sourceHost, row.destinationHost, row.srcip, row.destip, row.lateralVector || row.ruleId, row.processName, row.processCmdline, row.riskScore, row.severity, row.mitreId || row.mitreTechnique, row.status]);
    if (format === 'csv') return res.type('text/csv').attachment(`lateral-movement-${Date.now()}.csv`).send([columns.map(csvCell).join(','), ...rows.map(row => row.map(csvCell).join(','))].join('\n'));
    if (format === 'pdf') {
      const lines = ['AJNAT SOC - Lateral Movement Report', `Generated: ${new Date().toISOString()}`, `Records: ${events.length}`, '', ...rows.map(row => row.map(value => String(value ?? '')).join(' | '))];
      return res.type('application/pdf').attachment(`lateral-movement-${Date.now()}.pdf`).send(buildPdf(lines));
    }
    return res.status(400).json({ message: 'Supported formats: csv, pdf, json' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
