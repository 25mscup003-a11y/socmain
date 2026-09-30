const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const MemoryDetectionRule = require('../models/MemoryDetectionRule.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');

const CAPABILITY_ID = 29;
const MAX_PAGE_SIZE = 500;
const SORT_FIELDS = new Set(['createdAt', 'severity', 'riskScore', 'processName', 'hostname', 'status']);
const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const STATUSES = new Set(['open', 'investigating', 'resolved', 'false_positive', 'under_observation']);

const DEFAULT_RULES = [
  ['MEM-001', 'Sustained high memory', 'Host memory remains above the configured threshold.', 90, 300, 10, 'high', 90, 80, 'host'],
  ['MEM-002', 'Sudden memory spike', 'Host or process memory rises sharply inside a short window.', 25, 60, 2, 'high', 82, 78, 'process'],
  ['MEM-003', 'Process memory leak', 'Rolling samples show persistent process memory growth without recovery.', 30, 1800, 10, 'high', 86, 80, 'process'],
  ['MEM-004', 'Abnormal allocation burst', 'Allocation rate is abnormal relative to the process baseline.', 250, 60, 3, 'high', 75, 75, 'process'],
  ['MEM-005', 'Repeated memory-related crash', 'Repeated access violations, corruption or segmentation faults.', 3, 600, 3, 'high', 90, 84, 'process'],
  ['MEM-006', 'Writable and executable memory', 'A process exposes writable and executable memory regions.', 1, 60, 1, 'high', 88, 82, 'process'],
  ['MEM-007', 'Executable anonymous memory', 'Anonymous or deleted-file memory becomes executable.', 1, 60, 1, 'high', 86, 84, 'process'],
  ['MEM-008', 'Suspicious cross-process memory access', 'Untrusted process access targets another process.', 1, 120, 1, 'high', 78, 78, 'target_process'],
  ['MEM-009', 'Process-injection indicator', 'Correlated access, allocation, protection and thread evidence.', 3, 300, 2, 'critical', 92, 94, 'target_process'],
  ['MEM-010', 'LSASS memory access', 'Unauthorized process attempts to access LSASS memory.', 1, 120, 1, 'critical', 95, 96, 'target_process'],
  ['MEM-011', 'OOM or memory exhaustion', 'Host, container, service or application reports exhaustion.', 1, 300, 1, 'critical', 95, 92, 'host'],
  ['MEM-012', 'Agent tampering', 'A process attempts to patch, terminate or modify the SOC agent.', 1, 120, 1, 'critical', 95, 96, 'target_process'],
  ['MEM-013', 'Suspicious protection change', 'Writable memory transitions to executable protection.', 1, 120, 1, 'high', 86, 84, 'process'],
  ['MEM-014', 'Stack or heap corruption', 'OS or application telemetry reports stack or heap corruption.', 1, 300, 1, 'critical', 92, 94, 'process'],
  ['MEM-015', 'Fileless malware indicators', 'Executable memory correlates with script or unsigned-module evidence.', 2, 300, 2, 'critical', 88, 92, 'process'],
].map(([ruleId, name, description, threshold, timeWindowSeconds, minimumSampleCount, severity, confidence, riskScore, alertGrouping]) => ({
  ruleId, name, description, threshold, timeWindowSeconds, minimumSampleCount,
  severity, confidence, riskScore, alertGrouping, builtIn: true, enabled: true,
  operatingSystems: ['windows', 'linux', 'darwin', 'container'], cooldownSeconds: 300,
  suppressionEnabled: true,
}));

function escapeRegex(value) {
  return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function companyScope(req) {
  const companyId = req.user?.companyId;
  if (!companyId) throw Object.assign(new Error('Company scope is required'), { status: 400 });
  return {
    companyId,
    ...(req.user.role === 'department_admin' && req.user.departmentId
      ? { departmentId: req.user.departmentId }
      : {}),
  };
}

function capabilityFilter() {
  // capabilityIds contains legacy cross-capability tags, so the ID by itself is
  // not a safe boundary (old network/TI rows can also contain 29). Require both
  // the canonical tag and concrete memory-overflow evidence.
  return {
    $and: [
      { $or: [{ capabilityId: CAPABILITY_ID }, { capabilityIds: CAPABILITY_ID }] },
      {
        $or: [
          { source: 'memory_overflow_detector' },
          { category: /^memory$/i },
          { eventCategory: /^memory$/i },
          { subCategory: /memory[ _-]*(?:overflow|metrics?)/i },
          { eventType: /^memory(?:[._ -]|$)/i },
          { ruleId: /^(?:MEM-|MEMORY_OVERFLOW_)/i },
          { detectionRuleId: /^MEM-/i },
          { memoryMetricType: { $in: ['host', 'process'] } },
        ],
      },
    ],
  };
}

function ruleReadScope(req) {
  const base = { companyId: companyScope(req).companyId };
  if (req.user.role !== 'department_admin' || !req.user.departmentId) return base;
  return { ...base, $or: [{ departmentId: req.user.departmentId }, { departmentId: null }, { departmentId: { $exists: false } }] };
}

function metricFilter(kind) {
  const filter = { $or: [{ eventType: 'memory.metric' }, { memoryMetricType: { $in: ['host', 'process'] } }] };
  return kind ? { $and: [filter, { memoryMetricType: kind }] } : filter;
}

function detectionBase(req) {
  return { $and: [companyScope(req), capabilityFilter(), { $nor: [metricFilter()] }] };
}

function metricBase(req, kind) {
  return { $and: [companyScope(req), capabilityFilter(), metricFilter(kind), { isSynthetic: { $ne: true } }] };
}

function memoryActivityMetricBase(req) {
  return {
    $and: [
      companyScope(req),
      { $or: [{ capabilityId: 5 }, { capabilityIds: 5 }] },
      {
        $or: [
          { ruleId: 'MEM_TOP_CONSUMER' },
          { eventType: /^High Memory Process$/i },
          { userAction: 'memory_activity' },
        ],
      },
      { processMemoryPercent: { $type: 'number' } },
      { isSynthetic: { $ne: true } },
    ],
  };
}

function parseDate(value, field) {
  if (!value) return null;
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) throw Object.assign(new Error(`${field} must be an ISO-8601 date`), { status: 400 });
  return date;
}

function filteredQuery(req, base) {
  const clauses = [base];
  const from = parseDate(req.query.from, 'from');
  const to = parseDate(req.query.to, 'to');
  if (from || to) clauses.push({ createdAt: { ...(from && { $gte: from }), ...(to && { $lte: to }) } });
  else clauses.push({ createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } });
  if (req.query.severity && SEVERITIES.has(req.query.severity)) clauses.push({ severity: req.query.severity });
  if (req.query.status && STATUSES.has(req.query.status)) clauses.push({ status: req.query.status });
  if (req.query.host) clauses.push({ $or: [{ hostname: new RegExp(escapeRegex(req.query.host), 'i') }, { agentName: new RegExp(escapeRegex(req.query.host), 'i') }] });
  if (req.query.process) clauses.push({ processName: new RegExp(escapeRegex(req.query.process), 'i') });
  if (req.query.eventType) clauses.push({ eventType: req.query.eventType });
  if (req.query.operatingSystem) clauses.push({ osType: new RegExp(escapeRegex(req.query.operatingSystem), 'i') });
  if (req.query.rule) clauses.push({ $or: [{ ruleId: req.query.rule }, { detectionRuleId: req.query.rule }] });
  if (req.query.user) clauses.push({ username: new RegExp(escapeRegex(req.query.user), 'i') });
  if (req.query.agent) clauses.push({ agentId: req.query.agent });
  if (req.query.assignedTo && mongoose.isValidObjectId(req.query.assignedTo)) clauses.push({ assignedTo: req.query.assignedTo });
  const minRisk = Number(req.query.minRisk);
  const maxRisk = Number(req.query.maxRisk);
  if (Number.isFinite(minRisk) || Number.isFinite(maxRisk)) clauses.push({ riskScore: { ...(Number.isFinite(minRisk) && { $gte: minRisk }), ...(Number.isFinite(maxRisk) && { $lte: maxRisk }) } });
  if (req.query.search) {
    const rx = new RegExp(escapeRegex(String(req.query.search).slice(0, 160)), 'i');
    clauses.push({ $or: [{ description: rx }, { ruleId: rx }, { processName: rx }, { hostname: rx }, { agentName: rx }] });
  }
  return { $and: clauses };
}

function pageOptions(req) {
  const page = Math.max(1, Number.parseInt(req.query.page, 10) || 1);
  const limit = Math.min(MAX_PAGE_SIZE, Math.max(1, Number.parseInt(req.query.limit, 10) || 50));
  const sortBy = SORT_FIELDS.has(req.query.sortBy) ? req.query.sortBy : 'createdAt';
  const sortOrder = req.query.sortOrder === 'asc' ? 1 : -1;
  return { page, limit, sort: { [sortBy]: sortOrder, _id: -1 } };
}

async function listRows(req, base) {
  const query = filteredQuery(req, base);
  const { page, limit, sort } = pageOptions(req);
  const [events, total] = await Promise.all([
    Alert.find(query).sort(sort).skip((page - 1) * limit).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status lastSeen')
      .populate('assignedTo', 'name email').lean(),
    Alert.countDocuments(query),
  ]);
  return { events, alerts: events, total, page, limit, pages: Math.ceil(total / limit) };
}

async function ensureBuiltIns(req) {
  const scope = { companyId: companyScope(req).companyId, departmentId: null };
  await MemoryDetectionRule.bulkWrite(DEFAULT_RULES.map(rule => ({
    updateOne: {
      filter: { companyId: scope.companyId, ruleId: rule.ruleId },
      update: { $setOnInsert: { ...rule, ...scope, tenantId: req.user.tenantId || null } },
      upsert: true,
    },
  })), { ordered: false });
}

async function writeAudit(req, action, targetType, targetId, metadata = {}) {
  if (!req.user?.tenantId || !(req.user?.id || req.user?._id)) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId, companyId: req.user.companyId,
    actorId: req.user.id || req.user._id, action, targetType,
    targetId: String(targetId || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

function asyncRoute(handler) {
  return (req, res) => Promise.resolve(handler(req, res)).catch(error => {
    console.error('[memory-overflow]', error.message);
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Memory overflow request failed' });
  });
}

router.use(authenticate, requireAnalyst);

router.get('/overview', asyncRoute(async (req, res) => {
  const eventQuery = filteredQuery(req, detectionBase(req));
  const metricQuery = filteredQuery(req, metricBase(req));
  const activityMetricQuery = filteredQuery(req, memoryActivityMetricBase(req));
  const [alerts, total, severityRows, latestMetrics, activityMetrics, systems] = await Promise.all([
    Alert.find(eventQuery).sort({ createdAt: -1 }).limit(250).populate('systemId', 'name hostname ip os osType status lastSeen').populate('assignedTo', 'name email').lean(),
    Alert.countDocuments(eventQuery),
    Alert.aggregate([{ $match: eventQuery }, { $group: { _id: '$severity', count: { $sum: 1 } } }]),
    Alert.find(metricQuery).sort({ createdAt: -1 }).limit(500).lean(),
    Alert.aggregate([
      { $match: activityMetricQuery },
      { $sort: { createdAt: -1 } },
      { $group: { _id: { host: { $ifNull: ['$hostname', '$agentName'] }, pid: '$pid' }, row: { $first: '$$ROOT' } } },
      { $replaceRoot: { newRoot: '$row' } },
      { $limit: 500 },
    ]),
    require('../models/System.model').find(companyScope(req)).select('name hostname ip ipAddress os osType status lastSeen memoryMonitorEnabled').lean(),
  ]);
  const seen = new Set();
  const metrics = [...latestMetrics, ...activityMetrics.map(row => ({ ...row, memoryMetricType: row.memoryMetricType || 'process' }))].filter(row => {
    const key = `${row.systemId || row.agentId || row.hostname}:${row.memoryMetricType}:${row.processName || ''}:${row.pid || ''}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  });
  const severity = Object.fromEntries(severityRows.map(row => [row._id || 'low', row.count]));
  res.json({ capabilityId: CAPABILITY_ID, total, alerts, metrics, systems, severity, updatedAt: new Date().toISOString() });
}));

router.get('/metrics', asyncRoute(async (req, res) => res.json(await listRows(req, metricBase(req, req.query.kind)))));
router.get('/events', asyncRoute(async (req, res) => res.json(await listRows(req, detectionBase(req)))));
router.get('/alerts', asyncRoute(async (req, res) => res.json(await listRows(req, detectionBase(req)))));

router.get('/events/:id', asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
  const event = await Alert.findOne({ _id: req.params.id, $and: [detectionBase(req)] })
    .populate('systemId', 'name hostname ip os osType status lastSeen agentVersion')
    .populate('assignedTo', 'name email').populate('notes.user', 'name email').lean();
  if (!event) return res.status(404).json({ message: 'Memory event not found' });
  res.json({ event });
}));

router.get('/processes', asyncRoute(async (req, res) => {
  const rows = await Alert.find(filteredQuery(req, metricBase(req, 'process'))).sort({ createdAt: -1 }).limit(2000).lean();
  const seen = new Set();
  const processes = rows.filter(row => {
    const key = `${row.systemId || row.hostname}:${row.pid}:${row.processName}`;
    if (seen.has(key)) return false;
    seen.add(key); return true;
  }).slice(0, 200);
  res.json({ processes, total: processes.length });
}));

router.get('/hosts', asyncRoute(async (req, res) => {
  const rows = await Alert.find(filteredQuery(req, metricBase(req, 'host'))).sort({ createdAt: -1 }).limit(2000).lean();
  const seen = new Set();
  const hosts = rows.filter(row => {
    const key = String(row.systemId || row.hostname || row.agentId);
    if (seen.has(key)) return false;
    seen.add(key); return true;
  }).slice(0, 500);
  res.json({ hosts, total: hosts.length });
}));

router.get('/timeline', asyncRoute(async (req, res) => {
  const query = filteredQuery(req, detectionBase(req));
  const rows = await Alert.aggregate([
    { $match: query },
    { $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, total: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } }, high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } } } },
    { $sort: { _id: 1 } }, { $limit: 744 },
  ]);
  res.json({ timeline: rows.map(row => ({ timestamp: row._id, total: row.total, critical: row.critical, high: row.high })) });
}));

router.get('/severity-distribution', asyncRoute(async (req, res) => {
  const rows = await Alert.aggregate([{ $match: filteredQuery(req, detectionBase(req)) }, { $group: { _id: '$severity', count: { $sum: 1 } } }]);
  res.json({ distribution: Object.fromEntries(rows.map(row => [row._id || 'low', row.count])) });
}));

router.get('/top-processes', asyncRoute(async (req, res) => {
  const rows = await Alert.aggregate([
    { $match: filteredQuery(req, detectionBase(req)) },
    { $group: { _id: '$processName', alerts: { $sum: 1 }, maxRiskScore: { $max: '$riskScore' }, latestAt: { $max: '$createdAt' } } },
    { $match: { _id: { $nin: [null, ''] } } }, { $sort: { alerts: -1, maxRiskScore: -1 } }, { $limit: 25 },
  ]);
  res.json({ processes: rows.map(row => ({ processName: row._id, alerts: row.alerts, riskScore: row.maxRiskScore, latestAt: row.latestAt })) });
}));

router.get('/rules', asyncRoute(async (req, res) => {
  await ensureBuiltIns(req);
  const rules = await MemoryDetectionRule.find(ruleReadScope(req)).sort({ builtIn: -1, ruleId: 1 }).lean();
  res.json({ rules });
}));

router.post('/rules', requireManager, asyncRoute(async (req, res) => {
  const allowed = ['name', 'description', 'enabled', 'operatingSystems', 'hostGroupIds', 'processExclusions', 'allowlist', 'threshold', 'timeWindowSeconds', 'minimumSampleCount', 'cooldownSeconds', 'severity', 'confidence', 'riskScore', 'alertGrouping', 'suppressionEnabled', 'maintenanceWindows'];
  if (!String(req.body.name || '').trim()) return res.status(400).json({ message: 'Rule name is required' });
  const values = Object.fromEntries(allowed.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
  const ruleId = `MEM-CUSTOM-${new mongoose.Types.ObjectId().toString().slice(-8).toUpperCase()}`;
  const rule = await MemoryDetectionRule.create({ ...companyScope(req), tenantId: req.user.tenantId || null, ...values, name: String(values.name).trim(), ruleId, builtIn: false, createdBy: req.user.id || req.user._id, auditHistory: [{ action: 'created', actorId: req.user.id || req.user._id, changes: values }] });
  await writeAudit(req, 'memory.rule.created', 'MemoryDetectionRule', rule._id, { ruleId: rule.ruleId });
  req.app.get('io')?.to(`company:${rule.companyId}`).emit('memory:rule-updated', rule);
  res.status(201).json({ rule });
}));

router.patch('/rules/:id', requireManager, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule id' });
  const allowed = ['name', 'description', 'enabled', 'operatingSystems', 'hostGroupIds', 'processExclusions', 'allowlist', 'threshold', 'timeWindowSeconds', 'minimumSampleCount', 'cooldownSeconds', 'severity', 'confidence', 'riskScore', 'alertGrouping', 'suppressionEnabled', 'maintenanceWindows'];
  const changes = Object.fromEntries(allowed.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
  if (!Object.keys(changes).length) return res.status(400).json({ message: 'No supported fields supplied' });
  const rule = await MemoryDetectionRule.findOneAndUpdate(
    { _id: req.params.id, ...companyScope(req) },
    { $set: { ...changes, updatedBy: req.user.id || req.user._id }, $push: { auditHistory: { action: 'updated', actorId: req.user.id || req.user._id, changes } } },
    { new: true, runValidators: true },
  );
  if (!rule) return res.status(404).json({ message: 'Memory rule not found' });
  await writeAudit(req, 'memory.rule.updated', 'MemoryDetectionRule', rule._id, { fields: Object.keys(changes) });
  req.app.get('io')?.to(`company:${rule.companyId}`).emit('memory:rule-updated', rule);
  res.json({ rule });
}));

async function updateEvent(req, res, update, action) {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
  const actorId = req.user.id || req.user._id;
  const event = await Alert.findOneAndUpdate(
    { _id: req.params.id, $and: [detectionBase(req)] },
    { $set: update, $push: { auditHistory: { action, at: new Date(), actorId, metadata: { reason: String(req.body.reason || '').slice(0, 500) } } } },
    { new: true, runValidators: true },
  ).populate('assignedTo', 'name email');
  if (!event) return res.status(404).json({ message: 'Memory event not found' });
  await writeAudit(req, `memory.event.${action}`, 'Alert', event._id, { status: event.status });
  const io = req.app.get('io');
  io?.to(`company:${event.companyId}`).emit('alert:updated', event);
  io?.to(`company:${event.companyId}`).emit('memory:alert-updated', event);
  return res.json({ event });
}

router.post('/events/:id/acknowledge', asyncRoute((req, res) => updateEvent(req, res, { status: 'investigating', assignedTo: req.user.id || req.user._id }, 'acknowledged')));
router.post('/events/:id/assign', requireManager, asyncRoute((req, res) => {
  if (!mongoose.isValidObjectId(req.body.assignedTo)) return res.status(400).json({ message: 'Valid assignedTo is required' });
  return updateEvent(req, res, { assignedTo: req.body.assignedTo, status: 'investigating' }, 'assigned');
}));
router.post('/events/:id/resolve', requireManager, asyncRoute((req, res) => updateEvent(req, res, { status: 'resolved', resolvedAt: new Date() }, 'resolved')));

router.post('/events/:id/notes', asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
  const text = String(req.body.text || '').trim();
  if (!text) return res.status(400).json({ message: 'Note text is required' });
  if (text.length > 4000) return res.status(400).json({ message: 'Note text exceeds 4000 characters' });
  const actorId = req.user.id || req.user._id;
  const event = await Alert.findOneAndUpdate(
    { _id: req.params.id, $and: [detectionBase(req)] },
    {
      $push: {
        notes: { user: actorId, text, at: new Date() },
        auditHistory: { action: 'note_added', actorId, at: new Date(), metadata: {} },
      },
    },
    { new: true, runValidators: true },
  ).populate('assignedTo', 'name email').populate('notes.user', 'name email');
  if (!event) return res.status(404).json({ message: 'Memory event not found' });
  await writeAudit(req, 'memory.event.note_added', 'Alert', event._id);
  req.app.get('io')?.to(`company:${event.companyId}`).emit('memory:alert-updated', event);
  res.json({ event });
}));

router.post('/events/:id/create-incident', requireManager, asyncRoute(async (req, res) => {
  const event = await Alert.findOne({ _id: req.params.id, $and: [detectionBase(req)] });
  if (!event) return res.status(404).json({ message: 'Memory event not found' });
  let incident = event.incidentId ? await EdrIncident.findOne({ _id: event.incidentId, companyId: event.companyId }) : null;
  if (!incident) {
    incident = await EdrIncident.create({
      companyId: event.companyId, systemId: event.systemId, departmentId: event.departmentId,
      title: req.body.title || `Memory detection: ${event.ruleId}`,
      description: event.description, severity: event.severity, alertIds: [event._id],
      category: /inject|hollow|remote.thread/i.test(`${event.ruleId} ${event.eventType}`) ? 'process_injection' : 'other',
      confidenceScore: event.confidenceScore || 80, affectedEndpoint: event.hostname || event.agentName,
      affectedUser: event.username, agentId: event.agentId, agentName: event.agentName,
      mitreTechnique: event.mitreId, recommendedActions: [event.recommendedAction].filter(Boolean),
      sourceAlertCount: 1, firstEventAt: event.createdAt, lastEventAt: event.createdAt,
    });
    event.incidentId = incident._id;
    event.socCaseType = 'incident'; event.socCaseTypeSetAt = new Date();
    event.auditHistory.push({ action: 'incident_created', actorId: req.user.id || req.user._id, at: new Date(), metadata: { incidentId: incident._id } });
    await event.save();
  }
  await writeAudit(req, 'memory.incident.created', 'EdrIncident', incident._id, { alertId: event._id });
  req.app.get('io')?.to(`company:${event.companyId}`).emit('memory:incident-updated', incident);
  res.status(201).json({ incident });
}));

router.get('/export', asyncRoute(async (req, res) => {
  const format = String(req.query.format || 'json').toLowerCase();
  const rows = await Alert.find(filteredQuery(req, detectionBase(req))).sort({ createdAt: -1 }).limit(10000).lean();
  const safeRows = rows.map(row => ({
    timestamp: row.createdAt, severity: row.severity, status: row.status,
    hostname: row.hostname || row.agentName, processName: row.processName, pid: row.pid,
    eventType: row.eventType, ruleId: row.ruleId, riskScore: row.riskScore,
    description: row.description, assignedTo: row.assignedTo || null,
  }));
  if (format === 'json') return res.json({ events: safeRows, total: safeRows.length });
  if (format !== 'csv') return res.status(400).json({ message: 'format must be csv or json' });
  const protect = value => {
    let text = value == null ? '' : String(value);
    if (/^[=+\-@]/.test(text)) text = `'${text}`;
    return `"${text.replace(/"/g, '""')}"`;
  };
  const headers = Object.keys(safeRows[0] || { timestamp: '', severity: '', status: '', hostname: '', processName: '', pid: '', eventType: '', ruleId: '', riskScore: '', description: '', assignedTo: '' });
  const csv = [headers.join(','), ...safeRows.map(row => headers.map(key => protect(row[key])).join(','))].join('\n');
  res.type('text/csv').attachment(`memory-overflow-${Date.now()}.csv`).send(csv);
}));

router.post('/simulate', requireManager, asyncRoute(async (req, res) => {
  if (process.env.MEMORY_SIMULATION_ENABLED !== 'true') return res.status(403).json({ message: 'Memory simulation is disabled' });
  const scenarios = {
    gradual_leak: ['MEM_LEAK', 'memory.leak', 'high', 82], sudden_spike: ['MEM_SPIKE', 'memory.spike', 'high', 80],
    sustained_pressure: ['MEM_EXHAUSTION', 'memory.exhaustion', 'critical', 94], segmentation_fault: ['MEM_SEGMENTATION_FAULT', 'memory.segmentation_fault', 'high', 82],
    rwx_region: ['MEM_RWX_REGION', 'memory.rwx_region', 'high', 86], lsass_access: ['MEM_LSASS_ACCESS', 'memory.lsass_access', 'critical', 96],
    injection_correlation: ['MEM_PROCESS_INJECTION', 'memory.process_injection', 'critical', 96], container_oom: ['MEM_OOM_KILL', 'memory.oom_kill', 'critical', 92],
    agent_tampering: ['MEM_AGENT_TAMPERING', 'memory.agent_tampering', 'critical', 98],
  };
  const scenario = String(req.body.scenario || 'sudden_spike');
  if (!scenarios[scenario]) return res.status(400).json({ message: 'Unsupported simulation scenario' });
  const [ruleId, eventType, severity, riskScore] = scenarios[scenario];
  const event = await Alert.create({ ...companyScope(req), tenantId: req.user.tenantId || null, capabilityId: CAPABILITY_ID, capabilityIds: [5, CAPABILITY_ID], eventId: `memory-sim-${Date.now()}-${Math.random().toString(16).slice(2)}`, eventCategory: 'memory', category: 'memory', ruleId, type: ruleId, eventType, subCategory: 'Memory Overflow Detection', severity, riskScore, confidenceScore: 100, actionable: false, isSynthetic: true, dataOrigin: 'synthetic', hostname: 'SIMULATED-ENDPOINT', processName: 'simulation-process', description: `[SIMULATED] ${scenario.replace(/_/g, ' ')}`, source: 'memory_safe_simulator', userAction: 'memory_overflow_detected', rawEvent: { simulated: true, scenario }, expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000) });
  await writeAudit(req, 'memory.simulation.created', 'Alert', event._id, { scenario });
  req.app.get('io')?.to(`company:${event.companyId}`).emit('memory:simulated-alert', event);
  res.status(201).json({ event });
}));

module.exports = router;
