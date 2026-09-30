const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const TimeAnomalyPolicy = require('../models/TimeAnomalyPolicy.model');
const TimeAnomalyException = require('../models/TimeAnomalyException.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');

router.use(authenticate, requireAnalyst);

const DEFAULT_POLICY = Object.freeze({
  id: 'builtin-time-anomaly-baseline',
  name: 'Time-Based Behavioral Baseline',
  description: 'Detect correlated security activity outside the configured organization schedule.',
  enabled: true,
  priority: 100,
  systemIds: [],
  workingHoursStart: 8,
  workingHoursEnd: 20,
  weekendDays: [5, 6],
  holidays: [],
  timezone: 'endpoint-local',
  authFailureWindowSeconds: 300,
  authFailureThreshold: 5,
  anomalyRiskThreshold: 45,
  alertCooldownSeconds: 3600,
  baselineMinimumSamples: 20,
  exceptions: [],
  requireApprovalForResponse: true,
  builtIn: true,
});

function objectId(value, label) {
  if (!mongoose.Types.ObjectId.isValid(value)) {
    const error = new Error(`Invalid ${label}`);
    error.statusCode = 400;
    throw error;
  }
  return new mongoose.Types.ObjectId(String(value));
}

function userScope(req) {
  if (req.user.role === 'superadmin') {
    const companyId = req.query.companyId || req.body?.companyId || req.user.companyId;
    return { companyId: objectId(companyId, 'companyId') };
  }
  const resolved = scopeForUser(req.user, { departmentScoped: true });
  if (!resolved.companyId) {
    const error = new Error('Company scope required');
    error.statusCode = 403;
    throw error;
  }
  return Object.fromEntries(Object.entries(resolved).map(([key, value]) => (
    ['tenantId', 'companyId', 'departmentId', 'partnerId'].includes(key) && mongoose.Types.ObjectId.isValid(value)
      ? [key, new mongoose.Types.ObjectId(String(value))]
      : [key, value]
  )));
}

function boundedInt(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, Math.trunc(number))) : fallback;
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const since = req.query.from
    ? new Date(req.query.from)
    : new Date(until.getTime() - boundedInt(req.query.windowHours, defaultHours, 1, 2160) * 3600000);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    const error = new Error('Invalid time range');
    error.statusCode = 400;
    throw error;
  }
  return { since, until };
}

function rawTelemetry(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function first(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function padHour(value) {
  return `${String(boundedInt(value, 0, 0, 23)).padStart(2, '0')}:00`;
}

function csvCell(value) {
  return `"${String(value ?? '').replace(/"/g, '""')}"`;
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No time anomaly records found']);
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 30 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`;
  });
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (let id = 1; id < objects.length; id += 1) {
    offsets[id] = Buffer.byteLength(pdf);
    pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`;
  }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

function canonicalTimeEvent(row = {}, policy = DEFAULT_POLICY) {
  const raw = rawTelemetry(row);
  const timestamp = first(row.timestamp, row.eventTimestamp, row.createdAt, raw.timestamp);
  const parsedTime = timestamp ? new Date(timestamp) : null;
  const validTime = parsedTime && !Number.isNaN(parsedTime.getTime());
  const localHour = boundedInt(first(raw.local_hour, raw.localHour, validTime ? parsedTime.getUTCHours() : 0), 0, 0, 23);
  const weekday = boundedInt(first(raw.weekday, validTime ? (parsedTime.getUTCDay() + 6) % 7 : 0), 0, 0, 6);
  const start = boundedInt(first(raw.working_hours_start, raw.workingHoursStart, policy.workingHoursStart), 8, 0, 23);
  const end = boundedInt(first(raw.working_hours_end, raw.workingHoursEnd, policy.workingHoursEnd), 20, 0, 23);
  const insideHours = start === end || (start < end ? localHour >= start && localHour < end : localHour >= start || localHour < end);
  const weekendDays = Array.isArray(policy.weekendDays) ? policy.weekendDays : [5, 6];
  const ruleText = `${row.ruleId || ''} ${row.eventType || ''} ${row.description || ''}`;
  const weekend = raw.weekend === true || weekendDays.includes(weekday) || /weekend/i.test(ruleText);
  const holiday = raw.holiday === true || /holiday/i.test(ruleText);
  const afterHours = raw.after_hours === true || !insideHours || /after.hours|off.hours|late night|odd hours|night/i.test(ruleText);
  const anomalyType = first(row.anomalyType, raw.anomaly_type, raw.anomalyType, row.detectionRuleName, row.ruleName, row.eventType, row.ruleId, 'Time anomaly event');
  const riskScore = Math.min(100, Math.max(0, Number(first(row.riskScore, raw.risk_score, raw.riskScore, 0)) || 0));
  return {
    ...row,
    timestamp,
    anomalyType,
    actualTime: first(row.actualTime, raw.actual_time, raw.actualTime, validTime ? parsedTime.toISOString() : null),
    expectedTime: first(row.expectedTime, raw.expected_time, raw.expectedTime, `${padHour(start)}–${padHour(end)}`),
    timeWindow: first(row.timeWindow, raw.time_window, raw.timeWindow, afterHours ? 'Outside configured business hours' : 'Configured business hours'),
    baselineDiff: first(row.baselineDiff, raw.baseline_diff, raw.baselineDiff, raw.historical_frequency != null ? `Historical frequency ${raw.historical_frequency}%` : 'Not reported'),
    baselineConfidence: Number(first(row.baselineConfidence, raw.baseline_confidence, raw.baselineConfidence, 0)) || 0,
    riskScore,
    localHour,
    weekday,
    afterHours,
    weekend,
    holiday,
    sourceEvent: first(raw.source_event, row.sourceEvent),
    relatedEvents: first(row.relatedEvents, raw.related_events, []),
  };
}

function evidenceFilter() {
  return { $or: [{ capabilityId: 22 }, { capabilityIds: 22 }] };
}

function eventQuery(scope, since, until, extra = {}) {
  return { $and: [scope, { createdAt: { $gte: since, $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), extra] };
}

function systemOnline(system, now = Date.now()) {
  const seen = system.lastSeen ? new Date(system.lastSeen).getTime() : NaN;
  const status = String(system.status || '').toLowerCase();
  return Boolean(system.isActive !== false && (status === 'active' || status === 'online')
    && system.agentVersion && Number.isFinite(seen) && now - seen < 10 * 60 * 1000);
}

function namedCounts(events, picker, limit = 10) {
  const counts = new Map();
  events.forEach(event => {
    const name = String(picker(event) || '').trim();
    if (!name || /^unknown/i.test(name)) return;
    const current = counts.get(name) || { name, count: 0, critical: 0, high: 0, riskScore: 0, lastActivity: null };
    current.count += 1;
    if (event.severity === 'critical') current.critical += 1;
    if (event.severity === 'high') current.high += 1;
    current.riskScore = Math.max(current.riskScore, event.riskScore || 0);
    if (!current.lastActivity || new Date(event.timestamp) > new Date(current.lastActivity)) current.lastActivity = event.timestamp;
    counts.set(name, current);
  });
  return [...counts.values()].sort((left, right) => right.count - left.count).slice(0, limit);
}

function summarize(events, total, systems) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const categories = new Map();
  const hourly = Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0, critical: 0, high: 0, medium: 0, low: 0 }));
  const heatmap = Array.from({ length: 7 }, () => Array(12).fill(0));
  events.forEach(event => {
    const severity = String(event.severity || 'low').toLowerCase();
    if (bySeverity[severity] !== undefined) bySeverity[severity] += 1;
    const hour = boundedInt(event.localHour, 0, 0, 23);
    hourly[hour].count += 1;
    if (hourly[hour][severity] !== undefined) hourly[hour][severity] += 1;
    heatmap[boundedInt(event.weekday, 0, 0, 6)][Math.floor(hour / 2)] += 1;
    categories.set(event.anomalyType, (categories.get(event.anomalyType) || 0) + 1);
  });
  const topUsers = namedCounts(events, event => event.username || event.user || event.userName);
  const topHosts = namedCounts(events, event => event.hostname || event.agentName || event.systemId?.hostname || event.systemId?.name);
  const affectedUsers = new Set(events
    .map(event => String(event.username || event.user || event.userName || '').trim())
    .filter(name => name && !/^unknown/i.test(name)));
  const affectedHosts = new Set(events
    .map(event => String(event.hostname || event.agentName || event.systemId?.hostname || event.systemId?.name || '').trim())
    .filter(name => name && !/^unknown/i.test(name)));
  return {
    totalEvents: total,
    fetchedEvents: events.length,
    bySeverity,
    affectedUsers: affectedUsers.size,
    affectedHosts: affectedHosts.size,
    afterHours: events.filter(event => event.afterHours).length,
    weekend: events.filter(event => event.weekend).length,
    holidays: events.filter(event => event.holiday).length,
    baselineDeviations: events.filter(event => event.baselineDiff && event.baselineDiff !== 'Not reported').length,
    averageBaselineConfidence: events.length ? Math.round(events.reduce((sum, event) => sum + event.baselineConfidence, 0) / events.length) : 0,
    activeAgents: systems.filter(systemOnline).length,
    topUsers,
    topHosts,
    topCategories: [...categories.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count })),
    hourly,
    heatmap,
  };
}

async function effectivePolicy(scope) {
  return (await TimeAnomalyPolicy.findOne({ ...scope, enabled: true }).sort({ priority: 1, updatedAt: -1 }).lean()) || DEFAULT_POLICY;
}

async function validatePolicyTargets(scope, systemIds) {
  if (!Array.isArray(systemIds) || !systemIds.length) return;
  const uniqueIds = [...new Set(systemIds.map(String))];
  if (uniqueIds.some(id => !mongoose.Types.ObjectId.isValid(id))) {
    const error = new Error('One or more selected AJNAT agents are invalid');
    error.statusCode = 400;
    throw error;
  }
  const count = await System.countDocuments({
    companyId: scope.companyId,
    ...(scope.departmentId ? { departmentId: scope.departmentId } : {}),
    _id: { $in: uniqueIds.map(id => new mongoose.Types.ObjectId(id)) },
    isActive: true,
  });
  if (count !== uniqueIds.length) {
    const error = new Error('Selected AJNAT agent does not belong to this tenant or is inactive');
    error.statusCode = 403;
    throw error;
  }
}

async function auditException(req, action, exception) {
  const actorId = req.user?.id || req.user?._id;
  if (!req.user?.tenantId || !actorId) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId,
    companyId: req.user.companyId,
    actorId,
    action,
    targetType: 'TimeAnomalyException',
    targetId: String(exception?._id || ''),
    metadata: {
      name: exception?.name,
      reason: exception?.reason,
      systemIds: (exception?.systemIds || []).map(String),
      startsAt: exception?.startsAt,
      expiresAt: exception?.expiresAt,
    },
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

function exceptionInput(body = {}) {
  const name = String(body.name || '').trim().slice(0, 160);
  const reason = String(body.reason || '').trim().slice(0, 500);
  const startsAt = body.startsAt ? new Date(body.startsAt) : new Date();
  const expiresAt = new Date(body.expiresAt);
  const systemIds = Array.isArray(body.systemIds) ? [...new Set(body.systemIds.map(String))] : [];
  if (!name) throw Object.assign(new Error('Exception name is required'), { statusCode: 400 });
  if (!reason) throw Object.assign(new Error('Exception reason is required'), { statusCode: 400 });
  if (!systemIds.length) throw Object.assign(new Error('Select at least one AJNAT agent'), { statusCode: 400 });
  if (Number.isNaN(startsAt.getTime()) || Number.isNaN(expiresAt.getTime()) || expiresAt <= startsAt) {
    throw Object.assign(new Error('Exception expiry must be later than its start time'), { statusCode: 400 });
  }
  if (expiresAt.getTime() - startsAt.getTime() > 366 * 86400000) {
    throw Object.assign(new Error('Exception duration cannot exceed 366 days'), { statusCode: 400 });
  }
  return { name, reason, startsAt, expiresAt, systemIds, enabled: body.enabled !== false };
}

async function loadEvents(scope, since, until, { limit = 1000, skip = 0, extra = {} } = {}) {
  const policy = await effectivePolicy(scope);
  const [rows, total] = await Promise.all([
    Alert.find(eventQuery(scope, since, until, extra)).sort({ createdAt: -1 }).skip(skip).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean(),
    Alert.countDocuments(eventQuery(scope, since, until, extra)),
  ]);
  return { events: rows.map(row => canonicalTimeEvent(row, policy)), total, policy };
}

router.get('/overview', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const limit = boundedInt(req.query.limit, 1000, 1, 2000);
    const [{ events, total, policy }, systems] = await Promise.all([
      loadEvents(scope, since, until, { limit }),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}), isActive: true })
        .select('name hostname os osType status lastSeen agentVersion isActive').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const liveSystems = systems.map(system => ({ ...system, isOnline: systemOnline(system) }));
    res.json({ success: true, events, alerts: events, total, summary: summarize(events, total, liveSystems), systems: liveSystems, policy, since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Time anomaly overview unavailable' });
  }
});

async function eventsHandler(req, res) {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 168);
    const page = boundedInt(req.query.page, 1, 1, 100000);
    const limit = boundedInt(req.query.limit, 250, 1, 2000);
    const conditions = [];
    if (req.query.severity) conditions.push({ severity: String(req.query.severity).toLowerCase() });
    if (req.query.status) conditions.push({ status: String(req.query.status).toLowerCase() });
    if (req.query.search) {
      const escaped = String(req.query.search).slice(0, 200).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const search = new RegExp(escaped, 'i');
      conditions.push({ $or: [{ ruleId: search }, { eventType: search }, { username: search }, { hostname: search }, { agentName: search }, { description: search }] });
    }
    const { events, total } = await loadEvents(scope, since, until, { limit, skip: (page - 1) * limit, extra: conditions.length ? { $and: conditions } : {} });
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit), since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Time anomaly events unavailable' });
  }
}

router.get('/events', eventsHandler);
router.get('/alerts', eventsHandler);

router.get('/statistics', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const [{ events, total }, systems] = await Promise.all([
      loadEvents(scope, since, until, { limit: 2000 }),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}), isActive: true })
        .select('status lastSeen agentVersion isActive').lean(),
    ]);
    res.json({ statistics: summarize(events, total, systems), since, until });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/hourly-trends', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const { events, total } = await loadEvents(scope, since, until, { limit: 2000 });
    res.json({ hourly: summarize(events, total, []).hourly, since, until });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/heatmap', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 720);
    const { events, total } = await loadEvents(scope, since, until, { limit: 5000 });
    res.json({ heatmap: summarize(events, total, []).heatmap, since, until });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

async function actorBaseline(req, res, actorType) {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 720);
    const escaped = String(req.params.id || '').slice(0, 200).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const value = new RegExp(`^${escaped}$`, 'i');
    const extra = actorType === 'user'
      ? { $or: [{ username: value }, { user: value }, { userName: value }] }
      : { $or: [{ hostname: value }, { agentName: value }] };
    const { events, total } = await loadEvents(scope, since, until, { limit: 5000, extra });
    const hourly = Array(24).fill(0);
    events.forEach(event => { hourly[boundedInt(event.localHour, 0, 0, 23)] += 1; });
    const observedHours = hourly.map((count, hour) => ({ hour, count })).filter(item => item.count > 0);
    res.json({
      actorType,
      actor: req.params.id,
      total,
      observedHours,
      averageConfidence: events.length
        ? Math.round(events.reduce((sum, event) => sum + Number(event.baselineConfidence || 0), 0) / events.length)
        : 0,
      latest: events[0] || null,
      since,
      until,
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Time anomaly baseline unavailable' });
  }
}

router.get('/users/:id/baseline', (req, res) => actorBaseline(req, res, 'user'));
router.get('/hosts/:id/baseline', (req, res) => actorBaseline(req, res, 'host'));

router.get('/export/csv', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 720);
    const { events } = await loadEvents(scope, since, until, { limit: 10000 });
    const rows = [[
      'Timestamp', 'Tenant', 'User', 'Host', 'Event', 'Expected Time', 'Actual Time',
      'Deviation', 'Risk Score', 'Severity', 'Status', 'MITRE Technique',
    ]];
    events.forEach(event => rows.push([
      event.timestamp, event.tenantId || event.companyId, event.username || event.user,
      event.hostname || event.agentName || event.systemId?.hostname, event.anomalyType,
      event.expectedTime, event.actualTime, event.baselineDiff, event.riskScore,
      event.severity, event.status, event.mitreId || event.rawEvent?.mitre_id,
    ]));
    res.type('text/csv').attachment(`time-anomaly-${since.toISOString().slice(0, 10)}-${until.toISOString().slice(0, 10)}.csv`)
      .send(rows.map(row => row.map(csvCell).join(',')).join('\n'));
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Time anomaly CSV export unavailable' });
  }
});

router.get('/export/pdf', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 720);
    const { events, total } = await loadEvents(scope, since, until, { limit: 5000 });
    const summary = summarize(events, total, []);
    const lines = [
      'AJNAT EDR - TIME-BASED ANOMALY REPORT',
      `Generated: ${new Date().toISOString()}`,
      `Window: ${since.toISOString()} to ${until.toISOString()}`,
      `Total anomalies: ${total} | Critical: ${summary.bySeverity.critical} | High: ${summary.bySeverity.high}`,
      `Users affected: ${summary.affectedUsers} | Hosts affected: ${summary.affectedHosts}`,
      `After-hours: ${summary.afterHours} | Weekend: ${summary.weekend} | Holidays: ${summary.holidays}`,
      ' ',
      ...events.flatMap(event => [
        `${event.timestamp || ''} | ${String(event.severity || '').toUpperCase()} | Risk ${event.riskScore || 0} | ${event.anomalyType}`,
        `User: ${event.username || event.user || 'Not reported'} | Host: ${event.hostname || event.agentName || event.systemId?.hostname || 'Not reported'}`,
        `Expected: ${event.expectedTime || 'Not reported'} | Actual: ${event.actualTime || 'Not reported'} | ${event.baselineDiff || ''}`,
        `Reason: ${event.description || ''}`,
        ' ',
      ]),
    ];
    res.type('application/pdf').attachment(`time-anomaly-${since.toISOString().slice(0, 10)}-${until.toISOString().slice(0, 10)}.pdf`).send(buildPdf(lines));
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Time anomaly PDF export unavailable' });
  }
});

router.get('/policies', async (req, res) => {
  try {
    const policies = await TimeAnomalyPolicy.find(userScope(req)).sort({ priority: 1, updatedAt: -1 }).lean();
    res.json({ policies, defaultPolicy: DEFAULT_POLICY });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

function policyInput(body = {}, partial = false) {
  const input = {};
  const stringField = (key, max) => {
    if (body[key] !== undefined) input[key] = String(body[key] || '').trim().slice(0, max);
  };
  const integerField = (key, min, max) => {
    if (body[key] === undefined) return;
    const value = Number(body[key]);
    if (!Number.isInteger(value) || value < min || value > max) {
      const error = new Error(`${key} must be an integer from ${min} to ${max}`);
      error.statusCode = 400;
      throw error;
    }
    input[key] = value;
  };
  stringField('name', 160);
  stringField('description', 1000);
  stringField('timezone', 64);
  if (input.timezone && input.timezone !== 'endpoint-local') {
    try {
      new Intl.DateTimeFormat('en-US', { timeZone: input.timezone }).format();
    } catch {
      const error = new Error('timezone must be endpoint-local or a valid IANA timezone');
      error.statusCode = 400;
      throw error;
    }
  }
  ['enabled', 'requireApprovalForResponse'].forEach(key => {
    if (body[key] === undefined) return;
    if (typeof body[key] !== 'boolean') {
      const error = new Error(`${key} must be a boolean`);
      error.statusCode = 400;
      throw error;
    }
    input[key] = body[key];
  });
  integerField('priority', 1, 10000);
  integerField('workingHoursStart', 0, 23);
  integerField('workingHoursEnd', 0, 23);
  integerField('authFailureWindowSeconds', 30, 86400);
  integerField('authFailureThreshold', 3, 10000);
  integerField('anomalyRiskThreshold', 0, 100);
  integerField('alertCooldownSeconds', 300, 604800);
  integerField('baselineMinimumSamples', 1, 10000);
  if (body.systemIds !== undefined) {
    if (!Array.isArray(body.systemIds) || body.systemIds.length > 1000) {
      const error = new Error('systemIds must be an array with at most 1000 agents');
      error.statusCode = 400;
      throw error;
    }
    input.systemIds = [...new Set(body.systemIds.map(String))];
  }
  if (body.weekendDays !== undefined) {
    if (!Array.isArray(body.weekendDays)) {
      const error = new Error('weekendDays must be an array');
      error.statusCode = 400;
      throw error;
    }
    const days = body.weekendDays.map(Number);
    if (days.some(day => !Number.isInteger(day) || day < 0 || day > 6)) {
      const error = new Error('weekendDays values must be integers from 0 to 6');
      error.statusCode = 400;
      throw error;
    }
    input.weekendDays = [...new Set(days)];
  }
  if (body.holidays !== undefined) {
    if (!Array.isArray(body.holidays) || body.holidays.length > 366
        || body.holidays.some(value => !/^\d{4}-\d{2}-\d{2}$/.test(String(value)))) {
      const error = new Error('holidays must contain ISO dates (YYYY-MM-DD)');
      error.statusCode = 400;
      throw error;
    }
    input.holidays = [...new Set(body.holidays.map(String))];
  }
  if (body.exceptions !== undefined) {
    const allowedTypes = new Set(['user', 'service_account', 'host', 'process', 'ip', 'maintenance_window']);
    if (!Array.isArray(body.exceptions) || body.exceptions.length > 500) {
      const error = new Error('exceptions must be an array with at most 500 entries');
      error.statusCode = 400;
      throw error;
    }
    input.exceptions = body.exceptions.map(item => {
      const type = String(item?.type || '').trim();
      const value = String(item?.value || '').trim().slice(0, 500);
      if (!allowedTypes.has(type) || !value) {
        const error = new Error('Each exception requires a supported type and value');
        error.statusCode = 400;
        throw error;
      }
      const expiresAt = item?.expiresAt ? new Date(item.expiresAt) : null;
      if (expiresAt && Number.isNaN(expiresAt.getTime())) {
        const error = new Error('Exception expiry is invalid');
        error.statusCode = 400;
        throw error;
      }
      return { type, value, reason: String(item?.reason || '').trim().slice(0, 500), expiresAt };
    });
  }
  if (!partial && !String(input.name || '').trim()) {
    const error = new Error('Policy name is required');
    error.statusCode = 400;
    throw error;
  }
  return input;
}

router.post('/policies', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const input = policyInput(req.body);
    await validatePolicyTargets(scope, input.systemIds);
    const policy = await TimeAnomalyPolicy.create({ ...scope, ...input, createdBy: req.user.id, updatedBy: req.user.id });
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('time:policy-updated', { policy });
    res.status(201).json({ policy });
  } catch (error) { res.status(error.code === 11000 ? 409 : error.statusCode || 400).json({ message: error.code === 11000 ? 'A policy with this name already exists' : error.message }); }
});

router.put('/policies/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const input = policyInput(req.body, true);
    await validatePolicyTargets(scope, input.systemIds);
    const policy = await TimeAnomalyPolicy.findOneAndUpdate(
      { _id: objectId(req.params.id, 'policy id'), ...scope },
      { $set: { ...input, updatedBy: req.user.id } },
      { new: true, runValidators: true },
    ).lean();
    if (!policy) return res.status(404).json({ message: 'Policy not found' });
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('time:policy-updated', { policy });
    res.json({ policy });
  } catch (error) { res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.delete('/policies/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const policy = await TimeAnomalyPolicy.findOneAndDelete({ _id: objectId(req.params.id, 'policy id'), ...scope }).lean();
    if (!policy) return res.status(404).json({ message: 'Policy not found' });
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('time:policy-updated', { removedPolicyId: policy._id });
    res.json({ deleted: true });
  } catch (error) { res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.get('/exceptions', async (req, res) => {
  try {
    const exceptions = await TimeAnomalyException.find(userScope(req))
      .populate('systemIds', 'name hostname status isOnline lastSeen agentVersion')
      .sort({ expiresAt: -1, createdAt: -1 }).lean();
    res.json({ exceptions, serverTime: new Date().toISOString() });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/exceptions', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const input = exceptionInput(req.body);
    await validatePolicyTargets(scope, input.systemIds);
    const actorId = req.user.id || req.user._id;
    const exception = await TimeAnomalyException.create({ ...scope, ...input, createdBy: actorId, updatedBy: actorId });
    await auditException(req, 'time_anomaly.exception.created', exception);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('time:exception-updated', { action: 'created', exception });
    res.status(201).json({ exception });
  } catch (error) { res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.delete('/exceptions/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const exception = await TimeAnomalyException.findOneAndDelete({ _id: objectId(req.params.id, 'exception id'), ...scope }).lean();
    if (!exception) return res.status(404).json({ message: 'Approved exception not found' });
    await auditException(req, 'time_anomaly.exception.deleted', exception);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('time:exception-updated', { action: 'deleted', removedExceptionId: exception._id });
    res.json({ deleted: true });
  } catch (error) { res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.get('/:id', async (req, res) => {
  try {
    const scope = userScope(req);
    const row = await Alert.findOne({ _id: objectId(req.params.id, 'event id'), ...scope, ...evidenceFilter() })
      .populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean();
    if (!row) return res.status(404).json({ message: 'Time anomaly event not found' });
    res.json({ event: canonicalTimeEvent(row, await effectivePolicy(scope)) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

module.exports = router;
module.exports._private = { canonicalTimeEvent, evidenceFilter, summarize, systemOnline, policyInput, exceptionInput, buildPdf };
