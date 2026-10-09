const { REPORT_PERIOD_HOURS } = require('../utils/edrTimeRange');
const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');

router.use(authenticate, requireAnalyst);

const first = (...values) => values.find(value => value !== undefined && value !== null && value !== '');
const boundedInt = (value, fallback, min, max) => {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, Math.trunc(number))) : fallback;
};

function objectId(value, label = 'id') {
  if (!mongoose.Types.ObjectId.isValid(value)) throw Object.assign(new Error(`Invalid ${label}`), { statusCode: 400 });
  return new mongoose.Types.ObjectId(String(value));
}

function userScope(req) {
  if (req.user.role === 'superadmin') {
    const companyId = req.query.companyId || req.user.companyId;
    if (!companyId) throw Object.assign(new Error('companyId is required'), { statusCode: 400 });
    return { companyId: objectId(companyId, 'companyId') };
  }
  const resolved = scopeForUser(req.user, { departmentScoped: true });
  if (!resolved.companyId) throw Object.assign(new Error('Company scope required'), { statusCode: 403 });
  return Object.fromEntries(Object.entries(resolved).map(([key, value]) => (
    ['tenantId', 'companyId', 'departmentId', 'partnerId'].includes(key) && mongoose.Types.ObjectId.isValid(value)
      ? [key, new mongoose.Types.ObjectId(String(value))] : [key, value]
  )));
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const since = req.query.from ? new Date(req.query.from) : new Date(until.getTime() - boundedInt(req.query.windowHours, defaultHours, 1, 2160) * 3600000);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    throw Object.assign(new Error('Invalid time range'), { statusCode: 400 });
  }
  return { since, until };
}

function companyQuery(companyId, departmentId) {
  return {
    company: { $in: [String(companyId), objectId(companyId, 'companyId')] },
    ...(departmentId ? { departmentId: { $in: [String(departmentId), objectId(departmentId, 'departmentId')] } } : {}),
  };
}

function severity(value) {
  const normalized = String(value || 'info').toLowerCase();
  if (normalized === 'informational') return 'info';
  return ['critical', 'high', 'medium', 'low', 'info'].includes(normalized) ? normalized : 'info';
}

function safeTelemetry(value, depth = 0, key = '') {
  if (depth > 4 || value === undefined || value === null) return value;
  const normalizedKey = String(key).toLowerCase().replace(/-/g, '_');
  if (/password|passwd|secret|authorization|cookie|token|api_key|apikey|session/.test(normalizedKey)) return '[REDACTED]';
  if (Array.isArray(value)) return value.slice(0, 100).map(item => safeTelemetry(item, depth + 1, key));
  if (typeof value === 'object') return Object.fromEntries(Object.entries(value).slice(0, 200).map(([name, item]) => [name, safeTelemetry(item, depth + 1, name)]));
  if (typeof value === 'string') return value.replace(/(bearer\s+)[a-z0-9._~+/=-]+/ig, '$1[REDACTED]').slice(0, 16000);
  return value;
}

function calculateRisk(row) {
  const level = severity(row.severity);
  const text = `${row.attackType || ''} ${row.ruleId || ''} ${row.description || ''}`.toLowerCase();
  let score = { info: 5, low: 15, medium: 45, high: 70, critical: 90 }[level];
  if (row.blocked) score += 5;
  if (/sql injection|command injection|rce|xxe|ssrf|file inclusion|credential stuffing/.test(text)) score += 10;
  if (/tor|malicious|threat.intel/.test(text)) score += 10;
  return Math.min(100, Number(row.riskScore) || score);
}

function normalizeAlert(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const raw = root.raw && typeof root.raw === 'object' ? root.raw : {};
  const method = String(first(row.httpMethod, row.method, row.requestMethod, root.httpMethod, root.method, root.request_method, raw.method, 'UNKNOWN')).toUpperCase();
  const requestPath = first(row.requestPath, row.url, root.requestPath, root.request_path, root.url, root.path, raw.path);
  const statusCode = Number(first(row.statusCode, row.responseCode, root.statusCode, root.status_code, root.response_status, raw.status_code, 0)) || 0;
  const blocked = row.blocked === true || /block|deny|drop/.test(String(first(row.actionTaken, row.action, row.status, '')).toLowerCase());
  const event = {
    ...row,
    _id: String(row._id),
    sourceCollection: 'alerts',
    timestamp: first(row.eventTimestamp, row.createdAt, root.timestamp),
    eventType: first(row.eventType, root.eventType, root.event_type, 'api_request'),
    method, httpMethod: method,
    url: requestPath || 'Not reported', requestPath: requestPath || 'Not reported',
    statusCode,
    responseTimeMs: Number(first(row.responseTime, root.responseTimeMs, root.response_time_ms, root.response_time, raw.response_time_ms, 0)) || 0,
    requestSize: Number(first(row.requestSize, root.requestSize, root.request_size, raw.request_size, 0)) || 0,
    responseSize: Number(first(row.responseSize, root.responseSize, root.response_size, raw.response_size, 0)) || 0,
    clientIp: first(row.srcip, root.clientIp, root.source_ip, root.src_ip, raw.source_ip, 'Not reported'),
    sourceIp: first(row.srcip, root.clientIp, root.source_ip, root.src_ip, raw.source_ip, 'Not reported'),
    destinationIp: first(row.destip, root.destination_ip, root.dst_ip),
    destinationPort: first(row.destPort, row.port, root.target_port, root.destination_port),
    hostname: first(row.hostname, row.agentName, row.systemId?.hostname, root.hostname, 'Not reported'),
    apiVersion: first(row.apiVersion, root.apiVersion, root.api_version),
    authType: first(row.authType, root.authType, root.auth_type),
    wafProvider: first(row.wafProvider, root.wafProvider, root.waf_provider, root.provider, row.source),
    wafRuleId: first(row.wafRuleId, root.wafRuleId, root.waf_rule_id, row.ruleId),
    wafRuleName: first(row.wafRuleName, root.wafRuleName, root.waf_rule_name),
    matchedSignature: first(row.matchedSignature, root.matchedSignature, root.matched_signature, root.matched),
    attackType: first(row.attackType, root.attackType, root.attack_type, row.description, 'API telemetry'),
    blocked,
    severity: severity(row.severity),
    riskScore: calculateRisk({ ...row, blocked }),
    action: blocked ? 'blocked' : first(row.actionTaken, row.action, 'observed'),
    country: first(row.geoCountry, row.country, root.country, root.geo_country),
    city: first(row.geoCity, root.city, root.geo_city),
    region: first(row.geoRegion, root.region, root.geo_region),
    asn: first(row.asn, root.asn, root.geo_asn),
    isp: first(row.geoISP, root.isp, root.geo_isp),
    processName: first(row.processName, root.processName, root.process_name),
    pid: first(row.pid, root.pid),
    parentProcess: first(row.parentProcessName, root.parentProcess, root.parent_process_name),
    backendService: first(row.backendService, root.backendService, root.backend_service),
    backendError: first(row.backendError, root.backendError, root.backend_error),
    requestHeaders: safeTelemetry(first(row.requestHeaders, root.requestHeaders, root.request_headers, {})),
    requestPayload: safeTelemetry(first(row.requestPayload, root.requestPayload, root.request_payload)),
    responseHeaders: safeTelemetry(first(row.responseHeaders, root.responseHeaders, root.response_headers, {})),
    responsePayload: safeTelemetry(first(row.responsePayload, root.responsePayload, root.response_payload)),
    rawEvent: undefined,
  };
  delete event.full_log;
  delete event.raw;
  delete event.rawEvent;
  delete event.commandLine;
  delete event.processCmdline;
  return event;
}

function normalizeWaf(row = {}) {
  const blocked = row.blocked !== false;
  const normalizedSeverity = severity(row.severity || (blocked ? 'high' : 'low'));
  return {
    _id: String(row._id), sourceCollection: 'waf_events', timestamp: row.ts || row.receivedAt,
    createdAt: row.ts || row.receivedAt, eventType: 'waf_api_request', capabilityId: 20, capabilityIds: [20],
    companyId: row.company, systemId: row.systemId, hostname: row.hostname || 'Not reported',
    method: String(row.method || 'UNKNOWN').toUpperCase(), httpMethod: String(row.method || 'UNKNOWN').toUpperCase(),
    url: row.requestPath || 'Not reported', requestPath: row.requestPath || 'Not reported', statusCode: Number(row.statusCode || 0),
    responseTimeMs: Number(row.responseTimeMs || 0), requestSize: Number(row.requestSize || 0), responseSize: Number(row.responseSize || 0),
    clientIp: row.ip || 'Not reported', sourceIp: row.ip || 'Not reported', attackType: row.attackType || 'WAF event',
    ruleId: row.ruleId, wafRuleId: row.ruleId, wafProvider: row.provider || 'AJNAT WAF', matchedSignature: row.matched,
    blocked, action: row.action || (blocked ? 'blocked' : 'observed'), severity: normalizedSeverity,
    riskScore: calculateRisk({ ...row, blocked, severity: normalizedSeverity }),
    country: first(row.country, row.geoCountry), city: first(row.city, row.geoCity), region: first(row.region, row.geoRegion),
    asn: row.asn, isp: row.isp, source: row.source || 'waf', status: blocked ? 'blocked' : 'observed',
  };
}

function alertEvidenceFilter() {
  return { $or: [{ capabilityId: 20 }, { capabilityIds: 20 }] };
}

function categoryMatches(event, category) {
  if (!category || category === 'all') return true;
  const text = `${event.attackType || ''} ${event.ruleId || ''} ${event.description || ''} ${event.authType || ''}`.toLowerCase();
  const patterns = {
    attacks: /sql injection|sqli|xss|command injection|rce|xxe|ssrf|path traversal|file inclusion|attack/,
    authentication: /authentication|api key|jwt|oauth|bearer|token|unauthori[sz]ed|forbidden|credential|brute force/,
    performance: /latency|slow|timeout|backend|5\d\d|service down/,
    rate_limit: /rate limit|rate abuse|http flood|429/,
    payload: /payload|pii|credit card|base64|json|xml|data leak/,
    blocked: /block|deny|drop/,
  };
  return patterns[category]?.test(text) || (category === 'blocked' && event.blocked === true);
}

async function loadEvents(scope, since, until, options = {}) {
  const db = mongoose.connection.db;
  if (!db) throw Object.assign(new Error('Database unavailable'), { statusCode: 503 });
  const limit = boundedInt(options.limit, 1000, 1, 10000);
  const fetchLimit = Math.min(10000, limit + boundedInt(options.skip, 0, 0, 100000));
  const alertQuery = { $and: [scope, { createdAt: { $gte: since, $lte: until } }, { isSynthetic: { $ne: true } }, alertEvidenceFilter()] };
  const wafQuery = { ...companyQuery(scope.companyId, scope.departmentId), ts: { $gte: since, $lte: until } };
  const [alerts, wafRows, alertTotal, wafTotal] = await Promise.all([
    Alert.find(alertQuery).sort({ createdAt: -1 }).limit(fetchLimit).populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean(),
    db.collection('waf_events').find(wafQuery).sort({ ts: -1 }).limit(fetchLimit).toArray(),
    Alert.countDocuments(alertQuery), db.collection('waf_events').countDocuments(wafQuery),
  ]);
  let events = [...alerts.map(normalizeAlert), ...wafRows.map(normalizeWaf)]
    .filter(event => categoryMatches(event, options.category))
    .sort((a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0));
  if (options.search) {
    const term = String(options.search).toLowerCase();
    events = events.filter(event => `${event.url} ${event.method} ${event.sourceIp} ${event.hostname} ${event.attackType} ${event.wafProvider}`.toLowerCase().includes(term));
  }
  if (options.severity) events = events.filter(event => event.severity === String(options.severity).toLowerCase());
  const filteredTotal = options.category && options.category !== 'all' || options.search || options.severity ? events.length : alertTotal + wafTotal;
  return { events: events.slice(options.skip || 0, (options.skip || 0) + limit), total: filteredTotal };
}

function summarize(events, total, systems = []) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const endpoints = new Set(); const ips = new Set(); const sessions = new Set();
  let successful = 0; let failed = 0; let blocked = 0; let latencyTotal = 0; let latencyCount = 0;
  events.forEach(event => {
    bySeverity[event.severity] = (bySeverity[event.severity] || 0) + 1;
    if (event.url && event.url !== 'Not reported') endpoints.add(`${event.method}:${event.url}`);
    if (event.sourceIp && event.sourceIp !== 'Not reported') ips.add(event.sourceIp);
    if (event.connectionId || event.sessionId) sessions.add(String(event.connectionId || event.sessionId));
    if (event.statusCode >= 200 && event.statusCode < 400) successful += 1;
    if (event.statusCode >= 400 || ['high', 'critical'].includes(event.severity)) failed += 1;
    if (event.blocked) blocked += 1;
    if (event.responseTimeMs > 0) { latencyTotal += event.responseTimeMs; latencyCount += 1; }
  });
  return {
    totalApiCalls: total, successfulCalls: successful, failedCalls: failed, activeApis: endpoints.size,
    wafBlockedRequests: blocked, criticalThreats: bySeverity.critical || 0,
    averageResponseTimeMs: latencyCount ? Math.round(latencyTotal / latencyCount) : null,
    activeSessions: sessions.size, uniqueSourceIps: ips.size, bySeverity,
    monitoredSystems: systems.length, onlineSystems: systems.filter(system => system.isOnline).length,
  };
}

function systemOnline(system, now = Date.now()) {
  const seen = new Date(system.lastSeen || 0).getTime();
  return system.isActive !== false && String(system.status || '').toLowerCase() === 'active' && Number.isFinite(seen) && now - seen < 10 * 60 * 1000;
}

router.get('/overview', async (req, res) => {
  try {
    const scope = userScope(req); const { since, until } = timeRange(req);
    const [{ events, total }, systems] = await Promise.all([
      loadEvents(scope, since, until, { limit: boundedInt(req.query.limit, 2000, 1, 5000) }),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}), isActive: true })
        .select('name hostname os osType status lastSeen agentVersion isActive').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const liveSystems = systems.map(system => ({ ...system, isOnline: systemOnline(system) }));
    return res.json({ success: true, events, alerts: events, total, summary: summarize(events, total, liveSystems), systems: liveSystems, since, until });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'API monitoring overview unavailable' }); }
});

router.get('/events', async (req, res) => {
  try {
    const scope = userScope(req); const { since, until } = timeRange(req, 168);
    const page = boundedInt(req.query.page, 1, 1, 100000); const limit = boundedInt(req.query.limit, 250, 1, 2000);
    const result = await loadEvents(scope, since, until, { limit, skip: (page - 1) * limit, category: req.query.category, search: req.query.search, severity: req.query.severity });
    return res.json({ ...result, alerts: result.events, page, limit, pages: Math.ceil(result.total / limit), since, until });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/statistics', async (req, res) => {
  try {
    const scope = userScope(req); const { since, until } = timeRange(req);
    const { events, total } = await loadEvents(scope, since, until, { limit: 10000 });
    return res.json({ statistics: summarize(events, total), since, until });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/report', async (req, res) => {
  try {
    const period = String(req.query.period || '90days');
    if (!Object.prototype.hasOwnProperty.call(REPORT_PERIOD_HOURS, period)) return res.status(400).json({ message: 'Invalid report period' });
    const hours = REPORT_PERIOD_HOURS[period];
    const scope = userScope(req); const until = new Date(); const since = new Date(until.getTime() - hours * 3600000);
    const { events, total } = await loadEvents(scope, since, until, { limit: 10000, category: req.query.category });
    const summary = summarize(events, total);
    return res.json({ success: true, source: 'backend', capabilityId: 20, period: req.query.period || '90days', category: req.query.category || 'all', windowHours: hours, since, until, total, fetchedCount: events.length, truncated: total > events.length, stats: { bySeverity: summary.bySeverity }, summary, alerts: events });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    const scope = userScope(req); const id = objectId(req.params.id, 'eventId');
    const alert = await Alert.findOne({ ...scope, _id: id, ...alertEvidenceFilter() }).populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean();
    if (alert) return res.json({ event: normalizeAlert(alert) });
    const waf = await mongoose.connection.db.collection('waf_events').findOne({ _id: id, ...companyQuery(scope.companyId, scope.departmentId) });
    if (!waf) return res.status(404).json({ message: 'API event not found' });
    return res.json({ event: normalizeWaf(waf) });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/timeline/:id', async (req, res) => {
  try {
    const scope = userScope(req); const id = objectId(req.params.id, 'eventId');
    const alert = await Alert.findOne({ ...scope, _id: id, ...alertEvidenceFilter() }).lean();
    const waf = alert ? null : await mongoose.connection.db.collection('waf_events').findOne({ _id: id, ...companyQuery(scope.companyId, scope.departmentId) });
    if (!alert && !waf) return res.status(404).json({ message: 'API event not found' });
    const event = alert ? normalizeAlert(alert) : normalizeWaf(waf);
    const center = new Date(event.timestamp); const since = new Date(center.getTime() - 5 * 60000); const until = new Date(center.getTime() + 5 * 60000);
    const { events } = await loadEvents(scope, since, until, { limit: 250 });
    return res.json({ event, timeline: events.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp)) });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router._private = { normalizeAlert, normalizeWaf, summarize, safeTelemetry, categoryMatches, calculateRisk };
module.exports = router;
