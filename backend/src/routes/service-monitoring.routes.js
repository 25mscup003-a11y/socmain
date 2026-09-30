const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const ServiceMonitoringPolicy = require('../models/ServiceMonitoringPolicy.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');

router.use(authenticate, requireAnalyst);

const SECURITY_SERVICE_RE = /ajnat|soc-agent|windefend|sense|msmpeng|securityhealth|mpssvc|firewall|clamd|clamav|auditd|rsyslog|syslog-ng|suricata|zeek|wazuh|elastic-agent|falcon|crowdstrike|sentinel|backup|veeam/i;
const INVENTORY_RULE_RE = /^PROC_ASSET_INVENTORY$/i;

const BUILT_IN_POLICIES = Object.freeze([
  { id: 'builtin-security-service-protection', name: 'Critical Security Service Protection', enabled: true, eventTypes: ['SERVICE_STOPPED', 'SERVICE_FAILED', 'SERVICE_DELETED'], severity: 'critical', riskScore: 90, requireApproval: true, responseActions: ['alert', 'restart_service'] },
  { id: 'builtin-unauthorized-service', name: 'Unauthorized Service Creation', enabled: true, eventTypes: ['SERVICE_CREATED'], severity: 'high', riskScore: 70, requireApproval: true, responseActions: ['alert', 'collect_evidence'] },
  { id: 'builtin-service-binary-integrity', name: 'Service Binary Integrity', enabled: true, eventTypes: ['SERVICE_CONFIG_CHANGED'], severity: 'high', riskScore: 75, requireApproval: true, responseActions: ['alert', 'quarantine_file'] },
]);

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
    const companyId = req.query.companyId || req.body?.companyId;
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
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, Math.trunc(parsed))) : fallback;
}

function first(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function rawTelemetry(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function normalizeState(value) {
  const state = String(value || 'UNKNOWN').trim().toUpperCase().replace(/[ -]+/g, '_');
  return ({ ACTIVE: 'RUNNING', DEAD: 'STOPPED', INACTIVE: 'STOPPED' })[state] || state;
}

function canonicalServiceEvent(row = {}) {
  const raw = rawTelemetry(row);
  const item = row.inventoryItem || raw.inventory_item || raw.inventoryItem || {};
  const oldItem = row.oldInventoryItem || raw.old_inventory_item || raw.oldInventoryItem || {};
  const serviceName = first(row.serviceName, raw.service_name, raw.serviceName, row.inventoryName, raw.inventory_name, item.name, item.id);
  const serviceCurrentStatus = normalizeState(first(row.serviceCurrentStatus, raw.current_status, raw.serviceCurrentStatus, item.sub_status, item.status, item.state));
  const servicePreviousStatus = normalizeState(first(row.servicePreviousStatus, raw.previous_status, raw.servicePreviousStatus, oldItem.sub_status, oldItem.status, oldItem.state));
  const serviceEventType = first(row.serviceEventType, raw.service_event_type, raw.serviceEventType, /^SERVICE_/i.test(String(row.eventType || '')) ? row.eventType : undefined, row.ruleId);
  return {
    ...row,
    serviceName,
    serviceDisplayName: first(row.serviceDisplayName, raw.service_display_name, raw.serviceDisplayName, item.display_name, item.description, serviceName),
    serviceEventType,
    servicePreviousStatus,
    serviceCurrentStatus,
    serviceStartupType: first(row.serviceStartupType, raw.startup_type, raw.serviceStartupType, item.start_type, item.unit_file_state),
    serviceAccount: first(row.serviceAccount, raw.service_account, raw.serviceAccount, item.username, item.user),
    serviceBinaryPath: first(row.serviceBinaryPath, raw.service_binary_path, raw.serviceBinaryPath, item.binary_path, item.exec_start),
    serviceBinarySha256: first(row.serviceBinarySha256, raw.service_binary_sha256, raw.serviceBinarySha256),
    serviceSignatureStatus: first(row.serviceSignatureStatus, raw.service_signature_status, raw.serviceSignatureStatus),
    servicePublisher: first(row.servicePublisher, raw.service_publisher, raw.servicePublisher),
    servicePid: first(row.servicePid, raw.service_pid, raw.servicePid, item.pid, item.main_pid),
    serviceRestartCount: Number(first(row.serviceRestartCount, raw.service_restart_count, raw.serviceRestartCount, item.restart_count, 0)) || 0,
    serviceSecurityCritical: row.serviceSecurityCritical === true || raw.security_service === true || SECURITY_SERVICE_RE.test(String(serviceName || '')),
    riskScore: Number(first(row.riskScore, raw.risk_score, raw.riskScore, 0)) || 0,
    timestamp: first(row.timestamp, row.createdAt, raw.timestamp),
  };
}

function evidenceFilter() {
  return {
    // Capability 24 is exclusively Service Monitoring. Keeping this query on
    // the existing capability/time indexes avoids a costly multi-planner OR
    // across every service evidence field on high-volume alert collections.
    $or: [{ capabilityId: 24 }, { capabilityIds: 24 }],
  };
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const hours = boundedInt(req.query.windowHours, defaultHours, 1, 2160);
  const since = req.query.from ? new Date(req.query.from) : new Date(until.getTime() - hours * 3600000);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    const error = new Error('Invalid time range');
    error.statusCode = 400;
    throw error;
  }
  return { since, until };
}

function eventQuery(scope, since, until, extra = {}) {
  return { $and: [scope, { createdAt: { $gte: since, $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), extra] };
}

function endpointKey(row = {}) {
  return String(row.systemId?._id || row.systemId || row.endpointId || row.agentId || row.agentName || row.hostname || 'unknown');
}

function mergeDefined(base, update) {
  return Object.fromEntries(Object.entries({ ...base, ...update }).filter(([, value]) => value !== undefined && value !== null && value !== ''));
}

async function loadEvents(scope, since, until, limit = 500, extra = {}) {
  const query = eventQuery(scope, since, until, {
    ruleId: { $not: INVENTORY_RULE_RE },
    ...extra,
  });
  const [rows, total] = await Promise.all([
    Alert.find(query).sort({ createdAt: -1 }).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion')
      .lean(),
    Alert.countDocuments(query),
  ]);
  return { events: rows.map(canonicalServiceEvent), total };
}

async function loadCurrentServices(scope, until) {
  const snapshots = await Alert.find({
    $and: [scope, { createdAt: { $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), {
      inventoryType: 'service', ruleId: INVENTORY_RULE_RE,
    }],
  }).sort({ createdAt: -1 }).limit(2500)
    .select('_id tenantId companyId departmentId systemId endpointId agentId agentName hostname osType createdAt inventoryItems inventoryBatchIndex inventoryBatchCount rawEvent')
    .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion')
    .lean();

  const latestBatch = new Map();
  const endpointSnapshotAt = new Map();
  const selectedSnapshotTimes = [];
  const services = new Map();
  for (const snapshot of snapshots) {
    const endpoint = endpointKey(snapshot);
    const batch = Number(snapshot.inventoryBatchIndex || snapshot.rawEvent?.inventory_batch_index || 1);
    if (latestBatch.has(`${endpoint}:${batch}`)) continue;
    latestBatch.set(`${endpoint}:${batch}`, true);
    const snapshotAt = new Date(snapshot.createdAt).getTime();
    if (Number.isFinite(snapshotAt)) {
      selectedSnapshotTimes.push(snapshotAt);
      endpointSnapshotAt.set(endpoint, Math.max(endpointSnapshotAt.get(endpoint) || 0, snapshotAt));
    }
    const items = snapshot.inventoryItems || snapshot.rawEvent?.inventory_items || [];
    for (const item of Array.isArray(items) ? items : []) {
      const row = canonicalServiceEvent({
        ...snapshot,
        inventoryItem: item,
        serviceName: item.name || item.id,
        serviceEventType: 'SERVICE_INVENTORY',
        serviceCurrentStatus: item.sub_status || item.status || item.state,
      });
      if (row.serviceName) services.set(`${endpoint}:${String(row.serviceName).toLowerCase()}`, row);
    }
  }


  // Inventory is emitted when the collector starts; lifecycle events keep that
  // snapshot current between agent restarts without forcing expensive polling.
  const lifecycleSince = selectedSnapshotTimes.length
    ? new Date(Math.min(...selectedSnapshotTimes))
    : new Date(until.getTime() - (30 * 86400000));
  const lifecycleRows = await Alert.find({
    $and: [scope, { createdAt: { $gte: lifecycleSince, $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), {
      $or: [
        { serviceEventType: /^SERVICE_/i },
        { ruleId: /^SERVICE_/i },
        { inventoryType: 'service', ruleId: /^PROC_ASSET_(?:CREATED|REMOVED|CHANGED)$/i },
      ],
    }],
  }).sort({ createdAt: 1 }).limit(10000)
    .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion')
    .lean();

  for (const lifecycleRow of lifecycleRows) {
    const row = canonicalServiceEvent(lifecycleRow);
    if (!row.serviceName) continue;
    const endpoint = endpointKey(row);
    const key = `${endpoint}:${String(row.serviceName).toLowerCase()}`;
    const current = services.get(key);
    const eventAt = new Date(row.timestamp || row.createdAt).getTime();
    const currentAt = new Date(current?.timestamp || current?.createdAt || 0).getTime();
    const snapshotAt = endpointSnapshotAt.get(endpoint) || 0;
    if (!Number.isFinite(eventAt) || eventAt <= (current ? currentAt : snapshotAt)) continue;

    const type = String(row.serviceEventType || row.ruleId || '').toUpperCase();
    if (type === 'SERVICE_DELETED' || (type === 'PROC_ASSET_REMOVED' && row.inventoryType === 'service')) {
      services.delete(key);
      continue;
    }
    services.set(key, mergeDefined(current || {}, row));
  }
  return [...services.values()];
}

function summarize(events, services, systems) {
  const status = { running: 0, stopped: 0, failed: 0, unknown: 0 };
  services.forEach(service => {
    const state = normalizeState(service.serviceCurrentStatus).toLowerCase();
    if (state === 'running') status.running += 1;
    else if (state === 'stopped') status.stopped += 1;
    else if (state === 'failed') status.failed += 1;
    else status.unknown += 1;
  });
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  events.forEach(event => { const key = String(event.severity || 'low').toLowerCase(); if (bySeverity[key] !== undefined) bySeverity[key] += 1; });
  const created = events.filter(event => /SERVICE_CREATED/i.test(String(event.serviceEventType || event.ruleId))).length;
  const changes = events.filter(event => /SERVICE_(?:CONFIG_CHANGED|CREATED|DELETED|STARTED|STOPPED|RESTARTED|FAILED)|PROC_ASSET_(?:CREATED|REMOVED|CHANGED)/i.test(String(event.serviceEventType || event.ruleId))).length;
  const securityIssues = events.filter(event => event.serviceSecurityCritical && /STOPPED|FAILED|DELETED|CONFIG_CHANGED/i.test(String(event.serviceEventType || event.ruleId))).length;
  const healthScore = Math.max(0, Math.round(100 - (status.failed * 8) - (securityIssues * 12) - (bySeverity.critical * 6) - (bySeverity.high * 3)));
  return {
    totalServices: services.length, ...status, newServices24h: created, serviceChanges24h: changes,
    criticalServices: services.filter(service => service.serviceSecurityCritical).length,
    criticalAlerts: bySeverity.critical, highAlerts: bySeverity.high,
    endpointsReporting: new Set(services.map(service => String(service.systemId?._id || service.endpointId || service.agentId || service.agentName)).filter(Boolean)).size,
    activeAgents: systems.filter(system => system.status === 'active' || system.isOnline || system.agentOk).length,
    healthScore, bySeverity,
  };
}

router.get('/overview', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const limit = boundedInt(req.query.limit, 500, 1, 2000);
    const [{ events, total }, services, systems] = await Promise.all([
      loadEvents(scope, since, until, limit),
      loadCurrentServices(scope, until),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}) })
        .select('name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const summary = summarize(events, services, systems);
    const timeline = Array.from({ length: 24 }, (_, index) => ({ hour: index, count: 0 }));
    const startMs = since.getTime();
    const width = Math.max(1, until.getTime() - startMs);
    events.forEach(event => {
      const eventMs = new Date(event.timestamp || event.createdAt).getTime();
      const bucket = Math.min(23, Math.max(0, Math.floor(((eventMs - startMs) / width) * 24)));
      if (Number.isFinite(bucket)) timeline[bucket].count += 1;
    });
    const topMap = new Map();
    events.forEach(event => { if (event.serviceName) topMap.set(event.serviceName, (topMap.get(event.serviceName) || 0) + 1); });
    const topServices = [...topMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([name, count]) => ({ name, count }));
    const criticalServices = services.filter(service => service.serviceSecurityCritical).slice(0, 25);
    res.json({ success: true, since, until, total, events, alerts: events, services, systems, summary, timeline, topServices, criticalServices });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service monitoring overview unavailable' });
  }
});

async function eventsHandler(req, res) {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 168);
    const limit = boundedInt(req.query.limit, 250, 1, 2000);
    const page = boundedInt(req.query.page, 1, 1, 100000);
    const conditions = [];
    if (req.query.severity) conditions.push({ severity: String(req.query.severity).toLowerCase() });
    if (req.query.eventType) conditions.push({ $or: [{ serviceEventType: req.query.eventType }, { eventType: req.query.eventType }, { ruleId: req.query.eventType }] });
    if (req.query.search) {
      const escaped = String(req.query.search).slice(0, 200).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const search = new RegExp(escaped, 'i');
      conditions.push({ $or: [{ serviceName: search }, { hostname: search }, { agentName: search }, { username: search }, { serviceAccount: search }, { serviceBinaryPath: search }, { description: search }] });
    }
    const query = eventQuery(scope, since, until, { ruleId: { $not: INVENTORY_RULE_RE }, ...(conditions.length ? { $and: conditions } : {}) });
    const [rows, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion').lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events: rows.map(canonicalServiceEvent), total, page, limit, since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service events unavailable' });
  }
}

router.get('/events', eventsHandler);
router.get('/alerts', eventsHandler);

router.get('/services', async (req, res) => {
  try {
    const scope = userScope(req);
    const { until } = timeRange(req);
    const services = await loadCurrentServices(scope, until);
    res.json({ services, total: services.length });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service inventory unavailable' });
  }
});

router.get('/health', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const [{ events }, services, systems] = await Promise.all([
      loadEvents(scope, since, until, 2000),
      loadCurrentServices(scope, until),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}) }).select('status isOnline agentOk').lean(),
    ]);
    res.json({ summary: summarize(events, services, systems), since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service health unavailable' });
  }
});

router.get('/policies', async (req, res) => {
  try {
    const scope = userScope(req);
    const policies = await ServiceMonitoringPolicy.find(scope).sort({ createdAt: 1 }).lean();
    res.json({ policies: [...BUILT_IN_POLICIES.map(policy => ({ ...policy, builtIn: true })), ...policies], total: BUILT_IN_POLICIES.length + policies.length });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service policies unavailable' });
  }
});

router.post('/policies', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const policy = await ServiceMonitoringPolicy.create({ ...scope, name: req.body.name, enabled: req.body.enabled !== false, eventTypes: req.body.eventTypes || [], servicePatterns: req.body.servicePatterns || [], severity: req.body.severity || 'medium', riskScore: req.body.riskScore ?? 50, requireApproval: req.body.requireApproval !== false, responseActions: req.body.responseActions || [], createdBy: req.user.id, updatedBy: req.user.id });
    res.status(201).json({ policy });
  } catch (error) {
    res.status(error.code === 11000 ? 409 : error.statusCode || 400).json({ message: error.code === 11000 ? 'A policy with this name already exists' : error.message });
  }
});

router.put('/policies/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const allowed = ['name', 'enabled', 'eventTypes', 'servicePatterns', 'severity', 'riskScore', 'requireApproval', 'responseActions'];
    const update = Object.fromEntries(allowed.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    update.updatedBy = req.user.id;
    const policy = await ServiceMonitoringPolicy.findOneAndUpdate({ _id: objectId(req.params.id, 'policy id'), ...scope }, { $set: update }, { new: true, runValidators: true }).lean();
    if (!policy) return res.status(404).json({ message: 'Policy not found' });
    res.json({ policy });
  } catch (error) {
    res.status(error.statusCode || 400).json({ message: error.message });
  }
});

router.delete('/policies/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const policy = await ServiceMonitoringPolicy.findOneAndDelete({ _id: objectId(req.params.id, 'policy id'), ...scope }).lean();
    if (!policy) return res.status(404).json({ message: 'Policy not found' });
    res.json({ deleted: true });
  } catch (error) {
    res.status(error.statusCode || 400).json({ message: error.message });
  }
});

router.get('/:id', async (req, res) => {
  try {
    const scope = userScope(req);
    const row = await Alert.findOne({ _id: objectId(req.params.id, 'event id'), ...scope, ...evidenceFilter() })
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion').lean();
    if (!row) return res.status(404).json({ message: 'Service event not found' });
    res.json({ event: canonicalServiceEvent(row) });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Service event unavailable' });
  }
});

module.exports = router;
module.exports._private = { canonicalServiceEvent, evidenceFilter, normalizeState, summarize };
