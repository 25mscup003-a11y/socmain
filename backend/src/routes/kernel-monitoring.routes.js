const { REPORT_PERIOD_HOURS } = require('../utils/edrTimeRange');
const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');

router.use(authenticate, requireAnalyst);

const INVENTORY_RULE = 'KERNEL_INVENTORY_SNAPSHOT';
const first = (...values) => values.find(value => value !== undefined && value !== null && value !== '');
const boundedInt = (value, fallback, min, max) => {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, Math.trunc(parsed))) : fallback;
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
  const scope = scopeForUser(req.user, { departmentScoped: true });
  if (!scope.companyId) throw Object.assign(new Error('Company scope required'), { statusCode: 403 });
  return Object.fromEntries(Object.entries(scope).map(([key, value]) => (
    ['tenantId', 'companyId', 'departmentId', 'partnerId'].includes(key) && mongoose.Types.ObjectId.isValid(value)
      ? [key, new mongoose.Types.ObjectId(String(value))] : [key, value]
  )));
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const since = req.query.from ? new Date(req.query.from) : new Date(until.getTime() - boundedInt(req.query.windowHours, defaultHours, 1, 4320) * 3600000);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    throw Object.assign(new Error('Invalid time range'), { statusCode: 400 });
  }
  return { since, until };
}

function evidenceFilter() {
  return { $or: [{ capabilityId: 19 }, { capabilityIds: 19 }] };
}

function rawTelemetry(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function canonicalKernelEvent(row = {}) {
  const raw = rawTelemetry(row);
  const item = row.inventoryItem || raw.inventory_item || {};
  const driverName = first(row.driverName, row.moduleName, raw.driver_name, raw.module_name, item.driver_name, item.module_name, item.name, row.fileName, row.processName);
  const driverPath = first(row.driverPath, row.modulePath, raw.driver_path, raw.module_path, item.driver_path, item.module_path, item.path, row.filePath);
  return {
    ...row,
    timestamp: first(row.timestamp, row.createdAt, raw.timestamp),
    kernelEventType: first(row.kernelEventType, raw.kernel_event_type, row.eventType, row.ruleId),
    kernelCategory: first(row.kernelCategory, raw.kernel_category, row.subCategory, 'kernel'),
    driverName, moduleName: first(row.moduleName, driverName),
    driverPath, modulePath: first(row.modulePath, driverPath),
    sha256: first(row.sha256, row.fileHash, row.hash, raw.sha256, item.sha256),
    signatureStatus: first(row.signatureStatus, row.moduleSignature, raw.signature_status, item.signature_status, 'not_reported'),
    publisher: first(row.publisher, raw.publisher, item.publisher),
    driverVersion: first(row.driverVersion, raw.driver_version, item.driver_version),
    driverState: first(row.driverState, raw.driver_state, item.state),
    vulnerableDriver: row.vulnerableDriver === true || raw.vulnerable_driver === true || item.vulnerable_driver === true,
    inventorySnapshotId: first(row.inventorySnapshotId, raw.inventory_snapshot_id, raw.inventorySnapshotId),
    kernelPosture: first(row.kernelPosture, raw.kernel_posture, {}),
    riskScore: Number(first(row.riskScore, raw.risk_score, 0)) || 0,
    detectionReasons: row.detectionReasons || raw.detection_reasons || [],
  };
}

function eventQuery(scope, since, until, includeInventory = false) {
  return {
    $and: [scope, { createdAt: { $gte: since, $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(),
      ...(includeInventory ? [] : [{ ruleId: { $ne: INVENTORY_RULE } }])],
  };
}

function endpointKey(row = {}) {
  return String(row.systemId?._id || row.systemId || row.endpointId || row.agentId || row.agentName || row.hostname || 'unknown');
}

async function loadCurrentInventory(scope, until) {
  const snapshots = await Alert.find({
    $and: [scope, { createdAt: { $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), { ruleId: INVENTORY_RULE }],
  }).sort({ createdAt: -1 }).limit(1500)
    .select('tenantId companyId departmentId systemId endpointId agentId agentName hostname osType createdAt inventorySnapshotId inventoryItems inventoryBatchIndex inventoryBatchCount kernelPosture rawEvent')
    .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion')
    .lean();
  return reconstructCurrentInventory(snapshots);
}

function reconstructCurrentInventory(snapshots = []) {
  const seenBatches = new Set();
  const newestSnapshotByEndpoint = new Map();
  const modules = [];
  let posture = {};
  for (const snapshot of snapshots) {
    const endpoint = endpointKey(snapshot);
    const raw = rawTelemetry(snapshot);
    // New agents provide one ID shared by every batch in an inventory pass.
    // Preserve exact-timestamp grouping for legacy records that predate it.
    const snapshotId = String(first(
      snapshot.inventorySnapshotId,
      raw.inventory_snapshot_id,
      raw.inventorySnapshotId,
      `legacy:${new Date(snapshot.createdAt).getTime()}`,
    ));
    const newest = newestSnapshotByEndpoint.get(endpoint);
    if (newest === undefined) newestSnapshotByEndpoint.set(endpoint, snapshotId);
    else if (snapshotId !== newest) continue;
    const batch = Number(snapshot.inventoryBatchIndex || snapshot.rawEvent?.inventory_batch_index || 1);
    const key = `${endpoint}:${snapshotId}:${batch}`;
    if (seenBatches.has(key)) continue;
    seenBatches.add(key);
    posture = Object.keys(posture).length ? posture : (snapshot.kernelPosture || raw.kernel_posture || {});
    const items = snapshot.inventoryItems || raw.inventory_items || [];
    for (const item of Array.isArray(items) ? items : []) {
      modules.push(canonicalKernelEvent({ ...snapshot, inventoryItem: item, kernelEventType: 'KERNEL_MODULE_INVENTORY' }));
    }
  }
  return { modules, posture };
}

function summarize(events, modules, systems, posture = {}) {
  const text = row => `${row.kernelEventType || ''} ${row.ruleId || ''} ${row.description || ''} ${row.signatureStatus || ''}`.toLowerCase();
  const count = pattern => events.filter(row => pattern.test(text(row))).length;
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  events.forEach(row => { const severity = String(row.severity || 'low').toLowerCase(); if (bySeverity[severity] !== undefined) bySeverity[severity] += 1; });
  const unsignedDrivers = modules.filter(row => /unsigned|notsigned|invalid|tainted/i.test(String(row.signatureStatus || ''))).length;
  const vulnerableDrivers = modules.filter(row => row.vulnerableDriver).length + count(/byovd|vulnerable driver/);
  const healthScore = Math.max(0, 100 - bySeverity.critical * 12 - bySeverity.high * 6 - unsignedDrivers * 2 - vulnerableDrivers * 8);
  return {
    totalEvents: events.length, activeDrivers: modules.length, unsignedDrivers, vulnerableDrivers,
    rootkitAlerts: count(/rootkit|hidden|dkom/), syscallHooks: count(/sys.?call|ssdt|hook/),
    kernelMemoryAlerts: count(/kernel memory|rwx|shellcode|injection|corruption/),
    privilegeEscalations: count(/privilege|token|sedebug|seload|uac|byovd/),
    callbackAlerts: count(/callback|kprobe|ebpf|xdp/), criticalAlerts: bySeverity.critical,
    highAlerts: bySeverity.high, bySeverity, healthScore,
    activeAgents: systems.filter(system => system.isOnline || system.agentOk || String(system.status).toLowerCase() === 'active').length,
    monitoredSystems: systems.length, posture,
  };
}

async function loadEvents(scope, since, until, limit = 1000, categoryFilter = null) {
  const query = eventQuery(scope, since, until);
  if (categoryFilter) query.$and.push(categoryFilter);
  const [rows, total] = await Promise.all([
    Alert.find(query).sort({ createdAt: -1 }).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').lean(),
    Alert.countDocuments(query),
  ]);
  return { events: rows.map(canonicalKernelEvent), total };
}

router.get('/overview', async (req, res) => {
  try {
    const scope = userScope(req); const { since, until } = timeRange(req);
    const [{ events, total }, inventory, systems] = await Promise.all([
      loadEvents(scope, since, until, boundedInt(req.query.limit, 1000, 1, 3000)),
      loadCurrentInventory(scope, until),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}), isActive: true })
        .select('name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const summary = summarize(events, inventory.modules, systems, inventory.posture);
    res.json({ success: true, capabilityId: 19, since, until, total, events, alerts: events, modules: inventory.modules, posture: inventory.posture, systems, summary });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Kernel monitoring overview unavailable' });
  }
});

router.get('/events', async (req, res) => {
  try {
    const scope = userScope(req); const { since, until } = timeRange(req, 168);
    const page = boundedInt(req.query.page, 1, 1, 100000); const limit = boundedInt(req.query.limit, 250, 1, 2000);
    const query = eventQuery(scope, since, until);
    const [rows, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events: rows.map(canonicalKernelEvent), total, page, limit, since, until });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/report', async (req, res) => {
  try {
    const period = String(req.query.period || '90days');
    if (!Object.prototype.hasOwnProperty.call(REPORT_PERIOD_HOURS, period)) return res.status(400).json({ message: 'Invalid report period' });
    const hours = REPORT_PERIOD_HOURS[period];
    const categories = {
      all: null,
      drivers: { $or: [{ kernelCategory: /driver|module/i }, { kernelEventType: /driver|module/i }, { ruleId: /driver|module|byovd/i }] },
      rootkits: { $or: [{ kernelEventType: /rootkit|hidden|dkom/i }, { ruleId: /rootkit|hidden|dkom/i }, { description: /rootkit|hidden (?:process|module|driver)|dkom/i }] },
      syscalls: { $or: [{ syscallName: { $exists: true, $nin: ['', null] } }, { kernelEventType: /sys.?call|ssdt|hook|kprobe|callback/i }, { ruleId: /sys.?call|ssdt|hook|kprobe|callback/i }] },
      memory: { $or: [{ kernelCategory: /memory/i }, { kernelEventType: /memory|rwx|shellcode|injection|corruption/i }, { ruleId: /memory|rwx|shellcode|injection|corruption/i }] },
      privilege: { $or: [{ kernelEventType: /privilege|token|sedebug|seload|uac|byovd/i }, { ruleId: /privilege|token|sedebug|seload|uac|byovd/i }, { description: /privilege|token|sedebug|seload|uac|byovd/i }] },
      integrity: { $or: [{ kernelCategory: /integrity|boot/i }, { kernelEventType: /secure.boot|code.integrity|patchguard|test.sign|lockdown|signature/i }, { ruleId: /secure.boot|code.integrity|patchguard|test.sign|lockdown|signature/i }] },
    };
    const category = String(req.query.category || 'all');
    if (!Object.prototype.hasOwnProperty.call(categories, category)) return res.status(400).json({ message: 'Invalid report category' });
    req.query.windowHours = hours;
    const scope = userScope(req); const { since, until } = timeRange(req, hours);
    const [{ events, total }, inventory, systems] = await Promise.all([
      loadEvents(scope, since, until, 10000, categories[category]), loadCurrentInventory(scope, until),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}) }).select('status isOnline agentOk').lean(),
    ]);
    const summary = summarize(events, inventory.modules, systems, inventory.posture);
    res.json({ success: true, source: 'backend', capabilityId: 19, period: req.query.period || '90days', category, since, until, total, fetchedCount: events.length, truncated: total > events.length, alerts: events, modules: inventory.modules, summary, stats: { bySeverity: summary.bySeverity } });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    const scope = userScope(req);
    const row = await Alert.findOne({ _id: objectId(req.params.id, 'event id'), ...scope, ...evidenceFilter() })
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion').lean();
    if (!row) return res.status(404).json({ message: 'Kernel event not found' });
    res.json({ event: canonicalKernelEvent(row) });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

module.exports = router;
module.exports._private = { canonicalKernelEvent, evidenceFilter, summarize, reconstructCurrentInventory };
