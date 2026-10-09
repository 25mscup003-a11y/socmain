const router = require('express').Router();
const mongoose = require('mongoose');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const Company = require('../models/Company.model');
const System = require('../models/System.model');
const Alert = require('../models/Alert.model');
const NetworkConnection = require('../models/NetworkConnection.model');
const NetworkPolicy = require('../models/NetworkPolicy.model');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { LOG_RANGE_HOURS } = require('../utils/edrTimeRange');
const { enrichIp } = require('../services/ipEnrichmentService');
const { buildGpsDestinationMap, isPublicRoutableIp } = require('../services/idsAttackMap.service');
const {
  BEACON_BASE_NAME,
  BEACON_BUILTIN_RULES,
  BEACON_CUSTOM_PREFIX,
  BEACON_POLICY_PREFIX,
  DEFAULT_BEACON_CONFIG,
} = require('../services/networkMonitoring.service');

const NETWORK_SENSOR_NOISE_RULES = [
  'NET_CONNECTION_SUMMARY',
  'NET_DNS_SUMMARY',
  'NET_EXPOSURE_SUMMARY',
  'NET_THREAT_INTEL_SUMMARY',
  'WAF_AGENT_STATUS',
  'IDS_TELEMETRY',
  'NETWORK_TELEMETRY',
  'SURICATA_2200003',
  'SURICATA_2210045',
  'SURICATA_2210046',
  'ZEEK_truncated_tcp_payload',
];

router.use(authenticate, requireAnalyst);

function escapeRegex(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function integer(value, fallback, min, max) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function networkWindow(query = {}, nowValue = new Date()) {
  const now = new Date(nowValue);
  const safeNow = Number.isNaN(now.getTime()) ? new Date() : now;
  // Overview remains a rolling 24 hours; SIEM logs explicitly select a preset.
  if (query.range && !Object.prototype.hasOwnProperty.call(LOG_RANGE_HOURS, query.range)) {
    const error = new Error('Invalid log time range');
    error.statusCode = 400;
    throw error;
  }
  const maxHours = query.range ? LOG_RANGE_HOURS[query.range] : 24;
  const hours = query.range ? maxHours : integer(query.hours || query.windowHours, 24, 1, 24);
  const requestedEnd = query.range && query.windowEnd ? new Date(query.windowEnd) : safeNow;
  const anchor = Number.isNaN(requestedEnd.getTime()) ? safeNow : new Date(Math.min(safeNow.getTime(), requestedEnd.getTime()));
  const earliest = new Date(anchor.getTime() - maxHours * 3600000);
  const requestedTo = query.to ? new Date(query.to) : safeNow;
  const safeTo = Number.isNaN(requestedTo.getTime())
    ? safeNow
    : new Date(Math.min(safeNow.getTime(), Math.max(earliest.getTime(), requestedTo.getTime())));
  const requestedFrom = query.from ? new Date(query.from) : new Date(safeTo.getTime() - hours * 3600000);
  const from = Number.isNaN(requestedFrom.getTime())
    ? earliest
    : new Date(Math.min(safeTo.getTime(), Math.max(earliest.getTime(), requestedFrom.getTime())));
  return { from, to: safeTo, hours: Math.ceil((safeTo - from) / 3600000) };
}

async function requestScope(req) {
  const requested = req.headers['x-company-id'] || req.query.companyId || req.body?.companyId || req.user.companyId;
  if (!requested || !mongoose.Types.ObjectId.isValid(String(requested))) {
    const error = new Error('A valid companyId is required');
    error.statusCode = 400;
    throw error;
  }
  const company = await Company.findById(requested).select('_id tenantId partnerId').lean();
  if (!company) {
    const error = new Error('Company not found');
    error.statusCode = 404;
    throw error;
  }
  if (!['superadmin', 'partner_admin'].includes(req.user.role)
      && String(req.user.companyId || '') !== String(company._id)) {
    const error = new Error('Access denied to this company');
    error.statusCode = 403;
    throw error;
  }
  if (req.user.role === 'partner_admin'
      && String(req.user.partnerId || '') !== String(company.partnerId || '')) {
    const error = new Error('Access denied to this partner company');
    error.statusCode = 403;
    throw error;
  }
  // companyId is the canonical data-isolation key. Requiring tenantId or
  // partnerId here would hide valid legacy telemetry that predates those
  // denormalized fields, while authorization above still checks ownership.
  const scope = { companyId: company._id };
  if (req.user.role === 'department_admin' && req.user.departmentId) scope.departmentId = req.user.departmentId;
  return { company, filter: scope };
}

function connectionFilter(scope, req) {
  const { from, to } = networkWindow(req.query);
  const filter = { ...scope, observedAt: { $gte: from, $lte: to } };
  if (req.query.systemId) {
    if (!mongoose.Types.ObjectId.isValid(String(req.query.systemId))) {
      const error = new Error('Invalid system scope');
      error.statusCode = 400;
      throw error;
    }
    filter.systemId = new mongoose.Types.ObjectId(String(req.query.systemId));
  }
  const exact = {
    hostname: 'hostname', username: 'username', process: 'processName', pid: 'pid',
    sourceIp: 'sourceIp', destinationIp: 'destinationIp', port: 'destinationPort',
    protocol: 'protocol', severity: 'severity', state: 'state', assetType: 'assetType',
  };
  for (const [queryKey, field] of Object.entries(exact)) {
    if (req.query[queryKey] === undefined || req.query[queryKey] === '') continue;
    if (['pid', 'destinationPort'].includes(field)) filter[field] = integer(req.query[queryKey], -1, 0, 65535);
    else filter[field] = new RegExp(`^${escapeRegex(req.query[queryKey])}$`, 'i');
  }
  if (req.query.riskMin !== undefined) filter.riskScore = { $gte: integer(req.query.riskMin, 0, 0, 100) };
  if (req.query.domain) filter.domain = new RegExp(escapeRegex(req.query.domain), 'i');
  if (req.query.search) {
    const regex = new RegExp(escapeRegex(req.query.search).slice(0, 200), 'i');
    filter.$or = [
      { hostname: regex }, { username: regex }, { processName: regex },
      { sourceIp: regex }, { destinationIp: regex }, { domain: regex },
    ];
  }
  return filter;
}

function stableConnectionGroupId() {
  const value = (field, fallback = '') => ({ $ifNull: [`$${field}`, fallback] });
  return {
    agentId: value('agentId'),
    protocol: value('protocol', 'other'),
    direction: value('direction', 'unknown'),
    sourceIp: value('sourceIp'),
    // Client ports and PIDs are observation details, not topology identity.
    // Retain the listening service port because changing it is meaningful.
    servicePort: {
      $cond: [
        { $or: [{ $eq: ['$state', 'LISTEN'] }, { $eq: ['$direction', 'inbound'] }] },
        value('sourcePort', 0),
        0,
      ],
    },
    // A CDN/SaaS hostname commonly resolves to several anycast IPs. Treat the
    // process-to-domain relationship as one logical activity; without a
    // captured domain, the destination IP remains the identity.
    destination: {
      $cond: [
        { $ne: [value('domain'), ''] },
        { $concat: ['domain:', { $toLower: value('domain') }] },
        { $concat: ['ip:', value('destinationIp')] },
      ],
    },
    destinationPort: value('destinationPort', 0),
    processName: value('processName'),
    executablePath: value('executablePath'),
    username: value('username'),
  };
}

function latestStableConnections(filter) {
  return [
    { $match: filter },
    { $sort: { observedAt: -1, _id: -1 } },
    { $group: {
      _id: stableConnectionGroupId(),
      connection: { $first: '$$ROOT' },
      destinationIps: { $addToSet: '$destinationIp' },
      coalescedCount: { $sum: 1 },
      firstObservedAt: { $min: '$observedAt' },
      lastObservedAt: { $max: '$observedAt' },
    } },
    { $set: {
      'connection.destinationIps': {
        $filter: { input: '$destinationIps', as: 'ip', cond: { $not: [{ $in: ['$$ip', ['', null]] }] } },
      },
      'connection.coalescedCount': '$coalescedCount',
      'connection.firstObservedAt': '$firstObservedAt',
      'connection.lastObservedAt': '$lastObservedAt',
    } },
    { $replaceRoot: { newRoot: '$connection' } },
  ];
}

function mapCoordinate(value, minimum, maximum) {
  if (value === null || value === undefined || value === '') return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= minimum && parsed <= maximum ? parsed : null;
}

function coordinatesFromGeo(geo = {}) {
  const location = String(geo.loc || geo.location || '').split(',');
  const lat = mapCoordinate(geo.latitude ?? geo.lat ?? location[0], -90, 90);
  const lon = mapCoordinate(geo.longitude ?? geo.lon ?? geo.lng ?? location[1], -180, 180);
  return lat === null || lon === null ? null : { lat, lon };
}

function configuredAgentLocations(policies = []) {
  const locations = new Map();
  for (const policy of policies) {
    const latitude = mapCoordinate(policy.conditions?.latitude, -90, 90);
    const longitude = mapCoordinate(policy.conditions?.longitude, -180, 180);
    if (latitude === null || longitude === null) continue;
    for (const systemId of policy.conditions?.systemIds || []) {
      const key = String(systemId);
      if (!locations.has(key)) locations.set(key, {
        dstSystemId: key,
        dstLat: latitude,
        dstLon: longitude,
        dstLocationSource: `Geolocation policy: ${policy.name}`,
      });
    }
  }
  return locations;
}

function logicalNetworkAlertGroupId() {
  const value = (field, fallback = '') => ({ $ifNull: [`$${field}`, fallback] });
  const isDnsAttribution = { $eq: [{ $toUpper: value('ruleId') }, 'PROC_DNS_ATTRIBUTED'] };
  return {
    event: { $cond: [isDnsAttribution, '', { $toString: '$_id' }] },
    ruleId: { $cond: [isDnsAttribution, 'PROC_DNS_ATTRIBUTED', ''] },
    agentId: { $cond: [isDnsAttribution, value('agentId'), ''] },
    hostname: { $cond: [isDnsAttribution, value('hostname'), ''] },
    processName: { $cond: [isDnsAttribution, value('processName'), ''] },
    pid: { $cond: [isDnsAttribution, value('pid', 0), 0] },
    domain: { $cond: [isDnsAttribution, { $toLower: value('domain') }, ''] },
    destinationPort: { $cond: [isDnsAttribution, value('destPort', 0), 0] },
  };
}

function latestLogicalNetworkAlerts(filter) {
  return [
    { $match: filter },
    { $sort: { createdAt: -1, _id: -1 } },
    { $group: {
      _id: logicalNetworkAlertGroupId(),
      alert: { $first: '$$ROOT' },
      destinationIps: { $addToSet: { $ifNull: ['$destip', '$destinationIp'] } },
      coalescedCount: { $sum: 1 },
      firstObservedAt: { $min: '$createdAt' },
      lastObservedAt: { $max: '$createdAt' },
    } },
    { $set: {
      'alert.destinationIps': {
        $filter: { input: '$destinationIps', as: 'ip', cond: { $not: [{ $in: ['$$ip', ['', null]] }] } },
      },
      'alert.coalescedCount': '$coalescedCount',
      'alert.firstObservedAt': '$firstObservedAt',
      'alert.lastObservedAt': '$lastObservedAt',
    } },
    { $replaceRoot: { newRoot: '$alert' } },
  ];
}

function alertFilter(scope, req) {
  const { from, to } = networkWindow(req.query);
  const filter = {
    ...scope,
    createdAt: { $gte: from, $lte: to },
    isSynthetic: { $ne: true },
    $and: [
      { $or: [{ capabilityId: 3 }, { capabilityIds: 3 }, { eventCategory: 'network' }] },
      { ruleId: { $nin: NETWORK_SENSOR_NOISE_RULES } },
      { $nor: [{ source: 'zeek', ruleId: 'ZEEK_weird', signatureName: /^truncated_tcp_payload$/i }] },
    ],
  };
  if (req.query.systemId) {
    if (!mongoose.Types.ObjectId.isValid(String(req.query.systemId))) {
      const error = new Error('Invalid system scope');
      error.statusCode = 400;
      throw error;
    }
    filter.systemId = new mongoose.Types.ObjectId(String(req.query.systemId));
  }
  if (req.query.severity) filter.severity = req.query.severity;
  if (req.query.detectionType) filter.ruleId = new RegExp(escapeRegex(req.query.detectionType).slice(0, 100), 'i');
  if (req.query.mitre) filter.mitreId = new RegExp(escapeRegex(req.query.mitre).slice(0, 64), 'i');
  return filter;
}

const VPN_INTERFACE_PATTERN = /(^|[-_.])(tun|tap|wg|ppp|vpn)(\d|[-_.]|$)|wireguard|openvpn|proton|nordvpn|expressvpn|surfshark|mullvad|anyconnect|globalprotect/i;
const NON_HOST_TRAFFIC_INTERFACE_PATTERN = /^(lo|docker\d*|br-|veth|virbr|vmnet|vboxnet)/i;

function networkSummaryRaw(row = {}) {
  const rawEvent = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  return rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : rawEvent;
}

function summarizeAdapterUsage(rows = []) {
  const result = {
    bytesSent: 0,
    bytesReceived: 0,
    vpnBytesSent: 0,
    vpnBytesReceived: 0,
    vpnActiveEndpoints: 0,
    vpnEndpointsUsed: 0,
    vpnUsageEstimated: false,
    vpnMethods: [],
  };
  const vpnEndpoints = new Set();
  const latestVpnState = new Map();
  const vpnMethods = new Set();
  for (const row of rows) {
    const raw = networkSummaryRaw(row);
    const delta = raw.adapter_delta || raw.adapterDelta || {};
    const interfaces = Array.isArray(delta.interfaces) ? delta.interfaces : [];
    const hostInterfaces = interfaces.filter(item => !NON_HOST_TRAFFIC_INTERFACE_PATTERN.test(String(item.interface || item.name || '')));
    const hostBytesSent = hostInterfaces.length
      ? hostInterfaces.reduce((sum, item) => sum + Math.max(0, Number(item.bytes_sent ?? item.bytesSent) || 0), 0)
      : Math.max(0, Number(delta.bytes_sent ?? delta.bytesSent ?? row.bytesSent) || 0);
    const hostBytesReceived = hostInterfaces.length
      ? hostInterfaces.reduce((sum, item) => sum + Math.max(0, Number(item.bytes_received ?? item.bytesReceived) || 0), 0)
      : Math.max(0, Number(delta.bytes_received ?? delta.bytesReceived ?? row.bytesReceived) || 0);
    result.bytesSent += hostBytesSent;
    result.bytesReceived += hostBytesReceived;
    const vpn = raw.vpn && typeof raw.vpn === 'object' ? raw.vpn : {};
    const endpointKey = String(row.systemId || row.agentId || row.hostname || row._id);
    const confirmedVpnActive = vpn.active === true
      && ((Array.isArray(vpn.interfaces) && vpn.interfaces.length > 0)
        || ((Array.isArray(vpn.ports) && vpn.ports.length > 0)
          && (Array.isArray(vpn.processes) && vpn.processes.length > 0)));
    if (confirmedVpnActive) {
      vpnEndpoints.add(endpointKey);
      if (vpn.method) vpnMethods.add(String(vpn.method));
    }
    const observedAt = new Date(row.createdAt || row.timestamp || 0).getTime();
    const previous = latestVpnState.get(endpointKey);
    if (!previous || observedAt >= previous.observedAt) {
      latestVpnState.set(endpointKey, { active: confirmedVpnActive, observedAt });
    }
    const vpnInterfaces = interfaces.filter(item => VPN_INTERFACE_PATTERN.test(String(item.interface || item.name || '')));
    for (const item of vpnInterfaces) {
      result.vpnBytesSent += Math.max(0, Number(item.bytes_sent ?? item.bytesSent) || 0);
      result.vpnBytesReceived += Math.max(0, Number(item.bytes_received ?? item.bytesReceived) || 0);
    }
    if (confirmedVpnActive && !vpnInterfaces.length) {
      // Some Linux VPN clients keep their tunnel inside a network namespace,
      // so psutil exposes only the encrypted physical-adapter counters.
      result.vpnBytesSent += hostBytesSent;
      result.vpnBytesReceived += hostBytesReceived;
      result.vpnUsageEstimated = true;
    }
  }
  result.vpnActiveEndpoints = [...latestVpnState.values()].filter(item => item.active).length;
  result.vpnEndpointsUsed = vpnEndpoints.size;
  result.vpnMethods = [...vpnMethods];
  return result;
}

async function audit(req, action, policy, company) {
  if (!company.tenantId || !req.user.id) return;
  await SocAuditEvent.create({
    tenantId: company.tenantId,
    companyId: company._id,
    actorId: req.user.id,
    action,
    targetType: 'NetworkPolicy',
    targetId: String(policy._id),
    metadata: { name: policy.name, enabled: policy.enabled },
    ipAddress: req.ip || '',
  }).catch(error => console.error('[network policy audit]', error.message));
}

function beaconConditionValue(policy, field, operator, fallback) {
  const condition = (policy?.conditions || []).find(item => item.field === field && (!operator || item.operator === operator));
  const value = Number(condition?.value);
  return Number.isFinite(value) ? value : fallback;
}

async function ensureBeaconBuiltInPolicies(company, actorId) {
  const policies = [];
  for (const rule of BEACON_BUILTIN_RULES) {
    const policy = await NetworkPolicy.findOneAndUpdate(
      { companyId: company._id, name: `${BEACON_POLICY_PREFIX}${rule.name}` },
      { $setOnInsert: {
        tenantId: company.tenantId || null,
        partnerId: company.partnerId || null,
        companyId: company._id,
        name: `${BEACON_POLICY_PREFIX}${rule.name}`,
        description: rule.description,
        enabled: true,
        scope: {},
        conditions: rule.conditions,
        actions: { severity: rule.severity, riskScore: rule.riskScore, createAlert: true, block: false },
        suppressionSeconds: DEFAULT_BEACON_CONFIG.cooldownSeconds,
        createdBy: actorId,
        updatedBy: actorId,
      } },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true },
    );
    policies.push(policy);
  }
  return policies;
}

function serializeBeaconRule(definition, stored) {
  return {
    id: definition.id,
    policyId: stored?._id || null,
    name: definition.name,
    category: definition.category,
    description: stored?.description || definition.description,
    enabled: stored ? stored.enabled !== false : true,
    severity: stored?.actions?.severity || definition.severity,
    riskScore: Number(stored?.actions?.riskScore ?? definition.riskScore),
    conditions: stored?.conditions?.length ? stored.conditions : definition.conditions,
    suppressionSeconds: Number(stored?.suppressionSeconds ?? DEFAULT_BEACON_CONFIG.cooldownSeconds),
    updatedAt: stored?.updatedAt || null,
    builtIn: true,
  };
}

function serializeCustomBeaconRule(policy) {
  return {
    id: String(policy._id),
    policyId: policy._id,
    name: String(policy.name || '').startsWith(BEACON_CUSTOM_PREFIX)
      ? String(policy.name).slice(BEACON_CUSTOM_PREFIX.length)
      : policy.name,
    category: 'Custom',
    description: policy.description || 'Custom Beaconing Detection policy',
    enabled: policy.enabled !== false,
    severity: policy.actions?.severity || 'medium',
    riskScore: Number(policy.actions?.riskScore ?? DEFAULT_BEACON_CONFIG.alertThreshold),
    conditions: policy.conditions || [],
    suppressionSeconds: Number(policy.suppressionSeconds ?? DEFAULT_BEACON_CONFIG.cooldownSeconds),
    updatedAt: policy.updatedAt || null,
    builtIn: false,
  };
}

function customBeaconConditions(body = {}) {
  const conditions = [
    { field: 'beaconing', operator: 'eq', value: true },
    { field: 'connectionCount', operator: 'gte', value: integer(body.minimumConnections, DEFAULT_BEACON_CONFIG.minimumConnections, 4, 1000) },
    { field: 'averageInterval', operator: 'gte', value: integer(body.minimumIntervalSeconds, DEFAULT_BEACON_CONFIG.minimumIntervalSeconds, 1, 86400) },
    { field: 'averageInterval', operator: 'lte', value: integer(body.maximumIntervalSeconds, DEFAULT_BEACON_CONFIG.maximumIntervalSeconds, 1, 86400) },
    { field: 'intervalConsistency', operator: 'gte', value: integer(body.consistencyThreshold, DEFAULT_BEACON_CONFIG.consistencyThreshold, 0, 100) },
  ];
  const protocol = String(body.protocol || 'any').toLowerCase();
  if (protocol !== 'any') conditions.push({
    field: 'protocol', operator: protocol === 'web' ? 'in' : 'eq', value: protocol === 'web' ? ['http', 'https', 'tls'] : protocol,
  });
  const processName = String(body.processName || '').trim().slice(0, 512);
  if (processName) conditions.push({ field: 'processName', operator: 'contains', value: processName });
  return conditions;
}

function editableBuiltInBeaconConditions(definition, stored, body = {}) {
  const editableFields = new Set(['connectionCount', 'averageInterval', 'intervalConsistency', 'protocol', 'processName']);
  const current = [...(stored?.conditions?.length ? stored.conditions : definition.conditions)];
  const hasConditionUpdate = ['minimumConnections', 'minimumIntervalSeconds', 'maximumIntervalSeconds', 'consistencyThreshold', 'protocol', 'processName']
    .some(field => body[field] !== undefined);
  if (!hasConditionUpdate) return current;
  const preserved = current
    .filter(condition => !editableFields.has(condition.field));
  return [...preserved, ...customBeaconConditions(body).filter(condition => condition.field !== 'beaconing')];
}

function beaconConfigurationFromPolicy(policy) {
  return {
    enabled: policy ? policy.enabled !== false : DEFAULT_BEACON_CONFIG.enabled,
    minimumConnections: beaconConditionValue(policy, 'connectionCount', 'gte', DEFAULT_BEACON_CONFIG.minimumConnections),
    minimumIntervalSeconds: beaconConditionValue(policy, 'averageInterval', 'gte', DEFAULT_BEACON_CONFIG.minimumIntervalSeconds),
    maximumIntervalSeconds: beaconConditionValue(policy, 'averageInterval', 'lte', DEFAULT_BEACON_CONFIG.maximumIntervalSeconds),
    minimumObservationSeconds: beaconConditionValue(policy, 'observationSeconds', 'gte', DEFAULT_BEACON_CONFIG.minimumObservationSeconds),
    consistencyThreshold: beaconConditionValue(policy, 'intervalConsistency', 'gte', DEFAULT_BEACON_CONFIG.consistencyThreshold),
    alertThreshold: Number(policy?.actions?.riskScore ?? DEFAULT_BEACON_CONFIG.alertThreshold),
    cooldownSeconds: Number(policy?.suppressionSeconds ?? DEFAULT_BEACON_CONFIG.cooldownSeconds),
  };
}

router.get('/connections', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = connectionFilter(scope, req);
    const page = integer(req.query.page, 1, 1, 1000000);
    const limit = String(req.query.limit) === '0' ? 0 : integer(req.query.limit, 200, 1, 1000);
    const sortFields = new Set(['observedAt', 'riskScore', 'bytesSent', 'bytesReceived', 'destinationPort', 'durationSeconds']);
    const sortBy = sortFields.has(req.query.sortBy) ? req.query.sortBy : 'observedAt';
    const sort = { [sortBy]: req.query.order === 'asc' ? 1 : -1, _id: -1 };
    const [connections, totals] = await Promise.all([
      NetworkConnection.aggregate([
        ...latestStableConnections(filter),
        { $sort: sort },
        ...(limit ? [{ $skip: (page - 1) * limit }, { $limit: limit }] : []),
      ]),
      NetworkConnection.aggregate([...latestStableConnections(filter), { $count: 'total' }]),
    ]);
    const total = totals[0]?.total || 0;
    res.json({ connections, total, page, limit, windowHours: networkWindow(req.query).hours });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/forensics/:id', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    if (!mongoose.Types.ObjectId.isValid(String(req.params.id))) {
      return res.status(400).json({ message: 'Invalid network record ID' });
    }
    const objectId = new mongoose.Types.ObjectId(String(req.params.id));
    const networkAlertScope = {
      ...scope,
      _id: objectId,
      isSynthetic: { $ne: true },
      $or: [{ capabilityId: 3 }, { capabilityIds: 3 }, { eventCategory: 'network' }],
    };
    const [connection, alert] = await Promise.all([
      NetworkConnection.findOne({ ...scope, _id: objectId }).lean(),
      Alert.findOne(networkAlertScope).lean(),
    ]);
    if (!connection && !alert) return res.status(404).json({ message: 'Network record not found' });

    const base = connection || alert;
    const identity = [
      base.systemId ? { systemId: base.systemId } : null,
      base.agentId ? { agentId: base.agentId } : null,
      base.hostname ? { hostname: base.hostname } : null,
    ].filter(Boolean);
    const destinationIp = base.destinationIp || base.destip || base.dstip || '';
    const destinationPort = base.destinationPort ?? base.destPort ?? base.dstPort;
    let correlatedConnection = null;
    if (!connection && identity.length) {
      const correlation = { ...scope, $or: identity };
      if (destinationIp) correlation.destinationIp = destinationIp;
      if (destinationPort !== undefined && destinationPort !== null && destinationPort !== '') {
        correlation.destinationPort = Number(destinationPort);
      }
      correlatedConnection = await NetworkConnection.findOne(correlation).sort({ observedAt: -1, _id: -1 }).lean();
    }
    const [system, summary] = await Promise.all([
      base.systemId && mongoose.Types.ObjectId.isValid(String(base.systemId))
        ? System.findOne({ ...scope, _id: base.systemId })
          .select('_id agentId name hostname os osType platform ip ipAddress status lastSeen agentVersion').lean()
        : Promise.resolve(null),
      identity.length
        ? Alert.findOne({ ...scope, ruleId: 'NET_CONNECTION_SUMMARY', $or: identity })
          .select('systemId agentId hostname bytesSent bytesReceived rawEvent createdAt').sort({ createdAt: -1 }).lean()
        : Promise.resolve(null),
    ]);
    const snapshot = networkSummaryRaw(summary || {});
    const record = alert && correlatedConnection
      ? { ...correlatedConnection, ...alert, correlatedConnection }
      : base;
    if (connection && Number(connection.bytesSent || 0) === 0 && Number(connection.bytesReceived || 0) === 0) {
      record.rawMetadata = { ...(record.rawMetadata || {}), bytesScope: 'not_available' };
    }
    res.json({
      record: {
        ...record,
        liveContext: {
          endpoint: system,
          networkSnapshot: snapshot,
          refreshedAt: new Date(),
        },
      },
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

// Active, agent-linked connection topology for the dashboard and full-screen
// map. A connection remains present until the agent reports its CLOSED state;
// agent heartbeat status is returned separately so stale/offline evidence is
// never presented as a currently verified endpoint.
router.get('/live-map', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const maximumGpsAccuracyMeters = integer(req.query.maximumGpsAccuracyMeters, 50000, 5, 50000);
    const gpsSince = new Date(Date.now() - 24 * 3600000);
    const [connections, gpsRows, locationPolicies, systems] = await Promise.all([
      NetworkConnection.find({ ...scope, state: { $nin: ['CLOSED', 'CLOSING'] }, endTime: null })
        .sort({ observedAt: -1, _id: -1 }).limit(1000).lean(),
      Alert.find({
        ...scope,
        ruleId: 'GPS_LOCATION_TELEMETRY',
        gpsStatus: 'available',
        gpsAccuracyMeters: { $gte: 0, $lte: maximumGpsAccuracyMeters },
        gpsLat: { $gte: -90, $lte: 90 },
        gpsLon: { $gte: -180, $lte: 180 },
        createdAt: { $gte: gpsSince },
      }).select('systemId agentName hostname gpsLat gpsLon gpsAccuracyMeters gpsProvider gpsObservedAt createdAt')
        .sort({ createdAt: -1 }).limit(1000).lean(),
      GeolocationPolicy.find({
        ...scope,
        enabled: true,
        category: 'Location-Based',
        'conditions.latitude': { $ne: null },
        'conditions.longitude': { $ne: null },
      }).select('name conditions.systemIds conditions.latitude conditions.longitude').lean(),
      System.find({ ...scope, isActive: { $ne: false } })
        .select('_id agentId name hostname ip ipAddress status lastSeen agentVersion').lean(),
    ]);

    const gpsLocations = buildGpsDestinationMap(gpsRows, maximumGpsAccuracyMeters);
    const policyLocations = configuredAgentLocations(locationPolicies);
    const systemById = new Map(systems.map(system => [String(system._id), system]));
    const systemByAgent = new Map(systems.flatMap(system => [system.agentId, system.hostname, system.name]
      .filter(Boolean).map(value => [String(value), system])));
    // Resolve the endpoint's public address first so an AJNAT agent can still
    // be placed approximately when device GPS has not been reported. GPS and
    // configured policy coordinates always take precedence.
    const agentPublicIps = [...new Set(connections.map(row => row.sourceIp).filter(isPublicRoutableIp))];
    const remotePublicIps = [...new Set(connections.map(row => row.destinationIp).filter(isPublicRoutableIp))];
    const publicIps = [...new Set([...agentPublicIps, ...remotePublicIps])];
    const enrichedByIp = new Map();
    await Promise.all(publicIps.slice(0, 50).map(async ip => {
      try { enrichedByIp.set(ip, await enrichIp(ip)); } catch { /* Retain the connection without a map point. */ }
    }));

    const directionCounts = { inbound: 0, outbound: 0, internal: 0, unknown: 0 };
    const agentCounts = new Map();
    const networkAgentLocations = new Map();
    const now = Date.now();
    const liveConnections = connections.map(connection => {
      const direction = directionCounts[connection.direction] === undefined ? 'unknown' : connection.direction;
      const systemId = String(connection.systemId || '');
      const system = systemById.get(systemId) || systemByAgent.get(String(connection.agentId || ''))
        || systemByAgent.get(String(connection.hostname || ''));
      const resolvedSystemId = String(system?._id || systemId);
      if (!networkAgentLocations.has(resolvedSystemId)) {
        const sourceGeo = enrichedByIp.get(connection.sourceIp) || {};
        const sourceCoordinates = coordinatesFromGeo(sourceGeo);
        if (sourceCoordinates) networkAgentLocations.set(resolvedSystemId, {
          dstSystemId: resolvedSystemId,
          dstLat: sourceCoordinates.lat,
          dstLon: sourceCoordinates.lon,
          dstLocationSource: 'Agent public IP geolocation (approximate)',
        });
      }
      const destination = gpsLocations.get(resolvedSystemId)
        || policyLocations.get(resolvedSystemId)
        || networkAgentLocations.get(resolvedSystemId)
        || {};
      const storedGeo = connection.geo || {};
      const enrichedGeo = enrichedByIp.get(connection.destinationIp) || {};
      const remoteCoordinates = coordinatesFromGeo(storedGeo) || coordinatesFromGeo(enrichedGeo);
      const start = new Date(connection.startTime || connection.firstSeen || connection.observedAt).getTime();
      const systemLastSeen = new Date(system?.lastSeen || 0).getTime();
      const agentOnline = Boolean(system && ['active', 'online'].includes(String(system.status || '').toLowerCase())
        && Number.isFinite(systemLastSeen) && now - systemLastSeen < 10 * 60 * 1000);
      const observedAt = new Date(connection.observedAt || 0).getTime();
      const active = agentOnline || (!system && Number.isFinite(observedAt) && now - observedAt < 2 * 60 * 1000);
      if (active) {
        directionCounts[direction] += 1;
        const counts = agentCounts.get(resolvedSystemId) || { inbound: 0, outbound: 0, internal: 0, total: 0 };
        counts[direction] = (counts[direction] || 0) + 1;
        counts.total += 1;
        agentCounts.set(resolvedSystemId, counts);
      }
      return {
        id: String(connection._id || connection.connectionId),
        connectionId: connection.connectionId,
        srcIp: connection.destinationIp,
        srcLat: remoteCoordinates?.lat ?? null,
        srcLon: remoteCoordinates?.lon ?? null,
        srcCountry: storedGeo.country || enrichedGeo.country || enrichedGeo.countryCode || 'Unknown',
        srcCity: storedGeo.city || enrichedGeo.city || 'Unknown',
        srcISP: storedGeo.isp || enrichedGeo.organization || '',
        dstSystemId: resolvedSystemId || null,
        dstLat: destination.dstLat ?? null,
        dstLon: destination.dstLon ?? null,
        dstName: system?.hostname || system?.name || connection.hostname,
        dstIp: system?.ip || system?.ipAddress || connection.sourceIp,
        dstLocationSource: destination.dstLocationSource || 'Awaiting AJNAT GPS telemetry',
        direction,
        state: connection.state,
        active,
        agentOnline,
        protocol: connection.protocol,
        sourcePort: connection.sourcePort,
        destinationPort: connection.destinationPort,
        processName: connection.processName,
        username: connection.username,
        severity: connection.severity === 'elevated' ? 'high' : connection.severity,
        riskScore: connection.riskScore,
        description: `${String(direction).toUpperCase()} ${String(connection.protocol || '').toUpperCase()} connection${connection.processName ? ` · ${connection.processName}` : ''}`,
        timestamp: connection.observedAt,
        startedAt: connection.startTime,
        durationSeconds: Number.isFinite(start) ? Math.max(Number(connection.durationSeconds || 0), Math.floor((now - start) / 1000)) : Number(connection.durationSeconds || 0),
        blocked: false,
        eventType: 'network_connection',
      };
    });

    const agents = systems.map(system => {
      const systemId = String(system._id);
      const location = gpsLocations.get(systemId) || policyLocations.get(systemId) || networkAgentLocations.get(systemId) || {};
      const counts = agentCounts.get(systemId) || { inbound: 0, outbound: 0, internal: 0, total: 0 };
      return {
        systemId,
        agentId: system.agentId || null,
        name: system.name || system.hostname || 'Unnamed endpoint',
        hostname: system.hostname || system.name || 'Unnamed endpoint',
        ip: system.ip || system.ipAddress || null,
        status: system.status || 'unknown',
        lastSeen: system.lastSeen || null,
        sensors: ['Network activity'],
        inputEvents: counts.inbound,
        outputEvents: counts.outbound,
        activeConnections: counts.total,
        ...location,
      };
    });

    const verifiedConnections = liveConnections.filter(row => row.active);
    const mappedConnections = verifiedConnections.filter(row => row.srcLat !== null && row.srcLon !== null
      && row.dstLat !== null && row.dstLon !== null);
    res.json({
      ok: true,
      mode: 'live_network_connections',
      // A missing GPS/map coordinate must never hide a genuine live network
      // connection. Consumers can plot the rows that have coordinates while
      // still showing accurate inbound/outbound totals and connection data.
      connections: verifiedConnections,
      total: verifiedConnections.length,
      mapped: mappedConnections.length,
      unmapped: verifiedConnections.length - mappedConnections.length,
      stale: liveConnections.length - verifiedConnections.length,
      directionCounts,
      agents,
      observedAt: new Date(),
      lifecycle: 'visible_until_closed_while_agent_online',
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/alerts', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = alertFilter(scope, req);
    const page = integer(req.query.page, 1, 1, 1000000);
    const limit = String(req.query.limit) === '0' ? 0 : integer(req.query.limit, 200, 1, 1000);
    const [alerts, totals] = await Promise.all([
      Alert.aggregate([
        ...latestLogicalNetworkAlerts(filter),
        { $sort: { createdAt: -1, _id: -1 } },
        ...(limit ? [{ $skip: (page - 1) * limit }, { $limit: limit }] : []),
      ]),
      Alert.aggregate([...latestLogicalNetworkAlerts(filter), { $count: 'total' }]),
    ]);
    const total = totals[0]?.total || 0;
    res.json({ alerts, total, page, limit, windowHours: networkWindow(req.query).hours });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/dns', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = alertFilter(scope, req);
    filter.$and.push({ $or: [
      { ruleId: /DNS|DGA|DOMAIN/i }, { protocol: 'dns' },
      { domain: { $exists: true, $nin: ['', null] } },
    ] });
    const limit = integer(req.query.limit, 200, 1, 1000);
    const [queries, total] = await Promise.all([
      Alert.find(filter).sort({ createdAt: -1 }).limit(limit).lean(),
      Alert.countDocuments(filter),
    ]);
    res.json({ queries, total, windowHours: networkWindow(req.query).hours });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/top-talkers', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = connectionFilter(scope, req);
    const limit = integer(req.query.limit, 10, 1, 50);
    const group = (field) => [
      ...latestStableConnections({ ...filter, [field]: { $nin: ['', null] } }),
      { $group: { _id: `$${field}`, connections: { $sum: 1 }, bytesSent: { $sum: '$bytesSent' }, bytesReceived: { $sum: '$bytesReceived' } } },
      { $sort: { connections: -1 } }, { $limit: limit },
    ];
    const [sources, destinations, processes, users, servers] = await Promise.all([
      NetworkConnection.aggregate(group('sourceIp')),
      NetworkConnection.aggregate(group('destinationIp')),
      NetworkConnection.aggregate(group('processName')),
      NetworkConnection.aggregate(group('username')),
      NetworkConnection.aggregate(group('hostname').map((stage, index) => (
        index === 0 ? { $match: { ...filter, assetType: 'server', hostname: { $nin: ['', null] } } } : stage
      ))),
    ]);
    res.json({ sources, destinations, processes, users, servers, windowHours: networkWindow(req.query).hours });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/statistics', async (req, res) => {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = connectionFilter(scope, req);
    const alertQuery = alertFilter(scope, req);
    const { from, to } = networkWindow(req.query);
    const connectionText = { $toLower: { $concat: [
      { $ifNull: ['$processName', ''] }, ' ', { $ifNull: ['$executablePath', ''] }, ' ',
      { $ifNull: ['$interfaceName', ''] }, ' ', { $ifNull: ['$networkAdapter', ''] }, ' ',
      { $ifNull: ['$domain', ''] },
    ] } };
    const alertText = { $toLower: { $concat: [
      { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$eventType', ''] }, ' ',
      { $ifNull: ['$subCategory', ''] }, ' ', { $ifNull: ['$description', ''] }, ' ',
      { $ifNull: ['$domain', ''] }, ' ', { $ifNull: ['$processName', ''] },
    ] } };
    const [connectionStats, endpointIds, serverIds, alertEndpointIds, alertStats, summaryRows] = await Promise.all([
      NetworkConnection.aggregate([
        ...latestStableConnections(filter),
        { $set: { _metricText: connectionText } },
        { $group: {
          _id: null,
          totalConnections: { $sum: 1 },
          activeConnections: { $sum: { $cond: [{ $not: [{ $in: ['$state', ['CLOSED', 'CLOSING']] }] }, 1, 0] } },
          externalConnections: { $sum: { $cond: [{ $eq: ['$direction', 'outbound'] }, 1, 0] } },
          listeningServices: { $sum: { $cond: [{ $eq: ['$state', 'LISTEN'] }, 1, 0] } },
          webRequests: { $sum: { $cond: [{ $in: ['$destinationPort', [80, 443, 8080, 8443]] }, 1, 0] } },
          processMappings: { $sum: { $cond: [{ $gt: [{ $strLenCP: { $ifNull: ['$processName', ''] } }, 0] }, 1, 0] } },
          remoteAdminTools: { $sum: { $cond: [{ $or: [
            { $in: ['$destinationPort', [22, 3389, 5900, 5938]] },
            { $regexMatch: { input: '$_metricText', regex: 'anydesk|teamviewer|logmein|vnc|remote desktop' } },
          ] }, 1, 0] } },
          eastWestTraffic: { $sum: { $cond: [{ $eq: ['$direction', 'internal'] }, 1, 0] } },
          cloudSaasConnections: { $sum: { $cond: [{ $regexMatch: { input: '$_metricText', regex: 'aws|amazonaws|azure|microsoftonline|googleapis|googleusercontent|cloudflare|dropbox|slack|salesforce|office365' } }, 1, 0] } },
          windowsSignals: { $sum: { $cond: [{ $regexMatch: { input: { $toLower: { $ifNull: ['$osType', ''] } }, regex: 'win' } }, 1, 0] } },
          linuxSignals: { $sum: { $cond: [{ $regexMatch: { input: { $toLower: { $ifNull: ['$osType', ''] } }, regex: 'linux|ubuntu|debian|centos|rhel|fedora' } }, 1, 0] } },
          webServerTraffic: { $sum: { $cond: [{ $regexMatch: { input: '$_metricText', regex: 'nginx|apache|httpd|iis' } }, 1, 0] } },
          databaseTraffic: { $sum: { $cond: [{ $or: [
            { $in: ['$destinationPort', [1433, 1521, 3306, 5432, 6379, 27017]] },
            { $regexMatch: { input: '$_metricText', regex: 'mysql|postgres|mongo|oracle|redis|sqlserver' } },
          ] }, 1, 0] } },
          vpnConnections: { $sum: { $cond: [{ $or: [
            { $in: ['$destinationPort', [500, 1701, 1723, 4500, 51820, 1194] ] },
            { $regexMatch: { input: '$_metricText', regex: '(^|[-_. ])(tun|tap|wg|ppp|vpn)([0-9]|[-_. ]|$)|wireguard|openvpn|proton|nordvpn|expressvpn|surfshark|mullvad|anyconnect|globalprotect' } },
          ] }, 1, 0] } },
          suspiciousConnections: { $sum: { $cond: [{ $gte: ['$riskScore', 41] }, 1, 0] } },
          connectionBytesSent: { $sum: '$bytesSent' },
          connectionBytesReceived: { $sum: '$bytesReceived' },
        } },
      ]),
      NetworkConnection.distinct('systemId', { ...filter, assetType: { $ne: 'server' } }),
      NetworkConnection.distinct('systemId', { ...filter, assetType: 'server' }),
      Alert.distinct('systemId', alertQuery),
      Alert.aggregate([
        ...latestLogicalNetworkAlerts(alertQuery),
        { $set: { _metricText: alertText } },
        { $group: {
          _id: null,
          networkAlerts: { $sum: 1 },
          dnsQueries: { $sum: { $cond: [{ $or: [
            { $eq: [{ $toLower: { $ifNull: ['$protocol', ''] } }, 'dns'] },
            { $regexMatch: { input: '$_metricText', regex: 'dns|domain|nxdomain' } },
          ] }, 1, 0] } },
          c2BeaconDetections: { $sum: { $cond: [{ $regexMatch: { input: '$_metricText', regex: 'c2|beacon|callback|periodic' } }, 1, 0] } },
          torVpnAnonymizers: { $sum: { $cond: [{ $or: [
            { $eq: ['$geoVpn', true] }, { $eq: ['$geoTor', true] }, { $eq: ['$geoProxy', true] },
            { $regexMatch: { input: '$_metricText', regex: 'tor|vpn|proxy|exit node' } },
          ] }, 1, 0] } },
          failedDns: { $sum: { $cond: [{ $or: [
            { $in: [{ $toUpper: { $ifNull: ['$responseCode', ''] } }, ['NXDOMAIN', 'SERVFAIL', 'REFUSED']] },
            { $regexMatch: { input: '$_metricText', regex: 'failed dns|dns fail|nxdomain|servfail' } },
          ] }, 1, 0] } },
          exfiltrationAlerts: { $sum: { $cond: [{ $regexMatch: { input: '$_metricText', regex: 'exfil|large upload|transfer anomaly|archive staging' } }, 1, 0] } },
          portScanDetections: { $sum: { $cond: [{ $regexMatch: { input: '$_metricText', regex: 'port scan|recon|sweep|nmap|network scan' } }, 1, 0] } },
          lateralMovement: { $sum: { $cond: [{ $or: [
            { $eq: ['$lateralMovement', true] },
            { $regexMatch: { input: '$_metricText', regex: 'lateral[ _-]?movement|smb|rdp' } },
          ] }, 1, 0] } },
        } },
      ]),
      Alert.find({ ...scope, ruleId: 'NET_CONNECTION_SUMMARY', createdAt: { $gte: from, $lte: to } })
        .select('systemId agentId hostname bytesSent bytesReceived rawEvent.raw.adapter_delta rawEvent.raw.adapterDelta rawEvent.raw.vpn rawEvent.adapter_delta rawEvent.adapterDelta rawEvent.vpn createdAt')
        .sort({ createdAt: 1 }).lean(),
    ]);
    const aggregate = connectionStats[0] || {};
    const detections = alertStats[0] || {};
    const usage = summarizeAdapterUsage(summaryRows);
    const monitoredEndpointIds = new Set([...endpointIds, ...alertEndpointIds].filter(Boolean).map(String));
    const bytesSent = usage.bytesSent || aggregate.connectionBytesSent || 0;
    const bytesReceived = usage.bytesReceived || aggregate.connectionBytesReceived || 0;
    res.json({
      windowHours: networkWindow(req.query).hours,
      totalConnections: aggregate.totalConnections || 0,
      activeConnections: aggregate.activeConnections || 0,
      endpointsMonitored: monitoredEndpointIds.size,
      serversMonitored: serverIds.filter(Boolean).length,
      externalConnections: aggregate.externalConnections || 0,
      suspiciousConnections: aggregate.suspiciousConnections || 0,
      networkAlerts: detections.networkAlerts || 0,
      dnsQueries: detections.dnsQueries || 0,
      listeningServices: aggregate.listeningServices || 0,
      c2BeaconDetections: detections.c2BeaconDetections || 0,
      torVpnAnonymizers: detections.torVpnAnonymizers || 0,
      failedDns: detections.failedDns || 0,
      webRequests: aggregate.webRequests || 0,
      exfiltrationAlerts: detections.exfiltrationAlerts || 0,
      processMappings: aggregate.processMappings || 0,
      portScanDetections: detections.portScanDetections || 0,
      lateralMovement: detections.lateralMovement || 0,
      remoteAdminTools: aggregate.remoteAdminTools || 0,
      eastWestTraffic: aggregate.eastWestTraffic || 0,
      cloudSaasConnections: aggregate.cloudSaasConnections || 0,
      windowsSignals: aggregate.windowsSignals || 0,
      linuxSignals: aggregate.linuxSignals || 0,
      webServerTraffic: aggregate.webServerTraffic || 0,
      databaseTraffic: aggregate.databaseTraffic || 0,
      vpnConnections: aggregate.vpnConnections || 0,
      vpnActiveEndpoints: usage.vpnActiveEndpoints,
      vpnEndpointsUsed: usage.vpnEndpointsUsed,
      vpnMethods: usage.vpnMethods,
      vpnBytesSent: usage.vpnBytesSent,
      vpnBytesReceived: usage.vpnBytesReceived,
      vpnDataTransferred: usage.vpnBytesSent + usage.vpnBytesReceived,
      vpnUsageEstimated: usage.vpnUsageEstimated,
      bytesSent,
      bytesReceived,
      dataTransferred: bytesSent + bytesReceived,
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

async function scopedConnections(req, res, selector) {
  try {
    const { filter: scope } = await requestScope(req);
    const filter = { ...connectionFilter(scope, req), ...selector(req) };
    const connections = await NetworkConnection.aggregate([
      ...latestStableConnections(filter),
      { $limit: integer(req.query.limit, 500, 1, 1000) },
    ]);
    res.json({ connections, total: connections.length, windowHours: networkWindow(req.query).hours });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
}

router.get('/process/:pid', (req, res) => scopedConnections(req, res, () => ({ pid: integer(req.params.pid, -1, 0, 2147483647) })));
router.get('/host/:id', (req, res) => scopedConnections(req, res, () => ({ $or: [{ systemId: req.params.id }, { endpointId: req.params.id }, { hostname: req.params.id }] })));
router.get('/server/:id', (req, res) => scopedConnections(req, res, () => ({ assetType: 'server', $or: [{ systemId: req.params.id }, { endpointId: req.params.id }, { hostname: req.params.id }] })));

router.get('/threat-intelligence', (req, res) => scopedConnections(req, res, () => ({
  $or: [{ riskScore: { $gte: 21 } }, { 'threatIntel.verdict': { $in: ['suspicious', 'malicious', 'c2', 'botnet'] } }],
})));

router.get('/policies', async (req, res) => {
  try {
    const { filter } = await requestScope(req);
    res.json({ policies: await NetworkPolicy.find(filter).sort({ updatedAt: -1 }).lean() });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.get('/beaconing/configuration', async (req, res) => {
  try {
    const { company, filter } = await requestScope(req);
    const policies = await NetworkPolicy.find({ companyId: company._id, 'conditions.field': 'beaconing' }).sort({ updatedAt: -1 }).lean();
    const byName = new Map(policies.map(policy => [policy.name, policy]));
    const reservedNames = new Set([BEACON_BASE_NAME, ...BEACON_BUILTIN_RULES.map(rule => `${BEACON_POLICY_PREFIX}${rule.name}`)]);
    const customRules = policies.filter(policy => !reservedNames.has(policy.name) && String(policy.name || '').startsWith(BEACON_CUSTOM_PREFIX));
    const targetFilter = { companyId: company._id };
    if (filter.departmentId) targetFilter.departmentId = filter.departmentId;
    res.json({
      configuration: beaconConfigurationFromPolicy(byName.get(BEACON_BASE_NAME)),
      rules: [
        ...BEACON_BUILTIN_RULES.map(rule => serializeBeaconRule(rule, byName.get(`${BEACON_POLICY_PREFIX}${rule.name}`))),
        ...customRules.map(serializeCustomBeaconRule),
      ],
      targetCount: await System.countDocuments(targetFilter),
    });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.message });
  }
});

router.post('/beaconing/configuration/rules', requireManager, async (req, res) => {
  try {
    const { company } = await requestScope(req);
    const name = String(req.body.name || '').trim().replace(/\s+/g, ' ').slice(0, 100);
    if (name.length < 3) return res.status(400).json({ message: 'Rule name must contain at least 3 characters' });
    const minimumInterval = integer(req.body.minimumIntervalSeconds, DEFAULT_BEACON_CONFIG.minimumIntervalSeconds, 1, 86400);
    const maximumInterval = integer(req.body.maximumIntervalSeconds, DEFAULT_BEACON_CONFIG.maximumIntervalSeconds, 1, 86400);
    if (maximumInterval < minimumInterval) return res.status(400).json({ message: 'Maximum interval must be greater than or equal to minimum interval' });
    const severity = ['low', 'medium', 'high', 'critical'].includes(String(req.body.severity).toLowerCase())
      ? String(req.body.severity).toLowerCase()
      : 'medium';
    const policy = await NetworkPolicy.create({
      tenantId: company.tenantId || null,
      partnerId: company.partnerId || null,
      companyId: company._id,
      name: `${BEACON_CUSTOM_PREFIX}${name}`,
      description: String(req.body.description || '').trim().slice(0, 2000),
      enabled: req.body.enabled !== false,
      scope: req.body.scope || {},
      conditions: customBeaconConditions(req.body),
      actions: {
        severity,
        riskScore: integer(req.body.riskScore, DEFAULT_BEACON_CONFIG.alertThreshold, 25, 100),
        createAlert: req.body.createAlert !== false,
        block: false,
      },
      suppressionSeconds: integer(req.body.cooldownSeconds, DEFAULT_BEACON_CONFIG.cooldownSeconds, 60, 86400),
      createdBy: req.user.id,
      updatedBy: req.user.id,
    });
    await audit(req, 'network.beaconing.rule.created', policy, company);
    res.status(201).json({
      rule: serializeCustomBeaconRule(policy),
      message: `${name} rule added and queued for agent synchronization`,
    });
  } catch (error) {
    res.status(error.statusCode || (error.code === 11000 ? 409 : 400)).json({ message: error.code === 11000 ? 'A Beaconing rule with this name already exists' : error.message });
  }
});

router.put('/beaconing/configuration', requireManager, async (req, res) => {
  try {
    const { company, filter } = await requestScope(req);
    const config = {
      enabled: req.body.enabled !== false,
      minimumConnections: integer(req.body.minimumConnections, DEFAULT_BEACON_CONFIG.minimumConnections, 4, 1000),
      minimumIntervalSeconds: integer(req.body.minimumIntervalSeconds, DEFAULT_BEACON_CONFIG.minimumIntervalSeconds, 1, 86400),
      maximumIntervalSeconds: integer(req.body.maximumIntervalSeconds, DEFAULT_BEACON_CONFIG.maximumIntervalSeconds, 1, 86400),
      minimumObservationSeconds: integer(req.body.minimumObservationSeconds, DEFAULT_BEACON_CONFIG.minimumObservationSeconds, 0, 604800),
      consistencyThreshold: integer(req.body.consistencyThreshold, DEFAULT_BEACON_CONFIG.consistencyThreshold, 0, 100),
      alertThreshold: integer(req.body.alertThreshold, DEFAULT_BEACON_CONFIG.alertThreshold, 25, 100),
      cooldownSeconds: integer(req.body.cooldownSeconds, DEFAULT_BEACON_CONFIG.cooldownSeconds, 60, 86400),
    };
    if (config.maximumIntervalSeconds < config.minimumIntervalSeconds) {
      return res.status(400).json({ message: 'Maximum interval must be greater than or equal to minimum interval' });
    }
    const conditions = [
      { field: 'beaconing', operator: 'eq', value: true },
      { field: 'connectionCount', operator: 'gte', value: config.minimumConnections },
      { field: 'averageInterval', operator: 'gte', value: config.minimumIntervalSeconds },
      { field: 'averageInterval', operator: 'lte', value: config.maximumIntervalSeconds },
      { field: 'observationSeconds', operator: 'gte', value: config.minimumObservationSeconds },
      { field: 'intervalConsistency', operator: 'gte', value: config.consistencyThreshold },
    ];
    const policy = await NetworkPolicy.findOneAndUpdate(
      { companyId: company._id, name: BEACON_BASE_NAME },
      {
        $set: {
          enabled: config.enabled,
          description: 'Company-wide Beaconing Detection thresholds synchronized to endpoint agents.',
          scope: {},
          conditions,
          actions: { severity: 'high', riskScore: config.alertThreshold, createAlert: true, block: false },
          suppressionSeconds: config.cooldownSeconds,
          updatedBy: req.user.id,
        },
        $setOnInsert: {
          tenantId: company.tenantId || null,
          partnerId: company.partnerId || null,
          companyId: company._id,
          name: BEACON_BASE_NAME,
          createdBy: req.user.id,
        },
      },
      { upsert: true, new: true, setDefaultsOnInsert: true, runValidators: true },
    );
    const builtInPolicies = await ensureBeaconBuiltInPolicies(company, req.user.id);
    await audit(req, 'network.beaconing.configuration.updated', policy, company);
    const targetFilter = { companyId: company._id };
    if (filter.departmentId) targetFilter.departmentId = filter.departmentId;
    res.json({
      configuration: beaconConfigurationFromPolicy(policy),
      rules: BEACON_BUILTIN_RULES.map((rule, index) => serializeBeaconRule(rule, builtInPolicies[index])),
      targetCount: await System.countDocuments(targetFilter),
      message: 'Beaconing configuration saved and queued for agent heartbeat synchronization',
    });
  } catch (error) {
    res.status(error.statusCode || (error.code === 11000 ? 409 : 400)).json({ message: error.message });
  }
});

router.patch('/beaconing/configuration/rules/:ruleId', requireManager, async (req, res) => {
  try {
    const { company } = await requestScope(req);
    const definition = BEACON_BUILTIN_RULES.find(rule => rule.id === req.params.ruleId);
    if (!definition) {
      if (!mongoose.Types.ObjectId.isValid(req.params.ruleId)) return res.status(404).json({ message: 'Beaconing rule not found' });
      const existing = await NetworkPolicy.findOne({ companyId: company._id, _id: req.params.ruleId, 'conditions.field': 'beaconing' });
      if (!existing || existing.name === BEACON_BASE_NAME) return res.status(404).json({ message: 'Beaconing rule not found' });
      const severity = ['low', 'medium', 'high', 'critical'].includes(String(req.body.severity).toLowerCase())
        ? String(req.body.severity).toLowerCase()
        : existing.actions?.severity || 'medium';
      const update = {
        enabled: req.body.enabled !== false,
        description: req.body.description === undefined ? existing.description : String(req.body.description || '').trim().slice(0, 2000),
        'actions.severity': severity,
        updatedBy: req.user.id,
      };
      if (req.body.name !== undefined) {
        const name = String(req.body.name || '').trim().replace(/\s+/g, ' ').slice(0, 100);
        if (name.length < 3) return res.status(400).json({ message: 'Rule name must contain at least 3 characters' });
        update.name = `${BEACON_CUSTOM_PREFIX}${name}`;
      }
      if (req.body.riskScore !== undefined) update['actions.riskScore'] = integer(req.body.riskScore, existing.actions?.riskScore || 70, 25, 100);
      if (req.body.cooldownSeconds !== undefined) update.suppressionSeconds = integer(req.body.cooldownSeconds, existing.suppressionSeconds || 1800, 60, 86400);
      if (req.body.minimumConnections !== undefined || req.body.minimumIntervalSeconds !== undefined || req.body.maximumIntervalSeconds !== undefined || req.body.consistencyThreshold !== undefined || req.body.protocol !== undefined || req.body.processName !== undefined) {
        update.conditions = customBeaconConditions(req.body);
      }
      const policy = await NetworkPolicy.findOneAndUpdate({ companyId: company._id, _id: existing._id }, { $set: update }, { new: true, runValidators: true });
      await audit(req, 'network.beaconing.rule.updated', policy, company);
      return res.json({ rule: serializeCustomBeaconRule(policy), message: `${serializeCustomBeaconRule(policy).name} rule updated and queued for agent synchronization` });
    }
    await ensureBeaconBuiltInPolicies(company, req.user.id);
    const stored = await NetworkPolicy.findOne({ companyId: company._id, name: `${BEACON_POLICY_PREFIX}${definition.name}` }).lean();
    const minimumInterval = integer(req.body.minimumIntervalSeconds, DEFAULT_BEACON_CONFIG.minimumIntervalSeconds, 1, 86400);
    const maximumInterval = integer(req.body.maximumIntervalSeconds, DEFAULT_BEACON_CONFIG.maximumIntervalSeconds, 1, 86400);
    if (maximumInterval < minimumInterval) return res.status(400).json({ message: 'Maximum interval must be greater than or equal to minimum interval' });
    const severity = ['low', 'medium', 'high', 'critical'].includes(String(req.body.severity).toLowerCase())
      ? String(req.body.severity).toLowerCase()
      : stored?.actions?.severity || definition.severity;
    const policy = await NetworkPolicy.findOneAndUpdate(
      { companyId: company._id, name: `${BEACON_POLICY_PREFIX}${definition.name}` },
      { $set: {
        enabled: req.body.enabled !== false,
        description: req.body.description === undefined ? definition.description : String(req.body.description || '').trim().slice(0, 2000),
        conditions: editableBuiltInBeaconConditions(definition, stored, req.body),
        'actions.severity': severity,
        'actions.riskScore': integer(req.body.riskScore, stored?.actions?.riskScore || definition.riskScore, 25, 100),
        suppressionSeconds: integer(req.body.cooldownSeconds, stored?.suppressionSeconds || DEFAULT_BEACON_CONFIG.cooldownSeconds, 60, 86400),
        updatedBy: req.user.id,
      } },
      { new: true, runValidators: true },
    );
    await audit(req, 'network.beaconing.rule.updated', policy, company);
    res.json({
      rule: serializeBeaconRule(definition, policy),
      message: `${definition.name} rule updated and queued for agent synchronization`,
    });
  } catch (error) {
    res.status(error.statusCode || 400).json({ message: error.message });
  }
});

router.post('/policy', requireManager, async (req, res) => {
  try {
    const { company, filter } = await requestScope(req);
    if (!req.body.name || !Array.isArray(req.body.conditions) || !req.body.conditions.length) {
      return res.status(400).json({ message: 'name and at least one condition are required' });
    }
    const policy = await NetworkPolicy.create({
      ...filter,
      name: req.body.name,
      description: req.body.description || '',
      enabled: req.body.enabled !== false,
      scope: req.body.scope || {},
      conditions: req.body.conditions,
      actions: { ...(req.body.actions || {}), block: req.body.actions?.block === true && req.body.explicitBlockingApproval === true },
      suppressionSeconds: integer(req.body.suppressionSeconds, 900, 0, 86400),
      createdBy: req.user.id,
      updatedBy: req.user.id,
    });
    await audit(req, 'network.policy.created', policy, company);
    res.status(201).json({ policy });
  } catch (error) {
    res.status(error.statusCode || (error.code === 11000 ? 409 : 400)).json({ message: error.message });
  }
});

router.put('/policy/:id', requireManager, async (req, res) => {
  try {
    const { company, filter } = await requestScope(req);
    const allowed = ['name', 'description', 'enabled', 'scope', 'conditions', 'suppressionSeconds'];
    const update = {};
    for (const field of allowed) if (req.body[field] !== undefined) update[field] = req.body[field];
    if (req.body.actions) update.actions = { ...req.body.actions, block: req.body.actions.block === true && req.body.explicitBlockingApproval === true };
    update.updatedBy = req.user.id;
    const policy = await NetworkPolicy.findOneAndUpdate({ ...filter, _id: req.params.id }, { $set: update }, { new: true, runValidators: true });
    if (!policy) return res.status(404).json({ message: 'Network policy not found' });
    await audit(req, 'network.policy.updated', policy, company);
    res.json({ policy });
  } catch (error) {
    res.status(error.statusCode || 400).json({ message: error.message });
  }
});

module.exports = router;
module.exports.networkWindow = networkWindow;
module.exports.latestStableConnections = latestStableConnections;
module.exports.latestLogicalNetworkAlerts = latestLogicalNetworkAlerts;
module.exports.summarizeAdapterUsage = summarizeAdapterUsage;
