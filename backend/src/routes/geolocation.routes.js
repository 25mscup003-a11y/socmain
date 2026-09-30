const router = require('express').Router();
const mongoose = require('mongoose');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const System = require('../models/System.model');
const Alert = require('../models/Alert.model');
const AutomatedResponse = require('../models/AutomatedResponse.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');
const { assertCompanyScope } = require('../services/socAccess.service');
const { ACTIVE_STATUSES, createResponse } = require('../services/automatedResponse.service');
const { isSafeLocalUsername, trackIdentityProtectionResponse } = require('../services/uebaProfileLock.service');
const { geolocationEvidenceFilter } = require('../utils/capabilityOverview');

const ONLINE_THRESHOLD_MS = 10 * 60 * 1000;
const IDENTITY_RESPONSE_ACTIONS = new Set(['lock_account', 'force_logoff', 'isolate']);
const GEO_POLICY_CATEGORIES = new Set([
  'Country-Based', 'Device GPS Tracking', 'Location-Based', 'User-Based', 'Authentication',
  'Impossible Travel', 'VPN / Proxy / Tor', 'Corporate Network', 'Risk Score Matrix', 'Time + Location',
]);
const GEO_PASSIVE_ACTIONS = ['ALLOW & AUDIT', 'LOG & MONITOR', 'ALERT & NOTIFY SOC'];
const GEO_ENFORCEMENT_ACTIONS = ['BLOCK & IP BAN', 'ENDPOINT ISOLATION', 'CRITICAL BLOCK & SOC ESCALATION'];
function actionsForCategory(category) {
  if (category === 'Device GPS Tracking') return new Set(['ALLOW & AUDIT', 'LOG & MONITOR']);
  if (category === 'Location-Based') return new Set([...GEO_PASSIVE_ACTIONS, 'LOGOUT ACCOUNT OUTSIDE ALLOWED RADIUS', 'ENDPOINT ISOLATION']);
  return new Set([...GEO_PASSIVE_ACTIONS, ...GEO_ENFORCEMENT_ACTIONS]);
}

function withLiveSystemStatus(system, now = Date.now()) {
  const lastSeenAt = system.lastSeen ? new Date(system.lastSeen).getTime() : NaN;
  const status = String(system.status || '').toLowerCase();
  const isOnline = Boolean(
    system.isActive !== false
    && (status === 'active' || status === 'online')
    && system.agentVersion
    && Number.isFinite(lastSeenAt)
    && (now - lastSeenAt) < ONLINE_THRESHOLD_MS
  );
  return { ...system, isOnline, agentOk: isOnline };
}

const BUILT_IN_POLICIES = Object.freeze([
  {
    builtInKey: 'agent-gps-tracking', name: 'AJNAT Device GPS Tracking',
    description: 'Collect native OS location for selected AJNAT agents without enabling geo-fence enforcement.',
    category: 'Device GPS Tracking', severity: 'Low', action: 'LOG & MONITOR', enabled: false, priority: 5,
    conditions: {
      systemIds: [], gpsTracking: true, gpsIntervalSeconds: 300, gpsAccuracyMeters: 50000,
    },
  },
  {
    builtInKey: 'agent-location-radius', name: 'Agent Allowed Location & Radius',
    description: 'Monitor a selected AJNAT agent against its company-approved location and radius.',
    category: 'Location-Based', severity: 'High', action: 'ALERT & NOTIFY SOC', enabled: false, priority: 10,
    conditions: {
      systemIds: [], latitude: null, longitude: null, radiusMeters: 500, riskCutoff: 70,
      gpsTracking: true, gpsIntervalSeconds: 300, gpsAccuracyMeters: 100,
    },
  },
  {
    builtInKey: 'impossible-travel', name: 'Impossible Travel Detection',
    description: 'Detect travel that exceeds the configured distance and maximum realistic speed.',
    category: 'Impossible Travel', severity: 'Critical', action: 'ALERT & NOTIFY SOC', enabled: false, priority: 20,
    conditions: { systemIds: [], maxSpeed: 900, minDistanceKm: 500, riskCutoff: 80 },
  },
  {
    builtInKey: 'vpn-proxy-tor', name: 'VPN / Proxy / Tor Detection',
    description: 'Monitor anonymized access without automatically blocking it.',
    category: 'VPN / Proxy / Tor', severity: 'High', action: 'ALERT & NOTIFY SOC', enabled: false, priority: 30,
    conditions: { systemIds: [], vpn: true, proxy: true, tor: true, riskCutoff: 70 },
  },
  {
    builtInKey: 'high-risk-country', name: 'Configured High-Risk Countries',
    description: 'Alert only for company-defined country codes; no geopolitical list is hardcoded.',
    category: 'Country-Based', severity: 'High', action: 'ALERT & NOTIFY SOC', enabled: false, priority: 40,
    conditions: { systemIds: [], countries: [], riskCutoff: 70 },
  },
]);

router.get('/agent-policies/:agentKey', async (req, res) => {
  const verified = await verifySignedAgentRequest(req, { agentKey: req.params.agentKey });
  if (!verified.ok) return res.status(verified.status).json({ message: verified.message });
  const policies = await GeolocationPolicy.find({
    companyId: verified.system.companyId,
    enabled: true,
    $or: [{ departmentId: null }, { departmentId: { $exists: false } }, ...(verified.system.departmentId ? [{ departmentId: verified.system.departmentId }] : [])],
  }).select('name category severity action priority conditions version updatedAt').sort({ priority: 1 }).lean();
  res.json({ policies });
});

router.use(authenticate);

async function scope(req) {
  const requestedCompanyId = req.query.companyId || req.body?.companyId || req.user.companyId;
  if (!requestedCompanyId) {
    const error = new Error('Select an assigned company first');
    error.status = 400;
    throw error;
  }
  if (req.user.role !== 'superadmin') await assertCompanyScope(req.user, [requestedCompanyId]);
  return {
    companyId: requestedCompanyId,
    ...(req.user.role === 'department_admin' && req.user.departmentId ? { departmentId: req.user.departmentId } : {}),
  };
}

async function responseScope(req) {
  const base = await scope(req);
  if (req.user.role !== 'soc_manager') return base;
  const actorId = req.user.id || req.user._id;
  const companyAssigned = await SocCompanyAssignment.exists({ userId: actorId, companyId: base.companyId, active: true });
  if (companyAssigned) return base;
  const departmentIds = await SocDepartmentAssignment.find({ userId: actorId, companyId: base.companyId, active: true }).distinct('departmentId');
  if (!departmentIds.length) {
    const error = new Error('No active SOC assignment exists for this company');
    error.status = 403;
    throw error;
  }
  return { ...base, departmentId: { $in: departmentIds } };
}

function boundedInt(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, Math.trunc(parsed))) : fallback;
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const hours = boundedInt(req.query.windowHours, defaultHours, 1, 2160);
  const since = req.query.from ? new Date(req.query.from) : new Date(until.getTime() - (hours * 3600000));
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    const error = new Error('Invalid time range');
    error.status = 400;
    throw error;
  }
  return { since, until };
}

function geoQuery(companyScope, since, until, extra = {}) {
  return {
    $and: [
      companyScope,
      { createdAt: { $gte: since, $lte: until } },
      { isSynthetic: { $ne: true } },
      geolocationEvidenceFilter(),
      extra,
    ],
  };
}

async function ensureBuiltInPolicies(companyScope, userId) {
  try {
    await GeolocationPolicy.bulkWrite(BUILT_IN_POLICIES.map(template => ({
      updateOne: {
        filter: { companyId: companyScope.companyId, builtInKey: template.builtInKey },
        update: { $setOnInsert: { ...companyScope, ...template, createdBy: userId, updatedBy: userId } },
        upsert: true,
      },
    })), { ordered: false });
  } catch (error) {
    // Concurrent first loads can race on the unique built-in key; the other
    // request has already created the same tenant-scoped defaults.
    if (error?.code !== 11000) throw error;
  }
}

function validatePolicyConfiguration(policy = {}) {
  if (!GEO_POLICY_CATEGORIES.has(policy.category)) {
    const error = new Error('Unsupported geolocation policy category');
    error.status = 400;
    throw error;
  }
  if (!actionsForCategory(policy.category).has(policy.action)) {
    const error = new Error(`Action ${policy.action || '(missing)'} is not supported for ${policy.category}`);
    error.status = 400;
    throw error;
  }
  if (policy.enabled !== true) return;
  const conditions = policy.conditions || {};
  const gpsOnly = policy.category === 'Device GPS Tracking';
  if (gpsOnly) {
    const targetsValid = Array.isArray(conditions.systemIds) && conditions.systemIds.some(mongoose.Types.ObjectId.isValid);
    const gpsInterval = Number(conditions.gpsIntervalSeconds ?? 300);
    const gpsAccuracy = Number(conditions.gpsAccuracyMeters ?? 100);
    if (!targetsValid || conditions.gpsTracking !== true
      || !Number.isFinite(gpsInterval) || gpsInterval < 30 || gpsInterval > 3600
      || !Number.isFinite(gpsAccuracy) || gpsAccuracy < 5 || gpsAccuracy > 50) {
      const error = new Error('Select an AJNAT system and valid GPS interval/accuracy before enabling tracking');
      error.status = 400;
      throw error;
    }
    return;
  }
  if (policy.category === 'Country-Based' && !(conditions.countries || []).length) {
    const error = new Error('Select at least one ISO country code before enabling this rule');
    error.status = 400;
    throw error;
  }
  if (policy.category !== 'Location-Based') return;
  const coordinatesValid = conditions.latitude !== null && conditions.latitude !== ''
    && conditions.longitude !== null && conditions.longitude !== ''
    && Number.isFinite(Number(conditions.latitude)) && Number.isFinite(Number(conditions.longitude));
  const targetsValid = Array.isArray(conditions.systemIds) && conditions.systemIds.some(mongoose.Types.ObjectId.isValid);
  const latitude = Number(conditions.latitude);
  const longitude = Number(conditions.longitude);
  const radius = Number(conditions.radiusMeters);
  const gpsInterval = Number(conditions.gpsIntervalSeconds ?? 300);
  const gpsAccuracy = Number(conditions.gpsAccuracyMeters ?? 100);
  if (!coordinatesValid || latitude < -90 || latitude > 90 || longitude < -180 || longitude > 180
    || !targetsValid || !Number.isFinite(radius) || radius < 1 || radius > 100000
    || !Number.isFinite(gpsInterval) || gpsInterval < 30 || gpsInterval > 3600
    || !Number.isFinite(gpsAccuracy) || gpsAccuracy < 5 || gpsAccuracy > 50) {
    const error = new Error('Select an AJNAT system, valid latitude/longitude and allowed radius before enabling this rule');
    error.status = 400;
    throw error;
  }
}

async function validatePolicyTargets(policy = {}, companyScope = {}) {
  const targetIds = Array.isArray(policy.conditions?.systemIds)
    ? [...new Set(policy.conditions.systemIds.map(String))]
    : [];
  if (!targetIds.length) return;
  if (targetIds.some(id => !mongoose.Types.ObjectId.isValid(id))) {
    const error = new Error('One or more selected AJNAT agents are invalid');
    error.status = 400;
    throw error;
  }
  const matchingSystems = await System.countDocuments({
    ...companyScope,
    _id: { $in: targetIds.map(id => new mongoose.Types.ObjectId(id)) },
    isActive: true,
  });
  if (matchingSystems !== targetIds.length) {
    const error = new Error('Selected AJNAT agent does not belong to this company or is inactive');
    error.status = 403;
    throw error;
  }
}

function riskScore(row = {}) {
  const value = Number(row.riskScore ?? row.risk?.score ?? 0);
  return Number.isFinite(value) ? Math.max(0, Math.min(100, value)) : 0;
}

function countryOf(row = {}) {
  return row.geoCountry || row.country || row.sourceGeo?.country || row.rawEvent?.geoCountry || 'Unknown';
}

function userOf(row = {}) {
  return row.username || row.user || row.userName || row.rawEvent?.username || null;
}

function firstValue(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '') ?? null;
}

function eventAt(row = {}) {
  return firstValue(row.eventTimestamp, row.timestamp, row.createdAt, row.updatedAt);
}

function distanceMeters(first, second) {
  const lat1 = Number(first?.gpsLat ?? first?.geoLat);
  const lon1 = Number(first?.gpsLon ?? first?.geoLon);
  const lat2 = Number(second?.gpsLat ?? second?.geoLat);
  const lon2 = Number(second?.gpsLon ?? second?.geoLon);
  if (![lat1, lon1, lat2, lon2].every(Number.isFinite)) return null;
  const radians = value => value * Math.PI / 180;
  const dLat = radians(lat2 - lat1);
  const dLon = radians(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(radians(lat1)) * Math.cos(radians(lat2)) * Math.sin(dLon / 2) ** 2;
  return 6371000 * 2 * Math.asin(Math.min(1, Math.sqrt(a)));
}

function evidenceRef(row) {
  return row ? { eventId: row._id, ruleId: row.ruleId, observedAt: eventAt(row) } : null;
}

async function buildLiveForensics(event, responseAction = null) {
  const system = event.systemId && typeof event.systemId === 'object' ? event.systemId : {};
  const systemId = system._id || event.systemId;
  const noEvidence = 'No matching agent evidence observed in the last 24 hours';
  const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
  const evidenceFields = [
    '_id', 'ruleId', 'description', 'createdAt', 'updatedAt', 'eventTimestamp', 'timestamp',
    'source', 'severity', 'riskScore', 'status', 'hostname', 'agentName', 'agentId', 'endpointId',
    'osType', 'agentVersion', 'srcip', 'destip', 'srcPort', 'destPort', 'protocol', 'networkInterface',
    'geoCountry', 'geoCountryCode', 'geoRegion', 'geoCity', 'geoTimezone', 'geoISP', 'asn', 'asnOrg',
    'geoVpn', 'geoProxy', 'geoTor', 'geoHosting', 'gpsLat', 'gpsLon', 'gpsAccuracyMeters',
    'gpsAltitudeMeters', 'gpsProvider', 'gpsStatus', 'gpsReason', 'gpsObservedAt',
    'username', 'userAction', 'authType', 'authResult', 'mfaStatus', 'identityProvider', 'privilegeLevel',
    'sessionId', 'deviceId', 'processName', 'processExe', 'processCmdline', 'pid', 'parentPid',
    'parentProcessName', 'processStatus', 'processCpuPercent', 'processMemoryPercent',
    'dataEventType', 'dataClassification', 'bytesTransferred', 'bytesSent', 'bytesReceived',
    'transferChannel', 'transferProtocol', 'destinationDomain', 'fileName', 'filePath', 'direction',
    'mitreTechnique', 'mitreId', 'technique', 'mitreTactic', 'threatCategory', 'confidenceScore',
    'policyId', 'policyName', 'policyCategory', 'policyAction', 'policyTriggered', 'policyActionStatus',
    'containmentStatus', 'actionTaken', 'blocked', 'reputationScore', 'vtVerdict',
  ];
  const projection = Object.fromEntries(evidenceFields.map(field => [field, 1]));
  const baseMatch = {
    // The selected event has already passed company/department authorization.
    // Reuse its typed ObjectId values because Mongoose does not cast aggregate pipelines.
    companyId: event.companyId,
    systemId,
    createdAt: { $gte: since },
    isSynthetic: { $ne: true },
    dataOrigin: 'agent',
  };
  const branch = (match, limit = 1) => [{ $match: match }, { $limit: limit }, { $project: projection }];
  const [evidence] = systemId ? await Alert.aggregate([
    { $match: baseMatch },
    { $sort: { createdAt: -1 } },
    { $facet: {
      latest: [{ $limit: 1 }, { $project: projection }],
      gps: branch({ ruleId: { $in: ['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'] } }, 2),
      auth: branch({ $or: [{ ruleId: /^(?:AUTH_|.*(?:LOGIN|LOGON|CREDENTIAL))/i }, { authType: { $exists: true, $nin: [null, ''] } }, { authResult: { $exists: true, $nin: [null, ''] } }] }),
      process: branch({ $or: [{ ruleId: /^(?:PROC_|EDR_)/i }, { processName: { $exists: true, $nin: [null, ''] } }] }),
      network: branch({ $or: [{ ruleId: /^(?:NET_|DNS_|WEB_|WAF_)/i }, { destip: { $exists: true, $nin: [null, ''] } }, { protocol: { $exists: true, $nin: [null, ''] } }] }),
      data: branch({ $or: [{ ruleId: /(?:DLP|EXFIL|DATA_)/i }, { dataEventType: { $exists: true, $nin: [null, ''] } }, { bytesTransferred: { $exists: true, $ne: null } }] }),
      mitre: branch({ $or: [{ mitreTechnique: { $exists: true, $nin: [null, ''] } }, { mitreId: { $exists: true, $nin: [null, ''] } }, { mitreTactic: { $exists: true, $nin: [null, ''] } }] }),
      total: [{ $count: 'count' }],
    } },
  ]) : [{ latest: [], gps: [], auth: [], process: [], network: [], data: [], mitre: [], total: [] }];

  const gpsRows = evidence.gps || [];
  const currentGps = gpsRows[0] || event;
  const previousGps = gpsRows[1];
  const auth = evidence.auth?.[0];
  const process = evidence.process?.[0];
  const network = evidence.network?.[0];
  const data = evidence.data?.[0];
  const mitre = evidence.mitre?.[0];
  const relatedCount = Number(evidence.total?.[0]?.count || 0);
  const distance = distanceMeters(previousGps, currentGps);
  const elapsedHours = previousGps && eventAt(previousGps) && eventAt(currentGps)
    ? Math.abs(new Date(eventAt(currentGps)) - new Date(eventAt(previousGps))) / 3600000 : null;
  const speed = distance != null && elapsedHours > 0 ? (distance / 1000) / elapsedHours : null;
  const embedded = event.rawEvent?.raw?.geoForensics || {};
  const accuracy = firstValue(currentGps.gpsAccuracyMeters, system.gpsAccuracyMeters, event.gpsAccuracyMeters);
  const requiredAccuracy = firstValue(embedded.travel?.requiredAccuracyMeters, 50);
  const policyEligible = String(firstValue(currentGps.gpsStatus, system.gpsStatus, event.gpsStatus)).toLowerCase() === 'available'
    && Number.isFinite(Number(accuracy)) && Number(accuracy) <= Number(requiredAccuracy);
  const latestActivity = evidence.latest?.[0];

  return {
    schemaVersion: 2,
    generatedAt: new Date(),
    lookbackHours: 24,
    evidenceOrigin: 'AJNAT agent live telemetry',
    overview: {
      detectionTrigger: firstValue(event.ruleId, event.description),
      observationStatus: firstValue(event.gpsStatus, system.gpsStatus, event.status),
      riskScore: riskScore(event),
      evidenceSource: 'AJNAT agent + correlated endpoint telemetry',
      collectedAt: firstValue(event.gpsObservedAt, eventAt(event)),
      relatedEvents: relatedCount,
      latestAgentActivityAt: eventAt(latestActivity) || noEvidence,
    },
    network: {
      localIp: firstValue(embedded.network?.localIp, system.ip, system.ipAddress, event.srcip, network?.srcip, noEvidence),
      destinationIp: firstValue(network?.destip, noEvidence),
      sourcePort: firstValue(network?.srcPort, noEvidence),
      destinationPort: firstValue(network?.destPort, noEvidence),
      protocol: firstValue(network?.protocol, noEvidence),
      interface: firstValue(embedded.network?.interface, network?.networkInterface, noEvidence),
      fqdn: firstValue(embedded.network?.fqdn, system.hostname, event.hostname, noEvidence),
      localAddresses: firstValue(embedded.network?.localAddresses, system.ipAddress, system.ip, noEvidence),
      country: firstValue(event.geoCountry, network?.geoCountry, 'Unavailable from current GPS/agent evidence'),
      countryCode: firstValue(event.geoCountryCode, network?.geoCountryCode, 'Unavailable'),
      region: firstValue(event.geoRegion, network?.geoRegion, 'Unavailable'),
      city: firstValue(event.geoCity, network?.geoCity, 'Unavailable'),
      timezone: firstValue(event.geoTimezone, network?.geoTimezone, 'Unavailable'),
      isp: firstValue(event.geoISP, network?.geoISP, 'Unavailable'),
      asn: firstValue(event.asn, network?.asn, 'Unavailable'),
      organization: firstValue(event.asnOrg, network?.asnOrg, 'Unavailable'),
      locationProvider: firstValue(event.gpsProvider, system.gpsProvider, embedded.network?.locationProvider, 'unknown'),
      locationStatus: firstValue(event.gpsStatus, system.gpsStatus, embedded.network?.locationStatus, 'unknown'),
      locationReason: firstValue(event.gpsReason, system.gpsReason, embedded.network?.locationReason, noEvidence),
      vpnDetected: event.geoVpn === true || network?.geoVpn === true,
      proxyDetected: event.geoProxy === true || network?.geoProxy === true,
      torDetected: event.geoTor === true || network?.geoTor === true,
      hostingDetected: event.geoHosting === true || network?.geoHosting === true,
      networkClassification: event.geoTor || network?.geoTor ? 'Tor' : event.geoProxy || network?.geoProxy ? 'Proxy' : event.geoVpn || network?.geoVpn ? 'VPN' : event.geoHosting || network?.geoHosting ? 'Hosting / Datacenter' : 'No anonymizer detected',
      threatReputation: firstValue(network?.reputationScore, network?.vtVerdict, 'No reputation finding in latest agent network evidence'),
      evidence: evidenceRef(network),
    },
    travel: {
      previousLatitude: firstValue(previousGps?.gpsLat, previousGps?.geoLat, 'No previous coordinate in 24 hours'),
      previousLongitude: firstValue(previousGps?.gpsLon, previousGps?.geoLon, 'No previous coordinate in 24 hours'),
      previousObservedAt: firstValue(previousGps && eventAt(previousGps), 'No previous coordinate in 24 hours'),
      currentLatitude: firstValue(currentGps.gpsLat, system.gpsLat, event.gpsLat, embedded.travel?.currentLatitude, 'Unavailable'),
      currentLongitude: firstValue(currentGps.gpsLon, system.gpsLon, event.gpsLon, embedded.travel?.currentLongitude, 'Unavailable'),
      accuracyMeters: firstValue(accuracy, 'Unavailable'),
      requiredAccuracyMeters: requiredAccuracy,
      distanceMeters: distance == null ? 'Not calculable from available fixes' : Math.round(distance),
      requiredSpeedKmh: speed == null ? 'Not calculable from available fixes' : Math.round(speed),
      allowedRadiusMeters: firstValue(embedded.travel?.allowedRadiusMeters, 'No radius policy on event'),
      insideAllowedRadius: firstValue(embedded.travel?.insideAllowedRadius, 'Not evaluated without a qualified fix and radius policy'),
      policyEligible,
      evaluation: policyEligible ? 'qualified_location_fix' : 'display_only_fix_accuracy_exceeds_policy',
      evidence: evidenceRef(previousGps),
    },
    authentication: {
      username: firstValue(event.username, auth?.username, embedded.authentication?.username, 'No authenticated user identified'),
      loginAction: firstValue(auth?.userAction, auth?.ruleId, noEvidence),
      accountRole: firstValue(auth?.privilegeLevel, 'Not supplied by endpoint auth sensor'),
      authType: firstValue(auth?.authType, embedded.authentication?.authType, 'OS local authentication'),
      authResult: firstValue(auth?.authResult, auth?.status, noEvidence),
      mfaStatus: firstValue(auth?.mfaStatus, embedded.authentication?.mfaStatus, 'Not observable for local OS session'),
      identityProvider: firstValue(auth?.identityProvider, embedded.authentication?.identityProvider, 'operating-system'),
      cloudProvider: 'Not applicable to local OS session',
      sessionId: firstValue(auth?.sessionId, 'Not supplied by endpoint auth sensor'),
      observedAt: firstValue(auth && eventAt(auth), noEvidence),
      evidence: evidenceRef(auth),
    },
    endpoint: {
      hostname: firstValue(system.hostname, event.hostname, process?.hostname, embedded.endpoint?.hostname, noEvidence),
      systemId: String(systemId || event.endpointId || ''),
      agentId: firstValue(event.agentId, process?.agentId, embedded.endpoint?.agentId, noEvidence),
      agentVersion: firstValue(system.agentVersion, event.agentVersion, embedded.endpoint?.agentVersion, noEvidence),
      operatingSystem: firstValue(system.os, system.osType, event.osType, embedded.endpoint?.operatingSystem, noEvidence),
      osVersion: firstValue(embedded.endpoint?.osVersion, 'Available after forensic-enabled agent update'),
      architecture: firstValue(embedded.endpoint?.architecture, 'Available after forensic-enabled agent update'),
      processName: firstValue(process?.processName, embedded.endpoint?.processName, noEvidence),
      processId: firstValue(process?.pid, embedded.endpoint?.processId, noEvidence),
      parentProcessId: firstValue(process?.parentPid, embedded.endpoint?.parentProcessId, noEvidence),
      processExecutable: firstValue(process?.processExe, noEvidence),
      processStatus: firstValue(process?.processStatus, process?.ruleId, noEvidence),
      cpuPercent: firstValue(process?.processCpuPercent, noEvidence),
      memoryPercent: firstValue(process?.processMemoryPercent, noEvidence),
      lastSeen: firstValue(system.lastSeen, eventAt(latestActivity), noEvidence),
      evidence: evidenceRef(process),
    },
    data: {
      eventType: firstValue(data?.dataEventType, data?.ruleId, embedded.data?.eventType, 'No DLP/exfiltration event observed'),
      sourceFile: firstValue(data?.fileName, data?.filePath, 'No file involved in GPS status event'),
      transferBytes: firstValue(data?.bytesTransferred, embedded.data?.transferBytes, 0),
      bytesSent: firstValue(data?.bytesSent, 0),
      bytesReceived: firstValue(data?.bytesReceived, 0),
      destination: firstValue(data?.destinationDomain, data?.destip, 'No DLP destination observed'),
      dataClassification: firstValue(data?.dataClassification, embedded.data?.dataClassification, 'Unknown'),
      transferChannel: firstValue(data?.transferChannel, embedded.data?.transferChannel, 'No DLP transfer observed'),
      transferProtocol: firstValue(data?.transferProtocol, 'Not applicable'),
      direction: firstValue(data?.direction, 'Not applicable'),
      exfiltrationObserved: Boolean(data && /EXFIL|DLP_BLOCK|DATA_LEAK/i.test(`${data.ruleId || ''} ${data.description || ''}`)),
      scope: firstValue(embedded.data?.scope, 'Latest related agent DLP telemetry'),
      observedAt: firstValue(data && eventAt(data), noEvidence),
      evidence: evidenceRef(data),
    },
    mitre: {
      mapped: Boolean(mitre),
      techniqueId: firstValue(mitre?.mitreTechnique, mitre?.mitreId, mitre?.technique, 'No ATT&CK mapping for GPS sensor status'),
      techniqueName: firstValue(mitre?.technique, mitre?.mitreTechnique, 'Operational location telemetry'),
      tactic: firstValue(mitre?.mitreTactic, 'Not applicable to GPS sensor status'),
      reason: firstValue(mitre?.description, 'GPS status is telemetry, not ATT&CK behavior by itself'),
      confidence: firstValue(mitre?.confidenceScore, 'Not applicable'),
      threatCategory: firstValue(mitre?.threatCategory, 'Operational telemetry'),
      evidence: evidenceRef(mitre),
    },
    policy: {
      policyId: firstValue(event.policyId, embedded.policy?.policyId, 'No policy ID attached'),
      policyName: firstValue(event.policyName, embedded.policy?.policyName, 'AJNAT Device GPS Tracking'),
      category: firstValue(event.policyCategory, embedded.policy?.category, 'Device GPS Tracking'),
      action: firstValue(event.policyAction, embedded.policy?.action, 'LOG & MONITOR'),
      triggered: event.policyTriggered === true || embedded.policy?.triggered === true,
      actionStatus: firstValue(event.policyActionStatus, 'logged'),
      containmentStatus: firstValue(event.containmentStatus, 'none'),
      blocked: event.blocked === true,
      logoutRequested: event.systemLogoutRequested === true || event.sessionRevokeRequested === true,
      lockIsolationRequested: event.geoFenceLockRequested === true,
      ipBlockRequested: event.ipBlockRequested === true,
      requiredAccuracyMeters: requiredAccuracy,
    },
    timeline: {
      observedAt: firstValue(event.gpsObservedAt, eventAt(event)),
      collectedAt: firstValue(event.eventTimestamp, eventAt(event)),
      receivedAt: firstValue(event.receivedAt, event.createdAt),
      queuedAt: firstValue(embedded.timeline?.queuedAt, event.receivedAt, event.createdAt),
      updatedAt: firstValue(event.updatedAt, event.createdAt),
      latestAgentActivityAt: firstValue(eventAt(latestActivity), noEvidence),
      stage: 'server_live_correlation_complete',
      relatedEventCount: relatedCount,
    },
    actions: {
      agentDisposition: firstValue(event.policyActionStatus, event.actionTaken, 'logged'),
      policyAction: firstValue(event.policyAction, 'LOG & MONITOR'),
      containmentStatus: firstValue(event.containmentStatus, 'none'),
      blocked: event.blocked === true,
      responseType: firstValue(responseAction?.actionType, 'No response requested'),
      responseStatus: firstValue(responseAction?.status, 'not_requested'),
      responseUpdatedAt: firstValue(responseAction?.updatedAt, responseAction?.completedAt, 'Not applicable'),
      responseError: firstValue(responseAction?.errorDetail, 'None'),
      recommendedAction: policyEligible ? 'Continue monitoring' : 'Enable GNSS/Wi-Fi location and obtain a fix within the policy accuracy threshold',
    },
  };
}

function isFlagged(row = {}, ...fields) {
  return fields.some(field => row[field] === true || row.rawEvent?.[field] === true);
}

function summarize(rows = [], total = rows.length) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const countries = new Map();
  const users = new Set();
  const endpoints = new Set();
  let impossibleTravel = 0;
  let vpnProxyTor = 0;
  let highRiskLocations = 0;

  rows.forEach(row => {
    const severity = String(row.severity || 'info').toLowerCase();
    bySeverity[bySeverity[severity] === undefined ? 'info' : severity] += 1;
    const country = countryOf(row);
    if (country && country !== 'Unknown') countries.set(country, (countries.get(country) || 0) + 1);
    const user = userOf(row);
    if (user) users.add(String(user));
    const endpoint = row.systemId?._id || row.systemId || row.endpointId || row.agentId || row.hostname || row.agentName;
    if (endpoint) endpoints.add(String(endpoint));
    const rule = `${row.ruleId || ''} ${row.ruleName || ''} ${row.description || ''}`;
    if (/impossible[ _-]?travel/i.test(rule)) impossibleTravel += 1;
    if (isFlagged(row, 'geoVpn', 'vpnDetected', 'geoProxy', 'proxyDetected', 'geoTor', 'torDetected', 'geoHosting')) vpnProxyTor += 1;
    if (isFlagged(row, 'highRiskCountry')) highRiskLocations += 1;
  });

  return {
    totalEvents: total,
    uniqueUsers: users.size,
    endpointsReporting: endpoints.size,
    countriesAccessed: countries.size,
    anomalousEvents: bySeverity.critical + bySeverity.high + bySeverity.medium,
    highRiskEvents: bySeverity.critical + bySeverity.high,
    criticalAlerts: bySeverity.critical,
    impossibleTravel,
    vpnProxyTor,
    highRiskLocations,
    bySeverity,
    topCountries: [...countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10).map(([country, count]) => ({ country, count })),
    averageRiskScore: rows.length ? Math.round(rows.reduce((sum, row) => sum + riskScore(row), 0) / rows.length) : 0,
  };
}

async function loadGeoEvents(companyScope, since, until, { limit = 500, skip = 0, extra = {} } = {}) {
  const query = geoQuery(companyScope, since, until, extra);
  const [events, total] = await Promise.all([
    Alert.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion')
      .lean(),
    Alert.countDocuments(query),
  ]);
  return { events, total };
}

router.get('/overview', requireAnalyst, async (req, res) => {
  try {
    const companyScope = await scope(req);
    const { since, until } = timeRange(req);
    const limit = boundedInt(req.query.limit, 1000, 1, 2000);
    const [{ events, total }, systems] = await Promise.all([
      loadGeoEvents(companyScope, since, until, { limit }),
      System.find({ ...companyScope, isActive: true })
        .select('name hostname os osType ip ipAddress status isOnline agentOk lastSeen agentVersion gpsLat gpsLon gpsAccuracyMeters gpsAltitudeMeters gpsProvider gpsStatus gpsReason gpsObservedAt')
        .sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const bucketCount = 24;
    const timeline = Array.from({ length: bucketCount }, (_, index) => ({ index, count: 0 }));
    const span = Math.max(1, until.getTime() - since.getTime());
    events.forEach(event => {
      const timestamp = new Date(event.timestamp || event.createdAt).getTime();
      if (!Number.isFinite(timestamp)) return;
      const index = Math.min(bucketCount - 1, Math.max(0, Math.floor(((timestamp - since.getTime()) / span) * bucketCount)));
      timeline[index].count += 1;
    });
    res.json({
      events,
      alerts: events,
      total,
      summary: summarize(events, total),
      timeline,
      systems: systems.map(system => withLiveSystemStatus(system)),
      from: since,
      to: until,
    });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get(['/events', '/alerts'], requireAnalyst, async (req, res) => {
  try {
    const companyScope = await scope(req);
    const { since, until } = timeRange(req);
    const page = boundedInt(req.query.page, 1, 1, 1000000);
    const limit = boundedInt(req.query.limit, 100, 1, 1000);
    const extra = {};
    if (req.query.severity) extra.severity = new RegExp(`^${String(req.query.severity).replace(/[^a-z]/gi, '')}$`, 'i');
    if (req.query.status) extra.status = new RegExp(`^${String(req.query.status).replace(/[^a-z_ -]/gi, '')}$`, 'i');
    const { events, total } = await loadGeoEvents(companyScope, since, until, { limit, skip: (page - 1) * limit, extra });
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/statistics', requireAnalyst, async (req, res) => {
  try {
    const companyScope = await scope(req);
    const { since, until } = timeRange(req);
    const { events, total } = await loadGeoEvents(companyScope, since, until, { limit: 2000 });
    res.json({ statistics: summarize(events, total), from: since, to: until });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/heatmap', requireAnalyst, async (req, res) => {
  try {
    const companyScope = await scope(req);
    const { since, until } = timeRange(req);
    const { events } = await loadGeoEvents(companyScope, since, until, { limit: 2000 });
    const grouped = new Map();
    events.forEach(event => {
      const lat = Number(event.gpsLat ?? event.geoLat);
      const lon = Number(event.gpsLon ?? event.geoLon);
      if (!Number.isFinite(lat) || !Number.isFinite(lon)) return;
      const key = `${lat}:${lon}:${countryOf(event)}:${event.geoCity || ''}`;
      const current = grouped.get(key) || { lat, lon, country: countryOf(event), city: event.geoCity, count: 0, riskScore: 0 };
      current.count += 1;
      current.riskScore = Math.max(current.riskScore, riskScore(event));
      grouped.set(key, current);
    });
    res.json({ points: [...grouped.values()].sort((a, b) => b.count - a.count).slice(0, 500) });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/timeline', requireAnalyst, async (req, res) => {
  try {
    const companyScope = await scope(req);
    const { since, until } = timeRange(req);
    const { events } = await loadGeoEvents(companyScope, since, until, { limit: boundedInt(req.query.limit, 500, 1, 2000) });
    res.json({ timeline: events.map(event => ({
      id: event._id, timestamp: event.timestamp || event.createdAt, user: userOf(event), endpoint: event.hostname || event.agentName,
      ip: event.srcip, country: countryOf(event), city: event.geoCity, ruleId: event.ruleId, severity: event.severity, riskScore: riskScore(event),
    })) });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get(['/events/:id', '/alerts/:id'], requireAnalyst, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid geolocation event id' });
    const companyScope = await scope(req);
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope, ...geolocationEvidenceFilter() })
      .populate('systemId', 'name hostname ip ipAddress os osType status isOnline lastSeen agentVersion gpsLat gpsLon gpsAccuracyMeters gpsAltitudeMeters gpsProvider gpsStatus gpsReason gpsObservedAt').lean();
    if (!event) return res.status(404).json({ message: 'Geolocation event not found' });
    const responseAction = await AutomatedResponse.findOne({ alertId: event._id, companyId: event.companyId })
      .sort({ updatedAt: -1, createdAt: -1 })
      .select('actionType status actionResult errorDetail approvalStatus trigger createdAt updatedAt startedAt completedAt')
      .lean();
    const liveForensics = await buildLiveForensics(event, responseAction);
    res.json({ event: { ...event, responseAction: responseAction || null, liveForensics } });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.post('/respond', requireManager, async (req, res) => {
  try {
    const actionType = String(req.body.actionType || '').trim();
    const reason = String(req.body.reason || '').trim();
    if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
    if (!IDENTITY_RESPONSE_ACTIONS.has(actionType)) return res.status(400).json({ message: 'Supported geolocation identity actions: lock_account, force_logoff, isolate' });
    if (req.body.confirmed !== true || reason.length < 5) return res.status(400).json({ message: 'confirmed=true and a reason of at least 5 characters are required' });

    const eventScope = await responseScope(req);
    const alert = await Alert.findOne({ _id: req.body.alertId, ...eventScope, ...geolocationEvidenceFilter() });
    if (!alert) return res.status(404).json({ message: 'Geolocation event not found in your assigned scope' });
    const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId, isActive: true });
    if (!system) return res.status(409).json({ message: 'Target AJNAT endpoint is unavailable' });
    const tenantId = alert.tenantId || system.tenantId;
    if (!tenantId) return res.status(409).json({ message: 'Target event has no tenant identity and cannot be actioned safely' });

    const actionParams = { ...(req.body.actionParams || {}) };
    if (['lock_account', 'force_logoff'].includes(actionType)) {
      actionParams.username = String(actionParams.username || alert.username || alert.user || '').trim();
      if (!isSafeLocalUsername(actionParams.username)) {
        return res.status(409).json({ message: 'A verified endpoint-local, non-service username is required for account lock or logout' });
      }
    }
    const duplicate = await AutomatedResponse.findOne({
      companyId: alert.companyId,
      alertId: alert._id,
      systemId: system._id,
      actionType,
      status: { $in: [...ACTIVE_STATUSES] },
    }).select('_id status').lean();
    if (duplicate) return res.status(409).json({ message: `This ${actionType.replaceAll('_', ' ')} response is already ${duplicate.status}`, responseId: duplicate._id });
    const actorId = req.user.id || req.user._id;
    const response = await createResponse({
      companyId: alert.companyId,
      tenantId,
      alert,
      system,
      actionType,
      actionParams,
      triggeredBy: actorId,
      trigger: 'manual',
      io: req.app.get('io'),
      forceApproval: true,
    });
    const protectionEvent = await trackIdentityProtectionResponse({
      response,
      alert,
      system,
      actor: req.user,
      reason,
      io: req.app.get('io'),
    });
    if (alert.tenantId || system.tenantId) await SocAuditEvent.create({
      tenantId: alert.tenantId || system.tenantId,
      companyId: alert.companyId,
      actorId,
      action: `geolocation.response.${actionType}.requested`,
      targetType: 'UebaProfileLockEvent',
      targetId: String(protectionEvent._id),
      metadata: {
        alertId: String(alert._id),
        systemId: String(system._id),
        responseId: String(response._id),
        username: actionParams.username || String(alert.username || ''),
        reason: reason.slice(0, 500),
      },
    });
    res.status(202).json({ response, protectionEvent });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/policies', requireAnalyst, async (req, res) => {
  try {
    const policyScope = await scope(req);
    await ensureBuiltInPolicies(policyScope, req.user._id || req.user.id);
    const policies = await GeolocationPolicy.find(policyScope).sort({ priority: 1, updatedAt: -1 }).lean();
    res.json({ policies });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/policies/:id', requireAnalyst, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid geolocation policy id' });
    const policy = await GeolocationPolicy.findOne({ _id: req.params.id, ...(await scope(req)) }).lean();
    if (!policy) return res.status(404).json({ message: 'Geolocation policy not found' });
    res.json({ policy });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.get('/systems', requireAnalyst, async (req, res) => {
  try {
    const systems = await System.find({ ...(await scope(req)), isActive: true })
      .select('name hostname agentName os osType ip ipAddress macAddress status isOnline agentOk lastSeen agentVersion gpsLat gpsLon gpsAccuracyMeters gpsAltitudeMeters gpsProvider gpsStatus gpsReason gpsObservedAt')
      .sort({ lastSeen: -1 }).lean();
    res.json({ systems: systems.map(system => withLiveSystemStatus(system)) });
  } catch (err) { res.status(err.status || 500).json({ message: err.message }); }
});

router.post('/policies', requireManager, async (req, res) => {
  try {
    const policyScope = await scope(req);
    const actorId = req.user._id || req.user.id;
    const payload = {
      ...policyScope,
      name: req.body.name,
      description: req.body.description || '',
      category: req.body.category || req.body.cat,
      severity: req.body.severity || 'Medium',
      action: req.body.action,
      enabled: req.body.enabled !== false,
      priority: Number(req.body.priority) || 100,
      conditions: req.body.conditions || req.body.details || {},
      createdBy: actorId,
      updatedBy: actorId,
    };
    validatePolicyConfiguration(payload);
    await validatePolicyTargets(payload, policyScope);
    const policy = await GeolocationPolicy.create(payload);
    req.app.get('io')?.to(`company:${policyScope.companyId}`).emit('geo:policy-updated', { id: policy._id });
    res.status(201).json({ policy });
  } catch (err) { res.status(err.status || 400).json({ message: err.message }); }
});

async function updatePolicy(req, res) {
  try {
    const policyScope = await scope(req);
    const existing = await GeolocationPolicy.findOne({ _id: req.params.id, ...policyScope }).lean();
    if (!existing) return res.status(404).json({ message: 'Geolocation policy not found' });
    const allowed = ['name', 'description', 'category', 'severity', 'action', 'enabled', 'priority', 'conditions'];
    const update = Object.fromEntries(allowed.filter(key => req.body[key] !== undefined).map(key => [key, req.body[key]]));
    update.updatedBy = req.user._id || req.user.id;
    validatePolicyConfiguration({ ...existing, ...update });
    await validatePolicyTargets({ ...existing, ...update }, policyScope);
    const policy = await GeolocationPolicy.findOneAndUpdate(
      { _id: req.params.id, ...policyScope },
      { $set: update, $inc: { version: 1 } },
      { new: true, runValidators: true },
    );
    if (!policy) return res.status(404).json({ message: 'Geolocation policy not found' });
    req.app.get('io')?.to(`company:${policyScope.companyId}`).emit('geo:policy-updated', { id: policy._id });
    res.json({ policy });
  } catch (err) { res.status(err.status || 400).json({ message: err.message }); }
}

router.patch('/policies/:id', requireManager, updatePolicy);
router.put('/policies/:id', requireManager, updatePolicy);

router.delete('/policies/:id', requireManager, async (req, res) => {
  try {
    const policyScope = await scope(req);
    const policy = await GeolocationPolicy.findOneAndDelete({ _id: req.params.id, ...policyScope });
    if (!policy) return res.status(404).json({ message: 'Geolocation policy not found' });
    res.json({ ok: true });
  } catch (err) { res.status(err.status || 400).json({ message: err.message }); }
});

module.exports = router;
