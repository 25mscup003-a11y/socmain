/**
 * idsips.routes.js — Unified IDS/IPS Status & Data API
 *
 * GET  /api/idsips/status       — Combined IDS/IPS stats (role-scoped)
 * GET  /api/ipserver/status     — Real IPS server connectivity check (ping/socket)
 * GET  /api/idsips/logs         — Real-time IDS/IPS event logs
 * GET  /api/idsips/threats      — Aggregated threat summary
 * GET  /api/idsips/summary      — Dashboard summary for widgets
 */

const router = require('express').Router();
const http   = require('http');
const https  = require('https');
const net    = require('net');
const Alert  = require('../models/Alert.model');
const { BlockedIP } = require('../services/ips.service');
const { authenticate, requireAnalyst, requireSuperAdmin } = require('../middleware/auth.middleware');
const { CAPABILITY_GROUPS, listAttackTypes, resolveAttackType } = require('../constants/idsIpsCapabilities');
const threatIntel = require('../services/threat-intel.service');
const ipEnrichmentService = require('../services/ipEnrichmentService');
const { loadIdsAlertRollup } = require('../services/idsSummary.service');

const idsLogCountCache = new Map();
const IDS_LOG_COUNT_CACHE_MS = 60 * 1000;

const IPS_URL    = process.env.IPS_WEBHOOK_URL    || 'http://localhost:5050';
const IPS_SECRET = process.env.IPS_WEBHOOK_SECRET || '';
const IDS_IPS_EVENT_CATEGORIES = [
  'ids_alert',
  'ips_block',
  'ips_action',
  'blacklist_event',
  'intrusion_detection',
  'intrusion_prevention',
];
const IDS_IPS_LOG_EVENT_CATEGORIES = [...IDS_IPS_EVENT_CATEGORIES, 'network_telemetry'];
const IDS_SENSOR_NOISE_RULE_IDS = [
  'SURICATA_2200003',
  'SURICATA_2210045',
  'SURICATA_2210046',
  'ZEEK_truncated_tcp_payload',
];

function withoutSensorNoise(conditions = []) {
  return [
    ...conditions,
    { ruleId: { $nin: IDS_SENSOR_NOISE_RULE_IDS } },
    { $nor: [{ source: 'zeek', ruleId: 'ZEEK_weird', signatureName: /^truncated_tcp_payload$/i }] },
  ];
}

function idsIpsLogMatch(extra = {}) {
  const { $and = [], ...rest } = extra;
  return {
    ...rest,
    $and: withoutSensorNoise([
      ...$and,
      {
        $or: [
          { event_category: { $in: IDS_IPS_LOG_EVENT_CATEGORIES } },
          { event_category: null, module: { $in: ['IDS', 'IPS', 'ids', 'ips'] } },
          { event_category: null, source_type: { $in: ['IDS', 'IPS', 'ids', 'ips'] } },
          { event_category: null, sourceType: { $in: ['IDS', 'IPS', 'ZEEK'] } },
          { event_category: null, source: { $in: ['suricata', 'zeek', 'ids', 'ips'] } },
          { event_category: null, type: { $in: ['IDS_ALERT', 'IDS_TELEMETRY', 'IPS_BLOCK', 'BLACKLIST_EVENT'] } },
        ],
      },
    ]),
  };
}

function strictIdsIpsAlertMatch(extra = {}) {
  const { $and = [], ...rest } = extra;
  return {
    ...rest,
    $and: withoutSensorNoise([
      ...$and,
      { event_category: { $in: IDS_IPS_EVENT_CATEGORIES } },
    ]),
  };
}

async function resolveIdsIpsWindow(companyFilter, hours = 24) {
  const now = new Date();
  const windowMs = hours * 60 * 60 * 1000;
  const liveFilter = strictIdsIpsAlertMatch({
    ...companyFilter,
    createdAt: { $gte: new Date(now.getTime() - windowMs) },
  });
  return { filter: liveFilter, isStale: false, capturedAt: null };
}

router.get('/idsips/public-debug-unknowns', async (req, res) => {
  try {
    const alerts = await Alert.find({
      $or: [{ attackType: 'Unknown Attack' }, { attackType: null }]
    })
      .select('description ruleId type attackType severity')
      .limit(20)
      .lean();
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── All routes require authentication ────────────────────────────────────────
router.use(authenticate, requireAnalyst);

// ── Helper: check IPS server connectivity via socket ─────────────────────────
async function checkIPSServerConnectivity(timeout = 3000) {
  const parsed = new URL(IPS_URL);
  const host   = parsed.hostname;
  const port   = parseInt(parsed.port || (parsed.protocol === 'https:' ? '443' : '80'), 10);

  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeout);

    socket.on('connect', () => {
      socket.destroy();
      resolve({ online: true, host, port });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ online: false, host, port, reason: 'Connection timed out' });
    });

    socket.on('error', (err) => {
      socket.destroy();
      resolve({ online: false, host, port, reason: err.message });
    });

    socket.connect(port, host);
  });
}

// ── Helper: fetch live IPS server data ────────────────────────────────────────
function fetchIPSServer(path, companyId = '') {
  return new Promise((resolve, reject) => {
    const parsed   = new URL(IPS_URL + path);
    const protocol = parsed.protocol === 'https:' ? https : http;

    const headers = { 'Content-Type': 'application/json' };
    if (IPS_SECRET)  headers['X-Webhook-Secret'] = IPS_SECRET;
    if (companyId) {
      // Send both headers: X-Company-ID (canonical, checked first by IPS middleware)
      // and X-Company (legacy, backward compat)
      headers['X-Company-ID'] = companyId.toString();
      headers['X-Company']    = companyId.toString();
    }

    const req = protocol.request({
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   'GET',
      headers,
    }, (res) => {
      let data = '';
      res.on('data', (c) => { data += c; });
      res.on('end', () => {
        try { resolve(JSON.parse(data)); } catch { resolve({}); }
      });
    });

    req.setTimeout(5000, () => { req.destroy(); reject(new Error('IPS server timeout')); });
    req.on('error', reject);
    req.end();
  });
}

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/ipserver/status
// Real connectivity check using a raw TCP socket (no hardcoded "online")
// ──────────────────────────────────────────────────────────────────────────────
router.get('/ipserver/status', async (req, res) => {
  try {
    const connectivity = await checkIPSServerConnectivity();

    if (!connectivity.online) {
      return res.json({
        online:  false,
        status:  'offline',
        host:    connectivity.host,
        port:    connectivity.port,
        reason:  connectivity.reason,
        checked: new Date().toISOString(),
      });
    }

    // If socket connected, try to get live stats
    try {
      const live = await fetchIPSServer('/health', '');
      return res.json({
        online:     true,
        status:     'online',
        host:       connectivity.host,
        port:       connectivity.port,
        uptime:     live.uptime,
        ok:         live.ok,
        checked:    new Date().toISOString(),
      });
    } catch {
      // Socket connected but HTTP failed — still online
      return res.json({
        online:  true,
        status:  'online',
        host:    connectivity.host,
        port:    connectivity.port,
        checked: new Date().toISOString(),
      });
    }
  } catch (err) {
    console.error('[ipserver/status]', err.message);
    res.json({
      online:  false,
      status:  'offline',
      reason:  err.message,
      checked: new Date().toISOString(),
    });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/idsips/capabilities
// Canonical IDS/IPS coverage registry used by dashboard + install agent config
// ──────────────────────────────────────────────────────────────────────────────
router.get('/idsips/capabilities', (req, res) => {
  const attackTypes = listAttackTypes();
  res.json({
    ok: true,
    generatedAt: new Date().toISOString(),
    groups: CAPABILITY_GROUPS,
    attackTypes,
    totals: {
      groups: CAPABILITY_GROUPS.length,
      capabilities: CAPABILITY_GROUPS.reduce((sum, group) => sum + group.capabilities.length, 0),
      attackTypes: attackTypes.length,
    },
    notes: [
      'Counts/logs remain real-data-only. This endpoint describes monitoring coverage, it does not create fake alerts.',
      'SYN/FIN/NULL/XMAS/ACK scans and packet-level detections require Suricata/Zeek or packet capture telemetry.',
      'Web attacks are detected by the WAF/IDS sensor and only appear in IDS/IPS when emitted as IDS/IPS alerts or IPS block events.',
    ],
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/idsips/status
// Combined IDS + IPS stats, role-scoped
// Superadmin: all companies | Company admin: own company only
// ──────────────────────────────────────────────────────────────────────────────
router.get('/idsips/status', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const mongoose = require('mongoose');

    // Resolve companyId filter
    let companyFilter = {};
    if (!isSuperAdmin) {
      const cid = req.user.companyId;
      companyFilter.companyId = new mongoose.Types.ObjectId(cid);
    } else if (req.query.companyId) {
      companyFilter.companyId = new mongoose.Types.ObjectId(req.query.companyId);
    }

    const { filter: alertFilter24h, isStale, capturedAt } = await resolveIdsIpsWindow(companyFilter, 24);

    const [
      totalAlerts24h,
      blockedAlerts24h,
      criticalAlerts24h,
      highAlerts24h,
      bySeverity,
      bySource,
      byCategory,
      topSrcIps,
      recentAlerts,
      alertsTimeline,
      activeBlocksCount,
      totalBlocksCount,
      activeAgents,
    ] = await Promise.all([
      Alert.countDocuments(alertFilter24h).maxTimeMS(5000).catch(() => 0),
      Alert.countDocuments({ ...alertFilter24h, blocked: true }).maxTimeMS(5000).catch(() => 0),
      Alert.countDocuments({ ...alertFilter24h, severity: 'critical' }).maxTimeMS(5000).catch(() => 0),
      Alert.countDocuments({ ...alertFilter24h, severity: 'high' }).maxTimeMS(5000).catch(() => 0),
      Alert.aggregate([
        { $match: alertFilter24h },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.aggregate([
        { $match: alertFilter24h },
        { $group: { _id: '$source', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.aggregate([
        { $match: alertFilter24h },
        { $group: {
          _id: '$eventCategory',
          count:    { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity','critical'] }, 1, 0] } },
          high:     { $sum: { $cond: [{ $eq: ['$severity','high']     }, 1, 0] } },
          blocked:  { $sum: { $cond: ['$blocked', 1, 0] } },
        }},
        { $sort: { count: -1 } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.aggregate([
        { $match: { ...alertFilter24h, srcip: { $exists: true, $nin: [null, ''] } } },
        { $group: { _id: '$srcip', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.find(alertFilter24h)
        .sort({ createdAt: -1 })
        .limit(50)
        .select('source eventCategory severity description ruleId signatureName srcip srcPort destip destPort protocol packetCount cveId mitre mitreId domain processName pid createdAt lastOccurrenceAt occurrenceCount blocked type agentName companyId')
        .maxTimeMS(5000)
        .lean()
        .catch(() => []),
      Alert.aggregate([
        { $match: alertFilter24h },
        { $group: { _id: { $hour: '$createdAt' }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      BlockedIP.countDocuments({ ...companyFilter, reverted: false }).maxTimeMS(4000).catch(() => 0),
      BlockedIP.countDocuments(companyFilter).maxTimeMS(4000).catch(() => 0),
      Alert.distinct('agentName', alertFilter24h).maxTimeMS(4000).catch(() => []),
    ]);

    // Try to get live IPS server blocklist count
    let ipsLiveBlocked = 0;
    let ipsServerOnline = false;
    try {
      const companyId = isSuperAdmin ? (req.query.companyId || '') : (req.user.companyId?.toString() || '');
      const qs = companyId ? `?company=${companyId}` : '';
      const live = await fetchIPSServer(`/status${qs}`, companyId);
      ipsLiveBlocked = live.blockedCount || live.active_blocks || 0;
      ipsServerOnline = true;
    } catch {
      // IPS server offline — use DB counts
      ipsLiveBlocked = activeBlocksCount;
    }

    // Build severity map
    const sevMap = {};
    bySeverity.forEach(s => { sevMap[s._id] = s.count; });

    // Build category map
    const catMap = {};
    byCategory.forEach(c => { catMap[c._id] = c; });

    // Fill sparkline (24h by hour)
    const timeMap = {};
    alertsTimeline.forEach(t => { timeMap[t._id] = t.count; });
    const sparkline = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: timeMap[i] || 0 }));

    res.json({
      ok: true,
      period: isStale ? 'Latest available 24h snapshot' : '24h',
      isStale,
      capturedAt,
      // Aggregate KPIs
      total:    totalAlerts24h,
      blocked:  blockedAlerts24h,
      critical: criticalAlerts24h,
      high:     highAlerts24h,
      // IPS blocklist
      ipsBlocked:     ipsLiveBlocked,
      dbBlocked:      activeBlocksCount,
      totalBlocks:    totalBlocksCount,
      ipsServerOnline,
      // Severity breakdown
      severity: {
        critical: sevMap['critical'] || 0,
        high:     sevMap['high']     || 0,
        medium:   sevMap['medium']   || 0,
        low:      sevMap['low']      || 0,
      },
      // Category breakdown
      categories: {
        network: catMap['network']  || { count: 0, critical: 0, high: 0, blocked: 0 },
        malware: catMap['malware']  || { count: 0, critical: 0, high: 0, blocked: 0 },
        edr:     catMap['edr']      || { count: 0, critical: 0, high: 0, blocked: 0 },
        file:    catMap['file']     || { count: 0, critical: 0, high: 0, blocked: 0 },
        system:  catMap['system']   || { count: 0, critical: 0, high: 0, blocked: 0 },
      },
      // Sources
      sources:    bySource,
      // Top IPs
      topSrcIps,
      // Active agents
      agentNetwork:  activeAgents.length,
      activeAgents:  activeAgents.filter(Boolean),
      // Recent events
      recentAlerts,
      // Sparkline
      sparkline,
      // Meta
      isSuperAdmin,
      companyFilter: isSuperAdmin ? (req.query.companyId || 'all') : req.user.companyId,
    });
  } catch (err) {
    console.error('[idsips/status]', err);
    res.status(500).json({ message: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/idsips/logs
// Real-time IDS/IPS event logs from DB
// ──────────────────────────────────────────────────────────────────────────────
router.get('/idsips/logs', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const mongoose = require('mongoose');
    const { page = 1, limit = 100, severity, sourceType, category, from, to, search, agent } = req.query;
    const includeTelemetry = req.query.includeTelemetry === 'true';
    const countOnly = req.query.countOnly === 'true';
    const skipCount = req.query.skipCount === 'true';
    const pageNumber = Math.max(1, Number(page) || 1);
    const pageLimit = Math.min(500, Math.max(1, Number(limit) || 100));
    const retentionDays = 90;
    const queryWindowDays = req.query.range === 'retention' ? retentionDays : 1;
    const retentionStart = new Date(Date.now() - queryWindowDays * 24 * 60 * 60 * 1000);

    let filter = {};
    if (!isSuperAdmin) {
      filter.companyId = new mongoose.Types.ObjectId(req.user.companyId);
    } else if (req.query.companyId) {
      filter.companyId = new mongoose.Types.ObjectId(req.query.companyId);
    }

    if (sourceType === 'IPS') {
      filter.$or = [
        { module: /ips/i },
        { source_type: /ips/i },
        { event_category: /ips/i },
        { source: /ips/i },
        { type: /ips/i },
        { blocked: true }
      ];
    } else if (sourceType === 'IDS') {
      filter.$and = [
        { module: { $not: /ips/i } },
        { source_type: { $not: /ips/i } },
        { event_category: { $not: /ips/i } },
        { source: { $not: /ips/i } },
        { type: { $not: /ips/i } },
        { blocked: { $ne: true } }
      ];
    }

    if (agent && agent !== 'ALL') {
      const agentFilterObj = {
        $or: [
          { agentName: agent },
          { hostname: agent },
          { source: agent }
        ]
      };
      if (filter.$and) {
        filter.$and.push(agentFilterObj);
      } else {
        filter.$and = [agentFilterObj];
      }
    }

    if (category) filter.eventCategory = category;
    filter.createdAt = { $gte: retentionStart };
    if (from) {
      const requestedFrom = new Date(from);
      if (!Number.isNaN(requestedFrom.getTime()) && requestedFrom > retentionStart) filter.createdAt.$gte = requestedFrom;
    }
    if (to) {
      const requestedTo = new Date(to);
      if (!Number.isNaN(requestedTo.getTime())) filter.createdAt.$lte = requestedTo;
    }

    if (search) {
      const q = search.trim();
      const searchRegex = { $regex: q, $options: 'i' };
      const searchOr = [
        { description: searchRegex },
        { srcip: searchRegex },
        { destip: searchRegex },
        { agentName: searchRegex },
        { ruleId: searchRegex },
        { type: searchRegex },
        { status: searchRegex },
        { actionTaken: searchRegex },
      ];
      if (filter.$and) {
        filter.$and.push({ $or: searchOr });
      } else if (filter.$or) {
        filter.$and = [{ $or: filter.$or }, { $or: searchOr }];
        delete filter.$or;
      } else {
        filter.$or = searchOr;
      }
    }

    const matchIdsIpsRecords = includeTelemetry ? idsIpsLogMatch : strictIdsIpsAlertMatch;
    const countFilter = matchIdsIpsRecords({ ...filter });

    if (severity && severity !== 'all') {
      filter.severity = severity.toLowerCase();
    }
    const queryFilter = matchIdsIpsRecords(filter);

    const normalizedSeverity = {
      $let: {
        vars: { raw: { $toLower: { $toString: { $ifNull: ['$severity', 'low'] } } } },
        in: {
          $switch: {
            branches: [
              { case: { $in: ['$$raw', ['critical', 'crit', 'fatal', 'emergency', 'emerg', '0', '1', '2']] }, then: 'critical' },
              { case: { $in: ['$$raw', ['high', '3']] }, then: 'high' },
              { case: { $in: ['$$raw', ['medium', 'med', 'warning', 'warn', 'error', 'err', 'alert', 'block', 'blocked', '4', '5']] }, then: 'medium' },
            ],
            default: 'low',
          },
        },
      },
    };

    const countCacheKey = [
      String(filter.companyId || 'all'), includeTelemetry, queryWindowDays,
      sourceType || 'ALL', category || '', search || '', agent || 'ALL', from || '', to || '',
    ].join('|');
    const cachedCounts = idsLogCountCache.get(countCacheKey);
    const emptyCounts = { low: 0, medium: 0, high: 0, critical: 0, total: 0 };
    const countsPromise = skipCount
      ? Promise.resolve(emptyCounts)
      : cachedCounts?.expiresAt > Date.now()
      ? Promise.resolve(cachedCounts.counts)
      : Alert.aggregate([
        { $match: countFilter },
        { $group: { _id: normalizedSeverity, count: { $sum: 1 } } }
      ]).option({ maxTimeMS: 30000 }).then(rows => {
        const nextCounts = { low: 0, medium: 0, high: 0, critical: 0, total: 0 };
        rows.forEach(row => {
          if (!row._id) return;
          nextCounts[row._id.toLowerCase()] = row.count;
          nextCounts.total += row.count;
        });
        idsLogCountCache.set(countCacheKey, {
          counts: nextCounts,
          expiresAt: Date.now() + IDS_LOG_COUNT_CACHE_MS,
        });
        return nextCounts;
      }).catch(() => emptyCounts);

    const [logs, counts] = await Promise.all([
      countOnly ? Promise.resolve([]) : Alert.find(queryFilter)
        .sort({ createdAt: -1 })
        .skip((pageNumber - 1) * pageLimit)
        .limit(pageLimit)
        .select('source module source_type event_category eventCategory severity description signatureName srcip srcPort destip destPort protocol packetCount cveId mitre mitreId domain processName pid createdAt lastOccurrenceAt occurrenceCount blocked actionable type agentName companyId ruleId status actionTaken containmentStatus detectionSource aiInvestigation asn asnOrg asnDomain geoCountry geoCountryCode geoContinent geoContinentCode geoCity geoRegion geoPostal geoTimezone geoLoc geoProxy geoHosting geoVpn geoTor geoRelay geoAnycast geoHostname geoAbuseEmail geoAbusePhone geoAbuseAddress geoAbuseNetwork geoDomainsCount geoAsnRoute destAsn destAsnOrg destAsnDomain destGeoCountry destGeoCountryCode destGeoContinent destGeoContinentCode destGeoCity destGeoRegion destGeoPostal destGeoTimezone destGeoLoc destGeoProxy destGeoHosting destGeoVpn destGeoTor destGeoRelay destGeoAnycast destGeoHostname destGeoAbuseEmail destGeoAbusePhone destGeoAbuseAddress destGeoAbuseNetwork destGeoDomainsCount destGeoAsnRoute tiSummary tiConfidence tiEnriched')
        .maxTimeMS(15000)
        .lean()
        .catch(() => []),
      countsPromise,
    ]);

    const total = severity && severity !== 'all'
      ? Number(counts[severity.toLowerCase()] || 0)
      : counts.total;
    const uniqueAgents = [...new Set(logs.flatMap(log => [log.agentName, log.hostname]).filter(Boolean))];

    res.json({
      logs,
      total,
      overallTotal: counts.total,
      retentionDays,
      queryWindowDays,
      retentionStart,
      page: pageNumber,
      limit: pageLimit,
      severityCounts: counts,
      agents: uniqueAgents
    });
  } catch (err) {
    console.error('[idsips/logs]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/idsips/threats
// Threat intelligence summary
// ──────────────────────────────────────────────────────────────────────────────
router.get('/idsips/threats', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const mongoose = require('mongoose');
    const hours = parseInt(req.query.hours || '24', 10);

    let companyFilter = {};
    if (!isSuperAdmin) {
      companyFilter.companyId = new mongoose.Types.ObjectId(req.user.companyId);
    } else if (req.query.companyId) {
      companyFilter.companyId = new mongoose.Types.ObjectId(req.query.companyId);
    }

    const { filter, isStale, capturedAt } = await resolveIdsIpsWindow(companyFilter, hours);

    const [total, byLevel, byType, topIPs, topDests, recentCritical, recentAlerts] = await Promise.all([
      Alert.countDocuments(filter).maxTimeMS(5000).catch(() => 0),
      Alert.aggregate([
        { $match: filter },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.aggregate([
        { $match: filter },
        {
          $group: {
            _id: {
              description: '$description',
              ruleId: '$ruleId',
              type: '$type',
              attackType: '$attackType'
            },
            count: { $sum: 1 },
            severity: { $max: '$severity' },
          },
        },
      ]).option({ maxTimeMS: 8000 }).catch(() => []),
      Alert.aggregate([
        { $match: { ...filter, srcip: { $exists: true, $ne: null } } },
        { $group: { _id: '$srcip', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.aggregate([
        { $match: { ...filter, destip: { $exists: true, $ne: null } } },
        { $group: { _id: '$destip', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      Alert.find({ ...filter, severity: { $in: ['critical','high'] } })
        .sort({ createdAt: -1 })
        .limit(20)
        .select('severity description srcip srcPort destip destPort protocol packetCount cveId mitre mitreId domain processName pid createdAt lastOccurrenceAt occurrenceCount blocked type source agentName ruleId attackType signatureName status actionTaken containmentStatus detectionSource geoCountry geoCountryCode geoCity destGeoCountry destGeoCountryCode destGeoCity')
        .maxTimeMS(5000)
        .lean()
        .catch(() => []),
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .limit(500)
        .select('severity description srcip srcPort destip destPort protocol packetCount cveId mitre mitreId domain processName pid createdAt lastOccurrenceAt occurrenceCount blocked type source agentName ruleId attackType signatureName status actionTaken containmentStatus detectionSource geoCountry geoCountryCode geoCity destGeoCountry destGeoCountryCode destGeoCity')
        .maxTimeMS(8000)
        .lean()
        .catch(() => []),
    ]);

    const levMap = {};
    byLevel.forEach(l => {
      const key = String(l._id || 'low').toLowerCase();
      levMap[key] = l.count;
    });

    const typeMap = {};
    byType.forEach(t => {
      const { description, ruleId, type, attackType } = t._id || {};
      let resolved = 'Unknown Attack';
      if (attackType && attackType !== 'Unknown Attack') {
        resolved = attackType;
      } else {
        resolved = resolveAttackType(description, ruleId, type);
      }
      if (!typeMap[resolved]) {
        typeMap[resolved] = { type: resolved, count: 0, level: 'low' };
      }
      typeMap[resolved].count += t.count;

      const priority = { critical: 4, high: 3, medium: 2, low: 1 };
      const currentLevel = typeMap[resolved].level;
      const tSeverity = t.severity || 'low';
      if (priority[tSeverity] > priority[currentLevel]) {
        typeMap[resolved].level = tSeverity;
      }
    });

    const finalByType = Object.values(typeMap)
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    // Enrichment is useful but external lookups must never block the dashboard
    // response. Persist missing country data in the background for later reads.
    const rowsNeedingCountry = recentAlerts.filter(row => !row.geoCountry);
    if (rowsNeedingCountry.length) {
      setImmediate(() => (async () => {
        const indicatorById = new Map();
        for (const row of rowsNeedingCountry) {
          const indicator = threatIntel.isPublicIp(row.srcip)
            ? row.srcip
            : (threatIntel.isPublicIp(row.destip) ? row.destip : null);
          if (indicator) indicatorById.set(String(row._id), indicator);
          if (new Set(indicatorById.values()).size >= 40) break;
        }
        const uniqueIndicators = [...new Set(indicatorById.values())];
        const geoResults = await Promise.allSettled(uniqueIndicators.map(ip => ipEnrichmentService.enrichIp(ip)));
        const geoByIp = new Map();
        geoResults.forEach((result, index) => {
          if (result.status === 'fulfilled' && result.value?.country) geoByIp.set(uniqueIndicators[index], result.value);
        });
        const geoWrites = [];
        rowsNeedingCountry.forEach(row => {
          const geo = geoByIp.get(indicatorById.get(String(row._id)));
          if (!geo) return;
          geoWrites.push({
            updateOne: {
              filter: { _id: row._id },
              update: { $set: { geoCountry: geo.country, geoCountryCode: geo.countryCode || '', geoCity: geo.city || '' } },
            },
          });
        });
        if (geoWrites.length) await Alert.bulkWrite(geoWrites, { ordered: false });
      })().catch(error => console.warn('[idsips/threats] Country persistence failed:', error.message)));
    }

    res.json({
      ok: true,
      period:   isStale ? 'Latest available snapshot' : `${hours}h`,
      isStale,
      capturedAt,
      total,
      byLevel:  levMap,
      byType:   finalByType,
      topIPs:   topIPs.map(ip => ({ ip: ip._id, count: ip.count })),
      topDests: topDests.map(d  => ({ ip: d._id,  count: d.count })),
      recentCritical,
      recentAlerts,
    });
  } catch (err) {
    console.error('[idsips/threats]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET /api/idsips/summary — quick widget summary (for dashboards)
// ──────────────────────────────────────────────────────────────────────────────
router.get('/idsips/summary', async (req, res) => {
  try {
    const isSuperAdmin = req.user.role === 'superadmin';
    const mongoose = require('mongoose');
    let companyFilter = {};
    if (!isSuperAdmin) {
      companyFilter.companyId = new mongoose.Types.ObjectId(req.user.companyId);
    } else if (req.query.companyId) {
      companyFilter.companyId = new mongoose.Types.ObjectId(req.query.companyId);
    }
    if (req.query.systemId && mongoose.Types.ObjectId.isValid(String(req.query.systemId))) {
      companyFilter.systemId = new mongoose.Types.ObjectId(String(req.query.systemId));
    }

    const { filter, isStale, capturedAt } = await resolveIdsIpsWindow(companyFilter, 24);

    // Check IPS server connectivity (non-blocking — parallel with DB queries)
    // Dashboard data must not wait several seconds for an optional IPS
    // process. The durable MongoDB blocklist remains authoritative here.
    const connectivityPromise = checkIPSServerConnectivity(750).catch(() => ({ online: false }));

    const [alertRollup, ipsBlockedFromDb] = await Promise.all([
      loadIdsAlertRollup(Alert, filter),
      BlockedIP.countDocuments({
        ...(isSuperAdmin ? {} : { companyId: req.user.companyId }),
        reverted: false,
      }).maxTimeMS(10000),
    ]);
    const { total, blocked, critical, high } = alertRollup;

    // Resolve connectivity (was running in parallel)
    const connectivity = await connectivityPromise;
    const ipsBlockedCount = ipsBlockedFromDb;

    res.json({
      ok:            true,
      total,
      blocked,
      critical,
      high,
      capabilities: CAPABILITY_GROUPS.reduce((sum, group) => sum + group.capabilities.length, 0),
      ipsBlocked:    ipsBlockedCount,
      ipsOnline:     connectivity.online,
      ipsStatus:     connectivity.online ? 'online' : 'offline',
      checked:       new Date().toISOString(),
      isStale,
      capturedAt,
    });
  } catch (err) {
    console.error('[idsips/summary]', err.message);
    res.status(503).json({
      ok: false,
      message: 'IDS summary is temporarily unavailable',
      code: 'IDS_SUMMARY_QUERY_FAILED',
    });
  }
});

router.get('/idsips/debug-unknowns', async (req, res) => {
  try {
    const alerts = await Alert.find({
      $or: [{ attackType: 'Unknown Attack' }, { attackType: null }]
    })
      .select('description ruleId type attackType severity')
      .limit(20)
      .lean();
    res.json(alerts);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
