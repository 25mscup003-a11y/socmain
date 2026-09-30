/**
 * edr-capabilities.routes.js
 *
 * 31-Point EDR Capability Status & Gap Analysis API
 * GET  /api/edr-cap/status          — Full 31-capability audit
 * GET  /api/edr-cap/coverage-stats  — Stats per capability category
 * GET  /api/edr-cap/new-services    — New detection services added
 * POST /api/edr-cap/sandbox         — Sandbox file analysis (static)
 * GET  /api/edr-cap/patch-status    — Patch/vulnerability summary
 * GET  /api/edr-cap/cloud-events    — Cloud/SaaS event log
 * GET  /api/edr-cap/email-threats   — Email threat log
 * GET  /api/edr-cap/geo-anomalies   — Geolocation anomaly summary
 * GET  /api/edr-cap/service-status  — Monitored services health
 * GET  /api/edr-cap/threat-intel    — Threat intelligence hits
 * GET  /api/edr-cap/api-calls       — Suspicious API call log
 */

const router = require('express').Router();
const fs = require('fs');
const path = require('path');
const mongoose = require('mongoose');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const System = require('../models/System.model');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const {
  PUBLIC_EDR_CAPABILITY_IDS,
  attachLiveCapabilityMetrics,
  capabilityCountPipeline,
  capabilityTimelinePipeline,
  geolocationEvidenceFilter,
  liveCardCapabilityMatch,
} = require('../utils/capabilityOverview');
const { registryMonitoringFilter } = require('../utils/registryMonitoring');

router.use(authenticate, requireAnalyst);

// ─── Helper ───────────────────────────────────────────────────────────────────
const since = (days) => new Date(Date.now() - days * 86400000);
const agentRoot = path.resolve(__dirname, '../../soc-agent');
const agentFileExists = (rel) => fs.existsSync(path.join(agentRoot, rel));
const statusCache = new Map();
const statusInFlight = new Map();
const STATUS_CACHE_MS = 60000;
const STATUS_QUERY_TIMEOUT_MS = 8000;
const liveOverviewCache = new Map();
const liveOverviewInFlight = new Map();
const LIVE_OVERVIEW_CACHE_MS = 30000;
const LIVE_OVERVIEW_QUERY_TIMEOUT_MS = 15000;

function withTimeout(promise, fallback, ms = STATUS_QUERY_TIMEOUT_MS) {
  return Promise.race([
    promise,
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]).catch(() => fallback);
}

function statusMetricsFallback() {
  const metrics = Array(41).fill(0);
  metrics[1] = [];
  metrics[1].timedOut = true;
  metrics[23] = [];
  metrics[25] = [];
  metrics[26] = [];
  metrics[40] = [];
  return metrics;
}

async function registryDashboardMetrics(companyId, departmentId, since48h, since24h) {
  // Linux/Solaris configuration files are included alongside Windows registry
  // keys, but unrelated endpoint telemetry must never count as capability 6.
  const match = {
    companyId,
    ...(departmentId ? { departmentId } : {}),
    createdAt: { $gte: since48h },
    isSynthetic: { $ne: true },
    $and: [
      {
        $or: [
          { systemId: { $exists: true, $ne: null } },
          { agentId: { $exists: true, $ne: '' } },
          { agentName: { $exists: true, $ne: '' } },
        ],
      },
      registryMonitoringFilter(),
    ],
  };
  const [result = {}] = await Alert.aggregate([
    { $match: match },
    {
      $facet: {
        counts: [
          {
            $group: {
              _id: null,
              logs24h: { $sum: { $cond: [{ $gte: ['$createdAt', since24h] }, 1, 0] } },
              previous24h: { $sum: { $cond: [{ $lt: ['$createdAt', since24h] }, 1, 0] } },
              highCritical24h: {
                $sum: {
                  $cond: [
                    { $and: [{ $gte: ['$createdAt', since24h] }, { $in: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, ['critical', 'high']] }] },
                    1,
                    0,
                  ],
                },
              },
              lastSeenAt: { $max: { $cond: [{ $gte: ['$createdAt', since24h] }, '$createdAt', null] } },
              reportingAgents: {
                $addToSet: {
                  $cond: [
                    { $gte: ['$createdAt', since24h] },
                    { $ifNull: ['$systemId', { $ifNull: ['$agentId', '$agentName'] }] },
                    null,
                  ],
                },
              },
            },
          },
        ],
        timeline: [
          { $match: { createdAt: { $gte: since24h } } },
          { $group: { _id: { $dateToString: { format: '%Y-%m-%dT%H', date: '$createdAt', timezone: 'UTC' } }, count: { $sum: 1 } } },
        ],
      },
    },
  ]).option({ maxTimeMS: LIVE_OVERVIEW_QUERY_TIMEOUT_MS });
  const row = result.counts?.[0];
  return {
    countRows: row ? [{
      ...row,
      _id: 6,
      unauthorized24h: 0,
      reportingAgents: (row.reportingAgents || []).filter(Boolean).length,
    }] : [],
    timelineRows: (result.timeline || []).map(row => ({ _id: { capabilityId: 6, hour: row._id }, count: row.count })),
  };
}

async function apiMonitoringExternalMetrics(companyId, departmentId, since24h, until) {
  const db = mongoose.connection.db;
  if (!db) return null;
  // WAF/API gateway rows are stored separately from Alert records. Match the
  // API Monitoring dashboard's total while preserving department isolation
  // when the source supplied a department identifier.
  const match = {
    company: { $in: [String(companyId), companyId] },
    ts: { $gte: since24h, $lte: until },
    ...(departmentId ? { departmentId: { $in: [String(departmentId), departmentId] } } : {}),
  };
  const [row] = await db.collection('waf_events').aggregate([
    { $match: match },
    { $group: {
      _id: null,
      logs24h: { $sum: 1 },
      highCritical24h: { $sum: { $cond: [{ $in: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, ['critical', 'high']] }, 1, 0] } },
      lastSeenAt: { $max: '$ts' },
    } },
  ], { maxTimeMS: LIVE_OVERVIEW_QUERY_TIMEOUT_MS }).toArray();
  return row || null;
}

async function geolocationDashboardMetrics(companyId, departmentId, since24h, until) {
  const policyScope = { companyId, ...(departmentId ? { departmentId } : {}) };
  const policies = await GeolocationPolicy.find({ ...policyScope, enabled: true })
    .select('conditions.systemIds').maxTimeMS(5000).lean();
  if (!policies.length) return null;
  let policyFilter = {};
  if (!policies.some(policy => !Array.isArray(policy.conditions?.systemIds) || policy.conditions.systemIds.length === 0)) {
    const systemIds = [...new Set(policies.flatMap(policy => policy.conditions?.systemIds || []).map(String))]
      .filter(mongoose.Types.ObjectId.isValid)
      .map(value => new mongoose.Types.ObjectId(value));
    if (!systemIds.length) return null;
    policyFilter = { systemId: { $in: systemIds } };
  }
  const [row] = await Alert.aggregate([
    { $match: {
      $and: [
        { companyId, ...(departmentId ? { departmentId } : {}) },
        { createdAt: { $gte: since24h, $lte: until } },
        { isSynthetic: { $ne: true } },
        geolocationEvidenceFilter(),
        policyFilter,
      ],
    } },
    { $group: {
      _id: null,
      logs24h: { $sum: 1 },
      highCritical24h: { $sum: { $cond: [{ $in: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, ['critical', 'high']] }, 1, 0] } },
      lastSeenAt: { $max: '$createdAt' },
      reportingAgents: { $addToSet: { $ifNull: ['$systemId', { $ifNull: ['$endpointId', { $ifNull: ['$agentId', '$agentName'] }] }] } },
    } },
    { $project: {
      _id: { $literal: 23 }, logs24h: 1, highCritical24h: 1, lastSeenAt: 1,
      previous24h: { $literal: 0 }, unauthorized24h: { $literal: 0 },
      reportingAgents: { $size: { $filter: { input: '$reportingAgents', as: 'agent', cond: { $ne: ['$$agent', null] } } } },
    } },
  ]).option({ maxTimeMS: LIVE_OVERVIEW_QUERY_TIMEOUT_MS });
  return row || null;
}

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/live-overview — fast, real 24h data for all overview cards
// ─────────────────────────────────────────────────────────────────────────────
router.get('/live-overview', async (req, res) => {
  const cid = req.user.companyId;
  if (!mongoose.Types.ObjectId.isValid(cid)) {
    return res.status(400).json({ message: 'Invalid tenant scope' });
  }
  const rawDepartmentId = req.user.role === 'department_admin' ? req.user.departmentId : undefined;
  if (rawDepartmentId && !mongoose.Types.ObjectId.isValid(rawDepartmentId)) {
    return res.status(400).json({ message: 'Invalid department scope' });
  }
  const cacheKey = `${String(cid)}:${rawDepartmentId ? String(rawDepartmentId) : 'company'}`;
  let resolveInFlight;
  try {
    const cached = liveOverviewCache.get(cacheKey);
    if (cached && Date.now() - cached.at < LIVE_OVERVIEW_CACHE_MS) {
      return res.json(cached.data);
    }
    const inFlight = liveOverviewInFlight.get(cacheKey);
    if (inFlight) return res.json(await inFlight);
    const overviewPromise = new Promise(resolve => { resolveInFlight = resolve; });
    liveOverviewInFlight.set(cacheKey, overviewPromise);
    const now = new Date();
    const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    // The overview is a strict rolling 24-hour view. Avoid scanning an extra
    // historical day merely for a comparison trend on high-volume tenants.
    const companyId = new mongoose.Types.ObjectId(cid);
    const departmentId = rawDepartmentId ? new mongoose.Types.ObjectId(rawDepartmentId) : undefined;
    // Two bounded aggregations replace the former 31 parallel countDocuments
    // calls. Those per-card queries caused a connection-pool/CPU spike every
    // time an overview snapshot expired.
    const [countRowsBase, timelineRows, wafMetrics, geoMetrics] = await Promise.all([
      withTimeout(
        Alert.aggregate(capabilityCountPipeline(companyId, since24h, since24h, departmentId)).option({ maxTimeMS: LIVE_OVERVIEW_QUERY_TIMEOUT_MS }),
        [],
        LIVE_OVERVIEW_QUERY_TIMEOUT_MS + 1000,
      ),
      withTimeout(
        Alert.aggregate(capabilityTimelinePipeline(companyId, since24h, departmentId, now)).option({ maxTimeMS: LIVE_OVERVIEW_QUERY_TIMEOUT_MS }),
        [],
        LIVE_OVERVIEW_QUERY_TIMEOUT_MS + 1000,
      ),
      withTimeout(apiMonitoringExternalMetrics(companyId, departmentId, since24h, now), null, LIVE_OVERVIEW_QUERY_TIMEOUT_MS),
      withTimeout(geolocationDashboardMetrics(companyId, departmentId, since24h, now), null, LIVE_OVERVIEW_QUERY_TIMEOUT_MS),
    ]);
    const countRows = countRowsBase.map(row => {
      if (Number(row._id) !== 20 || !wafMetrics) return row;
      return {
        ...row,
        logs24h: Number(row.logs24h || 0) + Number(wafMetrics.logs24h || 0),
        highCritical24h: Number(row.highCritical24h || 0) + Number(wafMetrics.highCritical24h || 0),
        lastSeenAt: [row.lastSeenAt, wafMetrics.lastSeenAt].filter(Boolean).sort().at(-1) || null,
      };
    }).map(row => Number(row._id) === 23
      ? (geoMetrics || { _id: 23, logs24h: 0, previous24h: 0, highCritical24h: 0, unauthorized24h: 0, reportingAgents: 0, lastSeenAt: null })
      : row);
    const overview = attachLiveCapabilityMetrics(
      Array.from({ length: 31 }, (_, index) => ({ id: index + 1 })),
      countRows,
      timelineRows,
      now,
    );
    const payload = {
      capabilities: overview.capabilities,
      liveSummary: overview.summary,
      updatedAt: now.toISOString(),
      source: 'tenant_alerts',
      syntheticExcluded: true,
      countMode: 'normalized',
      countLimited: false,
      partial: countRowsBase.length === 0 && timelineRows.length === 0,
    };
    liveOverviewCache.set(cacheKey, { at: Date.now(), data: payload });
    resolveInFlight(payload);
    liveOverviewInFlight.delete(cacheKey);
    res.json(payload);
  } catch (err) {
    const now = new Date();
    const overview = attachLiveCapabilityMetrics(
      Array.from({ length: 31 }, (_, index) => ({ id: index + 1 })),
      [],
      [],
      now,
    );
    const payload = {
      capabilities: overview.capabilities,
      liveSummary: overview.summary,
      updatedAt: now.toISOString(),
      source: 'tenant_alerts',
      syntheticExcluded: true,
      countMode: 'normalized',
      countLimited: false,
      partial: true,
      warning: 'Live overview query timed out; showing safe empty metrics.',
    };
    if (resolveInFlight) resolveInFlight(payload);
    liveOverviewInFlight.delete(cacheKey);
    res.json(payload);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/status — Full 35-capability audit report
// ─────────────────────────────────────────────────────────────────────────────
router.get('/status', async (req, res) => {
  const cid = req.user.companyId;
  const cacheKey = `${String(cid)}:${req.user.role === 'department_admin' ? String(req.user.departmentId || 'none') : 'company'}`;
  const cached = statusCache.get(cacheKey);
  if (cached && Date.now() - cached.at < STATUS_CACHE_MS) {
    return res.json(cached.data);
  }
  const inFlight = statusInFlight.get(cacheKey);
  if (inFlight) {
    try {
      return res.json(await inFlight);
    } catch (err) {
      return res.status(503).json({ message: 'EDR capability status is temporarily unavailable' });
    }
  }
  let resolveInFlight;
  let rejectInFlight;
  const statusPromise = new Promise((resolve, reject) => {
    resolveInFlight = resolve;
    rejectInFlight = reject;
  });
  // The primary request sends its response below; this avoids duplicate heavy
  // collection scans when several EDR components load at the same time.
  statusPromise.catch(() => {});
  statusInFlight.set(cacheKey, statusPromise);
  const s7d = since(7);
  const s14d = since(14);
  const s24h = since(1);
  const s48h = since(2);
  const s30d = since(30);
  const s60d = since(60);
  let statusQueryTimedOut = false;

  try {
    // Process telemetry is normalized with capability 1 during ingestion.
    // Keep status polling on indexed tags/rule IDs: existence checks and
    // unanchored regexes across descriptions forced full collection scans.
    const processSignalOr = [
      { capabilityId: 1 },
      { capabilityIds: 1 },
      { ruleId: 'PROC_INVENTORY_SUMMARY' },
      { ruleId: /^PROC_(STARTED|TERMINATED|TERMINATE_REQUESTED|SUSPICIOUS|SUSPICIOUS_CMDLINE|UNAUTHORIZED_EXECUTION|HIGH_CPU|HIGH_MEMORY)$/i },
      { ruleId: /^EDR_(?:.*PROCESS|HIGH_CPU|HIGH_MEMORY|SUSPICIOUS_CMDLINE)$/i },
    ];
    const processMatch24h = { companyId: cid, createdAt: { $gte: s24h }, $or: processSignalOr };
    const previousProcessMatch = { companyId: cid, createdAt: { $gte: since(2), $lt: s24h }, $or: processSignalOr };
    const fimMatch24h = { companyId: cid, eventCategory: 'file', createdAt: { $gte: s24h } };
    const previousFimMatch = { companyId: cid, eventCategory: 'file', createdAt: { $gte: since(2), $lt: s24h } };
    const registryMatch30d = { companyId: cid, capabilityId: 6, createdAt: { $gte: s30d } };
    const previousRegistryMatch = { companyId: cid, capabilityId: 6, createdAt: { $gte: s60d, $lt: s30d } };
    const fimActionCount = (match, pattern) => Alert.countDocuments({
      $and: [
        match,
        {
          $or: [
            { fileAction: pattern },
            { ruleId: pattern },
            { description: pattern },
            { 'rawEvent.file_action': pattern },
            { 'rawEvent.fileAction': pattern },
            { 'rawEvent.event_type': pattern },
            { 'rawEvent.change_type': pattern },
            { 'rawEvent.action': pattern },
          ],
        },
      ],
    });

    const [
      alertCount, alertCats, incidentCount,
      malwareCount, networkCount, fileCount,
      usbCount, authCount, systemCount,
      ransomwareCount, lateralCount, c2Count,
      privEscCount, credDumpCount, lolbinCount,
      processTotalCount, previousProcessTotalCount,
      processLifecycleCount, processHighCpuCount, processHighMemoryCount,
      processSuspiciousCount, processUnauthorizedCount, processClosedCount,
      processTrend, latestProcessInventory,
      activeSystems, allSystems,
      fimTotal24h, previousFimTotal24h,
      fimCreated24h, fimModified24h, fimDeleted24h, fimPermission24h,
      fimCritical24h, fimHigh24h,
      registryTotal30d, previousRegistryTotal30d,
      registryCriticalHigh30d, registrySecurity30d, registryUnauthorized30d,
      registrySystemIds,
    ] = await withTimeout(Promise.all([
      Alert.countDocuments({ companyId: cid }),
      Alert.distinct('eventCategory', { companyId: cid }),
      EdrIncident.countDocuments({ companyId: cid }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'malware', createdAt: { $gte: s7d } }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'network', createdAt: { $gte: s7d } }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'file', createdAt: { $gte: s7d } }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'usb', createdAt: { $gte: s7d } }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'edr', createdAt: { $gte: s7d } }),
      Alert.countDocuments({ companyId: cid, eventCategory: 'system', createdAt: { $gte: s7d } }),
      EdrIncident.countDocuments({ companyId: cid, category: 'ransomware' }),
      EdrIncident.countDocuments({ companyId: cid, category: 'lateral_movement' }),
      EdrIncident.countDocuments({ companyId: cid, category: 'c2_communication' }),
      Alert.countDocuments({ companyId: cid, $or: [{ userAction: 'privilege_escalation' }, { ruleId: /priv|escalat|sudo/i }] }),
      EdrIncident.countDocuments({ companyId: cid, category: 'credential_dumping' }),
      Alert.countDocuments({ companyId: cid, $or: [{ ruleId: /lolbin|wmic|mshta|certutil|regsvr/i }] }),
      Alert.countDocuments(processMatch24h),
      Alert.countDocuments(previousProcessMatch),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          { ruleId: /^PROC_(STARTED|TERMINATED|INVENTORY_SUMMARY)$/i },
        ],
      }),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          {
            $or: [
              { ruleId: /^(PROC_HIGH_CPU|EDR_HIGH_CPU)$/i },
              { processCpuPercent: { $gte: 80 } },
              { description: /high cpu/i },
            ]
          },
        ],
      }),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          {
            $or: [
              { ruleId: /^(PROC_HIGH_MEMORY|EDR_HIGH_MEMORY)$/i },
              { processMemoryPercent: { $gte: 10 } },
              { description: /(high memory|high ram)/i },
            ]
          },
        ],
      }),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          {
            $or: [
              { ruleId: /(PROC_SUSPICIOUS|PROC_SUSPICIOUS_CMDLINE|EDR_SUSPICIOUS_CMDLINE)/i },
              { userAction: /suspicious_execution|malware_process|suspicious_cmd/i },
            ]
          },
        ],
      }),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          {
            $or: [
              { ruleId: /(PROC_UNAUTHORIZED_EXECUTION|UNAUTHORIZED_PROCESS)/i },
              { description: /unauthorized execution|unauthorized process/i },
            ]
          },
        ],
      }),
      Alert.countDocuments({
        $and: [
          processMatch24h,
          {
            $or: [
              { ruleId: /^(PROC_TERMINATED|PROC_KILLED)$/i },
              { processStatus: /^(terminated|killed|exited|closed|dead|stopped)$/i },
              { description: /(process terminated|process killed|process closed|process exited)/i },
            ]
          },
        ],
      }),
      Alert.aggregate([
        { $match: processMatch24h },
        { $group: { _id: { $dateToString: { format: '%Y-%m-%d %H:00', date: '$createdAt' } }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]),
      Alert.findOne({ companyId: cid, ruleId: 'PROC_INVENTORY_SUMMARY', createdAt: { $gte: s24h } })
        .sort({ createdAt: -1 })
        .select('processCount rawEvent createdAt')
        .lean(),
      System.find({
        companyId: cid,
        isActive: true,
        status: 'active',
        agentVersion: { $exists: true, $nin: [null, ''] },
        lastSeen: { $gte: s24h },
      })
        .select('name hostname osType edrEnabled idsEnabled ipsEnabled firewallEnabled yaraEnabled wafEnabled networkMonitorEnabled usbMonitorEnabled processMonitorEnabled advancedProcessMonitorEnabled containerMonitorEnabled advancedProcessSensorStatus responseEnabled geoEnrichmentEnabled lastSeen velociraptorClientId')
        .lean(),
      System.find({ companyId: cid, isActive: true })
        .select('name hostname osType lastSeen')
        .lean(),
      Alert.countDocuments(fimMatch24h),
      Alert.countDocuments(previousFimMatch),
      fimActionCount(fimMatch24h, /creat|new file/i),
      fimActionCount(fimMatch24h, /modif|write|hash_changed|content|integrity/i),
      fimActionCount(fimMatch24h, /delet|unlink|remove/i),
      fimActionCount(fimMatch24h, /permission|chmod|mode|acl|suid|sgid|world-writable/i),
      Alert.countDocuments({ ...fimMatch24h, severity: /^critical$/i }),
      Alert.countDocuments({ ...fimMatch24h, severity: /^high$/i }),
      Alert.countDocuments(registryMatch30d),
      Alert.countDocuments(previousRegistryMatch),
      Alert.countDocuments({ ...registryMatch30d, severity: /^(critical|high)$/i }),
      Alert.countDocuments({
        ...registryMatch30d,
        $or: [
          { ruleId: /security|firewall|defender|audit|selinux|apparmor|pam|unauthorized|threat|malware/i },
          { description: /security|firewall|defender|audit|selinux|apparmor|pam|unauthorized|threat|malware/i },
        ],
      }),
      Alert.countDocuments({
        ...registryMatch30d,
        $or: [
          { ruleId: /unauthorized|tamper|policy.violation/i },
          { description: /unauthorized|tamper|policy violation/i },
        ],
      }),
      Alert.distinct('systemId', registryMatch30d),
    ]), statusMetricsFallback());
    statusQueryTimedOut = alertCats.timedOut === true;

    const activeAgentCount = activeSystems.length;
    const hasActiveAgent = activeAgentCount > 0;
    const hasWindowsEndpoint = allSystems.some(s => /win/i.test(s.osType || ''));
    const hasVelociraptorKey = Boolean(process.env.VELOCIRAPTOR_URL && (process.env.VELOCIRAPTOR_KEY || process.env.VELOCIRAPTOR_SERVER_CONFIG || process.env.VELOCIRAPTOR_API_CONFIG));
    const moduleKeys = ['edrEnabled', 'idsEnabled', 'ipsEnabled', 'firewallEnabled', 'yaraEnabled', 'wafEnabled', 'networkMonitorEnabled', 'usbMonitorEnabled', 'processMonitorEnabled', 'advancedProcessMonitorEnabled', 'containerMonitorEnabled', 'responseEnabled', 'geoEnrichmentEnabled'];
    const agentModuleSummary = moduleKeys.reduce((acc, key) => {
      acc[key] = {
        enabled: activeSystems.filter(s => s[key] !== false).length,
        disabled: activeSystems.filter(s => s[key] === false).length,
        total: activeSystems.length,
      };
      return acc;
    }, {});
    const agentModules = {
      logs: agentFileExists('collectors/logs.py'),
      network: agentFileExists('collectors/network.py'),
      processes: agentFileExists('collectors/processes.py'),
      usb: agentFileExists('collectors/usb.py'),
      file: agentFileExists('collectors/file_monitor.py'),
      rules: agentFileExists('detectors/rules.py'),
      anomaly: agentFileExists('detectors/anomaly.py'),
      yara: agentFileExists('detectors/yara_scanner.py'),
      vt: agentFileExists('detectors/virustotal.py'),
      edr: agentFileExists('core/edr.py'),
      ids: agentFileExists('core/ids.py'),
      ips: agentFileExists('core/ips.py'),
      firewall: agentFileExists('core/firewall.py'),
      responder: agentFileExists('core/malware_responder.py'),
      registry: agentFileExists('core/registry_monitor.py'),
      memoryScanner: agentFileExists('core/memory_scanner.py'),
      memoryOverflow: agentFileExists('core/memory_overflow.py'),
      cachePoison: agentFileExists('core/cache_poison_detector.py'),
      dnsSinkhole: agentFileExists('core/dns_sinkhole.py'),
      geo: agentFileExists('core/geo_enrichment.py'),
      waf: agentFileExists('core/waf.py'),
      suricata: agentFileExists('core/suricata_parser.py'),
      command: agentFileExists('core/command_listener.py'),
    };

    const latestProcessRaw = latestProcessInventory?.rawEvent?.raw || latestProcessInventory?.rawEvent || {};
    const latestProcesses = Array.isArray(latestProcessRaw.processes) ? latestProcessRaw.processes : [];
    const latestProcessCount = Number(
      latestProcessInventory?.processCount
      || latestProcessRaw.process_count
      || latestProcesses.length
      || 0
    );
    const latestRunningCount = Number(
      latestProcessRaw.running_count
      || latestProcesses.filter(p => !p.status || ['running', 'sleeping', 'disk-sleep', 'idle'].includes(String(p.status).toLowerCase())).length
      || latestProcessCount
      || 0
    );
    const processHighResourceCount = processHighCpuCount + processHighMemoryCount;
    const processCategorizedTotal = processLifecycleCount + processHighResourceCount + processSuspiciousCount + processUnauthorizedCount;
    const processTotalCurrent24h = latestRunningCount + processClosedCount;
    const processTrendData = (processTrend || []).map(row => ({ date: row._id, count: row.count || 0 }));

    const hasProcessMon = processTotalCount > 0 || agentModules.processes;
    const hasFileMon = alertCats.includes('file');
    const hasNetworkMon = alertCats.includes('network');
    const hasAuthMon = authCount > 0;
    const hasUSBMon = alertCats.includes('usb');
    const hasMalwareMon = malwareCount > 0;
    const hasIncidents = incidentCount > 0;

    const CAPABILITIES = [
      // 1
      {
        id: 1, name: 'Process Activity Monitoring',
        status: hasProcessMon ? 'implemented' : 'missing',
        description: 'SOC Agent monitors process lifecycle and lineage, executable trust, resource/network use, Windows Sysmon kernel evidence, service/task/startup inventories, application/database workloads, process DNS, and container/Kubernetes activity.',
        source: 'collectors/processes.py, windows_process_events.py, process_assets.py, workload_activity.py, core/memory_scanner.py',
        evidence: `${processTotalCount} process events (24h). Advanced sensor health is reported separately so missing Sysmon/runtime providers are shown as degraded rather than assumed active.`,
        metrics: {
          totalAlerts: processTotalCount,
          previousTotalAlerts: previousProcessTotalCount,
          totalProcesses24h: processTotalCurrent24h,
          activeProcesses: latestProcessCount,
          running: latestRunningCount,
          closed24h: processClosedCount,
          activeAgents: activeAgentCount,
          lifecycle: processLifecycleCount,
          highCpu: processHighCpuCount,
          highMemory: processHighMemoryCount,
          highResource: processHighResourceCount,
          suspicious: processSuspiciousCount,
          unauthorized: processUnauthorizedCount,
          other: Math.max(processTotalCount - processCategorizedTotal, 0),
          trend: processTrendData,
          latestInventoryAt: latestProcessInventory?.createdAt || null,
        },
        priority: 'high',
      },
      // 2
      {
        id: 2, name: 'File Activity Monitoring (FIM)',
        status: hasFileMon ? 'implemented' : 'partial',
        description: 'Real-time file integrity monitoring via watchdog on critical paths. YARA-scans new files.',
        source: 'collectors/file_monitor.py, detectors/yara_scanner.py',
        evidence: `${fimTotal24h} file alerts (24h), ${fileCount} file alerts (7d)`,
        metrics: {
          totalAlerts: fimTotal24h,
          totalEvents: fimTotal24h,
          previousTotalAlerts: previousFimTotal24h,
          activeAgents: activeAgentCount,
          lifecycle: fimTotal24h,
          created: fimCreated24h,
          modified: fimModified24h,
          deleted: fimDeleted24h,
          permission: fimPermission24h,
          highResource: 0,
          suspicious: fimCritical24h + fimHigh24h,
          unauthorized: 0,
        },
        priority: 'high',
      },
      // 3
      {
        id: 3, name: 'Network Activity Monitoring',
        status: hasNetworkMon ? 'implemented' : 'partial',
        description: 'Monitors ESTABLISHED connections every 10s, VT-enriched, suppresses clean IPs. Suspicious port detection.',
        source: 'collectors/network.py (VT-aware), ips.service.js',
        evidence: `${networkCount} network alerts (7d)`,
        priority: 'high',
      },
      // 4
      {
        id: 4, name: 'User & Authentication Monitoring',
        status: hasAuthMon ? 'implemented' : 'partial',
        description: 'Auth failure detection, brute-force, root/sudo logins, account lockouts, SSH key auth via regex rules.',
        source: 'detectors/rules.py (AUTH_* rules), LoginActivity.model.js',
        evidence: `${authCount} auth alerts (7d)`,
        priority: 'high',
      },
      // 5
      {
        id: 5, name: 'Memory Activity Monitoring',
        status: 'implemented',
        description: 'Process injection, hollowing, LSASS access, Mimikatz detected via rules. core/memory_scanner.py added for /proc/maps scanning on Linux.',
        source: 'core/memory_scanner.py, detectors/rules.py (WIN_MIMIKATZ, SHELL_REVERSE), CR-006',
        evidence: `${credDumpCount} memory/injection incidents`,
        priority: 'high',
      },
      // 6
      {
        id: 6, name: 'Registry Monitoring',
        status: 'implemented',
        description: 'Windows registry, Linux configuration, Solaris monitoring, and file-integrity changes collected from live Capability 6 agents.',
        source: 'core/registry_monitor.py, collectors/file_monitor.py, detectors/rules.py',
        evidence: `${registryTotal30d} registry and configuration events (30d)`,
        metrics: {
          totalAlerts: registryTotal30d,
          totalEvents: registryTotal30d,
          previousTotalAlerts: previousRegistryTotal30d,
          activeAgents: registrySystemIds.filter(Boolean).length || activeAgentCount,
          lifecycle: registryTotal30d,
          highResource: registrySecurity30d,
          suspicious: registryCriticalHigh30d,
          unauthorized: registryUnauthorized30d,
        },
        priority: 'medium',
      },
      // 7
      {
        id: 7, name: 'System Changes Monitoring',
        status: hasUSBMon ? 'implemented' : 'partial',
        description: 'Cron changes, service failures, kernel module loads, firewall disable, disk full — all covered.',
        source: 'detectors/rules.py (SYS_* rules), anomaly.py',
        evidence: `${systemCount} system alerts (7d)`,
        priority: 'medium',
      },
      // 8
      {
        id: 8, name: 'Persistence Mechanism Detection',
        status: 'implemented',
        description: 'Scheduled tasks, autostart entries, registry run keys, cron jobs, new services, startup folders detected.',
        source: 'detectors/rules.py (WIN_REG_PERSIST, SYS_CRON_MOD), CR-007 correlation rule',
        evidence: 'MITRE T1053, T1547, T1543 coverage',
        priority: 'high',
      },
      // 9
      {
        id: 9, name: 'Web & DNS Monitoring',
        status: 'implemented',
        description: 'DNS tunneling detected. Tor .onion traffic flagged. core/dns_monitor.py captures DNS query volume and detects DGA domains.',
        source: 'core/dns_monitor.py, detectors/rules.py (NET_DNS_TUNNEL, NET_TOR), T1071.004',
        evidence: 'DNS tunnel regex + DGA detection + Tor exit detection active',
        priority: 'high',
      },
      // 10
      {
        id: 10, name: 'Device Control (USB) Monitoring',
        status: 'implemented',
        description: 'USB storage detection, auto-scan with YARA + VT, block policies, malicious content detection.',
        source: 'collectors/usb.py, detectors/yara_scanner.py, CR-010',
        evidence: `${usbCount} USB alerts (7d)`,
        priority: 'high',
      },
      // 11
      {
        id: 11, name: 'Behavioral Analytics (UEBA)',
        status: 'implemented',
        description: 'Per-user behavioral baseline built over 7 days. Anomaly detector flags 3x spikes. Impossible travel detection active. UEBA scoring per user/endpoint.',
        source: 'detectors/anomaly.py, soc-agent-edr.service.js (Hunt 3), UEBA per-user baseline',
        evidence: 'Statistical baseline + geo anomaly + UEBA scoring active',
        priority: 'high',
      },
      // 12
      {
        id: 12, name: 'Data Security Monitoring',
        status: 'implemented',
        description: 'Sensitive-file/FIM, archive staging, database export, USB copy, cloud/network transfer and ransomware metadata are monitored automatically without collecting file contents.',
        source: 'collectors/data_security.py + file_monitor.py + usb.py + network.py, detectors/rules.py',
        evidence: 'Privacy-safe data-security telemetry, DLP classification and real-time SOC streaming active',
        priority: 'high',
      },
      // 13
      {
        id: 13, name: 'Credential Security Monitoring',
        status: 'implemented',
        description: 'Mimikatz, LSASS access, credential dumping tools, pass-the-hash, kerberoasting all detected.',
        source: 'collectors/credential_security.py, detectors/rules.py, MITRE T1003/T1555/T1558, correlation engine',
        evidence: `${credDumpCount} credential dumping incidents`,
        priority: 'critical',
      },
      // 14
      {
        id: 14, name: 'Lateral Movement Detection',
        status: 'implemented',
        description: 'PsExec, RDP abuse, SMB exploitation, WMI remote execution, pass-the-hash detection.',
        source: 'detectors/rules.py (WIN_PSEXEC), CR-005, MITRE T1021',
        evidence: `${lateralCount} lateral movement incidents`,
        priority: 'critical',
      },
      // 15
      {
        id: 15, name: 'Email Threat Monitoring',
        status: 'implemented',
        description: 'Phishing MITRE mapping active. Email threat log endpoint collects phishing/BEC alerts. Postfix/Sendmail log parser integrated via webhook.',
        source: 'GET /api/edr-cap/email-threats, MITRE_MAP.phishing T1566',
        evidence: 'T1566 mapped + email threat endpoint active',
        priority: 'medium',
      },
      // 16
      {
        id: 16, name: 'Insider Threat Detection',
        status: 'implemented',
        description: 'Anomalous login pattern (CR-013), impossible travel, multi-source login, per-user UEBA baseline, after-hours access detection.',
        source: 'soc-agent-edr.service.js CR-013, runThreatHunt Hunt-3, anomaly.py UEBA',
        evidence: 'Impossible travel + after-hours + UEBA per-user scoring active',
        priority: 'high',
      },
      // 17
      {
        id: 17, name: 'Patch & Vulnerability Monitoring',
        status: 'implemented',
        description: 'CVE alert correlation from agent logs. Patch status tracking via /api/edr-cap/patch-status. OS package version monitoring active.',
        source: 'GET /api/edr-cap/patch-status, CVE alert correlation, System.model.js',
        evidence: 'CVE patch status endpoint active',
        priority: 'high',
      },
      // 18
      {
        id: 18, name: 'Sandbox Analysis',
        status: 'implemented',
        description: 'VirusTotal 70+ engine analysis on every file hash. YARA local scanning. /api/edr-cap/sandbox endpoint for manual file detonation submission.',
        source: 'POST /api/edr-cap/sandbox, detectors/virustotal.py, yara_scanner.py',
        evidence: 'VT + YARA + sandbox endpoint active',
        priority: 'medium',
      },
      // 19
      {
        id: 19, name: 'Kernel-Level Monitoring',
        status: 'implemented',
        description: 'Kernel module load, kernel errors, rootkit indicators detected. auditd syscall rules active for privilege escalation and memory hooking detection.',
        source: 'detectors/rules.py (SYS_KERNEL_ERR, SYS_MODULE_LOAD, CR-014), auditd syscall rules',
        evidence: 'Rootkit/kernel manipulation + auditd syscall monitoring active',
        priority: 'critical',
      },
      // 20
      {
        id: 20, name: 'API Call Monitoring',
        status: 'implemented',
        description: 'WMIC, WinAPI, PowerShell API abuse tracked via rules. /api/edr-cap/api-calls returns suspicious API call log. auditd syscall tracing on Linux.',
        source: 'GET /api/edr-cap/api-calls, detectors/rules.py (WIN_WMIC_EXEC, WIN_LOLBIN), auditd',
        evidence: 'API abuse detection + live query endpoint active',
        priority: 'medium',
      },
      // 21
      {
        id: 21, name: 'Script Execution Monitoring',
        status: 'implemented',
        description: 'PowerShell obfuscation, encoded commands, Invoke-Expression, WScript, mshta detected.',
        source: 'detectors/rules.py (WIN_POWERSHELL, WIN_LOLBIN), MITRE T1059',
        evidence: 'Multiple script execution rules active',
        priority: 'high',
      },
      // 22
      {
        id: 22, name: 'Time-Based Anomaly Detection',
        status: 'implemented',
        description: 'Baseline deviation (3x spike) for CPU/memory/connections. Hunt-5 brute surge. Hourly login profiling — detects after-hours access patterns.',
        source: 'detectors/anomaly.py, runThreatHunt Hunt-5, hourly activity profiling',
        evidence: 'Statistical baseline + hourly profiling + surge detection active',
        priority: 'medium',
      },
      // 23
      {
        id: 23, name: 'Geolocation Anomaly Detection',
        status: 'implemented',
        description: 'Impossible travel, unusual locations, proxy/VPN/hosting, high-risk geography, geo-fence, GPS/IP mismatch, failed-login geo spray, and new-device location anomalies active.',
        source: 'GET /api/edr-cap/geo-anomalies, core/geo_enrichment.py, runThreatHunt Hunt-3',
        evidence: 'Multi-country login hunt + IP geo enrichment + account/location anomaly rules active',
        priority: 'high',
      },
      // 24
      {
        id: 24, name: 'Service Monitoring',
        status: 'implemented',
        description: 'Systemd service failures, firewall disable, AV stop detected. /api/edr-cap/service-status polls all security services. psutil-based service health check every 60s.',
        source: 'GET /api/edr-cap/service-status, detectors/rules.py (SYS_SERVICE_FAIL, SYS_FIREWALL_OFF, WIN_DEFENDER_OFF), psutil',
        evidence: 'Service failure + security disable detection + live health endpoint active',
        priority: 'medium',
      },
      // 25
      {
        id: 25, name: 'Hash/Signature Analysis',
        status: 'implemented',
        description: 'MD5/SHA256 hashing of files, VT multi-engine check, YARA rule matching on all new files and USB.',
        source: 'collectors/file_monitor.py, detectors/yara_scanner.py, detectors/virustotal.py',
        evidence: 'Hash + YARA + VT pipeline active',
        priority: 'high',
      },
      // 26
      {
        id: 26, name: 'Beaconing Detection',
        status: 'implemented',
        description: 'Threat hunt detects ≥10 connections to same external IP (beaconing pattern) over 24h window.',
        source: 'soc-agent-edr.service.js runThreatHunt Hunt-1, CR-004 C2 rule',
        evidence: 'Beaconing hunt + C2 correlation active, MITRE T1071.001',
        priority: 'critical',
      },
      // 27
      {
        id: 27, name: 'Encryption/Ransomware Detection',
        status: 'implemented',
        description: 'Shadow copy deletion, ransomware file extensions (.locked, .wncry, .ryuk), mass file encryption detected.',
        source: 'detectors/rules.py (RANSOMWARE_SHADOW, RANSOMWARE_EXT), CR-001',
        evidence: `${ransomwareCount} ransomware incidents`,
        priority: 'critical',
      },
      // 28
      {
        id: 28, name: 'Living-off-the-Land (LOLBins) Detection',
        status: 'implemented',
        description: 'certutil, regsvr32, mshta, bitsadmin, wscript, WMIC abuse all detected as LOLBin attacks.',
        source: 'detectors/rules.py (WIN_LOLBIN, WIN_WMIC_EXEC), CR-008, MITRE T1218',
        evidence: `${lolbinCount} LOLBin alerts`,
        priority: 'high',
      },
      // 29
      {
        id: 29, name: 'Memory Overflow Detection',
        status: 'implemented',
        description: 'Detects SIGSEGV, SIGABRT, stack smashing, heap spray (>500MB/60s), NX/DEP violations, ASAN heap overflow, and kernel BUG via log scanning and process memory monitoring.',
        source: 'core/memory_overflow.py, /api/advanced/memory-overflow/recent, MITRE T1203/T1190',
        evidence: 'Overflow log scanner + heap spray detector + process spike monitor active',
        priority: 'critical',
      },
      // 30
      {
        id: 30, name: 'DNS Cache Poisoning Detection',
        status: 'implemented',
        description: 'Monitors DNS resolution for IP changes, TTL drops, private IP substitution (MITM indicator), and unexpected domain changes across 4+ watched domains.',
        source: 'core/cache_poison_detector.py, /api/advanced/cache-poison/baseline, MITRE T1557.003',
        evidence: 'DNS baseline monitoring + IP change detection active',
        priority: 'high',
      },
      // 31
      {
        id: 31, name: 'DNS Sinkhole',
        status: 'implemented',
        description: 'Redirects malicious domains to 0.0.0.0 via /etc/hosts and dnsmasq. Supports single domain, bulk import, and audit log of all sinkhole actions.',
        source: 'core/dns_sinkhole.py, /api/advanced/sinkhole/add, /api/advanced/sinkhole/bulk',
        evidence: 'DNS sinkhole endpoint active, hosts file management integrated',
        priority: 'high',
      },
    ];

    const fromAgent = (required, telemetry = true) => {
      const missingModules = required.filter(name => !agentModules[name]);
      if (missingModules.length) {
        return {
          status: 'missing',
          suffix: `Missing agent module(s): ${missingModules.join(', ')}`,
        };
      }
      if (!hasActiveAgent) {
        return {
          status: 'partial',
          suffix: 'Agent module exists, but no active agent heartbeat in last 24h',
        };
      }
      return {
        status: 'implemented',
        suffix: `Running on ${activeAgentCount} active agent(s)`,
      };
    };

    const backendReady = (ready, evidence) => ({
      status: ready ? 'implemented' : 'partial',
      suffix: evidence,
    });

    const runtime = {
      1: fromAgent(['processes', 'rules', 'edr'], hasProcessMon),
      2: fromAgent(['file', 'yara'], hasFileMon),
      3: fromAgent(['network', 'vt'], hasNetworkMon),
      4: fromAgent(['logs', 'rules'], hasAuthMon),
      5: fromAgent(['memoryScanner', 'rules'], credDumpCount > 0),
      6: agentModules.registry
        ? {
          status: registryTotal30d > 0 && hasActiveAgent ? 'implemented' : 'partial',
          suffix: registryTotal30d > 0
            ? `${registryTotal30d} live Windows/Linux/Solaris registry and configuration event(s) in 30d`
            : 'Registry monitor available; waiting for live registry or configuration telemetry',
        }
        : { status: 'missing', suffix: 'Missing agent module: registry_monitor.py' },
      7: fromAgent(['logs', 'rules', 'anomaly'], systemCount > 0),
      8: fromAgent(['logs', 'rules'], hasIncidents),
      9: fromAgent(['network', 'rules', 'cachePoison'], hasNetworkMon),
      10: fromAgent(['usb', 'yara'], hasUSBMon),
      11: fromAgent(['anomaly', 'geo'], true),
      12: fromAgent(['file', 'network', 'rules'], fileCount > 0 || networkCount > 0),
      13: fromAgent(['rules'], credDumpCount > 0),
      14: fromAgent(['network', 'logs', 'rules'], lateralCount > 0),
      15: backendReady(false, 'Email threat endpoint exists, but mail gateway integration/events are not confirmed'),
      16: fromAgent(['anomaly', 'geo', 'logs'], true),
      17: backendReady(true, 'Patch/vulnerability endpoint available; depends on agent OS inventory'),
      18: fromAgent(['yara', 'vt'], malwareCount > 0),
      19: fromAgent(['logs', 'rules'], systemCount > 0),
      20: fromAgent(['logs', 'rules'], systemCount > 0),
      21: fromAgent(['logs', 'rules'], systemCount > 0),
      22: fromAgent(['anomaly'], true),
      23: fromAgent(['geo'], true),
      24: fromAgent(['logs', 'rules'], systemCount > 0),
      25: fromAgent(['file', 'yara', 'vt'], fileCount > 0 || malwareCount > 0),
      26: fromAgent(['network', 'rules'], c2Count > 0),
      27: fromAgent(['file', 'rules'], ransomwareCount > 0),
      28: fromAgent(['logs', 'rules'], lolbinCount > 0),
      29: fromAgent(['memoryOverflow'], true),
      30: fromAgent(['cachePoison'], true),
      31: fromAgent(['dnsSinkhole'], true),
    };

    for (const cap of CAPABILITIES) {
      const r = runtime[cap.id];
      if (!r) continue;
      cap.status = r.status;
      cap.evidence = `${cap.evidence || ''}${cap.evidence ? ' · ' : ''}${r.suffix}`;
      cap.activeAgents = activeAgentCount;
      cap.runtimeCheckedAt = new Date();
    }

    const liveCompanyId = mongoose.Types.ObjectId.isValid(cid) ? new mongoose.Types.ObjectId(cid) : cid;
    const rawDepartmentId = req.user.role === 'department_admin' ? req.user.departmentId : undefined;
    const departmentId = rawDepartmentId && mongoose.Types.ObjectId.isValid(rawDepartmentId)
      ? new mongoose.Types.ObjectId(rawDepartmentId)
      : rawDepartmentId;
    const liveNow = new Date();
    const liveSince24h = new Date(liveNow.getTime() - 24 * 60 * 60 * 1000);
    let alertLiveCountRows = [];
    let alertLiveTimelineRows = [];
    if (!statusQueryTimedOut) {
      const [liveCountRows, liveTimelineRows] = await Promise.all([
        withTimeout(Alert.aggregate(capabilityCountPipeline(liveCompanyId, liveSince24h, liveSince24h, departmentId)), []),
        withTimeout(Alert.aggregate(capabilityTimelinePipeline(liveCompanyId, liveSince24h, departmentId, liveNow)), []),
      ]);
      alertLiveCountRows = liveCountRows;
      alertLiveTimelineRows = liveTimelineRows;
    }
    const liveOverview = attachLiveCapabilityMetrics(CAPABILITIES, alertLiveCountRows, alertLiveTimelineRows, liveNow);

    const totalCount = CAPABILITIES.length;
    const implemented = CAPABILITIES.filter(c => c.status === 'implemented').length;
    const partial = CAPABILITIES.filter(c => c.status === 'partial').length;
    const missing = CAPABILITIES.filter(c => c.status === 'missing').length;
    const score = Math.round(((implemented + partial * 0.5) / totalCount) * 100);
    const displayScore = implemented === totalCount ? 100 : score;

    const payload = {
      capabilities: liveOverview.capabilities,
      summary: { implemented, partial, missing, total: totalCount, score: displayScore },
      liveSummary: liveOverview.summary,
      liveUpdatedAt: liveNow.toISOString(),
      degraded: statusQueryTimedOut,
      agents: {
        active: activeAgentCount,
        total: allSystems.length,
        modules: agentModuleSummary,
        systems: activeSystems,
      },
      newServicesAdded: [
        'Cloud & SaaS monitoring endpoint (edr-cap/cloud-events)',
        'Email threat log endpoint (edr-cap/email-threats)',
        'Patch status summary (edr-cap/patch-status)',
        'Sandbox analysis (edr-cap/sandbox)',
        'Service health monitoring (edr-cap/service-status)',
        'API call monitoring log (edr-cap/api-calls)',
        'Geo-anomaly detection (edr-cap/geo-anomalies)',
        'Threat intelligence hits (edr-cap/threat-intel)',
        'Memory overflow detection (advanced/memory-overflow)',
        'DNS cache poisoning detection (advanced/cache-poison)',
        'DNS sinkhole manager (advanced/sinkhole)',
      ],
    };
    statusCache.set(cacheKey, { at: Date.now(), data: payload });
    resolveInFlight(payload);
    statusInFlight.delete(cacheKey);
    res.json(payload);
  } catch (err) {
    rejectInFlight(err);
    statusInFlight.delete(cacheKey);
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/new-services — list newly added monitoring capabilities
// ─────────────────────────────────────────────────────────────────────────────
router.get('/new-services', async (req, res) => {
  res.json({
    services: [
      {
        id: 'cloud_monitor',
        name: '☁️ Cloud & SaaS Monitoring',
        status: 'new',
        description: 'Ingests AWS CloudTrail, Azure Activity, GCP Audit logs via webhook. Detects IAM abuse, unusual API calls, public bucket creation.',
        implementation: 'POST /api/edr-cap/cloud-events webhook',
        mitreIds: ['T1078.004', 'T1530', 'T1537'],
        priority: 'medium',
      },
      {
        id: 'email_monitor',
        name: '📧 Email Threat Monitoring',
        status: 'new',
        description: 'Monitors for phishing indicators, malicious attachments, BEC patterns via mail server log parsing.',
        implementation: 'Parse Postfix/Sendmail logs for suspicious FROM/TO patterns',
        mitreIds: ['T1566', 'T1566.001', 'T1566.002'],
        priority: 'medium',
      },
      {
        id: 'patch_monitor',
        name: '🔧 Patch & Vulnerability Tracking',
        status: 'new',
        description: 'Tracks CVE exposure per endpoint using installed package versions. Alerts on critical unpatched CVEs.',
        implementation: 'GET /api/edr-cap/patch-status — aggregates from agent heartbeat data',
        mitreIds: ['T1190', 'T1210'],
        priority: 'high',
      },
      {
        id: 'sandbox_analysis',
        name: '🧪 Sandbox Analysis',
        status: 'new',
        description: 'Static + VirusTotal dynamic analysis of suspicious files. Detonation report generation.',
        implementation: 'POST /api/edr-cap/sandbox — analyze file hash via VT + YARA',
        mitreIds: ['T1204.002'],
        priority: 'medium',
      },
      {
        id: 'service_health',
        name: '🔌 Service Health Monitoring',
        status: 'new',
        description: 'Polls critical security services (AV, EDR agent, firewall, IDS) for status. Alerts on unexpected stop.',
        implementation: 'GET /api/edr-cap/service-status',
        mitreIds: ['T1562.001'],
        priority: 'medium',
      },
      {
        id: 'api_call_monitor',
        name: '📡 API Call Monitoring',
        status: 'new',
        description: 'Tracks WMIC, WinAPI, Linux syscall abuse patterns via auditd/Sysmon log parsing.',
        implementation: 'GET /api/edr-cap/api-calls',
        mitreIds: ['T1047', 'T1106'],
        priority: 'medium',
      },
      {
        id: 'geo_anomaly',
        name: '🌍 Geolocation Anomaly Detection',
        status: 'new',
        description: 'Real-time IP geolocation enrichment on every alert with impossible travel, unusual location, VPN/proxy, geo-fence, and failed-login geo-spray rules.',
        implementation: 'GET /api/edr-cap/geo-anomalies — scans alerts for account/location anomalies',
        mitreIds: ['T1078', 'T1021'],
        priority: 'high',
      },
      {
        id: 'threat_intel',
        name: '🔴 Threat Intelligence Feed',
        status: 'new',
        description: 'Cross-references all alert IPs/hashes against VT + AbuseIPDB reputation feeds.',
        implementation: 'GET /api/edr-cap/threat-intel — returns all VT-confirmed hits in last 7d',
        mitreIds: ['T1071', 'T1105'],
        priority: 'high',
      },
    ]
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/geo-anomalies — geolocation anomaly summary
// ─────────────────────────────────────────────────────────────────────────────
router.get('/geo-anomalies', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const alerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      username: { $exists: true, $ne: '' },
      geoCountry: { $exists: true, $ne: '' },
    }).select('username geoCountry geoCity srcip createdAt agentName ruleId userAction geoProxy geoHosting highRiskCountry device').sort({ createdAt: -1 }).lean();

    const userGeos = {};
    for (const a of alerts) {
      if (!userGeos[a.username]) userGeos[a.username] = { countries: new Set(), alerts: [] };
      userGeos[a.username].countries.add(a.geoCountry);
      userGeos[a.username].alerts.push(a);
    }

    const anomalies = Object.entries(userGeos)
      .filter(([_, v]) => v.countries.size >= 2)
      .map(([user, v]) => ({
        type: 'impossible_travel',
        user,
        countries: [...v.countries],
        alertCount: v.alerts.length,
        lastSeen: v.alerts[0]?.createdAt,
        severity: v.countries.size >= 3 ? 'critical' : 'high',
        description: `User "${user}" active from ${v.countries.size} countries: ${[...v.countries].join(', ')}`,
      }));

    const ipAnomalies = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(1) },
      $or: [
        { highRiskCountry: true },
        { ruleId: 'GEO_HIGH_RISK_COUNTRY' },
      ],
    }).select('srcip geoCountry geoCity description severity createdAt ruleId username agentName').limit(20).lean();

    const proxyOrVpn = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      $or: [
        { geoProxy: true },
        { geoHosting: true },
        { ruleId: 'GEO_PROXY_OR_HOSTING' },
      ],
    }).select('srcip geoCountry geoCity geoProxy geoHosting description severity createdAt username agentName').limit(20).lean();

    const geoFenceViolations = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      ruleId: 'GEO_FENCE_VIOLATION',
    }).select('srcip geoCountry geoCity description severity createdAt username agentName').limit(20).lean();

    const unusualLocations = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      ruleId: { $in: ['GEO_UNUSUAL_LOGIN_LOCATION', 'GEO_NEW_DEVICE_LOCATION'] },
    }).select('srcip geoCountry geoCity description severity createdAt username agentName device ruleId').limit(20).lean();

    const failedLoginGeoSpray = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      ruleId: 'GEO_FAILED_LOGIN_SPRAY',
    }).select('srcip geoCountry geoCity description severity createdAt username agentName').limit(20).lean();

    const locationMismatch = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      ruleId: 'GEO_LOCATION_MISMATCH',
    }).select('srcip geoCountry geoCity description severity createdAt username agentName rawEvent').limit(20).lean();

    res.json({
      impossibleTravel: anomalies,
      highRiskCountryIPs: ipAnomalies,
      proxyOrVpn,
      geoFenceViolations,
      unusualLocations,
      failedLoginGeoSpray,
      locationMismatch,
      summary: {
        travelAnomalies: anomalies.length,
        highRiskIPAlerts: ipAnomalies.length,
        proxyOrVpnAlerts: proxyOrVpn.length,
        geoFenceViolations: geoFenceViolations.length,
        unusualLocationAlerts: unusualLocations.length,
        failedLoginGeoSpray: failedLoginGeoSpray.length,
        locationMismatch: locationMismatch.length,
        period: '7d',
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/threat-intel — VT confirmed threat hits
// ─────────────────────────────────────────────────────────────────────────────
router.get('/threat-intel', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const [vtHits, yaraHits, iocAlerts] = await Promise.all([
      Alert.find({
        companyId: cid,
        createdAt: { $gte: since(7) },
        vtVerdict: 'malicious',
      }).select('description vtVerdict vtDetections fileHash fileName srcip agentName createdAt severity').limit(30).lean(),

      Alert.find({
        companyId: cid,
        createdAt: { $gte: since(7) },
        yaraRules: { $exists: true, $not: { $size: 0 } },
      }).select('description yaraRules fileHash fileName agentName createdAt severity').limit(20).lean(),

      EdrIncident.find({
        companyId: cid,
        createdAt: { $gte: since(7) },
        'iocs.0': { $exists: true },
      }).select('title iocs severity category mitreTechnique createdAt').limit(20).lean(),
    ]);

    res.json({
      vtMaliciousHits: vtHits,
      yaraMatches: yaraHits,
      incidentIOCs: iocAlerts,
      summary: {
        vtHits: vtHits.length,
        yaraMatches: yaraHits.length,
        incidentsWithIOC: iocAlerts.length,
        period: '7d',
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/api-calls — suspicious API/system call log
// ─────────────────────────────────────────────────────────────────────────────
router.get('/api-calls', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const alerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      $or: [
        { ruleId: /WIN_WMIC|WIN_LOLBIN|WIN_POWERSHELL|WIN_PSEXEC|SYS_MODULE/i },
        { description: /wmic|powershell|regsvr32|mshta|certutil|bitsadmin|modprobe|insmod/i },
      ]
    }).select('ruleId description severity agentName srcip createdAt eventCategory').limit(50).lean();

    const byType = {};
    for (const a of alerts) {
      const key = a.ruleId || 'UNKNOWN';
      byType[key] = (byType[key] || 0) + 1;
    }

    res.json({
      alerts,
      byType: Object.entries(byType).map(([ruleId, count]) => ({ ruleId, count })).sort((a, b) => b.count - a.count),
      total: alerts.length,
      period: '7d',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/service-status — monitored security services health
// ─────────────────────────────────────────────────────────────────────────────
router.get('/service-status', async (req, res) => {
  try {
    const cid = req.user.companyId;
    // Check for recent "service disabled" alerts
    const disabledAlerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(1) },
      $or: [
        { ruleId: /SYS_FIREWALL_OFF|WIN_DEFENDER_OFF|SYS_SERVICE_FAIL/i },
        { description: /firewall.*disabled|antivirus.*stopped|defender.*off/i },
      ]
    }).select('ruleId description agentName createdAt severity').lean();

    // Active endpoints from last heartbeat
    const activeEndpoints = await System.find({
      companyId: cid,
      isActive: true,
      status: 'active',
      agentVersion: { $exists: true, $nin: [null, ''] },
      lastSeen: { $gte: since(1) },
    }).select('name hostname lastSeen status edrEnabled idsEnabled ipsEnabled firewallEnabled yaraEnabled wafEnabled networkMonitorEnabled usbMonitorEnabled processMonitorEnabled advancedProcessMonitorEnabled containerMonitorEnabled advancedProcessSensorStatus responseEnabled geoEnrichmentEnabled velociraptorClientId').lean();

    const offlineEndpoints = await System.find({
      companyId: cid,
      isActive: true,
      agentVersion: { $exists: true, $nin: [null, ''] },
      $or: [
        { status: { $ne: 'active' } },
        { lastSeen: { $lt: since(1) } },
      ],
    }).select('name hostname lastSeen').lean();

    const moduleStatus = (field) => {
      if (!activeEndpoints.length) return { status: 'no agents', count: 0 };
      const enabled = activeEndpoints.filter(s => s[field] !== false).length;
      return { status: enabled > 0 ? 'running' : 'disabled', count: enabled };
    };

    const services = [
      { name: 'SOC Agent', status: activeEndpoints.length > 0 ? 'running' : 'no agents', count: activeEndpoints.length, icon: '🤖' },
      { name: 'File Integrity Monitor', ...moduleStatus('edrEnabled'), icon: '📁' },
      { name: 'Network Monitor', ...moduleStatus('networkMonitorEnabled'), icon: '🌐' },
      { name: 'YARA Scanner', ...moduleStatus('yaraEnabled'), icon: '🦠' },
      { name: 'WAF Monitor', ...moduleStatus('wafEnabled'), icon: '🛡️' },
      { name: 'Correlation Engine', status: 'running', icon: '⚡' },
      { name: 'Anomaly Detector', status: agentFileExists('detectors/anomaly.py') ? 'running' : 'missing', icon: '📊' },
      { name: 'USB Monitor', ...moduleStatus('usbMonitorEnabled'), icon: '💾' },
      { name: 'IPS Auto-block', ...moduleStatus('ipsEnabled'), icon: '🔒' },
      { name: 'SOAR Playbooks', ...moduleStatus('responseEnabled'), icon: '🎭' },
      { name: 'Velociraptor Forensics', status: process.env.VELOCIRAPTOR_URL ? 'configured' : 'not configured', count: activeEndpoints.filter(s => s.velociraptorClientId).length, icon: '🔍' },
    ];

    res.json({
      services,
      disabledAlerts,
      activeEndpoints,
      offlineEndpoints,
      summary: {
        totalServices: services.length,
        running: services.filter(s => s.status === 'running').length,
        alerts24h: disabledAlerts.length,
        activeAgents: activeEndpoints.length,
        offlineAgents: offlineEndpoints.length,
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/patch-status — vulnerability & patch summary
// ─────────────────────────────────────────────────────────────────────────────
router.get('/patch-status', async (req, res) => {
  try {
    const cid = req.user.companyId;
    // Leverage exploit/vulnerability alerts
    const vulnAlerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(30) },
      $or: [
        { ruleId: /CVE|exploit|overflow|vuln/i },
        { description: /CVE-[\d-]+|unpatched|vulnerability|exploit/i },
      ]
    }).select('ruleId description severity agentName srcip createdAt').limit(40).lean();

    const systems = await System.find({ companyId: cid, isActive: true })
      .select('name hostname os osType lastSeen').lean();

    // Extrapolate CVE mentions
    const cvePattern = /CVE-\d{4}-\d+/g;
    const cveSet = new Set();
    vulnAlerts.forEach(a => {
      const matches = (a.description || '').match(cvePattern) || [];
      matches.forEach(c => cveSet.add(c));
    });

    res.json({
      vulnerabilityAlerts: vulnAlerts,
      discoveredCVEs: [...cveSet],
      endpoints: systems.map(s => ({
        name: s.name,
        hostname: s.hostname,
        os: s.os,
        lastSeen: s.lastSeen,
        patchStatus: 'unknown', // Requires a vulnerability scan for actual data
      })),
      summary: {
        vulnAlerts: vulnAlerts.length,
        uniqueCVEs: cveSet.size,
        endpointsTracked: systems.length,
        period: '30d',
        note: 'Full CVE results require a configured vulnerability scanner',
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/cloud-events — cloud/SaaS event log
// ─────────────────────────────────────────────────────────────────────────────
router.get('/cloud-events', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const cloudAlerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      $or: [
        { ruleId: /CLOUD|AWS|AZURE|GCP|S3|IAM/i },
        { description: /cloudtrail|s3.*bucket|azure.*login|gcp.*api|saas/i },
        { source: 'cloud' },
      ]
    }).select('ruleId description severity agentName createdAt').limit(30).lean();

    res.json({
      events: cloudAlerts,
      total: cloudAlerts.length,
      period: '7d',
      integrationStatus: {
        awsCloudTrail: 'not configured',
        azureMonitor: 'not configured',
        gcpAuditLog: 'not configured',
        office365: 'not configured',
        note: 'Add webhook: POST /api/edr-cap/cloud-events with x-cloud-source header',
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/edr-cap/cloud-events — ingest cloud event (webhook)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/cloud-events', async (req, res) => {
  try {
    const { source, eventType, user, resource, region, risk, raw } = req.body;
    const cid = req.user?.companyId || req.body.companyId;
    if (!cid) return res.status(400).json({ message: 'companyId required' });

    const alert = await Alert.create({
      companyId: cid,
      ruleId: `CLOUD_${(eventType || 'EVENT').toUpperCase().replace(/[^A-Z0-9]/g, '_')}`,
      eventCategory: 'system',
      severity: risk === 'high' ? 'high' : risk === 'critical' ? 'critical' : 'medium',
      description: `[${source || 'Cloud'}] ${eventType}: ${resource || ''} by ${user || 'unknown'}`,
      source: 'cloud',
      username: user,
      rawLog: JSON.stringify(raw || req.body).substring(0, 500),
    });

    res.status(201).json({ ok: true, alertId: alert._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/edr-cap/email-threats — email threat log
// ─────────────────────────────────────────────────────────────────────────────
router.get('/email-threats', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const emailAlerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      $or: [
        { ruleId: /EMAIL|PHISH|SPAM|MAIL/i },
        { description: /phishing|malicious.*attachment|suspicious.*email|bec|spear.phish/i },
        { source: 'email' },
        { eventCategory: 'phishing' },
      ]
    }).select('ruleId description severity agentName createdAt username').limit(20).lean();

    res.json({
      threats: emailAlerts,
      total: emailAlerts.length,
      period: '7d',
      integrationStatus: {
        configured: false,
        note: 'Connect your mail server or Office 365 Defender to send events to POST /api/edr-cap/email-threats',
        supportedPlatforms: ['Microsoft Defender for Office 365', 'Google Workspace Alert Center', 'Postfix syslog', 'Exchange Online'],
      }
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/edr-cap/sandbox — static sandbox analysis using VT + YARA
// ─────────────────────────────────────────────────────────────────────────────
router.post('/sandbox', async (req, res) => {
  try {
    const { fileHash, fileName, filePath } = req.body;
    if (!fileHash) return res.status(400).json({ message: 'fileHash is required' });

    const cid = req.user.companyId;

    // Check if we already have VT results for this hash
    const existing = await Alert.findOne({
      companyId: cid,
      fileHash,
      vtVerdict: { $exists: true },
    }).sort({ createdAt: -1 }).lean();

    if (existing) {
      return res.json({
        source: 'cache',
        fileHash,
        fileName: fileName || existing.fileName,
        vtVerdict: existing.vtVerdict,
        vtDetections: existing.vtDetections,
        yaraRules: existing.yaraRules,
        analysisDate: existing.createdAt,
        cached: true,
      });
    }

    // Try live VT lookup
    const vtService = require('../services/virustotal.service');
    let vtResult = null;
    try {
      vtResult = await vtService.scanHash(fileHash);
    } catch (e) { /* VT not configured */ }

    res.json({
      source: 'virustotal',
      fileHash,
      fileName,
      filePath,
      vtVerdict: vtResult?.verdict || 'not_found',
      vtDetections: vtResult?.detections || 0,
      vtEngines: vtResult?.total_engines || 0,
      vtLink: `https://www.virustotal.com/gui/file/${fileHash}`,
      analysisDate: new Date(),
      cached: false,
      note: vtResult ? 'Live VT result' : 'VT not configured — add VIRUSTOTAL_API_KEY to backend/.env',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
