const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const UebaProfileLockEvent = require('../models/UebaProfileLockEvent.model');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { createResponse, SUPPORTED_ACTIONS } = require('../services/automatedResponse.service');
const { hydrateResponseStatuses } = require('../services/uebaProfileLock.service');
const { allowedCompanyIds } = require('../services/socAccess.service');
const { resolveCapabilityDepartmentScope, uebaCapabilityFilter } = require('../utils/capabilityOverview');
const { readyUebaSystemIds } = require('../utils/uebaBaseline');

// Do not advertise a response that the shared response engine/agent cannot
// execute. Additional actions can be enabled centrally when their signed
// agent handlers are available.
const ACTIONS = new Set([
  'isolate', 'kill_process', 'block_ip', 'block_domain', 'quarantine_file', 'disable_user',
].filter(action => SUPPORTED_ACTIONS.has(action)));
const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const scoreExpr = { $cond: [
  { $gt: [{ $convert: { input: '$riskScore', to: 'double', onError: 0, onNull: 0 } }, 0] },
  { $convert: { input: '$riskScore', to: 'double', onError: 0, onNull: 0 } },
  { $cond: [
    { $gt: [{ $convert: { input: '$behaviorScore', to: 'double', onError: 0, onNull: 0 } }, 0] },
    { $convert: { input: '$behaviorScore', to: 'double', onError: 0, onNull: 0 } },
    { $switch: { branches: [
      { case: { $eq: ['$severity', 'critical'] }, then: 100 },
      { case: { $eq: ['$severity', 'high'] }, then: 80 },
      { case: { $eq: ['$severity', 'medium'] }, then: 60 },
      { case: { $eq: ['$severity', 'info'] }, then: 10 },
    ], default: 30 } },
  ] },
] };

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(req.user.companyId?._id || req.user.companyId)),
    ...(departmentId ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) } : {}),
    ...(req.query?.systemId && mongoose.isValidObjectId(req.query.systemId)
      ? { systemId: new mongoose.Types.ObjectId(String(req.query.systemId)) }
      : {}),
  };
}

function requireProfileLockManager(req, res, next) {
  if (!['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(req.user?.role)) {
    return res.status(403).json({ message: 'Profile lock management access required' });
  }
  next();
}

async function profileLockScope(req) {
  if (req.user.role === 'soc_manager') {
    const actorId = req.user.id || req.user._id;
    const [companyIds, departmentAssignments] = await Promise.all([
      SocCompanyAssignment.find({ userId: actorId, active: true }).distinct('companyId'),
      SocDepartmentAssignment.find({ userId: actorId, active: true }).select('companyId departmentId').lean(),
    ]);
    const scopes = [
      ...(companyIds.length ? [{ companyId: { $in: companyIds } }] : []),
      ...departmentAssignments.map(item => ({ companyId: item.companyId, departmentId: item.departmentId })),
    ];
    if (scopes.length) return { $and: [{ $or: scopes }] };
    const ids = await allowedCompanyIds(req.user);
    return { companyId: { $in: ids } };
  }
  return companyScope(req);
}

function uebaQuery(req, source = req.query) {
  const hours = PERIOD_HOURS[String(source.period || '')] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const query = {
    ...companyScope(req, source.departmentId), isSynthetic: { $ne: true },
    createdAt: { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from },
    $and: [uebaCapabilityFilter()],
  };
  const to = source.to ? new Date(source.to) : null;
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname)}$`, 'i');
  if (source.status) query.status = source.status;
  if (source.search) {
    const search = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and.push({ $or: [{ description: search }, { ruleId: search }, { username: search }, { hostname: search }, { srcip: search }, { processName: search }, { geoCountry: search }] });
  }
  return query;
}

const eventText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$eventType', ''] }, ' ', { $ifNull: ['$description', ''] }, ' ',
  { $ifNull: ['$behaviorCategory', ''] }, ' ', { $ifNull: ['$userAction', ''] }, ' ',
  { $ifNull: ['$processName', ''] }, ' ', { $ifNull: ['$processCmdline', ''] }, ' ',
  { $ifNull: ['$source', ''] }, ' ', { $ifNull: ['$eventCategory', ''] }, ' ', { $ifNull: ['$subCategory', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: '$_uebaText', regex } });
const sumWhen = condition => ({ $sum: { $cond: [condition, 1, 0] } });
const BASELINE_WINDOW_DAYS = 30;

function baselineScope(system, counts = {}) {
  const edrEnabled = system.edrEnabled !== false;
  return [
    { key: 'authentication', label: 'User & Authentication', description: 'Login, MFA, session, privilege and credential-abuse anomalies', enabled: edrEnabled, events: Number(counts.authentication || 0) },
    { key: 'endpoint', label: 'Process & Endpoint Behavior', description: 'Process launches, scripts, injection, persistence and resource deviations', enabled: edrEnabled && system.processMonitorEnabled !== false, events: Number(counts.endpoint || 0) },
    { key: 'data', label: 'File & Data Access', description: 'Sensitive-file access, bulk operations, exfiltration and cloud-transfer signals', enabled: edrEnabled, events: Number(counts.data || 0) },
    { key: 'email', label: 'Email & Webmail Behavior', description: 'Webmail, mail-client, attachment, URL and mailbox activity metadata', enabled: edrEnabled, events: Number(counts.email || 0) },
    { key: 'memory', label: 'Memory & Credential Access', description: 'LSASS access, credential dumping, injection and fileless activity', enabled: edrEnabled && system.memoryMonitorEnabled !== false, events: Number(counts.memory || 0) },
    { key: 'input', label: 'Mouse & Keyboard Activity', description: 'Aggregate typing rate, pointer speed, clicks, scrolling and active/idle time; after 30 learned days, multi-feature deviation requests user verification', enabled: edrEnabled, available: counts.inputAvailable !== false, events: Number(counts.input || 0), metrics: { keyboardRate: Number(counts.keyboardRate || 0), mouseRate: Number(counts.mouseRate || 0), activityPercent: Number(counts.activityPercent || 0), baselineDays: Number(counts.inputBaselineDays || 0), identityConfidence: Number(counts.inputIdentityConfidence || 0), mismatches: Number(counts.inputProfileMismatches || 0), profileActive: Boolean(counts.inputProfileActive) } },
  ];
}

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const query = uebaQuery(req);
    const scope = companyScope(req);
    const readySystemIds = await readyUebaSystemIds({ companyId: scope.companyId, departmentId: scope.departmentId });
    query.systemId = { $in: readySystemIds };
    const limit = integer(req.query.limit, 250, 1, 500);
    const activeSince = new Date(Date.now() - 5 * 60 * 1000);
    const [facets = {}, agentSummary = {}] = await Promise.all([
      Alert.aggregate([
        { $match: query }, { $set: {
          _uebaText: eventText,
          _uebaRisk: scoreExpr,
          _uebaUser: { $convert: {
            input: { $ifNull: [
              '$username',
              { $ifNull: [
                '$user',
                { $ifNull: [
                  '$entityId',
                  { $ifNull: ['$targetUser', { $ifNull: ['$rawEvent.username', { $ifNull: ['$rawEvent.user', ''] }] }] },
                ] },
              ] },
            ] },
            to: 'string', onError: '', onNull: '',
          } },
        } },
        { $facet: {
          summary: [{ $group: {
            _id: null, total: { $sum: 1 }, averageRiskScore: { $avg: '$_uebaRisk' },
            critical: sumWhen({ $eq: ['$severity', 'critical'] }), high: sumWhen({ $eq: ['$severity', 'high'] }),
            medium: sumWhen({ $eq: ['$severity', 'medium'] }), low: sumWhen({ $eq: ['$severity', 'low'] }),
            activeSessions: sumWhen(matches('session|login|logon|rdp|ssh|vpn')),
            dataExfiltration: sumWhen(matches('exfil|large.upload|bulk.copy|cloud.upload|usb.copy')),
            lateralMovement: sumWhen(matches('lateral|psexec|winrm|remote.service|smb.abuse|rdp.abuse|ssh.abuse')),
            privilegeEscalation: sumWhen(matches('privilege|admin.group|sudo|root.login|role.change')),
            suspiciousDevices: sumWhen(matches('unknown.device|suspicious.device|new.device')),
            newDevices: sumWhen(matches('new.device|unknown.device')),
            newLocations: sumWhen(matches('new.location|new.country|impossible.travel|geo.anomal')),
            blockedUsers: sumWhen(matches('blocked.user|disable.user|account.lock')),
            insiderThreatScore: { $avg: { $cond: [matches('insider|exfil|privilege|usb.copy|sensitive.file'), '$_uebaRisk', null] } },
          } }],
          users: [{ $match: { _uebaUser: { $nin: ['', null] } } }, { $group: { _id: '$_uebaUser', riskScore: { $max: '$_uebaRisk' }, events: { $sum: 1 }, lastSeen: { $max: '$createdAt' } } }, { $sort: { riskScore: -1, events: -1 } }, { $limit: 25 }],
          userStats: [
            { $match: { _uebaUser: { $nin: ['', null] } } },
            { $group: { _id: '$_uebaUser', riskScore: { $max: '$_uebaRisk' }, lastSeen: { $max: '$createdAt' } } },
            { $group: { _id: null, totalUsers: { $sum: 1 }, activeUsers: { $sum: { $cond: [{ $gte: ['$lastSeen', activeSince] }, 1, 0] } }, highRiskUsers: { $sum: { $cond: [{ $gte: ['$riskScore', 80] }, 1, 0] } } } },
          ],
          timeline: [{ $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, total: { $sum: 1 }, averageRisk: { $avg: '$_uebaRisk' }, high: sumWhen({ $gte: ['$_uebaRisk', 80] }), medium: sumWhen({ $and: [{ $gte: ['$_uebaRisk', 60] }, { $lt: ['$_uebaRisk', 80] }] }), low: sumWhen({ $lt: ['$_uebaRisk', 60] }) } }, { $sort: { _id: 1 } }],
          categories: [{ $group: { _id: { $switch: { branches: [
            { case: matches('auth|login|logon|password|mfa|account'), then: 'Authentication' },
            { case: matches('file|download|upload|usb|exfil'), then: 'Data Access' },
            { case: matches('network|dns|beacon|scan|lateral|rdp|ssh'), then: 'Network Behavior' },
            { case: matches('process|powershell|cmd|bash|python|wscript|mshta|lolbin'), then: 'Endpoint Behavior' },
            { case: matches('cloud|aws|azure|gcp|iam'), then: 'Cloud Activity' },
            { case: matches('email|mailbox|attachment|phish'), then: 'Email Behavior' },
            { case: matches('application|api|jwt|token.replay|bot.activity'), then: 'Application Behavior' },
            { case: matches('server|service|restart|shutdown|resource.abuse'), then: 'Server Behavior' },
          ], default: 'User Behavior' } }, count: { $sum: 1 } } }, { $sort: { count: -1 } }],
          countries: [{ $match: { geoCountry: { $exists: true, $nin: ['', null] } } }, { $group: { _id: '$geoCountry', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          channels: [{ $group: { _id: { $switch: { branches: [
            { case: matches('usb'), then: 'USB Device' }, { case: matches('cloud|drive|dropbox|s3'), then: 'Cloud Storage' },
            { case: matches('email|attachment|smtp'), then: 'Email' }, { case: matches('upload|https|ftp|scp|sftp'), then: 'Web / Network Upload' },
          ], default: 'Other' } }, count: { $sum: 1 } } }, { $sort: { count: -1 } }],
          events: [{ $sort: { createdAt: -1 } }, { $limit: limit }],
        } },
      ]).option({ allowDiskUse: true, maxTimeMS: 15000 }).then(rows => rows[0] || {}),
      System.aggregate([
        { $match: companyScope(req) },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            live: { $sum: { $cond: [{ $gte: ['$lastSeen', activeSince] }, 1, 0] } },
          },
        },
      ]).option({ maxTimeMS: 5000 }).then(rows => rows[0] || {}),
    ]);
    const users = facets.users || [];
    const summary = facets.summary?.[0] || {};
    const userStats = facets.userStats?.[0] || {};
    res.json({
      summary: {
        ...summary, _id: undefined,
        total: Number(summary.total || 0),
        critical: Number(summary.critical || 0),
        high: Number(summary.high || 0),
        medium: Number(summary.medium || 0),
        low: Number(summary.low || 0),
        totalUsers: Number(userStats.totalUsers || 0),
        activeUsers: Number(agentSummary.live || 0),
        highRiskUsers: Number(userStats.highRiskUsers || 0),
        insiderThreatScore: Math.round(Number(summary.insiderThreatScore || 0)),
        averageRiskScore: Math.round(Number(summary.averageRiskScore || 0)),
        protectedEndpoints: Number(agentSummary.total || 0), liveAgents: Number(agentSummary.live || 0),
      },
      users, timeline: facets.timeline || [], categories: facets.categories || [], countries: facets.countries || [],
      channels: facets.channels || [], events: facets.events || [], generatedAt: new Date(), realtimeEvent: 'ueba:event',
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

// Fixed rolling window: this endpoint never accepts a wider or older range.
// Agent pagination keeps the 30-day aggregation bounded for large tenants.
router.get('/baseline', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000);
    const limit = integer(req.query.limit, 60, 1, 200);
    const now = new Date();
    const from = new Date(now.getTime() - BASELINE_WINDOW_DAYS * 86400000);
    const scope = companyScope(req);
    const systemQuery = { ...scope, isActive: true, agentType: { $in: ['system', 'server'] } };
    const [systems, totalAgents] = await Promise.all([
      System.find(systemQuery)
        .sort({ lastSeen: -1, _id: 1 })
        .skip((page - 1) * limit).limit(limit)
        .select('name hostname ip os osType agentVersion lastSeen installDate status edrEnabled processMonitorEnabled networkMonitorEnabled usbMonitorEnabled memoryMonitorEnabled')
        .lean(),
      System.countDocuments(systemQuery),
    ]);
    const systemIds = systems.map(system => system._id);
    let statsRows = [];
    let warning = '';
    if (systemIds.length) {
      const query = {
        ...scope,
        systemId: { $in: systemIds },
        isSynthetic: { $ne: true },
        capabilityIds: 11,
        createdAt: { $gte: from, $lte: now },
      };
      try {
        statsRows = await Alert.aggregate([
          { $match: query },
          { $set: { _uebaText: eventText, _uebaRisk: scoreExpr } },
          { $group: {
          _id: '$systemId', events: { $sum: 1 }, firstSeen: { $min: '$createdAt' }, lastSeen: { $max: '$createdAt' },
          observedDates: { $addToSet: { $dateToString: { date: '$createdAt', format: '%Y-%m-%d', timezone: 'UTC' } } },
          averageRisk: { $avg: '$_uebaRisk' }, maximumRisk: { $max: '$_uebaRisk' },
          behaviorScore: { $avg: { $convert: { input: '$behaviorScore', to: 'double', onError: 0, onNull: 0 } } },
          baselineScore: { $avg: { $convert: { input: '$baselineScore', to: 'double', onError: 0, onNull: 0 } } },
          peerDeviationScore: { $avg: { $convert: { input: '$peerDeviationScore', to: 'double', onError: 0, onNull: 0 } } },
          confidence: { $avg: { $convert: { input: '$uebaConfidence', to: 'double', onError: 0, onNull: 0 } } },
          critical: sumWhen({ $eq: ['$severity', 'critical'] }), high: sumWhen({ $eq: ['$severity', 'high'] }),
          medium: sumWhen({ $eq: ['$severity', 'medium'] }), low: sumWhen({ $eq: ['$severity', 'low'] }),
          authentication: sumWhen(matches('auth|login|logon|password|mfa|account|credential|session|privilege')),
          endpoint: sumWhen(matches('process|powershell|cmd|bash|python|script|injection|persistence|resource|cpu|memory|tamper|agent.security|lolbin|system.change')),
          data: sumWhen(matches('file|download|upload|usb|exfil|archive|cloud.storage|sensitive|outbound.transfer')),
          email: sumWhen(matches('email|mailbox|attachment|phish|webmail')),
          memory: sumWhen(matches('lsass|credential.dump|memory|injection|shellcode|fileless')),
          input: sumWhen(matches('input.behavior|keyboard|mouse|typing.rate|pointer.speed')),
          inputAvailable: { $max: '$inputMonitoringAvailable' },
          keyboardRate: { $avg: '$inputKeyboardRate' }, mouseRate: { $avg: '$inputMouseRate' },
          activityPercent: { $avg: '$inputActivityPercent' },
          inputBaselineDays: { $max: '$inputBaselineDays' },
          inputIdentityConfidence: { $avg: '$inputIdentityConfidence' },
          inputProfileMismatches: sumWhen({ $eq: ['$inputProfileMismatch', true] }),
          inputProfileActive: { $max: { $cond: [{ $eq: ['$inputProfileStatus', 'verification_active'] }, 1, 0] } },
          } },
        ]).option({
          allowDiskUse: true, maxTimeMS: 12000,
          hint: { companyId: 1, capabilityIds: 1, createdAt: -1 },
        });
      } catch (aggregationError) {
        const message = String(aggregationError.message || '');
        if (aggregationError.code === 50 || /time limit|multiplanner|hint provided/i.test(message)) {
          warning = 'Agent cards are available; 30-day metrics are rebuilding on the optimized index.';
          console.warn('[ueba baseline] bounded aggregation unavailable:', message);
        } else {
          throw aggregationError;
        }
      }
    }
    const statMap = new Map(statsRows.map(row => [String(row._id), row]));
    const agents = systems.map(system => {
      const id = String(system._id);
      const stats = statMap.get(id) || {};
      // Baseline progress is earned only by days that actually contain agent
      // telemetry. Calendar age since the first event must never unlock alerts.
      const eventObservedDays = Math.min(BASELINE_WINDOW_DAYS, Array.isArray(stats.observedDates) ? stats.observedDates.length : 0);
      const observedDays = Math.max(eventObservedDays, Math.min(BASELINE_WINDOW_DAYS, Number(stats.inputBaselineDays || 0)));
      const scopeCounts = {
        authentication: stats.authentication, endpoint: stats.endpoint, data: stats.data,
        email: stats.email, memory: stats.memory, input: stats.input,
        inputAvailable: stats.inputAvailable, keyboardRate: stats.keyboardRate,
        mouseRate: stats.mouseRate, activityPercent: stats.activityPercent,
        inputBaselineDays: stats.inputBaselineDays, inputIdentityConfidence: stats.inputIdentityConfidence,
        inputProfileMismatches: stats.inputProfileMismatches, inputProfileActive: stats.inputProfileActive,
      };
      return {
        id, name: system.name || system.hostname || 'Unnamed agent', hostname: system.hostname || system.name || 'unknown',
        ip: system.ip || '', os: system.os || system.osType || 'Unknown', agentVersion: system.agentVersion || '',
        status: system.status || 'unknown', lastSeen: system.lastSeen || null,
        online: Boolean(system.lastSeen && new Date(system.lastSeen) >= new Date(now.getTime() - 5 * 60000)),
        windowDays: BASELINE_WINDOW_DAYS, observedDays, progressPercent: Math.round((observedDays / BASELINE_WINDOW_DAYS) * 100),
        firstSeen: stats.firstSeen || null, lastEventAt: stats.lastSeen || null,
        events: Number(stats.events || 0), users: 0,
        averageRisk: Math.round(Number(stats.averageRisk || 0)), maximumRisk: Math.round(Number(stats.maximumRisk || 0)),
        behaviorScore: Math.round(Number(stats.behaviorScore || 0)), baselineScore: Math.round(Number(stats.baselineScore || 0)),
        peerDeviationScore: Math.round(Number(stats.peerDeviationScore || 0)), confidence: Math.round(Number(stats.confidence || 0)),
        severity: { critical: Number(stats.critical || 0), high: Number(stats.high || 0), medium: Number(stats.medium || 0), low: Number(stats.low || 0) },
        riskFactors: [], monitoringScopes: baselineScope(system, scopeCounts),
      };
    });
    res.json({
      windowDays: BASELINE_WINDOW_DAYS, from, to: now, page, limit, totalAgents,
      pages: Math.ceil(totalAgents / limit), agents, generatedAt: now, warning,
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/baseline/:systemId', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.systemId)) return res.status(400).json({ message: 'Invalid agent id' });
    const scope = companyScope(req);
    const system = await System.findOne({ _id: req.params.systemId, ...scope, isActive: true })
      .select('name hostname ip os osType agentVersion lastSeen status edrEnabled processMonitorEnabled networkMonitorEnabled usbMonitorEnabled memoryMonitorEnabled')
      .lean();
    if (!system) return res.status(404).json({ message: 'Agent not found' });
    const now = new Date();
    const from = new Date(now.getTime() - BASELINE_WINDOW_DAYS * 86400000);
    const detailQuery = {
      ...scope, systemId: system._id, capabilityIds: 11, isSynthetic: { $ne: true }, createdAt: { $gte: from, $lte: now },
    };
    const [rows, dailyRows] = await Promise.all([
      Alert.find(detailQuery).sort({ createdAt: -1 }).limit(500)
        .select('username entityId uebaRiskFactors createdAt')
        .hint({ companyId: 1, capabilityIds: 1, createdAt: -1 }).maxTimeMS(8000).lean(),
      Alert.aggregate([
        { $match: detailQuery },
        { $set: { _uebaText: eventText, _uebaRisk: scoreExpr } },
        { $group: {
          _id: { $dateToString: { date: '$createdAt', format: '%Y-%m-%d', timezone: 'UTC' } },
          signals: { $sum: 1 }, averageRisk: { $avg: '$_uebaRisk' }, maximumRisk: { $max: '$_uebaRisk' },
          critical: sumWhen({ $eq: ['$severity', 'critical'] }), high: sumWhen({ $eq: ['$severity', 'high'] }),
          medium: sumWhen({ $eq: ['$severity', 'medium'] }), low: sumWhen({ $eq: ['$severity', 'low'] }),
          authentication: sumWhen(matches('auth|login|logon|password|mfa|account|credential|session|privilege')),
          endpoint: sumWhen(matches('process|powershell|cmd|bash|python|script|injection|persistence|resource|cpu|memory|tamper|agent.security|lolbin|system.change')),
          data: sumWhen(matches('file|download|upload|usb|exfil|archive|cloud.storage|sensitive|outbound.transfer')),
          email: sumWhen(matches('email|mailbox|attachment|phish|webmail')),
          memory: sumWhen(matches('lsass|credential.dump|memory|injection|shellcode|fileless')),
          input: sumWhen(matches('input.behavior|keyboard|mouse|typing.rate|pointer.speed')),
          inputKeyboardRate: { $avg: { $convert: { input: '$inputKeyboardRate', to: 'double', onError: null, onNull: null } } },
          inputMouseRate: { $avg: { $convert: { input: '$inputMouseRate', to: 'double', onError: null, onNull: null } } },
          inputActivityPercent: { $avg: { $convert: { input: '$inputActivityPercent', to: 'double', onError: null, onNull: null } } },
          inputSpeedSamples: { $sum: { $cond: [{ $ne: [{ $convert: { input: '$inputKeyboardRate', to: 'double', onError: null, onNull: null } }, null] }, 1, 0] } },
          inputUnavailableSignals: { $sum: { $cond: [{ $eq: ['$inputMonitoringAvailable', false] }, 1, 0] } },
          changeTypes: { $addToSet: { $ifNull: ['$eventType', { $ifNull: ['$ruleId', '$behaviorCategory'] }] } },
          entities: { $addToSet: { $ifNull: ['$username', '$entityId'] } },
        } },
        { $sort: { _id: 1 } },
      ]).option({ allowDiskUse: true, maxTimeMS: 12000, hint: { companyId: 1, capabilityIds: 1, createdAt: -1 } }),
    ]);
    const entities = new Set();
    const factors = new Map();
    rows.forEach(row => {
      const entity = row.username || row.entityId;
      if (entity) entities.add(String(entity));
      (row.uebaRiskFactors || []).forEach(factor => {
        const name = String(factor || '').trim();
        if (name) factors.set(name, (factors.get(name) || 0) + 1);
      });
    });
    const dailyMap = new Map(dailyRows.map(day => [day._id, day]));
    const dailyChanges = Array.from({ length: BASELINE_WINDOW_DAYS }, (_, index) => {
      const date = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - (BASELINE_WINDOW_DAYS - 1 - index)));
      const key = date.toISOString().slice(0, 10);
      const day = dailyMap.get(key) || {};
      const areas = ['authentication', 'endpoint', 'data', 'email', 'memory', 'input']
        .filter(area => Number(day[area] || 0) > 0);
      return {
        date: key, signals: Number(day.signals || 0),
        averageRisk: Math.round(Number(day.averageRisk || 0)), maximumRisk: Math.round(Number(day.maximumRisk || 0)),
        severity: { critical: Number(day.critical || 0), high: Number(day.high || 0), medium: Number(day.medium || 0), low: Number(day.low || 0) },
        activeAreas: areas,
        scopeCounts: Object.fromEntries(['authentication', 'endpoint', 'data', 'email', 'memory', 'input']
          .map(area => [area, Number(day[area] || 0)])),
        inputMetrics: {
          available: Number(day.inputSpeedSamples || 0) > 0,
          samples: Number(day.inputSpeedSamples || 0),
          sensorUnavailable: Number(day.inputUnavailableSignals || 0) > 0,
          keyboardRate: Number(day.inputKeyboardRate || 0),
          mouseRate: Number(day.inputMouseRate || 0),
          activityPercent: Number(day.inputActivityPercent || 0),
        },
        changeTypes: (day.changeTypes || []).filter(Boolean).map(String).slice(0, 8),
        entities: (day.entities || []).filter(Boolean).length,
      };
    });
    dailyChanges.forEach((day, index) => {
      day.changeFromPreviousDay = index ? day.signals - dailyChanges[index - 1].signals : 0;
    });
    res.json({
      systemId: String(system._id), users: entities.size,
      riskFactors: [...factors.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12).map(([name, count]) => ({ name, count })),
      dailyChanges, sampledSignals: rows.length, sampleLimit: 500, from, to: now,
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/profile-locks', requireProfileLockManager, async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000);
    const limit = integer(req.query.limit, 30, 1, 100);
    const filter = await profileLockScope(req);
    if (req.query.status) {
      const statuses = String(req.query.status).split(',').filter(status => UebaProfileLockEvent.schema.path('status').enumValues.includes(status));
      if (statuses.length) filter.status = { $in: statuses };
    }
    if (req.query.search) {
      const search = new RegExp(escapeRegex(req.query.search).slice(0, 100), 'i');
      filter.$or = [{ hostname: search }, { username: search }, { agentId: search }];
    }
    const [events, total, counts] = await Promise.all([
      UebaProfileLockEvent.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('lockResponseId', 'status commandId actionResult errorDetail createdAt completedAt')
        .populate('unlockResponseId', 'status commandId actionResult errorDetail createdAt completedAt')
        .populate('responseActions.responseId', 'status commandId actionType actionResult errorDetail createdAt completedAt')
        .lean(),
      UebaProfileLockEvent.countDocuments(filter),
      UebaProfileLockEvent.aggregate([
        { $match: await profileLockScope(req) },
        { $group: {
          _id: null,
          detected: { $sum: 1 },
          lockCount: { $sum: { $cond: [{ $ne: ['$lockedAt', null] }, 1, 0] } },
          locked: { $sum: { $cond: [{ $eq: ['$status', 'locked'] }, 1, 0] } },
          unlocked: { $sum: { $cond: [{ $eq: ['$status', 'unlocked'] }, 1, 0] } },
          activeLocked: { $sum: { $cond: [{ $in: ['$status', ['response_pending', 'lock_dispatching', 'lock_pending', 'locked', 'unlock_pending']] }, 1, 0] } },
          failed: { $sum: { $cond: [{ $in: ['$status', ['response_failed', 'lock_failed', 'unlock_failed']] }, 1, 0] } },
        } },
      ]).option({ maxTimeMS: 5000 }).then(rows => rows[0] || {}),
    ]);
    res.json({
      events, total, page, limit, pages: Math.ceil(total / limit),
      counts: {
        detected: Number(counts.detected || 0), lockCount: Number(counts.lockCount || 0), locked: Number(counts.locked || 0),
        unlocked: Number(counts.unlocked || 0), activeLocked: Number(counts.activeLocked || 0),
        failed: Number(counts.failed || 0),
      },
      generatedAt: new Date(), realtimeEvent: 'ueba:profile-lock',
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/profile-locks/:id', requireProfileLockManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid profile lock id' });
    const event = await UebaProfileLockEvent.findOne({ _id: req.params.id, ...(await profileLockScope(req)) })
      .populate('alertId')
      .populate('systemId', 'name hostname ip os osType agentVersion lastSeen status')
      .populate('unlockedBy', 'name email role');
    if (!event) return res.status(404).json({ message: 'Profile lock event not found' });
    await hydrateResponseStatuses([event], req.app.get('io'));
    await event.populate([
      { path: 'lockResponseId', select: 'status commandId actionParams actionResult errorDetail auditTrail createdAt completedAt' },
      { path: 'unlockResponseId', select: 'status commandId actionParams actionResult errorDetail auditTrail createdAt completedAt' },
      { path: 'responseActions.responseId', select: 'status commandId actionType actionParams actionResult errorDetail auditTrail createdAt completedAt' },
    ]);
    res.json({ event });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/profile-locks/:id/unlock', requireProfileLockManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid profile lock id' });
    const reason = String(req.body.reason || '').trim();
    if (req.body.confirmed !== true || reason.length < 5) return res.status(400).json({ message: 'confirmed=true and an unlock reason of at least 5 characters are required' });
    const event = await UebaProfileLockEvent.findOne({ _id: req.params.id, ...(await profileLockScope(req)) });
    if (!event) return res.status(404).json({ message: 'Profile lock event not found' });
    if (event.status === 'unlocked') return res.status(409).json({ message: 'Account is already unlocked' });
    if (!['locked', 'unlock_failed'].includes(event.status)) return res.status(409).json({ message: 'Unlock is available after the endpoint confirms the account lock' });
    const system = await System.findOne({ _id: event.systemId, companyId: event.companyId, isActive: true }).lean();
    if (!system) return res.status(409).json({ message: 'Target endpoint is unavailable' });
    const sourceAlert = await Alert.findOne({ _id: event.alertId, companyId: event.companyId });
    if (!sourceAlert) return res.status(409).json({ message: 'Source identity-protection alert is unavailable' });
    const actorId = req.user.id || req.user._id;
    const claimed = await UebaProfileLockEvent.findOneAndUpdate(
      { _id: event._id, status: { $in: ['locked', 'unlock_failed'] } },
      { $set: { status: 'unlock_pending', unlockResponseId: null, unlockedBy: actorId, unlockReason: reason.slice(0, 500) }, $push: { auditTrail: { action: 'account_unlock.requested', message: reason.slice(0, 500), actorId, actorRole: req.user.role } } },
      { new: true },
    );
    if (!claimed) return res.status(409).json({ message: 'An unlock workflow is already active for this event' });
    let response;
    try {
      response = await createResponse({
        companyId: claimed.companyId, tenantId: claimed.tenantId, alert: sourceAlert, system,
        actionType: 'enable_user', actionParams: { username: claimed.username },
        triggeredBy: actorId, trigger: 'manual', io: req.app.get('io'),
      });
      claimed.unlockResponseId = response._id;
      await claimed.save();
    } catch (dispatchError) {
      claimed.status = 'unlock_failed';
      claimed.auditTrail.push({ action: 'account_unlock.failed', message: String(dispatchError.message || dispatchError).slice(0, 600), actorId, actorRole: req.user.role });
      await claimed.save();
      throw dispatchError;
    }
    if (actorId && event.tenantId) await SocAuditEvent.create({
      tenantId: event.tenantId, companyId: event.companyId, actorId,
      action: 'ueba.profile_account_unlock.requested', targetType: 'UebaProfileLockEvent', targetId: String(event._id),
      metadata: { username: event.username, systemId: String(event.systemId), responseId: String(response._id), reason: reason.slice(0, 500) },
    });
    req.app.get('io')?.to(`company:${claimed.companyId}`).emit('ueba:profile-lock', { id: String(claimed._id), status: claimed.status, systemId: String(claimed.systemId), username: claimed.username, updatedAt: claimed.updatedAt });
    res.status(202).json({ event: claimed, response });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/logs', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000); const limit = integer(req.query.limit, 100, 1, 500);
    const query = uebaQuery(req);
    const scope = companyScope(req);
    const readySystemIds = await readyUebaSystemIds({ companyId: scope.companyId, departmentId: scope.departmentId });
    query.systemId = { $in: readySystemIds };
    const [events, total] = await Promise.all([Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(), Alert.countDocuments(query)]);
    res.json({ events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/log/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), $and: [uebaCapabilityFilter()] }).lean();
    if (!event) return res.status(404).json({ message: 'UEBA event not found' });
    const pivots = [event.systemId ? { systemId: event.systemId } : null, event.username ? { username: event.username } : null, event.srcip ? { srcip: event.srcip } : null].filter(Boolean);
    const relatedEvents = pivots.length ? await Alert.find({ ...companyScope(req), createdAt: { $gte: new Date(new Date(event.createdAt).getTime() - 30 * 60000), $lte: new Date(new Date(event.createdAt).getTime() + 30 * 60000) }, $and: [{ $or: pivots }] }).sort({ createdAt: 1 }).limit(100).lean() : [];
    res.json({ event, relatedEvents });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/respond', requireCompanyAdmin, async (req, res) => {
  try {
    const actionType = String(req.body.actionType || '');
    if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
    if (!ACTIONS.has(actionType)) return res.status(400).json({ message: 'Unsupported response action' });
    if (!req.body.confirmed || !String(req.body.reason || '').trim()) return res.status(400).json({ message: 'confirmed=true and reason are required' });
    const alert = await Alert.findOne({ _id: req.body.alertId, ...companyScope(req), $and: [uebaCapabilityFilter()] });
    if (!alert) return res.status(404).json({ message: 'UEBA event not found' });
    const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId }).lean();
    if (!system) return res.status(409).json({ message: 'Target endpoint is unavailable' });
    const actionParams = { ...(req.body.actionParams || {}) };
    if (actionType === 'kill_process' && !actionParams.pid) actionParams.pid = alert.pid;
    if (actionType === 'block_ip' && !actionParams.ip) actionParams.ip = alert.srcip || alert.destip;
    if (actionType === 'block_domain' && !actionParams.domain) actionParams.domain = alert.domain;
    if (actionType === 'quarantine_file' && !actionParams.path) actionParams.path = alert.filePath;
    if ((actionType === 'disable_user' || actionType === 'force_password_reset') && !actionParams.username) actionParams.username = alert.username;
    const response = await createResponse({ companyId: alert.companyId, tenantId: alert.tenantId, alert, system, actionType, actionParams, triggeredBy: req.user.id || req.user._id, trigger: 'manual', io: req.app.get('io'), forceApproval: true });
    const actorId = req.user.id || req.user._id;
    if (actorId && req.user.tenantId) await SocAuditEvent.create({ tenantId: req.user.tenantId, companyId: alert.companyId, actorId, action: 'ueba.response.requested', targetType: 'UebaAlert', targetId: String(alert._id), metadata: { actionType, reason: String(req.body.reason).slice(0, 500), responseId: response?._id } });
    res.status(202).json({ response });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
