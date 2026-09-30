const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');
const { authCapabilityFilter } = require('../utils/authCapability');

const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const AUTH_EVIDENCE = authCapabilityFilter();
const sumWhen = condition => ({ $sum: { $cond: [condition, 1, 0] } });
const authText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$userAction', ''] }, ' ',
  { $ifNull: ['$eventType', ''] }, ' ', { $ifNull: ['$credentialEventType', ''] }, ' ',
  { $ifNull: ['$authType', ''] }, ' ', { $ifNull: ['$description', ''] }, ' ',
  { $ifNull: ['$failureReason', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: '$_authText', regex } });

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const rawCompany = req.user.companyId?._id || req.user.companyId;
  if (!mongoose.isValidObjectId(rawCompany)) throw Object.assign(new Error('Invalid tenant scope'), { status: 400 });
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(rawCompany)),
    ...(departmentId && mongoose.isValidObjectId(departmentId)
      ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) }
      : {}),
  };
}

function timeWindow(source = {}) {
  const hours = integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const fallback = new Date(Date.now() - hours * 3600000);
  const from = source.from ? new Date(source.from) : fallback;
  const to = source.to ? new Date(source.to) : null;
  const createdAt = { $gte: Number.isNaN(from.getTime()) ? fallback : from };
  if (to && !Number.isNaN(to.getTime())) createdAt.$lte = to;
  return createdAt;
}

function authenticationQuery(req, source = req.query) {
  const query = {
    ...companyScope(req, source.departmentId),
    isSynthetic: { $ne: true },
    createdAt: timeWindow(source),
    $and: [AUTH_EVIDENCE],
  };
  if (source.severity && ['critical', 'high', 'medium', 'low', 'info'].includes(String(source.severity).toLowerCase())) {
    query.severity = String(source.severity).toLowerCase();
  }
  if (source.username || source.user) query.username = new RegExp(escapeRegex(source.username || source.user).slice(0, 160), 'i');
  if (source.hostname || source.host) query.hostname = new RegExp(escapeRegex(source.hostname || source.host).slice(0, 253), 'i');
  if (source.sourceIp) query.srcip = new RegExp(`^${escapeRegex(source.sourceIp).slice(0, 64)}$`, 'i');
  if (source.country) query.geoCountry = new RegExp(`^${escapeRegex(source.country).slice(0, 80)}$`, 'i');
  if (source.protocol) query.authType = new RegExp(escapeRegex(source.protocol).slice(0, 80), 'i');
  if (source.result) query.authResult = new RegExp(`^${escapeRegex(source.result).slice(0, 32)}$`, 'i');
  if (source.search) {
    const search = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and.push({ $or: [
      { description: search }, { ruleId: search }, { username: search }, { hostname: search },
      { srcip: search }, { authType: search }, { userAction: search }, { mitreId: search },
    ] });
  }
  return query;
}

const projection = [
  'eventId tenantId companyId departmentId systemId agentId agentName endpointId hostname endpointType os osType platform agentVersion capabilityId capabilityIds',
  'ruleId description source category subCategory eventCategory eventType severity riskScore confidenceScore status actionTaken recommendedAction',
  'username userSid userDomain domain userAction credentialEventType authResult authType authProtocol failureReason sessionId sessionState deviceId identityProvider privilegeLevel mfaStatus',
  'srcip sourcePort srcPort destip destPort protocol geoCountry geoCountryCode geoCity geoRegion windowsEventId',
  'processName pid parentPid parentProcessName processCmdline processExe commandLine groupName targetUser logonType sourceHost destinationHost',
  'mitreId mitreTechnique mitreTactic technique relatedEventIds timeline notes assignedTo rawEvent full_log createdAt updatedAt',
].join(' ');

async function dashboardPayload(req) {
  const query = authenticationQuery(req);
  const limit = integer(req.query.limit, 500, 1, 1000);
  const [facets = {}, systems] = await Promise.all([
    Alert.aggregate([
      { $match: query },
      { $set: { _authText: authText } },
      { $facet: {
        summary: [{ $group: {
          _id: null,
          total: { $sum: 1 },
          successful: sumWhen({ $or: [{ $eq: ['$authResult', 'success'] }, matches('successful.authentication|auth.success|accepted.password|accepted.publickey|login.success|screen.unlock.success') ] }),
          failed: sumWhen({ $or: [{ $eq: ['$authResult', 'failure'] }, matches('authentication.failure|auth.fail|failed.password|invalid.user|login.failed|screen.unlock.fail') ] }),
          lockouts: sumWhen(matches('account.lock|locked.out|4740')),
          logouts: sumWhen(matches('logout|logoff|session.closed|4634|4647')),
          newUsers: sumWhen(matches('user.created|new.user|account.created|4720')),
          userModifications: sumWhen(matches('user.modified|account.modified|4738|account.state.change')),
          userDeletions: sumWhen(matches('user.deleted|account.deleted|4726')),
          privilegeChanges: sumWhen(matches('privilege|admin.right|sudo|4672')),
          groupChanges: sumWhen(matches('group.membership|group.change|4728|4729|4732|4733|4756|4757')),
          windowsAuthentication: sumWhen(matches('windows|kerberos|ntlm|eventid|4624|4625|4768|4769|4771|4776')),
          linuxAuthentication: sumWhen(matches('linux|ssh|sshd|pam|sudo|auth.log|/var/log/secure')),
          activeDirectory: sumWhen(matches('active.directory|ldap|kerberos|domain.controller')),
          webSuccess: sumWhen({ $and: [matches('web|browser|portal|http'), { $or: [{ $eq: ['$authResult', 'success'] }, matches('login.success|authentication.success') ] }] }),
          webFailed: sumWhen({ $and: [matches('web|browser|portal|http'), { $or: [{ $eq: ['$authResult', 'failure'] }, matches('login.failed|authentication.failure') ] }] }),
          vpn: sumWhen(matches('vpn|openvpn|wireguard|anyconnect|globalprotect')),
          rdp: sumWhen(matches('rdp|remote.desktop|logon.type.?10|eventid.?1149')),
          mfaFailure: sumWhen(matches('mfa.failure|mfa.failed|mfa.bypass|otp.failed|duo.denied')),
          mfaSuccess: sumWhen(matches('mfa.success|otp.verified|2fa.success|duo.success')),
          passwordChanges: sumWhen(matches('password.change|password.reset|4723|4724')),
          bruteForce: sumWhen(matches('brute.force|password.spray|credential.stuffing|authentication.burst')),
          impossibleTravel: sumWhen(matches('impossible.travel|geo.anomaly')),
          dormantAccounts: sumWhen(matches('dormant.account|disabled.account|expired.account')),
          serviceAccounts: sumWhen(matches('service.account|svc[-_.]|machine.account')),
          accountTakeover: sumWhen(matches('account.takeover|session.hijack|token.abuse')),
          policyViolations: sumWhen(matches('policy.violation|unauthorized|suspicious')),
          critical: sumWhen({ $eq: ['$severity', 'critical'] }),
          high: sumWhen({ $eq: ['$severity', 'high'] }),
          medium: sumWhen({ $eq: ['$severity', 'medium'] }),
          low: sumWhen({ $in: ['$severity', ['low', 'info']] }),
          maximumRisk: { $max: '$riskScore' },
          averageRisk: { $avg: '$riskScore' },
        } }],
        timeline: [{ $group: { _id: { hour: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, result: { $ifNull: ['$authResult', '$userAction'] } }, count: { $sum: 1 } } }, { $sort: { '_id.hour': 1 } }, { $limit: 2000 }],
        protocols: [{ $group: { _id: { $ifNull: ['$authType', { $ifNull: ['$authProtocol', 'Not reported'] }] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 20 }],
        sourceIps: [{ $match: { srcip: { $nin: [null, ''] } } }, { $group: { _id: '$srcip', count: { $sum: 1 }, failures: sumWhen({ $or: [{ $eq: ['$authResult', 'failure'] }, matches('auth.fail|failed.password|login.failed') ] }), lastSeen: { $max: '$createdAt' } } }, { $sort: { failures: -1, count: -1 } }, { $limit: 20 }],
        riskyUsers: [{ $match: { username: { $nin: [null, ''] } } }, { $group: {
          _id: '$username', alerts: { $sum: 1 }, maxRisk: { $max: { $ifNull: ['$riskScore', 0] } },
          failures: sumWhen({ $or: [{ $eq: ['$authResult', 'failure'] }, matches('auth.fail|failed.password|login.failed') ] }),
          successes: sumWhen({ $or: [{ $eq: ['$authResult', 'success'] }, matches('auth.success|accepted.password|accepted.publickey|login.success') ] }),
          privilegedActions: sumWhen(matches('privilege|admin.right|sudo|root.login')),
          ips: { $addToSet: '$srcip' }, devices: { $addToSet: { $ifNull: ['$deviceId', '$hostname'] } }, lastActivity: { $max: '$createdAt' },
        } }, { $set: { riskScore: { $min: [100, { $max: ['$maxRisk', { $add: [{ $multiply: ['$failures', 5] }, { $multiply: ['$privilegedActions', 10] }] }] }] }, uniqueIps: { $size: { $setDifference: ['$ips', [null, '']] } }, uniqueDevices: { $size: { $setDifference: ['$devices', [null, '']] } } } }, { $sort: { riskScore: -1, alerts: -1 } }, { $limit: 20 }],
        events: [{ $sort: { createdAt: -1 } }, { $limit: limit }, { $project: Object.fromEntries(projection.split(' ').map(field => [field, 1])) }],
      } },
    ]).option({ allowDiskUse: true, maxTimeMS: 12000 }).then(rows => rows[0] || {}),
    System.find(companyScope(req)).select('name hostname ip ipAddress os osType platform agentType status isOnline agentOk lastSeen agentVersion').sort({ lastSeen: -1 }).limit(2000).lean(),
  ]);
  const summary = facets.summary?.[0] || {};
  const activeSessions = Math.max(0, Number(summary.successful || 0) - Number(summary.logouts || 0));
  const systemsById = new Map(systems.map(system => [String(system._id), system]));
  const events = (facets.events || []).map(event => {
    const systemId = event.systemId?._id || event.systemId;
    const system = systemId ? systemsById.get(String(systemId)) : null;
    return system ? { ...event, systemId: system } : event;
  });
  return {
    capabilityId: 4,
    summary: { ...summary, _id: undefined, total: summary.total || 0, activeSessions },
    timeline: facets.timeline || [], protocols: facets.protocols || [], sourceIps: facets.sourceIps || [],
    riskyUsers: facets.riskyUsers || [], events, systems,
    generatedAt: new Date(), realtimeEvents: ['auth:event', 'authentication_event', 'authentication_alert'],
  };
}

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try { res.json(await dashboardPayload(req)); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication dashboard could not be loaded' }); }
});

router.get('/statistics', async (req, res) => {
  try { const payload = await dashboardPayload(req); res.json({ summary: payload.summary, timeline: payload.timeline, protocols: payload.protocols, sourceIps: payload.sourceIps, riskyUsers: payload.riskyUsers, generatedAt: payload.generatedAt }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication statistics could not be loaded' }); }
});

router.get('/events', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 1000000); const limit = integer(req.query.limit, 100, 1, 1000); const query = authenticationQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform agentType status lastSeen agentVersion').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Alert.countDocuments(query),
    ]);
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication events could not be loaded' }); }
});

router.get('/timeline', async (req, res) => {
  try {
    const timeline = await Alert.aggregate([{ $match: authenticationQuery(req) }, { $group: { _id: { hour: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, result: { $ifNull: ['$authResult', '$userAction'] } }, count: { $sum: 1 } } }, { $sort: { '_id.hour': 1 } }, { $limit: 2000 }]);
    res.json({ timeline });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication timeline could not be loaded' }); }
});

router.get('/risky-users', async (req, res) => {
  try { const payload = await dashboardPayload(req); res.json({ users: payload.riskyUsers, total: payload.riskyUsers.length }); }
  catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Risky users could not be loaded' }); }
});

router.get('/users/:username', async (req, res) => {
  try {
    const username = String(req.params.username || '').trim();
    if (!username || username.length > 160) return res.status(400).json({ message: 'Invalid username' });
    const query = authenticationQuery(req); query.username = new RegExp(`^${escapeRegex(username)}$`, 'i');
    const events = await Alert.find(query).select(projection).sort({ createdAt: -1 }).limit(integer(req.query.limit, 500, 1, 2000)).lean();
    const riskScore = events.reduce((max, row) => Math.max(max, Number(row.riskScore || 0)), 0);
    res.json({ user: { username, riskScore, firstSeen: events.at(-1)?.createdAt || null, lastSeen: events[0]?.createdAt || null }, events, total: events.length });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'User authentication history could not be loaded' }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), $and: [AUTH_EVIDENCE] }).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform agentType status lastSeen agentVersion').lean();
    if (!event) return res.status(404).json({ message: 'Authentication event not found' });
    res.json({ event });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication event could not be loaded' }); }
});

router.post('/events/:id/notes', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const text = String(req.body.text || '').trim();
    if (!text) return res.status(400).json({ message: 'Note text is required' });
    if (text.length > 4000) return res.status(400).json({ message: 'Note text exceeds 4000 characters' });
    const allowedStatuses = new Set(['open', 'investigating', 'under_observation', 'resolved', 'false_positive']);
    const status = allowedStatuses.has(String(req.body.status || '').toLowerCase())
      ? String(req.body.status).toLowerCase()
      : null;
    const update = {
      $push: {
        notes: { user: req.user.id || req.user._id, text, at: new Date() },
        auditHistory: { action: 'authentication.note_added', actorId: req.user.id || req.user._id, at: new Date(), metadata: status ? { status } : {} },
      },
      ...(status ? { $set: { status, resolvedAt: ['resolved', 'false_positive'].includes(status) ? new Date() : null } } : {}),
    };
    const event = await Alert.findOneAndUpdate(
      { _id: req.params.id, ...companyScope(req), $and: [AUTH_EVIDENCE] },
      update,
      { new: true, runValidators: true },
    ).select(projection).lean();
    if (!event) return res.status(404).json({ message: 'Authentication event not found' });
    req.app.get('io')?.to(`company:${event.companyId}`).emit('auth:event', event);
    res.json({ event });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Authentication note could not be saved' }); }
});

module.exports = router;
