/**
 * Fraud Controller
 * Business logic for fraud REST endpoints.
 * Keeps route handlers thin; all DB queries live here.
 */
const mongoose = require('mongoose');
const crypto = require('crypto');
const FraudEvent    = require('../models/FraudEvent.model');
const FraudAlert    = require('../models/FraudAlert.model');
const FraudRule     = require('../models/FraudRule.model');
const Device        = require('../models/Device.model');
const DeviceHistory = require('../models/DeviceHistory.model');
const LoginAttempt  = require('../models/LoginAttempt.model');
const LoginActivity = require('../models/LoginActivity.model');
const RiskScore     = require('../models/RiskScore.model');
const FraudAuditLog = require('../models/FraudAuditLog.model');
const User          = require('../models/User.model');
const { processFraudCheck } = require('../services/fraud.service');
const { buildSessions } = require('../utils/analystActivityAnalytics');
const { normalizeIpAddress } = require('../utils/clientIp');
const { parseUserAgent } = require('../utils/userAgent');

// Helper: Resolve dynamic scoping filter based on role (Super Admin, Partner Admin, Company Admin/Analyst)
async function getScopingFilter(req) {
  const filter = {};
  if (req.user.role === 'superadmin') {
    filter.simulatedData = { $ne: true };
    if (req.query.companyId) {
      try {
        filter.companyId = new mongoose.Types.ObjectId(req.query.companyId);
      } catch (e) {
        filter.companyId = new mongoose.Types.ObjectId(); // invalid id -> match nothing
      }
    }
    return filter;
  }
  if (req.user.role === 'partner_admin') {
    if (!req.user.partnerId) {
      filter.companyId = new mongoose.Types.ObjectId(); // Match nothing
      return filter;
    }
    const Company = require('../models/Company.model');
    const companies = await Company.find({ partnerId: req.user.partnerId }).select('_id').lean();
    const companyIds = companies.map(c => c._id);
    
    if (req.query.companyId) {
      try {
        const queryCompanyId = new mongoose.Types.ObjectId(req.query.companyId);
        if (companyIds.some(id => id.toString() === queryCompanyId.toString())) {
          filter.companyId = queryCompanyId;
        } else {
          filter.companyId = new mongoose.Types.ObjectId(); // Match nothing (not their company)
        }
      } catch (e) {
        filter.companyId = new mongoose.Types.ObjectId(); // Match nothing
      }
    } else {
      filter.companyId = { $in: companyIds };
    }
    return filter;
  }
  if (req.user.companyId) {
    try {
      filter.companyId = new mongoose.Types.ObjectId(req.user.companyId);
    } catch (e) {
      filter.companyId = req.user.companyId;
    }
  }
  return filter;
}

async function getAccountScopingFilter(req) {
  if (req.user.role === 'superadmin') {
    if (!req.query.companyId) return {};
    return mongoose.isValidObjectId(req.query.companyId)
      ? { companyId: new mongoose.Types.ObjectId(req.query.companyId) }
      : { _id: new mongoose.Types.ObjectId() };
  }

  if (req.user.role === 'partner_admin') {
    if (!req.user.partnerId) return { _id: new mongoose.Types.ObjectId() };
    const Company = require('../models/Company.model');
    const companyIds = (await Company.find({ partnerId: req.user.partnerId }).select('_id').lean()).map(item => item._id);
    if (req.query.companyId) {
      if (!mongoose.isValidObjectId(req.query.companyId)) return { _id: new mongoose.Types.ObjectId() };
      const requestedId = new mongoose.Types.ObjectId(req.query.companyId);
      return companyIds.some(id => id.equals(requestedId))
        ? { companyId: requestedId }
        : { _id: new mongoose.Types.ObjectId() };
    }
    return { companyId: { $in: companyIds } };
  }

  return req.user.companyId
    ? { companyId: new mongoose.Types.ObjectId(req.user.companyId) }
    : { _id: new mongoose.Types.ObjectId() };
}

function escapeRegex(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function loginLocation(activity = {}, relatedFraudEvent = null) {
  const browserLocation = activity.browserLocation || {};
  const hasBrowserCoordinates = browserLocation.permission === 'granted'
    && Number.isFinite(browserLocation.latitude)
    && Number.isFinite(browserLocation.longitude);
  return {
    country: activity.geoCountry || relatedFraudEvent?.country || null,
    city: activity.geoCity || relatedFraudEvent?.city || null,
    region: activity.geoRegion || relatedFraudEvent?.region || null,
    timezone: activity.geoTimezone || null,
    isp: activity.geoISP || relatedFraudEvent?.isp || null,
    lat: hasBrowserCoordinates ? browserLocation.latitude : (activity.geoLat ?? relatedFraudEvent?.lat ?? null),
    lon: hasBrowserCoordinates ? browserLocation.longitude : (activity.geoLon ?? relatedFraudEvent?.lon ?? null),
    accuracyMeters: hasBrowserCoordinates ? (browserLocation.accuracyMeters ?? null) : null,
    capturedAt: hasBrowserCoordinates ? (browserLocation.capturedAt || null) : null,
    permission: browserLocation.permission || null,
    source: hasBrowserCoordinates
      ? 'browser_geolocation'
      : (activity.geoCountry || activity.geoCity ? 'ip_geolocation' : (relatedFraudEvent ? 'fraud_intelligence' : null)),
  };
}

function serializeLoginActivity(activity = {}, relatedFraudEvent = null) {
  const parsedClient = parseUserAgent(activity.userAgent);
  return {
    _id: activity._id,
    action: activity.action,
    success: activity.success,
    failReason: activity.failReason || null,
    at: activity.createdAt,
    ipAddress: normalizeIpAddress(activity.ipAddress) || 'unknown',
    browser: activity.browser || parsedClient.browser,
    os: activity.os || parsedClient.os,
    device: activity.device || parsedClient.device,
    userAgent: activity.userAgent || null,
    location: loginLocation(activity, relatedFraudEvent),
  };
}

function emitRuleChange(req, action, rule) {
  const io = req.app.get('io');
  if (!io) return;
  io.to('fraud:stream').emit('fraud:rule-changed', {
    action,
    rule,
    ruleId: rule?._id,
    at: new Date(),
  });
}

async function observedAuthenticationDevices(loginFilter, limit = 200) {
  const result = await LoginActivity.aggregate([
    {
      $match: {
        ...loginFilter,
        ipAddress: { $exists: true, $nin: [null, '', 'unknown'] },
        userAgent: { $exists: true, $nin: [null, ''] },
      },
    },
    { $sort: { createdAt: 1 } },
    {
      $set: {
        _browserGps: {
          $cond: [
            { $eq: ['$browserLocation.permission', 'granted'] },
            {
              lat: '$browserLocation.latitude',
              lon: '$browserLocation.longitude',
              accuracyMeters: '$browserLocation.accuracyMeters',
              capturedAt: '$browserLocation.capturedAt',
            },
            null,
          ],
        },
      },
    },
    {
      $group: {
        _id: { companyId: '$companyId', ipAddress: '$ipAddress', userAgent: '$userAgent' },
        firstSeenAt: { $min: '$createdAt' },
        lastSeenAt: { $max: '$createdAt' },
        browser: { $last: '$browser' },
        os: { $last: '$os' },
        device: { $last: '$device' },
        country: { $last: '$geoCountry' },
        city: { $last: '$geoCity' },
        region: { $last: '$geoRegion' },
        isp: { $last: '$geoISP' },
        gpsEvidence: { $push: '$_browserGps' },
        emails: { $addToSet: '$email' },
        totalLogins: { $sum: { $cond: [{ $eq: ['$action', 'login_success'] }, 1, 0] } },
        failedAttempts: { $sum: { $cond: [{ $in: ['$action', ['login_failed', 'otp_failed']] }, 1, 0] } },
        totalChallenges: { $sum: { $cond: [{ $eq: ['$action', 'otp_required'] }, 1, 0] } },
      },
    },
    {
      $set: {
        lastGps: {
          $arrayElemAt: [
            { $filter: { input: '$gpsEvidence', as: 'gps', cond: { $ne: ['$$gps', null] } } },
            -1,
          ],
        },
      },
    },
    { $sort: { lastSeenAt: -1 } },
    { $limit: limit },
  ]);

  return result.map(row => {
    const client = parseUserAgent(row._id.userAgent);
    const fingerprint = `auth_${crypto.createHash('sha256').update(`${normalizeIpAddress(row._id.ipAddress)}|${row._id.userAgent}`).digest('hex')}`;
    return {
      _id: `observed-${fingerprint.slice(-24)}`,
      deviceFingerprint: fingerprint,
      identitySource: 'authentication_audit',
      browser: row.browser || client.browser,
      os: row.os || client.os,
      device: row.device || client.device.toLowerCase(),
      firstSeenAt: row.firstSeenAt,
      lastSeenAt: row.lastSeenAt,
      firstSeenIp: normalizeIpAddress(row._id.ipAddress),
      lastSeenIp: normalizeIpAddress(row._id.ipAddress),
      country: row.country || null,
      city: row.city || null,
      region: row.region || null,
      isp: row.isp || null,
      gpsLat: Number.isFinite(row.lastGps?.lat) ? row.lastGps.lat : null,
      gpsLon: Number.isFinite(row.lastGps?.lon) ? row.lastGps.lon : null,
      gpsAccuracyMeters: Number.isFinite(row.lastGps?.accuracyMeters) ? row.lastGps.accuracyMeters : null,
      gpsCapturedAt: row.lastGps?.capturedAt || null,
      emails: row.emails.filter(Boolean),
      totalLogins: row.totalLogins,
      failedAttempts: row.failedAttempts,
      totalBlocks: 0,
      totalChallenges: row.totalChallenges,
      riskScoreLast: 0,
      status: 'known',
      simulatedData: false,
    };
  });
}

// ── GET /api/fraud/accounts ──────────────────────────────────────────────────
exports.getAccounts = async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), 1000);
    const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
    const filter = await getAccountScopingFilter(req);
    const search = String(req.query.search || '').trim().slice(0, 100);
    if (search) {
      const pattern = new RegExp(escapeRegex(search), 'i');
      filter.$or = [{ name: pattern }, { email: pattern }, { role: pattern }];
    }

    const [users, total] = await Promise.all([
      User.find(filter)
        .select('name email phone role companyId departmentId departmentIds isActive accountStatus isEmailVerified mfaEnabled twoFactorEnabled lastLogin createdAt updatedAt')
        .populate('companyId', 'name status company_type')
        .sort({ lastLogin: -1, name: 1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .lean(),
      User.countDocuments(filter),
    ]);

    const userIds = users.map(item => item._id);
    const emails = users.map(item => item.email).filter(Boolean);
    const stats = userIds.length ? await LoginActivity.aggregate([
      { $match: { $or: [{ userId: { $in: userIds } }, { email: { $in: emails } }] } },
      { $sort: { createdAt: 1 } },
      {
        $group: {
          _id: { $toLower: '$email' },
          totalLogins: { $sum: { $cond: [{ $eq: ['$action', 'login_success'] }, 1, 0] } },
          failedAttempts: { $sum: { $cond: [{ $in: ['$action', ['login_failed', 'otp_failed']] }, 1, 0] } },
          totalLogouts: { $sum: { $cond: [{ $in: ['$action', ['logout', 'auto_logout']] }, 1, 0] } },
          lastLogin: { $max: { $cond: [{ $eq: ['$action', 'login_success'] }, '$createdAt', null] } },
          lastLogout: { $max: { $cond: [{ $in: ['$action', ['logout', 'auto_logout']] }, '$createdAt', null] } },
          lastActivity: { $max: '$createdAt' },
          lastIp: { $last: '$ipAddress' },
          lastBrowser: { $last: '$browser' },
          lastOs: { $last: '$os' },
          lastDevice: { $last: '$device' },
          lastUserAgent: { $last: '$userAgent' },
          lastCountry: { $last: '$geoCountry' },
          lastCity: { $last: '$geoCity' },
          lastBrowserLatitude: { $last: '$browserLocation.latitude' },
          lastBrowserLongitude: { $last: '$browserLocation.longitude' },
          lastLocationPermission: { $last: '$browserLocation.permission' },
          uniqueIps: { $addToSet: '$ipAddress' },
          uniqueCountries: { $addToSet: '$geoCountry' },
        },
      },
    ]) : [];
    const statsByEmail = new Map(stats.map(item => [item._id, item]));

    const accounts = users.map(item => {
      const accountStats = statsByEmail.get(String(item.email || '').toLowerCase()) || {};
      const parsedClient = parseUserAgent(accountStats.lastUserAgent);
      const lastLogin = accountStats.lastLogin || item.lastLogin || null;
      const lastLogout = accountStats.lastLogout || null;
      return {
        ...item,
        company: item.companyId || null,
        companyId: item.companyId?._id || item.companyId || null,
        activity: {
          totalLogins: accountStats.totalLogins || 0,
          failedAttempts: accountStats.failedAttempts || 0,
          totalLogouts: accountStats.totalLogouts || 0,
          lastLogin,
          lastLogout,
          lastActivity: accountStats.lastActivity || lastLogin,
          lastIp: normalizeIpAddress(accountStats.lastIp) || null,
          lastBrowser: accountStats.lastBrowser || parsedClient.browser,
          lastOs: accountStats.lastOs || parsedClient.os,
          lastDevice: accountStats.lastDevice || parsedClient.device,
          lastLocation: [accountStats.lastCity, accountStats.lastCountry].filter(Boolean).join(', ')
            || (Number.isFinite(accountStats.lastBrowserLatitude) && Number.isFinite(accountStats.lastBrowserLongitude)
              ? `${accountStats.lastBrowserLatitude}, ${accountStats.lastBrowserLongitude}`
              : null),
          locationPermission: accountStats.lastLocationPermission || null,
          uniqueIpCount: (accountStats.uniqueIps || []).filter(Boolean).length,
          uniqueCountryCount: (accountStats.uniqueCountries || []).filter(Boolean).length,
          logoutPending: Boolean(lastLogin && (!lastLogout || new Date(lastLogin) > new Date(lastLogout))),
        },
      };
    });

    res.json({ accounts, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/account/:id ───────────────────────────────────────────────
exports.getAccountById = async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid account id' });
    const scope = await getAccountScopingFilter(req);
    const user = await User.findOne({ ...scope, _id: req.params.id })
      .select('name email phone role companyId departmentId departmentIds isActive accountStatus isEmailVerified mfaEnabled twoFactorEnabled lastLogin createdAt updatedAt')
      .populate('companyId', 'name email phone industry country status company_type')
      .populate('departmentId', 'name')
      .populate('departmentIds', 'name')
      .lean();
    if (!user) return res.status(404).json({ message: 'Account not found' });

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 500, 1), 1000);
    const activityMatch = { $or: [{ userId: user._id }, { email: user.email }] };
    const [rawActivities, totalActivity, fraudEvents] = await Promise.all([
      LoginActivity.find(activityMatch).sort({ createdAt: -1 }).limit(limit).lean(),
      LoginActivity.countDocuments(activityMatch),
      FraudEvent.find({
        simulatedData: { $ne: true },
        $or: [{ userId: user._id }, { email: user.email }],
      }).sort({ createdAt: -1 }).limit(100).lean(),
    ]);

    const fraudByIp = new Map();
    fraudEvents.forEach(event => {
      const ip = normalizeIpAddress(event.ipAddress);
      if (ip && !fraudByIp.has(ip)) fraudByIp.set(ip, event);
    });
    const activities = rawActivities.map(activity => serializeLoginActivity(
      activity,
      fraudByIp.get(normalizeIpAddress(activity.ipAddress)) || null,
    ));
    const activityById = new Map(activities.map(item => [String(item._id), item]));
    const now = new Date();
    const sessions = buildSessions(rawActivities, now).reverse().map(session => {
      const login = activityById.get(String(session.login._id)) || serializeLoginActivity(session.login);
      const logout = session.logout ? (activityById.get(String(session.logout._id)) || serializeLoginActivity(session.logout)) : null;
      return {
        loginAt: session.start,
        logoutAt: logout?.at || null,
        durationMinutes: Math.max(0, Math.round((new Date(session.end) - new Date(session.start)) / 60000)),
        active: Boolean(session.active),
        inferredLogout: Boolean(session.inferredLogout),
        logoutAction: logout?.action || null,
        ipAddress: login.ipAddress,
        browser: login.browser,
        os: login.os,
        device: login.device,
        userAgent: login.userAgent,
        location: login.location,
      };
    });

    const successfulLogins = activities.filter(item => item.action === 'login_success' && item.success !== false);
    const logoutEvents = activities.filter(item => ['logout', 'auto_logout'].includes(item.action));
    const failedEvents = activities.filter(item => ['login_failed', 'otp_failed'].includes(item.action));
    const uniqueIps = [...new Set(activities.map(item => item.ipAddress).filter(ip => ip && ip !== 'unknown'))];
    const uniqueLocations = [...new Set(activities.map(item => (
      [item.location.city, item.location.country].filter(Boolean).join(', ')
      || (item.location.lat != null && item.location.lon != null ? `${item.location.lat}, ${item.location.lon}` : '')
    )).filter(Boolean))];

    res.json({
      account: { ...user, company: user.companyId || null, companyId: user.companyId?._id || user.companyId || null },
      summary: {
        totalLogins: successfulLogins.length,
        totalLogouts: logoutEvents.length,
        failedAttempts: failedEvents.length,
        lastLogin: successfulLogins[0]?.at || user.lastLogin || null,
        lastLogout: logoutEvents[0]?.at || null,
        uniqueIps,
        uniqueLocations,
      },
      sessions,
      activities,
      totalActivity,
      activityLimit: limit,
      fraudEvents: fraudEvents.map(event => ({
        _id: event._id,
        at: event.createdAt,
        ipAddress: normalizeIpAddress(event.ipAddress),
        location: [event.city, event.region, event.country].filter(Boolean).join(', ') || null,
        browser: event.browser || null,
        os: event.os || null,
        device: event.device || null,
        riskScore: event.riskScore,
        riskLevel: event.riskLevel,
        decision: event.decision,
        matchedRules: event.matchedRules || [],
        isVpn: event.isVpn,
        isTor: event.isTor,
        isProxy: event.isProxy,
      })),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};


// ── GET /api/fraud/events ─────────────────────────────────────────────────────
exports.getEvents = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const page  = parseInt(req.query.page) || 1;
    const skip  = (page - 1) * limit;
    const filter = await getScopingFilter(req);
    if (req.query.decision) filter.decision = req.query.decision;
    if (req.query.riskLevel) filter.riskLevel = req.query.riskLevel;

    const loginFilter = { ...filter };
    delete loginFilter.simulatedData;
    delete loginFilter.decision;
    delete loginFilter.riskLevel;
    const [fraudEvents, fraudTotal, loginActivities, loginTotal] = await Promise.all([
      FraudEvent.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      FraudEvent.countDocuments(filter),
      LoginActivity.find(loginFilter).sort({ createdAt: -1 }).limit(limit).lean(),
      LoginActivity.countDocuments(loginFilter),
    ]);
    const authEvents = loginActivities.map(activity => ({
      _id: activity._id,
      requestId: `login-${activity._id}`,
      companyId: activity.companyId,
      email: activity.email,
      ipAddress: activity.ipAddress,
      browser: activity.browser,
      os: activity.os,
      action: activity.action,
      success: activity.success,
      failReason: activity.failReason,
      decision: activity.action === 'otp_required' ? 'CHALLENGE' : (activity.success ? 'ALLOW' : 'AUTH_FAILED'),
      riskScore: null,
      riskLevel: null,
      matchedRules: activity.failReason ? [`Authentication: ${activity.failReason}`] : [],
      source: 'authentication',
      createdAt: activity.createdAt,
      simulatedData: false,
    }));
    const events = [...fraudEvents, ...authEvents]
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, limit);
    const total = fraudTotal + loginTotal;
    res.json({ events, total, page, pages: Math.max(1, Math.ceil(total / limit)), realOnly: true });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/dashboard ──────────────────────────────────────────────────
exports.getDashboard = async (req, res) => {
  try {
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d  = new Date(Date.now() - 7  * 24 * 60 * 60 * 1000);
    const filter = await getScopingFilter(req);
    const loginActivityFilter = { ...filter };
    delete loginActivityFilter.simulatedData;
    const deviceFilter = {};
    if (filter.companyId) {
      deviceFilter.companyIds = filter.companyId;
    }
    if (filter.simulatedData !== undefined) {
      deviceFilter.simulatedData = filter.simulatedData;
    }
    deviceFilter.deviceFingerprint = { $not: /^df_/ };

    const [
      totalDevices, blockedDevices, trustedDevices,
      todayLogins, todayBlocks, todayAlerts,
      openAlerts, riskDist,
      decisionBreakdown, topCountries, topAsns, topBrowsers,
      recentEvents, stytchFraudEvents,
    ] = await Promise.all([
      Device.countDocuments(deviceFilter),
      Device.countDocuments({ ...deviceFilter, status: 'blocked' }),
      Device.countDocuments({ ...deviceFilter, status: 'trusted' }),
      LoginActivity.countDocuments({
        ...loginActivityFilter,
        action: { $in: ['login_success', 'login_failed'] },
        createdAt: { $gte: since24h },
      }),
      LoginAttempt.countDocuments({ ...filter, decision: 'BLOCK', createdAt: { $gte: since24h } }),
      FraudAlert.countDocuments({ ...filter, createdAt: { $gte: since24h } }),
      FraudAlert.countDocuments({ ...filter, status: 'open' }),
      // Risk score distribution (7d)
      RiskScore.aggregate([
        { $match: { ...filter, createdAt: { $gte: since7d } } },
        { $group: { _id: '$level', count: { $sum: 1 } } },
      ]),
      // Decision breakdown (7d)
      FraudEvent.aggregate([
        { $match: { ...filter, createdAt: { $gte: since7d } } },
        { $group: { _id: '$decision', count: { $sum: 1 } } },
      ]),
      // Top 5 countries by event count
      FraudEvent.aggregate([
        { $match: { ...filter, createdAt: { $gte: since7d }, country: { $exists: true, $ne: null } } },
        { $group: { _id: '$country', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ]),
      // Top 5 ASNs
      FraudEvent.aggregate([
        { $match: { ...filter, createdAt: { $gte: since7d }, asn: { $exists: true, $ne: null } } },
        { $group: { _id: '$asn', count: { $sum: 1 }, isp: { $first: '$isp' } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ]),
      // Top 5 browsers
      FraudEvent.aggregate([
        { $match: { ...filter, createdAt: { $gte: since7d }, browser: { $exists: true, $ne: null } } },
        { $group: { _id: '$browser', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 5 },
      ]),
      // Last 10 events for live preview
      FraudEvent.find(filter).sort({ createdAt: -1 }).limit(10).lean(),
      FraudEvent.countDocuments({ ...filter, evidenceSource: { $ne: 'authentication_audit' } }),
    ]);

    // Format aggregations
    const riskDistMap = {};
    riskDist.forEach(r => { riskDistMap[r._id] = r.count; });
    const decisionMap = {};
    decisionBreakdown.forEach(d => { decisionMap[d._id] = d.count; });

    const highRiskDevices = await Device.countDocuments({
      ...deviceFilter,
      riskScoreLast: { $gte: 70 },
      status: { $nin: ['blocked', 'trusted'] },
    });
    const todayNewDevices = await Device.countDocuments({
      ...deviceFilter,
      firstSeenAt: { $gte: since24h },
    });
    const todayChallenges = await LoginActivity.countDocuments({ ...loginActivityFilter, action: 'otp_required', createdAt: { $gte: since24h } });
    const todayMfa = todayChallenges;
    const authenticationSignals24h = await LoginActivity.countDocuments({
      ...loginActivityFilter,
      action: { $in: ['login_failed', 'otp_failed'] },
      createdAt: { $gte: since24h },
    });
    const vpnCount = await FraudEvent.countDocuments({ ...filter, isVpn: true, createdAt: { $gte: since7d } });
    const torCount = await FraudEvent.countDocuments({ ...filter, isTor: true, createdAt: { $gte: since7d } });
    const [observedDevices, persistedFingerprints] = await Promise.all([
      observedAuthenticationDevices(loginActivityFilter, 5000),
      Device.distinct('deviceFingerprint', deviceFilter),
    ]);
    const persistedFingerprintSet = new Set(persistedFingerprints);
    const observedOnlyDevices = observedDevices.filter(device => !persistedFingerprintSet.has(device.deviceFingerprint));
    const effectiveTotalDevices = totalDevices + observedOnlyDevices.length;
    const effectiveTodayNewDevices = todayNewDevices
      + observedOnlyDevices.filter(device => new Date(device.firstSeenAt) >= since24h).length;

    res.json({
      kpis: {
        totalDevices: effectiveTotalDevices, blockedDevices, trustedDevices, highRiskDevices,
        openAlerts: openAlerts + authenticationSignals24h,
        todayLogins, todayBlocks, todayAlerts: todayAlerts + authenticationSignals24h,
        todayNewDevices: effectiveTodayNewDevices, todayChallenges, todayMfa,
        vpnDetected: vpnCount, torDetected: torCount,
        challengeRequests: todayChallenges,
      },
      riskDistribution: riskDistMap,
      decisionBreakdown: decisionMap,
      topCountries: topCountries.map(c => ({ country: c._id, count: c.count })),
      topAsns: topAsns.map(a => ({ asn: a._id, isp: a.isp, count: a.count })),
      topBrowsers: topBrowsers.map(b => ({ browser: b._id, count: b.count })),
      recentEvents,
      dataStatus: {
        realOnly: true,
        stytchDeviceIntelligence: stytchFraudEvents > 0 ? 'active' : 'awaiting_valid_stytch_data',
        authenticationActivity: 'active',
        deviceEvidence: totalDevices > 0 ? 'fingerprinted' : 'authentication_audit_observed',
      },
      generatedAt: new Date(),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/devices ────────────────────────────────────────────────────
exports.getDevices = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const page  = parseInt(req.query.page) || 1;
    const scope = await getScopingFilter(req);
    const loginFilter = { ...scope };
    delete loginFilter.simulatedData;
    const deviceFilter = { ...scope };
    if (deviceFilter.companyId) {
      deviceFilter.companyIds = deviceFilter.companyId;
      delete deviceFilter.companyId;
    }
    deviceFilter.deviceFingerprint = { $not: /^df_/ };
    if (req.query.status) deviceFilter.status = req.query.status;
    const [fingerprintedDevices, fingerprintedTotal, observedDevices, allPersistedFingerprints] = await Promise.all([
      Device.find(deviceFilter).sort({ lastSeenAt: -1 }).skip((page - 1) * limit).limit(limit).lean(),
      Device.countDocuments(deviceFilter),
      page === 1 && !req.query.status ? observedAuthenticationDevices(loginFilter, limit) : [],
      Device.distinct('deviceFingerprint', deviceFilter),
    ]);
    const persistedFingerprints = new Set(allPersistedFingerprints);
    const observedOnly = observedDevices.filter(device => !persistedFingerprints.has(device.deviceFingerprint));
    const devices = [...fingerprintedDevices, ...observedOnly]
      .sort((left, right) => new Date(right.lastSeenAt) - new Date(left.lastSeenAt))
      .slice(0, limit);
    const total = fingerprintedTotal + observedOnly.length;
    res.json({
      devices,
      total,
      page,
      pages: Math.max(1, Math.ceil(total / limit)),
      sources: {
        fingerprinted: fingerprintedTotal,
        authenticationObserved: observedOnly.length,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/device/:id ─────────────────────────────────────────────────
exports.getDeviceById = async (req, res) => {
  try {
    const filter = await getScopingFilter(req);
    if (filter.companyId) {
      filter.companyIds = filter.companyId;
      delete filter.companyId;
    }
    filter._id = req.params.id;
    const device = await Device.findOne(filter).lean();
    if (!device) return res.status(404).json({ message: 'Device not found' });
    const history = await DeviceHistory.find({ deviceId: device._id }).sort({ createdAt: -1 }).limit(50).lean();
    res.json({ device, history });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/alerts ─────────────────────────────────────────────────────
exports.getAlerts = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 50, 200);
    const scope = await getScopingFilter(req);
    const loginFilter = { ...scope };
    delete loginFilter.simulatedData;
    loginFilter.action = { $in: ['login_failed', 'otp_failed'] };
    const alertFilter = { ...scope, status: req.query.status || 'open' };
    const [persistedAlerts, persistedTotal, failedActivities, failedTotal] = await Promise.all([
      FraudAlert.find(alertFilter).sort({ createdAt: -1 }).limit(limit).lean(),
      FraudAlert.countDocuments(alertFilter),
      LoginActivity.find(loginFilter).sort({ createdAt: -1 }).limit(limit).lean(),
      LoginActivity.countDocuments(loginFilter),
    ]);
    const authenticationAlerts = failedActivities.map(activity => {
      const severe = ['account_locked', 'fraud_block'].includes(activity.failReason);
      return {
        _id: `auth-alert-${activity._id}`,
        userId: activity.userId,
        companyId: activity.companyId,
        email: activity.email,
        title: severe ? 'High-risk authentication failure' : 'Authentication failure observed',
        description: `${activity.action === 'otp_failed' ? 'OTP verification' : 'Login'} failed${activity.failReason ? `: ${activity.failReason.replaceAll('_', ' ')}` : ''}`,
        category: severe ? 'brute_force' : 'manual',
        severity: severe ? 'high' : 'medium',
        ipAddress: normalizeIpAddress(activity.ipAddress),
        country: activity.geoCountry,
        riskScore: severe ? 75 : 35,
        decision: 'AUTH_FAILED',
        matchedRules: [],
        status: 'open',
        evidenceSource: 'authentication_audit',
        createdAt: activity.createdAt,
      };
    });
    const alerts = [...persistedAlerts, ...authenticationAlerts]
      .sort((left, right) => new Date(right.createdAt) - new Date(left.createdAt))
      .slice(0, limit);
    res.json({
      alerts,
      total: persistedTotal + failedTotal,
      sources: { ruleAlerts: persistedTotal, authenticationSignals: failedTotal },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── POST /api/fraud/login-check ───────────────────────────────────────────────
exports.manualLoginCheck = async (req, res) => {
  try {
    const { telemetryId, ipAddress, email, companyId: requestedCompanyId } = req.body;
    if (!telemetryId || typeof telemetryId !== 'string') {
      return res.status(400).json({ message: 'A genuine Stytch telemetry ID is required' });
    }
    let companyId = req.user.companyId;
    if (req.user.role === 'superadmin') {
      if (!mongoose.isValidObjectId(requestedCompanyId)) {
        return res.status(400).json({ message: 'Select a valid company before enrolling a device' });
      }
      const Company = require('../models/Company.model');
      if (!await Company.exists({ _id: requestedCompanyId })) {
        return res.status(404).json({ message: 'Company not found' });
      }
      companyId = new mongoose.Types.ObjectId(requestedCompanyId);
    }
    const result = await processFraudCheck({
      telemetryId,
      ipAddress: ipAddress || req.ip,
      userAgent: req.get('user-agent') || '',
      action: 'manual_check',
      email: email || req.user.email,
      userId: req.user.id,
      companyId,
    });
    if (!result.fraudEventId) {
      return res.status(503).json({
        message: 'Real device enrollment could not be verified. Check Stytch credentials and Device Fingerprinting access.',
        decision: result.decision,
        requiresMFA: result.requiresMFA,
      });
    }
    res.json(result);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/history ────────────────────────────────────────────────────
exports.getHistory = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const page  = parseInt(req.query.page) || 1;
    const filter = await getScopingFilter(req);
    const logs = await FraudAuditLog.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean();
    const total = await FraudAuditLog.countDocuments(filter);
    res.json({ logs, total, page });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── GET /api/fraud/live ───────────────────────────────────────────────────────
exports.getLive = async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 20, 100);
    const filter = await getScopingFilter(req);
    const events = await FraudEvent.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ events });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

// ── CRUD for Rules ────────────────────────────────────────────────────────────
exports.getRules = async (req, res) => {
  try {
    const rules = await FraudRule.find().sort({ priority: -1, createdAt: -1 }).lean();
    res.json({ rules });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};

exports.createRule = async (req, res) => {
  try {
    const rule = await FraudRule.create({ ...req.body, createdBy: req.user.id });
    emitRuleChange(req, 'created', rule.toObject());
    res.status(201).json({ rule, message: 'Rule created successfully' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.updateRule = async (req, res) => {
  try {
    const rule = await FraudRule.findByIdAndUpdate(req.params.id, req.body, { new: true });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    emitRuleChange(req, 'updated', rule.toObject());
    res.json({ rule, message: 'Rule updated' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
};

exports.deleteRule = async (req, res) => {
  try {
    const rule = await FraudRule.findById(req.params.id);
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    if (rule.isBuiltIn) return res.status(403).json({ message: 'Built-in rules cannot be deleted' });
    await rule.deleteOne();
    emitRuleChange(req, 'deleted', rule.toObject());
    res.json({ message: 'Rule deleted' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
};
