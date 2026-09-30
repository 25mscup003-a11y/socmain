/**
 * Fraud Service — Main Orchestrator
 * Coordinates: Stytch lookup → Rules Engine → Decision Engine → DB saves → Socket.IO emit
 * Called from auth routes on every login, signup, password_reset, etc.
 */
const crypto = require('crypto');
const { lookupTelemetry }  = require('./stytch.service');
const { evaluateRules }    = require('./rulesEngine.service');
const { decide, getRiskLevel } = require('./decisionEngine.service');

const FraudEvent      = require('../models/FraudEvent.model');
const FraudAlert      = require('../models/FraudAlert.model');
const FraudAuditLog   = require('../models/FraudAuditLog.model');
const Device          = require('../models/Device.model');
const DeviceHistory   = require('../models/DeviceHistory.model');
const LoginAttempt    = require('../models/LoginAttempt.model');
const RiskScore       = require('../models/RiskScore.model');
const VisitorProfile  = require('../models/VisitorProfile.model');
const BlockedDevice   = require('../models/BlockedDevice.model');
const { normalizeIpAddress } = require('../utils/clientIp');
const { parseUserAgent } = require('../utils/userAgent');

// ── Socket.IO reference (set once server starts) ───────────────────────────────
let _io = null;
function attachIO(io) { _io = io; }

function authenticationTelemetry(ipAddress, userAgent, reason) {
  const ip = normalizeIpAddress(ipAddress) || 'unknown';
  const agent = String(userAgent || '').slice(0, 1000);
  const client = parseUserAgent(agent);
  const identityHash = crypto.createHash('sha256').update(`${ip}|${agent || 'unknown-client'}`).digest('hex');
  const browserHash = crypto.createHash('sha256').update(agent || 'unknown-client').digest('hex');
  return {
    visitorId: `authv_${identityHash.slice(0, 32)}`,
    browserId: `authb_${browserHash.slice(0, 32)}`,
    deviceFingerprint: `auth_${identityHash}`,
    browserFingerprint: null,
    hardwareFingerprint: null,
    networkFingerprint: null,
    ip,
    country: null,
    region: null,
    city: null,
    asn: null,
    isp: null,
    lat: null,
    lon: null,
    browser: client.browser,
    os: client.os,
    device: client.device.toLowerCase(),
    isVpn: false,
    isTor: false,
    isProxy: false,
    isBot: false,
    riskScore: 0,
    simulated: false,
    evidenceSource: 'authentication_audit',
    raw: { source: 'authentication_audit', stytchUnavailableReason: reason },
  };
}

async function emitFraudEvent(event, payload) {
  if (!_io) return;
  _io.to('fraud:stream').emit(event, payload);
  if (payload.companyId) {
    _io.to(`company:${payload.companyId}`).emit(event, payload);
    try {
      const Company = require('../models/Company.model');
      const comp = await Company.findById(payload.companyId).select('partnerId').lean();
      if (comp && comp.partnerId) {
        _io.to(`partner:${comp.partnerId}:fraud`).emit(event, payload);
      }
    } catch (err) {
      console.error('[FraudService] Failed to emit to partner room:', err.message);
    }
  }
}

// ── Gather contextual signals for rules engine ─────────────────────────────────
async function buildContext(telemetry, userId, email, companyId) {
  const now = new Date();
  const fiveMinAgo = new Date(now - 5 * 60 * 1000);

  const [
    recentLogins,
    existingDevice,
    visitorProfile,
    blockedDevice,
  ] = await Promise.all([
    // Velocity: how many logins in last 5 min from this IP or email
    LoginAttempt.countDocuments({
      $or: [{ ipAddress: telemetry.ip }, { email }],
      createdAt: { $gte: fiveMinAgo },
    }),
    // Is this a known device?
    Device.findOne({ deviceFingerprint: telemetry.deviceFingerprint }),
    // Multi-account detection
    VisitorProfile.findOne({ visitorId: telemetry.visitorId }),
    // Is device currently blocked?
    BlockedDevice.findOne({ deviceFingerprint: telemetry.deviceFingerprint, isActive: true }),
  ]);

  const isNewDevice  = !existingDevice;
  const multipleAccounts = visitorProfile ? visitorProfile.totalAccounts > 1 : false;

  // Country change detection
  const lastCountry = existingDevice?.lastSeenCountry;
  const isNewCountry = lastCountry && lastCountry !== telemetry.country;

  return {
    isNewDevice,
    isNewCountry,
    multipleAccounts,
    multipleDevices: false,    // computed per-user if needed
    recentLoginCount: recentLogins,
    impossibleTravel: false,   // simplified — can add geo distance calc
    bruteForceDetected: recentLogins >= 5,
    existingDevice,
    visitorProfile,
    isBlocked: !!blockedDevice,
  };
}

// ── Upsert Device document ─────────────────────────────────────────────────────
async function upsertDevice(telemetry, userId, email, companyId, decisionResult, browserLocation = null) {
  const fp = telemetry.deviceFingerprint;
  if (!fp) return null;
  const decision = decisionResult?.decision || 'ALLOW';

  const update = {
    lastSeenAt:   new Date(),
    lastSeenIp:   telemetry.ip,
    lastSeenCountry: telemetry.country,
    riskScoreLast: decisionResult?.riskScore ?? telemetry.riskScore ?? 0,
    browser: telemetry.browser,
    os:      telemetry.os,
    device:  telemetry.device,
    isVpn:   telemetry.isVpn,
    isTor:   telemetry.isTor,
    isProxy: telemetry.isProxy,
    isBot:   telemetry.isBot,
    asn:     telemetry.asn,
    isp:     telemetry.isp,
    country: telemetry.country,
    region:  telemetry.region,
    city:    telemetry.city,
    identitySource: telemetry.evidenceSource === 'authentication_audit' ? 'authentication_audit' : 'stytch',
    ...(browserLocation?.permission === 'granted' ? {
      gpsLat: browserLocation.latitude,
      gpsLon: browserLocation.longitude,
      gpsAccuracyMeters: browserLocation.accuracyMeters,
      gpsCapturedAt: browserLocation.capturedAt || new Date(),
    } : {}),
    $inc: { totalLogins: 1 },
  };
  if (decision === 'BLOCK')     update.$inc.totalBlocks = 1;
  if (decision === 'CHALLENGE') update.$inc.totalChallenges = 1;
  if (userId)    { update.$addToSet = { ...(update.$addToSet || {}), userIds: userId, emails: email }; }
  if (companyId) { update.$addToSet = { ...(update.$addToSet || {}), companyIds: companyId }; }
  const { $inc, $addToSet, ...setFields } = update;

  const device = await Device.findOneAndUpdate(
    { deviceFingerprint: fp },
    {
      $setOnInsert: { firstSeenAt: new Date(), firstSeenIp: telemetry.ip, firstSeenCountry: telemetry.country, visitorId: telemetry.visitorId, browserId: telemetry.browserId, simulatedData: telemetry.simulated },
      $set: setFields,
      $inc,
      ...($addToSet ? { $addToSet } : {}),
    },
    { upsert: true, new: true }
  );

  // Update status if needed
  let newStatus = device.status;
  if (decision === 'BLOCK' && newStatus !== 'blocked') newStatus = 'blocked';
  else if (decision !== 'BLOCK' && newStatus === 'new') newStatus = 'known';
  if (newStatus !== device.status) {
    await Device.findByIdAndUpdate(device._id, { status: newStatus, statusUpdatedAt: new Date() });
  }

  return device;
}

// ── Update VisitorProfile ──────────────────────────────────────────────────────
async function updateVisitorProfile(telemetry, userId, email, companyId, riskScore) {
  if (!telemetry.visitorId) return;
  await VisitorProfile.findOneAndUpdate(
    { visitorId: telemetry.visitorId },
    {
      $setOnInsert: { firstSeenAt: new Date() },
      $set: { lastSeenAt: new Date(), lastIpAddress: telemetry.ip, lastCountry: telemetry.country, browserId: telemetry.browserId, deviceFingerprint: telemetry.deviceFingerprint },
      $addToSet: { emails: email, ...(userId ? { userIds: userId } : {}), ...(companyId ? { companyIds: companyId } : {}) },
      $inc: { totalSessions: 1 },
      $max: { maxRiskScore: riskScore },
    },
    { upsert: true, new: true }
  );
}

// ── Create FraudAlert if warranted ───────────────────────────────────────────
async function maybeCreateAlert(decisionResult, telemetry, fraudEventId, userId, email, companyId, deviceId) {
  if (!decisionResult.shouldCreateAlert) return;

  const category =
    telemetry.isTor   ? 'tor' :
    telemetry.isVpn   ? 'vpn' :
    telemetry.isProxy ? 'proxy' :
    telemetry.isBot   ? 'bot' :
    decisionResult.riskLevel === 'critical' ? 'high_risk' : 'high_risk';

  const title = `[${decisionResult.decision}] ${decisionResult.riskLevel.toUpperCase()} risk login — ${email || 'unknown'}`;
  const alert = await FraudAlert.create({
    fraudEventId,
    deviceId,
    userId,
    companyId,
    email,
    title,
    description: decisionResult.summary,
    category,
    severity: decisionResult.riskLevel === 'critical' ? 'critical' : decisionResult.highestSeverity || 'high',
    ipAddress: telemetry.ip,
    country:   telemetry.country,
    asn:       telemetry.asn,
    isVpn:     telemetry.isVpn,
    isTor:     telemetry.isTor,
    riskScore: telemetry.riskScore,
    decision:  decisionResult.decision,
    matchedRules: decisionResult.matchedRules,
    simulatedData: telemetry.simulated,
  });

  const alertObj = alert.toObject();
  alertObj.simulated = telemetry.simulated;
  emitFraudEvent('fraud:alert', alertObj);
  return alert;
}

// ─────────────────────────────────────────────────────────────────────────────
// PUBLIC API
// ─────────────────────────────────────────────────────────────────────────────

/**
 * processFraudCheck
 * Main entry point called from auth routes.
 *
 * @param {Object} params
 * @param {string} params.telemetryId - From Stytch JS SDK (or mock)
 * @param {string} params.ipAddress
 * @param {string} params.userAgent
 * @param {string} params.action      - 'login' | 'signup' | 'password_reset' etc.
 * @param {string} [params.email]
 * @param {string} [params.userId]
 * @param {string} [params.companyId]
 *
 * @returns {Promise<{decision, riskScore, riskLevel, requiresMFA, blocked, decisionResult, fraudEventId}>}
 */
async function processFraudCheck({ telemetryId, ipAddress, userAgent, action = 'login', email, userId, companyId, allowAuthFallback = false, browserLocation = null }) {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const auditStages = {};

  try {
    // ── Stage 1: Stytch Lookup ─────────────────────────────────────────────
    const stageS = Date.now();
    let telemetry;
    try {
      telemetry = await lookupTelemetry(telemetryId, ipAddress);
      telemetry.evidenceSource = telemetry.simulated ? 'simulation' : 'stytch';
      auditStages.stytchLookup = { success: true, durationMs: Date.now() - stageS, simulated: telemetry.simulated };
    } catch (lookupError) {
      if (!allowAuthFallback || !['STYTCH_UNAVAILABLE', 'STYTCH_TELEMETRY_MISSING'].includes(lookupError.code)) throw lookupError;
      telemetry = authenticationTelemetry(ipAddress, userAgent, lookupError.message);
      auditStages.stytchLookup = {
        success: false,
        durationMs: Date.now() - stageS,
        simulated: false,
        error: lookupError.message,
        fallback: 'authentication_audit',
      };
    }

    // ── Stage 2: Context Building ─────────────────────────────────────────
    const context = await buildContext(telemetry, userId, email, companyId);

    // ── Fast Path: Is device explicitly blocked? ───────────────────────────
    if (context.isBlocked) {
      const blockedResult = {
        decision: 'BLOCK',
        riskScore: 100,
        riskLevel: 'critical',
        requiresMFA: false,
        shouldLockAccount: false,
        shouldBlockIP: false,
        shouldBlockDevice: true,
        shouldCreateAlert: true,
        matchedRules: ['Device Blocklist'],
        highestSeverity: 'critical',
        summary: `Device explicitly blocked (fingerprint: ${telemetry.deviceFingerprint?.slice(0, 16)}...)`,
      };
      return { decision: 'BLOCK', riskScore: 100, riskLevel: 'critical', requiresMFA: false, blocked: true, decisionResult: blockedResult, requestId };
    }

    // ── Stage 3: Rules Engine ─────────────────────────────────────────────
    const stageR = Date.now();
    const rulesResult = await evaluateRules(telemetry, context);
    auditStages.rulesEngine = {
      success: true,
      durationMs: Date.now() - stageR,
      rulesEvaluated: -1,
      rulesMatched: rulesResult.matchedRules.length,
      matchedRuleNames: rulesResult.matchedRules,
    };

    // ── Stage 4: Decision Engine ──────────────────────────────────────────
    const stageD = Date.now();
    const decisionResult = decide(telemetry, rulesResult, context);
    auditStages.decisionEngine = {
      success: true,
      durationMs: Date.now() - stageD,
      decision: decisionResult.decision,
      riskScore: decisionResult.riskScore,
    };

    // ── Stage 5: Persist to DB ────────────────────────────────────────────
    const stageDb = Date.now();
    const device = await upsertDevice(telemetry, userId, email, companyId, decisionResult, browserLocation);
    await updateVisitorProfile(telemetry, userId, email, companyId, telemetry.riskScore);

    const fraudEvent = await FraudEvent.create({
      requestId,
      userId,
      companyId,
      email,
      evidenceSource: telemetry.evidenceSource === 'authentication_audit' ? 'authentication_audit' : 'stytch',
      telemetryId,
      visitorId:          telemetry.visitorId,
      browserId:          telemetry.browserId,
      deviceFingerprint:  telemetry.deviceFingerprint,
      browserFingerprint: telemetry.browserFingerprint,
      hardwareFingerprint:telemetry.hardwareFingerprint,
      networkFingerprint: telemetry.networkFingerprint,
      ipAddress:          telemetry.ip,
      country:            telemetry.country,
      region:             telemetry.region,
      city:               telemetry.city,
      asn:                telemetry.asn,
      isp:                telemetry.isp,
      lat:                telemetry.lat,
      lon:                telemetry.lon,
      isVpn:              telemetry.isVpn,
      isTor:              telemetry.isTor,
      isProxy:            telemetry.isProxy,
      isBot:              telemetry.isBot,
      browser:            telemetry.browser,
      os:                 telemetry.os,
      device:             telemetry.device,
      userAgent,
      riskScore:          decisionResult.riskScore,
      riskLevel:          decisionResult.riskLevel,
      decision:           decisionResult.decision,
      requiresMFA:        decisionResult.requiresMFA,
      shouldLockAccount:  decisionResult.shouldLockAccount,
      shouldBlockIP:      decisionResult.shouldBlockIP,
      shouldBlockDevice:  decisionResult.shouldBlockDevice,
      shouldCreateAlert:  decisionResult.shouldCreateAlert,
      matchedRules:       decisionResult.matchedRules,
      action,
      stytchResponse:     telemetry.raw,
      simulatedData:      telemetry.simulated,
      deviceId:           device?._id,
    });

    // Save login attempt record
    await LoginAttempt.create({
      userId, companyId, email,
      action,
      success: decisionResult.decision !== 'BLOCK',
      ipAddress: telemetry.ip,
      userAgent,
      country: telemetry.country,
      asn: telemetry.asn,
      fraudEventId: fraudEvent._id,
      telemetryId,
      visitorId:         telemetry.visitorId,
      browserId:         telemetry.browserId,
      deviceFingerprint: telemetry.deviceFingerprint,
      deviceId:          device?._id,
      riskScore:         decisionResult.riskScore,
      riskLevel:         decisionResult.riskLevel,
      decision:          decisionResult.decision,
      matchedRules:      decisionResult.matchedRules,
      isVpn:  telemetry.isVpn,
      isTor:  telemetry.isTor,
      isProxy:telemetry.isProxy,
    });

    // Save risk score record
    await RiskScore.create({
      fraudEventId: fraudEvent._id,
      userId, companyId, email,
      deviceId: device?._id,
      visitorId: telemetry.visitorId,
      ipAddress: telemetry.ip,
      score:     decisionResult.riskScore,
      level:     decisionResult.riskLevel,
      decision:  decisionResult.decision,
      action,
      matchedRules: decisionResult.matchedRules,
      country: telemetry.country,
      isVpn: telemetry.isVpn,
      isTor: telemetry.isTor,
    });

    auditStages.dbSave = { success: true, durationMs: Date.now() - stageDb };

    // ── Stage 6: Create alert if warranted ────────────────────────────────
    await maybeCreateAlert(decisionResult, telemetry, fraudEvent._id, userId, email, companyId, device?._id);

    // ── Stage 7: Device history entry ─────────────────────────────────────
    await DeviceHistory.create({
      deviceId: device?._id,
      visitorId: telemetry.visitorId,
      browserId: telemetry.browserId,
      userId, companyId, email, action,
      ipAddress: telemetry.ip,
      country: telemetry.country,
      city: telemetry.city,
      asn: telemetry.asn,
      isp: telemetry.isp,
      userAgent,
      isVpn: telemetry.isVpn,
      isTor: telemetry.isTor,
      isProxy: telemetry.isProxy,
      riskScore: decisionResult.riskScore,
      riskLevel: decisionResult.riskLevel,
      decision: decisionResult.decision,
      matchedRules: decisionResult.matchedRules,
      requestId,
    });

    // ── Stage 8: Emit Socket.IO event ─────────────────────────────────────
    const socketPayload = {
      requestId,
      fraudEventId: fraudEvent._id,
      email,
      companyId,
      action,
      visitorId:   telemetry.visitorId,
      browserId:   telemetry.browserId,
      fingerprint: telemetry.deviceFingerprint,
      ip:          telemetry.ip,
      country:     telemetry.country,
      asn:         telemetry.asn,
      isp:         telemetry.isp,
      browser:     telemetry.browser,
      os:          telemetry.os,
      isVpn:       telemetry.isVpn,
      isTor:       telemetry.isTor,
      isProxy:     telemetry.isProxy,
      riskScore:   decisionResult.riskScore,
      riskLevel:   decisionResult.riskLevel,
      decision:    decisionResult.decision,
      matchedRules:decisionResult.matchedRules,
      simulated:   telemetry.simulated,
      source:      telemetry.evidenceSource || 'stytch',
      ts:          new Date(),
    };
    emitFraudEvent('fraud:event', socketPayload);
    if (context.isNewDevice) emitFraudEvent('fraud:device:new', socketPayload);
    if (decisionResult.decision === 'BLOCK') emitFraudEvent('fraud:device:blocked', socketPayload);

    // ── Save audit log ────────────────────────────────────────────────────
    FraudAuditLog.create({
      requestId,
      fraudEventId: fraudEvent._id,
      userId, companyId, email,
      action,
      ipAddress: telemetry.ip,
      telemetryId,
      visitorId: telemetry.visitorId,
      stages: auditStages,
      finalDecision: decisionResult.decision,
      riskScore: decisionResult.riskScore,
      totalDurationMs: Date.now() - startTime,
    }).catch(() => {});

    console.log(`[Fraud] ${action} | ${email} | ${decisionResult.decision} | score=${decisionResult.riskScore} | rules=[${decisionResult.matchedRules.join(',')}]`);

    return {
      decision:      decisionResult.decision,
      riskScore:     decisionResult.riskScore,
      riskLevel:     decisionResult.riskLevel,
      requiresMFA:   decisionResult.requiresMFA,
      blocked:       decisionResult.decision === 'BLOCK',
      decisionResult,
      requestId,
      fraudEventId:  fraudEvent._id,
    };

  } catch (err) {
    if (!['STYTCH_UNAVAILABLE', 'STYTCH_TELEMETRY_MISSING'].includes(err.code)) {
      console.error('[FraudService] Error in processFraudCheck:', err.message);
    }
    // Log the error but do NOT block the user — fail open for reliability
    FraudAuditLog.create({
      requestId,
      userId, companyId, email, action,
      stages: auditStages,
      error: err.message,
      totalDurationMs: Date.now() - startTime,
    }).catch(() => {});

    if (['STYTCH_UNAVAILABLE', 'STYTCH_TELEMETRY_MISSING'].includes(err.code)) {
      return {
        decision: 'CHALLENGE',
        riskScore: 50,
        riskLevel: 'medium',
        requiresMFA: true,
        blocked: false,
        decisionResult: null,
        requestId,
        fraudEventId: null,
        error: err.message,
      };
    }

    // Non-telemetry internal errors remain fail-open for platform availability.
    return {
      decision: 'ALLOW',
      riskScore: 0,
      riskLevel: 'low',
      requiresMFA: false,
      blocked: false,
      decisionResult: null,
      requestId,
      fraudEventId: null,
      error: err.message,
    };
  }
}

module.exports = { processFraudCheck, attachIO };
