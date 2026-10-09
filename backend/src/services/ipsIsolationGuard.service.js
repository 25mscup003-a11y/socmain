const System = require('../models/System.model');
const Alert = require('../models/Alert.model');

const FRESHNESS_MS = 120000;
const COMMAND_TTL_MS = 30000;
const DEFERRED_PREFIX = 'Automatic isolation deferred:';
const deferred = reason => ({ allowed: false, reason });
const timestamp = value => value == null ? NaN : new Date(value).getTime();

function isAutomaticIsolation(command) {
  return command?.command === 'isolate' && (command.autoIsolation != null
    || /^Automatic IPS isolation\b/i.test(String(command.reason || '')));
}

function commandValidityError(command, now = Date.now()) {
  if (!isAutomaticIsolation(command)) return null;
  const proof = command.autoIsolation;
  const verified = timestamp(proof?.verifiedAt);
  const expires = timestamp(proof?.expiresAt);
  const started = timestamp(proof?.incidentStartedAt);
  if (proof?.version !== 1 || !proof.threatAlertId || typeof proof.requireUnconfirmedBlock !== 'boolean'
      || !Number.isFinite(verified) || !Number.isFinite(expires) || !Number.isFinite(started)
      || started >= verified || verified > now || expires <= verified || expires - verified > COMMAND_TTL_MS) {
    return 'missing or invalid fresh-threat verification';
  }
  if (now >= expires) return 'fresh-threat verification expired';
  return null;
}

// A repeated/new persisted detection is required. Ingestion of old buffered
// telemetry and IPS action records cannot provide evidence of an ongoing attack.
async function checkAutoIsolation({ companyId, systemId, srcIp, startedAt,
  requireUnconfirmedBlock = true, threatAlertId = null, commandId = null }) {
  try {
    const now = Date.now();
    const started = timestamp(startedAt);
    if (!companyId || !systemId || !srcIp || !Number.isFinite(started) || started >= now) {
      return deferred('incident is missing an exact endpoint, source IP or valid start time');
    }
    const system = await System.findOne({ _id: systemId, companyId, isActive: true })
      .select('companyId isActive agentVersion ipsEnabled responseEnabled lastSeen blockedIps isIsolated isolationStatus isolationCommandId pendingCommands lastIpsCommand').lean();
    if (!system || system.isActive !== true || !String(system.agentVersion || '').trim()) {
      return deferred('target is not an active enrolled endpoint');
    }
    if (system.ipsEnabled === false || system.responseEnabled === false) return deferred('endpoint IPS or response is disabled');
    const heartbeat = timestamp(system.lastSeen);
    if (!Number.isFinite(heartbeat) || heartbeat > now || now - heartbeat >= FRESHNESS_MS) {
      return deferred('endpoint heartbeat is missing or older than 2 minutes');
    }
    if (system.isIsolated === true) return deferred('endpoint is already isolated');
    if (system.isolationStatus === 'reconnecting' || system.pendingCommands?.some(item => item.command === 'reconnect')
        || (system.lastIpsCommand?.command === 'reconnect'
          && Math.max(timestamp(system.lastIpsCommand.queuedAt) || 0, timestamp(system.lastIpsCommand.completedAt) || 0) >= started)) {
      return deferred('endpoint recovery superseded this incident');
    }
    if (commandId && !system.pendingCommands?.some(item => item.command === 'isolate' && String(item.id || item.commandId) === String(commandId))) {
      return deferred('isolation command was superseded');
    }
    if (requireUnconfirmedBlock && system.blockedIps?.includes(srcIp)) return deferred('endpoint has confirmed the source IP block');
    const { isWhitelistedForCompany } = require('./ips.service');
    if (await isWhitelistedForCompany(srcIp, companyId, { requireRemote: true })) return deferred('source IP now matches an active allow rule or whitelist');

    const since = new Date(Math.max(started, now - FRESHNESS_MS));
    const until = new Date(now);
    const alert = await Alert.findOne({
      companyId, systemId, srcip: srcIp,
      ...(threatAlertId ? { _id: threatAlertId } : {}),
      severity: { $in: ['high', 'critical'] },
      status: { $in: ['open', 'investigating'] },
      underObservation: { $ne: true }, isSynthetic: { $ne: true },
      dataOrigin: { $nin: ['synthetic', 'manual'] },
      blocked: { $ne: true }, quarantined: { $ne: true },
      action: { $nin: ['blocked', 'dropped', 'rejected', 'quarantined'] },
      actionTaken: { $nin: ['Blocked', 'Quarantined', 'Deleted', 'Isolated', 'Logged Out'] },
      containmentStatus: { $nin: ['blocked', 'quarantined', 'isolated', 'logged_out'] },
      event_category: { $nin: ['ips_action', 'ips_block', 'blacklist_event'] },
      sourceType: { $ne: 'IPS' }, module: { $ne: 'IPS' }, source_type: { $ne: 'ips' },
      source: { $not: /^ips$/i }, type: { $not: /^IPS_/i },
      createdAt: { $gt: since, $lte: until },
      $and: [
        { $or: [{ eventTimestamp: null }, { eventTimestamp: { $gt: since, $lte: until } }] },
        { $or: [{ receivedAt: null }, { receivedAt: { $gt: since, $lte: until } }] },
      ],
    }).sort({ createdAt: -1 }).select('_id createdAt eventTimestamp').lean();
    if (!alert) return deferred('no new active High/Critical detection for this endpoint and source IP in the last 2 minutes');
    const threatDecision = await require('./ipsThreatGate.service').verifyAutomaticNetworkAction({
      ip: srcIp, companyId, systemId, action: 'isolate', alertId: alert._id,
    });
    if (!threatDecision.allowed) return deferred(threatDecision.reason);
    const verifiedAt = Date.now();
    const expiresAt = Math.min(verifiedAt + COMMAND_TTL_MS, heartbeat + FRESHNESS_MS, Date.parse(threatDecision.expiresAt),
      timestamp(alert.createdAt) + FRESHNESS_MS,
      timestamp(alert.eventTimestamp || alert.createdAt) + FRESHNESS_MS);
    if (expiresAt <= verifiedAt) return deferred('heartbeat or threat evidence became stale during verification');
    return { allowed: true, reason: 'fresh ongoing threat and endpoint heartbeat verified',
      threatVerification: threatDecision.verification,
      autoIsolation: { version: 1, incidentStartedAt: new Date(started).toISOString(),
        verifiedAt: new Date(verifiedAt).toISOString(), expiresAt: new Date(expiresAt).toISOString(),
        threatAlertId: String(alert._id), requireUnconfirmedBlock } };
  } catch (error) {
    return deferred(`verification unavailable: ${error.message}`);
  }
}

// Shared by both heartbeat routes and immediate socket delivery. Never extend
// the original expiry when a queued command is retried or the agent reconnects.
async function filterDeliverableCommands({ companyId, systemId, commands }) {
  const deliverable = [];
  for (const command of commands || []) {
    if (!isAutomaticIsolation(command)) { deliverable.push(command); continue; }
    let reason = commandValidityError(command);
    if (!reason) {
      const proof = command.autoIsolation;
      const check = await checkAutoIsolation({ companyId, systemId, srcIp: command.srcIp,
        startedAt: proof.incidentStartedAt, requireUnconfirmedBlock: proof.requireUnconfirmedBlock,
        threatAlertId: proof.threatAlertId, commandId: command.id || command.commandId });
      reason = check.allowed ? commandValidityError(command) : check.reason;
    }
    if (!reason) { deliverable.push(command); continue; }
    // Use the existing atomic ACK/queue lifecycle so a concurrent reconnect or
    // already accepted ACK is never overwritten by this cancellation.
    try {
      await require('./ips.service').recordAgentCommandResult({ systemId,
        commandId: command.id || command.commandId, command: 'isolate', ok: false,
        message: `${DEFERRED_PREFIX} ${reason}` });
    } catch (error) {
      console.warn(`[IPS] Automatic isolation cancellation pending: ${error.message}`);
    }
  }
  return require('./ipsThreatGate.service').filterNetworkCommands({ companyId, systemId, commands: deliverable });
}

module.exports = { FRESHNESS_MS, COMMAND_TTL_MS, DEFERRED_PREFIX, isAutomaticIsolation,
  commandValidityError, checkAutoIsolation, filterDeliverableCommands };
