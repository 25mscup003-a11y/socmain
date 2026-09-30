/**
 * ips.service.js  — Active IPS Response Engine
 *
 * Auto-blocks malicious IPs via:
 *   1. IPS Webhook Server
 *   2. Linux nftables (on Linux IPS server)
 *   3. Windows Defender Firewall (on Windows IPS server)
 *
 * Triggered automatically when:
 *   - Alert severity === 'critical' AND eventCategory === 'network'
 *   - IDS/Suricata sends a DROP-action alert
 *   - Correlation engine detects brute-force + malware pattern
 *   - SOAR rule fires a "block_ip" action
 *
 * Maintains an in-memory + MongoDB blocklist.
 */

const { exec } = require('child_process');
const axios = require('axios');
const mongoose = require('mongoose');
const { Address6 } = require('ip-address');
const System = require('../models/System.model');
const Alert = require('../models/Alert.model');
const Firewall = require('../models/Firewall.model');
const IpsWhitelist = require('../models/IpsWhitelist.model');
const { normalizeThreatLabels } = require('../utils/threatIntelLabels');

// ── BlockList schema (embedded in IOC model) ──────────────────────────────────
const BlockSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  ip: { type: String, required: true, index: true },
  port: { type: Number },  // optional port (null = all ports)
  reason: String,
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert' },
  blockedBy: { type: String, enum: ['auto', 'analyst', 'soar'], default: 'auto' },
  method: { type: String },   // 'webhook', 'nftables', 'windows-defender', 'log-only'
  reverted: { type: Boolean, default: false },
  revertedAt: { type: Date },
  revertReason: { type: String },
  blockedAt: { type: Date, default: Date.now },
  expiresAt: { type: Date },
  // ── Threat Intelligence metadata (for TI auto-blocks) ───────────────────
  abuseScore:      { type: Number },           // AbuseIPDB confidence score 0-100
  otxPulses:       { type: Number },           // OTX AlienVault pulse count
  malwareFamilies: { type: [String], set: value => normalizeThreatLabels(value, { limit: 10 }) }, // malware families from OTX
  feedSource:      { type: String },           // e.g. 'Feodo Tracker C2', 'AbuseIPDB'
  geoCountry:      { type: String },           // country code from AbuseIPDB
}, { timestamps: true });

BlockSchema.index({ companyId: 1, ip: 1 }, { unique: true, partialFilterExpression: { reverted: false } });
const BlockedIP = mongoose.models.BlockedIP || mongoose.model('BlockedIP', BlockSchema);

// ── Config from env ────────────────────────────────────────────────────────────
const IPS_MODE = process.env.IPS_MODE || 'host-firewall';  // 'log' | 'host-firewall' | 'webhook'
const IPS_WEBHOOK_URL = process.env.IPS_WEBHOOK_URL || '';
const IPS_WEBHOOK_SECRET = process.env.IPS_WEBHOOK_SECRET || '';
const IPS_AUTO_BLOCK = process.env.IPS_AUTO_BLOCK === 'true';
const IPS_BLOCK_TTL_H = parseInt(process.env.IPS_BLOCK_TTL_HOURS || '24', 10);
const IPS_AUTO_RECOVER_DELAY_MS = Math.max(1000, parseInt(process.env.IPS_AUTO_RECOVER_DELAY_MS || `${20 * 60 * 1000}`, 10));

const PRIVATE_RANGES = [
  /^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./,
  /^127\./, /^::1$/, /^fc[0-9a-f]{2}:/i, /^localhost$/i,
];

function normalizeIP(value = '') {
  let ip = String(value || '').trim();
  const bracketed = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) ip = bracketed[1];
  if (/^::ffff:/i.test(ip)) ip = ip.slice(7);
  return ip;
}

const isPrivateIP = value => {
  const ip = normalizeIP(value);
  return !ip || PRIVATE_RANGES.some(range => range.test(ip));
};
const isLoopbackIP = value => {
  const ip = normalizeIP(value);
  return /^127\./.test(ip) || ip === '::1' || /^localhost$/i.test(ip);
};

// ── Blocklist cache (in-process) ───────────────────────────────────────────────
const _blocked = new Set();
let expirySweepTimer = null;

async function persistIpsActionAlert({ block, sourceAlertId, enforcement, reason, blockedBy, systemId = null }) {
  if (!block?._id || !block.companyId || !block.ip) return null;
  const sourceAlert = sourceAlertId
    ? await Alert.findOne({ _id: sourceAlertId, companyId: block.companyId }).lean().catch(() => null)
    : null;
  const prevented = Boolean(enforcement?.ok);
  const eventTimestamp = block.blockedAt ? new Date(block.blockedAt) : new Date();
  const ruleId = blockedBy === 'analyst' ? 'IPS_MANUAL_BLOCK' : blockedBy === 'soar' ? 'IPS_SOAR_BLOCK' : 'IPS_AUTO_BLOCK';
  const alert = await Alert.findOneAndUpdate(
    { companyId: block.companyId, eventId: `ips:block:${block._id}` },
    {
      $set: {
        tenantId: sourceAlert?.tenantId || null,
        partnerId: sourceAlert?.partnerId || null,
        departmentId: sourceAlert?.departmentId || null,
        systemId: sourceAlert?.systemId || systemId || null,
        endpointId: sourceAlert?.endpointId || (systemId ? String(systemId) : undefined),
        agentId: sourceAlert?.agentId,
        agentName: sourceAlert?.agentName || 'IPS Engine',
        hostname: sourceAlert?.hostname,
        schemaVersion: 1,
        sourceType: 'IPS', sourceVendor: 'SOC IPS Engine', source: 'ips', sensor: 'IPS Engine',
        module: 'IPS', source_type: 'ips', event_category: 'ips_action', eventCategory: 'network',
        normalizedEventType: 'IPS_BLOCK_ATTEMPT', eventName: prevented ? 'IPS Prevention Successful' : 'IPS Prevention Failed',
        ruleId, type: 'IPS_BLOCK', severity: prevented ? 'medium' : 'high',
        status: 'open', actionable: true, blocked: prevented,
        action: prevented ? 'blocked' : 'allowed',
        actionTaken: prevented ? 'Blocked' : 'Allowed',
        containmentStatus: prevented ? 'blocked' : 'allowed',
        srcip: block.ip,
        destip: sourceAlert?.destip,
        srcPort: sourceAlert?.srcPort,
        destPort: block.port || sourceAlert?.destPort,
        protocol: sourceAlert?.protocol,
        direction: sourceAlert?.direction || 'inbound',
        signatureId: sourceAlert?.signatureId,
        signatureName: sourceAlert?.signatureName,
        attackType: sourceAlert?.attackType || 'IPS prevention action',
        description: prevented
          ? `IPS blocked ${block.ip}${block.port ? `:${block.port}` : ''}: ${reason || 'security policy'}`
          : `IPS attempted to block ${block.ip}${block.port ? `:${block.port}` : ''}, but enforcement failed: ${enforcement?.error || 'firewall unavailable'}`,
        eventTimestamp, receivedAt: eventTimestamp,
        riskScore: prevented ? 60 : 75,
        metadata: {
          blockedIpId: String(block._id), sourceAlertId: sourceAlertId ? String(sourceAlertId) : null,
          blockedBy: blockedBy || block.blockedBy, enforcementMethod: block.method || 'host-firewall',
          enforcementSucceeded: prevented, enforcementError: enforcement?.error || null,
        },
        rawEvent: {
          blockId: String(block._id), ip: block.ip, port: block.port || null,
          reason, blockedBy: blockedBy || block.blockedBy, enforcementSucceeded: prevented,
        },
      },
      $setOnInsert: {
        eventId: `ips:block:${block._id}`, companyId: block.companyId,
        dataOrigin: 'integration', createdAt: eventTimestamp,
      },
    },
    { upsert: true, new: true, runValidators: true },
  );
  try {
    const { scheduleCompanyCorrelation } = require('./correlation.service');
    scheduleCompanyCorrelation(String(block.companyId), global.io);
  } catch (error) {
    console.warn('[IPS] Correlation scheduling failed:', error.message);
  }
  return alert;
}

async function loadBlockCache() {
  try {
    await sweepExpiredBlocks();
    await revokeLoopbackBlocks();
    const now = new Date();
    const docs = await BlockedIP.find({
      reverted: false,
      $or: [
        { expiresAt: { $exists: false } },
        { expiresAt: null },
        { expiresAt: { $gt: now } },
      ],
    }).select('ip port').lean();
    docs.forEach(d => {
      if (!d.ip) return;
      _blocked.add(d.port ? `${d.ip}:${d.port}` : d.ip);
    });
    console.log(`[IPS] Loaded ${_blocked.size} blocked IPs into cache`);
  } catch { }
}

async function revokeLoopbackBlocks() {
  const legacyLoopbackBlocks = await BlockedIP.find({
    reverted: false,
    $or: [
      { ip: /^127\./ },
      { ip: /^::ffff:127\./i },
      { ip: /^localhost$/i },
      { ip: '::1' },
    ],
  }).select('_id companyId ip port').lean().catch(() => []);

  if (!legacyLoopbackBlocks.length) return 0;

  await BlockedIP.updateMany(
    { _id: { $in: legacyLoopbackBlocks.map(block => block._id) } },
    {
      $set: {
        reverted: true,
        revertedAt: new Date(),
        revertReason: 'Loopback addresses cannot be blocked by IPS',
      },
    },
  );

  await Promise.allSettled(legacyLoopbackBlocks.flatMap(block => {
    const normalizedIp = normalizeIP(block.ip);
    _blocked.delete(block.ip);
    _blocked.delete(normalizedIp);
    if (block.port) {
      _blocked.delete(`${block.ip}:${block.port}`);
      _blocked.delete(`${normalizedIp}:${block.port}`);
    }
    return [block.ip, normalizedIp]
      .filter((ip, index, ips) => ip && ips.indexOf(ip) === index)
      .map(ip => unblockViaWebhook(ip, block.companyId));
  }));

  console.warn(`[IPS] Revoked ${legacyLoopbackBlocks.length} invalid loopback block record(s)`);
  return legacyLoopbackBlocks.length;
}

async function sweepExpiredBlocks() {
  const now = new Date();
  const expired = await BlockedIP.find({
    reverted: false,
    expiresAt: { $lte: now },
  }).select('companyId ip port').lean().catch(() => []);

  if (!expired.length) return 0;

  for (const block of expired) {
    if (!block.ip) continue;
    const blockKey = block.port ? `${block.ip}:${block.port}` : block.ip;
    _blocked.delete(block.ip);
    _blocked.delete(blockKey);
    if (process.send) {
      process.send({ type: 'block_cache_sync', action: 'delete_multiple', ips: [block.ip, blockKey], senderPid: process.pid });
    }
    // Expiry is an enforcement action, not just a database cleanup. Send the
    // inverse command to every enrolled endpoint before deleting the record.
    await Promise.allSettled([
      unblockViaWebhook(block.ip, block.companyId),
      queueAgentUnblock({ companyId: block.companyId, ip: block.ip, reason: 'TTL expired auto-unblock' }),
    ]);
  }

  const ids = expired.map(block => block._id).filter(Boolean);
  if (ids.length) {
    await BlockedIP.deleteMany(
      { _id: { $in: ids } },
    ).catch(() => {});
  }

  console.log(`[IPS] TTL expired — auto-unblocked and deleted ${expired.length} block(s)`);
  return expired.length;
}

function startExpirySweeper(intervalMs = 5 * 60 * 1000) {
  if (expirySweepTimer) return expirySweepTimer;
  expirySweepTimer = setInterval(() => {
    sweepExpiredBlocks().catch(err => console.warn('[IPS] Expiry sweep failed:', err.message));
  }, intervalMs);
  if (typeof expirySweepTimer.unref === 'function') expirySweepTimer.unref();
  return expirySweepTimer;
}

// ── Core: block an IP ─────────────────────────────────────────────────────────
async function blockIP({ ip, port, companyId, reason = 'Auto-blocked by IPS', alertId, blockedBy = 'auto', ttlHours,
  systemId, mac,
  // TI metadata (optional — passed from threat-intel.service when auto-blocking)
  abuseScore, otxPulses, malwareFamilies, feedSource, geoCountry
} = {}) {
  ip = normalizeIP(ip);
  if (!ip || isPrivateIP(ip)) return { ok: false, reason: 'private/invalid IP' };
  if (await isWhitelistedForCompany(ip, companyId)) {
    console.log(`[IPS] Block bypassed by active whitelist/allow rule: ${ip}`);
    return { ok: false, reason: 'whitelisted by active whitelist/allow rule', whitelisted: true };
  }
  if (!systemId && alertId) {
    const sourceIdentity = await Alert.findOne({ _id: alertId, companyId })
      .select('systemId').lean().catch(() => null);
    systemId = sourceIdentity?.systemId || null;
  }
  const blockKey = port ? `${ip}:${port}` : ip;
  const alreadyRecorded = _blocked.has(blockKey);

  const ttl = ttlHours ? (ttlHours * 3600000) : (IPS_BLOCK_TTL_H * 3600000);
  const expiresAt = ttl > 0 ? new Date(Date.now() + ttl) : null;
  const normalizedMalwareFamilies = normalizeThreatLabels(malwareFamilies, { limit: 10 });

  // Persist to backend DB first so the SOC has an audit trail even if an
  // external firewall is temporarily unavailable.
  let dbSaved = alreadyRecorded;
  let blockDocument = null;
  try {
    blockDocument = await BlockedIP.findOneAndUpdate(
      { companyId, ip, port: port || null },
      {
        companyId, ip, port: port || null, reason, alertId, blockedBy,
        method: 'host-firewall', expiresAt, reverted: false,
        // Store TI metadata if provided
        ...(abuseScore    != null && { abuseScore }),
        ...(otxPulses     != null && { otxPulses }),
        ...(normalizedMalwareFamilies.length && { malwareFamilies: normalizedMalwareFamilies }),
        ...(feedSource    && { feedSource }),
        ...(geoCountry    && { geoCountry }),
      },
      { upsert: true, new: true }
    );
    _blocked.add(blockKey);
    dbSaved = true;
    if (process.send) {
      process.send({ type: 'block_cache_sync', action: 'add', ip: blockKey, senderPid: process.pid });
    }
  } catch (err) {
    if (err.code !== 11000) console.error('[IPS] DB error:', err.message);
    if (err.code === 11000) dbSaved = true;
  }

  // Delegate actual host firewall enforcement to IPS Webhook Server.
  let blockResult = { ok: true, method: 'host-firewall', ip, port };
  const webhookBlock = blockViaWebhook(ip, reason, companyId, { systemId, mac });

  const [whResult] = await Promise.allSettled([
    // Always notify the IPS Webhook Server when configured. The /ids Blocklist
    // UI reads the IPS server blocklist, so TI auto-blocks must land there too.
    IPS_WEBHOOK_URL ? webhookBlock : Promise.resolve({ ok: false, error: 'webhook not configured' })
  ]).then(results => results.map(r => r.value || { ok: false }));

  blockResult.webhook   = whResult;
  blockResult.dbSaved   = dbSaved;
  blockResult.webhookOk = Boolean(whResult.ok && whResult.enforced === true);

  // The central service returns HTTP 200 for a whitelist skip. That is not a
  // successful block and must never be followed by an endpoint block command.
  if (whResult.whitelisted || whResult.skipped) {
    _blocked.delete(blockKey);
    await BlockedIP.updateMany(
      { companyId, ip, port: port || null, reverted: false },
      { $set: { reverted: true, revertedAt: new Date(), revertReason: whResult.reason || 'Whitelisted by IPS server' } },
    ).catch(() => {});
    return {
      ok: false, dbSaved, webhookOk: false, whitelisted: true,
      reason: whResult.reason || 'whitelisted by IPS server', webhook: whResult,
      ip, expiresAt, agentDispatch: { queued: 0, confirmed: false, status: 'skipped' },
    };
  }

  if (!whResult.ok) {
    console.warn(`[IPS] Block DB-recorded for ${ip} but webhook enforcement failed (${whResult.error || 'webhook offline'}) — ${reason}`);
  } else {
    console.log(`[IPS] Block applied for ${ip} via DB + webhook: ${whResult.ok} — ${reason}`);
  }

  // Persisted blocks must reach every installed, active IPS agent.  Offline
  // agents receive the same command on their next authenticated heartbeat.
  let agentDispatch = { queued: 0 };
  if (dbSaved) {
    try {
      agentDispatch = await queueAgentBlock({ companyId, ip, port, reason, systemId });
    } catch (error) {
      console.warn(`[IPS] Agent block synchronization failed for ${ip}: ${error.message}`);
    }
  }

  // A durable queue is useful state, but is not proof of enforcement. Only an
  // endpoint ACK/already-active state or a real central firewall result counts
  // as a successful block.
  const endpointAccepted = Boolean(
    agentDispatch.confirmed || agentDispatch.alreadyActive ||
    agentDispatch.queued > 0 || agentDispatch.pending > 0
  );
  blockResult.agentAccepted = endpointAccepted;
  blockResult.agentConfirmed = Boolean(agentDispatch.confirmed || agentDispatch.alreadyActive);
  blockResult.ok = dbSaved && (blockResult.webhookOk || blockResult.agentConfirmed);
  if (alreadyRecorded && agentDispatch.alreadyActive) {
    blockResult.note = 'already blocked';
    blockResult.reason = 'already blocked';
  }

  if (blockDocument) {
    const enforcement = blockResult.agentConfirmed
      ? { ok: true, method: 'endpoint-agent' }
      : blockResult.webhookOk
        ? whResult
        : { ok: false, method: 'endpoint-agent-queue', error: endpointAccepted ? 'Awaiting endpoint ACK' : whResult.error };
    await persistIpsActionAlert({
      block: blockDocument, sourceAlertId: alertId, enforcement,
      reason, blockedBy, systemId,
    }).catch(error => console.error('[IPS] Action alert persistence failed:', error.message));
  }

  // Schedule expiry check (only if TTL is set)
  if (ttl > 0) {
    setTimeout(() => unblockIP({ ip, companyId, reason: 'TTL expired auto-unblock' }), ttl);
  }

  return { ...blockResult, ip, reason: blockResult.reason || reason, expiresAt, agentDispatch };
}

// ── Unblock ────────────────────────────────────────────────────────────────────
async function unblockIP({ ip, companyId, reason = 'Manual unblock', skipWebhook = false, systemId = null }) {
  const originalIp = ip;
  ip = normalizeIP(ip);
  const ips = [...new Set([originalIp, ip].filter(Boolean))];
  ips.forEach(blockedIp => _blocked.delete(blockedIp));
  if (process.send) {
    process.send({ type: 'block_cache_sync', action: 'delete_multiple', ips, senderPid: process.pid });
  }
  const dbResult = await BlockedIP.updateMany(
    { companyId, ip: { $in: ips } },
    { $set: { reverted: true, revertedAt: new Date(), revertReason: reason } },
  );

  if (!skipWebhook) await Promise.allSettled(ips.map(blockedIp => unblockViaWebhook(blockedIp, companyId)));
  const dispatches = await Promise.all(ips.map(blockedIp => queueAgentUnblock({ companyId, ip: blockedIp, reason, systemId })));

  console.log(`[IPS] Unblock request for ${ip} sent to host firewall webhook — ${reason}`);
  return {
    ok: dispatches.some(dispatch => dispatch.confirmed),
    accepted: dispatches.some(dispatch => dispatch.queued > 0 || dispatch.pending > 0),
    ip, reason, dbUpdated: dbResult.modifiedCount || 0, agentDispatch: dispatches[0] || null,
  };
}

function isBlocked(ip) { return _blocked.has(ip); }

function ipv4ToInt(ip) {
  const parts = String(ip || '').split('.').map(Number);
  if (parts.length !== 4 || parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)) return null;
  return parts.reduce((value, part) => ((value << 8) | part) >>> 0, 0);
}

function matchesAllowedIp(ip, candidate) {
  const value = normalizeIP(candidate).split('/')[0];
  const normalized = normalizeIP(ip);
  if (!value || !normalized) return false;
  if (!String(candidate).includes('/')) return value === normalized;
  if (normalized.includes(':') || String(candidate).includes(':')) {
    try {
      return new Address6(normalized).isInSubnet(new Address6(String(candidate)));
    } catch { return false; }
  }
  const [network, bitsText] = String(candidate).split('/');
  const bits = Number(bitsText);
  const networkInt = ipv4ToInt(network);
  const ipInt = ipv4ToInt(normalized);
  if (networkInt === null || ipInt === null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (networkInt & mask) === (ipInt & mask);
}

// A live Firewall "allow" rule is authoritative.  IPS must never override it.
async function isWhitelistedForCompany(ip, companyId) {
  if (!ip || !companyId) return false;
  const [rules, localWhitelist] = await Promise.all([
    Firewall.find({
      companyId,
      enabled: true,
      action: 'allow',
      $or: [{ expiresAt: null }, { expiresAt: { $exists: false } }, { expiresAt: { $gt: new Date() } }],
    }).select('conditions.ipAddress').lean(),
    IpsWhitelist.find({ companyId, type: { $in: ['ip', 'cidr'] } }).select('value').lean(),
  ]);
  if (rules.some(rule => matchesAllowedIp(ip, rule.conditions?.ipAddress)) ||
      localWhitelist.some(entry => matchesAllowedIp(ip, entry.value))) return true;

  // Backward compatibility for whitelist entries created before the backend
  // mirror existed. A successful read also repairs the local mirror.
  const remote = await fetchRemoteWhitelist(companyId).catch(() => []);
  if (remote.length) await syncWhitelistMirror(companyId, remote).catch(() => {});
  return remote.some(entry => ['ip', 'cidr'].includes(String(entry.type || 'ip').toLowerCase()) && matchesAllowedIp(ip, entry.value));
}

function normalizeDomain(value = '') {
  return String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0].replace(/^\*\./, '').replace(/\.$/, '');
}

function matchesAllowedDomain(domain, candidate) {
  const host = normalizeDomain(domain);
  const allowed = normalizeDomain(candidate);
  return Boolean(host && allowed && (host === allowed || host.endsWith(`.${allowed}`)));
}

async function fetchRemoteWhitelist(companyId) {
  if (!IPS_WEBHOOK_URL || !companyId) return [];
  const base = IPS_WEBHOOK_URL.replace(/\/+$/, '').replace(/\/webhook$/i, '');
  const response = await axios.get(`${base}/whitelist`, {
    headers: {
      'X-Webhook-Secret': IPS_WEBHOOK_SECRET,
      'X-Company-ID': companyId.toString(),
    },
    timeout: 2000,
  });
  return Array.isArray(response.data?.whitelist) ? response.data.whitelist : [];
}

async function syncWhitelistMirror(companyId, entries = []) {
  if (!companyId || !Array.isArray(entries)) return;
  await Promise.all(entries.filter(entry => entry?.value).map(entry => IpsWhitelist.updateOne(
    { companyId, value: String(entry.value).trim() },
    { $set: {
      type: ['ip', 'cidr', 'domain'].includes(String(entry.type).toLowerCase()) ? String(entry.type).toLowerCase() : 'ip',
      reason: entry.reason || '', source: entry.source || 'ipsserver',
    } },
    { upsert: true },
  )));
}

async function isWhitelistedTarget({ companyId, ip, domain } = {}) {
  if (ip && await isWhitelistedForCompany(ip, companyId)) return true;
  if (!domain || !companyId) return false;
  let entries = await IpsWhitelist.find({ companyId, type: 'domain' }).select('value').lean();
  if (!entries.length) {
    const remote = await fetchRemoteWhitelist(companyId).catch(() => []);
    if (remote.length) await syncWhitelistMirror(companyId, remote).catch(() => {});
    entries = remote.filter(entry => String(entry.type).toLowerCase() === 'domain');
  }
  return entries.some(entry => matchesAllowedDomain(domain, entry.value));
}

function commandMatches(item = {}, command, params = {}) {
  if (item.command !== command) return false;
  for (const field of ['ip', 'domain', 'application', 'port', 'protocol', 'value', 'type']) {
    if (params[field] !== undefined && String(item[field] || '') !== String(params[field] || '')) return false;
  }
  return true;
}

const INVERSE_ENDPOINT_COMMANDS = Object.freeze({
  block_ip: 'unblock_ip',
  unblock_ip: 'block_ip',
  block_domain: 'unblock_domain',
  unblock_domain: 'block_domain',
  block_application: 'unblock_application',
  unblock_application: 'block_application',
  block_port: 'unblock_port',
  unblock_port: 'block_port',
  block_protocol: 'unblock_protocol',
  unblock_protocol: 'block_protocol',
});

function inverseEndpointCommand(command = '') {
  return INVERSE_ENDPOINT_COMMANDS[String(command || '').trim()] || '';
}

async function recordAgentCommandResult({ systemId, commandId, command, ip, ok, message = '' }, io = global._ipsEngineIO) {
  if (!systemId || !commandId || !command) return null;
  const now = new Date();
  const text = String(message || '').slice(0, 1000);
  const update = {
    $pull: { pendingCommands: { $or: [{ id: String(commandId) }, { commandId: String(commandId) }] } },
    $push: { completedIpsCommandIds: { $each: [String(commandId)], $slice: -200 } },
    $set: {
      lastIpsCommand: {
        id: String(commandId), command, ip: normalizeIP(ip),
        status: ok === true ? 'success' : 'failed', ok: ok === true,
        message: text, completedAt: now,
      },
    },
  };

  if (command === 'block_ip' && ok === true) update.$addToSet = { blockedIps: normalizeIP(ip) };
  if (command === 'unblock_ip' && ok === true) {
    update.$pull.blockedIps = normalizeIP(ip);
  }
  if (command === 'isolate') {
    Object.assign(update.$set, ok === true ? {
      isIsolated: true,
      isolatedAt: now,
      isolationStatus: 'isolated',
      isolationError: null,
      isolationLastThreatAt: now,
      isolationAutoRecoverAt: new Date(now.getTime() + IPS_AUTO_RECOVER_DELAY_MS),
    } : {
      isIsolated: false,
      isolationStatus: 'failed',
      isolationError: text || 'Agent isolation failed',
      isolationAutoRecoverAt: null,
    });
  } else if (command === 'reconnect') {
    Object.assign(update.$set, ok === true ? {
      isIsolated: false,
      isolatedAt: null,
      isolationReason: null,
      isolationStatus: 'none',
      isolationCommandId: null,
      isolationError: null,
      isolationSourceIp: null,
      isolationAttackType: null,
      isolationLastThreatAt: null,
      isolationAutoRecoverAt: null,
      isolationRecoveryAttempts: 0,
    } : {
      isolationStatus: 'failed',
      isolationError: text || 'Agent reconnect failed',
    });
    if (ok !== true) update.$inc = { isolationRecoveryAttempts: 1 };
  }

  const system = await System.findOneAndUpdate(
    { _id: systemId, completedIpsCommandIds: { $ne: String(commandId) } },
    update,
    { new: true },
  ).select('_id companyId name hostname ip isIsolated isolatedAt isolationReason isolationStatus isolationError lastIpsCommand');
  if (!system) return null;

  const event = command === 'isolate'
    ? (ok ? 'system:isolated' : 'system:isolation_failed')
    : command === 'reconnect'
      ? (ok ? 'system:reconnected' : 'system:reconnect_failed')
      : 'ips:agentCommandResult';
  const payload = {
    systemId: String(system._id),
    systemName: system.name || system.hostname,
    commandId: String(commandId), command, ok: ok === true, message: text,
    isIsolated: system.isIsolated === true,
    isolationStatus: system.isolationStatus,
    isolatedAt: system.isolatedAt,
    reason: system.isolationReason,
  };
  io?.to(`company:${system.companyId}`).emit(event, payload);

  try {
    const ipsEngine = require('./ipsEngine.service');
    await ipsEngine.handleAgentCommandResult?.({ ...payload, companyId: String(system.companyId) });
  } catch (error) {
    console.warn(`[IPS] Agent command lifecycle update failed: ${error.message}`);
  }
  return system;
}

function emitAgentCommand(system, outbound) {
  const io = global._ipsEngineIO;
  if (!io) return Promise.resolve({ confirmed: false, status: 'pending' });
  return new Promise(resolve => {
    io.to(`system_${system._id}`).timeout(4000).emit('agent:command', outbound, async (error, responses = []) => {
      const acknowledgement = !error && responses.find(response => response && response.ignored !== true);
      if (!acknowledgement) return resolve({ confirmed: false, status: 'pending' });
      const ok = acknowledgement.ok === true;
      const result = acknowledgement.result?.result || acknowledgement.result || acknowledgement.message || '';
      await recordAgentCommandResult({
        systemId: system._id,
        commandId: outbound.id,
        command: outbound.command,
        ip: outbound.ip,
        ok,
        message: typeof result === 'string' ? result : JSON.stringify(result),
      }, io).catch(err => console.warn(`[IPS] Socket acknowledgement persistence failed: ${err.message}`));
      resolve({ confirmed: ok, failed: !ok, status: ok ? 'confirmed' : 'failed', message: String(result || '') });
    });
  });
}

async function queueEndpointCommand({ companyId, systemId, command, reason, ...params }) {
  if (!systemId) return { queued: 0, confirmed: false, status: 'no-target' };
  const system = await System.findOne({ _id: systemId, companyId, isActive: true });
  if (!system) return { queued: 0, confirmed: false, status: 'no-target' };

  // The durable queue is ordered, but an endpoint may be offline for days. If
  // an operator reverses a block before delivery, never let the obsolete block
  // survive by itself and fire when that endpoint reconnects. Keep the newest
  // intent and still queue it: the older command may have been delivered while
  // its ACK was lost, so the inverse action must be executed idempotently.
  const inverse = inverseEndpointCommand(command);
  const supersededIds = inverse
    ? (system.pendingCommands || [])
      .filter(item => commandMatches(item, inverse, params))
      .map(item => String(item.id || item.commandId || ''))
      .filter(Boolean)
    : [];
  if (supersededIds.length) {
    await System.updateOne(
      { _id: system._id },
      { $pull: { pendingCommands: { $or: [
        { id: { $in: supersededIds } },
        { commandId: { $in: supersededIds } },
      ] } } },
    );
    system.pendingCommands = (system.pendingCommands || []).filter(item => (
      !supersededIds.includes(String(item.id || item.commandId || ''))
    ));
  }

  if (command === 'block_ip' && system.blockedIps?.includes(normalizeIP(params.ip))) {
    return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
  }
  if (command === 'isolate' && system.isIsolated === true) {
    return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
  }
  if (command === 'reconnect' && system.isIsolated !== true && !['pending', 'isolated', 'reconnecting'].includes(system.isolationStatus)) {
    return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
  }
  const existing = (system.pendingCommands || []).find(item => commandMatches(item, command, params));
  if (existing) {
    return { queued: 0, pending: 1, confirmed: false, status: 'pending', commandId: existing.id };
  }

  const commandId = `${Date.now()}-ips-${command.replace(/_/g, '-')}-${Math.random().toString(36).slice(2, 8)}`;
  const outbound = {
    id: commandId,
    command,
    systemId: String(system._id),
    reason: reason || 'IPS endpoint response',
    ...params,
    createdAt: new Date(),
  };
  const state = command === 'isolate' ? {
    isIsolated: false,
    isolationStatus: 'pending',
    isolationCommandId: commandId,
    isolationReason: outbound.reason,
    isolationError: null,
    isolationSourceIp: normalizeIP(params.srcIp || params.ip) || null,
    isolationAttackType: params.attackType || null,
    isolationLastThreatAt: null,
    isolationAutoRecoverAt: null,
    isolationRecoveryAttempts: 0,
  } : command === 'reconnect' ? {
    isolationStatus: 'reconnecting',
    isolationCommandId: commandId,
    isolationError: null,
  } : {};
  const dedupeMatch = { command };
  for (const field of ['ip', 'domain', 'application', 'port', 'protocol', 'value', 'type']) {
    if (params[field] !== undefined) dedupeMatch[field] = field === 'ip' ? normalizeIP(params[field]) : params[field];
  }
  const queued = await System.updateOne({
    _id: system._id,
    pendingCommands: { $not: { $elemMatch: dedupeMatch } },
    ...(command === 'block_ip' ? { blockedIps: { $ne: normalizeIP(params.ip) } } : {}),
  }, {
    $set: {
      ...state,
      lastIpsCommand: {
        id: commandId, command, ip: normalizeIP(params.ip), status: 'pending',
        reason: outbound.reason, queuedAt: outbound.createdAt,
      },
    },
    $push: { pendingCommands: { $each: [outbound], $slice: -20 } },
  });
  if (!queued.modifiedCount) {
    const current = await System.findById(system._id).select('blockedIps pendingCommands isIsolated isolationStatus').lean();
    if (command === 'block_ip' && current?.blockedIps?.includes(normalizeIP(params.ip))) {
      return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
    }
    if (command === 'isolate' && current?.isIsolated === true) {
      return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
    }
    if (command === 'reconnect' && current?.isIsolated !== true && !['pending', 'isolated', 'reconnecting'].includes(current?.isolationStatus)) {
      return { queued: 0, confirmed: true, alreadyActive: true, status: 'confirmed' };
    }
    const pending = (current?.pendingCommands || []).find(item => commandMatches(item, command, params));
    return { queued: 0, pending: pending ? 1 : 0, confirmed: false, status: 'pending', commandId: pending?.id };
  }

  const delivery = await emitAgentCommand(system, outbound);
  return { queued: 1, commandId, ...delivery };
}

async function queueAgentBlock({ companyId, ip, port, reason, systemId = null }) {
  const query = {
    companyId, isActive: true, ipsEnabled: { $ne: false },
    agentVersion: { $nin: [null, ''] },
  };
  if (systemId) query._id = systemId;
  const systems = await System.find(query).select('_id').lean();
  if (!systems.length) return { queued: 0, pending: 0, confirmed: false, status: 'no-target' };
  const results = await Promise.all(systems.map(system => queueEndpointCommand({
    companyId, systemId: system._id, command: 'block_ip', ip, port: port || undefined,
    reason: reason || 'IPS blocklist synchronization',
  })));
  return {
    queued: results.reduce((sum, result) => sum + (result.queued || 0), 0),
    pending: results.reduce((sum, result) => sum + (result.pending || 0), 0),
    confirmed: results.some(result => result.confirmed),
    alreadyActive: results.every(result => result.alreadyActive === true),
    status: results.every(result => result.confirmed) ? 'confirmed' : results.some(result => result.failed) ? 'failed' : 'pending',
    commandIds: results.map(result => result.commandId).filter(Boolean),
  };
}

async function queueAgentUnblock({ companyId, ip, reason, systemId = null }) {
  const query = {
    companyId, isActive: true, ipsEnabled: { $ne: false },
    agentVersion: { $nin: [null, ''] },
  };
  if (systemId) query._id = systemId;
  const systems = await System.find(query).select('_id').lean();
  const results = await Promise.all(systems.map(system => queueEndpointCommand({
    companyId, systemId: system._id, command: 'unblock_ip', ip,
    reason: reason || 'IPS blocklist synchronization',
  })));
  return {
    queued: results.reduce((sum, result) => sum + (result.queued || 0), 0),
    pending: results.reduce((sum, result) => sum + (result.pending || 0), 0),
    confirmed: results.some(result => result.confirmed),
    status: results.length && results.every(result => result.confirmed) ? 'confirmed' : results.some(result => result.failed) ? 'failed' : 'pending',
    results,
  };
}



// ── Generic webhook ─────────────────────────────────────────────────────
// SECURITY: companyId is MANDATORY for all webhook calls.
// A missing companyId would create a global block not scoped to any tenant.
async function blockViaWebhook(ip, reason, companyId, identity = {}) {
  if (!IPS_WEBHOOK_URL) return { ok: false, method: 'webhook', error: 'IPS_WEBHOOK_URL not set' };
  if (!companyId) {
    console.error('[IPS/Webhook] BLOCKED — companyId is required for webhook block calls');
    return { ok: false, method: 'webhook', error: 'companyId missing — cross-company block prevented' };
  }
  try {
    let system = null;
    if (identity.systemId) {
      system = await System.findOne({ _id: identity.systemId, companyId }).select('_id name hostname ip macAddress agentId departmentId').lean();
    }
    if (!system) {
      system = await System.findOne({ companyId, ip }).select('_id name hostname ip macAddress agentId departmentId').lean();
    }
    const matchedMac = identity.mac || (system?.ip === ip ? system.macAddress : null);
    const webhookUrl = IPS_WEBHOOK_URL.replace(/\/+$/, '');
    const url = /\/webhook$/i.test(webhookUrl) ? webhookUrl : `${webhookUrl}/webhook`;
    const headers = {
      'X-Webhook-Secret': IPS_WEBHOOK_SECRET,
      // Always scope to the company — prevents global/cross-tenant blocks
      'X-Company-ID': companyId.toString(),
    };
    const res = await axios.post(url, {
      action: 'block',
      ip,
      reason,
      companyId,
      source: 'backend-threat-intel',
      orchestrationOwner: 'soc-backend',
      threatLevel: 'high',
      attackType: 'Threat Intelligence Auto-Block',
      systemId: system?._id?.toString() || identity.systemId || undefined,
      departmentId: system?.departmentId?.toString() || undefined,
      agentId: system?.agentId || undefined,
      agentName: system?.name || system?.hostname || undefined,
      agentHostname: system?.hostname || undefined,
      agentIp: system?.ip || undefined,
      mac: matchedMac || undefined,
      ttlHours: IPS_BLOCK_TTL_H,
      ts: new Date(),
    }, { headers, timeout: 5000 });
    const skipped = res.data?.skipped === true;
    const enforced = res.data?.enforced === true;
    return {
      ok: !skipped && enforced,
      enforced,
      delegated: res.data?.delegated === true,
      skipped,
      whitelisted: skipped && /whitelist/i.test(String(res.data?.reason || '')),
      reason: res.data?.reason,
      method: res.data?.method || 'webhook',
      status: res.status,
    };
  } catch (err) {
    return { ok: false, method: 'webhook', error: err.message };
  }
}
async function unblockViaWebhook(ip, companyId) {
  if (!IPS_WEBHOOK_URL) return;
  if (!companyId) {
    console.error('[IPS/Webhook] BLOCKED — companyId is required for webhook unblock calls');
    return;
  }
  const headers = {
    'X-Webhook-Secret': IPS_WEBHOOK_SECRET,
    'X-Company-ID': companyId.toString(),
  };
  const webhookUrl = IPS_WEBHOOK_URL.replace(/\/+$/, '');
  const url = /\/webhook$/i.test(webhookUrl) ? webhookUrl : `${webhookUrl}/webhook`;
  await axios.post(url, { action: 'unblock', ip, companyId, source: 'backend-threat-intel', ts: new Date() }, { headers, timeout: 5000 }).catch(() => { });
}

// ── Auto-block handler (called from alert pipeline) ───────────────────────
async function autoBlockFromAlert(alert, companyId) {
  if (!IPS_AUTO_BLOCK) return null;
  // SECURITY: Reject if companyId is not provided — prevents global blocks
  if (!companyId) {
    console.error('[IPS] autoBlockFromAlert rejected — companyId is required (multi-tenant policy)');
    return null;
  }
  const ip = normalizeIP(alert.srcip);
  if (!ip || isPrivateIP(ip)) return null;
  if (alert.severity !== 'critical' && alert.severity !== 'high') return null;

  // Only auto-block confirmed threats
  const shouldBlock =
    alert.eventCategory === 'network' ||
    alert.userAction === 'brute_force' ||
    alert.vtVerdict === 'malicious' ||
    alert.eventCategory === 'malware' ||
    alert.isolationStatus === 'blocked';

  if (!shouldBlock) return null;
  return blockIP({
    ip, companyId, reason: `Auto-block: ${alert.description?.slice(0, 100)}`,
    alertId: alert._id, systemId: alert.systemId || null,
  });
}

// ── Query blocklist ────────────────────────────────────────────────────────────
async function getBlocklist(companyId, { includeExpired = false } = {}) {
  if (!includeExpired) await sweepExpiredBlocks().catch(() => {});
  const q = { companyId };
  if (!includeExpired) {
    q.reverted = false;
    q.$or = [
      { expiresAt: { $exists: false } },
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } },
    ];
  }
  return BlockedIP.find(q).sort({ blockedAt: -1 }).lean();
}

function syncBlockCache(action, payload) {
  if (action === 'add') {
    _blocked.add(payload);
  } else if (action === 'delete') {
    _blocked.delete(payload);
  } else if (action === 'delete_multiple' && Array.isArray(payload)) {
    payload.forEach(ip => _blocked.delete(ip));
  }
}

module.exports = {
  blockIP, unblockIP, isBlocked, autoBlockFromAlert,
  getBlocklist, loadBlockCache, sweepExpiredBlocks, startExpirySweeper, BlockedIP,
  normalizeIP, isPrivateIP, isLoopbackIP, revokeLoopbackBlocks,
  isWhitelistedForCompany,
  isWhitelistedTarget,
  matchesAllowedIp,
  matchesAllowedDomain,
  fetchRemoteWhitelist,
  syncWhitelistMirror,
  syncBlockCache,
  persistIpsActionAlert,
  queueEndpointCommand,
  queueAgentBlock,
  recordAgentCommandResult,
  _test: { commandMatches, inverseEndpointCommand },
};
