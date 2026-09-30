/**
 * MongoDB Service — SOC4 IPS Server v3.0
 * ========================================
 * Complete database integration for persistence and real-time analytics.
 *
 * Collections:
 *   firewall_blocks  — Block/unblock history
 *   ips_logs         — Server activity logs
 *   threat_intel     — Threat intelligence records
 *   attack_events    — Detected attack instances (granular)
 *   whitelist        — Whitelisted IPs/domains
 *
 * New in v3.0:
 *   - TTL indexes for auto-cleanup
 *   - Aggregation pipelines for threat stats
 *   - Whitelist management
 *   - Attack event granular tracking
 *   - getDB() pattern (works with existing mongodb.js connection)
 */

const { getDB, getMainDB } = require('../db/mongodb');
const logger = require('../utils/logger');
const crypto = require('crypto');
const net = require('net');

// ── Collection Names ──────────────────────────────────────────────────────────
const COLLECTIONS = {
  BLOCKS:   'firewall_blocks',
  LOGS:     'ips_logs',
  THREATS:  'threat_intel',
  ATTACKS:  'attack_events',
  WHITELIST:'whitelist',
  // NOTE: COMPANIES is read from main DB only, not soc4_ips
};

// ── Safe DB accessor ──────────────────────────────────────────────────────────
function col(name) {
  const db = getDB();
  return db ? db.collection(name) : null;
}

// ── Index Bootstrapping ───────────────────────────────────────────────────────
async function ensureAllIndexes() {
  const db = getDB();
  if (!db) return;
  try {
    /* firewall_blocks */
    const blocks = db.collection(COLLECTIONS.BLOCKS);
    await blocks.createIndex({ blockKey: 1, company: 1 }, { unique: true, sparse: true });
    await blocks.createIndex({ company: 1, ip: 1 });
    await blocks.createIndex({ company: 1, domain: 1 });
    await blocks.createIndex({ company: 1, application: 1 });
    await blocks.createIndex({ company: 1, status: 1 });
    await blocks.createIndex({ company: 1, ts: -1 });
    await blocks.createIndex({ company: 1, type: 1 });

    /* ips_logs */
    const logs = db.collection(COLLECTIONS.LOGS);
    await logs.createIndex({ company: 1, ts: -1 });
    await logs.createIndex({ company: 1, level: 1 });

    /* threat_intel */
    const threats = db.collection(COLLECTIONS.THREATS);
    await threats.createIndex({ company: 1, ip: 1 });
    await threats.createIndex({ company: 1, domain: 1 });
    await threats.createIndex({ company: 1, attackType: 1 });
    await threats.createIndex({ company: 1, threatLevel: 1 });
    await threats.createIndex({ company: 1, ts: -1 });
    await threats.createIndex({ company: 1, score: -1 });

    /* attack_events */
    const attacks = db.collection(COLLECTIONS.ATTACKS);
    await attacks.createIndex({ company: 1, ip: 1 });
    await attacks.createIndex({ company: 1, attackType: 1 });
    await attacks.createIndex({ company: 1, threatLevel: 1 });
    await attacks.createIndex({ company: 1, ts: -1 });

    /* whitelist */
    const wl = db.collection(COLLECTIONS.WHITELIST);
    await wl.createIndex({ company: 1, value: 1 }, { unique: true, sparse: true });
    await wl.createIndex({ company: 1, type: 1 });

    logger.info('[MongoService] All indexes verified/created');
    await syncActiveBlocksToSocAlerts();
  } catch (err) {
    logger.warn(`[MongoService] Index creation warning: ${err.message}`);
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// BLOCK RECORDS
// ──────────────────────────────────────────────────────────────────────────────

async function storeBlock(blockData, company = null) {
  const c = col(COLLECTIONS.BLOCKS);
  if (!c) return null;
  try {
    const doc = { ...blockData, ts: blockData.ts || new Date(), status: blockData.status || 'blocked' };
    if (company) doc.company = company;
    return await c.updateOne(
      { blockKey: blockData.blockKey, ...(company && { company }) },
      { $set: doc },
      { upsert: true }
    );
  } catch (err) {
    logger.warn(`[MongoService] storeBlock: ${err.message}`);
    return null;
  }
}

async function removeBlock(blockKey, company = null) {
  const c = col(COLLECTIONS.BLOCKS);
  if (!c) return null;
  try {
    const filter = { blockKey, ...(company && { company }) };
    return await c.deleteOne(filter);
  } catch { return null; }
}

async function getAllBlocks(filter = {}, limit = 200, company = null) {
  const c = col(COLLECTIONS.BLOCKS);
  if (!c) return [];
  try {
    const query = { status: 'blocked', ...filter, ...(company && { company }) };
    return await c.find(query).sort({ ts: -1 }).limit(limit).toArray();
  } catch { return []; }
}

async function getBlocksByIP(ip, company = null) { return getAllBlocks({ ip }, 200, company); }
async function getBlocksByDomain(domain, company = null) { return getAllBlocks({ domain }, 200, company); }

async function markUnblocked(blockKey, company = null) {
  const c = col(COLLECTIONS.BLOCKS);
  if (!c) return null;
  try {
    const filter = { blockKey, ...(company && { company }) };
    return await c.updateOne(filter, { $set: { status: 'unblocked', unblockedAt: new Date() } });
  } catch { return null; }
}

// ──────────────────────────────────────────────────────────────────────────────
// LOG RECORDS
// ──────────────────────────────────────────────────────────────────────────────

async function storeLog(logData, company = null) {
  const c = col(COLLECTIONS.LOGS);
  if (!c) return null;
  try {
    const doc = { ...logData, ts: logData.ts || new Date() };
    if (company) doc.company = company;
    return await c.insertOne(doc);
  } catch { return null; }
}

async function getRecentLogs(limit = 200, level = null, company = null) {
  const c = col(COLLECTIONS.LOGS);
  if (!c) return [];
  try {
    const filter = { ...(level && { level }), ...(company && { company }) };
    return await c.find(filter).sort({ ts: -1 }).limit(limit).toArray();
  } catch { return []; }
}

// ──────────────────────────────────────────────────────────────────────────────
// THREAT INTELLIGENCE
// ──────────────────────────────────────────────────────────────────────────────

async function storeThreat(threatData, company = null) {
  const c = col(COLLECTIONS.THREATS);
  if (!c) return null;
  try {
    const doc = { ...threatData, ts: threatData.ts || new Date() };
    if (company) doc.company = company;
    if (threatData.ip && threatData.attackType) {
      const filter = { ip: threatData.ip, attackType: threatData.attackType, ...(company && { company }) };
      return await c.updateOne(
        filter,
        { $set: doc, $inc: { occurrences: 1 } },
        { upsert: true }
      );
    }
    return await c.insertOne(doc);
  } catch (err) {
    logger.warn(`[MongoService] storeThreat: ${err.message}`);
    return null;
  }
}

async function getThreatStats(timeWindowMs = 24 * 60 * 60 * 1000, company = null) {
  const c = col(COLLECTIONS.THREATS);
  if (!c) return {};
  try {
    const since = new Date(Date.now() - timeWindowMs);
    const match = { ts: { $gte: since }, ...(company && { company }) };
    const [result] = await c.aggregate([
      { $match: match },
      {
        $facet: {
          byLevel: [
            { $group: { _id: '$threatLevel', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
          ],
          byType: [
            { $group: { _id: '$attackType', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ],
          topIPs: [
            { $group: { _id: '$ip', count: { $sum: 1 }, maxScore: { $max: '$score' } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ],
          total: [{ $count: 'count' }],
        },
      },
    ]).toArray();
    return {
      timeWindowHours: Math.round(timeWindowMs / 3600000),
      total:    result.total[0]?.count || 0,
      byLevel:  Object.fromEntries((result.byLevel || []).map(r => [r._id, r.count])),
      byType:   (result.byType || []).map(r => ({ type: r._id, count: r.count })),
      topIPs:   (result.topIPs || []).map(r => ({ ip: r._id, count: r.count, maxScore: r.maxScore })),
    };
  } catch (err) {
    logger.warn(`[MongoService] getThreatStats: ${err.message}`);
    return {};
  }
}

async function getThreatsByIP(ip, company = null) {
  const c = col(COLLECTIONS.THREATS);
  if (!c) return [];
  try {
    const filter = { ip, ...(company && { company }) };
    return await c.find(filter).sort({ ts: -1 }).limit(50).toArray();
  } catch { return []; }
}

// ──────────────────────────────────────────────────────────────────────────────
// ATTACK EVENTS
// ──────────────────────────────────────────────────────────────────────────────

async function storeAttackEvent(event, company = null) {
  const c = col(COLLECTIONS.ATTACKS);
  if (!c) return null;
  try {
    const doc = { ...event, ts: event.ts || new Date() };
    if (company) doc.company = company;
    return await c.insertOne(doc);
  } catch (err) {
    logger.warn(`[MongoService] storeAttackEvent: ${err.message}`);
    return null;
  }
}

async function getRecentAttacks(limit = 100, filter = {}, company = null) {
  const c = col(COLLECTIONS.ATTACKS);
  if (!c) return [];
  try {
    const query = { ...filter, ...(company && { company }) };
    return await c.find(query).sort({ ts: -1 }).limit(limit).toArray();
  } catch { return []; }
}

async function getAttackStats(since = new Date(Date.now() - 24 * 3600 * 1000), company = null) {
  const c = col(COLLECTIONS.ATTACKS);
  if (!c) return { total: 0, byType: [], byHour: [], topSrcIPs: [] };
  try {
    const match = { ts: { $gte: since }, ...(company && { company }) };
    const [result] = await c.aggregate([
      { $match: match },
      {
        $facet: {
          total:      [{ $count: 'count' }],
          blocked:    [{ $match: { autoBlocked: true } }, { $count: 'count' }],
          byType:     [
            { $group: { _id: '$attackType', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 15 },
          ],
          byHour:     [
            { $group: { _id: { $hour: '$ts' }, count: { $sum: 1 } } },
            { $sort: { _id: 1 } },
          ],
          topSrcIPs:  [
            { $match: { srcIp: { $exists: true, $ne: null } } },
            { $group: { _id: '$srcIp', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 10 },
          ],
        },
      },
    ]).toArray();
    return {
      total:     result.total[0]?.count || 0,
      blocked:   result.blocked[0]?.count || 0,
      byType:    result.byType.map(r => ({ type: r._id || 'Unknown', count: r.count })),
      byHour:    result.byHour.map(r => ({ hour: r._id, count: r.count })),
      topSrcIPs: result.topSrcIPs.map(r => ({ ip: r._id, count: r.count })),
    };
  } catch (err) {
    logger.warn(`[MongoService] getAttackStats: ${err.message}`);
    return { total: 0, byType: [], byHour: [], topSrcIPs: [] };
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// WHITELIST
// ──────────────────────────────────────────────────────────────────────────────

async function addToWhitelist(value, type = 'ip', reason = '', company = null) {
  const c = col(COLLECTIONS.WHITELIST);
  if (!c) return null;
  try {
    const doc = { value, type, reason, updatedAt: new Date(), ...(company && { company }) };
    return await c.updateOne(
      { value, ...(company && { company }) },
      {
        $set: doc,
        $setOnInsert: { addedAt: new Date() },
      },
      { upsert: true }
    );
  } catch (err) {
    logger.warn(`[MongoService] addToWhitelist: ${err.message}`);
    return null;
  }
}

async function removeFromWhitelist(value, company = null) {
  const c = col(COLLECTIONS.WHITELIST);
  if (!c) return null;
  try {
    const filter = { value, ...(company && { company }) };
    return await c.deleteOne(filter);
  } catch { return null; }
}

function normalizeWhitelistDomain(value = '') {
  return String(value || '').trim().toLowerCase().replace(/^https?:\/\//, '')
    .split('/')[0].split(':')[0].replace(/^\*\./, '').replace(/\.$/, '');
}

function ipToBigInt(value) {
  const ip = String(value || '').trim().split('%')[0];
  const version = net.isIP(ip);
  if (version === 4) {
    return { version, bits: 32, value: ip.split('.').reduce((result, octet) => (result << 8n) | BigInt(octet), 0n) };
  }
  if (version !== 6) return null;
  let source = ip.toLowerCase();
  if (source.includes('.')) {
    const lastColon = source.lastIndexOf(':');
    const ipv4 = source.slice(lastColon + 1).split('.').map(Number);
    if (ipv4.length !== 4 || ipv4.some(part => part < 0 || part > 255)) return null;
    source = `${source.slice(0, lastColon)}:${((ipv4[0] << 8) | ipv4[1]).toString(16)}:${((ipv4[2] << 8) | ipv4[3]).toString(16)}`;
  }
  const halves = source.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < 0 || (halves.length === 1 && missing !== 0)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8) return null;
  try {
    return { version, bits: 128, value: groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group || '0'}`), 0n) };
  } catch { return null; }
}

function whitelistEntryMatches(value, entry = {}) {
  const candidate = String(entry.value || '').trim();
  const type = String(entry.type || (candidate.includes('/') ? 'cidr' : net.isIP(candidate) ? 'ip' : 'domain')).toLowerCase();
  if (type === 'domain') {
    const host = normalizeWhitelistDomain(value);
    const allowed = normalizeWhitelistDomain(candidate);
    return Boolean(host && allowed && (host === allowed || host.endsWith(`.${allowed}`)));
  }
  if (type === 'ip') return String(value || '').trim().toLowerCase() === candidate.toLowerCase();
  if (type !== 'cidr') return false;
  const [network, prefixText] = candidate.split('/', 2);
  const address = ipToBigInt(value);
  const base = ipToBigInt(network);
  const prefix = Number(prefixText);
  if (!address || !base || address.version !== base.version || !Number.isInteger(prefix) || prefix < 0 || prefix > base.bits) return false;
  const shift = BigInt(base.bits - prefix);
  return (address.value >> shift) === (base.value >> shift);
}

async function isWhitelisted(value, company = null) {
  const c = col(COLLECTIONS.WHITELIST);
  if (!c) return false;
  try {
    const entries = await c.find({ ...(company && { company }) }).toArray();
    return entries.some(entry => whitelistEntryMatches(value, entry));
  } catch { return false; }
}

async function getWhitelist(filter = {}, company = null) {
  const c = col(COLLECTIONS.WHITELIST);
  if (!c) return [];
  try {
    const query = { ...filter, ...(company && { company }) };
    return await c.find(query).sort({ addedAt: -1 }).toArray();
  } catch { return []; }
}

// ──────────────────────────────────────────────────────────────────────────────
// COMPANY MANAGEMENT — READ-ONLY from main SOC4 database
// Companies are registered ONLY in the Company Frontend (auth system).
// IPS server reads company info from the central Company collection in main DB.
// ──────────────────────────────────────────────────────────────────────────────

const { ObjectId } = require('mongodb');

function _colorForStatus(status) {
  const map = { active: '#22c55e', trial: '#3B82F6', pending_payment: '#f59e0b', suspended: '#ef4444' };
  return map[status] || '#6b7280';
}

async function getAllCompanies() {
  const mainDb = getMainDB();
  if (!mainDb) {
    logger.warn('[MongoService] Main DB not available for getAllCompanies');
    return [];
  }
  try {
    const companies = await mainDb.collection('companies')
      .find({ status: { $ne: 'suspended' } })
      .sort({ createdAt: -1 })
      .toArray();
    return companies.map(c => ({
      companyId: c._id.toString(),
      name: c.name,
      email: c.email || '',
      industry: c.plan?.type || 'basic',
      active: ['active', 'trial'].includes(c.status),
      status: c.status,
      color: _colorForStatus(c.status),
      icon: '\ud83c\udfe2',
      registeredAt: c.createdAt,
    }));
  } catch (err) {
    logger.warn(`[MongoService] getAllCompanies (mainDB): ${err.message}`);
    return [];
  }
}

async function getCompanyByID(companyId) {
  const mainDb = getMainDB();
  if (!mainDb) return null;
  try {
    let filter;
    try { filter = { _id: new ObjectId(companyId) }; }
    catch { filter = { email: companyId }; }
    const c = await mainDb.collection('companies').findOne(filter);
    if (!c) return null;
    return {
      companyId: c._id.toString(),
      name: c.name,
      email: c.email || '',
      active: ['active', 'trial'].includes(c.status),
      status: c.status,
      color: _colorForStatus(c.status),
      icon: '\ud83c\udfe2',
      registeredAt: c.createdAt,
    };
  } catch (err) {
    logger.warn(`[MongoService] getCompanyByID (mainDB): ${err.message}`);
    return null;
  }
}

function _socCompanyId(company) {
  if (!company) return null;
  try {
    return company instanceof ObjectId ? company : new ObjectId(String(company));
  } catch {
    return null;
  }
}

function _socIpsAlert({ action = 'block', company, block = {}, threat = {} }) {
  const companyId = _socCompanyId(company);
  if (!companyId) return null;
  const systemId = _socCompanyId(block.systemId);
  const departmentId = _socCompanyId(block.departmentId);

  const isBlock = action === 'block';
  const target = block.ip || block.domain || block.application ||
    (block.port ? `port ${block.port}` : block.protocol || 'target');
  const severity = ['low', 'medium', 'high', 'critical'].includes(String(threat.level || '').toLowerCase())
    ? String(threat.level).toLowerCase()
    : (isBlock ? 'high' : 'low');
  const now = new Date();
  const candidateTimestamp = block.ts ? new Date(block.ts) : now;
  const eventTimestamp = Number.isNaN(candidateTimestamp.getTime()) ? now : candidateTimestamp;
  const fingerprintBasis = [
    String(companyId),
    action,
    block.blockKey || '',
    target,
    block.systemId || '',
    eventTimestamp.toISOString(),
  ].join('|');
  const eventFingerprint = crypto.createHash('sha256').update(fingerprintBasis).digest('hex');

  return {
    companyId,
    ...(systemId && { systemId }),
    ...(departmentId && { departmentId }),
    eventId: `ips-${eventFingerprint}`,
    eventFingerprint,
    source: 'IPS',
    type: isBlock ? 'IPS_BLOCK' : 'IPS_UNBLOCK',
    category: 'intrusion_prevention',
    subCategory: block.attackType || threat.type || (isBlock ? 'Manual Block' : 'Manual Unblock'),
    eventType: isBlock ? 'ips_block' : 'ips_unblock',
    eventCategory: 'network',
    severity,
    status: isBlock ? 'open' : 'resolved',
    ruleId: isBlock ? 'IPS_BLOCK_APPLIED' : 'IPS_BLOCK_REMOVED',
    description: `IPS ${isBlock ? 'blocked' : 'unblocked'} ${target}`,
    srcip: block.ip || null,
    destip: block.agentIp || null,
    destPort: block.port ? Number(block.port) : null,
    port: block.port ? Number(block.port) : null,
    protocol: block.protocol || 'all',
    direction: block.direction || 'both',
    blocked: isBlock,
    actionTaken: isBlock ? 'Blocked' : 'Allowed',
    containmentStatus: isBlock ? 'blocked' : 'allowed',
    detectionSource: 'IPS Server',
    riskScore: Number(threat.score || 0),
    agentName: block.agentName || block.agentHostname || 'IPS Server',
    agentId: block.agentId || null,
    endpointId: systemId ? String(systemId) : (block.agentId || null),
    hostname: block.agentHostname || null,
    firstSeen: now,
    lastSeen: now,
    createdAt: eventTimestamp,
    updatedAt: now,
    rawEvent: {
      module: 'IPS',
      blockKey: block.blockKey || null,
      action,
      reason: block.reason || '',
      method: block.method || '',
      source: block.source || '',
      attackType: block.attackType || threat.type || '',
      systemId: systemId ? String(systemId) : null,
      departmentId: departmentId ? String(departmentId) : null,
      agentId: block.agentId || null,
      agentHostname: block.agentHostname || null,
      agentIp: block.agentIp || null,
      threat,
    },
  };
}

async function storeSocIdsIpsEvent(eventData, company = null) {
  const mainDb = getMainDB();
  if (!mainDb) return null;
  try {
    const doc = _socIpsAlert({ ...eventData, company });
    if (!doc) return null;
    return await mainDb.collection('alerts').updateOne(
      { companyId: doc.companyId, eventFingerprint: doc.eventFingerprint },
      { $setOnInsert: doc },
      { upsert: true },
    );
  } catch (err) {
    logger.warn(`[MongoService] storeSocIdsIpsEvent: ${err.message}`);
    return null;
  }
}

async function syncActiveBlocksToSocAlerts() {
  const mainDb = getMainDB();
  const blocks = col(COLLECTIONS.BLOCKS);
  if (!mainDb || !blocks) return { synced: 0 };

  let synced = 0;
  try {
    const active = await blocks.find({ status: 'blocked' }).toArray();
    for (const block of active) {
      const doc = _socIpsAlert({
        action: 'block',
        company: block.company,
        block,
        threat: { level: block.threatLevel || 'high', type: block.attackType || 'Active Block' },
      });
      if (!doc) continue;
      const result = await mainDb.collection('alerts').updateOne(
        {
          companyId: doc.companyId,
          source: 'IPS',
          type: 'IPS_BLOCK',
          'rawEvent.blockKey': block.blockKey,
        },
        { $setOnInsert: doc },
        { upsert: true },
      );
      synced += result.upsertedCount || 0;
    }
    if (synced) logger.info(`[MongoService] Synced ${synced} active IPS block event(s) to SOC alerts`);
  } catch (err) {
    logger.warn(`[MongoService] syncActiveBlocksToSocAlerts: ${err.message}`);
  }
  return { synced };
}

// Disabled — companies are registered via Company Frontend only
async function registerCompany(companyData) {
  logger.warn('[MongoService] registerCompany() is DISABLED. Use Company Frontend to register companies.');
  throw new Error('Company registration is managed by the Company Frontend. This endpoint is disabled.');
}
async function updateCompany() { return null; }
async function deleteCompany() { return null; }

// ──────────────────────────────────────────────────────────────────────────────
// CLEANUP
// ──────────────────────────────────────────────────────────────────────────────

async function cleanup(ageMs = 30 * 24 * 60 * 60 * 1000) {
  const cutoff = new Date(Date.now() - ageMs);
  const results = {};
  for (const name of [COLLECTIONS.LOGS, COLLECTIONS.ATTACKS]) {
    const c = col(name);
    if (!c) continue;
    try { const r = await c.deleteMany({ ts: { $lt: cutoff } }); results[name] = r.deletedCount; }
    catch {}
  }
  logger.info(`[MongoService] Cleanup: ${JSON.stringify(results)}`);
  return results;
}

// ── Legacy compatibility (original mongoService API) ─────────────────────────
async function connect() {
  logger.info('[MongoService] connect() called — using getDB() pattern from mongodb.js');
  return !!getDB();
}

async function disconnect() {
  logger.info('[MongoService] disconnect() — use disconnectDB() from mongodb.js');
}

// ── Exports ───────────────────────────────────────────────────────────────────
module.exports = {
  COLLECTIONS,
  ensureAllIndexes,
  // Block records
  storeBlock, removeBlock, getAllBlocks, getBlocksByIP, getBlocksByDomain, markUnblocked,
  // Logs
  storeLog, getRecentLogs, storeSocIdsIpsEvent, syncActiveBlocksToSocAlerts,
  // Threat intelligence
  storeThreat, getThreatStats, getThreatsByIP,
  // Attack events
  storeAttackEvent, getRecentAttacks, getAttackStats,
  // Whitelist
  addToWhitelist, removeFromWhitelist, isWhitelisted, getWhitelist,
  // Company management
  registerCompany, getAllCompanies, getCompanyByID, updateCompany, deleteCompany,
  // Maintenance
  cleanup,
  // Legacy
  connect, disconnect,
  // Pure document builder used by regression tests.
  _test: { _socIpsAlert, ipToBigInt, whitelistEntryMatches, normalizeWhitelistDomain },
};
