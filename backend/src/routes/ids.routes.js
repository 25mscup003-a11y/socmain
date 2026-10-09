/**
 * ids.routes.js
 * Webhook receiver for IDS/IPS tools:
 *  - Suricata (EVE JSON format)
 *  - Zeek (connection/dns/notice logs)
 *  - Generic IDS (key-value JSON)
 *
 * POST /api/ids/suricata  — Suricata EVE JSON
 * POST /api/ids/zeek      — Zeek notice log
 * POST /api/ids/generic   — Generic { srcip, dstip, rule, severity, description }
 * GET  /api/ids/stats     — IDS alert counts (auth required)
 */
const router = require('express').Router();
const crypto = require('crypto');
const net = require('net');
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const BlockedIP = require('../models/BlockedIP.model');
const IdsIpsPolicy = require('../models/IdsIpsPolicy.model');
const IdsPolicyViolation = require('../models/IdsPolicyViolation.model');
const IpsWhitelist = require('../models/IpsWhitelist.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const ipsEngine   = require('../services/ipsEngine.service');
const threatIntel = require('../services/threat-intel.service');
const vt          = require('../services/virustotal.service');
const { resolveAttackType } = require('../constants/idsIpsCapabilities');
const { POLICY_PRESETS, publicPreset, effectivePresetMode } = require('../constants/idsIpsPolicyPresets');
const { getCompanyIngestionStatus, sendIngestionBlocked } = require('../utils/agentEntitlement');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');
const { normalizeSecurityEvent } = require('../utils/securityEventNormalizer');
const { enqueueSecurityEventAnalysis } = require('../services/azureAi.service');
const { loadIdsAlertRollup } = require('../services/idsSummary.service');
const ipEnrichmentService = require('../services/ipEnrichmentService');
const {
  buildGpsDestinationMap,
  destinationForAlert,
  buildAgentFlowSummary,
  isPublicRoutableIp,
  isMapEligibleAttack,
} = require('../services/idsAttackMap.service');

const IDS_POLICY_CACHE_MS = Number(process.env.IDS_POLICY_CACHE_MS || 15000);
const idsPolicyCache = new Map();
const idsPolicyInflight = new Map();
const IDS_STATS_CACHE_MS = Number(process.env.IDS_STATS_CACHE_MS || 15000);
const idsStatsCache = new Map();
const IDS_ALERT_COOLDOWN_MS = Math.max(
  60 * 1000,
  Math.min(24 * 60 * 60 * 1000, Number(process.env.IDS_ALERT_COOLDOWN_MS || 15 * 60 * 1000)),
);

function idsAlertIdentity(doc = {}) {
  const identity = {
    companyId: doc.companyId,
    source: String(doc.source || 'ids').toLowerCase(),
    ruleId: doc.ruleId || 'IDS_UNKNOWN',
    severity: doc.severity || 'low',
    blocked: doc.blocked === true,
  };
  for (const field of ['srcip', 'destip', 'destPort', 'srcPort', 'protocol']) {
    if (doc[field] !== undefined && doc[field] !== null && doc[field] !== '') identity[field] = doc[field];
    else identity[field] = null;
  }
  return identity;
}

async function coalesceRecentIdsAlert(doc, observedAt = new Date()) {
  if (doc.event_category !== 'ids_alert') return null;
  const eventTime = Number.isNaN(new Date(observedAt).getTime()) ? new Date() : new Date(observedAt);
  const duplicate = await Alert.findOne({
    ...idsAlertIdentity(doc),
    createdAt: { $gte: new Date(eventTime.getTime() - IDS_ALERT_COOLDOWN_MS) },
  }).sort({ createdAt: -1 }).select('_id occurrenceCount').lean();
  if (!duplicate) return null;

  await Alert.updateOne(
    { _id: duplicate._id },
    {
      $set: {
        occurrenceCount: Number(duplicate.occurrenceCount || 1) + 1,
        lastSeen: eventTime,
        receivedAt: new Date(),
      },
    },
  );
  return { ...duplicate, occurrenceCount: Number(duplicate.occurrenceCount || 1) + 1 };
}

function initializeOccurrence(doc, observedAt = new Date()) {
  const eventTime = Number.isNaN(new Date(observedAt).getTime()) ? new Date() : new Date(observedAt);
  doc.firstSeen = doc.firstSeen || eventTime;
  doc.lastSeen = doc.lastSeen || eventTime;
  doc.occurrenceCount = Math.max(1, Number(doc.occurrenceCount || 1));
  return doc;
}

async function cachedIdsPolicyRead(key, loader) {
  const now = Date.now();
  const cached = idsPolicyCache.get(key);
  if (cached && cached.expiresAt > now) return { ...cached.value, cached: true };
  if (idsPolicyInflight.has(key)) return idsPolicyInflight.get(key);
  const run = Promise.resolve()
    .then(loader)
    .then(value => {
      idsPolicyCache.set(key, { value, expiresAt: Date.now() + IDS_POLICY_CACHE_MS });
      return value;
    })
    .finally(() => idsPolicyInflight.delete(key));
  idsPolicyInflight.set(key, run);
  return run;
}

function clearIdsPolicyCache(companyId) {
  const prefix = `policy:${String(companyId || '')}:`;
  for (const key of idsPolicyCache.keys()) {
    if (key.startsWith(prefix)) idsPolicyCache.delete(key);
  }
}

function queueAiInvestigation(alert, io) {
  setImmediate(() => enqueueSecurityEventAnalysis(alert, { io })
    .catch(error => console.warn('[IDS→AI]', error.message)));
}

const IDS_IPS_EVENT_CATEGORIES = [
  'ids_alert',
  'ips_block',
  'ips_action',
  'blacklist_event',
  'intrusion_detection',
  'intrusion_prevention',
];
const SURICATA_INFORMATIONAL_NOISE_SIDS = new Set([
  '2017926', '2017928', '2022082', '2054141', '2210044', '2210054',
  '2200003', '2210045', '2210046',
]);
const SURICATA_DECODER_NOISE_SIDS = new Set(['2200003', '2210045', '2210046']);
const IDS_SENSOR_NOISE_RULE_IDS = [
  'SURICATA_2200003',
  'SURICATA_2210045',
  'SURICATA_2210046',
  'ZEEK_truncated_tcp_payload',
];

function isSuricataInformationalNoise(event = {}) {
  if (String(event.source || '').toLowerCase() !== 'suricata' || String(event.log_type || '').toLowerCase() !== 'alert') return false;
  const sid = String(event.signature_id || '');
  const signature = String(event.signature || '').toLowerCase();
  const raw = String(event.raw_event || '').toLowerCase();
  return ['2210044', '2210054'].includes(sid) || SURICATA_DECODER_NOISE_SIDS.has(sid) || (SURICATA_INFORMATIONAL_NOISE_SIDS.has(sid)
    && (signature.includes('check.torproject.org') || raw.includes('check.torproject.org')
      || signature.includes('ip-api.com') || raw.includes('ip-api.com')));
}

function isZeekInformationalNoise(event = {}) {
  if (String(event.source || '').toLowerCase() !== 'zeek' || String(event.log_type || '').toLowerCase() !== 'weird') return false;
  return String(event.signature || event.signature_id || '').toLowerCase() === 'truncated_tcp_payload';
}

function isSensorInformationalNoise(event = {}) {
  return isSuricataInformationalNoise(event) || isZeekInformationalNoise(event);
}

function strictIdsIpsAlertMatch(extra = {}) {
  const { $and = [], ...rest } = extra;
  return {
    ...rest,
    $and: [
      ...$and,
      // Ingestion normalizes actionable network detections into this field.
      // Query it directly so MongoDB can skip the high-volume
      // event_category=network_telemetry stream instead of evaluating regexes
      // across every document in the tenant.
      { event_category: { $in: IDS_IPS_EVENT_CATEGORIES } },
      { ruleId: { $nin: IDS_SENSOR_NOISE_RULE_IDS } },
      { $nor: [{ source: 'zeek', ruleId: 'ZEEK_weird', signatureName: /^truncated_tcp_payload$/i }] },
    ],
  };
}

async function resolveIdsIpsWindow(companyId, hours = 24) {
  const now = new Date();
  const windowMs = hours * 60 * 60 * 1000;
  const liveFilter = strictIdsIpsAlertMatch({
    companyId,
    createdAt: { $gte: new Date(now.getTime() - windowMs) },
  });

  // Use maxTimeMS to avoid indefinite hangs when DB is under load
  const liveExists = await Alert.exists(liveFilter).maxTimeMS(3000).catch(() => false);
  if (liveExists) {
    return { filter: liveFilter, isStale: false, capturedAt: null };
  }

  const latest = await Alert.findOne(strictIdsIpsAlertMatch({ companyId }))
    .sort({ createdAt: -1 })
    .select('createdAt')
    .maxTimeMS(3000)
    .lean()
    .catch(() => null);
  if (!latest?.createdAt) return { filter: liveFilter, isStale: false, capturedAt: null };

  const capturedAt = new Date(latest.createdAt);
  return {
    filter: strictIdsIpsAlertMatch({
      companyId,
      createdAt: { $gte: new Date(capturedAt.getTime() - windowMs), $lte: capturedAt },
    }),
    isStale: true,
    capturedAt,
  };
}

// ── Fire-and-forget TI enrichment + IPS auto-block ─────────────────────────────
function enrichAndBlock(ip, companyId, alertId, io) {
  if (!ip) return Promise.resolve(null);
  return threatIntel.enrichAndMaybeBlock(ip, companyId, alertId, io)
    .then(intel => {
      if (intel?.isMalicious) {
        console.log(`[IDS→TI] Malicious IP ${ip} — score ${intel.confidence}% — ${
          intel.shouldBlock ? 'AUTO-BLOCKED via IPS' : 'flagged (below threshold)'
        }`);
      }
    })
    .catch(e => console.warn('[IDS→TI] Enrich error:', e.message));
}

async function verifyThreatIntelBeforeBlock(srcip, destip, alertId, companyId, systemId) {
  const decision = await require('../services/ipsThreatGate.service').verifyAutomaticNetworkAction({
    ip: srcip, companyId, systemId, alertId, action: 'block_ip',
  });
  // Preserve display enrichment independently of the mandatory response gate.
  if (alertId) {
    const values = await Promise.all([srcip, destip].map(ip => ip
      ? ipEnrichmentService.enrichIp(ip).catch(() => null) : null));
    const fields = { asn: 'asn', asnOrg: 'organization', asnDomain: 'domain',
      geoCountry: 'country', geoCountryCode: 'countryCode', geoContinent: 'continent', geoContinentCode: 'continentCode',
      geoCity: 'city', geoRegion: 'region', geoPostal: 'postal', geoTimezone: 'timezone', geoLoc: 'loc',
      geoAnycast: 'anycast', geoHostname: 'hostname', geoDomainsCount: 'domainsCount', geoAsnRoute: 'asnRoute' };
    const update = {};
    for (const [index, info] of values.entries()) {
      if (!info) continue;
      const key = field => index ? `dest${field[0].toUpperCase()}${field.slice(1)}` : field;
      for (const [field, source] of Object.entries(fields)) if (info[source] != null) update[key(field)] = info[source];
      for (const field of ['proxy', 'hosting', 'vpn', 'tor', 'relay']) {
        if (info.privacy?.[field] != null) update[key(`geo${field[0].toUpperCase()}${field.slice(1)}`)] = info.privacy[field];
      }
      for (const field of ['email', 'phone', 'address', 'network']) {
        if (info.abuse?.[field] != null) update[key(`geoAbuse${field[0].toUpperCase()}${field.slice(1)}`)] = info.abuse[field];
      }
    }
    if (Object.keys(update).length) await Alert.updateOne({ _id: alertId, companyId }, { $set: update }).catch(() => {});
  }
  return { allowed: decision.allowed, summary: decision.reason, blockIp: decision.ip };
}

// ── IDS notifies IPS Engine (NEVER blocks directly) ────────────────────────────
// Called after saving each alert. IPS Engine handles all blocking decisions.
function trustedSensorSource(doc = {}) {
  return String(doc.source || doc.agentName || doc.sensor || '').toLowerCase();
}

function sensorBlockCandidate(doc = {}) {
  const source = trustedSensorSource(doc);
  if (!/(suricata|zeek)/i.test(source)) return false;
  const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
  const severity = String(doc.severity || 'low').toLowerCase();
  // BUG FIX: threshold was >=2 (medium+), now >=2 still correct but severity mapping above fixed
  // doc.blocked=true (Suricata action=blocked) OR severity medium/high/critical
  return Boolean(doc.blocked) || (severityRank[severity] || 1) >= 2;
}

async function resolveTargetSystem(doc = {}) {
  const companyId = doc.companyId;
  if (!companyId) return null;
  if (doc.systemId && mongoose.isValidObjectId(doc.systemId)) {
    const exact = await System.findOne({ _id: doc.systemId, companyId, isActive: true })
      .select('_id os osType platform').lean();
    if (exact) return exact;
  }
  const identity = [];
  if (doc.destip) identity.push({ ip: doc.destip });
  if (doc.endpointId) identity.push({ agentId: doc.endpointId });
  if (doc.agentId) identity.push({ agentId: doc.agentId });
  if (doc.macAddress) identity.push({ macAddress: doc.macAddress });
  if (identity.length) {
    const exact = await System.findOne({ companyId, isActive: true, $or: identity })
      .select('_id os osType platform').lean();
    if (exact) return exact;
  }
  // A single installed endpoint is unambiguous and is common for an on-host
  // Suricata sensor. Never guess when a company has multiple endpoints.
  const systems = await System.find({
    companyId, isActive: true, ipsEnabled: { $ne: false },
    agentVersion: { $nin: [null, ''] },
  })
    .select('_id os osType platform').limit(2).lean();
  return systems.length === 1 ? systems[0] : null;
}

async function notifyIPS(doc, adminEmail) {
  const { srcip, destip, attackType, description, severity, companyId } = doc;
  if (!srcip || !companyId) return;
  try {
    const targetSystem = await resolveTargetSystem(doc);
    const systemId = targetSystem?._id || null;
    const eventPlatform = systemPolicyPlatform(targetSystem || doc);
    const policies = await IdsIpsPolicy.find({ companyId }).lean();
    const severityRank = { low: 1, medium: 2, high: 3, critical: 4 };
    const eventSeverity = String(severity || 'low').toLowerCase();
    const severityBlock = ['high', 'critical'].includes(eventSeverity);
    const sensorTiCandidate = sensorBlockCandidate(doc);
    let policyBlock = false;
    let policyMatched = false;

    if (policies.length) {
      const activePolicies = policies.filter(policy => policy.enabled);
      if (activePolicies.length) {
        const searchable = [
          attackType, description, doc.ruleId, doc.type, doc.source, doc.sensor,
          doc.sensorEventType, doc.category, doc.signatureName, doc.agentName,
        ].filter(Boolean).join(' ').toLowerCase();
        const matches = activePolicies.filter(policy => {
          if (policy.targetSystemId && (!systemId || String(policy.targetSystemId) !== String(systemId))) return false;
          const policyPlatform = normalizePolicyPlatform(policy.targetPlatform);
          if (policyPlatform !== 'all' && policyPlatform !== eventPlatform) return false;
          if ((severityRank[eventSeverity] || 1) < (severityRank[policy.minimumSeverity] || 1)) return false;
          if (policy.sensor && policy.sensor !== 'any' && policy.sensor !== String(doc.source || '').toLowerCase()) return false;
          const patterns = String(policy.attackPattern || '').toLowerCase().split('|').map(value => value.trim()).filter(Boolean);
          if (patterns.length && !patterns.some(pattern => searchable.includes(pattern))) return false;
          if (policy.protocol && policy.protocol !== 'any' && policy.protocol !== String(doc.protocol || '').toLowerCase()) return false;
          if (policy.sourceIp && policy.sourceIp !== srcip) return false;
          if (policy.destinationPort && Number(policy.destinationPort) !== Number(doc.destPort)) return false;
          return true;
        });

        if (matches.length) {
          policyMatched = true;
          policyBlock = matches.some(policy => policy.mode === 'block');
          const matchedAt = new Date();
          await IdsIpsPolicy.updateMany(
            { _id: { $in: matches.map(policy => policy._id) } },
            { $inc: { matchCount: 1 }, $set: { lastMatchAt: matchedAt } },
          );
          if (doc._id) {
            await IdsPolicyViolation.insertMany(matches.map(policy => ({
              companyId,
              policyId: policy._id,
              alertId: doc._id,
              policyName: policy.name,
              policyRevision: Number(policy.revision || 1),
              mode: policy.mode,
              severity: eventSeverity,
              source: doc.source || doc.sensor || 'ids',
              srcip,
              destip,
              destPort: doc.destPort || null,
              protocol: doc.protocol || '',
              systemId,
              agentName: doc.agentName || '',
              description: description || attackType || policy.name,
              blocked: false, // policy intent is not proof of firewall enforcement
              createdAt: matchedAt,
              updatedAt: matchedAt,
            })), { ordered: false }).catch(error => {
              if (error?.code !== 11000 && !error?.writeErrors?.every(item => item.code === 11000)) throw error;
            });
            await Alert.updateOne({ _id: doc._id, companyId }, {
              $set: {
                policyTriggered: true,
                policyId: String(matches[0]._id),
                policyName: matches[0].name,
                policyAction: policyBlock ? 'block' : 'detect',
                policyActionStatus: policyBlock ? 'pending_enforcement' : 'detected',
              },
            });
          }
        }
      }
    }

    if (!severityBlock && !policyBlock && !sensorTiCandidate) return;

    const tiGate = await verifyThreatIntelBeforeBlock(srcip, destip, doc._id, companyId, systemId);
    if (!tiGate.allowed) {
      if (doc._id && policyBlock) await Alert.updateOne({ _id: doc._id, companyId }, { $set: { policyActionStatus: 'skipped' } });
      console.log(`[IDS → IPS] Block skipped until TI confirms ${srcip} (${doc.source || 'ids'}): ${tiGate.summary}`);
      return;
    }

    const targetBlockIp = tiGate.blockIp || srcip;

    // ── ISOLATION GATE ────────────────────────────────────────────────────
    // handleDetection → full IPS Engine cycle (email alerts + isolation after 5min)
    // This should ONLY run for confirmed policy matches or TI-verified sensor blocks.
    //
    // Severity-only blocks (high/critical) → direct DB block, NO isolation cycle.
    // Reason: a "high severity" IDS alert doesn't mean the endpoint is compromised.
    // Isolation is reserved for: policy enforcement + confirmed TI sensor threats.
    const needsFullCycle = policyBlock || sensorTiCandidate;

    if (needsFullCycle) {
      const decisionReason = policyBlock
        ? 'Policy IDS&IPS block'
        : 'Sensor TI-confirmed block';
      const incident = await ipsEngine.handleDetection({
        companyId: companyId.toString(),
        srcIp: targetBlockIp,
        attackType: attackType || description || 'Unknown Attack',
        severity,
        adminEmail: adminEmail || process.env.SMTP_USER,
        description: `${description || `${attackType} from ${srcip}`} [${decisionReason}; sensor=${doc.source || doc.agentName || 'IDS'}; policyMatched=${policyMatched}; TI verified: ${tiGate.summary}]`,
        forceBlock: true,
        systemId: systemId?.toString?.() || systemId || null,
      });
      if (doc._id && policyBlock) {
        await IdsPolicyViolation.updateMany({ companyId, alertId: doc._id, mode: 'block' }, { $set: { blocked: incident?.blockStatus === 'success' } });
        await Alert.updateOne({ _id: doc._id, companyId }, {
          $set: {
            policyActionStatus: incident?.blockStatus === 'success'
              ? 'enforced'
              : incident?.blockStatus === 'failed' ? 'failed' : 'skipped',
          },
        });
      }
    } else {
      // Severity-only: block IP directly — no email flood, no isolation
      console.log(`[IDS → IPS] Severity block (${eventSeverity}) for ${targetBlockIp} — direct DB block, no isolation cycle`);
      try {
        const IpsService = require('../services/ips.service');
        await IpsService.blockIP({
          ip: targetBlockIp,
          companyId: companyId.toString(),
          reason: `Severity auto-block (${eventSeverity}): ${attackType || description || 'IDS alert'}`,
          blockedBy: 'auto',
          systemId: systemId?.toString?.() || systemId || null,
        });
      } catch (blockErr) {
        console.warn(`[IDS → IPS] Direct block failed for ${targetBlockIp}: ${blockErr.message}`);
      }
    }
  } catch (e) {
    console.error('[IDS → Policy/IPS Engine] Error:', e.message);
  }
}


// ── GET /api/ids/health — Simple health check (no auth required) ──────────────────
router.get('/health', (req, res) => {
  res.json({ ok: true, message: 'IDS endpoint is healthy' });
});

// Auth: integration secret (same as agent) or JWT
async function idsAuth(req, res, next) {
  if (req.agentTransportSystem) {
    const auth = await verifySignedAgentRequest(req);
    if (auth.ok) {
      req.agentAuth = auth;
      return next();
    }
    return res.status(auth.status || 401).json({ message: auth.message || 'Invalid agent signature' });
  }
  const secret = String(req.headers['x-integration-secret'] || '');
  const expected = String(process.env.INTEGRATION_SECRET || '');
  if (secret && expected && secret.length === expected.length
      && crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(expected))) return next();
  // Fall back to JWT (for testing via dashboard)
  authenticate(req, res, next);
}

const SENSOR_SOURCES = new Set(['zeek', 'suricata']);
const SENSOR_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const MAX_SENSOR_BATCH = 500;

function sensorText(value, max) {
  return String(value == null ? '' : value).replace(/\0/g, '').slice(0, max);
}

function validIp(value) {
  const text = sensorText(value, 64);
  if (!text) return undefined;
  return require('net').isIP(text) ? text : undefined;
}

function sensorDocument(event, companyId) {
  if (!event || typeof event !== 'object' || Array.isArray(event)) throw new Error('Each event must be an object');
  const source = sensorText(event.source, 16).toLowerCase();
  if (!SENSOR_SOURCES.has(source)) throw new Error(`Unsupported sensor source: ${source}`);
  const eventId = sensorText(event.event_id, 160);
  if (!eventId) throw new Error('event_id is required');
  const severity = sensorText(event.severity, 16).toLowerCase();
  if (!SENSOR_SEVERITIES.has(severity)) throw new Error(`Invalid severity: ${severity}`);
  const logType = sensorText(event.log_type, 32).toLowerCase();
  const sensorName = sensorText(event.sensor, 128);
  const signature = sensorText(event.signature || logType, 2048);
  const port = value => Number.isInteger(Number(value)) && Number(value) >= 0 && Number(value) <= 65535 ? Number(value) : undefined;
  let rawEvent = event.raw_event;
  if (typeof rawEvent === 'string') {
    if (Buffer.byteLength(rawEvent) > 65536) throw new Error('raw_event exceeds 64 KiB');
    try { rawEvent = JSON.parse(rawEvent); } catch { rawEvent = { message: rawEvent }; }
  }
  const mitre = signature.match(/\bT\d{4}(?:\.\d{3})?\b/i)?.[0]?.toUpperCase();
  const cve = signature.match(/\bCVE-\d{4}-\d{4,7}\b/i)?.[0]?.toUpperCase();
  return {
    companyId, eventId, schemaVersion: 1, module: 'IDS', source_type: 'ids',
    event_category: event.actionable ? 'ids_alert' : 'network_telemetry',
    eventCategory: 'network', source, sensor: sensorName, agentName: sensorName, hostname: sensorName,
    sensorEventType: logType, severity, category: sensorText(event.category || logType, 128),
    srcip: validIp(event.src_ip), srcPort: port(event.src_port), destip: validIp(event.dest_ip),
    destPort: port(event.dest_port), protocol: sensorText(event.protocol, 16).toLowerCase(),
    blocked: ['blocked', 'drop', 'dropped'].includes(sensorText(event.action, 32).toLowerCase()),
    actionable: Boolean(event.actionable), ruleId: `${source.toUpperCase()}_${sensorText(event.signature_id || logType, 128)}`,
    signatureId: sensorText(event.signature_id, 128), signatureName: signature,
    description: `[${source}] ${signature}`, attackType: resolveAttackType(signature, logType),
    communityId: sensorText(event.community_id, 128), hostnameObserved: sensorText(event.hostname, 253),
    mitreId: mitre, cve, rawEvent, type: event.actionable ? 'IDS_ALERT' : 'IDS_TELEMETRY',
    dataOrigin: 'integration', createdAt: event.timestamp ? new Date(event.timestamp) : new Date(),
  };
}

// Unified, authenticated, idempotent Zeek/Suricata batch ingestion.
router.post('/events', idsAuth, async (req, res) => {
  try {
    const companyId = req.body?.company_id || req.body?.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'company_id required' });
    const status = await getCompanyIngestionStatus(companyId);
    if (!status.allowed) return sendIngestionBlocked(res, status);
    const events = Array.isArray(req.body?.events) ? req.body.events : [];
    if (!events.length || events.length > MAX_SENSOR_BATCH) {
      return res.status(400).json({ message: `events must contain 1-${MAX_SENSOR_BATCH} items` });
    }
    const acceptedEvents = events.filter(event => !isSensorInformationalNoise(event));
    const ignored = events.length - acceptedEvents.length;
    if (!acceptedEvents.length) {
      return res.status(202).json({ ok: true, accepted: 0, duplicates: 0, ignored });
    }
    const documents = acceptedEvents.map(event => sensorDocument(event, companyId));
    const newDocuments = [];
    const pendingActionable = new Map();
    for (const doc of documents) {
      const duplicate = await coalesceRecentIdsAlert(doc, doc.createdAt);
      if (duplicate) continue;
      if (doc.event_category !== 'ids_alert') {
        newDocuments.push(doc);
        continue;
      }
      const identity = JSON.stringify(idsAlertIdentity(doc));
      const pending = pendingActionable.get(identity);
      if (pending) {
        pending.occurrenceCount += 1;
        pending.lastSeen = doc.createdAt;
        continue;
      }
      initializeOccurrence(doc, doc.createdAt);
      pendingActionable.set(identity, doc);
      newDocuments.push(doc);
    }
    let inserted = [];
    try {
      inserted = newDocuments.length ? await Alert.insertMany(newDocuments, { ordered: false }) : [];
    } catch (error) {
      if (error?.code !== 11000 && !error?.writeErrors?.every(item => item.code === 11000)) throw error;
      inserted = error.insertedDocs || [];
    }
    const io = req.app.get('io');
    for (const doc of inserted) {
      queueAiInvestigation(doc, io);
      if (doc.actionable) {
        io?.to(`company:${companyId}`).emit('alert:new', doc);
        io?.to('superadmin').emit('alert:new', doc);
        notifyIPS(doc).catch(error => console.warn('[IDS/events→IPS]', error.message));
        const indicatorIp = threatIntel.isPublicIp?.(doc.srcip) ? doc.srcip : doc.destip;
        enrichAndBlock(indicatorIp, companyId, doc._id, io).catch(error => console.warn('[IDS/events→TI]', error.message));
      }
    }
    res.status(202).json({ ok: true, accepted: inserted.length, duplicates: documents.length - inserted.length, ignored });
  } catch (error) {
    console.error('[ids/events]', error.message);
    res.status(400).json({ message: error.message });
  }
});

// Map Suricata severity to our scale
function suricataSeverity(s) {
  // Suricata: 1=highest priority (critical), 2=high, 3=medium, 4+=low
  if (s === 1) return 'critical';
  if (s === 2) return 'high';    // BUG FIX: was 'medium' — severity 2 never triggered block
  if (s === 3) return 'medium';
  return 'low';
}

// ── Suricata EVE JSON ─────────────────────────────────────────────────────────
router.post('/suricata', idsAuth, async (req, res) => {
  try {
    const body = req.body;

    // Accept single event or array
    const events = Array.isArray(body) ? body : [body];
    const created = [];

    for (const evt of events) {
      // Only process alert events
      if (evt.event_type && evt.event_type !== 'alert') continue;

      const alert_data = evt.alert || {};

      // Ignore noisy informational Suricata SIDs to prevent alert fatigue:
      // - 2022082: ET POLICY External IP Lookup ip-api.com
      // - 2054141: ET INFO External IP Lookup Domain in DNS Lookup (ip-api.com)
      // - 2200003, 2210045, 2210046: local capture-path decoder diagnostics
      // - 2210044, 2210054: HARMLESS Stream Event false positives
      const sigId = Number(alert_data.signature_id);
      if ([2017926, 2017928, 2022082, 2054141, 2200003, 2210044, 2210045, 2210046, 2210054].includes(sigId)) {
        continue;
      }
      // company_id: check per-event first (array batch), then outer body, then query
      const companyId = evt.company_id || evt.companyId
        || body.company_id || body.companyId
        || req.query.companyId;
      if (!companyId) continue;
      const ingestionStatus = await getCompanyIngestionStatus(companyId);
      if (!ingestionStatus.allowed) {
        return sendIngestionBlocked(res, ingestionStatus);
      }

      const doc = {
        companyId,
        module: 'IDS',
        source_type: 'ids',
        event_category: 'ids_alert',
        source: 'suricata',
        ruleId: `SUR_${alert_data.signature_id || '0'}`,
        description: alert_data.signature || evt.event_type || 'Suricata alert',
        severity: suricataSeverity(alert_data.severity || 3),
        eventCategory: 'network',
        srcip: evt.src_ip,
        destip: evt.dest_ip,
        destPort: evt.dest_port,
        srcPort: evt.src_port,
        protocol: evt.proto,
        direction: 'inbound',
        blocked: alert_data.action === 'blocked',
        agentName: 'Suricata-IDS',
        rawEvent: evt,
        type: 'IDS_ALERT',
        attackType: resolveAttackType(alert_data.signature, evt.event_type),
      };
      doc.eventFingerprint = normalizeSecurityEvent({
        ...evt,
        ...doc,
        signatureId: alert_data.signature_id,
        signatureName: alert_data.signature,
      }).eventFingerprint;

      // Isolate only an exact destination endpoint; never select an arbitrary company system.
      const sys = companyId && evt.dest_ip
        ? await System.findOne({ companyId, isActive: true, ip: evt.dest_ip }).select('_id departmentId').lean()
        : null;
      if (sys) { doc.systemId = sys._id; doc.departmentId = sys.departmentId; }

      // Coalesce semantically identical alerts into one row during the noise
      // cooldown. Severity and blocked-state changes form a new identity and
      // remain immediately visible.
      const eventTime = evt.timestamp ? new Date(evt.timestamp) : new Date();
      const duplicate = await coalesceRecentIdsAlert(doc, eventTime);

      if (duplicate) {
        console.log(`[IDS/Suricata] Coalesced duplicate alert: ${doc.ruleId} from ${doc.srcip} to ${doc.destip}`);
        continue;
      }

      initializeOccurrence(doc, eventTime);

      let saved;
      try {
        saved = await Alert.create(doc);
      } catch (error) {
        if (error?.code === 11000) {
          console.log(`[IDS/Suricata] Skipping concurrently duplicated alert: ${doc.ruleId} from ${doc.srcip} to ${doc.destip}`);
          continue;
        }
        throw error;
      }
      created.push(saved._id);

      // Emit socket (IDS detection event — no blocking)
      const io = req.app.get('io');
      if (io) {
        io.to(`company:${companyId}`).emit('alert:new', saved);
        io.to('superadmin').emit('alert:new', saved);
      }
      queueAiInvestigation(saved, io);

      // IDS → IPS Engine: hand off high/critical alerts for blocking decision
      notifyIPS({ ...doc, _id: saved._id });

      // → Threat Intel enrichment on the ATTACKER (srcip), not the victim (destip)
      // BUG FIX: was enrichAndBlock(doc.destip,...) — TI was checking the victim IP, not attacker
      enrichAndBlock(doc.srcip, companyId, saved._id, io);
    }

    res.status(201).json({ ok: true, created: created.length });
  } catch (err) {
    console.error('[ids/suricata]', err.message);
    res.status(400).json({ message: err.message });
  }
});

// ── Zeek notice log ───────────────────────────────────────────────────────────
router.post('/zeek', idsAuth, async (req, res) => {
  try {
    const body = req.body;
    if (isZeekInformationalNoise({
      source: 'zeek',
      log_type: 'weird',
      signature: body?.name || body?.note,
    })) {
      return res.status(202).json({ ok: true, ignored: 1, reason: 'capture_diagnostic' });
    }
    const companyId = body.company_id || body.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'company_id required' });
    const ingestionStatus = await getCompanyIngestionStatus(companyId);
    if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);

      const doc = {
        companyId,
        module: 'IDS',
        source_type: 'ids',
        event_category: 'ids_alert',
        source: 'zeek',
        ruleId: `ZEEK_${(body.note || 'NOTICE').replace('::', '_')}`,
        description: body.msg || body.rule_message || 'Zeek network notice',
      severity: (body.severity || 'low').toLowerCase(),
      eventCategory: 'network',
      srcip: body.src || body['id.orig_h'],
      destip: body.dst || body['id.resp_h'],
      destPort: body['id.resp_p'],
      protocol: body.proto,
      agentName: 'Zeek-NSM',
        rawEvent: body,
        type: 'ZEEK_NOTICE',
        attackType: resolveAttackType(body.attack_type, body.note, body.msg),
      };

    const eventTime = body.ts || body.timestamp || new Date();
    const duplicate = await coalesceRecentIdsAlert(doc, eventTime);

    if (duplicate) {
      console.log(`[IDS/Zeek] Coalesced duplicate alert: ${doc.ruleId} from ${doc.srcip} to ${doc.destip}`);
      return res.status(201).json({ ok: true, note: 'duplicate coalesced', occurrenceCount: duplicate.occurrenceCount });
    }

    initializeOccurrence(doc, eventTime);
    const saved = await Alert.create(doc);
    const io = req.app.get('io');
    if (io) io.to(`company:${companyId}`).emit('alert:new', saved);
    queueAiInvestigation(saved, io);

    // IDS → IPS Engine handoff (IDS only detects)
    notifyIPS({ ...doc, _id: saved._id, attackType: doc.attackType || body.attack_type || doc.description });

    // → Threat Intel enrichment
    enrichAndBlock(doc.srcip, companyId, saved._id, io);

    res.status(201).json({ ok: true, alertId: saved._id });
  } catch (err) {
    console.error('[ids/zeek]', err.message);
    res.status(400).json({ message: err.message });
  }
});

// ── Generic IDS (pfSense, custom) ────────────────────────────────────────────
router.post('/generic', idsAuth, async (req, res) => {
  try {
    const body = req.body;
    const companyId = body.company_id || body.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'company_id required' });
    const ingestionStatus = await getCompanyIngestionStatus(companyId);
    if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);

      const doc = {
        companyId,
        module: 'IDS',
        source_type: 'ids',
        event_category: 'ids_alert',
        source: String(body.source || 'ids').toLowerCase(),
        ruleId: body.rule_id || body.rule || 'IDS_GENERIC',
        description: body.description || body.message || 'IDS alert',
      severity: body.severity || 'low',
      eventCategory: body.category || 'network',
      srcip: body.src_ip || body.srcip,
      destip: body.dst_ip || body.destip,
      destPort: body.dst_port || body.dest_port,
      protocol: body.protocol,
      blocked: body.blocked || body.action === 'block',
      agentName: body.sensor || body.host || 'IDS-Sensor',
        rawEvent: body,
        type: 'IDS_GENERIC',
        attackType: resolveAttackType(body.attack_type, body.attackType, body.description, body.message, body.rule_id, body.rule),
      };

    const eventTime = body.timestamp || body.ts || new Date();
    const duplicate = await coalesceRecentIdsAlert(doc, eventTime);
    if (duplicate) {
      return res.status(201).json({ ok: true, note: 'duplicate coalesced', occurrenceCount: duplicate.occurrenceCount });
    }
    initializeOccurrence(doc, eventTime);
    const saved = await Alert.create(doc);
    const io = req.app.get('io');
    if (io) io.to(`company:${companyId}`).emit('alert:new', saved);
    queueAiInvestigation(saved, io);

    // IDS → IPS Engine: all blocking decisions delegated to IPS
    const attackType = doc.attackType || body.attack_type || body.attackType || doc.description;
    notifyIPS({ ...doc, _id: saved._id, attackType });

    // → Threat Intel enrichment
    enrichAndBlock(doc.srcip, companyId, saved._id, io);

    res.status(201).json({ ok: true, alertId: saved._id });
  } catch (err) {
    console.error('[ids/generic]', err.message);
    res.status(400).json({ message: err.message });
  }
});

// ── Firewall log receiver (pfSense / OPNsense / iptables / UFW) ──────────────
router.post('/firewall', idsAuth, async (req, res) => {
  try {
    const body = req.body;
    const companyId = body.company_id || body.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'company_id required' });

    const action = (body.action || body.rule_action || 'allow').toLowerCase();
    const isBlocked = action === 'block' || action === 'drop' || action === 'deny';
    const description = isBlocked
      ? `Firewall BLOCKED: ${body.src_ip || ''} → ${body.dst_ip || ''}:${body.dst_port || ''}`
      : `Firewall ALLOWED: ${body.src_ip || ''} → ${body.dst_ip || ''}:${body.dst_port || ''}`;

    const doc = {
      companyId,
      source: body.source || 'firewall',
      ruleId: `FW_${body.rule || (isBlocked ? 'BLOCK' : 'ALLOW')}`,
      description,
      severity: isBlocked ? 'medium' : 'low',
      eventCategory: 'network',
      srcip: body.src_ip || body.srcip || body.src,
      destip: body.dst_ip || body.destip || body.dst,
      destPort: body.dst_port || body.dstport,
      protocol: body.protocol || body.proto,
      direction: body.direction || (body.interface === 'wan' ? 'inbound' : 'outbound'),
      blocked: isBlocked,
      agentName: body.hostname || body.sensor || 'Firewall',
      rawEvent: body,
      type: isBlocked ? 'FW_BLOCK' : 'FW_ALLOW',
    };

    const saved = await Alert.create(doc);
    const io = req.app.get('io');
    if (io && isBlocked) io.to(`company:${companyId}`).emit('alert:new', saved);

    // → Threat Intel enrichment for all firewall traffic
    enrichAndBlock(doc.srcip, companyId, saved._id, io);

    res.status(201).json({ ok: true, alertId: saved._id });
  } catch (err) {
    console.error('[ids/firewall]', err.message);
    res.status(400).json({ message: err.message });
  }
});

function policyCompanyId(req) {
  if (req.user.role === 'superadmin' || req.user.isSuperAdmin) {
    return req.query.companyId || req.body?.companyId || req.user.companyId;
  }
  return req.user.companyId;
}

function normalizePolicyPlatform(value) {
  const platform = String(value || 'all').trim().toLowerCase();
  return ['all', 'windows', 'linux', 'macos', 'android'].includes(platform) ? platform : 'all';
}

function systemPolicyPlatform(system = {}) {
  const value = `${system.osType || ''} ${system.os || ''} ${system.platform || ''} ${system.preferredPackageType || ''} ${system.agentType || ''}`.toLowerCase();
  if (/win|\.exe|\bexe\b|\bmsi\b/.test(value)) return 'windows';
  if (/android|\bapk\b/.test(value)) return 'android';
  if (/darwin|mac\s*os|macos|os\s*x|macpkg|dmg/.test(value)) return 'macos';
  if (/phone/.test(value)) return 'android';
  if (/linux|ubuntu|debian|centos|fedora|rhel|red hat|suse|\bdeb\b|\brpm\b/.test(value)) return 'linux';
  return '';
}

function validateAgentPolicyInput(body = {}) {
  const protocol = String(body.protocol || 'any').toLowerCase();
  if (!['any', 'tcp', 'udp', 'http', 'https', 'dns'].includes(protocol)) {
    return 'Unsupported policy protocol';
  }
  const sourceIp = String(body.sourceIp || '').trim();
  if (sourceIp) {
    const [address, prefix] = sourceIp.split('/', 2);
    const version = net.isIP(address);
    const maxPrefix = version === 4 ? 32 : version === 6 ? 128 : -1;
    if (maxPrefix < 0 || (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > maxPrefix))) {
      return 'Source IP must be a valid IPv4/IPv6 address or CIDR';
    }
  }
  const pattern = String(body.attackPattern || '').trim();
  if (pattern && !/^[A-Za-z0-9 ._/@?&=%:+|\-]+$/.test(pattern)) {
    return 'Attack pattern contains unsupported characters';
  }
  if (!body.presetId && !pattern && !sourceIp && !body.destinationPort) {
    return 'Custom agent policy requires an attack pattern, source IP, or destination port';
  }
  return '';
}

async function nativePolicyPayload(companyId, targetPlatform = '', targetSystemId = '') {
  const [policies, ipsWhitelist] = await Promise.all([
    IdsIpsPolicy.find({ companyId, enabled: true })
      .select('_id presetId name sensor mode minimumSeverity attackPattern protocol sourceIp destinationPort targetPlatform targetSystemId revision updatedAt')
      .sort({ presetId: 1 })
      .lean(),
    IpsWhitelist.find({ companyId }).select('value type').sort({ value: 1 }).lean(),
  ]);
  const platform = normalizePolicyPlatform(targetPlatform || 'all');
  const eligible = policies.filter(policy => {
    if (policy.targetSystemId && String(policy.targetSystemId) !== String(targetSystemId || '')) return false;
    const target = normalizePolicyPlatform(policy.targetPlatform);
    const platformMatches = platform === 'all' || target === 'all' || target === platform;
    const sensorSupported = platform !== 'windows' || policy.sensor !== 'zeek';
    return platformMatches && sensorSupported;
  });
  return {
    schemaVersion: 2,
    generatedAt: new Date().toISOString(),
    targetPlatform: platform,
    policies: eligible.map(policy => ({
      policyId: String(policy._id),
      revision: Number(policy.revision || 1),
      presetId: policy.presetId || '',
      name: policy.name,
      sensor: policy.sensor,
      mode: policy.mode,
      minimumSeverity: policy.minimumSeverity,
      attackPattern: policy.attackPattern || '',
      protocol: policy.protocol || 'any',
      sourceIp: policy.sourceIp || '',
      destinationPort: policy.destinationPort || null,
      targetPlatform: normalizePolicyPlatform(policy.targetPlatform),
      targetSystemId: policy.targetSystemId ? String(policy.targetSystemId) : null,
    })),
    ipsWhitelist: ipsWhitelist.map(entry => ({ value: entry.value, type: entry.type })),
  };
}

async function broadcastNativePolicies(req, companyId) {
  const payload = await nativePolicyPayload(companyId);
  const io = req.app.get('io');
  if (io) {
    const systems = await System.find({
      companyId,
      isActive: true,
      agentVersion: { $nin: [null, ''] },
    })
      .select('_id os osType platform preferredPackageType agentType').lean();
    for (const system of systems) {
      // Android policies are evaluated by the SOC backend and enforcement is
      // delivered through its durable heartbeat command queue. Android does
      // not run Suricata/Zeek and must not receive a native sensor payload.
      if (systemPolicyPlatform(system) === 'android') continue;
      io.to(`system_${system._id}`).emit(
        'ids:policy-sync',
        await nativePolicyPayload(companyId, systemPolicyPlatform(system), system._id),
      );
    }
  }
  return payload;
}

// ── IDS/IPS enforcement policy CRUD ─────────────────────────────────────────
router.get('/policy-presets', authenticate, requireAnalyst, (req, res) => {
  res.json({ presets: POLICY_PRESETS.map(publicPreset) });
});

router.post('/policy-presets/apply', authenticate, requireManager, async (req, res) => {
  try {
    const companyId = policyCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const ids = [...new Set(Array.isArray(req.body.presetIds) ? req.body.presetIds.map(String) : [])];
    if (!ids.length || ids.length > POLICY_PRESETS.length) return res.status(400).json({ message: 'Select at least one valid preset' });
    const requested = ids.map(id => POLICY_PRESETS.find(item => item.id === id));
    if (requested.some(item => !item)) return res.status(400).json({ message: 'Unsupported policy preset selected' });
    const mode = req.body.mode === 'block' ? 'block' : req.body.mode === 'detect' ? 'detect' : null;
    let targetSystemId = null;
    let targetPlatform = normalizePolicyPlatform(req.body.targetPlatform);
    if (req.body.targetSystemId) {
      if (!mongoose.isValidObjectId(req.body.targetSystemId)) return res.status(400).json({ message: 'Invalid target agent' });
      const targetSystem = await System.findOne({ _id: req.body.targetSystemId, companyId, isActive: { $ne: false } })
        .select('_id os osType platform preferredPackageType agentType').lean();
      if (!targetSystem) return res.status(400).json({ message: 'Selected agent was not found in this company' });
      targetSystemId = targetSystem._id;
      targetPlatform = systemPolicyPlatform(targetSystem);
      if (!targetPlatform) return res.status(400).json({ message: 'Selected agent OS is not available yet' });
    }
    if (targetPlatform !== 'all' && requested.some(preset => !publicPreset(preset).supportedPlatforms.includes(targetPlatform))) {
      return res.status(400).json({ message: `One or more selected presets do not support ${targetPlatform} agents` });
    }
    const allowedSeverity = new Set(['low', 'medium', 'high', 'critical']);
    const minimumSeverity = allowedSeverity.has(req.body.minimumSeverity) ? req.body.minimumSeverity : null;
    const createdBy = req.user.id || req.user._id;
    const policies = [];
    for (const preset of requested) {
      const supportedPlatforms = publicPreset(preset).supportedPlatforms;
      const requestedTargetPlatform = targetPlatform === 'all' && supportedPlatforms.length === 1
        ? supportedPlatforms[0]
        : targetPlatform;
      const existing = await IdsIpsPolicy.findOne({ companyId, presetId: preset.id })
        .select('targetPlatform').lean();
      const existingPlatform = normalizePolicyPlatform(existing?.targetPlatform);
      const effectiveTargetPlatform = targetSystemId || !existing || existingPlatform === requestedTargetPlatform
        ? requestedTargetPlatform
        : 'all';
      const policy = await IdsIpsPolicy.findOneAndUpdate(
        { companyId, presetId: preset.id },
        { $set: {
          name: preset.name, description: preset.description, enabled: true,
          sensor: preset.sensor, mode: effectivePresetMode(preset, mode),
          minimumSeverity: minimumSeverity || preset.minimumSeverity,
          attackPattern: preset.attackPattern, protocol: preset.protocol,
          destinationPort: preset.destinationPort || undefined,
          targetPlatform: effectiveTargetPlatform,
          targetSystemId,
          deploymentStatus: 'pending', deploymentAcks: [],
        }, $setOnInsert: { companyId, presetId: preset.id, createdBy }, $inc: { revision: 1 } },
        { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true },
      );
      policies.push(policy);
    }
    clearIdsPolicyCache(companyId);
    const deployment = await broadcastNativePolicies(req, companyId);
    res.status(201).json({ ok: true, applied: policies.length, policies, deployment });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// Signed polling fallback for agents that were offline during a Socket.IO push.
router.get('/agent-policies/:agentKey', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.params.agentKey });
    if (!auth.ok || !auth.system?.companyId) {
      return res.status(401).json({ message: auth.message || 'Invalid agent signature' });
    }
    res.json(await nativePolicyPayload(auth.system.companyId, systemPolicyPlatform(auth.system), auth.system._id));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/agent-policy-ack/:agentKey', async (req, res) => {
  try {
    const auth = await verifySignedAgentRequest(req, { agentKey: req.params.agentKey });
    if (!auth.ok || !auth.system?.companyId) {
      return res.status(401).json({ message: auth.message || 'Invalid agent signature' });
    }
    const results = Array.isArray(req.body?.policies) ? req.body.policies : [];
    if (!results.length) return res.status(400).json({ message: 'policies acknowledgement is required' });
    for (const item of results) {
      if (!mongoose.isValidObjectId(item.policyId)) continue;
      const policy = await IdsIpsPolicy.findOne({ _id: item.policyId, companyId: auth.system.companyId });
      if (!policy || Number(item.revision || 0) !== Number(policy.revision || 1)) continue;
      policy.deploymentAcks = (policy.deploymentAcks || []).filter(ack => String(ack.systemId) !== String(auth.system._id));
      policy.deploymentAcks.push({
        systemId: auth.system._id,
        agentId: auth.system.agentId || '',
        hostname: auth.system.hostname || auth.system.name || '',
        revision: Number(policy.revision || 1),
        ok: item.ok === true,
        result: String(item.result || '').slice(0, 1000),
        appliedAt: new Date(),
      });
      const revisionAcks = policy.deploymentAcks.filter(ack => Number(ack.revision) === Number(policy.revision));
      const hasSuccess = revisionAcks.some(ack => ack.ok === true);
      const hasFailure = revisionAcks.some(ack => ack.ok === false);
      const targets = await System.find({
        companyId: policy.companyId,
        isActive: true,
        agentVersion: { $nin: [null, ''] },
      })
        .select('_id os osType platform preferredPackageType agentType').lean();
      const eligibleTargets = targets.filter(system => {
        if (policy.targetSystemId && String(policy.targetSystemId) !== String(system._id)) return false;
        const platform = normalizePolicyPlatform(policy.targetPlatform);
        const systemPlatform = systemPolicyPlatform(system);
        if (systemPlatform === 'android') return false;
        if (policy.sensor === 'zeek' && systemPlatform === 'windows') return false;
        return platform === 'all' || platform === systemPlatform;
      });
      const allAcknowledged = eligibleTargets.length > 0 && revisionAcks.length >= eligibleTargets.length;
      policy.deploymentStatus = hasFailure
        ? (hasSuccess ? 'partial' : 'failed')
        : allAcknowledged && hasSuccess ? 'deployed'
          : hasSuccess ? 'partial' : 'pending';
      await policy.save();
    }
    clearIdsPolicyCache(auth.system.companyId);
    res.json({ ok: true, acknowledged: results.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/policies', authenticate, requireAnalyst, async (req, res) => {
  try {
    const companyId = policyCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const policies = await IdsIpsPolicy.find({ companyId }).sort({ createdAt: -1 }).lean();
    res.json({ policies });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/policies', authenticate, requireManager, async (req, res) => {
  try {
    const companyId = policyCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    if (!String(req.body.name || '').trim()) {
      return res.status(400).json({ message: 'Policy name is required' });
    }
    const sensor = ['suricata', 'zeek'].includes(req.body.sensor) ? req.body.sensor : 'any';
    let targetPlatform = normalizePolicyPlatform(req.body.targetPlatform);
    let targetSystemId = null;
    if (req.body.targetSystemId) {
      if (!mongoose.isValidObjectId(req.body.targetSystemId)) return res.status(400).json({ message: 'Invalid target agent' });
      const targetSystem = await System.findOne({ _id: req.body.targetSystemId, companyId, isActive: { $ne: false } })
        .select('_id os osType platform preferredPackageType agentType').lean();
      if (!targetSystem) return res.status(400).json({ message: 'Selected agent was not found in this company' });
      targetSystemId = targetSystem._id;
      targetPlatform = systemPolicyPlatform(targetSystem) || targetPlatform;
    }
    if (targetPlatform === 'windows' && sensor === 'zeek') {
      return res.status(400).json({ message: 'Windows policies require the Suricata / WinDivert sensor' });
    }
    const validationError = validateAgentPolicyInput(req.body);
    if (validationError) return res.status(400).json({ message: validationError });
    const policy = await IdsIpsPolicy.create({
      companyId,
      name: req.body.name,
      description: req.body.description,
      sensor,
      targetPlatform,
      targetSystemId,
      enabled: req.body.enabled !== false,
      mode: sensor === 'zeek' ? 'detect' : req.body.mode === 'block' ? 'block' : 'detect',
      minimumSeverity: req.body.minimumSeverity || 'medium',
      attackPattern: req.body.attackPattern,
      protocol: req.body.protocol || 'any',
      sourceIp: req.body.sourceIp,
      destinationPort: req.body.destinationPort || undefined,
      createdBy: req.user.id || req.user._id,
      revision: 1,
      deploymentStatus: targetPlatform === 'android' ? 'server_enforced' : 'pending',
    });
    clearIdsPolicyCache(companyId);
    const deployment = await broadcastNativePolicies(req, companyId);
    res.status(201).json({ policy, deployment });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.patch('/policies/:id', authenticate, requireManager, async (req, res) => {
  try {
    const companyId = policyCompanyId(req);
    const allowed = [
      'name', 'description', 'enabled', 'mode', 'minimumSeverity',
      'attackPattern', 'protocol', 'sourceIp', 'destinationPort', 'sensor',
      'targetPlatform', 'targetSystemId',
    ];
    const update = {};
    allowed.forEach(field => {
      if (req.body[field] !== undefined) update[field] = req.body[field];
    });
    if (update.destinationPort === '') update.destinationPort = undefined;
    const existing = await IdsIpsPolicy.findOne({ _id: req.params.id, companyId })
      .select('sensor targetPlatform targetSystemId attackPattern sourceIp destinationPort protocol presetId')
      .lean();
    if (!existing) return res.status(404).json({ message: 'Policy not found' });
    if (update.targetSystemId) {
      if (!mongoose.isValidObjectId(update.targetSystemId)) return res.status(400).json({ message: 'Invalid target agent' });
      const targetSystem = await System.findOne({ _id: update.targetSystemId, companyId, isActive: { $ne: false } })
        .select('_id os osType platform preferredPackageType agentType').lean();
      if (!targetSystem) return res.status(400).json({ message: 'Selected agent was not found in this company' });
      update.targetSystemId = targetSystem._id;
      update.targetPlatform = systemPolicyPlatform(targetSystem) || normalizePolicyPlatform(update.targetPlatform || existing.targetPlatform);
    } else if (update.targetSystemId === '') {
      update.targetSystemId = null;
    }
    if (update.targetPlatform !== undefined) update.targetPlatform = normalizePolicyPlatform(update.targetPlatform);
    const effectivePlatform = update.targetPlatform || normalizePolicyPlatform(existing.targetPlatform);
    if (effectivePlatform === 'windows' && (update.sensor || existing.sensor) === 'zeek') {
      return res.status(400).json({ message: 'Windows policies require the Suricata / WinDivert sensor' });
    }
    if ((update.sensor || existing.sensor) === 'zeek') update.mode = 'detect';
    const validationError = validateAgentPolicyInput({ ...existing, ...update });
    if (validationError) return res.status(400).json({ message: validationError });
    const policy = await IdsIpsPolicy.findByIdAndUpdate(
      req.params.id,
      {
        $set: {
          ...update,
          deploymentStatus: effectivePlatform === 'android' ? 'server_enforced' : 'pending',
          deploymentAcks: [],
        },
        $inc: { revision: 1 },
      },
      { new: true, runValidators: true },
    );
    clearIdsPolicyCache(companyId);
    const deployment = await broadcastNativePolicies(req, companyId);
    res.json({ policy, deployment });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

router.delete('/policies/:id', authenticate, requireManager, async (req, res) => {
  try {
    const companyId = policyCompanyId(req);
    const policy = await IdsIpsPolicy.findOneAndDelete({ _id: req.params.id, companyId });
    if (!policy) return res.status(404).json({ message: 'Policy not found' });
    clearIdsPolicyCache(companyId);
    const deployment = await broadcastNativePolicies(req, companyId);
    res.json({ ok: true, deployment });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// ── GET /api/ids/policy-violations — IDS/IPS policy matches and violations ──
router.get('/policy-violations', authenticate, requireAnalyst, async (req, res) => {
  try {
    const mongoose = require('mongoose');
    const isSuperAdmin = req.user.role === 'superadmin' || req.user.isSuperAdmin;
    const rawCid = isSuperAdmin
      ? (req.query.companyId || req.user.companyId)
      : req.user.companyId;
    if (!rawCid) return res.status(400).json({ message: 'companyId required' });

    let companyId;
    try {
      companyId = new mongoose.Types.ObjectId(rawCid);
    } catch {
      return res.status(400).json({ message: 'Invalid companyId format' });
    }

    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 100));
    const response = await cachedIdsPolicyRead(`policy:${String(companyId)}:${hours}:${limit}`, async () => {
      const windowStart = new Date(Date.now() - hours * 60 * 60 * 1000);
      const match = { companyId, createdAt: { $gte: windowStart } };
      const [violations, total, blocked, severityRows] = await Promise.all([
        IdsPolicyViolation.find(match).sort({ createdAt: -1 }).limit(limit).lean().maxTimeMS(2000),
        IdsPolicyViolation.countDocuments(match).maxTimeMS(2000),
        IdsPolicyViolation.countDocuments({ ...match, blocked: true }).maxTimeMS(2000),
        IdsPolicyViolation.aggregate([
          { $match: match },
          { $group: { _id: '$severity', count: { $sum: 1 } } },
        ]).option({ maxTimeMS: 2000 }),
      ]);
      const events = violations.map(item => ({
        ...item,
        ruleId: item.policyId,
        status: 'open',
        matchCount: 1,
      }));
      const open = total;
      const severity = { critical: 0, high: 0, medium: 0, low: 0 };
      severityRows.forEach(row => {
        if (Object.hasOwn(severity, row._id)) severity[row._id] = row.count;
      });

      return {
        period: `${hours}h`,
        total,
        blocked,
        detected: Math.max(0, total - blocked),
        open,
        severity,
        events,
      };
    });

    res.json({
      ...response,
      period: `${hours}h`,
    });
  } catch (err) {
    console.error('[IDS/policy-violations]', err.message);
    res.json({
      period: `${Math.min(168, Math.max(1, Number(req.query.hours) || 24))}h`,
      total: 0,
      blocked: 0,
      detected: 0,
      open: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0 },
      events: [],
      degraded: true,
      message: 'Policy violation data temporarily unavailable; returning safe empty result.',
    });
  }
});

// ── GET /api/ids/stats — IDS/Firewall alert stats ────────────────────────────
router.get('/stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const mongoose = require('mongoose');

    // Superadmin can query any company via ?companyId= query param
    // Regular analysts are always scoped to their own companyId from JWT
    const isSuperAdmin = req.user.role === 'superadmin' || req.user.isSuperAdmin;
    const rawCid = isSuperAdmin
      ? (req.query.companyId || req.user.companyId)
      : req.user.companyId;

    if (!rawCid) return res.status(400).json({ message: 'companyId required — select a company first' });

    let companyId;
    try {
      companyId = new mongoose.Types.ObjectId(rawCid);
    } catch {
      return res.status(400).json({ message: 'Invalid companyId format' });
    }

    if (req.query.summary === 'true' || req.query.light === 'true') {
      const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
      const lightFilter = strictIdsIpsAlertMatch({
        companyId,
        createdAt: { $gte: since },
      });
      const { total, high, critical, blocked, activeSystems } = await loadIdsAlertRollup(Alert, lightFilter);
      return res.json({
        period: '24h',
        summary: true,
        total,
        high,
        critical,
        blocked,
        severity: { critical, high, medium: 0, low: Math.max(0, total - high - critical) },
        agentNetwork: activeSystems,
      });
    }

    const recentLimit = Math.min(1000, Math.max(1, Number(req.query.recentLimit) || 25));
    const topLimit = Math.min(500, Math.max(1, Number(req.query.topLimit) || 10));
    const statsCacheKey = `${String(companyId)}:${recentLimit}:${topLimit}`;
    const cachedStats = idsStatsCache.get(statsCacheKey);
    if (cachedStats && cachedStats.expiresAt > Date.now()) {
      return res.json({ ...cachedStats.value, cached: true });
    }
    const normalizeSeverityStage = {
      $addFields: {
        normalizedSeverity: {
          $let: {
            vars: {
              rawSeverity: {
                $toLower: { $toString: { $ifNull: ['$severity', 'low'] } },
              },
            },
            in: {
              $switch: {
                branches: [
                  { case: { $in: ['$$rawSeverity', ['critical', 'crit', 'fatal', 'emergency']] }, then: 'critical' },
                  { case: { $in: ['$$rawSeverity', ['high']] }, then: 'high' },
                  { case: { $in: ['$$rawSeverity', ['medium', 'med', 'warning', 'warn', 'error', 'err', 'alert', 'block', 'blocked']] }, then: 'medium' },
                  { case: { $in: ['$$rawSeverity', ['low', 'info', 'informational', 'notice', 'debug']] }, then: 'low' },
                ],
                default: 'low',
              },
            },
          },
        },
      },
    };
    // This dashboard is explicitly labelled 24H. Never substitute an older
    // snapshot, otherwise severity and source-IP totals look current when they
    // are not.
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const base = strictIdsIpsAlertMatch({ companyId, createdAt: { $gte: since } });
    const isStale = false;
    const capturedAt = null;
    const [
      // ── By dedicated IDS tool source (suricata, zeek, firewall)
      suricataCount, zeekCount, firewallSourceCount,
      // ── By eventCategory (real agent data)
      byCategory,
      // ── Severity distribution
      bySeverity,
      // ── Top source IPs
      topSrcIps,
      // ── Blocked
      blockedCount,
      blockedSourceIps,
      // ── By source (debug)
      bySource,
      // ── Recent alerts with details (24h)
      recentAlerts,
      // ── 7-day timeline (hourly buckets, last 24h)
      timeline,
      // ── Active systems sending data
      activeSystems,
      // ── Threat-intel confirmed or blocked source IPs
      enrichedMaliciousIps,
      activeBlockedIps,
    ] = await Promise.all([
      Alert.countDocuments({ ...base, source: 'suricata' }).maxTimeMS(4000).catch(() => 0),
      Alert.countDocuments({ ...base, source: 'zeek' }).maxTimeMS(4000).catch(() => 0),
      Alert.countDocuments({ ...base, source: 'firewall' }).maxTimeMS(4000).catch(() => 0),
      // Category breakdown (includes agent data)
      Alert.aggregate([
        { $match: base },
        normalizeSeverityStage,
        {
          $group: {
            _id: '$eventCategory', count: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'high'] }, 1, 0] } },
            blocked: { $sum: { $cond: ['$blocked', 1, 0] } },
          }
        },
        { $sort: { count: -1 } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      // Severity distribution
      Alert.aggregate([
        { $match: base },
        normalizeSeverityStage,
        { $group: { _id: '$normalizedSeverity', count: { $sum: 1 } } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      // Top IP totals. Hourly trend buckets are queried separately for only
      // these ranked IPs, keeping the aggregation bounded and exact.
      Alert.aggregate([
        {
          $match: {
            ...base,
            srcip: {
              $exists: true,
              $nin: [null, '', '::1', '::ffff:127.0.0.1', 'localhost', '0.0.0.0'],
              $not: /^127\./,
            },
          },
        },
        normalizeSeverityStage,
        {
          $addFields: {
            severityRank: {
              $switch: {
                branches: [
                  { case: { $eq: ['$normalizedSeverity', 'critical'] }, then: 4 },
                  { case: { $eq: ['$normalizedSeverity', 'high'] }, then: 3 },
                  { case: { $eq: ['$normalizedSeverity', 'medium'] }, then: 2 },
                ],
                default: 1,
              },
            },
          },
        },
        {
          $group: {
            _id: '$srcip',
            count: { $sum: 1 },
            maxSeverityRank: { $max: '$severityRank' },
            critical: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'high'] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'medium'] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: ['$normalizedSeverity', 'low'] }, 1, 0] } },
            lastSeen: { $max: '$createdAt' },
            firstSeen: { $min: '$createdAt' },
          },
        },
        {
          $addFields: {
            severity: {
              $switch: {
                branches: [
                  { case: { $eq: ['$maxSeverityRank', 4] }, then: 'critical' },
                  { case: { $eq: ['$maxSeverityRank', 3] }, then: 'high' },
                  { case: { $eq: ['$maxSeverityRank', 2] }, then: 'medium' },
                ],
                default: 'low',
              },
            },
          },
        },
        { $sort: { count: -1 } }, { $limit: topLimit },
      ]).option({ maxTimeMS: 8000 }).catch(() => []),
      Alert.countDocuments({ ...base, blocked: true }).maxTimeMS(4000).catch(() => 0),
      Alert.distinct('srcip', {
        ...base,
        blocked: true,
        srcip: {
          $exists: true,
          $nin: [null, '', '::1', '::ffff:127.0.0.1', 'localhost', '0.0.0.0'],
          $not: /^127\./,
        },
      }).maxTimeMS(4000).catch(() => []),
      // By source (debug)
      Alert.aggregate([
        { $match: base },
        { $group: { _id: '$source', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]).option({ maxTimeMS: 5000 }).catch(() => []),
      // Recent alerts
      Alert.find(base).sort({ createdAt: -1 }).limit(recentLimit)
        .select('source source_type module event_category eventCategory severity description ruleId attackType signatureName srcip srcPort destip destPort protocol packetCount cveId mitre mitreId domain processName pid createdAt lastOccurrenceAt occurrenceCount blocked type agentName geoCountry geoCity geoLat geoLon')
        .maxTimeMS(5000)
        .lean()
        .catch(() => []),
      // Timeline (24h by hour)
      Alert.aggregate([
        { $match: base },
        { $group: { _id: { $hour: '$createdAt' }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      // Active systems
      Alert.distinct('agentName', base).maxTimeMS(4000).catch(() => []),
      Alert.aggregate([
        {
          $match: {
            $and: [
              base,
              { srcip: { $exists: true, $nin: [null, ''] } },
              {
                $or: [
                  { tiConfidence: { $gte: 75 } },
                  { 'tiFeeds.abuseScore': { $gte: 75 } },
                  { blocked: true },
                ],
              },
            ],
          },
        },
        {
          $group: {
            _id: '$srcip',
            count: { $sum: 1 },
            confidence: { $max: { $ifNull: ['$tiConfidence', '$tiFeeds.abuseScore'] } },
            lastSeen: { $max: '$createdAt' },
          },
        },
        { $sort: { confidence: -1, count: -1 } },
        { $limit: 50 },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
      BlockedIP.find({
        companyId,
        reverted: false,
        $or: [
          { blockedAt: { $gte: since } },
          { createdAt: { $gte: since } },
        ],
      })
        .select('ip reason blockedAt blockedBy')
        .sort({ blockedAt: -1 })
        .maxTimeMS(4000)
        .lean()
        .catch(() => []),
    ]);

    const activeBlocklistIps = activeBlockedIps.map(item => ({
      ip: item.ip,
      count: 1,
      confidence: 100,
      lastSeen: item.blockedAt,
      source: item.blockedBy === 'auto' ? 'IPS Auto Block' : 'IPS Blocklist',
      reason: item.reason,
    })).filter(item => item.ip);
    const maliciousIps = enrichedMaliciousIps.map(item => ({
      ip: item._id,
      count: item.count,
      confidence: item.confidence || 0,
      lastSeen: item.lastSeen,
      source: 'Threat Intelligence',
    }))
      .sort((a, b) => b.confidence - a.confidence || b.count - a.count);
    const maliciousEventCount = maliciousIps.reduce((sum, item) => sum + Number(item.count || 0), 0);
    const trendStartMs = Math.floor(since.getTime() / 3600000) * 3600000;
    const trendBucketCount = Math.ceil((Date.now() - trendStartMs) / 3600000);
    const topIpHourlyRows = topSrcIps.length
      ? await Alert.aggregate([
        { $match: { ...base, srcip: { $in: topSrcIps.map(item => item._id) } } },
        {
          $group: {
            _id: {
              ip: '$srcip',
              hour: { $dateToString: { date: '$createdAt', format: '%Y-%m-%dT%H:00:00.000Z', timezone: 'UTC' } },
            },
            count: { $sum: 1 },
          },
        },
      ]).option({ maxTimeMS: 6000 }).catch(() => [])
      : [];
    const hourlyByIp = new Map();
    topIpHourlyRows.forEach(row => {
      const bucketIndex = Math.floor((new Date(row._id.hour).getTime() - trendStartMs) / 3600000);
      if (bucketIndex < 0 || bucketIndex >= trendBucketCount) return;
      if (!hourlyByIp.has(row._id.ip)) hourlyByIp.set(row._id.ip, Array(trendBucketCount).fill(0));
      hourlyByIp.get(row._id.ip)[bucketIndex] = row.count;
    });
    const rankedTopSrcIps = topSrcIps.map(item => {
      return { ...item, hourly: hourlyByIp.get(item._id) || Array(trendBucketCount).fill(0) };
    });

    // Build category map
    const catMap = {};
    byCategory.forEach(c => { catMap[c._id] = c; });
    const sevMap = {};
    bySeverity.forEach(s => { sevMap[s._id] = s.count; });

    // Effective counts: IDS tools + agent-generated fallback
    const networkCat = catMap['network'] || { count: 0, critical: 0, high: 0, blocked: 0 };
    const malwareCat = catMap['malware'] || { count: 0, critical: 0, high: 0, blocked: 0 };
    const systemCat = catMap['system'] || { count: 0, critical: 0, high: 0, blocked: 0 };

    // For IDS view: only network IDS/firewall detections belong here. EDR/File alerts stay out.
    const effectiveSuricata = suricataCount || networkCat.count;
    const effectiveZeek = zeekCount || systemCat.count;
    const effectiveFirewall = firewallSourceCount || malwareCat.count;

    const totalAll = Object.values(sevMap).reduce((sum, count) => sum + Number(count || 0), 0);

    // Timeline for sparkline (fill all 24 hours)
    const timeMap = {};
    timeline.forEach(t => { timeMap[t._id] = t.count; });
    const sparkline = Array.from({ length: 24 }, (_, i) => ({ hour: i, count: timeMap[i] || 0 }));

    const statsPayload = {
      period: '24h',
      isStale,
      capturedAt,
      // Tool-specific counts (use real data or map from categories)
      suricata: effectiveSuricata,
      zeek: effectiveZeek,
      firewall: effectiveFirewall,
      // Aggregate counts  
      blocked: blockedCount,
      blockedIps: new Set([...blockedSourceIps, ...activeBlocklistIps.map(item => item.ip).filter(Boolean)]).size,
      total: totalAll,
      // Category breakdown with real data
      categories: {
        network: { count: networkCat.count, critical: networkCat.critical, high: networkCat.high, blocked: networkCat.blocked },
        malware: { count: maliciousEventCount, critical: malwareCat.critical, high: malwareCat.high, blocked: maliciousIps.length },
        system: { count: systemCat.count, critical: systemCat.critical, high: systemCat.high, blocked: systemCat.blocked },
      },
      // Severity distribution
      severity: {
        critical: sevMap['critical'] || 0,
        high: sevMap['high'] || 0,
        medium: sevMap['medium'] || 0,
        low: sevMap['low'] || 0,
      },
      // Top source IPs
      topSrcIps: rankedTopSrcIps,
      maliciousIps,
      activeBlocklistIps,
      // Active agents
      agentNetwork: activeSystems.length,
      activeAgents: activeSystems.filter(Boolean),
      // Recent alerts
      recentAlerts,
      // Sparkline
      sparkline,
      // Debug
      _debug: { companyId: rawCid, since, totalBySource: bySource },
    };
    idsStatsCache.set(statsCacheKey, {
      value: statsPayload,
      expiresAt: Date.now() + IDS_STATS_CACHE_MS,
    });
    if (idsStatsCache.size > 500) {
      const now = Date.now();
      for (const [key, entry] of idsStatsCache) {
        if (entry.expiresAt <= now) idsStatsCache.delete(key);
      }
    }
    res.json(statsPayload);
  } catch (err) {
    if (process.env.DEBUG_IDS_STATS === 'true') console.error('[IDS/stats] Error:', err);
    res.json({
      period: '24h',
      degraded: true,
      total: 0,
      high: 0,
      critical: 0,
      blocked: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0 },
      categories: { network: { count: 0, critical: 0, high: 0, blocked: 0 }, malware: { count: 0, critical: 0, high: 0, blocked: 0 }, system: { count: 0, critical: 0, high: 0, blocked: 0 } },
      topSrcIps: [],
      maliciousIps: [],
      activeBlocklistIps: [],
      agentNetwork: 0,
      activeAgents: [],
      recentAlerts: [],
      sparkline: Array.from({ length: 24 }, (_, hour) => ({ hour, count: 0 })),
    });
  }
});

// ── POST /api/ids/test-data — generate test IDS alerts (testing only) ─────────
router.post('/test-data', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { count = 20 } = req.body;
    const companyId = req.user.companyId;
    const testAlerts = [];

    const categories = ['network', 'malware', 'edr', 'file', 'system'];
    const severities = ['low', 'medium', 'high', 'critical'];
    const sources = ['suricata', 'agent', 'zeek', 'firewall'];
    const ips = ['192.168.1.100', '10.0.0.50', '172.16.0.200', '203.0.113.42', '198.51.100.89', '45.33.32.156'];
    const descs = {
      network: ['Port scan detected', 'DNS tunneling attempt', 'SYN flood attack', 'ARP spoofing'],
      malware: ['YARA rule matched: Emotet', 'Suspicious PE file', 'Ransomware pattern', 'Trojan dropper'],
      edr: ['Brute force login attempt', 'Privilege escalation', 'Lateral movement detected', 'Credential dump'],
      file: ['Critical file modified', 'Startup entry added', '/etc/passwd changed', 'Suspicious script created'],
      system: ['Service crashed unexpectedly', 'Kernel panic logged', 'SSH config changed', 'Cron job added'],
    };

    for (let i = 0; i < count; i++) {
      const cat = categories[i % categories.length];
      const severity = severities[i % severities.length];
      const srcIp = ips[i % ips.length];
      const descList = descs[cat];
      testAlerts.push({
        companyId,
        source: sources[i % sources.length],
        ruleId: `TEST_${cat.toUpperCase()}_${i}`,
        description: descList[i % descList.length],
        severity,
        eventCategory: cat,
        srcip: srcIp,
        destip: '10.0.0.1',
        destPort: 80 + i,
        srcPort: 54000 + i,
        protocol: 'tcp',
        direction: 'inbound',
        blocked: severity === 'critical' || severity === 'high',
        agentName: `Test-Agent-${(i % 3) + 1}`,
        type: `IDS_${cat.toUpperCase()}`,
        rawEvent: { test: true, index: i },
      });
    }

    const created = await Alert.insertMany(testAlerts);
    res.status(201).json({
      ok: true,
      created: created.length,
      byCategory: categories.reduce((acc, cat) => {
        acc[cat] = testAlerts.filter(a => a.eventCategory === cat).length;
        return acc;
      }, {}),
      message: `Generated ${created.length} test IDS alerts across all categories`,
    });
  } catch (err) {
    console.error('[IDS/test-data] Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/ids/block-stats — IPS block statistics (Auto vs Manual) ────────
router.get('/block-stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const mongoose = require('mongoose');

    const isSuperAdmin = req.user.role === 'superadmin' || req.user.isSuperAdmin;
    const rawCid = isSuperAdmin ? (req.query.companyId || req.user.companyId) : req.user.companyId;

    if (!rawCid) {
      return res.status(400).json({ message: 'companyId required' });
    }

    let companyId;
    try {
      companyId = new mongoose.Types.ObjectId(rawCid);
    } catch {
      return res.status(400).json({ message: 'Invalid companyId format' });
    }

    // Query BlockedIP model for stats
    if (!BlockedIP) {
      return res.status(500).json({ message: 'BlockedIP model not found' });
    }

    const base = { companyId, reverted: false, blockedAt: { $gte: since } };

    const [autoBlocked, manualBlocked, blocksByType, totalActive] = await Promise.all([
      BlockedIP.countDocuments({ ...base, blockedBy: 'auto' }),
      BlockedIP.countDocuments({ ...base, blockedBy: { $in: ['analyst', 'soar'] } }),
      BlockedIP.aggregate([
        { $match: base },
        { $group: { _id: '$method', count: { $sum: 1 } } },
      ]),
      BlockedIP.countDocuments({ companyId, reverted: false }),
    ]);

    const methodMap = {};
    blocksByType.forEach(b => { methodMap[b._id || 'unknown'] = b.count; });

    res.json({
      period: '24h',
      stats: {
        totalActive,
        autoBlocked,
        manualBlocked,
        byMethod: methodMap,
      },
      breakdown: {
        auto: {
          count: autoBlocked,
          percentage: totalActive > 0 ? Math.round((autoBlocked / totalActive) * 100) : 0,
        },
        manual: {
          count: manualBlocked,
          percentage: totalActive > 0 ? Math.round((manualBlocked / totalActive) * 100) : 0,
        },
      },
      generatedAt: new Date(),
    });
  } catch (err) {
    console.error('[IDS/block-stats] Error:', err);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/ids/geo-attacks — real 24h IDS/IPS/WAF attack activity ──────
router.get('/geo-attacks', authenticate, requireAnalyst, async (req, res) => {
  try {
    const mongoose = require('mongoose');
    const isSuperAdmin = req.user.role === 'superadmin' || req.user.isSuperAdmin;
    const rawCid = isSuperAdmin ? (req.query.companyId || req.user.companyId) : req.user.companyId;
    if (!rawCid) return res.status(400).json({ message: 'companyId required' });

    let companyId;
    try { companyId = new mongoose.Types.ObjectId(rawCid); }
    catch { return res.status(400).json({ message: 'Invalid companyId' }); }

    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    const maximumGpsAccuracyMeters = 50;
    const maximumDisplayedAccuracyMeters = 50000;
    const since = new Date(Date.now() - hours * 60 * 60 * 1000);
    const selectedIp = String(req.query.ip || '').trim().slice(0, 64);
    const recentIdsFilter = strictIdsIpsAlertMatch({
      companyId,
      createdAt: { $gte: since },
      srcip: selectedIp || { $exists: true, $nin: [null, ''] },
    });
    const wafFilter = {
      company: { $in: [String(rawCid), companyId] },
      ts: { $gte: since },
      ...(selectedIp ? { ip: selectedIp } : {}),
    };
    const [recentIdsAlerts, recentIdsTotal, recentIpsBlockedTotal, activeBlocks, wafEvents, wafTotal, recentGpsPositions, monitoredSystems, perAgentCounts] = await Promise.all([
      Alert.find(recentIdsFilter)
        .sort({ createdAt: -1 })
        .limit(300)
        .lean(),
      Alert.countDocuments(recentIdsFilter).maxTimeMS(6000).catch(() => 0),
      Alert.countDocuments({
        ...recentIdsFilter,
        $or: [
          { blocked: true },
          { event_category: { $in: ['ips_block', 'blacklist_event'] } },
        ],
      }).maxTimeMS(6000).catch(() => 0),
      BlockedIP.find({
        companyId,
        reverted: false,
        blockedAt: { $gte: since },
        ...(selectedIp ? { ip: selectedIp } : {}),
      })
        .select('ip reason blockedAt alertId blockedBy')
        .sort({ blockedAt: -1 })
        .limit(300)
        .lean(),
      mongoose.connection.db.collection('waf_events')
        .find(wafFilter)
        .sort({ ts: -1 })
        .limit(300)
        .toArray(),
      mongoose.connection.db.collection('waf_events').countDocuments(wafFilter, { maxTimeMS: 6000 }).catch(() => 0),
      Alert.find({
        companyId,
        ruleId: 'GPS_LOCATION_TELEMETRY',
        gpsStatus: 'available',
        gpsAccuracyMeters: { $gte: 0, $lte: maximumGpsAccuracyMeters },
        gpsLat: { $gte: -90, $lte: 90 },
        gpsLon: { $gte: -180, $lte: 180 },
        createdAt: { $gte: since },
      })
        .select('systemId agentName hostname gpsLat gpsLon gpsAccuracyMeters gpsProvider gpsObservedAt createdAt')
        .sort({ createdAt: -1 })
        .limit(100)
        .hint({ companyId: 1, createdAt: -1 })
        .maxTimeMS(10000)
        .lean(),
      System.find({
        companyId,
        isActive: { $ne: false },
        $or: [{ idsEnabled: true }, { endpointIdsEnabled: true }, { packetSensorAvailable: true }],
      })
        .select('_id agentId name hostname ip status lastSeen idsEnabled endpointIdsEnabled ipsEnabled wafEnabled packetSensorAvailable gpsLat gpsLon gpsAccuracyMeters gpsProvider gpsStatus gpsReason gpsObservedAt')
        .sort({ status: 1, name: 1 })
        .lean(),
      Alert.aggregate([
        { $match: recentIdsFilter },
        { $match: { systemId: { $ne: null } } },
        { $group: { _id: '$systemId', count: { $sum: 1 } } },
      ]).option({ maxTimeMS: 6000 }).catch(() => []),
    ]);
    const latestAlertByIp = new Map();
    recentIdsAlerts.forEach(alert => {
      if (!latestAlertByIp.has(alert.srcip)) latestAlertByIp.set(alert.srcip, alert);
    });
    const idsAlerts = recentIdsAlerts.map(alert => ({
      ...alert,
      mapEventType: alert.blocked === true || ['ips_block', 'blacklist_event'].includes(alert.event_category)
        ? 'ips_block'
        : 'ids_alert',
    }));
    const ipsBlockAlerts = activeBlocks.filter(block => !idsAlerts.some(alert => (
      alert.mapEventType === 'ips_block' && alert.srcip === block.ip
    ))).map(block => ({
      ...(latestAlertByIp.get(block.ip) || {}),
      _id: block.alertId || block._id,
      srcip: block.ip,
      severity: latestAlertByIp.get(block.ip)?.severity || 'medium',
      description: block.reason || latestAlertByIp.get(block.ip)?.description || 'Active IPS block',
      createdAt: block.blockedAt,
      blocked: true,
      mapEventType: 'ips_block',
    }));
    const wafAlerts = wafEvents.map(event => ({
      _id: event._id,
      srcip: event.ip,
      destip: event.hostname || event.requestPath || 'Protected Web Application',
      severity: event.severity || 'medium',
      description: event.attackType || event.ruleId || 'WAF attack',
      createdAt: event.ts || event.createdAt,
      blocked: event.blocked !== false,
      geoLat: event.geoLat,
      geoLon: event.geoLon,
      geoCountry: event.geoCountry,
      geoCountryCode: event.geoCountryCode,
      geoCity: event.geoCity,
      asnOrg: event.asnOrg || event.provider,
      mapEventType: 'waf_attack',
    })).filter(event => event.srcip);
    const alerts = [...idsAlerts, ...ipsBlockAlerts, ...wafAlerts]
      .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
    const totalEvents = Number(recentIdsTotal || 0) + Number(wafTotal || 0) + ipsBlockAlerts.length;

    // Destination coordinates must come from the protected AJNAT endpoint's
    // native location telemetry. Never present a hardcoded city as live GPS.
    const currentAgentDestinations = buildGpsDestinationMap(monitoredSystems, maximumDisplayedAccuracyMeters);
    const preciseEventDestinations = buildGpsDestinationMap(recentGpsPositions, maximumGpsAccuracyMeters);
    const gpsDestinations = new Map([...currentAgentDestinations, ...preciseEventDestinations]);

    // The geographic attack map must show remote attack origins, not the
    // protected endpoint's outbound Zeek protocol diagnostics.
    const mapEligibleAlerts = alerts.filter(isMapEligibleAttack);

    // Phase 1: Use actionable remote alerts that already have geo enrichment.
    const enrichedAlerts = mapEligibleAlerts.filter(a =>
      a.geoLat && a.geoLon &&
      Number.isFinite(Number(a.geoLat)) && Number.isFinite(Number(a.geoLon))
    );

    // Phase 2: For remaining alerts with public IPs, do live geo lookup
    const enrichedIps = new Set(enrichedAlerts.map(a => a.srcip));
    const needsGeo = mapEligibleAlerts
      .filter(a => !enrichedIps.has(a.srcip) && isPublicRoutableIp(a.srcip))
      .slice(0, 25);
    const uniqueGeoIps = [...new Set(needsGeo.map(a => a.srcip))].slice(0, 20);

    const geoMap = {};
    if (uniqueGeoIps.length > 0) {
      // Use the shared enrichment service here as well. Besides caching and
      // provider fallback, it supports public IPv6 sources; the previous
      // ip-api-only lookup returned no coordinates for valid IPv6 IDS events.
      const geoLookup = async ip => {
        try {
          const result = await ipEnrichmentService.enrichIp(ip);
          const [lat, lon] = String(result?.loc || '').split(',').map(Number);
          if (Number.isFinite(lat) && Number.isFinite(lon)) {
            return {
              ip,
              status: 'success',
              lat,
              lon,
              country: result.country || '',
              countryCode: result.countryCode || '',
              city: result.city || '',
              isp: result.organization || '',
            };
          }
        } catch { /* Try the IPv6-capable fallback below. */ }

        try {
          const response = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, {
            signal: AbortSignal.timeout(4000),
          });
          if (!response.ok) return { ip, status: 'fail' };
          const result = await response.json();
          const lat = Number(result?.latitude);
          const lon = Number(result?.longitude);
          if (result?.success !== true || !Number.isFinite(lat) || !Number.isFinite(lon)) {
            return { ip, status: 'fail' };
          }
          return {
            ip,
            status: 'success',
            lat,
            lon,
            country: result.country || '',
            countryCode: result.country_code || '',
            city: result.city || '',
            isp: result.connection?.isp || result.connection?.org || '',
          };
        } catch {
          return { ip, status: 'fail' };
        }
      };
      const geoResults = await Promise.all(uniqueGeoIps.map(geoLookup));
      geoResults.forEach(g => { if (g.status === 'success') geoMap[g.ip] = g; });
    }

    // Build attack points from enriched alerts (have geoLat/geoLon stored)
    const fromEnriched = enrichedAlerts.slice(0, 80).map(a => {
      const destination = destinationForAlert(a, gpsDestinations) || {};
      return {
        id: String(a._id),
        srcIp: a.srcip,
        dstIp: a.destip || 'Protected Network',
        severity: a.severity || 'low',
        blocked: a.mapEventType === 'ips_block' || a.blocked === true,
        eventType: a.mapEventType,
        description: a.description || a.type || 'IDS Alert',
        timestamp: a.createdAt,
        srcLat: Number(a.geoLat),
        srcLon: Number(a.geoLon),
        srcCountry: a.geoCountry || '',
        srcCountryCode: a.geoCountryCode || '',
        srcCity: a.geoCity || '',
        srcISP: a.asnOrg || '',
        ...destination,
      };
    });

    // Build from live geo lookup results
    const fromLiveGeo = needsGeo
      .filter(a => geoMap[a.srcip])
      .map(a => {
        const geo = geoMap[a.srcip];
        const destination = destinationForAlert(a, gpsDestinations) || {};
        return {
          id: String(a._id),
          srcIp: a.srcip,
          dstIp: a.destip || 'Protected Network',
          severity: a.severity || 'low',
          blocked: a.mapEventType === 'ips_block' || a.blocked === true,
          eventType: a.mapEventType,
          description: a.description || a.type || 'IDS Alert',
          timestamp: a.createdAt,
          srcLat: geo.lat,
          srcLon: geo.lon,
          srcCountry: geo.country || '',
          srcCountryCode: geo.countryCode || '',
          srcCity: geo.city || '',
          srcISP: geo.isp || '',
          ...destination,
        };
      });

    const attacks = [...fromEnriched, ...fromLiveGeo]
      .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
      .slice(0, 80);

    const primaryDestination = attacks.find(attack => Number.isFinite(attack.dstLat) && Number.isFinite(attack.dstLon));
    const monitoringSummary = buildAgentFlowSummary(monitoredSystems, perAgentCounts, {
      hours,
      totalEvents,
      mappedEvents: attacks.length,
      idsIpsEvents: recentIdsTotal,
      idsDetectedEvents: Math.max(0, Number(recentIdsTotal || 0) - Number(recentIpsBlockedTotal || 0)),
      ipsBlockedEvents: Number(recentIpsBlockedTotal || 0) + ipsBlockAlerts.length,
      wafEvents: wafTotal,
      activeBlockEvents: activeBlocks.length,
    }, gpsDestinations);
    const googleMapsKey = (process.env.GOOGLE_MAPS_KEY || '').trim();
    res.json({
      ok: true,
      mode: 'ids_ips_waf',
      selectedIp: selectedIp || null,
      total: totalEvents,
      mapped: attacks.length,
      originSummary: {
        remoteAttackEvents: mapEligibleAlerts.length,
        plottedRemoteEvents: attacks.length,
        localOrSensorOnlyEvents: Math.max(0, alerts.length - mapEligibleAlerts.length),
      },
      attacks,
      monitoringSummary,
      agents: monitoringSummary.agents,
      destLat: primaryDestination?.dstLat ?? null,
      destLon: primaryDestination?.dstLon ?? null,
      destinationSource: primaryDestination?.dstLocationSource ?? null,
      maximumGpsAccuracyMeters,
      maximumDisplayedAccuracyMeters,
      destinationStatus: primaryDestination
        ? (primaryDestination.dstLocationPrecision === 'approximate' ? 'approximate' : 'available')
        : 'awaiting_location',
      hours,
      googleMapsKey,
    });
  } catch (err) {
    console.error('[IDS/geo-attacks] Error:', err);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
