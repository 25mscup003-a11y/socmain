/**
 * waf.routes.js — WAF Real-time Data API
 * ========================================
 * Provides WAF data directly from MongoDB (waf_events, waf_agents collections).
 * Works independently of the IPS server (port 5050).
 *
 * Routes:
 *   POST /api/waf/report       — SOC Agent reports WAF startup / block event
 *   GET  /api/waf/status       — Active WAF agents + stats per company
 *   GET  /api/waf/attacks      — Recent WAF blocked attacks (?limit=50)
 *   GET  /api/waf/stats        — Attack type breakdown (24h)
 *   POST /api/waf/test-event   — Inject a test WAF block event (dev only)
 */

const router = require('express').Router();
const mongoose = require('mongoose');
const crypto = require('crypto');
const System = require('../models/System.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { verifySignedAgentRequest } = require('../utils/agentRequestAuth');

// ── Auth: Integration secret OR JWT ──────────────────────────────────────────
async function wafAuth(req, res, next) {
  const secret = req.headers['x-integration-secret'] || req.headers['x-webhook-secret'];
  if (secret && (secret === process.env.INTEGRATION_SECRET || secret === process.env.IPS_WEBHOOK_SECRET)) {
    req.user = { role: 'superadmin', isSuperAdmin: true, companyId: '' };
    req.integrationAuth = true;
    return next();
  }
  if (req.headers['x-agent-signature'] || req.body?.agent_key || req.body?.agentKey) {
    const verified = await verifySignedAgentRequest(req);
    if (!verified.ok) return res.status(verified.status).json({ message: verified.message });
    req.agentSystem = verified.system;
    req.user = { role: 'agent', companyId: verified.system.companyId };
    return next();
  }
  authenticate(req, res, next);
}

// ── Get MongoDB connection (uses Mongoose's default connection) ───────────────
function getWafDB() {
  const conn = mongoose.connection;
  if (conn.readyState !== 1) return null;
  return conn.db;
}

async function ensureWafIndexes() {
  const db = getWafDB();
  if (!db) throw new Error('Database unavailable');
  const events = db.collection('waf_events');
  await Promise.all([
    // UI uses a rolling 24-hour window, while audit data remains queryable for
    // 90 days. MongoDB's TTL monitor removes it only after that retention.
    events.createIndex(
      { ts: 1 },
      { name: 'waf_events_90d_ttl', expireAfterSeconds: 90 * 24 * 60 * 60 },
    ),
    events.createIndex(
      { company: 1, ts: -1 },
      { name: 'waf_events_company_ts' },
    ),
    events.createIndex(
      { company: 1, requestPath: 1, method: 1, ts: -1 },
      { name: 'waf_events_company_endpoint_ts' },
    ),
    events.createIndex(
      { company: 1, severity: 1, blocked: 1, ts: -1 },
      { name: 'waf_events_company_severity_blocked_ts' },
    ),
    events.createIndex(
      { integrationId: 1, externalEventId: 1 },
      { name: 'waf_events_external_dedupe', unique: true, sparse: true },
    ),
  ]);
}

// ── Resolve companyId from request ───────────────────────────────────────────
function resolveCompany(req) {
  const isSuperAdmin = req.user?.role === 'superadmin' || req.user?.isSuperAdmin;
  if (isSuperAdmin) return req.query.company || req.query.companyId || req.body?.company || '';
  return req.user?.companyId?.toString() || '';
}

function companyQuery(company) {
  if (!company) return {};
  const ids = [company.toString()];
  if (mongoose.Types.ObjectId.isValid(company)) ids.push(new mongoose.Types.ObjectId(company));
  return { company: { $in: ids } };
}

const tokenHash = token => crypto.createHash('sha256').update(String(token || '')).digest('hex');
const wafFallbackCache = new Map();
const WAF_FALLBACK_CACHE_MS = 15 * 1000;
const safeEqual = (left, right) => {
  const a = Buffer.from(String(left || ''), 'utf8');
  const b = Buffer.from(String(right || ''), 'utf8');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const first = (...values) => values.find(value => value !== undefined && value !== null && value !== '');
const parseProtectedPorts = value => [...new Set(String(value || '')
  .split(/[\s,;]+/)
  .filter(Boolean)
  .map(Number)
  .filter(port => Number.isInteger(port) && port >= 1 && port <= 65535))].sort((a, b) => a - b);
const DEFAULT_ATTACK_PROTECTION_POLICY = Object.freeze({
  enabled: true,
  webAttackBlocking: true,
  networkAttackBlocking: true,
  webMinimumSeverity: 'medium',
  networkMinimumSeverity: 'high',
});
const ATTACK_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const normalizeAttackSeverity = (value, fallback) => {
  const severity = String(value || fallback).trim().toLowerCase();
  if (!ATTACK_SEVERITIES.has(severity)) throw new Error(`Invalid severity: ${severity}`);
  return severity;
};
const reportedPortStatus = (ports, observedAt = new Date()) => (Array.isArray(ports) ? ports : [])
  .map(Number)
  .filter(port => Number.isInteger(port) && port >= 1 && port <= 65535)
  .map(port => ({ port, alive: true, observedAt }));
const normalizeMonitoredServices = value => (Array.isArray(value) ? value : []).slice(0, 200)
  .map(service => ({
    port: Number(service?.port),
    protocol: String(service?.protocol || 'tcp').toLowerCase() === 'tcp' ? 'tcp' : 'unknown',
    scheme: ['http', 'https'].includes(String(service?.scheme || '').toLowerCase())
      ? String(service.scheme).toLowerCase() : 'http',
    bindAddress: String(service?.bindAddress || '').slice(0, 64),
    pid: Number.isInteger(Number(service?.pid)) ? Number(service.pid) : null,
    processName: String(service?.processName || '').slice(0, 200),
    executable: String(service?.executable || '').slice(0, 1000),
    username: String(service?.username || '').slice(0, 200),
  }))
  .filter(service => Number.isInteger(service.port) && service.port >= 1 && service.port <= 65535);
const normalizeListenerInventory = value => (Array.isArray(value) ? value : []).slice(0, 500)
  .map(listener => ({
    port: Number(listener?.local_port ?? listener?.port),
    protocol: String(listener?.protocol || 'tcp').toLowerCase() === 'udp' ? 'udp' : 'tcp',
    bindAddress: String(listener?.local_ip || listener?.bindAddress || '').slice(0, 64),
    pid: Number.isInteger(Number(listener?.pid)) ? Number(listener.pid) : null,
    processName: String(listener?.process_name || listener?.processName || '').slice(0, 200),
    executable: String(listener?.executable || '').slice(0, 1000),
    username: String(listener?.username || '').slice(0, 200),
  }))
  .filter(listener => Number.isInteger(listener.port) && listener.port >= 1 && listener.port <= 65535);

function normalizeExternalWafEvent(payload = {}, provider = 'Other / Custom') {
  const body = payload.properties || payload.event || payload;
  const http = body.httpRequest || body.http_request || body.request || {};
  const rule = payload.rule || payload.ruleGroup || payload.rule_group || {};
  const action = String(first(body.action, body.Action, body.disposition, body.outcome, 'blocked')).toLowerCase();
  const blocked = !/allow|pass|monitor|count|log/.test(action);
  const timestamp = first(body.timestamp, body.datetime, body.eventTime, body.event_time, body.time, body.ts, body.Date);
  const parsedTime = timestamp ? new Date(typeof timestamp === 'number' && timestamp < 1e12 ? timestamp * 1000 : timestamp) : new Date();
  const externalEventId = String(first(body.id, body.eventId, body.event_id, body.rayId, body.ray_id, body.RayID, body.requestId, body.request_id, '')).slice(0, 200);
  return {
    ...(externalEventId ? { externalEventId } : {}),
    ip: String(first(body.clientIP, body.clientIp, body.client_ip, body.ClientIP, body.sourceIp, body.source_ip, body.srcip, http.clientIp, http.client_ip, http.sourceIp, '')).slice(0, 64),
    attackType: String(first(body.attackType, body.attack_type, body.message, body.description, body.ruleName, body.rule_name, rule.name, 'Web Attack')).slice(0, 200),
    severity: String(first(body.severity, body.level, body.priority, 'high')).toLowerCase().slice(0, 20),
    ruleId: String(first(body.ruleId, body.rule_id, body.ruleID, body.terminatingRuleId, rule.id, `${provider}_WAF`)).slice(0, 200),
    requestPath: String(first(body.requestPath, body.request_path, body.uri, body.url, body.ClientRequestURI, body.requestUri, http.uri, http.path, '/')).slice(0, 2000),
    method: String(first(body.method, body.httpMethod, body.http_method, body.ClientRequestMethod, http.method, 'UNKNOWN')).toUpperCase().slice(0, 16),
    statusCode: Number(first(body.statusCode, body.status_code, body.responseStatus, body.response_status, body.EdgeResponseStatus, http.statusCode, 0)) || 0,
    responseTimeMs: Number(first(body.responseTimeMs, body.response_time_ms, body.responseTime, body.latencyMs, body.latency_ms, 0)) || 0,
    requestSize: Number(first(body.requestSize, body.request_size, body.bytesIn, body.bytes_in, 0)) || 0,
    responseSize: Number(first(body.responseSize, body.response_size, body.bytesOut, body.bytes_out, 0)) || 0,
    apiVersion: String(first(body.apiVersion, body.api_version, '')).slice(0, 64),
    authType: String(first(body.authType, body.auth_type, '')).slice(0, 64),
    hostname: String(first(body.hostname, body.Hostname, body.host, body.domain, http.host, '')).slice(0, 253),
    userAgent: String(first(body.userAgent, body.user_agent, body.UserAgent, http.userAgent, http.user_agent, '')).slice(0, 1000),
    matched: String(first(body.matched, body.match, body.matchedData, body.matched_data, body.message, '')).slice(0, 2000),
    action,
    blocked,
    ts: Number.isNaN(parsedTime.getTime()) ? new Date() : parsedTime,
  };
}

// Dedicated push bridge for Cloudflare/AWS/Azure/ModSecurity/custom forwarders.
// The token is connector-specific; tenant identity is resolved from its hash
// and is never accepted from the submitted payload.
router.post('/ingest/:integrationId', async (req, res) => {
  try {
    const db = getWafDB();
    if (!db) return res.status(503).json({ message: 'Database unavailable' });
    const supplied = String(req.headers['x-waf-token'] || req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    if (!supplied) return res.status(401).json({ message: 'WAF connector token required' });
    const integration = await db.collection('waf_integrations').findOne({ integrationId: req.params.integrationId, enabled: true });
    if (!integration || !safeEqual(tokenHash(supplied), integration.tokenHash)) {
      return res.status(401).json({ message: 'Invalid WAF connector credentials' });
    }
    const payloads = Array.isArray(req.body) ? req.body : Array.isArray(req.body?.events) ? req.body.events : [req.body];
    if (!payloads.length || payloads.length > 1000) return res.status(400).json({ message: '1 to 1000 events required' });
    const receivedAt = new Date();
    const docs = payloads.map(payload => ({
      ...normalizeExternalWafEvent(payload, integration.provider),
      company: integration.company,
      integrationId: integration.integrationId,
      provider: integration.provider,
      source: 'external-waf-bridge',
      receivedAt,
    })).filter(event => event.ip || event.requestPath !== '/');
    if (!docs.length) return res.status(400).json({ message: 'No recognizable WAF events found' });
    let accepted = 0;
    for (const doc of docs) {
      const dedupe = doc.externalEventId
        ? { integrationId: doc.integrationId, externalEventId: doc.externalEventId }
        : { integrationId: doc.integrationId, ip: doc.ip, ruleId: doc.ruleId, ts: doc.ts };
      const result = await db.collection('waf_events').updateOne(dedupe, { $setOnInsert: doc }, { upsert: true });
      if (result.upsertedCount) accepted += 1;
    }
    await db.collection('waf_integrations').updateOne({ _id: integration._id }, { $set: { lastEventAt: receivedAt, lastStatus: 'connected', lastError: '', lastReceivedCount: docs.length } });
    const io = req.app.get('io');
    docs.forEach(doc => {
      io?.to(`company:${integration.company}`).emit('waf:block', doc);
      io?.to(`company:${integration.company}`).emit('api:event', doc);
    });
    return res.status(202).json({ received: docs.length, accepted, duplicates: docs.length - accepted });
  } catch (err) {
    console.error('[WAF/ingest]', err.message);
    return res.status(500).json({ message: 'WAF event ingestion failed' });
  }
});

// ── POST /api/waf/report — SOC Agent reports WAF startup / block ─────────────
router.post('/report', wafAuth, async (req, res) => {
  try {
    const db = getWafDB();
    const {
      action, systemId, hostname, agentVersion, agentIP,
      detectedPorts, monitoredServices, ip, attackType, severity, ruleId,
      requestPath, method, matched, wafPort, originalPort, statusCode,
      responseTimeMs, requestSize, responseSize,
    } = req.body;

    const company = req.agentSystem?.companyId?.toString() || req.body.company || req.body.companyId ||
      req.headers['x-company-id'] || req.headers['x-company'] || req.query.company || '';

    if (!action) return res.status(400).json({ message: 'action required' });

    // ── STARTUP / HEARTBEAT ───────────────────────────────────────────────────
    if (action === 'startup' || action === 'heartbeat') {
      const normalizedServices = normalizeMonitoredServices(monitoredServices);
      const normalizedPorts = parseProtectedPorts([
        ...(Array.isArray(detectedPorts) ? detectedPorts : []),
        ...normalizedServices.map(service => service.port),
      ]);
      const agentDoc = {
        company,
        systemId: systemId || hostname || 'unknown',
        hostname: hostname || systemId || 'unknown',
        agentIP: agentIP || '',
        agentVersion: agentVersion || '',
        ports: normalizedPorts,
        services: normalizedServices,
        portStatus: reportedPortStatus(normalizedPorts),
        lastSeen: new Date(),
        online: true,
      };

      if (db) {
        await db.collection('waf_agents').updateOne(
          { company, systemId: agentDoc.systemId },
          { $set: agentDoc },
          { upsert: true }
        );
      }

      // Emit socket event
      const io = req.app.get('io');
      if (io && company) {
        io.to(`company:${company}`).emit('waf:agent', { action, ...agentDoc });
      }

      if (process.env.WAF_LOG_HEARTBEAT === 'true' || action === 'startup') {
        console.log(`[WAF] ${action.toUpperCase()}: agent=${agentDoc.systemId} ip=${agentIP} ports=${normalizedPorts.join(',')} company=${company}`);
      }
      return res.json({ received: true, action, company });
    }

    // ── BLOCK EVENT ───────────────────────────────────────────────────────────
    if (action === 'block') {
      if (!ip) return res.status(400).json({ message: 'ip required for block events' });

      const eventDoc = {
        company,
        systemId: systemId || hostname || 'unknown',
        hostname: hostname || '',
        ip,
        attackType: attackType || 'Web Attack',
        severity: severity || 'high',
        ruleId: ruleId || 'WAF_BLOCK',
        requestPath: requestPath || '/',
        method: method || 'GET',
        statusCode: Number(statusCode) || 403,
        responseTimeMs: Number(responseTimeMs) || 0,
        requestSize: Number(requestSize) || 0,
        responseSize: Number(responseSize) || 0,
        matched: matched || '',
        originalPort: originalPort || null,
        wafPort: wafPort || null,
        blocked: true,
        ts: new Date(),
      };

      if (db) {
        await db.collection('waf_events').insertOne(eventDoc);
      }

      // Real-time socket emit
      const io = req.app.get('io');
      if (io) {
        if (company) {
          io.to(`company:${company}`).emit('waf:block', eventDoc);
          io.to(`company:${company}`).emit('api:event', eventDoc);
        }
        io.to('superadmin').emit('waf:block', eventDoc);
      }

      console.warn(`[WAF] BLOCK: ${attackType} from ${ip} → ${requestPath} [company=${company}]`);
      return res.json({ received: true, action: 'block', ip, attackType, company });
    }

    return res.status(400).json({ message: `Unknown action: ${action}` });
  } catch (err) {
    console.error('[WAF/report] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ── Existing WAF configuration (no passwords or provider secrets stored) ─────
router.get('/integration', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company) return res.status(400).json({ message: 'companyId required' });
    let integration = db
      ? await db.collection('waf_integrations').findOne(companyQuery(company))
      : null;
    if (integration) {
      if (!integration.integrationId) {
        const integrationId = crypto.randomUUID();
        await db.collection('waf_integrations').updateOne(
          { _id: integration._id },
          { $set: { integrationId, updatedAt: new Date() } }
        );
        integration = { ...integration, integrationId };
      }
      integration.tokenConfigured = Boolean(integration.tokenHash);
      delete integration.tokenHash;
      integration.webhookPath = `/api/waf/ingest/${integration.integrationId}`;
    }
    return res.json({ integration });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

router.put('/integration', authenticate, requireManager, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company) return res.status(400).json({ message: 'companyId required' });
    if (!db) return res.status(503).json({ message: 'Database unavailable' });
    const text = (value, max = 500) => String(value || '').trim().slice(0, max);
    const allowedProviders = ['Cloudflare', 'F5 ASM', 'FortiWeb', 'Imperva', 'ModSecurity / Nginx', 'AWS WAF', 'Azure WAF', 'NGINX App Protect', 'Other / Custom'];
    const provider = text(req.body.provider, 80);
    if (!allowedProviders.includes(provider)) return res.status(400).json({ message: 'Unsupported WAF provider' });
    const existing = await db.collection('waf_integrations').findOne(companyQuery(company));
    const integrationId = existing?.integrationId || crypto.randomUUID();
    const connectorToken = existing?.tokenHash ? '' : `waf_${crypto.randomBytes(32).toString('base64url')}`;
    const protectedPorts = parseProtectedPorts(req.body.protectedPorts);
    if (String(req.body.protectedPorts || '').trim() && !protectedPorts.length) {
      return res.status(400).json({ message: 'Enter valid ports between 1 and 65535' });
    }
    const integration = {
      company,
      integrationId,
      provider,
      deploymentType: text(req.body.deploymentType, 40),
      protectedDomain: text(req.body.protectedDomain, 253),
      webServer: text(req.body.webServer, 80),
      logPaths: text(req.body.logPaths, 1000),
      protectedPorts: protectedPorts.join(', '),
      logFormat: text(req.body.logFormat, 40),
      hostname: text(req.body.hostname, 253),
      internalIp: text(req.body.internalIp, 64),
      notes: text(req.body.notes, 1000),
      enabled: req.body.enabled !== false,
      updatedAt: new Date(),
      updatedBy: req.user._id || req.user.id || null,
      ...(connectorToken ? { tokenHash: tokenHash(connectorToken), tokenCreatedAt: new Date() } : {}),
    };
    await db.collection('waf_integrations').updateOne(companyQuery(company), { $set: integration }, { upsert: true });
    const safeIntegration = { ...integration, tokenConfigured: Boolean(existing?.tokenHash || connectorToken), webhookPath: `/api/waf/ingest/${integrationId}` };
    delete safeIntegration.tokenHash;
    return res.json({ ok: true, integration: safeIntegration, ...(connectorToken ? { connectorToken } : {}) });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

router.post('/integration/rotate-token', authenticate, requireManager, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company || !db) return res.status(400).json({ message: 'WAF integration is unavailable' });
    const integration = await db.collection('waf_integrations').findOne(companyQuery(company));
    if (!integration) return res.status(404).json({ message: 'Save WAF integration first' });
    const connectorToken = `waf_${crypto.randomBytes(32).toString('base64url')}`;
    await db.collection('waf_integrations').updateOne({ _id: integration._id }, { $set: { tokenHash: tokenHash(connectorToken), tokenCreatedAt: new Date(), lastStatus: 'token_rotated', updatedAt: new Date() } });
    return res.json({ connectorToken, webhookPath: `/api/waf/ingest/${integration.integrationId}` });
  } catch (err) { return res.status(500).json({ message: err.message }); }
});

router.post('/integration/test', authenticate, requireManager, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    const integration = db && await db.collection('waf_integrations').findOne(companyQuery(company));
    if (!integration) return res.status(404).json({ message: 'Save WAF integration first' });
    const eventDoc = {
      company: integration.company, integrationId: integration.integrationId, provider: integration.provider,
      source: 'waf-bridge-test', systemId: 'external-waf', hostname: integration.hostname || integration.protectedDomain || '',
      ip: req.ip || '', attackType: 'WAF Bridge Connection Test', severity: 'info', ruleId: 'WAF_BRIDGE_TEST',
      requestPath: '/__ajnat_waf_bridge_test__', method: 'GET', matched: 'Authenticated dashboard connection test',
      blocked: false, action: 'test', ts: new Date(), receivedAt: new Date(),
    };
    await db.collection('waf_events').insertOne(eventDoc);
    await db.collection('waf_integrations').updateOne({ _id: integration._id }, { $set: { lastTestAt: new Date(), lastStatus: 'test_ok', lastError: '' } });
    req.app.get('io')?.to(`company:${integration.company}`).emit('waf:block', eventDoc);
    return res.json({ ok: true, message: 'WAF bridge test event accepted' });
  } catch (err) { return res.status(500).json({ message: err.message }); }
});

// ── Native AJNAT attack prevention policy ───────────────────────────────────
router.get('/attack-protection-policy', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company) return res.status(400).json({ message: 'companyId required' });
    const saved = db
      ? await db.collection('waf_attack_protection_policies').findOne({ company: String(company) })
      : null;
    const policy = { ...DEFAULT_ATTACK_PROTECTION_POLICY, ...(saved || {}) };
    delete policy._id;
    delete policy.company;
    return res.json({ policy });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

router.put('/attack-protection-policy', authenticate, requireManager, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company) return res.status(400).json({ message: 'companyId required' });
    if (!db) return res.status(503).json({ message: 'Database unavailable' });
    const policy = {
      enabled: req.body.enabled !== false,
      webAttackBlocking: req.body.webAttackBlocking !== false,
      networkAttackBlocking: req.body.networkAttackBlocking !== false,
      webMinimumSeverity: normalizeAttackSeverity(req.body.webMinimumSeverity, 'medium'),
      networkMinimumSeverity: normalizeAttackSeverity(req.body.networkMinimumSeverity, 'high'),
      updatedAt: new Date(),
      updatedBy: req.user._id || req.user.id || null,
    };
    await db.collection('waf_attack_protection_policies').updateOne(
      { company: String(company) },
      { $set: { company: String(company), ...policy } },
      { upsert: true },
    );
    req.app.get('io')?.to(`company:${company}`).emit('waf:policy', policy);
    return res.json({ ok: true, policy });
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
});

router.delete('/attack-protection-policy/:ruleId', authenticate, requireManager, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    if (!company) return res.status(400).json({ message: 'companyId required' });
    if (!db) return res.status(503).json({ message: 'Database unavailable' });
    const ruleId = String(req.params.ruleId || '').toUpperCase();
    const field = ruleId === 'WAF-WEB-AUTO-BLOCK'
      ? 'webAttackBlocking'
      : ruleId === 'IPS-NETWORK-AUTO-BLOCK' ? 'networkAttackBlocking' : '';
    if (!field) return res.status(404).json({ message: 'Attack-blocking rule not found' });
    await db.collection('waf_attack_protection_policies').updateOne(
      { company: String(company) },
      {
        $set: {
          company: String(company),
          [field]: false,
          updatedAt: new Date(),
          updatedBy: req.user._id || req.user.id || null,
        },
      },
      { upsert: true },
    );
    const saved = await db.collection('waf_attack_protection_policies').findOne({ company: String(company) });
    const policy = { ...DEFAULT_ATTACK_PROTECTION_POLICY, ...(saved || {}), [field]: false };
    delete policy._id;
    delete policy.company;
    req.app.get('io')?.to(`company:${company}`).emit('waf:policy', policy);
    return res.json({ ok: true, deletedRuleId: ruleId, policy });
  } catch (err) {
    return res.status(400).json({ message: err.message });
  }
});

// ── GET /api/waf/status — WAF agents + stats ─────────────────────────────────
router.get('/status', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    const hours = Math.min(24 * 90, Math.max(1, parseInt(req.query.hours || '24', 10)));

    // ── 1. Load registered WAF agents ────────────────────────────────────────
    let agents = [];
    if (db) {
      const onlineSince = new Date(Date.now() - 30 * 60 * 1000);
      // Keep the last known service inventory for the selected dashboard
      // retention window. A missed heartbeat must mark an agent offline, not
      // erase its monitored ports from the UI.
      const inventorySince = new Date(Date.now() - hours * 60 * 60 * 1000);
      const filter = { ...companyQuery(company), lastSeen: { $gte: inventorySince } };
      agents = await db.collection('waf_agents').find(filter).toArray();

      // AJNAT agents register automatically through normal signed telemetry;
      // no "Add Existing WAF" configuration is required for this path.
      const companyIds = [company];
      if (mongoose.Types.ObjectId.isValid(company)) companyIds.push(new mongoose.Types.ObjectId(company));
      const autoStatuses = await db.collection('alerts').find({
        companyId: { $in: companyIds },
        ruleId: 'WAF_AGENT_STATUS',
      }).sort({ createdAt: -1 }).limit(2000).toArray();
      const agentIndexes = new Map(agents.map((agent, index) => [String(agent.systemId || ''), index]));
      for (const statusEvent of autoStatuses) {
        const rawEvent = statusEvent.rawEvent || {};
        const reportedServices = normalizeMonitoredServices(rawEvent.monitoredServices);
        const reportedPorts = parseProtectedPorts([
          ...(Array.isArray(rawEvent.detectedPorts) ? rawEvent.detectedPorts : []),
          ...reportedServices.map(service => service.port),
        ]);
        const lastSeen = statusEvent.createdAt || statusEvent.eventTimestamp || statusEvent.receivedAt || new Date();
        const systemId = String(statusEvent.systemId || rawEvent.system_id || statusEvent.agentId || '');
        if (!systemId) continue;
        const heartbeatAgent = {
          systemId,
          hostname: rawEvent.hostname || statusEvent.hostname || statusEvent.agentName || 'AJNAT Agent',
          agentIP: rawEvent.agentIP || '',
          agentVersion: rawEvent.agentVersion || statusEvent.agentVersion || '',
          company,
          ports: reportedPorts,
          services: reportedServices,
          portStatus: reportedPortStatus(reportedPorts, lastSeen),
          online: new Date(lastSeen) >= onlineSince,
          lastSeen,
          autoConnected: true,
          enforcementEnabled: rawEvent.wafIntercept === true,
        };
        const existingIndex = agentIndexes.get(systemId);
        if (existingIndex === undefined) {
          agentIndexes.set(systemId, agents.length);
          agents.push(heartbeatAgent);
          continue;
        }
        const existing = agents[existingIndex];
        if (new Date(existing.lastSeen || 0) < new Date(lastSeen)) {
          agents[existingIndex] = {
            ...existing,
            ...heartbeatAgent,
            hostname: heartbeatAgent.hostname || existing.hostname,
            agentIP: heartbeatAgent.agentIP || existing.agentIP,
            agentVersion: heartbeatAgent.agentVersion || existing.agentVersion,
          };
        }
      }

      // Merge the endpoint listener inventory. WAF inspection applies only to
      // HTTP(S), while this inventory intentionally includes every TCP/UDP
      // listener so the dashboard never hides an exposed non-web service.
      const exposureStatuses = await db.collection('alerts').find({
        companyId: { $in: companyIds },
        ruleId: 'NET_EXPOSURE_SUMMARY',
      }).sort({ createdAt: -1 }).limit(2000).toArray();
      const exposureSeen = new Set();
      for (const exposure of exposureStatuses) {
        const rawEvent = exposure.rawEvent || {};
        const systemId = String(exposure.systemId || rawEvent.system_id || exposure.agentId || '');
        if (!systemId || exposureSeen.has(systemId)) continue;
        exposureSeen.add(systemId);
        const listeners = normalizeListenerInventory(rawEvent.raw?.listeners || rawEvent.listeners);
        const lastSeen = exposure.createdAt || exposure.eventTimestamp || exposure.receivedAt || new Date();
        const existingIndex = agentIndexes.get(systemId);
        if (existingIndex !== undefined) {
          agents[existingIndex] = { ...agents[existingIndex], listeners, listenerInventoryAt: lastSeen };
        } else {
          agentIndexes.set(systemId, agents.length);
          agents.push({
            systemId,
            hostname: rawEvent.hostname || exposure.hostname || exposure.agentName || 'AJNAT Agent',
            agentIP: rawEvent.agentIP || '',
            company,
            ports: [],
            services: [],
            listeners,
            online: new Date(lastSeen) >= onlineSince,
            lastSeen,
            autoConnected: true,
          });
        }
      }

      // Company-configured third-party WAF ports are monitored directly and
      // appear beside AJNAT-discovered ports. No local proxy port is created.
      const integration = await db.collection('waf_integrations').findOne({
        ...companyQuery(company),
        enabled: true,
      });
      const configuredPorts = parseProtectedPorts(integration?.protectedPorts);
      if (integration && configuredPorts.length) {
        agents.push({
          systemId: `external-waf:${integration.integrationId || integration._id}`,
          hostname: integration.hostname || integration.protectedDomain || integration.provider || 'Existing WAF',
          agentIP: integration.internalIp || '',
          agentVersion: integration.provider || 'Existing WAF',
          company,
          ports: configuredPorts,
          online: true,
          lastSeen: integration.lastEventAt || integration.updatedAt || new Date(),
          configuredIntegration: true,
          autoConnected: false,
          enforcementEnabled: false,
        });
      }

      // WAF listener inventories arrive less frequently than normal signed
      // agent telemetry. Use the enrolled system heartbeat for agent liveness,
      // while preserving the WAF report timestamp for its port inventory.
      if (mongoose.Types.ObjectId.isValid(company)) {
        const liveSystems = await System.find({
          companyId: new mongoose.Types.ObjectId(company),
          isActive: true,
          wafEnabled: { $ne: false },
        }).select('_id lastSeen status').lean();
        const systemsById = new Map(liveSystems.map(system => [String(system._id), system]));
        agents = agents.map(agent => {
          if (agent.configuredIntegration) return agent;
          const system = systemsById.get(String(agent.systemId || ''));
          const agentLastSeen = system?.lastSeen;
          const agentIsOnline = system?.status === 'active'
            && new Date(agentLastSeen || 0).getTime() >= onlineSince.getTime();
          if (!agentIsOnline) return agent;
          return {
            ...agent,
            lastWafReportAt: agent.lastSeen,
            lastAgentSeen: agentLastSeen,
            lastSeen: agentLastSeen,
            online: true,
          };
        });
      }
    }

    agents = agents.map(agent => ({
      ...agent,
      allPorts: [...new Set([
        ...(agent.ports || []),
        ...(agent.listeners || []).map(listener => listener.port),
      ])].sort((a, b) => a - b),
      online: agent.configuredIntegration
        ? true
        : agent.online !== false && new Date(agent.lastSeen).getTime() >= Date.now() - 30 * 60 * 1000,
    }));

    // ── 3. WAF stats from waf_events collection ───────────────────────────────
    let stats24h = db ? await _getWAFStats(db, hours * 3600 * 1000, company) : _emptyStats();
    let recentAttacks = db ? await _getRecentAttacks(db, 20, company, hours * 3600 * 1000) : [];

    if (company) {
      const fallback = await _getFallbackFromAlerts(company, hours);
      stats24h = _mergeWafStats(stats24h, fallback.stats);
      recentAttacks = [...recentAttacks, ...fallback.recentAttacks]
        .sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, 20);
    }

    const activeAgents = agents.filter(a => a.online).length;
    const uniquePorts = [...new Set(agents.flatMap(a => a.ports || []))];
    const uniqueListeningPorts = [...new Set(agents.flatMap(a => a.allPorts || []))];

    return res.json({
      activeAgents,
      agents,
      allAgents: agents,
      protectedPorts: uniquePorts,
      totalPortsProtected: uniquePorts.length,
      listeningPorts: uniqueListeningPorts,
      totalListeningPorts: uniqueListeningPorts.length,
      stats24h,
      statsWindowHours: hours,
      recentAttacks,
    });
  } catch (err) {
    console.error('[WAF/status] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ── GET /api/waf/attacks — Recent WAF blocked attacks ────────────────────────
router.get('/attacks', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    const limit = Math.min(parseInt(req.query.limit || '100', 10), 500);
    const hours = Math.min(24 * 90, Math.max(1, parseInt(req.query.hours || '24', 10)));

    let attacks = db ? await _getRecentAttacks(db, limit, company, hours * 3600 * 1000) : [];
    let stats = db ? await _getWAFStats(db, hours * 3600 * 1000, company) : _emptyStats();

    if (company) {
      const fallback = await _getFallbackFromAlerts(company, hours);
      attacks = [...attacks, ...fallback.recentAttacks]
        .sort((a, b) => new Date(b.ts) - new Date(a.ts)).slice(0, limit);
      stats = _mergeWafStats(stats, fallback.stats);
    }

    return res.json({ count: attacks.length, attacks, stats, statsWindowHours: hours });
  } catch (err) {
    console.error('[WAF/attacks] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ── GET /api/waf/stats — Attack type breakdown (24h) ─────────────────────────
router.get('/stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req);
    const hours = parseInt(req.query.hours || '24', 10);
    const stats = db ? await _getWAFStats(db, hours * 3600 * 1000, company) : _emptyStats();
    return res.json(stats);
  } catch (err) {
    console.error('[WAF/stats] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ── POST /api/waf/test-event — Inject test WAF block event ───────────────────
router.post('/test-event', authenticate, requireAnalyst, async (req, res) => {
  try {
    const db = getWafDB();
    const company = resolveCompany(req) || req.user?.companyId?.toString();
    if (!company) return res.status(400).json({ message: 'companyId required' });

    const attackTypes = ['SQL Injection', 'XSS', 'Command Injection', 'RFI/LFI', 'CSRF', 'Directory Traversal'];
    const severities = ['critical', 'high', 'medium'];
    const paths = ['/login', '/admin', '/api/users', '/search', '/upload', '/.env', '/wp-admin'];
    const ips = ['185.220.101.45', '45.142.212.100', '91.108.4.67', '194.165.16.10', '103.85.95.33'];

    const n = Math.min(parseInt(req.body.count || '5', 10), 20);
    const events = [];
    for (let i = 0; i < n; i++) {
      events.push({
        company,
        systemId: 'test-agent',
        hostname: 'test-host',
        ip: ips[i % ips.length],
        attackType: attackTypes[i % attackTypes.length],
        severity: severities[i % severities.length],
        ruleId: `WAF_TEST_${i + 1}`,
        requestPath: paths[i % paths.length],
        method: ['GET', 'POST', 'PUT'][i % 3],
        matched: `test-pattern-${i + 1}`,
        blocked: true,
        ts: new Date(Date.now() - i * 60000), // spread over last N minutes
      });
    }

    if (db) {
      await db.collection('waf_events').insertMany(events);
    }

    // Emit real-time events
    const io = req.app.get('io');
    if (io) {
      events.forEach(evt => {
        io.to(`company:${company}`).emit('waf:block', evt);
        io.to('superadmin').emit('waf:block', evt);
      });
    }

    return res.json({ ok: true, created: events.length, events });
  } catch (err) {
    console.error('[WAF/test-event] Error:', err.message);
    return res.status(500).json({ message: err.message });
  }
});

// ── Helpers ───────────────────────────────────────────────────────────────────

function _mergeWafStats(primary = _emptyStats(), sensor = _emptyStats()) {
  const byType = new Map();
  for (const row of [...(primary.byType || []), ...(sensor.byType || [])]) {
    const type = row.type || 'Unknown';
    byType.set(type, (byType.get(type) || 0) + Number(row.count || 0));
  }
  const severities = { ...(primary.bySeverity || {}) };
  for (const [key, value] of Object.entries(sensor.bySeverity || {})) {
    severities[key] = Number(severities[key] || 0) + Number(value || 0);
  }
  const topIps = new Map();
  for (const row of [...(primary.topIPs || []), ...(sensor.topIPs || [])]) {
    if (row.ip) topIps.set(row.ip, (topIps.get(row.ip) || 0) + Number(row.count || 0));
  }
  return {
    total: Number(primary.total || 0) + Number(sensor.total || 0),
    requests: Number(primary.requests || 0) + Number(sensor.requests || 0),
    blocked: Number(primary.blocked || 0) + Number(sensor.blocked || 0),
    byType: [...byType].map(([type, count]) => ({ type, count })).sort((a, b) => b.count - a.count),
    bySeverity: severities,
    topIPs: [...topIps].map(([ip, count]) => ({ ip, count })).sort((a, b) => b.count - a.count).slice(0, 10),
    traffic: [...(primary.traffic || []), ...(sensor.traffic || [])],
  };
}

// Fallback: pull WAF-like data from the main IDS Alert collection
async function _getFallbackFromAlerts(companyId, hours = 24) {
  const cacheKey = `${String(companyId || '')}:${hours}`;
  const cached = wafFallbackCache.get(cacheKey);
  if (cached?.value && cached.expiresAt > Date.now()) return cached.value;
  if (cached?.promise) return cached.promise;

  const promise = _queryFallbackFromAlerts(companyId, hours);
  wafFallbackCache.set(cacheKey, { promise });
  try {
    const value = await promise;
    wafFallbackCache.set(cacheKey, {
      value,
      expiresAt: Date.now() + WAF_FALLBACK_CACHE_MS,
    });
    return value;
  } catch (err) {
    wafFallbackCache.delete(cacheKey);
    throw err;
  }
}

async function _queryFallbackFromAlerts(companyId, hours = 24) {
  try {
    const mongoose = require('mongoose');
    const Alert = mongoose.models.Alert || require('../models/Alert.model');

    let cid;
    try { cid = new mongoose.Types.ObjectId(companyId); }
    catch { return { total: 0, stats: _emptyStats(), recentAttacks: [], agents: [] }; }

    const since = new Date(Date.now() - hours * 3600 * 1000);
    const base = { companyId: cid, createdAt: { $gte: since } };

    // Pull only WAF/web-layer detections as fallback. Routine IDS network
    // summaries do not belong in the WAF dashboard.
    const webAttackPattern = /(web[_ -]?(server|client|application)|http attack|sql.?injection|xss|cross.?site|command injection|path traversal|directory traversal|rfi|lfi|xxe|ssrf|log4j|web shell)/i;
    const wafFilter = {
      ...base,
      $or: [
        { source: 'waf', ruleId: { $ne: 'WAF_AGENT_STATUS' } },
        {
          source: 'suricata',
          eventCategory: 'ids_alert',
          $or: [
            { attackType: { $regex: webAttackPattern } },
            { signatureName: { $regex: webAttackPattern } },
            { description: { $regex: webAttackPattern } },
          ],
        },
        {
          ruleId: 'IPS_AUTO_BLOCK',
          blocked: true,
          $or: [
            { attackType: { $regex: webAttackPattern } },
            { description: { $regex: webAttackPattern } },
            { 'rawEvent.attackType': { $regex: webAttackPattern } },
          ],
        },
      ],
    };

    const [alerts, aggResult] = await Promise.all([
      Alert.find(wafFilter).sort({ createdAt: -1 }).limit(50)
        .select('source severity description srcip destip destPort createdAt blocked attackType signatureName type agentName ruleId eventCategory rawEvent')
        .maxTimeMS(8000).lean(),
      Alert.aggregate([
        { $match: wafFilter },
        {
          $facet: {
            total: [{ $count: 'c' }],
            blocked: [
              { $match: { blocked: true } },
              { $count: 'c' },
            ],
            byType: [
              { $group: { _id: { $ifNull: ['$attackType', '$eventCategory'] }, count: { $sum: 1 } } },
              { $sort: { count: -1 } }, { $limit: 8 },
            ],
            bySeverity: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
            topIPs: [
              { $match: { srcip: { $exists: true, $ne: null } } },
              { $group: { _id: '$srcip', count: { $sum: 1 } } },
              { $sort: { count: -1 } }, { $limit: 10 },
            ],
            traffic: [
              { $group: { _id: { $hour: '$createdAt' }, requests: { $sum: 1 } } },
              { $sort: { '_id': 1 } },
            ],
          },
        },
      ]).option({ maxTimeMS: 8000 }),
    ]);

    const agg = aggResult[0] || {};
    const total = agg.total?.[0]?.c || 0;
    const blocked = agg.blocked?.[0]?.c || 0;

    // Map IDS alerts to WAF event shape
    const recentAttacks = alerts.map(a => ({
      _id: a._id,
      company: companyId,
      systemId: a.agentName || 'ids-sensor',
      hostname: a.agentName || '',
      ip: a.srcip || '—',
      attackType: a.attackType || a.eventCategory || a.description?.slice(0, 40) || 'Security Alert',
      severity: a.severity || 'medium',
      ruleId: a.ruleId || `IDS_${(a.type || 'ALERT').toUpperCase()}`,
      requestPath: a.rawEvent?.requestPath || a.rawEvent?.http?.url || (a.destip ? `→ ${a.destip}${a.destPort ? `:${a.destPort}` : ''}` : '/'),
      method: a.rawEvent?.method || a.rawEvent?.http?.http_method || 'DETECT',
      blocked: a.blocked || false,
      source: a.source,
      provider: a.ruleId === 'IPS_AUTO_BLOCK'
        ? 'AJNAT WAF Direct'
        : a.source === 'suricata' ? 'Suricata' : 'AJNAT WAF',
      ts: a.createdAt,
    }));

    const stats = {
      total,
      byType: (agg.byType || []).map(r => ({ type: r._id || 'Unknown', count: r.count })),
      bySeverity: Object.fromEntries((agg.bySeverity || []).map(r => [r._id, r.count])),
      topIPs: (agg.topIPs || []).map(r => ({ ip: r._id, count: r.count })),
      traffic: (agg.traffic || []).map(r => ({ hour: r._id, requests: r.requests })),
      blocked,
      requests: total,
    };

    return { total, stats, recentAttacks, agents: [] };
  } catch (err) {
    console.error('[WAF/fallback] Error:', err.message);
    return { total: 0, stats: _emptyStats(), recentAttacks: [], agents: [] };
  }
}

async function _getRecentAttacks(db, limit, company, windowMs = 24 * 3600 * 1000) {
  try {
    const filter = {
      ...companyQuery(company),
      ts: { $gte: new Date(Date.now() - windowMs) },
    };
    return await db.collection('waf_events')
      .find(filter).sort({ ts: -1 }).limit(limit).toArray();
  } catch { return []; }
}

async function _getWAFStats(db, windowMs, company) {
  try {
    const since = new Date(Date.now() - windowMs);
    const match = { ts: { $gte: since }, ...companyQuery(company) };
    const [result] = await db.collection('waf_events').aggregate([
      { $match: match },
      {
        $facet: {
          total: [{ $count: 'c' }],
          blocked: [
            { $match: { blocked: { $ne: false } } },
            { $count: 'c' },
          ],
          byType: [
            { $group: { _id: '$attackType', count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 10 },
          ],
          bySeverity: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
          topIPs: [
            { $group: { _id: '$ip', count: { $sum: 1 } } },
            { $sort: { count: -1 } }, { $limit: 10 },
          ],
          traffic: [
            {
              $group: {
                _id: { $hour: '$ts' },
                requests: { $sum: 1 },
              }
            },
            { $sort: { '_id': 1 } },
          ],
        }
      },
    ]).toArray();

    return {
      total: result?.total?.[0]?.c || 0,
      blocked: result?.blocked?.[0]?.c || 0,
      byType: (result?.byType || []).map(r => ({ type: r._id, count: r.count })),
      bySeverity: Object.fromEntries((result?.bySeverity || []).map(r => [r._id, r.count])),
      topIPs: (result?.topIPs || []).map(r => ({ ip: r._id, count: r.count })),
      traffic: (result?.traffic || []).map(r => ({ hour: r._id, requests: r.requests })),
      requests: result?.total?.[0]?.c || 0,
    };
  } catch { return _emptyStats(); }
}

function _emptyStats() {
  return { total: 0, blocked: 0, byType: [], topIPs: [], bySeverity: {}, traffic: [], requests: 0 };
}

// ── Localhost port scanner (same logic as IPS server wafController) ─────────
function _getLocalhostLivePorts() {
  return new Promise((resolve) => {
    const { exec } = require('child_process');
    const SKIP = new Set([
      22, 23, 25, 53, 69, 110, 111, 143, 161, 162, 389, 443, 445, 465, 514, 587,
      993, 995, 1433, 1521, 3306, 3389, 5432, 5672, 6379, 27017, 27018,
    ]);
    const parse = (stdout) => {
      const ports = new Set();
      for (const line of stdout.split('\n')) {
        for (const part of line.split(/\s+/)) {
          if (!part.includes(':')) continue;
          const p = parseInt(part.split(':').pop(), 10);
          if (!isNaN(p) && p >= 79 && p < 10000 && !SKIP.has(p)) ports.add(p);
        }
      }
      return [...ports].sort((a, b) => a - b);
    };
    exec('ss -tlnH 2>/dev/null', { timeout: 3000 }, (err, out) => {
      if (!err && out) {
        const ports = parse(out);
        if (ports.length > 0) return resolve(ports);
      }
      exec('netstat -tlnp 2>/dev/null', { timeout: 3000 }, (err2, out2) => {
        const ports = err2 ? [] : parse(out2 || '');
        resolve(ports);
      });
    });
  });
}

function _getRealIP() {
  try {
    const os = require('os');
    const ifaces = os.networkInterfaces();
    for (const name of Object.keys(ifaces)) {
      if (name.toLowerCase().startsWith('lo')) continue;
      for (const iface of ifaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) return iface.address;
      }
    }
  } catch { }
  return '127.0.0.1';
}

router.ensureIndexes = ensureWafIndexes;
module.exports = router;
