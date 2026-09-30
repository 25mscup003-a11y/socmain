/**
 * logs.routes.js
 * Centralized log ingestion from ALL sources:
 *   - Syslog (Linux/macOS/network devices)
 *   - Windows Event Log (via agent)
 *   - Apache / Nginx web server logs
 *   - Database logs (MongoDB, MySQL, PostgreSQL)
 *   - Application logs (Node.js, custom)
 *   - Cloud logs (AWS CloudTrail, Azure, generic)
 *   - Payment logs (Razorpay events)
 *   - CEF / LEEF format (SIEM-standard)
 *   - Generic JSON
 *
 * POST /api/logs/ingest          — single log
 * POST /api/logs/batch           — batch of logs (up to 500)
 * POST /api/logs/syslog          — syslog RFC5424
 * POST /api/logs/webserver       — Apache/Nginx combined log format
 * POST /api/logs/db              — database audit log
 * POST /api/logs/cloud           — cloud provider logs
 * GET  /api/logs                 — paginated log search (auth)
 * GET  /api/logs/stats           — log statistics (auth)
 * GET  /api/logs/stream          — SSE stream of recent logs (auth)
 */
const router = require('express').Router();
const Log    = require('../models/Log.model');
const Alert  = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { autoScanSiemLog } = require('../services/velociraptor.service');
const { resolveScope, scopeForUser, assertUserScope } = require('../utils/tenantScope');
const { getCompanyIngestionStatus, sendIngestionBlocked } = require('../utils/agentEntitlement');
const { boundedInteger, escapeRegex, enforceBatchLimit } = require('../utils/requestLimits');
const { verifyCompanyIntegrationKey } = require('../security/integrationAuthorization');

// Company-bound integration credential, agent key, or user JWT.
async function logAuth(req, res, next) {
  try {
    const bearer = req.headers.authorization;
    if (bearer?.startsWith('Bearer ')) return authenticate(req, res, next);

    const requestedCompanyId = req.headers['x-company-id']
      || req.body?.companyId || req.body?.company_id || req.query.companyId;
    const companyKey = req.headers['x-company-integration-key'];
    if (verifyCompanyIntegrationKey(requestedCompanyId, companyKey, process.env.INTEGRATION_KEY_SECRET)) {
      req.user = { role: 'integration', companyId: requestedCompanyId };
      return next();
    }

    const first = Array.isArray(req.body?.logs) ? req.body.logs[0] : req.body;
    const agentKey = first?.agentKey || first?.agent_key;
    if (agentKey) {
      const system = await resolveSystem(agentKey, requestedCompanyId);
      if (system) {
        req.user = { role: 'integration', companyId: system.companyId };
        return next();
      }
    }

    const legacySecret = req.headers['x-integration-secret'];
    if (process.env.ALLOW_LEGACY_GLOBAL_INTEGRATION_SECRET === 'true'
        && legacySecret && legacySecret === process.env.INTEGRATION_SECRET) {
      req.user = { role: 'superadmin' };
      return next();
    }
    return res.status(401).json({ message: 'Valid company integration key, agent key, or token required' });
  } catch {
    return res.status(401).json({ message: 'Integration authentication failed' });
  }
}

// ── Helpers ────────────────────────────────────────────────────────────────────
function syslogSeverity(pri) {
  // RFC5424: severity 0-7
  if (pri === undefined) return 'info';
  const s = pri % 8;
  return ['critical','critical','critical','error','warning','info','info','debug'][s] || 'info';
}

function parseApacheLog(line) {
  // Combined Log Format: 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326 ...
  const m = line.match(/^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) (\d+)/);
  if (!m) return null;
  return {
    clientIp: m[1], user: m[2], time: m[3],
    method: m[4], path: m[5], status: parseInt(m[6]), bytes: parseInt(m[7]),
    isError: parseInt(m[6]) >= 400,
  };
}

function classifyWebLog(parsed) {
  if (!parsed) return 'info';
  if (parsed.status >= 500) return 'error';
  if (parsed.status >= 400) return 'warning';
  return 'info';
}

async function resolveSystem(agentKey, companyId) {
  if (!agentKey) return null;
  const filter = companyId ? { agentKey, companyId } : { agentKey };
  return System.findOne(filter).select('_id companyId departmentId').lean();
}

function scheduleVelociraptorAutoScan(req, logOrLogs) {
  const logs = Array.isArray(logOrLogs) ? logOrLogs : [logOrLogs];
  const io = req.app.get('io');

  for (const log of logs.filter(Boolean)) {
    setImmediate(() => {
      autoScanSiemLog(log, { io }).catch((err) => {
        console.error('[velociraptor/siem-auto-scan]', err.message);
      });
    });
  }
}

function normalizeAuthResult(value) {
  if (value === true) return 'Pass';
  if (value === false) return 'Fail';
  const text = String(value || '').trim().toLowerCase();
  if (/^(pass|passed|success|successful|allow|allowed|approved|authenticated|verified|ok|200|201|204|true)$/.test(text)) return 'Pass';
  if (/^(fail|failed|deny|denied|blocked|rejected|invalid|lockout|locked|error|401|403|false)$/.test(text)) return 'Fail';
  return value ? String(value) : 'Not Captured';
}

function normalizeAuthProviderEvent(body = {}) {
  const fields = body.fields || body.data || body;
  const provider = fields.provider || body.provider || fields.source_provider || 'auth-provider';
  const website = fields.website || fields.domain || fields.site || fields.url || fields.endpoint || fields.api || body.website || body.domain || body.endpoint || '';
  const username = fields.username || fields.user || fields.account || fields.email || body.username || body.user || '';
  const srcIp = fields.source_ip || fields.src_ip || fields.client_ip || fields.clientIp || fields.ip || body.source_ip || body.src_ip || body.ip || '';
  const loginResult = normalizeAuthResult(fields.login_result || fields.loginResult || fields.auth_result || fields.authResult || fields.result || fields.status || fields.success || fields.ok || body.login_result || body.status || body.success);
  const mfaResult = normalizeAuthResult(fields.mfa_result || fields.mfaResult || fields.mfa_status || fields.mfaStatus || fields.mfa_success || fields.mfaSuccess || fields.mfa_ok || fields.mfaOk || body.mfa_result || body.mfa_success);
  const action = fields.auth_action || fields.action || fields.event_type || body.action || 'provider_auth_event';
  return {
    provider,
    website,
    username,
    srcIp,
    loginResult,
    mfaResult,
    action,
    fields: {
      ...fields,
      provider,
      website,
      username,
      source_ip: srcIp,
      login_result: loginResult,
      mfa_result: mfaResult,
      auth_action: action,
      log_type: 'authentication',
    },
  };
}

// ── POST /api/logs/auth-provider — Okta/Duo/Entra/HackerOne/app auth result logs
router.post('/auth-provider', logAuth, async (req, res) => {
  try {
    const payload = Array.isArray(req.body?.events) ? req.body.events : Array.isArray(req.body) ? req.body : [req.body];
    if (!payload.length) return res.status(400).json({ message: 'At least one auth event is required' });
    const batchCheck = enforceBatchLimit(payload, 500, 'events');
    if (!batchCheck.ok) return res.status(batchCheck.status).json({ message: batchCheck.message });
    const limited = payload;
    const docs = [];
    for (const item of limited) {
      const companyId = item.companyId || item.company_id || req.body.companyId || req.query.companyId;
      const agentKey = item.agentKey || item.agent_key || req.body.agentKey || req.body.agent_key;
      if (!companyId && !agentKey) return res.status(400).json({ message: 'companyId or agentKey required' });
      const sys = await resolveSystem(agentKey, companyId);
      const scope = await resolveScope({
        system: sys,
        companyId,
        body: item,
        requireSystem: Boolean(agentKey),
      });
      assertUserScope(req.user, scope);
      const ingestionStatus = await getCompanyIngestionStatus(scope.companyId);
      if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);
      const normalized = normalizeAuthProviderEvent(item);
      const now = new Date();
      docs.push({
        tenantId: scope.tenantId,
        partnerId: scope.partnerId,
        companyId: scope.companyId,
        departmentId: scope.departmentId,
        systemId: scope.systemId,
        source: String(normalized.provider || 'auth-provider').toLowerCase(),
        agentKey,
        agentName: item.agentName || item.hostname || normalized.provider,
        hostname: item.hostname || item.host,
        ipAddress: normalized.srcIp,
        logType: 'auth',
        level: normalized.loginResult === 'Fail' || normalized.mfaResult === 'Fail' ? 'warning' : 'info',
        message: `${normalized.provider} ${normalized.action} user=${normalized.username || '-'} website=${normalized.website || '-'} login=${normalized.loginResult} mfa=${normalized.mfaResult}`,
        program: normalized.provider,
        logTime: item.timestamp ? new Date(item.timestamp) : now,
        receivedAt: item.receivedAt ? new Date(item.receivedAt) : now,
        fields: normalized.fields,
        raw: JSON.stringify(item),
        format: 'json',
        tags: ['auth-provider', 'web-auth', normalized.provider].filter(Boolean),
      });
    }
    const result = await Log.insertMany(docs, { ordered: false });
    scheduleVelociraptorAutoScan(req, result);
    const io = req.app.get('io');
    if (io) {
      for (const doc of result) {
        io.to(`company:${doc.companyId}`).emit('log:new', doc);
      }
    }
    res.status(201).json({ ok: true, created: result.length });
  } catch (err) {
    console.error('[logs/auth-provider]', err.message);
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/ingest — single log ────────────────────────────────────────
router.post('/ingest', logAuth, async (req, res) => {
  try {
    const body = req.body;
    const requestedCompanyId = body.companyId || body.company_id || req.query.companyId;
    const agentKey = body.agentKey || body.agent_key;
    if (!requestedCompanyId && !agentKey) return res.status(400).json({ message: 'companyId or agentKey required' });

    const sys = await resolveSystem(agentKey, requestedCompanyId);
    const scope = await resolveScope({
      system: sys,
      companyId: requestedCompanyId,
      body,
      requireSystem: Boolean(agentKey),
    });
    assertUserScope(req.user, scope);
    const ingestionStatus = await getCompanyIngestionStatus(scope.companyId);
    if (!ingestionStatus.allowed) return sendIngestionBlocked(res, ingestionStatus);

    const now = new Date();
    const doc = {
      tenantId: scope.tenantId,
      partnerId: scope.partnerId,
      companyId: scope.companyId,
      departmentId: scope.departmentId,
      systemId:     scope.systemId,
      source:   body.source   || 'custom',
      agentKey: body.agentKey || body.agent_key,
      agentName:body.agentName|| body.hostname || body.host,
      hostname: body.hostname || body.host,
      ipAddress:body.ip       || body.ipAddress,
      logType:  body.logType  || body.log_type  || 'system',
      level:    body.level    || body.severity  || 'info',
      message:  body.message  || body.msg       || JSON.stringify(body),
      facility: body.facility,
      program:  body.program  || body.process,
      pid:      body.pid,
      logTime:  body.timestamp ? new Date(body.timestamp) : now,
      receivedAt: body.receivedAt ? new Date(body.receivedAt) : now,
      fields:   body.fields   || body.data,
      raw:      body.raw      || JSON.stringify(body),
      format:   body.format   || 'json',
      tags:     body.tags     || [],
    };

    const log = await Log.create(doc);
    scheduleVelociraptorAutoScan(req, log);

    // Emit to socket
    const io = req.app.get('io');
    if (io) {
      console.log('[logs/ingest] Emitting log:new to company room:', scope.companyId, 'msg:', doc.message);
      io.to(`company:${scope.companyId}`).emit('log:new', { ...doc, _id: log._id });
    }

    res.status(201).json({ ok: true, id: log._id });
  } catch (err) {
    console.error('[logs/ingest]', err.message);
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/batch — up to 500 logs ────────────────────────────────────
router.post('/batch', logAuth, async (req, res) => {
  try {
    const { logs = [], companyId } = req.body;
    const batchAgentKey = logs[0]?.agentKey || logs[0]?.agent_key;
    if (!companyId && !batchAgentKey) return res.status(400).json({ message: 'companyId or agentKey required' });
    if (!logs.length) return res.json({ ok: true, created: 0 });
    const batchCheck = enforceBatchLimit(logs, 500, 'logs');
    if (!batchCheck.ok) return res.status(batchCheck.status).json({ message: batchCheck.message });

    const limited = logs;
    const now = new Date();
    const batchSystem = await resolveSystem(batchAgentKey, companyId);
    const batchScope = await resolveScope({
      system: batchSystem,
      companyId,
      body: logs[0] || {},
      requireSystem: Boolean(batchAgentKey),
    });
    assertUserScope(req.user, batchScope);
    const batchIngestionStatus = await getCompanyIngestionStatus(batchScope.companyId);
    if (!batchIngestionStatus.allowed) return sendIngestionBlocked(res, batchIngestionStatus);

    const docs = await Promise.all(limited.map(async b => {
      const itemAgentKey = b.agentKey || b.agent_key || batchAgentKey;
      const itemCompanyId = b.companyId || b.company_id || companyId;
      const itemSystem = itemAgentKey === batchAgentKey
        ? batchSystem
        : await resolveSystem(itemAgentKey, itemCompanyId);
      const scope = await resolveScope({
        system: itemSystem,
        companyId: itemCompanyId,
        body: b,
        requireSystem: Boolean(itemAgentKey),
      });
      assertUserScope(req.user, scope);
      return {
        tenantId: scope.tenantId,
        partnerId: scope.partnerId,
        companyId: scope.companyId,
        departmentId: scope.departmentId,
        systemId: scope.systemId,
        source: b.source || 'agent',
        agentKey: itemAgentKey,
        agentName: b.agentName || b.hostname,
        hostname: b.hostname || b.host,
        ipAddress: b.ip || b.ipAddress,
        logType: b.logType || b.log_type || 'system',
        level: b.level || 'info',
        message: b.message || b.msg || '',
        program: b.program,
        pid: b.pid,
        logTime: b.timestamp ? new Date(b.timestamp) : now,
        receivedAt: b.receivedAt ? new Date(b.receivedAt) : now,
        fields: b.fields,
        raw: b.raw,
        format: b.format || 'json',
        tags: b.tags || [],
      };
    }));

    const result = await Log.insertMany(docs, { ordered: false });
    scheduleVelociraptorAutoScan(req, result);
    res.status(201).json({ ok: true, created: result.length });
  } catch (err) {
    if (err.writeErrors) return res.status(207).json({ ok: true, created: err.insertedDocs?.length || 0 });
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/syslog — RFC5424/RFC3164 syslog over HTTP ──────────────────
router.post('/syslog', logAuth, async (req, res) => {
  try {
    const body      = req.body;
    const companyId = body.companyId || body.company_id || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const scope = await resolveScope({ companyId, body });
    assertUserScope(req.user, scope);

    // Accept pre-parsed or raw string
    const message  = body.message  || body.msg || body.raw || String(body);
    const priority = body.priority || body.pri || 14; // default: user.info

    const now = new Date();
    const doc = {
      tenantId: scope.tenantId,
      partnerId: scope.partnerId,
      companyId: scope.companyId,
      source:    'syslog',
      agentName: body.hostname || body.host,
      hostname:  body.hostname || body.host,
      ipAddress: body.fromhost_ip || body.ip,
      logType:   body.logType || 'system',
      level:     syslogSeverity(priority),
      message,
      facility:  body.facility   || String(Math.floor(priority / 8)),
      program:   body.programname|| body.program,
      pid:       body.procid     || body.pid,
      logTime:   body.timereported ? new Date(body.timereported) : now,
      receivedAt: now,
      raw:       body.rawmsg || message,
      format:    'syslog',
      tags:      ['syslog'],
    };

    const log = await Log.create(doc);
    scheduleVelociraptorAutoScan(req, log);
    res.status(201).json({ ok: true, id: log._id });
  } catch (err) {
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/webserver — Apache/Nginx access/error log ─────────────────
router.post('/webserver', logAuth, async (req, res) => {
  try {
    const body      = req.body;
    const companyId = body.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const scope = await resolveScope({ companyId, body });
    assertUserScope(req.user, scope);

    const lines  = body.lines || (body.line ? [body.line] : [body.message || '']);
    const batchCheck = enforceBatchLimit(lines, 200, 'lines');
    if (!batchCheck.ok) return res.status(batchCheck.status).json({ message: batchCheck.message });
    const server = body.server || body.serverType || 'nginx';
    const docs   = [];
    const now    = new Date();

    for (const line of lines) {
      const parsed = parseApacheLog(line);
      const level  = classifyWebLog(parsed);

      docs.push({
        tenantId: scope.tenantId,
        partnerId: scope.partnerId,
        companyId: scope.companyId,
        source:   server,
        agentName:body.host || server,
        hostname: body.host,
        ipAddress:body.host,
        logType:  'webserver',
        level,
        message:  line.length > 400 ? line.slice(0, 400) : line,
        logTime:  new Date(),
        receivedAt: now,
        fields:   parsed || {},
        raw:      line,
        format:   'combined',
        tags:     [server, level === 'error' ? 'error' : 'access'],
      });

      // Auto-raise alert for 4xx/5xx
      if (parsed?.status >= 400) {
        Alert.create({
          tenantId: scope.tenantId,
          partnerId: scope.partnerId,
          companyId: scope.companyId,
          source:       server,
          ruleId:       `HTTP_${parsed.status}`,
          description:  `HTTP ${parsed.status} — ${parsed.method} ${parsed.path} from ${parsed.clientIp}`,
          severity:     parsed.status >= 500 ? 'high' : 'medium',
          eventCategory:'network',
          srcip:        parsed.clientIp,
          type:         parsed.status >= 500 ? 'WEB_ERROR' : 'WEB_WARN',
          agentName:    body.host || server,
        }).catch(() => {});
      }
    }

    const result = await Log.insertMany(docs, { ordered: false });
    scheduleVelociraptorAutoScan(req, result);
    res.status(201).json({ ok: true, created: docs.length });
  } catch (err) {
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/db — Database audit log ────────────────────────────────────
router.post('/db', logAuth, async (req, res) => {
  try {
    const body      = req.body;
    const companyId = body.companyId || body.company_id || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const scope = await resolveScope({ companyId, body });
    assertUserScope(req.user, scope);

    const now = new Date();
    const dbType = body.dbType || body.db || 'mongodb';
    const action = (body.action || body.operation || '').toLowerCase();
    const isRisky = ['drop','delete','truncate','grant','revoke','shutdown'].includes(action);

    const doc = {
      tenantId: scope.tenantId,
      partnerId: scope.partnerId,
      companyId: scope.companyId,
      source:   `db:${dbType}`,
      agentName:body.host || dbType,
      hostname: body.host,
      ipAddress:body.clientIp || body.client_ip,
      logType:  'database',
      level:    isRisky ? 'warning' : 'info',
      message:  body.message || `${dbType} ${action || 'query'}: ${body.ns || body.table || ''}`,
      logTime:  body.timestamp ? new Date(body.timestamp) : now,
      receivedAt: now,
      fields:   { dbType, action, ns: body.ns, table: body.table, user: body.user, rows: body.rows },
      raw:      JSON.stringify(body),
      format:   'json',
      tags:     ['database', dbType, action],
    };

    const log = await Log.create(doc);
    scheduleVelociraptorAutoScan(req, log);

    if (isRisky) {
      Alert.create({
        tenantId: scope.tenantId,
        partnerId: scope.partnerId,
        companyId: scope.companyId,
        source:       `db:${dbType}`,
        ruleId:       `DB_RISKY_${action.toUpperCase()}`,
        description:  `⚠️ Risky DB operation: ${action.toUpperCase()} by ${body.user || 'unknown'} on ${body.ns || body.table}`,
        severity:     'high',
        eventCategory:'system',
        agentName:    body.host || dbType,
        type:         'DB_AUDIT',
      }).catch(() => {});
    }

    res.status(201).json({ ok: true, id: log._id });
  } catch (err) {
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── POST /api/logs/cloud — AWS CloudTrail / Azure / GCP ───────────────────────
router.post('/cloud', logAuth, async (req, res) => {
  try {
    const body      = req.body;
    const companyId = body.companyId || req.query.companyId;
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const scope = await resolveScope({ companyId, body });
    assertUserScope(req.user, scope);

    const provider = body.provider || 'cloud';
    const events   = Array.isArray(body.Records || body.events) ? (body.Records || body.events) : [body];
    const batchCheck = enforceBatchLimit(events, 100, 'events');
    if (!batchCheck.ok) return res.status(batchCheck.status).json({ message: batchCheck.message });
    const now = new Date();

    const docs = events.map(ev => {
      const eventName = ev.eventName || ev.operationName || ev.protoPayload?.methodName || 'CloudEvent';
      const isRisky   = /delete|terminate|stop|disable|revoke|detach|deregister/i.test(eventName);
      return {
        tenantId: scope.tenantId,
        partnerId: scope.partnerId,
        companyId: scope.companyId,
        source:    provider,
        agentName: provider,
        hostname:  provider,
        logType:   'cloud',
        level:     isRisky ? 'warning' : 'info',
        message:   `${provider} ${eventName} by ${ev.userIdentity?.userName || ev.caller || 'unknown'}`,
        logTime:   ev.eventTime ? new Date(ev.eventTime) : now,
        receivedAt: now,
        fields:    { provider, eventName, region: ev.awsRegion, user: ev.userIdentity?.userName },
        raw:       JSON.stringify(ev),
        format:    'json',
        tags:      ['cloud', provider, isRisky ? 'risky' : 'normal'],
      };
    });

    const result = await Log.insertMany(docs, { ordered: false });
    scheduleVelociraptorAutoScan(req, result);
    res.status(201).json({ ok: true, created: docs.length });
  } catch (err) {
    res.status(err.statusCode || 400).json({ message: err.message });
  }
});

// ── GET /api/logs — paginated search (authenticated) ─────────────────────────
router.get('/', authenticate, requireAnalyst, async (req, res) => {
  try {
    const { logType, level, source, from, to, search, fimModule } = req.query;
    const page = boundedInteger(req.query.page, { defaultValue: 1, max: 100000 });
    const limit = boundedInteger(req.query.limit, { defaultValue: 50, max: 200 });
    const filter = scopeForUser(req.user, { departmentScoped: true });

    if (logType) filter.logType = logType;
    if (level)   filter.level   = level;
    if (source)  filter.source  = { $regex: escapeRegex(source), $options: 'i' };
    if (logType === 'file' && fimModule) {
      const modulePattern = new RegExp(escapeRegex(fimModule).replace(/[-_]/g, '[-_ ]?'), 'i');
      filter.$or = [
        { 'fields.module_type': modulePattern },
        { 'fields.moduleType': modulePattern },
        { 'fields.fim_module': modulePattern },
        { 'fields.event_type': modulePattern },
        { 'fields.change_type': modulePattern },
        { message: modulePattern },
        { raw: modulePattern },
      ];
      if (/permission/i.test(fimModule)) filter.$or.push({ 'fields.permission_risk': { $exists: true, $ne: '' } }, { message: /permission|chmod|mode|acl|suid|sgid|world-writable/i }, { raw: /permission|chmod|mode|acl|suid|sgid|world-writable/i });
      if (/ownership/i.test(fimModule)) filter.$or.push({ message: /ownership|owner|group|chown|chgrp/i }, { raw: /ownership|owner|group|chown|chgrp/i });
      if (/ransom/i.test(fimModule)) filter.$or.push({ message: /ransom|encrypt|mass rename|shadow copy|backup deletion|bulk file deletion|locked|crypt/i }, { raw: /ransom|encrypt|mass rename|shadow copy|backup deletion|bulk file deletion|locked|crypt/i });
      if (/sensitive/i.test(fimModule)) filter.$or.push({ message: /passwd|shadow|authorized_keys|id_rsa|\.env|secret|token|\.pem|\.key|backup|source_code|usb|download|upload|copy/i }, { raw: /passwd|shadow|authorized_keys|id_rsa|\.env|secret|token|\.pem|\.key|backup|source_code|usb|download|upload|copy/i });
      if (/integrity|hash/i.test(fimModule)) filter.$or.push({ 'fields.old_hash': { $exists: true, $ne: '' } }, { 'fields.new_hash': { $exists: true, $ne: '' } }, { 'fields.file_hash': { $exists: true, $ne: '' } }, { message: /hash|integrity|baseline|checksum|mismatch/i }, { raw: /hash|integrity|baseline|checksum|mismatch/i });
    }
    if (from || to) {
      filter.receivedAt = {};
      if (from) filter.receivedAt.$gte = new Date(from);
      if (to)   filter.receivedAt.$lte = new Date(to);
    }
    if (search) filter.$text = { $search: search };
    if (req.query.companyId && req.user.role === 'partner_admin') filter.companyId = req.query.companyId;
    if (req.query.companyId && req.user.role === 'superadmin') filter.companyId = req.query.companyId;

    const [logs, total] = await Promise.all([
      Log.find(filter)
        .sort({ receivedAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .select(logType === 'file' ? 'source agentKey agentName hostname ipAddress logType level message facility program pid logTime receivedAt fields raw format tags createdAt updatedAt' : '-raw -fields')
        .lean(),
      Log.countDocuments(filter),
    ]);

    res.json({ logs, total, page, limit });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/logs/stats ───────────────────────────────────────────────────────
router.get('/stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const since  = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const filter = { ...scopeForUser(req.user, { departmentScoped: true }), receivedAt: { $gte: since } };
    if (req.query.companyId && req.user.role === 'partner_admin') filter.companyId = req.query.companyId;
    if (req.query.companyId && req.user.role === 'superadmin') filter.companyId = req.query.companyId;

    const [total, bySource, byType, byLevel, perHour] = await Promise.all([
      Log.countDocuments(filter),
      Log.aggregate([{ $match: filter }, { $group: { _id: '$source', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }]),
      Log.aggregate([{ $match: filter }, { $group: { _id: '$logType', count: { $sum: 1 } } }, { $sort: { count: -1 } }]),
      Log.aggregate([{ $match: filter }, { $group: { _id: '$level',   count: { $sum: 1 } } }]),
      Log.aggregate([
        { $match: filter },
        { $group: { _id: { $hour: '$receivedAt' }, count: { $sum: 1 } } },
        { $sort: { _id: 1 } },
      ]),
    ]);

    res.json({ total, bySource, byType, byLevel, perHour, period: '24h' });
  } catch (err) {
    console.error('[logs/stats] Error:', err.message, err.stack);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/logs/stream — SSE real-time log stream ──────────────────────────
router.get('/stream', authenticate, requireAnalyst, (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  // Join socket room and forward to SSE
  const io  = req.app.get('io');
  const cid = req.user.companyId?.toString();
  if (!cid && req.user.role !== 'partner_admin') {
    res.write(`data: ${JSON.stringify({ error: 'company scope required' })}\n\n`);
    return res.end();
  }

  // Heartbeat every 30s
  const hb = setInterval(() => res.write(': ping\n\n'), 30000);

  // Listen to socket events and send to SSE
  const handler = (log) => send(log);
  if (io && cid) io.on(`company:${cid}:log`, handler);

  req.on('close', () => {
    clearInterval(hb);
    if (io && cid) io.off(`company:${cid}:log`, handler);
  });
});

// ── POST /api/logs/seed — populate test logs (for development) ────────────────
router.post('/seed', authenticate, requireAnalyst, async (req, res) => {
  try {
    const companyId = req.user.companyId || req.body.companyId;
    const count = parseInt(req.body.count) || 50;
    const force = req.body.force === true;

    if (!companyId) {
      return res.status(400).json({ message: 'companyId required' });
    }

    // Check if data already exists
    let existing = await Log.countDocuments({ companyId });
    if (existing > 0 && !force) {
      return res.json({
        ok: true,
        message: `Already have ${existing} logs for this company. Skipping seed.`,
        skipped: existing,
      });
    }

    // If force, delete existing data
    if (force && existing > 0) {
      await Log.deleteMany({ companyId });
      console.log(`[logs/seed] Deleted ${existing} existing logs for force-seed`);
    }

    const seedLogs = [];
    const logTypes = ['system', 'auth', 'network', 'file', 'usb', 'webserver', 'database', 'cloud', 'ids', 'edr', 'firewall'];
    const sources = ['web-server', 'firewall', 'ids', 'antivirus', 'edr', 'syslog', 'sysmon', 'agent', 'suricata', 'nginx', 'apache'];
    const levels = ['critical', 'error', 'warning', 'info', 'debug'];
    const messages = [
      'Connection attempt from suspicious IP',
      'File system activity detected',
      'Authentication attempt failed',
      'Suspicious process execution detected',
      'USB device connected',
      'Web server error 500 detected',
      'Database query executed',
      'Network traffic anomaly detected',
      'File integrity check failed',
      'User privilege escalation attempt',
      'API request rate limit exceeded',
      'Certificate validation failure',
      'Malware signature matched',
      'Port scan detected',
      'Data exfiltration risk',
      'Configuration change detected',
      'Service restart detected',
      'Memory corruption attempt',
      'Buffer overflow detected',
      'Ransomware activity detected',
    ];

    for (let i = 0; i < count; i++) {
      const now = new Date();
      const randomHours = Math.floor(Math.random() * 24);
      const randomMinutes = Math.floor(Math.random() * 60);

      seedLogs.push({
        companyId,
        source: sources[i % sources.length],
        agentName: `Agent-${Math.floor(i / 5) + 1}`,
        hostname: `host-${Math.floor(i / 5) + 1}.local`,
        ipAddress: `192.168.1.${100 + (i % 155)}`,
        logType: logTypes[i % logTypes.length],
        level: levels[i % levels.length],
        message: messages[i % messages.length],
        facility: 'user',
        program: `app${(i % 5) + 1}`,
        pid: 1000 + i,
        logTime: new Date(now.getTime() - (randomHours * 60 + randomMinutes) * 60000),
        fields: { index: i },
        raw: `Log entry ${i}`,
        format: 'json',
        tags: [logTypes[i % logTypes.length], levels[i % levels.length]],
        receivedAt: new Date(now.getTime() - (randomHours * 60 + randomMinutes) * 60000),
      });
    }

    const created = await Log.insertMany(seedLogs);
    res.status(201).json({
      ok: true,
      created: created.length,
      message: `Generated ${created.length} test logs for demo/development`,
    });
  } catch (err) {
    console.error('[logs] seed error:', err);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
