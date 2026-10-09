/**
 * IPS Proxy Routes — SOC4 Backend
 * ================================
 * Proxies IPS Webhook server requests through the main backend.
 * This gives Company Admin and Superadmin dashboards access to
 * IPS data without hitting the IPS server directly.
 *
 * All requests are authenticated and company-scoped.
 *
 * Base path: /api/ips-proxy
 */

const router = require('express').Router();
const http   = require('http');
const https  = require('https');
const axios  = require('axios');
const { authenticate, requireAnalyst, requireSuperAdmin, requireManager } = require('../middleware/auth.middleware');
const System = require('../models/System.model');
const IpsWhitelist = require('../models/IpsWhitelist.model');
const IpsService = require('../services/ips.service');

const IPS_URL    = process.env.IPS_WEBHOOK_URL    || 'http://localhost:5050';
const IPS_SECRET = process.env.IPS_WEBHOOK_SECRET || '';
const IPS_PROXY_GET_TIMEOUT_MS = Number(process.env.IPS_PROXY_GET_TIMEOUT_MS || 2000);
const IPS_PROXY_CACHE_MS = Number(process.env.IPS_PROXY_CACHE_MS || 15000);
const IPS_PROXY_CIRCUIT_MS = Number(process.env.IPS_PROXY_CIRCUIT_MS || 30000);
const DEBUG_IPS_PROXY = process.env.DEBUG_IPS_PROXY === 'true';
const ipsReadCache = new Map();
const ipsReadInflight = new Map();
const ipsGetCircuit = { unavailableUntil: 0, lastWarningAt: 0 };

async function cachedIpsRead(key, loader) {
  const now = Date.now();
  const cached = ipsReadCache.get(key);
  if (cached && cached.expiresAt > now) return { ...cached.value, cached: true };
  if (ipsReadInflight.has(key)) return ipsReadInflight.get(key);
  const run = Promise.resolve()
    .then(loader)
    .then(value => {
      ipsReadCache.set(key, { value, expiresAt: Date.now() + IPS_PROXY_CACHE_MS });
      return value;
    })
    .finally(() => ipsReadInflight.delete(key));
  ipsReadInflight.set(key, run);
  return run;
}

// ── Proxy helper ──────────────────────────────────────────────────────────────
function proxyRequest(req, res, ipsPath, options = {}) {
  return new Promise((resolve, reject) => {
    let finished = false;

    const parsed   = new URL(IPS_URL + ipsPath);
    const protocol = parsed.protocol === 'https:' ? https : http;

    const proxyHeaders = {
      'Content-Type': 'application/json',
      // Send BOTH headers for compatibility:
      //   X-Company-ID = canonical header checked first by IPS auth middleware
      //   X-Company    = legacy header (backward compat)
      ...(options.companyId && {
        'X-Company-ID': options.companyId.toString(),
        'X-Company':    options.companyId.toString(),
      }),
      ...(IPS_SECRET && { 'X-Webhook-Secret': IPS_SECRET }),
    };

    const body = options.body ? JSON.stringify(options.body) : null;
    if (body) proxyHeaders['Content-Length'] = Buffer.byteLength(body);

    const reqOpts = {
      hostname: parsed.hostname,
      port:     parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path:     parsed.pathname + (parsed.search || ''),
      method:   options.method || 'GET',
      headers:  proxyHeaders,
    };

    const proxyReq = protocol.request(reqOpts, (proxyRes) => {
      let data = '';
      proxyRes.on('data', chunk => { data += chunk; });
      proxyRes.on('end', () => {
        if (finished) return;
        finished = true;
        try {
          const json = JSON.parse(data);
          // Log 4xx/5xx from IPS server so issues are visible
          if (proxyRes.statusCode >= 400) {
            console.error(`[IPS-Proxy] IPS returned ${proxyRes.statusCode} for ${options.method || 'GET'} ${ipsPath}:`, JSON.stringify(json));
          }
          res.status(proxyRes.statusCode).json(json);
          resolve();
        } catch {
          res.status(proxyRes.statusCode).send(data);
          resolve();
        }
      });
    });

    proxyReq.on('error', (err) => {
      if (finished) return;
      console.error('[IPS-Proxy] Connection error:', err.message);
      // Never retry dashboard reads in the request path: an unavailable IPS
      // server otherwise turns every poll into two long-lived sockets.
      if (options.retry === true && !options._retried) {
        finished = true;
        console.warn('[IPS-Proxy] Retrying in 500ms...');
        setTimeout(() => {
          proxyRequest(req, res, ipsPath, { ...options, _retried: true })
            .then(resolve).catch(resolve);
        }, 500);
        return;
      }
      finished = true;
      res.status(502).json({ message: `IPS server unavailable: ${err.message}` });
      resolve();
    });

    proxyReq.setTimeout(options.timeoutMs || (options.method === 'GET' ? IPS_PROXY_GET_TIMEOUT_MS : 8000), () => {
      if (finished) return;
      console.warn('[IPS-Proxy] Timeout — destroying socket...');
      finished = true;
      proxyReq.destroy();
      // Writes may opt in to a retry; polling GET requests must fail fast.
      if (options.retry === true && !options._retried) {
        console.warn('[IPS-Proxy] Retrying in 500ms...');
        setTimeout(() => {
          proxyRequest(req, res, ipsPath, { ...options, _retried: true })
            .then(resolve).catch(resolve);
        }, 500);
        return;
      }
      res.status(504).json({ message: 'IPS server timeout' });
      resolve();
    });

    if (body) proxyReq.write(body);
    proxyReq.end();
  });
}

// ── Auth: Check for integration secret OR JWT ─────────────────────────────────
function anyAuth(req, res, next) {
  const secret = req.headers['x-integration-secret'];
  if (secret && secret === process.env.INTEGRATION_SECRET) {
    // Decode JWT if present to extract companyId context
    let companyId = '';
    const authHeader = req.headers['authorization'];
    if (authHeader && authHeader.startsWith('Bearer ')) {
      try {
        const token = authHeader.split(' ')[1];
        const decoded = require('jsonwebtoken').decode(token);
        if (decoded) {
          companyId = decoded.companyId || decoded.company || decoded.company_id || '';
        }
      } catch (e) {
        console.error('[anyAuth] JWT decode error:', e.message);
      }
    }
    // Valid integration secret - set minimal user object (with superadmin role so it can access all companies)
    req.user = { role: 'superadmin', isSuperAdmin: true, companyId };
    req.integrationAuth = true;  // Flag this as integration auth
    return next();
  }
  // Fall back to JWT auth
  authenticate(req, res, (err) => {
    if (err) return res.status(401).json({ message: 'No token provided' });
    requireAnalyst(req, res, next);
  });
}

// Apply custom auth to all routes
router.use(anyAuth);

// Helper to resolve companyId (superadmin can see all, others scoped to own)
function resolveCompanyId(req) {
  if (req.user.role === 'superadmin') {
    // Check query param first, then request body, then fall back to token-level companyId, then empty
    return req.query.companyId || req.body?.companyId || req.user.companyId?.toString() || '';
  }
  return req.user.companyId?.toString() || '';
}

async function callIpsWebhook(companyId, body) {
  const webhookUrl = `${IPS_URL.replace(/\/+$/, '')}/webhook`;
  const response = await axios.post(webhookUrl, body, {
    headers: {
      'Content-Type': 'application/json',
      'X-Company-ID': String(companyId),
      'X-Company': String(companyId),
      ...(IPS_SECRET && { 'X-Webhook-Secret': IPS_SECRET }),
    },
    timeout: 8000,
    validateStatus: () => true,
  });
  if (response.status < 200 || response.status >= 300 || response.data?.success === false) {
    const message = response.data?.message || response.data?.error || `IPS server returned HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status >= 400 ? response.status : 502;
    throw error;
  }
  return response.data;
}

async function callIpsMutation(method, companyId, path, body = undefined) {
  const response = await axios({
    method,
    url: `${IPS_URL.replace(/\/+$/, '')}${path}`,
    data: body,
    headers: {
      'Content-Type': 'application/json',
      'X-Company-ID': String(companyId),
      'X-Company': String(companyId),
      ...(IPS_SECRET && { 'X-Webhook-Secret': IPS_SECRET }),
    },
    timeout: 8000,
    validateStatus: () => true,
  });
  if (response.status < 200 || response.status >= 300 || response.data?.ok === false) {
    const error = new Error(response.data?.message || response.data?.error || `IPS server returned HTTP ${response.status}`);
    error.status = response.status >= 400 ? response.status : 502;
    throw error;
  }
  return response.data;
}

async function callIpsGet(companyId, path) {
  if (Date.now() < ipsGetCircuit.unavailableUntil) {
    const error = new Error('IPS server circuit open');
    error.circuitOpen = true;
    throw error;
  }
  const response = await axios.get(`${IPS_URL.replace(/\/+$/, '')}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(companyId && {
        'X-Company-ID': String(companyId),
        'X-Company': String(companyId),
      }),
      ...(IPS_SECRET && { 'X-Webhook-Secret': IPS_SECRET }),
    },
    timeout: IPS_PROXY_GET_TIMEOUT_MS,
    validateStatus: () => true,
  });
  if (response.status < 200 || response.status >= 300) {
    const error = new Error(response.data?.message || response.data?.error || `IPS server returned HTTP ${response.status}`);
    error.status = response.status;
    throw error;
  }
  return response.data;
}

function markIpsGetUnavailable(message) {
  ipsGetCircuit.unavailableUntil = Date.now() + IPS_PROXY_CIRCUIT_MS;
  if (DEBUG_IPS_PROXY && Date.now() - ipsGetCircuit.lastWarningAt >= IPS_PROXY_CIRCUIT_MS) {
    console.warn(`[IPS-Proxy] ipsserver read temporarily unavailable (${message}); using SOC DB fallback for ${Math.round(IPS_PROXY_CIRCUIT_MS / 1000)}s`);
    ipsGetCircuit.lastWarningAt = Date.now();
  }
}

async function localIpsWhitelist(companyId) {
  const whitelist = companyId
    ? await IpsWhitelist.find({ companyId }).sort({ createdAt: -1 }).lean().catch(() => [])
    : [];
  return {
    ok: true,
    source: 'soc-backend-fallback',
    whitelist,
    rules: [],
  };
}

async function localIpsBlocklist(companyId) {
  const blocks = await IpsService.getBlocklist(companyId);
  return {
    ok: true,
    source: 'soc-backend-db',
    blocklist: blocks.map(block => ({
      _id: block._id,
      ip: block.ip,
      port: block.port || null,
      reason: block.reason || '',
      blockedBy: block.blockedBy || 'auto',
      method: block.method || 'host-firewall',
      blockedAt: block.blockedAt || block.createdAt,
      expiresAt: block.expiresAt || null,
      abuseScore: block.abuseScore,
      otxPulses: block.otxPulses,
      malwareFamilies: block.malwareFamilies || [],
      feedSource: block.feedSource || '',
      geoCountry: block.geoCountry || '',
    })),
  };
}

async function localIpsStats(companyId) {
  const [total, active, auto, manual] = await Promise.all([
    IpsService.BlockedIP.countDocuments({ companyId }),
    IpsService.BlockedIP.countDocuments({ companyId, reverted: false }),
    IpsService.BlockedIP.countDocuments({ companyId, reverted: false, blockedBy: 'auto' }),
    IpsService.BlockedIP.countDocuments({ companyId, reverted: false, blockedBy: { $in: ['analyst', 'soar'] } }),
  ]);
  return {
    ok: true,
    source: 'soc-backend-db',
    totalBlocks: total,
    activeBlocks: active,
    autoBlocks: auto,
    manualBlocks: manual,
  };
}

function localIpsStatus() {
  return {
    ok: true,
    online: false,
    status: 'degraded',
    source: 'soc-backend-fallback',
    ipsserverUnavailable: true,
    message: 'IPS webhook service is unavailable; endpoint agents continue local enforcement.',
  };
}

// ── GET /api/ips-proxy/status ──────────────────────────────────────────────────
router.get('/status', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  try {
    const data = await cachedIpsRead(`status:${companyId || 'all'}`, async () => {
      try {
        const remote = await callIpsGet(companyId, `/status${qs}`);
        return { ...remote, source: remote.source || 'ipsserver' };
      } catch (err) {
        if (!err.circuitOpen) markIpsGetUnavailable(err.message);
        return localIpsStatus();
      }
    });
    res.json(data);
  } catch (err) {
    console.warn('[IPS-Proxy] status degraded fallback:', err.message);
    res.json(localIpsStatus());
  }
});

// ── GET /api/ips-proxy/blocklist ───────────────────────────────────────────────
router.get('/blocklist', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  try {
    const data = await cachedIpsRead(`blocklist:${companyId || 'all'}`, async () => {
      try {
        const remote = await callIpsGet(companyId, `/blocklist${qs}`);
        return { ...remote, source: remote.source || 'ipsserver' };
      } catch (err) {
        if (!err.circuitOpen) markIpsGetUnavailable(err.message);
        return { ...(await localIpsBlocklist(companyId)), ipsserverUnavailable: true };
      }
    });
    res.json(data);
  } catch (err) {
    console.warn('[IPS-Proxy] blocklist degraded fallback:', err.message);
    res.json({ ok: true, source: 'soc-backend-fallback', blocklist: [], ipsserverUnavailable: true, degraded: true });
  }
});

// ── GET /api/ips-proxy/blocks ──────────────────────────────────────────────────
router.get('/blocks', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  try {
    const data = await cachedIpsRead(`blocks:${companyId || 'all'}`, async () => {
      try {
        const remote = await callIpsGet(companyId, `/blocks${qs}`);
        return { ...remote, source: remote.source || 'ipsserver' };
      } catch (err) {
        if (!err.circuitOpen) markIpsGetUnavailable(err.message);
        return { ...(await localIpsBlocklist(companyId)), ipsserverUnavailable: true };
      }
    });
    res.json(data);
  } catch (err) {
    console.warn('[IPS-Proxy] blocks degraded fallback:', err.message);
    res.json({ ok: true, source: 'soc-backend-fallback', blocklist: [], ipsserverUnavailable: true, degraded: true });
  }
});

// ── GET /api/ips-proxy/stats ──────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  try {
    const data = await cachedIpsRead(`stats:${companyId || 'all'}`, async () => {
      try {
        const remote = await callIpsGet(companyId, `/stats${qs}`);
        return { ...remote, source: remote.source || 'ipsserver' };
      } catch (err) {
        if (!err.circuitOpen) markIpsGetUnavailable(err.message);
        return { ...(await localIpsStats(companyId)), ipsserverUnavailable: true };
      }
    });
    res.json(data);
  } catch (err) {
    console.warn('[IPS-Proxy] stats degraded fallback:', err.message);
    res.json({ ok: true, source: 'soc-backend-fallback', totalBlocks: 0, activeBlocks: 0, autoBlocks: 0, manualBlocks: 0, ipsserverUnavailable: true, degraded: true });
  }
});

// ── GET /api/ips-proxy/incidents ──────────────────────────────────────────────
router.get('/incidents', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  await proxyRequest(req, res, `/incidents${qs}`, { companyId });
});

// ── POST /api/ips-proxy/block ──────────────────────────────────────────────────
router.post('/block', requireManager, async (req, res) => {
  try {
    const companyId = resolveCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    let body = { ...req.body, action: 'block' };
    let system = null;

    if (req.body.systemId) {
      system = await System.findOne({
        _id: req.body.systemId,
        companyId,
        isActive: true,
      }).select('_id agentId name hostname ip macAddress');

      if (!system) {
        return res.status(400).json({ message: 'Selected agent was not found for this company' });
      }

      body = {
        ...body,
        systemId: system._id.toString(),
        agentId: system.agentId || system._id.toString(),
        agentName: system.name || system.hostname || 'Agent',
        agentHostname: system.hostname || '',
        agentIp: system.ip || '',
        mac: req.body.ip && system.ip === req.body.ip ? (system.macAddress || undefined) : undefined,
      };
    }

    if (body.ip) {
      const result = await IpsService.blockIP({
        ip: body.ip,
        port: body.port ? Number(body.port) : undefined,
        companyId,
        reason: body.reason || body.attackType || 'Manual IPS block',
        alertId: body.alertId,
        blockedBy: 'analyst',
        ttlHours: body.ttlHours == null ? undefined : Number(body.ttlHours),
        systemId: body.systemId,
        mac: body.mac,
      });

      return res.status(result.ok ? 200 : result.agentAccepted ? 202 : result.whitelisted ? 409 : 422).json({
        ok: Boolean(result.ok),
        action: 'block',
        source: 'soc-backend-ips-service',
        backendStateUpdated: Boolean(result.dbSaved),
        firewallEnforced: Boolean(result.webhookOk || result.agentConfirmed),
        ipsserver: result.webhook || null,
        message: result.ok
          ? 'IPS block persisted and confirmed by a firewall endpoint'
          : result.whitelisted
            ? `IPS block skipped: ${result.reason}`
            : result.agentAccepted ? 'IPS block queued; waiting for endpoint firewall ACK'
              : `IPS block could not be confirmed: ${result.reason || result.webhook?.error || 'no available enforcement target'}`,
        result,
      });
    }

    if (await IpsService.isWhitelistedTarget({ companyId, domain: body.domain })) {
      return res.status(409).json({ ok: false, skipped: true, whitelisted: true, message: 'Target is whitelisted' });
    }

    const ipsResult = await callIpsWebhook(companyId, body);
    const centralEnforced = ipsResult.enforced === true;
    let agentResult = null;
    if (system) {
      const command = body.domain ? 'block_domain'
        : body.application ? 'block_application'
          : body.port ? 'close_port' : 'block_protocol';
      agentResult = await IpsService.queueEndpointCommand({
        companyId,
        systemId: system._id,
        command,
        domain: body.domain,
        application: body.application,
        port: body.port,
        protocol: body.protocol || 'tcp',
        reason: body.reason || body.attackType || 'Manual IPS block',
      });
    }
    const agentConfirmed = agentResult?.confirmed === true;
    const agentAccepted = agentConfirmed || agentResult?.queued > 0 || agentResult?.pending > 0;
    if (!centralEnforced && !agentAccepted) {
      return res.status(503).json({
        ok: false,
        message: 'Central IPS delegated enforcement but no endpoint agent was selected and confirmed',
        ips: ipsResult,
      });
    }
    return res.status(centralEnforced || agentConfirmed ? 200 : 202).json({
      ok: centralEnforced || agentConfirmed,
      accepted: agentAccepted,
      action: 'block',
      firewallEnforced: centralEnforced || agentConfirmed,
      agentEnforced: agentConfirmed,
      agentResult,
      ips: ipsResult,
    });
  } catch (error) {
    console.error('[IPS-Proxy] Manual block failed:', error.message);
    res.status(error.status || 502).json({ ok: false, message: error.message });
  }
});

// ── POST /api/ips-proxy/unblock ───────────────────────────────────────────────
router.post('/unblock', requireManager, async (req, res) => {
  const stages = { centralFirewall: false, backendState: false, endpointFirewall: null };
  try {
    const companyId = resolveCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const body = { ...req.body, action: 'unblock' };
    if (!body.ip && !body.domain && !body.application && !body.port && !body.protocol) {
      return res.status(400).json({ message: 'An IP, domain, application, port, or protocol is required' });
    }

    let system = null;
    if (body.systemId) {
      system = await System.findOne({ _id: body.systemId, companyId, isActive: true })
        .select('_id name hostname');
      if (!system) return res.status(400).json({ message: 'Selected agent was not found for this company' });
    }

    const ipsResult = await callIpsWebhook(companyId, body).catch(error => {
      if (!body.ip && !system) throw error;
      return { enforced: false, error: error.message, unavailable: true };
    });
    stages.centralFirewall = ipsResult.enforced === true;
    if (!stages.centralFirewall && !system && !body.ip) {
      const unavailable = new Error('Central IPS is in log-only mode and no endpoint agent was selected');
      unavailable.status = 503;
      throw unavailable;
    }

    let agentResult = null;
    if (body.ip) {
      const unblockResult = await IpsService.unblockIP({
        ip: body.ip,
        companyId,
        reason: body.reason || 'Manual Override Approved',
        skipWebhook: true,
        webhookEnforced: stages.centralFirewall,
        systemId: system?._id || null,
      });
      stages.backendState = unblockResult.dbUpdated > 0;
      stages.endpointFirewall = unblockResult.agentDispatch?.confirmed === true;
      agentResult = unblockResult.agentDispatch;
    }

    if (system && !body.ip) {
      const command = body.domain ? 'unblock_domain'
          : body.application ? 'unblock_application'
            : body.port ? 'unblock_port' : 'unblock_protocol';
      agentResult = await IpsService.queueEndpointCommand({
          companyId,
          systemId: system._id,
          command,
          ip: body.ip,
          domain: body.domain,
          application: body.application,
          port: body.port,
          protocol: body.protocol || 'tcp',
          reason: body.reason || 'Manual Override Approved',
        });
      stages.endpointFirewall = agentResult.confirmed === true;
    }

    const agentAccepted = agentResult?.confirmed === true || (agentResult?.status !== 'failed' && (agentResult?.queued > 0 || agentResult?.pending > 0));
    const completed = stages.centralFirewall || stages.endpointFirewall === true;
    res.status(completed ? 200 : agentAccepted ? 202 : 503).json({
      ok: completed,
      accepted: agentAccepted,
      action: 'unblock',
      firewallEnforced: stages.centralFirewall || stages.endpointFirewall === true,
      backendStateUpdated: stages.backendState,
      agentEnforced: system ? stages.endpointFirewall === true : null,
      agentResult,
      ips: ipsResult,
      stages,
    });
  } catch (error) {
    console.error('[IPS-Proxy] Manual unblock failed:', error.message);
    res.status(error.status || 502).json({
      ok: false,
      message: error.message,
      partial: Object.values(stages).some(value => value === true),
      stages,
    });
  }
});

// ── GET /api/ips-proxy/threats ────────────────────────────────────────────────
router.get('/threats', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const hours = req.query.hours || 24;
  const qs = `?hours=${hours}${companyId ? `&company=${companyId}` : ''}`;
  await proxyRequest(req, res, `/threats${qs}`, { companyId });
});

// ── GET /api/ips-proxy/attacks ────────────────────────────────────────────────
router.get('/attacks', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const limit = req.query.limit || 100;
  const qs = `?limit=${limit}${companyId ? `&company=${companyId}` : ''}`;
  await proxyRequest(req, res, `/attacks${qs}`, { companyId });
});

// ── GET /api/ips-proxy/logs ───────────────────────────────────────────────────
router.get('/logs', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const limit = req.query.limit || 200;
  const level = req.query.level || '';
  let qs = `?limit=${limit}${level ? `&level=${level}` : ''}`;
  if (companyId) qs += `&company=${companyId}`;
  await proxyRequest(req, res, `/logs${qs}`, { companyId });
});

// ── GET /api/ips-proxy/whitelist ──────────────────────────────────────────────
router.get('/whitelist', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  try {
    const data = await cachedIpsRead(`whitelist:${companyId || 'all'}`, async () => {
      try {
        const remote = await callIpsGet(companyId, `/whitelist${qs}`);
        await IpsService.syncWhitelistMirror(companyId, remote.whitelist || []);
        return { ...remote, source: remote.source || 'ipsserver' };
      } catch (err) {
        if (!err.circuitOpen) markIpsGetUnavailable(err.message);
        return { ...(await localIpsWhitelist(companyId)), ipsserverUnavailable: true };
      }
    });
    res.json(data);
  } catch (err) {
    console.warn('[IPS-Proxy] whitelist degraded fallback:', err.message);
    res.json({ ...(await localIpsWhitelist(companyId)), ipsserverUnavailable: true, degraded: true });
  }
});

// ── POST /api/ips-proxy/whitelist ─────────────────────────────────────────────
router.post('/whitelist', requireManager, async (req, res) => {
  try {
    const companyId = resolveCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const body = { ...req.body };
    if (body.ip && !body.value) body.value = body.ip;
    body.value = String(body.value || '').trim();
    body.type = String(body.type || 'ip').toLowerCase();
    if (!body.value || !['ip', 'cidr', 'domain'].includes(body.type)) {
      return res.status(400).json({ message: 'Valid value and type (ip, cidr, domain) are required' });
    }
    const remote = await callIpsMutation('post', companyId, '/whitelist', body);
    await IpsWhitelist.findOneAndUpdate(
      { companyId, value: body.value },
      { $set: { type: body.type, reason: body.reason || '', source: 'manual', addedBy: req.user.id || req.user._id } },
      { upsert: true, new: true, runValidators: true },
    );
    ipsReadCache.delete(`whitelist:${companyId}`);

    const systems = await System.find({ companyId, isActive: true, agentVersion: { $nin: [null, ''] } }).select('_id').lean();
    const agentSync = await Promise.all(systems.map(system => IpsService.queueEndpointCommand({
      companyId, systemId: system._id, command: 'ips_whitelist_add',
      value: body.value, type: body.type, reason: body.reason || 'Dashboard whitelist',
    })));

    // A new allow entry must also remove any matching stale endpoint block.
    if (body.type === 'ip') {
      await IpsService.unblockIP({ ip: body.value, companyId, reason: 'Added to IPS whitelist' });
    } else if (body.type === 'domain') {
      await Promise.allSettled(systems.map(system => IpsService.queueEndpointCommand({
        companyId, systemId: system._id, command: 'unblock_domain', domain: body.value,
        reason: 'Added to IPS whitelist',
      })));
    }
    res.json({ ...remote, mirrored: true, agentSync });
  } catch (error) {
    res.status(error.status || 502).json({ ok: false, message: error.message });
  }
});

// ── DELETE /api/ips-proxy/whitelist/:value ────────────────────────────────────
router.delete('/whitelist/:value', requireManager, async (req, res) => {
  try {
    const companyId = resolveCompanyId(req);
    if (!companyId) return res.status(400).json({ message: 'companyId required' });
    const value = decodeURIComponent(req.params.value);
    const existing = await IpsWhitelist.findOne({ companyId, value }).lean();
    const remote = await callIpsMutation('delete', companyId, `/whitelist/${encodeURIComponent(value)}`);
    await IpsWhitelist.deleteOne({ companyId, value });
    ipsReadCache.delete(`whitelist:${companyId}`);
    const systems = await System.find({ companyId, isActive: true, agentVersion: { $nin: [null, ''] } }).select('_id').lean();
    const agentSync = await Promise.all(systems.map(system => IpsService.queueEndpointCommand({
      companyId, systemId: system._id, command: 'ips_whitelist_remove',
      value, type: existing?.type || 'ip', reason: 'Removed from dashboard whitelist',
    })));
    res.json({ ...remote, mirrored: true, agentSync });
  } catch (error) {
    res.status(error.status || 502).json({ ok: false, message: error.message });
  }
});

// ── GET /api/ips-proxy/companies — Superadmin view all companies with IPS stats
router.get('/companies', requireSuperAdmin, async (req, res) => {
  await proxyRequest(req, res, '/companies', { companyId: '' });
});

// ── GET /api/ips-proxy/health ─────────────────────────────────────────────────
router.get('/health', async (req, res) => {
  await proxyRequest(req, res, '/health', {});
});

// ── WAF Routes ────────────────────────────────────────────────────────────────
// ── GET /api/ips-proxy/waf/status — Active WAF agents + protected ports ───────
router.get('/waf/status', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const qs = companyId ? `?company=${companyId}` : '';
  await proxyRequest(req, res, `/waf/status${qs}`, { companyId });
});

// ── GET /api/ips-proxy/waf/attacks — Recent WAF blocked attacks ────────────────
router.get('/waf/attacks', async (req, res) => {
  const companyId = resolveCompanyId(req);
  const limit = req.query.limit || 100;
  const qs = `?limit=${limit}${companyId ? `&company=${companyId}` : ''}`;
  await proxyRequest(req, res, `/waf/attacks${qs}`, { companyId });
});

module.exports = router;
