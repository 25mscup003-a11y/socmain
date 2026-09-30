/**
 * WAF Controller — SOC4 IPS Server v4.0
 * ========================================
 * Receives WAF block events from SOC Agents (auto-detected ports).
 * Stores in MongoDB waf_events collection.
 * Provides status + attack history for the IDS dashboard.
 *
 * Endpoints:
 *   POST /waf/report   — Agent reports WAF startup / block event
 *   GET  /waf/status   — Active WAF agents + protected ports per company
 *   GET  /waf/attacks  — Recent WAF-blocked attacks (?limit=50)
 *   GET  /waf/stats    — Attack type breakdown (24h)
 */

const logger = require('../utils/logger');
const { sendSuccess, sendError } = require('../utils/response');
const { parseBody } = require('../middlewares/bodyParser');
const mongoService = require('../services/mongoService');
const firewallService = require('../services/firewallService');
const { createWAFNATRule, removeWAFNATRule } = firewallService;

// ── In-memory: active WAF agents per company ──────────────────────────────────
// Map<companyId, Map<systemId, { ports, natRules, lastSeen, hostname, agentIP }>>
const _wafAgents = new Map();

function _getAgents(company) {
  if (!_wafAgents.has(company)) _wafAgents.set(company, new Map());
  return _wafAgents.get(company);
}

function _upsertAgent(company, systemId, info) {
  const agents = _getAgents(company);
  const existing = agents.get(systemId) || {};
  agents.set(systemId, { ...existing, ...info, systemId, lastSeen: new Date() });
}

// ── MongoDB persistence helpers ───────────────────────────────────────────────
async function _persistAgent(company, systemId, info) {
  try {
    const { getDB } = require('../db/mongodb');
    const db = getDB();
    if (!db) return;
    await db.collection('waf_agents').updateOne(
      { company, systemId },
      { $set: { ...info, company, systemId, lastSeen: new Date() } },
      { upsert: true }
    );
  } catch (e) {
    logger.debug(`[WAF] persistAgent: ${e.message}`);
  }
}

async function _loadAgentsFromDB(company) {
  try {
    const { getDB } = require('../db/mongodb');
    const db = getDB();
    if (!db) return [];
    const since = new Date(Date.now() - 30 * 60 * 1000); // last 30 min
    const query = company
      ? { company, lastSeen: { $gte: since } }
      : { lastSeen: { $gte: since } };
    return await db.collection('waf_agents').find(query).toArray();
  } catch { return []; }
}

// ── POST /waf/report ──────────────────────────────────────────────────────────
async function reportWAFEvent(req, res) {
  try {
    const data = await parseBody(req);
    const {
      action, systemId, hostname, agentVersion, agentIP,
      detectedPorts,
      ip, attackType, severity, ruleId,
      requestPath, method, matched, wafPort, originalPort,
    } = data;

    const company = req.company;
    if (!company) return sendError(res, 'company_id required', 400);
    if (!action) return sendError(res, 'action required', 400);

    // ── STARTUP / HEARTBEAT ───────────────────────────────────────────────────
    if (action === 'startup' || action === 'heartbeat') {
      const WAF_PORT_OFFSET = 10000;
      const natRules = [];

      if (action === 'startup' && agentIP && (detectedPorts || []).length > 0) {
        for (const port of detectedPorts) {
          const wafProxyPort = port + WAF_PORT_OFFSET;
          const r = await createWAFNATRule(
            agentIP, port, wafProxyPort,
            `SOC4 WAF agent=${systemId || hostname}`
          );
          natRules.push({ originalPort: port, wafPort: wafProxyPort, ...r });
        }
      }

      const agentInfo = {
        hostname, agentVersion, agentIP,
        ports: detectedPorts || [],
        natRules,
      };

      // Update in-memory
      _upsertAgent(company, systemId || hostname || 'unknown', agentInfo);

      // Persist to MongoDB
      await _persistAgent(company, systemId || hostname || 'unknown', agentInfo);

      await mongoService.storeLog({
        level: 'INFO',
        message: `🛡️ WAF ${action}: agent=${systemId || hostname} agentIP=${agentIP} ports=${(detectedPorts || []).join(',')} [${company}]`,
        wafAction: action, systemId, hostname, agentIP, ports: detectedPorts, natRules,
      }, company).catch(() => { });

      logger.info(`[WAF] ${action.toUpperCase()}: agent=${systemId || hostname} ip=${agentIP} ports=${(detectedPorts || []).join(',')} company=${company}`);
      return sendSuccess(res, { received: true, action, company, natRules });
    }

    // ── BLOCK EVENT ───────────────────────────────────────────────────────────
    if (action === 'block') {
      if (!ip) return sendError(res, 'ip required for block events', 400);

      const eventDoc = {
        company,
        systemId: systemId || hostname || 'unknown',
        hostname,
        ip,
        attackType: attackType || 'Web Attack',
        severity: severity || 'high',
        ruleId: ruleId || 'WAF_BLOCK',
        requestPath: requestPath || '/',
        method: method || 'GET',
        matched: matched || '',
        originalPort: originalPort || null,
        wafPort: wafPort || null,
        blocked: true,
        ts: new Date(),
      };

      // Store in waf_events collection
      await _storeWAFEvent(eventDoc);

      // Also store as standard attack_event so existing dashboard stats pick it up
      await mongoService.storeAttackEvent({
        srcIp: ip,
        attackType: attackType || 'Web Attack',
        threatLevel: severity || 'high',
        score: severity === 'critical' ? 95 : severity === 'high' ? 75 : 50,
        direction: 'inbound',
        autoBlocked: true,
        source: 'waf',
        systemId,
        requestPath,
      }, company).catch(() => { });

      // Store as threat intel
      await mongoService.storeThreat({
        ip,
        attackType: attackType || 'Web Attack',
        threatLevel: severity || 'high',
        confidence: 0.9,
        score: 80,
        reason: `WAF auto-block: ${attackType} on ${requestPath}`,
        source: 'waf',
      }, company).catch(() => { });

      // Log it
      await mongoService.storeLog({
        level: 'BLOCK',
        message: `🛡️ WAF BLOCKED: ${attackType || 'Web Attack'} from ${ip} → ${requestPath} [${company}]`,
        ip, attackType, severity, requestPath, method, ruleId,
      }, company).catch(() => { });

      // Auto-block at network level via firewall service
      const whitelisted = await mongoService.isWhitelisted(ip, company);
      if (!whitelisted) {
        await firewallService.blockTarget({
          ip, reason: `WAF auto-block: ${attackType || 'Web Attack'} on ${requestPath}`,
          source: 'WAF', attackType: attackType || 'Web Attack',
          direction: 'inbound', company,
        }).catch(err => logger.debug(`[WAF] Firewall block failed: ${err.message}`));
      }

      // Emit real-time event to dashboard
      if (typeof global.emitIPSEvent === 'function') {
        global.emitIPSEvent('waf:block', {
          company, ip, attackType, severity, requestPath, method, systemId,
          ts: new Date().toISOString(),
        });
      }

      logger.warn(`[WAF] BLOCK: ${attackType} from ${ip} → ${requestPath} [company=${company}]`);
      return sendSuccess(res, { received: true, action: 'block', ip, attackType, company });
    }

    return sendError(res, `Unknown action: ${action}`, 400);
  } catch (err) {
    logger.error(`[WAF] reportWAFEvent error: ${err.message}`);
    return sendError(res, err.message, 500);
  }
}

// ── Port liveness check ───────────────────────────────────────────────────────
function _checkPort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    const net = require('net');
    const socket = new net.Socket();
    let done = false;
    const finish = (alive) => {
      if (done) return; done = true;
      try { socket.destroy(); } catch { }
      resolve(alive);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => finish(true));
    socket.once('error', () => finish(false));
    socket.once('timeout', () => finish(false));
    socket.connect(port, host);
  });
}

async function _isPortListening(host, port, timeoutMs = 800) {
  // Many Node.js dev servers bind to ::1 (IPv6) not 127.0.0.1 (IPv4)
  // Try both — if either responds, port is alive
  const isLocalhost = !host || host === '127.0.0.1' || host === 'localhost';
  if (isLocalhost) {
    const [v4, v6] = await Promise.all([
      _checkPort('127.0.0.1', port, timeoutMs),
      _checkPort('::1', port, timeoutMs),
    ]);
    return v4 || v6;
  }
  return _checkPort(host, port, timeoutMs);
}

// ── HTTP + HTTPS probe: detect both plain and TLS web services ────────────────
function _isHttpService(host, port) {
  const TIMEOUT = 2000;

  // ── Plain HTTP probe (IPv4 + IPv6) ─────────────────────────────────────────
  const HTTP_REQ = Buffer.from(`GET / HTTP/1.0\r\nHost: ${host}\r\nConnection: close\r\n\r\n`);
  const _isValidHttpResponse = (chunk) => {
    const r = chunk.toString('utf8', 0, 256).toUpperCase();
    return r.startsWith('HTTP/') || r.includes('SERVER:') ||
      r.includes('CONTENT-TYPE:') || r.includes('X-POWERED-BY:') ||
      r.includes('LOCATION:') || r.includes('WWW-AUTHENTICATE:');
  };

  const tcpProbe = (addr) => new Promise((resolve) => {
    const net = require('net');
    const s = new net.Socket();
    let resolved = false;
    const done = (v) => { if (!resolved) { resolved = true; try { s.destroy(); } catch { } resolve(v); } };
    const timer = setTimeout(() => done(false), TIMEOUT);
    s.once('connect', () => {
      s.write(HTTP_REQ);
      s.once('data', (d) => { clearTimeout(timer); done(_isValidHttpResponse(d)); });
      s.once('error', () => { clearTimeout(timer); done(false); });
      s.once('timeout', () => { clearTimeout(timer); done(false); });
      s.once('close', () => { clearTimeout(timer); done(false); });
      s.once('end', () => { clearTimeout(timer); done(false); });
    });
    s.once('error', () => { clearTimeout(timer); done(false); });
    s.setTimeout(TIMEOUT);
    s.connect(port, addr);
  });

  // ── HTTPS probe (handles self-signed certs like Greenbone/OpenVAS) ─────────
  const httpsProbe = (addr) => new Promise((resolve) => {
    try {
      const https = require('https');
      const req = https.request({
        hostname: addr,
        port,
        path: '/',
        method: 'GET',
        timeout: TIMEOUT,
        rejectUnauthorized: false,  // accept self-signed certs
        headers: { 'Connection': 'close' },
      }, (res) => {
        req.destroy();
        resolve(true);  // got HTTP response → it's a web service
      });
      req.on('error', () => resolve(false));
      req.on('timeout', () => { req.destroy(); resolve(false); });
      req.end();
    } catch { resolve(false); }
  });

  // Run all probes in parallel — resolve true if ANY succeeds
  return Promise.all([
    tcpProbe('127.0.0.1'),
    tcpProbe('::1'),
    httpsProbe('127.0.0.1'),
    httpsProbe('::1'),
  ]).then(results => results.some(Boolean)).catch(() => false);
}

// ── Dynamic localhost port discovery using ss/netstat/proc ────────────────────
function _getLocalhostListeningPorts() {
  return new Promise((resolve) => {
    const { exec } = require('child_process');

    // Non-web ports to skip
    const SKIP = new Set([
      22, 23, 25, 53, 69, 110, 111, 143, 161, 162, 389, 443, 445, 465, 514, 587, 636,
      993, 995, 1194, 1433, 1521, 1883, 2181, 2375, 2376, 3306, 3389, 4369, 5432,
      5433, 5672, 6379, 6443, 7001, 7199, 9092, 9300, 11211, 15672, 27017, 27018,
      28017, 50070
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

    // Try ss first, then netstat, then /proc/net/tcp
    exec('ss -tlnH 2>/dev/null', { timeout: 5000 }, (err, out) => {
      if (!err && out) {
        const ports = parse(out);
        if (ports.length > 0) return resolve(ports);
      }
      exec('netstat -tlnp 2>/dev/null', { timeout: 5000 }, (err2, out2) => {
        if (!err2 && out2) {
          const ports = parse(out2);
          if (ports.length > 0) return resolve(ports);
        }
        // Fallback: /proc/net/tcp
        const fs = require('fs');
        const ports = new Set();
        for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
          try {
            fs.readFileSync(f, 'utf8').split('\n').slice(1).forEach(line => {
              const p = line.trim().split(/\s+/);
              if (p[3] !== '0A') return;
              const port = parseInt(p[1]?.split(':').pop(), 16);
              if (!isNaN(port) && port >= 79 && port < 10000 && !SKIP.has(port)) ports.add(port);
            });
          } catch { }
        }
        resolve([...ports].sort((a, b) => a - b));
      });
    });
  });
}

// ── GET /waf/status ───────────────────────────────────────────────────────────
async function getWAFStatus(req, res) {
  try {
    const company = req.company || null;
    const os = require('os');

    // 1) Load registered agents (in-memory + MongoDB)
    let rawAgents = [];
    if (company) {
      const memAgents = [...(_getAgents(company).values())];
      rawAgents = memAgents.length > 0 ? memAgents : await _loadAgentsFromDB(company);
    } else {
      for (const [comp, agents] of _wafAgents.entries())
        rawAgents.push(...[...agents.values()].map(a => ({ ...a, company: comp })));
      if (rawAgents.length === 0) rawAgents = await _loadAgentsFromDB(null);
    }

    // 2) ALWAYS do a fresh localhost dynamic scan (ss → netstat → /proc/net/tcp)
    //    HTTP-probe each candidate to confirm it's actually a web service.
    const candidatePorts = await _getLocalhostListeningPorts();
    logger.info(`[WAF] localhost candidates: ${candidatePorts}`);

    const httpChecks = await Promise.all(
      candidatePorts.map(async (port) => ({
        port,
        alive: await _isHttpService('127.0.0.1', port),
      }))
    );
    const livePorts = httpChecks.filter(p => p.alive).map(p => p.port);
    logger.info(`[WAF] HTTP-confirmed web ports on localhost: ${livePorts}`);

    // 3) Build agent list — merge registered agents with localhost scan
    const checkedAgents = [];

    // Detect the REAL IP of this machine (not 127.0.0.1) so we can deduplicate
    const _getRealIP = () => {
      try {
        const ifaces = os.networkInterfaces();
        for (const name of Object.keys(ifaces)) {
          if (name.toLowerCase().startsWith('lo')) continue;
          for (const iface of ifaces[name]) {
            if (iface.family === 'IPv4' && !iface.internal) {
              return iface.address;
            }
          }
        }
      } catch { }
      return os.hostname();
    };
    const realIP = _getRealIP();

    // 3a) For each registered REMOTE agent, verify their reported ports
    // An agent is REMOTE if it has an IP, is not 127.0.0.1, AND is not our own realIP
    const remoteAgents = rawAgents.filter(a => a.agentIP && a.agentIP !== '127.0.0.1' && a.agentIP !== realIP);
    for (const agent of remoteAgents) {
      const portChecks = await Promise.all(
        (agent.ports || []).map(async (port) => ({
          port, alive: await _isPortListening(agent.agentIP, port),
        }))
      );
      const activePorts = portChecks.filter(p => p.alive).map(p => p.port);
      const lastSeenMs = agent.lastSeen ? new Date(agent.lastSeen).getTime() : 0;
      checkedAgents.push({
        ...agent,
        ports: activePorts,
        allPorts: agent.ports || [],
        portStatus: portChecks,
        online: (lastSeenMs > Date.now() - 30 * 60 * 1000) || activePorts.length > 0,
        lastSeen: agent.lastSeen,
      });
    }

    // 3b) Localhost agent — use the live dynamic scan result
    // An agent is LOCAL if it has no IP, is 127.0.0.1, OR matches our realIP
    const localAgent = rawAgents.find(a => !a.agentIP || a.agentIP === '127.0.0.1' || a.agentIP === realIP) || null;

    // Only show HTTP-confirmed ports in the table
    const localPortStatus = livePorts.map(p => ({ port: p, alive: true }));

    // Determine which company "owns" this IPS server's local scan:
    // 1. If agent registered → use its stored company
    // 2. If auto-detected → use IPS_OWNER_COMPANY_ID env var (set in .env)
    // 3. If nothing configured → superadmin only
    const ownerCompany = localAgent?.company || process.env.IPS_OWNER_COMPANY_ID || null;

    // Company isolation for local agent:
    // - Superadmin (no company): sees everything
    // - Company user: sees ONLY if their company matches ownerCompany
    const localAgentBelongsToCompany = !company                  // superadmin — show all
      || !ownerCompany                                            // not configured — superadmin only (safe default)
      || ownerCompany === company;                                // company matches owner — show

    if (localAgentBelongsToCompany && (livePorts.length > 0 || (localAgent && localAgent.ports?.length > 0))) {
      const localStatusAgent = {
        ...(localAgent || {}),
        systemId:     localAgent?.systemId     || 'localhost',
        hostname:     localAgent?.hostname     || os.hostname(),
        agentIP:      localAgent?.agentIP && localAgent.agentIP !== '127.0.0.1'
                        ? localAgent.agentIP : realIP,
        agentVersion: localAgent?.agentVersion || 'auto-scan',
        company:      ownerCompany,              // tag with owner company for clarity
        ports:        livePorts,
        allPorts:     livePorts,
        portStatus:   localPortStatus,
        online:       livePorts.length > 0,
        lastSeen:     localAgent?.lastSeen || new Date(),
        autoDetected: !localAgent,
      };

      const sameAgentIndex = checkedAgents.findIndex(a => {
        if (!a.online) return false;
        if (localAgent && a.systemId && a.systemId === localAgent.systemId) return true;
        if (a.hostname && localStatusAgent.hostname && a.hostname === localStatusAgent.hostname) return true;
        if (a.agentIP && localStatusAgent.agentIP && a.agentIP === localStatusAgent.agentIP) return true;
        return company && rawAgents.length === 1 && a.company === company;
      });

      if (sameAgentIndex >= 0) {
        const existing = checkedAgents[sameAgentIndex];
        const mergedPorts = [...new Set([...(existing.ports || []), ...livePorts])];
        checkedAgents[sameAgentIndex] = {
          ...existing,
          ports: mergedPorts,
          allPorts: [...new Set([...(existing.allPorts || existing.ports || []), ...mergedPorts])],
          portStatus: [
            ...(existing.portStatus || []),
            ...localPortStatus.filter(p => !(existing.portStatus || []).some(ep => ep.port === p.port)),
          ],
          online: true,
          localScanMerged: true,
        };
      } else {
        checkedAgents.push(localStatusAgent);
      }
    }


    const onlineAgents = checkedAgents
      .filter(a => a.online)
      .reduce((agents, agent) => {
        const identity = [
          agent.company || company || 'global',
          (agent.hostname || '').toLowerCase(),
          agent.agentIP || '',
        ].join('|');
        const existingIndex = agents.findIndex(a => [
          a.company || company || 'global',
          (a.hostname || '').toLowerCase(),
          a.agentIP || '',
        ].join('|') === identity);

        if (existingIndex === -1) {
          agents.push(agent);
          return agents;
        }

        const existing = agents[existingIndex];
        const ports = [...new Set([...(existing.ports || []), ...(agent.ports || [])])];
        agents[existingIndex] = {
          ...existing,
          ...agent,
          ports,
          allPorts: [...new Set([...(existing.allPorts || existing.ports || []), ...(agent.allPorts || agent.ports || []), ...ports])],
          portStatus: [
            ...(existing.portStatus || []),
            ...(agent.portStatus || []).filter(p => !(existing.portStatus || []).some(ep => ep.port === p.port)),
          ],
          lastSeen: new Date(existing.lastSeen || 0) > new Date(agent.lastSeen || 0) ? existing.lastSeen : agent.lastSeen,
          deduped: true,
        };
        return agents;
      }, []);
    const recentAttacks = await _getRecentWAFEvents(20, company);
    const stats24h = await _getWAFStats(24 * 3600 * 1000, company);
    const uniquePorts = [...new Set(onlineAgents.flatMap(a => a.ports))];

    return sendSuccess(res, {
      activeAgents: onlineAgents.length,
      agents: onlineAgents,
      allAgents: checkedAgents,
      protectedPorts: uniquePorts,
      totalPortsProtected: uniquePorts.length,
      stats24h,
      recentAttacks,
    });
  } catch (err) {
    logger.error(`[WAF] getWAFStatus error: ${err.message}`);
    return sendError(res, err.message, 500);
  }
}

// ── GET /waf/attacks ──────────────────────────────────────────────────────────
async function getWAFAttacks(req, res) {
  try {
    const url = new URL(req.url, 'http://localhost');
    const limit = parseInt(url.searchParams.get('limit') || '100', 10);
    const company = req.company || null;
    const attacks = await _getRecentWAFEvents(limit, company);
    const stats = await _getWAFStats(24 * 3600 * 1000, company);
    return sendSuccess(res, { count: attacks.length, attacks, stats });
  } catch (err) {
    return sendError(res, err.message, 500);
  }
}

// ── MongoDB helpers ───────────────────────────────────────────────────────────
async function _storeWAFEvent(doc) {
  try {
    const { getDB } = require('../db/mongodb');
    const db = getDB();
    if (db) await db.collection('waf_events').insertOne(doc);
  } catch (err) {
    logger.debug(`[WAF] storeWAFEvent: ${err.message}`);
  }
}

async function _getRecentWAFEvents(limit = 100, company = null) {
  try {
    const { getDB } = require('../db/mongodb');
    const db = getDB();
    if (!db) return [];
    const filter = company ? { company } : {};
    return await db.collection('waf_events')
      .find(filter).sort({ ts: -1 }).limit(limit).toArray();
  } catch { return []; }
}

async function _getWAFStats(windowMs = 24 * 3600 * 1000, company = null) {
  try {
    const { getDB } = require('../db/mongodb');
    const db = getDB();
    if (!db) return { total: 0, byType: [], topIPs: [], bySeverity: {} };
    const since = new Date(Date.now() - windowMs);
    const match = { ts: { $gte: since }, ...(company && { company }) };
    const [result] = await db.collection('waf_events').aggregate([
      { $match: match },
      {
        $facet: {
          total: [{ $count: 'c' }],
          byType: [{ $group: { _id: '$attackType', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          bySeverity: [{ $group: { _id: '$severity', count: { $sum: 1 } } }],
          topIPs: [{ $group: { _id: '$ip', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }],
        }
      },
    ]).toArray();
    return {
      total: result.total[0]?.c || 0,
      byType: (result.byType || []).map(r => ({ type: r._id, count: r.count })),
      bySeverity: Object.fromEntries((result.bySeverity || []).map(r => [r._id, r.count])),
      topIPs: (result.topIPs || []).map(r => ({ ip: r._id, count: r.count })),
    };
  } catch { return { total: 0, byType: [], topIPs: [], bySeverity: {} }; }
}

module.exports = { reportWAFEvent, getWAFStatus, getWAFAttacks };
