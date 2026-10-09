/**
 * Webhook Controller — SOC4 IPS Server v4.0
 * ===========================================
 * Handles all incoming API requests.
 *
 * Endpoints:
 *   POST /webhook           — Block/unblock by IP, MAC, domain, port, app, protocol
 *   GET  /                  — Server status + blocklist
 *   GET  /status            — Server status
 *   GET  /health            — Liveness probe
 *   GET  /blocklist         — Blocked IPs, MACs, attack logs (Blockment Overview)
 *   GET  /network           — Active traffic, suspicious activity, allowed connections
 *   GET  /ip-status         — Active vs blocked IP panel
 *   GET  /threats           — Threat statistics (24h)
 *   GET  /attacks           — Recent attack events
 *   GET  /logs              — Recent server logs
 *   GET  /whitelist         — Whitelisted IPs/domains
 *   POST /whitelist         — Add to whitelist
 *   DELETE /whitelist/:value — Remove from whitelist
 *   POST /analyze           — Analyze payload for threats (no blocking)
 *   GET  /companies         — All registered companies
 *   GET  /stats             — Aggregate dashboard KPIs
 *   GET  /incidents         — Active IPS Engine incidents
 *   POST /simulate          — Simulate attack for testing
 *   POST /isolate           — Manually isolate a system
 *   POST /unisolate         — Manual unisolate (requires consent)
 *   POST /consent           — Submit consent form for override action
 *   GET  /audit-logs        — Admin action audit logs (Super Admin only)
 */

const logger = require('../utils/logger');
const { sendSuccess, sendError } = require('../utils/response');
const { parseBody } = require('../middlewares/bodyParser');
const firewallService = require('../services/firewallService');
const mongoService = require('../services/mongoService');
const attackDetection = require('../utils/attackDetection');
const alertEngine = require('../services/alertEngine');

// 16 canonical attack types supported by the IPS engine
const ATTACK_TYPES_16 = [
  'SQL Injection', 'XSS', 'CSRF', 'Command Injection', 'Path Traversal',
  'DoS', 'DDoS', 'Brute Force', 'Port Scan', 'Man-in-the-Middle',
  'DNS Spoofing', 'ARP Spoofing', 'Ransomware', 'Malware', 'Phishing',
  'Zero-Day Exploit',
];

// ── POST /webhook — Block / Unblock ──────────────────────────────────────────
async function handleWebhook(req, res) {
  try {
    const data = await parseBody(req);
    const {
      action, ip, port, domain, application, protocol, direction, reason,
      attackType: manualAttackType, blockProtocol, rawBlockKey,
      failedAttempts, requestsPerSecond, payload, ipReputation,
      mac, adminEmail, severity,
      systemId, departmentId, agentId, agentName, agentHostname, agentIp,
      ttlHours,
    } = data;

    if (!req.company) {
      logger.warn('[Webhook] Rejected — company_id missing');
      return sendError(res, 'company_id is required — request rejected (multi-tenant policy)', 400);
    }

    if (!action) return sendError(res, 'action is required (block or unblock)', 400);
    if (action !== 'block' && action !== 'unblock') {
      return sendError(res, 'Invalid action. Use: block or unblock', 400);
    }

    const effectiveProtocol = (blockProtocol || protocol || '').toLowerCase() || undefined;
    if (!ip && !domain && !application && !port && !effectiveProtocol && !(action === 'unblock' && rawBlockKey)) {
      return sendError(res, 'At least one of: ip, domain, application, port, or protocol is required', 400);
    }

    const effectiveDirection = firewallService.normalizeDirection(direction ?? 'both');

    let detectedAttack = null;
    if (payload) {
      const detected = attackDetection.detectAttackType(payload);
      if (detected) detectedAttack = detected.type;
    }

    const threat = attackDetection.classifyThreat({
      ip: ip || '',
      failedAttempts: parseInt(failedAttempts || 0, 10),
      requestsPerSecond: parseInt(requestsPerSecond || 0, 10),
      payload: payload || '',
      ipReputation: ipReputation || null,
      attackType: manualAttackType || detectedAttack,
    });

    const effectiveReason = reason
      || (manualAttackType ? `Blocked due to ${manualAttackType}` : null)
      || (detectedAttack ? `Auto-detected: ${detectedAttack}` : null)
      || 'Blocked via webhook';

    const blockCriteria = {
      ip: ip || undefined,
      port: port ?? undefined,
      domain: domain || undefined,
      application: application || undefined,
      protocol: effectiveProtocol,
      direction: effectiveDirection,
      reason: effectiveReason,
      source: data.source || 'Auto',
      automatic: data.automatic,
      attackType: manualAttackType || detectedAttack || threat.attackType || undefined,
      company: req.company || undefined,
      mac: mac || undefined,
      systemId: systemId || undefined,
      departmentId: departmentId || undefined,
      agentId: agentId || undefined,
      agentName: agentName || undefined,
      agentHostname: agentHostname || undefined,
      agentIp: agentIp || undefined,
      ttlHours: ttlHours ?? undefined,
      rawBlockKey,
    };

    logger.info(
      `[Webhook] ${action.toUpperCase()} dir=${effectiveDirection} ` +
      `ip=${ip || '-'} port=${port || '-'} domain=${domain || '-'} ` +
      `mac=${mac || '-'} threat=${threat.threatLevel} type=${threat.attackType}`
    );

    // Whitelist check covers IP/CIDR and domain entries before any firewall or
    // delegated endpoint action is recorded.
    if (action === 'block' && (ip || domain)) {
      const target = ip || domain;
      const whitelisted = await mongoService.isWhitelisted(target, req.company);
      if (whitelisted) {
        logger.info(`[Webhook] Target ${target} is whitelisted — block skipped`);
        return sendSuccess(res, { action: 'block', skipped: true, enforced: false, reason: 'Target is whitelisted', ip, domain, threat });
      }
    }

    let result;
    if (action === 'block') {
      result = await firewallService.blockTarget(blockCriteria);
      if (result.tiDeferred) return sendSuccess(res, { ...result, action: 'block' });

      // Auto-trigger alert engine on block if threat is high/critical and attack type is known
      const isThreatIntel = data.source === 'backend-threat-intel' ||
                            data.source === 'threat-intel' ||
                            data.source === 'threat_intel' ||
                            manualAttackType === 'Threat Intelligence Auto-Block' ||
                            threat.attackType === 'Threat Intelligence Auto-Block' ||
                            (effectiveReason && /threat\s*intel|ti\s*auto-block/i.test(effectiveReason));
      // The main SOC backend owns retry/isolation/recovery for its webhook
      // calls. Starting this server's independent timer/email engine as well
      // creates duplicate isolation and false recovery (unlock) emails.
      const managedBySocBackend = data.orchestrationOwner === 'soc-backend' ||
                                  String(data.source || '').startsWith('backend-');

      if (ip && (threat.threatLevel === 'high' || threat.threatLevel === 'critical') && !isThreatIntel && !managedBySocBackend) {
        const resolvedAdminEmail = adminEmail || process.env.SMTP_USER;
        alertEngine.handleDetection({
          companyId: req.company,
          srcIp: ip,
          mac: mac || null,
          attackType: manualAttackType || detectedAttack || threat.attackType,
          severity: threat.threatLevel,
          adminEmail: resolvedAdminEmail,
          description: effectiveReason,
          failedAttempts: parseInt(failedAttempts || 0, 10),
          requestsPerSecond: parseInt(requestsPerSecond || 0, 10),
        }).catch(err => logger.error(`[AlertEngine] handleDetection error: ${err.message}`));
      }
    } else {
      result = await firewallService.unblockTarget(blockCriteria);
      // Resolve any active incident for this IP
      if (ip) alertEngine.resolveIncident(req.company, ip);
    }

    if (action === 'block') _storeThreatAsync(ip, domain, threat, effectiveReason, manualAttackType || detectedAttack, req.company, result.enforced === true);

    mongoService.storeLog({
      level: action === 'block' ? 'BLOCK' : 'UNBLOCK',
      message: `${action === 'block' ? '✅' : '↩️'} ${result.method || 'applied'}: ${result.description || ip || domain || port} — ${effectiveReason}`,
      ip, mac, domain, port, application, direction: effectiveDirection, threat: threat.threatLevel,
    }, req.company).catch(() => {});

    mongoService.storeSocIdsIpsEvent({
      action,
      block: {
        ...blockCriteria,
        blockKey: result.blockKey || rawBlockKey || null,
        method: result.method || '',
        enforced: result.enforced === true,
        delegated: result.delegated === true,
        ts: new Date(),
      },
      threat: {
        level: threat.threatLevel,
        type: manualAttackType || detectedAttack || threat.attackType,
        score: threat.score,
      },
    }, req.company).catch(() => {});

    const eventPayload = {
      action, ip, mac, domain, port, application,
      enforced: result.enforced === true, delegated: result.delegated === true,
      direction: effectiveDirection, reason: effectiveReason,
      company: req.company || null,
      systemId: systemId || null,
      agentId: agentId || null,
      agentName: agentName || null,
      threat: { level: threat.threatLevel, type: threat.attackType, score: threat.score },
      ts: new Date().toISOString(),
    };
    if (typeof global.emitIPSEvent === 'function') {
      global.emitIPSEvent(action === 'block' ? 'block' : 'unblock', eventPayload);
    }

    return sendSuccess(res, {
      ...result,
      action,
      ip: ip || null,
      domain: domain || null,
      port: port || null,
      threat: {
        level: threat.threatLevel,
        type: threat.attackType,
        score: threat.score,
        autoDetectedType: detectedAttack,
        recommendedAction: threat.recommendedAction,
      },
    });
  } catch (err) {
    logger.error(`[Webhook] Error: ${err.message}`);
    return sendError(res, err.message, err.statusCode || 400);
  }
}

function _storeThreatAsync(ip, domain, threat, reason, explicitType, company = null, enforced = false) {
  const doc = {
    ip: ip || null, domain: domain || null,
    attackType: explicitType || threat.attackType,
    threatLevel: threat.threatLevel, confidence: threat.confidence,
    score: threat.score, reason, source: 'webhook',
  };
  mongoService.storeThreat(doc, company).catch(() => {});
  if (threat.score >= 55) {
    mongoService.storeAttackEvent({
      srcIp: ip || null, attackType: doc.attackType,
      threatLevel: doc.threatLevel, score: doc.score,
      direction: 'inbound', autoBlocked: enforced,
    }, company).catch(() => {});
  }
}

// ── POST /analyze ─────────────────────────────────────────────────────────────
async function analyzePayload(req, res) {
  try {
    const data = await parseBody(req);
    const { payload, ip, failedAttempts, requestsPerSecond, ipReputation } = data;
    const detected = payload ? attackDetection.detectAttackType(payload) : null;
    const threat = attackDetection.classifyThreat({
      ip: ip || '', failedAttempts: parseInt(failedAttempts || 0, 10),
      requestsPerSecond: parseInt(requestsPerSecond || 0, 10),
      payload: payload || '', ipReputation: ipReputation || null,
    });
    const reqAnalysis = attackDetection.analyzeRequest(req, data);
    return sendSuccess(res, { ip: ip || null, detection: detected, threat, requestAnalysis: reqAnalysis, autoAction: threat.recommendedAction });
  } catch (err) {
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── GET /status | GET / ───────────────────────────────────────────────────────
async function getStatus(req, res) {
  const { PLATFORM, getEnforcementMethod } = require('../utils/constants');
  const os = require('os');
  const { list, count } = firewallService.getBlocklistStatus(req.company);
  const threatSummary = await mongoService.getThreatStats(60 * 60 * 1000, req.company).catch(() => ({}));
  const fwType = firewallService._getFirewallType();
  const isLogOnly = fwType === 'log-only';
  const isEndpointAgent = fwType === 'endpoint-agent';
  return sendSuccess(res, {
    status: 'running',
    platform: PLATFORM, architecture: os.arch(),
    enforcement: isEndpointAgent
      ? 'endpoint-agent (delegated to enrolled AJNAT agent firewalls)'
      : isLogOnly ? 'log-only (no firewall configured)' : fwType,
    firewallType: fwType,
    autoBlock: !isLogOnly,
    supportedFirewalls: ['endpoint-agent', 'nftables', 'windows-defender'],
    uptime: process.uptime(),
    blockedCount: count,
    threats1h: threatSummary,
    blocklist: list,
  });
}


// ── GET /health ───────────────────────────────────────────────────────────────
function getHealth(req, res) {
  return sendSuccess(res, { ok: true, timestamp: new Date().toISOString(), uptime: process.uptime() });
}

// ── GET /blocklist — Blocked IPs, MACs, attack logs (Blockment Overview) ─────
function getBlocklist(req, res) {
  const { list, count } = firewallService.getBlocklistStatus(req.company);
  // Enrich with attack log context
  const enriched = list.map(b => ({
    ...b,
    displayType: b.type === 'ip' ? '🔴 IP Block' : b.type === 'domain' ? '🌐 Domain Block' : `🔒 ${(b.type||'block').toUpperCase()}`,
    blockState: b.source === 'Auto' ? 'auto-block' : 'manual-block',
  }));
  return sendSuccess(res, { count, blocklist: enriched });
}

// ── GET /network — Network Overview (active traffic, suspicious, allowed) ─────
async function getNetworkOverview(req, res) {
  try {
    const companyId = req.company || null;
    const [threatData, attackData, blockData] = await Promise.all([
      mongoService.getThreatStats(24 * 3600 * 1000, companyId).catch(() => ({})),
      mongoService.getRecentAttacks(50, {}, companyId).catch(() => []),
      Promise.resolve(firewallService.getBlocklistStatus(companyId)),
    ]);

    const incident = alertEngine.getIncidents(companyId);
    const suspiciousIPs = (threatData.topIPs || []).map(t => ({ ip: t.ip, hits: t.count, maxScore: t.maxScore }));

    return sendSuccess(res, {
      activeTraffic: {
        suspiciousCount: threatData.total || 0,
        byLevel: threatData.byLevel || {},
        byType: threatData.byType || [],
      },
      suspiciousActivity: suspiciousIPs,
      allowedConnections: {
        whitelistedCount: 0, // fetched separately via /whitelist
        comment: 'Use GET /whitelist to get allowed connections',
      },
      blockedCount: blockData.count,
      recentAttacks: attackData.slice(0, 20),
      activeIncidents: incident.slice(0, 10),
    });
  } catch (err) {
    return sendError(res, err.message, 500);
  }
}

// ── GET /ip-status — Active vs Blocked IP Panel ───────────────────────────────
async function getIPStatus(req, res) {
  try {
    const companyId = req.company || null;
    const { list: blockedList, count: blockedCount } = firewallService.getBlocklistStatus(companyId);
    const attacks = await mongoService.getRecentAttacks(100, {}, companyId).catch(() => []);
    const whitelistData = await mongoService.getWhitelist({}, companyId).catch(() => []);

    const blockedIPs = blockedList.filter(b => b.ip).map(b => ({
      ip: b.ip, mac: b.mac || null, status: 'blocked',
      blockState: b.source === 'Auto' ? 'auto-block' : 'manual-block',
      attackType: b.attackType || 'Unknown', ts: b.ts, reason: b.reason,
    }));

    const seenIPs = new Set(blockedIPs.map(b => b.ip));
    const activeIPs = attacks
      .filter(a => a.srcIp && !seenIPs.has(a.srcIp))
      .reduce((acc, a) => {
        if (!acc.find(e => e.ip === a.srcIp)) {
          acc.push({ ip: a.srcIp, status: 'suspicious', lastSeen: a.ts, attackType: a.attackType });
        }
        return acc;
      }, []);

    return sendSuccess(res, {
      blockedIPs,
      activeIPs,
      whitelistedIPs: whitelistData.filter(w => w.type === 'ip'),
      summary: {
        blocked: blockedIPs.length,
        active: activeIPs.length,
        whitelisted: whitelistData.filter(w => w.type === 'ip').length,
      },
    });
  } catch (err) {
    return sendError(res, err.message, 500);
  }
}

// ── GET /threats ──────────────────────────────────────────────────────────────
async function getThreats(req, res) {
  const url = new URL(req.url, `http://localhost`);
  const hours = parseInt(url.searchParams.get('hours') || '24', 10);
  const msWin = hours * 3600 * 1000;
  const [stats, topIPs] = await Promise.all([
    mongoService.getThreatStats(msWin, req.company),
    mongoService.getRecentAttacks(20, {}, req.company),
  ]);
  return sendSuccess(res, { timeWindowHours: hours, stats, recentAttacks: topIPs });
}

// ── GET /attacks ──────────────────────────────────────────────────────────────
async function getAttacks(req, res) {
  const url = new URL(req.url, `http://localhost`);
  const limit = parseInt(url.searchParams.get('limit') || '100', 10);
  const since = new Date(Date.now() - 24 * 3600 * 1000);
  const [events, stats] = await Promise.all([
    mongoService.getRecentAttacks(limit, {}, req.company),
    mongoService.getAttackStats(since, req.company),
  ]);
  return sendSuccess(res, { stats, events });
}

// ── GET /logs ─────────────────────────────────────────────────────────────────
async function getLogs(req, res) {
  const url = new URL(req.url, `http://localhost`);
  const limit = parseInt(url.searchParams.get('limit') || '200', 10);
  const level = url.searchParams.get('level') || null;
  const logs = await mongoService.getRecentLogs(limit, level, req.company);
  return sendSuccess(res, { count: logs.length, logs });
}

// ── GET /audit-logs — For Super Admin ────────────────────────────────────────
async function getAuditLogs(req, res) {
  try {
    const url = new URL(req.url, `http://localhost`);
    const limit = parseInt(url.searchParams.get('limit') || '500', 10);
    // Audit logs include consent forms, admin actions, isolation events
    const logs = await mongoService.getRecentLogs(limit, null, req.company);
    const auditLogs = logs.filter(l =>
      ['CONSENT', 'ISOLATION', 'RECOVERY', 'MANUAL-OVERRIDE', 'ADMIN-ACTION', 'ALERT'].includes(l.level)
    );
    return sendSuccess(res, { count: auditLogs.length, logs: auditLogs });
  } catch (err) {
    return sendError(res, err.message, 500);
  }
}

// ── GET /whitelist ────────────────────────────────────────────────────────────
async function getWhitelistHandler(req, res) {
  const list = await mongoService.getWhitelist({}, req.company);
  return sendSuccess(res, { count: list.length, whitelist: list });
}

// ── POST /whitelist ───────────────────────────────────────────────────────────
async function addWhitelist(req, res) {
  try {
    const { value, type = 'ip', reason = '' } = await parseBody(req);
    if (!value) return sendError(res, 'value is required', 400);
    await mongoService.addToWhitelist(value, type, reason, req.company);
    logger.info(`[Whitelist] Added: ${value} (${type})`);
    return sendSuccess(res, { added: true, value, type });
  } catch (err) {
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── DELETE /whitelist/:value ──────────────────────────────────────────────────
async function removeWhitelist(req, res, value) {
  try {
    if (!value) return sendError(res, 'value required in path', 400);
    await mongoService.removeFromWhitelist(decodeURIComponent(value), req.company);
    logger.info(`[Whitelist] Removed: ${value}`);
    return sendSuccess(res, { removed: true, value });
  } catch (err) {
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── POST /register-company — DISABLED ─────────────────────────────────────────
async function registerCompany(req, res) {
  return sendError(res, 'Company registration is managed centrally via the Company Frontend.', 400);
}

// ── GET /companies ────────────────────────────────────────────────────────────
async function getCompanies(req, res) {
  try {
    const allCompanies = await mongoService.getAllCompanies();
    const companies = req.company ? allCompanies.filter(company => company.companyId === req.company) : allCompanies;
    const enrichedCompanies = await Promise.all(
      companies.map(async (comp) => {
        const [threats, blocks] = await Promise.all([
          mongoService.getThreatStats(24 * 60 * 60 * 1000, comp.companyId),
          mongoService.getAllBlocks({}, 1000, comp.companyId),
        ]);
        return { ...comp, threats: threats?.total || 0, blocked: blocks?.length || 0 };
      })
    );
    return sendSuccess(res, { count: enrichedCompanies.length, companies: enrichedCompanies });
  } catch (err) {
    logger.error(`[Company] Fetch error: ${err.message}`);
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── GET /stats ────────────────────────────────────────────────────────────────
async function getStats(req, res) {
  try {
    const companyId = req.company || null;
    const [threatStats, blockStatus] = await Promise.all([
      mongoService.getThreatStats(24 * 3600 * 1000, companyId),
      Promise.resolve(firewallService.getBlocklistStatus(companyId)),
    ]);
    return sendSuccess(res, {
      activeBlocks:   blockStatus.count || 0,
      totalThreats:   threatStats.total || 0,
      networkThreats: threatStats.total || 0,
      byLevel:  threatStats.byLevel || {},
      byType:   threatStats.byType  || [],
      topIPs:   threatStats.topIPs  || [],
      companyId,
      firewallType: firewallService._getFirewallType(),
      supportedFirewalls: ['nftables', 'windows-defender'],
    });
  } catch (err) {
    logger.error(`[Stats] ${err.message}`);
    return sendError(res, err.message, 500);
  }
}

// ── GET /incidents ────────────────────────────────────────────────────────────
async function getIncidents(req, res) {
  try {
    const companyId = req.company || null;
    const incidents = alertEngine.getIncidents(companyId);
    return sendSuccess(res, { count: incidents.length, incidents, supportedAttackTypes: ATTACK_TYPES_16 });
  } catch (err) {
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── POST /isolate — Manual Isolation (no consent needed for initial) ──────────
async function isolateSystem(req, res) {
  return sendError(res, 'Endpoint isolation must be performed through the SOC backend system isolation API; this IPS service cannot confirm endpoint isolation.', 501);
}

async function unisolateSystem(req, res) {
  return sendError(res, 'Endpoint recovery must be performed through the SOC backend system isolation API; this IPS service cannot confirm endpoint recovery.', 501);
}

// ── POST /consent — Submit consent form before manual override ────────────────
async function submitConsent(req, res) {
  try {
    const data = await parseBody(req);
    const { srcIp, mac, action, adminName, adminEmail, reason, acknowledged } = data;
    const companyId = req.company;
    if (!companyId) return sendError(res, 'company_id required', 400);
    if (!srcIp) return sendError(res, 'srcIp required', 400);
    if (!adminName || !reason) return sendError(res, 'adminName and reason required', 400);
    if (acknowledged !== true) return sendError(res, 'You must acknowledge the consent form', 400);

    const consentId = `CONSENT-${Date.now()}-${Math.random().toString(36).slice(2, 8).toUpperCase()}`;
    const consentDoc = {
      consentId, companyId, srcIp, mac: mac || null,
      action: action || 'unisolate', adminName, adminEmail,
      reason, acknowledged: true,
      ts: new Date(), expiresAt: new Date(Date.now() + 15 * 60 * 1000), // 15 min validity
    };

    const db = require('../db/mongodb').getDB();
    if (!db) return sendError(res, 'Consent storage is unavailable', 503);
    await db.collection('consent_logs').insertOne(consentDoc);

    // Log to audit log
    await mongoService.storeLog({
      level: 'CONSENT',
      message: `[CONSENT] ${adminName} submitted consent for ${action || 'unisolate'} on ${srcIp} — "${reason}"`,
      ip: srcIp, mac: mac || null, companyId, consentId,
      adminName, adminEmail, adminAction: true,
    }, null).catch(() => {}); // global audit

    logger.info(`[Consent] ${consentId} submitted by ${adminName} for ${srcIp} [${companyId}]`);

    return sendSuccess(res, {
      consentId,
      message: 'Consent recorded. Use this consentId in your override request.',
      expiresAt: consentDoc.expiresAt,
      srcIp, companyId,
    });
  } catch (err) {
    return sendError(res, err.message, err.statusCode || 400);
  }
}

// ── POST /simulate ─────────────────────────────────────────────────────────────
async function simulateAttack(req, res) {
  try {
    const data = await parseBody(req);
    const companyId = data.companyId || req.company;
    if (!companyId) return sendError(res, 'companyId is required for attack simulation', 400);

    const srcIp = data.srcIp || `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`;
    const attackIdx = data.attackTypeIndex !== undefined ? parseInt(data.attackTypeIndex, 10) : Math.floor(Math.random() * ATTACK_TYPES_16.length);
    const attackType = data.attackType || ATTACK_TYPES_16[attackIdx % ATTACK_TYPES_16.length];
    const severity = data.severity || 'high';
    const adminEmail = data.adminEmail || process.env.SMTP_USER;
    const mac = data.mac || null;

    logger.info(`[Simulate] Injecting IDS detection: ${attackType} from ${srcIp} [company=${companyId}]`);

    await mongoService.storeAttackEvent({
      srcIp, mac, attackType, threatLevel: severity,
      score: severity === 'critical' ? 95 : 75,
      direction: 'inbound', autoBlocked: false, simulated: true,
    }, companyId).catch(() => {});

    await mongoService.storeThreat({
      ip: srcIp, attackType, threatLevel: severity, confidence: 0.9,
      score: severity === 'critical' ? 95 : 75,
      reason: `Simulated attack: ${attackType}`, source: 'simulation',
    }, companyId).catch(() => {});

    await mongoService.storeLog({
      level: 'INFO',
      message: `🧪 SIMULATE: ${attackType} from ${srcIp} [severity=${severity}]`,
      ip: srcIp, mac,
    }, companyId).catch(() => {});

    let engineResult = null;
    if (['high', 'critical'].includes(severity.toLowerCase())) {
      engineResult = await alertEngine.handleDetection({
        companyId, srcIp, mac, attackType, severity, adminEmail,
        description: `Simulated ${attackType} from ${srcIp}`,
      }).catch(e => ({ error: e.message }));
    }

    return sendSuccess(res, {
      simulated: true, srcIp, mac, attackType, severity, companyId,
      alertEngineTriggered: ['high', 'critical'].includes(severity.toLowerCase()),
      engineResult: engineResult ? { status: engineResult.status, alertCount: engineResult.alertCount } : null,
      supportedAttackTypes: ATTACK_TYPES_16,
    });
  } catch (err) {
    logger.error(`[Simulate] Error: ${err.message}`);
    return sendError(res, err.message, err.statusCode || 400);
  }
}

module.exports = {
  handleWebhook, analyzePayload, getStatus, getHealth,
  getBlocklist, getNetworkOverview, getIPStatus,
  getThreats, getAttacks, getLogs, getAuditLogs,
  getWhitelistHandler, addWhitelist, removeWhitelist,
  registerCompany, getCompanies, getStats, getIncidents,
  isolateSystem, unisolateSystem, submitConsent,
  simulateAttack,
};
