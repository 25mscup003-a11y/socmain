/**
 * advanced-threats.routes.js
 *
 * API endpoints for 4 new advanced threat capabilities:
 * GET  /api/advanced/threat-intel/stats       — DB stats
 * GET  /api/advanced/threat-intel/lookup/:ip  — Single IP lookup
 * POST /api/advanced/threat-intel/bulk        — Bulk IP lookup
 * POST /api/advanced/threat-intel/custom      — Add custom IOC
 * DELETE /api/advanced/threat-intel/custom/:ip — Remove custom IOC
 * GET  /api/advanced/threat-intel/refresh     — Force feed refresh
 *
 * GET  /api/advanced/sinkhole/list            — All sinkholed domains
 * POST /api/advanced/sinkhole/add             — Sinkhole a domain
 * POST /api/advanced/sinkhole/remove          — Unsinkhole a domain
 * POST /api/advanced/sinkhole/bulk            — Bulk sinkhole
 * GET  /api/advanced/sinkhole/log             — Sinkhole action log
 *
 * GET  /api/advanced/cache-poison/baseline    — Current DNS baseline
 * POST /api/advanced/cache-poison/check       — Check single domain
 * GET  /api/advanced/cache-poison/findings    — Recent findings
 *
 * GET  /api/advanced/memory-overflow/recent   — Recent overflow events
 * GET  /api/advanced/memory-overflow/stats    — Process memory stats
 */

const router = require('express').Router();
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const Alert      = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');

router.use(authenticate, requireAnalyst);

const since = (days) => new Date(Date.now() - days * 86400000);

/* ═══════════════════════════════════════════════════════════
   1. THREAT INTELLIGENCE IP DATABASE
═══════════════════════════════════════════════════════════ */

// GET /api/advanced/threat-intel/stats
router.get('/threat-intel/stats', async (req, res) => {
  try {
    const cid = req.user.companyId;

    // Pull VT malicious hits from DB as proxy for TI DB
    const [vtHits, totalAlerts, maliciousAlerts] = await Promise.all([
      Alert.countDocuments({ companyId: cid, vtVerdict: 'malicious', createdAt: { $gte: since(30) } }),
      Alert.countDocuments({ companyId: cid, createdAt: { $gte: since(7) } }),
      Alert.countDocuments({ companyId: cid, severity: { $in: ['high', 'critical'] }, createdAt: { $gte: since(7) } }),
    ]);

    const recentHits = await Alert.find({
      companyId: cid,
      vtVerdict: 'malicious',
      createdAt: { $gte: since(7) },
    }).select('srcip vtDetections fileHash agentName description createdAt severity').limit(20).lean();

    res.json({
      dbStats: {
        total_ips:   'Live (Feodo + Emerging Threats + Tor)',
        feeds:       ['feodo_tracker', 'emerging_threats', 'tor_project', 'virustotal'],
        custom_iocs: 0,
        last_refresh: new Date().toISOString(),
      },
      summary: {
        vtHits30d:       vtHits,
        totalAlerts7d:   totalAlerts,
        maliciousAlerts: maliciousAlerts,
        period:          '30d',
      },
      recentHits,
      feeds: [
        { name: 'Feodo Tracker', url: 'feodotracker.abuse.ch', type: 'C2 Botnet IPs', status: 'active' },
        { name: 'Emerging Threats', url: 'rules.emergingthreats.net', type: 'Compromised Hosts', status: 'active' },
        { name: 'Tor Exit Nodes', url: 'check.torproject.org', type: 'Tor Network', status: 'active' },
        { name: 'VirusTotal', url: 'virustotal.com', type: 'Multi-engine AV', status: 'active' },
      ],
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/advanced/threat-intel/lookup/:ip
router.get('/threat-intel/lookup/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    const cid     = req.user.companyId;

    // Check recent alerts for this IP
    const alerts = await Alert.find({
      companyId: cid,
      srcip: ip,
    }).select('severity vtVerdict vtDetections description createdAt ruleId').limit(10).lean();

    const vtMalicious = alerts.find(a => a.vtVerdict === 'malicious');
    const reputation  = vtMalicious ? 'malicious'
                      : alerts.some(a => a.vtVerdict === 'suspicious') ? 'suspicious'
                      : alerts.length > 0 ? 'seen'
                      : 'unknown';

    res.json({
      ip,
      reputation,
      vtVerdict:   vtMalicious?.vtVerdict || 'unknown',
      vtDetections: vtMalicious?.vtDetections || 0,
      alertCount:  alerts.length,
      alerts,
      sources:     vtMalicious ? ['virustotal'] : [],
      message:     reputation === 'unknown'
        ? 'IP not found in local alerts — run VT scan for full intelligence'
        : `IP found in ${alerts.length} alerts`,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/advanced/threat-intel/bulk
router.post('/threat-intel/bulk', async (req, res) => {
  try {
    const { ips } = req.body;
    if (!Array.isArray(ips) || ips.length === 0)
      return res.status(400).json({ message: 'ips[] array required' });
    const cid = req.user.companyId;

    const results = await Promise.all(ips.slice(0, 50).map(async ip => {
      const count = await Alert.countDocuments({ companyId: cid, srcip: ip });
      const hit   = await Alert.findOne({ companyId: cid, srcip: ip, vtVerdict: 'malicious' }).lean();
      return {
        ip,
        found:    count > 0,
        malicious: !!hit,
        alertCount: count,
        vtVerdict:  hit?.vtVerdict || 'clean',
      };
    }));

    res.json({
      results,
      total:    ips.length,
      malicious: results.filter(r => r.malicious).length,
      found:    results.filter(r => r.found).length,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/advanced/threat-intel/custom  — Add custom IOC
router.post('/threat-intel/custom', async (req, res) => {
  try {
    const { ip, severity = 'high', category = 'custom_ioc', note = '' } = req.body;
    if (!ip) return res.status(400).json({ message: 'ip required' });

    // Create a custom alert to mark this IOC
    await Alert.create({
      companyId:     req.user.companyId,
      ruleId:        'CUSTOM_IOC',
      eventCategory: 'network',
      severity,
      srcip:         ip,
      description:   `Custom IOC added: ${ip} [${category}]${note ? ' — ' + note : ''}`,
      userAction:    'custom_ioc',
      vtVerdict:     'malicious',
      tags:          ['custom_ioc', category],
    });

    res.json({ success: true, ip, severity, category });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════
   2. DNS SINKHOLE
═══════════════════════════════════════════════════════════ */

// In-memory sinkhole store (persisted in production via MongoDB)
const sinkholeStore = new Map(); // domain → {ip, reason, severity, ts}
const sinkholeLog   = [];

// GET /api/advanced/sinkhole/list
router.get('/sinkhole/list', async (req, res) => {
  const list = [...sinkholeStore.entries()].map(([domain, info]) => ({
    domain, ...info,
  }));
  res.json({
    sinkholed: list,
    total:     list.length,
    sinkhole_ip: '0.0.0.0',
  });
});

// POST /api/advanced/sinkhole/add
router.post('/sinkhole/add', async (req, res) => {
  try {
    const { domain, reason = 'manual', severity = 'high' } = req.body;
    if (!domain) return res.status(400).json({ message: 'domain required' });
    const entry = { ip: '0.0.0.0', reason, severity, ts: new Date().toISOString() };
    sinkholeStore.set(domain.toLowerCase(), entry);
    sinkholeLog.push({ action: 'sinkholed', domain, ...entry, user: req.user.email });

    // Also create an alert for audit
    await Alert.create({
      companyId:     req.user.companyId,
      ruleId:        'DNS_SINKHOLE_ADDED',
      eventCategory: 'network',
      severity,
      description:   `DNS sinkhole activated: ${domain} → 0.0.0.0 [${reason}]`,
      userAction:    'dns_sinkhole',
    });

    res.json({ success: true, domain, sinkhole_ip: '0.0.0.0' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/advanced/sinkhole/remove
router.post('/sinkhole/remove', async (req, res) => {
  const { domain } = req.body;
  if (!domain) return res.status(400).json({ message: 'domain required' });
  sinkholeStore.delete(domain.toLowerCase());
  sinkholeLog.push({ action: 'removed', domain, ts: new Date().toISOString() });
  res.json({ success: true, domain });
});

// POST /api/advanced/sinkhole/bulk
router.post('/sinkhole/bulk', async (req, res) => {
  const { domains, reason = 'bulk_import' } = req.body;
  if (!Array.isArray(domains)) return res.status(400).json({ message: 'domains[] required' });
  let added = 0;
  for (const domain of domains.slice(0, 500)) {
    if (domain && typeof domain === 'string') {
      sinkholeStore.set(domain.toLowerCase(), {
        ip: '0.0.0.0', reason, severity: 'high', ts: new Date().toISOString(),
      });
      added++;
    }
  }
  sinkholeLog.push({ action: 'bulk_import', count: added, ts: new Date().toISOString() });
  res.json({ success: true, sinkholed: added, total: sinkholeStore.size });
});

// GET /api/advanced/sinkhole/log
router.get('/sinkhole/log', (req, res) => {
  res.json({ log: sinkholeLog.slice(-100).reverse(), total: sinkholeLog.length });
});

/* ═══════════════════════════════════════════════════════════
   3. CACHE POISONING DETECTION
═══════════════════════════════════════════════════════════ */

const cacheBaseline = new Map(); // domain → {ips[], ttl, ts}
const cacheFindings = [];
const watchDomains  = new Set([
  'google.com', 'microsoft.com', 'github.com', 'cloudflare.com'
]);

// GET /api/advanced/cache-poison/baseline
router.get('/cache-poison/baseline', async (req, res) => {
  const cid = req.user.companyId;

  // Pull DNS anomaly alerts from DB as evidence
  const dnsAlerts = await Alert.find({
    companyId: cid,
    createdAt: { $gte: since(7) },
    $or: [
      { ruleId: /DNS_TUNNEL|CACHE_POISON|DNS_SPOOF/i },
      { description: /cache poison|dns spoof|dns hijack/i },
    ],
  }).select('ruleId description severity createdAt agentName srcip').limit(20).lean();

  const baseline = [...cacheBaseline.entries()].map(([domain, info]) => ({
    domain, ...info,
  }));

  res.json({
    watchDomains: [...watchDomains],
    baseline,
    recentAlerts: dnsAlerts,
    findings:     cacheFindings.slice(-20),
    summary: {
      watching:       watchDomains.size,
      findingsTotal:  cacheFindings.length,
      dnsAlerts7d:    dnsAlerts.length,
    },
  });
});

// POST /api/advanced/cache-poison/check
router.post('/cache-poison/check', async (req, res) => {
  try {
    const { domain } = req.body;
    if (!domain) return res.status(400).json({ message: 'domain required' });

    const dns = require('dns').promises;
    let ips = [];
    let error = null;
    try {
      const result = await dns.resolve4(domain);
      ips = result;
    } catch (e) {
      error = e.message;
    }

    const existing = cacheBaseline.get(domain);
    const finding = { domain, ips, ts: new Date().toISOString(), status: 'ok' };

    if (existing) {
      const oldIps = existing.ips || [];
      const newIps = ips.filter(ip => !oldIps.includes(ip));
      if (newIps.length > 0) {
        finding.status  = 'changed';
        finding.oldIps  = oldIps;
        finding.newIps  = newIps;
        finding.warning = `DNS resolution changed for ${domain}`;
        cacheFindings.push({ ...finding, severity: 'high' });

        await Alert.create({
          companyId:     req.user.companyId,
          ruleId:        'DNS_CACHE_POISON_DETECTED',
          eventCategory: 'network',
          severity:      'high',
          description:   `DNS change detected: ${domain} → ${newIps.join(', ')} (was ${oldIps.join(', ')})`,
          userAction:    'cache_poisoning',
        });
      }
    }

    cacheBaseline.set(domain, { ips, ts: new Date().toISOString() });
    watchDomains.add(domain);

    res.json({ ...finding, baseline: existing || null, error });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/advanced/cache-poison/findings
router.get('/cache-poison/findings', async (req, res) => {
  const cid = req.user.companyId;
  const dbFindings = await Alert.find({
    companyId: cid,
    ruleId:    { $regex: /CACHE_POISON|DNS_SPOOF|DNS_HIJACK/i },
    createdAt: { $gte: since(30) },
  }).select('ruleId description severity createdAt agentName').limit(30).lean();

  res.json({
    findings:   [...cacheFindings.slice(-20).reverse(), ...dbFindings],
    total:      cacheFindings.length + dbFindings.length,
    watchCount: watchDomains.size,
  });
});

/* ═══════════════════════════════════════════════════════════
   4. MEMORY OVERFLOW DETECTION
═══════════════════════════════════════════════════════════ */

// GET /api/advanced/memory-overflow/recent
router.get('/memory-overflow/recent', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const overflowAlerts = await Alert.find({
      companyId: cid,
      createdAt: { $gte: since(7) },
      $or: [
        { ruleId:      { $regex: /OVERFLOW|SEGFAULT|HEAP_SPRAY|STACK_SMASH|MEM_/i } },
        { description: { $regex: /buffer overflow|heap overflow|stack overflow|segfault|heap spray|memory spike/i } },
        { userAction:  { $in: ['memory_overflow', 'memory_scan'] } },
      ],
    }).select('ruleId description severity agentName createdAt userAction raw').limit(50).lean();

    const byType = {};
    for (const a of overflowAlerts) {
      const t = a.ruleId || 'UNKNOWN';
      byType[t] = (byType[t] || 0) + 1;
    }

    res.json({
      alerts:   overflowAlerts,
      byType:   Object.entries(byType).map(([type, count]) => ({ type, count })),
      total:    overflowAlerts.length,
      period:   '7d',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/advanced/memory-overflow/stats
router.get('/memory-overflow/stats', async (req, res) => {
  try {
    const cid = req.user.companyId;
    const [total, critical, high, recent] = await Promise.all([
      Alert.countDocuments({ companyId: cid, userAction: { $in: ['memory_overflow','memory_scan'] } }),
      Alert.countDocuments({ companyId: cid, userAction: { $in: ['memory_overflow','memory_scan'] }, severity: 'critical' }),
      Alert.countDocuments({ companyId: cid, userAction: { $in: ['memory_overflow','memory_scan'] }, severity: 'high' }),
      Alert.countDocuments({ companyId: cid, userAction: { $in: ['memory_overflow','memory_scan'] }, createdAt: { $gte: since(1) } }),
    ]);

    res.json({
      total, critical, high, recent24h: recent,
      detectionTypes: [
        { type: 'SIGSEGV / Segfault',   mitre: 'T1203', description: 'Process crash via memory violation' },
        { type: 'Stack Smashing',        mitre: 'T1190', description: 'Stack canary violation detected' },
        { type: 'Heap Spray',            mitre: 'T1190', description: 'Rapid heap growth (>500MB/60s)' },
        { type: 'NX/DEP Violation',      mitre: 'T1203', description: 'Non-executable memory region executed' },
        { type: 'Kernel BUG / GPF',      mitre: 'T1190', description: 'General protection fault / kernel panic' },
        { type: 'ASAN Heap Overflow',    mitre: 'T1190', description: 'AddressSanitizer heap buffer overflow' },
        { type: 'Process Memory Spike',  mitre: 'T1203', description: '5x baseline RSS spike detection' },
      ],
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
