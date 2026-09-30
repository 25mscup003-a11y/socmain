/**
 * ips.routes.js — IPS Blocklist Management API
 *
 * GET  /api/ips/blocklist          — view current blocklist
 * POST /api/ips/block              — manually block an IP
 * DELETE /api/ips/block/:ip        — unblock an IP
 * GET  /api/ips/status             — IPS engine status + config
 * POST /api/ips/test               — test block a private IP (no effect)
 * GET  /api/ips/stats              — 24h block statistics
 */
const router = require('express').Router();
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { blockIP, unblockIP, getBlocklist, isBlocked, BlockedIP } = require('../services/ips.service');
const Alert = require('../models/Alert.model');

router.use(authenticate, requireAnalyst);

// ── GET /blocklist ─────────────────────────────────────────────────────────────
router.get('/blocklist', async (req, res) => {
  try {
    const list = await getBlocklist(req.user.companyId, {
      includeExpired: req.query.all === 'true',
    });
    res.json({ blocked: list, total: list.length });
  } catch (err) {
    console.error('[IPS] Blocklist error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /block-events — successful automatic IPS blocks from alert history ───
router.get('/block-events', async (req, res) => {
  try {
    const hours = Math.min(168, Math.max(1, Number(req.query.hours) || 24));
    const limit = Math.min(500, Math.max(1, Number(req.query.limit) || 200));
    const events = await Alert.find({
      companyId: req.user.companyId,
      ruleId: 'IPS_AUTO_BLOCK',
      blocked: true,
      srcip: { $not: /^(?:::ffff:)?127\.|^::1$|^localhost$/i },
      createdAt: { $gte: new Date(Date.now() - hours * 60 * 60 * 1000) },
    })
      .sort({ createdAt: -1 })
      .limit(limit)
      .select('_id srcip destip destPort description attackType agentName agentId systemId metadata createdAt severity blocked geoCountry geoCity geoRegion geoLat geoLon geoLoc geoISP destGeoLat destGeoLon destGeoLoc')
      .lean();
    res.json({ events, total: events.length, period: `${hours}h` });
  } catch (err) {
    console.error('[IPS] Block events error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /block — manual block ─────────────────────────────────────────────────
router.post('/block', requireManager, async (req, res) => {
  try {
    const { ip, port, reason, ttlHours } = req.body;
    if (!ip) return res.status(400).json({ message: 'ip required' });
    const result = await blockIP({
      ip, port: port || undefined, reason: reason || `Manual block by ${req.user.name || req.user.email}`,
      companyId: req.user.companyId,
      blockedBy: 'analyst',
      ttlHours: ttlHours || undefined,
    });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── DELETE /block/:ip — unblock ────────────────────────────────────────────────
router.delete('/block/:ip', requireManager, async (req, res) => {
  try {
    const result = await unblockIP({
      ip: req.params.ip,
      companyId: req.user.companyId,
      reason: `Manual unblock by ${req.user.name || req.user.email}`,
    });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /status — IPS config & engine status ──────────────────────────────────
router.get('/status', async (req, res) => {
  try {
    const mode = process.env.IPS_MODE || 'host-firewall';
    const firewallMode = process.env.IPS_FIREWALL_MODE || 'auto';
    const auto = process.env.IPS_AUTO_BLOCK === 'true';
    const [total, active] = await Promise.all([
      BlockedIP.countDocuments({ companyId: req.user.companyId }),
      BlockedIP.countDocuments({ companyId: req.user.companyId, reverted: false }),
    ]);
    res.json({
      mode,
      autoBlock: auto,
      configured: {
        nftables: firewallMode === 'nftables' || (firewallMode === 'auto' && process.platform === 'linux'),
        windowsDefender: firewallMode === 'windows-defender' || firewallMode === 'windows' || (firewallMode === 'auto' && process.platform === 'win32'),
        webhook: !!process.env.IPS_WEBHOOK_URL,
        firewallMode,
      },
      blocklistTotal: total,
      blocklistActive: active,
      ttlHours: parseInt(process.env.IPS_BLOCK_TTL_HOURS || '24', 10),
    });
  } catch (err) {
    console.error('[IPS] Status error:', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /stats ─────────────────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const since = new Date(Date.now() - 24 * 3600000);
    const [total, auto, manual, byMethod] = await Promise.all([
      BlockedIP.countDocuments({ companyId: req.user.companyId, reverted: false }),
      BlockedIP.countDocuments({ companyId: req.user.companyId, reverted: false, blockedBy: 'auto' }),
      BlockedIP.countDocuments({ companyId: req.user.companyId, reverted: false, blockedBy: { $in: ['analyst', 'soar'] } }),
      BlockedIP.aggregate([
        { $match: { companyId: req.user.companyId, reverted: false } },
        { $group: { _id: '$method', count: { $sum: 1 } } },
      ]),
    ]);
    const recent = await BlockedIP.find({ companyId: req.user.companyId, blockedAt: { $gte: since } })
      .sort({ blockedAt: -1 }).limit(20).lean();
    res.json({ total, auto, manual, byMethod, recent, period: '24h' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /rules — list firewall rules for a company ────────────────────────────
// SECURITY: companyId is ALWAYS sourced from the authenticated JWT.
// Superadmin may optionally pass ?companyId= to inspect another company.
// All other roles are strictly limited to their own company.
router.get('/rules', async (req, res) => {
  try {
    let companyId;
    if (req.user.role === 'superadmin' && req.query.companyId) {
      companyId = req.query.companyId;
    } else {
      // Non-superadmin: always use own companyId, never trust query param
      companyId = req.user.companyId?.toString();
    }

    if (!companyId) {
      return res.status(400).json({ message: 'company_id is required — request rejected' });
    }

    const rules = await BlockedIP.find({ companyId }).sort({ blockedAt: -1 }).lean();
    const formattedRules = rules.map(r => ({
      _id: r._id, type: 'ip', value: r.ip, direction: 'inbound',
      action: 'block', protocol: 'all', enabled: !r.reverted,
      reason: r.reason, blockedBy: r.blockedBy, createdAt: r.blockedAt,
      // Include companyId in response for audit trail
      companyId: r.companyId?.toString(),
    }));
    res.json({
      rules: formattedRules,
      blocked: rules.filter(r => !r.reverted).map(r => r.ip),
      companyId, // echo back which company was queried
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── POST /rules — add a new firewall rule ─────────────────────────────────────
// SECURITY: companyId is ALWAYS taken from the authenticated JWT.
// Any companyId supplied in the request body is IGNORED to prevent
// cross-company rule injection by a malicious or compromised client.
router.post('/rules', requireManager, async (req, res) => {
  try {
    const { type, value, direction, action, protocol } = req.body;
    // STRICT: never accept companyId from request body
    const companyId = req.user.companyId?.toString();

    if (!companyId) {
      return res.status(400).json({ message: 'company_id is required — request rejected' });
    }
    if (!value) return res.status(400).json({ message: 'value required' });

    if (type === 'ip' && action === 'block') {
      const result = await blockIP({
        ip: value,
        reason: `Firewall rule: ${type}=${value} dir=${direction} proto=${protocol}`,
        companyId, blockedBy: 'analyst',
      });
      return res.json({ ok: true, rule: result, companyId });
    }
    const entry = await BlockedIP.create({
      ip: `${type}:${value}`, companyId,
      reason: `Firewall rule: ${type}=${value} dir=${direction} action=${action} proto=${protocol}`,
      blockedBy: 'analyst', method: 'firewall_rule',
    });
    res.json({ ok: true, rule: entry, companyId });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
