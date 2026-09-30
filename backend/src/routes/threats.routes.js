/**
 * threats.routes.js
 * Dedicated /api/threats endpoint for threat summary.
 * Uses logarithmic scoring from shared securityScore utility.
 *
 * GET /api/threats            — threat summary: totalThreats, criticalRisks, score, top10, health
 * GET /api/threats/top        — top 10 most severe recent alerts
 * GET /api/threats/summary    — severity breakdown + score
 */
const router   = require('express').Router();
const mongoose = require('mongoose');
const Alert    = require('../models/Alert.model');
const System   = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { calculateScore } = require('../utils/securityScore');
const BlockedIP = require('../models/BlockedIP.model');

router.use(authenticate, requireAnalyst);

// Normalize severity to lowercase canonical form
function normalizeSev(s) {
  const m = { critical: 'critical', high: 'high', medium: 'medium', low: 'low' };
  return m[(s || '').toLowerCase()] || 'low';
}

// ── GET /api/threats — full threat overview ────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const deptParam  = req.query.departmentId;
    const hoursBack  = parseInt(req.query.hours) || 168; // default 7d
    const since      = new Date(Date.now() - hoursBack * 3600000);
    const cid        = new mongoose.Types.ObjectId(companyId);

    const base = { companyId: cid, createdAt: { $gte: since } };
    if (deptParam) base.departmentId = new mongoose.Types.ObjectId(deptParam);
    else if (role === 'department_admin' && departmentId)
      base.departmentId = new mongoose.Types.ObjectId(departmentId);

    const [sevAgg, top10, systemCount] = await Promise.all([
      // Severity counts
      Alert.aggregate([
        { $match: base },
        { $group: { _id: { $toLower: '$severity' }, count: { $sum: 1 } } },
      ]),

      // Top 10 most recent critical/high alerts
      Alert.find({ ...base, severity: { $in: ['critical', 'high'] } })
        .sort({ createdAt: -1 })
        .limit(10)
        .populate('systemId', 'name hostname')
        .populate('departmentId', 'name')
        .lean(),

      // Get all blocks for this company to cross-reference
      BlockedIP.find({ companyId: cid, reverted: false }).select('ip srcip alertId blockedBy blockedAt').lean(),

      // Active system count
      System.countDocuments({ companyId: cid, isActive: true }),
    ]);

    // Aggregate severity
    const sev = { critical: 0, high: 0, medium: 0, low: 0 };
    sevAgg.forEach(r => { if (sev[normalizeSev(r._id)] !== undefined) sev[normalizeSev(r._id)] += r.count; });

    const totalThreats  = sev.critical + sev.high + sev.medium + sev.low;
    const criticalRisks = sev.critical + sev.high;

    // Logarithmic scoring (shared engine)
    const scoreResult  = totalThreats === 0 ? { score: 100, systemHealth: 'Healthy' } : calculateScore(sev);
    const securityScore = scoreResult.score;
    const systemHealth  = scoreResult.systemHealth;

    res.json({
      totalThreats,
      criticalRisks,
      securityScore: Math.round(securityScore),
      systemHealth,
      systemCount,
      severity: sev,
      top10Alerts: top10.map(a => ({
        id:          a._id,
        description: a.description,
        severity:    normalizeSev(a.severity),
        source:      a.source || a.eventCategory || 'unknown',
        srcip:       a.srcip,
        system:      a.systemId?.name || a.agentName || '—',
        department:  a.departmentId?.name || '—',
        timestamp:   a.createdAt,
        status:      a.status,
        eventCategory: a.eventCategory,
      })),
      period: { hours: hoursBack, since },
      generatedAt: new Date(),
    });
  } catch (err) {
    console.error('[threats]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/threats/top — top 10 alerts (paginated) ─────────────────────
router.get('/top', async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const limit  = Math.min(parseInt(req.query.limit) || 10, 50);
    const since  = new Date(Date.now() - 7 * 24 * 3600000);
    const cid    = new mongoose.Types.ObjectId(companyId);

    const base = { companyId: cid, createdAt: { $gte: since } };
    if (role === 'department_admin' && departmentId)
      base.departmentId = new mongoose.Types.ObjectId(departmentId);

    const alerts = await Alert.find(base)
      .sort({ createdAt: -1 })
      .limit(limit)
      .populate('systemId', 'name hostname')
      .populate('departmentId', 'name')
      .lean();

    // Ensure consistent severity format
    const normalized = alerts.map(a => ({
      ...a,
      severity: normalizeSev(a.severity),
    }));

    res.json({ alerts: normalized, count: normalized.length });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/threats/summary — severity breakdown only ────────────────────
router.get('/summary', async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const hours  = parseInt(req.query.hours) || 168;
    const since  = new Date(Date.now() - hours * 3600000);
    const cid    = new mongoose.Types.ObjectId(companyId);

    const base = { companyId: cid, createdAt: { $gte: since } };
    if (role === 'department_admin' && departmentId)
      base.departmentId = new mongoose.Types.ObjectId(departmentId);

    const [sevAgg, byCategory] = await Promise.all([
      Alert.aggregate([
        { $match: base },
        { $group: { _id: { $toLower: '$severity' }, count: { $sum: 1 } } },
      ]),
      Alert.aggregate([
        { $match: base },
        { $group: { _id: '$eventCategory', count: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity','critical'] }, 1, 0] } } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
    ]);

    const sev = { critical: 0, high: 0, medium: 0, low: 0 };
    sevAgg.forEach(r => { if (sev[normalizeSev(r._id)] !== undefined) sev[normalizeSev(r._id)] += r.count; });

    const totalThreats = sev.critical + sev.high + sev.medium + sev.low;
    const scoreResult  = totalThreats === 0 ? { score: 100 } : calculateScore(sev);

    res.json({
      severity: sev,
      byCategory,
      totalThreats,
      criticalRisks: sev.critical + sev.high,
      securityScore: scoreResult.score,
      period: { hours, since },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
