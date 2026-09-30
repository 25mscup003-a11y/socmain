/**
 * LOLBins Detection routes
 * Base: /api/lolbins
 */
const router = require('express').Router();
const Alert  = require('../models/Alert.model');
const { authenticate, requireDeptAdmin } = require('../middleware/auth.middleware');

router.use(authenticate, requireDeptAdmin);

const LOLBIN_FILTER = {
  $or: [
    { ruleId: 'LOLBIN_DETECTED' },
    { source: 'lolbins' },
    { malwareType: 'LolBin' },
  ],
};

// ─── KPI Stats ───────────────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d  = new Date(Date.now() - 7  * 24 * 60 * 60 * 1000);

    const base = { companyId, ...LOLBIN_FILTER };

    const [total, critical, today, endpoints, topLolbins, topUsers, mitreMap] = await Promise.all([
      Alert.countDocuments({ ...base, createdAt: { $gte: since7d } }),
      Alert.countDocuments({ ...base, severity: 'critical', createdAt: { $gte: since7d } }),
      Alert.countDocuments({ ...base, createdAt: { $gte: since24h } }),
      Alert.distinct('hostname', { ...base, createdAt: { $gte: since7d } }),
      Alert.aggregate([
        { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since7d } } },
        { $group: { _id: '$processName', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 10 },
      ]),
      Alert.aggregate([
        { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since7d }, username: { $ne: '' } } },
        { $group: { _id: '$username', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 10 },
      ]),
      Alert.aggregate([
        { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since7d }, mitreId: { $ne: '' } } },
        { $group: { _id: '$mitreId', technique: { $first: '$technique' }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
    ]);

    res.json({
      total, critical, today,
      activeEndpoints: endpoints.length,
      topLolbins, topUsers, mitreMap,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Detection trend ──────────────────────────────────────────────────────────
router.get('/trend', async (req, res) => {
  try {
    const { companyId } = req.user;
    const days = parseInt(req.query.days) || 7;
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const data = await Alert.aggregate([
      { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since } } },
      {
        $group: {
          _id: {
            date:     { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            severity: '$severity',
          },
          count: { $sum: 1 },
        },
      },
      { $sort: { '_id.date': 1 } },
    ]);
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Top parent processes ─────────────────────────────────────────────────────
router.get('/top-parents', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const data = await Alert.aggregate([
      { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since }, parentProcessName: { $ne: '' } } },
      { $group: { _id: '$parentProcessName', count: { $sum: 1 } } },
      { $sort: { count: -1 } }, { $limit: 10 },
    ]);
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Alerts list ──────────────────────────────────────────────────────────────
router.get('/alerts', async (req, res) => {
  try {
    const { companyId } = req.user;
    const { page = 1, limit = 50, severity, hostname, search } = req.query;

    const filter = { companyId, ...LOLBIN_FILTER };
    if (severity) filter.severity = severity;
    if (hostname) filter.hostname = { $regex: hostname, $options: 'i' };
    if (search) {
      filter.$and = [
        LOLBIN_FILTER,
        {
          $or: [
            { processName:    { $regex: search, $options: 'i' } },
            { processCmdline: { $regex: search, $options: 'i' } },
            { description:    { $regex: search, $options: 'i' } },
            { username:       { $regex: search, $options: 'i' } },
            { hostname:       { $regex: search, $options: 'i' } },
          ],
        },
      ];
      delete filter.$or;
    }

    const [docs, total] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .lean(),
      Alert.countDocuments(filter),
    ]);

    res.json({ docs, total, page: Number(page), limit: Number(limit) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Risk score distribution ──────────────────────────────────────────────────
router.get('/risk-distribution', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const data = await Alert.aggregate([
      { $match: { companyId, ...LOLBIN_FILTER, createdAt: { $gte: since }, riskScore: { $exists: true } } },
      {
        $bucket: {
          groupBy: '$riskScore',
          boundaries: [0, 20, 40, 60, 80, 101],
          default: 'other',
          output: { count: { $sum: 1 } },
        },
      },
    ]);
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
