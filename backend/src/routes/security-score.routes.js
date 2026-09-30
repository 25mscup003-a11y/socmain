/**
 * security-score.routes.js — HIGH PERFORMANCE REAL-TIME SCORING ENGINE
 *
 * Performance Optimizations:
 *  - 100% Single-Pass MongoDB $facet Aggregations (replaces 11+ sequential queries)
 *  - Single-Pass 30-Day Daily Aggregation (replaces 30 sequential loop queries)
 *  - Single-Pass System Alert Aggregation (replaces N-system loop queries)
 *  - 10-Second In-Memory TTL Caching to shield DB during rapid socket bursts
 */

const router   = require('express').Router();
const mongoose = require('mongoose');
const Alert    = require('../models/Alert.model');
const System   = require('../models/System.model');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const {
  calculateScore,
  calculateCategoryScore,
  scoreToGrade,
  scoreToRisk,
  scoreToHealth,
  CATEGORY_CONFIG,
} = require('../utils/securityScore');

router.use(authenticate, requireAnalyst);

// Per-category display weights
const WEIGHTS = {
  file_violations:      CATEGORY_CONFIG.fileViolations?.weight      || 1.5,
  usb_violations:       CATEGORY_CONFIG.usbViolations?.weight       || 2.5,
  network_attacks:      CATEGORY_CONFIG.networkAttacks?.weight      || 1.5,
  malware_events:       CATEGORY_CONFIG.malwareEvents?.weight       || 4,
  login_failures:       CATEGORY_CONFIG.loginFailures?.weight       || 1,
  unresolved_critical:  CATEGORY_CONFIG.unresolvedCritical?.weight  || 5,
  privilege_escalation: CATEGORY_CONFIG.privilege_escalation?.weight|| 3,
  ransomware:           CATEGORY_CONFIG.ransomware?.weight          || 5,
  reverse_shell:        CATEGORY_CONFIG.reverse_shell?.weight       || 4.5,
};

// Simple In-Memory Cache (TTL: 10 seconds)
const scoreCache = new Map();
const CACHE_TTL_MS = 10000;

function getCached(key) {
  const item = scoreCache.get(key);
  if (item && Date.now() - item.time < CACHE_TTL_MS) {
    return item.data;
  }
  return null;
}

function setCached(key, data) {
  scoreCache.set(key, { time: Date.now(), data });
}

async function getEffectiveCompanyId(req) {
  if (req.query.companyId && mongoose.Types.ObjectId.isValid(req.query.companyId)) {
    return req.query.companyId;
  }
  if (req.user?.companyId && mongoose.Types.ObjectId.isValid(req.user.companyId)) {
    return req.user.companyId.toString();
  }
  const Company = require('../models/Company.model');
  const comp = await Company.findOne({ status: 'active' }).select('_id').lean() || await Company.findOne({}).select('_id').lean();
  if (comp) return comp._id.toString();
  return null;
}

/**
 * Optimized Core Score Engine using single $facet aggregation pass
 */
async function computeScore(companyId, { from, to, departmentId } = {}) {
  const start = from ? new Date(from) : new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
  const end   = to   ? new Date(to)   : new Date();
  
  if (!companyId || !mongoose.Types.ObjectId.isValid(companyId)) {
    return buildResult(100, { critical: 0, high: 0, medium: 0, low: 0 }, { critical: 0, high: 0, medium: 0, low: 0 }, { file_violations: 0, usb_violations: 0, network_attacks: 0, malware_events: 0, login_failures: 0, unresolved_critical: 0, privilege_escalation: 0, ransomware: 0, reverse_shell: 0 }, {}, start, end, 0);
  }

  const cid  = new mongoose.Types.ObjectId(companyId);
  const base = { companyId: cid, createdAt: { $gte: start, $lte: end } };
  if (departmentId && mongoose.Types.ObjectId.isValid(departmentId)) {
    base.departmentId = new mongoose.Types.ObjectId(departmentId);
  }

  // ── Single-pass $facet query ───────────────────────────────────────────────
  const [facetResult] = await Alert.aggregate([
    { $match: base },
    {
      $facet: {
        sevAgg: [
          {
            $group: {
              _id: {
                $cond: [
                  { $in: ['$severity', ['critical', 'high', 'medium', 'low']] },
                  '$severity',
                  'low'
                ]
              },
              count: { $sum: 1 }
            }
          }
        ],
        countsRaw: [
          {
            $group: {
              _id: null,
              fileV: { $sum: { $cond: [{ $eq: ['$eventCategory', 'file'] }, 1, 0] } },
              usbV: { $sum: { $cond: [{ $eq: ['$eventCategory', 'usb'] }, 1, 0] } },
              netA: { $sum: { $cond: [{ $eq: ['$eventCategory', 'network'] }, 1, 0] } },
              malwareA: { $sum: { $cond: [{ $eq: ['$eventCategory', 'malware'] }, 1, 0] } },
              loginF: { $sum: { $cond: [{ $and: [{ $eq: ['$eventCategory', 'edr'] }, { $in: ['$userAction', ['failed_login', 'auth_failure', 'brute_force']] }] }, 1, 0] } },
              unresC: { $sum: { $cond: [{ $and: [{ $eq: ['$severity', 'critical'] }, { $in: ['$status', ['open', 'investigating']] }] }, 1, 0] } },
              privEsc: { $sum: { $cond: [{ $eq: ['$userAction', 'privilege_escalation'] }, 1, 0] } },
              ransomware: { $sum: { $cond: [{ $eq: ['$userAction', 'ransomware_detected'] }, 1, 0] } },
              revShell: { $sum: { $cond: [{ $eq: ['$userAction', 'reverse_shell'] }, 1, 0] } },
            }
          }
        ]
      }
    }
  ]);

  const sevAgg = facetResult?.sevAgg || [];
  const raw    = facetResult?.countsRaw?.[0] || {};

  const fileV      = raw.fileV || 0;
  const usbV       = raw.usbV || 0;
  const netA       = raw.netA || 0;
  const malwareA   = raw.malwareA || 0;
  const loginF     = raw.loginF || 0;
  const unresC     = raw.unresC || 0;
  const privEsc    = raw.privEsc || 0;
  const ransomware = raw.ransomware || 0;
  const revShell   = raw.revShell || 0;

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  sevAgg.forEach(r => {
    const key = r._id && sevCounts[r._id] !== undefined ? r._id : 'low';
    sevCounts[key] += r.count;
  });

  const totalAlerts = sevCounts.critical + sevCounts.high + sevCounts.medium + sevCounts.low;

  if (totalAlerts === 0) {
    return buildResult(100, sevCounts, { critical:0,high:0,medium:0,low:0 }, { file_violations:0,usb_violations:0,network_attacks:0,malware_events:0,login_failures:0,unresolved_critical:0,privilege_escalation:0,ransomware:0,reverse_shell:0 }, {}, start, end, totalAlerts);
  }

  const sevResult = calculateScore(sevCounts);
  const categoryCounts = {
    fileViolations:      fileV,
    usbViolations:       usbV,
    networkAttacks:      netA,
    malwareEvents:       malwareA,
    loginFailures:       loginF,
    unresolvedCritical:  unresC,
    privilege_escalation: privEsc,
    ransomware,
    reverse_shell:       revShell,
  };
  const catResult = calculateCategoryScore(categoryCounts);
  const finalScore = Math.min(sevResult.score, catResult.score);

  const counts = {
    file_violations:      fileV,
    usb_violations:       usbV,
    network_attacks:      netA,
    malware_events:       malwareA,
    login_failures:       loginF,
    unresolved_critical:  unresC,
    privilege_escalation: privEsc,
    ransomware,
    reverse_shell:        revShell,
  };

  const deductions = {};
  const catKeyMap = {
    file_violations:      'fileViolations',
    usb_violations:       'usbViolations',
    network_attacks:      'networkAttacks',
    malware_events:       'malwareEvents',
    login_failures:       'loginFailures',
    unresolved_critical:  'unresolvedCritical',
    privilege_escalation: 'privilege_escalation',
    ransomware:           'ransomware',
    reverse_shell:        'reverse_shell',
  };
  for (const [displayKey, catKey] of Object.entries(catKeyMap)) {
    deductions[displayKey] = catResult.deductions[catKey] || 0;
  }

  return buildResult(finalScore, sevCounts, sevResult.deductions, counts, deductions, start, end, totalAlerts);
}

function buildResult(score, sevCounts, sevDeductionDetails, counts, deductions, start, end, totalAlerts) {
  return {
    score,
    grade:        scoreToGrade(score),
    risk:         scoreToRisk(score),
    systemHealth: scoreToHealth(score),
    counts,
    deductions,
    severity:           sevCounts,
    severityDeductions: sevDeductionDetails,
    totalAlerts,
    criticalAlerts:     sevCounts.critical,
    highAlerts:         sevCounts.high,
    period:             { from: start, to: end },
  };
}

// ── GET /api/security-score ───────────────────────────────────────────────────
router.get('/', async (req, res) => {
  try {
    const companyId = await getEffectiveCompanyId(req);
    const cacheKey = `score_${companyId}_${req.query.from || ''}_${req.query.to || ''}`;
    const cached = getCached(cacheKey);
    if (cached) return res.json(cached);

    const result = await computeScore(companyId, {
      from: req.query.from,
      to:   req.query.to,
      departmentId: req.user.role === 'department_admin' ? req.user.departmentId?.toString() : null,
    });
    setCached(cacheKey, result);
    res.json(result);
  } catch (err) {
    console.error('[security-score]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/security-score/history — Single-Pass 30-Day Aggregation ────────
router.get('/history', async (req, res) => {
  try {
    const companyId = await getEffectiveCompanyId(req);
    const cacheKey = `history_${companyId}`;
    const cached = getCached(cacheKey);
    if (cached) return res.json(cached);

    if (!companyId || !mongoose.Types.ObjectId.isValid(companyId)) {
      const days = Array.from({ length: 30 }, (_, i) => {
        const from = new Date(Date.now() - (29 - i) * 86400000);
        return { date: from.toISOString().slice(0, 10), score: 100, alerts: 0, severity: { critical: 0, high: 0, medium: 0, low: 0 } };
      });
      return res.json({ history: days });
    }

    const cid = new mongoose.Types.ObjectId(companyId);
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    // Single-pass MongoDB aggregation grouping by YYYY-MM-DD
    const agg = await Alert.aggregate([
      { $match: { companyId: cid, createdAt: { $gte: thirtyDaysAgo } } },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            severity: {
              $cond: [
                { $in: ['$severity', ['critical', 'high', 'medium', 'low']] },
                '$severity',
                'low'
              ]
            }
          },
          count: { $sum: 1 }
        }
      }
    ]);

    // Map aggregated results by date
    const dateMap = {};
    agg.forEach(item => {
      const d = item._id.date;
      const s = item._id.severity || 'low';
      if (!dateMap[d]) dateMap[d] = { critical: 0, high: 0, medium: 0, low: 0 };
      dateMap[d][s] = (dateMap[d][s] || 0) + item.count;
    });

    const days = [];
    for (let i = 29; i >= 0; i--) {
      const dateStr = new Date(Date.now() - i * 86400000).toISOString().slice(0, 10);
      const sev = dateMap[dateStr] || { critical: 0, high: 0, medium: 0, low: 0 };
      const total = sev.critical + sev.high + sev.medium + sev.low;

      let score = 100;
      if (total > 0) {
        score = calculateScore(sev).score;
      }

      days.push({
        date: dateStr,
        score: Math.round(score),
        alerts: total,
        severity: sev,
      });
    }

    const payload = { history: days };
    setCached(cacheKey, payload);
    res.json(payload);
  } catch (err) {
    console.error('[security-score/history]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/security-score/breakdown ────────────────────────────────────────
router.get('/breakdown', async (req, res) => {
  try {
    const companyId = await getEffectiveCompanyId(req);
    const cacheKey = `breakdown_${companyId}`;
    const cached = getCached(cacheKey);
    if (cached) return res.json(cached);

    const result = await computeScore(companyId);
    const breakdown = Object.entries(result.counts).map(([category, count]) => ({
      category:  category.replace(/_/g, ' '),
      count,
      weight:    WEIGHTS[category] || 1,
      deduction: result.deductions[category] || 0,
      impact:    count === 0 ? 'none' : (result.deductions[category] || 0) >= 10 ? 'high' : 'medium',
    })).sort((a, b) => b.deduction - a.deduction);

    const payload = {
      score:       result.score,
      grade:       result.grade,
      risk:        result.risk,
      breakdown,
      severity:    result.severity,
      totalAlerts: result.totalAlerts,
    };
    setCached(cacheKey, payload);
    res.json(payload);
  } catch (err) {
    console.error('[security-score/breakdown]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/security-score/systems — Single-Pass System Alert Aggregation ────
router.get('/systems', async (req, res) => {
  try {
    const companyId = await getEffectiveCompanyId(req);
    const cacheKey = `systems_${companyId}`;
    const cached = getCached(cacheKey);
    if (cached) return res.json(cached);

    if (!companyId || !mongoose.Types.ObjectId.isValid(companyId)) {
      return res.json({ systems: [] });
    }

    const cid          = new mongoose.Types.ObjectId(companyId);
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const ONLINE_THRESHOLD = 5 * 60 * 1000;
    const now = Date.now();

    // Run System query and Single-Pass Alert Aggregation concurrently
    const [systems, sysAlertAgg] = await Promise.all([
      System.find({ companyId: cid, isActive: true })
        .populate('departmentId', 'name')
        .select('name hostname ip macAddress os osVersion agentId agentVersion status lastSeen edrEnabled idsEnabled ipsEnabled firewallEnabled departmentId installDate')
        .lean(),

      Alert.aggregate([
        { $match: { companyId: cid, systemId: { $ne: null }, createdAt: { $gte: sevenDaysAgo } } },
        {
          $group: {
            _id: {
              systemId: "$systemId",
              severity: {
                $cond: [
                  { $in: ['$severity', ['critical', 'high', 'medium', 'low']] },
                  '$severity',
                  'low'
                ]
              }
            },
            count: { $sum: 1 }
          }
        }
      ])
    ]);

    // Map aggregated alerts per system ID
    const sysAlertMap = {};
    sysAlertAgg.forEach(item => {
      const sId = item._id.systemId?.toString();
      const sev = item._id.severity || 'low';
      if (sId) {
        if (!sysAlertMap[sId]) sysAlertMap[sId] = { critical: 0, high: 0, medium: 0, low: 0 };
        sysAlertMap[sId][sev] = (sysAlertMap[sId][sev] || 0) + item.count;
      }
    });

    const results = systems.map(sys => {
      const sev = sysAlertMap[sys._id.toString()] || { critical: 0, high: 0, medium: 0, low: 0 };
      const total = sev.critical + sev.high + sev.medium + sev.low;

      let score = 100;
      if (total > 0) {
        score = calculateScore(sev).score;
      }

      const risk = scoreToRisk(score);
      const isOnline = sys.lastSeen && (now - new Date(sys.lastSeen).getTime()) < ONLINE_THRESHOLD;
      return { ...sys, score: Math.round(score), risk, total, severity: sev, isOnline };
    });

    results.sort((a, b) => a.score - b.score);
    const payload = { systems: results };
    setCached(cacheKey, payload);
    res.json(payload);
  } catch (err) {
    console.error('[security-score/systems]', err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
