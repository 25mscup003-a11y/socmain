/**
 * /api/log-monitor — Log Monitoring Dashboard API
 * Role-based: superadmin > company_admin > department_admin > analyst
 */
const router  = require('express').Router();
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const Alert   = require('../models/Alert.model');

// ── helpers ────────────────────────────────────────────────────────────────────
function buildFilter(user, query = {}) {
  const filter = {};

  // Scope by role
  if (user.role === 'superadmin') {
    if (query.companyId) filter.companyId = query.companyId;
  } else {
    filter.companyId = user.companyId;
    if (user.role === 'department_admin' || user.role === 'analyst') {
      if (user.departmentId) filter.departmentId = user.departmentId;
    }
    if (query.departmentId && user.role === 'company_admin') {
      filter.departmentId = query.departmentId;
    }
  }

  // Time range (explicit date range takes priority over hours)
  const now = new Date();
  if (query.fromDate || query.toDate) {
    filter.createdAt = {};
    if (query.fromDate) filter.createdAt.$gte = new Date(query.fromDate);
    if (query.toDate)   filter.createdAt.$lte = new Date(query.toDate + 'T23:59:59');
  } else {
    const hours = parseInt(query.hours) || 24;
    filter.createdAt = { $gte: new Date(now - hours * 3600000) };
  }

  // IP filter
  if (query.ip) filter.$or = [{ srcip: query.ip }, { destIp: query.ip }];

  // Severity filter (canonical lowercase)
  const SEV_VALUES = ['critical','high','medium','low'];
  if (query.severity && SEV_VALUES.includes(query.severity.toLowerCase())) {
    filter.severity = query.severity.toLowerCase();
  }

  // Source/type filter (eventCategory)
  if (query.eventCategory) {
    filter.eventCategory = query.eventCategory;
  }

  // Status filter (map to severity/status fields we have)
  if (query.status === 'failed') {
    filter.$or = [
      ...(filter.$or || []),
      { eventCategory: 'edr', description: /fail/i },
      { severity: 'critical' },
      { severity: 'high' },
    ];
  } else if (query.status === 'success') {
    filter.severity = { $in: ['low', 'medium'] };
  }

  return filter;
}

// ── GET /api/log-monitor/stats ─────────────────────────────────────────────────
router.get('/stats', authenticate, requireAnalyst, async (req, res) => {
  try {
    const filter = buildFilter(req.user, req.query);

    // Phase 1: Fast counts (use indexes, no aggregation)
    const [total, sevCritical, sevHigh, sevMedium, sevLow, failedLogins] =
      await Promise.all([
        Alert.countDocuments(filter),
        Alert.countDocuments({ ...filter, severity: 'critical' }),
        Alert.countDocuments({ ...filter, severity: 'high' }),
        Alert.countDocuments({ ...filter, severity: 'medium' }),
        Alert.countDocuments({ ...filter, severity: 'low' }),
        Alert.countDocuments({
          ...filter,
          $or: [
            { description: /fail/i },
            { eventCategory: 'edr', userAction: /fail/i },
          ],
        }),
      ]);

    const sevMap = { critical: sevCritical, high: sevHigh, medium: sevMedium, low: sevLow };
    const suspiciousCount = sevCritical + sevHigh;

    // Phase 2: Aggregations (run after counts are done)
    const [byCategory, topIps, overTime] = await Promise.all([
      Alert.aggregate([
        { $match: filter },
        { $group: { _id: '$eventCategory', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 8 },
      ]),
      Alert.aggregate([
        { $match: { ...filter, srcip: { $exists: true, $ne: null } } },
        { $group: { _id: '$srcip', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      Alert.aggregate([
        { $match: filter },
        {
          $group: {
            _id: {
              $dateToString: {
                format: parseInt(req.query.hours) > 48 ? '%Y-%m-%d' : '%Y-%m-%dT%H:00',
                date: '$createdAt',
              },
            },
            count: { $sum: 1 },
          },
        },
        { $sort: { _id: 1 } },
      ]),
    ]);

    res.json({
      role: req.user.role,
      total,
      severity: sevMap,
      byCategory,
      topIps,
      overTime,
      failedLogins,
      suspiciousCount,
      generatedAt: new Date(),
    });
  } catch (err) {
    console.error('[log-monitor] stats error:', err);
    res.status(500).json({ message: 'Failed to load log monitor stats' });
  }
});


// ── GET /api/log-monitor/stream — paginated live log feed ─────────────────────
router.get('/stream', authenticate, requireAnalyst, async (req, res) => {
  try {
    const filter = buildFilter(req.user, req.query);
    const page   = parseInt(req.query.page)  || 1;
    const limit  = parseInt(req.query.limit) || 30;

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .select('description severity eventCategory srcip destPort createdAt agentName systemId departmentId status username')
        .populate('systemId', 'name hostname')
        .populate('departmentId', 'name')
        .lean(),
      Alert.countDocuments(filter),
    ]);

    res.json({ alerts, total, page, pages: Math.ceil(total / limit) });
  } catch (err) {
    console.error('[log-monitor] stream error:', err);
    res.status(500).json({ message: 'Failed to load log stream' });
  }
});

// ── POST /api/log-monitor/seed — populate test data (for development) ──────────
router.post('/seed', authenticate, requireAnalyst, async (req, res) => {
  try {
    const companyId = req.user.companyId || req.body.companyId;
    const count = parseInt(req.body.count) || 25;

    if (!companyId) {
      return res.status(400).json({ message: 'companyId required' });
    }

    // Check if data already exists
    const existing = await Alert.countDocuments({ companyId });
    if (existing > 0) {
      return res.json({
        ok: true,
        message: `Already have ${existing} alerts for this company. Skipping seed.`,
        skipped: existing,
      });
    }

    const seedAlerts = [];
    const sources = ['web-server', 'firewall', 'ids', 'antivirus', 'edr', 'usb-monitor'];
    const categories = ['malware', 'network', 'file', 'system', 'edr', 'usb', 'other'];
    const severities = ['low', 'medium', 'high', 'critical'];
    const ips = [
      '192.168.1.100', '192.168.1.105', '10.0.0.50', '10.0.0.75',
      '172.16.0.200', '203.0.113.42', '198.51.100.89', '192.168.50.50'
    ];
    const descriptions = [
      'Suspicious file access detected',
      'Unsuccessful login attempt detected',
      'Malware signature matched',
      'Unauthorized network connection',
      'USB device connected',
      'Privilege escalation attempt',
      'Data exfiltration risk detected',
      'Configuration change detected',
      'Service restart detected',
      'Failed authentication from remote host',
      'Port scan detected from external IP',
      'Database query with high privilege',
      'Certificate validation failed',
      'System command execution detected',
      'Memory injection attempt detected',
      'Browser history modification detected',
      'Registry modification detected',
      'Ransomware file signature identified',
      'C2 communication detected',
      'Lateral movement attempt detected',
    ];

    for (let i = 0; i < count; i++) {
      const now = new Date();
      const randomHours = Math.floor(Math.random() * 24);
      const randomMinutes = Math.floor(Math.random() * 60);

      seedAlerts.push({
        companyId,
        source: sources[i % sources.length],
        ruleId: `RULE_${i.toString().padStart(3, '0')}`,
        description: descriptions[i % descriptions.length],
        eventCategory: categories[i % categories.length],
        severity: severities[i % severities.length],
        srcip: ips[i % ips.length],
        destip: '10.0.0.1',
        destPort: 80 + (i % 1000),
        protocol: i % 3 === 0 ? 'udp' : 'tcp',
        agentName: `Agent-${Math.floor(i / 4) + 1}`,
        status: i % 5 === 0 ? 'resolved' : (i % 3 === 0 ? 'investigating' : 'open'),
        createdAt: new Date(now.getTime() - (randomHours * 60 + randomMinutes) * 60000),
      type: `TYPE_${i % sources.length}`,
      isSynthetic: true,
      dataOrigin: 'synthetic',
      });
    }

    const created = await Alert.insertMany(seedAlerts);
    res.status(201).json({
      ok: true,
      created: created.length,
      message: `Generated ${created.length} test alerts for demo/development`,
    });
  } catch (err) {
    console.error('[log-monitor] seed error:', err);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
