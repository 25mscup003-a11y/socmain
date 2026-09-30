/**
 * Ransomware & Encryption Detection routes
 * Base: /api/ransomware
 */
const router = require('express').Router();
const mongoose = require('mongoose');
const Alert  = require('../models/Alert.model');
const System = require('../models/System.model');
const RansomwareConfig = require('../models/RansomwareConfig.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireDeptAdmin } = require('../middleware/auth.middleware');

router.use(authenticate, requireDeptAdmin);

const RANSOM_RULE_IDS = [
  'RANSOMWARE_NOTE', 'RANSOMWARE_EXTENSION', 'RANSOMWARE_MASS_ENCRYPTION',
  'RANSOMWARE_MASS_DELETION', 'RANSOMWARE_HIGH_ENTROPY', 'RANSOMWARE_SHADOW_DELETE',
  'RANSOMWARE_ENCRYPTION_PROC', 'RANSOMWARE_BACKUP_TAMPER', 'RANSOMWARE_VSS_DELETED',
  'RANSOMWARE_SHADOW', 'RANSOMWARE_EXT',
];

const RANSOM_FILTER = {
  $or: [
    { ruleId: { $in: RANSOM_RULE_IDS } },
    { source: 'ransomware' },
    { malwareType: 'Ransomware' },
  ],
};

const CONFIG_DEFAULTS = Object.freeze({
  enabled: true,
  windowSeconds: 30,
  massModificationThreshold: 50,
  massDeletionThreshold: 30,
  entropyThreshold: 7,
  entropyFileTrigger: 10,
  alertCooldownSeconds: 120,
  customExtensions: [],
  protectedDirectories: [],
  version: 1,
});

const BUILT_IN_RULES = Object.freeze([
  { id: 'RANSOMWARE_MASS_ENCRYPTION', name: 'Mass File Encryption', category: 'Impact', severity: 'critical', description: 'Detect rapid modification or rename activity combined with high file entropy.' },
  { id: 'RANSOMWARE_MASS_DELETION', name: 'Mass File Deletion', category: 'Impact', severity: 'critical', description: 'Detect destructive bulk deletion inside the configured time window.' },
  { id: 'RANSOMWARE_HIGH_ENTROPY', name: 'High Entropy Activity', category: 'Encryption', severity: 'critical', description: 'Detect multiple newly encrypted or compressed files.' },
  { id: 'RANSOMWARE_NOTE', name: 'Ransom Note Creation', category: 'File', severity: 'critical', description: 'Detect known ransom-note filenames and recovery instructions.' },
  { id: 'RANSOMWARE_EXTENSION', name: 'Ransomware Extension', category: 'File', severity: 'critical', description: 'Detect known and company-defined ransomware file extensions.' },
  { id: 'RANSOMWARE_SHADOW_DELETE', name: 'Shadow Copy Command', category: 'Recovery', severity: 'critical', description: 'Detect command-line attempts to delete or resize shadow copies.' },
  { id: 'RANSOMWARE_VSS_DELETED', name: 'Volume Shadow Copy Removed', category: 'Recovery', severity: 'critical', description: 'Detect a reduction in Windows Volume Shadow Copy inventory.' },
  { id: 'RANSOMWARE_BACKUP_TAMPER', name: 'Backup Service Tampering', category: 'Recovery', severity: 'critical', description: 'Detect backup service stop, deletion, or recovery tampering.' },
  { id: 'RANSOMWARE_ENCRYPTION_PROC', name: 'Suspicious Encryption Process', category: 'Process', severity: 'high', description: 'Detect suspicious encryption tools and scripted encryption commands.' },
]);
const RULE_IDS = new Set(BUILT_IN_RULES.map(rule => rule.id));
const RULE_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);

function builtInRulesFor(configuration = {}) {
  const overrides = configuration.builtInRuleOverrides || {};
  return BUILT_IN_RULES.map(rule => ({ ...rule, enabled: overrides[rule.id]?.enabled !== false, severity: overrides[rule.id]?.severity || rule.severity }));
}

function boundedNumber(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function normalizedList(value, { maxItems, maxLength, extension = false }) {
  const input = Array.isArray(value) ? value : String(value || '').split(/[\n,]/);
  const values = input.map(item => String(item || '').trim()).filter(Boolean).slice(0, maxItems);
  const normalized = values.map(item => {
    const clean = item.replace(/\0/g, '').slice(0, maxLength);
    return extension && !clean.startsWith('.') ? `.${clean}` : clean;
  });
  if (extension && normalized.some(item => !/^\.[a-z0-9_-]{1,31}$/i.test(item))) {
    throw Object.assign(new Error('Custom extensions may contain only letters, numbers, underscore and hyphen'), { status: 400 });
  }
  return [...new Set(normalized.map(item => extension ? item.toLowerCase() : item))];
}

function sanitizeConfiguration(body = {}) {
  const protectedDirectories = normalizedList(body.protectedDirectories, { maxItems: 100, maxLength: 512 });
  if (protectedDirectories.some(item => !/^(?:[a-z]:[\\/]|\/)/i.test(item) || /(?:^|[\\/])\.\.(?:[\\/]|$)/.test(item))) {
    throw Object.assign(new Error('Protected directories must be absolute paths without parent traversal'), { status: 400 });
  }
  return {
    enabled: body.enabled !== false,
    windowSeconds: Math.round(boundedNumber(body.windowSeconds, 30, 5, 300)),
    massModificationThreshold: Math.round(boundedNumber(body.massModificationThreshold, 50, 2, 10000)),
    massDeletionThreshold: Math.round(boundedNumber(body.massDeletionThreshold, 30, 2, 10000)),
    entropyThreshold: boundedNumber(body.entropyThreshold, 7, 0, 8),
    entropyFileTrigger: Math.round(boundedNumber(body.entropyFileTrigger, 10, 1, 1000)),
    alertCooldownSeconds: Math.round(boundedNumber(body.alertCooldownSeconds, 120, 10, 86400)),
    customExtensions: normalizedList(body.customExtensions, { maxItems: 100, maxLength: 32, extension: true }),
    protectedDirectories,
  };
}

async function currentConfiguration(companyId) {
  return (await RansomwareConfig.findOne({ companyId }).lean()) || CONFIG_DEFAULTS;
}

// ─── Agent-backed detector configuration ────────────────────────────────────
router.get('/configuration', async (req, res) => {
  try {
    const config = await currentConfiguration(req.user.companyId);
    const targetCount = await System.countDocuments({ companyId: req.user.companyId, isActive: { $ne: false } });
    res.json({ configuration: { ...CONFIG_DEFAULTS, ...(config || {}) }, rules: builtInRulesFor(config), targetCount });
  } catch (err) {
    res.status(500).json({ message: 'Unable to load ransomware configuration' });
  }
});

router.patch('/configuration/rules/:ruleId', async (req, res) => {
  try {
    const ruleId = String(req.params.ruleId || '').toUpperCase();
    if (!RULE_IDS.has(ruleId)) return res.status(404).json({ message: 'Ransomware rule not found' });
    const severity = String(req.body.severity || '').toLowerCase();
    if (!RULE_SEVERITIES.has(severity)) return res.status(400).json({ message: 'Invalid rule severity' });
    const current = await currentConfiguration(req.user.companyId);
    const builtInRuleOverrides = {
      ...(current.builtInRuleOverrides || {}),
      [ruleId]: { enabled: req.body.enabled !== false, severity },
    };
    const configuration = await RansomwareConfig.findOneAndUpdate(
      { companyId: req.user.companyId },
      { $set: {
        tenantId: req.user.tenantId || null,
        builtInRuleOverrides,
        version: Number(current.version || 0) + 1,
        lastDeployedAt: new Date(),
        lastDeployedBy: req.user.id || req.user._id,
      } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    if (req.user.tenantId && (req.user.id || req.user._id)) {
      await SocAuditEvent.create({
        tenantId: req.user.tenantId,
        companyId: req.user.companyId,
        actorId: req.user.id || req.user._id,
        action: 'ransomware.rule.updated',
        targetType: 'RansomwareConfig',
        targetId: ruleId,
        metadata: { enabled: req.body.enabled !== false, severity, version: configuration.version },
        ipAddress: req.ip || '',
      });
    }
    const rule = builtInRulesFor(configuration).find(item => item.id === ruleId);
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('ransomware:configuration-updated', { version: configuration.version, ruleId });
    res.json({ message: `${rule.name} rule updated and queued for agent synchronization.`, rule, version: configuration.version });
  } catch (err) {
    res.status(err instanceof mongoose.Error.ValidationError ? 400 : 500).json({ message: 'Unable to update ransomware rule' });
  }
});

router.put('/configuration', async (req, res) => {
  try {
    const settings = sanitizeConfiguration(req.body);
    const existing = await RansomwareConfig.findOne({ companyId: req.user.companyId }).select('version').lean();
    const configuration = await RansomwareConfig.findOneAndUpdate(
      { companyId: req.user.companyId },
      { $set: {
        ...settings,
        tenantId: req.user.tenantId || null,
        version: Number(existing?.version || 0) + 1,
        lastDeployedAt: new Date(),
        lastDeployedBy: req.user.id || req.user._id,
      } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    if (req.user.tenantId && (req.user.id || req.user._id)) {
      await SocAuditEvent.create({
        tenantId: req.user.tenantId,
        companyId: req.user.companyId,
        actorId: req.user.id || req.user._id,
        action: 'ransomware.configuration.updated',
        targetType: 'RansomwareConfig',
        targetId: String(configuration._id),
        metadata: { version: configuration.version, fields: Object.keys(settings) },
        ipAddress: req.ip || '',
      });
    }
    const targetCount = await System.countDocuments({ companyId: req.user.companyId, isActive: { $ne: false } });
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('ransomware:configuration-updated', {
      version: configuration.version,
    });
    res.json({
      message: `Ransomware policy saved for ${targetCount} agent(s); agents apply it on their next heartbeat.`,
      configuration,
      targetCount,
    });
  } catch (err) {
    res.status(err.status || (err instanceof mongoose.Error.ValidationError ? 400 : 500)).json({
      message: err.status ? err.message : 'Unable to save ransomware configuration',
    });
  }
});

// ─── KPI stats ────────────────────────────────────────────────────────────────
router.get('/stats', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d  = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const base     = { companyId, ...RANSOM_FILTER };

    const [
      total, critical, today,
      ransomNotes, shadowDeletes, massEncryptions,
      affectedHosts, topMalware,
      backupTamper, vssDeleted,
    ] = await Promise.all([
      Alert.countDocuments({ ...base, createdAt: { $gte: since7d } }),
      Alert.countDocuments({ ...base, severity: 'critical', createdAt: { $gte: since7d } }),
      Alert.countDocuments({ ...base, createdAt: { $gte: since24h } }),
      Alert.countDocuments({ companyId, ruleId: 'RANSOMWARE_NOTE' }),
      Alert.countDocuments({ companyId, ruleId: { $in: ['RANSOMWARE_SHADOW_DELETE', 'RANSOMWARE_VSS_DELETED'] } }),
      Alert.countDocuments({ companyId, ruleId: 'RANSOMWARE_MASS_ENCRYPTION' }),
      Alert.distinct('hostname', { ...base, createdAt: { $gte: since7d } }),
      Alert.aggregate([
        { $match: { companyId, ...RANSOM_FILTER, createdAt: { $gte: since7d } } },
        { $group: { _id: '$processName', count: { $sum: 1 } } },
        { $sort: { count: -1 } }, { $limit: 10 },
      ]),
      Alert.countDocuments({ companyId, ruleId: 'RANSOMWARE_BACKUP_TAMPER' }),
      Alert.countDocuments({ companyId, ruleId: 'RANSOMWARE_VSS_DELETED' }),
    ]);

    res.json({
      total, critical, today,
      ransomNotes, shadowDeletes, massEncryptions,
      affectedHosts: affectedHosts.length,
      topMalware, backupTamper, vssDeleted,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Timeline trend ───────────────────────────────────────────────────────────
router.get('/trend', async (req, res) => {
  try {
    const { companyId } = req.user;
    const days = parseInt(req.query.days) || 14;
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);

    const data = await Alert.aggregate([
      { $match: { companyId, ...RANSOM_FILTER, createdAt: { $gte: since } } },
      {
        $group: {
          _id: {
            date:   { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            ruleId: '$ruleId',
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

// ─── Threat type breakdown ────────────────────────────────────────────────────
router.get('/type-breakdown', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    const data = await Alert.aggregate([
      { $match: { companyId, ...RANSOM_FILTER, createdAt: { $gte: since } } },
      { $group: { _id: '$ruleId', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
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
    const { page = 1, limit = 50, severity, hostname, ruleId, search } = req.query;

    const filter = { companyId, ...RANSOM_FILTER };
    if (severity) filter.severity = severity;
    if (hostname) filter.hostname = { $regex: hostname, $options: 'i' };
    if (ruleId)   filter.ruleId   = ruleId;
    if (search) {
      filter.$and = [
        RANSOM_FILTER,
        {
          $or: [
            { description: { $regex: search, $options: 'i' } },
            { hostname:    { $regex: search, $options: 'i' } },
            { filePath:    { $regex: search, $options: 'i' } },
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

// ─── Entropy heatmap data ─────────────────────────────────────────────────────
router.get('/entropy', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const data = await Alert.find(
      { companyId, ruleId: 'RANSOMWARE_HIGH_ENTROPY', createdAt: { $gte: since } },
      { hostname: 1, description: 1, createdAt: 1, severity: 1, riskScore: 1 }
    ).sort({ createdAt: -1 }).limit(200).lean();
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ─── Live activity feed ───────────────────────────────────────────────────────
router.get('/live', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 15 * 60 * 1000); // last 15 min
    const docs = await Alert.find(
      { companyId, ...RANSOM_FILTER, createdAt: { $gte: since } }
    ).sort({ createdAt: -1 }).limit(50).lean();
    res.json(docs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
