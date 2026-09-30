/**
 * correlation.routes.js
 * API for correlation events (multi-step attack chains).
 *
 * GET  /api/correlation         — list correlation events
 * GET  /api/correlation/stats   — summary counts
 * GET  /api/correlation/:id     — single event detail
 * PATCH /api/correlation/:id    — update status/notes
 * POST  /api/correlation/run    — manually trigger correlation engine
 */
const router  = require('express').Router();
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const Alert = require('../models/Alert.model');
const CorrelationRule = require('../models/CorrelationRule.model');
const BuiltInCorrelationOverride = require('../models/BuiltInCorrelationOverride.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const { detectCorrelations } = require('../services/correlation.service');
const { getUserDataFilter } = require('../services/socAccess.service');
const mongoose = require('mongoose');

const SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const STATUSES = new Set(['all', 'open', 'investigating', 'resolved', 'false_positive', 'benign']);
const RULE_ROLES = new Set(['superadmin', 'company_admin', 'soc_manager', 'l3_analyst']);
const CUSTOM_RULE_ROLES = new Set([...RULE_ROLES, 'department_admin']);

async function correlationScope(req, { personal = false } = {}) {
  const { filter } = await getUserDataFilter(req.user, { personal });
  if (!filter.companyId?.$in?.length) return { _id: null };
  const requestedCompanyId = String(req.query?.companyId || req.body?.companyId || '');
  if (requestedCompanyId) {
    const allowed = filter.companyId.$in.map(String);
    if (!allowed.includes(requestedCompanyId)) {
      const error = new Error('Company outside authorized correlation scope');
      error.status = 403;
      throw error;
    }
    filter.companyId = { $in: [requestedCompanyId] };
  }
  return filter;
}

async function writeAudit(req, action, event, metadata = {}) {
  if (!req.user.tenantId || !req.user.id) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId, companyId: event.companyId, actorId: req.user.id,
    action, targetType: 'CorrelationEvent', targetId: String(event._id), metadata,
    ipAddress: String(req.ip || '').slice(0, 100),
  });
}

function validDate(value) {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

async function resolveRuleDepartment(companyId, departmentId) {
  if (!departmentId) return null;
  if (!mongoose.isValidObjectId(departmentId)) {
    const error = new Error('Invalid department');
    error.status = 400;
    throw error;
  }
  const department = await Department.findOne({ _id: departmentId, companyId }).select('_id').lean();
  if (!department) {
    const error = new Error('Department is outside the selected company');
    error.status = 403;
    throw error;
  }
  return department._id;
}

async function resolveAuthorizedRuleDepartment(req, companyId, departmentId) {
  if (req.user.role === 'department_admin') {
    if (!req.user.departmentId) {
      const error = new Error('Department assignment required');
      error.status = 403;
      throw error;
    }
    departmentId = req.user.departmentId;
  }
  return resolveRuleDepartment(companyId, departmentId);
}

function customRuleScope(req, scope) {
  return {
    companyId: scope.companyId,
    ...(req.user.role === 'department_admin' ? { departmentId: req.user.departmentId } : {}),
  };
}

router.use(authenticate);

// Companies visible in the correlation workspace. SOC Manager and L3 users
// use this to select an explicit tenant before changing rules or running the
// engine; the server still enforces the assignment scope for every request.
router.get('/companies', requireAnalyst, async (req, res) => {
  try {
    const scope = await correlationScope(req);
    const companies = await Company.find({ _id: scope.companyId }).select('_id name status').sort({ name: 1 }).lean();
    res.json({ companies });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── GET /api/correlation — list with filters ──────────────────────────────────
router.get('/', requireAnalyst, async (req, res) => {
  try {
    const { severity, status, page = 1, limit = 20, from, to, search, sort = 'newest' } = req.query;
    const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, Number.parseInt(limit, 10) || 20));
    const filter = await correlationScope(req, { personal: ['analyst', 'l1_analyst', 'l2_analyst'].includes(req.user.role) });
    if (severity && !SEVERITIES.has(severity)) return res.status(400).json({ message: 'Invalid severity' });
    if (status && !STATUSES.has(status)) return res.status(400).json({ message: 'Invalid status' });

    if (severity) filter.severity = severity;
    // No status means full correlation-match history. Consumers that only need
    // the active queue must explicitly request open/investigating.
    if (status && status !== 'all') filter.status = status;
    if (search) {
      const escaped = String(search).slice(0, 100).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      filter.$or = [
        { incidentId: { $regex: escaped, $options: 'i' } },
        { patternName: { $regex: escaped, $options: 'i' } },
        { agentName: { $regex: escaped, $options: 'i' } },
      ];
    }
    if (from || to) {
      if ((from && !validDate(from)) || (to && !validDate(to))) return res.status(400).json({ message: 'Invalid date range' });
      filter.createdAt = {};
      if (from) filter.createdAt.$gte = validDate(from);
      if (to)   filter.createdAt.$lte = validDate(to);
    }

    const [events, total] = await Promise.all([
      CorrelationEvent.find(filter)
        .sort(sort === 'risk' ? { riskScore: -1, lastActivityAt: -1 } : { lastActivityAt: -1, createdAt: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
        .populate('alertIds', 'description severity eventCategory source ruleId createdAt')
        .populate('systemId', 'name hostname')
        .lean(),
      CorrelationEvent.countDocuments(filter),
    ]);

    res.json({ events, total, page: safePage, limit: safeLimit, totalPages: Math.max(1, Math.ceil(total / safeLimit)) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/correlation/stats ────────────────────────────────────────────────
router.get('/stats', requireAnalyst, async (req, res) => {
  try {
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const scope = await correlationScope(req, { personal: ['analyst', 'l1_analyst', 'l2_analyst'].includes(req.user.role) });
    const base  = { ...scope, createdAt: { $gte: since } };
    // Open work must not disappear from the dashboard merely because it is
    // older than the seven-day activity window.
    const activeBase = { ...scope, status: { $in: ['open', 'investigating'] } };
    // Mongoose casts find/count filters, but aggregation $match values are not
    // cast automatically. Convert scoped IDs so severity/pattern charts use
    // the same tenant records as the headline counts.
    const aggregateActiveBase = {
      ...activeBase,
      companyId: { $in: (scope.companyId?.$in || []).map(id => new mongoose.Types.ObjectId(id)) },
      ...(scope.departmentId?.$in
        ? { departmentId: { $in: scope.departmentId.$in.map(id => new mongoose.Types.ObjectId(id)) } }
        : scope.departmentId ? { departmentId: new mongoose.Types.ObjectId(scope.departmentId) } : {}),
    };

    const correlationService = require('../services/correlation.service');
    const alertBase = correlationService.correlationEligibleFilter(scope.companyId, new Date(Date.now() - 24 * 60 * 60 * 1000));
    if (scope.departmentId) alertBase.departmentId = scope.departmentId;
    const [total, active, rejected, bySeverity, byPattern, openCritical, eventsAnalyzed24h, latestAlert, customRuleCount, disabledBuiltInCount] = await Promise.all([
      CorrelationEvent.countDocuments(base),
      CorrelationEvent.countDocuments(activeBase),
      CorrelationEvent.countDocuments({ ...base, status: 'false_positive' }),
      CorrelationEvent.aggregate([
        { $match: aggregateActiveBase },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ]),
      CorrelationEvent.aggregate([
        { $match: aggregateActiveBase },
        { $group: { _id: '$patternName', count: { $sum: 1 }, severity: { $first: '$severity' } } },
        { $sort: { count: -1 } },
        { $limit: 10 },
      ]),
      CorrelationEvent.countDocuments({ ...activeBase, severity: 'critical' }),
      Alert.countDocuments(alertBase),
      Alert.findOne(alertBase).sort({ createdAt: -1 }).select('createdAt agentName eventCategory').lean(),
      CorrelationRule.countDocuments({ companyId: scope.companyId, enabled: true, ...(req.user.role === 'department_admin' ? { departmentId: req.user.departmentId } : {}) }),
      BuiltInCorrelationOverride.countDocuments({ companyId: scope.companyId, enabled: false }),
    ]);

    res.json({
      total, active, rejected, bySeverity, byPattern, openCritical, period: '7d',
      eventsAnalyzed24h, lastEventAt: latestAlert?.createdAt || null,
      ruleCount: Math.max(0, correlationService.PATTERNS.length - disabledBuiltInCount) + customRuleCount,
      edrCapabilityCoverage: new Set(Object.values(correlationService.EDR_CAPABILITY_COVERAGE).flat()).size,
      edrCapabilityTotal: 31,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Configurable company-scoped rules. Built-ins remain code-reviewed rules; these
// records are deliberately constrained to a safe condition DSL.
router.get('/rules', requireAnalyst, async (req, res) => {
  try {
    const scope = await correlationScope(req);
    const [rules, overrides] = await Promise.all([
      CorrelationRule.find(customRuleScope(req, scope)).sort({ updatedAt: -1 }).populate('departmentId', 'name').lean(),
      BuiltInCorrelationOverride.find({ companyId: scope.companyId }).lean(),
    ]);
    const correlationService = require('../services/correlation.service');
    const overrideByPattern = new Map(overrides.map(item => [item.patternId, item]));
    const builtInRules = correlationService.PATTERNS.map(pattern => {
      const defaults = correlationService.publicPattern(pattern);
      const override = overrideByPattern.get(pattern.id);
      if (!override) return { ...defaults, overridden: false };
      const effective = correlationService.publicPattern(correlationService.applyBuiltInOverride(pattern, override));
      return { ...effective, enabled: override.enabled, overridden: true, overrideId: override._id, defaults };
    });
    res.json({ rules, builtInRules, total: rules.length + builtInRules.length });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.patch('/rules/built-in/:patternId', requireAnalyst, async (req, res) => {
  try {
    if (!RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'L3 or SOC management access required' });
    const correlationService = require('../services/correlation.service');
    const pattern = correlationService.PATTERNS.find(item => item.id === String(req.params.patternId || '').toUpperCase());
    if (!pattern) return res.status(404).json({ message: 'Built-in correlation rule not found' });
    const scope = await correlationScope(req);
    const companyId = req.user.companyId && scope.companyId.$in.map(String).includes(String(req.user.companyId))
      ? String(req.user.companyId) : scope.companyId.$in.length === 1 ? String(scope.companyId.$in[0]) : '';
    if (!companyId) return res.status(400).json({ message: 'Select one company before editing a built-in rule' });

    const defaults = correlationService.publicPattern(pattern);
    const defaultRisk = defaults.riskScore ?? ({ low: 50, medium: 68, high: 82, critical: 92 }[defaults.severity] || 70);
    const riskScoreMin = Number(req.body.riskScoreMin ?? defaults.riskScoreMin ?? defaultRisk);
    const riskScoreMax = Number(req.body.riskScoreMax ?? defaults.riskScoreMax ?? defaultRisk);
    if (!Number.isFinite(riskScoreMin) || !Number.isFinite(riskScoreMax)
      || riskScoreMin < 0 || riskScoreMax > 100 || riskScoreMin > riskScoreMax) {
      return res.status(400).json({ message: 'Risk score range must be between 0 and 100, with start less than or equal to end' });
    }
    const update = {
      enabled: Object.hasOwn(req.body, 'enabled') ? req.body.enabled : true,
      name: Object.hasOwn(req.body, 'name') ? req.body.name : defaults.name,
      description: Object.hasOwn(req.body, 'description') ? req.body.description : defaults.description,
      severity: Object.hasOwn(req.body, 'severity') ? req.body.severity : defaults.severity,
      confidence: Object.hasOwn(req.body, 'confidence') ? req.body.confidence : defaults.confidence,
      timeWindowSeconds: Object.hasOwn(req.body, 'timeWindowSeconds') ? req.body.timeWindowSeconds : defaults.timeWindowSeconds,
      riskScoreMin, riskScoreMax, riskScore: Math.round((riskScoreMin + riskScoreMax) / 2),
      tenantId: req.user.tenantId || null, updatedBy: req.user.id,
    };
    const override = await BuiltInCorrelationOverride.findOneAndUpdate(
      { companyId, patternId: pattern.id }, { $set: update }, { new: true, upsert: true, runValidators: true, setDefaultsOnInsert: true }
    );
    res.json(override);
  } catch (err) { res.status(err.code === 11000 ? 409 : 400).json({ message: err.message }); }
});

router.delete('/rules/built-in/:patternId', requireAnalyst, async (req, res) => {
  try {
    if (!RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'L3 or SOC management access required' });
    const scope = await correlationScope(req);
    const companyId = req.user.companyId && scope.companyId.$in.map(String).includes(String(req.user.companyId))
      ? String(req.user.companyId) : scope.companyId.$in.length === 1 ? String(scope.companyId.$in[0]) : '';
    if (!companyId) return res.status(400).json({ message: 'Select one company before resetting a built-in rule' });
    await BuiltInCorrelationOverride.deleteOne({ companyId, patternId: String(req.params.patternId || '').toUpperCase() });
    res.json({ ok: true, message: 'Built-in rule restored to production defaults' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.post('/rules', requireAnalyst, async (req, res) => {
  try {
    if (!CUSTOM_RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'Department Admin, L3, or SOC management access required' });
    const riskScoreMin = Number(req.body.riskScoreMin);
    const riskScoreMax = Number(req.body.riskScoreMax);
    if (!Number.isFinite(riskScoreMin) || !Number.isFinite(riskScoreMax)
      || riskScoreMin < 0 || riskScoreMax > 100 || riskScoreMin > riskScoreMax) {
      return res.status(400).json({ message: 'Risk score range must be between 0 and 100, with start less than or equal to end' });
    }
    const scope = await correlationScope(req);
    const companyId = String(req.body.companyId || req.user.companyId || '');
    if (!scope.companyId.$in.map(String).includes(companyId)) return res.status(403).json({ message: 'Company outside authorized scope' });
    const departmentId = await resolveAuthorizedRuleDepartment(req, companyId, req.body.departmentId);
    const rule = await CorrelationRule.create({
      ...req.body, _id: undefined, riskScore: Math.round((riskScoreMin + riskScoreMax) / 2),
      companyId, departmentId, tenantId: req.user.tenantId || null, createdBy: req.user.id, updatedBy: req.user.id,
    });
    res.status(201).json(rule);
  } catch (err) { res.status(err.code === 11000 ? 409 : 400).json({ message: err.message }); }
});

router.patch('/rules/:id', requireAnalyst, async (req, res) => {
  try {
    if (!CUSTOM_RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'Department Admin, L3, or SOC management access required' });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule' });
    const scope = await correlationScope(req);
    if (Object.hasOwn(req.body, 'riskScoreMin') || Object.hasOwn(req.body, 'riskScoreMax')) {
      const riskScoreMin = Number(req.body.riskScoreMin);
      const riskScoreMax = Number(req.body.riskScoreMax);
      if (!Number.isFinite(riskScoreMin) || !Number.isFinite(riskScoreMax)
        || riskScoreMin < 0 || riskScoreMax > 100 || riskScoreMin > riskScoreMax) {
        return res.status(400).json({ message: 'Risk score range must be between 0 and 100, with start less than or equal to end' });
      }
      req.body.riskScore = Math.round((riskScoreMin + riskScoreMax) / 2);
    }
    const allowed = ['name','description','enabled','severity','riskScore','riskScoreMin','riskScoreMax','confidence','logic','conditions','entityFields','threshold','timeWindowSeconds','dataSources','eventTypes','mitreTactics','mitreTechniques','tags'];
    const update = Object.fromEntries(allowed.filter(key => Object.hasOwn(req.body, key)).map(key => [key, req.body[key]]));
    if (Object.hasOwn(req.body, 'departmentId')) {
      const companyId = scope.companyId.$in.length === 1 ? scope.companyId.$in[0] : req.body.companyId;
      if (!companyId || !scope.companyId.$in.map(String).includes(String(companyId))) {
        return res.status(403).json({ message: 'Company outside authorized scope' });
      }
      update.departmentId = await resolveAuthorizedRuleDepartment(req, companyId, req.body.departmentId);
    }
    update.updatedBy = req.user.id;
    const rule = await CorrelationRule.findOneAndUpdate({ _id: req.params.id, ...customRuleScope(req, scope) }, update, { new: true, runValidators: true });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    res.json(rule);
  } catch (err) { res.status(err.code === 11000 ? 409 : 400).json({ message: err.message }); }
});

router.delete('/rules/:id', requireAnalyst, async (req, res) => {
  try {
    if (!CUSTOM_RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'Department Admin, L3, or SOC management access required' });
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule' });
    const scope = await correlationScope(req);
    const rule = await CorrelationRule.findOneAndDelete({ _id: req.params.id, ...customRuleScope(req, scope) });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    res.json({ ok: true, id: rule._id, message: 'Correlation rule deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/correlation/:id ──────────────────────────────────────────────────
router.get('/:id', requireAnalyst, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid correlation event' });
    const detailFilter = { _id: req.params.id, ...(await correlationScope(req, { personal: ['analyst', 'l1_analyst', 'l2_analyst'].includes(req.user.role) })) };
    const event = await CorrelationEvent.findOne(detailFilter)
      .populate('alertIds', 'description severity eventCategory srcip filePath processName userAction createdAt agentName')
      .populate('relatedAlertIds', 'description severity eventCategory srcip destip filePath processName userAction createdAt agentName')
      .populate('systemId', 'name hostname ip os')
      .populate('assignedTo', 'name email')
      .populate('linkedIncidentId', 'title status severity assignedTo createdAt')
      .lean();

    if (!event) return res.status(404).json({ message: 'Correlation event not found' });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── PATCH /api/correlation/:id ────────────────────────────────────────────────
router.patch('/:id', requireAnalyst, async (req, res) => {
  try {
    const { status, notes, assignedTo, verdict, reason } = req.body;
    const update = {};
    const allowedStatuses = ['open', 'investigating', 'resolved', 'false_positive', 'benign'];
    const allowedVerdicts = ['undetermined', 'true_positive', 'false_positive', 'benign'];
    if (status && !allowedStatuses.includes(status)) return res.status(400).json({ message: 'Invalid status' });
    if (status) update.status = status;
    if (typeof notes === 'string') update.notes = notes.slice(0, 4000);
    if (assignedTo && !['superadmin','company_admin','soc_manager'].includes(req.user.role)) return res.status(403).json({ message: 'SOC management access required to assign' });
    if (assignedTo && !mongoose.isValidObjectId(assignedTo)) return res.status(400).json({ message: 'Invalid analyst' });
    if (assignedTo) update.assignedTo = assignedTo;
    if (verdict && !allowedVerdicts.includes(verdict)) return res.status(400).json({ message: 'Invalid verdict' });
    if (verdict && verdict !== 'undetermined' && !String(reason || '').trim()) return res.status(400).json({ message: 'A disposition reason is required' });
    if (verdict) {
      update.verdict = verdict; update.dispositionReason = String(reason || '').trim().slice(0, 4000);
      update.dispositionBy = req.user.id; update.dispositionAt = new Date();
      if (verdict === 'false_positive' || verdict === 'benign') update.status = verdict;
    }
    if (['resolved', 'false_positive'].includes(status)) update.resolvedAt = new Date();
    if (status && !['resolved', 'false_positive'].includes(status)) update.resolvedAt = null;
    if (status || typeof notes === 'string') {
      update.$push = { resolutionHistory: {
        status: status || 'note', notes: String(notes || '').slice(0, 4000),
        changedBy: req.user.id, changedAt: new Date(),
      } };
    }

    const updateDoc = { $set: Object.fromEntries(Object.entries(update).filter(([key]) => key !== '$push')) };
    if (update.$push) updateDoc.$push = update.$push;
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid correlation event' });
    const eventFilter = { _id: req.params.id, ...(await correlationScope(req, { personal: ['analyst', 'l1_analyst', 'l2_analyst'].includes(req.user.role) })) };
    const event = await CorrelationEvent.findOneAndUpdate(
      eventFilter, updateDoc, { new: true },
    );
    if (!event) return res.status(404).json({ message: 'Not found' });
    await writeAudit(req, verdict ? `correlation.${verdict}` : status ? `correlation.status.${status}` : assignedTo ? 'correlation.assigned' : 'correlation.noted', event, { reason: update.dispositionReason || '', assignedTo: assignedTo || null });
    const io = req.app.get('io');
    io?.to(`company:${event.companyId}`).emit('correlation:updated', { change: 'status', event });
    io?.to('superadmin').emit('correlation:updated', { change: 'status', event });
    res.json(event);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/correlation/run — manually trigger engine ───────────────────────
router.post('/run', requireAnalyst, async (req, res) => {
  try {
    if (!RULE_ROLES.has(req.user.role)) return res.status(403).json({ message: 'L3 or SOC management access required' });
    const scope = await correlationScope(req);
    const companyIds = scope.companyId?.$in || [];
    if (!companyIds.length) return res.status(400).json({ message: 'An assigned company context is required' });
    const detected = [];
    for (const companyId of companyIds) {
      const matches = await detectCorrelations(String(companyId), { io: req.app.get('io') });
      detected.push(...matches);
    }

    res.json({ ok: true, companiesProcessed: companyIds.length, detected: detected.length, events: detected });
  } catch (err) {
    console.error('[correlation/run]', err.message);
    res.status(err.status || 500).json({ message: err.message });
  }
});

module.exports = router;
