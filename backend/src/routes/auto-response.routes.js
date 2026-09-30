/**
 * Automated response API. Commands are allowlisted and are delivered through the
 * existing agent Socket.IO/heartbeat channel; this route never accepts a shell command.
 */
const router = require('express').Router();
const AutomatedResponse = require('../models/AutomatedResponse.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const { authenticate, requireDeptAdmin, requireCompanyAdmin } = require('../middleware/auth.middleware');
const {
  SUPPORTED_ACTIONS, ACTIVE_STATUSES, isHighRisk, createResponse, dispatchResponse, transition,
} = require('../services/automatedResponse.service');

router.use(authenticate, requireDeptAdmin);

const SUCCESS = ['successful', 'success'];
const FAILED = ['failed', 'timed_out', 'rollback_failed'];
const PENDING = ['waiting_approval', 'pending'];
const asNumber = (value, fallback, max = 200) => Math.min(max, Math.max(1, Number(value) || fallback));

function responseFilter(companyId, query = {}) {
  const filter = { companyId };
  if (query.status) filter.status = query.status;
  if (query.actionType) filter.actionType = query.actionType;
  if (query.hostname) filter.hostname = { $regex: String(query.hostname).slice(0, 120), $options: 'i' };
  if (query.search) {
    const search = String(query.search).slice(0, 120);
    filter.$or = [
      { threatName: { $regex: search, $options: 'i' } },
      { hostname: { $regex: search, $options: 'i' } },
      { actionResult: { $regex: search, $options: 'i' } },
    ];
  }
  return filter;
}

function emit(io, companyId, event, body) {
  if (io) io.to(`company:${companyId}`).emit(event, body);
}

router.get('/supported-actions', (req, res) => {
  res.json([...SUPPORTED_ACTIONS].map(actionType => ({
    actionType,
    risk: isHighRisk(actionType) ? 'high' : 'low',
    approvalRequired: isHighRisk(actionType),
  })));
});

router.get('/stats', async (req, res) => {
  try {
    const { companyId } = req.user;
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const match = { companyId };
    const [total, active, success, failed, pending, isolated, quarantined, blockedIps, blockedDomains, killedProcs, avg] = await Promise.all([
      AutomatedResponse.countDocuments(match),
      AutomatedResponse.countDocuments({ ...match, status: { $in: [...ACTIVE_STATUSES] } }),
      AutomatedResponse.countDocuments({ ...match, status: { $in: SUCCESS }, createdAt: { $gte: since } }),
      AutomatedResponse.countDocuments({ ...match, status: { $in: FAILED }, createdAt: { $gte: since } }),
      AutomatedResponse.countDocuments({ ...match, status: { $in: PENDING } }),
      AutomatedResponse.countDocuments({ ...match, actionType: 'isolate', status: { $in: SUCCESS } }),
      AutomatedResponse.countDocuments({ ...match, actionType: 'quarantine_file', status: { $in: SUCCESS } }),
      AutomatedResponse.countDocuments({ ...match, actionType: 'block_ip', status: { $in: SUCCESS } }),
      AutomatedResponse.countDocuments({ ...match, actionType: 'block_domain', status: { $in: SUCCESS } }),
      AutomatedResponse.countDocuments({ ...match, actionType: { $in: ['kill_process', 'kill_process_tree'] }, status: { $in: SUCCESS } }),
      AutomatedResponse.aggregate([
        { $match: { ...match, status: { $in: SUCCESS }, executionTimeMs: { $gt: 0 } } },
        { $group: { _id: null, value: { $avg: '$executionTimeMs' } } },
      ]),
    ]);
    const completed = success + failed;
    res.json({
      total, active, success, failed, pending, isolated, quarantined, blockedIps, blockedDomains, killedProcs,
      successRate: completed ? Math.round((success / completed) * 100) : 0,
      avgResponseTime: Math.round(avg[0]?.value || 0),
      mttr: Math.round((avg[0]?.value || 0) / 1000),
      windowHours: 24,
    });
  } catch (err) { res.status(500).json({ message: 'Unable to load response statistics' }); }
});

router.get('/trend', async (req, res) => {
  try {
    const days = asNumber(req.query.days, 7, 90);
    const since = new Date(Date.now() - days * 86400000);
    const data = await AutomatedResponse.aggregate([
      { $match: { companyId: req.user.companyId, createdAt: { $gte: since } } },
      { $group: { _id: { date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }, status: '$status' }, count: { $sum: 1 } } },
      { $sort: { '_id.date': 1 } },
    ]);
    res.json(data);
  } catch (err) { res.status(500).json({ message: 'Unable to load response trend' }); }
});

router.get('/distribution', async (req, res) => {
  try {
    const data = await AutomatedResponse.aggregate([
      { $match: { companyId: req.user.companyId } },
      { $group: { _id: '$actionType', count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 15 },
    ]);
    res.json(data);
  } catch (err) { res.status(500).json({ message: 'Unable to load response distribution' }); }
});

router.get('/top-hosts', async (req, res) => {
  try {
    const data = await AutomatedResponse.aggregate([
      { $match: { companyId: req.user.companyId, hostname: { $ne: '' } } },
      { $group: { _id: '$hostname', count: { $sum: 1 }, systemId: { $first: '$systemId' } } },
      { $sort: { count: -1 } }, { $limit: 10 },
    ]);
    res.json(data);
  } catch (err) { res.status(500).json({ message: 'Unable to load affected endpoints' }); }
});

router.get('/pending-approvals', async (req, res) => {
  try {
    const docs = await AutomatedResponse.find({ companyId: req.user.companyId, status: { $in: PENDING } })
      .sort({ createdAt: -1 }).limit(asNumber(req.query.limit, 50)).populate('alertId', 'description severity ruleId').lean();
    res.json({ docs, total: docs.length });
  } catch (err) { res.status(500).json({ message: 'Unable to load pending approvals' }); }
});

router.get('/playbooks', async (req, res) => {
  try {
    const docs = await ResponsePlaybook.find({ companyId: req.user.companyId }).sort({ priority: 1, createdAt: -1 }).lean();
    res.json(docs);
  } catch (err) { res.status(500).json({ message: 'Unable to load response policies' }); }
});

router.post('/playbooks', requireCompanyAdmin, async (req, res) => {
  try {
    const steps = Array.isArray(req.body.steps) ? req.body.steps : [];
    if (!req.body.name || !steps.length || steps.some(step => !SUPPORTED_ACTIONS.has(step.actionType))) {
      return res.status(400).json({ message: 'A policy name and one or more supported actions are required' });
    }
    const doc = await ResponsePlaybook.create({ ...req.body, steps, companyId: req.user.companyId, createdBy: req.user.id, updatedBy: req.user.id });
    emit(req.app.get('io'), req.user.companyId, 'autoresponse:policy-updated', { id: String(doc._id), enabled: doc.enabled });
    res.status(201).json(doc);
  } catch (err) { res.status(400).json({ message: 'Unable to create response policy' }); }
});

router.put('/playbooks/:id', requireCompanyAdmin, async (req, res) => {
  try {
    if (req.body.steps && (!Array.isArray(req.body.steps) || req.body.steps.some(step => !SUPPORTED_ACTIONS.has(step.actionType)))) {
      return res.status(400).json({ message: 'Policy contains an unsupported action' });
    }
    const doc = await ResponsePlaybook.findOneAndUpdate({ _id: req.params.id, companyId: req.user.companyId }, { ...req.body, updatedBy: req.user.id }, { new: true, runValidators: true });
    if (!doc) return res.status(404).json({ message: 'Response policy not found' });
    emit(req.app.get('io'), req.user.companyId, 'autoresponse:policy-updated', { id: String(doc._id), enabled: doc.enabled });
    res.json(doc);
  } catch (err) { res.status(400).json({ message: 'Unable to update response policy' }); }
});

router.post('/playbooks/:id/test', requireCompanyAdmin, async (req, res) => {
  try {
    const playbook = await ResponsePlaybook.findOne({ _id: req.params.id, companyId: req.user.companyId }).lean();
    const alert = req.body.alertId && await Alert.findOne({ _id: req.body.alertId, companyId: req.user.companyId }).lean();
    if (!playbook || !alert) return res.status(404).json({ message: 'Policy or source alert not found' });
    const { playbookMatches } = require('../services/automatedResponse.service');
    res.json({ matches: playbookMatches(alert, playbook), simulation: true, actions: playbook.steps || [] });
  } catch (err) { res.status(400).json({ message: 'Unable to test response policy' }); }
});

router.delete('/playbooks/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await ResponsePlaybook.findOneAndDelete({ _id: req.params.id, companyId: req.user.companyId });
    if (!doc) return res.status(404).json({ message: 'Response policy not found' });
    res.json({ message: 'Response policy deleted' });
  } catch (err) { res.status(500).json({ message: 'Unable to delete response policy' }); }
});

router.get('/endpoint-status/:systemId', async (req, res) => {
  try {
    const last = await AutomatedResponse.findOne({ companyId: req.user.companyId, systemId: req.params.systemId, actionType: { $in: ['isolate', 'reconnect'] }, status: { $in: SUCCESS } }).sort({ createdAt: -1 }).lean();
    res.json({ isolated: last?.actionType === 'isolate', lastAction: last || null });
  } catch (err) { res.status(500).json({ message: 'Unable to load endpoint response status' }); }
});

router.get('/', async (req, res) => {
  try {
    const page = asNumber(req.query.page, 1, 100000);
    const limit = asNumber(req.query.limit, 50);
    const filter = responseFilter(req.user.companyId, req.query);
    const [docs, total] = await Promise.all([
      AutomatedResponse.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('alertId', 'description severity ruleId').populate('triggeredBy', 'name email').populate('approvedBy', 'name email').lean(),
      AutomatedResponse.countDocuments(filter),
    ]);
    res.json({ docs, total, page, limit });
  } catch (err) { res.status(500).json({ message: 'Unable to load automated responses' }); }
});

router.post('/execute', requireCompanyAdmin, async (req, res) => {
  try {
    const { systemId, actionType, actionParams = {}, alertId, threatName, severity } = req.body;
    if (!systemId || !SUPPORTED_ACTIONS.has(actionType)) return res.status(400).json({ message: 'A system and supported action are required' });
    const [system, alert] = await Promise.all([
      System.findOne({ _id: systemId, companyId: req.user.companyId }).lean(),
      alertId ? Alert.findOne({ _id: alertId, companyId: req.user.companyId }).lean() : null,
    ]);
    if (!system) return res.status(404).json({ message: 'System not found' });
    const response = await createResponse({
      companyId: req.user.companyId, tenantId: req.user.tenantId, alert: alert || { threatName, severity, systemId }, system,
      actionType, actionParams, triggeredBy: req.user.id, trigger: 'manual', io: req.app.get('io'), forceApproval: isHighRisk(actionType),
    });
    res.status(201).json({ message: response.requiresApproval ? 'Approval required before execution' : 'Response queued', response });
  } catch (err) { res.status(400).json({ message: err.message || 'Unable to queue response' }); }
});

router.get('/:id', async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId })
      .populate('alertId', 'description severity ruleId srcip hostname').populate('triggeredBy', 'name email').populate('approvedBy', 'name email');
    if (!doc) return res.status(404).json({ message: 'Automated response not found' });
    res.json(doc);
  } catch (err) { res.status(400).json({ message: 'Invalid response id' }); }
});

router.get('/:id/audit', async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId }).select('auditTrail createdAt updatedAt').lean();
    if (!doc) return res.status(404).json({ message: 'Automated response not found' });
    res.json(doc.auditTrail || []);
  } catch (err) { res.status(400).json({ message: 'Invalid response id' }); }
});

router.post('/:id/approve', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId, status: 'waiting_approval' });
    if (!doc) return res.status(404).json({ message: 'Response is not awaiting approval' });
    doc.approvalStatus = 'approved'; doc.approvedBy = req.user.id; doc.approvedAt = new Date(); doc.approvalComment = String(req.body.comment || '').slice(0, 500);
    await transition(doc, 'approved', 'Approved by analyst', req.user.id, req.app.get('io'));
    const system = await System.findOne({ _id: doc.systemId, companyId: req.user.companyId }).lean();
    await dispatchResponse(doc, system, req.app.get('io'));
    res.json({ message: 'Response approved and queued', response: doc });
  } catch (err) { res.status(400).json({ message: 'Unable to approve response' }); }
});

router.post('/:id/reject', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId, status: 'waiting_approval' });
    if (!doc) return res.status(404).json({ message: 'Response is not awaiting approval' });
    doc.approvalStatus = 'rejected'; doc.approvedBy = req.user.id; doc.approvedAt = new Date(); doc.approvalComment = String(req.body.comment || '').slice(0, 500);
    await transition(doc, 'cancelled', 'Rejected by analyst', req.user.id, req.app.get('io'));
    res.json({ message: 'Response rejected', response: doc });
  } catch (err) { res.status(400).json({ message: 'Unable to reject response' }); }
});

router.post('/:id/cancel', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId });
    if (!doc || !ACTIVE_STATUSES.has(doc.status)) return res.status(409).json({ message: 'Response cannot be cancelled' });
    await transition(doc, 'cancelled', 'Cancelled by analyst', req.user.id, req.app.get('io'));
    res.json({ message: 'Response cancelled', response: doc });
  } catch (err) { res.status(400).json({ message: 'Unable to cancel response' }); }
});

router.post('/:id/retry', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId });
    if (!doc || !['failed', 'timed_out'].includes(doc.status) || doc.retryCount >= doc.maxRetries) return res.status(409).json({ message: 'Response is not eligible for retry' });
    doc.retryCount += 1; await transition(doc, 'queued', 'Retry requested by analyst', req.user.id, req.app.get('io'));
    const system = await System.findOne({ _id: doc.systemId, companyId: req.user.companyId }).lean();
    await dispatchResponse(doc, system, req.app.get('io'));
    res.json({ message: 'Response retry queued', response: doc });
  } catch (err) { res.status(400).json({ message: 'Unable to retry response' }); }
});

router.post('/:id/rollback', requireCompanyAdmin, async (req, res) => {
  try {
    const doc = await AutomatedResponse.findOne({ _id: req.params.id, companyId: req.user.companyId, status: { $in: SUCCESS } });
    if (!doc || !doc.rollbackAvailable) return res.status(409).json({ message: 'Rollback is not available for this response' });
    await transition(doc, 'rollback_pending', 'Rollback requested by analyst', req.user.id, req.app.get('io'));
    res.json({ message: 'Rollback recorded; an approved compensating action must be queued separately', response: doc });
  } catch (err) { res.status(400).json({ message: 'Unable to request rollback' }); }
});

module.exports = router;
