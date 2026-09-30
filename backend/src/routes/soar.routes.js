const router = require('express').Router();
const mongoose = require('mongoose');
const SoarRule = require('../models/SoarRule.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const SoarExecution = require('../models/SoarExecution.model');
const SoarApproval = require('../models/SoarApproval.model');
const SoarConnector = require('../models/SoarConnector.model');
const SoarCredential = require('../models/SoarCredential.model');
const SoarTemplate = require('../models/SoarTemplate.model');
const SoarAuditLog = require('../models/SoarAuditLog.model');
const SoarLog = require('../models/SoarLog.model');
const Alert = require('../models/Alert.model');
const AutomatedResponse = require('../models/AutomatedResponse.model');
const System = require('../models/System.model');
const Department = require('../models/Department.model');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const { authenticate, requireDeptAdmin, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { runSoarForAlert, ruleMatches, resolveApproval, rollbackExecution, writeExecutionOutcomeLogs } = require('../services/soar.service');
const { ensureDefaultSoarPlaybooks } = require('../services/defaultSoarPlaybooks.service');
const { testConnectorHealth, encryptTenantSecret, decryptCredential } = require('../services/soarConnector.service');
const { simulateRuleExecution } = require('../services/soarSimulator.service');
const { dispatchResponse, transition } = require('../services/automatedResponse.service');

router.use(authenticate);

function getCompanyFilter(req) {
  if (req.user.role === 'superadmin') return {};
  if (req.user.role === 'partner_admin' && req.user.partnerId) {
    return { partnerId: req.user.partnerId };
  }
  if (req.user.role === 'department_admin') {
    return { companyId: req.user.companyId, departmentId: req.user.departmentId };
  }
  return { companyId: req.user.companyId };
}

function scopedId(req, id) {
  return { _id: id, ...getCompanyFilter(req) };
}

function safeUpdate(body = {}) {
  const update = { ...body };
  for (const field of ['_id', 'tenantId', 'partnerId', 'companyId', 'departmentId', 'builtInKey', 'isBuiltIn', 'createdBy', 'createdAt', 'updatedAt']) {
    delete update[field];
  }
  return update;
}

async function resolveRuleDepartment(req, companyId, requestedDepartmentId) {
  const departmentId = req.user.role === 'department_admin'
    ? req.user.departmentId
    : requestedDepartmentId;
  if (!departmentId) return null;
  if (!mongoose.isValidObjectId(departmentId)) throw new Error('Select a valid Department');
  const department = await Department.findOne({ _id: departmentId, companyId }).select('_id').lean();
  if (!department) throw new Error('Selected Department is outside the rule company');
  return department._id;
}

function redactAuditValue(value) {
  if (Array.isArray(value)) return value.map(redactAuditValue);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value).map(([key, item]) => [
    key,
    /secret|password|token|api.?key|authorization|encrypted|authTag|\biv\b/i.test(key) ? '[REDACTED]' : redactAuditValue(item),
  ]));
}

function connectorDefaultsForCredential(name = '') {
  const normalized = String(name).toUpperCase();
  if (normalized.includes('VIRUSTOTAL')) return { name: 'VirusTotal Threat Intelligence', type: 'threat_intel', baseUrl: 'https://www.virustotal.com/api/v3', authType: 'api_key', status: 'enabled' };
  if (normalized.includes('ABUSEIPDB')) return { name: 'AbuseIPDB Reputation', type: 'ip_reputation', baseUrl: 'https://api.abuseipdb.com/api/v2', authType: 'api_key', status: 'enabled' };
  if (normalized.includes('OTX')) return { name: 'AlienVault OTX', type: 'threat_intel', baseUrl: 'https://otx.alienvault.com/api/v1', authType: 'api_key', status: 'enabled' };
  return { name: `${name} Connector`, type: 'generic_rest', baseUrl: '', authType: 'api_key', status: 'disabled' };
}

async function appendSoarAudit(req, { action, resourceType, resourceId, previousValue = null, newValue = null, result = 'success', message = '', correlationId = '' }) {
  return SoarAuditLog.create({
    tenantId: req.user.tenantId || null,
    partnerId: req.user.partnerId || null,
    companyId: req.user.companyId || newValue?.companyId || previousValue?.companyId || null,
    departmentId: req.user.departmentId || newValue?.departmentId || previousValue?.departmentId || null,
    user: req.user.id,
    userName: req.user.name || req.user.email || 'System',
    userRole: req.user.role || 'system',
    action, resourceType, resourceId: String(resourceId || ''), correlationId,
    previousValue: redactAuditValue(previousValue), newValue: redactAuditValue(newValue),
    ipAddress: req.ip || '', userAgent: req.get('user-agent') || '', result, message,
  });
}

async function verifyVaultPassword(req, password) {
  if (!password) return false;
  const user = await User.findById(req.user.id).select('password isActive accountStatus');
  return Boolean(user?.isActive && user.accountStatus === 'active' && await user.comparePassword(password));
}

function buildAuditPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 150);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No audit records found']);
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 32 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`;
  });
  let pdf = '%PDF-1.4\n';
  const offsets = [0];
  for (let id = 1; id < objects.length; id += 1) {
    offsets[id] = Buffer.byteLength(pdf);
    pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`;
  }
  const xref = Buffer.byteLength(pdf);
  pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

const ACTION_TYPES = new Set(SoarRule.schema.path('actions').schema.path('type').enumValues);
const CONDITION_OPERATORS = new Set(SoarRule.schema.path('conditions').schema.path('operator').enumValues);

function normalizeRulePayload(body = {}) {
  const normalized = safeUpdate(body);
  normalized.conditionLogic = body.matchLogic
    ? (body.matchLogic === 'ANY' ? 'OR' : 'AND')
    : (body.conditionLogic || 'AND');
  delete normalized.matchLogic;
  if (body.dedupWindowMinutes !== undefined) normalized.deduplicationWindowMs = Math.max(60_000, Number(body.dedupWindowMinutes) * 60_000);
  if (body.maxExecutionsPerHour !== undefined) normalized.rateLimitPerHour = Number(body.maxExecutionsPerHour);
  if (body.autoDisableFailureThreshold !== undefined) normalized.autoDisableOnFailures = Number(body.autoDisableFailureThreshold);
  delete normalized.dedupWindowMinutes; delete normalized.maxExecutionsPerHour; delete normalized.autoDisableFailureThreshold;
  normalized.conditions = (body.conditions || []).map(condition => ({
    field: String(condition.field || '').trim(),
    operator: condition.operator === 'not_eq'
      ? 'neq'
      : (condition.operator === 'in_cidr' ? 'cidr_contains' : condition.operator),
    value: condition.value,
  }));
  normalized.actions = (body.actions || []).map(action => ({
    ...action,
    id: String(action._id || (typeof action.id === 'string' && action.id !== '[object Object]' ? action.id : new mongoose.Types.ObjectId())),
    retryCount: Math.max(0, Number(action.maxRetries ?? action.retryCount ?? 1)),
    retryBackoffSec: Math.max(0, Number(action.retryBackoffSec ?? 1)),
    timeoutMs: Math.max(1000, Number(action.timeoutMs || 10000)),
  }));
  for (const condition of normalized.conditions) {
    if (!condition.field || !CONDITION_OPERATORS.has(condition.operator)) throw new Error(`Invalid SOAR condition: ${condition.field || 'missing field'} / ${condition.operator}`);
  }
  for (const action of normalized.actions) {
    if (!ACTION_TYPES.has(action.type)) throw new Error(`Unsupported SOAR action: ${action.type}`);
  }
  if (!normalized.name?.trim()) throw new Error('Rule name is required');
  if (!normalized.actions.length) throw new Error('At least one SOAR action is required');
  return normalized;
}

function validateRequiredRuleFields(payload = {}) {
  if (!String(payload.name || '').trim()) throw new Error('Rule Name is required');
  if (!payload.triggerType) throw new Error('Trigger Source is required');
  if (!payload.executionMode) throw new Error('Automation Mode is required');
  if (!Array.isArray(payload.actions) || !payload.actions.length) {
    throw new Error('Select a Playbook or add at least one Action Pipeline step');
  }
}

async function validateLinkedPlaybooks(req, payload) {
  const ids = (payload.actions || [])
    .filter(action => action.type === 'start_playbook')
    .map(action => action.payload?.playbookId);
  if (ids.some(id => !mongoose.isValidObjectId(id))) throw new Error('Select a valid Playbook for every Start Playbook action');
  if (!ids.length) return;
  const uniqueIds = [...new Set(ids.map(String))];
  const linked = await ResponsePlaybook.find({
    ...getCompanyFilter(req),
    _id: { $in: uniqueIds },
    enabled: true,
    executionMode: { $ne: 'disabled' },
  }).select('_id name executionMode').lean();
  if (linked.length !== uniqueIds.length) throw new Error('One or more linked Playbooks are unavailable, disabled, or outside your scope');
  if (payload.executionMode === 'automatic' && linked.some(item => item.executionMode === 'approval_required')) {
    throw new Error('Approval Required Playbooks must use an Approval Required Automation Rule');
  }
  if (payload.executionMode !== 'manual' && linked.some(item => item.executionMode === 'manual_only')) {
    throw new Error('Manual Only Playbooks must use a Manual Trigger Only Automation Rule');
  }
}

async function validatePlaybookConnectors(req, body = {}) {
  const connectorActions = new Set(['webhook', 'call_api']);
  const missingConnector = (body.steps || []).some(step => connectorActions.has(step.actionType) && !step.connectorId);
  if (missingConnector) throw new Error('Webhook and Call API Playbook steps require an enabled Vault-linked connector');
  const ids = (body.steps || []).map(step => step.connectorId).filter(Boolean);
  if (ids.some(id => !mongoose.isValidObjectId(id))) throw new Error('One or more Playbook connectors are invalid');
  if (!ids.length) return;
  const uniqueIds = [...new Set(ids.map(String))];
  const count = await SoarConnector.countDocuments({
    ...getCompanyFilter(req),
    _id: { $in: uniqueIds },
    status: 'enabled',
    deletedAt: null,
  });
  if (count !== uniqueIds.length) throw new Error('One or more Playbook connectors are disabled, deleted, or outside your scope');
}

function requireSoarApprover(req, res, next) {
  if (!['superadmin', 'partner_admin', 'company_admin', 'soc_manager'].includes(req.user?.role)) {
    return res.status(403).json({ message: 'SOC Manager approval required' });
  }
  next();
}

function boundedLimit(value, fallback = 50, max = 200) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? Math.min(number, max) : fallback;
}

function escapedRegex(value) {
  return new RegExp(String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&').slice(0, 200), 'i');
}

async function expirePendingApprovals(filter) {
  const expired = await SoarApproval.find({ ...filter, status: 'pending', expiresAt: { $lte: new Date() } }).select('_id executionId');
  const approvalIds = expired.map(item => item._id);
  const executionIds = expired.map(item => item.executionId).filter(Boolean);
  if (expired.length) {
    await Promise.all([
      SoarApproval.updateMany({ _id: { $in: approvalIds } }, { $set: { status: 'expired', resolvedAt: new Date(), notes: 'Approval expired automatically' } }),
      SoarExecution.updateMany(
        { _id: { $in: executionIds }, status: 'waiting_for_approval' },
        { $set: { status: 'cancelled', completedAt: new Date(), errorMessage: 'Approval expired before resolution' } },
      ),
    ]);
    const expiredExecutions = await SoarExecution.find({ _id: { $in: executionIds } });
    await Promise.all(expiredExecutions.map(execution => writeExecutionOutcomeLogs(execution, {
      action: 'SOAR_APPROVAL_EXPIRED',
      message: 'Approval expired before resolution',
    })));
  }

  const responseExpiryFilter = {
    ...filter,
    status: 'waiting_approval',
    approvalStatus: 'pending',
    $or: [
      { expiresAt: { $lte: new Date() } },
      { expiresAt: null, createdAt: { $lte: new Date(Date.now() - 24 * 60 * 60 * 1000) } },
    ],
  };
  const staleResponses = await AutomatedResponse.find(responseExpiryFilter).select('_id companyId actionType correlationId');
  if (staleResponses.length) {
    const ids = staleResponses.map(item => item._id);
    await AutomatedResponse.updateMany({ _id: { $in: ids } }, {
      $set: {
        status: 'cancelled', approvalStatus: 'expired', completedAt: new Date(),
        errorDetail: 'Approval expired before resolution',
      },
      $push: { auditTrail: { status: 'cancelled', message: 'Approval expired automatically' } },
    });
    for (const item of staleResponses) {
      await SoarAuditLog.create({
        companyId: item.companyId, action: 'SOAR_ENDPOINT_APPROVAL_EXPIRED',
        resourceType: 'AutomatedResponse', resourceId: String(item._id),
        correlationId: item.correlationId || String(item._id), result: 'failure',
        message: `${item.actionType} approval expired before resolution`,
      });
    }
  }
}

// ── RULES ENDPOINTS ────────────────────────────────────────────────────────────

// GET /api/soar/rules
router.get('/rules', async (req, res) => {
  try {
    const filter = getCompanyFilter(req);
    const rules = await SoarRule.find(filter).sort({ priority: 1, createdAt: -1 }).populate('departmentId', 'name');
    res.json(rules);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/rules
router.post('/rules', requireDeptAdmin, async (req, res) => {
  try {
    const payload = normalizeRulePayload(req.body);
    validateRequiredRuleFields(payload);
    await validateLinkedPlaybooks(req, payload);
    const companyId = req.user.companyId || req.body.companyId;
    const departmentId = await resolveRuleDepartment(req, companyId, req.body.departmentId);
    const rule = await SoarRule.create({
      ...payload,
      companyId,
      departmentId,
      createdBy: req.user.id,
    });
    await appendSoarAudit(req, { action: 'CREATE_RULE', resourceType: 'SoarRule', resourceId: rule._id, newValue: rule.toObject(), message: `Rule "${rule.name}" created` });
    res.status(201).json(rule);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// GET /api/soar/rules/:id
router.get('/rules/:id', async (req, res) => {
  try {
    const rule = await SoarRule.findOne(scopedId(req, req.params.id));
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    res.json(rule);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PUT /api/soar/rules/:id
router.put('/rules/:id', requireDeptAdmin, async (req, res) => {
  try {
    const payload = normalizeRulePayload(req.body);
    validateRequiredRuleFields(payload);
    await validateLinkedPlaybooks(req, payload);
    const previous = await SoarRule.findOne(scopedId(req, req.params.id)).lean();
    if (!previous) return res.status(404).json({ message: 'Rule not found' });
    if (req.user.role === 'department_admin' || Object.hasOwn(req.body, 'departmentId')) {
      payload.departmentId = await resolveRuleDepartment(req, previous.companyId, req.body.departmentId);
    }
    const rule = await SoarRule.findOneAndUpdate(scopedId(req, req.params.id), payload, { new: true, runValidators: true });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    await appendSoarAudit(req, { action: 'UPDATE_RULE', resourceType: 'SoarRule', resourceId: rule._id, previousValue: previous, newValue: rule.toObject(), message: `Rule "${rule.name}" updated` });
    res.json(rule);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// DELETE /api/soar/rules/:id
router.delete('/rules/:id', requireDeptAdmin, async (req, res) => {
  try {
    const rule = await SoarRule.findOneAndDelete(scopedId(req, req.params.id));
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    await appendSoarAudit(req, { action: 'DELETE_RULE', resourceType: 'SoarRule', resourceId: rule._id, previousValue: rule.toObject(), message: `Rule "${rule.name}" deleted` });
    res.json({ message: 'Rule deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/rules/:id/duplicate
router.post('/rules/:id/duplicate', requireDeptAdmin, async (req, res) => {
  try {
    const rule = await SoarRule.findOne(scopedId(req, req.params.id));
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    const dup = rule.toObject();
    delete dup._id;
    delete dup.createdAt;
    delete dup.updatedAt;
    dup.name = `${dup.name} (Copy)`;
    const newRule = await SoarRule.create(dup);
    await appendSoarAudit(req, { action: 'DUPLICATE_RULE', resourceType: 'SoarRule', resourceId: newRule._id, newValue: newRule.toObject(), message: `Rule "${rule.name}" duplicated as "${newRule.name}"` });
    res.status(201).json(newRule);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/rules/:id/activate
router.post('/rules/:id/activate', requireDeptAdmin, async (req, res) => {
  try {
    const rule = await SoarRule.findOneAndUpdate(scopedId(req, req.params.id), { enabled: true, status: 'active' }, { new: true });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    await appendSoarAudit(req, { action: 'ACTIVATE_RULE', resourceType: 'SoarRule', resourceId: rule._id, newValue: { enabled: true, status: 'active' }, message: `Rule "${rule.name}" activated` });
    res.json(rule);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/rules/:id/disable
router.post('/rules/:id/disable', requireDeptAdmin, async (req, res) => {
  try {
    const rule = await SoarRule.findOneAndUpdate(scopedId(req, req.params.id), { enabled: false, status: 'disabled' }, { new: true });
    if (!rule) return res.status(404).json({ message: 'Rule not found' });
    await appendSoarAudit(req, { action: 'DISABLE_RULE', resourceType: 'SoarRule', resourceId: rule._id, newValue: { enabled: false, status: 'disabled' }, message: `Rule "${rule.name}" disabled` });
    res.json(rule);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── PLAYBOOKS ENDPOINTS ────────────────────────────────────────────────────────

// GET /api/soar/playbooks
router.get('/playbooks', async (req, res) => {
  try {
    const companyLookup = req.user.companyId
      ? { _id: req.user.companyId }
      : req.user.role === 'partner_admin' && req.user.partnerId
        ? { partnerId: req.user.partnerId }
        : req.user.role === 'superadmin' ? {} : null;
    if (companyLookup) {
      const companies = await Company.find(companyLookup).select('_id tenantId partnerId').lean();
      await Promise.all(companies.map(company => ensureDefaultSoarPlaybooks({
        companyId: company._id,
        tenantId: company.tenantId || req.user.tenantId || null,
        partnerId: company.partnerId || null,
        createdBy: req.user.id,
      })));
    }
    const filter = getCompanyFilter(req);
    const playbooks = await ResponsePlaybook.find(filter).sort({ priority: 1 });
    res.json(playbooks);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/playbooks
router.post('/playbooks', requireDeptAdmin, async (req, res) => {
  try {
    await validatePlaybookConnectors(req, req.body);
    const pb = await ResponsePlaybook.create({
      ...safeUpdate(req.body),
      companyId: req.user.companyId || req.body.companyId,
      departmentId: req.user.role === 'department_admin' ? req.user.departmentId : req.body.departmentId,
      createdBy: req.user.id,
    });
    await appendSoarAudit(req, { action: 'CREATE_PLAYBOOK', resourceType: 'ResponsePlaybook', resourceId: pb._id, newValue: pb.toObject(), message: `Playbook "${pb.name}" created` });
    res.status(201).json(pb);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// GET /api/soar/playbooks/:id
router.get('/playbooks/:id', async (req, res) => {
  try {
    const pb = await ResponsePlaybook.findOne(scopedId(req, req.params.id));
    if (!pb) return res.status(404).json({ message: 'Playbook not found' });
    res.json(pb);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PUT /api/soar/playbooks/:id
router.put('/playbooks/:id', requireDeptAdmin, async (req, res) => {
  try {
    await validatePlaybookConnectors(req, req.body);
    const previous = await ResponsePlaybook.findOne(scopedId(req, req.params.id)).lean();
    const pb = await ResponsePlaybook.findOneAndUpdate(scopedId(req, req.params.id), safeUpdate(req.body), { new: true, runValidators: true });
    if (!pb) return res.status(404).json({ message: 'Playbook not found' });
    await appendSoarAudit(req, { action: 'UPDATE_PLAYBOOK', resourceType: 'ResponsePlaybook', resourceId: pb._id, previousValue: previous, newValue: pb.toObject(), message: `Playbook "${pb.name}" updated` });
    res.json(pb);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// DELETE /api/soar/playbooks/:id
router.delete('/playbooks/:id', requireDeptAdmin, async (req, res) => {
  try {
    const pb = await ResponsePlaybook.findOne(scopedId(req, req.params.id));
    if (!pb) return res.status(404).json({ message: 'Playbook not found' });
    if (pb.isBuiltIn) return res.status(409).json({ message: 'Built-in playbooks cannot be deleted; disable one instead' });
    await pb.deleteOne();
    await appendSoarAudit(req, { action: 'DELETE_PLAYBOOK', resourceType: 'ResponsePlaybook', resourceId: pb._id, previousValue: pb.toObject(), message: `Playbook "${pb.name}" deleted` });
    res.json({ message: 'Playbook deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── EXECUTIONS ENDPOINTS ───────────────────────────────────────────────────────

// POST /api/soar/executions/:id/retry
router.post('/executions/:id/retry', requireDeptAdmin, async (req, res) => {
  try {
    const execution = await SoarExecution.findOne(scopedId(req, req.params.id));
    if (!execution) return res.status(404).json({ message: 'Execution not found' });
    if (!['failed', 'partially_completed', 'timed_out', 'cancelled'].includes(execution.status)) {
      return res.status(409).json({ message: `Execution in ${execution.status} state cannot be retried` });
    }
    const alert = await Alert.findOne({ _id: execution.alertId, ...getCompanyFilter(req) });
    if (!alert) return res.status(404).json({ message: 'Original alert not found in your scope' });
    await runSoarForAlert(alert, 'manual', req.user, {
      ruleId: execution.ruleId,
      idempotencySource: execution._id,
    });
    await appendSoarAudit(req, { action: 'SOAR_EXECUTION_RETRY', resourceType: 'SoarExecution', resourceId: execution._id, correlationId: String(execution._id), message: `Manual retry requested for execution ${execution._id}` });
    res.status(202).json({ message: 'SOAR execution retry started' });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// GET /api/soar/executions
router.get('/executions', async (req, res) => {
  const { status, search, outcome } = req.query;
  const page = Math.max(1, Number(req.query.page) || 1);
  const limit = boundedLimit(req.query.limit);
  try {
    const filter = getCompanyFilter(req);
    if (status) filter.status = status;
    if (outcome === 'successful') filter.status = 'completed';
    if (outcome === 'failed') filter.status = 'failed';
    if (outcome === 'alerts_auto_resolved') {
      filter.steps = { $elemMatch: { actionType: 'set_alert_status', status: 'completed' } };
    }
    if (outcome === 'incidents_created') filter.incidentId = { $ne: null };
    if (outcome === 'tickets_assigned') filter.ticketId = { $ne: null };
    if (search) {
      filter.$or = [
        { ruleName: escapedRegex(search) },
        { playbookName: escapedRegex(search) },
        { errorMessage: escapedRegex(search) },
      ];
    }
    const [executions, total] = await Promise.all([
      SoarExecution.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(limit),
      SoarExecution.countDocuments(filter),
    ]);
    res.json({ executions, total, page: Number(page), pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/soar/executions/:id
router.get('/executions/:id', async (req, res) => {
  try {
    const exec = await SoarExecution.findOne(scopedId(req, req.params.id))
      .populate('ruleId')
      .populate('alertId')
      .populate('triggeredBy', 'name email');
    if (!exec) return res.status(404).json({ message: 'Execution not found' });
    res.json(exec);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/executions/:id/cancel
router.post('/executions/:id/cancel', requireDeptAdmin, async (req, res) => {
  try {
    const exec = await SoarExecution.findOneAndUpdate(scopedId(req, req.params.id), { status: 'cancelled', completedAt: new Date() }, { new: true });
    if (!exec) return res.status(404).json({ message: 'Execution not found' });
    res.json(exec);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/executions/:id/rollback
router.post('/executions/:id/rollback', requireDeptAdmin, async (req, res) => {
  try {
    const exec = await rollbackExecution(req.params.id, req.user, getCompanyFilter(req));
    res.json(exec);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── APPROVALS ENDPOINTS ────────────────────────────────────────────────────────

// GET /api/soar/approvals
router.get('/approvals', async (req, res) => {
  try {
    const filter = getCompanyFilter(req);
    await expirePendingApprovals(filter);
    const requestedStatus = req.query.status;
    if (requestedStatus) filter.status = requestedStatus;
    const limit = boundedLimit(req.query.limit, 100);
    const responseFilter = { ...getCompanyFilter(req) };
    if (requestedStatus === 'pending' || !requestedStatus) {
      responseFilter.status = 'waiting_approval'; responseFilter.approvalStatus = 'pending';
    } else if (requestedStatus === 'approved') responseFilter.approvalStatus = 'approved';
    else if (requestedStatus === 'rejected') responseFilter.approvalStatus = 'rejected';
    else responseFilter._id = null;
    const [approvals, responses] = await Promise.all([
      SoarApproval.find(filter).sort({ createdAt: -1 }).limit(limit).populate('executionId').populate('alertId').lean(),
      AutomatedResponse.find(responseFilter).sort({ createdAt: -1 }).limit(limit)
        .populate('alertId', 'description severity ruleId').populate('systemId', 'name hostname').lean(),
    ]);
    const unified = [
      ...approvals.map(item => ({ ...item, source: 'soar', approvalId: item._id, requestedAction: item.requestedAction, requestedAt: item.requestedAt || item.createdAt })),
      ...responses.map(item => ({
        _id: item._id, approvalId: item._id, source: 'automated_response',
        requestedAction: item.actionType, targetResource: item.hostname || item.agentId || item.systemId?.hostname || 'Endpoint',
        targetSummary: item.threatName || item.alertId?.description || `${item.actionType} response`,
        reason: item.policyName || item.playbookName || 'Automated response safety policy',
        riskLevel: item.severity || 'high', status: item.approvalStatus === 'pending' ? 'pending' : item.approvalStatus,
        requestedAt: item.createdAt, createdAt: item.createdAt, expiresAt: item.expiresAt,
        alertId: item.alertId, systemId: item.systemId,
      })),
    ].sort((a, b) => new Date(b.requestedAt || b.createdAt) - new Date(a.requestedAt || a.createdAt)).slice(0, limit);
    res.json(unified);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

async function resolveAutomatedResponse(req, decision) {
  const doc = await AutomatedResponse.findOne({
    _id: req.params.id, ...getCompanyFilter(req), status: 'waiting_approval', approvalStatus: 'pending',
  });
  if (!doc) throw new Error('Automated response is not awaiting approval');
  doc.approvalStatus = decision === 'approved' ? 'approved' : 'rejected';
  doc.approvedBy = req.user.id; doc.approvedAt = new Date();
  doc.approvalComment = String(req.body.notes || req.body.comment || '').slice(0, 500);
  if (decision === 'rejected') {
    await transition(doc, 'cancelled', 'Rejected from unified SOAR approval queue', req.user.id, req.app.get('io'));
    return doc;
  }
  await transition(doc, 'approved', 'Approved from unified SOAR approval queue', req.user.id, req.app.get('io'));
  const system = await System.findOne({ _id: doc.systemId, companyId: doc.companyId }).lean();
  if (!system) throw new Error('Target endpoint no longer exists in this company');
  await dispatchResponse(doc, system, req.app.get('io'));
  return doc;
}

router.post('/approvals/automated-response/:id/approve', requireSoarApprover, async (req, res) => {
  try { res.json({ source: 'automated_response', response: await resolveAutomatedResponse(req, 'approved') }); }
  catch (err) { res.status(400).json({ message: err.message }); }
});

router.post('/approvals/automated-response/:id/reject', requireSoarApprover, async (req, res) => {
  try { res.json({ source: 'automated_response', response: await resolveAutomatedResponse(req, 'rejected') }); }
  catch (err) { res.status(400).json({ message: err.message }); }
});

// POST /api/soar/approvals/:id/approve
router.post('/approvals/:id/approve', requireSoarApprover, async (req, res) => {
  try {
    const { notes } = req.body;
    const result = await resolveApproval(req.params.id, 'approved', req.user, notes, getCompanyFilter(req));
    res.json(result);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// POST /api/soar/approvals/:id/reject
router.post('/approvals/:id/reject', requireSoarApprover, async (req, res) => {
  try {
    const { notes } = req.body;
    const result = await resolveApproval(req.params.id, 'rejected', req.user, notes, getCompanyFilter(req));
    res.json(result);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// POST /api/soar/approvals/bulk-approve
router.post('/approvals/bulk-approve', requireSoarApprover, async (req, res) => {
  try {
    const { ids, notes } = req.body;
    if (!Array.isArray(ids) || ids.length > 100) return res.status(400).json({ message: 'Provide at most 100 approval IDs' });
    const results = [];
    for (const id of (ids || [])) {
      results.push(await resolveApproval(id, 'approved', req.user, notes, getCompanyFilter(req)));
    }
    res.json({ message: `${results.length} approvals processed`, results });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// ── CONNECTORS ENDPOINTS ───────────────────────────────────────────────────────

// GET /api/soar/connectors
router.get('/connectors', async (req, res) => {
  try {
    const filter = { ...getCompanyFilter(req), deletedAt: null };
    const connectors = await SoarConnector.find(filter).populate('credentialId', 'name type');
    res.json(connectors);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/connectors
router.post('/connectors', requireCompanyAdmin, async (req, res) => {
  try {
    const connector = await SoarConnector.create({
      ...req.body,
      companyId: req.user.companyId || req.body.companyId,
      createdBy: req.user.id,
    });
    await appendSoarAudit(req, { action: 'CREATE_CONNECTOR', resourceType: 'SoarConnector', resourceId: connector._id, newValue: connector.toObject(), message: `Connector "${connector.name}" created` });
    res.status(201).json(connector);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// PUT /api/soar/connectors/:id
router.put('/connectors/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const previous = await SoarConnector.findOne(scopedId(req, req.params.id)).lean();
    const connector = await SoarConnector.findOneAndUpdate(scopedId(req, req.params.id), safeUpdate(req.body), { new: true, runValidators: true });
    if (!connector) return res.status(404).json({ message: 'Connector not found' });
    await appendSoarAudit(req, { action: 'UPDATE_CONNECTOR', resourceType: 'SoarConnector', resourceId: connector._id, previousValue: previous, newValue: connector.toObject(), message: `Connector "${connector.name}" updated` });
    res.json(connector);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// DELETE /api/soar/connectors/:id
router.delete('/connectors/:id', requireCompanyAdmin, async (req, res) => {
  try {
    const connector = await SoarConnector.findOneAndDelete(scopedId(req, req.params.id));
    if (!connector) return res.status(404).json({ message: 'Connector not found' });
    await appendSoarAudit(req, { action: 'DELETE_CONNECTOR', resourceType: 'SoarConnector', resourceId: connector._id, previousValue: connector.toObject(), message: `Connector "${connector.name}" deleted` });
    res.json({ message: 'Connector deleted' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/connectors/:id/test
router.post('/connectors/:id/test', requireCompanyAdmin, async (req, res) => {
  try {
    const connector = await SoarConnector.findOne(scopedId(req, req.params.id)).select('_id');
    if (!connector) return res.status(404).json({ message: 'Connector not found' });
    const result = await testConnectorHealth(req.params.id);
    await appendSoarAudit(req, { action: 'TEST_CONNECTOR', resourceType: 'SoarConnector', resourceId: connector._id, result: result?.ok === false ? 'failure' : 'success', message: `Connector health test ${result?.ok === false ? 'failed' : 'completed'}` });
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── CREDENTIALS ENDPOINTS ──────────────────────────────────────────────────────

// GET /api/soar/credentials
router.get('/credentials', requireCompanyAdmin, async (req, res) => {
  try {
    const filter = getCompanyFilter(req);
    const creds = await SoarCredential.find(filter);
    res.json(creds);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/credentials
router.post('/credentials', requireCompanyAdmin, async (req, res) => {
  try {
    const { name, type, secretValue } = req.body;
    if (!name || !type || !secretValue) return res.status(400).json({ message: 'name, type, and secretValue are required' });

    const credentialId = new mongoose.Types.ObjectId();
    const tenantId = req.user.tenantId || null;
    const companyId = req.user.companyId || req.body.companyId;
    if (!tenantId || !companyId) return res.status(400).json({ message: 'Tenant and company scope are required for credential encryption' });
    const encrypted = await encryptTenantSecret(secretValue, {
      _id: credentialId, tenantId, companyId, createdBy: req.user.id,
    });
    const cred = await SoarCredential.create({
      _id: credentialId,
      tenantId,
      companyId,
      name, type,
      encrypted,
      createdBy: req.user.id,
    });
    const connectorDefaults = connectorDefaultsForCredential(name);
    const connector = await SoarConnector.create({
      tenantId: req.user.tenantId || null,
      partnerId: req.user.partnerId || null,
      companyId: cred.companyId,
      ...connectorDefaults,
      credentialId: cred._id,
      createdBy: req.user.id,
    });
    await appendSoarAudit(req, {
      action: 'CREATE_VAULT_CREDENTIAL', resourceType: 'SoarCredential', resourceId: cred._id,
      newValue: { name: cred.name, type: cred.type, companyId: cred.companyId, createdBy: cred.createdBy },
      message: `SOAR Vault credential "${cred.name}" created (secret redacted)`,
    });
    await appendSoarAudit(req, { action: 'CREATE_CONNECTOR', resourceType: 'SoarConnector', resourceId: connector._id, newValue: connector.toObject(), message: `Connector "${connector.name}" automatically created from company Vault credential` });
    res.status(201).json(cred);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

router.post('/credentials/:id/reveal', requireCompanyAdmin, async (req, res) => {
  try {
    if (!await verifyVaultPassword(req, req.body?.currentPassword)) {
      await appendSoarAudit(req, { action: 'REVEAL_VAULT_CREDENTIAL', resourceType: 'SoarCredential', resourceId: req.params.id, result: 'denied', message: 'Vault reveal denied: password verification failed' });
      return res.status(403).json({ message: 'Current password verification failed' });
    }
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Company Vault credential not found' });
    const credential = await SoarCredential.findOne(scopedId(req, req.params.id)).select('+encryptedValue +iv +authTag +encrypted');
    if (!credential) return res.status(404).json({ message: 'Vault credential not found' });
    const secretValue = await decryptCredential(credential);
    await appendSoarAudit(req, { action: 'REVEAL_VAULT_CREDENTIAL', resourceType: 'SoarCredential', resourceId: credential._id, newValue: { name: credential.name, type: credential.type }, message: `SOAR Vault credential "${credential.name}" revealed after password verification (value not logged)` });
    res.set('Cache-Control', 'no-store, max-age=0').set('Pragma', 'no-cache').json({ secretValue, expiresInSeconds: 30 });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

router.delete('/credentials/:id', requireCompanyAdmin, async (req, res) => {
  try {
    if (!await verifyVaultPassword(req, req.body?.currentPassword)) {
      await appendSoarAudit(req, { action: 'DELETE_VAULT_CREDENTIAL', resourceType: 'SoarCredential', resourceId: req.params.id, result: 'denied', message: 'Vault deletion denied: password verification failed' });
      return res.status(403).json({ message: 'Current password verification failed' });
    }
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(404).json({ message: 'Company Vault credential not found' });
    const credential = await SoarCredential.findOne(scopedId(req, req.params.id));
    if (!credential) return res.status(404).json({ message: 'Vault credential not found' });
    const linkedConnectors = await SoarConnector.find({ ...getCompanyFilter(req), credentialId: credential._id, deletedAt: null }).select('_id name').lean();
    if (linkedConnectors.length) {
      await SoarConnector.updateMany(
        { _id: { $in: linkedConnectors.map(item => item._id) } },
        { $set: { status: 'disabled', deletedAt: new Date(), updatedBy: req.user.id } },
      );
    }
    await SoarCredential.deleteOne({ _id: credential._id });
    await appendSoarAudit(req, { action: 'DELETE_VAULT_CREDENTIAL', resourceType: 'SoarCredential', resourceId: credential._id, previousValue: { name: credential.name, type: credential.type, version: credential.version, removedConnectors: linkedConnectors.map(item => ({ id: item._id, name: item.name })) }, message: `SOAR Vault credential "${credential.name}" and ${linkedConnectors.length} linked connector(s) removed (secret not logged)` });
    res.json({ message: `Vault credential deleted; ${linkedConnectors.length} linked connector(s) removed`, removedConnectorIds: linkedConnectors.map(item => item._id) });
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// ── TEMPLATES & SIMULATOR ENDPOINTS ───────────────────────────────────────────

// GET /api/soar/templates
router.get('/templates', async (req, res) => {
  try {
    const templates = await SoarTemplate.find({});
    res.json(templates);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/soar/simulator
router.post('/simulator', async (req, res) => {
  try {
    if (req.body.ruleId) {
      const rule = await SoarRule.findOne(scopedId(req, req.body.ruleId)).lean();
      if (!rule) return res.status(404).json({ message: 'Rule not found' });
      req.body.rule = rule;
      delete req.body.ruleId;
    }
    if (req.body.playbookId) {
      const playbook = await ResponsePlaybook.findOne(scopedId(req, req.body.playbookId)).lean();
      if (!playbook) return res.status(404).json({ message: 'Playbook not found' });
      req.body.playbook = playbook;
      delete req.body.playbookId;
    }
    const result = await simulateRuleExecution(req.body);
    res.json(result);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── DASHBOARD & AUDIT LOGS ENDPOINTS ───────────────────────────────────────────

// GET /api/soar/dashboard/summary
router.get('/dashboard/summary', async (req, res) => {
  try {
    const filter = getCompanyFilter(req);
    await expirePendingApprovals(filter);
    const [
      totalRules, activeRules, disabledRules,
      totalExecutions, successfulExecutions, failedExecutions, soarPendingApprovals, responsePendingApprovals,
      todayExecutions, alertsAutoResolved, incidentsCreated, ticketsAssigned
    ] = await Promise.all([
      SoarRule.countDocuments(filter),
      SoarRule.countDocuments({ ...filter, enabled: true }),
      SoarRule.countDocuments({ ...filter, enabled: false }),
      SoarExecution.countDocuments(filter),
      SoarExecution.countDocuments({ ...filter, status: 'completed' }),
      SoarExecution.countDocuments({ ...filter, status: 'failed' }),
      SoarApproval.countDocuments({ ...filter, status: 'pending' }),
      AutomatedResponse.countDocuments({ ...filter, status: 'waiting_approval', approvalStatus: 'pending' }),
      SoarExecution.countDocuments({ ...filter, createdAt: { $gte: new Date(new Date().setHours(0,0,0,0)) } }),
      SoarExecution.countDocuments({ ...filter, steps: { $elemMatch: { actionType: 'set_alert_status', status: 'completed' } } }),
      SoarExecution.countDocuments({ ...filter, incidentId: { $ne: null } }),
      SoarExecution.countDocuments({ ...filter, ticketId: { $ne: null } }),
    ]);

    const aggregateFilter = { ...filter, status: 'completed' };
    if (aggregateFilter.companyId && mongoose.isValidObjectId(aggregateFilter.companyId)) {
      aggregateFilter.companyId = new mongoose.Types.ObjectId(aggregateFilter.companyId);
    }
    if (aggregateFilter.partnerId && mongoose.isValidObjectId(aggregateFilter.partnerId)) {
      aggregateFilter.partnerId = new mongoose.Types.ObjectId(aggregateFilter.partnerId);
    }
    const avgDuration = await SoarExecution.aggregate([
      { $match: aggregateFilter },
      { $group: { _id: null, avgDuration: { $avg: '$durationMs' } } },
    ]);

    res.json({
      totalRules,
      activeRules,
      disabledRules,
      totalExecutions,
      successfulExecutions,
      failedExecutions,
      pendingApprovals: soarPendingApprovals + responsePendingApprovals,
      soarPendingApprovals,
      responsePendingApprovals,
      todayExecutions,
      alertsAutoResolved,
      incidentsCreated,
      ticketsAssigned,
      avgAutomationTimeMs: Math.round(avgDuration[0]?.avgDuration || 0),
      analystHoursSaved: 0,
      slaBreachesPrevented: 0,
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/soar/audit-logs
router.get('/audit-logs', async (req, res) => {
  try {
    const filter = getCompanyFilter(req);
    const limit = Math.min(200, Math.max(1, Number(req.query.limit) || 100));
    const page = Math.max(1, Number(req.query.page) || 1);
    const query = SoarAuditLog.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit);
    const logs = await query;
    if (!req.query.page && !req.query.limit) return res.json(logs); // Backward-compatible UI response.
    const total = await SoarAuditLog.countDocuments(filter);
    res.json({ logs, page, limit, total, pages: Math.ceil(total / limit) });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/audit-logs/verify', async (req, res) => {
  try {
    res.json(await SoarAuditLog.verifyCompanyChain(getCompanyFilter(req)));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/audit-logs/export.csv', async (req, res) => {
  try {
    const logs = await SoarAuditLog.find(getCompanyFilter(req)).sort({ createdAt: -1 }).limit(10_000).lean();
    const escapeCsv = value => `"${String(value ?? '').replaceAll('"', '""')}"`;
    const rows = [['Timestamp', 'Action', 'User', 'Role', 'Resource Type', 'Resource ID', 'Result', 'Message', 'Entry Hash', 'Previous Hash']];
    logs.forEach(log => rows.push([
      log.createdAt?.toISOString?.() || log.createdAt, log.action, log.userName, log.userRole,
      log.resourceType, log.resourceId, log.result, log.message, log.entryHash || 'LEGACY', log.previousHash || 'LEGACY',
    ]));
    res.type('text/csv').attachment(`soar-audit-${new Date().toISOString().slice(0, 10)}.csv`).send(rows.map(row => row.map(escapeCsv).join(',')).join('\n'));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

router.get('/audit-logs/export.pdf', async (req, res) => {
  try {
    const logs = await SoarAuditLog.find(getCompanyFilter(req)).sort({ createdAt: -1 }).limit(5_000).lean();
    const verification = await SoarAuditLog.verifyCompanyChain(getCompanyFilter(req));
    const lines = [
      'SOAR IMMUTABLE SECURITY AUDIT TRAIL',
      `Generated: ${new Date().toISOString()}`,
      `Integrity: ${verification.valid ? 'VERIFIED' : `FAILED at ${verification.brokenAt}`}`,
      `Signed records: ${verification.checked} | Legacy records: ${verification.legacyRecords}`,
      ' ',
      ...logs.flatMap(log => [
        `${new Date(log.createdAt).toISOString()} | ${log.result || 'success'} | ${log.action} | ${log.userName || 'System'} (${log.userRole || 'system'})`,
        `Resource: ${log.resourceType || ''}/${log.resourceId || ''} | Hash: ${log.entryHash || 'LEGACY'}`,
        `Message: ${log.message || ''}`,
        ' ',
      ]),
    ];
    const pdf = buildAuditPdf(lines);
    res.type('application/pdf').attachment(`soar-audit-${new Date().toISOString().slice(0, 10)}.pdf`).send(pdf);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/soar/logs (legacy compatibility)
router.get('/logs', async (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  try {
    const filter = getCompanyFilter(req);
    const [logs, total] = await Promise.all([
      SoarLog.find(filter)
        .sort({ createdAt: -1 })
        .skip((page - 1) * limit)
        .limit(Number(limit))
        .populate('ruleId', 'name')
        .populate('alertId', 'description severity'),
      SoarLog.countDocuments(filter),
    ]);
    res.json({ logs, total });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
