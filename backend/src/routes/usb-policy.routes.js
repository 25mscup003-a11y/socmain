const router = require('express').Router();
const mongoose = require('mongoose');
const UsbPolicy = require('../models/UsbPolicy.model');
const Alert = require('../models/Alert.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');

const RULE_TYPES = new Set([
  'allow_serials', 'block_serials', 'block_vendor', 'block_device_type',
  'block_sensitive_files', 'block_extensions', 'max_file_size', 'read_only',
]);
const ACTIONS = new Set(['audit', 'block']);
const RULES_REQUIRING_VALUES = new Set([
  'allow_serials', 'block_serials', 'block_vendor', 'block_device_type', 'block_extensions',
]);

router.use(authenticate);

function scope(req) {
  if (!req.user?.companyId) throw Object.assign(new Error('Company scope is required'), { status: 400 });
  return {
    companyId: req.user.companyId,
    ...(req.user.role === 'department_admin' && req.user.departmentId ? { departmentId: req.user.departmentId } : {}),
  };
}

function asyncRoute(handler) {
  return (req, res) => Promise.resolve(handler(req, res)).catch(error => {
    console.error('[usb-policy]', error.message);
    res.status(error.status || 500).json({ message: error.status ? error.message : 'USB policy request failed' });
  });
}

function invalid(message) {
  throw Object.assign(new Error(message), { status: 400 });
}

function cleanText(value, maxLength, field, required = false) {
  const text = String(value ?? '').trim();
  if (required && !text) invalid(`${field} is required`);
  if (text.length > maxLength) invalid(`${field} exceeds ${maxLength} characters`);
  return text;
}

function normalizeValues(value) {
  const source = Array.isArray(value) ? value : String(value ?? '').split(',');
  if (source.length > 256) invalid('values cannot contain more than 256 entries');
  return [...new Set(source.map(item => cleanText(item, 260, 'value')).filter(Boolean))];
}

function policyInput(body = {}, partial = false) {
  const values = {};
  if (!partial || body.name !== undefined) values.name = cleanText(body.name, 120, 'name', true);
  if (!partial || body.description !== undefined) values.description = cleanText(body.description, 500, 'description');
  if (!partial || body.ruleType !== undefined) {
    if (!RULE_TYPES.has(body.ruleType)) invalid('Unsupported USB policy ruleType');
    values.ruleType = body.ruleType;
  }
  if (!partial || body.action !== undefined) {
    const action = body.action || 'audit';
    if (!ACTIONS.has(action)) invalid('action must be audit or block');
    values.action = action;
  }
  if (!partial || body.values !== undefined) values.values = normalizeValues(body.values);
  if (!partial || body.maxBytes !== undefined) {
    const maxBytes = Number(body.maxBytes || 0);
    if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 10 * 1024 ** 4) {
      invalid('maxBytes must be a non-negative integer no larger than 10 TB');
    }
    values.maxBytes = maxBytes;
  }
  if (!partial || body.enabled !== undefined) {
    if (body.enabled !== undefined && typeof body.enabled !== 'boolean') invalid('enabled must be boolean');
    values.enabled = body.enabled !== false;
  }
  const effectiveType = values.ruleType || body.ruleType;
  if (!partial && RULES_REQUIRING_VALUES.has(effectiveType) && !values.values.length) {
    invalid('At least one policy value is required for this rule type');
  }
  if (!partial && effectiveType === 'max_file_size' && values.maxBytes <= 0) {
    invalid('maxBytes must be greater than zero for max_file_size rules');
  }
  return values;
}

async function audit(req, action, policy, metadata = {}) {
  const actorId = req.user?.id || req.user?._id;
  if (!req.user?.tenantId || !actorId) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId,
    companyId: req.user.companyId,
    actorId,
    action,
    targetType: 'UsbPolicy',
    targetId: String(policy?._id || ''),
    metadata: { policyName: policy?.name, ruleType: policy?.ruleType, ...metadata },
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

function emitUpdate(req, action, policy) {
  req.app.get('io')?.to(`company:${req.user.companyId}`).emit('usb-policy:updated', {
    action,
    id: String(policy._id),
    policy,
    updatedAt: new Date().toISOString(),
  });
}

router.get('/', requireAnalyst, asyncRoute(async (req, res) => {
  const policies = await UsbPolicy.find(scope(req)).sort({ enabled: -1, updatedAt: -1 }).lean();
  res.json({ policies });
}));

router.get('/violations', requireAnalyst, asyncRoute(async (req, res) => {
  const days = Math.min(365, Math.max(1, Number.parseInt(req.query.days, 10) || 90));
  const limit = Math.min(500, Math.max(1, Number.parseInt(req.query.limit, 10) || 250));
  const since = new Date(Date.now() - days * 86400000);
  const query = {
    $and: [
      { ...scope(req), createdAt: { $gte: since }, isSynthetic: { $ne: true } },
      { $or: [{ capabilityId: 10 }, { capabilityIds: 10 }] },
      { $or: [{ ruleId: /USB_.*(POLICY|BLOCK|DENIED)/i }, { policyName: { $exists: true, $ne: '' } }] },
    ],
  };
  const [violations, total] = await Promise.all([
    Alert.find(query)
      .select('createdAt ruleId policyName usbPolicyId usbPolicyRuleType usbEnforcementStatus usbEnforcementError blocked actionTaken agentName hostname username device description severity')
      .sort({ createdAt: -1 }).limit(limit).maxTimeMS(5000).lean(),
    Alert.countDocuments(query).maxTimeMS(5000),
  ]);
  res.json({ violations, total, days, limit });
}));

router.post('/', requireManager, asyncRoute(async (req, res) => {
  const values = policyInput(req.body);
  const policy = await UsbPolicy.create({
    ...scope(req),
    ...values,
    createdBy: req.user.id || req.user._id,
  });
  await audit(req, 'usb.policy.created', policy);
  emitUpdate(req, 'created', policy);
  res.status(201).json({ policy });
}));

router.patch('/:id', requireManager, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid USB policy id' });
  const update = policyInput(req.body, true);
  if (!Object.keys(update).length) return res.status(400).json({ message: 'No supported fields supplied' });
  const existing = await UsbPolicy.findOne({ _id: req.params.id, ...scope(req) });
  if (!existing) return res.status(404).json({ message: 'USB policy not found' });
  const effectiveType = update.ruleType || existing.ruleType;
  const effectiveValues = update.values === undefined ? existing.values : update.values;
  const effectiveMaxBytes = update.maxBytes === undefined ? existing.maxBytes : update.maxBytes;
  if (RULES_REQUIRING_VALUES.has(effectiveType) && !effectiveValues.length) invalid('At least one policy value is required for this rule type');
  if (effectiveType === 'max_file_size' && Number(effectiveMaxBytes) <= 0) invalid('maxBytes must be greater than zero for max_file_size rules');
  Object.assign(existing, update);
  await existing.save();
  await audit(req, 'usb.policy.updated', existing, { fields: Object.keys(update) });
  emitUpdate(req, 'updated', existing);
  res.json({ policy: existing });
}));

router.delete('/:id', requireManager, asyncRoute(async (req, res) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid USB policy id' });
  const policy = await UsbPolicy.findOneAndDelete({ _id: req.params.id, ...scope(req) });
  if (!policy) return res.status(404).json({ message: 'USB policy not found' });
  await audit(req, 'usb.policy.deleted', policy);
  emitUpdate(req, 'deleted', policy);
  res.json({ ok: true });
}));

module.exports = router;
