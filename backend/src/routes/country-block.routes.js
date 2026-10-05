const router = require('express').Router();
const { requireManager } = require('../middleware/auth.middleware');
const { assertCompanyScope } = require('../services/socAccess.service');
const CountryBlockRule = require('../models/CountryBlockRule.model');
const System = require('../models/System.model');
const Department = require('../models/Department.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const { countries, countryCodes, policyForSystem, enforcementStatus } = require('../services/countryBlock.service');
const { systemConnectionState } = require('../utils/systemPresence');
const { lookupCountry } = require('../services/countryLookup.service');

function fail(message, status = 400) { throw Object.assign(new Error(message), { status }); }
const validId = value => typeof value === 'string' && /^[a-f\d]{24}$/i.test(value);

async function authorizedScope(user) {
  const companyId = String(user.companyId || '');
  if (!validId(companyId)) fail('Select a company first');
  if (user.role !== 'superadmin') await assertCompanyScope(user, [companyId]);
  const query = { companyId };
  if (user.role === 'department_admin' || user.role === 'analyst') {
    if (!validId(String(user.departmentId || ''))) fail('No department is assigned', 403);
    query.departmentId = user.departmentId;
  } else if (['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(user.role)) {
    const userId = user.id || user._id;
    const companyAssignment = await SocCompanyAssignment.exists({ userId, companyId, active: true });
    if (!companyAssignment) {
      const departments = await SocDepartmentAssignment.find({ userId, companyId, active: true }).distinct('departmentId');
      if (!departments.length) fail('No departments are assigned', 403);
      query.departmentId = { $in: departments };
    }
  }
  return query;
}

async function validateRule(body, query) {
  const countryCode = typeof body.countryCode === 'string' ? body.countryCode.toUpperCase() : '';
  if (!countryCodes.has(countryCode)) fail('Select a valid country');
  if (!['inbound', 'outbound', 'both'].includes(body.direction)) fail('Select inbound, outbound or both');
  if (!['company', 'department', 'system'].includes(body.scope)) fail('Select company, department or system scope');
  if (body.enabled !== undefined && typeof body.enabled !== 'boolean') fail('enabled must be a boolean');
  if (body.reason !== undefined && (typeof body.reason !== 'string' || body.reason.length > 500)) fail('Reason must be at most 500 characters');
  let departmentId = null;
  let systemId = null;
  if (body.scope === 'company') {
    if (query.departmentId) fail('Company-level rules require access to the entire company', 403);
  } else if (body.scope === 'department') {
    if (!validId(body.departmentId)) fail('Select a department');
    const department = await Department.findOne({
      companyId: query.companyId, _id: body.departmentId, isActive: true,
      ...(query.departmentId ? { $and: [{ _id: query.departmentId }] } : {}),
    }).lean();
    if (!department) fail('Department is outside your authorized scope', 403);
    departmentId = department._id;
  } else {
    if (!validId(body.systemId)) fail('Select a system');
    const system = await System.findOne({ ...query, _id: body.systemId, isActive: true }).lean();
    if (!system) fail('System is outside your authorized scope', 403);
    if (system.agentType === 'phone' || /android|ios|solaris/i.test(system.osType || '')) fail('Country blocking requires a Linux, Windows or macOS system');
    departmentId = system.departmentId;
    systemId = system._id;
  }
  return { companyId: query.companyId, countryCode, direction: body.direction, scope: body.scope,
    departmentId, systemId, enabled: body.enabled !== false, reason: (body.reason || '').trim() };
}

async function ruleScope(query, { includeCompany = false } = {}) {
  if (!query.departmentId) return query;
  // System rules follow the system when it moves department. Authorize against
  // its current owner rather than the department recorded when the rule was made.
  const ids = await System.find(query).distinct('_id');
  return { companyId: query.companyId, $or: [
    ...(includeCompany ? [{ scope: 'company' }] : []),
    { scope: 'department', departmentId: query.departmentId },
    { scope: 'system', systemId: { $in: ids } },
  ] };
}

function handleError(res, error) {
  if (error.code === 11000) return res.status(409).json({ message: 'A rule for this country, direction and target already exists. Edit or enable that rule.' });
  if (!error.status) console.error('[CountryBlock]', error.message);
  return res.status(error.status || 500).json({ message: error.status ? error.message : 'Could not save or load country blocking rules' });
}

router.get('/countries', (_req, res) => res.json({ countries }));

router.get('/country-blocks/lookup', async (req, res) => {
  try {
    await authorizedScope(req.user);
    res.set('Cache-Control', 'no-store');
    res.json(await lookupCountry(req.query.target));
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Country lookup unavailable' });
  }
});

router.get('/country-blocks/summary', async (req, res) => {
  try {
    const query = await authorizedScope(req.user);
    res.json({ enabled: await CountryBlockRule.countDocuments({ ...await ruleScope(query, { includeCompany: true }), enabled: true }) });
  } catch (error) { handleError(res, error); }
});

router.get('/country-blocks', async (req, res) => {
  try {
    const query = await authorizedScope(req.user);
    const scopedRules = await ruleScope(query, { includeCompany: true });
    const [rules, systems, departments] = await Promise.all([
      CountryBlockRule.find(scopedRules).sort({ createdAt: -1 }).lean(),
      System.find({ ...query, isActive: true }).select('_id companyId departmentId name hostname osType agentType status isActive agentVersion lastSeen countryBlockStatus').lean(),
      Department.find({ companyId: query.companyId, isActive: true, ...(query.departmentId ? { _id: query.departmentId } : {}) }).select('_id name').sort({ name: 1 }).lean(),
    ]);
    const now = Date.now();
    const statusSystems = systems.map(system => {
      const connectionState = systemConnectionState(system, now);
      return { ...system, connectionState, isOnline: connectionState === 'online',
        syncState: enforcementStatus(system, policyForSystem(rules, system), now) };
    });
    const canManage = ['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(req.user.role);
    const canManageCompany = canManage && !query.departmentId;
    res.json({ countries, departments, systems: statusSystems, canManageCompany, rules: rules.map(rule => {
      const targets = statusSystems.filter(system => rule.scope === 'company' || (rule.scope === 'department'
        ? String(system.departmentId) === String(rule.departmentId) : String(system._id) === String(rule.systemId)));
      const enforcement = { total: targets.length, applied: 0, pending: 0, failed: 0, offline: 0, unsupported: 0 };
      targets.forEach(system => { enforcement[system.syncState] += 1; });
      return { ...rule, departmentId: rule.scope === 'system' && targets[0] ? targets[0].departmentId : rule.departmentId,
        canEdit: canManage && (rule.scope !== 'company' || canManageCompany), enforcement };
    }) });
  } catch (error) { handleError(res, error); }
});

router.post('/country-blocks', requireManager, async (req, res) => {
  try {
    const query = await authorizedScope(req.user);
    const values = await validateRule(req.body, query);
    const actor = req.user.id || req.user._id;
    const rule = await CountryBlockRule.create({ ...values, createdBy: actor, updatedBy: actor });
    res.status(201).json({ rule, message: 'Rule saved. Target agents will apply it on their next heartbeat.' });
  } catch (error) { handleError(res, error); }
});

router.patch('/country-blocks/:id', requireManager, async (req, res) => {
  try {
    if (!validId(req.params.id)) fail('Invalid rule ID');
    const query = await authorizedScope(req.user);
    const scopedRules = await ruleScope(query);
    const existing = await CountryBlockRule.findOne({ ...scopedRules, _id: req.params.id }).lean();
    if (!existing) fail('Rule not found', 404);
    const values = await validateRule({ ...existing, departmentId: String(existing.departmentId), systemId: existing.systemId ? String(existing.systemId) : null, ...req.body }, query);
    const rule = await CountryBlockRule.findOneAndUpdate({ ...scopedRules, _id: req.params.id }, {
      $set: { ...values, updatedBy: req.user.id || req.user._id },
    }, { new: true, runValidators: true });
    res.json({ rule, message: 'Rule updated. Target agents will synchronize on their next heartbeat.' });
  } catch (error) { handleError(res, error); }
});

router.delete('/country-blocks/:id', requireManager, async (req, res) => {
  try {
    if (!validId(req.params.id)) fail('Invalid rule ID');
    const query = await authorizedScope(req.user);
    const rule = await CountryBlockRule.findOneAndDelete({ ...await ruleScope(query), _id: req.params.id });
    if (!rule) fail('Rule not found', 404);
    res.json({ message: 'Rule deleted. Target agents will remove its block on their next heartbeat.' });
  } catch (error) { handleError(res, error); }
});

module.exports = router;
module.exports._test = { authorizedScope, validateRule, validId, ruleScope };
