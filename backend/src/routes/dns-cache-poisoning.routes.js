const router = require('express').Router();
const crypto = require('crypto');
const net = require('net');
const mongoose = require('mongoose');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const DnsCachePoisonConfig = require('../models/DnsCachePoisonConfig.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { buildCapabilityQuery } = require('../utils/advancedCapability');

router.use(authenticate, requireAnalyst);

const BUILT_IN_RULES = Object.freeze([
  { id: 'private-answer', name: 'Private / Loopback Answer', description: 'Detect a public monitored domain resolving to private, loopback, link-local or reserved space.', severity: 'critical', settings: { severity: 'critical' } },
  { id: 'ttl-anomaly', name: 'DNS TTL Anomaly', description: 'Detect a significant TTL drop or TTL outside the configured safe range.', severity: 'high', settings: { severity: 'high', minSafeTtl: 30, maxSafeTtl: 86400 } },
  { id: 'resolver-change', name: 'Resolver Configuration Change', description: 'Detect changes to endpoint DNS resolver configuration and untrusted resolvers.', severity: 'high', settings: { severity: 'high' } },
  { id: 'hosts-file-change', name: 'Hosts File Change', description: 'Detect modification of the operating-system hosts file.', severity: 'high', settings: { severity: 'high' } },
]);
const RULE_IDS = new Set(BUILT_IN_RULES.map(rule => rule.id));
const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const DEFAULTS = Object.freeze({
  enabled: true,
  telemetryEnabled: true,
  watchDomains: [],
  trustedResolvers: [],
  scanIntervalSeconds: 300,
  minSafeTtl: 30,
  maxSafeTtl: 86400,
  baselineWindowSeconds: 3600,
  monitorResolverChanges: true,
  monitorHostsChanges: true,
  detectPrivateAnswers: true,
  builtInRuleIds: [...RULE_IDS],
  builtInRuleOverrides: {},
  customRules: [],
  targetMode: 'all',
  targetSystemIds: [],
  version: 1,
});

function companyId(req) {
  if (!mongoose.isValidObjectId(req.user?.companyId)) {
    const error = new Error('A valid company scope is required');
    error.status = 403;
    throw error;
  }
  return new mongoose.Types.ObjectId(req.user.companyId);
}

function errorResponse(res, error) {
  const status = Number(error?.status) || (error?.name === 'CastError' ? 400 : 500);
  if (status >= 500) console.error('[dns-cache-poisoning]', error);
  res.status(status).json({ message: status >= 500 ? 'DNS Cache Poisoning request failed' : error.message });
}

function cleanDomain(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function sanitize(body = {}) {
  const watchDomains = [...new Set((Array.isArray(body.watchDomains) ? body.watchDomains : [])
    .map(cleanDomain).filter(Boolean))];
  if (watchDomains.length > 200 || watchDomains.some(domain => domain.length > 253 || !DOMAIN_PATTERN.test(domain))) {
    const error = new Error('Watch domains contain an invalid domain'); error.status = 400; throw error;
  }
  const trustedResolvers = [...new Set((Array.isArray(body.trustedResolvers) ? body.trustedResolvers : [])
    .map(value => String(value || '').trim()).filter(Boolean))];
  if (trustedResolvers.length > 100 || trustedResolvers.some(ip => !net.isIP(ip))) {
    const error = new Error('Trusted resolvers must contain valid IP addresses'); error.status = 400; throw error;
  }
  const integer = (name, fallback, min, max) => {
    const value = Number(body[name] ?? fallback);
    if (!Number.isInteger(value) || value < min || value > max) {
      const error = new Error(`${name} must be between ${min} and ${max}`); error.status = 400; throw error;
    }
    return value;
  };
  const builtInRuleIds = [...new Set(Array.isArray(body.builtInRuleIds) ? body.builtInRuleIds.map(String) : [...RULE_IDS])];
  if (builtInRuleIds.some(id => !RULE_IDS.has(id))) {
    const error = new Error('One or more built-in rules are invalid'); error.status = 400; throw error;
  }
  const targetMode = body.targetMode === 'selected' ? 'selected' : 'all';
  const targetSystemIds = targetMode === 'selected'
    ? [...new Set((Array.isArray(body.targetSystemIds) ? body.targetSystemIds : []).map(String))]
    : [];
  if (targetMode === 'selected' && (!targetSystemIds.length || targetSystemIds.some(id => !mongoose.isValidObjectId(id)))) {
    const error = new Error('Select at least one valid endpoint'); error.status = 400; throw error;
  }
  const minSafeTtl = integer('minSafeTtl', 30, 1, 86400);
  const maxSafeTtl = integer('maxSafeTtl', 86400, 30, 604800);
  if (maxSafeTtl <= minSafeTtl) {
    const error = new Error('Maximum safe TTL must be greater than minimum safe TTL'); error.status = 400; throw error;
  }
  const incomingOverrides = body.builtInRuleOverrides && typeof body.builtInRuleOverrides === 'object'
    ? body.builtInRuleOverrides
    : {};
  if (Object.keys(incomingOverrides).some(id => !RULE_IDS.has(id))) {
    const error = new Error('One or more built-in rule overrides are invalid'); error.status = 400; throw error;
  }
  const builtInRuleOverrides = Object.fromEntries(Object.entries(incomingOverrides)
    .map(([id, settings]) => [id, sanitizeBuiltInSettings(id, settings)]));
  const incomingCustomRules = Array.isArray(body.customRules) ? body.customRules : [];
  if (incomingCustomRules.length > 100) {
    const error = new Error('A maximum of 100 custom DNS rules is allowed'); error.status = 400; throw error;
  }
  const customRules = incomingCustomRules.map(rule => {
    const suppliedId = String(rule?.id || '');
    const safeId = /^custom-[a-z0-9-]{1,72}$/i.test(suppliedId) ? suppliedId : '';
    return sanitizeCustomRule(rule, safeId);
  });
  const customKeys = customRules.map(rule => `${rule.domain}|${rule.queryType}`);
  if (new Set(customKeys).size !== customKeys.length) {
    const error = new Error('Only one custom rule is allowed per domain and query type'); error.status = 409; throw error;
  }
  return {
    enabled: body.enabled !== false,
    telemetryEnabled: body.telemetryEnabled !== false,
    watchDomains,
    trustedResolvers,
    scanIntervalSeconds: integer('scanIntervalSeconds', 300, 60, 3600),
    minSafeTtl,
    maxSafeTtl,
    baselineWindowSeconds: integer('baselineWindowSeconds', 3600, 60, 86400),
    monitorResolverChanges: body.monitorResolverChanges !== false,
    monitorHostsChanges: body.monitorHostsChanges !== false,
    detectPrivateAnswers: body.detectPrivateAnswers !== false,
    builtInRuleIds,
    builtInRuleOverrides,
    customRules,
    targetMode,
    targetSystemIds,
  };
}

function agentSettings(config, targeted = true) {
  const selected = new Set(config.builtInRuleIds || [...RULE_IDS]);
  const overrides = config.builtInRuleOverrides || {};
  const ttl = overrides['ttl-anomaly'] || {};
  const builtInIpRules = BUILT_IN_RULES.flatMap(rule => {
    const settings = overrides[rule.id] || {};
    if (!selected.has(rule.id) || !settings.domain || !(settings.expectedIps || []).length) return [];
    return [{
      id: `built-in-${rule.id}`, name: `${rule.name} IP condition`, domain: settings.domain,
      queryType: settings.queryType || 'A', expectedIps: settings.expectedIps,
      severity: settings.severity || rule.severity, enabled: settings.enabled !== false,
    }];
  });
  return {
    cache_poison_enabled: targeted && config.enabled !== false,
    cache_poison_telemetry_enabled: targeted && config.telemetryEnabled !== false,
    cache_poison_watch_domains: config.watchDomains || [],
    cache_poison_trusted_resolvers: config.trustedResolvers || [],
    cache_poison_scan_interval_seconds: Number(config.scanIntervalSeconds || 300),
    cache_poison_min_safe_ttl: Number(ttl.minSafeTtl || config.minSafeTtl || 30),
    cache_poison_max_safe_ttl: Number(ttl.maxSafeTtl || config.maxSafeTtl || 86400),
    cache_poison_baseline_window_seconds: Number(config.baselineWindowSeconds || 3600),
    cache_poison_monitor_resolver_changes: selected.has('resolver-change') && config.monitorResolverChanges !== false,
    cache_poison_monitor_hosts_changes: selected.has('hosts-file-change') && config.monitorHostsChanges !== false,
    cache_poison_detect_private_answers: selected.has('private-answer') && config.detectPrivateAnswers !== false,
    cache_poison_detect_ttl_anomaly: selected.has('ttl-anomaly'),
    cache_poison_builtin_rule_ids: [...selected],
    cache_poison_rule_severities: Object.fromEntries(BUILT_IN_RULES.map(rule => [rule.id, overrides[rule.id]?.severity || rule.settings.severity])),
    cache_poison_custom_rules: [...builtInIpRules, ...(config.customRules || []).map(rule => ({
      id: rule.id, name: rule.name, domain: rule.domain, queryType: rule.queryType,
      expectedIps: rule.expectedIps || [], severity: rule.severity, enabled: rule.enabled !== false,
    }))],
    cache_poison_policy_version: Number(config.version || 0),
  };
}

async function audit(req, action, targetType, targetId, metadata = {}) {
  try {
    await SocAuditEvent.create({
      tenantId: req.user.tenantId || null,
      companyId: companyId(req), actorId: req.user.id || req.user._id,
      action, targetType, targetId: String(targetId || ''), metadata,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || '',
    });
  } catch (error) { console.error('[dns-cache-poisoning/audit]', error.message); }
}

async function currentConfig(id) {
  return (await DnsCachePoisonConfig.findOne({ companyId: id }).lean()) || { ...DEFAULTS, companyId: id };
}

function builtInRulesFor(config) {
  const overrides = config?.builtInRuleOverrides || {};
  return BUILT_IN_RULES.map(rule => ({
    ...rule,
    settings: { ...rule.settings, ...(overrides[rule.id] || {}) },
  }));
}

function sanitizeBuiltInSettings(ruleId, input = {}) {
  const severity = String(input.severity || BUILT_IN_RULES.find(rule => rule.id === ruleId)?.severity || 'high').toLowerCase();
  if (!['low', 'medium', 'high', 'critical'].includes(severity)) {
    const error = new Error('Rule severity is invalid'); error.status = 400; throw error;
  }
  const settings = { severity };
  if (ruleId === 'ttl-anomaly') {
    const minSafeTtl = Number(input.minSafeTtl ?? 30);
    const maxSafeTtl = Number(input.maxSafeTtl ?? 86400);
    if (!Number.isInteger(minSafeTtl) || minSafeTtl < 1 || minSafeTtl > 86400
      || !Number.isInteger(maxSafeTtl) || maxSafeTtl < 30 || maxSafeTtl > 604800
      || maxSafeTtl <= minSafeTtl) {
      const error = new Error('TTL rule requires valid minimum and maximum values'); error.status = 400; throw error;
    }
    settings.minSafeTtl = minSafeTtl;
    settings.maxSafeTtl = maxSafeTtl;
  }
  const domain = cleanDomain(input.domain);
  const expectedIps = [...new Set((Array.isArray(input.expectedIps) ? input.expectedIps : [])
    .map(value => String(value || '').trim()).filter(Boolean))];
  if (domain || expectedIps.length) {
    const queryType = String(input.queryType || 'A').toUpperCase();
    if (!domain || domain.length > 253 || !DOMAIN_PATTERN.test(domain)) {
      const error = new Error('Enter a valid domain for the built-in rule IP condition'); error.status = 400; throw error;
    }
    if (!['A', 'AAAA'].includes(queryType)) {
      const error = new Error('Query type must be A or AAAA'); error.status = 400; throw error;
    }
    const expectedVersion = queryType === 'AAAA' ? 6 : 4;
    if (!expectedIps.length || expectedIps.length > 50 || expectedIps.some(ip => net.isIP(ip) !== expectedVersion)) {
      const error = new Error(`Add 1-50 valid ${queryType === 'AAAA' ? 'IPv6' : 'IPv4'} expected addresses`); error.status = 400; throw error;
    }
    Object.assign(settings, { domain, queryType, expectedIps, enabled: input.enabled !== false });
  }
  return settings;
}

function sanitizeCustomRule(input = {}, ruleId = '') {
  const name = String(input.name || '').trim();
  const domain = cleanDomain(input.domain);
  const queryType = String(input.queryType || 'A').toUpperCase();
  const severity = String(input.severity || 'high').toLowerCase();
  const expectedIps = [...new Set((Array.isArray(input.expectedIps) ? input.expectedIps : [])
    .map(value => String(value || '').trim()).filter(Boolean))];

  if (!name || name.length > 120) {
    const error = new Error('Rule name is required and must be 120 characters or fewer'); error.status = 400; throw error;
  }
  if (!domain || domain.length > 253 || !DOMAIN_PATTERN.test(domain)) {
    const error = new Error('Enter a valid domain for the rule'); error.status = 400; throw error;
  }
  if (!['A', 'AAAA'].includes(queryType)) {
    const error = new Error('Query type must be A or AAAA'); error.status = 400; throw error;
  }
  if (!['low', 'medium', 'high', 'critical'].includes(severity)) {
    const error = new Error('Rule severity is invalid'); error.status = 400; throw error;
  }
  const expectedVersion = queryType === 'AAAA' ? 6 : 4;
  if (!expectedIps.length || expectedIps.length > 50 || expectedIps.some(ip => net.isIP(ip) !== expectedVersion)) {
    const error = new Error(`Add 1-50 valid ${queryType === 'AAAA' ? 'IPv6' : 'IPv4'} expected addresses`); error.status = 400; throw error;
  }
  return {
    id: ruleId || `custom-${crypto.randomUUID()}`,
    name, domain, queryType, expectedIps, severity,
    enabled: input.enabled !== false,
  };
}

async function ownedSystems(id) {
  return System.find({
    companyId: id,
    $or: [{ agentType: { $in: ['system', 'server'] } }, { agentType: { $exists: false } }],
  }).select('_id name hostname status lastSeen dnsCachePoisonEnabled dnsCachePoisonTelemetryEnabled dnsCachePoisonPolicyVersion dnsCachePoisonStatus pendingCommands').lean();
}

async function queueConfiguration(req, config) {
  const systems = await ownedSystems(companyId(req));
  const targets = new Set((config.targetSystemIds || []).map(String));
  await Promise.all(systems.map(async system => {
    const targeted = config.targetMode !== 'selected' || targets.has(String(system._id));
    const command = {
      id: `${Date.now()}-dcp-${crypto.randomUUID().slice(0, 8)}`,
      command: 'configure_dns_cache_poisoning',
      systemId: String(system._id), settings: agentSettings(config, targeted), createdAt: new Date(),
    };
    await System.updateOne({ _id: system._id }, {
      $pull: { pendingCommands: { command: 'configure_dns_cache_poisoning' } },
    });
    await System.updateOne({ _id: system._id }, {
      $push: { pendingCommands: { $each: [command], $slice: -20 } },
    });
    req.app.get('io')?.to(`system_${system._id}`).emit('agent:command', command);
  }));
  return systems.filter(system => config.targetMode !== 'selected' || targets.has(String(system._id)));
}

router.get('/configuration', async (req, res) => {
  try {
    const id = companyId(req);
    const [config, systems] = await Promise.all([currentConfig(id), ownedSystems(id)]);
    res.json({
      configuration: {
        ...DEFAULTS, ...config,
        targetSystemIds: (config.targetSystemIds || []).map(String),
      },
      builtInRules: builtInRulesFor(config),
      systems: systems.map(system => ({
        _id: system._id, name: system.name, hostname: system.hostname, status: system.status,
        lastSeen: system.lastSeen, enabled: system.dnsCachePoisonEnabled,
        telemetryEnabled: system.dnsCachePoisonTelemetryEnabled,
        appliedVersion: Number(system.dnsCachePoisonPolicyVersion || 0),
        telemetryStatus: system.dnsCachePoisonStatus || {},
        pending: (system.pendingCommands || []).some(command => command?.command === 'configure_dns_cache_poisoning'),
      })),
    });
  } catch (error) { errorResponse(res, error); }
});

router.patch('/configuration/built-in/:ruleId', requireManager, async (req, res) => {
  try {
    const id = companyId(req);
    const ruleId = String(req.params.ruleId || '');
    if (!RULE_IDS.has(ruleId)) return res.status(404).json({ message: 'Built-in DNS cache-poisoning rule not found' });
    const settings = sanitizeBuiltInSettings(ruleId, req.body?.settings || {});
    const existing = await currentConfig(id);
    const builtInRuleOverrides = { ...(existing.builtInRuleOverrides || {}), [ruleId]: settings };
    const config = await DnsCachePoisonConfig.findOneAndUpdate(
      { companyId: id },
      { $set: { builtInRuleOverrides, lastDeployedBy: req.user.id || req.user._id } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    await audit(req, 'Edit Built-in DNS Cache Poisoning Rule', 'DnsCachePoisonConfig', config._id, { ruleId, settings });
    res.json({ message: 'Built-in rule saved. Apply Configuration to deploy it.', rule: builtInRulesFor(config).find(rule => rule.id === ruleId) });
  } catch (error) { errorResponse(res, error); }
});

router.post('/configuration/rules', requireManager, async (req, res) => {
  try {
    const id = companyId(req);
    const rule = sanitizeCustomRule(req.body || {});
    const existing = await currentConfig(id);
    const customRules = [...(existing.customRules || []).map(item => ({ ...item })), rule];
    if (customRules.length > 100) return res.status(400).json({ message: 'A maximum of 100 custom DNS rules is allowed' });
    const duplicate = customRules.some(item => item.id !== rule.id
      && item.domain === rule.domain && item.queryType === rule.queryType);
    if (duplicate) return res.status(409).json({ message: 'A custom rule already exists for this domain and query type' });
    const config = await DnsCachePoisonConfig.findOneAndUpdate(
      { companyId: id },
      { $set: { customRules, lastDeployedBy: req.user.id || req.user._id } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    await audit(req, 'Create Custom DNS Cache Poisoning Rule', 'DnsCachePoisonConfig', config._id, { ruleId: rule.id, domain: rule.domain });
    res.status(201).json({ message: 'Custom rule added. Apply Configuration to deploy it.', rule });
  } catch (error) { errorResponse(res, error); }
});

router.patch('/configuration/rules/:ruleId', requireManager, async (req, res) => {
  try {
    const id = companyId(req);
    const existing = await currentConfig(id);
    const ruleId = String(req.params.ruleId || '');
    const index = (existing.customRules || []).findIndex(item => item.id === ruleId);
    if (index < 0) return res.status(404).json({ message: 'Custom DNS rule not found' });
    const rule = sanitizeCustomRule(req.body || {}, ruleId);
    const customRules = (existing.customRules || []).map((item, itemIndex) => itemIndex === index ? rule : { ...item });
    const duplicate = customRules.some(item => item.id !== rule.id
      && item.domain === rule.domain && item.queryType === rule.queryType);
    if (duplicate) return res.status(409).json({ message: 'A custom rule already exists for this domain and query type' });
    const config = await DnsCachePoisonConfig.findOneAndUpdate(
      { companyId: id },
      { $set: { customRules, lastDeployedBy: req.user.id || req.user._id } },
      { new: true, runValidators: true },
    ).lean();
    await audit(req, 'Edit Custom DNS Cache Poisoning Rule', 'DnsCachePoisonConfig', config._id, { ruleId, domain: rule.domain });
    res.json({ message: 'Custom rule updated. Apply Configuration to deploy it.', rule });
  } catch (error) { errorResponse(res, error); }
});

router.delete('/configuration/rules/:ruleId', requireManager, async (req, res) => {
  try {
    const id = companyId(req);
    const existing = await currentConfig(id);
    const ruleId = String(req.params.ruleId || '');
    const customRules = (existing.customRules || []).filter(item => item.id !== ruleId);
    if (customRules.length === (existing.customRules || []).length) return res.status(404).json({ message: 'Custom DNS rule not found' });
    const config = await DnsCachePoisonConfig.findOneAndUpdate(
      { companyId: id },
      { $set: { customRules, lastDeployedBy: req.user.id || req.user._id } },
      { new: true, runValidators: true },
    ).lean();
    await audit(req, 'Delete Custom DNS Cache Poisoning Rule', 'DnsCachePoisonConfig', config._id, { ruleId });
    res.json({ message: 'Custom rule deleted. Apply Configuration to deploy the change.' });
  } catch (error) { errorResponse(res, error); }
});

router.put('/configuration', requireManager, async (req, res) => {
  try {
    const id = companyId(req);
    const settings = sanitize(req.body || {});
    if (settings.targetMode === 'selected') {
      const count = await System.countDocuments({ companyId: id, _id: { $in: settings.targetSystemIds } });
      if (count !== settings.targetSystemIds.length) return res.status(404).json({ message: 'One or more selected endpoints were not found' });
    }
    const existing = await currentConfig(id);
    const config = await DnsCachePoisonConfig.findOneAndUpdate({ companyId: id }, { $set: {
      ...settings, version: Number(existing.version || 0) + 1,
      lastDeployedAt: new Date(), lastDeployedBy: req.user.id || req.user._id,
    } }, { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true }).lean();
    const systems = await queueConfiguration(req, config);
    await audit(req, 'Configure DNS Cache Poisoning', 'DnsCachePoisonConfig', config._id, { version: config.version, targetCount: systems.length });
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('dns-cache-poisoning:configuration-updated', { version: config.version });
    res.json({ message: `DNS cache-poisoning policy queued for ${systems.length} agent(s)`, configuration: config, targetCount: systems.length });
  } catch (error) { errorResponse(res, error); }
});

router.post('/configuration/sync', requireManager, async (req, res) => {
  try {
    const config = await currentConfig(companyId(req));
    const systems = await queueConfiguration(req, config);
    await audit(req, 'Synchronize DNS Cache Poisoning Policy', 'DnsCachePoisonConfig', config._id || req.user.companyId, { targetCount: systems.length });
    res.json({ message: `Policy synchronization queued for ${systems.length} agent(s)`, targetCount: systems.length });
  } catch (error) { errorResponse(res, error); }
});

router.get('/status', async (req, res) => {
  try {
    const id = companyId(req);
    const [config, systems, lastAlert] = await Promise.all([
      currentConfig(id), ownedSystems(id),
      Alert.findOne(buildCapabilityQuery({ companyId: id, capabilityId: 30, since: new Date(0) })).sort({ createdAt: -1 }).select('createdAt').lean(),
    ]);
    const online = systems.filter(system => ['active', 'online'].includes(String(system.status || '').toLowerCase()));
    res.json({
      enabled: config.enabled !== false, telemetryEnabled: config.telemetryEnabled !== false,
      totalAgents: systems.length, onlineAgents: online.length,
      reportingAgents: systems.filter(system => system.dnsCachePoisonStatus?.lastScanAt).length,
      policyVersion: Number(config.version || 0), lastTelemetryAt: lastAlert?.createdAt || null,
    });
  } catch (error) { errorResponse(res, error); }
});

async function queueAlertAction(req, res, command, actionName) {
  const id = companyId(req);
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
  const alert = await Alert.findOne({ _id: req.params.id, ...buildCapabilityQuery({ companyId: id, capabilityId: 30, since: new Date(0) }) }).lean();
  if (!alert) return res.status(404).json({ message: 'DNS cache-poisoning alert not found' });
  const systemId = alert.systemId?._id || alert.systemId;
  if (!mongoose.isValidObjectId(systemId)) return res.status(409).json({ message: 'Alert is not linked to an endpoint agent' });
  const queued = { id: `${Date.now()}-dcp-${crypto.randomUUID().slice(0, 8)}`, command, alertId: String(alert._id), createdAt: new Date() };
  const updated = await System.updateOne({ _id: systemId, companyId: id }, { $push: { pendingCommands: { $each: [queued], $slice: -20 } } });
  if (!updated.matchedCount) return res.status(404).json({ message: 'Endpoint agent not found' });
  req.app.get('io')?.to(`system_${systemId}`).emit('agent:command', queued);
  await audit(req, actionName, 'Alert', alert._id, { systemId: String(systemId), commandId: queued.id });
  return res.status(202).json({ message: `${actionName} queued for the endpoint agent`, commandId: queued.id });
}

router.post('/alerts/:id/flush-cache', requireManager, async (req, res) => {
  try { await queueAlertAction(req, res, 'flush_dns_cache', 'Flush DNS Cache'); } catch (error) { errorResponse(res, error); }
});

router.post('/alerts/:id/restore-resolver', requireManager, async (req, res) => {
  try { await queueAlertAction(req, res, 'restore_dns_resolver', 'Restore DNS Resolver'); } catch (error) { errorResponse(res, error); }
});

module.exports = router;
