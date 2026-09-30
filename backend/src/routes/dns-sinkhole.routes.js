const router = require('express').Router();
const mongoose = require('mongoose');
const net = require('net');
const crypto = require('crypto');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const EdrIncident = require('../models/EdrIncident.model');
const DnsSinkholeRule = require('../models/DnsSinkholeRule.model');
const DnsSinkholeConfig = require('../models/DnsSinkholeConfig.model');
const { buildCapabilityQuery, indicatorValue } = require('../utils/advancedCapability');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { claimAlertsForIncident } = require('../services/socCaseExclusivity.service');

// Middleware to secure all routes under /api/dns-sinkhole
router.use(authenticate, requireAnalyst);

// Helper for audit logging
async function auditLog(req, action, targetType, targetId, metadata = {}) {
  try {
    await SocAuditEvent.create({
      tenantId: req.user.tenantId || null,
      companyId: req.user.companyId ? new mongoose.Types.ObjectId(req.user.companyId) : null,
      actorId: req.user.id || req.user._id,
      action,
      targetType,
      targetId: String(targetId || ''),
      metadata,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || '127.0.0.1',
    });
  } catch (err) {
    console.error('[dns-sinkhole/audit] failed:', err.message);
  }
}

// Helper to determine time range
function getTimeRange(windowHours) {
  const hours = Math.min(720, Math.max(1, parseInt(windowHours || 24, 10)));
  const now = new Date();
  const since = new Date(now.getTime() - hours * 60 * 60 * 1000);
  const prevSince = new Date(since.getTime() - hours * 60 * 60 * 1000);
  const prevUntil = since;
  return { since, prevSince, prevUntil, now };
}

function escapeRegExp(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function safeRegex(value, maxLength = 253) {
  return new RegExp(escapeRegExp(String(value || '').trim().slice(0, maxLength)), 'i');
}

function validCompanyId(req) {
  if (!mongoose.Types.ObjectId.isValid(req.user?.companyId)) {
    const error = new Error('A valid company scope is required');
    error.status = 403;
    throw error;
  }
  return new mongoose.Types.ObjectId(req.user.companyId);
}

function sendError(res, err) {
  const status = Number(err?.status) || (err?.name === 'CastError' ? 400 : 500);
  if (status >= 500) console.error('[dns-sinkhole]', err);
  return res.status(status).json({ message: status >= 500 ? 'DNS Sinkhole request failed' : err.message });
}

function eventWeight(alert) {
  const raw = alert?.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : {};
  const candidate = [alert?.dnsQueryCount, alert?.queryCount, alert?.hitCount, raw.dns_query_count, raw.query_count, raw.hit_count]
    .map(Number).find(number => Number.isFinite(number) && number > 0);
  return candidate || 1;
}

function normalizeDomain(value) {
  const domain = String(value || '').trim().toLowerCase().replace(/\.$/, '');
  if (!domain || domain.length > 253 || !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(domain)) {
    const error = new Error('A valid domain name is required');
    error.status = 400;
    throw error;
  }
  return domain;
}

function normalizeSinkholeIp(value, fallback = '0.0.0.0') {
  const sinkholeIp = String(value || fallback || '0.0.0.0').trim();
  if (net.isIP(sinkholeIp) !== 4) {
    const error = new Error('Sinkhole server IP must be a valid IPv4 address');
    error.status = 400;
    throw error;
  }
  return sinkholeIp;
}

function normalizeRedirectIp(value) {
  const sinkholeIp = normalizeSinkholeIp(value);
  if (sinkholeIp === '0.0.0.0') {
    const error = new Error('Redirect rules require a reachable safe server IPv4 address');
    error.status = 400;
    throw error;
  }
  return sinkholeIp;
}

function sinkholeTargets(rules, configuration) {
  return Object.fromEntries(rules
    .filter(rule => ['blocklist', 'redirect'].includes(rule.type))
    .map(rule => [rule.domain, rule.type === 'redirect'
      ? normalizeRedirectIp(rule.sinkholeIp)
      : normalizeSinkholeIp(rule.sinkholeIp, configuration.sinkholeIp)]));
}

const isSinkholeRule = rule => ['blocklist', 'redirect'].includes(rule?.type);

const BUILT_IN_DNS_RULES = Object.freeze([
  { id: 'company-blocklist-enforcement', name: 'Company Blocklist Enforcement', description: 'Sinkhole every active domain in this company blocklist on targeted endpoints.', severity: 'critical', category: 'Enforcement', settings: { defaultSeverity: 'high' } },
  { id: 'dns-anomaly-detection', name: 'DNS Anomaly & Tunneling Detection', description: 'Detect high query volume, repeated NXDOMAIN responses, encoded labels and long subdomains.', severity: 'high', category: 'Detection', settings: { alertThreshold: 45, cooldownSeconds: 1800 } },
  { id: 'strict-dns-anomaly-detection', name: 'Strict DNS Tunnel Sensitivity', description: 'Lower the DNS anomaly alert threshold for high-risk endpoint groups.', severity: 'high', category: 'Detection', settings: { alertThreshold: 30, cooldownSeconds: 900 } },
  { id: 'dns-beaconing-detection', name: 'DNS Beaconing Detection', description: 'Detect periodic DNS callbacks that may indicate command-and-control activity.', severity: 'high', category: 'Detection', settings: { alertThreshold: 55, minimumConnections: 6, consistencyThreshold: 75, cooldownSeconds: 1800 } },
  { id: 'sinkhole-policy-telemetry', name: 'Sinkhole Policy Telemetry', description: 'Report applied policy state and domain policy changes as capability-31 telemetry.', severity: 'medium', category: 'Telemetry', settings: { reportIntervalSeconds: 300 } },
]);
const BUILT_IN_DNS_RULE_IDS = new Set(BUILT_IN_DNS_RULES.map(rule => rule.id));
const DEFAULT_BUILT_IN_RULE_IDS = [
  'company-blocklist-enforcement',
  'dns-anomaly-detection',
  'dns-beaconing-detection',
  'sinkhole-policy-telemetry',
];

const DEFAULT_CONFIGURATION = Object.freeze({
  enabled: true,
  sinkholeIp: '0.0.0.0',
  enforcementMode: 'both',
  telemetryEnabled: true,
  reportIntervalSeconds: 300,
  syncBlocklist: true,
  builtInRuleIds: DEFAULT_BUILT_IN_RULE_IDS,
  builtInRuleOverrides: {},
  targetMode: 'all',
  targetSystemIds: [],
  version: 1,
});

function sanitizeConfiguration(body = {}) {
  const sinkholeIp = String(body.sinkholeIp || '0.0.0.0').trim();
  if (net.isIP(sinkholeIp) !== 4) {
    const error = new Error('Sinkhole IP must be a valid IPv4 address');
    error.status = 400;
    throw error;
  }
  const enforcementMode = String(body.enforcementMode || 'both').toLowerCase();
  if (!['hosts', 'dnsmasq', 'both'].includes(enforcementMode)) {
    const error = new Error('Unsupported enforcement mode');
    error.status = 400;
    throw error;
  }
  const reportIntervalSeconds = Number(body.reportIntervalSeconds ?? 300);
  if (!Number.isInteger(reportIntervalSeconds) || reportIntervalSeconds < 60 || reportIntervalSeconds > 3600) {
    const error = new Error('Report interval must be between 60 and 3600 seconds');
    error.status = 400;
    throw error;
  }
  const targetMode = body.targetMode === 'selected' ? 'selected' : 'all';
  const targetSystemIds = targetMode === 'selected'
    ? [...new Set(Array.isArray(body.targetSystemIds) ? body.targetSystemIds.map(String) : [])]
    : [];
  if (targetMode === 'selected' && (!targetSystemIds.length || targetSystemIds.some(id => !mongoose.isValidObjectId(id)))) {
    const error = new Error('Select at least one valid agent endpoint');
    error.status = 400;
    throw error;
  }
  return {
    enabled: body.enabled !== false,
    sinkholeIp,
    enforcementMode,
    telemetryEnabled: body.telemetryEnabled !== false,
    reportIntervalSeconds,
    syncBlocklist: body.syncBlocklist !== false,
    targetMode,
    targetSystemIds,
  };
}

function agentSettings(configuration) {
  const selectedRules = new Set(configuration.builtInRuleIds || DEFAULT_BUILT_IN_RULE_IDS);
  const strictDns = selectedRules.has('strict-dns-anomaly-detection');
  const overrides = configuration.builtInRuleOverrides || {};
  const anomalySettings = overrides['dns-anomaly-detection'] || {};
  const strictSettings = overrides['strict-dns-anomaly-detection'] || {};
  const beaconSettings = overrides['dns-beaconing-detection'] || {};
  const telemetrySettings = overrides['sinkhole-policy-telemetry'] || {};
  const blocklistSettings = overrides['company-blocklist-enforcement'] || {};
  return {
    dns_sinkhole_enabled: configuration.enabled === true,
    dns_sinkhole_ip: configuration.sinkholeIp,
    dns_sinkhole_enforcement_mode: configuration.enforcementMode,
    dns_sinkhole_telemetry_enabled: configuration.telemetryEnabled === true,
    dns_sinkhole_report_interval_seconds: Number(telemetrySettings.reportIntervalSeconds || configuration.reportIntervalSeconds),
    dns_sinkhole_sync_blocklist: configuration.syncBlocklist === true,
    dns_sinkhole_policy_version: configuration.version,
    dns_sinkhole_builtin_rule_ids: [...selectedRules],
    dns_anomaly_detection_enabled: selectedRules.has('dns-anomaly-detection') || strictDns,
    dns_sinkhole_default_severity: blocklistSettings.defaultSeverity || 'high',
    dns_anomaly_threshold: Number(strictDns ? (strictSettings.alertThreshold || 30) : (anomalySettings.alertThreshold || 45)),
    dns_anomaly_cooldown_seconds: Number(strictDns ? (strictSettings.cooldownSeconds || 900) : (anomalySettings.cooldownSeconds || 1800)),
    dns_beacon_detection_enabled: selectedRules.has('dns-beaconing-detection'),
    dns_beacon_alert_threshold: Number(beaconSettings.alertThreshold || (strictDns ? 45 : 55)),
    beacon_min_connections: Number(beaconSettings.minimumConnections || 6),
    beacon_consistency_threshold: Number(beaconSettings.consistencyThreshold || 75),
    beacon_alert_cooldown_seconds: Number(beaconSettings.cooldownSeconds || 1800),
  };
}

function builtInRulesFor(configuration) {
  const overrides = configuration?.builtInRuleOverrides || {};
  return BUILT_IN_DNS_RULES.map(rule => ({
    ...rule,
    settings: { ...rule.settings, ...(overrides[rule.id] || {}) },
  }));
}

function sanitizeBuiltInSettings(ruleId, input = {}) {
  const integer = (key, fallback, min, max) => {
    const value = Number(input[key] ?? fallback);
    if (!Number.isInteger(value) || value < min || value > max) {
      const error = new Error(`${key} must be between ${min} and ${max}`);
      error.status = 400;
      throw error;
    }
    return value;
  };
  if (ruleId === 'company-blocklist-enforcement') {
    const defaultSeverity = String(input.defaultSeverity || 'high').toLowerCase();
    if (!['low', 'medium', 'high', 'critical'].includes(defaultSeverity)) {
      const error = new Error('defaultSeverity is invalid'); error.status = 400; throw error;
    }
    return { defaultSeverity };
  }
  if (ruleId === 'dns-anomaly-detection' || ruleId === 'strict-dns-anomaly-detection') {
    const defaults = ruleId === 'strict-dns-anomaly-detection'
      ? { alertThreshold: 30, cooldownSeconds: 900 }
      : { alertThreshold: 45, cooldownSeconds: 1800 };
    return {
      alertThreshold: integer('alertThreshold', defaults.alertThreshold, 25, 100),
      cooldownSeconds: integer('cooldownSeconds', defaults.cooldownSeconds, 60, 86400),
    };
  }
  if (ruleId === 'dns-beaconing-detection') {
    return {
      alertThreshold: integer('alertThreshold', 55, 25, 100),
      minimumConnections: integer('minimumConnections', 6, 4, 100),
      consistencyThreshold: integer('consistencyThreshold', 75, 40, 100),
      cooldownSeconds: integer('cooldownSeconds', 1800, 60, 86400),
    };
  }
  if (ruleId === 'sinkhole-policy-telemetry') {
    return { reportIntervalSeconds: integer('reportIntervalSeconds', 300, 60, 3600) };
  }
  const error = new Error('Unknown built-in DNS rule'); error.status = 404; throw error;
}

async function targetSystems(companyId, configuration) {
  const query = { companyId, $or: [{ agentType: { $in: ['system', 'server'] } }, { agentType: { $exists: false } }] };
  if (configuration?.targetMode === 'selected') query._id = { $in: configuration.targetSystemIds || [] };
  return System.find(query).select('_id name hostname status lastSeen dnsSinkholeEnabled dnsSinkholeTelemetryEnabled dnsSinkholeEnforcementMode dnsSinkholePolicyVersion pendingCommands').lean();
}

async function allDnsSystems(companyId) {
  return System.find({ companyId, $or: [{ agentType: { $in: ['system', 'server'] } }, { agentType: { $exists: false } }] })
    .select('_id name hostname status lastSeen dnsSinkholeEnabled dnsSinkholeTelemetryEnabled dnsSinkholeEnforcementMode dnsSinkholePolicyVersion pendingCommands')
    .lean();
}

async function queueDnsCommand(req, configuration, command, payload = {}) {
  const companyId = validCompanyId(req);
  const systems = command === 'configure_dns_sinkhole'
    ? await allDnsSystems(companyId)
    : await targetSystems(companyId, configuration);
  const io = req.app.get('io');
  await Promise.all(systems.map(async system => {
    const id = `${Date.now()}-dns-${crypto.randomUUID().slice(0, 8)}`;
    const isTarget = configuration?.targetMode !== 'selected'
      || (configuration.targetSystemIds || []).map(String).includes(String(system._id));
    const commandPayload = command === 'configure_dns_sinkhole'
      ? {
          ...payload,
          settings: { ...(payload.settings || {}), dns_sinkhole_enabled: configuration.enabled === true && isTarget },
          blocklist: isTarget ? (payload.blocklist || []) : [],
          allowlist: isTarget ? (payload.allowlist || []) : [],
        }
      : payload;
    const outbound = { id, command, systemId: String(system._id), ...commandPayload, createdAt: new Date() };
    if (command === 'configure_dns_sinkhole') {
      await System.updateOne({ _id: system._id }, { $pull: { pendingCommands: { command } } });
    } else if (command.startsWith('dns_sinkhole_') && commandPayload.domain) {
      await System.updateOne({ _id: system._id }, {
        $pull: {
          pendingCommands: {
            command: { $in: ['dns_sinkhole_add', 'dns_sinkhole_remove'] },
            domain: commandPayload.domain,
          },
        },
      });
    }
    await System.updateOne(
      { _id: system._id },
      { $push: { pendingCommands: { $each: [outbound], $slice: -20 } } },
    );
    io?.to(`system_${system._id}`).emit('agent:command', outbound);
  }));
  return systems.filter(system => configuration?.targetMode !== 'selected'
    || (configuration.targetSystemIds || []).map(String).includes(String(system._id)));
}

async function configurationWithDefaults(companyId) {
  return (await DnsSinkholeConfig.findOne({ companyId }).lean()) || { ...DEFAULT_CONFIGURATION, companyId };
}

// ─────────────────────────────────────────────────────────────────────────────
// GET/PUT /api/dns-sinkhole/configuration
// ─────────────────────────────────────────────────────────────────────────────
router.get('/configuration', async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    const configuration = await configurationWithDefaults(companyId);
    const [systems, rules] = await Promise.all([
      allDnsSystems(companyId),
      DnsSinkholeRule.find({ companyId }).sort({ type: 1, domain: 1 }).lean(),
    ]);
    const safeConfig = {
      enabled: configuration.enabled ?? DEFAULT_CONFIGURATION.enabled,
      sinkholeIp: configuration.sinkholeIp || DEFAULT_CONFIGURATION.sinkholeIp,
      enforcementMode: configuration.enforcementMode || DEFAULT_CONFIGURATION.enforcementMode,
      telemetryEnabled: configuration.telemetryEnabled ?? DEFAULT_CONFIGURATION.telemetryEnabled,
      reportIntervalSeconds: configuration.reportIntervalSeconds || DEFAULT_CONFIGURATION.reportIntervalSeconds,
      syncBlocklist: configuration.syncBlocklist ?? DEFAULT_CONFIGURATION.syncBlocklist,
      targetMode: configuration.targetMode || DEFAULT_CONFIGURATION.targetMode,
      targetSystemIds: (configuration.targetSystemIds || []).map(String),
      builtInRuleIds: Array.isArray(configuration.builtInRuleIds)
        ? configuration.builtInRuleIds
        : DEFAULT_BUILT_IN_RULE_IDS,
      builtInRuleOverrides: configuration.builtInRuleOverrides || {},
      version: Number(configuration.version || DEFAULT_CONFIGURATION.version),
      lastDeployedAt: configuration.lastDeployedAt || null,
      updatedAt: configuration.updatedAt || null,
    };
    res.json({
      configuration: safeConfig,
      builtInRules: builtInRulesFor(configuration),
      rules,
      systems: systems.map(system => ({
        _id: system._id,
        name: system.name,
        hostname: system.hostname,
        status: system.status,
        lastSeen: system.lastSeen,
        appliedVersion: Number(system.dnsSinkholePolicyVersion || 0),
        enabled: system.dnsSinkholeEnabled,
        telemetryEnabled: system.dnsSinkholeTelemetryEnabled,
        enforcementMode: system.dnsSinkholeEnforcementMode,
        pending: (system.pendingCommands || []).some(item => item?.command === 'configure_dns_sinkhole'),
      })),
    });
  } catch (err) {
    sendError(res, err);
  }
});

router.put('/configuration', requireManager, async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    const settings = sanitizeConfiguration(req.body || {});
    if (settings.targetMode === 'selected') {
      const owned = await System.countDocuments({
        companyId,
        _id: { $in: settings.targetSystemIds },
        $or: [{ agentType: { $in: ['system', 'server'] } }, { agentType: { $exists: false } }],
      });
      if (owned !== settings.targetSystemIds.length) return res.status(404).json({ message: 'One or more selected agents were not found' });
    }
    const existing = await DnsSinkholeConfig.findOne({ companyId }).lean();
    const configuration = await DnsSinkholeConfig.findOneAndUpdate(
      { companyId },
      {
        $set: {
          ...settings,
          version: Number(existing?.version || 0) + 1,
          lastDeployedAt: new Date(),
          lastDeployedBy: req.user.id || req.user._id,
        },
      },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    const rules = await DnsSinkholeRule.find({ companyId }).lean();
    const systems = await queueDnsCommand(req, configuration, 'configure_dns_sinkhole', {
      settings: agentSettings(configuration),
      blocklist: rules.filter(isSinkholeRule).map(rule => rule.domain),
      allowlist: rules.filter(rule => rule.type === 'allowlist').map(rule => rule.domain),
      sinkholeTargets: sinkholeTargets(rules, configuration),
    });
    await auditLog(req, 'Configure DNS Sinkhole', 'DnsSinkholeConfig', configuration._id, {
      version: configuration.version,
      targetMode: configuration.targetMode,
      targetCount: systems.length,
      enabled: configuration.enabled,
      enforcementMode: configuration.enforcementMode,
    });
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('dns-sinkhole:configuration-updated', {
      version: configuration.version,
      targetCount: systems.length,
    });
    res.json({ message: `DNS Sinkhole configuration queued for ${systems.length} agent(s)`, configuration, targetCount: systems.length });
  } catch (err) {
    sendError(res, err);
  }
});

router.post('/configuration/sync', requireManager, async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    const configuration = await configurationWithDefaults(companyId);
    const rules = await DnsSinkholeRule.find({ companyId }).lean();
    const systems = await queueDnsCommand(req, configuration, 'configure_dns_sinkhole', {
      settings: agentSettings(configuration),
      blocklist: rules.filter(isSinkholeRule).map(rule => rule.domain),
      allowlist: rules.filter(rule => rule.type === 'allowlist').map(rule => rule.domain),
      sinkholeTargets: sinkholeTargets(rules, configuration),
    });
    await auditLog(req, 'Synchronize DNS Sinkhole Policy', 'DnsSinkholeConfig', configuration._id || companyId, { targetCount: systems.length });
    res.json({ message: `DNS Sinkhole policy synchronization queued for ${systems.length} agent(s)`, targetCount: systems.length });
  } catch (err) {
    sendError(res, err);
  }
});

router.patch('/configuration/built-in/:ruleId', requireManager, async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    const ruleId = String(req.params.ruleId || '');
    if (!BUILT_IN_DNS_RULE_IDS.has(ruleId)) return res.status(404).json({ message: 'Built-in DNS rule not found' });
    const settings = sanitizeBuiltInSettings(ruleId, req.body?.settings || {});
    const existing = await configurationWithDefaults(companyId);
    const builtInRuleOverrides = { ...(existing.builtInRuleOverrides || {}), [ruleId]: settings };
    const configuration = await DnsSinkholeConfig.findOneAndUpdate(
      { companyId },
      { $set: { builtInRuleOverrides, lastDeployedBy: req.user.id || req.user._id } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    const rule = builtInRulesFor(configuration).find(item => item.id === ruleId);
    await auditLog(req, 'Edit Built-in DNS Sinkhole Rule', 'DnsSinkholeConfig', configuration._id, { ruleId, settings });
    res.json({ message: `${rule.name} settings saved. Apply Selected to deploy them.`, rule });
  } catch (err) {
    sendError(res, err);
  }
});

router.post('/configuration/apply-built-in', requireManager, async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    const selectedIds = [...new Set(Array.isArray(req.body?.ruleIds) ? req.body.ruleIds.map(String) : [])];
    if (selectedIds.some(id => !BUILT_IN_DNS_RULE_IDS.has(id))) {
      return res.status(400).json({ message: 'One or more built-in DNS rules are invalid' });
    }
    const existing = await configurationWithDefaults(companyId);
    const configuration = await DnsSinkholeConfig.findOneAndUpdate(
      { companyId },
      {
        $set: {
          enabled: existing.enabled !== false,
          sinkholeIp: existing.sinkholeIp || '0.0.0.0',
          enforcementMode: existing.enforcementMode || 'both',
          reportIntervalSeconds: Number(existing.reportIntervalSeconds || 300),
          targetMode: existing.targetMode || 'all',
          targetSystemIds: existing.targetSystemIds || [],
          builtInRuleIds: selectedIds,
          syncBlocklist: selectedIds.includes('company-blocklist-enforcement'),
          telemetryEnabled: selectedIds.includes('sinkhole-policy-telemetry'),
          version: Number(existing.version || 0) + 1,
          lastDeployedAt: new Date(),
          lastDeployedBy: req.user.id || req.user._id,
        },
      },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    const rules = await DnsSinkholeRule.find({ companyId }).lean();
    const systems = await queueDnsCommand(req, configuration, 'configure_dns_sinkhole', {
      settings: agentSettings(configuration),
      blocklist: rules.filter(isSinkholeRule).map(rule => rule.domain),
      allowlist: rules.filter(rule => rule.type === 'allowlist').map(rule => rule.domain),
      sinkholeTargets: sinkholeTargets(rules, configuration),
    });
    await auditLog(req, 'Apply Built-in DNS Sinkhole Rules', 'DnsSinkholeConfig', configuration._id, {
      ruleIds: selectedIds,
      version: configuration.version,
      targetCount: systems.length,
    });
    res.json({
      message: `${selectedIds.length} built-in DNS rule(s) queued for ${systems.length} agent(s)`,
      configuration,
      targetCount: systems.length,
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/summary
// ─────────────────────────────────────────────────────────────────────────────
router.get('/summary', async (req, res) => {
  try {
    const { windowHours = 24, departmentId } = req.query;
    const { since, prevSince, prevUntil } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);
    
    const deptId = departmentId && mongoose.Types.ObjectId.isValid(departmentId)
      ? new mongoose.Types.ObjectId(departmentId)
      : undefined;

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since, departmentId: deptId });
    const prevQuery = {
      $and: [
        buildCapabilityQuery({ companyId, capabilityId: 31, since: prevSince, departmentId: deptId }),
        { createdAt: { $lt: prevUntil } },
      ],
    };

    const [alerts, prevAlerts, systems] = await Promise.all([
      Alert.find(query).lean(),
      Alert.find(prevQuery).lean(),
      System.find({ companyId, ...(deptId ? { departmentId: deptId } : {}) }).lean()
    ]);

    // Compute metrics
    const onlineAgents = systems.filter(s => s.agentOk || s.isOnline || ['online', 'active'].includes(String(s.status || '').toLowerCase())).length;
    
    const getStats = (list) => {
      const hits = list.filter(a => a.blocked || /block|sinkhol/i.test(`${a.actionTaken || ''} ${a.containmentStatus || ''} ${a.userAction || ''}`)).length;
      const uniqueDomains = new Set(list.map(a => indicatorValue(a, 'domain')).filter(Boolean)).size;
      const uniqueBlocked = new Set(list.filter(a => a.blocked || /block|sinkhol/i.test(`${a.actionTaken || ''}`)).map(a => indicatorValue(a, 'domain')).filter(Boolean)).size;
      const uniqueClients = new Set(list.map(a => indicatorValue(a, 'host')).filter(Boolean)).size;
      const highAlerts = list.filter(a => ['high', 'critical'].includes(String(a.severity || '').toLowerCase())).length;
      const totalQ = list.reduce((sum, alert) => sum + eventWeight(alert), 0);
      return { hits, uniqueDomains, uniqueBlocked, uniqueClients, highAlerts, totalQ };
    };

    const current = getStats(alerts);
    const prev = getStats(prevAlerts);

    const pct = (curr, prevVal) => prevVal ? Math.round(((curr - prevVal) / prevVal) * 100) : 0;

    res.json({
      totalQueries: { value: current.totalQ, change: pct(current.totalQ, prev.totalQ) },
      sinkholeHits: { value: current.hits, change: pct(current.hits, prev.hits) },
      blockedDomains: { value: current.uniqueBlocked, change: pct(current.uniqueBlocked, prev.uniqueBlocked) },
      maliciousDomains: { value: current.uniqueDomains, change: pct(current.uniqueDomains, prev.uniqueDomains) },
      uniqueClients: { value: current.uniqueClients, change: pct(current.uniqueClients, prev.uniqueClients) },
      highAlerts: { value: current.highAlerts, change: pct(current.highAlerts, prev.highAlerts) },
      onlineAgents: { value: onlineAgents, total: systems.length },
      queriesPerMinute: current.totalQ / (Math.max(1, Number(windowHours) || 24) * 60)
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/activity
// ─────────────────────────────────────────────────────────────────────────────
router.get('/activity', async (req, res) => {
  try {
    const { windowHours = 24, departmentId } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);
    
    const deptId = departmentId && mongoose.Types.ObjectId.isValid(departmentId)
      ? new mongoose.Types.ObjectId(departmentId)
      : undefined;

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since, departmentId: deptId });
    const alerts = await Alert.find(query).sort({ createdAt: 1 }).lean();

    const hours = parseInt(windowHours, 10);
    const timeline = [];
    const intervalMs = (hours * 60 * 60 * 1000) / 12;

    for (let i = 0; i < 12; i++) {
      const bucketStart = new Date(since.getTime() + i * intervalMs);
      const bucketEnd = new Date(bucketStart.getTime() + intervalMs);
      const label = bucketStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

      const periodAlerts = alerts.filter(a => a.createdAt >= bucketStart && a.createdAt < bucketEnd);
      const hits = periodAlerts.filter(a => a.blocked || /block|sinkhol/i.test(`${a.actionTaken || ''}`)).length;
      const blocked = new Set(periodAlerts.filter(a => a.blocked).map(a => indicatorValue(a, 'domain')).filter(Boolean)).size;
      const total = periodAlerts.reduce((sum, alert) => sum + eventWeight(alert), 0);
      const allowed = Math.max(0, total - hits);

      timeline.push({ label, total, hits, blocked, allowed });
    }

    res.json(timeline);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/alerts
// ─────────────────────────────────────────────────────────────────────────────
router.get('/alerts', async (req, res) => {
  try {
    const {
      page = 1, limit = 25, search = '',
      severity, status, domain, ip, endpoint,
      windowHours = 24, departmentId
    } = req.query;

    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);
    const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
    const safeLimit = Math.min(250, Math.max(1, Number.parseInt(limit, 10) || 25));

    const deptId = departmentId && mongoose.Types.ObjectId.isValid(departmentId)
      ? new mongoose.Types.ObjectId(departmentId)
      : undefined;

    const capabilityQuery = buildCapabilityQuery({ companyId, capabilityId: 31, since, departmentId: deptId });

    // Apply additional filters
    const filter = { ...capabilityQuery };

    if (severity && ['critical', 'high', 'medium', 'low'].includes(String(severity).toLowerCase())) filter.severity = String(severity).toLowerCase();
    if (status && ['open', 'investigating', 'resolved', 'false_positive', 'under_observation'].includes(String(status).toLowerCase())) filter.status = String(status).toLowerCase();
    if (domain) filter.domain = safeRegex(domain);
    if (ip) {
      filter.$and.push({ $or: [
        { srcip: ip },
        { destip: ip },
        { sinkholeIp: ip }
      ] });
    }
    if (endpoint) {
      const endpointRx = safeRegex(endpoint);
      filter.$and.push({ $or: [
        { hostname: endpointRx },
        { agentName: endpointRx }
      ] });
    }

    if (search.trim()) {
      const rx = safeRegex(search, 200);
      filter.$and = filter.$and || [];
      filter.$and.push({
        $or: [
          { domain: rx },
          { srcip: rx },
          { destip: rx },
          { hostname: rx },
          { agentName: rx },
          { description: rx },
          { threatCategory: rx }
        ]
      });
    }

    const [alerts, total] = await Promise.all([
      Alert.find(filter)
        .sort({ createdAt: -1 })
        .skip((safePage - 1) * safeLimit)
        .limit(safeLimit)
        .populate('systemId', 'name hostname ip os osType status isOnline agentOk lastSeen')
        .lean(),
      Alert.countDocuments(filter)
    ]);

    res.json({ alerts, total, page: safePage, limit: safeLimit });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/alerts/:id
// ─────────────────────────────────────────────────────────────────────────────
router.get('/alerts/:id', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const companyId = validCompanyId(req);
    const alert = await Alert.findOne({
      _id: req.params.id,
      companyId
    }).populate('systemId').lean();

    if (!alert) return res.status(404).json({ message: 'Alert not found' });

    // Domain reputation
    const domain = indicatorValue(alert, 'domain') || '';
    const hitsCount = domain ? await Alert.countDocuments({ companyId, domain }) : 0;
    const reputationScore = Number.isFinite(Number(alert.reputationScore)) ? Number(alert.reputationScore) : null;

    // DNS query history in last 24h
    const queryHistory = await Alert.find({
      companyId,
      domain,
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    }).sort({ createdAt: -1 }).limit(10).lean();

    // MITRE ATT&CK Mapping
    const mitre = {
      id: alert.mitreId || 'T1071.004',
      tactic: 'Command and Control',
      technique: 'Application Layer Protocol: DNS'
    };

    // Audit logs for this target
    const auditLogs = await SocAuditEvent.find({
      companyId,
      targetId: String(alert._id)
    }).sort({ createdAt: -1 }).lean();

    res.json({
      alert,
      reputationScore,
      queryHistory,
      mitre,
      auditLogs
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/domains
// ─────────────────────────────────────────────────────────────────────────────
router.get('/domains', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).lean();

    const domainMap = new Map();
    alerts.forEach(a => {
      const dom = indicatorValue(a, 'domain');
      if (!dom || dom === '-') return;
      if (!domainMap.has(dom)) {
        domainMap.set(dom, {
          domain: dom,
          hitCount: 0,
          threatLevel: a.severity || 'medium',
          threatCategory: a.threatCategory || a.category || 'Other',
          firstSeen: a.createdAt,
          lastSeen: a.createdAt,
          reputationScore: Number.isFinite(Number(a.reputationScore)) ? Number(a.reputationScore) : null,
          sourceFeed: a.tiFeeds?.feedSource || a.detectionSource || a.source || null,
          status: a.status || 'open'
        });
      }
      const data = domainMap.get(dom);
      data.hitCount++;
      if (a.createdAt < data.firstSeen) data.firstSeen = a.createdAt;
      if (a.createdAt > data.lastSeen) data.lastSeen = a.createdAt;
    });

    const domains = Array.from(domainMap.values())
      .sort((a, b) => b.hitCount - a.hitCount)
      .slice(0, 20);

    res.json(domains);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/endpoints
// ─────────────────────────────────────────────────────────────────────────────
router.get('/endpoints', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).populate('systemId').lean();

    const endpointMap = new Map();
    alerts.forEach(a => {
      const hostname = indicatorValue(a, 'host');
      if (!hostname) return;
      if (!endpointMap.has(hostname)) {
        endpointMap.set(hostname, {
          endpointId: a.systemId?._id || a.endpointId,
          endpointName: hostname,
          ipAddress: a.srcip || a.systemId?.ip || null,
          operatingSystem: a.systemId?.os || a.osType || null,
          loggedInUser: a.username || null,
          sinkholeHits: 0,
          totalDnsQueries: 0,
          lastActivity: a.createdAt,
          agentStatus: a.systemId?.status || (a.systemId?.isOnline ? 'Online' : 'Offline'),
          riskScore: Number.isFinite(Number(a.riskScore)) ? Number(a.riskScore) : null,
          lastHeartbeat: a.systemId?.lastSeen || null,
          agentVersion: a.agentVersion || a.systemId?.agentVersion || null,
          dnsTelemetryStatus: a.dnsTelemetryStatus || 'enabled',
        });
      }
      const data = endpointMap.get(hostname);
      data.sinkholeHits++;
      data.totalDnsQueries += eventWeight(a);
      if (a.createdAt > data.lastActivity) data.lastActivity = a.createdAt;
      data.telemetryDelaySeconds = data.lastActivity ? Math.max(0, Math.round((Date.now() - new Date(data.lastActivity).getTime()) / 1000)) : null;
    });

    const endpoints = Array.from(endpointMap.values())
      .sort((a, b) => b.sinkholeHits - a.sinkholeHits);

    res.json(endpoints);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/query-types
// ─────────────────────────────────────────────────────────────────────────────
router.get('/query-types', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).lean();

    const counts = { A: 0, AAAA: 0, CNAME: 0, MX: 0, TXT: 0, NS: 0, PTR: 0, SRV: 0, Other: 0 };
    let total = 0;

    alerts.forEach(a => {
      const q = (a.queryType || 'A').toUpperCase();
      if (counts[q] !== undefined) {
        counts[q]++;
      } else {
        counts.Other++;
      }
      total++;
    });

    const response = Object.entries(counts).map(([label, value]) => ({
      label,
      value,
      percentage: total ? Math.round((value / total) * 100) : 0
    }));

    res.json(response);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/response-types
// ─────────────────────────────────────────────────────────────────────────────
router.get('/response-types', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).lean();

    const counts = { 'Sinkhole IP': 0, NXDOMAIN: 0, REFUSED: 0, Allowed: 0, Other: 0 };
    let total = 0;

    alerts.forEach(a => {
      const resp = a.responseType || (a.blocked ? 'Sinkhole IP' : 'Allowed');
      if (counts[resp] !== undefined) {
        counts[resp]++;
      } else {
        counts.Other++;
      }
      total++;
    });

    const response = Object.entries(counts).map(([label, value]) => ({
      label,
      value,
      percentage: total ? Math.round((value / total) * 100) : 0
    }));

    res.json(response);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/threat-categories
// ─────────────────────────────────────────────────────────────────────────────
router.get('/threat-categories', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).lean();

    const categories = {
      Malware: 0, Phishing: 0, 'Botnet C2': 0, Ransomware: 0, DGA: 0,
      'DNS Tunneling': 0, Cryptomining: 0, Adware: 0,
      'Suspicious Newly Registered Domain': 0, Other: 0
    };
    let total = 0;

    alerts.forEach(a => {
      const cat = a.threatCategory || a.category || 'Other';
      if (categories[cat] !== undefined) {
        categories[cat]++;
      } else {
        categories.Other++;
      }
      total++;
    });

    const response = Object.entries(categories).map(([label, value]) => ({
      label,
      value,
      percentage: total ? Math.round((value / total) * 100) : 0
    })).sort((a, b) => b.value - a.value);

    res.json(response);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/geolocation
// ─────────────────────────────────────────────────────────────────────────────
router.get('/geolocation', async (req, res) => {
  try {
    const { windowHours = 24 } = req.query;
    const { since } = getTimeRange(windowHours);
    const companyId = validCompanyId(req);

    const query = buildCapabilityQuery({ companyId, capabilityId: 31, since });
    const alerts = await Alert.find(query).lean();

    const geoMap = new Map();
    alerts.forEach(a => {
      const country = indicatorValue(a, 'country');
      if (!country) return;
      if (!geoMap.has(country)) {
        geoMap.set(country, { country, hits: 0, severity: a.severity || 'low' });
      }
      const data = geoMap.get(country);
      data.hits++;
      if (a.severity === 'critical' || (a.severity === 'high' && data.severity !== 'critical')) {
        data.severity = a.severity;
      }
    });

    const countries = Array.from(geoMap.values())
      .sort((a, b) => b.hits - a.hits)
      .slice(0, 10);

    res.json(countries);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/dns-sinkhole/service-status
// ─────────────────────────────────────────────────────────────────────────────
router.get('/service-status', async (req, res) => {
  try {
    const companyId = validCompanyId(req);
    
    // Count active custom block rules
    const fiveMinutesAgo = new Date(Date.now() - 5 * 60 * 1000);
    const dayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const liveQuery = buildCapabilityQuery({ companyId, capabilityId: 31, since: dayAgo });
    const recentQuery = buildCapabilityQuery({ companyId, capabilityId: 31, since: fiveMinutesAgo });
    const [blockCount, allowCount, recentAlerts, lastAlert, latestRule] = await Promise.all([
      DnsSinkholeRule.countDocuments({ companyId, type: 'blocklist' }),
      DnsSinkholeRule.countDocuments({ companyId, type: 'allowlist' }),
      Alert.find(recentQuery).select('hitCount queryCount dnsQueryCount rawEvent').lean(),
      Alert.findOne(liveQuery).sort({ createdAt: -1 }).select('createdAt sinkholeIp').lean(),
      DnsSinkholeRule.findOne({ companyId }).sort({ updatedAt: -1 }).select('updatedAt').lean(),
    ]);
    const recentQueries = recentAlerts.reduce((sum, alert) => sum + eventWeight(alert), 0);
    
    res.json({
      sinkholeServiceStatus: lastAlert ? 'reporting' : 'no recent data',
      dnsResolverStatus: lastAlert ? 'reporting' : 'unknown',
      sinkholeIp: lastAlert?.sinkholeIp || null,
      queriesPerMinute: recentQueries / 5,
      blocklistSourceCount: blockCount,
      allowlistSourceCount: allowCount,
      threatIntelligenceFeedStatus: latestRule ? 'configured' : 'not configured',
      lastFeedUpdate: latestRule?.updatedAt || null,
      lastTelemetryReceived: lastAlert?.createdAt || null,
      databaseStatus: 'connected',
      queueStatus: 'not reported'
    });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/blocklist
// ─────────────────────────────────────────────────────────────────────────────
router.post('/blocklist', requireManager, async (req, res) => {
  try {
    const { domain, reason } = req.body;
    const companyId = validCompanyId(req);
    const normalizedDomain = normalizeDomain(domain);
    const safeReason = String(reason || '').trim().slice(0, 500);
    const configuration = await configurationWithDefaults(companyId);
    const sinkholeIp = normalizeSinkholeIp(req.body?.sinkholeIp, configuration.sinkholeIp);

    await DnsSinkholeRule.deleteMany({ companyId, type: { $in: ['allowlist', 'redirect'] }, domain: normalizedDomain });

    const rule = await DnsSinkholeRule.findOneAndUpdate(
      { companyId, type: 'blocklist', domain: normalizedDomain },
      { $set: { sinkholeIp, reason: safeReason, addedBy: req.user.id } },
      { upsert: true, new: true }
    );

    // Emit real-time policy update to connected clients
    const io = req.app.get('io');
    if (io) {
      io.to(`company:${req.user.companyId}`).emit('dns-sinkhole:policy-updated', { rule });
    }

    if (configuration.enabled && configuration.syncBlocklist) {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_add', { domain: normalizedDomain, sinkholeIp, reason: safeReason || 'dashboard blocklist' });
    }

    await auditLog(req, 'Add Domain to Blocklist', 'DnsRule', rule._id, { domain: normalizedDomain, sinkholeIp, reason: safeReason });

    res.status(201).json({ message: 'Domain added to blocklist successfully', rule });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/redirect
// Resolve a domain to a company-controlled safe server instead of its original
// DNS destination. This is an intentional DNS override, not an allowlist rule.
// ─────────────────────────────────────────────────────────────────────────────
router.post('/redirect', requireManager, async (req, res) => {
  try {
    const { domain, reason } = req.body;
    const companyId = validCompanyId(req);
    const normalizedDomain = normalizeDomain(domain);
    if (!String(req.body?.sinkholeIp || '').trim()) {
      const error = new Error('A safe server IPv4 address is required for redirect rules');
      error.status = 400;
      throw error;
    }
    const sinkholeIp = normalizeRedirectIp(req.body.sinkholeIp);
    const safeReason = String(reason || '').trim().slice(0, 500);
    const configuration = await configurationWithDefaults(companyId);

    await DnsSinkholeRule.deleteMany({ companyId, type: { $in: ['blocklist', 'allowlist'] }, domain: normalizedDomain });
    const rule = await DnsSinkholeRule.findOneAndUpdate(
      { companyId, type: 'redirect', domain: normalizedDomain },
      { $set: { sinkholeIp, reason: safeReason, addedBy: req.user.id || req.user._id } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    );

    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('dns-sinkhole:policy-updated', { rule });
    if (configuration.enabled && configuration.syncBlocklist) {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_add', {
        domain: normalizedDomain,
        sinkholeIp,
        reason: safeReason || 'dashboard safe-server redirect',
      });
    }
    await auditLog(req, 'Redirect Domain to Safe Server', 'DnsRule', rule._id, { domain: normalizedDomain, sinkholeIp, reason: safeReason });
    res.status(201).json({ message: `Domain redirect to ${sinkholeIp} created successfully`, rule });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/allowlist
// ─────────────────────────────────────────────────────────────────────────────
router.post('/allowlist', requireManager, async (req, res) => {
  try {
    const { domain, reason } = req.body;
    const companyId = validCompanyId(req);
    const normalizedDomain = normalizeDomain(domain);
    const safeReason = String(reason || '').trim().slice(0, 500);

    await DnsSinkholeRule.deleteMany({ companyId, type: { $in: ['blocklist', 'redirect'] }, domain: normalizedDomain });

    const rule = await DnsSinkholeRule.findOneAndUpdate(
      { companyId, type: 'allowlist', domain: normalizedDomain },
      { $set: { reason: safeReason, addedBy: req.user.id } },
      { upsert: true, new: true }
    );

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${req.user.companyId}`).emit('dns-sinkhole:policy-updated', { rule });
    }

    const configuration = await configurationWithDefaults(companyId);
    await queueDnsCommand(req, configuration, 'dns_sinkhole_remove', { domain: normalizedDomain, reason: safeReason || 'dashboard allowlist' });

    await auditLog(req, 'Add Domain to Allowlist', 'DnsRule', rule._id, { domain: normalizedDomain, reason: safeReason });

    res.status(201).json({ message: 'Domain added to allowlist successfully', rule });
  } catch (err) {
    sendError(res, err);
  }
});

router.delete('/rules/:id', requireManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule id' });
    const companyId = validCompanyId(req);
    const rule = await DnsSinkholeRule.findOneAndDelete({ _id: req.params.id, companyId }).lean();
    if (!rule) return res.status(404).json({ message: 'DNS Sinkhole rule not found' });
    const configuration = await configurationWithDefaults(companyId);
    if (isSinkholeRule(rule)) {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_remove', { domain: rule.domain, reason: 'rule removed from dashboard' });
    }
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('dns-sinkhole:policy-updated', { removedRuleId: rule._id });
    await auditLog(req, 'Delete DNS Sinkhole Rule', 'DnsRule', rule._id, { domain: rule.domain, type: rule.type });
    res.json({ message: 'DNS Sinkhole rule removed', rule });
  } catch (err) {
    sendError(res, err);
  }
});

router.patch('/rules/:id', requireManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule id' });
    const companyId = validCompanyId(req);
    const existing = await DnsSinkholeRule.findOne({ _id: req.params.id, companyId }).lean();
    if (!existing) return res.status(404).json({ message: 'DNS Sinkhole rule not found' });
    const domain = normalizeDomain(req.body?.domain ?? existing.domain);
    const type = String(req.body?.type || existing.type).toLowerCase();
    if (!['blocklist', 'redirect', 'allowlist'].includes(type)) return res.status(400).json({ message: 'Rule type must be blocklist, redirect, or allowlist' });
    const reason = String(req.body?.reason ?? existing.reason ?? '').trim().slice(0, 500);
    const configuration = await configurationWithDefaults(companyId);
    const sinkholeIp = type === 'redirect'
      ? normalizeRedirectIp(req.body?.sinkholeIp ?? existing.sinkholeIp)
      : type === 'blocklist'
        ? normalizeSinkholeIp(req.body?.sinkholeIp ?? existing.sinkholeIp, configuration.sinkholeIp)
        : null;
    const duplicate = await DnsSinkholeRule.findOne({ companyId, type, domain, _id: { $ne: existing._id } }).lean();
    if (duplicate) return res.status(409).json({ message: 'This domain already exists in the selected rule list' });

    await DnsSinkholeRule.deleteMany({ companyId, domain, _id: { $ne: existing._id } });
    const rule = await DnsSinkholeRule.findOneAndUpdate(
      { _id: existing._id, companyId },
      { $set: { domain, type, sinkholeIp, reason, addedBy: req.user.id || req.user._id } },
      { new: true, runValidators: true },
    ).lean();
    if (isSinkholeRule(existing) && (existing.domain !== domain || !['blocklist', 'redirect'].includes(type) || existing.sinkholeIp !== sinkholeIp)) {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_remove', { domain: existing.domain, reason: 'company DNS rule edited' });
    }
    if (['blocklist', 'redirect'].includes(type) && configuration.enabled !== false) {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_add', { domain, sinkholeIp, reason: reason || 'edited company blocklist rule' });
    } else if (type === 'allowlist') {
      await queueDnsCommand(req, configuration, 'dns_sinkhole_remove', { domain, reason: reason || 'edited company allowlist rule' });
    }
    req.app.get('io')?.to(`company:${req.user.companyId}`).emit('dns-sinkhole:policy-updated', { rule });
    await auditLog(req, 'Edit DNS Sinkhole Rule', 'DnsRule', rule._id, {
      before: { domain: existing.domain, type: existing.type, sinkholeIp: existing.sinkholeIp || configuration.sinkholeIp, reason: existing.reason },
      after: { domain, type, sinkholeIp, reason },
    });
    res.json({ message: 'DNS Sinkhole rule updated and queued for agents', rule });
  } catch (err) {
    sendError(res, err);
  }
});

router.post('/rules/:id/apply', requireManager, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid rule id' });
    const companyId = validCompanyId(req);
    const [rule, configuration] = await Promise.all([
      DnsSinkholeRule.findOne({ _id: req.params.id, companyId }).lean(),
      configurationWithDefaults(companyId),
    ]);
    if (!rule) return res.status(404).json({ message: 'DNS Sinkhole rule not found' });
    if (isSinkholeRule(rule) && configuration.enabled === false) {
      return res.status(409).json({ message: 'Enable DNS Sinkhole before applying a block or redirect rule' });
    }
    const command = isSinkholeRule(rule) ? 'dns_sinkhole_add' : 'dns_sinkhole_remove';
    const systems = await queueDnsCommand(req, configuration, command, {
      domain: rule.domain,
      sinkholeIp: rule.type === 'redirect'
        ? normalizeRedirectIp(rule.sinkholeIp)
        : rule.type === 'blocklist' ? normalizeSinkholeIp(rule.sinkholeIp, configuration.sinkholeIp) : undefined,
      reason: rule.reason || `Company ${rule.type} rule`,
    });
    await auditLog(req, 'Apply DNS Sinkhole Rule', 'DnsRule', rule._id, {
      domain: rule.domain,
      type: rule.type,
      sinkholeIp: rule.sinkholeIp || configuration.sinkholeIp,
      targetCount: systems.length,
    });
    res.json({ message: `${rule.domain} queued for ${systems.length} agent(s)`, targetCount: systems.length, rule });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/alerts/:id/investigate
// ─────────────────────────────────────────────────────────────────────────────
router.post('/alerts/:id/investigate', async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const companyId = validCompanyId(req);
    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.id, companyId },
      { $set: { status: 'investigating' } },
      { new: true }
    );

    if (!alert) return res.status(404).json({ message: 'Alert not found' });

    const io = req.app.get('io');
    if (io) io.to(`company:${req.user.companyId}`).emit('alert:updated', alert);

    await auditLog(req, 'Mark Alert Investigating', 'Alert', alert._id);

    res.json({ message: 'Alert status set to investigating', alert });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/alerts/:id/resolve
// ─────────────────────────────────────────────────────────────────────────────
router.post('/alerts/:id/resolve', requireManager, async (req, res) => {
  try {
    const { reason, note } = req.body;
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const companyId = validCompanyId(req);
    
    const update = {
      $set: { status: 'resolved', resolvedAt: new Date() }
    };
    if (note) {
      update.$push = {
        notes: { user: req.user.id, text: String(note).slice(0, 4000), at: new Date() }
      };
    }

    const alert = await Alert.findOneAndUpdate(
      { _id: req.params.id, companyId },
      update,
      { new: true }
    );

    if (!alert) return res.status(404).json({ message: 'Alert not found' });

    const io = req.app.get('io');
    if (io) io.to(`company:${req.user.companyId}`).emit('alert:updated', alert);

    await auditLog(req, 'Resolve Alert', 'Alert', alert._id, { reason, note });

    res.json({ message: 'Alert resolved successfully', alert });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/endpoints/:id/isolate
// ─────────────────────────────────────────────────────────────────────────────
router.post('/endpoints/:id/isolate', requireManager, async (req, res) => {
  try {
    const { reason } = req.body;
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid endpoint id' });
    const companyId = validCompanyId(req);
    const safeReason = String(reason || 'Manually isolated from DNS Sinkhole dashboard').slice(0, 500);
    const system = await System.findOneAndUpdate(
      { _id: req.params.id, companyId },
      {
        $set: {
          isIsolated: true,
          isolatedAt: new Date(),
          isolationReason: safeReason,
          status: 'active',
        },
        $push: {
          pendingCommands: {
            id: `${Date.now()}-dns-isolate`,
            command: 'isolate',
            systemId: String(req.params.id),
            reason: safeReason,
            createdAt: new Date(),
          },
        },
      },
      { new: true }
    );

    if (!system) return res.status(404).json({ message: 'System not found' });

    const io = req.app.get('io');
    if (io) {
      io.to(`system_${system._id}`).emit('agent:command', {
        command: 'isolate',
        systemId: String(system._id),
        reason: system.isolationReason,
      });
      io.to(`company:${system.companyId}`).emit('system:isolated', {
        systemId: system._id,
        systemName: system.name,
        isIsolated: true,
        isolatedAt: system.isolatedAt,
        reason: system.isolationReason,
      });
    }

    await auditLog(req, 'Isolate Endpoint', 'System', system._id, { reason });

    res.json({ message: 'Endpoint isolation command dispatched successfully', system });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/endpoints/:id/scan
// ─────────────────────────────────────────────────────────────────────────────
router.post('/endpoints/:id/scan', requireManager, async (req, res) => {
  try {
    if (!mongoose.Types.ObjectId.isValid(req.params.id)) return res.status(400).json({ message: 'Invalid endpoint id' });
    const companyId = validCompanyId(req);
    const system = await System.findOneAndUpdate(
      { _id: req.params.id, companyId },
      {
        $push: {
          pendingCommands: {
            id: `${Date.now()}-dns-scan`,
            command: 'scan',
            systemId: String(req.params.id),
            createdAt: new Date(),
          },
        },
      },
      { new: true }
    );

    if (!system) return res.status(404).json({ message: 'System not found' });

    const io = req.app.get('io');
    if (io) {
      io.to(`system_${system._id}`).emit('agent:command', {
        command: 'scan',
        systemId: String(system._id),
      });
      io.to(`company:${system.companyId}`).emit('system:scan_triggered', {
        systemId: system._id,
        systemName: system.name,
      });
    }

    await auditLog(req, 'Scan Endpoint', 'System', system._id);

    res.json({ message: 'Endpoint scan command dispatched successfully', system });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/dns-sinkhole/incidents
// ─────────────────────────────────────────────────────────────────────────────
router.post('/incidents', requireManager, async (req, res) => {
  try {
    const { title, description, severity, category, alertIds } = req.body;
    const companyId = validCompanyId(req);
    const ids = Array.isArray(alertIds) ? [...new Set(alertIds)].slice(0, 100) : [];
    if (!String(title || '').trim() || !ids.length || ids.some(id => !mongoose.Types.ObjectId.isValid(id))) {
      return res.status(400).json({ message: 'Title and alertIds are required' });
    }

    // Find the first alert to copy system info
    const ownedCount = await Alert.countDocuments({ _id: { $in: ids }, companyId });
    if (ownedCount !== ids.length) return res.status(404).json({ message: 'One or more alerts were not found' });
    const sampleAlert = await Alert.findOne({ _id: ids[0], companyId }).lean();
    const claim = await claimAlertsForIncident(ids, companyId);
    if (claim.rejectedIds.length) {
      return res.status(409).json({
        message: 'Incident not created because one or more selected alerts already have tickets',
        ticketAlertIds: claim.rejectedIds,
      });
    }

    const incident = await EdrIncident.create({
      companyId,
      systemId: sampleAlert?.systemId || null,
      departmentId: sampleAlert?.departmentId || null,
      title: String(title).trim().slice(0, 300),
      description: String(description || '').slice(0, 4000),
      severity: ['low', 'medium', 'high', 'critical'].includes(severity) ? severity : 'medium',
      status: 'open',
      assignedTo: sampleAlert?.assignedTo || null,
      alertIds: ids.map(id => new mongoose.Types.ObjectId(id)),
      affectedEndpoint: sampleAlert?.hostname || sampleAlert?.srcip || 'Unknown Endpoint',
      affectedUser: sampleAlert?.username || 'Unknown User',
      agentId: sampleAlert?.agentId || null,
      agentName: sampleAlert?.agentName || null,
      category: String(category || 'c2_communication').slice(0, 100),
      confidenceScore: 75,
      firstEventAt: sampleAlert?.createdAt || new Date(),
      lastEventAt: new Date()
    });

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${req.user.companyId}`).emit('edr:incident:new', incident);
    }

    await auditLog(req, 'Create DNS Incident', 'EdrIncident', incident._id, { alertCount: ids.length });

    res.status(201).json({ message: 'Incident created successfully', incident });
  } catch (err) {
    sendError(res, err);
  }
});

module.exports = router;
