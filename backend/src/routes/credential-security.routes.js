const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const CredentialSecurityConfig = require('../models/CredentialSecurityConfig.model');
const { getCredentialSecurityConfig, setCredentialSecurityConfig } = require('../services/credentialSecurityConfig.service');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { createResponse } = require('../services/automatedResponse.service');
const { resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');

const CREDENTIAL_FILTER = { isSynthetic: { $ne: true }, $or: [{ capabilityId: 13 }, { capabilityIds: 13 }] };
const ACTIONS = new Set(['disable_user', 'lock_account', 'force_logoff', 'revoke_token', 'block_ip', 'kill_process', 'isolate', 'create_ticket']);
const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const RULE_SEVERITIES = new Set(['low', 'medium', 'high', 'critical']);
const CONFIG_DEFAULTS = Object.freeze({
  enabled: true,
  monitorProcesses: true,
  monitorCredentialStores: true,
  monitorLockScreen: true,
  scanIntervalSeconds: 20,
  minimumRiskScore: 50,
  builtInRuleOverrides: {},
  manualPolicies: [],
  version: 1,
});
const BUILT_IN_RULES = Object.freeze([
  { id: 'CRED_DUMP_TOOL', name: 'Credential Dumping Tools', category: 'Credential Theft', severity: 'critical', description: 'Detect Mimikatz, NanoDump, Pypykatz, LaZagne and SecretsDump execution.' },
  { id: 'CRED_LSASS_DUMP', name: 'LSASS Memory Dump', category: 'Credential Theft', severity: 'critical', description: 'Detect process-memory dump commands targeting LSASS.' },
  { id: 'CRED_SAM_SECRETS_DUMP', name: 'SAM / LSA Secrets Dump', category: 'Credential Theft', severity: 'critical', description: 'Detect SAM, SECURITY or SYSTEM hive export and secrets extraction.' },
  { id: 'CRED_KERBEROS_ABUSE', name: 'Kerberos Ticket Abuse', category: 'Authentication', severity: 'critical', description: 'Detect roasting, forged tickets and ticket theft tooling.' },
  { id: 'CRED_PASS_THE_HASH', name: 'Pass-the-Hash', category: 'Authentication', severity: 'critical', description: 'Detect Pass-the-Hash and Overpass-the-Hash tools and commands.' },
  { id: 'CRED_WINDOWS_VAULT_ACCESS', name: 'Windows Credential Vault Access', category: 'Credential Store', severity: 'high', description: 'Detect suspicious access to Windows Vault and Credential Manager.' },
  { id: 'CRED_MACOS_KEYCHAIN_ACCESS', name: 'macOS Keychain Access', category: 'Credential Store', severity: 'critical', description: 'Detect credential extraction commands targeting macOS Keychain.' },
  { id: 'CRED_UNIX_SECRET_FILE_ACCESS', name: 'Linux / Unix Secret Access', category: 'Credential Store', severity: 'high', description: 'Detect suspicious process access to shadow, SSH and cloud credential paths.' },
  { id: 'CRED_BROWSER_PASSWORD_STORE_ACCESS', name: 'Browser Password Store Access', category: 'Credential Store', severity: 'high', description: 'Detect process references to browser and password-manager stores.' },
  { id: 'CRED_EXPLICIT_PRIVILEGED_AUTH', name: 'Explicit Privileged Authentication', category: 'Privilege', severity: 'medium', description: 'Detect explicit RunAs, sudo, su and PowerShell credential use.' },
  { id: 'CRED_STORE_METADATA_CHANGED', name: 'Credential Store Changed', category: 'Credential Store', severity: 'high', description: 'Detect metadata changes to protected credential-store files without reading contents.' },
  { id: 'AUTH_SCREEN_LOCK', name: 'Workstation Locked', category: 'Lock Screen', severity: 'low', description: 'Record when a user workstation or desktop session is locked.' },
  { id: 'AUTH_SCREEN_UNLOCK_SUCCESS', name: 'Screen Unlock Successful', category: 'Lock Screen', severity: 'low', description: 'Record successful workstation unlock authentication.' },
  { id: 'AUTH_SCREEN_UNLOCK_FAILURE', name: 'Screen Unlock Failed', category: 'Lock Screen', severity: 'medium', description: 'Detect invalid credentials or denied authentication at the lock screen.' },
]);
const BUILT_IN_RULE_IDS = new Set(BUILT_IN_RULES.map(rule => rule.id));
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const periodStart = value => new Date(Date.now() - integer(value, 24, 1, 24 * 365) * 3600000);
const sumWhen = condition => ({ $sum: { $cond: [condition, 1, 0] } });
const csvCell = value => {
  let text = String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
};

const companyScope = (req, requestedDepartmentId = req.query?.departmentId) => {
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(req.user.companyId?._id || req.user.companyId)),
    ...(departmentId ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) } : {}),
  };
};

function boundedNumber(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function sanitizeConfiguration(body = {}) {
  const incoming = body.builtInRuleOverrides && typeof body.builtInRuleOverrides === 'object'
    && !Array.isArray(body.builtInRuleOverrides) ? body.builtInRuleOverrides : {};
  const builtInRuleOverrides = {};
  Object.entries(incoming).forEach(([ruleId, settings]) => {
    if (!BUILT_IN_RULE_IDS.has(ruleId) || !settings || typeof settings !== 'object') return;
    const severity = String(settings.severity || '').toLowerCase();
    builtInRuleOverrides[ruleId] = {
      enabled: settings.enabled !== false,
      ...(RULE_SEVERITIES.has(severity) ? { severity } : {}),
    };
  });
  return {
    enabled: body.enabled !== false,
    monitorProcesses: body.monitorProcesses !== false,
    monitorCredentialStores: body.monitorCredentialStores !== false,
    monitorLockScreen: body.monitorLockScreen !== false,
    scanIntervalSeconds: Math.round(boundedNumber(body.scanIntervalSeconds, 20, 10, 3600)),
    minimumRiskScore: Math.round(boundedNumber(body.minimumRiskScore, 50, 0, 100)),
    builtInRuleOverrides,
  };
}

function rulesFor(configuration = {}) {
  const overrides = configuration.builtInRuleOverrides || {};
  return BUILT_IN_RULES.map(rule => ({
    ...rule,
    defaultSeverity: rule.severity,
    enabled: overrides[rule.id]?.enabled !== false,
    severity: RULE_SEVERITIES.has(overrides[rule.id]?.severity) ? overrides[rule.id].severity : rule.severity,
  }));
}

async function currentConfiguration(companyId) {
  return (await getCredentialSecurityConfig(companyId)) || CONFIG_DEFAULTS;
}

const credentialText = { $toLower: { $concat: [
  { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$credentialEventType', ''] }, ' ',
  { $ifNull: ['$description', ''] }, ' ', { $ifNull: ['$eventType', ''] }, ' ',
  { $ifNull: ['$authType', ''] }, ' ', { $ifNull: ['$processName', ''] }, ' ',
  { $ifNull: ['$processCmdline', ''] },
] } };
const matches = regex => ({ $regexMatch: { input: '$_credentialText', regex } });

function credentialQuery(req, source = req.query) {
  const query = { ...companyScope(req, source.departmentId), ...CREDENTIAL_FILTER };
  const period = String(source.period || '');
  const hours = PERIOD_HOURS[period] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : periodStart(hours);
  const to = source.to ? new Date(source.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? periodStart(24) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (source.severity && ['low', 'medium', 'high', 'critical'].includes(source.severity)) query.severity = source.severity;
  if (source.eventType) query.credentialEventType = new RegExp(escapeRegex(source.eventType).slice(0, 100), 'i');
  if (source.authType) query.authType = new RegExp(escapeRegex(source.authType).slice(0, 100), 'i');
  if (source.status) query.status = new RegExp(`^${escapeRegex(source.status)}$`, 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.country) query.geoCountry = new RegExp(`^${escapeRegex(source.country)}$`, 'i');
  if (source.search) {
    const search = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and = [{ $or: [
      { description: search }, { ruleId: search }, { hostname: search }, { username: search },
      { srcip: search }, { destip: search }, { authType: search }, { credentialEventType: search },
      { processName: search }, { processCmdline: search }, { mitreId: search }, { fileHash: search },
    ] }];
  }
  return query;
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No credential security records found']);
  const objects = []; const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index]; const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 30 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${contentId} 0 R >>`;
    objects[contentId] = `<< /Length ${Buffer.byteLength(content)} >>\nstream\n${content}\nendstream`;
  });
  let pdf = '%PDF-1.4\n'; const offsets = [0];
  for (let id = 1; id < objects.length; id += 1) { offsets[id] = Buffer.byteLength(pdf); pdf += `${id} 0 obj\n${objects[id]}\nendobj\n`; }
  const xref = Buffer.byteLength(pdf); pdf += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id += 1) pdf += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  pdf += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
  return Buffer.from(pdf);
}

async function writeAudit(req, alert, actionType, reason, responseId) {
  const actorId = req.user.id || req.user._id;
  const tenantId = req.user.tenantId || alert?.tenantId;
  if (!actorId || !tenantId) return;
  await SocAuditEvent.create({
    tenantId, companyId: alert.companyId, actorId, action: 'credential-security.response.requested',
    targetType: 'CredentialSecurityAlert', targetId: String(alert._id),
    metadata: { actionType, reason: String(reason).slice(0, 500), responseId },
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

async function writeConfigurationAudit(req, action, targetId, metadata = {}) {
  const actorId = req.user.id || req.user._id;
  if (!actorId || !req.user.tenantId) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId,
    companyId: companyScope(req).companyId,
    actorId,
    action,
    targetType: 'CredentialSecurityConfig',
    targetId: String(targetId),
    metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

router.use(authenticate, requireAnalyst);

router.get('/configuration', async (req, res) => {
  try {
    const companyId = companyScope(req).companyId;
    const [configuration, targetCount, onlineCount] = await Promise.all([
      currentConfiguration(companyId),
      System.countDocuments({ companyId, isActive: { $ne: false } }),
      System.countDocuments({ companyId, isActive: { $ne: false }, lastSeen: { $gte: new Date(Date.now() - 5 * 60 * 1000) } }),
    ]);
    res.json({
      configuration: { ...CONFIG_DEFAULTS, ...(configuration || {}) },
      rules: rulesFor(configuration),
      targetCount,
      onlineCount,
    });
  } catch (error) {
    res.status(500).json({ message: 'Unable to load credential security configuration' });
  }
});

router.put('/configuration', requireCompanyAdmin, async (req, res) => {
  try {
    const companyId = companyScope(req).companyId;
    const settings = sanitizeConfiguration(req.body);
    const existing = await CredentialSecurityConfig.findOne({ companyId }).select('version').lean();
    const configuration = await CredentialSecurityConfig.findOneAndUpdate(
      { companyId },
      { $set: {
        ...settings,
        tenantId: req.user.tenantId || null,
        version: Number(existing?.version || 0) + 1,
        lastDeployedAt: new Date(),
        lastDeployedBy: req.user.id || req.user._id,
      } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    ).lean();
    setCredentialSecurityConfig(companyId, configuration);
    const actorId = req.user.id || req.user._id;
    if (req.user.tenantId && actorId) {
      await SocAuditEvent.create({
        tenantId: req.user.tenantId,
        companyId,
        actorId,
        action: 'credential-security.configuration.updated',
        targetType: 'CredentialSecurityConfig',
        targetId: String(configuration._id),
        metadata: { version: configuration.version, enabled: configuration.enabled },
        ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
      });
    }
    const targetCount = await System.countDocuments({ companyId, isActive: { $ne: false } });
    req.app.get('io')?.to(`company:${companyId}`).emit('credential:configuration-updated', {
      version: configuration.version,
      enabled: configuration.enabled,
    });
    res.json({
      message: `Credential security policy saved for ${targetCount} agent(s); agents apply it on their next heartbeat.`,
      configuration,
      rules: rulesFor(configuration),
      targetCount,
    });
  } catch (error) {
    res.status(error instanceof mongoose.Error.ValidationError ? 400 : 500).json({
      message: error instanceof mongoose.Error.ValidationError ? error.message : 'Unable to save credential security configuration',
    });
  }
});

router.post('/configuration/policies', requireCompanyAdmin, async (req, res) => {
  try {
    const companyId = companyScope(req).companyId;
    const name = String(req.body.name || '').trim().replace(/\s+/g, ' ').slice(0, 80);
    const nameKey = name.toLowerCase();
    const description = String(req.body.description || '').trim().slice(0, 300);
    if (name.length < 3) return res.status(400).json({ message: 'Policy name must contain at least 3 characters' });
    const settings = sanitizeConfiguration(req.body.settings || {});
    let configuration = await CredentialSecurityConfig.findOneAndUpdate(
      { companyId },
      { $setOnInsert: { ...CONFIG_DEFAULTS, companyId, tenantId: req.user.tenantId || null } },
      { upsert: true, new: true, runValidators: true, setDefaultsOnInsert: true },
    );
    if ((configuration.manualPolicies || []).some(policy => policy.nameKey === nameKey)) {
      return res.status(409).json({ message: 'A manual policy with this name already exists' });
    }
    if ((configuration.manualPolicies || []).length >= 50) {
      return res.status(409).json({ message: 'Maximum 50 manual credential policies are allowed' });
    }
    configuration.manualPolicies.push({
      name,
      nameKey,
      description,
      settings,
      createdBy: req.user.id || req.user._id,
      createdAt: new Date(),
      updatedAt: new Date(),
    });
    await configuration.save();
    const policy = configuration.manualPolicies[configuration.manualPolicies.length - 1];
    setCredentialSecurityConfig(companyId, configuration.toObject());
    await writeConfigurationAudit(req, 'credential-security.manual-policy.created', policy._id, { name });
    res.status(201).json({
      message: `Manual policy “${name}” created. Use Apply to deploy it to agents.`,
      policy,
      manualPolicies: configuration.manualPolicies,
    });
  } catch (error) {
    res.status(error instanceof mongoose.Error.ValidationError ? 400 : 500).json({
      message: error instanceof mongoose.Error.ValidationError ? error.message : 'Unable to create manual credential policy',
    });
  }
});

router.post('/configuration/policies/:policyId/apply', requireCompanyAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.policyId)) return res.status(400).json({ message: 'Invalid policy id' });
    const companyId = companyScope(req).companyId;
    const configuration = await CredentialSecurityConfig.findOne({ companyId });
    if (!configuration) return res.status(404).json({ message: 'Credential security configuration not found' });
    const policy = configuration.manualPolicies.id(req.params.policyId);
    if (!policy) return res.status(404).json({ message: 'Manual credential policy not found' });
    const settings = sanitizeConfiguration(policy.settings || {});
    configuration.set(settings);
    configuration.version = Number(configuration.version || 0) + 1;
    configuration.lastDeployedAt = new Date();
    configuration.lastDeployedBy = req.user.id || req.user._id;
    policy.updatedAt = new Date();
    await configuration.save();
    const plainConfiguration = configuration.toObject();
    setCredentialSecurityConfig(companyId, plainConfiguration);
    const targetCount = await System.countDocuments({ companyId, isActive: { $ne: false } });
    await writeConfigurationAudit(req, 'credential-security.manual-policy.applied', policy._id, {
      name: policy.name,
      version: configuration.version,
      targetCount,
    });
    req.app.get('io')?.to(`company:${companyId}`).emit('credential:configuration-updated', {
      version: configuration.version,
      enabled: configuration.enabled,
      policyId: String(policy._id),
    });
    res.json({
      message: `Manual policy “${policy.name}” applied to ${targetCount} agent(s); agents receive it on their next heartbeat.`,
      configuration: plainConfiguration,
      rules: rulesFor(plainConfiguration),
      manualPolicies: plainConfiguration.manualPolicies || [],
      targetCount,
    });
  } catch (error) {
    res.status(error instanceof mongoose.Error.ValidationError ? 400 : 500).json({
      message: error instanceof mongoose.Error.ValidationError ? error.message : 'Unable to apply manual credential policy',
    });
  }
});

router.get('/dashboard', async (req, res) => {
  try {
    const query = credentialQuery(req);
    const eventLimit = integer(req.query.limit, 250, 1, 500);
    const activeSince = new Date(Date.now() - 5 * 60 * 1000);
    const [facets = {}, agents = {}] = await Promise.all([
      Alert.aggregate([
        { $match: query }, { $set: { _credentialText: credentialText } },
        { $facet: {
          summary: [{ $group: {
            _id: null, total: { $sum: 1 },
            successfulLogins: sumWhen({ $eq: ['$authResult', 'success'] }),
            failedLogins: sumWhen({ $eq: ['$authResult', 'failure'] }),
            bruteForce: sumWhen(matches('brute.force|password.spray|credential.stuffing')),
            passwordEvents: sumWhen(matches('password.change|password.reset|passwd')),
            accountLockouts: sumWhen(matches('account.lock|4740')),
            privilegedLogins: sumWhen(matches('privileged|admin.rights|sudo|root.login|4672')),
            mfaFailures: sumWhen(matches('mfa.failure|mfa.bypass|otp.fail|2fa.fail')),
            credentialTheft: sumWhen(matches('lsass|mimikatz|credential.dump|sam.dump|secretsdump|browser.password|keychain')),
            kerberosAbuse: sumWhen(matches('kerberoast|as.rep|golden.ticket|silver.ticket|pass.the.ticket')),
            tokenAbuse: sumWhen(matches('token.replay|token.abuse|jwt.abuse|oauth.abuse|refresh.token')),
            cloudIam: sumWhen(matches('aws.iam|azure.ad|entra|google.workspace|okta|cloud.iam|api.key')),
            screenLocks: sumWhen(matches('auth.screen.lock|workstation.locked')),
            screenUnlocks: sumWhen(matches('auth.screen.unlock.success|screen.unlock.success')),
            screenUnlockFailures: sumWhen(matches('auth.screen.unlock.failure|screen.unlock.fail')),
            critical: sumWhen({ $eq: ['$severity', 'critical'] }), high: sumWhen({ $eq: ['$severity', 'high'] }),
            medium: sumWhen({ $eq: ['$severity', 'medium'] }), low: sumWhen({ $eq: ['$severity', 'low'] }),
            averageRiskScore: { $avg: { $ifNull: ['$riskScore', 0] } },
          } }],
          timeline: [{ $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, count: { $sum: 1 }, failures: sumWhen({ $eq: ['$authResult', 'failure'] }), successes: sumWhen({ $eq: ['$authResult', 'success'] }) } }, { $sort: { _id: 1 } }],
          topUsers: [{ $group: { _id: '$username', count: { $sum: 1 }, riskScore: { $max: '$riskScore' }, failures: sumWhen({ $eq: ['$authResult', 'failure'] }), lastSeen: { $max: '$createdAt' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { riskScore: -1, count: -1 } }, { $limit: 10 }],
          topSources: [{ $group: { _id: '$srcip', count: { $sum: 1 }, riskScore: { $max: '$riskScore' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          countries: [{ $group: { _id: '$geoCountry', count: { $sum: 1 }, riskScore: { $max: '$riskScore' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 20 }],
          authMethods: [{ $group: { _id: { $ifNull: ['$authType', 'Unknown'] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }, { $limit: 10 }],
          events: [{ $sort: { createdAt: -1 } }, { $limit: eventLimit }, { $project: {
            _id: 1, tenantId: 1, companyId: 1, departmentId: 1, systemId: 1, createdAt: 1, timestamp: 1,
            capabilityId: 1, capabilityIds: 1, eventId: 1, windowsEventId: 1, agentId: 1, agentName: 1, hostname: 1,
            username: 1, user: 1, userDomain: 1, ruleId: 1, description: 1, source: 1, eventType: 1,
            credentialEventType: 1, authType: 1, authResult: 1, failureReason: 1, sessionId: 1, deviceId: 1,
            mfaStatus: 1, identityProvider: 1, privilegeLevel: 1, credentialTarget: 1, tokenType: 1,
            severity: 1, status: 1, actionable: 1, action: 1, actionTaken: 1, srcip: 1, sourcePort: 1,
            destip: 1, destPort: 1, protocol: 1, riskScore: 1, confidenceScore: 1, processName: 1,
            processCmdline: 1, processExe: 1, pid: 1, parentPid: 1, parentProcessName: 1, filePath: 1,
            fileHash: 1, os: 1, osType: 1, platform: 1, mitreId: 1, mitreTechnique: 1, mitreTactic: 1,
            geoCountry: 1, geoCity: 1, geoISP: 1, asn: 1, userAgent: 1, iocMatched: 1, recommendedAction: 1,
          } }],
        } },
      ]).option({ allowDiskUse: true, maxTimeMS: 15000 }).then(rows => rows[0] || {}),
      System.aggregate([{ $match: companyScope(req) }, { $group: { _id: null, total: { $sum: 1 }, live: { $sum: { $cond: [{ $gte: ['$lastSeen', activeSince] }, 1, 0] } } } }]).option({ maxTimeMS: 5000 }).then(rows => rows[0] || {}),
    ]);
    res.json({
      summary: { ...(facets.summary?.[0] || {}), _id: undefined, protectedEndpoints: Number(agents.total || 0), liveAgents: Number(agents.live || 0), offlineAgents: Math.max(0, Number(agents.total || 0) - Number(agents.live || 0)) },
      timeline: facets.timeline || [], topUsers: facets.topUsers || [], topSources: facets.topSources || [],
      countries: facets.countries || [], authMethods: facets.authMethods || [], events: facets.events || [],
      generatedAt: new Date(), realtimeEvent: 'credential:event',
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/live', async (req, res) => {
  try {
    const events = await Alert.find(credentialQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 100, 1, 500)).lean();
    res.json({ events, total: events.length, realtimeEvent: 'credential:event' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/logs', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 100000); const limit = integer(req.query.limit, 100, 1, 500);
    const query = credentialQuery(req);
    const [events, total] = await Promise.all([Alert.find(query).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean(), Alert.countDocuments(query)]);
    res.json({ events, total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/log/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid alert id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), ...CREDENTIAL_FILTER }).lean();
    if (!event) return res.status(404).json({ message: 'Credential security event not found' });
    const pivots = [event.username, event.srcip, event.sessionId, event.deviceId].filter(Boolean);
    const relatedEvents = pivots.length ? await Alert.find({
      ...companyScope(req), ...CREDENTIAL_FILTER,
      createdAt: { $gte: new Date(new Date(event.createdAt).getTime() - 30 * 60000), $lte: new Date(new Date(event.createdAt).getTime() + 30 * 60000) },
      $and: [{ $or: [{ username: { $in: pivots } }, { srcip: { $in: pivots } }, { sessionId: { $in: pivots } }, { deviceId: { $in: pivots } }] }],
    }).sort({ createdAt: 1 }).limit(100).lean() : [];
    res.json({ event, relatedEvents });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/reports', async (req, res) => {
  try {
    const events = await Alert.find(credentialQuery(req)).sort({ createdAt: -1 }).limit(integer(req.query.limit, 5000, 1, 10000)).lean();
    res.json({ events, total: events.length, filters: req.query, generatedAt: new Date() });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/respond', requireCompanyAdmin, async (req, res) => {
  try {
    const actionType = String(req.body.actionType || '');
    if (!mongoose.isValidObjectId(req.body.alertId)) return res.status(400).json({ message: 'Valid alertId is required' });
    if (!ACTIONS.has(actionType)) return res.status(400).json({ message: 'Unsupported response action' });
    if (!req.body.confirmed || !String(req.body.reason || '').trim()) return res.status(400).json({ message: 'confirmed=true and reason are required' });
    const alert = await Alert.findOne({ _id: req.body.alertId, ...companyScope(req), ...CREDENTIAL_FILTER });
    if (!alert) return res.status(404).json({ message: 'Credential security event not found' });
    const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId }).lean();
    if (!system) return res.status(409).json({ message: 'Target endpoint is unavailable' });
    const actionParams = { ...(req.body.actionParams || {}) };
    if (['disable_user', 'lock_account'].includes(actionType) && !actionParams.username) actionParams.username = alert.username;
    if (actionType === 'revoke_token' && !actionParams.sessionId) actionParams.sessionId = alert.sessionId;
    if (actionType === 'kill_process' && !actionParams.pid) actionParams.pid = alert.pid;
    if (actionType === 'block_ip' && !actionParams.ip) actionParams.ip = alert.srcip;
    const response = await createResponse({ companyId: alert.companyId, tenantId: alert.tenantId, alert, system, actionType, actionParams, triggeredBy: req.user.id || req.user._id, trigger: 'manual', io: req.app.get('io'), forceApproval: true });
    await writeAudit(req, alert, actionType, req.body.reason, response?._id);
    res.status(202).json({ response });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase();
    const events = await Alert.find(credentialQuery(req, req.body.filters || {})).sort({ createdAt: -1 }).limit(10000).lean();
    if (format === 'json') return res.json({ events, total: events.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Hostname', 'Username', 'Event', 'Authentication', 'Result', 'Source IP', 'Destination IP', 'Process', 'Risk Score', 'Severity', 'MITRE', 'Country', 'Status'];
    const rows = events.map(row => [row.createdAt, row.hostname, row.username, row.credentialEventType || row.ruleId, row.authType, row.authResult, row.srcip, row.destip, row.processName, row.riskScore, row.severity, row.mitreId || row.mitreTechnique, row.geoCountry, row.status]);
    if (format === 'csv') return res.type('text/csv').attachment(`credential-security-${Date.now()}.csv`).send([columns.map(csvCell).join(','), ...rows.map(row => row.map(csvCell).join(','))].join('\n'));
    if (format === 'pdf') return res.type('application/pdf').attachment(`credential-security-${Date.now()}.pdf`).send(buildPdf(['AJNAT SOC - Credential Security Report', `Generated: ${new Date().toISOString()}`, `Records: ${events.length}`, '', ...rows.map(row => row.map(value => String(value ?? '')).join(' | '))]));
    return res.status(400).json({ message: 'Supported formats: csv, pdf, json' });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
