const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const RegistryConfigurationControl = require('../models/RegistryConfigurationControl.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { capabilityTagFilter, resolveCapabilityDepartmentScope } = require('../utils/capabilityOverview');
const { BUILTIN_POLICIES, invalidateRegistryPolicyCache } = require('../services/registryConfigurationPolicy.service');

const PERIOD_HOURS = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
const VALID_STATUS = new Set(['open', 'investigating', 'resolved', 'false_positive', 'under_observation']);
const VALID_SEVERITY = new Set(['low', 'medium', 'high', 'critical']);
const integer = (value, fallback, min, max) => Math.min(max, Math.max(min, Number.parseInt(value, 10) || fallback));
const escapeRegex = value => String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const CAPABILITY_EVIDENCE = capabilityTagFilter(6);

const projection = [
  'eventId eventFingerprint tenantId companyId departmentId systemId agentId agentName endpointId hostname os osType platform agentVersion',
  'ruleId detectionRuleId description details source eventCategory category subCategory eventType severity riskScore status username userSid',
  'configurationCategory configurationOperation configurationObject configurationPlatform configurationBaselineStatus configurationPolicyId configurationPolicyViolation configurationRiskFactors',
  'registryHive registryValueName registryValueType keyPath registryKey sourcePath oldValue newValue oldHash newHash hashAlgorithm hash',
  'filePath fileName fileAction changedByUser processName processExe processCmdline commandLine pid parentPid parentProcessName processAttribution',
  'signatureStatus publisher processSignatureStatus processPublisher mitreId mitreTechnique technique mitreTactic detectionReason confidenceScore',
  'rawEvent processTree childProcesses networkConnections filesCreated filesModified filesDeleted assignedTo createdAt updatedAt firstSeen lastSeen actionTaken',
].join(' ');

function companyScope(req, requestedDepartmentId = req.query?.departmentId) {
  const rawCompany = req.user.companyId?._id || req.user.companyId;
  if (!mongoose.Types.ObjectId.isValid(rawCompany)) throw Object.assign(new Error('Invalid tenant scope'), { status: 400 });
  const departmentId = resolveCapabilityDepartmentScope(req.user, requestedDepartmentId);
  return {
    companyId: new mongoose.Types.ObjectId(String(rawCompany)),
    ...(departmentId && mongoose.Types.ObjectId.isValid(departmentId)
      ? { departmentId: new mongoose.Types.ObjectId(String(departmentId)) }
      : {}),
  };
}

function eventQuery(req, source = req.query) {
  const query = { ...companyScope(req, source.departmentId), isSynthetic: { $ne: true }, $and: [CAPABILITY_EVIDENCE] };
  const hours = PERIOD_HOURS[String(source.period || '')] || integer(source.windowHours || source.hours, 24, 1, 24 * 365);
  const from = source.from ? new Date(source.from) : new Date(Date.now() - hours * 3600000);
  const to = source.to ? new Date(source.to) : null;
  query.createdAt = { $gte: Number.isNaN(from.getTime()) ? new Date(Date.now() - 86400000) : from };
  if (to && !Number.isNaN(to.getTime())) query.createdAt.$lte = to;
  if (VALID_SEVERITY.has(String(source.severity || '').toLowerCase())) query.severity = String(source.severity).toLowerCase();
  if (VALID_STATUS.has(String(source.status || '').toLowerCase())) query.status = String(source.status).toLowerCase();
  if (source.platform) query.configurationPlatform = new RegExp(`^${escapeRegex(source.platform).slice(0, 40)}$`, 'i');
  if (source.category) query.configurationCategory = new RegExp(`^${escapeRegex(source.category).slice(0, 120)}$`, 'i');
  if (source.operation) query.configurationOperation = new RegExp(escapeRegex(source.operation).slice(0, 80), 'i');
  if (source.hostname) query.hostname = new RegExp(`^${escapeRegex(source.hostname).slice(0, 253)}$`, 'i');
  if (source.user) query.username = new RegExp(escapeRegex(source.user).slice(0, 100), 'i');
  if (source.minRisk != null) query.riskScore = { $gte: integer(source.minRisk, 0, 0, 100) };
  if (String(source.policyViolation || '').toLowerCase() === 'true') query.configurationPolicyViolation = true;
  if (source.search) {
    const value = new RegExp(escapeRegex(source.search).slice(0, 200), 'i');
    query.$and.push({ $or: [
      { description: value }, { ruleId: value }, { hostname: value }, { username: value },
      { configurationCategory: value }, { configurationOperation: value }, { configurationObject: value },
      { keyPath: value }, { registryKey: value }, { registryValueName: value }, { processName: value }, { mitreId: value },
    ] });
  }
  return query;
}

function csvCell(value) {
  let text = typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value ?? '');
  if (/^[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No registry/configuration records found']);
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

async function audit(req, action, targetId, metadata = {}) {
  const actorId = req.user.id || req.user._id;
  if (!actorId || !req.user.tenantId) return;
  await SocAuditEvent.create({
    tenantId: req.user.tenantId, companyId: req.user.companyId?._id || req.user.companyId,
    actorId, action, targetType: 'RegistryConfiguration', targetId: String(targetId || ''), metadata,
    ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64),
  });
}

function emit(req, eventName, payload) {
  const companyId = req.user.companyId?._id || req.user.companyId;
  req.app.get('io')?.to(`company:${companyId}`).emit(eventName, payload);
}

router.use(authenticate, requireAnalyst);

router.get('/dashboard', async (req, res) => {
  try {
    const match = eventQuery(req);
    const [facets = {}, systems = []] = await Promise.all([
      Alert.aggregate([
        { $match: match },
        { $set: { _registryDashboardText: { $toLower: { $concat: [
          { $ifNull: ['$configurationObject', ''] }, ' ', { $ifNull: ['$description', ''] }, ' ',
          { $ifNull: ['$ruleId', ''] }, ' ', { $ifNull: ['$configurationCategory', ''] },
        ] } } } },
        { $facet: {
        summary: [{ $group: { _id: null, total: { $sum: 1 },
          critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
          medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
          low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
          unauthorized: { $sum: { $cond: [{ $in: ['$configurationBaselineStatus', ['unexpected', 'deviation', 'unauthorized']] }, 1, 0] } },
          persistence: { $sum: { $cond: [{ $eq: ['$configurationCategory', 'persistence'] }, 1, 0] } },
          security: { $sum: { $cond: [{ $eq: ['$configurationCategory', 'security_configuration'] }, 1, 0] } },
          policyViolations: { $sum: { $cond: ['$configurationPolicyViolation', 1, 0] } },
          averageRisk: { $avg: '$riskScore' }, maximumRisk: { $max: '$riskScore' },
        } }],
        timeline: [{ $group: { _id: { hour: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, severity: '$severity' }, count: { $sum: 1 } } }, { $sort: { '_id.hour': 1 } }],
        categories: [{ $group: { _id: { $ifNull: ['$configurationCategory', 'unclassified'] }, count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { count: -1 } }],
        platforms: [{ $group: { _id: { $ifNull: ['$configurationPlatform', { $ifNull: ['$osType', '$platform'] }] }, count: { $sum: 1 } } }, { $sort: { count: -1 } }],
        hosts: [{ $group: { _id: { $ifNull: ['$hostname', '$agentName'] }, count: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } }, maxRisk: { $max: '$riskScore' }, lastSeen: { $max: '$createdAt' } } }, { $match: { _id: { $nin: [null, ''] } } }, { $sort: { count: -1 } }, { $limit: 50 }],
        signals: [{ $group: { _id: null,
          runKeys: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'runonce|autorun|startup|winlogon' } }, 1, 0] } },
          services: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'service|systemd' } }, 1, 0] } },
          defender: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'defender|antivirus|disableantispyware' } }, 1, 0] } },
          firewall: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'firewall|iptables|ufw' } }, 1, 0] } },
          uac: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'uac|enablelua|security.center' } }, 1, 0] } },
          rdp: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'rdp|fdenytsconnections|remote.desktop' } }, 1, 0] } },
          sudoers: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'sudoers' } }, 1, 0] } },
          cron: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'crontab|cron\\.|/cron/' } }, 1, 0] } },
          ssh: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'sshd.config|authorized.keys|ssh.key' } }, 1, 0] } },
          dnsProxy: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'resolv.conf|hosts|proxy|dns|tcpip' } }, 1, 0] } },
          packages: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'apt|yum|dpkg|rpm|zypper|msi|package' } }, 1, 0] } },
          auditTampering: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'log.cleared|eventlog|audit.*disable|sysmon.*disable' } }, 1, 0] } },
          solarisSmf: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'smf|svcs|svcadm|user.attr|rbac' } }, 1, 0] } },
          solarisZfs: { $sum: { $cond: [{ $regexMatch: { input: '$_registryDashboardText', regex: 'zfs|zpool' } }, 1, 0] } },
        } }],
        events: [{ $sort: { createdAt: -1 } }, { $limit: integer(req.query.limit, 250, 1, 1000) }, { $project: Object.fromEntries(projection.split(' ').map(field => [field, 1])) }],
      } }]).option({ allowDiskUse: true, maxTimeMS: 12000 }).then(rows => rows[0] || {}),
      System.find(companyScope(req)).select('name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').sort({ lastSeen: -1 }).limit(2000).lean(),
    ]);
    const summary = facets.summary?.[0] || {};
    res.json({
      summary: { ...summary, _id: undefined, affectedSystems: facets.hosts?.length || 0 },
      timeline: facets.timeline || [], categories: facets.categories || [], platforms: facets.platforms || [], hosts: facets.hosts || [],
      signals: { ...(facets.signals?.[0] || {}), _id: undefined },
      events: facets.events || [], systems, total: summary.total || 0, generatedAt: new Date(), realtimeEvent: 'registry:event',
    });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry dashboard could not be loaded' }); }
});

router.get('/events', async (req, res) => {
  try {
    const page = integer(req.query.page, 1, 1, 1000000); const limit = integer(req.query.limit, 100, 1, 1000); const query = eventQuery(req);
    const [events, total] = await Promise.all([
      Alert.find(query).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).maxTimeMS(5000).lean(),
      Alert.countDocuments(query).maxTimeMS(5000),
    ]);
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit), realtimeEvent: 'registry:event' });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry events could not be loaded' }); }
});

router.get('/statistics', async (req, res) => {
  try {
    const rows = await Alert.aggregate([{ $match: eventQuery(req) }, { $group: { _id: { category: '$configurationCategory', platform: '$configurationPlatform', severity: '$severity' }, count: { $sum: 1 } } }]).option({ maxTimeMS: 5000 });
    res.json({ statistics: rows });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry statistics could not be loaded' }); }
});

router.get('/timeline', async (req, res) => {
  try {
    const timeline = await Alert.aggregate([{ $match: eventQuery(req) }, { $group: { _id: { $dateTrunc: { date: '$createdAt', unit: 'hour' } }, count: { $sum: 1 }, maxRisk: { $max: '$riskScore' } } }, { $sort: { _id: 1 } }]).option({ maxTimeMS: 5000 });
    res.json({ timeline });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry timeline could not be loaded' }); }
});

router.get('/policies', async (req, res) => {
  try {
    const custom = await RegistryConfigurationControl.find({ ...companyScope(req), kind: 'policy' }).sort({ createdAt: -1 }).lean();
    const overrides = new Map(custom.filter(item => item.policyId).map(item => [item.policyId, item]));
    const policies = BUILTIN_POLICIES.map(item => ({ ...item, ...(overrides.get(item.policyId) || {}), builtin: true }))
      .concat(custom.filter(item => !BUILTIN_POLICIES.some(definition => definition.policyId === item.policyId)));
    res.json({ policies, total: policies.length });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry policies could not be loaded' }); }
});

router.get('/baselines', async (req, res) => {
  try {
    const controls = await RegistryConfigurationControl.find({ ...companyScope(req), kind: { $in: ['baseline', 'exception'] }, $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] }).sort({ createdAt: -1 }).limit(1000).lean();
    res.json({ controls, total: controls.length });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry baselines could not be loaded' }); }
});

async function saveControl(req, res, kind) {
  const actorId = req.user.id || req.user._id; const scope = companyScope(req, req.body.departmentId);
  const target = String(req.body.target || '*').trim(); const name = String(req.body.name || req.body.reason || '').trim();
  if (!name || !target) return res.status(400).json({ message: 'name/reason and target are required' });
  const expiresAt = req.body.expiresAt ? new Date(req.body.expiresAt) : null;
  if (expiresAt && Number.isNaN(expiresAt.getTime())) return res.status(400).json({ message: 'Invalid expiresAt' });
  const control = await RegistryConfigurationControl.create({
    tenantId: req.user.tenantId, ...scope, systemId: mongoose.isValidObjectId(req.body.systemId) ? req.body.systemId : null,
    kind, policyId: kind === 'policy' ? String(req.body.policyId || `REG-CUSTOM-${Date.now()}`).slice(0, 120) : undefined,
    name: name.slice(0, 200), category: String(req.body.category || 'all').slice(0, 120), operation: String(req.body.operation || '').slice(0, 80),
    target: target.slice(0, 2048), expectedState: req.body.expectedState ?? null, enabled: req.body.enabled !== false,
    severity: VALID_SEVERITY.has(String(req.body.severity || '').toLowerCase()) ? String(req.body.severity).toLowerCase() : 'medium',
    riskThreshold: integer(req.body.riskThreshold, 50, 0, 100),
    excludedHosts: Array.isArray(req.body.excludedHosts) ? req.body.excludedHosts.map(String).slice(0, 100) : [],
    excludedUsers: Array.isArray(req.body.excludedUsers) ? req.body.excludedUsers.map(String).slice(0, 100) : [],
    excludedProcesses: Array.isArray(req.body.excludedProcesses) ? req.body.excludedProcesses.map(String).slice(0, 100) : [],
    excludedPaths: Array.isArray(req.body.excludedPaths) ? req.body.excludedPaths.map(String).slice(0, 100) : [],
    allowedChanges: Array.isArray(req.body.allowedChanges) ? req.body.allowedChanges.map(String).slice(0, 100) : [],
    monitoringSchedule: req.body.monitoringSchedule || null, alertAction: String(req.body.alertAction || 'alert').slice(0, 80),
    reason: String(req.body.reason || name).slice(0, 1000), ticketReference: String(req.body.ticketReference || '').slice(0, 160), expiresAt,
    createdBy: actorId, updatedBy: actorId,
  });
  invalidateRegistryPolicyCache(scope.companyId);
  await audit(req, `registry.${kind}.created`, control._id, { target, category: control.category });
  emit(req, kind === 'policy' ? 'registry:policy-updated' : 'registry:baseline-updated', control);
  return res.status(201).json({ control });
}

router.post('/policies', requireCompanyAdmin, (req, res) => saveControl(req, res, 'policy').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/baselines/approve', requireCompanyAdmin, (req, res) => saveControl(req, res, 'baseline').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/exceptions', requireCompanyAdmin, (req, res) => saveControl(req, res, 'exception').catch(error => res.status(error.status || 500).json({ message: error.message })));

router.patch('/policies/:id', requireCompanyAdmin, async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Valid policy id is required' });
    const allowed = ['name', 'category', 'operation', 'target', 'expectedState', 'enabled', 'severity', 'riskThreshold', 'excludedHosts', 'excludedUsers', 'excludedProcesses', 'excludedPaths', 'allowedChanges', 'monitoringSchedule', 'alertAction', 'reason', 'ticketReference', 'expiresAt'];
    const updates = Object.fromEntries(allowed.filter(field => req.body[field] !== undefined).map(field => [field, req.body[field]]));
    updates.updatedBy = req.user.id || req.user._id;
    const policy = await RegistryConfigurationControl.findOneAndUpdate({ _id: req.params.id, ...companyScope(req, req.body.departmentId), kind: 'policy' }, { $set: updates }, { new: true, runValidators: true });
    if (!policy) return res.status(404).json({ message: 'Registry policy not found' });
    invalidateRegistryPolicyCache(policy.companyId);
    await audit(req, 'registry.policy.updated', policy._id, { fields: Object.keys(updates) });
    emit(req, 'registry:policy-updated', policy);
    res.json({ policy });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

async function updateWorkflow(req, res, status, action) {
  if (!mongoose.isValidObjectId(req.body.eventId)) return res.status(400).json({ message: 'Valid eventId is required' });
  const event = await Alert.findOne({ _id: req.body.eventId, ...companyScope(req, req.body.departmentId), $and: [CAPABILITY_EVIDENCE] });
  if (!event) return res.status(404).json({ message: 'Registry/configuration event not found' });
  event.status = status; if (status === 'investigating') event.assignedTo = req.user.id || req.user._id;
  await event.save(); await audit(req, action, event._id, { reason: String(req.body.reason || '').slice(0, 1000) });
  const payload = event.toObject(); emit(req, 'registry:event-updated', payload); return res.json({ event: payload });
}

router.post('/acknowledge', (req, res) => updateWorkflow(req, res, 'under_observation', 'registry.event.acknowledged').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/investigate', (req, res) => updateWorkflow(req, res, 'investigating', 'registry.event.investigating').catch(error => res.status(error.status || 500).json({ message: error.message })));
router.post('/resolve', (req, res) => updateWorkflow(req, res, 'resolved', 'registry.event.resolved').catch(error => res.status(error.status || 500).json({ message: error.message })));

router.post('/export', async (req, res) => {
  try {
    const format = String(req.body.format || 'csv').toLowerCase();
    const rows = await Alert.find(eventQuery(req, req.body.filters || {})).select(projection).sort({ createdAt: -1 }).limit(10000).maxTimeMS(10000).lean();
    if (format === 'json') return res.json({ events: rows, total: rows.length, generatedAt: new Date() });
    const columns = ['Timestamp', 'Company', 'Host', 'Platform', 'User', 'Process', 'Operation', 'Object', 'Old Value', 'New Value', 'Severity', 'Risk Score', 'Detection', 'MITRE', 'Policy Violation', 'Status'];
    const values = rows.map(row => [row.createdAt, row.companyId, row.hostname || row.agentName, row.configurationPlatform || row.osType || row.platform, row.username, row.processName, row.configurationOperation || row.eventType, row.configurationObject || row.keyPath || row.filePath, row.oldValue, row.newValue, row.severity, row.riskScore, row.detectionReason || row.description, row.mitreId || row.mitreTechnique, row.configurationPolicyViolation, row.status]);
    const csv = [columns, ...values].map(line => line.map(csvCell).join(',')).join('\n');
    if (format === 'csv') return res.type('text/csv').attachment(`registry-configuration-${Date.now()}.csv`).send(csv);
    if (format === 'pdf') return res.type('application/pdf').attachment(`registry-configuration-${Date.now()}.pdf`).send(buildPdf(['AJNAT EDR - Registry & System Configuration Report', `Generated: ${new Date().toISOString()}`, `Records: ${rows.length}`, '', ...values.map(line => line.map(value => String(value ?? '')).join(' | '))]));
    return res.status(400).json({ message: 'Supported formats: csv, pdf, json' });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry export failed' }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: 'Invalid event id' });
    const event = await Alert.findOne({ _id: req.params.id, ...companyScope(req), $and: [CAPABILITY_EVIDENCE] }).select(projection).populate('systemId', 'name hostname ip ipAddress os osType platform status isOnline agentOk lastSeen agentVersion').lean();
    if (!event) return res.status(404).json({ message: 'Registry/configuration event not found' });
    res.json({ event });
  } catch (error) { res.status(error.status || 500).json({ message: error.status ? error.message : 'Registry event could not be loaded' }); }
});

module.exports = router;
