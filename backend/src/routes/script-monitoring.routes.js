const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const System = require('../models/System.model');
const ScriptMonitoringRule = require('../models/ScriptMonitoringRule.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { authenticate, requireAnalyst, requireManager } = require('../middleware/auth.middleware');
const { scopeForUser } = require('../utils/tenantScope');

router.use(authenticate, requireAnalyst);

const DEFAULT_RULES = Object.freeze([
  { id: 'builtin-script-obfuscation', name: 'Encoded / Obfuscated Script', enabled: true, priority: 10, riskThreshold: 60, ruleIds: ['SCRIPT_OBFUSCATED_COMMAND'] },
  { id: 'builtin-script-download', name: 'Script Download and Execute', enabled: true, priority: 20, riskThreshold: 65, ruleIds: ['SCRIPT_DOWNLOAD_EXECUTE'] },
  { id: 'builtin-script-policy-bypass', name: 'Script Policy Bypass', enabled: true, priority: 30, riskThreshold: 65, ruleIds: ['SCRIPT_POLICY_BYPASS'] },
]);

function objectId(value, label) {
  if (!mongoose.Types.ObjectId.isValid(value)) throw Object.assign(new Error(`Invalid ${label}`), { statusCode: 400 });
  return new mongoose.Types.ObjectId(String(value));
}

function userScope(req) {
  if (req.user.role === 'superadmin') {
    const companyId = req.query.companyId || req.body?.companyId || req.user.companyId;
    return { companyId: objectId(companyId, 'companyId') };
  }
  const resolved = scopeForUser(req.user, { departmentScoped: true });
  if (!resolved.companyId) throw Object.assign(new Error('Company scope required'), { statusCode: 403 });
  return Object.fromEntries(Object.entries(resolved).map(([key, value]) => (
    ['tenantId', 'companyId', 'departmentId', 'partnerId'].includes(key) && mongoose.Types.ObjectId.isValid(value)
      ? [key, new mongoose.Types.ObjectId(String(value))]
      : [key, value]
  )));
}

function first(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function boundedInt(value, fallback, min, max) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(max, Math.max(min, Math.trunc(number))) : fallback;
}

function rawTelemetry(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function interpreterName(value, scriptPath = '') {
  const text = `${value || ''} ${scriptPath || ''}`.toLowerCase();
  if (/powershell|pwsh|\.ps1\b/.test(text)) return 'PowerShell';
  if (/cmd(?:\.exe)?|\.bat\b|\.cmd\b/.test(text)) return 'CMD / Batch';
  if (/wscript|cscript|\.vbs?e?\b/.test(text)) return 'VBScript';
  if (/\bnode(?:\.exe)?\b|javascript|\.jse?\b/.test(text)) return 'Node.js / JavaScript';
  if (/\bpython(?:3|\.exe)?\b|\.py\b/.test(text)) return 'Python';
  if (/\bbash\b|\bzsh\b|\bdash\b|\/bin\/sh|\.sh\b/.test(text)) return 'Unix Shell';
  if (/\bperl\b|\.pl\b/.test(text)) return 'Perl';
  if (/\bruby\b|\.rb\b/.test(text)) return 'Ruby';
  if (/\bphp(?:\.exe)?\b|\.php\b/.test(text)) return 'PHP';
  return value || 'Unknown interpreter';
}

function canonicalScriptEvent(row = {}) {
  const raw = rawTelemetry(row);
  const commandLine = first(row.commandLine, row.processCmdline, raw.command_line, raw.cmdline, raw.process_cmdline);
  const processName = first(row.processName, raw.process_name, raw.processName, raw.process);
  const scriptPath = first(row.scriptPath, raw.script_path, raw.scriptPath, row.filePath, raw.file_path);
  const scriptName = first(row.scriptName, raw.script_name, raw.scriptName, row.fileName, raw.file_name,
    scriptPath && String(scriptPath).split(/[\\/]/).pop(), processName);
  const processTree = first(row.processTree, raw.process_tree, raw.processTree);
  const normalizedTree = Array.isArray(processTree) && processTree.length ? processTree : [
    first(row.parentProcessName, raw.parent_process_name) ? {
      pid: first(row.parentPid, raw.parent_pid),
      name: first(row.parentProcessName, raw.parent_process_name),
      path: first(raw.parent_exe, raw.parent_path),
      cmd: first(row.parentCommandLine, raw.parent_cmdline),
      status: 'Observed',
    } : null,
    processName ? {
      pid: first(row.pid, raw.pid), name: processName,
      path: first(row.processExe, raw.exe, raw.process_exe), cmd: commandLine, status: String(row.severity || '').toLowerCase() === 'critical' ? 'Critical' : 'Observed',
    } : null,
  ].filter(Boolean);
  const remoteAddresses = first(row.networkConnections, raw.network_connections, row.processRemoteAddresses, raw.remote_addresses, []);
  const detectionReasons = first(row.detectionReasons, raw.detection_reasons, raw.matched_patterns, row.matchedPatterns,
    row.description ? [row.description] : []);
  return {
    ...row,
    timestamp: first(row.timestamp, row.eventTimestamp, row.createdAt, raw.timestamp),
    eventType: first(row.eventType, raw.event_type, raw.eventType, 'script_execution'),
    scriptName: scriptName || 'Unknown script',
    scriptPath: scriptPath || '',
    scriptHash: first(row.scriptHash, raw.script_hash, raw.scriptHash, row.sha256, row.fileHash, raw.sha256),
    scriptSha1: first(row.scriptSha1, raw.script_sha1, raw.sha1),
    scriptMd5: first(row.scriptMd5, raw.script_md5, raw.md5),
    interpreter: interpreterName(first(row.interpreter, raw.interpreter, processName), scriptPath),
    commandLine: commandLine || '',
    processName,
    processPath: first(row.processExe, raw.process_exe, raw.exe),
    pid: first(row.pid, raw.pid),
    parentPid: first(row.parentPid, raw.parent_pid),
    parentProcess: first(row.parentProcessName, raw.parent_process_name),
    parentCommandLine: first(row.parentCommandLine, raw.parent_cmdline),
    processTree: normalizedTree,
    childProcesses: first(row.childProcesses, raw.child_processes, []),
    networkConnections: Array.isArray(remoteAddresses) ? remoteAddresses : [],
    filesCreated: first(row.filesCreated, raw.files_created, []),
    filesModified: first(row.filesModified, raw.files_modified, []),
    filesDeleted: first(row.filesDeleted, raw.files_deleted, []),
    executionSource: first(row.executionSource, raw.execution_source, raw.executionSource),
    integrityLevel: first(row.processIntegrityLevel, raw.integrity_level),
    obfuscationScore: boundedInt(first(row.obfuscationScore, raw.obfuscation_score), 0, 0, 100),
    detectionReasons: Array.isArray(detectionReasons) ? detectionReasons : [String(detectionReasons)],
    riskScore: boundedInt(first(row.riskScore, raw.risk_score), 0, 0, 100),
    mitreTechnique: first(row.mitreTechnique, row.technique, raw.mitre_technique, raw.technique),
    mitreId: first(row.mitreId, raw.mitre_id),
    mitreTechniques: first(row.mitreTechniques, raw.mitre_techniques, []),
    signatureStatus: first(row.signatureStatus, row.processSignatureStatus, raw.signature_status),
    signer: first(row.publisher, row.processPublisher, raw.publisher, raw.signer),
    threatIntel: {
      matched: row.threatIntelMatch === true || raw.threat_intel_match === true,
      source: first(row.threatIntelSource, raw.threat_intel_source),
      reputation: first(row.reputation, raw.reputation, row.vtVerdict),
    },
  };
}

function timeRange(req, defaultHours = 24) {
  const until = req.query.to ? new Date(req.query.to) : new Date();
  const since = req.query.from ? new Date(req.query.from) : new Date(until.getTime() - boundedInt(req.query.windowHours, defaultHours, 1, 2160) * 3600000);
  if (Number.isNaN(since.getTime()) || Number.isNaN(until.getTime()) || since > until) {
    throw Object.assign(new Error('Invalid time range'), { statusCode: 400 });
  }
  return { since, until };
}

function evidenceFilter() {
  return { $or: [{ capabilityId: 21 }, { capabilityIds: 21 }] };
}

function eventQuery(scope, since, until, extra = {}) {
  return { $and: [scope, { createdAt: { $gte: since, $lte: until } }, { isSynthetic: { $ne: true } }, evidenceFilter(), extra] };
}

async function loadEvents(scope, since, until, { limit = 1000, skip = 0, extra = {} } = {}) {
  const query = eventQuery(scope, since, until, extra);
  const [rows, total] = await Promise.all([
    Alert.find(query).sort({ createdAt: -1 }).skip(skip).limit(limit)
      .populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean(),
    Alert.countDocuments(query),
  ]);
  return { events: rows.map(canonicalScriptEvent), total };
}

function summarize(events, total, systems = []) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byInterpreter = {};
  const affectedHosts = new Set();
  const affectedUsers = new Set();
  let suspicious = 0;
  let encoded = 0;
  let blocked = 0;
  const telemetryText = event => [
    event.interpreter, event.processName, event.scriptName, event.scriptPath,
    event.commandLine, event.ruleId, event.description, event.evidenceType,
    event.telemetryProvider, ...(event.detectionReasons || []),
  ].filter(Boolean).join(' ').toLowerCase();
  const metricPatterns = {
    powershellEvents: /powershell|pwsh|\.ps1\b/,
    cmdBatchEvents: /cmd\.exe|cmd \/c|\.bat\b|\.cmd\b/,
    pythonEvents: /python(?:3|\.exe)?|\.py\b/,
    linuxShellEvents: /\bbash\b|\bzsh\b|\bdash\b|unix shell|\/bin\/sh|\.sh\b/,
    nodeEvents: /\bnode(?:\.exe)?\b|javascript|\.js\b/,
    vbscriptEvents: /vbscript|wscript|cscript|\.vbs\b|\.vbe\b/,
    lolbinEvents: /lolbin|certutil|mshta|regsvr32|rundll32/,
    reverseShellEvents: /reverse shell|bind shell|\/dev\/tcp|invoke-shellcode/,
    amsiEvents: /amsi/,
    scriptBlockEvents: /scriptblock|script block|powershell_410[34]|event\s*410[34]/,
    ebpfEvents: /ebpf|execve|auditd/,
    pythonAnalysisEvents: /python.*(?:ast|decompil)|(?:ast|decompil).*python/,
    outboundEvents: /outbound|external network|network connection|socket|destination ip/,
    unsignedEvents: /unsigned|signature.*invalid|unknown publisher/,
  };
  const metrics = Object.fromEntries(Object.keys(metricPatterns).map(key => [key, 0]));
  const detections = { encodedCommands: 0, reverseShells: 0, downloaderScripts: 0, persistenceScripts: 0, filelessAttacks: 0 };
  events.forEach(event => {
    const severity = String(event.severity || 'low').toLowerCase();
    if (bySeverity[severity] !== undefined) bySeverity[severity] += 1;
    byInterpreter[event.interpreter] = (byInterpreter[event.interpreter] || 0) + 1;
    if (event.hostname || event.agentName || event.systemId) affectedHosts.add(String(event.hostname || event.agentName || event.systemId?._id || event.systemId));
    if (event.username) affectedUsers.add(String(event.username));
    if ((event.riskScore || 0) >= 30 || severity === 'high' || severity === 'critical') suspicious += 1;
    if (event.obfuscationScore > 0 || /encoded|obfuscat|base64/i.test(`${event.ruleId || ''} ${event.description || ''}`)) encoded += 1;
    if (event.blocked || /block|quarantin|terminat/i.test(`${event.status || ''} ${event.actionTaken || ''} ${event.containmentStatus || ''}`)) blocked += 1;
    const text = telemetryText(event);
    Object.entries(metricPatterns).forEach(([key, pattern]) => { if (pattern.test(text)) metrics[key] += 1; });
    if (event.obfuscationScore > 0 || /encoded|obfuscat|base64|invoke-expression|\biex\b/.test(text)) detections.encodedCommands += 1;
    if (metricPatterns.reverseShellEvents.test(text)) detections.reverseShells += 1;
    if (/download|stringfromurl|webclient|invoke-webrequest|curl|wget|ingress tool transfer/.test(text)) detections.downloaderScripts += 1;
    if (/scheduled task|cron|systemd|startup|persistence|new-service|sc(?:\.exe)?\s+create/.test(text)) detections.persistenceScripts += 1;
    if (/fileless|memory execution|reflective|inline script/.test(text)) detections.filelessAttacks += 1;
  });
  return {
    totalScripts: total,
    suspiciousScripts: suspicious,
    criticalAlerts: bySeverity.critical,
    encodedCommands: encoded,
    blockedScripts: blocked,
    activeThreats: events.filter(event => ['open', 'investigating'].includes(String(event.status || 'open')) && (event.riskScore || 0) >= 60).length,
    affectedHosts: affectedHosts.size,
    affectedUsers: affectedUsers.size,
    bySeverity,
    byInterpreter,
    endpointsReporting: systems.filter(system => system.isOnline).length,
    lowRiskScripts: events.filter(event => ['low', 'info'].includes(String(event.severity || '').toLowerCase())).length,
    ...metrics,
    detections,
  };
}

function systemOnline(system, now = Date.now()) {
  const seen = system.lastSeen ? new Date(system.lastSeen).getTime() : NaN;
  return Boolean(system.isActive !== false && ['active', 'online'].includes(String(system.status || '').toLowerCase())
    && system.agentVersion && Number.isFinite(seen) && now - seen < 10 * 60 * 1000);
}

function filters(req) {
  const conditions = [];
  if (req.query.severity) conditions.push({ severity: String(req.query.severity).toLowerCase() });
  if (req.query.status) conditions.push({ status: String(req.query.status).toLowerCase() });
  if (req.query.systemId) conditions.push({ systemId: objectId(req.query.systemId, 'systemId') });
  if (req.query.interpreter) conditions.push({ $or: [{ interpreter: new RegExp(String(req.query.interpreter).slice(0, 64), 'i') }, { processName: new RegExp(String(req.query.interpreter).slice(0, 64), 'i') }] });
  if (req.query.search) {
    const escaped = String(req.query.search).slice(0, 200).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const search = new RegExp(escaped, 'i');
    conditions.push({ $or: [{ ruleId: search }, { scriptName: search }, { scriptPath: search }, { processName: search }, { processCmdline: search }, { username: search }, { hostname: search }, { description: search }] });
  }
  return conditions.length ? { $and: conditions } : {};
}

router.get('/overview', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const limit = boundedInt(req.query.limit, 1000, 1, 2000);
    const [{ events, total }, systems] = await Promise.all([
      loadEvents(scope, since, until, { limit }),
      System.find({ companyId: scope.companyId, ...(scope.departmentId ? { departmentId: scope.departmentId } : {}), isActive: true })
        .select('name hostname os osType status lastSeen agentVersion isActive').sort({ lastSeen: -1 }).limit(1000).lean(),
    ]);
    const liveSystems = systems.map(system => ({ ...system, isOnline: systemOnline(system) }));
    res.json({ success: true, events, alerts: events, total, summary: summarize(events, total, liveSystems), systems: liveSystems, since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Script monitoring overview unavailable' });
  }
});

async function eventsHandler(req, res) {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req, 168);
    const page = boundedInt(req.query.page, 1, 1, 100000);
    const limit = boundedInt(req.query.limit, 250, 1, 2000);
    const { events, total } = await loadEvents(scope, since, until, { limit, skip: (page - 1) * limit, extra: filters(req) });
    res.json({ events, alerts: events, total, page, limit, pages: Math.ceil(total / limit), since, until });
  } catch (error) {
    res.status(error.statusCode || 500).json({ message: error.statusCode ? error.message : 'Script events unavailable' });
  }
}

router.get('/events', eventsHandler);
router.get('/alerts', eventsHandler);

router.get('/statistics', async (req, res) => {
  try {
    const scope = userScope(req);
    const { since, until } = timeRange(req);
    const { events, total } = await loadEvents(scope, since, until, { limit: 5000 });
    res.json({ statistics: summarize(events, total), since, until });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/rules', async (req, res) => {
  try {
    const rules = await ScriptMonitoringRule.find(userScope(req)).sort({ priority: 1, updatedAt: -1 }).lean();
    res.json({ rules, builtInRules: DEFAULT_RULES });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

function ruleInput(body = {}) {
  const name = String(body.name || '').trim().slice(0, 160);
  if (!name) throw Object.assign(new Error('Rule name is required'), { statusCode: 400 });
  const hashes = Array.isArray(body.trustedHashes) ? [...new Set(body.trustedHashes.map(value => String(value).trim().toLowerCase()))] : [];
  if (hashes.some(hash => !/^[a-f0-9]{64}$/.test(hash))) throw Object.assign(new Error('Trusted hashes must be SHA-256'), { statusCode: 400 });
  const riskThreshold = Number(body.riskThreshold ?? 30);
  if (!Number.isFinite(riskThreshold) || riskThreshold < 0 || riskThreshold > 100) throw Object.assign(new Error('Risk threshold must be 0 to 100'), { statusCode: 400 });
  return {
    name, description: String(body.description || '').trim().slice(0, 1000), enabled: body.enabled !== false,
    priority: boundedInt(body.priority, 100, 1, 10000), systemIds: Array.isArray(body.systemIds) ? [...new Set(body.systemIds.map(String))].map(id => objectId(id, 'systemId')) : [],
    interpreters: Array.isArray(body.interpreters) ? [...new Set(body.interpreters.map(value => String(value).trim().slice(0, 64)).filter(Boolean))] : [],
    trustedPaths: Array.isArray(body.trustedPaths) ? [...new Set(body.trustedPaths.map(value => String(value).trim().slice(0, 1000)).filter(Boolean))] : [],
    trustedHashes: hashes, trustedPublishers: Array.isArray(body.trustedPublishers) ? [...new Set(body.trustedPublishers.map(value => String(value).trim().slice(0, 300)).filter(Boolean))] : [],
    riskThreshold, alertCooldownSeconds: boundedInt(body.alertCooldownSeconds, 900, 60, 604800),
    detectEncodedCommands: body.detectEncodedCommands !== false, detectObfuscation: body.detectObfuscation !== false,
    detectDownloadExecution: body.detectDownloadExecution !== false, detectPersistence: body.detectPersistence !== false,
    detectExternalConnections: body.detectExternalConnections !== false, requireApprovalForResponse: body.requireApprovalForResponse !== false,
    riskWeights: body.riskWeights && typeof body.riskWeights === 'object' && !Array.isArray(body.riskWeights) ? body.riskWeights : {},
  };
}

async function assertSystemsInScope(scope, systemIds) {
  if (!systemIds.length) return;
  const query = { companyId: scope.companyId, _id: { $in: systemIds } };
  if (scope.departmentId) query.departmentId = scope.departmentId;
  const count = await System.countDocuments(query);
  if (count !== systemIds.length) {
    throw Object.assign(new Error('One or more selected systems are outside your tenant scope'), { statusCode: 403 });
  }
}

async function auditRule(req, action, rule) {
  const actorId = req.user?.id || req.user?._id;
  if (!req.user?.tenantId || !actorId) return;
  await SocAuditEvent.create({ tenantId: req.user.tenantId, companyId: req.user.companyId, actorId, action, targetType: 'ScriptMonitoringRule', targetId: String(rule?._id || ''), metadata: { name: rule?.name, enabled: rule?.enabled, systemIds: (rule?.systemIds || []).map(String) }, ipAddress: String(req.ip || '').replace(/^::ffff:/, '').slice(0, 64) });
}

router.post('/rules', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const input = ruleInput(req.body);
    await assertSystemsInScope(scope, input.systemIds);
    const rule = await ScriptMonitoringRule.create({ ...scope, ...input, createdBy: req.user.id || req.user._id, updatedBy: req.user.id || req.user._id });
    await auditRule(req, 'script_monitoring.rule.created', rule);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('script:rule-updated', { action: 'created', rule });
    res.status(201).json({ rule });
  } catch (error) { res.status(error.code === 11000 ? 409 : error.statusCode || 400).json({ message: error.code === 11000 ? 'A rule with this name already exists' : error.message }); }
});

router.put('/rules/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const input = ruleInput(req.body);
    await assertSystemsInScope(scope, input.systemIds);
    const rule = await ScriptMonitoringRule.findOneAndUpdate({ ...scope, _id: objectId(req.params.id, 'ruleId') }, { $set: { ...input, updatedBy: req.user.id || req.user._id } }, { new: true, runValidators: true });
    if (!rule) return res.status(404).json({ message: 'Script monitoring rule not found' });
    await auditRule(req, 'script_monitoring.rule.updated', rule);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('script:rule-updated', { action: 'updated', rule });
    return res.json({ rule });
  } catch (error) { return res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.delete('/rules/:id', requireManager, async (req, res) => {
  try {
    const scope = userScope(req);
    const rule = await ScriptMonitoringRule.findOneAndDelete({ ...scope, _id: objectId(req.params.id, 'ruleId') });
    if (!rule) return res.status(404).json({ message: 'Script monitoring rule not found' });
    await auditRule(req, 'script_monitoring.rule.deleted', rule);
    req.app.get('io')?.to(`company:${scope.companyId}`).emit('script:rule-updated', { action: 'deleted', removedRuleId: rule._id });
    return res.json({ deleted: true });
  } catch (error) { return res.status(error.statusCode || 400).json({ message: error.message }); }
});

router.get('/events/:id', async (req, res) => {
  try {
    const row = await Alert.findOne({ ...userScope(req), _id: objectId(req.params.id, 'eventId'), isSynthetic: { $ne: true }, ...evidenceFilter() }).populate('systemId', 'name hostname ip ipAddress os osType status lastSeen agentVersion').lean();
    if (!row) return res.status(404).json({ message: 'Script event not found' });
    return res.json({ event: canonicalScriptEvent(row) });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/timeline/:id', async (req, res) => {
  try {
    const scope = userScope(req);
    const row = await Alert.findOne({ ...scope, _id: objectId(req.params.id, 'eventId'), ...evidenceFilter() }).lean();
    if (!row) return res.status(404).json({ message: 'Script event not found' });
    const start = new Date(new Date(row.createdAt).getTime() - 5 * 60 * 1000);
    const end = new Date(new Date(row.createdAt).getTime() + 5 * 60 * 1000);
    const related = await Alert.find({ ...scope, systemId: row.systemId, createdAt: { $gte: start, $lte: end }, isSynthetic: { $ne: true } }).sort({ createdAt: 1 }).limit(250).lean();
    return res.json({ event: canonicalScriptEvent(row), timeline: related });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/process-tree/:id', async (req, res) => {
  try {
    const row = await Alert.findOne({ ...userScope(req), _id: objectId(req.params.id, 'eventId'), ...evidenceFilter() }).lean();
    if (!row) return res.status(404).json({ message: 'Script event not found' });
    return res.json({ processTree: canonicalScriptEvent(row).processTree });
  } catch (error) { return res.status(error.statusCode || 500).json({ message: error.message }); }
});

function csvCell(value) { return `"${String(value ?? '').replace(/"/g, '""')}"`; }

function buildPdf(lines) {
  const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, ' ').replace(/([\\()])/g, '\\$1').slice(0, 180);
  const pages = [];
  for (let index = 0; index < lines.length; index += 52) pages.push(lines.slice(index, index + 52));
  if (!pages.length) pages.push(['No script execution records found']);
  const objects = [];
  const pageIds = pages.map((_, index) => 4 + index * 2);
  objects[1] = '<< /Type /Catalog /Pages 2 0 R >>';
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map(id => `${id} 0 R`).join(' ')}] /Count ${pages.length} >>`;
  objects[3] = '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>';
  pages.forEach((pageLines, index) => {
    const pageId = pageIds[index];
    const contentId = pageId + 1;
    const content = `BT /F1 8 Tf 30 810 Td 11 TL ${pageLines.map(line => `(${safe(line)}) Tj T*`).join(' ')} ET`;
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

router.get('/export/csv', async (req, res) => {
  try {
    const { since, until } = timeRange(req, 2160);
    const { events } = await loadEvents(userScope(req), since, until, { limit: 10000, extra: filters(req) });
    const rows = [['Timestamp', 'Company', 'Host', 'User', 'Script', 'Path', 'Interpreter', 'SHA256', 'Command Line', 'Risk Score', 'Severity', 'Detection', 'MITRE ATT&CK', 'Status']];
    events.forEach(event => rows.push([event.timestamp, event.companyId, event.hostname || event.agentName, event.username, event.scriptName, event.scriptPath, event.interpreter, event.scriptHash, event.commandLine, event.riskScore, event.severity, event.ruleId || event.description, event.mitreId, event.status]));
    res.type('text/csv').attachment(`script-monitoring-${since.toISOString().slice(0, 10)}-${until.toISOString().slice(0, 10)}.csv`).send(rows.map(row => row.map(csvCell).join(',')).join('\n'));
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.get('/export/pdf', async (req, res) => {
  try {
    const { since, until } = timeRange(req, 2160);
    const { events, total } = await loadEvents(userScope(req), since, until, { limit: 5000, extra: filters(req) });
    const summary = summarize(events, total);
    const lines = [
      'AJNAT EDR - SCRIPT EXECUTION MONITORING REPORT',
      `Generated: ${new Date().toISOString()}`,
      `Window: ${since.toISOString()} to ${until.toISOString()}`,
      `Total: ${total} | Suspicious: ${summary.suspiciousScripts} | Critical: ${summary.criticalAlerts} | Encoded: ${summary.encodedCommands}`,
      ' ',
      ...events.flatMap(event => [
        `${event.timestamp || ''} | ${String(event.severity || '').toUpperCase()} | Risk ${event.riskScore || 0} | ${event.ruleId || event.eventType || ''}`,
        `Host: ${event.hostname || event.agentName || ''} | User: ${event.username || ''} | Interpreter: ${event.interpreter || ''}`,
        `Script: ${event.scriptPath || event.scriptName || ''} | SHA256: ${event.scriptHash || ''}`,
        `MITRE: ${event.mitreId || ''} ${event.mitreTechnique || ''} | Action: ${event.actionTaken || event.status || ''}`,
        ' ',
      ]),
    ];
    res.type('application/pdf').attachment(`script-monitoring-${since.toISOString().slice(0, 10)}-${until.toISOString().slice(0, 10)}.pdf`).send(buildPdf(lines));
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router.post('/export', async (req, res) => {
  try {
    const { since, until } = timeRange({ ...req, query: req.body || {} }, 2160);
    const { events, total } = await loadEvents(userScope(req), since, until, { limit: 10000 });
    res.json({ generatedAt: new Date(), since, until, total, events });
  } catch (error) { res.status(error.statusCode || 500).json({ message: error.message }); }
});

router._private = { canonicalScriptEvent, summarize, ruleInput, assertSystemsInScope, evidenceFilter, interpreterName, buildPdf };

module.exports = router;
