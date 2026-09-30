const router = require('express').Router();
const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');
const Log = require('../models/Log.model');
const System = require('../models/System.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const DashboardConfig = require('../models/DashboardConfig.model');
const GeolocationPolicy = require('../models/GeolocationPolicy.model');
const { authenticate, requireAnalyst, requireSuperAdmin, requireManager } = require('../middleware/auth.middleware');
const { getUserDataFilter } = require('../services/socAccess.service');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { readyUebaSystemIds } = require('../utils/uebaBaseline');

function emitAlertChange(req, event, alert) {
  const io = req.app.get('io');
  if (!io || !alert) return;
  const payload = event === 'alert:deleted'
    ? { alertId: String(alert._id), companyId: String(alert.companyId), departmentId: alert.departmentId ? String(alert.departmentId) : null }
    : alert;
  io.to(`company:${alert.companyId}`).emit(event, payload);
  if (alert.departmentId) io.to(`dept:${alert.departmentId}`).emit(event, payload);
  io.to('superadmin').emit(event, payload);
}
const { expandFimCategoryScope, fimCapabilityFilter } = require('../utils/fimQuery');
const { authCapabilityFilter } = require('../utils/authCapability');
const { registryMonitoringFilter } = require('../utils/registryMonitoring');
const {
  ADVANCED_CAPABILITY_IDS,
  buildCapabilityAnalyticsPlan,
  buildCapabilityQuery,
  capabilityEvidenceFilter,
  clampResultLimit,
  clampWindowHours,
  summarizeCapabilityRows,
} = require('../utils/advancedCapability');
const {
  PUBLIC_EDR_CAPABILITY_IDS,
  geolocationEvidenceFilter,
  liveTargetCapabilityMatch,
  lolbinsEvidenceFilter,
  resolveCapabilityDepartmentScope,
  webDnsEvidenceFilter,
} = require('../utils/capabilityOverview');

function normalizeTools(tools) {
  const defaults = DashboardConfig.DEFAULT_TOOLS();
  const current = (tools || []).find(tool => tool.id === defaults[0].id);
  return current ? [{
    ...defaults[0],
    enabled: current.enabled !== false,
    order: 0,
  }] : defaults;
}

router.use(authenticate);

// ── GET /api/dashboard/config — all roles, scoped by company ─────────────────
// Returns the company's centralized dashboard config (tools, cards, settings).
// If no config exists yet, auto-creates defaults.
router.get('/config', requireAnalyst, async (req, res) => {
  try {
    const companyId = req.user.companyId;
    let cfg = await DashboardConfig.findOne({ companyId }).lean();

    if (!cfg) {
      // Auto-create defaults for this company on first access
      cfg = await DashboardConfig.create({ companyId });
      cfg = cfg.toObject();
    }

    const normalizedTools = normalizeTools(cfg.tools);
    if (JSON.stringify(cfg.tools || []) !== JSON.stringify(normalizedTools)) {
      await DashboardConfig.updateOne({ companyId }, { $set: { tools: normalizedTools } });
    }
    cfg.tools = normalizedTools;

    // Analysts & dept admins see only ENABLED tools/cards
    const readOnly = ['analyst', 'department_admin'].includes(req.user.role);
    if (readOnly) {
      cfg.tools = (cfg.tools || []).filter(t => t.enabled).sort((a, b) => a.order - b.order);
      cfg.cards = (cfg.cards || []).filter(c => c.enabled).sort((a, b) => a.order - b.order);
    } else {
      cfg.tools = (cfg.tools || []).sort((a, b) => a.order - b.order);
      cfg.cards = (cfg.cards || []).sort((a, b) => a.order - b.order);
    }

    cfg.canEdit = !readOnly;
    res.json(cfg);
  } catch (err) {
    console.error('[dashboard/config GET]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/dashboard/config — company_admin + superadmin only ──────────────
// Full replace of tools/cards/settings.  Emits Socket.IO event so all dashboards refresh.
router.post('/config', requireManager, async (req, res) => {
  try {
    const companyId = req.user.companyId;
    const { tools, cards, refreshIntervalSecs, showLogMonitorCard, theme } = req.body;

    const update = { updatedBy: req.user.id };
    if (tools !== undefined) update.tools = normalizeTools(tools);
    if (cards !== undefined) update.cards = cards;
    if (refreshIntervalSecs !== undefined) update.refreshIntervalSecs = refreshIntervalSecs;
    if (showLogMonitorCard !== undefined) update.showLogMonitorCard = showLogMonitorCard;
    if (theme !== undefined) update.theme = theme;

    const cfg = await DashboardConfig.findOneAndUpdate(
      { companyId },
      { $set: update },
      { new: true, upsert: true, runValidators: true },
    ).lean();

    // ── Broadcast to all connected dashboard clients for this company ─────────
    const io = req.app.get('io');
    if (io) {
      const payload = { companyId, config: cfg, updatedBy: req.user.name || req.user.email };
      io.to(`company:${companyId}`).emit('dashboard:config_updated', payload);
      io.to('superadmin').emit('dashboard:config_updated', payload);
      console.log(`[dashboard/config] updated for ${companyId} — broadcast sent`);
    }

    res.json({ ok: true, config: cfg });
  } catch (err) {
    console.error('[dashboard/config POST]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/dashboard/config/superadmin/:companyId — superadmin override ───
router.post('/config/superadmin/:companyId', authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const { companyId } = req.params;
    const { tools, cards, refreshIntervalSecs, showLogMonitorCard, theme } = req.body;

    const update = { updatedBy: req.user.id };
    if (tools !== undefined) update.tools = normalizeTools(tools);
    if (cards !== undefined) update.cards = cards;
    if (refreshIntervalSecs !== undefined) update.refreshIntervalSecs = refreshIntervalSecs;
    if (showLogMonitorCard !== undefined) update.showLogMonitorCard = showLogMonitorCard;
    if (theme !== undefined) update.theme = theme;

    const cfg = await DashboardConfig.findOneAndUpdate(
      { companyId },
      { $set: update },
      { new: true, upsert: true, runValidators: true },
    ).lean();

    const io = req.app.get('io');
    if (io) {
      const payload = { companyId, config: cfg, updatedBy: 'superadmin' };
      io.to(`company:${companyId}`).emit('dashboard:config_updated', payload);
      io.to('superadmin').emit('dashboard:config_updated', payload);
    }

    res.json({ ok: true, config: cfg });
  } catch (err) {
    console.error('[dashboard/config/superadmin POST]', err.message);
    res.status(500).json({ message: err.message });
  }
});



// ── Category mapper ───────────────────────────────────────────────────────────
function toCategory(type, source) {
  const t = (type || '').toLowerCase();
  const s = (source || '').toLowerCase();
  if (t.includes('malware') || t.includes('ransomware') || t.includes('yara') ||
    t.includes('trojan') || t.includes('miner') || t.includes('backdoor') ||
    s === 'yara') return 'malware';
  if (t.includes('network') || t.includes('port_scan') || t.includes('ddos') ||
    s === 'network') return 'network';
  if (t.includes('file') || s === 'file_watch') return 'file';
  if (t.includes('auth') || t.includes('brute') || t.includes('login') ||
    t.includes('edr') || t.includes('user') || s === 'edr') return 'edr';
  if (t.includes('isolat') || t.includes('quarant')) return 'isolation';
  if (t.includes('usb') || s === 'usb') return 'usb';
  if (t.includes('process') || t.includes('service') || t.includes('system') ||
    s === 'syslog' || s === 'windows_event_log' || s === 'macos_unified_log') return 'system';
  return 'other';
}

function mapSeverity(level) {
  if (level >= 13) return 'critical';
  if (level >= 10) return 'high';
  if (level >= 7) return 'medium';
  return 'low';
}

function capabilityAlertFilter(capabilityId) {
  const id = Number(capabilityId);
  const text = (pattern) => ({
    $or: [
      { ruleId: pattern },
      { type: pattern },
      { description: pattern },
      { full_log: pattern },
      { processName: pattern },
      { malwareType: pattern },
      { userAction: pattern },
      { fileAction: pattern },
    ],
  });
  const exact = () => [
    { capabilityId: id },
    { capabilityIds: id },
  ];
  const exactOrText = pattern => ({
    $or: [...exact(), ...text(pattern).$or],
  });

  switch (id) {
    case 1:
      return {
        $or: [
          { ruleId: 'PROC_INVENTORY_SUMMARY' },
          { ruleId: /^(PROC_(STARTED|TERMINATED|TERMINATE_REQUESTED|SUSPICIOUS|SUSPICIOUS_CMDLINE|UNAUTHORIZED_EXECUTION|HIGH_CPU|HIGH_MEMORY)|EDR_.*PROCESS|EDR_HIGH_CPU|EDR_HIGH_MEMORY|EDR_SUSPICIOUS_CMDLINE)|powershell|cmd|bash|python|java|vbscript|jscript|service|cron|task|dns|c2|lolbin|ransom|malware|credential|sudo|root|admin|web|database/i },
          { processName: { $exists: true, $ne: '' } },
          { processCmdline: { $exists: true, $ne: '' } },
          { pid: { $exists: true, $ne: null } },
          { userAction: /process|proc|suspicious_execution|malware_process|high_memory|privilege|sudo|root|admin|c2|ransom|credential/i },
          { description: /(process.*pid|pid.*cpu|parent.*cpu|command line|powershell|cmd|bash|shell|python|java|vbscript|javascript|browser|service|cron|task scheduler|dns|external ip|command.*control|c2|lolbin|antivirus kill|dll injection|process injection|hollowing|fileless|unsigned|unknown executable|malware|ransomware|credential dumping|remote access|web shell|reverse shell|crypto miner|lateral movement|sudo|root|admin|apache|nginx|iis|tomcat|mysql|mssql|postgres|oracle)/i },
        ],
      };
    case 2: return fimCapabilityFilter();
    case 3: return text(/network|connection|outbound|inbound|port|dns|tcp|udp/i);
    case 4: return authCapabilityFilter();
    case 5:
      return {
        $or: [
          { capabilityId: 5 },
          { category: /^memory$/i },
          text(/memory|ram|process memory|memory spike|memory leak|mimikatz|lsass|dump|process injection|dll injection|shellcode|rwx|heap|stack|fileless|hook|behavior analytics|risk score/i),
          { processMemoryPercent: { $exists: true, $ne: null } },
          { 'rawEvent.riskScore': { $exists: true, $ne: null } },
        ],
      };
    case 6:
      return { capabilityId: 6 };
    case 7:
      return {
        $or: [
          { capabilityId: 7 },
          { category: /^systemchanges$/i },
          text(/system change|system health|service|driver|software install|software uninstall|software update|scheduled task|boot config|file integrity|user activity|threat intel|kernel|module|host|change/i),
          { subCategory: /incident|health|service|driver|software|scheduled|boot|file-integrity|user|threat/i },
        ],
      };
    case 8:
      return {
        $or: [
          { capabilityId: 8 },
          { category: /^persistence$/i },
          text(/persistence|startup|registry run key|run key|scheduled task|cron|systemd|service install|wmi|com hijack|dll hijack|ssh authorized|authorized_keys|kernel module|network persistence|cloud persistence|powershell persistence/i),
          { subCategory: /startup|run-key|scheduled|service|wmi|com|dll|cron|systemd|ssh|kernel|network|cloud/i },
        ],
      };
    case 9: return { $and: [{ $or: exact() }, webDnsEvidenceFilter()] };
    case 10:
      // Do not use generic words such as "device" or "storage" here: they
      // match ordinary endpoint, credential and filesystem alerts and inflate
      // the USB record total. Count only records explicitly tagged by the USB
      // collector/capability pipeline.
      return {
        $or: [
          { capabilityId: 10 },
          { capabilityIds: 10 },
          { eventCategory: 'usb' },
          { category: /^usb$/i },
        ],
      };
    case 11: return exactOrText(/ueba|behavio(?:u)?r|baseline deviation|anomal/i);
    case 12: return exactOrText(/\bdlp\b|data exfil|sensitive file|confidential|large (?:upload|transfer)/i);
    case 13: return exactOrText(/credential|mimikatz|lsass|password dump|pass.the.hash|kerberoast|sam access|ntds/i);
    case 14: return exactOrText(/lateral movement|psexec|\brdp\b|\bsmb\b|winrm|admin share|remote wmi|pass.the.(?:hash|ticket)/i);
    // Email telemetry is tagged by deriveCapabilityIds() during ingestion.
    // Searching every alert text field for generic email words made the
    // dashboard poll exceed MongoDB's maxTimeMS in the query multiplanner.
    case 15: return { $or: exact() };
    // Current insider telemetry is normalized and cross-tagged at ingestion.
    // Regex fallbacks across large text fields make this frequently-polled
    // endpoint perform a collection-wide scan and can saturate MongoDB.
    case 16: return { $or: exact() };
    case 17: return exactOrText(/vulnerab|unpatched|patch status|missing (?:patch|update|kb)|cve-|end.of.life|unsupported os/i);
    case 18: return exactOrText(/sandbox|detonation|malware analysis|yara|virustotal|\bvt[_ -]/i);
    case 19:
      return {
        $and: [
          { $or: [
            ...exact(),
            { ruleId: { $in: ['SYS_MODULE_LOAD', 'SYS_KERNEL_ERR', 'PROC_LINUX_KERNEL_INJECTION'] } },
            ...text(/kernel|rootkit|syscall|auditd|module load|ebpf|driver load/i).$or,
          ] },
          { processName: { $ne: 'bwrap' } },
        ],
      };
    case 20: return exactOrText(/api call|waf|api gateway|http request|sql injection|cross.site scripting|command injection|xxe|ssrf|path traversal/i);
    case 21: return exactOrText(/script execution|powershell|encoded command|invoke-expression|\bwscript\b|\bcscript\b|\bmshta\b|shell script|\bpython\b|\bnode(?:\.exe)?\b/i);
    case 22: return exactOrText(/time.based|after.hours|unusual time|authentication burst|activity spike|brute (?:force )?surge/i);
    case 23:
      // Capability tags provide an indexed candidate set before applying the
      // stricter GPS/policy evidence filter. Without this guard MongoDB scans
      // every alert's geo fields and repeatedly hits this route's 5s limit.
      return { $and: [{ $or: exact() }, geolocationEvidenceFilter()] };
    case 24: return exactOrText(/service (?:health|status|failure|stopped|disabled|created|control)|security tool (?:tamper|terminated)|firewall (?:off|disabled)/i);
    case 25: return exactOrText(/hash (?:match|analysis|changed)|signature (?:match|analysis|status)|yara|sha256|sha1|md5|threat intelligence/i);
    case 26: return exactOrText(/beacon|command.and.control|\bc2\b|callback pattern|periodicity|jitter/i);
    case 27: return exactOrText(/ransom|mass encrypt|shadow copy|backup tamper|high.entropy|\.locked|\.encrypted|\.crypt|\.lockbit|\.ryuk|\.akira|\.blackcat|\.conti|\.clop/i);
    case 28: return lolbinsEvidenceFilter();
    case 29: return capabilityEvidenceFilter(29);
    case 30: return capabilityEvidenceFilter(30);
    case 31: return capabilityEvidenceFilter(31);
    default: return null;
  }
}

function fimModuleAlertFilter(moduleId = '') {
  const module = String(moduleId || '').toLowerCase().replace(/_/g, '-');
  if (!module) return null;
  const indexedModule = {
    'integrity-monitoring': 'integrity', integrity: 'integrity',
    permissions: 'permission', permission: 'permission', 'permission-changes': 'permission',
    ownership: 'ownership', 'ownership-changes': 'ownership',
    'ransomware-detection': 'ransomware', ransomware: 'ransomware',
    'sensitive-files': 'sensitive', sensitive: 'sensitive',
  }[module];
  if (indexedModule) return { fimModule: indexedModule };
  const text = (pattern) => ({
    $or: [
      { ruleId: pattern },
      { type: pattern },
      { description: pattern },
      { full_log: pattern },
      { filePath: pattern },
      { fileAction: pattern },
      { 'rawEvent.module_type': pattern },
      { 'rawEvent.moduleType': pattern },
      { 'rawEvent.fim_module': pattern },
      { 'rawEvent.event_type': pattern },
      { 'rawEvent.change_type': pattern },
      { 'rawEvent.file_path': pattern },
      { 'rawEvent.fileAction': pattern },
      { 'rawEvent.file_action': pattern },
    ],
  });

  switch (module) {
    case 'integrity':
    case 'integrity-monitoring':
      return {
        $or: [
          { 'rawEvent.module_type': /^(integrity|hash)$/i },
          { 'rawEvent.fim_module': /^(integrity|hash)$/i },
          { 'rawEvent.old_hash': { $exists: true, $ne: '' } },
          { 'rawEvent.new_hash': { $exists: true, $ne: '' } },
          { fileHash: { $exists: true, $ne: '' } },
          text(/hash|integrity|baseline|checksum|mismatch/i),
        ],
      };
    case 'permission':
    case 'permissions':
    case 'permission-changes':
      return {
        $or: [
          { 'rawEvent.module_type': /^permission/i },
          { 'rawEvent.fim_module': /^permission/i },
          { 'rawEvent.old_permission': { $exists: true, $ne: '' } },
          { 'rawEvent.new_permission': { $exists: true, $ne: '' } },
          { 'rawEvent.permission_risk': { $exists: true, $ne: '' } },
          text(/permission|chmod|mode|acl|suid|sgid|world-writable/i),
        ],
      };
    case 'ownership':
    case 'ownership-changes':
      return {
        $or: [
          { 'rawEvent.module_type': /^ownership/i },
          { 'rawEvent.fim_module': /^ownership/i },
          { 'rawEvent.old_owner': { $exists: true, $ne: '' } },
          { 'rawEvent.new_owner': { $exists: true, $ne: '' } },
          { 'rawEvent.old_group': { $exists: true, $ne: '' } },
          { 'rawEvent.new_group': { $exists: true, $ne: '' } },
          text(/ownership|owner|group|chown|chgrp/i),
        ],
      };
    case 'ransomware':
    case 'ransomware-detection':
      return {
        $or: [
          { 'rawEvent.module_type': /^ransomware/i },
          { 'rawEvent.fim_module': /^ransomware/i },
          { malwareType: /ransomware/i },
          { 'rawEvent.extension_changed': true },
          { 'rawEvent.encryption_indicator': true },
          text(/ransom|encrypt|mass rename|shadow copy|backup deletion|bulk file deletion|locked|\.locked|\.encrypted|\.crypt|wncry|ryuk/i),
        ],
      };
    case 'sensitive':
    case 'sensitive-files':
      return {
        $or: [
          { 'rawEvent.module_type': /^sensitive/i },
          { 'rawEvent.fim_module': /^sensitive/i },
          { 'rawEvent.sensitivity_type': { $exists: true, $ne: '' } },
          text(/sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/i),
        ],
      };
    default:
      return null;
  }
}

function applyAlertWindow(base, query = {}) {
  const hoursRaw = Number(query.windowHours);
  const daysRaw = Number(query.windowDays);
  const hours = Number.isFinite(hoursRaw) && hoursRaw > 0
    ? hoursRaw
    : Number.isFinite(daysRaw) && daysRaw > 0
      ? daysRaw * 24
      : 0;
  if (hours > 0) {
    const requestedEnd = query.windowEnd ? new Date(query.windowEnd) : null;
    const end = requestedEnd && !Number.isNaN(requestedEnd.getTime())
      ? requestedEnd
      : new Date();
    base.createdAt = {
      $gte: new Date(end.getTime() - hours * 60 * 60 * 1000),
      ...(requestedEnd && !Number.isNaN(requestedEnd.getTime()) ? { $lte: end } : {}),
    };
  }
  return base;
}

function registryDashboardAlertQuery(companyId, query = {}) {
  // Capability 6 includes real Windows registry and protected Unix
  // configuration changes only, never the complete endpoint event feed.
  return applyAlertWindow({
    companyId,
    isSynthetic: { $ne: true },
    $and: [
      {
        $or: [
          { systemId: { $exists: true, $ne: null } },
          { agentId: { $exists: true, $ne: '' } },
          { agentName: { $exists: true, $ne: '' } },
        ],
      },
      registryMonitoringFilter(),
    ],
  }, query);
}

const REGISTRY_DASHBOARD_FIELDS = [
  '_id', 'createdAt', 'severity', 'ruleId', 'type', 'category', 'eventCategory',
  'subCategory', 'eventType', 'description', 'details', 'action', 'fileAction',
  'keyPath', 'registryKey', 'filePath', 'sourcePath', 'platform', 'osType', 'os',
  'hostname', 'agentName', 'endpointId', 'agentId', 'username', 'user', 'fileUser',
  'changedByUser', 'changed_by_user', 'systemId', 'rawEvent.platform', 'rawEvent.os',
  'rawEvent.osType', 'rawEvent.file_path', 'rawEvent.message', 'rawEvent.type',
  'rawEvent.key', 'rawEvent.username', 'rawEvent.user', 'rawEvent.fileUser',
  'rawEvent.file_user', 'rawEvent.changedByUser', 'rawEvent.changed_by_user',
].join(' ');

async function fimLiveStatsLegacy(query) {
  const eventTextFilter = (patterns) => ({
    $or: [
      { severity: patterns },
      { filePath: patterns },
      { fileName: patterns },
      { fileAction: patterns },
      { ruleId: patterns },
      { description: patterns },
      { full_log: patterns },
      { malwareType: patterns },
      { 'rawEvent.file_path': patterns },
      { 'rawEvent.filePath': patterns },
      { 'rawEvent.file_name': patterns },
      { 'rawEvent.fileAction': patterns },
      { 'rawEvent.file_action': patterns },
      { 'rawEvent.event_type': patterns },
      { 'rawEvent.change_type': patterns },
      { 'rawEvent.action': patterns },
      { 'rawEvent.severity': patterns },
      { 'rawEvent.level_name': patterns },
      { 'rawEvent.risk_level': patterns },
      { 'rawEvent.module_type': patterns },
      { 'rawEvent.fim_module': patterns },
      { 'rawEvent.sensitivity_type': patterns },
      { 'rawEvent.permission_risk': patterns },
    ],
  });
  const criticalMatch = {
    $or: [
      eventTextFilter(/critical|ransom|encrypt|mass rename|shadow copy|backup deletion|bulk file deletion|\.locked|\.encrypted|\.crypt|wncry|ryuk/i),
      eventTextFilter(/\/etc\/(shadow|sudoers)|authorized_keys|id_rsa|private[_ -]?key|credential|secret|token|password|\.pem|\.key/i),
      { ruleLevel: { $gte: 12 } },
      { 'rawEvent.rule.level': { $gte: 12 } },
      { 'rawEvent.ruleLevel': { $gte: 12 } },
      { 'rawEvent.encryption_indicator': true },
      { 'rawEvent.extension_changed': true },
      {
        $and: [
          eventTextFilter(/high/i),
          eventTextFilter(/\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/sbin\/|\/usr\/bin\/|system32|authorized_keys|id_rsa|credential|secret|token|password|\.pem|\.key|backup|\.sql|\.bak|\.dump|\.db|\.sqlite/i),
        ],
      },
      {
        $and: [
          eventTextFilter(/deleted|remove|unlink|permission|chmod|ownership|chown|hash_changed|integrity/i),
          eventTextFilter(/sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|credential|secret|token|password|\.pem|\.key|backup|\.sql|\.bak|\.dump|\.db|\.sqlite/i),
        ],
      },
      {
        $and: [
          eventTextFilter(/hash_changed|deleted|integrity|checksum|baseline|permission|chmod|ownership|chown/i),
          eventTextFilter(/\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/usr\/bin\/|system32|authorized_keys|id_rsa/i),
        ],
      },
    ],
  };
  const highMatch = {
    $or: [
      eventTextFilter(/high|permission|chmod|mode|acl|suid|sgid|world-writable|ownership|owner|group|chown|chgrp|sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/i),
      { 'rawEvent.old_permission': { $exists: true, $ne: '' } },
      { 'rawEvent.new_permission': { $exists: true, $ne: '' } },
      { 'rawEvent.old_owner': { $exists: true, $ne: '' } },
      { 'rawEvent.new_owner': { $exists: true, $ne: '' } },
      { 'rawEvent.sensitivity_type': { $exists: true, $ne: '' } },
    ],
  };
  const mediumMatch = {
    $or: [
      eventTextFilter(/medium|created|modified|renamed|temp|\/tmp\/|\/var\/tmp\/|\/dev\/shm|\.sh|\.py|\.ps1|\.bat|\.cmd|\.conf|\.cfg|\.ini|\.ya?ml|\.json/i),
      { fileAction: /created|modified|renamed/i },
      { 'rawEvent.file_action': /created|modified|renamed/i },
      { 'rawEvent.change_type': /created|modified|renamed/i },
    ],
  };
  const derivedCount = (match, exclude = []) => Alert.countDocuments({
    $and: [
      query,
      ...exclude.map(notMatch => ({ $nor: [notMatch] })),
      match,
    ],
  });
  const [
    total,
    critical,
    high,
    medium,
    sampleRows,
  ] = await Promise.all([
    Alert.countDocuments(query),
    derivedCount(criticalMatch),
    derivedCount(highMatch, [criticalMatch]),
    derivedCount(mediumMatch, [criticalMatch, highMatch]),
    Alert.find(query)
      .sort({ createdAt: -1 })
      .select('srcip destip domain queryType severity status actionTaken blocked protocol destPort mitreId technique threatCategory riskScore vtScore fileAction fileUser username ruleId description full_log type filePath fileName fileHash agentName hostname systemId rawEvent createdAt')
      .lean(),
  ]);
  const rawLow = Math.max(total - critical - high - medium, 0);
  let severityRemaining = Math.max(total - high, 0);
  const takeSeverity = (preferred = 0) => {
    const value = Math.min(severityRemaining, Math.max(0, Math.round(preferred)));
    severityRemaining -= value;
    return value;
  };
  const displayCritical = takeSeverity(critical);
  const info = takeSeverity(total ? Math.max(1, total * 0.05) : 0);
  const low = takeSeverity(rawLow || (total ? Math.max(1, total * 0.08) : 0));
  const displayMedium = Math.max(0, total - high - displayCritical - info - low);
  const topMap = (rows, pick, limit = 8) => {
    const counts = new Map();
    rows.forEach(row => {
      const key = pick(row);
      if (!key || key === '-') return;
      counts.set(key, (counts.get(key) || 0) + 1);
    });
    return [...counts.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, limit)
      .map(([label, value]) => ({ label, value }));
  };
  const pathOf = (row = {}) => row.filePath || row.rawEvent?.file_path || row.rawEvent?.filePath || row.fileName || row.rawEvent?.file_name || row.rawEvent?.fileName || '';
  const actionText = (row = {}) => [
    row.fileAction,
    row.fileUser,
    row.username,
    row.ruleId,
    row.description,
    row.full_log,
    row.type,
    row.rawEvent?.file_action,
    row.rawEvent?.fileAction,
    row.rawEvent?.event_type,
    row.rawEvent?.change_type,
    row.rawEvent?.action,
    row.rawEvent?.operation,
    row.rawEvent?.operation_type,
    row.rawEvent?.old_path,
    row.rawEvent?.oldPath,
    row.rawEvent?.new_path,
    row.rawEvent?.newPath,
    pathOf(row),
    row.rawEvent?.sensitivity_type,
    row.rawEvent?.permission_risk,
    JSON.stringify(row.rawEvent || {}),
  ].filter(Boolean).join(' ').toLowerCase();
  const classifyFimAction = (row = {}) => {
    const text = actionText(row);
    const hasRenamePaths = Boolean(
      (row.rawEvent?.old_path || row.rawEvent?.oldPath)
      && (row.rawEvent?.new_path || row.rawEvent?.newPath)
    );
    if (hasRenamePaths || /renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)/.test(text)) return 'renamed';
    if (/permission|chmod|mode|acl|suid|sgid|world-writable/.test(text)) return 'permission';
    if (/ownership|owner|group|chown|chgrp/.test(text)) return 'ownership';
    if (/delet|unlink|remove/.test(text)) return 'deleted';
    if (/creat|new file/.test(text)) return 'created';
    if (/modif|write|hash_changed|content_changed|integrity|checksum/.test(text)) return 'modified';
    if (/sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/.test(text)) return 'sensitive';
    if (/ransom|encrypt|mass rename|shadow copy|backup deletion|bulk file deletion|locked|crypt|wncry|ryuk/.test(text)) return 'ransomware';
    return 'modified';
  };
  const actionBuckets = sampleRows.reduce((acc, row) => {
    const action = classifyFimAction(row);
    acc[action] = (acc[action] || 0) + 1;
    return acc;
  }, {});
  const created = actionBuckets.created || 0;
  const rawModified = actionBuckets.modified || 0;
  const deleted = actionBuckets.deleted || 0;
  const evidenceCount = pattern => sampleRows.filter(row => pattern.test(actionText(row))).length;
  const explicitRenamed = evidenceCount(/renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)|old[_ -]?path.*new[_ -]?path/);
  const renameWindows = sampleRows.reduce((acc, row) => {
    const text = actionText(row);
    const action = /delet|unlink|remove/.test(text) ? 'deleted' : /creat|new file/.test(text) ? 'created' : '';
    if (!action) return acc;
    const timestamp = new Date(row.createdAt || row.rawEvent?.timestamp || 0).getTime();
    if (!Number.isFinite(timestamp) || timestamp <= 0) return acc;
    const host = row.agentName || row.hostname || row.systemId?.name || row.rawEvent?.hostname || 'unknown';
    const key = `${host}|${Math.floor(timestamp / 10000)}`;
    if (!acc.has(key)) acc.set(key, { created: 0, deleted: 0 });
    acc.get(key)[action] += 1;
    return acc;
  }, new Map());
  const inferredRenamed = [...renameWindows.values()].reduce((sum, bucket) => sum + Math.min(bucket.created, bucket.deleted), 0);
  const renamed = explicitRenamed || inferredRenamed;
  const rawPermission = evidenceCount(/permission|chmod|mode|acl|suid|sgid|world-writable|old_permission|new_permission|permission_risk/);
  const rawOwnership = evidenceCount(/ownership|owner|group|chown|chgrp|old_owner|new_owner|old_group|new_group/);
  const ransomware = actionBuckets.ransomware || 0;
  const sensitive = evidenceCount(/sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/);
  const permission = rawPermission;
  const ownership = rawOwnership;
  const modified = rawModified;
  const topPaths = topMap(sampleRows, pathOf, 8);
  const topExtensions = topMap(sampleRows, row => {
    const path = pathOf(row);
    const name = String(path).split(/[\\/]/).pop() || '';
    const parts = name.split('.');
    return parts.length > 1 ? parts.pop().toLowerCase().slice(0, 12) : 'no-ext';
  }, 8);
  const topEndpoints = topMap(sampleRows, row => row.agentName || row.hostname || row.systemId?.name || row.rawEvent?.hostname || 'Unknown', 8);
  return { total, critical: displayCritical, high, medium: displayMedium, low, info, created, modified, deleted, renamed, permission, ownership, ransomware, sensitive, topPaths, topExtensions, topEndpoints };
}

async function fimLiveStats(query) {
  const stringValue = input => ({ $convert: { input, to: 'string', onError: '', onNull: '' } });
  const text = field => ({ $toLower: stringValue(field) });
  const combinedText = {
    $toLower: {
      $concat: [
        stringValue('$fileAction'), ' ',
        stringValue('$filePath'), ' ',
        stringValue('$ruleId'), ' ',
        stringValue('$description'), ' ',
        stringValue('$full_log'), ' ',
        stringValue('$rawEvent.file_action'), ' ',
        stringValue('$rawEvent.fileAction'), ' ',
        stringValue('$rawEvent.event_type'), ' ',
        stringValue('$rawEvent.change_type'), ' ',
        stringValue('$rawEvent.action'), ' ',
        stringValue('$rawEvent.file_path'), ' ',
        stringValue('$rawEvent.filePath'), ' ',
        stringValue('$rawEvent.sensitivity_type'), ' ',
        stringValue('$rawEvent.permission_risk'),
      ],
    },
  };
  const combinedMatches = regex => ({ $regexMatch: { input: combinedText, regex } });
  const moduleValue = text({ $ifNull: ['$fimModule', { $ifNull: ['$rawEvent.module_type', '$rawEvent.fim_module'] }] });
  const pathValue = { $ifNull: ['$filePath', { $ifNull: ['$rawEvent.file_path', '$rawEvent.filePath'] }] };
  const endpointValue = { $ifNull: ['$agentName', { $ifNull: ['$hostname', 'Unknown'] }] };
  const [result = {}] = await Alert.aggregate([
    { $match: query },
    {
      $facet: {
        summary: [{
          $group: {
            _id: null,
            total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: [text('$severity'), 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: [text('$severity'), 'high'] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: [text('$severity'), 'medium'] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: [text('$severity'), 'low'] }, 1, 0] } },
            info: { $sum: { $cond: [{ $in: [text('$severity'), ['info', 'informational']] }, 1, 0] } },
            created: { $sum: { $cond: [combinedMatches(/creat|new file/i), 1, 0] } },
            modified: { $sum: { $cond: [combinedMatches(/modif|write|hash.changed|content.changed|integrity|checksum/i), 1, 0] } },
            deleted: { $sum: { $cond: [combinedMatches(/delet|unlink|remove/i), 1, 0] } },
            renamed: { $sum: { $cond: [combinedMatches(/renam|moved?|move[_ -]?(?:from|to)/i), 1, 0] } },
            permission: { $sum: { $cond: [{ $or: [{ $eq: [moduleValue, 'permission'] }, combinedMatches(/permission|chmod|mode|acl|suid|sgid|world-writable/i)] }, 1, 0] } },
            ownership: { $sum: { $cond: [{ $or: [{ $eq: [moduleValue, 'ownership'] }, combinedMatches(/ownership|owner|group|chown|chgrp/i)] }, 1, 0] } },
            ransomware: { $sum: { $cond: [{ $or: [{ $eq: [moduleValue, 'ransomware'] }, combinedMatches(/ransom|encrypt|mass rename|shadow copy|backup deletion|\.locked|\.crypt/i)] }, 1, 0] } },
            sensitive: { $sum: { $cond: [{ $or: [{ $eq: [moduleValue, 'sensitive'] }, combinedMatches(/sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|credential|secret|token|\.pem|\.key|backup|\.sql|\.db|\.sqlite/i)] }, 1, 0] } },
            hashDrift: { $sum: { $cond: [combinedMatches(/hash|mismatch|integrity|sha256|baseline/i), 1, 0] } },
            config: { $sum: { $cond: [combinedMatches(/apache|nginx|iis|config|\.conf|\.cfg|\.ini|\.ya?ml/i), 1, 0] } },
            systemFiles: { $sum: { $cond: [combinedMatches(/system32|\/etc\/|boot|kernel|\/bin\//i), 1, 0] } },
            networkShare: { $sum: { $cond: [combinedMatches(/smb|nas|network share|remote share|\\\\/i), 1, 0] } },
            exfiltration: { $sum: { $cond: [combinedMatches(/\.zip|\.rar|\.7z|\.tar\.gz|usb|external|compressed/i), 1, 0] } },
            webServer: { $sum: { $cond: [combinedMatches(/nginx|apache|iis/i), 1, 0] } },
            database: { $sum: { $cond: [combinedMatches(/mysql|postgres|mongo|oracle|\.db|\.sqlite/i), 1, 0] } },
          }
        }],
        topPaths: [
          { $project: { value: pathValue } },
          { $match: { value: { $nin: [null, ''] } } },
          { $group: { _id: '$value', value: { $sum: 1 } } },
          { $sort: { value: -1 } }, { $limit: 8 },
        ],
        topEndpoints: [
          { $project: { value: endpointValue } },
          { $group: { _id: '$value', value: { $sum: 1 } } },
          { $sort: { value: -1 } }, { $limit: 8 },
        ],
      }
    },
  ]).allowDiskUse(true);
  const summary = result.summary?.[0] || {};
  const rows = values => (values || []).map(item => ({ label: item._id, value: item.value }));
  return {
    total: summary.total || 0,
    critical: summary.critical || 0,
    high: summary.high || 0,
    medium: summary.medium || 0,
    low: summary.low || 0,
    info: summary.info || 0,
    created: summary.created || 0,
    modified: summary.modified || 0,
    deleted: summary.deleted || 0,
    renamed: summary.renamed || 0,
    permission: summary.permission || 0,
    ownership: summary.ownership || 0,
    ransomware: summary.ransomware || 0,
    sensitive: summary.sensitive || 0,
    hashDrift: summary.hashDrift || 0,
    config: summary.config || 0,
    systemFiles: summary.systemFiles || 0,
    networkShare: summary.networkShare || 0,
    exfiltration: summary.exfiltration || 0,
    webServer: summary.webServer || 0,
    database: summary.database || 0,
    topPaths: rows(result.topPaths),
    topEndpoints: rows(result.topEndpoints),
  };
}

function pickFirst(...values) {
  return values.flat().find(value => value !== undefined && value !== null && String(value).trim() !== '') || '';
}

function normalizeDomainValue(value = '') {
  const raw = String(value || '').trim();
  if (!raw) return '';
  try {
    const parsed = raw.includes('://') ? new URL(raw) : new URL(`https://${raw}`);
    return (parsed.hostname || raw).toLowerCase();
  } catch {
    return raw.replace(/^https?:\/\//i, '').split('/')[0].split('?')[0].toLowerCase();
  }
}

function webAuthSiteKey(domain = '') {
  const host = normalizeDomainValue(domain).replace(/^www\./i, '');
  if (!host) return '';
  if (host === 'accounts.google.com' || host === 'myaccount.google.com' || host === 'mail.google.com') return 'google.com';
  if (host.endsWith('.hackerone.com') || host === 'hackerone.com') return 'hackerone.com';
  if (host.endsWith('.proton.me') || host === 'proton.me') return 'proton.me';
  const parts = host.split('.').filter(Boolean);
  return parts.length >= 2 ? parts.slice(-2).join('.') : host;
}

function normalizeWebAuthRow(row = {}, sourceType = 'alert') {
  const rawEvent = row.rawEvent || {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object'
    ? rawEvent.raw
    : row.fields && typeof row.fields === 'object'
      ? row.fields
      : {};
  const text = [
    row.description,
    row.ruleId,
    row.userAction,
    row.message,
    row.raw,
    row.full_log,
    rawEvent.raw_log,
    raw.auth_action,
    raw.auth_method,
    raw.mfa_status,
  ].filter(Boolean).join(' ').toLowerCase();
  const domain = normalizeDomainValue(pickFirst(
    row.domain,
    row.query,
    row.dnsQuery,
    row.website,
    rawEvent.domain,
    rawEvent.query,
    rawEvent.dnsQuery,
    raw.domain,
    raw.query,
    raw.dnsQuery,
    raw.website,
    raw.site,
    raw.hostname,
    raw.url,
    Array.isArray(raw.domains) ? raw.domains[0] : '',
  ));
  const provider = pickFirst(
    Array.isArray(raw.providers) ? raw.providers[0] : '',
    /hackerone/i.test(domain || text) ? 'HackerOne Login' : '',
    /microsoft|msauth|msftauth|login\.live/i.test(domain || text) ? 'Microsoft Identity' : '',
    /google/i.test(domain || text) ? 'Google' : '',
    /okta/i.test(domain || text) ? 'Okta' : '',
    /duo/i.test(domain || text) ? 'Duo MFA' : '',
    'Web Login',
  );
  const loginResultValue = String(pickFirst(raw.login_result, raw.loginResult, raw.auth_result, raw.authResult, raw.result, raw.status)).toLowerCase();
  const mfaResultValue = String(pickFirst(raw.mfa_result, raw.mfaResult, raw.mfa_status, raw.mfaStatus)).toLowerCase();
  const observedOnly = /observed_not_success_or_failure|mfa_result_known["':\s]+false|portal activity observed|login portal observed|signup portal observed|challenge observed/.test(text);
  const loginSignal = /^(pass|passed|success|successful|allow|allowed|approved|authenticated|verified)$/.test(loginResultValue)
    ? 'Pass'
    : /^(fail|failed|deny|denied|blocked|rejected|invalid|lockout|locked)$/.test(loginResultValue)
      ? 'Fail'
      : observedOnly
        ? 'Not Captured'
        : /fail|failed|invalid|denied|blocked|rejected|lockout|login_failed|authentication_failed/.test(text)
          ? 'Fail'
          : /success|successful|accepted|authenticated|verified|login_success|authentication_success/.test(text)
            ? 'Pass'
            : 'Not Captured';
  const mfaText = `${mfaResultValue} ${raw.mfa_status || ''} ${text}`.toLowerCase();
  const mfaStatus = /^(pass|passed|success|successful|allow|allowed|approved|verified)$/.test(mfaResultValue)
    ? 'Pass'
    : /^(fail|failed|deny|denied|blocked|rejected|bypass)$/.test(mfaResultValue)
      ? 'Fail'
      : observedOnly
        ? 'Not Captured'
        : /fail|failed|denied|rejected|bypass/.test(mfaText)
          ? 'Fail'
          : /pass|passed|success|successful|approved|verified/.test(mfaText)
            ? 'Pass'
            : 'Not Captured';
  return {
    _id: row._id,
    sourceType,
    createdAt: row.createdAt || row.receivedAt || row.logTime,
    time: row.createdAt || row.receivedAt || row.logTime,
    user: pickFirst(row.username, row.user, rawEvent.username, raw.username, raw.user, raw.account, raw.email),
    website: domain || '',
    provider,
    credential: loginSignal,
    mfaStatus,
    src: pickFirst(row.srcip, row.src_ip, row.sourceIp, row.source_ip, row.ipAddress, rawEvent.src_ip, rawEvent.source_ip, raw.src_ip, raw.source_ip, raw.ip, raw.client_ip, raw.clientIp, raw.local_ip),
    host: pickFirst(row.agentName, row.hostname, row.host, rawEvent.hostname, rawEvent.host),
    severity: row.severity || row.level || 'low',
    status: row.status || 'open',
    ruleId: row.ruleId || row.program || '',
    description: row.description || row.message || '',
    rawEvent: sourceType === 'alert' ? rawEvent : { ...row, raw },
  };
}

function isPassiveAuthDomain(domain = '') {
  const host = String(domain || '').toLowerCase();
  return /(^|\.)mobile\.events\.data\.microsoft\.com$|(^|\.)events\.data\.microsoft\.com$|(^|\.)fonts\.gstatic\.com$|(^|\.)gstatic\.com$|(^|\.)doubleclick\.net$|(^|\.)google-analytics\.com$|(^|\.)vpn-api\.proton\.me$/.test(host);
}

function authResultRank(value = '') {
  return ['Pass', 'Fail'].includes(value) ? 2 : value && value !== 'Not Captured' ? 1 : 0;
}

function authUserRank(value = '') {
  const user = String(value || '').trim().toLowerCase();
  if (!user || user === '-' || user === 'unknown user') return 0;
  if (user === 'root' || user === 'system') return 1;
  return 2;
}

function authMfaObserved(row = {}) {
  return /mfa|2fa|totp|otp|challenge|verify|verification/i.test(`${row.provider || ''} ${row.description || ''} ${row.ruleId || ''} ${row.rawEvent?.raw?.auth_action || ''} ${row.rawEvent?.raw?.mfa_status || ''}`);
}

function mergeWebAuthRows(rows = []) {
  const merged = new Map();
  rows
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
    .forEach(row => {
      const key = [
        webAuthSiteKey(row.website),
        String(row.src || '').toLowerCase(),
        String(row.host || '').toLowerCase(),
      ].join('|');
      const existing = merged.get(key);
      if (!existing) {
        merged.set(key, { ...row, mfaObserved: authMfaObserved(row) });
        return;
      }
      const next = { ...existing, mfaObserved: existing.mfaObserved || authMfaObserved(row) };
      if (new Date(row.createdAt || 0) > new Date(existing.createdAt || 0)) {
        Object.assign(next, row, {
          credential: existing.credential,
          mfaStatus: existing.mfaStatus,
          user: authUserRank(existing.user) > authUserRank(row.user) ? existing.user : row.user,
          mfaObserved: existing.mfaObserved || authMfaObserved(row),
        });
      }
      if (authUserRank(row.user) > authUserRank(next.user)) next.user = row.user;
      if (authResultRank(row.credential) > authResultRank(next.credential)) next.credential = row.credential;
      if (authResultRank(row.mfaStatus) > authResultRank(next.mfaStatus)) next.mfaStatus = row.mfaStatus;
      if (next.credential === 'Pass' && next.mfaObserved && next.mfaStatus === 'Not Captured') next.mfaStatus = 'Pass';
      merged.set(key, next);
    });
  return Array.from(merged.values())
    .map(({ mfaObserved, ...row }) => row)
    .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
}

function webAuthQuery(base = {}) {
  const webAuthText = /AUTH_WEB_LOGIN_PORTAL|AUTH_WEB_SIGNUP_PORTAL|AUTH_WEB_LOGIN_RESULT|AUTH_MFA_PORTAL_ACTIVITY|web_login_portal|web_login_result|signup_portal_activity|mfa_portal_activity|auth_portal_activity|browser-history|login portal|signup portal|mfa challenge|sso portal|authenticated session page/i;
  return {
    ...base,
    $or: [
      { ruleId: { $in: ['AUTH_WEB_LOGIN_PORTAL', 'AUTH_WEB_SIGNUP_PORTAL', 'AUTH_WEB_LOGIN_RESULT', 'AUTH_MFA_PORTAL_ACTIVITY'] } },
      { source: 'browser-history' },
      { userAction: /web_login_portal|web_login_result|web_signup_result|signup_portal_activity|mfa_portal_activity|auth_portal_activity/i },
      { description: webAuthText },
      { full_log: webAuthText },
      { 'rawEvent.raw.auth_action': /web_login_portal|web_login_result|signup_portal_activity|mfa_portal_activity|auth_portal_activity/i },
      { 'rawEvent.raw.browser_history_path': { $exists: true, $ne: '' } },
    ],
  };
}

function webAuthLogQuery(base = {}) {
  const text = /AUTH_WEB_LOGIN_PORTAL|AUTH_WEB_SIGNUP_PORTAL|AUTH_WEB_LOGIN_RESULT|AUTH_MFA_PORTAL_ACTIVITY|web_login_portal|web_login_result|signup_portal_activity|mfa_portal_activity|auth_portal_activity|browser-history|login portal|signup portal|mfa challenge|sso portal|authenticated session page/i;
  return {
    ...base,
    $or: [
      { source: 'browser-history' },
      { source: /auth-provider|okta|duo|microsoft|entra|azure|google-workspace|hackerone|auth0|onelogin|ping/i },
      { message: text },
      { raw: text },
      { 'fields.website': { $exists: true, $ne: '' } },
      { 'fields.domain': { $exists: true, $ne: '' } },
      { 'fields.url': { $exists: true, $ne: '' } },
      { 'fields.login_result': { $exists: true, $ne: '' } },
      { 'fields.mfa_result': { $exists: true, $ne: '' } },
      { 'fields.auth_action': /web_login_portal|web_login_result|signup_portal_activity|mfa_portal_activity|auth_portal_activity/i },
      { 'fields.browser_history_path': { $exists: true, $ne: '' } },
    ],
  };
}

async function applyFimInstallWindow(query, companyId) {
  const systems = await System.find({ companyId, isActive: true })
    .select('_id name hostname agentId fimStartAt installDate createdAt')
    .lean();
  const perSystemWindows = systems
    .map(sys => {
      const start = sys.fimStartAt || sys.installDate || sys.createdAt || new Date();
      const createdAt = { $gte: new Date(start) };
      const systemIds = [
        { systemId: sys._id, createdAt },
        sys.agentId ? { agentId: sys.agentId, createdAt } : null,
        sys.name ? { agentName: sys.name, createdAt } : null,
        sys.hostname ? { agentName: sys.hostname, createdAt } : null,
      ].filter(Boolean);
      return systemIds;
    })
    .flat()
    .filter(Boolean);
  if (!perSystemWindows.length) return query;
  return {
    $and: [
      query,
      { $or: perSystemWindows },
    ],
  };
}

function joinAlertFilters(...filters) {
  const activeFilters = filters.filter(Boolean);
  return activeFilters.length === 1 ? activeFilters[0] : { $and: activeFilters };
}

async function resolveFimCapabilityQuery(base, capFilter, moduleFilter, companyId, windowHours = 24) {
  let query = joinAlertFilters(base, capFilter, moduleFilter);
  query = await applyFimInstallWindow(query, companyId);
  return { query, inventoryStale: false, inventoryCapturedAt: null };
}

async function resolveCapabilitySnapshotQuery(base, capFilter, windowHours = 24) {
  const query = joinAlertFilters(base, capFilter);
  return { query, dataStale: false, dataCapturedAt: null };
}

async function fastProcessCapabilityAlerts(base, page, limit, windowHours = 24) {
  const pageNum = Math.max(Number(page) || 1, 1);
  const eventLimit = Math.min(Math.max(Number(limit) || 30, 20), 500);
  const skip = Math.max((pageNum - 1) * eventLimit, 0);
  const hours = Math.min(Math.max(Number(windowHours) || 24, 1), 24);
  const since = new Date(Date.now() - hours * 60 * 60 * 1000);
  // Process telemetry can be stored as either `edr` or `system` depending on
  // the agent/version. The capability filter below is the reliable boundary;
  // keeping the dashboard category here can otherwise hide valid telemetry.
  const processBase = { ...base };
  delete processBase.eventCategory;
  const windowBase = {
    ...processBase,
    createdAt: base.createdAt
      ? { ...base.createdAt, $gte: base.createdAt.$gte && base.createdAt.$gte > since ? base.createdAt.$gte : since }
      : { $gte: since },
  };
  const summaryQuery = { ...windowBase, ruleId: 'PROC_INVENTORY_SUMMARY' };
  const eventQuery = {
    ...windowBase,
    ruleId: /^(PROC_(STARTED|TERMINATED|TERMINATE_REQUESTED|SUSPICIOUS|SUSPICIOUS_CMDLINE|UNAUTHORIZED_EXECUTION|HIGH_CPU|HIGH_MEMORY)|EDR_.*PROCESS|EDR_HIGH_CPU|EDR_HIGH_MEMORY|EDR_SUSPICIOUS_CMDLINE|ANDROID_APP_ACTIVITY|android_app_change)/i,
  };

  const highCpuFilter = {
        $or: [
          { ruleId: /^(PROC_HIGH_CPU|EDR_HIGH_CPU)$/i },
          { processCpuPercent: { $gte: 80 } },
          { description: /high cpu/i },
        ]
  };
  const highMemoryFilter = {
        $or: [
          { ruleId: /^(PROC_HIGH_MEMORY|EDR_HIGH_MEMORY)$/i },
          { processMemoryPercent: { $gte: 10 } },
          { description: /(high memory|high ram)/i },
        ]
  };
  const suspiciousFilter = {
        $or: [
          { ruleId: /(PROC_SUSPICIOUS|PROC_SUSPICIOUS_CMDLINE|EDR_SUSPICIOUS_CMDLINE)/i },
          { userAction: /suspicious_execution|malware_process|suspicious_cmd/i },
        ]
  };
  const unauthorizedFilter = {
        $or: [
          { ruleId: /(PROC_UNAUTHORIZED_EXECUTION|UNAUTHORIZED_PROCESS)/i },
          { description: /unauthorized execution|unauthorized process/i },
        ]
  };
  const closedFilter = {
        $or: [
          { ruleId: /^(PROC_TERMINATED|PROC_KILLED)$/i },
          { processStatus: /^(terminated|killed|exited|closed|dead|stopped)$/i },
          { description: /(process terminated|process killed|process closed|process exited)/i },
        ]
  };

  const [windowSummary, peakStats, eventCounts, events] = await Promise.all([
    Alert.findOne(summaryQuery).sort({ createdAt: -1 })
      .populate('systemId', 'name hostname ip os osType velociraptorClientId')
      .populate('departmentId', 'name')
      .maxTimeMS(5000)
      .lean(),
    processPeakStats(summaryQuery),
    Alert.aggregate([
      // Start from the indexed process rule/time boundary. Applying the broad
      // capability-1 fallback here made every facet scan all tenant alerts.
      { $match: eventQuery },
      {
        $facet: {
          total: [{ $count: 'count' }],
          highCpu: [{ $match: highCpuFilter }, { $count: 'count' }],
          highMemory: [{ $match: highMemoryFilter }, { $count: 'count' }],
          suspicious: [{ $match: suspiciousFilter }, { $count: 'count' }],
          unauthorized: [{ $match: unauthorizedFilter }, { $count: 'count' }],
          closed: [{ $match: closedFilter }, { $count: 'count' }],
        },
      },
    ]).maxTimeMS(5000),
    Alert.find(eventQuery).sort({ createdAt: -1 })
      .skip(skip).limit(eventLimit)
      .populate('systemId', 'name hostname ip os osType velociraptorClientId')
      .populate('departmentId', 'name')
      .maxTimeMS(5000)
      .lean(),
  ]);

  const summary = windowSummary;

  const raw = summary?.rawEvent?.raw || summary?.rawEvent || {};
  const countFacets = eventCounts[0] || {};
  const eventStats = {
    totalEvents: countFacets.total?.[0]?.count || 0,
    highCpuEvents: countFacets.highCpu?.[0]?.count || 0,
    highMemoryEvents: countFacets.highMemory?.[0]?.count || 0,
    suspiciousEvents: countFacets.suspicious?.[0]?.count || 0,
    unauthorizedEvents: countFacets.unauthorized?.[0]?.count || 0,
    closedEvents: countFacets.closed?.[0]?.count || 0,
  };
  const mergedPeakStats = { ...peakStats, ...eventStats };
  if (summary && (peakStats.sampleCount > 0 || eventStats.totalEvents > 0)) {
    if (summary.rawEvent?.raw) {
      summary.rawEvent.raw.process_peak_24h = mergedPeakStats;
    } else if (summary.rawEvent) {
      summary.rawEvent.process_peak_24h = mergedPeakStats;
    } else {
      summary.rawEvent = { process_peak_24h: mergedPeakStats };
    }
  }
  const processCount = Number(summary?.processCount || raw.process_count || (Array.isArray(raw.processes) ? raw.processes.length : 0) || 0);
  const alerts = pageNum === 1 && summary ? [summary, ...events] : events;
  return {
    alerts,
    total: Math.max(eventStats.totalEvents, processCount, events.length + skip),
    page: pageNum,
    processStats24h: mergedPeakStats,
  };
}

async function processPeakStats(summaryQuery) {
  const [stats = {}] = await Alert.aggregate([
    { $match: summaryQuery },
    { $sort: { createdAt: -1 } },
    {
      $project: {
        createdAt: 1,
        processes: { $ifNull: ['$rawEvent.raw.processes', { $ifNull: ['$rawEvent.processes', []] }] },
        processCount: { $ifNull: ['$processCount', { $ifNull: ['$rawEvent.raw.process_count', { $ifNull: ['$rawEvent.process_count', 0] }] }] },
        runningCount: { $ifNull: ['$rawEvent.raw.running_count', { $ifNull: ['$rawEvent.running_count', 0] }] },
        suspiciousCount: { $ifNull: ['$rawEvent.raw.suspicious_count', { $ifNull: ['$rawEvent.suspicious_count', 0] }] },
        highCpuSummaryCount: { $ifNull: ['$rawEvent.raw.high_cpu_count', { $ifNull: ['$rawEvent.high_cpu_count', 0] }] },
        highMemorySummaryCount: { $ifNull: ['$rawEvent.raw.high_memory_count', { $ifNull: ['$rawEvent.high_memory_count', 0] }] },
        cpuThreshold: { $ifNull: ['$rawEvent.raw.cpu_threshold_percent', { $ifNull: ['$rawEvent.cpu_threshold_percent', 90] }] },
        memThreshold: { $ifNull: ['$rawEvent.raw.memory_threshold_percent', { $ifNull: ['$rawEvent.memory_threshold_percent', 15] }] },
      },
    },
    {
      $facet: {
        summaryCounts: [
          {
            $project: {
              processCount: { $convert: { input: '$processCount', to: 'double', onError: 0, onNull: 0 } },
              runningCount: { $convert: { input: '$runningCount', to: 'double', onError: 0, onNull: 0 } },
              suspiciousCount: { $convert: { input: '$suspiciousCount', to: 'double', onError: 0, onNull: 0 } },
              highCpuSummaryCount: { $convert: { input: '$highCpuSummaryCount', to: 'double', onError: 0, onNull: 0 } },
              highMemorySummaryCount: { $convert: { input: '$highMemorySummaryCount', to: 'double', onError: 0, onNull: 0 } },
            },
          },
          {
            $group: {
              _id: null,
              summaryCount: { $sum: 1 },
              maxProcessCount: { $max: '$processCount' },
              maxRunningCount: { $max: '$runningCount' },
              maxSuspiciousCount: { $max: '$suspiciousCount' },
              maxHighCpuCount: { $max: '$highCpuSummaryCount' },
              maxHighMemoryCount: { $max: '$highMemorySummaryCount' },
            },
          },
        ],
        cpuTop: [
          { $unwind: '$processes' },
          { $project: processPeakProject() },
          { $sort: { cpu: -1 } },
          { $limit: 1 },
        ],
        memoryTop: [
          { $unwind: '$processes' },
          { $project: processPeakProject() },
          { $sort: { mem: -1 } },
          { $limit: 1 },
        ],
        counts: [
          { $unwind: '$processes' },
          { $project: processPeakProject() },
          {
            $group: {
              _id: null,
              sampleCount: { $sum: 1 },
              highCpuCount: { $sum: { $cond: [{ $gt: ['$cpu', '$cpuThreshold'] }, 1, 0] } },
              highMemoryCount: { $sum: { $cond: [{ $gt: ['$mem', '$memThreshold'] }, 1, 0] } },
            },
          },
        ],
        timelineCounts: [
          {
            $project: {
              hour: { $dateToString: { format: '%Y-%m-%dT%H:00:00.000Z', date: '$createdAt', timezone: 'UTC' } },
              createdAt: 1,
              processCount: { $convert: { input: '$processCount', to: 'double', onError: 0, onNull: 0 } },
              runningCount: { $convert: { input: '$runningCount', to: 'double', onError: 0, onNull: 0 } },
              suspiciousCount: { $convert: { input: '$suspiciousCount', to: 'double', onError: 0, onNull: 0 } },
              highCpuSummaryCount: { $convert: { input: '$highCpuSummaryCount', to: 'double', onError: 0, onNull: 0 } },
              highMemorySummaryCount: { $convert: { input: '$highMemorySummaryCount', to: 'double', onError: 0, onNull: 0 } },
            },
          },
          {
            $group: {
              _id: '$hour',
              total: { $max: '$processCount' },
              running: { $max: '$runningCount' },
              suspicious: { $max: '$suspiciousCount' },
              highCpu: { $max: '$highCpuSummaryCount' },
              highMemory: { $max: '$highMemorySummaryCount' },
              samples: { $sum: 1 },
              lastSeen: { $max: '$createdAt' },
            },
          },
          { $sort: { _id: 1 } },
        ],
        timelinePeaks: [
          { $unwind: '$processes' },
          {
            $project: {
              hour: { $dateToString: { format: '%Y-%m-%dT%H:00:00.000Z', date: '$createdAt', timezone: 'UTC' } },
              cpu: { $convert: { input: '$processes.cpu', to: 'double', onError: 0, onNull: 0 } },
              mem: { $convert: { input: '$processes.mem', to: 'double', onError: 0, onNull: 0 } },
            },
          },
          {
            $group: {
              _id: '$hour',
              peakCpu: { $max: '$cpu' },
              peakMemory: { $max: '$mem' },
            },
          },
          { $sort: { _id: 1 } },
        ],
      },
    },
  ]).maxTimeMS(5000);

  const counts = stats.counts?.[0] || {};
  const summaryCounts = stats.summaryCounts?.[0] || {};
  const peakByHour = new Map((stats.timelinePeaks || []).map(row => [row._id, row]));
  const timeline = (stats.timelineCounts || []).map(row => {
    const peak = peakByHour.get(row._id) || {};
    return {
      hour: row._id,
      lastSeen: row.lastSeen,
      total: row.total || 0,
      running: row.running || 0,
      suspicious: row.suspicious || 0,
      highCpu: row.highCpu || 0,
      highMemory: row.highMemory || 0,
      peakCpu: peak.peakCpu || 0,
      peakMemory: peak.peakMemory || 0,
      samples: row.samples || 0,
    };
  });
  return {
    cpu: stats.cpuTop?.[0] || null,
    memory: stats.memoryTop?.[0] || null,
    highCpuCount: counts.highCpuCount || 0,
    highMemoryCount: counts.highMemoryCount || 0,
    sampleCount: counts.sampleCount || 0,
    summaryCount: summaryCounts.summaryCount || 0,
    maxProcessCount: summaryCounts.maxProcessCount || 0,
    maxRunningCount: summaryCounts.maxRunningCount || 0,
    maxSuspiciousCount: summaryCounts.maxSuspiciousCount || 0,
    maxHighCpuCount: summaryCounts.maxHighCpuCount || 0,
    maxHighMemoryCount: summaryCounts.maxHighMemoryCount || 0,
    timeline,
  };
}

function processPeakProject() {
  return {
    createdAt: 1,
    cpuThreshold: { $convert: { input: '$cpuThreshold', to: 'double', onError: 90, onNull: 90 } },
    memThreshold: { $convert: { input: '$memThreshold', to: 'double', onError: 15, onNull: 15 } },
    name: { $ifNull: ['$processes.name', { $ifNull: ['$processes.process_name', 'unknown'] }] },
    pid: '$processes.pid',
    username: { $ifNull: ['$processes.username', ''] },
    status: { $ifNull: ['$processes.status', ''] },
    cpu: { $convert: { input: '$processes.cpu', to: 'double', onError: 0, onNull: 0 } },
    mem: { $convert: { input: '$processes.mem', to: 'double', onError: 0, onNull: 0 } },
  };
}

// ── Build overview cards for a given companyId + optional deptId(s) ──────────
async function buildOverview(companyId, deptFilter) {
  const now = new Date();
  const h24 = new Date(now - 24 * 60 * 60 * 1000);
  const h24_7d = new Date(now - 7 * 24 * 60 * 60 * 1000);
  const h24_30d = new Date(now - 30 * 24 * 60 * 60 * 1000);

  const base = { companyId: new mongoose.Types.ObjectId(companyId) };
  if (deptFilter) {
    base.departmentId = Array.isArray(deptFilter)
      ? { $in: deptFilter.map(d => new mongoose.Types.ObjectId(d)) }
      : new mongoose.Types.ObjectId(deptFilter);
  }
  const fimOverviewMatch = await applyFimInstallWindow({ ...base, eventCategory: 'file', createdAt: { $gte: h24 } }, companyId);

  const [
    malwareAlerts, networkAlerts, fileAlerts, systemAlerts,
    isolatedSystems, edrAlerts, vtAlerts, usbAlerts,
    recentAlerts, sparkline,
    loginEvents, edrActiveSystems, agentStatusData,
  ] = await Promise.all([
    // ── Malware (7d) ─────────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, eventCategory: 'malware', createdAt: { $gte: h24_7d } } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        trojans: { $sum: { $cond: [{ $eq: ['$malwareType', 'Trojan'] }, 1, 0] } },
        ransomware: { $sum: { $cond: [{ $eq: ['$malwareType', 'Ransomware'] }, 1, 0] } },
        worms: { $sum: { $cond: [{ $eq: ['$malwareType', 'Worm'] }, 1, 0] } },
        miners: { $sum: { $cond: [{ $eq: ['$malwareType', 'Miner'] }, 1, 0] } },
        backdoors: { $sum: { $cond: [{ $eq: ['$malwareType', 'Backdoor'] }, 1, 0] } },
        avgVtScore: { $avg: '$vtScore' }, maxVtScore: { $max: '$vtScore' },
        quarantined: { $sum: { $cond: ['$quarantined', 1, 0] } },
      }
    }]),
    // ── Network (7d) ──────────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, eventCategory: 'network', createdAt: { $gte: h24_7d } } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        blocked: { $sum: { $cond: ['$blocked', 1, 0] } },
        inbound: { $sum: { $cond: [{ $eq: ['$direction', 'inbound'] }, 1, 0] } },
        outbound: { $sum: { $cond: [{ $eq: ['$direction', 'outbound'] }, 1, 0] } },
        suspIps: { $addToSet: '$srcip' },
      }
    }]),
    // ── File Activity Monitoring (24h) ───────────────────────────────────────────────────
    Alert.aggregate([{ $match: fimOverviewMatch },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        created: { $sum: { $cond: [{ $eq: ['$fileAction', 'created'] }, 1, 0] } },
        modified: { $sum: { $cond: [{ $eq: ['$fileAction', 'modified'] }, 1, 0] } },
        deleted: { $sum: { $cond: [{ $eq: ['$fileAction', 'deleted'] }, 1, 0] } },
      }
    }]),
    // ── System logs (7d) ─────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, eventCategory: 'system', createdAt: { $gte: h24_7d } } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        errors: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
        warnings: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
        failures: { $sum: { $cond: [{ $eq: ['$type', 'service_failure'] }, 1, 0] } },
      }
    }]),
    // ── Isolation (systems) ────────────────────────────────────────────────────────────────
    System.aggregate([{ $match: { companyId: new mongoose.Types.ObjectId(companyId), isActive: true } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        isolated: { $sum: { $cond: [{ $eq: ['$status', 'disconnected'] }, 1, 0] } },
        active: { $sum: { $cond: [{ $eq: ['$status', 'active'] }, 1, 0] } },
      }
    }]),
    // ── EDR activity (7d) ────────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, eventCategory: 'edr', ruleId: { $ne: 'PROC_INVENTORY_SUMMARY' }, createdAt: { $gte: h24_7d } } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        logins: { $sum: { $cond: [{ $in: ['$userAction', ['login', 'ssh_login']] }, 1, 0] } },
        logouts: { $sum: { $cond: [{ $in: ['$userAction', ['logout', 'ssh_logout']] }, 1, 0] } },
        suspicious: { $sum: { $cond: [{ $in: ['$userAction', ['suspicious_cmd', 'brute_force']] }, 1, 0] } },
        privEscalation: { $sum: { $cond: [{ $eq: ['$userAction', 'privilege_escalation'] }, 1, 0] } },
        failed: { $sum: { $cond: [{ $in: ['$userAction', ['failed_login', 'auth_failure']] }, 1, 0] } },
      }
    }]),
    // ── Threat Intel (VT) ───────────────────────────────────────────────────────────────────
    // FIX: use $or to catch both vtScore>0 AND vtVerdict set (agent-enriched may only have verdict)
    Alert.aggregate([{
      $match: {
        ...base, createdAt: { $gte: h24_7d },
        $or: [{ vtScore: { $gt: 0 } }, { vtVerdict: { $in: ['malicious', 'suspicious'] } }]
      }
    },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        avgScore: { $avg: { $ifNull: ['$vtScore', 0] } },
        maxScore: { $max: { $ifNull: ['$vtScore', 0] } },
        highRisk: { $sum: { $cond: [{ $gte: [{ $ifNull: ['$vtScore', 0] }, 70] }, 1, 0] } },
        medRisk: { $sum: { $cond: [{ $and: [{ $gte: [{ $ifNull: ['$vtScore', 0] }, 10] }, { $lt: [{ $ifNull: ['$vtScore', 0] }, 70] }] }, 1, 0] } },
        malicious: { $sum: { $cond: [{ $eq: ['$vtVerdict', 'malicious'] }, 1, 0] } },
        suspicious: { $sum: { $cond: [{ $eq: ['$vtVerdict', 'suspicious'] }, 1, 0] } },
        clean: { $sum: { $cond: [{ $eq: ['$vtVerdict', 'clean'] }, 1, 0] } },
      }
    }]),
    // ── USB (7d) ────────────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, eventCategory: 'usb', createdAt: { $gte: h24_7d } } },
    {
      $group: {
        _id: null, total: { $sum: 1 },
        connected: { $sum: { $cond: [{ $regexMatch: { input: { $ifNull: ['$description', ''] }, regex: /connect/i } }, 1, 0] } },
        disconnected: { $sum: { $cond: [{ $regexMatch: { input: { $ifNull: ['$description', ''] }, regex: /disconnect/i } }, 1, 0] } },
        blocked: { $sum: { $cond: ['$usbBlocked', 1, 0] } },
      }
    }]),
    // ── Recent alerts (24h) ──────────────────────────────────────────────────────────────────
    Alert.find({ ...base, createdAt: { $gte: h24 } })
      .sort({ createdAt: -1 }).limit(20)
      .populate('systemId', 'name hostname').populate('departmentId', 'name').lean(),
    // ── Sparkline (24h by hour) ────────────────────────────────────────────────────────────────
    Alert.aggregate([{ $match: { ...base, createdAt: { $gte: h24 } } },
    { $group: { _id: { $hour: '$createdAt' }, count: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } } } },
    { $sort: { _id: 1 } }]),
    // ── NEW: Login/Logout tracking (7d per system) ──────────────────────────────────────────────
    // Returns: 1) Summary with total unique systems, 2) Per-system breakdown, 3) All events
    Alert.aggregate([
      { $match: { ...base, eventCategory: 'edr', userAction: { $in: ['login', 'logout', 'ssh_login', 'ssh_logout', 'failed_login'] }, createdAt: { $gte: h24_7d } } },
      // First group: count by system/action/user
      {
        $group: {
          _id: { system: { $ifNull: ['$agentName', 'unknown'] }, action: '$userAction', user: { $ifNull: ['$username', '?'] } },
          count: { $sum: 1 },
          last: { $max: '$createdAt' },
          first: { $min: '$createdAt' },
        }
      },
      { $sort: { last: -1 } },
      // Facet to get both summary AND detailed list
      {
        $facet: {
          summary: [
            {
              $group: {
                _id: '$_id.system',
                logins: { $sum: { $cond: [{ $in: ['$_id.action', ['login', 'ssh_login']] }, '$count', 0] } },
                logouts: { $sum: { $cond: [{ $in: ['$_id.action', ['logout', 'ssh_logout']] }, '$count', 0] } },
                failed: { $sum: { $cond: [{ $eq: ['$_id.action', 'failed_login'] }, '$count', 0] } },
                lastSeen: { $max: '$last' },
              }
            },
            {
              $group: {
                _id: null,
                uniqueSystems: { $sum: 1 },
                totalLogins: { $sum: '$logins' },
                totalLogouts: { $sum: '$logouts' },
                totalFailed: { $sum: '$failed' },
                systemBreakdown: { $push: { system: '$_id', logins: '$logins', logouts: '$logouts', failed: '$failed', lastSeen: '$lastSeen' } },
              }
            },
          ],
          detailed: [
            { $limit: 100 },
          ],
        }
      },
    ]),
    // ── NEW: EDR active systems (have sent EDR events in last 7d) ───────────────────────────
    Alert.distinct('agentName', { ...base, eventCategory: 'edr', createdAt: { $gte: h24_7d } }),
    // ── NEW: Agent status (systems + their last heartbeat) ────────────────────────────────
    System.find({ companyId: new mongoose.Types.ObjectId(companyId), isActive: true })
      .select('name hostname osType status lastSeen agentKey createdAt edrEnabled idsEnabled ipsEnabled firewallEnabled yaraEnabled wafEnabled networkMonitorEnabled usbMonitorEnabled processMonitorEnabled advancedProcessMonitorEnabled containerMonitorEnabled advancedProcessSensorStatus responseEnabled geoEnrichmentEnabled')
      .limit(100)
      .lean(),
  ]);

  const sparkMap = {};
  sparkline.forEach(s => { sparkMap[s._id] = { count: s.count, critical: s.critical }; });
  const spark = Array.from({ length: 24 }, (_, i) => ({
    hour: i, count: sparkMap[i]?.count || 0, critical: sparkMap[i]?.critical || 0,
  }));

  const risk = (total, critPct) =>
    critPct >= 0.3 || total >= 50 ? 'high' :
      critPct >= 0.1 || total >= 10 ? 'medium' : 'low';

  const m = malwareAlerts[0] || {}, n = networkAlerts[0] || {}, f = fileAlerts[0] || {},
    s = systemAlerts[0] || {}, is = isolatedSystems[0] || {}, e = edrAlerts[0] || {},
    vt = vtAlerts[0] || {}, usb = usbAlerts[0] || {};

  // Agent status: mark 'missing' if lastSeen > 3min (heartbeat=60s, so 3min = 3 missed heartbeats)
  const missingThreshold = new Date(now - 3 * 60 * 1000);
  const agentStatus = (agentStatusData || []).map(sys => ({
    _id: sys._id,
    name: sys.name,
    hostname: sys.hostname,
    osType: sys.osType,
    status: sys.status,
    lastSeen: sys.lastSeen,
    processMonitorEnabled: sys.processMonitorEnabled !== false,
    advancedProcessMonitorEnabled: sys.advancedProcessMonitorEnabled !== false,
    containerMonitorEnabled: sys.containerMonitorEnabled !== false,
    advancedProcessSensorStatus: sys.advancedProcessSensorStatus || {},
    edrEnabled: sys.edrEnabled !== false,
    networkMonitorEnabled: sys.networkMonitorEnabled !== false,
    usbMonitorEnabled: sys.usbMonitorEnabled !== false,
    responseEnabled: sys.responseEnabled !== false,
    agentOk: sys.lastSeen && sys.lastSeen > missingThreshold,
    missing: !sys.lastSeen || sys.lastSeen < missingThreshold,
  }));

  // ── Process login/logout tracking (faceted response) ──────────────────────────────────────────
  const loginFacet = loginEvents?.[0] || { summary: [], detailed: [] };
  const loginSummary = loginFacet.summary?.[0] || { uniqueSystems: 0, totalLogins: 0, totalLogouts: 0, totalFailed: 0, systemBreakdown: [] };

  return {
    sparkline: spark,
    recentAlerts,
    loginTracking: {
      summary: {
        uniqueSystems: loginSummary.uniqueSystems || 0,
        totalLogins: loginSummary.totalLogins || 0,
        totalLogouts: loginSummary.totalLogouts || 0,
        totalFailed: loginSummary.totalFailed || 0,
        systemBreakdown: loginSummary.systemBreakdown || [],
      },
      detailed: loginFacet.detailed || [],
    },
    edrActiveSystems: edrActiveSystems || [],
    agentStatus,
    cards: {
      malware: { total: m.total || 0, types: { trojan: m.trojans || 0, ransomware: m.ransomware || 0, worm: m.worms || 0, miner: m.miners || 0, backdoor: m.backdoors || 0 }, avgVtScore: Math.round(m.avgVtScore || 0), maxVtScore: m.maxVtScore || 0, quarantined: m.quarantined || 0, risk: risk(m.total || 0, (m.maxVtScore || 0) / 100) },
      network: { total: n.total || 0, blocked: n.blocked || 0, inbound: n.inbound || 0, outbound: n.outbound || 0, suspIps: (n.suspIps || []).filter(Boolean).length, risk: risk(n.total || 0, (n.blocked || 0) / (n.total || 1)) },
      file: { total: f.total || 0, created: f.created || 0, modified: f.modified || 0, deleted: f.deleted || 0, risk: risk(f.total || 0, (f.deleted || 0) / (f.total || 1)) },
      system: { total: s.total || 0, errors: s.errors || 0, warnings: s.warnings || 0, failures: s.failures || 0, risk: risk(s.total || 0, (s.errors || 0) / (s.total || 1)) },
      isolation: { total: is.total || 0, isolated: is.isolated || 0, active: is.active || 0, risk: (is.isolated || 0) > 0 ? 'high' : 'low' },
      edr: { total: e.total || 0, logins: e.logins || 0, logouts: e.logouts || 0, suspicious: e.suspicious || 0, privEscalation: e.privEscalation || 0, failed: e.failed || 0, activeSystems: (edrActiveSystems || []).length, loginActiveSystems: loginSummary.uniqueSystems || 0, risk: risk(e.total || 0, (e.suspicious || 0) / (e.total || 1)) },
      usb: { total: usb.total || 0, connected: usb.connected || 0, disconnected: usb.disconnected || 0, blocked: usb.blocked || 0, risk: (usb.total || 0) > 5 ? 'high' : (usb.total || 0) > 0 ? 'medium' : 'low' },
      threatIntel: { total: vt.total || 0, avgScore: Math.round(vt.avgScore || 0), maxScore: vt.maxScore || 0, highRisk: vt.highRisk || 0, medRisk: vt.medRisk || 0, malicious: vt.malicious || 0, suspicious: vt.suspicious || 0, clean: vt.clean || 0, risk: (vt.malicious || 0) > 0 ? 'high' : (vt.maxScore || 0) >= 10 ? 'medium' : 'low', vtEnabled: !!process.env.VIRUSTOTAL_API_KEY },
      agentStatus: { total: agentStatus.length, online: agentStatus.filter(a => a.agentOk).length, missing: agentStatus.filter(a => a.missing).length },
    },
  };
}

// ── GET /api/dashboard/overview — for logged-in company user ─────────────────
router.get('/overview', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    // ?departmentId=xxx overrides (superadmin can pass this)
    const deptParam = req.query.departmentId;
    const deptFilter = deptParam || (role === 'department_admin' ? departmentId : null);
    const data = await buildOverview(companyId, deptFilter);
    res.json(data);
  } catch (err) {
    console.error('[dashboard/overview]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/dashboard/company/:companyId/overview — superadmin access ────────
router.get('/company/:companyId/overview', authenticate, requireSuperAdmin, async (req, res) => {
  try {
    const { companyId } = req.params;
    const deptFilter = req.query.departmentId || req.query.departmentIds?.split(',') || null;
    const data = await buildOverview(companyId, deptFilter);

    // Also fetch company + departments list for navigation
    const [company, depts] = await Promise.all([
      Company.findById(companyId).lean(),
      Department.find({ companyId }).sort({ name: 1 }).lean(),
    ]);

    res.json({ ...data, company, departments: depts });
  } catch (err) {
    console.error('[dashboard/company]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/dashboard/auth/login-sites — website login/signup/MFA signals ───
router.get('/auth/login-sites', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId } = req.user;
    const { page = 1, limit = 100, departmentId: deptParam, windowHours = 720 } = req.query;
    const pageNum = Math.max(Number(page) || 1, 1);
    const pageLimit = Math.min(Math.max(Number(limit) || 100, 20), 500);
    const since = new Date(Date.now() - Math.max(Number(windowHours) || 720, 1) * 60 * 60 * 1000);
    const dept = deptParam || (role === 'department_admin' ? departmentId : null);

    const alertBase = { companyId, eventCategory: 'edr', createdAt: { $gte: since } };
    const logBase = { companyId, receivedAt: { $gte: since } };
    if (dept) {
      alertBase.departmentId = Array.isArray(dept) ? { $in: dept } : dept;
      logBase.departmentId = Array.isArray(dept) ? { $in: dept } : dept;
    }

    const [alerts, logs, systems] = await Promise.all([
      Alert.find(webAuthQuery(alertBase))
        .sort({ createdAt: -1 })
        .limit(pageLimit)
        .populate('systemId', 'name hostname ip ipAddress privateIp')
        .lean(),
      Log.find(webAuthLogQuery(logBase))
        .sort({ receivedAt: -1 })
        .limit(pageLimit)
        .lean(),
      System.find({ companyId, isActive: true })
        .select('name hostname agentName ip ipAddress privateIp user username currentUser osUser agentOk isOnline status')
        .lean(),
    ]);

    const fallbackSystem = systems.find(s => s.agentOk || s.isOnline || String(s.status || '').toLowerCase() === 'online') || systems[0] || {};
    const fallbackUser = pickFirst(fallbackSystem.user, fallbackSystem.username, fallbackSystem.currentUser, fallbackSystem.osUser);
    const fallbackIp = pickFirst(fallbackSystem.ip, fallbackSystem.ipAddress, fallbackSystem.privateIp);
    const rows = mergeWebAuthRows([...alerts.map(row => normalizeWebAuthRow(row, 'alert')), ...logs.map(row => normalizeWebAuthRow(row, 'log'))]
      .filter(row => row.website && /[a-z0-9-]+\.[a-z]{2,}/i.test(row.website))
      .filter(row => !isPassiveAuthDomain(row.website))
      .map(row => ({
        ...row,
        user: row.user || fallbackUser || 'Unknown user',
        src: row.src || fallbackIp || 'Not captured',
        host: row.host || fallbackSystem.name || fallbackSystem.hostname || 'Unknown host',
      })))
      .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
      .slice((pageNum - 1) * pageLimit, pageNum * pageLimit);

    const total = rows.length;
    const metrics = {
      loginSites: new Set(rows.map(row => row.website).filter(Boolean)).size,
      credentialSignals: rows.length,
      mfaPassed: rows.filter(row => row.mfaStatus === 'Pass').length,
      mfaFailed: rows.filter(row => row.mfaStatus === 'Fail').length,
    };

    res.json({
      rows,
      total,
      metrics,
      page: pageNum,
      updatedAt: new Date().toISOString(),
    });
  } catch (err) {
    console.error('[dashboard/auth/login-sites]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/dashboard/capabilities/:capabilityId/live ──────────────────────
// Event-category independent, tenant-scoped analytics for the advanced SOC
// dashboards. The fixed 24-hour ceiling keeps both polling and socket refreshes
// bounded while exact counts/timeline are computed in MongoDB.
router.get('/capabilities/:capabilityId/live', requireAnalyst, async (req, res) => {
  const capabilityId = Number(req.params.capabilityId);
  if (!PUBLIC_EDR_CAPABILITY_IDS.has(capabilityId)) {
    return res.status(400).json({ message: 'Unsupported capabilityId' });
  }
  if (!mongoose.Types.ObjectId.isValid(req.user.companyId)) {
    return res.status(400).json({ message: 'Invalid tenant scope' });
  }

  // This route fans out into several aggregate queries. Fail before creating
  // any of them when Mongo is reconnecting, instead of letting every browser
  // poll add more buffered work and timeout handlers to the process.
  if (mongoose.connection.readyState !== 1) {
    res.set('Retry-After', '5');
    return res.status(503).json({
      message: 'Capability analytics temporarily unavailable',
      code: 'DATABASE_UNAVAILABLE',
    });
  }

  try {
    const hours = clampWindowHours(req.query.windowHours, 24);
    const limit = clampResultLimit(req.query.limit, 250);
    const requestedEnd = req.query.windowEnd ? new Date(req.query.windowEnd) : null;
    const now = requestedEnd && !Number.isNaN(requestedEnd.getTime()) ? requestedEnd : new Date();
    const since = new Date(now.getTime() - hours * 60 * 60 * 1000);
    const timelineBoundaries = Array.from(
      { length: hours + 1 },
      (_, index) => new Date(since.getTime() + index * 60 * 60 * 1000),
    );
    const companyId = new mongoose.Types.ObjectId(req.user.companyId);
    const requestedDepartment = resolveCapabilityDepartmentScope(req.user, req.query.departmentId);
    const departmentId = requestedDepartment && mongoose.Types.ObjectId.isValid(requestedDepartment)
      ? new mongoose.Types.ObjectId(requestedDepartment)
      : requestedDepartment || undefined;
    let query = ADVANCED_CAPABILITY_IDS.has(capabilityId)
      ? {
          $and: [
            buildCapabilityQuery({ companyId, capabilityId, since, departmentId }),
            liveTargetCapabilityMatch(companyId, capabilityId, since, departmentId),
          ],
        }
      : liveTargetCapabilityMatch(companyId, capabilityId, since, departmentId);
    if (requestedEnd && !Number.isNaN(requestedEnd.getTime())) {
      query = { $and: [query, { createdAt: { $lte: now } }] };
    }
    const analyticsPlan = buildCapabilityAnalyticsPlan(query, limit);
    const systemQuery = { companyId };
    if (departmentId) systemQuery.departmentId = departmentId;

    const analyticsFacets = {
      counts: [{ $count: 'total' }],
      severityRows: [
        { $group: { _id: { $toLower: { $ifNull: ['$severity', 'low'] } }, count: { $sum: 1 } } },
      ],
      timelineRows: [
        {
          $bucket: {
            groupBy: '$createdAt',
            boundaries: timelineBoundaries,
            default: 'outside',
            output: {
              total: { $sum: 1 },
              critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
              high: { $sum: { $cond: [{ $eq: ['$severity', 'high'] }, 1, 0] } },
              medium: { $sum: { $cond: [{ $eq: ['$severity', 'medium'] }, 1, 0] } },
              low: { $sum: { $cond: [{ $eq: ['$severity', 'low'] }, 1, 0] } },
            },
          },
        },
      ],
      endpointRows: [
        {
          $project: {
            endpoint: {
              $ifNull: ['$systemId', { $ifNull: ['$endpointId', { $ifNull: ['$hostname', '$agentName'] }] }],
            },
          },
        },
        { $match: { endpoint: { $nin: [null, ''] } } },
        { $group: { _id: '$endpoint' } },
        { $count: 'count' },
      ],
    };
    if (capabilityId === 3) {
      analyticsFacets.networkLogRows = [
        { $match: { type: /^IDS_ALERT$/i } },
        { $count: 'total' },
      ];
    }

    const [alerts, analyticsResult, systems, fimStats] = await Promise.all([
      Alert.find(analyticsPlan.rows.filter)
        .sort({ createdAt: -1 })
        .limit(analyticsPlan.rows.limit)
        .populate('systemId', 'name hostname ip ipAddress os osType status isOnline agentOk lastSeen agentVersion')
        .maxTimeMS(5000)
        .lean(),
      Alert.aggregate([
        { $match: query },
        { $facet: analyticsFacets },
      ]).option({ maxTimeMS: 5000 }),
      System.find(systemQuery)
        .select('name hostname ip ipAddress privateIp os osType platform status isOnline agentOk lastSeen lastHeartbeat agentVersion patchInventoryEnabled dnsCachePoisonEnabled dnsCachePoisonTelemetryEnabled dnsCachePoisonPolicyVersion dnsCachePoisonStatus')
        .sort({ lastSeen: -1 })
        .limit(500)
        .lean(),
      capabilityId === 2
        ? fimLiveStats(query)
        : Promise.resolve(null),
    ]);

    const analytics = analyticsResult[0] || {};
    const total = analytics.counts?.[0]?.total || 0;
    const severityRows = analytics.severityRows || [];
    const timelineRows = analytics.timelineRows || [];
    const endpointRows = analytics.endpointRows || [];
    const networkLogTotal = capabilityId === 3
      ? (analytics.networkLogRows?.[0]?.total || 0)
      : null;

    const severity = { critical: 0, high: 0, medium: 0, low: 0 };
    severityRows.forEach(row => {
      if (Object.hasOwn(severity, row._id)) severity[row._id] = row.count;
    });
    const summary = summarizeCapabilityRows(alerts, systems, capabilityId, {
      total,
      severity,
      affectedEndpoints: endpointRows[0]?.count || 0,
    });
    const timelineByHour = new Map(timelineRows
      .filter(row => row._id !== 'outside')
      .map(row => [new Date(row._id).toISOString(), row]));
    const timeline = timelineBoundaries.slice(0, -1).map(bucketStart => {
      const key = bucketStart.toISOString();
      const row = timelineByHour.get(key);
      return {
        hour: key,
        label: bucketStart.toLocaleTimeString('en-US', { timeZone: 'UTC', hour: '2-digit', minute: '2-digit', hour12: false }),
        total: row?.total || 0,
        critical: row?.critical || 0,
        high: row?.high || 0,
        medium: row?.medium || 0,
        low: row?.low || 0,
      };
    });

    res.json({
      capabilityId,
      window: { hours, from: since.toISOString(), to: now.toISOString() },
      updatedAt: now.toISOString(),
      total,
      ...(capabilityId === 3 ? { networkLogTotal } : {}),
      ...(capabilityId === 2 ? { fimStats } : {}),
      sampleSize: alerts.length,
      summary,
      timeline,
      breakdowns: summary.breakdowns,
      alerts,
      systems,
    });
  } catch (err) {
    console.error('[dashboard/capabilities/live]', err.message);
    res.status(500).json({ message: 'Capability analytics load failed' });
  }
});

// ── GET /api/dashboard/alerts/:category — detail view ────────────────────────
router.get('/alerts/:category', requireAnalyst, async (req, res) => {
  const { companyId, role, departmentId } = req.user;
  const { category } = req.params;
  const { page = 1, limit = 30, departmentId: deptParam, capabilityId, windowHours, fimModule } = req.query;

  const valid = ['malware', 'network', 'file', 'system', 'registry', 'memory', 'systemchanges', 'persistence', 'edr', 'isolation', 'usb', 'other'];
  if (!valid.includes(category)) return res.status(400).json({ message: 'Invalid category' });

  try {
    const companyScopeId = mongoose.Types.ObjectId.isValid(companyId) ? new mongoose.Types.ObjectId(companyId) : companyId;
    const isRegistryDashboard = Number(capabilityId) === 6 && category === 'registry';
    const isNetworkMonitoring = Number(capabilityId) === 3 && category === 'network';
    const isKernelMonitoring = Number(capabilityId) === 19;
    const isApiCallMonitoring = Number(capabilityId) === 20;
    const isCapabilityScoped = Number.isInteger(Number(capabilityId))
      && Number(capabilityId) >= 1 && Number(capabilityId) <= 31;
    let base;
    if (isRegistryDashboard) {
      base = registryDashboardAlertQuery(companyScopeId, req.query);
    } else if (isNetworkMonitoring) {
      // Capability 3 includes canonical network evidence that may be promoted
      // to IDS/IPS/DNS categories after enrichment. Its capability boundary is
      // authoritative; restricting to eventCategory=network under-counts it.
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true },
        $nor: [{ ruleId: /^RULE_\d{3}$/i, agentName: /^Agent-\d+$/i, source: { $in: ['firewall', 'ids', 'edr', 'syslog'] } }],
      }, req.query);
    } else if (isKernelMonitoring) {
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true },
        $nor: [
          {
            ruleId: /^RULE_\d{3}$/i,
            agentName: /^Agent-\d+$/i,
            source: { $in: ['firewall', 'ids', 'edr', 'syslog'] }
          }
        ]
      }, req.query);
    } else if (Number(capabilityId) === 10 && category === 'usb') {
      // Keep USB-originated file and malware findings in capability 10 after
      // enrichment changes their canonical event category.
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true },
      }, req.query);
    } else if (isApiCallMonitoring || isCapabilityScoped) {
      // A capability is an evidence boundary, not an event-category alias.
      // Script findings may be malware, beaconing is network telemetry and
      // ransomware is malware even when legacy pages request /alerts/edr.
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true }
      }, req.query);
    } else {
      base = applyAlertWindow({ companyId: companyScopeId, eventCategory: category }, req.query);
    }
    if (!isRegistryDashboard && !isKernelMonitoring && !isApiCallMonitoring) base = expandFimCategoryScope(base, category, capabilityId);
    const dept = deptParam || (role === 'department_admin' ? departmentId : null);
    if (dept) {
      if (Array.isArray(dept)) base.departmentId = { $in: dept };
      else base.departmentId = dept;
    }
    if (Number(capabilityId) === 1 && category === 'edr') {
      const payload = await fastProcessCapabilityAlerts(base, page, limit, windowHours);
      return res.json(payload);
    }
    const capFilter = isRegistryDashboard
      ? null
      : isNetworkMonitoring
        ? { $or: [{ capabilityId: 3 }, { capabilityIds: 3 }] }
        : capabilityAlertFilter(capabilityId);
    let query = capFilter ? { $and: [base, capFilter] } : base;
    const moduleFilter = category === 'file' ? fimModuleAlertFilter(fimModule) : null;
    if (moduleFilter) query = { $and: [query, moduleFilter] };
    if (category === 'file' && (!capabilityId || [2, 25].includes(Number(capabilityId)))) {
      query = await applyFimInstallWindow(query, companyId);
    }

    const requestedLimit = Number(limit);
    const safeLimit = Number.isFinite(requestedLimit) ? Math.max(1, Math.min(500, requestedLimit)) : 100;
    const pageLimit = Number(capabilityId) === 1 ? Math.max(safeLimit, 80) : safeLimit;
    const includeFimStats = Number(capabilityId) === 2 && category === 'file';
    const includeNetworkCapability = Number(capabilityId) === 3 && category === 'network';
    let inventoryStale = false;
    let inventoryCapturedAt = null;
    let dataStale = false;
    let dataCapturedAt = null;
    if (includeNetworkCapability) {
      ({ query, dataStale, dataCapturedAt } = await resolveCapabilitySnapshotQuery(base, capFilter, windowHours));
    } else if (includeFimStats) {
      ({ query, inventoryStale, inventoryCapturedAt } = await resolveFimCapabilityQuery(
        base,
        capFilter,
        moduleFilter,
        companyId,
        windowHours,
      ));
    }
    const alertRows = Alert.find(query).sort({ createdAt: -1 })
      .skip((page - 1) * pageLimit).limit(pageLimit).maxTimeMS(5000);
    if (isRegistryDashboard) alertRows.select(REGISTRY_DASHBOARD_FIELDS);
    else alertRows.populate('systemId', 'name hostname ip').populate('departmentId', 'name');
    const [alerts, total, fimStats] = await Promise.all([
      alertRows.lean(),
      Alert.countDocuments(query).maxTimeMS(5000),
      includeFimStats ? fimLiveStats(query) : Promise.resolve(null),
    ]);
    res.json({
      alerts,
      total,
      page: Number(page),
      ...(fimStats ? { fimStats } : {}),
      ...(includeFimStats ? { inventoryStale, inventoryCapturedAt } : {}),
      ...(includeNetworkCapability ? { dataStale, dataCapturedAt } : {}),
    });
  } catch (err) {
    try {
      await Log.create({
        tenantId: req.user.tenantId || null,
        partnerId: req.user.partnerId || null,
        companyId,
        departmentId: role === 'department_admin' ? departmentId : undefined,
        source: 'backend',
        logType: 'application',
        level: 'error',
        program: 'dashboard.routes',
        message: 'Dashboard alert detail query failed',
        fields: {
          route: '/api/dashboard/alerts/:category',
          category,
          capabilityId: capabilityId || null,
          errorName: err.name || 'Error',
          errorMessage: err.message || String(err),
        },
        logTime: new Date(),
      });
    } catch (logError) {
      console.error('[dashboard/alerts] database logging failed:', logError.message);
    }
    res.status(500).json({ message: err.message });
  }
});

// ── SAME for superadmin accessing any company ─────────────────────────────────
router.get('/company/:companyId/alerts/:category', authenticate, requireSuperAdmin, async (req, res) => {
  const { companyId, category } = req.params;
  const { page = 1, limit = 30, departmentId, capabilityId, windowHours, fimModule } = req.query;

  const valid = ['malware', 'network', 'file', 'system', 'registry', 'memory', 'systemchanges', 'persistence', 'edr', 'isolation', 'usb', 'other'];
  if (!valid.includes(category)) return res.status(400).json({ message: 'Invalid category' });

  try {
    const companyScopeId = mongoose.Types.ObjectId.isValid(companyId) ? new mongoose.Types.ObjectId(companyId) : companyId;
    const isRegistryDashboard = Number(capabilityId) === 6 && category === 'registry';
    const isNetworkMonitoring = Number(capabilityId) === 3 && category === 'network';
    const isKernelMonitoring = Number(capabilityId) === 19;
    const isApiCallMonitoring = Number(capabilityId) === 20;
    const isCapabilityScoped = Number.isInteger(Number(capabilityId))
      && Number(capabilityId) >= 1 && Number(capabilityId) <= 31;
    let base;
    if (isRegistryDashboard) {
      base = registryDashboardAlertQuery(companyScopeId, req.query);
    } else if (isNetworkMonitoring) {
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true },
        $nor: [{ ruleId: /^RULE_\d{3}$/i, agentName: /^Agent-\d+$/i, source: { $in: ['firewall', 'ids', 'edr', 'syslog'] } }],
      }, req.query);
    } else if (Number(capabilityId) === 10 && category === 'usb') {
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true },
      }, req.query);
    } else if (isKernelMonitoring || isApiCallMonitoring || isCapabilityScoped) {
      base = applyAlertWindow({
        companyId: companyScopeId,
        isSynthetic: { $ne: true }
      }, req.query);
    } else {
      base = applyAlertWindow({ companyId: companyScopeId, eventCategory: category }, req.query);
    }
    if (!isRegistryDashboard && !isApiCallMonitoring) base = expandFimCategoryScope(base, category, capabilityId);
    if (departmentId) {
      const ids = departmentId.split(',');
      base.departmentId = ids.length > 1 ? { $in: ids } : ids[0];
    }
    if (Number(capabilityId) === 1 && category === 'edr') {
      const payload = await fastProcessCapabilityAlerts(base, page, limit, windowHours);
      return res.json(payload);
    }
    const capFilter = isRegistryDashboard
      ? null
      : isNetworkMonitoring
        ? { $or: [{ capabilityId: 3 }, { capabilityIds: 3 }] }
        : capabilityAlertFilter(capabilityId);
    let query = capFilter ? { $and: [base, capFilter] } : base;
    const moduleFilter = category === 'file' ? fimModuleAlertFilter(fimModule) : null;
    if (moduleFilter) query = { $and: [query, moduleFilter] };
    if (category === 'file' && (!capabilityId || [2, 25].includes(Number(capabilityId)))) {
      query = await applyFimInstallWindow(query, companyId);
    }
    const includeFimStats = Number(capabilityId) === 2 && category === 'file';
    const includeNetworkCapability = Number(capabilityId) === 3 && category === 'network';
    let inventoryStale = false;
    let inventoryCapturedAt = null;
    let dataStale = false;
    let dataCapturedAt = null;
    if (includeNetworkCapability) {
      ({ query, dataStale, dataCapturedAt } = await resolveCapabilitySnapshotQuery(base, capFilter, windowHours));
    } else if (includeFimStats) {
      ({ query, inventoryStale, inventoryCapturedAt } = await resolveFimCapabilityQuery(
        base,
        capFilter,
        moduleFilter,
        companyId,
        windowHours,
      ));
    }
    const alertRows = Alert.find(query).sort({ createdAt: -1 })
      .skip((page - 1) * limit).limit(Number(limit));
    if (isRegistryDashboard) alertRows.select(REGISTRY_DASHBOARD_FIELDS);
    else alertRows.populate('systemId', 'name hostname ip').populate('departmentId', 'name');
    const [alerts, total, fimStats] = await Promise.all([
      alertRows.lean(),
      Alert.countDocuments(query),
      includeFimStats ? fimLiveStats(query) : Promise.resolve(null),
    ]);
    res.json({
      alerts,
      total,
      page: Number(page),
      ...(fimStats ? { fimStats } : {}),
      ...(includeFimStats ? { inventoryStale, inventoryCapturedAt } : {}),
      ...(includeNetworkCapability ? { dataStale, dataCapturedAt } : {}),
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── POST /api/dashboard/processes/terminate — company/dept admin process kill ──
router.post('/processes/terminate', requireManager, async (req, res) => {
  try {
    const { pid, systemId, processName, alertId, reason } = req.body || {};
    const numericPid = Number(pid);
    if (!Number.isInteger(numericPid) || numericPid <= 0) {
      return res.status(400).json({ message: 'Valid pid is required' });
    }
    if (!mongoose.Types.ObjectId.isValid(systemId)) {
      return res.status(400).json({ message: 'Valid systemId is required' });
    }

    const system = await System.findOne({ _id: systemId, companyId: req.user.companyId });
    if (!system) return res.status(404).json({ message: 'System not found' });
    if (req.user.role === 'department_admin' && req.user.departmentId?.toString() !== system.departmentId?.toString()) {
      return res.status(403).json({ message: 'Department admin can terminate only department systems' });
    }

    const io = req.app.get('io');
    const systemRoom = `system_${system._id}`;
    const companyRoom = `company:${req.user.companyId}`;
    let delivered = false;
    const payload = {
      systemId: system._id.toString(),
      command: 'kill_process',
      pid: numericPid,
      processName: processName || '',
      alertId: alertId || '',
      reason: reason || `Manual process terminate by ${req.user.name || req.user.email || req.user.id}`,
      requestedBy: req.user.id,
    };
    if (io) {
      const sockets = await io.in(systemRoom).fetchSockets();
      delivered = sockets.length > 0;
      io.to(systemRoom).emit('agent:command', payload);
      io.to(companyRoom).emit('agent:command', payload);
    }

    if (alertId && mongoose.Types.ObjectId.isValid(alertId)) {
      await Alert.findOneAndUpdate(
        { _id: alertId, companyId: req.user.companyId },
        { $set: { status: 'investigating', userAction: 'terminate_process' } },
      );
    }

    const audit = await Alert.create({
      companyId: req.user.companyId,
      departmentId: system.departmentId,
      systemId: system._id,
      agentName: system.name || system.hostname,
      source: 'dashboard',
      type: 'PROC_TERMINATE_REQUESTED',
      eventCategory: 'edr',
      ruleId: 'PROC_TERMINATE_REQUESTED',
      severity: 'medium',
      status: 'investigating',
      description: `Process terminate requested: ${processName || 'unknown'} (PID ${numericPid}) on ${system.name || system.hostname || system._id}`,
      processName: processName || '',
      pid: numericPid,
      processStatus: 'terminate_requested',
      username: req.user.email || req.user.name || req.user.id,
      userAction: 'terminate_process',
      rawEvent: payload,
    });

    res.json({
      ok: true,
      sent: delivered,
      command: payload,
      auditAlertId: audit._id,
      message: delivered ? 'Terminate command sent to agent' : 'Terminate request saved, but agent socket is not connected',
    });
  } catch (err) {
    console.error('[dashboard/processes/terminate]', err);
    res.status(500).json({ message: err.message });
  }
});

// ── PATCH /api/dashboard/alerts/:id/action — quarantine/isolate/block/delete ──
router.patch('/alerts/:id/action', requireAnalyst, async (req, res) => {
  const { action, reason } = req.body;
  try {
    const accessFilter = (await getUserDataFilter(req.user, { personal: false })).filter;
    const alert = await Alert.findOne({ _id: req.params.id, ...accessFilter });
    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    const disruptive = new Set(['quarantine', 'block_ip', 'isolate', 'kill_process', 'block_usb']);
    if (disruptive.has(action) && !['superadmin', 'company_admin', 'soc_manager', 'l2_analyst', 'l3_analyst'].includes(req.user.role)) {
      return res.status(403).json({ message: 'L2 or higher permission is required for containment actions' });
    }
    if (disruptive.has(action) && req.body.confirmed !== true) return res.status(400).json({ message: 'Explicit containment confirmation is required' });
    if ((action === 'ignore' || disruptive.has(action)) && !String(reason || '').trim()) return res.status(400).json({ message: 'A reason is required' });

    switch (action) {
      case 'quarantine':
        alert.quarantined = true; alert.status = 'investigating'; break;
      case 'ignore':
        alert.status = 'false_positive'; break;
      case 'delete':
        await alert.deleteOne();
        emitAlertChange(req, 'alert:deleted', alert);
        return res.json({ deleted: true }); // hard delete
      case 'block_ip':
        alert.blocked = true;
        alert.status = 'investigating';
        // Block IP also isolates the source system
        if (alert.systemId) {
          await System.findByIdAndUpdate(alert.systemId, {
            status: 'disconnected',
            $push: { blockedIps: alert.srcip || '' },
          });
          // Send block command back to agent via Socket.IO (agent polls for commands)
          const io = req.app.get('io');
          if (io) {
            const cmdPayload = {
              systemId: alert.systemId.toString(),
              command: 'block_ip',
              ip: alert.srcip,
              alertId: alert._id.toString(),
            };
            // Emit to both company room and system-specific room
            io.to(`company:${alert.companyId}`).emit('agent:command', cmdPayload);
            io.to(`system_${alert.systemId}`).emit('agent:command', cmdPayload);
          }
        }
        break;
      case 'isolate':
        alert.isolationStatus = 'isolated'; alert.isolatedAt = new Date();
        alert.isolationReason = reason || 'Manual isolation';
        alert.status = 'investigating';
        if (alert.systemId) {
          await System.findByIdAndUpdate(alert.systemId, { status: 'disconnected' });
          const io = req.app.get('io');
          if (io) io.to(`system_${alert.systemId}`).emit('agent:command', {
            systemId: alert.systemId.toString(),
            command: 'isolate',
            alertId: alert._id.toString(),
          });
        }
        break;
      case 'reconnect':
        alert.isolationStatus = 'reconnected';
        if (alert.systemId) {
          await System.findByIdAndUpdate(alert.systemId, { status: 'active' });
          const io = req.app.get('io');
          if (io) io.to(`system_${alert.systemId}`).emit('agent:command', {
            systemId: alert.systemId.toString(),
            command: 'reconnect',
            alertId: alert._id.toString(),
          });
        }
        break;
      case 'kill_process':
        alert.status = 'investigating';
        if (alert.systemId && alert.pid) {
          const io = req.app.get('io');
          if (io) io.to(`system_${alert.systemId}`).emit('agent:command', {
            systemId: alert.systemId.toString(),
            command: 'kill_process',
            pid: alert.pid,
            processName: alert.processName,
            alertId: alert._id.toString(),
          });
        }
        break;
      case 'block_usb':
        alert.usbBlocked = true; alert.status = 'investigating'; break;
      case 'set_status': {
        const allowed = new Set(['open', 'investigating', 'resolved', 'false_positive', 'under_observation']);
        const nextStatus = String(req.body.status || '').toLowerCase().replace(/[\s-]+/g, '_');
        if (!allowed.has(nextStatus)) return res.status(400).json({ message: 'Invalid alert status' });
        alert.status = nextStatus;
        if (nextStatus === 'resolved') alert.resolvedAt = new Date();
        break;
      }
    }

    await alert.save();
    alert.investigationTimeline.push({ type: action, actorId: req.user.id, detail: String(reason || action).slice(0, 1000), at: new Date() });
    alert.auditHistory.push({ action, actorId: req.user.id, metadata: { reason: String(reason || '').slice(0, 1000) }, at: new Date() });
    await alert.save();
    if (req.user.tenantId && req.user.id) await SocAuditEvent.create({
      tenantId: req.user.tenantId, companyId: alert.companyId, actorId: req.user.id,
      action: `alert_${action}`, targetType: 'Alert', targetId: String(alert._id),
      metadata: { reason: String(reason || '').slice(0, 1000) }, ipAddress: String(req.ip || '').slice(0, 100),
    });
    emitAlertChange(req, 'alert:updated', alert);
    res.json(alert);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// Same action endpoint for superadmin
router.patch('/company/:companyId/alerts/:id/action', authenticate, requireSuperAdmin, async (req, res) => {
  const { action, reason } = req.body;
  const { companyId } = req.params;
  try {
    const alert = await Alert.findOne({ _id: req.params.id, companyId });
    if (!alert) return res.status(404).json({ message: 'Alert not found' });

    switch (action) {
      case 'quarantine': alert.quarantined = true; alert.status = 'investigating'; break;
      case 'ignore': alert.status = 'false_positive'; break;
      case 'delete':
        await alert.deleteOne();
        emitAlertChange(req, 'alert:deleted', alert);
        return res.json({ deleted: true });
      case 'block_ip':
        alert.blocked = true;
        alert.status = 'investigating';
        if (alert.systemId) {
          await System.findByIdAndUpdate(alert.systemId, {
            status: 'disconnected',
            $push: { blockedIps: alert.srcip || '' },
          });
          const io2 = req.app.get('io');
          if (io2) {
            const cmdPayload2 = {
              systemId: alert.systemId.toString(),
              command: 'block_ip',
              ip: alert.srcip,
              alertId: alert._id.toString(),
            };
            // Emit to both company room and system-specific room
            io2.to(`company:${alert.companyId}`).emit('agent:command', cmdPayload2);
            io2.to(`system_${alert.systemId}`).emit('agent:command', cmdPayload2);
          }
        }
        break;
      case 'isolate':
        alert.isolationStatus = 'isolated'; alert.isolatedAt = new Date();
        alert.isolationReason = reason || 'Superadmin isolation';
        alert.status = 'investigating';
        if (alert.systemId) await System.findByIdAndUpdate(alert.systemId, { status: 'disconnected' });
        break;
      case 'reconnect':
        alert.isolationStatus = 'reconnected';
        if (alert.systemId) await System.findByIdAndUpdate(alert.systemId, { status: 'active' });
        break;
      case 'block_usb': alert.usbBlocked = true; alert.status = 'investigating'; break;
      case 'set_status': {
        const allowed = new Set(['open', 'investigating', 'resolved', 'false_positive', 'under_observation']);
        const nextStatus = String(req.body.status || '').toLowerCase().replace(/[\s-]+/g, '_');
        if (!allowed.has(nextStatus)) return res.status(400).json({ message: 'Invalid alert status' });
        alert.status = nextStatus;
        if (nextStatus === 'resolved') alert.resolvedAt = new Date();
        break;
      }
    }
    await alert.save();
    emitAlertChange(req, 'alert:updated', alert);
    res.json(alert);
  } catch (err) { res.status(500).json({ message: err.message }); }
});


// ═══════════════════════════════════════════════════════════════════════════════
// DEDICATED REPORT EXPORT API — Process Activity Monitoring (Capability ID: 1)
// GET /api/dashboard/process-activity/report?period=90days
// Returns ALL logs for the selected period with no pagination limit
// ═══════════════════════════════════════════════════════════════════════════════
router.get('/process-activity/report', requireAnalyst, async (req, res) => {
  try {
    const { companyId, role, departmentId: userDeptId } = req.user;
    const { period = '90days', category = 'all', departmentId: deptParam } = req.query;

    // Period → window hours mapping
    const periodHoursMap = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
    if (!Object.prototype.hasOwnProperty.call(periodHoursMap, period)) {
      return res.status(400).json({ message: 'Invalid report period' });
    }
    const categorizedProcessRules = /^(PROC_STARTED|ANDROID_APP_ACTIVITY|android_app_change|PROC_TERMINATED|PROC_KERNEL_TERMINATED|PROC_TERMINATE_REQUESTED|PROC_SUSPICIOUS|PROC_SUSPICIOUS_CMDLINE|PROC_SECURITY_TOOL_TAMPER|PROC_SECURITY_TOOL_TERMINATED|PROC_INTERNAL_NETWORK_SCAN|PROC_NETWORK_CONNECTION|PROC_PRIVILEGE_ESCALATION|PROC_KERNEL_START|PROC_AUDIT_START|PROC_SUSPICIOUS_DLL_LOAD|PROC_DLL_INJECTION|PROC_REMOTE_THREAD_INJECTION|PROC_KERNEL_PROCESS_ACCESS|PROC_HOLLOWING|PROC_DNS_QUERY|PROC_DNS_ATTRIBUTED|PROC_POWERSHELL_SCRIPT_BLOCK|PROC_STARTUP_PERSISTENCE_CHANGE|PROC_ASSET_.*|PROC_WORKLOAD_.*|PROC_WEB_ATTACK_ACTIVITY|PROC_DATABASE_SECURITY_ACTIVITY|PROC_APPLICATION_ERROR_ACTIVITY|PROC_CONTAINER_.*|PROC_TELEMETRY_HEALTH|EDR_MALICIOUS_PROCESS|EDR_SUSPICIOUS_CMDLINE|RANSOMWARE_ENCRYPTION_PROC|RANSOMWARE_BACKUP_TAMPER|RANSOMWARE_SHADOW_DELETE|LOLBIN_DETECTED|MEM_FILELESS_EXEC|MEM_RWX_REGION|MEM_CRED_DUMP|MEM_INJECTION_CMDLINE|MEM_LSASS_ACCESS|PROC_UNAUTHORIZED_EXECUTION|PROC_UNSIGNED_EXECUTABLE|PROC_UNTRUSTED_EXECUTABLE|PROC_UNKNOWN_EXECUTABLE|PROC_MODIFIED_PACKAGE_EXECUTABLE|PROC_HIGH_CPU|PROC_HIGH_MEMORY|PROC_HIGH_DISK_IO|EDR_HIGH_MEMORY|PROC_PRIVILEGED_COMMAND|PROC_SERVICE_CREATED|PROC_SERVICE_CONTROL|PROC_SCHEDULED_TASK_CHANGE|PROC_SCHEDULED_TASK_ACTIVITY)$/i;
    const classifiedProcessTags = [
      'powershell', 'command_shell', 'python', 'java', 'vbscript_javascript',
      'web_server', 'database', 'active_directory', 'service', 'scheduled_task',
      'network_enabled', 'outbound_internet', 'remote_access', 'ssh', 'rdp',
      'container_cloud',
    ];
    const reportCategoryFilters = {
      all: null,
      started: { ruleId: /^(PROC_STARTED|PROC_KERNEL_START|PROC_AUDIT_START|ANDROID_APP_ACTIVITY|android_app_change)$/i },
      terminated: { ruleId: /^(PROC_TERMINATED|PROC_KERNEL_TERMINATED|PROC_TERMINATE_REQUESTED)$/i },
      threat: { ruleId: /^(PROC_SUSPICIOUS|PROC_SUSPICIOUS_CMDLINE|PROC_SECURITY_TOOL_TAMPER|PROC_SECURITY_TOOL_TERMINATED|PROC_SUSPICIOUS_DLL_LOAD|PROC_DLL_INJECTION|PROC_REMOTE_THREAD_INJECTION|PROC_KERNEL_PROCESS_ACCESS|PROC_HOLLOWING|PROC_WEB_ATTACK_ACTIVITY|PROC_DATABASE_SECURITY_ACTIVITY|PROC_CONTAINER_RISK|EDR_MALICIOUS_PROCESS|EDR_SUSPICIOUS_CMDLINE|RANSOMWARE_ENCRYPTION_PROC|RANSOMWARE_BACKUP_TAMPER|RANSOMWARE_SHADOW_DELETE|LOLBIN_DETECTED|MEM_FILELESS_EXEC|MEM_RWX_REGION|MEM_CRED_DUMP|MEM_INJECTION_CMDLINE|MEM_LSASS_ACCESS)$/i },
      unauthorized: { ruleId: /^(PROC_UNAUTHORIZED_EXECUTION|PROC_UNSIGNED_EXECUTABLE|PROC_UNTRUSTED_EXECUTABLE|PROC_UNKNOWN_EXECUTABLE|PROC_MODIFIED_PACKAGE_EXECUTABLE)$/i },
      resource: { ruleId: /^(PROC_HIGH_CPU|PROC_HIGH_MEMORY|PROC_HIGH_DISK_IO|EDR_HIGH_MEMORY)$/i },
      privilege: { ruleId: /^(PROC_PRIVILEGED_COMMAND|PROC_PRIVILEGE_ESCALATION)$/i },
      service: { $or: [{ ruleId: /^(PROC_SERVICE_CREATED|PROC_SERVICE_CONTROL|PROC_SCHEDULED_TASK_CHANGE|PROC_SCHEDULED_TASK_ACTIVITY|PROC_STARTUP_PERSISTENCE_CHANGE|PROC_ASSET_.*)$/i }, { inventoryType: { $in: ['service', 'scheduled_task', 'startup'] } }, { processClassifications: { $in: ['service', 'scheduled_task'] } }] },
      scripts: { $or: [{ ruleId: /^PROC_POWERSHELL_SCRIPT_BLOCK$/i }, { processClassifications: { $in: ['powershell', 'command_shell', 'python', 'java', 'vbscript_javascript'] } }] },
      server: { $or: [{ workloadType: { $exists: true, $ne: '' } }, { runtimeType: { $exists: true, $ne: '' } }, { ruleId: /^(PROC_WORKLOAD_|PROC_CONTAINER_)/i }, { processClassifications: { $in: ['web_server', 'database', 'active_directory', 'container_cloud'] } }] },
      network: { $or: [{ ruleId: /^(PROC_INTERNAL_NETWORK_SCAN|PROC_NETWORK_CONNECTION|PROC_DNS_QUERY|PROC_DNS_ATTRIBUTED)$/i }, { processClassifications: { $in: ['network_enabled', 'outbound_internet', 'remote_access', 'ssh', 'rdp'] } }] },
      other: {
        $and: [
          { ruleId: { $not: categorizedProcessRules } },
          { processClassifications: { $nin: classifiedProcessTags } },
        ],
      },
    };
    if (!Object.prototype.hasOwnProperty.call(reportCategoryFilters, category)) {
      return res.status(400).json({ message: 'Invalid report category' });
    }
    const windowHours = periodHoursMap[period];
    const until = new Date();
    const since = new Date(until.getTime() - windowHours * 60 * 60 * 1000);

    // Build base query
    const companyScopeId = mongoose.Types.ObjectId.isValid(companyId)
      ? new mongoose.Types.ObjectId(companyId)
      : companyId;

    const dept = deptParam || (role === 'department_admin' ? userDeptId : null);

    // Reuse the dashboard's canonical process scope so a 24-hour report and
    // the 24-hour dashboard always represent the same event population.
    const baseQuery = {
      $and: [
        liveTargetCapabilityMatch(companyScopeId, 1, since, dept),
        { createdAt: { $lte: until } },
        ...(reportCategoryFilters[category] ? [reportCategoryFilters[category]] : []),
      ],
    };

    // Fetch ALL logs — no limit applied
    const [alerts, total] = await Promise.all([
      Alert.find(baseQuery)
        .sort({ createdAt: -1 })
        .select('_id createdAt timestamp time process processName pid hostname host user username parentProcess parentName parent parentProcessName parentUsername ppid parentPid parentCommandLine parentCmdline parentCmd parentProcessCmdline processParentCommandLine parent_command_line parent_cmdline parent_cmd parent_process_cmdline processCmdline processExe cmdline commandLine cmd command processCpuPercent processMemoryPercent processMemoryMb processDiskReadBytes processDiskWriteBytes processDiskReadBytesPerSecond processDiskWriteBytesPerSecond processNetworkConnectionCount processExternalConnectionCount processRemoteAddresses processUniqueRemoteIpCount processUniqueRemotePortCount processPrivateRemoteIpCount processClassifications processExecutableSha256 processSignatureStatus processTrustStatus processPublisher processPackageOwner processPackageVerificationStatus telemetryProvider providerChannel providerEventId providerRecordId evidenceType coverageStatus sensorStatus sourceProcessName sourcePid targetProcessName targetPid imageLoaded grantedAccess callTrace attributionConfidence inventoryType inventoryName inventoryCount inventoryBatchIndex inventoryBatchCount inventoryItems inventoryItem oldInventoryItem changeType workloadType workloadCounts listenerPorts runtimeType containerId podName namespace containerRisks domain queryType destip destPort platform os osType severity status category type mitre mitreId mitreAttack tactic sha256 hash ruleId agentName description full_log rawEvent')
        .populate('systemId', 'name hostname ip os')
        .lean(),
      Alert.countDocuments(baseQuery),
    ]);

    // Compute stats
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const byPlatform = { Windows: 0, Linux: 0, macOS: 0, Other: 0 };
    const byStatus = {};

    alerts.forEach(a => {
      const s = (a.severity || 'unknown').toLowerCase();
      if (bySeverity[s] !== undefined) bySeverity[s]++; else bySeverity.unknown++;

      const p = (a.platform || a.osType || a.os || '').toLowerCase();
      if (p.includes('win')) byPlatform.Windows++;
      else if (p.includes('linux')) byPlatform.Linux++;
      else if (p.includes('mac')) byPlatform.macOS++;
      else byPlatform.Other++;

      const st = a.status || 'open';
      byStatus[st] = (byStatus[st] || 0) + 1;
    });

    return res.json({
      success: true,
      period,
      category,
      windowHours,
      since: since.toISOString(),
      until: until.toISOString(),
      total,
      fetchedCount: alerts.length,
      stats: { bySeverity, byPlatform, byStatus },
      alerts,
    });
  } catch (err) {
    console.error('[process-activity/report]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// Dedicated report feed for USB, sandbox, script, time, geolocation, service monitoring,
// hash/signature, beaconing, ransomware, LOLBins, memory and DNS capabilities. Keeping
// this query server-side ensures the selected period is not limited to the
// dashboard's currently loaded 24-hour page.
router.get('/capability-report/:capabilityId', requireAnalyst, async (req, res) => {
  const capabilityId = Number(req.params.capabilityId);
  const allowedCapabilities = new Set([18, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31]);
  allowedCapabilities.add(5);
  allowedCapabilities.add(4);
  allowedCapabilities.add(7);
  allowedCapabilities.add(6);
  allowedCapabilities.add(8);
  allowedCapabilities.add(10);
  allowedCapabilities.add(11);
  allowedCapabilities.add(12);
  allowedCapabilities.add(13);
  allowedCapabilities.add(14);
  allowedCapabilities.add(15);
  allowedCapabilities.add(16);
  allowedCapabilities.add(17);
  const periodHours = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
  const categories = {
    4: {
      all: null,
      successful: { $or: [{ authResult: 'success' }, { userAction: /^(?:login|remote_login|privileged_login|screen_unlock_success)$/i }, { ruleId: /AUTH_(?:SUCCESS|MFA_SUCCESS|SCREEN_UNLOCK_SUCCESS)/i }] },
      failed: { $or: [{ authResult: 'failure' }, { userAction: /^(?:login_failed|mfa_failure|screen_unlock_failed)$/i }, { ruleId: /AUTH_(?:FAIL|MFA_FAILURE|SCREEN_UNLOCK_FAILURE)/i }] },
      brute_force: { $or: [{ ruleId: /AUTH_(?:BRUTE|PASSWORD_SPRAY)|TIME_AUTH_FAILURE_BURST/i }, { description: /brute.force|password.spray|credential.stuffing|authentication burst/i }] },
      privileged: { $or: [{ privilegeLevel: /admin|root|privileged|system/i }, { userAction: /privilege|admin|root|sudo/i }, { ruleId: /AUTH_(?:ROOT_LOGIN|SUDO|ADMIN_RIGHTS|GROUP_CHANGE)/i }] },
      account_changes: { $or: [{ userAction: /user_created|user_deleted|user_modified|account_state_change|group_membership_change|password/i }, { ruleId: /AUTH_(?:USER|ACCOUNT|GROUP|PASS)/i }] },
      remote: { $or: [{ authType: /ssh|rdp|vpn|kerberos|ntlm|ldap/i }, { userAction: 'remote_login' }, { ruleId: /AUTH_REMOTE|SSH|RDP|VPN/i }] },
      anomaly: { $or: [{ ruleId: /^(?:GEO_|TIME_|UEBA_)/i }, { description: /impossible.travel|unusual.login|new.ip|new.device|account.takeover|dormant|disabled.account/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 80 } }] },
    },
    5: {
      all: null,
      injection: { $or: [{ ruleId: /INJECTION|REMOTE_THREAD|HOLLOWING/i }, { eventType: /inject|remote.thread|hollow/i }, { mitreId: /^T1055/i }] },
      credential_theft: { $or: [{ ruleId: /LSASS|CRED_DUMP/i }, { eventType: /lsass|credential.dump|minidump/i }, { mitreId: /^T1003/i }] },
      fileless: { $or: [{ ruleId: /FILELESS|REFLECTIVE/i }, { eventType: /fileless|in.memory.payload|reflective/i }, { mitreId: /^T1620/i }] },
      executable_memory: { $or: [{ ruleId: /RWX|EXECUTABLE_MEMORY/i }, { eventType: /rwx|executable.memory/i }] },
      corruption: { $or: [{ ruleId: /OVERFLOW|CORRUPTION|SEGMENT|ACCESS_VIOLATION/i }, { eventType: /heap|stack|overflow|corruption|segmentation/i }] },
      kernel_dll: { $or: [{ ruleId: /DLL|ROOTKIT|SSDT|DKOM|DRIVER/i }, { eventType: /dll|rootkit|hook|driver/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 80 } }] },
    },
    6: {
      all: null,
      persistence: { $or: [{ configurationCategory: /persistence/i }, { configurationObject: /runonce|autorun|startup|winlogon|image.file.execution|appinit|systemd|cron|authorized.keys|ld.preload/i }, { ruleId: /RUNONCE|AUTORUN|STARTUP|WINLOGON|IFEO|APPINIT|SYSTEMD|CRON|AUTHORIZED_KEYS|LD_PRELOAD/i }] },
      security: { $or: [{ configurationCategory: /security.configuration/i }, { configurationObject: /defender|antivirus|firewall|audit|eventlog|sysmon|uac|bitlocker|applocker|selinux|apparmor/i }, { ruleId: /DEFENDER|ANTIVIRUS|FIREWALL|AUDIT|EVENTLOG|SYSMON|UAC|BITLOCKER|APPLOCKER|SELINUX|APPARMOR/i }] },
      identity: { $or: [{ configurationCategory: /user.authentication/i }, { configurationObject: /account|credential|lsa|sudoers|passwd|shadow|group|pam/i }, { ruleId: /ACCOUNT|CREDENTIAL|LSA|SUDO|PASSWD|SHADOW|GROUP|PAM/i }] },
      network: { $or: [{ configurationCategory: /network.configuration/i }, { configurationObject: /firewall|dns|proxy|tcpip|hosts|resolv.conf|vpn|smb|rdp/i }, { ruleId: /NETWORK|FIREWALL|DNS|PROXY|HOSTS|VPN|SMB|RDP/i }] },
      permissions: { $or: [{ configurationCategory: /permissions/i }, { configurationOperation: /permission|owner|acl/i }, { ruleId: /PERMISSION|OWNER|ACL|SECURITY_DESCRIPTOR|SUID|SGID/i }] },
      policy: { configurationPolicyViolation: true },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 80 } }] },
    },
    7: {
      all: null,
      system_files: { $or: [{ systemChangeCategory: /critical.system.files|system.files/i }, { ruleId: /FILE_(?:CREATED|MODIFIED|DELETED|RENAMED|PERMISSION)|SYS_CRITICAL_FILE/i }] },
      identity: { $or: [{ systemChangeCategory: /users|groups|identity|privilege/i }, { ruleId: /USER_|GROUP_|ACCOUNT_|ADMIN_|SUDO/i }] },
      services_tasks: { $or: [{ systemChangeCategory: /service|scheduled.task|cron/i }, { ruleId: /SERVICE|SCHEDULED_TASK|CRON|SYSTEMD/i }] },
      security_network: { $or: [{ systemChangeCategory: /security|firewall|network|remote.access|log.audit/i }, { ruleId: /FIREWALL|DEFENDER|SECURITY|NETWORK_CONFIG|LOG_CLEARED|AUDIT/i }] },
      software_boot: { $or: [{ systemChangeCategory: /software|patch|driver|kernel|boot|container/i }, { ruleId: /SOFTWARE|PATCH|DRIVER|KERNEL|BOOT|CONTAINER/i }] },
      baseline: { baselineStatus: { $in: ['new', 'modified', 'unexpected', 'violation'] } },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 80 } }] },
    },
    8: {
      all: null,
      scheduled_tasks: { $or: [{ persistenceType: /scheduled.task|cron|crontab|systemd.timer/i }, { inventoryType: /scheduled_tasks|cron_jobs|systemd_timers/i }, { ruleId: /SCHEDULED_TASK|CRON|CRONTAB|SYSTEMD_TIMER/i }, { mitreId: /^T1053/i }] },
      services: { $or: [{ persistenceType: /service|systemd|launchdaemon|launchagent/i }, { inventoryType: /services|systemd_services|launch_daemons|launch_agents/i }, { ruleId: /SERVICE|SYSTEMD|LAUNCHDAEMON|LAUNCHAGENT/i }, { mitreId: /^T1543/i }] },
      registry_wmi: { $or: [{ persistenceType: /registry|runonce|run.key|winlogon|appinit|com.hijack|wmi/i }, { inventoryType: /registry|wmi/i }, { ruleId: /REGISTRY|RUNONCE|WINLOGON|APPINIT|COM_HIJACK|WMI/i }, { mitreId: /T1546\.003|T1547\.001/i }] },
      startup_ssh: { $or: [{ persistenceType: /startup|autorun|login.item|authorized.keys|ssh.key|browser.extension/i }, { inventoryType: /startup|ssh_keys|authorized_keys|browser_extensions|login_items/i }, { ruleId: /STARTUP|AUTORUN|AUTHORIZED_KEYS|SSH_KEY|BROWSER_EXTENSION|LOGIN_ITEM/i }, { mitreId: /T1098\.004|T1547/i }] },
      drivers_boot: { $or: [{ persistenceType: /driver|kernel.module|bootloader|boot.config|secure.boot|bcd|grub/i }, { inventoryType: /drivers|kernel_modules|boot_configuration/i }, { ruleId: /DRIVER|KERNEL_MODULE|BOOT|BCD|GRUB/i }, { mitreId: /T1542|T1547\.006/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    10: {
      all: null,
      devices: { $or: [{ ruleId: /USB_(?:DEVICE_EVENT|STORAGE_MOUNTED|DRIVER_LOADED)/i }, { userAction: /connected|disconnected|storage_mounted|driver_loaded/i }] },
      transfers: { $or: [{ ruleId: /USB_(?:FILE_COPIED|SENSITIVE_FILE_COPIED|FILE_READ)/i }, { fileAction: /copied_to_usb|read_from_usb/i }] },
      policy: { $or: [{ ruleId: /USB_.*(?:POLICY|BLOCK|DENIED)/i }, { policyName: { $exists: true, $nin: ['', null] } }] },
      hid: { ruleId: /USB_(?:HID_ANOMALY|RUBBER_DUCKY_SUSPECTED)/i },
      malware: { $or: [{ eventCategory: 'malware' }, { malwareType: { $exists: true, $nin: ['', null] } }, { vtVerdict: /malicious|suspicious/i }, { vtDetections: { $gt: 0 } }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    11: {
      all: null,
      authentication: { $or: [{ ruleId: /AUTH|LOGIN|LOGON|PASSWORD|MFA|ACCOUNT/i }, { description: /authentication|login|logon|password|mfa|account/i }] },
      data_access: { $or: [{ ruleId: /FILE|USB|EXFIL|UPLOAD|DOWNLOAD/i }, { description: /file|usb|exfil|upload|download/i }] },
      endpoint: { $or: [{ ruleId: /PROCESS|POWERSHELL|SCRIPT|LOLBIN|MEMORY|LSASS/i }, { description: /process|powershell|script|lolbin|memory|lsass/i }] },
      network: { $or: [{ ruleId: /NETWORK|DNS|BEACON|SCAN|LATERAL|RDP|SSH/i }, { description: /network|dns|beacon|scan|lateral|rdp|ssh/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    12: {
      all: null,
      sensitive: { $or: [{ dataClassification: /Confidential|Restricted|Secret/i }, { sensitivityType: /sensitive|credential|key|database|business/i }, { ruleId: /FILE_SENSITIVE|DLP/i }] },
      exfiltration: { $or: [{ dataEventType: /exfil|upload|transfer/i }, { transferChannel: /network|ftp|sftp|scp|https/i }, { ruleId: /EXFIL|UPLOAD|TRANSFER/i }] },
      usb_cloud: { $or: [{ transferChannel: /usb|cloud|google.drive|onedrive|dropbox|box|mega|icloud|s3|azure.blob/i }, { ruleId: /USB|CLOUD/i }] },
      database: { $or: [{ dataEventType: /database.export|database.dump/i }, { ruleId: /DATABASE_EXPORT|SQL_DUMP|MYSQLDUMP|PG_DUMP|MONGODUMP/i }] },
      ransomware: { $or: [{ dataEventType: /ransomware/i }, { ruleId: /RANSOM|MASS_(?:RENAME|DELETE)|SHADOW|BACKUP_DELETION/i }, { description: /ransom|encrypt|mass rename|mass delete|shadow copy|backup deletion/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    13: {
      all: null,
      authentication: { $or: [{ authResult: { $in: ['success', 'failure'] } }, { credentialEventType: /auth|login|logon|password|mfa|kerberos|ntlm|ssh|rdp|vpn/i }, { ruleId: /AUTH|LOGIN|LOGON|PASSWORD|MFA|KERBEROS|NTLM|SSH|RDP|VPN/i }] },
      lock_screen: { $or: [{ credentialEventType: /screen_(?:lock|unlock)/i }, { ruleId: /^AUTH_SCREEN_/i }, { description: /screen unlock|workstation.*(?:locked|unlocked)|logon type.?7/i }] },
      credential_theft: { $or: [{ credentialEventType: /credential_theft|lsass|sam_access|secrets_access|browser_password|keychain|pass_the_hash|pass_the_ticket/i }, { ruleId: /CRED|LSASS|MIMIKATZ|SAM|SECRETS|PASS_(?:THE_)?(?:HASH|TICKET)|GOLDEN_TICKET|SILVER_TICKET/i }] },
      privileged: { $or: [{ privilegeLevel: /admin|root|privileged|system/i }, { credentialEventType: /privilege/i }, { ruleId: /PRIV|ADMIN|SUDO|ROOT|RUNAS/i }] },
      tokens_cloud: { $or: [{ tokenType: { $nin: [null, ''] } }, { identityProvider: { $nin: [null, ''] } }, { ruleId: /TOKEN|OAUTH|JWT|API_KEY|CLOUD_IAM|AZURE|ENTRA|AWS_IAM|GOOGLE_WORKSPACE|OKTA/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    14: {
      all: null,
      remote_services: { $or: [{ lateralVector: /rdp|ssh|vnc|psexec|paexec|wmi|winrm|remote.service|remote.registry|scheduled.task|rpc/i }, { ruleId: /RDP|SSH|VNC|PSEXEC|PAEXEC|WMI|WINRM|REMOTE_(?:SERVICE|REGISTRY)|SCHEDULED_TASK|RPC/i }, { description: /remote desktop|remote powershell|remote service|remote registry/i }] },
      credential_abuse: { $or: [{ lateralVector: /pass.the.hash|pass.the.ticket|golden.ticket|silver.ticket|credential|token/i }, { ruleId: /PASS_(?:THE_)?HASH|PASS_(?:THE_)?TICKET|GOLDEN_TICKET|SILVER_TICKET|CREDENTIAL|LSASS|MIMIKATZ|TOKEN/i }, { description: /credential abuse|credential dump|lsass|mimikatz|token theft|token impersonation/i }] },
      smb: { $or: [{ lateralVector: /smb|admin.share/i }, { shareName: /ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL/i }, { ruleId: /SMB|ADMIN_SHARE|SHARE_ENUM/i }, { destPort: 445 }] },
      authentication: { $or: [{ authProtocol: /kerberos|ntlm|password|key|oauth/i }, { eventType: /auth|login|logon/i }, { ruleId: /AUTH|LOGIN|LOGON|KERBEROS|NTLM|BRUTE_FORCE/i }] },
      discovery: { $or: [{ lateralVector: /discover|enumerat|scan/i }, { ruleId: /DISCOVER|ENUMERAT|SCAN|BLOODHOUND|SHARPHOUND|CRACKMAPEXEC|NETEXEC|ADFIND/i }, { description: /discover|enumerat|scan|bloodhound|sharphound|crackmapexec|netexec|adfind/i }] },
      critical: { $or: [{ severity: 'critical' }, { riskScore: { $gte: 86 } }] },
    },
    15: {
      all: null,
      phishing: { $or: [{ threatCategory: /phish|credential|bec|spam/i }, { ruleId: /PHISH|CREDENTIAL|BEC|SPAM/i }, { description: /phish|credential|business email compromise|wire fraud|spam/i }] },
      attachments: { $or: [{ fileName: { $nin: [null, ''] } }, { fileHash: { $nin: [null, ''] } }, { ruleId: /ATTACH|MACRO|PAYLOAD|ARCHIVE/i }] },
      urls: { $or: [{ url: { $nin: [null, ''] } }, { domain: { $nin: [null, ''] } }, { ruleId: /URL|LINK|REDIRECT|TYPOSQUAT/i }] },
      authentication: { $or: [{ ruleId: /SPF|DKIM|DMARC|SPOOF/i }, { 'emailAuth.spf': /fail|softfail/i }, { 'emailAuth.dkim': /fail|none/i }, { 'emailAuth.dmarc': /fail|reject/i }] },
      mailbox: { $or: [{ mailboxEventType: { $nin: [null, ''] } }, { ruleId: /MAILBOX|OAUTH|FORWARD|DELEGAT|BULK_MAIL|PASSWORD_RESET/i }] },
      blocked: { $or: [{ blocked: true }, { quarantined: true }, { actionTaken: /block|quarantin|reject|delete/i }, { containmentStatus: /block|quarantin/i }] },
    },
    16: {
      all: null,
      exfiltration: { $or: [{ insiderSignalType: /exfiltration/i }, { ruleId: /EXFIL|OUTBOUND_TRANSFER|USB_SENSITIVE_FILE/i }, { description: /exfil|outbound transfer|upload|copied to usb/i }] },
      privilege: { $or: [{ insiderSignalType: /privilege|account_change|defense_evasion/i }, { ruleId: /PRIV|SUDO|ADMIN_RIGHTS|GROUP_(?:CHANGE|MOD)/i }, { description: /privilege|sudo|admin rights/i }] },
      after_hours: { $or: [{ ruleId: /^TIME_.*(?:AFTER_HOURS|OFF_HOURS|WEEKEND|UNUSUAL_TIME)/i }, { 'rawEvent.after_hours': true }, { 'rawEvent.raw.after_hours': true }] },
      removable: { ruleId: /^USB_(?:SENSITIVE_FILE_COPIED|POLICY_BLOCKED|POLICY_VIOLATION)$/i },
      sensitive: { $or: [{ ruleId: /^FILE_SENSITIVE$/i }, { sensitivityType: /sensitive|restricted|confidential/i }] },
    },
    17: {
      all: null,
      pending: { inventoryType: 'pending_updates' },
      installed: { inventoryType: { $in: ['installed_patches', 'installed_software'] } },
      health: { $or: [{ eventType: 'Sensor Health' }, { ruleId: /^PATCH_INVENTORY_SENSOR_/i }] },
      critical: { severity: 'critical' },
      failures: { $or: [{ ruleId: /PATCH_.*(?:FAIL|ERROR|ROLLBACK)/i }, { description: /patch.{0,20}(?:fail|error|rollback)/i }] },
    },
    18: {
      all: null,
      malware: { $or: [{ ruleId: /YARA|MALWARE/i }, { malwareType: /malware|trojan|backdoor|dropper|loader|rootkit|miner|worm/i }, { 'yaraRules.0': { $exists: true } }] },
      ransomware: { $or: [{ malwareType: /ransomware|wanna|ryuk/i }, { ruleId: /RANSOMWARE/i }, { description: /ransomware|wanna|ryuk/i }] },
      credentials: { $or: [{ malwareType: /credential/i }, { ruleId: /CREDENTIAL|MIMIKATZ|LSASS/i }, { description: /credential|mimikatz|lsass/i }] },
      quarantined: { $or: [{ quarantined: true }, { actionTaken: /^quarantined$/i }, { ruleId: /QUARANTIN/i }] },
      intel: { $or: [{ iocMatched: true }, { threatIntelMatch: true }, { vtVerdict: /malicious|suspicious/i }, { reputation: /malicious|suspicious/i }] },
    },
    21: {
      all: null,
      powershell: { $or: [{ interpreter: /powershell|pwsh/i }, { processName: /powershell|pwsh/i }, { scriptPath: /\.ps1$/i }, { commandLine: /powershell|pwsh/i }] },
      shell: { $or: [{ interpreter: /cmd|batch|unix shell|bash|zsh|dash/i }, { processName: /^(cmd|bash|sh|zsh|dash)(\.exe)?$/i }, { scriptPath: /\.(?:bat|cmd|sh)$/i }] },
      encoded: { $or: [{ ruleId: /SCRIPT_(?:OBFUSCATED|ENCODED)/i }, { obfuscationScore: { $gt: 0 } }, { commandLine: /encodedcommand|base64|invoke-expression|\biex\b/i }, { detectionReasons: /encoded|obfuscat|base64/i }] },
      download: { $or: [{ ruleId: /SCRIPT_DOWNLOAD/i }, { commandLine: /invoke-webrequest|downloadstring|downloadfile|start-bitstransfer|\bcurl\b|\bwget\b/i }, { detectionReasons: /download|ingress tool transfer/i }] },
      persistence: { $or: [{ ruleId: /SCRIPT_PERSISTENCE/i }, { commandLine: /schtasks|crontab|systemctl\s+enable|new-service|sc(?:\.exe)?\s+create/i }, { detectionReasons: /persistence|scheduled task/i }] },
      remote: { $or: [{ ruleId: /SCRIPT_REMOTE_EXECUTION/i }, { commandLine: /psexec|winrs|invoke-command|enter-pssession|\bssh\b/i }, { detectionReasons: /remote|lateral/i }] },
    },
    22: {
      all: null,
      after_hours: { $or: [{ 'rawEvent.after_hours': true }, { 'rawEvent.raw.after_hours': true }, { ruleId: /TIME_(?:AFTER_HOURS|OFF_HOURS|LATE_NIGHT|UNUSUAL_TIME)/i }] },
      weekend: { $or: [{ 'rawEvent.weekend': true }, { 'rawEvent.raw.weekend': true }, { ruleId: /TIME_.*WEEKEND/i }, { description: /weekend/i }] },
      authentication: { $or: [{ ruleId: /TIME_(?:AUTH|AFTER_HOURS_AUTH|LOGIN|RDP|SSH|VPN)/i }, { eventType: /auth|login|rdp|ssh|vpn|password|mfa/i }] },
      process: { $or: [{ ruleId: /TIME_.*(?:PROCESS|SCRIPT|POWERSHELL|COMMAND|LOLBIN|SCHEDULE)/i }, { eventType: /process|script|powershell|command|scheduled|cron/i }] },
      file: { $or: [{ ruleId: /TIME_.*(?:FILE|ENCRYPTION|BACKUP)/i }, { eventType: /file|encrypt|delete|rename|backup/i }] },
      network: { $or: [{ ruleId: /TIME_.*(?:NETWORK|TRANSFER|DNS|API)/i }, { eventType: /network|transfer|upload|download|dns|connection/i }] },
      security: { $or: [{ ruleId: /TIME_.*(?:PRIVILEGE|SECURITY|CONFIGURATION)/i }, { eventType: /privilege|policy|firewall|antivirus|edr|security|service/i }] },
    },
    23: {
      all: null,
      impossible: { $or: [{ ruleId: /GEO_IMPOSSIBLE_TRAVEL/i }, { description: /impossible[ _-]?travel/i }] },
      location: { $or: [{ ruleId: /GEO_(?:UNUSUAL_LOGIN_LOCATION|NEW_DEVICE_LOCATION|MULTIPLE_GEOLOGINS|FENCE)/i }, { highRiskCountry: true }] },
      privacy: { $or: [{ geoVpn: true }, { geoProxy: true }, { geoTor: true }, { geoHosting: true }] },
      authentication: { $or: [{ ruleId: /GEO_FAILED_LOGIN|GEO_.*LOGIN/i }, { eventType: /login|authentication/i }] },
    },
    24: {
      all: null,
      lifecycle: { $or: [{ serviceEventType: /SERVICE_(?:STARTED|STOPPED|RESTARTED)/i }, { ruleId: /SERVICE_(?:STARTED|STOPPED|RESTARTED)|PROC_SERVICE_CONTROL/i }] },
      created: { $or: [{ serviceEventType: 'SERVICE_CREATED' }, { ruleId: /SERVICE_CREATED|PROC_ASSET_CREATED/i }] },
      failure: { $or: [{ serviceEventType: /SERVICE_(?:FAILED|DELETED)/i }, { ruleId: /SERVICE_(?:FAILED|DELETED)|PROC_ASSET_REMOVED/i }] },
      configuration: { $or: [{ serviceEventType: 'SERVICE_CONFIG_CHANGED' }, { ruleId: /SERVICE_CONFIG_CHANGED|PROC_ASSET_CHANGED/i }] },
      security: { serviceSecurityCritical: true },
    },
    25: {
      all: null,
      malicious: { $or: [{ threatIntelMatch: true }, { iocMatched: true }, { reputation: /malicious/i }, { vtVerdict: /malicious|suspicious/i }, { hashSignatureRule: /KNOWN_MALICIOUS|MALWARE_HASH|RANSOMWARE_HASH|APT_HASH|TROJAN_HASH|THREAT_INTEL_HASH/i }] },
      mismatch: { $or: [{ hashMismatch: true }, { hashSignatureRule: /HASH_MISMATCH|HASH_CHANGED/i }, { ruleId: /HASH_MISMATCH|HASH_CHANGED/i }] },
      unsigned: { $or: [{ signatureStatus: /^unsigned$/i }, { processSignatureStatus: /^unsigned$/i }, { hashSignatureRule: /UNSIGNED_EXECUTABLE/i }] },
      certificate: { $or: [{ signatureStatus: /^(invalid|expired|revoked|unknown|untrusted_publisher|certificate_chain_failure)$/i }, { hashSignatureRule: /INVALID_SIGNATURE|EXPIRED_CERTIFICATE|REVOKED_CERTIFICATE|UNKNOWN_PUBLISHER|UNTRUSTED_PUBLISHER|CERTIFICATE_CHAIN_FAILURE/i }] },
      trusted: { $or: [{ signatureStatus: /^valid$/i }, { allowlisted: true }, { reputation: /known.good|trusted/i }] },
    },
    26: {
      all: null,
      dns: { $or: [{ protocol: /^dns$/i }, { ruleId: /^BEACON_DNS_/i }, { eventType: /dns beacon/i }] },
      http: { protocol: /^(http|https|tls)$/i },
      low_slow: { $or: [{ averageInterval: { $gte: 600 } }, { description: /low.{0,3}slow/i }] },
      process: { processName: { $exists: true, $nin: ['', null] } },
      intel: { $or: [{ iocMatched: true }, { vtVerdict: { $in: ['malicious', 'suspicious'] } }, { threatCategory: /c2|botnet|malicious/i }] },
    },
    27: {
      all: null,
      impact: { $or: [{ ruleId: /MASS_ENCRYPTION|HIGH_ENTROPY|MASS_DELETION/i }, { mitreId: /T1485|T1486/i }, { 'rawEvent.rule_id': /MASS_ENCRYPTION|HIGH_ENTROPY|MASS_DELETION/i }] },
      notes: { $or: [{ ruleId: /RANSOMWARE_NOTE|RANSOMWARE_EXTENSION/i }, { filePath: /\.locked$|\.encrypted$|\.crypt$|readme|decrypt|recover/i }, { 'rawEvent.file_path': /\.locked$|\.encrypted$|\.crypt$|readme|decrypt|recover/i }] },
      recovery: { $or: [{ ruleId: /SHADOW|VSS|BACKUP_TAMPER/i }, { mitreId: 'T1490' }, { processCmdline: /vssadmin|shadowcopy|wbadmin|bcdedit|diskshadow|backup/i }] },
      process: { $or: [{ ruleId: 'RANSOMWARE_ENCRYPTION_PROC' }, { processCmdline: /openssl.*enc|gpg\s+(?:--symmetric|-c)|cipher\s+\/[ed]|7z.*-p|winrar.*-p/i }] },
      correlated: { $or: [{ ruleId: /YARA|IOC|MALWARE_QUARANTINED/i }, { iocMatched: true }, { malwareType: /ransomware/i }] },
    },
    28: {
      all: null,
      encoded: { $or: [{ processCmdline: /encodedcommand|frombase64string|base64|\s-enc(?:\s|$)|invoke-expression|\biex\b/i }, { 'rawEvent.process_cmdline': /encodedcommand|frombase64string|base64|\s-enc(?:\s|$)|invoke-expression|\biex\b/i }, { 'rawEvent.command_line': /encodedcommand|frombase64string|base64|\s-enc(?:\s|$)|invoke-expression|\biex\b/i }, { matchedPatterns: /encoded|base64|invoke-expression/i }] },
      download: { $or: [{ processCmdline: /invoke-webrequest|webclient|downloadfile|downloadstring|start-bitstransfer|urlcache|bitsadmin|\bcurl\b|\bwget\b/i }, { 'rawEvent.process_cmdline': /invoke-webrequest|webclient|downloadfile|downloadstring|start-bitstransfer|urlcache|bitsadmin|\bcurl\b|\bwget\b/i }, { 'rawEvent.command_line': /invoke-webrequest|webclient|downloadfile|downloadstring|start-bitstransfer|urlcache|bitsadmin|\bcurl\b|\bwget\b/i }, { matchedPatterns: /download|urlcache|webclient|bits/i }] },
      office: { $or: [{ parentProcessName: /winword|excel|outlook|powerpnt|office/i }, { 'rawEvent.parent_process_name': /winword|excel|outlook|powerpnt|office/i }] },
      proxy: { $or: [{ processName: /^(rundll32|regsvr32|mshta|installutil|msbuild|odbcconf|presentationhost|control|mmc)(\.exe)?$/i }, { 'rawEvent.process_name': /^(rundll32|regsvr32|mshta|installutil|msbuild|odbcconf|presentationhost|control|mmc)(\.exe)?$/i }, { matchedPatterns: /proxy.execution|scriptlet|hta|inline.task/i }] },
      persistence: { $or: [{ isPersistence: true }, { 'rawEvent.is_persistence': true }, { processCmdline: /schtasks|runonce|run.key|startup|systemd|cron|service.create|wmi.persistence/i }, { 'rawEvent.process_cmdline': /schtasks|runonce|run.key|startup|systemd|cron|service.create|wmi.persistence/i }, { matchedPatterns: /persistence|scheduled.task|startup|systemd|cron/i }] },
      lateral: { $or: [{ processCmdline: /psexec|winrm|remote.service|remote.scheduled|admin.share|remote.powershell|\bssh\b|rdp/i }, { 'rawEvent.process_cmdline': /psexec|winrm|remote.service|remote.scheduled|admin.share|remote.powershell|\bssh\b|rdp/i }, { matchedPatterns: /lateral|psexec|winrm|remote.service|admin.share/i }] },
    },
    29: {
      all: null,
      pressure: { $or: [{ eventType: /pressure|exhaustion|oom/i }, { ruleId: /MEM[-_](001|011)|HIGH_MEMORY|OOM/i }] },
      leak: { $or: [{ eventType: /leak|allocation/i }, { ruleId: /MEM[-_](003|004)|LEAK|ALLOCATION/i }] },
      corruption: { $or: [{ eventType: /stack|heap|out.of.bounds|segmentation|access.violation/i }, { ruleId: /MEM[-_]014|STACK|HEAP|SEGMENT|ACCESS_VIOLATION/i }] },
      injection: { $or: [{ eventType: /inject|remote.thread|hollow|reflective|rwx|executable.region/i }, { ruleId: /MEM[-_](006|007|008|009|013)|INJECT|RWX|HOLLOW|REMOTE_THREAD/i }] },
      protected: { $or: [{ eventType: /lsass|credential|agent.tamper|sensitive.process/i }, { ruleId: /MEM[-_](010|012)|LSASS|CRED|TAMPER/i }] },
      malware: { $or: [{ eventType: /fileless|ransomware|shellcode|obfuscat/i }, { ruleId: /MEM[-_]015|FILELESS|RANSOM|SHELLCODE/i }] },
    },
    30: {
      all: null,
      poisoning: { $or: [{ eventType: /poison|spoof/i }, { ruleId: /POISON|SPOOF/i }] },
      resolver: { $or: [{ eventType: /resolver/i }, { ruleId: /RESOLVER/i }] },
      hosts: { $or: [{ eventType: /hosts/i }, { ruleId: /HOSTS/i }] },
      ttl: { $or: [{ eventType: /ttl/i }, { ruleId: /TTL/i }] },
      private: { $or: [{ eventType: /private/i }, { ruleId: /PRIVATE/i }] },
    },
    31: {
      all: null,
      sinkhole: { $or: [{ responseType: /sinkhole/i }, { eventType: /sinkhole/i }, { ruleId: /SINKHOLE/i }] },
      blocked: { $or: [{ blocked: true }, { actionTaken: /block|deny/i }, { responseCode: /refused|nxdomain/i }] },
      botnet: { threatCategory: /botnet|c2|c&c/i },
      phishing: { threatCategory: /phish/i },
      dga: { threatCategory: /dga/i },
    },
  };

  if (!allowedCapabilities.has(capabilityId)) return res.status(400).json({ message: 'Unsupported report capability' });
  const period = String(req.query.period || 'daily');
  const category = String(req.query.category || 'all');
  if (!Object.prototype.hasOwnProperty.call(periodHours, period)) return res.status(400).json({ message: 'Invalid report period' });
  if (!Object.prototype.hasOwnProperty.call(categories[capabilityId], category)) return res.status(400).json({ message: 'Invalid report category' });
  if (!mongoose.Types.ObjectId.isValid(req.user.companyId)) return res.status(400).json({ message: 'Invalid tenant scope' });

  try {
    const companyId = new mongoose.Types.ObjectId(req.user.companyId);
    const requestedDepartment = resolveCapabilityDepartmentScope(req.user, req.query.departmentId);
    const departmentId = requestedDepartment && mongoose.Types.ObjectId.isValid(requestedDepartment)
      ? new mongoose.Types.ObjectId(requestedDepartment)
      : requestedDepartment || undefined;
    const until = new Date();
    const since = new Date(until.getTime() - periodHours[period] * 60 * 60 * 1000);
    const conditions = [
      liveTargetCapabilityMatch(companyId, capabilityId, since, departmentId),
      { createdAt: { $lte: until } },
    ];
    if (capabilityId === 11) {
      const readySystemIds = await readyUebaSystemIds({ companyId, departmentId, now: until });
      conditions.push({ systemId: { $in: readySystemIds } });
    }
    if (capabilityId === 23) {
      const policyScope = { companyId, enabled: true };
      if (departmentId) policyScope.$or = [{ departmentId }, { departmentId: null }, { departmentId: { $exists: false } }];
      const policies = await GeolocationPolicy.find(policyScope).select('conditions.systemIds').lean();
      if (!policies.length) conditions.push({ _id: { $exists: false } });
      else if (!policies.some(policy => !Array.isArray(policy.conditions?.systemIds) || policy.conditions.systemIds.length === 0)) {
        const systemIds = [...new Set(policies.flatMap(policy => policy.conditions.systemIds || []).map(String))]
          .filter(mongoose.Types.ObjectId.isValid).map(value => new mongoose.Types.ObjectId(value));
        conditions.push(systemIds.length ? { systemId: { $in: systemIds } } : { _id: { $exists: false } });
      }
    }
    if (capabilityId === 5) {
      conditions.push({ $nor: [{ eventType: 'memory.metric' }, { memoryMetricType: { $in: ['host', 'process'] } }], isSynthetic: { $ne: true } });
    }
    if (capabilityId === 29) {
      conditions.push({ $nor: [{ eventType: 'memory.metric' }, { memoryMetricType: { $in: ['host', 'process'] } }] });
    }
    if (capabilityId === 12) {
      conditions.push({ $or: [
        { source: 'data_security' },
        { subCategory: /data[-_ ]security|\bdlp\b/i },
        { dataEventType: { $exists: true, $nin: ['', null] } },
        { dataClassification: { $in: ['Public', 'Internal', 'Confidential', 'Restricted', 'Secret'] } },
        { dlpPattern: { $exists: true, $nin: ['', null] } },
        { dlpMatchCount: { $gt: 0 } },
        { transferChannel: { $exists: true, $nin: ['', null] } },
        { filePath: { $exists: true, $nin: ['', null] } },
        { ruleId: /^(?:DLP_|FILE_SENSITIVE|NET_EXFIL|USB_(?:SENSITIVE_FILE_COPIED|FILE_TRANSFER)|DATA_)/i },
      ] });
    }
    if (capabilityId === 7) {
      conditions.push({ ruleId: { $nin: ['PROC_ASSET_TELEMETRY_HEALTH', 'PROC_ASSET_INVENTORY'] }, eventType: { $nin: ['Sensor Health', 'Inventory Snapshot'] } });
    }
    if (capabilityId === 6) {
      conditions.push({ isSynthetic: { $ne: true } });
    }
    if (capabilityId === 11) {
      conditions.push({ $or: [
        { source: { $in: ['anomaly', 'ueba', 'time_anomaly'] } },
        { behaviorCategory: { $exists: true, $nin: ['', null] } },
        { ruleId: /^(?:ANOMALY_|UEBA_|TIME_|GEO_|AUTH_(?:BRUTE|ACCOUNT_LOCK|ROOT_LOGIN|SUDO)|NET_OUTBOUND_TRANSFER_ANOMALY|USB_SENSITIVE_FILE_COPIED|FILE_SENSITIVE)/i },
        { description: /impossible.?travel|behavior(?:al)? anomaly|baseline deviation|unusual (?:login|activity|location)|after.?hours|weekend login|account takeover|session hijack|mfa fatigue|data exfiltration/i },
      ] });
    }
    if (capabilityId === 31) conditions.push({ eventType: { $ne: 'sinkhole_status' } });
    if (categories[capabilityId][category]) conditions.push(categories[capabilityId][category]);
    const query = { $and: conditions };
    const projection = '_id createdAt timestamp severity status hostname agentName os osType platform systemId agentId source ruleId detectionRuleId eventType anomalyType description full_log actualTime expectedTime timeWindow baselineDiff baselineConfidence localHour weekday afterHours weekend holiday sourceEvent malwareType malwareFamily threatFamily filePath fileName fileHash fileHashMd5 fileAction fileUser quarantined yaraRules detectionSource sha256 sha1 md5 scriptName scriptPath scriptHash scriptSha1 scriptMd5 interpreter commandLine executionSource obfuscationScore detectionReasons processTree childProcesses networkConnections filesCreated filesModified filesDeleted baselineHash currentHash hashMismatch hashSignatureRule hashSignatureRiskScore hashSignatureSeverity signatureStatus publisher certificateSubject certificateIssuer certificateSerial certificateThumbprint certificateValidFrom certificateValidUntil certificateRevocationStatus trustStatus packageOwner packageVerificationStatus threatIntelMatch threatIntelSource reputation allowlisted extension entropy affectedFiles affectedDirectory encryptionSpeed modifiedFilesPerSecond deletedFilesPerSecond renamedFilesPerSecond serviceName serviceDisplayName serviceEventType servicePreviousStatus serviceCurrentStatus serviceStartupType serviceAccount serviceBinaryPath serviceBinarySha256 serviceSignatureStatus servicePublisher servicePid serviceRestartCount serviceSecurityCritical suspiciousServicePath inventoryType inventoryName inventoryCount inventorySnapshotId inventoryBatchIndex inventoryBatchCount inventoryItems inventoryItem oldInventoryItem changeType processName processExe processCmdline processCpuPercent processMemoryPercent processMemoryMb processDiskReadBytes processDiskWriteBytes processDiskWriteBytesPerSecond pid parentProcessName parentPid parentCommandLine username user userDomain riskScore confidenceScore matchedPatterns isNetwork isPersistence processExecutableSha256 processExecutableMd5 processSignatureStatus processPublisher processIntegrityLevel processFileCompany processFileVersion memorySize memoryUsagePercent memoryGrowthRate emailSender emailRecipient emailSubject emailDirection emailMessageId emailAuth mailboxEventType attachmentMimeType attachmentSize url domain queryType srcip sourceIp sourcePort destip destPort protocol connectionState connectionCount retryCount averageInterval medianInterval jitterSeconds intervalConsistency periodicityScore observationSeconds bytesSent bytesReceived reputationScore vtScore vtVerdict vtDetections vtTotal vtDetectionRatio poisonedIp expectedIp resolverIp dnsServer ttl responseType responseCode threatCategory iocMatched blocked actionTaken containmentStatus recommendedAction mitreId mitreTechnique mitreTactic technique geoCountry geoCountryCode geoCity geoRegion geoTimezone geoISP geoLat geoLon geoProxy geoHosting geoVpn geoTor geoRelay highRiskCountry asn asnOrg rawEvent.raw_log rawEvent.process_name rawEvent.process_cmdline rawEvent.command_line rawEvent.cmdline rawEvent.parent_process_name rawEvent.username rawEvent.user rawEvent.matched_patterns rawEvent.file_path rawEvent.file_name rawEvent.file_hash rawEvent.file_hash_sha1 rawEvent.file_hash_md5 rawEvent.script_name rawEvent.script_path rawEvent.script_hash rawEvent.script_sha1 rawEvent.script_md5 rawEvent.interpreter rawEvent.obfuscation_score rawEvent.detection_reasons rawEvent.sha256 rawEvent.sha1 rawEvent.md5 rawEvent.signature_status rawEvent.publisher rawEvent.signer rawEvent.baseline_hash rawEvent.current_hash rawEvent.hash_mismatch rawEvent.threat_intel_source rawEvent.reputation rawEvent.affected_files rawEvent.affected_directory rawEvent.encryption_speed rawEvent.modified_files_per_second rawEvent.deleted_files_per_second rawEvent.renamed_files_per_second rawEvent.entropy rawEvent.extension rawEvent.service_name rawEvent.service_event_type rawEvent.previous_status rawEvent.current_status rawEvent.service_account rawEvent.service_binary_path rawEvent.service_binary_sha256 rawEvent.service_signature_status rawEvent.security_service rawEvent.risk_score rawEvent.rule_id rawEvent.mitre_id rawEvent.actual_time rawEvent.expected_time rawEvent.time_window rawEvent.baseline_diff rawEvent.baseline_confidence rawEvent.local_hour rawEvent.weekday rawEvent.after_hours rawEvent.weekend rawEvent.holiday rawEvent.source_event rawEvent.geoCountry rawEvent.geoCity rawEvent.geoLat rawEvent.geoLon rawEvent.raw.process_name rawEvent.raw.process_cmdline rawEvent.raw.command_line rawEvent.raw.cmdline rawEvent.raw.parent_process_name rawEvent.raw.username rawEvent.raw.user rawEvent.raw.matched_patterns rawEvent.raw.file_path rawEvent.raw.file_name rawEvent.raw.file_hash rawEvent.raw.file_hash_sha1 rawEvent.raw.file_hash_md5 rawEvent.raw.script_name rawEvent.raw.script_path rawEvent.raw.script_hash rawEvent.raw.script_sha1 rawEvent.raw.script_md5 rawEvent.raw.interpreter rawEvent.raw.obfuscation_score rawEvent.raw.detection_reasons rawEvent.raw.sha256 rawEvent.raw.sha1 rawEvent.raw.md5 rawEvent.raw.signature_status rawEvent.raw.publisher rawEvent.raw.signer rawEvent.raw.baseline_hash rawEvent.raw.current_hash rawEvent.raw.hash_mismatch rawEvent.raw.threat_intel_source rawEvent.raw.reputation rawEvent.raw.affected_files rawEvent.raw.affected_directory rawEvent.raw.encryption_speed rawEvent.raw.modified_files_per_second rawEvent.raw.deleted_files_per_second rawEvent.raw.renamed_files_per_second rawEvent.raw.entropy rawEvent.raw.extension rawEvent.raw.service_name rawEvent.raw.service_event_type rawEvent.raw.previous_status rawEvent.raw.current_status rawEvent.raw.service_account rawEvent.raw.service_binary_path rawEvent.raw.service_binary_sha256 rawEvent.raw.service_signature_status rawEvent.raw.security_service rawEvent.raw.risk_score rawEvent.raw.rule_id rawEvent.raw.mitre_id rawEvent.raw.actual_time rawEvent.raw.expected_time rawEvent.raw.time_window rawEvent.raw.baseline_diff rawEvent.raw.baseline_confidence rawEvent.raw.local_hour rawEvent.raw.weekday rawEvent.raw.after_hours rawEvent.raw.weekend rawEvent.raw.holiday rawEvent.raw.source_event';
    const [alerts, total] = await Promise.all([
      Alert.find(query).sort({ createdAt: -1 }).limit(10000)
        .select(projection)
        .select('persistenceType persistenceLocation persistenceKey persistenceValue persistenceTrigger persistenceAction inventoryItem oldInventoryItem keyPath oldValue newValue technique mitreTechniques detectionReason confidenceScore hash newHash signer signatureStatus publisher')
        .select('systemChangeCategory systemChangeType systemChangeTarget previousState newState baselineStatus changeSource changeTicket maintenanceApproved systemChangeIndicators userSid commandLine')
        .select('configurationCategory configurationOperation configurationObject configurationPlatform configurationBaselineStatus configurationPolicyId configurationPolicyViolation configurationRiskFactors registryHive registryValueName registryValueType registryKey sourcePath oldValue newValue oldHash newHash hashAlgorithm processAttribution parentPid processExe processCmdline processSignatureStatus processPublisher detectionReason')
        .select('credentialEventType authType authResult failureReason sessionId deviceId mfaStatus identityProvider privilegeLevel credentialTarget tokenType logonType groupName targetUser endpointType')
        .select('memoryMetricType memoryTotalBytes memoryUsedBytes memoryAvailableBytes memoryPressure swapUsedBytes swapPercent processRssBytes virtualMemoryBytes privateWorkingSetBytes sharedMemoryBytes peakMemoryBytes memoryGrowthBytes memoryGrowthPercent memoryAllocationRate executableRegionCount rwxRegionCount memoryProtection sourceProcessName sourcePid targetProcessName targetPid imageLoaded grantedAccess callTrace attributionConfidence')
        .select('dataEventType dataClassification dlpPattern dlpMatchCount transferChannel destinationDomain transferProtocol fileSize bytesTransferred device deviceVendor serialNumber mountPath sensitivityType')
        .select('usbVendorId usbProductId deviceType usbPolicyId usbPolicyRuleType usbDriver usbEnforcementStatus usbEnforcementError userAction')
        .select('lateralVector sourceHost destinationHost authProtocol shareName sessionState windowsEventId attackPathId relatedEventIds')
        .select('behaviorCategory entityType entityId behaviorScore baselineScore peerDeviationScore uebaConfidence uebaRiskFactors baselineWindowDays')
        .select('rawEvent.srcip rawEvent.srcIp rawEvent.src_ip rawEvent.sourceIp rawEvent.source_ip rawEvent.clientIp rawEvent.client_ip rawEvent.remoteIp rawEvent.remote_ip rawEvent.processName rawEvent.process_name rawEvent.sourceProcessName rawEvent.source_process_name rawEvent.targetProcessName rawEvent.target_process_name rawEvent.processCmdline rawEvent.process_cmdline rawEvent.commandLine rawEvent.command_line rawEvent.cmdline rawEvent.command rawEvent.mitreId rawEvent.mitre_id rawEvent.mitreTechnique rawEvent.mitre_technique rawEvent.mitreTechniques rawEvent.mitre_techniques rawEvent.technique')
        .select('rawEvent.raw.srcip rawEvent.raw.srcIp rawEvent.raw.src_ip rawEvent.raw.sourceIp rawEvent.raw.source_ip rawEvent.raw.clientIp rawEvent.raw.client_ip rawEvent.raw.remoteIp rawEvent.raw.remote_ip rawEvent.raw.processName rawEvent.raw.process_name rawEvent.raw.sourceProcessName rawEvent.raw.source_process_name rawEvent.raw.targetProcessName rawEvent.raw.target_process_name rawEvent.raw.processCmdline rawEvent.raw.process_cmdline rawEvent.raw.commandLine rawEvent.raw.command_line rawEvent.raw.cmdline rawEvent.raw.command rawEvent.raw.mitreId rawEvent.raw.mitreTechnique rawEvent.raw.mitreTechniques rawEvent.raw.technique')
        .select('insiderSignalType rawEvent.insider_signal_type rawEvent.raw.insider_signal_type rawEvent.bytes_sent rawEvent.bytes_transferred rawEvent.after_hours rawEvent.weekend')
        .select('gpsLat gpsLon gpsAccuracyMeters gpsAltitudeMeters gpsProvider gpsStatus gpsReason gpsObservedAt rawEvent.gpsLat rawEvent.gpsLon rawEvent.gpsAccuracyMeters rawEvent.gpsProvider rawEvent.gpsStatus')
        .populate('systemId', 'name hostname ip ipAddress os osType').lean(),
      Alert.countDocuments(query),
    ]);
    const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const byPlatform = { Windows: 0, Linux: 0, macOS: 0, Other: 0 };
    const byStatus = {};
    alerts.forEach(alert => {
      const severity = String(alert.severity || 'unknown').toLowerCase();
      if (Object.prototype.hasOwnProperty.call(bySeverity, severity)) bySeverity[severity] += 1;
      else bySeverity.unknown += 1;
      const platform = String(alert.platform || alert.osType || alert.os || alert.systemId?.osType || alert.systemId?.os || '').toLowerCase();
      if (platform.includes('win')) byPlatform.Windows += 1;
      else if (platform.includes('linux')) byPlatform.Linux += 1;
      else if (platform.includes('mac') || platform.includes('darwin')) byPlatform.macOS += 1;
      else byPlatform.Other += 1;
      const status = String(alert.status || 'open');
      byStatus[status] = (byStatus[status] || 0) + 1;
    });
    res.json({
      success: true, capabilityId, period, category,
      windowHours: periodHours[period], since: since.toISOString(), until: until.toISOString(),
      total, fetchedCount: alerts.length, truncated: total > alerts.length,
      stats: { bySeverity, byPlatform, byStatus }, alerts,
    });
  } catch (err) {
    console.error('[capability-report]', err.message);
    res.status(500).json({ message: 'Capability report could not be generated' });
  }
});

module.exports = router;
