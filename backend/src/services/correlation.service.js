/**
 * correlation.service.js
 * Multi-step attack correlation engine.
 *
 * Detects complex attack chains by looking at recent alerts
 * within a time window (default: last 60 minutes) for each system.
 *
 * Built-in patterns:
 *  1. USB_EXFIL       — USB insert + file access + process execution
 *  2. BRUTE_MALWARE   — Brute-force login + malware detection
 *  3. PRIV_ESC_EXEC   — Privilege escalation + suspicious process
 *  4. PORT_SCAN_ATTACK — Port scan detected + subsequent connection attempts
 *  5. RANSOMWARE_CHAIN — Mass file modification + process + network
 *  6. LATERAL_MOVE    — Multi-system logins from same IP within window
 */

const Alert            = require('../models/Alert.model');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const CorrelationRule  = require('../models/CorrelationRule.model');
const BuiltInCorrelationOverride = require('../models/BuiltInCorrelationOverride.model');
const EdrIncident      = require('../models/EdrIncident.model');
const User             = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const mongoose         = require('mongoose');
const { autoScanCorrelationFinding } = require('./velociraptor.service');
const { networkEvidenceAlertIds } = require('../utils/networkEvidence');
const { claimAlertsForIncident } = require('./socCaseExclusivity.service');

const WINDOW_MS = 60 * 60 * 1000; // 60-minute correlation window
const DEDUP_MS = 2 * 60 * 60 * 1000;
const UPDATE_NOTIFICATION_MIN_MS = 10 * 60 * 1000;
const MAX_INCIDENT_TIMELINE = 100;
const MAX_RELATED_ALERTS = 100;
const CORRELATION_DEBUG = /^(1|true)$/i.test(String(process.env.CORRELATION_DEBUG || ''));
const realtimeTimers = new Map();
const companyRuns = new Map();
const missingIdentityWarnings = new Map();
const MISSING_IDENTITY_WARNING_INTERVAL_MS = 15 * 60 * 1000;
const ROUTINE_RULE_IDS = [
  'FILE_CREATED', 'FILE_MODIFIED', 'FILE_DELETED', 'FILE_RENAMED',
  'PROC_STARTED', 'PROC_TERMINATED', 'PROC_INVENTORY_SUMMARY',
  'NET_DNS_SUMMARY', 'NET_CONNECTION_SUMMARY', 'NET_EXPOSURE_SUMMARY',
  'MEM_TOP_CONSUMER', 'SURICATA_stats',
  'KERNEL_INVENTORY_SNAPSHOT',
  'SURICATA_2022082', 'SURICATA_2054141', 'SURICATA_2200003',
  'SURICATA_2210044', 'SURICATA_2210045', 'SURICATA_2210046', 'SURICATA_2210054',
  'ZEEK_truncated_tcp_payload',
];

function correlationEligibleFilter(companyId, since) {
  return {
    companyId,
    createdAt: { $gte: since },
    status: { $nin: ['false_positive', 'resolved'] },
    isSynthetic: { $ne: true },
    $and: [
      { ticketOpenedAt: null },
      { ticketSource: { $ne: 'soar' } },
      { socCaseType: { $ne: 'ticket' } },
      { ruleId: { $nin: ROUTINE_RULE_IDS } },
      { $or: [
        { severity: { $in: ['high', 'critical'] } },
        { actionable: true },
        { blocked: true },
        { quarantined: true },
        // Low/medium detections may provide an important first step in a
        // multi-event chain. Admit them only with explicit threat evidence;
        // severity alone never promotes routine low telemetry.
        { iocMatched: true },
        { vtVerdict: { $in: ['malicious', 'suspicious'] } },
        { vtDetections: { $gt: 0 } },
        { riskScore: { $gte: 70 } },
        { userAction: { $in: ['failed_login', 'brute_force', 'privilege_escalation'] } },
        { ruleId: { $regex: /^(AUTH_REMOTE_ACCESS|AUTH_ROOT_LOGIN|AUTH_SUDO|SYS_CRON_MOD|SYS_MODULE_LOAD|NET_THREAT_INTEL_SUMMARY|YARA_MATCH|EDR_MALICIOUS_PROCESS|LOLBIN_DETECTED|PROC_UNAUTHORIZED_EXECUTION|USB_LOG_DETECTED|ZEEK_weird)$/i } },
        {
          $and: [
            { module: 'IDS' },
            { sensorEventType: { $in: ['alert', 'weird'] } },
            { severity: { $in: ['medium', 'high', 'critical'] } },
          ],
        },
        {
          $and: [
            { eventCategory: { $in: ['edr', 'system', 'memory', 'persistence'] } },
            { severity: { $in: ['low', 'medium'] } },
            { ruleId: { $regex: /AUTH_|SUDO|ROOT|REMOTE|HIGH_CPU|HIGH_MEMORY|MEMORY_SPIKE|SERVICE_FAIL|SUSPICIOUS|UNAUTHORIZED/i } },
          ],
        },
        { ruleId: { $regex: /^FIREWALL_(?:BLOCK|RULE_APPLIED|CLOSE_PORT)/i } },
        { ruleId: { $regex: /brute|failed.?login|impossible.?travel|malicious|exploit|scan|c2|beacon|ransom|mimikatz|credential|inject|hollow|shellcode|persistence|psexec|lateral|exfil|phish|rootkit|dns.?tunnel|cache.?poison/i } },
        { normalizedEventType: { $regex: /brute|failed.?login|impossible.?travel|malicious|exploit|scan|c2|beacon|ransom|credential|inject|persistence|lateral|exfil|phish/i } },
      ] },
    ],
  };
}

function warnMissingEndpointIdentities(companyId, alertIds) {
  if (!alertIds.length) return;
  const key = String(companyId);
  const now = Date.now();
  const previous = missingIdentityWarnings.get(key) || 0;
  if (now - previous < MISSING_IDENTITY_WARNING_INTERVAL_MS) return;
  missingIdentityWarnings.set(key, now);
  console.warn(
    `[CORRELATION] decision=skipped company=${companyId} reason=missing_endpoint_identity count=${alertIds.length} samples=${alertIds.slice(0, 5).join(',')}`,
  );
}

function correlationGroupKey(alert) {
  const endpoint = alert.systemId?.toString() || alert.endpointId || alert.agentId || alert.agentName || alert.hostname || alert.sensor
    || alert.srcip || alert.destip || alert.username;
  if (!endpoint) return null;
  // Department is part of the security boundary inside a company. Identical
  // hostnames/agent labels in different departments must never share a chain.
  return `${alert.departmentId?.toString() || 'company'}:${endpoint}`;
}

const PATTERN_INTELLIGENCE = {
  MALICIOUS_LOGIN: { techniques: ['T1078'], tactics: ['Initial Access'] },
  IAM_IDS_CORRELATION: { techniques: ['T1078', 'T1046'], tactics: ['Initial Access', 'Discovery'] },
  IDS_IPS_CORRELATION: { techniques: ['T1046'], tactics: ['Discovery'] },
  ZEEK_IOC_MATCH: { techniques: ['T1071'], tactics: ['Command and Control'] },
  USB_EXFIL: { techniques: ['T1052.001', 'T1041'], tactics: ['Collection', 'Exfiltration'] },
  BRUTE_MALWARE: { techniques: ['T1110', 'T1204'], tactics: ['Credential Access', 'Execution'] },
  PRIV_ESC_EXEC: { techniques: ['T1068', 'T1059'], tactics: ['Privilege Escalation', 'Execution'] },
  RANSOMWARE_CHAIN: { techniques: ['T1486', 'T1071'], tactics: ['Impact', 'Command and Control'] },
  PORT_SCAN_ATTACK: { techniques: ['T1046'], tactics: ['Discovery'] },
  IDS_BRUTE: { techniques: ['T1110'], tactics: ['Credential Access'] },
  MALWARE_NETWORK: { techniques: ['T1204', 'T1071'], tactics: ['Execution', 'Command and Control'] },
  EDR_CREDENTIAL_ACCESS: { techniques: ['T1059', 'T1555'], tactics: ['Execution', 'Credential Access'] },
  REMOTE_ROOT_ACCESS: { techniques: ['T1133', 'T1078'], tactics: ['Initial Access', 'Privilege Escalation'] },
  EDR_PERSISTENCE_CHAIN: { techniques: ['T1053.003', 'T1547'], tactics: ['Persistence', 'Privilege Escalation'] },
  PERSISTENCE_MULTI_MECHANISM: { techniques: ['T1059.001', 'T1547.001', 'T1053.005'], tactics: ['Execution', 'Persistence'] },
  SYSTEM_ACCOUNT_SERVICE_CHAIN: { techniques: ['T1136', 'T1098', 'T1543.003'], tactics: ['Persistence', 'Privilege Escalation'] },
  SYSTEM_DEFENSE_EVASION_CHAIN: { techniques: ['T1562.001', 'T1105'], tactics: ['Defense Evasion', 'Command and Control'] },
  SYSTEM_TASK_PERSISTENCE_CHAIN: { techniques: ['T1053.005', 'T1059.001'], tactics: ['Persistence', 'Execution'] },
  DNS_NETWORK_ANOMALY: { techniques: ['T1071.004', 'T1041'], tactics: ['Command and Control', 'Exfiltration'] },
  UEBA_ACCOUNT_TAKEOVER: { techniques: ['T1078'], tactics: ['Initial Access'] },
  MEMORY_EXPLOIT_CHAIN: { techniques: ['T1055', 'T1190'], tactics: ['Execution', 'Privilege Escalation'] },
  CLOUD_CONTROL_PLANE_ABUSE: { techniques: ['T1098', 'T1562.007'], tactics: ['Persistence', 'Defense Evasion'] },
  EMAIL_PAYLOAD_EXECUTION: { techniques: ['T1566', 'T1204.002'], tactics: ['Initial Access', 'Execution'] },
  VULNERABILITY_EXPLOIT_CHAIN: { techniques: ['T1190', 'T1059'], tactics: ['Initial Access', 'Execution'] },
  API_SCRIPT_ABUSE: { techniques: ['T1106', 'T1059.001'], tactics: ['Execution'] },
  FIM_EXECUTION_CHAIN: { techniques: ['T1565.001', 'T1204'], tactics: ['Impact', 'Execution'] },
  TIME_ANOMALY_INTRUSION: { techniques: ['T1078'], tactics: ['Initial Access'] },
  LATERAL_AUTH_REMOTE_EXEC: { techniques: ['T1110', 'T1078', 'T1021', 'T1059.001'], tactics: ['Credential Access', 'Lateral Movement', 'Execution'] },
  LATERAL_ADMIN_SHARE_PSEXEC: { techniques: ['T1021.002', 'T1569.002'], tactics: ['Lateral Movement', 'Execution'] },
  LATERAL_KERBEROS_CREDENTIAL: { techniques: ['T1558', 'T1003', 'T1550'], tactics: ['Credential Access', 'Defense Evasion', 'Lateral Movement'] },
  EDR_HIGH_RISK_EXECUTION: { techniques: ['T1059'], tactics: ['Execution'] },
  EDR_CONFIRMED_MALWARE: { techniques: ['T1204'], tactics: ['Execution'] },
  EDR_PRIVILEGED_AUTH_ANOMALY: { techniques: ['T1078'], tactics: ['Privilege Escalation'] },
  TI_NETWORK_IOC_INCIDENT: { techniques: ['T1071'], tactics: ['Command and Control'] },
  TI_FILE_HASH_IOC_INCIDENT: { techniques: ['T1204'], tactics: ['Execution'] },
  TI_IDS_ANOMALY_CLUSTER: { techniques: ['T1046', 'T1499'], tactics: ['Discovery', 'Impact'] },
  TI_IPS_BLOCKED_THREAT: { techniques: ['T1046'], tactics: ['Discovery'] },
  LOW_MEDIUM_IDS_REVIEW: { techniques: ['T1046'], tactics: ['Discovery'] },
  LOW_MEDIUM_EDR_REVIEW: { techniques: ['T1059'], tactics: ['Execution'] },
};

// Explicit mapping for the 31 core EDR monitoring capabilities. The mapping is
// returned by the rules API and persisted into correlation/incident evidence.
const EDR_CAPABILITY_COVERAGE = {
  MALICIOUS_LOGIN: [4, 29], IAM_IDS_CORRELATION: [3, 4, 12], IDS_IPS_CORRELATION: [3, 12],
  ZEEK_IOC_MATCH: [9, 29], USB_EXFIL: [2, 10, 13, 30], BRUTE_MALWARE: [4, 14, 21, 30],
  PRIV_ESC_EXEC: [1, 4], RANSOMWARE_CHAIN: [1, 2, 3, 5, 13, 31], PORT_SCAN_ATTACK: [3],
  IDS_BRUTE: [3, 4, 12], MALWARE_NETWORK: [3, 21, 29, 30, 31],
  EDR_CREDENTIAL_ACCESS: [1, 5, 13, 14, 24], REMOTE_ROOT_ACCESS: [4, 13, 16, 19, 27],
  EDR_PERSISTENCE_CHAIN: [6, 7, 8, 22, 28], DNS_NETWORK_ANOMALY: [9, 29, 31],
  PERSISTENCE_MULTI_MECHANISM: [1, 2, 6, 7, 8, 21, 24],
  SYSTEM_ACCOUNT_SERVICE_CHAIN: [1, 4, 7, 24], SYSTEM_DEFENSE_EVASION_CHAIN: [1, 3, 7, 21],
  SYSTEM_TASK_PERSISTENCE_CHAIN: [1, 7, 8, 21],
  UEBA_ACCOUNT_TAKEOVER: [11, 19, 26, 27], MEMORY_EXPLOIT_CHAIN: [5, 15, 22],
  CLOUD_CONTROL_PLANE_ABUSE: [17, 23], EMAIL_PAYLOAD_EXECUTION: [18, 21, 24, 30],
  VULNERABILITY_EXPLOIT_CHAIN: [15, 20], API_SCRIPT_ABUSE: [23, 24],
  FIM_EXECUTION_CHAIN: [2, 25, 30], TIME_ANOMALY_INTRUSION: [11, 19, 26],
  LATERAL_AUTH_REMOTE_EXEC: [4, 13, 14, 21], LATERAL_ADMIN_SHARE_PSEXEC: [14, 24],
  LATERAL_KERBEROS_CREDENTIAL: [5, 13, 14],
  EDR_HIGH_RISK_EXECUTION: [1, 24, 30], EDR_CONFIRMED_MALWARE: [14, 21, 30],
  EDR_PRIVILEGED_AUTH_ANOMALY: [4, 16, 19], TI_NETWORK_IOC_INCIDENT: [9, 29, 31],
  TI_FILE_HASH_IOC_INCIDENT: [14, 21, 29, 30],
  TI_IDS_ANOMALY_CLUSTER: [3, 9, 29], TI_IPS_BLOCKED_THREAT: [3, 12, 29],
  LOW_MEDIUM_IDS_REVIEW: [3, 9, 12], LOW_MEDIUM_EDR_REVIEW: [1, 4, 24],
};

function patternCapabilityIds(patternId) {
  return [...new Set(EDR_CAPABILITY_COVERAGE[patternId] || [])].sort((a, b) => a - b);
}

function alertText(alert) {
  return `${alert.ruleId || ''} ${alert.type || ''} ${alert.normalizedEventType || ''} ${alert.eventName || ''} ${alert.description || ''} ${alert.processName || ''} ${alert.processCmdline || ''}`.toLowerCase();
}

function hasCapability(alert, id) {
  return Number(alert.capabilityId) === id || (alert.capabilityIds || []).map(Number).includes(id);
}

function alertTimeline(alerts) {
  return alerts
    .slice()
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt))
    .map(a => ({
      alertId: a._id, timestamp: a.createdAt, category: a.eventCategory || a.category || 'other',
      severity: a.severity, description: String(a.description || a.ruleId || 'Security event').slice(0, 500),
      source: a.source || a.module || 'agent',
    }));
}

function calculateRisk(pattern, alerts) {
  const weight = { low: 15, medium: 35, high: 70, critical: 95 };
  const peak = Math.max(...alerts.map(a => weight[a.severity] || 20));
  const diversity = new Set(alerts.map(a => a.eventCategory || a.source || 'other')).size;
  const steps = Math.min(alerts.length, 4);
  // Confidence is one input, not a minimum score. The previous formula made
  // every completed chain 75+, leaving Low/Medium correlation bands empty.
  let computed = (Number(pattern.confidence || 50) * 0.30)
    + (peak * 0.35)
    + (Math.min(diversity, 5) * 4)
    + (steps * 3)
    + (Number(pattern.riskScore || 0) * 0.10);
  if (alerts.some(alert => alert.iocMatched === true || alert.vtVerdict === 'malicious')) computed += 6;
  if (alerts.some(isConfirmedMalware)) computed += 6;
  if (alerts.some(alert => alert.privilegedUser === true || alert.userAction === 'privilege_escalation')) computed += 4;
  const rounded = Math.min(100, Math.max(0, Math.round(computed)));
  if (Number.isFinite(Number(pattern.riskScoreMin)) && Number.isFinite(Number(pattern.riskScoreMax))) {
    return Math.min(Number(pattern.riskScoreMax), Math.max(Number(pattern.riskScoreMin), rounded));
  }
  return rounded;
}

function severityFromCorrelationRisk(score) {
  const risk = Number(score) || 0;
  if (risk >= 90) return 'critical';
  if (risk >= 75) return 'high';
  if (risk >= 65) return 'medium';
  return 'low';
}

function calculateCorrelationConfidence(pattern, alerts, riskScore) {
  const diversity = new Set(alerts.map(alert => alert.eventCategory || alert.sourceType || alert.source || 'other')).size;
  const requiredSteps = Math.max(1, pattern.requires?.length || 1);
  const completeness = Math.min(1, alerts.length / requiredSteps);
  let confidence = (Number(riskScore || 0) * 0.55)
    + (Number(pattern.confidence || 60) * 0.20)
    + (completeness * 10)
    + (Math.min(diversity, 5) * 3);
  if (alerts.some(alert => alert.iocMatched === true || alert.vtVerdict === 'malicious')) confidence += 8;
  if (alerts.some(isConfirmedMalware)) confidence += 6;
  if (alerts.some(alert => alert.blocked === true || ['blocked', 'dropped', 'rejected', 'quarantined'].includes(alert.action))) confidence += 3;
  return Math.max(0, Math.min(100, Math.round(confidence)));
}

const CUSTOM_FIELDS = new Set([
  'eventCategory', 'eventType', 'normalizedEventType', 'source', 'sourceType', 'module', 'ruleId', 'type', 'severity',
  'userAction', 'srcip', 'destip', 'domain', 'processName', 'username', 'hostname',
  'agentId', 'endpointId', 'actionable', 'blocked', 'action', 'actionTaken',
  'iocMatched', 'vtVerdict', 'capabilityId', 'riskScore', 'confidenceScore',
]);

function conditionMatches(alert, condition) {
  if (!condition || !CUSTOM_FIELDS.has(condition.field)) return false;
  const actual = alert[condition.field];
  if (condition.operator === 'exists') return actual !== undefined && actual !== null && actual !== '';
  if (condition.operator === 'contains') return String(actual || '').toLowerCase().includes(String(condition.value || '').toLowerCase());
  if (condition.operator === 'in') return Array.isArray(condition.value) && condition.value.map(String).includes(String(actual));
  if (condition.operator === 'gte') return Number.isFinite(Number(actual)) && Number(actual) >= Number(condition.value);
  return String(actual ?? '').toLowerCase() === String(condition.value ?? '').toLowerCase();
}

function customRuleToPattern(rule) {
  const conditions = (rule.conditions || []).filter(condition => CUSTOM_FIELDS.has(condition.field));
  if (!conditions.length) return null;
  const threshold = Math.max(1, Number(rule.threshold || 1));
  const predicate = alert => rule.logic === 'OR'
    ? conditions.some(condition => conditionMatches(alert, condition))
    : conditions.every(condition => conditionMatches(alert, condition));
  return {
    id: `CUSTOM_${rule._id}`, name: rule.name, description: rule.description,
    departmentId: rule.departmentId || null,
    severity: rule.severity, confidence: rule.confidence, riskScore: rule.riskScore,
    riskScoreMin: rule.riskScoreMin, riskScoreMax: rule.riskScoreMax,
    timeWindowMs: Number(rule.timeWindowSeconds || 3600) * 1000,
    intelligence: { techniques: rule.mitreTechniques || [], tactics: rule.mitreTactics || [] },
    requires: Array.from({ length: threshold }, () => predicate),
  };
}

function extractIocs(alerts) {
  const values = new Set();
  for (const alert of alerts) {
    [alert.srcip, alert.destip, alert.domain, alert.fileHash, alert.fileHashMd5]
      .filter(Boolean).forEach(value => values.add(String(value).slice(0, 300)));
  }
  return [...values].slice(0, 100);
}

function incidentCategory(patternId) {
  if (/RANSOM/.test(patternId)) return 'ransomware';
  if (/BRUTE/.test(patternId)) return 'brute_force';
  if (/LATERAL/.test(patternId)) return 'lateral_movement';
  if (/PRIV/.test(patternId)) return 'privilege_escalation';
  if (/USB|EXFIL/.test(patternId)) return 'data_exfiltration';
  if (/NETWORK|C2/.test(patternId)) return 'c2_communication';
  if (/PORT_SCAN/.test(patternId)) return 'reconnaissance';
  return 'other';
}

function correlationIncidentSource(pattern, alerts) {
  if ([
    'MALICIOUS_LOGIN',
    'ZEEK_IOC_MATCH',
    'TI_NETWORK_IOC_INCIDENT',
    'TI_FILE_HASH_IOC_INCIDENT',
    'TI_IDS_ANOMALY_CLUSTER',
    'TI_IPS_BLOCKED_THREAT',
    'DNS_NETWORK_ANOMALY',
  ].includes(pattern.id)) return 'threat_intelligence';
  return alerts.some(alert => alert.sourceType === 'THREAT_FEED' || alert.iocMatched === true)
    ? 'threat_intelligence'
    : 'edr';
}

async function assignThreatIntelligenceIncident(incident) {
  if (!incident || incident.incidentSource !== 'threat_intelligence') return incident;
  const candidateIds = await SocCompanyAssignment.find({ companyId: incident.companyId, active: true }).distinct('userId');
  let analysts = await User.find({
    _id: { $in: candidateIds }, role: 'l4_analyst', isActive: true, accountStatus: 'active',
  }).select('_id').lean();
  if (!analysts.length) return incident;

  // Prefer an L4 analyst explicitly mapped to the incident department. A
  // company-assigned L4 remains the safe fallback so TI incidents never stay
  // unassigned merely because an optional department mapping is absent.
  if (incident.departmentId) {
    const departmentUserIds = new Set((await SocDepartmentAssignment.find({
      companyId: incident.companyId, departmentId: incident.departmentId, active: true,
    }).distinct('userId')).map(String));
    const departmentAnalysts = analysts.filter(item => departmentUserIds.has(String(item._id)));
    if (departmentAnalysts.length) analysts = departmentAnalysts;
  }

  const currentAssignee = analysts.find(item => String(item._id) === String(incident.assignedTo || ''));
  const loads = await EdrIncident.aggregate([
    { $match: { assignedTo: { $in: analysts.map(item => item._id) }, incidentSource: 'threat_intelligence', status: { $in: ['open', 'investigating'] } } },
    { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
  ]);
  const loadById = new Map(loads.map(item => [String(item._id), item.count]));
  analysts.sort((a, b) => (loadById.get(String(a._id)) || 0) - (loadById.get(String(b._id)) || 0));
  const assignee = currentAssignee?._id || analysts[0]._id;
  const assignmentChanged = String(incident.assignedTo || '') !== String(assignee);
  if (assignmentChanged) {
    incident.assignedTo = assignee;
    incident.actionsLog.push({
      action: 'auto_assign_l4', target: String(assignee), result: 'Threat Intelligence incident assigned to L4 analyst', takenBy: 'correlation_engine', takenAt: new Date(),
    });
  }
  if (incident.status === 'open') incident.status = 'investigating';
  if (assignmentChanged || incident.isModified('status')) {
    await incident.save();
  }
  if (incident.correlationId) {
    const correlationAssignment = { assignedTo: assignee };
    if (['open', 'investigating'].includes(incident.status)) correlationAssignment.status = 'investigating';
    await CorrelationEvent.updateOne(
      { _id: incident.correlationId, companyId: incident.companyId },
      { $set: correlationAssignment },
    );
  }
  return incident;
}

async function syncIncident(correlation) {
  if (Number(correlation.riskScore || 0) < 50 || correlation.status === 'false_positive' || correlation.status === 'benign') return null;
  const candidateAlertIds = correlation.relatedAlertIds?.length ? correlation.relatedAlertIds : correlation.alertIds;
  const claim = await claimAlertsForIncident(candidateAlertIds, correlation.companyId);
  const correlatedAlertIds = claim.claimedIds;
  if (!correlatedAlertIds.length) return EdrIncident.findOne({
    companyId: correlation.companyId,
    correlationId: correlation._id,
  });
  const correlatedAlerts = correlatedAlertIds?.length
    ? await Alert.find({ _id: { $in: correlatedAlertIds }, companyId: correlation.companyId })
      .select('_id eventCategory sourceType source srcip destip domain dnsQuery protocol communityId')
      .lean()
    : [];
  const networkAlertIds = networkEvidenceAlertIds(correlatedAlerts);
  const iocs = (correlation.iocs || []).map(value => ({
    type: /^[a-f0-9]{32,64}$/i.test(value) ? 'hash' : /^\d{1,3}(\.\d{1,3}){3}$/.test(value) ? 'ip' : 'domain',
    value, context: `Correlation ${correlation.incidentId}`,
  }));
  // Never erase an endpoint identity that was resolved later from stronger
  // incident/forensic evidence. Legacy IPS correlations often carry the
  // synthetic agentName "IPS Server" with no systemId.
  const endpointIdentity = {
    ...(correlation.systemId ? { systemId: correlation.systemId } : {}),
    ...(correlation.departmentId ? { departmentId: correlation.departmentId } : {}),
  };
  const incident = await EdrIncident.findOneAndUpdate(
    { companyId: correlation.companyId, correlationId: correlation._id },
    { $set: {
      ...endpointIdentity,
      title: correlation.patternName, description: correlation.description, severity: correlation.severity,
      incidentSource: correlation.incidentSource || 'edr',
      confidenceScore: correlation.confidence, alertIds: correlatedAlertIds,
      networkInvolved: networkAlertIds.length > 0, networkEvidenceAlertIds: networkAlertIds,
      affectedEndpoint: correlation.agentName, agentName: correlation.agentName, iocs,
      category: incidentCategory(correlation.patternId), mitreTechnique: correlation.mitreTechniques?.[0] || '',
      mitreTactics: correlation.mitreTactics || [], sourceAlertCount: correlatedAlertIds.length,
      firstEventAt: correlation.windowStart, lastEventAt: correlation.windowEnd,
      rawCorrelationData: {
        correlationEventId: correlation._id, incidentId: correlation.incidentId,
        riskScore: correlation.riskScore, coveredCapabilityIds: correlation.coveredCapabilityIds || [],
      },
    }, $setOnInsert: { companyId: correlation.companyId, correlationId: correlation._id, status: 'open' } },
    { upsert: true, new: true, runValidators: true },
  );
  await assignThreatIntelligenceIncident(incident);
  if (String(correlation.linkedIncidentId || '') !== String(incident._id)) {
    await CorrelationEvent.updateOne({ _id: correlation._id }, { linkedIncidentId: incident._id });
    correlation.linkedIncidentId = incident._id;
  }
  return incident;
}

function isConfirmedMalware(alert) {
  const text = `${alert.ruleId || ''} ${alert.type || ''} ${alert.description || ''} ${alert.malwareType || ''}`.toLowerCase();
  const severity = String(alert.severity || '').toLowerCase();
  const independentlyConfirmed = (
    alert.vtVerdict === 'malicious'
    || Number(alert.vtDetections || 0) > 0
    || alert.quarantined === true
    || alert.actionTaken === 'Quarantined'
    || (Array.isArray(alert.yaraRules) && alert.yaraRules.length > 0 && ['high', 'critical'].includes(severity))
  );
  if (!independentlyConfirmed && (
    alert.underObservation === true
    || alert.vtIntelMissing === true
    || /under observation|vt (?:data )?unavailable|awaiting (?:vt|verification)/.test(text)
  )) return false;
  return alert.eventCategory === 'malware'
    && alert.status !== 'false_positive'
    && (
      independentlyConfirmed
      || (
        ['high', 'critical'].includes(severity)
        && (alert.actionable === true || Number(alert.riskScore || 0) >= 80 || Number(alert.confidenceScore || 0) >= 80)
        && /malware|trojan|ransom|backdoor|yara[_ -]?match/.test(text)
      )
    );
}

function isSuspiciousOutbound(alert) {
  if (alert.eventCategory !== 'network') return false;
  const outbound = alert.direction === 'outbound' || alert.inbound === false;
  if (!outbound) return false;
  const text = `${alert.ruleId || ''} ${alert.type || ''} ${alert.description || ''} ${alert.attackType || ''} ${alert.threatCategory || ''}`.toLowerCase();
  return (
    Number(alert.reputationScore || 0) >= 70
    || alert.highRiskCountry === true
    || alert.destGeoTor === true
    || alert.destGeoProxy === true
    || /command.?and.?control|\\bc2\\b|beacon(?:ing)?|confirmed malicious|known malicious|blacklist(?:ed)?/.test(text)
  );
}

function isRansomwareImpact(alert) {
  if (alert.status === 'false_positive' || !['high', 'critical'].includes(String(alert.severity || '').toLowerCase())) return false;
  const text = `${alert.ruleId || ''} ${alert.type || ''} ${alert.description || ''} ${alert.attackType || ''}`.toLowerCase();
  if (/under observation|threat intel missing|vt (?:data )?unavailable|awaiting (?:vt|verification)/.test(text)) return false;
  const ransomwareSignal = /ransomware|mass[_ -]?(?:file[_ -]?)?(?:encrypt|renam|modif)|file[_ -]?encryption|encrypt(?:ed|ion)/.test(text);
  const independentlyConfirmed = (
    alert.actionable === true
    || alert.quarantined === true
    || alert.actionTaken === 'Quarantined'
    || alert.vtVerdict === 'malicious'
    || Number(alert.vtDetections || 0) > 0
    || Number(alert.riskScore || 0) >= 80
    || Number(alert.confidenceScore || 0) >= 80
  );
  return ransomwareSignal && independentlyConfirmed;
}

function isSuspiciousExecution(alert) {
  if (alert.status === 'false_positive' || !['high', 'critical'].includes(String(alert.severity || '').toLowerCase())) return false;
  if (isConfirmedMalware(alert)) return true;
  if (!['system', 'edr', 'malware', 'memory', 'persistence'].includes(alert.eventCategory)) return false;
  const text = `${alert.ruleId || ''} ${alert.type || ''} ${alert.description || ''} ${alert.processName || ''} ${alert.processCmdline || ''}`.toLowerCase();
  return /powershell|pwsh|cmd(?:\.exe)?|wmi|wmic|psexec|rundll32|regsvr32|mshta|certutil|lolbin|process[_ -]?(?:exec|inject|hollow)|shellcode|mimikatz|credential dump/.test(text);
}

function isCredentialAccess(alert) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.filePath || ''}`.toLowerCase();
  return ['high', 'critical'].includes(String(alert.severity || '').toLowerCase())
    && /credential|password|shadow|passwd|keyring|application_default_credentials|client_credentials|mimikatz/.test(text);
}

function isHighConfidenceEdrExecution(alert) {
  const ruleId = String(alert.ruleId || '').toUpperCase();
  const process = String(alert.processName || '').toLowerCase();
  const command = String(alert.processCmdline || '').toLowerCase();
  if (!['PROC_UNAUTHORIZED_EXECUTION', 'LOLBIN_DETECTED'].includes(ruleId)) return false;
  if (!['high', 'critical'].includes(String(alert.severity || '').toLowerCase())) return false;
  // Historical noisy agent versions classified trusted bwrap solely because a
  // /run/user argument appeared in its command line.
  if (process === 'bwrap' && !/download|string|encoded|base64|\/dev\/tcp|credential|mimikatz/.test(command)) return false;
  return ruleId === 'PROC_UNAUTHORIZED_EXECUTION'
    || /download|string|encoded|base64|\/dev\/tcp|credential|mimikatz|reverse shell|remote powershell/.test(`${command} ${alert.description || ''}`.toLowerCase());
}

function isThreatIntelNetwork(alert) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  return alert.eventCategory === 'network'
    && ['medium', 'high', 'critical'].includes(String(alert.severity || '').toLowerCase())
    && (/net_threat_intel|reputation review|malicious|\bc2\b|command.?and.?control/.test(text)
      || Number(alert.reputationScore || 0) >= 70);
}

function isIdsIpsTelemetry(alert) {
  const source = String(alert.source || '').toLowerCase();
  const module = String(alert.module || '').toUpperCase();
  const sourceType = String(alert.sourceType || '').toUpperCase();
  const sourceTypeLegacy = String(alert.source_type || '').toLowerCase();
  return ['IDS', 'IPS', 'ZEEK'].includes(sourceType)
    || ['IDS', 'IPS'].includes(module)
    || ['ids', 'ips'].includes(sourceTypeLegacy)
    || ['suricata', 'zeek', 'ids', 'ips'].includes(source);
}

function isIdsSuspiciousAnomaly(alert) {
  if (!isIdsIpsTelemetry(alert)) return false;
  if (String(alert.module || '').toUpperCase() === 'IPS' || String(alert.sourceType || '').toUpperCase() === 'IPS') return false;
  const text = alertText(alert);
  const sensorType = String(alert.sensorEventType || '').toLowerCase();
  const severity = String(alert.severity || '').toLowerCase();
  return ['medium', 'high', 'critical'].includes(severity)
    && (
      sensorType === 'alert'
      || sensorType === 'weird'
      || /^SURICATA_(?!stats$|flow$|tls$|http$|dns$)/i.test(String(alert.ruleId || ''))
      || /^ZEEK_weird$/i.test(String(alert.ruleId || ''))
      || /truncated|malformed|exploit|scan|shellcode|command.?and.?control|\bc2\b|suspicious|anomaly/.test(text)
    );
}

function isIpsBlockedThreat(alert) {
  if (!isIdsIpsTelemetry(alert)) return false;
  const text = alertText(alert);
  return (String(alert.module || '').toUpperCase() === 'IPS' || String(alert.sourceType || '').toUpperCase() === 'IPS' || /ips/.test(String(alert.source || '').toLowerCase()))
    && (
      alert.blocked === true
      || alert.action === 'blocked'
      || alert.actionTaken === 'Blocked'
      || /ips.*block|auto.?block|blocked|dropped|rejected/.test(text)
    );
}

function matchPatternAlerts(alerts, pattern) {
  const ordered = alerts.slice().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const matched = [];
  const usedIds = new Set();
  let after = 0;

  for (const requirement of pattern.requires) {
    const hit = ordered.find(alert => (
      !usedIds.has(String(alert._id))
      && new Date(alert.createdAt).getTime() >= after
      && requirement(alert)
    ));
    if (!hit) return [];
    matched.push(hit);
    usedIds.add(String(hit._id));
    after = new Date(hit.createdAt).getTime();
  }
  return matched;
}

function matchLatestPatternAlerts(alerts, pattern) {
  const ordered = alerts.slice().sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const matched = [];
  const usedIds = new Set();
  let before = Number.POSITIVE_INFINITY;

  for (let index = pattern.requires.length - 1; index >= 0; index -= 1) {
    const requirement = pattern.requires[index];
    const hit = ordered.slice().reverse().find(alert => (
      !usedIds.has(String(alert._id))
      && new Date(alert.createdAt).getTime() <= before
      && requirement(alert)
    ));
    if (!hit) return [];
    matched.unshift(hit);
    usedIds.add(String(hit._id));
    before = new Date(hit.createdAt).getTime();
  }
  return matched;
}

function matchSignature(pattern, alerts) {
  return `${pattern.id}:${alerts.map(alert => String(alert._id)).join(':')}`;
}

function shouldNotifyCorrelationUpdate(existing, nextRiskScore, now = Date.now()) {
  const lastNotifiedAt = existing?.lastNotifiedAt || existing?.createdAt;
  const lastNotifiedMs = lastNotifiedAt ? new Date(lastNotifiedAt).getTime() : 0;
  return !Number.isFinite(lastNotifiedMs)
    || lastNotifiedMs <= 0
    || (now - lastNotifiedMs) >= UPDATE_NOTIFICATION_MIN_MS
    || Number(nextRiskScore || 0) > Number(existing?.riskScore || 0);
}

function mergeByAlertId(existing = [], incoming = [], limit = MAX_INCIDENT_TIMELINE) {
  const merged = [];
  const seen = new Set();
  for (const item of [...existing, ...incoming]) {
    const key = String(item?.alertId || '');
    if (!key || seen.has(key)) continue;
    seen.add(key);
    merged.push(item);
  }
  return merged
    .sort((a, b) => new Date(a.timestamp || a.observedAt) - new Date(b.timestamp || b.observedAt))
    .slice(-limit);
}

// ── Pattern definitions ───────────────────────────────────────────────────────
const PATTERNS = [
  {
    id: 'MALICIOUS_LOGIN', name: 'Login from Malicious IOC',
    description: 'IAM authentication originated from an indicator confirmed malicious by threat intelligence',
    severity: 'high', confidence: 92, riskScore: 88, timeWindowMs: 15 * 60 * 1000,
    requires: [a => a.sourceType === 'IAM' && a.iocMatched === true && /login|auth|session/i.test(`${a.normalizedEventType || ''} ${a.eventName || ''}`)],
  },
  {
    id: 'IAM_IDS_CORRELATION', name: 'Suspicious Identity + Network Attack',
    description: 'Suspicious IAM activity and IDS exploitation, scanning, or C2 evidence share an identity, host, asset, or IP',
    severity: 'critical', confidence: 94, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => a.sourceType === 'IAM' && (a.iocMatched || /suspicious|failed|brute|impossible|malicious/i.test(`${a.normalizedEventType || ''} ${a.eventName || ''}`)),
      a => a.sourceType === 'IDS' && /scan|exploit|c2|command.?and.?control|malware/i.test(`${a.normalizedEventType || ''} ${a.eventName || ''} ${a.description || ''}`),
    ],
  },
  {
    id: 'IDS_IPS_CORRELATION', name: 'IDS Detection + IPS/Firewall Prevention Outcome',
    description: 'An IDS detection was linked to the corresponding IPS or endpoint-firewall action, preserving whether prevention succeeded',
    severity: 'high', confidence: 90, timeWindowMs: 10 * 60 * 1000,
    requires: [
      a => a.sourceType === 'IDS' && a.action === 'detected',
      a => {
        const text = `${a.ruleId || ''} ${a.normalizedEventType || ''} ${a.description || ''}`;
        const normalizedIpsAction = a.sourceType === 'IPS'
          && /IPS_(?:AUTO|MANUAL|SOAR)_BLOCK|IPS_BLOCK_(?:ATTEMPT|APPLIED)/i.test(text)
          && ['allowed', 'blocked', 'dropped', 'rejected', 'quarantined'].includes(a.action);
        const firewallPrevention = /FIREWALL_(?:BLOCK|RULE_APPLIED|CLOSE_PORT)/i.test(text)
          && (a.blocked === true || a.actionTaken === 'Blocked' || /ACTION:block|block(?:ed|_\w+)?[^;]*=(?:ok|success)/i.test(text));
        return normalizedIpsAction || firewallPrevention;
      },
    ],
  },
  {
    id: 'ZEEK_IOC_MATCH', name: 'Zeek Telemetry IOC Match',
    description: 'Zeek DNS, connection, HTTP, SSL, or file telemetry matched a malicious indicator',
    severity: 'high', confidence: 90, riskScore: 85, timeWindowMs: 15 * 60 * 1000,
    requires: [a => a.sourceType === 'ZEEK' && a.iocMatched === true],
  },
  {
    id: 'TI_NETWORK_IOC_INCIDENT',
    name: 'Threat-Intel Network IOC Incident',
    description: 'Network telemetry matched a malicious IP, domain, C2, proxy, Tor, or reputation indicator',
    severity: 'high', confidence: 88, riskScore: 82, timeWindowMs: 15 * 60 * 1000,
    requires: [a => {
      const text = alertText(a);
      return (
        a.sourceType === 'THREAT_FEED'
        || a.iocMatched === true
        || a.ruleId === 'NET_THREAT_INTEL_SUMMARY'
        || Number(a.reputationScore || 0) >= 70
        || /malicious|threat.?intel|command.?and.?control|\bc2\b|tor|proxy|blacklist/.test(text)
      ) && ['network', 'edr', 'other'].includes(a.eventCategory || 'other');
    }],
  },
  {
    id: 'TI_FILE_HASH_IOC_INCIDENT',
    name: 'Threat-Intel File Hash IOC Incident',
    description: 'A file hash, YARA, or malware alert matched threat-intelligence or VirusTotal evidence',
    severity: 'high', confidence: 90, riskScore: 84, timeWindowMs: 15 * 60 * 1000,
    requires: [a => {
      const text = alertText(a);
      return (
        a.iocMatched === true
        || a.vtVerdict === 'malicious'
        || Number(a.vtDetections || 0) > 0
        || (Array.isArray(a.yaraRules) && a.yaraRules.length > 0)
        || /virustotal|yara|ioc|malicious hash|threat.?intel/.test(text)
      ) && ['malware', 'file', 'edr', 'other'].includes(a.eventCategory || 'other');
    }],
  },
  {
    id: 'TI_IDS_ANOMALY_CLUSTER',
    name: 'IDS Threat Anomaly Cluster',
    description: 'Multiple IDS anomaly or alert events were observed from Zeek/Suricata on the same monitored asset',
    severity: 'high', confidence: 82, riskScore: 70, timeWindowMs: 15 * 60 * 1000,
    requires: [
      isIdsSuspiciousAnomaly,
      isIdsSuspiciousAnomaly,
    ],
  },
  {
    id: 'TI_IPS_BLOCKED_THREAT',
    name: 'IPS Blocked Threat Intelligence Incident',
    description: 'IPS blocked a network threat or auto-blocked malicious/suspicious traffic',
    severity: 'high', confidence: 84, riskScore: 76, timeWindowMs: 15 * 60 * 1000,
    requires: [isIpsBlockedThreat],
  },
  {
    id: 'LOW_MEDIUM_IDS_REVIEW',
    name: 'Low/Medium IDS Review Candidate',
    description: 'Repeated low or medium IDS/Zeek/Suricata review signals were observed on the same monitored asset',
    severity: 'medium', confidence: 70, riskScore: 58, riskScoreMin: 50, riskScoreMax: 64, timeWindowMs: 15 * 60 * 1000,
    requires: [
      a => isIdsIpsTelemetry(a)
        && String(a.module || '').toUpperCase() !== 'IPS'
        && ['low', 'medium'].includes(String(a.severity || '').toLowerCase())
        && ['alert', 'weird'].includes(String(a.sensorEventType || '').toLowerCase())
        && !/^SURICATA_stats$/i.test(String(a.ruleId || '')),
      a => isIdsIpsTelemetry(a)
        && String(a.module || '').toUpperCase() !== 'IPS'
        && ['low', 'medium'].includes(String(a.severity || '').toLowerCase())
        && ['alert', 'weird'].includes(String(a.sensorEventType || '').toLowerCase())
        && !/^SURICATA_stats$/i.test(String(a.ruleId || '')),
    ],
  },
  {
    id: 'LOW_MEDIUM_EDR_REVIEW',
    name: 'Low/Medium EDR Review Candidate',
    description: 'Repeated low or medium EDR signals indicate suspicious but lower-confidence activity requiring analyst review',
    severity: 'medium', confidence: 72, riskScore: 60, riskScoreMin: 50, riskScoreMax: 64, timeWindowMs: 15 * 60 * 1000,
    requires: [
      a => ['low', 'medium'].includes(String(a.severity || '').toLowerCase())
        && ['edr', 'system', 'memory', 'persistence'].includes(a.eventCategory)
        && /auth_|sudo|root|remote.?access|high.?cpu|high.?memory|memory.?spike|service.?fail|suspicious|unauthori[sz]ed/.test(alertText(a)),
      a => ['low', 'medium'].includes(String(a.severity || '').toLowerCase())
        && ['edr', 'system', 'memory', 'persistence'].includes(a.eventCategory)
        && /auth_|sudo|root|remote.?access|high.?cpu|high.?memory|memory.?spike|service.?fail|suspicious|unauthori[sz]ed/.test(alertText(a)),
    ],
  },
  {
    id:          'USB_EXFIL',
    name:        'USB Data Exfiltration Chain',
    description: 'USB device inserted, followed by file access and process execution — potential data theft',
    severity:    'critical',
    confidence:  90,
    requires:    [
      a => a.eventCategory === 'usb' && a.usbBlocked !== true
        && /insert|connect|mount|attach/.test(`${a.ruleId || ''} ${a.description || ''}`.toLowerCase()),
      a => a.eventCategory === 'file'
        && /copy|read|access|download|archive|sensitive|confidential/.test(`${a.fileAction || ''} ${a.ruleId || ''} ${a.description || ''}`.toLowerCase()),
      isSuspiciousExecution,
    ],
  },
  {
    id:          'BRUTE_MALWARE',
    name:        'Brute Force + Malware Deployment',
    description: 'Brute force login attempts followed by malware detection — credential-based intrusion',
    severity:    'critical',
    confidence:  95,
    requires:    [
      a => a.eventCategory === 'edr' && ['failed_login','brute_force'].includes(a.userAction),
      isConfirmedMalware,
    ],
  },
  {
    id: 'EDR_CONFIRMED_MALWARE',
    name: 'EDR Confirmed Malware Incident',
    description: 'EDR detected confirmed malware through VirusTotal, YARA, quarantine, or malicious verdict evidence',
    severity: 'high', confidence: 86, riskScore: 78, timeWindowMs: 15 * 60 * 1000,
    requires: [isConfirmedMalware],
  },
  {
    id:          'PRIV_ESC_EXEC',
    name:        'Privilege Escalation + Execution',
    description: 'Privilege escalation followed by suspicious process — possible rootkit or backdoor',
    severity:    'critical',
    confidence:  88,
    requires:    [
      a => a.userAction === 'privilege_escalation',
      isSuspiciousExecution,
    ],
  },
  {
    id: 'EDR_HIGH_RISK_EXECUTION',
    name: 'EDR High-Risk Execution Incident',
    description: 'High-risk EDR process execution, LOLBin, injection, shell, or credential-tool activity was detected',
    severity: 'high', confidence: 82, riskScore: 74, timeWindowMs: 15 * 60 * 1000,
    requires: [a => isSuspiciousExecution(a) && (
      a.actionable === true
      || Number(a.riskScore || 0) >= 70
      || Number(a.confidenceScore || 0) >= 70
      || /unauthori[sz]ed|lolbin|inject|hollow|mimikatz|credential|reverse.?shell|encoded|base64/.test(alertText(a))
    )],
  },
  {
    id: 'EDR_PRIVILEGED_AUTH_ANOMALY',
    name: 'EDR Privileged Authentication Incident',
    description: 'Root, sudo, privilege escalation, or suspicious privileged authentication activity was detected',
    severity: 'high', confidence: 82, riskScore: 72, timeWindowMs: 15 * 60 * 1000,
    requires: [a => {
      const text = alertText(a);
      return a.eventCategory === 'edr'
        && ['medium', 'high', 'critical'].includes(String(a.severity || '').toLowerCase())
        && (
          a.userAction === 'privilege_escalation'
          || ['AUTH_ROOT_LOGIN', 'AUTH_SUDO', 'AUTH_REMOTE_ACCESS'].includes(String(a.ruleId || ''))
          || /root.?login|sudo|privilege.?escalation|remote.?access|admin.?login/.test(text)
        );
    }],
  },
  {
    id:          'RANSOMWARE_CHAIN',
    name:        'Ransomware Activity Chain',
    description: 'Suspicious execution + verified mass-encryption impact + high-risk outbound C2 — active ransomware suspected',
    severity:    'critical',
    confidence:  92,
    requires:    [
      isSuspiciousExecution,
      isRansomwareImpact,
      isSuspiciousOutbound,
    ],
  },
  {
    id:          'PORT_SCAN_ATTACK',
    name:        'Port Scan + Connection Attempt',
    description: 'Port scan detected followed by suspicious inbound connections — reconnaissance to attack',
    severity:    'high',
    confidence:  80,
    requires:    [
      a => a.ruleId?.toLowerCase().includes('port_scan') || a.description?.toLowerCase().includes('port scan'),
      a => a.eventCategory === 'network'
        && (a.direction === 'inbound' || a.inbound === true)
        && (a.blocked === true || ['high', 'critical'].includes(a.severity))
        && !String(a.ruleId || '').toLowerCase().includes('port_scan'),
    ],
  },
  {
    id:          'IDS_BRUTE',
    name:        'IDS Alert + Authentication Failure',
    description: 'IDS/IPS detection followed by authentication failures — coordinated attack pattern',
    severity:    'high',
    confidence:  85,
    requires:    [
      a => ['suricata', 'zeek', 'ids'].includes(String(a.source || '').toLowerCase())
        && ['high', 'critical'].includes(a.severity),
      a => a.eventCategory === 'edr'
        && /fail|brute/.test(`${a.userAction || ''} ${a.ruleId || ''} ${a.description || ''}`.toLowerCase()),
    ],
  },
  {
    id:          'MALWARE_NETWORK',
    name:        'Malware + Network Anomaly (C2 Communication)',
    description: 'Confirmed malware followed by a high-risk outbound connection — possible command-and-control activity',
    severity:    'critical',
    confidence:  87,
    requires:    [
      isConfirmedMalware,
      isSuspiciousOutbound,
    ],
  },
  {
    id: 'EDR_CREDENTIAL_ACCESS',
    name: 'Suspicious EDR Execution → Credential Access',
    description: 'Unauthorized or LOLBin execution was followed by access to credential material on the same endpoint',
    severity: 'critical', confidence: 90, timeWindowMs: 10 * 60 * 1000,
    requires: [
      isHighConfidenceEdrExecution,
      isCredentialAccess,
    ],
  },
  {
    id: 'REMOTE_ROOT_ACCESS',
    name: 'Remote Access → Root Login',
    description: 'Remote authentication activity was followed by a root login on the same endpoint',
    severity: 'critical', confidence: 92, timeWindowMs: 10 * 60 * 1000,
    requires: [
      a => a.ruleId === 'AUTH_REMOTE_ACCESS',
      a => a.ruleId === 'AUTH_ROOT_LOGIN' && a.severity === 'critical',
    ],
  },
  {
    id: 'LATERAL_AUTH_REMOTE_EXEC', name: 'Failed Login → Remote Session → Command Execution',
    description: 'Repeated authentication failures were followed by a successful remote session and remote command execution',
    severity: 'high', confidence: 92, riskScore: 88, timeWindowMs: 20 * 60 * 1000,
    requires: [
      a => /auth_(?:fail|brute)|failed.?login|brute.?force/.test(alertText(a)),
      a => /auth_success|auth_remote_access|successful authentication|remote.?session/.test(alertText(a)),
      a => /rdp|remote desktop|ssh|winrm|remote.?session/.test(alertText(a)),
      a => /powershell|invoke-command|pssession|psexec|wmic|remote.?execution/.test(alertText(a)),
    ],
  },
  {
    id: 'LATERAL_ADMIN_SHARE_PSEXEC', name: 'Administrative Share → Remote Service → PsExec',
    description: 'Administrative-share access was followed by remote service creation and PsExec activity',
    severity: 'critical', confidence: 96, riskScore: 96, timeWindowMs: 15 * 60 * 1000,
    requires: [
      a => /admin\$|c\$|ipc\$|administrative.?share|smb/.test(alertText(a)),
      a => /remote.?service|service.?creat|eventid.?7045|proc_service_created/.test(alertText(a)),
      a => /psexec|psexesvc|paexec/.test(alertText(a)),
    ],
  },
  {
    id: 'LATERAL_KERBEROS_CREDENTIAL', name: 'Kerberos Abuse → LSASS Access → Credential Pivot',
    description: 'Kerberos ticket abuse was followed by LSASS access and credential-based lateral movement',
    severity: 'critical', confidence: 97, riskScore: 98, timeWindowMs: 20 * 60 * 1000,
    requires: [
      a => /kerberos|golden.?ticket|silver.?ticket|pass.the.ticket|overpass.the.hash|rubeus/.test(alertText(a)),
      a => /lsass|credential.?dump|mimikatz|sekurlsa/.test(alertText(a)),
      a => /pass.the.hash|pass.the.ticket|psexec|winrm|smb|remote.?service|lateral/.test(alertText(a)),
    ],
  },
  {
    id: 'EDR_PERSISTENCE_CHAIN',
    name: 'Privilege Activity → Persistence Change',
    description: 'Sudo/root activity was followed by a cron or kernel-module persistence change on the same endpoint',
    severity: 'high', confidence: 84, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => ['AUTH_SUDO', 'AUTH_ROOT_LOGIN'].includes(a.ruleId),
      a => ['SYS_CRON_MOD', 'SYS_MODULE_LOAD'].includes(a.ruleId) && ['medium', 'high', 'critical'].includes(a.severity),
    ],
  },
  {
    id: 'PERSISTENCE_MULTI_MECHANISM', name: 'PowerShell → Artifact Drop → Autostart Registration',
    description: 'PowerShell activity was followed by a dropped or changed artifact and a registry, task, service, WMI, cron, systemd, or startup persistence change',
    severity: 'critical', confidence: 94, riskScore: 94, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => /powershell|pwsh|encoded.?command|script_download_execute/.test(alertText(a)),
      a => /file_(?:created|modified)|artifact|payload|executable.?drop/.test(alertText(a)),
      a => /registry|runonce|scheduled.?task|schtasks|service.?creat|wmi.?subscription|authorized_keys|cron|systemd|startup|launchagent|launchdaemon/.test(alertText(a)),
    ],
  },
  {
    id: 'SYSTEM_ACCOUNT_SERVICE_CHAIN', name: 'New Account → Privilege Change → Service Execution',
    description: 'A new account was elevated and then used to create a service or execute a process',
    severity: 'critical', confidence: 94, riskScore: 95, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => hasCapability(a, 7) && /user.?creat|account.?creat|new.?user/.test(alertText(a)),
      a => hasCapability(a, 7) && /admin|privilege|group.?add|sudo/.test(alertText(a)),
      a => /service.?creat|process.?execut|powershell|cmd|bash/.test(alertText(a)),
    ],
  },
  {
    id: 'SYSTEM_DEFENSE_EVASION_CHAIN', name: 'Security Control Disabled → Payload Network Activity',
    description: 'Firewall or endpoint protection was weakened before suspicious executable or outbound activity',
    severity: 'critical', confidence: 96, riskScore: 97, timeWindowMs: 20 * 60 * 1000,
    requires: [
      a => hasCapability(a, 7) && /firewall.?(?:disable|stop)|defender.?(?:disable|exclusion)|security.?service.?stop|audit.?(?:disable|clear)/.test(alertText(a)),
      a => /executable.?creat|payload|unsigned|malware|suspicious.?process/.test(alertText(a)),
      a => /outbound|connection|connect|c2|command.and.control/.test(alertText(a)),
    ],
  },
  {
    id: 'SYSTEM_TASK_PERSISTENCE_CHAIN', name: 'Scheduled Task → Encoded PowerShell → Persistence',
    description: 'A scheduled task or cron change launched encoded script activity associated with persistence',
    severity: 'high', confidence: 92, riskScore: 89, timeWindowMs: 20 * 60 * 1000,
    requires: [
      a => hasCapability(a, 7) && /scheduled.?task|schtasks|cron|crontab/.test(alertText(a)),
      a => /powershell|pwsh/.test(alertText(a)) && /encoded|base64|hidden|obfuscat/.test(alertText(a)),
      a => /persistence|run.?key|startup|service|wmi|autorun/.test(alertText(a)),
    ],
  },
  {
    id: 'DNS_NETWORK_ANOMALY',
    name: 'DNS Integrity Change → Threat-Intel Network Activity',
    description: 'A high-confidence DNS integrity alert was followed by threat-intelligence network activity on the same endpoint',
    severity: 'high', confidence: 86, timeWindowMs: 10 * 60 * 1000,
    requires: [
      a => a.ruleId === 'DNS_CACHE_POISON_IP_CHANGE' && ['high', 'critical'].includes(a.severity),
      isThreatIntelNetwork,
    ],
  },
  {
    id: 'UEBA_ACCOUNT_TAKEOVER', name: 'UEBA Anomaly → Account Takeover Activity',
    description: 'A behavioral, time, or geolocation anomaly was followed by suspicious authentication activity on the same identity or endpoint',
    severity: 'critical', confidence: 90, riskScore: 88, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => [11, 26, 27].some(id => hasCapability(a, id)) || /ueba|impossible.?travel|geo.?anomal|after.?hours|time.?anomal|new.?location/.test(alertText(a)),
      a => a.eventCategory === 'edr' && /failed.?login|brute|root.?login|privilege|account.?takeover|suspicious.?session/.test(alertText(a)),
    ],
  },
  {
    id: 'MEMORY_EXPLOIT_CHAIN', name: 'Memory Exploit → Suspicious Execution',
    description: 'Memory exploitation, shellcode, injection, or kernel tampering was linked to suspicious process execution',
    severity: 'critical', confidence: 92, riskScore: 92, timeWindowMs: 15 * 60 * 1000,
    requires: [
      a => [5, 15, 22].some(id => hasCapability(a, id)) && /overflow|shellcode|heap.?spray|rop|inject|hollow|kernel|rootkit/.test(alertText(a)),
      isSuspiciousExecution,
    ],
  },
  {
    id: 'CLOUD_CONTROL_PLANE_ABUSE', name: 'Cloud Control-Plane Abuse',
    description: 'Risky Cloud/SaaS API activity changed identity, public access, logging, or security controls',
    severity: 'critical', confidence: 88, riskScore: 86, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => (hasCapability(a, 17) || /cloudtrail|azure.?activity|gcp.?audit|cloud|saas/.test(alertText(a))) && /iam|role|policy|public.?bucket|security.?group|access.?key|logging|audit/.test(alertText(a)),
      a => (hasCapability(a, 23) || /api|control.?plane|console/.test(alertText(a))) && ['high', 'critical'].includes(String(a.severity || '').toLowerCase()),
    ],
  },
  {
    id: 'EMAIL_PAYLOAD_EXECUTION', name: 'Email Threat → Payload Execution',
    description: 'A phishing/BEC or malicious attachment detection was followed by malware or script execution',
    severity: 'critical', confidence: 92, riskScore: 90, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => hasCapability(a, 18) || /phish|business.?email|\bbec\b|malicious.?attachment|email.?threat/.test(alertText(a)),
      a => isConfirmedMalware(a) || isSuspiciousExecution(a),
    ],
  },
  {
    id: 'VULNERABILITY_EXPLOIT_CHAIN', name: 'Known Vulnerability → Exploitation',
    description: 'A vulnerable or unpatched asset was followed by matching exploitation evidence',
    severity: 'critical', confidence: 91, riskScore: 90, timeWindowMs: 60 * 60 * 1000,
    requires: [
      a => hasCapability(a, 20) || /\bcve-\d{4}-\d+\b|unpatched|missing.?patch|vulnerab/.test(alertText(a)),
      a => hasCapability(a, 15) || /exploit|shellcode|buffer.?overflow|remote.?code.?execution|\brce\b/.test(alertText(a)),
    ],
  },
  {
    id: 'API_SCRIPT_ABUSE', name: 'Suspicious API → Script Execution',
    description: 'Suspicious API/syscall activity was followed by obfuscated or high-risk script execution',
    severity: 'high', confidence: 86, riskScore: 84, timeWindowMs: 15 * 60 * 1000,
    requires: [
      a => hasCapability(a, 23) || /winapi|syscall|wmic|api.?call|invoke/.test(alertText(a)),
      a => hasCapability(a, 24) && /powershell|pwsh|wscript|cscript|mshta|encoded|obfuscat|invoke-expression/.test(alertText(a)),
    ],
  },
  {
    id: 'FIM_EXECUTION_CHAIN', name: 'File Integrity Change → Execution',
    description: 'A security-sensitive file or hash change was followed by suspicious execution on the same endpoint',
    severity: 'high', confidence: 87, riskScore: 84, timeWindowMs: 20 * 60 * 1000,
    requires: [
      a => (hasCapability(a, 25) || a.eventCategory === 'file') && /critical|sensitive|unauthor|hash.?change|modified|created|yara/.test(alertText(a)),
      isSuspiciousExecution,
    ],
  },
  {
    id: 'TIME_ANOMALY_INTRUSION', name: 'Time Anomaly → Security Control Change',
    description: 'After-hours or statistically abnormal activity was followed by a privileged system/service change',
    severity: 'high', confidence: 84, riskScore: 82, timeWindowMs: 30 * 60 * 1000,
    requires: [
      a => hasCapability(a, 26) || /after.?hours|time.?anomal|baseline.?deviation|activity.?spike/.test(alertText(a)),
      a => /sudo|root|privilege|service|firewall|defender|scheduled.?task|cron|module.?load/.test(alertText(a)) && ['high', 'critical'].includes(String(a.severity || '').toLowerCase()),
    ],
  },
];

function publicPattern(pattern) {
  return {
    id: pattern.id,
    name: pattern.name,
    description: pattern.description,
    severity: pattern.severity,
    confidence: pattern.confidence,
    riskScore: pattern.riskScore || null,
    riskScoreMin: Number.isFinite(Number(pattern.riskScoreMin)) ? Number(pattern.riskScoreMin) : null,
    riskScoreMax: Number.isFinite(Number(pattern.riskScoreMax)) ? Number(pattern.riskScoreMax) : null,
    threshold: pattern.requires.length,
    timeWindowSeconds: Math.round((pattern.timeWindowMs || WINDOW_MS) / 1000),
    mitreTechniques: (PATTERN_INTELLIGENCE[pattern.id] || pattern.intelligence || {}).techniques || [],
    mitreTactics: (PATTERN_INTELLIGENCE[pattern.id] || pattern.intelligence || {}).tactics || [],
    coveredCapabilityIds: patternCapabilityIds(pattern.id),
    builtIn: true,
    enabled: true,
  };
}

function applyBuiltInOverride(pattern, override) {
  if (!override) return pattern;
  return {
    ...pattern,
    name: override.name || pattern.name,
    description: override.description || pattern.description,
    severity: override.severity || pattern.severity,
    confidence: Number.isFinite(Number(override.confidence)) ? Number(override.confidence) : pattern.confidence,
    riskScore: Number.isFinite(Number(override.riskScore)) ? Number(override.riskScore) : pattern.riskScore,
    riskScoreMin: Number.isFinite(Number(override.riskScoreMin)) ? Number(override.riskScoreMin) : pattern.riskScoreMin,
    riskScoreMax: Number.isFinite(Number(override.riskScoreMax)) ? Number(override.riskScoreMax) : pattern.riskScoreMax,
    timeWindowMs: Number.isFinite(Number(override.timeWindowSeconds))
      ? Number(override.timeWindowSeconds) * 1000 : pattern.timeWindowMs,
    builtInOverrideId: override._id,
    enabled: override.enabled !== false,
  };
}

// ── Detect patterns for a company ─────────────────────────────────────────────
async function detectCorrelationsInternal(companyId, { io = null } = {}) {
  if (!mongoose.isValidObjectId(companyId)) {
    throw new Error('A valid companyId is required for tenant-safe correlation');
  }
  const cid   = new mongoose.Types.ObjectId(companyId);
  const [customRules, builtInOverrides] = await Promise.all([
    CorrelationRule.find({ companyId: cid, enabled: true }).lean(),
    BuiltInCorrelationOverride.find({ companyId: cid }).lean(),
  ]);
  const customPatterns = customRules.map(customRuleToPattern).filter(Boolean);
  const overridesById = new Map(builtInOverrides.map(item => [item.patternId, item]));
  const builtInPatterns = PATTERNS
    .map(pattern => applyBuiltInOverride(pattern, overridesById.get(pattern.id)))
    .filter(pattern => pattern.enabled !== false);
  const allPatterns = [...builtInPatterns, ...customPatterns];
  const maxWindowMs = Math.max(WINDOW_MS, ...allPatterns.map(pattern => pattern.timeWindowMs || WINDOW_MS));
  const since = new Date(Date.now() - maxWindowMs);

  // Fetch recent alerts grouped by agentName/systemId
  const alerts = await Alert.find(correlationEligibleFilter(cid, since))
    .select('_id tenantId partnerId companyId departmentId systemId endpointId agentId agentName hostname createdAt status severity eventCategory source sourceType module ruleId type normalizedEventType eventName description username userAction malwareType vtVerdict vtDetections yaraRules quarantined action actionTaken actionable iocMatched riskScore confidenceScore direction inbound blocked reputationScore highRiskCountry destGeoTor destGeoProxy srcip destip domain fileHash fileHashMd5 device usbBlocked fileAction processName processCmdline attackType threatCategory capabilityId capabilityIds')
    .sort({ createdAt: -1 })
    .limit(10000)
    .lean();

  if (!alerts.length) return [];

  // Group by immutable endpoint identity. Hostnames are not unique.
  const bySystem = {};
  const missingIdentityAlertIds = [];
  for (const a of alerts) {
    const key = correlationGroupKey(a);
    if (!key) {
      // Sensor health/statistics are company-level telemetry, not endpoint
      // security events, so they intentionally do not participate in an
      // endpoint attack chain.
      if (!/^SURICATA_stats$/i.test(String(a.ruleId || ''))) {
        missingIdentityAlertIds.push(String(a._id));
      }
      continue;
    }
    if (!bySystem[key]) bySystem[key] = {
      alerts: [], systemId: a.systemId, departmentId: a.departmentId,
      agentName: a.agentName || a.hostname || a.endpointId || key,
    };
    bySystem[key].alerts.push(a);
  }
  warnMissingEndpointIdentities(companyId, missingIdentityAlertIds);

  const detected = [];

  for (const [systemName, sysData] of Object.entries(bySystem)) {
    const sAlerts = sysData.alerts;

    for (const pattern of allPatterns) {
      if (pattern.departmentId && String(pattern.departmentId) !== String(sysData.departmentId || '')) continue;
      const matched = matchLatestPatternAlerts(sAlerts, pattern);
      if (matched.length < pattern.requires.length) continue;
      const matchedSpan = new Date(matched[matched.length - 1].createdAt) - new Date(matched[0].createdAt);
      if (matchedSpan > (pattern.timeWindowMs || WINDOW_MS)) continue;
      const signature = matchSignature(pattern, matched);

      const existing = await CorrelationEvent.findOne({
        companyId: cid,
        patternId: pattern.id,
        ...(sysData.systemId ? { systemId: sysData.systemId } : { agentName: sysData.agentName }),
        lastActivityAt: { $gte: new Date(Date.now() - DEDUP_MS) },
        status:    { $nin: ['resolved', 'false_positive'] },
      }).sort({ lastActivityAt: -1 });

      const intelligence = pattern.intelligence || PATTERN_INTELLIGENCE[pattern.id] || { techniques: [], tactics: [] };
      const matchedRisk = calculateRisk(pattern, matched);
      const matchedConfidence = calculateCorrelationConfidence(pattern, matched, matchedRisk);
      if (existing) {
        if (existing.lastMatchSignature === signature
          || matched.every(alert => existing.alertIds.some(id => String(id) === String(alert._id)))) {
          existing.incidentSource = correlationIncidentSource(pattern, matched);
          existing.coveredCapabilityIds = patternCapabilityIds(pattern.id);
          existing.riskScore = Math.max(existing.riskScore || 0, matchedRisk);
          existing.confidence = Math.max(existing.confidence || 0, matchedConfidence);
          existing.severity = severityFromCorrelationRisk(existing.riskScore);
          await existing.save();
          await syncIncident(existing);
          if (CORRELATION_DEBUG) {
            console.debug(`[CORRELATION] decision=duplicate company=${companyId} pattern=${pattern.id} endpoint=${sysData.agentName} signature=${signature}`);
          }
          continue;
        }

        const timeline = mergeByAlertId(existing.timeline || [], alertTimeline(matched));
        const evidence = mergeByAlertId(
          existing.evidence || [],
          matched.map(alert => ({ alertId: alert._id, ruleId: alert.ruleId, source: alert.source, observedAt: alert.createdAt })),
        );
        const relatedIds = [...new Set([
          ...(existing.relatedAlertIds || []).map(String),
          ...(existing.alertIds || []).map(String),
          ...matched.map(alert => String(alert._id)),
        ])];
        const overflow = Math.max(0, relatedIds.length - MAX_RELATED_ALERTS);

        existing.alertIds = matched.map(alert => alert._id);
        existing.relatedAlertIds = relatedIds.slice(-MAX_RELATED_ALERTS);
        existing.timeline = timeline;
        existing.evidence = evidence;
        existing.eventCount = timeline.length;
        existing.occurrenceCount = Number(existing.occurrenceCount || 1) + 1;
        existing.suppressedDuplicateCount = Number(existing.suppressedDuplicateCount || 0) + overflow;
        existing.lastMatchSignature = signature;
        const activityAt = new Date();
        const nextRiskScore = Math.max(existing.riskScore || 0, matchedRisk);
        const shouldNotifyUpdate = shouldNotifyCorrelationUpdate(existing, nextRiskScore, activityAt.getTime());
        existing.lastActivityAt = activityAt;
        existing.windowEnd = matched[matched.length - 1].createdAt;
        existing.riskScore = nextRiskScore;
        existing.confidence = Math.max(existing.confidence || 0, matchedConfidence);
        existing.severity = severityFromCorrelationRisk(existing.riskScore);
        existing.iocs = [...new Set([...(existing.iocs || []), ...extractIocs(matched)])].slice(0, 100);
        existing.mitreTechniques = [...new Set([...(existing.mitreTechniques || []), ...intelligence.techniques])];
        existing.mitreTactics = [...new Set([...(existing.mitreTactics || []), ...intelligence.tactics])];
        existing.coveredCapabilityIds = patternCapabilityIds(pattern.id);
        existing.incidentSource = correlationIncidentSource(pattern, matched);
        if (shouldNotifyUpdate) existing.lastNotifiedAt = activityAt;
        const correlation = await existing.save();
        await Alert.updateMany({ _id: { $in: matched.map(alert => alert._id) }, companyId: cid }, { $addToSet: { correlationIds: correlation._id } });
        await syncIncident(correlation);
        if (shouldNotifyUpdate) {
          setImmediate(() => require('./soar.service').runSoarForCorrelation(correlation, 'updated')
            .catch(err => console.error('[CORRELATION->SOAR]', err.message)));
        }
        if (shouldNotifyUpdate) detected.push(correlation);
        const payload = { change: 'updated', event: correlation };
        if (io && shouldNotifyUpdate) {
          io.to(`company:${companyId}`).emit('correlation:updated', payload);
          io.to('superadmin').emit('correlation:updated', payload);
        }
        if (CORRELATION_DEBUG) {
          console.debug(`[CORRELATION] decision=${shouldNotifyUpdate ? 'updated' : 'updated_suppressed'} company=${companyId} pattern=${pattern.id} endpoint=${sysData.agentName} occurrence=${correlation.occurrenceCount} signature=${signature}`);
        }
        continue;
      }

      const correlation = await CorrelationEvent.create({
        tenantId: matched[0].tenantId || null,
        partnerId: matched[0].partnerId || null,
        companyId: cid,
        departmentId: sysData.departmentId,
        systemId:     sysData.systemId,
        patternId:    pattern.id,
        patternName:  pattern.name,
        incidentSource: correlationIncidentSource(pattern, matched),
        description:  pattern.description,
        alertIds:     matched.map(a => a._id),
        relatedAlertIds: matched.map(a => a._id),
        agentName:    sysData.agentName,
        severity:     severityFromCorrelationRisk(matchedRisk),
        confidence:   matchedConfidence,
        riskScore:    matchedRisk,
        mitreTechniques: intelligence.techniques,
        mitreTactics: intelligence.tactics,
        coveredCapabilityIds: patternCapabilityIds(pattern.id),
        iocs: extractIocs(matched),
        evidence: matched.map(a => ({ alertId: a._id, ruleId: a.ruleId, source: a.source, observedAt: a.createdAt })),
        timeline: alertTimeline(matched),
        eventCount: matched.length,
        occurrenceCount: 1,
        lastMatchSignature: signature,
        lastActivityAt: new Date(),
        lastNotifiedAt: new Date(),
        windowStart:  matched[0].createdAt,
        windowEnd:    matched[matched.length - 1].createdAt,
      });
      await Alert.updateMany({ _id: { $in: matched.map(alert => alert._id) }, companyId: cid }, { $addToSet: { correlationIds: correlation._id } });

      detected.push(correlation);
      await syncIncident(correlation);
      setImmediate(() => require('./soar.service').runSoarForCorrelation(correlation, 'created')
        .catch(err => console.error('[CORRELATION->SOAR]', err.message)));
      autoScanCorrelationFinding(correlation, { io, source: 'correlation_event' }).catch((err) => {
        console.error('[CORRELATION] Velociraptor auto-scan error:', err.message);
      });
      const payload = { change: 'created', event: correlation };
      if (io) {
        io.to(`company:${companyId}`).emit('correlation:new', payload);
        io.to('superadmin').emit('correlation:new', payload);
      }
      if (CORRELATION_DEBUG) {
        console.debug(`[CORRELATION] decision=created company=${companyId} pattern=${pattern.id} endpoint=${sysData.agentName} alerts=${matched.map(a=>a._id).join(',')}`);
      }
    }
  }

  return detected;
}

async function detectCorrelations(companyId, options = {}) {
  const key = String(companyId || '');
  if (companyRuns.has(key)) return companyRuns.get(key);
  const run = detectCorrelationsInternal(key, options).finally(() => companyRuns.delete(key));
  companyRuns.set(key, run);
  return run;
}

// ── Schedule: run correlation every 5 minutes ─────────────────────────────────
async function runCorrelationForAllCompanies(io = null) {
  try {
    const Company = require('../models/Company.model');
    const companies = await Company.find({ status: 'active', 'plan.isActive': true }).select('_id').lean();
    let total = 0;
    for (const c of companies) {
      const hits = await detectCorrelations(c._id.toString(), { io });
      total += hits.length;
    }
    if (total > 0) console.log(`[CORRELATION] cycle complete — ${total} new correlation(s) found`);
  } catch (err) {
    console.error('[CORRELATION] scheduler error:', err.message);
  }
}

function scheduleCorrelation(io = null) {
  // Run on startup
  setTimeout(() => runCorrelationForAllCompanies(io), 30_000); // 30s after server start
  // Then every 5 minutes
  setInterval(() => runCorrelationForAllCompanies(io), 5 * 60 * 1000);
  console.log('[CORRELATION] Scheduler started (5-min intervals)');
}

function scheduleCompanyCorrelation(companyId, io, delayMs = 1000) {
  const key = String(companyId || '');
  if (!mongoose.isValidObjectId(key)) return;
  if (realtimeTimers.has(key)) clearTimeout(realtimeTimers.get(key));
  const timer = setTimeout(() => {
    realtimeTimers.delete(key);
    detectCorrelations(key, { io }).catch(err => {
      console.error(`[CORRELATION] realtime company=${key} error=${err.message}`);
    });
  }, delayMs);
  timer.unref?.();
  realtimeTimers.set(key, timer);
}

module.exports = {
  PATTERNS, PATTERN_INTELLIGENCE, EDR_CAPABILITY_COVERAGE, patternCapabilityIds,
  alertTimeline, calculateRisk, severityFromCorrelationRisk, calculateCorrelationConfidence, extractIocs,
  correlationIncidentSource,
  assignThreatIntelligenceIncident,
  ROUTINE_RULE_IDS, correlationEligibleFilter,
  correlationGroupKey,
  CUSTOM_FIELDS, conditionMatches, customRuleToPattern, publicPattern,
  applyBuiltInOverride,
  incidentCategory, syncIncident,
  isConfirmedMalware, isSuspiciousOutbound,
  isRansomwareImpact, isSuspiciousExecution,
  isCredentialAccess, isHighConfidenceEdrExecution, isThreatIntelNetwork,
  matchPatternAlerts, matchLatestPatternAlerts, matchSignature, mergeByAlertId,
  shouldNotifyCorrelationUpdate,
  detectCorrelations, scheduleCorrelation,
  runCorrelationForAllCompanies, scheduleCompanyCorrelation,
};
