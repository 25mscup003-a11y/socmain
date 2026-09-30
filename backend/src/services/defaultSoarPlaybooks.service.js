const ResponsePlaybook = require('../models/ResponsePlaybook.model');

const step = (order, actionType, description, requireApproval = false, actionParams = {}) => ({
  order,
  actionType,
  description,
  requireApproval,
  continueOnFail: true,
  actionParams,
});

const DEFAULT_SOAR_PLAYBOOKS = [
  {
    builtInKey: 'ransomware-containment',
    name: 'Ransomware Containment',
    description: 'Isolate the affected endpoint, open an incident, and notify the SOC team when ransomware behavior is detected.',
    priority: 10,
    conditionLogic: 'OR',
    conditions: [
      { field: 'threatCategory', operator: 'contains', value: 'ransomware' },
      { field: 'description', operator: 'contains', value: 'ransomware' },
    ],
    steps: [
      step(1, 'isolate_agent', 'Isolate the affected endpoint', true),
      step(2, 'create_incident', 'Create a ransomware incident'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'ransomware', 'endpoint'],
  },
  {
    builtInKey: 'phishing-response',
    name: 'Phishing Email Response',
    description: 'Create a SOC ticket and notify responders for suspected phishing alerts.',
    priority: 20,
    conditionLogic: 'OR',
    conditions: [
      { field: 'threatCategory', operator: 'contains', value: 'phishing' },
      { field: 'description', operator: 'contains', value: 'phishing' },
    ],
    steps: [
      step(1, 'create_ticket', 'Create and route a phishing investigation ticket'),
      step(2, 'notify_soc_manager', 'Notify the SOC manager'),
      step(3, 'send_email', 'Email the incident response contacts'),
    ],
    tags: ['built-in', 'phishing', 'email'],
  },
  {
    builtInKey: 'malware-containment',
    name: 'Malware Endpoint Containment',
    description: 'Quarantine an endpoint and open an incident for confirmed malware activity.',
    priority: 30,
    conditionLogic: 'OR',
    conditions: [
      { field: 'malwareType', operator: 'contains', value: 'malware' },
      { field: 'threatCategory', operator: 'contains', value: 'malware' },
    ],
    steps: [
      step(1, 'quarantine_endpoint', 'Quarantine the affected endpoint', true),
      step(2, 'create_incident', 'Create a malware incident'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'malware', 'endpoint'],
  },
  {
    builtInKey: 'brute-force-account-protection',
    name: 'Brute Force Account Protection',
    description: 'Disable the targeted account after approval and open an investigation for brute-force activity.',
    priority: 40,
    conditionLogic: 'OR',
    conditions: [
      { field: 'ruleId', operator: 'contains', value: 'brute' },
      { field: 'description', operator: 'contains', value: 'brute force' },
    ],
    steps: [
      step(1, 'disable_user', 'Disable the targeted user account', true),
      step(2, 'create_incident', 'Create an identity-security incident'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'identity', 'brute-force'],
  },
  {
    builtInKey: 'command-control-beacon',
    name: 'Command & Control Beacon Containment',
    description: 'Block the remote address, isolate the endpoint, and create an incident for C2 beaconing.',
    priority: 50,
    conditionLogic: 'OR',
    conditions: [
      { field: 'description', operator: 'contains', value: 'beacon' },
      { field: 'threatCategory', operator: 'contains', value: 'command and control' },
    ],
    steps: [
      step(1, 'block_ip', 'Block the detected remote IP', true),
      step(2, 'isolate_agent', 'Isolate the affected endpoint', true),
      step(3, 'create_incident', 'Create a command-and-control incident'),
    ],
    tags: ['built-in', 'c2', 'network'],
  },
  {
    builtInKey: 'data-exfiltration-response',
    name: 'Data Exfiltration Response',
    description: 'Contain the endpoint and escalate suspected data-loss activity to incident response.',
    priority: 60,
    conditionLogic: 'OR',
    conditions: [
      { field: 'description', operator: 'contains', value: 'exfiltration' },
      { field: 'eventCategory', operator: 'contains', value: 'data_loss' },
    ],
    steps: [
      step(1, 'isolate_agent', 'Isolate the source endpoint', true),
      step(2, 'create_incident', 'Create a data-loss incident'),
      step(3, 'send_email', 'Notify incident response contacts'),
    ],
    tags: ['built-in', 'data-loss', 'exfiltration'],
  },
  {
    builtInKey: 'privilege-escalation-response',
    name: 'Privilege Escalation Response',
    description: 'Protect the affected identity and create an incident for privilege-escalation activity.',
    priority: 70,
    conditionLogic: 'OR',
    conditions: [
      { field: 'description', operator: 'contains', value: 'privilege escalation' },
      { field: 'mitreId', operator: 'eq', value: 'T1068' },
    ],
    steps: [
      step(1, 'disable_user', 'Disable the affected user account', true),
      step(2, 'create_incident', 'Create a privilege-escalation incident'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'identity', 'privilege-escalation'],
  },
  {
    builtInKey: 'suspicious-powershell-response',
    name: 'Suspicious PowerShell Response',
    description: 'Contain endpoints showing suspicious PowerShell or script execution behavior.',
    priority: 80,
    conditionLogic: 'OR',
    conditions: [
      { field: 'processName', operator: 'contains', value: 'powershell' },
      { field: 'description', operator: 'contains', value: 'suspicious script' },
    ],
    steps: [
      step(1, 'quarantine_endpoint', 'Quarantine the affected endpoint', true),
      step(2, 'create_ticket', 'Create a script investigation ticket'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'powershell', 'script'],
  },
  {
    builtInKey: 'dns-tunneling-response',
    name: 'DNS Tunneling Response',
    description: 'Block the detected remote address and open an incident for suspected DNS tunneling.',
    priority: 90,
    conditionLogic: 'OR',
    conditions: [
      { field: 'description', operator: 'contains', value: 'dns tunneling' },
      { field: 'ruleId', operator: 'contains', value: 'dns-tunnel' },
    ],
    steps: [
      step(1, 'block_ip', 'Block the detected remote IP', true),
      step(2, 'create_incident', 'Create a DNS tunneling incident'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'dns', 'network'],
  },
  {
    builtInKey: 'critical-alert-triage',
    name: 'Critical Alert Triage',
    description: 'Provide a standard catch-all triage workflow for critical alerts not matched by a specialized playbook.',
    priority: 100,
    conditionLogic: 'AND',
    conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
    steps: [
      step(1, 'set_alert_status', 'Move the alert into investigation', false, { status: 'investigating' }),
      step(2, 'create_ticket', 'Create and route a critical-alert ticket'),
      step(3, 'notify_soc_manager', 'Notify the SOC manager'),
    ],
    tags: ['built-in', 'critical', 'triage'],
  },
].map(playbook => ({
  ...playbook,
  isBuiltIn: true,
  enabled: true,
  executionMode: 'approval_required',
  requireGlobalApproval: true,
  stopOnMatch: true,
  maxExecutionsPerHour: 10,
  timeoutMs: 60_000,
  retryCount: 1,
  cooldownMinutes: 30,
  rollbackEnabled: true,
  dryRun: false,
  simulationMode: false,
}));

async function ensureDefaultSoarPlaybooks({ companyId, tenantId = null, partnerId = null, createdBy = null }) {
  if (!companyId) return [];
  await ResponsePlaybook.bulkWrite(DEFAULT_SOAR_PLAYBOOKS.map(playbook => ({
    updateOne: {
      filter: { companyId, builtInKey: playbook.builtInKey },
      update: {
        $setOnInsert: {
          ...playbook,
          tenantId,
          partnerId,
          companyId,
          departmentId: null,
          createdBy,
        },
      },
      upsert: true,
    },
  })), { ordered: false });
  return ResponsePlaybook.find({
    companyId,
    builtInKey: { $in: DEFAULT_SOAR_PLAYBOOKS.map(playbook => playbook.builtInKey) },
  }).sort({ priority: 1 }).lean();
}

module.exports = { DEFAULT_SOAR_PLAYBOOKS, ensureDefaultSoarPlaybooks };
