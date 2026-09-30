import { useCallback, useEffect, useState } from 'react';
import api from '../api/axios';
import toast from 'react-hot-toast';
import { connectSocket, io, SOCKET_URL } from '../api/config';
import { useAuth } from '../context/AuthContext';

// ── Status Badge Component ─────────────────────────────────────────────────────
const BADGE_COLORS = {
  running: { bg: '#1e3a8a', text: '#93c5fd' },
  completed: { bg: '#064e3b', text: '#34d399' },
  success: { bg: '#064e3b', text: '#34d399' },
  failed: { bg: '#7f1d1d', text: '#fca5a5' },
  waiting_for_approval: { bg: '#78350f', text: '#fde68a' },
  waiting_for_agent: { bg: '#164e63', text: '#67e8f9' },
  pending: { bg: '#78350f', text: '#fde68a' },
  cancelled: { bg: '#374151', text: '#9ca3af' },
  rolled_back: { bg: '#581c87', text: '#e9d5ff' },
};

function StatusBadge({ status }) {
  const cfg = BADGE_COLORS[status] || { bg: '#1e293b', text: '#94a3b8' };
  return (
    <span style={{
      fontSize: 10, padding: '2px 8px', borderRadius: 12, fontWeight: 600,
      background: cfg.bg, color: cfg.text, textTransform: 'uppercase', letterSpacing: '0.5px',
      display: 'inline-flex', alignItems: 'center', gap: 4,
    }}>
      <span style={{ width: 6, height: 6, borderRadius: '50%', background: cfg.text }} />
      {status ? status.replace(/_/g, ' ') : 'unknown'}
    </span>
  );
}

function formatAuditValue(value, prefix = '') {
  if (value === null || value === undefined || value === '') return '—';
  if (typeof value !== 'object') return String(value);
  if (Array.isArray(value)) {
    return value.map((item, index) => (
      typeof item === 'object' && item !== null
        ? formatAuditValue(item, `${prefix}Item ${index + 1}`)
        : `${prefix}Item ${index + 1}: ${String(item)}`
    )).join('\n');
  }

  return Object.entries(value).flatMap(([key, item]) => {
    const label = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2').replace(/_/g, ' ');
    const field = prefix ? `${prefix} · ${label}` : label;
    if (item && typeof item === 'object') return formatAuditValue(item, field).split('\n');
    return `${field}: ${item === null || item === undefined || item === '' ? '—' : String(item)}`;
  }).join('\n');
}

const CATEGORIES = ['IDS', 'IPS', 'EDR', 'Firewall'];

const TRIGGER_SOURCE_GROUPS = {
  EDR: [
    { value: 'new_alert', label: 'All EDR Security Alerts' },
    { value: 'anomaly_detected', label: 'Endpoint Anomaly Detected' },
    { value: 'ioc_detected', label: 'Threat Intel IOC Detected' },
  ],
  IDS: [
    { value: 'ids_alert', label: 'All IDS Alerts' },
    { value: 'suricata_alert', label: 'Suricata IDS Alert' },
    { value: 'zeek_event', label: 'Zeek Network Event' },
  ],
  IPS: [
    { value: 'ips_alert', label: 'All IPS Alerts' },
  ],
  Firewall: [
    { value: 'firewall_alert', label: 'All Firewall Alerts' },
  ],
  Correlation: [
    { value: 'correlation_created', label: 'Correlation Match Created' },
    { value: 'correlation_updated', label: 'Correlation Match Updated' },
  ],
};

const FIREWALL_TRIGGER_CATEGORIES = [
  { value: 'all', label: 'All firewall activity' },
  { value: 'ip_activity', label: 'IP activity' },
  { value: 'domain_activity', label: 'Domain activity' },
  { value: 'port_activity', label: 'Port activity' },
  { value: 'protocol_activity', label: 'Protocol activity' },
  { value: 'application_activity', label: 'Application activity' },
];

const EDR_TRIGGER_CATEGORIES = [
  { value: 'all', label: 'All EDR capabilities' },
  { value: 'process_activity', label: 'Process activity' },
  { value: 'file_activity_fim', label: 'File activity / FIM' },
  { value: 'network_activity', label: 'Network activity' },
  { value: 'user_authentication', label: 'User & authentication' },
  { value: 'memory_activity', label: 'Memory activity' },
  { value: 'registry_monitoring', label: 'Registry monitoring' },
  { value: 'system_changes', label: 'System changes' },
  { value: 'persistence', label: 'Persistence' },
  { value: 'web_dns', label: 'Web & DNS' },
  { value: 'usb_devices', label: 'USB devices' },
  { value: 'behavior_analytics', label: 'Behavior analytics' },
  { value: 'data_security', label: 'Data security' },
  { value: 'credential_security', label: 'Credential security' },
  { value: 'lateral_movement', label: 'Lateral movement' },
  { value: 'email_threats', label: 'Email threats' },
  { value: 'insider_threats', label: 'Insider threats' },
  { value: 'patch_vulnerability', label: 'Patch & vulnerability' },
  { value: 'sandbox_analysis', label: 'Sandbox analysis' },
  { value: 'kernel_monitoring', label: 'Kernel monitoring' },
  { value: 'api_calls', label: 'API calls' },
  { value: 'script_execution', label: 'Script execution' },
  { value: 'time_anomaly', label: 'Time anomaly' },
  { value: 'geolocation_anomaly', label: 'Geolocation anomaly' },
  { value: 'service_monitoring', label: 'Service monitoring' },
  { value: 'hash_signature_analysis', label: 'Hash/signature analysis' },
  { value: 'beaconing', label: 'Beaconing' },
  { value: 'encryption_ransomware', label: 'Encryption / ransomware' },
  { value: 'living_off_the_land', label: 'Living-off-the-Land' },
  { value: 'memory_overflow', label: 'Memory overflow' },
  { value: 'dns_cache_poisoning', label: 'DNS cache poisoning' },
  { value: 'dns_sinkhole', label: 'DNS sinkhole' },
];

function monitoringCategories(sourceGroup) {
  if (sourceGroup === 'Firewall') return FIREWALL_TRIGGER_CATEGORIES;
  if (sourceGroup === 'EDR') return EDR_TRIGGER_CATEGORIES;
  return null;
}

function triggerSourceGroup(triggerType) {
  return Object.entries(TRIGGER_SOURCE_GROUPS).find(([, options]) => options.some(option => option.value === triggerType))?.[0] || 'EDR';
}

const DEFAULT_TEMPLATES = [
  { name: 'Malicious IP Containment Playbook', category: 'IDS / IPS', description: 'Enrich source IP using threat intel, check allowlist, and block IP in firewall or IPS', riskLevel: 'critical' },
  { name: 'Phishing Email Response Playbook', category: 'Email Security', description: 'Parse suspicious email, extract links, block sender, and notify SOC team', riskLevel: 'high' },
  { name: 'Malware Endpoint Response Playbook', category: 'EDR / Endpoint', description: 'Capture malicious file hash, isolate infected host from network, and alert SOC Manager', riskLevel: 'critical' },
  { name: 'Brute-Force Authentication Defense', category: 'Identity / IAM', description: 'Detect repeated auth failures, revoke active user sessions, and force password reset', riskLevel: 'medium' },
  { name: 'Ransomware Outbreak Containment', category: 'EDR / Outbreak', description: 'Immediately isolate affected endpoint, kill suspicious child processes, and notify L3 analysts', riskLevel: 'critical' },
  { name: 'Data Exfiltration Defense', category: 'Firewall / Network', description: 'Detect high volume outbound network transfer, block destination domain, and open critical ticket', riskLevel: 'critical' },
  { name: 'Suricata IDS Automatic Block', category: 'IDS', description: 'Automatically create incident and dispatch firewall block for high confidence Suricata IDS alerts', riskLevel: 'high' },
  { name: 'Zeek Anomaly Ticket Escalation', category: 'IDS / IPS', description: 'Correlate Zeek DNS/HTTP anomalies, open support ticket, and escalate to L2 analyst', riskLevel: 'medium' },
  { name: 'SQL Injection WAF Mitigation', category: 'Firewall', description: 'Detect SQL injection payload on web application firewall, block attacker IP, and update WAF rules', riskLevel: 'high' },
  { name: 'DNS Tunneling & C2 Sinkhole', category: 'IDS', description: 'Detect suspicious DNS query patterns, sinkhole malicious domain, and block communication', riskLevel: 'high' },
  { name: 'Insider Threat Privilege Escalation Containment', category: 'Identity / IAM', description: 'Detect unauthorized sudo/admin privilege escalation, revoke active tokens, and notify SOC Manager', riskLevel: 'critical' },
  { name: 'Cryptomining Process Kill & Quarantine', category: 'EDR', description: 'Detect CPU mining processes (XMRig, MinerD), terminate process, and quarantine binary file', riskLevel: 'medium' },
  { name: 'Unauthorized USB Storage Device Isolation', category: 'EDR', description: 'Detect unapproved USB storage insertion, disable USB port interface, and trigger security warning', riskLevel: 'low' },
  { name: 'Stolen OAuth Token Revocation', category: 'Identity / IAM', description: 'Detect anomalous API token usage from unexpected geographic location, invalidate token, and log audit event', riskLevel: 'high' },
  { name: 'DDoS Attack Rate Limiting', category: 'Firewall / IPS', description: 'Detect high volume SYN/HTTP flood, enforce temporary rate limit, and block attacking subnet CIDR', riskLevel: 'critical' },
  { name: 'File Integrity Breach Auto-Recovery', category: 'EDR / FIM', description: 'Detect unauthorized modification to critical system configuration files and restore file from baseline', riskLevel: 'high' },
];

const TEMPLATE_RULE_PRESETS = {
  'Malicious IP Containment Playbook': { triggerType: 'suricata_alert', actions: ['block_ip', 'create_incident'] },
  'Phishing Email Response Playbook': { triggerType: 'email_alert', actions: ['send_email', 'create_ticket'] },
  'Malware Endpoint Response Playbook': { triggerType: 'new_alert', actions: ['isolate_agent', 'create_incident'] },
  'Brute-Force Authentication Defense': { triggerType: 'new_alert', actions: ['disable_user', 'notify_soc_manager'] },
  'Ransomware Outbreak Containment': { triggerType: 'new_alert', actions: ['isolate_agent', 'escalate_l3'] },
  'Data Exfiltration Defense': { triggerType: 'zeek_event', actions: ['block_ip', 'create_ticket'] },
  'Suricata IDS Automatic Block': { triggerType: 'suricata_alert', actions: ['block_ip', 'create_incident'] },
  'Zeek Anomaly Ticket Escalation': { triggerType: 'zeek_event', actions: ['create_ticket', 'escalate_l2'] },
  'SQL Injection WAF Mitigation': { triggerType: 'new_alert', actions: ['block_ip', 'add_firewall_rule'] },
  'DNS Tunneling & C2 Sinkhole': { triggerType: 'zeek_event', actions: ['block_domain', 'add_ioc'] },
  'Insider Threat Privilege Escalation Containment': { triggerType: 'new_alert', actions: ['revoke_token', 'notify_soc_manager'] },
  'Cryptomining Process Kill & Quarantine': { triggerType: 'new_alert', actions: ['kill_process', 'delete_file'] },
  'Unauthorized USB Storage Device Isolation': { triggerType: 'new_alert', actions: ['isolate_agent'] },
  'Stolen OAuth Token Revocation': { triggerType: 'new_alert', actions: ['revoke_token', 'send_email'] },
  'DDoS Attack Rate Limiting': { triggerType: 'ips_alert', actions: ['add_firewall_rule', 'notify_company_admin'] },
  'File Integrity Breach Auto-Recovery': { triggerType: 'new_alert', actions: ['run_script'] },
};

function templateCategory(template) {
  const value = String(template.category || '').toLowerCase();
  if (value.includes('firewall')) return 'Firewall';
  if (value.includes('ips') && !value.includes('ids')) return 'IPS';
  if (value.includes('ids')) return 'IDS';
  return 'EDR';
}

function templateTriggerSubtype(template, triggerType) {
  const aliases = {
    auth: 'user_authentication', login_anomaly: 'user_authentication',
    process: 'process_activity', edr: 'all', ransomware: 'encryption_ransomware',
    fim: 'file_activity_fim', usb: 'usb_devices', device: 'usb_devices',
    network: 'network_activity', cloud: 'all',
  };
  const requested = aliases[template.supportedAlertTypes?.[0]] || template.supportedAlertTypes?.[0] || 'all';
  const categories = monitoringCategories(triggerSourceGroup(triggerType));
  return categories?.some(option => option.value === requested) ? requested : 'all';
}

function templateRuleForm(template, departmentId = '') {
  const preset = TEMPLATE_RULE_PRESETS[template.name] || {};
  const triggerType = template.triggerType || preset.triggerType || 'new_alert';
  const riskLevel = ['low', 'medium', 'high', 'critical'].includes(template.riskLevel)
    ? template.riskLevel
    : 'medium';
  const sourceActions = Array.isArray(template.actions) && template.actions.length
    ? template.actions
    : (preset.actions || ['create_incident']).map(type => ({ type }));
  const actions = sourceActions.map(action => ({
    type: action.type || action.actionType || 'create_incident',
    payload: action.payload || action.actionParams || {},
    requireApproval: action.requireApproval === true,
    riskLevel: action.riskLevel || riskLevel,
    maxRetries: Number(action.maxRetries ?? action.retryCount ?? 3),
    retryBackoffSec: Number(action.retryBackoffSec ?? 5),
  }));
  const requiresApproval = actions.some(action => action.requireApproval);
  return {
    ...EMPTY_RULE,
    name: template.name || 'Template Automation Rule',
    description: template.description || '',
    departmentId,
    category: templateCategory(template),
    triggerType,
    triggerSubtype: templateTriggerSubtype(template, triggerType),
    executionMode: requiresApproval ? 'approval_required' : 'automatic',
    matchLogic: template.conditionLogic === 'OR' ? 'ANY' : 'ALL',
    conditions: Array.isArray(template.conditions) && template.conditions.length
      ? template.conditions.map(condition => ({ ...condition, operator: condition.operator === 'neq' ? 'not_eq' : condition.operator }))
      : [{ field: 'severity', operator: 'eq', value: riskLevel }],
    actions,
  };
}

const EMPTY_RULE = {
  name: '',
  description: '',
  departmentId: '',
  category: 'IDS',
  priority: 10,
  triggerType: 'suricata_alert',
  triggerSubtype: 'all',
  executionMode: 'automatic',
  enabled: true,
  stopOnMatch: false,
  matchLogic: 'ALL',
  dedupWindowMinutes: 5,
  maxExecutionsPerHour: 100,
  conditions: [
    { field: 'severity', operator: 'eq', value: 'critical' },
    { field: 'srcip', operator: 'not_eq', value: '127.0.0.1' },
  ],
  actions: [
    { type: 'block_ip', payload: {}, requireApproval: false, riskLevel: 'high', maxRetries: 3, retryBackoffSec: 5 },
    { type: 'create_incident', payload: {}, requireApproval: false, riskLevel: 'medium', maxRetries: 2, retryBackoffSec: 2 },
    { type: 'notify_soc_manager', payload: {}, requireApproval: false, riskLevel: 'low', maxRetries: 1, retryBackoffSec: 1 },
  ],
  autoDisableFailureThreshold: 5,
};

const EMPTY_CONNECTOR = {
  name: '', type: 'generic_rest', baseUrl: '', authType: 'none', timeoutMs: 8000, rateLimitPerMinute: 60, status: 'enabled',
};

const EMPTY_PLAYBOOK = {
  name: '', description: '', enabled: true, priority: 100, executionMode: 'automatic',
  conditionLogic: 'AND',
  conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
  steps: [{ order: 1, actionType: 'block_ip', connectorId: '', actionParams: {}, requireApproval: false, continueOnFail: true }],
};

export default function SoarPage({ defaultTab = 'dashboard' }) {
  const { user } = useAuth();
  const canManageCredentials = ['superadmin', 'partner_admin', 'company_admin'].includes(user?.role);
  const [activeTab, setActiveTab] = useState(defaultTab);

  useEffect(() => {
    setActiveTab(defaultTab);
  }, [defaultTab]);
  const [summary, setSummary] = useState(null);
  const [rules, setRules] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [executions, setExecutions] = useState([]);
  const [approvals, setApprovals] = useState([]);
  const [connectors, setConnectors] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [templates, setTemplates] = useState(DEFAULT_TEMPLATES);
  const [auditLogs, setAuditLogs] = useState([]);
  const [auditVerification, setAuditVerification] = useState(null);
  const [auditPage, setAuditPage] = useState(1);
  const [auditTotal, setAuditTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');

  // Modals & Wizard State
  const [ruleModalOpen, setRuleModalOpen] = useState(false);
  const [wizardStep, setWizardStep] = useState(1);
  const [ruleForm, setRuleForm] = useState(EMPTY_RULE);
  const [savingRule, setSavingRule] = useState(false);
  const [testRunOutput, setTestRunOutput] = useState(null);

  const [connectorModalOpen, setConnectorModalOpen] = useState(false);
  const [connectorForm, setConnectorForm] = useState(EMPTY_CONNECTOR);
  const [playbookModalOpen, setPlaybookModalOpen] = useState(false);
  const [playbookForm, setPlaybookForm] = useState(EMPTY_PLAYBOOK);
  const [savingPlaybook, setSavingPlaybook] = useState(false);
  const [liveAuditOpen, setLiveAuditOpen] = useState(false);
  const [immutableAuditOpen, setImmutableAuditOpen] = useState(false);
  const [selectedAuditLog, setSelectedAuditLog] = useState(null);
  const [metricLogs, setMetricLogs] = useState({ open: false, title: '', outcome: '', rows: [], total: 0, page: 1, pages: 1, loading: false });
  const [selectedExecution, setSelectedExecution] = useState(null);
  const [executionAuditLoading, setExecutionAuditLoading] = useState(false);

  const [simPayload, setSimPayload] = useState('{\n  "description": "ET MALWARE Command and Control Traffic",\n  "severity": "critical",\n  "srcip": "198.51.100.45",\n  "agentName": "FINANCE-HOST-09"\n}');
  const [simResult, setSimResult] = useState(null);
  const [credForm, setCredForm] = useState({ name: '', type: 'api_key', secretValue: '' });
  const [vaultAuth, setVaultAuth] = useState(null);
  const [vaultPassword, setVaultPassword] = useState('');
  const [revealedSecrets, setRevealedSecrets] = useState({});
  const [vaultActionBusy, setVaultActionBusy] = useState(false);

  const verifyAuditChain = async () => {
    try {
      const { data } = await api.get('/soar/audit-logs/verify');
      setAuditVerification(data);
      data.valid ? toast.success('Audit hash-chain verification passed') : toast.error(`Audit tampering detected at ${data.brokenAt}`);
    } catch (error) { toast.error(error.response?.data?.message || 'Audit verification failed'); }
  };

  const exportAuditCsv = async () => {
    try {
      const response = await api.get('/soar/audit-logs/export.csv', { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url; link.download = `soar-audit-${new Date().toISOString().slice(0, 10)}.csv`; link.click();
      URL.revokeObjectURL(url);
    } catch { toast.error('Audit export failed'); }
  };

  const exportAuditPdf = async () => {
    try {
      const response = await api.get('/soar/audit-logs/export.pdf', { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url; link.download = `soar-audit-${new Date().toISOString().slice(0, 10)}.pdf`; link.click();
      URL.revokeObjectURL(url);
    } catch { toast.error('Audit PDF export failed'); }
  };

  const loadAuditPage = async page => {
    try {
      const { data } = await api.get('/soar/audit-logs', { params: { page, limit: 100 } });
      setAuditLogs(data.logs || []); setAuditPage(data.page || page); setAuditTotal(data.total || 0);
    } catch { toast.error('Audit page could not be loaded'); }
  };

  const loadAllData = useCallback(async () => {
    setLoading(true);
    const requests = [
      ['summary', api.get('/soar/dashboard/summary')],
      ['rules', api.get('/soar/rules')],
      ['playbooks', api.get('/soar/playbooks')],
      ['executions', api.get('/soar/executions')],
      ['approvals', api.get('/soar/approvals')],
      ['connectors', api.get('/soar/connectors')],
      ['credentials', canManageCredentials ? api.get('/soar/credentials') : Promise.resolve({ data: [] })],
      ['templates', api.get('/soar/templates')],
      ['audit logs', api.get('/soar/audit-logs', { params: { page: 1, limit: 100 } })],
      ['departments', api.get('/department')],
    ];
    const results = await Promise.allSettled(requests.map(([, request]) => request));
    const fulfilled = index => results[index].status === 'fulfilled' ? results[index].value : null;

    const sRes = fulfilled(0); if (sRes) setSummary(sRes.data || {});
    const rRes = fulfilled(1); if (rRes) setRules(rRes.data || []);
    const pRes = fulfilled(2); if (pRes) setPlaybooks(pRes.data || []);
    const eRes = fulfilled(3); if (eRes) setExecutions(eRes.data.executions || []);
    const aRes = fulfilled(4); if (aRes) setApprovals(aRes.data || []);
    const cRes = fulfilled(5); if (cRes) setConnectors(cRes.data || []);
    const crRes = fulfilled(6); if (crRes) setCredentials(crRes.data || []);
    const tRes = fulfilled(7); if (tRes) setTemplates(Array.isArray(tRes.data) && tRes.data.length ? tRes.data : DEFAULT_TEMPLATES);
    const auRes = fulfilled(8); if (auRes) { setAuditLogs(auRes.data.logs || []); setAuditPage(auRes.data.page || 1); setAuditTotal(auRes.data.total || 0); }
    const dRes = fulfilled(9); if (dRes) setDepartments(Array.isArray(dRes.data) ? dRes.data : (dRes.data?.departments || []));

    const failures = results.flatMap((result, index) => {
      if (result.status === 'fulfilled') return [];
      const error = result.reason;
      return [`${requests[index][0]} (${error.response?.status || 'network'}: ${error.response?.data?.message || error.message || 'request failed'})`];
    });
    const message = failures.length ? `Unable to refresh: ${failures.join(', ')}` : '';
    setLoadError(message);
    if (message) toast.error(message);
    setLoading(false);
  }, [canManageCredentials]);

  const openExecutionAudit = async execution => {
    setLiveAuditOpen(true);
    setSelectedExecution(execution || executions[0] || null);
    if (!execution?._id) return;
    setExecutionAuditLoading(true);
    try {
      const { data } = await api.get(`/soar/executions/${execution._id}`);
      setSelectedExecution(data);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Execution audit details could not be loaded');
    } finally {
      setExecutionAuditLoading(false);
    }
  };

  const openMetricLogs = async (title, outcome, page = 1) => {
    setMetricLogs(previous => ({ ...previous, open: true, title, outcome, page, loading: true }));
    try {
      const params = { page, limit: 100 };
      if (outcome && outcome !== 'all') params.outcome = outcome;
      const { data } = await api.get('/soar/executions', { params });
      setMetricLogs({ open: true, title, outcome, rows: data.executions || [], total: data.total || 0, page: data.page || page, pages: data.pages || 1, loading: false });
    } catch (error) {
      setMetricLogs(previous => ({ ...previous, loading: false }));
      toast.error(error.response?.data?.message || 'SOAR logs could not be loaded');
    }
  };

  useEffect(() => { loadAllData(); }, [loadAllData]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const release = connectSocket(socket);
    let timer;
    const refresh = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(loadAllData, 500);
    };
    const events = [
      'soar.execution.created', 'soar.execution.step.started', 'soar.execution.step.completed',
      'soar.execution.step.failed', 'soar.execution.waiting_for_approval',
      'soar.execution.completed', 'soar.approval.approved', 'soar.approval.rejected',
      'soar.execution.rolled_back', 'soar:ai-updated',
    ];
    events.forEach(event => socket.on(event, refresh));
    return () => {
      window.clearTimeout(timer);
      events.forEach(event => socket.off(event, refresh));
      release();
    };
  }, [loadAllData]);

  // Wizard Modal Handlers
  const openNewRuleModal = () => {
    const assignedDepartmentId = typeof user?.departmentId === 'object' ? user.departmentId?._id : user?.departmentId;
    setRuleForm({ ...EMPTY_RULE, departmentId: user?.role === 'department_admin' ? String(assignedDepartmentId || '') : '' });
    setWizardStep(1);
    setTestRunOutput(null);
    setRuleModalOpen(true);
  };

  const openTemplateRuleModal = template => {
    const assignedDepartmentId = typeof user?.departmentId === 'object' ? user.departmentId?._id : user?.departmentId;
    const departmentId = user?.role === 'department_admin' ? String(assignedDepartmentId || '') : '';
    setRuleForm(templateRuleForm(template, departmentId));
    setWizardStep(1);
    setTestRunOutput(null);
    setRuleModalOpen(true);
  };

  const openEditRuleModal = (rule) => {
    setRuleForm({
      ...rule,
      departmentId: String(rule.departmentId?._id || rule.departmentId || ''),
      matchLogic: rule.conditionLogic === 'OR' ? 'ANY' : 'ALL',
      conditions: rule.conditions && rule.conditions.length ? rule.conditions : [{ field: 'severity', operator: 'eq', value: 'critical' }],
      actions: rule.actions && rule.actions.length ? rule.actions : [{ type: 'block_ip', payload: {}, requireApproval: false, riskLevel: 'high' }],
    });
    setWizardStep(1);
    setTestRunOutput(null);
    setRuleModalOpen(true);
  };

  const handleSaveRuleSubmit = async (e) => {
    if (e) e.preventDefault();
    if (!ruleForm.name?.trim()) { toast.error('Rule Name is required'); setWizardStep(1); return; }
    if (!ruleForm.triggerType) { toast.error('Trigger Source is required'); setWizardStep(2); return; }
    if (!ruleForm.executionMode) { toast.error('Automation Mode is required'); setWizardStep(2); return; }
    if (!ruleForm.actions?.length) { toast.error('Select a Playbook or add at least one Action Pipeline step'); setWizardStep(1); return; }
    const invalidCondition = (ruleForm.conditions || []).some(condition => !condition.field?.trim() || !condition.operator || condition.value === '');
    if (invalidCondition) { toast.error('Complete or remove the incomplete Condition row'); setWizardStep(3); return; }
    setSavingRule(true);
    try {
      if (ruleForm._id) {
        const { data } = await api.put(`/soar/rules/${ruleForm._id}`, ruleForm);
        setRules(prev => prev.map(r => r._id === data._id ? data : r));
        toast.success(`SOAR Rule "${data.name}" updated!`);
      } else {
        const { data } = await api.post('/soar/rules', ruleForm);
        setRules(prev => [data, ...prev]);
        toast.success(`SOAR Rule "${data.name}" created successfully!`);
      }
      setRuleModalOpen(false);
      loadAllData();
    } catch (err) { toast.error(err.response?.data?.message || 'Failed to save rule'); }
    finally { setSavingRule(false); }
  };

  const handleDeleteRule = async (id, name) => {
    if (!window.confirm(`Delete rule "${name}"?`)) return;
    try {
      await api.delete(`/soar/rules/${id}`);
      setRules(prev => prev.filter(r => r._id !== id));
      toast.success(`Rule "${name}" deleted`);
    } catch { toast.error('Failed to delete rule'); }
  };

  const handleDeletePlaybook = async (id, name) => {
    if (!window.confirm(`Delete playbook "${name}"?`)) return;
    try {
      await api.delete(`/soar/playbooks/${id}`);
      setPlaybooks(prev => prev.filter(playbook => playbook._id !== id));
      toast.success(`Playbook "${name}" deleted`);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to delete playbook');
    }
  };

  const openNewPlaybookModal = () => {
    setPlaybookForm({ ...EMPTY_PLAYBOOK, conditions: EMPTY_PLAYBOOK.conditions.map(item => ({ ...item })), steps: EMPTY_PLAYBOOK.steps.map(item => ({ ...item })) });
    setPlaybookModalOpen(true);
  };

  const openEditPlaybookModal = (playbook) => {
    setPlaybookForm({
      ...playbook,
      conditions: playbook.conditions?.length ? playbook.conditions.map(item => ({ ...item })) : [{ field: 'severity', operator: 'eq', value: 'critical' }],
      steps: playbook.steps?.length ? playbook.steps.map(item => ({ ...item, connectorId: item.connectorId?._id || item.connectorId || '' })) : [{ order: 1, actionType: 'block_ip', connectorId: '', actionParams: {}, requireApproval: false, continueOnFail: true }],
    });
    setPlaybookModalOpen(true);
  };

  const savePlaybook = async (event) => {
    event.preventDefault();
    if (!playbookForm.name.trim()) return toast.error('Playbook name is required');
    if (!playbookForm.steps.length) return toast.error('At least one playbook action is required');
    setSavingPlaybook(true);
    try {
      const payload = {
        ...playbookForm,
        steps: playbookForm.steps.map((step, index) => ({ ...step, order: index + 1 })),
      };
      const { data } = playbookForm._id
        ? await api.put(`/soar/playbooks/${playbookForm._id}`, payload)
        : await api.post('/soar/playbooks', payload);
      setPlaybooks(prev => playbookForm._id
        ? prev.map(item => item._id === data._id ? data : item)
        : [data, ...prev]);
      toast.success(`Playbook "${data.name}" ${playbookForm._id ? 'updated' : 'created'}`);
      setPlaybookModalOpen(false);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to save playbook');
    } finally {
      setSavingPlaybook(false);
    }
  };

  const handleToggleRule = async (rule) => {
    try {
      const endpoint = rule.enabled ? `/soar/rules/${rule._id}/disable` : `/soar/rules/${rule._id}/activate`;
      const { data } = await api.post(endpoint);
      setRules(prev => prev.map(r => r._id === data._id ? data : r));
      toast.success(`Rule "${data.name}" ${data.enabled ? 'activated' : 'disabled'}`);
    } catch { toast.error('Failed to toggle rule'); }
  };

  // Condition Form Helpers
  const addConditionItem = () => {
    setRuleForm(prev => ({
      ...prev,
      conditions: [...prev.conditions, { field: 'signature', operator: 'contains', value: 'MALWARE' }],
    }));
  };

  const updateConditionItem = (index, field, value) => {
    setRuleForm(prev => {
      const updated = [...prev.conditions];
      updated[index] = { ...updated[index], [field]: value };
      return { ...prev, conditions: updated };
    });
  };

  const removeConditionItem = (index) => {
    setRuleForm(prev => ({
      ...prev,
      conditions: prev.conditions.filter((_, idx) => idx !== index),
    }));
  };

  // Action Form Helpers
  const addActionItem = () => {
    setRuleForm(prev => ({
      ...prev,
      actions: [...prev.actions, { type: 'create_ticket', payload: {}, requireApproval: false, riskLevel: 'low', maxRetries: 2, retryBackoffSec: 2 }],
    }));
  };

  const updateActionItem = (index, field, value) => {
    setRuleForm(prev => {
      const updated = [...prev.actions];
      updated[index] = { ...updated[index], [field]: value };
      return { ...prev, actions: updated };
    });
  };

  const removeActionItem = (index) => {
    setRuleForm(prev => ({
      ...prev,
      actions: prev.actions.filter((_, idx) => idx !== index),
    }));
  };

  const handleTestRunDryRun = async () => {
    try {
      const samplePayload = {
        severity: 'critical',
        srcip: '198.51.100.45',
        signature: 'ET MALWARE Command and Control Traffic',
        agentName: 'FINANCE-HOST-09',
      };
      const { data } = await api.post('/soar/simulator', { eventPayload: samplePayload, rule: ruleForm });
      setTestRunOutput(data);
      toast.success('Dry-Run Test Passed!');
    } catch {
      setTestRunOutput(null);
      toast.error('Dry-run failed. No simulated success result was generated.');
    }
  };

  // Approvals & Connectors Handlers
  const handleApprove = async (approval) => {
    try {
      const endpoint = approval.source === 'automated_response'
        ? `/soar/approvals/automated-response/${approval.approvalId || approval._id}/approve`
        : `/soar/approvals/${approval.approvalId || approval._id}/approve`;
      await api.post(endpoint, { notes: 'Approved via unified SOAR Command Center' });
      toast.success('Approval granted — Execution resumed');
      loadAllData();
    } catch { toast.error('Approval failed'); }
  };

  const handleReject = async (approval) => {
    try {
      const endpoint = approval.source === 'automated_response'
        ? `/soar/approvals/automated-response/${approval.approvalId || approval._id}/reject`
        : `/soar/approvals/${approval.approvalId || approval._id}/reject`;
      await api.post(endpoint, { notes: 'Rejected via unified SOAR Command Center' });
      toast.success('Approval request rejected');
      loadAllData();
    } catch { toast.error('Rejection failed'); }
  };

  const handleBulkApprove = async () => {
    const pending = approvals.filter(a => a.status === 'pending');
    if (!pending.length) return;
    try {
      await Promise.all(pending.map(handle => {
        const endpoint = handle.source === 'automated_response'
          ? `/soar/approvals/automated-response/${handle.approvalId || handle._id}/approve`
          : `/soar/approvals/${handle.approvalId || handle._id}/approve`;
        return api.post(endpoint, { notes: 'Bulk approved by SOC Manager' });
      }));
      toast.success(`Bulk approved ${pending.length} requests`);
      loadAllData();
    } catch { toast.error('Bulk approval failed'); }
  };

  const handleTestConnector = async (id) => {
    try {
      const { data } = await api.post(`/soar/connectors/${id}/test`);
      toast.success(`Connector check: ${data.status.toUpperCase()}`);
      loadAllData();
    } catch { toast.error('Connector test failed'); }
  };

  const handleRetryExecution = async (id) => {
    try {
      const { data } = await api.post(`/soar/executions/${id}/retry`);
      toast.success(data.message || 'SOAR execution retry started');
      loadAllData();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Retry failed');
    }
  };

  const handleSaveCredential = async (e) => {
    e.preventDefault();
    try {
      await api.post('/soar/credentials', credForm);
      toast.success('Secret safely stored in AES-256-GCM Vault');
      setCredForm({ name: '', type: 'api_key', secretValue: '' });
      loadAllData();
    } catch { toast.error('Failed to store credential'); }
  };

  const handleVaultProtectedAction = async event => {
    event.preventDefault();
    if (!vaultAuth?.credential || !vaultPassword) return;
    setVaultActionBusy(true);
    try {
      const credential = vaultAuth.credential;
      if (vaultAuth.mode === 'reveal') {
        const { data } = await api.post(`/soar/credentials/${credential._id}/reveal`, { currentPassword: vaultPassword });
        setRevealedSecrets(previous => ({ ...previous, [credential._id]: data.secretValue }));
        window.setTimeout(() => setRevealedSecrets(previous => { const next = { ...previous }; delete next[credential._id]; return next; }), (data.expiresInSeconds || 30) * 1000);
        toast.success('Secret revealed for 30 seconds');
      } else {
        const { data } = await api.delete(`/soar/credentials/${credential._id}`, { data: { currentPassword: vaultPassword } });
        setCredentials(previous => previous.filter(item => item._id !== credential._id));
        const removed = new Set((data.removedConnectorIds || []).map(String));
        if (removed.size) setConnectors(previous => previous.filter(item => !removed.has(String(item._id))));
        setRevealedSecrets(previous => { const next = { ...previous }; delete next[credential._id]; return next; });
        toast.success('Vault credential deleted');
      }
      setVaultAuth(null); setVaultPassword('');
    } catch (error) { toast.error(error.response?.data?.message || `Credential ${vaultAuth.mode} failed`); }
    finally { setVaultActionBusy(false); }
  };

  const handleRunSimulator = async () => {
    try {
      const parsed = JSON.parse(simPayload);
      const { data } = await api.post('/soar/simulator', { eventPayload: parsed, ruleId: rules[0]?._id });
      setSimResult(data);
      toast.success('Simulation dry-run completed');
    } catch { toast.error('Simulator error: Invalid JSON or evaluation error'); }
  };

  const pendingApprovalsCount = summary?.pendingApprovals ?? approvals.filter(a => a.status === 'pending').length;
  const failedExecutionsCount = summary?.failedExecutions ?? executions.filter(e => e.status === 'failed').length;

  const NAV_ITEMS = [
    { id: 'dashboard', label: 'SOAR Dashboard', icon: '📊' },
    { id: 'rules', label: 'Automation Rules', icon: '⚙️' },
    { id: 'builder', label: 'Visual Rule Builder', icon: '🎨' },
    { id: 'playbooks', label: 'Playbooks', icon: '📘' },
    { id: 'templates', label: 'Templates', icon: '📄' },
    { id: 'simulator', label: 'Rule Simulator', icon: '🧪' },
    { id: 'history', label: `Execution History (${executions.length})`, icon: '📜' },
    { id: 'approvals', label: `Approval Queue (${pendingApprovalsCount})`, icon: '⏳' },
    { id: 'failed', label: `Failed Actions (${failedExecutionsCount})`, icon: '⚠️' },
    { id: 'audit', label: `Audit Logs (${auditTotal || auditLogs.length})`, icon: '🛡️' },
  ];

  return (
    <div style={{ background: '#060e1a', color: '#e2e8f0', minHeight: '100vh', padding: '20px' }}>
      {loadError && <div style={{ background: '#450a0a', border: '1px solid #991b1b', color: '#fecaca', padding: '10px 14px', borderRadius: 8, marginBottom: 12 }}>SOAR API error: {loadError}</div>}
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, borderBottom: '1px solid #1e3a5f', paddingBottom: 15 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ color: '#38bdf8' }}>⚡</span> SOAR Command Center
          </h1>
          <p style={{ margin: '4px 0 0', fontSize: 13, color: '#64748b' }}>
            Security Orchestration, Automation, and Response Module — Enterprise SOC Enforcement
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button onClick={openNewRuleModal} style={{ background: 'linear-gradient(135deg, #2563eb 0%, #1d4ed8 100%)', color: '#fff', border: 'none', padding: '10px 18px', borderRadius: 8, fontSize: 13, cursor: 'pointer', fontWeight: 700, boxShadow: '0 4px 12px rgba(37,99,235,0.4)', display: 'flex', alignItems: 'center', gap: 6 }}>
            ⚡ + Build New Rule
          </button>
          <button onClick={loadAllData} style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', padding: '10px 14px', borderRadius: 8, fontSize: 12, cursor: 'pointer', fontWeight: 600 }}>
            ↻ Refresh Real-Time
          </button>
        </div>
      </div>

      {/* Sub-Navigation Tabs */}
      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 20, background: '#0b172a', padding: 8, borderRadius: 8, border: '1px solid #1e3a5f' }}>
        {NAV_ITEMS.map(item => (
          <button
            key={item.id}
            onClick={() => setActiveTab(item.id)}
            style={{
              padding: '7px 14px', borderRadius: 6, border: 'none', fontSize: 12, fontWeight: 600, cursor: 'pointer',
              background: activeTab === item.id ? '#2563eb' : 'transparent',
              color: activeTab === item.id ? '#ffffff' : '#94a3b8',
              transition: 'all 0.15s ease',
            }}
          >
            {item.icon} {item.label}
          </button>
        ))}
      </div>

      {/* ── ENTERPRISE 5-STEP RULE BUILDER WIZARD MODAL ───────────────────────── */}
      {ruleModalOpen && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(2, 6, 23, 0.88)', backdropFilter: 'blur(6px)', display: 'flex', justifyContent: 'center', alignItems: 'center', zIndex: 99999, padding: 20 }}>
          <div style={{ background: '#0b172a', border: '1px solid #38bdf8', borderRadius: 16, width: '100%', maxWidth: 860, maxHeight: '92vh', overflowY: 'auto', padding: 28, boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.85)' }}>
            
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e3a5f', paddingBottom: 16, marginBottom: 20 }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 20, color: '#38bdf8', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 8 }}>
                  ⚡ {ruleForm._id ? 'Edit Enterprise SOAR Rule' : 'Create Enterprise SOAR Automation Rule'}
                </h3>
                <span style={{ fontSize: 12, color: '#64748b', marginTop: 2, display: 'block' }}>Configure intelligent automated detection triggers, multi-condition logic, and response workflows</span>
              </div>
              <button onClick={() => setRuleModalOpen(false)} style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', width: 32, height: 32, borderRadius: '50%', cursor: 'pointer', fontSize: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
            </div>

            {/* 5-Step Wizard Progress Bar */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6, marginBottom: 24, background: '#060e1a', padding: 6, borderRadius: 10, border: '1px solid #1e3a5f' }}>
              {[
                [1, '1. Info & Scope'],
                [2, '2. Trigger Source'],
                [3, '3. Condition Logic'],
                [4, '4. Action Pipeline'],
                [5, '5. Test & Safety'],
              ].map(([stepNum, label]) => (
                <button
                  key={stepNum}
                  onClick={() => setWizardStep(stepNum)}
                  style={{
                    padding: '8px 10px', borderRadius: 6, border: 'none', fontSize: 11, fontWeight: 700, cursor: 'pointer',
                    background: wizardStep === stepNum ? '#2563eb' : (wizardStep > stepNum ? '#064e3b' : 'transparent'),
                    color: wizardStep === stepNum ? '#ffffff' : (wizardStep > stepNum ? '#34d399' : '#64748b'),
                    transition: 'all 0.2s ease',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            <form onSubmit={handleSaveRuleSubmit}>
              
              {/* STEP 1: GENERAL INFO & SCOPE */}
              {wizardStep === 1 && (
                <div>
                  <h4 style={{ margin: '0 0 8px', fontSize: 15, color: '#f8fafc', borderBottom: '1px solid #1e3a5f', paddingBottom: 6 }}>Step 1: Rule Identity</h4>
                  <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 14 }}>* Required: Rule Name, Trigger Source, and either a Playbook or Action Step. Automation Mode selected Playbook से automatically set होगा.</div>
                  <div style={{ marginBottom: 14 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Rule Name *</label>
                      <input required placeholder="e.g. Block Critical Malware C2 IP & Isolate Endpoint Host" value={ruleForm.name} onChange={e => setRuleForm({ ...ruleForm, name: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }} />
                    </div>
                  </div>

                  <div style={{ marginBottom: 14, padding: 12, border: '1px solid #2563eb', borderRadius: 8, background: '#071827' }}>
                    <label style={{ display: 'block', fontSize: 12, color: '#7dd3fc', marginBottom: 6, fontWeight: 800 }}>📘 Playbook (Optional)</label>
                    <select value={ruleForm.actions.find(action => action.type === 'start_playbook')?.payload?.playbookId || ''} onChange={event => {
                      const playbookId = event.target.value;
                      const selectedPlaybook = playbooks.find(item => item._id === playbookId);
                      setRuleForm(previous => {
                        const actionsWithoutPlaybook = previous.actions.filter(action => action.type !== 'start_playbook');
                        if (!playbookId) return { ...previous, actions: actionsWithoutPlaybook };
                        const playbookAction = {
                          type: 'start_playbook',
                          payload: { playbookId },
                          requireApproval: selectedPlaybook?.executionMode === 'approval_required',
                          riskLevel: 'high',
                          maxRetries: 2,
                          retryBackoffSec: 5,
                        };
                        const executionMode = selectedPlaybook?.executionMode === 'approval_required'
                          ? 'approval_required'
                          : selectedPlaybook?.executionMode === 'manual_only'
                            ? 'manual'
                            : previous.executionMode;
                        return { ...previous, actions: [playbookAction], executionMode, stopOnMatch: true };
                      });
                    }} style={{ width: '100%', background: '#040914', border: '1px solid #38bdf8', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }}>
                      <option value="">No Playbook — use individual Action Pipeline steps</option>
                      {playbooks.map(playbook => (
                        <option key={playbook._id} value={playbook._id} disabled={!playbook.enabled || playbook.executionMode === 'disabled'}>
                          {playbook.name} · {String(playbook.executionMode || 'approval_required').replace(/_/g, ' ')}{!playbook.enabled ? ' · disabled' : ''}
                        </option>
                      ))}
                    </select>
                    <div style={{ marginTop: 6, fontSize: 11, color: playbooks.length ? '#94a3b8' : '#fbbf24' }}>
                      {playbooks.length ? 'Playbook select karne par uska complete workflow use hoga; alag Action Steps bharna required nahi hai.' : 'Abhi koi saved Playbook available nahi hai. Pehle Playbooks tab se Playbook create aur enable karein.'}
                    </div>
                  </div>

                </div>
              )}

              {/* STEP 2: TRIGGER CONFIGURATION */}
              {wizardStep === 2 && (
                <div>
                  <h4 style={{ margin: '0 0 14px', fontSize: 15, color: '#f8fafc', borderBottom: '1px solid #1e3a5f', paddingBottom: 6 }}>Step 2: Security Event Trigger Source & Deduplication</h4>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>What do you want to detect? *</label>
                      <select required value={triggerSourceGroup(ruleForm.triggerType)} onChange={e => {
                        const firstSubtype = TRIGGER_SOURCE_GROUPS[e.target.value][0].value;
                        setRuleForm({ ...ruleForm, triggerType: firstSubtype, triggerSubtype: 'all' });
                      }} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }}>
                        {Object.keys(TRIGGER_SOURCE_GROUPS).map(group => <option key={group} value={group}>{group}</option>)}
                      </select>
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Category *</label>
                      <select required value={monitoringCategories(triggerSourceGroup(ruleForm.triggerType)) ? (ruleForm.triggerSubtype || 'all') : ruleForm.triggerType} onChange={e => {
                        if (monitoringCategories(triggerSourceGroup(ruleForm.triggerType))) setRuleForm({ ...ruleForm, triggerSubtype: e.target.value });
                        else setRuleForm({ ...ruleForm, triggerType: e.target.value, triggerSubtype: 'all' });
                      }} style={{ width: '100%', background: '#040914', border: '1px solid #2563eb', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }}>
                        {(monitoringCategories(triggerSourceGroup(ruleForm.triggerType)) || TRIGGER_SOURCE_GROUPS[triggerSourceGroup(ruleForm.triggerType)]).map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
                      </select>
                    </div>
                  </div>

                  <div style={{ marginBottom: 14 }}>
                    <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Department *</label>
                    <select required={user?.role === 'department_admin'} disabled={user?.role === 'department_admin'} value={ruleForm.departmentId || ''} onChange={e => setRuleForm({ ...ruleForm, departmentId: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #8b5cf6', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }}>
                      {user?.role !== 'department_admin' && <option value="">All Departments</option>}
                      {departments.map(department => <option key={department._id} value={department._id}>{department.name}</option>)}
                    </select>
                    <div style={{ color: '#64748b', fontSize: 10, marginTop: 6 }}>Selected department ID rule payload mein pass hoga. All Departments company-wide rule banata hai.</div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginBottom: 14 }}>
                    <div>
                      <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Alert Deduplication Window (Minutes)</label>
                      <input type="number" value={ruleForm.dedupWindowMinutes} onChange={e => setRuleForm({ ...ruleForm, dedupWindowMinutes: Number(e.target.value) })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }} />
                    </div>
                    <div>
                      <label style={{ display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 6 }}>Max Executions Per Hour (Rate Limit)</label>
                      <input type="number" value={ruleForm.maxExecutionsPerHour} onChange={e => setRuleForm({ ...ruleForm, maxExecutionsPerHour: Number(e.target.value) })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '10px 14px', borderRadius: 8, fontSize: 13 }} />
                    </div>
                  </div>
                </div>
              )}

              {/* STEP 3: MULTI-CONDITION EVALUATOR */}
              {wizardStep === 3 && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <h4 style={{ margin: 0, fontSize: 15, color: '#38bdf8' }}>Step 3: Multi-Condition Logical Evaluator</h4>
                    <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                      <span style={{ fontSize: 11, color: '#94a3b8' }}>Match Logic:</span>
                      <select value={ruleForm.matchLogic} onChange={e => setRuleForm({ ...ruleForm, matchLogic: e.target.value })} style={{ background: '#040914', border: '1px solid #38bdf8', color: '#38bdf8', padding: '4px 10px', borderRadius: 6, fontSize: 12, fontWeight: 700 }}>
                        <option value="ALL">Match ALL Conditions (AND)</option>
                        <option value="ANY">Match ANY Condition (OR)</option>
                      </select>
                      <button type="button" onClick={addConditionItem} style={{ background: '#1e293b', border: '1px solid #3b82f6', color: '#93c5fd', padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>+ Add Condition</button>
                    </div>
                  </div>

                  <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 10 }}>
                    Conditions optional hain. Sab condition rows remove karne par Rule har selected Trigger Source event par chalega.
                  </div>

                  {ruleForm.conditions.map((cond, idx) => (
                    <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.5fr 1.2fr 2fr 32px', gap: 10, marginBottom: 10, background: '#060e1a', border: '1px solid #1e3a5f', padding: 10, borderRadius: 8, alignItems: 'center' }}>
                      <input placeholder="Field (severity, srcip, signature)" value={cond.field} onChange={e => updateConditionItem(idx, 'field', e.target.value)} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '8px 10px', borderRadius: 6, fontSize: 12 }} />
                      <select value={cond.operator} onChange={e => updateConditionItem(idx, 'operator', e.target.value)} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '8px 10px', borderRadius: 6, fontSize: 12 }}>
                        <option value="eq">Equals (=)</option>
                        <option value="not_eq">Not Equals (!=)</option>
                        <option value="contains">Contains String</option>
                        <option value="starts_with">Starts With</option>
                        <option value="ends_with">Ends With</option>
                        <option value="cidr_contains">In CIDR Range (e.g. 10.0.0.0/8)</option>
                        <option value="matches_regex">Regex Pattern</option>
                        <option value="gt">Greater Than (&gt;)</option>
                      </select>
                      <input placeholder="Target Value (e.g. critical, 192.168.1.0/24)" value={cond.value} onChange={e => updateConditionItem(idx, 'value', e.target.value)} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '8px 10px', borderRadius: 6, fontSize: 12 }} />
                      <button type="button" onClick={() => removeConditionItem(idx)} style={{ background: '#7f1d1d', border: 'none', color: '#fca5a5', width: 28, height: 28, borderRadius: 4, cursor: 'pointer', fontSize: 12 }}>✕</button>
                    </div>
                  ))}
                </div>
              )}

              {/* STEP 4: ACTION PIPELINE & APPROVALS */}
              {wizardStep === 4 && (
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
                    <h4 style={{ margin: 0, fontSize: 15, color: '#34d399' }}>Step 4: Ordered Response Action Pipeline & Approval Gates {ruleForm.actions.some(action => action.type === 'start_playbook') ? '(Provided by Playbook)' : '*'}</h4>
                    <button type="button" onClick={addActionItem} style={{ background: '#1e293b', border: '1px solid #10b981', color: '#a7f3d0', padding: '4px 12px', borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>+ Add Response Action</button>
                  </div>

                  {ruleForm.actions.map((act, idx) => (
                    <div key={idx} style={{ background: '#060e1a', border: '1px solid #1e3a5f', padding: 12, borderRadius: 8, marginBottom: 10 }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 32px', gap: 10, marginBottom: 8, alignItems: 'center' }}>
                        <div>
                          <label style={{ display: 'block', fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>Action Type (Step #{idx + 1})</label>
                          <select value={act.type} onChange={e => {
                            const type = e.target.value;
                            setRuleForm(previous => {
                              const actions = [...previous.actions];
                              actions[idx] = { ...actions[idx], type, payload: type === 'start_playbook' ? { playbookId: '' } : actions[idx].payload };
                              return { ...previous, actions };
                            });
                          }} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '8px 10px', borderRadius: 6, fontSize: 12 }}>
                            <option value="start_playbook">📘 Start Linked Playbook</option>
                            <option value="block_ip">🛡️ Block Source IP (Host/Gateway Firewall)</option>
                            <option value="isolate_agent">💻 Isolate Host Endpoint (EDR Containment)</option>
                            <option value="disable_user">👤 Disable User Account (IAM Session Revoke)</option>
                            <option value="create_incident">🚨 Create EDR Incident</option>
                            <option value="create_ticket">🎟️ Create Support Ticket</option>
                            <option value="send_email">📧 Send Email Alert</option>
                            <option value="notify_soc_manager">🛡️ Notify SOC Manager</option>
                            <option value="escalate_l2">↗ Escalate to L2 Analyst</option>
                            <option value="escalate_l3">🚀 Escalate to L3 Analyst</option>
                          </select>
                        </div>
                        <div>
                          <label style={{ display: 'block', fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>Risk Level</label>
                          <select value={act.riskLevel} onChange={e => updateActionItem(idx, 'riskLevel', e.target.value)} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: '8px 10px', borderRadius: 6, fontSize: 12 }}>
                            <option value="low">Low Risk</option>
                            <option value="medium">Medium Risk</option>
                            <option value="high">High Risk</option>
                            <option value="critical">Critical Risk</option>
                          </select>
                        </div>
                        <div>
                          <label style={{ display: 'block', fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>Human Approval Gate</label>
                          <label style={{ fontSize: 11, color: '#fef08a', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', marginTop: 4 }}>
                            <input type="checkbox" disabled={ruleForm.executionMode === 'automatic'} checked={ruleForm.executionMode !== 'automatic' && act.requireApproval} onChange={e => updateActionItem(idx, 'requireApproval', e.target.checked)} />
                            {ruleForm.executionMode === 'automatic' ? 'No Approval (Automatic)' : 'Requires Approval'}
                          </label>
                        </div>
                        <button type="button" onClick={() => removeActionItem(idx)} style={{ background: '#7f1d1d', border: 'none', color: '#fca5a5', width: 28, height: 28, borderRadius: 4, cursor: 'pointer', fontSize: 12 }}>✕</button>
                      </div>

                      {act.type === 'start_playbook' && (
                        <div style={{ marginBottom: 8, padding: 10, border: '1px solid #28557a', borderRadius: 6, background: '#071827' }}>
                          <label style={{ display: 'block', fontSize: 10, color: '#7dd3fc', marginBottom: 5, fontWeight: 800 }}>Linked Response Playbook</label>
                          <select required value={act.payload?.playbookId || ''} onChange={event => {
                            const playbookId = event.target.value;
                            const selectedPlaybook = playbooks.find(item => item._id === playbookId);
                            setRuleForm(previous => {
                              const actions = [...previous.actions];
                              actions[idx] = {
                                ...actions[idx],
                                payload: { ...(actions[idx].payload || {}), playbookId },
                                requireApproval: selectedPlaybook?.executionMode === 'approval_required',
                              };
                              const executionMode = selectedPlaybook?.executionMode === 'approval_required'
                                ? 'approval_required'
                                : selectedPlaybook?.executionMode === 'manual_only'
                                  ? 'manual'
                                  : previous.executionMode;
                              return { ...previous, actions, executionMode };
                            });
                          }} style={{ width: '100%', background: '#040914', border: '1px solid #2563eb', color: '#fff', padding: '9px 10px', borderRadius: 6, fontSize: 12 }}>
                            <option value="">Select a saved Playbook…</option>
                            {playbooks.map(playbook => (
                              <option key={playbook._id} value={playbook._id} disabled={!playbook.enabled || playbook.executionMode === 'disabled'}>
                                {playbook.name} · {String(playbook.executionMode || 'approval_required').replace(/_/g, ' ')}{!playbook.enabled ? ' · disabled' : ''}
                              </option>
                            ))}
                          </select>
                          {!playbooks.length && <div style={{ marginTop: 6, color: '#fbbf24', fontSize: 10 }}>No saved Playbook is available. Create one from the Playbooks tab first.</div>}
                        </div>
                      )}

                      {/* Action Retry Policy */}
                      <div style={{ display: 'flex', gap: 14, background: '#040914', padding: '6px 10px', borderRadius: 4, fontSize: 11, color: '#94a3b8' }}>
                        <span>Max Retries: <input type="number" min={0} max={5} value={act.maxRetries ?? act.retryCount ?? 2} onChange={e => updateActionItem(idx, 'maxRetries', Number(e.target.value))} style={{ width: 40, background: '#0b172a', border: '1px solid #334155', color: '#fff', borderRadius: 4, padding: '2px 4px', textAlign: 'center' }} /></span>
                        <span>Backoff Delay: <input type="number" min={1} max={60} value={act.retryBackoffSec ?? 5} onChange={e => updateActionItem(idx, 'retryBackoffSec', Number(e.target.value))} style={{ width: 40, background: '#0b172a', border: '1px solid #334155', color: '#fff', borderRadius: 4, padding: '2px 4px', textAlign: 'center' }} /> sec</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* STEP 5: SAFETY POLICY & SIMULATION TEST */}
              {wizardStep === 5 && (
                <div>
                  <h4 style={{ margin: '0 0 14px', fontSize: 15, color: '#f59e0b', borderBottom: '1px solid #1e3a5f', paddingBottom: 6 }}>Step 5: Rule Safety Controls & Dry-Run Simulation Test</h4>
                  
                  <div style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 14, marginBottom: 16 }}>
                    <div style={{ fontSize: 13, fontWeight: 700, color: '#38bdf8', marginBottom: 6 }}>⚙️ Safety Guardrails & Auto-Disable Threshold</div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                      <div>
                        <label style={{ display: 'block', fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>Auto-Disable Rule After Failure Threshold</label>
                        <input type="number" value={ruleForm.autoDisableFailureThreshold || 5} onChange={e => setRuleForm({ ...ruleForm, autoDisableFailureThreshold: Number(e.target.value) })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 6, fontSize: 12 }} />
                      </div>
                      <div>
                        <button type="button" onClick={handleTestRunDryRun} style={{ width: '100%', marginTop: 20, background: '#059669', color: '#fff', border: 'none', padding: '9px', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>
                          🧪 Run Dry-Run Simulation Test
                        </button>
                      </div>
                    </div>
                  </div>

                  {testRunOutput && (
                    <div style={{ background: '#040914', border: '1px solid #10b981', padding: 12, borderRadius: 8, marginBottom: 16 }}>
                      <div style={{ fontSize: 12, fontWeight: 700, color: '#34d399', marginBottom: 4 }}>✓ Dry-Run Test Result: MATCH SUCCESSFUL</div>
                      <pre style={{ margin: 0, fontSize: 11, color: '#94a3b8', fontFamily: 'monospace' }}>
                        {JSON.stringify(testRunOutput, null, 2)}
                      </pre>
                    </div>
                  )}

                  <div style={{ background: '#040914', border: '1px solid #1e3a5f', padding: 12, borderRadius: 8 }}>
                    <div style={{ fontSize: 11, color: '#64748b', fontWeight: 700, marginBottom: 4 }}>CONFIGURED RULE SUMMARY</div>
                    <div style={{ fontSize: 12, color: '#f1f5f9' }}>
                      When <strong>{ruleForm.triggerType}</strong> occurs, evaluate <strong>{ruleForm.conditions.length} conditions ({ruleForm.matchLogic})</strong>. If matched, execute <strong>{ruleForm.actions.length} actions</strong> (Execution Mode: <strong>{ruleForm.executionMode}</strong>).
                    </div>
                  </div>
                </div>
              )}

              {/* Wizard Footer Navigation */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #1e3a5f', paddingTop: 16, marginTop: 24 }}>
                <button
                  type="button"
                  disabled={wizardStep === 1}
                  onClick={() => setWizardStep(prev => prev - 1)}
                  style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', padding: '8px 18px', borderRadius: 8, fontSize: 12, fontWeight: 600, cursor: wizardStep === 1 ? 'not-allowed' : 'pointer' }}
                >
                  ← Previous Step
                </button>

                <div style={{ display: 'flex', gap: 10 }}>
                  <button type="button" onClick={() => setRuleModalOpen(false)} style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', padding: '8px 16px', borderRadius: 8, fontSize: 12, cursor: 'pointer' }}>
                    Cancel
                  </button>

                  {wizardStep < 5 ? (
                    <button type="button" onClick={() => setWizardStep(prev => prev + 1)} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '8px 20px', borderRadius: 8, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>
                      Next Step →
                    </button>
                  ) : (
                    <button type="submit" disabled={savingRule} style={{ background: 'linear-gradient(135deg, #059669 0%, #047857 100%)', color: '#fff', border: 'none', padding: '8px 24px', borderRadius: 8, fontSize: 12, fontWeight: 800, cursor: 'pointer', boxShadow: '0 4px 12px rgba(16,185,129,0.4)' }}>
                      {savingRule ? 'Saving SOAR Rule...' : (ruleForm._id ? 'Update Rule' : '⚡ Save & Activate Rule')}
                    </button>
                  )}
                </div>
              </div>

            </form>
          </div>
        </div>
      )}

      {playbookModalOpen && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(2,6,23,.88)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 99999, padding: 20 }}>
          <form onSubmit={savePlaybook} style={{ width: '100%', maxWidth: 760, maxHeight: '90vh', overflowY: 'auto', background: '#0b172a', border: '1px solid #38bdf8', borderRadius: 14, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
              <h3 style={{ margin: 0, color: '#38bdf8' }}>{playbookForm._id ? 'Edit Playbook' : 'Create Playbook'}</h3>
              <button type="button" onClick={() => setPlaybookModalOpen(false)} style={{ background: '#1e293b', border: 0, color: '#fff', borderRadius: 6, padding: '6px 10px', cursor: 'pointer' }}>✕</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 12, marginBottom: 12 }}>
              <input required placeholder="Playbook name" value={playbookForm.name} onChange={e => setPlaybookForm({ ...playbookForm, name: e.target.value })} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 10, borderRadius: 6 }} />
              <input type="number" placeholder="Priority" value={playbookForm.priority} onChange={e => setPlaybookForm({ ...playbookForm, priority: Number(e.target.value) })} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 10, borderRadius: 6 }} />
            </div>
            <textarea rows={2} placeholder="Description" value={playbookForm.description} onChange={e => setPlaybookForm({ ...playbookForm, description: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 10, borderRadius: 6, marginBottom: 12 }} />
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 18 }}>
              <select value={playbookForm.executionMode} onChange={e => setPlaybookForm({ ...playbookForm, executionMode: e.target.value })} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 10, borderRadius: 6 }}>
                <option value="automatic">Automatic</option>
                <option value="approval_required">Approval Required</option>
                <option value="manual_only">Manual Only</option>
                <option value="disabled">Disabled</option>
              </select>
              <select value={String(playbookForm.enabled)} onChange={e => setPlaybookForm({ ...playbookForm, enabled: e.target.value === 'true' })} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 10, borderRadius: 6 }}>
                <option value="true">Enabled</option><option value="false">Disabled</option>
              </select>
            </div>

            <h4 style={{ color: '#f8fafc', marginBottom: 8 }}>Trigger Conditions</h4>
            {playbookForm.conditions.map((condition, index) => (
              <div key={index} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.4fr 32px', gap: 8, marginBottom: 8 }}>
                <input value={condition.field} onChange={e => { const conditions = [...playbookForm.conditions]; conditions[index] = { ...condition, field: e.target.value }; setPlaybookForm({ ...playbookForm, conditions }); }} placeholder="Field" style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 5 }} />
                <select value={condition.operator} onChange={e => { const conditions = [...playbookForm.conditions]; conditions[index] = { ...condition, operator: e.target.value }; setPlaybookForm({ ...playbookForm, conditions }); }} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 5 }}>
                  {['eq','neq','contains','not_contains','in','gt','gte','lt','lte'].map(value => <option key={value}>{value}</option>)}
                </select>
                <input value={condition.value} onChange={e => { const conditions = [...playbookForm.conditions]; conditions[index] = { ...condition, value: e.target.value }; setPlaybookForm({ ...playbookForm, conditions }); }} placeholder="Value" style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 5 }} />
                <button type="button" onClick={() => setPlaybookForm({ ...playbookForm, conditions: playbookForm.conditions.filter((_, i) => i !== index) })} style={{ background: '#7f1d1d', color: '#fff', border: 0, borderRadius: 5 }}>✕</button>
              </div>
            ))}
            <button type="button" onClick={() => setPlaybookForm({ ...playbookForm, conditions: [...playbookForm.conditions, { field: 'severity', operator: 'eq', value: 'critical' }] })} style={{ background: '#1e293b', color: '#93c5fd', border: '1px solid #3b82f6', padding: '6px 10px', borderRadius: 5, cursor: 'pointer' }}>+ Condition</button>

            <h4 style={{ color: '#f8fafc', margin: '18px 0 8px' }}>Action Steps</h4>
            {playbookForm.steps.map((step, index) => (
              <div key={index} style={{ display: 'grid', gridTemplateColumns: '38px 1fr 1.25fr 1fr 32px', gap: 8, alignItems: 'center', marginBottom: 8 }}>
                <span style={{ color: '#38bdf8' }}>#{index + 1}</span>
                <select value={step.actionType} onChange={e => { const steps = [...playbookForm.steps]; steps[index] = { ...step, actionType: e.target.value }; setPlaybookForm({ ...playbookForm, steps }); }} style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 5 }}>
                  {['block_ip','unblock_ip','isolate_agent','quarantine_endpoint','release_host','disable_user','enable_user','create_incident','create_ticket','send_email','notify_soc_manager','escalate_l2','escalate_l3','webhook','call_api'].map(value => <option key={value} value={value}>{value.replaceAll('_', ' ')}</option>)}
                </select>
                <select required={['webhook', 'call_api'].includes(step.actionType)} value={step.connectorId || ''} onChange={e => { const steps = [...playbookForm.steps]; steps[index] = { ...step, connectorId: e.target.value }; setPlaybookForm({ ...playbookForm, steps }); }} title="Connector securely uses its linked Credentials Vault secret at runtime" style={{ background: '#040914', border: '1px solid #2563eb', color: '#fff', padding: 8, borderRadius: 5 }}>
                  <option value="">{['webhook', 'call_api'].includes(step.actionType) ? 'Select Vault-linked Connector…' : 'No Connector / Vault Secret'}</option>
                  {connectors.map(connector => (
                    <option key={connector._id} value={connector._id} disabled={connector.status !== 'enabled'}>
                      {connector.name} · {connector.credentialId?.name ? `🔐 ${connector.credentialId.name}` : 'No credential'} · {connector.status}
                    </option>
                  ))}
                </select>
                <label style={{ color: '#94a3b8', fontSize: 12 }}><input type="checkbox" checked={Boolean(step.requireApproval)} onChange={e => { const steps = [...playbookForm.steps]; steps[index] = { ...step, requireApproval: e.target.checked }; setPlaybookForm({ ...playbookForm, steps }); }} /> Require approval</label>
                <button type="button" onClick={() => setPlaybookForm({ ...playbookForm, steps: playbookForm.steps.filter((_, i) => i !== index) })} style={{ background: '#7f1d1d', color: '#fff', border: 0, borderRadius: 5 }}>✕</button>
              </div>
            ))}
            <button type="button" onClick={() => setPlaybookForm({ ...playbookForm, steps: [...playbookForm.steps, { order: playbookForm.steps.length + 1, actionType: 'create_ticket', connectorId: '', actionParams: {}, requireApproval: false, continueOnFail: true }] })} style={{ background: '#1e293b', color: '#86efac', border: '1px solid #10b981', padding: '6px 10px', borderRadius: 5, cursor: 'pointer' }}>+ Action Step</button>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 22, borderTop: '1px solid #1e3a5f', paddingTop: 16 }}>
              <button type="button" onClick={() => setPlaybookModalOpen(false)} style={{ background: '#1e293b', color: '#fff', border: 0, padding: '8px 16px', borderRadius: 6, cursor: 'pointer' }}>Cancel</button>
              <button type="submit" disabled={savingPlaybook} style={{ background: '#2563eb', color: '#fff', border: 0, padding: '8px 18px', borderRadius: 6, cursor: 'pointer' }}>{savingPlaybook ? 'Saving...' : 'Save Playbook'}</button>
            </div>
          </form>
        </div>
      )}

      {/* ── TAB 1: DASHBOARD ─────────────────────────────────────────────────── */}
      {activeTab === 'dashboard' && (
        <div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 12, marginBottom: 20 }}>
            {[
              ['Total Rules', summary?.totalRules || rules.length, '#38bdf8', null],
              ['Active Rules', summary?.activeRules || rules.filter(r=>r.enabled).length, '#34d399', null],
              ['Total Executions', summary?.totalExecutions || executions.length, '#f59e0b', 'all'],
              ['Successful Executions', summary?.successfulExecutions || executions.filter(e=>e.status==='completed').length, '#10b981', 'successful'],
              ['Failed Executions', summary?.failedExecutions || executions.filter(e=>e.status==='failed').length, '#ef4444', 'failed'],
              ['Pending Approvals', summary?.pendingApprovals || pendingApprovalsCount, '#f59e0b', null],
              ['Alerts Auto-Resolved', summary?.alertsAutoResolved ?? 0, '#8b5cf6', 'alerts_auto_resolved'],
              ['Incidents Created', summary?.incidentsCreated ?? 0, '#ec4899', 'incidents_created'],
              ['Tickets Assigned', summary?.ticketsAssigned ?? 0, '#06b6d4', 'tickets_assigned'],
              ['Avg Automation Time', `${summary?.avgAutomationTimeMs ?? 0} ms`, '#3b82f6', null],
              ['Analyst Hours Saved', `${summary?.analystHoursSaved ?? 0} hrs`, '#10b981', null],
            ].map(([title, val, color, outcome]) => (
              <div key={title} role={outcome ? 'button' : undefined} tabIndex={outcome ? 0 : undefined} onClick={() => outcome && openMetricLogs(title, outcome)} onKeyDown={event => { if (outcome && (event.key === 'Enter' || event.key === ' ')) openMetricLogs(title, outcome); }} style={{ background: '#0b172a', border: `1px solid ${outcome ? color : '#1e3a5f'}`, borderRadius: 8, padding: 14, cursor: outcome ? 'pointer' : 'default' }} title={outcome ? `Open ${title} logs` : undefined}>
                <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 500 }}>{title}</small>
                <div style={{ fontSize: 24, fontWeight: 800, color, marginTop: 4 }}>{val}</div>
                {outcome && <div style={{ color: '#64748b', fontSize: 9, marginTop: 5 }}>View logs ↗</div>}
              </div>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 16 }}>
            <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
              <button type="button" onClick={() => openExecutionAudit(executions[0])} style={{ width: '100%', margin: '0 0 12px', padding: 0, display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'transparent', border: 0, color: '#38bdf8', cursor: 'pointer', textAlign: 'left' }} aria-label="Open real-time execution audit">
                <span style={{ fontSize: 14, fontWeight: 700 }}>📡 Real-Time Live Execution Feed</span>
                <span style={{ fontSize: 11, color: '#7dd3fc' }}>Open Audit ↗</span>
              </button>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                    <th style={{ padding: 8 }}>Rule / Playbook</th>
                    <th style={{ padding: 8 }}>Trigger</th>
                    <th style={{ padding: 8 }}>Status</th>
                    <th style={{ padding: 8 }}>Duration</th>
                    <th style={{ padding: 8 }}>Started</th>
                  </tr>
                </thead>
                <tbody>
                  {executions.slice(0, 8).map(exec => (
                    <tr key={exec._id} onClick={() => openExecutionAudit(exec)} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') openExecutionAudit(exec); }} style={{ borderBottom: '1px solid #0f2744', cursor: 'pointer' }} title="Open execution audit details">
                      <td style={{ padding: 8, fontWeight: 600, color: '#f1f5f9' }}>{exec.ruleName || exec.playbookName || 'Automated Response'}</td>
                      <td style={{ padding: 8, color: '#94a3b8' }}>{exec.triggerType}</td>
                      <td style={{ padding: 8 }}><StatusBadge status={exec.status} /></td>
                      <td style={{ padding: 8, color: '#94a3b8' }}>{exec.durationMs ? `${exec.durationMs}ms` : 'running'}</td>
                      <td style={{ padding: 8, color: '#64748b' }}>{new Date(exec.createdAt).toLocaleTimeString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#f59e0b' }}>⏳ Urgent Approval Queue</h3>
              {approvals.filter(a => a.status === 'pending').slice(0, 4).map(app => (
                <div key={app._id} style={{ background: '#060e1a', border: '1px solid #78350f', padding: 10, borderRadius: 6, marginBottom: 8 }}>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#fef08a' }}>{app.requestedAction}</div>
                  <div style={{ fontSize: 11, color: '#94a3b8', margin: '3px 0' }}>{app.targetSummary}</div>
                  <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
                    <button onClick={() => handleApprove(app)} style={{ background: '#059669', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Approve</button>
                    <button onClick={() => handleReject(app)} style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Reject</button>
                  </div>
                </div>
              ))}
              {approvals.filter(a => a.status === 'pending').length === 0 && (
                <p style={{ fontSize: 12, color: '#64748b', textAlign: 'center', marginTop: 30 }}>No pending human approvals</p>
              )}
            </div>
          </div>
        </div>
      )}

      {metricLogs.open && (
        <div role="dialog" aria-modal="true" aria-label={`${metricLogs.title} logs`} onMouseDown={event => { if (event.target === event.currentTarget) setMetricLogs(previous => ({ ...previous, open: false })); }} style={{ position: 'fixed', inset: 0, zIndex: 99999, background: 'rgba(2,6,23,.9)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <div style={{ width: 'min(1220px, 97vw)', maxHeight: '90vh', overflow: 'auto', background: '#07111f', border: '1px solid #f59e0b', borderRadius: 12, boxShadow: '0 24px 80px rgba(0,0,0,.75)' }}>
            <div style={{ position: 'sticky', top: 0, zIndex: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 18px', background: '#0b172a', borderBottom: '1px solid #1e3a5f' }}>
              <div><h2 style={{ margin: 0, color: '#fbbf24', fontSize: 17 }}>{metricLogs.title} — Logs</h2><div style={{ color: '#64748b', fontSize: 10, marginTop: 4 }}>{metricLogs.total} matching records · click a log for complete details</div></div>
              <button type="button" onClick={() => setMetricLogs(previous => ({ ...previous, open: false }))} style={{ background: '#1e293b', border: '1px solid #475569', color: '#fff', width: 34, height: 34, borderRadius: 7, cursor: 'pointer', fontSize: 18 }} aria-label="Close logs">×</button>
            </div>
            <div style={{ padding: 16, overflowX: 'auto' }}>
              {metricLogs.loading ? <div style={{ color: '#7dd3fc', textAlign: 'center', padding: 40 }}>Loading filtered SOAR logs…</div> : (
                <table style={{ width: '100%', minWidth: 900, borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                  <thead><tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}><th style={{ padding: 9 }}>Execution ID</th><th style={{ padding: 9 }}>Rule / Playbook</th><th style={{ padding: 9 }}>Trigger</th><th style={{ padding: 9 }}>Status</th><th style={{ padding: 9 }}>Actions</th><th style={{ padding: 9 }}>Duration</th><th style={{ padding: 9 }}>Started</th><th style={{ padding: 9 }}>Detail</th></tr></thead>
                  <tbody>
                    {metricLogs.rows.map(execution => <tr key={execution._id} onClick={() => openExecutionAudit(execution)} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') openExecutionAudit(execution); }} style={{ borderBottom: '1px solid #0f2744', cursor: 'pointer' }}><td style={{ padding: 9, color: '#64748b', fontFamily: 'monospace' }}>{String(execution._id).slice(-10)}</td><td style={{ padding: 9, color: '#f1f5f9', fontWeight: 700 }}>{execution.ruleName || execution.playbookName || 'Automated Response'}</td><td style={{ padding: 9, color: '#38bdf8' }}>{execution.triggerType || '—'}</td><td style={{ padding: 9 }}><StatusBadge status={execution.status} /></td><td style={{ padding: 9, color: '#94a3b8' }}>{execution.successActions || 0} passed · {execution.failedActions || 0} failed</td><td style={{ padding: 9, color: '#94a3b8' }}>{execution.durationMs ? `${execution.durationMs} ms` : 'Running'}</td><td style={{ padding: 9, color: '#64748b', whiteSpace: 'nowrap' }}>{new Date(execution.createdAt).toLocaleString()}</td><td style={{ padding: 9, color: '#7dd3fc', fontWeight: 700 }}>Open ↗</td></tr>)}
                    {!metricLogs.rows.length && <tr><td colSpan="8" style={{ padding: 35, color: '#64748b', textAlign: 'center' }}>No matching SOAR logs found.</td></tr>}
                  </tbody>
                </table>
              )}
              {metricLogs.pages > 1 && <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 9, marginTop: 15 }}><button type="button" disabled={metricLogs.loading || metricLogs.page <= 1} onClick={() => openMetricLogs(metricLogs.title, metricLogs.outcome, metricLogs.page - 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', borderRadius: 5, padding: '6px 11px', cursor: 'pointer' }}>Previous</button><span style={{ color: '#94a3b8', fontSize: 11 }}>Page {metricLogs.page} / {metricLogs.pages}</span><button type="button" disabled={metricLogs.loading || metricLogs.page >= metricLogs.pages} onClick={() => openMetricLogs(metricLogs.title, metricLogs.outcome, metricLogs.page + 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', borderRadius: 5, padding: '6px 11px', cursor: 'pointer' }}>Next</button></div>}
            </div>
          </div>
        </div>
      )}

      {liveAuditOpen && (
        <div role="dialog" aria-modal="true" aria-label="SOAR live execution audit" onMouseDown={event => { if (event.target === event.currentTarget) setLiveAuditOpen(false); }} style={{ position: 'fixed', inset: 0, zIndex: 100000, background: 'rgba(2,6,23,.88)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <div style={{ width: 'min(1180px, 96vw)', maxHeight: '90vh', overflow: 'auto', background: '#07111f', border: '1px solid #2563eb', borderRadius: 12, boxShadow: '0 24px 80px rgba(0,0,0,.72)' }}>
            <div style={{ position: 'sticky', top: 0, zIndex: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '15px 18px', background: '#0b172a', borderBottom: '1px solid #1e3a5f' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: 17, color: '#7dd3fc' }}>📡 Real-Time Execution Audit</h2>
                <div style={{ marginTop: 4, fontSize: 11, color: '#64748b' }}>Live SOAR workflow, action steps, timing and enforcement result</div>
              </div>
              <button type="button" onClick={() => setLiveAuditOpen(false)} style={{ background: '#1e293b', border: '1px solid #475569', color: '#fff', width: 34, height: 34, borderRadius: 7, cursor: 'pointer', fontSize: 18 }} aria-label="Close execution audit">×</button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'minmax(260px, .8fr) minmax(420px, 1.7fr)', gap: 14, padding: 16 }}>
              <div style={{ background: '#081525', border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, maxHeight: '70vh', overflow: 'auto' }}>
                <div style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700, margin: '2px 4px 9px' }}>RECENT EXECUTIONS ({executions.length})</div>
                {executions.map(execution => (
                  <button key={execution._id} type="button" onClick={() => openExecutionAudit(execution)} style={{ width: '100%', background: selectedExecution?._id === execution._id ? '#102a46' : '#060e1a', border: `1px solid ${selectedExecution?._id === execution._id ? '#38bdf8' : '#162b44'}`, borderRadius: 7, padding: 10, marginBottom: 7, color: '#fff', cursor: 'pointer', textAlign: 'left' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><b style={{ fontSize: 12 }}>{execution.ruleName || execution.playbookName || 'Automated Response'}</b><StatusBadge status={execution.status} /></div>
                    <div style={{ color: '#64748b', fontSize: 10, marginTop: 6 }}>{new Date(execution.createdAt).toLocaleString()} · {execution.durationMs ? `${execution.durationMs} ms` : 'running'}</div>
                  </button>
                ))}
                {!executions.length && <div style={{ color: '#64748b', padding: 20, textAlign: 'center', fontSize: 12 }}>No SOAR executions recorded.</div>}
              </div>

              <div style={{ background: '#081525', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16, minHeight: 360 }}>
                {executionAuditLoading ? <div style={{ color: '#7dd3fc', padding: 30, textAlign: 'center' }}>Loading verified execution record…</div> : selectedExecution ? (
                  <>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start', marginBottom: 14 }}>
                      <div><h3 style={{ margin: 0, color: '#f8fafc', fontSize: 16 }}>{selectedExecution.ruleName || selectedExecution.playbookName || 'Automated Response'}</h3><div style={{ color: '#64748b', fontFamily: 'monospace', fontSize: 10, marginTop: 5 }}>Execution ID: {selectedExecution._id}</div></div>
                      <StatusBadge status={selectedExecution.status} />
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 8, marginBottom: 16 }}>
                      {[['Trigger', selectedExecution.triggerType || '—'], ['Mode', selectedExecution.executionType || 'automatic'], ['Started', selectedExecution.startedAt ? new Date(selectedExecution.startedAt).toLocaleString() : '—'], ['Completed', selectedExecution.completedAt ? new Date(selectedExecution.completedAt).toLocaleString() : 'In progress'], ['Duration', selectedExecution.durationMs ? `${selectedExecution.durationMs} ms` : 'Running'], ['Retries', `${selectedExecution.retryCount || 0}/${selectedExecution.maxRetries ?? 0}`]].map(([label, value]) => <div key={label} style={{ background: '#040914', border: '1px solid #162b44', borderRadius: 6, padding: 9 }}><div style={{ color: '#64748b', fontSize: 9 }}>{label.toUpperCase()}</div><div style={{ color: '#cbd5e1', fontSize: 11, marginTop: 4, wordBreak: 'break-word' }}>{value}</div></div>)}
                    </div>
                    {(selectedExecution.errorCode || selectedExecution.errorMessage) && <div style={{ background: '#2b1015', border: '1px solid #7f1d1d', color: '#fecaca', padding: 10, borderRadius: 6, marginBottom: 14, fontSize: 11 }}><b>{selectedExecution.errorCode || 'EXECUTION ERROR'}</b><div style={{ marginTop: 4 }}>{selectedExecution.errorMessage}</div></div>}
                    <h4 style={{ margin: '0 0 9px', color: '#38bdf8', fontSize: 13 }}>Action Timeline</h4>
                    {(selectedExecution.steps || []).map((step, index) => <div key={step._id || step.stepId || index} style={{ display: 'grid', gridTemplateColumns: '30px minmax(150px,1fr) auto', gap: 10, alignItems: 'center', background: '#040914', border: '1px solid #162b44', borderRadius: 7, padding: 10, marginBottom: 7 }}><div style={{ width: 25, height: 25, display: 'grid', placeItems: 'center', borderRadius: '50%', background: '#172554', color: '#93c5fd', fontWeight: 800, fontSize: 11 }}>{index + 1}</div><div><b style={{ color: '#e2e8f0', fontSize: 12 }}>{step.name || step.actionType || `Step ${index + 1}`}</b><div style={{ color: step.errorMessage ? '#fca5a5' : '#64748b', fontSize: 10, marginTop: 3 }}>{step.errorMessage || `${step.retryCount || 0} retries · ${step.durationMs || 0} ms`}</div></div><StatusBadge status={step.status} /></div>)}
                    {!(selectedExecution.steps || []).length && <div style={{ color: '#64748b', fontSize: 11, padding: 12, background: '#040914', borderRadius: 6 }}>No action steps were recorded for this execution.</div>}
                  </>
                ) : <div style={{ color: '#64748b', padding: 30, textAlign: 'center' }}>Select an execution to audit.</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 2: AUTOMATION RULES ─────────────────────────────────────────── */}
      {activeTab === 'rules' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#38bdf8' }}>Automated SOAR Detection & Response Rules</h3>
            <button onClick={openNewRuleModal} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>+ Build New Rule</button>
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 10 }}>Rule Name</th>
                <th style={{ padding: 10 }}>Category</th>
                <th style={{ padding: 10 }}>Trigger</th>
                <th style={{ padding: 10 }}>Department</th>
                <th style={{ padding: 10 }}>Mode</th>
                <th style={{ padding: 10 }}>Status</th>
                <th style={{ padding: 10 }}>Matches</th>
                <th style={{ padding: 10 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.map(rule => (
                <tr key={rule._id} style={{ borderBottom: '1px solid #0f2744' }}>
                  <td style={{ padding: 10 }}>
                    <div style={{ fontWeight: 700, color: '#f1f5f9' }}>{rule.name}</div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{rule.description || 'No description provided'}</div>
                  </td>
                  <td style={{ padding: 10, color: '#94a3b8' }}>{rule.category || 'IDS'}</td>
                  <td style={{ padding: 10, color: '#38bdf8' }}>{rule.triggerType}</td>
                  <td style={{ padding: 10, color: '#a78bfa' }}>{departments.find(department => String(department._id) === String(rule.departmentId?._id || rule.departmentId))?.name || 'All Departments'}</td>
                  <td style={{ padding: 10, color: '#94a3b8' }}>{rule.executionMode || 'automatic'}</td>
                  <td style={{ padding: 10 }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: rule.enabled ? '#064e3b' : '#1e293b', color: rule.enabled ? '#34d399' : '#64748b' }}>
                      {rule.enabled ? 'ACTIVE' : 'DISABLED'}
                    </span>
                  </td>
                  <td style={{ padding: 10, color: '#f59e0b', fontWeight: 600 }}>{rule.matchCount || 0}</td>
                  <td style={{ padding: 10, display: 'flex', gap: 6 }}>
                    <button onClick={() => openEditRuleModal(rule)} style={{ background: '#0284c7', border: 'none', color: '#fff', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Edit</button>
                    <button onClick={() => handleToggleRule(rule)} style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>{rule.enabled ? 'Disable' : 'Enable'}</button>
                    <button onClick={() => handleDeleteRule(rule._id, rule.name)} style={{ background: '#7f1d1d', border: 'none', color: '#fca5a5', padding: '4px 8px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, color: '#94a3b8', fontSize: 11 }}>
            <span>Page {auditPage} of {Math.max(1, Math.ceil(auditTotal / 100))} · {auditTotal} records</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" disabled={auditPage <= 1} onClick={() => loadAuditPage(auditPage - 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', padding: '5px 10px', borderRadius: 5, cursor: auditPage <= 1 ? 'not-allowed' : 'pointer', opacity: auditPage <= 1 ? 0.5 : 1 }}>Previous</button>
              <button type="button" disabled={auditPage * 100 >= auditTotal} onClick={() => loadAuditPage(auditPage + 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', padding: '5px 10px', borderRadius: 5, cursor: auditPage * 100 >= auditTotal ? 'not-allowed' : 'pointer', opacity: auditPage * 100 >= auditTotal ? 0.5 : 1 }}>Next</button>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 3: VISUAL RULE BUILDER ───────────────────────────────────────── */}
      {activeTab === 'builder' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#38bdf8' }}>🎨 Interactive Visual Workflow Canvas</h3>
            <button onClick={openNewRuleModal} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>+ Build New Rule</button>
          </div>
          
          <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr 280px', gap: 16, minHeight: 480 }}>
            <div style={{ background: '#060e1a', border: '1px solid #1e3a5f', padding: 12, borderRadius: 6 }}>
              <h4 style={{ margin: '0 0 10px', fontSize: 12, color: '#94a3b8' }}>WORKFLOW NODES</h4>
              {['⚡ Trigger Event', '🔍 Condition Evaluator', '🔀 Branch Splitter', '🛡️ Block IP Action', '💻 Host Isolate Action', '🎟️ Ticket Creation', '⏳ Approval Gate', '🔄 Rollback Action'].map(n => (
                <div key={n} style={{ background: '#0f2744', border: '1px solid #1e3a5f', padding: '8px 10px', borderRadius: 4, marginBottom: 8, fontSize: 12, cursor: 'grab' }}>
                  {n}
                </div>
              ))}
            </div>

            <div style={{ background: '#040914', border: '2px dashed #1e3a5f', borderRadius: 6, padding: 20, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
              <div style={{ background: '#1e3a8a', border: '1px solid #3b82f6', color: '#fff', padding: '12px 24px', borderRadius: 8, fontSize: 13, fontWeight: 700, boxShadow: '0 4px 12px rgba(37,99,235,0.3)' }}>
                ⚡ TRIGGER: Suricata / Zeek / EDR Security Alert Arrival
              </div>
              <div style={{ color: '#3b82f6', fontSize: 20, fontWeight: 800 }}>↓</div>
              <div style={{ background: '#78350f', border: '1px solid #f59e0b', color: '#fff', padding: '12px 24px', borderRadius: 8, fontSize: 13, fontWeight: 700, boxShadow: '0 4px 12px rgba(245,158,11,0.3)' }}>
                🔍 CONDITION: severity == 'critical' AND confidence &gt; 80
              </div>
              <div style={{ color: '#f59e0b', fontSize: 20, fontWeight: 800 }}>↓</div>
              <div style={{ background: '#581c87', border: '1px solid #a855f7', color: '#fff', padding: '12px 24px', borderRadius: 8, fontSize: 13, fontWeight: 700 }}>
                ⏳ APPROVAL: Pause for SOC Manager Approval (High-Risk Action)
              </div>
              <div style={{ color: '#a855f7', fontSize: 20, fontWeight: 800 }}>↓</div>
              <div style={{ background: '#064e3b', border: '1px solid #10b981', color: '#fff', padding: '12px 24px', borderRadius: 8, fontSize: 13, fontWeight: 700, boxShadow: '0 4px 12px rgba(16,185,129,0.3)' }}>
                🛡️ ACTION: Block Source IP + Isolate Endpoint Host
              </div>
            </div>

            <div style={{ background: '#060e1a', border: '1px solid #1e3a5f', padding: 12, borderRadius: 6 }}>
              <h4 style={{ margin: '0 0 10px', fontSize: 12, color: '#94a3b8' }}>WORKFLOW PROPERTIES</h4>
              <button onClick={openNewRuleModal} style={{ width: '100%', background: '#2563eb', color: '#fff', border: 'none', padding: '8px', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: 'pointer', marginBottom: 12 }}>+ Build New Rule</button>
              <div style={{ fontSize: 12, color: '#64748b' }}>Configure rule nodes, drag and drop steps, setup retry delays, and attach connector parameters.</div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 4: PLAYBOOKS ─────────────────────────────────────────────────── */}
      {activeTab === 'playbooks' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#38bdf8' }}>📘 SOAR Response Playbooks</h3>
            <button onClick={openNewPlaybookModal} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>+ Create Playbook</button>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 10 }}>Playbook Name</th>
                <th style={{ padding: 10 }}>Steps Count</th>
                <th style={{ padding: 10 }}>Mode</th>
                <th style={{ padding: 10 }}>Status</th>
                <th style={{ padding: 10 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.map(pb => (
                <tr key={pb._id} style={{ borderBottom: '1px solid #0f2744' }}>
                  <td style={{ padding: 10 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontWeight: 700, color: '#f1f5f9' }}>{pb.name}</span>
                      {pb.isBuiltIn && <span style={{ padding: '2px 7px', borderRadius: 10, background: 'rgba(56,189,248,.14)', border: '1px solid rgba(56,189,248,.35)', color: '#7dd3fc', fontSize: 9, fontWeight: 900 }}>PREBUILT</span>}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b' }}>{pb.description}</div>
                  </td>
                  <td style={{ padding: 10, color: '#38bdf8', fontWeight: 600 }}>{pb.steps?.length || 0} steps</td>
                  <td style={{ padding: 10, color: '#94a3b8' }}>{pb.executionMode}</td>
                  <td style={{ padding: 10 }}><StatusBadge status={pb.enabled ? 'completed' : 'cancelled'} /></td>
                  <td style={{ padding: 10 }}>
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button onClick={() => openEditPlaybookModal(pb)} style={{ background: '#0284c7', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Edit Playbook</button>
                      {!pb.isBuiltIn && <button onClick={() => handleDeletePlaybook(pb._id, pb.name)} style={{ background: '#7f1d1d', color: '#fca5a5', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Delete</button>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── TAB 5: DEFAULT TEMPLATES ─────────────────────────────────────────── */}
      {activeTab === 'templates' && (
        <div>
          <h3 style={{ margin: '0 0 6px', fontSize: 16, color: '#38bdf8' }}>📄 Rule Templates ({templates.length})</h3>
          <div style={{ marginBottom: 14, color: '#94a3b8', fontSize: 12 }}>Choose a template to open a complete editable Automation Rule. Change its name, trigger, conditions and response actions before saving; the original template remains unchanged.</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16 }}>
            {templates.map(tmpl => (
              <div key={tmpl._id || tmpl.slug || tmpl.name} style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
                <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: '#1e293b', color: '#38bdf8', float: 'right' }}>{tmpl.category}</span>
                <h4 style={{ margin: '0 0 8px', fontSize: 14, color: '#f8fafc' }}>{tmpl.name}</h4>
                <p style={{ margin: '0 0 14px', fontSize: 12, color: '#94a3b8' }}>{tmpl.description}</p>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 12 }}>
                  <span style={{ fontSize: 10, color: '#7dd3fc', background: '#082f49', borderRadius: 10, padding: '2px 7px' }}>Trigger: {tmpl.triggerType || TEMPLATE_RULE_PRESETS[tmpl.name]?.triggerType || 'new_alert'}</span>
                  <span style={{ fontSize: 10, color: '#c4b5fd', background: '#2e1065', borderRadius: 10, padding: '2px 7px' }}>{tmpl.actions?.length || TEMPLATE_RULE_PRESETS[tmpl.name]?.actions?.length || 1} actions</span>
                </div>
                <button onClick={() => openTemplateRuleModal(tmpl)} style={{ width: '100%', background: '#2563eb', color: '#fff', border: 'none', padding: '8px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
                  ✏️ Edit & Create Rule
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── TAB 6: RULE SIMULATOR ────────────────────────────────────────────── */}
      {activeTab === 'simulator' && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
          <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
            <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#38bdf8' }}>🧪 JSON Event Payload Input</h3>
            <textarea
              rows={12}
              value={simPayload}
              onChange={e => setSimPayload(e.target.value)}
              style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#38bdf8', fontFamily: 'monospace', fontSize: 12, padding: 10, borderRadius: 6 }}
            />
            <button onClick={handleRunSimulator} style={{ marginTop: 12, background: '#059669', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>
              Run Dry-Run Simulation
            </button>
          </div>

          <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
            <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#38bdf8' }}>📊 Evaluation Results & Proposed Actions</h3>
            {simResult ? (
              <div>
                <div style={{ fontSize: 13, fontWeight: 700, color: simResult.overallMatch ? '#34d399' : '#fca5a5', marginBottom: 8 }}>
                  Match Status: {simResult.overallMatch ? 'MATCHED' : 'UNMATCHED'}
                </div>
                <pre style={{ background: '#040914', border: '1px solid #1e3a5f', color: '#94a3b8', padding: 10, borderRadius: 6, fontSize: 11, overflow: 'auto', maxHeight: 280 }}>
                  {JSON.stringify(simResult, null, 2)}
                </pre>
              </div>
            ) : (
              <div style={{ fontSize: 12, color: '#64748b', textAlign: 'center', marginTop: 40 }}>Click "Run Dry-Run Simulation" to inspect evaluation output</div>
            )}
          </div>
        </div>
      )}

      {/* ── TAB 7: EXECUTION HISTORY ─────────────────────────────────────────── */}
      {activeTab === 'history' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#38bdf8' }}>📜 Searchable SOAR Execution History</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 8 }}>Execution ID</th>
                <th style={{ padding: 8 }}>Rule / Playbook</th>
                <th style={{ padding: 8 }}>Trigger Event</th>
                <th style={{ padding: 8 }}>Status</th>
                <th style={{ padding: 8 }}>AI Review</th>
                <th style={{ padding: 8 }}>Duration</th>
                <th style={{ padding: 8 }}>Started</th>
              </tr>
            </thead>
            <tbody>
              {executions.map(ex => (
                <tr key={ex._id} style={{ borderBottom: '1px solid #0f2744' }}>
                  <td style={{ padding: 8, fontFamily: 'monospace', color: '#64748b' }}>{ex._id.slice(-6)}</td>
                  <td style={{ padding: 8, fontWeight: 600, color: '#f1f5f9' }}>{ex.ruleName || ex.playbookName || 'Automated Response'}</td>
                  <td style={{ padding: 8, color: '#38bdf8' }}>{ex.triggerType}</td>
                  <td style={{ padding: 8 }}><StatusBadge status={ex.status} /></td>
                  <td style={{ padding: 8, maxWidth: 300 }}>
                    {ex.aiInvestigation?.status && ex.aiInvestigation.status !== 'not_required'
                      ? <div><b style={{ color: '#c4b5fd' }}>✦ {ex.aiInvestigation.status}{ex.aiInvestigation.confidence ? ` · ${ex.aiInvestigation.confidence}%` : ''}</b><div style={{ color: '#94a3b8', marginTop: 3 }}>{ex.aiInvestigation.summary || 'AI review queued'}</div></div>
                      : <span style={{ color: '#475569' }}>Not required</span>}
                  </td>
                  <td style={{ padding: 8, color: '#94a3b8' }}>{ex.durationMs ? `${ex.durationMs}ms` : 'running'}</td>
                  <td style={{ padding: 8, color: '#64748b' }}>{new Date(ex.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── TAB 8: APPROVAL QUEUE ────────────────────────────────────────────── */}
      {activeTab === 'approvals' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#f59e0b' }}>⏳ Human-in-the-Loop Approval Queue ({pendingApprovalsCount} Pending)</h3>
            {pendingApprovalsCount > 0 && (
              <button onClick={handleBulkApprove} style={{ background: '#059669', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>
                ✓ Bulk Approve Pending
              </button>
            )}
          </div>

          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 10 }}>Requested Action</th>
                <th style={{ padding: 10 }}>Source</th>
                <th style={{ padding: 10 }}>Target Resource</th>
                <th style={{ padding: 10 }}>Reason / Summary</th>
                <th style={{ padding: 10 }}>Risk Level</th>
                <th style={{ padding: 10 }}>Status</th>
                <th style={{ padding: 10 }}>Requested At</th>
                <th style={{ padding: 10 }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {approvals.map(app => (
                <tr key={app._id} style={{ borderBottom: '1px solid #0f2744' }}>
                  <td style={{ padding: 10, fontWeight: 700, color: '#fef08a' }}>{app.requestedAction}</td>
                  <td style={{ padding: 10 }}><StatusBadge status={app.source === 'automated_response' ? 'endpoint response' : 'soar execution'} /></td>
                  <td style={{ padding: 10, color: '#f1f5f9', fontFamily: 'monospace' }}>{app.targetResource || 'Endpoint'}</td>
                  <td style={{ padding: 10, color: '#94a3b8' }}>{app.targetSummary || app.reason || 'High risk containment action'}</td>
                  <td style={{ padding: 10 }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: '#7f1d1d', color: '#fca5a5', fontWeight: 700 }}>{String(app.riskLevel || 'high').toUpperCase()}</span>
                  </td>
                  <td style={{ padding: 10 }}><StatusBadge status={app.status} /></td>
                  <td style={{ padding: 10, color: '#64748b' }}>{new Date(app.createdAt).toLocaleString()}</td>
                  <td style={{ padding: 10 }}>
                    {app.status === 'pending' ? (
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button onClick={() => handleApprove(app)} style={{ background: '#059669', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Approve</button>
                        <button onClick={() => handleReject(app)} style={{ background: '#dc2626', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Reject</button>
                      </div>
                    ) : (
                      <span style={{ color: '#64748b', fontSize: 11 }}>Resolved</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── TAB 9: FAILED ACTIONS ────────────────────────────────────────────── */}
      {activeTab === 'failed' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#ef4444' }}>⚠️ Failed Actions Triage</h3>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 8 }}>Rule Name</th>
                <th style={{ padding: 8 }}>Error Code</th>
                <th style={{ padding: 8 }}>Error Message</th>
                <th style={{ padding: 8 }}>Failed At</th>
                <th style={{ padding: 8 }}>Triage Action</th>
              </tr>
            </thead>
            <tbody>
              {executions.filter(e => e.status === 'failed').map(ex => (
                <tr key={ex._id} style={{ borderBottom: '1px solid #0f2744' }}>
                  <td style={{ padding: 8, fontWeight: 600, color: '#f1f5f9' }}>{ex.ruleName}</td>
                  <td style={{ padding: 8, color: '#ef4444', fontFamily: 'monospace' }}>{ex.errorCode || 'EXEC_FAIL'}</td>
                  <td style={{ padding: 8, color: '#fca5a5' }}>{ex.errorMessage || 'Action execution error'}</td>
                  <td style={{ padding: 8, color: '#64748b' }}>{new Date(ex.createdAt).toLocaleString()}</td>
                  <td style={{ padding: 8 }}>
                    <button onClick={() => handleRetryExecution(ex._id)} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>Retry Now</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* ── TAB 10: CONNECTORS ──────────────────────────────────────────────── */}
      {activeTab === 'connectors' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0, fontSize: 16, color: '#38bdf8' }}>🔌 Integrations & Connectors Framework</h3>
            <button onClick={() => setConnectorModalOpen(true)} style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '6px 14px', borderRadius: 6, fontSize: 12, fontWeight: 700, cursor: 'pointer' }}>+ Add Connector</button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
            {connectors.map(c => (
              <div key={c._id} style={{ background: '#060e1a', border: '1px solid #1e3a5f', padding: 12, borderRadius: 6 }}>
                <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: c.status === 'enabled' ? '#064e3b' : '#7f1d1d', color: c.status === 'enabled' ? '#34d399' : '#fca5a5', float: 'right' }}>
                  {c.status.toUpperCase()}
                </span>
                <div style={{ fontSize: 13, fontWeight: 700, color: '#f8fafc', marginBottom: 4 }}>{c.name}</div>
                <div style={{ fontSize: 11, color: '#64748b', marginBottom: 10 }}>Type: {c.type} · Auth: {c.authType}</div>
                <div style={{ fontSize: 10, color: c.lastError ? '#fca5a5' : '#64748b', marginBottom: 8 }}>
                  {c.lastError
                    ? `Last error: ${c.lastError}`
                    : c.lastSuccessAt
                      ? `Verified: ${new Date(c.lastSuccessAt).toLocaleString()}`
                      : 'Not verified yet'}
                </div>
                <button onClick={() => handleTestConnector(c._id)} style={{ background: '#1e293b', border: '1px solid #334155', color: '#94a3b8', padding: '4px 10px', borderRadius: 4, fontSize: 11, cursor: 'pointer' }}>
                  Test Connection
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── TAB 11: CREDENTIALS VAULT ────────────────────────────────────────── */}
      {activeTab === 'vault' && (
        <div>
          <h3 style={{ margin: '0 0 12px', fontSize: 16, color: '#7dd3fc' }}>🔐 SOAR Credentials Vault</h3>
          <div style={{ background: '#0f2744', border: '1px solid #1e3a5f', padding: 14, borderRadius: 8, marginBottom: 16 }}>
            <h4 style={{ margin: '0 0 6px', color: '#38bdf8', fontSize: 14 }}>🔐 AES-256-GCM Secret Vault Architecture</h4>
            <p style={{ margin: 0, fontSize: 12, color: '#94a3b8' }}>
              Each company has an isolated Vault. Credentials are stored in MongoDB encrypted with AES-256-GCM, explicit IV and auth tag tracking. This Vault never reads, writes, updates, or deletes backend `.env` keys. Secrets are masked in the UI (`••••••••`) and never included in logs or stack traces.
            </p>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
            <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#38bdf8' }}>Store New Secret</h3>
              <form onSubmit={handleSaveCredential}>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>Credential Name</label>
                  <input required value={credForm.name} onChange={e => setCredForm({ ...credForm, name: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 4, fontSize: 12 }} />
                </div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: 'block', fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>Type</label>
                  <select value={credForm.type} onChange={e => setCredForm({ ...credForm, type: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 4, fontSize: 12 }}>
                    <option value="api_key">API Key</option>
                    <option value="bearer_token">Bearer Token</option>
                    <option value="password">Password</option>
                    <option value="oauth_secret">OAuth Secret</option>
                  </select>
                </div>
                <div style={{ marginBottom: 16 }}>
                  <label style={{ display: 'block', fontSize: 11, color: '#94a3b8', marginBottom: 4 }}>Plaintext Secret</label>
                  <input required type="password" value={credForm.secretValue} onChange={e => setCredForm({ ...credForm, secretValue: e.target.value })} style={{ width: '100%', background: '#040914', border: '1px solid #1e3a5f', color: '#fff', padding: 8, borderRadius: 4, fontSize: 12 }} />
                </div>
                <button type="submit" style={{ background: '#2563eb', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: 'pointer' }}>Save Secret</button>
              </form>
            </div>

            <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: '0 0 12px', fontSize: 14, color: '#38bdf8' }}>Vault Encrypted Secrets List</h3>
              {credentials.map(c => (
                <div key={c._id} style={{ background: '#060e1a', border: '1px solid #1e3a5f', padding: 10, borderRadius: 6, marginBottom: 8, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9' }}>{c.name}</div>
                    <div style={{ fontSize: 10, color: '#64748b' }}>{c.type} · AES-256-GCM · Company scoped</div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ minWidth: 110, fontSize: 12, color: '#10b981', fontFamily: 'monospace', wordBreak: 'break-all' }}>{revealedSecrets[c._id] || '••••••••'}</div>
                    <button type="button" onClick={() => { setVaultAuth({ mode: 'reveal', credential: c }); setVaultPassword(''); }} style={{ background: '#1e3a8a', color: '#dbeafe', border: '1px solid #3b82f6', padding: '4px 8px', borderRadius: 4, cursor: 'pointer', fontSize: 10 }}>{revealedSecrets[c._id] ? 'Reveal again' : '👁 Reveal'}</button>
                    <button type="button" onClick={() => { setVaultAuth({ mode: 'delete', credential: c }); setVaultPassword(''); }} style={{ background: '#7f1d1d', color: '#fee2e2', border: '1px solid #ef4444', padding: '4px 8px', borderRadius: 4, cursor: 'pointer', fontSize: 10 }}>🗑 Delete</button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {vaultAuth && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 100000, background: 'rgba(2,6,23,.86)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <form onSubmit={handleVaultProtectedAction} style={{ width: '100%', maxWidth: 440, background: '#0b172a', border: `1px solid ${vaultAuth.mode === 'delete' ? '#ef4444' : '#38bdf8'}`, borderRadius: 12, padding: 22, boxShadow: '0 24px 70px rgba(0,0,0,.65)' }}>
            <h3 style={{ margin: '0 0 8px', color: vaultAuth.mode === 'delete' ? '#fca5a5' : '#7dd3fc' }}>{vaultAuth.mode === 'delete' ? '🗑 Delete Vault Credential' : '👁 Reveal Vault Secret'}</h3>
            <div style={{ color: '#cbd5e1', fontSize: 12, marginBottom: 14 }}>
              {vaultAuth.credential.name} · {vaultAuth.mode === 'delete' ? 'This action cannot be undone. Any linked Connector will also be removed from the active Connectors list.' : 'Secret will automatically hide after 30 seconds.'}
            </div>
            <label style={{ display: 'block', color: '#94a3b8', fontSize: 11, marginBottom: 5 }}>Current account password *</label>
            <input autoFocus required type="password" autoComplete="current-password" value={vaultPassword} onChange={event => setVaultPassword(event.target.value)} style={{ width: '100%', background: '#040914', color: '#fff', border: '1px solid #334155', padding: '10px 12px', borderRadius: 6 }} />
            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 18 }}>
              <button type="button" disabled={vaultActionBusy} onClick={() => { setVaultAuth(null); setVaultPassword(''); }} style={{ background: '#1e293b', color: '#fff', border: 0, padding: '8px 13px', borderRadius: 6, cursor: 'pointer' }}>Cancel</button>
              <button type="submit" disabled={vaultActionBusy} style={{ background: vaultAuth.mode === 'delete' ? '#dc2626' : '#2563eb', color: '#fff', border: 0, padding: '8px 13px', borderRadius: 6, cursor: 'pointer' }}>{vaultActionBusy ? 'Please wait…' : vaultAuth.mode === 'delete' ? 'Verify & Delete' : 'Verify & Reveal'}</button>
            </div>
          </form>
        </div>
      )}

      {/* ── TAB 12: AUDIT LOGS ──────────────────────────────────────────────── */}
      {activeTab === 'audit' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 12 }}>
            <div>
              <h3 style={{ margin: 0, color: '#38bdf8', fontSize: 14, fontWeight: 700 }}>
                🛡️ Immutable Security Audit Trail
              </h3>
              <div style={{ marginTop: 4, fontSize: 10, color: auditVerification?.valid ? '#34d399' : auditVerification ? '#fb7185' : '#64748b' }}>
                {auditVerification ? (auditVerification.valid ? `✓ Verified · ${auditVerification.checked} signed records · ${auditVerification.legacyRecords} legacy` : `⚠ Chain broken at ${auditVerification.brokenAt}`) : 'SHA-256 hash-chain + HMAC signature · verification not run'}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" onClick={verifyAuditChain} style={{ background: '#065f46', border: '1px solid #10b981', color: '#d1fae5', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>✓ Verify Chain</button>
              <button type="button" onClick={exportAuditCsv} style={{ background: '#1e3a8a', border: '1px solid #3b82f6', color: '#dbeafe', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>↓ Export CSV</button>
              <button type="button" onClick={exportAuditPdf} style={{ background: '#7f1d1d', border: '1px solid #ef4444', color: '#fee2e2', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>↓ Download PDF</button>
            </div>
          </div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}>
                <th style={{ padding: 8 }}>Action</th>
                <th style={{ padding: 8 }}>User</th>
                <th style={{ padding: 8 }}>Resource</th>
                <th style={{ padding: 8 }}>Message</th>
                <th style={{ padding: 8 }}>Result</th>
                <th style={{ padding: 8 }}>Integrity</th>
                <th style={{ padding: 8 }}>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              {auditLogs.map(log => (
                <tr key={log._id} role="button" tabIndex={0} aria-label={`Open audit log ${log.action}`} onClick={() => setSelectedAuditLog(log)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedAuditLog(log); } }} style={{ borderBottom: '1px solid #0f2744', cursor: 'pointer' }}>
                  <td style={{ padding: 8, fontWeight: 700, color: '#38bdf8' }}>{log.action}</td>
                  <td style={{ padding: 8, color: '#94a3b8' }}>{log.userName || 'System'}</td>
                  <td style={{ padding: 8, color: '#94a3b8' }}>{log.resourceType}</td>
                  <td style={{ padding: 8, color: '#f1f5f9' }}>{log.message}</td>
                  <td style={{ padding: 8 }}><StatusBadge status={log.result || 'success'} /></td>
                  <td style={{ padding: 8, color: log.entryHash ? '#34d399' : '#fbbf24', fontFamily: 'monospace', fontSize: 10 }}>{log.entryHash ? `✓ ${log.entryHash.slice(0, 10)}…` : 'LEGACY'}</td>
                  <td style={{ padding: 8, color: '#64748b' }}>{new Date(log.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {immutableAuditOpen && (
        <div role="dialog" aria-modal="true" aria-label="Immutable security audit trail" onMouseDown={event => { if (event.target === event.currentTarget) setImmutableAuditOpen(false); }} style={{ position: 'fixed', inset: 0, zIndex: 100001, background: 'rgba(2,6,23,.9)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <div style={{ width: 'min(1280px, 97vw)', maxHeight: '91vh', overflow: 'auto', background: '#07111f', border: '1px solid #10b981', borderRadius: 12, boxShadow: '0 24px 80px rgba(0,0,0,.75)' }}>
            <div style={{ position: 'sticky', top: 0, zIndex: 3, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '15px 18px', background: '#0b172a', borderBottom: '1px solid #1e3a5f' }}>
              <div>
                <h2 style={{ margin: 0, color: '#6ee7b7', fontSize: 17 }}>🛡️ Immutable Security Audit Trail</h2>
                <div style={{ marginTop: 4, color: auditVerification?.valid ? '#34d399' : auditVerification ? '#fb7185' : '#64748b', fontSize: 10 }}>
                  {auditVerification ? (auditVerification.valid ? `✓ Verified · ${auditVerification.checked} signed records · ${auditVerification.legacyRecords} legacy` : `⚠ Chain broken at ${auditVerification.brokenAt}`) : 'SHA-256 hash-chain + HMAC signature · verification not run'}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <button type="button" onClick={verifyAuditChain} style={{ background: '#065f46', border: '1px solid #10b981', color: '#d1fae5', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>✓ Verify Chain</button>
                <button type="button" onClick={exportAuditCsv} style={{ background: '#1e3a8a', border: '1px solid #3b82f6', color: '#dbeafe', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>↓ CSV</button>
                <button type="button" onClick={exportAuditPdf} style={{ background: '#7f1d1d', border: '1px solid #ef4444', color: '#fee2e2', padding: '7px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>↓ PDF</button>
                <button type="button" onClick={() => setImmutableAuditOpen(false)} style={{ background: '#1e293b', border: '1px solid #475569', color: '#fff', width: 34, height: 34, borderRadius: 7, cursor: 'pointer', fontSize: 18 }} aria-label="Close audit trail">×</button>
              </div>
            </div>
            <div style={{ padding: 16, overflowX: 'auto' }}>
              <div style={{ color: '#94a3b8', fontSize: 11, marginBottom: 10 }}>{auditTotal} total audit records · page {auditPage}</div>
              <table style={{ width: '100%', minWidth: 900, borderCollapse: 'collapse', fontSize: 12, textAlign: 'left' }}>
                <thead><tr style={{ borderBottom: '1px solid #1e3a5f', color: '#64748b' }}><th style={{ padding: 9 }}>Action</th><th style={{ padding: 9 }}>User</th><th style={{ padding: 9 }}>Resource</th><th style={{ padding: 9 }}>Message</th><th style={{ padding: 9 }}>Result</th><th style={{ padding: 9 }}>Integrity Hash</th><th style={{ padding: 9 }}>Timestamp</th></tr></thead>
                <tbody>
                  {auditLogs.map(log => <tr key={log._id} role="button" tabIndex={0} aria-label={`Open audit log ${log.action}`} onClick={() => setSelectedAuditLog(log)} onKeyDown={event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedAuditLog(log); } }} style={{ borderBottom: '1px solid #0f2744', cursor: 'pointer' }}><td style={{ padding: 9, fontWeight: 700, color: '#38bdf8' }}>{log.action}</td><td style={{ padding: 9, color: '#94a3b8' }}>{log.userName || 'System'}</td><td style={{ padding: 9, color: '#94a3b8' }}>{log.resourceType || '—'}<div style={{ color: '#475569', fontFamily: 'monospace', fontSize: 9 }}>{log.resourceId || ''}</div></td><td style={{ padding: 9, color: '#f1f5f9', maxWidth: 360 }}>{log.message}</td><td style={{ padding: 9 }}><StatusBadge status={log.result || 'success'} /></td><td style={{ padding: 9, color: log.entryHash ? '#34d399' : '#fbbf24', fontFamily: 'monospace', fontSize: 10 }}>{log.entryHash || 'LEGACY RECORD'}</td><td style={{ padding: 9, color: '#64748b', whiteSpace: 'nowrap' }}>{new Date(log.createdAt).toLocaleString()}</td></tr>)}
                  {!auditLogs.length && <tr><td colSpan="7" style={{ padding: 30, color: '#64748b', textAlign: 'center' }}>No immutable audit records found.</td></tr>}
                </tbody>
              </table>
              {auditTotal > 100 && <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 9, marginTop: 15 }}><button type="button" disabled={auditPage <= 1} onClick={() => loadAuditPage(auditPage - 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', borderRadius: 5, padding: '6px 11px', cursor: 'pointer' }}>Previous</button><span style={{ color: '#94a3b8', fontSize: 11 }}>Page {auditPage} / {Math.ceil(auditTotal / 100)}</span><button type="button" disabled={auditPage >= Math.ceil(auditTotal / 100)} onClick={() => loadAuditPage(auditPage + 1)} style={{ background: '#1e293b', color: '#fff', border: '1px solid #334155', borderRadius: 5, padding: '6px 11px', cursor: 'pointer' }}>Next</button></div>}
            </div>
          </div>
        </div>
      )}

      {selectedAuditLog && (
        <div role="dialog" aria-modal="true" aria-labelledby="audit-log-detail-title" onMouseDown={event => { if (event.target === event.currentTarget) setSelectedAuditLog(null); }} style={{ position: 'fixed', inset: 0, zIndex: 100002, background: 'rgba(2,6,23,.9)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
          <div style={{ width: 'min(760px, 96vw)', maxHeight: '90vh', overflow: 'auto', background: '#07111f', border: '1px solid #38bdf8', borderRadius: 12, boxShadow: '0 24px 80px rgba(0,0,0,.75)' }}>
            <div style={{ position: 'sticky', top: 0, zIndex: 2, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '15px 18px', background: '#0b172a', borderBottom: '1px solid #1e3a5f' }}>
              <div>
                <h2 id="audit-log-detail-title" style={{ margin: 0, color: '#7dd3fc', fontSize: 17 }}>🛡️ Audit Log Details</h2>
                <div style={{ marginTop: 4, color: '#64748b', fontSize: 10, fontFamily: 'monospace' }}>{selectedAuditLog._id}</div>
              </div>
              <button type="button" autoFocus onClick={() => setSelectedAuditLog(null)} style={{ background: '#1e293b', border: '1px solid #475569', color: '#fff', width: 34, height: 34, borderRadius: 7, cursor: 'pointer', fontSize: 18 }} aria-label="Close audit log details">×</button>
            </div>
            <div style={{ padding: 18 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 10 }}>
                {[
                  ['Action', selectedAuditLog.action],
                  ['Result', selectedAuditLog.result || 'success'],
                  ['User', selectedAuditLog.userName || 'System'],
                  ['User Role', selectedAuditLog.userRole || 'system'],
                  ['Resource Type', selectedAuditLog.resourceType || '—'],
                  ['Resource ID', selectedAuditLog.resourceId || '—'],
                  ['IP Address', selectedAuditLog.ipAddress || '—'],
                  ['Timestamp', new Date(selectedAuditLog.createdAt).toLocaleString()],
                  ['Correlation ID', selectedAuditLog.correlationId || '—'],
                ].map(([label, value]) => (
                  <div key={label} style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 7, padding: 10 }}>
                    <div style={{ color: '#64748b', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.6px', marginBottom: 5 }}>{label}</div>
                    <div style={{ color: '#e2e8f0', fontSize: 12, overflowWrap: 'anywhere' }}>{value}</div>
                  </div>
                ))}
              </div>
              <div style={{ marginTop: 12, background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 7, padding: 12 }}>
                <div style={{ color: '#64748b', fontSize: 9, textTransform: 'uppercase', letterSpacing: '.6px', marginBottom: 6 }}>Message</div>
                <div style={{ color: '#f1f5f9', fontSize: 13, lineHeight: 1.6 }}>{selectedAuditLog.message || 'No message'}</div>
              </div>
              {[['Previous Value', selectedAuditLog.previousValue], ['New Value', selectedAuditLog.newValue]].filter(([, value]) => value !== null && value !== undefined).map(([label, value]) => (
                <div key={label} style={{ marginTop: 12 }}>
                  <div style={{ color: '#94a3b8', fontSize: 10, marginBottom: 5 }}>{label}</div>
                  <div style={{ margin: 0, padding: 12, background: '#040914', border: '1px solid #1e293b', borderRadius: 7, color: '#cbd5e1', fontSize: 11, lineHeight: 1.7, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{formatAuditValue(value)}</div>
                </div>
              ))}
              <div style={{ marginTop: 12, padding: 12, background: '#040914', border: '1px solid #1e293b', borderRadius: 7, color: '#94a3b8', fontFamily: 'monospace', fontSize: 10, lineHeight: 1.7, overflowWrap: 'anywhere' }}>
                <div><span style={{ color: '#64748b' }}>Entry hash: </span>{selectedAuditLog.entryHash || 'LEGACY RECORD'}</div>
                <div><span style={{ color: '#64748b' }}>Previous hash: </span>{selectedAuditLog.previousHash || '—'}</div>
                <div><span style={{ color: '#64748b' }}>Signature: </span>{selectedAuditLog.signature || '—'}</div>
                {selectedAuditLog.userAgent && <div><span style={{ color: '#64748b' }}>User agent: </span>{selectedAuditLog.userAgent}</div>}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── TAB 13: SETTINGS ────────────────────────────────────────────────── */}
      {activeTab === 'settings' && (
        <div style={{ background: '#0b172a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 16, maxWidth: 600 }}>
          <h3 style={{ margin: '0 0 14px', fontSize: 16, color: '#38bdf8' }}>🔧 SOAR Runtime Policy</h3>
          <div style={{ background: '#040914', border: '1px solid #1e3a5f', borderRadius: 6, padding: 12, color: '#cbd5e1', fontSize: 12, lineHeight: 1.7 }}>
            SOAR does not use editable global defaults. Deduplication, retry limits, backoff, execution mode, and approval gates are stored on each rule or playbook.
          </div>
          <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 10 }}>Open Automation Rules or Playbooks to review and change their runtime policy.</div>
        </div>
      )}

    </div>
  );
}
