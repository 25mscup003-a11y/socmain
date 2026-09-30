const mongoose = require('mongoose');
require('dotenv').config();

const SoarRule = require('./src/models/SoarRule.model');
const ResponsePlaybook = require('./src/models/ResponsePlaybook.model');
const SoarConnector = require('./src/models/SoarConnector.model');
const SoarCredential = require('./src/models/SoarCredential.model');
const SoarTemplate = require('./src/models/SoarTemplate.model');
const SoarExecution = require('./src/models/SoarExecution.model');
const SoarApproval = require('./src/models/SoarApproval.model');
const SoarAuditLog = require('./src/models/SoarAuditLog.model');
const Company = require('./src/models/Company.model');
const User = require('./src/models/User.model');
const { encryptSecret } = require('./src/services/soarConnector.service');

async function seedSoar() {
  const mongoUri = process.env.MONGO_URI || process.env.MONGODB_URI || 'mongodb://localhost:27017/soc-saas';
  await mongoose.connect(mongoUri);
  console.log('Connected to MongoDB for SOAR Seeding...');

  const company = await Company.findOne({});
  const companyId = company ? company._id : null;
  const user = await User.findOne({});
  const userId = user ? user._id : null;

  // 1. Seed 16 Comprehensive Templates
  await SoarTemplate.deleteMany({});
  await SoarTemplate.insertMany([
    {
      name: 'Malicious IP Containment Playbook',
      slug: 'malicious-ip-containment',
      category: 'IDS / IPS',
      description: 'Enrich source IP using threat intel, check allowlist, and block IP in firewall or IPS',
      riskLevel: 'critical',
      supportedAlertTypes: ['suricata', 'zeek', 'firewall'],
      requiredIntegrations: ['firewall', 'ip_reputation'],
      triggerType: 'new_alert',
      conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
      actions: [{ type: 'block_ip', requireApproval: true }],
    },
    {
      name: 'Phishing Email Response Playbook',
      slug: 'phishing-email-response',
      category: 'Email Security',
      description: 'Parse suspicious email, extract links, block sender, and notify SOC team',
      riskLevel: 'high',
      supportedAlertTypes: ['email_alert'],
      requiredIntegrations: ['email', 'slack'],
      triggerType: 'email_alert',
      actions: [{ type: 'send_email' }, { type: 'create_ticket' }],
    },
    {
      name: 'Malware Endpoint Response Playbook',
      slug: 'malware-endpoint-quarantine',
      category: 'EDR / Endpoint',
      description: 'Capture malicious file hash, isolate infected host from network, and alert SOC Manager',
      riskLevel: 'critical',
      supportedAlertTypes: ['edr', 'process'],
      requiredIntegrations: ['endpoint', 'slack'],
      triggerType: 'new_alert',
      actions: [{ type: 'isolate_agent', requireApproval: true }, { type: 'create_incident' }],
    },
    {
      name: 'Brute-Force Authentication Defense',
      slug: 'brute-force-defense',
      category: 'Identity / IAM',
      description: 'Detect repeated auth failures, revoke active user sessions, and force password reset',
      riskLevel: 'medium',
      supportedAlertTypes: ['auth', 'login_anomaly'],
      requiredIntegrations: ['iam'],
      triggerType: 'new_alert',
      actions: [{ type: 'disable_user', requireApproval: true }, { type: 'notify_soc_manager' }],
    },
    {
      name: 'Ransomware Outbreak Containment',
      slug: 'ransomware-containment',
      category: 'EDR / Outbreak',
      description: 'Immediately isolate affected endpoint, kill suspicious child processes, and notify L3 analysts',
      riskLevel: 'critical',
      supportedAlertTypes: ['ransomware', 'fim'],
      requiredIntegrations: ['endpoint', 'teams'],
      triggerType: 'new_alert',
      actions: [{ type: 'isolate_agent', requireApproval: true }, { type: 'escalate_l3' }],
    },
    {
      name: 'Data Exfiltration Defense',
      slug: 'data-exfiltration-defense',
      category: 'Firewall / Network',
      description: 'Detect high volume outbound network transfer, block destination domain, and open critical ticket',
      riskLevel: 'critical',
      supportedAlertTypes: ['network', 'zeek'],
      requiredIntegrations: ['firewall', 'ticketing'],
      triggerType: 'zeek_event',
      actions: [{ type: 'block_ip', requireApproval: true }, { type: 'create_ticket' }],
    },
    {
      name: 'Suricata IDS Automatic Block',
      slug: 'suricata-auto-block',
      category: 'IDS',
      description: 'Automatically create incident and dispatch firewall block for high confidence Suricata IDS alerts',
      riskLevel: 'high',
      supportedAlertTypes: ['suricata_alert'],
      requiredIntegrations: ['suricata', 'firewall'],
      triggerType: 'suricata_alert',
      actions: [{ type: 'block_ip' }, { type: 'create_incident' }],
    },
    {
      name: 'Zeek Anomaly Ticket Escalation',
      slug: 'zeek-anomaly-escalation',
      category: 'IDS / IPS',
      description: 'Correlate Zeek DNS/HTTP anomalies, open support ticket, and escalate to L2 analyst',
      riskLevel: 'medium',
      supportedAlertTypes: ['zeek_event'],
      requiredIntegrations: ['zeek', 'ticketing'],
      triggerType: 'zeek_event',
      actions: [{ type: 'create_ticket' }, { type: 'escalate_l2' }],
    },
    {
      name: 'SQL Injection WAF Mitigation',
      slug: 'sqli-waf-mitigation',
      category: 'Firewall',
      description: 'Detect SQL injection payload on web application firewall, block attacker IP, and update WAF rules',
      riskLevel: 'high',
      supportedAlertTypes: ['waf', 'http'],
      requiredIntegrations: ['waf', 'firewall'],
      triggerType: 'new_alert',
      actions: [{ type: 'block_ip' }, { type: 'add_firewall_rule' }],
    },
    {
      name: 'DNS Tunneling & C2 Sinkhole',
      slug: 'dns-tunneling-sinkhole',
      category: 'IDS',
      description: 'Detect suspicious DNS query patterns, sinkhole malicious domain, and block communication',
      riskLevel: 'high',
      supportedAlertTypes: ['dns', 'zeek'],
      requiredIntegrations: ['dns', 'threat_intel'],
      triggerType: 'zeek_event',
      actions: [{ type: 'block_domain', requireApproval: true }, { type: 'add_ioc' }],
    },
    {
      name: 'Insider Threat Privilege Escalation Containment',
      slug: 'insider-threat-containment',
      category: 'Identity / IAM',
      description: 'Detect unauthorized sudo/admin privilege escalation, revoke active tokens, and notify SOC Manager',
      riskLevel: 'critical',
      supportedAlertTypes: ['auth', 'privilege_escalation'],
      requiredIntegrations: ['iam', 'slack'],
      triggerType: 'new_alert',
      actions: [{ type: 'revoke_token' }, { type: 'notify_soc_manager' }],
    },
    {
      name: 'Cryptomining Process Kill & Quarantine',
      slug: 'cryptomining-kill',
      category: 'EDR',
      description: 'Detect CPU mining processes (XMRig, MinerD), terminate process, and quarantine binary file',
      riskLevel: 'medium',
      supportedAlertTypes: ['process', 'edr'],
      requiredIntegrations: ['endpoint'],
      triggerType: 'new_alert',
      actions: [{ type: 'kill_process' }, { type: 'delete_file' }],
    },
    {
      name: 'Unauthorized USB Storage Device Isolation',
      slug: 'usb-device-isolation',
      category: 'EDR',
      description: 'Detect unapproved USB storage insertion, disable USB port interface, and trigger security warning',
      riskLevel: 'low',
      supportedAlertTypes: ['usb', 'device'],
      requiredIntegrations: ['endpoint'],
      triggerType: 'new_alert',
      actions: [{ type: 'isolate_agent' }],
    },
    {
      name: 'Stolen OAuth Token Revocation',
      slug: 'stolen-oauth-revocation',
      category: 'Identity / IAM',
      description: 'Detect anomalous API token usage from unexpected geographic location, invalidate token, and log audit event',
      riskLevel: 'high',
      supportedAlertTypes: ['auth', 'cloud'],
      requiredIntegrations: ['iam'],
      triggerType: 'new_alert',
      actions: [{ type: 'revoke_token' }, { type: 'send_email' }],
    },
    {
      name: 'DDoS Attack Rate Limiting',
      slug: 'ddos-rate-limit',
      category: 'Firewall / IPS',
      description: 'Detect high volume SYN/HTTP flood, enforce temporary rate limit, and block attacking subnet CIDR',
      riskLevel: 'critical',
      supportedAlertTypes: ['firewall', 'network'],
      requiredIntegrations: ['firewall'],
      triggerType: 'new_alert',
      actions: [{ type: 'add_firewall_rule' }, { type: 'notify_company_admin' }],
    },
    {
      name: 'File Integrity Breach Auto-Recovery',
      slug: 'fim-auto-recovery',
      category: 'EDR / FIM',
      description: 'Detect unauthorized modification to critical system configuration files and restore file from baseline',
      riskLevel: 'high',
      supportedAlertTypes: ['fim'],
      requiredIntegrations: ['endpoint'],
      triggerType: 'new_alert',
      actions: [{ type: 'run_script', requireApproval: true }],
    },
  ]);
  console.log('✔ 16 Comprehensive SOAR Templates Seeded');

  // 2. Seed Default Rules & Playbooks
  if (companyId && userId) {
    await SoarRule.deleteMany({ companyId });
    const rule1 = await SoarRule.create({
      companyId,
      name: 'Critical Suricata IDS Auto-Containment',
      description: 'Automatically block source IP and create incident when critical Suricata alert triggers',
      category: 'IDS',
      triggerType: 'suricata_alert',
      executionMode: 'approval_required',
      enabled: true,
      priority: 10,
      conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
      actions: [
        { type: 'block_ip', payload: {}, requireApproval: true, riskLevel: 'high' },
        { type: 'create_incident', payload: {} },
        { type: 'notify_soc_manager', payload: {} },
      ],
      createdBy: userId,
    });

    const rule2 = await SoarRule.create({
      companyId,
      name: 'Malware EDR Host Isolation Rule',
      description: 'Isolate host agent immediately upon ransomware execution detection',
      category: 'EDR',
      triggerType: 'new_alert',
      executionMode: 'automatic',
      enabled: true,
      priority: 20,
      conditions: [{ field: 'severity', operator: 'eq', value: 'critical' }],
      actions: [
        { type: 'isolate_agent', payload: {}, requireApproval: true, riskLevel: 'critical' },
        { type: 'escalate_l3', payload: {} },
      ],
      createdBy: userId,
    });

    await ResponsePlaybook.deleteMany({ companyId });
    await ResponsePlaybook.create({
      companyId,
      name: 'Phishing Containment Workflow',
      description: 'Multi-step playbook for isolating phishing campaign indicators',
      executionMode: 'approval_required',
      enabled: true,
      priority: 15,
      conditions: [{ field: 'severity', operator: 'eq', value: 'high' }],
      steps: [
        { order: 1, actionType: 'send_email', description: 'Send alert email to user', requireApproval: false },
        { order: 2, actionType: 'disable_user', description: 'Suspend compromised user session', requireApproval: true },
        { order: 3, actionType: 'create_ticket', description: 'Create ticket for L2 review', requireApproval: false },
      ],
      createdBy: userId,
    });

    // Seed Credentials Vault & Connectors
    await SoarCredential.deleteMany({ companyId });
    const credVt = await SoarCredential.create({
      companyId,
      name: 'VirusTotal Production API Key',
      type: 'api_key',
      ...encryptSecret('vt_secret_key_8492048123491203'),
      createdBy: userId,
    });
    const credSlack = await SoarCredential.create({
      companyId,
      name: 'Slack Webhook Secret Token',
      type: 'webhook_secret',
      ...encryptSecret('https://hooks.slack.com/services/T00/B00/X00'),
      createdBy: userId,
    });

    await SoarConnector.deleteMany({ companyId });
    await SoarConnector.create([
      {
        companyId,
        name: 'VirusTotal Threat Intel Gateway',
        type: 'threat_intel',
        baseUrl: 'https://www.virustotal.com/api/v3',
        authType: 'api_key',
        credentialId: credVt._id,
        status: 'enabled',
        createdBy: userId,
      },
      {
        companyId,
        name: 'AbuseIPDB Reputation Service',
        type: 'ip_reputation',
        baseUrl: 'https://api.abuseipdb.com/api/v2',
        authType: 'api_key',
        credentialId: credVt._id,
        status: 'enabled',
        createdBy: userId,
      },
      {
        companyId,
        name: 'Slack SOC Alerts Channel Bot',
        type: 'slack',
        baseUrl: 'https://hooks.slack.com/services/T00000000/B00000000/XXXXX',
        authType: 'none',
        credentialId: credSlack._id,
        status: 'enabled',
        createdBy: userId,
      },
      {
        companyId,
        name: 'Suricata Sensor Node 01',
        type: 'suricata',
        baseUrl: 'https://192.168.1.200:9443/api',
        authType: 'bearer',
        status: 'enabled',
        createdBy: userId,
      },
      {
        companyId,
        name: 'Zeek Network Probe 01',
        type: 'zeek',
        baseUrl: 'https://192.168.1.201:8443/api',
        authType: 'bearer',
        status: 'enabled',
        createdBy: userId,
      },
    ]);

    // Seed Executions & Approvals
    await SoarExecution.deleteMany({ companyId });
    const exec1 = await SoarExecution.create({
      companyId,
      ruleId: rule1._id,
      ruleName: rule1.name,
      triggerType: 'suricata_alert',
      status: 'waiting_for_approval',
      idempotencyKey: `seed_exec_1_${Date.now()}`,
      currentStep: 0,
      currentStepName: 'block_ip',
      steps: [
        { stepId: 'step_1', name: 'block_ip', actionType: 'block_ip', status: 'waiting_for_approval', input: { ip: '198.51.100.45' } },
        { stepId: 'step_2', name: 'create_incident', actionType: 'create_incident', status: 'queued' },
      ],
      startedAt: new Date(),
    });

    const exec2 = await SoarExecution.create({
      companyId,
      ruleId: rule2._id,
      ruleName: rule2.name,
      triggerType: 'new_alert',
      status: 'completed',
      idempotencyKey: `seed_exec_2_${Date.now()}`,
      currentStep: 1,
      currentStepName: 'escalate_l3',
      durationMs: 1420,
      successActions: 2,
      steps: [
        { stepId: 'step_1', name: 'isolate_agent', actionType: 'isolate_agent', status: 'completed', durationMs: 820 },
        { stepId: 'step_2', name: 'escalate_l3', actionType: 'escalate_l3', status: 'completed', durationMs: 600 },
      ],
      startedAt: new Date(Date.now() - 3600000),
      completedAt: new Date(Date.now() - 3598580),
    });

    await SoarApproval.deleteMany({ companyId });
    await SoarApproval.create([
      {
        companyId,
        executionId: exec1._id,
        stepId: 'step_1',
        ruleId: rule1._id,
        requestedAction: 'block_ip',
        targetResource: '198.51.100.45',
        targetSummary: 'Block malicious source IP 198.51.100.45 in host firewall',
        reason: 'Suricata ET MALWARE Command & Control Traffic Detected',
        riskLevel: 'high',
        requiredRole: 'soc_manager',
        status: 'pending',
        requestedBy: userId,
        expiresAt: new Date(Date.now() + 86400000),
      },
      {
        companyId,
        executionId: exec2._id,
        stepId: 'step_1',
        ruleId: rule2._id,
        requestedAction: 'isolate_agent',
        targetResource: 'FINANCE-HOST-09',
        targetSummary: 'Isolate FINANCE-HOST-09 from network',
        reason: 'Ransomware file encryption signature matched',
        riskLevel: 'critical',
        requiredRole: 'soc_manager',
        status: 'approved',
        requestedBy: userId,
        resolvedBy: userId,
        resolvedAt: new Date(Date.now() - 3590000),
        expiresAt: new Date(Date.now() + 86400000),
        notes: 'Host isolation approved by SOC Manager',
      },
    ]);

    // Seed Audit Logs
    await SoarAuditLog.deleteMany({ companyId });
    await SoarAuditLog.create([
      {
        companyId,
        user: userId,
        userName: user.name || user.email || 'Admin',
        userRole: 'soc_manager',
        action: 'CREATE_SOAR_RULE',
        resourceType: 'SoarRule',
        resourceId: String(rule1._id),
        message: `Created SOAR Rule "${rule1.name}"`,
        result: 'success',
      },
    ]);
  }

  console.log('🎉 16 SOAR Templates & Data Seeding Complete!');
  process.exit(0);
}

seedSoar().catch(err => {
  console.error('Seeding failed:', err);
  process.exit(1);
});
