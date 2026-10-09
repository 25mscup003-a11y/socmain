const crypto = require('crypto');
const net = require('net');
const Alert = require('../models/Alert.model');
const SoarRule = require('../models/SoarRule.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const SoarExecution = require('../models/SoarExecution.model');
const SoarApproval = require('../models/SoarApproval.model');
const SoarLog = require('../models/SoarLog.model');
const SoarAuditLog = require('../models/SoarAuditLog.model');
const AutomatedResponse = require('../models/AutomatedResponse.model');
const BlockedIP = require('../models/BlockedIP.model');
const BlockedDevice = require('../models/BlockedDevice.model');
const EdrIncident = require('../models/EdrIncident.model');
const CompanyNotification = require('../models/CompanyNotification.model');
const User = require('../models/User.model');
const System = require('../models/System.model');
const { sendMail } = require('../utils/email');
const { resolveSoarEmailRecipients } = require('./soarEmailRecipients.service');
const { executeConnectorAction } = require('./soarConnector.service');
const { dispatchResponse } = require('./automatedResponse.service');
const { queueAndAutoAssignSoarTicket } = require('./socTicketAssignment.service');
const { claimAlertsForIncident, isTicketAlert } = require('./socCaseExclusivity.service');

// Reference to Socket.IO (set after server starts)
let _io = null;
function attachIO(io) { _io = io; }

function broadcastSoarEvent(eventName, payload) {
  if (_io) {
    if (payload.companyId) {
      _io.to(`company:${payload.companyId}`).emit(eventName, payload);
    }
    _io.to('soar_monitoring').emit(eventName, payload);
  }
}

/**
 * Condition Evaluator
 */
function evalCondition(alert, condition) {
  const val = alert[condition.field] !== undefined ? alert[condition.field] : (alert.data ? alert.data[condition.field] : undefined);
  const ref = condition.value;
  const strVal = String(val !== undefined && val !== null ? val : '').toLowerCase();
  const strRef = String(ref !== undefined && ref !== null ? ref : '').toLowerCase();

  switch (condition.operator) {
    case 'eq':
      return String(val) === String(ref);
    case 'neq':
      return String(val) !== String(ref);
    case 'gt':
      return Number(val) > Number(ref);
    case 'gte':
      return Number(val) >= Number(ref);
    case 'lt':
      return Number(val) < Number(ref);
    case 'lte':
      return Number(val) <= Number(ref);
    case 'contains':
      return strVal.includes(strRef);
    case 'not_contains':
      return !strVal.includes(strRef);
    case 'starts_with':
      return strVal.startsWith(strRef);
    case 'ends_with':
      return strVal.endsWith(strRef);
    case 'in':
      return Array.isArray(ref) && ref.map(String).includes(String(val));
    case 'not_in':
      return Array.isArray(ref) && !ref.map(String).includes(String(val));
    case 'exists':
      return val !== undefined && val !== null && val !== '';
    case 'does_not_exist':
      return val === undefined || val === null || val === '';
    case 'matches_regex':
      try { return new RegExp(ref, 'i').test(String(val)); } catch { return false; }
    case 'cidr_contains':
      return ipv4CidrContains(strRef, strVal);
    case 'risk_range':
      return Number(val) >= Number(ref.min || 0) && Number(val) <= Number(ref.max || 100);
    default:
      return false;
  }
}

function ipv4CidrContains(cidr, ip) {
  const [network, prefixText] = String(cidr || '').split('/');
  const prefix = Number(prefixText);
  if (net.isIP(network) !== 4 || net.isIP(ip) !== 4 || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) return false;
  const toInt = value => value.split('.').reduce((result, part) => ((result << 8) | Number(part)) >>> 0, 0);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return (toInt(network) & mask) === (toInt(ip) & mask);
}

function ruleMatches(alert, rule) {
  const subtype = String(rule.triggerSubtype || 'all').toLowerCase();
  if (subtype !== 'all') {
    const evidence = [
      alert.action, alert.eventType, alert.eventCategory, alert.category,
      alert.description, alert.message, alert.signature, alert.ruleName,
      alert.protocol, alert.application, alert.sourceType,
      (alert.srcip || alert.dstip || alert.sourceIp || alert.destinationIp) && 'srcip',
      (alert.domain || alert.hostname || alert.query) && 'domain',
      (alert.srcport || alert.dstport || alert.sourcePort || alert.destinationPort) && 'port',
      alert.protocol && 'protocol',
      (alert.application || alert.processName || alert.service) && 'application',
    ].filter(Boolean).join(' ').toLowerCase();
    const subtypePatterns = {
      ip_activity: ['srcip', 'dstip', 'source ip', 'destination ip', ' ip ', 'ipv4', 'ipv6'],
      domain_activity: ['domain', 'hostname', 'dns', 'fqdn'],
      port_activity: ['port', 'srcport', 'dstport', 'source port', 'destination port'],
      protocol_activity: ['protocol', 'tcp', 'udp', 'icmp', 'http', 'https', 'tls'],
      application_activity: ['application', 'app ', 'process', 'service'],
      // Backward compatibility for rules saved before monitoring-only labels.
      ip_block: ['ip block', 'blocked ip', 'block_ip', 'deny ip'],
      domain_block: ['domain block', 'blocked domain', 'block_domain', 'dns block'],
      port_closed: ['port closed', 'closed port', 'close_port'],
      protocol_block: ['protocol block', 'blocked protocol', 'deny protocol'],
      application_block: ['application block', 'blocked application', 'app block', 'block_application'],
    };
    const patterns = subtypePatterns[subtype] || [subtype.replaceAll('_', ' ')];
    if (!patterns.some(pattern => evidence.includes(pattern))) return false;
  }
  if (!rule.conditions || rule.conditions.length === 0) return true;
  if (rule.conditionLogic === 'OR') {
    return rule.conditions.some(c => evalCondition(alert, c));
  }
  return rule.conditions.every(c => evalCondition(alert, c));
}

function departmentScopeFilter(departmentId) {
  if (!departmentId) {
    return { $or: [{ departmentId: null }, { departmentId: { $exists: false } }] };
  }
  return { $or: [
    { departmentId },
    { departmentId: null },
    { departmentId: { $exists: false } },
  ] };
}

function inferAlertTriggerTypes(alert = {}) {
  const evidence = [
    alert.sourceType, alert.sourceVendor, alert.sensor, alert.source,
    alert.module, alert.source_type, alert.detectionSource,
  ].filter(Boolean).join(' ').toLowerCase();
  const triggers = new Set(['new_alert']);
  if (evidence.includes('suricata')) triggers.add('suricata_alert');
  if (evidence.includes('ids') || evidence.includes('suricata')) triggers.add('ids_alert');
  if (evidence.includes('zeek')) triggers.add('zeek_event');
  if (evidence.includes('ips')) {
    triggers.add('ips_alert');
    triggers.add('firewall_alert'); // Preserve compatibility with existing combined Firewall/IPS rules.
  }
  if (evidence.includes('firewall')) triggers.add('firewall_alert');
  if (evidence.includes('threat_feed') || evidence.includes('threat feed') || alert.iocMatched) {
    triggers.add('threat_intel_match');
    triggers.add('ioc_detected');
  }
  if (evidence.includes('anomaly')) triggers.add('anomaly_detected');
  return [...triggers];
}

function actionRequiresApproval(rule, action) {
  // "automatic" is an explicit authorization to run the configured pipeline
  // without pausing, including high-risk actions. Use approval_required when a
  // human gate is desired for the rule.
  if (rule.executionMode === 'automatic') return false;
  return rule.executionMode === 'approval_required' || Boolean(action.requireApproval);
}

async function writeExecutionOutcomeLogs(execution, { action = 'SOAR_EXECUTION_FINALIZED', user = null, message = '' } = {}) {
  if (!execution?._id || !execution.companyId) return;
  const correlationId = String(execution._id);
  const alreadyLogged = await SoarAuditLog.exists({ correlationId, action });
  if (alreadyLogged) return;

  const results = (execution.steps || []).map(step => ({
    action: step.actionType,
    success: step.status === 'completed',
    detail: step.output?.detail || step.errorMessage || step.status,
  }));
  if (execution.alertId && execution.ruleId) {
    await SoarLog.create({
      companyId: execution.companyId,
      alertId: execution.alertId,
      ruleId: execution.ruleId,
      ruleName: execution.ruleName,
      actionsRun: (execution.steps || []).map(step => step.actionType),
      results,
      error: execution.errorMessage || '',
    });
  }
  await SoarAuditLog.create({
    tenantId: execution.tenantId || null,
    partnerId: execution.partnerId || null,
    companyId: execution.companyId,
    departmentId: execution.departmentId || null,
    user: user ? (user._id || user.id) : null,
    userName: user?.name || user?.email || 'System',
    userRole: user?.role || 'system',
    action,
    resourceType: 'SoarExecution',
    resourceId: correlationId,
    correlationId,
    result: ['failed', 'cancelled'].includes(execution.status) ? 'failure' : 'success',
    message: message || `SOAR execution ${execution.status}: ${execution.ruleName || correlationId}`,
  });
}

/**
 * Action Handler Factory
 */
async function executeActionHandler(alert, action, execution) {
  const payload = action.payload || {};

  switch (action.type) {
    case 'set_alert_status':
      await Alert.findByIdAndUpdate(alert._id, { status: payload.status || 'investigating' });
      return `Alert status updated to ${payload.status || 'investigating'}`;

    case 'set_alert_severity':
      await Alert.findByIdAndUpdate(alert._id, { severity: payload.severity || 'high' });
      alert.severity = payload.severity || 'high';
      return `Alert severity updated to ${payload.severity || 'high'}`;

    case 'assign_alert': {
      if (execution.incidentId) {
        return `Ticket assignment skipped: alert #${alert._id} already belongs to incident #${execution.incidentId}`;
      }
      const result = await queueAndAutoAssignSoarTicket(alert, {
        openedBy: execution.triggeredBy || null,
        executionId: execution._id,
      });
      execution.socTicketAlertId = alert._id;
      execution.assignedAnalyst = result.assignee?._id || null;
      await execution.save();
      broadcastSoarEvent('soc.ticket.routed', {
        companyId: alert.companyId,
        ticketId: alert._id,
        assigneeId: result.assignee?._id || null,
        requiredRole: result.requiredRole,
        category: result.category,
      });
      return result.assignee
        ? `SOC Manager queue routed ${result.category} ticket to ${result.assignee.name || result.assignee.email} (${result.requiredRole}); category workload ${result.categoryWorkload || 0}, total workload ${result.totalWorkload || 0}`
        : `Ticket queued for SOC Manager; no active on-shift ${result.requiredRole} analyst is available`;
    }

    case 'create_incident': {
      const storedAlert = await Alert.findOne({ _id: alert._id, companyId: alert.companyId })
        .select('_id ticketOpenedAt ticketSource socCaseType').lean();
      if (!storedAlert) throw new Error('Source alert was not found for incident creation');
      if (execution.socTicketAlertId || isTicketAlert(storedAlert)) {
        return `Incident skipped: alert #${alert._id} already has a SOAR ticket`;
      }
      const existingIncident = await EdrIncident.findOne({ companyId: alert.companyId, alertIds: alert._id })
        .select('_id').lean();
      if (existingIncident) {
        execution.incidentId = existingIncident._id;
        await execution.save();
        return `Incident #${existingIncident._id} already owns alert #${alert._id}`;
      }
      const claim = await claimAlertsForIncident([alert._id], alert.companyId);
      if (!claim.claimedIds.length) {
        return `Incident skipped: alert #${alert._id} was already claimed as a ticket`;
      }
      const incident = await EdrIncident.create({
        companyId: alert.companyId,
        systemId: alert.systemId || null,
        departmentId: alert.departmentId || null,
        title: payload.title || alert.description || 'SOAR Automated Incident',
        description: `Created by SOAR execution ${execution._id} from alert ${alert._id}`,
        severity: alert.severity || 'high',
        status: 'open',
        assignedTo: alert.assignedTo || null,
        alertIds: [alert._id],
        affectedEndpoint: alert.hostname || alert.agentName || '',
        affectedUser: alert.username || '', agentId: alert.agentId || '', agentName: alert.agentName || '',
        confidenceScore: Number(alert.confidenceScore || alert.riskScore || 70),
        sourceAlertCount: 1, firstEventAt: alert.firstSeen || alert.createdAt, lastEventAt: alert.lastSeen || alert.createdAt,
        rawCorrelationData: { source: 'soar', executionId: execution._id, alertId: alert._id },
      });
      execution.incidentId = incident._id;
      await execution.save();
      return `Created incident #${incident._id}`;
    }

    case 'create_ticket': {
      if (execution.incidentId) {
        return `Ticket skipped: alert #${alert._id} already belongs to incident #${execution.incidentId}`;
      }
      const result = await queueAndAutoAssignSoarTicket(alert, {
        openedBy: execution.triggeredBy || null,
        executionId: execution._id,
      });
      execution.socTicketAlertId = alert._id;
      execution.assignedAnalyst = result.assignee?._id || null;
      await execution.save();
      broadcastSoarEvent('soc.ticket.routed', {
        companyId: alert.companyId,
        ticketId: alert._id,
        assigneeId: result.assignee?._id || null,
        requiredRole: result.requiredRole,
        category: result.category,
      });
      return result.assignee
        ? `SOAR ticket #${alert._id} sent to SOC Manager queue and auto-assigned to ${result.assignee.name || result.assignee.email} (${result.requiredRole}) by lowest ${result.category} workload`
        : `SOAR ticket #${alert._id} sent to SOC Manager queue; awaiting an active on-shift ${result.requiredRole}`;
    }

    case 'block_ip': {
      const ip = alert.srcip || payload.ip;
      if (!ip) return 'No IP specified — block_ip skipped';
      if (!alert.systemId) throw new Error('No systemId attached to alert — endpoint block cannot be verified');
      const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId });
      if (!system) throw new Error('Target endpoint was not found in this company');
      const response = await AutomatedResponse.create({
        companyId: alert.companyId,
        tenantId: alert.tenantId || null,
        departmentId: alert.departmentId || null,
        alertId: alert._id,
        systemId: system._id,
        agentId: system.agentId || '',
        hostname: system.hostname || system.name || alert.agentName || '',
        actionType: 'block_ip',
        actionParams: { ip },
        status: 'queued',
        trigger: 'playbook',
        triggeredBy: execution.triggeredBy,
        requiresApproval: false,
        approvalStatus: 'auto_approved',
        executionMode: 'automatic',
        correlationId: String(execution._id),
        auditTrail: [{ status: 'queued', message: 'Approved SOAR action queued for verified endpoint execution', actorId: execution.triggeredBy }],
      });
      await dispatchResponse(response, system, _io);
      if (response.status === 'failed') throw new Error(response.errorDetail || 'Automatic IP block verification failed');
      return {
        pending: true,
        automatedResponseId: response._id,
        detail: `Block command for ${ip} sent to ${system.hostname || system._id}; waiting for endpoint confirmation`,
      };
    }

    case 'unblock_ip': {
      const ip = alert.srcip || payload.ip;
      if (!ip) return 'No IP specified';
      if (!alert.systemId) throw new Error('No systemId attached to alert — endpoint unblock cannot be verified');
      const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId });
      if (!system) throw new Error('Target endpoint was not found in this company');
      const response = await AutomatedResponse.create({
        companyId: alert.companyId, tenantId: alert.tenantId || null, departmentId: alert.departmentId || null, alertId: alert._id,
        systemId: system._id, agentId: system.agentId || '', hostname: system.hostname || system.name || alert.agentName || '',
        actionType: 'unblock_ip', actionParams: { ip }, status: 'queued', trigger: 'playbook',
        triggeredBy: execution.triggeredBy, requiresApproval: false, approvalStatus: 'auto_approved',
        executionMode: 'automatic', correlationId: String(execution._id),
        auditTrail: [{ status: 'queued', message: 'SOAR unblock queued for verified endpoint execution', actorId: execution.triggeredBy }],
      });
      await dispatchResponse(response, system, _io);
      return { pending: true, automatedResponseId: response._id, detail: `Unblock command for ${ip} sent; waiting for endpoint confirmation` };
    }

    case 'isolate_agent':
    case 'quarantine_endpoint': {
      if (!alert.systemId) return 'No systemId attached to alert — isolate skipped';
      const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId });
      if (!system) throw new Error('Target endpoint was not found in this company');
      const response = await AutomatedResponse.create({
        companyId: alert.companyId,
        tenantId: alert.tenantId || null,
        departmentId: alert.departmentId || null,
        alertId: alert._id,
        systemId: alert.systemId,
        agentId: system.agentId || '',
        hostname: system.hostname || system.name || alert.agentName || '',
        actionType: action.type,
        actionParams: {},
        status: 'queued',
        trigger: 'playbook',
        triggeredBy: execution.triggeredBy,
        requiresApproval: false,
        approvalStatus: 'auto_approved',
        executionMode: 'automatic',
        correlationId: String(execution._id),
        auditTrail: [{ status: 'queued', message: 'Approved SOAR isolation queued for verified endpoint execution', actorId: execution.triggeredBy }],
      });
      await dispatchResponse(response, system, _io);
      return {
        pending: true,
        automatedResponseId: response._id,
        detail: `Isolation command sent to ${system.hostname || system._id}; waiting for endpoint confirmation`,
      };
    }

    case 'release_host': {
      if (!alert.systemId) return 'No systemId attached';
      const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId });
      if (!system) throw new Error('Target endpoint was not found in this company');
      const response = await AutomatedResponse.create({
        companyId: alert.companyId, tenantId: alert.tenantId || null, departmentId: alert.departmentId || null, alertId: alert._id,
        systemId: system._id, agentId: system.agentId || '', hostname: system.hostname || system.name || alert.agentName || '',
        actionType: 'release_host', actionParams: {}, status: 'queued', trigger: 'playbook',
        triggeredBy: execution.triggeredBy, requiresApproval: false, approvalStatus: 'auto_approved',
        executionMode: 'automatic', correlationId: String(execution._id),
        auditTrail: [{ status: 'queued', message: 'SOAR release queued for verified endpoint execution', actorId: execution.triggeredBy }],
      });
      await dispatchResponse(response, system, _io);
      return { pending: true, automatedResponseId: response._id, detail: `Release command sent to ${system.hostname || system._id}; waiting for endpoint confirmation` };
    }

    case 'disable_user':
    case 'enable_user': {
      const username = alert.username || payload.username;
      if (!username) return 'No username specified';
      if (!alert.systemId) throw new Error(`No systemId attached to alert — endpoint ${action.type} cannot be verified`);
      const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId });
      if (!system) throw new Error('Target endpoint was not found in this company');
      const response = await AutomatedResponse.create({
        companyId: alert.companyId, tenantId: alert.tenantId || null, departmentId: alert.departmentId || null, alertId: alert._id,
        systemId: system._id, agentId: system.agentId || '', hostname: system.hostname || system.name || alert.agentName || '',
        actionType: action.type, actionParams: { username }, status: 'queued', trigger: 'playbook',
        triggeredBy: execution.triggeredBy, requiresApproval: false, approvalStatus: 'auto_approved',
        executionMode: 'automatic', correlationId: String(execution._id),
        auditTrail: [{ status: 'queued', message: `SOAR ${action.type} queued for verified endpoint execution`, actorId: execution.triggeredBy }],
      });
      await dispatchResponse(response, system, _io);
      return {
        pending: true,
        automatedResponseId: response._id,
        detail: `${action.type} command for ${username} sent to ${system.hostname || system._id}; waiting for endpoint confirmation`,
      };
    }

    case 'send_email': {
      const to = await resolveSoarEmailRecipients(alert);
      if (!to.length) throw new Error('No active company, department, SOC Manager, or shift analyst email recipients found');
      await sendMail({
        to,
        subject: payload.subject || `[SOAR Alert] ${alert.description}`,
        text: `SOAR Rule triggered. Alert: ${alert.description} | Severity: ${alert.severity}`,
      });
      return `Notification email dispatched to ${to.join(', ')}`;
    }

    case 'webhook':
    case 'call_api': {
      if (payload.connectorId) {
        return await executeConnectorAction(payload.connectorId, action.type, payload);
      }
      throw new Error('Webhook/call_api requires a configured connectorId; no request was sent');
    }

    case 'start_playbook': {
      if (!payload.playbookId) throw new Error('Start Playbook action requires playbookId');
      const playbook = await ResponsePlaybook.findOne({
        _id: payload.playbookId,
        companyId: alert.companyId,
        enabled: true,
        executionMode: { $ne: 'disabled' },
      }).lean();
      if (!playbook) throw new Error('Linked Playbook is disabled, unavailable, or outside the alert company');
      if (playbook.executionMode === 'manual_only' && execution.executionType !== 'manual') {
        throw new Error(`Playbook "${playbook.name}" is Manual Only and cannot run from an automatic rule`);
      }
      const results = [];
      for (const step of [...(playbook.steps || [])].sort((left, right) => left.order - right.order)) {
        if (step.actionType === 'start_playbook') throw new Error('Nested Start Playbook actions are not allowed');
        try {
          const detail = await executeActionHandler(alert, {
            type: step.actionType,
            payload: { ...(step.actionParams || {}), ...(step.connectorId ? { connectorId: step.connectorId } : {}) },
          }, execution);
          results.push(`${step.actionType}: ${detail}`);
        } catch (error) {
          results.push(`${step.actionType}: failed (${error.message})`);
          if (step.continueOnFail === false) throw error;
        }
      }
      return `Playbook "${playbook.name}" executed ${results.length} step(s): ${results.join(' | ')}`;
    }

    case 'notify_soc_manager': {
      await CompanyNotification.create({
        companyId: alert.companyId,
        title: `SOAR Escalation: ${alert.description}`,
        message: `High severity alert triggered SOAR action. Priority: ${alert.severity}`,
        type: 'warning',
      }).catch(() => {});
      return 'SOC Manager notified via in-app banner';
    }

    case 'escalate_l2':
    case 'escalate_l3': {
      const targetRole = action.type === 'escalate_l3' ? 'l3_analyst' : 'l2_analyst';
      const analyst = await User.findOne({ companyId: alert.companyId, role: targetRole });
      if (analyst) {
        await Alert.findByIdAndUpdate(alert._id, { assignedTo: analyst._id });
        return `Alert escalated to ${targetRole.toUpperCase()} (${analyst.name || analyst.email})`;
      }
      return `Escalated alert to ${targetRole.toUpperCase()} queue`;
    }

    default:
      throw new Error(`SOAR action "${action.type}" is not implemented; no external change was made`);
  }
}

/**
 * Main SOAR Rule Execution Orchestrator
 */
async function runSoarForAlert(alert, executionType = 'automatic', triggeredUser = null, context = {}) {
  const executions = [];
  const triggerTypes = Array.isArray(context.triggerTypes) && context.triggerTypes.length
    ? context.triggerTypes
    : (context.ruleId ? null : inferAlertTriggerTypes(alert));
  let rules = [];
  try {
    const ruleFilter = {
      $and: [
        { $or: [{ companyId: alert.companyId }, { companyId: null }] },
        departmentScopeFilter(alert.departmentId),
      ],
      enabled: true,
      status: 'active',
    };
    if (context.ruleId) ruleFilter._id = context.ruleId;
    if (triggerTypes) ruleFilter.triggerType = { $in: triggerTypes };
    else ruleFilter.triggerType = { $nin: ['correlation_created', 'correlation_updated'] };
    rules = await SoarRule.find(ruleFilter).sort({ priority: 1 });
  } catch (err) {
    console.error('[SOAR Engine] Failed to load active rules:', err.message);
    return executions;
  }

  for (const rule of rules) {
    if (rule.executionMode === 'manual' && executionType !== 'manual') continue;
    if (!ruleMatches(alert, rule)) continue;

    if (executionType !== 'manual') {
      const hourlyLimit = Math.max(1, Number(rule.rateLimitPerHour || 100));
      const executionsThisHour = await SoarExecution.countDocuments({
        companyId: alert.companyId,
        ruleId: rule._id,
        createdAt: { $gte: new Date(Date.now() - 60 * 60_000) },
      });
      if (executionsThisHour >= hourlyLimit) {
        console.log(`[SOAR Engine] Hourly rate limit reached for rule=${rule._id}`);
        continue;
      }
    }

    // Do not create an unbounded queue for the same destructive action target.
    // One pending approval per company/rule/target is sufficient; later alerts
    // remain visible and can be correlated with the existing approval.
    const targetResource = alert.systemId || alert.agentName || alert.srcip || 'Endpoint';
    const existingApproval = await SoarApproval.findOne({
      companyId: alert.companyId,
      ruleId: rule._id,
      targetResource: String(targetResource),
      status: 'pending',
      expiresAt: { $gt: new Date() },
    }).select('_id executionId');
    if (existingApproval) {
      console.log(`[SOAR Engine] Pending approval dedupe for rule=${rule._id} target=${targetResource}`);
      continue;
    }

    const dedupMs = Math.max(60_000, Number(rule.deduplicationWindowMs || 300_000));
    const recentTargetExecution = await SoarExecution.findOne({
      companyId: alert.companyId,
      ruleId: rule._id,
      'triggerPayload.systemId': alert.systemId || undefined,
      createdAt: { $gte: new Date(Date.now() - dedupMs) },
      status: { $in: ['queued', 'running', 'waiting_for_approval', 'waiting_for_agent', 'completed', 'partially_completed'] },
    }).select('_id');
    if (executionType !== 'manual' && alert.systemId && recentTargetExecution) {
      console.log(`[SOAR Engine] Dedup window skip for rule=${rule._id} target=${targetResource}`);
      continue;
    }

    // Idempotency check
    const dateWindow = new Date().toISOString().slice(0, 13); // 1-hour window
    const manualNonce = executionType === 'manual' ? `_${crypto.randomUUID()}` : '';
    const sourceId = context.idempotencySource || context.correlationId || alert._id;
    const idempotencyKey = `soar_${alert.companyId}_${rule._id}_${sourceId}_${dateWindow}${manualNonce}`;

    const existingExec = await SoarExecution.findOne({ idempotencyKey });
    if (existingExec) {
      console.log(`[SOAR Engine] Idempotent execution skip for key ${idempotencyKey}`);
      continue;
    }

    // Create execution record
    const execution = await SoarExecution.create({
      tenantId: alert.tenantId || null,
      partnerId: alert.partnerId || null,
      companyId: alert.companyId,
      departmentId: alert.departmentId || null,
      ruleId: rule._id,
      ruleName: rule.name,
      alertId: alert._id,
      incidentId: context.incidentId || null,
      correlationId: context.correlationId ? String(context.correlationId) : '',
      triggerType: context.triggerType || rule.triggerType || 'new_alert',
      triggerPayload: alert.toObject ? alert.toObject() : alert,
      status: 'running',
      idempotencyKey,
      executionType,
      triggeredBy: triggeredUser ? (triggeredUser._id || triggeredUser.id) : null,
      steps: rule.actions.map(act => ({
        stepId: String(act.id || act._id),
        name: act.type,
        actionType: act.type,
        status: 'queued',
        input: act.payload || {},
      })),
      startedAt: new Date(),
    });
    executions.push(execution);

    broadcastSoarEvent('soar.execution.created', { executionId: execution._id, companyId: alert.companyId, ruleName: rule.name });

    let stopExecution = false;

    for (let i = 0; i < rule.actions.length; i++) {
      const action = rule.actions[i];
      const step = execution.steps[i];
      step.status = 'running';
      step.startedAt = new Date();
      execution.currentStep = i;
      execution.currentStepName = action.type;
      await execution.save();

      broadcastSoarEvent('soar.execution.step.started', { executionId: execution._id, stepIndex: i, actionType: action.type });

      // Check if action requires human approval
      const requiresApproval = actionRequiresApproval(rule, action);

      if (requiresApproval && executionType !== 'dry_run') {
        step.status = 'waiting_for_approval';
        execution.status = 'waiting_for_approval';
        await execution.save();

        const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours
        let approval;
        try {
          approval = await SoarApproval.create({
            tenantId: execution.tenantId,
            companyId: execution.companyId,
            departmentId: execution.departmentId || null,
            executionId: execution._id,
            stepId: step.stepId,
            ruleId: rule._id,
            alertId: alert._id,
            requestedAction: action.type,
            targetResource: String(targetResource),
            targetSummary: `${action.type} for ${alert.description}`,
            riskLevel: action.riskLevel || 'high',
            requiredRole: 'soc_manager',
            status: 'pending',
            requestedBy: triggeredUser ? (triggeredUser._id || triggeredUser.id) : null,
            expiresAt,
          });
        } catch (error) {
          if (error?.code !== 11000) throw error;
          step.status = 'skipped';
          execution.status = 'cancelled';
          execution.errorMessage = 'Duplicate pending approval already exists for this rule and target';
          execution.completedAt = new Date();
          await execution.save();
          stopExecution = true;
          break;
        }

        broadcastSoarEvent('soar.execution.waiting_for_approval', { executionId: execution._id, approvalId: approval._id, companyId: alert.companyId });
        stopExecution = true;
        break; // Pause execution for approval
      }

      // Execute Step Action with Retries
      let success = false;
      let outputDetail = '';
      let retries = 0;
      const maxRetries = Math.max(0, Number(action.retryCount ?? rule.retryPolicy?.maxRetries ?? 1));
      const retryDelayMs = Math.max(0, action.retryBackoffSec != null
        ? Number(action.retryBackoffSec) * 1000
        : Number(rule.retryPolicy?.retryDelayMs ?? 1000));

      while (retries <= maxRetries && !success) {
        try {
          outputDetail = await executeActionHandler(alert, action, execution);
          success = true;
        } catch (err) {
          retries++;
          step.retryCount = retries;
          step.errorMessage = err.message;
          if (retries <= maxRetries) {
            await new Promise(res => setTimeout(res, retryDelayMs));
          }
        }
      }

      step.completedAt = new Date();
      step.durationMs = step.completedAt - step.startedAt;

      if (success) {
        if (outputDetail && typeof outputDetail === 'object' && outputDetail.pending) {
          step.status = 'waiting_for_agent';
          step.automatedResponseId = outputDetail.automatedResponseId;
          step.output = { detail: outputDetail.detail, verified: false };
          broadcastSoarEvent('soar.execution.step.waiting_for_agent', { executionId: execution._id, stepIndex: i, detail: outputDetail.detail });
        } else {
          step.status = 'completed';
          step.output = { detail: outputDetail, verified: true };
          execution.successActions += 1;
          broadcastSoarEvent('soar.execution.step.completed', { executionId: execution._id, stepIndex: i, detail: outputDetail });
        }
      } else {
        step.status = 'failed';
        execution.failedActions += 1;
        execution.errorMessage = step.errorMessage;
        broadcastSoarEvent('soar.execution.step.failed', { executionId: execution._id, stepIndex: i, error: step.errorMessage });

        if (!action.continueOnFail) {
          execution.status = 'failed';
          stopExecution = true;
          break;
        }
      }

      await execution.save();
    }

    if (!stopExecution) {
      const waitingForAgent = execution.steps.some(step => step.status === 'waiting_for_agent');
      execution.status = waitingForAgent ? 'waiting_for_agent' : (execution.failedActions > 0 ? 'partially_completed' : 'completed');
      if (!waitingForAgent) {
        execution.completedAt = new Date();
        execution.durationMs = execution.completedAt - execution.startedAt;
      }
      await execution.save();

      // Log execution match
      await SoarRule.findByIdAndUpdate(rule._id, { $inc: { matchCount: 1 }, lastMatchAt: new Date() });
      await writeExecutionOutcomeLogs(execution, {
        message: `SOAR Rule "${rule.name}" executed for alert ${alert._id}`,
      });

      broadcastSoarEvent('soar.execution.completed', { executionId: execution._id, status: execution.status, companyId: alert.companyId });
    }

    // Review failed/partial/approval-sensitive SOAR outcomes asynchronously.
    setImmediate(() => require('./azureAi.service')
      .enqueueSoarExecutionAnalysis(execution, { io: _io })
      .catch(err => console.error('[AI SOAR review]', err.message)));

    if (rule.stopOnMatch) break;
  }
  return executions;
}

/** Evaluate SOAR rules that explicitly subscribe to correlation lifecycle events. */
async function runSoarForCorrelation(correlation, change = 'created') {
  if (!correlation?.companyId || !correlation?._id) return [];
  const alertId = correlation.alertIds?.[correlation.alertIds.length - 1]
    || correlation.relatedAlertIds?.[correlation.relatedAlertIds.length - 1];
  if (!alertId) return [];
  const sourceAlert = await Alert.findOne({ _id: alertId, companyId: correlation.companyId }).lean();
  if (!sourceAlert) return [];

  const triggerType = change === 'updated' ? 'correlation_updated' : 'correlation_created';
  const payload = {
    ...sourceAlert,
    source: 'correlation',
    sourceType: 'CORRELATION',
    eventCategory: 'correlation',
    correlationId: String(correlation._id),
    correlationIncidentId: correlation.incidentId,
    patternId: correlation.patternId,
    patternName: correlation.patternName,
    riskScore: Number(correlation.riskScore || 0),
    confidence: Number(correlation.confidence || 0),
    confidenceScore: Number(correlation.confidence || 0),
    severity: correlation.severity,
    iocs: correlation.iocs || [],
    eventCount: Number(correlation.eventCount || 0),
    occurrenceCount: Number(correlation.occurrenceCount || 1),
    description: correlation.description || sourceAlert.description,
  };
  const executions = await runSoarForAlert(payload, 'automatic', null, {
    triggerType,
    triggerTypes: [triggerType],
    correlationId: correlation._id,
    incidentId: correlation.linkedIncidentId || null,
    idempotencySource: `${correlation._id}_${triggerType}_${Number(correlation.occurrenceCount || 1)}`,
  });
  if (executions.length) {
    await require('../models/CorrelationEvent.model').updateOne(
      { _id: correlation._id, companyId: correlation.companyId },
      { $set: { soarTriggered: true } },
    );
  }
  return executions;
}

/**
 * Approve or Reject an Execution Approval Request
 */
async function resolveApproval(approvalId, status, user, notes = '', scope = {}) {
  const approval = await SoarApproval.findOne({ _id: approvalId, ...scope });
  if (!approval) throw new Error('Approval request not found');
  if (approval.status !== 'pending') throw new Error(`Approval already ${approval.status}`);

  approval.status = status;
  approval.resolvedBy = user._id || user.id;
  approval.resolvedAt = new Date();
  approval.notes = notes;
  await approval.save();

  const execution = await SoarExecution.findOne({ _id: approval.executionId, companyId: approval.companyId });
  if (!execution) throw new Error('Associated execution record not found');

  if (status === 'rejected') {
    execution.status = 'cancelled';
    execution.errorMessage = `Approval rejected by ${user.name || user.email}`;
    await execution.save();

    await writeExecutionOutcomeLogs(execution, {
      action: 'SOAR_APPROVAL_REJECTED', user,
      message: `Approval rejected: ${notes || 'No reason supplied'}`,
    });

    broadcastSoarEvent('soar.approval.rejected', { approvalId: approval._id, executionId: execution._id, companyId: approval.companyId });
    return { approval, execution };
  }

  // Resume Execution on Approval
  execution.status = 'running';
  await execution.save();

  const alert = await Alert.findOne({ _id: execution.alertId, companyId: approval.companyId });
  const rule = await SoarRule.findOne({ _id: execution.ruleId, companyId: approval.companyId });

  broadcastSoarEvent('soar.approval.approved', { approvalId: approval._id, executionId: execution._id, companyId: approval.companyId });

  // Resume from paused step index
  const pausedStepIndex = execution.steps.findIndex(s => s.stepId === approval.stepId);
  if (pausedStepIndex !== -1 && rule && alert) {
    for (let i = pausedStepIndex; i < rule.actions.length; i++) {
      const action = rule.actions[i];
      const step = execution.steps[i];
      step.status = 'running';
      step.startedAt = new Date();
      execution.currentStep = i;
      await execution.save();

      try {
        const detail = await executeActionHandler(alert, action, execution);
        if (detail && typeof detail === 'object' && detail.pending) {
          step.status = 'waiting_for_agent';
          step.automatedResponseId = detail.automatedResponseId;
          step.output = { detail: detail.detail, verified: false };
        } else {
          step.status = 'completed';
          step.output = { detail, verified: true };
          execution.successActions += 1;
        }
      } catch (err) {
        step.status = 'failed';
        step.errorMessage = err.message;
        execution.failedActions += 1;
      }
      step.completedAt = new Date();
      step.durationMs = step.completedAt - step.startedAt;
      await execution.save();
    }

    const waitingForAgent = execution.steps.some(step => step.status === 'waiting_for_agent');
    execution.status = waitingForAgent ? 'waiting_for_agent' : (execution.failedActions > 0 ? 'partially_completed' : 'completed');
    if (!waitingForAgent) {
      execution.completedAt = new Date();
      execution.durationMs = execution.completedAt - execution.startedAt;
    }
    await execution.save();

    await writeExecutionOutcomeLogs(execution, {
      action: 'SOAR_APPROVAL_APPROVED', user,
      message: `Approval granted and execution resumed by ${user.name || user.email || user.id}`,
    });

    broadcastSoarEvent('soar.execution.completed', { executionId: execution._id, status: execution.status, companyId: approval.companyId });
  }

  return { approval, execution };
}

/**
 * Rollback Supported Completed Execution Steps
 */
async function rollbackExecution(executionId, user, scope = {}) {
  const execution = await SoarExecution.findOne({ _id: executionId, ...scope });
  if (!execution) throw new Error('Execution not found');

  execution.status = 'rollback_running';
  await execution.save();

  const alert = await Alert.findOne({ _id: execution.alertId, companyId: execution.companyId });

  for (const step of execution.steps) {
    if (step.status === 'completed') {
      try {
        if (step.actionType === 'block_ip') {
          const ip = step.input.ip || (alert ? alert.srcip : null);
          if (ip) await BlockedIP.deleteOne({ companyId: execution.companyId, ip });
        } else if (step.actionType === 'isolate_agent') {
          if (alert && alert.systemId) await BlockedDevice.deleteOne({ companyId: execution.companyId, systemId: alert.systemId });
        } else if (step.actionType === 'disable_user') {
          const username = step.input.username || (alert ? alert.username : null);
          if (username) await User.findOneAndUpdate({ companyId: execution.companyId, email: username }, { isBlocked: false });
        }
        step.rollbackStatus = 'rolled_back';
      } catch (err) {
        step.rollbackStatus = 'failed';
      }
    }
  }

  execution.status = 'rolled_back';
  await execution.save();

  await SoarAuditLog.create({
    companyId: execution.companyId,
    user: user ? (user._id || user.id) : null,
    userName: user?.name || user?.email || 'System',
    userRole: user?.role || 'system',
    action: 'SOAR_EXECUTION_ROLLBACK',
    resourceType: 'SoarExecution',
    resourceId: String(execution._id),
    result: 'success',
    message: `Rollback completed for execution ${execution._id}`,
  });

  broadcastSoarEvent('soar.execution.rolled_back', { executionId: execution._id, companyId: execution.companyId });
  return execution;
}

async function recordSoarAgentResult(automatedResponse, ok, result = '') {
  const execution = await SoarExecution.findOne({
    companyId: automatedResponse.companyId,
    'steps.automatedResponseId': automatedResponse._id,
  });
  if (!execution) return null;
  const step = execution.steps.find(item => String(item.automatedResponseId || '') === String(automatedResponse._id));
  if (!step || step.status !== 'waiting_for_agent') return execution;

  step.completedAt = new Date();
  step.durationMs = step.startedAt ? step.completedAt - step.startedAt : 0;
  step.output = { ...(step.output || {}), detail: String(result || ''), verified: Boolean(ok) };
  if (ok) {
    step.status = 'completed';
    execution.successActions += 1;
    const alert = await Alert.findOne({ _id: execution.alertId, companyId: execution.companyId }).lean();
    if (step.actionType === 'block_ip') {
      const ip = automatedResponse.actionParams?.ip || alert?.srcip;
      if (ip) await BlockedIP.updateOne(
        { companyId: execution.companyId, ip },
        { $set: { reason: `SOAR verified endpoint block: ${result || 'agent confirmed'}`, createdBy: execution.triggeredBy } },
        { upsert: true },
      );
    } else if (step.actionType === 'unblock_ip') {
      const ip = automatedResponse.actionParams?.ip || alert?.srcip;
      if (ip) await BlockedIP.deleteOne({ companyId: execution.companyId, ip });
    } else if (['isolate_agent', 'quarantine_endpoint'].includes(step.actionType) && automatedResponse.systemId) {
      await BlockedDevice.updateOne(
        { companyId: execution.companyId, systemId: automatedResponse.systemId },
        { $set: { hostname: automatedResponse.hostname || 'Endpoint', reason: `SOAR verified isolation: ${result || 'agent confirmed'}` } },
        { upsert: true },
      );
    } else if (step.actionType === 'release_host' && automatedResponse.systemId) {
      await BlockedDevice.deleteOne({ companyId: execution.companyId, systemId: automatedResponse.systemId });
    }
  } else {
    step.status = 'failed';
    step.errorMessage = String(result || 'Endpoint rejected or failed the command');
    execution.failedActions += 1;
  }

  const stillWaiting = execution.steps.some(item => item.status === 'waiting_for_agent');
  if (!stillWaiting) {
    execution.status = execution.failedActions > 0
      ? (execution.successActions > 0 ? 'partially_completed' : 'failed')
      : 'completed';
    execution.completedAt = new Date();
    execution.durationMs = execution.completedAt - execution.startedAt;
  }
  await execution.save();
  broadcastSoarEvent('soar.execution.endpoint_result', {
    executionId: execution._id,
    companyId: execution.companyId,
    status: execution.status,
    verified: Boolean(ok),
  });
  return execution;
}

module.exports = {
  attachIO,
  evalCondition,
  ipv4CidrContains,
  ruleMatches,
  departmentScopeFilter,
  inferAlertTriggerTypes,
  actionRequiresApproval,
  executeActionHandler,
  runSoarForAlert,
  runSoarForCorrelation,
  resolveApproval,
  rollbackExecution,
  recordSoarAgentResult,
  writeExecutionOutcomeLogs,
};
