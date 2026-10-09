const crypto = require('crypto');
const net = require('net');
const AutomatedResponse = require('../models/AutomatedResponse.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const SoarRule = require('../models/SoarRule.model');
const System = require('../models/System.model');
const EdrIncident = require('../models/EdrIncident.model');

const SUPPORTED_ACTIONS = new Set([
  'isolate', 'isolate_agent', 'quarantine_endpoint', 'reconnect', 'release_host',
  'kill_process', 'kill_process_tree', 'kill_child_processes',
  'quarantine_file', 'restore_file', 'delete_file', 'block_hash', 'unblock_hash',
  'block_ip', 'unblock_ip', 'block_domain', 'unblock_domain', 'block_port', 'unblock_port', 'add_firewall_rule', 'add_ioc',
  'block_usb', 'unblock_usb', 'disable_user', 'enable_user', 'lock_account', 'force_logoff', 'revoke_token',
  'restart_service', 'stop_service', 'start_service', 'delete_scheduled_task',
  'delete_startup_entry', 'rollback_registry', 'terminate_script', 'run_script',
  'create_incident', 'create_ticket', 'send_email', 'notify_soc_manager', 'notify_company_admin',
  'escalate_l2', 'escalate_l3', 'set_alert_status', 'set_alert_severity', 'assign_alert',
  'webhook', 'call_api',
]);

const HIGH_RISK_ACTIONS = new Set([
  'isolate', 'isolate_agent', 'quarantine_endpoint', 'delete_file', 'disable_user', 'lock_account', 'force_logoff',
  'stop_service', 'delete_scheduled_task', 'delete_startup_entry', 'rollback_registry',
  'block_usb', 'block_port', 'revoke_token', 'run_script',
]);

const ACTIVE_STATUSES = new Set([
  'created', 'waiting_approval', 'approved', 'queued', 'sent_to_agent',
  'acknowledged', 'executing', 'pending', 'running',
]);

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(key => `${JSON.stringify(key)}:${canonicalize(value[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

function signCommand(command, agentKey) {
  return crypto.createHmac('sha256', agentKey).update(canonicalize(command)).digest('hex');
}

function isHighRisk(actionType) {
  return HIGH_RISK_ACTIONS.has(actionType);
}

function requiresApprovalForAction(actionType, playbook = null, forceApproval = false) {
  return Boolean(forceApproval || playbook?.requireGlobalApproval || isHighRisk(actionType));
}

function valueAt(alert, field) {
  if (!field) return undefined;
  return field.split('.').reduce((value, key) => value == null ? undefined : value[key], alert);
}

function conditionMatches(alert, condition = {}) {
  const value = valueAt(alert, condition.field);
  const expected = condition.value;
  switch (condition.operator) {
    case 'eq': return String(value) === String(expected);
    case 'neq': return String(value) !== String(expected);
    case 'contains': return String(value || '').toLowerCase().includes(String(expected || '').toLowerCase());
    case 'not_contains': return !String(value || '').toLowerCase().includes(String(expected || '').toLowerCase());
    case 'in': return Array.isArray(expected) && expected.map(String).includes(String(value));
    case 'gt': return Number(value) > Number(expected);
    case 'gte': return Number(value) >= Number(expected);
    case 'lt': return Number(value) < Number(expected);
    case 'lte': return Number(value) <= Number(expected);
    default: return false;
  }
}

function playbookMatches(alert, playbook) {
  const conditions = playbook.conditions || [];
  if (!conditions.length) return false;
  const outcomes = conditions.map(condition => conditionMatches(alert, condition));
  return playbook.conditionLogic === 'OR' ? outcomes.some(Boolean) : outcomes.every(Boolean);
}

function responseParamsForAlert(actionType, configured = {}, alert = {}) {
  const params = { ...(configured || {}) };
  if (actionType === 'block_ip' && !params.ip) {
    const destination = String(alert.destip || alert.destinationIp || alert.remoteIp || '');
    if (net.isIP(destination)) params.ip = destination;
  }
  if (['kill_process', 'kill_process_tree', 'kill_child_processes'].includes(actionType) && !params.pid) {
    const pid = Number(alert.pid || alert.processId);
    if (Number.isSafeInteger(pid) && pid > 0) params.pid = pid;
  }
  if (actionType === 'block_domain' && !params.domain) {
    const domain = String(alert.domain || alert.destinationDomain || '').trim().toLowerCase();
    if (/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) params.domain = domain;
  }
  return params;
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

function emitResponse(io, response) {
  if (!io || !response) return;
  io.to(`company:${response.companyId}`).emit('autoresponse:updated', {
    id: String(response._id),
    status: response.status,
    actionType: response.actionType,
    hostname: response.hostname,
    systemId: response.systemId ? String(response.systemId) : '',
  });
}

async function transition(response, status, message, actorId = null, io = null, extra = {}) {
  response.status = status;
  response.auditTrail.push({ status, message: String(message || '').slice(0, 500), actorId, at: new Date() });
  Object.assign(response, extra);
  await response.save();
  if (response.incidentId) {
    const result = String(message || '').slice(0, 500);
    const update = { $push: { actionsLog: { action: response.actionType, target: response.hostname || String(response.systemId || ''), result, takenBy: actorId ? String(actorId) : 'auto', takenAt: new Date() } } };
    if (status === 'successful' && isHighRisk(response.actionType)) update.$set = { status: 'contained' };
    await EdrIncident.updateOne({ _id: response.incidentId, companyId: response.companyId }, update).catch(() => {});
  }
  emitResponse(io, response);
  if (['lock_account', 'enable_user', 'force_logoff', 'isolate'].includes(response.actionType)) {
    setImmediate(() => require('./uebaProfileLock.service').syncProfileLockFromResponse(response, io)
      .catch(error => console.error('[identity protection response sync]', error.message)));
  }
  return response;
}

const SERVER_SIDE_ACTIONS = new Set([
  'create_incident', 'create_ticket', 'send_email', 'notify_soc_manager', 'notify_company_admin',
  'escalate_l2', 'escalate_l3', 'set_alert_status', 'set_alert_severity', 'assign_alert',
  'webhook', 'call_api', 'add_firewall_rule', 'add_ioc',
]);

async function dispatchResponse(response, system, io) {
  if (!SUPPORTED_ACTIONS.has(response.actionType)) {
    return transition(response, 'failed', 'Unsupported response action', null, io, { errorDetail: 'Action is not allowlisted.' });
  }

  if (SERVER_SIDE_ACTIONS.has(response.actionType)) {
    return transition(response, 'successful', `Server-side action ${response.actionType} executed successfully`, null, io);
  }

  if (!system?.responseEnabled || !system?.isActive) {
    return transition(response, 'queued', 'Endpoint is offline or response execution is disabled', null, io);
  }
  let threatVerification = null;
  const automaticNetwork = response.trigger !== 'manual'
    && ['block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint'].includes(response.actionType);
  if (automaticNetwork) {
    const alert = response.alertId ? await require('../models/Alert.model').findOne({
      _id: response.alertId, companyId: response.companyId, systemId: system._id,
    }).select('srcip').lean() : null;
    const ip = response.actionParams?.ip || alert?.srcip;
    const decision = await require('./ipsThreatGate.service').verifyAutomaticNetworkAction({ ip,
      companyId: response.companyId, systemId: system._id, alertId: response.alertId,
      action: response.actionType === 'block_ip' ? 'block_ip' : 'isolate' });
    const allowed = decision.allowed && !await require('./ips.service').isWhitelistedForCompany(ip, response.companyId, { requireRemote: true }).catch(() => true);
    if (!allowed) return transition(response, 'failed', `Threat verification deferred: ${decision.reason}`, null, io, { errorDetail: decision.reason });
    threatVerification = decision.verification;
    response.actionParams = { ...response.actionParams, ip };
  }

  const command = {
    commandId: crypto.randomUUID(),
    responseId: String(response._id),
    tenantId: response.tenantId ? String(response.tenantId) : '',
    agentId: system.agentId || response.agentId || '',
    systemId: String(system._id),
    command: response.actionType,
    params: response.actionParams || {},
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + Math.max(10_000, Number(response.timeoutMs || 60_000))).toISOString(),
    retryCount: response.retryCount || 0,
    maxRetries: response.maxRetries || 0,
    correlationId: response.correlationId || String(response._id),
    ...(automaticNetwork ? { automatic: true, threatVerification } : {}),
  };
  command.signature = signCommand(command, system.agentKey);
  const outbound = { ...command, ...command.params };

  response.commandId = command.commandId;
  response.signature = command.signature;
  response.expiresAt = new Date(command.expiresAt);
  await System.updateOne({ _id: system._id, companyId: response.companyId }, { $push: { pendingCommands: outbound } });
  if (io) io.to(`system_${system._id}`).emit('agent:command', outbound);
  return transition(response, 'sent_to_agent', 'Signed command sent to endpoint and queued for heartbeat delivery', null, io);
}

async function createResponse({ companyId, tenantId = null, alert, system, actionType, actionParams = {}, playbook = null, triggeredBy = null, trigger = 'automatic', io, forceApproval = false, verifiedProfileMismatch = false }) {
  if (!SUPPORTED_ACTIONS.has(actionType)) throw new Error('Unsupported response action');
  const profileMismatchAutoLock = Boolean(
    verifiedProfileMismatch
    && actionType === 'lock_account'
    && alert?.ruleId === 'UEBA_INPUT_PROFILE_MISMATCH'
    && alert?.inputProfileMismatch === true
    && Number(alert?.inputBaselineDays || 0) >= 30
    && alert?.inputUserVerified === true
    && String(actionParams?.username || '') === String(alert?.username || ''),
  );
  const cooldownMinutes = Math.max(0, Number(playbook?.cooldownMinutes || 0));
  if (cooldownMinutes && alert?._id && system?._id) {
    const duplicate = await AutomatedResponse.exists({
      companyId, alertId: alert._id, systemId: system._id, actionType,
      createdAt: { $gte: new Date(Date.now() - cooldownMinutes * 60_000) },
      status: { $in: [...ACTIVE_STATUSES] },
    });
    if (duplicate) return null;
  }
  const executionMode = profileMismatchAutoLock
    ? 'automatic'
    : playbook?.executionMode || (isHighRisk(actionType) ? 'approval_required' : 'automatic');
  // Approval is evaluated per action. A playbook may opt into a global gate,
  // while an individual step or a high-risk action always remains gated.
  const requiresApproval = profileMismatchAutoLock
    ? false
    : requiresApprovalForAction(actionType, playbook, forceApproval);
  const incident = alert?._id && system?._id
    ? await EdrIncident.findOne({ companyId, systemId: system._id, alertIds: alert._id, status: { $in: ['open', 'investigating', 'contained'] } }).sort({ createdAt: -1 }).lean()
    : null;
  const response = await AutomatedResponse.create({
    companyId, tenantId, departmentId: alert?.departmentId || system?.departmentId || null,
    alertId: alert?._id || null, incidentId: incident ? String(incident._id) : null, systemId: system?._id || null,
    agentId: system?.agentId || alert?.agentId || '', hostname: system?.hostname || system?.name || alert?.hostname || alert?.agentName || '',
    osType: system?.osType || system?.os || alert?.osType || '', endpointIp: system?.ip || '',
    threatName: alert?.description || '', threatType: alert?.threatCategory || alert?.attackType || alert?.malwareType || '',
    severity: alert?.severity || 'medium', mitreTechnique: alert?.mitreId || '', riskScore: Number(alert?.riskScore || alert?.confidenceScore || 0),
    actionType, actionParams, trigger, triggeredBy, playbookId: playbook?._id || null, playbookName: playbook?.name || '',
    policyId: playbook?._id ? String(playbook._id) : null, policyName: playbook?.name || '',
    executionMode, requiresApproval, approvalStatus: requiresApproval ? 'pending' : 'auto_approved',
    status: requiresApproval ? 'waiting_approval' : 'queued', timeoutMs: Number(playbook?.timeoutMs || 60_000),
    maxRetries: Number(playbook?.retryCount || 0), rollbackAvailable: Boolean(playbook?.rollbackEnabled),
    dryRun: Boolean(playbook?.dryRun || playbook?.simulationMode), correlationId: crypto.randomUUID(),
    auditTrail: [{ status: requiresApproval ? 'waiting_approval' : 'queued', message: requiresApproval ? 'Approval required by safety policy' : 'Response queued', actorId: triggeredBy, at: new Date() }],
  });
  emitResponse(io, response);
  if (response.dryRun) return transition(response, 'successful', 'Dry-run/simulation completed; no endpoint command was sent', triggeredBy, io, { completedAt: new Date() });
  if (!requiresApproval) await dispatchResponse(response, system, io);
  return response;
}

async function createVerifiedProfileMismatchLock({ alert, system, io }) {
  if (!alert || !system) throw new Error('Profile mismatch lock requires alert and endpoint');
  return createResponse({
    companyId: alert.companyId,
    tenantId: alert.tenantId || null,
    alert,
    system,
    actionType: 'lock_account',
    actionParams: { username: alert.username },
    trigger: 'automatic',
    io,
    verifiedProfileMismatch: true,
  });
}

async function evaluatePlaybooksForAlert(alert, io) {
  if (!alert?.companyId || !alert?.systemId) return [];
  const [system, linkedRules] = await Promise.all([
    System.findOne({ _id: alert.systemId, companyId: alert.companyId }).lean(),
    SoarRule.find({
      companyId: alert.companyId,
      enabled: true,
      status: 'active',
      actions: { $elemMatch: { type: 'start_playbook', 'payload.playbookId': { $exists: true } } },
      ...departmentScopeFilter(alert.departmentId),
    }).select('actions').lean(),
  ]);
  if (!system?.responseEnabled || !system?.isActive) return [];
  const linkedPlaybookIds = linkedRules.flatMap(rule => rule.actions || [])
    .filter(action => action.type === 'start_playbook' && action.payload?.playbookId)
    .map(action => action.payload.playbookId);
  const playbooks = await ResponsePlaybook.find({
    companyId: alert.companyId,
    enabled: true,
    executionMode: { $ne: 'disabled' },
    ...(linkedPlaybookIds.length ? { _id: { $nin: linkedPlaybookIds } } : {}),
    ...departmentScopeFilter(alert.departmentId),
  }).sort({ priority: 1 }).lean();
  const responses = [];
  for (const playbook of playbooks) {
    if (!playbookMatches(alert, playbook) || playbook.executionMode === 'manual_only') continue;
    const executionsThisHour = await AutomatedResponse.countDocuments({
      companyId: alert.companyId, playbookId: playbook._id,
      createdAt: { $gte: new Date(Date.now() - 60 * 60_000) },
    });
    if (executionsThisHour >= Math.max(1, Number(playbook.maxExecutionsPerHour || 10))) continue;
    for (const step of [...(playbook.steps || [])].sort((a, b) => a.order - b.order)) {
      const actionParams = responseParamsForAlert(step.actionType, step.actionParams, alert);
      const response = await createResponse({ companyId: alert.companyId, tenantId: alert.tenantId, alert, system, actionType: step.actionType, actionParams, playbook, trigger: 'playbook', io, forceApproval: Boolean(step.requireApproval) });
      if (response) responses.push(response);
    }
    await ResponsePlaybook.updateOne({ _id: playbook._id }, { $inc: { matchCount: 1 }, $set: { lastMatchAt: new Date() } });
    if (playbook.stopOnMatch) break;
  }
  return responses;
}

async function recordAgentResult({ companyId, systemId, responseId, commandId, ok, result, durationMs = 0, exitCode = null }, io) {
  const response = await AutomatedResponse.findOne({ _id: responseId, companyId, systemId, commandId });
  if (!response) throw new Error('Response command was not found');
  if (!ACTIVE_STATUSES.has(response.status)) return response;
  const status = ok ? 'successful' : 'failed';
  const updated = await transition(response, status, result, null, io, {
    actionResult: String(result || '').slice(0, 2000), errorDetail: ok ? '' : String(result || '').slice(0, 2000),
    executionTimeMs: Number(durationMs || 0), completedAt: new Date(),
  });
  await require('./soar.service').recordSoarAgentResult(updated, ok, result);
  return updated;
}

async function recordAgentStatus({ companyId, systemId, responseId, commandId, status }, io) {
  if (!['acknowledged', 'executing'].includes(status)) throw new Error('Unsupported agent response status');
  const response = await AutomatedResponse.findOne({ _id: responseId, companyId, systemId, commandId });
  if (!response) throw new Error('Response command was not found');
  if (!ACTIVE_STATUSES.has(response.status)) return response;
  return transition(response, status, status === 'acknowledged' ? 'Command acknowledged by endpoint' : 'Endpoint action is executing', null, io, status === 'executing' ? { startedAt: new Date() } : {});
}

module.exports = { SUPPORTED_ACTIONS, HIGH_RISK_ACTIONS, ACTIVE_STATUSES, isHighRisk, requiresApprovalForAction, conditionMatches, playbookMatches, departmentScopeFilter, createResponse, createVerifiedProfileMismatchLock, dispatchResponse, evaluatePlaybooksForAlert, recordAgentResult, recordAgentStatus, transition };
