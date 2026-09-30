const Alert = require('../models/Alert.model');
const AutomatedResponse = require('../models/AutomatedResponse.model');
const System = require('../models/System.model');
const User = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const UebaProfileLockEvent = require('../models/UebaProfileLockEvent.model');
const { sendMail } = require('../utils/email');

const ACTIVE_RESPONSE_STATUSES = new Set(['created', 'waiting_approval', 'approved', 'queued', 'sent_to_agent', 'acknowledged', 'executing', 'pending', 'running']);
const FAILED_RESPONSE_STATUSES = new Set(['failed', 'timed_out', 'cancelled', 'rollback_failed']);
const PROTECTED_EVENT_STATUSES = ['lock_dispatching', 'lock_pending', 'locked', 'unlock_pending', 'unlock_failed'];
const IDENTITY_RESPONSE_ACTIONS = new Set(['lock_account', 'force_logoff', 'isolate']);
const SERVICE_USERS = /^(?:system|local service|network service|localsystem|root|daemon|nobody|www-data|sshd|messagebus|svc[-_.].*|.*\$)$/i;
// Endpoint-local lock only. Domain/UPN identities require an IdP connector and
// are notified for verification instead of risking a tenant-wide directory lock.
const SAFE_USERNAME = /^[a-z0-9][a-z0-9._-]{0,127}$/i;

function isSafeLocalUsername(username) {
  const value = String(username || '').trim();
  return Boolean(value && SAFE_USERNAME.test(value) && !SERVICE_USERS.test(value));
}

function isProfileMismatch(alert) {
  return alert?.ruleId === 'UEBA_INPUT_PROFILE_MISMATCH'
    && alert?.inputProfileMismatch === true
    && Number(alert?.inputBaselineDays || 0) >= 30;
}

function safeInteractiveUsername(alert) {
  const username = String(alert?.username || '').trim();
  return Boolean(isSafeLocalUsername(username)
    && alert?.inputUserVerified === true
    && Number(alert?.inputSessionCount || 0) === 1);
}

function responseEventStatus(response, action) {
  const status = String(response?.status || '');
  if (action === 'unlock') {
    if (['successful', 'success'].includes(status)) return 'unlocked';
    if (FAILED_RESPONSE_STATUSES.has(status)) return 'unlock_failed';
    return 'unlock_pending';
  }
  if (['successful', 'success'].includes(status)) return 'locked';
  if (FAILED_RESPONSE_STATUSES.has(status)) return 'lock_failed';
  return ACTIVE_RESPONSE_STATUSES.has(status) ? 'lock_pending' : 'lock_pending';
}

function emitUpdate(io, event) {
  if (!io || !event) return;
  io.to(`company:${event.companyId}`).emit('ueba:profile-lock', {
    id: String(event._id), status: event.status, systemId: String(event.systemId),
    hostname: event.hostname, username: event.username, updatedAt: event.updatedAt,
  });
}

async function resolveRecipients(event) {
  const [companyAdmins, companyAssignments, departmentAssignments] = await Promise.all([
    User.find({ companyId: event.companyId, role: 'company_admin', isActive: true, accountStatus: 'active' }).select('_id email').lean(),
    SocCompanyAssignment.find({ companyId: event.companyId, active: true }).select('userId').lean(),
    event.departmentId
      ? SocDepartmentAssignment.find({ companyId: event.companyId, departmentId: event.departmentId, active: true }).select('userId').lean()
      : [],
  ]);
  const assignedIds = [...new Set([
    ...companyAssignments.map(item => String(item.userId)),
    ...departmentAssignments.map(item => String(item.userId)),
  ])];
  const [departmentAdmins, assignedManagers] = await Promise.all([
    event.departmentId ? User.find({
      companyId: event.companyId, role: 'department_admin', isActive: true, accountStatus: 'active',
      $or: [{ departmentId: event.departmentId }, { departmentIds: event.departmentId }],
    }).select('_id email').lean() : [],
    assignedIds.length ? User.find({
      _id: { $in: assignedIds }, role: 'soc_manager', isActive: true, accountStatus: 'active',
    }).select('_id email').lean() : [],
  ]);
  return [...new Set([...companyAdmins, ...departmentAdmins, ...assignedManagers]
    .map(user => String(user.email || '').trim().toLowerCase())
    .filter(email => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)))];
}

function htmlEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
}

async function sendIdentityProtectionNotification(event) {
  const recipients = await resolveRecipients(event);
  if (!recipients.length) {
    event.notificationStatus = 'not_configured';
    event.notificationError = 'No active company admin, department admin, or assigned SOC manager email was found';
    await event.save();
    return;
  }
  const baseUrl = String(process.env.FRONTEND_URL || process.env.APP_URL || 'http://localhost:3000').replace(/\/$/, '');
  const detailUrl = `${baseUrl}/profile-locks?event=${event._id}`;
  const geolocation = event.sourceType === 'geolocation_response';
  const actions = (event.responseActions || []).map(item => String(item.actionType || '').replaceAll('_', ' ')).join(', ') || 'account lock';
  try {
    await sendMail({
      to: recipients,
      subject: geolocation
        ? `[Geolocation Response] ${event.hostname} / ${event.username}`
        : `[UEBA Verification Required] ${event.hostname} / ${event.username}`,
      text: geolocation
        ? `A geolocation anomaly response (${actions}) was requested for ${event.username} on ${event.hostname}. Current status: ${event.status}. Review and approve pending high-risk actions in AJNAT SOC: ${detailUrl}`
        : `A 30-day aggregate input behavior profile mismatch was detected for ${event.username} on ${event.hostname}. Account protection status: ${event.status}. This signal does not prove a different person; interactive identity verification is required. Review: ${detailUrl}`,
      html: geolocation
        ? `<div style="font-family:Arial,sans-serif;color:#0f172a"><h2>Geolocation identity protection response</h2><p>AJNAT SOC recorded a geolocation anomaly response action.</p><table cellpadding="7" style="border-collapse:collapse"><tr><td><b>Endpoint</b></td><td>${htmlEscape(event.hostname)}</td></tr><tr><td><b>Account</b></td><td>${htmlEscape(event.username)}</td></tr><tr><td><b>Source</b></td><td>${htmlEscape([event.sourceIp, event.geoCity, event.geoCountry].filter(Boolean).join(' · ') || 'Not reported')}</td></tr><tr><td><b>Actions</b></td><td>${htmlEscape(actions)}</td></tr><tr><td><b>Status</b></td><td>${htmlEscape(event.status)}</td></tr></table><p>Endpoint-confirmed lock status is required before account unlock becomes available.</p><p><a href="${htmlEscape(detailUrl)}">Open identity protection log</a></p></div>`
        : `<div style="font-family:Arial,sans-serif;color:#0f172a"><h2>UEBA profile mismatch — verification required</h2><p>A 30-day aggregate mouse/keyboard behavior profile mismatch was detected.</p><table cellpadding="7" style="border-collapse:collapse"><tr><td><b>Endpoint</b></td><td>${htmlEscape(event.hostname)}</td></tr><tr><td><b>Account</b></td><td>${htmlEscape(event.username)}</td></tr><tr><td><b>Confidence</b></td><td>${Number(event.confidence || 0)}%</td></tr><tr><td><b>Protection</b></td><td>${htmlEscape(event.status)}</td></tr></table><p><b>This signal is not identity proof.</b> Verify the user interactively before unlocking.</p><p><a href="${htmlEscape(detailUrl)}">Open lock event details</a></p></div>`,
    });
    event.notificationRecipients = recipients;
    event.notificationStatus = 'sent';
    event.notificationError = '';
    event.auditTrail.push({ action: 'notification.sent', message: `Email sent to ${recipients.length} scoped administrator/SOC recipient(s)` });
  } catch (error) {
    event.notificationRecipients = recipients;
    event.notificationStatus = 'failed';
    event.notificationError = String(error.message || error).slice(0, 500);
    event.auditTrail.push({ action: 'notification.failed', message: event.notificationError });
  }
  await event.save();
}

async function createEvent(alert, system) {
  try {
    return await UebaProfileLockEvent.create({
      tenantId: alert.tenantId,
      partnerId: alert.partnerId || null,
      companyId: alert.companyId,
      departmentId: alert.departmentId || system.departmentId || null,
      alertId: alert._id,
      systemId: system._id,
      agentId: system.agentId || alert.agentId || '',
      hostname: system.hostname || system.name || alert.hostname || alert.agentName || 'Unknown endpoint',
      username: String(alert.username || 'unresolved').slice(0, 128),
      sourceType: 'ueba_profile_mismatch',
      sourceCapabilityId: 11,
      detectionName: alert.ruleName || alert.description || alert.ruleId || 'UEBA input profile mismatch',
      riskScore: Math.max(0, Math.min(100, Number(alert.riskScore || 0))),
      confidence: Math.max(0, Math.min(100, Number(alert.inputIdentityConfidence || alert.uebaConfidence || 0))),
      baselineDays: Math.max(0, Math.min(30, Number(alert.inputBaselineDays || 0))),
      mismatchFeatures: (alert.inputProfileMismatchFeatures || []).map(String).slice(0, 8),
      featureDeviation: alert.inputProfileDeviation || {},
      privacyMode: alert.inputPrivacyMode || 'aggregate_counts_only',
      auditTrail: [{ action: 'profile_mismatch.detected', message: '30-day aggregate behavior mismatch requires interactive user verification' }],
    });
  } catch (error) {
    if (error?.code === 11000) return UebaProfileLockEvent.findOne({ alertId: alert._id });
    throw error;
  }
}

async function processProfileMismatchAlert(alert, io = null) {
  if (!isProfileMismatch(alert) || !alert?.companyId || !alert?.tenantId || !alert?.systemId) return null;
  const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId, isActive: true });
  if (!system) return null;
  const event = await createEvent(alert, system);
  if (!event || event.lockResponseId || event.status !== 'detected') return event;

  if (!safeInteractiveUsername(alert)) {
    event.status = 'lock_skipped';
    event.auditTrail.push({ action: 'account_lock.skipped', message: 'Auto-lock skipped: exactly one verified non-service interactive username is required' });
    await event.save();
    emitUpdate(io, event);
    await sendIdentityProtectionNotification(event);
    return event;
  }

  const duplicate = await UebaProfileLockEvent.findOne({
    _id: { $ne: event._id }, companyId: event.companyId, systemId: event.systemId,
    username: event.username, status: { $in: PROTECTED_EVENT_STATUSES },
    createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60_000) },
  }).sort({ createdAt: -1 });
  if (duplicate) {
    event.status = duplicate.status;
    event.lockResponseId = duplicate.lockResponseId;
    event.notificationStatus = 'suppressed_duplicate';
    event.auditTrail.push({ action: 'account_lock.deduplicated', message: `Existing protection workflow ${duplicate._id} reused` });
    await event.save();
    emitUpdate(io, event);
    return event;
  }

  const claimed = await UebaProfileLockEvent.findOneAndUpdate(
    { _id: event._id, status: 'detected', lockResponseId: null },
    { $set: { status: 'lock_dispatching' }, $push: { auditTrail: { action: 'account_lock.dispatching', message: 'Validated mismatch; signed endpoint lock command is being created' } } },
    { new: true },
  );
  if (!claimed) return UebaProfileLockEvent.findById(event._id);

  try {
    const { createVerifiedProfileMismatchLock } = require('./automatedResponse.service');
    const response = await createVerifiedProfileMismatchLock({ alert, system, io });
    claimed.lockResponseId = response._id;
    claimed.status = responseEventStatus(response, 'lock');
    claimed.auditTrail.push({ action: 'account_lock.queued', message: `Signed endpoint command ${response.commandId || response._id} queued` });
  } catch (error) {
    claimed.status = 'lock_failed';
    claimed.auditTrail.push({ action: 'account_lock.failed', message: String(error.message || error).slice(0, 600) });
  }
  await claimed.save();
  emitUpdate(io, claimed);
  await sendIdentityProtectionNotification(claimed);
  return claimed;
}

function responseActionState(response) {
  const status = String(response?.status || 'created');
  if (['successful', 'success'].includes(status)) return 'successful';
  if (FAILED_RESPONSE_STATUSES.has(status)) return 'failed';
  return 'pending';
}

function deriveProtectionStatus(event) {
  const actions = event.responseActions || [];
  const lock = actions.find(item => item.actionType === 'lock_account');
  if (lock) {
    if (event.unlockResponseId) {
      if (event.unlockedAt) return 'unlocked';
      if (event.status === 'unlock_failed') return 'unlock_failed';
      return 'unlock_pending';
    }
    if (lock.status === 'successful') return 'locked';
    if (lock.status === 'failed') return 'lock_failed';
    return 'lock_pending';
  }
  if (actions.some(item => item.status === 'pending')) return 'response_pending';
  if (actions.some(item => item.status === 'successful')) return 'response_success';
  if (actions.length && actions.every(item => item.status === 'failed')) return 'response_failed';
  return event.status || 'detected';
}

function geolocationPolicyResponse(alert = {}) {
  const raw = alert.rawEvent || {};
  const nestedRaw = raw.raw || {};
  const containmentStatus = String(alert.containmentStatus || raw.containmentStatus || raw.containment_status || '').toLowerCase();
  const logoutRequested = raw.systemLogoutRequested === true || raw.sessionRevokeRequested === true
    || nestedRaw.systemLogoutRequested === true || nestedRaw.sessionRevokeRequested === true;
  const isolationRequested = raw.geoFenceLockRequested === true || raw.lockRecommended === true
    || nestedRaw.geoFenceLockRequested === true || nestedRaw.lockRecommended === true;
  const ipBlockRequested = raw.ipBlockRequested === true || nestedRaw.ipBlockRequested === true;
  const actionType = logoutRequested ? 'force_logoff' : isolationRequested ? 'isolate' : ipBlockRequested ? 'block_ip' : null;
  if (!actionType) return null;
  const successful = actionType === 'force_logoff'
    ? containmentStatus === 'logged_out'
    : actionType === 'isolate'
      ? containmentStatus === 'isolated'
      : containmentStatus === 'blocked';
  const failed = /fail|error/.test(containmentStatus)
    || Boolean(raw.logoutError || raw.lockError || raw.ipBlockError
      || nestedRaw.logoutError || nestedRaw.lockError || nestedRaw.ipBlockError);
  return {
    actionType,
    status: successful ? 'successful' : failed ? 'failed' : 'pending',
    result: String(
      raw.logoutError || raw.lockError || raw.ipBlockError || raw.sessionResponse?.action
      || nestedRaw.logoutError || nestedRaw.lockError || nestedRaw.ipBlockError || nestedRaw.sessionResponse?.action
      || alert.description || containmentStatus
    ).slice(0, 1000),
  };
}

async function processGeolocationProtectionAlert(alert, io = null) {
  const capabilityIds = [alert?.capabilityId, ...(alert?.capabilityIds || [])].map(Number);
  if (!alert?._id || !capabilityIds.includes(23) || !alert.companyId || !alert.systemId) return null;
  const raw = alert.rawEvent || {};
  const policyResponse = geolocationPolicyResponse(alert);
  if (!policyResponse) return null;
  const { actionType, status: actionStatus, result: actionResult } = policyResponse;

  const system = await System.findOne({ _id: alert.systemId, companyId: alert.companyId, isActive: true });
  const tenantId = alert.tenantId || system?.tenantId;
  if (!system || !tenantId) return null;
  const completed = actionStatus !== 'pending';

  let event = await UebaProfileLockEvent.findOne({ alertId: alert._id });
  let created = false;
  if (!event) {
    try {
      event = await UebaProfileLockEvent.create({
        tenantId,
        partnerId: alert.partnerId || system.partnerId || null,
        companyId: alert.companyId,
        departmentId: alert.departmentId || system.departmentId || null,
        alertId: alert._id,
        systemId: system._id,
        agentId: system.agentId || alert.agentId || '',
        hostname: system.hostname || system.name || alert.hostname || alert.agentName || 'Unknown endpoint',
        username: String(alert.username || alert.user || 'unresolved').trim().slice(0, 128) || 'unresolved',
        sourceType: 'geolocation_response',
        sourceCapabilityId: 23,
        detectionName: String(alert.ruleName || alert.description || alert.ruleId || 'Geolocation policy response').slice(0, 300),
        sourceIp: String(alert.srcip || alert.sourceIp || '').slice(0, 64),
        geoCountry: String(alert.geoCountry || alert.country || '').slice(0, 128),
        geoCity: String(alert.geoCity || alert.city || '').slice(0, 128),
        riskScore: Math.max(0, Math.min(100, Number(alert.riskScore || 0))),
        verificationMessage: 'Agent-enforced geolocation policy action recorded. Verify identity and endpoint evidence before account recovery.',
        auditTrail: [{ action: 'geolocation_policy.enforced', message: String(alert.description || `${actionType} policy action reported`).slice(0, 600) }],
      });
      created = true;
    } catch (error) {
      if (error?.code !== 11000) throw error;
      event = await UebaProfileLockEvent.findOne({ alertId: alert._id });
    }
  }
  if (!event) return null;
  const exists = (event.responseActions || []).some(item => item.actionSource === 'agent_policy' && item.actionType === actionType);
  if (!exists) {
    event.responseActions.push({
      actionType,
      actionSource: 'agent_policy',
      status: actionStatus,
      result: actionResult,
      requestedAt: alert.createdAt || new Date(),
      completedAt: completed ? (alert.createdAt || new Date()) : null,
    });
    event.status = deriveProtectionStatus(event);
    await event.save();
  }
  emitUpdate(io, event);
  if (created || !exists) await sendIdentityProtectionNotification(event);
  return event;
}

async function trackIdentityProtectionResponse({ response, alert, system, actor = null, reason = '', io = null }) {
  if (!response?._id || !alert?._id || !IDENTITY_RESPONSE_ACTIONS.has(response.actionType)) return null;
  const capabilityIds = [alert.capabilityId, ...(alert.capabilityIds || [])].map(Number);
  if (!capabilityIds.includes(23)) return null;
  const tenantId = alert.tenantId || system?.tenantId;
  if (!tenantId || !alert.companyId || !system?._id) throw new Error('Tenant, company and endpoint identity are required for protection tracking');

  let event = await UebaProfileLockEvent.findOne({ alertId: alert._id });
  if (!event) {
    try {
      event = await UebaProfileLockEvent.create({
        tenantId,
        partnerId: alert.partnerId || system.partnerId || null,
        companyId: alert.companyId,
        departmentId: alert.departmentId || system.departmentId || null,
        alertId: alert._id,
        systemId: system._id,
        agentId: system.agentId || alert.agentId || '',
        hostname: system.hostname || system.name || alert.hostname || alert.agentName || 'Unknown endpoint',
        username: String(alert.username || alert.user || 'unresolved').trim().slice(0, 128) || 'unresolved',
        sourceType: 'geolocation_response',
        sourceCapabilityId: 23,
        detectionName: String(alert.ruleName || alert.description || alert.ruleId || 'Geolocation anomaly').slice(0, 300),
        sourceIp: String(alert.srcip || alert.sourceIp || '').slice(0, 64),
        geoCountry: String(alert.geoCountry || alert.country || alert.sourceGeo?.country || '').slice(0, 128),
        geoCity: String(alert.geoCity || alert.city || alert.sourceGeo?.city || '').slice(0, 128),
        riskScore: Math.max(0, Math.min(100, Number(alert.riskScore || 0))),
        confidence: Math.max(0, Math.min(100, Number(alert.confidenceScore || alert.geoConfidence || 0))),
        verificationMessage: 'Geolocation anomaly response recorded. Verify the identity and endpoint evidence before account recovery.',
        auditTrail: [{
          action: 'geolocation_response.detected',
          message: String(reason || 'Geolocation anomaly containment response requested').slice(0, 600),
          actorId: actor?._id || actor?.id || null,
          actorRole: actor?.role || 'system',
        }],
      });
    } catch (error) {
      if (error?.code !== 11000) throw error;
      event = await UebaProfileLockEvent.findOne({ alertId: alert._id });
    }
  }
  if (!event) throw new Error('Unable to create identity protection log');

  let actionAdded = false;
  if (!(event.responseActions || []).some(item => String(item.responseId) === String(response._id))) {
    actionAdded = true;
    event.responseActions.push({
      actionType: response.actionType,
      responseId: response._id,
      status: responseActionState(response),
      result: String(response.actionResult || response.errorDetail || '').slice(0, 1000),
      requestedAt: response.createdAt || new Date(),
      completedAt: response.completedAt || null,
    });
    if (response.actionType === 'lock_account') event.lockResponseId = response._id;
    event.status = deriveProtectionStatus(event);
    event.auditTrail.push({
      action: `${response.actionType}.requested`,
      message: `${String(reason || 'Containment requested').slice(0, 440)} · Response ${response._id} is ${response.status}`,
      actorId: actor?._id || actor?.id || null,
      actorRole: actor?.role || 'system',
    });
    await event.save();
  }
  emitUpdate(io, event);
  if (actionAdded) await sendIdentityProtectionNotification(event);
  return event;
}

async function syncProfileLockFromResponse(response, io = null) {
  if (!response?._id || ![...IDENTITY_RESPONSE_ACTIONS, 'enable_user'].includes(response.actionType)) return null;
  const selector = response.actionType === 'enable_user'
    ? { unlockResponseId: response._id }
    : { $or: [{ lockResponseId: response._id }, { 'responseActions.responseId': response._id }] };
  const event = await UebaProfileLockEvent.findOne(selector);
  if (!event) return null;
  const previousStatus = event.status;
  let actionChanged = false;
  let nextStatus;
  if (response.actionType === 'enable_user') {
    nextStatus = responseEventStatus(response, 'unlock');
    event.status = nextStatus;
    if (nextStatus === 'unlocked') event.unlockedAt = response.completedAt || new Date();
  } else {
    const action = (event.responseActions || []).find(item => String(item.responseId) === String(response._id));
    if (action) {
      const actionStatus = responseActionState(response);
      const actionResult = String(response.actionResult || response.errorDetail || response.status).slice(0, 1000);
      actionChanged = action.status !== actionStatus || action.result !== actionResult;
      action.status = actionStatus;
      action.result = actionResult;
      action.completedAt = response.completedAt || (actionStatus === 'pending' ? null : new Date());
    }
    if (response.actionType === 'lock_account' && responseActionState(response) === 'successful') {
      event.lockedAt = response.completedAt || new Date();
    }
    nextStatus = action
      ? deriveProtectionStatus(event)
      : responseEventStatus(response, 'lock');
    event.status = nextStatus;
  }
  if (!actionChanged && previousStatus === nextStatus) return event;
  event.auditTrail.push({ action: `${response.actionType}.${nextStatus}`, message: String(response.actionResult || response.errorDetail || response.status).slice(0, 600) });
  await event.save();
  emitUpdate(io, event);
  if (['locked', 'unlocked', 'response_success', 'response_failed', 'lock_failed', 'unlock_failed'].includes(nextStatus)) {
    await sendIdentityProtectionNotification(event);
  }
  return event;
}

async function hydrateResponseStatuses(events, io = null) {
  const responseIds = [...new Set(events.flatMap(event => [
    event.lockResponseId,
    event.unlockResponseId,
    ...(event.responseActions || []).map(item => item.responseId),
  ]).filter(Boolean).map(String))];
  if (!responseIds.length) return events;
  const responses = await AutomatedResponse.find({ _id: { $in: responseIds } }).select('status actionType completedAt actionResult errorDetail').lean();
  const updatedEvents = await Promise.all(responses.map(response => syncProfileLockFromResponse(response, io)));
  updatedEvents.filter(Boolean).forEach(updated => {
    const target = events.find(event => String(event._id) === String(updated._id));
    if (!target) return;
    target.status = updated.status;
    target.lockedAt = updated.lockedAt;
    target.unlockedAt = updated.unlockedAt;
  });
  return events;
}

module.exports = {
  isProfileMismatch,
  safeInteractiveUsername,
  isSafeLocalUsername,
  responseEventStatus,
  responseActionState,
  deriveProtectionStatus,
  geolocationPolicyResponse,
  processProfileMismatchAlert,
  processGeolocationProtectionAlert,
  trackIdentityProtectionResponse,
  syncProfileLockFromResponse,
  hydrateResponseStatuses,
  resolveRecipients,
};
