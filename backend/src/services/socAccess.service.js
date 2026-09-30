const mongoose = require('mongoose');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');

const SOC_ROLES = ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const ANALYST_ROLES = ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const ROUTINE_QUEUE_RULES = [
  'FILE_CREATED', 'FILE_MODIFIED', 'FILE_DELETED', 'FILE_RENAMED',
  'PROC_STARTED', 'PROC_TERMINATED', 'PROC_INVENTORY_SUMMARY',
  'NET_DNS_SUMMARY', 'NET_CONNECTION_SUMMARY', 'NET_EXPOSURE_SUMMARY',
  'MEM_TOP_CONSUMER', 'SURICATA_stats',
];

function isThreatIntelligenceWorkItem(item = {}) {
  return item.incidentSource === 'threat_intelligence'
    || item.ticketCategory === 'threat_intelligence'
    || item.sourceType === 'THREAT_FEED'
    || item.iocMatched === true
    || (item.tiEnriched === true && Number(item.tiConfidence || 0) >= 50)
    || ['malicious', 'suspicious'].includes(String(item.vtVerdict || '').toLowerCase())
    || (Array.isArray(item.capabilityIds) && item.capabilityIds.includes(29));
}

function requiredSocRoleForWorkItem(item = {}) {
  if (isThreatIntelligenceWorkItem(item)) return 'l4_analyst';
  if (String(item.severity || '').toLowerCase() === 'critical') return 'l3_analyst';
  if (String(item.severity || '').toLowerCase() === 'high') return 'l2_analyst';
  return 'l1_analyst';
}

function socWorkItemFilter() {
  return {
    isSynthetic: { $ne: true },
    $and: [
      { ruleId: { $nin: ROUTINE_QUEUE_RULES } },
      { $or: [
        { severity: { $in: ['high', 'critical'] } },
        { actionable: true }, { blocked: true }, { quarantined: true },
        { iocMatched: true }, { correlationIds: { $exists: true, $ne: [] } },
        { action: { $in: ['blocked', 'dropped', 'rejected', 'quarantined'] } },
        { userAction: { $in: ['failed_login', 'brute_force', 'privilege_escalation'] } },
        { normalizedEventType: { $regex: /brute|impossible|malicious|suspicious|exploit|scan|c2|mfa.?bypass|disabled.?account/i } },
        { ruleId: { $regex: /^(AUTH_ROOT_LOGIN|AUTH_REMOTE_ACCESS|AUTH_SUDO|SYS_CRON_MOD|SYS_MODULE_LOAD|USB_LOG_DETECTED)$/i } },
      ] },
      // Resource telemetry is not threat intelligence unless an IOC, blocking
      // action, or an explicit detection made it security-relevant.
      { $or: [
        { eventCategory: { $nin: ['memory'] } },
        { iocMatched: true }, { actionable: true }, { blocked: true },
        { normalizedEventType: { $regex: /malware|exploit|injection|ransom|suspicious/i } },
      ] },
    ],
  };
}

async function allowedCompanyIds(user) {
  if (!user) return [];
  if (['company_admin', 'department_admin'].includes(user.role)) {
    return user.companyId ? [String(user.companyId)] : [];
  }
  // When DB is disconnected (e.g. unit testing environment), fallback to user.companyId if available
  if (mongoose.connection.readyState !== 1) {
    return user.companyId ? [String(user.companyId)] : [];
  }
  if (user.role === 'superadmin') {
    return (await Company.find().distinct('_id')).map(String);
  }
  if (user.role === 'partner_admin') {
    if (!user.partnerId) return [];
    return (await Company.find({ partnerId: user.partnerId }).distinct('_id')).map(String);
  }
  if (SOC_ROLES.includes(user.role) || user.role === 'analyst') {
    const assigned = await SocCompanyAssignment.find({ userId: user.id || user._id, active: true }).distinct('companyId');
    if (assigned.length) return assigned.map(String);
    if (user.companyId) return [String(user.companyId)];
  }
  return [];
}

async function assertCompanyScope(user, requestedIds) {
  const requested = [...new Set((requestedIds || []).filter(Boolean).map(String))];
  if (!requested.length) {
    const error = new Error('At least one company is required');
    error.status = 400;
    throw error;
  }
  const allowed = new Set(await allowedCompanyIds(user));
  if (requested.some(id => !allowed.has(id))) {
    const error = new Error('One or more companies are outside your authorized scope');
    error.status = 403;
    throw error;
  }
  return requested;
}

function forbidden(message) {
  const error = new Error(message);
  error.status = 403;
  return error;
}

async function resolveSocActor(user) {
  if (!user || user.role === 'superadmin' || mongoose.connection.readyState !== 1) return user;
  const actor = await User.findById(user.id || user._id)
    .select('_id role tenantId partnerId companyId socManagerId superadminManaged isActive accountStatus')
    .lean();
  if (!actor || actor.isActive === false || ['disabled', 'suspended'].includes(actor.accountStatus)) {
    throw forbidden('Your account cannot manage SOC staff');
  }
  return { ...user, ...actor, id: String(actor._id) };
}

function socStaffVisibilityFilter(actor) {
  if (actor?.role === 'superadmin') return {};
  if (actor?.role === 'soc_manager' && actor.superadminManaged === true) {
    return { superadminManaged: true };
  }
  return { superadminManaged: { $ne: true } };
}

function socInvitationVisibilityFilter(actor) {
  if (actor?.role === 'superadmin') return {};
  if (actor?.role === 'soc_manager' && actor.superadminManaged === true) {
    return { $or: [{ superadminManaged: true }, { socManagerPool: true }] };
  }
  return { superadminManaged: { $ne: true }, socManagerPool: { $ne: true } };
}

function assertSocStaffOrigin(actor, target) {
  if (actor?.role === 'superadmin') return;
  const actorIsSuperadminManaged = actor?.superadminManaged === true;
  const targetIsSuperadminManaged = target?.superadminManaged === true;

  if (actorIsSuperadminManaged !== targetIsSuperadminManaged) {
    throw forbidden('This SOC user is managed by a different administration scope');
  }
  if (actor?.role === 'partner_admin' && !actor.partnerId) {
    throw forbidden('Partner scope is missing');
  }
  if (actor?.partnerId && target?.partnerId && String(actor.partnerId) !== String(target.partnerId)) {
    throw forbidden('This SOC user belongs to another partner');
  }
  if (actor?.role === 'soc_manager') {
    if (!ANALYST_ROLES.includes(target?.role)) {
      throw forbidden('SOC Managers can manage analysts only');
    }
    if (target.socManagerId && String(target.socManagerId) !== String(actor.id || actor._id)) {
      throw forbidden('This analyst is managed by another SOC Manager');
    }
  }
}

async function assertSocStaffManagementScope(user, target) {
  const actor = await resolveSocActor(user);
  assertSocStaffOrigin(actor, target);
  if (actor?.role === 'superadmin') return { actor, companyIds: [], assignmentCompanyIds: [] };

  const companyIds = await allowedCompanyIds(actor);
  const allowed = new Set(companyIds.map(String));
  const assignmentCompanyIds = await SocCompanyAssignment.find({ userId: target._id, active: true }).distinct('companyId');
  if (!assignmentCompanyIds.length || assignmentCompanyIds.some(id => !allowed.has(String(id)))) {
    throw forbidden('This SOC user is outside your administration scope');
  }
  return { actor, companyIds, assignmentCompanyIds: assignmentCompanyIds.map(String) };
}

async function assertSocInvitationManagementScope(user, invitation) {
  const actor = await resolveSocActor(user);
  if (actor?.role === 'superadmin') return { actor, companyIds: [] };

  const invitationIsSuperadminManaged = invitation?.superadminManaged === true || invitation?.socManagerPool === true;
  const actorIsSuperadminManaged = actor?.role === 'soc_manager' && actor.superadminManaged === true;
  if (invitationIsSuperadminManaged !== actorIsSuperadminManaged) {
    throw forbidden('This invitation is managed by a different administration scope');
  }
  if (actor?.role === 'partner_admin' && !actor.partnerId) throw forbidden('Partner scope is missing');
  if (actor?.partnerId && invitation?.partnerId && String(actor.partnerId) !== String(invitation.partnerId)) {
    throw forbidden('This invitation belongs to another partner');
  }

  const companyIds = await allowedCompanyIds(actor);
  const allowed = new Set(companyIds.map(String));
  const scopeCompanyIds = await require('../models/SocInvitationScope.model')
    .find({ invitationId: invitation._id }).distinct('companyId');
  if (!scopeCompanyIds.length || scopeCompanyIds.some(id => !allowed.has(String(id)))) {
    throw forbidden('This invitation is outside your administration scope');
  }
  return { actor, companyIds };
}

async function getUserDataFilter(user, { personal = false } = {}) {
  const companyIds = await allowedCompanyIds(user);
  const filter = { companyId: { $in: companyIds } };
  if (user.role === 'department_admin' && user.departmentId) {
    filter.departmentId = user.departmentId;
  }
  if (ANALYST_ROLES.includes(user.role) || user.role === 'analyst') {
    if (mongoose.connection.readyState === 1) {
      const deptIds = await SocDepartmentAssignment.find({ userId: user.id || user._id, active: true }).distinct('departmentId');
      if (deptIds.length) filter.departmentId = { $in: deptIds };
    }
    if (personal) filter.assignedTo = user.id || user._id;
  }
  return { companyIds, filter };
}

module.exports = {
  SOC_ROLES,
  ANALYST_ROLES,
  ROUTINE_QUEUE_RULES,
  isThreatIntelligenceWorkItem,
  requiredSocRoleForWorkItem,
  socWorkItemFilter,
  allowedCompanyIds,
  assertCompanyScope,
  resolveSocActor,
  socStaffVisibilityFilter,
  socInvitationVisibilityFilter,
  assertSocStaffOrigin,
  assertSocStaffManagementScope,
  assertSocInvitationManagementScope,
  getUserDataFilter,
};
