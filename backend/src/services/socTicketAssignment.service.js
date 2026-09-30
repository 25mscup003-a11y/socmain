const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const User = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocShift = require('../models/SocShift.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { requiredSocRoleForWorkItem, isThreatIntelligenceWorkItem } = require('./socAccess.service');
const { isShiftActiveAt } = require('./soarEmailRecipients.service');
const { createSocNotification } = require('./socNotification.service');
const { sendMail } = require('../utils/email');
const { claimAlertForTicket } = require('./socCaseExclusivity.service');

const ACTIVE_STATUSES = ['open', 'investigating'];
const routingTails = new Map();

function ticketCategoryFor(item = {}) {
  if (isThreatIntelligenceWorkItem(item)) return 'threat_intelligence';
  const text = [
    item.category, item.subCategory, item.eventCategory, item.sourceType,
    item.module, item.source, item.normalizedEventType, item.ruleId,
    item.signatureName, item.description,
  ].filter(Boolean).join(' ').toLowerCase();
  if (/ransom|malware|virus|trojan|yara|quarantin/.test(text)) return 'malware';
  if (/auth|identity|iam|login|credential|user|mfa|privilege/.test(text)) return 'identity';
  if (/ids|ips|zeek|network|dns|firewall|scan|c2|beacon/.test(text)) return 'network';
  if (/file|fim|integrity|registry/.test(text)) return 'file_integrity';
  if (/endpoint|edr|process|memory|system|kernel|service/.test(text)) return 'endpoint';
  return 'general';
}

function isIdsIpsFirewallTicket(item = {}) {
  const evidence = [
    item.sourceType, item.sourceVendor, item.sensor, item.module,
    item.source, item.source_type, item.detectionSource,
  ].filter(Boolean).join(' ').toLowerCase();
  return /(^|[^a-z])(ids|ips|suricata|zeek|firewall)([^a-z]|$)/.test(evidence);
}

function ticketAssignmentRoles(item = {}) {
  return isIdsIpsFirewallTicket(item)
    ? ['soc_manager', 'l4_analyst']
    : [requiredSocRoleForWorkItem(item)];
}

function roleRequirementLabel(roles = []) {
  return roles.map(role => role.replace(/_/g, ' ').toUpperCase()).join(' / ');
}

function rankEligibleAnalysts(analysts, categoryLoads = new Map(), totalLoads = new Map()) {
  return [...analysts].sort((a, b) => {
    const aId = String(a._id || a);
    const bId = String(b._id || b);
    return (categoryLoads.get(aId) || 0) - (categoryLoads.get(bId) || 0)
      || (totalLoads.get(aId) || 0) - (totalLoads.get(bId) || 0)
      || aId.localeCompare(bId);
  });
}

async function eligibleAnalystsFor(ticket, requiredRoles, now = new Date()) {
  const roles = Array.isArray(requiredRoles) ? requiredRoles : [requiredRoles];
  const assignmentFilter = { companyId: ticket.companyId, active: true };
  let candidateIds = await SocCompanyAssignment.find(assignmentFilter).distinct('userId');

  if (roles.includes('soc_manager')) {
    const managerIds = await User.find({
      role: 'soc_manager',
      isActive: true,
      accountStatus: 'active',
      $or: [
        { _id: { $in: candidateIds } },
        { companyId: ticket.companyId },
      ],
    }).distinct('_id');
    candidateIds = [...new Set([...candidateIds, ...managerIds].map(String))];
  }
  if (!candidateIds.length) return [];

  if (ticket.departmentId && !roles.includes('soc_manager')) {
    const departmentIds = await SocDepartmentAssignment.find({
      companyId: ticket.companyId,
      departmentId: ticket.departmentId,
      userId: { $in: candidateIds },
      active: true,
    }).distinct('userId');
    if (departmentIds.length) candidateIds = departmentIds;
  }

  const analysts = await User.find({
    _id: { $in: candidateIds },
    role: { $in: roles },
    isActive: true,
    accountStatus: 'active',
  }).select('_id name email role').lean();
  if (!analysts.length) return [];

  const configuredShifts = await SocShift.find({ companyId: ticket.companyId, active: true })
    .select('timezone startTime endTime weekdays analystIds').lean();
  const onShift = new Set(configuredShifts
    .filter(shift => isShiftActiveAt(shift, now))
    .flatMap(shift => shift.analystIds || [])
    .map(String));
  const onShiftForRole = analysts.filter(analyst => onShift.has(String(analyst._id)));

  // Prefer active shift coverage, but do not strand a severity tier when its
  // required role is missing from the current shift. Company-scoped active
  // analysts remain the controlled fallback; TI can still only reach L4.
  return onShiftForRole.length ? onShiftForRole : analysts;
}

async function selectLeastLoadedAnalyst(ticket, category, requiredRoles, now = new Date()) {
  const analysts = await eligibleAnalystsFor(ticket, requiredRoles, now);
  if (!analysts.length) return null;
  const ids = analysts.map(item => item._id);
  const [categoryRows, alertRows, incidentRows] = await Promise.all([
    Alert.aggregate([
      { $match: { assignedTo: { $in: ids }, ticketCategory: category, status: { $in: ACTIVE_STATUSES } } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    ]),
    Alert.aggregate([
      { $match: { assignedTo: { $in: ids }, status: { $in: ACTIVE_STATUSES } } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    ]),
    EdrIncident.aggregate([
      { $match: { assignedTo: { $in: ids }, status: { $in: ['open', 'investigating', 'contained'] } } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    ]),
  ]);
  const categoryLoads = new Map(categoryRows.map(row => [String(row._id), Number(row.count || 0)]));
  const totalLoads = new Map();
  [...alertRows, ...incidentRows].forEach(row => {
    const id = String(row._id);
    totalLoads.set(id, (totalLoads.get(id) || 0) + Number(row.count || 0));
  });
  const selected = rankEligibleAnalysts(analysts, categoryLoads, totalLoads)[0];
  return selected ? {
    analyst: selected,
    categoryWorkload: categoryLoads.get(String(selected._id)) || 0,
    totalWorkload: totalLoads.get(String(selected._id)) || 0,
  } : null;
}

async function writeTicketAudit(ticket, action, metadata) {
  let actorId = metadata.actorId || metadata.assigneeId || ticket.ticketOpenedBy;
  if (!actorId) {
    const companyUsers = await SocCompanyAssignment.find({ companyId: ticket.companyId, active: true }).distinct('userId');
    actorId = (await User.findOne({ _id: { $in: companyUsers }, role: 'soc_manager', isActive: true }).select('_id').lean())?._id;
  }
  if (!actorId || !ticket.tenantId) return null;
  return SocAuditEvent.create({
    tenantId: ticket.tenantId,
    companyId: ticket.companyId,
    actorId,
    action,
    targetType: 'Alert',
    targetId: String(ticket._id),
    metadata,
    ipAddress: 'system',
  }).catch(() => null);
}

async function notifyUsers(ticket, users, type, title, message) {
  const uniqueUsers = [...new Map((users || []).filter(user => user?._id).map(user => [String(user._id), user])).values()];
  if (!uniqueUsers.length) return;
  await Promise.all(uniqueUsers.map(async user => {
    const rolePrefix = {
      soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2',
      l3_analyst: '/l3', l4_analyst: '/l4',
    }[user.role] || '';
    const notification = await createSocNotification({
      tenantId: ticket.tenantId || user.tenantId || null,
      companyId: ticket.companyId,
      userId: user._id,
      ticketId: ticket._id,
      type,
      sourceType: 'ticket',
      sourceId: ticket._id,
      dedupeKey: `ticket:${ticket._id}:${type}`,
      title,
      message,
      link: rolePrefix ? `${rolePrefix}/tickets/${ticket._id}` : '',
    }).catch(() => null);
    if (user.email && notification) {
      await sendMail({
        to: user.email,
        subject: title,
        text: `${message}\n\nTicket ID: ${ticket._id}`,
      }).catch(error => console.error(`[SOC ticket email] ${user.email}:`, error.message));
    }
  }));
}

async function companySocManagers(ticket) {
  const assignedIds = await SocCompanyAssignment.find({ companyId: ticket.companyId, active: true }).distinct('userId');
  return User.find({
    role: 'soc_manager',
    isActive: true,
    accountStatus: 'active',
    $or: [
      { _id: { $in: assignedIds } },
      { companyId: ticket.companyId },
    ],
  }).select('_id name email role tenantId').lean();
}

async function routeSoarTicket(alertOrId, options = {}) {
  const ticket = typeof alertOrId === 'object' && alertOrId._id
    ? await Alert.findById(alertOrId._id)
    : await Alert.findById(alertOrId);
  if (!ticket) throw new Error('SOAR ticket alert not found');

  const claim = await claimAlertForTicket(ticket._id, ticket.companyId);
  if (!claim.claimed) {
    const error = new Error('SOAR ticket skipped because this alert already belongs to an incident');
    error.code = 'SOC_CASE_INCIDENT_EXISTS';
    error.incidentId = claim.incidentId || null;
    throw error;
  }

  if (ticket.ticketSource === 'soar' && ticket.ticketRoutedAt && ticket.assignedTo) {
    const assignmentRoles = ticketAssignmentRoles(ticket);
    const assignee = await User.findById(ticket.assignedTo).select('_id name email role').lean();
    if (assignee && assignmentRoles.includes(assignee.role)) {
      return {
        ticket,
        assignee,
        requiredRole: roleRequirementLabel(assignmentRoles),
        eligibleRoles: assignmentRoles,
        category: ticket.ticketCategory || ticketCategoryFor(ticket),
        queuedForManager: true,
        alreadyRouted: true,
      };
    }
  }

  const now = options.now || new Date();
  const category = ticketCategoryFor(ticket);
  const assignmentRoles = ticketAssignmentRoles(ticket);
  const requiredRole = roleRequirementLabel(assignmentRoles);
  ticket.ticketOpenedAt ||= now;
  ticket.ticketQueuedAt ||= now;
  ticket.ticketSource = 'soar';
  ticket.ticketCategory = category;
  ticket.ticketOpenedBy ||= options.openedBy || null;
  // The SOC Manager queue receives the ticket before the routing decision.
  ticket.assignedTo = null;
  ticket.ticketRoutedAt = null;
  ticket.ticketAssignmentMode = null;
  await ticket.save();

  ticket.auditHistory.push({
    action: 'soar.ticket.queued_for_manager',
    at: now,
    actorId: options.openedBy || null,
    metadata: { source: 'soar', category, severity: ticket.severity, executionId: options.executionId || null },
  });
  await ticket.save();
  const managers = await companySocManagers(ticket);
  await notifyUsers(
    ticket,
    managers,
    'ticket_queued',
    `[SOAR Ticket] ${String(ticket.severity || 'low').toUpperCase()} ${category.replace(/_/g, ' ')} ticket queued`,
    `SOAR sent a ${category.replace(/_/g, ' ')} ticket to your SOC Manager queue. Automatic ${requiredRole} routing is being evaluated by current shift and workload.`,
  );
  await writeTicketAudit(ticket, 'soar.ticket.queued_for_manager', {
    actorId: options.openedBy || null,
    source: 'soar', category, severity: ticket.severity,
    executionId: options.executionId ? String(options.executionId) : null,
  });

  const selection = await selectLeastLoadedAnalyst(ticket, category, assignmentRoles, now);
  if (!selection) {
    return { ticket, assignee: null, requiredRole, eligibleRoles: assignmentRoles, category, queuedForManager: true };
  }

  const updated = await Alert.findOneAndUpdate(
    { _id: ticket._id, assignedTo: null, status: { $in: ACTIVE_STATUSES } },
    { $set: {
      assignedTo: selection.analyst._id,
      ticketRoutedAt: new Date(),
      ticketAssignmentMode: 'auto',
      ...(ticket.status === 'open' ? { status: 'investigating' } : {}),
    } },
    { new: true },
  );
  if (!updated) return { ticket, assignee: null, requiredRole, category, queuedForManager: true };

  await Alert.updateOne({ _id: updated._id }, { $push: { auditHistory: {
    action: 'soar.ticket.auto_assigned',
    at: new Date(),
    actorId: selection.analyst._id,
    metadata: {
      assigneeId: selection.analyst._id,
      category,
      severity: updated.severity,
      requiredRole,
      eligibleRoles: assignmentRoles,
      categoryWorkloadBeforeAssignment: selection.categoryWorkload,
      totalWorkloadBeforeAssignment: selection.totalWorkload,
    },
  } } });

  await writeTicketAudit(updated, 'soar.ticket.auto_assigned', {
    assigneeId: selection.analyst._id,
    source: 'soar', category, severity: updated.severity, requiredRole,
    categoryWorkloadBeforeAssignment: selection.categoryWorkload,
    totalWorkloadBeforeAssignment: selection.totalWorkload,
    executionId: options.executionId ? String(options.executionId) : null,
  });
  await notifyUsers(
    updated,
    [selection.analyst],
    'ticket_assigned',
    `[SOC Ticket Assigned] ${String(updated.severity || 'low').toUpperCase()} ${category.replace(/_/g, ' ')}`,
    `A ${category.replace(/_/g, ' ')} ticket was automatically assigned to you based on severity and the lowest same-category workload.`,
  );
  return {
    ticket: updated,
    assignee: selection.analyst,
    requiredRole,
    eligibleRoles: assignmentRoles,
    category,
    categoryWorkload: selection.categoryWorkload,
    totalWorkload: selection.totalWorkload,
    queuedForManager: true,
  };
}

async function queueAndAutoAssignSoarTicket(alertOrId, options = {}) {
  const ticketId = alertOrId?._id || alertOrId;
  const identity = await Alert.findById(ticketId).select('_id companyId').lean();
  if (!identity) throw new Error('SOAR ticket alert not found');
  const key = String(identity.companyId);
  const previous = routingTails.get(key) || Promise.resolve();
  const current = previous.catch(() => null).then(() => routeSoarTicket(identity._id, options));
  routingTails.set(key, current);
  try {
    return await current;
  } finally {
    if (routingTails.get(key) === current) routingTails.delete(key);
  }
}

module.exports = {
  ticketCategoryFor,
  isIdsIpsFirewallTicket,
  ticketAssignmentRoles,
  rankEligibleAnalysts,
  selectLeastLoadedAnalyst,
  queueAndAutoAssignSoarTicket,
};
