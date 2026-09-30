const router = require('express').Router();
const mongoose = require('mongoose');
const { authenticate } = require('../middleware/auth.middleware');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const System = require('../models/System.model');
const SocEscalation = require('../models/SocEscalation.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocShift = require('../models/SocShift.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const LoginActivity = require('../models/LoginActivity.model');
const IdsIpsPolicy = require('../models/IdsIpsPolicy.model');
const Firewall = require('../models/Firewall.model');
const SocIncidentAuditReview = require('../models/SocIncidentAuditReview.model');
const SocNotification = require('../models/SocNotification.model');
const ForensicHunt = require('../models/ForensicHunt.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');
const AiAnalysis = require('../models/AiAnalysis.model');
const { syncHuntIfFinished } = require('../services/velociraptor.service');
const { SOC_ROLES, ANALYST_ROLES, socWorkItemFilter, allowedCompanyIds } = require('../services/socAccess.service');
const { buildPersonalAuditTrail } = require('../services/socAuditTrail.service');
const { isNetworkEvidenceAlert } = require('../utils/networkEvidence');

const ALLOWED = ['soc_manager', ...ANALYST_ROLES];
const LEVEL = { l1_analyst:'l1', l2_analyst:'l2', l3_analyst:'l3', l4_analyst:'l4', soc_manager:'manager' };
const NEXT_LEVEL = { l1_analyst:'l2', l2_analyst:'l3', l3_analyst:'manager' };
const CLOSURE_AUDIT_ROUTE = {
  l1_analyst: { reviewerRole: 'l2_analyst', auditType: 'standard' },
  l2_analyst: { reviewerRole: 'l3_analyst', auditType: 'standard' },
  l3_analyst: { reviewerRole: 'soc_manager', auditType: 'standard' },
  l4_analyst: { reviewerRole: 'soc_manager', auditType: 'threat' },
};

function idsIpsFirewallTicketFilter() {
  return { $or: [
    { sourceType: /^(IDS|IPS|FIREWALL)$/i },
    { module: /^(IDS|IPS|FIREWALL)$/i },
    { sourceVendor: /^(Suricata|Zeek|Firewall)$/i },
    { source: /^(ids|ips|suricata|zeek|firewall)$/i },
  ] };
}

function networkSecurityTicketFilter(kind) {
  const normalized = String(kind || '').toLowerCase();
  if (normalized === 'ids') return { $or: [
    { sourceType: /^IDS$/i },
    { sourceType: { $in: [null, ''] }, module: /^IDS$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: /^Zeek$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: { $in: [null, ''] }, source: /^(ids|zeek)$/i },
  ] };
  if (normalized === 'ips') return { $or: [
    { sourceType: /^IPS$/i },
    { sourceType: { $in: [null, ''] }, module: /^IPS$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: /^Suricata$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: { $in: [null, ''] }, source: /^(ips|suricata)$/i },
  ] };
  if (normalized === 'firewall') return { $or: [
    { sourceType: /^FIREWALL$/i },
    { sourceType: { $in: [null, ''] }, module: /^FIREWALL$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: /^Firewall$/i },
    { sourceType: { $in: [null, ''] }, module: { $in: [null, ''] }, sourceVendor: { $in: [null, ''] }, source: /^firewall$/i },
  ] };
  return idsIpsFirewallTicketFilter();
}

function appendAnd(filter, condition) {
  filter.$and = [...(filter.$and || []), condition];
}

router.use(authenticate);
router.use(async (req, res, next) => {
  const companyIncidentDetailRead = req.user?.role === 'company_admin'
    && req.method === 'GET'
    && /^\/incidents\/[a-f\d]{24}$/i.test(req.path);
  if (!ALLOWED.includes(req.user?.role) && !companyIncidentDetailRead) {
    return res.status(403).json({ message:'SOC dashboard role required' });
  }
  const account = await User.findById(req.user.id).select('role isActive accountStatus tenantId').lean();
  if (!account || !account.isActive || !['active', undefined].includes(account.accountStatus)) {
    return res.status(403).json({ message:'Account is not active' });
  }
  if (account.role !== req.user.role) return res.status(401).json({ message:'Session role is stale; sign in again' });
  next();
});

router.get('/notifications', async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const [items, unread] = await Promise.all([
      SocNotification.find({ userId: req.user.id })
        .sort({ createdAt: -1 }).limit(limit)
        .populate('companyId', 'name')
        .populate('actorId', 'name email role')
        .lean(),
      SocNotification.countDocuments({ userId: req.user.id, read: false }),
    ]);
    res.set('Cache-Control', 'no-store');
    res.json({ items, unread });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.patch('/notifications/read', async (req, res) => {
  try {
    const filter = { userId: req.user.id, read: false };
    if (req.body.notificationId) filter._id = req.body.notificationId;
    await SocNotification.updateMany(filter, { $set: { read: true, readAt: new Date() } });
    const unread = await SocNotification.countDocuments({ userId: req.user.id, read: false });
    req.app.get('io')?.to(`user:${req.user.id}`).emit('soc:notifications:read', { unread });
    res.json({ success: true, unread });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// Analysts can only see shifts to which they are explicitly assigned. This is
// intentionally separate from the manager endpoint, which exposes the full
// company schedule and its controls.
router.get('/shifts', async (req, res) => {
  try {
    const { companyIds } = await scope(req);
    const filter = { companyId: { $in: companyIds }, active: true };
    if (req.user.role !== 'soc_manager') filter.analystIds = req.user.id;
    const shifts = await SocShift.find(filter)
      .populate('companyId', 'name')
      .populate('analystIds', 'name email role')
      .populate('createdBy', 'name email role')
      .sort({ startTime: 1, name: 1 })
      .lean();
    res.set('Cache-Control', 'no-store');
    res.json(shifts);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

function pageParams(query) {
  return {
    page: Math.max(1, Math.min(100000, Number(query.page) || 1)),
    limit: Math.max(1, Math.min(100, Number(query.limit) || 20)),
  };
}

function escapeRegex(value) { return String(value || '').replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function dashboardRangeStart(range, now = new Date()) {
  const start = new Date(now);
  start.setHours(0, 0, 0, 0);
  if (range === '7d') start.setDate(start.getDate() - 6);
  if (range === '30d') start.setDate(start.getDate() - 29);
  return start;
}

function asObjectId(value) {
  if (value instanceof mongoose.Types.ObjectId) return value;
  return mongoose.Types.ObjectId.isValid(value) ? new mongoose.Types.ObjectId(value) : value;
}

function countMap(rows = []) {
  return Object.fromEntries(rows.map(row => [row._id || 'unknown', Number(row.count || 0)]));
}

function mergeCountMaps(...maps) {
  return maps.reduce((result, values) => {
    Object.entries(values || {}).forEach(([key, value]) => {
      result[key] = (result[key] || 0) + Number(value || 0);
    });
    return result;
  }, {});
}

function isShiftActiveNow(shift, now = new Date()) {
  try {
    const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
      timeZone: shift.timezone || 'UTC', weekday: 'short', hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).formatToParts(now).map(part => [part.type, part.value]));
    const dayIndex = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(parts.weekday);
    const minute = (Number(parts.hour) * 60) + Number(parts.minute);
    const [startHour, startMinute] = String(shift.startTime || '00:00').split(':').map(Number);
    const [endHour, endMinute] = String(shift.endTime || '00:00').split(':').map(Number);
    const start = (startHour * 60) + startMinute;
    const end = (endHour * 60) + endMinute;
    const weekdays = Array.isArray(shift.weekdays) && shift.weekdays.length ? shift.weekdays : [0, 1, 2, 3, 4, 5, 6];
    if (start <= end) return weekdays.includes(dayIndex) && minute >= start && minute < end;
    return (weekdays.includes(dayIndex) && minute >= start)
      || (weekdays.includes((dayIndex + 6) % 7) && minute < end);
  } catch (_) {
    return false;
  }
}

async function scope(req, { personal = false } = {}) {
  const companyIds = await allowedCompanyIds(req.user);
  const filter = { companyId: { $in: companyIds } };
  if (req.user.role !== 'soc_manager') {
    const departmentIds = await SocDepartmentAssignment.find({ userId:req.user.id, active:true }).distinct('departmentId');
    if (departmentIds.length) filter.departmentId = { $in: departmentIds };
    if (personal) filter.assignedTo = req.user.id;
  }
  return { companyIds, filter };
}

async function writeAudit(req, action, targetType, targetId, companyId, metadata = {}) {
  const event = await SocAuditEvent.create({
    tenantId:req.user.tenantId, companyId, actorId:req.user.id, action,
    targetType, targetId:String(targetId), metadata, ipAddress:String(req.ip || '').slice(0,100),
  });
  return event;
}

router.get('/summary', async (req, res) => {
  try {
    if (req.user.role === 'l4_analyst') {
      const { companyIds, filter: scopedFilter } = await scope(req, { personal: true });
      const range = ['today', '7d', '30d'].includes(req.query.range) ? req.query.range : 'today';
      const now = new Date();
      const rangeStart = dashboardRangeStart(range, now);
      const todayStart = dashboardRangeStart('today', now);
      const assignedTo = asObjectId(req.user.id);
      const companyScope = companyIds.map(asObjectId);
      const departmentScope = scopedFilter.departmentId ? { departmentId: scopedFilter.departmentId } : {};
      const activeIncidentStatuses = ['open', 'investigating', 'contained'];
      const activeTicketStatuses = ['open', 'investigating', 'under_observation'];
      const completeStatuses = ['resolved', 'false_positive'];
      const incidentBase = {
        companyId: { $in: companyScope }, assignedTo, incidentSource: 'threat_intelligence', ...departmentScope,
      };
      const ticketBase = {
        companyId: { $in: companyScope }, assignedTo: { $ne: null }, ...departmentScope,
        ticketOpenedAt: { $ne: null },
        ticketSource: 'soar',
        ...socWorkItemFilter(),
      };
      appendAnd(ticketBase, { $or: [
        { assignedTo },
        ...idsIpsFirewallTicketFilter().$or,
      ] });
      const summaryFacet = (activeStatuses, openedAtField) => ({
        summary: [{ $group: {
          _id: null,
          total: { $sum: 1 },
          pending: { $sum: { $cond: [{ $in: ['$status', activeStatuses] }, 1, 0] } },
          completed: { $sum: { $cond: [{ $in: ['$status', completeStatuses] }, 1, 0] } },
          open: { $sum: { $cond: [{ $eq: ['$status', 'open'] }, 1, 0] } },
          investigating: { $sum: { $cond: [{ $eq: ['$status', 'investigating'] }, 1, 0] } },
          contained: { $sum: { $cond: [{ $eq: ['$status', 'contained'] }, 1, 0] } },
          underObservation: { $sum: { $cond: [{ $eq: ['$status', 'under_observation'] }, 1, 0] } },
          falsePositive: { $sum: { $cond: [{ $eq: ['$status', 'false_positive'] }, 1, 0] } },
          criticalPending: { $sum: { $cond: [{ $and: [
            { $eq: ['$severity', 'critical'] }, { $in: ['$status', activeStatuses] },
          ] }, 1, 0] } },
          newInRange: { $sum: { $cond: [{ $gte: [`$${openedAtField}`, rangeStart] }, 1, 0] } },
          pendingInRange: { $sum: { $cond: [{ $and: [
            { $in: ['$status', activeStatuses] }, { $gte: [`$${openedAtField}`, rangeStart] },
          ] }, 1, 0] } },
          openInRange: { $sum: { $cond: [{ $and: [
            { $eq: ['$status', 'open'] }, { $gte: [`$${openedAtField}`, rangeStart] },
          ] }, 1, 0] } },
          investigatingInRange: { $sum: { $cond: [{ $and: [
            { $eq: ['$status', 'investigating'] }, { $gte: [`$${openedAtField}`, rangeStart] },
          ] }, 1, 0] } },
          criticalPendingInRange: { $sum: { $cond: [{ $and: [
            { $eq: ['$severity', 'critical'] },
            { $in: ['$status', activeStatuses] },
            { $gte: [`$${openedAtField}`, rangeStart] },
          ] }, 1, 0] } },
          completedInRange: { $sum: { $cond: [{ $and: [
            { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', rangeStart] },
          ] }, 1, 0] } },
          completedToday: { $sum: { $cond: [{ $and: [
            { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', todayStart] },
          ] }, 1, 0] } },
        } }],
        status: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
        severity: [
          { $match: { status: { $in: activeStatuses } } },
          { $group: { _id: '$severity', count: { $sum: 1 } } },
        ],
      });

      const policyFacet = mode => [
        { $match: { mode } },
        { $group: {
          _id: null,
          total: { $sum: 1 },
          active: { $sum: { $cond: ['$enabled', 1, 0] } },
          appliedPresetRules: { $sum: { $cond: [{ $ne: ['$presetId', ''] }, 1, 0] } },
        } },
      ];
      const [incidentAggregation, ticketAggregation, securityConfigurationAggregation, recentIncidents, recentTickets, recentAudit, assignedShifts] = await Promise.all([
        EdrIncident.aggregate([{ $match: incidentBase }, { $facet: {
          ...summaryFacet(activeIncidentStatuses, 'createdAt'),
          categories: [
            { $match: { status: { $in: activeIncidentStatuses } } },
            { $group: { _id: '$category', count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 6 },
          ],
        } }]),
        Alert.aggregate([{ $match: ticketBase }, { $facet: summaryFacet(activeTicketStatuses, 'ticketOpenedAt') }]),
        Promise.all([
          IdsIpsPolicy.aggregate([
            { $match: { companyId: { $in: companyScope } } },
            { $facet: { ids: policyFacet('detect'), ips: policyFacet('block') } },
          ]),
          Firewall.aggregate([
            { $match: { companyId: { $in: companyScope } } },
            { $group: {
              _id: null,
              totalRules: { $sum: 1 },
              activePolicies: { $sum: { $cond: ['$enabled', 1, 0] } },
              deployedRules: { $sum: { $cond: [{ $eq: ['$deploymentStatus', 'deployed'] }, 1, 0] } },
              pendingRules: { $sum: { $cond: [{ $in: ['$deploymentStatus', ['pending', 'partial']] }, 1, 0] } },
            } },
          ]),
        ]),
        EdrIncident.find({ ...incidentBase, status: { $in: activeIncidentStatuses } })
          .sort({ createdAt: -1 }).limit(8).populate('companyId', 'name').lean(),
        Alert.find({ ...ticketBase, status: { $in: activeTicketStatuses } })
          .sort({ ticketOpenedAt: -1, createdAt: -1 }).limit(8).populate('companyId', 'name').lean(),
        SocAuditEvent.find({ actorId: req.user.id }).sort({ createdAt: -1 }).limit(8).lean(),
        SocShift.find({ companyId: { $in: companyIds }, analystIds: req.user.id, active: true })
          .populate('companyId', 'name').sort({ startTime: 1 }).lean(),
      ]);

      const incidentResult = incidentAggregation[0] || {};
      const ticketResult = ticketAggregation[0] || {};
      const incidentSummary = incidentResult.summary?.[0] || {};
      const ticketSummary = ticketResult.summary?.[0] || {};
      const idsSummary = {};
      const ipsSummary = {};
      const firewallSummary = {};
      const [policyRows, firewallRows] = securityConfigurationAggregation;
      const idsPolicySummary = policyRows[0]?.ids?.[0] || {};
      const ipsPolicySummary = policyRows[0]?.ips?.[0] || {};
      const firewallConfigurationSummary = firewallRows[0] || {};
      const securityConfiguration = {
        ids: {
          observedRules: Number(idsPolicySummary.total || 0),
          appliedRules: Number(idsPolicySummary.appliedPresetRules || 0),
          policies: Number(idsPolicySummary.total || 0),
          activePolicies: Number(idsPolicySummary.active || 0),
        },
        ips: {
          observedRules: Number(ipsPolicySummary.total || 0),
          appliedRules: Number(ipsPolicySummary.appliedPresetRules || 0),
          policies: Number(ipsPolicySummary.total || 0),
          activePolicies: Number(ipsPolicySummary.active || 0),
        },
        firewall: {
          rules: Number(firewallConfigurationSummary.totalRules || 0),
          activePolicies: Number(firewallConfigurationSummary.activePolicies || 0),
          deployedRules: Number(firewallConfigurationSummary.deployedRules || 0),
          pendingRules: Number(firewallConfigurationSummary.pendingRules || 0),
        },
      };
      const totalAssignedWork = Number(incidentSummary.total || 0) + Number(ticketSummary.total || 0);
      const pendingWork = Number(incidentSummary.pending || 0) + Number(ticketSummary.pending || 0);
      const completedWork = Number(incidentSummary.completed || 0) + Number(ticketSummary.completed || 0);
      const completionRate = totalAssignedWork ? Math.round((completedWork / totalAssignedWork) * 100) : 0;
      const assignedWorkInRange = Number(incidentSummary.newInRange || 0) + Number(ticketSummary.newInRange || 0);
      const pendingWorkInRange = Number(incidentSummary.pendingInRange || 0) + Number(ticketSummary.pendingInRange || 0);
      const completedWorkInRange = Number(incidentSummary.completedInRange || 0) + Number(ticketSummary.completedInRange || 0);
      const rangeWorkTotal = pendingWorkInRange + completedWorkInRange;
      const severity = mergeCountMaps(countMap(incidentResult.severity), countMap(ticketResult.severity));
      const status = mergeCountMaps(countMap(incidentResult.status), countMap(ticketResult.status));
      const recentAlerts = [
        ...recentIncidents.map(item => ({ ...item, resourceType: 'incident', resourceId: item._id })),
        ...recentTickets.map(item => ({ ...item, resourceType: 'ticket', resourceId: item._id })),
      ].sort((a, b) => new Date(b.ticketOpenedAt || b.createdAt) - new Date(a.ticketOpenedAt || a.createdAt)).slice(0, 10);
      const shifts = assignedShifts.map(shift => ({ ...shift, isCurrent: isShiftActiveNow(shift, now) }));

      res.set('Cache-Control', 'no-store');
      return res.json({
        role: req.user.role,
        range: { key: range, from: rangeStart, to: now },
        refreshedAt: now,
        metrics: {
          totalAssignedWork, pendingWork, completedWork, completionRate,
          assignedWorkInRange,
          pendingWorkInRange,
          completedWorkInRange,
          completionRateInRange: rangeWorkTotal ? Math.round((completedWorkInRange / rangeWorkTotal) * 100) : 0,
          openWorkInRange: Number(incidentSummary.openInRange || 0) + Number(ticketSummary.openInRange || 0),
          investigatingWorkInRange: Number(incidentSummary.investigatingInRange || 0) + Number(ticketSummary.investigatingInRange || 0),
          criticalPendingInRange: Number(incidentSummary.criticalPendingInRange || 0) + Number(ticketSummary.criticalPendingInRange || 0),
          assignedIncidents: Number(incidentSummary.total || 0),
          pendingIncidents: Number(incidentSummary.pending || 0),
          completedIncidents: Number(incidentSummary.completed || 0),
          newIncidentsInRange: Number(incidentSummary.newInRange || 0),
          totalTickets: Number(ticketSummary.total || 0),
          assignedTickets: Number(ticketSummary.pending || 0),
          pendingTickets: Number(ticketSummary.pending || 0),
          completedTickets: Number(ticketSummary.completed || 0),
          closedTickets: Number(ticketSummary.completed || 0),
          closedTicketsInRange: Number(ticketSummary.completedInRange || 0),
          newTicketsInRange: Number(ticketSummary.newInRange || 0),
          openWork: Number(incidentSummary.open || 0) + Number(ticketSummary.open || 0),
          investigatingWork: Number(incidentSummary.investigating || 0) + Number(ticketSummary.investigating || 0),
          containedIncidents: Number(incidentSummary.contained || 0),
          underObservationTickets: Number(ticketSummary.underObservation || 0),
          criticalPending: Number(incidentSummary.criticalPending || 0) + Number(ticketSummary.criticalPending || 0),
          newInRange: Number(incidentSummary.newInRange || 0) + Number(ticketSummary.newInRange || 0),
          completedInRange: Number(incidentSummary.completedInRange || 0) + Number(ticketSummary.completedInRange || 0),
          completedToday: Number(incidentSummary.completedToday || 0) + Number(ticketSummary.completedToday || 0),
          falsePositives: Number(incidentSummary.falsePositive || 0) + Number(ticketSummary.falsePositive || 0),
          activeShifts: shifts.length,
          onShiftNow: shifts.filter(shift => shift.isCurrent).length,
          idsTicketsActive: Number(idsSummary.active || 0),
          ipsTicketsActive: Number(ipsSummary.active || 0),
          firewallTicketsActive: Number(firewallSummary.active || 0),
          idsTicketsInRange: Number(idsSummary.newInRange || 0),
          ipsTicketsInRange: Number(ipsSummary.newInRange || 0),
          firewallTicketsInRange: Number(firewallSummary.newInRange || 0),
          networkTicketsActive: Number(idsSummary.active || 0) + Number(ipsSummary.active || 0) + Number(firewallSummary.active || 0),
          idsRuleCount: securityConfiguration.ids.observedRules,
          idsPolicyCount: securityConfiguration.ids.policies,
          ipsRuleCount: securityConfiguration.ips.observedRules,
          ipsPolicyCount: securityConfiguration.ips.policies,
          firewallRuleCount: securityConfiguration.firewall.rules,
          firewallPolicyCount: securityConfiguration.firewall.activePolicies,
        },
        assignedAlerts: totalAssignedWork,
        openAlerts: pendingWork,
        investigating: Number(incidentSummary.investigating || 0) + Number(ticketSummary.investigating || 0),
        criticalAlerts: Number(incidentSummary.criticalPending || 0) + Number(ticketSummary.criticalPending || 0),
        resolvedToday: Number(incidentSummary.completedToday || 0) + Number(ticketSummary.completedToday || 0),
        severity,
        status,
        categories: countMap(incidentResult.categories),
        networkSecurity: {
          ids: { total: Number(idsSummary.total || 0), active: Number(idsSummary.active || 0), newInRange: Number(idsSummary.newInRange || 0) },
          ips: { total: Number(ipsSummary.total || 0), active: Number(ipsSummary.active || 0), newInRange: Number(ipsSummary.newInRange || 0) },
          firewall: { total: Number(firewallSummary.total || 0), active: Number(firewallSummary.active || 0), newInRange: Number(firewallSummary.newInRange || 0) },
        },
        securityConfiguration,
        recentAlerts,
        recentAudit,
        assignedShifts: shifts,
      });
    }
    const { companyIds, filter } = await scope(req, { personal:req.user.role !== 'soc_manager' });
    const start = new Date(); start.setHours(0,0,0,0);
    const alertScope = { ...filter };
    const [severity, status, today, resolvedToday, escalations, companies, shifts, analysts, recentAlerts, recentAudit] = await Promise.all([
      Alert.aggregate([{ $match:alertScope }, { $group:{ _id:'$severity', count:{ $sum:1 } } }]),
      Alert.aggregate([{ $match:alertScope }, { $group:{ _id:'$status', count:{ $sum:1 } } }]),
      Alert.countDocuments({ ...alertScope, createdAt:{ $gte:start } }),
      Alert.countDocuments({ ...alertScope, resolvedAt:{ $gte:start } }),
      SocEscalation.countDocuments(req.user.role === 'soc_manager'
        ? { companyId:{ $in:companyIds }, status:'pending' }
        : { $or:[{ assignedTo:req.user.id }, { fromUserId:req.user.id }], status:'pending' }),
      Company.countDocuments({ _id:{ $in:companyIds } }),
      SocShift.countDocuments({ companyId:{ $in:companyIds }, active:true, analystIds:req.user.role === 'soc_manager' ? { $exists:true } : req.user.id }),
      req.user.role === 'soc_manager' ? User.countDocuments({ role:{ $in:ANALYST_ROLES }, _id:{ $in:await SocCompanyAssignment.find({ companyId:{ $in:companyIds }, active:true }).distinct('userId') }, isActive:true }) : 0,
      Alert.find(alertScope).sort({ createdAt:-1 }).limit(8).populate('companyId','name').populate('assignedTo','name email role').lean(),
      SocAuditEvent.find(req.user.role === 'soc_manager' ? { companyId:{ $in:companyIds } } : { actorId:req.user.id }).sort({ createdAt:-1 }).limit(8).lean(),
    ]);
    const severityCounts = Object.fromEntries(severity.map(row => [row._id,row.count]));
    const statusCounts = Object.fromEntries(status.map(row => [row._id,row.count]));
    res.json({
      role:req.user.role, companyCount:companies, activeAnalysts:analysts, activeShifts:shifts,
      alertsToday:today, resolvedToday, pendingEscalations:escalations,
      criticalAlerts:severityCounts.critical || 0, highAlerts:severityCounts.high || 0,
      openAlerts:statusCounts.open || 0, investigating:statusCounts.investigating || 0,
      assignedAlerts:Object.values(statusCounts).reduce((a,b) => a+b,0),
      severity:severityCounts, status:statusCounts, recentAlerts, recentAudit,
    });
  } catch (error) { res.status(500).json({ message:error.message }); }
});

// Personal settings audit trail. Keep this user-scoped; the role audit pages
// intentionally use broader company/team scopes for operational review.
router.get('/audit-events', async (req, res) => {
  try {
    const [socEvents, loginEvents] = await Promise.all([
      SocAuditEvent.find({ actorId: req.user.id })
        .populate('actorId', 'name email role')
        .populate('companyId', 'name')
        .sort({ createdAt: -1 })
        .limit(500)
        .lean(),
      LoginActivity.find({ userId: req.user.id })
        .populate('userId', 'name email role')
        .populate('companyId', 'name')
        .sort({ createdAt: -1 })
        .limit(500)
        .lean(),
    ]);

    const items = buildPersonalAuditTrail({ socEvents, loginEvents, limit: 500 });

    res.set('Cache-Control', 'no-store');
    res.json({ items, total: items.length });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

router.get('/alerts', async (req, res) => {
  try {
    if (req.user.role === 'l4_analyst') return res.status(403).json({ message: 'L4 Analysts can access Threat Intelligence incidents only' });
    const personal = req.user.role !== 'soc_manager' && req.query.queue !== 'shared';
    const { filter } = await scope(req, { personal });
    Object.assign(filter, socWorkItemFilter());
    const { page, limit } = pageParams(req.query);
    if (req.query.queue === 'unassigned') filter.assignedTo = null;
    if (req.query.severity) filter.severity = req.query.severity;
    if (req.query.active === 'true') filter.status = { $in: ['open', 'investigating'] };
    else if (req.query.status) filter.status = req.query.status;
    if (req.query.escalatableTo === 'l3') {
      if (req.user.role !== 'l2_analyst') return res.status(403).json({ message: 'L2 Analyst access required' });
      const alreadyEscalatedAlertIds = await SocEscalation.find({
        companyId: filter.companyId,
        toLevel: 'l3',
        status: { $in: ['pending', 'accepted', 'resolved'] },
        alertId: { $ne: null },
      }).distinct('alertId');
      filter._id = { $nin: alreadyEscalatedAlertIds };
    }
    if (req.query.companyId) {
      const allowed = filter.companyId.$in.map(String);
      if (!allowed.includes(String(req.query.companyId))) return res.status(403).json({ message:'Company outside assigned scope' });
      filter.companyId = req.query.companyId;
    }
    if (req.query.search) {
      const pattern = new RegExp(escapeRegex(req.query.search).slice(0,200), 'i');
      filter.$or = [{ description:pattern }, { ruleId:pattern }, { signatureName:pattern }, { eventId:pattern }];
    }
    const sortFields = new Set(['createdAt','severity','status','resolvedAt']);
    const sortBy = sortFields.has(req.query.sortBy) ? req.query.sortBy : 'createdAt';
    const sortDir = req.query.sortDir === 'asc' ? 1 : -1;
    const [items,total] = await Promise.all([
      Alert.find(filter).sort({ [sortBy]:sortDir }).skip((page-1)*limit).limit(limit)
        .populate('companyId','name').populate('departmentId','name').populate('assignedTo','name email role').lean(),
      Alert.countDocuments(filter),
    ]);
    res.json({ items,total,page,limit,pages:Math.ceil(total/limit) });
  } catch (error) { res.status(500).json({ message:error.message }); }
});

router.get('/tickets', async (req, res) => {
  try {
    const sharedL4View = req.user.role === 'l4_analyst';
    const { filter } = await scope(req, { personal: !['soc_manager', 'l4_analyst'].includes(req.user.role) });
    const { page, limit } = pageParams(req.query);
    const requestedStatus = String(req.query.status || '').toLowerCase();
    const ticketStatuses = ['open', 'investigating', 'under_observation', 'resolved', 'false_positive'];
    Object.assign(filter, {
      assignedTo: filter.assignedTo || { $ne: null },
      ticketOpenedAt: { $ne: null },
      ticketSource: 'soar',
      status: requestedStatus && ticketStatuses.includes(requestedStatus)
        ? requestedStatus
        : { $in: ['open', 'investigating', 'under_observation'] },
      ...socWorkItemFilter(),
    });
    if (sharedL4View) {
      appendAnd(filter, { $or: [
        { assignedTo: req.user.id },
        ...idsIpsFirewallTicketFilter().$or,
      ] });
    }
    if (['ids', 'ips', 'firewall'].includes(String(req.query.networkSource || '').toLowerCase())) {
      appendAnd(filter, networkSecurityTicketFilter(req.query.networkSource));
    }
    const [items, total] = await Promise.all([
      Alert.find(filter).sort({ ticketOpenedAt: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('companyId', 'name').populate('departmentId', 'name')
        .populate('assignedTo', 'name email role').populate('ticketOpenedBy', 'name email role').lean(),
      Alert.countDocuments(filter),
    ]);
    res.set('Cache-Control', 'no-store');
    res.json({ items, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/tickets/:id', async (req, res) => {
  try {
    const sharedL4View = req.user.role === 'l4_analyst';
    const { filter } = await scope(req, { personal: !['soc_manager', 'l4_analyst'].includes(req.user.role) });
    Object.assign(filter, {
      _id: req.params.id,
      ticketOpenedAt: { $ne: null },
      ticketSource: 'soar',
      ...socWorkItemFilter(),
    });
    if (sharedL4View) {
      appendAnd(filter, { $or: [
        { assignedTo: req.user.id },
        ...idsIpsFirewallTicketFilter().$or,
      ] });
    }
    const ticket = await Alert.findOne(filter)
      .populate('companyId', 'name industry country companySize status riskScore')
      .populate('departmentId', 'name')
      .populate('systemId', 'name hostname osType agentId velociraptorClientId lastSeen')
      .populate('assignedTo', 'name email role')
      .populate('ticketOpenedBy', 'name email role')
      .populate('notes.user', 'name email role')
      .populate('auditHistory.actorId', 'name email role')
      .lean();
    if (!ticket) return res.status(404).json({ message: 'SOAR ticket not found in your authorized scope' });

    const evidence = { ...ticket, companyId: undefined, departmentId: undefined, assignedTo: undefined, notes: undefined, auditHistory: undefined };
    const chainOfCustody = (ticket.auditHistory || []).map((entry, index) => ({
      id: `ticket-audit-${index}`,
      action: entry.action || 'ticket_activity',
      title: String(entry.action || 'Ticket activity').replace(/[._]/g, ' '),
      at: entry.at,
      actor: entry.actorId || { name: 'SOAR Automation', role: 'system' },
      details: entry.metadata ? JSON.stringify(entry.metadata) : 'SOAR ticket lifecycle event',
      integrityStatus: 'verified',
    }));
    res.set('Cache-Control', 'no-store');
    res.json({
      ...ticket,
      resourceType: 'ticket',
      title: ticket.signatureName || ticket.ruleId || ticket.eventId || 'SOAR Ticket',
      affectedEndpoint: ticket.hostname || ticket.agentName || ticket.systemId?.hostname || '',
      affectedUser: ticket.username || '',
      confidenceScore: Number(ticket.confidenceScore || ticket.riskScore || 0),
      sourceAlertCount: 1,
      alertIds: [evidence],
      networkInvolved: isNetworkEvidenceAlert(ticket),
      networkEvidence: isNetworkEvidenceAlert(ticket) ? [evidence] : [],
      iocs: (ticket.iocMatches || []).map(item => ({
        type: item.type || 'indicator', value: item.indicator, context: item.source || 'Ticket evidence',
      })).filter(item => item.value),
      chainOfCustody,
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/queue', async (req, res) => {
  try {
    const { filter } = await scope(req, { personal: false });
    const { page, limit } = pageParams(req.query);
    const severityByRole = {
      l1_analyst: ['low', 'medium'],
      l2_analyst: ['high'],
      l3_analyst: ['critical'],
    };
    const severities = severityByRole[req.user.role] || ['low', 'medium', 'high', 'critical'];
    const baseQueueFilter = {
      ...filter,
      assignedTo: null,
      status: { $in: ['open', 'investigating'] },
      severity: { $in: severities },
    };
    const alertQueueFilter = { ...baseQueueFilter, 'correlationIds.0': { $exists: false }, ...socWorkItemFilter() };
    const incidentQueueFilter = { ...baseQueueFilter, correlationId: { $ne: null } };
    const fetchLimit = Math.min(200, page * limit);
    const [alerts, incidents, alertTotal, incidentTotal] = await Promise.all([
      Alert.find(alertQueueFilter).sort({ createdAt: -1 }).limit(fetchLimit)
        .populate('companyId', 'name').populate('departmentId', 'name').lean(),
      EdrIncident.find(incidentQueueFilter).sort({ createdAt: -1 }).limit(fetchLimit)
        .populate('companyId', 'name').populate('departmentId', 'name').lean(),
      Alert.countDocuments(alertQueueFilter),
      EdrIncident.countDocuments(incidentQueueFilter),
    ]);
    const items = [
      ...alerts.map(item => ({ ...item, resourceType: 'alert', resourceId: item._id })),
      ...incidents.map(item => ({ ...item, resourceType: 'incident', resourceId: item._id })),
    ].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    const start = (page - 1) * limit;
    const total = alertTotal + incidentTotal;
    res.json({ items: items.slice(start, start + limit), total, page, limit, pages: Math.max(1, Math.ceil(total / limit)), severities });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/incidents', async (req, res) => {
  try {
    const { filter } = await scope(req, { personal: req.user.role !== 'soc_manager' });
    if (req.user.role === 'l4_analyst') {
      filter.incidentSource = 'threat_intelligence';
    } else {
      filter.incidentSource = { $ne: 'threat_intelligence' };
    }
    if (req.query.status) {
      const statuses = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];
      if (!statuses.includes(req.query.status)) return res.status(400).json({ message: 'Invalid incident status' });
      filter.status = req.query.status;
    }
    if (req.query.severity) {
      const severities = ['low', 'medium', 'high', 'critical'];
      if (!severities.includes(req.query.severity)) return res.status(400).json({ message: 'Invalid incident severity' });
      filter.severity = req.query.severity;
    }
    if (req.query.search) {
      const pattern = new RegExp(escapeRegex(req.query.search).slice(0, 200), 'i');
      filter.$or = [
        { title: pattern },
        { description: pattern },
        { affectedEndpoint: pattern },
        { affectedUser: pattern },
        { agentName: pattern },
      ];
    }
    const { page, limit } = pageParams(req.query);
    const [items, total] = await Promise.all([
      EdrIncident.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('companyId', 'name').populate('departmentId', 'name').populate('assignedTo', 'name email role').lean().maxTimeMS(8000),
      EdrIncident.countDocuments(filter).maxTimeMS(8000),
    ]);
    res.json({ items: items.map(item => ({ ...item, resourceType: 'incident', resourceId: item._id })), total, page, limit, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/incidents/:id', async (req, res) => {
  try {
    const { filter } = await scope(req, { personal: false });
    if (req.user.role === 'l4_analyst') {
      filter.incidentSource = 'threat_intelligence';
      filter.assignedTo = req.user.id;
    }
    const incident = await EdrIncident.findOne({ _id: req.params.id, ...filter })
      .populate('companyId', 'name industry country companySize status riskScore').populate('departmentId', 'name')
      .populate('assignedTo', 'name email role')
      .populate('notes.user', 'name email role')
      .populate('alertIds', 'eventId ruleId description severity source sourceType eventCategory type normalizedEventType createdAt hostname hostnameObserved agentName agentId endpointId systemId srcip destip srcport destport protocol domain dnsQuery url networkDirection action blocked')
      .populate('networkEvidenceAlertIds', 'eventId ruleId description severity source sourceType eventCategory type normalizedEventType createdAt hostname hostnameObserved agentName agentId endpointId systemId srcip destip srcport destport protocol domain dnsQuery url networkDirection action blocked');
    if (!incident) return res.status(404).json({ message: 'Incident not found in your authorized scope' });

    // Older/correlation-generated incidents can miss systemId even though the
    // linked alerts carry an endpoint hostname. Resolve the best authorized
    // endpoint once and persist it so forensic actions always receive a valid ID.
    if (!incident.systemId) {
      const incidentCompanyId = incident.companyId?._id || incident.companyId;
      const evidence = [...(incident.alertIds || []), ...(incident.networkEvidenceAlertIds || [])];
      const evidenceSystemIds = [...new Set(evidence
        .flatMap(item => [item.systemId?._id || item.systemId, item.endpointId])
        .filter(value => mongoose.isValidObjectId(value))
        .map(String))];
      const evidenceAgentIds = [...new Set([
        incident.agentId,
        ...evidence.flatMap(item => [item.agentId, !mongoose.isValidObjectId(item.endpointId) ? item.endpointId : null]),
      ].filter(Boolean).map(value => String(value).trim()).filter(Boolean))];
      const systemScope = {
        companyId: incidentCompanyId,
        ...(incident.departmentId?._id || incident.departmentId
          ? { departmentId: incident.departmentId?._id || incident.departmentId }
          : {}),
      };
      let resolvedSystem = (evidenceSystemIds.length || evidenceAgentIds.length)
        ? await System.findOne({
          ...systemScope,
          $or: [
            ...(evidenceSystemIds.length ? [{ _id: { $in: evidenceSystemIds } }] : []),
            ...(evidenceAgentIds.length ? [{ agentId: { $in: evidenceAgentIds } }] : []),
          ],
        }).sort({ isActive: -1, lastSeen: -1, updatedAt: -1 }).select('_id departmentId').lean().maxTimeMS(5000)
        : null;
      const endpointNames = [...new Set([
        incident.affectedEndpoint,
        incident.agentName,
        ...evidence.flatMap(item => [item.hostname, item.hostnameObserved, item.agentName]),
      ].filter(Boolean).map(value => String(value).trim()).filter(value => value && !/^(IPS Server|SOC IPS Engine|IDS|IPS)$/i.test(value)))];
      if (!resolvedSystem && endpointNames.length) {
        resolvedSystem = await System.findOne({
          ...systemScope,
          $or: [
            { hostname: { $in: endpointNames.map(value => new RegExp(`^${escapeRegex(value)}$`, 'i')) } },
            { name: { $in: endpointNames.map(value => new RegExp(`^${escapeRegex(value)}$`, 'i')) } },
          ],
        }).sort({ isActive: -1, lastSeen: -1, updatedAt: -1 }).select('_id departmentId').lean().maxTimeMS(5000);
      }
      if (!resolvedSystem && incident.incidentSource === 'threat_intelligence') {
        // Legacy IPS alerts used the synthetic label "IPS Server" and omitted
        // endpoint identity. Only infer a target when exactly one installed
        // endpoint exists inside the authorized company/
        // department scope; never guess between multiple endpoints.
        const activeEndpoints = await System.find({
          ...systemScope,
          isActive: true,
          agentVersion: { $nin: [null, ''] },
        }).sort({ lastSeen: -1, updatedAt: -1 }).limit(2).select('_id departmentId').lean().maxTimeMS(5000);
        if (activeEndpoints.length === 1) resolvedSystem = activeEndpoints[0];
      }
      if (resolvedSystem?._id) {
        incident.systemId = resolvedSystem._id;
        await Promise.all([
          EdrIncident.updateOne(
            { _id: incident._id, $or: [{ systemId: null }, { systemId: { $exists: false } }] },
            { $set: { systemId: resolvedSystem._id } },
          ).maxTimeMS(5000),
          incident.correlationId ? CorrelationEvent.updateOne(
            { _id: incident.correlationId, companyId: incidentCompanyId, $or: [{ systemId: null }, { systemId: { $exists: false } }] },
            { $set: { systemId: resolvedSystem._id } },
          ).maxTimeMS(5000) : null,
        ]);
      }
    }

    const explicitNetworkEvidence = [
      ...(incident.networkEvidenceAlertIds || []),
      ...(incident.alertIds || []).filter(isNetworkEvidenceAlert),
    ].filter(Boolean);
    const explicitById = new Map(explicitNetworkEvidence.map(item => [String(item._id), item]));
    const networkInvolved = incident.networkInvolved === true || explicitById.size > 0;

    // When network telemetry participated in correlation, enrich those explicit
    // records with bounded same-endpoint context without mutating alertIds.
    const startAt = new Date(new Date(incident.firstEventAt || incident.createdAt).getTime() - (5 * 60 * 1000));
    const endAt = new Date(new Date(incident.lastEventAt || incident.createdAt).getTime() + (5 * 60 * 1000));
    const endpointName = incident.affectedEndpoint || incident.agentName;
    const endpointScope = [
      ...(incident.systemId ? [{ systemId: incident.systemId }] : []),
      ...(endpointName ? [
        { hostname: new RegExp(`^${escapeRegex(endpointName)}$`, 'i') },
        { agentName: new RegExp(`^${escapeRegex(endpointName)}$`, 'i') },
      ] : []),
    ];
    let networkEvidence = Array.from(explicitById.values()).map(item => item.toObject ? item.toObject() : item);
    let networkEvidenceError = '';
    if (networkInvolved && endpointScope.length && networkEvidence.length < 50) {
      try {
        const relatedNetworkEvidence = await Alert.find({
          companyId: incident.companyId._id || incident.companyId,
          createdAt: { $gte: startAt, $lte: endAt },
          $and: [
            { $or: endpointScope },
            { $or: [
              { eventCategory: { $in: ['network', 'dns', 'connection'] } },
              { sourceType: { $in: ['IDS', 'IPS', 'ZEEK'] } },
              { source: /^(network|ids|ips|zeek|firewall|suricata)$/i },
              { srcip: { $exists: true, $nin: [null, ''] } },
              { destip: { $exists: true, $nin: [null, ''] } },
              { domain: { $exists: true, $nin: [null, ''] } },
            ] },
          ],
        })
          .sort({ createdAt: -1 })
          .limit(50 - networkEvidence.length)
          .select('eventId ruleId description severity source sourceType eventCategory type normalizedEventType createdAt hostname agentName systemId srcip destip srcport destport protocol domain dnsQuery url networkDirection action blocked')
          .hint({ companyId: 1, createdAt: -1 })
          .lean()
          .maxTimeMS(5000);
        const mergedById = new Map(networkEvidence.map(item => [String(item._id), item]));
        relatedNetworkEvidence.forEach(item => mergedById.set(String(item._id), item));
        networkEvidence = Array.from(mergedById.values()).slice(0, 50);
      } catch (networkError) {
        networkEvidenceError = 'Related network telemetry query timed out';
        console.warn(`[SOC incident network evidence] ${req.params.id}: ${networkError.message}`);
      }
    }

    const incidentCompanyId = incident.companyId?._id || incident.companyId;
    const incidentKeys = [incident._id, incident.correlationId].filter(Boolean).map(value => escapeRegex(String(value)));
    const huntNameFilter = incidentKeys.length ? new RegExp(incidentKeys.join('|'), 'i') : /^$/;
    const [auditEvents, rawForensicHunts, aiAnalysisJobs] = await Promise.all([
      SocAuditEvent.find({
        companyId: incidentCompanyId,
        targetType: 'EdrIncident',
        targetId: String(incident._id),
      }).sort({ createdAt: 1 }).limit(100).populate('actorId', 'name email role').lean().maxTimeMS(5000),
      ForensicHunt.find({ companyId: incidentCompanyId, name: huntNameFilter })
        .select('name artifacts status error clientId requestedBy requestedByRole sourceIp companyId departmentId systemId createdAt startedAt completedAt providerResult')
        .sort({ createdAt: 1 }).limit(30).populate('requestedBy', 'name email role').lean().maxTimeMS(5000),
      AiAnalysis.find({
        companyId: incidentCompanyId,
        resourceType: 'EdrIncident',
        resourceId: incident._id,
        taskType: 'edr_incident_analysis',
      }).select('requestedBy requestedByRole status model promptVersion confidence error sourceIp createdAt updatedAt startedAt completedAt')
        .sort({ createdAt: 1 }).limit(20).populate('requestedBy', 'name email role').lean().maxTimeMS(5000),
    ]);
    const forensicHunts = await Promise.all((rawForensicHunts || []).map(async hunt => {
      if (hunt.status !== 'completed') {
        return syncHuntIfFinished(hunt, { io: req.app.get('io') });
      }
      return hunt;
    }));
    const forensicEvidence = forensicHunts.length ? await ForensicEvidence.find({
      companyId: incidentCompanyId,
      huntId: { $in: forensicHunts.map(item => item._id) },
    }).select('huntId evidenceId name type sourceHost artifactName sizeBytes sha256 integrityStatus storageState collectedAt custody')
      .populate('custody.actorId', 'name email role').sort({ collectedAt: 1 }).limit(100).lean().maxTimeMS(5000) : [];

    const actor = (user, fallbackRole = 'system') => ({
      name: user?.name || (fallbackRole === 'system' ? 'SOC Correlation Engine' : 'Unknown actor'),
      email: user?.email || '',
      role: user?.role || fallbackRole,
    });
    const custodyTrail = [{
      id: `incident-created-${incident._id}`,
      action: 'incident_created',
      title: 'Incident created and registered',
      at: incident.createdAt,
      actor: actor(null),
      details: `${(incident.alertIds || []).length} correlated alert(s) linked to case ${incident.correlationId || incident._id}.`,
      integrityStatus: 'verified',
    }];
    if (incident.assignedTo) custodyTrail.push({
      id: `incident-assigned-${incident._id}`,
      action: 'incident_assigned',
      title: 'Incident assigned for investigation',
      at: incident.createdAt,
      actor: actor(incident.assignedTo, incident.assignedTo.role || 'analyst'),
      details: `Assigned to ${incident.assignedTo.name || incident.assignedTo.email || 'analyst'}.`,
      integrityStatus: 'verified',
    });
    (incident.notes || []).forEach((note, index) => custodyTrail.push({
      id: `note-${index}-${note.at?.getTime?.() || index}`,
      action: 'analyst_note',
      title: 'Analyst note added',
      at: note.at,
      actor: actor(note.user, note.user?.role || 'analyst'),
      details: note.text || '',
      integrityStatus: 'verified',
    }));
    auditEvents.filter(event => event.action !== 'incident.note').forEach(event => custodyTrail.push({
      id: `audit-${event._id}`,
      action: event.action,
      title: String(event.action || 'audit_event').replace(/[._]/g, ' '),
      at: event.createdAt,
      actor: actor(event.actorId, event.actorId?.role || 'analyst'),
      sourceIp: event.ipAddress || '',
      details: event.metadata && Object.keys(event.metadata).length ? JSON.stringify(event.metadata) : 'SOC workflow action recorded.',
      integrityStatus: 'verified',
    }));
    (incident.actionsLog || []).forEach((entry, index) => custodyTrail.push({
      id: `response-${index}-${entry.takenAt?.getTime?.() || index}`,
      action: entry.action || 'response_action',
      title: `Response action: ${String(entry.action || 'action').replace(/_/g, ' ')}`,
      at: entry.takenAt,
      actor: { name: String(entry.takenBy || 'SOAR automation'), email: '', role: entry.takenBy === 'auto' ? 'automation' : 'analyst' },
      details: [entry.target && `Target: ${entry.target}`, entry.result && `Result: ${entry.result}`].filter(Boolean).join(' · '),
      integrityStatus: 'verified',
    }));
    aiAnalysisJobs.forEach(aiJob => {
      const aiActor = actor(aiJob.requestedBy, aiJob.requestedByRole || 'analyst');
      custodyTrail.push({
        id: `ai-requested-${aiJob._id}`,
        action: 'ai_analysis_requested',
        title: 'AI forensic analysis requested',
        at: aiJob.createdAt,
        actor: aiActor,
        sourceIp: aiJob.sourceIp || '',
        details: `Job ${aiJob._id} · prompt ${aiJob.promptVersion || 'v1'}.`,
        integrityStatus: 'verified',
      });
      if (aiJob.startedAt) custodyTrail.push({
        id: `ai-started-${aiJob._id}`,
        action: 'ai_analysis_started',
        title: 'AI forensic analysis started',
        at: aiJob.startedAt,
        actor: { name: aiJob.model || 'Configured AI provider', email: '', role: 'ai_provider' },
        details: `Model ${aiJob.model || 'provider default'} began processing incident evidence.`,
        integrityStatus: 'verified',
      });
      if (aiJob.completedAt || aiJob.status === 'failed') custodyTrail.push({
        id: `ai-finished-${aiJob._id}`,
        action: aiJob.status === 'completed' ? 'ai_analysis_completed' : 'ai_analysis_failed',
        title: aiJob.status === 'completed' ? 'AI forensic analysis completed' : 'AI forensic analysis failed',
        at: aiJob.completedAt || aiJob.updatedAt || aiJob.createdAt,
        actor: { name: aiJob.model || 'Configured AI provider', email: '', role: 'ai_provider' },
        sourceIp: aiJob.sourceIp || '',
        details: aiJob.error || `Confidence ${Number(aiJob.confidence || 0)}% · result linked to this incident.`,
        integrityStatus: aiJob.status === 'completed' ? 'verified' : 'warning',
      });
    });
    if (!aiAnalysisJobs.length && incident.aiInvestigation?.status && incident.aiInvestigation.status !== 'not_required') {
      custodyTrail.push({
        id: `ai-incident-${incident.aiInvestigation.jobId || incident._id}`,
        action: `ai_analysis_${incident.aiInvestigation.status}`,
        title: `AI forensic analysis ${String(incident.aiInvestigation.status).replace(/_/g, ' ')}`,
        at: incident.aiInvestigation.completedAt || incident.updatedAt,
        actor: { name: 'Configured AI provider', email: '', role: 'ai_provider' },
        details: `Confidence ${Number(incident.aiInvestigation.confidence || 0)}% · persisted incident analysis record.`,
        integrityStatus: incident.aiInvestigation.status === 'failed' ? 'warning' : 'verified',
      });
    }
    forensicHunts.forEach(hunt => {
      const huntActor = actor(hunt.requestedBy, hunt.requestedByRole || 'analyst');
      custodyTrail.push({
        id: `hunt-queued-${hunt._id}`, action: 'collection_requested', title: 'Velociraptor collection requested',
        at: hunt.createdAt, actor: huntActor, sourceIp: hunt.sourceIp || '',
        details: `${hunt.name} · ${(hunt.artifacts || []).join(', ')}`, integrityStatus: 'verified',
      });
      if (hunt.startedAt) custodyTrail.push({
        id: `hunt-started-${hunt._id}`, action: 'collection_started', title: 'Velociraptor collection started',
        at: hunt.startedAt, actor: huntActor, sourceIp: hunt.sourceIp || '',
        details: `Client ${hunt.clientId || 'not recorded'} · ${(hunt.artifacts || []).length} artifact(s).`, integrityStatus: 'verified',
      });
      if (hunt.completedAt) custodyTrail.push({
        id: `hunt-finished-${hunt._id}`, action: hunt.status === 'completed' ? 'collection_completed' : 'collection_failed',
        title: hunt.status === 'completed' ? 'Velociraptor collection completed' : 'Velociraptor collection failed',
        at: hunt.completedAt, actor: huntActor, sourceIp: hunt.sourceIp || '',
        details: hunt.error || `Job ${hunt._id} completed and output was linked.`,
        integrityStatus: hunt.status === 'completed' ? 'verified' : 'warning',
      });
    });
    forensicEvidence.forEach(evidenceItem => {
      const events = evidenceItem.custody?.length ? evidenceItem.custody : [{
        action: 'collected', actorId: null, actorRole: 'system', at: evidenceItem.collectedAt, sourceIp: '', note: '',
      }];
      events.forEach((event, index) => custodyTrail.push({
        id: `evidence-${evidenceItem._id}-${index}`,
        action: event.action || 'evidence_recorded',
        title: event.action === 'integrity_verified' ? 'Evidence integrity verified' : 'Forensic evidence sealed',
        at: event.at || evidenceItem.collectedAt,
        actor: actor(event.actorId, event.actorRole || 'system'),
        sourceIp: event.sourceIp || '',
        details: event.note || `${evidenceItem.evidenceId} · ${evidenceItem.artifactName}`,
        evidence: {
          evidenceId: evidenceItem.evidenceId, sha256: evidenceItem.sha256,
          integrityStatus: evidenceItem.integrityStatus, sizeBytes: evidenceItem.sizeBytes,
        },
        integrityStatus: evidenceItem.integrityStatus,
      }));
    });
    custodyTrail.sort((a, b) => new Date(a.at || 0) - new Date(b.at || 0));

    res.json({
      ...incident.toObject(),
      networkInvolved,
      networkEvidence,
      networkEvidenceError,
      chainOfCustody: custodyTrail,
      networkEvidenceScope: {
        relationship: networkInvolved ? 'correlated_and_same_endpoint_incident_window' : 'not_involved',
        startAt,
        endAt,
        limit: 50,
      },
      resourceType: 'incident',
      resourceId: incident._id,
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/audit-reviews', async (req, res) => {
  try {
    const { filter: dataScope } = await scope(req, { personal: false });
    const auditType = req.query.type === 'threat' ? 'threat' : 'standard';
    const filter = {
      companyId: dataScope.companyId,
      ...(dataScope.departmentId ? { departmentId: dataScope.departmentId } : {}),
      auditType,
    };
    if (req.user.role === 'l1_analyst' || req.user.role === 'l4_analyst') filter.submittedBy = req.user.id;
    else filter.reviewerRole = req.user.role;
    if (req.query.status) {
      const statuses = ['pending', 'approved', 'changes_requested'];
      if (!statuses.includes(req.query.status)) return res.status(400).json({ message: 'Invalid audit status' });
      filter.status = req.query.status;
    }
    const { page, limit } = pageParams(req.query);
    const [items, total] = await Promise.all([
      SocIncidentAuditReview.find(filter).sort({ submittedAt: -1 }).skip((page - 1) * limit).limit(limit)
        .populate('incidentId', 'title description severity status incidentSource affectedEndpoint resolvedAt closedBy')
        .populate('companyId', 'name').populate('departmentId', 'name')
        .populate('submittedBy', 'name email role').populate('reviewedBy', 'name email role').lean().maxTimeMS(8000),
      SocIncidentAuditReview.countDocuments(filter).maxTimeMS(8000),
    ]);
    res.json({ items, total, page, limit, pages: Math.max(1, Math.ceil(total / limit)) });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/audit-reviews/:id/action', async (req, res) => {
  try {
    const action = String(req.body.action || '').toLowerCase();
    if (!['approve', 'request_changes'].includes(action)) return res.status(400).json({ message: 'Invalid audit action' });
    const note = String(req.body.note || '').trim().slice(0, 5000);
    if (action === 'request_changes' && !note) return res.status(400).json({ message: 'Review note is required when requesting changes' });
    const { filter: dataScope } = await scope(req, { personal: false });
    const review = await SocIncidentAuditReview.findOne({
      _id: req.params.id,
      companyId: dataScope.companyId,
      ...(dataScope.departmentId ? { departmentId: dataScope.departmentId } : {}),
      reviewerRole: req.user.role,
      status: 'pending',
    });
    if (!review) return res.status(404).json({ message: 'Pending audit review not found in your scope' });
    const incident = await EdrIncident.findOne({ _id: review.incidentId, companyId: review.companyId });
    if (!incident) return res.status(404).json({ message: 'Linked incident not found' });
    review.status = action === 'approve' ? 'approved' : 'changes_requested';
    review.reviewNote = note;
    review.reviewedBy = req.user.id;
    review.reviewedAt = new Date();
    await review.save();
    if (action === 'request_changes') {
      incident.status = 'investigating';
      incident.resolvedAt = null;
      incident.closedBy = null;
      incident.assignedTo = review.submittedBy;
      incident.notes.push({ user: req.user.id, text: `Audit changes requested: ${note}`, at: new Date() });
      await incident.save();
      await Promise.all([
        incident.correlationId ? CorrelationEvent.updateOne({ _id: incident.correlationId }, { $set: { status: 'investigating', resolvedAt: null, assignedTo: review.submittedBy } }) : null,
        Alert.updateMany({ _id: { $in: incident.alertIds || [] }, companyId: incident.companyId }, { $set: { status: 'investigating', resolvedAt: null } }),
      ]);
    }
    await writeAudit(req, `incident.audit_${action}`, 'EdrIncident', incident._id, incident.companyId, { reviewId: review._id, sourceRole: review.sourceRole, auditType: review.auditType, note });
    const payload = { type: `audit_${action}`, resourceType: 'incident', resourceId: incident._id, reviewId: review._id };
    req.app.get('io')?.to(`company:${incident.companyId}`).emit('soc:audit:update', payload);
    req.app.get('io')?.to(`user:${review.submittedBy}`).emit('soc:audit:update', payload);
    res.json({ message: action === 'approve' ? 'Incident closure audit approved' : 'Incident reopened and returned for changes', review, incident });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/work-items/:type/:id/action', async (req, res) => {
  try {
    if (req.params.type !== 'incident') return res.status(400).json({ message: 'Invalid work item type' });
    const action = String(req.body.action || '').toLowerCase();
    const allowed = req.user.role === 'soc_manager'
      ? ['investigate','note','resolve','false_positive']
      : ['acknowledge','investigate','note','escalate','resolve','false_positive'];
    if (!allowed.includes(action)) return res.status(403).json({ message: 'Action not permitted for this role' });
    const { filter } = await scope(req, { personal: req.user.role !== 'soc_manager' && action !== 'acknowledge' });
    if (req.user.role === 'l4_analyst') filter.incidentSource = 'threat_intelligence';
    if (action === 'acknowledge') filter.$or = [{ assignedTo: req.user.id }, { assignedTo: null }];
    const incident = await EdrIncident.findOne({ _id: req.params.id, ...filter });
    if (!incident) return res.status(404).json({ message: 'Incident not found in your assigned scope' });
    if (['resolve', 'false_positive'].includes(action) && ['resolved', 'false_positive'].includes(incident.status)) {
      return res.status(409).json({ message: 'Incident is already closed and submitted for audit' });
    }
    const analystNote = String(req.body.note || '').trim().slice(0, 5000);
    if (action === 'acknowledge') { incident.assignedTo = req.user.id; incident.status = 'investigating'; }
    if (action === 'investigate') {
      incident.status = 'investigating';
      incident.resolvedAt = null;
      incident.closedBy = null;
    }
    if (action === 'resolve') { incident.status = 'resolved'; incident.resolvedAt = new Date(); incident.closedBy = req.user.id; }
    if (action === 'false_positive') { incident.status = 'false_positive'; incident.resolvedAt = new Date(); incident.closedBy = req.user.id; }
    if (action === 'note') {
      if (!analystNote) return res.status(400).json({ message: 'Note is required' });
      incident.notes.push({ user: req.user.id, text: analystNote, at: new Date() });
    }
    if (analystNote && action !== 'note') incident.notes.push({ user: req.user.id, text: analystNote, at: new Date() });
    let escalation = null;
    if (action === 'escalate') {
      const reason = String(req.body.reason || '').trim().slice(0, 2000);
      if (!reason) return res.status(400).json({ message: 'Escalation reason is required' });
      const toLevel = NEXT_LEVEL[req.user.role];
      const targetRole = toLevel === 'l2' ? 'l2_analyst' : toLevel === 'l3' ? 'l3_analyst' : 'soc_manager';
      const candidates = await SocCompanyAssignment.find({ companyId: incident.companyId, active: true }).distinct('userId');
      const target = await User.findOne({ _id: { $in: candidates }, role: targetRole, isActive: true }).select('_id');
      escalation = await SocEscalation.create({
        tenantId: req.user.tenantId, companyId: incident.companyId, departmentId: incident.departmentId,
        incidentId: incident._id, resourceType: 'incident', fromUserId: req.user.id,
        fromLevel: LEVEL[req.user.role], toLevel, assignedTo: target?._id || null, reason,
        summary: String(req.body.summary || '').slice(0, 5000), observedIoc: String(req.body.observedIoc || '').slice(0, 1000),
        affectedAsset: String(req.body.affectedAsset || incident.affectedEndpoint || '').slice(0, 500),
        priority: ['low','medium','high','critical'].includes(req.body.priority) ? req.body.priority : incident.severity,
      });
      if (target) incident.assignedTo = target._id;
      incident.status = 'investigating';
    }
    await incident.save();
    let closureAuditReview = null;
    const auditRoute = CLOSURE_AUDIT_ROUTE[req.user.role];
    if (auditRoute && ['resolve', 'false_positive'].includes(action)) {
      closureAuditReview = await SocIncidentAuditReview.findOneAndUpdate(
        { incidentId: incident._id },
        {
          $set: {
            tenantId: req.user.tenantId,
            companyId: incident.companyId,
            departmentId: incident.departmentId || null,
            auditType: auditRoute.auditType,
            closureAction: action,
            sourceRole: req.user.role,
            reviewerRole: auditRoute.reviewerRole,
            submittedBy: req.user.id,
            submittedAt: new Date(),
            status: 'pending',
            reviewNote: '',
            reviewedBy: null,
            reviewedAt: null,
          },
          $inc: { submissionCount: 1 },
        },
        { upsert: true, new: true, setDefaultsOnInsert: true },
      );
    }
    const linkedSync = { correlation: 0, alerts: 0, escalations: 0 };
    const statusAction = ['investigate', 'resolve', 'false_positive'].includes(action);
    if (incident.correlationId && statusAction) {
      const correlationUpdate = await CorrelationEvent.updateOne(
        { _id: incident.correlationId, companyId: incident.companyId },
        {
          $set: {
            assignedTo: incident.assignedTo,
            status: incident.status,
            resolvedAt: incident.resolvedAt || null,
          },
          $push: { resolutionHistory: {
            status: incident.status,
            notes: analystNote || `Synchronized from incident ${incident._id}`,
            changedBy: req.user.id,
            changedAt: new Date(),
          } },
        },
      );
      linkedSync.correlation = correlationUpdate.modifiedCount || 0;
    } else if (incident.correlationId) {
      const correlationUpdate = await CorrelationEvent.updateOne(
        { _id: incident.correlationId, companyId: incident.companyId },
        { $set: { assignedTo: incident.assignedTo } },
      );
      linkedSync.correlation = correlationUpdate.modifiedCount || 0;
    }
    const linkedAlertIds = [...new Set([
      ...(incident.alertIds || []).map(String),
      ...(incident.networkEvidenceAlertIds || []).map(String),
    ])];
    if (statusAction && linkedAlertIds.length) {
      const alertStatus = action === 'resolve' ? 'resolved' : action === 'false_positive' ? 'false_positive' : 'investigating';
      const alertFilter = { _id: { $in: linkedAlertIds }, companyId: incident.companyId };
      const alertUpdate = await Alert.updateMany(alertFilter, {
        $set: {
          status: alertStatus,
          resolvedAt: action === 'investigate' ? null : incident.resolvedAt || new Date(),
        },
      });
      linkedSync.alerts = alertUpdate.modifiedCount || 0;
    }
    if (['resolve', 'false_positive'].includes(action)) {
      const escalationUpdate = await SocEscalation.updateMany(
        { incidentId: incident._id, companyId: incident.companyId, status: { $in: ['pending', 'accepted'] } },
        { $set: {
          status: 'resolved', resolvedAt: incident.resolvedAt || new Date(),
          managerNote: analystNote || `Automatically closed with incident ${incident._id}`,
        } },
      );
      linkedSync.escalations = escalationUpdate.modifiedCount || 0;
    }
    await writeAudit(req, action === 'escalate' ? `incident.escalated_to_${NEXT_LEVEL[req.user.role]}` : `incident.${action}`, 'EdrIncident', incident._id, incident.companyId, {
      escalationId: escalation?._id || null, closureAuditReviewId: closureAuditReview?._id || null, note: analystNote, linkedSync,
    });
    req.app.get('io')?.to(`company:${incident.companyId}`).emit('soc:dashboard:update', { type: action, resourceType: 'incident', resourceId: incident._id });
    req.app.get('io')?.to(`company:${incident.companyId}`).emit('correlation:updated', { change: 'status', correlationId: incident.correlationId, status: incident.status });
    req.app.get('io')?.to('superadmin').emit('soc:dashboard:update', { type: action, resourceType: 'incident', resourceId: incident._id, companyId: incident.companyId });
    if (closureAuditReview) req.app.get('io')?.to(`company:${incident.companyId}`).emit('soc:audit:update', { type: 'closure_submitted', reviewId: closureAuditReview._id, resourceId: incident._id, reviewerRole: closureAuditReview.reviewerRole, auditType: closureAuditReview.auditType });
    res.json({ message: `Incident ${action} completed`, incident, escalation, closureAuditReview, linkedSync });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/escalations', async (req, res) => {
  try {
    const { companyIds, filter: dataScope } = await scope(req);
    const { page,limit } = pageParams(req.query);
    const filter = {
      companyId:{ $in:companyIds },
      ...(dataScope.departmentId ? { departmentId: dataScope.departmentId } : {}),
    };
    if (req.user.role !== 'soc_manager') {
      if (req.query.direction === 'incoming') {
        filter.toLevel = LEVEL[req.user.role];
      } else if (req.query.direction === 'outgoing') {
        filter.fromUserId = req.user.id;
        if (req.user.role === 'l2_analyst') filter.toLevel = 'l3';
        if (req.user.role === 'l3_analyst') filter.toLevel = 'manager';
      } else {
        filter.$or = [{ assignedTo:req.user.id },{ fromUserId:req.user.id },{ toLevel:LEVEL[req.user.role] }];
      }
    }
    if (req.query.status) filter.status = req.query.status;
    const [items,total] = await Promise.all([
      SocEscalation.find(filter).sort({ createdAt:-1 }).skip((page-1)*limit).limit(limit)
        .populate('alertId','eventId description severity status signatureName').populate('incidentId','title severity status').populate('companyId','name')
        .populate('fromUserId','name email role').populate('assignedTo','name email role').lean(),
      SocEscalation.countDocuments(filter),
    ]);
    res.json({ items,total,page,limit,pages:Math.ceil(total/limit) });
  } catch (error) { res.status(500).json({ message:error.message }); }
});

router.post('/alerts/:id/action', async (req, res) => {
  try {
    const action = String(req.body.action || '').toLowerCase();
    const allowedActions = req.user.role === 'soc_manager'
      ? ['assign','investigate','note','resolve','false_positive']
      : ['acknowledge','investigate','note','escalate','resolve','false_positive'];
    if (!allowedActions.includes(action)) return res.status(403).json({ message:'Action not permitted for this role' });
    const { filter } = await scope(req, { personal:req.user.role !== 'soc_manager' && action !== 'acknowledge' });
    if (action === 'acknowledge' && req.user.role !== 'soc_manager') {
      filter.$or = [{ assignedTo:req.user.id }, { assignedTo:null }];
    }
    const alert = await Alert.findOne({ _id:req.params.id, ...filter });
    if (!alert) return res.status(404).json({ message:'Alert not found in your assigned scope' });
    if (action === 'acknowledge') {
      alert.assignedTo=req.user.id;
      alert.status='investigating';
      alert.ticketOpenedAt ||= new Date();
      alert.ticketOpenedBy ||= req.user.id;
    }
    if (action === 'investigate') alert.status='investigating';
    if (action === 'resolve') { alert.status='resolved'; alert.resolvedAt=new Date(); }
    if (action === 'false_positive') { alert.status='false_positive'; alert.resolvedAt=new Date(); }
    if (action === 'note') {
      const note = String(req.body.note || '').trim().slice(0,5000);
      if (!note) return res.status(400).json({ message:'Note is required' });
      alert.notes.push({ user:req.user.id, text:note, at:new Date() });
    }
    let escalation = null;
    if (action === 'escalate') {
      const reason = String(req.body.reason || '').trim().slice(0,2000);
      if (!reason) return res.status(400).json({ message:'Escalation reason is required' });
      const toLevel = NEXT_LEVEL[req.user.role];
      const existingEscalation = await SocEscalation.findOne({
        companyId: alert.companyId,
        alertId: alert._id,
        toLevel,
        status: { $in: ['pending', 'accepted', 'resolved'] },
      }).select('_id status').lean();
      if (existingEscalation) {
        return res.status(409).json({
          message: `This alert is already escalated to ${String(toLevel || '').toUpperCase()} (${existingEscalation.status})`,
          escalationId: existingEscalation._id,
        });
      }
      const targetRole = toLevel === 'l2' ? 'l2_analyst' : toLevel === 'l3' ? 'l3_analyst' : 'soc_manager';
      const candidates = await SocCompanyAssignment.find({ companyId:alert.companyId, active:true }).distinct('userId');
      const target = await User.findOne({ _id:{ $in:candidates }, role:targetRole, isActive:true }).sort({ lastLogin:-1 }).select('_id');
      escalation = await SocEscalation.create({
        tenantId:alert.tenantId || req.user.tenantId, companyId:alert.companyId, departmentId:alert.departmentId,
        alertId:alert._id, fromUserId:req.user.id, fromLevel:LEVEL[req.user.role], toLevel,
        assignedTo:target?._id || null, reason, summary:String(req.body.summary || '').slice(0,5000),
        observedIoc:String(req.body.observedIoc || '').slice(0,1000), affectedAsset:String(req.body.affectedAsset || '').slice(0,500),
        priority:['low','medium','high','critical'].includes(req.body.priority) ? req.body.priority : alert.severity,
      });
      if (target) alert.assignedTo=target._id;
      alert.status='investigating';
    }
    await alert.save();
    await writeAudit(req, action === 'escalate' ? `escalated_to_${NEXT_LEVEL[req.user.role]}` : `alert.${action}`, 'Alert', alert._id, alert.companyId, { escalationId:escalation?._id || null });
    const io=req.app.get('io');
    io?.to(`company:${alert.companyId}`).emit('soc:dashboard:update',{ type:action, alertId:alert._id });
    res.json({ message:`Alert ${action} completed`, alert, escalation });
  } catch (error) { res.status(500).json({ message:error.message }); }
});

router.patch('/escalations/:id', async (req,res) => {
  try {
    if (req.user.role !== 'soc_manager') return res.status(403).json({ message:'SOC Manager approval required' });
    const { companyIds } = await scope(req);
    const status = String(req.body.status || '');
    if (!['accepted','rejected','resolved'].includes(status)) return res.status(400).json({ message:'Invalid escalation status' });
    const escalation = await SocEscalation.findOneAndUpdate(
      { _id:req.params.id, companyId:{ $in:companyIds } },
      { status, managerNote:String(req.body.note || '').slice(0,3000), ...(status === 'resolved' ? { resolvedAt:new Date() } : {}) },
      { new:true, runValidators:true },
    );
    if (!escalation) return res.status(404).json({ message:'Escalation not found' });
    await writeAudit(req, `escalation.${status}`, 'SocEscalation', escalation._id, escalation.companyId, {});
    res.json(escalation);
  } catch (error) { res.status(500).json({ message:error.message }); }
});

module.exports = router;
