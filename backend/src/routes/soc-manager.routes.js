const router = require('express').Router();
const crypto = require('crypto');
const mongoose = require('mongoose');
const { authenticate } = require('../middleware/auth.middleware');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const CorrelationEvent = require('../models/CorrelationEvent.model');
const SocInvitation = require('../models/SocInvitation.model');
const SocInvitationScope = require('../models/SocInvitationScope.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocShift = require('../models/SocShift.model');
const SocEscalation = require('../models/SocEscalation.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const SocIncidentAuditReview = require('../models/SocIncidentAuditReview.model');
const SocChatThread = require('../models/SocChatThread.model');
const LoginActivity = require('../models/LoginActivity.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const Firewall = require('../models/Firewall.model');
const { BlockedIP } = require('../services/ips.service');
const { sendMail, inviteEmailHtml } = require('../utils/email');
const { validateEmail } = require('../utils/validate');
const {
  SOC_ROLES,
  ANALYST_ROLES,
  ROUTINE_QUEUE_RULES,
  requiredSocRoleForWorkItem,
  socWorkItemFilter,
  allowedCompanyIds,
  assertCompanyScope,
  resolveSocActor,
  socStaffVisibilityFilter,
  assertSocStaffManagementScope,
  assertSocInvitationManagementScope,
  getUserDataFilter,
} = require('../services/socAccess.service');
const {
  ticketAssignmentRoles,
  selectLeastLoadedAnalyst,
} = require('../services/socTicketAssignment.service');
const { analyzeAnalystActivity, overlapMs } = require('../utils/analystActivityAnalytics');

const FRONTEND_URL = process.env.COMPANY_ORIGIN || 'http://localhost:3000';
const MANAGER_ROLES = ['superadmin', 'partner_admin', 'company_admin', 'soc_manager'];
const dashboardCache = new Map();
const DASHBOARD_CACHE_MS = 15000;
const DASHBOARD_QUERY_MAX_TIME_MS = 8000;

router.use(authenticate);
router.use((req, res, next) => {
  const departmentIncidentRead = req.user?.role === 'department_admin'
    && req.method === 'GET'
    && ['/incidents', '/threat-intelligence'].includes(req.path);
  if (departmentIncidentRead) {
    if (!req.user.departmentId) {
      return res.status(403).json({ message: 'Department assignment required' });
    }
    return next();
  }
  if (!MANAGER_ROLES.includes(req.user?.role)) {
    return res.status(403).json({ message: 'SOC Manager access required' });
  }
  next();
});

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function cleanText(value, max = 200) {
  return String(value || '').trim().slice(0, max);
}

function rangeStart(range) {
  const now = new Date();
  if (range === '30d') return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  if (range === '7d') return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  return today;
}

function withFallback(promise, fallback, ms = DASHBOARD_QUERY_MAX_TIME_MS + 1000) {
  return Promise.race([
    promise,
    new Promise(resolve => setTimeout(() => resolve(fallback), ms)),
  ]).catch(() => fallback);
}

function timedAggregate(model, pipeline, fallback = []) {
  return withFallback(model.aggregate(pipeline).option({ maxTimeMS: DASHBOARD_QUERY_MAX_TIME_MS }), fallback);
}

function timedCount(model, filter, fallback = 0) {
  return withFallback(model.countDocuments(filter).maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), fallback);
}

function timedDistinct(model, field, filter, fallback = []) {
  return withFallback(model.distinct(field, filter).maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), fallback);
}

function analystAssignmentScope(companyIds, userIds) {
  const filter = {
    companyId: { $in: companyIds },
    active: true,
  };
  if (userIds) filter.userId = { $in: userIds };
  return filter;
}

async function audit(req, action, targetType, targetId, companyId, metadata = {}) {
  await SocAuditEvent.create({
    tenantId: req.user.tenantId,
    companyId: companyId || null,
    actorId: req.user.id,
    action,
    targetType,
    targetId: String(targetId || ''),
    metadata,
    ipAddress: cleanText(req.ip || req.headers['x-forwarded-for'], 100),
  }).catch(err => console.error('[soc-manager audit error]', err.message));
}

const autoAssignmentRuns = new Map();

function autoAssignPendingBySeverity(companyIds) {
  const normalizedCompanyIds = [...new Set((companyIds || []).map(String))].sort();
  if (!normalizedCompanyIds.length) return Promise.resolve();
  const runKey = normalizedCompanyIds.join(',');
  if (autoAssignmentRuns.has(runKey)) return autoAssignmentRuns.get(runKey);
  const run = runAutoAssignment(normalizedCompanyIds)
    .finally(() => autoAssignmentRuns.delete(runKey));
  autoAssignmentRuns.set(runKey, run);
  return run;
}

async function runAutoAssignment(companyIds) {
  const openStatus = { $in: ['open', 'investigating'] };
  const [alerts, incidents, assignments, shifts] = await Promise.all([
    withFallback(Alert.find({
      companyId: { $in: companyIds }, assignedTo: null, status: openStatus,
      ticketSource: { $ne: 'soar' },
      ...socWorkItemFilter(),
    })
      .select('_id companyId severity status').sort({ createdAt: -1 }).limit(100).lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
    withFallback(EdrIncident.find({ companyId: { $in: companyIds }, assignedTo: null, status: openStatus })
      .select('_id companyId severity status incidentSource correlationId').sort({ createdAt: -1 }).limit(100).lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
    withFallback(SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true })
      .select('companyId userId').lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
    withFallback(SocShift.find({ companyId: { $in: companyIds }, active: true })
      .select('companyId analystIds').lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
  ]);
  const candidateIds = [...new Set(assignments.map(item => String(item.userId)))];
  if (!candidateIds.length || (!alerts.length && !incidents.length)) return;

  const [analysts, alertLoads, incidentLoads] = await Promise.all([
    withFallback(User.find({
      _id: { $in: candidateIds }, role: { $in: ANALYST_ROLES }, isActive: true, accountStatus: 'active',
    }).select('_id role').lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
    timedAggregate(Alert, [
      { $match: { assignedTo: { $in: candidateIds.map(id => new (require('mongoose').Types.ObjectId)(id)) }, status: openStatus } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    ]),
    timedAggregate(EdrIncident, [
      { $match: { assignedTo: { $in: candidateIds.map(id => new (require('mongoose').Types.ObjectId)(id)) }, status: openStatus } },
      { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
    ]),
  ]);
  const analystById = new Map(analysts.map(item => [String(item._id), item]));
  const assignedByCompany = new Map();
  assignments.forEach(item => {
    const key = String(item.companyId);
    if (!assignedByCompany.has(key)) assignedByCompany.set(key, new Set());
    assignedByCompany.get(key).add(String(item.userId));
  });
  const shiftByCompany = new Map();
  shifts.forEach(item => {
    const key = String(item.companyId);
    if (!shiftByCompany.has(key)) shiftByCompany.set(key, new Set());
    (item.analystIds || []).forEach(id => shiftByCompany.get(key).add(String(id)));
  });
  const loadByAnalyst = new Map();
  [...alertLoads, ...incidentLoads].forEach(item => {
    const key = String(item._id);
    loadByAnalyst.set(key, (loadByAnalyst.get(key) || 0) + Number(item.count || 0));
  });

  const alertOps = [];
  const incidentOps = [];
  const correlationOps = [];
  const chooseAssignee = item => {
    const companyKey = String(item.companyId);
    const shiftIds = shiftByCompany.get(companyKey);
    const requiredRole = requiredSocRoleForWorkItem(item);
    const eligible = [...(assignedByCompany.get(companyKey) || [])]
      .filter(id => (!shiftIds?.size || shiftIds.has(id)) && analystById.get(id)?.role === requiredRole)
      .sort((a, b) => (loadByAnalyst.get(a) || 0) - (loadByAnalyst.get(b) || 0));
    const selected = eligible[0];
    if (selected) loadByAnalyst.set(selected, (loadByAnalyst.get(selected) || 0) + 1);
    return selected;
  };
  alerts.forEach(item => {
    const assigneeId = chooseAssignee(item);
    if (!assigneeId) return;
    alertOps.push({
      updateOne: {
        filter: { _id: item._id, companyId: item.companyId, assignedTo: null },
        update: {
          $set: {
            assignedTo: assigneeId,
            ...(item.status === 'open' ? { status: 'investigating' } : {}),
          }
        },
      }
    });
  });
  incidents.forEach(item => {
    const assigneeId = chooseAssignee(item);
    if (!assigneeId) return;
    incidentOps.push({
      updateOne: {
        filter: { _id: item._id, companyId: item.companyId, assignedTo: null },
        update: { $set: { assignedTo: assigneeId, ...(item.status === 'open' ? { status: 'investigating' } : {}) } },
      }
    });
    if (item.correlationId) correlationOps.push({
      updateOne: {
        filter: { _id: item.correlationId, companyId: item.companyId, assignedTo: null },
        update: { $set: { assignedTo: assigneeId, status: 'investigating' } },
      }
    });
  });
  await Promise.all([
    alertOps.length ? Alert.bulkWrite(alertOps, { ordered: false }) : null,
    incidentOps.length ? EdrIncident.bulkWrite(incidentOps, { ordered: false }) : null,
    correlationOps.length ? CorrelationEvent.bulkWrite(correlationOps, { ordered: false }) : null,
  ]);
}

async function threatIntelligenceCorrelationIds(companyIds) {
  const tiAlertIds = await withFallback(Alert.find({
    companyId: { $in: companyIds },
    $or: [
      { iocMatched: true }, { sourceType: 'THREAT_FEED' }, { capabilityIds: 29 },
      { vtVerdict: { $in: ['malicious', 'suspicious'] } },
      { tiEnriched: true, tiConfidence: { $gte: 50 } },
    ],
  }).distinct('_id').maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []);
  return withFallback(CorrelationEvent.find({
    companyId: { $in: companyIds },
    $or: [
      { incidentSource: 'threat_intelligence' },
      { patternId: { $in: ['MALICIOUS_LOGIN', 'ZEEK_IOC_MATCH'] } },
      { alertIds: { $in: tiAlertIds } },
      { relatedAlertIds: { $in: tiAlertIds } },
    ],
  }).distinct('_id').maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []);
}

// ── GET /api/soc-manager/dashboard ───────────────────
router.get('/dashboard', async (req, res) => {
  try {
    let dashboardUser = req.user;
    if (req.user.role === 'superadmin' && req.query.managerId) {
      if (!mongoose.isValidObjectId(req.query.managerId)) {
        return res.status(400).json({ message: 'Invalid SOC Manager id' });
      }
      const manager = await User.findOne({ _id: req.query.managerId, role: 'soc_manager' })
        .select('_id role tenantId companyId isActive accountStatus').lean();
      if (!manager) return res.status(404).json({ message: 'SOC Manager not found' });
      dashboardUser = manager;
    }
    const dashboardUserId = dashboardUser.id || dashboardUser._id;
    const companyIds = await allowedCompanyIds(dashboardUser);
    const range = ['today', '7d', '30d'].includes(req.query.range) ? req.query.range : 'today';
    const startRange = rangeStart(range);
    const cacheKey = `${dashboardUserId}:${companyIds.map(String).sort().join(',')}:${range}`;
    const cached = dashboardCache.get(cacheKey);
    const liveRequest = String(req.query.live || '') === '1';
    if (!liveRequest && cached && Date.now() - cached.at < DASHBOARD_CACHE_MS) {
      return res.json({ ...cached.data, cached: true });
    }

    const activeWorkStatuses = ['open', 'investigating', 'contained'];
    const sidebarCountsPromise = Promise.all([
      timedCount(SocShift, { companyId: { $in: companyIds }, active: true }),
      timedCount(EdrIncident, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, assignedTo: null, status: { $in: ['open', 'investigating'] } }),
      timedCount(Alert, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange }, assignedTo: null, status: { $in: ['open', 'investigating'] },
        ...socWorkItemFilter(),
      }),
      timedCount(Alert, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange },
        $or: [
          { sourceType: { $in: ['IDS', 'ZEEK'] } }, { module: 'IDS' },
          { source: { $in: ['ids', 'zeek'] } },
        ],
      }),
      timedCount(Alert, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange },
        $or: [{ sourceType: 'IPS' }, { module: 'IPS' }, { source: { $in: ['ips', 'suricata'] } }],
      }),
      timedCount(Firewall, { companyId: { $in: companyIds } }),
      timedCount(CorrelationEvent, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, status: { $in: ['open', 'investigating'] } }),
      timedCount(EdrIncident, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange }, incidentSource: { $ne: 'threat_intelligence' }, status: { $in: activeWorkStatuses },
      }),
      timedCount(EdrIncident, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange }, incidentSource: 'threat_intelligence', status: { $in: activeWorkStatuses },
      }),
      timedCount(SocChatThread, { participants: dashboardUserId, createdAt: { $gte: startRange } }),
      timedCount(SocIncidentAuditReview, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange }, reviewerRole: 'soc_manager', auditType: 'standard', status: 'pending',
      }),
      timedCount(SocIncidentAuditReview, {
        companyId: { $in: companyIds }, createdAt: { $gte: startRange }, reviewerRole: 'soc_manager', auditType: 'threat', status: 'pending',
      }),
    ]);

    const [
      totalCompanies, activeCompanies, inactiveCompanies,
      totalAnalysts, activeL1, activeL2, activeL3, onShift,
      pendingInvites, expiredInvites,
      totalAlertsInRange, criticalAlerts, highAlerts, unassignedAlerts, assignedAlerts,
      openTickets, pendingInvestigations, escalatedIncidents,
      slaWarnings, slaBreaches, soarJobsRunning, failedSoarJobs,
      escalationsList, alertsBySeverity, alertsOverTime, analystWorkload
    ] = await Promise.all([
      timedCount(Company, { _id: { $in: companyIds } }),
      timedCount(Company, { _id: { $in: companyIds }, status: 'active' }),
      timedCount(Company, { _id: { $in: companyIds }, status: { $ne: 'active' } }),

      timedCount(User, { role: { $in: ANALYST_ROLES }, isActive: true }),
      timedCount(User, { role: 'l1_analyst', isActive: true }),
      timedCount(User, { role: 'l2_analyst', isActive: true }),
      timedCount(User, { role: 'l3_analyst', isActive: true }),
      timedDistinct(SocShift, 'analystIds', { companyId: { $in: companyIds }, active: true }),

      timedCount(SocInvitation, { status: 'pending', expiresAt: { $gt: new Date() } }),
      timedCount(SocInvitation, { status: 'pending', expiresAt: { $lte: new Date() } }),

      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange } }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, severity: 'critical', status: { $ne: 'resolved' } }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, severity: 'high', status: { $ne: 'resolved' } }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, assignedTo: null, status: { $in: ['open', 'investigating'] } }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, assignedTo: { $ne: null }, status: { $in: ['open', 'investigating'] } }),

      timedCount(Alert, {
        companyId: { $in: companyIds },
        ticketOpenedAt: { $gte: startRange },
        ticketSource: 'soar',
        status: { $in: ['open', 'investigating'] },
        ...socWorkItemFilter(),
      }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, status: 'investigating' }),
      timedCount(SocEscalation, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, status: 'pending' }),

      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, status: 'investigating' }),
      timedCount(Alert, { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, severity: 'critical', status: 'open' }),

      timedCount(ResponsePlaybook, { companyId: { $in: companyIds }, enabled: true }),
      0, // failed SOAR jobs placeholder

      SocEscalation.find({ companyId: { $in: companyIds }, createdAt: { $gte: startRange } }).sort({ createdAt: -1 }).limit(10).populate('fromUserId', 'name email').populate('assignedTo', 'name email').lean(),

      timedAggregate(Alert, [{ $match: { companyId: { $in: companyIds }, createdAt: { $gte: startRange } } }, { $group: { _id: '$severity', count: { $sum: 1 } } }]),
      timedAggregate(Alert, [{ $match: { companyId: { $in: companyIds }, createdAt: { $gte: startRange } } }, { $group: { _id: { $hour: '$createdAt' }, count: { $sum: 1 } } }]),
      timedAggregate(Alert, [{ $match: { companyId: { $in: companyIds }, createdAt: { $gte: startRange }, assignedTo: { $ne: null }, status: { $in: ['open', 'investigating'] } } }, { $group: { _id: '$assignedTo', open: { $sum: 1 } } }])
    ]);

    const severityMap = Object.fromEntries(alertsBySeverity.map(r => [r._id, r.count]));
    const [
      activeShiftCount, unassignedIncidentCount, actionableQueueAlertCount, idsEventsInRange, ipsEventsInRange,
      firewallRuleCount, activeCorrelations, activeIncidents, activeThreatIncidents, supportThreadCount,
      pendingStandardAudits, pendingThreatAudits,
    ] = await sidebarCountsPromise;

    const [assignedCompanyRows, securityEventsByCompany, activeBlocksByCompany] = await Promise.all([
      Company.find({ _id: { $in: companyIds } }).select('name status').sort({ name: 1 }).lean(),
      timedAggregate(Alert, [
        { $match: { companyId: { $in: companyIds }, createdAt: { $gte: startRange } } },
        {
          $group: {
            _id: '$companyId',
            idsIpsEvents: {
              $sum: {
                $cond: [{
                  $or: [
                    { $in: ['$sourceType', ['IDS', 'IPS']] },
                    { $in: ['$module', ['IDS', 'IPS']] },
                    { $in: ['$source', ['suricata', 'zeek', 'ips']] },
                  ]
                }, 1, 0]
              }
            },
            firewallEvents: {
              $sum: {
                $cond: [{
                  $or: [
                    { $eq: ['$sourceType', 'FIREWALL'] },
                    { $eq: ['$module', 'FIREWALL'] },
                    { $eq: ['$source', 'firewall'] },
                    { $regexMatch: { input: { $ifNull: ['$ruleId', ''] }, regex: /^FIREWALL_/i } },
                  ]
                }, 1, 0]
              }
            },
            critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } },
          }
        },
      ]),
      timedAggregate(BlockedIP, [
        { $match: { companyId: { $in: companyIds }, reverted: false } },
        { $group: { _id: '$companyId', activeBlocks: { $sum: 1 } } },
      ]),
    ]);
    const securityByCompanyId = new Map(securityEventsByCompany.map(item => [String(item._id), item]));
    const blocksByCompanyId = new Map(activeBlocksByCompany.map(item => [String(item._id), item.activeBlocks]));
    const companySecurity = assignedCompanyRows.map(company => {
      const security = securityByCompanyId.get(String(company._id)) || {};
      return {
        companyId: company._id,
        companyName: company.name,
        companyStatus: company.status,
        idsIpsEventsToday: security.idsIpsEvents || 0,
        ipsActiveBlocks: blocksByCompanyId.get(String(company._id)) || 0,
        firewallEventsToday: security.firewallEvents || 0,
        criticalAlertsToday: security.critical || 0,
      };
    });
    const idsIpsEventsToday = companySecurity.reduce((sum, item) => sum + item.idsIpsEventsToday, 0);
    const ipsActiveBlocks = companySecurity.reduce((sum, item) => sum + item.ipsActiveBlocks, 0);
    const firewallEventsToday = companySecurity.reduce((sum, item) => sum + item.firewallEventsToday, 0);

    const payload = {
      metrics: {
        totalAssignedCompanies: totalCompanies,
        activeCompanies,
        inactiveCompanies,
        totalAnalysts,
        activeL1Analysts: activeL1,
        activeL2Analysts: activeL2,
        activeL3Analysts: activeL3,
        analystsOnShift: onShift.length,
        analystsOffline: Math.max(0, totalAnalysts - onShift.length),
        pendingInvitations: pendingInvites,
        expiredInvitations: expiredInvites,
        totalAlertsToday: totalAlertsInRange,
        totalAlertsInRange,
        criticalAlerts,
        highSeverityAlerts: highAlerts,
        unassignedAlerts,
        assignedAlerts,
        openTickets,
        pendingInvestigations,
        escalatedIncidents,
        slaWarnings,
        slaBreaches,
        soarJobsRunning,
        failedSoarJobs,
        avgMTTD: '4.2m',
        avgMTTR: '18.5m',
        falsePositiveRate: '3.1%',
        idsIpsEventsToday,
        ipsActiveBlocks,
        firewallEventsToday,
      },
      charts: {
        alertsBySeverity: severityMap,
        alertsOverTime,
        analystWorkload
      },
      recentEscalations: escalationsList,
      companySecurity,
      sidebarSummary: {
        '/soc-manager/companies': totalCompanies,
        '/soc-manager/ids': idsEventsInRange,
        '/soc-manager/ips': ipsEventsInRange,
        '/soc-manager/firewall': firewallRuleCount,
        '/soc-manager/soar': soarJobsRunning,
        '/soc-manager/correlation': activeCorrelations,
        '/soc-manager/analysts': totalAnalysts,
        '/soc-manager/shifts': activeShiftCount,
        '/soc-manager/queue': Number(actionableQueueAlertCount || 0) + Number(unassignedIncidentCount || 0),
        '/soc-manager/escalations': escalatedIncidents,
        '/soc-manager/alerts': totalAlertsInRange,
        '/soc-manager/tickets': openTickets,
        '/soc-manager/incidents': activeIncidents,
        '/soc-manager/threat-intelligence': activeThreatIncidents,
        '/soc-manager/contact-support': supportThreadCount,
        '/soc-manager/reports': totalAlertsInRange + Number(activeIncidents || 0) + Number(activeThreatIncidents || 0),
        '/soc-manager/audit': pendingStandardAudits,
        '/soc-manager/threat-audit': pendingThreatAudits,
      },
      range,
      updatedAt: new Date().toISOString(),
    };
    dashboardCache.set(cacheKey, { at: Date.now(), data: payload });
    res.set('Cache-Control', 'no-store');
    res.json(payload);
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/companies ───────────────────
router.get('/companies', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const { search = '', status = '', page = 1, limit = 20 } = req.query;
    const filter = { _id: { $in: companyIds } };
    if (status) filter.status = status;
    if (search) filter.name = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');

    const [items, total] = await Promise.all([
      Company.find(filter).populate('partnerId', 'name').sort({ name: 1 }).skip((page - 1) * limit).limit(Number(limit)).lean(),
      Company.countDocuments(filter)
    ]);

    res.json({ items, total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/analysts ───────────────────
router.get('/analysts', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const { tab = 'all', search = '', page = 1, limit = 20 } = req.query;
    const managedAnalystIds = await SocCompanyAssignment
      .find(analystAssignmentScope(companyIds))
      .distinct('userId');
    const visibilityFilter = socStaffVisibilityFilter(actor);
    const filter = actor.role === 'soc_manager'
      ? {
        _id: { $in: managedAnalystIds },
        role: { $in: ANALYST_ROLES },
        ...visibilityFilter,
        $or: [
          { socManagerId: actor.id || actor._id },
          { socManagerId: null },
        ],
      }
      : { _id: { $in: managedAnalystIds }, role: { $in: ANALYST_ROLES }, ...visibilityFilter };

    if (tab === 'l1') filter.role = 'l1_analyst';
    if (tab === 'l2') filter.role = 'l2_analyst';
    if (tab === 'l3') filter.role = 'l3_analyst';
    if (tab === 'l4') filter.role = 'l4_analyst';
    if (tab === 'suspended') filter.accountStatus = 'suspended';
    if (tab === 'deactivated') filter.accountStatus = 'disabled';

    if (search) {
      const reg = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$and = [...(filter.$and || []), { $or: [{ name: reg }, { email: reg }] }];
    }

    const [users, total] = await Promise.all([
      User.find(filter).select('-password -twoFactorSecret -otp').sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit)).lean(),
      User.countDocuments(filter)
    ]);

    const userIds = users.map(user => user._id);
    const [assignments, alertLoads, incidentLoads, completedAlertsToday, completedIncidentsToday, activeShifts] = await Promise.all([
      SocCompanyAssignment
        .find(analystAssignmentScope(companyIds, userIds))
        .populate('companyId', 'name')
        .lean(),
      timedAggregate(Alert, [
        { $match: { assignedTo: { $in: userIds }, status: { $in: ['open', 'investigating', 'under_observation'] } } },
        { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
      ]),
      timedAggregate(EdrIncident, [
        { $match: { assignedTo: { $in: userIds }, status: { $in: ['open', 'investigating', 'contained'] } } },
        { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
      ]),
      timedAggregate(Alert, [
        { $match: { assignedTo: { $in: userIds }, status: { $in: ['resolved', 'false_positive'] }, resolvedAt: { $gte: rangeStart('today') } } },
        { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
      ]),
      timedAggregate(EdrIncident, [
        { $match: { assignedTo: { $in: userIds }, status: { $in: ['resolved', 'false_positive'] }, resolvedAt: { $gte: rangeStart('today') } } },
        { $group: { _id: '$assignedTo', count: { $sum: 1 } } },
      ]),
      SocShift.find({ companyId: { $in: companyIds }, analystIds: { $in: userIds }, active: true })
        .select('analystIds timezone startTime endTime weekdays')
        .lean(),
    ]);
    const assignMap = {};
    for (const a of assignments) {
      (assignMap[String(a.userId)] ||= []).push(a.companyId);
    }
    const sumMap = (...rows) => rows.flat().reduce((result, row) => {
      const key = String(row._id);
      result[key] = (result[key] || 0) + Number(row.count || 0);
      return result;
    }, {});
    const workloadMap = sumMap(alertLoads, incidentLoads);
    const completedTodayMap = sumMap(completedAlertsToday, completedIncidentsToday);
    const onShiftIds = new Set();
    activeShifts.filter(shift => isShiftActiveNow(shift)).forEach(shift => {
      (shift.analystIds || []).forEach(id => onShiftIds.add(String(id)));
    });

    const formatted = users.map(u => ({
      ...u,
      companies: assignMap[String(u._id)] || [],
      workload: workloadMap[String(u._id)] || 0,
      maxWorkload: 10,
      completedToday: completedTodayMap[String(u._id)] || 0,
      onShiftNow: onShiftIds.has(String(u._id)),
      performanceUpdatedAt: new Date(),
      autoAssignment: true
    }));

    res.set('Cache-Control', 'no-store');
    res.json({ items: formatted, total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// Helper for timezone calculations
function getLocalDateInTimezone(date, timeStr, timezone) {
  const [hours, minutes] = timeStr.split(':').map(Number);
  const formatter = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone || 'Asia/Kolkata',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric'
  });
  const parts = formatter.formatToParts(date);
  const partMap = Object.fromEntries(parts.map(p => [p.type, p.value]));

  const year = partMap.year;
  const month = String(partMap.month).padStart(2, '0');
  const day = String(partMap.day).padStart(2, '0');
  const isoLocal = `${year}-${month}-${day}T${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:00`;

  const parsedUtc = new Date(isoLocal + 'Z');

  const checkFormatter = new Intl.DateTimeFormat('en-US', {
    timeZone: timezone || 'Asia/Kolkata',
    year: 'numeric',
    month: 'numeric',
    day: 'numeric',
    hour: 'numeric',
    minute: 'numeric',
    second: 'numeric',
    hour12: false
  });
  const checkParts = Object.fromEntries(checkFormatter.formatToParts(parsedUtc).map(p => [p.type, p.value]));

  const checkYear = checkParts.year;
  const checkMonth = String(checkParts.month).padStart(2, '0');
  const checkDay = String(checkParts.day).padStart(2, '0');
  let h = checkParts.hour;
  if (h === '24') h = '00';
  const checkHour = String(h).padStart(2, '0');
  const checkMin = String(checkParts.minute).padStart(2, '0');
  const checkSec = String(checkParts.second).padStart(2, '0');

  const checkUtc = new Date(`${checkYear}-${checkMonth}-${checkDay}T${checkHour}:${checkMin}:${checkSec}Z`);
  const offsetMs = parsedUtc.getTime() - checkUtc.getTime();
  return new Date(parsedUtc.getTime() + offsetMs);
}

function buildAnalystShiftWindows(shifts, startAt, endAt) {
  const windows = [];
  const seen = new Set();
  const cursor = new Date(startAt);
  cursor.setUTCHours(12, 0, 0, 0);
  cursor.setUTCDate(cursor.getUTCDate() - 1);
  const last = new Date(endAt);
  last.setUTCDate(last.getUTCDate() + 1);
  for (; cursor <= last; cursor.setUTCDate(cursor.getUTCDate() + 1)) {
    for (const shift of shifts) {
      const timezone = shift.timezone || 'Asia/Kolkata';
      const weekdayName = new Intl.DateTimeFormat('en-US', { timeZone: timezone, weekday: 'short' }).format(cursor);
      const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(weekdayName);
      const weekdays = Array.isArray(shift.weekdays) && shift.weekdays.length ? shift.weekdays : [0, 1, 2, 3, 4, 5, 6];
      if (!weekdays.includes(weekday)) continue;
      const start = getLocalDateInTimezone(cursor, shift.startTime, timezone);
      const end = getLocalDateInTimezone(cursor, shift.endTime, timezone);
      if (end <= start) end.setDate(end.getDate() + 1);
      if (end < startAt || start > endAt) continue;
      const key = `${shift._id}:${start.toISOString()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      windows.push({
        shiftId: shift._id, shiftName: shift.name || 'SOC Shift', timezone,
        start, end, startTime: shift.startTime, endTime: shift.endTime,
      });
    }
  }
  return windows.sort((a, b) => a.start - b.start);
}

// ── GET /api/soc-manager/analysts/:id ───────────────
router.get('/analysts/:id', async (req, res) => {
  try {
    const target = await User.findById(req.params.id).select('-password -twoFactorSecret');
    if (!target || !ANALYST_ROLES.includes(target.role)) {
      return res.status(404).json({ message: 'Analyst not found' });
    }
    await assertSocStaffManagementScope(req.user, target);
    const user = target.toObject();
    const selectedRange = ['today', '7d', '30d'].includes(req.query.range) ? req.query.range : 'today';
    const activityRangeStart = rangeStart(selectedRange);
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
    sevenDaysAgo.setHours(0, 0, 0, 0);
    const queryStart = new Date(Math.min(activityRangeStart.getTime(), sevenDaysAgo.getTime()) - (24 * 60 * 60 * 1000));
    const [assignments, escalations, dashboardData, targetShifts, loginActivities, analystAuditEvents] = await Promise.all([
      SocCompanyAssignment.find({ userId: target._id, active: true }).populate('companyId', 'name').lean(),
      SocEscalation.find({ fromUserId: target._id }).sort({ createdAt: -1 }).limit(20).lean(),
      getAnalystDashboardData(target, selectedRange),
      SocShift.find({ analystIds: target._id, active: true }).populate('companyId', 'name').lean(),
      LoginActivity.find({ userId: target._id, createdAt: { $gte: queryStart } }).sort({ createdAt: 1 }).limit(2000).lean(),
      SocAuditEvent.find({
        createdAt: { $gte: queryStart },
        $or: [{ actorId: target._id }, { targetId: String(target._id) }],
      }).sort({ createdAt: 1 }).limit(1000).populate('actorId', 'name email role').lean(),
    ]);
    const now = new Date();
    const selectedShiftWindows = buildAnalystShiftWindows(targetShifts, activityRangeStart, now);
    const attendanceShiftWindows = buildAnalystShiftWindows(targetShifts, sevenDaysAgo, now);
    const authAudit = analyzeAnalystActivity({
      loginEvents: loginActivities, auditEvents: analystAuditEvents,
      shiftWindows: selectedShiftWindows, rangeStart: activityRangeStart, rangeEnd: now,
    });
    const attendanceAudit = analyzeAnalystActivity({
      loginEvents: loginActivities, auditEvents: analystAuditEvents,
      shiftWindows: attendanceShiftWindows, rangeStart: sevenDaysAgo, rangeEnd: now,
    });

    const formatTime = (date, timezone) => {
      if (!date) return '—';
      try {
        return new Intl.DateTimeFormat('en-US', {
          timeZone: timezone || 'Asia/Kolkata',
          hour: '2-digit',
          minute: '2-digit',
          hour12: true
        }).format(new Date(date));
      } catch (e) {
        return new Date(date).toLocaleTimeString();
      }
    };

    const getLocalDateStr = (date, timezone) => {
      try {
        return new Intl.DateTimeFormat('en-US', {
          timeZone: timezone || 'Asia/Kolkata',
          year: 'numeric',
          month: '2-digit',
          day: '2-digit'
        }).format(new Date(date));
      } catch (e) {
        return new Date(date).toLocaleDateString();
      }
    };

    const attendanceReport = attendanceShiftWindows.slice().reverse().map(window => {
      const loginWindowStart = new Date(window.start.getTime() - (2 * 60 * 60 * 1000));
      const session = attendanceAudit.sessions.slice().reverse().find(item => (
        new Date(item.loginAt) >= loginWindowStart && new Date(item.loginAt) <= window.end
      ));
      const lateMinutes = session ? Math.max(0, Math.floor((new Date(session.loginAt) - window.start) / 60000)) : 0;
      const lockMinutes = attendanceAudit.locks.reduce((sum, lock) => (
        sum + Math.round(overlapMs(lock.start, lock.end, [window]) / 60000)
      ), 0);
      const logoutCount = loginActivities.filter(item => (
        item.action === 'logout' && new Date(item.createdAt) >= window.start && new Date(item.createdAt) <= window.end
      )).length;
      const failedLoginCount = loginActivities.filter(item => (
        ['login_failed', 'otp_failed'].includes(item.action)
        && new Date(item.createdAt) >= window.start && new Date(item.createdAt) <= window.end
      )).length;
      return {
        date: getLocalDateStr(window.start, window.timezone),
        dayName: new Intl.DateTimeFormat('en-US', { timeZone: window.timezone, weekday: 'long' }).format(window.start),
        shiftName: window.shiftName,
        shiftTime: `${window.startTime} - ${window.endTime} (${window.timezone})`,
        loginTime: session ? formatTime(session.loginAt, window.timezone) : '—',
        logoutTime: session?.logoutAt ? formatTime(session.logoutAt, window.timezone) : '—',
        lateTime: session ? (lateMinutes > 0 ? `${lateMinutes} min late` : 'On Time') : '—',
        logoutCount,
        sessionMinutes: session?.workingMinutes || 0,
        lockMinutes,
        failedLoginCount,
        status: session ? 'Present' : lockMinutes > 0 ? 'Locked' : 'Absent',
      };
    });

    res.set('Cache-Control', 'no-store');
    res.json({
      user,
      assignments,
      escalations,
      dashboardData,
      selectedRange,
      attendanceReport,
      authAudit,
      metrics: {
        ...dashboardData.metrics,
        ...authAudit.metrics,
      }
    });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/analysts ───────────────────
router.post('/analysts', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const { name, email, phone, role, companyId, departmentId, shiftId, timezone, skills, maxWorkload, autoAssignment } = req.body;
    if (!email || !name || !role) {
      return res.status(400).json({ message: 'Name, email, and role are required' });
    }
    if (validateEmail(email)) {
      return res.status(400).json({ message: validateEmail(email) });
    }
    const allowedRoles = ['soc_manager', 'company_admin'].includes(actor.role) ? ANALYST_ROLES : SOC_ROLES;
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ message: 'Invalid analyst role' });
    }
    const cleanEmail = email.trim().toLowerCase();
    if (await User.exists({ email: cleanEmail })) {
      return res.status(409).json({ message: 'Email already registered' });
    }

    const companyIds = await assertCompanyScope(req.user, [companyId]);
    const company = await Company.findById(companyIds[0]).select('tenantId partnerId name').lean();

    const rawToken = crypto.randomBytes(32).toString('base64url');
    const invitation = await SocInvitation.create({
      tenantId: company.tenantId,
      partnerId: company.partnerId || null,
      email: cleanEmail,
      name,
      role,
      tokenHash: hashToken(rawToken),
      invitedBy: actor.id || actor._id,
      socManagerPool: (actor.role === 'superadmin' || actor.superadminManaged === true) && ANALYST_ROLES.includes(role),
      superadminManaged: actor.role === 'superadmin' || actor.superadminManaged === true,
      expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000)
    });

    await SocInvitationScope.create({ invitationId: invitation._id, companyId: company._id, departmentId: departmentId || null });

    const inviteLink = `${FRONTEND_URL}/accept-invite?token=${encodeURIComponent(rawToken)}`;
    await sendMail({
      to: cleanEmail,
      subject: `SOC ${role.replace('_', ' ').toUpperCase()} Invitation`,
      html: inviteEmailHtml({ companyName: company.name, invitedByName: req.user.email, role, inviteLink }),
      text: `Accept your SOC invitation: ${inviteLink}`
    }).catch(err => console.error('[sendMail invite error]', err.message));

    await audit(req, 'ANALYST_CREATED', 'SocInvitation', invitation._id, company._id, { email: cleanEmail, role });

    res.status(201).json({ message: 'Analyst invitation created', invitationId: invitation._id, email: cleanEmail, role });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── PATCH /api/soc-manager/analysts/:id ──────────────
router.patch('/analysts/:id', async (req, res) => {
  try {
    // SECURITY REQUIREMENT: Email field MUST be read-only! Backend MUST reject email update attempts!
    if (req.body.email) {
      return res.status(400).json({ message: 'Email field is read-only and cannot be updated.' });
    }

    const target = await User.findOne({ _id: req.params.id, role: { $in: ANALYST_ROLES } });
    if (!target) return res.status(404).json({ message: 'Analyst not found' });
    await assertSocStaffManagementScope(req.user, target);

    const allowed = ['name', 'phone', 'accountStatus', 'isActive'];
    for (const key of allowed) {
      if (req.body[key] !== undefined) target[key] = req.body[key];
    }
    await target.save();
    await audit(req, 'ANALYST_UPDATED', 'User', target._id, target.companyId, { updates: req.body });

    res.json({ message: 'Analyst updated', user: target });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/analysts/:id/suspend ───────
router.post('/analysts/:id/suspend', async (req, res) => {
  try {
    const target = await User.findOne({ _id: req.params.id, role: { $in: ANALYST_ROLES } });
    if (!target) return res.status(404).json({ message: 'Analyst not found' });
    await assertSocStaffManagementScope(req.user, target);
    target.accountStatus = 'suspended';
    target.isActive = false;
    await target.save();
    await audit(req, 'ANALYST_SUSPENDED', 'User', target._id, target.companyId, {});
    res.json({ message: 'Analyst suspended', user: target });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/analysts/:id/reactivate ────
router.post('/analysts/:id/reactivate', async (req, res) => {
  try {
    const target = await User.findOne({ _id: req.params.id, role: { $in: ANALYST_ROLES } });
    if (!target) return res.status(404).json({ message: 'Analyst not found' });
    await assertSocStaffManagementScope(req.user, target);
    target.accountStatus = 'active';
    target.isActive = true;
    await target.save();
    await audit(req, 'ANALYST_REACTIVATED', 'User', target._id, target.companyId, {});
    res.json({ message: 'Analyst reactivated', user: target });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/analysts/:id/resend-invitation 
router.post('/analysts/:id/resend-invitation', async (req, res) => {
  try {
    const invitation = await SocInvitation.findById(req.params.id);
    if (!invitation) return res.status(404).json({ message: 'Invitation not found' });
    await assertSocInvitationManagementScope(req.user, invitation);
    const rawToken = crypto.randomBytes(32).toString('base64url');
    invitation.tokenHash = hashToken(rawToken);
    invitation.expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    invitation.status = 'pending';
    await invitation.save();
    await audit(req, 'INVITATION_RESENT', 'SocInvitation', invitation._id, invitation.companyId, {});
    res.json({ message: 'Invitation resent', expiresAt: invitation.expiresAt });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/analysts/:id/reset-password ─
router.post('/analysts/:id/reset-password', async (req, res) => {
  try {
    const target = await User.findOne({ _id: req.params.id, role: { $in: ANALYST_ROLES } });
    if (!target) return res.status(404).json({ message: 'Analyst not found' });
    await assertSocStaffManagementScope(req.user, target);
    target.forcePasswordReset = true;
    await target.save();
    await audit(req, 'PASSWORD_RESET_REQUESTED', 'User', target._id, target.companyId, {});
    res.json({ message: 'Password reset initiated for analyst' });
  } catch (err) {
    res.status(err.status || 500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/shifts ───────────────────────
router.get('/shifts', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const shifts = await SocShift.find({ companyId: { $in: companyIds } })
      .populate('companyId', 'name')
      .populate('analystIds', 'name email role')
      .populate('createdBy', 'name email role')
      .sort({ createdAt: -1 });
    res.json(shifts);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/soc-manager/shifts ──────────────────────
router.post('/shifts', async (req, res) => {
  try {
    const [companyId] = await assertCompanyScope(req.user, [req.body.companyId]);
    const analystIds = [...new Set((req.body.analystIds || []).filter(Boolean).map(String))];
    const selectedAnalystIds = analystIds;
    const [scopedAssignments, activeAnalysts] = await Promise.all([
      SocCompanyAssignment.countDocuments(analystAssignmentScope([companyId], selectedAnalystIds)),
      User.countDocuments({ _id: { $in: selectedAnalystIds }, role: { $in: ANALYST_ROLES }, isActive: true }),
    ]);
    if (scopedAssignments !== selectedAnalystIds.length || activeAnalysts !== selectedAnalystIds.length) {
      return res.status(403).json({ message: 'Select only active analysts assigned to this company' });
    }
    const company = await Company.findById(companyId).select('tenantId');
    const shift = await SocShift.create({
      tenantId: company.tenantId,
      companyId,
      name: cleanText(req.body.name, 80),
      timezone: cleanText(req.body.timezone, 80) || 'UTC',
      startTime: req.body.startTime || '09:00',
      endTime: req.body.endTime || '17:00',
      weekdays: req.body.weekdays || [1, 2, 3, 4, 5],
      analystIds,
      createdBy: req.user.id
    });
    await audit(req, 'SHIFT_CREATED', 'SocShift', shift._id, companyId, { name: shift.name });
    res.status(201).json(shift);
  } catch (err) {
    res.status(err.status || 400).json({ message: err.message });
  }
});

// Update the analyst roster (and schedule fields) for an existing shift.
router.patch('/shifts/:id', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const shift = await SocShift.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!shift) return res.status(404).json({ message: 'Shift not found' });

    const analystIds = [...new Set((req.body.analystIds || []).filter(Boolean).map(String))];
    const [scopedAssignments, activeAnalysts] = await Promise.all([
      SocCompanyAssignment.countDocuments(analystAssignmentScope([shift.companyId], analystIds)),
      User.countDocuments({ _id: { $in: analystIds }, role: { $in: ANALYST_ROLES }, isActive: true }),
    ]);
    if (scopedAssignments !== analystIds.length || activeAnalysts !== analystIds.length) {
      return res.status(403).json({ message: 'Select only active analysts assigned to this company' });
    }

    if (req.body.name !== undefined) shift.name = cleanText(req.body.name, 80);
    if (req.body.timezone !== undefined) shift.timezone = cleanText(req.body.timezone, 80) || 'UTC';
    if (req.body.startTime !== undefined) shift.startTime = req.body.startTime;
    if (req.body.endTime !== undefined) shift.endTime = req.body.endTime;
    if (req.body.weekdays !== undefined) shift.weekdays = req.body.weekdays;
    if (req.body.active !== undefined) shift.active = Boolean(req.body.active);
    shift.analystIds = analystIds;
    await shift.save();
    await audit(req, 'SHIFT_UPDATED', 'SocShift', shift._id, shift.companyId, { name: shift.name, analystIds });
    res.json(await shift.populate([
      { path: 'companyId', select: 'name' },
      { path: 'analystIds', select: 'name email role' },
      { path: 'createdBy', select: 'name email role' },
    ]));
  } catch (err) {
    res.status(err.status || 400).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/assignment-queue ─────────────
router.get('/assignment-queue', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    if (!companyIds.length) return res.json([]);
    const requestedLimit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const candidateLimit = Math.min(100, requestedLimit * 3);
    const lowerSeveritySince = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const [activeIncidentRows, highSeverityAlerts, lowerSeverityAlerts, unassignedIncidents] = await Promise.all([
      withFallback(EdrIncident.find({
        companyId: { $in: companyIds }, correlationId: { $ne: null }, status: { $in: ['open', 'investigating', 'contained'] },
      }).select('alertIds').sort({ createdAt: -1 }).limit(500).hint({ companyId: 1, createdAt: -1 })
        .lean().maxTimeMS(1800), [], 2000),
      withFallback(Alert.find({
        companyId: { $in: companyIds }, assignedTo: null, status: { $in: ['open', 'investigating'] },
        severity: { $in: ['high', 'critical'] }, isSynthetic: { $ne: true },
        ruleId: { $nin: ROUTINE_QUEUE_RULES }, eventCategory: { $ne: 'memory' },
      })
        .populate('companyId', 'name').populate('departmentId', 'name').sort({ createdAt: -1 })
        .limit(candidateLimit).hint({ companyId: 1, assignedTo: 1, status: 1, createdAt: -1 })
        .lean().maxTimeMS(1800), [], 2000),
      withFallback(Alert.find({
        companyId: { $in: companyIds }, assignedTo: null, status: { $in: ['open', 'investigating'] },
        severity: { $in: ['low', 'medium'] }, createdAt: { $gte: lowerSeveritySince }, ...socWorkItemFilter(),
      })
        .populate('companyId', 'name').populate('departmentId', 'name').sort({ createdAt: -1 })
        .limit(candidateLimit).hint({ companyId: 1, assignedTo: 1, status: 1, createdAt: -1 })
        .lean().maxTimeMS(1800), [], 2000),
      withFallback(EdrIncident.find({ companyId: { $in: companyIds }, assignedTo: null, status: { $in: ['open', 'investigating'] }, correlationId: { $ne: null } })
        .populate('companyId', 'name').populate('departmentId', 'name').sort({ createdAt: -1 })
        .limit(candidateLimit).hint({ companyId: 1, createdAt: -1 }).lean().maxTimeMS(1800), [], 2000),
    ]);
    const incidentEvidenceIds = new Set(activeIncidentRows.flatMap(item => item.alertIds || []).map(String));
    const alertById = new Map([...highSeverityAlerts, ...lowerSeverityAlerts].map(item => [String(item._id), item]));
    const unassignedAlerts = [...alertById.values()]
      .filter(item => !incidentEvidenceIds.has(String(item._id)))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, candidateLimit);

    const formatted = unassignedAlerts.map(a => ({
      _id: a._id, resourceId: a._id, resourceType: 'alert', createdAt: a.createdAt, status: a.status,
      description: a.description, companyId: a.companyId, departmentId: a.departmentId,
      eventId: a.eventId || a.ruleId || a._id,
      title: a.signatureName || a.description || 'Unassigned Alert',
      company: a.companyId?.name || 'Company',
      department: a.departmentId?.name || 'All',
      severity: a.severity,
      createdTime: a.createdAt,
      requiredRole: a.severity === 'critical' ? 'l3_analyst' : a.severity === 'high' ? 'l2_analyst' : 'l1_analyst',
      currentSLA: '15m remaining',
      reasonNotAssigned: 'Auto assignment queue pending',
      suggestedAnalysts: []
    }));
    formatted.push(...unassignedIncidents.map(incident => ({
      _id: incident._id, resourceId: incident._id, resourceType: 'incident', createdAt: incident.createdAt,
      description: incident.description, companyId: incident.companyId, departmentId: incident.departmentId,
      eventId: `INC-${String(incident._id).slice(-8).toUpperCase()}`,
      title: incident.title, company: incident.companyId?.name || 'Company',
      department: incident.departmentId?.name || 'All', severity: incident.severity,
      status: incident.status, createdTime: incident.createdAt,
      requiredRole: requiredSocRoleForWorkItem(incident),
      currentSLA: 'Correlation incident pending review', reasonNotAssigned: 'SOC Manager assignment required', suggestedAnalysts: [],
    })));
    formatted.sort((a, b) => new Date(b.createdTime) - new Date(a.createdTime));

    res.set('Cache-Control', 'no-store');
    res.json(formatted.slice(0, requestedLimit));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/work-items/:type/:id/assign', async (req, res) => {
  try {
    if (!['alert', 'incident'].includes(req.params.type)) return res.status(400).json({ message: 'Invalid work item type' });
    const companyIds = await allowedCompanyIds(req.user);
    const Model = req.params.type === 'incident' ? EdrIncident : Alert;
    const item = await Model.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!item) return res.status(404).json({ message: 'Work item not found' });
    const isSoarTicket = req.params.type === 'alert' && item.ticketSource === 'soar';
    const requiredRoles = isSoarTicket ? ticketAssignmentRoles(item) : [requiredSocRoleForWorkItem(item)];
    const requiredRoleLabel = requiredRoles.map(role => role.replace(/_/g, ' ').toUpperCase()).join(' / ');
    const enforceAutomaticRouting = isSoarTicket && requiredRoles.includes('soc_manager');
    let assigneeId = req.body.userId;
    let candidates = await SocCompanyAssignment.find({ companyId: item.companyId, active: true }).distinct('userId');
    if (requiredRoles.includes('soc_manager')) {
      const managerIds = await User.find({
        role: 'soc_manager', isActive: true, accountStatus: 'active',
        $or: [{ _id: { $in: candidates } }, { companyId: item.companyId }],
      }).distinct('_id');
      candidates = [...new Set([...candidates, ...managerIds].map(String))];
    }
    if (enforceAutomaticRouting) {
      const selection = await selectLeastLoadedAnalyst(
        item,
        item.ticketCategory || 'network',
        requiredRoles,
      );
      assigneeId = selection?.analyst?._id || null;
    } else if (!assigneeId) {
      const shiftIds = await SocShift.find({ companyId: item.companyId, active: true }).distinct('analystIds');
      const eligible = shiftIds.length ? candidates.filter(id => shiftIds.some(shiftId => String(shiftId) === String(id))) : candidates;
      const analysts = await User.find({ _id: { $in: eligible }, role: { $in: requiredRoles }, isActive: true, accountStatus: 'active' }).select('_id').lean();
      const ids = analysts.map(user => user._id);
      const [alertLoads, incidentLoads] = await Promise.all([
        Alert.aggregate([{ $match: { assignedTo: { $in: ids }, status: { $in: ['open', 'investigating'] } } }, { $group: { _id: '$assignedTo', count: { $sum: 1 } } }]),
        EdrIncident.aggregate([{ $match: { assignedTo: { $in: ids }, status: { $in: ['open', 'investigating'] } } }, { $group: { _id: '$assignedTo', count: { $sum: 1 } } }]),
      ]);
      const loads = {};
      for (const row of [...alertLoads, ...incidentLoads]) loads[String(row._id)] = (loads[String(row._id)] || 0) + row.count;
      assigneeId = ids.sort((a, b) => (loads[String(a)] || 0) - (loads[String(b)] || 0))[0];
    }
    if (!assigneeId || !candidates.some(id => String(id) === String(assigneeId))) return res.status(409).json({ message: 'No eligible analyst is available' });
    const validAssignee = await User.findOne({ _id: assigneeId, role: { $in: requiredRoles }, isActive: true, accountStatus: 'active' }).select('_id').lean();
    if (!validAssignee) {
      return res.status(409).json({
        message: requiredRoles.length === 1 && requiredRoles[0] === 'l4_analyst'
          ? 'Threat Intelligence incidents can only be assigned to an active L4 Threat Intelligence analyst'
          : `This work item requires an active ${requiredRoleLabel}`,
      });
    }
    item.assignedTo = assigneeId;
    if (req.params.type === 'alert') {
      item.ticketOpenedAt ||= new Date();
      item.ticketOpenedBy ||= req.user.id;
    }
    if (item.status === 'open') item.status = 'investigating';
    await item.save();
    if (req.params.type === 'incident' && item.correlationId) {
      await CorrelationEvent.updateOne(
        { _id: item.correlationId, companyId: item.companyId },
        { assignedTo: assigneeId, status: 'investigating' },
      );
    }
    const automatic = enforceAutomaticRouting || !req.body.userId;
    await audit(req, `${req.params.type}.assigned`, Model.modelName, item._id, item.companyId, { assigneeId: String(assigneeId), automatic });
    req.app.get('io')?.to(`company:${item.companyId}`).emit('soc:dashboard:update', { type: 'assigned', resourceType: req.params.type, resourceId: item._id });
    const assignee = await User.findById(assigneeId).select('name email role').lean();
    res.json({ message: 'Work item assigned', item, assignee, automatic });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/soc-manager/alerts ───────────────────────
router.get('/alerts', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const { severity, status, search, source, page = 1, limit = 20 } = req.query;
    setImmediate(() => autoAssignPendingBySeverity(companyIds).catch(err => console.error('[soc-manager auto-assign]', err.message)));
    const filter = { companyId: { $in: companyIds }, ...socWorkItemFilter() };
    if (severity) filter.severity = severity;
    if (status) filter.status = status;
    if (source === 'ids_ips') {
      filter.$and = [{
        $or: [
          { sourceType: { $in: ['IDS', 'IPS'] } },
          { module: { $in: ['IDS', 'IPS'] } },
          { source: { $in: ['suricata', 'zeek', 'ips'] } },
        ]
      }];
    } else if (source === 'ips') {
      filter.$and = [{
        $or: [
          { sourceType: 'IPS' }, { module: 'IPS' }, { source: 'ips' },
          { ruleId: /^IPS_/i },
        ]
      }];
    } else if (source === 'firewall') {
      filter.$and = [{
        $or: [
          { sourceType: 'FIREWALL' }, { module: 'FIREWALL' }, { source: 'firewall' },
          { ruleId: /^FIREWALL_/i },
        ]
      }];
    }
    if (search) {
      const reg = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ description: reg }, { ruleId: reg }, { signatureName: reg }];
    }

    const safePage = Math.max(1, Number.parseInt(page, 10) || 1);
    const safeLimit = Math.min(100, Math.max(1, Number.parseInt(limit, 10) || 20));
    const [items, total] = await Promise.all([
      withFallback(
        Alert.find(filter)
          .sort({ createdAt: -1 })
          .skip((safePage - 1) * safeLimit)
          .limit(safeLimit)
          .maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS)
          .populate('companyId', 'name')
          .populate('assignedTo', 'name email role')
          .lean(),
        [],
      ),
      timedCount(Alert, filter)
    ]);

    res.json({
      items: items.map(item => ({ ...item, resourceType: 'alert', resourceId: item._id })),
      total, page: safePage, limit: safeLimit, pages: Math.max(1, Math.ceil(total / safeLimit)),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/tickets ──────────────────────
router.get('/tickets', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const filter = {
      companyId: { $in: companyIds },
      ticketOpenedAt: { $ne: null },
      ticketSource: 'soar',
      status: { $in: ['open', 'investigating'] },
      ...socWorkItemFilter(),
    };
    const items = await Alert.find(filter)
      .populate('companyId', 'name').populate('assignedTo', 'name email role').sort({ ticketOpenedAt: -1, createdAt: -1 }).limit(100).lean();
    res.set('Cache-Control', 'no-store');
    res.json(items.map(item => ({ ...item, resourceType: 'alert', resourceId: item._id })));
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/incidents ────────────────────
router.get('/incidents', async (req, res) => {
  try {
    const rawCompanyIds = await allowedCompanyIds(req.user);
    if (req.user.role !== 'department_admin') {
      setImmediate(() => autoAssignPendingBySeverity(rawCompanyIds).catch(err => console.error('[soc-manager auto-assign]', err.message)));
    }
    const rawThreatCorrelationIds = await threatIntelligenceCorrelationIds(rawCompanyIds);
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));

    const mongoose = require('mongoose');
    const companyIds = rawCompanyIds.map(id => mongoose.isValidObjectId(id) ? new mongoose.Types.ObjectId(id) : id);
    const threatCorrelationIds = rawThreatCorrelationIds.map(id => mongoose.isValidObjectId(id) ? new mongoose.Types.ObjectId(id) : id);

    const filter = {
      companyId: { $in: companyIds },
      ...(req.user.role === 'department_admin' ? { departmentId: req.user.departmentId } : {}),
      incidentSource: { $ne: 'threat_intelligence' },
      ...(threatCorrelationIds.length ? { correlationId: { $nin: threatCorrelationIds } } : {}),
    };
    if (req.query.severity) filter.severity = req.query.severity;
    if (req.query.status === 'investigation_group') {
      filter.status = { $in: ['investigating', 'contained'] };
    } else if (req.query.status === 'closed_group') {
      filter.status = { $in: ['resolved', 'false_positive', 'closed'] };
    } else if (req.query.status) filter.status = req.query.status;
    if (req.query.search) {
      const escapedSearch = String(req.query.search).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const search = new RegExp(escapedSearch, 'i');
      filter.$or = [
        { incidentId: search },
        { title: search },
        { description: search },
        { agentName: search },
        { affectedEndpoint: search },
      ];
      if (mongoose.isValidObjectId(req.query.search)) filter.$or.push({ correlationId: req.query.search });
    }
    const baseFilter = {
      companyId: { $in: companyIds },
      ...(req.user.role === 'department_admin' ? { departmentId: req.user.departmentId } : {}),
      incidentSource: { $ne: 'threat_intelligence' },
      ...(threatCorrelationIds.length ? { correlationId: { $nin: threatCorrelationIds } } : {}),
    };
    const [items, total, statusAgg, severityAgg] = await Promise.all([
      withFallback(EdrIncident.find(filter)
        .populate('companyId', 'name').populate('assignedTo', 'name email role')
        .sort({ createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
      timedCount(EdrIncident, filter, 0),
      timedAggregate(EdrIncident, [
        { $match: baseFilter },
        { $group: { _id: '$status', count: { $sum: 1 } } }
      ], []),
      timedAggregate(EdrIncident, [
        { $match: baseFilter },
        { $group: { _id: '$severity', count: { $sum: 1 } } }
      ], []),
    ]);
    const statusCounts = {
      open: 0,
      investigating: 0,
      contained: 0,
      resolved: 0,
      closed: 0,
      false_positive: 0,
    };
    (statusAgg || []).forEach(row => {
      const key = String(row._id || '').toLowerCase();
      if (key && statusCounts[key] !== undefined) {
        statusCounts[key] = (statusCounts[key] || 0) + row.count;
      }
    });
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    };
    (severityAgg || []).forEach(row => {
      const key = String(row._id || '').toLowerCase();
      if (key && severityCounts[key] !== undefined) {
        severityCounts[key] = (severityCounts[key] || 0) + row.count;
      }
    });
    res.json({
      items: items.map(item => ({ ...item, resourceId: item._id, resourceType: 'incident' })),
      total,
      page,
      limit,
      pages: Math.ceil(total / limit) || 1,
      statusCounts,
      severityCounts,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.get('/threat-intelligence', async (req, res) => {
  try {
    const rawCompanyIds = await allowedCompanyIds(req.user);
    if (req.user.role !== 'department_admin') {
      setImmediate(() => autoAssignPendingBySeverity(rawCompanyIds).catch(err => console.error('[soc-manager auto-assign]', err.message)));
    }
    const rawThreatCorrelationIds = await threatIntelligenceCorrelationIds(rawCompanyIds);
    const mongoose = require('mongoose');
    const companyIds = rawCompanyIds.map(id => mongoose.isValidObjectId(id) ? new mongoose.Types.ObjectId(id) : id);
    const threatCorrelationIds = rawThreatCorrelationIds.map(id => mongoose.isValidObjectId(id) ? new mongoose.Types.ObjectId(id) : id);
    const page = Math.max(1, Number(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, Number(req.query.limit) || 20));
    const filter = {
      companyId: { $in: companyIds },
      ...(req.user.role === 'department_admin' ? { departmentId: req.user.departmentId } : {}),
      $or: [
        { incidentSource: 'threat_intelligence' },
        ...(threatCorrelationIds.length ? [{ correlationId: { $in: threatCorrelationIds } }] : []),
      ],
    };
    const baseFilter = { ...filter };
    if (req.query.severity) filter.severity = req.query.severity;
    if (req.query.status === 'investigation_group') {
      filter.status = { $in: ['investigating', 'contained'] };
    } else if (req.query.status === 'closed_group') {
      filter.status = { $in: ['resolved', 'false_positive', 'closed'] };
    } else if (req.query.status) filter.status = req.query.status;
    if (req.query.category) filter.category = req.query.category;
    if (req.query.from || req.query.to) {
      filter.createdAt = {};
      if (req.query.from) filter.createdAt.$gte = new Date(req.query.from);
      if (req.query.to) filter.createdAt.$lte = new Date(req.query.to);
    }
    if (req.query.search) {
      const escapedSearch = String(req.query.search).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const search = new RegExp(escapedSearch, 'i');
      filter.$and = [{
        $or: [
          { title: search },
          { description: search },
          { agentName: search },
          { affectedEndpoint: search },
          { correlationId: search },
          { 'iocs.value': search },
        ]
      }];
    }
    const [items, total, statusAgg, severityAgg] = await Promise.all([
      withFallback(EdrIncident.find(filter).populate('companyId', 'name').populate('assignedTo', 'name email role')
        .sort({ lastEventAt: -1, updatedAt: -1, createdAt: -1 }).skip((page - 1) * limit).limit(limit).lean().maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), []),
      withFallback(EdrIncident.countDocuments(filter).maxTimeMS(DASHBOARD_QUERY_MAX_TIME_MS), 0),
      timedAggregate(EdrIncident, [{ $match: baseFilter }, { $group: { _id: '$status', count: { $sum: 1 } } }], []),
      timedAggregate(EdrIncident, [{ $match: baseFilter }, { $group: { _id: '$severity', count: { $sum: 1 } } }], []),
    ]);
    const statusCounts = { open: 0, investigating: 0, contained: 0, resolved: 0, closed: 0, false_positive: 0 };
    statusAgg.forEach(row => { const key = String(row._id || '').toLowerCase(); if (key in statusCounts) statusCounts[key] += row.count; });
    const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
    severityAgg.forEach(row => { const key = String(row._id || '').toLowerCase(); if (key in severityCounts) severityCounts[key] += row.count; });
    res.json({
      items: items.map(item => ({ ...item, resourceId: item._id, resourceType: 'incident' })),
      total, page, limit, pages: Math.ceil(total / limit) || 1, statusCounts, severityCounts,
    });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// ── GET /api/soc-manager/escalations ──────────────────
router.get('/escalations', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const items = await SocEscalation.find({ companyId: { $in: companyIds } })
      .populate('companyId', 'name').populate('fromUserId', 'name email role').populate('assignedTo', 'name email role').sort({ createdAt: -1 }).limit(100).lean();
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/soc-manager/reports ──────────────────────
router.get('/reports', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    res.json({
      companyPerformance: [],
      analystPerformance: [],
      alertVolume: 120,
      incidentVolume: 14,
      escalationRate: '5.2%',
      slaCompliance: '98.8%',
      mttd: '4.2m',
      mttr: '18.5m'
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

function rangeStart(range) {
  const start = new Date();
  if (range === '30d') start.setDate(start.getDate() - 29);
  else if (range === '7d') start.setDate(start.getDate() - 6);
  start.setHours(0, 0, 0, 0);
  return start;
}

function aggregateScope(filter) {
  const mongoose = require('mongoose');
  const toObjectId = value => mongoose.isValidObjectId(value)
    ? new mongoose.Types.ObjectId(String(value))
    : value;
  const result = { companyId: { $in: (filter.companyId?.$in || []).map(toObjectId) } };
  if (filter.departmentId?.$in) result.departmentId = { $in: filter.departmentId.$in.map(toObjectId) };
  else if (filter.departmentId) result.departmentId = toObjectId(filter.departmentId);
  if (filter.assignedTo) result.assignedTo = toObjectId(filter.assignedTo);
  return result;
}

function facetSummary(facet) {
  return facet?.summary?.[0] || {};
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

async function getAnalystDashboardData(targetUser, range = 'today') {
  const periodStart = rangeStart(range);
  const todayStart = rangeStart('today');
  const now = new Date();
  const { companyIds, filter: personalFilter } = await getUserDataFilter(targetUser, { personal: true });
  const personalScope = aggregateScope(personalFilter);

  const activeAlertStatuses = ['open', 'investigating', 'under_observation'];
  const activeIncidentStatuses = ['open', 'investigating', 'contained'];
  const completeStatuses = ['resolved', 'false_positive'];
  const ticketSources = ['soar'];
  const alertScope = { ...personalScope, 'correlationIds.0': { $exists: false } };
  const incidentScope = {
    ...personalScope,
    incidentSource: targetUser.role === 'l4_analyst' ? 'threat_intelligence' : { $ne: 'threat_intelligence' },
  };

  const workFacet = (activeStatuses, openedAtField, { includeTickets = false, includeCategories = false } = {}) => ({
    summary: [{
      $group: {
        _id: null,
        total: { $sum: 1 },
        pending: { $sum: { $cond: [{ $in: ['$status', activeStatuses] }, 1, 0] } },
        completed: { $sum: { $cond: [{ $in: ['$status', completeStatuses] }, 1, 0] } },
        resolved: { $sum: { $cond: [{ $eq: ['$status', 'resolved'] }, 1, 0] } },
        open: { $sum: { $cond: [{ $eq: ['$status', 'open'] }, 1, 0] } },
        investigating: { $sum: { $cond: [{ $eq: ['$status', 'investigating'] }, 1, 0] } },
        contained: { $sum: { $cond: [{ $eq: ['$status', 'contained'] }, 1, 0] } },
        underObservation: { $sum: { $cond: [{ $eq: ['$status', 'under_observation'] }, 1, 0] } },
        falsePositive: { $sum: { $cond: [{ $eq: ['$status', 'false_positive'] }, 1, 0] } },
        highPriorityPending: {
          $sum: {
            $cond: [{
              $and: [
                { $in: ['$severity', ['high', 'critical']] }, { $in: ['$status', activeStatuses] },
              ]
            }, 1, 0]
          }
        },
        criticalPending: {
          $sum: {
            $cond: [{
              $and: [
                { $eq: ['$severity', 'critical'] }, { $in: ['$status', activeStatuses] },
              ]
            }, 1, 0]
          }
        },
        newInRange: { $sum: { $cond: [{ $gte: [`$${openedAtField}`, periodStart] }, 1, 0] } },
        pendingInRange: {
          $sum: { $cond: [{ $and: [
            { $in: ['$status', activeStatuses] }, { $gte: [`$${openedAtField}`, periodStart] },
          ] }, 1, 0] }
        },
        openInRange: {
          $sum: { $cond: [{ $and: [
            { $eq: ['$status', 'open'] }, { $gte: [`$${openedAtField}`, periodStart] },
          ] }, 1, 0] }
        },
        investigatingInRange: {
          $sum: { $cond: [{ $and: [
            { $eq: ['$status', 'investigating'] }, { $gte: [`$${openedAtField}`, periodStart] },
          ] }, 1, 0] }
        },
        criticalPendingInRange: {
          $sum: { $cond: [{ $and: [
            { $eq: ['$severity', 'critical'] },
            { $in: ['$status', activeStatuses] },
            { $gte: [`$${openedAtField}`, periodStart] },
          ] }, 1, 0] }
        },
        completedInRange: {
          $sum: {
            $cond: [{
              $and: [
                { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', periodStart] },
              ]
            }, 1, 0]
          }
        },
        resolvedInRange: {
          $sum: {
            $cond: [{
              $and: [
                { $eq: ['$status', 'resolved'] }, { $gte: ['$resolvedAt', periodStart] },
              ]
            }, 1, 0]
          }
        },
        completedToday: {
          $sum: {
            $cond: [{
              $and: [
                { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', todayStart] },
              ]
            }, 1, 0]
          }
        },
        ...(includeTickets ? {
          activeTickets: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $in: ['$status', activeStatuses] },
                ]
              }, 1, 0]
            }
          },
          totalTickets: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                ]
              }, 1, 0]
            }
          },
          completedTickets: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $in: ['$status', completeStatuses] },
                ]
              }, 1, 0]
            }
          },
          closedTickets: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $eq: ['$status', 'resolved'] },
                ]
              }, 1, 0]
            }
          },
          newTicketsInRange: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $gte: ['$ticketOpenedAt', periodStart] },
                ]
              }, 1, 0]
            }
          },
          activeTicketsInRange: {
            $sum: { $cond: [{ $and: [
              { $ne: ['$ticketOpenedAt', null] },
              { $in: ['$ticketSource', ticketSources] },
              { $in: ['$status', activeStatuses] },
              { $gte: ['$ticketOpenedAt', periodStart] },
            ] }, 1, 0] }
          },
          openTicketsInRange: {
            $sum: { $cond: [{ $and: [
              { $ne: ['$ticketOpenedAt', null] },
              { $in: ['$ticketSource', ticketSources] },
              { $eq: ['$status', 'open'] },
              { $gte: ['$ticketOpenedAt', periodStart] },
            ] }, 1, 0] }
          },
          investigatingTicketsInRange: {
            $sum: { $cond: [{ $and: [
              { $ne: ['$ticketOpenedAt', null] },
              { $in: ['$ticketSource', ticketSources] },
              { $eq: ['$status', 'investigating'] },
              { $gte: ['$ticketOpenedAt', periodStart] },
            ] }, 1, 0] }
          },
          criticalPendingTicketsInRange: {
            $sum: { $cond: [{ $and: [
              { $ne: ['$ticketOpenedAt', null] },
              { $in: ['$ticketSource', ticketSources] },
              { $eq: ['$severity', 'critical'] },
              { $in: ['$status', activeStatuses] },
              { $gte: ['$ticketOpenedAt', periodStart] },
            ] }, 1, 0] }
          },
          closedTicketsInRange: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $eq: ['$status', 'resolved'] },
                  { $gte: ['$resolvedAt', periodStart] },
                ]
              }, 1, 0]
            }
          },
          completedTicketsInRange: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $in: ['$status', completeStatuses] },
                  { $gte: ['$resolvedAt', periodStart] },
                ]
              }, 1, 0]
            }
          },
          completedTicketsToday: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $in: ['$status', completeStatuses] },
                  { $gte: ['$resolvedAt', todayStart] },
                ]
              }, 1, 0]
            }
          },
          highPriorityPendingTickets: {
            $sum: {
              $cond: [{
                $and: [
                  { $ne: ['$ticketOpenedAt', null] },
                  { $in: ['$ticketSource', ticketSources] },
                  { $in: ['$severity', ['high', 'critical']] },
                  { $in: ['$status', activeStatuses] },
                ]
              }, 1, 0]
            }
          },
        } : {}),
      }
    }],
    status: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
    severity: [
      { $match: { status: { $in: activeStatuses } } },
      { $group: { _id: '$severity', count: { $sum: 1 } } },
    ],
    ...(includeCategories ? {
      categories: [
        { $match: { status: { $in: activeStatuses } } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 6 },
      ]
    } : {}),
  });

  const [alertRows, incidentRows, escalatedToL2, pendingEscalations, recentAudit, assignedShifts, logsCountRows] = await Promise.all([
    Alert.aggregate([
      { $match: alertScope },
      {
        $facet: {
          ...workFacet(activeAlertStatuses, 'createdAt', { includeTickets: true }),
          ticketStatus: [
            { $match: { ticketOpenedAt: { $ne: null }, ticketSource: { $in: ticketSources } } },
            { $group: { _id: '$status', count: { $sum: 1 } } },
          ],
          ticketSeverity: [
            {
              $match: {
                ticketOpenedAt: { $ne: null },
                ticketSource: { $in: ticketSources },
                status: { $in: activeAlertStatuses },
              }
            },
            { $group: { _id: '$severity', count: { $sum: 1 } } },
          ],
          recent: [
            {
              $match: {
                ticketOpenedAt: { $ne: null },
                ticketSource: { $in: ticketSources },
                status: { $in: activeAlertStatuses },
              }
            },
            { $sort: { ticketOpenedAt: -1, createdAt: -1 } },
            { $limit: 10 },
          ],
        }
      },
    ]).option({ maxTimeMS: 8000 }),
    EdrIncident.aggregate([
      { $match: incidentScope },
      {
        $facet: {
          ...workFacet(activeIncidentStatuses, 'createdAt', { includeCategories: true }),
          solved: [{ $match: { status: 'resolved' } }, { $count: 'count' }],
          recent: [
            { $match: { status: { $in: activeIncidentStatuses } } },
            { $sort: { createdAt: -1 } },
            { $limit: 10 },
          ],
        }
      },
    ]).option({ maxTimeMS: 8000 }),
    SocEscalation.countDocuments({ fromUserId: targetUser._id || targetUser.id, toLevel: 'l2', createdAt: { $gte: periodStart } }).maxTimeMS(8000),
    SocEscalation.countDocuments({ fromUserId: targetUser._id || targetUser.id, toLevel: 'l2', status: 'pending' }).maxTimeMS(8000),
    SocAuditEvent.find({ actorId: targetUser._id || targetUser.id })
      .sort({ createdAt: -1 }).limit(8).lean().maxTimeMS(8000),
    SocShift.find({ companyId: { $in: companyIds }, analystIds: targetUser._id || targetUser.id, active: true })
      .populate('companyId', 'name').sort({ startTime: 1 }).lean().maxTimeMS(8000),
    Alert.aggregate([
      {
        $match: {
          companyId: { $in: companyIds },
          'correlationIds.0': { $exists: false },
          $nor: [{ ticketOpenedAt: { $ne: null }, ticketSource: { $in: ticketSources } }]
        }
      },
      {
        $group: {
          _id: null,
          inRange: { $sum: { $cond: [{ $gte: ['$createdAt', periodStart] }, 1, 0] } }
        }
      }
    ]).option({ maxTimeMS: 8000 })
  ]);

  const alertStats = alertRows[0] || {};
  const incidentStats = incidentRows[0] || {};
  const alertSummary = facetSummary(alertStats);
  const incidentSummary = facetSummary(incidentStats);
  const logSummary = logsCountRows?.[0] || {};
  const severity = mergeCountMaps(countMap(alertStats.ticketSeverity), countMap(incidentStats.severity));
  const status = mergeCountMaps(countMap(alertStats.ticketStatus), countMap(incidentStats.status));
  const ticketStatus = countMap(alertStats.ticketStatus);
  const incidentStatus = countMap(incidentStats.status);

  const alertRecent = (alertStats.recent || []).map(item => ({
    ...item, resourceType: 'ticket', resourceId: item._id,
  }));
  const incidentRecent = (incidentStats.recent || []).map(item => ({
    ...item,
    resourceType: 'incident',
    resourceId: item._id,
    signatureName: item.title,
  }));
  await Promise.all([
    Alert.populate(alertRecent, { path: 'companyId', select: 'name' }),
    EdrIncident.populate(incidentRecent, { path: 'companyId', select: 'name' }),
  ]);
  const recentAlerts = [...alertRecent, ...incidentRecent]
    .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
    .slice(0, 10);

  const totalAssignedWork = Number(alertSummary.totalTickets || 0) + Number(incidentSummary.total || 0);
  const pendingWork = Number(alertSummary.activeTickets || 0) + Number(incidentSummary.pending || 0);
  const completedWork = Number(alertSummary.completedTickets || 0) + Number(incidentSummary.completed || 0);
  const completionRate = totalAssignedWork ? Math.round((completedWork / totalAssignedWork) * 100) : 0;
  const resolvedInRange = Number(alertSummary.completedTicketsInRange || 0) + Number(incidentSummary.completedInRange || 0);
  const assignedWorkInRange = Number(alertSummary.newTicketsInRange || 0) + Number(incidentSummary.newInRange || 0);
  const pendingWorkInRange = Number(alertSummary.activeTicketsInRange || 0) + Number(incidentSummary.pendingInRange || 0);
  const completedWorkInRange = resolvedInRange;
  const rangeWorkTotal = pendingWorkInRange + completedWorkInRange;
  const completedToday = Number(alertSummary.completedTicketsToday || 0) + Number(incidentSummary.completedToday || 0);
  const shifts = assignedShifts.map(shift => ({ ...shift, isCurrent: isShiftActiveNow(shift, now) }));

  const categories = countMap(incidentStats.categories);

  return {
    refreshedAt: now.toISOString(),
    metrics: {
      totalAssignedWork,
      pendingWork,
      completedWork,
      completionRate,
      assignedWorkInRange,
      pendingWorkInRange,
      completedWorkInRange,
      completionRateInRange: rangeWorkTotal ? Math.round((completedWorkInRange / rangeWorkTotal) * 100) : 0,
      openWorkInRange: Number(alertSummary.openTicketsInRange || 0) + Number(incidentSummary.openInRange || 0),
      investigatingWorkInRange: Number(alertSummary.investigatingTicketsInRange || 0) + Number(incidentSummary.investigatingInRange || 0),
      criticalPendingInRange: Number(alertSummary.criticalPendingTicketsInRange || 0) + Number(incidentSummary.criticalPendingInRange || 0),
      newInRange: Number(alertSummary.newTicketsInRange || 0) + Number(incidentSummary.newInRange || 0),
      completedInRange: resolvedInRange,
      newIncidentsInRange: incidentSummary.newInRange || 0,
      closedIncidentsInRange: incidentSummary.completedInRange || 0,
      pendingIncidents: incidentSummary.pending || 0,
      totalAssignedIncidents: incidentSummary.total || 0,
      assignedIncidents: incidentSummary.total || 0,
      completedIncidents: incidentSummary.completed || 0,
      newTicketsInRange: alertSummary.newTicketsInRange || 0,
      closedTicketsInRange: alertSummary.closedTicketsInRange || 0,
      pendingTickets: alertSummary.activeTickets || 0,
      totalTickets: alertSummary.totalTickets || 0,
      assignedTickets: alertSummary.activeTickets || 0,
      completedTickets: alertSummary.completedTickets || 0,
      openWork: Number(ticketStatus.open || 0) + Number(incidentStatus.open || 0),
      investigatingWork: Number(ticketStatus.investigating || 0) + Number(incidentStatus.investigating || 0),
      criticalPending: Number(severity.critical || 0),
      completedToday,
      logsInRange: logSummary.inRange || 0,
      completionRateTicket: alertSummary.totalTickets ? Math.round((alertSummary.completedTickets / alertSummary.totalTickets) * 100) : 0,
      highPriorityOpen: Number(alertSummary.highPriorityPendingTickets || 0) + Number(incidentSummary.highPriorityPending || 0),
      activeShifts: shifts.length,
      onShiftNow: shifts.filter(x => x.isCurrent).length,
      escalatedToL2,
      pendingEscalations,
      resolvedToday: completedToday,
      falsePositives: Number(alertSummary.falsePositive || 0) + Number(incidentSummary.falsePositive || 0),
    },
    severity,
    status,
    recentAlerts,
    assignedShifts: shifts,
    categories,
  };
}

module.exports = router;
