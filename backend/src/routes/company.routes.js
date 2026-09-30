const router = require('express').Router();
const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const System = require('../models/System.model');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const SoarExecution = require('../models/SoarExecution.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const CompanySupportTicket = require('../models/CompanySupportTicket.model');
const User = require('../models/User.model');
const Firewall = require('../models/Firewall.model');
const BlockedIP = require('../models/BlockedIP.model');
const ForensicHunt = require('../models/ForensicHunt.model');
const ForensicEvidence = require('../models/ForensicEvidence.model');
const { authenticate, requireCompanyAdmin, requireManager, requireAnalyst } = require('../middleware/auth.middleware');
const { getSubscriptionEntitlement } = require('../utils/subscriptionEntitlement');
const { dashboardCompanySummary } = require('../utils/companyPublicView');

router.use(authenticate);

// GET /api/company/overview  — full stats for dashboard (all roles, dept-scoped)
router.get('/overview', requireAnalyst, async (req, res) => {
  try {
    const targetCompanyId = req.query.companyId || req.user.companyId;
    if (!targetCompanyId || !mongoose.Types.ObjectId.isValid(targetCompanyId)) {
      return res.status(400).json({ message: 'Invalid company scope' });
    }
    const companyId = new mongoose.Types.ObjectId(String(targetCompanyId));
    const rawDepartmentId = req.user.role === 'department_admin' ? req.user.departmentId : null;
    const departmentId = rawDepartmentId && mongoose.Types.ObjectId.isValid(rawDepartmentId)
      ? new mongoose.Types.ObjectId(String(rawDepartmentId))
      : null;
    const now = new Date();
    const since24h = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    const onlineSince = new Date(now.getTime() - 10 * 60 * 1000);

    const baseFilter = departmentId ? { companyId, departmentId } : { companyId };
    const alertFilter = { ...baseFilter, status: { $ne: 'false_positive' } };
    const scopedDepartment = departmentId
      ? await Department.findOne({ _id: departmentId, companyId, isActive: true }).lean()
      : null;
    if (req.user.role === 'department_admin' && !scopedDepartment) {
      return res.status(403).json({ message: 'Active department assignment required' });
    }
    const userScopeFilter = departmentId
      ? { companyId, $or: [{ departmentId }, { departmentIds: departmentId }] }
      : { companyId };

    // The dashboard uses the same 31 public EDR capabilities exposed by the UI.
    // Backend IDs 12, 15, 17, 25, 29, 34 and 35 are internal/legacy entries.
    const publicEdrCapabilityIds = [
      1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 16, 18, 19,
      20, 21, 22, 23, 24, 26, 27, 28, 30, 31, 32, 33, 36, 37, 38,
    ];
    const edr24hFilter = {
      ...alertFilter,
      createdAt: { $gte: since24h },
      isSynthetic: { $ne: true },
      $or: [
        { capabilityId: { $in: publicEdrCapabilityIds } },
        { capabilityIds: { $in: publicEdrCapabilityIds } },
      ],
    };
    const ids24hFilter = {
      ...alertFilter,
      createdAt: { $gte: since24h },
      isSynthetic: { $ne: true },
      $or: [
        { module: { $in: ['IDS', 'IPS', 'ids', 'ips'] } },
        { sourceType: { $in: ['IDS', 'IPS', 'ZEEK'] } },
        { source_type: { $in: ['IDS', 'IPS', 'ids', 'ips'] } },
        { source: { $in: ['suricata', 'zeek', 'ids', 'ips'] } },
        { type: { $in: ['IPS_BLOCK', 'IDS_ALERT', 'BLACKLIST_EVENT'] } },
      ],
    };
    const sourceWarnings = [];
    const safeSourceQuery = (label, query, fallback = []) => query.catch((error) => {
      sourceWarnings.push(label);
      console.warn(`[company/overview] ${label} degraded:`, error.message);
      return fallback;
    });

    const tiFilter = {
      ...baseFilter,
      $or: [
        { incidentSource: 'threat_intelligence' },
        { iocMatched: true },
        { tiEnriched: true },
        { category: /threat_intel|threat_intelligence/i },
        { patternId: { $in: ['MALICIOUS_LOGIN', 'ZEEK_IOC_MATCH'] } },
      ],
    };
    const nonTiFilter = {
      ...baseFilter,
      incidentSource: { $ne: 'threat_intelligence' },
      iocMatched: { $ne: true },
      tiEnriched: { $ne: true },
    };

    const [
      company, deptCount, systemCount, userCount, analystCount,
      openAlerts, criticalAlerts,
      totalIncidents, solvedIncidents, edrCorrelationIncidents, edrSolvedIncidents,
      threatIntelIncidents, threatIntelSolvedIncidents,
      soarTotal, soarSolved, soarFailed, supportTickets, supportTicketsSolved,
      forensicHunts, forensicActiveHunts, forensicEvidence, soar24hBreakdownRows, soarPlaybookBreakdownRows, alertActivityRows,
      edrLiveRows, edrCapabilityRows, idsLiveRows, ipsRows, firewallRows, agentRows,
    ] = await Promise.all([
      Company.findById(companyId),
      departmentId ? Promise.resolve(1) : Department.countDocuments({ companyId, isActive: true }),
      System.countDocuments({ ...baseFilter, isActive: true }),
      User.countDocuments({ ...userScopeFilter, isActive: true, role: { $in: ['department_admin', 'soc_manager'] } }),
      User.countDocuments({ ...userScopeFilter, isActive: true, role: { $in: ['analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'] } }),

      Alert.countDocuments({ ...alertFilter, status: 'open' }),
      Alert.countDocuments({ ...alertFilter, severity: 'critical', status: 'open' }),

      EdrIncident.countDocuments(baseFilter).maxTimeMS(5000),
      EdrIncident.countDocuments({ ...baseFilter, status: { $in: ['resolved', 'closed', 'false_positive'] } }).maxTimeMS(5000),
      EdrIncident.countDocuments(nonTiFilter).maxTimeMS(5000),
      EdrIncident.countDocuments({ ...nonTiFilter, status: { $in: ['resolved', 'closed', 'false_positive'] } }).maxTimeMS(5000),
      EdrIncident.countDocuments(tiFilter).maxTimeMS(5000),
      EdrIncident.countDocuments({ ...tiFilter, status: { $in: ['resolved', 'closed', 'false_positive'] } }).maxTimeMS(5000),

      SoarExecution.countDocuments(baseFilter).maxTimeMS(5000),
      SoarExecution.countDocuments({ ...baseFilter, status: { $in: ['completed', 'partially_completed', 'rolled_back'] } }).maxTimeMS(5000),
      SoarExecution.countDocuments({ ...baseFilter, status: { $in: ['failed', 'timed_out', 'rollback_failed', 'cancelled'] } }).maxTimeMS(5000),
      departmentId ? Promise.resolve(0) : CompanySupportTicket.countDocuments({ companyId }).maxTimeMS(5000),
      departmentId ? Promise.resolve(0) : CompanySupportTicket.countDocuments({ companyId, status: { $in: ['Resolved', 'Closed'] } }).maxTimeMS(5000),
      ForensicHunt.countDocuments(baseFilter).maxTimeMS(5000),
      ForensicHunt.countDocuments({ ...baseFilter, status: { $in: ['queued', 'running'] } }).maxTimeMS(5000),
      ForensicEvidence.countDocuments(baseFilter).maxTimeMS(5000),

      safeSourceQuery('soar-24h-breakdown', SoarExecution.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since24h } } },
        { $group: {
          _id: null,
          total: { $sum: 1 },
          manual: { $sum: { $cond: [{ $eq: ['$executionType', 'manual'] }, 1, 0] } },
          automatic: { $sum: { $cond: [{ $eq: ['$executionType', 'automatic'] }, 1, 0] } },
          tickets: { $sum: { $cond: [{ $ne: ['$ticketId', null] }, 1, 0] } },
          pending: { $sum: { $cond: [{ $in: ['$status', ['queued', 'running', 'waiting_for_approval', 'waiting_for_agent', 'waiting_for_retry', 'rollback_running']] }, 1, 0] } },
          completed: { $sum: { $cond: [{ $in: ['$status', ['completed', 'partially_completed', 'rolled_back']] }, 1, 0] } },
          failed: { $sum: { $cond: [{ $in: ['$status', ['failed', 'timed_out', 'rollback_failed', 'cancelled']] }, 1, 0] } },
          aiAnalyzed: { $sum: { $cond: [{ $eq: ['$aiInvestigation.status', 'completed'] }, 1, 0] } },
        } },
      ]).option({ maxTimeMS: 5000 })),

      safeSourceQuery('soar-playbook-breakdown', ResponsePlaybook.aggregate([
        { $match: baseFilter },
        { $group: {
          _id: null,
          total: { $sum: 1 },
          enabled: { $sum: { $cond: ['$enabled', 1, 0] } },
          disabled: { $sum: { $cond: [{ $eq: ['$enabled', false] }, 1, 0] } },
          automatic: { $sum: { $cond: [{ $eq: ['$executionMode', 'automatic'] }, 1, 0] } },
          approvalRequired: { $sum: { $cond: [{ $eq: ['$executionMode', 'approval_required'] }, 1, 0] } },
          manualOnly: { $sum: { $cond: [{ $eq: ['$executionMode', 'manual_only'] }, 1, 0] } },
          modeDisabled: { $sum: { $cond: [{ $eq: ['$executionMode', 'disabled'] }, 1, 0] } },
        } },
      ]).option({ maxTimeMS: 5000 })),

      safeSourceQuery('alert-activity-timeline', Alert.aggregate([
        { $match: { ...alertFilter, createdAt: { $gte: since24h }, isSynthetic: { $ne: true } } },
        { $group: {
          _id: { $dateToString: { format: '%Y-%m-%dT%H:00:00.000Z', date: '$createdAt', timezone: 'UTC' } },
          critical: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'critical'] }, 1, 0] } },
          high: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'high'] }, 1, 0] } },
          investigated: { $sum: { $cond: [{ $in: [{ $toLower: { $ifNull: ['$status', 'open'] } }, ['investigating', 'resolved', 'under_observation']] }, 1, 0] } },
          mitigated: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$status', 'open'] } }, 'resolved'] }, 1, 0] } },
        } },
        { $sort: { _id: 1 } },
      ]).hint('companyId_1_createdAt_-1').option({ maxTimeMS: 8000 })),

      // Real 24h EDR telemetry. A document is counted once in `logs`, while
      // capability coverage is calculated from its canonical capability tags.
      safeSourceQuery('edr-telemetry', Alert.aggregate([
        { $match: edr24hFilter },
        {
          $project: {
            severity: { $toLower: { $ifNull: ['$severity', 'low'] } },
            agent: { $ifNull: ['$systemId', { $ifNull: ['$endpointId', { $ifNull: ['$agentId', '$agentName'] }] }] },
          },
        },
        {
          $group: {
            _id: null,
            logs: { $sum: 1 },
            highCritical: { $sum: { $cond: [{ $in: ['$severity', ['high', 'critical']] }, 1, 0] } },
            reportingAgents: { $addToSet: '$agent' },
          },
        },
        {
          $project: {
            _id: 0,
            logs: 1,
            highCritical: 1,
            reportingAgents: {
              $size: { $setDifference: ['$reportingAgents', [null, '']] },
            },
          },
        },
      ]).hint('companyId_1_createdAt_-1').option({ maxTimeMS: 8000 })),

      // Coverage is grouped directly by capability, avoiding the previous
      // unbounded $push/$reduce array that timed out on busy tenants.
      safeSourceQuery('edr-capability-coverage', Alert.aggregate([
        { $match: edr24hFilter },
        {
          $project: {
            capabilities: {
              $setIntersection: [
                {
                  $setUnion: [
                    { $ifNull: ['$capabilityIds', []] },
                    { $cond: [{ $in: ['$capabilityId', publicEdrCapabilityIds] }, ['$capabilityId'], []] },
                  ],
                },
                publicEdrCapabilityIds,
              ],
            },
          },
        },
        { $unwind: '$capabilities' },
        { $group: { _id: '$capabilities' } },
        { $limit: publicEdrCapabilityIds.length },
      ]).hint('companyId_1_createdAt_-1').option({ maxTimeMS: 8000 })),

      safeSourceQuery('ids-telemetry', Alert.aggregate([
        { $match: ids24hFilter },
        {
          $group: {
            _id: null,
            total: { $sum: 1 },
            critical: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'critical'] }, 1, 0] } },
            high: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'high'] }, 1, 0] } },
            medium: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'medium'] }, 1, 0] } },
            low: { $sum: { $cond: [{ $eq: [{ $toLower: { $ifNull: ['$severity', 'low'] } }, 'low'] }, 1, 0] } },
            blocked: {
              $sum: {
                $cond: [
                  { $or: [{ $eq: ['$blocked', true] }, { $eq: ['$type', 'IPS_BLOCK'] }, { $in: [{ $toLower: { $ifNull: ['$action', ''] } }, ['blocked', 'dropped', 'rejected']] }] },
                  1,
                  0,
                ],
              },
            },
            agents: { $addToSet: { $ifNull: ['$systemId', { $ifNull: ['$agentId', '$agentName'] }] } },
          },
        },
        { $project: { _id: 0, total: 1, critical: 1, high: 1, medium: 1, low: 1, blocked: 1, agentNetwork: { $size: { $setDifference: ['$agents', [null, '']] } } } },
      ]).hint('companyId_1_createdAt_-1').option({ maxTimeMS: 8000 })),

      departmentId ? Promise.resolve([]) : safeSourceQuery('ips-blocklist', BlockedIP.aggregate([
        { $match: { companyId, reverted: false } },
        { $group: { _id: null, activeBlocks: { $sum: 1 }, autoBlocks: { $sum: { $cond: [{ $eq: ['$blockedBy', 'auto'] }, 1, 0] } }, manualBlocks: { $sum: { $cond: [{ $in: ['$blockedBy', ['analyst', 'soar']] }, 1, 0] } } } },
        { $project: { _id: 0, activeBlocks: 1, autoBlocks: 1, manualBlocks: 1 } },
      ]).option({ maxTimeMS: 8000 })),

      safeSourceQuery('firewall-rules', Firewall.aggregate([
        { $match: departmentId ? { companyId, level: 'department', departmentIds: departmentId } : { companyId } },
        { $group: {
          _id: null,
          totalRules: { $sum: 1 },
          enabledRules: { $sum: { $cond: [{ $and: [{ $eq: ['$enabled', true] }, { $eq: ['$deploymentStatus', 'deployed'] }] }, 1, 0] } },
          blockRules: { $sum: { $cond: [{ $eq: ['$action', 'block'] }, 1, 0] } },
          pendingRules: { $sum: { $cond: [{ $and: [{ $eq: ['$enabled', true] }, { $eq: ['$deploymentStatus', 'pending'] }] }, 1, 0] } },
          failedRules: { $sum: { $cond: [{ $and: [{ $eq: ['$enabled', true] }, { $eq: ['$deploymentStatus', 'failed'] }] }, 1, 0] } },
        } },
        { $project: { _id: 0, totalRules: 1, enabledRules: 1, blockRules: 1, pendingRules: 1, failedRules: 1 } },
      ]).option({ maxTimeMS: 8000 })),

      safeSourceQuery('agent-health', System.aggregate([
        { $match: { ...baseFilter, isActive: true } },
        { $group: {
          _id: null,
          total: { $sum: 1 },
          online: { $sum: { $cond: [{ $and: [{ $eq: ['$status', 'active'] }, { $ne: [{ $ifNull: ['$agentVersion', ''] }, ''] }, { $gte: ['$lastSeen', onlineSince] }] }, 1, 0] } },
        } },
        { $project: { _id: 0, total: 1, online: 1, offline: { $subtract: ['$total', '$online'] } } },
      ]).option({ maxTimeMS: 8000 })),
    ]);

    if (!company) return res.status(404).json({ message: 'Company not found' });
    const entitlement = await getSubscriptionEntitlement(company);
    const edrLive = {
      ...(edrLiveRows[0] || { logs: 0, highCritical: 0, reportingAgents: 0 }),
      activeCapabilities: edrCapabilityRows.length,
    };
    const idsLive = idsLiveRows[0] || { total: 0, critical: 0, high: 0, medium: 0, low: 0, blocked: 0, agentNetwork: 0 };
    const ipsLive = ipsRows[0] || { activeBlocks: 0, autoBlocks: 0, manualBlocks: 0 };
    const firewallLive = firewallRows[0] || { totalRules: 0, enabledRules: 0, blockRules: 0, pendingRules: 0, failedRules: 0 };
    const systemsLive = agentRows[0] || { total: systemCount, online: 0, offline: systemCount };

    res.json({
      // Never expose enrollment keys, 2FA material, contact details, or payment
      // gateway identifiers in the dashboard summary response.
      company: departmentId
        ? { _id: company._id, name: company.name, status: company.status }
        : dashboardCompanySummary(company),
      stats: {
        departments: deptCount,
        users: userCount,
        analysts: analystCount,
        systemsUsed: systemCount,
        systemLimit: departmentId
          ? Number(scopedDepartment.assignedSystemCount || 0) + Number(scopedDepartment.assignedServerCount || 0) + Number(scopedDepartment.assignedPhoneCount || 0)
          : company.plan?.systemLimit || 0,
        systemsRemaining: Math.max(0, (departmentId
          ? Number(scopedDepartment.assignedSystemCount || 0) + Number(scopedDepartment.assignedServerCount || 0) + Number(scopedDepartment.assignedPhoneCount || 0)
          : company.plan?.systemLimit || 0) - systemCount),
        openAlerts,
        criticalAlerts,
        planActive: entitlement.licenseActive,
        basePlanActive: entitlement.baseActive,
        addSystemBatchActive: entitlement.batchActive,
        planType: company.plan?.type || 'none',
        planExpires: company.plan?.expiresAt,
        riskScore: company.riskScore || 0,
        status: company.status,
        incidents: {
          total: totalIncidents,
          solved: solvedIncidents,
          open: Math.max(0, totalIncidents - solvedIncidents),
          edrCorrelation: {
            total: edrCorrelationIncidents,
            solved: edrSolvedIncidents,
            open: Math.max(0, edrCorrelationIncidents - edrSolvedIncidents),
          },
          threatIntel: {
            total: threatIntelIncidents,
            solved: threatIntelSolvedIncidents,
            open: Math.max(0, threatIntelIncidents - threatIntelSolvedIncidents),
          },
        },
        soar: {
          total: soarTotal,
          solved: soarSolved,
          failed: soarFailed,
          open: Math.max(0, soarTotal - soarSolved - soarFailed),
          last24h: soar24hBreakdownRows[0] || {
            total: 0, manual: 0, automatic: 0, tickets: 0,
            pending: 0, completed: 0, failed: 0, aiAnalyzed: 0,
          },
          playbooks: soarPlaybookBreakdownRows[0] || {
            total: 0, enabled: 0, disabled: 0, automatic: 0,
            approvalRequired: 0, manualOnly: 0, modeDisabled: 0,
          },
        },
        supportTickets: {
          total: supportTickets,
          solved: supportTicketsSolved,
          open: Math.max(0, supportTickets - supportTicketsSolved),
        },
        forensics: {
          hunts: forensicHunts,
          activeHunts: forensicActiveHunts,
          evidence: forensicEvidence,
        },
        sources: {
          windowHours: 24,
          updatedAt: now,
          degraded: sourceWarnings.length > 0,
          warnings: sourceWarnings,
          edr: { ...edrLive, totalCapabilities: publicEdrCapabilityIds.length },
          ids: { ...idsLive, severity: { critical: idsLive.critical, high: idsLive.high, medium: idsLive.medium, low: idsLive.low } },
          ips: ipsLive,
          firewall: firewallLive,
          systems: systemsLive,
          alertActivity: alertActivityRows,
        },
      },
    });
  } catch (err) {
    console.error('[overview]', err);
    res.status(500).json({ message: err.message });
  }
});

// GET /api/company/me
router.get('/me', requireAnalyst, async (req, res) => {
  try {
    const company = await Company.findById(req.user.companyId);
    res.json(company);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/company/profile  — update company metadata (company_admin only)
router.patch('/profile', requireCompanyAdmin, async (req, res) => {
  try {
    const allowed = ['name', 'phone', 'industry', 'website', 'companySize', 'country'];
    const updates = Object.fromEntries(
      Object.entries(req.body).filter(([k]) => allowed.includes(k))
    );
    const company = await Company.findByIdAndUpdate(
      req.user.companyId,
      { $set: updates },
      { new: true, runValidators: true }
    );
    if (!company) return res.status(404).json({ message: 'Company not found' });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: req.user.id,
      companyId: req.user.companyId,
      email: req.user.email,
      action: 'company_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${req.user.companyId}`).emit('activity:new', { companyId: req.user.companyId });
      io.to('superadmin').emit('activity:new', { companyId: req.user.companyId });
    }

    res.json(company);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/company/support-tickets - list tickets
router.get('/support-tickets', requireAnalyst, async (req, res) => {
  try {
    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const tickets = await CompanySupportTicket.find({ companyId: req.user.companyId })
      .sort({ createdAt: -1 });
    res.json(tickets);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/company/support-tickets - submit ticket
router.post('/support-tickets', requireAnalyst, async (req, res) => {
  try {
    const { subject, message, severity } = req.body;
    if (!subject || !message) {
      return res.status(400).json({ message: 'Subject and message are required' });
    }

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticketId = 'SOC-' + Math.floor(1000 + Math.random() * 9000);
    const ticket = await CompanySupportTicket.create({
      ticketId,
      companyId: req.user.companyId,
      createdBy: req.user.id,
      subject,
      description: message,
      severity: severity || 'low',
      status: 'Open',
      messages: [{
        senderId: req.user.id,
        senderName: req.user.name || req.user.email,
        senderRole: req.user.role,
        message,
      }]
    });

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:ticket_new', { ticket, companyId: req.user.companyId });
      io.to(`company:${req.user.companyId}`).emit('support:ticket_new', { ticket, companyId: req.user.companyId });
    }

    res.status(201).json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/company/support-tickets/:id/messages - send chat message
router.post('/support-tickets/:id/messages', requireAnalyst, async (req, res) => {
  try {
    const { message } = req.body;
    if (!message) return res.status(400).json({ message: 'Message is required' });

    const CompanySupportTicket = require('../models/CompanySupportTicket.model');
    const ticket = await CompanySupportTicket.findOne({
      _id: req.params.id,
      companyId: req.user.companyId
    });
    if (!ticket) return res.status(404).json({ message: 'Ticket not found' });

    ticket.messages.push({
      senderId: req.user.id,
      senderName: req.user.name || req.user.email,
      senderRole: req.user.role,
      message,
    });
    ticket.status = 'Open'; // update to open when customer messages
    await ticket.save();

    const io = req.app.get('io');
    if (io) {
      io.to('superadmin').emit('support:message_new', { ticketId: ticket.ticketId, ticket });
      io.to(`company:${req.user.companyId}`).emit('support:message_new', { ticketId: ticket.ticketId, ticket });
    }

    res.json(ticket);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


// GET /api/company/notifications
router.get('/notifications', requireAnalyst, async (req, res) => {
  try {
    const CompanyNotification = require('../models/CompanyNotification.model');
    const Company = require('../models/Company.model');

    let companyId = req.user.companyId;
    if (!companyId && (req.user.role === 'superadmin' || req.user.role === 'company_admin' || req.user.role === 'partner_admin')) {
      const firstCo = await Company.findOne().sort({ createdAt: 1 }).lean();
      if (firstCo) companyId = firstCo._id;
    }

    if (!companyId) {
      return res.json({ items: [], unread: 0 });
    }

    await CompanyNotification.updateMany(
      { companyId, title: /SOC Operational/i },
      { link: '/company-admin/soc-manager', targetUrl: '/company-admin/soc-manager' }
    ).catch(() => {});
    await CompanyNotification.updateMany(
      { companyId, title: /Endpoint Defense/i },
      { link: '/company-admin/systems', targetUrl: '/company-admin/systems' }
    ).catch(() => {});
    await CompanyNotification.updateMany(
      { companyId, title: /User Roles/i },
      { link: '/company-admin/users', targetUrl: '/company-admin/users' }
    ).catch(() => {});
    await CompanyNotification.updateMany(
      { companyId, title: /Threat Detection/i },
      { link: '/company-admin/alerts', targetUrl: '/company-admin/alerts' }
    ).catch(() => {});
    await CompanyNotification.updateMany(
      { companyId, title: /Compliance Report/i },
      { link: '/company-admin/reports', targetUrl: '/company-admin/reports' }
    ).catch(() => {});

    const notificationFilter = {
      companyId,
      ...(req.user.role === 'department_admin' ? { source: { $ne: 'superadmin' } } : {}),
    };

    let items = await CompanyNotification.find(notificationFilter)
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();

    if (items.length < 5) {
      const company = await Company.findById(companyId).lean();
      const demoNotifs = [
        {
          companyId,
          title: 'SOC Operational Security Active',
          message: 'Your organization endpoints and network traffic are actively monitored 24/7 by SOC Manager.',
          source: 'soc_manager',
          type: 'soc_status',
          link: '/company-admin/soc-manager',
          targetUrl: '/company-admin/soc-manager',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 15),
        },
        {
          companyId,
          title: 'Global Security Rules Synchronized',
          message: 'Global threat detection and compliance rules have been updated by Super Admin.',
          source: 'superadmin',
          type: 'security_policy',
          link: '/company-admin/settings',
          targetUrl: '/company-admin/settings',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 60),
        },
        {
          companyId,
          title: 'Endpoint Defense Engine Active',
          message: 'Automated EDR agent defense policies and signature databases have been updated by SOC Manager.',
          source: 'soc_manager',
          type: 'system_defense',
          link: '/company-admin/systems',
          targetUrl: '/company-admin/systems',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 180),
        },
        {
          companyId,
          title: 'User Roles & Access Audit Completed',
          message: 'Super Admin completed periodic organization user privilege and role audit.',
          source: 'superadmin',
          type: 'user_audit',
          link: '/company-admin/users',
          targetUrl: '/company-admin/users',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 360),
        },
        {
          companyId,
          title: 'Threat Detection Alert Mitigated',
          message: 'Suspicious network anomaly ticket #4820 resolved by SOC Manager operations team.',
          source: 'soc_manager',
          type: 'alert_mitigation',
          link: '/company-admin/alerts',
          targetUrl: '/company-admin/alerts',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 720),
        },
        {
          companyId,
          title: 'Monthly Security Compliance Report',
          message: 'Super Admin system generated the monthly endpoint compliance and audit executive summary.',
          source: 'superadmin',
          type: 'report_summary',
          link: '/company-admin/reports',
          targetUrl: '/company-admin/reports',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 1440),
        },
      ];

      if (company && company.partnerId) {
        demoNotifs.unshift({
          companyId,
          title: 'Partner Organization Account Linked',
          message: 'Your company profile and agent allocations are managed under Partner Admin organization.',
          source: 'partner',
          type: 'partner_notice',
          link: '/company-admin/settings',
          targetUrl: '/company-admin/settings',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 5),
        });
        demoNotifs.push({
          companyId,
          title: 'Partner License Quota Verified',
          message: 'Partner Admin allocated additional agent seats and validated billing parameters.',
          source: 'partner',
          type: 'partner_quota',
          link: '/company-admin/settings',
          targetUrl: '/company-admin/settings',
          read: false,
          createdAt: new Date(Date.now() - 1000 * 60 * 2880),
        });
      }

      const visibleDemoNotifs = req.user.role === 'department_admin'
        ? demoNotifs.filter(notif => notif.source !== 'superadmin')
        : demoNotifs;
      for (const notif of visibleDemoNotifs) {
        await CompanyNotification.updateOne(
          { companyId, title: notif.title },
          { $setOnInsert: notif },
          { upsert: true }
        ).catch(() => {});
      }

      items = await CompanyNotification.find(notificationFilter).sort({ createdAt: -1 }).limit(100).lean();
    }

    const unread = await CompanyNotification.countDocuments({ ...notificationFilter, read: false });
    res.json({ items, unread });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// PATCH /api/company/notifications/read
router.patch('/notifications/read', requireAnalyst, async (req, res) => {
  try {
    const CompanyNotification = require('../models/CompanyNotification.model');
    const requestedIds = [
      ...(Array.isArray(req.body?.ids) ? req.body.ids : []),
      ...(req.body?.notificationId ? [req.body.notificationId] : []),
    ].filter(id => mongoose.isValidObjectId(id));
    const filter = {
      companyId: req.user.companyId,
      ...(req.user.role === 'department_admin' ? { source: { $ne: 'superadmin' } } : {}),
    };
    if (requestedIds.length) filter._id = { $in: requestedIds };
    await CompanyNotification.updateMany(filter, { read: true });
    const unread = await CompanyNotification.countDocuments({
      companyId: req.user.companyId,
      read: false,
      ...(req.user.role === 'department_admin' ? { source: { $ne: 'superadmin' } } : {}),
    });
    res.json({ success: true, unread });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/company/activity-log - retrieve the caller's permitted administrative audit trail
router.get('/activity-log', requireAnalyst, async (req, res) => {
  try {
    const LoginActivity = require('../models/LoginActivity.model');
    const User = require('../models/User.model');
    const Company = require('../models/Company.model');

    let companyId = req.user.companyId;
    if (!companyId && (req.user.role === 'superadmin' || req.user.role === 'company_admin' || req.user.role === 'partner_admin')) {
      const firstCo = await Company.findOne().sort({ createdAt: 1 }).lean();
      if (firstCo) companyId = firstCo._id;
    }

    const actorId = req.user.id || req.user._id;
    const isDepartmentAdmin = req.user.role === 'department_admin';
    let activityIdentityFilter;

    if (isDepartmentAdmin) {
      const ownIdentity = [];
      if (actorId && mongoose.isValidObjectId(actorId)) ownIdentity.push({ userId: actorId });
      if (req.user.email) ownIdentity.push({ email: req.user.email });
      activityIdentityFilter = ownIdentity.length ? ownIdentity : [{ userId: null }];
    } else {
      const companyAdminUsers = await User.find({
        $or: [
          { companyId, role: 'company_admin' },
          ...(actorId && mongoose.isValidObjectId(actorId) ? [{ _id: actorId }] : []),
          ...(req.user.email ? [{ email: req.user.email }] : []),
        ]
      }).select('_id email').lean();
      const adminUserIds = companyAdminUsers.map(u => u._id);
      const adminEmails = companyAdminUsers.map(u => u.email).filter(Boolean);
      activityIdentityFilter = [
        { userId: { $in: adminUserIds } },
        { email: { $in: adminEmails } },
      ];
    }
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 60 * 60 * 1000);

    const query = {
      createdAt: { $gte: ninetyDaysAgo },
      action: {
        $nin: [
          'superadmin_company_impersonation_started',
          'superadmin_impersonation_started',
          'superadmin_company_impersonation_blocked',
          'superadmin_impersonation_blocked'
        ]
      },
      failReason: { $not: /^by:/i },
      $or: activityIdentityFilter,
    };

    if (companyId) {
      query.companyId = companyId;
    }

    let logs = await LoginActivity.find(query)
      .sort({ createdAt: -1 })
      .limit(1000)
      .lean();

    if (logs.length === 0) {
      const demoLog = {
        userId: actorId,
        companyId,
        email: req.user.email || 'admin@company.com',
        action: 'login_success',
        success: true,
        ipAddress: req.ip || '127.0.0.1',
        createdAt: new Date()
      };
      await LoginActivity.create(demoLog).catch(() => {});
      logs = await LoginActivity.find(query).sort({ createdAt: -1 }).limit(1000).lean();
    }

    res.json(logs);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
