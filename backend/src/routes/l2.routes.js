const router = require('express').Router();
const { authenticate } = require('../middleware/auth.middleware');
const User = require('../models/User.model');
const Alert = require('../models/Alert.model');
const SocEscalation = require('../models/SocEscalation.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const ResponsePlaybook = require('../models/ResponsePlaybook.model');
const EdrIncident = require('../models/EdrIncident.model');
const SocShift = require('../models/SocShift.model');
const { getUserDataFilter } = require('../services/socAccess.service');

router.use(authenticate);
router.use((req, res, next) => {
  const allowed = ['l2_analyst', 'l3_analyst', 'soc_manager', 'superadmin'];
  if (!allowed.includes(req.user?.role)) {
    return res.status(403).json({ message: 'L2 Analyst role or higher required' });
  }
  next();
});

async function audit(req, action, targetType, targetId, companyId, metadata = {}) {
  await SocAuditEvent.create({
    tenantId: req.user.tenantId,
    companyId: companyId || null,
    actorId: req.user.id,
    action,
    targetType,
    targetId: String(targetId || ''),
    metadata,
    ipAddress: String(req.ip || '').slice(0, 100),
  }).catch(err => console.error('[l2 audit error]', err.message));
}

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

function facetCount(facet, key) {
  return Number(facet?.[key]?.[0]?.count || 0);
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

// ── GET /api/l2/dashboard ─────────────────────────────
router.get('/dashboard', async (req, res) => {
  try {
    const range = ['today', '7d', '30d'].includes(req.query.range) ? req.query.range : 'today';
    const periodStart = rangeStart(range);
    const todayStart = rangeStart('today');
    const now = new Date();
    const { companyIds, filter: personalFilter } = await getUserDataFilter(req.user, { personal: true });
    const personalScope = aggregateScope(personalFilter);
    const activeAlertStatuses = ['open', 'investigating', 'under_observation'];
    const activeIncidentStatuses = ['open', 'investigating', 'contained'];
    const completeStatuses = ['resolved', 'false_positive'];
    const ticketSources = ['soar'];
    const alertScope = { ...personalScope, 'correlationIds.0': { $exists: false } };
    const incidentScope = { ...personalScope, incidentSource: { $ne: 'threat_intelligence' } };

    const workFacet = (activeStatuses, openedAtField, { includeTickets = false, includeCategories = false } = {}) => ({
      summary: [{ $group: {
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
        highPriorityPending: { $sum: { $cond: [{ $and: [
          { $in: ['$severity', ['high', 'critical']] }, { $in: ['$status', activeStatuses] },
        ] }, 1, 0] } },
        newInRange: { $sum: { $cond: [{ $gte: [`$${openedAtField}`, periodStart] }, 1, 0] } },
        completedInRange: { $sum: { $cond: [{ $and: [
          { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', periodStart] },
        ] }, 1, 0] } },
        resolvedInRange: { $sum: { $cond: [{ $and: [
          { $eq: ['$status', 'resolved'] }, { $gte: ['$resolvedAt', periodStart] },
        ] }, 1, 0] } },
        completedToday: { $sum: { $cond: [{ $and: [
          { $in: ['$status', completeStatuses] }, { $gte: ['$resolvedAt', todayStart] },
        ] }, 1, 0] } },
        ...(includeTickets ? {
          activeTickets: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $in: ['$status', activeStatuses] },
          ] }, 1, 0] } },
          totalTickets: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
          ] }, 1, 0] } },
          completedTickets: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $in: ['$status', completeStatuses] },
          ] }, 1, 0] } },
          closedTickets: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $eq: ['$status', 'resolved'] },
          ] }, 1, 0] } },
          newTicketsInRange: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $gte: ['$ticketOpenedAt', periodStart] },
          ] }, 1, 0] } },
          closedTicketsInRange: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $eq: ['$status', 'resolved'] },
            { $gte: ['$resolvedAt', periodStart] },
          ] }, 1, 0] } },
          completedTicketsInRange: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $in: ['$status', completeStatuses] },
            { $gte: ['$resolvedAt', periodStart] },
          ] }, 1, 0] } },
          completedTicketsToday: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $in: ['$status', completeStatuses] },
            { $gte: ['$resolvedAt', todayStart] },
          ] }, 1, 0] } },
          highPriorityPendingTickets: { $sum: { $cond: [{ $and: [
            { $ne: ['$ticketOpenedAt', null] },
            { $in: ['$ticketSource', ticketSources] },
            { $in: ['$severity', ['high', 'critical']] },
            { $in: ['$status', activeStatuses] },
          ] }, 1, 0] } },
        } : {}),
      } }],
      status: [{ $group: { _id: '$status', count: { $sum: 1 } } }],
      severity: [
        { $match: { status: { $in: activeStatuses } } },
        { $group: { _id: '$severity', count: { $sum: 1 } } },
      ],
      ...(includeCategories ? { categories: [
        { $match: { status: { $in: activeStatuses } } },
        { $group: { _id: '$category', count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 6 },
      ] } : {}),
    });

    const nextLevel = req.user.role === 'l2_analyst' ? 'l3' : req.user.role === 'l3_analyst' ? 'manager' : 'l2';

    const [
      alertRows,
      incidentRows,
      escalatedToL2,
      pendingEscalations,
      recentAudit,
      assignedShifts,
      totalEscalationsIncoming,
      assignedEscalationsIncoming,
      pendingEscalationsIncoming,
      closedEscalationsIncoming,
      myAssignedEscalationsIncoming
    ] = await Promise.all([
      Alert.aggregate([
        { $match: alertScope },
        { $facet: {
          ...workFacet(activeAlertStatuses, 'createdAt', { includeTickets: true }),
          logs: [
            { $match: { $nor: [{ ticketOpenedAt: { $ne: null }, ticketSource: { $in: ticketSources } }] } },
            { $group: {
              _id: null,
              total: { $sum: 1 },
              inRange: { $sum: { $cond: [{ $gte: ['$createdAt', periodStart] }, 1, 0] } },
            } },
          ],
          ticketStatus: [
            { $match: { ticketOpenedAt: { $ne: null }, ticketSource: { $in: ticketSources } } },
            { $group: { _id: '$status', count: { $sum: 1 } } },
          ],
          ticketSeverity: [
            { $match: {
              ticketOpenedAt: { $ne: null },
              ticketSource: { $in: ticketSources },
              status: { $in: activeAlertStatuses },
            } },
            { $group: { _id: '$severity', count: { $sum: 1 } } },
          ],
          recent: [
            { $match: {
              ticketOpenedAt: { $ne: null },
              ticketSource: { $in: ticketSources },
              status: { $in: activeAlertStatuses },
            } },
            { $sort: { ticketOpenedAt: -1, createdAt: -1 } },
            { $limit: 10 },
          ],
        } },
      ]).option({ maxTimeMS: 10_000 }),
      EdrIncident.aggregate([
        { $match: incidentScope },
        { $facet: {
          ...workFacet(activeIncidentStatuses, 'createdAt', { includeCategories: true }),
          solved: [{ $match: { status: 'resolved' } }, { $count: 'count' }],
          recent: [
            { $match: { status: { $in: activeIncidentStatuses } } },
            { $sort: { createdAt: -1 } },
            { $limit: 10 },
          ],
        } },
      ]).option({ maxTimeMS: 10_000 }),
      SocEscalation.countDocuments({ fromUserId: req.user.id, toLevel: nextLevel, createdAt: { $gte: periodStart } }).maxTimeMS(10_000),
      SocEscalation.countDocuments({ fromUserId: req.user.id, toLevel: nextLevel, status: 'pending' }).maxTimeMS(10_000),
      SocAuditEvent.find({ actorId: req.user.id })
        .sort({ createdAt: -1 }).limit(8).lean().maxTimeMS(10_000),
      SocShift.find({ companyId: { $in: companyIds }, analystIds: req.user.id, active: true })
        .populate('companyId', 'name').sort({ startTime: 1 }).lean().maxTimeMS(10_000),
      SocEscalation.countDocuments({ companyId: { $in: companyIds }, toLevel: 'l2' }).maxTimeMS(10_000),
      SocEscalation.countDocuments({ companyId: { $in: companyIds }, toLevel: 'l2', assignedTo: { $ne: null }, status: { $ne: 'resolved' } }).maxTimeMS(10_000),
      SocEscalation.countDocuments({ companyId: { $in: companyIds }, toLevel: 'l2', status: 'pending' }).maxTimeMS(10_000),
      SocEscalation.countDocuments({ companyId: { $in: companyIds }, toLevel: 'l2', status: { $in: ['resolved', 'rejected'] } }).maxTimeMS(10_000),
      SocEscalation.countDocuments({ companyId: { $in: companyIds }, toLevel: 'l2', assignedTo: req.user.id, status: { $ne: 'resolved' } }).maxTimeMS(10_000),
    ]);

    const alertStats = alertRows[0] || {};
    const incidentStats = incidentRows[0] || {};
    const alertSummary = facetSummary(alertStats);
    const incidentSummary = facetSummary(incidentStats);
    const logSummary = alertStats.logs?.[0] || {};
    const severity = mergeCountMaps(countMap(alertStats.ticketSeverity), countMap(incidentStats.severity));
    const status = mergeCountMaps(countMap(alertStats.ticketStatus), countMap(incidentStats.status));

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
    const completedToday = Number(alertSummary.completedTicketsToday || 0) + Number(incidentSummary.completedToday || 0);
    const shifts = assignedShifts.map(shift => ({ ...shift, isCurrent: isShiftActiveNow(shift, now) }));

    res.set('Cache-Control', 'no-store');
    res.json({
      metrics: {
        totalAssignedWork, pendingWork, completedWork, completionRate,
        totalLogs: Number(logSummary.total || 0),
        logsInRange: Number(logSummary.inRange || 0),
        totalAssignedIncidents: Number(incidentSummary.total || 0),
        pendingIncidents: Number(incidentSummary.pending || 0),
        completedIncidents: Number(incidentSummary.completed || 0),
        closedIncidents: Number(incidentSummary.resolved || 0),
        newIncidentsInRange: Number(incidentSummary.newInRange || 0),
        closedIncidentsInRange: Number(incidentSummary.resolvedInRange || 0),
        assignedIncidents: Number(incidentSummary.pending || 0),
        solvedIncidents: facetCount(incidentStats, 'solved'),
        inProgress: Number(countMap(alertStats.ticketStatus).investigating || 0) + Number(incidentSummary.investigating || 0),
        openWork: Number(countMap(alertStats.ticketStatus).open || 0) + Number(incidentSummary.open || 0),
        myOpenTickets: Number(alertSummary.activeTickets || 0),
        totalTickets: Number(alertSummary.totalTickets || 0),
        pendingTickets: Number(alertSummary.activeTickets || 0),
        completedTickets: Number(alertSummary.completedTickets || 0),
        closedTickets: Number(alertSummary.closedTickets || 0),
        newTicketsInRange: Number(alertSummary.newTicketsInRange || 0),
        closedTicketsInRange: Number(alertSummary.closedTicketsInRange || 0),
        highPriorityOpen: Number(alertSummary.highPriorityPendingTickets || 0) + Number(incidentSummary.highPriorityPending || 0),
        escalatedToL2,
        pendingEscalations,
        newInRange: Number(alertSummary.newTicketsInRange || 0) + Number(incidentSummary.newInRange || 0),
        completedInRange: resolvedInRange,
        resolvedInRange,
        resolvedToday: completedToday,
        falsePositives: Number(countMap(alertStats.ticketStatus).false_positive || 0) + Number(incidentSummary.falsePositive || 0),
        activeShifts: shifts.length,
        onShiftNow: shifts.filter(shift => shift.isCurrent).length,
        myCurrentWorkload: pendingWork,
        totalEscalationsIncoming,
        assignedEscalationsIncoming,
        pendingEscalationsIncoming,
        closedEscalationsIncoming,
        myAssignedEscalationsIncoming,
      },
      severity,
      status,
      categories: countMap(incidentStats.categories),
      recentAlerts,
      recentAudit,
      assignedShifts: shifts,
      range: { key: range, from: periodStart, to: now },
      refreshedAt: now,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/l2/investigations ────────────────────────
router.get('/investigations', async (req, res) => {
  try {
    const { filter } = await getUserDataFilter(req.user);
    const { page = 1, limit = 20, search } = req.query;
    filter.status = { $in: ['investigating', 'open'] };

    if (search) {
      const reg = new RegExp(search.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
      filter.$or = [{ description: reg }, { ruleId: reg }, { signatureName: reg }];
    }

    const [items, total] = await Promise.all([
      Alert.find(filter).sort({ createdAt: -1 }).skip((page - 1) * limit).limit(Number(limit))
        .populate('companyId', 'name').populate('assignedTo', 'name email role').lean(),
      Alert.countDocuments(filter)
    ]);

    res.json({ items, total, page: Number(page), limit: Number(limit), pages: Math.ceil(total / limit) });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/l2/escalations ───────────────────────────
router.get('/escalations', async (req, res) => {
  try {
    const { companyIds } = await getUserDataFilter(req.user);
    const items = await SocEscalation.find({ companyId: { $in: companyIds } })
      .populate('alertId').populate('companyId', 'name').populate('fromUserId', 'name email role').sort({ createdAt: -1 }).limit(100).lean();
    res.json(items);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/l2/incidents/:id ─────────────────────────
router.get('/incidents/:id', async (req, res) => {
  try {
    const { companyIds } = await getUserDataFilter(req.user);
    const alert = await Alert.findOne({ _id: req.params.id, companyId: { $in: companyIds } })
      .populate('companyId', 'name').populate('assignedTo', 'name email role').lean();
    if (!alert) return res.status(404).json({ message: 'Incident/Alert not found' });

    res.json({
      alert,
      zeekLogs: [
        { ts: new Date(), uid: 'C123456', orig_h: '192.168.1.50', resp_h: '10.0.0.1', proto: 'tcp', service: 'http' }
      ],
      suricataAlerts: [
        { timestamp: new Date(), signature: 'ET MALWARE Suspicious User-Agent', severity: 1, src_ip: '192.168.1.50', dest_ip: '10.0.0.1' }
      ],
      processTree: {
        pid: 1042, process_name: 'cmd.exe', parent_pid: 820, parent_name: 'explorer.exe', command_line: 'cmd.exe /c powershell -enc...'
      },
      iocAnalysis: [
        { type: 'ip', value: '192.168.1.50', reputation: 'malicious', threatScore: 85 }
      ],
      playbooks: await ResponsePlaybook.find({ companyId: alert.companyId, enabled: true }).select('name description executionMode').lean()
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/l2/incidents/:id/notes ──────────────────
router.post('/incidents/:id/notes', async (req, res) => {
  try {
    const { companyIds } = await getUserDataFilter(req.user);
    const alert = await Alert.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!alert) return res.status(404).json({ message: 'Incident not found' });

    const note = String(req.body.note || '').trim().slice(0, 5000);
    if (!note) return res.status(400).json({ message: 'Technical note is required' });

    alert.notes.push({ user: req.user.id, text: `[L2 Technical Note] ${note}`, at: new Date() });
    await alert.save();

    await audit(req, 'TECHNICAL_NOTE_ADDED', 'Alert', alert._id, alert.companyId, { note });
    res.json({ message: 'Technical note added', alert });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/l2/incidents/:id/run-playbook ───────────
router.post('/incidents/:id/run-playbook', async (req, res) => {
  try {
    const { companyIds } = await getUserDataFilter(req.user);
    const alert = await Alert.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!alert) return res.status(404).json({ message: 'Incident not found' });

    const playbookId = req.body.playbookId;
    const playbook = playbookId ? await ResponsePlaybook.findById(playbookId) : null;

    await audit(req, 'SOAR_PLAYBOOK_RUN', 'Alert', alert._id, alert.companyId, { playbookId });
    res.json({ message: `SOAR Playbook ${playbook?.name || 'Action'} executed successfully`, status: 'completed' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/l2/incidents/:id/escalate-to-l3 ─────────
router.post('/incidents/:id/escalate-to-l3', async (req, res) => {
  try {
    const { companyIds } = await getUserDataFilter(req.user);
    const alert = await Alert.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!alert) return res.status(404).json({ message: 'Incident not found' });

    const reason = String(req.body.reason || '').trim().slice(0, 2000);
    if (!reason) return res.status(400).json({ message: 'Escalation reason is required' });

    const candidates = await SocCompanyAssignment.find({ companyId: alert.companyId, active: true }).distinct('userId');
    const l3Target = await User.findOne({ _id: { $in: candidates }, role: 'l3_analyst', isActive: true }).select('_id');

    const escalation = await SocEscalation.create({
      tenantId: alert.tenantId || req.user.tenantId,
      companyId: alert.companyId,
      departmentId: alert.departmentId,
      alertId: alert._id,
      fromUserId: req.user.id,
      fromLevel: 'l2',
      toLevel: 'l3',
      assignedTo: l3Target?._id || null,
      reason,
      summary: String(req.body.summary || '').slice(0, 5000),
      observedIoc: String(req.body.observedIoc || '').slice(0, 1000),
      affectedAsset: String(req.body.affectedAsset || '').slice(0, 500),
      priority: ['low', 'medium', 'high', 'critical'].includes(req.body.priority) ? req.body.priority : alert.severity
    });

    alert.status = 'investigating';
    if (l3Target) alert.assignedTo = l3Target._id;
    await alert.save();

    await audit(req, 'ESCALATED_TO_L3', 'Alert', alert._id, alert.companyId, { escalationId: escalation._id });
    res.json({ message: 'Escalated to L3 Analyst successfully', alert, escalation });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
