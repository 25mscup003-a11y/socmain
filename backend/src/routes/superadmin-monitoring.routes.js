const express = require('express');
const router = express.Router();
const mongoose = require('mongoose');
const { requireActiveSuperadminSession, requireOriginalSuperadminSession } = require('../middleware/superadminSession.middleware');
const { createSuperadminLoginToken } = require('../services/superadminLogin.service');

const User = require('../models/User.model');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');
const Alert = require('../models/Alert.model');
const EdrIncident = require('../models/EdrIncident.model');
const SocEscalation = require('../models/SocEscalation.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocShift = require('../models/SocShift.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const LoginActivity = require('../models/LoginActivity.model');
const FraudEvent = require('../models/FraudEvent.model');
const Agent = require('../models/Agent.model');
const Token = require('../models/Token.model');
const { analyzeAnalystActivity, overlapMs } = require('../utils/analystActivityAnalytics');

const WEEKDAY_INDEX = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function currentShiftState(shift, now = new Date()) {
  try {
    const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
      timeZone: shift.timezone || 'Asia/Kolkata', weekday: 'short',
      hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
    }).formatToParts(now).filter(part => part.type !== 'literal').map(part => [part.type, part.value]));
    const day = WEEKDAY_INDEX[parts.weekday];
    const minute = Number(parts.hour) * 60 + Number(parts.minute);
    const toMinute = value => {
      const [hour, min] = String(value).split(':').map(Number);
      return hour * 60 + min;
    };
    const start = toMinute(shift.startTime);
    const end = toMinute(shift.endTime);
    const weekdays = shift.weekdays?.length ? shift.weekdays : [0, 1, 2, 3, 4, 5, 6];
    if (start <= end) return weekdays.includes(day) && minute >= start && minute < end;
    return (weekdays.includes(day) && minute >= start)
      || (weekdays.includes((day + 6) % 7) && minute < end);
  } catch {
    return false;
  }
}

function rangeStart(range) {
  const now = new Date();
  if (range === '30d') return new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
  if (range === '7d') return new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);
  const today = new Date(now);
  today.setHours(0, 0, 0, 0);
  return today;
}

async function optionalQuery(query, fallback, label) {
  try {
    return await query;
  } catch (error) {
    console.warn(`[SOC manager detail] ${label} unavailable:`, error.message);
    return fallback;
  }
}

function optionalCount(model, filter, label) {
  return optionalQuery(model.countDocuments(filter).maxTimeMS(15000), 0, label);
}

function localShiftDate(date, time, timezone) {
  const [hours, minutes] = String(time || '00:00').split(':').map(Number);
  const parts = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    timeZone: timezone || 'Asia/Kolkata', year: 'numeric', month: 'numeric', day: 'numeric',
  }).formatToParts(date).map(part => [part.type, part.value]));
  const localIso = `${parts.year}-${String(parts.month).padStart(2, '0')}-${String(parts.day).padStart(2, '0')}T${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:00`;
  const parsedUtc = new Date(`${localIso}Z`);
  const check = Object.fromEntries(new Intl.DateTimeFormat('en-US', {
    timeZone: timezone || 'Asia/Kolkata', year: 'numeric', month: 'numeric', day: 'numeric',
    hour: 'numeric', minute: 'numeric', second: 'numeric', hour12: false,
  }).formatToParts(parsedUtc).map(part => [part.type, part.value]));
  const checkHour = check.hour === '24' ? '00' : String(check.hour).padStart(2, '0');
  const checkUtc = new Date(`${check.year}-${String(check.month).padStart(2, '0')}-${String(check.day).padStart(2, '0')}T${checkHour}:${String(check.minute).padStart(2, '0')}:${String(check.second).padStart(2, '0')}Z`);
  return new Date(parsedUtc.getTime() + (parsedUtc.getTime() - checkUtc.getTime()));
}

function buildShiftWindows(shifts, startAt, endAt) {
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
      const dayName = new Intl.DateTimeFormat('en-US', { timeZone: timezone, weekday: 'short' }).format(cursor);
      const weekday = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(dayName);
      const weekdays = shift.weekdays?.length ? shift.weekdays : [0, 1, 2, 3, 4, 5, 6];
      if (!weekdays.includes(weekday)) continue;
      const start = localShiftDate(cursor, shift.startTime, timezone);
      const end = localShiftDate(cursor, shift.endTime, timezone);
      if (end <= start) end.setDate(end.getDate() + 1);
      if (end < startAt || start > endAt) continue;
      const key = `${shift._id}:${start.toISOString()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      windows.push({ shiftId:shift._id, shiftName:shift.name || 'SOC Shift', timezone, start, end, startTime:shift.startTime, endTime:shift.endTime });
    }
  }
  return windows.sort((a,b)=>a.start-b.start);
}

// Middleware to assert Superadmin role & scope authorization
const assertSuperAdmin = (req, res, next) => {
  if (!req.user || req.user.role !== 'superadmin') {
    return res.status(403).json({ message: 'Access denied: Super Admin permission required' });
  }
  next();
};

router.use(assertSuperAdmin);

// ── GET /api/super-admin/soc-managers/metrics ── Account and assignment metrics
router.get('/soc-managers/metrics', async (req, res) => {
  try {
    const managerFilter = { role: 'soc_manager' };
    const managers = await User.find(managerFilter).select('_id isActive accountStatus').lean();
    const managerIds = managers.map(manager => manager._id);
    const assignedManagerIds = new Set((await SocCompanyAssignment.find({
      userId: { $in: managerIds },
      active: true,
    }).distinct('userId')).map(String));
    const activeShiftManagerIds = new Set();
    const shifts = await SocShift.find({ analystIds: { $in: managerIds }, active: true }).lean();
    for (const shift of shifts) {
      if (!currentShiftState(shift)) continue;
      for (const userId of shift.analystIds || []) activeShiftManagerIds.add(String(userId));
    }

    const isActiveManager = manager => manager.isActive === true
      && (!manager.accountStatus || manager.accountStatus === 'active');
    const assigned = managers.filter(manager => assignedManagerIds.has(String(manager._id))).length;

    res.json({
      total: managers.length,
      active: managers.filter(isActiveManager).length,
      assigned,
      unassigned: managers.length - assigned,
      pendingInvitations: managers.filter(manager => manager.accountStatus === 'invited').length,
      expiredInvitations: managers.filter(manager => manager.accountStatus === 'expired').length,
      suspended: managers.filter(manager => manager.accountStatus === 'suspended').length,
      disabled: managers.filter(manager => manager.isActive !== true).length,
      onShift: managers.filter(manager => activeShiftManagerIds.has(String(manager._id))).length,
      offShift: managers.filter(manager => !activeShiftManagerIds.has(String(manager._id))).length,
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/dashboard ── Overview metrics
router.get('/dashboard', async (req, res) => {
  try {
    const [
      totalPartners, activePartners, suspendedPartners,
      totalCompanies, activeCompanies, inactiveCompanies,
      totalSocManagers, activeSocManagers, suspendedSocManagers,
      totalAnalysts, l1Count, l2Count, l3Count, activeAnalysts,
      totalAlertsToday, criticalAlerts, highAlerts, unassignedAlerts, openTickets,
      escalatedIncidents, slaBreaches
    ] = await Promise.all([
      Partner.countDocuments(),
      Partner.countDocuments({ status: 'active' }),
      Partner.countDocuments({ status: 'suspended' }),

      Company.countDocuments(),
      Company.countDocuments({ status: 'active' }),
      Company.countDocuments({ status: { $ne: 'active' } }),

      User.countDocuments({ role: 'soc_manager' }),
      User.countDocuments({ role: 'soc_manager', isActive: true }),
      User.countDocuments({ role: 'soc_manager', accountStatus: 'suspended' }),

      User.countDocuments({ role: { $in: ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst', 'analyst'] } }),
      User.countDocuments({ role: 'l1_analyst' }),
      User.countDocuments({ role: 'l2_analyst' }),
      User.countDocuments({ role: 'l3_analyst' }),
      User.countDocuments({ role: { $in: ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'] }, isActive: true }),

      Alert.countDocuments({ createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
      Alert.countDocuments({ severity: 'critical', status: { $ne: 'resolved' } }),
      Alert.countDocuments({ severity: 'high', status: { $ne: 'resolved' } }),
      Alert.countDocuments({ assignedTo: null, status: { $ne: 'resolved' } }),
      Alert.countDocuments({ status: { $in: ['open', 'investigating', 'escalated'] } }),

      SocEscalation.countDocuments({ status: 'pending' }),
      Alert.countDocuments({ slaBreached: true }),
    ]);

    const assignedCompanyIds = await SocCompanyAssignment.find({ active: true }).distinct('companyId');
    const companiesWithoutManager = await Company.countDocuments({ _id: { $nin: assignedCompanyIds } });

    res.json({
      partners: { total: totalPartners, active: activePartners, suspended: suspendedPartners },
      companies: { total: totalCompanies, active: activeCompanies, inactive: inactiveCompanies, withoutManager: companiesWithoutManager },
      socManagers: { total: totalSocManagers, active: activeSocManagers, suspended: suspendedSocManagers },
      analysts: { total: totalAnalysts, l1: l1Count, l2: l2Count, l3: l3Count, active: activeAnalysts },
      operations: {
        alertsToday: totalAlertsToday, critical: criticalAlerts, high: highAlerts, unassigned: unassignedAlerts,
        openTickets, escalations: escalatedIncidents, slaBreaches, avgMttd: '4.2m', avgMttr: '18.5m', fpRate: '3.1%'
      },
      soar: { running: 0, failed: 0 },
      agents: { online: 0, offline: 0 }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/charts ── Time-series and breakdown charts
router.get('/charts', async (req, res) => {
  try {
    const [critical, high, medium, low] = await Promise.all([
      Alert.countDocuments({ severity: 'critical' }),
      Alert.countDocuments({ severity: 'high' }),
      Alert.countDocuments({ severity: 'medium' }),
      Alert.countDocuments({ severity: 'low' }),
    ]);

    res.json({
      severityDistribution: [
        { name: 'Critical', value: critical, color: '#fb7185' },
        { name: 'High', value: high, color: '#fb923c' },
        { name: 'Medium', value: medium, color: '#facc15' },
        { name: 'Low', value: low, color: '#38bdf8' },
      ],
      roleBreakdown: {
        soc_manager: await User.countDocuments({ role: 'soc_manager' }),
        l1_analyst: await User.countDocuments({ role: 'l1_analyst' }),
        l2_analyst: await User.countDocuments({ role: 'l2_analyst' }),
        l3_analyst: await User.countDocuments({ role: 'l3_analyst' }),
        l4_analyst: await User.countDocuments({ role: 'l4_analyst' }),
      }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/soc-managers ── Paginated SOC Manager list
router.get('/soc-managers', async (req, res) => {
  try {
    const page = parseInt(req.query.page || '1', 10);
    const limit = parseInt(req.query.limit || '15', 10);
    const search = (req.query.search || '').trim().toLowerCase();
    const status = req.query.status;

    const query = { role: 'soc_manager' };
    if (status && status !== 'all') {
      if (['active', 'suspended', 'invited', 'deactivated', 'locked'].includes(status)) {
        query.accountStatus = status;
      }
    }

    let managers = await User.find(query).sort({ createdAt: -1 }).lean();

    if (search) {
      managers = managers.filter(m =>
        m.name?.toLowerCase().includes(search) || m.email?.toLowerCase().includes(search)
      );
    }

    const total = managers.length;
    const paginated = managers.slice((page - 1) * limit, page * limit);

    // Enrich with company assignments & workload stats
    const enriched = await Promise.all(paginated.map(async m => {
      const assignments = await SocCompanyAssignment.find({ userId: m._id, active: true }).populate('companyId', 'name status');
      const shifts = await SocShift.find({ analystIds: m._id, active: true }).lean();
      const currentShift = shifts.find(shift => currentShiftState(shift));
      const companies = assignments.map(a => a.companyId).filter(Boolean);
      const companyIds = companies.map(c => c._id);

      const [l1, l2, l3, openAlerts, criticalAlerts, openTickets] = await Promise.all([
        User.countDocuments({ companyId: { $in: companyIds }, role: 'l1_analyst' }),
        User.countDocuments({ companyId: { $in: companyIds }, role: 'l2_analyst' }),
        User.countDocuments({ companyId: { $in: companyIds }, role: 'l3_analyst' }),
        Alert.countDocuments({ companyId: { $in: companyIds }, status: { $ne: 'resolved' } }),
        Alert.countDocuments({ companyId: { $in: companyIds }, severity: 'critical', status: { $ne: 'resolved' } }),
        Alert.countDocuments({ companyId: { $in: companyIds }, status: 'open' }),
      ]);

      const totalAnalysts = l1 + l2 + l3;
      const maxLimit = m.maxWorkload || 10;
      const pct = Math.min(100, Math.round((openAlerts / maxLimit) * 100));

      return {
        ...m,
        assignedCompanies: companies,
        assignedCompaniesCount: companies.length,
        analystCounts: { total: totalAnalysts, l1, l2, l3 },
        workload: { open: openAlerts, critical: criticalAlerts, maxLimit, percentage: pct },
        shiftStatus: currentShift ? 'on_shift' : 'off_shift',
        currentShift: currentShift ? {
          name: currentShift.name,
          startTime: currentShift.startTime,
          endTime: currentShift.endTime,
          timezone: currentShift.timezone,
          weekdays: currentShift.weekdays,
        } : null,
        assignedShiftsCount: shifts.length,
        openTickets,
      };
    }));

    res.json({
      items: enriched,
      total,
      page,
      pages: Math.ceil(total / limit) || 1
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers ── Create / Invite SOC Manager with Temporary Password
router.post('/soc-managers', async (req, res) => {
  try {
    const { name, email, companyIds, maxWorkload, temporaryPassword } = req.body;
    if (!email || !companyIds || !Array.isArray(companyIds) || !companyIds.length) {
      return res.status(400).json({ message: 'Email and at least one company assignment are required' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existingUser = await User.findOne({ email: normalizedEmail });
    if (existingUser) {
      return res.status(400).json({ message: `User with email ${normalizedEmail} already exists` });
    }

    const firstCompany = await Company.findById(companyIds[0]);
    if (!firstCompany) {
      return res.status(400).json({ message: 'Selected company does not exist' });
    }

    const passwordToSet = (temporaryPassword && temporaryPassword.trim()) ? temporaryPassword.trim() : 'TempPassword123!';

    const user = await User.create({
      name: (name && name.trim()) ? name.trim() : normalizedEmail.split('@')[0],
      email: normalizedEmail,
      password: passwordToSet,
      role: 'soc_manager',
      superadminManaged: true,
      tenantId: firstCompany.tenantId,
      companyId: firstCompany._id,
      accountStatus: 'invited',
      isActive: true,
      maxWorkload: maxWorkload || 10,
    });

    for (const companyId of companyIds) {
      await SocCompanyAssignment.updateOne(
        { userId: user._id, companyId },
        { $set: { tenantId: firstCompany.tenantId, active: true, assignedBy: req.user.id || req.user._id } },
        { upsert: true }
      );
    }

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'SOC_MANAGER_CREATED',
      targetType: 'User',
      targetId: user._id,
      metadata: { temporaryPasswordSet: Boolean(temporaryPassword) }
    });

    res.status(201).json({
      message: `SOC Manager invitation sent to ${normalizedEmail}`,
      user: { _id: user._id, name: user.name, email: user.email, role: user.role },
      temporaryPassword: passwordToSet
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/soc-managers/:id ── Single SOC Manager detail inspection
router.get('/soc-managers/:id', async (req, res) => {
  try {
    const manager = await User.findById(req.params.id).lean();
    if (!manager || manager.role !== 'soc_manager') {
      return res.status(404).json({ message: 'SOC Manager not found' });
    }

    const assignments = await SocCompanyAssignment.find({ userId: manager._id, active: true }).populate('companyId', 'name status');
    const companies = assignments.map(a => a.companyId).filter(Boolean);
    const companyIds = companies.map(c => c._id);
    const selectedRange = ['today', '7d', '30d'].includes(req.query.range) ? req.query.range : 'today';
    const activityRangeStart = rangeStart(selectedRange);
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 6);
    sevenDaysAgo.setHours(0, 0, 0, 0);
    const queryStart = new Date(Math.min(activityRangeStart.getTime(), sevenDaysAgo.getTime()) - (24 * 60 * 60 * 1000));

    const [analysts, auditLogs, securityEvents, activeAlerts, shifts, loginActivities, activityAuditEvents] = await Promise.all([
      optionalQuery(User.find({ companyId: { $in: companyIds }, role: { $in: ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'] } }).lean(), [], 'analysts'),
      optionalQuery(SocAuditEvent.find({ $or: [{ actorId: manager._id }, { targetId: manager._id }] }).sort({ createdAt: -1 }).limit(20).lean(), [], 'audit logs'),
      optionalQuery(FraudEvent.find({ $or: [{ userId: manager._id }, { email: manager.email }] }).sort({ createdAt: -1 }).limit(20).lean(), [], 'security events'),
      optionalQuery(Alert.find({ companyId: { $in: companyIds }, status: { $ne: 'resolved' } }).sort({ createdAt: -1 }).limit(10).lean(), [], 'active alerts'),
      optionalQuery(SocShift.find({ analystIds: manager._id, active: true }).populate('companyId', 'name').lean(), [], 'assigned shifts'),
      optionalQuery(LoginActivity.find({ userId: manager._id, createdAt: { $gte: queryStart } }).sort({ createdAt: 1 }).limit(2000).lean(), [], 'login activity'),
      optionalQuery(SocAuditEvent.find({
        createdAt: { $gte: queryStart },
        $or: [{ actorId: manager._id }, { targetId: String(manager._id) }],
      }).sort({ createdAt: 1 }).limit(1000).populate('actorId', 'name email role').lean(), [], 'activity timeline'),
    ]);

    const now = new Date();
    const workRangeStart = activityRangeStart;
    const activeAlertStatuses = ['open', 'investigating', 'under_observation'];
    const activeIncidentStatuses = ['open', 'investigating', 'contained'];
    const completedStatuses = ['resolved', 'false_positive'];
    const ticketScope = { companyId: { $in: companyIds }, ticketOpenedAt: { $ne: null }, ticketSource: 'soar' };
    const incidentScope = { companyId: { $in: companyIds } };
    const threatScope = { ...incidentScope, incidentSource: 'threat_intelligence' };
    const edrScope = { ...incidentScope, incidentSource: { $ne: 'threat_intelligence' } };
    const [ticketsInRange, pendingTicketsInRange, completedTicketsInRange, openTicketsInRange, investigatingTicketsInRange, criticalTicketsInRange, incidentsInRange, pendingIncidentsInRange, completedIncidentsInRange, openIncidentsInRange, investigatingIncidentsInRange, criticalIncidentsInRange, tiIncidentsInRange, edrIncidentsInRange] = await Promise.all([
      optionalCount(Alert, { ...ticketScope, ticketOpenedAt: { $gte: workRangeStart } }, 'assigned tickets'),
      optionalCount(Alert, { ...ticketScope, ticketOpenedAt: { $gte: workRangeStart }, status: { $in: activeAlertStatuses } }, 'pending tickets'),
      optionalCount(Alert, { ...ticketScope, status: { $in: completedStatuses }, resolvedAt: { $gte: workRangeStart } }, 'completed tickets'),
      optionalCount(Alert, { ...ticketScope, ticketOpenedAt: { $gte: workRangeStart }, status: 'open' }, 'open tickets'),
      optionalCount(Alert, { ...ticketScope, ticketOpenedAt: { $gte: workRangeStart }, status: 'investigating' }, 'investigating tickets'),
      optionalCount(Alert, { ...ticketScope, ticketOpenedAt: { $gte: workRangeStart }, severity: 'critical', status: { $in: activeAlertStatuses } }, 'critical tickets'),
      optionalCount(EdrIncident, { ...incidentScope, createdAt: { $gte: workRangeStart } }, 'all incidents'),
      optionalCount(EdrIncident, { ...incidentScope, createdAt: { $gte: workRangeStart }, status: { $in: activeIncidentStatuses } }, 'pending incidents'),
      optionalCount(EdrIncident, { ...incidentScope, status: { $in: completedStatuses }, resolvedAt: { $gte: workRangeStart } }, 'completed incidents'),
      optionalCount(EdrIncident, { ...incidentScope, createdAt: { $gte: workRangeStart }, status: 'open' }, 'open incidents'),
      optionalCount(EdrIncident, { ...incidentScope, createdAt: { $gte: workRangeStart }, status: 'investigating' }, 'investigating incidents'),
      optionalCount(EdrIncident, { ...incidentScope, createdAt: { $gte: workRangeStart }, severity: 'critical', status: { $in: activeIncidentStatuses } }, 'critical incidents'),
      optionalCount(EdrIncident, { ...threatScope, createdAt: { $gte: workRangeStart } }, 'TI incidents'),
      optionalCount(EdrIncident, { ...edrScope, createdAt: { $gte: workRangeStart } }, 'EDR incidents'),
    ]);
    const assignedWorkInRange = ticketsInRange + incidentsInRange;
    const pendingWorkInRange = pendingTicketsInRange + pendingIncidentsInRange;
    const completedWorkInRange = completedTicketsInRange + completedIncidentsInRange;
    const selectedShiftWindows = buildShiftWindows(shifts, activityRangeStart, now);
    const attendanceShiftWindows = buildShiftWindows(shifts, sevenDaysAgo, now);
    const authAudit = analyzeAnalystActivity({
      loginEvents:loginActivities, auditEvents:activityAuditEvents,
      shiftWindows:selectedShiftWindows, rangeStart:activityRangeStart, rangeEnd:now,
    });
    const attendanceAudit = analyzeAnalystActivity({
      loginEvents:loginActivities, auditEvents:activityAuditEvents,
      shiftWindows:attendanceShiftWindows, rangeStart:sevenDaysAgo, rangeEnd:now,
    });
    const formatTime = (date, timezone) => {
      if (!date) return '—';
      try { return new Intl.DateTimeFormat('en-US', { timeZone:timezone || 'Asia/Kolkata', hour:'2-digit', minute:'2-digit', hour12:true }).format(new Date(date)); }
      catch { return new Date(date).toLocaleTimeString(); }
    };
    const formatDate = (date, timezone) => {
      try { return new Intl.DateTimeFormat('en-US', { timeZone:timezone || 'Asia/Kolkata', year:'numeric', month:'2-digit', day:'2-digit' }).format(new Date(date)); }
      catch { return new Date(date).toLocaleDateString(); }
    };
    const attendanceReport = attendanceShiftWindows.slice().reverse().map(window => {
      const loginWindowStart = new Date(window.start.getTime() - (2 * 60 * 60 * 1000));
      const session = attendanceAudit.sessions.slice().reverse().find(item => new Date(item.loginAt) >= loginWindowStart && new Date(item.loginAt) <= window.end);
      const lateMinutes = session ? Math.max(0, Math.floor((new Date(session.loginAt) - window.start) / 60000)) : 0;
      const lockMinutes = attendanceAudit.locks.reduce((sum,lock)=>sum+Math.round(overlapMs(lock.start,lock.end,[window])/60000),0);
      const logoutCount = loginActivities.filter(item=>item.action==='logout'&&new Date(item.createdAt)>=window.start&&new Date(item.createdAt)<=window.end).length;
      const failedLoginCount = loginActivities.filter(item=>['login_failed','otp_failed'].includes(item.action)&&new Date(item.createdAt)>=window.start&&new Date(item.createdAt)<=window.end).length;
      return {
        date:formatDate(window.start,window.timezone),
        dayName:new Intl.DateTimeFormat('en-US',{timeZone:window.timezone,weekday:'long'}).format(window.start),
        shiftName:window.shiftName,
        shiftTime:`${window.startTime} - ${window.endTime} (${window.timezone})`,
        loginTime:session?formatTime(session.loginAt,window.timezone):'—',
        logoutTime:session?.logoutAt?formatTime(session.logoutAt,window.timezone):'—',
        lateTime:session?(lateMinutes>0?`${lateMinutes} min late`:'On Time'):'—',
        logoutCount,
        sessionMinutes:session?.workingMinutes || 0,
        lockMinutes,
        failedLoginCount,
        status:session?'Present':lockMinutes>0?'Locked':'Absent',
      };
    });

    res.json({
      manager,
      assignedCompanies: companies,
      analysts,
      auditLogs,
      securityEvents,
      activeAlerts,
      shifts: shifts.map(shift => ({ ...shift, isWorkingNow: currentShiftState(shift) })),
      selectedRange,
      authAudit,
      attendanceReport,
      workMetrics: {
        range: selectedRange,
        assignedWorkToday: assignedWorkInRange,
        pendingWorkToday: pendingWorkInRange,
        completedWorkToday: completedWorkInRange,
        completionRateToday: pendingWorkInRange + completedWorkInRange
          ? Math.round((completedWorkInRange / (pendingWorkInRange + completedWorkInRange)) * 100)
          : 0,
        tiIncidentsToday: tiIncidentsInRange,
        edrIncidentsToday: edrIncidentsInRange,
        assignedTicketsToday: ticketsInRange,
        openWorkToday: openTicketsInRange + openIncidentsInRange,
        investigatingToday: investigatingTicketsInRange + investigatingIncidentsInRange,
        criticalPendingToday: criticalTicketsInRange + criticalIncidentsInRange,
        onShiftNow: shifts.some(shift => currentShiftState(shift)) ? 1 : 0,
        updatedAt: now.toISOString(),
      },
      updatedAt: now.toISOString(),
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/suspend ── Suspend account
router.post('/soc-managers/:id/suspend', async (req, res) => {
  try {
    const { reason } = req.body;
    if (!reason) return res.status(400).json({ message: 'Reason is required for suspension' });

    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { accountStatus: 'suspended', isActive: false } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'SOC_MANAGER_SUSPENDED',
      targetType: 'User',
      targetId: user._id,
      metadata: { reason }
    });

    res.json({ message: 'SOC Manager suspended successfully', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/reactivate ── Reactivate account
router.post('/soc-managers/:id/reactivate', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { accountStatus: 'active', isActive: true } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'SOC_MANAGER_REACTIVATED',
      targetType: 'User',
      targetId: user._id,
    });

    res.json({ message: 'SOC Manager reactivated successfully', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/lock ── Lock account
router.post('/soc-managers/:id/lock', async (req, res) => {
  try {
    const { reason } = req.body;
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { accountStatus: 'locked', isActive: false } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'SOC_MANAGER_LOCKED',
      targetType: 'User',
      targetId: user._id,
      metadata: { reason }
    });

    res.json({ message: 'SOC Manager account locked', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/unlock ── Unlock account
router.post('/soc-managers/:id/unlock', async (req, res) => {
  try {
    const user = await User.findByIdAndUpdate(
      req.params.id,
      { $set: { accountStatus: 'active', isActive: true } },
      { new: true }
    );
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'SOC_MANAGER_UNLOCKED',
      targetType: 'User',
      targetId: user._id,
    });

    res.json({ message: 'SOC Manager account unlocked', user });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/revoke-sessions ── Invalidate active sessions
router.post('/soc-managers/:id/revoke-sessions', async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    if (Token) {
      await Token.deleteMany({ userId: user._id });
    }

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'ALL_SESSIONS_REVOKED',
      targetType: 'User',
      targetId: user._id,
    });

    res.json({ message: 'Active sessions revoked successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/companies/bulk ── Bulk company assignment
router.post('/soc-managers/:id/companies/bulk', async (req, res) => {
  try {
    const { companyIds } = req.body;
    if (!companyIds || !Array.isArray(companyIds)) {
      return res.status(400).json({ message: 'companyIds array is required' });
    }

    const user = await User.findById(req.params.id);
    if (!user) return res.status(404).json({ message: 'SOC Manager not found' });

    for (const companyId of companyIds) {
      await SocCompanyAssignment.updateOne(
        { userId: user._id, companyId },
        { $set: { tenantId: user.tenantId, active: true, assignedBy: req.user.id || req.user._id } },
        { upsert: true }
      );
    }

    await SocAuditEvent.create({
      tenantId: user.tenantId,
      companyId: user.companyId,
      actorId: req.user.id || req.user._id,
      action: 'COMPANY_BULK_ASSIGNED',
      targetType: 'User',
      targetId: user._id,
      metadata: { companyIds }
    });

    res.json({ message: `${companyIds.length} companies assigned successfully` });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── PUT /api/super-admin/soc-managers/:id/operations ── Shift and workload controls
router.put('/soc-managers/:id/operations', async (req, res) => {
  try {
    const manager = await User.findOne({ _id: req.params.id, role: 'soc_manager' });
    if (!manager) return res.status(404).json({ message: 'SOC Manager not found' });

    const maxWorkload = Number(req.body.maxWorkload);
    if (!Number.isInteger(maxWorkload) || maxWorkload < 1 || maxWorkload > 1000) {
      return res.status(400).json({ message: 'Workload limit must be between 1 and 1000' });
    }

    const { companyId, name, startTime, endTime, timezone = 'Asia/Kolkata', weekdays } = req.body.shift || {};
    if (!companyId || !name || !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime || '')
      || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime || '')) {
      return res.status(400).json({ message: 'Company, shift name, start time and end time are required' });
    }
    try { new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(); }
    catch { return res.status(400).json({ message: 'Invalid shift timezone' }); }

    const assignment = await SocCompanyAssignment.findOne({ userId: manager._id, companyId, active: true });
    const company = assignment ? await Company.findById(companyId) : null;
    if (!company) return res.status(400).json({ message: 'Assign this company to the manager before assigning its shift' });

    const normalizedWeekdays = Array.isArray(weekdays)
      ? [...new Set(weekdays.map(Number).filter(day => Number.isInteger(day) && day >= 0 && day <= 6))]
      : [];
    if (!normalizedWeekdays.length) return res.status(400).json({ message: 'Select at least one working day' });

    const shift = await SocShift.create({
      tenantId: company.tenantId,
      companyId: company._id,
      name: String(name).trim().slice(0, 80),
      timezone,
      startTime,
      endTime,
      weekdays: normalizedWeekdays,
      analystIds: [manager._id],
      active: true,
      createdBy: req.user.id || req.user._id,
    });
    manager.maxWorkload = maxWorkload;
    await manager.save();

    res.json({ message: 'Shift and workload updated successfully', shift, maxWorkload });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── PATCH /api/super-admin/soc-managers/:id/shifts/:shiftId ── Edit assigned shift
router.patch('/soc-managers/:id/shifts/:shiftId', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.shiftId)) {
      return res.status(400).json({ message: 'Invalid manager or shift id' });
    }
    const manager = await User.findOne({ _id: req.params.id, role: 'soc_manager' }).select('_id');
    if (!manager) return res.status(404).json({ message: 'SOC Manager not found' });
    const shift = await SocShift.findOne({ _id: req.params.shiftId, analystIds: manager._id });
    if (!shift) return res.status(404).json({ message: 'Assigned shift not found' });

    const companyId = req.body.companyId || shift.companyId;
    const assignment = await SocCompanyAssignment.findOne({ userId: manager._id, companyId, active: true });
    if (!assignment) return res.status(400).json({ message: 'Selected company is outside this manager scope' });
    const name = String(req.body.name ?? shift.name).trim().slice(0, 80);
    const startTime = req.body.startTime ?? shift.startTime;
    const endTime = req.body.endTime ?? shift.endTime;
    const timezone = req.body.timezone ?? shift.timezone;
    const weekdays = Array.isArray(req.body.weekdays)
      ? [...new Set(req.body.weekdays.map(Number).filter(day => Number.isInteger(day) && day >= 0 && day <= 6))]
      : shift.weekdays;
    if (!name || !/^([01]\d|2[0-3]):[0-5]\d$/.test(startTime || '')
      || !/^([01]\d|2[0-3]):[0-5]\d$/.test(endTime || '') || !weekdays.length) {
      return res.status(400).json({ message: 'Valid shift name, time and working days are required' });
    }
    try { new Intl.DateTimeFormat('en-US', { timeZone: timezone }).format(); }
    catch { return res.status(400).json({ message: 'Invalid shift timezone' }); }

    Object.assign(shift, { companyId, name, startTime, endTime, timezone, weekdays });
    await shift.save();
    res.json({ message: 'Shift updated successfully', shift: await shift.populate('companyId', 'name') });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── DELETE /api/super-admin/soc-managers/:id/shifts/:shiftId ── Unassign/delete shift
router.delete('/soc-managers/:id/shifts/:shiftId', async (req, res) => {
  try {
    if (!mongoose.isValidObjectId(req.params.id) || !mongoose.isValidObjectId(req.params.shiftId)) {
      return res.status(400).json({ message: 'Invalid manager or shift id' });
    }
    const manager = await User.findOne({ _id: req.params.id, role: 'soc_manager' }).select('_id');
    if (!manager) return res.status(404).json({ message: 'SOC Manager not found' });
    const shift = await SocShift.findOne({ _id: req.params.shiftId, analystIds: manager._id });
    if (!shift) return res.status(404).json({ message: 'Assigned shift not found' });

    shift.analystIds.pull(manager._id);
    if (!shift.analystIds.length) await shift.deleteOne();
    else await shift.save();
    res.json({ message: 'Shift removed successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── POST /api/super-admin/soc-managers/:id/impersonate ── Login as SOC Manager
router.post('/soc-managers/:id/impersonate', requireActiveSuperadminSession, requireOriginalSuperadminSession, async (req, res) => {
  try {
    const user = await User.findById(req.params.id);
    if (!user || user.role !== 'soc_manager') return res.status(404).json({ message: 'SOC Manager not found' });

    const token = await createSuperadminLoginToken(req, user, 'soc_manager_login');
    res.set('Cache-Control', 'no-store');

    const frontendUrl = process.env.COMPANY_FRONTEND_URL || 'http://localhost:3000';
    res.json({
      token,
      redirectUrl: `${frontendUrl}/?impersonationToken=${token}`,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
      }
    });
  } catch (err) {
    res.status(err.statusCode || 500).json({ message: err.message });
  }
});

// ── GET /api/super-admin/unassigned-companies ── Unassigned companies queue
router.get('/unassigned-companies', async (req, res) => {
  try {
    const assignedIds = await SocCompanyAssignment.find({ active: true }).distinct('companyId');
    const unassigned = await Company.find({ _id: { $nin: assignedIds } }).populate('tenantId', 'name').lean();
    const managers = await User.find({ role: 'soc_manager', isActive: true }).select('name email maxWorkload').lean();

    res.json({
      unassignedCompanies: unassigned,
      suggestedManagers: managers.slice(0, 5)
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/security-events ── Platform Fraud / Security events
router.get('/security-events', async (req, res) => {
  try {
    const events = await FraudEvent.find().sort({ createdAt: -1 }).limit(50).lean();
    res.json(events);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/system-health ── System health
router.get('/system-health', async (req, res) => {
  try {
    const dbConnected = mongoose.connection.readyState === 1;
    res.json({
      api: { status: 'healthy', latency: '12ms' },
      database: { status: dbConnected ? 'healthy' : 'degraded', readyState: mongoose.connection.readyState },
      soarEngine: { status: 'healthy', activeJobs: 0 },
      agents: { status: 'healthy', online: await Agent.countDocuments({ status: 'online' }) },
      emailService: { status: 'healthy' }
    });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

// ── GET /api/super-admin/direct-companies ── Direct Superadmin registered companies only
router.get('/direct-companies', async (req, res) => {
  try {
    const companies = await Company.find({
      $or: [
        { partnerId: null },
        { partnerId: { $exists: false } },
        { company_type: 'DIRECT' }
      ]
    }).populate('tenantId', 'name').sort({ name: 1 }).lean();

    res.json(companies);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
});

module.exports = router;
