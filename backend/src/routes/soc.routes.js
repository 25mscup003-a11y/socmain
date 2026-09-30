const router = require('express').Router();
const crypto = require('crypto');
const { authenticate } = require('../middleware/auth.middleware');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const Alert = require('../models/Alert.model');
const SocInvitation = require('../models/SocInvitation.model');
const SocInvitationScope = require('../models/SocInvitationScope.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocShift = require('../models/SocShift.model');
const SocAuditEvent = require('../models/SocAuditEvent.model');
const { sendMail, inviteEmailHtml } = require('../utils/email');
const { validateEmail } = require('../utils/validate');
const {
  SOC_ROLES,
  ANALYST_ROLES,
  allowedCompanyIds,
  assertCompanyScope,
  resolveSocActor,
  socStaffVisibilityFilter,
  socInvitationVisibilityFilter,
  assertSocStaffManagementScope,
  assertSocInvitationManagementScope,
} = require('../services/socAccess.service');

const FRONTEND_URL = process.env.COMPANY_ORIGIN || 'http://localhost:3000';
const MANAGEMENT_ROLES = ['superadmin', 'partner_admin', 'company_admin', 'soc_manager'];

router.use(authenticate);
router.use((req, res, next) => MANAGEMENT_ROLES.includes(req.user?.role)
  ? next()
  : res.status(403).json({ message: 'SOC management access required' }));

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function cleanText(value, max = 200) {
  return String(value || '').trim().slice(0, max);
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
  });
}

async function assignmentMap(userIds) {
  const [companies, departments] = await Promise.all([
    SocCompanyAssignment.find({ userId: { $in: userIds }, active: true })
      .populate('companyId', 'name').lean(),
    SocDepartmentAssignment.find({ userId: { $in: userIds }, active: true })
      .populate('departmentId', 'name').lean(),
  ]);
  const result = {};
  for (const id of userIds) result[String(id)] = { companies: [], departments: [] };
  for (const item of companies) result[String(item.userId)]?.companies.push(item.companyId);
  for (const item of departments) result[String(item.userId)]?.departments.push(item.departmentId);
  return result;
}

// ── GET /api/soc/managers/metrics ── 12 Top Monitoring Metric Cards (partner-scoped)
router.get('/managers/metrics', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const assignedUserIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId');
    const visFilter = socStaffVisibilityFilter(actor);

    const [
      total, active, suspended, locked, invited, expired,
      slaBreaches, criticalIncidents,
    ] = await Promise.all([
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', ...visFilter }),
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', isActive: true, ...visFilter }),
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', accountStatus: 'suspended', ...visFilter }),
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', accountStatus: 'locked', ...visFilter }),
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', accountStatus: 'invited', ...visFilter }),
      User.countDocuments({ _id: { $in: assignedUserIds }, role: 'soc_manager', accountStatus: 'expired', ...visFilter }),
      Alert.countDocuments({ companyId: { $in: companyIds }, slaBreached: true }),
      Alert.countDocuments({ companyId: { $in: companyIds }, severity: 'critical', status: { $ne: 'resolved' } }),
    ]);

    // companies without any manager assigned
    const managedCompanyIds = await SocCompanyAssignment.find({
      userId: { $in: assignedUserIds },
      companyId: { $in: companyIds },
      active: true,
    }).distinct('companyId');
    const withoutCompanies = companyIds.length - managedCompanyIds.length;

    res.json({
      total,
      active,
      onShift: active,
      online: active,
      offline: Math.max(0, total - active),
      overloaded: 0,
      pendingInvitations: invited,
      expiredInvitations: expired,
      suspended,
      locked,
      withoutCompanies: Math.max(0, withoutCompanies),
      slaBreaches,
      criticalIncidents,
    });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

// ── GET /api/soc/managers ── Paginated SOC Manager list with workload (partner-scoped)
router.get('/managers', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const assignedUserIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId');
    const visFilter = socStaffVisibilityFilter(actor);

    const page = Math.max(1, parseInt(req.query.page) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit) || 15));
    const skip = (page - 1) * limit;
    const search = req.query.search?.trim();
    const status = req.query.status;

    const matchFilter = {
      _id: { $in: assignedUserIds },
      role: 'soc_manager',
      ...visFilter,
    };
    if (status && status !== 'all') matchFilter.accountStatus = status;
    if (search) {
      matchFilter.$or = [
        { name: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }

    const [users, total] = await Promise.all([
      User.find(matchFilter).select('-password -otp -twoFactorSecret').sort({ createdAt: -1 }).skip(skip).limit(limit).lean(),
      User.countDocuments(matchFilter),
    ]);

    // Enrich with company assignment count and workload
    const userIds = users.map(u => u._id);
    const [companyAssignments, workloads, analystCountsAgg] = await Promise.all([
      SocCompanyAssignment.find({ userId: { $in: userIds }, active: true }).lean(),
      Alert.aggregate([
        { $match: { assignedTo: { $in: userIds }, status: { $in: ['open', 'investigating'] } } },
        { $group: { _id: '$assignedTo', open: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } } } },
      ]),
      SocCompanyAssignment.aggregate([
        { $match: { userId: { $in: userIds }, active: true } },
        { $lookup: { from: 'users', let: { cid: '$companyId' }, pipeline: [{ $match: { $expr: { $and: [{ $eq: ['$companyId', '$$cid'] }, { $in: ['$role', ['l1_analyst','l2_analyst','l3_analyst','l4_analyst']] }] } } }], as: 'analysts' } },
        { $group: { _id: '$userId', total: { $sum: { $size: '$analysts' } } } },
      ]).catch(() => []),
    ]);

    const companyCountMap = {};
    companyAssignments.forEach(a => {
      const key = String(a.userId);
      companyCountMap[key] = (companyCountMap[key] || 0) + 1;
    });

    // Get analyst counts per manager (by company scope)
    const managerCompanyMap = {};
    companyAssignments.forEach(a => {
      const key = String(a.userId);
      if (!managerCompanyMap[key]) managerCompanyMap[key] = [];
      managerCompanyMap[key].push(a.companyId);
    });

    // Build analyst count map
    const analystCountMap = {};
    analystCountsAgg.forEach(a => { analystCountMap[String(a._id)] = a.total; });

    const workloadMap = Object.fromEntries(workloads.map(w => [String(w._id), w]));

    // Per manager get analyst breakdown
    const allManagerCompanyIds = [...new Set(companyAssignments.map(a => String(a.companyId)))];
    const analystByCompany = await User.find({
      companyId: { $in: allManagerCompanyIds },
      role: { $in: ['l1_analyst','l2_analyst','l3_analyst','l4_analyst'] },
    }).select('role companyId').lean();

    const analystsByCompanyMap = {};
    analystByCompany.forEach(a => {
      const key = String(a.companyId);
      if (!analystsByCompanyMap[key]) analystsByCompanyMap[key] = { total: 0, l1: 0, l2: 0, l3: 0 };
      analystsByCompanyMap[key].total++;
      if (a.role === 'l1_analyst') analystsByCompanyMap[key].l1++;
      if (a.role === 'l2_analyst') analystsByCompanyMap[key].l2++;
      if (a.role === 'l3_analyst') analystsByCompanyMap[key].l3++;
    });

    const items = users.map(u => {
      const uid = String(u._id);
      const mgrCompIds = managerCompanyMap[uid] || [];
      const analystCounts = { total: 0, l1: 0, l2: 0, l3: 0 };
      mgrCompIds.forEach(cid => {
        const ac = analystsByCompanyMap[String(cid)];
        if (ac) { analystCounts.total += ac.total; analystCounts.l1 += ac.l1; analystCounts.l2 += ac.l2; analystCounts.l3 += ac.l3; }
      });
      const wl = workloadMap[uid] || { open: 0, critical: 0 };
      const maxWorkload = u.maxWorkload || 10;
      return {
        ...u,
        assignedCompaniesCount: companyCountMap[uid] || 0,
        analystCounts,
        workload: { ...wl, percentage: Math.round((wl.open / maxWorkload) * 100) },
      };
    });

    res.json({ items, total, page, pages: Math.ceil(total / limit) });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.get('/overview', async (req, res) => {

  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const assignmentFilter = { companyId: { $in: companyIds }, active: true };
    const userIds = await SocCompanyAssignment.find(assignmentFilter).distinct('userId');
    const [roleCounts, openAlerts, shifts] = await Promise.all([
      User.aggregate([
        { $match: { _id: { $in: userIds }, role: { $in: SOC_ROLES }, ...socStaffVisibilityFilter(actor) } },
        { $group: { _id: '$role', count: { $sum: 1 } } },
      ]),
      Alert.countDocuments({ companyId: { $in: companyIds }, status: { $in: ['open', 'investigating'] } }),
      SocShift.countDocuments({ companyId: { $in: companyIds }, active: true }),
    ]);
    const counts = Object.fromEntries(roleCounts.map(item => [item._id, item.count]));
    res.json({ companyCount: companyIds.length, openAlerts, activeShifts: shifts, roleCounts: counts });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.get('/companies', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    res.json(await Company.find({ _id: { $in: companyIds } }).select('name tenantId partnerId status').sort({ name: 1 }).lean());
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.get('/staff', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const userIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId');
    const roleFilter = req.query.role && SOC_ROLES.includes(req.query.role) ? req.query.role : { $in: SOC_ROLES };
    const visibilityFilter = socStaffVisibilityFilter(actor);
    const users = await User.find({ _id: { $in: userIds }, role: roleFilter, ...visibilityFilter })
      .select('-password -otp -twoFactorSecret').sort({ createdAt: -1 }).lean();
    const assignments = await assignmentMap(users.map(user => user._id));
    const workloads = await Alert.aggregate([
      { $match: { assignedTo: { $in: users.map(user => user._id) }, status: { $in: ['open', 'investigating'] } } },
      { $group: { _id: '$assignedTo', open: { $sum: 1 }, critical: { $sum: { $cond: [{ $eq: ['$severity', 'critical'] }, 1, 0] } } } },
    ]);
    const workloadMap = Object.fromEntries(workloads.map(item => [String(item._id), item]));
    res.json(users.map(user => ({ ...user, assignments: assignments[String(user._id)], workload: workloadMap[String(user._id)] || { open: 0, critical: 0 } })));
  } catch (error) { res.status(500).json({ message: error.message }); }
});

// ── GET /api/soc/staff/:id ── Full detail for a single SOC staff member (used by partner dashboard)
router.get('/staff/:id', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);

    // Find the target user and verify they are in scope
    const target = await User.findOne({ _id: req.params.id, role: { $in: SOC_ROLES } })
      .select('-password -otp -twoFactorSecret').lean();
    if (!target) return res.status(404).json({ message: 'SOC staff member not found' });

    // Verify the target is accessible to the actor
    const assignments = await SocCompanyAssignment.find({ userId: target._id, active: true }).lean();
    const assignedCompanyIds = assignments.map(a => String(a.companyId));
    const hasScope = assignedCompanyIds.some(cid => companyIds.map(String).includes(cid));
    if (!hasScope && req.user.role !== 'superadmin') {
      return res.status(403).json({ message: 'Access denied: SOC staff member is outside your scope' });
    }

    const [companies, analysts, auditLogs, activeAlerts] = await Promise.all([
      Company.find({ _id: { $in: assignedCompanyIds } }).select('name tenantId partnerId status').lean(),
      User.find({ companyId: { $in: assignedCompanyIds }, role: { $in: ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'] } })
        .select('-password -otp -twoFactorSecret').lean(),
      SocAuditEvent.find({ $or: [{ actorId: target._id }, { targetId: target._id }] })
        .sort({ createdAt: -1 }).limit(20).populate('actorId', 'name email').lean(),
      Alert.find({ companyId: { $in: assignedCompanyIds }, status: { $ne: 'resolved' } })
        .sort({ createdAt: -1 }).limit(10).lean(),
    ]);

    res.json({ manager: target, assignedCompanies: companies, analysts, auditLogs, activeAlerts });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.get('/invitations', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const companyIds = await allowedCompanyIds(actor);
    const invitationIds = await SocInvitationScope.find({ companyId: { $in: companyIds } }).distinct('invitationId');
    const invitationVisibility = socInvitationVisibilityFilter(actor);
    const invitations = await SocInvitation.find({ _id: { $in: invitationIds }, ...invitationVisibility })
      .populate('invitedBy', 'name email').sort({ createdAt: -1 }).limit(250).lean();
    const scopes = await SocInvitationScope.find({ invitationId: { $in: invitationIds } })
      .populate('companyId', 'name').populate('departmentId', 'name').lean();
    const byInvite = {};
    for (const scope of scopes) (byInvite[String(scope.invitationId)] ||= []).push(scope);
    res.json(invitations.map(invite => ({
      ...invite,
      status: invite.status === 'pending' && new Date(invite.expiresAt) < new Date() ? 'expired' : invite.status,
      scopes: byInvite[String(invite._id)] || [],
    })));
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/invitations', async (req, res) => {
  try {
    const actor = await resolveSocActor(req.user);
    const email = cleanText(req.body.email, 254).toLowerCase();
    const name = cleanText(req.body.name, 120);
    const role = cleanText(req.body.role, 30);
    const companyIds = await assertCompanyScope(req.user, req.body.companyIds || [req.body.companyId]);
    if (validateEmail(email)) return res.status(400).json({ message: validateEmail(email) });
    const allowedRoles = ['soc_manager', 'company_admin'].includes(actor.role) ? ANALYST_ROLES : SOC_ROLES;
    if (!allowedRoles.includes(role)) return res.status(403).json({ message: `You cannot invite role ${role}` });
    if (await User.exists({ email })) return res.status(409).json({ message: 'Email already registered' });
    if (await SocInvitation.exists({ email, role, status: 'pending', expiresAt: { $gt: new Date() } })) {
      return res.status(409).json({ message: 'An active invitation already exists for this email and role' });
    }
    const companies = await Company.find({ _id: { $in: companyIds } }).select('tenantId partnerId name').lean();
    if (companies.length !== companyIds.length) return res.status(400).json({ message: 'Invalid company selection' });
    const tenantIds = new Set(companies.map(company => String(company.tenantId)));
    if (tenantIds.size !== 1) return res.status(400).json({ message: 'All companies must belong to one tenant' });
    const rawToken = crypto.randomBytes(32).toString('base64url');
    const invitation = await SocInvitation.create({
      tenantId: companies[0].tenantId,
      partnerId: companies[0].partnerId || null,
      email, name, role, tokenHash: hashToken(rawToken), invitedBy: actor.id || actor._id,
      socManagerPool: (actor.role === 'superadmin' || actor.superadminManaged === true) && ANALYST_ROLES.includes(role),
      superadminManaged: actor.role === 'superadmin' || actor.superadminManaged === true,
      expiresAt: new Date(Date.now() + 48 * 60 * 60 * 1000),
    });
    const departmentIds = [...new Set((req.body.departmentIds || []).filter(Boolean).map(String))];
    if (departmentIds.length) {
      const valid = await Department.find({ _id: { $in: departmentIds }, companyId: { $in: companyIds } }).select('_id companyId').lean();
      if (valid.length !== departmentIds.length) {
        await invitation.deleteOne();
        throw Object.assign(new Error('Invalid department selection'), { status: 400 });
      }
      await SocInvitationScope.insertMany(valid.map(department => ({ invitationId: invitation._id, companyId: department.companyId, departmentId: department._id })));
      const scopedCompanies = new Set(valid.map(department => String(department.companyId)));
      await SocInvitationScope.insertMany(companyIds.filter(id => !scopedCompanies.has(id)).map(companyId => ({ invitationId: invitation._id, companyId })));
    } else {
      await SocInvitationScope.insertMany(companyIds.map(companyId => ({ invitationId: invitation._id, companyId })));
    }
    const inviteLink = `${FRONTEND_URL}/accept-invite?token=${encodeURIComponent(rawToken)}`;
    await sendMail({
      to: email,
      subject: `SOC ${role.replaceAll('_', ' ').toUpperCase()} invitation`,
      html: inviteEmailHtml({ companyName: companies.map(company => company.name).join(', '), invitedByName: req.user.email, role, inviteLink }),
      text: `Accept your SOC invitation: ${inviteLink}`,
    });
    await audit(req, 'invitation.created', 'SocInvitation', invitation._id, companies[0]._id, { email, role, companyIds });
    res.status(201).json({ message: 'Invitation sent', invitationId: invitation._id, email, role });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.message });
  }
});

router.patch('/invitations/:id/revoke', async (req, res) => {
  try {
    const invitation = await SocInvitation.findById(req.params.id);
    if (!invitation) return res.status(404).json({ message: 'Invitation not found' });
    await assertSocInvitationManagementScope(req.user, invitation);
    if (invitation.status !== 'pending') return res.status(409).json({ message: 'Only pending invitations can be revoked' });
    invitation.status = 'revoked';
    invitation.revokedAt = new Date();
    await invitation.save();
    await audit(req, 'invitation.revoked', 'SocInvitation', invitation._id, null, { email: invitation.email });
    res.json({ message: 'Invitation revoked', invitation });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.post('/invitations/:id/resend', async (req, res) => {
  try {
    const invitation = await SocInvitation.findOne({ _id: req.params.id, status: { $in: ['pending', 'expired'] } }).select('+tokenHash');
    if (!invitation) return res.status(409).json({ message: 'Accepted or revoked invitations cannot be resent' });
    await assertSocInvitationManagementScope(req.user, invitation);
    const scopes = await SocInvitationScope.find({ invitationId: invitation._id })
      .populate('companyId', 'name').lean();
    const rawToken = crypto.randomBytes(32).toString('base64url');
    invitation.tokenHash = hashToken(rawToken);
    invitation.status = 'pending';
    invitation.expiresAt = new Date(Date.now() + 48 * 60 * 60 * 1000);
    await invitation.save();
    const inviteLink = `${FRONTEND_URL}/accept-invite?token=${encodeURIComponent(rawToken)}`;
    await sendMail({
      to: invitation.email,
      subject: `SOC ${invitation.role.replaceAll('_', ' ').toUpperCase()} invitation`,
      html: inviteEmailHtml({ companyName: [...new Set(scopes.map(scope => scope.companyId?.name).filter(Boolean))].join(', '), invitedByName: req.user.email, role: invitation.role, inviteLink }),
      text: `Accept your SOC invitation: ${inviteLink}`,
    });
    await audit(req, 'invitation.resent', 'SocInvitation', invitation._id, scopes[0].companyId?._id, { email: invitation.email });
    res.json({ message: 'Invitation resent', expiresAt: invitation.expiresAt });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.patch('/staff/:id/status', async (req, res) => {
  try {
    const status = cleanText(req.body.status, 20);
    if (!['active', 'disabled', 'suspended'].includes(status)) return res.status(400).json({ message: 'Invalid status' });
    const target = await User.findOne({ _id: req.params.id, role: { $in: SOC_ROLES } });
    if (!target) return res.status(404).json({ message: 'SOC user not found' });
    await assertSocStaffManagementScope(req.user, target);
    target.accountStatus = status;
    target.isActive = status === 'active';
    await target.save();
    await audit(req, `staff.${status}`, 'User', target._id, null, { role: target.role });
    res.json({ message: `User ${status}`, user: target });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.put('/staff/:id/assignments', async (req, res) => {
  try {
    const companyIds = await assertCompanyScope(req.user, req.body.companyIds);
    const target = await User.findOne({ _id: req.params.id, role: { $in: SOC_ROLES } });
    if (!target) return res.status(404).json({ message: 'SOC user not found' });
    await assertSocStaffManagementScope(req.user, target);
    const companies = await Company.find({ _id: { $in: companyIds } }).select('tenantId partnerId').lean();
    const departmentIds = [...new Set((req.body.departmentIds || []).filter(Boolean).map(String))];
    const departments = departmentIds.length
      ? await Department.find({ _id: { $in: departmentIds }, companyId: { $in: companyIds } }).select('_id companyId').lean()
      : [];
    if (departments.length !== departmentIds.length) return res.status(400).json({ message: 'Invalid department selection' });
    await SocCompanyAssignment.bulkWrite(companies.map(company => ({ updateOne: {
      filter: { userId: target._id, companyId: company._id },
      update: { $set: { tenantId: company.tenantId, partnerId: company.partnerId, assignedBy: req.user.id, active: true } },
      upsert: true,
    } })));
    await SocCompanyAssignment.deleteMany({ userId: target._id, companyId: { $nin: companyIds } });
    if (departments.length) await SocDepartmentAssignment.bulkWrite(departments.map(department => ({ updateOne: {
      filter: { userId: target._id, departmentId: department._id },
      update: { $set: { tenantId: companies[0].tenantId, companyId: department.companyId, assignedBy: req.user.id, active: true } },
      upsert: true,
    } })));
    await SocDepartmentAssignment.deleteMany({ userId: target._id, departmentId: { $nin: departmentIds } });
    const confirmedAssignments = await SocCompanyAssignment.find({
      userId: target._id,
      companyId: { $in: companyIds },
      active: true,
    }).distinct('companyId');
    if (confirmedAssignments.length !== companyIds.length) {
      return res.status(500).json({ message: 'Company assignment could not be verified', assignmentConfirmed: false, emailSent: false });
    }
    let emailInfo = null;
    if (req.user.role === 'soc_manager') {
      target.socManagerId = req.user.id;
      target.companyId = companies[0]._id;
      await target.save();
      const assignedCompany = await Company.findById(companies[0]._id).select('name').lean();
      try {
        emailInfo = await sendMail({
          to: target.email,
          subject: 'SOC Analyst company assignment',
          text: `Hello ${target.name}, you have been assigned to ${assignedCompany?.name || 'a company'} by your SOC Manager.`,
          html: `<p>Hello <strong>${target.name}</strong>,</p><p>You have been assigned to <strong>${assignedCompany?.name || 'a company'}</strong> by your SOC Manager.</p>`,
        });
      } catch (emailError) {
        console.error('[analyst assignment email]', emailError.message);
        return res.status(502).json({
          message: `Company assigned successfully, but email delivery to ${target.email} failed`,
          assignmentConfirmed: true,
          emailSent: false,
        });
      }
    }
    await audit(req, 'staff.assignments_updated', 'User', target._id, companies[0]._id, { companyIds, departmentIds });
    res.json({
      message: 'Company assigned and email sent successfully',
      assignmentConfirmed: true,
      assignedCompanyIds: confirmedAssignments.map(String),
      emailSent: req.user.role === 'soc_manager' ? Boolean(emailInfo?.messageId) : false,
      email: target.email,
    });
  } catch (error) { res.status(error.status || 500).json({ message: error.message }); }
});

router.get('/shifts', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    res.json(await SocShift.find({ companyId: { $in: companyIds } }).populate('companyId', 'name').populate('analystIds', 'name email role').sort({ createdAt: -1 }));
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/shifts', async (req, res) => {
  try {
    const [companyId] = await assertCompanyScope(req.user, [req.body.companyId]);
    const analystIds = [...new Set((req.body.analystIds || []).filter(Boolean).map(String))];
    const scopedAnalysts = await SocCompanyAssignment.countDocuments({ userId: { $in: analystIds }, companyId, active: true });
    if (scopedAnalysts !== analystIds.length) return res.status(400).json({ message: 'One or more analysts are outside this company' });
    const company = await Company.findById(companyId).select('tenantId');
    const shift = await SocShift.create({
      tenantId: company.tenantId, companyId, name: cleanText(req.body.name, 80),
      timezone: cleanText(req.body.timezone, 80) || 'Asia/Kolkata',
      startTime: req.body.startTime, endTime: req.body.endTime,
      weekdays: req.body.weekdays || [1, 2, 3, 4, 5], analystIds, createdBy: req.user.id,
    });
    await audit(req, 'shift.created', 'SocShift', shift._id, companyId, { name: shift.name });
    res.status(201).json(shift);
  } catch (error) { res.status(error.status || 400).json({ message: error.message }); }
});

router.post('/alerts/:id/assign', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const alert = await Alert.findOne({ _id: req.params.id, companyId: { $in: companyIds } });
    if (!alert) return res.status(404).json({ message: 'Alert not found' });
    let assigneeId = req.body.userId;
    if (!assigneeId) {
      const candidates = await SocCompanyAssignment.find({ companyId: alert.companyId, active: true }).distinct('userId');
      const analysts = await User.find({ _id: { $in: candidates }, role: { $in: ANALYST_ROLES }, isActive: true }).select('_id').lean();
      const ids = analysts.map(user => user._id);
      const loads = await Alert.aggregate([{ $match: { assignedTo: { $in: ids }, status: { $in: ['open', 'investigating'] } } }, { $group: { _id: '$assignedTo', count: { $sum: 1 } } }]);
      const map = Object.fromEntries(loads.map(load => [String(load._id), load.count]));
      assigneeId = ids.sort((a, b) => (map[String(a)] || 0) - (map[String(b)] || 0))[0];
    }
    if (!assigneeId) return res.status(409).json({ message: 'No active analyst is available' });
    const valid = await SocCompanyAssignment.exists({ userId: assigneeId, companyId: alert.companyId, active: true });
    if (!valid) return res.status(400).json({ message: 'Assignee is outside this company' });
    alert.assignedTo = assigneeId;
    if (alert.status === 'open') alert.status = 'investigating';
    await alert.save();
    await audit(req, 'alert.assigned', 'Alert', alert._id, alert.companyId, { assigneeId: String(assigneeId), automatic: !req.body.userId });
    res.json({ message: 'Alert assigned', alert });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/audit', async (req, res) => {
  try {
    const companyIds = await allowedCompanyIds(req.user);
    const filter = req.user.role === 'superadmin' ? {} : { $or: [{ companyId: { $in: companyIds } }, { actorId: req.user.id }] };
    res.json(await SocAuditEvent.find(filter).populate('actorId', 'name email role').sort({ createdAt: -1 }).limit(200).lean());
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
