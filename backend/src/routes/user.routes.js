const router  = require('express').Router();
const crypto  = require('crypto');
const User    = require('../models/User.model');
const Token   = require('../models/Token.model');
const Company = require('../models/Company.model');
const Department = require('../models/Department.model');
const { authenticate, requireCompanyAdmin } = require('../middleware/auth.middleware');
const { sendMail, inviteEmailHtml, resetPasswordEmailHtml } = require('../utils/email');
const { validatePassword } = require('../utils/validate');
const SocInvitation = require('../models/SocInvitation.model');
const SocInvitationScope = require('../models/SocInvitationScope.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');

const FRONTEND_URL = process.env.COMPANY_ORIGIN || 'http://localhost:3000';

// Valid invitable roles — analyst only (company_admin and dept_admin are created differently)
const INVITABLE_ROLES = ['analyst'];

function requireTeamReader(req, res, next) {
  if (req.user?.role === 'department_admin') return next();
  return requireCompanyAdmin(req, res, next);
}

async function partnerUserScopeFilter(user, extra = {}) {
  const companyIds = await Company.find({ partnerId: user.partnerId }).distinct('_id');
  const assignedUserIds = companyIds.length
    ? await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId')
    : [];

  return {
    ...extra,
    superadminManaged: { $ne: true },
    $or: [
      { partnerId: user.partnerId },
      { companyId: { $in: companyIds } },
      { _id: { $in: assignedUserIds } },
    ],
  };
}

// POST /api/users/invite
router.post('/invite', authenticate, async (req, res) => {
  // Allow company_admin for own company, or superadmin for any company
  if (!['company_admin', 'partner_admin', 'superadmin'].includes(req.user.role))
    return res.status(403).json({ message: 'Access denied' });

  const { email, role = 'analyst', departmentId, departmentIds, companyId: bodyCompanyId } = req.body;
  if (!email) return res.status(400).json({ message: 'Email is required' });

  // Determine which company this invite is for
  const targetCompanyId = req.user.role === 'superadmin'
    ? bodyCompanyId
    : req.user.role === 'partner_admin'
      ? bodyCompanyId
      : req.user.companyId;
  if (!targetCompanyId) return res.status(400).json({ message: 'companyId required' });

  // Superadmin can invite operational roles; company_admin can only invite analysts.
  const allowedRoles = req.user.role === 'superadmin' ? ['analyst','department_admin'] : ['analyst'];
  if (!allowedRoles.includes(role))
    return res.status(400).json({ message: `Invalid role. Allowed: ${allowedRoles.join(', ')}` });

  try {
    const existing = await User.findOne({ email: email.trim().toLowerCase() });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const ownership = [
      ...(req.user.partnerId ? [{ partnerId: req.user.partnerId }] : []),
      ...(req.user.tenantId ? [{ tenantId: req.user.tenantId }] : []),
    ];
    if (req.user.role === 'partner_admin' && !ownership.length) {
      return res.status(403).json({ message: 'Access denied' });
    }
    const companyFilter = req.user.role === 'partner_admin'
      ? { _id: targetCompanyId, $or: ownership }
      : { _id: targetCompanyId };
    const company  = await Company.findOne(companyFilter);
    if (!company) return res.status(404).json({ message: 'Company not found' });
    const deptIds = departmentIds?.length ? departmentIds : (departmentId ? [departmentId] : []);
    if (deptIds.length) {
      const count = await Department.countDocuments({ _id: { $in: deptIds }, companyId: company._id });
      if (count !== deptIds.length) return res.status(400).json({ message: 'Invalid department for selected company' });
    }
    const inviter  = await User.findById(req.user.id);
    const rawToken = crypto.randomBytes(32).toString('hex');

    await Token.create({
      token:        rawToken,
      type:         'invite',
      email:        email.trim().toLowerCase(),
      tenantId:     company.tenantId || req.user.tenantId || null,
      partnerId:    company.partnerId || req.user.partnerId || null,
      companyId:    targetCompanyId,
      departmentId:  deptIds[0] || null,
      departmentIds: deptIds,
      role,
      invitedBy:    req.user.id,
      expiresAt:    new Date(Date.now() + 48 * 60 * 60 * 1000),
    });

    const inviteLink = `${FRONTEND_URL}/accept-invite?token=${rawToken}`;
    await sendMail({
      to: email,
      cc: req.user.role === 'partner_admin' ? inviter?.email : undefined,
      replyTo: req.user.role === 'partner_admin' ? inviter?.email : undefined,
      subject: `You've been invited to ${company?.name} on SOC SaaS`,
      html: inviteEmailHtml({
        companyName:   company?.name || 'SOC SaaS',
        invitedByName: inviter?.name || 'Admin',
        invitedByEmail: inviter?.email || '',
        role,
        inviteLink,
      }),
      text: `Accept your invitation: ${inviteLink}${inviter?.email ? `\nPartner Admin: ${inviter.email}` : ''}`,
    });

    res.json({ message: 'Invitation sent', email, role });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/users/invites
router.get('/invites', authenticate, async (req, res) => {
  if (!['company_admin', 'partner_admin', 'superadmin'].includes(req.user.role)) {
    return res.status(403).json({ message: 'Access denied' });
  }
  try {
    const filter = { type: 'invite' };
    if (req.user.role === 'partner_admin') {
      filter.partnerId = req.user.partnerId;
    } else if (req.user.role === 'company_admin') {
      filter.companyId = req.user.companyId;
    }
    const invites = await Token.find(filter)
      .populate('companyId', 'name')
      .populate('departmentId', 'name')
      .populate('invitedBy', 'name email')
      .sort({ createdAt: -1 })
      .limit(100)
      .lean();
    res.json(invites.map(invite => ({
      _id: invite._id,
      email: invite.email,
      role: invite.role || 'analyst',
      company: invite.companyId?.name || '-',
      department: invite.departmentId?.name || 'All departments',
      invitedBy: invite.invitedBy?.email || invite.invitedBy?.name || '-',
      status: invite.used ? 'accepted' : invite.expiresAt && new Date(invite.expiresAt) < new Date() ? 'expired' : 'pending',
      createdAt: invite.createdAt,
      expiresAt: invite.expiresAt,
    })));
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/users/accept-invite
router.post('/accept-invite', async (req, res) => {
  const { token, name, password } = req.body;
  if (!token || !name || !password)
    return res.status(400).json({ message: 'token, name and password are required' });

  const tokenHash = crypto.createHash('sha256').update(String(token)).digest('hex');
  const socInvitation = await SocInvitation.findOne({ tokenHash, status: 'pending' }).select('+tokenHash');
  const record = socInvitation ? null : await Token.findOne({ token, type: 'invite', used: false });
  if ((!socInvitation && !record) || (socInvitation && socInvitation.expiresAt < new Date()) || (record && record.expiresAt < new Date()))
    return res.status(400).json({ message: 'Invalid or expired invite link' });

  try {
    const jwt  = require('jsonwebtoken');
    const source = socInvitation || record;
    const scopes = socInvitation
      ? await SocInvitationScope.find({ invitationId: socInvitation._id }).lean()
      : [];
    const primaryScope = scopes[0];
    const user = await User.create({
      name,
      email:        source.email,
      password,
      role:         source.role || 'analyst',
      tenantId:     source.tenantId || null,
      partnerId:    source.partnerId || null,
      companyId:    primaryScope?.companyId || record?.companyId || null,
      socManagerPool: Boolean(socInvitation?.socManagerPool),
      superadminManaged: Boolean(socInvitation?.superadminManaged || socInvitation?.socManagerPool),
      departmentId: primaryScope?.departmentId || record?.departmentId || null,
      departmentIds: socInvitation ? scopes.map(scope => scope.departmentId).filter(Boolean) : record.departmentIds || [],
      isEmailVerified: true,
      accountStatus: 'active',
      forcePasswordReset: false,
      passwordChangedAt: new Date(),
    });

    if (socInvitation) {
      const companies = await Company.find({ _id: { $in: scopes.map(scope => scope.companyId) } }).select('tenantId partnerId').lean();
      const companyMap = Object.fromEntries(companies.map(company => [String(company._id), company]));
      const companyScopes = [...new Map(scopes.map(scope => [String(scope.companyId), scope])).values()];
      await SocCompanyAssignment.insertMany(companyScopes.map(scope => ({
        tenantId: companyMap[String(scope.companyId)]?.tenantId,
        partnerId: companyMap[String(scope.companyId)]?.partnerId || null,
        userId: user._id,
        companyId: scope.companyId,
        assignedBy: socInvitation.invitedBy,
      }))).catch(error => { if (error.code !== 11000) throw error; });
      const departmentScopes = scopes.filter(scope => scope.departmentId);
      if (departmentScopes.length) await SocDepartmentAssignment.insertMany(departmentScopes.map(scope => ({
        tenantId: companyMap[String(scope.companyId)].tenantId,
        userId: user._id,
        companyId: scope.companyId,
        departmentId: scope.departmentId,
        assignedBy: socInvitation.invitedBy,
      }))).catch(error => { if (error.code !== 11000) throw error; });
      socInvitation.status = 'accepted';
      socInvitation.acceptedAt = new Date();
      await socInvitation.save();
    } else {
      record.used = true;
      await record.save();
    }

    const jwtToken = jwt.sign(
      { id: user._id, email: user.email, role: user.role, tenantId: user.tenantId, partnerId: user.partnerId, companyId: user.companyId, departmentId: user.departmentId },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    res.json({ token: jwtToken, user });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// GET /api/users
router.get('/', authenticate, requireTeamReader, async (req, res) => {
  try {
    if (req.user.role === 'department_admin' && !req.user.departmentId) {
      return res.status(403).json({ message: 'Department assignment required' });
    }
    const targetCompanyId = req.headers['x-company-id'] || req.query.companyId || req.user.companyId;
    let filter = {};
    if (req.user.role === 'department_admin') {
      filter = {
        companyId: req.user.companyId,
        $or: [
          { departmentId: req.user.departmentId },
          { departmentIds: req.user.departmentId },
        ],
      };
    } else if (targetCompanyId) {
      const assignedManagerIds = await SocCompanyAssignment.find({ companyId: targetCompanyId, active: true }).distinct('userId');
      filter = {
        $or: [
          { companyId: targetCompanyId },
          { _id: { $in: assignedManagerIds } },
        ],
      };
    } else if (req.user.role === 'partner_admin') {
      filter = await partnerUserScopeFilter(req.user);
    } else if (req.user.role !== 'superadmin') {
      filter = { companyId: req.user.companyId, superadminManaged: { $ne: true } };
    }
    const users = await User.find(filter)
      .populate('companyId', 'name')
      .populate('departmentId', 'name')
      .sort({ role: 1, createdAt: -1 });
    res.json(users);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/users/:id
router.patch('/:id', authenticate, requireCompanyAdmin, async (req, res) => {
  // Prevent changing role to anything invalid
  if (req.body.role && !['analyst','department_admin','company_admin','soc_manager','l1_analyst','l2_analyst','l3_analyst','l4_analyst'].includes(req.body.role))
    return res.status(400).json({ message: 'Invalid role' });

  try {
    const filter = req.user.role === 'superadmin'
      ? { _id: req.params.id }
      : req.user.role === 'partner_admin'
        ? await partnerUserScopeFilter(req.user, { _id: req.params.id })
        : { _id: req.params.id, companyId: req.user.companyId, superadminManaged: { $ne: true } };
    const { email, password, tenantId, partnerId, companyId, ...safeUpdates } = req.body;
    const user = await User.findOneAndUpdate(
      filter,
      safeUpdates, { new: true, runValidators: true }
    );
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) { res.status(400).json({ message: err.message }); }
});

// POST /api/users/forgot-password
router.post('/forgot-password', async (req, res) => {
  res.json({ message: 'If that email exists, a reset link has been sent.' });
  const user = await User.findOne({ email: req.body.email?.trim().toLowerCase() });
  if (!user) return;
  try {
    const rawToken = crypto.randomBytes(32).toString('hex');
    await Token.create({
      token: rawToken, type: 'password_reset',
      email: user.email,
      expiresAt: new Date(Date.now() + 60 * 60 * 1000),
    });
    const resetLink = `${FRONTEND_URL}/reset-password?token=${rawToken}`;
    await sendMail({
      to: user.email,
      subject: 'Reset your SOC SaaS password',
      html: resetPasswordEmailHtml({ resetLink }),
      text: `Reset your password: ${resetLink}`,
    });
  } catch (err) { console.error('[user] forgot-password error:', err.message); }
});

// POST /api/users/reset-password
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password)
    return res.status(400).json({ message: 'token and password required' });
  const record = await Token.findOne({ token, type: 'password_reset', used: false });
  if (!record || record.expiresAt < new Date())
    return res.status(400).json({ message: 'Invalid or expired link' });
  try {
    const user = await User.findOne({ email: record.email });
    if (!user) return res.status(404).json({ message: 'User not found' });
    user.password = password;
    await user.save();
    record.used = true;
    await record.save();
    res.json({ message: 'Password updated' });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/users/force-password-reset
// Used after first login with Super Admin generated temporary password.
router.post('/force-password-reset', authenticate, async (req, res) => {
  const { newPassword } = req.body;
  try {
    const passwordError = validatePassword(newPassword);
    if (passwordError) return res.status(400).json({ message: passwordError });
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (!user.forcePasswordReset) {
      return res.status(400).json({ message: 'Password reset is not required for this account.' });
    }
    user.password = newPassword;
    user.forcePasswordReset = false;
    await user.save();

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: user._id,
      companyId: user.companyId,
      email: user.email,
      action: 'password_reset',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${user.companyId}`).emit('activity:new', { companyId: user.companyId });
      io.to('superadmin').emit('activity:new', { companyId: user.companyId });
    }

    res.json({ message: 'Password updated successfully', user });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// POST /api/users/change-password
router.post('/change-password', authenticate, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const passwordError = validatePassword(newPassword);
    if (passwordError) return res.status(400).json({ message: passwordError });
    const user  = await User.findById(req.user.id);
    const match = await user.comparePassword(currentPassword);
    if (!match) return res.status(400).json({ message: 'Current password incorrect' });
    user.password = newPassword;
    user.forcePasswordReset = false;
    await user.save();

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: user._id,
      companyId: user.companyId,
      email: user.email,
      action: 'password_changed',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${user.companyId}`).emit('activity:new', { companyId: user.companyId });
      io.to('superadmin').emit('activity:new', { companyId: user.companyId });
    }

    res.json({ message: 'Password changed successfully', user });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// GET /api/users/me  — own profile
router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -twoFactorSecret');
    if (!user) return res.status(404).json({ message: 'User not found' });
    res.json(user);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

// PATCH /api/users/me  — update own name/phone
router.patch('/me', authenticate, async (req, res) => {
  try {
    const allowed = ['name', 'phone'];
    const updates = Object.fromEntries(
      Object.entries(req.body).filter(([k]) => allowed.includes(k))
    );
    const user = await User.findByIdAndUpdate(
      req.user.id,
      { $set: updates },
      { new: true, runValidators: true }
    ).select('-password -twoFactorSecret');
    if (!user) return res.status(404).json({ message: 'User not found' });

    // Log this activity
    const LoginActivity = require('../models/LoginActivity.model');
    await LoginActivity.create({
      userId: user._id,
      companyId: user.companyId,
      email: user.email,
      action: 'admin_updated',
      success: true,
      ipAddress: req.ip || req.headers['x-forwarded-for'] || req.connection?.remoteAddress,
      userAgent: req.get('user-agent') || '',
    });

    const io = req.app.get('io');
    if (io) {
      io.to(`company:${user.companyId}`).emit('activity:new', { companyId: user.companyId });
      io.to('superadmin').emit('activity:new', { companyId: user.companyId });
    }

    res.json(user);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

module.exports = router;
