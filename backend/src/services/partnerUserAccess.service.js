const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const LoginActivity = require('../models/LoginActivity.model');

const MANAGED_ROLES = ['company_admin', 'department_admin', 'soc_manager', 'analyst', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const ACCOUNT_FIELDS = 'name email role tenantId partnerId companyId departmentId isActive accountStatus passwordChangedAt forcePasswordReset';
const active = user => user?.isActive === true && (!user.accountStatus || user.accountStatus === 'active');
const same = (a, b) => String(a?._id || a || '') === String(b?._id || b || '');
const failure = (message, status = 403) => Object.assign(new Error(message), { status });
const AUDIT_ACTIONS = ['partner_impersonation_started', 'partner_impersonation_ended', 'password_changed', 'partner_impersonation_blocked'];

function partnerAccessSnapshot(actor, target, company) {
  return {
    partnerId: actor.partnerId, partnerName: actor.partnerName, actorName: actor.name,
    targetUserId: target._id, targetName: target.name, targetEmail: target.email, targetRole: target.role,
    companyName: company?.name,
  };
}

async function activePartnerActor(claims) {
  if (claims?.role !== 'partner_admin' || claims.impersonatedBy) {
    throw failure('Use your original Partner Admin session to manage user accounts.');
  }
  if (!mongoose.isObjectIdOrHexString(claims.id) || !mongoose.isObjectIdOrHexString(claims.partnerId)) {
    throw failure('A linked partner account is required.');
  }
  const actor = await User.findById(claims.id).select(ACCOUNT_FIELDS).lean();
  if (!active(actor) || actor.role !== 'partner_admin' || !same(actor.partnerId, claims.partnerId)) {
    throw failure('Partner Admin session is no longer active.', 401);
  }
  if (actor.passwordChangedAt && new Date(actor.passwordChangedAt).getTime() > Number(claims.iat) * 1000) {
    throw failure('Session expired after credential change.', 401);
  }
  const partner = await Partner.findById(actor.partnerId).select('status name').lean();
  if (!partner || !['approved', 'pending_quote', 'pending_payment', 'active'].includes(partner.status)) {
    throw failure('Partner account is not active.');
  }
  actor.partnerName = partner.name || '';
  return actor;
}

// Credentials control the whole account: any assignment outside this partner
// excludes the account, even if it also has an assignment inside the partner.
async function partnerManagedAccounts(actor, targetId) {
  const companies = await Company.find({ partnerId: actor.partnerId }).select('_id name').lean();
  const companyIds = companies.map(company => company._id);
  const assignedIds = companyIds.length
    ? await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId')
    : [];
  const users = await User.find({
    ...(targetId ? { _id: targetId } : {}),
    role: { $in: MANAGED_ROLES }, superadminManaged: { $ne: true }, socManagerPool: { $ne: true },
    partnerId: { $in: [actor.partnerId, null] }, companyId: { $in: [...companyIds, null] },
    $or: [{ partnerId: actor.partnerId }, { companyId: { $in: companyIds } }, { _id: { $in: assignedIds } }],
  }).select(ACCOUNT_FIELDS).sort({ role: 1, name: 1 });
  const outsideIds = users.length ? await SocCompanyAssignment.find({
    userId: { $in: users.map(user => user._id) }, active: true, companyId: { $nin: companyIds },
  }).distinct('userId') : [];
  const excluded = new Set(outsideIds.map(String));
  return { users: users.filter(user => !excluded.has(String(user._id))), companies };
}

async function partnerManagedAccount(actor, id) {
  if (!mongoose.isObjectIdOrHexString(id)) throw failure('Invalid user ID.', 400);
  const { users } = await partnerManagedAccounts(actor, id);
  if (!users.length) throw failure('User account not found in your partner scope.', 404);
  return users[0];
}

async function createPartnerLoginToken(req, user) {
  if (!active(user)) throw failure('This account is not active. Activate it before logging in.');
  const actor = req.activePartnerUser;
  const companies = user.companyId
    ? await Company.find({ _id: user.companyId, partnerId: actor.partnerId }).select('_id name').lean()
    : [];
  const sessionId = crypto.randomUUID();
  const token = jwt.sign({
    id: user._id, name: user.name, email: user.email, role: user.role,
    tenantId: user.tenantId, partnerId: user.partnerId, companyId: user.companyId, departmentId: user.departmentId,
    sessionId, impersonatedBy: actor._id, impersonatedByEmail: actor.email,
    impersonatedByName: actor.name,
    impersonatedByRole: 'partner_admin', impersonatorPartnerId: actor.partnerId,
    impersonationMode: 'user_login', impersonationIssuedAt: Date.now(),
  }, process.env.JWT_SECRET, { expiresIn: '4h' });
  await LoginActivity.create({
    userId: actor._id, email: actor.email, companyId: user.companyId,
    partnerAccess: partnerAccessSnapshot(actor, user, companies[0]),
    action: 'partner_impersonation_started', success: true, sessionId,
    failReason: `partner:${actor.partnerId};user:${user._id}`,
    ipAddress: req.ip || req.socket?.remoteAddress || 'unknown', userAgent: req.get('user-agent') || '',
  });
  return token;
}

async function partnerAccessAudit(actor, query = {}) {
  const requestedPage = query.page === undefined ? 1 : Number(query.page);
  if (!Number.isSafeInteger(requestedPage) || requestedPage < 1) throw failure('Invalid audit page.', 400);
  if (query.action && query.action !== 'all' && !AUDIT_ACTIONS.includes(query.action)) throw failure('Invalid audit action.', 400);
  const partnerId = String(actor.partnerId);
  const filter = {
    action: { $in: query.action && query.action !== 'all' ? [query.action] : AUDIT_ACTIONS },
    $or: [
      { 'partnerAccess.partnerId': actor.partnerId },
      // Older logs stored scope in a server-generated marker. Never infer
      // historical ownership from the actor's or target's current partner.
      { 'partnerAccess.partnerId': null, $or: [
        { action: { $in: ['partner_impersonation_started', 'partner_impersonation_ended'] },
          failReason: { $regex: `^partner:${partnerId};user:[a-f0-9]{24}(?:;|$)`, $options: 'i' } },
        { action: 'password_changed',
          failReason: { $regex: `^partner_password_change:partner:${partnerId};user:[a-f0-9]{24}(?:;|$)`, $options: 'i' } },
      ] },
    ],
  };
  const pageSize = 6;
  const total = await LoginActivity.countDocuments(filter);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(total / pageSize)));
  const logs = await LoginActivity.find(filter)
    .select('_id userId email action success createdAt ipAddress failReason partnerAccess')
    .sort({ createdAt: -1, _id: -1 }).skip((page - 1) * pageSize).limit(pageSize).lean();
  // Only enrich legacy names from accounts still managed by this partner.
  // New records use snapshots, so deleted or reassigned accounts retain history.
  const needsNames = logs.some(log => !log.partnerAccess?.targetEmail);
  const { users } = needsNames ? await partnerManagedAccounts(actor) : { users: [] };
  const accounts = new Map(users.map(user => [String(user._id), user]));
  return {
    page, pageSize, total,
    entries: logs.map(log => {
      const snapshot = log.partnerAccess || {};
      const targetId = String(snapshot.targetUserId || /(?:^|;)user:([a-f0-9]{24})(?:;|$)/i.exec(log.failReason || '')?.[1] || '');
      const target = accounts.get(targetId);
      return {
        _id: log._id, action: log.action, success: log.success, createdAt: log.createdAt, ipAddress: log.ipAddress || '',
        actor: { _id: log.userId, name: snapshot.actorName || (same(log.userId, actor._id) ? actor.name : ''), email: log.email },
        target: { _id: targetId, name: snapshot.targetName || target?.name || '',
          email: snapshot.targetEmail || target?.email || '', role: snapshot.targetRole || target?.role || '' },
      };
    }),
  };
}

async function validatePartnerSupportSession(claims) {
  if (!claims.impersonatedBy || !claims.sessionId || !Number.isFinite(claims.impersonationIssuedAt)) {
    throw failure('Invalid partner support session.', 401);
  }
  const actor = await activePartnerActor({ id: claims.impersonatedBy, role: 'partner_admin', partnerId: claims.impersonatorPartnerId, iat: claims.impersonationIssuedAt / 1000 });
  const target = await partnerManagedAccount(actor, claims.id);
  if (!active(target) || ['role', 'tenantId', 'partnerId', 'companyId', 'departmentId'].some(field => !same(target[field], claims[field]))
    || (target.passwordChangedAt && new Date(target.passwordChangedAt).getTime() > claims.impersonationIssuedAt)) {
    throw failure('Partner support session has expired.', 401);
  }
  if (await LoginActivity.exists({ userId: actor._id, sessionId: claims.sessionId, action: 'partner_impersonation_ended', success: true })) {
    throw failure('Partner support session has ended.', 401);
  }
  return { actor, target };
}

module.exports = { MANAGED_ROLES, activePartnerActor, partnerManagedAccounts, partnerManagedAccount, createPartnerLoginToken, validatePartnerSupportSession, partnerAccessSnapshot, partnerAccessAudit };
