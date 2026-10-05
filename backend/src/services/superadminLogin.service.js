const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const SuperadminLoginAudit = require('../models/SuperadminLoginAudit.model');

// Every superadmin "Login as" entry point must issue its token and persist its
// private audit together. The shared session ID also connects the logout time.
async function createSuperadminLoginToken(req, user, mode = 'user_login', scope = {}) {
  if (!req.activeUser || req.user?.impersonatedBy) {
    const error = new Error('Use your original active Superadmin session to log in as another user.');
    error.statusCode = 403;
    throw error;
  }
  if (!user.isActive || (user.accountStatus && user.accountStatus !== 'active')) {
    const error = new Error('This account is not active. Activate it before logging in.');
    error.statusCode = 403;
    throw error;
  }
  const sessionId = crypto.randomUUID();
  const token = jwt.sign({
    id: user._id, email: user.email, role: user.role,
    tenantId: user.tenantId, partnerId: user.partnerId,
    companyId: user.companyId, departmentId: user.departmentId,
    ...scope,
    sessionId,
    impersonatedBy: req.activeUser._id,
    impersonatedByEmail: req.activeUser.email,
    impersonatedByRole: 'superadmin', impersonationMode: mode,
  }, process.env.JWT_SECRET, { expiresIn: '4h' });
  await SuperadminLoginAudit.create({
    sessionId,
    actorId: req.activeUser._id, actorName: req.activeUser.name, actorEmail: req.activeUser.email,
    targetUserId: user._id, targetName: user.name, targetEmail: user.email, targetRole: user.role,
    ipAddress: String(req.ip || req.socket?.remoteAddress || 'unknown').replace(/^::ffff:/, '').replace(/^::1$/, '127.0.0.1'),
    userAgent: req.get('user-agent') || '',
  });
  return token;
}

module.exports = { createSuperadminLoginToken };
