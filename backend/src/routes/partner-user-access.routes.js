const router = require('express').Router();
const Token = require('../models/Token.model');
const LoginActivity = require('../models/LoginActivity.model');
const { validatePassword } = require('../utils/validate');
const { activePartnerActor, partnerManagedAccounts, partnerManagedAccount, createPartnerLoginToken, partnerAccessSnapshot, partnerAccessAudit } = require('../services/partnerUserAccess.service');

router.use(async (req, res, next) => {
  try {
    req.activePartnerUser = await activePartnerActor(req.user);
    res.set('Cache-Control', 'no-store');
    next();
  } catch (error) {
    res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to verify your Partner Admin session.' });
  }
});

router.get('/', async (req, res) => {
  try {
    const { users, companies } = await partnerManagedAccounts(req.activePartnerUser);
    const names = new Map(companies.map(company => [String(company._id), company.name]));
    res.json(users.map(user => ({ ...user.toJSON(), companyName: names.get(String(user.companyId)) || '' })));
  } catch {
    res.status(503).json({ message: 'Unable to load user accounts. Please retry.' });
  }
});

router.get('/audit', async (req, res) => {
  try {
    res.json(await partnerAccessAudit(req.activePartnerUser, req.query));
  } catch (error) {
    res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to load audit logs. Please retry.' });
  }
});

router.post('/:id/password', async (req, res) => {
  const { newPassword } = req.body || {};
  const passwordError = validatePassword(newPassword);
  if (passwordError) return res.status(400).json({ message: passwordError });
  if (newPassword.length > 128) return res.status(400).json({ message: 'Password must be at most 128 characters.' });
  try {
    const user = await partnerManagedAccount(req.activePartnerUser, req.params.id);
    const passwordChangedAt = new Date();
    await Token.updateMany({ email: user.email, type: 'password_reset', used: false, createdAt: { $lte: passwordChangedAt } }, { $set: { used: true } });
    user.password = newPassword;
    user.passwordChangedAt = passwordChangedAt;
    user.forcePasswordReset = false;
    await user.save();
    await LoginActivity.create({
      userId: req.activePartnerUser._id, email: req.activePartnerUser.email, companyId: user.companyId,
      partnerAccess: partnerAccessSnapshot(req.activePartnerUser, user),
      action: 'password_changed', success: true,
      failReason: `partner_password_change:partner:${req.activePartnerUser.partnerId};user:${user._id}`,
      ipAddress: req.ip || req.socket?.remoteAddress || 'unknown', userAgent: req.get('user-agent') || '',
    }).catch(() => console.error('[partner] Could not record password change activity'));
    res.json({ message: 'Password changed successfully.', userId: user._id, passwordChangedAt });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Unable to change password. Please retry.' });
  }
});

router.post('/:id/impersonate', async (req, res) => {
  try {
    const user = await partnerManagedAccount(req.activePartnerUser, req.params.id);
    const token = await createPartnerLoginToken(req, user);
    res.json({ token, user: { _id: user._id, name: user.name, email: user.email, role: user.role } });
  } catch (error) {
    res.status(error.status || 500).json({ message: error.status ? error.message : 'Unable to log in as this user. Please retry.' });
  }
});

module.exports = router;
