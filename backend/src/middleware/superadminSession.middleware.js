const User = require('../models/User.model');

async function requireActiveSuperadminSession(req, res, next) {
  try {
    const userId = req.user?.id || req.user?._id;
    const user = userId
      ? await User.findOne({
        _id: userId, role: 'superadmin', isActive: true,
        $or: [{ accountStatus: 'active' }, { accountStatus: { $exists: false } }],
      })
        .select('_id name email role passwordChangedAt').lean()
      : null;
    if (!user) return res.status(401).json({ message: 'Superadmin session is no longer active' });
    if (user.passwordChangedAt && req.user.iat
      && user.passwordChangedAt.getTime() > Number(req.user.iat) * 1000) {
      return res.status(401).json({ message: 'Session expired after credential change' });
    }
    req.activeUser = user;
    next();
  } catch (err) {
    next(err);
  }
}

function requireOriginalSuperadminSession(req, res, next) {
  if (req.user?.impersonatedBy) {
    return res.status(403).json({ message: 'Return to your original Superadmin session to log in as another user.' });
  }
  next();
}

module.exports = { requireActiveSuperadminSession, requireOriginalSuperadminSession };
