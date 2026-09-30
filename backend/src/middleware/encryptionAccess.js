const User = require('../models/User.model');

const ROLE_PERMISSIONS = Object.freeze({
  superadmin: ['view', 'encrypt', 'decrypt_request', 'decrypt', 'approve', 'key_manage', 'audit_export'],
  company_admin: ['view', 'encrypt', 'decrypt_request', 'decrypt', 'audit_export'],
  soc_manager: ['view', 'encrypt', 'decrypt_request', 'decrypt', 'approve', 'key_manage', 'audit_export'],
  l2_analyst: ['view', 'decrypt_request', 'decrypt'],
  l3_analyst: ['view', 'encrypt', 'decrypt_request', 'decrypt'],
  l4_analyst: ['view', 'encrypt', 'decrypt_request', 'decrypt'],
});

function requireEncryptionPermission(permission) {
  return (req, res, next) => {
    const allowed = ROLE_PERMISSIONS[req.user?.role] || [];
    if (!allowed.includes(permission)) {
      return res.status(403).json({ message: `Encryption permission '${permission}' is required` });
    }
    next();
  };
}

async function requireFreshMfa(req, res, next) {
  try {
    const maxAgeMs = Math.max(60_000, Number(process.env.DECRYPT_MFA_MAX_AGE_MS || 15 * 60_000));
    const verifiedAt = Number(req.user?.mfaVerifiedAt || 0);
    if (req.user?.mfaVerified !== true || !verifiedAt || Date.now() - verifiedAt > maxAgeMs) {
      return res.status(403).json({ message: 'Fresh MFA verification is required for this cryptographic operation', code: 'MFA_REQUIRED' });
    }
    const user = await User.findById(req.user.id).select('isActive accountStatus twoFactorEnabled');
    if (!user?.isActive || user.accountStatus === 'disabled' || user.accountStatus === 'suspended') {
      return res.status(403).json({ message: 'Active user identity is required' });
    }
    next();
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
}

const buckets = new Map();
function cryptoRateLimit(req, res, next) {
  const windowMs = Math.max(10_000, Number(process.env.CRYPTO_API_RATE_WINDOW_MS || 60_000));
  const max = Math.max(1, Number(process.env.CRYPTO_API_RATE_LIMIT || 60));
  const key = `${req.user?.id || req.ip}:${req.path}`;
  const now = Date.now();
  const current = buckets.get(key);
  if (!current || current.resetAt <= now) {
    buckets.set(key, { count: 1, resetAt: now + windowMs });
    return next();
  }
  current.count += 1;
  if (current.count > max) {
    res.setHeader('Retry-After', Math.ceil((current.resetAt - now) / 1000));
    return res.status(429).json({ message: 'Cryptography API rate limit exceeded' });
  }
  next();
}

module.exports = { ROLE_PERMISSIONS, requireEncryptionPermission, requireFreshMfa, cryptoRateLimit };
