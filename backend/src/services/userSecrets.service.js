const { encryptValue, decryptValue } = require('./tenantKms.service');

async function setTwoFactorSecret(user, secret) {
  if (!user?._id || !user.tenantId) throw new Error('User tenant identity is required to encrypt the MFA secret');
  user.twoFactorSecretEncrypted = await encryptValue({
    tenantId: user.tenantId,
    companyId: user.companyId || null,
    purpose: 'user-totp-secret',
    recordId: user._id,
    value: String(secret),
    actorId: user._id,
  });
  user.twoFactorSecret = null;
}

async function getTwoFactorSecret(user, { migrateLegacy = true } = {}) {
  if (!user?._id || !user.tenantId) return null;
  if (user.twoFactorSecretEncrypted?.ciphertext) {
    return decryptValue({
      tenantId: user.tenantId,
      companyId: user.companyId || null,
      purpose: 'user-totp-secret',
      recordId: user._id,
      envelope: user.twoFactorSecretEncrypted,
    });
  }
  if (!user.twoFactorSecret) return null;
  const legacy = String(user.twoFactorSecret);
  if (migrateLegacy) {
    await setTwoFactorSecret(user, legacy);
    await user.save();
  }
  return legacy;
}

async function clearTwoFactorSecret(user) {
  user.twoFactorSecret = null;
  user.twoFactorSecretEncrypted = null;
}

module.exports = { setTwoFactorSecret, getTwoFactorSecret, clearTwoFactorSecret };
