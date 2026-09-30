/**
 * twofa.routes.js — Google Authenticator (TOTP) 2FA implementation
 *
 * POST /api/2fa/setup    — Generate secret & QR code
 * POST /api/2fa/verify   — Verify TOTP code & enable 2FA
 * POST /api/2fa/disable  — Disable 2FA
 * POST /api/2fa/validate — Validate TOTP for an authenticated session
 */
const router  = require('express').Router();
const speakeasy = require('speakeasy');
const qrcode    = require('qrcode');
const User      = require('../models/User.model');
const Company   = require('../models/Company.model');
const Partner   = require('../models/Partner.model');
const { authenticate } = require('../middleware/auth.middleware');
const { setTwoFactorSecret, getTwoFactorSecret, clearTwoFactorSecret } = require('../services/userSecrets.service');
const { getOrCreateMainTenant } = require('../utils/tenant');

async function loadTwoFactorUser(userId, selection = '+twoFactorSecret +twoFactorSecretEncrypted') {
  const user = await User.findById(userId).select(`${selection} tenantId companyId partnerId role`);
  if (!user || user.tenantId) return user;

  let tenantId = null;
  let company = null;
  if (user.companyId) {
    company = await Company.findById(user.companyId).select('tenantId partnerId');
    tenantId = company?.tenantId || null;
  }

  const partnerId = user.partnerId || company?.partnerId;
  if (!tenantId && partnerId) {
    const partner = await Partner.findById(partnerId).select('tenantId');
    tenantId = partner?.tenantId || null;
  }

  // Legacy direct-company and superadmin accounts belong to the main tenant.
  if (!tenantId && (company || user.role === 'superadmin')) {
    tenantId = (await getOrCreateMainTenant(user._id))._id;
  }

  if (tenantId) {
    user.tenantId = tenantId;
    await user.save();
  }
  return user;
}

// ── POST /api/2fa/setup — initiate 2FA setup ─────────────────────────────────
router.post('/setup', authenticate, async (req, res) => {
  try {
    const user = await loadTwoFactorUser(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (user.twoFactorEnabled) {
      return res.status(400).json({ message: '2FA is already enabled' });
    }

    // Generate TOTP secret
    const secret = speakeasy.generateSecret({
      name:   `SOC4 (${user.email})`,
      issuer: 'SOC4 Security Platform',
    });

    // Save secret (pending confirm)
    await setTwoFactorSecret(user, secret.base32);
    user.twoFactorPending = true;
    await user.save();

    // Generate QR code
    const qrUrl = await qrcode.toDataURL(secret.otpauth_url);

    res.json({
      secret:    secret.base32,
      qrCode:    qrUrl,
      otpauthUrl: secret.otpauth_url,
      message:   'Scan the QR code with Google Authenticator, then verify with the 6-digit code',
    });
  } catch (err) {
    console.error('[2fa/setup]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/2fa/cancel — discard an unfinished setup ──────────────────────
router.post('/cancel', authenticate, async (req, res) => {
  try {
    const user = await loadTwoFactorUser(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    if (user.twoFactorEnabled) return res.status(400).json({ message: 'Enabled 2FA cannot be cancelled; disable it with a current code' });
    await clearTwoFactorSecret(user);
    user.twoFactorPending = false;
    await user.save();
    res.json({ success: true, message: '2FA setup cancelled' });
  } catch (err) {
    console.error('[2fa/cancel]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/2fa/verify — confirm code & enable 2FA ─────────────────────────
router.post('/verify', authenticate, async (req, res) => {
  const { code } = req.body;

  if (!/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ message: 'Please provide a valid 6-digit TOTP code' });
  }

  try {
    const user = await loadTwoFactorUser(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const twoFactorSecret = await getTwoFactorSecret(user);
    if (!twoFactorSecret || !user.twoFactorPending) {
      return res.status(400).json({ message: 'Please start 2FA setup first' });
    }

    // Verify the TOTP code
    const isValid = speakeasy.totp.verify({
      secret: twoFactorSecret,
      encoding: 'base32',
      token:  code,
      window: 1, // allow 1 step window for clock drift
    });

    if (!isValid) {
      return res.status(400).json({ message: 'Invalid code. Please try again.' });
    }

    // Enable 2FA
    user.twoFactorEnabled = true;
    user.twoFactorPending = false;
    await user.save();

    // Company-level posture reflects the Company Admin account only. Enabling
    // an individual SOC analyst must not change the whole company's 2FA flag.
    if (user.role === 'company_admin' && user.companyId) {
      await Company.findByIdAndUpdate(user.companyId, {
        twoFactorEnabled: true,
      });
    }

    res.json({ success: true, message: '2FA enabled successfully! Your account is now more secure.' });
  } catch (err) {
    console.error('[2fa/verify]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/2fa/disable — disable 2FA ──────────────────────────────────────
router.post('/disable', authenticate, async (req, res) => {
  const { code } = req.body;

  if (!/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ message: 'Please provide your current 6-digit code to disable 2FA' });
  }

  try {
    const user = await loadTwoFactorUser(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    if (!user.twoFactorEnabled) {
      return res.status(400).json({ message: '2FA is not enabled' });
    }

    // Verify the current TOTP code before disabling
    const twoFactorSecret = await getTwoFactorSecret(user);
    const isValid = speakeasy.totp.verify({
      secret:   twoFactorSecret,
      encoding: 'base32',
      token:    code,
      window:   1,
    });

    if (!isValid) {
      return res.status(400).json({ message: 'Invalid code. Cannot disable 2FA.' });
    }

    user.twoFactorEnabled = false;
    await clearTwoFactorSecret(user);
    user.twoFactorPending = false;
    await user.save();

    if (user.role === 'company_admin' && user.companyId) {
      await Company.findByIdAndUpdate(user.companyId, { twoFactorEnabled: false });
    }

    res.json({ success: true, message: '2FA disabled successfully.' });
  } catch (err) {
    console.error('[2fa/disable]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/2fa/validate — validate TOTP for current authenticated user ────
router.post('/validate', authenticate, async (req, res) => {
  const { code } = req.body;

  if (!/^\d{6}$/.test(String(code || ''))) {
    return res.status(400).json({ message: 'A valid 6-digit code is required' });
  }

  try {
    const user = await loadTwoFactorUser(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });

    const twoFactorSecret = user.twoFactorEnabled ? await getTwoFactorSecret(user) : null;
    if (!user.twoFactorEnabled || !twoFactorSecret) {
      return res.status(400).json({ message: '2FA is not enabled for this account' });
    }

    const isValid = speakeasy.totp.verify({
      secret:   twoFactorSecret,
      encoding: 'base32',
      token:    code,
      window:   1,
    });

    if (!isValid) {
      return res.status(401).json({ message: 'Invalid 2FA code. Please try again.' });
    }

    res.json({ success: true, message: '2FA validated' });
  } catch (err) {
    console.error('[2fa/validate]', err.message);
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/2fa/status — get 2FA status for current user ────────────────────
router.get('/status', authenticate, async (req, res) => {
  try {
    const user = await loadTwoFactorUser(req.user.id, 'twoFactorEnabled twoFactorPending email');
    if (!user) return res.status(404).json({ message: 'User not found' });

    res.json({
      enabled: user.twoFactorEnabled,
      pending: user.twoFactorPending,
      email:   user.email,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
