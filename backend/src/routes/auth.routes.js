const { emitPartnerUpdate } = require('../utils/partnerRealtime');
const router = require('express').Router();
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const LoginActivity = require('../models/LoginActivity.model');
const SuperadminLoginAudit = require('../models/SuperadminLoginAudit.model');
const Tenant = require('../models/Tenant.model');
const { generateOTP, sendOTP } = require('../utils/emailService');
const {
  getOrCreateMainTenant,
  resolveReferralTenant,
  buildDashboardUrl,
} = require('../utils/tenant');
const {
  validateEmail, validatePassword, validatePhone,
  validateCompanyName, firstError,
} = require('../utils/validate');
const { authenticate, requireAnalyst } = require('../middleware/auth.middleware');
const { registerPartner } = require('../controllers/partnerRegistration.controller');
const { getSubscriptionEntitlement } = require('../utils/subscriptionEntitlement');
const { processFraudCheck } = require('../services/fraud.service');
const { getTwoFactorSecret } = require('../services/userSecrets.service');
const { ensureDefaultSoarPlaybooks } = require('../services/defaultSoarPlaybooks.service');
const stytchConfig = require('../config/stytch.config');
const { companyLoginScope, transformLoginActionCounts } = require('../utils/loginAnalytics');
const { getClientIp } = require('../utils/clientIp');
const { parseUserAgent } = require('../utils/userAgent');
const { enrichIp } = require('../services/ipEnrichmentService');

function scheduleLoginLocationEnrichment(activity) {
  if (!activity?._id || !activity.ipAddress || activity.ipAddress === 'unknown') return;
  setImmediate(async () => {
    try {
      const result = await enrichIp(activity.ipAddress);
      const [lat, lon] = String(result?.loc || '').split(',').map(Number);
      const update = {
        geoCountry: result?.country || result?.countryCode || undefined,
        geoCity: result?.city || undefined,
        geoRegion: result?.region || undefined,
        geoTimezone: result?.timezone || undefined,
        geoISP: result?.organization || undefined,
        geoLat: Number.isFinite(lat) ? lat : undefined,
        geoLon: Number.isFinite(lon) ? lon : undefined,
      };
      Object.keys(update).forEach(key => update[key] === undefined && delete update[key]);
      if (Object.keys(update).length) await LoginActivity.updateOne({ _id: activity._id }, { $set: update });
    } catch (error) {
      console.error('[LoginTracker:geo]', error.message);
    }
  });
}

function browserLocationFromRequest(req) {
  const input = req.body?.location;
  if (!input || typeof input !== 'object') return undefined;
  const allowedPermissions = new Set(['granted', 'denied', 'prompt', 'unavailable', 'unsupported', 'declined']);
  const permission = allowedPermissions.has(input.permission) ? input.permission : 'unavailable';
  const latitude = Number(input.latitude);
  const longitude = Number(input.longitude);
  const accuracyMeters = Number(input.accuracyMeters);
  const capturedAt = new Date(input.capturedAt);
  const coordinatesValid = permission === 'granted'
    && Number.isFinite(latitude) && latitude >= -90 && latitude <= 90
    && Number.isFinite(longitude) && longitude >= -180 && longitude <= 180;
  const capturedAtValid = !Number.isNaN(capturedAt.getTime())
    && capturedAt.getTime() <= Date.now() + (5 * 60 * 1000)
    && capturedAt.getTime() >= Date.now() - (24 * 60 * 60 * 1000);
  return {
    permission,
    ...(coordinatesValid ? {
      latitude,
      longitude,
      accuracyMeters: Number.isFinite(accuracyMeters) && accuracyMeters >= 0 ? Math.min(accuracyMeters, 100000) : undefined,
      capturedAt: capturedAtValid ? capturedAt : new Date(),
    } : {}),
    source: 'browser_geolocation',
  };
}

// Helper: record login activity (fire-and-forget)
function trackLogin(req, userId, companyId, email, action, success, failReason) {
  if (req?.user?.impersonatedBy) return Promise.resolve(null);
  if (action === 'login_success') req.loginSessionId = crypto.randomUUID();
  const userAgent = req.get('user-agent') || '';
  const client = parseUserAgent(userAgent);
  return LoginActivity.create({
    userId,
    companyId,
    email,
    action,
    success,
    sessionId: req.user?.sessionId || req.loginSessionId,
    failReason: failReason || undefined,
    ipAddress: getClientIp(req),
    userAgent,
    browserLocation: browserLocationFromRequest(req),
    ...client,
  }).then(activity => {
    const io = req.app.get('io');
    scheduleLoginLocationEnrichment(activity);
    if (activity.companyId) io?.to(`company:${activity.companyId}`).emit('geo:login', activity);
    if (!io) return;
    const decision = action === 'otp_required'
      ? 'CHALLENGE'
      : (success ? 'ALLOW' : 'AUTH_FAILED');
    io.to('fraud:stream').emit('fraud:auth-event', {
      _id: activity._id,
      requestId: `login-${activity._id}`,
      companyId: activity.companyId,
      email: activity.email,
      ipAddress: activity.ipAddress,
      browser: activity.browser,
      os: activity.os,
      action: activity.action,
      success: activity.success,
      failReason: activity.failReason,
      decision,
      riskScore: null,
      riskLevel: null,
      source: 'authentication',
      createdAt: activity.createdAt,
      simulated: false,
    });
  }).catch(err => console.error('[LoginTracker]', err.message));
}

async function trackSessionResume(req, user) {
  if (!user?._id || req.user?.impersonatedBy) return;
  const recentSessionEvent = await LoginActivity.exists({
    userId: user._id,
    action: { $in: ['login_success', 'session_resumed'] },
    success: true,
    createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) },
  });
  if (recentSessionEvent) return;
  await trackLogin(req, user._id, user.companyId, user.email, 'session_resumed', true);
}

const sign = (user, extra = {}) =>
  jwt.sign(
    {
      id: user._id,
      email: user.email,
      role: user.role,
      tenantId: user.tenantId,
      partnerId: user.partnerId,
      companyId: user.companyId,
      departmentId: user.departmentId,
      ...extra,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );

// Public partner registration endpoint. Kept under /auth so public forms never
// pass through partner/admin route middleware.
router.post('/partner-register', registerPartner);

router.get('/me', authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: 'User not found' });
    // Support sessions must keep their actor and original expiry on refresh.
    // Otherwise /me silently upgrades an impersonation token to a normal login.
    if (req.user.impersonatedBy) {
      if (!user.isActive || (user.accountStatus && user.accountStatus !== 'active')) {
        return res.status(401).json({ message: 'This user account is no longer active' });
      }
      const actor = await User.findById(req.user.impersonatedBy);
      if (!actor || actor.role !== 'superadmin' || !actor.isActive
        || (actor.accountStatus && actor.accountStatus !== 'active')
        || [actor, user].some(account => account.passwordChangedAt
          && new Date(account.passwordChangedAt).getTime() > Number(req.user.iat) * 1000)) {
        return res.status(401).json({ message: 'Superadmin login session has expired' });
      }
    }
    const payload = await authPayload(user, {
      sessionId: req.user.sessionId,
      mfaVerified: req.user.mfaVerified === true,
      mfaVerifiedAt: req.user.mfaVerifiedAt || null,
      amr: Array.isArray(req.user.amr) ? req.user.amr : [],
    });
    await trackSessionResume(req, user);
    res.json({
      ...payload,
      ...(req.user.impersonatedBy ? { token: req.headers.authorization.slice(7) } : {}),
      impersonation: req.user.impersonatedBy ? {
        active: true,
        by: req.user.impersonatedBy,
        mode: req.user.impersonationMode || 'support_debug',
        banner: `You are logged in as ${user.name || user.email} (${user.role.replaceAll('_', ' ')}) via Super Admin`,
      } : null,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

async function authPayload(user, authContext = {}) {
  let company = null;
  let tenant = null;
  let partner = null;
  if (user.companyId) {
    const companyDocument = await Company.findById(user.companyId);
    if (companyDocument) {
      company = companyDocument.toObject();
      company.entitlement = await getSubscriptionEntitlement(companyDocument);
    }
  }
  if (user.tenantId) tenant = await Tenant.findById(user.tenantId);
  if (user.partnerId) {
    const Partner = require('../models/Partner.model');
    partner = await Partner.findById(user.partnerId)
      .select('-agreementDataUrl -profile.avatarDataUrl -profile.kycDocuments.gstCertificateDataUrl -profile.kycDocuments.panCardDataUrl -profile.kycDocuments.businessRegistrationDataUrl');
  }
  if (!tenant && user.role === 'superadmin') tenant = await getOrCreateMainTenant(user._id);

  return {
    token: sign(user, authContext),
    user,
    company,
    tenant,
    partner,
    requiresPasswordReset: !!user.forcePasswordReset,
    partnerPaymentRequired: user.role === 'partner_admin'
      ? !(partner?.plan?.paymentStatus === 'paid' && partner?.plan?.isActive === true)
      : false,
    redirectUrl: buildDashboardUrl(user, tenant),
  };
}

// POST /api/auth/signup
router.post(['/signup', '/signup/:referralSlug'], async (req, res) => {
  const { companyName, email, password, phone } = req.body;

  // ── Validate all fields before touching DB ──
  const check = firstError([
    validateCompanyName(companyName),
    validateEmail(email),
    validatePassword(password),
    validatePhone(phone),
  ]);
  if (!check.valid) return res.status(400).json({ message: check.message });

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = companyName.trim();

  try {
    const { tenant, partner, referral } = await resolveReferralTenant(req.params.referralSlug);
    if (partner && !partner.capabilities?.createCompany) {
      return res.status(403).json({ message: 'Partner company creation is disabled until resource approval' });
    }
    const existing = await User.findOne({ email: cleanEmail });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const companyExists = await Company.findOne({ email: cleanEmail });
    if (companyExists) return res.status(400).json({ message: 'Company with this email already exists' });

    const agentKey = crypto.randomBytes(24).toString('hex');
    const company = await Company.create({
      name: cleanName,
      email: cleanEmail,
      phone: phone?.trim() || '',
      tenantId: tenant._id,
      partnerId: partner?._id || null,
      referralId: referral?._id || null,
      source: referral ? 'partner_referral' : 'public',
      company_type: partner ? 'PARTNER_MANAGED' : 'DIRECT',
      agentKey,
      status: 'pending_payment',
    });

    const otp = generateOTP();
    const user = await User.create({
      name: cleanName + ' Admin',
      email: cleanEmail,
      password,
      phone: phone?.trim() || '',
      role: 'company_admin',
      tenantId: tenant._id,
      partnerId: partner?._id || null,
      companyId: company._id,
      otp: otp,
      otpExpires: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
      otpAttempts: 0,
    });

    // Send OTP to email
    try {
      await sendOTP(cleanEmail, otp, cleanName);
    } catch (emailErr) {
      console.error('OTP email failed:', emailErr);
      // Continue anyway - OTP is saved in DB
    }

    if (referral) {
      await referral.updateOne({ $inc: { signups: 1 } });
    }

    // ── Fraud check on signup (async, non-blocking unless BLOCKED) ──
    if (stytchConfig.fraudEnabled) {
      try {
        const fraudResult = await processFraudCheck({
          telemetryId: req.body.telemetry_id || null,
          ipAddress: getClientIp(req),
          userAgent: req.get('user-agent') || '',
          action: 'signup',
          email: cleanEmail,
          userId: user._id,
          companyId: company._id,
          allowAuthFallback: true,
          browserLocation: browserLocationFromRequest(req),
        });
        if (fraudResult.blocked) {
          // Rollback user and company creation on hard block
          await user.deleteOne().catch(() => {});
          await company.deleteOne().catch(() => {});
          return res.status(403).json({ message: 'Registration blocked due to security policy. Please contact support.', blocked: true });
        }
      } catch (fraudErr) {
        console.error('[auth/signup] fraud check error (non-fatal):', fraudErr.message);
      }
    }

    emitPartnerUpdate(req.app?.get?.('io'), company.partnerId, 'company_created', company._id);
    await ensureDefaultSoarPlaybooks({
      companyId: company._id,
      tenantId: company.tenantId,
      partnerId: company.partnerId,
      createdBy: user._id,
    }).catch(error => console.error('[auth/signup] default SOAR playbooks:', error.message));

    res.status(201).json({
      message: 'Account created. OTP sent to your email. Please verify to continue.',
      email: cleanEmail,
      userId: user._id,
      companyId: company._id,
      tenant,
      partner,
      referralSlug: referral?.slug || null,
      requiresOTP: true,
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// POST /api/auth/verify-otp (Registration)
router.post('/verify-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() })
      .select('+twoFactorSecret +twoFactorSecretEncrypted');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP is expired
    if (!user.otpExpires || new Date() > user.otpExpires) {
      return res.status(400).json({ message: 'OTP has expired. Please request a new one.' });
    }

    // Check OTP attempts
    if (user.otpAttempts >= 5) {
      return res.status(429).json({ message: 'Too many attempts. Please try again later.' });
    }

    // Verify OTP
    if (user.otp !== otp.trim()) {
      user.otpAttempts += 1;
      await user.save();
      return res.status(400).json({
        message: 'Invalid OTP',
        remainingAttempts: 5 - user.otpAttempts,
      });
    }

    // OTP verified successfully - CRITICAL: Set isEmailVerified = true
    console.log(`[VERIFY-REGIST-OTP] 🔍 Verifying OTP for ${user.email}`);

    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        $set: { isEmailVerified: true },  // Use $set operator for reliability
        otp: null,
        otpExpires: null,
        otpAttempts: 0,
      },
      { new: true }
    );

    console.log(`[VERIFY-REGIST-OTP] ✅ Updated - isEmailVerified: ${updatedUser.isEmailVerified}`);

    // Verify change persisted to DB
    const verified = await User.findById(user._id);
    console.log(`[VERIFY-REGIST-OTP] 📋 DB Check - isEmailVerified: ${verified.isEmailVerified}`);

    if (!verified.isEmailVerified) {
      console.error(`[VERIFY-REGIST-OTP] ❌ WARNING: Flag not persisted! Trying again...`);
      verified.isEmailVerified = true;
      await verified.save();
      console.log(`[VERIFY-REGIST-OTP] ✅ Saved again - isEmailVerified: ${verified.isEmailVerified}`);
    }

    const company = await Company.findById(updatedUser.companyId);
    const tenant = updatedUser.tenantId ? await Tenant.findById(updatedUser.tenantId) : null;

    res.json({
      message: 'Email verified successfully!',
      token: sign(updatedUser, { mfaVerified: true, mfaVerifiedAt: Date.now(), amr: ['pwd', 'email_otp'] }),
      user: updatedUser,
      company,
      tenant,
      redirectUrl: buildDashboardUrl(updatedUser, tenant),
    });
  } catch (err) {
    return res.status(500).json({ message: err.message });
  }
});

// POST /api/auth/resend-otp
router.post('/resend-otp', async (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.status(400).json({ message: 'Email is required' });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const newOtp = generateOTP();
    user.otp = newOtp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes
    user.otpAttempts = 0;
    await user.save();

    // Send new OTP
    try {
      await sendOTP(email.trim().toLowerCase(), newOtp, user.name);
    } catch (emailErr) {
      console.error('OTP resend failed:', emailErr);
    }

    res.json({ message: 'OTP resent to your email' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


router.post('/superadmin-signup', async (req, res) => {
  const { name, email, password, phone } = req.body;

  // ── Validate all fields before touching DB ──
  const check = firstError([
    validateCompanyName(name),
    validateEmail(email),
    validatePassword(password),
    validatePhone(phone || ''),
  ]);
  if (!check.valid) return res.status(400).json({ message: check.message });

  const cleanEmail = email.trim().toLowerCase();
  const cleanName = name.trim();

  try {
    const existing = await User.findOne({ email: cleanEmail });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const user = await User.create({
      name: cleanName,
      email: cleanEmail,
      password,
      phone: phone?.trim() || '',
      role: 'superadmin',
      tenantId: (await getOrCreateMainTenant())._id,
      isActive: true,
      isEmailVerified: true,  // ✅ Email pre-verified for superadmin
    });

    res.status(201).json({
      token: sign(user),
      user,
      tenant: await getOrCreateMainTenant(user._id),
      redirectUrl: buildDashboardUrl(user, await getOrCreateMainTenant(user._id)),
      message: 'Superadmin account created successfully',
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

// POST /api/auth/login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password)
    return res.status(400).json({ message: 'Email and password are required' });

  const check = firstError([validateEmail(email)]);
  if (!check.valid) return res.status(400).json({ message: check.message });

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user || !user.isActive) {
      trackLogin(req, null, null, email.trim().toLowerCase(), 'login_failed', false, 'user_not_found');
      return res.status(401).json({ message: 'User not found' });
    }

    const match = await user.comparePassword(password);
    if (!match) {
      trackLogin(req, user._id, user.companyId, user.email, 'login_failed', false, 'wrong_password');
      return res.status(401).json({ message: 'Wrong password' });
    }

    if (user.role === 'superadmin') {
      const updatedUser = await User.findByIdAndUpdate(
        user._id,
        {
          otp: null,
          otpExpires: null,
          otpAttempts: 0,
          isEmailVerified: true,
          lastLogin: new Date(),
        },
        { new: true }
      ).select('+twoFactorSecret +twoFactorSecretEncrypted');

      if (stytchConfig.fraudEnabled) {
        try {
          const fraudResult = await processFraudCheck({
            telemetryId: req.body.telemetry_id || null,
            ipAddress: getClientIp(req),
            userAgent: req.get('user-agent') || '',
            action: 'admin_login',
            email: updatedUser.email,
            userId: updatedUser._id,
            companyId: updatedUser.companyId,
            allowAuthFallback: true,
            browserLocation: browserLocationFromRequest(req),
          });
          if (fraudResult.blocked) {
            trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'login_failed', false, 'fraud_block');
            return res.status(403).json({ message: 'Login blocked due to security policy.', blocked: true, fraudEventId: fraudResult.fraudEventId });
          }
        } catch (fraudErr) {
          console.error('[auth/login] superadmin fraud check error (non-fatal):', fraudErr.message);
        }
      }

      const superAdminTotpSecret = updatedUser.twoFactorEnabled ? await getTwoFactorSecret(updatedUser) : null;
      if (updatedUser.twoFactorEnabled && superAdminTotpSecret) {
        trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'otp_required', true);
        return res.json({
          message: 'Please enter your Google Authenticator code to complete login.',
          email: updatedUser.email,
          requires2FA: true,
        });
      }

      await trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'login_success', true);
      return res.json({
        message: 'Login successful',
        ...(await authPayload(updatedUser, { sessionId: req.loginSessionId })),
      });
    }

    const otp = generateOTP();
    await User.findByIdAndUpdate(
      user._id,
      {
        otp,
        otpExpires: new Date(Date.now() + 10 * 60 * 1000),
        otpAttempts: 0,
      }
    );

    try {
      await sendOTP(user.email, otp, user.name);
    } catch (emailErr) {
      console.error('OTP email failed:', emailErr);
    }

    // ── Fraud check before issuing OTP ──────────────────────────────────
    if (stytchConfig.fraudEnabled) {
      try {
        const fraudResult = await processFraudCheck({
          telemetryId: req.body.telemetry_id || null,
          ipAddress: getClientIp(req),
          userAgent: req.get('user-agent') || '',
          action: 'login',
          email: user.email,
          userId: user._id,
          companyId: user.companyId,
          allowAuthFallback: true,
          browserLocation: browserLocationFromRequest(req),
        });
        if (fraudResult.blocked) {
          trackLogin(req, user._id, user.companyId, user.email, 'login_failed', false, 'fraud_block');
          return res.status(403).json({ message: 'Login blocked due to security policy.', blocked: true, fraudEventId: fraudResult.fraudEventId });
        }
      } catch (fraudErr) {
        console.error('[auth/login] fraud check error (non-fatal):', fraudErr.message);
      }
    }

    trackLogin(req, user._id, user.companyId, user.email, 'otp_required', true);

    return res.status(200).json({
      message: 'OTP sent to your email. Please verify to login.',
      email: user.email,
      userId: user._id,
      requiresOTP: true,
      nextStep: 'email_otp',
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// POST /api/auth/verify-login-otp
router.post('/verify-login-otp', async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ message: 'Email and OTP are required' });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Check if OTP is expired
    if (!user.otpExpires || new Date() > user.otpExpires) {
      trackLogin(req, user._id, user.companyId, user.email, 'otp_failed', false, 'otp_expired');
      return res.status(400).json({ message: 'OTP has expired. Please login again.' });
    }

    // Check OTP attempts
    if (user.otpAttempts >= 5) {
      trackLogin(req, user._id, user.companyId, user.email, 'login_failed', false, 'account_locked');
      return res.status(429).json({ message: 'Too many attempts. Your account is temporarily locked.' });
    }

    // Verify OTP
    if (user.otp !== otp.trim()) {
      user.otpAttempts += 1;
      await user.save();
      trackLogin(req, user._id, user.companyId, user.email, 'otp_failed', false, user.otpAttempts >= 5 ? 'account_locked' : 'otp_invalid');
      return res.status(400).json({
        message: 'Invalid OTP',
        remainingAttempts: 5 - user.otpAttempts,
      });
    }

    // OTP verified successfully - use findByIdAndUpdate for atomic update
    console.log(`[VERIFY-LOGIN-OTP] Verifying OTP for ${user.email}`);
    const updatedUser = await User.findByIdAndUpdate(
      user._id,
      {
        otp: null,
        otpExpires: null,
        otpAttempts: 0,
        isEmailVerified: true,  // ✅ Mark email as verified
        lastLogin: new Date(),  // ✅ Track login timestamp
      },
      { new: true }
    ).select('+twoFactorSecret +twoFactorSecretEncrypted');
    console.log(`[VERIFY-LOGIN-OTP] User ${updatedUser.email} - isEmailVerified: ${updatedUser.isEmailVerified}`);

    // ── Fraud check after OTP verification — before issuing token ───────
    if (stytchConfig.fraudEnabled) {
      try {
        const fraudResult = await processFraudCheck({
          telemetryId: req.body.telemetry_id || null,
          ipAddress: getClientIp(req),
          userAgent: req.get('user-agent') || '',
          action: 'login',
          email: updatedUser.email,
          userId: updatedUser._id,
          companyId: updatedUser.companyId,
          allowAuthFallback: true,
          browserLocation: browserLocationFromRequest(req),
        });
        if (fraudResult.blocked) {
          trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'login_failed', false, 'fraud_block');
          return res.status(403).json({ message: 'Login blocked due to security policy.', blocked: true, fraudEventId: fraudResult.fraudEventId });
        }
      } catch (fraudErr) {
        console.error('[auth/verify-login-otp] fraud check error (non-fatal):', fraudErr.message);
      }
    }

    trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'otp_verified', true);
    const loginTotpSecret = updatedUser.twoFactorEnabled ? await getTwoFactorSecret(updatedUser) : null;
    if (updatedUser.twoFactorEnabled && loginTotpSecret) {
      trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'otp_required', true);
      return res.json({
        message: 'Email OTP verified. Please enter your Google Authenticator code to complete login.',
        email: updatedUser.email,
        requires2FA: true,
      });
    }

    await trackLogin(req, updatedUser._id, updatedUser.companyId, updatedUser.email, 'login_success', true);

    res.json({
      message: 'Login successful',
      ...(await authPayload(updatedUser, { sessionId: req.loginSessionId, mfaVerified: true, mfaVerifiedAt: Date.now(), amr: ['pwd', 'email_otp'] })),
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── POST /api/auth/verify-2fa-login — TOTP 2FA verification before dashboard ──
router.post('/verify-2fa-login', async (req, res) => {
  const { email, code } = req.body;

  if (!email || !code) {
    return res.status(400).json({ message: 'Email and 2FA code are required' });
  }

  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    return res.status(400).json({ message: 'Please enter a valid 6-digit code' });
  }

  try {
    const user = await User.findOne({ email: email.trim().toLowerCase() })
      .select('+twoFactorSecret +twoFactorSecretEncrypted');
    if (!user || !user.isActive) {
      return res.status(404).json({ message: 'User not found' });
    }

    const twoFactorSecret = user.twoFactorEnabled ? await getTwoFactorSecret(user) : null;
    if (!user.twoFactorEnabled || !twoFactorSecret) {
      return res.status(400).json({ message: '2FA is not enabled for this account' });
    }

    // Verify TOTP code using speakeasy
    const speakeasy = require('speakeasy');
    const isValid = speakeasy.totp.verify({
      secret: twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 1,  // allow 30-second clock drift
    });

    if (!isValid) {
      trackLogin(req, user._id, user.companyId, user.email, 'otp_failed', false, '2fa_invalid_code');
      return res.status(401).json({ message: 'Invalid authenticator code. Please check Google Authenticator and try again.' });
    }

    // 2FA verified — complete login
    await User.findByIdAndUpdate(user._id, { lastLogin: new Date() });

    trackLogin(req, user._id, user.companyId, user.email, 'otp_verified', true);
    await trackLogin(req, user._id, user.companyId, user.email, 'login_success', true);

    console.log(`[LOGIN] ✅ 2FA verified for ${user.email} — Login complete`);

    res.json({
      message: '2FA verified. Login successful.',
      ...(await authPayload(user, { sessionId: req.loginSessionId, mfaVerified: true, mfaVerifiedAt: Date.now(), amr: ['pwd', 'email_otp', 'totp'] })),
    });
  } catch (err) {
    console.error('[verify-2fa-login]', err.message);
    res.status(500).json({ message: err.message });
  }
});


router.post('/session-event', authenticate, async (req, res) => {
  try {
    const action = String(req.body?.action || '').trim().toLowerCase();
    if (!['screen_locked', 'screen_unlocked'].includes(action)) {
      return res.status(400).json({ message: 'Unsupported session event' });
    }
    const reason = String(req.body?.reason || '').trim().slice(0, 100) || undefined;
    await trackLogin(req, req.user._id || req.user.id, req.user.companyId, req.user.email || '', action, true, reason);
    res.json({ message: action === 'screen_locked' ? 'Screen lock recorded' : 'Screen unlock recorded' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

router.post('/logout', authenticate, async (req, res) => {
  try {
    if (req.user.impersonatedBy && req.user.sessionId) {
      await SuperadminLoginAudit.updateOne({
        sessionId: req.user.sessionId, actorId: req.user.impersonatedBy,
        targetUserId: req.user.id, logoutAt: null,
      }, { $set: { logoutAt: new Date() } });
    }
    const automatic = String(req.body?.reason || '').toLowerCase() === 'inactivity';
    await trackLogin(
      req,
      req.user._id || req.user.id,
      req.user.companyId,
      req.user.email || '',
      automatic ? 'auto_logout' : 'logout',
      true,
      automatic ? 'idle_timeout_30m' : undefined,
    );
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// ── GET /api/auth/login-analytics — login stats for company ──────────────────
router.get('/login-analytics', authenticate, requireAnalyst, async (req, res) => {
  try {
    const companyId = req.user.companyId;
    const since24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const since7d = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const since30d = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);

    const baseFilter = companyLoginScope(companyId);
    if (!baseFilter) {
      return res.status(403).json({ message: 'A valid company context is required for login analytics' });
    }

    const [
      stats24h,
      stats7d,
      stats30d,
      recentFailures,
      recentActivity,
      failureReasons30d,
      failedUsers30d,
      locations30d,
      perUserStats,
      perHourDistribution,
    ] = await Promise.all([
      // 24h breakdown
      LoginActivity.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since24h } } },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 },
          }
        },
      ]),
      // 7d breakdown
      LoginActivity.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since7d } } },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 },
          }
        },
      ]),
      // 30d totals
      LoginActivity.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since30d } } },
        {
          $group: {
            _id: '$action',
            count: { $sum: 1 },
          }
        },
      ]),
      // Recent failed logins (last 50)
      LoginActivity.find({ ...baseFilter, action: { $in: ['login_failed', 'otp_failed'] }, createdAt: { $gte: since30d } })
        .sort({ createdAt: -1 })
        .limit(50)
        .select('email action success ipAddress failReason userAgent geoCountry geoCity createdAt')
        .lean(),
      // Recent tenant login activity for the dashboard event table.
      LoginActivity.find({ ...baseFilter, createdAt: { $gte: since30d } })
        .sort({ createdAt: -1 })
        .limit(200)
        .select('email action success ipAddress failReason browser os device geoCountry geoCity createdAt')
        .lean(),
      LoginActivity.aggregate([
        { $match: { ...baseFilter, success: false, createdAt: { $gte: since30d } } },
        { $group: { _id: { $ifNull: ['$failReason', 'unknown'] }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
      // Exact failed-user totals; the recent event list is intentionally bounded.
      LoginActivity.aggregate([
        {
          $match: {
            ...baseFilter,
            action: { $in: ['login_failed', 'otp_failed'] },
            createdAt: { $gte: since30d },
          },
        },
        {
          $group: {
            _id: { $ifNull: ['$email', 'unknown'] },
            count: { $sum: 1 },
            lastFailed: { $max: '$createdAt' },
          },
        },
        { $sort: { count: -1, lastFailed: -1 } },
        { $limit: 20 },
        { $project: { _id: 0, email: '$_id', count: 1, lastFailed: 1 } },
      ]),
      // Only return real geo-enriched login attempts; missing geo is not a location.
      LoginActivity.aggregate([
        {
          $match: {
            ...baseFilter,
            action: { $in: ['login_success', 'login_failed', 'otp_verified', 'otp_failed'] },
            createdAt: { $gte: since30d },
            geoCountry: { $exists: true, $nin: [null, ''] },
          },
        },
        { $group: { _id: { country: '$geoCountry', city: '$geoCity' }, count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 20 },
        { $project: { _id: 0, country: '$_id.country', city: '$_id.city', count: 1 } },
      ]),
      // Per-user stats (top 20 active users)
      LoginActivity.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since7d } } },
        { $sort: { createdAt: 1 } },
        {
          $group: {
            _id: '$email',
            totalLogins: { $sum: { $cond: [{ $eq: ['$action', 'login_success'] }, 1, 0] } },
            totalFailed: { $sum: { $cond: [{ $eq: ['$action', 'login_failed'] }, 1, 0] } },
            totalLogouts: { $sum: { $cond: [{ $eq: ['$action', 'logout'] }, 1, 0] } },
            lastLogin: { $max: { $cond: [{ $eq: ['$action', 'login_success'] }, '$createdAt', null] } },
            lastIp: { $last: '$ipAddress' },
            uniqueIps: { $addToSet: '$ipAddress' },
          }
        },
        { $sort: { totalLogins: -1 } },
        { $limit: 20 },
        {
          $project: {
            email: '$_id',
            totalLogins: 1,
            totalFailed: 1,
            totalLogouts: 1,
            lastLogin: 1,
            lastIp: 1,
            uniqueIpCount: { $size: '$uniqueIps' },
          }
        },
      ]),
      // Per-hour distribution (24h)
      LoginActivity.aggregate([
        { $match: { ...baseFilter, createdAt: { $gte: since24h } } },
        {
          $group: {
            _id: { hour: { $hour: '$createdAt' }, action: '$action' },
            count: { $sum: 1 },
          }
        },
        { $sort: { '_id.hour': 1 } },
      ]),
    ]);

    res.json({
      period24h: transformLoginActionCounts(stats24h),
      period7d: transformLoginActionCounts(stats7d),
      period30d: transformLoginActionCounts(stats30d),
      recentFailures,
      recentActivity,
      failureReasons30d: Object.fromEntries(failureReasons30d.map(item => [item._id, item.count])),
      failedUsers30d,
      locations30d,
      perUserStats,
      perHourDistribution,
    });
  } catch (err) {
    console.error('[auth/login-analytics]', err.message);
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
