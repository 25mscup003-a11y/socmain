const mongoose = require('mongoose');

/**
 * LoginActivity Model
 * Tracks every login attempt, successful login, failed login, and logout.
 * Provides comprehensive analytics beyond simple login count.
 */
const LoginActivitySchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  email:     { type: String, required: true, index: true },

  // Immutable account-access identity, retained if a user is renamed or moved.
  partnerAccess: {
    type: new mongoose.Schema({
      partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', required: true },
      partnerName: String,
      actorName: String,
      targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
      targetName: String,
      targetEmail: String,
      targetRole: String,
      companyName: String,
    }, { _id: false }),
    default: undefined,
  },

  // Event type
  action: {
    type: String,
    enum: [
      'login_success',
      'session_resumed',
      'screen_locked',
      'screen_unlocked',
      'auto_logout',
      'login_failed',
      'logout',
      'otp_verified',
      'otp_failed',
      'otp_required',
      'password_reset',
      'superadmin_impersonation_started',
      'superadmin_company_impersonation_started',
      'superadmin_impersonation_blocked',
      'superadmin_company_impersonation_blocked',
      'partner_impersonation_started',
      'partner_impersonation_ended',
      'partner_impersonation_blocked',
      'partner_updated',
      'company_updated',
      'company_plan_updated',
      'company_payment_updated',
      'company_autopay_updated',
      'company_status_updated',
      'company_created',
      'admin_updated',
      'password_changed',
    ],
    required: true,
    index: true,
  },

  // Result
  success:    { type: Boolean, default: false },
  failReason: { type: String }, // wrong_password, user_not_found, account_locked, otp_expired, etc.

  // Client info
  ipAddress:  { type: String },
  userAgent:  { type: String },
  browser:    { type: String },
  os:         { type: String },
  device:     { type: String },

  // Session
  sessionId: { type: String }, // Stable across token refreshes; never a bearer token.
  sessionToken: { type: String }, // JWT token hash (not actual token)
  
  // Geo (optional, can be enriched later)
  geoCountry: { type: String },
  geoCity:    { type: String },
  geoRegion:  { type: String },
  geoTimezone:{ type: String },
  geoISP:     { type: String },
  geoLat:     { type: Number },
  geoLon:     { type: Number },

  // User-approved browser Geolocation API reading. This is client-supplied
  // evidence and is kept separate from the server-derived IP location above.
  browserLocation: {
    permission: { type: String, enum: ['granted', 'denied', 'prompt', 'unavailable', 'unsupported', 'declined'] },
    latitude: { type: Number, min: -90, max: 90 },
    longitude: { type: Number, min: -180, max: 180 },
    accuracyMeters: { type: Number, min: 0 },
    capturedAt: { type: Date },
    source: { type: String, default: 'browser_geolocation' },
  },

}, { timestamps: true });

// Indexes for fast queries
LoginActivitySchema.index({ companyId: 1, createdAt: -1 });
LoginActivitySchema.index({ userId: 1, createdAt: -1 });
LoginActivitySchema.index({ 'partnerAccess.partnerId': 1, createdAt: -1, _id: -1 });
LoginActivitySchema.index({ userId: 1, sessionId: 1, createdAt: -1 });
LoginActivitySchema.index({ email: 1, action: 1, createdAt: -1 });
LoginActivitySchema.index({ companyId: 1, action: 1, createdAt: -1 });

// Auto-delete logs older than 1 year
LoginActivitySchema.index({ createdAt: 1 }, { expireAfterSeconds: 365 * 24 * 60 * 60 });

module.exports = mongoose.model('LoginActivity', LoginActivitySchema);
