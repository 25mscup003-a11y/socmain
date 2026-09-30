const mongoose = require('mongoose');

const SecurityEventSchema = new mongoose.Schema({
  eventType: {
    type: String,
    required: true,
    enum: [
      'LOGIN_FAILED',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'PASSWORD_RESET_REQUESTED',
      'PASSWORD_CHANGED',
      'SESSION_REVOKED',
      'UNAUTHORIZED_ACCESS_ATTEMPT',
      'CROSS_TENANT_ACCESS_ATTEMPT',
      'ROLE_PERMISSION_DENIED',
      'INVITATION_ABUSE_ATTEMPT',
      'RATE_LIMIT_TRIGGERED',
      'SUSPICIOUS_LOGIN',
      'API_TOKEN_FAILURE'
    ]
  },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  user: { type: String, default: null },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  role: { type: String, default: null },
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null },
  ipAddress: { type: String, default: null },
  userAgent: { type: String, default: null },
  resource: { type: String, default: null },
  requestId: { type: String, default: null },
  status: { type: String, enum: ['detected', 'reviewed', 'resolved'], default: 'detected' },
  details: { type: mongoose.Schema.Types.Mixed, default: {} }
}, { timestamps: true });

SecurityEventSchema.index({ eventType: 1, createdAt: -1 });
SecurityEventSchema.index({ userId: 1, createdAt: -1 });
SecurityEventSchema.index({ companyId: 1, createdAt: -1 });

module.exports = mongoose.models.SecurityEvent || mongoose.model('SecurityEvent', SecurityEventSchema);
