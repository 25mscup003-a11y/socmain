const mongoose = require('mongoose');

const AuditEntrySchema = new mongoose.Schema({
  action: { type: String, required: true, maxlength: 80 },
  message: { type: String, default: '', maxlength: 600 },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  actorRole: { type: String, default: 'system', maxlength: 40 },
  at: { type: Date, default: Date.now },
}, { _id: false });

const ResponseActionSchema = new mongoose.Schema({
  actionType: {
    type: String,
    enum: ['lock_account', 'force_logoff', 'isolate', 'block_ip'],
    required: true,
  },
  responseId: { type: mongoose.Schema.Types.ObjectId, ref: 'AutomatedResponse', default: null },
  actionSource: { type: String, enum: ['manual_response', 'agent_policy'], default: 'manual_response' },
  status: { type: String, default: 'created', maxlength: 40 },
  result: { type: String, default: '', maxlength: 1000 },
  requestedAt: { type: Date, default: Date.now },
  completedAt: { type: Date, default: null },
}, { _id: false });

const UebaProfileLockEventSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', required: true, unique: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', required: true, index: true },
  agentId: { type: String, default: '', maxlength: 128 },
  hostname: { type: String, default: '', maxlength: 255 },
  username: { type: String, required: true, maxlength: 128 },
  sourceType: {
    type: String,
    enum: ['ueba_profile_mismatch', 'geolocation_response'],
    default: 'ueba_profile_mismatch',
    index: true,
  },
  sourceCapabilityId: { type: Number, default: 11, index: true },
  detectionName: { type: String, default: '', maxlength: 300 },
  sourceIp: { type: String, default: '', maxlength: 64 },
  geoCountry: { type: String, default: '', maxlength: 128 },
  geoCity: { type: String, default: '', maxlength: 128 },
  status: {
    type: String,
    enum: [
      'detected', 'response_pending', 'response_success', 'response_failed',
      'lock_dispatching', 'lock_pending', 'locked', 'lock_failed', 'lock_skipped',
      'unlock_pending', 'unlocked', 'unlock_failed',
    ],
    default: 'detected',
    index: true,
  },
  riskScore: { type: Number, min: 0, max: 100, default: 0 },
  confidence: { type: Number, min: 0, max: 100, default: 0 },
  baselineDays: { type: Number, min: 0, max: 30, default: 0 },
  mismatchFeatures: [{ type: String, maxlength: 64 }],
  featureDeviation: { type: mongoose.Schema.Types.Mixed, default: {} },
  privacyMode: { type: String, default: 'aggregate_counts_only', maxlength: 64 },
  verificationMessage: { type: String, default: 'Behavioral profile mismatch detected; interactive identity verification is required.', maxlength: 600 },
  lockResponseId: { type: mongoose.Schema.Types.ObjectId, ref: 'AutomatedResponse', default: null, index: true },
  unlockResponseId: { type: mongoose.Schema.Types.ObjectId, ref: 'AutomatedResponse', default: null, index: true },
  responseActions: { type: [ResponseActionSchema], default: [] },
  lockedAt: { type: Date, default: null },
  unlockedAt: { type: Date, default: null },
  unlockedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  unlockReason: { type: String, default: '', maxlength: 500 },
  notificationRecipients: [{ type: String, maxlength: 320 }],
  notificationStatus: { type: String, enum: ['pending', 'sent', 'failed', 'not_configured', 'suppressed_duplicate'], default: 'pending' },
  notificationError: { type: String, default: '', maxlength: 500 },
  auditTrail: { type: [AuditEntrySchema], default: [] },
}, { timestamps: true });

UebaProfileLockEventSchema.index({ companyId: 1, createdAt: -1 });
UebaProfileLockEventSchema.index({ companyId: 1, status: 1, createdAt: -1 });
UebaProfileLockEventSchema.index({ companyId: 1, departmentId: 1, createdAt: -1 });

module.exports = mongoose.model('UebaProfileLockEvent', UebaProfileLockEventSchema);
