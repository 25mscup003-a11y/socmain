const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null },

  name:         { type: String, required: true, trim: true, maxlength: 120 },
  type:         { type: String, enum: ['generic_rest', 'webhook', 'smtp', 'slack', 'teams', 'zeek', 'suricata', 'threat_intel', 'ip_reputation', 'firewall', 'endpoint', 'ticketing'], required: true },
  baseUrl:      { type: String, default: '' },
  authType:     { type: String, enum: ['none', 'api_key', 'bearer', 'basic', 'oauth2', 'custom_header', 'mtls'], default: 'none' },
  credentialId: { type: mongoose.Schema.Types.ObjectId, ref: 'SoarCredential', default: null },
  headers:      { type: mongoose.Schema.Types.Mixed, default: {} },
  timeoutMs:    { type: Number, default: 8000, min: 500, max: 60000 },
  retryCount:   { type: Number, default: 2, min: 0, max: 10 },
  rateLimitPerMinute: { type: Number, default: 60, min: 1, max: 10000 },
  verifyTls:    { type: Boolean, default: true },
  status:       { type: String, enum: ['enabled', 'disabled', 'unhealthy'], default: 'disabled', index: true },
  lastHealthCheck: Date,
  lastSuccessAt:   Date,
  lastError:    { type: String, default: '' },
  createdBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  deletedAt:    { type: Date, default: null },
}, { timestamps: true });

schema.index({ companyId: 1, type: 1, status: 1 });

module.exports = mongoose.model('SoarConnector', schema);
