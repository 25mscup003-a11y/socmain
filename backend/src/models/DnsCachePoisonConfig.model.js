const mongoose = require('mongoose');

const DnsCachePoisonCustomRuleSchema = new mongoose.Schema({
  id: { type: String, required: true, maxlength: 80 },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  domain: { type: String, required: true, trim: true, lowercase: true, maxlength: 253 },
  queryType: { type: String, enum: ['A', 'AAAA'], default: 'A' },
  expectedIps: { type: [{ type: String, maxlength: 45 }], default: [] },
  severity: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  enabled: { type: Boolean, default: true },
}, { _id: false });

const DnsCachePoisonConfigSchema = new mongoose.Schema({
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Company',
    required: true,
    unique: true,
    index: true,
  },
  enabled: { type: Boolean, default: true },
  telemetryEnabled: { type: Boolean, default: true },
  watchDomains: { type: [{ type: String, maxlength: 253 }], default: [] },
  trustedResolvers: { type: [{ type: String, maxlength: 45 }], default: [] },
  scanIntervalSeconds: { type: Number, min: 60, max: 3600, default: 300 },
  minSafeTtl: { type: Number, min: 1, max: 86400, default: 30 },
  maxSafeTtl: { type: Number, min: 30, max: 604800, default: 86400 },
  baselineWindowSeconds: { type: Number, min: 60, max: 86400, default: 3600 },
  monitorResolverChanges: { type: Boolean, default: true },
  monitorHostsChanges: { type: Boolean, default: true },
  detectPrivateAnswers: { type: Boolean, default: true },
  builtInRuleIds: {
    type: [{ type: String, maxlength: 80 }],
    default: ['private-answer', 'ttl-anomaly', 'resolver-change', 'hosts-file-change'],
  },
  builtInRuleOverrides: { type: mongoose.Schema.Types.Mixed, default: {} },
  customRules: { type: [DnsCachePoisonCustomRuleSchema], default: [] },
  targetMode: { type: String, enum: ['all', 'selected'], default: 'all' },
  targetSystemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
  version: { type: Number, min: 1, default: 1 },
  lastDeployedAt: { type: Date, default: null },
  lastDeployedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

module.exports = mongoose.models.DnsCachePoisonConfig
  || mongoose.model('DnsCachePoisonConfig', DnsCachePoisonConfigSchema);
