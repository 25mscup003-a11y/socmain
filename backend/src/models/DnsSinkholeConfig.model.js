const mongoose = require('mongoose');

const DnsSinkholeConfigSchema = new mongoose.Schema({
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Company',
    required: true,
    unique: true,
  },
  enabled: { type: Boolean, default: true },
  sinkholeIp: { type: String, default: '0.0.0.0', maxlength: 45 },
  enforcementMode: {
    type: String,
    enum: ['hosts', 'dnsmasq', 'both'],
    default: 'both',
  },
  telemetryEnabled: { type: Boolean, default: true },
  reportIntervalSeconds: { type: Number, min: 60, max: 3600, default: 300 },
  syncBlocklist: { type: Boolean, default: true },
  builtInRuleIds: {
    type: [{ type: String, maxlength: 80 }],
    default: [
      'company-blocklist-enforcement',
      'dns-anomaly-detection',
      'dns-beaconing-detection',
      'sinkhole-policy-telemetry',
    ],
  },
  builtInRuleOverrides: { type: mongoose.Schema.Types.Mixed, default: {} },
  targetMode: { type: String, enum: ['all', 'selected'], default: 'all' },
  targetSystemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
  version: { type: Number, min: 1, default: 1 },
  lastDeployedAt: { type: Date, default: null },
  lastDeployedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

module.exports = mongoose.models.DnsSinkholeConfig
  || mongoose.model('DnsSinkholeConfig', DnsSinkholeConfigSchema);
