const mongoose = require('mongoose');

const IdsIpsPolicySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  description: { type: String, default: '', trim: true, maxlength: 500 },
  presetId: { type: String, default: '', trim: true, maxlength: 80 },
  sensor: { type: String, enum: ['any', 'suricata', 'zeek'], default: 'any' },
  targetPlatform: { type: String, enum: ['all', 'windows', 'linux', 'macos', 'android'], default: 'all', index: true },
  targetSystemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  enabled: { type: Boolean, default: true, index: true },
  mode: { type: String, enum: ['detect', 'block'], default: 'detect' },
  minimumSeverity: {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
  },
  attackPattern: { type: String, default: '', trim: true, maxlength: 160 },
  protocol: { type: String, default: 'any', trim: true, lowercase: true },
  sourceIp: { type: String, default: '', trim: true },
  destinationPort: { type: Number, min: 1, max: 65535 },
  matchCount: { type: Number, default: 0 },
  lastMatchAt: { type: Date },
  revision: { type: Number, default: 1, min: 1 },
  deploymentStatus: {
    type: String,
    enum: ['pending', 'deployed', 'server_enforced', 'failed', 'partial', 'not_targeted'],
    default: 'pending',
    index: true,
  },
  deploymentAcks: [{
    systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System' },
    agentId: String,
    hostname: String,
    revision: Number,
    ok: Boolean,
    result: String,
    appliedAt: Date,
  }],
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

IdsIpsPolicySchema.index({ companyId: 1, enabled: 1, createdAt: -1 });
IdsIpsPolicySchema.index({ companyId: 1, presetId: 1 }, { unique: true, partialFilterExpression: { presetId: { $type: 'string', $gt: '' } } });

module.exports = mongoose.models.IdsIpsPolicy
  || mongoose.model('IdsIpsPolicy', IdsIpsPolicySchema);
