const mongoose = require('mongoose');

const NetworkPolicySchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  description: { type: String, default: '', trim: true, maxlength: 2000 },
  enabled: { type: Boolean, default: true, index: true },
  scope: {
    endpointGroups: [{ type: String, maxlength: 128 }],
    serverGroups: [{ type: String, maxlength: 128 }],
    assetIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
    users: [{ type: String, maxlength: 512 }],
  },
  conditions: [{
    field: { type: String, required: true, enum: [
      'destinationReputation', 'state', 'bytesSent', 'destinationIp',
      'destinationPort', 'protocol', 'processName', 'riskScore', 'direction',
      'newDestination', 'newCountry', 'beaconing', 'scanning', 'lateralMovement',
      'connectionCount', 'averageInterval', 'jitterSeconds',
      'intervalConsistency', 'observationSeconds',
    ] },
    operator: { type: String, required: true, enum: ['eq', 'ne', 'gt', 'gte', 'lt', 'lte', 'in', 'not_in', 'contains'] },
    value: { type: mongoose.Schema.Types.Mixed, required: true },
  }],
  actions: {
    severity: { type: String, enum: ['low', 'medium', 'elevated', 'high', 'critical'], default: 'high' },
    riskScore: { type: Number, min: 0, max: 100, default: 70 },
    createAlert: { type: Boolean, default: true },
    block: { type: Boolean, default: false },
  },
  suppressionSeconds: { type: Number, min: 0, max: 86400, default: 900 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

NetworkPolicySchema.index({ companyId: 1, name: 1 }, { unique: true });
NetworkPolicySchema.index({ companyId: 1, enabled: 1, updatedAt: -1 });

module.exports = mongoose.models.NetworkPolicy || mongoose.model('NetworkPolicy', NetworkPolicySchema);
