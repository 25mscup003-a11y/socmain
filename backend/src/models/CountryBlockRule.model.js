const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
  countryCode: { type: String, required: true },
  direction: { type: String, enum: ['inbound', 'outbound', 'both'], required: true },
  scope: { type: String, enum: ['company', 'department', 'system'], required: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null,
    required: function () { return ['department', 'system'].includes(this.scope); } },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null },
  enabled: { type: Boolean, default: true },
  reason: { type: String, default: '', maxlength: 500 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });
schema.index({ companyId: 1, countryCode: 1, scope: 1, departmentId: 1, systemId: 1, direction: 1 }, { unique: true });
schema.index({ companyId: 1, enabled: 1, departmentId: 1 });
schema.index({ companyId: 1, enabled: 1, systemId: 1 });
module.exports = mongoose.models.CountryBlockRule || mongoose.model('CountryBlockRule', schema);
