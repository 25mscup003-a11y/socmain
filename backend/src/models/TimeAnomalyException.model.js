const mongoose = require('mongoose');

const TimeAnomalyExceptionSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  reason: { type: String, required: true, trim: true, maxlength: 500 },
  systemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System', required: true }],
  startsAt: { type: Date, required: true },
  expiresAt: { type: Date, required: true },
  enabled: { type: Boolean, default: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

TimeAnomalyExceptionSchema.index({ companyId: 1, systemIds: 1, enabled: 1, startsAt: 1, expiresAt: 1 });
TimeAnomalyExceptionSchema.index({ companyId: 1, expiresAt: -1 });

module.exports = mongoose.model('TimeAnomalyException', TimeAnomalyExceptionSchema);
