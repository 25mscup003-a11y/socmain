const mongoose = require('mongoose');

const SystemChangeControlSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  kind: { type: String, enum: ['baseline', 'exception'], required: true, index: true },
  category: { type: String, default: '', trim: true, maxlength: 120 },
  changeType: { type: String, default: '', trim: true, maxlength: 120 },
  target: { type: String, required: true, trim: true, maxlength: 2048 },
  processName: { type: String, default: '', trim: true, maxlength: 260 },
  expectedState: { type: mongoose.Schema.Types.Mixed, default: null },
  reason: { type: String, required: true, trim: true, maxlength: 1000 },
  ticketReference: { type: String, default: '', trim: true, maxlength: 160 },
  temporary: { type: Boolean, default: false },
  expiresAt: { type: Date, default: null, index: true },
  enabled: { type: Boolean, default: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

SystemChangeControlSchema.index({ companyId: 1, departmentId: 1, kind: 1, enabled: 1, createdAt: -1 });
SystemChangeControlSchema.index({ companyId: 1, systemId: 1, target: 1, kind: 1, enabled: 1 });

module.exports = mongoose.model('SystemChangeControl', SystemChangeControlSchema);
