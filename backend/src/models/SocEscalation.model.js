const mongoose = require('mongoose');

const SocEscalationSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null, index: true },
  incidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', default: null, index: true },
  resourceType: { type: String, enum: ['alert', 'incident'], default: 'alert', index: true },
  fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  fromLevel: { type: String, enum: ['l1', 'l2', 'l3', 'manager'], required: true },
  toLevel: { type: String, enum: ['l2', 'l3', 'manager'], required: true, index: true },
  assignedTo: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  reason: { type: String, required: true, trim: true, maxlength: 2000 },
  summary: { type: String, default: '', trim: true, maxlength: 5000 },
  observedIoc: { type: String, default: '', trim: true, maxlength: 1000 },
  affectedAsset: { type: String, default: '', trim: true, maxlength: 500 },
  priority: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'high' },
  status: { type: String, enum: ['pending', 'accepted', 'rejected', 'resolved'], default: 'pending', index: true },
  managerNote: { type: String, default: '', trim: true, maxlength: 3000 },
  resolvedAt: { type: Date, default: null },
}, { timestamps: true });

SocEscalationSchema.pre('validate', function requireResource(next) {
  if (!this.alertId && !this.incidentId) return next(new Error('An alert or incident resource is required'));
  if (this.alertId && this.incidentId) return next(new Error('Escalation must reference only one resource'));
  this.resourceType = this.incidentId ? 'incident' : 'alert';
  next();
});

SocEscalationSchema.index({ tenantId: 1, companyId: 1, status: 1, createdAt: -1 });
SocEscalationSchema.index({ assignedTo: 1, status: 1, createdAt: -1 });
SocEscalationSchema.index({ companyId: 1, toLevel: 1, status: 1, createdAt: -1 });
SocEscalationSchema.index({ fromUserId: 1, toLevel: 1, createdAt: -1 });

module.exports = mongoose.model('SocEscalation', SocEscalationSchema);
