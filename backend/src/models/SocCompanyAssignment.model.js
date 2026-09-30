const mongoose = require('mongoose');

const SocCompanyAssignmentSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  active: { type: Boolean, default: true, index: true },
}, { timestamps: true });

SocCompanyAssignmentSchema.index({ userId: 1, companyId: 1 }, { unique: true });
SocCompanyAssignmentSchema.index({ tenantId: 1, companyId: 1, active: 1 });

module.exports = mongoose.model('SocCompanyAssignment', SocCompanyAssignmentSchema);
