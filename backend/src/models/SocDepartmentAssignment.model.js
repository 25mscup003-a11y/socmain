const mongoose = require('mongoose');

const SocDepartmentAssignmentSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', required: true, index: true },
  assignedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  active: { type: Boolean, default: true, index: true },
}, { timestamps: true });

SocDepartmentAssignmentSchema.index({ userId: 1, departmentId: 1 }, { unique: true });
SocDepartmentAssignmentSchema.index({ tenantId: 1, companyId: 1, active: 1 });

module.exports = mongoose.model('SocDepartmentAssignment', SocDepartmentAssignmentSchema);
