const mongoose = require('mongoose');

const DepartmentSchema = new mongoose.Schema({
  name:        { type: String, required: true },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  description: { type: String, default: '' },
  adminId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  systemCount: { type: Number, default: 0 },
  assignedSystemCount: { type: Number, default: 0 },
  assignedPhoneCount:  { type: Number, default: 0 },
  assignedServerCount: { type: Number, default: 0 },
  isActive:    { type: Boolean, default: true },
}, { timestamps: true });

DepartmentSchema.index({ name: 1, companyId: 1 }, { unique: true });

module.exports = mongoose.model('Department', DepartmentSchema);
