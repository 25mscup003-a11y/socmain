const mongoose = require('mongoose');

const SocIncidentAuditReviewSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  incidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', required: true, unique: true, index: true },
  auditType: { type: String, enum: ['standard', 'threat'], default: 'standard', index: true },
  closureAction: { type: String, enum: ['resolve', 'false_positive'], required: true },
  sourceRole: { type: String, enum: ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'], required: true, index: true },
  reviewerRole: { type: String, enum: ['l2_analyst', 'l3_analyst', 'soc_manager'], required: true, index: true },
  submittedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  submittedAt: { type: Date, default: Date.now, index: true },
  submissionCount: { type: Number, default: 0 },
  status: { type: String, enum: ['pending', 'approved', 'changes_requested'], default: 'pending', index: true },
  reviewNote: { type: String, default: '', maxlength: 5000 },
  reviewedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  reviewedAt: { type: Date, default: null },
}, { timestamps: true });

SocIncidentAuditReviewSchema.index({ reviewerRole: 1, auditType: 1, status: 1, submittedAt: -1 });
SocIncidentAuditReviewSchema.index({ submittedBy: 1, submittedAt: -1 });

module.exports = mongoose.model('SocIncidentAuditReview', SocIncidentAuditReviewSchema);
