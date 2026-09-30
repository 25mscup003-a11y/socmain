const mongoose = require('mongoose');

const SocInvitationScopeSchema = new mongoose.Schema({
  invitationId: { type: mongoose.Schema.Types.ObjectId, ref: 'SocInvitation', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
}, { timestamps: true });

SocInvitationScopeSchema.index(
  { invitationId: 1, companyId: 1, departmentId: 1 },
  { unique: true },
);

module.exports = mongoose.model('SocInvitationScope', SocInvitationScopeSchema);
