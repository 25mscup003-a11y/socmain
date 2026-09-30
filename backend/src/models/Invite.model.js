const mongoose = require('mongoose');

const InviteSchema = new mongoose.Schema({
  tenantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  email:     { type: String, required: true, lowercase: true, trim: true },
  role:      { type: String, required: true },
  tokenHash: { type: String, required: true },
  status:    { type: String, enum: ['pending', 'accepted', 'expired', 'revoked'], default: 'pending' },
  expiresAt: { type: Date, required: true },
  acceptedAt:{ type: Date, default: null },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

InviteSchema.index({ email: 1, status: 1 });

module.exports = mongoose.model('Invite', InviteSchema);
