const mongoose = require('mongoose');

const SocInvitationSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  email: { type: String, required: true, lowercase: true, trim: true, index: true },
  name: { type: String, trim: true, default: '' },
  role: {
    type: String,
    enum: ['soc_manager', 'l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'],
    required: true,
    index: true,
  },
  tokenHash: { type: String, required: true, unique: true, select: false },
  status: {
    type: String,
    enum: ['pending', 'accepted', 'expired', 'revoked'],
    default: 'pending',
    index: true,
  },
  expiresAt: { type: Date, required: true, index: true },
  acceptedAt: { type: Date, default: null },
  revokedAt: { type: Date, default: null },
  invitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  socManagerPool: { type: Boolean, default: false },
  superadminManaged: { type: Boolean, default: false, index: true },
}, { timestamps: true });

SocInvitationSchema.index({ tenantId: 1, email: 1, status: 1 });
SocInvitationSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 30 * 24 * 60 * 60 });

module.exports = mongoose.model('SocInvitation', SocInvitationSchema);
