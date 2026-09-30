const mongoose = require('mongoose');

const ReferralSchema = new mongoose.Schema({
  tenantId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  slug:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  url:       { type: String, required: true },
  status:    { type: String, enum: ['active', 'disabled'], default: 'active' },
  clicks:    { type: Number, default: 0 },
  signups:   { type: Number, default: 0 },
  expiresAt: { type: Date, default: null },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

module.exports = mongoose.model('Referral', ReferralSchema);
