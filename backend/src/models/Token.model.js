const mongoose = require('mongoose');

/**
 * Stores short-lived one-time tokens for:
 *  - type: 'invite'         — company user invitation
 *  - type: 'password_reset' — password reset request
 */
const TokenSchema = new mongoose.Schema({
  token:     { type: String, required: true, unique: true, index: true },
  type:      { type: String, enum: ['invite', 'password_reset'], required: true },
  email:     { type: String, required: true },
  tenantId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant' },
  partnerId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Partner' },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company' },
  departmentId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
  departmentIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Department' }],
  role:      { type: String },
  invitedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  expiresAt: { type: Date, required: true },
  used:      { type: Boolean, default: false },
}, { timestamps: true });

// TTL index — MongoDB auto-deletes expired tokens
TokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.model('Token', TokenSchema);
