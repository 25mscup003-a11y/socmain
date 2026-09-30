const mongoose = require('mongoose');

const schema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null },

  name:         { type: String, required: true, trim: true },
  type:         { type: String, enum: ['api_key', 'password', 'bearer_token', 'oauth_secret', 'private_key', 'certificate', 'webhook_secret', 'custom'], required: true },
  encryptedValue:{ type: String, default: '', select: false }, // legacy vault format
  iv:           { type: String, default: '', select: false },
  authTag:      { type: String, default: '', select: false },
  encrypted:    { type: mongoose.Schema.Types.Mixed, default: null, select: false },
  version:      { type: Number, default: 1 },
  lastUsedAt:   Date,
  rotatedAt:    Date,
  createdBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

schema.index({ companyId: 1, name: 1 });

schema.methods.toJSON = function () {
  const o = this.toObject();
  delete o.encryptedValue;
  delete o.iv;
  delete o.authTag;
  delete o.encrypted;
  o.masked = '••••••••';
  return o;
};

module.exports = mongoose.model('SoarCredential', schema);
