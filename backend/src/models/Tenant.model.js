const mongoose = require('mongoose');

const TenantSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true },
  slug:      { type: String, required: true, unique: true, lowercase: true, trim: true },
  type:      { type: String, enum: ['main', 'partner'], required: true, default: 'partner' },
  subdomain: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
  status:    { type: String, enum: ['active', 'suspended'], default: 'active' },
  branding:  { type: mongoose.Schema.Types.Mixed, default: {} },
  settings:  { type: mongoose.Schema.Types.Mixed, default: {} },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

TenantSchema.index({ type: 1, status: 1 });

module.exports = mongoose.model('Tenant', TenantSchema);
