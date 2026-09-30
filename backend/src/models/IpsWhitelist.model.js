const mongoose = require('mongoose');

const IpsWhitelistSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  value: { type: String, required: true, trim: true },
  type: { type: String, enum: ['ip', 'cidr', 'domain'], default: 'ip', index: true },
  reason: { type: String, default: '', trim: true, maxlength: 500 },
  source: { type: String, default: 'manual' },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

IpsWhitelistSchema.index({ companyId: 1, value: 1 }, { unique: true });

module.exports = mongoose.models.IpsWhitelist
  || mongoose.model('IpsWhitelist', IpsWhitelistSchema);
