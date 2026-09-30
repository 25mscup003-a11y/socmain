const mongoose = require('mongoose');

const DnsSinkholeRuleSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  type: { type: String, enum: ['blocklist', 'redirect', 'allowlist'], required: true, index: true },
  domain: { type: String, required: true, index: true },
  sinkholeIp: { type: String, maxlength: 45, default: null },
  reason: { type: String },
  addedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

DnsSinkholeRuleSchema.index({ companyId: 1, type: 1, domain: 1 }, { unique: true });

module.exports = mongoose.models.DnsSinkholeRule || mongoose.model('DnsSinkholeRule', DnsSinkholeRuleSchema);
