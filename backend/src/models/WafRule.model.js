const mongoose = require('mongoose');

/**
 * WafRule — Custom WAF Detection Rules
 * =====================================
 * Company admin creates custom HTTP-layer rules.
 * SOC Agents fetch these rules every 5 min and apply them in real-time WAF.
 */
const WafRuleSchema = new mongoose.Schema({
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  name:        { type: String, required: true, trim: true },
  description: { type: String, default: '' },
  pattern:     { type: String, required: true },   // regex pattern string
  flags:       { type: String, default: 'i' },     // regex flags: i, g, m, s
  attackType:  { type: String, required: true },   // e.g. "SQL Injection", "CMS Exploit"
  severity:    { type: String, enum: ['critical','high','medium','low'], default: 'high' },
  targets:     { type: [String], default: ['url','body','headers'] }, // what to check
  action:      { type: String, enum: ['block','log'], default: 'block' },
  enabled:     { type: Boolean, default: true },
  hitCount:    { type: Number,  default: 0 },
  lastHitAt:   { type: Date },
  createdBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

module.exports = mongoose.model('WafRule', WafRuleSchema);
