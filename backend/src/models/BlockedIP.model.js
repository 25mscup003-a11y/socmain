/**
 * BlockedIP.model.js
 * Tracks all IP blocks: auto-blocker by IPS or manual by analyst
 */
const mongoose = require('mongoose');

const BlockSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true },
  ip: { type: String, required: true, index: true },
  port: { type: Number },  // optional port (null = all ports)
  reason: String,
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert' },
  blockedBy: { type: String, enum: ['auto', 'analyst', 'soar'], default: 'auto' },
  method: { type: String },   // 'pfsense', 'opnsense', 'webhook', 'dual-firewall'
  reverted: { type: Boolean, default: false, index: true },
  revertedAt: { type: Date },
  revertReason: { type: String },
  blockedAt: { type: Date, default: Date.now, index: true },
  expiresAt: { type: Date },
  blockFailureReason: String, // reason if block failed
}, { timestamps: true });

BlockSchema.index({ companyId: 1, ip: 1 }, { unique: true, partialFilterExpression: { reverted: false } });
BlockSchema.index({ blockedAt: 1 }, { expireAfterSeconds: 86400 * 30 }); // Auto-delete after 30 days

module.exports = mongoose.models.BlockedIP || mongoose.model('BlockedIP', BlockSchema);
