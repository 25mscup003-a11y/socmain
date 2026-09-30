const mongoose = require('mongoose');

const SocAuditEventSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  action: { type: String, required: true, trim: true, maxlength: 100, index: true },
  targetType: { type: String, required: true, trim: true, maxlength: 50 },
  targetId: { type: String, default: '', maxlength: 100 },
  metadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  ipAddress: { type: String, default: '' },
}, { timestamps: true });

SocAuditEventSchema.index({ tenantId: 1, createdAt: -1 });
SocAuditEventSchema.index({ companyId: 1, createdAt: -1 });

SocAuditEventSchema.post('save', async function createAdministrativeNotification(event) {
  try {
    await require('../services/socNotification.service').notifyAuditEvent(event);
  } catch (error) {
    console.error('[soc notification] audit event notification failed:', error.message);
  }
});

module.exports = mongoose.model('SocAuditEvent', SocAuditEventSchema);
