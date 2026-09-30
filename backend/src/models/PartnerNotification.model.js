const mongoose = require('mongoose');

const PartnerNotificationSchema = new mongoose.Schema({
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', required: true, index: true },
  type: { type: String, default: 'partner_update', index: true },
  title: { type: String, required: true },
  message: { type: String, default: '' },
  read: { type: Boolean, default: false, index: true },
  meta: { type: Object, default: {} },
}, { timestamps: true });

PartnerNotificationSchema.index({ partnerId: 1, createdAt: -1 });

module.exports = mongoose.model('PartnerNotification', PartnerNotificationSchema);
