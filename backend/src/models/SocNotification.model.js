const mongoose = require('mongoose');

const SocNotificationSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  ticketId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null, index: true },
  chatThreadId: { type: mongoose.Schema.Types.ObjectId, ref: 'SocChatThread', default: null, index: true },
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null, index: true },
  type: { type: String, enum: ['ticket_queued', 'ticket_assigned', 'admin_change', 'chat_message'], required: true, index: true },
  sourceType: { type: String, enum: ['ticket', 'audit', 'chat'], default: 'ticket', index: true },
  sourceId: { type: String, default: '', maxlength: 100 },
  dedupeKey: { type: String, default: null, maxlength: 180 },
  title: { type: String, required: true, trim: true, maxlength: 200 },
  message: { type: String, required: true, trim: true, maxlength: 1000 },
  link: { type: String, default: '', maxlength: 500 },
  read: { type: Boolean, default: false, index: true },
  readAt: { type: Date, default: null },
}, { timestamps: true, autoIndex: false });

SocNotificationSchema.index({ userId: 1, read: 1, createdAt: -1 });
SocNotificationSchema.index(
  { userId: 1, ticketId: 1, type: 1 },
  { unique: true, partialFilterExpression: { ticketId: { $type: 'objectId' } } },
);
SocNotificationSchema.index(
  { userId: 1, dedupeKey: 1 },
  { unique: true, partialFilterExpression: { dedupeKey: { $type: 'string' } } },
);

module.exports = mongoose.model('SocNotification', SocNotificationSchema);
