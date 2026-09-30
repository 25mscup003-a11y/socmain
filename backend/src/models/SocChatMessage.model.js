const mongoose = require('mongoose');

const SocChatMessageSchema = new mongoose.Schema({
  threadId: { type: mongoose.Schema.Types.ObjectId, ref: 'SocChatThread', required: true, index: true },
  senderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  recipientId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  message: { type: String, required: true, trim: true, maxlength: 4000 },
  readAt: { type: Date, default: null, index: true },
}, { timestamps: true });

SocChatMessageSchema.index({ threadId: 1, createdAt: -1 });
SocChatMessageSchema.index({ recipientId: 1, readAt: 1, createdAt: -1 });

module.exports = mongoose.model('SocChatMessage', SocChatMessageSchema);
