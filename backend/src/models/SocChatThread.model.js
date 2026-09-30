const mongoose = require('mongoose');

const SocChatThreadSchema = new mongoose.Schema({
  participantKey: { type: String, required: true, unique: true, index: true },
  participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }],
  lastMessage: { type: String, default: '' },
  lastMessageAt: { type: Date, default: Date.now, index: true },
  lastSenderId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

SocChatThreadSchema.index({ participants: 1, lastMessageAt: -1 });

module.exports = mongoose.model('SocChatThread', SocChatThreadSchema);
