const mongoose = require('mongoose');

// Kept separate from LoginActivity so support logins never enter user history.
const schema = new mongoose.Schema({
  actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  actorName: String,
  actorEmail: { type: String, required: true },
  targetUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  targetName: String,
  targetEmail: { type: String, required: true },
  targetRole: { type: String, required: true },
  sessionId: { type: String, unique: true, sparse: true },
  logoutAt: { type: Date, default: null },
  ipAddress: String,
  userAgent: String,
}, { timestamps: true });

schema.index({ createdAt: -1 });
schema.index({ updatedAt: -1, createdAt: -1 });
module.exports = mongoose.model('SuperadminLoginAudit', schema);
