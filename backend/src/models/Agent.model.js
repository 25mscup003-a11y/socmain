const mongoose = require('mongoose');

const AgentSchema = new mongoose.Schema({
  agentId:      { type: String, required: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true },
  hostname:     String,
  ip:           String,
  os:           String,
  agentVersion: String,
  status:       { type: String, enum: ['active','inactive','disconnected'], default: 'inactive' },
  lastSeen:     Date
}, { timestamps: true });

AgentSchema.index({ agentId: 1, companyId: 1 }, { unique: true });

module.exports = mongoose.model('Agent', AgentSchema);
