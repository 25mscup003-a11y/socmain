const mongoose = require('mongoose');

const SoarTemplateSchema = new mongoose.Schema({
  name:                { type: String, required: true, unique: true },
  slug:                { type: String, required: true, unique: true },
  category:            { type: String, required: true },
  description:         { type: String, required: true },
  riskLevel:           { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'medium' },
  supportedAlertTypes: [{ type: String }],
  requiredIntegrations:[{ type: String }],
  triggerType:         { type: String, default: 'new_alert' },
  conditions:          { type: mongoose.Schema.Types.Mixed, default: [] },
  steps:               { type: mongoose.Schema.Types.Mixed, default: [] },
  actions:             { type: mongoose.Schema.Types.Mixed, default: [] },
  isGlobal:            { type: Boolean, default: true },
  createdBy:           { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

module.exports = mongoose.model('SoarTemplate', SoarTemplateSchema);
