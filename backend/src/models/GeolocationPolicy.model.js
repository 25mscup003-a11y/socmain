const mongoose = require('mongoose');

const GeolocationPolicySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  builtInKey: { type: String, trim: true },
  name: { type: String, required: true, trim: true, maxlength: 160 },
  description: { type: String, default: '', maxlength: 1000 },
  category: { type: String, required: true, trim: true, maxlength: 80 },
  severity: { type: String, enum: ['Critical', 'High', 'Medium', 'Low'], default: 'Medium' },
  action: { type: String, required: true, trim: true, maxlength: 120 },
  enabled: { type: Boolean, default: true, index: true },
  priority: { type: Number, min: 0, max: 1000, default: 100 },
  conditions: { type: mongoose.Schema.Types.Mixed, default: {} },
  version: { type: Number, min: 1, default: 1 },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true, minimize: false });

GeolocationPolicySchema.index({ companyId: 1, enabled: 1, priority: 1 });
GeolocationPolicySchema.index({ companyId: 1, builtInKey: 1 }, { unique: true, sparse: true });
module.exports = mongoose.model('GeolocationPolicy', GeolocationPolicySchema);
