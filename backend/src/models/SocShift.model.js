const mongoose = require('mongoose');

const SocShiftSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', required: true, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  name: { type: String, required: true, trim: true, maxlength: 80 },
  timezone: { type: String, required: true, default: 'Asia/Kolkata' },
  startTime: { type: String, required: true, match: /^([01]\d|2[0-3]):[0-5]\d$/ },
  endTime: { type: String, required: true, match: /^([01]\d|2[0-3]):[0-5]\d$/ },
  weekdays: [{ type: Number, min: 0, max: 6 }],
  analystIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  active: { type: Boolean, default: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
}, { timestamps: true });

SocShiftSchema.index({ tenantId: 1, companyId: 1, active: 1 });

module.exports = mongoose.model('SocShift', SocShiftSchema);
