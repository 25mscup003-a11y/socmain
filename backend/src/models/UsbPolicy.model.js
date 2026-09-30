const mongoose = require('mongoose');

const UsbPolicySchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  name: { type: String, required: true, trim: true, maxlength: 120 },
  description: { type: String, default: '', maxlength: 500 },
  ruleType: {
    type: String,
    required: true,
    enum: ['allow_serials', 'block_serials', 'block_vendor', 'block_device_type', 'block_sensitive_files', 'block_extensions', 'max_file_size', 'read_only'],
  },
  action: { type: String, enum: ['audit', 'block'], default: 'audit' },
  values: [{ type: String, trim: true }],
  maxBytes: { type: Number, default: 0, min: 0 },
  enabled: { type: Boolean, default: true, index: true },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

UsbPolicySchema.index({ companyId: 1, enabled: 1, updatedAt: -1 });
module.exports = mongoose.model('UsbPolicy', UsbPolicySchema);
