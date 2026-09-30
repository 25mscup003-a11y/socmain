const mongoose = require('mongoose');

const CompanyNotificationSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  title: { type: String, required: true },
  message: { type: String, required: true },
  read: { type: Boolean, default: false, index: true },
  source: { type: String, enum: ['superadmin', 'partner', 'soc_manager', 'system'], default: 'system', index: true },
  type: { type: String, default: 'general' },
  link: { type: String, default: '' },
  targetUrl: { type: String, default: '' },
  meta: { type: Object, default: {} },
  createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('CompanyNotification', CompanyNotificationSchema);
