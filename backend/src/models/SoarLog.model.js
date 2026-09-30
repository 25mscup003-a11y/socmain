const mongoose = require('mongoose');

const SoarLogSchema = new mongoose.Schema({
  companyId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  alertId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Alert',   required: true },
  ruleId:     { type: mongoose.Schema.Types.ObjectId, ref: 'SoarRule',required: true },
  ruleName:   { type: String },
  actionsRun: [{ type: String }],
  results:    [{ action: String, success: Boolean, detail: String }],
  error:      { type: String },
}, { timestamps: true });

module.exports = mongoose.model('SoarLog', SoarLogSchema);
