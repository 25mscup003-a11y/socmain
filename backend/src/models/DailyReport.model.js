const mongoose = require('mongoose');

const DailyReportSchema = new mongoose.Schema({
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company',    required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', index: true },
  date:         { type: String, required: true, index: true }, // 'YYYY-MM-DD'
  generatedBy:  { type: String, default: 'auto' },             // 'auto' | userId

  summary:      { type: mongoose.Schema.Types.Mixed },
  bySeverity:   [{ severity: String, count: Number }],
  byStatus:     [{ status: String,   count: Number }],
  byCategory:   [{ category: String, count: Number }],
  topRules:     [{ ruleId: String, description: String, count: Number }],
  topSystems:   [{ agent: String, count: Number }],
}, { timestamps: true });

// Unique per company+dept+date (auto reports are idempotent)
DailyReportSchema.index({ companyId: 1, departmentId: 1, date: 1 }, { unique: false });

module.exports = mongoose.model('DailyReport', DailyReportSchema);
