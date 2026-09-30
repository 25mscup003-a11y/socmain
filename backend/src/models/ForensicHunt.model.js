const mongoose = require('mongoose');

const ForensicHuntSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  incidentId: { type: mongoose.Schema.Types.ObjectId, ref: 'EdrIncident', default: null, index: true },
  clientId: { type: String, default: '', index: true },
  name: { type: String, required: true, maxlength: 240 },
  artifacts: [{ type: String, required: true, maxlength: 240 }],
  status: {
    type: String,
    enum: ['queued', 'running', 'completed', 'failed', 'cancelled'],
    default: 'queued',
    index: true,
  },
  requestedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  requestedByRole: { type: String, required: true },
  sourceIp: { type: String, default: '' },
  // Keep absent legacy links truly missing. A sparse unique index still indexes
  // explicit null values, which otherwise prevents more than one normal hunt.
  legacyLogId: { type: mongoose.Schema.Types.ObjectId, ref: 'Log', default: undefined, unique: true, sparse: true },
  providerResult: { type: mongoose.Schema.Types.Mixed, default: null },
  error: { type: String, default: '', maxlength: 4000 },
  startedAt: { type: Date, default: null },
  completedAt: { type: Date, default: null },
}, { timestamps: true });

ForensicHuntSchema.index({ companyId: 1, createdAt: -1 });
ForensicHuntSchema.index({ companyId: 1, incidentId: 1, createdAt: -1 });
ForensicHuntSchema.index({ tenantId: 1, companyId: 1, status: 1, createdAt: -1 });

ForensicHuntSchema.pre('validate', async function (next) {
  if (this.companyId && (!this.tenantId || this.isModified('companyId'))) {
    const Company = require('./Company.model');
    const company = await Company.findById(this.companyId).select('tenantId partnerId').lean();
    if (company) {
      this.tenantId = company.tenantId || null;
      this.partnerId = company.partnerId || null;
    }
  }
  next();
});

module.exports = mongoose.model('ForensicHunt', ForensicHuntSchema);
