const mongoose = require('mongoose');

/**
 * Log — Raw log collection (separate from Alerts).
 * Stores all incoming logs before correlation/normalization.
 * Supports: OS logs, web server, database, app logs, payment logs, cloud logs.
 */
const LogSchema = new mongoose.Schema({
  // Tenant
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', index: true },
  systemId:     { type: mongoose.Schema.Types.ObjectId, ref: 'System', index: true },
  expiresAt:    { type: Date, default: null },
  archivedAt:   { type: Date, default: null },
  archiveKey:   { type: String, default: '' },

  // Source identification
  source:     { type: String, index: true },  // 'agent', 'suricata', 'firewall', 'syslog', 'apache', etc.
  agentKey:   { type: String, index: true },
  agentName:  { type: String },
  hostname:   { type: String },
  ipAddress:  { type: String },

  // Log classification
  logType:    { type: String, enum: [
    'system', 'auth', 'network', 'file', 'process', 'usb',
    'application', 'webserver', 'database', 'cloud', 'payment',
    'ids', 'firewall', 'edr', 'malware', 'custom'
  ], default: 'system', index: true },

  // Content
  level:      { type: String, enum: ['debug','info','warning','error','critical'], default: 'info' },
  message:    { type: String, required: true },
  facility:   { type: String },     // syslog facility
  program:    { type: String },     // program that generated log
  pid:        { type: Number },

  // Timestamps
  logTime:    { type: Date, index: true },  // original log timestamp
  receivedAt: { type: Date, default: Date.now, index: true },

  // Structured data
  fields:     { type: mongoose.Schema.Types.Mixed },  // parsed key-value data

  // Raw log
  raw:        { type: String },      // original log line
  format:     { type: String },      // 'syslog', 'json', 'cef', 'leef', 'csv', 'freetext'

  // Tags for fast filtering
  tags:       [String],

  // Processing status
  processed:  { type: Boolean, default: false },
  alertId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Alert' },
}, { timestamps: true });

LogSchema.index({ expiresAt: 1 }, { name: 'expires_at_ttl', expireAfterSeconds: 0, sparse: true });
LogSchema.index({ companyId: 1, archivedAt: 1, receivedAt: 1 });
LogSchema.index({ companyId: 1, logType: 1, receivedAt: -1 });
LogSchema.index({ companyId: 1, source: 1, receivedAt: -1 });
LogSchema.index({ tenantId: 1, companyId: 1, receivedAt: -1 });
LogSchema.index({ tenantId: 1, partnerId: 1, receivedAt: -1 });

LogSchema.pre('validate', async function (next) {
  if ((!this.tenantId || this.isModified('companyId')) && this.companyId) {
    const Company = require('./Company.model');
    const company = await Company.findById(this.companyId).select('tenantId partnerId retentionPolicy').lean();
    if (company) {
      this.tenantId = company.tenantId || this.tenantId;
      this.partnerId = company.partnerId || null;
      if (!this.expiresAt && !company.retentionPolicy?.legalHold) {
        const { applyRetention } = require('../utils/retentionPolicy');
        this.expiresAt = applyRetention(this.toObject(), company.retentionPolicy, this.receivedAt).expiresAt;
      }
    }
  }
  next();
});

LogSchema.pre('insertMany', async function (next, docs) {
  try {
    const Company = require('./Company.model');
    const companyIds = [...new Set((docs || []).map(doc => String(doc.companyId || '')).filter(Boolean))];
    const companies = await Company.find({ _id: { $in: companyIds } }).select('tenantId partnerId retentionPolicy').lean();
    const scopeByCompany = companies.reduce((acc, company) => {
      acc[String(company._id)] = company;
      return acc;
    }, {});
    for (const doc of docs || []) {
      const company = scopeByCompany[String(doc.companyId || '')];
      if (!company) continue;
      if (!doc.tenantId) doc.tenantId = company.tenantId || null;
      if (!doc.partnerId) doc.partnerId = company.partnerId || null;
      if (!doc.expiresAt && !company.retentionPolicy?.legalHold) {
        const { applyRetention } = require('../utils/retentionPolicy');
        doc.expiresAt = applyRetention(doc, company.retentionPolicy, doc.receivedAt).expiresAt;
      }
    }
    next();
  } catch (err) {
    next(err);
  }
});

module.exports = mongoose.model('Log', LogSchema);
