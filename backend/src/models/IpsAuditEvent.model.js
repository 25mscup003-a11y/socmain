const mongoose = require('mongoose');

const IpsAuditEventSchema = new mongoose.Schema({
  eventId:    { type: String, required: true, unique: true, index: true },
  companyId:  { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  incidentId: { type: String, default: null, index: true },
  systemId:   { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  action:     { type: String, required: true, index: true },
  severity:   { type: String, default: 'info', index: true },
  actor:      { type: String, default: 'IPS Engine' },
  target:     { type: String, default: '—' },
  attackType: { type: String, default: null },
  phase:      { type: String, default: null },
  detail:     { type: String, required: true },
  metadata:   { type: mongoose.Schema.Types.Mixed, default: null },
  ts:         { type: Date, required: true, default: Date.now, index: true },
}, { timestamps: true });

IpsAuditEventSchema.index({ companyId: 1, ts: -1 });
IpsAuditEventSchema.index({ companyId: 1, action: 1, ts: -1 });

module.exports = mongoose.model('IpsAuditEvent', IpsAuditEventSchema);
