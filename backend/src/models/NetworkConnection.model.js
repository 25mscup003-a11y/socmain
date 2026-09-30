const mongoose = require('mongoose');

const NetworkConnectionSchema = new mongoose.Schema({
  tenantId: { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },
  systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  endpointId: { type: String, default: '', index: true, maxlength: 128 },
  agentId: { type: String, required: true, index: true, maxlength: 128 },
  connectionId: { type: String, required: true, maxlength: 128 },
  eventId: { type: String, default: '', maxlength: 128 },
  hostname: { type: String, required: true, index: true, maxlength: 253 },
  assetType: { type: String, enum: ['endpoint', 'server', 'user-device', 'virtual-machine', 'unknown'], default: 'unknown', index: true },
  osType: { type: String, default: 'unknown', index: true, maxlength: 64 },

  username: { type: String, default: '', index: true, maxlength: 512 },
  userId: { type: String, default: '', maxlength: 256 },
  loginSession: { type: String, default: '', maxlength: 256 },
  processName: { type: String, default: '', index: true, maxlength: 512 },
  pid: { type: Number, index: true },
  parentPid: { type: Number },
  parentProcessName: { type: String, default: '', maxlength: 512 },
  executablePath: { type: String, default: '', maxlength: 4096 },
  commandLine: { type: String, default: '', maxlength: 8192 },
  processHash: { type: String, default: '', maxlength: 128 },
  signatureStatus: { type: String, default: 'unknown', maxlength: 128 },
  processStartTime: { type: Date, default: null },

  sourceIp: { type: String, required: true, index: true, maxlength: 64 },
  sourcePort: { type: Number, min: 0, max: 65535 },
  destinationIp: { type: String, required: true, index: true, maxlength: 64 },
  destinationPort: { type: Number, min: 0, max: 65535, index: true },
  protocol: { type: String, enum: ['tcp', 'udp', 'icmp', 'other'], default: 'other', index: true },
  state: { type: String, default: 'UNKNOWN', index: true, maxlength: 64 },
  direction: { type: String, enum: ['inbound', 'outbound', 'internal', 'unknown'], default: 'unknown', index: true },
  ipVersion: { type: Number, enum: [4, 6], default: 4 },
  interfaceName: { type: String, default: '', maxlength: 256 },
  networkAdapter: { type: String, default: '', maxlength: 256 },
  bytesSent: { type: Number, default: 0, min: 0 },
  bytesReceived: { type: Number, default: 0, min: 0 },
  domain: { type: String, default: '', index: true, maxlength: 1024 },
  dnsQueryType: { type: String, default: '', maxlength: 32 },

  startTime: { type: Date, required: true, index: true },
  endTime: { type: Date, default: null },
  observedAt: { type: Date, required: true, index: true },
  durationSeconds: { type: Number, default: 0, min: 0 },
  firstSeen: { type: Date, required: true },
  lastSeen: { type: Date, required: true, index: true },

  geo: { type: mongoose.Schema.Types.Mixed, default: {} },
  threatIntel: { type: mongoose.Schema.Types.Mixed, default: {} },
  newDestination: { type: Boolean, default: false, index: true },
  newCountry: { type: Boolean, default: false },
  beaconing: { type: Boolean, default: false, index: true },
  scanning: { type: Boolean, default: false, index: true },
  lateralMovement: { type: Boolean, default: false, index: true },
  transferAnomaly: { type: Boolean, default: false, index: true },
  riskScore: { type: Number, default: 0, min: 0, max: 100, index: true },
  severity: { type: String, enum: ['low', 'medium', 'elevated', 'high', 'critical'], default: 'low', index: true },
  detectionReasons: [{ type: String, maxlength: 1000 }],
  mitre: [{ type: String, maxlength: 64 }],
  rawMetadata: { type: mongoose.Schema.Types.Mixed, default: {} },
  expiresAt: { type: Date, required: true },
}, { timestamps: true, minimize: true });

NetworkConnectionSchema.index({ companyId: 1, connectionId: 1 }, { unique: true });
NetworkConnectionSchema.index({ companyId: 1, observedAt: -1, _id: -1 });
NetworkConnectionSchema.index({ companyId: 1, hostname: 1, observedAt: -1 });
NetworkConnectionSchema.index({ companyId: 1, processName: 1, observedAt: -1 });
NetworkConnectionSchema.index({ companyId: 1, destinationIp: 1, destinationPort: 1, observedAt: -1 });
NetworkConnectionSchema.index({ companyId: 1, severity: 1, riskScore: -1, observedAt: -1 });
NetworkConnectionSchema.index({ companyId: 1, state: 1, endTime: 1, observedAt: -1 });
NetworkConnectionSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

module.exports = mongoose.models.NetworkConnection
  || mongoose.model('NetworkConnection', NetworkConnectionSchema);
