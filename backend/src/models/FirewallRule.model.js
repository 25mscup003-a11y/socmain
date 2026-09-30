const mongoose = require('mongoose');

const FirewallRuleSchema = new mongoose.Schema({
  companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department' },
  
  name: { type: String, required: true },
  description: { type: String },
  
  // Rule type: 'allow' | 'deny' | 'drop' | 'reject' | 'log'
  action: {
    type: String,
    enum: ['allow', 'deny', 'drop', 'reject', 'log', 'accept'],
    default: 'allow',
  },

  // Network parameters
  protocol: {
    type: String,
    enum: ['tcp', 'udp', 'icmp', 'all'],
    default: 'tcp',
  },
  
  // Source IP (CIDR notation: 10.0.0.0/8 or 192.168.1.1)
  sourceIp: { type: String, default: 'any' },
  sourcePort: { type: String, default: 'any' },
  
  // Destination IP
  destinationIp: { type: String, default: 'any' },
  destinationPort: { type: String, default: 'any' },
  
  // Direction: 'in' | 'out' | 'both'
  direction: {
    type: String,
    enum: ['in', 'out', 'both'],
    default: 'in',
  },

  // For pfSense/OPNsense
  interface: { type: String, default: 'wan' }, // wan, lan, etc.
  ipVersion: {
    type: String,
    enum: ['inet', 'inet6', 'inet4_6'],
    default: 'inet',
  },

  // Rule trigger/source
  sourceType: {
    type: String,
    enum: ['alert', 'manual', 'threat_intel', 'ips_block', 'ids_detection'],
    default: 'manual',
  },
  
  // If triggered by alert
  alertId: { type: mongoose.Schema.Types.ObjectId, ref: 'Alert' },
  
  // If triggered by threat intelligence
  threatIntelSource: { type: String }, // e.g., 'virustotal', 'abuse.ch'
  
  // Automation triggers
  autoTrigger: {
    enabled: { type: Boolean, default: false },
    condition: { type: String }, // JSON condition
    expireAfterMinutes: { type: Number }, // Auto-remove after N minutes
  },

  // Status
  status: {
    type: String,
    enum: ['draft', 'approved', 'active', 'disabled', 'expired'],
    default: 'draft',
  },

  // Target systems
  systemIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'System' }],
  applyToAll: { type: Boolean, default: false },
  
  // Deployment tracking
  deploymentStatus: {
    total: { type: Number, default: 0 },
    successful: { type: Number, default: 0 },
    failed: { type: Number, default: 0 },
    lastDeployment: { type: Date },
    details: [
      {
        systemId: { type: mongoose.Schema.Types.ObjectId },
        systemName: { type: String },
        success: { type: Boolean },
        error: { type: String },
        deployedAt: { type: Date },
      },
    ],
  },

  // Firewall-specific settings
  logging: { type: Boolean, default: false },
  priority: { type: Number, default: 100 }, // Lower = higher priority
  
  // Rules version (for tracking changes)
  version: { type: Number, default: 1 },
  
  // Audit trail
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  approvalReason: { type: String },

  // Tags for organization
  tags: [{ type: String }],

  // Expiration for temporary rules
  expiresAt: { type: Date },

}, { timestamps: true });

// Index for common queries
FirewallRuleSchema.index({ companyId: 1, status: 1, createdAt: -1 });
FirewallRuleSchema.index({ sourceIp: 1, destinationPort: 1 });
FirewallRuleSchema.index({ expiresAt: 1 }); // For cleanup of expired rules

module.exports = mongoose.model('FirewallRule', FirewallRuleSchema);
