const mongoose = require('mongoose');

/**
 * Firewall Rule Schema - 3-Level Hierarchy:
 * 1. Company Level - Global rules for entire organization
 * 2. Department Level - Rules for one or multiple departments
 * 3. System Level - Rules for individual systems
 * 
 * Rules are automatically deployed to nftables (Linux) and Windows Defender Firewall (Windows)
 */
const FirewallSchema = new mongoose.Schema(
  {
    companyId: { type: mongoose.Schema.Types.ObjectId, ref: 'Company', index: true }, // Not required for global rules
    
    // Deployment targets
    deployedTo: {
      nftables: { type: Boolean, default: false },          // Linux nftables
      windows_defender: { type: Boolean, default: false },  // Windows Defender Firewall
    },
    
    // Remote rule IDs for tracking
    remoteRuleIds: {
      nftables: { type: String },          // nftables handle/ID
      windows_defender: { type: String },  // Windows Firewall rule name
    },
    
    // Rule Level (company, department, system, global)
    level: {
      type: String,
      enum: ['company', 'department', 'system', 'global'],
      required: true,
      index: true,
    },
    
    // Department IDs (for department-level rules only)
    departmentIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Department' }],
    
    // System ID (for system-level rules only)
    systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System' },
    
    // Rule Details
    ruleName: { type: String, required: true },
    description: { type: String },
    enabled: { type: Boolean, default: true, index: true },
    priority: { type: Number, default: 100 }, // Lower number = higher priority
    
    // Action
    action: {
      type: String,
      enum: ['block', 'allow', 'log'],
      default: 'block',
      required: true,
    },
    
    // Direction
    direction: {
      type: String,
      enum: ['inbound', 'outbound', 'both'],
      default: 'both',
      required: true,
    },
    
    // Rule Conditions (at least one must be specified)
    conditions: {
      ipAddress: { type: String }, // Single IP or CIDR (e.g., 1.2.3.4 or 1.2.3.0/24)
      host: { type: String }, // Hostname or domain
      domain: { type: String }, // Domain name
      application: { type: String }, // Application name or path
      protocol: {
        type: String,
        enum: ['tcp', 'udp', 'icmp', 'all'],
        default: 'all',
      },
      blockProtocol: { type: String }, // Protocol to block entirely (tcp, udp, icmp)
      port: { type: String }, // Single port or range (e.g., 22 or 80-443)
      portRange: {
        start: Number,
        end: Number,
      },
    },
    
    // Additional Settings
    logTraffic: { type: Boolean, default: true },
    notifyOnBlock: { type: Boolean, default: true },
    ttlDays: { type: Number }, // Auto-disable after N days (optional)
    expiresAt: { type: Date }, // Explicit expiration date
    
    // Metadata
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    createdAt: { type: Date, default: Date.now, index: true },
    updatedAt: { type: Date, default: Date.now },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    
    // Rule Statistics
    stats: {
      blockCount: { type: Number, default: 0 },
      allowCount: { type: Number, default: 0 },
      lastTriggered: Date,
    },
    
    // Deployment status tracking
    deploymentStatus: {
      type: String,
      enum: ['pending', 'deployed', 'failed', 'partial'],
      default: 'pending',
      index: true,
    },
    
    // Deployment errors
    deploymentErrors: {
      nftables: { type: String },
      windows_defender: { type: String },
      agent: { type: String },
    },
    deploymentAcks: [{
      systemId: { type: mongoose.Schema.Types.ObjectId, ref: 'System' },
      agentId: String,
      hostname: String,
      ok: Boolean,
      result: String,
      appliedAt: Date,
    }],
  },
  { timestamps: true }
);

// Indexes for fast queries
FirewallSchema.index({ companyId: 1, level: 1, enabled: 1 });
FirewallSchema.index({ systemId: 1, enabled: 1 });
FirewallSchema.index({ deploymentStatus: 1 });
FirewallSchema.index({ 'deployedTo.nftables': 1, 'deployedTo.windows_defender': 1 });
FirewallSchema.index({ departmentIds: 1, enabled: 1 });
FirewallSchema.index({ _id: 1, 'deploymentAcks.systemId': 1 });
FirewallSchema.index({ companyId: 1, level: 1, priority: 1 });

module.exports = mongoose.model('Firewall', FirewallSchema);
