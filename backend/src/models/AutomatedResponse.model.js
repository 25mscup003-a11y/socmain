const mongoose = require('mongoose');

/**
 * AutomatedResponse — tracks every automated response action taken.
 * Central audit store for the Response Engine dashboard.
 */
const AutomatedResponseSchema = new mongoose.Schema({
  tenantId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:   { type: mongoose.Schema.Types.ObjectId, ref: 'Company', required: true, index: true },
  departmentId:{ type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },

  // Source alert / incident
  alertId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Alert', default: null },
  incidentId:  { type: String, default: null },

  // Playbook / policy that triggered this
  playbookId:  { type: mongoose.Schema.Types.ObjectId, ref: 'ResponsePlaybook', default: null },
  playbookName:{ type: String, default: '' },
  policyId:    { type: String, default: null },
  policyName:  { type: String, default: '' },

  // Endpoint
  systemId:    { type: mongoose.Schema.Types.ObjectId, ref: 'System', default: null, index: true },
  agentId:     { type: String, default: '' },
  hostname:    { type: String, default: '' },
  osType:      { type: String, default: '' },
  endpointIp:  { type: String, default: '' },

  // Threat context
  threatName:  { type: String, default: '' },
  threatType:  { type: String, default: '' },
  severity:    {
    type: String,
    enum: ['low', 'medium', 'high', 'critical'],
    default: 'medium',
  },
  mitreTechnique: { type: String, default: '' },
  riskScore:   { type: Number, default: 0 },

  // Action details
  actionType: {
    type: String,
    enum: [
      'kill_process', 'kill_process_tree', 'kill_child_processes',
      'isolate', 'isolate_agent', 'quarantine_endpoint', 'reconnect', 'release_host',
      'quarantine_file', 'restore_file', 'delete_file',
      'block_hash', 'unblock_hash',
      'block_ip', 'unblock_ip',
      'block_domain', 'unblock_domain',
      'block_port', 'unblock_port', 'add_firewall_rule', 'add_ioc',
      'block_usb', 'unblock_usb',
      'disable_user', 'enable_user', 'lock_account', 'force_logoff', 'revoke_token',
      'restart_service', 'stop_service', 'start_service',
      'delete_scheduled_task', 'delete_startup_entry', 'rollback_registry',
      'terminate_script', 'run_script', 'run_command',
      'send_email', 'send_slack', 'send_webhook',
      'create_incident', 'create_ticket', 'assign_alert', 'notify_soc_manager', 'notify_company_admin',
      'escalate_l2', 'escalate_l3', 'set_alert_status', 'set_alert_severity',
      'webhook', 'call_api',
      'manual_override',
      'other',
    ],
    required: true,
  },
  actionParams:   { type: mongoose.Schema.Types.Mixed, default: {} },
  actionResult:   { type: String, default: '' },

  // Execution
  status: {
    type: String,
    enum: [
      'created', 'waiting_approval', 'approved', 'queued', 'sent_to_agent',
      'acknowledged', 'executing', 'successful', 'partially_successful', 'failed',
      'timed_out', 'cancelled', 'rollback_pending', 'rolled_back', 'rollback_failed',
      // Backward-compatible values used by the original implementation.
      'pending', 'running', 'success', 'skipped',
    ],
    default: 'created',
    index: true,
  },
  executionTimeMs: { type: Number, default: 0 },
  startedAt:       { type: Date, default: null },
  completedAt:     { type: Date, default: null },

  // Trigger mode
  trigger: {
    type: String,
    enum: ['automatic', 'manual', 'scheduled', 'playbook'],
    default: 'automatic',
  },
  triggeredBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // Approval
  requiresApproval:  { type: Boolean, default: false },
  approvedBy:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  approvedAt:        { type: Date, default: null },
  approvalStatus:    {
    type: String,
    enum: ['pending', 'approved', 'rejected', 'expired', 'auto_approved'],
    default: 'auto_approved',
  },

  // Rollback
  rollbackAvailable: { type: Boolean, default: false },
  rolledBackAt:      { type: Date, default: null },
  rolledBackBy:      { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },

  // Digital signature / integrity
  signature:   { type: String, default: '' },
  errorDetail: { type: String, default: '' },

  commandId:       { type: String, default: '', index: true },
  correlationId:   { type: String, default: '', index: true },
  expiresAt:       { type: Date, default: null },
  retryCount:      { type: Number, default: 0 },
  maxRetries:      { type: Number, default: 0 },
  timeoutMs:       { type: Number, default: 60_000 },
  executionMode:   { type: String, enum: ['automatic', 'approval_required', 'manual_only', 'disabled'], default: 'manual_only' },
  dryRun:          { type: Boolean, default: false },
  approvalComment: { type: String, default: '' },
  auditTrail: [{
    status: { type: String, required: true },
    message: { type: String, default: '' },
    actorId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
    at: { type: Date, default: Date.now },
  }],

  // Notes / analyst comment
  analystNotes: { type: String, default: '' },
}, { timestamps: true });

AutomatedResponseSchema.index({ companyId: 1, createdAt: -1 });
AutomatedResponseSchema.index({ companyId: 1, status: 1, createdAt: -1 });
AutomatedResponseSchema.index({ companyId: 1, actionType: 1, createdAt: -1 });
AutomatedResponseSchema.index({ companyId: 1, systemId: 1, createdAt: -1 });
AutomatedResponseSchema.index({ companyId: 1, alertId: 1 });
AutomatedResponseSchema.index({ companyId: 1, commandId: 1 }, { sparse: true });
AutomatedResponseSchema.index({ companyId: 1, systemId: 1, actionType: 1, createdAt: -1 });
AutomatedResponseSchema.index({ companyId: 1, departmentId: 1, status: 1, createdAt: -1 });

module.exports = mongoose.model('AutomatedResponse', AutomatedResponseSchema);
