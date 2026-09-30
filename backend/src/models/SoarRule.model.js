const mongoose = require('mongoose');

const ActionSchema = new mongoose.Schema({
  id: { type: String, default: () => new mongoose.Types.ObjectId().toString() },
  type: {
    type: String,
    enum: [
      'create_incident', 'update_incident', 'create_ticket', 'assign_ticket',
      'set_alert_status', 'set_alert_severity', 'assign_alert', 'mark_false_positive',
      'add_comment', 'add_timeline_entry', 'attach_evidence', 'add_ioc', 'enrich_ioc',
      'threat_intel_lookup', 'block_ip', 'unblock_ip', 'block_domain', 'block_url',
      'quarantine_endpoint', 'isolate_agent', 'release_host', 'disable_user', 'enable_user',
      'reset_user_session', 'revoke_token', 'kill_process', 'delete_file',
      'add_firewall_rule', 'remove_firewall_rule', 'run_script', 'call_api',
      'webhook', 'send_email', 'send_sms', 'send_slack', 'send_teams',
      'notify_soc_manager', 'notify_company_admin', 'escalate_l2', 'escalate_l3',
      'start_playbook', 'wait_approval', 'delay', 'close_alert', 'close_incident', 'generate_report',
    ],
    required: true,
  },
  payload: { type: mongoose.Schema.Types.Mixed, default: {} },
  requireApproval: { type: Boolean, default: false },
  riskLevel: { type: String, enum: ['low', 'medium', 'high', 'critical'], default: 'low' },
  retryCount: { type: Number, default: 1 },
  retryBackoffSec: { type: Number, default: 1, min: 0, max: 300 },
  timeoutMs: { type: Number, default: 10000 },
  rollbackAction: { type: mongoose.Schema.Types.Mixed, default: null },
}, { _id: true });

const ConditionSchema = new mongoose.Schema({
  field: { type: String, required: true },
  operator: {
    type: String,
    enum: [
      'eq', 'neq', 'gt', 'gte', 'lt', 'lte',
      'contains', 'not_contains', 'starts_with', 'ends_with',
      'in', 'not_in', 'exists', 'does_not_exist', 'matches_regex',
      'cidr_contains', 'date_before', 'date_after', 'risk_range', 'confidence_range',
    ],
    required: true,
  },
  value: { type: mongoose.Schema.Types.Mixed, required: true },
}, { _id: false });

const SoarRuleSchema = new mongoose.Schema({
  tenantId:     { type: mongoose.Schema.Types.ObjectId, ref: 'Tenant', default: null, index: true },
  partnerId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Partner', default: null, index: true },
  companyId:    { type: mongoose.Schema.Types.ObjectId, ref: 'Company', default: null, index: true },
  departmentId: { type: mongoose.Schema.Types.ObjectId, ref: 'Department', default: null, index: true },

  ruleId:       { type: String, index: true },
  name:         { type: String, required: true, trim: true },
  description:  { type: String, default: '' },
  category:     { type: String, default: 'General' },
  tags:         [{ type: String }],
  version:      { type: Number, default: 1 },
  status:       { type: String, enum: ['draft', 'active', 'disabled', 'testing', 'archived'], default: 'active', index: true },
  enabled:      { type: Boolean, default: true, index: true },
  priority:     { type: Number, default: 100 },

  triggerType: {
    type: String,
    enum: [
      'new_alert', 'alert_severity_changed', 'incident_created', 'incident_updated',
      'ticket_created', 'ticket_status_changed', 'ioc_detected', 'anomaly_detected',
      'suricata_alert', 'zeek_event', 'siem_event', 'firewall_alert', 'ids_alert', 'ips_alert',
      'email_alert', 'cloud_alert', 'threat_intel_match', 'webhook', 'cron', 'manual',
      'correlation_created', 'correlation_updated',
      'sla_threshold', 'approval_completed', 'playbook_completed', 'api_request',
    ],
    default: 'new_alert',
  },
  triggerSubtype: { type: String, default: 'all' },

  conditionLogic: { type: String, enum: ['AND', 'OR'], default: 'AND' },
  conditions:     { type: [ConditionSchema], default: [] },
  conditionTree:  { type: mongoose.Schema.Types.Mixed, default: null }, // nested AND/OR tree

  actions:        { type: [ActionSchema], default: [] },
  actionGraph:    { type: mongoose.Schema.Types.Mixed, default: null }, // node workflow JSON

  executionMode:  { type: String, enum: ['automatic', 'manual', 'approval_required'], default: 'automatic' },
  stopOnMatch:    { type: Boolean, default: false },

  retryPolicy: {
    maxRetries: { type: Number, default: 2 },
    retryDelayMs: { type: Number, default: 5000 },
    backoffMultiplier: { type: Number, default: 2 },
  },

  safetyPolicy: {
    dryRun: { type: Boolean, default: false },
    testMode: { type: Boolean, default: false },
    requireApprovalForDestructive: { type: Boolean, default: true },
    protectedAssets: [{ type: String }],
    allowedCompanies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Company' }],
    deniedCompanies: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Company' }],
  },

  deduplicationWindowMs: { type: Number, default: 300000 },
  rateLimitPerHour:      { type: Number, default: 100 },
  cooldownMinutes:       { type: Number, default: 15 },
  autoDisableOnFailures: { type: Number, default: 5 },
  consecutiveFailures:   { type: Number, default: 0 },

  matchCount:  { type: Number, default: 0 },
  lastMatchAt: { type: Date },

  createdBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  updatedBy:   { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
}, { timestamps: true });

SoarRuleSchema.index({ companyId: 1, enabled: 1, priority: 1 });
SoarRuleSchema.index({ companyId: 1, departmentId: 1, enabled: 1, priority: 1 });
SoarRuleSchema.index({ tenantId: 1, companyId: 1, status: 1 });

module.exports = mongoose.model('SoarRule', SoarRuleSchema);
