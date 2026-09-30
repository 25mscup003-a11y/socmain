/**
 * DashboardConfig — centralized per-company dashboard configuration.
 * Single source of truth consumed by all roles:
 *   superadmin / company_admin / department_admin / analyst
 */
const mongoose = require('mongoose');

const ToolSchema = new mongoose.Schema({
  id:          { type: String, required: true },   // e.g. 'soc-log-monitor'
  name:        { type: String, required: true },
  icon:        { type: String, default: '🔧' },
  enabled:     { type: Boolean, default: true },
  color:       { type: String, default: '#60a5fa' },
  badge:       { type: String, default: '' },
  features:    [{ type: String }],
  externalUrl: { type: String, default: '' },       // optional deep-link
  order:       { type: Number, default: 0 },
}, { _id: false });

const CardSchema = new mongoose.Schema({
  id:      { type: String, required: true },        // 'malware', 'network', etc.
  enabled: { type: Boolean, default: true },
  order:   { type: Number, default: 0 },
  label:   { type: String },                        // optional override label
}, { _id: false });

const DashboardConfigSchema = new mongoose.Schema({
  companyId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Company',
    required: true,
    unique: true,                                    // one config per company
    index: true,
  },

  // ── Built-in log monitoring tools ─────────────────────────────────────────
  tools: { type: [ToolSchema], default: () => DEFAULT_TOOLS() },

  // ── Dashboard cards visibility / ordering ─────────────────────────────────
  cards: { type: [CardSchema], default: () => DEFAULT_CARDS() },

  // ── Global settings ───────────────────────────────────────────────────────
  refreshIntervalSecs: { type: Number, default: 30 },  // live-poll interval
  showLogMonitorCard:  { type: Boolean, default: true },
  theme:               { type: String, enum: ['dark','light'], default: 'dark' },

  // ── Audit ─────────────────────────────────────────────────────────────────
  updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
}, { timestamps: true });

// ── Defaults ──────────────────────────────────────────────────────────────────
function DEFAULT_TOOLS() {
  return [
    {
      id: 'soc-log-monitor', name: 'SOC Log Monitor', icon: '📋', enabled: true,
      color: '#60a5fa', badge: 'Built-in · Centralized', order: 0,
      features: [
        '📥  Multi-source log ingestion',
        '🔎  Centralized log search and filtering',
        '🔔  Real-time monitoring and alerts',
      ],
    },
  ];
}

function DEFAULT_CARDS() {
  return [
    { id: 'malware',     enabled: true,  order: 0 },
    { id: 'network',     enabled: true,  order: 1 },
    { id: 'file',        enabled: true,  order: 2 },
    { id: 'system',      enabled: true,  order: 3 },
    { id: 'isolation',   enabled: true,  order: 4 },
    { id: 'edr',         enabled: true,  order: 5 },
    { id: 'usb',         enabled: true,  order: 6 },
    { id: 'threatIntel', enabled: true,  order: 7 },
  ];
}

DashboardConfigSchema.statics.DEFAULT_TOOLS = DEFAULT_TOOLS;
DashboardConfigSchema.statics.DEFAULT_CARDS = DEFAULT_CARDS;

module.exports = mongoose.model('DashboardConfig', DashboardConfigSchema);
