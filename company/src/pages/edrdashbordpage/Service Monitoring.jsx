/**
 * Service Monitoring — Capability ID: 24 (Backend ID: 24)
 *
 * 100% Self-Contained Enterprise SOC Service Monitoring & Security Agent Control Module
 * Full Coverage across 15 Service Monitoring Categories & Policy Engine Specifications (Service Start/Stop, New Service Creation, Deletion, Config Changes, Binary Hash Tampering, Security Services Guard, Windows & Linux systemd Daemons, etc.)
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=24`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19), API Call (20), Script (21), Time Anomaly (22), Geolocation (23)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens ──────────────────────────────────────────────────
const MON = {
  bg: '#060d16',
  card: '#0b1929',
  card2: '#0f233a',
  border: '#1a3050',
  line: '#162942',
  text: '#e2e8f0',
  muted: '#8ea0b8',
  sub: '#64748b',
  blue: '#38bdf8',
  cyan: '#22d3ee',
  green: '#34d399',
  yellow: '#fbbf24',
  orange: '#fb923c',
  red: '#f87171',
  purple: '#a78bfa',
  pink: '#ec4899',
  accent: '#6366f1',
};

const SEV_COLOR = {
  critical: MON.red,
  high: MON.orange,
  medium: MON.yellow,
  low: MON.green,
  info: MON.cyan,
  clean: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
  clean: 'rgba(34, 211, 238, 0.15)',
};

function MiniSparkline({ data = [12, 18, 14, 22, 19, 28, 24, 32], color = MON.cyan, height = 30 }) {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const points = data.map((val, idx) => {
    const x = (idx / (data.length - 1)) * 100;
    const y = height - ((val - min) / (max - min || 1)) * (height - 6) - 3;
    return `${x},${y}`;
  }).join(' ');

  return (
    <svg viewBox={`0 0 100 ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      <polyline fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" points={points} />
    </svg>
  );
}

// ── Helper Utilities ────────────────────────────────────────────────────────
function createEventBuffer(callback, delay = 1200) {
  let timer = null;
  return {
    add() {
      clearTimeout(timer);
      timer = setTimeout(callback, delay);
    },
    clear() {
      clearTimeout(timer);
    },
  };
}

function shortNum(n = 0) {
  const val = Number(n) || 0;
  return val >= 1000 ? val.toLocaleString('en-IN') : String(val);
}

function normHost(h) {
  return String(h || 'unknown').trim().toLowerCase();
}

function alertTime(row) {
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'Unknown host';
}

function alertUser(row) {
  const raw = serviceRaw(row);
  return row?.username || row?.user || row?.userName || raw.username || raw.user || 'Unknown user';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'info').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'critical';
}

function processOs(row) {
  const raw = serviceRaw(row);
  const osStr = String(row?.osType || row?.os || row?.platform || raw.os_type || raw.os || raw.platform || row?.systemId?.osType || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows Server';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux systemd';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS launchd';
  return 'Windows Server';
}

// ── Service Telemetry Extractors ──────────────────────────────────────────
function serviceRaw(row) {
  const root = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  const item = row?.inventoryItem || root.inventory_item || root.inventoryItem || {};
  return { ...nested, ...root, ...item };
}

function serviceName(row) {
  const raw = serviceRaw(row);
  return row?.serviceName || row?.inventoryName || row?.service || raw.service_name || raw.serviceName || raw.inventory_name || raw.name || raw.id || 'Unknown service';
}

function serviceDisplayName(row) {
  const raw = serviceRaw(row);
  return row?.serviceDisplayName || row?.displayName || raw.service_display_name || raw.display_name || raw.description || serviceName(row);
}

function serviceStatus(row) {
  const raw = serviceRaw(row);
  return row?.serviceCurrentStatus || row?.currentStatus || raw.current_status || raw.serviceCurrentStatus || raw.sub_status || raw.state || raw.status || 'Unknown';
}

function serviceAccount(row) {
  const raw = serviceRaw(row);
  return row?.serviceAccount || row?.account || raw.service_account || raw.username || raw.user || 'Not reported';
}

function serviceBinaryPath(row) {
  const raw = serviceRaw(row);
  return row?.serviceBinaryPath || row?.binaryPath || row?.path || raw.service_binary_path || raw.binary_path || raw.exec_start || 'Not reported';
}

function serviceStartupType(row) {
  const raw = serviceRaw(row);
  return row?.serviceStartupType || row?.startupType || row?.startType || raw.startup_type || raw.start_type || raw.unit_file_state || 'Not reported';
}

function serviceRule(row) {
  const raw = serviceRaw(row);
  return row?.serviceEventType || row?.eventType || row?.ruleName || row?.ruleId || raw.service_event_type || raw.eventType || raw.rule_id || row?.category || 'Service telemetry event';
}

function serviceRiskScore(row) {
  const raw = serviceRaw(row);
  const score = Number(row?.riskScore ?? row?.score ?? raw.risk_score ?? raw.riskScore);
  return Number.isFinite(score) ? score : 0;
}

function buildBuckets(rows = [], bucketCount = 12, hours = 24) {
  const now = Date.now();
  const start = now - hours * 3600000;
  const bucketMs = (hours * 3600000) / bucketCount;
  const buckets = Array(bucketCount).fill(0);
  rows.forEach(row => {
    const t = alertTime(row);
    const ms = t ? new Date(t).getTime() : NaN;
    if (!Number.isFinite(ms) || ms < start || ms > now) return;
    const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((ms - start) / bucketMs)));
    buckets[idx] += 1;
  });
  return buckets;
}

function topCounts(rows = [], picker = () => 'unknown', limit = 5) {
  const counts = new Map();
  rows.forEach(row => {
    const key = String(picker(row) || 'unknown').trim() || 'unknown';
    if (key === 'unknown' || key === '—') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function recordId(row) {
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${serviceName(row)}`;
}

function csvCell(val) {
  const str = String(val ?? '').replace(/"/g, '""');
  return `"${str}"`;
}

function downloadBlob(content, filename, type = 'text/csv;charset=utf-8;') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. SERVICE FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function ServiceForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const raw = serviceRaw(log);
  const present = (...values) => values.find(value => value !== undefined && value !== null && value !== '') ?? 'Not reported';
  const printable = value => Array.isArray(value) ? (value.join(', ') || 'None') : (typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value));
  const detailRows = {
    config: [
      ['Startup Type', serviceStartupType(log)], ['Previous State', present(log.servicePreviousStatus, raw.previous_status)],
      ['Current State', serviceStatus(log)], ['Service Account', serviceAccount(log)],
      ['Old Value', present(log.oldValue, raw.old_value)], ['New Value', present(log.newValue, raw.new_value)],
    ],
    binary: [
      ['Binary Path', serviceBinaryPath(log)], ['SHA-256', present(log.serviceBinarySha256, raw.service_binary_sha256, log.hash)],
      ['Signature Status', present(log.serviceSignatureStatus, raw.service_signature_status)], ['Publisher', present(log.servicePublisher, raw.service_publisher)],
      ['Package Owner', present(log.servicePackageOwner, raw.service_package_owner)], ['Package Verification', present(log.servicePackageVerificationStatus, raw.service_package_verification_status)],
    ],
    resource: [
      ['PID', present(log.servicePid, raw.service_pid, raw.pid)], ['Process', present(log.processName, raw.process_name)],
      ['Parent Process', present(log.parentProcessName, raw.parent_process)], ['Command Line', present(log.processCmdline, log.commandLine, raw.command_line)],
      ['CPU', present(log.processCpuPercent, raw.cpu_percent)], ['Memory', present(log.processMemoryPercent, raw.memory_percent)],
    ],
    security: [
      ['Security Critical', (log.serviceSecurityCritical || raw.security_service) ? 'Yes' : 'No'],
      ['Suspicious Path', (log.suspiciousServicePath || raw.suspicious_service_path) ? 'Yes' : 'No'],
      ['Initiating User', alertUser(log)], ['Threat Intelligence', present(log.threatIntelMatch, raw.threat_intel_match)],
      ['Severity', sev.toUpperCase()], ['Risk Score', `${serviceRiskScore(log)}/100`],
    ],
    dependency: [
      ['Dependencies', present(log.serviceDependencies, raw.service_dependencies, raw.dependencies)], ['Unit Path', present(log.serviceUnitPath, raw.service_unit_path, raw.unit_path)],
      ['Platform', processOs(log)], ['Agent', present(log.agentName, log.agentId, raw.agent_id)],
    ],
    mitre: [
      ['Technique ID', present(log.mitreId, log.mitreTechnique, raw.mitre_id)], ['Technique', present(log.technique, raw.technique)],
      ['Tactic', present(log.mitreTactic, raw.mitre_tactic)], ['Evidence Type', present(log.evidenceType, raw.evidence_type)],
    ],
    health: [
      ['Current State', serviceStatus(log)], ['Restart Count', present(log.serviceRestartCount, raw.service_restart_count, 0)],
      ['Coverage', present(log.coverageStatus, raw.coverage_status)], ['Health Risk', `${serviceRiskScore(log)}/100`],
    ],
    timeline: [
      ['Observed At', alertTime(log) ? new Date(alertTime(log)).toLocaleString() : 'Not reported'], ['Lifecycle Event', serviceRule(log)],
      ['Previous State', present(log.servicePreviousStatus, raw.previous_status)], ['Current State', serviceStatus(log)],
      ['Change Type', present(log.changeType, raw.change_type)], ['Event ID', present(log.eventId, log._id)],
    ],
  };

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'config', label: '⚙️ 2. Config & Startup' },
    { id: 'binary', label: '🔑 3. Binary & Integrity' },
    { id: 'resource', label: '💻 4. Process & Resources' },
    { id: 'security', label: '🛡️ 5. Security & Privileges' },
    { id: 'dependency', label: '🔗 6. Dependencies' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'health', label: '💖 8. Health Evaluation' },
    { id: 'timeline', label: '⏱️ 9. Service Lifecycle' },
    { id: 'actions', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionName) => {
    const actionType = /quarantine/i.test(actionName) ? 'quarantine' : /approved baseline/i.test(actionName) ? 'ignore' : null;
    if (!actionType || typeof onAction !== 'function' || !log?._id) {
      setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
      return;
    }
    try {
      await onAction(String(log._id), actionType);
      setActionSuccess(`Approved action submitted: ${actionName}`);
    } catch (error) {
      setActionSuccess(error?.message || `Failed to submit: ${actionName}`);
    }
    setTimeout(() => setActionSuccess(null), 3500);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>⚙️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Service Forensic Investigation — {serviceName(log)} ({serviceDisplayName(log)})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {serviceRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Status: <strong style={{ color: MON.green }}>{serviceStatus(log)}</strong> | Account: <strong style={{ color: MON.yellow }}>{serviceAccount(log)}</strong> | Host: <strong>{alertHost(log)}</strong> | Startup: <strong>{serviceStartupType(log)}</strong>
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map((t) => (
            <button key={t.id} type="button" onClick={() => setActiveTab(t.id)} style={{ padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600, color: activeTab === t.id ? MON.cyan : MON.muted, background: activeTab === t.id ? MON.bg : 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Body Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: MON.bg }}>
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Service Name', serviceName(log), MON.cyan],
                  ['Service Status', serviceStatus(log), MON.green],
                  ['Run As Account', serviceAccount(log), MON.yellow],
                  ['Startup Type', serviceStartupType(log), MON.purple],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>⚙️ Incident Summary & Binary Path</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  The Service Monitoring Engine flagged an event: <strong>{serviceRule(log)}</strong> for service <strong>{serviceName(log)}</strong> running on endpoint <strong>{alertHost(log)}</strong>. Binary executable path: <code style={{ color: MON.yellow, background: '#000', padding: '2px 6px', borderRadius: 4 }}>{serviceBinaryPath(log)}</code>.
                </div>
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Service Policy Action Engine Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction(`Restart Service ${serviceName(log)}`)} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ⚡ Restart Service
                  </button>
                  <button type="button" onClick={() => handleAction(`Stop & Disable Service ${serviceName(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛑 Stop & Disable Service
                  </button>
                  <button type="button" onClick={() => handleAction(`Quarantine Service Binary ${serviceBinaryPath(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Quarantine Binary
                  </button>
                  <button type="button" onClick={() => handleAction('Mark Service as Approved Baseline')} style={{ padding: '8px 14px', background: `${MON.cyan}25`, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Mark Approved Baseline
                  </button>
                </div>
              </div>
            </div>
          )}

          {['config', 'binary', 'resource', 'security', 'dependency', 'mitre', 'health', 'timeline'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry Inspection</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10 }}>
                {(detailRows[activeTab] || []).map(([label, value]) => (
                  <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 10, minWidth: 0 }}>
                    <div style={{ color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{label}</div>
                    <div style={{ color: MON.text, fontSize: 11, marginTop: 4, overflowWrap: 'anywhere' }}>{printable(value)}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. POLICY RULE CREATOR WIZARD MODAL (`ServicePolicyWizardModal`)
// ═════════════════════════════════════════════════════════════════════════════
export function ServicePolicyWizardModal({ onClose, onSave }) {
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Antivirus / EDR Guard');
  const [severity, setSeverity] = useState('Critical');
  const [action, setAction] = useState('AUTO-RESTART & ALERT');
  const [servicePattern, setServicePattern] = useState('WinDefend, EDRService, wazuh-agent');
  const [cpuLimit, setCpuLimit] = useState('85');

  const categories = [
    'Antivirus / EDR Guard', 'New Service Creation', 'Binary Hash Tampering',
    'Startup Configuration', 'Service Deletion Guard', 'Account Privilege Escalation',
    'Remote Management Services', 'Crash & Restart Loop', 'Service Resource Spikes',
    'Windows Defender Status', 'Linux systemd Protection', 'Database & Web Services',
    'Persistence Detection', 'Dependency Monitoring', 'EDR Heartbeat Integrity'
  ];

  const actions = [
    'LOG & MONITOR', 'ALERT & NOTIFY SOC', 'AUTO-RESTART & ALERT',
    'STOP & DISABLE SERVICE', 'QUARANTINE BINARY', 'ISOLATE ENDPOINT', 'CRITICAL BLOCK & SOC ESCALATION'
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave({
      id: `svc-pol-${Date.now()}`,
      name: name.trim(),
      cat: category,
      action,
      severity,
      status: 'Active',
      details: { servicePattern, cpuLimit }
    });
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: 'min(720px, 95vw)', background: MON.bg, border: `1px solid ${MON.cyan}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.85)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22 }}>🛡️</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 900, color: MON.cyan }}>
                Service Policy Rule Creator Wizard
              </h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>
                Construct custom Windows service & Linux systemd daemon monitoring policies
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer' }}>✕</button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Policy Rule Title *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Auto-Restart Antivirus Service on Unauthorized Stop"
              value={name}
              onChange={e => setName(e.target.value)}
              style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 12, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Policy Category
              </label>
              <select value={category} onChange={e => setCategory(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Rule Severity
              </label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Action Engine Response
            </label>
            <select value={action} onChange={e => setAction(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.red, fontWeight: 800, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
              {actions.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>

          <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: MON.cyan }}>⚙️ Advanced Service Thresholds & Target Patterns</div>

            <div>
              <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Target Service Names (Comma Separated)</label>
              <input type="text" value={servicePattern} onChange={e => setServicePattern(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.yellow, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Resource Spike Limit (CPU % Threshold)</label>
              <input type="number" value={cpuLimit} onChange={e => setCpuLimit(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
            </div>
          </div>

          {/* Footer Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
            <button type="button" onClick={onClose} style={{ padding: '9px 18px', background: 'transparent', border: `1px solid ${MON.border}`, color: MON.muted, borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
              Cancel
            </button>
            <button type="submit" style={{ padding: '9px 22px', background: MON.cyan, border: 'none', color: '#000', borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
              ⚡ Deploy Service Policy
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SERVICE POLICY ENGINE MANAGEMENT PANEL (`ServicePolicyEngine`)
// ═════════════════════════════════════════════════════════════════════════════
export function ServicePolicyEngine() {
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [policies, setPolicies] = useState([
    { id: 'svc-pol-1', name: 'Antivirus & EDR Service Anti-Tamper Guard', cat: 'Antivirus / EDR Guard', action: 'AUTO-RESTART & CRITICAL ALERT', status: 'Active', severity: 'Critical' },
    { id: 'svc-pol-2', name: 'Unauthorized New Service Installation Block', cat: 'New Service Creation', action: 'STOP & DISABLE SERVICE', status: 'Active', severity: 'Critical' },
    { id: 'svc-pol-3', name: 'Service Executable Hash Tampering Guard', cat: 'Binary Hash Tampering', action: 'QUARANTINE BINARY & ISOLATE', status: 'Active', severity: 'Critical' },
    { id: 'svc-pol-4', name: 'Service Startup Type Change (Auto -> Disabled)', cat: 'Startup Configuration', action: 'ALERT & NOTIFY SOC', status: 'Active', severity: 'High' },
    { id: 'svc-pol-5', name: 'Critical Security Service Deletion Guard', cat: 'Service Deletion Guard', action: 'CRITICAL ALERT & RESTORE', status: 'Active', severity: 'Critical' },
    { id: 'svc-pol-6', name: 'Service Run As Domain Administrator', cat: 'Account Privilege Escalation', action: 'ALERT & PRIVILEGE AUDIT', status: 'Active', severity: 'High' },
    { id: 'svc-pol-7', name: 'Unauthorized Remote Desktop & Registry Services', cat: 'Remote Management Services', action: 'STOP SERVICE & ALERT', status: 'Active', severity: 'High' },
    { id: 'svc-pol-8', name: 'Repeated Service Failure & Crash Loop (>3 fails)', cat: 'Crash & Restart Loop', action: 'SOC INVESTIGATION ALERT', status: 'Active', severity: 'Medium' },
  ]);
  const [successMsg, setSuccessMsg] = useState(null);

  const togglePolicy = (id) => {
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: p.status === 'Active' ? 'Disabled' : 'Active' } : p));
  };

  const handleAddPolicy = (newPolicy) => {
    setPolicies(prev => [newPolicy, ...prev]);
    setIsWizardOpen(false);
    setSuccessMsg(`Service Policy "${newPolicy.name}" successfully created & deployed!`);
    setTimeout(() => setSuccessMsg(null), 4000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, color: MON.cyan, fontWeight: 900 }}>🛡️ Service Monitoring — Policy Engine</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Configure 15 Service Monitoring Categories: Windows Services, Linux systemd Daemons, Anti-Tamper Guards, and Automated Action Engines</div>
        </div>
        <button type="button" onClick={() => setIsWizardOpen(true)} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 900, cursor: 'pointer', fontSize: 12 }}>
          ➕ Create New Policy Rule
        </button>
      </div>

      {successMsg && (
        <div style={{ padding: '10px 14px', background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 800 }}>
          ✅ {successMsg}
        </div>
      )}

      {/* Policy Rules Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              <th style={{ padding: 10 }}>Policy Name</th>
              <th style={{ padding: 10 }}>Policy Category</th>
              <th style={{ padding: 10 }}>Action Engine Rule</th>
              <th style={{ padding: 10 }}>Severity</th>
              <th style={{ padding: 10 }}>Status</th>
              <th style={{ padding: 10 }}>Toggle</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id} style={{ borderBottom: `1px solid ${MON.line}` }}>
                <td style={{ padding: 10, color: MON.text, fontWeight: 900 }}>{p.name}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{p.cat}</td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 900 }}>{p.action}</td>
                <td style={{ padding: 10, color: p.severity === 'Critical' ? MON.red : MON.orange, fontWeight: 800 }}>{p.severity}</td>
                <td style={{ padding: 10, color: p.status === 'Active' ? MON.green : MON.sub, fontWeight: 900 }}>{p.status}</td>
                <td style={{ padding: 10 }}>
                  <button type="button" onClick={() => togglePolicy(p.id)} style={{ padding: '3px 10px', background: p.status === 'Active' ? `${MON.green}20` : `${MON.red}20`, border: `1px solid ${p.status === 'Active' ? MON.green : MON.red}55`, color: p.status === 'Active' ? MON.green : MON.red, borderRadius: 4, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>
                    {p.status === 'Active' ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isWizardOpen && <ServicePolicyWizardModal onClose={() => setIsWizardOpen(false)} onSave={handleAddPolicy} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
export function ServiceAnomalyLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${serviceName(a)} ${serviceDisplayName(a)} ${serviceRule(a)} ${alertHost(a)} ${serviceAccount(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Service Name, Rule, Target Host, Account..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Service Monitoring Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Detection Rule / Event</span><span>Target Host</span><span>Service Name</span><span>Run As Account</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{serviceRule(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.yellow }}>{serviceName(row)}</span>
                <span style={{ color: MON.purple }}>{serviceAccount(row)}</span>
                <b style={{ color: serviceRiskScore(row) > 75 ? MON.red : MON.orange }}>{serviceRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No service monitoring logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <ServiceForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

function LegacyServiceAnomalyReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);

  const getFilteredAlerts = () => {
    const now = Date.now();
    const dayMs = 86400000;
    const windowMap = { daily: 1, weekly: 7, monthly: 30, '90days': 90 };
    const days = windowMap[reportType] || 90;
    const cutoff = now - days * dayMs;
    const filtered = alerts.filter(a => {
      const t = alertTime(a);
      return t ? new Date(t).getTime() >= cutoff : true;
    });
    return filtered.length > 0 ? filtered : alerts;
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const days = { daily: 1, weekly: 7, monthly: 30, '90days': 90 }[reportType] || 90;
      const to = new Date();
      const from = new Date(to.getTime() - days * 86400000);
      const response = await api.get('/service-monitoring/events', { params: { from: from.toISOString(), to: to.toISOString(), limit: 2000 }, skipCache: true });
      const filtered = Array.isArray(response.data?.events) ? response.data.events : getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: Number(response.data?.total || filtered.length),
        bySev,
      });
      setGenerated(true);
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => { const s = alertSeverity(a); if (bySev[s] !== undefined) bySev[s] += 1; });
      setReportData({ alerts: filtered, total: filtered.length, bySev });
      setGenerated(true);
    } finally {
      setGenerating(false);
    }
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Event Rule,Service Name,Display Name,Target Host,Account,Risk Score,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(serviceRule(a)),
      csvCell(serviceName(a)),
      csvCell(serviceDisplayName(a)),
      csvCell(alertHost(a)),
      csvCell(serviceAccount(a)),
      csvCell(serviceRiskScore(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `service_monitoring_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Service Monitoring Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for Windows Services, systemd daemons, security service anti-tamper events, and persistence detection</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Service Report'}
          </button>
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📅 Select Time Window</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              { key: 'daily', label: '24 Hours', icon: '⏱', sub: 'Last 24h' },
              { key: 'weekly', label: '1 Week', icon: '📆', sub: 'Last 7 days' },
              { key: 'monthly', label: '1 Month', icon: '🗓', sub: 'Last 30 days' },
              { key: '90days', label: '3 Months', icon: '📊', sub: 'Last 90 days' },
            ].map(opt => {
              const active = reportType === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => { setReportType(opt.key); setGenerated(false); }}
                  style={{
                    background: active ? MON.cyan : MON.card2,
                    color: active ? '#000' : MON.text,
                    border: `2px solid ${active ? MON.cyan : MON.border}`,
                    borderRadius: 8, padding: '10px 18px', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, minWidth: 100,
                    fontWeight: active ? 900 : 600,
                  }}
                >
                  <span style={{ fontSize: 18 }}>{opt.icon}</span>
                  <span style={{ fontSize: 12, fontWeight: 800 }}>{opt.label}</span>
                  <span style={{ fontSize: 9, opacity: 0.7 }}>{opt.sub}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Service Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Service Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Service Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Service Tampering', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Service Failures', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Healthy Service Starts', val: reportData?.bySev?.low, color: MON.green },
            ].map(c => (
              <div key={c.label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 9, color: MON.muted, fontWeight: 700, textTransform: 'uppercase' }}>{c.label}</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: c.color, marginTop: 6 }}>{c.val}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function ServiceAnomalyReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={24} alerts={alerts} />;
}

// ── Visual Helper Components for Service Monitoring Dashboard ─────────────
function TopServiceChangesChart({ data = [] }) {
  const points = (data.length ? data : Array(12).fill(0)).map(point => Number(point?.count ?? point) || 0);
  const maxVal = Math.max(...points, 1);
  const width = 360;
  const height = 90;

  const getSvgPath = (pts) => {
    return pts.map((val, idx) => {
      const x = (idx / (pts.length - 1)) * width;
      const y = height - (val / maxVal) * (height - 10) - 5;
      return `${x},${y}`;
    }).join(' L ');
  };

  const areaPath = `M 0,${height} L ${getSvgPath(points)} L ${width},${height} Z`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top 10 Service Changes <span style={{ fontSize: 8, color: '#64748b' }}>(Last 24h)</span></span>
        </div>

        <div style={{ position: 'relative', width: '100%', height: 90 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" style={{ overflow: 'visible' }}>
            <defs>
              <linearGradient id="serviceGrad" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.3" />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
              </linearGradient>
            </defs>
            <path d={areaPath} fill="url(#serviceGrad)" />
            <path d={`M ${getSvgPath(points)}`} fill="none" stroke="#38bdf8" strokeWidth="2" />
            <circle cx={width} cy={height - ((points[points.length - 1] || 0) / maxVal) * (height - 10) - 5} r="3" fill="#38bdf8" />
          </svg>

          <div style={{ position: 'absolute', right: 0, top: 10, background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '2px 6px', fontSize: 7, color: '#8ea0b8' }}>
            <span>Latest</span><br />
            <b style={{ color: '#38bdf8' }}>Changes: {points[points.length - 1] || 0}</b>
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
          {['12 PM', '04 PM', '08 PM', '12 AM', '04 AM', '08 AM'].map(t => (
            <span key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function ServiceStatusDistributionDonut({ summary = {} }) {
  const totalServices = Number(summary.totalServices || 0);
  const items = [
    { label: 'Running', val: Number(summary.running || 0), color: '#22c55e' },
    { label: 'Stopped', val: Number(summary.stopped || 0), color: '#eab308' },
    { label: 'Failed', val: Number(summary.failed || 0), color: '#ef4444' },
    { label: 'Unknown', val: Number(summary.unknown || 0), color: '#64748b' },
  ].map(item => ({ ...item, pct: totalServices ? Number(((item.val / totalServices) * 100).toFixed(1)) : 0 }));

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = items.map((s) => {
    const angle = (s.pct / 100) * 360;
    const startAngle = cumAngle;
    const endAngle = cumAngle + angle;
    cumAngle += angle;

    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (endAngle - 90) * (Math.PI / 180);

    const x1 = cx + radius * Math.cos(startRad);
    const y1 = cy + radius * Math.sin(startRad);
    const x2 = cx + radius * Math.cos(endRad);
    const y2 = cy + radius * Math.sin(endRad);

    const largeArcFlag = angle > 180 ? 1 : 0;
    const d = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`;

    return { ...s, d };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Service Status Distribution</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(totalServices)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.val} <span style={{ fontSize: 7, color: '#64748b' }}>({it.pct}%)</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ServiceHealthScoreGauge({ score = 0 }) {
  const normalized = Math.max(0, Math.min(100, Number(score) || 0));
  const color = normalized >= 80 ? '#22c55e' : normalized >= 60 ? '#eab308' : '#ef4444';
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', alignItems: 'center', textAlign: 'center' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', alignSelf: 'flex-start' }}>Service Health Score</span>
      <div style={{ position: 'relative', width: 120, height: 65, marginTop: 4 }}>
        <svg viewBox="0 0 120 65" width="120" height="65">
          <path d="M 10 60 A 50 50 0 0 1 110 60" fill="none" stroke="#16273e" strokeWidth="10" strokeLinecap="round" />
          <path d="M 10 60 A 50 50 0 0 1 110 60" fill="none" stroke={color} strokeWidth="10" strokeLinecap="round" pathLength="100" strokeDasharray={`${normalized} 100`} />
        </svg>
        <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, textAlign: 'center' }}>
          <span style={{ fontSize: 20, fontWeight: 900, color: '#fff' }}>{normalized}</span>
          <span style={{ fontSize: 10, color: '#8ea0b8' }}> /100</span>
          <div style={{ fontSize: 9, fontWeight: 800, color, marginTop: -2 }}>{normalized >= 80 ? 'Healthy' : normalized >= 60 ? 'Degraded' : 'At Risk'}</div>
        </div>
      </div>
    </div>
  );
}

function ServiceOverviewDashboard({ alerts = [], total = 0, data = null, onRefresh }) {
  const [resourceTab, setResourceTab] = useState('CPU');

  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const summary = data?.summary || {};
  const totalServices = Number(summary.totalServices || 0);
  const percent = value => totalServices ? `${((Number(value || 0) / totalServices) * 100).toFixed(1)}%` : '0%';
  const topCards = [
    { title: 'Total Services', val: shortNum(totalServices), sub: `${shortNum(summary.endpointsReporting || 0)} endpoints`, col: '#38bdf8', icon: '🗄️' },
    { title: 'Running', val: shortNum(summary.running), sub: percent(summary.running), col: '#22c55e', icon: '▶️' },
    { title: 'Stopped', val: shortNum(summary.stopped), sub: percent(summary.stopped), col: '#eab308', icon: '⏹️' },
    { title: 'Failed', val: shortNum(summary.failed), sub: percent(summary.failed), col: '#ef4444', icon: '❌' },
    { title: 'New Services (24h)', val: shortNum(summary.newServices24h), sub: 'Live events', col: '#a78bfa', icon: '📋' },
    { title: 'Service Changes (24h)', val: shortNum(summary.serviceChanges24h ?? total), sub: 'Live events', col: '#38bdf8', icon: '⚙️' },
  ];

  const criticalSecurityServices = (data?.criticalServices || []).map(service => {
    const status = serviceStatus(service);
    return { name: serviceName(service), status, col: /running/i.test(status) ? '#22c55e' : /failed/i.test(status) ? '#ef4444' : '#eab308' };
  });

  const recentServiceEvents = alerts.slice(0, 7).map(row => {
    const status = serviceStatus(row);
    const severity = alertSeverity(row);
    return {
      time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
      asset: alertHost(row), assetType: processOs(row).startsWith('Linux') ? '🐧' : '🪟',
      service: serviceName(row), evt: serviceRule(row), status,
      statusCol: /running/i.test(status) ? '#22c55e' : /failed/i.test(status) ? '#ef4444' : '#eab308',
      user: alertUser(row) !== 'Unknown user' ? alertUser(row) : serviceAccount(row),
      details: row.description || 'Service telemetry event', sev: severity,
      sevCol: SEV_COLOR[severity] || '#38bdf8',
    };
  });

  const resourceFields = {
    CPU: ['processCpuPercent', 'cpu_percent'], Memory: ['processMemoryPercent', 'memory_percent'],
    Disk: ['processDiskWriteBytesPerSecond', 'disk_write_bytes_per_second'], Network: ['processNetworkConnectionCount', 'network_connection_count'],
  };
  const resourceUsageData = Object.fromEntries(Object.entries(resourceFields).map(([label, keys]) => [label, alerts
    .map(row => ({ name: serviceName(row), pct: Number(keys.map(key => row?.[key] ?? serviceRaw(row)?.[key]).find(value => value != null) || 0) }))
    .filter(item => item.pct > 0).sort((a, b) => b.pct - a.pct).slice(0, 5)]));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* Filters Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <span style={{ background: '#07101b', border: '1px solid #16273e', padding: '3px 8px', borderRadius: 4, color: '#cbd5e1' }}>All Groups v</span>
          <span style={{ background: '#07101b', border: '1px solid #16273e', padding: '3px 8px', borderRadius: 4, color: '#cbd5e1' }}>All Assets v</span>
          <span style={{ background: '#07101b', border: '1px solid #16273e', padding: '3px 8px', borderRadius: 4, color: '#cbd5e1' }}>All OS v</span>
          <span style={{ background: '#07101b', border: '1px solid #16273e', padding: '3px 8px', borderRadius: 4, color: '#cbd5e1' }}>All Service Status v</span>
          <span style={{ background: '#07101b', border: '1px solid #16273e', padding: '3px 8px', borderRadius: 4, color: '#cbd5e1' }}>📅 Last 24 Hours v</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#64748b' }}>
          <span>Last Updated: {data?.until ? new Date(data.until).toLocaleTimeString() : 'Waiting for telemetry'}</span>
          <span onClick={onRefresh} style={{ color: '#38bdf8', fontWeight: 800, cursor: 'pointer' }}>🔄 Refresh</span>
        </div>
      </div>

      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        {topCards.map(s => (
          <div key={s.title} style={{ ...panelStyle, padding: '10px 10px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: '#8ea0b8', fontWeight: 800 }}>{s.title}</span>
              <span style={{ fontSize: 10 }}>{s.icon}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>{s.val}</div>
            <span style={{ fontSize: 7.5, color: s.col, fontWeight: 700 }}>{s.sub}</span>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (4 Panels Grid Layout) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr 1fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <ServiceStatusDistributionDonut summary={summary} />
        </div>

        <div style={panelStyle}>
          <TopServiceChangesChart data={data?.timeline || []} />
        </div>

        <div style={panelStyle}>
          <ServiceHealthScoreGauge score={summary.healthScore} />
        </div>

        {/* Critical Security Services */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Critical Security Services</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 3, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>Service Name</span>
              <span>Status</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4, fontSize: 7.5 }}>
              {criticalSecurityServices.map(css => (
                <div key={css.name} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr', gap: 4, alignItems: 'center' }}>
                  <span style={{ color: '#cbd5e1' }}>{css.name}</span>
                  <span style={{ color: css.col, fontWeight: 800 }}>{css.status}</span>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 4 }}>View All ({criticalSecurityServices.length})</span>
        </div>
      </div>

      {/* 3. LOWER MIDDLE & BOTTOM SECTION (2 Main Columns: Left 70%, Right 30%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '2.4fr 1fr', gap: 12 }}>
        {/* Left Column: Recent Service Events */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Recent Service Events</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1fr 1.4fr 1fr 0.7fr 1.2fr 1.5fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>Asset</span>
              <span>Service Name</span>
              <span>Event Type</span>
              <span>Status</span>
              <span>User/Account</span>
              <span>Details</span>
              <span>Severity</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {recentServiceEvents.map((rse, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.9fr 1fr 1.4fr 1fr 0.7fr 1.2fr 1.5fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#64748b' }}>{rse.time}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{rse.assetType} {rse.asset}</span>
                  <span style={{ color: '#e2e8f0' }}>{rse.service}</span>
                  <span style={{ color: '#cbd5e1' }}>{rse.evt}</span>
                  <span style={{ color: rse.statusCol, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: rse.statusCol }} /> {rse.status}
                  </span>
                  <span style={{ color: '#8ea0b8' }}>{rse.user}</span>
                  <span style={{ color: '#8ea0b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rse.details}</span>
                  <span style={{ fontSize: 7, fontWeight: 800, color: rse.sevCol, padding: '1px 3px', background: `${rse.sevCol}15`, borderRadius: 3, border: `1px solid ${rse.sevCol}33`, textAlign: 'center' }}>
                    {rse.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderTop: '1px solid #16273e', paddingTop: 8, marginTop: 8, fontSize: 8, color: '#64748b' }}>
            <span>Showing {recentServiceEvents.length ? 1 : 0} to {recentServiceEvents.length} of {Number(total || alerts.length || 0)} entries</span>
            <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
              <span style={{ padding: '2px 6px', background: '#07101b', borderRadius: 3, cursor: 'pointer' }}>&lt;</span>
              <span style={{ padding: '2px 6px', background: '#38bdf8', color: '#000', fontWeight: 800, borderRadius: 3, cursor: 'pointer' }}>1</span>
              <span style={{ padding: '2px 6px', background: '#07101b', borderRadius: 3, cursor: 'pointer' }}>2</span>
              <span style={{ padding: '2px 6px', background: '#07101b', borderRadius: 3, cursor: 'pointer' }}>3</span>
              <span>...</span>
              <span style={{ padding: '2px 6px', background: '#07101b', borderRadius: 3, cursor: 'pointer' }}>6</span>
              <span style={{ padding: '2px 6px', background: '#07101b', borderRadius: 3, cursor: 'pointer' }}>&gt;</span>
            </div>
          </div>
        </div>

        {/* Right Column: Resource Usage + Alerts Summary */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Top Resource Usage by Services */}
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Resource Usage by Services</span>
              </div>
              <div style={{ display: 'flex', gap: 4, marginBottom: 8 }}>
                {['CPU', 'Memory', 'Disk', 'Network'].map(t => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setResourceTab(t)}
                    style={{
                      background: resourceTab === t ? '#38bdf8' : '#07101b',
                      color: resourceTab === t ? '#000' : '#8ea0b8',
                      border: '1px solid #16273e',
                      borderRadius: 3, padding: '2px 8px', fontSize: 7.5, fontWeight: 800, cursor: 'pointer',
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {(resourceUsageData[resourceTab] || resourceUsageData.CPU).map(item => (
                  <div key={item.name} style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 7.5 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: '#cbd5e1' }}>{item.name}</span>
                      <span style={{ color: '#38bdf8', fontWeight: 800 }}>{item.pct}%</span>
                    </div>
                    <div style={{ width: '100%', height: 4, background: '#07101b', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${Math.min(100, item.pct * 2.5)}%`, height: '100%', background: '#38bdf8', borderRadius: 2 }} />
                    </div>
                  </div>
                ))}
              </div>
            </div>
            <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All</span>
          </div>

          {/* Service Alerts Summary */}
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Service Alerts Summary</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 8.5 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 6 }}>🚨 Critical Alerts</span>
                  <span style={{ color: '#ef4444', fontWeight: 900 }}>{shortNum(summary.criticalAlerts)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#eab308', display: 'flex', alignItems: 'center', gap: 6 }}>⚠️ Warning Alerts</span>
                  <span style={{ color: '#eab308', fontWeight: 900 }}>{shortNum(summary.highAlerts)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 6 }}>ℹ️ Informational Alerts</span>
                  <span style={{ color: '#38bdf8', fontWeight: 900 }}>{shortNum((summary.bySeverity?.medium || 0) + (summary.bySeverity?.low || 0))}</span>
                </div>
              </div>
            </div>
            <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 8 }}>View All Alerts</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD COMPONENT (`ServiceMonitoringDashboardPanel` / `ServiceMonitoringDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function ServiceMonitoringDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);

  useEffect(() => {
    if (systems.length) { setBackendSystems(systems); return; }
    let active = true;
    api.get('/system')
      .then(r => {
        if (!active) return;
        const rows = r.data?.systems || r.data?.agents || r.data || [];
        setBackendSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setBackendSystems([]); });
    return () => { active = false; };
  }, [systems]);

  const rows = Array.isArray(alerts) ? alerts : [];
  const totalRows = total || recordsTotal || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const summary = data?.summary || {};
  const inventory = Array.isArray(data?.services) ? data.services : [];
  const eventCount = pattern => rows.filter(row => pattern.test(String(serviceRule(row)))).length;
  const securityServices = inventory.filter(row => row.serviceSecurityCritical || /ajnat|soc-agent|defender|firewall|antivirus|clam|auditd|suricata|zeek|wazuh|elastic-agent|falcon|sentinel/i.test(serviceName(row)));
  const securityOperational = securityServices.length > 0 && securityServices.every(row => /running|active/i.test(serviceStatus(row)));
  const edrServices = securityServices.filter(row => /ajnat|soc-agent|edr|wazuh|elastic-agent|falcon|sentinel/i.test(serviceName(row)));
  const edrOperational = edrServices.length > 0 && edrServices.every(row => /running|active/i.test(serviceStatus(row)));

  // 20 Service Specific SOC Categories & Metrics
  const kpis = [
    { label: '⚙️ 1. Total Service Monitoring Events', val: shortNum(totalRows), trend: 'Services', color: MON.blue, data: timeline },
    { label: '▶️ 2. Currently Running Services', val: shortNum(summary.running), trend: 'Running', color: MON.green, data: timeline },
    { label: '⏹️ 3. Stopped Services (Manual/Disabled)', val: shortNum(summary.stopped), trend: 'Stopped', color: MON.yellow, data: timeline },
    { label: '💥 4. Failed Services & Crash Loops', val: shortNum(summary.failed), trend: 'Failed', color: MON.red, data: timeline },
    { label: '➕ 5. New Service Creation (24h)', val: shortNum(summary.newServices24h), trend: 'New Services', color: MON.purple, data: timeline },
    { label: '🔧 6. Service Config Changes (Auto->Manual)', val: shortNum(eventCount(/CONFIG_CHANGED|ASSET_CHANGED/i)), trend: 'Config Edits', color: MON.orange, data: timeline },
    { label: '🛡️ 7. Antivirus (Defender) Service Status', val: securityOperational ? 'Operational' : securityServices.length ? 'Attention' : 'No Data', trend: 'AV Protected', color: securityOperational ? MON.green : MON.yellow, data: timeline },
    { label: '🛰 8. EDR Agent Service Status', val: edrOperational ? 'Operational' : edrServices.length ? 'Attention' : 'No Data', trend: 'EDR Online', color: edrOperational ? MON.green : MON.yellow, data: timeline },
    { label: '🔑 9. Service Executable Hash Tampering', val: shortNum(eventCount(/BINARY|HASH|TAMPER/i)), trend: 'Tamper Alert', color: MON.red, data: timeline },
    { label: '👤 10. Service Account Privileges (LocalSystem)', val: shortNum(inventory.filter(row => /system|root|administrator/i.test(serviceAccount(row))).length), trend: 'System Account', color: MON.purple, data: timeline },
    { label: '🖥️ 11. Unauthorized Remote Access Services', val: shortNum(rows.filter(row => /remote|psexec|winrm|ssh|rdp/i.test(`${serviceName(row)} ${row.description || ''}`)).length), trend: 'Remote Access', color: MON.red, data: timeline },
    { label: '💻 12. Windows Server Services Monitored', val: shortNum(inventory.filter(row => /windows/i.test(processOs(row))).length), trend: 'Windows Srv', color: MON.cyan, data: timeline },
    { label: '🐧 13. Linux systemd Daemons Monitored', val: shortNum(inventory.filter(row => /linux/i.test(processOs(row))).length), trend: 'Linux Daemons', color: MON.purple, data: timeline },
    { label: '🚨 14. Critical Service Security Alerts', val: shortNum(sevCounts.critical), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 15. High Severity Service Anomalies', val: shortNum(sevCounts.high), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🖥️ 16. Endpoints Reporting Services', val: shortNum(backendSystems.length), trend: 'Endpoints', color: MON.cyan, data: timeline },
    { label: '💖 17. Service Health Score', val: `${Number(summary.healthScore || 0)}/100`, trend: 'Health Score', color: Number(summary.healthScore || 0) >= 80 ? MON.green : MON.yellow, data: timeline },
    { label: '📊 18. Service CPU & Memory Resource Spikes', val: shortNum(rows.filter(row => Number(row.processCpuPercent || 0) >= 80 || Number(row.processMemoryPercent || 0) >= 80).length), trend: 'Spike Alerts', color: MON.yellow, data: timeline },
    { label: '🔗 19. Service Dependency Failure Chain', val: shortNum(eventCount(/DEPENDENC/i)), trend: 'Dependency Fail', color: MON.orange, data: timeline },
    { label: '🔒 20. Persistence Service Detection (Malicious)', val: shortNum(rows.filter(row => /SERVICE_CREATED|persistence/i.test(`${serviceRule(row)} ${row.description || ''}`) && serviceRiskScore(row) >= 60).length), trend: 'Persistence', color: MON.red, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const hostServices = inventory.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'active'),
      monitor: true,
      events: hostEvents,
      services: hostServices,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || new Date().toISOString(),
    });
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📊', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'log-monitor', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
        ].map(item => {
          const selected = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                background: selected ? item.activeColor : 'transparent',
                color: selected ? (item.id === 'reports' ? '#fff' : '#000') : MON.text,
                border: selected ? `1px solid ${item.activeColor}` : '1px solid transparent',
                padding: '10px 12px', borderRadius: 7, fontSize: 12, fontWeight: 800,
                textAlign: 'left', cursor: 'pointer',
              }}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </aside>

      {/* Main Container */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>
        {activeTab === 'log-monitor' ? (
          <ServiceAnomalyLogMonitor alerts={alerts} onAction={onAction} />
        ) : activeTab === 'reports' ? (
          <ServiceAnomalyReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <ServiceOverviewDashboard alerts={alerts} total={totalRows} data={data} onRefresh={onRefresh} />
        ) : (
          <>
            {/* 20 Top KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: MON.muted }}>{kpi.label}</div>
                    <span style={{ fontSize: 9, fontWeight: 800, color: MON.green, background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>{kpi.trend}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Service Inspection (Windows Services & Linux systemd Daemons)</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Real-Time Service Manager Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>Service Engine</span><span>Total Services</span><span>Service Anomalies</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: MON.green, textTransform: 'uppercase' }}>Active</b>
                  <b>{row.services}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{new Date(row.lastSeen).toLocaleTimeString()}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Service Anomaly Event Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} service anomalies`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Flagged Services</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(data?.topServices || []).slice(0, 4).map(({ name: svc, count }, index) => [svc, `${count} Events`, [MON.red, MON.orange, MON.purple, MON.yellow][index]]).map(([svc, cnt, col]) => (
                    <div key={svc} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{svc}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{cnt}</span>
                    </div>
                  ))}
                  {!data?.topServices?.length && <span style={{ color: MON.muted }}>No service events in the selected window.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Service Policy Protection Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['AV / EDR Anti-Tamper', securityServices.length ? 'Monitored' : 'No telemetry', securityServices.length ? MON.green : MON.yellow],
                    ['Unauthorized Service Install', eventCount(/SERVICE_CREATED/i) ? 'Events detected' : 'No events', eventCount(/SERVICE_CREATED/i) ? MON.orange : MON.green],
                    ['Service Executable Hash', inventory.some(row => serviceRaw(row).service_binary_sha256 || row.serviceBinarySha256) ? 'Telemetry active' : 'Awaiting telemetry', inventory.some(row => serviceRaw(row).service_binary_sha256 || row.serviceBinarySha256) ? MON.green : MON.yellow],
                    ['Remote Access Services', rows.some(row => /remote|psexec|winrm|ssh|rdp/i.test(`${serviceName(row)} ${row.description || ''}`)) ? 'Events detected' : 'Monitored', rows.some(row => /remote|psexec|winrm|ssh|rdp/i.test(`${serviceName(row)} ${row.description || ''}`)) ? MON.orange : MON.green],
                  ].map(([lbl, stat, col]) => (
                    <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{lbl}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. OVERLAY CAPABILITY MODAL EXPORT (`ServiceMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function ServiceMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '24';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [serviceData, setServiceData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/service-monitoring/overview', { params: { windowHours: 24, limit: 500 }, skipCache: quiet });
      const next = r.data?.events || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
      setServiceData(r.data || null);
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);
    } catch {
      setAlerts([]);
      setServiceData(null);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  const loadSystems = useCallback(async () => {
    try {
      const r = await api.get('/system');
      setSystems(Array.isArray(r.data?.systems || r.data) ? (r.data?.systems || r.data) : []);
    } catch {
      setSystems([]);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    loadSystems();
    const interval = setInterval(() => loadAlerts(true), 15000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('service:alert', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('service:alert', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            ⚙️ 24. Service Monitoring & Security Agent Control
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <ServiceMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={serviceData} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <ServiceMonitoringPage />;
}

export function ServiceSocTabPage({ tab }) {
  return <ServiceMonitoringDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function ServiceSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=24" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Service Monitoring SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=24')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="servicemonitoring" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <ServiceMonitoringDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { ServiceMonitoringDashboardPanel as ServiceMonitoringDashboard };
export { ServiceSubTabPage as ServiceMonitoringSubTabPage };
