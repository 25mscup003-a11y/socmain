import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Time-Based Anomaly Detection — Capability ID: 22 (Backend ID: 22)
 *
 * 100% Self-Contained Enterprise SOC Agent-Based Time-Based Anomaly Monitoring Module
 * Tracks 50+ Agent-Based Time Anomaly Monitoring Points (After-Hours Login, Weekend Activity, Mass File Encryption at Night, Off-Hours Admin Elevation, Data Transfer Bursts, etc.)
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=22`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19), API Call (20), Script (21)
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

function MiniSparkline({ data = [], color = MON.cyan, height = 30 }) {
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || row?.rawEvent?.hostname || row?.rawEvent?.host || 'Unknown host';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || row?.rawEvent?.username || row?.rawEvent?.user || 'Unknown user';
}

function alertStatus(row) {
  return row?.status || row?.state || 'Observed';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'info').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'critical';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Windows';
}

// ── 50+ Agent-Based Time Anomaly Monitoring Categories ──────────────────────
const TIME_MONITOR_CATEGORIES = [
  'Login Outside Business Hours', 'Late Night User Login', 'Weekend Login Activity', 'Holiday Access Attempts',
  'Multiple Logins in Short Time', 'Rapid Logoff / Logon Events', 'Unusual Working Hour Access', 'Server Access at Odd Hours',
  'Administrator Login After Hours', 'Service Account Usage at Unusual Time', 'Scheduled Task Running at Wrong Time', 'Cron Job Execution Anomaly',
  'Startup Program Trigger at Unexpected Time', 'Process Execution Outside Baseline Hours', 'Application Launch at Unusual Time', 'USB Usage During Non-Working Hours',
  'File Access During Night Hours', 'Mass File Modification in Short Duration', 'Bulk File Deletion in Few Minutes', 'Sudden File Encryption Activity',
  'Registry Changes at Odd Hours', 'Configuration Changes After Hours', 'Software Installation at Unusual Time', 'Patch Deployment Outside Maintenance Window',
  'Network Connection Spike', 'Data Transfer During Night Hours', 'Large Upload Activity at Unusual Time', 'Large Download Activity at Unusual Time',
  'DNS Request Burst', 'API Call Burst Activity', 'Privilege Escalation at Odd Hours', 'Password Change at Unusual Time',
  'New User Creation After Hours', 'Security Policy Modification at Night', 'Firewall Rule Changes at Unexpected Time', 'Antivirus Disabled at Odd Hours',
  'EDR Agent Stopped Unexpectedly', 'Log Clearing Activity', 'Backup Process Failure Timing', 'Backup Running Outside Schedule',
  'Database Access During Restricted Hours', 'Database Query Spike', 'Email Sending Burst', 'Email Attachment Surge',
  'Remote Desktop Session at Night', 'VPN Login at Unusual Time', 'Lateral Movement Attempts in Short Duration', 'Command Execution Burst',
  'Script Execution During Off Hours', 'Repeated Failed Login Attempts Over Time'
];

function anomalyType(row) {
  return row?.anomalyType || row?.rawEvent?.anomaly_type || row?.rawEvent?.anomalyType || row?.detectionRuleName || row?.ruleName || row?.eventType || row?.ruleId || row?.category || 'Time anomaly event';
}

function anomalyTimeWindow(row) {
  return row?.timeWindow || row?.timeWindowDesc || row?.rawEvent?.time_window || row?.rawEvent?.raw?.time_window || 'Not reported';
}

function anomalyBaselineDiff(row) {
  return row?.baselineDiff || row?.rawEvent?.baseline_diff || row?.rawEvent?.raw?.baseline_diff || 'Not reported';
}

function anomalyRiskScore(row) {
  const score = Number(row?.riskScore ?? row?.score);
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${alertUser(row)}`;
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
// 1. TIME ANOMALY FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function TimeAnomalyDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const rawRoot = log.rawEvent && typeof log.rawEvent === 'object' ? log.rawEvent : {};
  const raw = { ...(rawRoot.raw && typeof rawRoot.raw === 'object' ? rawRoot.raw : {}), ...rawRoot };
  const fieldValue = (...values) => values.find(value => value !== undefined && value !== null && value !== '') ?? 'Not reported';
  const tabFields = {
    loginmatrix: [
      ['Authentication action', fieldValue(log.userAction, raw.user_action, raw.auth_action)],
      ['Authentication method', fieldValue(raw.auth_method, raw.authenticationMethod)],
      ['User account', alertUser(log)],
      ['Source IP', fieldValue(log.srcip, raw.src_ip, raw.source_ip)],
      ['Expected time', fieldValue(log.expectedTime, raw.expected_time)],
      ['Actual time', fieldValue(log.actualTime, raw.actual_time, alertTime(log))],
    ],
    process: [
      ['Process', fieldValue(log.processName, raw.process_name, raw.process)],
      ['PID', fieldValue(log.pid, raw.pid)],
      ['Parent process', fieldValue(log.parentProcessName, raw.parent_process_name)],
      ['Parent PID', fieldValue(log.parentPid, raw.parent_pid)],
      ['Command line', fieldValue(log.processCmdline, raw.command_line, raw.cmdline)],
      ['Executable hash', fieldValue(log.processExecutableSha256, raw.executable_sha256, log.fileHash)],
    ],
    file: [
      ['File path', fieldValue(log.filePath, raw.file_path)],
      ['File action', fieldValue(log.fileAction, raw.file_action)],
      ['File hash', fieldValue(log.fileHash, raw.file_hash, raw.sha256)],
      ['Affected files', fieldValue(log.affectedFiles, raw.affected_files)],
      ['Bytes transferred', fieldValue(log.bytesTransferred, raw.bytes_transferred)],
    ],
    network: [
      ['Source IP', fieldValue(log.srcip, raw.src_ip, raw.source_ip)],
      ['Destination IP', fieldValue(log.destip, raw.dst_ip, raw.destination_ip)],
      ['Destination port', fieldValue(log.destPort, raw.dst_port, raw.destination_port)],
      ['Protocol', fieldValue(log.protocol, raw.protocol)],
      ['Bytes sent', fieldValue(log.bytesSent, raw.bytes_sent)],
      ['Bytes received', fieldValue(log.bytesReceived, raw.bytes_received)],
    ],
    security: [
      ['Detection rule', fieldValue(log.ruleId, raw.rule_id)],
      ['Source event', fieldValue(log.sourceEvent, raw.source_event)],
      ['Risk score', `${anomalyRiskScore(log)}/100`],
      ['Severity', sev],
      ['Status', alertStatus(log)],
      ['Detection reason', fieldValue(log.description, raw.description)],
    ],
    mitre: [
      ['Technique ID', fieldValue(log.mitreId, raw.mitre_id, raw.mitreTechnique)],
      ['Technique name', fieldValue(log.mitreName, raw.mitre_name)],
      ['Tactic', fieldValue(log.mitreTactic, raw.mitre_tactic)],
      ['Evidence', fieldValue(log.description, raw.description)],
    ],
    agent: [
      ['Agent', fieldValue(log.agentName, log.systemId?.name, raw.agent_name)],
      ['Hostname', alertHost(log)],
      ['Operating system', fieldValue(log.osType, log.systemId?.osType, raw.os, raw.platform)],
      ['Agent version', fieldValue(log.agentVersion, log.systemId?.agentVersion, raw.agent_version)],
      ['Telemetry source', fieldValue(log.source, raw.source, raw.log_source)],
      ['Event ID', fieldValue(log.eventId, raw.event_id, log._id)],
    ],
    timeline: [
      ['Observed at', fieldValue(alertTime(log))],
      ['Expected window', fieldValue(log.expectedTime, raw.expected_time)],
      ['Actual activity time', fieldValue(log.actualTime, raw.actual_time)],
      ['Time deviation', anomalyBaselineDiff(log)],
      ['Historical frequency', fieldValue(raw.historical_frequency)],
      ['Baseline confidence', `${Number(fieldValue(log.baselineConfidence, raw.baseline_confidence, 0)) || 0}%`],
      ['Related events', Array.isArray(log.relatedEvents) ? log.relatedEvents.length : 0],
    ],
  };

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'loginmatrix', label: '🔐 2. Login & Auth Matrix' },
    { id: 'process', label: '⚙️ 3. Process Execution' },
    { id: 'file', label: '📁 4. File & Encryption Volatility' },
    { id: 'network', label: '🌐 5. Network & Data Burst' },
    { id: 'security', label: '🛡️ 6. Security & Admin Changes' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK Map' },
    { id: 'agent', label: '🛰️ 8. Agent Infrastructure' },
    { id: 'timeline', label: '⏱️ 9. Chronological Timeline' },
    { id: 'actions', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionName) => {
    const actionType = /isolate/i.test(actionName) ? 'isolate' : /authorized|confirm/i.test(actionName) ? 'ignore' : null;
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
            <span style={{ fontSize: 24 }}>⏱️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Time Anomaly Investigation — {anomalyType(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {anomalyRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Host: <strong style={{ color: MON.cyan }}>{alertHost(log)}</strong> | User: <strong style={{ color: MON.yellow }}>{alertUser(log)}</strong> | Time Window: <strong>{anomalyTimeWindow(log)}</strong> | Baseline Shift: <strong style={{ color: MON.red }}>{anomalyBaselineDiff(log)}</strong>
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
                  ['Anomaly Monitor Category', anomalyType(log), sevColor],
                  ['Risk Score', `${anomalyRiskScore(log)} / 100`, MON.red],
                  ['Time Window Triggered', anomalyTimeWindow(log), MON.yellow],
                  ['Baseline Deviation Shift', anomalyBaselineDiff(log), MON.orange],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>⏱️ Agent Time Pattern Analysis Summary</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  <strong>{fieldValue(log.description, raw.description, anomalyType(log))}</strong> Agent <strong>{alertHost(log)}</strong> reported this activity for <strong>{alertUser(log)}</strong> in <strong>{anomalyTimeWindow(log)}</strong>. Baseline evidence: <strong>{anomalyBaselineDiff(log)}</strong>; confidence <strong>{Number(fieldValue(log.baselineConfidence, raw.baseline_confidence, 0)) || 0}%</strong>.
                </div>
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Automated SOC Time Anomaly Response Actions</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction(`Suspend Off-Hour Session for ${alertUser(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Suspend Off-Hour User Session
                  </button>
                  <button type="button" onClick={() => handleAction(`Isolate Host ${alertHost(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Host Endpoint
                  </button>
                  <button type="button" onClick={() => handleAction('Apply Off-Hours Time-Lock Lockout Policy')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ⚡ Apply Time-Lock Lockout Policy
                  </button>
                  <button type="button" onClick={() => handleAction('Confirm Authorized Overtime Maintenance')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Mark Authorized Maintenance
                  </button>
                </div>
              </div>
            </div>
          )}

          {['loginmatrix', 'process', 'file', 'network', 'security', 'mitre', 'agent', 'timeline'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry Inspection</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8 }}>
                {(tabFields[activeTab] || []).map(([label, value]) => (
                  <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 10, minWidth: 0 }}>
                    <div style={{ color: MON.muted, fontSize: 9, textTransform: 'uppercase', fontWeight: 800 }}>{label}</div>
                    <div style={{ color: MON.text, fontSize: 11, marginTop: 4, wordBreak: 'break-word' }}>{String(value)}</div>
                  </div>
                ))}
              </div>
              <details style={{ marginTop: 12 }}>
                <summary style={{ color: MON.cyan, cursor: 'pointer', fontSize: 10, fontWeight: 800 }}>Raw agent evidence</summary>
                <pre style={{ marginTop: 8, background: MON.bg, color: MON.muted, padding: 10, borderRadius: 6, overflow: 'auto', fontSize: 9, whiteSpace: 'pre-wrap' }}>{JSON.stringify(rawRoot, null, 2)}</pre>
              </details>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard, Inspector)
// ═════════════════════════════════════════════════════════════════════════════
export function TimeAnomalyLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${anomalyType(a)} ${alertUser(a)} ${alertHost(a)} ${anomalyTimeWindow(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Anomaly Monitor, User Account, Target Host, Time Window..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Time-Based Anomaly Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 100px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Time Anomaly Category</span><span>Target Host</span><span>User</span><span>Time Window & Shift</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 100px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{anomalyType(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.yellow }}>{alertUser(row)}</span>
                <div>
                  <div style={{ color: MON.sub, fontSize: 9 }}>{anomalyTimeWindow(row)}</div>
                  <b style={{ color: MON.red, fontSize: 9 }}>{anomalyBaselineDiff(row)}</b>
                </div>
                <b style={{ color: anomalyRiskScore(row) > 75 ? MON.red : MON.orange }}>{anomalyRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No time-based anomaly logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <TimeAnomalyDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

function LegacyTimeAnomalyReportsTab({ alerts = [] }) {
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
      const windowMap = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
      const response = await api.get('/time-anomaly/events', {
        params: { page: 1, limit: 2000, windowHours: windowMap[reportType] || 2160 },
        skipCache: true,
      });
      const remoteRows = Array.isArray(response.data?.events) ? response.data.events : [];
      const filtered = remoteRows.length || Number(response.data?.total || 0) ? remoteRows : getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: Number(response.data?.total ?? filtered.length),
        bySev,
        weekend: filtered.filter(row => row.weekend === true || /weekend/i.test(`${anomalyType(row)} ${anomalyTimeWindow(row)}`)).length,
      });
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => { const severity = alertSeverity(a); if (bySev[severity] !== undefined) bySev[severity] += 1; });
      setReportData({
        alerts: filtered,
        total: filtered.length,
        bySev,
        weekend: filtered.filter(row => row.weekend === true || /weekend/i.test(`${anomalyType(row)} ${anomalyTimeWindow(row)}`)).length,
      });
    } finally {
      setGenerating(false);
      setGenerated(true);
    }
  };

  const handleExportCSV = async () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    try {
      const windowMap = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
      const response = await api.get('/time-anomaly/export/csv', {
        params: { windowHours: windowMap[reportType] || 2160 },
        responseType: 'blob',
        skipCache: true,
      });
      downloadBlob(response.data, `time_anomaly_detection_${reportType}.csv`, 'text/csv;charset=utf-8;');
    } catch {
      const header = 'Timestamp,Anomaly Category,User,Target Host,Time Window,Baseline Shift,Risk Score,Severity';
      const rows = filtered.map(a => [
        csvCell(alertTime(a)), csvCell(anomalyType(a)), csvCell(alertUser(a)), csvCell(alertHost(a)),
        csvCell(anomalyTimeWindow(a)), csvCell(anomalyBaselineDiff(a)), csvCell(anomalyRiskScore(a)), csvCell(alertSeverity(a)),
      ].join(','));
      downloadBlob([header, ...rows].join('\n'), `time_anomaly_detection_${reportType}_${filtered.length}records.csv`);
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Time-Based Anomaly Security Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for after-hours logins, night file mass modifications, off-hour admin escalation, and weekend activity</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Anomaly Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Time-Based Anomaly Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Time Anomalies: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Time Anomalies', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Off-Hour Spikes', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Night Access', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Weekend Logins', val: reportData?.weekend, color: MON.green },
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

export function TimeAnomalyReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={22} alerts={alerts} />;
}

const NEW_TIME_POLICY = {
  name: '', description: '', enabled: true, priority: 100, systemIds: [],
  workingHoursStart: 8, workingHoursEnd: 20, weekendDays: [5, 6], holidays: [],
  timezone: 'endpoint-local', authFailureWindowSeconds: 300, authFailureThreshold: 5,
  anomalyRiskThreshold: 45, alertCooldownSeconds: 3600, baselineMinimumSamples: 20,
  exceptions: [], requireApprovalForResponse: true,
};

function timePolicyDraft(policy = {}) {
  return {
    ...NEW_TIME_POLICY,
    ...policy,
    systemIds: (policy.systemIds || []).map(value => String(value?._id || value)),
    weekendDays: Array.isArray(policy.weekendDays) ? policy.weekendDays.map(Number) : [5, 6],
    holidays: Array.isArray(policy.holidays) ? policy.holidays : [],
    exceptions: Array.isArray(policy.exceptions) ? policy.exceptions.map(item => ({
      type: item.type || 'user', value: item.value || '', reason: item.reason || '',
      expiresAt: item.expiresAt ? String(item.expiresAt).slice(0, 10) : '',
    })) : [],
  };
}

export function TimeAnomalyConfigureTab({ systems = [], onRefresh, embedded = false }) {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [policies, setPolicies] = useState([]);
  const [draft, setDraft] = useState(timePolicyDraft());
  const [editingId, setEditingId] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [togglingId, setTogglingId] = useState(null);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  const loadPolicies = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const response = await api.get('/time-anomaly/policies', { skipCache: quiet });
      const rows = Array.isArray(response.data?.policies) ? response.data.policies : [];
      setPolicies(rows);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Time anomaly policies could not be loaded');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => { loadPolicies(false); }, [loadPolicies]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refresh = () => {
      loadPolicies(true);
      if (typeof onRefresh === 'function') onRefresh();
    };
    socket.on('connect', join);
    socket.on('time:policy-updated', refresh);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('time:policy-updated', refresh);
      disconnect();
    };
  }, [companyId, loadPolicies, onRefresh]);

  const update = (key, value) => setDraft(current => ({ ...current, [key]: value }));
  const toggleSystem = id => update('systemIds', draft.systemIds.includes(id)
    ? draft.systemIds.filter(value => value !== id)
    : [...draft.systemIds, id]);
  const toggleWeekend = day => update('weekendDays', draft.weekendDays.includes(day)
    ? draft.weekendDays.filter(value => value !== day)
    : [...draft.weekendDays, day].sort());
  const editPolicy = policy => {
    const nextEditingId = policy._id || null;
    setEditingId(nextEditingId);
    setDraft(timePolicyDraft(policy));
    setMessage('');
    setError('');
  };

  const resetForm = () => {
    setEditingId(null);
    setDraft(timePolicyDraft());
    setMessage('');
    setError('');
  };

  const savePolicy = async event => {
    event.preventDefault();
    setSaving(true);
    setError('');
    setMessage('');
    const payload = {
      ...draft,
      name: String(draft.name || '').trim(),
      description: String(draft.description || '').trim(),
      holidays: draft.holidays.map(value => String(value).trim()).filter(Boolean),
      exceptions: draft.exceptions
        .filter(item => String(item.value || '').trim())
        .map(item => ({
          type: item.type,
          value: String(item.value).trim(),
          reason: String(item.reason || '').trim(),
          expiresAt: item.expiresAt ? new Date(`${item.expiresAt}T23:59:59.999Z`).toISOString() : null,
        })),
    };
    delete payload._id;
    delete payload.id;
    delete payload.builtIn;
    delete payload.createdAt;
    delete payload.updatedAt;
    try {
      if (editingId) await api.put(`/time-anomaly/policies/${editingId}`, payload);
      else await api.post('/time-anomaly/policies', payload);
      setMessage(editingId ? 'Rule updated and queued for selected AJNAT agents.' : 'Rule created and queued for selected AJNAT agents.');
      setEditingId(null);
      setDraft(timePolicyDraft());
      await loadPolicies(true);
      if (typeof onRefresh === 'function') onRefresh();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Rule could not be saved');
    } finally {
      setSaving(false);
    }
  };

  const deletePolicy = async policy => {
    if (!policy?._id || !window.confirm(`Delete time anomaly rule “${policy.name}”?`)) return;
    try {
      await api.delete(`/time-anomaly/policies/${policy._id}`);
      if (editingId === policy._id) resetForm();
      setMessage('Rule deleted.');
      await loadPolicies(true);
      if (typeof onRefresh === 'function') onRefresh();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Rule could not be deleted');
    }
  };

  const togglePolicyEnabled = async policy => {
    if (!policy?._id || togglingId) return;
    const enabled = policy.enabled === false;
    setTogglingId(policy._id);
    setMessage('');
    setError('');
    try {
      await api.put(`/time-anomaly/policies/${policy._id}`, { enabled });
      setMessage(`Rule ${enabled ? 'enabled' : 'disabled'} and queued for selected AJNAT agents.`);
      await loadPolicies(true);
      if (typeof onRefresh === 'function') onRefresh();
    } catch (requestError) {
      setError(requestError.response?.data?.message || `Rule could not be ${enabled ? 'enabled' : 'disabled'}`);
    } finally {
      setTogglingId(null);
    }
  };

  const inputStyle = { width: '100%', boxSizing: 'border-box', background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '8px 10px', fontSize: 11 };
  const labelStyle = { display: 'flex', flexDirection: 'column', gap: 5, color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase' };
  const weekNames = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];

  return (
    <div style={embedded ? { display: 'contents' } : { display: 'grid', gridTemplateColumns: 'minmax(260px, .8fr) minmax(560px, 1.7fr)', gap: 14, alignItems: 'start' }}>
      <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden', ...(embedded ? { gridColumn: '1 / -1', order: 2 } : {}) }}>
        <div style={{ padding: 14, borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div><b style={{ color: '#fff', fontSize: 13 }}>🛡️ Time Detection Rules</b><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>{policies.length} configured rule(s)</div></div>
          <button type="button" onClick={resetForm} style={{ background: MON.cyan, color: '#001018', border: 0, borderRadius: 5, padding: '7px 10px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>＋ Add Rule</button>
        </div>
        {loading ? <div style={{ padding: 18, color: MON.muted, fontSize: 11 }}>Loading live configuration…</div> : policies.map(policy => (
          <div key={policy._id || policy.id || policy.name} style={{ padding: 12, borderTop: `1px solid ${MON.line}`, background: editingId && editingId === policy._id ? MON.card2 : 'transparent' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
              <div style={{ minWidth: 0 }}>
                <div style={{ color: MON.text, fontSize: 11, fontWeight: 900 }}>{policy.name}</div>
                <div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>{policy.systemIds?.length ? `${policy.systemIds.length} selected agent(s)` : 'All company agents'} · {String(policy.workingHoursStart).padStart(2, '0')}:00–{String(policy.workingHoursEnd).padStart(2, '0')}:00</div>
              </div>
              <span style={{ color: policy.enabled === false ? MON.sub : MON.green, fontSize: 9, fontWeight: 900 }}>{policy.enabled === false ? 'DISABLED' : 'ENABLED'}</span>
            </div>
            <div style={{ display: 'flex', gap: 7, marginTop: 9 }}>
              <button type="button" disabled={togglingId === policy._id} onClick={() => togglePolicyEnabled(policy)} style={{ background: policy.enabled === false ? `${MON.green}18` : `${MON.yellow}18`, border: `1px solid ${policy.enabled === false ? MON.green : MON.yellow}88`, color: policy.enabled === false ? MON.green : MON.yellow, borderRadius: 4, padding: '4px 8px', fontSize: 9, fontWeight: 800, cursor: togglingId === policy._id ? 'wait' : 'pointer' }}>{togglingId === policy._id ? 'Updating…' : policy.enabled === false ? 'Enable' : 'Disable'}</button>
              <button type="button" onClick={() => editPolicy(policy)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 4, padding: '4px 8px', fontSize: 9, cursor: 'pointer' }}>Edit</button>
              <button type="button" onClick={() => deletePolicy(policy)} style={{ background: 'transparent', border: `1px solid ${MON.red}66`, color: MON.red, borderRadius: 4, padding: '4px 8px', fontSize: 9, cursor: 'pointer' }}>Delete</button>
            </div>
          </div>
        ))}
        {!loading && !policies.length && <div style={{ padding: 18, color: MON.muted, fontSize: 10 }}>No Time Detection Rules created yet.</div>}
      </section>

      <form onSubmit={savePolicy} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 14, ...(embedded ? { order: 1 } : {}) }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div><h3 style={{ margin: 0, color: MON.cyan, fontSize: 14 }}>{editingId ? 'Edit Time Anomaly Rule' : 'Configure Time Anomaly Rule'}</h3><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>Saved values are delivered securely on the selected agent’s next heartbeat.</div></div>
          <label style={{ display: 'flex', alignItems: 'center', gap: 7, color: draft.enabled ? MON.green : MON.sub, fontSize: 10, fontWeight: 900 }}><input type="checkbox" checked={draft.enabled} onChange={event => update('enabled', event.target.checked)} /> {draft.enabled ? 'ENABLED' : 'DISABLED'}</label>
        </div>

        {(message || error) && <div style={{ background: error ? `${MON.red}18` : `${MON.green}18`, border: `1px solid ${error ? MON.red : MON.green}55`, color: error ? MON.red : MON.green, padding: 9, borderRadius: 6, fontSize: 10 }}>{error || message}</div>}

        <div style={{ display: 'grid', gridTemplateColumns: '1.5fr .5fr', gap: 10 }}>
          <label style={labelStyle}>Rule Name<input required maxLength={160} value={draft.name} onChange={event => update('name', event.target.value)} style={inputStyle} placeholder="After-Hours Admin Activity" /></label>
          <label style={labelStyle}>Priority<input required type="number" min="1" max="10000" value={draft.priority} onChange={event => update('priority', Number(event.target.value))} style={inputStyle} /></label>
        </div>
        <label style={labelStyle}>Description<textarea maxLength={1000} rows={2} value={draft.description} onChange={event => update('description', event.target.value)} style={{ ...inputStyle, resize: 'vertical' }} placeholder="Explain what this time policy protects" /></label>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
          <label style={labelStyle}>Business Hours Start<input type="number" min="0" max="23" value={draft.workingHoursStart} onChange={event => update('workingHoursStart', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Business Hours End<input type="number" min="0" max="23" value={draft.workingHoursEnd} onChange={event => update('workingHoursEnd', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Timezone<input required maxLength={64} value={draft.timezone} onChange={event => update('timezone', event.target.value)} style={inputStyle} placeholder="endpoint-local or Asia/Kolkata" /></label>
        </div>

        <div>
          <div style={{ color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase', marginBottom: 6 }}>Weekend Days</div>
          <div style={{ display: 'flex', gap: 6 }}>{weekNames.map((name, day) => <button key={name} type="button" onClick={() => toggleWeekend(day)} style={{ flex: 1, padding: 7, borderRadius: 5, cursor: 'pointer', fontSize: 9, fontWeight: 800, border: `1px solid ${draft.weekendDays.includes(day) ? MON.cyan : MON.border}`, background: draft.weekendDays.includes(day) ? `${MON.cyan}22` : MON.bg, color: draft.weekendDays.includes(day) ? MON.cyan : MON.muted }}>{name}</button>)}</div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 9 }}>
          <label style={labelStyle}>Risk Threshold<input type="number" min="0" max="100" value={draft.anomalyRiskThreshold} onChange={event => update('anomalyRiskThreshold', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Auth Failures<input type="number" min="3" max="10000" value={draft.authFailureThreshold} onChange={event => update('authFailureThreshold', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Auth Window (sec)<input type="number" min="30" max="86400" value={draft.authFailureWindowSeconds} onChange={event => update('authFailureWindowSeconds', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Cooldown (sec)<input type="number" min="300" max="604800" value={draft.alertCooldownSeconds} onChange={event => update('alertCooldownSeconds', Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Baseline Samples<input type="number" min="1" max="10000" value={draft.baselineMinimumSamples} onChange={event => update('baselineMinimumSamples', Number(event.target.value))} style={inputStyle} /></label>
        </div>

        <label style={labelStyle}>Holidays (YYYY-MM-DD, one per line)<textarea rows={2} value={draft.holidays.join('\n')} onChange={event => update('holidays', event.target.value.split(/\r?\n/))} style={{ ...inputStyle, resize: 'vertical', fontFamily: 'monospace' }} placeholder="2026-10-02" /></label>

        <div style={{ background: MON.bg, border: `1px solid ${MON.line}`, borderRadius: 7, padding: 11 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}><b style={{ color: MON.text, fontSize: 10 }}>Apply Rule To AJNAT Agent</b><span style={{ color: MON.muted, fontSize: 9 }}>{draft.systemIds.length ? `${draft.systemIds.length} selected` : 'All agents'}</span></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 7, maxHeight: 180, overflowY: 'auto' }}>
            {systems.map(system => {
              const id = String(system._id || system.id);
              const online = system.isOnline === true;
              return <label key={id} style={{ display: 'flex', alignItems: 'center', gap: 8, background: MON.card2, border: `1px solid ${draft.systemIds.includes(id) ? MON.cyan : MON.border}`, borderRadius: 5, padding: 8, cursor: 'pointer' }}><input type="checkbox" checked={draft.systemIds.includes(id)} onChange={() => toggleSystem(id)} /><span style={{ flex: 1, minWidth: 0 }}><b style={{ display: 'block', color: MON.text, fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis' }}>{system.name || system.hostname || id}</b><span style={{ color: online ? MON.green : MON.sub, fontSize: 8 }}>● {online ? 'ONLINE' : 'OFFLINE'}{system.lastSeen ? ` · ${new Date(system.lastSeen).toLocaleString()}` : ''}</span></span></label>;
            })}
            {!systems.length && <div style={{ color: MON.muted, fontSize: 9 }}>No tenant agents returned by the backend.</div>}
          </div>
          <div style={{ color: MON.sub, fontSize: 8, marginTop: 7 }}>No selection means all company agents. Offline agents receive this rule when they reconnect.</div>
        </div>

        <label style={{ display: 'flex', gap: 8, alignItems: 'center', color: MON.text, fontSize: 10 }}><input type="checkbox" checked={draft.requireApprovalForResponse} onChange={event => update('requireApprovalForResponse', event.target.checked)} /> Require analyst approval before disruptive response actions</label>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}><button type="button" onClick={resetForm} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, borderRadius: 5, padding: '8px 14px', cursor: 'pointer' }}>Reset</button><button type="submit" disabled={saving} style={{ background: MON.cyan, border: 0, color: '#001018', borderRadius: 5, padding: '8px 16px', fontWeight: 900, cursor: saving ? 'wait' : 'pointer' }}>{saving ? 'Saving…' : editingId ? 'Save & Deploy Changes' : 'Create & Deploy Rule'}</button></div>
      </form>
    </div>
  );
}

function localDateTimeInput(date = new Date()) {
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

export function TimeAnomalyExceptionsTab({ systems = [], onRefresh, embedded = false }) {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [exceptions, setExceptions] = useState([]);
  const [name, setName] = useState('');
  const [reason, setReason] = useState('');
  const [systemIds, setSystemIds] = useState([]);
  const [startsAt, setStartsAt] = useState(localDateTimeInput());
  const [duration, setDuration] = useState(60);
  const [durationUnit, setDurationUnit] = useState('minutes');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [clock, setClock] = useState(Date.now());

  const loadExceptions = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const response = await api.get('/time-anomaly/exceptions', { skipCache: quiet });
      setExceptions(Array.isArray(response.data?.exceptions) ? response.data.exceptions : []);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Approved exceptions could not be loaded');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => { loadExceptions(false); }, [loadExceptions]);

  useEffect(() => {
    const timer = setInterval(() => setClock(Date.now()), 30000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refresh = () => {
      loadExceptions(true);
      if (typeof onRefresh === 'function') onRefresh();
    };
    socket.on('connect', join);
    socket.on('time:exception-updated', refresh);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('time:exception-updated', refresh);
      disconnect();
    };
  }, [companyId, loadExceptions, onRefresh]);

  const toggleSystem = id => setSystemIds(current => current.includes(id)
    ? current.filter(value => value !== id)
    : [...current, id]);

  const reset = () => {
    setName('');
    setReason('');
    setSystemIds([]);
    setStartsAt(localDateTimeInput());
    setDuration(60);
    setDurationUnit('minutes');
  };

  const createException = async event => {
    event.preventDefault();
    setSaving(true);
    setMessage('');
    setError('');
    try {
      const start = new Date(startsAt);
      const multiplier = durationUnit === 'days' ? 86400000 : durationUnit === 'hours' ? 3600000 : 60000;
      const expiry = new Date(start.getTime() + Number(duration) * multiplier);
      if (Number.isNaN(start.getTime()) || Number.isNaN(expiry.getTime())) throw new Error('Choose a valid start time and duration');
      await api.post('/time-anomaly/exceptions', {
        name: name.trim(), reason: reason.trim(), systemIds,
        startsAt: start.toISOString(), expiresAt: expiry.toISOString(), enabled: true,
      });
      setMessage('Temporary bypass deployed. Selected AJNAT agents will resume all time-anomaly rules automatically at expiry.');
      reset();
      await loadExceptions(true);
      if (typeof onRefresh === 'function') onRefresh();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Approved exception could not be created');
    } finally {
      setSaving(false);
    }
  };

  const removeException = async exception => {
    if (!exception?._id || !window.confirm(`End approved exception “${exception.name}”?`)) return;
    try {
      await api.delete(`/time-anomaly/exceptions/${exception._id}`);
      setMessage('Exception ended. Time-anomaly rules will resume on the selected agents at their next heartbeat.');
      await loadExceptions(true);
      if (typeof onRefresh === 'function') onRefresh();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Approved exception could not be ended');
    }
  };

  const inputStyle = { width: '100%', boxSizing: 'border-box', background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '8px 10px', fontSize: 11 };
  const labelStyle = { display: 'flex', flexDirection: 'column', gap: 5, color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase' };
  const now = clock;

  return (
    <div style={{ display: 'grid', gridTemplateColumns: embedded ? '1fr' : 'minmax(340px, .9fr) minmax(520px, 1.4fr)', gap: 14, alignItems: 'start', ...(embedded ? { order: 1 } : {}) }}>
      <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: 14, borderBottom: `1px solid ${MON.line}` }}>
          <b style={{ color: '#fff', fontSize: 13 }}>✅ Approved Exceptions</b>
          <div style={{ color: MON.muted, fontSize: 9, marginTop: 4 }}>Temporary full bypass of Time-Based Anomaly rules for explicitly selected AJNAT agents.</div>
        </div>
        {loading ? <div style={{ padding: 18, color: MON.muted, fontSize: 11 }}>Loading live exceptions…</div> : exceptions.map(exception => {
          const start = new Date(exception.startsAt).getTime();
          const expiry = new Date(exception.expiresAt).getTime();
          const active = exception.enabled !== false && start <= now && expiry > now;
          const scheduled = exception.enabled !== false && start > now;
          return (
            <div key={exception._id} style={{ padding: 12, borderTop: `1px solid ${MON.line}` }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <div><b style={{ color: MON.text, fontSize: 11 }}>{exception.name}</b><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>{exception.reason}</div></div>
                <span style={{ color: active ? MON.green : scheduled ? MON.cyan : MON.sub, fontSize: 9, fontWeight: 900 }}>{active ? 'ACTIVE' : scheduled ? 'SCHEDULED' : 'EXPIRED'}</span>
              </div>
              <div style={{ color: MON.sub, fontSize: 9, marginTop: 7 }}>{(exception.systemIds || []).map(item => item.name || item.hostname || item._id).join(', ') || 'No agent'} · until {new Date(exception.expiresAt).toLocaleString()}</div>
              {expiry > now && <button type="button" onClick={() => removeException(exception)} style={{ marginTop: 8, background: 'transparent', border: `1px solid ${MON.red}66`, color: MON.red, borderRadius: 4, padding: '5px 9px', fontSize: 9, cursor: 'pointer' }}>End Exception</button>}
            </div>
          );
        })}
        {!loading && !exceptions.length && <div style={{ padding: 18, color: MON.muted, fontSize: 10 }}>No approved exceptions configured.</div>}
      </section>

      <form onSubmit={createException} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div><h3 style={{ margin: 0, color: MON.green, fontSize: 14 }}>Create Temporary Agent Bypass</h3><div style={{ color: MON.muted, fontSize: 9, marginTop: 4 }}>All Time-Based Anomaly rules are skipped only on selected agents and only for the approved duration.</div></div>
        {(message || error) && <div style={{ background: error ? `${MON.red}18` : `${MON.green}18`, border: `1px solid ${error ? MON.red : MON.green}55`, color: error ? MON.red : MON.green, padding: 9, borderRadius: 6, fontSize: 10 }}>{error || message}</div>}
        <label style={labelStyle}>Exception Name<input required maxLength={160} value={name} onChange={event => setName(event.target.value)} style={inputStyle} placeholder="Approved maintenance window" /></label>
        <label style={labelStyle}>Approval Reason<textarea required maxLength={500} rows={2} value={reason} onChange={event => setReason(event.target.value)} style={{ ...inputStyle, resize: 'vertical' }} placeholder="Ticket/change reference and business reason" /></label>
        <div style={{ display: 'grid', gridTemplateColumns: '1.3fr .6fr .8fr', gap: 9 }}>
          <label style={labelStyle}>Starts At<input required type="datetime-local" value={startsAt} onChange={event => setStartsAt(event.target.value)} style={inputStyle} /></label>
          <label style={labelStyle}>Duration<input required type="number" min="1" max="527040" value={duration} onChange={event => setDuration(Number(event.target.value))} style={inputStyle} /></label>
          <label style={labelStyle}>Unit<select value={durationUnit} onChange={event => setDurationUnit(event.target.value)} style={inputStyle}><option value="minutes">Minutes</option><option value="hours">Hours</option><option value="days">Days</option></select></label>
        </div>
        <div style={{ background: MON.bg, border: `1px solid ${MON.line}`, borderRadius: 7, padding: 11 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}><b style={{ color: MON.text, fontSize: 10 }}>Select AJNAT Agents</b><span style={{ color: systemIds.length ? MON.green : MON.red, fontSize: 9 }}>{systemIds.length} selected</span></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 7, maxHeight: 220, overflowY: 'auto' }}>
            {systems.map(system => {
              const id = String(system._id || system.id);
              const online = system.isOnline === true;
              return <label key={id} style={{ display: 'flex', alignItems: 'center', gap: 8, background: MON.card2, border: `1px solid ${systemIds.includes(id) ? MON.green : MON.border}`, borderRadius: 5, padding: 8, cursor: 'pointer' }}><input type="checkbox" checked={systemIds.includes(id)} onChange={() => toggleSystem(id)} /><span style={{ flex: 1, minWidth: 0 }}><b style={{ display: 'block', color: MON.text, fontSize: 10 }}>{system.name || system.hostname || id}</b><span style={{ color: online ? MON.green : MON.sub, fontSize: 8 }}>● {online ? 'ONLINE' : 'OFFLINE'}{system.lastSeen ? ` · ${new Date(system.lastSeen).toLocaleString()}` : ''}</span></span></label>;
            })}
            {!systems.length && <div style={{ color: MON.muted, fontSize: 9 }}>No tenant agents returned by the backend.</div>}
          </div>
          <div style={{ color: MON.sub, fontSize: 8, marginTop: 7 }}>Offline agents receive the active bypass after reconnecting. The exception cannot apply to agents outside this company.</div>
        </div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}><button type="button" onClick={reset} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, borderRadius: 5, padding: '8px 14px', cursor: 'pointer' }}>Reset</button><button type="submit" disabled={saving || !systemIds.length} style={{ background: MON.green, border: 0, color: '#00150d', borderRadius: 5, padding: '8px 16px', fontWeight: 900, cursor: saving ? 'wait' : 'pointer', opacity: !systemIds.length ? .55 : 1 }}>{saving ? 'Approving…' : 'Approve Temporary Bypass'}</button></div>
      </form>
    </div>
  );
}

// ── Visual Helper Components for Time-Based Anomaly Detection Dashboard ─
function LoginTimeHeatmap({ rows = [], heatmap }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hours = ['00', '02', '04', '06', '08', '10', '12', '14', '16', '18', '20', '22'];
  const counts = Array.isArray(heatmap) && heatmap.length === 7
    ? heatmap
    : rows.reduce((matrix, row) => {
      const timestamp = alertTime(row);
      const date = timestamp ? new Date(timestamp) : null;
      if (!date || Number.isNaN(date.getTime())) return matrix;
      const day = Number.isFinite(Number(row.weekday)) ? Number(row.weekday) : (date.getDay() + 6) % 7;
      const hour = Number.isFinite(Number(row.localHour)) ? Number(row.localHour) : date.getHours();
      matrix[Math.max(0, Math.min(6, day))][Math.max(0, Math.min(11, Math.floor(hour / 2)))] += 1;
      return matrix;
    }, Array.from({ length: 7 }, () => Array(12).fill(0)));
  const maxCell = Math.max(1, ...counts.flat().map(Number));
  const matrix = counts.map(day => day.map(value => Number(value || 0) / maxCell));

  const getColor = (v) => {
    if (v > 0.8) return '#ef4444';
    if (v > 0.6) return '#f97316';
    if (v > 0.4) return '#eab308';
    if (v > 0.2) return '#1e3a8a';
    return '#091e3a';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Login Time Heatmap <span style={{ fontSize: 8, color: '#64748b' }}>(User Logins)</span></span>
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 7, color: '#64748b', fontWeight: 700, paddingTop: 1 }}>
            {days.map(d => (
              <span key={d} style={{ height: 11, lineHeight: '11px' }}>{d}</span>
            ))}
          </div>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {matrix.map((row, rIdx) => (
              <div key={rIdx} style={{ display: 'flex', gap: 2 }}>
                {row.map((val, cIdx) => (
                  <div key={cIdx} style={{ flex: 1, height: 11, background: getColor(val), borderRadius: 1.5 }} />
                ))}
              </div>
            ))}
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
              {hours.map(h => (
                <span key={h}>{h}</span>
              ))}
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'space-between', fontSize: 6.5, color: '#64748b', width: 24 }}>
            <span>High</span>
            <div style={{ width: 6, flex: 1, margin: '2px 0', background: 'linear-gradient(180deg, #ef4444 0%, #f97316 35%, #eab308 65%, #091e3a 100%)', borderRadius: 2 }} />
            <span>Low</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ActivityTimelineChart({ rows = [] }) {
  const bucketFor = matcher => {
    const buckets = Array(12).fill(0);
    rows.forEach(row => {
      if (!matcher(`${anomalyType(row)} ${row.eventCategory || ''} ${row.category || ''} ${row.sourceEvent || ''}`.toLowerCase())) return;
      const timestamp = alertTime(row);
      const date = timestamp ? new Date(timestamp) : null;
      if (!date || Number.isNaN(date.getTime())) return;
      const hour = Number.isFinite(Number(row.localHour)) ? Number(row.localHour) : date.getHours();
      buckets[Math.max(0, Math.min(11, Math.floor(hour / 2)))] += 1;
    });
    return buckets;
  };
  const pointsLogins = bucketFor(text => /login|auth|rdp|ssh|vpn/.test(text));
  const pointsFile = bucketFor(text => /file|encrypt|delete|rename/.test(text));
  const pointsProcess = bucketFor(text => /process|script|powershell|command|lolbin/.test(text));
  const pointsNetwork = bucketFor(text => /network|dns|upload|download|transfer/.test(text));
  const pointsAlerts = bucketFor(() => true);

  const maxVal = Math.max(1, ...pointsLogins, ...pointsFile, ...pointsProcess, ...pointsNetwork, ...pointsAlerts);
  const width = 360;
  const height = 95;

  const getSvgPath = (pts) => {
    return pts.map((val, idx) => {
      const x = (idx / (pts.length - 1)) * width;
      const y = height - (val / maxVal) * (height - 10) - 5;
      return `${x},${y}`;
    }).join(' L ');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Activity Timeline <span style={{ fontSize: 8, color: '#64748b' }}>(All Events)</span></span>
          <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>All Events v</span>
        </div>

        <div style={{ display: 'flex', gap: 8, fontSize: 7, marginBottom: 4 }}>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#38bdf8', borderRadius: 1 }} /> Logins</span>
          <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#22c55e', borderRadius: 1 }} /> File Access</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#a78bfa', borderRadius: 1 }} /> Process Execution</span>
          <span style={{ color: '#f97316', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#f97316', borderRadius: 1 }} /> Network Activity</span>
          <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#ef4444', borderRadius: 1 }} /> Alerts</span>
        </div>

        <div style={{ position: 'relative', width: '100%', height: 85 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" style={{ overflow: 'visible' }}>
            <path d={`M ${getSvgPath(pointsLogins)}`} fill="none" stroke="#38bdf8" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsFile)}`} fill="none" stroke="#22c55e" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsProcess)}`} fill="none" stroke="#a78bfa" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsNetwork)}`} fill="none" stroke="#f97316" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsAlerts)}`} fill="none" stroke="#ef4444" strokeWidth="1.5" />
          </svg>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
          {['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'].map(t => (
            <span key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function AnomaliesByTimeRangeDonut({ rows = [], policy = {} }) {
  const start = Number(policy.workingHoursStart ?? 8);
  const end = Number(policy.workingHoursEnd ?? 20);
  const counts = rows.reduce((acc, row) => {
    if (row.holiday) acc.holiday += 1;
    else if (row.weekend) acc.weekend += 1;
    else if (row.afterHours) acc.after += 1;
    else acc.business += 1;
    return acc;
  }, { after: 0, business: 0, weekend: 0, holiday: 0 });
  const denominator = Math.max(1, rows.length);
  const items = [
    { label: `After-Hours (${String(end).padStart(2, '0')}:00 - ${String(start).padStart(2, '0')}:00)`, val: counts.after, pct: (counts.after / denominator) * 100, color: '#ef4444' },
    { label: `Business Hours (${String(start).padStart(2, '0')}:00 - ${String(end).padStart(2, '0')}:00)`, val: counts.business, pct: (counts.business / denominator) * 100, color: '#22c55e' },
    { label: 'Weekend', val: counts.weekend, pct: (counts.weekend / denominator) * 100, color: '#22d3ee' },
    { label: 'Holidays', val: counts.holiday, pct: (counts.holiday / denominator) * 100, color: '#38bdf8' },
  ];

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
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Anomalies by Time Range</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(rows.length)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 7.5 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 3 }}>
                  <span style={{ width: 4, height: 4, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.pct.toFixed(1)}% <span style={{ fontSize: 6.5, color: '#64748b' }}>({it.val})</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function AnomalyTrendStackedBarChart({ rows = [] }) {
  const today = new Date();
  const days = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(today);
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - (6 - index));
    return { key: date.toISOString().slice(0, 10), date: date.toLocaleDateString([], { day: '2-digit', month: 'short' }), crit: 0, high: 0, med: 0, low: 0 };
  });
  const byDay = new Map(days.map(day => [day.key, day]));
  rows.forEach(row => {
    const timestamp = alertTime(row);
    const date = timestamp ? new Date(timestamp) : null;
    if (!date || Number.isNaN(date.getTime())) return;
    const bucket = byDay.get(date.toISOString().slice(0, 10));
    if (!bucket) return;
    const key = alertSeverity(row) === 'critical' ? 'crit' : alertSeverity(row) === 'high' ? 'high' : alertSeverity(row) === 'medium' ? 'med' : 'low';
    bucket[key] += 1;
  });
  const maxTotal = Math.max(1, ...days.map(day => day.crit + day.high + day.med + day.low));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Anomaly Trend Over Time</span>
          <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>Daily v</span>
        </div>

        <div style={{ height: 85, display: 'flex', alignItems: 'flex-end', gap: 8, paddingBottom: 4, borderBottom: '1px solid #16273e' }}>
          {days.map(d => {
            const tot = d.crit + d.high + d.med + d.low;
            return (
              <div key={d.date} style={{ flex: 1, display: 'flex', flexDirection: 'column', height: `${Math.max(2, (tot / maxTotal) * 100)}%`, borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ height: `${(d.crit / tot) * 100}%`, background: '#ef4444' }} />
                <div style={{ height: `${(d.high / tot) * 100}%`, background: '#f97316' }} />
                <div style={{ height: `${(d.med / tot) * 100}%`, background: '#eab308' }} />
                <div style={{ height: `${(d.low / tot) * 100}%`, background: '#38bdf8' }} />
              </div>
            );
          })}
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
          {days.map(d => (
            <span key={d.date}>{d.date}</span>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'center', gap: 10, fontSize: 7, marginTop: 4 }}>
        <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#ef4444', borderRadius: 1 }} /> Critical</span>
        <span style={{ color: '#f97316', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#f97316', borderRadius: 1 }} /> High</span>
        <span style={{ color: '#eab308', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#eab308', borderRadius: 1 }} /> Medium</span>
        <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#38bdf8', borderRadius: 1 }} /> Low</span>
      </div>
    </div>
  );
}

function TimeAnomalyOverviewDashboard({ alerts = [], total = 0, summary = {}, policy = {} }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const severityCount = level => rows.filter(row => alertSeverity(row) === level).length;
  const afterHoursRows = rows.filter(row => row.afterHours === true || /after.hours|off.hours|late night|odd hours|night/i.test(`${anomalyType(row)} ${anomalyTimeWindow(row)}`));
  const weekendRows = rows.filter(row => row.weekend === true || /weekend/i.test(`${anomalyType(row)} ${anomalyTimeWindow(row)}`));
  const affectedUsers = new Set(rows.map(alertUser).filter(value => value !== 'Unknown user'));
  const affectedHosts = new Set(rows.map(alertHost).filter(value => value !== 'Unknown host'));
  const timeline = buildBuckets(rows, 6, 24);
  const afterHoursArc = Math.min(188, Math.round((afterHoursRows.length / Math.max(1, rows.length)) * 188));
  const weekendArc = Math.min(188, Math.round((weekendRows.length / Math.max(1, rows.length)) * 188));
  const topCards = [
    { title: 'Total Time Anomalies', val: shortNum(total || rows.length), sub: 'Live 24-hour telemetry', col: '#ef4444', icon: '⏰', spark: timeline },
    { title: 'Critical Alerts', val: shortNum(summary.bySeverity?.critical ?? severityCount('critical')), sub: 'Current critical events', col: '#ef4444', icon: '🛡️', spark: buildBuckets(rows.filter(row => alertSeverity(row) === 'critical'), 6, 24) },
    { title: 'Users Affected', val: shortNum(summary.affectedUsers ?? affectedUsers.size), sub: 'Unique reported users', col: '#a78bfa', icon: '👥', spark: timeline },
    { title: 'Hosts Affected', val: shortNum(summary.affectedHosts ?? affectedHosts.size), sub: 'Unique reporting hosts', col: '#38bdf8', icon: '🖥️', spark: timeline },
    { title: 'After-Hours Events', val: shortNum(summary.afterHours ?? afterHoursRows.length), sub: 'Outside configured hours', col: '#f97316', icon: '🌙', spark: buildBuckets(afterHoursRows, 6, 24) },
    { title: 'Weekend Events', val: shortNum(summary.weekend ?? weekendRows.length), sub: 'Configured weekend days', col: '#22c55e', icon: '📅', spark: buildBuckets(weekendRows, 6, 24) },
  ];

  const aggregateActors = (picker, label) => {
    const values = new Map();
    rows.forEach(row => {
      const name = picker(row);
      if (!name || /^unknown/i.test(name)) return;
      const item = values.get(name) || { [label]: name, evts: 0, crit: 0, rows: [] };
      item.evts += 1;
      if (alertSeverity(row) === 'critical') item.crit += 1;
      item.rows.push(row);
      values.set(name, item);
    });
    return [...values.values()].sort((a, b) => b.evts - a.evts).slice(0, 5)
      .map(item => ({ ...item, spark: buildBuckets(item.rows, 5, 24) }));
  };
  const topAnomalousUsers = aggregateActors(alertUser, 'user');
  const topAnomalousHosts = aggregateActors(alertHost, 'host');
  const categoryCounts = topCounts(rows, anomalyType, 5);
  const categoryMax = Math.max(1, ...categoryCounts.map(([, count]) => count));
  const categoryColors = ['#ef4444', '#f97316', '#eab308', '#38bdf8', '#a78bfa'];
  const topAnomalyCategories = categoryCounts.map(([cat, count], index) => ({ cat, count, pct: (count / categoryMax) * 100, col: categoryColors[index] }));
  const recentTimeAlerts = rows.slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleString() : 'Not reported',
    alert: anomalyType(row), user: alertUser(row), host: alertHost(row),
    sev: alertSeverity(row).replace(/^./, char => char.toUpperCase()),
    col: SEV_COLOR[alertSeverity(row)] || MON.muted,
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        {topCards.map(s => (
          <div key={s.title} style={{ ...panelStyle, padding: '10px 10px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: '#8ea0b8', fontWeight: 800 }}>{s.title}</span>
              <span style={{ fontSize: 10 }}>{s.icon}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>{s.val}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: s.col, fontWeight: 700 }}>{s.sub}</span>
              <div style={{ width: 35, height: 12 }}>
                <MiniSparkline data={s.spark} color={s.col} height={12} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.3fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <LoginTimeHeatmap rows={rows} heatmap={summary.heatmap} />
        </div>

        <div style={panelStyle}>
          <ActivityTimelineChart rows={rows} />
        </div>

        <div style={panelStyle}>
          <AnomaliesByTimeRangeDonut rows={rows} policy={policy} />
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.1fr 1fr 1fr', gap: 12 }}>
        {/* Top Anomalous Users */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Anomalous Users</span>
              <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Users</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.9fr 0.9fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>User</span>
              <span>Anomaly Evts</span>
              <span>Critical Evts</span>
              <span>Trend</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topAnomalousUsers.map(u => (
                <div key={u.user} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.9fr 0.9fr 1fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#cbd5e1' }}>{u.user}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{u.evts}</span>
                  <span style={{ color: '#ef4444', fontWeight: 700 }}>{u.crit}</span>
                  <div style={{ width: 35, height: 10 }}>
                    <MiniSparkline data={u.spark} color="#ef4444" height={10} />
                  </div>
                </div>
              ))}
              {!topAnomalousUsers.length && <span style={{ color: '#64748b', fontSize: 8 }}>No user anomaly telemetry</span>}
            </div>
          </div>
        </div>

        {/* Top Anomalous Hosts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Anomalous Hosts</span>
              <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Hosts</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.9fr 0.9fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>Host Name</span>
              <span>Anomaly Evts</span>
              <span>Critical Evts</span>
              <span>Trend</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topAnomalousHosts.map(h => (
                <div key={h.host} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.9fr 0.9fr 1fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{h.host}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{h.evts}</span>
                  <span style={{ color: '#ef4444', fontWeight: 700 }}>{h.crit}</span>
                  <div style={{ width: 35, height: 10 }}>
                    <MiniSparkline data={h.spark} color="#ef4444" height={10} />
                  </div>
                </div>
              ))}
              {!topAnomalousHosts.length && <span style={{ color: '#64748b', fontSize: 8 }}>No host anomaly telemetry</span>}
            </div>
          </div>
        </div>

        <div style={panelStyle}>
          <AnomalyTrendStackedBarChart rows={rows} />
        </div>

        {/* Top Anomaly Categories */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Anomaly Categories</span>
              <span style={{ fontSize: 7.5, color: '#64748b' }}>Events</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
              {topAnomalyCategories.map(tac => (
                <div key={tac.cat} style={{ display: 'flex', flexDirection: 'column', gap: 2, fontSize: 7.5 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#cbd5e1' }}>{tac.cat}</span>
                    <span style={{ color: '#e2e8f0', fontWeight: 800 }}>{tac.count}</span>
                  </div>
                  <div style={{ width: '100%', height: 4, background: '#07101b', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${tac.pct}%`, height: '100%', background: tac.col, borderRadius: 2 }} />
                  </div>
                </div>
              ))}
              {!topAnomalyCategories.length && <span style={{ color: '#64748b', fontSize: 8 }}>No anomaly category telemetry</span>}
            </div>
          </div>
          <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Categories</span>
        </div>
      </div>

      {/* 4. BOTTOM GRID (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 1fr', gap: 12 }}>
        {/* Recent Time-Based Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Recent Time-Based Alerts</span>
              <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.4fr 0.9fr 0.9fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>Alert</span>
              <span>User</span>
              <span>Host</span>
              <span>Severity</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {recentTimeAlerts.map((rta, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.4fr 0.9fr 0.9fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#64748b' }}>{rta.time}</span>
                  <span style={{ color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rta.alert}</span>
                  <span style={{ color: '#8ea0b8' }}>{rta.user}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{rta.host}</span>
                  <span style={{ fontSize: 7, fontWeight: 800, color: rta.col, background: `${rta.col}15`, padding: '1px 3px', borderRadius: 3, border: `1px solid ${rta.col}33`, textAlign: 'center' }}>
                    {rta.sev}
                  </span>
                </div>
              ))}
              {!recentTimeAlerts.length && <span style={{ color: '#64748b', fontSize: 8 }}>No recent time-based alerts</span>}
            </div>
          </div>
        </div>

        {/* After-Hours Activity */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6, display: 'block' }}>After-Hours Activity <span style={{ fontSize: 8, color: '#64748b' }}>({String(policy.workingHoursEnd ?? 20).padStart(2, '0')}:00 - {String(policy.workingHoursStart ?? 8).padStart(2, '0')}:00)</span></span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ position: 'relative', width: 75, height: 75, flexShrink: 0 }}>
                <svg viewBox="0 0 75 75" width="75" height="75">
                  <circle cx="37.5" cy="37.5" r="30" fill="none" stroke="#16273e" strokeWidth="8" />
                  <circle cx="37.5" cy="37.5" r="30" fill="none" stroke="#f97316" strokeWidth="8" strokeDasharray={`${afterHoursArc} 188`} strokeDashoffset="45" />
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(summary.afterHours ?? afterHoursRows.length)}</span>
                  <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Events</span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 7.5 }}>
                <span style={{ color: '#22c55e', fontWeight: 700 }}>Live <span style={{ color: '#64748b', fontWeight: 400 }}>24-hour window</span></span>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                  <span>Users</span>
                  <span style={{ fontWeight: 800, color: '#fff' }}>{new Set(afterHoursRows.map(alertUser).filter(value => value !== 'Unknown user')).size}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                  <span>Hosts</span>
                  <span style={{ fontWeight: 800, color: '#fff' }}>{new Set(afterHoursRows.map(alertHost).filter(value => value !== 'Unknown host')).size}</span>
                </div>
              </div>
            </div>
          </div>
          <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 4 }}>View Detailed Report</span>
        </div>

        {/* Weekend Activity */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6, display: 'block' }}>Weekend Activity <span style={{ fontSize: 8, color: '#64748b' }}>(Sat - Sun)</span></span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ position: 'relative', width: 75, height: 75, flexShrink: 0 }}>
                <svg viewBox="0 0 75 75" width="75" height="75">
                  <circle cx="37.5" cy="37.5" r="30" fill="none" stroke="#16273e" strokeWidth="8" />
                  <circle cx="37.5" cy="37.5" r="30" fill="none" stroke="#22c55e" strokeWidth="8" strokeDasharray={`${weekendArc} 188`} strokeDashoffset="45" />
                </svg>
                <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                  <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(summary.weekend ?? weekendRows.length)}</span>
                  <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Events</span>
                </div>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 7.5 }}>
                <span style={{ color: '#22c55e', fontWeight: 700 }}>Live <span style={{ color: '#64748b', fontWeight: 400 }}>24-hour window</span></span>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                  <span>Users</span>
                  <span style={{ fontWeight: 800, color: '#fff' }}>{new Set(weekendRows.map(alertUser).filter(value => value !== 'Unknown user')).size}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                  <span>Hosts</span>
                  <span style={{ fontWeight: 800, color: '#fff' }}>{new Set(weekendRows.map(alertHost).filter(value => value !== 'Unknown host')).size}</span>
                </div>
              </div>
            </div>
          </div>
          <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 4 }}>View Detailed Report</span>
        </div>

        {/* Activity Summary */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Activity Summary</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, fontSize: 7.5 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8ea0b8', display: 'flex', alignItems: 'center', gap: 4 }}>⏱️ Total Events Monitored</span>
                <span style={{ color: '#fff', fontWeight: 800 }}>{shortNum(total || rows.length)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8ea0b8', display: 'flex', alignItems: 'center', gap: 4 }}>🛡️ Baseline Deviations</span>
                <span style={{ color: '#fff', fontWeight: 800 }}>{shortNum(summary.baselineDeviations ?? rows.filter(row => anomalyBaselineDiff(row) !== 'Not reported').length)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8ea0b8', display: 'flex', alignItems: 'center', gap: 4 }}>👥 Anomalous Users</span>
                <span style={{ color: '#fff', fontWeight: 800 }}>{shortNum(summary.affectedUsers ?? affectedUsers.size)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8ea0b8', display: 'flex', alignItems: 'center', gap: 4 }}>🖥️ Anomalous Hosts</span>
                <span style={{ color: '#fff', fontWeight: 800 }}>{shortNum(summary.affectedHosts ?? affectedHosts.size)}</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8ea0b8', display: 'flex', alignItems: 'center', gap: 4 }}>💾 Data Scanned</span>
                <span style={{ color: '#fff', fontWeight: 800 }}>{shortNum(rows.reduce((sum, row) => sum + Number(row.bytesSent || row.rawEvent?.bytes_sent || 0) + Number(row.bytesReceived || row.rawEvent?.bytes_received || 0), 0))} bytes</span>
              </div>
            </div>
          </div>
          <span style={{ fontSize: 8.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 4 }}>View Full Summary</span>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`TimeBasedAnomalyDashboardPanel` / `TimeBasedAnomalyDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function TimeBasedAnomalyDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = {}, onAction, onRefresh }) {
  const [searchParams] = useSearchParams();
  const requestedTab = searchParams.get('tab');
  const [activeTab, setActiveTab] = useState(requestedTab === 'configure' ? 'configure' : 'dashboard');
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

  useEffect(() => {
    if (requestedTab === 'configure') setActiveTab('configure');
  }, [requestedTab]);

  const rows = Array.isArray(alerts) ? alerts : [];
  const totalRows = total || recordsTotal || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const summary = data?.summary || {};
  const policy = data?.policy || {};
  const countMatching = pattern => rows.filter(row => pattern.test(`${anomalyType(row)} ${row.description || ''} ${row.sourceEvent || ''}`)).length;
  const baselineScore = summary.averageBaselineConfidence ?? (rows.length
    ? Math.round(rows.reduce((sum, row) => sum + Number(row.baselineConfidence || row.rawEvent?.baseline_confidence || 0), 0) / rows.length)
    : 0);

  // 20 Time-Based Anomaly Specific SOC Categories & Metrics
  const kpis = [
    { label: '⏱️ 1. Total Time Anomalies (24h)', val: shortNum(totalRows), trend: 'Anomalies', color: MON.blue, data: timeline },
    { label: '🌙 2. Login Outside Business Hours', val: shortNum(countMatching(/login.*(?:after|outside|off.hours)|after.hours.*(?:login|auth)/i)), trend: 'Off-Hours Login', color: MON.red, data: timeline },
    { label: '🌃 3. Late Night User Logins', val: shortNum(countMatching(/late night|night.*login/i)), trend: 'Late Night', color: MON.purple, data: timeline },
    { label: '🗓️ 4. Weekend Login Activity', val: shortNum(summary.weekend ?? countMatching(/weekend/i)), trend: 'Weekend', color: MON.cyan, data: timeline },
    { label: '🔑 5. Administrator Login After Hours', val: shortNum(rows.filter(row => /admin|root|system/i.test(alertUser(row)) && /after.hours|outside|off.hours|night/i.test(`${anomalyType(row)} ${anomalyTimeWindow(row)}`)).length), trend: 'Off-Hour Admin', color: MON.red, data: timeline },
    { label: '⚡ 6. Multiple Logins in Short Time', val: shortNum(countMatching(/auth.*burst|multiple login|rapid login|brute/i)), trend: 'Rapid Login', color: MON.orange, data: timeline },
    { label: '📁 7. File Access During Night Hours', val: shortNum(countMatching(/file.*(?:night|odd|off.hours)|(?:night|odd|off.hours).*file/i)), trend: 'Night File Access', color: MON.yellow, data: timeline },
    { label: '✏️ 8. Mass File Modification Spike', val: shortNum(countMatching(/mass file mod|bulk file mod/i)), trend: 'Mass Edit Spike', color: MON.red, data: timeline },
    { label: '🔐 9. Sudden File Encryption Activity', val: shortNum(countMatching(/encrypt|ransom/i)), trend: 'Encryption Spike', color: MON.red, data: timeline },
    { label: '🌐 10. Data Transfer During Night Hours', val: shortNum(countMatching(/data transfer|upload|download|exfil/i)), trend: 'Night Data Transfer', color: MON.purple, data: timeline },
    { label: '⚡ 11. API Call & DNS Request Bursts', val: shortNum(countMatching(/api.*burst|dns.*burst/i)), trend: 'Burst Activity', color: MON.cyan, data: timeline },
    { label: '🛡️ 12. Privilege Escalation at Odd Hours', val: shortNum(countMatching(/privilege|sudo|admin rights/i)), trend: 'PrivEsc Spike', color: MON.red, data: timeline },
    { label: '🔒 13. Security Policy Modification Night', val: shortNum(countMatching(/policy mod|firewall.*change/i)), trend: 'Policy Mod Night', color: MON.orange, data: timeline },
    { label: '🚨 14. Critical Time-Based Alerts', val: shortNum(sevCounts.critical), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 15. High Severity Time Anomalies', val: shortNum(sevCounts.high), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🖥️ 16. Monitored Agent Hosts', val: shortNum(backendSystems.length), trend: 'Agents Reporting', color: MON.cyan, data: timeline },
    { label: '💖 17. 30-Day Behavioral Model Score', val: `${baselineScore}/100`, trend: 'Baseline Confidence', color: MON.green, data: timeline },
    { label: '⚙️ 18. Scheduled Task Running Wrong Time', val: shortNum(countMatching(/scheduled task|cron/i)), trend: 'Task Anomaly', color: MON.yellow, data: timeline },
    { label: '💻 19. RDP & VPN Sessions at Night', val: shortNum(countMatching(/rdp|vpn|remote login|ssh/i)), trend: 'Night RDP/VPN', color: MON.purple, data: timeline },
    { label: '✅ 20. Verified Maintenance Window Events', val: shortNum(countMatching(/authorized maintenance|maintenance window/i)), trend: 'Maintenance OK', color: MON.green, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.isOnline ? 'online' : 'offline',
      monitor: true,
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || null,
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
          { id: 'configure', icon: '⚙️', label: 'Configure', activeColor: MON.green },
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
        {activeTab === 'inspector' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: 0, fontSize: 14, color: MON.cyan, fontWeight: 900 }}>⏱️ 50+ Agent-Based Time Anomaly Monitors</h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>Behavioral baseline engine tracking unusual time patterns</div>
            </div>

            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
                    <th style={{ padding: 10 }}>Monitoring Point / Anomaly Type</th>
                    <th style={{ padding: 10 }}>Time Window</th>
                    <th style={{ padding: 10 }}>30d Baseline Shift</th>
                    <th style={{ padding: 10 }}>Risk Score</th>
                    <th style={{ padding: 10 }}>EDR Action</th>
                  </tr>
                </thead>
                <tbody>
                  {TIME_MONITOR_CATEGORIES.slice(0, 15).map((point, idx) => {
                    const matches = rows.filter(row => `${anomalyType(row)} ${row.description || ''}`.toLowerCase().includes(point.toLowerCase()));
                    const maxRisk = matches.reduce((maximum, row) => Math.max(maximum, anomalyRiskScore(row)), 0);
                    return (
                    <tr key={idx} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 10, color: MON.cyan, fontWeight: 900 }}>{point}</td>
                      <td style={{ padding: 10, color: MON.sub }}>{matches[0] ? anomalyTimeWindow(matches[0]) : 'No event reported'}</td>
                      <td style={{ padding: 10, color: matches.length ? MON.red : MON.sub, fontWeight: 900 }}>{matches[0] ? anomalyBaselineDiff(matches[0]) : '—'}</td>
                      <td style={{ padding: 10, color: maxRisk >= 80 ? MON.red : maxRisk ? MON.yellow : MON.sub, fontWeight: 'bold' }}>{maxRisk}/100</td>
                      <td style={{ padding: 10, color: matches.length ? MON.yellow : MON.green, fontWeight: 800 }}>{matches.length ? `${matches.length} alert(s)` : 'Monitoring'}</td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        ) : activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={22}>
            <TimeAnomalyLogMonitor alerts={alerts} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <TimeAnomalyReportsTab alerts={alerts} />
        ) : activeTab === 'configure' ? (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 14, alignItems: 'start' }}>
            <TimeAnomalyConfigureTab systems={backendSystems} onRefresh={onRefresh} embedded />
            <TimeAnomalyExceptionsTab systems={backendSystems} onRefresh={onRefresh} embedded />
          </div>
        ) : activeTab === 'dashboard' ? (
          <TimeAnomalyOverviewDashboard alerts={alerts} total={totalRows} summary={summary} policy={policy} />
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
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Time Anomaly Inspection Subsystems</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {summary.activeAgents ?? agentStatusRows.filter(row => row.status === 'online').length} agents online · Behavioral baseline {policy.enabled === false ? 'disabled' : 'active'}</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>ML Model</span><span>Total Events</span><span>Anomalies</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.status === 'online' ? MON.green : MON.sub, textTransform: 'uppercase' }}>{row.status}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
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
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 24-Hour Time Anomaly Activity Wave (00:00 - 23:00)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} anomalies`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⏱️ Top Time Anomaly Categories</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(summary.topCategories || topCounts(rows, anomalyType, 4).map(([name, count]) => ({ name, count }))).map((item, index) => (
                    <div key={item.name} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{item.name}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan, fontWeight: 800 }}>{item.count} Events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔒 Behavioral Baseline Engine Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Behavioral Baseline Model', policy.enabled === false ? 'Disabled' : 'Active', policy.enabled === false ? MON.red : MON.green],
                    ['Business Hours Window', `${String(policy.workingHoursStart ?? 8).padStart(2, '0')}:00 - ${String(policy.workingHoursEnd ?? 20).padStart(2, '0')}:00`, MON.cyan],
                    ['Risk Score Threshold', `>= ${policy.anomalyRiskThreshold ?? 45}`, MON.yellow],
                    ['Agent Telemetry Heatmap', rows.length ? 'Active (Live)' : 'Awaiting telemetry', rows.length ? MON.green : MON.sub],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`TimeBasedAnomalyDetectionPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function TimeBasedAnomalyDetectionPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [liveData, setLiveData] = useState({});

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/time-anomaly/overview', { params: { limit: 1000, windowHours: 24 }, skipCache: quiet });
      const next = r.data?.events || r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);
      setLiveData(r.data || {});
    } catch {
      setAlerts([]);
      setSystems([]);
      setLiveData({});
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 15000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('time:anomaly', buf.add);
    socket.on('time:policy-updated', buf.add);
    socket.on('time:exception-updated', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('time:anomaly', buf.add);
      socket.off('time:policy-updated', buf.add);
      socket.off('time:exception-updated', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleAlertAction = useCallback(async (alertId, action) => {
    const disruptive = new Set(['isolate', 'quarantine', 'kill_process', 'block_ip']);
    let reason = '';
    let confirmed = false;
    if (disruptive.has(action)) {
      reason = window.prompt('Enter the reason for this containment action:')?.trim() || '';
      if (!reason) throw new Error('Containment cancelled: a reason is required');
      confirmed = window.confirm(`Confirm ${action.replaceAll('_', ' ')} for this alert?`);
      if (!confirmed) throw new Error('Containment cancelled');
    } else if (action === 'ignore') {
      reason = window.prompt('Enter the reason for marking this event as expected activity:')?.trim() || '';
      if (!reason) throw new Error('Action cancelled: a reason is required');
    }
    const response = await api.patch(`/dashboard/alerts/${alertId}/action`, { action, reason, confirmed });
    await loadAlerts(true);
    return response.data;
  }, [loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 22. Time-Based Anomaly Detection (Agent-Based Monitoring)
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <TimeBasedAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={liveData} onAction={handleAlertAction} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <TimeBasedAnomalyDetectionPage />;
}

export function TimeBasedAnomalySocTabPage({ tab }) {
  return <TimeBasedAnomalyDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function TimeAnomalySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=22" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Time Anomaly SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=22')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="timeanomaly" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <TimeBasedAnomalyDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { TimeBasedAnomalyDashboardPanel as TimeBasedAnomalyDashboard };
