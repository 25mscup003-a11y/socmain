import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Kernel-Level Monitoring — Capability ID: 19 (Backend ID: 22)
 *
 * 100% Self-Contained Enterprise SOC Kernel-Level & Rootkit Monitoring Module (Linux Kernel & eBPF Native)
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=19`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18)
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

function MiniSparkline({ data = [5, 9, 7, 14, 12, 18, 15, 22], color = MON.cyan, height = 30 }) {
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
  return row?.username || row?.user || row?.userName || 'Unknown user';
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
  if (osStr.includes('lin') || osStr.includes('ubuntu') || osStr.includes('rhel') || osStr.includes('debian')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Linux';
}

// ── Kernel Telemetry Field Extractors ──────────────────────────────────────
function kernelModule(row) {
  return row?.driverName || row?.moduleName || row?.fileName || row?.processName || 'Unknown module';
}

function kernelPath(row) {
  return row?.driverPath || row?.modulePath || row?.filePath || 'Not reported';
}

function kernelHash(row) {
  return row?.hashes?.sha256 || row?.fileHash || row?.sha256 || 'Not reported';
}

function kernelCategory(row) {
  return row?.kernelCategory || row?.category || row?.subCategory || 'Kernel telemetry event';
}

function kernelEventType(row) {
  return row?.kernelEventType || row?.eventType || row?.ruleId || 'Kernel telemetry event';
}

function kernelDescription(row) {
  return row?.description || row?.message || row?.detectionReasons?.join(', ') || 'No description reported';
}

function kernelPid(row) {
  return row?.pid ?? row?.processId ?? row?.process?.pid ?? '—';
}

function kernelProcess(row) {
  return row?.processName || row?.process?.name || row?.parentProcess || kernelModule(row);
}

function eventText(row) {
  return [kernelEventType(row), kernelCategory(row), kernelDescription(row), ...(row?.detectionReasons || [])]
    .filter(Boolean).join(' ').toLowerCase();
}

function formatClock(value) {
  const date = value ? new Date(value) : null;
  return date && Number.isFinite(date.getTime()) ? date.toLocaleTimeString() : '—';
}

function reported(value) {
  return value === undefined || value === null || value === '' ? 'Not reported' : String(value);
}

function normalizeProcessRows(alerts = []) {
  const output = [];
  const seen = new Set();
  const add = (item, fallback = {}) => {
    if (!item || typeof item !== 'object') return;
    const pid = item.pid ?? item.processId ?? fallback.pid;
    const name = item.name || item.processName || item.image || fallback.name;
    if (!name && pid === undefined) return;
    const row = {
      pid: pid ?? '—', ppid: item.ppid ?? item.parentPid ?? fallback.ppid ?? '—',
      name: name || 'Unknown process', user: item.user || item.username || fallback.user || 'Not reported',
      hook: item.syscall || item.hook || fallback.hook || 'Not reported',
      severity: String(item.severity || fallback.severity || 'info').toLowerCase(),
      commandLine: item.commandLine || item.cmd || fallback.commandLine || '',
    };
    const key = `${row.pid}:${row.name}:${row.ppid}`;
    if (!seen.has(key)) { seen.add(key); output.push(row); }
  };
  alerts.forEach(alert => {
    const fallback = {
      pid: kernelPid(alert), ppid: alert.parentPid, name: kernelProcess(alert), user: alertUser(alert),
      hook: alert.syscallName || alert.syscall, severity: alertSeverity(alert), commandLine: alert.commandLine,
    };
    if (Array.isArray(alert.processTree)) alert.processTree.forEach(item => add(item, fallback));
    else if (kernelPid(alert) !== '—' || alert.processName || alert.process) add(alert, fallback);
  });
  return output;
}

function normalizeNetworkRows(alerts = []) {
  const rows = [];
  alerts.forEach(alert => {
    const nested = Array.isArray(alert.networkConnections) ? alert.networkConnections : [];
    if (nested.length) {
      nested.forEach(item => rows.push({
        src: item.source || item.src || item.sourceIp || item.localAddress || 'Not reported',
        dst: item.destination || item.dst || item.destinationIp || item.remoteAddress || 'Not reported',
        status: item.status || item.state || 'Observed', severity: alertSeverity(alert),
      }));
    } else if (alert.sourceIp || alert.destinationIp) {
      rows.push({
        src: alert.sourceIp || 'Not reported', dst: alert.destinationIp || 'Not reported',
        status: alert.connectionStatus || 'Observed', severity: alertSeverity(alert),
      });
    }
  });
  return rows;
}

function containsAny(row, words = []) {
  const haystack = [
    kernelModule(row), kernelPath(row), kernelHash(row), alertHost(row),
    row?.description, row?.message, row?.malwareFamily, kernelCategory(row),
  ].filter(Boolean).join(' ').toLowerCase();
  return words.some(word => haystack.includes(word));
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${kernelModule(row)}-${kernelHash(row).substring(0, 8)}`;
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
// 1. LINUX FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function KernelForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'processtree', label: '⚙️ 2. Linux Process & LKM Tree' },
    { id: 'memory', label: '🧠 3. Memory & RWX Pages' },
    { id: 'ssdt', label: '🔧 4. sys_call_table & kprobes' },
    { id: 'network', label: '🌐 5. eBPF & Netfilter Hooks' },
    { id: 'ioc', label: '🎯 6. IOC Extraction' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'byovd', label: '☣️ 8. BYOVD & Vulnerable LKMs' },
    { id: 'screenshots', label: '🖼️ 9. Kernel Memory Snapshots' },
    { id: 'reports', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionName) => {
    const actionType = /isolate/i.test(actionName) ? 'isolate' : /block.*hash/i.test(actionName) ? 'quarantine' : null;
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
            <span style={{ fontSize: 24 }}>🐧</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Linux Kernel Forensic Panel — {kernelModule(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {log.verdict || 'NOT REPORTED'}
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {log.riskScore ?? 0}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Host: <strong style={{ color: MON.cyan }}>{alertHost(log)}</strong> | User: <strong style={{ color: MON.yellow }}>{alertUser(log)}</strong> | Kernel: <strong>{log.osTarget || processOs(log)}</strong> | Signature: <strong>{log.signatureStatus || 'Not reported'}</strong>
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
          {/* TAB 1: OVERVIEW & STATIC ANALYSIS */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Module Verdict', (log.verdict || 'Not reported').toUpperCase(), sevColor],
                  ['Risk Score', `${log.riskScore ?? 0} / 100`, MON.red],
                  ['Signature Status', log.signatureStatus || 'Not reported', MON.orange],
                  ['Malware Family', log.malwareFamily || 'Not reported', MON.purple],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>🔑 Linux LKM Module Cryptographic Hashes & File Details</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: '8px 12px', fontSize: 11, fontFamily: 'monospace' }}>
                  <span style={{ color: MON.muted }}>Module Path:</span> <span style={{ color: MON.text }}>{kernelPath(log)}</span>
                  <span style={{ color: MON.muted }}>SHA256:</span> <span style={{ color: MON.red, fontWeight: 'bold' }}>{kernelHash(log)}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PROCESS & LKM TREE */}
          {activeTab === 'processtree' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 14px 0', fontSize: 13, color: MON.cyan }}>🌳 Linux Process & Kernel Module Execution Hierarchy Tree</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(Array.isArray(log.processTree) ? log.processTree : []).map((proc, idx) => (
                  <div key={proc.pid} style={{ padding: '10px 14px', background: MON.bg, border: `1px solid ${proc.status === 'Critical' ? MON.red : proc.status === 'Suspicious' ? MON.orange : MON.border}`, borderRadius: 6, marginLeft: idx * 24 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 900, color: proc.status === 'Critical' ? MON.red : MON.cyan, fontSize: 12 }}>
                        {idx > 0 ? '└── ' : ''}{proc.name} (PID: {proc.pid})
                      </span>
                      <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: proc.status === 'Critical' ? `${MON.red}20` : `${MON.yellow}20`, color: proc.status === 'Critical' ? MON.red : MON.yellow, fontWeight: 800 }}>
                        {proc.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 10, color: MON.muted, fontFamily: 'monospace', marginTop: 4 }}>Path: {proc.path}</div>
                    <div style={{ fontSize: 10, color: MON.sub, fontFamily: 'monospace', marginTop: 2 }}>Command: {proc.cmd}</div>
                  </div>
                ))}
                {!Array.isArray(log.processTree) || !log.processTree.length ? (
                  <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                    Process-tree telemetry was not reported by this endpoint.
                  </div>
                ) : null}
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Automated Linux SOC Remediation Actions</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction(`Force Remove Kernel Module (rmmod -f ${kernelModule(log)})`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Unload Linux Kernel Module (rmmod -f {kernelModule(log)})
                  </button>
                  <button type="button" onClick={() => handleAction('Isolate Linux Host')} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Linux Host ({alertHost(log)})
                  </button>
                  <button type="button" onClick={() => handleAction('Block LKM Module Hash in eBPF Engine')} style={{ padding: '8px 14px', background: `${MON.purple}25`, border: `1px solid ${MON.purple}`, color: MON.purple, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛡️ Add Module Hash to eBPF Block Filter
                  </button>
                </div>
              </div>
            </div>
          )}

          {['memory', 'ssdt', 'network', 'ioc', 'mitre', 'byovd', 'screenshots'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry Inspection</h4>
              <div style={{ fontSize: 11, color: MON.muted }}>
                Detailed Linux kernel telemetry captured for {activeTab}. Full raw payload logged in SIEM database.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard, LKM Inspector)
// ═════════════════════════════════════════════════════════════════════════════
export function KernelLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${kernelModule(a)} ${kernelHash(a)} ${kernelCategory(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Module Name (.ko), SHA256 Hash, Target Host, Category..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Linux Kernel Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Module Name (.ko)</span><span>Target Host</span><span>SHA256 Hash</span><span>Verdict</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{kernelModule(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: MON.sub }}>{kernelHash(row).substring(0, 16)}...</span>
                <b style={{ color: SEV_COLOR[alertSeverity(row)] || MON.blue, textTransform: 'uppercase' }}>{row.verdict || 'not reported'}</b>
                <b style={{ color: Number(row.riskScore || 0) > 75 ? MON.red : MON.orange }}>{row.riskScore ?? 0}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No kernel telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <KernelForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function KernelReportsTab({ alerts = [] }) {
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

  const handleGenerate = () => {
    setGenerating(true);
    setGenerated(false);
    setTimeout(() => {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: filtered.length,
        bySev,
      });
      setGenerating(false);
      setGenerated(true);
    }, 400);
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Module Name,SHA256,Target Host,Category,Severity,Status';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(kernelModule(a)),
      csvCell(kernelHash(a)),
      csvCell(alertHost(a)),
      csvCell(kernelCategory(a)),
      csvCell(alertSeverity(a)),
      csvCell(alertStatus(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `kernel_monitoring_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Linux Kernel-Level Monitoring Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for LKM rootkits, sys_call_table hooks, eBPF tracepoint anomalies, and BYOVD driver exploits</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Kernel Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Linux Kernel Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Kernel Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Risk LKMs', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Hooks', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Verified Signed LKMs', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Kernel-Level Monitoring Dashboard ──────
function AlertsSummaryDonut({ alerts = [], summary = {} }) {
  const counts = summary.bySeverity || alerts.reduce((acc, row) => {
    const severity = alertSeverity(row);
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});
  const categories = [
    { label: 'Critical', count: Number(counts.critical || 0), color: '#ef4444' },
    { label: 'High', count: Number(counts.high || 0), color: '#f97316' },
    { label: 'Medium', count: Number(counts.medium || 0), color: '#eab308' },
    { label: 'Low', count: Number(counts.low || 0), color: '#38bdf8' },
  ];
  const total = categories.reduce((sum, item) => sum + item.count, 0);

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = categories.map((s) => {
    const angle = total ? (s.count / total) * 359.99 : 0;
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

  const recentCriticalAlerts = alerts
    .filter(row => alertSeverity(row) === 'critical')
    .slice(0, 5)
    .map(row => ({ msg: kernelDescription(row), time: formatClock(alertTime(row)) }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6, display: 'block' }}>ALERTS SUMMARY</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.filter(arc => arc.count > 0).map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{total}</span>
              <span style={{ fontSize: 7, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 8.5 }}>
            {categories.map(c => (
              <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginTop: 10 }}>
          <span style={{ fontSize: 8, color: '#8ea0b8', fontWeight: 700, display: 'block', marginBottom: 4 }}>Recent Critical Alerts</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
            {recentCriticalAlerts.map((ra, idx) => (
              <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8 }}>
                <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span>🔴</span> {ra.msg}
                </span>
                <span style={{ color: '#64748b', fontSize: 7.5 }}>{ra.time}</span>
              </div>
            ))}
            {!recentCriticalAlerts.length && <span style={{ color: '#64748b', fontSize: 8 }}>No critical kernel alerts reported.</span>}
          </div>
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Alerts →</span>
    </div>
  );
}

function TopAttackTacticsMitre({ alerts = [] }) {
  const colors = ['#ef4444', '#f97316', '#eab308', '#38bdf8', '#a78bfa'];
  const counts = new Map();
  alerts.forEach(row => {
    const values = [row.mitreTactic, row.attackTactic, ...(Array.isArray(row.mitreTactics) ? row.mitreTactics : [])].filter(Boolean);
    values.forEach(value => counts.set(String(value), (counts.get(String(value)) || 0) + 1));
  });
  const total = Array.from(counts.values()).reduce((sum, count) => sum + count, 0);
  const items = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, 5).map(([label, count], index) => ({
    label, count, pct: total ? Number(((count / total) * 100).toFixed(1)) : 0, color: colors[index],
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 8, display: 'block' }}>TOP ATTACK TACTICS (MITRE)</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {items.map(item => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 8.5 }}>
              <span style={{ width: 95, color: '#8ea0b8', flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.label}</span>
              <div style={{ flex: 1, height: 6, background: '#07101b', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${item.pct}%`, height: '100%', background: item.color, borderRadius: 3 }} />
              </div>
              <span style={{ color: '#e2e8f0', fontWeight: 700, width: 45, textAlign: 'right', fontSize: 8 }}>{item.count} ({item.pct}%)</span>
            </div>
          ))}
          {!items.length && <span style={{ color: '#64748b', fontSize: 8 }}>No MITRE tactic telemetry reported.</span>}
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Full MITRE Map →</span>
    </div>
  );
}

function RootkitDetectionPanel({ alerts = [] }) {
  const checks = [
    ['Hidden Processes', /hidden process/], ['Hidden Modules', /hidden (?:module|driver)/],
    ['Hidden Files', /hidden file/], ['Kernel Hooks', /kernel hook/],
    ['Syscall Table', /sys.?call(?:_table)?.{0,20}(?:hook|tamper)/], ['DKOM Detection', /dkom/],
  ].map(([label, pattern]) => {
    const count = alerts.filter(row => pattern.test(eventText(row))).length;
    return { label, status: count ? `${count} detected` : 'Not reported', count };
  });
  const detected = checks.reduce((sum, check) => sum + check.count, 0);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 8, display: 'block' }}>ROOTKIT DETECTION</span>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <div style={{ width: 64, height: 64, borderRadius: '50%', background: detected ? 'rgba(239, 68, 68, 0.1)' : 'rgba(100, 116, 139, 0.1)', border: `2px solid ${detected ? '#ef4444' : '#64748b'}`, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
            <span style={{ fontSize: 24 }}>🛡️</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 8.5 }}>
            {checks.map(c => (
              <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: '#8ea0b8' }}>{c.label}</span>
                <span style={{ color: c.count ? '#ef4444' : '#64748b', fontWeight: 700 }}>{c.status}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>Run Full Scan →</span>
    </div>
  );
}

function KernelProcessTreeModal({ onClose, processes = [] }) {
  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 10, width: '90%', maxWidth: 1100, maxHeight: '90vh', overflowY: 'auto', padding: 20, boxShadow: '0 20px 50px rgba(0,0,0,0.8)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #16273e', paddingBottom: 12 }}>
          <div>
            <span style={{ fontSize: 16, fontWeight: 900, color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>🐧</span> KERNEL LIVE PROCESS TREE ANALYSIS
            </span>
            <span style={{ fontSize: 10, color: '#8ea0b8' }}>Linux eBPF & sys_call_table Execution Hierarchy</span>
          </div>
          <button onClick={onClose} style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#ef4444', borderRadius: 6, width: 28, height: 28, cursor: 'pointer', fontWeight: 800, fontSize: 14 }}>
            ✕
          </button>
        </div>

        {/* Expanded Visual Tree */}
        <div style={{ background: '#050a12', border: '1px solid #16273e', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <span style={{ fontSize: 10, fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Reported Process Execution Hierarchy</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11, fontFamily: 'monospace' }}>
            {processes.map((row, index) => {
              const color = SEV_COLOR[row.severity] || '#8ea0b8';
              return (
                <div key={`${row.pid}-${row.name}-${index}`} style={{ marginLeft: Math.min(index, 5) * 14, background: '#0b1626', border: `1px solid ${color}`, borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span style={{ color, fontWeight: 800 }}>{index ? '└── ' : ''}[PID: {row.pid}] {row.name}</span>
                    <span style={{ color: '#8ea0b8', fontSize: 9.5, display: 'block', marginTop: 2 }}>{row.commandLine || `Parent PID: ${row.ppid}`}</span>
                  </div>
                  <span style={{ fontSize: 9, background: `${color}22`, color, padding: '2px 8px', borderRadius: 4, fontWeight: 800 }}>{row.severity.toUpperCase()}</span>
                </div>
              );
            })}
            {!processes.length && <div style={{ padding: 20, textAlign: 'center', color: '#64748b' }}>Process-tree telemetry has not been reported by the endpoint agent.</div>}
          </div>
        </div>

        {/* Detailed Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ fontSize: 10, fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Kernel Process & Syscall Telemetry</span>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 8.5, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: '#07101b', color: '#64748b', borderBottom: '1px solid #16273e' }}>
                  <th style={{ padding: '6px 8px' }}>PID</th>
                  <th style={{ padding: '6px 8px' }}>PPID</th>
                  <th style={{ padding: '6px 8px' }}>COMMAND / PROCESS</th>
                  <th style={{ padding: '6px 8px' }}>USER</th>
                  <th style={{ padding: '6px 8px' }}>EBPF HOOK / SYSCALL</th>
                  <th style={{ padding: '6px 8px' }}>SEVERITY</th>
                  <th style={{ padding: '6px 8px' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {processes.map(r => {
                  const col = SEV_COLOR[r.severity] || '#8ea0b8';
                  return (
                  <tr key={r.pid} style={{ borderBottom: '1px solid #16273e' }}>
                    <td style={{ padding: '6px 8px', color: '#38bdf8', fontWeight: 700, fontFamily: 'monospace' }}>{r.pid}</td>
                    <td style={{ padding: '6px 8px', color: '#8ea0b8', fontFamily: 'monospace' }}>{r.ppid}</td>
                    <td style={{ padding: '6px 8px', color: '#fff', fontWeight: 700 }}>{r.name}</td>
                    <td style={{ padding: '6px 8px', color: '#cbd5e1' }}>{r.user}</td>
                    <td style={{ padding: '6px 8px', color: '#38bdf8', fontFamily: 'monospace', fontSize: 7.5 }}>{r.hook}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ fontSize: 7.5, fontWeight: 800, color: col, background: `${col}15`, border: `1px solid ${col}33`, padding: '2px 6px', borderRadius: 3 }}>
                        {r.severity}
                      </span>
                    </td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ color: '#64748b' }}>Investigation only</span>
                    </td>
                  </tr>
                  );
                })}
                {!processes.length && <tr><td colSpan={7} style={{ padding: 18, textAlign: 'center', color: '#64748b' }}>No process telemetry reported.</td></tr>}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function KernelOverviewDashboard({ alerts = [], total = 0, data = {} }) {
  const [showProcessModal, setShowProcessModal] = useState(false);
  const summary = data?.summary || {};
  const posture = data?.posture || summary.posture || {};
  const modules = Array.isArray(data?.modules) ? data.modules : [];
  const processes = normalizeProcessRows(alerts);
  const processSlots = Array.from({ length: 8 }, (_, index) => processes[index] || { name: 'Not reported', pid: '—', severity: 'info' });
  const networkRows = normalizeNetworkRows(alerts);
  const timeline = buildBuckets(alerts, 6, 24);

  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const headerStats = [
    { title: 'System Call Alerts', val: shortNum(summary.syscallHooks || 0), sub: '24h telemetry', col: '#38bdf8', icon: '⏱️', spark: timeline },
    { title: 'Processes Reported', val: shortNum(processes.length), sub: processes.length ? 'Agent reported' : 'Not reported', col: '#22c55e', icon: '🌿', spark: timeline },
    { title: 'Kernel Modules', val: shortNum(summary.activeDrivers ?? modules.length), sub: modules.length ? 'Current inventory' : 'Not reported', col: '#a78bfa', icon: '🧊', spark: timeline },
    { title: 'Open Connections', val: shortNum(networkRows.length), sub: networkRows.length ? 'Kernel events' : 'Not reported', col: '#38bdf8', icon: '🌐', spark: timeline },
    { title: 'Security Alerts', val: shortNum(total || alerts.length), sub: 'Selected window', col: '#ef4444', icon: '🛡️', spark: timeline },
  ];

  const systemCalls = topCounts(alerts, row => row.syscallName || row.syscall || '', 10)
    .map(([name, count]) => ({ name, count: shortNum(count), trend: 'Observed', col: '#22c55e' }));

  const kernelModules = modules.slice(0, 7).map(row => ({
    name: kernelModule(row), status: row.driverState || row.state || 'Loaded',
    signer: row.publisher || row.signatureStatus || 'Not reported',
    unsig: /unsigned|notsigned|invalid|tainted/i.test(String(row.signatureStatus || '')),
  }));

  const memoryAlerts = alerts.filter(row => /memory|rwx|injection|shellcode|corruption/.test(eventText(row))).slice(0, 4).map(row => ({
    proc: kernelProcess(row), type: kernelEventType(row), pid: kernelPid(row), time: formatClock(alertTime(row)),
    col: SEV_COLOR[alertSeverity(row)] || '#64748b',
  }));

  const persistenceItems = [
    ['Startup Services', /startup|service/, '🛡️'], ['Scheduled Tasks', /scheduled task/, '📅'],
    ['Registry Run Keys', /registry|run key/, '🔑'], ['Cron Jobs', /cron/, '⏰'],
  ].map(([label, pattern, icon]) => {
    const count = alerts.filter(row => pattern.test(eventText(row))).length;
    return { label, val: count ? `${count} observed` : 'Not reported', col: count ? '#f97316' : '#64748b', icon };
  });

  const netConns = networkRows.slice(0, 4).map(row => ({
    src: row.src, dst: row.dst, st: row.status,
    col: ['critical', 'high'].includes(row.severity) ? '#f97316' : '#22c55e',
  }));

  const recentKernelEvents = alerts.slice(0, 5).map(row => {
    const sev = alertSeverity(row);
    return { time: formatClock(alertTime(row)), type: kernelEventType(row), details: kernelDescription(row), mod: kernelModule(row), pid: kernelPid(row), sev, sevCol: SEV_COLOR[sev] || '#64748b' };
  });

  const realTimeFeed = alerts.slice(0, 5).map(row => {
    const severity = alertSeverity(row);
    return { time: formatClock(alertTime(row)), tag: severity.toUpperCase(), msg: kernelDescription(row), pid: kernelPid(row) === '—' ? '—' : `PID: ${kernelPid(row)}`, tagCol: SEV_COLOR[severity] || '#64748b' };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {showProcessModal && (
        <KernelProcessTreeModal processes={processes} onClose={() => setShowProcessModal(false)} />
      )}

      {/* 1. TOP HEADER (KERNEL SECURITY OVERVIEW + ALERTS SUMMARY) */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 1.2fr', gap: 12 }}>
        {/* Kernel Security Overview */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>KERNEL SECURITY OVERVIEW</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
            {headerStats.map(s => (
              <div key={s.title} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '10px 10px', display: 'flex', flexDirection: 'column', gap: 4 }}>
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
        </div>

        <div style={panelStyle}>
          <AlertsSummaryDonut alerts={alerts} summary={summary} />
        </div>
      </div>

      {/* 2. UPPER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr 1.1fr 1fr', gap: 12 }}>
        {/* System Call Activity */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>SYSTEM CALL ACTIVITY <span style={{ fontSize: 8, color: '#64748b' }}>(Top 10)</span></span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>System Call</span>
              <span>Count</span>
              <span>Trend</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
              {systemCalls.map(sc => (
                <div key={sc.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>{sc.name}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{sc.count}</span>
                  <span style={{ color: sc.col, fontWeight: 700 }}>{sc.trend}</span>
                </div>
              ))}
              {!systemCalls.length && <span style={{ color: '#64748b', fontSize: 8 }}>No syscall telemetry reported.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All System Calls →</span>
        </div>

        {/* Process Tree (Live) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>PROCESS TREE <span style={{ fontSize: 8, color: '#22c55e' }}>(Live)</span></span>
            <div onClick={() => setShowProcessModal(true)} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, marginTop: 4, cursor: 'pointer' }}>
              <div style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 8px', textAlign: 'center' }}>
                <span style={{ fontSize: 8, color: '#e2e8f0' }}>{processSlots[0].name}</span>
                <span style={{ fontSize: 7, color: '#64748b', display: 'block' }}>PID: {processSlots[0].pid}</span>
              </div>
              <div style={{ width: 1, height: 8, background: '#16273e' }} />
              <div style={{ display: 'flex', gap: 16 }}>
                {processSlots.slice(1, 3).map((row, index) => (
                  <div key={`${row.pid}-${index}`} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 8px', textAlign: 'center' }}>
                    <span style={{ fontSize: 8, color: '#e2e8f0' }}>{row.name}</span>
                    <span style={{ fontSize: 7, color: '#64748b', display: 'block' }}>PID: {row.pid}</span>
                  </div>
                ))}
              </div>
              <div style={{ width: 1, height: 8, background: '#16273e' }} />
              <div style={{ display: 'flex', gap: 10 }}>
                {processSlots.slice(3, 5).map((row, index) => (
                  <div key={`${row.pid}-${index}`} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '2px 6px', textAlign: 'center' }}>
                    <span style={{ fontSize: 7.5, color: '#cbd5e1' }}>{row.name}</span>
                    <span style={{ fontSize: 6.5, color: '#64748b', display: 'block' }}>PID: {row.pid}</span>
                  </div>
                ))}
              </div>
              <div style={{ width: 1, height: 8, background: '#16273e' }} />
              <div style={{ display: 'flex', gap: 6 }}>
                {processSlots.slice(5, 8).map((row, index) => {
                  const color = SEV_COLOR[row.severity] || '#64748b';
                  return (
                    <div key={`${row.pid}-${index}`} style={{ background: `${color}20`, border: `1px solid ${color}`, borderRadius: 4, padding: '2px 5px', textAlign: 'center' }}>
                      <span style={{ fontSize: 7.5, color }}>{['critical', 'high'].includes(row.severity) ? '⚠️ ' : ''}{row.name}</span>
                      <span style={{ fontSize: 6.5, color, display: 'block' }}>PID: {row.pid}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
          <span onClick={() => setShowProcessModal(true)} style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Full Process Tree →</span>
        </div>

        {/* Kernel Modules */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>KERNEL MODULES</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.2fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>Module Name</span>
              <span>Status</span>
              <span>Signer</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 4 }}>
              {kernelModules.map(km => (
                <div key={km.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.2fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: km.unsig ? '#f87171' : '#cbd5e1', fontWeight: km.unsig ? 800 : 500 }}>{km.name}</span>
                  <span style={{ color: '#22c55e', fontWeight: 700 }}>{km.status}</span>
                  <span style={{ color: km.unsig ? '#f87171' : '#8ea0b8', fontWeight: km.unsig ? 800 : 500 }}>{km.signer}</span>
                </div>
              ))}
              {!kernelModules.length && <span style={{ color: '#64748b', fontSize: 8 }}>No kernel module inventory reported.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Modules →</span>
        </div>

        <div style={panelStyle}>
          <TopAttackTacticsMitre alerts={alerts} />
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.4fr 1.1fr', gap: 12 }}>
        {/* Memory Injection Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>MEMORY INJECTION ALERTS</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr 0.6fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>Process</span>
              <span>Type</span>
              <span>PID</span>
              <span>Time</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {memoryAlerts.map((ma, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr 0.6fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: ma.col, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 3 }}>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: ma.col }} /> {ma.proc}
                  </span>
                  <span style={{ color: '#e2e8f0' }}>{ma.type}</span>
                  <span style={{ color: '#8ea0b8' }}>{ma.pid}</span>
                  <span style={{ color: '#64748b', fontSize: 7.5 }}>{ma.time}</span>
                </div>
              ))}
              {!memoryAlerts.length && <span style={{ color: '#64748b', fontSize: 8 }}>No kernel memory alerts reported.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Memory Alerts →</span>
        </div>

        {/* Persistence Monitoring */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>PERSISTENCE MONITORING</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {persistenceItems.map(pi => (
                <div key={pi.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{pi.icon}</span> {pi.label}
                  </span>
                  <span style={{ color: pi.col, fontWeight: 800 }}>{pi.val}</span>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Persistence →</span>
        </div>

        {/* Network Activity (Kernel Level) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 6, display: 'block' }}>NETWORK ACTIVITY <span style={{ fontSize: 8, color: '#64748b' }}>(KERNEL LEVEL)</span></span>
            <div style={{ height: 40, background: '#07101b', borderRadius: 4, border: '1px solid #16273e', overflow: 'hidden', position: 'relative', marginBottom: 6 }}>
              <svg viewBox="0 0 200 60" width="100%" height="100%" style={{ opacity: 0.5 }}>
                <path d="M 20,20 Q 30,10 45,25 T 70,20 T 90,35 T 60,50 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
                <path d="M 110,15 Q 130,5 160,15 T 180,35 T 150,55 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
              </svg>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {netConns.map((nc, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{nc.src} → {nc.dst}</span>
                  <span style={{ color: nc.col, fontWeight: 700, fontSize: 7 }}>{nc.st}</span>
                </div>
              ))}
              {!netConns.length && <span style={{ color: '#64748b', fontSize: 8 }}>No kernel network telemetry reported.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Connections →</span>
        </div>

        <div style={panelStyle}>
          <RootkitDetectionPanel alerts={alerts} posture={posture} />
        </div>
      </div>

      {/* 4. BOTTOM GRID (RECENT KERNEL EVENTS + REAL-TIME EVENT FEED) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr', gap: 12 }}>
        {/* Recent Kernel Events */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>RECENT KERNEL EVENTS</span>
          <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.3fr 2.2fr 1fr 0.5fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
            <span>Time</span>
            <span>Event Type</span>
            <span>Details</span>
            <span>Process / Module</span>
            <span>PID</span>
            <span>Severity</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
            {recentKernelEvents.map((rke, idx) => (
              <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.3fr 2.2fr 1fr 0.5fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                <span style={{ color: '#64748b' }}>{rke.time}</span>
                <span style={{ color: rke.sevCol, fontWeight: 700 }}>{rke.type}</span>
                <span style={{ color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rke.details}</span>
                <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{rke.mod}</span>
                <span style={{ color: '#8ea0b8' }}>{rke.pid}</span>
                <span style={{ fontSize: 7.5, fontWeight: 800, color: rke.sevCol, padding: '1px 4px', background: `${rke.sevCol}15`, borderRadius: 3, border: `1px solid ${rke.sevCol}33`, textAlign: 'center' }}>
                  {rke.sev}
                </span>
              </div>
            ))}
            {!recentKernelEvents.length && <span style={{ color: '#64748b', fontSize: 8 }}>No kernel events reported in this window.</span>}
          </div>
        </div>

        {/* Real-Time Event Feed */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>REAL-TIME EVENT FEED</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, background: '#050a12', border: '1px solid #16273e', borderRadius: 6, padding: 8, fontFamily: 'monospace', fontSize: 7.5 }}>
              {realTimeFeed.map((rf, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', gap: 6 }}>
                  <span style={{ color: '#64748b' }}>{rf.time}</span>
                  <span style={{ color: rf.tagCol, fontWeight: 800, width: 45 }}>{rf.tag}</span>
                  <span style={{ color: '#cbd5e1', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rf.msg}</span>
                  <span style={{ color: '#8ea0b8' }}>{rf.pid}</span>
                </div>
              ))}
              {!realTimeFeed.length && <span style={{ color: '#64748b', fontSize: 8 }}>Waiting for agent kernel telemetry.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Full Event Log →</span>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`KernelLevelMonitoringDashboardPanel` / `KernelLevelMonitoringDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function KernelLevelMonitoringDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction, onRefresh }) {
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
  const modules = Array.isArray(data?.modules) ? data.modules : [];
  const summary = data?.summary || {};
  const posture = data?.posture || summary.posture || {};
  const totalRows = total || recordsTotal || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const countMatching = pattern => rows.filter(row => pattern.test(eventText(row))).length;
  const inventoryReported = modules.length > 0;
  const kernelEvidenceReported = rows.length > 0 || inventoryReported;
  const osCount = pattern => backendSystems.filter(system => pattern.test(String(system.os || system.osType || system.platform || ''))).length;

  // 20 Kernel-Level Specific SOC Categories & Metrics
  const kpis = [
    { label: '🛡️ 1. Linux Kernel Health Score', val: kernelEvidenceReported ? `${Number(summary.healthScore ?? 0)}/100` : 'Not reported', trend: 'Kernel Score', color: MON.green, data: timeline },
    { label: '🚨 2. Unsigned / Vulnerable LKMs', val: shortNum(Number(summary.unsignedDrivers || 0) + Number(summary.vulnerableDrivers || 0)), trend: 'Unsigned LKM', color: MON.red, data: timeline },
    { label: '⚠️ 3. sys_call_table Hooks Detected', val: shortNum(summary.syscallHooks || 0), trend: 'Syscall Hook', color: MON.orange, data: timeline },
    { label: '🦠 4. Rootkit & LKM Stealth Alerts', val: shortNum(summary.rootkitAlerts || 0), trend: 'Rootkits', color: MON.red, data: timeline },
    { label: '🧠 5. Writable Executable (RWX) Pages', val: shortNum(countMatching(/rwx|writable executable/)), trend: 'RWX Memory', color: MON.red, data: timeline },
    { label: '🔐 6. root Privilege Escalation Signals', val: shortNum(summary.privilegeEscalations || 0), trend: 'root Escalation', color: MON.orange, data: timeline },
    { label: '🌐 7. eBPF Probe Hooks & XDP Attachments', val: shortNum(countMatching(/ebpf|xdp/)), trend: 'eBPF Probes', color: MON.purple, data: timeline },
    { label: '👤 8. task_struct cred Tampering (DKOM)', val: shortNum(countMatching(/dkom|task_struct|cred tamper/)), trend: 'DKOM Tamper', color: MON.cyan, data: timeline },
    { label: '🔒 9. Protected Kernel Memory Maps', val: 'Not reported', trend: 'Protected Maps', color: MON.cyan, data: timeline },
    { label: '⚓ 10. kprobe & kretprobe Injections', val: shortNum(countMatching(/kretprobe|kprobe/)), trend: 'kprobe Attach', color: MON.yellow, data: timeline },
    { label: '🖥️ 11. Monitored Linux Enterprise Endpoints', val: shortNum(summary.monitoredSystems ?? backendSystems.length), trend: 'Linux Servers', color: MON.cyan, data: timeline },
    { label: '🛡️ 12. CONFIG_STRICT_MODULE_RWX', val: reported(posture.strict_module_rwx), trend: 'Kernel Policy', color: MON.green, data: timeline },
    { label: '🚨 13. Critical Linux Kernel Threats', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '📦 14. Active Loaded Kernel Modules (.ko)', val: shortNum(summary.activeDrivers ?? modules.length), trend: 'Loaded LKMs', color: MON.blue, data: timeline },
    { label: '🐧 15. Ubuntu Linux Monitored Servers', val: shortNum(osCount(/ubuntu/i)), trend: 'Ubuntu Server', color: MON.cyan, data: timeline },
    { label: '🎩 16. Red Hat Enterprise (RHEL) Servers', val: shortNum(osCount(/rhel|red hat|rocky|alma|centos/i)), trend: 'RHEL Server', color: MON.red, data: timeline },
    { label: '🌀 17. Debian K8s Cluster Nodes', val: shortNum(osCount(/debian/i)), trend: 'Debian K8s', color: MON.purple, data: timeline },
    { label: '☣️ 18. BYOVD Vulnerable Driver Matches', val: shortNum(summary.vulnerableDrivers || 0), trend: 'BYOVD Match', color: MON.yellow, data: timeline },
    { label: '🕵️ 19. Hidden Processes (/proc Unlinked)', val: shortNum(countMatching(/hidden process|proc unlinked/)), trend: 'Hidden Proc', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Severity Kernel Anomaly Alerts', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'active'),
      monitor: hostEvents > 0 || modules.some(item => normHost(alertHost(item)) === normHost(host)),
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen,
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
        {activeTab === 'inspector' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: 0, fontSize: 14, color: MON.cyan, fontWeight: 900 }}>💻 Active Linux Kernel Modules (.ko) & eBPF Probes</h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>Linux kernel inspection engine monitoring loaded LKMs across monitored Linux servers</div>
            </div>

            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
                    <th style={{ padding: 10 }}>Module Name</th>
                    <th style={{ padding: 10 }}>Module Path</th>
                    <th style={{ padding: 10 }}>SHA256 Hash</th>
                    <th style={{ padding: 10 }}>Signature & License</th>
                    <th style={{ padding: 10 }}>Publisher / Origin</th>
                    <th style={{ padding: 10 }}>Kernel Load Status</th>
                  </tr>
                </thead>
                <tbody>
                  {modules.map((row, idx) => {
                    const sig = reported(row.signatureStatus);
                    const vulnerable = row.vulnerableDriver === true;
                    const status = vulnerable ? 'Vulnerable' : reported(row.driverState || row.state || 'Loaded');
                    return (
                    <tr key={recordId(row) || idx} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 10, color: MON.cyan, fontWeight: 900 }}>{kernelModule(row)}</td>
                      <td style={{ padding: 10, fontFamily: 'monospace', color: MON.text }}>{kernelPath(row)}</td>
                      <td style={{ padding: 10, fontFamily: 'monospace', color: MON.sub }}>{kernelHash(row)}</td>
                      <td style={{ padding: 10, color: /unsigned|notsigned|invalid|tainted/i.test(sig) ? MON.red : vulnerable ? MON.orange : MON.green, fontWeight: 800 }}>{sig}</td>
                      <td style={{ padding: 10, color: MON.text }}>{reported(row.publisher)}</td>
                      <td style={{ padding: 10, color: vulnerable ? MON.orange : MON.cyan, fontWeight: 800 }}>{status}</td>
                    </tr>
                    );
                  })}
                  {!modules.length && <tr><td colSpan={6} style={{ padding: 22, textAlign: 'center', color: MON.muted }}>No kernel module inventory has been reported by the deployed agent.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        ) : activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={19}>
            <KernelLogMonitor alerts={alerts} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={19} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <KernelOverviewDashboard alerts={alerts} total={totalRows} data={data || {}} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Linux Kernel & eBPF Inspection Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {summary.activeAgents ?? agentStatusRows.filter(row => row.monitor).length} endpoints reporting kernel telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>eBPF Filter</span><span>Signals</span><span>Unsigned LKM</span><span>Last Scan</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.sub, textTransform: 'uppercase' }}>{row.monitor ? reported(posture.ebpf_sensor || 'Reporting') : 'Not reported'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend kernel monitoring agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Linux Syscall Execution & LKM Hook Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} kernel events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Linux Kernel Threat Categories</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Unsigned Kernel Modules (.ko)', `${summary.unsignedDrivers || 0} LKMs`, MON.red],
                    ['sys_call_table Hijacks', `${summary.syscallHooks || 0} Hooks`, MON.orange],
                    ['eBPF Tracepoint Hooks', `${countMatching(/ebpf|tracepoint|xdp/)} Programs`, MON.purple],
                    ['Vulnerable LKMs (BYOVD)', `${summary.vulnerableDrivers || 0} Modules`, MON.yellow],
                  ].map(([cat, cnt, col]) => (
                    <div key={cat} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Rootkit & Kernel Hook Integrity Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Hidden Process (DKOM)', countMatching(/hidden process|dkom/) ? `${countMatching(/hidden process|dkom/)} detected` : 'Not reported', countMatching(/hidden process|dkom/) ? MON.red : MON.sub],
                    ['Hidden LKMs (/proc/modules)', countMatching(/hidden (?:module|driver)|unlinked lkm/) ? `${countMatching(/hidden (?:module|driver)|unlinked lkm/)} detected` : 'Not reported', countMatching(/hidden (?:module|driver)|unlinked lkm/) ? MON.orange : MON.sub],
                    ['sys_call_table Tampering', summary.syscallHooks ? `${summary.syscallHooks} detected` : 'Not reported', summary.syscallHooks ? MON.red : MON.sub],
                    ['Kernel Memory Protection', reported(posture.strict_module_rwx), posture.strict_module_rwx ? MON.green : MON.sub],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`KernelLevelMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function KernelLevelMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '19';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [kernelData, setKernelData] = useState({ events: [], modules: [], systems: [], summary: {}, posture: {} });

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/kernel-monitoring/overview', { params: { limit: 1000, windowHours: 24 }, skipCache: quiet });
      const payload = r.data || {};
      const next = Array.isArray(payload.events) ? payload.events : [];
      setAlerts(next);
      setTotal(Number(payload.total || 0));
      setSystems(Array.isArray(payload.systems) ? payload.systems : []);
      setKernelData(payload);
    } catch {
      setAlerts([]);
      setTotal(0);
      setKernelData({ events: [], modules: [], systems: [], summary: {}, posture: {} });
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
    socket.on('kernel:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('kernel:event', buf.add);
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
            🖥️ 19. Kernel-Level Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <KernelLevelMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={kernelData} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <KernelLevelMonitoringPage />;
}

export function KernelLevelSocTabPage({ tab }) {
  return <KernelLevelMonitoringDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function KernelLevelSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=19" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Kernel SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=19')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="kernelmonitoring" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <KernelLevelMonitoringDashboardPanel />
        </main>
      </div>
    </div>
  );
}

export function KernelMonitoringSubTabPage() {
  return <KernelLevelSubTabPage />;
}

// ── Alias export for backward compatibility ──
export { KernelLevelMonitoringDashboardPanel as KernelLevelMonitoringDashboard };
