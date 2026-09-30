/**
 * System Changes Monitoring — Capability ID: 7
 *
 * 100% Self-Contained Enterprise SOC System Changes Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=7`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process (1), FIM (2), Network (3), Auth (4), Memory (5) & Registry (6)
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
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
};

function MiniSparkline({ data = [], color = MON.cyan, height = 30 }) {
  const values = data.length > 1 ? data : [0, Number(data[0] || 0)];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values.map((val, idx) => {
    const x = (idx / (values.length - 1)) * 100;
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'unknown';
}

function alertUser(row) {
  return row?.user || row?.username || row?.userName || row?.account || 'Not reported by agent';
}

function alertStatus(row) {
  return row?.status || row?.changeStatus || row?.state || 'Changed';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('solaris') || osStr.includes('sun')) return 'Solaris';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── System Changes Telemetry Field Extractors ──────────────────────────────
function sysChangeTarget(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.systemChangeTarget || row?.system_change_target || row?.target || row?.targetFile || row?.changePath || row?.filePath || row?.path || row?.file ||
    raw.systemChangeTarget || raw.system_change_target || raw.target || raw.targetFile || raw.file_path || raw.path || 'Not reported by agent';
}

function sysChangeCategory(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.systemChangeCategory || row?.system_change_category || row?.changeCategory || row?.category || row?.type || raw.systemChangeCategory || raw.system_change_category || raw.changeCategory || raw.type || 'Unclassified';
}

function sysChangeAction(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.systemChangeType || row?.system_change_type || row?.changeType || row?.action || row?.operation || raw.systemChangeType || raw.system_change_type || raw.change_type || raw.action || raw.operation || 'Unclassified';
}

function sysChangeActor(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.process || row?.actor || row?.processName || raw.process || raw.process_name || raw.actor || 'Not attributed by agent';
}

function containsAny(row, words = []) {
  const haystack = [
    sysChangeTarget(row), sysChangeCategory(row), sysChangeAction(row), sysChangeActor(row), alertHost(row), alertUser(row),
    row?.description, row?.message, row?.ruleName, row?.type,
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
    if (key === 'unknown' || key === '—' || /^not reported/i.test(key) || key === 'Unclassified') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function recordId(row) {
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${sysChangeTarget(row)}-${sysChangeAction(row)}`;
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
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function SystemChangeLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || ''));
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.System.Services');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Services & Driver Installation Audit');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'srv-app'} system change forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Host' },
    { id: 'target', label: '🎯 4. Target & Path' },
    { id: 'services', label: '🛠️ 5. Services & Drivers' },
    { id: 'policies', label: '🛡️ 6. Policies & Audit Tampering' },
    { id: 'ioc', label: '🚨 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Raw Diff' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Services & Drivers', desc: 'Dump installed Windows services, startup types, and driver signatures.', artifact: 'Windows.System.Services' },
    { title: 'Linux Journal & Systemd Audit', desc: 'Inspect systemd service unit changes, journal logs, and init scripts.', artifact: 'Linux.Sys.Journal' },
    { title: 'Linux Crontab & Cron.d Sweep', desc: 'Audit cron jobs across /etc/crontab and user spool files.', artifact: 'Linux.Sys.Crontab' },
    { title: 'Windows Driver Signer Audit', desc: 'Scan installed kernel drivers for unsigned or vulnerable certificates.', artifact: 'Windows.System.Drivers' },
    { title: 'System File Integrity YARA Sweep', desc: 'Scan System32 /etc binaries for unauthorized modifications.', artifact: 'Generic.Detection.Yara.Glob' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setTimeout(() => {
      setLaunchingHunt(false);
      setHuntSuccessMsg('Not sent: no forensic-hunt executor is configured; no hunt or case was created.');
    }, 1200);
  };

  const handleSaveNotes = async () => {
    if (!log?._id) return;
    try {
      await api.post('/system-changes/investigate', { eventId: log._id, reason: analystNotes || 'Investigation opened from system-change detail panel' });
      setNotesSaved(true);
      setCaseStatus('investigating');
      setTimeout(() => setNotesSaved(false), 2000);
    } catch {
      setNotesSaved(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🖥️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  System Changes Forensic Investigation — {sysChangeTarget(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Action: {sysChangeAction(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Path: <strong style={{ color: MON.cyan, fontFamily: 'monospace' }}>{sysChangeTarget(log)}</strong> | Actor Process: <strong style={{ color: MON.green }}>{sysChangeActor(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              {[
                ['Incident Summary', log.description || log.message || 'Critical System File / Service / Policy Change Detected', MON.cyan],
                ['Risk Score', Number.isFinite(Number(log.riskScore ?? log.score)) ? `${Number(log.riskScore ?? log.score)}/100` : 'Not reported', MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Target Host System', alertHost(log), MON.blue],
                ['Modifying User Account', alertUser(log), MON.cyan],
                ['Actor Process / Bin', sysChangeActor(log), MON.purple],
                ['Operation Executed', sysChangeAction(log), MON.red],
              ].map(([lbl, val, col]) => (
                <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-word' }}>{val}</div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 System Change Lifecycle & Event Audit Timeline</div>
              {[
                { type: 'Process Execution', time: alertTime(log) || '—', title: 'Actor Process Initiated', desc: `Process ${sysChangeActor(log)} spawned by user ${alertUser(log)}.`, col: MON.blue },
                { type: 'Change Executed', time: alertTime(log) || '—', title: 'System Configuration Modified', desc: `Operation: ${sysChangeAction(log)} | Category: ${sysChangeCategory(log)}.`, col: MON.orange },
                { type: 'Detection', time: alertTime(log) || '—', title: log.ruleId || 'System change rule', desc: log.detectionReason || log.description || 'No detection reason reported.', col: MON.yellow },
              ].map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col, background: `${ev.col}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content' }}>{ev.type}</span>
                  <div style={{ color: MON.muted, fontWeight: 800, fontSize: 11, minWidth: 90 }}>{ev.time}</div>
                  <div style={{ width: 2, background: ev.col, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{ev.title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{ev.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: ENDPOINT & HOST */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Target Endpoint Details</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'Not reported'}</strong></div>
                  <div><span style={{ color: MON.sub }}>System Sensor:</span> <strong style={{ color: log.agentId || log.agentName ? MON.green : MON.muted }}>{log.agentId || log.agentName ? '● Reporting telemetry' : 'Not reported'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔍 Change Sensor Driver Status</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Telemetry source:</span> <b style={{ color: MON.cyan }}>{log.changeSource || log.source || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Agent version:</span> <b style={{ color: MON.text }}>{log.agentVersion || log.systemId?.agentVersion || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Last agent report:</span> <b style={{ color: MON.text }}>{alertTime(log) ? new Date(alertTime(log)).toLocaleString() : 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: TARGET & PATH */}
          {activeTab === 'target' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🎯 Target System Object & Path</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Target Path:</span> <span style={{ fontFamily: 'monospace', color: MON.cyan }}>{sysChangeTarget(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Change Category:</span> <b style={{ color: MON.green }}>{sysChangeCategory(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Action Executed:</span> <span style={{ color: MON.yellow }}>{sysChangeAction(log)}</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📊 Object Integrity Snapshot</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.muted }}>Baseline SHA256 Hash:</span>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: MON.sub, marginTop: 4 }}>{log.baselineHash || log.previousHash || 'Not reported by agent'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.red }}>Modified SHA256 Hash:</span>
                    <div style={{ fontSize: 11, fontFamily: 'monospace', color: MON.red, marginTop: 4 }}>{log.currentHash || log.fileHash || log.hash || 'Not reported by agent'}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: SERVICES & DRIVERS */}
          {activeTab === 'services' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🛠️ Windows Services, Systemd & Driver Load Audit</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Service / Unit:</span> <b style={{ color: MON.red }}>{log.serviceName || log.inventoryName || 'Not reported'}</b></div>
                <div><span style={{ color: MON.sub }}>Binary / Unit path:</span> <span style={{ fontFamily: 'monospace' }}>{log.serviceBinaryPath || sysChangeTarget(log)}</span></div>
                <div><span style={{ color: MON.sub }}>Process command:</span> <span style={{ color: MON.yellow }}>{log.processCmdline || log.commandLine || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Signature:</span> <b style={{ color: MON.text }}>{log.signatureStatus || 'Not reported'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 6: POLICIES & AUDIT TAMPERING */}
          {activeTab === 'policies' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🛡️ Security Policy & Defender Settings</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Category:</span> <b style={{ color: MON.red }}>{sysChangeCategory(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Previous state:</span> <b style={{ color: MON.orange }}>{typeof log.previousState === 'object' ? JSON.stringify(log.previousState) : (log.previousState || log.oldValue || 'Not reported')}</b></div>
                  <div><span style={{ color: MON.sub }}>New state:</span> <b style={{ color: MON.yellow }}>{typeof log.newState === 'object' ? JSON.stringify(log.newState) : (log.newState || log.newValue || 'Not reported')}</b></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔒 Log Tampering & Audit Clearing</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span>Detection rule:</span> <b style={{ color: MON.red }}>{log.ruleId || log.detectionRuleId || 'Not reported'}</b></div>
                  <div><span>Detection reason:</span> <b style={{ color: MON.orange }}>{log.detectionReason || log.description || 'Not reported'}</b></div>
                  <div><span>Baseline status:</span> <b>{log.baselineStatus || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE ATT&CK */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Mapping</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {([...(Array.isArray(log.mitreTechniques) ? log.mitreTechniques : []), log.mitreId || log.mitreTechnique].filter(Boolean)).map(technique => <div key={String(technique)} style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}><b style={{ color: MON.red }}>{typeof technique === 'object' ? JSON.stringify(technique) : technique}</b></div>)}
                  {!log.mitreId && !log.mitreTechnique && !log.mitreTechniques?.length && <span style={{ color: MON.muted }}>No MITRE technique was assigned to this event.</span>}
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>📊 Hosts File & DNS Tampering Indicators</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Changed target:</b> <span style={{ color: MON.yellow, fontFamily: 'monospace' }}>{sysChangeTarget(log)}</span></div>
                  <div><b>Network evidence:</b> <span style={{ color: MON.red, fontFamily: 'monospace' }}>{[log.srcip || log.sourceIp, log.destip || log.destinationIp].filter(Boolean).join(' → ') || 'Not reported by agent'}</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL System Changes Artifact Hunt Launcher</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                  {forensicHuntCards.map((item) => (
                    <div key={item.artifact} onClick={() => handleSelectArtifactCard(item)} style={{ background: selectedArtifact === item.artifact ? MON.card2 : MON.bg, border: `1px solid ${selectedArtifact === item.artifact ? MON.cyan : MON.border}`, borderRadius: 6, padding: 12, cursor: 'pointer' }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{item.title}</div>
                      <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>{item.desc}</div>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 11, color: MON.cyan }}>Selected VQL Artifact: <b>{selectedArtifact}</b></span>
                  <button type="button" onClick={handleLaunchHunt} disabled={launchingHunt} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: launchingHunt ? 'not-allowed' : 'pointer' }}>
                    {launchingHunt ? 'Dispatching Hunt...' : '🚀 Launch VQL Hunt'}
                  </button>
                </div>
                {huntSuccessMsg && (
                  <div style={{ marginTop: 12, padding: 10, background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11 }}>
                    {huntSuccessMsg}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 System Change Payload & Event Log Extract</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[SYSTEM CHANGE AUDIT PAYLOAD]
Target Object: ${sysChangeTarget(log)}
Category: ${sysChangeCategory(log)}
Action Executed: ${sysChangeAction(log)}
Actor Process: ${sysChangeActor(log)}
Initiating Account: ${alertUser(log)}
System Host: ${alertHost(log)}`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst System Change Triage & Rollback</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Assigned Analyst</label>
                    <input type="text" value={assignedAnalyst} onChange={e => setAssignedAnalyst(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Case Status</label>
                    <select value={caseStatus} onChange={e => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }}>
                      <option value="In Triage">In Triage</option>
                      <option value="Escalated to L3">Escalated to L3</option>
                      <option value="Contained">Contained</option>
                      <option value="False Positive">False Positive</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Incident Tags</label>
                    <input type="text" value={tags} onChange={e => setTags(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                </div>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" disabled title="No safe rollback executor is configured for this event" style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'not-allowed', opacity: 0.5 }}>
                    ⛔ Rollback Unavailable
                  </button>
                  <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    {notesSaved ? '✓ Saved!' : 'Save Triage Notes'}
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
function SystemChangeLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${sysChangeTarget(a)} ${sysChangeCategory(a)} ${sysChangeAction(a)} ${sysChangeActor(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchC = categoryFilter === 'all' || sysChangeCategory(a).toLowerCase().includes(categoryFilter.toLowerCase());
      return matchQ && matchP && matchS && matchC;
    });
  }, [alerts, query, platform, severity, categoryFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Target Path, Category, Action, Actor, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={platform} onChange={e => setPlatform(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All OS Platforms</option>
          <option value="win">Windows</option>
          <option value="lin">Linux</option>
          <option value="solaris">Solaris</option>
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Change Categories</option>
          <option value="service">Services & Tasks</option>
          <option value="file">System Files / FIM</option>
          <option value="policy">Security & Defender Policies</option>
          <option value="driver">Drivers & Kernel Modules</option>
          <option value="audit">Log Clearing / Audit Tampering</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 System Changes Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Target System Object / Path</span><span>Host / OS</span><span>User</span><span>Change Category & Action</span><span>Actor Process</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', fontFamily: 'monospace', display: 'block' }} onClick={() => setSelectedLog(row)}>{sysChangeTarget(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{sysChangeAction(row)}</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <div>
                  <span style={{ color: MON.yellow, fontWeight: 800, display: 'block' }}>{sysChangeCategory(row)}</span>
                  <span style={{ fontSize: 9, color: MON.muted }}>Action: {sysChangeAction(row)}</span>
                </div>
                <b style={{ color: MON.purple }}>{sysChangeActor(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No system change telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <SystemChangeLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

function LegacySystemChangeReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,Target Object,Category,Action,Actor Process,Host,User,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(sysChangeTarget(a)),
      csvCell(sysChangeCategory(a)),
      csvCell(sysChangeAction(a)),
      csvCell(sysChangeActor(a)),
      csvCell(alertHost(a)),
      csvCell(alertUser(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `system_changes_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 System Changes Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for critical file changes, service creation, log tampering, and policy edits</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate System Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 System Changes Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored System Changes: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total System Changes', val: reportData?.total, color: MON.cyan },
              { label: 'Critical System Drift Alerts', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Policy Modifications', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard File/Service Edits', val: reportData?.bySev?.low, color: MON.green },
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

function SystemChangeReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={7} alerts={alerts} />;
}

// ── Visual Helper Components for System Changes Dashboard ──────────────────
function ChangesOverTimeChart({ rows = [] }) {
  const times = Array.from({ length: 7 }, (_, index) => `${Math.round((index * 24) / 6)}h`);
  const total = buildBuckets(rows, 7, 24);
  const low = buildBuckets(rows.filter(row => alertSeverity(row) === 'low'), 7, 24);
  const medium = buildBuckets(rows.filter(row => alertSeverity(row) === 'medium'), 7, 24);
  const high = buildBuckets(rows.filter(row => alertSeverity(row) === 'high'), 7, 24);
  const critical = buildBuckets(rows.filter(row => alertSeverity(row) === 'critical'), 7, 24);
  const scaleMax = Math.max(...total, 1);
  const yLabels = Array.from({ length: 6 }, (_, index) => String(Math.round(scaleMax * (1 - index / 5))));

  const chartW = 420;
  const chartH = 140;
  const padLeft = 32;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const makePath = (data) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / (data.length - 1)) * innerW,
      y: padTop + innerH - (v / scaleMax) * innerH,
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
    return { d, pts };
  };

  const totalRes = makePath(total);
  const lowRes = makePath(low);
  const medRes = makePath(medium);
  const highRes = makePath(high);
  const critRes = makePath(critical);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Changes Over Time</span>
        <div style={{ display: 'flex', gap: 10, fontSize: 9 }}>
          <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f87171' }} /> Critical</span>
          <span style={{ color: '#fb923c', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fb923c' }} /> High</span>
          <span style={{ color: '#fbbf24', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fbbf24' }} /> Medium</span>
          <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399' }} /> Low</span>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#38bdf8' }} /> Total</span>
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 110 }}>
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
          <path d={`${totalRes.d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#totalGrad)" />
          <path d={totalRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          <path d={lowRes.d} fill="none" stroke="#34d399" strokeWidth="1.5" />
          <path d={medRes.d} fill="none" stroke="#fbbf24" strokeWidth="1.5" />
          <path d={highRes.d} fill="none" stroke="#fb923c" strokeWidth="1.5" />
          <path d={critRes.d} fill="none" stroke="#f87171" strokeWidth="1.5" />
          <defs>
            <linearGradient id="totalGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function ChangesByCategoryDonut({ rows = [] }) {
  const colors = ['#38bdf8', '#fb923c', '#f87171', '#22d3ee', '#a78bfa', '#ec4899', '#1e3a8a'];
  const counts = topCounts(rows, sysChangeCategory, 7);
  const denominator = Math.max(rows.length, 1);
  const cats = counts.map(([label, count], index) => ({ label, count, pct: (count / denominator) * 100, color: colors[index % colors.length] }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = cats.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Changes by Category</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(rows.length)}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 9 }}>
          {cats.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.pct.toFixed(1)}% ({c.count})</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ChangesByOsDonut({ rows = [] }) {
  const colors = ['#38bdf8', '#34d399', '#22d3ee', '#64748b'];
  const counts = topCounts(rows, processOs, 4);
  const denominator = Math.max(rows.length, 1);
  const osList = counts.map(([label, count], index) => ({ label, count, pct: (count / denominator) * 100, color: colors[index % colors.length] }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = osList.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Changes by OS</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(rows.length)}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 9 }}>
          {osList.map(o => (
            <div key={o.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: o.color }} /> {o.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{o.pct.toFixed(1)}% ({o.count})</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function ChangeSeverityDonut({ rows = [] }) {
  const counts = rows.reduce((out, row) => { const key = alertSeverity(row); out[key] = (out[key] || 0) + 1; return out; }, {});
  const denominator = Math.max(rows.length, 1);
  const sevs = [['Critical', '#f87171'], ['High', '#fb923c'], ['Medium', '#fbbf24'], ['Low', '#34d399']]
    .map(([label, color]) => ({ label, color, count: counts[label.toLowerCase()] || 0, pct: ((counts[label.toLowerCase()] || 0) / denominator) * 100 }));

  let cumAngle = 0;
  const radius = 38;
  const cx = 48;
  const cy = 48;
  const strokeWidth = 12;

  const arcs = sevs.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Change Severity Distribution</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
        <div style={{ position: 'relative', width: 96, height: 96, flexShrink: 0 }}>
          <svg viewBox="0 0 96 96" width="96" height="96">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(rows.length)}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 9 }}>
          {sevs.map(s => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color }} /> {s.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{s.count} ({s.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function HeatmapTimeOfDay({ rows = [] }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
  const cells = Array.from({ length: 7 }, () => Array(24).fill(0));
  rows.forEach(row => { const date = new Date(alertTime(row)); if (!Number.isNaN(date.getTime())) cells[(date.getDay() + 6) % 7][date.getHours()] += 1; });
  const maximum = Math.max(...cells.flat(), 1);
  const getCellColor = (dayIdx, hour) => {
    const ratio = cells[dayIdx][hour] / maximum;
    if (!ratio) return 'rgba(15, 35, 58, 0.4)';
    if (ratio >= 0.75) return '#ef4444';
    if (ratio >= 0.45) return '#f97316';
    return `rgba(56, 189, 248, ${Math.max(0.25, ratio).toFixed(2)})`;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Changes by Time of Day</span>
      <div style={{ display: 'flex', gap: 6, flex: 1 }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-around', fontSize: 8, color: '#64748b', fontWeight: 700, width: 22 }}>
          {days.map(d => <span key={d}>{d}</span>)}
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: '#64748b', marginBottom: 2 }}>
            {times.map(t => <span key={t}>{t}</span>)}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
            {days.map((d, dIdx) => (
              <div key={d} style={{ display: 'grid', gridTemplateColumns: 'repeat(24, 1fr)', gap: 2, flex: 1 }}>
                {Array.from({ length: 24 }).map((_, hIdx) => (
                  <div key={hIdx} title={`${cells[dIdx][hIdx]} changes`} style={{ background: getCellColor(dIdx, hIdx), borderRadius: 1 }} />
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4, fontSize: 8, color: '#64748b' }}>
        <span>Low</span>
        <div style={{ height: 4, width: 80, background: 'linear-gradient(90deg, rgba(15,35,58,1), #38bdf8, #f97316, #ef4444)', borderRadius: 2 }} />
        <span>High</span>
      </div>
    </div>
  );
}

function SystemChangeOverviewDashboard({ alerts = [], total = 0, summary = {} }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const severityCounts = rows.reduce((out, row) => { const key = alertSeverity(row); out[key] = (out[key] || 0) + 1; return out; }, {});
  const affectedCount = new Set(rows.map(alertHost).filter(value => value && value !== 'unknown')).size;
  const topCards = [
    { title: 'TOTAL CHANGES', val: shortNum(total || rows.length), sub: 'Live agent telemetry · 24h', subCol: '#38bdf8', icon: '🔀', iconBg: 'rgba(56, 189, 248, 0.15)', col: '#38bdf8' },
    { title: 'CRITICAL CHANGES', val: shortNum(summary.critical ?? severityCounts.critical), sub: 'Live agent telemetry · 24h', subCol: '#f87171', icon: '🛑', iconBg: 'rgba(248, 113, 113, 0.15)', col: '#f87171' },
    { title: 'HIGH CHANGES', val: shortNum(summary.high ?? severityCounts.high), sub: 'Live agent telemetry · 24h', subCol: '#fb923c', icon: '⚠️', iconBg: 'rgba(251, 146, 60, 0.15)', col: '#fb923c' },
    { title: 'MEDIUM CHANGES', val: shortNum(summary.medium ?? severityCounts.medium), sub: 'Live agent telemetry · 24h', subCol: '#fbbf24', icon: '🛡️', iconBg: 'rgba(251, 191, 36, 0.15)', col: '#fbbf24' },
    { title: 'LOW CHANGES', val: shortNum(summary.low ?? severityCounts.low), sub: 'Live agent telemetry · 24h', subCol: '#34d399', icon: '✅', iconBg: 'rgba(52, 211, 153, 0.15)', col: '#34d399' },
    { title: 'AFFECTED SYSTEMS', val: shortNum(summary.affectedSystems ?? affectedCount), sub: 'Endpoints with reported change', subCol: '#a78bfa', icon: '💻', iconBg: 'rgba(167, 139, 250, 0.15)', col: '#a78bfa' },
  ];

  const recentCritical = rows.filter(row => ['critical', 'high'].includes(alertSeverity(row))).slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—', system: alertHost(row), user: alertUser(row),
    type: sysChangeAction(row), details: row.description || sysChangeTarget(row), sev: alertSeverity(row).toUpperCase(),
  }));
  const affectedSystems = topCounts(rows, alertHost, 5).map(([name, changes]) => {
    const match = rows.find(row => alertHost(row) === name);
    return { name, os: processOs(match), changes };
  });
  const typeCounts = topCounts(rows, sysChangeAction, 10);
  const maxType = Math.max(...typeCounts.map(([, value]) => value), 1);
  const changeTypes = typeCounts.map(([label, val]) => ({ label, val, pct: Math.round((val / maxType) * 100) }));
  const sourceCounts = topCounts(rows, row => row.changeSource || row.source || row.rawEvent?.change_source || 'Not reported', 4);
  const changeSources = sourceCounts.map(([label, count], index) => ({ label, val: `${count} (${rows.length ? ((count / rows.length) * 100).toFixed(1) : 0}%)`, pct: rows.length ? (count / rows.length) * 100 : 0, icon: ['🖥️', '🌐', '⚙️', '📦'][index], col: ['#38bdf8', '#22d3ee', '#fbbf24', '#a78bfa'][index] }));
  const alertsSummary = [
    { label: 'Critical Alerts', count: severityCounts.critical || 0, col: '#f87171', icon: '🛑' },
    { label: 'High Alerts', count: severityCounts.high || 0, col: '#fb923c', icon: '⚠️' },
    { label: 'Medium Alerts', count: severityCounts.medium || 0, col: '#fbbf24', icon: '🛡️' },
    { label: 'Low Alerts', count: severityCounts.low || 0, col: '#34d399', icon: '✅' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{ fontSize: 10, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px' }}>
                {c.title}
              </span>
              <div style={{ width: 26, height: 26, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 12 }}>
                {c.icon}
              </div>
            </div>

            <div style={{ fontSize: 24, fontWeight: 800, color: '#ffffff', margin: '8px 0 2px 0' }}>
              {c.val}
            </div>

            <div style={{ fontSize: 10, fontWeight: 700, color: c.subCol || '#64748b' }}>
              {c.sub}
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <ChangesOverTimeChart rows={rows} />
        </div>
        <div style={panelStyle}>
          <ChangesByCategoryDonut rows={rows} />
        </div>
        <div style={panelStyle}>
          <ChangesByOsDonut rows={rows} />
        </div>
      </div>

      {/* 3. MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.1fr', gap: 12 }}>
        {/* Panel 1: Recent Critical Changes */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent Critical Changes</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.9fr 0.9fr 1fr 1.4fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>TIME</span>
              <span>SYSTEM</span>
              <span>USER</span>
              <span>CHANGE TYPE</span>
              <span>DETAILS</span>
              <span>SEVERITY</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {recentCritical.map((rc, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1fr 0.9fr 0.9fr 1fr 1.4fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#64748b', fontSize: 9 }}>{rc.time}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{rc.system}</span>
                  <span style={{ color: '#8ea0b8' }}>{rc.user}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{rc.type}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rc.details}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, padding: '1px 5px', borderRadius: 8, background: 'rgba(248, 113, 113, 0.15)', color: '#f87171', border: '1px solid rgba(248, 113, 113, 0.3)', display: 'inline-block', textAlign: 'center' }}>
                    {rc.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Panel 2: Top Affected Systems */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Affected Systems</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.3fr 0.7fr 0.9fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>SYSTEM</span>
              <span>OS</span>
              <span>CHANGES</span>
              <span>TREND (24H)</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {affectedSystems.map((sys) => (
                <div key={sys.name} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.3fr 0.7fr 0.9fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{sys.name}</span>
                  <span style={{ color: '#8ea0b8', fontSize: 9 }}>{sys.os}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{sys.changes}</span>
                  <div style={{ height: 16, width: '100%' }}>
                    <MiniSparkline data={[10, 18, 14, 25, 20, 38, 48]} color="#f87171" height={16} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Panel 3: Change Types (Top 10) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>
            Change Types (Top 10)
          </span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {changeTypes.map(ct => (
              <div key={ct.label} style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr 0.5fr', gap: 6, alignItems: 'center', fontSize: 9 }}>
                <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ct.label}</span>
                <div style={{ height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${ct.pct}%`, height: '100%', background: '#38bdf8', borderRadius: 3 }} />
                </div>
                <span style={{ color: '#8ea0b8', fontWeight: 700, textAlign: 'right' }}>{ct.val}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. BOTTOM SECTION (4 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr 1fr 0.9fr', gap: 12 }}>
        <div style={panelStyle}>
          <ChangeSeverityDonut rows={rows} />
        </div>

        <div style={panelStyle}>
          <HeatmapTimeOfDay rows={rows} />
        </div>

        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>
            Change Sources
          </span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
            {changeSources.map(cs => (
              <div key={cs.label} style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span>{cs.icon}</span> {cs.label}
                  </span>
                  <span style={{ color: '#8ea0b8', fontWeight: 700, fontSize: 9 }}>{cs.val}</span>
                </div>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${cs.pct}%`, height: '100%', background: cs.col, borderRadius: 3 }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Alerts Summary</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {alertsSummary.map(as => (
                <div key={as.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10, padding: '4px 6px', background: '#07101b', borderRadius: 4, border: '1px solid #16273e' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{as.icon}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{as.label}</span>
                  </div>
                  <span style={{ color: as.col, fontWeight: 800 }}>{as.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`SystemChangesDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function SystemChangesDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction }) {
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
  const loadedSevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const sevCounts = {
    ...loadedSevCounts,
    ...(data?.summary ? {
      critical: Number(data.summary.critical || 0), high: Number(data.summary.high || 0),
      medium: Number(data.summary.medium || 0), low: Number(data.summary.low || 0),
    } : {}),
  };
  const osCounts = rows.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);

  // 20 System Changes Specific SOC Categories & Metrics
  const criticalFileCount = rows.filter(r => containsAny(r, ['system32', '/etc/passwd', '/etc/shadow', '/etc/sudoers', 'hosts', 'dll', 'exe'])).length;
  const serviceCount = rows.filter(r => containsAny(r, ['service', 'systemd', 'smf', 'svcs'])).length;
  const taskCount = rows.filter(r => containsAny(r, ['scheduled task', 'schtasks', 'cron', 'crontab'])).length;
  const startupCount = rows.filter(r => containsAny(r, ['startup', 'run', 'runonce', 'init.d'])).length;
  const securityPolicyCount = rows.filter(r => containsAny(r, ['group policy', 'security policy', 'uac', 'audit policy'])).length;
  const defenderFirewallCount = rows.filter(r => containsAny(r, ['defender', 'firewall', 'iptables', 'ufw', 'firewalld'])).length;
  const driverKernelCount = rows.filter(r => containsAny(r, ['driver', 'kernel module', 'insmod', 'rmmod', 'sysctl', 'grub'])).length;
  const softwarePatchCount = rows.filter(r => containsAny(r, ['install', 'uninstall', 'patch', 'apt', 'yum', 'dpkg', 'rpm'])).length;
  const logTamperCount = rows.filter(r => containsAny(r, ['cleared', 'log deletion', 'event log', 'auditd stopped'])).length;
  const rdpCount = rows.filter(r => containsAny(r, ['rdp', 'fdenytsconnections', 'sshd_config'])).length;
  const usbMountCount = rows.filter(r => containsAny(r, ['usb', 'mount', 'unmount', 'device insertion'])).length;
  const containerK8sCount = rows.filter(r => containsAny(r, ['docker', 'container', 'k8s', 'kubernetes', 'pod'])).length;

  const kpis = [
    { label: '🖥️ 1. Total System Change Signals', val: shortNum(totalRows), trend: 'System Changes', color: MON.blue, data: timeline },
    { label: '📂 2. Critical System File Changes (FIM)', val: shortNum(criticalFileCount), trend: 'System32/etc', color: MON.red, data: timeline },
    { label: '🛠️ 3. Windows & Systemd Service Changes', val: shortNum(serviceCount), trend: 'Service Mod', color: MON.purple, data: timeline },
    { label: '⏱️ 4. Scheduled Tasks & Cron Job Edits', val: shortNum(taskCount), trend: 'Task/Cron', color: MON.yellow, data: timeline },
    { label: '🚀 5. Startup Folder & Autostart Changes', val: shortNum(startupCount), trend: 'Startup Mod', color: MON.orange, data: timeline },
    { label: '👑 6. Sudoers & Local Privilege Changes', val: shortNum(rows.filter(r => containsAny(r, ['sudoers', 'admin', 'privilege'])).length), trend: 'Privilege Mod', color: MON.red, data: timeline },
    { label: '🛡️ 7. Group & Local Policy Modifications', val: shortNum(securityPolicyCount), trend: 'GPO Modified', color: MON.yellow, data: timeline },
    { label: '🔥 8. Defender & Firewall Settings Edits', val: shortNum(defenderFirewallCount), trend: 'Security Edit', color: MON.orange, data: timeline },
    { label: '🧩 9. Driver & Kernel Module Loading', val: shortNum(driverKernelCount), trend: 'Kernel Driver', color: MON.pink, data: timeline },
    { label: '📦 10. Software Install / Patch Updates', val: shortNum(softwarePatchCount), trend: 'Software Patch', color: MON.green, data: timeline },
    { label: '🚫 11. Event Logs Cleared / Log Tampering', val: shortNum(logTamperCount), trend: 'Log Cleared', color: MON.red, data: timeline },
    { label: '🌐 12. Hosts File & Network Config Edits', val: shortNum(rows.filter(r => containsAny(r, ['hosts', 'resolv.conf', 'dns'])).length), trend: 'Hosts Tamper', color: MON.cyan, data: timeline },
    { label: '🔒 13. RDP & SSH Remote Access Changes', val: shortNum(rdpCount), trend: 'Remote Access', color: MON.blue, data: timeline },
    { label: '🔌 14. USB & Storage Device Activity', val: shortNum(usbMountCount), trend: 'USB Mount', color: MON.yellow, data: timeline },
    { label: '☁️ 15. Docker & Kubernetes Pod Configs', val: shortNum(containerK8sCount), trend: 'K8s/Docker', color: MON.cyan, data: timeline },
    { label: '🪟 16. Windows System Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows FIM', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux System Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux Auditd', color: MON.orange, data: timeline },
    { label: '☀️ 18. Solaris / Unix System Endpoints', val: shortNum(osCounts.Solaris || 0), trend: 'Solaris SMF', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical System Drift Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Drift', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk System Alterations', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    const lastSeen = sys.lastSeen ? new Date(sys.lastSeen) : null;
    const reporting = Boolean(sys.agentOk || sys.isOnline || sys.online || ['online', 'active', 'reporting'].includes(String(sys.status || '').toLowerCase()) || (lastSeen && Date.now() - lastSeen.getTime() < 5 * 60 * 1000));
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (reporting ? 'reporting' : 'offline'),
      monitor: reporting,
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
          <SystemChangeLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <SystemChangeReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <SystemChangeOverviewDashboard alerts={alerts} total={totalRows} summary={data?.summary || {}} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based System Changes Audit Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(row => row.monitor).length} endpoints reporting real telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>FIM/Audit Sensor</span><span>Signals</span><span>System Alerts</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.monitor ? 'Reporting' : 'Not reporting'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'No heartbeat'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend system change agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 System Change Activity Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} system events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🎯 Top Modified System Objects</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, sysChangeTarget, 5).map(([target, count], index) => (
                    <div key={target} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{target}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                  {!topCounts(rows, sysChangeTarget, 5).length && <span style={{ color: MON.muted }}>No target objects reported by agents.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 System Change Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Critical System Files', criticalFileCount],
                    ['Services & Scheduled Tasks', serviceCount + taskCount],
                    ['Security Policies & Defender', securityPolicyCount + defenderFirewallCount],
                    ['Log Tampering & Cleared Logs', logTamperCount],
                  ].map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.cyan, MON.blue, MON.purple, MON.red][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`SystemChangesMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function SystemChangesMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '7';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ windowHours: 24, limit: 250 });
      const r = await api.get(`/system-changes/summary?${q}`, { skipCache: quiet });
      const next = r.data?.events || [];
      setAlerts(next);
      setTotal(r.data?.summary?.total || r.data?.total || next.length);
      setDashboardData(r.data || null);
      if (Array.isArray(r.data?.systems)) setSystems(r.data.systems);
    } catch {
      setAlerts([]);
      setTotal(0);
      setDashboardData(null);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [capabilityId]);

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
    socket.on('system-change:event', buf.add);
    socket.on('system-change:updated', buf.add);
    socket.on('system-change:baseline-changed', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('system-change:event', buf.add);
      socket.off('system-change:updated', buf.add);
      socket.off('system-change:baseline-changed', buf.add);
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
            🛡️ 7. System Changes Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <SystemChangesDashboard alerts={alerts} loading={loading} total={total} systems={systems} data={dashboardData} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <SystemChangesMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function SystemChangesSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=7" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>System Changes SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=7')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="system" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <SystemChangesDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { SystemChangesDashboard as SystemChangesDashboardPanel };
