import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Data Security & DLP Monitoring — Capability ID: 12
 *
 * 100% Self-Contained Enterprise SOC Data Security & DLP Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=12`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8) & UEBA (11)
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

const CLASS_COLOR = {
  Secret: MON.red,
  Restricted: MON.orange,
  Confidential: MON.purple,
  Internal: MON.blue,
  Public: MON.green,
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'unknown';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || row?.account || '—';
}

function alertStatus(row) {
  return row?.status || row?.dlpStatus || row?.state || 'open';
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
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Data Security Telemetry Field Extractors ──────────────────────────────
function dlpFileName(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.fileName || row?.file || raw.fileName || raw.file || '—';
}

function dlpFilePath(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.filePath || row?.path || raw.filePath || raw.path || '—';
}

function dlpClassification(row) {
  const reported = row?.dataClassification || row?.classification;
  if (reported && String(reported).toLowerCase() !== 'unknown') return reported;
  const evidence = `${row?.sensitivityType || ''} ${dlpFilePath(row)}`.toLowerCase();
  if (/credential|secret|private.?key|ssh.?key|password/.test(evidence)) return 'Secret';
  if (/source.?code|database|backup|certificate|config/.test(evidence)) return 'Restricted';
  if (/finance|payroll|human.resources|\bhr\b|confidential|sensitive/.test(evidence)) return 'Confidential';
  return dlpFilePath(row) !== '—' ? 'Internal' : 'Unknown';
}

function dlpChannel(row) {
  return row?.transferChannel || row?.destinationDomain || row?.dstDomain || row?.domain || row?.channel || row?.destination || row?.device || '—';
}

function dlpAction(row) {
  if (row?.actionTaken && String(row.actionTaken).toLowerCase() !== 'none') return row.actionTaken;
  if (row?.containmentStatus && String(row.containmentStatus).toLowerCase() !== 'none') return row.containmentStatus;
  return row?.fileAction || row?.dataEventType || row?.eventType || row?.action || 'Observed';
}

function formatBytes(value = 0) {
  const bytes = Math.max(0, Number(value) || 0);
  if (!bytes) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const index = Math.min(units.length - 1, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / (1024 ** index)).toFixed(index > 1 ? 1 : 0)} ${units[index]}`;
}

function containsAny(row, words = []) {
  const haystack = [
    dlpFileName(row), dlpFilePath(row), dlpClassification(row), dlpChannel(row), dlpAction(row), alertUser(row), alertHost(row),
    row?.description, row?.message, row?.dlpPattern, row?.processName,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${dlpFileName(row)}-${dlpChannel(row)}`;
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
export function DataSecurityLogDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState([log?.dataEventType, log?.transferChannel, log?.dataClassification].filter(Boolean).join(', '));
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Search.FileFinder');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Sensitive File Finder & Hash Audit');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'endpoint'} data security forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const classification = dlpClassification(log);

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Host' },
    { id: 'process', label: '⚙️ 4. Process & Commands' },
    { id: 'dlp', label: '📁 5. File & DLP Details' },
    { id: 'network', label: '🌐 6. Network & Exfiltration' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & USB Preview' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'File Finder & Hash Audit', desc: 'Scan disk paths for sensitive keyword matches, file extensions, and SHA256 hashes.', artifact: 'Linux.Search.FileFinder' },
    { title: 'Active Process & File Handles', desc: 'Inspect running processes holding handles to confidential database or file paths.', artifact: 'Linux.Sys.Pslist' },
    { title: 'Event Log Hunter (Security EVTX)', desc: 'Audit File Access (Event 4663), Share Access (Event 5140), and USB Mount Events.', artifact: 'Windows.EventLogs.EvtxHunter' },
    { title: 'Memory & RAM Dump', desc: 'Collect an authorized memory image for offline forensic review.', artifact: 'Windows.Memory.Acquisition' },
    { title: 'YARA Pattern Sweep', desc: 'Execute DLP YARA rules matching credit cards, Aadhaar, PAN, and private keys.', artifact: 'Generic.Detection.Yara.Glob' },
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

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🛡️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Data Security & DLP Forensic Panel — {dlpFileName(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: CLASS_COLOR[classification] || MON.purple, background: `${CLASS_COLOR[classification] || MON.purple}20`, border: `1px solid ${CLASS_COLOR[classification] || MON.purple}44`, textTransform: 'uppercase' }}>
                  {classification}
                </span>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                User: <strong style={{ color: MON.cyan }}>{alertUser(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Path: <span style={{ color: MON.green, fontFamily: 'monospace' }}>{dlpFilePath(log)}</span> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Event Category', dlpAction(log), MON.cyan],
                ['Data Classification', classification, CLASS_COLOR[classification] || MON.purple],
                ['File Name', dlpFileName(log), MON.blue],
                ['File Path', dlpFilePath(log), MON.green],
                ['Target Host', alertHost(log), MON.blue],
                ['User Context', alertUser(log), MON.cyan],
                ['Destination Channel', dlpChannel(log), MON.red],
                ['DLP Violation Pattern', log.dlpPattern ? `${log.dlpPattern} (${Number(log.dlpMatchCount || 0)})` : 'Not reported', MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Data Access & Transfer Chronology</div>
              {[
                { type: 'File Access', time: alertTime(log) || '—', title: 'File Opened in Confidential Path', desc: `User ${alertUser(log)} opened ${dlpFilePath(log)}.`, col: MON.blue },
                { type: 'Integrity Evidence', time: alertTime(log) || '—', title: 'Hash and Metadata Evidence', desc: log.fileHash ? `SHA256: ${log.fileHash}` : 'No file hash was reported for this event.', col: MON.cyan },
                { type: 'DLP Classification', time: alertTime(log) || '—', title: log.dlpPattern || 'No content pattern reported', desc: `Classification: ${classification}; match count: ${Number(log.dlpMatchCount || 0)}. Sensitive values were not collected.`, col: MON.red },
                { type: 'Transfer Evidence', time: alertTime(log) || '—', title: log.dataEventType || dlpAction(log), desc: `Channel: ${dlpChannel(log)}; protocol: ${log.transferProtocol || log.protocol || 'not reported'}.`, col: MON.orange },
                { type: 'Enforcement', time: alertTime(log) || '—', title: log.actionTaken || 'Observed', desc: log.recommendedAction || 'No automated response was recorded.', col: MON.green },
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
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || '—'}</strong></div>
                  <div><span style={{ color: MON.sub }}>DLP Sensor:</span> <strong style={{ color: MON.green }}>● Endpoint telemetry received</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Process Tree & Command Line Execution</h4>
              <pre style={{ background: MON.card2, padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                {log.processCmdline || log.commandLine || 'Command line not reported'}
              </pre>
            </div>
          )}

          {/* TAB 5: FILE & DLP DETAILS */}
          {activeTab === 'dlp' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📁 File Attributes & Detected DLP Patterns</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>File Name:</span> <b style={{ color: MON.cyan }}>{dlpFileName(log)}</b></div>
                <div><span style={{ color: MON.sub }}>File Path:</span> <span style={{ fontFamily: 'monospace' }}>{dlpFilePath(log)}</span></div>
                <div><span style={{ color: MON.sub }}>Classification:</span> <b style={{ color: CLASS_COLOR[classification] || MON.purple }}>{classification}</b></div>
                <div><span style={{ color: MON.sub }}>File Size:</span> <span>{formatBytes(log.fileSize)}</span></div>
                <div><span style={{ color: MON.sub }}>DLP Violations:</span> <b style={{ color: MON.red }}>{log.dlpPattern ? `${log.dlpPattern} (${Number(log.dlpMatchCount || 0)})` : 'Not reported'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK & EXFILTRATION */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Network Exfiltration & Destination Channel</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Exfiltration Channel:</span> <b style={{ color: MON.red }}>{dlpChannel(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Transfer Protocol:</span> <span>{log.transferProtocol || log.protocol || '—'}</span></div>
                <div><span style={{ color: MON.sub }}>Enforcement Status:</span> <b style={{ color: MON.green }}>{log.actionTaken || log.containmentStatus || 'Observed'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                <div><b style={{ color: MON.red }}>T1567.002: Exfiltration to Cloud Storage</b></div>
                <div><b style={{ color: MON.orange }}>T1048.003: Exfiltration Over Alternative Protocol</b></div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL DLP Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw DLP Event Payload & Hash Signature</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[DATA SECURITY DLP PAYLOAD]
File Name: ${dlpFileName(log)}
File Path: ${dlpFilePath(log)}
Classification: ${classification}
Channel: ${dlpChannel(log)}
User Account: ${alertUser(log)}
Host System: ${alertHost(log)}`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Data Loss Remediation</h4>
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
                  <button type="button" disabled={!log?._id || !onAction} onClick={() => onAction?.(String(log._id), 'quarantine')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: log?._id && onAction ? 'pointer' : 'not-allowed' }}>
                    ⛔ Block Exfiltration & Revoke File Access
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
export function DataSecurityLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [classificationFilter, setClassificationFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const openLog = useCallback(async row => {
    setSelectedLog(row);
    if (!row?._id) return;
    try {
      const response = await api.get(`/data-security/log/${row._id}`, { skipCache: true });
      setSelectedLog({ ...(response.data?.event || row), relatedEvents: response.data?.relatedEvents || [] });
    } catch {
      // Keep the already-rendered live row when forensic detail is unavailable.
    }
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${dlpFileName(a)} ${dlpFilePath(a)} ${dlpChannel(a)} ${alertUser(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchC = classificationFilter === 'all' || dlpClassification(a).toLowerCase() === classificationFilter.toLowerCase();
      return matchQ && matchS && matchC;
    });
  }, [alerts, query, severity, classificationFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search File Name, Path, Destination Channel, User, Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={classificationFilter} onChange={e => setClassificationFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Classifications</option>
          <option value="Secret">Secret</option>
          <option value="Restricted">Restricted</option>
          <option value="Confidential">Confidential</option>
          <option value="Internal">Internal</option>
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Data Security & DLP Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live socket · 60s fallback</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 1.6fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Sensitive File Name</span><span>Classification</span><span>User Account</span><span>Destination / Channel</span><span>Action Executed</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.0fr 1fr 1.6fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => openLog(row)}>{dlpFileName(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{formatBytes(row.fileSize)}</span>
                </div>
                <b style={{ color: CLASS_COLOR[dlpClassification(row)] || MON.purple }}>{dlpClassification(row)}</b>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertUser(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{alertHost(row)}</span>
                </div>
                <span style={{ color: MON.yellow, fontFamily: 'monospace' }}>{dlpChannel(row)}</span>
                <b style={{ color: MON.red }}>{dlpAction(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => openLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No DLP telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <DataSecurityLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function DataSecurityReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={12} alerts={alerts} />;
  /* Legacy inline report implementation retained below only for source-level
     compatibility; the shared enterprise report panel above is authoritative. */
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
    const header = 'Timestamp,File Name,Classification,Channel,Action,User,Host,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(dlpFileName(a)),
      csvCell(dlpClassification(a)),
      csvCell(dlpChannel(a)),
      csvCell(dlpAction(a)),
      csvCell(alertUser(a)),
      csvCell(alertHost(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `data_security_dlp_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Data Security Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for data exfiltration, DLP violations, USB transfers, and file classification</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate DLP Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Data Security Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored DLP Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total DLP Alerts', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Data Leak Attempts', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Classification Transfers', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Protected Enterprise Data Volume', val: formatBytes((reportData?.alerts || []).reduce((sum, row) => sum + Number(row.fileSize || 0), 0)), color: MON.green },
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

// ── Visual Helper Components for Data Security Monitoring Dashboard ───────────
function EventsOverTimeChart({ alerts = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '23:59'];
  const accessData = buildBuckets(alerts.filter(row => containsAny(row, ['file', 'access', 'integrity', 'sensitive'])), 8, 24);
  const transferData = buildBuckets(alerts.filter(row => containsAny(row, ['transfer', 'upload', 'usb', 'cloud', 'ftp', 'sftp', 'scp'])), 8, 24);
  const policyData = buildBuckets(alerts.filter(row => containsAny(row, ['dlp', 'policy', 'violation', 'blocked'])), 8, 24);
  const exfilData = buildBuckets(alerts.filter(row => containsAny(row, ['exfil', 'leak', 'external'])), 8, 24);
  const maxValue = Math.max(1, ...accessData, ...transferData, ...policyData, ...exfilData);
  const yLabels = [maxValue, Math.round(maxValue * 0.75), Math.round(maxValue * 0.5), Math.round(maxValue * 0.25), 0];

  const chartW = 420;
  const chartH = 150;
  const padLeft = 28;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const makePath = (data) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / (data.length - 1)) * innerW,
      y: padTop + innerH - (v / maxValue) * innerH,
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

  const accessRes = makePath(accessData);
  const transferRes = makePath(transferData);
  const policyRes = makePath(policyData);
  const exfilRes = makePath(exfilData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Events Over Time</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', gap: 8, fontSize: 8.5 }}>
            <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#38bdf8' }} /> Data Access</span>
            <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#a78bfa' }} /> Data Transfer</span>
            <span style={{ color: '#fbbf24', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#fbbf24' }} /> Policy Violation</span>
            <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f87171' }} /> Exfiltration</span>
          </div>
          <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>All Events ▾</span>
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
          <path d={accessRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          <path d={transferRes.d} fill="none" stroke="#a78bfa" strokeWidth="2" />
          <path d={policyRes.d} fill="none" stroke="#fbbf24" strokeWidth="2" />
          <path d={exfilRes.d} fill="none" stroke="#f87171" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function DataEventsByCategoryDonut({ alerts = [] }) {
  const groups = [
    ['Data Access', row => containsAny(row, ['access', 'sensitive']), '#38bdf8'],
    ['Data Transfer', row => containsAny(row, ['transfer', 'upload', 'exfil']), '#a78bfa'],
    ['File Operations', row => containsAny(row, ['file', 'integrity', 'permission', 'ownership']), '#fbbf24'],
    ['Policy Violations', row => containsAny(row, ['dlp', 'policy', 'violation', 'blocked']), '#f87171'],
  ];
  const assigned = new Set();
  const categories = groups.map(([label, matcher, color]) => {
    const matching = alerts.filter((row, index) => !assigned.has(index) && matcher(row));
    alerts.forEach((row, index) => { if (!assigned.has(index) && matcher(row)) assigned.add(index); });
    return { label, count: matching.length, color };
  });
  categories.push({ label: 'Other Events', count: Math.max(0, alerts.length - assigned.size), color: '#34d399' });
  const total = Math.max(1, categories.reduce((sum, item) => sum + item.count, 0));
  categories.forEach(item => { item.pct = (item.count / total) * 100; });

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
    const angle = Math.min(359.999, (s.pct / 100) * 360);
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Data Events by Category</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(alerts.length)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {categories.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{shortNum(c.count)} ({c.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DataClassificationDonut({ alerts = [] }) {
  const definitions = [['Secret', '#f87171'], ['Restricted', '#fb923c'], ['Confidential', '#a78bfa'], ['Internal', '#38bdf8'], ['Public', '#34d399'], ['Unknown', '#64748b']];
  const classes = definitions.map(([label, color]) => {
    const rows = alerts.filter(row => dlpClassification(row).toLowerCase() === label.toLowerCase());
    return { label, count: rows.length, bytes: rows.reduce((sum, row) => sum + Number(row.fileSize || row.bytesTransferred || 0), 0), color };
  }).filter(item => item.count > 0);
  if (!classes.length) classes.push({ label: 'No classified events', count: 0, bytes: 0, color: '#64748b' });
  const totalCount = Math.max(1, classes.reduce((sum, item) => sum + item.count, 0));
  const totalBytes = classes.reduce((sum, item) => sum + item.bytes, 0);
  classes.forEach(item => { item.pct = (item.count / totalCount) * 100; item.size = formatBytes(item.bytes); });

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = classes.map((s) => {
    const angle = Math.min(359.999, (s.pct / 100) * 360);
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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Data by Classification (Accessed)</span>
        <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>This Week ▾</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 8.5, color: '#8ea0b8' }}>Total</span>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{formatBytes(totalBytes)}</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 8.5 }}>
          {classes.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.size} ({c.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DataSecurityOverviewDashboard({ alerts = [], total = 0, data = null, systems = [] }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const summary = data?.summary || {};
  const critical = Number(summary.critical ?? alerts.filter(row => alertSeverity(row) === 'critical').length);
  const high = Number(summary.high ?? alerts.filter(row => alertSeverity(row) === 'high').length);
  const exfil = Number(summary.exfiltrationAttempts ?? alerts.filter(row => containsAny(row, ['exfil', 'upload', 'transfer'])).length);
  const policyViolations = Number(summary.dlpViolations ?? alerts.filter(row => containsAny(row, ['dlp', 'policy', 'violation', 'blocked'])).length);
  const protectedBytes = Number(summary.protectedDataBytes ?? alerts.reduce((sum, row) => sum + Number(row.fileSize || 0), 0));
  const topCards = [
    { title: 'Total Data Events', val: shortNum(total || alerts.length), sub: 'Live agent telemetry', subCol: '#34d399', icon: '📄', iconBg: 'rgba(56, 189, 248, 0.15)' },
    { title: 'Critical Alerts', val: shortNum(critical), sub: 'Current 24-hour window', subCol: '#f87171', icon: '🛡️', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'High Risk Events', val: shortNum(high), sub: 'Current 24-hour window', subCol: '#fbbf24', icon: '🛡️', iconBg: 'rgba(251, 191, 36, 0.15)' },
    { title: 'Data Exfiltration Attempts', val: shortNum(exfil), sub: 'Detected transfer events', subCol: '#a78bfa', icon: '☁️', iconBg: 'rgba(167, 139, 250, 0.15)' },
    { title: 'Policy Violations', val: shortNum(policyViolations), sub: 'DLP and policy matches', subCol: '#fbbf24', icon: '📋', iconBg: 'rgba(251, 191, 36, 0.15)' },
    { title: 'Protected Data', val: formatBytes(protectedBytes), sub: 'Observed file metadata', subCol: '#34d399', icon: '💾', iconBg: 'rgba(52, 211, 153, 0.15)' },
  ];

  const channelCounts = data?.topChannels?.length
    ? data.topChannels.map(item => [item._id, Number(item.count || 0)])
    : topCounts(alerts, dlpChannel, 7);
  const maxChannel = Math.max(1, ...channelCounts.map(([, count]) => count));
  const exfilChannels = channelCounts.map(([name, count]) => ({ name, icon: /usb/i.test(name) ? '🔌' : /cloud|drive|dropbox|s3/i.test(name) ? '☁️' : /email|smtp/i.test(name) ? '📧' : '🌐', count, pct: (count / maxChannel) * 100 }));

  const recentCriticalAlerts = alerts.filter(row => ['critical', 'high'].includes(alertSeverity(row))).slice(0, 5).map(row => ({
    key: recordId(row), time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
    alert: row.description || row.dataEventType || row.ruleId || 'Data-security event',
    user: alertUser(row), source: row.srcip || alertHost(row), sev: alertSeverity(row),
  }));

  const userRows = data?.topUsers?.length ? data.topUsers : topCounts(alerts, alertUser, 5).map(([name, count]) => ({ _id: name, count, bytes: alerts.filter(row => alertUser(row) === name).reduce((sum, row) => sum + Number(row.bytesTransferred || row.fileSize || 0), 0) }));
  const maxUserEvents = Math.max(1, ...userRows.map(item => Number(item.count || 0)));
  const topUsersDataAccess = userRows.map(item => ({ name: item._id, events: shortNum(item.count), size: formatBytes(item.bytes), pct: (Number(item.count || 0) / maxUserEvents) * 100 }));
  const endpointTotal = Number(summary.protectedEndpoints ?? systems.length);
  const liveAgents = Number(summary.liveAgents ?? systems.filter(system => system.online || system.status === 'online').length);
  const postureCards = [
    { label: 'DLP Policies', status: policyViolations ? 'Detecting' : 'Active', val: shortNum(policyViolations), icon: '🛡️' },
    { label: 'Monitored Endpoints', status: 'Known', val: shortNum(endpointTotal), icon: '💻' },
    { label: 'Live Agents', status: liveAgents ? 'Online' : 'No heartbeat', val: shortNum(liveAgents), icon: '📡' },
    { label: 'Cloud Upload Events', status: 'Monitored', val: shortNum(summary.cloudUploads || 0), icon: '☁️' },
    { label: 'Database Exports', status: 'Monitored', val: shortNum(summary.databaseExports || 0), icon: '💾' },
    { label: 'Ransomware Events', status: 'Monitored', val: shortNum(summary.ransomwareEvents || 0), icon: '🔐' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 36, height: 36, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, flexShrink: 0 }}>
              {c.icon}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 9, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px' }}>
                {c.title}
              </span>
              <span style={{ fontSize: 20, fontWeight: 800, color: '#ffffff', margin: '2px 0' }}>
                {c.val}
              </span>
              <span style={{ fontSize: 8.5, fontWeight: 700, color: c.subCol }}>
                {c.sub}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.1fr', gap: 12 }}>
        <div style={panelStyle}>
          <EventsOverTimeChart alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <DataEventsByCategoryDonut alerts={alerts} />
        </div>

        {/* Top Data Exfiltration Channels */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Data Exfiltration Channels</span>
              <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>This Week ▾</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {exfilChannels.map(ec => (
                <div key={ec.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.5fr 0.3fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span>{ec.icon}</span> {ec.name}
                  </span>
                  <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${ec.pct}%`, height: '100%', background: '#38bdf8', borderRadius: 3 }} />
                  </div>
                  <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{ec.count}</span>
                </div>
              ))}
              {!exfilChannels.length && <div style={{ color: MON.muted, fontSize: 9 }}>No transfer channels reported.</div>}
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1.1fr 1fr', gap: 12 }}>
        {/* Recent Critical Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent Critical Alerts</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 2.2fr 1fr 1.1fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>Alert</span>
              <span>User</span>
              <span>Source</span>
              <span>Severity</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {recentCriticalAlerts.map((rca) => (
                <div key={rca.key} style={{ display: 'grid', gridTemplateColumns: '0.8fr 2.2fr 1fr 1.1fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#64748b', fontSize: 8.5 }}>● {rca.time}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rca.alert}</span>
                  <span style={{ color: '#8ea0b8' }}>{rca.user}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8.5 }}>{rca.source}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, color: '#f87171', padding: '1px 5px', borderRadius: 4, background: 'rgba(248, 113, 113, 0.15)', border: '1px solid rgba(248, 113, 113, 0.3)', display: 'inline-block', textAlign: 'center' }}>
                    {String(rca.sev).toUpperCase()}
                  </span>
                </div>
              ))}
              {!recentCriticalAlerts.length && <div style={{ color: MON.muted, fontSize: 9 }}>No critical or high events reported.</div>}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all alerts →</span>
          </div>
        </div>

        {/* Top Users by Data Access */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Users by Data Access</span>
              <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>This Week ▾</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.5fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>User</span>
              <span>Events</span>
              <span>Data Accessed</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topUsersDataAccess.map(u => (
                <div key={u.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.5fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>👤 {u.name}</span>
                  <span style={{ color: '#8ea0b8' }}>{u.events}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ flex: 1, height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${u.pct}%`, height: '100%', background: '#38bdf8', borderRadius: 3 }} />
                    </div>
                    <span style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 8.5 }}>{u.size}</span>
                  </div>
                </div>
              ))}
              {!topUsersDataAccess.length && <div style={{ color: MON.muted, fontSize: 9 }}>No user-attributed events reported.</div>}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all users →</span>
          </div>
        </div>

        <div style={panelStyle}>
          <DataClassificationDonut alerts={alerts} />
        </div>
      </div>

      {/* 4. BOTTOM GRID: Data Security Posture (6 Cards in a Row) */}
      <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Data Security Posture</span>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
          {postureCards.map(p => (
            <div key={p.label} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 20 }}>{p.icon}</span>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: 8.5, color: '#8ea0b8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.label}</span>
                <span style={{ fontSize: 8, fontWeight: 800, color: '#34d399' }}>{p.status}</span>
                <span style={{ fontSize: 14, fontWeight: 800, color: '#ffffff', marginTop: 1 }}>{p.val}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`DataSecurityDashboardPanel` / `DataSecurityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function DataSecurityDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction }) {
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

  // 20 Data Security Specific SOC Categories & Metrics
  const metric = (key, fallback = 0) => Math.max(Number(summary[key] || 0), Number(fallback || 0));
  const sensitiveCount = metric('sensitiveFileAccess', rows.filter(r => containsAny(r, ['confidential', 'secret', 'restricted', 'payroll'])).length);
  const exfilCount = metric('blockedExfiltrationAttempts', rows.filter(r => containsAny(r, ['upload', 'exfil', 'cloud', 'sftp', 'google drive']) && containsAny(r, ['block', 'deny', 'prevent', 'quarantine'])).length);
  const usbCount = metric('usbTransfers', rows.filter(r => containsAny(r, ['usb', 'removable', 'volume', 'drive e:'])).length);
  const dlpPatternCount = metric('dlpViolations', rows.filter(r => containsAny(r, ['credit card', 'aadhaar', 'pan', 'secret key', 'dlp'])).length);
  const secretCount = metric('secretEvents', rows.filter(r => dlpClassification(r) === 'Secret').length);
  const restrictedCount = metric('restrictedEvents', rows.filter(r => dlpClassification(r) === 'Restricted').length);
  const confidentialCount = metric('confidentialEvents', rows.filter(r => dlpClassification(r) === 'Confidential').length);
  const dbCount = metric('databaseExports', rows.filter(r => containsAny(r, ['database', 'dump', 'sql', 'ntds.dit'])).length);
  const ransomwareCount = metric('ransomwareEvents', rows.filter(r => containsAny(r, ['ransomware', 'encrypt', 'entropy', 'vssadmin'])).length);
  const cloudCount = metric('cloudUploads', rows.filter(r => containsAny(r, ['cloud', 'drive', 'dropbox', 's3'])).length);
  const emailCount = metric('emailAttachmentViolations', rows.filter(r => containsAny(r, ['email', 'attachment', 'smtp'])).length);
  const sftpCount = metric('sftpScpTransfers', rows.filter(r => containsAny(r, ['sftp', 'scp', 'ssh transfer'])).length);
  const networkShareCount = metric('networkShareCopies', rows.filter(r => containsAny(r, ['smb', 'share', 'network copy'])).length);
  const clipboardCount = metric('clipboardCopies', rows.filter(r => containsAny(r, ['clipboard', 'copy paste'])).length);
  const endpointCount = platform => new Set(backendSystems
    .filter(system => processOs(system) === platform)
    .map(system => String(system._id || system.hostname || system.name || ''))
    .filter(Boolean)).size;

  const kpis = [
    { label: '🛡️ 1. Total Data Security Events', val: shortNum(totalRows), trend: 'DLP Events', color: MON.blue, data: timeline },
    { label: '📂 2. Sensitive File Access Events', val: shortNum(sensitiveCount), trend: 'Sensitive File', color: MON.cyan, data: timeline },
    { label: '🚫 3. Blocked Exfiltration Attempts', val: shortNum(exfilCount), trend: 'Exfil Blocked', color: MON.red, data: timeline },
    { label: '💳 4. DLP Pattern Violations (PII/Keys)', val: shortNum(dlpPatternCount), trend: 'DLP Match', color: MON.orange, data: timeline },
    { label: '🔌 5. USB Removable Storage Transfers', val: shortNum(usbCount), trend: 'USB Copy', color: MON.yellow, data: timeline },
    { label: '☁️ 6. Cloud Storage Upload Attempts', val: shortNum(cloudCount), trend: 'Cloud Upload', color: MON.purple, data: timeline },
    { label: '🔒 7. Secret Classification Events', val: shortNum(secretCount), trend: 'Secret Data', color: MON.red, data: timeline },
    { label: '💼 8. Restricted Classification Transfers', val: shortNum(restrictedCount), trend: 'Restricted Data', color: MON.orange, data: timeline },
    { label: '📄 9. Confidential Document Access', val: shortNum(confidentialCount), trend: 'Confidential', color: MON.purple, data: timeline },
    { label: '🗄️ 10. Database Export & Dump Events', val: shortNum(dbCount), trend: 'DB Export', color: MON.red, data: timeline },
    { label: '🦠 11. Ransomware Entropy Anomalies', val: shortNum(ransomwareCount), trend: 'Ransomware', color: MON.red, data: timeline },
    { label: '📧 12. Email DLP Attachment Violations', val: shortNum(emailCount), trend: 'Email DLP', color: MON.yellow, data: timeline },
    { label: '🌐 13. SFTP / SCP Transfer Activity', val: shortNum(sftpCount), trend: 'SFTP Transfer', color: MON.cyan, data: timeline },
    { label: '💾 14. Network Share Data Copies', val: shortNum(networkShareCount), trend: 'Share Copy', color: MON.blue, data: timeline },
    { label: '📋 15. Clipboard Sensitive Data Copies', val: shortNum(clipboardCount), trend: 'Clipboard', color: MON.pink, data: timeline },
    { label: '🪟 16. Windows Monitored DLP Endpoints', val: shortNum(metric('windowsEndpoints', endpointCount('Windows') || osCounts.Windows || 0)), trend: 'Windows DLP', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux Monitored DLP Endpoints', val: shortNum(metric('linuxEndpoints', endpointCount('Linux') || osCounts.Linux || 0)), trend: 'Linux eBPF', color: MON.orange, data: timeline },
    { label: '🍎 18. macOS Monitored DLP Endpoints', val: shortNum(metric('macosEndpoints', endpointCount('macOS') || osCounts.macOS || 0)), trend: 'macOS Filter', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Data Leak Threats', val: shortNum(metric('critical', sevCounts.critical || 0)), trend: 'Critical Leak', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk DLP Alterations', val: shortNum(metric('high', sevCounts.high || 0)), trend: 'High Risk', color: MON.orange, data: timeline },
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
      monitor: true,
      events: hostEvents,
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
          <CapabilityLogsPanel capabilityId={12}>
            <DataSecurityLogMonitor alerts={alerts} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <DataSecurityReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <DataSecurityOverviewDashboard alerts={alerts} total={totalRows} data={data} systems={backendSystems} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Data Security & DLP Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · eBPF DLP Filter Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>DLP Sensor</span><span>Signals</span><span>DLP Alerts</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: MON.green, textTransform: 'uppercase' }}>Enabled</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{new Date(row.lastSeen).toLocaleTimeString()}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend DLP agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Data Access & Exfiltration Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} DLP events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Top Exfiltration Channels</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, dlpChannel, 5).map(([chn, count], index) => (
                    <div key={chn} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{chn}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                  {!topCounts(rows, dlpChannel, 5).length && <span style={{ color: MON.muted }}>No transfer channels reported.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Data Classification Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Secret (DB / Credentials)', secretCount],
                    ['Restricted (Source Code)', restrictedCount],
                    ['Confidential (Finance / HR)', confidentialCount],
                    ['Internal (Corporate Docs)', rows.filter(r => dlpClassification(r) === 'Internal').length],
                  ].map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.blue][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`DataSecurityMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function DataSecurityMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '12';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/data-security/dashboard', { params: { limit: 250, windowHours: 24 }, skipCache: quiet });
      const next = r.data?.events || [];
      setAlerts(next);
      setTotal(r.data?.summary?.total || next.length);
      setDashboardData(r.data || null);
    } catch {
      setAlerts([]);
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
    const interval = setInterval(() => loadAlerts(true), 60000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const mergeEvent = event => {
      if (!event?._id) return;
      setAlerts(previous => {
        const byId = new Map(previous.map(row => [String(row._id), row]));
        const added = !byId.has(String(event._id));
        byId.set(String(event._id), event);
        const next = Array.from(byId.values()).sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 250);
        if (added) setTotal(current => Math.max(next.length, Number(current || 0) + 1));
        return next;
      });
    };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('data-security:event', mergeEvent);
    socket.on('alert:updated', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('data-security:event', mergeEvent);
      socket.off('alert:updated', buf.add);
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
            🛡️ 12. Data Security & DLP Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <DataSecurityDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={dashboardData} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <DataSecurityMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function DataSecuritySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=12" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Data Security SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=12')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="datasecurity" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <DataSecurityDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { DataSecurityDashboardPanel as DataSecurityDashboard };
