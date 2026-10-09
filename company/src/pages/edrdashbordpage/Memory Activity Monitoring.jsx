import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Memory Activity Monitoring — Capability ID: 5
 *
 * 100% Self-Contained Enterprise SOC Memory Activity Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=5`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process Activity Monitoring (Capability ID: 1), FIM (Capability ID: 2), Network (Capability ID: 3) & Auth (Capability ID: 4)
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
  const values = data.length ? data : [0, 0];
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

function formatBytes(bytes = 0) {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(2)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${b} B`;
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
  return row?.user || row?.username || row?.userName || row?.account || 'Not reported';
}

function alertStatus(row) {
  return row?.status || row?.processStatus || row?.state || 'Not reported';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const osStr = String(row?.osType || row?.os || row?.platform || row?.systemId?.osType || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Memory Specific Telemetry Field Extractors ─────────────────────────────
function memProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.process || row?.processName || row?.executable || row?.command ||
    raw.process || raw.processName || raw.process_name || raw.executable || 'Not reported';
}

function memPid(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.pid ?? row?.processId ?? raw.pid ?? raw.processId ?? 'Not reported';
}

function memAddress(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.memoryAddress || row?.address || raw.memoryAddress || raw.address || 'Not reported';
}

function memProtection(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.memoryProtection || row?.protection || row?.memProtection || raw.memoryProtection || raw.protection || 'Not reported';
}

function memBytes(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const bytes = row?.processRssBytes ?? row?.privateWorkingSetBytes ?? row?.workingSet ?? row?.bytes ?? raw.process_rss_bytes ?? raw.workingSet;
  if (Number.isFinite(Number(bytes))) return Number(bytes);
  const mb = row?.processMemoryMb ?? row?.memoryMb ?? raw.memory_mb;
  return Number.isFinite(Number(mb)) ? Number(mb) * 1048576 : 0;
}

function memTechnique(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.technique || row?.injectionType || row?.mitreTechnique || row?.eventType || row?.ruleId || raw.technique || raw.injectionType || 'Not reported';
}

function memEntropy(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.entropy ?? raw.entropy ?? 'Not reported';
}

function containsAny(row, words = []) {
  const haystack = [
    memProcess(row), memAddress(row), memProtection(row), memTechnique(row), alertHost(row), alertUser(row),
    row?.description, row?.message, row?.ruleName, row?.type, row?.category,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${memProcess(row)}-${memPid(row)}`;
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
export function MemoryLogDetailModal({ log, onClose, onAction }) {
  const rawEvidence = log?.rawEvent?.raw || log?.rawEvent || log?.raw || {};
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedTo?.name || log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'Not reported');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : '');
  const [notesSaved, setNotesSaved] = useState(false);
  const [noteError, setNoteError] = useState('');

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.Memory.ProcessDump');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Process Memory Dump & Volatility Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || log?.agentName || 'endpoint'} memory forensic dump hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const eventTimeline = Array.isArray(log.timeline) && log.timeline.length ? log.timeline : [{
    type: log.eventType || log.ruleId || 'Memory detection',
    time: alertTime(log), title: log.description || 'Memory telemetry event',
    desc: log.detectionReason || log.description || 'No additional timeline evidence was reported.', col: sevColor,
  }];

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Host' },
    { id: 'protection', label: '🛡️ 4. Page & Protection' },
    { id: 'injection', label: '💉 5. Injection & Lineage' },
    { id: 'creds', label: '🔑 6. LSASS & Cred Dumping' },
    { id: 'ioc', label: '🎯 7. Entropy & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Shellcode' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Process Memory Dump', desc: 'Acquire full or minidump of target process memory for Volatility analysis.', artifact: 'Windows.Memory.ProcessDump' },
    { title: 'Linux Process Memory & Pslist', desc: 'Inspect Linux process memory maps (/proc/PID/maps) and memory usage.', artifact: 'Linux.Sys.Pslist' },
    { title: 'Windows PSTree & Parent Lineage', desc: 'Dump process ancestry tree, command lines, and handle tables.', artifact: 'Windows.System.PSTree' },
    { title: 'YARA Process Memory Scan', desc: 'Run YARA rules across active process memory ranges.', artifact: 'Windows.Detection.Yara.Process' },
    { title: 'Generic YARA Glob Sweep', desc: 'Scan memory pages and temporary payloads for shellcode signatures.', artifact: 'Generic.Detection.Yara.Glob' },
    { title: 'KAPE Memory Artifact Collection', desc: 'Collect crash dumps, hibernation files, and memory metadata targets.', artifact: 'Windows.KapeFiles.Targets' },
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
    setNoteError('');
    if (!log?._id) { setNoteError('A persisted event ID is required.'); return; }
    try {
      await api.post(`/memory-activity/events/${log._id}/notes`, { text: analystNotes });
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 2000);
    } catch (error) {
      setNoteError(error.response?.data?.message || 'Note could not be saved.');
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🧠</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Memory Activity Forensic Investigation — {memProcess(log)} (PID {memPid(log)})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Address: {memAddress(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | User: <strong style={{ color: MON.text }}>{alertUser(log)}</strong> | Protection: <strong style={{ color: MON.red }}>{memProtection(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Incident Summary', log.description || log.message || 'Not reported by agent', MON.cyan],
                ['Risk Score', log.riskScore != null || log.score != null ? `${log.riskScore ?? log.score}/100` : 'Not reported', MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', alertHost(log), MON.blue],
                ['Executing Account', alertUser(log), MON.cyan],
                ['Target Process (PID)', `${memProcess(log)} (PID ${memPid(log)})`, MON.purple],
                ['Memory Protection', memProtection(log), MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 In-Memory Execution Chronology & Injection Lifecycle</div>
              {eventTimeline.map((ev, i) => (
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
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Host Endpoint Telemetry</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'Not reported'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Telemetry Source:</span> <strong style={{ color: MON.green }}>{log.source || rawEvidence.source || 'Not reported'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🖥️ System Memory Metrics</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Total Physical RAM:</span> <b>{log.memoryTotalBytes != null ? formatBytes(log.memoryTotalBytes) : 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Used RAM:</span> <b style={{ color: MON.orange }}>{log.memoryUsedBytes != null ? formatBytes(log.memoryUsedBytes) : 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Swap Usage:</span> <b>{log.swapUsedBytes != null ? formatBytes(log.swapUsedBytes) : 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PAGE & PROTECTION */}
          {activeTab === 'protection' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🛡️ RWX Memory Page & Protection Flags</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Base Address:</span> <span style={{ fontFamily: 'monospace', color: MON.cyan }}>{memAddress(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Page Protection:</span> <b style={{ color: MON.red }}>{memProtection(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Working Set Size:</span> <span style={{ color: MON.yellow }}>{formatBytes(memBytes(log))}</span></div>
                  <div><span style={{ color: MON.sub }}>Page State:</span> <b style={{ color: MON.green }}>{log.memoryPageState || rawEvidence.page_state || 'Not reported'}</b></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📊 Virtual Memory Allocation History</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.green }}>API Call Sequence:</span>
                    <div style={{ fontSize: 12, fontWeight: 800, color: MON.text, marginTop: 4 }}>{Array.isArray(log.apiCallSequence) ? log.apiCallSequence.join(' → ') : rawEvidence.api_call_sequence || 'Not reported'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.orange }}>Unsigned PE Header:</span>
                    <div style={{ fontSize: 12, fontWeight: 800, color: MON.orange, marginTop: 4 }}>{log.peHeaderStatus || rawEvidence.pe_header_status || 'Not reported'}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: INJECTION & LINEAGE */}
          {activeTab === 'injection' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>💉 Memory Injection & Process Hollowing</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Injection Technique:</span> <b style={{ color: MON.red }}>{memTechnique(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Source Process:</span> <b style={{ color: MON.cyan }}>{log.sourceProcessName || rawEvidence.source_process_name || 'Not reported'} {log.sourcePid || rawEvidence.source_pid ? `(PID ${log.sourcePid || rawEvidence.source_pid})` : ''}</b></div>
                <div><span style={{ color: MON.sub }}>Target Process:</span> <b style={{ color: MON.purple }}>{memProcess(log)} (PID {memPid(log)})</b></div>
                <div><span style={{ color: MON.sub }}>Executable Path:</span> <span style={{ fontFamily: 'monospace' }}>{log.processExe || rawEvidence.exe || 'Not reported'}</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: LSASS & CRED DUMPING */}
          {activeTab === 'creds' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🔑 Protected Process Access (lsass.exe)</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Target Process:</span> <b style={{ color: MON.red }}>{log.targetProcessName || rawEvidence.target_process_name || 'Not reported'} {log.targetPid || rawEvidence.target_pid ? `(PID ${log.targetPid || rawEvidence.target_pid})` : ''}</b></div>
                  <div><span style={{ color: MON.sub }}>Access Rights:</span> <span style={{ fontFamily: 'monospace', color: MON.yellow }}>{log.grantedAccess || rawEvidence.granted_access || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>API Trigger:</span> <b style={{ color: MON.red }}>{log.apiCall || rawEvidence.api_call || 'Not reported'}</b></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>🔒 Protected System Processes Watchlist</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span>Evidence:</span> <b style={{ color: MON.red }}>{log.description || 'Not reported'}</b></div>
                  <div><span>IOC Match:</span> <b style={{ color: log.iocMatched ? MON.red : MON.muted }}>{log.iocMatched == null ? 'Not reported' : log.iocMatched ? 'Matched' : 'No match reported'}</b></div>
                  <div><span>Call Trace:</span> <b style={{ color: MON.muted }}>{log.callTrace || rawEvidence.call_trace || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC, ENTROPY & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Mapping</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}>
                    <b style={{ color: MON.red }}>{log.mitreId || 'Not reported'}: {log.mitreTechnique || log.technique || 'No technique reported'}</b>
                  </div>
                  <div style={{ background: 'rgba(251, 146, 60, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.orange}` }}>
                    <b style={{ color: MON.orange }}>Tactic: {log.mitreTactic || 'Not reported'}</b>
                  </div>
                  <div style={{ background: 'rgba(251, 191, 36, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.yellow}` }}>
                    <b style={{ color: MON.yellow }}>Detection: {log.ruleId || log.detectionRuleId || 'Not reported'}</b>
                  </div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>📊 Shellcode Entropy & YARA Matches</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Memory Entropy Score:</b> <span style={{ color: MON.red, fontWeight: 900 }}>{memEntropy(log)}</span></div>
                  <div><b>YARA Signature:</b> <span style={{ color: MON.purple, fontFamily: 'monospace' }}>{Array.isArray(log.yaraRules) && log.yaraRules.length ? log.yaraRules.join(', ') : 'Not reported'}</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Memory Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Extracted RWX Memory Shellcode Hex Dump</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {log.memoryHexDump || rawEvidence.memory_hex_dump || 'Memory content was not collected. Only agent-reported metadata is available.'}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Memory Triage & Incident Response</h4>
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
                {noteError && <div style={{ marginTop: 8, color: MON.red, fontSize: 10 }}>{noteError}</div>}
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" disabled={!onAction || !log?._id || !Number.isFinite(Number(memPid(log)))} onClick={() => onAction?.(log._id, 'kill_process')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: onAction && log?._id ? 'pointer' : 'not-allowed', opacity: onAction && log?._id ? 1 : .55 }}>
                    ⛔ Kill Process (PID {memPid(log)})
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
function MemoryLogMonitor({ alerts = [], metrics = [], loading = false, onAction }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [techFilter, setTechFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    const records = new Map();
    [...alerts, ...metrics].forEach(row => records.set(recordId(row), row));
    return [...records.values()].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).filter(a => {
      const matchQ = !query || `${memProcess(a)} ${memAddress(a)} ${memProtection(a)} ${memTechnique(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchT = techFilter === 'all' || memTechnique(a).toLowerCase().includes(techFilter.toLowerCase());
      return matchQ && matchP && matchS && matchT;
    });
  }, [alerts, metrics, query, platform, severity, techFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Process, Address, Protection, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={platform} onChange={e => setPlatform(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All OS Platforms</option>
          <option value="win">Windows</option>
          <option value="lin">Linux</option>
          <option value="mac">macOS</option>
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={techFilter} onChange={e => setTechFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Memory Techniques</option>
          <option value="inject">Process Injection</option>
          <option value="rwx">RWX Page Creation</option>
          <option value="lsass">LSASS Dump</option>
          <option value="fileless">Fileless Malware</option>
          <option value="hook">API Hooking</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Memory Activity & Threat Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr 1.4fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Process / Host Metric</span><span>Host / OS</span><span>User</span><span>Memory / Address & Protection</span><span>Event / Technique</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr 1.4fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, display: 'block' }}>{row.memoryMetricType === 'host' ? 'Host RAM telemetry' : memProcess(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{row.memoryMetricType === 'host' ? 'Host metric' : `PID: ${memPid(row)}`}</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <div>
                  {row.memoryMetricType && <span style={{ color: MON.cyan, display: 'block' }}>{row.memoryMetricType === 'host' ? `${row.memoryUsedBytes != null ? formatBytes(row.memoryUsedBytes) : '—'} / ${row.memoryTotalBytes != null ? formatBytes(row.memoryTotalBytes) : '—'}` : formatBytes(memBytes(row))}</span>}
                  {!row.memoryMetricType && <>
                  <span style={{ color: MON.yellow, fontFamily: 'monospace', display: 'block' }}>{memAddress(row)}</span>
                  <span style={{ fontSize: 9, color: MON.red }}>{memProtection(row)}</span>
                  </>}
                </div>
                <b style={{ color: MON.purple }}>{row.memoryMetricType ? `${row.memoryMetricType} memory sample` : memTechnique(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" disabled={Boolean(row.memoryMetricType)} onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  {row.memoryMetricType ? 'Telemetry' : '🔍 Investigate'}
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading memory telemetry…' : 'No memory telemetry logs match filters. Waiting for agent data.'}</div>}
          </div>
        </div>
      </div>

      {selectedLog && <MemoryLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

function MemoryReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState('');

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
    setReportError('');
    try {
      const response = await api.get('/dashboard/capability-report/5', { params: { period: reportType, category: 'all' }, skipCache: true });
      const payload = response.data || {};
      setReportData({
        ...payload,
        alerts: Array.isArray(payload.alerts) ? payload.alerts : [],
        total: Number(payload.total || 0),
        bySev: payload.stats?.bySeverity || {},
      });
      setGenerated(true);
    } catch (error) {
      setReportData(null);
      setReportError(error.response?.data?.message || 'Memory report could not be generated.');
    } finally {
      setGenerating(false);
    }
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Process,PID,Host,User,Address,Protection,Technique,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(memProcess(a)),
      csvCell(memPid(a)),
      csvCell(alertHost(a)),
      csvCell(alertUser(a)),
      csvCell(memAddress(a)),
      csvCell(memProtection(a)),
      csvCell(memTechnique(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `memory_activity_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Memory Activity & Threat Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for memory injection, fileless malware, and credential dumping</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Memory Report'}
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

      {reportError && <div style={{ background: `${MON.red}18`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 8, padding: 12, fontSize: 11 }}>{reportError}</div>}

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Memory Threat Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Memory Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Memory Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Injections / Dumps', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk RWX Pages', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Normal Allocations', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Memory Activity Dashboard ──────────────────
function MemUsageOverTimeChart({ metrics = [] }) {
  const samples = [...metrics].filter(row => row.memoryMetricType === 'host').sort((a, b) => new Date(a.createdAt || a.timestamp || 0) - new Date(b.createdAt || b.timestamp || 0)).slice(-7);
  const times = samples.length ? samples.map(row => new Date(alertTime(row)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : Array(7).fill('—');
  const yLabels = ['100%', '75%', '50%', '25%', '0%'];
  const data = samples.length ? samples.map(row => Number(row.memoryPressure ?? row.processMemoryPercent ?? 0)) : Array(7).fill(0);

  const chartW = 320;
  const chartH = 120;
  const padLeft = 32;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = data.map((v, i) => {
    const x = padLeft + (i / Math.max(1, data.length - 1)) * innerW;
    const y = padTop + innerH - (v / 100) * innerH;
    return { x, y };
  });

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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 10, fontWeight: 800, color: '#e2e8f0' }}>MEMORY USAGE OVER TIME</span>
        <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 6px', borderRadius: 4, background: '#38bdf822', color: '#38bdf8', border: '1px solid #38bdf844' }}>{samples.length ? `${data[data.length - 1].toFixed(1)}%` : 'Not reported'}</span>
      </div>
      <div style={{ flex: 1, minHeight: 90 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={lbl}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="9" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / Math.max(1, times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="9" textAnchor="middle">{t}</text>;
          })}
          <path d={`${d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#memUsageGrad)" />
          <path d={d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          <defs>
            <linearGradient id="memUsageGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function HostMemDonut({ metrics = [] }) {
  const totalHosts = metrics.length;
  const count = predicate => metrics.filter(predicate).length;
  const hostRows = [
    ['Healthy (0 - 60%)', count(row => Number(row.memoryPressure ?? 0) < 60), '#34d399'],
    ['Warning (60 - 80%)', count(row => Number(row.memoryPressure ?? 0) >= 60 && Number(row.memoryPressure ?? 0) < 80), '#fbbf24'],
    ['High (80 - 95%)', count(row => Number(row.memoryPressure ?? 0) >= 80 && Number(row.memoryPressure ?? 0) < 95), '#fb923c'],
    ['Critical (> 95%)', count(row => Number(row.memoryPressure ?? 0) >= 95), '#f87171'],
  ];
  const hosts = hostRows.map(([label, value, color]) => ({ label, val: `${value} (${totalHosts ? ((value / totalHosts) * 100).toFixed(1) : '0.0'}%)`, color, percent: totalHosts ? (value / totalHosts) * 100 : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 55;
  const cy = 55;
  const strokeWidth = 14;

  const arcs = hosts.map((s) => {
    const angle = (s.percent / 100) * 360;
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
      <span style={{ fontSize: 10, fontWeight: 800, color: '#e2e8f0', marginBottom: 4 }}>MEMORY USAGE BY HOST</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1 }}>
        <div style={{ position: 'relative', width: 110, height: 110, flexShrink: 0 }}>
          <svg viewBox="0 0 110 110" width="110" height="110">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 14, fontWeight: 800, color: '#fff' }}>{totalHosts}</span>
            <span style={{ fontSize: 9, color: '#8ea0b8' }}>Hosts</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 10 }}>
          {hosts.map(h => (
            <div key={h.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: h.color }} /> {h.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{h.val}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function MemTimelineChart({ metrics = [] }) {
  const samples = [...metrics].filter(row => row.memoryMetricType === 'host').sort((a, b) => new Date(a.createdAt || a.timestamp || 0) - new Date(b.createdAt || b.timestamp || 0)).slice(-7);
  const times = samples.length ? samples.map(row => new Date(alertTime(row)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })) : Array(7).fill('—');
  const totalData = samples.length ? samples.map(row => Number(row.memoryTotalBytes || 0) / 1073741824) : Array(7).fill(0);
  const usedData = samples.length ? samples.map(row => Number(row.memoryUsedBytes || 0) / 1073741824) : Array(7).fill(0);
  const scaleMax = Math.max(...totalData, 1);
  const yLabels = [scaleMax, scaleMax * 0.75, scaleMax * 0.5, scaleMax * 0.25, 0].map(value => `${value.toFixed(value >= 10 ? 0 : 1)} GB`);

  const chartW = 400;
  const chartH = 140;
  const padLeft = 36;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const buildPath = (data) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / Math.max(1, data.length - 1)) * innerW,
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

  const totalRes = buildPath(totalData);
  const usedRes = buildPath(usedData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>MEMORY USAGE TIMELINE (LAST 1 HOUR)</span>
        <div style={{ display: 'flex', gap: 12, fontSize: 10 }}>
          <span style={{ color: '#22d3ee', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 8, height: 2, background: '#22d3ee' }} /> Total Memory (GB)</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 8, height: 2, background: '#a78bfa' }} /> Used Memory (GB)</span>
        </div>
      </div>
      <div style={{ flex: 1, minHeight: 110 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={lbl}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="9" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / Math.max(1, times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="9" textAnchor="middle">{t}</text>;
          })}
          <path d={`${usedRes.d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#usedGrad)" />
          <path d={totalRes.d} fill="none" stroke="#22d3ee" strokeWidth="2" />
          <path d={usedRes.d} fill="none" stroke="#a78bfa" strokeWidth="2" />
          <defs>
            <linearGradient id="usedGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#a78bfa" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#a78bfa" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
      <div style={{ display: 'flex', gap: 12, fontSize: 9, justifyContent: 'center', marginTop: 4 }}>
        <span style={{ color: '#f87171' }}>● Critical</span>
        <span style={{ color: '#fb923c' }}>● High</span>
        <span style={{ color: '#fbbf24' }}>● Medium</span>
        <span style={{ color: '#38bdf8' }}>● Low</span>
      </div>
    </div>
  );
}



function MemoryOverviewDashboard({ alerts = [], total = 0, metrics = [], summary = {}, systems = [], metricHistory = [] }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const hostMetrics = metrics.filter(row => row.memoryMetricType === 'host');
  const processMetrics = metrics.filter(row => row.memoryMetricType === 'process');
  const recentAlerts = alerts.filter(row => {
    const timestamp = new Date(alertTime(row)).getTime();
    return Number.isFinite(timestamp) && timestamp >= Date.now() - 15 * 60 * 1000;
  });
  const memoryUsagePercent = summary.memoryUsagePercent;
  const topCards = [
    {
      title: 'TOTAL MEMORY USAGE',
      val: memoryUsagePercent == null ? '—' : `${Number(memoryUsagePercent).toFixed(1)}%`,
      sub: summary.totalRamBytes ? `${formatBytes(summary.usedRamBytes)} / ${formatBytes(summary.totalRamBytes)}` : 'Not reported by agents',
      icon: '🧠',
      iconBg: 'rgba(52, 211, 153, 0.15)',
      col: '#34d399',
      hasBar: true,
    },
    {
      title: 'HIGH MEMORY PROCESSES',
      val: shortNum(processMetrics.filter(row => memBytes(row) > 524288000).length),
      sub: 'Processes using >500 MB',
      subCol: '#fbbf24',
      icon: '⚙️',
      iconBg: 'rgba(251, 191, 36, 0.15)',
      col: '#fbbf24',
    },
    {
      title: 'SUSPICIOUS EVENTS',
      val: shortNum(summary.recentEvents ?? recentAlerts.length),
      sub: 'In Last 15 Minutes',
      icon: '🛡️',
      iconBg: 'rgba(248, 113, 113, 0.15)',
      col: '#f87171',
      spark: true,
    },
    {
      title: 'CRITICAL ALERTS',
      val: shortNum(summary.critical ?? 0),
      sub: 'Requires Immediate Attention',
      subCol: '#f87171',
      icon: '⚠️',
      iconBg: 'rgba(248, 113, 113, 0.15)',
      col: '#f87171',
    },
    {
      title: 'AT RISK ENDPOINTS',
      val: shortNum(hostMetrics.filter(row => Number(row.memoryPressure ?? 0) >= 80).length),
      sub: 'High Risk',
      subCol: '#a78bfa',
      icon: '👤',
      iconBg: 'rgba(167, 139, 250, 0.15)',
      col: '#a78bfa',
    },
  ];

  const processes = [...processMetrics].sort((a, b) => memBytes(b) - memBytes(a)).slice(0, 8).map(row => {
    const pct = Number(row.processMemoryPercent ?? 0);
    return { name: memProcess(row), pid: memPid(row), user: alertUser(row), usage: formatBytes(memBytes(row)), pct: `${pct.toFixed(2)}%`, bar: Math.min(100, pct * 10), barCol: pct >= 15 ? '#f87171' : pct >= 8 ? '#fb923c' : '#38bdf8' };
  });

  const categoryDefs = [
    ['Process Injection', ['injection', 't1055'], '#f87171', '💉'], ['Remote Thread', ['remote thread'], '#f87171', '🧵'],
    ['Process Hollowing', ['hollowing'], '#fb923c', '💡'], ['LSASS Access', ['lsass'], '#fb923c', '🔑'],
    ['Memory Dump', ['memory dump', 'minidump'], '#fb923c', '📦'], ['Credential Dumping', ['credential dump', 'mimikatz'], '#fb923c', '🔐'],
    ['Fileless Malware', ['fileless', 'in-memory payload'], '#fbbf24', '🧩'], ['RWX Memory', ['rwx', 'executable memory'], '#a78bfa', '🔓'],
    ['Heap / Stack Corruption', ['heap corruption', 'stack corruption', 'stack overflow'], '#a78bfa', '💥'],
    ['API / Kernel Hooking', ['api hook', 'ssdt', 'dkom', 'rootkit'], '#22d3ee', '🪝'],
    ['DLL Anomaly', ['dll injection', 'dll sideload', 'unsigned dll'], '#38bdf8', '📜'],
    ['Entropy Anomaly', ['entropy', 'packed memory'], '#22d3ee', '🌐'],
  ];
  const categories = categoryDefs.map(([name, words, col, icon]) => ({ name, count: alerts.filter(row => containsAny(row, words)).length, col, icon }));

  const memoryAlerts = [...alerts].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 10).map(row => {
    const sev = alertSeverity(row);
    return { title: row.eventType || row.ruleId || 'Memory event', sub: row.description || `${memProcess(row)} · ${alertHost(row)}`, sev: sev.toUpperCase(), sevCol: SEV_COLOR[sev] || MON.muted, time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : 'Not reported', icon: sev === 'critical' ? '🔴' : sev === 'high' ? '⚠️' : sev === 'medium' ? '🟡' : '🟢' };
  });

  const endpoints = hostMetrics.slice(0, 10).map(row => {
    const pressure = Number(row.memoryPressure ?? 0);
    const system = systems.find(item => normHost(item.hostname || item.name) === normHost(alertHost(row))) || {};
    const risk = pressure >= 95 ? 'Critical' : pressure >= 80 ? 'High' : pressure >= 60 ? 'Medium' : 'Low';
    const riskCol = pressure >= 95 ? '#f87171' : pressure >= 80 ? '#fb923c' : pressure >= 60 ? '#fbbf24' : '#34d399';
    return { name: alertHost(row), ip: system.ipAddress || system.ip || 'Not reported', usage: formatBytes(row.memoryUsedBytes), pct: `${pressure.toFixed(1)}%`, bar: pressure, risk, riskCol };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (5 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', position: 'relative', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 28, height: 28, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: c.col, fontSize: 13 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 10, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px' }}>
                {c.title}
              </span>
            </div>

            <div style={{ fontSize: 24, fontWeight: 800, color: '#ffffff', margin: '8px 0 2px 0' }}>
              {c.val}
            </div>

            <div style={{ fontSize: 10, fontWeight: 700, color: c.subCol || '#64748b' }}>
              {c.sub}
            </div>

            {c.hasBar && (
              <div style={{ marginTop: 8, height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${Math.min(100, Math.max(0, Number(memoryUsagePercent || 0)))}%`, height: '100%', background: '#34d399', borderRadius: 2 }} />
              </div>
            )}

            {c.spark && (
              <div style={{ marginTop: 6, height: 22, width: '100%' }}>
                <MiniSparkline data={buildBuckets(recentAlerts, 7, 0.25)} color="#f87171" height={22} />
              </div>
            )}
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (4 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.1fr 0.9fr 1.2fr', gap: 12 }}>
        {/* Col 1: TOP MEMORY CONSUMING PROCESSES */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>
              TOP MEMORY CONSUMING PROCESSES
            </span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 0.9fr 1fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Process Name</span>
              <span>PID</span>
              <span>User</span>
              <span>Memory Usage</span>
              <span>%</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {processes.map(p => (
                <div key={p.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 0.9fr 1fr 1fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{p.name}</span>
                  <span style={{ color: '#64748b' }}>{p.pid}</span>
                  <span style={{ color: '#8ea0b8' }}>{p.user}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{p.usage}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ flex: 1, height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${p.bar}%`, height: '100%', background: p.barCol, borderRadius: 2 }} />
                    </div>
                    <span style={{ color: p.barCol, fontWeight: 700, fontSize: 9 }}>{p.pct}</span>
                  </div>
                </div>
              ))}
              {!processes.length && <div style={{ color: '#64748b', fontSize: 10, padding: '12px 0' }}>No process-memory metrics reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Processes →</span>
          </div>
        </div>

        {/* Col 2: Stacked (Memory Usage Over Time + Memory Usage By Host) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ ...panelStyle, flex: 1 }}>
            <MemUsageOverTimeChart metrics={metricHistory} />
          </div>
          <div style={{ ...panelStyle, flex: 1 }}>
            <HostMemDonut metrics={hostMetrics} />
          </div>
        </div>

        {/* Col 3: THREAT SUMMARY (LAST 15 MIN) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>
            THREAT SUMMARY (LAST 15 MIN)
          </span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 6 }}>
            {[
              { label: 'Process Injection', words: ['injection', 'remote thread', 'hollowing'], col: '#f87171', icon: '🔴' },
              { label: 'LSASS Access', words: ['lsass'], col: '#fb923c', icon: '🟠' },
              { label: 'Memory Dump Attempts', words: ['memory dump', 'minidump'], col: '#fbbf24', icon: '🟡' },
              { label: 'Fileless Malware', words: ['fileless', 'in-memory payload'], col: '#fbbf24', icon: '🟡' },
              { label: 'RWX Memory Regions', words: ['rwx', 'executable memory'], col: '#a78bfa', icon: '🟣' },
              { label: 'DLL Anomalies', words: ['dll injection', 'dll sideload', 'unsigned dll'], col: '#38bdf8', icon: '🔵' },
              { label: 'API Hooking', words: ['api hook', 'ssdt', 'dkom'], col: '#22d3ee', icon: '🩵' },
              { label: 'Other Anomalies', words: [], col: '#38bdf8', icon: '⚪' },
            ].map(t => ({ ...t, count: t.words.length ? recentAlerts.filter(row => containsAny(row, t.words)).length : recentAlerts.filter(row => !categoryDefs.some(([, words]) => containsAny(row, words))).length })).map(t => (
              <div key={t.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                  <span>{t.icon}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{t.label}</span>
                </div>
                <span style={{ color: t.col, fontWeight: 800 }}>{t.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Col 4: REAL-TIME MEMORY ALERTS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>REAL-TIME MEMORY ALERTS</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {memoryAlerts.map((ma, i) => (
                <div key={i} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10, padding: '4px 6px', background: '#07101b', borderRadius: 4, border: '1px solid #16273e' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                    <span style={{ fontSize: 11 }}>{ma.icon}</span>
                    <div style={{ overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis' }}>
                      <div style={{ color: '#e2e8f0', fontWeight: 700, fontSize: 10 }}>{ma.title}</div>
                      <div style={{ color: '#64748b', fontSize: 9 }}>{ma.sub}</div>
                    </div>
                  </div>
                  <div style={{ textAlign: 'right', flexShrink: 0, marginLeft: 6 }}>
                    <span style={{ fontSize: 8, fontWeight: 800, padding: '1px 5px', borderRadius: 8, background: `${ma.sevCol}22`, color: ma.sevCol, border: `1px solid ${ma.sevCol}44`, display: 'inline-block' }}>
                      {ma.sev}
                    </span>
                    <div style={{ color: '#64748b', fontSize: 8, marginTop: 2 }}>{ma.time}</div>
                  </div>
                </div>
              ))}
              {!memoryAlerts.length && <div style={{ color: '#64748b', fontSize: 10, padding: 12 }}>No memory threat alerts reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 6 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts →</span>
          </div>
        </div>
      </div>

      {/* 3. CATEGORIES GRID (MEMORY ACTIVITY MONITORING - ALL CATEGORIES) */}
      <div style={panelStyle}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>
          MEMORY ACTIVITY MONITORING — ALL CATEGORIES
        </span>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 8 }}>
          {categories.map(cat => (
            <div key={cat.name} style={{ background: '#07101b', border: `1px solid ${cat.col}33`, borderRadius: 6, padding: '8px 10px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                <span style={{ fontSize: 12 }}>{cat.icon}</span>
                <span style={{ color: '#cbd5e1', fontSize: 10, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{cat.name}</span>
              </div>
              <span style={{ fontSize: 10, fontWeight: 800, color: cat.col, background: `${cat.col}22`, padding: '1px 6px', borderRadius: 4, marginLeft: 4 }}>{cat.count}</span>
            </div>
          ))}
        </div>
      </div>

      {/* 4. BOTTOM GRID (2 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <MemTimelineChart metrics={metricHistory} />
        </div>
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>TOP ENDPOINTS BY MEMORY USAGE</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr 0.9fr 0.8fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Endpoint</span>
              <span>IP Address</span>
              <span>Memory Usage</span>
              <span>%</span>
              <span>Risk</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {endpoints.map(ep => (
                <div key={ep.name} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr 0.9fr 0.8fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ep.name}</span>
                  <span style={{ color: '#64748b', fontFamily: 'monospace', fontSize: 9 }}>{ep.ip}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{ep.usage}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ flex: 1, height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${ep.bar}%`, height: '100%', background: ep.riskCol, borderRadius: 2 }} />
                    </div>
                    <span style={{ color: ep.riskCol, fontWeight: 700, fontSize: 9 }}>{ep.pct}</span>
                  </div>
                  <span style={{ color: ep.riskCol, fontWeight: 700 }}>{ep.risk}</span>
                </div>
              ))}
              {!endpoints.length && <div style={{ color: '#64748b', fontSize: 10, padding: '12px 0' }}>No host-memory metrics reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Endpoints →</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`MemoryActivityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function MemoryActivityDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = {}, metrics = [], onAction }) {
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
  const metricRows = Array.isArray(metrics) && metrics.length ? metrics : (Array.isArray(data?.metrics) ? data.metrics : []);
  const hostMetrics = Array.isArray(data?.hostMetrics) ? data.hostMetrics : metricRows.filter(row => row.memoryMetricType === 'host');
  const processMetrics = Array.isArray(data?.processMetrics) ? data.processMetrics : metricRows.filter(row => row.memoryMetricType === 'process');
  const summary = data?.summary || {};
  const totalRows = total || recordsTotal || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const osCounts = hostMetrics.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);

  // 20 Memory Specific SOC Categories & Metrics
  const injectionCount = Number(summary.injection ?? 0);
  const lsassCount = Number(summary.credentialTheft ?? 0);
  const rwxCount = Number(summary.rwx ?? 0);
  const filelessCount = Number(summary.fileless ?? 0);
  const rootkitCount = Number(summary.rootkits ?? 0);
  const memDumpCount = Number(summary.dumps ?? 0);
  const entropyCount = Number(summary.highEntropy ?? 0);
  const dllSideloadCount = Number(summary.dllSideload ?? 0);
  const protectedProcessHits = Number(summary.protectedProcess ?? 0);
  const exploitHits = Number(summary.exploits ?? 0);
  const browserHits = Number(summary.browserMiner ?? 0);
  const cloudContainerHits = Number(summary.containerSpikes ?? 0);

  const kpis = [
    { label: '🧠 1. Total RAM Telemetry Signals', val: shortNum(metricRows.length), trend: hostMetrics.length ? `${hostMetrics.length} hosts` : 'Not reported', color: MON.blue, data: timeline },
    { label: '💉 2. Process Injection Detections', val: shortNum(injectionCount), trend: 'Hollowing', color: MON.red, data: timeline },
    { label: '🔑 3. LSASS Credential Dump Hits', val: shortNum(lsassCount), trend: 'Mimikatz', color: MON.orange, data: timeline },
    { label: '🛡️ 4. RWX Executable Memory Pages', val: shortNum(rwxCount), trend: 'PAGE_EXECUTE_READWRITE', color: MON.purple, data: timeline },
    { label: '⚡ 5. Fileless Malware Injections', val: shortNum(filelessCount), trend: 'PowerShell/WMI', color: MON.red, data: timeline },
    { label: '🪝 6. API & Kernel SSDT Hooks', val: shortNum(rootkitCount), trend: 'Inline Hook', color: MON.pink, data: timeline },
    { label: '📦 7. Memory Dump Detections', val: shortNum(memDumpCount), trend: 'MiniDump', color: MON.yellow, data: timeline },
    { label: '📊 8. High Entropy Encrypted Pages', val: shortNum(entropyCount), trend: 'Packed Shellcode', color: MON.cyan, data: timeline },
    { label: '🧩 9. Unsigned DLL Sideloading', val: shortNum(dllSideloadCount), trend: 'DLL Sideload', color: MON.yellow, data: timeline },
    { label: '🔒 10. Protected Process Accesses', val: shortNum(protectedProcessHits), trend: 'Lsass/Winlogon', color: MON.red, data: timeline },
    { label: '🧪 11. Exploit & Heap Corruption', val: shortNum(exploitHits), trend: 'ROP/Overflow', color: MON.orange, data: timeline },
    { label: '🌐 12. Crypto Miner Detections', val: shortNum(browserHits), trend: 'JS Miner', color: MON.green, data: timeline },
    { label: '☁️ 13. Cloud Container RAM Spikes', val: shortNum(cloudContainerHits), trend: 'K8s/Docker', color: MON.cyan, data: timeline },
    { label: '📈 14. Average Memory Threat Risk', val: summary.averageRisk != null ? Number(summary.averageRisk).toFixed(2) : '—', trend: summary.averageRisk != null ? 'Reported risk / 100' : 'Not reported', color: MON.green, data: timeline },
    { label: '💻 15. Windows Endpoint Memory', val: shortNum(osCounts.Windows || 0), trend: 'Windows', color: MON.cyan, data: timeline },
    { label: '🐧 16. Linux Server RAM Metrics', val: shortNum(osCounts.Linux || 0), trend: 'Linux', color: MON.orange, data: timeline },
    { label: '🖥️ 17. High RAM Abuser Processes', val: shortNum(processMetrics.filter(r => memBytes(r) > 524288000).length), trend: '>500MB RAM', color: MON.yellow, data: timeline },
    { label: '🛡️ 18. Critical Memory Threats', val: shortNum(summary.critical ?? 0), trend: 'Critical', color: MON.red, data: timeline },
    { label: '⚠️ 19. High Risk Memory Alerts', val: shortNum(summary.high ?? 0), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '✅ 20. Memory Health Status', val: summary.averageMemoryPressure == null ? '—' : summary.averageMemoryPressure >= 90 ? 'Critical' : summary.averageMemoryPressure >= 75 ? 'Warning' : 'Healthy', trend: summary.averageMemoryPressure == null ? 'Not reported' : `${summary.averageMemoryPressure}% pressure`, color: summary.averageMemoryPressure >= 90 ? MON.red : summary.averageMemoryPressure >= 75 ? MON.yellow : MON.green, data: timeline },
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
      monitor: sys.memoryMonitorEnabled,
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
        {data?.error && <div role="alert" style={{ color: MON.yellow }}>{data.error}</div>}
        {data?.generatedAt && <div style={{ color: MON.muted, fontSize: 10 }}>Updated: {new Date(data.generatedAt).toLocaleTimeString()} · Live events / 15s refresh</div>}
        {activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={5}>
            <MemoryLogMonitor alerts={alerts} metrics={metricRows} loading={loading} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={5} alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <MemoryOverviewDashboard alerts={alerts} total={totalRows} metrics={metricRows} summary={summary} systems={backendSystems} metricHistory={data?.metricHistory || []} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Infrastructure Memory Monitoring</div>
                <div style={{ fontSize: 9, color: agentStatusRows.length ? MON.green : MON.muted }}>● {agentStatusRows.length} endpoints returned by backend</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Memory Driver</span><span>Signals</span><span>Memory Alerts</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.monitor === true ? 'Enabled' : row.monitor === false ? 'Disabled' : 'Not reported'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend memory agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Memory Activity & Threat Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} memory events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Memory-Consuming Processes</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[...processMetrics].sort((a, b) => memBytes(b) - memBytes(a)).slice(0, 5).map((metric, index) => (
                    <div key={`${metric.hostname || metric.agentName}-${metric.pid}-${memProcess(metric)}`} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{memProcess(metric)}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{formatBytes(memBytes(metric))}</span>
                    </div>
                  ))}
                  {!processMetrics.length && <span style={{ color: MON.muted }}>No process-memory metrics reported.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Memory Threat Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Process Injections', injectionCount],
                    ['LSASS Credential Dumps', lsassCount],
                    ['RWX & Fileless Malware', rwxCount + filelessCount],
                    ['Kernel Hooks & Rootkits', rootkitCount],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`MemoryActivityMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function MemoryActivityMonitoringPage({ onAction }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '5';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [data, setData] = useState({ summary: {}, events: [], metrics: [], hostMetrics: [], processMetrics: [] });

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/memory-activity/dashboard', { params: { windowHours: 24, limit: 1000 }, skipCache: quiet });
      const payload = r.data || {};
      const next = Array.isArray(payload.events) ? payload.events : [];
      setAlerts(next);
      setTotal(Number(payload.summary?.total || next.length));
      setSystems(Array.isArray(payload.systems) ? payload.systems : []);
      setData(payload);
    } catch (error) {
      setAlerts([]);
      setTotal(0);
      setSystems([]);
      setData({ error: error.response?.data?.message || 'Live memory activity data load failed', summary: {}, events: [], metrics: [], hostMetrics: [], processMetrics: [] });
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
    socket.on('memory:alert', buf.add);
    socket.on('memory:metric', buf.add);
    socket.on('memory:alert-updated', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('memory:alert', buf.add);
      socket.off('memory:metric', buf.add);
      socket.off('memory:alert-updated', buf.add);
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
            🛡️ 5. Memory Activity Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <MemoryActivityDashboard alerts={alerts} loading={loading} total={total} systems={systems} data={data} metrics={data?.metrics || []} onAction={onAction} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <MemoryActivityMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function MemorySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=5" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Memory Monitoring SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=5')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="memory" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <MemoryActivityDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { MemoryActivityDashboard as MemoryActivityDashboardPanel };
