/**
 * File Activity Monitoring (FIM) — Capability ID: 2
 *
 * 100% Self-Contained Enterprise SOC File Integrity Monitoring (FIM) Module
 * Linked to Live Backend API (`/api/dashboard/alerts/file?capabilityId=2`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process Activity Monitoring (Capability ID: 1)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
import { useAuth } from '../../context/AuthContext';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens (Mirroring Capability #1 Process Activity & #10 USB) ──
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
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt || raw.timestamp || raw.time;
}

function alertHost(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || raw.hostname || raw.host || raw.agent_name || 'unknown';
}

function alertUser(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.user || row?.username || row?.userName || row?.changedBy || row?.actor || row?.account || raw.user || raw.username || raw.actor || 'unknown';
}

function alertStatus(row) {
  return row?.status || row?.processStatus || row?.state || 'open';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.systemId?.osType || row?.system || raw.os || raw.platform || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  if (osStr.includes('linux') || osStr.includes('ubuntu') || osStr.includes('debian') || osStr.includes('rhel')) return 'Linux';
  return 'Unknown';
}

// ── FIM Specific Telemetry Field Extractors ──────────────────────────────────
function fimPath(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.filePath || row?.file_path || row?.source || row?.path || row?.fileName || row?.file_name ||
    raw.filePath || raw.file_path || raw.path || raw.file_name || raw.source || '—';
}

function fimAction(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const act = row?.fileAction || row?.file_action || row?.action || row?.operation || row?.event_action ||
    raw.fileAction || raw.file_action || raw.action || raw.operation || '';
  if (act) return String(act);

  const text = `${row?.ruleId || ''} ${row?.type || ''} ${row?.description || ''} ${row?.message || ''}`.toLowerCase();
  if (/renam|moved/.test(text)) return 'Renamed';
  if (/creat|new file/.test(text)) return 'Created';
  if (/delet|remove|unlink/.test(text)) return 'Deleted';
  if (/perm|chmod|mode/.test(text)) return 'Permission Changed';
  if (/owner|chown|group/.test(text)) return 'Ownership Changed';
  if (/encrypt|ransom/.test(text)) return 'Encrypted';
  return 'Modified';
}

function fimProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const proc = row?.process || row?.processName || row?.process_name || row?.executable || row?.command ||
    raw.process || raw.processName || raw.process_name || raw.executable || raw.command || '';
  if (proc) return String(proc);
  const path = fimPath(row).toLowerCase();
  if (path.includes('nginx')) return 'nginx';
  if (path.includes('apache')) return 'apache2';
  if (path.includes('mysql') || path.includes('postgres')) return 'mysqld';
  if (path.includes('etc/passwd') || path.includes('shadow')) return 'useradd';
  if (path.includes('auth.log')) return 'sshd';
  return 'auditd';
}

function fimHashOld(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.old_hash || row?.oldHash || row?.baseline_hash || raw.old_hash || raw.oldHash || '-';
}

function fimHashNew(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.new_hash || row?.newHash || row?.sha256 || row?.hash || raw.new_hash || raw.sha256 || raw.hash || '-';
}

function fimPermOld(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.old_permission || row?.oldPermission || raw.old_permission || raw.oldPermission || '-';
}

function fimPermNew(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.new_permission || row?.newPermission || raw.new_permission || raw.newPermission || '-';
}

function fimOwnerOld(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.old_owner || row?.oldOwner || raw.old_owner || raw.oldOwner || '-';
}

function fimOwnerNew(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.new_owner || row?.newOwner || raw.new_owner || raw.newOwner || '-';
}

function containsAny(row, words = []) {
  const haystack = [
    fimPath(row), fimAction(row), fimProcess(row), alertUser(row), alertHost(row),
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${fimPath(row)}-${row?.pid || ''}`;
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
export function FileLogDetailModal({ log, onClose, onSaved }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || log?.notes?.at?.(-1)?.text || '');
  const [assignedAnalyst] = useState(log?.assignedTo?.name || log?.assignedTo?.email || log?.assignedAnalyst?.name || log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || ''));
  const [notesSaved, setNotesSaved] = useState(false);
  const [savingNotes, setSavingNotes] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Search.FileFinder');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux File System Search & Hash');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'srv-web'} file forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);
  const [huntResults, setHuntResults] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const raw = log?.rawEvent?.raw || log?.rawEvent || log?.raw || {};
  const eventTimeline = (Array.isArray(raw.timeline) ? raw.timeline : Array.isArray(log.timeline) ? log.timeline : []).map((event, index) => ({
    type: event.type || event.action || `Event ${index + 1}`,
    time: event.timestamp || event.time || alertTime(log) || '—',
    title: event.title || event.description || event.message || fimAction(log),
    desc: event.details || event.description || event.message || fimPath(log),
    col: SEV_COLOR[String(event.severity || sev).toLowerCase()] || MON.blue,
  }));
  if (!eventTimeline.length) eventTimeline.push({
    type: fimAction(log),
    time: alertTime(log) || '—',
    title: log.description || log.message || log.ruleName || log.ruleId || 'FIM event',
    desc: `${fimPath(log)} · ${fimProcess(log)} · ${alertUser(log)}`,
    col: sevColor,
  });
  const mitreIds = [...new Set([
    log.mitreId, log.mitreTechnique, raw.mitre_id, raw.mitreId, raw.technique,
    ...(Array.isArray(log.mitreTechniques) ? log.mitreTechniques : []),
    ...(Array.isArray(raw.mitre_techniques) ? raw.mitre_techniques : []),
  ].filter(Boolean).map(String))];
  const yaraMatches = [...new Set([
    ...(Array.isArray(log.yaraRules) ? log.yaraRules : []),
    ...(Array.isArray(raw.yara_rules) ? raw.yara_rules : []),
    raw.yara_match,
  ].filter(Boolean).map(String))];
  const evidenceText = log.fileDiff || log.diff || raw.file_diff || raw.diff || raw.content_diff || '';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint' },
    { id: 'file', label: '📁 4. File & Lineage' },
    { id: 'permissions', label: '🔐 5. Permissions & Owner' },
    { id: 'config', label: '⚙️ 6. Config & System' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Hashes' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Linux File System Search & Hash', desc: 'Scan directory tree, hash MD5/SHA256, and detect recent modifications.', artifact: 'Linux.Search.FileFinder' },
    { title: 'Windows File Finder & Hash', desc: 'Find suspicious executables, scripts, and calculate SHA256 hashes.', artifact: 'Windows.Search.FileFinder' },
    { title: 'Linux Log Hunter', desc: 'Search auth.log, syslog, and service logs for file access events.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'Windows Prefetch Forensics', desc: 'Analyze prefetch execution evidence linked to modified file.', artifact: 'Windows.Forensics.Prefetch' },
    { title: 'YARA File Sweep', desc: 'Run IOC & ransomware YARA sweeps across file paths.', artifact: 'Generic.Detection.Yara.Glob' },
    { title: 'KAPE Triage Collection', desc: 'Extract critical registry, event logs, and file metadata targets.', artifact: 'Windows.KapeFiles.Targets' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setHuntResults(null);
    setTimeout(() => {
      setLaunchingHunt(false);
      setHuntSuccessMsg('Not sent: no forensic-hunt executor is configured; no hunt results were fabricated.');
    }, 1000);
  };

  const handleSaveNotes = async () => {
    if (!log?._id) {
      setNotesSaved('This telemetry row has no persistent alert ID.');
      return;
    }
    setSavingNotes(true);
    setNotesSaved(false);
    try {
      const requests = [api.patch(`/dashboard/alerts/${log._id}/action`, { action: 'set_status', status: caseStatus })];
      if (analystNotes.trim()) requests.push(api.post(`/alerts/${log._id}/notes`, { text: analystNotes.trim() }));
      await Promise.all(requests);
      setNotesSaved('Saved to the live alert record.');
      onSaved?.();
    } catch (error) {
      setNotesSaved(error.response?.data?.message || 'Unable to save this alert update.');
    } finally {
      setSavingNotes(false);
    }
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
                  FIM Forensic Investigation — {fimPath(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Action: {fimAction(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Actor: <strong style={{ color: MON.text }}>{alertUser(log)}</strong> | Process: <strong style={{ color: MON.cyan }}>{fimProcess(log)}</strong> | Event Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Incident Summary', log.description || log.message || log.ruleName || log.ruleId || 'FIM event', MON.cyan],
                ['Risk Score', log.riskScore !== undefined || log.score !== undefined ? `${log.riskScore ?? log.score}/100` : 'Not reported', MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', alertHost(log), MON.blue],
                ['User / Actor', alertUser(log), MON.cyan],
                ['Modifying Process', fimProcess(log), MON.purple],
                ['Target File Location', fimPath(log), MON.text],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 File Activity Event Chronology & Modification Flow</div>
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

          {/* TAB 3: ENDPOINT */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Endpoint System Details</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || log.systemId?._id || 'Not reported'}</strong></div>
                  <div><span style={{ color: MON.sub }}>FIM Driver:</span> <strong style={{ color: MON.green }}>{raw.fim_driver || raw.monitor_driver || raw.collector || log.source || 'Not reported'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🛡️ Monitored Platform Type</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Category:</span> <b>{log.category || log.eventCategory || raw.category || 'File integrity'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Policy Profile:</span> <span style={{ color: MON.yellow }}>{log.policyName || raw.policy_name || raw.policy || 'Not reported'}</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Collector Status:</span> <b>{raw.collector_status || raw.driver_status || 'Telemetry received'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: FILE & LINEAGE */}
          {activeTab === 'file' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📁 File Attributes & Path Information</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Full Path:</span> <span style={{ fontFamily: 'monospace', color: MON.text }}>{fimPath(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>File Action:</span> <b style={{ color: MON.orange }}>{fimAction(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Triggering Process:</span> <b style={{ color: MON.cyan }}>{fimProcess(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Process PID:</span> <span style={{ fontFamily: 'monospace', color: MON.yellow }}>{log.pid || raw.pid || 'Not reported'}</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>#️⃣ SHA256 Before vs After Hash Comparison</h4>
                <div style={{ fontFamily: 'monospace', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 10 }}>
                  <div style={{ background: MON.card2, padding: 10, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.green }}>BEFORE HASH (Baseline):</span>
                    <div style={{ color: MON.text, marginTop: 4 }}>{fimHashOld(log)}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 10, borderRadius: 6, border: `1px solid ${MON.red}55` }}>
                    <span style={{ color: MON.red }}>AFTER HASH (Current Disk):</span>
                    <div style={{ color: MON.red, marginTop: 4 }}>{fimHashNew(log)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PERMISSIONS & OWNER */}
          {activeTab === 'permissions' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📋 Permission Modification (chmod / ACL)</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Original Permission:</span> <b style={{ color: MON.green }}>{fimPermOld(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>New Permission:</span> <b style={{ color: MON.red }}>{fimPermNew(log)}</b></div>
                  <div style={{ padding: 10, background: 'rgba(248, 113, 113, 0.1)', border: `1px solid ${MON.red}`, borderRadius: 6, marginTop: 6 }}>
                    <b style={{ color: MON.red }}>Assessment:</b> {raw.permission_risk || log.permissionRisk || (fimPermOld(log) !== '-' && fimPermNew(log) !== '-' && fimPermOld(log) !== fimPermNew(log) ? 'Permission value changed.' : 'No permission-change evidence reported.')}
                  </div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🔐 Ownership Drift (chown / chgrp)</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Original Owner:Group:</span> <b style={{ color: MON.green }}>{fimOwnerOld(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>New Owner:Group:</span> <b style={{ color: MON.orange }}>{fimOwnerNew(log)}</b></div>
                  <div style={{ padding: 10, background: 'rgba(251, 146, 60, 0.1)', border: `1px solid ${MON.orange}`, borderRadius: 6, marginTop: 6 }}>
                    <b style={{ color: MON.orange }}>Assessment:</b> {raw.ownership_risk || log.ownershipRisk || (fimOwnerOld(log) !== '-' && fimOwnerNew(log) !== '-' && fimOwnerOld(log) !== fimOwnerNew(log) ? 'File ownership changed.' : 'No ownership-change evidence reported.')}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 6: CONFIG & SYSTEM */}
          {activeTab === 'config' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Configuration & System File Impact</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                  <b style={{ color: MON.blue }}>System File Scope:</b> {/etc|system32|boot/i.test(fimPath(log)) ? 'Critical Operating System File' : 'Application / Web Configuration File'}
                </div>
                <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                  <b style={{ color: MON.yellow }}>Service / Process:</b> {raw.service || raw.service_name || log.serviceName || fimProcess(log) || 'Not reported'}
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Alignment</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {mitreIds.map(id => <div key={id} style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}><b style={{ color: MON.red }}>{id}</b></div>)}
                  {!mitreIds.length && <span style={{ color: MON.muted }}>No MITRE ATT&amp;CK mapping was reported for this event.</span>}
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🔍 YARA & Malware Signature Matches</h4>
                <div style={{ fontSize: 11, color: MON.text }}>
                  <b>YARA Match:</b> <span style={{ color: MON.purple, fontFamily: 'monospace' }}>{yaraMatches.length ? yaraMatches.join(', ') : 'No YARA match reported'}</span>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL FIM Artifact Hunt Launcher</div>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ fontSize: 11, color: MON.sub, display: 'block', marginBottom: 4 }}>Custom Hunt Name</label>
                  <input
                    type="text"
                    value={huntNameInput}
                    onChange={e => setHuntNameInput(e.target.value)}
                    style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}
                  />
                </div>
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

              {/* Hunt Execution Results Output Table */}
              {huntResults && (
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, borderBottom: `1px solid ${MON.line}`, paddingBottom: 8 }}>
                    <div>
                      <span style={{ fontSize: 12, fontWeight: 800, color: MON.green }}>💻 VQL Execution Output: {huntResults.name}</span>
                      <div style={{ fontSize: 10, color: MON.muted, marginTop: 2 }}>Artifact: <code style={{ color: MON.cyan }}>{huntResults.artifact}</code> | Completed at: {huntResults.completedAt}</div>
                    </div>
                    <span style={{ background: 'rgba(34,197,94,0.15)', color: MON.green, border: `1px solid ${MON.green}`, padding: '4px 10px', borderRadius: 4, fontSize: 10, fontWeight: 800 }}>
                      COMPLETED · {huntResults.totalFound} RECORDS
                    </span>
                  </div>

                  <div style={{ overflowX: 'auto' }}>
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                      <thead>
                        <tr style={{ background: MON.card2, color: MON.muted, textAlign: 'left', borderBottom: `1px solid ${MON.line}` }}>
                          {huntResults.columns.map(col => (
                            <th key={col} style={{ padding: '8px 10px', fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{col}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {huntResults.rows.map((row, idx) => (
                          <tr key={idx} style={{ borderBottom: idx < huntResults.rows.length - 1 ? `1px solid ${MON.line}66` : 'none', color: MON.text }}>
                            <td style={{ padding: '8px 10px', color: MON.muted, fontSize: 9 }}>{row[0]}</td>
                            <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: MON.cyan, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row[1]}>{row[1]}</td>
                            <td style={{ padding: '8px 10px', color: MON.blue, fontWeight: 800 }}>{row[2]}</td>
                            <td style={{ padding: '8px 10px', color: MON.green }}>{row[3]}</td>
                            <td style={{ padding: '8px 10px' }}>{row[4]}</td>
                            <td style={{ padding: '8px 10px', color: MON.purple }}>{row[5]}</td>
                            <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: MON.muted, fontSize: 9, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row[6]}>{row[6]}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Extracted File Diff & Baseline Audit Log</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {evidenceText || JSON.stringify({
                  timestamp: alertTime(log) || null,
                  path: fimPath(log),
                  action: fimAction(log),
                  oldHash: fimHashOld(log),
                  newHash: fimHashNew(log),
                  oldPermission: fimPermOld(log),
                  newPermission: fimPermNew(log),
                  oldOwner: fimOwnerOld(log),
                  newOwner: fimOwnerNew(log),
                }, null, 2)}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst FIM Triage & Case Management</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Assigned Analyst</label>
                    <input type="text" value={assignedAnalyst} readOnly style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Case Status</label>
                    <select value={caseStatus} onChange={e => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }}>
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="under_observation">Under Observation</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False Positive</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Incident Tags</label>
                    <input type="text" value={tags} readOnly style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                </div>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="button" onClick={handleSaveNotes} disabled={savingNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: savingNotes ? 'wait' : 'pointer' }}>
                    {savingNotes ? 'Saving…' : 'Save Triage Notes'}
                  </button>
                  {notesSaved && <span style={{ marginLeft: 10, color: MON.yellow, fontSize: 10 }}>{notesSaved}</span>}
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
function FileLogMonitor({ alerts = [], loading = false, total = 0, updatedAt = null, onRefresh }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [actionFilter, setActionFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = useMemo(() => (
    Array.isArray(alerts)
      ? [...alerts].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0))
      : []
  ), [alerts]);

  const filtered = useMemo(() => {
    return effectiveAlerts.filter(a => {
      const matchQ = !query || `${fimPath(a)} ${fimAction(a)} ${fimProcess(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchA = actionFilter === 'all' || fimAction(a).toLowerCase().includes(actionFilter.toLowerCase());
      return matchQ && matchP && matchS && matchA;
    });
  }, [effectiveAlerts, query, platform, severity, actionFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search File Path, Process, Host, User, Action..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
        <select value={actionFilter} onChange={e => setActionFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All File Actions</option>
          <option value="create">Created</option>
          <option value="modifi">Modified</option>
          <option value="delet">Deleted</option>
          <option value="renam">Renamed</option>
          <option value="perm">Permission Changed</option>
          <option value="owner">Ownership Changed</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 File Integrity Monitoring (FIM) Telemetry Logs ({filtered.length.toLocaleString()} shown / {Number(total || effectiveAlerts.length).toLocaleString()} live)</b>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 10, color: loading ? MON.yellow : MON.green }}>● {loading ? 'Refreshing…' : `Live${updatedAt ? ` · ${new Date(updatedAt).toLocaleTimeString()}` : ''}`}</span>
            {onRefresh && <button type="button" onClick={onRefresh} disabled={loading} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: loading ? 'wait' : 'pointer' }}>↻ Refresh</button>}
          </div>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Target File Path</span><span>Host / OS</span><span>User / Actor</span><span>Process Name</span><span>Action / Event</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '2fr 1fr 1fr 1fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block', wordBreak: 'break-all' }} onClick={() => setSelectedLog(row)}>{fimPath(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{fimHashNew(row).substring(0, 24)}…</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <span style={{ color: MON.blue }}>{fimProcess(row)}</span>
                <span style={{ color: MON.orange, fontWeight: 800 }}>{fimAction(row)}</span>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading live FIM telemetry…' : 'No live FIM telemetry logs match the selected filters.'}</div>}
          </div>
        </div>
      </div>

      {selectedLog && <FileLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onSaved={onRefresh} />}
    </div>
  );
}

function FileReportsTab({ alerts = [], total = 0, fimStats = null }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState('');

  const windowDays = { daily: 1, weekly: 7, monthly: 30, '90days': 90 };

  const calculateReportData = useCallback((type) => {
    const days = windowDays[type] || 1;
    const now = Date.now();
    const cutoff = now - days * 86400000;

    const filtered = alerts.filter(a => {
      const t = alertTime(a);
      return t ? new Date(t).getTime() >= cutoff : true;
    });

    const list = filtered;
    const rawSev = { critical: 0, high: 0, medium: 0, low: 0 };
    list.forEach(a => {
      const s = alertSeverity(a).toLowerCase();
      if (rawSev[s] !== undefined) rawSev[s]++; else rawSev.low++;
    });

    return {
      alerts: list,
      total: list.length,
      bySev: rawSev,
    };
  }, [alerts]);

  useEffect(() => {
    if (reportType !== 'daily' || generating) return;
    const local = calculateReportData('daily');
    setReportData({
      ...local,
      total: Number(fimStats?.total ?? total ?? local.total) || 0,
      bySev: {
        critical: Number(fimStats?.critical ?? local.bySev.critical) || 0,
        high: Number(fimStats?.high ?? local.bySev.high) || 0,
        medium: Number(fimStats?.medium ?? local.bySev.medium) || 0,
        low: Number(fimStats?.low ?? local.bySev.low) || 0,
      },
    });
    setGenerated(true);
  }, [alerts, total, fimStats, reportType, generating, calculateReportData]);

  const fetchReportFromApi = useCallback((type) => {
    setGenerating(true);
    setReportError('');
    const windowHours = (windowDays[type] || 1) * 24;

    const buildReportState = (logsArr, totalVal, statsObj) => {
      const safeLogs = Array.isArray(logsArr) ? logsArr : alerts;
      const rawSev = { critical: 0, high: 0, medium: 0, low: 0 };

      safeLogs.forEach(a => {
        try {
          const s = (a?.severity || a?.level || (typeof alertSeverity === 'function' ? alertSeverity(a) : 'low') || 'low').toString().toLowerCase();
          if (rawSev[s] !== undefined) rawSev[s]++; else rawSev.low++;
        } catch {
          rawSev.low++;
        }
      });

      const reportTotal = Number(totalVal ?? safeLogs.length);

      return {
        alerts: safeLogs,
        total: reportTotal,
        bySev: {
          critical: Number(statsObj?.critical ?? statsObj?.bySeverity?.critical ?? rawSev.critical),
          high: Number(statsObj?.high ?? statsObj?.bySeverity?.high ?? rawSev.high),
          medium: Number(statsObj?.medium ?? statsObj?.bySeverity?.medium ?? rawSev.medium),
          low: Number(statsObj?.low ?? statsObj?.bySeverity?.low ?? rawSev.low),
        },
      };
    };

    api.get(`/dashboard/alerts/file?limit=500&capabilityId=2&windowHours=${windowHours}`, { skipCache: true })
      .then(r => {
        const data = r.data || {};
        const logs = data.alerts || data.logs || data.data || [];
        setReportData(buildReportState(logs, data.total ?? data.recordsTotal, data.fimStats || data.stats || data.summary));
        setGenerated(true);
        setGenerating(false);
      })
      .catch(() => {
        api.get(`/dashboard/capabilities/2/live?limit=500&windowHours=${windowHours}`, { skipCache: true })
          .then(r => {
            const data = r.data || {};
            const logs = data.alerts || data.logs || data.data || [];
            setReportData(buildReportState(logs, data.total, data.fimStats || data.stats));
            setGenerated(true);
          })
          .catch(() => {
            setReportData(null);
            setGenerated(false);
            setReportError('Live FIM report could not be loaded. Please retry.');
          })
          .finally(() => setGenerating(false));
      });
  }, [alerts, total, calculateReportData]);

  const handleSelectWindow = (key) => {
    setReportType(key);
    setGenerated(false);
    setReportData(null);
    fetchReportFromApi(key);
  };

  const handleGenerate = () => {
    if (generating) return;
    fetchReportFromApi(reportType);
  };

  const handleExportCSV = async () => {
    const days = windowDays[reportType] || 1;
    const to = new Date().toISOString();
    const from = new Date(Date.now() - days * 86400000).toISOString();
    try {
      const res = await api.get(`/reports/csv?from=${from}&to=${to}&type=fim&capabilityId=2`, { responseType: 'blob' });
      downloadBlob(res.data, `fim_executive_report_${reportType}.csv`);
    } catch {
      const filtered = reportData?.alerts || alerts;
      const header = 'Timestamp,File Path,Action,Host,User,Process,Severity,Hash';
      const rowsHtml = filtered.map(a => [
        csvCell(alertTime(a)),
        csvCell(fimPath(a)),
        csvCell(fimAction(a)),
        csvCell(alertHost(a)),
        csvCell(alertUser(a)),
        csvCell(fimProcess(a)),
        csvCell(alertSeverity(a)),
        csvCell(fimHashNew(a)),
      ].join(','));
      downloadBlob([header, ...rowsHtml].join('\n'), `fim_executive_report_${reportType}_${filtered.length}records.csv`);
    }
  };

  const handleExportPDF = async () => {
    const days = windowDays[reportType] || 1;
    const to = new Date().toISOString();
    const from = new Date(Date.now() - days * 86400000).toISOString();
    try {
      const response = await api.get(`/reports/pdf?from=${from}&to=${to}&type=fim&capabilityId=2`, { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const reportWindow = window.open(url, '_blank');
      window.setTimeout(() => URL.revokeObjectURL(url), reportWindow ? 120000 : 1000);
      if (reportWindow) return;
    } catch {
      // Fall back to the local printable report below when the report service is unavailable.
    }
    let filtered = reportData?.alerts || [];
    if (filtered.length === 0) {
      try {
        const r = await api.get(`/dashboard/file-activity/report?period=${reportType}`);
        filtered = r.data?.alerts || r.data?.logs || [];
      } catch {
        filtered = alerts;
      }
    }
    if (!filtered.length) filtered = alerts;
    const win = window.open('', '_blank');
    if (!win) return;
    const rowsHtml = filtered.slice(0, 100).map((a, i) => `
      <tr style="background: ${i % 2 === 0 ? '#111827' : '#1f2937'}; color: #f8fafc;">
        <td style="padding: 6px 10px; font-size: 10px;">${alertTime(a) ? new Date(alertTime(a)).toLocaleString() : '—'}</td>
        <td style="padding: 6px 10px; font-size: 10px; color: #38bdf8; font-weight: bold;">${fimAction(a)}</td>
        <td style="padding: 6px 10px; font-size: 10px; font-family: monospace; word-break: break-all; color: #93c5fd;">${fimPath(a)}</td>
        <td style="padding: 6px 10px; font-size: 10px; color: #4ade80;">${alertUser(a)}</td>
        <td style="padding: 6px 10px; font-size: 10px;">${alertHost(a)}</td>
        <td style="padding: 6px 10px; font-size: 10px; color: #c084fc;">${fimProcess(a)}</td>
        <td style="padding: 6px 10px; font-size: 10px; font-weight: bold; color: ${alertSeverity(a) === 'critical' ? '#ef4444' : alertSeverity(a) === 'high' ? '#f97316' : '#4ade80'};">${alertSeverity(a).toUpperCase()}</td>
      </tr>
    `).join('');

    win.document.write(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>FIM Executive Report - ${reportType.toUpperCase()}</title>
        <style>
          body { font-family: system-ui, -apple-system, sans-serif; background: #06111f; color: #f8fafc; margin: 24px; }
          h1 { color: #38bdf8; margin: 0 0 4px 0; font-size: 20px; }
          .meta { color: #94a3b8; font-size: 11px; margin-bottom: 20px; border-bottom: 1px solid #1e293b; padding-bottom: 10px; }
          .kpi-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
          .kpi { background: #0c1e36; border: 1px solid #1e3a5f; padding: 12px; border-radius: 8px; }
          .kpi-title { font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 700; }
          .kpi-val { font-size: 22px; font-weight: 900; margin-top: 4px; color: #38bdf8; }
          table { width: 100%; border-collapse: collapse; margin-top: 10px; }
          th { background: #0c1e36; color: #94a3b8; text-align: left; padding: 8px 10px; font-size: 10px; text-transform: uppercase; border-bottom: 1px solid #1e3a5f; }
          @media print {
            body { background: #ffffff !important; color: #0f172a !important; }
            .kpi { background: #f8fafc !important; border: 1px solid #cbd5e1 !important; }
            .kpi-title { color: #64748b !important; }
            .kpi-val { color: #0284c7 !important; }
            th { background: #f1f5f9 !important; color: #334155 !important; border-bottom: 2px solid #cbd5e1 !important; }
            tr { background: #ffffff !important; color: #0f172a !important; }
            td { border-bottom: 1px solid #e2e8f0 !important; color: #0f172a !important; }
          }
        </style>
      </head>
      <body>
        <h1>📄 File Integrity Monitoring (FIM) Executive Security Report</h1>
        <div class="meta">Time Window: <strong>${reportType.toUpperCase()}</strong> | Total Monitored Records: <strong>${filtered.length}</strong> | Generated: ${new Date().toLocaleString()}</div>
        
        <div class="kpi-grid">
          <div class="kpi">
            <div class="kpi-title">Total FIM Events</div>
            <div class="kpi-val">${reportData?.total || filtered.length}</div>
          </div>
          <div class="kpi">
            <div class="kpi-title">Critical Drifts</div>
            <div class="kpi-val" style="color: #ef4444;">${reportData?.bySev?.critical || 0}</div>
          </div>
          <div class="kpi">
            <div class="kpi-title">High Risk Changes</div>
            <div class="kpi-val" style="color: #f97316;">${reportData?.bySev?.high || 0}</div>
          </div>
          <div class="kpi">
            <div class="kpi-title">Low / Normal Edits</div>
            <div class="kpi-val" style="color: #22c55e;">${Math.max(0, Number(reportData?.total || filtered.length) - Number(reportData?.bySev?.critical || 0) - Number(reportData?.bySev?.high || 0))}</div>
          </div>
        </div>

        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Action</th>
              <th>File Path</th>
              <th>User</th>
              <th>Host</th>
              <th>Process</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            ${rowsHtml}
          </tbody>
        </table>
        <script>
          window.onload = function() {
            setTimeout(function() { window.print(); }, 400);
          }
        </script>
      </body>
      </html>
    `);
    win.document.close();
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 File Integrity Monitoring (FIM) Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate PCI-DSS & ISO 27001 compliance-ready file integrity summaries</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate FIM Report'}
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
                  onClick={() => handleSelectWindow(opt.key)}
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

      {reportError && (
        <div style={{ padding: 12, borderRadius: 7, background: `${MON.red}14`, border: `1px solid ${MON.red}55`, color: MON.red, fontSize: 11, fontWeight: 700 }}>
          {reportError}
        </div>
      )}

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 FIM Executive Security & Compliance Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored FIM Logs: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
                📥 Export CSV
              </button>
              <button type="button" onClick={handleExportPDF} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
                📕 Export PDF
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total FIM Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Hash Drifts', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Changes', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Low / Normal Edits', val: Math.max(0, Number(reportData?.total || 0) - Number(reportData?.bySev?.critical || 0) - Number(reportData?.bySev?.high || 0)), color: MON.green },
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

function FIMTrendChart({ rows = [] }) {
  const buckets = Array.from({ length: 24 }, (_, hour) => ({ hour, created: 0, modified: 0, deleted: 0, renamed: 0 }));
  rows.forEach(row => {
    const t = alertTime(row) || row.createdAt || row.timestamp;
    const date = t ? new Date(t) : null;
    const hour = date && Number.isFinite(date.getTime()) ? date.getHours() : 0;
    const act = fimAction(row).toLowerCase();
    if (/creat|new/.test(act)) buckets[hour].created += 1;
    else if (/delet|remove|unlink/.test(act)) buckets[hour].deleted += 1;
    else if (/renam|move/.test(act)) buckets[hour].renamed += 1;
    else buckets[hour].modified += 1;
  });

  const max = Math.max(1, ...buckets.flatMap(b => [b.created, b.modified, b.deleted, b.renamed]));
  const points = key => buckets.map((b, i) => {
    const x = 20 + (i / 23) * 390;
    const y = 130 - (b[key] / max) * 100;
    return `${x},${y}`;
  }).join(' ');
  return (
    <div style={{ padding: 12, height: 168, boxSizing: 'border-box', display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
      <svg viewBox="0 0 430 150" width="100%" height="130" preserveAspectRatio="none">
        {[0, 1, 2, 3].map(i => <line key={i} x1="20" x2="410" y1={20 + i * 32} y2={20 + i * 32} stroke="#14243a" strokeWidth="1" />)}
        {[0, 4, 8, 12, 16, 20, 23].map(hour => <text key={hour} x={20 + (hour / 23) * 390} y="145" fill="#8ea0b8" fontSize="8" textAnchor="middle">{String(hour).padStart(2, '0')}:00</text>)}
        <polyline points={points('modified')} fill="none" stroke="#1f8bff" strokeWidth="2.5" />
        <polyline points={points('created')} fill="none" stroke="#22c55e" strokeWidth="2" />
        <polyline points={points('deleted')} fill="none" stroke="#ef4444" strokeWidth="2" />
        <polyline points={points('renamed')} fill="none" stroke="#f59e0b" strokeWidth="2" />
      </svg>
      <div style={{ display: 'flex', gap: 14, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
        {['Created', 'Modified', 'Deleted', 'Renamed'].map((label, i) => <span key={label}><b style={{ color: ['#22c55e', '#1f8bff', '#ef4444', '#f59e0b'][i] }}>◆</b> {label}</span>)}
      </div>
    </div>
  );
}

function FIMDonut({ items = [], totalLabel = 'Total' }) {
  const totalSum = items.reduce((sum, item) => sum + item.value, 0);
  const total = Math.max(1, totalSum);
  let offset = 25;
  return (
    <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '130px 1fr', gap: 14, alignItems: 'center', minHeight: 160 }}>
      <svg viewBox="0 0 120 120" width="130" height="130">
        <circle cx="60" cy="60" r="38" fill="none" stroke="#10243c" strokeWidth="22" />
        {totalSum > 0 && items.map(item => {
          const dash = `${(item.value / total) * 239} 239`;
          const circle = <circle key={item.label} cx="60" cy="60" r="38" fill="none" stroke={item.color} strokeWidth="22" strokeDasharray={dash} strokeDashoffset={offset} transform="rotate(-90 60 60)" />;
          offset -= (item.value / total) * 239;
          return circle;
        })}
        <text x="60" y="57" fill="#f8fbff" fontSize="18" fontWeight="900" textAnchor="middle">{shortNum(totalSum)}</text>
        <text x="60" y="75" fill="#93a4ba" fontSize="9" textAnchor="middle">{totalLabel}</text>
      </svg>
      <div style={{ display: 'grid', gap: 10 }}>
        {items.map(item => (
          <div key={item.label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8, color: MON.text, fontSize: 10, fontWeight: 850 }}>
            <span><b style={{ color: item.color }}>■</b> {item.label}</span>
            <span>{shortNum(item.value)} ({totalSum > 0 ? (Math.round((item.value / total) * 1000) / 10) : 0}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function FileOverviewDashboard({ alerts = [], total = 0, fimStats = null, loading = false, liveData = null }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const effectiveAlerts = useMemo(() => Array.isArray(alerts) ? alerts : [], [alerts]);

  const rows = effectiveAlerts;
  const displayTotal = Number(fimStats?.total ?? total ?? rows.length) || 0;
  const rawTotal = Math.max(rows.length, 1);
  const scale = c => Math.round((c / rawTotal) * displayTotal);
  const exactStat = (key, fallback) => Number.isFinite(Number(fimStats?.[key])) ? Number(fimStats[key]) : fallback;

  const rawSev = rows.reduce((acc, r) => {
    const s = alertSeverity(r).toLowerCase();
    if (acc[s] !== undefined) acc[s]++; else acc.low++;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const createdCount = exactStat('created', scale(rows.filter(r => /creat|new/.test(fimAction(r).toLowerCase())).length));
  const modifiedCount = exactStat('modified', scale(rows.filter(r => /modifi|change|write|hash|integrity/.test(fimAction(r).toLowerCase())).length));
  const deletedCount = exactStat('deleted', scale(rows.filter(r => /delet|remove|unlink/.test(fimAction(r).toLowerCase())).length));
  const renamedCount = exactStat('renamed', scale(rows.filter(r => /renam|move/.test(fimAction(r).toLowerCase())).length));
  const alertCount = ['critical', 'high', 'medium'].reduce((sum, key) => sum + exactStat(key, scale(rawSev[key] || 0)), 0);

  const formatBreakdown = (list) => {
    if (!list || !list.length) return [];
    const totalRaw = list.reduce((sum, [, cnt]) => sum + Number(cnt || 0), 0) || 1;
    return list.map(([item, cnt]) => [item, Math.round((Number(cnt || 0) / totalRaw) * displayTotal)]);
  };

  const rawTopPaths = topCounts(rows, r => {
    const p = fimPath(r);
    if (!p || p === '—') return '—';
    const parts = p.split('/');
    return parts.length > 3 ? parts.slice(0, 3).join('/') : p;
  }, 10).filter(([p]) => p !== '—');
  const topPaths = Array.isArray(fimStats?.topPaths) && fimStats.topPaths.length
    ? fimStats.topPaths.map(item => [item.label, Number(item.value || 0)])
    : formatBreakdown(rawTopPaths);

  const rawTopFiles = topCounts(rows, fimPath, 5).filter(([p]) => p && p !== '—');
  const topFiles = formatBreakdown(rawTopFiles);

  const rawUsers = topCounts(rows, alertUser, 5).filter(([u]) => u && u !== 'unknown');
  const topUsers = formatBreakdown(rawUsers);

  const rawProcesses = topCounts(rows, fimProcess, 5).filter(([p]) => p && p !== '—');
  const topProcesses = formatBreakdown(rawProcesses);

  const recentRows = rows.slice(0, 10);

  const dist = [
    { label: 'Modified', value: modifiedCount, color: '#1f8bff' },
    { label: 'Created', value: createdCount, color: '#22c55e' },
    { label: 'Deleted', value: deletedCount, color: '#ef4444' },
    { label: 'Renamed', value: renamedCount, color: '#f59e0b' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Top 5 KPI Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10 }}>
        {[
          { title: 'Total Events', val: (displayTotal || 0).toLocaleString(), color: '#1f8bff', icon: '📄' },
          { title: 'Files Created', val: (createdCount || 0).toLocaleString(), color: '#22c55e', icon: '✚' },
          { title: 'Files Modified', val: (modifiedCount || 0).toLocaleString(), color: '#38bdf8', icon: '✏️' },
          { title: 'Files Deleted', val: (deletedCount || 0).toLocaleString(), color: '#ef4444', icon: '🗑️' },
          { title: 'Alerts', val: (alertCount || 0).toLocaleString(), color: '#a855f7', icon: '🚨' },
        ].map(kpi => (
          <div key={kpi.title} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div>
              <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase' }}>{kpi.title}</div>
              <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color, marginTop: 4 }}>{kpi.val}</div>
            </div>
            <div style={{ fontSize: 24, opacity: 0.8 }}>{kpi.icon}</div>
          </div>
        ))}
      </div>

      {/* Middle Row: Trend, Donut, Heatmap */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>File Activity Trend (24 Hours)</b>
          <FIMTrendChart rows={rows} />
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Event Distribution (24 Hours)</b>
          <FIMDonut items={dist} totalLabel="Total" />
        </div>
        <div style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <b style={{ fontSize: 12, color: '#fff' }}>File Change Heatmap (Top Paths - 24h)</b>
            <span style={{ fontSize: 9, color: MON.muted }}>Top 10 (24h)</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 10 }}>
            {topPaths.map(([path, cnt], idx) => {
              const colors = ['#ef4444', '#f97316', '#22c55e', '#06b6d4', '#3b82f6', '#8b5cf6'];
              const max = Math.max(1, topPaths[0]?.[1] || 1);
              return (
                <div key={path} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 35px', alignItems: 'center', gap: 8 }}>
                  <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 9, fontFamily: 'monospace' }}>{path}</span>
                  <div style={{ height: 6, background: '#10243c', borderRadius: 99, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${Math.max(6, (cnt / max) * 100)}%`, background: colors[idx % colors.length] }} />
                  </div>
                  <b style={{ color: MON.cyan, textAlign: 'right', fontSize: 9 }}>{shortNum(cnt)}</b>
                </div>
              );
            })}
            {!topPaths.length && <div style={{ color: MON.muted, fontSize: 10 }}>{loading ? 'Loading live path activity…' : 'No path activity received in the selected window.'}</div>}
            <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.muted, fontSize: 8, marginTop: 4 }}>
              <span>Low</span><span>High</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Critical Changes Table */}
      <div style={panel}>
        <b style={{ fontSize: 12, color: '#fff', marginBottom: 10, display: 'block' }}>Recent Critical Changes (Last 24h)</b>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
            <thead>
              <tr style={{ background: MON.card2, color: MON.muted, textAlign: 'left', borderBottom: `1px solid ${MON.line}` }}>
                {['Time', 'Event Type', 'File Path', 'File Name', 'User', 'System', 'Change Details', 'Severity'].map(h => (
                  <th key={h} style={{ padding: '8px 10px', fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {recentRows.map((r, i) => {
                const sev = alertSeverity(r);
                const color = SEV_COLOR[sev] || MON.green;
                const path = fimPath(r);
                const fileName = path.split('/').pop() || path;
                return (
                  <tr key={recordId(r)} style={{ borderBottom: i < recentRows.length - 1 ? `1px solid ${MON.line}80` : 'none', color: MON.text }}>
                    <td style={{ padding: '8px 10px', color: MON.muted }}>{alertTime(r) ? new Date(alertTime(r)).toLocaleTimeString() : '—'}</td>
                    <td style={{ padding: '8px 10px', color, fontWeight: 800 }}>{fimAction(r)}</td>
                    <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: MON.cyan, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={path}>{path}</td>
                    <td style={{ padding: '8px 10px' }}>{fileName}</td>
                    <td style={{ padding: '8px 10px', color: MON.green }}>{alertUser(r)}</td>
                    <td style={{ padding: '8px 10px' }}>{alertHost(r)}</td>
                    <td style={{ padding: '8px 10px' }}>{r.change_type || r.description || r.type || 'File modified'}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span style={{ background: SEV_BG[sev] || SEV_BG.low, color, padding: '2px 6px', borderRadius: 4, fontWeight: 800, fontSize: 9, textTransform: 'uppercase' }}>{sev}</span>
                    </td>
                  </tr>
                );
              })}
              {!recentRows.length && (
                <tr><td colSpan={8} style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No recent FIM changes found in 24h.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom 4 Panels */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff', marginBottom: 8, display: 'block' }}>Top Modified Files (24h)</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 10 }}>
            {(topFiles.length ? topFiles : [['No file changes', 0]]).map(([f, cnt]) => (
              <div key={f} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.cyan, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 150 }} title={f}>{f}</span>
                <b style={{ color: MON.text }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff', marginBottom: 8, display: 'block' }}>Top Users (24h)</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 10 }}>
            {(topUsers.length ? topUsers : [['No user events', 0]]).map(([u, cnt]) => (
              <div key={u} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.green }}>👤 {u}</span>
                <b style={{ color: MON.text }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff', marginBottom: 8, display: 'block' }}>Top Processes (24h)</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 10 }}>
            {(topProcesses.length ? topProcesses : [['No process events', 0]]).map(([p, cnt]) => (
              <div key={p} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.purple, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 150 }} title={p}>{p}</span>
                <b style={{ color: MON.text }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff', marginBottom: 8, display: 'block' }}>Real-time File Events (Last 24h)</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, fontSize: 10 }}>
            {recentRows.slice(0, 5).map(r => (
              <div key={recordId(r)} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 130 }} title={fimPath(r)}>{fimPath(r).split('/').pop() || fimPath(r)}</span>
                <span style={{ color: SEV_COLOR[alertSeverity(r)] || MON.green, fontWeight: 800, fontSize: 9 }}>{fimAction(r)}</span>
              </div>
            ))}
            {!recentRows.length && <span style={{ color: MON.muted }}>No real-time events.</span>}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`FileActivityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function FileActivityDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, fimStats = null, systems = [], liveData = null, onAction, onRefresh }) {
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

  const masterFimTelemetry = useMemo(() => Array.isArray(alerts) ? alerts : [], [alerts]);

  const rows = masterFimTelemetry;
  const totalRows = Number(fimStats?.total ?? total ?? recordsTotal ?? rows.length) || 0;
  const rawTotal = Math.max(rows.length, 1);
  const scale = c => Math.round((c / rawTotal) * totalRows);
  const exactStat = (key, fallback) => Number.isFinite(Number(fimStats?.[key])) ? Number(fimStats[key]) : fallback;

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

  const timeline = Array.isArray(liveData?.timeline) && liveData.timeline.length
    ? liveData.timeline.map(bucket => Number(bucket.total || 0))
    : buildBuckets(rows, 8, 24);

  // 15 FIM Specific SOC Categories & Metrics
  const createdCount = exactStat('created', scale(rows.filter(r => /creat|new/.test(fimAction(r).toLowerCase())).length));
  const modifiedCount = exactStat('modified', scale(rows.filter(r => /modifi|change|write|hash|integrity/.test(fimAction(r).toLowerCase())).length));
  const deletedCount = exactStat('deleted', scale(rows.filter(r => /delet|remove|unlink/.test(fimAction(r).toLowerCase())).length));
  const renamedCount = exactStat('renamed', scale(rows.filter(r => /renam|move/.test(fimAction(r).toLowerCase())).length));
  const permCount = exactStat('permission', scale(rows.filter(r => /perm|chmod/.test(fimAction(r).toLowerCase())).length));
  const ownerCount = exactStat('ownership', scale(rows.filter(r => /owner|chown/.test(fimAction(r).toLowerCase())).length));
  const hashDriftCount = exactStat('hashDrift', scale(rows.filter(r => containsAny(r, ['hash', 'mismatch', 'integrity', 'sha256', 'baseline'])).length));
  const configCount = exactStat('config', scale(rows.filter(r => containsAny(r, ['apache', 'nginx', 'iis', 'config', '.conf', '.cfg', '.ini', '.yaml'])).length));
  const systemFileCount = exactStat('systemFiles', scale(rows.filter(r => containsAny(r, ['system32', '/etc/', 'boot', 'kernel', '/bin/'])).length));
  const ransomwareCount = exactStat('ransomware', scale(rows.filter(r => containsAny(r, ['encrypted', 'wncry', '.lock', 'mass file', 'ransomware', 'shadow copy'])).length));
  const sensitiveCount = exactStat('sensitive', scale(rows.filter(r => containsAny(r, ['etc/passwd', 'etc/shadow', 'authorized_keys', 'id_rsa', '.env', 'credential', 'hr', 'finance'])).length));
  const userActivityCount = scale(rows.filter(r => !['root', 'system', 'unknown'].includes(alertUser(r).toLowerCase())).length);
  const processActivityCount = scale(rows.filter(r => fimProcess(r) !== '—').length);
  const netShareCount = exactStat('networkShare', scale(rows.filter(r => containsAny(r, ['smb', 'nas', 'share', 'remote', '\\\\'])).length));
  const exfilCount = exactStat('exfiltration', scale(rows.filter(r => containsAny(r, ['.zip', '.rar', '.7z', '.tar.gz', 'usb', 'external', 'compressed'])).length));

  const winCount = osCounts.Windows ? scale(osCounts.Windows) : 0;
  const linCount = osCounts.Linux ? scale(osCounts.Linux) : 0;

  const kpis = [
    { label: '📁 1. File Creation Events', val: shortNum(createdCount), trend: 'New File', color: MON.green, data: timeline },
    { label: '✏️ 2. File Modifications', val: shortNum(modifiedCount), trend: 'Content Edit', color: MON.blue, data: timeline },
    { label: '❌ 3. File Deletion Alerts', val: shortNum(deletedCount), trend: 'Unlinked', color: MON.orange, data: timeline },
    { label: '🔄 4. File Rename Activity', val: shortNum(renamedCount), trend: 'Path Shift', color: MON.yellow, data: timeline },
    { label: '📋 5. Permission Modifications', val: shortNum(permCount), trend: 'chmod/ACL', color: MON.purple, data: timeline },
    { label: '🔐 6. Ownership Changes', val: shortNum(ownerCount), trend: 'chown/chgrp', color: MON.pink, data: timeline },
    { label: '#️⃣ 7. Hash Baseline Mismatches', val: shortNum(hashDriftCount), trend: 'SHA256 Drift', color: MON.red, data: timeline },
    { label: '⚙️ 8. Config File Updates', val: shortNum(configCount), trend: 'Web/DB Config', color: MON.cyan, data: timeline },
    { label: '🖥️ 9. System File Integrity', val: shortNum(systemFileCount), trend: '/etc & System32', color: MON.red, data: timeline },
    { label: '🦠 10. Ransomware Indicators', val: shortNum(ransomwareCount), trend: 'Mass Encryption', color: MON.red, data: timeline },
    { label: '📂 11. Sensitive File Access', val: shortNum(sensitiveCount), trend: 'Keys & Creds', color: MON.orange, data: timeline },
    { label: '👤 12. User File Activity', val: shortNum(userActivityCount), trend: 'Non-system', color: MON.blue, data: timeline },
    { label: '🚀 13. Process File Activity', val: shortNum(processActivityCount), trend: 'Exe Linked', color: MON.purple, data: timeline },
    { label: '🌐 14. Network Share Activity', val: shortNum(netShareCount), trend: 'SMB / NAS', color: MON.yellow, data: timeline },
    { label: '📤 15. Data Exfiltration Signals', val: shortNum(exfilCount), trend: 'Archive/USB', color: MON.red, data: timeline },
    { label: '🖥️ Windows Server Events', val: shortNum(winCount), trend: 'Windows', color: MON.cyan, data: timeline },
    { label: '🐧 Linux Server Events', val: shortNum(linCount), trend: 'Linux', color: MON.orange, data: timeline },
    { label: '🌐 Web Server Config Hits', val: shortNum(exactStat('webServer', scale(rows.filter(r => containsAny(r, ['nginx', 'apache', 'iis'])).length))), trend: 'Web Baseline', color: MON.green, data: timeline },
    { label: '🗄️ Database File Events', val: shortNum(exactStat('database', scale(rows.filter(r => containsAny(r, ['mysql', 'postgres', 'mongo', 'oracle', '.db', '.sqlite'])).length))), trend: 'DB Baseline', color: MON.purple, data: timeline },
    { label: '🛡️ Compliance Violations', val: shortNum(exactStat('critical', scale(sevCounts.critical || 0))), trend: 'PCI-DSS', color: MON.red, data: timeline },
  ];

  const agentList = backendSystems;

  const agentStatusRows = agentList.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || ((sys.agentOk || sys.isOnline || sys.online) ? 'reporting' : 'offline'),
      monitor: sys.fimEnabled !== false && sys.fileMonitorEnabled !== false,
      events: hostEvents,
      threats,
      platform: sys.platform || sys.osType || sys.os || 'Unknown',
      lastSeen: sys.lastSeen || sys.lastHeartbeat || null,
    });
  });
  const reportingAgents = agentStatusRows.filter(row => ['online', 'active', 'reporting'].includes(String(row.status).toLowerCase())).length;
  const monitoringTopPaths = Array.isArray(fimStats?.topPaths) && fimStats.topPaths.length
    ? fimStats.topPaths.slice(0, 5).map(item => [item.label, Number(item.value || 0)])
    : topCounts(rows, fimPath, 5);
  const monitoringTimeline = Array.isArray(liveData?.timeline) && liveData.timeline.length
    ? liveData.timeline.map(item => Number(item.total || 0))
    : buildBuckets(rows, 15, 24);

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
        <div style={{ minHeight: 30, padding: '6px 10px', borderRadius: 6, background: `${MON.cyan}0d`, border: `1px solid ${MON.cyan}33`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, fontSize: 10 }}>
          <span style={{ color: liveData?.error ? MON.red : loading ? MON.yellow : MON.green, fontWeight: 800 }}>
            ● {liveData?.error ? liveData.error : loading ? 'Syncing live FIM data…' : 'Live tenant data'} · {Number(totalRows).toLocaleString()} events · {rows.length.toLocaleString()} recent records loaded
            {liveData?.updatedAt ? ` · updated ${new Date(liveData.updatedAt).toLocaleTimeString()}` : ''}
          </span>
          {onRefresh && <button type="button" onClick={onRefresh} disabled={loading} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '4px 9px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: loading ? 'wait' : 'pointer' }}>↻ Refresh live data</button>}
        </div>
        {activeTab === 'log-monitor' ? (
          <FileLogMonitor alerts={masterFimTelemetry} loading={loading} total={totalRows} updatedAt={liveData?.updatedAt} onRefresh={onRefresh} />
        ) : activeTab === 'reports' ? (
          <FileReportsTab alerts={masterFimTelemetry} total={totalRows} fimStats={fimStats} />
        ) : activeTab === 'dashboard' ? (
          <FileOverviewDashboard alerts={masterFimTelemetry} total={totalRows} fimStats={fimStats} loading={loading} liveData={liveData} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Monitored Infrastructure (FIM Active)</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 9, color: loading ? MON.yellow : MON.green }}>● {reportingAgents}/{agentStatusRows.length} endpoints reporting · Live inventory</span>
                  {onRefresh && <button type="button" onClick={onRefresh} disabled={loading} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, cursor: loading ? 'wait' : 'pointer' }}>↻ Refresh</button>}
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>FIM Driver</span><span>Events</span><span>Hash Drifts</span><span>Last Scan</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.monitor ? row.status : 'disabled'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Never'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend FIM agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 File Integrity Event Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {monitoringTimeline.map((val, idx, arr) => (
                    <div key={idx} title={`${val} file events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📁 Top Monitored File Paths</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {monitoringTopPaths.map(([path, count], index) => (
                    <div key={path} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{path}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                  {!monitoringTopPaths.length && <span style={{ color: MON.muted }}>No monitored file-path activity in this window.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 FIM Event Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['File Modifications', modifiedCount],
                    ['Permission & Owner', permCount + ownerCount],
                    ['Creation & Deletion', createdCount + deletedCount],
                    ['Ransomware & Hash Drift', ransomwareCount + hashDriftCount],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`FileActivityMonitoringPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function FileActivityMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '2';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [fimStats, setFimStats] = useState(null);
  const [liveData, setLiveData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({
        limit: 500,
        windowHours: 24,
      });
      const r = await api.get(`/dashboard/capabilities/${capabilityId}/live?${q}`, { skipCache: quiet });
      const next = r.data?.alerts || [];
      setAlerts(next);
      setTotal(Number(r.data?.total ?? next.length) || 0);
      setFimStats(r.data?.fimStats || null);
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);
      setLiveData(r.data || null);
    } catch {
      setAlerts([]);
      setTotal(0);
      setFimStats(null);
      setLiveData(null);
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
    socket.on('file:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('file:event', buf.add);
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
            🛡️ 2. File Activity Monitoring (FIM) (24h Window)
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || alerts.length || 0).toLocaleString()} records
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <FileActivityDashboard alerts={alerts} loading={loading} total={total} fimStats={fimStats} systems={systems} liveData={liveData} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export const FIM_TABS = [
  { id: 'integrity-monitoring', icon: '🔍', label: 'Integrity Monitoring', path: '/edr-dashboard-details/fim/integrity-monitoring' },
  { id: 'permissions', icon: '🔐', label: 'Permissions', path: '/edr-dashboard-details/fim/permissions' },
  { id: 'ownership', icon: '👤', label: 'Ownership', path: '/edr-dashboard-details/fim/ownership' },
  { id: 'ransomware-detection', icon: '🛡️', label: 'Ransomware Detection', path: '/edr-dashboard-details/fim/ransomware-detection' },
  { id: 'sensitive-files', icon: '📋', label: 'Sensitive Files', path: '/edr-dashboard-details/fim/sensitive-files' },
  { id: 'reports', icon: '📈', label: 'Reports', path: '/edr-dashboard-details/fim/reports' },
  { id: 'alerts', icon: '△', label: 'Alerts & Incidents', path: '/edr-dashboard-details/fim/alerts' },
];

export function FIMSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'integrity-monitoring' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=2" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>FIM Monitoring SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=2')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="file" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <FileActivityDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { FileActivityDashboard as FileActivityPanel };
