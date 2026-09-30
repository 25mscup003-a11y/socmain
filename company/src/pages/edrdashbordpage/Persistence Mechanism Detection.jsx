/**
 * Persistence Mechanism Detection — Capability ID: 8
 *
 * 100% Self-Contained Enterprise SOC Persistence Mechanism Detection Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=8`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process (1), FIM (2), Network (3), Auth (4), Memory (5), Registry (6) & System Changes (7)
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
  return row?.user || row?.username || row?.userName || row?.account || 'SYSTEM';
}

function alertStatus(row) {
  return row?.status || row?.persistenceStatus || row?.state || 'Detected';
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
  if (osStr.includes('solaris') || osStr.includes('sun')) return 'Solaris';
  return 'Unknown';
}

// ── Persistence Telemetry Field Extractors ─────────────────────────────────
function persistTechnique(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.technique || row?.mitreTechnique || row?.persistenceType || row?.inventoryType
    || raw.technique || raw.persistence_type || raw.inventory_type || 'Unmapped persistence mechanism';
}

function persistLocation(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.persistenceLocation || row?.keyPath || row?.sourcePath || row?.location || row?.path || row?.target
    || row?.inventoryItem?.location || row?.inventoryItem?.path || raw.persistence_location || raw.location || raw.path || 'Not reported by agent';
}

function persistBinary(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.serviceBinaryPath || row?.processExe || row?.binary || row?.executable || row?.command
    || row?.inventoryItem?.command || row?.inventoryItem?.exec_start || raw.binary || raw.executable || 'Not reported by agent';
}

function persistProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.processName || row?.process || row?.sourceProcessName || raw.process_name || raw.process || 'Not attributed by agent';
}

function persistenceTimeline(row) {
  const supplied = row?.forensics?.timeline || row?.timeline || row?.rawEvent?.forensics?.timeline || [];
  if (Array.isArray(supplied) && supplied.length) return supplied.map((event, index) => ({
    type: event.type || event.eventType || `Related Event ${index + 1}`,
    time: event.time || event.timestamp || alertTime(row) || 'Not reported',
    title: event.title || event.name || event.type || 'Persistence activity',
    desc: event.description || event.message || '',
    col: [MON.blue, MON.purple, MON.orange, MON.yellow][index % 4],
  }));
  return [{
    type: row?.eventType || row?.changeType || 'Persistence Event',
    time: alertTime(row) || 'Not reported',
    title: row?.description || row?.detectionReason || persistTechnique(row),
    desc: `${persistTechnique(row)} · ${persistLocation(row)}`,
    col: SEV_COLOR[alertSeverity(row)] || MON.cyan,
  }];
}

function containsAny(row, words = []) {
  const haystack = [
    persistTechnique(row), persistLocation(row), persistBinary(row), persistProcess(row), alertHost(row), alertUser(row),
    row?.description, row?.message, row?.ruleName, row?.category,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${persistTechnique(row)}-${persistLocation(row)}`;
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
export function PersistenceLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Persistence mechanism triaged. Scheduled Task / Registry Autorun / SSH Key / Service insertion under active SOC investigation.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Marcus Vance (L3 Persistence & Threat Hunting Lead)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState('PERSISTENCE_TRIAGE, TASK_SCHEDULED, AUTORUN_RUNKEY, WMI_EVENT');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.Registry.Autoruns');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Autorun & Persistence Registry Sweep');
  const [huntNameInput, setHuntNameInput] = useState(`${alertHost(log)} persistence mechanism forensic hunt`);
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
    { id: 'autostart', label: '⚙️ 4. Autostart & Registry' },
    { id: 'tasks', label: '⏱️ 5. Tasks & Cron Jobs' },
    { id: 'wmi', label: '🔮 6. WMI, PowerShell & SSH' },
    { id: 'ioc', label: '🚨 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Autostart Diff' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Autorun Registry Keys', desc: 'Inspect HKLM/HKCU Run, RunOnce, Winlogon, and Startup folder entries.', artifact: 'Windows.Registry.Autoruns' },
    { title: 'Linux Crontab & Systemd Audit', desc: 'Sweep /etc/crontab, systemd service units, and init startup scripts.', artifact: 'Linux.Sys.Crontab' },
    { title: 'Windows Scheduled Tasks XML', desc: 'Dump XML configurations and triggers for all scheduled tasks.', artifact: 'Windows.System.TaskScheduler' },
    { title: 'WMI Event Consumer Audit', desc: 'Inspect WMI Event Consumers, Filters, and Bindings for fileless persistence.', artifact: 'Windows.WMI.EventConsumer' },
    { title: 'macOS Launch Daemons & Agents', desc: 'Sweep /Library/LaunchDaemons, LaunchAgents, and user plist items.', artifact: 'macOS.Sys.LaunchDaemons' },
    { title: 'Generic Persistence YARA Sweep', desc: 'Scan startup locations and temp folders for autostart payloads.', artifact: 'Generic.Detection.Yara.Glob' },
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
                  Persistence Mechanism Investigation — {persistTechnique(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Target: {persistLocation(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Payload: <strong style={{ color: MON.red, fontFamily: 'monospace' }}>{persistBinary(log)}</strong> | Process: <strong style={{ color: MON.green }}>{persistProcess(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Incident Summary', log.description || log.message || 'Persistence Mechanism Created (Scheduled Task / Registry Autorun / Service)', MON.cyan],
                ['Risk Score', `${log.riskScore ?? log.score ?? 0}/100`, MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Target Host System', alertHost(log), MON.blue],
                ['Modifying User Account', alertUser(log), MON.cyan],
                ['Persistence Technique', persistTechnique(log), MON.purple],
                ['Payload Executable', persistBinary(log), MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Persistence Mechanism Creation & Autostart Execution Timeline</div>
              {persistenceTimeline(log).map((ev, i) => (
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
                  <div><span style={{ color: MON.sub }}>Telemetry Provider:</span> <strong style={{ color: MON.green }}>{log.telemetryProvider || log.source || 'Agent'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔍 Persistence Audit Toolchain Status</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Evidence Type:</span> <b style={{ color: MON.green }}>{log.evidenceType || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Coverage Status:</span> <b style={{ color: MON.green }}>{log.coverageStatus || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Agent Version:</span> <b style={{ color: MON.green }}>{log.agentVersion || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: AUTOSTART & REGISTRY */}
          {activeTab === 'autostart' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Registry & Startup Autostart Attributes</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Autostart Location:</span> <span style={{ fontFamily: 'monospace', color: MON.cyan }}>{persistLocation(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Technique Name:</span> <b style={{ color: MON.green }}>{persistTechnique(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Modifying Process:</span> <span style={{ color: MON.purple }}>{persistProcess(log)}</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📊 Payload Binary Command Line</h4>
                <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}`, fontFamily: 'monospace', fontSize: 11, color: MON.red }}>
                  {persistBinary(log)}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: TASKS & CRON JOBS */}
          {activeTab === 'tasks' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>⏱️ Windows Scheduled Tasks & Linux Cron Jobs</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Task / Job Name:</span> <b style={{ color: MON.red }}>{log.inventoryName || log.persistenceKey || 'Not reported'}</b></div>
                <div><span style={{ color: MON.sub }}>Trigger:</span> <span style={{ color: MON.yellow }}>{log.persistenceTrigger || JSON.stringify(log.inventoryItem?.triggers || '') || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Action / Command:</span> <span style={{ fontFamily: 'monospace', color: MON.orange }}>{log.persistenceAction || log.inventoryItem?.command || log.processCmdline || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Location:</span> <span style={{ color: MON.green }}>{persistLocation(log)}</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: WMI, POWERSHELL & SSH */}
          {activeTab === 'wmi' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🔮 WMI Event Subscription & Encoded PowerShell</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>WMI Subscription:</span> <b style={{ color: MON.red }}>{log.inventoryItem?.subscription_type || 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>WMI Namespace:</span> <span style={{ fontFamily: 'monospace' }}>{persistLocation(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Observed Command:</span> <b style={{ color: MON.orange }}>{log.processCmdline || log.inventoryItem?.command || 'Not reported'}</b></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔑 Linux SSH Key & User Account Persistence</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span>SSH Authorized Keys:</span> <b style={{ color: MON.red }}>{containsAny(log, ['ssh', 'authorized_keys']) ? persistLocation(log) : 'No SSH evidence in this event'}</b></div>
                  <div><span>User:</span> <b style={{ color: MON.orange }}>{alertUser(log)}</b></div>
                  <div><span>Fingerprint / Hash:</span> <b>{log.persistenceKey || log.hash || log.newHash || log.inventoryItem?.sha256 || 'Not reported'}</b></div>
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
                  <div style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}>
                    <b style={{ color: MON.red }}>T1547.001: Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder</b>
                  </div>
                  <div style={{ background: 'rgba(251, 146, 60, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.orange}` }}>
                    <b style={{ color: MON.orange }}>T1053.005: Scheduled Task/Job: Scheduled Task</b>
                  </div>
                  <div style={{ background: 'rgba(251, 191, 36, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.yellow}` }}>
                    <b style={{ color: MON.yellow }}>T1543.003: Create or Modify System Process: Windows Service</b>
                  </div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>📊 Payload Hash & YARA Match</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Payload Hash:</b> <span style={{ color: MON.yellow, fontFamily: 'monospace' }}>c4ca4238a0b923820dcc509a6f75849b</span></div>
                  <div><b>YARA Match:</b> <span style={{ color: MON.red, fontFamily: 'monospace' }}>PER_Backdoor_Autorun_Registry</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Persistence Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Persistence Entry & Task XML Payload</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[PERSISTENCE MECHANISM ENTRY PAYLOAD]
Technique: ${persistTechnique(log)}
Autostart Location: ${persistLocation(log)}
Payload Binary: ${persistBinary(log)}
Modifying Process: ${persistProcess(log)}
Target Account: ${alertUser(log)}
Host System: ${alertHost(log)}`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Persistence Remediation & Cleanup</h4>
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
                  <button type="button" style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    ⛔ Remove Persistence Entry & Quarantine Binary
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
function PersistenceLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [techniqueFilter, setTechniqueFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${persistTechnique(a)} ${persistLocation(a)} ${persistBinary(a)} ${persistProcess(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchT = techniqueFilter === 'all' || persistTechnique(a).toLowerCase().includes(techniqueFilter.toLowerCase());
      return matchQ && matchP && matchS && matchT;
    });
  }, [alerts, query, platform, severity, techniqueFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Technique, Location, Payload, Process, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
        <select value={techniqueFilter} onChange={e => setTechniqueFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Persistence Techniques</option>
          <option value="run">Registry Autorun Keys</option>
          <option value="task">Scheduled Tasks / Cron</option>
          <option value="service">Windows Services / Systemd</option>
          <option value="wmi">WMI Subscriptions</option>
          <option value="ssh">SSH Authorized Keys</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Persistence Mechanism Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr 1.6fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Persistence Technique</span><span>Host / OS</span><span>User</span><span>Autostart Location / Path</span><span>Payload Executable</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr 1.6fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{persistTechnique(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>Actor: {persistProcess(row)}</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <div>
                  <span style={{ color: MON.yellow, fontFamily: 'monospace', display: 'block' }}>{persistLocation(row)}</span>
                  <span style={{ fontSize: 9, color: MON.muted }}>Status: {alertStatus(row)}</span>
                </div>
                <b style={{ color: MON.red, fontFamily: 'monospace' }}>{persistBinary(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No persistence telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <PersistenceLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

function PersistenceReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState('');

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    setReportError('');
    try {
      const hours = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 }[reportType] || 2160;
      const response = await api.get('/persistence/events', { params: { windowHours: hours, page: 1, limit: 1000 }, skipCache: true });
      const filtered = response.data?.events || [];
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: response.data?.total ?? filtered.length,
        bySev,
      });
      setGenerated(true);
    } catch (error) {
      setReportError(error.response?.data?.message || 'Persistence report could not be generated');
    } finally {
      setGenerating(false);
    }
  };

  const handleExport = async format => {
    setReportError('');
    try {
      const hours = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 }[reportType] || 2160;
      const response = await api.get(`/persistence/export/${format}`, { params: { windowHours: hours }, responseType: 'blob', skipCache: true });
      downloadBlob(response.data, `persistence_detection_${reportType}.${format}`, format === 'pdf' ? 'application/pdf' : 'text/csv;charset=utf-8');
    } catch (error) {
      setReportError(error.response?.data?.message || `${format.toUpperCase()} export failed`);
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Persistence Mechanism Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for scheduled tasks, autorun registry keys, services, and WMI persistence</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Persistence Report'}
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

      {reportError && <div style={{ color: MON.red, fontSize: 11 }}>{reportError}</div>}

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Persistence Mechanism Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Persistence Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" onClick={() => handleExport('csv')} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>📥 Export CSV</button>
              <button type="button" onClick={() => handleExport('pdf')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>📄 Export PDF</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Persistence Alerts', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Backdoor Injections', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Scheduled Tasks', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Startup Items', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Persistence Mechanism Dashboard ────────────
function PersistenceAlertsOverTimeChart({ alerts = [] }) {
  const dayMs = 86400000;
  const starts = Array.from({ length: 8 }, (_, index) => {
    const value = new Date(Date.now() - (7 - index) * dayMs);
    value.setHours(0, 0, 0, 0);
    return value;
  });
  const dates = starts.map(value => value.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }));
  const data = starts.map((start, index) => {
    const end = index === starts.length - 1 ? Date.now() + 1 : starts[index + 1].getTime();
    return alerts.filter(row => {
      const value = new Date(alertTime(row)).getTime();
      return Number.isFinite(value) && value >= start.getTime() && value < end;
    }).length;
  });
  const chartMax = Math.max(...data, 1);
  const yLabels = Array.from({ length: 6 }, (_, index) => Math.round(chartMax * (1 - index / 5)));

  const chartW = 380;
  const chartH = 140;
  const padLeft = 28;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = data.map((v, i) => ({
    x: padLeft + (i / (data.length - 1)) * innerW,
    y: padTop + innerH - (v / chartMax) * innerH,
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Persistence Alerts Over Time</span>
        <span style={{ fontSize: 9, color: '#8ea0b8', background: '#07101b', padding: '2px 8px', borderRadius: 4, border: '1px solid #16273e' }}>Last 7 Days ▾</span>
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
          {dates.map((dt, i) => {
            const x = padLeft + (i / (dates.length - 1)) * innerW;
            return <text key={dt} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{dt}</text>;
          })}
          <path d={`${d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#redTrendGrad)" />
          <path d={d} fill="none" stroke="#ef4444" strokeWidth="2" />
          {pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="3" fill="#ef4444" stroke="#0b1626" strokeWidth="1.5" />
          ))}
          <defs>
            <linearGradient id="redTrendGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function AlertsByPersistenceCategoryDonut({ alerts = [] }) {
  const definitions = [
    ['Scheduled Tasks / Cron', ['scheduled task', 'schtasks', 'cron', 'crontab'], '#f97316'],
    ['Services', ['service', 'systemd'], '#ef4444'],
    ['Registry Persistence', ['registry', 'run key', 'runonce', 'winlogon'], '#f59e0b'],
    ['SSH Keys', ['authorized_keys', 'ssh key'], '#10b981'],
    ['WMI Persistence', ['wmi', 'event consumer'], '#3b82f6'],
    ['PowerShell Persistence', ['powershell', 'profile.ps1'], '#8b5cf6'],
    ['Startup Items', ['startup', 'launchagent', 'launchdaemon'], '#ec4899'],
  ];
  const allocated = new Set();
  const cats = definitions.map(([label, words, color]) => {
    const matches = alerts.filter((row, index) => !allocated.has(index) && containsAny(row, words));
    matches.forEach(row => allocated.add(alerts.indexOf(row)));
    return { label, count: matches.length, color };
  });
  cats.push({ label: 'Others', count: Math.max(0, alerts.length - allocated.size), color: '#14b8a6' });
  const total = Math.max(alerts.length, 1);
  cats.forEach(item => { item.pct = (item.count / total) * 100; });

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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Alerts by Persistence Category</span>
        <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{alerts.length}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 8.5 }}>
          {cats.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.count} ({c.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AlertsBySeverityDonut({ alerts = [] }) {
  const total = Math.max(alerts.length, 1);
  const sevs = [
    { label: 'Critical', key: 'critical', color: '#dc2626' },
    { label: 'High', key: 'high', color: '#ef4444' },
    { label: 'Medium', key: 'medium', color: '#f97316' },
    { label: 'Low', key: 'low', color: '#3b82f6' },
  ].map(item => ({ ...item, count: alerts.filter(row => alertSeverity(row) === item.key).length }))
    .map(item => ({ ...item, pct: (item.count / total) * 100 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Alerts by Severity</span>
        <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{alerts.length}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, flex: 1, fontSize: 9 }}>
          {sevs.map(s => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 5 }}>
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

function PersistenceOverviewDashboard({ alerts = [], total = 0 }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const countWords = words => alerts.filter(row => containsAny(row, words)).length;
  const severityCount = severity => alerts.filter(row => alertSeverity(row) === severity).length;
  const affectedEndpoints = new Set(alerts.map(alertHost).filter(host => host && host !== 'unknown')).size;
  const uniqueTechniques = new Set(alerts.map(row => row.mitreId || row.mitreTechnique || persistTechnique(row)).filter(Boolean)).size;
  const topCards = [
    { title: 'Persistence Alerts', val: shortNum(total || alerts.length), sub: 'Live agent events', subCol: '#38bdf8', icon: '🛡️', iconBg: 'rgba(248, 113, 113, 0.15)', col: '#f87171' },
    { title: 'High Severity Alerts', val: shortNum(severityCount('high')), sub: 'Current window', subCol: '#f87171', icon: '🛡️', iconBg: 'rgba(248, 113, 113, 0.15)', col: '#f87171' },
    { title: 'Medium Severity Alerts', val: shortNum(severityCount('medium')), sub: 'Current window', subCol: '#fbbf24', icon: '🛡️', iconBg: 'rgba(251, 191, 36, 0.15)', col: '#fbbf24' },
    { title: 'Low Severity Alerts', val: shortNum(severityCount('low')), sub: 'Current window', subCol: '#34d399', icon: '🛡️', iconBg: 'rgba(56, 189, 248, 0.15)', col: '#38bdf8' },
    { title: 'Affected Endpoints', val: shortNum(affectedEndpoints), sub: 'Unique reporting hosts', subCol: '#a78bfa', icon: '💻', iconBg: 'rgba(167, 139, 250, 0.15)', col: '#a78bfa' },
    { title: 'Unique Techniques', val: shortNum(uniqueTechniques), sub: 'Observed mappings', subCol: '#34d399', icon: '🖐️', iconBg: 'rgba(52, 211, 153, 0.15)', col: '#34d399' },
  ];

  const techniquesGrid = [
    { title: 'New Scheduled Tasks', count: countWords(['scheduled task', 'schtasks']), sub: 'Agent telemetry', icon: '📅', col: '#a78bfa', sparkCol: '#f87171' },
    { title: 'New Services Installed', count: countWords(['service created', 'service installed']), sub: 'Agent telemetry', icon: '⚙️', col: '#fbbf24', sparkCol: '#fb923c' },
    { title: 'New User Accounts', count: countWords(['new user', 'user created', 'account created']), sub: 'Agent telemetry', icon: '👤', col: '#fbbf24', sparkCol: '#fbbf24' },
    { title: 'Registry Changes', count: countWords(['registry', 'run key', 'runonce']), sub: 'Agent telemetry', icon: '📦', col: '#34d399', sparkCol: '#34d399' },
    { title: 'WMI Persistence Events', count: countWords(['wmi', 'event consumer']), sub: 'Agent telemetry', icon: '🪟', col: '#38bdf8', sparkCol: '#38bdf8' },
    { title: 'PowerShell Activity', count: countWords(['powershell', 'profile.ps1']), sub: 'Agent telemetry', icon: '⚡', col: '#a78bfa', sparkCol: '#a78bfa' },
    { title: 'SSH Key Changes', count: countWords(['authorized_keys', 'ssh key']), sub: 'Agent telemetry', icon: '🔑', col: '#22d3ee', sparkCol: '#22d3ee' },
    { title: 'Driver Installations', count: countWords(['driver', 'kernel module', 'modprobe']), sub: 'Agent telemetry', icon: '🔌', col: '#34d399', sparkCol: '#34d399' },
    { title: 'Startup Item Changes', count: countWords(['startup', 'launchagent', 'launchdaemon']), sub: 'Agent telemetry', icon: '⚡', col: '#ec4899', sparkCol: '#ec4899' },
    { title: 'Cron Job Changes', count: countWords(['cron', 'crontab', 'systemd timer']), sub: 'Agent telemetry', icon: '⏰', col: '#fb923c', sparkCol: '#fb923c' },
    { title: 'Browser Extension Changes', count: countWords(['browser extension', 'browser_extension']), sub: 'Agent telemetry', icon: '🌐', col: '#38bdf8', sparkCol: '#38bdf8' },
    { title: 'Cloud Persistence Alerts', count: countWords(['cloud persistence', 'kubernetes cronjob']), sub: 'Agent telemetry', icon: '☁️', col: '#a78bfa', sparkCol: '#a78bfa' },
  ];

  const recentAlerts = alerts.slice(0, 5).map(row => ({
    id: recordId(row), time: alertTime(row) ? new Date(alertTime(row)).toLocaleString() : 'Unknown',
    sev: alertSeverity(row), sevCol: SEV_COLOR[alertSeverity(row)] || '#38bdf8', tech: persistTechnique(row),
    desc: row.description || row.detectionReason || 'Persistence event', host: alertHost(row), src: row.source || 'Agent',
  }));
  const topEndpoints = topCounts(alerts, alertHost, 5).map(([name, count]) => ({ name, count }));
  const mitreTechniques = topCounts(alerts, row => row.mitreId || row.mitreTechnique || persistTechnique(row), 5)
    .map(([id, count]) => ({ id, name: alerts.find(row => (row.mitreId || row.mitreTechnique || persistTechnique(row)) === id)?.technique || id, count }));

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

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <PersistenceAlertsOverTimeChart alerts={alerts} />
        </div>
        <div style={panelStyle}>
          <AlertsByPersistenceCategoryDonut alerts={alerts} />
        </div>
        <div style={panelStyle}>
          <AlertsBySeverityDonut alerts={alerts} />
        </div>
      </div>

      {/* 3. MIDDLE SECTION (12 Grid Cards: 2 Rows x 6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        {techniquesGrid.map(tg => (
          <div key={tg.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', padding: 10 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 14 }}>{tg.icon}</span>
              <span style={{ fontSize: 9.5, fontWeight: 700, color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{tg.title}</span>
            </div>
            <div style={{ fontSize: 20, fontWeight: 800, color: '#ffffff', margin: '6px 0 2px 0' }}>
              {tg.count}
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
              <span style={{ fontSize: 9, fontWeight: 700, color: tg.col }}>{tg.sub}</span>
              <div style={{ height: 16, width: 45 }}>
                <MiniSparkline data={buildBuckets(alerts, 7, 24 * 7)} color={tg.sparkCol} height={16} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 4. BOTTOM GRID (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 12 }}>
        {/* Panel 1: Recent Persistence Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent Persistence Alerts</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all alerts</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 0.9fr 1.4fr 0.9fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>Severity</span>
              <span>Technique</span>
              <span>Description</span>
              <span>Endpoint / User</span>
              <span>Source</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {recentAlerts.map(ra => (
                <div key={ra.id} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 0.9fr 1.4fr 0.9fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                  <span style={{ color: '#64748b', fontSize: 8.5 }}>{ra.time}</span>
                  <span style={{ color: ra.sevCol, fontWeight: 700 }}>{ra.sev}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ra.tech}</span>
                  <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ra.desc}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 9 }}>{ra.host}</span>
                  <span style={{ color: '#8ea0b8' }}>{ra.src}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Panel 2: Top Affected Endpoints */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>
            Top Affected Endpoints
          </span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
            <span>Endpoint</span>
            <span>Alerts</span>
            <span>Trend (7 Days)</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {topEndpoints.map(ep => (
              <div key={ep.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                <span style={{ color: '#cbd5e1', fontWeight: 600, fontFamily: 'monospace', fontSize: 9 }}>{ep.name}</span>
                <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{ep.count}</span>
                <div style={{ height: 16, width: '100%' }}>
                  <MiniSparkline data={buildBuckets(alerts.filter(row => alertHost(row) === ep.name), 7, 24 * 7)} color="#f87171" height={16} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Panel 3: Top Persistence Techniques (MITRE ATT&CK) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Persistence Techniques (MITRE ATT&CK)</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.6fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Technique</span>
              <span>Name</span>
              <span style={{ textAlign: 'right' }}>Alerts</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {mitreTechniques.map(mt => (
                <div key={mt.id} style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.6fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#38bdf8', fontWeight: 700, fontSize: 9 }}>{mt.id}</span>
                  <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{mt.name}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{mt.count}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all →</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`PersistenceMechanismDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function PersistenceMechanismDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction }) {
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
  const osCounts = rows.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);

  // 20 Persistence Specific SOC Categories & Metrics matching User Requirements
  const regAutorun = rows.filter(r => containsAny(r, ['run', 'runonce', 'autorun', 'bho', 'ifeo', 'appinit', 'winlogon'])).length;
  const tasksCron = rows.filter(r => containsAny(r, ['scheduled task', 'schtasks', 'cron', 'crontab', 'systemd timer'])).length;
  const servicesSystemd = rows.filter(r => containsAny(r, ['service', 'systemd', 'init.d', 'rc.local'])).length;
  const userAccounts = rows.filter(r => containsAny(r, ['new user', 'privilege escalation', 'sudoers', 'hidden user'])).length;
  const dllHijacking = rows.filter(r => containsAny(r, ['dll hijacking', 'search order', 'side-loading', 'unsigned dll'])).length;
  const wmiEvents = rows.filter(r => containsAny(r, ['wmi', 'event consumer', 'event filter'])).length;
  const powershellPersist = rows.filter(r => containsAny(r, ['powershell', 'encoded command', 'profile.ps1'])).length;
  const sshKeys = rows.filter(r => containsAny(r, ['authorized_keys', 'ssh key', 'sshd_config'])).length;
  const browserExt = rows.filter(r => containsAny(r, ['browser extension', 'startup page', 'add-on'])).length;
  const driverKernel = rows.filter(r => containsAny(r, ['driver', 'kernel module', 'insmod', 'modprobe'])).length;
  const cloudContainer = rows.filter(r => containsAny(r, ['docker', 'k8s', 'kubernetes', 'pod', 'cronjob'])).length;
  const macLaunch = rows.filter(r => containsAny(r, ['launch agent', 'launch daemon', 'plist', 'login item'])).length;

  const kpis = [
    { label: '🛡️ 1. Total Persistence Alerts Count', val: shortNum(totalRows), trend: 'Autostart Signals', color: MON.blue, data: timeline },
    { label: '⏱️ 2. New Scheduled Tasks (Schtasks/Cron)', val: shortNum(tasksCron), trend: 'Tasks/Cron', color: MON.red, data: timeline },
    { label: '🛠️ 3. New Services Installed (Services/Systemd)', val: shortNum(servicesSystemd), trend: 'Service Installed', color: MON.purple, data: timeline },
    { label: '👤 4. New User Accounts & Privilege Grants', val: shortNum(userAccounts), trend: 'User Created', color: MON.orange, data: timeline },
    { label: '⚙️ 5. Registry Persistence Events (Run Keys)', val: shortNum(regAutorun), trend: 'Run Key', color: MON.red, data: timeline },
    { label: '🔮 6. WMI Persistence Events (Event Consumer)', val: shortNum(wmiEvents), trend: 'WMI Consumer', color: MON.yellow, data: timeline },
    { label: '🔑 7. SSH Key Changes (authorized_keys)', val: shortNum(sshKeys), trend: 'SSH Key', color: MON.cyan, data: timeline },
    { label: '⚡ 8. PowerShell Suspicious Persistence', val: shortNum(powershellPersist), trend: 'Encoded PS', color: MON.purple, data: timeline },
    { label: '🧩 9. Driver & Kernel Module Installations', val: shortNum(driverKernel), trend: 'Driver Load', color: MON.pink, data: timeline },
    { label: '🚀 10. Startup Item & Folder Modifications', val: shortNum(rows.filter(r => containsAny(r, ['startup folder', 'shell', 'userinit'])).length), trend: 'Startup Item', color: MON.orange, data: timeline },
    { label: '📆 11. Cron Job & Systemd Timer Changes', val: shortNum(rows.filter(r => containsAny(r, ['cron', 'crontab'])).length), trend: 'Cron Edit', color: MON.green, data: timeline },
    { label: '🧩 12. DLL Search Order & Sideload Hijacking', val: shortNum(dllHijacking), trend: 'DLL Sideload', color: MON.yellow, data: timeline },
    { label: '🌐 13. Browser Extension & Plugin Changes', val: shortNum(browserExt), trend: 'Browser Addon', color: MON.cyan, data: timeline },
    { label: '☁️ 14. Cloud & Kubernetes Cronjob Persistence', val: shortNum(cloudContainer), trend: 'K8s/Docker', color: MON.purple, data: timeline },
    { label: '🍎 15. macOS Launch Agents & Daemons', val: shortNum(macLaunch), trend: 'LaunchDaemon', color: MON.blue, data: timeline },
    { label: '🪟 16. Windows Autostart Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows Sysmon', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux Cron & Systemd Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux Auditd', color: MON.orange, data: timeline },
    { label: '🍎 18. macOS Monitored Endpoints', val: shortNum(osCounts.macOS || 0), trend: 'macOS Sensor', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Persistence Threats', val: shortNum(sevCounts.critical || 0), trend: 'Critical Threat', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk Autostart Alterations', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
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
      monitor: hostEvents > 0,
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
      </aside>

      {/* Main Container */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>
        {activeTab === 'log-monitor' ? (
          <PersistenceLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={8} alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <PersistenceOverviewDashboard alerts={alerts} total={totalRows} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Persistence Mechanism Audit Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(row => row.monitor).length} endpoints reporting persistence telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Autostart Driver</span><span>Signals</span><span>Persistence Alerts</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.monitor ? 'Reporting' : 'Awaiting telemetry'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend persistence agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Persistence Activity Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} persistence events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Top Persistence Techniques</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, persistTechnique, 5).map(([tech, count], index) => (
                    <div key={tech} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>🛡️ {tech}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Persistence Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Registry Run Keys', regAutorun],
                    ['Scheduled Tasks & Cron', tasksCron],
                    ['Services & Systemd', servicesSystemd],
                    ['WMI & PowerShell', wmiEvents + powershellPersist],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`PersistenceMechanismPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function PersistenceMechanismPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/persistence/events', {
        params: { page: 1, limit: 1000, windowHours: 24 },
        skipCache: true,
      });
      const next = r.data?.events || r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
    } catch {
      setAlerts([]);
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
    const interval = setInterval(() => loadAlerts(true), 60000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const onPersistenceEvent = event => {
      if (!event || (Number(event.capabilityId) !== 8 && !(event.capabilityIds || []).map(Number).includes(8))) return;
      setAlerts(current => {
        const exists = current.some(row => recordId(row) === recordId(event));
        if (!exists) setTotal(value => value + 1);
        return [event, ...current.filter(row => recordId(row) !== recordId(event))].slice(0, 1000);
      });
    };
    socket.on('connect', join);
    socket.on('alert:new', onPersistenceEvent);
    socket.on('persistence:event', onPersistenceEvent);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', onPersistenceEvent);
      socket.off('persistence:event', onPersistenceEvent);
      disc();
    };
  }, [companyId]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 8. Persistence Mechanism Detection
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <PersistenceMechanismDashboard alerts={alerts} loading={loading} total={total} systems={systems} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <PersistenceMechanismPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function PersistenceSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=8" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Persistence SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=8')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="persistence" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <PersistenceMechanismDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { PersistenceMechanismDashboard as PersistenceMechanismDashboardPanel };
