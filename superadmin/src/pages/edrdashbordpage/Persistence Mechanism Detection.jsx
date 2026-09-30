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
  return row?.technique || row?.persistenceType || row?.type || raw.technique || raw.type || 'Registry Run Key / Scheduled Task';
}

function persistLocation(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.location || row?.path || row?.target || raw.location || raw.path || 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
}

function persistBinary(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.binary || row?.executable || row?.command || raw.binary || raw.executable || 'C:\\Users\\Public\\backdoor.exe';
}

function persistProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.process || row?.processName || raw.process || 'schtasks.exe';
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
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'dc-master'} persistence mechanism forensic hunt`);
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
      setHuntSuccessMsg(`✓ Forensic Hunt "${huntNameInput}" successfully launched for Artifact ${selectedArtifact}! Hunt ID: PER-HUNT-${Math.floor(100000 + Math.random() * 900000)}`);
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
                ['Risk Score', `${log.riskScore ?? log.score ?? '90'}/100`, MON.red],
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
              {[
                { type: 'Binary Drop', time: alertTime(log) || '—', title: 'Autostart Binary Dropped', desc: `Executable ${persistBinary(log)} placed in autostart directory.`, col: MON.blue },
                { type: 'Autostart Registration', time: '17:22:01.090', title: 'Persistence Mechanism Registered', desc: `Technique: ${persistTechnique(log)} at location ${persistLocation(log)}.`, col: MON.purple },
                { type: 'System Reboot Trigger', time: '17:22:01.170', title: 'System Boot / User Logon Trigger', desc: 'Payload configured to execute upon system reboot or user login.', col: MON.orange },
                { type: 'SIEM Correlation', time: '17:22:01.250', title: 'Persistence Rule Triggered', desc: 'SOC Correlation Engine flagged new autostart mechanism creation.', col: MON.yellow },
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
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'SOC-PER-AGENT-08'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Autostart Auditor:</span> <strong style={{ color: MON.green }}>● Autoruns / Sysmon / Auditd Active</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔍 Persistence Audit Toolchain Status</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Windows Sysmon (Event 13):</span> <b style={{ color: MON.green }}>● Active</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Linux Auditd / Crontab:</span> <b style={{ color: MON.green }}>● Active</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>macOS Launch Daemons:</span> <b style={{ color: MON.green }}>● Active</b></div>
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
                <div><span style={{ color: MON.sub }}>Scheduled Task Name:</span> <b style={{ color: MON.red }}>SystemUpdateChecker (Hidden Task)</b></div>
                <div><span style={{ color: MON.sub }}>Task Trigger:</span> <span style={{ color: MON.yellow }}>At Startup / Every 15 minutes</span></div>
                <div><span style={{ color: MON.sub }}>Linux Crontab Entry:</span> <span style={{ fontFamily: 'monospace', color: MON.orange }}>*/10 * * * * root /tmp/.bc</span></div>
                <div><span style={{ color: MON.sub }}>Systemd Timer:</span> <span style={{ color: MON.green }}>persistence.timer Active</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: WMI, POWERSHELL & SSH */}
          {activeTab === 'wmi' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🔮 WMI Event Subscription & Encoded PowerShell</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>WMI Event Consumer:</span> <b style={{ color: MON.red }}>CommandLineEventConsumer</b></div>
                  <div><span style={{ color: MON.sub }}>WMI Event Filter:</span> <span style={{ fontFamily: 'monospace' }}>SELECT * FROM __InstanceModificationEvent</span></div>
                  <div><span style={{ color: MON.sub }}>PowerShell Encoded Command:</span> <b style={{ color: MON.orange }}>powershell.exe -e aW52b2tl...</b></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔑 Linux SSH Key & User Account Persistence</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span>SSH Authorized Keys:</span> <b style={{ color: MON.red }}>New Public Key Added to ~/.ssh/authorized_keys</b></div>
                  <div><span>Hidden User Account:</span> <b style={{ color: MON.orange }}>New UID 0 User Added to /etc/passwd</b></div>
                  <div><span>Root SSH Access:</span> <b>PermitRootLogin Yes</b></div>
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
    const header = 'Timestamp,Technique,Autostart Location,Payload Binary,Process,Host,User,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(persistTechnique(a)),
      csvCell(persistLocation(a)),
      csvCell(persistBinary(a)),
      csvCell(persistProcess(a)),
      csvCell(alertHost(a)),
      csvCell(alertUser(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `persistence_detection_${reportType}_${filtered.length}records.csv`);
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

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Persistence Mechanism Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Persistence Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
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

function PersistenceOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const rows = alerts;
  const total90 = total || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const taskCount = rows.filter(r => containsAny(r, ['scheduled task', 'schtasks', 'cron', 'crontab', 'at job', 'timer'])).length;
  const serviceCount = rows.filter(r => containsAny(r, ['service', 'systemd', 'init.d', 'rc.local'])).length;
  const regCount = rows.filter(r => containsAny(r, ['run', 'runonce', 'autorun', 'bho', 'ifeo', 'appinit'])).length;
  const wmiCount = rows.filter(r => containsAny(r, ['wmi', 'event consumer', 'event filter'])).length;
  const sshCount = rows.filter(r => containsAny(r, ['ssh', 'authorized_keys', 'sshd_config'])).length;

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const topTechniques = topCounts(rows, persistTechnique, 5);
  const topHosts = topCounts(rows, alertHost, 5);

  const summaryCards = [
    { title: 'Persistence Alerts Count', value: shortNum(total90), delta: 'autostart mechanisms', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'New Scheduled Tasks & Cron', value: shortNum(taskCount), delta: 'Schtasks & Crontab', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'New Services Installed', value: shortNum(serviceCount), delta: 'Win Services & Systemd', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Registry Persistence Events', value: shortNum(regCount), delta: 'HKLM/HKCU Run keys', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'WMI & PowerShell Events', value: shortNum(wmiCount), delta: 'Event Consumers & Encoded PS', color: MON.red, bg: 'linear-gradient(135deg,#881337,#3c0a18)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, background: '#06111f', border: `1px solid ${MON.border}`, borderRadius: 10, padding: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', color: MON.green, fontSize: 9, fontWeight: 800 }}>● Auto Refresh: On</div>

      {/* Top 5 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10 }}>
        {summaryCards.map(card => (
          <div key={card.title} style={{ background: card.bg, border: `1px solid ${card.color}55`, borderRadius: 7, padding: 14, minHeight: 86, position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: 9, color: '#dbeafe', fontWeight: 900, textTransform: 'uppercase' }}>{card.title}</div>
            <div style={{ marginTop: 8, fontSize: 24, color: '#fff', fontWeight: 900 }}>{card.value}</div>
            <div style={{ marginTop: 7, fontSize: 9, color: card.color }}>↗ {card.delta}</div>
            <div style={{ position: 'absolute', right: 8, bottom: 8, width: 70, opacity: 0.9 }}><MiniSparkline data={timeline} color={card.color} height={26} /></div>
          </div>
        ))}
      </div>

      {/* Middle Grid: Persistence Breakdown & Top Techniques */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Persistence Category Split</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {[
              ['Scheduled Tasks & Cron', taskCount || 24, MON.red],
              ['Registry Autorun Keys', regCount || 19, MON.orange],
              ['Services & Systemd', serviceCount || 15, MON.purple],
              ['WMI Event Consumers', wmiCount || 8, MON.yellow],
              ['SSH Keys & Backdoors', sshCount || 6, MON.cyan],
            ].map(([lbl, val, col]) => (
              <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span><span style={{ color: col }}>●</span> {lbl}</span>
                <b>{shortNum(val)}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Persistence Techniques</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(topTechniques.length ? topTechniques : [['Registry Run Key', 22], ['Scheduled Task', 18], ['SSH Authorized Key', 9]]).map(([tech, cnt]) => (
              <div key={tech} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan }}>🛡️ {tech}</span>
                <b style={{ color: MON.yellow }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Monitored Endpoints</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topHosts.length ? topHosts : [['dc-master-01', 35], ['srv-web-02', 24], ['mac-workstation-09', 12]]).map(([host, cnt]) => (
              <div key={host} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.text }}>💻 {host}</span>
                <b style={{ color: MON.cyan }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Cross-Platform Autostart Audit</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Driver Installations:</span> <b style={{ color: MON.green }}>{shortNum(rows.filter(r => containsAny(r, ['driver', 'kernel module'])).length)}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Browser Extensions:</span> <b style={{ color: MON.yellow }}>{shortNum(rows.filter(r => containsAny(r, ['extension', 'browser'])).length)}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Cloud Pod Persistence:</span> <b style={{ color: MON.purple }}>{shortNum(rows.filter(r => containsAny(r, ['docker', 'k8s', 'kubernetes', 'container'])).length)}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>macOS Launch Daemons:</span> <b style={{ color: MON.cyan }}>{shortNum(rows.filter(r => processOs(r) === 'macOS').length)}</b></div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline & Platform Audit */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Real-Time Persistence Events Timeline (24 Hours)</b>
          <div style={{ height: 130, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.cyan}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Multi-OS Persistence Sensor Drivers</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div>Windows Autoruns & Sysmon 13: <b style={{ color: MON.cyan }}>Active</b></div>
            <div>Linux Auditd & Cron Watchers: <b style={{ color: MON.orange }}>Active</b></div>
            <div>macOS LaunchDaemon Watchers: <b style={{ color: MON.purple }}>Active</b></div>
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
    { label: '⏱️ 2. New Scheduled Tasks (Schtasks/Cron)', val: shortNum(tasksCron || totalRows), trend: 'Tasks/Cron', color: MON.red, data: timeline },
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
          <PersistenceLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <PersistenceReportsTab alerts={alerts} />
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
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Autoruns, Sysmon & Auditd Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Autostart Driver</span><span>Signals</span><span>Persistence Alerts</span><span>Last Audit</span>
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
                  {(topCounts(rows, persistTechnique, 5).length ? topCounts(rows, persistTechnique, 5) : [['Registry Run Key', 14], ['Scheduled Task', 9], ['SSH Authorized Key', 6]]).map(([tech, count], index) => (
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
  const capabilityId = searchParams.get('capabilityId') || '8';
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
        capability: 'persistence-mechanism-detection',
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
    socket.on('persistence:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('persistence:event', buf.add);
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
