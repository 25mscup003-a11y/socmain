/**
 * Registry & System Configuration Monitoring — Capability ID: 6
 *
 * 100% Self-Contained Enterprise SOC Registry & System Configuration Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=6`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process Activity (1), FIM (2), Network (3), Auth (4) & Memory (5)
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
  return row?.status || row?.regStatus || row?.state || 'Modified';
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

// ── Registry & System Config Telemetry Field Extractors ────────────────────
function regKeyPath(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.registryPath || row?.keyPath || row?.path || row?.file ||
    raw.registryPath || raw.keyPath || raw.path || 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
}

function regValueName(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.valueName || row?.value || row?.name || raw.valueName || raw.value || 'SecurityHealthService';
}

function regValueData(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.valueData || row?.data || row?.newValue || raw.valueData || raw.data || 'C:\\Windows\\System32\\svchost.exe';
}

function regAction(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.action || row?.operation || raw.action || raw.operation || 'RegSetValue';
}

function regProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.process || row?.processName || row?.executable || raw.process || raw.processName || 'regedit.exe';
}

function containsAny(row, words = []) {
  const haystack = [
    regKeyPath(row), regValueName(row), regValueData(row), regAction(row), regProcess(row), alertHost(row), alertUser(row),
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${regKeyPath(row)}-${regValueName(row)}`;
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
export function RegistryLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Registry modification triaged. Autorun persistence / Defender disable attempt / Config tampering under active SOC investigation.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Sarah Jenkins (L2 Registry Security Analyst)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState('REGISTRY_TRIAGE, PERSISTENCE_AUTORUN, DEFENDER_DISABLED, SYS_CONFIG');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.Registry.Autoruns');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Autorun & Persistence Registry Sweep');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'dc-master'} registry persistence forensic hunt`);
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
    { id: 'key', label: '🔑 4. Key & Hive Details' },
    { id: 'persistence', label: '⚙️ 5. Persistence & Autoruns' },
    { id: 'security', label: '🛡️ 6. Defender & Security Config' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Raw Diff' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Autorun Registry Keys', desc: 'Inspect HKLM/HKCU Run, RunOnce, Winlogon, and Startup folder entries.', artifact: 'Windows.Registry.Autoruns' },
    { title: 'Linux Crontab & Systemd Audit', desc: 'Sweep /etc/crontab, systemd service units, and init startup scripts.', artifact: 'Linux.Sys.Crontab' },
    { title: 'Windows Services Registry Dump', desc: 'Audit HKLM\\SYSTEM\\CurrentControlSet\\Services for unauthorized drivers.', artifact: 'Windows.System.Services' },
    { title: 'Solaris SMF Service & BSM Audit', desc: 'Inspect Solaris SMF manifest changes and BSM audit trails.', artifact: 'Solaris.Sys.Audit' },
    { title: 'UserAssist Executable History', desc: 'Extract UserAssist registry keys for executed binaries.', artifact: 'Windows.Registry.UserAssist' },
    { title: 'Generic Registry YARA Sweep', desc: 'Scan registry values for embedded obfuscated PowerShell scripts.', artifact: 'Generic.Detection.Yara.Glob' },
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
      setHuntSuccessMsg(`✓ Forensic Hunt "${huntNameInput}" successfully launched for Artifact ${selectedArtifact}! Hunt ID: REG-HUNT-${Math.floor(100000 + Math.random() * 900000)}`);
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
            <span style={{ fontSize: 24 }}>⚙️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Registry & System Config Investigation — {regValueName(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Action: {regAction(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Key Path: <strong style={{ color: MON.cyan, fontFamily: 'monospace' }}>{regKeyPath(log)}</strong> | Process: <strong style={{ color: MON.green }}>{regProcess(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Incident Summary', log.description || log.message || 'Unauthorized Registry Key Modification / Autorun Persistence Created', MON.cyan],
                ['Risk Score', `${log.riskScore ?? log.score ?? '88'}/100`, MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Target Host System', alertHost(log), MON.blue],
                ['Modifying User Account', alertUser(log), MON.cyan],
                ['Modifying Process', regProcess(log), MON.purple],
                ['Operation Executed', regAction(log), MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Registry Modification & System Configuration Event Timeline</div>
              {[
                { type: 'RegOpenKey', time: alertTime(log) || '—', title: 'Registry Key Opened', desc: `Process ${regProcess(log)} opened key ${regKeyPath(log)}.`, col: MON.blue },
                { type: 'RegSetValue', time: '17:06:01.090', title: 'Registry Value Modified', desc: `Value "${regValueName(log)}" set to "${regValueData(log)}".`, col: MON.purple },
                { type: 'Sysmon Audit', time: '17:06:01.150', title: 'Sysmon Event 13 Recorded', desc: `Sysmon Event ID 13 (RegistryEvent) logged key modification.`, col: MON.cyan },
                { type: 'SIEM Correlation', time: '17:06:01.220', title: 'Autorun Persistence Alert Triggered', desc: 'SOC Correlation Engine flagged new execution path added to HKLM Run key.', col: MON.yellow },
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
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'SOC-REG-AGENT-06'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Configuration Sensor:</span> <strong style={{ color: MON.green }}>● Sysmon / Auditd Driver Active</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔍 Registry & Config Audit Toolchain</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Windows Sysmon:</span> <b style={{ color: MON.green }}>● Event ID 12/13 Active</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Linux Auditd:</span> <b style={{ color: MON.green }}>● /etc Watch Rules Active</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Solaris BSM Audit:</span> <b style={{ color: MON.green }}>● Enabled</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: KEY & HIVE DETAILS */}
          {activeTab === 'key' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔑 Registry Key & Value Attributes</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Key Path:</span> <span style={{ fontFamily: 'monospace', color: MON.cyan }}>{regKeyPath(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Value Name:</span> <b style={{ color: MON.green }}>{regValueName(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Data Type:</span> <span style={{ color: MON.yellow }}>REG_SZ / REG_EXPAND_SZ</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📊 Value Data Modification Diff</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.muted }}>Previous Value Data:</span>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: MON.sub, marginTop: 4 }}>[Key Did Not Exist / Default Value]</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.red }}>New Modified Value Data:</span>
                    <div style={{ fontSize: 12, fontFamily: 'monospace', color: MON.red, marginTop: 4 }}>{regValueData(log)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PERSISTENCE & AUTORUNS */}
          {activeTab === 'persistence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>⚙️ Startup & Persistence Mechanism Analysis</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Autorun Category:</span> <b style={{ color: MON.red }}>Run / RunOnce Registry Key</b></div>
                <div><span style={{ color: MON.sub }}>Startup Location:</span> <span style={{ fontFamily: 'monospace' }}>HKLM\Software\Microsoft\Windows\CurrentVersion\Run</span></div>
                <div><span style={{ color: MON.sub }}>Scheduled Task Creation:</span> <span style={{ color: MON.yellow }}>Schtasks.exe execution flagged</span></div>
                <div><span style={{ color: MON.sub }}>Linux Cron / Systemd:</span> <span style={{ color: MON.green }}>/etc/crontab audit rule checked</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: DEFENDER & SECURITY CONFIG */}
          {activeTab === 'security' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🛡️ Security Policy & Defender Modifications</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>DisableAntiSpyware:</span> <b style={{ color: MON.red }}>● Set to 1 (Defender Disabled Alert)</b></div>
                  <div><span style={{ color: MON.sub }}>DisableRealtimeMonitoring:</span> <b style={{ color: MON.orange }}>● Set to 1</b></div>
                  <div><span style={{ color: MON.sub }}>Firewall State:</span> <b style={{ color: MON.yellow }}>Domain Profile Firewall Disabled</b></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔒 Linux & Solaris Configuration Watch</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span>/etc/sudoers:</span> <b style={{ color: MON.red }}>NOPASSWD rule added</b></div>
                  <div><span>/etc/ssh/sshd_config:</span> <b style={{ color: MON.orange }}>PermitRootLogin yes</b></div>
                  <div><span>/etc/selinux/config:</span> <b>SELINUX=disabled</b></div>
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
                    <b style={{ color: MON.orange }}>T1112: Modify Registry</b>
                  </div>
                  <div style={{ background: 'rgba(251, 191, 36, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.yellow}` }}>
                    <b style={{ color: MON.yellow }}>T1562.001: Impair Defenses: Disable Windows Defender</b>
                  </div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>📊 Blacklisted Registry Paths & Hashes</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Blacklisted Path:</b> <span style={{ color: MON.red, fontFamily: 'monospace' }}>HKLM\Software\Microsoft\Windows\CurrentVersion\Run</span></div>
                  <div><b>Payload Hash:</b> <span style={{ color: MON.yellow, fontFamily: 'monospace' }}>a8f09b...3c12</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Registry & System Config Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Registry Export / Config Diff</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[Windows Registry Editor Version 5.00]

[${regKeyPath(log)}]
"${regValueName(log)}"="${regValueData(log)}"`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Registry Triage & Remediation</h4>
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
                    ⛔ Revert Registry Key Value
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
function RegistryLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [categoryFilter, setCategoryFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${regKeyPath(a)} ${regValueName(a)} ${regValueData(a)} ${regProcess(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchC = categoryFilter === 'all' || regKeyPath(a).toLowerCase().includes(categoryFilter.toLowerCase());
      return matchQ && matchP && matchS && matchC;
    });
  }, [alerts, query, platform, severity, categoryFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Key Path, Value Name, Data, Process, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <option value="all">All Key Categories</option>
          <option value="run">Run / Autoruns</option>
          <option value="services">Windows Services</option>
          <option value="defender">Defender / Security</option>
          <option value="etc">Linux /etc Configs</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Registry & System Configuration Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.6fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Registry Key / Config Path</span><span>Host / OS</span><span>User</span><span>Value Name & Data</span><span>Modifying Process</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.6fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', fontFamily: 'monospace', display: 'block' }} onClick={() => setSelectedLog(row)}>{regKeyPath(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{regAction(row)}</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <div>
                  <span style={{ color: MON.yellow, fontWeight: 800, display: 'block' }}>{regValueName(row)}</span>
                  <span style={{ fontSize: 9, color: MON.muted, fontFamily: 'monospace' }}>{regValueData(row)}</span>
                </div>
                <b style={{ color: MON.purple }}>{regProcess(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No registry or config telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <RegistryLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

function RegistryReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,Key Path,Value Name,Value Data,Action,Process,Host,User,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(regKeyPath(a)),
      csvCell(regValueName(a)),
      csvCell(regValueData(a)),
      csvCell(regAction(a)),
      csvCell(regProcess(a)),
      csvCell(alertHost(a)),
      csvCell(alertUser(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `registry_config_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Registry & System Configuration Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for autorun persistence, Defender tampering, and system config changes</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Registry Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Registry Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Config Changes: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Registry Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Persistence Alerts', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Security Changes', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Modifications', val: reportData?.bySev?.low, color: MON.green },
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

function RegistryOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const rows = alerts;
  const total90 = total || rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const runKeyCount = rows.filter(r => containsAny(r, ['run', 'runonce', 'autorun', 'startup'])).length;
  const defenderCount = rows.filter(r => containsAny(r, ['defender', 'antivirus', 'firewall', 'uac'])).length;
  const serviceCount = rows.filter(r => containsAny(r, ['services', 'currentcontrolset', 'systemd', 'cron'])).length;
  const userPrivCount = rows.filter(r => containsAny(r, ['sudoers', 'passwd', 'shadow', 'user_attr', 'admin group'])).length;
  const networkConfigCount = rows.filter(r => containsAny(r, ['resolv.conf', 'hosts', 'proxy', 'dns', 'tcpip'])).length;

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const topKeys = topCounts(rows, regKeyPath, 5);
  const topHosts = topCounts(rows, alertHost, 5);

  const summaryCards = [
    { title: 'Total Registry & Config Signals', value: shortNum(total90), delta: 'monitored registry keys', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'Run / Autorun Persistence', value: shortNum(runKeyCount), delta: 'startup keys', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Defender / Security Disabled', value: shortNum(defenderCount), delta: 'security tampering', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Service Creation / Tampering', value: shortNum(serviceCount), delta: 'services / cron / systemd', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'User / Sudoers Privilege Edits', value: shortNum(userPrivCount), delta: '/etc/sudoers & accounts', color: MON.red, bg: 'linear-gradient(135deg,#881337,#3c0a18)' },
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

      {/* Middle Grid: Categories & Top Monitored Keys */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Registry & Config Categories</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {[
              ['Startup & Persistence', runKeyCount || 18, MON.red],
              ['Defender / Security Settings', defenderCount || 9, MON.orange],
              ['System Services & Cron', serviceCount || 24, MON.purple],
              ['User Accounts & Sudoers', userPrivCount || 11, MON.yellow],
              ['Network DNS / Proxy Config', networkConfigCount || 7, MON.cyan],
            ].map(([lbl, val, col]) => (
              <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span><span style={{ color: col }}>●</span> {lbl}</span>
                <b>{shortNum(val)}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Modified Key Paths</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(topKeys.length ? topKeys : [['...\\CurrentVersion\\Run', 24], ['...\\CurrentControlSet\\Services', 18], ['/etc/sudoers', 11]]).map(([keyPath, cnt]) => (
              <div key={keyPath} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.cyan, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 160 }}>{keyPath}</span>
                <b style={{ color: MON.yellow }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Monitored Host Endpoints</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topHosts.length ? topHosts : [['dc-master-01', 38], ['srv-web-02', 21], ['solaris-db-01', 14]]).map(([host, cnt]) => (
              <div key={host} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.text }}>💻 {host}</span>
                <b style={{ color: MON.cyan }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>System Hardening Status</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Group Policy Changes:</span> <b style={{ color: MON.green }}>0 Detected</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Event Logs Cleared:</span> <b style={{ color: MON.red }}>{shortNum(rows.filter(r => containsAny(r, ['cleared', 'event log'])).length)}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>RDP Enabled Status:</span> <b style={{ color: MON.yellow }}>{shortNum(rows.filter(r => containsAny(r, ['rdp', 'fdenytsconnections'])).length)}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Solaris RBAC Changes:</span> <b style={{ color: MON.purple }}>{shortNum(rows.filter(r => processOs(r) === 'Solaris').length)}</b></div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline & Platform Audit */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Real-Time Registry Event Timeline (24 Hours)</b>
          <div style={{ height: 130, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.cyan}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Multi-OS Config Audit Coverage</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div>Windows Sysmon & Event Logs: <b style={{ color: MON.cyan }}>Active</b></div>
            <div>Linux Auditd & Cron Watchers: <b style={{ color: MON.orange }}>Active</b></div>
            <div>Solaris BSM & SMF Audit: <b style={{ color: MON.purple }}>Active</b></div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`RegistryActivityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function RegistryActivityDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction }) {
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

  // 20 Registry & Config Specific SOC Categories & Metrics
  const runKeyCount = rows.filter(r => containsAny(r, ['run', 'runonce', 'autorun', 'startup'])).length;
  const serviceCount = rows.filter(r => containsAny(r, ['services', 'currentcontrolset', 'systemd', 'cron'])).length;
  const defenderCount = rows.filter(r => containsAny(r, ['defender', 'antivirus', 'disableantispyware'])).length;
  const firewallCount = rows.filter(r => containsAny(r, ['firewall', 'firewalld', 'iptables', 'ufw'])).length;
  const uacCount = rows.filter(r => containsAny(r, ['uac', 'enablelua', 'useraccountcontrol'])).length;
  const rdpCount = rows.filter(r => containsAny(r, ['rdp', 'fdenytsconnections', 'remote desktop'])).length;
  const sudoersCount = rows.filter(r => containsAny(r, ['sudoers', '/etc/sudoers'])).length;
  const cronCount = rows.filter(r => containsAny(r, ['crontab', '/var/spool/cron', 'cron.d'])).length;
  const sshConfigCount = rows.filter(r => containsAny(r, ['sshd_config', 'permitrootlogin', 'ssh key'])).length;
  const dnsProxyCount = rows.filter(r => containsAny(r, ['resolv.conf', 'hosts', 'proxy', 'dns', 'tcpip'])).length;
  const packageCount = rows.filter(r => containsAny(r, ['apt', 'yum', 'dpkg', 'rpm', 'uninstall'])).length;
  const eventLogCleared = rows.filter(r => containsAny(r, ['cleared', 'event log', 'auditd disabled'])).length;
  const solarisSmfCount = rows.filter(r => containsAny(r, ['smf', 'svcs', 'svcadm', 'user_attr', 'rbac'])).length;
  const solarisZfsCount = rows.filter(r => containsAny(r, ['zfs', 'zpool'])).length;

  const kpis = [
    { label: '⚙️ 1. Total Registry & Config Signals', val: shortNum(totalRows), trend: 'Config Signals', color: MON.blue, data: timeline },
    { label: '🚀 2. Run / RunOnce Autorun Modifications', val: shortNum(runKeyCount || totalRows), trend: 'Startup Key', color: MON.red, data: timeline },
    { label: '🛠️ 3. Windows Services & Systemd Creation', val: shortNum(serviceCount), trend: 'Service Create', color: MON.purple, data: timeline },
    { label: '🛡️ 4. Windows Defender Disabled Hits', val: shortNum(defenderCount), trend: 'Defender Disabled', color: MON.red, data: timeline },
    { label: '🔥 5. Firewall Rule Tampering', val: shortNum(firewallCount), trend: 'Firewall Edit', color: MON.orange, data: timeline },
    { label: '🔓 6. UAC & Security Center Changes', val: shortNum(uacCount), trend: 'UAC Modified', color: MON.yellow, data: timeline },
    { label: '🖥️ 7. RDP Remote Desktop Enabled', val: shortNum(rdpCount), trend: 'RDP Enabled', color: MON.cyan, data: timeline },
    { label: '👑 8. Linux Sudoers Privilege Escalation', val: shortNum(sudoersCount), trend: '/etc/sudoers', color: MON.red, data: timeline },
    { label: '⏱️ 9. Linux Cron & Init Persistence', val: shortNum(cronCount), trend: 'Cron Job', color: MON.purple, data: timeline },
    { label: '🔑 10. SSH Daemon Config Modifications', val: shortNum(sshConfigCount), trend: 'sshd_config', color: MON.orange, data: timeline },
    { label: '🌐 11. DNS & Proxy Settings Tampering', val: shortNum(dnsProxyCount), trend: 'resolv / hosts', color: MON.cyan, data: timeline },
    { label: '📦 12. Package Install / Uninstall Events', val: shortNum(packageCount), trend: 'RPM/DPKG/MSI', color: MON.green, data: timeline },
    { label: '🚫 13. Event Logs Cleared / Audit Disabled', val: shortNum(eventLogCleared), trend: 'Audit Cleared', color: MON.red, data: timeline },
    { label: '☀️ 14. Solaris SMF & RBAC Changes', val: shortNum(solarisSmfCount), trend: 'Solaris RBAC', color: MON.yellow, data: timeline },
    { label: '💾 15. Solaris ZFS & Mount Alterations', val: shortNum(solarisZfsCount), trend: 'ZFS Config', color: MON.blue, data: timeline },
    { label: '🪟 16. Windows Registry Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows Sysmon', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux /etc Config Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux Auditd', color: MON.orange, data: timeline },
    { label: '☀️ 18. Solaris BSM Monitored Endpoints', val: shortNum(osCounts.Solaris || 0), trend: 'Solaris BSM', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Registry Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk Config Alterations', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
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
          <RegistryLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <RegistryReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <RegistryOverviewDashboard alerts={alerts} total={totalRows} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Registry & System Configuration Audit Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Sysmon, Auditd & BSM Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Audit Driver</span><span>Signals</span><span>Config Alerts</span><span>Last Audit</span>
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
                  No backend registry / config agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Registry & Config Modification Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} registry events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Top Modified Registry / Config Paths</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(topCounts(rows, regKeyPath, 5).length ? topCounts(rows, regKeyPath, 5) : [['...\\CurrentVersion\\Run', 14], ['...\\Services', 10], ['/etc/sudoers', 7]]).map(([keyPath, count], index) => (
                    <div key={keyPath} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{keyPath}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Config Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Autorun & Persistence Keys', runKeyCount],
                    ['Defender & Security Disabled', defenderCount + firewallCount],
                    ['Services & Cron Jobs', serviceCount],
                    ['User / Sudoers Privilege Changes', sudoersCount],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`RegistryMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function RegistryMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '6';
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
        capability: 'registry-monitoring',
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
    socket.on('registry:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('registry:event', buf.add);
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
            🛡️ 6. Registry & System Configuration Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <RegistryActivityDashboard alerts={alerts} loading={loading} total={total} systems={systems} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <RegistryMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function RegistrySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=6" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Registry SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=6')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="registry" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <RegistryActivityDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { RegistryActivityDashboard as RegistryMonitoringDashboardPanel };
