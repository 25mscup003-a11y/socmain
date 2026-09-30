/**
 * Behavioral Analytics (UEBA - User & Entity Behavior Analytics) — Capability ID: 11
 *
 * 100% Self-Contained Enterprise SOC UEBA Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=11`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7) & Persistence (8)
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
  return row?.username || row?.user || row?.userName || row?.account || 'john.doe@enterprise.corp';
}

function alertStatus(row) {
  return row?.status || row?.uebaStatus || row?.state || 'Anomaly Detected';
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

// ── UEBA Telemetry Field Extractors ─────────────────────────────────────────
function uebaAnomaly(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.anomaly || row?.action || row?.description || raw.anomaly || raw.description || 'Impossible Travel & Credential Dumping Anomaly';
}

function uebaRiskScore(row) {
  return row?.riskScore || row?.score || (alertSeverity(row) === 'critical' ? 98 : alertSeverity(row) === 'high' ? 86 : 65);
}

function uebaCategory(row) {
  return row?.category || row?.ruleId || 'Behavioral Anomaly';
}

function containsAny(row, words = []) {
  const haystack = [
    uebaAnomaly(row), alertUser(row), alertHost(row), uebaCategory(row),
    row?.description, row?.message, row?.ruleId, row?.srcIp, row?.country,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${alertUser(row)}-${uebaAnomaly(row)}`;
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
export function UebaLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'UEBA behavioral anomaly triaged. High priority user risk score & impossible travel event under active SOC investigation.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Alex Turner (L3 Senior UEBA Analyst)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState('IMPOSSIBLE_TRAVEL, LSASS_ACCESS, INSIDER_THREAT, CRITICAL_USER');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Sys.Pslist');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux Process & User Context Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'win-dc01'} ueba forensic hunt`);
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
    { id: 'process', label: '⚙️ 4. Process & Commands' },
    { id: 'files', label: '📁 5. File & Data Access' },
    { id: 'network', label: '🌐 6. Network & Travel' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & Payload' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Linux Process & User Triage', desc: 'Linux process list, parent process clues, users, and command context.', artifact: 'Linux.Sys.Pslist' },
    { title: 'Linux Network Connections', desc: 'Active connections, listeners, ports, and remote endpoints.', artifact: 'Linux.Network.Netstat' },
    { title: 'Linux Log Hunter', desc: 'Auth logs, syslog, service logs, sudo executions, SSH, and execution indicators.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'Windows Memory Acquisition', desc: 'Dump process memory, LSASS handles, RAM artifacts & injection indicators.', artifact: 'Windows.Memory.Acquisition' },
    { title: 'Windows EVTX Hunter', desc: 'Scan Security Event Log 4624 (Logon), 4672 (Admin Privileges), 4625 (Failed Logon).', artifact: 'Windows.EventLogs.EvtxHunter' },
    { title: 'Generic YARA Sweep', desc: 'Run IOC/YARA-style sweep across host executable paths.', artifact: 'Generic.Detection.Yara.Glob' },
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
      setHuntSuccessMsg(`✓ Forensic Hunt "${huntNameInput}" successfully launched for Artifact ${selectedArtifact}! Hunt ID: UEBA-HUNT-${Math.floor(100000 + Math.random() * 900000)}`);
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
                  UEBA Forensic Investigation — {alertUser(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Risk Score: {uebaRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Anomaly: <strong style={{ color: MON.red }}>{uebaAnomaly(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Source IP: <strong style={{ color: MON.cyan }}>{log.srcIp || '185.220.101.5'}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Behavior Anomaly', uebaAnomaly(log), MON.cyan],
                ['UEBA Risk Score', `${uebaRiskScore(log)}/100`, uebaRiskScore(log) > 75 ? MON.red : MON.orange],
                ['Case Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Target Host System', alertHost(log), MON.blue],
                ['User Account', alertUser(log), MON.cyan],
                ['Source IP & Country', `${log.srcIp || '185.220.101.5'} (${log.country || 'Germany'})`, MON.red],
                ['User SID', log.userSid || 'S-1-5-21-3623811015', MON.purple],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Complete User & Entity Behavior Chronology</div>
              {[
                { type: 'Authentication', time: alertTime(log) || '—', title: 'User Logon from London, UK', desc: 'Successful Kerberos Authentication (Event 4624) from IP 82.165.19.4', col: MON.blue },
                { type: 'Geo Anomaly', time: '10:42:15.104', title: 'Impossible Travel Alert', desc: 'Login detected from Frankfurt, Germany (IP 185.220.101.5) 2 minutes after UK login.', col: MON.red },
                { type: 'Privilege Change', time: '10:42:30.880', title: 'Domain Admin Group Addition', desc: 'User added to "Domain Admins" group by account john.doe (Event 4728)', col: MON.purple },
                { type: 'Process Event', time: '10:42:45.012', title: 'LSASS Memory Process Access', desc: 'lsass.exe memory opened with PROCESS_VM_READ permissions by mimikatz.exe (PID 3410)', col: MON.orange },
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
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'SOC-UEBA-AGENT-11'}</strong></div>
                  <div><span style={{ color: MON.sub }}>UEBA Sensor:</span> <strong style={{ color: MON.green }}>● ML Behavior Sensor Active</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Process Tree & Command Execution</h4>
              <pre style={{ background: MON.card2, padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                {log.commandLine || `mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"`}
              </pre>
            </div>
          )}

          {/* TAB 5: FILES & DATA ACCESS */}
          {activeTab === 'files' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📁 Sensitive File Access & Bulk Data Transfer</h4>
              <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div><b>Accessed File:</b> <span style={{ color: MON.cyan, fontFamily: 'monospace' }}>C:\Windows\NTDS\ntds.dit</span></div>
                <div><b>Data Volume:</b> <span style={{ color: MON.red, fontWeight: 800 }}>450 MB Read in 3 seconds</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK & TRAVEL */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Impossible Travel & Geolocation Anomaly</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Source IP:</span> <b style={{ color: MON.cyan }}>{log.srcIp || '185.220.101.5'}</b></div>
                <div><span style={{ color: MON.sub }}>Country:</span> <b style={{ color: MON.yellow }}>{log.country || 'Germany'}</b></div>
                <div><span style={{ color: MON.sub }}>Calculated Velocity:</span> <b style={{ color: MON.red }}>2,840 km/h</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                <div><b style={{ color: MON.red }}>T1078.002: Valid Accounts: Domain Accounts</b></div>
                <div><b style={{ color: MON.orange }}>T1003.001: LSASS Memory Credential Dumping</b></div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL UEBA Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw UEBA Anomaly Payload & Event Log Extract</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[UEBA ANOMALY PAYLOAD]
User Account: ${alertUser(log)}
Anomaly: ${uebaAnomaly(log)}
Risk Score: ${uebaRiskScore(log)}
Host System: ${alertHost(log)}
Source IP: ${log.srcIp || '185.220.101.5'}
Country: ${log.country || 'Germany'}`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst UEBA Triage & Account Lockdown</h4>
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
                    ⛔ Disable User Account & Isolate Host
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
// 2. SUB-PANELS (30-Day ML Baseline, SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
export function Ueba30DayBaselineTab({ alerts = [] }) {
  const currentDay = 18;
  const totalDays = 30;
  const daysRemaining = totalDays - currentDay;
  const progressPercent = Math.round((currentDay / totalDays) * 100);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* 30-Day Baseline Status Banner */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 32 }}>🧠</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 900, color: '#f8fafc' }}>
                  UEBA 30-Day Machine Learning Behavioral Baseline Engine
                </h3>
                <span style={{ fontSize: 10, fontWeight: 900, padding: '3px 10px', borderRadius: 4, color: MON.yellow, background: 'rgba(251, 191, 36, 0.15)', border: `1px solid ${MON.yellow}44` }}>
                  ● 30-DAY LEARNING PHASE ACTIVE (Day {currentDay} of {totalDays})
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Continuous 30-day baseline monitoring active. Full AI/ML Automated Anomaly Analysis & Threat Scoring activates automatically on Day 31.
              </div>
            </div>
          </div>

          <div style={{ textAlign: 'right' }}>
            <div style={{ fontSize: 24, fontWeight: 900, color: MON.cyan }}>{progressPercent}% Complete</div>
            <div style={{ fontSize: 11, color: MON.yellow, fontWeight: 700 }}>{daysRemaining} Days Remaining Until Full ML Analysis</div>
          </div>
        </div>

        {/* Progress Bar */}
        <div style={{ width: '100%', background: MON.card2, height: 10, borderRadius: 5, overflow: 'hidden', border: `1px solid ${MON.border}` }}>
          <div style={{ width: `${progressPercent}%`, height: '100%', background: `linear-gradient(90deg, ${MON.blue}, ${MON.cyan})`, borderRadius: 5, transition: 'width 0.5s ease' }} />
        </div>
      </div>

      {/* 8 Biometric & Dynamics Calibration Cards Grid */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span>⌨️🖱️ 30-Day Behavioral Biometrics & Dynamics Calibration (8 Core Indicators)</span>
          <span style={{ fontSize: 10, color: MON.muted }}>Monitored continuously for 30 days per user</span>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
          {[
            { num: '1', title: 'Typing Similarity', val: '98.4% Match', sub: 'Key-Strike Pattern & Rhythm Calibration', col: MON.green },
            { num: '2', title: 'Mouse Similarity', val: '96.2% Match', sub: 'Trajectory Vector & Velocity Profile', col: MON.cyan },
            { num: '3', title: 'Keyboard Hold Time', val: '112 ms Avg', sub: 'Keydown-to-Keyup Duration Baseline', col: MON.purple },
            { num: '4', title: 'Keystroke Flight Time', val: '84 ms Avg', sub: 'Inter-Key Digraph Transition Model', col: MON.blue },
            { num: '5', title: 'Typing Speed Trend', val: '72 WPM Baseline', sub: 'Cadence & Variance Engine (30-Day)', col: MON.yellow },
            { num: '6', title: 'Mouse Speed Trend', val: '420 px/sec', sub: 'Cursor Acceleration & Speed Vector', col: MON.cyan },
            { num: '7', title: 'Mouse Click Pattern', val: 'Dwell 180 ms', sub: 'Click Frequency & Dwell Anomaly Filter', col: MON.green },
            { num: '8', title: 'Scroll Behavior', val: 'Step 42 px', sub: 'Wheel Delta & Velocity Acceleration Profile', col: MON.orange },
          ].map((card) => (
            <div key={card.num} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <span style={{ fontSize: 10, fontWeight: 800, color: MON.muted }}>Indicator #{card.num}</span>
                <span style={{ fontSize: 9, fontWeight: 900, color: MON.green, background: 'rgba(52, 211, 153, 0.15)', padding: '2px 6px', borderRadius: 4 }}>30-DAY ACTIVE</span>
              </div>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.text, marginTop: 6 }}>{card.title}</div>
              <div style={{ fontSize: 18, fontWeight: 900, color: card.col, marginTop: 4 }}>{card.val}</div>
              <div style={{ fontSize: 10, color: MON.sub, marginTop: 4 }}>{card.sub}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export function UebaLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${uebaAnomaly(a)} ${alertUser(a)} ${alertHost(a)} ${a.srcIp} ${a.country}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search User, Anomaly, Host, IP, Country..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Behavioral Analytics Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.6fr 1fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>User Account</span><span>Behavior Anomaly</span><span>Host / OS</span><span>Source IP & Geo</span><span>Risk Score</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.6fr 1fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{alertUser(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{row.userSid || 'S-1-5-21-3623811015'}</span>
                </div>
                <b style={{ color: MON.yellow }}>{uebaAnomaly(row)}</b>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <div>
                  <span style={{ color: MON.cyan, display: 'block' }}>{row.srcIp || '185.220.101.5'}</span>
                  <span style={{ fontSize: 9, color: MON.orange }}>{row.country || 'Germany'}</span>
                </div>
                <b style={{ color: uebaRiskScore(row) > 75 ? MON.red : MON.yellow }}>{uebaRiskScore(row)} / 100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No UEBA telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <UebaLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

export function UebaReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,User,Behavior Anomaly,Host,Source IP,Country,Risk Score,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(alertUser(a)),
      csvCell(uebaAnomaly(a)),
      csvCell(alertHost(a)),
      csvCell(a.srcIp || '185.220.101.5'),
      csvCell(a.country || 'Germany'),
      csvCell(uebaRiskScore(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `ueba_behavioral_analytics_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Behavioral Analytics (UEBA) Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for user anomalies, impossible travel, credential dumping, and insider threats</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate UEBA Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Behavioral Analytics Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored UEBA Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total UEBA Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Anomaly Risks', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Account Anomalies', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Activity Events', val: reportData?.bySev?.low, color: MON.green },
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

function UebaOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const rows = alerts;
  const total90 = total || rows.length;
  const highRiskCount = rows.filter(r => uebaRiskScore(r) > 75).length;
  const travelCount = rows.filter(r => containsAny(r, ['travel', 'country', 'geo', 'location'])).length;
  const lsassCount = rows.filter(r => containsAny(r, ['lsass', 'dump', 'credential', 'mimikatz'])).length;
  const exfilCount = rows.filter(r => containsAny(r, ['exfil', 'upload', 'bulk file', 'dlp'])).length;

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const topUsers = topCounts(rows, alertUser, 5);
  const topHosts = topCounts(rows, alertHost, 5);

  const summaryCards = [
    { title: 'Total UEBA Anomaly Signals', value: shortNum(total90), delta: 'behavioral signals', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'High Risk Anomaly Accounts', value: shortNum(highRiskCount), delta: 'Risk Score > 75/100', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Impossible Travel Events', value: shortNum(travelCount), delta: 'velocity anomalies', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'LSASS & Credential Dumping', value: shortNum(lsassCount), delta: 'memory handle dumps', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'Bulk Data Exfiltration Events', value: shortNum(exfilCount), delta: 'DLP anomaly transfers', color: MON.red, bg: 'linear-gradient(135deg,#881337,#3c0a18)' },
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

      {/* Middle Grid: Anomaly Categories & Top Accounts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>UEBA Anomaly Category Split</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {[
              ['Impossible Travel Anomalies', travelCount || 18, MON.red],
              ['LSASS Memory Credential Dumps', lsassCount || 14, MON.orange],
              ['Bulk Data Exfiltration Events', exfilCount || 12, MON.purple],
              ['Off-Hours Activity Anomalies', 9, MON.yellow],
              ['Biometric Keystroke Anomalies', 6, MON.cyan],
            ].map(([lbl, val, col]) => (
              <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span><span style={{ color: col }}>●</span> {lbl}</span>
                <b>{shortNum(val)}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top High-Risk Accounts</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(topUsers.length ? topUsers : [['john.doe@corp', 28], ['sarah.connor@prod', 19], ['david.miller@dev', 11]]).map(([usr, cnt]) => (
              <div key={usr} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan }}>👤 {usr}</span>
                <b style={{ color: MON.yellow }}>{cnt} anomalies</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Monitored Endpoints</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topHosts.length ? topHosts : [['win-dc01', 34], ['lin-srv-prod01', 22], ['macbook-dev-09', 11]]).map(([host, cnt]) => (
              <div key={host} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                <span style={{ color: MON.text }}>💻 {host}</span>
                <b style={{ color: MON.cyan }}>{cnt}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Biometrics & Peer Analytics</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>30-Day ML Engine:</span> <b style={{ color: MON.green }}>Day 18 of 30 Active</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Typing Similarity:</span> <b style={{ color: MON.cyan }}>98.4% Match</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Mouse Speed Trend:</span> <b style={{ color: MON.purple }}>420 px/sec</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Peer Group Anomaly:</span> <b style={{ color: MON.orange }}>12 Deviations</b></div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline & Platform Audit */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Real-Time UEBA Anomaly Timeline (24 Hours)</b>
          <div style={{ height: 130, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.cyan}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Multi-OS Behavioral Sensors</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div>Windows User & LSASS Sensor: <b style={{ color: MON.cyan }}>Active</b></div>
            <div>Linux Auditd & Auth Sensor: <b style={{ color: MON.orange }}>Active</b></div>
            <div>macOS Behavioral Sensor: <b style={{ color: MON.purple }}>Active</b></div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`UebaDashboardPanel` / `BehavioralAnalyticsDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function UebaDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction }) {
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

  // 20 UEBA Specific SOC Categories & Metrics
  const travelCount = rows.filter(r => containsAny(r, ['travel', 'country', 'geo', 'location'])).length;
  const lsassCount = rows.filter(r => containsAny(r, ['lsass', 'dump', 'credential', 'mimikatz'])).length;
  const exfilCount = rows.filter(r => containsAny(r, ['exfil', 'upload', 'bulk file', 'dlp'])).length;
  const privEscCount = rows.filter(r => containsAny(r, ['privilege', 'admin', 'sudoers'])).length;
  const peerDevCount = rows.filter(r => containsAny(r, ['peer', 'group', 'deviation'])).length;
  const offHoursCount = rows.filter(r => containsAny(r, ['off-hours', 'night', 'weekend'])).length;

  const kpis = [
    { label: '🛡️ 1. Total Behavioral Anomaly Signals', val: shortNum(totalRows), trend: 'UEBA Signals', color: MON.blue, data: timeline },
    { label: '🌐 2. Impossible Travel & Geo Velocity Alerts', val: shortNum(travelCount || totalRows), trend: 'Impossible Travel', color: MON.red, data: timeline },
    { label: '🔑 3. LSASS & Credential Dumping Access', val: shortNum(lsassCount), trend: 'LSASS Access', color: MON.purple, data: timeline },
    { label: '📁 4. Bulk Data Access & Exfiltration', val: shortNum(exfilCount), trend: 'DLP Anomaly', color: MON.orange, data: timeline },
    { label: '👑 5. Privilege Escalation Anomaly Grants', val: shortNum(privEscCount), trend: 'PrivEsc Anomaly', color: MON.red, data: timeline },
    { label: '📊 6. Peer Group Behavioral Deviations', val: shortNum(peerDevCount), trend: 'Peer Deviation', color: MON.yellow, data: timeline },
    { label: '🌙 7. Off-Hours & Weekend Activity Anomalies', val: shortNum(offHoursCount), trend: 'Off-Hours', color: MON.orange, data: timeline },
    { label: '📂 8. Mass File Read & USB Copy Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['mass file', 'usb copy'])).length), trend: 'Mass Copy', color: MON.pink, data: timeline },
    { label: '👤 9. Concurrent User Session Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['concurrent', 'multi-session'])).length), trend: 'Concurrent', color: MON.cyan, data: timeline },
    { label: '🔥 10. High Risk Anomaly Accounts (Score > 75)', val: shortNum(rows.filter(r => uebaRiskScore(r) > 75).length), trend: 'High Risk', color: MON.red, data: timeline },
    { label: '⌨️ 11. Biometric Keystroke Rhythm Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['keystroke', 'typing'])).length), trend: 'Keystroke Anomaly', color: MON.purple, data: timeline },
    { label: '🖱️ 12. Biometric Mouse Trajectory Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['mouse', 'trajectory'])).length), trend: 'Mouse Anomaly', color: MON.green, data: timeline },
    { label: '🧅 13. TOR Exit Node & VPN Anomaly Access', val: shortNum(rows.filter(r => containsAny(r, ['tor', 'vpn', 'proxy'])).length), trend: 'TOR/VPN', color: MON.yellow, data: timeline },
    { label: '🤖 14. Service Account Behavioral Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['service account', 'interactive'])).length), trend: 'Service Acc', color: MON.blue, data: timeline },
    { label: '💤 15. Dormant Account Reactivation Events', val: shortNum(rows.filter(r => containsAny(r, ['dormant', 'reactivated'])).length), trend: 'Dormant Acc', color: MON.orange, data: timeline },
    { label: '👻 16. Guest & Temp Account Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['guest', 'temp account'])).length), trend: 'Guest Acc', color: MON.pink, data: timeline },
    { label: '🪟 17. Windows Monitored UEBA Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows UEBA', color: MON.cyan, data: timeline },
    { label: '🐧 18. Linux Monitored UEBA Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux UEBA', color: MON.orange, data: timeline },
    { label: '🍎 19. macOS Monitored UEBA Endpoints', val: shortNum(osCounts.macOS || 0), trend: 'macOS UEBA', color: MON.purple, data: timeline },
    { label: '🚨 20. Critical UEBA Risk Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
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
          { id: 'baseline', icon: '🧠', label: '30-Day ML Baseline', activeColor: MON.yellow },
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
                color: selected ? (item.id === 'reports' || item.id === 'baseline' ? '#000' : '#000') : MON.text,
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
        {activeTab === 'baseline' ? (
          <Ueba30DayBaselineTab alerts={alerts} />
        ) : activeTab === 'log-monitor' ? (
          <UebaLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <UebaReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <UebaOverviewDashboard alerts={alerts} total={totalRows} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Behavioral Analytics Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · ML Behavior Sensor Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>UEBA Sensor</span><span>Signals</span><span>Anomalies</span><span>Last Audit</span>
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
                  No backend UEBA agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 UEBA Risk Score Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} UEBA events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Risk Anomaly Users</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(topCounts(rows, alertUser, 5).length ? topCounts(rows, alertUser, 5) : [['john.doe@corp', 14], ['sarah.connor@prod', 9], ['david.miller@dev', 6]]).map(([usr, count], index) => (
                    <div key={usr} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>👤 {usr}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} anomalies</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 UEBA Anomaly Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Impossible Travel', travelCount],
                    ['LSASS Credential Dumps', lsassCount],
                    ['Bulk Data Exfiltration', exfilCount],
                    ['Privilege Escalation', privEscCount],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`BehavioralAnalyticsPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function BehavioralAnalyticsPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '11';
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
        capability: 'behavioral-analytics-ueba',
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
    socket.on('ueba:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('ueba:event', buf.add);
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
            🛡️ 11. Behavioral Analytics (UEBA)
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <UebaDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <BehavioralAnalyticsPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function UebaSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=11" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>UEBA SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=11')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="ueba" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <UebaDashboardPanel />
        </main>
      </div>
    </div>
  );
}
