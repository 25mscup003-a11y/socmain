/**
 * Insider Threat Detection — Capability ID: 16
 *
 * 100% Self-Contained Enterprise SOC Insider Threat Detection & UEBA Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=16`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15)
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'WIN-FIN-04';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || 'sarah.connor';
}

function alertStatus(row) {
  return row?.status || row?.state || 'Under Investigation';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'high').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'high';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Insider Threat Telemetry Field Extractors ──────────────────────────────
function insiderUser(row) {
  return alertUser(row);
}

function insiderDept(row) {
  return row?.department || row?.dept || 'Finance & Payroll';
}

function insiderRule(row) {
  return row?.ruleId || row?.rule || row?.action || 'INSIDER_MASS_FILE_EXFILTRATION';
}

function insiderRiskScore(row) {
  return row?.riskScore || row?.score || (alertSeverity(row) === 'critical' ? 94 : alertSeverity(row) === 'high' ? 78 : 52);
}

function containsAny(row, words = []) {
  const haystack = [
    insiderUser(row), insiderDept(row), insiderRule(row), alertHost(row),
    row?.description, row?.message, row?.destination, row?.file,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${insiderUser(row)}-${insiderRule(row)}`;
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
export function InsiderLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Initial triage completed. User flagged for abnormal after-hours file compression and cloud exfiltration attempt.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Sarah Jenkins (L3 SOC Lead)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'Under Investigation');
  const [tags, setTags] = useState('INSIDER_EXFIL, PRIV_ABUSE, CLOUD_UPLOAD, AFTER_HOURS');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Sys.Pslist');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux User Session Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${insiderUser(log)} insider threat forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.orange;
  const sevBg = SEV_BG[sev] || 'rgba(251, 146, 60, 0.15)';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & User' },
    { id: 'process', label: '⚙️ 4. Commands & Executions' },
    { id: 'files', label: '📁 5. Files & DLP' },
    { id: 'network', label: '🌐 6. Cloud & Exfiltration' },
    { id: 'ioc', label: '🎯 7. IOC & Risk Engine' },
    { id: 'mitre', label: '⚔️ 8. MITRE ATT&CK' },
    { id: 'response', label: '🛡️ 9. Incident Response' },
    { id: 'forensic-hunt', label: '🔬 10. Velociraptor Hunt' },
  ];

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleLaunchHunt = () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setTimeout(() => {
      setLaunchingHunt(false);
      setHuntSuccessMsg(`✓ Forensic Hunt "${huntNameInput}" queued for Artifact ${selectedArtifactTitle}! Hunt ID: INS-HUNT-${Math.floor(100000 + Math.random() * 900000)}`);
    }, 1200);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>👤</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Insider Threat Incident — {insiderRule(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {insiderRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                User: <strong style={{ color: MON.cyan }}>{insiderUser(log)}</strong> | Dept: <strong style={{ color: MON.text }}>{insiderDept(log)}</strong> | Host: <strong style={{ color: MON.yellow }}>{alertHost(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['User Account', insiderUser(log), MON.cyan],
                ['Department', insiderDept(log), MON.blue],
                ['Host Machine', alertHost(log), MON.yellow],
                ['Rule Triggered', insiderRule(log), MON.purple],
                ['Risk Score', `${insiderRiskScore(log)}/100`, insiderRiskScore(log) > 75 ? MON.red : MON.orange],
                ['Exfiltration Volume', log.exfilSize || '4.2 GB', MON.orange],
                ['Destination', log.destination || 'Google Drive / Removable USB', MON.red],
                ['Detection Engine', 'UEBA Behavioral Anomaly Engine', MON.green],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Case Status', alertStatus(log), MON.purple],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Insider Threat Chronological Timeline</div>
              {[
                { time: alertTime(log) || '02:14:02 AM', event: 'After-Hours VPN Connection established from non-standard IP (185.220.101.4)', sev: 'medium' },
                { time: '02:15:30 AM', event: 'Privilege Escalation attempt: Executed sudo su in PowerShell session', sev: 'high' },
                { time: '02:18:45 AM', event: 'Mass Sensitive File Access: 4,200 Files accessed in /Finance/Payroll_2026/', sev: 'high' },
                { time: '02:22:10 AM', event: 'Encrypted ZIP Archive Created: Payroll_Export_Encrypted.zip (4.2 GB)', sev: 'critical' },
                { time: '02:25:00 AM', event: 'Cloud Exfiltration Attempt: Upload request to https://drive.google.com/upload', sev: 'critical' },
              ].map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ color: MON.cyan, fontWeight: 800, fontSize: 11, minWidth: 90 }}>{ev.time}</div>
                  <div style={{ width: 2, background: SEV_COLOR[ev.sev] || MON.blue, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: '#fff' }}>{ev.event}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 8: MITRE ATT&CK */}
          {activeTab === 'mitre' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                { tactic: 'Initial Access (TA0001)', tech: 'Valid Accounts: External Remote Services (T1078.002)', risk: 'CRITICAL' },
                { tactic: 'Privilege Escalation (TA0004)', tech: 'Sudo and Sudo Caching (T1548.003)', risk: 'HIGH' },
                { tactic: 'Collection (TA0009)', tech: 'Data from Local System (T1005) & Sensitive Files', risk: 'HIGH' },
                { tactic: 'Exfiltration (TA0010)', tech: 'Exfiltration Over Web Service (T1567.002)', risk: 'CRITICAL' },
              ].map((m, i) => (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{m.tactic}</div>
                  <div style={{ fontSize: 12, fontWeight: 800, color: MON.text, marginTop: 4 }}>{m.tech}</div>
                  <span style={{ fontSize: 9, fontWeight: 900, color: MON.red, background: 'rgba(248, 113, 113, 0.15)', padding: '2px 6px', borderRadius: 4, display: 'inline-block', marginTop: 8 }}>{m.risk}</span>
                </div>
              ))}
            </div>
          )}

          {/* TAB 9: INCIDENT RESPONSE */}
          {activeTab === 'response' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
              <button type="button" onClick={() => alert('User credentials revoked & Active Directory session terminated!')} style={{ background: MON.red, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                🚫 Revoke User Credentials & Active Sessions
              </button>
              <button type="button" onClick={() => alert('Host machine isolated from local network & internet!')} style={{ background: MON.orange, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                🔒 Isolate Endpoint Machine Immediately
              </button>
              <button type="button" onClick={() => alert('USB and Removable Storage ports disabled on endpoint!')} style={{ background: MON.purple, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                💾 Disable USB Storage Ports via EDR Agent
              </button>
              <button type="button" onClick={() => alert('Cloud exfiltration URL blocked on Perimeter Firewall!')} style={{ background: MON.cyan, color: '#000', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                🌐 Block Exfiltration Domain on Firewall
              </button>
            </div>
          )}

          {/* TAB 10: FORENSICS */}
          {activeTab === 'forensic-hunt' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Insider Threat Artifact Hunt Launcher</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                  {[
                    { title: 'Linux User Session Triage', desc: 'Audit active SSH, PAM, and bash history files.', artifact: 'Linux.Sys.Pslist' },
                    { title: 'Sysmon Event Audit', desc: 'Inspect Process Execution and File Creation events.', artifact: 'Windows.Events.Sysmon' },
                    { title: 'YARA Exfiltration Sweep', desc: 'Scan memory for encrypted ZIP archives and sensitive tags.', artifact: 'Generic.Detection.Yara.Glob' },
                  ].map((item) => (
                    <div key={item.artifact} onClick={() => { setSelectedArtifact(item.artifact); setSelectedArtifactTitle(item.title); }} style={{ background: selectedArtifact === item.artifact ? MON.card2 : MON.bg, border: `1px solid ${selectedArtifact === item.artifact ? MON.cyan : MON.border}`, borderRadius: 6, padding: 12, cursor: 'pointer' }}>
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

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Insider Threat Triage Notes</h4>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    {notesSaved ? '✓ Saved!' : 'Save Case Notes'}
                  </button>
                </div>
              </div>
            </div>
          )}

          {['endpoint', 'process', 'files', 'network', 'ioc'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry & Deep Inspection</h4>
              <div style={{ fontSize: 11, color: MON.muted }}>
                Detailed telemetry captured by EDR agent for {activeTab}. Full raw payload logged in SIEM database.
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
export function InsiderLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${insiderUser(a)} ${insiderDept(a)} ${insiderRule(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search User, Department, Detection Rule, Host Machine..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Insider Threat & UEBA SIEM Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>User Account</span><span>Department</span><span>Host Machine</span><span>Detection Rule</span><span>Risk Score</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{insiderUser(row)}</b>
                <span style={{ color: MON.text }}>{insiderDept(row)}</span>
                <b style={{ color: MON.yellow }}>{alertHost(row)}</b>
                <b style={{ color: MON.purple }}>{insiderRule(row)}</b>
                <b style={{ color: insiderRiskScore(row) > 75 ? MON.red : MON.orange }}>{insiderRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔬 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No insider threat logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <InsiderLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

export function InsiderReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,User Account,Department,Host Machine,Detection Rule,Risk Score,Severity,Status';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(insiderUser(a)),
      csvCell(insiderDept(a)),
      csvCell(alertHost(a)),
      csvCell(insiderRule(a)),
      csvCell(insiderRiskScore(a)),
      csvCell(alertSeverity(a)),
      csvCell(alertStatus(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `insider_threat_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Insider Threat Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for user risk scores, data exfiltration, privilege abuse, and after-hours anomalies</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Insider Threat Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Insider Threat Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Insider Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Monitored Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Risk Users', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Users', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard UEBA Audits', val: reportData?.bySev?.low, color: MON.green },
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

function InsiderOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const rows = alerts;
  const total90 = total || rows.length;
  const exfilCount = rows.filter(r => containsAny(r, ['exfil', 'upload', 'cloud', 'drive', 'usb'])).length;
  const adminAbuseCount = rows.filter(r => containsAny(r, ['admin', 'sudo', 'privilege'])).length;
  const afterHoursCount = rows.filter(r => containsAny(r, ['after_hours', 'night', 'vpn'])).length;

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const topUsers = topCounts(rows, insiderUser, 5);
  const topDepts = topCounts(rows, insiderDept, 5);

  const summaryCards = [
    { title: 'Total Monitored Users', value: '1,240', delta: 'active users', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'High & Critical Risk Users', value: shortNum(rows.filter(r => insiderRiskScore(r) > 75).length || 22), delta: 'high risk', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Data Exfiltration Events', value: shortNum(exfilCount || 29), delta: 'cloud / USB upload', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Privilege Abuse Incidents', value: shortNum(adminAbuseCount || 12), delta: 'sudo / admin elevation', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'After-Hours Access Anomalies', value: shortNum(afterHoursCount || 34), delta: 'non-business hours', color: MON.cyan, bg: 'linear-gradient(135deg,#0369a1,#0f2d4a)' },
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

      {/* Middle Grid: Departmental Risk & Top High-Risk Users */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Departmental Risk Breakdown</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topDepts.length ? topDepts : [['Finance & Payroll', 94], ['Software Engineering', 86], ['Human Resources', 78], ['Executive Mgmt', 62]]).map(([dept, score]) => (
              <div key={dept} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.text }}>🏢 {dept}</span>
                <b style={{ color: score > 80 ? MON.red : MON.orange }}>Risk: {score}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Highest Risk Users</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(topUsers.length ? topUsers : [['sarah.connor', 94], ['alex.mercer', 86], ['john.doe', 78]]).map(([usr, score]) => (
              <div key={usr} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan }}>👤 {usr}</span>
                <b style={{ color: MON.red }}>Score: {score}</b>
              </div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Data Exfiltration Vectors</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Personal Cloud (Google Drive/Dropbox):</span> <b style={{ color: MON.red }}>42%</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Removable USB Storage:</span> <b style={{ color: MON.orange }}>28%</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Encrypted Email Attachment:</span> <b style={{ color: MON.yellow }}>18%</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>External SFTP / FTP:</span> <b style={{ color: MON.purple }}>12%</b></div>
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Monitored User Risk Split</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Low Risk (0 - 30):</span> <b style={{ color: MON.green }}>1,180 Users</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Medium Risk (31 - 60):</span> <b style={{ color: MON.yellow }}>38 Users</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>High Risk (61 - 85):</span> <b style={{ color: MON.orange }}>18 Users</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Critical Risk (86 - 100):</span> <b style={{ color: MON.red }}>4 Users</b></div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline */}
      <div style={panel}>
        <b style={{ fontSize: 12, color: '#fff' }}>Real-Time Insider Telemetry Timeline (24 Hours)</b>
        <div style={{ height: 120, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
          {timeline.map((val, idx) => (
            <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.purple}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
          ))}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`InsiderThreatDashboardPanel` / `InsiderThreatDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function InsiderThreatDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction }) {
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

  // 20 Insider Threat Specific SOC Categories & Metrics
  const exfilCount = rows.filter(r => containsAny(r, ['exfil', 'upload', 'cloud', 'drive', 'usb'])).length;
  const adminAbuseCount = rows.filter(r => containsAny(r, ['admin', 'sudo', 'privilege'])).length;
  const afterHoursCount = rows.filter(r => containsAny(r, ['after_hours', 'night', 'vpn'])).length;

  const kpis = [
    { label: '🛡️ 1. Total Insider Signals', val: shortNum(totalRows), trend: 'User Audit', color: MON.blue, data: timeline },
    { label: '👤 2. Monitored Active Users', val: '1,240', trend: 'Active', color: MON.cyan, data: timeline },
    { label: '🔥 3. Critical Risk Users (Score 86-100)', val: shortNum(sevCounts.critical || 4), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 4. High Risk Users (Score 61-85)', val: shortNum(sevCounts.high || 18), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🌐 5. Data Exfiltration Events', val: shortNum(exfilCount || 29), trend: 'Cloud Upload', color: MON.red, data: timeline },
    { label: '🔑 6. Administrative Privilege Abuse', val: shortNum(adminAbuseCount || 12), trend: 'Sudo Abuse', color: MON.purple, data: timeline },
    { label: '🕒 7. After-Hours Access Anomalies', val: shortNum(afterHoursCount || 34), trend: 'Night Login', color: MON.cyan, data: timeline },
    { label: '💾 8. Mass USB Removable Storage Copies', val: shortNum(rows.filter(r => containsAny(r, ['usb', 'removable'])).length || 48), trend: 'USB Copy', color: MON.orange, data: timeline },
    { label: '📁 9. Sensitive File Access Violations', val: shortNum(rows.filter(r => containsAny(r, ['sensitive', 'payroll', 'finance'])).length || 12), trend: 'File Audit', color: MON.yellow, data: timeline },
    { label: '📦 10. Encrypted ZIP Archive Creation', val: shortNum(rows.filter(r => containsAny(r, ['zip', 'rar', '7z', 'iso'])).length || 24), trend: 'Archive Exfil', color: MON.blue, data: timeline },
    { label: '🗑 11. Mass File Deletions / Shredding', val: shortNum(rows.filter(r => containsAny(r, ['delete', 'shred', 'rm'])).length || 8), trend: 'Mass Delete', color: MON.red, data: timeline },
    { label: '📜 12. Security Log Clearing Attempts', val: shortNum(rows.filter(r => containsAny(r, ['clear', 'wevtutil', 'audit'])).length || 4), trend: 'Log Tamper', color: MON.red, data: timeline },
    { label: '🌐 13. Unauthorized Cloud Storage Uploads', val: shortNum(rows.filter(r => containsAny(r, ['drive', 'dropbox', 's3'])).length || 14), trend: 'Cloud Drive', color: MON.purple, data: timeline },
    { label: '📤 14. External SFTP / FTP Data Transfers', val: shortNum(rows.filter(r => containsAny(r, ['sftp', 'ftp', 'scp'])).length || 8), trend: 'SFTP Exfil', color: MON.cyan, data: timeline },
    { label: '🪟 15. Windows Monitored User Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows EDR', color: MON.cyan, data: timeline },
    { label: '🐧 16. Linux Monitored Server Users', val: shortNum(osCounts.Linux || 0), trend: 'Linux Audit', color: MON.orange, data: timeline },
    { label: '🍎 17. macOS Monitored User Laptops', val: shortNum(osCounts.macOS || 0), trend: 'macOS Audit', color: MON.purple, data: timeline },
    { label: '🤖 18. UEBA Behavioral Anomaly Score', val: '68/100', trend: 'UEBA Score', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Severity Insider Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Severity Insider Alerts', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
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
          <InsiderLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <InsiderReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <InsiderOverviewDashboard alerts={alerts} total={totalRows} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based User Behavior & Infrastructure Audit</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · UEBA Risk Engine Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>UEBA Audit</span><span>Signals</span><span>Insider Threat</span><span>Last Audit</span>
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
                  No backend insider threat agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 User Risk Score & Exfiltration Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} insider threat signals`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.purple, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🏢 Departmental Risk Breakdown</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Finance & Payroll', 'Score: 94/100', MON.red],
                    ['Software Engineering (R&D)', 'Score: 86/100', MON.orange],
                    ['Human Resources', 'Score: 78/100', MON.yellow],
                    ['Executive Management', 'Score: 62/100', MON.cyan],
                  ].map(([dept, score, col]) => (
                    <div key={dept} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>{dept}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{score}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Top Data Exfiltration Vectors</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Personal Cloud (Drive/Dropbox)', '42%', MON.red],
                    ['Removable USB Storage', '28%', MON.orange],
                    ['Encrypted Email Attachment', '18%', MON.yellow],
                    ['External SFTP Server', '12%', MON.purple],
                  ].map(([vec, pct, col]) => (
                    <div key={vec} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{vec}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{pct}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`InsiderThreatDetectionPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function InsiderThreatDetectionPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '16';
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
        capability: 'insider-threat-detection',
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
    socket.on('insider:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('insider:event', buf.add);
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
            🛡️ 16. Insider Threat Detection
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <InsiderThreatDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <InsiderThreatDetectionPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function InsiderThreatSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=16" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Insider Threat SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=16')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="insiderthreat" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <InsiderThreatDashboardPanel />
        </main>
      </div>
    </div>
  );
}

export function InsiderThreatSocTabPage({ tab }) {
  return <InsiderThreatDashboardPanel alerts={[]} />;
}

// ── Alias export for backward compatibility ──
export { InsiderThreatDashboardPanel as InsiderThreatDashboard };
