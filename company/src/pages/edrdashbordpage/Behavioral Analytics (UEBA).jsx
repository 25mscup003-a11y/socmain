/**
 * Behavioral Analytics (UEBA - User & Entity Behavior Analytics) — Capability ID: 11
 *
 * 100% Self-Contained Enterprise SOC UEBA Module
 * Linked to Live Backend API (`/api/ueba/dashboard`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7) & Persistence (8)
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

function MiniSparkline({ data = [0, 0], color = MON.cyan, height = 30 }) {
  const series = data.length > 1 ? data : [data[0] || 0, data[0] || 0];
  const max = Math.max(...series, 1);
  const min = Math.min(...series, 0);
  const points = series.map((val, idx) => {
    const x = (idx / (series.length - 1)) * 100;
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
  return row?.username || row?.user || row?.userName || row?.account || row?.entityId || '—';
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
  return row?.anomaly || row?.anomalyType || row?.description || row?.eventType || row?.ruleId || raw.anomaly || raw.description || '—';
}

function uebaRiskScore(row) {
  const explicit = Number(row?.riskScore ?? row?.behaviorScore ?? row?.score);
  if (Number.isFinite(explicit)) return Math.max(0, Math.min(100, Math.round(explicit)));
  return ({ critical: 100, high: 80, medium: 60, low: 30, info: 10 })[alertSeverity(row)] || 10;
}

function uebaCategory(row) {
  return row?.behaviorCategory || row?.category || row?.eventType || row?.ruleId || 'Unclassified';
}

function sourceIp(row) { return row?.srcip || row?.srcIp || row?.sourceIp || '—'; }
function geoCountry(row) { return row?.geoCountry || row?.country || '—'; }
function eventClock(row) {
  const value = alertTime(row);
  const date = value ? new Date(value) : null;
  return date && !Number.isNaN(date.getTime()) ? date.toLocaleTimeString() : '—';
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

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function UebaLogDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState(Array.isArray(log?.uebaRiskFactors) ? log.uebaRiskFactors.join(', ') : '');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Sys.Pslist');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux Process & User Context Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${alertHost(log)} ueba forensic hunt`);
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
                Anomaly: <strong style={{ color: MON.red }}>{uebaAnomaly(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Source IP: <strong style={{ color: MON.cyan }}>{sourceIp(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Source IP & Country', `${sourceIp(log)} (${geoCountry(log)})`, MON.red],
                ['User SID', log.userSid || '—', MON.purple],
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
              {(Array.isArray(log.relatedEvents) && log.relatedEvents.length ? log.relatedEvents : [log]).map((ev, i) => {
                const eventColor = SEV_COLOR[alertSeverity(ev)] || MON.blue;
                return <div key={recordId(ev) || i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: eventColor, background: `${eventColor}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content' }}>{uebaCategory(ev)}</span>
                  <div style={{ color: MON.muted, fontWeight: 800, fontSize: 11, minWidth: 90 }}>{eventClock(ev)}</div>
                  <div style={{ width: 2, background: eventColor, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{uebaAnomaly(ev)}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{alertHost(ev)} · {alertUser(ev)}</div>
                  </div>
                </div>;
              })}
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
                {log.commandLine || log.processCmdline || 'No command-line evidence reported'}
              </pre>
            </div>
          )}

          {/* TAB 5: FILES & DATA ACCESS */}
          {activeTab === 'files' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📁 Sensitive File Access & Bulk Data Transfer</h4>
              <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div><b>Accessed File:</b> <span style={{ color: MON.cyan, fontFamily: 'monospace' }}>{log.filePath || log.fileName || '—'}</span></div>
                <div><b>Data Volume:</b> <span style={{ color: MON.red, fontWeight: 800 }}>{Number.isFinite(Number(log.bytesTransferred)) ? `${Number(log.bytesTransferred).toLocaleString()} bytes` : '—'}</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK & TRAVEL */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Impossible Travel & Geolocation Anomaly</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Source IP:</span> <b style={{ color: MON.cyan }}>{sourceIp(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Country:</span> <b style={{ color: MON.yellow }}>{geoCountry(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Destination:</span> <b style={{ color: MON.red }}>{log.destip || log.destinationHost || log.domain || '—'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                <div><b style={{ color: MON.red }}>{log.mitreId || log.mitreTechnique || 'No MITRE mapping reported'}</b></div>
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
                {JSON.stringify(log.rawEvent || log, null, 2)}
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
                  <button type="button" disabled={!onAction || !log._id} onClick={() => onAction?.(log._id, 'isolate')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: onAction && log._id ? 'pointer' : 'not-allowed', opacity: onAction && log._id ? 1 : 0.55 }}>
                    ⛔ Request Endpoint Isolation
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
function BaselineAgentDashboard({ agent, from, to, onBack, detailLoading = false, detailError = '' }) {
  const [selectedDailyKey, setSelectedDailyKey] = useState('');
  const riskColor = agent.maximumRisk >= 90 ? MON.red : agent.maximumRisk >= 80 ? MON.orange : agent.maximumRisk >= 60 ? MON.yellow : MON.green;
  const visibleMonitoringScopes = agent.monitoringScopes || [];
  const monitored = visibleMonitoringScopes.filter(scope => scope.enabled).length;
  const formatDate = value => value && !Number.isNaN(new Date(value).getTime()) ? new Date(value).toLocaleString() : '—';
  const dailyChanges = [...(agent.dailyChanges || [])].reverse();
  const selectedDay = dailyChanges.find(day => day.date === selectedDailyKey) || null;
  const selectedDayIndex = dailyChanges.findIndex(day => day.date === selectedDailyKey);
  const previousDay = selectedDayIndex >= 0 ? dailyChanges[selectedDayIndex + 1] || null : null;
  const oldestDay = dailyChanges[dailyChanges.length - 1] || null;
  const newestDay = dailyChanges[0] || null;
  const thirtyDayScopeCounts = visibleMonitoringScopes.reduce((totals, scope) => {
    totals[scope.key] = dailyChanges.reduce((sum, day) => sum + Number(day.scopeCounts?.[scope.key] || 0), 0);
    return totals;
  }, {});
  const thirtyDaySignals = dailyChanges.reduce((sum, day) => sum + Number(day.signals || 0), 0);
  const thirtyDayActiveDays = dailyChanges.filter(day => Number(day.signals || 0) > 0).length;
  const thirtyDayAverageRisk = dailyChanges.length
    ? Math.round(dailyChanges.reduce((sum, day) => sum + Number(day.averageRisk || 0), 0) / dailyChanges.length)
    : 0;
  const thirtyDayMaximumRisk = dailyChanges.reduce((maximum, day) => Math.max(maximum, Number(day.maximumRisk || 0)), 0);
  const thirtyDayChangeTypes = [...new Set(dailyChanges.flatMap(day => day.changeTypes || []))];
  const thirtyDayNetSignalChange = newestDay && oldestDay ? Number(newestDay.signals || 0) - Number(oldestDay.signals || 0) : 0;
  const readable = value => String(value || '').replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
  const signed = value => {
    const number = Number(value || 0);
    return number > 0 ? `+${number}` : String(number);
  };
  useEffect(() => {
    if (!selectedDailyKey) return undefined;
    const previousOverflow = document.body.style.overflow;
    const closeOnEscape = event => {
      if (event.key === 'Escape') setSelectedDailyKey('');
    };
    document.body.style.overflow = 'hidden';
    window.addEventListener('keydown', closeOnEscape);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener('keydown', closeOnEscape);
    };
  }, [selectedDailyKey]);
  const kpis = [
    ['Behavior Signals', shortNum(agent.events), MON.cyan],
    ['Average Risk', `${agent.averageRisk}/100`, MON.yellow],
    ['Maximum Risk', `${agent.maximumRisk}/100`, riskColor],
    ['Observed Entities', shortNum(agent.users), MON.blue],
    ['Active Monitor Areas', `${monitored}/${visibleMonitoringScopes.length}`, MON.green],
    ['Baseline Coverage', `${agent.progressPercent}%`, MON.purple],
  ];

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <button type="button" onClick={onBack} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, padding: '7px 11px', cursor: 'pointer', fontWeight: 800 }}>← Agent Cards</button>
          <span style={{ fontSize: 28 }}>🖥️</span>
          <div>
            <h3 style={{ margin: 0, fontSize: 17, color: '#fff' }}>{agent.name}</h3>
            <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>{agent.hostname} · {agent.os} · {agent.ip || 'IP not reported'} · Agent {agent.agentVersion || 'version unknown'}</div>
          </div>
        </div>
        <div style={{ textAlign: 'right', fontSize: 10, color: MON.muted }}>
          <b style={{ display: 'block', color: agent.online ? MON.green : MON.orange, fontSize: 11 }}>{agent.online ? '● ONLINE' : '● OFFLINE'}</b>
          Fixed baseline window: {formatDate(from)} — {formatDate(to)}
        </div>
      </div>

      {(detailLoading || detailError) && <div style={{ color: detailError ? MON.orange : MON.cyan, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 7, padding: 10, fontSize: 10 }}>{detailError || 'Loading the latest agent baseline details…'}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(120px, 1fr))', gap: 10 }}>
        {kpis.map(([label, value, color]) => (
          <div key={label} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12 }}>
            <div style={{ color: MON.muted, fontSize: 9, fontWeight: 800 }}>{label}</div>
            <div style={{ color, fontSize: 20, fontWeight: 900, marginTop: 6 }}>{value}</div>
          </div>
        ))}
      </div>

      <div>
        <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 13, fontWeight: 900, color: MON.cyan, marginBottom: 12 }}>Agent Monitoring Coverage — What Is Being Monitored</div>
          <div style={{ color: MON.sub, fontSize: 9.5, lineHeight: 1.55, margin: '-5px 0 11px' }}>All six areas contribute security context during the rolling 30-day learning window. After 30 distinct input-profile days, aggregate mouse/keyboard rhythm and the verified interactive session are compared. A mismatch means identity verification is required; it is not definitive identity proof.</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 9 }}>
            {visibleMonitoringScopes.map(scope => {
              const sensorUnavailable = scope.key === 'input' && scope.available === false;
              const reportedLearningDays = scope.key === 'input'
                ? Math.max(Number(scope.metrics?.baselineDays || 0), Number(agent.observedDays || 0))
                : Number(agent.observedDays || 0);
              const learningDays = Math.max(0, Math.min(30, reportedLearningDays));
              return (
                <div key={scope.key} style={{ background: MON.card2, border: `1px solid ${scope.enabled ? MON.border : '#4b2631'}`, borderRadius: 7, padding: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center' }}>
                    <b style={{ color: scope.enabled ? '#fff' : MON.muted, fontSize: 11 }}>{scope.label}</b>
                    <span style={{ color: !scope.enabled ? MON.red : sensorUnavailable ? MON.orange : MON.green, fontSize: 9, fontWeight: 900 }}>
                      {!scope.enabled ? '● DISABLED' : sensorUnavailable ? '● ENABLED · SENSOR UNAVAILABLE' : '● MONITORING'}
                    </span>
                  </div>
                  <div style={{ color: MON.sub, fontSize: 9, lineHeight: 1.45, marginTop: 5 }}>{scope.description}</div>
                  <div style={{ color: scope.events ? MON.cyan : MON.green, fontSize: 10, fontWeight: 800, marginTop: 7 }}>
                    {scope.events ? `${shortNum(scope.events)} correlated signals in 30 days` : 'Monitoring active · no anomaly/change observed in 30 days'}
                  </div>
                  <div style={{ marginTop: 8 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, color: learningDays >= 30 ? MON.green : MON.yellow, fontSize: 8.5, fontWeight: 900 }}>
                      <span>Learning profile</span>
                      <span>{learningDays}/30 days</span>
                    </div>
                    <div style={{ height: 4, background: MON.bg, borderRadius: 4, marginTop: 5, overflow: 'hidden' }}>
                      <div style={{ width: `${(learningDays / 30) * 100}%`, height: '100%', background: learningDays >= 30 ? MON.green : MON.yellow, transition: 'width 200ms ease' }} />
                    </div>
                  </div>
                  {scope.key === 'input' && <div style={{ color: MON.muted, fontSize: 8.5, marginTop: 7, lineHeight: 1.5 }}>Avg typing {Number(scope.metrics?.keyboardRate || 0).toFixed(1)} events/min · pointer {Number(scope.metrics?.mouseRate || 0).toFixed(1)} px/sec · active {Number(scope.metrics?.activityPercent || 0).toFixed(1)}%{scope.metrics?.profileActive ? <><br /><b style={{ color: MON.green }}>Behavior verification active · confidence {Number(scope.metrics?.identityConfidence || 0).toFixed(0)}%</b></> : null}{Number(scope.metrics?.mismatches || 0) > 0 ? <span style={{ color: MON.red }}> · {scope.metrics.mismatches} verification alert(s)</span> : null}</div>}
                </div>
              );
            })}
          </div>
        </section>
      </div>

      <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', gap: 10 }}>
          <b style={{ color: MON.cyan, fontSize: 12 }}>📅 Daily Monitoring Changes — Last 30 Days</b>
          <span style={{ color: MON.muted, fontSize: 9 }}>Live baseline data · newest day first</span>
        </div>
        <div style={{ padding: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(155px, 1fr))', gap: 9 }}>
            {dailyChanges.map(day => {
              const delta = Number(day.changeFromPreviousDay || 0);
              const deltaColor = delta > 0 ? MON.orange : delta < 0 ? MON.green : MON.muted;
              const selected = selectedDailyKey === day.date;
              return (
                <button key={day.date} type="button" onClick={() => setSelectedDailyKey(day.date)} style={{ background: selected ? `${MON.cyan}18` : MON.card2, border: `1px solid ${selected ? MON.cyan : MON.border}`, borderRadius: 8, padding: 11, color: MON.text, textAlign: 'left', cursor: 'pointer', fontFamily: 'inherit' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><b style={{ color: selected ? MON.cyan : '#fff', fontSize: 11 }}>{day.date}</b><b style={{ color: deltaColor, fontSize: 9 }}>{delta > 0 ? `+${delta}` : delta}</b></div>
                  <div style={{ color: day.signals ? MON.cyan : MON.muted, fontSize: 20, fontWeight: 900, marginTop: 7 }}>{shortNum(day.signals)} <small style={{ fontSize: 8, color: MON.muted }}>signals</small></div>
                  <div style={{ color: day.activeAreas?.length ? MON.purple : MON.muted, fontSize: 8.5, marginTop: 5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{day.activeAreas?.length ? `${day.activeAreas.length}/6 areas active` : 'No change observed'}</div>
                  <div style={{ color: MON.muted, fontSize: 8, marginTop: 4 }}>Risk {Number(day.averageRisk || 0)} avg / {Number(day.maximumRisk || 0)} max</div>
                </button>
              );
            })}
            {!dailyChanges.length && <div style={{ padding: 20, color: MON.muted, textAlign: 'center', fontSize: 10 }}>Daily baseline data is not available yet.</div>}
          </div>
        </div>
      </section>

      {selectedDay && (
        <div
          role="presentation"
          onMouseDown={() => setSelectedDailyKey('')}
          style={{ position: 'fixed', inset: 0, zIndex: 10000, background: 'rgba(2, 8, 18, 0.82)', backdropFilter: 'blur(5px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 18 }}
        >
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="daily-monitoring-summary-title"
            onMouseDown={event => event.stopPropagation()}
            style={{ width: 'min(920px, 94vw)', maxHeight: '90vh', overflowY: 'auto', background: MON.card, border: `1px solid ${MON.cyan}`, borderRadius: 12, boxShadow: '0 24px 80px rgba(0, 0, 0, 0.6)' }}
          >
            <div style={{ position: 'sticky', top: 0, zIndex: 1, background: MON.card, borderBottom: `1px solid ${MON.line}`, padding: '15px 18px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
              <div>
                <h3 id="daily-monitoring-summary-title" style={{ color: '#fff', fontSize: 16, margin: 0 }}>{selectedDay.date} — Six-Area Summary</h3>
                <div style={{ color: MON.muted, fontSize: 9, marginTop: 5 }}>Daily live agent monitoring summary</div>
              </div>
              <button type="button" aria-label="Close daily monitoring summary" onClick={() => setSelectedDailyKey('')} style={{ width: 32, height: 32, flex: '0 0 auto', borderRadius: 7, border: `1px solid ${MON.border}`, background: MON.card2, color: '#fff', fontSize: 17, cursor: 'pointer' }}>✕</button>
            </div>

            <div style={{ padding: 18 }}>
              <div style={{ color: MON.cyan, fontSize: 11, fontWeight: 900, marginBottom: 8 }}>LAST / SELECTED DAY SUMMARY · {selectedDay.date}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(135px, 1fr))', gap: 9, marginBottom: 12 }}>
                {[
                  ['Signals', shortNum(selectedDay.signals), MON.cyan],
                  ['Active Areas', `${selectedDay.activeAreas?.length || 0}/6`, MON.purple],
                  ['Average Risk', `${Number(selectedDay.averageRisk || 0)}/100`, MON.yellow],
                  ['Maximum Risk', `${Number(selectedDay.maximumRisk || 0)}/100`, MON.orange],
                ].map(([label, value, color]) => (
                  <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 11 }}>
                    <div style={{ color: MON.muted, fontSize: 8.5, fontWeight: 800 }}>{label}</div>
                    <div style={{ color, fontSize: 19, fontWeight: 900, marginTop: 5 }}>{value}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 11, marginBottom: 12 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
                  <b style={{ color: '#fff', fontSize: 9.5 }}>CHANGE FROM PREVIOUS DAY</b>
                  <span style={{ color: MON.muted, fontSize: 8.5 }}>{previousDay ? `${previousDay.date} → ${selectedDay.date}` : 'Previous-day baseline is not available'}</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(125px, 1fr))', gap: 8 }}>
                  {[
                    ['Signals', previousDay ? Number(selectedDay.signals || 0) - Number(previousDay.signals || 0) : Number(selectedDay.changeFromPreviousDay || 0)],
                    ['Active Areas', previousDay ? Number(selectedDay.activeAreas?.length || 0) - Number(previousDay.activeAreas?.length || 0) : 0],
                    ['Average Risk', previousDay ? Number(selectedDay.averageRisk || 0) - Number(previousDay.averageRisk || 0) : 0],
                    ['Maximum Risk', previousDay ? Number(selectedDay.maximumRisk || 0) - Number(previousDay.maximumRisk || 0) : 0],
                  ].map(([label, delta]) => (
                    <div key={label} style={{ background: MON.bg, borderRadius: 6, padding: 9 }}>
                      <div style={{ color: MON.muted, fontSize: 8 }}>{label}</div>
                      <b style={{ display: 'block', color: delta > 0 ? MON.orange : delta < 0 ? MON.green : MON.muted, fontSize: 14, marginTop: 4 }}>{previousDay ? signed(delta) : '—'}</b>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 11, marginBottom: 12 }}>
                <b style={{ color: MON.muted, fontSize: 8.5 }}>LAST DAY OBSERVED CHANGE TYPES</b>
                <div style={{ color: selectedDay.changeTypes?.length ? MON.cyan : MON.green, fontSize: 10, marginTop: 5 }}>{selectedDay.changeTypes?.length ? selectedDay.changeTypes.map(readable).join(' · ') : 'No anomaly or monitoring change observed on this day'}</div>
              </div>

              <div style={{ color: MON.purple, fontSize: 11, fontWeight: 900, margin: '16px 0 8px' }}>ALL 30 DAYS SUMMARY · {oldestDay?.date || '—'} → {newestDay?.date || '—'}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(125px, 1fr))', gap: 9, marginBottom: 12 }}>
                {[
                  ['Total Signals', shortNum(thirtyDaySignals), MON.cyan],
                  ['Active Days', `${thirtyDayActiveDays}/${dailyChanges.length}`, MON.green],
                  ['Average / Day', dailyChanges.length ? (thirtyDaySignals / dailyChanges.length).toFixed(1) : '0', MON.blue],
                  ['Average Risk', `${thirtyDayAverageRisk}/100`, MON.yellow],
                  ['Peak Risk', `${thirtyDayMaximumRisk}/100`, MON.orange],
                  ['30-Day Net Change', signed(thirtyDayNetSignalChange), thirtyDayNetSignalChange > 0 ? MON.orange : thirtyDayNetSignalChange < 0 ? MON.green : MON.muted],
                ].map(([label, value, color]) => (
                  <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 11 }}>
                    <div style={{ color: MON.muted, fontSize: 8.5, fontWeight: 800 }}>{label}</div>
                    <div style={{ color, fontSize: 18, fontWeight: 900, marginTop: 5 }}>{value}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 11, marginBottom: 12 }}>
                <b style={{ color: MON.muted, fontSize: 8.5 }}>CHANGES OBSERVED ACROSS 30 DAYS</b>
                <div style={{ color: thirtyDayChangeTypes.length ? MON.purple : MON.green, fontSize: 10, marginTop: 5 }}>{thirtyDayChangeTypes.length ? thirtyDayChangeTypes.map(readable).join(' · ') : 'No anomaly or monitoring change observed during this window'}</div>
              </div>

              <div style={{ color: MON.cyan, fontSize: 10, fontWeight: 900, marginBottom: 8 }}>SIX-AREA DAY vs PREVIOUS DAY vs 30 DAYS</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(230px, 1fr))', gap: 9 }}>
                {visibleMonitoringScopes.map((scope, index) => {
                  const count = Number(selectedDay.scopeCounts?.[scope.key] || 0);
                  const previousCount = Number(previousDay?.scopeCounts?.[scope.key] || 0);
                  const scopeDelta = count - previousCount;
                  const windowCount = Number(thirtyDayScopeCounts[scope.key] || 0);
                  const colors = [MON.blue, MON.cyan, MON.yellow, MON.purple, MON.red, MON.green];
                  return (
                    <div key={scope.key} style={{ background: MON.bg, border: `1px solid ${count ? colors[index] : MON.border}`, borderRadius: 8, padding: 12 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                        <b style={{ color: '#fff', fontSize: 10.5 }}>{index + 1}. {scope.label}</b>
                        <b style={{ color: count ? colors[index] : MON.muted, fontSize: 14 }}>{shortNum(count)}</b>
                      </div>
                      <div style={{ color: count ? MON.green : MON.muted, fontSize: 8.5, marginTop: 7 }}>{count ? 'Signals observed on this day' : 'Monitoring active · no change observed'}</div>
                      {scope.key === 'input' && (
                        <div style={{ marginTop: 8, padding: 8, background: MON.card2, borderRadius: 6, color: MON.cyan, fontSize: 8.5, lineHeight: 1.6 }}>
                          {selectedDay.inputMetrics?.available ? <>
                            <b style={{ color: '#fff' }}>Keyboard speed:</b> {Number(selectedDay.inputMetrics.keyboardRate || 0).toFixed(1)} events/min<br />
                            <b style={{ color: '#fff' }}>Mouse speed:</b> {Number(selectedDay.inputMetrics.mouseRate || 0).toFixed(1)} units/sec<br />
                            <b style={{ color: '#fff' }}>Active time:</b> {Number(selectedDay.inputMetrics.activityPercent || 0).toFixed(1)}%
                          </> : <b style={{ color: MON.orange }}>{selectedDay.inputMetrics?.sensorUnavailable ? 'Input sensor was unavailable on this day; no speed sample exists' : 'No live speed sample reported by agent on this day'}</b>}
                        </div>
                      )}
                      <div style={{ borderTop: `1px solid ${MON.line}`, marginTop: 9, paddingTop: 8, display: 'flex', justifyContent: 'space-between', gap: 8, color: MON.muted, fontSize: 8.5 }}>
                        <span>Previous day <b style={{ color: previousDay ? (scopeDelta > 0 ? MON.orange : scopeDelta < 0 ? MON.green : MON.muted) : MON.muted }}>{previousDay ? signed(scopeDelta) : '—'}</b></span>
                        <span>30-day total <b style={{ color: colors[index] }}>{shortNum(windowCount)}</b></span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        </div>
      )}

      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, fontSize: 10 }}>
        <span><b style={{ color: MON.muted }}>First baseline signal</b><br />{formatDate(agent.firstSeen)}</span>
        <span><b style={{ color: MON.muted }}>Latest baseline signal</b><br />{formatDate(agent.lastEventAt)}</span>
        <span><b style={{ color: MON.muted }}>Agent last seen</b><br />{formatDate(agent.lastSeen)}</span>
        <span><b style={{ color: MON.muted }}>Scores</b><br />Behavior {agent.behaviorScore} · Baseline {agent.baselineScore} · Peer deviation {agent.peerDeviationScore} · Confidence {agent.confidence}%</span>
      </div>
    </div>
  );
}

export function Ueba30DayBaselineTab() {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [payload, setPayload] = useState({ agents: [], totalAgents: 0, pages: 1, windowDays: 30 });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selectedAgentId, setSelectedAgentId] = useState(null);
  const [agentDetail, setAgentDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [liveRefreshTick, setLiveRefreshTick] = useState(0);

  const loadBaseline = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const response = await api.get('/ueba/baseline', { params: { page, limit: 60 }, skipCache: quiet });
      setPayload(response.data || { agents: [], totalAgents: 0, pages: 1, windowDays: 30 });
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.message || '30-day agent baseline could not be loaded');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [page]);

  useEffect(() => {
    loadBaseline(false);
    const timer = window.setInterval(() => loadBaseline(true), 60000);
    return () => window.clearInterval(timer);
  }, [loadBaseline]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refresh = createEventBuffer(() => {
      loadBaseline(true);
      setLiveRefreshTick(value => value + 1);
    }, 500);
    socket.on('connect', join);
    socket.on('ueba:event', refresh.add);
    socket.on('alert:new', refresh.add);
    socket.on('alert:updated', refresh.add);
    socket.on('alert:deleted', refresh.add);
    socket.on('agent:update-status', refresh.add);
    socket.on('system:status_changed', refresh.add);
    if (socket.connected) join();
    const disconnectSocket = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('ueba:event', refresh.add);
      socket.off('alert:new', refresh.add);
      socket.off('alert:updated', refresh.add);
      socket.off('alert:deleted', refresh.add);
      socket.off('agent:update-status', refresh.add);
      socket.off('system:status_changed', refresh.add);
      refresh.clear();
      disconnectSocket();
    };
  }, [companyId, loadBaseline]);

  useEffect(() => {
    if (!selectedAgentId) {
      setAgentDetail(null);
      setDetailError('');
      return undefined;
    }
    let active = true;
    const loadDetail = async (quiet = false) => {
      if (!quiet) setDetailLoading(true);
      try {
        const response = await api.get(`/ueba/baseline/${selectedAgentId}`, { skipCache: quiet });
        if (active) { setAgentDetail(response.data || null); setDetailError(''); }
      } catch (requestError) {
        if (active) setDetailError(requestError.response?.data?.message || 'Agent baseline detail could not be loaded');
      } finally {
        if (active && !quiet) setDetailLoading(false);
      }
    };
    loadDetail(false);
    const timer = window.setInterval(() => loadDetail(true), 60000);
    return () => { active = false; window.clearInterval(timer); };
  }, [selectedAgentId, liveRefreshTick]);

  const agents = Array.isArray(payload.agents) ? payload.agents : [];
  const selectedAgentBase = agents.find(agent => agent.id === selectedAgentId);
  const selectedAgent = selectedAgentBase ? { ...selectedAgentBase, ...(agentDetail || {}) } : null;
  const averageProgress = agents.length ? Math.round(agents.reduce((sum, agent) => sum + Number(agent.progressPercent || 0), 0) / agents.length) : 0;
  const totalSignals = agents.reduce((sum, agent) => sum + Number(agent.events || 0), 0);
  const onlineAgents = agents.filter(agent => agent.online).length;

  if (selectedAgent) {
    return <BaselineAgentDashboard agent={selectedAgent} from={payload.from} to={payload.to} detailLoading={detailLoading} detailError={detailError} onBack={() => setSelectedAgentId(null)} />;
  }

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 32 }}>🧠</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 18, fontWeight: 900, color: '#f8fafc' }}>UEBA 30-Day Agent Behavioral Baseline</h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Only the fixed rolling last 30 days of agent telemetry are processed. Click an agent card to view exactly what that endpoint monitors.</div>
            </div>
          </div>
          <span style={{ fontSize: 10, fontWeight: 900, padding: '4px 10px', borderRadius: 4, color: MON.yellow, background: 'rgba(251,191,36,.15)', border: `1px solid ${MON.yellow}44` }}>● FIXED 30-DAY WINDOW</span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
          {[['Installed Agents', payload.totalAgents, MON.blue], ['Agents on This Page', agents.length, MON.cyan], ['Online Agents', onlineAgents, MON.green], ['30-Day Signals', totalSignals, MON.orange]].map(([label, value, color]) => <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 7, padding: 10 }}><span style={{ color: MON.muted, fontSize: 9, fontWeight: 800 }}>{label}</span><b style={{ display: 'block', color, fontSize: 19, marginTop: 4 }}>{shortNum(value)}</b></div>)}
        </div>
        <div style={{ width: '100%', background: MON.card2, height: 8, borderRadius: 5, overflow: 'hidden', border: `1px solid ${MON.border}` }}><div style={{ width: `${averageProgress}%`, height: '100%', background: `linear-gradient(90deg, ${MON.blue}, ${MON.cyan})` }} /></div>
        <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.muted, fontSize: 9 }}><span>Average agent baseline coverage</span><b style={{ color: MON.cyan }}>{averageProgress}%</b></div>
      </div>

      <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center', marginBottom: 14 }}>
          <b style={{ fontSize: 13, color: MON.cyan }}>🖥️ Agent Baseline Cards</b>
          <span style={{ color: MON.muted, fontSize: 10 }}>{loading ? 'Loading live agent baselines…' : `Page ${page} of ${Math.max(1, Number(payload.pages || 1))}`}</span>
        </div>
        {error && <div style={{ color: MON.red, background: `${MON.red}12`, border: `1px solid ${MON.red}44`, borderRadius: 6, padding: 10, marginBottom: 12, fontSize: 10 }}>{error}</div>}
        {payload.warning && <div style={{ color: MON.orange, background: `${MON.orange}12`, border: `1px solid ${MON.orange}44`, borderRadius: 6, padding: 10, marginBottom: 12, fontSize: 10 }}>{payload.warning}</div>}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(250px, 1fr))', gap: 12 }}>
          {agents.map(agent => {
            const color = agent.maximumRisk >= 90 ? MON.red : agent.maximumRisk >= 80 ? MON.orange : agent.maximumRisk >= 60 ? MON.yellow : MON.green;
            return (
              <button key={agent.id} type="button" onClick={() => setSelectedAgentId(agent.id)} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, color: MON.text, textAlign: 'left', cursor: 'pointer', fontFamily: 'inherit' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}><b style={{ color: '#fff', fontSize: 12 }}>🖥️ {agent.name}</b><span style={{ color: agent.online ? MON.green : MON.orange, fontSize: 9, fontWeight: 900 }}>{agent.online ? '● ONLINE' : '● OFFLINE'}</span></div>
                <div style={{ color: MON.muted, fontSize: 9, marginTop: 5 }}>{agent.hostname} · {agent.os} · {agent.ip || 'No IP'}</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 7, marginTop: 12 }}>
                  {[['Signals', agent.events, MON.cyan], ['Risk', agent.averageRisk, color], ['High / Critical', Number(agent.severity?.critical || 0) + Number(agent.severity?.high || 0), MON.red]].map(([label, value, metricColor]) => <span key={label} style={{ background: MON.bg, borderRadius: 5, padding: 7 }}><small style={{ display: 'block', color: MON.sub, fontSize: 8 }}>{label}</small><b style={{ color: metricColor, fontSize: 14 }}>{shortNum(value)}</b></span>)}
                </div>
                <div style={{ marginTop: 11, display: 'flex', justifyContent: 'space-between', fontSize: 9, color: MON.muted }}><span>30-day coverage</span><b style={{ color: MON.cyan }}>{agent.observedDays}/30 days</b></div>
                <div style={{ height: 5, background: MON.bg, borderRadius: 4, marginTop: 5, overflow: 'hidden' }}><div style={{ width: `${agent.progressPercent}%`, height: '100%', background: MON.cyan }} /></div>
                <div style={{ color: MON.cyan, fontSize: 9, fontWeight: 900, textAlign: 'right', marginTop: 9 }}>OPEN MONITORING DASHBOARD →</div>
              </button>
            );
          })}
        </div>
        {!loading && !agents.length && <div style={{ color: MON.muted, textAlign: 'center', padding: 28, fontSize: 11 }}>No installed endpoint agent is available in this scope.</div>}
        {Number(payload.pages || 1) > 1 && <div style={{ display: 'flex', justifyContent: 'center', gap: 8, marginTop: 14 }}><button type="button" disabled={page <= 1} onClick={() => { setSelectedAgentId(null); setPage(value => Math.max(1, value - 1)); }} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, borderRadius: 5, padding: '5px 12px', cursor: page <= 1 ? 'not-allowed' : 'pointer' }}>Previous</button><button type="button" disabled={page >= Number(payload.pages || 1)} onClick={() => { setSelectedAgentId(null); setPage(value => value + 1); }} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, borderRadius: 5, padding: '5px 12px', cursor: page >= Number(payload.pages || 1) ? 'not-allowed' : 'pointer' }}>Next</button></div>}
      </section>
    </div>
  );
}

export function UebaLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);
  const [baselineAgents, setBaselineAgents] = useState([]);
  const [baselineWindowDays, setBaselineWindowDays] = useState(30);
  const [baselineLoading, setBaselineLoading] = useState(true);
  const [baselineError, setBaselineError] = useState('');

  const loadBaselineEligibility = useCallback(async (quiet = false) => {
    if (!quiet) setBaselineLoading(true);
    try {
      const response = await api.get('/ueba/baseline', { params: { page: 1, limit: 200 }, skipCache: quiet });
      setBaselineAgents(Array.isArray(response.data?.agents) ? response.data.agents : []);
      setBaselineWindowDays(Number(response.data?.windowDays || 30));
      setBaselineError('');
    } catch (requestError) {
      setBaselineAgents([]);
      setBaselineError(requestError.response?.data?.message || 'ML baseline eligibility could not be verified');
    } finally {
      if (!quiet) setBaselineLoading(false);
    }
  }, []);

  useEffect(() => {
    loadBaselineEligibility(false);
    const timer = window.setInterval(() => loadBaselineEligibility(true), 60000);
    return () => window.clearInterval(timer);
  }, [loadBaselineEligibility]);

  const readyAgents = useMemo(() => baselineAgents.filter(agent => Number(agent.observedDays || 0) >= baselineWindowDays), [baselineAgents, baselineWindowDays]);
  const eligibleAlerts = useMemo(() => {
    const readyIds = new Set(readyAgents.map(agent => String(agent.id || agent._id || '')).filter(Boolean));
    const readyHosts = new Set(readyAgents.flatMap(agent => [agent.hostname, agent.name]).map(normHost).filter(Boolean));
    return alerts.filter(alert => {
      const alertSystemId = String(alert.systemId?._id || alert.systemId || '');
      return (alertSystemId && readyIds.has(alertSystemId)) || readyHosts.has(normHost(alertHost(alert)));
    });
  }, [alerts, readyAgents]);

  const filtered = useMemo(() => {
    return eligibleAlerts.filter(a => {
      const matchQ = !query || `${uebaAnomaly(a)} ${alertUser(a)} ${alertHost(a)} ${sourceIp(a)} ${geoCountry(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [eligibleAlerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${baselineError ? MON.red : MON.yellow}`, borderRadius: 8, padding: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
        <div>
          <b style={{ display: 'block', color: baselineError ? MON.red : MON.yellow, fontSize: 11 }}>🧠 30-Day ML Baseline Alert Gate</b>
          <span style={{ display: 'block', color: MON.muted, fontSize: 9, marginTop: 4 }}>{baselineError || `Alerts appear here only after an agent completes ${baselineWindowDays}/${baselineWindowDays} learning days.`}</span>
        </div>
        <div style={{ display: 'flex', gap: 8, fontSize: 9, fontWeight: 900 }}>
          <span style={{ color: MON.green, background: `${MON.green}15`, border: `1px solid ${MON.green}55`, borderRadius: 5, padding: '5px 8px' }}>{baselineLoading ? 'Checking…' : `${readyAgents.length} READY`}</span>
          <span style={{ color: MON.yellow, background: `${MON.yellow}15`, border: `1px solid ${MON.yellow}55`, borderRadius: 5, padding: '5px 8px' }}>{Math.max(0, baselineAgents.length - readyAgents.length)} LEARNING</span>
        </div>
      </div>

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
          <span style={{ fontSize: 10, color: MON.green }}>● Live WebSocket + 60s Recovery Refresh</span>
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
                  <span style={{ fontSize: 9, color: MON.sub }}>{row.userSid || row.entityType || '—'}</span>
                </div>
                <b style={{ color: MON.yellow }}>{uebaAnomaly(row)}</b>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <div>
                  <span style={{ color: MON.cyan, display: 'block' }}>{sourceIp(row)}</span>
                  <span style={{ fontSize: 9, color: MON.orange }}>{geoCountry(row)}</span>
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
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{baselineLoading ? 'Checking 30-day ML baseline eligibility…' : baselineError ? 'Logs are hidden until ML baseline eligibility can be verified.' : readyAgents.length ? 'No baseline-qualified UEBA alerts match the selected filters.' : `No ML alerts yet — an agent must complete ${baselineWindowDays}/${baselineWindowDays} learning days first.`}</div>}
          </div>
        </div>
      </div>

      {selectedLog && <UebaLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function UebaReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={11} alerts={alerts} />;
}

// ── Visual Helper Components for UEBA Dashboard ─────────────────────────────
function AnomalousEventsOverTimeChart({ timeline = [] }) {
  const source = timeline.length ? timeline.slice(-12) : [{ high: 0, medium: 0, low: 0 }, { high: 0, medium: 0, low: 0 }];
  const times = source.map(point => {
    const date = point?._id ? new Date(point._id) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—';
  });
  const highData = source.map(point => Number(point.high || 0));
  const medData = source.map(point => Number(point.medium || 0));
  const lowData = source.map(point => Number(point.low || 0));
  const chartMax = Math.max(...highData, ...medData, ...lowData, 1);
  const yLabels = [chartMax, Math.round(chartMax * 0.75), Math.round(chartMax * 0.5), Math.round(chartMax * 0.25), 0];

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
    return { d, pts };
  };

  const highRes = makePath(highData);
  const medRes = makePath(medData);
  const lowRes = makePath(lowData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Anomalous Events Over Time</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ display: 'flex', gap: 10, fontSize: 9 }}>
            <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f87171' }} /> High Risk</span>
            <span style={{ color: '#fb923c', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#fb923c' }} /> Medium Risk</span>
            <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#38bdf8' }} /> Low Risk</span>
          </div>
          <span style={{ fontSize: 9, color: '#8ea0b8', background: '#07101b', padding: '2px 8px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
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
          <path d={highRes.d} fill="none" stroke="#f87171" strokeWidth="2" />
          <path d={medRes.d} fill="none" stroke="#fb923c" strokeWidth="2" />
          <path d={lowRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          {highRes.pts.map((p, i) => <circle key={`h-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#f87171" />)}
          {medRes.pts.map((p, i) => <circle key={`m-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#fb923c" />)}
          {lowRes.pts.map((p, i) => <circle key={`l-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#38bdf8" />)}
        </svg>
      </div>
    </div>
  );
}

function BehaviorRiskDistributionDonut({ summary = {} }) {
  const riskTotal = Number(summary.critical || 0) + Number(summary.high || 0) + Number(summary.medium || 0) + Number(summary.low || 0);
  const risks = [
    { label: 'High Risk', count: Number(summary.critical || 0) + Number(summary.high || 0), color: '#f87171' },
    { label: 'Medium Risk', count: Number(summary.medium || 0), color: '#fb923c' },
    { label: 'Low Risk', count: Number(summary.low || 0), color: '#38bdf8' },
  ].map(item => ({ ...item, pct: riskTotal ? Math.round((item.count / riskTotal) * 100) : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = risks.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Behavior Risk Distribution</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.filter(arc => arc.count > 0).map(arc => (
              <path key={arc.label} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(riskTotal)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total Events</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 9 }}>
          {risks.map(r => (
            <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: r.color }} /> {r.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{r.pct}% ({r.count})</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function UebaOverviewDashboard({ alerts = [], total = 0, data = null }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const summary = data?.summary || {};
  const eventRows = Array.isArray(data?.events) ? data.events : alerts;
  const timeline = Array.isArray(data?.timeline) ? data.timeline : [];
  const categoryCounts = new Map((data?.categories || []).map(item => [String(item._id || 'Other'), Number(item.count || 0)]));
  const categoryMeta = {
    'User Behavior': ['👤', '#38bdf8'], 'Endpoint Behavior': ['💻', '#a78bfa'],
    'Network Behavior': ['🌐', '#34d399'], 'Data Access': ['📁', '#fbbf24'],
    Authentication: ['🔐', '#22d3ee'], 'Cloud Activity': ['☁️', '#38bdf8'],
    'Email Behavior': ['📧', '#22d3ee'], 'Application Behavior': ['⚙️', '#a78bfa'],
    'Server Behavior': ['🖥️', '#38bdf8'], Other: ['💬', '#64748b'],
  };
  const topCards = [
    { title: 'RISKY EVENTS', val: shortNum(summary.total ?? total), sub: 'Live 24-hour tenant data', subCol: '#8ea0b8', icon: '🛡️', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'HIGH RISK USERS', val: shortNum(summary.highRiskUsers), sub: 'Risk score 80 or higher', subCol: '#f87171', icon: '👤', iconBg: 'rgba(251, 146, 60, 0.15)' },
    { title: 'ANOMALOUS DEVICES', val: shortNum(summary.suspiciousDevices), sub: 'Agent-reported device signals', subCol: '#a78bfa', icon: '💻', iconBg: 'rgba(167, 139, 250, 0.15)' },
    { title: 'DATA EXFILTRATION RISK', val: shortNum(summary.dataExfiltration), sub: 'Correlated transfer anomalies', subCol: '#fbbf24', icon: '💾', iconBg: 'rgba(251, 191, 36, 0.15)' },
    { title: 'UEBA ALERTS', val: shortNum(Number(summary.critical || 0) + Number(summary.high || 0) + Number(summary.medium || 0) + Number(summary.low || 0)), sub: 'Severity-classified signals', subCol: '#f87171', icon: '🔔', iconBg: 'rgba(248, 113, 113, 0.15)' },
  ];
  const topUebaAlerts = eventRows.slice().sort((a, b) => uebaRiskScore(b) - uebaRiskScore(a)).slice(0, 8).map(row => {
    const score = uebaRiskScore(row);
    const status = alertStatus(row);
    return { id: recordId(row), name: uebaAnomaly(row), user: alertUser(row), score, time: eventClock(row), status, statusCol: status === 'open' ? '#f87171' : '#fb923c', scoreCol: score >= 90 ? '#f87171' : score >= 80 ? '#fb923c' : '#fbbf24' };
  });
  const topRiskyUsers = (data?.users || []).slice(0, 5).map(user => {
    const score = Math.round(Number(user.riskScore || 0));
    const color = score >= 90 ? '#f87171' : score >= 80 ? '#fb923c' : '#fbbf24';
    return { name: user._id || '—', score, events: Number(user.events || 0), scoreCol: color, sparkCol: color };
  });
  const riskCategories = Object.entries(categoryMeta).map(([label, [icon, col]]) => ({
    label, val: shortNum(categoryCounts.get(label) || 0), pct: `${summary.total ? Math.round(((categoryCounts.get(label) || 0) / Number(summary.total)) * 100) : 0}%`, icon, col,
  }));
  const recentAnomalousActivities = eventRows.slice(0, 5).map(row => {
    const score = uebaRiskScore(row);
    return { id: recordId(row), time: eventClock(row), event: uebaAnomaly(row), user: alertUser(row), score, scoreCol: score >= 90 ? '#f87171' : score >= 80 ? '#fb923c' : '#fbbf24' };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (5 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 38, height: 38, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, flexShrink: 0 }}>
              {c.icon}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 9.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px' }}>
                {c.title}
              </span>
              <span style={{ fontSize: 22, fontWeight: 800, color: '#ffffff', margin: '2px 0' }}>
                {c.val}
              </span>
              <span style={{ fontSize: 9.5, fontWeight: 700, color: c.subCol }}>
                {c.sub}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (2 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr', gap: 12 }}>
        <div style={panelStyle}>
          <AnomalousEventsOverTimeChart timeline={timeline} />
        </div>

        {/* Top UEBA Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top UEBA Alerts</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.9fr 0.6fr 0.6fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>ALERT NAME</span>
              <span>USER / ENTITY</span>
              <span>RISK SCORE</span>
              <span>TIME</span>
              <span>STATUS</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
              {topUebaAlerts.map(al => (
                <div key={al.id} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.9fr 0.6fr 0.6fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>● {al.name}</span>
                  <span style={{ color: '#8ea0b8' }}>{al.user}</span>
                  <span style={{ fontSize: 8.5, fontWeight: 800, color: al.scoreCol, padding: '1px 4px', background: `${al.scoreCol}15`, borderRadius: 4, border: `1px solid ${al.scoreCol}33`, textAlign: 'center', width: 24 }}>
                    {al.score}
                  </span>
                  <span style={{ color: '#64748b', fontSize: 8.5 }}>{al.time}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, color: al.statusCol, padding: '1px 5px', borderRadius: 8, background: `${al.statusCol}15`, border: `1px solid ${al.statusCol}44`, display: 'inline-block', textAlign: 'center' }}>
                    {al.status}
                  </span>
                </div>
              ))}
              {!topUebaAlerts.length && <div style={{ color: MON.muted, fontSize: 9, padding: 8 }}>No UEBA alerts in this window.</div>}
            </div>
          </div>
        </div>
      </div>

      {/* 3. MIDDLE GRID (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.6fr', gap: 12 }}>
        <div style={panelStyle}>
          <BehaviorRiskDistributionDonut summary={summary} />
        </div>

        {/* Top Risky Users */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Risky Users</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>USER</span>
              <span>RISK SCORE</span>
              <span>TREND</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topRiskyUsers.map(ru => (
                <div key={ru.name} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr 1fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>👤 {ru.name}</span>
                  <span style={{ fontSize: 8.5, fontWeight: 800, color: ru.scoreCol, padding: '1px 4px', background: `${ru.scoreCol}15`, borderRadius: 4, border: `1px solid ${ru.scoreCol}33`, textAlign: 'center', width: 24 }}>
                    {ru.score}
                  </span>
                  <div style={{ height: 16, width: '100%' }}>
                    <MiniSparkline data={[0, ru.events]} color={ru.sparkCol} height={16} />
                  </div>
                </div>
              ))}
              {!topRiskyUsers.length && <div style={{ color: MON.muted, fontSize: 9, padding: 8 }}>No identified user entities.</div>}
            </div>
          </div>
        </div>

        {/* Risk by Category (10 Cards) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Risk by Category</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
              {riskCategories.map(rc => (
                <div key={rc.label} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '8px 6px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
                  <span style={{ fontSize: 16 }}>{rc.icon}</span>
                  <span style={{ fontSize: 8.5, color: '#8ea0b8', margin: '4px 0 2px 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', width: '100%' }}>{rc.label}</span>
                  <span style={{ fontSize: 14, fontWeight: 800, color: '#ffffff' }}>{rc.val}</span>
                  <span style={{ fontSize: 8, fontWeight: 700, color: rc.col }}>{rc.pct}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 4. BOTTOM GRID */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
        {/* Recent Anomalous Activities */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent Anomalous Activities</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {recentAnomalousActivities.map(raa => (
                <div key={raa.id} style={{ display: 'grid', gridTemplateColumns: '0.7fr 1.6fr 0.9fr 0.4fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#64748b', fontSize: 8.5 }}>{raa.time}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{raa.event}</span>
                  <span style={{ color: '#8ea0b8' }}>{raa.user}</span>
                  <span style={{ fontSize: 8.5, fontWeight: 800, color: raa.scoreCol, padding: '1px 4px', background: `${raa.scoreCol}15`, borderRadius: 4, border: `1px solid ${raa.scoreCol}33`, textAlign: 'center', width: 24 }}>
                    {raa.score}
                  </span>
                </div>
              ))}
              {!recentAnomalousActivities.length && <div style={{ color: MON.muted, fontSize: 9, padding: 8 }}>No recent anomalous activity.</div>}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`UebaDashboardPanel` / `BehavioralAnalyticsDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function UebaDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction }) {
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

  const rows = Array.isArray(data?.events) ? data.events : (Array.isArray(alerts) ? alerts : []);
  const summary = data?.summary || {};
  const totalRows = Number(summary.total ?? total ?? recordsTotal ?? rows.length);
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const timeline = Array.isArray(data?.timeline) && data.timeline.length
    ? data.timeline.slice(-8).map(point => Number(point.total || 0))
    : buildBuckets(rows, 8, 24);

  // 20 UEBA Specific SOC Categories & Metrics
  const travelCount = rows.filter(r => containsAny(r, ['travel', 'country', 'geo', 'location'])).length;
  const lsassCount = rows.filter(r => containsAny(r, ['lsass', 'dump', 'credential', 'mimikatz'])).length;
  const exfilCount = Number(summary.dataExfiltration ?? rows.filter(r => containsAny(r, ['exfil', 'upload', 'bulk file', 'dlp'])).length);
  const privEscCount = Number(summary.privilegeEscalation ?? rows.filter(r => containsAny(r, ['privilege', 'admin', 'sudoers'])).length);
  const kpis = [
    { label: '👥 Total Users', val: shortNum(summary.totalUsers), trend: 'Observed entities', color: MON.blue, data: timeline },
    { label: '🟢 Active Users', val: shortNum(summary.activeUsers), trend: 'Seen in 5 minutes', color: MON.green, data: timeline },
    { label: '🔥 High Risk Users', val: shortNum(summary.highRiskUsers), trend: 'Risk ≥ 80', color: MON.red, data: timeline },
    { label: '🚨 Critical Alerts', val: shortNum(summary.critical ?? sevCounts.critical ?? 0), trend: 'Critical', color: MON.red, data: timeline },
    { label: '⚠️ Medium Alerts', val: shortNum(summary.medium ?? sevCounts.medium ?? 0), trend: 'Medium', color: MON.yellow, data: timeline },
    { label: '🔎 Low Alerts', val: shortNum(summary.low ?? sevCounts.low ?? 0), trend: 'Low', color: MON.green, data: timeline },
    { label: '🔗 Active Sessions', val: shortNum(summary.activeSessions), trend: 'Session signals', color: MON.cyan, data: timeline },
    { label: '📤 Data Exfiltration Events', val: shortNum(exfilCount), trend: 'Transfer anomalies', color: MON.orange, data: timeline },
    { label: '🕵️ Insider Threat Score', val: shortNum(summary.insiderThreatScore), trend: '0–100 score', color: MON.pink, data: timeline },
    { label: '↔️ Lateral Movement Events', val: shortNum(summary.lateralMovement), trend: 'Correlated movement', color: MON.purple, data: timeline },
    { label: '👑 Privilege Escalation Events', val: shortNum(privEscCount), trend: 'Privilege anomalies', color: MON.red, data: timeline },
    { label: '📊 UEBA Risk Score', val: shortNum(Math.round(Number(summary.averageRiskScore || 0))), trend: 'Average risk', color: MON.yellow, data: timeline },
    { label: '💻 Suspicious Devices', val: shortNum(summary.suspiciousDevices), trend: 'Device anomalies', color: MON.purple, data: timeline },
    { label: '🆕 New Devices', val: shortNum(summary.newDevices), trend: 'First-seen devices', color: MON.cyan, data: timeline },
    { label: '🌍 New Locations', val: shortNum(summary.newLocations ?? travelCount), trend: 'Geo anomalies', color: MON.orange, data: timeline },
    { label: '⛔ Blocked Users', val: shortNum(summary.blockedUsers), trend: 'Response state', color: MON.red, data: timeline },
    { label: '🛡️ Protected Endpoints', val: shortNum(summary.protectedEndpoints ?? backendSystems.length), trend: 'Managed agents', color: MON.blue, data: timeline },
    { label: '📡 Live Agents', val: shortNum(summary.liveAgents), trend: 'Last 5 minutes', color: MON.green, data: timeline },
    { label: '📴 Offline Agents', val: shortNum(Math.max(0, Number(summary.protectedEndpoints || backendSystems.length) - Number(summary.liveAgents || 0))), trend: 'Not currently live', color: MON.orange, data: timeline },
    { label: '🧠 Behavioral Signals', val: shortNum(totalRows), trend: 'Current window', color: MON.cyan, data: timeline },
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
      monitor: sys.edrEnabled !== false,
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
          <Ueba30DayBaselineTab />
        ) : activeTab === 'log-monitor' ? (
          <UebaLogMonitor alerts={rows} onAction={onAction} />
        ) : activeTab === 'reports' ? (
          <UebaReportsTab alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <UebaOverviewDashboard alerts={rows} total={totalRows} data={data} />
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
                  <b style={{ color: row.monitor ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.monitor ? 'Enabled' : 'Disabled'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen && !Number.isNaN(new Date(row.lastSeen).getTime()) ? new Date(row.lastSeen).toLocaleTimeString() : '—'}</span>
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
                  {topCounts(rows, alertUser, 5).map(([usr, count], index) => (
                    <div key={usr} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>👤 {usr}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} anomalies</span>
                    </div>
                  ))}
                  {!topCounts(rows, alertUser, 5).length && <div style={{ color: MON.muted }}>No identified user anomalies.</div>}
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
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/ueba/dashboard', { params: { limit: 250, windowHours: 24 }, skipCache: quiet });
      const payload = r.data || {};
      const next = Array.isArray(payload.events) ? payload.events : [];
      setAlerts(next);
      setTotal(Number(payload.summary?.total || next.length));
      setDashboardData(payload);
    } catch {
      setAlerts([]);
      setTotal(0);
      setDashboardData(null);
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
    const interval = setInterval(() => {
      loadAlerts(true);
      loadSystems();
    }, 60000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    const systemBuf = createEventBuffer(() => loadSystems(), 500);
    socket.on('connect', join);
    socket.on('ueba:event', buf.add);
    socket.on('alert:new', buf.add);
    socket.on('alert:updated', buf.add);
    socket.on('alert:deleted', buf.add);
    socket.on('agent:update-status', systemBuf.add);
    socket.on('system:status_changed', systemBuf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('ueba:event', buf.add);
      socket.off('alert:new', buf.add);
      socket.off('alert:updated', buf.add);
      socket.off('alert:deleted', buf.add);
      socket.off('agent:update-status', systemBuf.add);
      socket.off('system:status_changed', systemBuf.add);
      buf.clear();
      systemBuf.clear();
      disc();
    };
  }, [companyId, loadAlerts, loadSystems]);

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
        <UebaDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={dashboardData} />
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
