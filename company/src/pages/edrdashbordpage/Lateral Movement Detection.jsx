/**
 * Lateral Movement Detection — Capability ID: 14
 *
 * 100% Self-Contained Enterprise SOC Lateral Movement Detection & Attack Path Tracking Module
 * Linked to Live Backend API (`/api/lateral-movement/*`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12) & Credential Security (13)
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
function createEventBuffer(callback, delay = 1200) {
  let timer = null;
  let events = [];
  return {
    add(event) {
      events.push(event);
      if (timer) return;
      timer = setTimeout(() => {
        const buffered = events;
        events = [];
        timer = null;
        callback(buffered);
      }, delay);
    },
    clear() {
      clearTimeout(timer);
      timer = null;
      events = [];
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

function lateralValue(row, ...keys) {
  const sources = [row, row?.rawEvent, row?.rawEvent?.raw, row?.raw];
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      const value = source[key];
      if (value !== undefined && value !== null && value !== '') return value;
    }
  }
  return undefined;
}

function alertHost(row) {
  return lateralValue(row, 'destinationHost', 'dstHost', 'destHost', 'destination_hostname', 'destip', 'dstIp', 'destinationIp', 'hostname', 'host', 'agentName')
    || row?.systemId?.hostname || row?.systemId?.name || 'Unknown destination';
}

function alertUser(row) {
  return lateralValue(row, 'username', 'user', 'userName', 'account', 'accountName') || 'Unknown user';
}

function alertStatus(row) {
  return row?.status || row?.latStatus || row?.state || 'Observed';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const osStr = String(lateralValue(row, 'os', 'platform') || row?.systemId?.os || row?.system || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Lateral Movement Telemetry Field Extractors ───────────────────────────
function latSourceHost(row) {
  return lateralValue(row, 'sourceHost', 'srcHost', 'source_hostname', 'srcip', 'srcIp', 'sourceIp') || 'Unknown source';
}

function latVector(row) {
  return lateralValue(row, 'lateralVector', 'vector', 'eventType', 'event_type', 'ruleId', 'protocol') || 'Unknown vector';
}

function latRiskScore(row) {
  const score = Number(lateralValue(row, 'riskScore', 'risk_score', 'score'));
  return Number.isFinite(score) ? score : 0;
}

function lateralCommand(row) {
  return lateralValue(row, 'processCmdline', 'commandLine', 'command_line', 'cmdline') || 'Not reported by endpoint agent';
}

function lateralMitre(row) {
  const value = lateralValue(row, 'mitreTechniques', 'mitreTechnique', 'mitreId', 'mitre');
  if (Array.isArray(value)) return value;
  return value ? [value] : [];
}

function containsAny(row, words = []) {
  const haystack = [
    latVector(row), alertUser(row), alertHost(row), latSourceHost(row),
    row?.description, row?.message, lateralValue(row, 'processName', 'process_name'), lateralValue(row, 'shareName', 'share'),
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${latSourceHost(row)}-${latVector(row)}`;
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
export function LateralMovementLogDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'Open');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || ''));
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.EventLogs.EvtxHunter');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Security EVTX Hunter');
  const [huntNameInput, setHuntNameInput] = useState(`${alertHost(log)} lateral movement hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const commandLine = lateralCommand(log);
  const authProtocol = lateralValue(log, 'authProtocol', 'auth_protocol', 'authenticationProtocol') || 'Not reported';
  const shareName = lateralValue(log, 'shareName', 'share', 'targetShare') || 'Not reported';
  const impersonationToken = lateralValue(log, 'impersonationToken', 'token', 'securityToken') || 'Not reported';
  const sourceIp = lateralValue(log, 'srcip', 'srcIp', 'sourceIp') || 'Not reported';
  const destinationIp = lateralValue(log, 'destip', 'dstIp', 'destinationIp') || 'Not reported';
  const mitreTechniques = lateralMitre(log);
  const relatedEvents = Array.isArray(log.relatedEvents) ? log.relatedEvents : [];
  const threatIntel = lateralValue(log, 'threatIntel', 'iocMatches', 'ioc');
  const threatIntelLabel = threatIntel ? (typeof threatIntel === 'string' ? threatIntel : JSON.stringify(threatIntel)) : 'Not reported';
  const processName = lateralValue(log, 'processName', 'process_name') || 'Not reported';
  const parentProcess = lateralValue(log, 'parentProcessName', 'parent_process_name', 'parentProcess') || 'Not reported';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Host & Attack Path' },
    { id: 'process', label: '⚙️ 4. Process Ancestry' },
    { id: 'cred', label: '🔑 5. Credential & Remote Access' },
    { id: 'network', label: '🌐 6. Network & Traffic' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & Memory Dump' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Event Log Hunter', desc: 'Scan Event Logs: 5140 (Share Access), 7045 (Service Created), 4624 (Logon Type 3/10).', artifact: 'Windows.EventLogs.EvtxHunter' },
    { title: 'LSASS Memory & RAM Dump', desc: 'Inspect process handles to lsass.exe, Pass-The-Hash tokens, and remote ticket injection.', artifact: 'Windows.Memory.Acquisition' },
    { title: 'Linux East-West Network Connections', desc: 'Audit active listeners, SSH sessions, WinRM endpoints, and internal pivot connections.', artifact: 'Linux.Network.Netstat' },
    { title: 'Linux Active Remote Processes', desc: 'Inspect execution of psexec, wmic, powershell, impacket scripts, and sshd.', artifact: 'Linux.Sys.Pslist' },
    { title: 'YARA Tool Signature Sweep', desc: 'Run YARA sweeps for Mimikatz, Impacket, CrackMapExec, BloodHound, and Rubeus.', artifact: 'Generic.Detection.Yara.Glob' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = async () => {
    const systemId = typeof log.systemId === 'object' ? log.systemId?._id : log.systemId;
    if (!systemId) {
      setHuntSuccessMsg('Hunt not sent: this event has no tenant-scoped endpoint ID.');
      return;
    }
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    try {
      const response = await api.post('/forensics/hunts', {
        name: huntNameInput.trim() || selectedArtifactTitle,
        artifacts: [selectedArtifact],
        systemId,
      });
      setHuntSuccessMsg(`Hunt queued: ${response.data?.hunt?._id || 'request accepted'}`);
    } catch (error) {
      setHuntSuccessMsg(error.response?.data?.message || 'Unable to launch the forensic hunt.');
    } finally {
      setLaunchingHunt(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!log?._id || !analystNotes.trim()) return;
    try {
      await api.post(`/alerts/${log._id}/notes`, { text: analystNotes.trim(), assignedAnalyst, caseStatus, tags: tags.split(',').map(tag => tag.trim()).filter(Boolean) });
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 2000);
    } catch (error) {
      window.alert(error.response?.data?.message || 'Unable to save analyst notes.');
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
                  Lateral Movement Forensic Panel — {latVector(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Case ID: {log.caseId || log._id || 'Not assigned'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Source Host: <strong style={{ color: MON.cyan }}>{latSourceHost(log)}</strong> ➔ Target Host: <strong style={{ color: MON.red }}>{alertHost(log)}</strong> | User: <strong style={{ color: MON.text }}>{alertUser(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Attack Vector', latVector(log), MON.cyan],
                ['Target Host', alertHost(log), MON.red],
                ['Source Host / IP', latSourceHost(log), MON.blue],
                ['User Account', alertUser(log), MON.purple],
                ['Risk Score', `${latRiskScore(log)}/100`, latRiskScore(log) > 75 ? MON.red : MON.orange],
                ['Protocol / Port', `${lateralValue(log, 'protocol') || 'Not reported'} (Port: ${lateralValue(log, 'destPort', 'port') || 'Not reported'})`, MON.yellow],
                ['Enforcement Status', alertStatus(log), MON.green],
                ['Threat Intel Status', threatIntelLabel, MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Lateral Movement Attack Timeline</div>
              {(Array.isArray(log.timeline) && log.timeline.length ? log.timeline : relatedEvents.length ? relatedEvents : [{
                type: 'Observed event', time: alertTime(log) || '—', title: latVector(log),
                desc: log.description || `Telemetry reported from ${latSourceHost(log)} to ${alertHost(log)}.`, col: MON.cyan,
              }]).map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col || MON.cyan, background: `${ev.col || MON.cyan}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content' }}>{ev.type || ev.eventType || 'Observed'}</span>
                  <div style={{ color: MON.muted, fontWeight: 800, fontSize: 11, minWidth: 90 }}>{ev.time || ev.timestamp || ev.createdAt || '—'}</div>
                  <div style={{ width: 2, background: ev.col || MON.cyan, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{ev.title || ev.name || ev.ruleId || latVector(ev)}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{ev.desc || ev.description || 'No additional detail reported.'}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: ENDPOINT & ATTACK PATH */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Target Host System & Attack Path Details</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Target Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Source Hostname:</span> <strong style={{ color: MON.cyan }}>{latSourceHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Session State:</span> <strong style={{ color: MON.green }}>{lateralValue(log, 'sessionState', 'session_state') || alertStatus(log)}</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS ANCESTRY */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Process Ancestry & Command Line Execution</h4>
              <pre style={{ background: MON.card2, padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                {`Parent: ${parentProcess}\nProcess: ${processName}\nCommand: ${commandLine}`}
              </pre>
            </div>
          )}

          {/* TAB 5: CREDENTIAL & REMOTE ACCESS */}
          {activeTab === 'cred' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔑 Credential Abuse & Remote Access Protocol</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Auth Protocol:</span> <b style={{ color: MON.purple }}>{authProtocol}</b></div>
                <div><span style={{ color: MON.sub }}>Target Share:</span> <span>{shareName}</span></div>
                <div><span style={{ color: MON.sub }}>Impersonation Token:</span> <b style={{ color: MON.red }}>{impersonationToken}</b></div>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK & TRAFFIC */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Internal East-West Traffic & Port Details</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Source IP:</span> <b style={{ color: MON.cyan }}>{sourceIp}</b></div>
                <div><span style={{ color: MON.sub }}>Destination IP:</span> <b style={{ color: MON.yellow }}>{destinationIp}</b></div>
                <div><span style={{ color: MON.sub }}>Enforcement Status:</span> <b style={{ color: MON.green }}>{alertStatus(log)}</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                {mitreTechniques.length ? mitreTechniques.map((technique, index) => (
                  <div key={`${technique}-${index}`}><b style={{ color: [MON.red, MON.orange, MON.yellow][index % 3] }}>{String(technique)}</b></div>
                )) : <div style={{ color: MON.muted }}>No MITRE technique reported for this event.</div>}
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Lateral Movement Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Lateral Movement Payload</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {JSON.stringify(log.rawEvent || log.raw || log, null, 2)}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Lateral Threat Remediation</h4>
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
                      <option value="Host Isolated">Host Isolated</option>
                      <option value="Resolved">Resolved</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Incident Tags</label>
                    <input type="text" value={tags} onChange={e => setTags(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                </div>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" onClick={() => (typeof onAction === 'function' && log?._id ? onAction(String(log._id), 'isolate') : window.alert('Not sent: no response executor is configured.'))} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    ⛔ Isolate Target Host & Terminate SMB Session
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
export function LateralMovementLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const openInvestigation = useCallback(async (row) => {
    setSelectedLog(row);
    if (!row?._id) return;
    try {
      const response = await api.get(`/lateral-movement/log/${row._id}`);
      const event = response.data?.event;
      if (event) setSelectedLog({ ...row, ...event, relatedEvents: response.data?.relatedEvents || [] });
    } catch {
      // Keep the list record visible when the optional forensic enrichment fails.
    }
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${alertHost(a)} ${latSourceHost(a)} ${latVector(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Target Host, Source Host, Vector, User Account, Protocol..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Lateral Movement & Attack Path SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 1fr 1.2fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Target Host System</span><span>Source Host / IP</span><span>Attack Vector / Protocol</span><span>User Account</span><span>Action Executed</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 1fr 1.2fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.red, cursor: 'pointer', display: 'block' }} onClick={() => openInvestigation(row)}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{processOs(row)}</span>
                </div>
                <b style={{ color: MON.blue }}>{latSourceHost(row)}</b>
                <b style={{ color: MON.purple }}>{latVector(row)}</b>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertUser(row)}</b>
                </div>
                <b style={{ color: MON.green }}>{alertStatus(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => openInvestigation(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No lateral movement telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <LateralMovementLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function LateralMovementReportsTab({ alerts = [], departmentId }) {
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

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const response = await api.get('/lateral-movement/reports', { params: { period: reportType, limit: 10000, departmentId: departmentId || undefined } });
      const filtered = Array.isArray(response.data?.events) ? response.data.events : [];
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({ alerts: filtered, total: Number(response.data?.total ?? filtered.length), bySev });
    } catch {
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
    } finally {
      setGenerating(false);
      setGenerated(true);
    }
  };

  const handleExportCSV = async () => {
    try {
      const response = await api.post('/lateral-movement/export', { format: 'csv', filters: { period: reportType, departmentId: departmentId || undefined } }, { responseType: 'blob' });
      downloadBlob(response.data, `lateral_movement_${reportType}.csv`, 'text/csv;charset=utf-8;');
    } catch {
      const filtered = reportData?.alerts || getFilteredAlerts();
      const header = 'Timestamp,Target Host,Source Host,Vector,User,Severity,Status';
      const rows = filtered.map(a => [csvCell(alertTime(a)), csvCell(alertHost(a)), csvCell(latSourceHost(a)), csvCell(latVector(a)), csvCell(alertUser(a)), csvCell(alertSeverity(a)), csvCell(alertStatus(a))].join(','));
      downloadBlob([header, ...rows].join('\n'), `lateral_movement_${reportType}_${filtered.length}records.csv`);
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Lateral Movement & Attack Path Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for internal PsExec, WMI, SMB ADMIN$, and SSH pivot attacks</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Lateral Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Lateral Movement Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Lateral Alerts: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Lateral Movement Alerts', val: reportData?.total, color: MON.cyan },
              { label: 'Critical PsExec & Share Execs', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Pass-The-Hash Pivots', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Remote Audits', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Lateral Movement Detection Dashboard ─────────────
function AlertsOverTimeChart({ data = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'];
  const chartData = data.length > 1 ? data.map(value => Number(value) || 0) : [0, 0];
  const yMax = Math.max(...chartData, 1);
  const yLabels = [yMax, Math.round(yMax * .75), Math.round(yMax * .5), Math.round(yMax * .25), 0].map(String);

  const chartW = 420;
  const chartH = 150;
  const padLeft = 28;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = chartData.map((v, i) => ({
    x: padLeft + (i / (chartData.length - 1)) * innerW,
    y: padTop + innerH - (v / yMax) * innerH,
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

  const areaPath = `${d} L ${pts[pts.length - 1].x},${padTop + innerH} L ${pts[0].x},${padTop + innerH} Z`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>ALERTS OVER TIME</span>
        <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          <defs>
            <linearGradient id="latAlertGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.0" />
            </linearGradient>
          </defs>
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
          <path d={areaPath} fill="url(#latAlertGrad)" />
          <path d={d} fill="none" stroke="#ef4444" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function AlertsBySeverityDonut({ counts = {} }) {
  const total = ['critical', 'high', 'medium', 'low'].reduce((sum, key) => sum + Number(counts[key] || 0), 0);
  const sevs = [
    { label: 'Critical', count: Number(counts.critical || 0), color: '#f87171' },
    { label: 'High', count: Number(counts.high || 0), color: '#fb923c' },
    { label: 'Medium', count: Number(counts.medium || 0), color: '#fbbf24' },
    { label: 'Low', count: Number(counts.low || 0), color: '#38bdf8' },
  ].map(item => ({ ...item, pct: total ? Number(((item.count / total) * 100).toFixed(1)) : 0 }));

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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>ALERTS BY SEVERITY</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 8.5 }}>
          {sevs.map(s => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color }} /> {s.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{s.count} ({s.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function AuthenticationEventsDonut({ counts = {} }) {
  const total = Number(counts.successful || 0) + Number(counts.failed || 0) + Number(counts.other || 0);
  const events = [
    { label: 'Successful', count: Number(counts.successful || 0), color: '#34d399' },
    { label: 'Failed', count: Number(counts.failed || 0), color: '#f87171' },
    { label: 'Other', count: Number(counts.other || 0), color: '#38bdf8' },
  ].map(item => ({ ...item, pct: total ? Number(((item.count / total) * 100).toFixed(1)) : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = events.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>AUTHENTICATION EVENTS</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 8.5 }}>
          {events.map(e => (
            <div key={e.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: e.color }} /> {e.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{e.count} ({e.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EndpointRiskStatusDonut({ counts = {} }) {
  const total = Number(counts.high || 0) + Number(counts.medium || 0) + Number(counts.low || 0);
  const statuses = [
    { label: 'High Risk', count: Number(counts.high || 0), color: '#f87171' },
    { label: 'Medium Risk', count: Number(counts.medium || 0), color: '#fb923c' },
    { label: 'Low Risk', count: Number(counts.low || 0), color: '#34d399' },
  ].map(item => ({ ...item, pct: total ? Number(((item.count / total) * 100).toFixed(1)) : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = statuses.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>ENDPOINT RISK STATUS</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 8.5 }}>
          {statuses.map(s => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color }} /> {s.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{s.count} ({s.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function RiskSpeedometerGauge({ score = 0 }) {
  const normalizedScore = Math.max(0, Math.min(100, Number(score) || 0));
  const maxScore = 100;
  const pct = normalizedScore / maxScore;

  // Arc calculation from -180 deg to 0 deg
  const radius = 45;
  const cx = 60;
  const cy = 60;
  const strokeWidth = 12;

  const startRad = Math.PI;
  const endRad = Math.PI * (1 - pct);

  const x2 = cx + radius * Math.cos(endRad);
  const y2 = cy - radius * Math.sin(endRad);

  const d = `M 15 60 A ${radius} ${radius} 0 0 1 ${x2} ${y2}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'space-between' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', width: '100%' }}>LATERAL MOVEMENT RISK SCORE</span>
      <div style={{ position: 'relative', width: 120, height: 65, marginTop: 4 }}>
        <svg viewBox="0 0 120 65" width="120" height="65">
          <path d="M 15 60 A 45 45 0 0 1 105 60" fill="none" stroke="#16273e" strokeWidth={strokeWidth} strokeLinecap="round" />
          <path d={d} fill="none" stroke="url(#riskGaugeGrad)" strokeWidth={strokeWidth} strokeLinecap="round" />
          <defs>
            <linearGradient id="riskGaugeGrad" x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor="#22c55e" />
              <stop offset="50%" stopColor="#eab308" />
              <stop offset="100%" stopColor="#ef4444" />
            </linearGradient>
          </defs>
        </svg>
        <div style={{ position: 'absolute', bottom: 0, insetX: 0, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <span style={{ fontSize: 18, fontWeight: 900, color: '#fff', lineHeight: 1 }}>{Math.round(normalizedScore)} <span style={{ fontSize: 10, color: '#8ea0b8', fontWeight: 600 }}>/100</span></span>
          <span style={{ fontSize: 9, color: normalizedScore >= 70 ? '#ef4444' : normalizedScore >= 40 ? '#fbbf24' : '#34d399', fontWeight: 800, marginTop: 2 }}>{normalizedScore >= 70 ? 'High Risk' : normalizedScore >= 40 ? 'Medium Risk' : 'Low Risk'}</span>
        </div>
      </div>
      <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View Details</span>
    </div>
  );
}

function LateralMovementOverviewDashboard({ alerts = [], total = 0, systems = [], analytics = null }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const localSeverityCounts = rows.reduce((acc, row) => { const key = alertSeverity(row); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
  const summary = analytics?.summary || {};
  const severityCounts = {
    critical: Number(summary.critical ?? localSeverityCounts.critical ?? 0), high: Number(summary.high ?? localSeverityCounts.high ?? 0),
    medium: Number(summary.medium ?? localSeverityCounts.medium ?? 0), low: Number(summary.low ?? localSeverityCounts.low ?? 0),
  };
  const averageRisk = Number(summary.averageRiskScore ?? (rows.length ? rows.reduce((sum, row) => sum + latRiskScore(row), 0) / rows.length : 0));
  const securityScore = Math.max(0, Math.round(100 - averageRisk));
  const isOnline = system => system?.online === true || ['online', 'active', 'reporting', 'connected'].includes(String(system?.status || '').toLowerCase()) || (system?.lastSeen && Date.now() - new Date(system.lastSeen).getTime() < 5 * 60 * 1000);
  const onlineSystems = Number(summary.liveAgents ?? systems.filter(isOnline).length);
  const protectedEndpoints = Number(summary.protectedEndpoints ?? systems.length);
  const topCards = [
    { title: 'OVERALL SECURITY SCORE', val: `${securityScore} /100`, sub: securityScore >= 80 ? 'Good' : securityScore >= 60 ? 'Watch' : 'At Risk', subCol: securityScore >= 80 ? '#34d399' : securityScore >= 60 ? '#fbbf24' : '#f87171', icon: '🛡️', iconBg: 'rgba(52, 211, 153, 0.15)' },
    { title: 'TOTAL ALERTS', val: shortNum(Math.max(Number(summary.total || 0), Number(total || 0), rows.length)), sub: 'Last 24h', subCol: '#f87171', icon: '🔔', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'CRITICAL ALERTS', val: shortNum(severityCounts.critical), sub: 'Observed', subCol: '#f87171', icon: '⚠️', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'HIGH ALERTS', val: shortNum(severityCounts.high), sub: 'Observed', subCol: '#fb923c', icon: '⚠️', iconBg: 'rgba(251, 146, 60, 0.15)' },
    { title: 'MEDIUM ALERTS', val: shortNum(severityCounts.medium), sub: 'Observed', subCol: '#fbbf24', icon: '⚠️', iconBg: 'rgba(251, 191, 36, 0.15)' },
    { title: 'LOW ALERTS', val: shortNum(severityCounts.low), sub: 'Observed', subCol: '#38bdf8', icon: 'ℹ️', iconBg: 'rgba(56, 189, 248, 0.15)' },
    { title: 'ASSETS MONITORED', val: shortNum(protectedEndpoints), sub: `${onlineSystems} Online`, subCol: '#34d399', icon: '🖥️', iconBg: 'rgba(52, 211, 153, 0.15)' },
  ];

  const categoryDefinitions = [
    ['Remote Services', ['rdp', 'ssh', 'smb', 'wmi', 'winrm', 'psexec', 'remote']],
    ['Credential Access', ['credential', 'hash', 'ticket', 'kerberos', 'lsass', 'mimikatz', 'rubeus']],
    ['Discovery', ['scan', 'enumeration', 'bloodhound', 'sharphound', 'adfind']],
    ['Execution', ['powershell', 'cmd', 'process', 'service', 'scheduled task']],
    ['Defense Evasion', ['token', 'impersonation', 'fileless', 'injection']],
  ];
  const categoryRows = categoryDefinitions.map(([name, words]) => ({ name, count: rows.filter(row => containsAny(row, words)).length }));
  const categoryMax = Math.max(...categoryRows.map(item => item.count), 1);
  const topCategories = categoryRows.map((item, index) => ({ ...item, pct: Math.round((item.count / categoryMax) * 100), col: ['#f87171', '#fb923c', '#fbbf24', '#38bdf8', '#34d399'][index] }));

  const vectorDefinitions = [
    ['RDP Sessions', ['rdp', 'mstsc', '3389'], '🖥️'], ['SMB Connections', ['smb', '445', 'admin$'], '📂'],
    ['WMI Executions', ['wmi', 'wmic'], '⚙️'], ['PsExec Activities', ['psexec', 'paexec'], '⚡'],
    ['PowerShell Remoting', ['powershell remoting', 'winrm', 'pssession'], '📜'],
  ];
  const lateralDetectionVectors = vectorDefinitions.map(([name, words, icon]) => ({ name, count: rows.filter(row => containsAny(row, words)).length, change: '24h', icon }));

  const sourceColors = ['#f87171', '#f87171', '#fb923c', '#fb923c', '#34d399'];
  const sourceCounts = analytics?.topSources?.length ? analytics.topSources.slice(0, 5).map(item => [item._id, item.count]) : topCounts(rows, latSourceHost, 5);
  const destinationCounts = analytics?.topDestinations?.length ? analytics.topDestinations.slice(0, 5).map(item => [item._id, item.count]) : topCounts(rows, alertHost, 5);
  const topSourcesInternal = sourceCounts.map(([ip, count], index) => ({ ip, count, col: sourceColors[index], data: buildBuckets(rows.filter(row => latSourceHost(row) === ip), 6, 24) }));
  const topDestinationsInternal = destinationCounts.map(([ip, count], index) => ({ ip, count, col: sourceColors[index], data: buildBuckets(rows.filter(row => alertHost(row) === ip), 6, 24) }));
  const timelineData = analytics?.timeline?.length ? analytics.timeline.map(item => Number(item.count || 0)) : buildBuckets(rows, 9, 24);

  const recentCriticalAlerts = rows.filter(row => ['critical', 'high'].includes(alertSeverity(row))).slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—',
    alert: row.description || row.ruleId || latVector(row), ip: latSourceHost(row),
  }));
  const threatIntelFeed = rows.filter(row => lateralValue(row, 'threatIntel', 'iocMatches', 'ioc')).slice(0, 5).map(row => ({
    title: typeof lateralValue(row, 'threatIntel', 'iocMatches', 'ioc') === 'string' ? lateralValue(row, 'threatIntel', 'iocMatches', 'ioc') : JSON.stringify(lateralValue(row, 'threatIntel', 'iocMatches', 'ioc')),
    sev: alertSeverity(row), sevCol: SEV_COLOR[alertSeverity(row)] || '#38bdf8',
  }));

  const sensorStatuses = systems.slice(0, 8).map(system => ({ name: system.hostname || system.name || 'Endpoint', icon: '💻', status: isOnline(system) ? 'Active' : 'Offline' }));
  const ingestionPct = rows.length ? 100 : 0;
  const processed = rows.filter(row => alertStatus(row)).length;
  const systemStatus = [
    { label: 'System Health', pct: protectedEndpoints ? Math.round((onlineSystems / protectedEndpoints) * 100) : 0 },
    { label: 'Log Ingestion', pct: ingestionPct },
    { label: 'Alert Processing', pct: rows.length ? Math.round((processed / rows.length) * 100) : 0 },
  ].map(item => ({ ...item, val: `${item.pct}%` }));
  const authCounts = rows.reduce((acc, row) => { const text = `${latVector(row)} ${row.description || ''} ${alertStatus(row)}`.toLowerCase(); const key = /fail|denied|invalid/.test(text) ? 'failed' : /success|accepted|logged.in/.test(text) ? 'successful' : 'other'; acc[key] += 1; return acc; }, { successful: 0, failed: 0, other: 0 });
  const endpointRisk = new Map();
  rows.forEach(row => endpointRisk.set(alertHost(row), Math.max(endpointRisk.get(alertHost(row)) || 0, latRiskScore(row))));
  const endpointRiskCounts = Array.from(endpointRisk.values()).reduce((acc, score) => { acc[score >= 70 ? 'high' : score >= 40 ? 'medium' : 'low'] += 1; return acc; }, { high: 0, medium: 0, low: 0 });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (7 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 10 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, padding: '10px 10px', display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 32, height: 32, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0 }}>
              {c.icon}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 8.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.title}
              </span>
              <span style={{ fontSize: 18, fontWeight: 800, color: '#ffffff', margin: '1px 0' }}>
                {c.val}
              </span>
              <span style={{ fontSize: 8, fontWeight: 700, color: c.subCol }}>
                {c.sub}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.2fr', gap: 12 }}>
        <div style={panelStyle}>
          <AlertsOverTimeChart data={timelineData} />
        </div>

        <div style={panelStyle}>
          <AlertsBySeverityDonut counts={severityCounts} />
        </div>

        {/* Top Alert Categories */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>TOP ALERT CATEGORIES</span>
              <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {topCategories.map(cat => (
                <div key={cat.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.5fr 0.3fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cat.name}</span>
                  <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ width: `${cat.pct}%`, height: '100%', background: cat.col, borderRadius: 3 }} />
                  </div>
                  <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{cat.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1.2fr', gap: 12 }}>
        {/* Lateral Movement Detection */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>LATERAL MOVEMENT DETECTION</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {lateralDetectionVectors.map(v => (
                <div key={v.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{v.icon}</span> {v.name}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: '#ffffff', fontWeight: 800 }}>{v.count}</span>
                    <span style={{ color: '#fb923c', fontWeight: 800, fontSize: 8.5 }}>{v.change}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
          </div>
        </div>

        {/* Top Sources (Internal) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP SOURCES (INTERNAL)</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>IP ADDRESS</span>
              <span>ALERTS</span>
              <span>TREND</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topSourcesInternal.map(s => (
                <div key={s.ip} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{s.ip}</span>
                  <span style={{ color: '#ffffff', fontWeight: 800 }}>{s.count}</span>
                  <div style={{ height: 14 }}>
                    <MiniSparkline data={s.data} color={s.col} height={14} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
          </div>
        </div>

        {/* Top Destinations (Internal) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP DESTINATIONS (INTERNAL)</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>IP ADDRESS</span>
              <span>ALERTS</span>
              <span>TREND</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topDestinationsInternal.map(d => (
                <div key={d.ip} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.6fr 1fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{d.ip}</span>
                  <span style={{ color: '#ffffff', fontWeight: 800 }}>{d.count}</span>
                  <div style={{ height: 14 }}>
                    <MiniSparkline data={d.data} color={d.col} height={14} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
          </div>
        </div>

        {/* Recent Critical Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>RECENT CRITICAL ALERTS</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {recentCriticalAlerts.map((rc, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5, borderBottom: '1px solid #16273e', paddingBottom: 4 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 1, minWidth: 0 }}>
                    <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>● {rc.alert}</span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8 }}>{rc.ip}</span>
                  </div>
                  <span style={{ color: '#64748b', fontSize: 8, flexShrink: 0, marginLeft: 6 }}>{rc.time}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8, textAlign: 'center' }}>
            <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts</span>
          </div>
        </div>
      </div>

      {/* 4. LOWER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <AuthenticationEventsDonut counts={authCounts} />
        </div>

        <div style={panelStyle}>
          <EndpointRiskStatusDonut counts={endpointRiskCounts} />
        </div>

        {/* Threat Intelligence Feed */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>THREAT INTELLIGENCE FEED</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {threatIntelFeed.map((ti, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ti.title}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, color: ti.sevCol, padding: '1px 5px', borderRadius: 4, background: `${ti.sevCol}15`, border: `1px solid ${ti.sevCol}33`, flexShrink: 0, marginLeft: 6 }}>
                    {ti.sev}
                  </span>
                </div>
              ))}
              {!threatIntelFeed.length && <span style={{ color: '#64748b', fontSize: 8.5 }}>No threat-intelligence matches reported.</span>}
            </div>
          </div>
          <div style={{ marginTop: 8, textAlign: 'center' }}>
            <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Intel</span>
          </div>
        </div>

        <div style={panelStyle}>
          <RiskSpeedometerGauge score={averageRisk} />
        </div>
      </div>

      {/* 5. BOTTOM GRID (2 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1fr', gap: 12 }}>
        {/* Sensor / Log Sources Status (8 Cards in a Row) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>SENSOR / LOG SOURCES STATUS</span>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 8 }}>
            {sensorStatuses.map(s => (
              <div key={s.name} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '8px 6px', display: 'flex', flexDirection: 'column', alignItems: 'center', textAlign: 'center' }}>
                <span style={{ fontSize: 16 }}>{s.icon}</span>
                <span style={{ fontSize: 8.5, color: '#8ea0b8', margin: '3px 0 1px 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', width: '100%' }}>{s.name}</span>
                <span style={{ fontSize: 7.5, fontWeight: 800, color: s.status === 'Active' ? '#34d399' : '#f87171' }}>● {s.status}</span>
              </div>
            ))}
            {!sensorStatuses.length && <span style={{ gridColumn: '1 / -1', color: '#64748b', fontSize: 9 }}>No endpoint agents reported.</span>}
          </div>
        </div>

        {/* System Status (3 Health Progress Bars) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>SYSTEM STATUS</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {systemStatus.map(ss => (
              <div key={ss.label} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr 0.4fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1' }}>{ss.label}</span>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${ss.pct}%`, height: '100%', background: '#34d399', borderRadius: 3 }} />
                </div>
                <span style={{ color: '#34d399', fontWeight: 800, textAlign: 'right' }}>{ss.val}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`LateralMovementDashboardPanel` / `LateralMovementDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function LateralMovementDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, departmentId, onAction }) {
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
  const summary = data?.summary || {};
  const totalRows = Math.max(Number(summary.total || 0), Number(total || 0), Number(recordsTotal || 0), rows.length);
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

  // 20 Lateral Movement Specific SOC Categories & Metrics
  const psexecCount = Number(summary.psexecActivities ?? rows.filter(r => containsAny(r, ['psexec', 'paexec', 'service'])).length);
  const wmiCount = Number(summary.wmiExecutions ?? rows.filter(r => containsAny(r, ['wmi', 'wmic', 'winrm'])).length);
  const pthCount = Number(summary.credentialAbuseEvents ?? rows.filter(r => containsAny(r, ['pass the hash', 'pth', 'ntlm relay'])).length);
  const smbCount = Number(summary.smbSessions ?? rows.filter(r => containsAny(r, ['smb', 'admin$', 'c$', 'ipc$'])).length);
  const sshCount = Number(summary.sshSessions ?? rows.filter(r => containsAny(r, ['ssh', 'pam', 'auth.log'])).length);
  const rdpCount = Number(summary.rdpSessions ?? rows.filter(r => containsAny(r, ['rdp', 'mstsc', '3389'])).length);

  const kpis = [
    { label: '🛡️ 1. Total Lateral Movement Alerts', val: shortNum(totalRows), trend: 'Pivot Signals', color: MON.blue, data: timeline },
    { label: '⚙️ 2. PsExec & Remote Service Execs', val: shortNum(psexecCount), trend: 'PsExec Exec', color: MON.red, data: timeline },
    { label: '🔑 3. Pass-The-Hash Credential Abuse', val: shortNum(pthCount), trend: 'Pass-The-Hash', color: MON.orange, data: timeline },
    { label: '📁 4. SMB ADMIN$ & C$ Share Pivots', val: shortNum(smbCount), trend: 'Admin Share', color: MON.purple, data: timeline },
    { label: '🖥️ 5. Remote WMI & WinRM Executions', val: shortNum(wmiCount), trend: 'WMI Exec', color: MON.yellow, data: timeline },
    { label: '🐧 6. Linux SSH East-West Key Pivots', val: shortNum(sshCount), trend: 'SSH Pivot', color: MON.red, data: timeline },
    { label: '💻 7. Active RDP Remote Interactive Sessions', val: shortNum(rdpCount), trend: 'RDP Session', color: MON.cyan, data: timeline },
    { label: '👑 8. Domain Admin Token Impersonation', val: shortNum(rows.filter(r => containsAny(r, ['admin', 'system', 'token'])).length), trend: 'Token Impers', color: MON.red, data: timeline },
    { label: '🛣️ 9. Multi-Hop East-West Attack Chains', val: shortNum(rows.filter(r => containsAny(r, ['chain', 'hop', 'pivot'])).length), trend: 'Attack Path', color: MON.orange, data: timeline },
    { label: '📡 10. RPC Endpoint Mapper Queries', val: shortNum(rows.filter(r => containsAny(r, ['rpc', 'epm', '135'])).length), trend: 'RPC Query', color: MON.pink, data: timeline },
    { label: '💾 11. Impacket Tool Suite Executions', val: shortNum(rows.filter(r => containsAny(r, ['impacket', 'smbexec', 'wmiexec'])).length), trend: 'Impacket', color: MON.red, data: timeline },
    { label: '🩸 12. BloodHound / Sharphound Recon', val: shortNum(rows.filter(r => containsAny(r, ['bloodhound', 'sharphound'])).length), trend: 'BloodHound', color: MON.purple, data: timeline },
    { label: '🛠️ 13. CrackMapExec Network Sweeps', val: shortNum(rows.filter(r => containsAny(r, ['crackmapexec', 'cme'])).length), trend: 'CrackMapExec', color: MON.yellow, data: timeline },
    { label: '🔌 14. Named Pipe File Transfers', val: shortNum(rows.filter(r => containsAny(r, ['pipe', 'psexecsvc'])).length), trend: 'Named Pipe', color: MON.cyan, data: timeline },
    { label: '🌐 15. Port 445 / 135 Internal Scanning', val: shortNum(rows.filter(r => containsAny(r, ['scan', 'port 445', 'port 135'])).length), trend: 'Internal Scan', color: MON.blue, data: timeline },
    { label: '🪟 16. Windows Monitored Pivot Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows Pivot', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux Monitored Pivot Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux eBPF', color: MON.orange, data: timeline },
    { label: '🍎 18. macOS Monitored Pivot Endpoints', val: shortNum(osCounts.macOS || 0), trend: 'macOS Pivot', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Lateral Compromise Alerts', val: shortNum(summary.critical ?? sevCounts.critical ?? 0), trend: 'Critical Pivot', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk Remote Execution Alerts', val: shortNum(summary.high ?? sevCounts.high ?? 0), trend: 'High Risk', color: MON.orange, data: timeline },
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
          <LateralMovementLogMonitor alerts={alerts} onAction={onAction} />
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={14} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <LateralMovementOverviewDashboard alerts={alerts} total={totalRows} systems={backendSystems} analytics={data} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Lateral Movement & Attack Path Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Network Pivot Sensor Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Pivot Sensor</span><span>Signals</span><span>Lateral Alerts</span><span>Last Audit</span>
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
                  No backend lateral agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 East-West Lateral Activity Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} lateral events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Lateral Attack Vectors</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, latVector, 5).map(([vec, count], index) => (
                    <div key={vec} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{vec}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Remote Protocol Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['SMB / CIFS (Port 445)', smbCount],
                    ['RDP / MSTSC (Port 3389)', rdpCount],
                    ['SSH / SFTP (Port 22)', sshCount],
                    ['WMI / WinRM (Port 5985)', wmiCount],
                  ].map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.cyan, MON.blue, MON.purple, MON.orange][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`LateralMovementMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function LateralMovementMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '14';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const dashboardResponse = await api.get('/lateral-movement/dashboard', { params: { windowHours: 24, limit: 250 }, skipCache: quiet });
      const payload = dashboardResponse.data || {};
      const next = payload.events || [];
      setAlerts(next);
      setTotal(payload.summary?.total || next.length);
      setDashboardData(payload);
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
    const buf = createEventBuffer(items => {
      const incoming = items.filter(event => event?._id);
      if (!incoming.length) return;
      setAlerts(previous => {
        const byId = new Map(previous.map(event => [String(event._id), event]));
        let added = 0;
        incoming.forEach(event => {
          const key = String(event._id);
          if (!byId.has(key)) added += 1;
          byId.set(key, event);
        });
        const merged = Array.from(byId.values())
          .sort((a, b) => new Date(b.createdAt || b.timestamp || 0) - new Date(a.createdAt || a.timestamp || 0))
          .slice(0, 250);
        if (added) setTotal(current => Math.max(merged.length, Number(current || 0) + added));
        return merged;
      });
    }, 1000);
    socket.on('connect', join);
    socket.on('lateral:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('lateral:event', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleResponseAction = useCallback(async (alertId, action) => {
    const reason = window.prompt('Enter the reason for this containment action:')?.trim() || '';
    if (!reason || !window.confirm(`Confirm ${String(action).replaceAll('_', ' ')} for this alert?`)) return;
    await api.post('/lateral-movement/respond', { alertId, actionType: action, reason, confirmed: true });
    await loadAlerts(true);
  }, [loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 14. Lateral Movement Detection
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <LateralMovementDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={dashboardData} onAction={handleResponseAction} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <LateralMovementMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function LateralMovementSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=14" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Lateral Movement SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=14')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="lateralmovement" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <LateralMovementDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { LateralMovementDashboardPanel as LateralMovementDashboard };
