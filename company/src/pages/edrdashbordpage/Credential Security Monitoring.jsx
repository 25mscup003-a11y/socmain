/**
 * Credential Security Monitoring — Capability ID: 13
 *
 * 100% Self-Contained Enterprise SOC Credential Security & Identity Protection Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=13`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11) & Data Security (12)
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

const CREDENTIAL_CONFIG_DEFAULTS = {
  enabled: true,
  monitorProcesses: true,
  monitorCredentialStores: true,
  monitorLockScreen: true,
  scanIntervalSeconds: 20,
  minimumRiskScore: 50,
  builtInRuleOverrides: {},
  version: 1,
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

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'unknown';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || row?.account || 'unknown';
}

function alertStatus(row) {
  return row?.status || row?.credStatus || row?.state || 'Blocked';
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

// ── Credential Security Telemetry Field Extractors ─────────────────────────
function credEventId(row) {
  return row?.windowsEventId || row?.rawEvent?.windows_event_id || row?.rawEvent?.raw?.windows_event_id || row?.eventCode || row?.ruleId || '—';
}

function credAuthType(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.authType || row?.authProtocol || raw.auth_method || row?.protocol || 'Unknown';
}

function credThreat(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.credentialEventType || row?.action || row?.description || row?.threat || raw.description || row?.ruleId || 'Unknown credential event';
}

function credRiskScore(row) {
  return Number(row?.riskScore ?? row?.score ?? 0);
}

function credentialResult(row) {
  const explicit = String(row?.authResult || row?.result || row?.rawEvent?.auth_result || row?.rawEvent?.raw?.auth_result || '').toLowerCase();
  if (explicit) return explicit;
  const text = `${row?.ruleId || ''} ${row?.credentialEventType || ''} ${row?.description || ''}`.toLowerCase();
  if (/fail|invalid|denied|lockout|brute|spray/.test(text)) return 'failure';
  if (/success|accepted|login|logon|session.open/.test(text)) return 'success';
  return 'unknown';
}

function credentialCategory(row) {
  const text = `${credThreat(row)} ${row?.ruleId || ''}`.toLowerCase();
  if (/brute|spray|stuffing/.test(text)) return 'Brute Force';
  if (/privilege|admin|sudo|root|uac/.test(text)) return 'Privileged Access';
  if (/lsass|sam|mimikatz|dump|secrets|password.store|keychain/.test(text)) return 'Credential Theft';
  if (/token|session.hijack|impossible.travel|new.device/.test(text)) return 'Account Takeover';
  if (/policy|disabled|dormant|lockout/.test(text)) return 'Policy Violation';
  return 'Other';
}

function credentialSourceIp(row) {
  return row?.srcip || row?.srcIp || row?.sourceIp || row?.rawEvent?.src_ip || row?.rawEvent?.raw?.src_ip || '—';
}

function credentialCountry(row) {
  return row?.geoCountry || row?.country || row?.rawEvent?.geoCountry || 'Unknown';
}

function containsAny(row, words = []) {
  const haystack = [
    credThreat(row), alertUser(row), alertHost(row), credAuthType(row), String(credEventId(row)),
    row?.description, row?.message, row?.processName, row?.failureReason,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${alertUser(row)}-${credEventId(row)}`;
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
export function CredentialSecurityLogDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || '');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState(log?.ruleId || log?.credentialEventType || '');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.EventLogs.EvtxHunter');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Security EVTX Hunter');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'unknown-host'} credential attack hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Host & Identity' },
    { id: 'process', label: '⚙️ 4. Process & Ancestry' },
    { id: 'auth', label: '🔑 5. Credential & Auth' },
    { id: 'network', label: '🌐 6. Network & Geo' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & LSASS Dump' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows EVTX Security Hunter', desc: 'Scan Event Logs: 4624 (Logon), 4625 (Failed Logon), 4672 (Admin Privs), 4768/4769 (Kerberos).', artifact: 'Windows.EventLogs.EvtxHunter' },
    { title: 'LSASS & Process RAM Acquisition', desc: 'Dump LSASS process memory handles, Kerberos ticket cache, and SAM hashes.', artifact: 'Windows.Memory.Acquisition' },
    { title: 'Linux Auth & PAM Log Hunter', desc: 'Inspect /var/log/auth.log, sudoers abuse, SSH key modifications, and PAM modules.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'Active Identity Processes', desc: 'Audit processes holding handles to LSASS, mimikatz, powershell, and sshd.', artifact: 'Linux.Sys.Pslist' },
    { title: 'YARA Credential Dump Sweep', desc: 'Run YARA sweeps for Mimikatz signatures, Pass-The-Hash tools, and browser password dumpers.', artifact: 'Generic.Detection.Yara.Glob' },
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
                  Credential Security Forensic Panel — {alertUser(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Event ID: {credEventId(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                User: <strong style={{ color: MON.cyan }}>{alertUser(log)}</strong> | Protocol: <strong style={{ color: MON.yellow }}>{credAuthType(log)}</strong> | Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Credential Threat', credThreat(log), MON.cyan],
                ['Event ID Code', credEventId(log), MON.yellow],
                ['Authentication Result', log.authResult || log.result || 'Unknown', log.authResult === 'success' ? MON.green : MON.red],
                ['Risk Score', `${credRiskScore(log)}/100`, credRiskScore(log) > 75 ? MON.red : MON.orange],
                ['Target Host System', alertHost(log), MON.blue],
                ['Target User Account', alertUser(log), MON.cyan],
                ['Source IP & Country', `${credentialSourceIp(log)} (${credentialCountry(log)})`, MON.red],
                ['Auth Protocol', credAuthType(log), MON.purple],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Credential Attack & Authentication Chronology</div>
              {[
                { type: log.credentialEventType || log.eventType || 'Credential Event', time: alertTime(log) || '—', title: credThreat(log), desc: `${alertUser(log)} · ${credentialSourceIp(log)} · ${credAuthType(log)}`, col: sevColor },
                ...(Array.isArray(log.relatedEvents) ? log.relatedEvents : []).map(item => ({ type: item.credentialEventType || item.eventType || 'Related Event', time: alertTime(item) || '—', title: credThreat(item), desc: item.description || item.ruleId || 'Related credential evidence', col: SEV_COLOR[alertSeverity(item)] || MON.cyan })),
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

          {/* TAB 3: ENDPOINT & IDENTITY */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Target Host System & Identity Profile</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Target User:</span> <strong style={{ color: MON.cyan }}>{alertUser(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Credential Guard:</span> <strong style={{ color: MON.green }}>● Active & Enforced</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & ANCESTRY */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Process Ancestry & Command Execution</h4>
              <pre style={{ background: MON.card2, padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                {log.processCmdline || log.commandLine || 'No process command line was reported for this event.'}
              </pre>
            </div>
          )}

          {/* TAB 5: CREDENTIAL & AUTH */}
          {activeTab === 'auth' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔑 Credential Protocols & MFA Status</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Auth Protocol:</span> <b style={{ color: MON.purple }}>{credAuthType(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Event Type:</span> <span>{log.credentialEventType || log.eventType || 'Unknown'}</span></div>
                <div><span style={{ color: MON.sub }}>MFA Status:</span> <b style={{ color: log.mfaStatus === 'success' ? MON.green : MON.red }}>{log.mfaStatus || 'Not reported'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK & GEO */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Source Network & Impossible Travel</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Source IP:</span> <b style={{ color: MON.cyan }}>{credentialSourceIp(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Origin Country:</span> <b style={{ color: MON.yellow }}>{credentialCountry(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Action:</span> <b style={{ color: MON.green }}>{log.actionTaken || log.status || 'No response recorded'}</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                <div><b style={{ color: MON.red }}>{log.mitreId || log.mitreTechnique || 'No MITRE technique reported'}</b></div>
                <div style={{ color: MON.muted }}>{log.mitreTactic || log.technique || credThreat(log)}</div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Credential Artifact Hunt Launcher</div>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Credential Security Payload & EVTX Extract</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[CREDENTIAL SECURITY PAYLOAD]
User Account: ${alertUser(log)}
Event ID: ${credEventId(log)}
Auth Protocol: ${credAuthType(log)}
Threat: ${credThreat(log)}
Target Host: ${alertHost(log)}
Source IP: ${credentialSourceIp(log)}
Raw Evidence: ${JSON.stringify(log.rawEvent || {}, null, 2)}`}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Credential Containment & Password Reset</h4>
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
                      <option value="Account Locked">Account Locked</option>
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
                  <button type="button" disabled={!log?._id || !onAction} onClick={() => onAction?.(log._id, 'lock_account')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: log?._id && onAction ? 'pointer' : 'not-allowed', opacity: log?._id && onAction ? 1 : .55 }}>
                    ⛔ Lock Account
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
export function CredentialSecurityLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);
  const openLog = useCallback(async row => {
    setSelectedLog(row);
    if (!row?._id) return;
    try {
      const response = await api.get(`/credential-security/log/${row._id}`, { skipCache: true });
      if (response.data?.event) setSelectedLog({ ...response.data.event, relatedEvents: response.data.relatedEvents || [] });
    } catch { /* keep the live row available when forensic expansion fails */ }
  }, []);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${alertUser(a)} ${credThreat(a)} ${alertHost(a)} ${credEventId(a)} ${credAuthType(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search User, Event ID, Auth Protocol, Host, Source IP..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Credential Security & Identity SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live WebSocket</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 90px 1.6fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Target User Account</span><span>Event ID</span><span>Threat / Anomaly</span><span>Host / OS</span><span>Auth Protocol</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 90px 1.6fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => openLog(row)}>{alertUser(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{row.userSid || row.userDomain || '—'}</span>
                </div>
                <b style={{ color: MON.yellow }}>{credEventId(row)}</b>
                <b style={{ color: MON.red }}>{credThreat(row)}</b>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.purple }}>{credAuthType(row)}</span>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => openLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No credential telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <CredentialSecurityLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function CredentialSecurityReportsTab({ alerts = [] }) {
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
    return filtered;
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const response = await api.get('/credential-security/reports', { params: { period: reportType, limit: 10000 }, skipCache: true });
      const filtered = Array.isArray(response.data?.events) ? response.data.events : [];
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
      setGenerated(true);
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => { const s = alertSeverity(a); if (bySev[s] !== undefined) bySev[s]++; });
      setReportData({ alerts: filtered, total: filtered.length, bySev });
      setGenerated(true);
    } finally {
      setGenerating(false);
    }
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,User,Event ID,Auth Protocol,Threat,Host,Source IP,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(alertUser(a)),
      csvCell(credEventId(a)),
      csvCell(credAuthType(a)),
      csvCell(credThreat(a)),
      csvCell(alertHost(a)),
      csvCell(credentialSourceIp(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `credential_security_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Credential Security Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for password spraying, LSASS memory dumps, Kerberoasting, and account compromises</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Credential Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Credential Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Credential Alerts: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Credential Alerts', val: reportData?.total, color: MON.cyan },
              { label: 'Critical LSASS & Hash Dumps', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Brute Force / Spray', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Authentication Audits', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Credential Security Monitoring Dashboard ─────────────
function AuthenticationOverviewChart({ alerts = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
  const start = Date.now() - 24 * 3600000;
  const bucketMs = (24 * 3600000) / 9;
  const successData = Array(9).fill(0);
  const failedData = Array(9).fill(0);
  const uniqueSets = Array.from({ length: 9 }, () => new Set());
  alerts.forEach(row => {
    const timestamp = new Date(alertTime(row)).getTime();
    if (!Number.isFinite(timestamp) || timestamp < start) return;
    const index = Math.min(8, Math.max(0, Math.floor((timestamp - start) / bucketMs)));
    if (credentialResult(row) === 'success') successData[index] += 1;
    if (credentialResult(row) === 'failure') failedData[index] += 1;
    const username = alertUser(row);
    if (username !== 'unknown') uniqueSets[index].add(username);
  });
  const uniqueData = uniqueSets.map(values => values.size);
  const chartMax = Math.max(1, ...successData, ...failedData, ...uniqueData);
  const yLabels = [chartMax, Math.round(chartMax * .75), Math.round(chartMax * .5), Math.round(chartMax * .25), 0].map(shortNum);

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

  const succRes = makePath(successData);
  const failRes = makePath(failedData);
  const uniqRes = makePath(uniqueData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Authentication Overview</span>
        <div style={{ display: 'flex', gap: 10, fontSize: 8.5 }}>
          <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#34d399' }} /> Successful Logins</span>
          <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f87171' }} /> Failed Logins</span>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#38bdf8' }} /> Unique Users</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={`y-${i}-${lbl}`}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="8" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / (times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{t}</text>;
          })}
          <path d={succRes.d} fill="none" stroke="#34d399" strokeWidth="2" />
          <path d={failRes.d} fill="none" stroke="#f87171" strokeWidth="2" />
          <path d={uniqRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function AuthenticationMethodsDonut({ alerts = [] }) {
  const authGroups = [['Password', /password|pam/i, '#38bdf8'], ['MFA', /mfa|otp|2fa|duo/i, '#34d399'], ['SSO', /sso|saml|oauth|oidc/i, '#fbbf24'], ['Other', /.*/, '#a78bfa']];
  const counts = new Map(authGroups.map(([label]) => [label, 0]));
  alerts.forEach(row => {
    const value = credAuthType(row);
    const group = authGroups.find(([label, pattern]) => label !== 'Other' && pattern.test(value))?.[0] || 'Other';
    counts.set(group, counts.get(group) + 1);
  });
  const total = alerts.length;
  const methods = authGroups.map(([label, , color]) => ({ label, count: counts.get(label), pct: total ? Math.round((counts.get(label) / total) * 100) : 0, color }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = methods.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Authentication Methods</span>
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
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {methods.map(m => (
            <div key={m.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: m.color }} /> {m.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{m.count} ({m.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function MfaStatusDonut({ alerts = [] }) {
  const success = alerts.filter(row => /success|enabled|verified/.test(String(row?.mfaStatus || credThreat(row)).toLowerCase()) && /mfa|otp|2fa|duo/.test(`${row?.mfaStatus || ''} ${credThreat(row)}`.toLowerCase())).length;
  const failure = alerts.filter(row => /fail|denied|disabled|bypass/.test(String(row?.mfaStatus || credThreat(row)).toLowerCase()) && /mfa|otp|2fa|duo/.test(`${row?.mfaStatus || ''} ${credThreat(row)}`.toLowerCase())).length;
  const unknown = Math.max(0, alerts.filter(row => /mfa|otp|2fa|duo/.test(`${row?.mfaStatus || ''} ${credThreat(row)}`.toLowerCase())).length - success - failure);
  const total = success + failure + unknown;
  const statuses = [
    { label: 'Success / Enabled', count: success, pct: total ? Math.round((success / total) * 100) : 0, color: '#34d399' },
    { label: 'Failed / Disabled', count: failure, pct: total ? Math.round((failure / total) * 100) : 0, color: '#f87171' },
    { label: 'Not Reported', count: unknown, pct: total ? Math.round((unknown / total) * 100) : 0, color: '#fb923c' },
  ];

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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>MFA Status</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{total ? `${Math.round((success / total) * 100)}%` : '0%'}</span>
            <span style={{ fontSize: 7.5, color: '#34d399', fontWeight: 700 }}>Successful</span>
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

function AlertsByCategoryDonut({ alerts = [] }) {
  const labels = [['Brute Force', '#f87171'], ['Privileged Access', '#fb923c'], ['Credential Theft', '#fbbf24'], ['Account Takeover', '#34d399'], ['Policy Violation', '#38bdf8'], ['Other', '#a78bfa']];
  const total = alerts.length;
  const categories = labels.map(([label, color]) => {
    const count = alerts.filter(row => credentialCategory(row) === label).length;
    return { label, count, pct: total ? Math.round((count / total) * 100) : 0, color };
  });

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Alerts by Category</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {categories.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.count} ({c.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function CredentialSecurityOverviewDashboard({ alerts = [], total = 0, data = null }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const failedRows = rows.filter(row => credentialResult(row) === 'failure');
  const successRows = rows.filter(row => credentialResult(row) === 'success');
  const bruteRows = rows.filter(row => /brute|spray|stuffing/.test(`${credThreat(row)} ${row.ruleId || ''}`.toLowerCase()));
  const privilegedRows = rows.filter(row => /privilege|admin|sudo|root|4672/.test(`${credThreat(row)} ${row.ruleId || ''}`.toLowerCase()));
  const resetRows = rows.filter(row => /password.(?:reset|change)|passwd|4723|4724/.test(`${credThreat(row)} ${row.ruleId || ''}`.toLowerCase()));
  const highRiskRows = rows.filter(row => ['critical', 'high'].includes(alertSeverity(row)) || credRiskScore(row) >= 70);
  const unlockFailureRows = rows.filter(row => /screen.unlock.fail|auth_screen_unlock_failure|logon type.?7/.test(`${row.credentialEventType || ''} ${row.ruleId || ''} ${row.description || ''}`.toLowerCase()));
  const totalRows = Number(total || rows.length);
  const summary = data?.summary || {};
  const topCards = [
    { title: 'Failed Login Attempts', val: shortNum(summary.failedLogins ?? failedRows.length), sub: 'Live last 24h', subCol: '#f87171', icon: '🔒', iconBg: 'rgba(248, 113, 113, 0.15)', sparkCol: '#f87171', spark: buildBuckets(failedRows, 7, 24) },
    { title: 'Successful Logins', val: shortNum(summary.successfulLogins ?? successRows.length), sub: 'Live last 24h', subCol: '#34d399', icon: '👤', iconBg: 'rgba(52, 211, 153, 0.15)', sparkCol: '#34d399', spark: buildBuckets(successRows, 7, 24) },
    { title: 'Brute Force Attempts', val: shortNum(summary.bruteForce ?? bruteRows.length), sub: 'Live last 24h', subCol: '#fb923c', icon: '🛡️', iconBg: 'rgba(251, 146, 60, 0.15)', sparkCol: '#fb923c', spark: buildBuckets(bruteRows, 7, 24) },
    { title: 'Privileged Logins', val: shortNum(summary.privilegedLogins ?? privilegedRows.length), sub: 'Live last 24h', subCol: '#a78bfa', icon: '👑', iconBg: 'rgba(167, 139, 250, 0.15)', sparkCol: '#a78bfa', spark: buildBuckets(privilegedRows, 7, 24) },
    { title: 'Password Resets', val: shortNum(summary.passwordEvents ?? resetRows.length), sub: 'Live last 24h', subCol: '#38bdf8', icon: '🔑', iconBg: 'rgba(56, 189, 248, 0.15)', sparkCol: '#38bdf8', spark: buildBuckets(resetRows, 7, 24) },
    { title: 'High Risk Alerts', val: shortNum((summary.critical ?? 0) + (summary.high ?? 0) || highRiskRows.length), sub: `${shortNum(totalRows)} total events`, subCol: '#f87171', icon: '⚠️', iconBg: 'rgba(248, 113, 113, 0.15)', sparkCol: '#f87171', spark: buildBuckets(highRiskRows, 7, 24) },
    { title: 'Lock-screen Failures', val: shortNum(summary.screenUnlockFailures ?? unlockFailureRows.length), sub: 'Invalid unlock attempts', subCol: '#f87171', icon: '🔐', iconBg: 'rgba(248, 113, 113, 0.15)', sparkCol: '#f87171', spark: buildBuckets(unlockFailureRows, 7, 24) },
  ];

  const locationCounts = topCounts(rows, credentialCountry, 6);
  const locationTotal = locationCounts.reduce((sum, [, count]) => sum + count, 0);
  const locationColors = ['#f87171', '#fb923c', '#fbbf24', '#34d399', '#38bdf8', '#a78bfa'];
  const locations = locationCounts.map(([country, count], index) => ({ country, count: shortNum(count), pct: locationTotal ? Math.round((count / locationTotal) * 100) : 0, col: locationColors[index] }));

  const userMap = new Map();
  rows.forEach(row => {
    const name = alertUser(row); if (name === 'unknown') return;
    const current = userMap.get(name) || { name, score: 0, alerts: 0 };
    current.alerts += 1; current.score = Math.max(current.score, credRiskScore(row)); userMap.set(name, current);
  });
  const topRiskyUsers = [...userMap.values()].sort((a, b) => b.score - a.score || b.alerts - a.alerts).slice(0, 5).map(item => ({ ...item, scoreCol: item.score >= 85 ? '#f87171' : item.score >= 60 ? '#fb923c' : '#fbbf24' }));

  const failedCounts = topCounts(failedRows, alertUser, 5);
  const maxFailed = Math.max(1, ...failedCounts.map(([, count]) => count));
  const failedLoginUsers = failedCounts.map(([name, count]) => ({ name, count, pct: Math.round((count / maxFailed) * 100) }));
  const bruteCounts = topCounts(bruteRows, credentialSourceIp, 5);
  const maxBrute = Math.max(1, ...bruteCounts.map(([, count]) => count));
  const bruteForceSources = bruteCounts.map(([ip, count]) => ({ ip, count, pct: Math.round((count / maxBrute) * 100) }));
  const recentHighRiskEvents = [...highRiskRows].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleString() : '—', user: alertUser(row),
    event: row.credentialEventType || row.eventType || row.ruleId || 'Credential Event', source: credentialSourceIp(row),
    score: credRiskScore(row), scoreCol: credRiskScore(row) >= 85 ? '#f87171' : credRiskScore(row) >= 60 ? '#fb923c' : '#fbbf24',
    details: row.description || row.failureReason || row.ruleId || '—',
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns with Sparklines) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(145px, 1fr))', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 6, position: 'relative', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 9, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px' }}>
                {c.title}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 2 }}>
              <div>
                <div style={{ fontSize: 20, fontWeight: 800, color: '#ffffff' }}>
                  {c.val}
                </div>
                <div style={{ fontSize: 8.5, fontWeight: 700, color: c.subCol, marginTop: 1 }}>
                  {c.sub}
                </div>
              </div>
              <div style={{ width: 60, height: 22 }}>
                <MiniSparkline data={c.spark} color={c.sparkCol} height={22} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <AuthenticationOverviewChart alerts={rows} />
        </div>

        {/* Login Attempts by Location */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Login Attempts by Location</span>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <div style={{ flex: 1.2, background: '#07101b', borderRadius: 6, border: '1px solid #16273e', position: 'relative', overflow: 'hidden', minHeight: 95 }}>
                <svg viewBox="0 0 200 100" width="100%" height="100%" style={{ opacity: 0.6 }}>
                  <path d="M 20,30 Q 30,20 45,35 T 70,30 T 90,45 T 60,70 T 30,60 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
                  <path d="M 110,25 Q 130,15 160,25 T 180,45 T 150,75 T 120,60 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
                  <circle cx="145" cy="45" r="7" fill="#ef4444" opacity="0.8" />
                  <circle cx="45" cy="35" r="5" fill="#f97316" opacity="0.8" />
                  <circle cx="115" cy="30" r="4" fill="#eab308" opacity="0.8" />
                  <circle cx="155" cy="55" r="3.5" fill="#22c55e" opacity="0.8" />
                  <circle cx="170" cy="65" r="3" fill="#3b82f6" opacity="0.8" />
                </svg>
              </div>
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3, fontSize: 8.5 }}>
                {locations.map(loc => (
                  <div key={loc.country} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span style={{ width: 5, height: 5, borderRadius: '50%', background: loc.col }} /> {loc.country}
                    </span>
                    <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{loc.count} ({loc.pct}%)</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* Top Risky Users */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top Risky Users</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>User</span>
              <span style={{ textAlign: 'center' }}>Risk Score</span>
              <span style={{ textAlign: 'right' }}>Alerts</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topRiskyUsers.map(ru => (
                <div key={ru.name} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ru.name}</span>
                  <span style={{ fontSize: 8.5, fontWeight: 800, color: ru.scoreCol, padding: '1px 4px', background: `${ru.scoreCol}15`, borderRadius: 4, border: `1px solid ${ru.scoreCol}33`, textAlign: 'center', margin: '0 auto', width: 24 }}>
                    {ru.score}
                  </span>
                  <span style={{ color: '#8ea0b8', fontWeight: 700, textAlign: 'right' }}>{ru.alerts}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.1fr 1fr 1fr', gap: 12 }}>
        {/* Failed Login Attempts (Top Users) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Failed Login Attempts (Top Users)</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {failedLoginUsers.map(u => (
              <div key={u.name} style={{ display: 'grid', gridTemplateColumns: '1fr 1.8fr 0.4fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{u.name}</span>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${u.pct}%`, height: '100%', background: '#ef4444', borderRadius: 3 }} />
                </div>
                <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{u.count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Brute Force Attempts (Top Sources) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Brute Force Attempts (Top Sources)</span>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {bruteForceSources.map(s => (
              <div key={s.ip} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.6fr 0.4fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{s.ip}</span>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${s.pct}%`, height: '100%', background: '#f97316', borderRadius: 3 }} />
                </div>
                <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{s.count}</span>
              </div>
            ))}
          </div>
        </div>

        <div style={panelStyle}>
          <AuthenticationMethodsDonut alerts={rows} />
        </div>

        <div style={panelStyle}>
          <MfaStatusDonut alerts={rows} />
        </div>
      </div>

      {/* 4. BOTTOM GRID (2 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 1fr', gap: 12 }}>
        {/* Recent High Risk Events */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent High Risk Events</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.3fr 1.1fr 0.7fr 2.5fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>User</span>
              <span>Event</span>
              <span>Source</span>
              <span>Risk Score</span>
              <span>Details</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {recentHighRiskEvents.map((hre, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.3fr 1.1fr 0.7fr 2.5fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                  <span style={{ color: '#64748b', fontSize: 8.5 }}>{hre.time}</span>
                  <span style={{ color: '#cbd5e1' }}>{hre.user}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{hre.event}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8.5 }}>{hre.source}</span>
                  <span style={{ fontSize: 8.5, fontWeight: 800, color: hre.scoreCol, padding: '1px 4px', background: `${hre.scoreCol}15`, borderRadius: 4, border: `1px solid ${hre.scoreCol}33`, textAlign: 'center', width: 24 }}>
                    {hre.score}
                  </span>
                  <span style={{ color: '#f87171', fontSize: 8.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{hre.details}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8, textAlign: 'center' }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts</span>
          </div>
        </div>

        <div style={panelStyle}>
          <AlertsByCategoryDonut alerts={rows} />
        </div>
      </div>
    </div>
  );
}

function CredentialSecurityConfigureTab() {
  const configPanelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };
  const [configuration, setConfiguration] = useState(CREDENTIAL_CONFIG_DEFAULTS);
  const [rules, setRules] = useState([]);
  const [targetCount, setTargetCount] = useState(0);
  const [onlineCount, setOnlineCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [creatingPolicy, setCreatingPolicy] = useState(false);
  const [policyName, setPolicyName] = useState('');
  const [policyDescription, setPolicyDescription] = useState('');
  const [applyingPolicyId, setApplyingPolicyId] = useState('');
  const [notice, setNotice] = useState('');
  const [error, setError] = useState('');

  const loadConfiguration = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const response = await api.get('/credential-security/configuration', { skipCache: true });
      setConfiguration({ ...CREDENTIAL_CONFIG_DEFAULTS, ...(response.data?.configuration || {}) });
      setRules(Array.isArray(response.data?.rules) ? response.data.rules : []);
      setTargetCount(Number(response.data?.targetCount || 0));
      setOnlineCount(Number(response.data?.onlineCount || 0));
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Unable to load credential security configuration.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadConfiguration(); }, [loadConfiguration]);

  const changeSetting = (field, value) => {
    setNotice('');
    setConfiguration(current => ({ ...current, [field]: value }));
  };

  const changeRule = (ruleId, field, value) => {
    setNotice('');
    setRules(current => current.map(rule => rule.id === ruleId ? { ...rule, [field]: value } : rule));
  };

  const saveConfiguration = async () => {
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const builtInRuleOverrides = Object.fromEntries(rules.map(rule => [rule.id, {
        enabled: rule.enabled !== false,
        severity: rule.severity,
      }]));
      const response = await api.put('/credential-security/configuration', {
        enabled: configuration.enabled !== false,
        monitorProcesses: configuration.monitorProcesses !== false,
        monitorCredentialStores: configuration.monitorCredentialStores !== false,
        monitorLockScreen: configuration.monitorLockScreen !== false,
        scanIntervalSeconds: Number(configuration.scanIntervalSeconds),
        minimumRiskScore: Number(configuration.minimumRiskScore),
        builtInRuleOverrides,
      });
      setConfiguration({ ...CREDENTIAL_CONFIG_DEFAULTS, ...(response.data?.configuration || {}) });
      setRules(Array.isArray(response.data?.rules) ? response.data.rules : rules);
      setTargetCount(Number(response.data?.targetCount ?? targetCount));
      setNotice(response.data?.message || 'Credential security policy saved.');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Unable to save credential security configuration.');
    } finally {
      setSaving(false);
    }
  };

  const currentRuleOverrides = () => Object.fromEntries(rules.map(rule => [rule.id, {
    enabled: rule.enabled !== false,
    severity: rule.severity,
  }]));

  const createManualPolicy = async () => {
    const name = policyName.trim();
    if (name.length < 3) {
      setError('Manual policy name must contain at least 3 characters.');
      return;
    }
    setSaving(true);
    setError('');
    setNotice('');
    try {
      const response = await api.post('/credential-security/configuration/policies', {
        name,
        description: policyDescription.trim(),
        settings: {
          enabled: configuration.enabled !== false,
          monitorProcesses: configuration.monitorProcesses !== false,
          monitorCredentialStores: configuration.monitorCredentialStores !== false,
          monitorLockScreen: configuration.monitorLockScreen !== false,
          scanIntervalSeconds: Number(configuration.scanIntervalSeconds),
          minimumRiskScore: Number(configuration.minimumRiskScore),
          builtInRuleOverrides: currentRuleOverrides(),
        },
      });
      setConfiguration(current => ({ ...current, manualPolicies: response.data?.manualPolicies || current.manualPolicies || [] }));
      setPolicyName('');
      setPolicyDescription('');
      setCreatingPolicy(false);
      setNotice(response.data?.message || 'Manual policy created and added to Detection Rules.');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Unable to create manual policy.');
    } finally {
      setSaving(false);
    }
  };

  const applyManualPolicy = async policyId => {
    setApplyingPolicyId(policyId);
    setError('');
    setNotice('');
    try {
      const response = await api.post(`/credential-security/configuration/policies/${policyId}/apply`);
      setConfiguration({ ...CREDENTIAL_CONFIG_DEFAULTS, ...(response.data?.configuration || {}) });
      setRules(Array.isArray(response.data?.rules) ? response.data.rules : rules);
      setTargetCount(Number(response.data?.targetCount ?? targetCount));
      setNotice(response.data?.message || 'Manual policy applied.');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Unable to apply manual policy.');
    } finally {
      setApplyingPolicyId('');
    }
  };

  const restoreDefaults = () => {
    setConfiguration(current => ({
      ...current,
      enabled: true,
      monitorProcesses: true,
      monitorCredentialStores: true,
      monitorLockScreen: true,
      scanIntervalSeconds: 20,
      minimumRiskScore: 50,
    }));
    setRules(current => current.map(rule => ({ ...rule, enabled: true, severity: rule.defaultSeverity || rule.severity })));
    setNotice('Default values loaded. Click Apply Configuration to deploy them.');
    setError('');
  };

  const toggleRow = (label, description, field) => (
    <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 18, padding: '12px 0', borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
      <span>
        <b style={{ display: 'block', color: MON.text, fontSize: 11 }}>{label}</b>
        <span style={{ color: MON.muted, fontSize: 9 }}>{description}</span>
      </span>
      <input type="checkbox" checked={configuration[field] !== false} onChange={event => changeSetting(field, event.target.checked)} style={{ width: 17, height: 17, accentColor: MON.cyan }} />
    </label>
  );

  if (loading) return <div style={{ padding: 28, color: MON.cyan, fontSize: 12 }}>Loading credential security policy…</div>;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ ...configPanelStyle, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 18 }}>
        <div>
          <div style={{ color: '#fff', fontSize: 14, fontWeight: 900 }}>⚙ Credential Security Configuration</div>
          <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Company policy is delivered securely to endpoint agents on their next heartbeat.</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span style={{ color: MON.cyan, background: `${MON.cyan}18`, border: `1px solid ${MON.cyan}44`, borderRadius: 5, padding: '5px 8px', fontSize: 9, fontWeight: 800 }}>POLICY v{Number(configuration.version || 1)}</span>
          <span style={{ color: MON.green, background: `${MON.green}18`, border: `1px solid ${MON.green}44`, borderRadius: 5, padding: '5px 8px', fontSize: 9, fontWeight: 800 }}>{onlineCount}/{targetCount} AGENTS ONLINE</span>
        </div>
      </div>

      {(notice || error) && (
        <div style={{ padding: '10px 12px', borderRadius: 7, border: `1px solid ${error ? MON.red : MON.green}`, background: error ? SEV_BG.critical : 'rgba(52,211,153,.1)', color: error ? MON.red : MON.green, fontSize: 10, fontWeight: 700 }}>
          {error || notice}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(280px, .8fr) minmax(420px, 1.6fr)', gap: 14 }}>
        <div style={configPanelStyle}>
          <div style={{ fontSize: 12, fontWeight: 900, color: '#fff', marginBottom: 5 }}>Agent Collection Policy</div>
          {toggleRow('Credential Security Monitoring', 'Master control for Capability 13 telemetry collection.', 'enabled')}
          {toggleRow('Process Telemetry', 'Monitor credential dumping and identity-abuse process metadata.', 'monitorProcesses')}
          {toggleRow('Credential Store Metadata', 'Monitor protected file metadata only; secret contents are never read.', 'monitorCredentialStores')}
          {toggleRow('Lock-screen Authentication', 'Monitor lock, unlock and rejected unlock attempts without collecting the entered PIN or password.', 'monitorLockScreen')}
          <label style={{ display: 'block', paddingTop: 13 }}>
            <span style={{ display: 'block', color: MON.text, fontSize: 10, fontWeight: 800, marginBottom: 6 }}>Scan interval (seconds)</span>
            <input type="number" min="10" max="3600" value={configuration.scanIntervalSeconds} onChange={event => changeSetting('scanIntervalSeconds', event.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 6, color: MON.text, padding: '9px 10px', fontSize: 11 }} />
            <span style={{ color: MON.sub, fontSize: 9 }}>10–3600 seconds. Higher intervals reduce endpoint CPU usage.</span>
          </label>
          <label style={{ display: 'block', paddingTop: 13 }}>
            <span style={{ display: 'block', color: MON.text, fontSize: 10, fontWeight: 800, marginBottom: 6 }}>Minimum risk score</span>
            <input type="number" min="0" max="100" value={configuration.minimumRiskScore} onChange={event => changeSetting('minimumRiskScore', event.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 6, color: MON.text, padding: '9px 10px', fontSize: 11 }} />
            <span style={{ color: MON.sub, fontSize: 9 }}>Events below this score stay suppressed at the agent.</span>
          </label>
          <div style={{ marginTop: 14, padding: 10, borderRadius: 6, border: `1px solid ${MON.border}`, background: MON.bg, color: MON.muted, fontSize: 9, lineHeight: 1.5 }}>
            Privacy guard: passwords, tokens, private keys, browser databases, LSASS memory and protected file contents are never collected.
          </div>
          <button type="button" onClick={() => { setCreatingPolicy(value => !value); setError(''); setNotice(''); }} style={{ width: '100%', marginTop: 12, border: `1px solid ${MON.cyan}`, background: `${MON.cyan}18`, color: MON.cyan, borderRadius: 6, padding: '9px 12px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>
            ＋ Create Manual Policy
          </button>
          {creatingPolicy && (
            <div style={{ marginTop: 10, padding: 10, background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 7, display: 'flex', flexDirection: 'column', gap: 8 }}>
              <input maxLength={80} value={policyName} onChange={event => setPolicyName(event.target.value)} placeholder="Policy name" style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 5, color: MON.text, padding: '8px 9px', fontSize: 10 }} />
              <textarea maxLength={300} rows={3} value={policyDescription} onChange={event => setPolicyDescription(event.target.value)} placeholder="Policy description (optional)" style={{ resize: 'vertical', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 5, color: MON.text, padding: '8px 9px', fontSize: 10 }} />
              <div style={{ color: MON.sub, fontSize: 8.5 }}>The current collection settings and all rule states will be saved in this reusable policy.</div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 7 }}>
                <button type="button" onClick={() => setCreatingPolicy(false)} style={{ border: `1px solid ${MON.border}`, background: MON.card2, color: MON.muted, borderRadius: 5, padding: '7px 10px', fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>Cancel</button>
                <button type="button" onClick={createManualPolicy} disabled={saving} style={{ border: 0, background: MON.cyan, color: '#001018', borderRadius: 5, padding: '7px 10px', fontSize: 9, fontWeight: 900, cursor: saving ? 'wait' : 'pointer' }}>{saving ? 'Creating…' : 'Save Manual Policy'}</button>
              </div>
            </div>
          )}
        </div>

        <div style={{ ...configPanelStyle, padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>Detection Rules</span>
            <span style={{ color: MON.muted, fontSize: 9 }}>{rules.length + (configuration.manualPolicies || []).length} rules / policies</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '44px 1.2fr .7fr 100px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
            <span>ON</span><span>RULE / POLICY</span><span>CATEGORY</span><span>SEVERITY / ACTION</span>
          </div>
          <div style={{ maxHeight: 450, overflowY: 'auto' }}>
            {rules.map(rule => (
              <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '44px 1.2fr .7fr 100px', gap: 8, alignItems: 'center', padding: '10px 12px', borderTop: `1px solid ${MON.line}` }}>
                <input type="checkbox" checked={rule.enabled !== false} onChange={event => changeRule(rule.id, 'enabled', event.target.checked)} style={{ width: 16, height: 16, accentColor: MON.cyan }} />
                <span style={{ minWidth: 0 }}>
                  <b style={{ color: MON.text, display: 'block', fontSize: 10 }}>{rule.name}</b>
                  <span title={rule.description} style={{ color: MON.sub, fontSize: 8.5, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rule.id} · {rule.description}</span>
                </span>
                <span style={{ color: MON.muted, fontSize: 9 }}>{rule.category}</span>
                <select value={rule.severity} onChange={event => changeRule(rule.id, 'severity', event.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 5, color: SEV_COLOR[rule.severity] || MON.text, padding: '6px 5px', fontSize: 9 }}>
                  <option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option>
                </select>
              </div>
            ))}
            {(configuration.manualPolicies || []).map(policy => (
              <div key={`manual-${policy._id}`} style={{ display: 'grid', gridTemplateColumns: '44px 1.2fr .7fr 100px', gap: 8, alignItems: 'center', padding: '10px 12px', borderTop: `1px solid ${MON.line}`, background: `${MON.purple}08` }}>
                <span title="Saved manual policy" style={{ width: 16, height: 16, borderRadius: '50%', background: `${MON.purple}25`, border: `1px solid ${MON.purple}`, color: MON.purple, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9 }}>◆</span>
                <span style={{ minWidth: 0 }}>
                  <b style={{ color: MON.purple, display: 'block', fontSize: 10 }}>{policy.name}</b>
                  <span title={policy.description} style={{ color: MON.sub, fontSize: 8.5, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{policy.description || 'Custom agent collection and detection policy'}</span>
                </span>
                <span style={{ color: MON.purple, fontSize: 9, fontWeight: 800 }}>Manual Policy</span>
                <button type="button" disabled={Boolean(applyingPolicyId)} onClick={() => applyManualPolicy(policy._id)} style={{ border: `1px solid ${MON.green}`, background: `${MON.green}18`, color: MON.green, borderRadius: 5, padding: '6px 7px', fontSize: 8.5, fontWeight: 900, cursor: applyingPolicyId ? 'wait' : 'pointer' }}>
                  {applyingPolicyId === policy._id ? 'Applying…' : 'Apply'}
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 9 }}>
        <button type="button" onClick={restoreDefaults} disabled={saving} style={{ border: `1px solid ${MON.border}`, background: MON.card2, color: MON.text, borderRadius: 6, padding: '9px 13px', fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>Restore Defaults</button>
        <button type="button" onClick={saveConfiguration} disabled={saving} style={{ border: `1px solid ${MON.cyan}`, background: saving ? MON.card2 : MON.cyan, color: saving ? MON.muted : '#001018', borderRadius: 6, padding: '9px 15px', fontSize: 10, fontWeight: 900, cursor: saving ? 'wait' : 'pointer' }}>{saving ? 'Applying…' : 'Apply Configuration'}</button>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`CredentialSecurityDashboardPanel` / `CredentialSecurityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function CredentialSecurityDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction }) {
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
  const totalRows = summary.total || total || recordsTotal || rows.length;
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

  // 20 Credential Security Specific SOC Categories & Metrics
  const bruteCount = Number(summary.bruteForce ?? rows.filter(r => containsAny(r, ['brute', 'spray', 'failed', '4625'])).length);
  const lsassCount = Number(summary.credentialTheft ?? rows.filter(r => containsAny(r, ['lsass', 'dump', 'mimikatz', 'sam'])).length);
  const kerberosCount = Number(summary.kerberosAbuse ?? rows.filter(r => containsAny(r, ['kerberos', 'kerberoast', '4769', 'rc4'])).length);
  const sshCount = rows.filter(r => containsAny(r, ['ssh', 'pam', 'auth.log'])).length;
  const lockoutCount = Number(summary.accountLockouts ?? rows.filter(r => containsAny(r, ['lockout', '4740', 'account locked'])).length);
  const cloudIamCount = Number(summary.cloudIam ?? rows.filter(r => containsAny(r, ['cloud', 'iam', 'aws', 'azure', 'okta'])).length);

  const kpis = [
    { label: '🛡️ 1. Total Credential Security Alerts', val: shortNum(totalRows), trend: 'Identity Signals', color: MON.blue, data: timeline },
    { label: '🔑 2. LSASS Process RAM Dump Events', val: shortNum(lsassCount), trend: 'LSASS Dump', color: MON.red, data: timeline },
    { label: '⚡ 3. Password Spraying & Brute Force', val: shortNum(bruteCount), trend: 'Password Spray', color: MON.orange, data: timeline },
    { label: '🎟️ 4. Kerberoasting & TGS Ticket Requests', val: shortNum(kerberosCount), trend: 'Kerberoasting', color: MON.purple, data: timeline },
    { label: '🔒 5. Domain Account Lockout Events', val: shortNum(lockoutCount), trend: 'Account Lockout', color: MON.yellow, data: timeline },
    { label: '🐧 6. Linux SSH Brute Force & PAM Failures', val: shortNum(sshCount), trend: 'SSH Failure', color: MON.red, data: timeline },
    { label: '☁️ 7. Cloud IAM & API Key Abuse Alerts', val: shortNum(cloudIamCount), trend: 'Cloud IAM', color: MON.purple, data: timeline },
    { label: '👑 8. Privileged Administrator Logins', val: shortNum(rows.filter(r => containsAny(r, ['admin', 'root', '4672'])).length), trend: 'Admin Login', color: MON.cyan, data: timeline },
    { label: '🌐 9. Impossible Travel Credential Reuse', val: shortNum(rows.filter(r => containsAny(r, ['travel', 'country', 'geo'])).length), trend: 'Travel Reuse', color: MON.orange, data: timeline },
    { label: '👤 10. Concurrent Remote Session Alerts', val: shortNum(rows.filter(r => containsAny(r, ['concurrent', 'multi-session'])).length), trend: 'Concurrent', color: MON.pink, data: timeline },
    { label: '🛡️ 11. MFA Challenge Failure & Bypasses', val: shortNum(rows.filter(r => containsAny(r, ['mfa', 'duo', 'azure mfa'])).length), trend: 'MFA Failure', color: MON.red, data: timeline },
    { label: '🔑 12. NTLM Hash Theft & Relay Attacks', val: shortNum(rows.filter(r => containsAny(r, ['ntlm', 'relay', 'hash'])).length), trend: 'NTLM Relay', color: MON.yellow, data: timeline },
    { label: '💤 13. Disabled / Dormant Account Logins', val: shortNum(rows.filter(r => containsAny(r, ['disabled', 'dormant'])).length), trend: 'Dormant Acc', color: MON.orange, data: timeline },
    { label: '🎟️ 14. Golden / Silver Ticket Anomalies', val: shortNum(rows.filter(r => containsAny(r, ['golden ticket', 'silver ticket', 'krbtgt'])).length), trend: 'Golden Ticket', color: MON.red, data: timeline },
    { label: '🔑 15. SAM Database / Registry Hash Exports', val: shortNum(rows.filter(r => containsAny(r, ['sam', 'secrets', 'lsadump'])).length), trend: 'SAM Hash Dump', color: MON.purple, data: timeline },
    { label: '🪟 16. Windows Monitored Identity Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows Guard', color: MON.cyan, data: timeline },
    { label: '🐧 17. Linux Monitored Identity Endpoints', val: shortNum(osCounts.Linux || 0), trend: 'Linux Auth', color: MON.orange, data: timeline },
    { label: '🍎 18. macOS Monitored Identity Endpoints', val: shortNum(osCounts.macOS || 0), trend: 'macOS Auth', color: MON.purple, data: timeline },
    { label: '🚨 19. Critical Identity Compromise Alerts', val: shortNum(summary.critical ?? sevCounts.critical ?? 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 20. High Risk Credential Alterations', val: shortNum(summary.high ?? sevCounts.high ?? 0), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🔐 21. Failed Lock-screen Unlock Attempts', val: shortNum(summary.screenUnlockFailures ?? rows.filter(r => containsAny(r, ['screen_unlock_failed', 'auth_screen_unlock_failure', 'logon type: 7'])).length), trend: 'Invalid Unlock', color: MON.red, data: timeline },
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
          <CredentialSecurityLogMonitor alerts={alerts} onAction={onAction} />
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={13} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <CredentialSecurityOverviewDashboard alerts={alerts} total={totalRows} data={data} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Credential Security & Identity Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Credential Guard & EVTX Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Auth Guard</span><span>Signals</span><span>Auth Alerts</span><span>Last Audit</span>
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
                  No backend credential agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Authentication Activity Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} auth events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Credential Attack Vectors</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, credThreat, 5).map(([vec, count], index) => (
                    <div key={vec} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{vec}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Auth Protocol Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, credAuthType, 5).map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.cyan, MON.yellow, MON.purple, MON.blue][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`CredentialSecurityMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function CredentialSecurityMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '13';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [dashboardData, setDashboardData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/credential-security/dashboard', { params: { windowHours: 24, limit: 250 }, skipCache: quiet });
      const next = r.data?.events || [];
      setAlerts(next);
      setTotal(r.data?.summary?.total || next.length);
      setDashboardData(r.data || null);
    } catch {
      setAlerts([]);
      setTotal(0);
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
        incoming.forEach(event => { const key = String(event._id); if (!byId.has(key)) added += 1; byId.set(key, event); });
        const merged = Array.from(byId.values()).sort((a, b) => new Date(b.createdAt || b.timestamp || 0) - new Date(a.createdAt || a.timestamp || 0)).slice(0, 250);
        if (added) setTotal(current => Math.max(merged.length, Number(current || 0) + added));
        return merged;
      });
    }, 1000);
    socket.on('connect', join);
    socket.on('credential:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('credential:event', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId]);

  const handleResponseAction = useCallback(async (alertId, actionType) => {
    const reason = window.prompt('Enter the reason for this credential containment action:')?.trim() || '';
    if (!reason || !window.confirm(`Confirm ${String(actionType).replaceAll('_', ' ')} for this alert?`)) return;
    await api.post('/credential-security/respond', { alertId, actionType, reason, confirmed: true });
  }, []);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 13. Credential Security Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <CredentialSecurityDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={dashboardData} onAction={handleResponseAction} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <CredentialSecurityMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function CredentialSecuritySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=13" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Credential Security SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=13')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="credentialsecurity" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <CredentialSecurityDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { CredentialSecurityDashboardPanel as CredentialSecurityDashboard };
