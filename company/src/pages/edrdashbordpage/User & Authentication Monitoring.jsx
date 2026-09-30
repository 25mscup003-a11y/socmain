/**
 * User & Authentication Monitoring — Capability ID: 4
 *
 * 100% Self-Contained Enterprise SOC User & Authentication Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=4`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process Activity Monitoring (Capability ID: 1), FIM (Capability ID: 2), & Network Activity (Capability ID: 3)
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

function normHost(h) {
  return String(h || 'unknown').trim().toLowerCase();
}

function alertTime(row) {
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'Not reported';
}

function alertUser(row) {
  return row?.user || row?.username || row?.targetUser || row?.userName || row?.account || 'Not reported';
}

function alertStatus(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.authResult || row?.authStatus || raw.auth_result || row?.state || row?.status || 'Not reported';
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

// ── User & Auth Specific Telemetry Field Extractors ──────────────────────────
function authSrcIp(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.srcip || row?.src_ip || row?.sourceIp || row?.source_ip || row?.ipAddress || row?.ip || row?.remoteIp || row?.clientIp ||
    raw.srcip || raw.src_ip || raw.sourceIp || raw.source_ip || raw.ipAddress || raw.ip || raw.remoteIp || raw.remote_ip || raw.clientIp || raw.client_ip ||
    row?.systemId?.ip || row?.systemId?.ipAddress || 'Not reported';
}

function systemRecordId(row) {
  const value = row?.systemId?._id || row?.systemId || row?.endpointId;
  return value ? String(value) : '';
}

function latestAnalystNote(row) {
  const notes = Array.isArray(row?.notes) ? row.notes : [];
  return row?.analystNotes || notes.at(-1)?.text || '';
}

function authTypeMethod(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.authType || row?.auth_type || row?.method || row?.logonType ||
    raw.authType || raw.auth_method || raw.method || 'Not reported';
}

function authEventCode(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.windowsEventId || row?.eventCode || raw.windowsEventId || raw.eventCode || raw.event_id || 'Not reported';
}

function authGeo(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const city = row?.geoCity || raw.geoCity || raw.geo_city;
  const country = row?.geoCountry || row?.geoCountryCode || row?.country || raw.geoCountry || raw.geo_country || raw.country;
  return [city, country].filter(Boolean).join(', ')
    || (row?.geoStatus === 'failed' ? 'Geo unavailable' : 'Resolving live location…');
}

function containsAny(row, words = []) {
  const haystack = [
    alertUser(row), alertHost(row), authSrcIp(row), authTypeMethod(row), authEventCode(row),
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${alertUser(row)}-${authSrcIp(row)}`;
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
export function UserAuthLogDetailModal({ log: initialLog, onClose }) {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [activeTab, setActiveTab] = useState('overview');
  const [liveLog, setLiveLog] = useState(initialLog);
  const [analystNotes, setAnalystNotes] = useState(latestAnalystNote(initialLog));
  const [assignedAnalyst] = useState(initialLog?.assignedTo?.name || initialLog?.assignedTo?.email || initialLog?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(initialLog?.status || 'open');
  const [notesSaved, setNotesSaved] = useState(false);
  const [noteError, setNoteError] = useState('');
  const [forensicsState, setForensicsState] = useState({ server: null, client: null, hunts: [] });
  const [forensicsChecking, setForensicsChecking] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.EventLogs.Evtx');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Auth Security Event Logs (4624/4625/4720)');
  const [huntNameInput, setHuntNameInput] = useState(`${initialLog?.hostname || initialLog?.agentName || 'endpoint'} user auth forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  const log = liveLog || initialLog;
  const systemId = systemRecordId(log);
  const rawEvidence = log?.rawEvent?.raw || log?.rawEvent || log?.raw || {};
  const tags = Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || 'None reported');

  const refreshEvent = useCallback(async () => {
    if (!initialLog?._id) return;
    try {
      const response = await api.get(`/authentication-monitoring/events/${initialLog._id}`, { skipCache: true });
      if (response.data?.event) {
        setLiveLog(previous => ({ ...(previous || initialLog), ...response.data.event }));
        setCaseStatus(response.data.event.status || 'open');
      }
    } catch {
      // Preserve the selected SIEM row when a detail refresh races retention.
    }
  }, [initialLog?._id]);

  const refreshForensics = useCallback(async () => {
    if (!systemId) {
      setForensicsState({ server: null, client: null, hunts: [] });
      return;
    }
    setForensicsChecking(true);
    try {
      const response = await api.get('/forensics/endpoint', { params: { systemId }, skipCache: true });
      setForensicsState({
        server: response.data?.server || null,
        client: response.data?.client || null,
        hunts: Array.isArray(response.data?.hunts) ? response.data.hunts : [],
      });
    } catch (error) {
      setForensicsState(previous => ({ ...previous, error: error.response?.data?.message || 'Forensic server/agent check failed.' }));
    } finally {
      setForensicsChecking(false);
    }
  }, [systemId]);

  useEffect(() => {
    setLiveLog(initialLog);
    setAnalystNotes(latestAnalystNote(initialLog));
    setCaseStatus(initialLog?.status || 'open');
  }, [initialLog?._id]);

  useEffect(() => {
    refreshEvent();
    const timer = setInterval(refreshEvent, 15000);
    return () => clearInterval(timer);
  }, [refreshEvent]);

  useEffect(() => {
    refreshForensics();
    const timer = setInterval(refreshForensics, 15000);
    return () => clearInterval(timer);
  }, [refreshForensics]);

  useEffect(() => {
    const socket = io(SOCKET_URL, socketOptions);
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const authHandler = event => {
      if (String(event?._id || '') === String(initialLog?._id || '')) {
        setLiveLog(previous => ({ ...(previous || initialLog), ...event }));
      }
    };
    const forensicHandler = () => refreshForensics();
    socket.on('connect', join);
    socket.on('auth:event', authHandler);
    socket.on('alert:updated', authHandler);
    socket.on('forensics:updated', forensicHandler);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('auth:event', authHandler);
      socket.off('alert:updated', authHandler);
      socket.off('forensics:updated', forensicHandler);
      disconnect();
    };
  }, [companyId, initialLog?._id, refreshForensics]);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const eventTimeline = Array.isArray(log?.timeline) && log.timeline.length ? log.timeline : [{
    type: log?.eventType || log?.userAction || log?.ruleId || 'Authentication event',
    time: alertTime(log) || 'Not reported',
    title: log?.description || 'Authentication telemetry received',
    desc: log?.failureReason || log?.detectionReason || 'No additional correlated timeline evidence was reported.',
    col: sevColor,
  }];

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & DC' },
    { id: 'auth', label: '🔑 4. Credential & Auth' },
    { id: 'privileges', label: '👑 5. Rights & Privileges' },
    { id: 'mfa', label: '🔐 6. MFA & Password' },
    { id: 'ioc', label: '🎯 7. IOC, Geo & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & Logs' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Windows Security Evtx Logs', desc: 'Inspect Security Event IDs 4624, 4625, 4720, 4726, 4728, 4732.', artifact: 'Windows.EventLogs.Evtx' },
    { title: 'Linux Auth Hunter (/var/log/auth.log)', desc: 'Search SSH logins, sudo commands, PAM authentication, and failed attempts.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'Windows Local & Domain Users', desc: 'Dump user accounts, SID mappings, admin groups, and dormant status.', artifact: 'Windows.Sys.Users' },
    { title: 'Linux System Users & Sudoers', desc: 'Inspect /etc/passwd, /etc/shadow permissions, and sudoer privileges.', artifact: 'Linux.Sys.Users' },
    { title: 'UserAssist Registry Artifacts', desc: 'Extract user execution history and GUI application usage timeline.', artifact: 'Windows.Registry.UserAssist' },
    { title: 'KAPE Identity & Event Triage', desc: 'Collect Security, System, and Active Directory event log targets.', artifact: 'Windows.KapeFiles.Targets' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = async () => {
    if (!systemId) {
      setHuntSuccessMsg('Hunt not sent: this event has no tenant-scoped endpoint ID.');
      return;
    }
    if (forensicsChecking) {
      setHuntSuccessMsg('Checking the forensic server and endpoint agent; try again in a moment.');
      return;
    }
    if (forensicsState.error || forensicsState.server?.error || forensicsState.server?.configured === false) {
      setHuntSuccessMsg(forensicsState.error || forensicsState.server?.error || 'Velociraptor forensic server is not configured.');
      return;
    }
    if (forensicsState.server?.connected && !forensicsState.client?.clientId) {
      setHuntSuccessMsg('Hunt not sent: the event endpoint is not matched to a live Velociraptor agent.');
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
      setHuntSuccessMsg(`Real forensic hunt queued: ${response.data?.hunt?._id || 'request accepted'}`);
      await refreshForensics();
    } catch (error) {
      setHuntSuccessMsg(error.response?.data?.message || 'Unable to launch the forensic hunt.');
    } finally {
      setLaunchingHunt(false);
    }
  };

  const handleSaveNotes = async () => {
    setNoteError('');
    if (!log?._id) { setNoteError('A persisted event ID is required.'); return; }
    try {
      const response = await api.post(`/authentication-monitoring/events/${log._id}/notes`, { text: analystNotes, status: caseStatus });
      if (response.data?.event) setLiveLog(previous => ({ ...(previous || log), ...response.data.event }));
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
            <span style={{ fontSize: 24 }}>🔑</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  User & Authentication Forensic Investigation — {alertUser(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Event: {authEventCode(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Source IP: <strong style={{ color: MON.green }}>{authSrcIp(log)}</strong> | Auth Type: <strong style={{ color: MON.cyan }}>{authTypeMethod(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['User Account', alertUser(log), MON.cyan],
                ['Auth Protocol', authTypeMethod(log), MON.purple],
                ['Source IP / Location', `${authSrcIp(log)} (${authGeo(log)})`, MON.text],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Authentication Handshake & Event Sequence</div>
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

          {/* TAB 3: ENDPOINT & DC */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Target Endpoint Details</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || 'Not reported'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Telemetry Source:</span> <strong style={{ color: MON.green }}>{log.source || rawEvidence.auth_source || 'Not reported'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🏰 Active Directory & Domain Controller</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Domain Controller:</span> <b style={{ color: MON.cyan }}>{log.destinationHost || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Destination:</span> <span style={{ fontFamily: 'monospace' }}>{log.destip ? `${log.destip}${log.destPort ? `:${log.destPort}` : ''}` : 'Not reported'}</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Domain Realm:</span> <b>{log.userDomain || log.domain || rawEvidence.domain || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: CREDENTIAL & AUTH */}
          {activeTab === 'auth' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>🔑 Logon Tuple & Protocol Details</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Target User:</span> <b style={{ color: MON.green }}>{alertUser(log)}</b></div>
                  <div><span style={{ color: MON.sub }}>Auth Method:</span> <span style={{ color: MON.cyan }}>{authTypeMethod(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Logon Event ID:</span> <span style={{ fontFamily: 'monospace', color: MON.yellow }}>{authEventCode(log)}</span></div>
                  <div><span style={{ color: MON.sub }}>Source IP:</span> <span style={{ fontFamily: 'monospace', color: MON.red }}>{authSrcIp(log)}</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📊 Logon Type & Session Context</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.green }}>Logon Type:</span>
                    <div style={{ fontSize: 14, fontWeight: 900, color: MON.green, marginTop: 4 }}>{log.logonType || rawEvidence.logon_type || 'Not reported'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.cyan }}>Workstation Name:</span>
                    <div style={{ fontSize: 14, fontWeight: 900, color: MON.cyan, marginTop: 4 }}>{log.sourceHost || rawEvidence.workstation || 'Not reported'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.yellow }}>Authentication Result:</span>
                    <div style={{ fontSize: 14, fontWeight: 900, color: alertStatus(log).toLowerCase().includes('fail') ? MON.red : MON.green, marginTop: 4 }}>{alertStatus(log)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: RIGHTS & PRIVILEGES */}
          {activeTab === 'privileges' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>👑 User Group Membership & Privilege Escalation Audit</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Assigned Group:</span> <b style={{ color: MON.cyan }}>{log.groupName || rawEvidence.group_name || 'Not reported'}</b></div>
                <div><span style={{ color: MON.sub }}>Privilege Status:</span> <b style={{ color: MON.red }}>{log.privilegeLevel || rawEvidence.privilege_level || 'Not reported'}</b></div>
                <div><span style={{ color: MON.sub }}>Account Action:</span> <span style={{ color: MON.yellow }}>{log.userAction || log.credentialEventType || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Command:</span> <span style={{ fontFamily: 'monospace', color: MON.orange }}>{log.commandLine || log.processCmdline || 'Not reported'}</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: MFA & PASSWORD */}
          {activeTab === 'mfa' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>🔐 Multi-Factor Authentication (MFA) Status</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>MFA Status:</span> <b style={{ color: MON.green }}>{log.mfaStatus || rawEvidence.mfa_status || 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>MFA Provider:</span> <b>{log.identityProvider || rawEvidence.identity_provider || 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>Failure Reason:</span> <span style={{ color: MON.green }}>{log.failureReason || rawEvidence.failure_reason || 'Not reported'}</span></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🔑 Password Policy & History</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Password Event:</span> <b>{/password/i.test(`${log.userAction || ''} ${log.ruleId || ''}`) ? (log.description || log.userAction) : 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>Detection Rule:</span> <span style={{ color: MON.sub }}>{log.ruleId || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Password Spraying Evidence:</span> <b style={{ color: MON.red }}>{/spray/i.test(`${log.ruleId || ''} ${log.description || ''}`) ? (log.description || 'Detected') : 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC, GEO & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Mapping</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}>
                    <b style={{ color: MON.red }}>{[log.mitreId, log.mitreTechnique || log.technique, log.mitreTactic].filter(Boolean).join(' · ') || 'Not reported'}</b>
                  </div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🌍 Impossible Travel & Geo Location</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Geo Location:</b> <span style={{ color: MON.yellow }}>{authGeo(log)}</span></div>
                  <div><b>Impossible Travel:</b> <span style={{ color: MON.red, fontWeight: 800 }}>{/impossible.travel|geo.anomaly/i.test(`${log.ruleId || ''} ${log.description || ''}`) ? (log.description || 'Detected') : 'Not reported'}</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL User & Auth Artifact Hunt Launcher</div>
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
                  <button type="button" onClick={handleLaunchHunt} disabled={launchingHunt || !systemId} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: launchingHunt || !systemId ? 'not-allowed' : 'pointer', opacity: systemId ? 1 : 0.55 }}>
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
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Security Event Log (Windows 4625 / Linux auth.log)</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {log.full_log || rawEvidence.raw_log || JSON.stringify(log.rawEvent || {}, null, 2) || 'No raw event was reported.'}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Auth Triage & Case Management</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Assigned Analyst</label>
                    <input type="text" value={assignedAnalyst} readOnly style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Case Status</label>
                    <select value={caseStatus} onChange={e => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }}>
                      <option value="open">In Triage</option>
                      <option value="investigating">Escalated to L3</option>
                      <option value="under_observation">Contained</option>
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
                  <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    {notesSaved ? '✓ Saved!' : 'Save Triage Notes'}
                  </button>
                </div>
                {noteError && <div style={{ marginTop: 8, color: MON.red, fontSize: 10 }}>{noteError}</div>}
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
function UserAuthLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [authFilter, setAuthFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${alertUser(a)} ${alertHost(a)} ${authSrcIp(a)} ${authTypeMethod(a)} ${authEventCode(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchA = authFilter === 'all' || authTypeMethod(a).toLowerCase().includes(authFilter.toLowerCase());
      return matchQ && matchP && matchS && matchA;
    });
  }, [alerts, query, platform, severity, authFilter]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search User, Host, IP, Auth Method, Event ID..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
        <select value={authFilter} onChange={e => setAuthFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Auth Sources</option>
          <option value="windows">Windows Logins</option>
          <option value="ssh">Linux SSH</option>
          <option value="web">Web Password (Pass/Fail)</option>
          <option value="vpn">VPN Sessions</option>
          <option value="rdp">RDP Logins</option>
          <option value="kerberos">Kerberos / NTLM</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 User & Authentication Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1450 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1.2fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Target User Account</span><span>Host / OS</span><span>Source IP</span><span>Auth Method & Event</span><span>Logon Status</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1.2fr 1.2fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{alertUser(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{row.userGroup || 'Domain User'}</span>
                </div>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  {processOs(row) !== 'Unknown' && <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>}
                </div>
                <div>
                  <b style={{ color: MON.green, display: 'block' }}>Source IP: {authSrcIp(row)}</b>
                </div>
                <div>
                  <b style={{ color: MON.purple, display: 'block' }}>{authTypeMethod(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{authEventCode(row)}</span>
                </div>
                <b style={{ color: alertStatus(row).toLowerCase().includes('fail') ? MON.red : MON.green }}>{alertStatus(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No user authentication telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <UserAuthLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

function UserAuthReportsTab({ alerts = [] }) {
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
      const response = await api.get('/dashboard/capability-report/4', { params: { period: reportType, category: 'all' }, skipCache: true });
      const payload = response.data || {};
      const reportAlerts = Array.isArray(payload.alerts) ? payload.alerts : [];
      setReportData({
        alerts: reportAlerts,
        total: Number(payload.total || 0),
        bySev: payload.stats?.bySeverity || {},
        successful: reportAlerts.filter(row => row.authResult === 'success' || /^(?:login|remote_login|privileged_login|screen_unlock_success)$/i.test(row.userAction || '')).length,
      });
      setGenerated(true);
    } catch {
      setReportData({ alerts: [], total: 0, bySev: {}, successful: 0, error: 'Authentication report could not be loaded.' });
      setGenerated(true);
    } finally {
      setGenerating(false);
    }
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Target User,Host,Source IP,Auth Method,Event ID,Status,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(alertUser(a)),
      csvCell(alertHost(a)),
      csvCell(authSrcIp(a)),
      csvCell(authTypeMethod(a)),
      csvCell(authEventCode(a)),
      csvCell(alertStatus(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `user_authentication_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 User & Authentication Security Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries for failed logins, privilege changes, and authentication threats</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Auth Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 User Authentication Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Auth Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Auth Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Auth Alerts', val: reportData?.bySev?.critical || 0, color: MON.red },
              { label: 'High Auth Alerts', val: reportData?.bySev?.high || 0, color: MON.orange },
              { label: 'Successful Logins', val: reportData?.successful || 0, color: MON.green },
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

// ── Dashboard Visual Components for EDR User & Authentication Monitoring ─────────────
function SmoothSparkline({ data = [], color = '#38bdf8', height = 36 }) {
  const values = data.length ? data : [0, 0];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const padding = 4;
  const w = 140;
  const h = height;

  const points = values.map((val, i) => {
    const x = (i / (values.length - 1)) * w;
    const y = h - padding - ((val - min) / (max - min || 1)) * (h - padding * 2);
    return { x, y };
  });

  let pathD = `M ${points[0].x},${points[0].y}`;
  for (let i = 0; i < points.length - 1; i++) {
    const curr = points[i];
    const next = points[i + 1];
    const cp1x = curr.x + (next.x - curr.x) / 2;
    const cp1y = curr.y;
    const cp2x = curr.x + (next.x - curr.x) / 2;
    const cp2y = next.y;
    pathD += ` C ${cp1x},${cp1y} ${cp2x},${cp2y} ${next.x},${next.y}`;
  }

  const fillD = `${pathD} L ${w},${h} L 0,${h} Z`;
  const gradId = `sparkGrad-${color.replace('#', '')}-${Math.random().toString(36).substr(2, 4)}`;

  return (
    <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      <defs>
        <linearGradient id={gradId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.35" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={fillD} fill={`url(#${gradId})`} />
      <path d={pathD} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" />
    </svg>
  );
}

function AuthTimeChart({ alerts = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
  const successData = Array(6).fill(0);
  const failedData = Array(6).fill(0);
  alerts.forEach(row => {
    const when = new Date(alertTime(row));
    if (Number.isNaN(when.getTime())) return;
    const bucket = Math.min(5, Math.floor(when.getHours() / 4));
    if (/fail|denied|invalid/i.test(alertStatus(row))) failedData[bucket] += 1;
    else if (/success/i.test(alertStatus(row)) || /login|remote_login|privileged_login/i.test(row.userAction || '')) successData[bucket] += 1;
  });
  const maxVal = Math.max(...successData, ...failedData, 1);
  const yLabels = Array.from({ length: 6 }, (_, index) => shortNum(Math.round(maxVal * (1 - index / 5))));
  const chartW = 500;
  const chartH = 170;
  const padLeft = 40;
  const padBottom = 22;
  const padTop = 15;
  const padRight = 15;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const getX = (idx) => padLeft + (idx / (times.length - 1)) * innerW;
  const getY = (val) => padTop + innerH - (val / maxVal) * innerH;

  const buildPath = (data) => {
    const pts = data.map((v, i) => ({ x: getX(i), y: getY(v) }));
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
    return { path: d, points: pts };
  };

  const succRes = buildPath(successData);
  const failRes = buildPath(failedData);

  return (
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>AUTHENTICATION OVER TIME</span>
        <div style={{ display: 'flex', gap: 14, fontSize: 11, fontWeight: 600 }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#94a3b8' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#34d399' }} /> Successful
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#94a3b8' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f87171' }} /> Failed
          </span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 160, position: 'relative' }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={lbl}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="3 3" />
                <text x={padLeft - 8} y={y + 4} fill="#64748b" fontSize="10" textAnchor="end" fontFamily="sans-serif">{lbl}</text>
              </g>
            );
          })}

          {times.map((t, i) => {
            const x = getX(i);
            return (
              <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="10" textAnchor="middle" fontFamily="sans-serif">{t}</text>
            );
          })}

          <path d={`${succRes.path} L ${getX(times.length - 1)},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#succGrad)" />
          <path d={succRes.path} fill="none" stroke="#34d399" strokeWidth="2.5" strokeLinecap="round" />
          {succRes.points.map((pt, i) => (
            <circle key={i} cx={pt.x} cy={pt.y} r="3.5" fill="#34d399" stroke="#0b1626" strokeWidth="2" />
          ))}

          <path d={`${failRes.path} L ${getX(times.length - 1)},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#failGrad)" />
          <path d={failRes.path} fill="none" stroke="#f87171" strokeWidth="2.5" strokeLinecap="round" />
          {failRes.points.map((pt, i) => (
            <circle key={i} cx={pt.x} cy={pt.y} r="3.5" fill="#f87171" stroke="#0b1626" strokeWidth="2" />
          ))}

          <defs>
            <linearGradient id="succGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#34d399" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#34d399" stopOpacity="0.0" />
            </linearGradient>
            <linearGradient id="failGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f87171" stopOpacity="0.25" />
              <stop offset="100%" stopColor="#f87171" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function AuthBySourceDonut({ protocols = [], total = 0 }) {
  const colors = ['#38bdf8', '#22d3ee', '#a78bfa', '#fb923c', '#64748b'];
  const sourceTotal = protocols.reduce((sum, row) => sum + Number(row.count || 0), 0);
  const sources = protocols.slice(0, 5).map((row, index) => ({
    label: row._id || 'Not reported',
    percent: sourceTotal ? Number(((Number(row.count || 0) / sourceTotal) * 100).toFixed(1)) : 0,
    color: colors[index % colors.length],
  }));

  let cumAngle = 0;
  const radius = 56;
  const cx = 75;
  const cy = 75;
  const strokeWidth = 16;

  const arcs = sources.map((s) => {
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
    <div style={{ width: '100%', height: '100%', display: 'flex', flexDirection: 'column' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 12 }}>
        AUTHENTICATION BY SOURCE
      </span>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16, flex: 1 }}>
        <div style={{ position: 'relative', width: 150, height: 150, flexShrink: 0 }}>
          <svg viewBox="0 0 150 150" width="150" height="150">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} strokeLinecap="butt" />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 18, fontWeight: 800, color: '#ffffff' }}>{shortNum(total)}</span>
            <span style={{ fontSize: 11, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 9, flex: 1 }}>
          {sources.map((item) => (
            <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: item.color }} />
                <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{item.label}</span>
              </div>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{item.percent}%</span>
            </div>
          ))}
          {!sources.length && <span style={{ color: '#64748b', fontSize: 11 }}>No authentication source data</span>}
        </div>
      </div>
    </div>
  );
}



function UserAuthOverviewDashboard({ alerts = [], total = 0, data = {} }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '14px 16px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = alerts;
  const summary = data?.summary || {};
  const totalCount = Number(summary.total ?? total ?? rows.length);
  const allTrend = buildBuckets(rows, 7, 24);
  const successRows = rows.filter(row => /success/i.test(alertStatus(row)) || /^(?:login|remote_login|privileged_login|screen_unlock_success)$/i.test(row.userAction || ''));
  const failedRows = rows.filter(row => /fail|denied|invalid/i.test(alertStatus(row)));
  const totalLogins = Number(summary.successful ?? successRows.length) + Number(summary.failed ?? failedRows.length);
  const successTrend = buildBuckets(successRows, 7, 24);
  const failureTrend = buildBuckets(failedRows, 7, 24);
  const riskyUsers = Array.isArray(data?.riskyUsers) ? data.riskyUsers : [];
  const protocols = Array.isArray(data?.protocols) ? data.protocols : [];
  const failedUsers = riskyUsers.filter(row => Number(row.failures || 0) > 0).slice(0, 5);
  const recentEvents = rows.slice(0, 5);
  const topAlerts = rows.filter(row => ['critical', 'high', 'medium'].includes(alertSeverity(row))).slice(0, 5);

  const topCards = [
    {
      title: 'TOTAL LOGINS',
      val: shortNum(totalLogins),
      trend: 'Live 24h',
      trendColor: '#38bdf8',
      icon: '👤',
      iconBg: 'rgba(56, 189, 248, 0.15)',
      sparkColor: '#38bdf8',
      sparkData: allTrend,
    },
    {
      title: 'SUCCESSFUL LOGINS',
      val: shortNum(summary.successful ?? successRows.length),
      trend: 'Live 24h',
      trendColor: '#34d399',
      icon: '✓',
      iconBg: 'rgba(52, 211, 153, 0.15)',
      sparkColor: '#34d399',
      sparkData: successTrend,
    },
    {
      title: 'FAILED LOGINS',
      val: shortNum(summary.failed ?? failedRows.length),
      trend: 'Live 24h',
      trendColor: '#f87171',
      icon: '🔒',
      iconBg: 'rgba(248, 113, 113, 0.15)',
      sparkColor: '#f87171',
      sparkData: failureTrend,
    },
    {
      title: 'LOCKED ACCOUNTS',
      val: shortNum(summary.lockouts || 0),
      trend: 'Live 24h',
      trendColor: '#fbbf24',
      icon: '🔐',
      iconBg: 'rgba(251, 191, 36, 0.15)',
      sparkColor: '#fbbf24',
      sparkData: allTrend,
    },
    {
      title: 'ACTIVE SESSIONS',
      val: shortNum(summary.activeSessions || 0),
      trend: 'Estimated live',
      trendColor: '#a78bfa',
      icon: '👤',
      iconBg: 'rgba(167, 139, 250, 0.15)',
      sparkColor: '#a78bfa',
      sparkData: successTrend,
    },
    {
      title: 'MFA FAILURES',
      val: shortNum(summary.mfaFailure || 0),
      trend: 'Live 24h',
      trendColor: '#f43f5e',
      icon: '🛡️',
      iconBg: 'rgba(244, 63, 94, 0.15)',
      sparkColor: '#f43f5e',
      sparkData: failureTrend,
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, padding: '12px 14px', display: 'flex', flexDirection: 'column', justifyContent: 'space-between', position: 'relative', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ width: 30, height: 30, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', color: c.trendColor, fontSize: 14, fontWeight: 800 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 10, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px', textTransform: 'uppercase' }}>
                {c.title}
              </span>
            </div>

            <div style={{ fontSize: 24, fontWeight: 800, color: '#ffffff', margin: '10px 0 2px 0' }}>
              {c.val}
            </div>

            <div style={{ fontSize: 11, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ color: c.trendColor }}>{c.trend}</span>
            </div>

            <div style={{ marginTop: 6, height: 30, width: '100%' }}>
              <SmoothSparkline data={c.sparkData} color={c.sparkColor} height={30} />
            </div>
          </div>
        ))}
      </div>

      {/* 2. MIDDLE SECTION (2 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <AuthTimeChart alerts={rows} />
        </div>
        <div style={panelStyle}>
          <AuthBySourceDonut protocols={protocols} total={totalCount} />
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (4 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
        {/* Panel 1: TOP FAILED LOGIN USERS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              TOP FAILED LOGIN USERS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              <span>USER</span>
              <span>FAILED ATTEMPTS</span>
              <span>LAST FAILED</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {failedUsers.map((r) => (
                <div key={r._id} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr', gap: 6, alignItems: 'center', fontSize: 11 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{r._id}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color: '#f87171', fontWeight: 700 }}>{r.failures}</span>
                    <div style={{ flex: 1, height: 4, background: '#1e293b', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${Math.min(100, Number(r.failures || 0) / Math.max(...failedUsers.map(item => Number(item.failures || 0)), 1) * 100)}%`, height: '100%', background: '#f87171', borderRadius: 2 }} />
                    </div>
                  </div>
                  <span style={{ color: '#64748b', fontSize: 10 }}>{r.lastActivity ? new Date(r.lastActivity).toLocaleString() : 'Not reported'}</span>
                </div>
              ))}
              {!failedUsers.length && <div style={{ color: MON.muted, fontSize: 11 }}>No failed-login users reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
        </div>

        {/* Panel 2: ACCOUNT CHANGES */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              ACCOUNT CHANGES
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              <span>EVENT TYPE</span>
              <span>COUNT</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {[
                { icon: '👤', label: 'New User Created', count: summary.newUsers || 0, iconCol: '#fb923c' },
                { icon: '👤', label: 'User Modified', count: summary.userModifications || 0, iconCol: '#fb923c' },
                { icon: '👤', label: 'User Deleted', count: summary.userDeletions || 0, iconCol: '#f87171' },
                { icon: '🔑', label: 'Password Changed', count: summary.passwordChanges || 0, iconCol: '#38bdf8' },
                { icon: '🔑', label: 'Group Changes', count: summary.groupChanges || 0, iconCol: '#38bdf8' },
                { icon: '🛡️', label: 'Privilege Changes', count: summary.privilegeChanges || 0, iconCol: '#38bdf8' },
              ].map((item) => (
                <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 13, color: item.iconCol }}>{item.icon}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{item.label}</span>
                  </div>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{item.count}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
        </div>

        {/* Panel 3: AUTHENTICATION EVENTS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              AUTHENTICATION EVENTS
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 8 }}>
              {[
                { icon: '🛡️', label: 'MFA Success', count: summary.mfaSuccess || 0, color: '#34d399' },
                { icon: '🛡️', label: 'MFA Failure', count: summary.mfaFailure || 0, color: '#f87171' },
                { icon: '🔑', label: 'Password Changes', count: summary.passwordChanges || 0, color: '#38bdf8' },
                { icon: '🚨', label: 'Brute Force / Spray', count: summary.bruteForce || 0, color: '#f87171' },
                { icon: '🔒', label: 'Account Lockout', count: summary.lockouts || 0, color: '#fb923c' },
                { icon: '⚠️', label: 'Privilege Escalation', count: summary.privilegeChanges || 0, color: '#fb923c' },
              ].map((ev) => (
                <div key={ev.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 13, color: ev.color }}>{ev.icon}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ev.label}</span>
                  </div>
                  <span style={{ color: ev.color, fontWeight: 800 }}>{ev.count}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Panel 4: RISKY USERS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              RISKY USERS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              <span>USER</span>
              <span>RISK SCORE</span>
              <span>ALERTS</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {riskyUsers.slice(0, 5).map((ru) => {
                const risk = Number(ru.riskScore || 0);
                const riskLabel = risk >= 80 ? 'Critical' : risk >= 60 ? 'High' : risk >= 30 ? 'Medium' : 'Low';
                const riskCol = risk >= 80 ? MON.red : risk >= 60 ? MON.orange : risk >= 30 ? MON.yellow : MON.green;
                return (
                <div key={ru._id} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 6, alignItems: 'center', fontSize: 11 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ru._id}</span>
                  <span>
                    <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 10, background: `${riskCol}22`, color: riskCol }}>
                      {riskLabel} ({risk})
                    </span>
                  </span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{ru.alerts}</span>
                </div>
                );
              })}
              {!riskyUsers.length && <div style={{ color: MON.muted, fontSize: 11 }}>No risky-user telemetry reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
        </div>
      </div>

      {/* 4. BOTTOM GRID (2 Wide Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 12 }}>
        {/* Panel 1: RECENT AUTHENTICATION EVENTS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              RECENT AUTHENTICATION EVENTS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.1fr 0.9fr 1.1fr 1.1fr 0.8fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 6, fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              <span>TIME</span>
              <span>USER</span>
              <span>EVENT</span>
              <span>SOURCE</span>
              <span>IP ADDRESS</span>
              <span>LOCATION</span>
              <span>STATUS</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {recentEvents.map((ev, i) => {
                const status = alertStatus(ev); const failed = /fail|denied|invalid/i.test(status);
                return (
                <div key={i} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.1fr 0.9fr 1.1fr 1.1fr 0.8fr', gap: 6, alignItems: 'center', fontSize: 11 }}>
                  <span style={{ color: '#64748b', fontSize: 10 }}>{alertTime(ev) ? new Date(alertTime(ev)).toLocaleString() : 'Not reported'}</span>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{alertUser(ev)}</span>
                  <span style={{ color: failed ? MON.red : MON.green, fontWeight: 700 }}>{ev.eventType || ev.userAction || ev.description || 'Not reported'}</span>
                  <span style={{ color: '#94a3b8' }}>{authTypeMethod(ev)}</span>
                  <span style={{ color: '#94a3b8', fontFamily: 'monospace', fontSize: 10 }}>{authSrcIp(ev)}</span>
                  <span style={{ color: '#cbd5e1' }}>{authGeo(ev)}</span>
                  <span style={{ color: failed ? MON.red : MON.green, fontWeight: 700 }}>{status}</span>
                </div>
                );
              })}
              {!recentEvents.length && <div style={{ color: MON.muted, fontSize: 11 }}>No authentication events reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Events →</span>
          </div>
        </div>

        {/* Panel 2: TOP SECURITY ALERTS */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10 }}>
              TOP SECURITY ALERTS
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.9fr 1.2fr 0.9fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 6, fontSize: 10, fontWeight: 700, color: '#64748b' }}>
              <span>ALERT</span>
              <span>SEVERITY</span>
              <span>TIME</span>
              <span>STATUS</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 8 }}>
              {topAlerts.map((al, i) => {
                const sev = alertSeverity(al); const color = SEV_COLOR[sev] || MON.muted;
                return (
                <div key={i} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.9fr 1.2fr 0.9fr', gap: 6, alignItems: 'center', fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ color, fontSize: 13 }}>{sev === 'critical' ? '🚨' : '⚠️'}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{al.description || al.ruleId || 'Authentication alert'}</span>
                  </div>
                  <span>
                    <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 10, background: SEV_BG[sev], color }}>
                      {sev}
                    </span>
                  </span>
                  <span style={{ color: '#64748b', fontSize: 10 }}>{alertTime(al) ? new Date(alertTime(al)).toLocaleString() : 'Not reported'}</span>
                  <span style={{ color: MON.yellow, fontWeight: 700 }}>{al.status || 'new'}</span>
                </div>
                );
              })}
              {!topAlerts.length && <div style={{ color: MON.muted, fontSize: 11 }}>No medium/high authentication alerts reported.</div>}
            </div>
          </div>
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <span style={{ fontSize: 11, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts →</span>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`UserAuthDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function UserAuthDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = {}, onAction }) {
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

  // User & Auth Specific SOC Categories & Metrics
  const count = (field, fallback) => Number(summary[field] ?? fallback);
  const successLogins = count('successful', rows.filter(r => /success/i.test(alertStatus(r)) || /^(?:login|remote_login|privileged_login)$/i.test(r.userAction || '')).length);
  const failedLogins = count('failed', rows.filter(r => /fail|denied|invalid/i.test(alertStatus(r))).length);
  const lockouts = count('lockouts', rows.filter(r => containsAny(r, ['lockout', 'locked out'])).length);
  const newUsers = count('newUsers', rows.filter(r => containsAny(r, ['new user', 'account created', '4720'])).length);
  const userModifications = count('userModifications', rows.filter(r => containsAny(r, ['account modified', 'user modified', '4738'])).length);
  const privilegeEscalations = count('privilegeChanges', rows.filter(r => containsAny(r, ['privilege', 'sudo', 'admin rights', 'admin assignment'])).length);
  const groupChanges = count('groupChanges', rows.filter(r => containsAny(r, ['group membership', 'local administrators', '4728', '4732'])).length);
  const winAuth = count('windowsAuthentication', rows.filter(r => processOs(r) === 'Windows' || containsAny(r, ['ntlm', 'kerberos', 'windows'])).length);
  const linuxSsh = count('linuxAuthentication', rows.filter(r => processOs(r) === 'Linux' || containsAny(r, ['ssh', 'auth.log', 'pam', 'sudo'])).length);
  const activeDirectory = count('activeDirectory', rows.filter(r => containsAny(r, ['active directory', 'ldap', 'kerberos', 'domain controller'])).length);
  const vpnLogins = count('vpn', rows.filter(r => containsAny(r, ['vpn'])).length);
  const rdpLogins = count('rdp', rows.filter(r => containsAny(r, ['rdp', 'remote desktop'])).length);
  const mfaFailures = count('mfaFailure', rows.filter(r => containsAny(r, ['mfa failure', 'mfa failed', 'mfa bypass'])).length);
  const mfaPass = count('mfaSuccess', rows.filter(r => containsAny(r, ['mfa pass', 'mfa success', 'mfa verified', '2fa pass', 'duo success'])).length);
  const passwordResets = count('passwordChanges', rows.filter(r => containsAny(r, ['password reset', 'password change'])).length);
  const bruteForce = count('bruteForce', rows.filter(r => containsAny(r, ['brute force', 'password spray', 'stuffing'])).length);
  const impossibleTravel = count('impossibleTravel', rows.filter(r => containsAny(r, ['impossible travel', 'geo anomaly'])).length);
  const dormantAccountHits = count('dormantAccounts', rows.filter(r => containsAny(r, ['dormant', 'disabled account'])).length);
  const serviceAccountHits = count('serviceAccounts', rows.filter(r => containsAny(r, ['service account', 'svc_'])).length);
  const webPassLogins = count('webSuccess', rows.filter(r => containsAny(r, ['web', 'http', 'browser']) && /success/i.test(alertStatus(r))).length);
  const webFailLogins = count('webFailed', rows.filter(r => containsAny(r, ['web', 'http', 'browser']) && /fail|denied|invalid/i.test(alertStatus(r))).length);

  const kpis = [
    { label: '👤 1. Successful User Logins', val: shortNum(successLogins), trend: 'Logon Success', color: MON.green, data: timeline },
    { label: '⚠️ 2. Failed Login Attempts', val: shortNum(failedLogins), trend: 'Logon Fail', color: MON.orange, data: timeline },
    { label: '🔒 3. Account Lockout Events', val: shortNum(lockouts), trend: 'Lockout', color: MON.red, data: timeline },
    { label: '➕ 4. New Account Creations', val: shortNum(newUsers), trend: 'User Created', color: MON.blue, data: timeline },
    { label: '✏️ 5. User Account Modifications', val: shortNum(userModifications), trend: 'User Edit', color: MON.cyan, data: timeline },
    { label: '👑 6. Privilege Escalations', val: shortNum(privilegeEscalations), trend: 'Admin Rights', color: MON.red, data: timeline },
    { label: '👥 7. Group Membership Changes', val: shortNum(groupChanges), trend: 'Group Mod', color: MON.purple, data: timeline },
    { label: '🪟 8. Windows Authentication', val: shortNum(winAuth), trend: 'NTLM/Kerberos', color: MON.cyan, data: timeline },
    { label: '🐧 9. Linux SSH & PAM Logins', val: shortNum(linuxSsh), trend: 'SSH/Sudo', color: MON.orange, data: timeline },
    { label: '🏰 10. Active Directory / LDAP', val: shortNum(activeDirectory), trend: 'AD KDC', color: MON.green, data: timeline },
    { label: '🌐 11. Web Password Pass (Success Logins)', val: shortNum(webPassLogins), trend: 'Web Pass', color: MON.green, data: timeline },
    { label: '🔑 12. Web Password Fail (Invalid / Failed)', val: shortNum(webFailLogins), trend: 'Web Fail', color: MON.red, data: timeline },
    { label: '🔒 13. VPN Login Sessions', val: shortNum(vpnLogins), trend: 'VPN Auth', color: MON.blue, data: timeline },
    { label: '🖥️ 14. RDP Remote Desktop Logins', val: shortNum(rdpLogins), trend: 'RDP Session', color: MON.yellow, data: timeline },
    { label: '🔑 15. MFA Failure / Bypass Hits', val: shortNum(mfaFailures), trend: 'MFA Alert', color: MON.red, data: timeline },
    { label: '🔑 16. MFA Pass (Success Logins)', val: shortNum(mfaPass), trend: 'MFA Pass', color: MON.green, data: timeline },
    { label: '🔄 17. Password Resets & Changes', val: shortNum(passwordResets), trend: 'Pass Reset', color: MON.cyan, data: timeline },
    { label: '🚨 18. Brute Force & Spraying', val: shortNum(bruteForce), trend: 'Brute Force', color: MON.red, data: timeline },
    { label: '🌍 19. Impossible Travel Alerts', val: shortNum(impossibleTravel), trend: 'Geo Shift', color: MON.purple, data: timeline },
    { label: '💤 20. Dormant Account Usage', val: shortNum(dormantAccountHits), trend: 'Dormant Hit', color: MON.yellow, data: timeline },
    { label: '⚙️ 21. Service Account Activity', val: shortNum(serviceAccountHits), trend: 'Svc Account', color: MON.blue, data: timeline },
    { label: '🚨 22. Account Takeover (ATO) Signals', val: shortNum(summary.accountTakeover || 0), trend: 'ATO Threat', color: MON.red, data: timeline },
    { label: '🛡️ 23. Identity Policy Violations', val: shortNum(summary.policyViolations || 0), trend: 'Policy Violation', color: MON.orange, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'unknown'),
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
        {activeTab === 'log-monitor' ? (
          <UserAuthLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={4} alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <UserAuthOverviewDashboard alerts={alerts} total={totalRows} data={data} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Identity & Security Audit Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints returned · authentication source availability is agent-reported</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Auth Auditor</span><span>Events</span><span>Auth Alerts</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.events > 0 ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.events > 0 ? 'Reporting' : 'No events'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend authentication agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 User Authentication Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} auth events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>👤 Top Targeted User Accounts</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, alertUser, 5).map(([user, count], index) => (
                    <div key={user} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>👤 {user}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                  {!topCounts(rows, alertUser, 5).length && <div style={{ color: MON.muted, fontSize: 11 }}>No user telemetry reported.</div>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Auth Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Successful Logins', successLogins],
                    ['Failed Logins & Lockouts', failedLogins + lockouts],
                    ['Privilege Escalations', privilegeEscalations],
                    ['Brute Force & Spraying', bruteForce],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`UserAuthMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function UserAuthMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '4';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [data, setData] = useState({ summary: {}, events: [], timeline: [], protocols: [], riskyUsers: [] });

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/authentication-monitoring/dashboard', { params: { windowHours: 24, limit: 1000 }, skipCache: quiet });
      const payload = r.data || {};
      const next = Array.isArray(payload.events) ? payload.events : [];
      setAlerts(next);
      setTotal(Number(payload.summary?.total ?? next.length));
      setSystems(Array.isArray(payload.systems) ? payload.systems : []);
      setData(payload);
    } catch (error) {
      const message = error.response?.data?.message || 'Live authentication data load failed';
      if (!quiet) {
        setAlerts([]);
        setTotal(0);
        setSystems([]);
        setData({ error: message, summary: {}, events: [], timeline: [], protocols: [], riskyUsers: [] });
      } else {
        setData(previous => ({ ...(previous || {}), error: message }));
      }
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
    socket.on('auth:event', buf.add);
    socket.on('authentication_event', buf.add);
    socket.on('authentication_alert', buf.add);
    socket.on('user:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('auth:event', buf.add);
      socket.off('authentication_event', buf.add);
      socket.off('authentication_alert', buf.add);
      socket.off('user:event', buf.add);
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
            🛡️ 4. User & Authentication Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <UserAuthDashboard alerts={alerts} loading={loading} total={total} systems={systems} data={data} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <UserAuthMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function UserAuthSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=4" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>User & Auth SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=4')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="auth" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <UserAuthDashboard />
        </main>
      </div>
    </div>
  );
}

export function AuthSubTabPage() {
  return <UserAuthSubTabPage />;
}

// ── Alias export for backward compatibility ──
export { UserAuthDashboard as AuthenticationMonitoringDashboardPanel };
