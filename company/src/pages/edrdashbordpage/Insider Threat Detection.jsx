import CapabilityLogsPanel from './CapabilityLogsPanel';
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'Unknown endpoint';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || row?.fileUser || row?.changedByUser || 'Unknown user';
}

function alertStatus(row) {
  return row?.status || row?.state || 'Open';
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

// ── Insider Threat Telemetry Field Extractors ──────────────────────────────
function insiderUser(row) {
  return alertUser(row);
}

function insiderDept(row) {
  return row?.department?.name || row?.departmentName || row?.department || row?.dept || 'Not reported';
}

function insiderRule(row) {
  return row?.ruleId || row?.rule_id || row?.rule || row?.action || 'Not reported';
}

function insiderRiskScore(row) {
  const score = Number(row?.riskScore ?? row?.risk_score ?? row?.score);
  if (Number.isFinite(score)) return Math.max(0, Math.min(100, Math.round(score)));
  return ({ critical: 95, high: 75, medium: 50, low: 25, info: 10 })[alertSeverity(row)] || 0;
}

function insiderSignalType(row) {
  const explicit = row?.insiderSignalType || row?.insider_signal_type
    || row?.rawEvent?.insiderSignalType || row?.rawEvent?.insider_signal_type
    || row?.rawEvent?.raw?.insider_signal_type;
  if (explicit) return String(explicit).replaceAll('_', ' ');
  const text = `${insiderRule(row)} ${row?.eventType || ''} ${row?.description || ''}`.toLowerCase();
  if (/exfil|outbound.transfer|upload|ftp|scp|cloud/.test(text)) return 'data exfiltration';
  if (/privilege|sudo|admin.right|group.change|root.login/.test(text)) return 'privilege misuse';
  if (/usb|removable/.test(text)) return 'removable media';
  if (/after.hours|off.hours|weekend|unusual.time/.test(text)) return 'after-hours activity';
  if (/sensitive.file/.test(text)) return 'sensitive file activity';
  if (/log.clear|security.tool|tamper/.test(text)) return 'defense evasion';
  if (/archive|zip|rar|7z/.test(text)) return 'archive staging';
  if (/lateral|remote.execution|psexec/.test(text)) return 'lateral movement';
  return 'other activity';
}

function eventBytes(row) {
  return Number(row?.bytesSent ?? row?.bytes_sent ?? row?.bytesTransferred ?? row?.bytes_transferred ?? row?.fileSize ?? row?.file_size ?? 0) || 0;
}

function formatBytes(value) {
  let bytes = Number(value) || 0;
  if (!bytes) return 'Not reported';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (bytes >= 1024 && unit < units.length - 1) { bytes /= 1024; unit += 1; }
  return `${bytes.toFixed(unit ? 1 : 0)} ${units[unit]}`;
}

function eventDestination(row) {
  return row?.destination || row?.domain || row?.url || row?.destip || row?.dstIp || row?.device || row?.filePath || 'Not reported';
}

function eventDescription(row) {
  return row?.description || row?.message || insiderRule(row);
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
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'Open');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || ''));
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
      setHuntSuccessMsg('Not sent: no forensic-hunt executor is configured; no hunt or case was created.');
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
                ['Exfiltration Volume', formatBytes(eventBytes(log)), MON.orange],
                ['Destination', eventDestination(log), MON.red],
                ['Detection Engine', log.detectionSource || log.source || 'Endpoint correlation', MON.green],
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
                { time: alertTime(log), event: eventDescription(log), sev: alertSeverity(log) },
                ...(Array.isArray(log.relatedEvents) ? log.relatedEvents.map(event => ({
                  time: alertTime(event), event: eventDescription(event), sev: alertSeverity(event),
                })) : []),
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
              {(log.mitreTechniques || log.mitre_techniques || [log.mitreId || log.mitre_id].filter(Boolean)).map((entry, i) => {
                const techniqueId = typeof entry === 'string' ? entry : (entry?.id || entry?.techniqueId || 'Not reported');
                const techniqueName = typeof entry === 'object' ? (entry?.name || entry?.technique || '') : (log.mitreTechnique || log.technique || '');
                return (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{log.mitreTactic || log.mitre_tactic || 'MITRE ATT&CK'}</div>
                  <div style={{ fontSize: 12, fontWeight: 800, color: MON.text, marginTop: 4 }}>{techniqueId}{techniqueName ? ` — ${techniqueName}` : ''}</div>
                  <span style={{ fontSize: 9, fontWeight: 900, color: sevColor, background: sevBg, padding: '2px 6px', borderRadius: 4, display: 'inline-block', marginTop: 8 }}>{sev.toUpperCase()}</span>
                </div>
                );
              })}
              {!(log.mitreTechniques || log.mitre_techniques || log.mitreId || log.mitre_id) && <div style={{ color: MON.muted, fontSize: 11 }}>No MITRE technique was reported for this event.</div>}
            </div>
          )}

          {/* TAB 9: INCIDENT RESPONSE */}
          {activeTab === 'response' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
              <button type="button" onClick={() => alert('Not sent: no credential-revocation executor is configured.')} style={{ background: MON.red, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                🚫 Revoke User Credentials & Active Sessions
              </button>
              <button type="button" onClick={() => alert('Not sent: no endpoint-isolation executor is configured.')} style={{ background: MON.orange, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                🔒 Isolate Endpoint Machine Immediately
              </button>
              <button type="button" onClick={() => alert('Not sent: no USB-control executor is configured.')} style={{ background: MON.purple, color: '#fff', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                💾 Disable USB Storage Ports via EDR Agent
              </button>
              <button type="button" onClick={() => alert('Not sent: no firewall response executor is configured.')} style={{ background: MON.cyan, color: '#000', border: 'none', padding: 14, borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
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
              <pre style={{ fontSize: 10, color: MON.muted, whiteSpace: 'pre-wrap', wordBreak: 'break-word', margin: 0 }}>
                {JSON.stringify(log.rawEvent || log.raw || log, null, 2)}
              </pre>
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
    return filtered;
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const response = await api.get('/dashboard/capability-report/16', {
        params: { period: reportType, category: 'all' },
        skipCache: true,
      });
      const filtered = Array.isArray(response.data?.alerts) ? response.data.alerts : getFilteredAlerts();
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
      filtered.forEach(a => { const severity = alertSeverity(a); if (bySev[severity] !== undefined) bySev[severity] += 1; });
      setReportData({ alerts: filtered, total: filtered.length, bySev });
      setGenerated(true);
    } finally {
      setGenerating(false);
    }
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

// ── Visual Helper Components for Insider Threat Detection Dashboard ─────────────
function InsiderThreatAlertsTimelineChart({ alerts = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'];
  const data = buildBuckets(alerts, 12, 24);
  const scaleMax = Math.max(...data, 1);
  const yLabels = Array.from({ length: 6 }, (_, index) => String(Math.round(scaleMax * (5 - index) / 5)));

  const chartW = 420;
  const chartH = 150;
  const padLeft = 24;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = data.map((v, i) => ({
    x: padLeft + (i / (data.length - 1)) * innerW,
    y: padTop + innerH - (v / scaleMax) * innerH,
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
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>INSIDER THREAT ALERTS TIMELINE</span>
        <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
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
          <path d={d} fill="none" stroke="#ef4444" strokeWidth="2" />
        </svg>
      </div>
    </div>
  );
}

function AlertsByCategoryDonut({ alerts = [] }) {
  const colors = ['#f87171', '#fb923c', '#fbbf24', '#38bdf8', '#a78bfa'];
  const total = alerts.length;
  const categories = topCounts(alerts, insiderSignalType, 5).map(([label, count], index) => ({
    label: label.replace(/\b\w/g, char => char.toUpperCase()), count,
    pct: total ? (count / total) * 100 : 0, color: colors[index],
  }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>ALERTS BY CATEGORY</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{total}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {categories.map(c => (
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

function UserRiskScoreDistributionDonut({ alerts = [] }) {
  const userScores = new Map();
  alerts.forEach(row => {
    const user = insiderUser(row);
    if (user === 'Unknown user') return;
    userScores.set(user, Math.max(userScores.get(user) || 0, insiderRiskScore(row)));
  });
  const total = userScores.size;
  const values = [...userScores.values()];
  const counts = [values.filter(score => score >= 80).length, values.filter(score => score >= 40 && score < 80).length, values.filter(score => score < 40).length];
  const dist = [
    { label: 'High Risk (80-100)', count: counts[0], color: '#f87171' },
    { label: 'Medium Risk (40-79)', count: counts[1], color: '#fb923c' },
    { label: 'Low Risk (1-39)', count: counts[2], color: '#34d399' },
  ].map(item => ({ ...item, pct: total ? (item.count / total) * 100 : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = dist.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>USER RISK SCORE DISTRIBUTION</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{total}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5, flex: 1, fontSize: 8.5 }}>
          {dist.map(d => (
            <div key={d.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: d.color }} /> {d.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{d.count} ({d.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function UebaRiskHeatmap({ alerts = [] }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hours = ['00', '04', '08', '12', '16', '20', '24'];

  const rawMatrix = Array.from({ length: 7 }, () => Array(7).fill(0));
  alerts.forEach(row => {
    const date = new Date(alertTime(row) || 0);
    if (Number.isNaN(date.getTime())) return;
    const day = (date.getDay() + 6) % 7;
    const hour = Math.min(6, Math.floor(date.getHours() / 4));
    rawMatrix[day][hour] += insiderRiskScore(row);
  });
  const maxRisk = Math.max(...rawMatrix.flat(), 1);
  const matrix = rawMatrix.map(row => row.map(value => value / maxRisk));

  const getHeatColor = (v) => {
    if (v > 0.8) return '#ef4444';
    if (v > 0.6) return '#f97316';
    if (v > 0.4) return '#eab308';
    if (v > 0.2) return '#22c55e';
    return '#15803d';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>UEBA RISK HEATMAP</span>
      <div style={{ display: 'flex', gap: 6, flex: 1 }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-around', fontSize: 7.5, color: '#64748b' }}>
          {days.map(d => <span key={d}>{d}</span>)}
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3 }}>
          {matrix.map((row, rIdx) => (
            <div key={rIdx} style={{ display: 'flex', gap: 3, flex: 1 }}>
              {row.map((val, cIdx) => (
                <div key={cIdx} style={{ flex: 1, background: getHeatColor(val), borderRadius: 2 }} />
              ))}
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-around', fontSize: 7.5, color: '#64748b', marginTop: 2 }}>
            {hours.map(h => <span key={h}>{h}</span>)}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 7.5, color: '#8ea0b8', marginTop: 4 }}>
        <span>Low Risk</span>
        <div style={{ width: 80, height: 4, background: 'linear-gradient(90deg, #15803d, #22c55e, #eab308, #f97316, #ef4444)', borderRadius: 2 }} />
        <span>High Risk</span>
      </div>
    </div>
  );
}

function FileAccessTrendChart({ alerts = [] }) {
  const now = new Date();
  const starts = Array.from({ length: 7 }, (_, index) => {
    const date = new Date(now);
    date.setHours(0, 0, 0, 0);
    date.setDate(date.getDate() - (6 - index));
    return date;
  });
  const days = starts.map(date => date.toLocaleDateString(undefined, { day: '2-digit', month: 'short' }));
  const data = starts.map(start => alerts.filter(row => {
    if (!/sensitive.file|file/.test(`${insiderSignalType(row)} ${insiderRule(row)}`.toLowerCase())) return false;
    const value = new Date(alertTime(row) || 0);
    return !Number.isNaN(value.getTime()) && value >= start && value < new Date(start.getTime() + 86400000);
  }).length);
  const scaleMax = Math.max(...data, 1);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>FILE ACCESS TREND</span>
        <span style={{ fontSize: 8.5, color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>Last 7 Days ▾</span>
      </div>

      <div style={{ flex: 1, display: 'flex', alignItems: 'flex-end', gap: 6, minHeight: 90, marginTop: 4 }}>
        {data.map((val, idx) => (
          <div key={idx} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', height: '100%', justifyContent: 'flex-end' }}>
            <div style={{ width: '100%', height: `${(val / scaleMax) * 100}%`, background: '#38bdf8', borderRadius: '3px 3px 0 0' }} />
            <span style={{ fontSize: 7.5, color: '#64748b', marginTop: 4 }}>{days[idx]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function InsiderOverviewDashboard({ alerts = [], total = 0, systems = [] }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const users = new Map();
  alerts.forEach(row => {
    const user = insiderUser(row);
    if (user === 'Unknown user') return;
    const current = users.get(user) || { name: user, dept: insiderDept(row), scores: [], score: 0 };
    const score = insiderRiskScore(row);
    current.score = Math.max(current.score, score);
    current.scores.push(score);
    users.set(user, current);
  });
  const userRows = [...users.values()];
  const highRiskUsers = userRows.filter(row => row.score >= 61).length;
  const exfilRows = alerts.filter(row => /exfil|outbound.transfer|upload|cloud|ftp|scp|removable.media/.test(insiderSignalType(row)));
  const privilegeRows = alerts.filter(row => /privilege|admin|account.change|defense.evasion/.test(insiderSignalType(row)));
  const riskAverage = alerts.length ? Math.round(alerts.reduce((sum, row) => sum + insiderRiskScore(row), 0) / alerts.length) : 0;
  const trend = buildBuckets(alerts, 7, 24);
  const metric = pattern => alerts.filter(row => pattern.test(`${insiderSignalType(row)} ${insiderRule(row)} ${eventDescription(row)}`.toLowerCase())).length;

  const topCards = [
    { title: 'Total Users Monitored', val: shortNum(users.size), sub: `${systems.length} reporting endpoints`, subCol: '#38bdf8', icon: '👥', iconBg: 'rgba(56, 189, 248, 0.15)' },
    { title: 'High Risk Users', val: shortNum(highRiskUsers), sub: 'Current 24h telemetry', subCol: '#f87171', icon: '👤', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'Insider Threat Alerts', val: shortNum(total || alerts.length), sub: 'Current 24h telemetry', subCol: '#f87171', icon: '🛡️', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'Data Exfiltration Attempts', val: shortNum(exfilRows.length), sub: 'Correlated signals', subCol: '#fb923c', icon: '☁️', iconBg: 'rgba(251, 146, 60, 0.15)' },
    { title: 'Privileged Activities', val: shortNum(privilegeRows.length), sub: 'Correlated signals', subCol: '#a78bfa', icon: '👑', iconBg: 'rgba(167, 139, 250, 0.15)' },
    { title: 'UEBA Risk Score (Avg)', val: shortNum(riskAverage), sub: 'Observed event average', subCol: '#fbbf24', icon: '📈', iconBg: 'rgba(251, 191, 36, 0.15)', spark: trend },
  ];

  const middleMetricCards = [
    { title: 'AFTER-HOURS ACCESS', val: shortNum(metric(/after.hours|off.hours|weekend|unusual.time/)), sub: 'Observed', col: '#a78bfa', icon: '⏰', spark: trend },
    { title: 'FAILED LOGIN ATTEMPTS', val: shortNum(metric(/auth.fail|failed.login|authentication.failure/)), sub: 'Observed', col: '#38bdf8', icon: '🔒', spark: trend },
    { title: 'SENSITIVE FILE ACTIVITY', val: shortNum(metric(/sensitive.file/)), sub: 'Observed', col: '#34d399', icon: '📄', spark: trend },
    { title: 'USB ACTIVITIES', val: shortNum(metric(/usb|removable.media/)), sub: 'Observed', col: '#fb923c', icon: '🔌', spark: trend },
    { title: 'CLOUD / OUTBOUND ACTIVITY', val: shortNum(exfilRows.length), sub: 'Observed', col: '#38bdf8', icon: '☁️', spark: trend },
    { title: 'LATERAL MOVEMENT ATTEMPTS', val: shortNum(metric(/lateral.movement|remote.execution|psexec/)), sub: 'Observed', col: '#f87171', icon: '🔀', spark: trend },
  ];

  const recentHighRiskAlerts = alerts
    .filter(row => ['critical', 'high'].includes(alertSeverity(row)))
    .sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0))
    .slice(0, 6)
    .map(row => ({ title: eventDescription(row), user: insiderUser(row), time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—', sev: alertSeverity(row), sevCol: SEV_COLOR[alertSeverity(row)] || MON.green, icon: alertSeverity(row) === 'critical' ? '🚨' : '⚠️' }));

  const topRiskUsers = userRows.sort((a, b) => b.score - a.score).slice(0, 5).map(row => ({
    ...row, col: row.score >= 80 ? MON.red : row.score >= 60 ? MON.orange : MON.green, spark: row.scores.slice(-8),
  }));

  const exfiltrationAttempts = exfilRows.slice(0, 5).map(row => ({
    user: insiderUser(row), activity: eventDescription(row), dest: eventDestination(row),
    size: formatBytes(eventBytes(row)), time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
  }));

  const privilegedActivities = privilegeRows.slice(0, 5).map(row => ({
    user: insiderUser(row), activity: eventDescription(row), res: alertHost(row),
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
    sev: alertSeverity(row), sevCol: SEV_COLOR[alertSeverity(row)] || MON.green,
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 6, position: 'relative', overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 8.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
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
              {c.spark && (
                <div style={{ width: 50, height: 20 }}>
                  <MiniSparkline data={c.spark} color={c.subCol} height={20} />
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.2fr', gap: 12 }}>
        <div style={panelStyle}>
          <InsiderThreatAlertsTimelineChart alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <AlertsByCategoryDonut alerts={alerts} />
        </div>

        {/* Recent High Risk Alerts */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>RECENT HIGH RISK ALERTS</span>
              <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View all</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {recentHighRiskAlerts.map((ra, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.8fr 0.8fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    <span>{ra.icon}</span>
                    <span style={{ color: '#e2e8f0', fontWeight: 600 }}>{ra.title}</span>
                  </div>
                  <span style={{ color: '#8ea0b8' }}>{ra.user}</span>
                  <span style={{ color: '#64748b', fontSize: 8 }}>{ra.time}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, color: ra.sevCol, padding: '1px 5px', background: `${ra.sevCol}15`, borderRadius: 4, border: `1px solid ${ra.sevCol}33`, textAlign: 'center' }}>
                    {ra.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 3. MIDDLE METRIC CARDS ROW (6 Columns with Sparklines) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {middleMetricCards.map(mc => (
          <div key={mc.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 8.5, fontWeight: 800, color: '#8ea0b8' }}>{mc.title}</span>
              <span style={{ fontSize: 12 }}>{mc.icon}</span>
            </div>
            <div style={{ fontSize: 18, fontWeight: 800, color: '#ffffff' }}>{mc.val}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 2 }}>
              <span style={{ fontSize: 8, fontWeight: 700, color: mc.col }}>{mc.sub}</span>
              <div style={{ width: 45, height: 16 }}>
                <MiniSparkline data={mc.spark} color={mc.col} height={16} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 4. LOWER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr 1.4fr', gap: 12 }}>
        {/* Top Risk Users */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP RISK USERS</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 0.6fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>User</span>
            <span>Department</span>
            <span>Risk Score</span>
            <span>Trend</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {topRiskUsers.map(ru => (
              <div key={ru.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 0.6fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1', fontWeight: 600 }}>👤 {ru.name}</span>
                <span style={{ color: '#8ea0b8' }}>{ru.dept}</span>
                <span style={{ color: ru.col, fontWeight: 800 }}>{ru.score}</span>
                <div style={{ height: 14 }}>
                  <MiniSparkline data={ru.spark} color={ru.col} height={14} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Data Exfiltration Attempts (Top 5) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>DATA EXFILTRATION ATTEMPTS (Top 5)</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.4fr 1.3fr 0.7fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>User</span>
            <span>Activity</span>
            <span>Destination</span>
            <span>Data Size</span>
            <span>Time</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {exfiltrationAttempts.map((ea, idx) => (
              <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.4fr 1.3fr 0.7fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1' }}>👤 {ea.user}</span>
                <span style={{ color: '#e2e8f0' }}>{ea.activity}</span>
                <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8 }}>{ea.dest}</span>
                <span style={{ color: '#fb923c', fontWeight: 700 }}>{ea.size}</span>
                <span style={{ color: '#64748b', fontSize: 8 }}>{ea.time}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Privileged User Activities (Latest) */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>PRIVILEGED USER ACTIVITIES (Latest)</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.5fr 1fr 0.7fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>User</span>
            <span>Activity</span>
            <span>Resource</span>
            <span>Time</span>
            <span>Risk</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {privilegedActivities.map((pa, idx) => (
              <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.5fr 1fr 0.7fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1' }}>👤 {pa.user}</span>
                <span style={{ color: '#e2e8f0' }}>{pa.activity}</span>
                <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8 }}>{pa.res}</span>
                <span style={{ color: '#64748b', fontSize: 8 }}>{pa.time}</span>
                <span style={{ fontSize: 8, fontWeight: 800, color: pa.sevCol, padding: '1px 5px', background: `${pa.sevCol}15`, borderRadius: 4, border: `1px solid ${pa.sevCol}33`, textAlign: 'center' }}>
                  {pa.sev}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 5. BOTTOM GRID (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <UserRiskScoreDistributionDonut alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <UebaRiskHeatmap alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <FileAccessTrendChart alerts={alerts} />
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
    api.get('/system', { skipCache: true })
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
  const osCounts = backendSystems.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);

  // 20 Insider Threat Specific SOC Categories & Metrics
  const exfilCount = rows.filter(r => containsAny(r, ['exfil', 'upload', 'cloud', 'drive', 'usb'])).length;
  const adminAbuseCount = rows.filter(r => containsAny(r, ['admin', 'sudo', 'privilege'])).length;
  const afterHoursCount = rows.filter(r => containsAny(r, ['after_hours', 'night', 'vpn'])).length;
  const monitoredUsers = new Set(rows.map(insiderUser).filter(user => user !== 'Unknown user')).size;
  const highRiskUsers = new Set(rows.filter(row => insiderRiskScore(row) >= 61).map(insiderUser).filter(user => user !== 'Unknown user')).size;
  const avgRisk = rows.length ? Math.round(rows.reduce((sum, row) => sum + insiderRiskScore(row), 0) / rows.length) : 0;

  const kpis = [
    { label: '🛡️ 1. Total Insider Signals', val: shortNum(totalRows), trend: 'User Audit', color: MON.blue, data: timeline },
    { label: '👤 2. Monitored Active Users', val: shortNum(monitoredUsers), trend: 'Observed', color: MON.cyan, data: timeline },
    { label: '🔥 3. Critical Risk Users (Score 86-100)', val: shortNum(new Set(rows.filter(row => insiderRiskScore(row) >= 86).map(insiderUser).filter(user => user !== 'Unknown user')).size), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 4. High Risk Users (Score 61-85)', val: shortNum(highRiskUsers), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🌐 5. Data Exfiltration Events', val: shortNum(exfilCount), trend: 'Observed', color: MON.red, data: timeline },
    { label: '🔑 6. Administrative Privilege Abuse', val: shortNum(adminAbuseCount), trend: 'Observed', color: MON.purple, data: timeline },
    { label: '🕒 7. After-Hours Access Anomalies', val: shortNum(afterHoursCount), trend: 'Observed', color: MON.cyan, data: timeline },
    { label: '💾 8. Mass USB Removable Storage Copies', val: shortNum(rows.filter(r => containsAny(r, ['usb', 'removable'])).length), trend: 'Observed', color: MON.orange, data: timeline },
    { label: '📁 9. Sensitive File Access Violations', val: shortNum(rows.filter(r => containsAny(r, ['sensitive file'])).length), trend: 'Observed', color: MON.yellow, data: timeline },
    { label: '📦 10. Encrypted ZIP Archive Creation', val: shortNum(rows.filter(r => containsAny(r, ['archive staging', 'zip', 'rar', '7z'])).length), trend: 'Observed', color: MON.blue, data: timeline },
    { label: '🗑 11. Mass File Deletions / Shredding', val: shortNum(rows.filter(r => containsAny(r, ['mass file', 'shred'])).length), trend: 'Observed', color: MON.red, data: timeline },
    { label: '📜 12. Security Log Clearing Attempts', val: shortNum(rows.filter(r => containsAny(r, ['security log', 'wevtutil', 'log clearing'])).length), trend: 'Observed', color: MON.red, data: timeline },
    { label: '🌐 13. Unauthorized Cloud Storage Uploads', val: shortNum(rows.filter(r => containsAny(r, ['drive', 'dropbox', 's3', 'cloud upload'])).length), trend: 'Observed', color: MON.purple, data: timeline },
    { label: '📤 14. External SFTP / FTP Data Transfers', val: shortNum(rows.filter(r => containsAny(r, ['sftp', 'ftp', 'scp'])).length), trend: 'Observed', color: MON.cyan, data: timeline },
    { label: '🪟 15. Windows Monitored User Endpoints', val: shortNum(osCounts.Windows || 0), trend: 'Windows EDR', color: MON.cyan, data: timeline },
    { label: '🐧 16. Linux Monitored Server Users', val: shortNum(osCounts.Linux || 0), trend: 'Linux Audit', color: MON.orange, data: timeline },
    { label: '🍎 17. macOS Monitored User Laptops', val: shortNum(osCounts.macOS || 0), trend: 'macOS Audit', color: MON.purple, data: timeline },
    { label: '🤖 18. UEBA Behavioral Anomaly Score', val: `${avgRisk}/100`, trend: 'Observed Average', color: MON.purple, data: timeline },
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
      status: sys.status || (sys.agentOk || sys.isOnline || sys.online ? 'reporting' : 'unknown'),
      monitor: hostEvents > 0,
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || sys.lastHeartbeat || null,
    });
  });
  const departmentRisk = [...rows.reduce((map, row) => {
    const department = insiderDept(row);
    if (department === 'Not reported') return map;
    const current = map.get(department) || { total: 0, count: 0 };
    current.total += insiderRiskScore(row);
    current.count += 1;
    map.set(department, current);
    return map;
  }, new Map()).entries()]
    .map(([department, value]) => [department, Math.round(value.total / value.count)])
    .sort((a, b) => b[1] - a[1])
    .slice(0, 4);
  const vectorCounts = topCounts(rows.filter(row => /exfil|outbound|upload|usb|removable|archive/.test(insiderSignalType(row))), insiderSignalType, 4);
  const vectorTotal = vectorCounts.reduce((sum, [, count]) => sum + count, 0);

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
          <CapabilityLogsPanel capabilityId={16}>
            <InsiderLogMonitor alerts={alerts} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={16} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <InsiderOverviewDashboard alerts={rows} total={totalRows} systems={backendSystems} />
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
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} managed endpoints · Capability 16 telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>UEBA Audit</span><span>Signals</span><span>Insider Threat</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.monitor ? 'Reporting' : 'No signals'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'No heartbeat'}</span>
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
                  {departmentRisk.map(([dept, score]) => (
                    <div key={dept} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text }}>{dept}</span>
                      <span style={{ color: score >= 80 ? MON.red : score >= 60 ? MON.orange : MON.green, fontWeight: 800 }}>Score: {score}/100</span>
                    </div>
                  ))}
                  {!departmentRisk.length && <span style={{ color: MON.muted }}>No department telemetry reported.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Top Data Exfiltration Vectors</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {vectorCounts.map(([vec, count], index) => (
                    <div key={vec} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{vec.replace(/\b\w/g, char => char.toUpperCase())}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.yellow, MON.purple][index], fontWeight: 800 }}>{vectorTotal ? Math.round(count / vectorTotal * 100) : 0}%</span>
                    </div>
                  ))}
                  {!vectorCounts.length && <span style={{ color: MON.muted }}>No exfiltration vectors reported.</span>}
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
      const r = await api.get(`/dashboard/alerts/edr?${q}`, { skipCache: true });
      const next = r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
    } catch {
      // Preserve the last successful snapshot while a live poll is retried.
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [capabilityId]);

  const loadSystems = useCallback(async () => {
    try {
      const r = await api.get('/system', { skipCache: true });
      setSystems(Array.isArray(r.data?.systems || r.data) ? (r.data?.systems || r.data) : []);
    } catch {
      // Preserve the last known endpoint state during transient failures.
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    loadSystems();
    const interval = setInterval(() => {
      loadAlerts(true);
      loadSystems();
    }, 15000);
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
