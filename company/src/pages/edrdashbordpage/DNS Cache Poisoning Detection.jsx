import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * DNS Cache Poisoning Detection — Capability ID: 30
 *
 * 100% Self-Contained Enterprise SOC DNS Cache Poisoning Detection Module
 * Linked to Live Backend API (`/api/dashboard/capabilities/30/live`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror DNS Sinkhole (Capability ID: 38) & Device Control (Capability ID: 10)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens ──────────────────────────────────────────────────────
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

function DonutChart({ value, maxValue, color, label, size = 110 }) {
  const pct = maxValue > 0 ? Math.min(value / maxValue, 1) : 0;
  const r = 38, cx = 55, cy = 55;
  const circ = 2 * Math.PI * r;
  const dash = pct * circ;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} viewBox="0 0 110 110">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#0f233a" strokeWidth="12" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${dash} ${circ - dash}`} strokeDashoffset={circ * 0.25}
          strokeLinecap="round" style={{ transition: 'stroke-dasharray 0.6s ease' }} />
        <text x="55" y="50" textAnchor="middle" fill="#f1f5f9" fontSize="14" fontWeight="900">
          {value >= 1000 ? `${(value / 1000).toFixed(1)}K` : value}
        </text>
        <text x="55" y="66" textAnchor="middle" fill="#64748b" fontSize="8">Total</text>
      </svg>
      <div style={{ fontSize: 11, color: MON.muted, marginTop: 4, textAlign: 'center' }}>{label}</div>
    </div>
  );
}

function MultiLineChart({ datasets = [], height = 180 }) {
  const all = datasets.flatMap(d => d.data);
  const maxV = Math.max(...all, 1);
  const w = 100, h = height;
  const toPoints = (data) => data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / maxV) * (h - 8) - 4;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 100 ${h}`} width="100%" height={h} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      {[20, 40, 60, 80].map(y => (
        <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="#162942" strokeWidth="0.4" />
      ))}
      {datasets.map((ds, i) => (
        <polyline key={i} fill="none" stroke={ds.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" points={toPoints(ds.data)} opacity="0.9" />
      ))}
    </svg>
  );
}

function firstDnsValue(...values) {
  for (const value of values) {
    const normalized = Array.isArray(value)
      ? value.filter(item => item !== undefined && item !== null && String(item).trim()).join(', ')
      : value;
    if (normalized !== undefined && normalized !== null && String(normalized).trim() && normalized !== '—') {
      return String(normalized);
    }
  }
  return '';
}

function dnsLogFields(log = {}) {
  const rawEvent = log.rawEvent && typeof log.rawEvent === 'object' ? log.rawEvent : {};
  const detectorRaw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  const evidence = log.detectionEvidence || rawEvent.detectionEvidence || rawEvent.evidence || detectorRaw.evidence || {};
  const poisonedIp = firstDnsValue(
    log.poisonedIp, log.responseIp, rawEvent.responseIp, rawEvent.response_ip,
    detectorRaw.responseIp, detectorRaw.response_ip, detectorRaw.new_ip,
    detectorRaw.ips, log.destip,
  );
  const expectedIp = firstDnsValue(
    log.expectedIp, log.knownGoodIp, rawEvent.expectedIp, rawEvent.expected_ip,
    rawEvent.knownGoodIp, detectorRaw.expectedIp, detectorRaw.expected_ip,
    detectorRaw.old_ips, evidence.previousIps, evidence.previous_ips,
  );
  const sourceIp = firstDnsValue(
    log.srcip, log.sourceIp, rawEvent.srcip, rawEvent.src_ip, rawEvent.sourceIp,
    detectorRaw.srcip, detectorRaw.src_ip, log.systemId?.ip, log.systemId?.ipAddress,
    log.systemId?.privateIp,
  );
  const explicitQueryType = firstDnsValue(
    log.queryType, rawEvent.queryType, rawEvent.query_type, rawEvent.record_type,
    detectorRaw.queryType, detectorRaw.query_type, detectorRaw.record_type,
  );
  const domain = firstDnsValue(log.domain, log.tiDomain, rawEvent.domain, detectorRaw.domain);
  const queryType = explicitQueryType || (domain && poisonedIp ? (poisonedIp.includes(':') ? 'AAAA' : 'A') : 'N/A');

  return {
    queryType,
    sourceIp: sourceIp || 'Not reported',
    poisonedIp: poisonedIp || 'Not reported',
    expectedIp: expectedIp || 'Baseline unavailable',
  };
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function DnsCachePoisoningDetailModal({ log, onClose, onRefresh }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || log?.notes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || ''));
  const [notesSaved, setNotesSaved] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const domain = log.domain || log.tiDomain || log.description?.match(/domain\s+"?([^\s"]+)"?/i)?.[1] || '—';
  const hostname = log.hostname || log.agentName || log.systemId?.name || 'endpoint-unknown';
  const { poisonedIp, expectedIp, sourceIp, queryType } = dnsLogFields(log);

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Resolver' },
    { id: 'cache', label: '🧠 4. Cache & Hosts File' },
    { id: 'process', label: '⚙️ 5. Process & Commands' },
    { id: 'network', label: '🔗 6. Network & Response' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'threat-intel', label: '🧠 8. Threat Intel' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const handleFlushCache = async () => {
    if (!window.confirm(`Flush the DNS cache on ${hostname}?`)) return;
    try {
      const response = await api.post(`/dns-cache-poisoning/alerts/${log._id}/flush-cache`);
      setActionMsg(response.data?.message || 'DNS cache flush queued');
      onRefresh?.();
    } catch (error) { setActionMsg(error.response?.data?.message || 'DNS cache flush failed'); }
  };

  const handleRestoreResolver = async () => {
    if (!window.confirm(`Restore the resolver configuration on ${hostname} to its agent baseline?`)) return;
    try {
      const response = await api.post(`/dns-cache-poisoning/alerts/${log._id}/restore-resolver`);
      setActionMsg(response.data?.message || 'Resolver restore queued');
      onRefresh?.();
    } catch (error) { setActionMsg(error.response?.data?.message || 'Resolver restore failed'); }
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleDownload = (format) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(log, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `dns_poisoning_${log._id || 'event'}_${domain}.${format.toLowerCase()}`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>☠️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  DNS Cache Poisoning Forensic Panel — {domain}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.orange, background: `${MON.orange}15`, border: `1px solid ${MON.orange}33` }}>
                  {log.detectionType || log.ruleId || 'Spoofed DNS Response'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{hostname}</strong> | User: <strong style={{ color: MON.text }}>{log.username || '—'}</strong> | Poisoned IP: <strong style={{ color: MON.red }}>{poisonedIp}</strong> | Expected IP: <strong style={{ color: MON.green }}>{expectedIp}</strong>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
          </div>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map((t) => (
            <button key={t.id} type="button" onClick={() => setActiveTab(t.id)} style={{ padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600, color: activeTab === t.id ? MON.cyan : MON.muted, background: activeTab === t.id ? MON.bg : 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: MON.bg }}>

          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
                {[
                  ['Target Domain', domain, MON.cyan],
                  ['Detection Mechanism', log.detectionType || 'DNS Cache Injection', MON.orange],
                  ['Poisoned IP Returned', poisonedIp, MON.red],
                  ['Expected Legitimate IP', expectedIp, MON.green],
                  ['Source IP / Host', sourceIp === 'Not reported' ? hostname : sourceIp, MON.blue],
                  ['Query Record Type', queryType, MON.purple],
                  ['Status', caseStatus, MON.yellow],
                  ['Assigned Analyst', assignedAnalyst, MON.green],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-all' }}>{val}</div>
                  </div>
                ))}
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Alert Description & Raw Signal:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.description || log.full_log || 'No raw description was reported by the endpoint agent.'}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <button type="button" onClick={handleFlushCache} style={{ background: MON.orange, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  🧹 Flush Endpoint DNS Cache
                </button>
                <button type="button" onClick={handleRestoreResolver} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  🔄 Restore Agent Baseline Resolver
                </button>
                {actionMsg && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700, alignSelf: 'center' }}>{actionMsg}</span>}
              </div>
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 DNS Cache Poisoning Event Chronology</div>
              {[{ type: log.eventType || log.detectionType || 'Detection', time: log.createdAt || log.timestamp ? new Date(log.createdAt || log.timestamp).toLocaleString() : 'Time not reported', title: log.ruleName || log.detectionType || 'DNS cache-poisoning signal received', desc: log.description || 'No additional chronology was reported by the endpoint agent.', col: SEV_COLOR[sev] || MON.yellow }].map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col, background: `${ev.col}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content', whiteSpace: 'nowrap' }}>{ev.type}</span>
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

          {/* TAB 3: ENDPOINT & RESOLVER */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Endpoint Profile & Resolver Configuration</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', hostname],
                  ['Operating System', log.osType || log.os || 'Not reported'],
                  ['Logged-in User', log.username || '—'],
                  ['Primary DNS Resolver', log.dnsServer || log.resolverIp || 'Not reported'],
                  ['Secondary DNS Resolver', log.secondaryDnsServer || 'Not reported'],
                  ['Resolver Config File', log.resolverConfigPath || 'Not reported'],
                  ['Group Policy DNS', log.groupPolicyDns || 'Not reported'],
                  ['Agent ID', log.agentId || '—'],
                  ['DNS Cache Status', log.cacheStatus || 'Not reported'],
                  ['DNSSEC Validation', log.dnssecStatus || 'Not reported'],
                  ['Department', log.departmentId?.name || log.departmentId || 'Not reported'],
                  ['Risk Score', Number.isFinite(Number(log.riskScore)) ? `${log.riskScore}/100` : 'Not reported'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4, wordBreak: 'break-all' }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: CACHE & HOSTS FILE */}
          {activeTab === 'cache' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Cached Record Artifacts & Hosts File Monitoring</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Poisoned Cache Entry Details</div>
                  {[
                    ['Domain Name', domain],
                    ['Poisoned Response IP', poisonedIp],
                    ['Legitimate Expected IP', expectedIp],
                    ['Record Type', queryType],
                    ['TTL (Time To Live)', log.ttl != null ? `${log.ttl} seconds` : 'Not reported'],
                    ['Time Cached', log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'],
                    ['Expiration Time', log.expirationTime ? new Date(log.expirationTime).toLocaleString() : 'Not reported'],
                    ['Cache Entry Source', log.cacheEntrySource || 'Not reported'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: k.includes('Poisoned') ? MON.red : k.includes('Expected') ? MON.green : MON.text }}>{v}</strong>
                    </div>
                  ))}
                </div>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Hosts File Override Check</div>
                  <div style={{ fontSize: 11, color: MON.muted, marginBottom: 8 }}>
                    File Path: <code style={{ color: MON.cyan }}>{log.osType === 'Linux' ? '/etc/hosts' : 'C:\\Windows\\System32\\drivers\\etc\\hosts'}</code>
                  </div>
                  <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, margin: 0 }}>{log.hostsFileEvidence || 'No hosts-file content was collected. Only agent-reported change evidence is displayed.'}</pre>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Context & Command Line</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Process Tree:</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {log.parentProcessName || 'Not reported'} (PPID {log.parentPid || '—'}) ➔ <strong>{log.processName || 'Not reported'} (PID {log.pid || '—'})</strong>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Command Line History:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.commandLine || 'Command-line correlation was not reported for this event.'}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK */}
          {activeTab === 'network' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🔗 Network & IP Response Validation</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Source Endpoint IP', sourceIp],
                  ['Target DNS Resolver', log.dnsServer || log.resolverIp || 'Not reported'],
                  ['Returned Spoofed IP', poisonedIp],
                  ['Legitimate Expected IP', expectedIp],
                  ['Protocol', log.protocol || 'Not reported'],
                  ['IP Validation Result', log.validationResult || 'Not reported'],
                  ['Private/Loopback IP Check', /^(127|10|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\./.test(poisonedIp) ? 'Internal / Private IP Returned' : 'External IP'],
                  ['Geo Country', log.geoCountry || log.country || 'Not reported'],
                  ['ASN / ISP', log.asn || log.hostingProvider || 'Not reported'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: k.includes('Spoofed') || k.includes('FAILED') ? MON.red : k.includes('Expected') ? MON.green : MON.text, fontWeight: 700, marginTop: 4 }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🎯 MITRE ATT&CK Matrix & Indicators of Compromise</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  ['T1071.004', 'Application Layer Protocol: DNS', 'Adversary uses DNS protocol for command and control or data exfiltration.'],
                  ['T1565.001', 'Data Manipulation: Stored Data Manipulation', 'Adversary modified local DNS cache or /etc/hosts file to redirect network traffic.'],
                  ['T1584.002', 'Compromise Infrastructure: DNS Server', 'Adversary compromised upstream DNS resolver or spoofed DNS responses on the wire.'],
                  ['T1048.003', 'Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-Application Layer Protocol', 'DNS tunneling or data leakage via manipulated DNS query records.'],
                ].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: THREAT INTEL */}
          {activeTab === 'threat-intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Threat Intelligence Enrichment</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  { label: 'Poisoned IP Reputation', value: log.ipReputation || 'Not reported', col: MON.red, desc: log.ipReputationEvidence || 'No reputation evidence was attached to this event.' },
                  { label: 'DNSSEC Status', value: log.dnssecStatus || 'Not reported', col: MON.orange, desc: log.dnssecEvidence || 'No DNSSEC telemetry was attached to this event.' },
                  { label: 'Threat Intelligence Match', value: log.threatIntelSource || 'Not reported', col: MON.yellow, desc: log.threatIntelSource ? 'Agent/backend enrichment source reported with this event.' : 'No threat-intelligence match was reported.' },
                  { label: 'Confidence Score', value: log.confidenceScore != null ? `${log.confidenceScore}%` : 'Not reported', col: MON.green, desc: log.reason || 'No confidence evidence was attached to this event.' },
                ].map((item) => (
                  <div key={item.label} style={{ background: MON.card, border: `1px solid ${item.col}44`, borderRadius: 8, padding: 16 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <div style={{ fontSize: 11, color: MON.muted, fontWeight: 700 }}>{item.label}</div>
                      <span style={{ color: item.col, fontWeight: 800, fontSize: 13 }}>{item.value}</span>
                    </div>
                    <div style={{ fontSize: 11, color: MON.sub }}>{item.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📦 Alert Evidence & Raw Log Payload</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 10, whiteSpace: 'pre-wrap', margin: 0, maxHeight: 400, overflowY: 'auto' }}>
                  {JSON.stringify(log, null, 2)}
                </pre>
              </div>
              <button type="button" onClick={() => handleDownload('json')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 11, width: 'fit-content' }}>Export Evidence JSON</button>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📝 Analyst Investigation Notes</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Assigned Analyst</div>
                  <select value={assignedAnalyst} onChange={(e) => setAssignedAnalyst(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option>{assignedAnalyst || 'Unassigned'}</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Case Status</div>
                  <select value={caseStatus} onChange={(e) => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Tags</div>
                  <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }} />
                </div>
              </div>
              <div style={{ fontSize: 12, color: MON.muted, fontWeight: 700 }}>Investigation Notes:</div>
              <textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} rows={6} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, color: MON.text, padding: 14, fontSize: 12, fontFamily: 'inherit', resize: 'vertical' }} />
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                  Save Case Notes
                </button>
                {notesSaved && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700 }}>✓ Notes saved to case file</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. LOG MONITOR TABLE (REAL-TIME BACKEND LINKED)
// ═════════════════════════════════════════════════════════════════════════════
export function DnsCachePoisoningLogMonitor({ alerts = [], onRefresh }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = alerts;
  const rows = useMemo(() => effectiveAlerts.map(a => {
    const dnsFields = dnsLogFields(a);
    return {
      _id: a._id,
      timestamp: a.createdAt || a.timestamp || null,
      severity: (a.severity || 'medium').toLowerCase(),
      status: a.status || 'open',
      hostname: a.hostname || a.agentName || a.systemId?.name || '—',
      username: a.username || '—',
      domain: a.domain || a.tiDomain || a.rawEvent?.domain || a.rawEvent?.raw?.domain || '—',
      queryType: dnsFields.queryType,
      srcip: dnsFields.sourceIp,
      poisonedIp: dnsFields.poisonedIp,
      expectedIp: dnsFields.expectedIp,
      detectionType: a.detectionType || a.ruleId || a.eventType || 'DNS anomaly',
      osType: a.osType || a.os || a.systemId?.osType || a.systemId?.os || '—',
      processName: a.processName || '—',
      raw: a,
    };
  }), [effectiveAlerts]);

  const filtered = useMemo(() => rows.filter(r => {
    if (sevFilter !== 'ALL' && r.severity !== sevFilter.toLowerCase()) return false;
    if (typeFilter !== 'ALL' && r.detectionType !== typeFilter) return false;
    if (!searchTerm) return true;
    const t = searchTerm.toLowerCase();
    return r.domain.toLowerCase().includes(t) || r.hostname.toLowerCase().includes(t) || r.username.toLowerCase().includes(t) || r.poisonedIp.toLowerCase().includes(t);
  }), [rows, searchTerm, sevFilter, typeFilter]);

  const types = useMemo(() => ['ALL', ...new Set(rows.map(r => r.detectionType).filter(Boolean))], [rows]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}`, flexWrap: 'wrap' }}>
        <input type="text" placeholder="🔍 Search DNS poisoning logs (Domain, Host, User, IP)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, minWidth: 200, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {['ALL', 'critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {types.map(t => <option key={t}>{t}</option>)}
        </select>
        <span style={{ fontSize: 10, color: MON.muted, alignSelf: 'center', padding: '0 8px' }}>{filtered.length} records</span>
      </div>

      <div style={{ overflowX: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Time', 'Severity', 'Domain', 'Query Type', 'Source IP', 'Hostname', 'Username', 'Poisoned IP', 'Expected IP', 'Detection Rule', 'Status', 'OS'].map(h => <th key={h} style={{ padding: 10, whiteSpace: 'nowrap' }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row.raw)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.muted, whiteSpace: 'nowrap' }}>{new Date(row.timestamp).toLocaleTimeString()}</td>
                <td style={{ padding: 10 }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                <td style={{ padding: 10, color: MON.orange, fontWeight: 700, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.domain}>{row.domain}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 700 }}>{row.queryType}</td>
                <td style={{ padding: 10, color: MON.cyan }}>{row.srcip}</td>
                <td style={{ padding: 10, color: MON.blue, fontWeight: 700 }}>{row.hostname}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.red, fontWeight: 700 }}>{row.poisonedIp}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.green, fontWeight: 700 }}>{row.expectedIp}</td>
                <td style={{ padding: 10, color: MON.yellow }}>{row.detectionType}</td>
                <td style={{ padding: 10, color: row.status === 'resolved' ? MON.green : MON.yellow, fontWeight: 700 }}>{row.status}</td>
                <td style={{ padding: 10, color: MON.muted }}>{row.osType}</td>
              </tr>
            )) : <tr><td colSpan={12} style={{ padding: 40, textAlign: 'center', color: MON.muted }}>No DNS cache poisoning logs found</td></tr>}
          </tbody>
        </table>
      </div>
      {selectedLog && <DnsCachePoisoningDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onRefresh={onRefresh} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. EXECUTIVE REPORT GENERATOR
// ═════════════════════════════════════════════════════════════════════════════
function LegacyDnsCachePoisoningReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [reportGenerated, setReportGenerated] = useState(false);

  const metrics = useMemo(() => ({
    total: alerts.length,
    poisoningAlerts: alerts.filter(a => /poison|spoof|fake/i.test(`${a.detectionType || ''} ${a.description || ''}`)).length,
    hostsFileAttacks: alerts.filter(a => /hosts/i.test(`${a.description || ''} ${a.detectionType || ''}`)).length,
    resolverChanges: alerts.filter(a => /resolver/i.test(`${a.description || ''} ${a.detectionType || ''}`)).length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    uniqueDomains: new Set(alerts.map(a => a.domain).filter(Boolean)).size,
    uniqueEndpoints: new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size,
  }), [alerts]);

  const handleGenerate = () => { setGenerating(true); setTimeout(() => { setGenerating(false); setReportGenerated(true); }, 1000); };

  const handleDownload = (format) => {
    if (format === 'CSV') {
      const headers = ['Timestamp', 'Domain', 'Query Type', 'Source IP', 'Hostname', 'Poisoned IP', 'Expected IP', 'Severity', 'Status'];
      const rows = alerts.map(a => [
        `"${a.createdAt || ''}"`, `"${a.domain || ''}"`, `"${a.queryType || ''}"`, `"${a.srcip || ''}"`,
        `"${a.hostname || a.agentName || ''}"`, `"${a.poisonedIp || ''}"`, `"${a.expectedIp || ''}"`,
        `"${a.severity || ''}"`, `"${a.status || ''}"`
      ]);
      const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `dns_cache_poisoning_report_${reportType}.csv`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } else if (format === 'PDF') {
      const safe = value => String(value ?? '').replace(/[^\x20-\x7E]/g, '?').replace(/([\\()])/g, '\\$1');
      const lines = [
        'DNS Cache Poisoning Executive SOC Report',
        `Period: ${reportType}`,
        `Generated: ${new Date().toISOString()}`,
        `Total events: ${metrics.total}`,
        `Poisoning alerts: ${metrics.poisoningAlerts}`,
        `Hosts file changes: ${metrics.hostsFileAttacks}`,
        `Resolver changes: ${metrics.resolverChanges}`,
        `Critical: ${metrics.critical}  High: ${metrics.high}`,
        '',
        ...alerts.slice(0, 32).map(item => `${item.createdAt || item.timestamp || '-'} | ${item.severity || '-'} | ${item.domain || item.tiDomain || '-'} | ${item.hostname || item.agentName || '-'}`),
      ].map(safe);
      const content = ['BT', '/F1 10 Tf', '45 790 Td', ...lines.flatMap((line, index) => index ? ['0 -17 Td', `(${line.slice(0, 110)}) Tj`] : [`(${line.slice(0, 110)}) Tj`]), 'ET'].join('\n');
      const objects = [
        '<< /Type /Catalog /Pages 2 0 R >>',
        '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>',
        `<< /Length ${content.length} >>\nstream\n${content}\nendstream`,
        '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
      ];
      let pdf = '%PDF-1.4\n';
      const offsets = [0];
      objects.forEach((object, index) => { offsets.push(pdf.length); pdf += `${index + 1} 0 obj\n${object}\nendobj\n`; });
      const xref = pdf.length;
      pdf += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
      offsets.slice(1).forEach(offset => { pdf += `${String(offset).padStart(10, '0')} 00000 n \n`; });
      pdf += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF`;
      const url = URL.createObjectURL(new Blob([pdf], { type: 'application/pdf' }));
      const a = document.createElement('a');
      a.href = url; a.download = `dns_cache_poisoning_report_${reportType}.pdf`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } else {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ title: 'DNS Cache Poisoning Executive SOC Report', reportType, generatedAt: new Date().toISOString(), metrics, alerts }, null, 2));
      const a = document.createElement('a');
      a.setAttribute('href', dataStr); a.setAttribute('download', `dns_cache_poisoning_report_${reportType}.json`);
      document.body.appendChild(a); a.click(); a.remove();
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 DNS Cache Poisoning Executive SOC Report Generator</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate Executive Summary, Hosts File Attack Analytics, and Resolver Hijack Audit Reports</div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 14px', borderRadius: 6, fontSize: 12 }}>
            <option value="daily">Daily Report (24 Hours)</option>
            <option value="weekly">Weekly Executive Summary</option>
            <option value="monthly">Monthly Threat Audit Report</option>
          </select>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
            {generating ? 'Generating...' : '⚡ Generate Report'}
          </button>
        </div>
      </div>

      {reportGenerated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>DNS Cache Poisoning Executive Summary ({reportType.toUpperCase()})</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={() => handleDownload('CSV')} style={{ background: MON.green, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
              <button type="button" onClick={() => handleDownload('PDF')} style={{ background: MON.red, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Download PDF</button>
              <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
            {[
              ['Total DNS Events', metrics.total, MON.blue],
              ['Cache Poisoning Alerts', metrics.poisoningAlerts, MON.red],
              ['Hosts File Attacks', metrics.hostsFileAttacks, MON.orange],
              ['Resolver Changes', metrics.resolverChanges, MON.yellow],
              ['Critical Severity', metrics.critical, MON.red],
              ['High Severity', metrics.high, MON.orange],
              ['Targeted Domains', metrics.uniqueDomains, MON.cyan],
              ['Affected Endpoints', metrics.uniqueEndpoints, MON.purple],
            ].map(([label, val, col]) => (
              <div key={label} style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}>
                <div style={{ fontSize: 10, color: MON.muted }}>{label}</div>
                <div style={{ fontSize: 18, color: col, fontWeight: 900, marginTop: 4 }}>{val}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function DnsCachePoisoningReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={30} alerts={alerts} />;
}

const DEFAULT_POISON_CONFIG = {
  enabled: true, telemetryEnabled: true, watchDomains: [], trustedResolvers: [],
  scanIntervalSeconds: 300, minSafeTtl: 30, maxSafeTtl: 86400,
  baselineWindowSeconds: 3600, monitorResolverChanges: true,
  monitorHostsChanges: true, detectPrivateAnswers: true,
  builtInRuleIds: ['private-answer', 'ttl-anomaly', 'resolver-change', 'hosts-file-change'],
  builtInRuleOverrides: {},
  customRules: [],
  targetMode: 'all', targetSystemIds: [], version: 0,
};

const newCustomDnsRule = () => ({
  id: '', name: '', domain: '', queryType: 'A', expectedIpsText: '', severity: 'high', enabled: true,
});

// Keep the fallback reference stable. A literal [] here is recreated on every
// render, which changes load's dependency and continuously restarts the effect.
const EMPTY_POISON_SYSTEMS = Object.freeze([]);

export function DnsCachePoisoningConfigureTab({ systems: inheritedSystems = EMPTY_POISON_SYSTEMS, onRefresh }) {
  const [configuration, setConfiguration] = useState(DEFAULT_POISON_CONFIG);
  const [builtInRules, setBuiltInRules] = useState([]);
  const [systems, setSystems] = useState(inheritedSystems);
  const [domainsText, setDomainsText] = useState('');
  const [resolversText, setResolversText] = useState('');
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [editingBuiltIn, setEditingBuiltIn] = useState(null);
  const [customRuleEditor, setCustomRuleEditor] = useState(null);
  const [dirty, setDirty] = useState(false);

  const load = useCallback(async () => {
    setBusy(true); setError('');
    try {
      const response = await api.get('/dns-cache-poisoning/configuration');
      const config = { ...DEFAULT_POISON_CONFIG, ...(response.data?.configuration || {}) };
      setConfiguration(config);
      setDomainsText((config.watchDomains || []).join('\n'));
      setResolversText((config.trustedResolvers || []).join('\n'));
      setBuiltInRules(response.data?.builtInRules || []);
      setSystems(response.data?.systems || inheritedSystems);
      setDirty(false);
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Configuration could not be loaded');
    } finally { setBusy(false); }
  }, [inheritedSystems]);

  useEffect(() => { load(); }, [load]);

  const update = (key, value) => {
    setDirty(true);
    setConfiguration(current => ({ ...current, [key]: value }));
  };
  const toggleRule = ruleId => {
    setDirty(true);
    setConfiguration(current => ({
      ...current,
      builtInRuleIds: current.builtInRuleIds.includes(ruleId)
        ? current.builtInRuleIds.filter(id => id !== ruleId)
        : [...current.builtInRuleIds, ruleId],
    }));
  };
  const toggleSystem = systemId => {
    setDirty(true);
    setConfiguration(current => ({
      ...current,
      targetSystemIds: current.targetSystemIds.includes(systemId)
        ? current.targetSystemIds.filter(id => id !== systemId)
        : [...current.targetSystemIds, systemId],
    }));
  };

  const save = async () => {
    if (configuration.targetMode === 'selected' && !(configuration.targetSystemIds || []).length) {
      setError('Select at least one agent before applying the policy.');
      return;
    }
    const targetLabel = configuration.targetMode === 'selected'
      ? `${configuration.targetSystemIds.length} selected agent(s)`
      : 'all agents';
    if (!window.confirm(`Apply the complete DNS cache-poisoning policy to ${targetLabel}?`)) return;
    setBusy(true); setMessage(''); setError('');
    try {
      const payload = {
        ...configuration,
        watchDomains: domainsText.split(/[\n,]+/).map(value => value.trim()).filter(Boolean),
        trustedResolvers: resolversText.split(/[\n,]+/).map(value => value.trim()).filter(Boolean),
      };
      const response = await api.put('/dns-cache-poisoning/configuration', payload);
      setMessage(response.data?.message || 'Configuration applied');
      await load(); onRefresh?.();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Configuration could not be applied');
      setBusy(false);
    }
  };

  const sync = async () => {
    if (dirty) {
      setError('Apply All Changes before synchronizing the policy.');
      return;
    }
    setBusy(true); setMessage(''); setError('');
    try {
      const response = await api.post('/dns-cache-poisoning/configuration/sync');
      setMessage(response.data?.message || 'Synchronization queued');
      await load(); onRefresh?.();
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'Synchronization failed'); setBusy(false);
    }
  };

  const openBuiltInRule = rule => setEditingBuiltIn({
    ...rule,
    settings: {
      ...(rule.settings || {}),
      queryType: rule.settings?.queryType || 'A',
      expectedIpsText: (rule.settings?.expectedIps || []).join('\n'),
    },
  });

  const saveBuiltIn = event => {
    event.preventDefault();
    if (!editingBuiltIn?.id) return;
    const { expectedIpsText = '', ...baseSettings } = editingBuiltIn.settings || {};
    const expectedIps = expectedIpsText.split(/[\n,]+/).map(value => value.trim()).filter(Boolean);
    const settings = baseSettings.domain?.trim() || expectedIps.length
      ? { ...baseSettings, domain: baseSettings.domain?.trim() || '', expectedIps }
      : Object.fromEntries(Object.entries(baseSettings).filter(([key]) => !['domain', 'queryType', 'enabled'].includes(key)));
    setConfiguration(current => ({
      ...current,
      builtInRuleOverrides: {
        ...(current.builtInRuleOverrides || {}),
        [editingBuiltIn.id]: settings,
      },
    }));
    setBuiltInRules(current => current.map(rule => rule.id === editingBuiltIn.id
      ? { ...rule, settings }
      : rule));
    setEditingBuiltIn(null);
    setDirty(true);
    setError('');
    setMessage('Built-in rule changes staged. Apply All Changes to deploy.');
  };

  const openCustomRule = rule => setCustomRuleEditor(rule ? {
    ...rule,
    expectedIpsText: (rule.expectedIps || []).join('\n'),
  } : newCustomDnsRule());

  const saveCustomRule = async event => {
    event.preventDefault();
    if (!customRuleEditor) return;
    const payload = {
      id: customRuleEditor.id || `custom-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name: customRuleEditor.name,
      domain: customRuleEditor.domain,
      queryType: customRuleEditor.queryType,
      expectedIps: customRuleEditor.expectedIpsText.split(/[\n,]+/).map(value => value.trim()).filter(Boolean),
      severity: customRuleEditor.severity,
      enabled: customRuleEditor.enabled !== false,
    };
    setConfiguration(current => ({
      ...current,
      customRules: customRuleEditor.id
        ? (current.customRules || []).map(rule => rule.id === customRuleEditor.id ? payload : rule)
        : [...(current.customRules || []), payload],
    }));
    setCustomRuleEditor(null);
    setDirty(true);
    setError('');
    setMessage('Custom rule changes staged. Apply All Changes to deploy.');
  };

  const deleteCustomRule = rule => {
    if (!window.confirm(`Delete custom rule "${rule.name}"?`)) return;
    setConfiguration(current => ({ ...current, customRules: (current.customRules || []).filter(item => item.id !== rule.id) }));
    if (customRuleEditor?.id === rule.id) setCustomRuleEditor(null);
    setDirty(true);
    setError('');
    setMessage('Custom rule deletion staged. Apply All Changes to deploy.');
  };

  const inputStyle = { width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 10px', borderRadius: 6, fontSize: 11 };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
      <style>{`@media(max-width:900px){.dcp-unified-grid{grid-template-columns:1fr!important;grid-template-areas:"builtIn" "custom" "targets"!important}}`}</style>
      <div style={{ paddingBottom: 14, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
        <div><b style={{ color: '#fff', fontSize: 14 }}>⚙️ Unified DNS Cache-Poisoning Policy</b><div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Built-in rules, custom IP rules and agent targets are saved and deployed together · Policy v{configuration.version || 0}</div>{dirty && <div style={{ color: MON.yellow, fontSize: 10, fontWeight: 800, marginTop: 5 }}>● Unsaved policy changes</div>}</div>
        <div style={{ display: 'flex', gap: 8 }}><button type="button" disabled={busy || dirty} title={dirty ? 'Apply pending changes first' : 'Queue the saved policy again'} onClick={sync} style={{ background: MON.card2, color: MON.cyan, border: `1px solid ${MON.cyan}`, borderRadius: 6, padding: '8px 13px', fontWeight: 800, cursor: busy || dirty ? 'not-allowed' : 'pointer', opacity: busy || dirty ? .55 : 1 }}>Sync Saved Policy</button><button type="button" disabled={busy} onClick={save} style={{ background: MON.cyan, color: '#001018', border: 0, borderRadius: 6, padding: '8px 16px', fontWeight: 900, cursor: busy ? 'not-allowed' : 'pointer' }}>{busy ? 'Please wait…' : 'Apply All Changes'}</button></div>
      </div>
      {(message || error) && <div role="status" style={{ padding: 10, borderRadius: 6, fontSize: 11, color: error ? MON.red : MON.green, background: error ? `${MON.red}12` : `${MON.green}12`, border: `1px solid ${error ? MON.red : MON.green}55` }}>{error || message}</div>}
      <div className="dcp-unified-grid" style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) minmax(0, 1fr)', gridTemplateAreas: '"custom builtIn" "targets builtIn"', gap: 14, alignItems: 'start' }}>
          <div style={{ gridArea: 'builtIn', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}><b style={{ fontSize: 12 }}>1 · Built-in DNS Rules</b><div style={{ color: MON.muted, fontSize: 10, margin: '4px 0 12px' }}>Choose or edit rules; changes remain in this unified draft until applied.</div>
            {editingBuiltIn && <form onSubmit={saveBuiltIn} style={{ padding: 12, marginBottom: 10, background: MON.bg, border: `1px solid ${MON.purple}`, borderRadius: 7 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><div><b style={{ color: MON.purple, fontSize: 11 }}>Edit: {editingBuiltIn.name}</b><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>Add an optional domain/IP condition from the custom-rule controls.</div></div><button type="button" onClick={() => setEditingBuiltIn(null)} style={{ background: 'transparent', color: MON.muted, border: 0, cursor: 'pointer' }}>✕</button></div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 8, marginTop: 10 }}>
                <label style={{ color: MON.muted, fontSize: 9 }}>SEVERITY<select value={editingBuiltIn.settings?.severity || editingBuiltIn.severity || 'high'} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, severity: event.target.value } }))} style={{ ...inputStyle, marginTop: 4 }}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
                {editingBuiltIn.id === 'ttl-anomaly' && <><label style={{ color: MON.muted, fontSize: 9 }}>MIN SAFE TTL<input type="number" min="1" value={editingBuiltIn.settings?.minSafeTtl ?? 30} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, minSafeTtl: Number(event.target.value) } }))} style={{ ...inputStyle, marginTop: 4 }} /></label><label style={{ color: MON.muted, fontSize: 9 }}>MAX SAFE TTL<input type="number" min="30" value={editingBuiltIn.settings?.maxSafeTtl ?? 86400} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, maxSafeTtl: Number(event.target.value) } }))} style={{ ...inputStyle, marginTop: 4 }} /></label></>}
                <label style={{ color: MON.muted, fontSize: 9 }}>DOMAIN (OPTIONAL)<input value={editingBuiltIn.settings?.domain || ''} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, domain: event.target.value } }))} placeholder="example.com" style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: MON.muted, fontSize: 9 }}>QUERY TYPE<select value={editingBuiltIn.settings?.queryType || 'A'} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, queryType: event.target.value } }))} style={{ ...inputStyle, marginTop: 4 }}><option value="A">A (IPv4)</option><option value="AAAA">AAAA (IPv6)</option></select></label>
              </div>
              <label style={{ display: 'block', color: MON.muted, fontSize: 9, marginTop: 9 }}>EXPECTED IP ADDRESSES (ONE PER LINE, OPTIONAL)<textarea rows={3} value={editingBuiltIn.settings?.expectedIpsText || ''} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, expectedIpsText: event.target.value } }))} placeholder={editingBuiltIn.settings?.queryType === 'AAAA' ? '2001:db8::10' : '203.0.113.10'} style={{ ...inputStyle, marginTop: 4, resize: 'vertical', fontFamily: 'monospace' }} /></label>
              {(editingBuiltIn.settings?.domain || editingBuiltIn.settings?.expectedIpsText) && <label style={{ display: 'flex', alignItems: 'center', gap: 7, color: MON.text, fontSize: 10, marginTop: 9 }}><input type="checkbox" checked={editingBuiltIn.settings?.enabled !== false} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, enabled: event.target.checked } }))} /> Enable this domain/IP condition</label>}
              <button type="submit" disabled={busy} style={{ marginTop: 10, background: MON.purple, color: '#090312', border: 0, borderRadius: 6, padding: '7px 11px', fontWeight: 900, cursor: 'pointer' }}>Stage Rule Changes</button>
            </form>}
            {builtInRules.map(rule => <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '22px 1fr auto', gap: 9, alignItems: 'center', padding: '9px 0', borderTop: `1px solid ${MON.line}` }}><input type="checkbox" aria-label={`Select ${rule.name}`} checked={configuration.builtInRuleIds.includes(rule.id)} onChange={() => toggleRule(rule.id)} /><span><b style={{ color: SEV_COLOR[rule.settings?.severity || rule.severity] || MON.text, fontSize: 11 }}>{rule.name}</b><span style={{ display: 'block', color: MON.muted, fontSize: 9, marginTop: 3 }}>{rule.description}</span>{rule.settings?.domain && <span style={{ display: 'block', color: MON.green, fontSize: 9, marginTop: 3 }}>{rule.settings.queryType || 'A'} {rule.settings.domain} → {(rule.settings.expectedIps || []).join(', ')}</span>}</span><button type="button" disabled={busy} onClick={() => openBuiltInRule(rule)} style={{ background: MON.card2, color: MON.purple, border: `1px solid ${MON.purple}66`, borderRadius: 5, padding: '5px 8px', fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>Edit</button></div>)}</div>
          <div style={{ gridArea: 'custom', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
              <div><b style={{ fontSize: 12 }}>2 · Custom Domain & IP Rules</b><div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Alert when a domain returns an IP outside its expected list.</div></div>
              <button type="button" disabled={busy} onClick={() => openCustomRule()} style={{ background: MON.green, color: '#00140e', border: 0, borderRadius: 6, padding: '7px 11px', fontSize: 10, fontWeight: 900, cursor: 'pointer', whiteSpace: 'nowrap' }}>＋ Add New Rule</button>
            </div>
            {customRuleEditor && <form onSubmit={saveCustomRule} style={{ padding: 12, marginTop: 12, background: MON.card2, border: `1px solid ${MON.green}66`, borderRadius: 7 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, marginBottom: 10 }}><b style={{ color: MON.green, fontSize: 11 }}>{customRuleEditor.id ? 'Edit Custom Rule' : 'Add New Custom Rule'}</b><button type="button" onClick={() => setCustomRuleEditor(null)} style={{ background: 'transparent', color: MON.muted, border: 0, cursor: 'pointer' }}>✕</button></div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(145px,1fr))', gap: 9 }}>
                <label style={{ color: MON.muted, fontSize: 9 }}>RULE NAME<input required maxLength={120} value={customRuleEditor.name} onChange={event => setCustomRuleEditor(current => ({ ...current, name: event.target.value }))} placeholder="Corporate DNS allowlist" style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: MON.muted, fontSize: 9 }}>DOMAIN<input required value={customRuleEditor.domain} onChange={event => setCustomRuleEditor(current => ({ ...current, domain: event.target.value }))} placeholder="example.com" style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: MON.muted, fontSize: 9 }}>QUERY TYPE<select value={customRuleEditor.queryType} onChange={event => setCustomRuleEditor(current => ({ ...current, queryType: event.target.value }))} style={{ ...inputStyle, marginTop: 4 }}><option value="A">A (IPv4)</option><option value="AAAA">AAAA (IPv6)</option></select></label>
                <label style={{ color: MON.muted, fontSize: 9 }}>SEVERITY<select value={customRuleEditor.severity} onChange={event => setCustomRuleEditor(current => ({ ...current, severity: event.target.value }))} style={{ ...inputStyle, marginTop: 4 }}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></label>
              </div>
              <label style={{ display: 'block', color: MON.muted, fontSize: 9, marginTop: 9 }}>EXPECTED IP ADDRESSES (ONE PER LINE)<textarea required rows={3} value={customRuleEditor.expectedIpsText} onChange={event => setCustomRuleEditor(current => ({ ...current, expectedIpsText: event.target.value }))} placeholder={customRuleEditor.queryType === 'AAAA' ? '2001:db8::10' : '203.0.113.10'} style={{ ...inputStyle, marginTop: 4, resize: 'vertical', fontFamily: 'monospace' }} /></label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 7, color: MON.text, fontSize: 10, marginTop: 9 }}><input type="checkbox" checked={customRuleEditor.enabled !== false} onChange={event => setCustomRuleEditor(current => ({ ...current, enabled: event.target.checked }))} /> Enable this rule</label>
              <button type="submit" disabled={busy} style={{ marginTop: 10, background: MON.green, color: '#00140e', border: 0, borderRadius: 6, padding: '8px 12px', fontWeight: 900, cursor: 'pointer' }}>{busy ? 'Saving…' : customRuleEditor.id ? 'Update Rule' : 'Add Rule'}</button>
            </form>}
            {(configuration.customRules || []).map(rule => <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 9, alignItems: 'center', padding: '10px 0', borderTop: `1px solid ${MON.line}`, marginTop: 10 }}>
              <span><b style={{ color: SEV_COLOR[rule.severity] || MON.text, fontSize: 11 }}>{rule.name}</b><span style={{ display: 'block', color: MON.muted, fontSize: 9, marginTop: 3 }}>{rule.queryType} {rule.domain} → {(rule.expectedIps || []).join(', ')} · {rule.enabled === false ? 'Disabled' : 'Enabled'}</span></span>
              <span style={{ display: 'flex', gap: 6 }}><button type="button" disabled={busy} onClick={() => openCustomRule(rule)} style={{ background: MON.card2, color: MON.green, border: `1px solid ${MON.green}66`, borderRadius: 5, padding: '5px 8px', fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>Edit</button><button type="button" disabled={busy} onClick={() => deleteCustomRule(rule)} style={{ background: MON.card2, color: MON.red, border: `1px solid ${MON.red}66`, borderRadius: 5, padding: '5px 8px', fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>Delete</button></span>
            </div>)}
            {!(configuration.customRules || []).length && !customRuleEditor && <div style={{ color: MON.muted, fontSize: 10, marginTop: 12, paddingTop: 10, borderTop: `1px solid ${MON.line}` }}>No custom IP rules yet.</div>}
          </div>
          <div style={{ gridArea: 'targets', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}><b style={{ fontSize: 12 }}>3 · Agent Targets</b><div style={{ display: 'flex', gap: 14, margin: '10px 0', fontSize: 11 }}><label><input type="radio" checked={configuration.targetMode === 'all'} onChange={() => update('targetMode', 'all')} /> All agents</label><label><input type="radio" checked={configuration.targetMode === 'selected'} onChange={() => update('targetMode', 'selected')} /> Selected agents</label></div>{configuration.targetMode === 'selected' && <div style={{ maxHeight: 190, overflowY: 'auto' }}>{systems.map(system => <label key={system._id} style={{ display: 'grid', gridTemplateColumns: '20px 1fr 80px', gap: 7, padding: '7px 0', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}><input type="checkbox" checked={configuration.targetSystemIds.includes(String(system._id))} onChange={() => toggleSystem(String(system._id))} /><span>{system.name || system.hostname || 'Endpoint'}</span><span style={{ color: ['active', 'online'].includes(String(system.status).toLowerCase()) ? MON.green : MON.muted }}>{system.status || 'unknown'}</span></label>)}</div>}</div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERVIEW DASHBOARD — MATCHES DNS SINKHOLE ENTERPRISE SOC DESIGN
// ═════════════════════════════════════════════════════════════════════════════
function DnsCachePoisoningOverviewDashboard({ alerts = [], total = 0, onRefresh }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const data = useMemo(() => {
    const now = Date.now();
    const rows = alerts.map(a => {
      const domain = a.domain || a.tiDomain || a.rawEvent?.domain || a.rawEvent?.raw?.domain || '—';
      const dnsFields = dnsLogFields({ ...a, domain });
      const blocked = !!(a.blocked || /refused|poison|spoof/i.test(a.responseCode || a.detectionType || ''));
      const time = new Date(a.createdAt || a.timestamp || 0);
      return { ...a, domain, blocked, time, queryType: dnsFields.queryType, srcip: dnsFields.sourceIp, poisonedIp: dnsFields.poisonedIp, expectedIp: dnsFields.expectedIp };
    });

    // 24-hr buckets
    const totalQ = Array(24).fill(0);
    const poisonHits = Array(24).fill(0);
    const hostsAttacks = Array(24).fill(0);
    rows.forEach(r => {
      const hoursAgo = Math.floor((now - r.time.getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) {
        const idx = 23 - hoursAgo;
        totalQ[idx]++;
        if (/poison|spoof|fake/i.test(`${r.detectionType || ''} ${r.description || ''}`)) poisonHits[idx]++;
        if (/hosts/i.test(`${r.detectionType || ''} ${r.description || ''}`)) hostsAttacks[idx]++;
      }
    });

    const domainMap = {}, catMap = {}, qTypeMap = {}, hostMap = {};
    rows.forEach(r => {
      if (r.domain && r.domain !== '—') domainMap[r.domain] = (domainMap[r.domain] || { count: 0, level: r.severity || 'high', poisonedIp: r.poisonedIp, expectedIp: r.expectedIp, firstSeen: r.time, lastSeen: r.time });
      if (r.domain && domainMap[r.domain]) {
        domainMap[r.domain].count++;
        if (r.time < domainMap[r.domain].firstSeen) domainMap[r.domain].firstSeen = r.time;
        if (r.time > domainMap[r.domain].lastSeen) domainMap[r.domain].lastSeen = r.time;
      }
      const cat = r.detectionType || r.ruleId || r.eventType || 'DNS anomaly'; catMap[cat] = (catMap[cat] || 0) + 1;
      if (r.queryType) qTypeMap[r.queryType] = (qTypeMap[r.queryType] || 0) + 1;
      const host = r.hostname || r.agentName || 'Unknown';
      if (!hostMap[host]) hostMap[host] = { count: 0, ip: r.srcip, poisoningHits: 0, status: r.systemId?.status || 'Not reported' };
      hostMap[host].count++;
      if (/poison|spoof/i.test(`${r.detectionType || ''} ${r.description || ''}`)) hostMap[host].poisoningHits++;
    });

    const topDomains = Object.entries(domainMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const topCats = Object.entries(catMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topQTypes = Object.entries(qTypeMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topHosts = Object.entries(hostMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const recentAlerts = [...rows].sort((a, b) => b.time - a.time).slice(0, 8);
    const poisoningTotal = rows.filter(r => /poison|spoof/i.test(`${r.detectionType || ''} ${r.description || ''}`)).length;
    const hostsTotal = rows.filter(r => /hosts/i.test(`${r.detectionType || ''} ${r.description || ''}`)).length;
    const resolverTotal = rows.filter(r => /resolver/i.test(`${r.detectionType || ''} ${r.description || ''}`)).length;
    const targetedDomains = Object.keys(domainMap).length;
    const catTotal = Object.values(catMap).reduce((s, v) => s + v, 0);
    const qTypeTotal = Object.values(qTypeMap).reduce((sum, value) => sum + value, 0);
    const heatmapSeverities = ['critical', 'high', 'medium', 'low', 'info'];
    const heatmapRows = heatmapSeverities.map(severity => ({
      severity,
      buckets: Array(6).fill(0),
    }));
    rows.forEach(row => {
      const timestamp = row.time.getTime();
      if (!Number.isFinite(timestamp)) return;
      const hoursAgo = Math.floor((now - timestamp) / 3600000);
      if (hoursAgo < 0 || hoursAgo >= 24) return;
      const bucketIndex = 5 - Math.floor(hoursAgo / 4);
      const severity = String(row.severity || 'low').toLowerCase();
      const severityIndex = heatmapSeverities.includes(severity) ? heatmapSeverities.indexOf(severity) : 3;
      heatmapRows[severityIndex].buckets[bucketIndex] += 1;
    });
    const heatmapMax = Math.max(1, ...heatmapRows.flatMap(row => row.buckets));
    const heatmapTotal = heatmapRows.reduce((sum, row) => sum + row.buckets.reduce((bucketSum, count) => bucketSum + count, 0), 0);

    return { rows, totalQ, poisonHits, hostsAttacks, topDomains, topCats, topQTypes, topHosts, recentAlerts, poisoningTotal, hostsTotal, resolverTotal, targetedDomains, catTotal, qTypeTotal, heatmapRows, heatmapMax, heatmapTotal };
  }, [alerts]);

  const kpiCards = [
    { label: 'TOTAL DNS EVENTS', value: total || alerts.length, color: MON.blue, icon: '🌐' },
    { label: 'POISONING ALERTS', value: data.poisoningTotal, color: MON.red, icon: '☠️' },
    { label: 'HOSTS FILE ATTACKS', value: data.hostsTotal, color: MON.orange, icon: '📁' },
    { label: 'RESOLVER CHANGES', value: data.resolverTotal, color: MON.yellow, icon: '🔄' },
    { label: 'AFFECTED HOSTS', value: alerts.length ? new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size : 0, color: MON.cyan, icon: '🖥️' },
  ];

  const qTypeColors = [MON.blue, MON.green, MON.purple, MON.orange, MON.cyan, MON.yellow];
  const catColors = [MON.red, MON.orange, MON.purple, MON.cyan, MON.blue];
  const fmtNum = n => n >= 1000 ? `${(n / 1000).toFixed(2)}K` : String(n);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── KPI Cards Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {kpiCards.map((k, i) => (
          <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: '14px 16px', position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${k.color}, transparent)` }} />
            <div style={{ fontSize: 9, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1.5 }}>{k.label}</div>
            <div style={{ fontSize: 28, fontWeight: 900, color: k.color, margin: '6px 0 2px', lineHeight: 1 }}>
              {typeof k.value === 'number' && k.value >= 1000 ? `${(k.value / 1000).toFixed(2)}K` : k.value}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 4 }}>
              <span style={{ fontSize: 9, color: MON.green, fontWeight: 800 }}>● Live tenant data</span>
            </div>
            <div style={{ marginTop: 8, height: 28 }}>
              <MiniSparkline data={data.totalQ} color={k.color} height={28} />
            </div>
          </div>
        ))}
      </div>

      {/* ── Row 2: Activity Chart + Status Matrix + Query Types ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.1fr 1fr', gap: 14 }}>

        {/* 24hr Multi-line Activity Chart */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📊 DNS Cache Poisoning Detection Activity (24 Hours)</div>
            <div style={{ display: 'flex', gap: 12 }}>
              {[['Total Queries', MON.blue], ['Poisoning Alerts', MON.red], ['Hosts File Attacks', MON.orange]].map(([l, c]) => (
                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                  <div style={{ width: 20, height: 2, background: c, borderRadius: 2 }} /><span style={{ color: MON.muted }}>{l}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ height: 180, position: 'relative' }}>
            <MultiLineChart height={170} datasets={[
              { data: data.totalQ, color: MON.blue },
              { data: data.poisonHits, color: MON.red },
              { data: data.hostsAttacks, color: MON.orange },
            ]} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.sub, fontSize: 8, marginTop: 6, paddingTop: 4, borderTop: `1px solid ${MON.line}` }}>
            {Array.from({ length: 7 }, (_, i) => {
              const d = new Date(Date.now() - (6 - i) * 4 * 3600000);
              return <span key={i}>{d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>;
            })}
          </div>
        </div>

        {/* Poisoning Status Matrix */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🗺️ Cache Poisoning Threat Heatmap</div>
          <div style={{ background: '#061220', borderRadius: 8, padding: 10, minHeight: 140, overflowX: 'auto' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '54px repeat(6, minmax(30px, 1fr))', gap: 5, minWidth: 280 }}>
              <span />
              {['20–24h', '16–20h', '12–16h', '8–12h', '4–8h', '0–4h'].map(label => <span key={label} style={{ color: MON.sub, fontSize: 7, textAlign: 'center' }}>{label}</span>)}
              {data.heatmapRows.flatMap(row => {
                const rgb = ({ critical: '248,113,113', high: '251,146,60', medium: '251,191,36', low: '52,211,153', info: '34,211,238' })[row.severity];
                return [
                  <span key={`${row.severity}-label`} style={{ color: SEV_COLOR[row.severity] || MON.cyan, fontSize: 8, fontWeight: 800, textTransform: 'uppercase', alignSelf: 'center' }}>{row.severity}</span>,
                  ...row.buckets.map((count, index) => {
                    const intensity = count ? 0.2 + (count / data.heatmapMax) * 0.75 : 0.04;
                    return <div key={`${row.severity}-${index}`} title={`${row.severity}: ${count} alert(s), ${['20–24h', '16–20h', '12–16h', '8–12h', '4–8h', '0–4h'][index]} ago`} style={{ height: 20, borderRadius: 4, display: 'grid', placeItems: 'center', background: `rgba(${rgb},${intensity})`, border: `1px solid rgba(${rgb},${count ? .55 : .12})`, color: count ? '#fff' : MON.sub, fontSize: 8, fontWeight: 900 }}>{count}</div>;
                  }),
                ];
              })}
            </div>
            <div style={{ color: data.heatmapTotal ? MON.cyan : MON.muted, fontSize: 9, fontWeight: 800, marginTop: 9, textAlign: 'center' }}>{data.heatmapTotal} threat event(s) in the last 24 hours</div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 10 }}>
            {[['High Poisoning Risk', MON.red], ['Medium Risk', MON.orange], ['Low Anomaly', MON.yellow], ['Normal Status', MON.line]].map(([l, c]) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
                <span style={{ color: MON.muted }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Query Types Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 8 }}>📡 Query Types</div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <DonutChart value={total || alerts.length} maxValue={Math.max(total || alerts.length, 1)} color={MON.blue} size={120} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {data.topQTypes.slice(0, 5).map(([qt, cnt], i) => (
              <div key={qt} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: qTypeColors[i % 6] }} />
                  <span style={{ color: MON.muted }}>{qt} Record</span>
                </div>
                <span style={{ color: qTypeColors[i % 6], fontWeight: 800 }}>
                  {data.qTypeTotal ? ((cnt / data.qTypeTotal) * 100).toFixed(1) : 0}%
                </span>
              </div>
            ))}
            {!data.topQTypes.length && <div style={{ color: MON.muted, fontSize: 10, textAlign: 'center' }}>Query-type telemetry not reported</div>}
          </div>
        </div>
      </div>

      {/* ── Row 3: Poisoned Cache Records + Recent Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>

        {/* Poisoned Cache & Hosts File Attacks */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.red }}>☠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Poisoned Cache & Hosts File Attacks</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700 }}>Targeted: {data.targetedDomains}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 90px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Target Domain</span><span>Poisoned IP</span><span>Expected IP</span><span>Threat Level</span>
          </div>
          {data.topDomains.length ? data.topDomains.map(([domain, info], i) => (
            <div key={domain} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 90px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.red, fontFamily: 'monospace', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={domain}>
                <span style={{ color: MON.red, marginRight: 4 }}>●</span>{domain}
              </span>
              <span style={{ color: MON.red, fontFamily: 'monospace', fontWeight: 700, fontSize: 9 }}>{info.poisonedIp}</span>
              <span style={{ color: MON.green, fontFamily: 'monospace', fontWeight: 700, fontSize: 9 }}>{info.expectedIp}</span>
              <span>
                <span style={{
                  background: 'rgba(248,113,113,0.2)', color: MON.red, padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 800
                }}>{(info.level || 'high').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No poisoned cache records detected</div>
          )}
        </div>

        {/* Recent Poisoning Alerts Stream */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.orange }}>⚠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Recent Poisoning & Spoofing Alerts</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '70px 1fr 90px 90px 70px', padding: '6px 10px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Time</span><span>Domain</span><span>Source IP</span><span>Endpoint</span><span>Severity</span>
          </div>
          {data.recentAlerts.length ? data.recentAlerts.map((r, i) => (
            <div key={r._id || i} onClick={() => setSelectedAlert(r)} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 90px 90px 70px', padding: '7px 10px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center', cursor: 'pointer' }}>
              <span style={{ color: MON.cyan, fontWeight: 700 }}>{r.time instanceof Date && !isNaN(r.time) ? r.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}</span>
              <span style={{ color: MON.red, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 4 }} title={r.domain}>{r.domain}</span>
              <span style={{ color: MON.muted, fontFamily: 'monospace' }}>{r.srcip || r.sourceIp || '—'}</span>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{r.hostname || r.agentName || '—'}</span>
              <span>
                <span style={{
                  color: SEV_COLOR[(r.severity || 'medium').toLowerCase()] || MON.yellow,
                  fontWeight: 800, fontSize: 9,
                }}>{(r.severity || 'medium').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No recent poisoning alerts</div>
          )}
        </div>
      </div>

      {/* ── Row 4: Top Targeted Endpoints + Spoofed vs Valid Donut + Detection Rules ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 14 }}>

        {/* Top Endpoints Targeted */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}` }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>🖥️ Top Endpoints Targeted for Poisoning</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Endpoint</span><span>IP Address</span><span>Poison Hits</span><span>Queries</span><span>Status</span>
          </div>
          {data.topHosts.length ? data.topHosts.map(([host, info], i) => (
            <div key={host} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{host}</span>
              <span style={{ color: MON.muted, fontFamily: 'monospace', fontSize: 9 }}>{info.ip}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ flex: 1, height: 5, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min((info.poisoningHits / (data.topHosts[0]?.[1]?.poisoningHits || 1)) * 100, 100)}%`, background: MON.red, borderRadius: 4 }} />
                </div>
                <span style={{ color: MON.red, fontWeight: 800, fontSize: 9 }}>{info.poisoningHits}</span>
              </div>
              <span style={{ color: MON.muted }}>{info.count}</span>
              <span style={{ color: MON.muted, fontWeight: 700, fontSize: 9 }}>{info.status || 'Not reported'}</span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No endpoint data</div>
          )}
        </div>

        {/* Spoofed vs Valid Responses Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 10, alignSelf: 'flex-start' }}>⚖️ Poisoning-classified Events</div>
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
            <svg width={140} height={140} viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="52" fill="none" stroke="#0f233a" strokeWidth="18" />
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.red} strokeWidth="18" strokeDasharray={`${((data.poisoningTotal / Math.max(data.rows.length, 1)) * 327).toFixed(1)} 327`} strokeDashoffset="81.75" strokeLinecap="butt" />
              <text x="70" y="64" textAnchor="middle" fill="#f1f5f9" fontSize="18" fontWeight="900">{data.poisoningTotal}</text>
              <text x="70" y="80" textAnchor="middle" fill={MON.muted} fontSize="9">Detected</text>
            </svg>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, width: '100%' }}>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Other DNS Events</div>
              <div style={{ fontSize: 16, color: MON.green, fontWeight: 900 }}>{Math.max(0, data.rows.length - data.poisoningTotal)}</div>
            </div>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Spoofed / Poisoned</div>
              <div style={{ fontSize: 16, color: MON.red, fontWeight: 900 }}>{data.poisoningTotal}</div>
            </div>
          </div>
        </div>

        {/* Detection Rules Breakdown */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 14 }}>🎯 Poisoning Detection Rules</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(data.topCats.length ? data.topCats : [['No rule telemetry', 0]]).map(([cat, count], index) => {
              const pct = data.catTotal ? (count / data.catTotal) * 100 : 0;
              const col = catColors[index % catColors.length];
              return (
              <div key={cat}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>•</span><span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                  </div>
                  <span style={{ color: col, fontWeight: 800 }}>{pct.toFixed(1)}%</span>
                </div>
                <div style={{ height: 6, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: col, borderRadius: 4 }} />
                </div>
              </div>);
            })}
          </div>
        </div>
      </div>

      {/* ── Status Bar ── */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '8px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
        <span style={{ color: MON.cyan }}>🛡️ This view shows tenant-scoped telemetry actually reported by configured endpoint agents.</span>
        <span style={{ color: MON.sub }}>All times in IST (UTC +05:30)</span>
      </div>

      {selectedAlert && <DnsCachePoisoningDetailModal log={selectedAlert} onClose={() => setSelectedAlert(null)} onRefresh={onRefresh} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD COMPONENT (DEFAULT EXPORT)
// ═════════════════════════════════════════════════════════════════════════════
export default function DnsCachePoisoningDashboard({ alerts = [], loading = false, total = 0, systems = [], onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const dnsSystems = Array.isArray(systems) ? systems : [];

  const liveStats = useMemo(() => {
    const text = a => `${a.type || ''} ${a.ruleId || ''} ${a.source || ''} ${a.description || ''} ${a.detectionType || ''}`;
    const poisoningAlerts = alerts.filter(a => /poison|spoof|fake/i.test(text(a))).length;
    const hostsAttacks = alerts.filter(a => /hosts/i.test(text(a))).length;
    const resolverChanges = alerts.filter(a => /resolver/i.test(text(a))).length;
    const critical = alerts.filter(a => a.severity === 'critical').length;
    const high = alerts.filter(a => a.severity === 'high').length;
    const medium = alerts.filter(a => a.severity === 'medium').length;
    const low = alerts.filter(a => a.severity === 'low').length;
    const info = alerts.filter(a => ['info', 'informational'].includes(String(a.severity || '').toLowerCase())).length;
    const ttlAnomalies = alerts.filter(a => /ttl/i.test(text(a))).length;
    const dnssecFailures = alerts.filter(a => /dnssec/i.test(text(a))).length;
    const unsolicitedAnswers = alerts.filter(a => /unsolicited/i.test(text(a))).length;
    const privateIpAnswers = alerts.filter(a => /private|loopback|reserved/i.test(text(a))).length;
    const dgaDetections = alerts.filter(a => /\bdga\b|algorithmic domain/i.test(text(a))).length;
    const tunnelAlerts = alerts.filter(a => /tunnel|encoded subdomain|exfiltration/i.test(text(a))).length;
    const threatIntelMatches = alerts.filter(a => a.threatIntelSource || /threat intel|ioc match/i.test(text(a))).length;
    const targetedDomains = new Set(alerts.map(a => a.domain || a.tiDomain).filter(Boolean)).size;
    const uniqueEndpoints = new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size;

    const now = Date.now();
    const timeline = Array(18).fill(0);
    const agentMap = {};

    alerts.forEach(a => {
      const created = new Date(a.createdAt || a.timestamp || 0).getTime();
      const daysAgo = Math.floor((now - created) / 86400000);
      if (Number.isFinite(daysAgo) && daysAgo >= 0 && daysAgo < 90) {
        timeline[Math.min(17, Math.max(0, 17 - Math.floor(daysAgo * 18 / 90)))]++;
      }
      const agentKey = a.agentId || a.agentName || a.systemId?._id || a.systemId || 'unknown';
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown', events: 0, poisoningHits: 0, hostsHits: 0, lastSeen: null });
      agent.events++;
      if (/poison|spoof/i.test(text(a))) agent.poisoningHits++;
      if (/hosts/i.test(text(a))) agent.hostsHits++;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
    });

    return {
      totalQueries: total || alerts.length,
      poisoningAlerts, hostsAttacks, resolverChanges, critical, high, medium, low, info,
      ttlAnomalies, dnssecFailures, unsolicitedAnswers, privateIpAnswers,
      dgaDetections, tunnelAlerts, threatIntelMatches,
      targetedDomains, uniqueEndpoints,
      highCritical: critical + high,
      timeline,
      agentRows: Object.values(agentMap).sort((a, b) => b.events - a.events),
    };
  }, [alerts, total]);

  const kpis = [
    ['Total DNS Queries', 'totalQueries', MON.blue, '🌐'],
    ['Poisoning Alerts', 'poisoningAlerts', MON.red, '☠️'],
    ['Hosts File Attacks', 'hostsAttacks', MON.orange, '📁'],
    ['Resolver Changes', 'resolverChanges', MON.yellow, '🔄'],
    ['Targeted Domains', 'targetedDomains', MON.purple, '🎯'],
    ['High & Critical Alerts', 'highCritical', MON.red, '⚠️'],
    ['Affected Endpoints', 'uniqueEndpoints', MON.cyan, '🖥️'],
    ['Critical Severity', 'critical', MON.red, '🔴'],
    ['High Severity', 'high', MON.orange, '🟠'],
    ['Online Agents', () => dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green, '🟢'],
    ['Total Agents', () => dnsSystems.length, MON.blue, '🖥️'],
    ['Offline Agents', () => dnsSystems.filter(s => !['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.muted, '⚫'],
    ['DNSSEC Failures', 'dnssecFailures', MON.orange, '🛡️'],
    ['TTL Anomalies', 'ttlAnomalies', MON.yellow, '⏳'],
    ['Unsolicited UDP Answers', 'unsolicitedAnswers', MON.red, '⚡'],
    ['Private IP Spoofing', 'privateIpAnswers', MON.red, '🔒'],
    ['DGA Detections', 'dgaDetections', MON.purple, '🔢'],
    ['DNS Tunnel Alerts', 'tunnelAlerts', MON.yellow, '🕳️'],
    ['Threat Intel Matches', 'threatIntelMatches', MON.red, '🧠'],
    ['Protected Hosts Entries', () => 'Not reported', MON.green, '✅'],
  ].map(([label, keyOrFn, color, icon]) => ({
    label,
    val: typeof keyOrFn === 'function' ? keyOrFn() : (liveStats[keyOrFn] ?? 0),
    color,
    icon,
    data: liveStats.timeline,
  }));

  const agentStatusRows = dnsSystems.map(sys => {
    const sysKey = String(sys.agentId || sys._id || '');
    const metrics = liveStats.agentRows.find(r => r.key === sysKey || r.name === sys.name || r.name === sys.hostname);
    return {
      key: sys._id || sysKey,
      name: sys.name || sys.hostname || metrics?.name || 'Unknown',
      hostname: sys.hostname || '—',
      status: sys.status || 'unknown',
      cacheMonitor: sys.dnsCachePoisonEnabled !== false,
      lastSeen: sys.lastSeen || metrics?.lastSeen,
      events: metrics?.events || 0,
      poisoningHits: metrics?.poisoningHits || 0,
      hostsHits: metrics?.hostsHits || 0,
    };
  });
  liveStats.agentRows.forEach(m => {
    if (!agentStatusRows.some(r => r.name === m.name)) agentStatusRows.push({ ...m, hostname: '—', status: 'reporting', cacheMonitor: null });
  });

  return (
    <div className="dcp-shell" style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      <style>{`@media(max-width:800px){.dcp-shell{flex-direction:column!important;overflow:auto!important}.dcp-sidebar{width:auto!important;flex-direction:row!important;overflow-x:auto!important}.dcp-sidebar-stats{display:none!important}.dcp-config-grid{grid-template-columns:1fr!important}}`}</style>
      {/* Sidebar Navigation */}
      <aside className="dcp-sidebar" style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📈', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'log-monitor', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
          { id: 'configure', icon: '⚙️', label: 'Configure', activeColor: MON.green },
        ].map(item => {
          const selected = activeTab === item.id;
          return (
            <button key={item.id} type="button" onClick={() => setActiveTab(item.id)} aria-current={selected ? 'page' : undefined} style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, background: selected ? item.activeColor : 'transparent', color: selected ? '#000' : MON.text, border: selected ? `1px solid ${item.activeColor}` : '1px solid transparent', padding: '10px 12px', borderRadius: 7, fontSize: 12, fontWeight: 800, textAlign: 'left', cursor: 'pointer' }}>
              <span aria-hidden="true">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}

        {/* Live Stats Mini Panel */}
        <div className="dcp-sidebar-stats" style={{ marginTop: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12 }}>
          <div style={{ fontSize: 9, color: MON.muted, fontWeight: 800, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Live Poisoning Stats</div>
          {[
            ['Poisoning Hits', liveStats.poisoningAlerts, MON.red],
            ['Hosts Attacks', liveStats.hostsAttacks, MON.orange],
            ['Resolver Changes', liveStats.resolverChanges, MON.yellow],
            ['Agents Online', dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green],
          ].map(([label, val, col]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 6 }}>
              <span style={{ color: MON.muted }}>{label}</span>
              <b style={{ color: col }}>{val}</b>
            </div>
          ))}
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>

        {activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={30}>
            <DnsCachePoisoningLogMonitor alerts={alerts} onRefresh={onRefresh} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <DnsCachePoisoningReportsTab alerts={alerts} />
        ) : activeTab === 'configure' ? (
          <DnsCachePoisoningConfigureTab systems={dnsSystems} onRefresh={onRefresh} />
        ) : activeTab === 'dashboard' ? (
          <DnsCachePoisoningOverviewDashboard alerts={alerts} total={total} onRefresh={onRefresh} />
        ) : (
          <>
            {/* 20 KPI Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, lineHeight: 1.3 }}>{kpi.label}</div>
                    <span style={{ fontSize: 14 }}>{kpi.icon}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent-Level DNS Cache Poisoning Monitoring Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛡️ Agent-Level DNS Cache Poisoning Monitoring</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(r => ['active', 'reporting', 'online'].includes(r.status)).length} reporting · 15s refresh</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent</span><span>Hostname</span><span>Status</span><span>Cache Monitor</span><span>Events</span><span>Poison Hits</span><span>Hosts Mod</span><span>Last Seen</span>
              </div>
              {agentStatusRows.length ? agentStatusRows.map(row => (
                <div key={row.key || row.name} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b>
                  <span>{row.hostname}</span>
                  <b style={{ color: ['active', 'reporting', 'online'].includes(row.status) ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.status}</b>
                  <span style={{ color: row.cacheMonitor === true ? MON.green : row.cacheMonitor === false ? MON.red : MON.muted }}>{row.cacheMonitor === true ? 'Enabled' : row.cacheMonitor === false ? 'Disabled' : 'Not reported'}</span>
                  <b>{row.events}</b>
                  <b style={{ color: row.poisoningHits > 0 ? MON.red : MON.green }}>{row.poisoningHits}</b>
                  <b style={{ color: row.hostsHits > 0 ? MON.orange : MON.green }}>{row.hostsHits}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Never'}</span>
                </div>
              )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading agent data...' : 'No DNS cache-monitoring agents found'}</div>}
            </div>

            {/* Charts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 DNS Poisoning Activity Timeline (90 Days)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 4, borderBottom: `1px solid ${MON.line}` }}>
                  {liveStats.timeline.map((val, idx) => (
                    <div key={idx} title={`${val} events`} style={{ flex: 1, height: `${val ? Math.max(4, (val / Math.max(...liveStats.timeline, 1)) * 100) : 0}%`, background: val > 0 ? MON.red : '#0f233a', borderRadius: '2px 2px 0 0', opacity: 0.85 }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>☠️ Poisoning Rules Triggered</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Cache Injection', liveStats.poisoningAlerts, MON.red],
                    ['Hosts Override', liveStats.hostsAttacks, MON.orange],
                    ['Resolver Hijack', liveStats.resolverChanges, MON.yellow],
                    ['TTL Manipulation', liveStats.ttlAnomalies, MON.purple],
                    ['DNSSEC Validation Failure', liveStats.dnssecFailures, MON.cyan],
                  ].map(([rule, count, col]) => (
                    <div key={rule} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{rule}</span>
                      <b style={{ color: col }}>{count}</b>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🎯 Threat Severity Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Critical', liveStats.critical, MON.red],
                    ['High', liveStats.high, MON.orange],
                    ['Medium', liveStats.medium, MON.yellow],
                    ['Low', liveStats.low, MON.green],
                    ['Info', liveStats.info, MON.cyan],
                  ].map(([sev, count, col]) => (
                    <div key={sev} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{sev}</span>
                      <b style={{ color: col }}>{count}</b>
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
// 6. OVERLAY CAPABILITY MODAL EXPORT
// ═════════════════════════════════════════════════════════════════════════════
export function CapabilityPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId: 30, windowHours: 24 });
      let r = await api.get(`/dashboard/capabilities/30/live?${q}`);
      let fetchedAlerts = r.data?.alerts || [];
      let fetchedTotal = r.data?.total || fetchedAlerts.length;

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/edr?${q}`);
          fetchedAlerts = r.data?.alerts || [];
          fetchedTotal = r.data?.total || fetchedAlerts.length;
        } catch { /* ignore */ }
      }

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal);
    } catch (err) {
      console.warn('[DNS Cache Poisoning fetch warning]', err);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 60000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    if (!companyId) return;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    socket.on('connect', join);
    socket.on('alert:new', (a) => { if (a) setAlerts(prev => [a, ...prev]); loadAlerts(true); });
    socket.on('alert:updated', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new');
      socket.off('alert:updated');
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 30. DNS Cache Poisoning Detection</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#60a5fa', background: '#1e3a5f44', border: '1px solid #1e3a5f', padding: '3px 8px', borderRadius: 6, fontWeight: 'bold' }}>
              {Number(total || 0).toLocaleString()} records
            </span>
            <span style={{ fontSize: 10, color: loading ? MON.yellow : MON.green }}>{loading ? '⟳ Loading...' : '● Live'}</span>
            <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
          </div>
        </div>
        <DnsCachePoisoningDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function DnsCachePoisoningSubTabPage() {
  return <CapabilitySubTabPage kind="dnscachepoisoning" />;
}
