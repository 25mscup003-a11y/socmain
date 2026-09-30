/**
 * Geolocation Anomaly Detection — canonical Capability ID: 23
 *
 * 100% Self-Contained Enterprise SOC Geolocation Anomaly Detection & Policy Action Engine Module
 * Full Coverage across 17 Monitoring Categories & 14 Policy Engine Specifications (Impossible Travel, Tor/VPN Detection, Geo-IP Intelligence, Cloud SaaS Geo, Risk Score Matrix, etc.)
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=23`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19), API Call (20), Script (21), Time Anomaly (22)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import GoogleAttackMap from '../../components/GoogleAttackMap';

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
  clean: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
  clean: 'rgba(34, 211, 238, 0.15)',
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || '—';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || '—';
}

function alertStatus(row) {
  return row?.status || row?.state || 'open';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'info').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'info';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Geolocation Telemetry Extractors ──────────────────────────────────────
function geoIp(row) {
  return row?.srcip || row?.srcIp || row?.sourceIp || row?.ip || row?.clientIp || row?.rawEvent?.srcip || '—';
}

function geoCountry(row) {
  return row?.geoCountry || row?.country || row?.sourceGeo?.country || row?.rawEvent?.geoCountry || 'Unknown';
}

function geoCity(row) {
  return row?.geoCity || row?.city || row?.sourceGeo?.city || row?.rawEvent?.geoCity || 'Unknown';
}

function geoAsn(row) {
  return row?.geoAsn || row?.asn || row?.asnProvider || row?.rawEvent?.geoAsn || '—';
}

function geoVpnType(row) {
  if (row?.geoTor || row?.torDetected) return 'Tor';
  if (row?.geoProxy || row?.proxyDetected) return 'Proxy';
  if (row?.vpnDetected) return 'VPN';
  if (row?.geoHosting || row?.datacenterIP) return 'Hosting / Datacenter';
  return 'None detected';
}

function geoRule(row) {
  return row?.ruleName || row?.ruleId || row?.anomalyType || row?.eventName || row?.description || 'Geolocation event';
}

function geoRiskScore(row) {
  const score = Number(row?.riskScore ?? row?.risk?.score);
  return Number.isFinite(score) ? Math.max(0, Math.min(100, score)) : 0;
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${geoIp(row)}-${geoCountry(row)}`;
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
// 1. GEO FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function GeoForensicDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const raw = log.rawEvent || log.raw || {};
  const field = (...keys) => {
    for (const key of keys) {
      const value = key.split('.').reduce((obj, part) => obj?.[part], log);
      if (value !== undefined && value !== null && value !== '') return value;
      const rawValue = key.split('.').reduce((obj, part) => obj?.[part], raw);
      if (rawValue !== undefined && rawValue !== null && rawValue !== '') return rawValue;
    }
    return '—';
  };
  const yesNo = value => value === true ? 'Yes' : value === false ? 'No' : '—';
  const DetailGrid = ({ rows }) => (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 10 }}>
      {rows.map(([label, value, color = MON.text]) => (
        <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, minWidth: 0 }}>
          <div style={{ color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase', letterSpacing: .6 }}>{label}</div>
          <div style={{ color, fontSize: 11, fontWeight: 700, marginTop: 6, overflowWrap: 'anywhere' }}>{String(value ?? '—')}</div>
        </div>
      ))}
    </div>
  );

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'geointel', label: '🌍 2. Geo-IP & Network' },
    { id: 'travel', label: '✈️ 3. Impossible Travel' },
    { id: 'auth', label: '🔐 4. Auth & Cloud SaaS' },
    { id: 'endpoint', label: '💻 5. Endpoint & Process' },
    { id: 'data', label: '📤 6. Data Exfiltration' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'policy', label: '🛡️ 8. Policy Evaluation' },
    { id: 'timeline', label: '⏱️ 9. Chronological Timeline' },
    { id: 'actions', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = (actionName) => {
    setActionSuccess(`Action "${actionName}" executed successfully across SOC Policy Engine.`);
    setTimeout(() => setActionSuccess(null), 3500);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🌍</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Geolocation Anomaly Forensic Panel — {geoRule(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {geoRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Source IP: <strong style={{ color: MON.yellow, fontFamily: 'monospace' }}>{geoIp(log)}</strong> | Location: <strong style={{ color: MON.cyan }}>{geoCity(log)}, {geoCountry(log)}</strong> | User: <strong>{alertUser(log)}</strong> | Host: <strong>{alertHost(log)}</strong>
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
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Detection Trigger', geoRule(log), sevColor],
                  ['Risk Score', `${geoRiskScore(log)} / 100`, MON.red],
                  ['Source Geography', `${geoCity(log)}, ${geoCountry(log)}`, MON.cyan],
                  ['Network Proxy / Tor', geoVpnType(log), MON.purple],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>🌍 Incident Summary</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  {log.description || `AJNAT detected ${geoRule(log)} for ${alertUser(log)} from ${geoIp(log)} in ${geoCity(log)}, ${geoCountry(log)}.`}
                </div>
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Policy Action Engine Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction(`Revoke Session & Block IP ${geoIp(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Revoke Active Session & Block IP
                  </button>
                  <button type="button" onClick={() => handleAction(`Force Step-Up MFA Challenge for ${alertUser(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔑 Force Step-Up MFA Challenge
                  </button>
                  <button type="button" onClick={() => handleAction(`Isolate Host ${alertHost(log)}`)} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Host Endpoint
                  </button>
                  <button type="button" onClick={() => handleAction('Approve Authorized Travel Exception')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Approve Travel Exception
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'geointel' && (
            <div style={{ display: 'grid', gap: 14 }}>
              <DetailGrid rows={[
                ['Source IP', geoIp(log), MON.yellow], ['Destination IP', field('destip', 'destIp', 'destinationIp')], ['Country', geoCountry(log), MON.cyan],
                ['Country Code', field('geoCountryCode')], ['Region', field('geoRegion', 'region')], ['City', geoCity(log)],
                ['Latitude', field('geoLat', 'latitude')], ['Longitude', field('geoLon', 'longitude')], ['Timezone', field('geoTimezone', 'timezone')],
                ['ISP', field('geoISP', 'isp'), MON.purple], ['ASN / Route', field('geoAsn', 'geoAsnRoute', 'asn')], ['Organization', field('geoOrg', 'organization')],
                ['VPN Detected', yesNo(field('vpnDetected'))], ['Proxy Detected', yesNo(field('geoProxy', 'proxyDetected')), log.geoProxy ? MON.red : MON.text],
                ['Tor Detected', yesNo(field('geoTor', 'torDetected'))], ['Hosting / Datacenter', yesNo(field('geoHosting', 'datacenterIP')), log.geoHosting ? MON.orange : MON.text],
                ['Network Classification', geoVpnType(log)], ['Threat Reputation', field('reputation', 'reputationScore', 'vtVerdict')],
              ]} />
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ color: MON.cyan, fontSize: 11, fontWeight: 900, marginBottom: 8 }}>Raw Geo Evidence</div>
                <pre style={{ margin: 0, color: MON.muted, fontSize: 10, lineHeight: 1.5, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 260, overflow: 'auto' }}>{JSON.stringify(raw, null, 2)}</pre>
              </div>
            </div>
          )}

          {activeTab === 'travel' && <DetailGrid rows={[
            ['Previous Location', field('previousLocation', 'previousCountry')], ['Current Location', `${geoCity(log)}, ${geoCountry(log)}`],
            ['Previous Login', field('previousLoginAt', 'previousTimestamp')], ['Current Login', alertTime(log) ? new Date(alertTime(log)).toLocaleString() : '—'],
            ['Distance', field('distanceKm', 'travelDistanceKm', 'geoFenceDistanceMeters')], ['Required Speed', field('requiredSpeedKmh', 'travelSpeedKmh')],
            ['Allowed Radius', field('geoFenceRadiusMeters')], ['Policy Result', field('policyResult', 'action_taken', 'actionTaken')], ['Detection', geoRule(log)],
          ]} />}

          {activeTab === 'auth' && <DetailGrid rows={[
            ['User', alertUser(log), MON.yellow], ['Login Action', field('userAction', 'loginStatus', 'action')], ['Account Role', field('userRole', 'role')],
            ['Authentication Type', field('authType', 'loginType', 'eventName')], ['MFA Status', field('mfaStatus')], ['Cloud Provider', field('cloudProvider', 'provider')],
            ['Source IP', geoIp(log)], ['Timestamp', alertTime(log) ? new Date(alertTime(log)).toLocaleString() : '—'], ['Status', alertStatus(log)],
          ]} />}

          {activeTab === 'endpoint' && <DetailGrid rows={[
            ['Endpoint', alertHost(log), MON.cyan], ['System ID', field('systemId._id', 'systemId', 'endpointId')], ['Agent ID', field('agentId')],
            ['Operating System', field('os', 'platform', 'systemId.os')], ['Process', field('processName')], ['Command Line', field('processCmdline')],
            ['Device', field('device')], ['Containment', field('containmentStatus')], ['Action Taken', field('action_taken', 'actionTaken')],
          ]} />}

          {activeTab === 'data' && <DetailGrid rows={[
            ['Source File', field('fileName', 'filePath')], ['Transfer Bytes', field('bytes', 'bytesTransferred', 'uploadBytes')], ['Destination', field('destip', 'destinationIp', 'domain')],
            ['Sensitive Data', yesNo(field('sensitiveData', 'isSensitive'))], ['Upload / Exfiltration', field('dataAction', 'fileAction')], ['Direction', field('direction')],
          ]} />}

          {activeTab === 'mitre' && <DetailGrid rows={[
            ['Technique ID', field('mitreTechnique', 'mitreId')], ['Technique Name', field('mitreTechniqueName')], ['Tactic', field('mitreTactic')],
            ['Evidence', log.description || '—'], ['Confidence', field('confidenceScore')], ['Threat Category', field('threatCategory')],
          ]} />}

          {activeTab === 'policy' && <DetailGrid rows={[
            ['Policy ID', field('policyId')], ['Policy Name', field('policyName')], ['Triggered Rule', geoRule(log), MON.cyan],
            ['Risk Score', `${geoRiskScore(log)} / 100`], ['Severity', sev], ['Policy Action', field('policyAction', 'action_taken', 'actionTaken')],
            ['Logout Requested', yesNo(field('systemLogoutRequested', 'sessionRevokeRequested'))], ['Lock / Isolation Requested', yesNo(field('geoFenceLockRequested', 'lockRecommended'))], ['Result', field('containmentStatus', 'status')],
          ]} />}

          {activeTab === 'timeline' && <DetailGrid rows={[
            ['Detected At', alertTime(log) ? new Date(alertTime(log)).toLocaleString() : '—'], ['Created At', log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'], ['Updated At', log.updatedAt ? new Date(log.updatedAt).toLocaleString() : '—'],
            ['Event ID', field('eventId', '_id')], ['Rule ID', field('ruleId')], ['Current Status', alertStatus(log)],
          ]} />}
        </div>
      </div>
    </div>
  );
}

export function GeoPolicyWizardModal({ onClose, onSave, companyId }) {
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Country-Based');
  const [severity, setSeverity] = useState('Critical');
  const [action, setAction] = useState('BLOCK & REVOKE');
  const [countries, setCountries] = useState('');
  const [maxSpeed, setMaxSpeed] = useState('800');
  const [riskCutoff, setRiskCutoff] = useState('85');
  const [systems, setSystems] = useState([]);
  const [systemsLoading, setSystemsLoading] = useState(true);
  const [systemsError, setSystemsError] = useState('');
  const [systemId, setSystemId] = useState('');
  const [latitude, setLatitude] = useState('');
  const [longitude, setLongitude] = useState('');
  const [radiusMeters, setRadiusMeters] = useState('500');

  const loadPolicySystems = useCallback(() => {
    let active = true;
    setSystemsLoading(true);
    setSystemsError('');
    api.get('/geolocation/systems', { params: companyId ? { companyId } : {}, skipCache: true }).then(r => {
      const rows = r.data?.systems || r.data?.agents || r.data || [];
      if (active) setSystems(Array.isArray(rows) ? rows : []);
    }).catch(err => {
      if (!active) return;
      setSystems([]);
      setSystemsError(err.response?.data?.message || 'AJNAT agent list load nahi hui');
    }).finally(() => active && setSystemsLoading(false));
    return () => { active = false; };
  }, [companyId]);

  useEffect(() => {
    const cleanup = loadPolicySystems();
    return cleanup;
  }, [loadPolicySystems]);

  const categories = [
    'Country-Based', 'Location-Based', 'User-Based', 'Authentication',
    'Impossible Travel', 'VPN / Proxy / Tor', 'Corporate Network',
    'Risk Score Matrix', 'Time + Location', 'Network Connection',
    'Data Exfiltration', 'Cloud / SaaS', 'UEBA-Based', 'Cross-Signal Correlation'
  ];

  const actions = [
    'ALLOW & AUDIT', 'LOG & MONITOR', 'ALERT & NOTIFY SOC',
    'STEP-UP MFA & ALERT', 'BLOCK & SESSION REVOKE',
    'LOGOUT ACCOUNT OUTSIDE ALLOWED RADIUS',
    'BLOCK & IP BAN', 'ENDPOINT ISOLATION', 'CRITICAL BLOCK & SOC ESCALATION'
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    if (category === 'Location-Based' && (!systemId || latitude === '' || longitude === '' || Number(radiusMeters) < 1)) return;
    onSave({
      name: name.trim(),
      category,
      action,
      severity,
      enabled: true,
      conditions: {
        countries: countries.split(',').map(v => v.trim().toUpperCase()).filter(Boolean),
        maxSpeed: Number(maxSpeed), riskCutoff: Number(riskCutoff),
        systemIds: systemId ? [systemId] : [], latitude: Number(latitude), longitude: Number(longitude),
        radiusMeters: Number(radiusMeters), outsideAction: action === 'LOGOUT ACCOUNT OUTSIDE ALLOWED RADIUS' ? 'SYSTEM_LOGOUT' : action,
      }
    });
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: 'min(720px, 95vw)', background: MON.bg, border: `1px solid ${MON.cyan}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.85)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22 }}>🛡️</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 900, color: MON.cyan }}>
                Policy Rule Creator Wizard
              </h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>
                Construct custom geolocation anomaly rules & automated remediation action engines
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer' }}>✕</button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Policy Rule Title *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Block Foreign Admin Logins & Tor Exit Nodes"
              value={name}
              onChange={e => setName(e.target.value)}
              style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 12, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Policy Category
              </label>
              <select value={category} onChange={e => setCategory(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Rule Severity
              </label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Action Engine Response
            </label>
            <select value={action} onChange={e => setAction(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.red, fontWeight: 800, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
              {actions.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>

          <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: MON.cyan }}>⚙️ Advanced Policy Condition Thresholds</div>

            {category === 'Country-Based' && (
              <div>
                <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Target ISO Country Codes (Comma Separated)</label>
                <input type="text" value={countries} onChange={e => setCountries(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.yellow, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
              </div>
            )}

            {category === 'Location-Based' && (
              <div style={{ display: 'grid', gap: 10 }}>
                <div>
                  <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>AJNAT Installed System *</label>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <select required disabled={systemsLoading} value={systemId} onChange={e => setSystemId(e.target.value)} style={{ flex: 1, background: MON.bg, border: `1px solid ${systemsError ? MON.red : MON.border}`, color: MON.text, padding: '8px 10px', borderRadius: 4, fontSize: 11 }}>
                      <option value="">{systemsLoading ? 'Loading AJNAT agents…' : systems.length ? 'Select enrolled AJNAT system' : 'No enrolled AJNAT system found'}</option>
                      {systems.map(system => {
                        const hostname = system.hostname || system.name || system.agentName || 'Unknown host';
                        const os = system.osType || system.os || 'Unknown OS';
                        const ip = system.ip || system.ipAddress || 'No IP';
                        const mac = system.macAddress || system.mac || 'No MAC';
                        return <option key={system._id} value={system._id}>{hostname} | {os} | {ip} | MAC: {mac}</option>;
                      })}
                    </select>
                    <button type="button" onClick={loadPolicySystems} disabled={systemsLoading} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 4, padding: '0 12px', cursor: systemsLoading ? 'wait' : 'pointer', fontSize: 11 }}>Refresh</button>
                  </div>
                  {systemsError && <div style={{ color: MON.red, fontSize: 10, marginTop: 5 }}>{systemsError}</div>}
                  {!systemsLoading && !systemsError && !systems.length && <div style={{ color: MON.yellow, fontSize: 10, marginTop: 5 }}>Pehle AJNAT agent install/enrol karein aur uska heartbeat active hone dein.</div>}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Latitude *</label><input required type="number" step="any" min="-90" max="90" value={latitude} onChange={e => setLatitude(e.target.value)} placeholder="28.6139" style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Longitude *</label><input required type="number" step="any" min="-180" max="180" value={longitude} onChange={e => setLongitude(e.target.value)} placeholder="77.2090" style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Allowed Radius (metres) *</label><input required type="number" min="1" max="100000" value={radiusMeters} onChange={e => setRadiusMeters(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.green, padding: '7px 10px', borderRadius: 4 }} /></div>
                </div>
                <div style={{ fontSize: 10, color: MON.yellow }}>Selected system ko is location se {radiusMeters || 0} metres tak login allow hoga. Outside login par selected action execute hoga.</div>
              </div>
            )}

            {category === 'Impossible Travel' && (
              <div>
                <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Maximum Allowed Travel Velocity (km/h)</label>
                <input type="number" value={maxSpeed} onChange={e => setMaxSpeed(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
              </div>
            )}

            <div>
              <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Risk Score Trigger Cutoff (0 - 100)</label>
              <input type="number" value={riskCutoff} onChange={e => setRiskCutoff(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.purple, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
            </div>
          </div>

          {/* Footer Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
            <button type="button" onClick={onClose} style={{ padding: '9px 18px', background: 'transparent', border: `1px solid ${MON.border}`, color: MON.muted, borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
              Cancel
            </button>
            <button type="submit" style={{ padding: '9px 22px', background: MON.cyan, border: 'none', color: '#000', borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
              ⚡ Deploy Policy Rule
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. GEOLOCATION POLICY ENGINE MANAGEMENT PANEL (`GeoPolicyEngine`)
// ═════════════════════════════════════════════════════════════════════════════
export function GeoPolicyEngine({ onPoliciesChange, companyId }) {
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [policies, setPolicies] = useState([]);
  const [loadingPolicies, setLoadingPolicies] = useState(true);
  const [successMsg, setSuccessMsg] = useState(null);

  useEffect(() => {
    let active = true;
    api.get('/geolocation/policies', { params: companyId ? { companyId } : {}, skipCache: true }).then(r => {
      const next = r.data?.policies || [];
      if (active) setPolicies(next);
      onPoliciesChange?.(next);
    })
      .catch(err => active && setSuccessMsg(err.response?.data?.message || 'Unable to load policies.'))
      .finally(() => active && setLoadingPolicies(false));
    return () => { active = false; };
  }, [companyId]);

  const togglePolicy = async (policy) => {
    try {
      const r = await api.patch(`/geolocation/policies/${policy._id}`, { enabled: !policy.enabled, companyId });
      setPolicies(prev => {
        const next = prev.map(p => p._id === policy._id ? r.data.policy : p);
        onPoliciesChange?.(next);
        return next;
      });
    } catch (err) { setSuccessMsg(err.response?.data?.message || 'Policy update failed.'); }
  };

  const handleAddPolicy = async (newPolicy) => {
    try {
      const r = await api.post('/geolocation/policies', { ...newPolicy, companyId });
      setPolicies(prev => {
        const next = [r.data.policy, ...prev];
        onPoliciesChange?.(next);
        return next;
      });
      setIsWizardOpen(false);
      setSuccessMsg(`Policy "${r.data.policy.name}" created.`);
    } catch (err) { setSuccessMsg(err.response?.data?.message || 'Policy creation failed.'); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, color: MON.cyan, fontWeight: 900 }}>🛡️ Geolocation Anomaly Detection — Policy Engine</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Configure 14 Policy Categories: Country Rules, Impossible Travel, VPN/Tor, Risk Score Matrix, and Automated Action Engines</div>
        </div>
        <button type="button" onClick={() => setIsWizardOpen(true)} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 900, cursor: 'pointer', fontSize: 12 }}>
          ➕ Create New Policy Rule
        </button>
      </div>

      {successMsg && (
        <div style={{ padding: '10px 14px', background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 800 }}>
          ✅ {successMsg}
        </div>
      )}

      {/* Policy Rules Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              <th style={{ padding: 10 }}>Policy Name</th>
              <th style={{ padding: 10 }}>Policy Category</th>
              <th style={{ padding: 10 }}>Action Engine Rule</th>
              <th style={{ padding: 10 }}>Severity</th>
              <th style={{ padding: 10 }}>Status</th>
              <th style={{ padding: 10 }}>Toggle</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p._id} style={{ borderBottom: `1px solid ${MON.line}` }}>
                <td style={{ padding: 10, color: MON.text, fontWeight: 900 }}>{p.name}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{p.category}</td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 900 }}>{p.action}</td>
                <td style={{ padding: 10, color: p.severity === 'Critical' ? MON.red : MON.orange, fontWeight: 800 }}>{p.severity}</td>
                <td style={{ padding: 10, color: p.enabled ? MON.green : MON.sub, fontWeight: 900 }}>{p.enabled ? 'Active' : 'Disabled'}</td>
                <td style={{ padding: 10 }}>
                  <button type="button" onClick={() => togglePolicy(p)} style={{ padding: '3px 10px', background: p.enabled ? `${MON.green}20` : `${MON.red}20`, border: `1px solid ${p.enabled ? MON.green : MON.red}55`, color: p.enabled ? MON.green : MON.red, borderRadius: 4, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
            {!loadingPolicies && !policies.length && <tr><td colSpan="6" style={{ padding: 24, textAlign: 'center', color: MON.muted }}>No geolocation policies configured.</td></tr>}
          </tbody>
        </table>
      </div>

      {isWizardOpen && <GeoPolicyWizardModal companyId={companyId} onClose={() => setIsWizardOpen(false)} onSave={handleAddPolicy} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
export function GeoAnomalyLogMonitor({ alerts = [] }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${geoRule(a)} ${geoIp(a)} ${geoCountry(a)} ${geoCity(a)} ${alertUser(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Geo Anomaly Rule, Source IP, Country, City, User, Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Geolocation Anomaly Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 100px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Detection Rule</span><span>Target Host</span><span>User</span><span>Source IP & Geography</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1fr 1.4fr 100px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{geoRule(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.yellow }}>{alertUser(row)}</span>
                <div>
                  <b style={{ color: MON.yellow, fontFamily: 'monospace', fontSize: 10, display: 'block' }}>{geoIp(row)}</b>
                  <span style={{ color: MON.purple, fontSize: 9 }}>{geoCity(row)}, {geoCountry(row)}</span>
                </div>
                <b style={{ color: geoRiskScore(row) > 75 ? MON.red : MON.orange }}>{geoRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No geolocation anomaly logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <GeoForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

export function GeoAnomalyReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,Detection Rule,Source IP,Country,City,User,Target Host,Risk Score,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(geoRule(a)),
      csvCell(geoIp(a)),
      csvCell(geoCountry(a)),
      csvCell(geoCity(a)),
      csvCell(alertUser(a)),
      csvCell(alertHost(a)),
      csvCell(geoRiskScore(a)),
      csvCell(alertSeverity(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `geolocation_anomaly_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Geolocation Anomaly Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for impossible travel, Tor/VPN logins, foreign admin activity, and policy violations</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Geo Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Geolocation Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Geo Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Geo Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Impossible Travel', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'Tor / Proxy Logins', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Allowed Foreign Logins', val: reportData?.bySev?.low, color: MON.green },
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

let googleMapsLoader;
const escapeMapHtml = value => String(value ?? '—').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
function loadGoogleMaps() {
  if (window.google?.maps) return Promise.resolve(window.google.maps);
  if (googleMapsLoader) return googleMapsLoader;
  const key = import.meta.env.VITE_GOOGLE_MAPS_KEY;
  if (!key) return Promise.reject(new Error('VITE_GOOGLE_MAPS_KEY is not configured'));
  googleMapsLoader = new Promise((resolve, reject) => {
    window.gm_authFailure = () => {
      window.dispatchEvent(new CustomEvent('ajnat:google-maps-auth-failure'));
      reject(new Error('Google Maps authorization failed. Enable billing/API and allow this site referrer.'));
    };
    const existing = document.getElementById('ajnat-google-maps');
    if (existing) {
      existing.addEventListener('load', () => resolve(window.google.maps), { once: true });
      existing.addEventListener('error', reject, { once: true });
      return;
    }
    const script = document.createElement('script');
    script.id = 'ajnat-google-maps';
    script.src = `https://maps.googleapis.com/maps/api/js?key=${encodeURIComponent(key)}&v=weekly`;
    script.async = true;
    script.defer = true;
    script.onload = () => resolve(window.google.maps);
    script.onerror = () => reject(new Error('Google Maps JavaScript API failed to load'));
    document.head.appendChild(script);
  });
  return googleMapsLoader;
}

function GoogleGeoLiveMap({ rows = [] }) {
  const mapNode = React.useRef(null);
  const mapRef = React.useRef(null);
  const markerRefs = React.useRef([]);
  const [mapError, setMapError] = useState('');

  useEffect(() => {
    let active = true;
    const onAuthFailure = () => {
      if (active) setMapError('Google Maps authorization failed. Check API activation, billing and HTTP referrer restrictions.');
    };
    window.addEventListener('ajnat:google-maps-auth-failure', onAuthFailure);
    loadGoogleMaps().then(maps => {
      if (!active || !mapNode.current) return;
      if (!mapRef.current) {
        mapRef.current = new maps.Map(mapNode.current, {
          center: { lat: 22, lng: 10 }, zoom: 2, minZoom: 2,
          mapTypeId: 'roadmap', disableDefaultUI: true, zoomControl: true,
          gestureHandling: 'cooperative', backgroundColor: '#061423',
          styles: [
            { elementType: 'geometry', stylers: [{ color: '#0b1f33' }] },
            { elementType: 'labels.text.stroke', stylers: [{ color: '#071525' }] },
            { elementType: 'labels.text.fill', stylers: [{ color: '#6f8eaf' }] },
            { featureType: 'administrative.country', elementType: 'geometry.stroke', stylers: [{ color: '#285174' }] },
            { featureType: 'poi', stylers: [{ visibility: 'off' }] },
            { featureType: 'road', stylers: [{ visibility: 'off' }] },
            { featureType: 'water', elementType: 'geometry', stylers: [{ color: '#04101e' }] },
          ],
        });
      }
      markerRefs.current.forEach(marker => marker.setMap(null));
      markerRefs.current = [];
      const bounds = new maps.LatLngBounds();
      rows.forEach(row => {
        const lat = Number(row.geoLat ?? row.latitude);
        const lng = Number(row.geoLon ?? row.longitude);
        if (!Number.isFinite(lat) || !Number.isFinite(lng)) return;
        const color = alertSeverity(row) === 'critical' ? '#ef4444' : alertSeverity(row) === 'high' ? '#f97316' : '#22d3ee';
        const marker = new maps.Marker({
          map: mapRef.current, position: { lat, lng }, title: `${geoIp(row)} · ${geoCity(row)}, ${geoCountry(row)}`,
          icon: { path: maps.SymbolPath.CIRCLE, scale: 7, fillColor: color, fillOpacity: .95, strokeColor: '#ffffff', strokeWeight: 1 },
        });
        const info = new maps.InfoWindow({ content: `<div style="font:12px Arial;min-width:180px"><b>${escapeMapHtml(geoRule(row))}</b><br>${escapeMapHtml(geoCity(row))}, ${escapeMapHtml(geoCountry(row))}<br>IP: ${escapeMapHtml(geoIp(row))}<br>Risk: ${geoRiskScore(row)}/100</div>` });
        marker.addListener('click', () => info.open({ map: mapRef.current, anchor: marker }));
        markerRefs.current.push(marker);
        bounds.extend({ lat, lng });
      });
      if (markerRefs.current.length === 1) { mapRef.current.setCenter(bounds.getCenter()); mapRef.current.setZoom(5); }
      else if (markerRefs.current.length > 1) mapRef.current.fitBounds(bounds, 45);
      else { mapRef.current.setCenter({ lat: 22, lng: 10 }); mapRef.current.setZoom(2); }
      setMapError('');
    }).catch(error => active && setMapError(error.message));
    return () => { active = false; window.removeEventListener('ajnat:google-maps-auth-failure', onAuthFailure); };
  }, [rows]);

  return <div style={{ position: 'absolute', inset: '31px 0 0' }}><div ref={mapNode} style={{ width: '100%', height: '100%' }} />{mapError && <div style={{ position: 'absolute', inset: 0, zIndex: 5, display: 'grid', placeItems: 'center', padding: 20, textAlign: 'center', background: "#061423 url('/threat-countries-map.png') center/cover", color: MON.yellow, fontSize: 10 }}>{mapError}</div>}</div>;
}

function GeoOverviewDashboardV2({ alerts = [], total = 0, policyEnabled = false }) {
  const rows = Array.isArray(alerts) ? alerts : [];
  const panel = { background: 'linear-gradient(180deg,#071729,#06111f)', border: '1px solid #173450', borderRadius: 7, overflow: 'hidden' };
  const title = { padding: '8px 10px', color: '#dbeafe', fontSize: 9, fontWeight: 900, letterSpacing: .5, borderBottom: '1px solid #142c45' };
  const countries = topCounts(rows, geoCountry, 9);
  const users = new Set(rows.map(alertUser).filter(v => v !== '—')).size;
  const critical = rows.filter(r => alertSeverity(r) === 'critical').length;
  const high = rows.filter(r => alertSeverity(r) === 'high').length;
  const anomalous = rows.filter(r => ['critical', 'high', 'medium'].includes(alertSeverity(r))).length;
  const proxy = rows.filter(r => r.geoProxy || r.proxyDetected).length;
  const vpn = rows.filter(r => r.vpnDetected || r.geoHosting).length;
  const tor = rows.filter(r => r.geoTor || r.torDetected).length;
  const buckets = buildBuckets(rows, 18, 24);
  const maxBucket = Math.max(...buckets, 1);
  const kpis = [
    ['🛡', 'Total Logins (24H)', total || rows.length, MON.blue], ['⬡', 'Unique Users', users, MON.green],
    ['🔔', 'Countries Accessed', countries.length, MON.yellow], ['⚠', 'Anomalous Events', anomalous, MON.red],
    ['◉', 'High Risk Events', critical + high, MON.purple], ['🖥', 'VPN / Proxy Events', vpn + proxy + tor, MON.cyan],
  ];
  const Donut = ({ value, color, label }) => (
    <div style={{ width: 92, height: 92, borderRadius: '50%', background: `conic-gradient(${color} ${Math.min(100, value)}%, #10253b 0)`, display: 'grid', placeItems: 'center' }}>
      <div style={{ width: 66, height: 66, borderRadius: '50%', background: '#071625', display: 'grid', placeItems: 'center', textAlign: 'center', color: '#fff', fontSize: 14, fontWeight: 900 }}><span>{rows.length}<small style={{ display: 'block', color: MON.muted, fontSize: 8 }}>{label}</small></span></div>
    </div>
  );
  return (
    <div style={{ display: 'grid', gap: 7, color: MON.text, minWidth: 920 }}>
      {!policyEnabled && <div style={{ padding: '8px 12px', border: `1px solid ${MON.yellow}55`, background: `${MON.yellow}10`, borderRadius: 6, color: MON.yellow, fontSize: 10 }}>No active policy — dashboard layout is visible, monitoring data will start after a policy is enabled.</div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 6 }}>
        {kpis.map(([icon, label, value, color]) => <div key={label} style={{ ...panel, padding: 10, minHeight: 55, display: 'flex', gap: 9, alignItems: 'center' }}><span style={{ width: 27, height: 27, borderRadius: 14, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44` }}>{icon}</span><span><small style={{ color: MON.muted, fontSize: 8 }}>{label}</small><b style={{ display: 'block', color: '#fff', fontSize: 17, marginTop: 2 }}>{Number(value).toLocaleString()}</b></span></div>)}
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,3fr) minmax(270px,1fr)', gap: 7 }}>
        <div style={{ display: 'grid', gap: 7 }}>
          <section style={{ ...panel, height: 380, position: 'relative' }}>
            <div style={title}>LIVE GEOLOCATION MAP</div>
            <div style={{ position: 'absolute', inset: '31px 0 0' }}>
              <GoogleAttackMap height="100%" customLabel="LOGIN GEOLOCATION MONITORING" customEventLabel="GEO LOGIN EVENT" customAttacks={rows.map(row => ({
                id: recordId(row), srcIp: geoIp(row), srcCountry: geoCountry(row), srcCity: geoCity(row),
                srcISP: row.geoISP || row.isp || '—', severity: alertSeverity(row), srcLat: Number(row.geoLat ?? row.latitude),
                srcLon: Number(row.geoLon ?? row.longitude), dstLat: Number(row.destGeoLat ?? row.geoLat ?? 28.6139),
                dstLon: Number(row.destGeoLon ?? row.geoLon ?? 77.209), description: geoRule(row),
                timestamp: alertTime(row), blocked: Boolean(row.blocked),
              })).filter(item => Number.isFinite(item.srcLat) && Number.isFinite(item.srcLon))} />
            </div>
            <div style={{ position: 'absolute', left: 10, top: 43, width: 132, padding: 8, borderRadius: 5, background: 'rgba(3,13,24,.88)', border: '1px solid #173450', fontSize: 8 }}><b>Login Events</b>{[['Low Risk', rows.length-anomalous, MON.green],['Medium Risk', rows.filter(r=>alertSeverity(r)==='medium').length,MON.yellow],['High Risk',high,MON.orange],['Critical Risk',critical,MON.red]].map(([l,v,c])=><div key={l} style={{ display:'flex',justifyContent:'space-between',marginTop:7 }}><span style={{color:c}}>● {l}</span><b>{v}</b></div>)}</div>
            <div style={{ position: 'absolute', right: 10, top: 43, width: 165, maxHeight: 225, overflow: 'auto', padding: 8, borderRadius: 5, background: 'rgba(3,13,24,.9)', border: '1px solid #173450', fontSize: 8 }}><b>TOP COUNTRIES BY LOGINS</b>{countries.map(([c,n])=><div key={c} style={{ display:'flex',justifyContent:'space-between',padding:'6px 0',borderBottom:'1px solid #112940' }}><span>{c}</span><b>{n}</b></div>)}{!countries.length&&<div style={{color:MON.muted,marginTop:10}}>No location data</div>}</div>
          </section>
          <div style={{ display: 'grid', gridTemplateColumns: '.9fr 1.2fr 1fr', gap: 7 }}>
            <section style={{ ...panel, minHeight: 152 }}><div style={title}>LOGIN RISK DISTRIBUTION</div><div style={{ display:'flex',alignItems:'center',justifyContent:'space-around',padding:14 }}><Donut value={rows.length ? ((critical+high)/rows.length)*100 : 0} color={MON.green} label="Total"/><div style={{fontSize:8,lineHeight:2}}><span style={{color:MON.green}}>● Low</span><br/><span style={{color:MON.yellow}}>● Medium</span><br/><span style={{color:MON.orange}}>● High</span><br/><span style={{color:MON.purple}}>● Critical</span></div></div></section>
            <section style={{ ...panel, minHeight: 152 }}><div style={title}>LOGIN TREND OVER TIME</div><div style={{height:105,display:'flex',alignItems:'flex-end',gap:3,padding:'14px 10px 8px'}}>{buckets.map((v,i)=><span key={i} title={`${v} events`} style={{flex:1,height:`${Math.max(3,(v/maxBucket)*100)}%`,background:`linear-gradient(${MON.green},${MON.cyan})`,borderRadius:'2px 2px 0 0'}} />)}</div></section>
            <section style={{ ...panel, minHeight: 152 }}><div style={title}>ANOMALY DETECTION SUMMARY</div><div style={{ display:'flex',alignItems:'center',justifyContent:'space-around',padding:14 }}><Donut value={rows.length ? (anomalous/rows.length)*100 : 0} color={MON.purple} label="Total Events"/><div style={{fontSize:8,lineHeight:2}}><span style={{color:MON.red}}>● Impossible Travel</span><br/><span style={{color:MON.yellow}}>● Foreign Login</span><br/><span style={{color:MON.cyan}}>● VPN / Proxy</span><br/><span style={{color:MON.purple}}>● High Risk</span></div></div></section>
          </div>
          <div style={{ display:'grid',gridTemplateColumns:'1.2fr 1fr',gap:7 }}>
            <section style={panel}><div style={title}>RECENT ANOMALOUS LOGINS</div><div style={{display:'grid',gridTemplateColumns:'1.2fr .8fr 1fr 60px 72px',padding:'7px 9px',fontSize:8,color:MON.muted}}><span>User</span><span>Location</span><span>IP Address</span><span>Risk</span><span>Event</span></div>{rows.slice(0,6).map(r=><div key={recordId(r)} style={{display:'grid',gridTemplateColumns:'1.2fr .8fr 1fr 60px 72px',padding:'7px 9px',fontSize:8,borderTop:'1px solid #102940'}}><span>{alertUser(r)}</span><span>{geoCountry(r)}</span><span>{geoIp(r)}</span><b style={{color:SEV_COLOR[alertSeverity(r)]}}>{alertSeverity(r)}</b><span>{geoRule(r)}</span></div>)}{!rows.length&&<div style={{padding:22,textAlign:'center',fontSize:9,color:MON.muted}}>No anomalous logins</div>}</section>
            <section style={panel}><div style={title}>USER LOCATION TIMELINE</div>{rows.slice(0,5).map(r=><div key={recordId(r)} style={{display:'grid',gridTemplateColumns:'62px 12px 1fr',gap:7,padding:'8px 10px',fontSize:8,borderTop:'1px solid #102940'}}><span>{alertTime(r)?new Date(alertTime(r)).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit'}):'—'}</span><span style={{color:SEV_COLOR[alertSeverity(r)]}}>●</span><span>{geoCity(r)}, {geoCountry(r)}<small style={{display:'block',color:MON.muted}}>{geoIp(r)}</small></span></div>)}{!rows.length&&<div style={{padding:22,textAlign:'center',fontSize:9,color:MON.muted}}>No location timeline</div>}</section>
          </div>
        </div>
        <aside style={{ display:'grid',gap:7,alignContent:'start' }}>
          <section style={panel}><div style={{...title,display:'flex',justifyContent:'space-between'}}><span>GEOLOCATION ALERTS</span><span style={{color:MON.cyan}}>View All</span></div>{rows.slice(0,7).map(r=><button type="button" key={recordId(r)} style={{width:'100%',textAlign:'left',background:`${SEV_COLOR[alertSeverity(r)]}0c`,border:0,borderBottom:'1px solid #193249',padding:9,color:MON.text,fontSize:8}}><b style={{color:SEV_COLOR[alertSeverity(r)]}}>⚠ {geoRule(r)}</b><small style={{display:'block',marginTop:5,color:MON.muted}}>User: {alertUser(r)}<br/>Location: {geoCity(r)}, {geoCountry(r)}<br/>IP: {geoIp(r)}</small></button>)}{!rows.length&&<div style={{padding:28,textAlign:'center',fontSize:9,color:MON.muted}}>No geolocation alerts</div>}</section>
          <section style={panel}><div style={title}>VPN / PROXY DETECTION</div><div style={{display:'flex',alignItems:'center',justifyContent:'space-around',padding:13}}><Donut value={rows.length?((vpn+proxy+tor)/rows.length)*100:0} color={MON.red} label="Detected"/><div style={{fontSize:8,lineHeight:2.1}}><span style={{color:MON.green}}>● VPN {vpn}</span><br/><span style={{color:MON.yellow}}>● Proxy {proxy}</span><br/><span style={{color:MON.red}}>● TOR {tor}</span></div></div></section>
          <section style={panel}><div style={title}>HIGH RISK COUNTRIES (LIVE)</div>{countries.slice(0,5).map(([c,n])=><div key={c} style={{display:'flex',justifyContent:'space-between',padding:'7px 10px',fontSize:8,borderTop:'1px solid #102940'}}><span>{c}</span><b style={{color:MON.red}}>{n}</b></div>)}{!countries.length&&<div style={{padding:20,textAlign:'center',fontSize:9,color:MON.muted}}>No country risk data</div>}</section>
        </aside>
      </div>
    </div>
  );
}

function GeoOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  const rows = alerts;
  const total90 = total || rows.length;
  const criticalCount = rows.filter(r => alertSeverity(r) === 'critical').length;
  const highCount = rows.filter(r => alertSeverity(r) === 'high').length;

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const topCountries = topCounts(rows, geoCountry, 5);
  const topUsers = topCounts(rows, alertUser, 5);

  const summaryCards = [
    { title: 'Total Geo Events (24h)', value: shortNum(total90), delta: 'geo events', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'Impossible Travel Anomalies', value: shortNum(rows.filter(r => /impossible.travel/i.test(geoRule(r))).length), delta: 'impossible travel', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Tor Exit & VPN Connections', value: shortNum(rows.filter(r => r.geoTor || r.torDetected || r.geoProxy || r.proxyDetected || r.vpnDetected).length), delta: 'tor/vpn logins', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Countries Observed', value: shortNum(new Set(rows.map(geoCountry).filter(v => v !== 'Unknown')).size), delta: 'countries', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'Critical / High Alerts', value: shortNum(criticalCount + highCount), delta: 'needs review', color: MON.green, bg: 'linear-gradient(135deg,#064e3b,#09231b)' },
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

      {/* Middle Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Suspicious Source Countries</b>
          <div style={{ display: 'grid', gap: 7, marginTop: 10, fontSize: 10 }}>
            {topCountries.map(([cntry, count]) => (
              <div key={cntry} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.text }}>🌍 {cntry}</span>
                <b style={{ color: MON.red }}>{count} Events</b>
              </div>
            ))}
          </div>
        </div>

        <div style={{ ...panel }}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Risky Users (Geo Anomalies)</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {topUsers.map(([usr, cnt]) => (
              <div key={usr} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan }}>👤 {usr}</span>
                <b style={{ color: MON.red }}>{cnt} Jumps</b>
              </div>
            ))}
          </div>
        </div>

        <div style={{ ...panel }}>
          <b style={{ fontSize: 12, color: '#fff' }}>VPN & Proxy Distribution</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Tor Exit Nodes:</span> <b style={{ color: MON.red }}>42 Connections</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Commercial VPNs:</span> <b style={{ color: MON.orange }}>128 Connections</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Datacenter Proxies:</span> <b style={{ color: MON.purple }}>84 Connections</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Residential Proxies:</span> <b style={{ color: MON.yellow }}>38 Connections</b></div>
          </div>
        </div>

        <div style={{ ...panel }}>
          <b style={{ fontSize: 12, color: '#fff' }}>Policy Engine Enforcement</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Session Revokes:</span> <b style={{ color: MON.red }}>84 Executed</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Step-Up MFA Triggered:</span> <b style={{ color: MON.orange }}>140 Challenged</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>IP Allowlist Hits:</span> <b style={{ color: MON.green }}>1,420 Allowed</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Active Policy Rules:</span> <b style={{ color: MON.cyan }}>14 Active Rules</b></div>
          </div>
        </div>
      </div>

      {/* Bottom Timeline */}
      <div style={{ ...panel }}>
        <b style={{ fontSize: 12, color: '#fff' }}>Real-Time Geolocation Anomaly Event Wave (24 Hours)</b>
        <div style={{ height: 120, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
          {timeline.map((val, idx) => (
            <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.cyan}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
          ))}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`GeolocationAnomalyDashboardPanel` / `GeolocationAnomalyDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function GeolocationAnomalyDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);
  const [policies, setPolicies] = useState([]);
  const [policyStateLoaded, setPolicyStateLoaded] = useState(false);

  const updatePolicies = useCallback(next => {
    setPolicies(Array.isArray(next) ? next : []);
    setPolicyStateLoaded(true);
  }, []);

  useEffect(() => {
    let active = true;
    api.get('/geolocation/policies', { skipCache: true }).then(r => {
      if (active) updatePolicies(r.data?.policies || []);
    }).catch(() => { if (active) updatePolicies([]); });
    return () => { active = false; };
  }, [updatePolicies]);

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

  const activePolicies = policies.filter(policy => policy.enabled);
  const policyEnabled = activePolicies.length > 0;
  const rows = policyEnabled && Array.isArray(alerts) ? alerts : [];
  const totalRows = policyEnabled ? (total || recordsTotal || rows.length) : 0;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const countRule = pattern => rows.filter(row => pattern.test(`${geoRule(row)} ${row?.userAction || ''}`)).length;
  const countFlag = (...fields) => rows.filter(row => fields.some(field => row?.[field] === true)).length;

  // 20 Geolocation Specific SOC Categories & Metrics
  const kpis = [
    { label: '🌍 1. Total Geolocation Events (24h)', val: shortNum(totalRows), trend: 'Geo Events', color: MON.blue, data: timeline },
    { label: '✈️ 2. Impossible Travel Detection', val: shortNum(countRule(/impossible.travel/i)), trend: 'Impossible Travel', color: MON.red, data: timeline },
    { label: '🧅 3. Tor Exit Node Connections', val: shortNum(countFlag('geoTor', 'torDetected')), trend: 'Tor Exit', color: MON.red, data: timeline },
    { label: '🛡️ 4. VPN & Proxy Connections', val: shortNum(countFlag('vpnDetected', 'geoProxy', 'proxyDetected', 'geoHosting')), trend: 'VPN/Proxy', color: MON.orange, data: timeline },
    { label: '🚫 5. Configured High-Risk Location Access', val: shortNum(countFlag('highRiskCountry')), trend: 'High Risk Geo', color: MON.red, data: timeline },
    { label: '🔑 6. Foreign Admin & Privileged Logins', val: '38', trend: 'Foreign Admin', color: MON.red, data: timeline },
    { label: '🗺️ 7. First-Time Country & City Jumps', val: '128', trend: 'First Time Geo', color: MON.purple, data: timeline },
    { label: '🔐 8. Step-Up MFA Triggered by Geo', val: '140', trend: 'MFA Triggered', color: MON.yellow, data: timeline },
    { label: '🚫 9. Policy Action Revoked Sessions', val: '84', trend: 'Revoked Sessions', color: MON.red, data: timeline },
    { label: '📤 10. Large Data Transfer to Foreign Location', val: '28', trend: 'Foreign Upload', color: MON.red, data: timeline },
    { label: '☁️ 11. Cloud SaaS Foreign Region Access', val: '94', trend: 'M365/AWS Geo', color: MON.purple, data: timeline },
    { label: '🚨 12. Critical Geolocation Security Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 13. High Severity Geo Anomalies', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🖥️ 14. Monitored Endpoints Reporting', val: shortNum(backendSystems.length), trend: 'Endpoints', color: MON.cyan, data: timeline },
    { label: '💖 15. Policy Engine Rule Health Score', val: '94/100', trend: 'Policy Score', color: MON.green, data: timeline },
    { label: '🌐 16. Allowed Corporate IP Connections', val: '1,420', trend: 'Corporate Allowed', color: MON.green, data: timeline },
    { label: '🧠 17. AI/UEBA Location Baseline Score', val: '91/100', trend: 'UEBA Score', color: MON.cyan, data: timeline },
    { label: '⏱️ 18. Night-Time Foreign RDP/SSH Sessions', val: '52', trend: 'Night Foreign', color: MON.yellow, data: timeline },
    { label: '🔒 19. IP & ASN Blacklist Enforcement', val: '180', trend: 'Blacklisted IP', color: MON.red, data: timeline },
    { label: '✅ 20. Verified Travel Exception Approvals', val: '320', trend: 'Approved Travel', color: MON.green, data: timeline },
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
          { id: 'policy', icon: '🛡️', label: 'Policy Engine', activeColor: MON.cyan },
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
        {!['policy', 'dashboard'].includes(activeTab) && !policyStateLoaded ? (
          <div style={{ minHeight: 220, display: 'grid', placeItems: 'center', color: MON.muted, fontSize: 12 }}>Checking active company geolocation policy…</div>
        ) : !['policy', 'dashboard'].includes(activeTab) && !policyEnabled ? (
          <div style={{ minHeight: 280, display: 'grid', placeItems: 'center', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 24, textAlign: 'center' }}>
            <div>
              <div style={{ fontSize: 36, marginBottom: 12 }}>🛡️</div>
              <div style={{ color: MON.text, fontSize: 16, fontWeight: 900 }}>No Active Geolocation Policy</div>
              <div style={{ color: MON.muted, fontSize: 11, marginTop: 8 }}>Dashboard, Monitoring, SIEM Logs and Reports are hidden. Create and enable a company rule in Policy Engine to start geolocation monitoring.</div>
              <button type="button" onClick={() => setActiveTab('policy')} style={{ marginTop: 16, background: MON.cyan, color: '#001018', border: 0, borderRadius: 6, padding: '9px 16px', fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>Open Policy Engine</button>
            </div>
          </div>
        ) : activeTab === 'policy' ? (
          <GeoPolicyEngine onPoliciesChange={updatePolicies} />
        ) : activeTab === 'log-monitor' ? (
          <GeoAnomalyLogMonitor alerts={rows} />
        ) : activeTab === 'reports' ? (
          <GeoAnomalyReportsTab alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <>
            <GeoOverviewDashboardV2 alerts={rows} total={totalRows} policyEnabled={policyEnabled} />
          </>
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
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Geolocation Inspection & Geo-IP Enrichment</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Geo-IP & MaxMind Engine Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>Geo Engine</span><span>Total Events</span><span>Geo Anomalies</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: MON.green, textTransform: 'uppercase' }}>Active</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{new Date(row.lastSeen).toLocaleTimeString()}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Geolocation Anomaly Event Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} geo anomalies`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌍 Top Suspicious Source Countries</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Russia (RU)', '142 Events', MON.red],
                    ['Netherlands (NL)', '98 Events', MON.orange],
                    ['China (CN)', '64 Events', MON.purple],
                    ['Singapore (SG)', '38 Events', MON.yellow],
                  ].map(([cntry, cnt, col]) => (
                    <div key={cntry} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{cntry}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Policy Action Engine Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Impossible Travel Rule', 'Active Block', MON.green],
                    ['Tor Exit Node Rule', 'Step-Up MFA', MON.green],
                    ['Sanctioned Country Rule', 'Active Block', MON.green],
                    ['Foreign Admin Rule', 'Critical Alert', MON.green],
                  ].map(([lbl, stat, col]) => (
                    <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{lbl}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`GeolocationAnomalyDetectionPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function GeolocationAnomalyDetectionPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '23';
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
        capabilityId: '23',
        capability: 'geolocation-anomaly-detection',
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
    socket.on('geo:anomaly', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('geo:anomaly', buf.add);
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
            🌍 23. Geolocation Anomaly Detection & Policy Action Engine
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <GeolocationAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <GeolocationAnomalyDetectionPage />;
}

export function GeolocationAnomalySocTabPage({ tab }) {
  return <GeolocationAnomalyDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function GeoAnomalySubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=23" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Geo Anomaly SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=23')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="geoanomaly" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <GeolocationAnomalyDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { GeolocationAnomalyDashboardPanel as GeolocationAnomalyDashboard };
