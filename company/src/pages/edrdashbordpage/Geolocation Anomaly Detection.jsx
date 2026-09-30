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
import CapabilityReportsPanel from './CapabilityReportsPanel';
import L from 'leaflet';
import 'leaflet/dist/leaflet.css';

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

function ajnatSystemKey(row = {}) {
  return String(row.systemId?._id || row.systemId || row.endpointId || row.agentId || '');
}

function systemRecordKey(system = {}) {
  return String(system._id || system.systemId?._id || system.systemId || system.endpointId || system.agentId || '');
}

function gpsStatusOf(row = {}) {
  return String(row.gpsStatus || row.rawEvent?.gpsStatus || '').toLowerCase();
}

function gpsProviderOf(row = {}) {
  return String(row.gpsProvider || row.rawEvent?.gpsProvider || 'unknown');
}

function gpsAccuracyOf(row = {}) {
  const value = Number(row.gpsAccuracyMeters ?? row.rawEvent?.gpsAccuracyMeters);
  return Number.isFinite(value) && value >= 0 ? value : null;
}

const GEO_POLICY_CATEGORIES = [
  'Country-Based', 'Device GPS Tracking', 'Location-Based', 'User-Based', 'Authentication',
  'Impossible Travel', 'VPN / Proxy / Tor', 'Corporate Network', 'Risk Score Matrix', 'Time + Location',
];

const GEO_PASSIVE_ACTIONS = ['ALLOW & AUDIT', 'LOG & MONITOR', 'ALERT & NOTIFY SOC'];
const GEO_ENFORCEMENT_ACTIONS = ['BLOCK & IP BAN', 'ENDPOINT ISOLATION', 'CRITICAL BLOCK & SOC ESCALATION'];
const actionsForGeoCategory = category => {
  if (category === 'Device GPS Tracking') return ['ALLOW & AUDIT', 'LOG & MONITOR'];
  if (category === 'Location-Based') return [...GEO_PASSIVE_ACTIONS, 'LOGOUT ACCOUNT OUTSIDE ALLOWED RADIUS', 'ENDPOINT ISOLATION'];
  return [...GEO_PASSIVE_ACTIONS, ...GEO_ENFORCEMENT_ACTIONS];
};

function isAjnatGeolocationEvent(row = {}) {
  const ruleId = String(row.ruleId || row.rule_id || row.rawEvent?.ruleId || row.rawEvent?.rule_id || '').toUpperCase();
  return Boolean(ajnatSystemKey(row) && (
    ruleId.startsWith('GEO_') || ruleId === 'GPS_LOCATION_TELEMETRY'
    || Number(row.capabilityId || row.rawEvent?.capabilityId) === 23
    || (row.capabilityIds || row.rawEvent?.capabilityIds || []).map(Number).includes(23)
  ));
}

function isAjnatGpsEvent(row = {}) {
  const ruleId = String(row.ruleId || row.rule_id || row.rawEvent?.ruleId || row.rawEvent?.rule_id || '').toUpperCase();
  const source = String(row.source || row.rawEvent?.source || '').toLowerCase();
  const hasGpsEvidence = ['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId)
    || source === 'gps-location'
    || row.gpsLat != null || row.rawEvent?.gpsLat != null
    || Boolean(row.gpsProvider || row.rawEvent?.gpsProvider || row.gpsStatus || row.rawEvent?.gpsStatus);
  return Boolean(ajnatSystemKey(row) && hasGpsEvidence);
}

function policyCategoryOf(row = {}) {
  const explicit = row.policyCategory || row.rawEvent?.policyCategory;
  if (explicit) return String(explicit);
  const ruleId = String(row.ruleId || row.rule_id || row.rawEvent?.ruleId || row.rawEvent?.rule_id || '').toUpperCase();
  if (['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId)) return 'Device GPS Tracking';
  if (/FENCE_RADIUS|LOCATION_MISMATCH/.test(ruleId)) return 'Location-Based';
  if (/HIGH_RISK_COUNTRY|FENCE_VIOLATION/.test(ruleId)) return 'Country-Based';
  if (/IMPOSSIBLE_TRAVEL/.test(ruleId)) return 'Impossible Travel';
  if (/PROXY|VPN|TOR|HOSTING/.test(ruleId)) return 'VPN / Proxy / Tor';
  if (/FAILED_LOGIN|AUTH/.test(ruleId)) return 'Authentication';
  if (/UNUSUAL_LOGIN|MULTIPLE_GEOLOGINS|NEW_DEVICE/.test(ruleId)) return 'User-Based';
  if (/CORPORATE_NETWORK/.test(ruleId)) return 'Corporate Network';
  if (/RISK_SCORE/.test(ruleId)) return 'Risk Score Matrix';
  if (/TIME_LOCATION/.test(ruleId)) return 'Time + Location';
  return '';
}

function policyBlocked(row = {}) {
  const raw = row.rawEvent || {};
  const outcome = String(row.containmentStatus || raw.containmentStatus || row.actionTaken || row.action_taken || raw.action_taken || '').toLowerCase();
  return row.blocked === true || raw.blocked === true || ['blocked', 'isolated', 'logged_out'].includes(outcome);
}

function isQualifiedGpsFix(row = {}) {
  const lat = Number(row.gpsLat ?? row.rawEvent?.gpsLat);
  const lon = Number(row.gpsLon ?? row.rawEvent?.gpsLon);
  const accuracy = gpsAccuracyOf(row);
  return gpsStatusOf(row) === 'available'
    && Number.isFinite(lat) && lat >= -90 && lat <= 90
    && Number.isFinite(lon) && lon >= -180 && lon <= 180
    && accuracy != null && accuracy <= 50;
}

function isDisplayableGpsLocation(row = {}) {
  const lat = Number(row.gpsLat ?? row.rawEvent?.gpsLat);
  const lon = Number(row.gpsLon ?? row.rawEvent?.gpsLon);
  const accuracy = gpsAccuracyOf(row);
  return ['available', 'inaccurate'].includes(gpsStatusOf(row))
    && Number.isFinite(lat) && lat >= -90 && lat <= 90
    && Number.isFinite(lon) && lon >= -180 && lon <= 180
    && accuracy != null;
}

function currentGpsRowFromSystem(system = {}) {
  const status = String(system.gpsStatus || '').toLowerCase();
  if (!status || !system.gpsObservedAt) return null;
  return {
    _id: `current-gps-${systemRecordKey(system)}`,
    systemId: system._id || system.systemId,
    endpointId: system.endpointId,
    agentId: system.agentId,
    agentName: system.agentName || system.name,
    hostname: system.hostname || system.name,
    os: system.os,
    osType: system.osType,
    ruleId: status === 'available' ? 'GPS_LOCATION_TELEMETRY' : 'GEO_GPS_STATUS',
    source: 'gps-location',
    gpsLat: system.gpsLat,
    gpsLon: system.gpsLon,
    gpsAccuracyMeters: system.gpsAccuracyMeters,
    gpsAltitudeMeters: system.gpsAltitudeMeters,
    gpsProvider: system.gpsProvider,
    gpsStatus: status,
    gpsReason: system.gpsReason,
    gpsObservedAt: system.gpsObservedAt,
    createdAt: system.gpsObservedAt,
    timestamp: system.gpsObservedAt,
    severity: 'low',
    _currentGpsState: true,
  };
}

function buildAjnatGpsMetrics(rows = [], systems = [], policies = []) {
  const geoRows = (Array.isArray(rows) ? rows : []).filter(isAjnatGeolocationEvent)
    .sort((left, right) => new Date(alertTime(right) || 0) - new Date(alertTime(left) || 0));
  const gpsRows = geoRows.filter(isAjnatGpsEvent)
    .sort((left, right) => new Date(alertTime(right) || 0) - new Date(alertTime(left) || 0));
  const currentGpsRows = (Array.isArray(systems) ? systems : [])
    .map(currentGpsRowFromSystem)
    .filter(Boolean);
  const latestBySystem = new Map();
  [...currentGpsRows, ...gpsRows]
    .sort((left, right) => new Date(alertTime(right) || 0) - new Date(alertTime(left) || 0))
    .forEach(row => {
    const key = ajnatSystemKey(row);
    if (key && !latestBySystem.has(key)) latestBySystem.set(key, row);
  });
  const latestRows = [...latestBySystem.values()];
  const statusCount = status => gpsRows.filter(row => gpsStatusOf(row) === status).length;
  const providerCount = pattern => gpsRows.filter(row => pattern.test(gpsProviderOf(row))).length;
  const accuracySamples = gpsRows.map(gpsAccuracyOf).filter(value => value != null);
  const qualifiedLatestRows = latestRows.filter(isQualifiedGpsFix);
  const displayableLatestRows = latestRows.filter(isDisplayableGpsLocation);
  const inaccurateLatestRows = latestRows.filter(row => gpsStatusOf(row) === 'inaccurate');
  const unavailableLatestRows = latestRows.filter(row => !['available', 'inaccurate'].includes(gpsStatusOf(row)));
  const onlineSystems = (Array.isArray(systems) ? systems : []).filter(system => system.isOnline === true || system.agentOk === true || system.online === true || String(system.status || '').toLowerCase() === 'online');
  const enabledPolicies = (Array.isArray(policies) ? policies : []).filter(policy => policy.enabled);
  const targetedAgentIds = new Set(enabledPolicies.flatMap(policy => Array.isArray(policy.conditions?.systemIds) ? policy.conditions.systemIds.map(String) : []));
  const providerCounts = gpsRows.reduce((counts, row) => {
    const provider = gpsProviderOf(row);
    counts.set(provider, (counts.get(provider) || 0) + 1);
    return counts;
  }, new Map());
  const categoryStats = GEO_POLICY_CATEGORIES.map(category => {
    const categoryRows = geoRows.filter(row => policyCategoryOf(row) === category);
    return {
      category,
      events: categoryRows.length,
      blocked: categoryRows.filter(policyBlocked).length,
      latestAt: categoryRows[0] ? alertTime(categoryRows[0]) : null,
    };
  });
  return {
    rows: gpsRows,
    policyRows: geoRows,
    categoryStats,
    latestRows,
    qualifiedLatestRows,
    displayableLatestRows,
    totalEvents: gpsRows.length,
    reportingAgents: latestRows.length,
    qualifiedAgents: qualifiedLatestRows.length,
    inaccurateAgents: inaccurateLatestRows.length,
    unavailableAgents: unavailableLatestRows.length,
    availableEvents: statusCount('available'),
    inaccurateEvents: statusCount('inaccurate'),
    permissionDeniedEvents: statusCount('permission_denied'),
    unavailableEvents: gpsRows.filter(row => ['sensor_unavailable', 'unsupported', 'accuracy_unknown'].includes(gpsStatusOf(row))).length,
    providerErrorEvents: statusCount('provider_error'),
    timeoutEvents: statusCount('provider_timeout'),
    averageAccuracy: accuracySamples.length ? Math.round(accuracySamples.reduce((sum, value) => sum + value, 0) / accuracySamples.length) : null,
    bestAccuracy: accuracySamples.length ? Math.min(...accuracySamples) : null,
    worstAccuracy: accuracySamples.length ? Math.max(...accuracySamples) : null,
    geoclueEvents: providerCount(/geoclue/i),
    gnssEvents: providerCount(/gpsd|gnss/i),
    windowsEvents: providerCount(/windows/i),
    macEvents: providerCount(/macos|corelocation/i),
    onlineAgents: onlineSystems.length,
    offlineAgents: Math.max(0, (Array.isArray(systems) ? systems.length : 0) - onlineSystems.length),
    totalPolicies: Array.isArray(policies) ? policies.length : 0,
    enabledPolicies: enabledPolicies.length,
    targetedAgents: targetedAgentIds.size,
    providerCounts: [...providerCounts.entries()].sort((left, right) => right[1] - left[1]),
    timeline: buildBuckets(gpsRows, 12, 24),
    latestAt: gpsRows[0] ? alertTime(gpsRows[0]) : null,
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

function relativeTime(value) {
  const timestamp = value ? new Date(value).getTime() : NaN;
  if (!Number.isFinite(timestamp)) return 'Unknown time';
  const seconds = Math.max(0, Math.round((Date.now() - timestamp) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)} hour ago`;
  return `${Math.floor(seconds / 86400)} day ago`;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name
    || row?.rawEvent?.raw?.geoForensics?.endpoint?.hostname || '—';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName
    || row?.rawEvent?.raw?.geoForensics?.authentication?.username || '—';
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
  return row?.srcip || row?.srcIp || row?.sourceIp || row?.ip || row?.clientIp || row?.rawEvent?.srcip
    || row?.liveForensics?.network?.localIp || row?.rawEvent?.raw?.geoForensics?.network?.localIp || '—';
}

function geoCountry(row) {
  return row?.geoCountry || row?.country || row?.sourceGeo?.country || row?.rawEvent?.geoCountry
    || row?.liveForensics?.network?.country || 'Unknown';
}

function geoCity(row) {
  return row?.geoCity || row?.city || row?.sourceGeo?.city || row?.rawEvent?.geoCity
    || row?.liveForensics?.network?.city || 'Unknown';
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
export function GeoForensicDetailModal({ log: initialLog, companyId, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);
  const [liveLog, setLiveLog] = useState(initialLog);
  const [lastLiveSync, setLastLiveSync] = useState(null);
  const [liveError, setLiveError] = useState('');
  const [refreshTick, setRefreshTick] = useState(0);

  useEffect(() => {
    setLiveLog(initialLog);
  }, [initialLog]);

  useEffect(() => {
    const eventId = String(initialLog?._id || '');
    if (!/^[a-f\d]{24}$/i.test(eventId)) return undefined;
    let active = true;
    const loadLiveEvent = async () => {
      try {
        const response = await api.get(`/geolocation/events/${eventId}`, {
          params: companyId ? { companyId } : {}, skipCache: true,
        });
        if (!active || !response.data?.event) return;
        setLiveLog(response.data.event);
        setLastLiveSync(new Date());
        setLiveError('');
      } catch (error) {
        if (active) setLiveError(error.response?.data?.message || 'Live event refresh unavailable');
      }
    };
    loadLiveEvent();
    const timer = setInterval(loadLiveEvent, 5000);
    return () => { active = false; clearInterval(timer); };
  }, [initialLog?._id, companyId, refreshTick]);

  if (!liveLog) return null;
  const log = liveLog;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const raw = log.rawEvent || log.raw || {};
  const evidenceRoots = [log, raw, raw.raw, raw.sourceAlert, raw.raw?.sourceAlert, log.responseAction].filter(Boolean);
  const field = (...keys) => {
    for (const key of keys) {
      for (const root of evidenceRoots) {
        const value = key.split('.').reduce((obj, part) => obj?.[part], root);
        if (value !== undefined && value !== null && value !== '') return value;
      }
    }
    return 'No matching live AJNAT evidence';
  };
  const agentField = (tab, key, ...fallbackKeys) => field(`liveForensics.${tab}.${key}`, `geoForensics.${tab}.${key}`, ...fallbackKeys);
  const yesNo = value => value === true ? 'Yes' : value === false ? 'No' : String(value || 'No matching live AJNAT evidence');
  const formatLiveTime = value => {
    const date = value ? new Date(value) : null;
    return date && !Number.isNaN(date.getTime()) ? date.toLocaleString() : String(value || 'No matching live AJNAT evidence');
  };
  const formatMeters = value => Number.isFinite(Number(value)) ? `${Number(value)} m` : String(value);
  const liveGpsStatus = field('systemId.gpsStatus', 'gpsStatus');
  const liveGpsProvider = field('systemId.gpsProvider', 'gpsProvider');
  const liveGpsLatitude = field('systemId.gpsLat', 'gpsLat', 'geoLat', 'latitude');
  const liveGpsLongitude = field('systemId.gpsLon', 'gpsLon', 'geoLon', 'longitude');
  const liveGpsAccuracy = field('systemId.gpsAccuracyMeters', 'gpsAccuracyMeters');
  const liveGpsObservedAt = field('systemId.gpsObservedAt', 'gpsObservedAt');
  const liveGpsEvidence = {
    ...log,
    gpsStatus: liveGpsStatus,
    gpsLat: liveGpsLatitude,
    gpsLon: liveGpsLongitude,
    gpsAccuracyMeters: liveGpsAccuracy,
  };
  const gpsQuality = isQualifiedGpsFix(liveGpsEvidence)
    ? 'Precise (eligible for policy enforcement)'
    : isDisplayableGpsLocation(liveGpsEvidence)
      ? 'Approximate (display only, not enforced)'
      : 'No displayable coordinate reported';
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

  const handleAction = async (actionName, actionType) => {
    if (!actionType || typeof onAction !== 'function' || !log?._id) {
      setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
      return;
    }
    try {
      await onAction(String(log._id), actionType);
      setActionSuccess(`Approved action submitted: ${actionName}`);
      setRefreshTick(value => value + 1);
    } catch (error) {
      setActionSuccess(error?.message || `Failed to submit: ${actionName}`);
    }
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
                <span style={{ fontSize: 10, fontWeight: 800, color: liveError ? MON.orange : MON.green }}>
                  ● {liveError ? 'LIVE REFRESH RETRYING' : `LIVE · ${lastLiveSync ? lastLiveSync.toLocaleTimeString() : 'SYNCING'}`}
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
                  ['Detection Trigger', agentField('overview', 'detectionTrigger', 'ruleName', 'ruleId'), sevColor],
                  ['Risk Score', `${agentField('overview', 'riskScore', 'riskScore')} / 100`, MON.red],
                  ['Source Geography', `${geoCity(log)}, ${geoCountry(log)}`, MON.cyan],
                  ['Network Proxy / Tor', geoVpnType(log), MON.purple],
                  ['GPS State', `${liveGpsStatus} · ${formatMeters(liveGpsAccuracy)}`, gpsStatusOf(liveGpsEvidence) === 'available' ? MON.green : MON.orange],
                  ['Policy Category', agentField('policy', 'category', 'policyCategory'), MON.cyan],
                  ['Agent Evidence', agentField('overview', 'evidenceSource', 'source'), MON.yellow],
                  ['Collected At', formatLiveTime(agentField('overview', 'collectedAt', 'gpsObservedAt')), MON.green],
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
              <DetailGrid rows={[
                ['Event Status', agentField('actions', 'agentDisposition', 'status')], ['Policy Action', agentField('policy', 'action', 'policyAction', 'action_taken', 'actionTaken')], ['Action Status', field('policyActionStatus')],
                ['Containment Status', agentField('actions', 'containmentStatus', 'containmentStatus')], ['Blocked', yesNo(agentField('actions', 'blocked', 'blocked'))], ['Response Error', agentField('actions', 'responseError', 'responseAction.errorDetail')],
                ['Latest Response', agentField('actions', 'responseType', 'responseAction.actionType')], ['Response State', agentField('actions', 'responseStatus', 'responseAction.status')], ['Agent Recommendation', agentField('actions', 'recommendedAction')],
              ]} />
              {actionSuccess && <div style={{ color: actionSuccess.startsWith('Failed') || actionSuccess.startsWith('Not sent') ? MON.orange : MON.green, fontSize: 11 }}>{actionSuccess}</div>}
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Policy Action Engine Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction(`Lock Account ${alertUser(log)}`, 'lock_account')} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔐 Lock Account
                  </button>
                  <button type="button" onClick={() => handleAction(`Force Logout ${alertUser(log)}`, 'force_logoff')} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Force Account Logout
                  </button>
                  <button type="button" onClick={() => handleAction(`Isolate Host ${alertHost(log)}`, 'isolate')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Host Endpoint
                  </button>
                  <button type="button" onClick={() => handleAction('Approve Authorized Travel Exception', 'ignore')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Approve Travel Exception
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'geointel' && (
            <div style={{ display: 'grid', gap: 14 }}>
              <DetailGrid rows={[
                ['Agent Local IP', agentField('network', 'localIp', 'srcip', 'sourceIp'), MON.yellow], ['Network Interface', agentField('network', 'interface')], ['Country', geoCountry(log), MON.cyan],
                ['Country Code', agentField('network', 'countryCode', 'geoCountryCode')], ['Region', agentField('network', 'region', 'geoRegion', 'region')], ['City', geoCity(log)],
                ['Latitude', liveGpsLatitude], ['Longitude', liveGpsLongitude], ['Timezone', agentField('network', 'timezone', 'geoTimezone', 'timezone')],
                ['Location Source', agentField('network', 'locationProvider', 'gpsProvider')], ['GPS Status', agentField('network', 'locationStatus', 'gpsStatus')], ['GPS Accuracy', formatMeters(liveGpsAccuracy)],
                ['GPS Quality', gpsQuality], ['GPS Reason', agentField('network', 'locationReason', 'systemId.gpsReason', 'gpsReason')], ['GPS Observed At', formatLiveTime(liveGpsObservedAt)],
                ['ISP', agentField('network', 'isp', 'geoISP', 'isp'), MON.purple], ['ASN / Route', agentField('network', 'asn', 'geoAsnRoute', 'asn')], ['Organization', agentField('network', 'organization', 'geoOrg', 'organization')],
                ['VPN Detected', yesNo(agentField('network', 'vpnDetected', 'vpnDetected'))], ['Proxy Detected', yesNo(agentField('network', 'proxyDetected', 'geoProxy', 'proxyDetected')), log.geoProxy ? MON.red : MON.text],
                ['Tor Detected', yesNo(agentField('network', 'torDetected', 'geoTor', 'torDetected'))], ['Hosting / Datacenter', yesNo(agentField('network', 'hostingDetected', 'geoHosting', 'datacenterIP')), log.geoHosting ? MON.orange : MON.text],
                ['Network Classification', agentField('network', 'networkClassification')], ['Threat Reputation', agentField('network', 'threatReputation', 'reputationScore', 'vtVerdict')],
              ]} />
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ color: MON.cyan, fontSize: 11, fontWeight: 900, marginBottom: 8 }}>Raw Geo Evidence</div>
                <pre style={{ margin: 0, color: MON.muted, fontSize: 10, lineHeight: 1.5, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 260, overflow: 'auto' }}>{JSON.stringify(raw, null, 2)}</pre>
              </div>
            </div>
          )}

          {activeTab === 'travel' && <DetailGrid rows={[
            ['Previous Coordinates', `${agentField('travel', 'previousLatitude')}, ${agentField('travel', 'previousLongitude')}`], ['Current Location', `${geoCity(log)}, ${geoCountry(log)}`],
            ['Previous Observation', agentField('travel', 'previousObservedAt')], ['Current Observation', formatLiveTime(agentField('timeline', 'observedAt'))],
            ['Travel Distance', agentField('travel', 'distanceMeters', 'geoFenceDistanceMeters')], ['Required Speed', agentField('travel', 'requiredSpeedKmh')],
            ['Allowed Radius', agentField('travel', 'allowedRadiusMeters', 'geoFenceRadiusMeters')], ['Inside Allowed Radius', yesNo(agentField('travel', 'insideAllowedRadius'))], ['Evaluation', agentField('travel', 'evaluation')],
            ['GPS Coordinates', `${agentField('travel', 'currentLatitude', 'gpsLat')}, ${agentField('travel', 'currentLongitude', 'gpsLon')}`], ['GPS Accuracy', agentField('travel', 'accuracyMeters', 'gpsAccuracyMeters')], ['Required Accuracy', agentField('travel', 'requiredAccuracyMeters')],
            ['GPS Quality', gpsQuality], ['Policy Action Status', field('policyActionStatus')], ['Containment Status', field('containmentStatus')],
          ]} />}

          {activeTab === 'auth' && <DetailGrid rows={[
            ['User', agentField('authentication', 'username', 'username', 'user'), MON.yellow], ['Login Action', agentField('authentication', 'loginAction', 'userAction')], ['Account Role', agentField('authentication', 'accountRole')],
            ['Authentication Type', agentField('authentication', 'authType', 'authType', 'loginType')], ['MFA Status', agentField('authentication', 'mfaStatus', 'mfaStatus')], ['Cloud Provider', agentField('authentication', 'cloudProvider')],
            ['Source IP', geoIp(log)], ['Timestamp', formatLiveTime(agentField('authentication', 'observedAt'))], ['Status', agentField('authentication', 'authResult', 'status')],
            ['AJNAT Host', alertHost(log)], ['Rule ID', field('ruleId')], ['Event Source', field('source')],
          ]} />}

          {activeTab === 'endpoint' && <DetailGrid rows={[
            ['Endpoint', agentField('endpoint', 'hostname', 'hostname'), MON.cyan], ['System ID', agentField('endpoint', 'systemId', 'systemId._id', 'systemId', 'endpointId')], ['Agent ID', agentField('endpoint', 'agentId', 'agentId')],
            ['Operating System', agentField('endpoint', 'operatingSystem', 'os', 'platform', 'systemId.os')], ['OS Version', agentField('endpoint', 'osVersion')], ['Architecture', agentField('endpoint', 'architecture')],
            ['Agent Process', agentField('endpoint', 'processName', 'processName')], ['Process ID', agentField('endpoint', 'processId', 'pid')], ['Parent Process ID', agentField('endpoint', 'parentProcessId', 'parentPid')],
            ['Agent Version', agentField('endpoint', 'agentVersion', 'systemId.agentVersion', 'agentVersion')], ['Agent Last Seen', formatLiveTime(agentField('endpoint', 'lastSeen', 'systemId.lastSeen', 'lastSeen'))], ['GPS Provider', liveGpsProvider],
          ]} />}

          {activeTab === 'data' && <DetailGrid rows={[
            ['Event Type', agentField('data', 'eventType', 'dataEventType')], ['Transfer Bytes', agentField('data', 'transferBytes', 'bytesTransferred')], ['Transfer Channel', agentField('data', 'transferChannel')],
            ['Classification', agentField('data', 'dataClassification', 'dataClassification')], ['Exfiltration Observed', yesNo(agentField('data', 'exfiltrationObserved'))], ['Collection Scope', agentField('data', 'scope')],
            ['Event Source', field('source')], ['Capability ID', field('capabilityId', 'capabilityIds')], ['Rule ID', field('ruleId')],
          ]} />}

          {activeTab === 'mitre' && <DetailGrid rows={[
            ['Technique ID', agentField('mitre', 'techniqueId', 'mitreTechnique', 'mitreId')], ['Technique Name', agentField('mitre', 'techniqueName', 'mitreTechniqueName')], ['Tactic', agentField('mitre', 'tactic', 'mitreTactic')],
            ['Evidence', agentField('mitre', 'reason', 'description')], ['Confidence', agentField('mitre', 'confidence', 'confidenceScore')], ['Threat Category', agentField('mitre', 'threatCategory', 'threatCategory')],
            ['Live Rule', geoRule(log)], ['Severity', sev], ['Risk Score', `${geoRiskScore(log)} / 100`],
          ]} />}

          {activeTab === 'policy' && <DetailGrid rows={[
            ['Policy ID', agentField('policy', 'policyId', 'policyId')], ['Policy Name', agentField('policy', 'policyName', 'policyName')], ['Triggered Rule', geoRule(log), MON.cyan],
            ['Risk Score', `${geoRiskScore(log)} / 100`], ['Severity', sev], ['Policy Action', agentField('policy', 'action', 'policyAction', 'action_taken', 'actionTaken')],
            ['Logout Requested', yesNo(agentField('policy', 'logoutRequested', 'systemLogoutRequested'))], ['Lock / Isolation Requested', yesNo(agentField('policy', 'lockIsolationRequested', 'geoFenceLockRequested'))], ['Result', agentField('policy', 'containmentStatus', 'containmentStatus', 'status')],
            ['Policy Category', agentField('policy', 'category', 'policyCategory')], ['Policy Triggered', yesNo(agentField('policy', 'triggered', 'policyTriggered'))], ['Action Status', agentField('policy', 'actionStatus', 'policyActionStatus')],
            ['IP Block Requested', yesNo(agentField('policy', 'ipBlockRequested', 'ipBlockRequested'))], ['Latest Response', agentField('actions', 'responseType', 'responseAction.actionType')], ['Response State', agentField('actions', 'responseStatus', 'responseAction.status')],
          ]} />}

          {activeTab === 'timeline' && <DetailGrid rows={[
            ['Observed At', formatLiveTime(agentField('timeline', 'observedAt', 'gpsObservedAt'))], ['Collected At', formatLiveTime(agentField('timeline', 'collectedAt', 'createdAt'))], ['Queued At', formatLiveTime(agentField('timeline', 'queuedAt'))],
            ['Event ID', field('eventId', '_id')], ['Rule ID', field('ruleId')], ['Related Agent Events', agentField('timeline', 'relatedEventCount')],
            ['Agent Stage', agentField('timeline', 'stage')], ['Latest Agent Activity', formatLiveTime(agentField('timeline', 'latestAgentActivityAt'))], ['Last Live Sync', lastLiveSync ? lastLiveSync.toLocaleString() : 'Syncing from server'],
          ]} />}
        </div>
      </div>
    </div>
  );
}

export function GeoPolicyWizardModal({ onClose, onSave, companyId, initialPolicy = null }) {
  const initial = initialPolicy?.conditions || {};
  const [name, setName] = useState(initialPolicy?.name || '');
  const [category, setCategory] = useState(initialPolicy?.category || 'Country-Based');
  const [severity, setSeverity] = useState(initialPolicy?.severity || 'Critical');
  const [action, setAction] = useState(initialPolicy?.action || 'ALERT & NOTIFY SOC');
  const [countries, setCountries] = useState((initial.countries || []).join(', '));
  const [maxSpeed, setMaxSpeed] = useState(String(initial.maxSpeed ?? '800'));
  const [riskCutoff, setRiskCutoff] = useState(String(initial.riskCutoff ?? '85'));
  const [systems, setSystems] = useState([]);
  const [systemsLoading, setSystemsLoading] = useState(true);
  const [systemsError, setSystemsError] = useState('');
  const [systemId, setSystemId] = useState(String(initial.systemIds?.[0] || ''));
  const [latitude, setLatitude] = useState(initial.latitude == null ? '' : String(initial.latitude));
  const [longitude, setLongitude] = useState(initial.longitude == null ? '' : String(initial.longitude));
  const [radiusMeters, setRadiusMeters] = useState(String(initial.radiusMeters ?? '500'));
  const [gpsTracking, setGpsTracking] = useState(initial.gpsTracking !== false);
  const [gpsIntervalSeconds, setGpsIntervalSeconds] = useState(String(initial.gpsIntervalSeconds ?? '300'));
  const [gpsAccuracyMeters, setGpsAccuracyMeters] = useState(String(Math.min(50, Number(initial.gpsAccuracyMeters ?? 50))));
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState('');

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

  const categories = GEO_POLICY_CATEGORIES;

  const actions = actionsForGeoCategory(category);

  useEffect(() => {
    if (!actions.includes(action)) setAction(actions[0]);
  }, [category, action, actions]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setFormError('');
    if (!name.trim()) return setFormError('Policy rule title required hai.');
    if (['Device GPS Tracking', 'Location-Based'].includes(category) && !systemId) return setFormError('Installed AJNAT agent select karein.');
    if (category === 'Location-Based' && (latitude === '' || longitude === '' || Number(radiusMeters) < 1)) return setFormError('Valid latitude, longitude aur allowed radius required hain.');
    if (['Device GPS Tracking', 'Location-Based'].includes(category)
      && (Number(gpsAccuracyMeters) < 5 || Number(gpsAccuracyMeters) > 50)) return setFormError('GPS accuracy 5 se 50 metres ke beech honi chahiye.');
    setSaving(true);
    try {
      await onSave({
        name: name.trim(),
        category,
        action,
        severity,
        enabled: true,
        conditions: {
          countries: countries.split(',').map(v => v.trim().toUpperCase()).filter(Boolean),
          maxSpeed: Number(maxSpeed), riskCutoff: Number(riskCutoff),
          systemIds: systemId ? [systemId] : [],
          latitude: category === 'Location-Based' ? Number(latitude) : null,
          longitude: category === 'Location-Based' ? Number(longitude) : null,
          radiusMeters: category === 'Location-Based' ? Number(radiusMeters) : null,
          outsideAction: action === 'LOGOUT ACCOUNT OUTSIDE ALLOWED RADIUS' ? 'SYSTEM_LOGOUT' : action,
          gpsTracking, gpsIntervalSeconds: Number(gpsIntervalSeconds), gpsAccuracyMeters: Number(gpsAccuracyMeters),
        }
      });
    } catch (error) {
      setFormError(error?.response?.data?.message || error?.message || 'Policy rule create nahi hui.');
    } finally {
      setSaving(false);
    }
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
                {initialPolicy ? 'Edit Geolocation Policy Rule' : 'Policy Rule Creator Wizard'}
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

          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Apply Rule To AJNAT Agent {['Device GPS Tracking', 'Location-Based'].includes(category) ? '*' : ''}
            </label>
            <div style={{ display: 'flex', gap: 8 }}>
              <select required={['Device GPS Tracking', 'Location-Based'].includes(category)} disabled={systemsLoading} value={systemId} onChange={e => setSystemId(e.target.value)} style={{ flex: 1, background: MON.card2, border: `1px solid ${systemsError ? MON.red : MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11 }}>
                <option value="">{systemsLoading ? 'Loading AJNAT agents…' : ['Device GPS Tracking', 'Location-Based'].includes(category) ? 'Select enrolled AJNAT agent' : 'All enrolled AJNAT agents'}</option>
                {systems.map(system => {
                  const hostname = system.hostname || system.name || system.agentName || 'Unknown host';
                  const os = system.osType || system.os || 'Unknown OS';
                  const ip = system.ip || system.ipAddress || 'No IP';
                  const status = system.isOnline || system.status === 'online' ? 'Online' : 'Offline';
                  return <option key={system._id} value={system._id}>{hostname} | {os} | {ip} | {status}</option>;
                })}
              </select>
              <button type="button" onClick={loadPolicySystems} disabled={systemsLoading} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 4, padding: '0 12px', cursor: systemsLoading ? 'wait' : 'pointer', fontSize: 11 }}>Refresh</button>
            </div>
            {systemsError && <div style={{ color: MON.red, fontSize: 10, marginTop: 5 }}>{systemsError}</div>}
            {!systemsLoading && !systemsError && !systems.length && <div style={{ color: MON.yellow, fontSize: 10, marginTop: 5 }}>Pehle AJNAT agent install/enrol karein aur heartbeat active hone dein.</div>}
            <div style={{ color: MON.muted, fontSize: 9, marginTop: 5 }}>{systemId ? 'Rule sirf selected agent par apply hoga.' : ['Device GPS Tracking', 'Location-Based'].includes(category) ? 'Is rule ke liye ek agent select karna required hai.' : 'No agent selected: rule company ke sab enrolled agents par apply hoga.'}</div>
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
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Latitude *</label><input required type="number" step="any" min="-90" max="90" value={latitude} onChange={e => setLatitude(e.target.value)} placeholder="28.6139" style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Longitude *</label><input required type="number" step="any" min="-180" max="180" value={longitude} onChange={e => setLongitude(e.target.value)} placeholder="77.2090" style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Allowed Radius (metres) *</label><input required type="number" min="1" max="100000" value={radiusMeters} onChange={e => setRadiusMeters(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.green, padding: '7px 10px', borderRadius: 4 }} /></div>
                </div>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, color: MON.text, fontSize: 10 }}>
                  <input type="checkbox" checked={gpsTracking} onChange={e => setGpsTracking(e.target.checked)} />
                  Native device GPS tracking (OS permission aur GPS/location sensor required)
                </label>
                {gpsTracking && <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>GPS Collection Interval (seconds)</label><input type="number" min="30" max="3600" value={gpsIntervalSeconds} onChange={e => setGpsIntervalSeconds(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Required Accuracy (5–50 metres)</label><input type="number" min="5" max="50" value={gpsAccuracyMeters} onChange={e => setGpsAccuracyMeters(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.green, padding: '7px 10px', borderRadius: 4 }} /></div>
                </div>}
                <div style={{ fontSize: 10, color: MON.yellow }}>GPS available ho to actual device position radius check ke liye use hogi. Permission/sensor unavailable ho to status show hoga; IP location ko GPS nahi mana jayega.</div>
              </div>
            )}

            {category === 'Device GPS Tracking' && (
              <div style={{ display: 'grid', gap: 10 }}>
                <div style={{ fontSize: 10, color: MON.yellow }}>Native OS location collect hogi; geo-fence enforcement ya automatic lock enable nahi hoga.</div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>GPS Collection Interval (seconds)</label><input type="number" min="30" max="3600" value={gpsIntervalSeconds} onChange={e => setGpsIntervalSeconds(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4 }} /></div>
                  <div><label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Required Accuracy (5–50 metres)</label><input type="number" min="5" max="50" value={gpsAccuracyMeters} onChange={e => setGpsAccuracyMeters(e.target.value)} style={{ width: '100%', boxSizing: 'border-box', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.green, padding: '7px 10px', borderRadius: 4 }} /></div>
                </div>
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
          {formError && <div role="alert" style={{ padding: '9px 12px', borderRadius: 6, border: `1px solid ${MON.red}`, background: `${MON.red}18`, color: MON.red, fontSize: 11, fontWeight: 800 }}>{formError}</div>}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
            <button type="button" onClick={onClose} style={{ padding: '9px 18px', background: 'transparent', border: `1px solid ${MON.border}`, color: MON.muted, borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
              Cancel
            </button>
            <button type="submit" disabled={saving} style={{ padding: '9px 22px', background: MON.cyan, border: 'none', color: '#000', borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: saving ? 'wait' : 'pointer', opacity: saving ? 0.7 : 1 }}>
              ⚡ {saving ? 'Saving…' : initialPolicy ? 'Save Policy Rule' : 'Deploy Policy Rule'}
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
  const [editingPolicy, setEditingPolicy] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [policySystems, setPolicySystems] = useState([]);
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
    api.get('/geolocation/systems', { params: companyId ? { companyId } : {}, skipCache: true })
      .then(r => active && setPolicySystems(Array.isArray(r.data?.systems) ? r.data.systems : []))
      .catch(() => active && setPolicySystems([]));
    return () => { active = false; };
  }, [companyId]);

  const policyAgentScope = (policy) => {
    const targetIds = Array.isArray(policy.conditions?.systemIds) ? policy.conditions.systemIds.map(String) : [];
    if (!targetIds.length) return policy.category === 'Location-Based' ? 'Not configured' : 'All enrolled agents';
    return targetIds.map(id => {
      const system = policySystems.find(item => String(item._id) === id);
      if (!system) return `Agent ${id.slice(-8)}`;
      const name = system.hostname || system.name || system.agentName || `Agent ${id.slice(-8)}`;
      const online = system.isOnline || system.status === 'online';
      return `${name} (${online ? 'Online' : 'Offline'})`;
    }).join(', ');
  };

  const togglePolicy = async (policy) => {
    const conditions = policy.conditions || {};
    const locationNeedsConfiguration = !policy.enabled && policy.category === 'Location-Based'
      && (!(conditions.systemIds || []).length || conditions.latitude == null || conditions.longitude == null || Number(conditions.radiusMeters) < 1);
    if (locationNeedsConfiguration) {
      setEditingPolicy(policy);
      setIsWizardOpen(true);
      setSuccessMsg('Select an installed AJNAT system and configure its allowed location/radius first.');
      return;
    }
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
      return r.data.policy;
    } catch (err) {
      const message = err.response?.data?.message || 'Policy creation failed.';
      setSuccessMsg(message);
      throw new Error(message);
    }
  };

  const handleSavePolicy = async (draft) => {
    if (!editingPolicy) return handleAddPolicy(draft);
    try {
      const response = await api.put(`/geolocation/policies/${editingPolicy._id}`, { ...draft, companyId });
      setPolicies(previous => {
        const next = previous.map(policy => policy._id === editingPolicy._id ? response.data.policy : policy);
        onPoliciesChange?.(next);
        return next;
      });
      setEditingPolicy(null);
      setIsWizardOpen(false);
      setSuccessMsg(`Policy "${response.data.policy.name}" updated.`);
      return response.data.policy;
    } catch (err) {
      const message = err.response?.data?.message || 'Policy update failed.';
      setSuccessMsg(message);
      throw new Error(message);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, color: MON.cyan, fontWeight: 900 }}>🛡️ Geolocation Anomaly Detection — Policy Engine</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Configure native GPS collection, allowed location radius, accuracy threshold, and AJNAT agent enforcement</div>
        </div>
        <button type="button" onClick={() => { setEditingPolicy(null); setIsWizardOpen(true); }} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 900, cursor: 'pointer', fontSize: 12 }}>
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
              <th style={{ padding: 10 }}>AJNAT Agent Scope</th>
              <th style={{ padding: 10 }}>Action Engine Rule</th>
              <th style={{ padding: 10 }}>Severity</th>
              <th style={{ padding: 10 }}>Status</th>
              <th style={{ padding: 10 }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p._id} style={{ borderBottom: `1px solid ${MON.line}` }}>
                <td style={{ padding: 10, color: MON.text, fontWeight: 900 }}>{p.name}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{p.category}</td>
                <td style={{ padding: 10, color: (p.conditions?.systemIds || []).length ? MON.cyan : MON.muted, fontWeight: 800 }}>{policyAgentScope(p)}</td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 900 }}>{p.action}</td>
                <td style={{ padding: 10, color: p.severity === 'Critical' ? MON.red : MON.orange, fontWeight: 800 }}>{p.severity}</td>
                <td style={{ padding: 10, color: p.enabled ? MON.green : MON.sub, fontWeight: 900 }}>{p.enabled ? 'Active' : 'Disabled'}</td>
                <td style={{ padding: 10 }}>
                  <button type="button" onClick={() => { setEditingPolicy(p); setIsWizardOpen(true); }} style={{ padding: '3px 10px', marginRight: 6, background: `${MON.cyan}20`, border: `1px solid ${MON.cyan}55`, color: MON.cyan, borderRadius: 4, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>
                    Edit
                  </button>
                  <button type="button" onClick={() => togglePolicy(p)} style={{ padding: '3px 10px', background: p.enabled ? `${MON.green}20` : `${MON.red}20`, border: `1px solid ${p.enabled ? MON.green : MON.red}55`, color: p.enabled ? MON.green : MON.red, borderRadius: 4, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>
                    {p.enabled ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
            {!loadingPolicies && !policies.length && <tr><td colSpan="7" style={{ padding: 24, textAlign: 'center', color: MON.muted }}>No geolocation policies configured.</td></tr>}
          </tbody>
        </table>
      </div>

      {isWizardOpen && <GeoPolicyWizardModal companyId={companyId} initialPolicy={editingPolicy} onClose={() => { setEditingPolicy(null); setIsWizardOpen(false); }} onSave={handleSavePolicy} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
function gpsDeliveryDiagnosis(row = {}, requiredAccuracy = 50) {
  const status = String(row.gpsStatus || row.rawEvent?.gpsStatus || 'unknown').toLowerCase();
  const accuracy = gpsAccuracyOf(row);
  const provider = String(row.gpsProvider || row.rawEvent?.gpsProvider || '').toLowerCase();
  const reason = row.gpsReason || row.rawEvent?.gpsReason || '';
  if (status === 'available' && accuracy != null && accuracy <= requiredAccuracy) {
    return { qualified: true, label: 'PRECISE LOCATION SENT', detail: `Native fix ±${accuracy}m meets the ≤${requiredAccuracy}m policy.` };
  }
  if (status === 'inaccurate' || (accuracy != null && accuracy > requiredAccuracy)) {
    const received = accuracy == null ? 'unknown accuracy' : `±${accuracy}m accuracy`;
    const coarseProviderReason = provider.includes('geoclue')
      ? `GPS/GNSS hardware fix is not available on this device. Linux GeoClue is returning only a network/IP location (${received}). This device cannot provide the ≤${requiredAccuracy}m GPS location required by policy; use a GPS-capable device with OS location permission.`
      : `The native provider returned ${received}. AJNAT requires ≤${requiredAccuracy}m, so the wrong coordinates are withheld until the device obtains a better GPS fix.`;
    return {
      qualified: false,
      label: 'PRECISE COORDINATE NOT SENT',
      detail: reason ? `${coarseProviderReason} Provider detail: ${reason}` : coarseProviderReason,
    };
  }
  const statusReasons = {
    permission_denied: 'OS location permission is denied for the AJNAT agent.',
    provider_unavailable: 'No native GPS/location provider is available on this device.',
    accuracy_unknown: 'The OS provider did not report an accuracy value.',
    provider_error: 'The native location provider returned an error.',
  };
  return {
    qualified: false,
    label: 'PRECISE COORDINATE NOT SENT',
    detail: reason || statusReasons[status] || `GPS status is ${status}; waiting for a native ≤${requiredAccuracy}m fix.`,
  };
}

function GeoLogLocationEvidence({ row, requiredAccuracy = 50 }) {
  const ruleId = String(row.ruleId || row.rule_id || '').toUpperCase();
  const gpsLat = row.gpsLat ?? row.rawEvent?.gpsLat;
  const gpsLon = row.gpsLon ?? row.rawEvent?.gpsLon;
  const gpsAccuracy = row.gpsAccuracyMeters ?? row.rawEvent?.gpsAccuracyMeters;
  const gpsProvider = row.gpsProvider || row.rawEvent?.gpsProvider;
  const gpsStatus = row.gpsStatus || row.rawEvent?.gpsStatus;
  const isGpsObservation = ['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId)
    || String(row.source || '').toLowerCase() === 'gps-location'
    || gpsStatus || gpsProvider || gpsAccuracy != null || gpsLat != null || gpsLon != null;
  if (!isGpsObservation) {
    return <div><b style={{ color: MON.muted, fontSize: 10 }}>Not a GPS observation</b><span style={{ color: MON.sub, fontSize: 9, display: 'block', marginTop: 3 }}>This is a geolocation policy/anomaly event. Current device GPS cause is shown in GPS Delivery Diagnosis.</span></div>;
  }
  const hasCoordinates = gpsLat != null && gpsLon != null && Number.isFinite(Number(gpsLat)) && Number.isFinite(Number(gpsLon));
  const hasDeviceGps = gpsStatus === 'available' && Number(gpsAccuracy) <= 50 && gpsLat != null && gpsLon != null;
  const diagnosis = gpsDeliveryDiagnosis(row, requiredAccuracy);

  return (
    <div>
      <b style={{ color: hasDeviceGps ? MON.cyan : MON.orange, fontFamily: 'monospace', fontSize: 10, display: 'block' }}>
        {hasDeviceGps ? `AJNAT GPS: ${gpsLat}, ${gpsLon}` : hasCoordinates ? `AJNAT APPROXIMATE: ${gpsLat}, ${gpsLon}` : 'AJNAT GPS: no coordinate received'}
      </b>
      <span style={{ color: gpsStatus === 'available' ? MON.green : MON.orange, fontSize: 9 }}>
        {gpsProvider || 'native provider'} · {gpsStatus || 'unknown'}
        {gpsAccuracy != null ? ` · ±${gpsAccuracy}m` : ''}
        {gpsStatus !== 'available' ? ' · not enforced' : ''}
      </span>
      {!diagnosis.qualified && <span style={{ color: MON.orange, fontSize: 9, display: 'block', marginTop: 3 }}>
        Reason: {diagnosis.detail}
      </span>}
    </div>
  );
}

export function GeoAnomalyLogMonitor({ alerts = [], companyId, onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  useEffect(() => {
    if (!selectedLog) return;
    const selectedId = String(selectedLog._id || '');
    const refreshed = alerts.find(row => String(row._id || '') === selectedId);
    if (refreshed) setSelectedLog(refreshed);
  }, [alerts, selectedLog?._id]);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const ajnatSystemId = a.systemId?._id || a.systemId || a.endpointId || a.agentId;
      if (!ajnatSystemId) return false;
      const ruleId = String(a.ruleId || a.rule_id || '');
      const isGpsTelemetry = ruleId.startsWith('GEO_') || ruleId === 'GPS_LOCATION_TELEMETRY'
        || String(a.source || '') === 'gps-location'
        || a.gpsLat != null || a.rawEvent?.gpsLat != null
        || Boolean(a.gpsProvider || a.rawEvent?.gpsProvider || a.gpsStatus || a.rawEvent?.gpsStatus);
      if (!isGpsTelemetry) return false;
      const matchQ = !query || `${geoRule(a)} ${a.gpsProvider || a.rawEvent?.gpsProvider || ''} ${a.gpsStatus || a.rawEvent?.gpsStatus || ''} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search GPS Rule, Provider, Status, AJNAT Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 AJNAT GPS Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px,.85fr) minmax(110px,1.1fr) minmax(220px,2.25fr) minmax(65px,100px) minmax(65px,90px) minmax(65px,90px)', gap: 2, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>GPS Rule</span><span>AJNAT Host</span><span>AJNAT GPS Evidence</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: 'minmax(120px,.85fr) minmax(110px,1.1fr) minmax(220px,2.25fr) minmax(65px,100px) minmax(65px,90px) minmax(65px,90px)', gap: 2, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{geoRule(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <GeoLogLocationEvidence row={row} />
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

      {selectedLog && <GeoForensicDetailModal log={selectedLog} companyId={companyId} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

function LegacyGeoAnomalyReportsTab({ alerts = [] }) {
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
      const response = await api.get('/dashboard/capability-report/23', { params: { period: reportType, category: 'all' }, skipCache: true });
      const filtered = response.data?.alerts || [];
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: Number(response.data?.total || filtered.length),
        bySev,
        impossibleTravel: filtered.filter(row => /impossible.travel/i.test(`${geoRule(row)} ${row.description || ''}`)).length,
        privacyEvents: filtered.filter(row => row.geoVpn || row.vpnDetected || row.geoProxy || row.proxyDetected || row.geoTor || row.torDetected || row.geoHosting).length,
        allowedForeign: filtered.filter(row => /allow|trusted|exception/i.test(`${row.actionTaken || ''} ${row.userAction || ''} ${row.description || ''}`)).length,
      });
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => { const s = alertSeverity(a); if (bySev[s] !== undefined) bySev[s]++; });
      setReportData({
        alerts: filtered, total: filtered.length, bySev,
        impossibleTravel: filtered.filter(row => /impossible.travel/i.test(`${geoRule(row)} ${row.description || ''}`)).length,
        privacyEvents: filtered.filter(row => row.geoVpn || row.vpnDetected || row.geoProxy || row.proxyDetected || row.geoTor || row.torDetected || row.geoHosting).length,
        allowedForeign: filtered.filter(row => /allow|trusted|exception/i.test(`${row.actionTaken || ''} ${row.userAction || ''} ${row.description || ''}`)).length,
      });
    } finally {
      setGenerating(false);
      setGenerated(true);
    }
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Detection Rule,Source IP,Country,City,GPS Latitude,GPS Longitude,GPS Accuracy Metres,GPS Provider,GPS Status,User,Target Host,Risk Score,Severity';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(geoRule(a)),
      csvCell(geoIp(a)),
      csvCell(geoCountry(a)),
      csvCell(geoCity(a)),
      csvCell(a.gpsLat ?? a.rawEvent?.gpsLat),
      csvCell(a.gpsLon ?? a.rawEvent?.gpsLon),
      csvCell(a.gpsAccuracyMeters ?? a.rawEvent?.gpsAccuracyMeters),
      csvCell(a.gpsProvider ?? a.rawEvent?.gpsProvider),
      csvCell(a.gpsStatus ?? a.rawEvent?.gpsStatus),
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
              { label: 'Impossible Travel', val: reportData?.impossibleTravel, color: MON.red },
              { label: 'Tor / Proxy Logins', val: reportData?.privacyEvents, color: MON.orange },
              { label: 'Allowed Foreign Logins', val: reportData?.allowedForeign, color: MON.green },
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

export function GeoAnomalyReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={23} alerts={alerts} />;
}

const escapeMapHtml = value => String(value ?? '—').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const isAgentGpsTelemetry = row => {
  const ruleId = String(row?.ruleId || row?.rule_id || row?.rawEvent?.ruleId || row?.rawEvent?.rule_id || '').toUpperCase();
  const source = String(row?.source || row?.rawEvent?.source || '').toLowerCase();
  return ['GPS_LOCATION_TELEMETRY', 'GEO_GPS_STATUS'].includes(ruleId) || source === 'gps-location';
};
const agentGpsPosition = row => ({
  lat: Number(row?.gpsLat ?? row?.rawEvent?.gpsLat),
  lng: Number(row?.gpsLon ?? row?.rawEvent?.gpsLon),
  accuracy: Number(row?.gpsAccuracyMeters ?? row?.rawEvent?.gpsAccuracyMeters),
});
const agentGpsKey = row => String(row?.systemId?._id || row?.systemId || row?.rawEvent?.system_id || row?.agentId || row?.hostname || row?.agentName || row?._id || '');
function GpsLiveMap({ rows = [], selectedEventId = null }) {
  const mapNode = React.useRef(null);
  const mapRef = React.useRef(null);
  const layerRef = React.useRef(null);
  const markerRefs = React.useRef(new Map());

  useEffect(() => {
    if (!mapNode.current || mapRef.current) return undefined;
    const map = L.map(mapNode.current, {
      center: [22, 10], zoom: 2, minZoom: 2, zoomControl: true,
      attributionControl: true, preferCanvas: true,
    });
    L.tileLayer('https://{s}.google.com/vt/lyrs=m&x={x}&y={y}&z={z}', {
      maxZoom: 20,
      subdomains: ['mt0', 'mt1', 'mt2', 'mt3'],
      attribution: '&copy; Google Maps',
    }).addTo(map);
    layerRef.current = L.layerGroup().addTo(map);
    mapRef.current = map;
    const invalidate = () => map.invalidateSize({ pan: false });
    const resizeObserver = typeof ResizeObserver === 'undefined' ? null : new ResizeObserver(invalidate);
    resizeObserver?.observe(mapNode.current);
    const timers = [50, 250, 750].map(delay => setTimeout(invalidate, delay));
    window.addEventListener('resize', invalidate);
    return () => {
      timers.forEach(clearTimeout);
      resizeObserver?.disconnect();
      window.removeEventListener('resize', invalidate);
      map.remove();
      mapRef.current = null;
      layerRef.current = null;
      markerRefs.current.clear();
    };
  }, []);

  useEffect(() => {
    const map = mapRef.current;
    const layer = layerRef.current;
    if (!map || !layer) return;
    layer.clearLayers();
    markerRefs.current.clear();
    const points = [];
    const renderedAgentIds = new Set();
    rows.forEach(row => {
      // Display both precise native fixes and explicitly-labelled coarse
      // provider estimates. No IP-derived fallback is invented here.
      const { lat, lng, accuracy: gpsAccuracy } = agentGpsPosition(row);
      const accuracyQualified = gpsAccuracy <= 50 && String(row.gpsStatus || row.rawEvent?.gpsStatus || '') === 'available';
      const status = String(row.gpsStatus || row.rawEvent?.gpsStatus || '').toLowerCase();
      const displayable = ['available', 'inaccurate'].includes(status);
      if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180
        || !Number.isFinite(gpsAccuracy) || gpsAccuracy < 0 || !displayable) return;
      const isAgentGps = isAgentGpsTelemetry(row);
      const agentKey = agentGpsKey(row);
      if (isAgentGps && agentKey && renderedAgentIds.has(agentKey)) return;
      if (isAgentGps && agentKey) renderedAgentIds.add(agentKey);
      const severity = alertSeverity(row);
      const color = isAgentGps ? '#ef4444' : accuracyQualified ? (severity === 'critical' ? '#ef4444' : severity === 'high' ? '#f97316' : severity === 'medium' ? '#eab308' : '#22d3ee') : '#f59e0b';
      const gpsProvider = row.gpsProvider || row.rawEvent?.gpsProvider || 'Device GPS';
      const id = String(row._id || row.eventId || '');
      if (isAgentGps) L.circle([lat, lng], {
        radius: Math.max(5, Math.min(100000, gpsAccuracy)), color: accuracyQualified ? '#ef4444' : '#f59e0b', weight: 1,
        fillColor: accuracyQualified ? '#ef4444' : '#f59e0b', fillOpacity: 0.12,
      }).addTo(layer);
      const marker = L.circleMarker([lat, lng], {
        radius: selectedEventId && id === String(selectedEventId) ? 12 : isAgentGps ? 10 : 7,
        color: isAgentGps ? '#fee2e2' : '#ffffff', weight: isAgentGps ? 3 : 1, fillColor: color, fillOpacity: 0.95,
      }).bindPopup(`
        <div style="font:12px Arial;min-width:210px;line-height:1.5">
          <b>${escapeMapHtml(isAgentGps ? (accuracyQualified ? 'AJNAT Agent Precise GPS Location' : 'AJNAT Agent Approximate Location') : geoRule(row))}</b><br>
          ${isAgentGps ? `Agent: ${escapeMapHtml(row.hostname || row.agentName || agentKey || 'AJNAT Agent')}<br>` : `User: ${escapeMapHtml(alertUser(row))}<br>`}
          Reported location: ${escapeMapHtml(lat)}, ${escapeMapHtml(lng)}<br>
          Provider: ${escapeMapHtml(gpsProvider)}<br>Accuracy: &plusmn;${escapeMapHtml(gpsAccuracy)} m<br>
          Policy: ${accuracyQualified ? 'Eligible (within 50m)' : 'NOT ENFORCED — accuracy exceeds 50m'}<br>
          IP: ${escapeMapHtml(geoIp(row))}<br>
          Risk: ${geoRiskScore(row)}/100
        </div>
      `).addTo(layer);
      if (isAgentGps) marker.bindTooltip(`AJNAT AGENT · ${escapeMapHtml(row.hostname || row.agentName || agentKey || 'CURRENT LOCATION')} · ±${escapeMapHtml(gpsAccuracy)}m${accuracyQualified ? '' : ' · APPROXIMATE'}`, {
        permanent: true, direction: 'top', offset: [0, -10], className: `ajnat-gps-label${accuracyQualified ? '' : ' ajnat-gps-label-approximate'}`,
      });
      markerRefs.current.set(id, marker);
      points.push([lat, lng]);
    });
    if (points.length === 1) map.setView(points[0], 7);
    else if (points.length > 1) map.fitBounds(L.latLngBounds(points), { padding: [35, 35], maxZoom: 8 });
    else map.setView([22, 10], 2);
    const selected = markerRefs.current.get(String(selectedEventId || ''));
    if (selected) {
      map.setView(selected.getLatLng(), Math.max(map.getZoom(), 8), { animate: true });
      selected.openPopup();
    }
  }, [rows, selectedEventId]);

  const gpsRowsWithCoordinates = rows.filter(row => {
    const { lat, lng, accuracy } = agentGpsPosition(row);
    return Number.isFinite(lat) && Number.isFinite(lng) && Number.isFinite(accuracy) && accuracy >= 0
      && ['available', 'inaccurate'].includes(String(row.gpsStatus || row.rawEvent?.gpsStatus || '').toLowerCase());
  });
  return <div style={{ position: 'absolute', inset: '31px 0 0', background: "#061423 url('/threat-countries-map.png') center/cover no-repeat" }}><div ref={mapNode} style={{ width: '100%', height: '100%', background: 'transparent' }} />{gpsRowsWithCoordinates.length === 0 && <div style={{ position: 'absolute', left: '50%', bottom: 12, transform: 'translateX(-50%)', zIndex: 800, padding: '7px 11px', borderRadius: 6, border: '1px solid #285174', background: 'rgba(6,20,35,.9)', pointerEvents: 'none', color: '#bae6fd', fontSize: 9, whiteSpace: 'nowrap' }}>Waiting for AJNAT precise or approximate location</div>}<style>{`.ajnat-gps-label{background:#450a0a!important;color:#fee2e2!important;border:1px solid #ef4444!important;font-weight:800!important;box-shadow:0 0 12px rgba(239,68,68,.65)!important}.ajnat-gps-label:before{border-top-color:#ef4444!important}.ajnat-gps-label-approximate{background:#451a03!important;color:#ffedd5!important;border-color:#f59e0b!important;box-shadow:0 0 12px rgba(245,158,11,.6)!important}.ajnat-gps-label-approximate:before{border-top-color:#f59e0b!important}`}</style></div>;
}

function GeoOverviewDashboardV2({ metrics, onRefresh }) {
  const cards = [
    ['📡', 'GPS Events (24H)', metrics.totalEvents, MON.blue, 'Live AJNAT GPS records'],
    ['🖥️', 'Reporting Agents', metrics.reportingAgents, MON.cyan, 'Agents with GPS telemetry'],
    ['✅', 'Accurate GPS Agents', metrics.qualifiedAgents, MON.green, 'Latest fix available and ≤50m'],
    ['⚠️', 'Inaccurate Agents', metrics.inaccurateAgents, MON.orange, 'Latest fix exceeds policy accuracy'],
    ['🎯', 'Best Accuracy', metrics.bestAccuracy == null ? '—' : `±${metrics.bestAccuracy}m`, MON.purple, 'Best native fix in live window'],
    ['🛡️', 'Enabled Policies', metrics.enabledPolicies, MON.yellow, `${metrics.targetedAgents} targeted AJNAT agents`],
  ];
  const maxTimeline = Math.max(...metrics.timeline, 1);

  return (
    <div style={{ display: 'grid', gap: 14 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div>
          <div style={{ color: MON.cyan, fontSize: 13, fontWeight: 900 }}>Live AJNAT GPS Overview</div>
          <div style={{ color: MON.muted, fontSize: 10, marginTop: 3 }}>
            {metrics.latestAt ? `Latest GPS event: ${new Date(metrics.latestAt).toLocaleString()}` : 'Waiting for AJNAT GPS telemetry'}
          </div>
        </div>
        <button type="button" onClick={onRefresh} style={{ border: `1px solid ${MON.cyan}`, background: `${MON.cyan}18`, color: MON.cyan, borderRadius: 6, padding: '7px 12px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>↻ Refresh live data</button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(180px,1fr))', gap: 12 }}>
        {cards.map(([icon, label, value, color, subtitle]) => (
          <div key={label} style={{ background: MON.card, border: `1px solid ${color}45`, borderRadius: 9, padding: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.muted, fontSize: 10, fontWeight: 800 }}><span>{label}</span><span>{icon}</span></div>
            <div style={{ color, fontSize: 25, fontWeight: 900, marginTop: 9 }}>{value}</div>
            <div style={{ color: MON.sub, fontSize: 9, marginTop: 6 }}>{subtitle}</div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14, minHeight: 340 }}>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 9, position: 'relative', overflow: 'hidden' }}>
          <div style={{ position: 'absolute', zIndex: 20, top: 9, left: 12, color: MON.text, fontSize: 10, fontWeight: 900 }}>AJNAT GPS MAP · {metrics.displayableLatestRows.length} LOCATIONS · {metrics.qualifiedAgents} WITHIN 50M</div>
          <GpsLiveMap rows={metrics.displayableLatestRows} />
        </div>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 9, padding: 14 }}>
          <div style={{ color: MON.text, fontSize: 11, fontWeight: 900, marginBottom: 12 }}>Latest Agent GPS State</div>
          <div style={{ display: 'grid', gap: 9 }}>
            {metrics.latestRows.map(row => {
              const status = gpsStatusOf(row) || 'unknown';
              const accuracy = gpsAccuracyOf(row);
              return (
                <div key={ajnatSystemKey(row)} style={{ paddingBottom: 8, borderBottom: `1px solid ${MON.line}` }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <b style={{ color: MON.cyan, fontSize: 10 }}>{alertHost(row)}</b>
                    <span style={{ color: isQualifiedGpsFix(row) ? MON.green : MON.orange, fontSize: 9, fontWeight: 900 }}>{status.toUpperCase()}</span>
                  </div>
                  <div style={{ color: MON.muted, fontSize: 9, marginTop: 4 }}>{gpsProviderOf(row)} · {accuracy == null ? 'accuracy unavailable' : `±${accuracy}m`} · {relativeTime(alertTime(row))}</div>
                </div>
              );
            })}
            {!metrics.latestRows.length && <span style={{ color: MON.muted, fontSize: 10 }}>No AJNAT GPS state reported.</span>}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 14 }}>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 9, padding: 14 }}>
          <div style={{ color: MON.text, fontSize: 11, fontWeight: 900 }}>GPS event activity · rolling 24 hours</div>
          <div style={{ height: 100, display: 'flex', alignItems: 'flex-end', gap: 7, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {metrics.timeline.map((value, index) => <div key={index} title={`${value} GPS events`} style={{ flex: 1, minHeight: 3, height: `${Math.max(3, (value / maxTimeline) * 100)}%`, borderRadius: '3px 3px 0 0', background: MON.cyan }} />)}
          </div>
        </div>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 9, padding: 14 }}>
          <div style={{ color: MON.text, fontSize: 11, fontWeight: 900, marginBottom: 12 }}>Live Provider Distribution</div>
          {metrics.providerCounts.map(([provider, count]) => <div key={provider} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 10 }}><span style={{ color: MON.muted }}>{provider}</span><b style={{ color: MON.cyan }}>{count}</b></div>)}
          {!metrics.providerCounts.length && <span style={{ color: MON.muted, fontSize: 10 }}>No provider telemetry.</span>}
        </div>
      </div>
    </div>
  );
}

// ── Visual Helper Components for Geolocation Anomaly Detection Dashboard ─
function LoginRiskDistributionDonut({ rows = [] }) {
  const total = rows.length;
  const riskItems = [
    ['Available', 'available', '#22c55e'], ['Inaccurate', 'inaccurate', '#f97316'],
    ['Unavailable', 'unavailable', '#ef4444'], ['Provider Error', 'provider_error', '#a78bfa'],
  ];
  const items = riskItems.map(([label, key, color]) => {
    const count = rows.filter(row => key === 'unavailable'
      ? ['sensor_unavailable', 'unsupported', 'accuracy_unknown', 'permission_denied', 'provider_timeout'].includes(gpsStatusOf(row))
      : gpsStatusOf(row) === key).length;
    return { label, count, pct: total ? (count / total) * 100 : 0, color };
  });

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = items.map((s) => {
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>GPS STATUS DISTRIBUTION</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.count} ({it.pct.toFixed(1)}%)</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function LoginTrendOverTimeChart({ rows = [] }) {
  const pointsLow = buildBuckets(rows.filter(row => gpsStatusOf(row) === 'available'), 12, 24);
  const pointsMed = buildBuckets(rows.filter(row => gpsStatusOf(row) === 'inaccurate'), 12, 24);
  const pointsHigh = buildBuckets(rows.filter(row => ['sensor_unavailable', 'unsupported', 'accuracy_unknown', 'permission_denied'].includes(gpsStatusOf(row))), 12, 24);
  const pointsCrit = buildBuckets(rows.filter(row => ['provider_error', 'provider_timeout'].includes(gpsStatusOf(row))), 12, 24);

  const maxVal = Math.max(1, ...pointsLow, ...pointsMed, ...pointsHigh, ...pointsCrit);
  const width = 360;
  const height = 95;

  const getSvgPath = (pts) => {
    return pts.map((val, idx) => {
      const x = (idx / (pts.length - 1)) * width;
      const y = height - (val / maxVal) * (height - 10) - 5;
      return `${x},${y}`;
    }).join(' L ');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>GPS STATUS TREND OVER TIME</span>
        </div>

        <div style={{ display: 'flex', gap: 8, fontSize: 7, marginBottom: 4 }}>
          <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#22c55e', borderRadius: 1 }} /> Available</span>
          <span style={{ color: '#eab308', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#eab308', borderRadius: 1 }} /> Inaccurate</span>
          <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#ef4444', borderRadius: 1 }} /> Unavailable</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#a78bfa', borderRadius: 1 }} /> Provider Error</span>
        </div>

        <div style={{ position: 'relative', width: '100%', height: 85 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" style={{ overflow: 'visible' }}>
            <path d={`M ${getSvgPath(pointsLow)}`} fill="none" stroke="#22c55e" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsMed)}`} fill="none" stroke="#eab308" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsHigh)}`} fill="none" stroke="#ef4444" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsCrit)}`} fill="none" stroke="#a78bfa" strokeWidth="1.5" />
          </svg>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
          {['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'].map(t => (
            <span key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function AnomalyDetectionSummaryDonut({ rows = [] }) {
  const descriptors = [
    ['Qualified Fix', row => isQualifiedGpsFix(row), '#22c55e'],
    ['Inaccurate', row => gpsStatusOf(row) === 'inaccurate', '#f97316'],
    ['No Coordinate', row => !isQualifiedGpsFix(row) && gpsStatusOf(row) !== 'inaccurate', '#38bdf8'],
    ['Provider Failure', row => ['provider_error', 'provider_timeout'].includes(gpsStatusOf(row)), '#a78bfa'],
  ];
  const counts = descriptors.map(([label, test, color]) => ({ label, val: rows.filter(test).length, color }));
  const total = counts.reduce((sum, item) => sum + item.val, 0);
  const items = counts.map(item => ({ ...item, pct: total ? (item.val / total) * 100 : 0 }));

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = items.map((s) => {
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>GPS SENSOR SUMMARY</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total Events</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 7.5 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 3 }}>
                  <span style={{ width: 4, height: 4, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.val} <span style={{ fontSize: 6.5, color: '#64748b' }}>({it.pct.toFixed(1)}%)</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function GeoOverviewDashboard({ metrics }) {
  const [selectedEventId, setSelectedEventId] = useState(null);
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = metrics.rows;
  const gpsRows = metrics.displayableLatestRows;
  const verifiedGpsCount = metrics.qualifiedAgents;
  const timeline = buildBuckets(rows, 6, 24);
  const statusRows = status => rows.filter(row => gpsStatusOf(row) === status);
  const unavailableRows = rows.filter(row => ['sensor_unavailable', 'unsupported', 'accuracy_unknown', 'permission_denied'].includes(gpsStatusOf(row)));
  const providerFailureRows = rows.filter(row => ['provider_error', 'provider_timeout'].includes(gpsStatusOf(row)));
  const topCards = [
    { title: 'GPS Events (24H)', val: shortNum(metrics.totalEvents), sub: 'Live AJNAT records', col: '#38bdf8', icon: '⏱️', spark: timeline },
    { title: 'Reporting Agents', val: shortNum(metrics.reportingAgents), sub: 'Unique AJNAT agents', col: '#22c55e', icon: '🛡️', spark: timeline },
    { title: 'Qualified GPS Fixes', val: shortNum(metrics.qualifiedAgents), sub: 'Latest fix within 50m', col: '#eab308', icon: '🎯', spark: buildBuckets(rows.filter(isQualifiedGpsFix), 6, 24) },
    { title: 'Inaccurate States', val: shortNum(metrics.inaccurateEvents), sub: 'Agent-reported states', col: '#ef4444', icon: '⚠️', spark: buildBuckets(statusRows('inaccurate'), 6, 24) },
    { title: 'Average Accuracy', val: metrics.averageAccuracy == null ? '—' : `±${metrics.averageAccuracy}m`, sub: 'Native GPS samples', col: '#a78bfa', icon: '📍', spark: timeline },
    { title: 'Enabled Policies', val: shortNum(metrics.enabledPolicies), sub: `${metrics.targetedAgents} targeted agents`, col: '#38bdf8', icon: '🛡️', spark: timeline },
  ];

  const providerList = metrics.providerCounts.slice(0, 10).map(([name, count]) => ({ name, flag: '🛰️', val: shortNum(count) }));
  const geoAlerts = rows.slice(0, 7).map(row => ({
    id: String(row._id || row.eventId || ''),
    hasGps: isQualifiedGpsFix(row),
    title: geoRule(row), time: relativeTime(alertTime(row)), user: alertHost(row),
    detail: `${gpsProviderOf(row)} · ${gpsStatusOf(row) || 'unknown'}`,
    extra: gpsAccuracyOf(row) == null ? 'Accuracy unavailable' : `Accuracy: ±${gpsAccuracyOf(row)}m`,
    sevCol: isQualifiedGpsFix(row) ? MON.green : MON.orange,
    icon: isQualifiedGpsFix(row) ? '📍' : '⚠️',
  }));
  const recentGpsStates = rows.slice(0, 7).map(row => ({
    agent: alertHost(row), provider: gpsProviderOf(row), accuracy: gpsAccuracyOf(row),
    status: gpsStatusOf(row) || 'unknown', detected: relativeTime(alertTime(row)), evt: geoRule(row),
    statusCol: isQualifiedGpsFix(row) ? MON.green : MON.orange,
  }));
  const availableCount = metrics.availableEvents;
  const inaccurateCount = metrics.inaccurateEvents;
  const unavailableCount = metrics.unavailableEvents + metrics.permissionDeniedEvents;
  const sensorTotal = availableCount + inaccurateCount + unavailableCount;
  const selectedAgent = metrics.latestRows[0] ? alertHost(metrics.latestRows[0]) : 'No AJNAT GPS telemetry';
  const agentTimeline = metrics.latestRows[0]
    ? rows.filter(row => ajnatSystemKey(row) === ajnatSystemKey(metrics.latestRows[0])).slice(0, 4).reverse()
    : [];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        {topCards.map(s => (
          <div key={s.title} style={{ ...panelStyle, padding: '10px 10px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: '#8ea0b8', fontWeight: 800 }}>{s.title}</span>
              <span style={{ fontSize: 10 }}>{s.icon}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>{s.val}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: s.col, fontWeight: 700 }}>{s.sub}</span>
              <div style={{ width: 35, height: 12 }}>
                <MiniSparkline data={s.spark} color={s.col} height={12} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (2 Main Columns: Map Left 75%, Alerts Right 25%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 12 }}>
        {/* LIVE GEOLOCATION MAP */}
        <div style={{ ...panelStyle, height: 320, position: 'relative', padding: 0, overflow: 'hidden' }}>
          <div style={{ position: 'absolute', top: 10, left: 12, zIndex: 10, fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>LIVE AJNAT GPS MAP · {gpsRows.length} AGENT LOCATIONS · {verifiedGpsCount} WITHIN 50M</div>
          
          <div style={{ position: 'absolute', inset: 0 }}>
            <GpsLiveMap rows={gpsRows} selectedEventId={selectedEventId} />
          </div>

          {/* Map Overlay Left: Native GPS states */}
          <div style={{ position: 'absolute', left: 12, top: 38, width: 120, padding: 8, borderRadius: 6, background: 'rgba(7, 16, 27, 0.88)', border: '1px solid #16273e', fontSize: 7.5, zIndex: 10 }}>
            <b style={{ color: '#e2e8f0', display: 'block', marginBottom: 4 }}>GPS States</b>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}><span style={{ color: '#22c55e' }}>● Available</span><b style={{ color: '#fff' }}>{metrics.availableEvents}</b></div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}><span style={{ color: '#eab308' }}>● Inaccurate</span><b style={{ color: '#fff' }}>{metrics.inaccurateEvents}</b></div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}><span style={{ color: '#f97316' }}>● Unavailable</span><b style={{ color: '#fff' }}>{unavailableRows.length}</b></div>
              <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}><span style={{ color: '#a78bfa' }}>● Provider Error</span><b style={{ color: '#fff' }}>{providerFailureRows.length}</b></div>
            </div>
          </div>

          {/* Map Overlay Right: Native GPS providers */}
          <div style={{ position: 'absolute', right: 12, top: 38, width: 145, maxHeight: 260, overflowY: 'auto', padding: 8, borderRadius: 6, background: 'rgba(7, 16, 27, 0.88)', border: '1px solid #16273e', fontSize: 7.5, zIndex: 10 }}>
            <b style={{ color: '#e2e8f0', display: 'block', marginBottom: 4 }}>NATIVE GPS PROVIDERS</b>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
              {providerList.map(tc => (
                <div key={tc.name} style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                  <span>{tc.flag} {tc.name}</span>
                  <b style={{ color: '#38bdf8' }}>{tc.val}</b>
                </div>
              ))}
              {!providerList.length && <span style={{ color: '#64748b' }}>No GPS provider telemetry</span>}
            </div>
          </div>

        </div>

        {/* AJNAT GPS Stream Feed */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: 320 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>AJNAT GPS EVENTS</span>
              <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, overflowY: 'auto', maxHeight: 270, paddingRight: 2 }}>
              {geoAlerts.map((ga, idx) => (
                <button type="button" key={ga.id || idx} onClick={() => ga.hasGps && setSelectedEventId(ga.id)} title={ga.hasGps ? 'Focus this qualified GPS fix on the map' : 'No policy-qualified GPS coordinate'} style={{ background: selectedEventId === ga.id ? '#102a43' : '#07101b', border: selectedEventId === ga.id ? '1px solid #38bdf8' : '1px solid #16273e', borderRadius: 6, padding: 6, display: 'flex', flexDirection: 'column', gap: 2, fontSize: 7.5, textAlign: 'left', cursor: ga.hasGps ? 'pointer' : 'not-allowed', opacity: ga.hasGps ? 1 : 0.72 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ color: ga.sevCol, fontWeight: 800, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>{ga.icon}</span> {ga.title}
                    </span>
                    <span style={{ color: '#64748b', fontSize: 6.5 }}>{ga.time}</span>
                  </div>
                  <span style={{ color: '#8ea0b8' }}>Agent: <span style={{ color: '#cbd5e1' }}>{ga.user}</span></span>
                  <span style={{ color: '#8ea0b8' }}>{ga.detail}</span>
                  {ga.extra && <span style={{ color: '#64748b', fontFamily: 'monospace' }}>{ga.extra}</span>}
                  <span style={{ color: ga.hasGps ? MON.green : MON.yellow }}>{ga.hasGps ? '● Qualified GPS — click to locate' : '○ Coordinate not qualified'}</span>
                </button>
              ))}
              {!geoAlerts.length && <div style={{ color: '#64748b', padding: 8, textAlign: 'center' }}>No AJNAT GPS events reported</div>}
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.4fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <LoginRiskDistributionDonut rows={rows} />
        </div>

        <div style={panelStyle}>
          <LoginTrendOverTimeChart rows={rows} />
        </div>

        <div style={panelStyle}>
          <AnomalyDetectionSummaryDonut rows={rows} />
        </div>
      </div>

      {/* 4. BOTTOM SECTION (2 Main Columns: Left 75%, Right 25%) */}
      <div style={{ display: 'grid', gridTemplateColumns: '3fr 1fr', gap: 12 }}>
        {/* Left Column (latest GPS states + agent timeline) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* RECENT AJNAT GPS STATES */}
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>RECENT AJNAT GPS STATES</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 0.6fr 0.8fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
                <span>Agent</span>
                <span>Provider</span>
                <span>Accuracy</span>
                <span>Status</span>
                <span>Reported At</span>
                <span>GPS Rule</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
                {recentGpsStates.map((ral, idx) => (
                  <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr 0.6fr 0.8fr 1fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                    <span style={{ color: '#cbd5e1' }}>{ral.agent}</span>
                    <span style={{ color: '#e2e8f0' }}>{ral.provider}</span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{ral.accuracy == null ? '—' : `±${ral.accuracy}m`}</span>
                    <span style={{ fontSize: 7, fontWeight: 800, color: ral.statusCol, padding: '1px 3px', background: `${ral.statusCol}15`, borderRadius: 3, border: `1px solid ${ral.statusCol}33`, textAlign: 'center' }}>
                      {ral.status}
                    </span>
                    <span style={{ color: '#64748b' }}>{ral.detected}</span>
                    <span style={{ color: '#e2e8f0' }}>{ral.evt}</span>
                  </div>
                ))}
                {!recentGpsStates.length && <div style={{ color: '#64748b', padding: 8, textAlign: 'center' }}>No AJNAT GPS states reported</div>}
              </div>
            </div>
          </div>

          {/* AJNAT AGENT GPS TIMELINE */}
          <div style={{ ...panelStyle, height: 160, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>AJNAT AGENT GPS TIMELINE</span>
                <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>Latest reporting agent</span>
              </div>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 800, display: 'block', marginBottom: 8 }}>{selectedAgent}</span>

              <div style={{ display: 'flex', gap: 12 }}>
                {/* Timeline Items */}
                <div style={{ flex: 1.2, display: 'flex', flexDirection: 'column', gap: 4, fontSize: 7.5 }}>
                  {agentTimeline.map(row => (
                    <div key={row._id || `${alertTime(row)}-${gpsStatusOf(row)}`} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: '#64748b', width: 50 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}</span>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: isQualifiedGpsFix(row) ? MON.green : MON.orange }} />
                      <span style={{ color: '#cbd5e1' }}>{gpsProviderOf(row)} <span style={{ color: '#64748b', fontFamily: 'monospace' }}>{gpsStatusOf(row)} {gpsAccuracyOf(row) == null ? '' : `· ±${gpsAccuracyOf(row)}m`}</span></span>
                    </div>
                  ))}
                  {!agentTimeline.length && <span style={{ color: '#64748b' }}>No AJNAT GPS timeline reported</span>}
                </div>

                {/* Live GPS state summary */}
                <div style={{ flex: 1, height: 75, background: '#07101b', borderRadius: 6, border: '1px solid #16273e', overflow: 'hidden', position: 'relative' }}>
                  <div style={{ height: '100%', display: 'grid', placeItems: 'center', color: '#8ea0b8', fontSize: 8, textAlign: 'center', padding: 8 }}>
                    <span><b style={{ color: MON.cyan, fontSize: 15 }}>{agentTimeline.length}</b><br />real GPS states in this agent timeline</span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right Column (GPS state breakdown + providers) */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* GPS SENSOR STATUS */}
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>GPS SENSOR STATUS</span>
                <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <div style={{ position: 'relative', width: 75, height: 75, flexShrink: 0 }}>
                  <svg viewBox="0 0 75 75" width="75" height="75">
                    <circle cx="37.5" cy="37.5" r="28" fill="none" stroke="#16273e" strokeWidth="7" />
                    <circle cx="37.5" cy="37.5" r="28" fill="none" stroke="#22c55e" strokeWidth="7" strokeDasharray="130 176" strokeDashoffset="40" />
                    <circle cx="37.5" cy="37.5" r="28" fill="none" stroke="#eab308" strokeWidth="7" strokeDasharray="35 176" strokeDashoffset="-90" />
                    <circle cx="37.5" cy="37.5" r="28" fill="none" stroke="#ef4444" strokeWidth="7" strokeDasharray="12 176" strokeDashoffset="-125" />
                  </svg>
                  <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
                    <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{sensorTotal}</span>
                    <span style={{ fontSize: 6, color: '#8ea0b8' }}>GPS States</span>
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 7.5 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#22c55e' }} /> Available</span>
                    <span style={{ fontWeight: 700 }}>{availableCount} <span style={{ color: '#64748b', fontSize: 6.5 }}>({sensorTotal ? ((availableCount / sensorTotal) * 100).toFixed(1) : '0.0'}%)</span></span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#eab308' }} /> Inaccurate</span>
                    <span style={{ fontWeight: 700 }}>{inaccurateCount} <span style={{ color: '#64748b', fontSize: 6.5 }}>({sensorTotal ? ((inaccurateCount / sensorTotal) * 100).toFixed(1) : '0.0'}%)</span></span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1' }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 4, height: 4, borderRadius: '50%', background: '#ef4444' }} /> Unavailable</span>
                    <span style={{ fontWeight: 700 }}>{unavailableCount} <span style={{ color: '#64748b', fontSize: 6.5 }}>({sensorTotal ? ((unavailableCount / sensorTotal) * 100).toFixed(1) : '0.0'}%)</span></span>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* GPS PROVIDERS (LIVE) */}
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>GPS PROVIDERS <span style={{ fontSize: 7.5, color: '#64748b' }}>(LIVE)</span></span>
                <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 7.5 }}>
                {providerList.slice(0, 5).map(provider => (
                  <div key={provider.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #16273e', paddingBottom: 3 }}>
                    <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>{provider.flag}</span> {provider.name}
                    </span>
                    <span style={{ color: '#38bdf8', fontWeight: 800 }}>{provider.val}</span>
                  </div>
                ))}
                {!providerList.length && <span style={{ color: '#64748b' }}>No GPS provider telemetry</span>}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`GeolocationAnomalyDashboardPanel` / `GeolocationAnomalyDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function GeolocationAnomalyDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction, onRefresh, companyId: companyIdProp }) {
  const { company, user } = useAuth();
  const companyId = companyIdProp || company?._id || user?.companyId?._id || user?.companyId;
  const [searchParams] = useSearchParams();
  const requestedView = searchParams.get('view');
  const [activeTab, setActiveTab] = useState(requestedView === 'policy' ? 'policy' : 'dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);
  const [policies, setPolicies] = useState([]);
  const [panelGpsRows, setPanelGpsRows] = useState([]);

  useEffect(() => {
    if (requestedView === 'policy') setActiveTab('policy');
  }, [requestedView]);

  const updatePolicies = useCallback(next => {
    setPolicies(Array.isArray(next) ? next : []);
  }, []);

  useEffect(() => {
    let active = true;
    const load = () => api.get('/geolocation/policies', { params: companyId ? { companyId } : {}, skipCache: true }).then(r => {
      if (active) updatePolicies(r.data?.policies || []);
    }).catch(() => {});
    load();
    const timer = setInterval(load, 15000);
    return () => { active = false; clearInterval(timer); };
  }, [companyId, updatePolicies]);

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

  const loadPanelGpsFallback = useCallback(async () => {
    const params = { windowHours: 24, limit: 1000, ...(companyId ? { companyId } : {}) };
    try {
      const response = await api.get('/geolocation/overview', { params, skipCache: true });
      let next = response.data?.events || response.data?.alerts || [];
      if (!next.length) {
        const fallback = await api.get('/dashboard/alerts/edr', {
          params: { capabilityId: 23, page: 1, limit: 1000, ...(companyId ? { companyId } : {}) },
          skipCache: true,
        });
        next = fallback.data?.alerts || fallback.data?.events || [];
      }
      setPanelGpsRows(Array.isArray(next) ? next : []);
      if (Array.isArray(response.data?.systems) && response.data.systems.length) setBackendSystems(response.data.systems);
    } catch {
      try {
        const fallback = await api.get('/dashboard/alerts/edr', {
          params: { capabilityId: 23, page: 1, limit: 1000, ...(companyId ? { companyId } : {}) },
          skipCache: true,
        });
        const next = fallback.data?.alerts || fallback.data?.events || [];
        setPanelGpsRows(Array.isArray(next) ? next : []);
      } catch {
        setPanelGpsRows([]);
      }
    }
  }, [alerts, companyId]);

  useEffect(() => {
    if (Array.isArray(alerts) && alerts.length) {
      setPanelGpsRows([]);
      return undefined;
    }
    loadPanelGpsFallback();
    const timer = setInterval(loadPanelGpsFallback, 15000);
    return () => clearInterval(timer);
  }, [alerts, loadPanelGpsFallback]);

  const incomingRows = panelGpsRows.length ? panelGpsRows : alerts;
  const rows = useMemo(() => incomingRows.filter(isAjnatGeolocationEvent), [incomingRows]);
  const gpsMetrics = useMemo(
    () => buildAjnatGpsMetrics(rows, backendSystems, policies),
    [rows, backendSystems, policies]
  );
  const activePolicies = policies.filter(policy => policy.enabled);

  // Every monitoring KPI is derived from the current GPS-only API response.
  const kpis = [
    { label: '📡 1. GPS Records (24h)', val: shortNum(gpsMetrics.totalEvents), trend: 'AJNAT GPS', color: MON.blue, data: gpsMetrics.timeline },
    { label: '🖥️ 2. GPS Reporting Agents', val: shortNum(gpsMetrics.reportingAgents), trend: 'Unique Agents', color: MON.cyan, data: gpsMetrics.timeline },
    { label: '🟢 3. Online AJNAT Agents', val: shortNum(gpsMetrics.onlineAgents), trend: 'Agent Status', color: MON.green, data: gpsMetrics.timeline },
    { label: '⚫ 4. Offline AJNAT Agents', val: shortNum(gpsMetrics.offlineAgents), trend: 'Agent Status', color: MON.muted, data: gpsMetrics.timeline },
    { label: '✅ 5. Available GPS Events', val: shortNum(gpsMetrics.availableEvents), trend: 'Native Fix', color: MON.green, data: gpsMetrics.timeline },
    { label: '🎯 6. Accurate GPS Agents', val: shortNum(gpsMetrics.qualifiedAgents), trend: '≤50 Metres', color: MON.green, data: gpsMetrics.timeline },
    { label: '⚠️ 7. Inaccurate GPS Agents', val: shortNum(gpsMetrics.inaccurateAgents), trend: 'Latest State', color: MON.orange, data: gpsMetrics.timeline },
    { label: '🚫 8. Unavailable GPS Agents', val: shortNum(gpsMetrics.unavailableAgents), trend: 'Latest State', color: MON.red, data: gpsMetrics.timeline },
    { label: '🔐 9. Permission Denied', val: shortNum(gpsMetrics.permissionDeniedEvents), trend: 'Agent Reported', color: MON.red, data: gpsMetrics.timeline },
    { label: '📴 10. Sensor Unavailable', val: shortNum(gpsMetrics.unavailableEvents), trend: 'Agent Reported', color: MON.orange, data: gpsMetrics.timeline },
    { label: '❌ 11. Provider Errors', val: shortNum(gpsMetrics.providerErrorEvents), trend: 'Native Provider', color: MON.red, data: gpsMetrics.timeline },
    { label: '⏱️ 12. Provider Timeouts', val: shortNum(gpsMetrics.timeoutEvents), trend: 'Native Provider', color: MON.yellow, data: gpsMetrics.timeline },
    { label: '📍 13. Average Accuracy', val: gpsMetrics.averageAccuracy == null ? '—' : `±${gpsMetrics.averageAccuracy}m`, trend: 'Reported GPS', color: MON.cyan, data: gpsMetrics.timeline },
    { label: '🎯 14. Best Accuracy', val: gpsMetrics.bestAccuracy == null ? '—' : `±${gpsMetrics.bestAccuracy}m`, trend: 'Reported GPS', color: MON.green, data: gpsMetrics.timeline },
    { label: '📏 15. Worst Accuracy', val: gpsMetrics.worstAccuracy == null ? '—' : `±${gpsMetrics.worstAccuracy}m`, trend: 'Reported GPS', color: MON.orange, data: gpsMetrics.timeline },
    { label: '🛰️ 16. GeoClue Events', val: shortNum(gpsMetrics.geoclueEvents), trend: 'Linux Provider', color: MON.purple, data: gpsMetrics.timeline },
    { label: '🛰️ 17. GNSS/GPSD Events', val: shortNum(gpsMetrics.gnssEvents), trend: 'Hardware GPS', color: MON.blue, data: gpsMetrics.timeline },
    { label: '🪟 18. Windows GPS Events', val: shortNum(gpsMetrics.windowsEvents), trend: 'Windows Provider', color: MON.cyan, data: gpsMetrics.timeline },
    { label: '🛡️ 19. Enabled GPS Policies', val: shortNum(gpsMetrics.enabledPolicies), trend: 'Policy Engine', color: MON.green, data: gpsMetrics.timeline },
    { label: '🎯 20. Policy Target Agents', val: shortNum(gpsMetrics.targetedAgents), trend: 'Unique Agents', color: MON.purple, data: gpsMetrics.timeline },
  ];

  const gpsRowsByAgent = gpsMetrics.rows.reduce((groups, row) => {
    const key = ajnatSystemKey(row) || normHost(alertHost(row));
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
    return groups;
  }, new Map());
  const latestGpsByAgent = gpsMetrics.latestRows.reduce((groups, row) => {
    const systemKey = ajnatSystemKey(row);
    const hostKey = normHost(alertHost(row));
    if (systemKey) groups.set(systemKey, row);
    if (hostKey && hostKey !== 'unknown') groups.set(hostKey, row);
    return groups;
  }, new Map());
  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const systemKey = systemRecordKey(sys);
    const agentEvents = gpsRowsByAgent.get(systemKey) || gpsRowsByAgent.get(normHost(host)) || [];
    const latest = latestGpsByAgent.get(systemKey) || latestGpsByAgent.get(normHost(host)) || agentEvents[0];
    const accuracy = latest ? gpsAccuracyOf(latest) : null;
    return ({
      key: systemKey || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      online: Boolean(sys.agentOk || sys.isOnline || sys.online || String(sys.status || '').toLowerCase() === 'online'),
      gpsStatus: latest ? (gpsStatusOf(latest) || 'unknown') : 'not reported',
      provider: latest ? gpsProviderOf(latest) : '—',
      accuracy,
      qualified: latest ? isQualifiedGpsFix(latest) : false,
      events: agentEvents.length,
      platform: processOs(sys),
      lastSeen: latest ? alertTime(latest) : null,
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
        {activeTab === 'policy' ? (
          <GeoPolicyEngine companyId={companyId} onPoliciesChange={updatePolicies} />
        ) : activeTab === 'log-monitor' ? (
          <GeoAnomalyLogMonitor alerts={rows} companyId={companyId} onAction={onAction} />
        ) : activeTab === 'reports' ? (
          <GeoAnomalyReportsTab alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <>
            <GeoOverviewDashboard metrics={gpsMetrics} />
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

            {/* Live policy-category outcomes */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {gpsMetrics.categoryStats.map(stat => {
                const policy = policies.find(item => item.category === stat.category && item.enabled);
                return (
                  <div key={stat.category} style={{ background: MON.card, border: `1px solid ${stat.blocked ? MON.red : MON.border}`, borderRadius: 8, padding: 12 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <b style={{ color: MON.cyan, fontSize: 10 }}>{stat.category}</b>
                      <span style={{ color: policy ? MON.green : MON.muted, fontSize: 8, fontWeight: 900 }}>{policy ? 'ACTIVE' : 'INACTIVE'}</span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 10 }}>
                      <div><b style={{ color: MON.text, fontSize: 20 }}>{stat.events}</b><div style={{ color: MON.sub, fontSize: 8 }}>LIVE EVENTS</div></div>
                      <div style={{ textAlign: 'right' }}><b style={{ color: stat.blocked ? MON.red : MON.muted, fontSize: 20 }}>{stat.blocked}</b><div style={{ color: MON.sub, fontSize: 8 }}>BLOCKED</div></div>
                    </div>
                    <div style={{ color: MON.sub, fontSize: 8, marginTop: 8 }}>{stat.latestAt ? `Latest ${relativeTime(stat.latestAt)}` : 'No category event received'}</div>
                  </div>
                );
              })}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 AJNAT Native GPS Agent Monitoring</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} AJNAT agents loaded · {gpsMetrics.totalEvents} GPS records observed</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 1fr 110px 100px 80px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>AJNAT Agent</span><span>Agent State</span><span>GPS Provider</span><span>GPS Status</span><span>Accuracy</span><span>Events</span><span>Latest GPS Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 1fr 110px 100px 80px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <div><b style={{ color: MON.cyan }}>{row.hostname}</b><div style={{ color: MON.sub, fontSize: 8 }}>{row.platform}</div></div>
                  <b style={{ color: row.online ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.online ? 'online' : 'offline'}</b>
                  <span style={{ color: MON.text }}>{row.provider}</span>
                  <b style={{ color: row.qualified ? MON.green : row.gpsStatus === 'not reported' ? MON.muted : MON.orange, textTransform: 'uppercase' }}>{row.gpsStatus}</b>
                  <b style={{ color: row.qualified ? MON.green : row.accuracy == null ? MON.muted : MON.orange }}>{row.accuracy == null ? '—' : `±${row.accuracy}m`}</b>
                  <b>{row.events}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? relativeTime(row.lastSeen) : 'Not reported'}</span>
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
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time AJNAT GPS Event Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {gpsMetrics.timeline.map((val, idx, arr) => (
                    <div key={idx} title={`${val} GPS events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛰 Native GPS Provider Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(gpsMetrics.providerCounts.length ? gpsMetrics.providerCounts.slice(0, 5) : [['No GPS provider telemetry', 0]]).map(([provider, count], index) => (
                    <div key={provider} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{provider}</span>
                      <span style={{ color: [MON.cyan, MON.purple, MON.green, MON.yellow, MON.orange][index] || MON.muted, fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Policy Action Engine Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(activePolicies.length ? activePolicies.slice(0, 4).map(policy => [policy.name || policy.policyName || 'Geolocation policy', String(policy.action || policy.actions?.[0]?.type || policy.actions?.[0] || 'Enabled'), MON.green]) : [['No enabled policies', 'Not configured', MON.muted]]).map(([lbl, stat, col]) => (
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
      const r = await api.get('/geolocation/overview', {
        params: { limit: 1000, windowHours: 24, ...(companyId ? { companyId } : {}) },
        skipCache: true,
      });
      const next = r.data?.events || r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
      if (Array.isArray(r.data?.systems)) setSystems(r.data.systems);
    } catch {
      setAlerts([]);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [companyId]);

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
    socket.on('geo:event', buf.add);
    socket.on('geo:anomaly', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('geo:event', buf.add);
      socket.off('geo:anomaly', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleResponseAction = useCallback(async (alertId, actionType) => {
    const reason = window.prompt(`Enter the reason for ${String(actionType).replaceAll('_', ' ')}:`)?.trim() || '';
    if (!reason) throw new Error('Action cancelled: a reason is required');
    if (actionType === 'ignore') {
      const response = await api.patch(`/dashboard/alerts/${alertId}/action`, { action: 'ignore', reason, confirmed: false });
      await loadAlerts(true);
      return response.data;
    }
    if (!window.confirm(`Confirm ${String(actionType).replaceAll('_', ' ')} for this AJNAT event?`)) {
      throw new Error('Containment cancelled');
    }
    const response = await api.post('/geolocation/respond', {
      alertId, actionType, reason, confirmed: true, ...(companyId ? { companyId } : {}),
    });
    await loadAlerts(true);
    return response.data;
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
        <GeolocationAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} companyId={companyId} onAction={handleResponseAction} onRefresh={() => loadAlerts(false)} />
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
