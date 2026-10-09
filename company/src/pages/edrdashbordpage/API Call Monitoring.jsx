import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * API Call Monitoring — Capability ID: 20
 *
 * 100% Self-Contained Enterprise SOC API Call Monitoring & WAF Attack Detection Module
 * Linked to the tenant-scoped API monitoring backend, MongoDB Alert/WAF queries, and Socket.io real-time streaming.
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19)
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

function MiniSparkline({ data = [], color = MON.cyan, height = 30 }) {
  const values = Array.isArray(data) && data.length ? data : [0, 0];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values.map((val, idx) => {
    const x = (idx / Math.max(values.length - 1, 1)) * 100;
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
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'Unknown host';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || 'Unknown user';
}

function alertStatus(row) {
  return row?.status || row?.state || 'Observed';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'info').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'critical';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu') || osStr.includes('k8s')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Linux';
}

// ── API Telemetry Field Extractors ──────────────────────────────────────────
function apiEndpointUrl(row) {
  return row?.url || row?.uri || row?.requestPath || row?.path || row?.rawEvent?.url || row?.rawEvent?.uri || row?.rawEvent?.path || 'Unknown endpoint';
}

function apiMethod(row) {
  return row?.method || row?.requestMethod || row?.rawEvent?.method || row?.rawEvent?.request_method || '—';
}

function apiStatusCode(row) {
  const value = Number(row?.statusCode ?? row?.httpStatusCode ?? row?.rawEvent?.status_code ?? row?.rawEvent?.response_status);
  return Number.isFinite(value) ? value : 0;
}

function apiClientIp(row) {
  return row?.clientIp || row?.srcip || row?.srcIp || row?.sourceIp || row?.rawEvent?.source_ip || row?.ip || 'Unknown IP';
}

function apiVerdict(row) {
  return row?.verdict || row?.ruleName || row?.category || 'API telemetry event';
}

function containsAny(row, words = []) {
  const haystack = [
    apiEndpointUrl(row), apiMethod(row), apiClientIp(row), apiVerdict(row), alertHost(row),
    row?.description, row?.message, row?.wafProvider, row?.payload,
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${apiEndpointUrl(row)}-${apiClientIp(row)}`;
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
// 1. API FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function ApiForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'request', label: '⇄ 2. Raw HTTP Request' },
    { id: 'payload', label: '▤ 3. Request Payload' },
    { id: 'response', label: '◎ 4. Response Payload' },
    { id: 'ipinfo', label: '⌾ 5. Source IP & Geo Info' },
    { id: 'waf', label: '🛡️ 6. WAF Rule & Engine' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK Map' },
    { id: 'agent', label: '⚙️ 8. Agent Process Details' },
    { id: 'iocs', label: '🔍 9. Threat IOCs & Artifacts' },
    { id: 'actions', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionType, actionName) => {
    if (!actionType || typeof onAction !== 'function' || !log?._id) {
      setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
      return;
    }
    try {
      await onAction(String(log._id), actionType);
      setActionSuccess(`Approved action submitted: ${actionName}`);
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
            <span style={{ fontSize: 24 }}>📡</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  API Forensic Panel — {apiEndpointUrl(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {apiVerdict(log)}
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {log.riskScore ?? 0}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Host: <strong style={{ color: MON.cyan }}>{alertHost(log)}</strong> | Client IP: <strong style={{ color: MON.yellow }}>{apiClientIp(log)}</strong> | Method: <strong>{apiMethod(log)}</strong> | Status: <strong>{apiStatusCode(log)}</strong>
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
          {/* TAB 1: OVERVIEW & STATIC ANALYSIS */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Attack Verdict', apiVerdict(log).toUpperCase(), sevColor],
                  ['Risk Score', `${log.riskScore ?? 0} / 100`, MON.red],
                  ['Response Status', `${apiStatusCode(log)} HTTP`, apiStatusCode(log) >= 400 ? MON.red : MON.green],
                  ['Target Method', apiMethod(log), MON.yellow],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>📡 Incident Event Description</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  The configured ingress source (<strong>{log.wafProvider || 'not reported'}</strong>) reported rule <strong>{log.wafRuleId || 'not reported'}</strong> for client IP <strong>{apiClientIp(log)}</strong> targeting API endpoint <strong>{apiEndpointUrl(log)}</strong>.
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: RAW HTTP REQUEST */}
          {activeTab === 'request' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan }}>⇄ Raw Request Headers & Query Params</h4>
              <pre style={{ background: MON.bg, color: MON.yellow, padding: 12, borderRadius: 6, fontFamily: 'monospace', fontSize: 11, overflowX: 'auto', border: `1px solid ${MON.border}` }}>
                {JSON.stringify({ method: apiMethod(log), url: apiEndpointUrl(log), headers: log.requestHeaders || {} }, null, 2)}
              </pre>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Automated API Gateway SOC Remediation Actions</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('block_ip', `Block IP ${apiClientIp(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Block IP on WAF
                  </button>
                  <button type="button" onClick={() => handleAction(null, `Apply Rate-Limit on ${apiEndpointUrl(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ⏳ Apply Endpoint Rate Limit
                  </button>
                  <button type="button" onClick={() => handleAction(null, 'Revoke Client Bearer Token')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔑 Revoke Bearer Token
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'payload' && <TelemetryBlock title="REQUEST PAYLOAD" value={log.requestPayload ?? 'Not reported by the agent/WAF source'} />}
          {activeTab === 'response' && <TelemetryBlock title="RESPONSE TELEMETRY" value={{ statusCode: apiStatusCode(log) || 'Not reported', responseTimeMs: log.responseTimeMs || 'Not reported', responseSize: log.responseSize || 'Not reported', headers: log.responseHeaders || {}, payload: log.responsePayload ?? 'Not reported' }} />}
          {activeTab === 'ipinfo' && <TelemetryBlock title="SOURCE IP & GEO" value={{ sourceIp: apiClientIp(log), country: log.country || 'Not reported', region: log.region || 'Not reported', city: log.city || 'Not reported', asn: log.asn || 'Not reported', isp: log.isp || 'Not reported' }} />}
          {activeTab === 'waf' && <TelemetryBlock title="WAF RULE & ENGINE" value={{ provider: log.wafProvider || 'Not reported', ruleId: log.wafRuleId || log.ruleId || 'Not reported', ruleName: log.wafRuleName || 'Not reported', signature: log.matchedSignature || 'Not reported', action: log.action || 'Observed' }} />}
          {activeTab === 'mitre' && <TelemetryBlock title="MITRE ATT&CK" value={log.mitreId || log.mitreTechnique || 'Not mapped for this event'} />}
          {activeTab === 'agent' && <TelemetryBlock title="AGENT PROCESS DETAILS" value={{ hostname: alertHost(log), process: log.processName || 'Not reported', pid: log.pid || 'Not reported', parentProcess: log.parentProcess || 'Not reported', backendService: log.backendService || 'Not reported', destinationPort: log.destinationPort || 'Not reported' }} />}
          {activeTab === 'iocs' && <TelemetryBlock title="THREAT IOCS & ARTIFACTS" value={{ sourceIp: apiClientIp(log), destinationIp: log.destinationIp || 'Not reported', matchedSignature: log.matchedSignature || 'Not reported', hash: log.hash || log.fileHash || 'Not reported', threatIntel: log.threatIntel || 'Not reported' }} />}
        </div>
      </div>
    </div>
  );
}

function TelemetryBlock({ title, value }) {
  return <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}><h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{title}</h4><pre style={{ margin: 0, whiteSpace: 'pre-wrap', color: MON.text, fontSize: 11 }}>{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre></div>;
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard, API Inspector)
// ═════════════════════════════════════════════════════════════════════════════
export function ApiLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${apiEndpointUrl(a)} ${apiClientIp(a)} ${apiVerdict(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Endpoint URL, Client IP, Target Host, Verdict..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
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
          <b style={{ fontSize: 12, color: '#fff' }}>📜 API Call & WAF Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1.2fr 90px 100px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>API Target Endpoint</span><span>Target Host</span><span>Client IP</span><span>Method</span><span>WAF Verdict</span><span>Risk Score</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.2fr 1.2fr 90px 100px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{apiEndpointUrl(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.yellow, fontFamily: 'monospace' }}>{apiClientIp(row)}</span>
                <b style={{ color: apiMethod(row) === 'POST' ? MON.yellow : MON.green }}>{apiMethod(row)}</b>
                <b style={{ color: SEV_COLOR[alertSeverity(row)] || MON.blue, textTransform: 'uppercase' }}>{apiVerdict(row)}</b>
                <b style={{ color: Number(row.riskScore || 0) > 75 ? MON.red : MON.orange }}>{row.riskScore ?? 0}/100</b>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No API call monitoring logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <ApiForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function ApiReportsTab({ alerts = [] }) {
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
    const header = 'Timestamp,Endpoint URL,Method,Client IP,Target Host,Verdict,Risk Score,Status';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(apiEndpointUrl(a)),
      csvCell(apiMethod(a)),
      csvCell(apiClientIp(a)),
      csvCell(alertHost(a)),
      csvCell(apiVerdict(a)),
      csvCell(a.riskScore ?? 0),
      csvCell(alertStatus(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `api_call_monitoring_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 API Call & WAF Attack Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for SQL Injection, Credential Stuffing, SSRF Cloud Exploits, and API Rate Limit Abuse</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate API Report'}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 API Call Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored API Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total API Requests', val: reportData?.total, color: MON.cyan },
              { label: 'Critical WAF Blocks', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk API Attacks', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Successful API Calls', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for API Call Monitoring Dashboard ─────────────
function ApiTrafficOverTimeChart({ alerts = [] }) {
  const now = Date.now();
  const start = now - 24 * 3600000;
  const pointsTotal = Array(12).fill(0);
  const pointsSuccess = Array(12).fill(0);
  const pointsFailed = Array(12).fill(0);
  alerts.forEach(row => {
    const ms = new Date(alertTime(row) || 0).getTime();
    if (!Number.isFinite(ms) || ms < start || ms > now) return;
    const index = Math.min(11, Math.max(0, Math.floor((ms - start) / (2 * 3600000))));
    const status = apiStatusCode(row);
    pointsTotal[index] += 1;
    if (status >= 200 && status < 400) pointsSuccess[index] += 1;
    else if (status >= 400 || ['high', 'critical'].includes(alertSeverity(row))) pointsFailed[index] += 1;
  });

  const maxVal = Math.max(...pointsTotal, ...pointsSuccess, ...pointsFailed, 1);
  const width = 360;
  const height = 110;

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
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>API Traffic Over Time</span>
          <div style={{ display: 'flex', gap: 10, fontSize: 7.5 }}>
            <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, background: '#38bdf8', borderRadius: 1 }} /> Total Calls</span>
            <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, background: '#22c55e', borderRadius: 1 }} /> Successful Calls</span>
            <span style={{ color: '#ef4444', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 6, height: 6, background: '#ef4444', borderRadius: 1 }} /> Failed Calls</span>
          </div>
        </div>

        <div style={{ position: 'relative', width: '100%', height: 110, marginTop: 4 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" style={{ overflow: 'visible' }}>
            {/* Grid lines */}
            {[0, 25, 50, 75, 100].map(val => {
              const y = height - (val / maxVal) * (height - 10) - 5;
              return <line key={val} x1="0" y1={y} x2={width} y2={y} stroke="#16273e" strokeWidth="0.5" strokeDasharray="2 2" />;
            })}

            {/* Total Line */}
            <path d={`M ${getSvgPath(pointsTotal)}`} fill="none" stroke="#38bdf8" strokeWidth="1.5" />
            {pointsTotal.map((val, idx) => {
              const x = (idx / (pointsTotal.length - 1)) * width;
              const y = height - (val / maxVal) * (height - 10) - 5;
              return <circle key={idx} cx={x} cy={y} r="2.5" fill="#38bdf8" />;
            })}

            {/* Success Line */}
            <path d={`M ${getSvgPath(pointsSuccess)}`} fill="none" stroke="#22c55e" strokeWidth="1.5" />
            {pointsSuccess.map((val, idx) => {
              const x = (idx / (pointsSuccess.length - 1)) * width;
              const y = height - (val / maxVal) * (height - 10) - 5;
              return <circle key={idx} cx={x} cy={y} r="2.5" fill="#22c55e" />;
            })}

            {/* Failed Line */}
            <path d={`M ${getSvgPath(pointsFailed)}`} fill="none" stroke="#ef4444" strokeWidth="1.5" />
            {pointsFailed.map((val, idx) => {
              const x = (idx / (pointsFailed.length - 1)) * width;
              const y = height - (val / maxVal) * (height - 10) - 5;
              return <circle key={idx} cx={x} cy={y} r="2.5" fill="#ef4444" />;
            })}
          </svg>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 4 }}>
          {['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'].map(t => (
            <span key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function AuthFailuresDonutChart({ alerts = [] }) {
  const definitions = [
    ['Invalid API Key', /invalid api key/, '#a78bfa'],
    ['Expired Token', /expired token/, '#38bdf8'],
    ['Invalid Token', /invalid token/, '#eab308'],
    ['Auth Failures', /auth(?:entication)? failure|unauthori[sz]ed|forbidden/, '#ef4444'],
  ];
  const text = row => `${row?.ruleId || ''} ${row?.attackType || ''} ${row?.description || ''}`.toLowerCase();
  const counts = definitions.map(([, pattern]) => alerts.filter(row => pattern.test(text(row))).length);
  const matched = counts.reduce((sum, count) => sum + count, 0);
  const other = alerts.filter(row => apiStatusCode(row) === 401 || apiStatusCode(row) === 403).length;
  const totalFailures = Math.max(matched, other);
  const items = definitions.map(([label, , color], index) => ({
    label, val: shortNum(counts[index]), color,
    pct: totalFailures ? Number(((counts[index] / totalFailures) * 100).toFixed(1)) : 0,
  }));

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
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 8, display: 'block' }}>Authentication Failures</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{shortNum(totalFailures)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total Failures</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.pct}% <span style={{ fontSize: 7, color: '#64748b' }}>({it.val})</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Auth Events →</span>
    </div>
  );
}

function ResponseTimeAnalyticsChart({ alerts = [] }) {
  const samples = alerts.map(row => Number(row?.responseTimeMs ?? row?.latencyMs ?? row?.rawEvent?.response_time_ms)).filter(Number.isFinite).sort((a, b) => a - b);
  const points = samples.length ? samples.slice(-12) : Array(12).fill(0);
  const maxVal = Math.max(...points, 1);
  const percentile = pct => samples.length ? samples[Math.min(samples.length - 1, Math.ceil(samples.length * pct) - 1)] : null;
  const formatMs = value => Number.isFinite(value) ? `${Math.round(value)} ms` : 'Not reported';
  const width = 280;
  const height = 65;

  const pointsStr = points.map((val, idx) => {
    const x = (idx / (points.length - 1)) * width;
    const y = height - (val / maxVal) * (height - 6) - 3;
    return `${x},${y}`;
  }).join(' L ');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 4, display: 'block' }}>Response Time Analytics</span>
        <span style={{ fontSize: 7.5, color: '#38bdf8', fontWeight: 700 }}>■ Avg Response Time (ms)</span>
        <div style={{ position: 'relative', width: '100%', height: 65, marginTop: 4 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" preserveAspectRatio="none">
            <path d={`M ${pointsStr}`} fill="none" stroke="#38bdf8" strokeWidth="1.5" />
          </svg>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 4, marginTop: 6, textAlign: 'center', fontSize: 7.5 }}>
          <div style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 2px' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: 6.5 }}>Min</span>
            <span style={{ color: '#fff', fontWeight: 800 }}>{formatMs(samples[0])}</span>
          </div>
          <div style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 2px' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: 6.5 }}>Max</span>
            <span style={{ color: '#fff', fontWeight: 800 }}>{formatMs(samples.at(-1))}</span>
          </div>
          <div style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 2px' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: 6.5 }}>95th Pct</span>
            <span style={{ color: '#fff', fontWeight: 800 }}>{formatMs(percentile(.95))}</span>
          </div>
          <div style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 4, padding: '3px 2px' }}>
            <span style={{ color: '#64748b', display: 'block', fontSize: 6.5 }}>99th Pct</span>
            <span style={{ color: '#fff', fontWeight: 800 }}>{formatMs(percentile(.99))}</span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ApiOverviewDashboard({ alerts = [], total = 0, summary = {} }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const traffic = buildBuckets(rows, 6, 24);
  const successful = summary.successfulCalls ?? rows.filter(row => apiStatusCode(row) >= 200 && apiStatusCode(row) < 400).length;
  const failed = summary.failedCalls ?? rows.filter(row => apiStatusCode(row) >= 400 || ['high', 'critical'].includes(alertSeverity(row))).length;
  const latency = rows.map(row => Number(row?.responseTimeMs ?? row?.latencyMs ?? row?.rawEvent?.response_time_ms)).filter(Number.isFinite);
  const avgLatency = summary.averageResponseTimeMs ?? (latency.length ? Math.round(latency.reduce((sum, value) => sum + value, 0) / latency.length) : null);
  const endpointMap = new Map();
  rows.forEach(row => {
    const ep = apiEndpointUrl(row);
    if (ep === 'Unknown endpoint') return;
    const entry = endpointMap.get(ep) || { ep, method: apiMethod(row), calls: 0, success: 0, latency: [] };
    entry.calls += 1;
    if (apiStatusCode(row) >= 200 && apiStatusCode(row) < 400) entry.success += 1;
    const ms = Number(row?.responseTimeMs ?? row?.latencyMs ?? row?.rawEvent?.response_time_ms);
    if (Number.isFinite(ms)) entry.latency.push(ms);
    endpointMap.set(ep, entry);
  });
  const topEndpoints = [...endpointMap.values()].sort((a, b) => b.calls - a.calls).slice(0, 5).map(entry => {
    const successRate = entry.calls ? (entry.success / entry.calls) * 100 : 0;
    const responseMs = entry.latency.length ? Math.round(entry.latency.reduce((sum, value) => sum + value, 0) / entry.latency.length) : null;
    return { ...entry, calls: shortNum(entry.calls), rate: `${successRate.toFixed(1)}%`, time: responseMs === null ? 'Not reported' : `${responseMs} ms`, col: successRate >= 90 ? '#22c55e' : successRate >= 70 ? '#f97316' : '#ef4444' };
  });
  const threatDefs = [
    ['SQL Injection Attempts', /sql injection|\bsqli\b/, 'High', '#ef4444'],
    ['XSS Attempts', /cross.site scripting|\bxss\b/, 'High', '#ef4444'],
    ['Path Traversal Attempts', /path traversal/, 'Medium', '#f97316'],
    ['Brute Force Attempts', /brute force|credential stuffing/, 'Medium', '#f97316'],
    ['SSRF Attempts', /\bssrf\b/, 'High', '#ef4444'],
  ];
  const eventText = row => `${row?.ruleId || ''} ${row?.attackType || ''} ${row?.description || ''}`.toLowerCase();
  const topThreats = threatDefs.map(([type, pattern, sev, col]) => {
    const matching = rows.filter(row => pattern.test(eventText(row)));
    return { type, count: shortNum(matching.length), sev, col, spark: buildBuckets(matching, 5, 24), rawCount: matching.length };
  }).filter(item => item.rawCount > 0);
  const limitedRows = rows.filter(row => apiStatusCode(row) === 429 || /rate limit/.test(eventText(row)));
  const rateLimitTimeline = buildBuckets(limitedRows, 9, 24);
  const rateLimitViolators = topCounts(limitedRows, apiClientIp, 4).map(([ip, count]) => ({ ip, count }));
  const requestSizes = rows.map(row => Number(row?.requestSize ?? row?.rawEvent?.request_size)).filter(Number.isFinite);
  const responseSizes = rows.map(row => Number(row?.responseSize ?? row?.rawEvent?.response_size)).filter(Number.isFinite);
  const avgKb = values => values.length ? `${(values.reduce((sum, value) => sum + value, 0) / values.length / 1024).toFixed(2)} kB` : 'Not reported';
  const payloadMetrics = [
    { title: 'Avg Request Size', val: avgKb(requestSizes), sub: 'Live telemetry', col: '#38bdf8', spark: requestSizes.slice(-5) },
    { title: 'Avg Response Size', val: avgKb(responseSizes), sub: 'Live telemetry', col: '#22c55e', spark: responseSizes.slice(-5) },
    { title: 'Large Payloads', val: shortNum(rows.filter(row => Number(row?.requestSize ?? row?.rawEvent?.request_size) >= 1048576 || /large payload/.test(eventText(row))).length), sub: '≥ 1 MB or detected', col: '#eab308', spark: traffic },
  ];
  const realTimeApiEvents = [...rows].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 5).map(row => ({
    type: row.attackType || row.ruleName || row.description || row.ruleId || 'API telemetry event',
    ep: `${apiMethod(row)} ${apiEndpointUrl(row)}`,
    tag: row.status || row.action || alertSeverity(row),
    tagCol: SEV_COLOR[alertSeverity(row)] || '#38bdf8',
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
    ip: apiClientIp(row),
    icon: ['critical', 'high'].includes(alertSeverity(row)) ? '⚠️' : '🟢',
  }));
  const topCards = [
    { title: 'Total API Calls', val: shortNum(total || rows.length), sub: 'Last 24 hours', col: '#38bdf8', icon: '🗄️', spark: traffic },
    { title: 'Successful Calls', val: shortNum(successful), sub: rows.length ? `${((successful / rows.length) * 100).toFixed(1)}% success rate` : 'No status telemetry', col: '#22c55e', icon: '✅', spark: traffic },
    { title: 'Failed Calls', val: shortNum(failed), sub: rows.length ? `${((failed / rows.length) * 100).toFixed(1)}% failure/risk rate` : 'No status telemetry', col: '#ef4444', icon: '❌', spark: traffic },
    { title: 'Avg Response Time', val: avgLatency === null ? 'Not reported' : `${avgLatency} ms`, sub: 'Live response telemetry', col: '#eab308', icon: '⏱️', spark: latency.slice(-6) },
    { title: 'Active Endpoints', val: shortNum(summary.activeApis ?? endpointMap.size), sub: 'Observed endpoints', col: '#a78bfa', icon: '🌐', spark: traffic },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* Filter Button */}
      <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
        <button style={{ background: '#0b1626', border: '1px solid #16273e', color: '#e2e8f0', padding: '4px 10px', borderRadius: 6, fontSize: 8.5, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer' }}>
          <span>🎛️</span> Filter
        </button>
      </div>

      {/* 1. TOP STAT CARDS (5 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {topCards.map(s => (
          <div key={s.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 4 }}>
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

      {/* 2. UPPER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.3fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <ApiTrafficOverTimeChart alerts={rows} />
        </div>

        {/* Top API Endpoints */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Top API Endpoints</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.6fr 1fr 1fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>Endpoint</span>
              <span>Method</span>
              <span>Total Calls</span>
              <span>Success Rate</span>
              <span>Avg Response Time</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topEndpoints.map(ep => (
                <div key={ep.ep} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.6fr 1fr 1fr 1fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: '#cbd5e1', fontFamily: 'monospace' }}>{ep.ep}</span>
                  <span style={{ color: '#38bdf8', fontWeight: 800 }}>{ep.method}</span>
                  <span style={{ color: '#e2e8f0' }}>{ep.calls}</span>
                  <span style={{ color: '#22c55e', fontWeight: 700 }}>{ep.rate}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <div style={{ width: 25, height: 4, background: '#07101b', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: '80%', height: '100%', background: ep.col }} />
                    </div>
                    <span style={{ color: '#8ea0b8', fontSize: 7.5 }}>{ep.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Endpoints →</span>
        </div>

        <div style={panelStyle}>
          <AuthFailuresDonutChart alerts={rows} />
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (2 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr', gap: 12 }}>
        {/* Threat Detection (Top Events) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Threat Detection <span style={{ fontSize: 8, color: '#64748b' }}>(Top Events)</span></span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 0.8fr 1fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>Threat Type</span>
              <span>Count</span>
              <span>Trend</span>
              <span>Severity</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topThreats.map(tt => (
                <div key={tt.type} style={{ display: 'grid', gridTemplateColumns: '1.5fr 0.8fr 1fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: '#cbd5e1' }}>{tt.type}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{tt.count}</span>
                  <div style={{ width: 35, height: 10 }}>
                    <MiniSparkline data={tt.spark} color={tt.col} height={10} />
                  </div>
                  <span style={{ fontSize: 7.5, fontWeight: 800, color: tt.col, padding: '1px 4px', background: `${tt.col}15`, borderRadius: 3, border: `1px solid ${tt.col}33`, textAlign: 'center' }}>
                    {tt.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Threats →</span>
        </div>

        <div style={panelStyle}>
          <ResponseTimeAnalyticsChart alerts={rows} />
        </div>
      </div>

      {/* 4. BOTTOM GRID (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1.3fr', gap: 12 }}>
        {/* Rate Limit Violations */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 6, display: 'block' }}>Rate Limit Violations</span>
            <div style={{ display: 'flex', gap: 12 }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 16, fontWeight: 800, color: '#fff' }}>{shortNum(limitedRows.length)}</span>
                <span style={{ fontSize: 7.5, color: '#22c55e', display: 'block', marginBottom: 6 }}>Observed in last 24 hours</span>
                <div style={{ height: 40, display: 'flex', alignItems: 'flex-end', gap: 3 }}>
                  {rateLimitTimeline.map((v, idx) => (
                    <div key={idx} style={{ flex: 1, height: `${Math.max(3, (v / Math.max(...rateLimitTimeline, 1)) * 100)}%`, background: '#ef4444', borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 3, fontSize: 8 }}>
                <span style={{ color: '#64748b', fontWeight: 700, fontSize: 7.5 }}>Top Violators</span>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b', fontSize: 7 }}>
                  <span>IP Address</span>
                  <span>Violations</span>
                </div>
                {rateLimitViolators.map(rv => (
                  <div key={rv.ip} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{rv.ip}</span>
                    <span style={{ color: '#ef4444', fontWeight: 800 }}>{rv.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Violations →</span>
        </div>

        {/* Payload Analysis */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Payload Analysis</span>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
              {payloadMetrics.map(pm => (
                <div key={pm.title} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '8px 6px', display: 'flex', flexDirection: 'column', gap: 3 }}>
                  <span style={{ fontSize: 7, color: '#8ea0b8', fontWeight: 700 }}>{pm.title}</span>
                  <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{pm.val}</span>
                  <span style={{ fontSize: 7, color: pm.col, fontWeight: 700 }}>{pm.sub}</span>
                  <div style={{ width: '100%', height: 10, marginTop: 2 }}>
                    <MiniSparkline data={pm.spark} color={pm.col} height={10} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Payload Analysis →</span>
        </div>

        {/* Real-time API Events */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Real-time API Events</span>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {realTimeApiEvents.map((ev, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden' }}>
                    <span>{ev.icon}</span>
                    <span style={{ color: '#e2e8f0', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.type}</span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 7.5 }}>{ev.ep}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexShrink: 0 }}>
                    <span style={{ fontSize: 7, fontWeight: 800, color: ev.tagCol, background: `${ev.tagCol}15`, padding: '1px 4px', borderRadius: 3, border: `1px solid ${ev.tagCol}33` }}>
                      {ev.tag}
                    </span>
                    <div style={{ textAlign: 'right', fontSize: 7, color: '#64748b' }}>
                      <span>{ev.time}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View All Events →</span>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`ApiCallMonitoringDashboardPanel` / `ApiCallMonitoringDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function ApiCallMonitoringDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);
  const [liveOverview, setLiveOverview] = useState(null);
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const refreshLiveOverview = useCallback(async () => {
    try {
      const response = await api.get('/api-monitoring/overview', { params: { windowHours: 24, limit: 5000 }, skipCache: true });
      setLiveOverview(response.data || null);
      if (Array.isArray(response.data?.systems)) setBackendSystems(response.data.systems);
    } catch {
      // Preserve parent-provided live data if the dedicated API is unavailable.
    }
  }, []);

  useEffect(() => {
    refreshLiveOverview();
    const refreshBuffer = createEventBuffer(refreshLiveOverview, 400);
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    socket.on('connect', join);
    socket.on('api:event', refreshBuffer.add);
    socket.on('waf:block', refreshBuffer.add);
    if (socket.connected) join();
    const disconnect = connectSocket(socket);
    const timer = window.setInterval(() => { if (document.visibilityState !== 'hidden') refreshLiveOverview(); }, 15000);
    return () => {
      window.clearInterval(timer); refreshBuffer.clear();
      socket.off('connect', join); socket.off('api:event', refreshBuffer.add); socket.off('waf:block', refreshBuffer.add);
      disconnect();
    };
  }, [companyId, refreshLiveOverview]);

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

  const rows = Array.isArray(liveOverview?.events) ? liveOverview.events : (Array.isArray(alerts) ? alerts : []);
  const totalRows = liveOverview?.total ?? (total || recordsTotal || rows.length);
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const eventText = row => `${row?.ruleId || ''} ${row?.attackType || ''} ${row?.eventType || ''} ${row?.description || ''} ${row?.source || ''}`.toLowerCase();
  const countText = pattern => rows.filter(row => pattern.test(eventText(row))).length;
  const statusCode = row => Number(row?.statusCode ?? row?.responseStatus ?? row?.rawEvent?.status_code);
  const clientIp = row => row?.srcip || row?.sourceIp || row?.clientIp || row?.rawEvent?.source_ip;
  const latencySamples = rows.map(row => Number(row?.responseTimeMs ?? row?.latencyMs ?? row?.rawEvent?.response_time_ms)).filter(Number.isFinite);
  const averageLatency = latencySamples.length
    ? `${Math.round(latencySamples.reduce((sum, value) => sum + value, 0) / latencySamples.length)} ms`
    : 'Not reported';
  const securityHealth = rows.length
    ? `${Math.max(0, Math.round(100 - (((sevCounts.critical || 0) * 4 + (sevCounts.high || 0) * 2) / Math.max(rows.length, 1)) * 10))}/100`
    : 'Not reported';
  const connectorRows = rows.filter(row => /waf|api gateway|ingress|reverse proxy/i.test(eventText(row)));
  // 20 API Call Monitoring Specific SOC Categories & Metrics
  const kpis = [
    { label: '🛡️ 1. API Security Health Score', val: securityHealth, trend: 'Health Index', color: MON.green, data: timeline },
    { label: '🚨 2. WAF Blocked Requests', val: shortNum(rows.filter(r => /block/i.test(String(r.status || r.action || r.description || ''))).length), trend: 'WAF Block', color: MON.red, data: timeline },
    { label: '⚠️ 3. Failed Backend Errors (5xx)', val: shortNum(rows.filter(r => Number(r.statusCode) >= 500 || /5\d\d|backend error/i.test(String(r.description || ''))).length), trend: '5xx Error', color: MON.orange, data: timeline },
    { label: '💉 4. SQL Injection Attacks', val: shortNum(countText(/sql injection|\bsqli\b/)), trend: 'SQLi Attack', color: MON.red, data: timeline },
    { label: '🔑 5. Credential Stuffing & Bot Abuse', val: shortNum(countText(/credential stuffing|bot abuse|bot attack/)), trend: 'Bot Stuffing', color: MON.purple, data: timeline },
    { label: '☁️ 6. SSRF & Cloud Metadata Access', val: shortNum(countText(/ssrf|cloud metadata/)), trend: 'SSRF Attack', color: MON.red, data: timeline },
    { label: '⏳ 7. Rate Limit Exceeded (429)', val: shortNum(rows.filter(row => statusCode(row) === 429 || /rate limit/.test(eventText(row))).length), trend: 'Rate Limit', color: MON.yellow, data: timeline },
    { label: '🔐 8. Unauthorized Access (401/403)', val: shortNum(rows.filter(row => [401, 403].includes(statusCode(row)) || /unauthori[sz]ed|forbidden/.test(eventText(row))).length), trend: '401/403 Error', color: MON.orange, data: timeline },
    { label: '🌐 9. Unique Threat Client IPs', val: shortNum(new Set(rows.map(clientIp).filter(Boolean)).size), trend: 'Unique IPs', color: MON.cyan, data: timeline },
    { label: '⚡ 10. Average API Latency', val: averageLatency, trend: 'Latency', color: MON.cyan, data: timeline },
    { label: '🖥️ 11. Monitored API Gateways', val: shortNum(backendSystems.length), trend: 'API Gateways', color: MON.cyan, data: timeline },
    { label: '🛡️ 12. WAF Connector Telemetry', val: shortNum(connectorRows.length), trend: 'WAF Events', color: MON.green, data: timeline },
    { label: '🚨 13. Critical API Security Alerts', val: shortNum(sevCounts.critical || 0), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '📊 14. Total API Monitoring Events', val: shortNum(totalRows), trend: 'API Events', color: MON.blue, data: timeline },
    { label: '✅ 15. Successful HTTP 200 Responses', val: shortNum(rows.filter(row => statusCode(row) >= 200 && statusCode(row) < 300).length), trend: '2xx', color: MON.green, data: timeline },
    { label: '🔎 16. API Endpoint Enumeration', val: shortNum(countText(/api enumeration|endpoint enumeration|scan bot/)), trend: 'Scan Bot', color: MON.yellow, data: timeline },
    { label: '🔒 17. OAuth & JWT Token Revocations', val: shortNum(countText(/oauth|jwt|token revok|invalid token|expired token/)), trend: 'JWT/OAuth', color: MON.purple, data: timeline },
    { label: '🛡️ 18. Cloudflare WAF Rule Triggers', val: shortNum(countText(/cloudflare/)), trend: 'CF WAF', color: MON.cyan, data: timeline },
    { label: '🧱 19. F5 ASM / ModSecurity Triggers', val: shortNum(countText(/f5 asm|modsecurity/)), trend: 'F5/ModSec', color: MON.orange, data: timeline },
    { label: '⚠️ 20. High Severity WAF Signals', val: shortNum(sevCounts.high || 0), trend: 'High Risk', color: MON.orange, data: timeline },
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
          <CapabilityLogsPanel capabilityId={20}>
            <ApiLogMonitor alerts={rows} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={20} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <ApiOverviewDashboard alerts={rows} total={totalRows} summary={liveOverview?.summary || {}} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based API Gateways & WAF Engine Connectors</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} tenant endpoints loaded · {connectorRows.length} WAF/API gateway events observed</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Gateway Name</span><span>Hostname</span><span>Platform Type</span><span>WAF Engine</span><span>Requests</span><span>Blocked Threats</span><span>Last Ingress</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: /online|reporting|active/i.test(String(row.status)) ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.status}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend API gateway connectors returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time WAF API Traffic Event Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} API events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top API Threat Categories</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['SQL Injection / Query Hijack', `${countText(/sql injection|\bsqli\b/)} events`, MON.red],
                    ['Credential Stuffing / Token Abuse', `${countText(/credential stuffing|token abuse|bot abuse/)} events`, MON.orange],
                    ['SSRF & Cloud Metadata Access', `${countText(/ssrf|cloud metadata/)} events`, MON.purple],
                    ['API Enumeration & Rate Abuse', `${countText(/api enumeration|endpoint enumeration|rate abuse|rate limit/)} events`, MON.yellow],
                  ].map(([cat, cnt, col]) => (
                    <div key={cat} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{cnt}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔒 WAF & API Gateway Engine Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Cloudflare WAF Connector', countText(/cloudflare/) ? `${countText(/cloudflare/)} events` : 'No telemetry', countText(/cloudflare/) ? MON.green : MON.muted],
                    ['F5 ASM / ModSecurity Engine', countText(/f5 asm|modsecurity/) ? `${countText(/f5 asm|modsecurity/)} events` : 'No telemetry', countText(/f5 asm|modsecurity/) ? MON.green : MON.muted],
                    ['AWS WAF & K8s Ingress', countText(/aws waf|kubernetes ingress|k8s ingress/) ? `${countText(/aws waf|kubernetes ingress|k8s ingress/)} events` : 'No telemetry', countText(/aws waf|kubernetes ingress|k8s ingress/) ? MON.green : MON.muted],
                    ['FortiWeb & Imperva WAF', countText(/fortiweb|imperva/) ? `${countText(/fortiweb|imperva/)} events` : 'No telemetry', countText(/fortiweb|imperva/) ? MON.green : MON.muted],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`ApiCallMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function ApiCallMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '20';
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
        capabilityId: '20',
        capability: 'api-call-monitoring',
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
    socket.on('api:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('api:event', buf.add);
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
            🛡️ 20. API Call Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <ApiCallMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <ApiCallMonitoringPage />;
}

export function ApiCallSocTabPage({ tab }) {
  return <ApiCallMonitoringDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function ApiCallMonitoringSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=20" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>API SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=20')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="apicallmonitoring" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <ApiCallMonitoringDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { ApiCallMonitoringDashboardPanel as ApiCallMonitoringDashboard };
