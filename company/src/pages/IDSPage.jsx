import { authStorage } from '../api/authStorage';
import React, { useEffect, useState, useCallback, useRef } from 'react';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { API_BASE_URL, SOCKET_URL, socketOptions, connectSocket, io, createEventBuffer } from '../api/config';
import { useAuth } from '../context/AuthContext';
import IdsIpsWafMap from '../components/IdsIpsWafMap';
import CountryBlockTab from '../components/CountryBlockTab';
import WhitelistBulkImport from '../components/WhitelistBulkImport';
import './IDSPage.css';

// ── Styles ────────────────────────────────────────────────────────────────────
const C = {
  page: { padding: '20px', maxWidth: '1400px', margin: '0 auto', color: '#e2e8f0', fontFamily: 'system-ui,sans-serif' },
  card: { background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: '12px', padding: '18px', marginBottom: '16px' },
  tab: (a) => ({ padding: '9px 16px', fontSize: '12px', cursor: 'pointer', border: 'none', background: 'none', fontWeight: a ? 700 : 400, color: a ? '#60a5fa' : '#64748b', borderBottom: a ? '2px solid #3b82f6' : '2px solid transparent', marginBottom: -1 }),
  btn: (v = 'primary') => ({ padding: '7px 14px', borderRadius: '6px', fontSize: '12px', cursor: 'pointer', border: 'none', background: v === 'danger' ? '#7f1d1d' : v === 'success' ? '#14532d' : v === 'warn' ? '#78350f' : '#1e3a8a', color: v === 'danger' ? '#fca5a5' : v === 'success' ? '#86efac' : v === 'warn' ? '#fde68a' : '#93c5fd', fontWeight: 600 }),
  inp: { padding: '7px 10px', borderRadius: '6px', fontSize: '12px', background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0', outline: 'none', width: '100%', boxSizing: 'border-box' },
  badge: (c) => ({ fontSize: 10, padding: '2px 8px', borderRadius: 10, fontWeight: 700, color: c, background: `${c}18`, border: `1px solid ${c}33` }),
  th: { padding: '8px 12px', color: '#3b82f6', fontWeight: 700, fontSize: '10px', textAlign: 'left', textTransform: 'uppercase', background: '#060e1a' },
  td: { padding: '8px 12px', fontSize: '12px', borderBottom: '1px solid #0a1628' },
};

const LEVEL_COLOR = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399', BLOCK: '#f87171', UNBLOCK: '#34d399', ERROR: '#f59e0b', WARN: '#fbbf24', INFO: '#94a3b8' };
const TABS = [
  { id: 'overview', label: '📡 IDS Overview' },
  { id: 'blocklist', label: '🛡️ Blocklist' },
  { id: 'country', label: '🌐 Block Country' },
  { id: 'threats', label: '⚠️ Threats' },
  { id: 'logs', label: '📋 Logs' },
  { id: 'coverage', label: '🧭 Coverage' },
  { id: 'whitelist', label: '✅ Whitelist' },
  { id: 'waf', label: '🔥 WAF' },
  { id: 'policy', label: '🛡️ Policy IDS&IPS' },
  { id: 'audit', label: '🧾 Audit Log' },
  { id: 'isolationFlow', label: '🔓 Isolation Flow' },
];

const IDS_TAB_IDS = new Set(['overview', 'threats', 'logs', 'coverage']);
const IPS_TAB_IDS = new Set(['blocklist', 'country', 'whitelist', 'waf', 'policy', 'audit', 'isolationFlow']);
const IDS_SENSOR_NOISE_RULES = new Set([
  'SURICATA_2200003',
  'SURICATA_2210045',
  'SURICATA_2210046',
  'ZEEK_truncated_tcp_payload',
]);

// ── helpers ───────────────────────────────────────────────────────────────────
// Use backend proxy to IPS server instead of direct calls
const ipsFetch = async (path) => {
  const endpoint = path.replace(/^\//, ''); // Remove leading slash
  const r = await api.get(`/ips-proxy/${endpoint}`);
  return r.data;
};

const isRoutineNetworkTelemetry = (alert) => {
  const rule = String(alert?.ruleId || alert?.type || '');
  const description = String(alert?.description || '');
  return /^(IDS_TELEMETRY|NETWORK_TELEMETRY|NET_CONNECTION_SUMMARY|NET_DNS_SUMMARY|NET_EXPOSURE_SUMMARY)$/i.test(rule)
    || /^network_telemetry$/i.test(String(alert?.event_category || ''))
    || /^(Live network summary|DNS monitor active|Network exposure scan|WAF (startup|heartbeat))/i.test(description);
};

const isSecurityActivity = (log) => {
  const level = String(log?.level || log?.severity || '').toLowerCase();
  const text = [log?.message, log?.description, log?.type, log?.action, log?.event]
    .filter(Boolean)
    .join(' ');
  return /^(warn|warning|error|critical|high|medium|danger|block)$/.test(level)
    || /(block(?:ed)?|attack|threat|intrusion|malicious|exploit|scan|brute force|injection|xss|\bc2\b|exfiltrat|den(?:y|ied)|drop(?:ped)?|incident|policy match)/i.test(text);
};

const isIdsIpsThreatEvent = (item = {}) => {
  const category = String(item.eventCategory || item.category || item.logType || '').toLowerCase();
  const source = String(item.source || item.liveSource || '').toLowerCase();
  const type = String(item.attackType || item.type || item.ruleId || item.event || item.action || item.detectionSource || '').toLowerCase();
  const text = [
    item.liveSource, item.source, item.eventCategory, item.category, item.logType,
    item.module, item.source_type, item.event_category, item.ruleId, item.type,
    item.attackType, item.detectionSource, item.description, item.message,
  ].filter(Boolean).join(' ');
  const hasExplicitIdsIpsSource = [item.module, item.source_type].some(value => /^(ids|ips)$/i.test(String(value || '')))
    || ['suricata', 'zeek', 'ids', 'ips'].includes(source)
    || /^(ids_alert|ips_block|blacklist_event|intrusion_detection|intrusion_prevention)$/i.test(String(item.event_category || ''));

  if (IDS_SENSOR_NOISE_RULES.has(String(item.ruleId || ''))) return false;
  if (source === 'zeek' && String(item.ruleId || '') === 'ZEEK_weird'
      && /^truncated_tcp_payload$/i.test(String(item.signatureName || item.signature || ''))) return false;

  if (['edr', 'file', 'fim', 'registry', 'usb', 'process', 'isolation', 'system', 'malware', 'auth', 'endpoint', 'other'].includes(category)) return false;
  if (/^(file_|fim_|edr_|usb_|process_|registry_|waf|fw_|firewall|auth|login|system|malware|yara)/i.test(type)) return false;
  if (hasExplicitIdsIpsSource) return !isRoutineNetworkTelemetry(item);
  if (/(WAF|firewall|file created|file deleted|file modified|fim|registry|usb|process|endpoint|auth|login|system|yara|quarantine|isolation)/i.test(text)) return false;
  if (isRoutineNetworkTelemetry(item)) return false;

  return /(IDS|IPS|suricata|zeek|intrusion detection|intrusion prevention|ids_alert|ips_block|blacklist_event|NET_SUSPICIOUS_CONNECTION)/i.test(text)
    || ['suricata', 'zeek', 'ids', 'ips'].includes(source);
};

const idsIpsSourceLabel = (item = {}) => {
  const haystack = [
    item.module, item.source_type, item.event_category, item.source, item.liveSource,
    item.type, item.ruleId, item.attackType, item.signatureName, item.description,
  ].filter(Boolean).join(' ').toLowerCase();
  const agent = String(item.agentName || item.sensor || item.host || '').trim();
  const cleanAgent = agent && !/^all agents$/i.test(agent) ? agent : '';

  if (/threat intelligence|ti auto-block|ti verified|abuseipdb|alienvault|otx|virustotal/.test(haystack)) return 'Threat Intel Auto-Block';
  if (/suricata/.test(haystack)) return 'Suricata-IDS';
  if (/zeek/.test(haystack)) return 'Zeek-NSM';
  if (/blacklist_event|ips_block|blocked|blocklist/.test(haystack) || item.blocked === true) return 'IPS Blocklist';
  if (/\bips\b|intrusion prevention/.test(haystack)) return 'IPS Engine';
  if (/\bids\b|intrusion detection/.test(haystack)) return 'IDS Sensor';
  if (cleanAgent && !/^[\w.-]+$/i.test(cleanAgent)) return cleanAgent;
  return 'IDS/IPS';
};

/**
 * SOC-Grade severity normalization
 * Maps agent/sensor severity strings → 4-tier SOC severity
 *
 * CRITICAL → Active exploitation, confirmed breach, ransomware, data exfiltration
 * HIGH     → Confirmed attack pattern, CVE exploit, brute force, known malicious IP
 * MEDIUM   → Suspicious activity, policy violation, single block, warning
 * LOW      → Informational, routine network events, benign anomalies
 */
const normalizeLiveSeverity = (value) => {
  const sev = String(value || 'info').toLowerCase().trim();

  // —— CRITICAL: Immediate response needed ———————————————————————
  if (['critical', 'crit', 'fatal', 'emergency', 'emerg', 'alert', '0', '1', '2'].includes(sev))
    return 'critical';

  // —— HIGH: Confirmed threat, urgent investigation needed —————————————
  if (['high', '3'].includes(sev))
    return 'high';

  // —— MEDIUM: Suspicious, investigate within hours ————————————————
  // Note: 'error', 'block', 'blocked' are medium — not every block is a high-severity event
  if (['medium', 'warning', 'warn', 'error', 'err', 'block', 'blocked', '4', '5'].includes(sev))
    return 'medium';

  // —— LOW: Informational, monitor only ———————————————————————
  if (['low', 'info', 'informational', 'notice', 'debug', 'verbose', 'trace', '6', '7'].includes(sev))
    return 'low';

  return 'low'; // default: treat unknown as low, not high
};

const liveEventTime = (item = {}) => item.ts || item.timestamp || item.createdAt || item.receivedAt || item.logTime || item.blockedAt || null;

const liveEventMessage = (item = {}) => (
  item.message || item.description || item.detail || item.raw_log || item.raw || item.type || item.action || 'Security event'
);

const normalizeThreatIndicator = (value = '') => String(value || '').trim();
const isUnknownThreatIndicator = (value = '') => {
  const v = normalizeThreatIndicator(value).toLowerCase();
  return !v || v === 'unknown' || v === '—' || v === '-' || v === 'null' || v === 'undefined';
};
const isLocalThreatIndicator = (value = '') => {
  const v = normalizeThreatIndicator(value);
  return isUnknownThreatIndicator(v) || isPrivateIp(v) || /^::ffff:127\./i.test(v);
};

const labelSeverity = (value) => {
  const severity = String(value || 'low').toLowerCase();
  return severity.charAt(0).toUpperCase() + severity.slice(1);
};

function IPTag({ v }) {
  return <code style={{ background: '#0f2040', color: '#60a5fa', padding: '1px 6px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace' }}>{v || '—'}</code>;
}
function Badge({ text, color }) {
  return <span style={C.badge(color || '#64748b')}>{text}</span>;
}
function Empty({ icon = '📭', msg = 'No data' }) {
  return <div style={{ textAlign: 'center', padding: '48px 0', color: '#475569' }}><div style={{ fontSize: 40 }}>{icon}</div><div style={{ marginTop: 8, fontSize: 13 }}>{msg}</div></div>;
}

function getCompanyIdFromStorage() {
  try {
    const user = JSON.parse(authStorage.getItem('co_user') || '{}');
    const company = JSON.parse(authStorage.getItem('co_company') || '{}');
    return user.companyId || user.company || company._id || company.id || '';
  } catch { return ''; }
}

function getStoredAuthorizationContext() {
  try {
    const user = JSON.parse(authStorage.getItem('co_user') || '{}');
    const company = JSON.parse(authStorage.getItem('co_company') || '{}');
    return {
      company: company.name || company.companyName || user.companyName || '',
      department: user.departmentId?.name || user.department?.name || user.departmentName || '',
    };
  } catch {
    return { company: '', department: '' };
  }
}

function isPrivateIp(ip = '') {
  return /^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^127\.|^::1$|^localhost$/i.test(String(ip));
}

// ══════════════════════════════════════════════════════════════════════════════
//  OVERVIEW — existing IDS stats
// ══════════════════════════════════════════════════════════════════════════════
const Sparkline = ({ points = '0,22 18,15 36,19 54,7 72,13 90,5', color = '#3b82f6' }) => (
  <svg className="ids-sparkline" viewBox="0 0 90 26" preserveAspectRatio="none" aria-hidden="true">
    <polyline points={points} fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
  </svg>
);

const sourceTrendPoints = (hourly = []) => {
  if (!Array.isArray(hourly) || hourly.length < 2) return '0,22 90,22';
  const max = Math.max(1, ...hourly.map(Number));
  return hourly.map((value, index) => {
    const x = index / (hourly.length - 1) * 90;
    const y = 23 - (Number(value) / max * 19);
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
};

function OverviewTab({ onTabChange, onOpenReport, onSeverityFilter, summary, ipsOnline }) {
  const OVERVIEW_LIST_LIMIT = 10;
  const [selectedIp, setSelectedIp] = useState(null);
  const [stats, setStats] = useState(null);
  const [recentLogs, setRecentLogs] = useState([]);
  const [blockStats, setBlockStats] = useState(null);
  const [policyStats, setPolicyStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const refreshTimerRef = useRef(null);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      // The stats response already contains recent IDS/IPS alerts and block
      // counts. Reusing it avoids three duplicate, collection-wide reads every
      // time the overview opens or receives a socket event.
      const [statsRes, policyRes] = await Promise.allSettled([
        api.get('/ids/stats'),
        api.get('/ids/policy-violations?hours=24&limit=1'),
      ]);
      if (statsRes.status === 'fulfilled') {
        const nextStats = statsRes.value.data;
        setStats(nextStats);
        setRecentLogs((nextStats?.recentAlerts || []).filter(isIdsIpsThreatEvent).slice(0, OVERVIEW_LIST_LIMIT));
        setBlockStats({ count: nextStats?.blockedIps ?? nextStats?.blocked ?? 0 });
      }
      if (policyRes.status === 'fulfilled') setPolicyStats(policyRes.value.data);
    }
    catch { if (!silent) setStats(null); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const companyId = getCompanyIdFromStorage();
    const sock = io(SOCKET_URL, socketOptions);
    if (companyId) sock.emit('join:company', companyId);

    const liveAlertBuffer = createEventBuffer((newAlerts) => {
      const relevant = newAlerts.filter(a => isIdsIpsThreatEvent(a) && (a?.srcip || a?.destip));
      if (relevant.length > 0) {
        setRecentLogs(prev => {
          const existingIds = new Set(prev.map(item => String(item._id || item.eventId || '')));
          return [...relevant.filter(item => !existingIds.has(String(item._id || item.eventId || ''))), ...prev].slice(0, 10);
        });
      }
      // The socket already carries the new row. Aggregate charts refresh on
      // the regular poll; querying all IDS stats for every incoming alert can
      // overload MongoDB during an incident burst.
    }, 1200);
    const refreshAiResult = () => load(true);

    sock.on('alert:new', liveAlertBuffer.add);
    sock.on('alert:ai-updated', refreshAiResult);
    const disconnectSocket = connectSocket(sock);
    const poll = setInterval(() => load(true), 60000);
    
    return () => {
      sock.off('alert:new', liveAlertBuffer.add);
      sock.off('alert:ai-updated', refreshAiResult);
      liveAlertBuffer.clear();
      disconnectSocket();
      clearInterval(poll);
    };
  }, [load]);

  const total = stats?.total ?? summary?.total ?? 0;
  const critical = stats?.severity?.critical ?? summary?.critical ?? 0;
  const topIps = stats?.topSrcIps || [];
  const recent = recentLogs
    .slice(0, OVERVIEW_LIST_LIMIT)
    .map(alert => [
      (alert.severity || 'low').toUpperCase(),
      alert.description || alert.type || alert.eventCategory || 'Security alert',
      [alert.srcip, alert.destip && `→ ${alert.destip}${alert.destPort ? `:${alert.destPort}` : ''}`].filter(Boolean).join(' ') || alert.agentName || 'System event',
      alert.createdAt ? new Date(alert.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—',
    ]);
  const sev = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#60a5fa' };
  const severity = stats?.severity || {};
  const high = severity.high || 0;
  const medium = severity.medium || 0;
  const low = severity.low || 0;
  const severityTotal = critical + high + medium + low;
  const sevTotal = Math.max(1, severityTotal);
  const criticalPct = critical / sevTotal * 100;
  const highPct = high / sevTotal * 100;
  const mediumPct = medium / sevTotal * 100;
  const donut = `conic-gradient(#ef4444 0 ${criticalPct}%,#f97316 ${criticalPct}% ${criticalPct + highPct}%,#eab308 ${criticalPct + highPct}% ${criticalPct + highPct + mediumPct}%,#3478dc ${criticalPct + highPct + mediumPct}% 100%)`;
  const categoryRows = [
    ['Network Intrusion', stats?.categories?.network?.count || 0, '#3b82f6'],
    ['Policy Violation', policyStats?.total || 0, '#22c55e'],
    [
      'Malicious IP Activity',
      stats?.categories?.malware?.count || 0,
      '#f59e0b',
      (stats?.maliciousIps || []).slice(0, 2).map(item => item.ip).join(', '),
    ],
  ];
  const maxCategory = Math.max(1, ...categoryRows.map(row => row[1]));
  const categoryTotal = Math.max(1, categoryRows.reduce((sum, row) => sum + Number(row[1] || 0), 0));
  const timeline = stats?.sparkline || [];
  const maxTimeline = Math.max(1, ...timeline.map(point => point.count));
  const trendPoints = timeline.length
    ? timeline.map((point, i) => `${i / Math.max(1, timeline.length - 1) * 500},${168 - point.count / maxTimeline * 145}`).join(' ')
    : '0,168 500,168';
  const trendArea = `M${trendPoints.replaceAll(' ', 'L')}L500,180L0,180Z`;
  const ipsBlocks = summary?.ipsBlocked ?? blockStats?.count ?? stats?.blocked ?? 0;
  const selectedSourceIndex = Math.max(0, topIps.findIndex(item => item._id === selectedIp));

  const selectSource = (index) => {
    const source = topIps[index];
    if (!source) return;
    setSelectedIp(source._id);
  };

  const openLiveMap = () => {
    const params = new URLSearchParams({ source: 'ids', view: 'ips-blocked' });
    window.open(`${window.location.origin}/live-network-map?${params}`, '_blank', 'noopener,noreferrer');
  };

  return (
    <div className={`ids-overview ${loading ? 'is-loading' : ''}`}>
      <div className="ids-main-panels">
        <section className="ids-panel ids-trend-panel">
          <div className="ids-panel-head"><strong>Alerts Trend (24H)</strong><button>Total Alerts⌄</button></div>
          <div className="ids-chart">
            <div className="ids-ylabels"><span>8K</span><span>6K</span><span>4K</span><span>2K</span><span>0</span></div>
            <svg viewBox="0 0 500 180" preserveAspectRatio="none" aria-label="Alerts trend chart">
              <defs>
                <linearGradient id="idsArea" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0" stopColor="#3b82f6" stopOpacity=".4" />
                  <stop offset="1" stopColor="#3b82f6" stopOpacity=".02" />
                </linearGradient>
              </defs>
              <path className="ids-grid-line" d="M0 20H500M0 60H500M0 100H500M0 140H500M0 178H500" />
              <path d={trendArea} fill="url(#idsArea)" />
              <polyline points={trendPoints} fill="none" stroke="#4f8df7" strokeWidth="2.5" />
            </svg>
            <div className="ids-xlabels"><span>18:00</span><span>00:00</span><span>06:00</span><span>12:00</span><span>18:00</span></div>
          </div>
        </section>

        <section className="ids-panel ids-severity-panel">
          <div className="ids-panel-head"><strong>Alerts by Severity</strong><small style={{ color: '#475569', fontWeight: 400 }}>Click to filter</small></div>
          <div className="ids-severity-body">
            <div className="ids-donut" style={{ '--total': `"${(severityTotal || total).toLocaleString()}"`, background: donut }} />
            <div className="ids-legend">
              {[['Critical', critical, '#ef4444'], ['High', high, '#f97316'], ['Medium', medium, '#eab308'], ['Low', low, '#3b82f6']].map(([name, value, color]) => (
                <div
                  key={name}
                  onClick={() => onSeverityFilter && onSeverityFilter(name.toUpperCase())}
                  title={`View ${name} alerts in Logs tab`}
                  style={{
                    cursor: onSeverityFilter ? 'pointer' : 'default',
                    borderRadius: 6,
                    padding: '4px 6px',
                    margin: '-4px -6px',
                    transition: 'background 0.15s',
                  }}
                  onMouseEnter={e => { if (onSeverityFilter) e.currentTarget.style.background = `${color}18`; }}
                  onMouseLeave={e => { e.currentTarget.style.background = 'transparent'; }}
                >
                  <i style={{ background: color }} />
                  <span style={{ color }}>{name}</span>
                  <b style={{ color }}>{Number(value).toLocaleString()}</b>
                  {onSeverityFilter && <span style={{ fontSize: 9, color: '#475569', marginLeft: 4 }}>→</span>}
                </div>
              ))}
            </div>
          </div>
        </section>

        <section className="ids-panel ids-distribution-panel">
          <div className="ids-panel-head"><strong>Alert Distribution</strong></div>
          <div className="ids-bars">
            {categoryRows.map(([name, count, color, detail]) => {
              const percent = count / categoryTotal * 100;
              return (
                <div className="ids-bar-row" key={name}>
                  <div>
                    <span>{name}{detail && <small className="ids-bar-detail">{detail}</small>}</span>
                    <b>{count.toLocaleString()} <small>({percent.toFixed(1)}%)</small></b>
                  </div>
                  <em><i style={{ width: `${count / maxCategory * 100}%`, background: color }} /></em>
                </div>
              )
            })}
          </div>
        </section>
      </div>

      <div className="ids-bottom-panels">
        <section className="ids-panel ids-sources">
          <div className="ids-panel-head">
            <strong>Top Source IPs (24H)</strong>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {topIps.length > 1 && (
                <input
                  type="range"
                  min="0"
                  max={topIps.length - 1}
                  value={selectedSourceIndex}
                  onChange={event => selectSource(Number(event.target.value))}
                  aria-label="Select source IP to focus on the attack map"
                  title={`Map focus: ${topIps[selectedSourceIndex]?._id || 'source IP'}`}
                  style={{ width: 92, accentColor: '#3b82f6', cursor: 'pointer' }}
                />
              )}
              <button type="button" onClick={() => onOpenReport('sources')}>View Report <span>→</span></button>
            </div>
          </div>
          <div className="ids-source-head"><span>Rank</span><span>Source IP</span><span>Alerts</span><span>Trend</span></div>
          {topIps.slice(0, OVERVIEW_LIST_LIMIT).map((ip, i) => (
            <div
              className="ids-source-row"
              key={`${ip._id}-${i}`}
              onClick={() => selectSource(i)}
              style={{
                cursor: 'pointer',
                background: selectedIp === ip._id ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                borderLeft: selectedIp === ip._id ? '3px solid #3b82f6' : '3px solid transparent',
                paddingLeft: selectedIp === ip._id ? '13px' : '16px',
                transition: 'all 0.15s ease',
              }}
            >
              <span>{i + 1}</span><code>{ip._id}</code><b>{ip.count}</b>
              <Sparkline
                color={{ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#60a5fa' }[String(ip.severity || 'low').toLowerCase()] || '#60a5fa'}
                points={sourceTrendPoints(ip.hourly)}
              />
            </div>
          ))}
          {!topIps.length && <div className="ids-empty-row">No source IP activity in the last 24 hours</div>}
        </section>

        <section className="ids-panel ids-map">
          <div className="ids-panel-head">
            <strong>AJNAT IDS / IPS / WAF Live Monitor Map <span className="ids-live">(Agent Linked)</span></strong>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button type="button" onClick={openLiveMap}>Open Live Monitor ↗</button>
              <i className="ids-online-dot" />
            </div>
          </div>
          <div className="ids-map-stage" style={{ padding: 0, overflow: 'hidden', borderRadius: '0 0 12px 12px', flex: 1, minHeight: 380, display: 'flex', flexDirection: 'column' }}>
            <IdsIpsWafMap height="100%" refreshInterval={30000} selectedIp={selectedIp} />
          </div>
        </section>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  MONITORING INTELLIGENCE SECTION — 13 comprehensive monitoring categories
// ══════════════════════════════════════════════════════════════════════════════
function MonitoringIntelligenceSection({ stats, blockStats }) {
  const [expandedSections, setExpandedSections] = useState({});
  const [alertsPage, setAlertsPage] = useState(0);
  const ALERTS_PER_PAGE = 8;

  const toggleSection = (id) => setExpandedSections(prev => ({ ...prev, [id]: !prev[id] }));

  // Derive counts from real stats
  const recentAlerts = stats?.recentAlerts || [];
  const categories = stats?.categories || {};
  const byType = stats?.byType || [];
  const topIps = stats?.topSrcIps || [];
  const blockedIps = blockStats?.count || stats?.blocked || 0;
  const hasLive = recentAlerts.length > 0;

  // Helper: count alerts matching a keyword list
  const countByKeyword = (keywords) => {
    const k = keywords.map(w => w.toLowerCase());
    return recentAlerts.filter(a => {
      const text = [a.description, a.type, a.ruleId, a.eventCategory].filter(Boolean).join(' ').toLowerCase();
      return k.some(kw => text.includes(kw));
    }).length;
  };

  // Count from byType stats
  const countType = (keywords) => {
    const k = keywords.map(w => w.toLowerCase());
    return byType.filter(t => k.some(kw => String(t.type || t._id || '').toLowerCase().includes(kw))).reduce((s, t) => s + (t.count || 0), 0);
  };

  const statusDot = (count, color = '#3b82f6') => {
    if (count > 0) return { color: '#ef4444', label: `${count} Detected` };
    return { color: '#22c55e', label: 'Monitoring' };
  };

  // Status badge component
  const SBadge = ({ count, blocked }) => {
    const c = count > 0 ? (blocked ? '#ef4444' : '#f59e0b') : '#22c55e';
    const lbl = count > 0 ? (blocked ? `${count} Blocked` : `${count} Detected`) : 'Monitoring';
    return (
      <span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 10, color: c, background: `${c}18`, border: `1px solid ${c}44`, whiteSpace: 'nowrap' }}>
        <span style={{ marginRight: 4 }}>●</span>{lbl}
      </span>
    );
  };

  // Section header
  const SectionHead = ({ id, icon, title, color, count }) => {
    const isOpen = expandedSections[id] !== false; // default open
    return (
      <div
        className="ids-mon-section-head"
        onClick={() => toggleSection(id)}
        style={{ '--accent': color }}
      >
        <span className="ids-mon-section-icon" style={{ color }}>{icon}</span>
        <strong>{title}</strong>
        {count > 0 && <span className="ids-mon-badge-count" style={{ color, background: `${color}18`, border: `1px solid ${color}33` }}>{count}</span>}
        <span className="ids-mon-section-toggle">{isOpen ? '▲' : '▼'}</span>
      </div>
    );
  };

  // Grid of monitoring items
  const MonGrid = ({ items }) => (
    <div className="ids-mon-grid">
      {items.map(([label, count, blocked]) => {
        const c = count > 0 ? (blocked ? '#ef4444' : '#f59e0b') : '#22c55e';
        return (
          <div key={label} className="ids-mon-item" style={{ '--item-color': c }}>
            <span className="ids-mon-item-dot" style={{ color: c }}>●</span>
            <span className="ids-mon-item-label">{label}</span>
            <SBadge count={count} blocked={blocked} />
          </div>
        );
      })}
    </div>
  );

  // ── SECTION DATA ──────────────────────────────────────────────────────────

  // 1. Traffic Monitoring
  const trafficItems = [
    ['Incoming Traffic', categories.network?.count || 0, false],
    ['Outgoing Traffic', 0, false],
    ['Internal Traffic', 0, false],
    ['Network Packets', (stats?.total || 0), false],
    ['TCP Traffic', countType(['tcp']), false],
    ['UDP Traffic', countType(['udp']), false],
    ['ICMP Traffic', countType(['icmp', 'ping']), false],
    ['IPv4 / IPv6 Traffic', countType(['ipv4', 'ipv6', 'ip']), false],
    ['Session Monitoring', 0, false],
    ['Connection Monitoring', topIps.length, false],
  ];

  // 2. Network Recon
  const reconItems = [
    ['Port Scan', countByKeyword(['port scan', 'portscan']), false],
    ['SYN Scan', countByKeyword(['syn scan', 'syn_scan']), false],
    ['FIN Scan', countByKeyword(['fin scan', 'fin_scan']), false],
    ['NULL Scan', countByKeyword(['null scan', 'null_scan']), false],
    ['XMAS Scan', countByKeyword(['xmas', 'christmas scan']), false],
    ['ACK Scan', countByKeyword(['ack scan', 'ack_scan']), false],
    ['UDP Scan', countByKeyword(['udp scan']), false],
    ['Ping Sweep', countByKeyword(['ping sweep', 'ping_sweep']), false],
    ['Host Discovery', countByKeyword(['host discovery', 'nmap', 'discovery']), false],
    ['Service Enumeration', countByKeyword(['service enum', 'enumeration']), false],
    ['Banner Grabbing', countByKeyword(['banner grab', 'banner']), false],
  ];

  // 3. Web App Attack Detection
  const webItems = [
    ['SQL Injection', countByKeyword(['sql injection', 'sqli', 'sql_injection']), true],
    ['Blind SQL Injection', countByKeyword(['blind sql', 'blind sqli']), true],
    ['XSS', countByKeyword(['xss', 'cross-site scripting']), true],
    ['Stored XSS', countByKeyword(['stored xss']), true],
    ['Reflected XSS', countByKeyword(['reflected xss']), true],
    ['CSRF', countByKeyword(['csrf', 'cross-site request forgery']), true],
    ['Command Injection', countByKeyword(['command injection', 'cmd injection']), true],
    ['Remote Code Execution (RCE)', countByKeyword(['rce', 'remote code exec']), true],
    ['File Upload Attack', countByKeyword(['file upload', 'upload attack']), true],
    ['Path Traversal', countByKeyword(['path traversal', '../']), true],
    ['Directory Traversal', countByKeyword(['directory traversal', 'dir traversal']), true],
    ['Local File Inclusion (LFI)', countByKeyword(['lfi', 'local file inclusion']), true],
    ['Remote File Inclusion (RFI)', countByKeyword(['rfi', 'remote file inclusion']), true],
    ['XXE Attack', countByKeyword(['xxe', 'xml external entity']), true],
    ['SSRF', countByKeyword(['ssrf', 'server-side request forgery']), true],
    ['SSTI', countByKeyword(['ssti', 'server-side template injection']), true],
  ];

  // 4. Auth Attack Detection
  const authItems = [
    ['Brute Force', countByKeyword(['brute force', 'bruteforce']), true],
    ['Password Spraying', countByKeyword(['password spray', 'spraying']), true],
    ['Credential Stuffing', countByKeyword(['credential stuffing', 'credentials']), true],
    ['Login Flood', countByKeyword(['login flood', 'login flood']), true],
    ['Multiple Failed Login Attempts', countByKeyword(['failed login', 'failed attempt']), true],
    ['Privilege Escalation Attempts', countByKeyword(['privilege escalation', 'privesc']), true],
  ];

  // 5. Malware Detection
  const malwareItems = [
    ['Virus', countByKeyword(['virus']), true],
    ['Worm', countByKeyword(['worm']), true],
    ['Trojan', countByKeyword(['trojan']), true],
    ['Spyware', countByKeyword(['spyware']), true],
    ['Rootkit', countByKeyword(['rootkit']), true],
    ['Ransomware', countByKeyword(['ransomware']), true],
    ['Botnet Traffic', countByKeyword(['botnet']), true],
    ['Crypto Miner', countByKeyword(['crypto miner', 'mining', 'cryptomining']), true],
    ['Backdoor', countByKeyword(['backdoor']), true],
    ['Malicious Payload', countByKeyword(['malicious payload', 'payload']), true],
  ];

  // 6. C2 Detection
  const c2Items = [
    ['HTTP Beaconing', countByKeyword(['http beacon', 'beaconing']), true],
    ['HTTPS Beaconing', countByKeyword(['https beacon']), true],
    ['DNS Tunneling', countByKeyword(['dns tunnel', 'dns_tunnel']), true],
    ['Reverse Shell', countByKeyword(['reverse shell', 'revshell']), true],
    ['C2 Communication', countByKeyword(['c2', 'command and control', 'c&c']), true],
    ['IRC C2', countByKeyword(['irc', 'irc c2']), true],
    ['TOR Traffic', countByKeyword(['tor', 'onion']), true],
  ];

  // 7. DoS Detection
  const dosItems = [
    ['DoS Attack', countByKeyword(['dos attack', 'denial of service']), true],
    ['DDoS Attack', countByKeyword(['ddos', 'distributed denial']), true],
    ['SYN Flood', countByKeyword(['syn flood']), true],
    ['UDP Flood', countByKeyword(['udp flood']), true],
    ['ICMP Flood', countByKeyword(['icmp flood', 'ping flood']), true],
    ['HTTP Flood', countByKeyword(['http flood']), true],
    ['HTTPS Flood', countByKeyword(['https flood']), true],
    ['Slowloris Attack', countByKeyword(['slowloris']), true],
  ];

  // 8. Network Spoofing
  const spoofItems = [
    ['ARP Spoofing', countByKeyword(['arp spoof']), true],
    ['ARP Poisoning', countByKeyword(['arp poison']), true],
    ['DNS Spoofing', countByKeyword(['dns spoof']), true],
    ['DNS Cache Poisoning', countByKeyword(['dns cache poison', 'dns poisoning']), true],
    ['IP Spoofing', countByKeyword(['ip spoof']), true],
    ['MAC Spoofing', countByKeyword(['mac spoof']), true],
  ];

  // 9. Protocol Monitoring
  const protoItems = [
    ['HTTP', countType(['http']), false],
    ['HTTPS', countType(['https', 'tls', 'ssl']), false],
    ['DNS', countType(['dns']), false],
    ['FTP', countType(['ftp']), false],
    ['SSH', countType(['ssh']), false],
    ['SMTP', countType(['smtp', 'email']), false],
    ['POP3', countType(['pop3']), false],
    ['IMAP', countType(['imap']), false],
    ['SMB', countType(['smb']), false],
    ['LDAP', countType(['ldap']), false],
    ['SNMP', countType(['snmp']), false],
    ['RDP', countType(['rdp']), false],
    ['Telnet', countType(['telnet']), false],
  ];

  // 10. Threat Intelligence
  const threatIntelItems = [
    ['Malicious IP Detection', (stats?.maliciousIps || []).length, true],
    ['Malicious Domain Detection', countByKeyword(['malicious domain', 'malicious url']), true],
    ['Malicious URL Detection', countByKeyword(['malicious url']), true],
    ['IOC Matching', countByKeyword(['ioc', 'indicator of compromise']), true],
    ['CVE Exploit Detection', countByKeyword(['cve', 'exploit']), true],
    ['Known Exploit Detection', countByKeyword(['known exploit']), true],
    ['Signature Match', countByKeyword(['signature', 'signature match']), true],
    ['Zero-Day Behavior Detection', countByKeyword(['zero-day', '0day', 'zero day']), true],
  ];

  // 11. Anomaly Detection
  const anomalyItems = [
    ['Unusual Traffic Volume', countByKeyword(['unusual traffic', 'traffic spike']), false],
    ['Unusual Packet Size', countByKeyword(['packet size', 'large packet']), false],
    ['Suspicious Connection Rate', countByKeyword(['connection rate', 'conn flood']), false],
    ['Unknown Protocol Usage', countByKeyword(['unknown protocol']), false],
    ['Abnormal Network Behavior', countByKeyword(['abnormal', 'anomaly']), false],
    ['Suspicious Payload', countByKeyword(['suspicious payload']), false],
    ['Traffic Spike Detection', countByKeyword(['traffic spike', 'bandwidth spike']), false],
  ];

  // 12. IPS Prevention Actions
  const ipsActions = [
    ['Block Source IP', blockedIps, true],
    ['Block Destination IP', 0, true],
    ['Drop Malicious Packet', blockedIps, true],
    ['Reset TCP Session', 0, true],
    ['Block Port', 0, true],
    ['Block Protocol', 0, true],
    ['Block URL', 0, true],
    ['Block Domain', 0, true],
    ['Quarantine Connection', 0, true],
    ['Temporary IP Block', blockedIps, true],
    ['Permanent IP Block', 0, true],
    ['Auto Blacklist', blockedIps, true],
  ];

  // 13. Full Alerts Table data
  const alertRows = recentAlerts.slice(alertsPage * ALERTS_PER_PAGE, (alertsPage + 1) * ALERTS_PER_PAGE);
  const totalAlertPages = Math.ceil(recentAlerts.length / ALERTS_PER_PAGE);

  const SECTIONS = [
    { id: 's1', icon: '📡', title: '1. Traffic Monitoring', color: '#3b82f6', items: trafficItems },
    { id: 's2', icon: '🔍', title: '2. Network Reconnaissance Detection', color: '#f59e0b', items: reconItems },
    { id: 's3', icon: '🌐', title: '3. Web Application Attack Detection', color: '#ef4444', items: webItems },
    { id: 's4', icon: '🔑', title: '4. Authentication Attack Detection', color: '#f97316', items: authItems },
    { id: 's5', icon: '🦠', title: '5. Malware Detection', color: '#a855f7', items: malwareItems },
    { id: 's6', icon: '📡', title: '6. Command & Control (C2)', color: '#ec4899', items: c2Items },
    { id: 's7', icon: '💥', title: '7. Denial of Service Detection', color: '#ef4444', items: dosItems },
    { id: 's8', icon: '🎭', title: '8. Network Spoofing Detection', color: '#6366f1', items: spoofItems },
    { id: 's9', icon: '🔗', title: '9. Protocol Monitoring', color: '#0ea5e9', items: protoItems },
    { id: 's10', icon: '🧠', title: '10. Threat Intelligence Matching', color: '#22c55e', items: threatIntelItems },
    { id: 's11', icon: '📊', title: '11. Anomaly Detection', color: '#eab308', items: anomalyItems },
    { id: 's12', icon: '🛡️', title: '12. IPS Prevention Actions', color: '#34d399', items: ipsActions },
  ];

  const sev3Color = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };

  return (
    <div className="ids-mon-root">
      <div className="ids-mon-header">
        <div>
          <h3>🔭 Monitoring Intelligence Dashboard</h3>
          <p>Comprehensive real-time coverage across all 13 monitoring categories</p>
        </div>
        <div className="ids-mon-header-stats">
          <div><span>Total Alerts (24H)</span><strong>{(stats?.total || 0).toLocaleString()}</strong></div>
          <div><span>IPS Blocked</span><strong style={{ color: '#ef4444' }}>{blockedIps.toLocaleString()}</strong></div>
          <div><span>Live Feed</span><strong style={{ color: hasLive ? '#22c55e' : '#64748b' }}>{hasLive ? '● Active' : '○ Idle'}</strong></div>
        </div>
      </div>

      {/* Monitoring Category Grid */}
      <div className="ids-mon-sections">
        {SECTIONS.map(sec => {
          const totalDetected = sec.items.reduce((s, [, c]) => s + c, 0);
          const isOpen = expandedSections[sec.id] !== false;
          return (
            <div key={sec.id} className="ids-mon-section" style={{ '--section-accent': sec.color }}>
              <SectionHead id={sec.id} icon={sec.icon} title={sec.title} color={sec.color} count={totalDetected} />
              {isOpen && <MonGrid items={sec.items} />}
            </div>
          );
        })}
      </div>

      {/* 13. IDS/IPS Alerts & Logs Table */}
      <div className="ids-mon-alerts-section">
        <div className="ids-mon-alerts-head">
          <div>
            <span className="ids-mon-section-icon" style={{ color: '#60a5fa' }}>📋</span>
            <strong>13. IDS/IPS Alerts & Logs</strong>
            <span className="ids-mon-badge-count" style={{ color: '#60a5fa', background: '#3b82f618', border: '1px solid #3b82f633' }}>{recentAlerts.length}</span>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button
              onClick={() => setAlertsPage(p => Math.max(0, p - 1))}
              disabled={alertsPage === 0}
              className="ids-mon-pg-btn"
            >‹</button>
            <span style={{ fontSize: 11, color: '#64748b' }}>{alertsPage + 1} / {Math.max(1, totalAlertPages)}</span>
            <button
              onClick={() => setAlertsPage(p => Math.min(totalAlertPages - 1, p + 1))}
              disabled={alertsPage >= totalAlertPages - 1}
              className="ids-mon-pg-btn"
            >›</button>
          </div>
        </div>
        <div className="ids-mon-table-wrap">
          <table className="ids-mon-table">
            <thead>
              <tr>
                {['Alert ID', 'Attack Type', 'Severity', 'Signature / Rule', 'Source IP', 'Dest IP', 'Src Port', 'Dst Port', 'Protocol', 'Timestamp', 'Packets', 'Action', 'Sensor', 'Rule ID', 'CVE', 'MITRE ATT&CK'].map(h => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alertRows.length ? alertRows.map((alert, i) => {
                const sev = (alert.severity || 'low').toLowerCase();
                const sevCol = sev3Color[sev] || '#60a5fa';
                const action = alert.blocked ? 'Blocked' : 'Detected';
                const actionCol = alert.blocked ? '#ef4444' : '#f59e0b';
                return (
                  <tr key={alert._id || i}>
                    <td><code style={{ fontSize: 10 }}>{(alert._id || `ALERT-${i + 1}`).toString().slice(-8)}</code></td>
                    <td>{alert.description || alert.type || alert.eventCategory || '—'}</td>
                    <td><span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 8, color: sevCol, background: `${sevCol}18`, border: `1px solid ${sevCol}44` }}>{sev.toUpperCase()}</span></td>
                    <td><code style={{ fontSize: 10 }}>{alert.signatureName || alert.signature || alert.ruleId || '—'}</code></td>
                    <td><code style={{ fontSize: 11 }}>{alert.srcip || '—'}</code></td>
                    <td><code style={{ fontSize: 11 }}>{alert.destip || '—'}</code></td>
                    <td>{alert.srcPort ?? '—'}</td>
                    <td>{alert.destPort ?? '—'}</td>
                    <td>{(alert.protocol || '—').toUpperCase()}</td>
                    <td style={{ fontSize: 10, color: '#64748b' }}>{alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '—'}</td>
                    <td>{alert.packetCount ?? '—'}{Number(alert.occurrenceCount || 1) > 1 ? ` · ×${alert.occurrenceCount}` : ''}</td>
                    <td><span style={{ fontSize: 10, fontWeight: 700, padding: '2px 7px', borderRadius: 8, color: actionCol, background: `${actionCol}18`, border: `1px solid ${actionCol}44` }}>{action}</span></td>
                    <td>{alert.agentName || alert.source || 'IDS/IPS'}</td>
                    <td><code style={{ fontSize: 10 }}>{alert.ruleId || '—'}</code></td>
                    <td>{alert.cveId ? <a href={`https://nvd.nist.gov/vuln/detail/${alert.cveId}`} target="_blank" rel="noreferrer" style={{ color: '#60a5fa', fontSize: 10 }}>{alert.cveId}</a> : '—'}</td>
                    <td>{alert.mitreId || alert.mitre || alert.mitreAttack || '—'}</td>
                  </tr>
                );
              }) : (
                <tr>
                  <td colSpan="16" style={{ textAlign: 'center', padding: '32px 0', color: '#475569' }}>
                    <div style={{ fontSize: 32 }}>📭</div>
                    <div style={{ marginTop: 8, fontSize: 13 }}>No IDS/IPS alerts in monitoring window</div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function FullReportTab({ focus = 'sources', onBack }) {
  const [stats, setStats] = useState(null);
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const sectionRefs = useRef({});

  const load = useCallback(async () => {
    setLoading(true); setErr('');
    try {
      const [statsRes, logsRes] = await Promise.allSettled([
        api.get('/ids/stats?recentLimit=1000&topLimit=500'),
        api.get('/idsips/logs?limit=500'),
      ]);
      if (statsRes.status === 'fulfilled') setStats(statsRes.value.data);
      if (logsRes.status === 'fulfilled') setLogs((logsRes.value.data?.logs || []).filter(isIdsIpsThreatEvent));
      if (statsRes.status !== 'fulfilled' && logsRes.status !== 'fulfilled') {
        throw new Error('Unable to load IDS report data');
      }
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (loading || !sectionRefs.current[focus]) return;
    const frame = requestAnimationFrame(() => {
      sectionRefs.current[focus]?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
    return () => cancelAnimationFrame(frame);
  }, [focus, loading]);

  const recentAlerts = (stats?.recentAlerts || []).filter(isIdsIpsThreatEvent);
  const topSources = stats?.topSrcIps || [];
  const sourceRiskColor = { critical: '#ef4444', high: '#ef4444', medium: '#f59e0b', low: '#22c55e' };
  const incidentLogs = logs.filter(isIdsIpsThreatEvent);
  const activityRows = incidentLogs.length
    ? [...incidentLogs].reverse().map((log, i) => ({
      id: log.id || log._id || i,
      time: log.ts ? new Date(log.ts).toLocaleString() : '—',
      level: log.level || log.type || 'INFO',
      source: log.source || (/ips|block/i.test(log.message || '') ? 'IPS' : 'IDS'),
      message: log.message || JSON.stringify(log),
    }))
    : recentAlerts.map(alert => ({
      id: alert._id,
      time: alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '—',
      level: alert.severity || 'low',
      source: alert.source || 'IDS',
      message: `${alert.description || alert.type || 'Security alert'} ${alert.srcip || ''}${alert.destip ? ` -> ${alert.destip}` : ''}`,
    }));

  const sectionClass = (name) => `ids-report-section ${focus === name ? 'focused' : ''}`;
  const reportTitle = {
    sources: 'Top Source IPs Report',
    alerts: 'Recent Alerts Report',
    activity: 'Live Activity Report',
  }[focus] || 'IDS / IPS Full Report';

  return (
    <div className="ids-report-page">
      <div className="ids-report-head">
        <div>
          <h3>{reportTitle}</h3>
          <p>Real-time IDS / IPS monitoring data.</p>
        </div>
        <div>
          <button onClick={load} disabled={loading}>↻ Refresh</button>
          <button onClick={onBack}>← Back to IDS Overview</button>
        </div>
      </div>

      {loading ? <Empty icon="⏳" msg="Loading full report…" /> : err ? (
        <div style={{ color: '#f87171', fontSize: 13 }}>❌ {err}</div>
      ) : (
        <>
          {focus === 'sources' && <section ref={node => { sectionRefs.current.sources = node; }} className={sectionClass('sources')}>
            <div className="ids-report-title"><strong>Top Source IPs (24H)</strong><span>{topSources.length} sources</span></div>
            <div className="ids-report-table-wrap">
              <table className="ids-report-table">
                <thead><tr><th>Rank</th><th>Source IP</th><th>Alerts</th><th>Risk</th><th>Trend</th></tr></thead>
                <tbody>
                  {topSources.map((row, i) => (
                    <tr key={`${row._id}-${i}`}>
                      <td>#{i + 1}</td><td><code>{row._id}</code></td><td>{row.count}</td>
                      <td><span className={`ids-report-pill ${String(row.severity || 'low').toLowerCase()}`}>{labelSeverity(row.severity)}</span></td>
                      <td>
                        <Sparkline
                          color={sourceRiskColor[String(row.severity || 'low').toLowerCase()] || '#22c55e'}
                          points={sourceTrendPoints(row.hourly)}
                        />
                      </td>
                    </tr>
                  ))}
                  {!topSources.length && <tr><td colSpan="5"><Empty icon="✅" msg="No IDS/IPS source IP activity found" /></td></tr>}
                </tbody>
              </table>
            </div>
          </section>}

          {focus === 'alerts' && <section ref={node => { sectionRefs.current.alerts = node; }} className={sectionClass('alerts')}>
            <div className="ids-report-title"><strong>Recent Alerts</strong><span>{recentAlerts.length} alerts</span></div>
            <div className="ids-report-table-wrap">
              <table className="ids-report-table">
                <thead><tr><th>Time</th><th>Severity</th><th>Source</th><th>Flow</th><th>Description</th></tr></thead>
                <tbody>
                  {recentAlerts.map(alert => (
                    <tr key={alert._id || `${alert.srcip}-${alert.createdAt}`}>
                      <td>{alert.createdAt ? new Date(alert.createdAt).toLocaleString() : '—'}</td>
                      <td><span className={`ids-report-pill ${(alert.severity || 'low').toLowerCase()}`}>{alert.severity || 'low'}</span></td>
                      <td>{alert.source || 'IDS'}</td>
                      <td><code>{[alert.srcip, alert.destip && `→ ${alert.destip}${alert.destPort ? `:${alert.destPort}` : ''}`].filter(Boolean).join(' ') || '—'}</code></td>
                      <td>{alert.description || alert.type || 'Security alert'}</td>
                    </tr>
                  ))}
                  {!recentAlerts.length && <tr><td colSpan="5"><Empty icon="✅" msg="No IDS/IPS logs found" /></td></tr>}
                </tbody>
              </table>
            </div>
            <div className="ids-report-bottom-actions">
              <button onClick={onBack}>← Back to IDS Overview</button>
            </div>
          </section>}

          {focus === 'activity' && <section ref={node => { sectionRefs.current.activity = node; }} className={sectionClass('activity')}>
            <div className="ids-report-title"><strong>Live Activity Feed</strong><span>{activityRows.length} events</span></div>
            <div className="ids-report-table-wrap">
              <table className="ids-report-table">
                <thead><tr><th>Time</th><th>Level</th><th>Source</th><th>Message</th></tr></thead>
                <tbody>
                  {activityRows.map(row => (
                    <tr key={row.id}>
                      <td>{row.time}</td><td><span className={`ids-report-pill ${String(row.level).toLowerCase()}`}>{row.level}</span></td><td>{row.source}</td><td>{row.message}</td>
                    </tr>
                  ))}
                  {!activityRows.length && <tr><td colSpan="4"><Empty icon="✅" msg="No IDS/IPS logs found" /></td></tr>}
                </tbody>
              </table>
            </div>
          </section>}
        </>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  INLINE LOG PANEL — reusable log strip embedded inside Blocklist & Whitelist
// ══════════════════════════════════════════════════════════════════════════════
function InlineLogPanel({ title = '📋 Activity Log', filterLevel = null }) {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [collapsed, setCollapsed] = useState(false);
  const [level, setLevel] = useState(filterLevel || 'ALL');
  const [limit, setLimit] = useState(50);
  const bottomRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const qs = level !== 'ALL' ? `?limit=${limit}&severity=${level.toLowerCase()}` : `?limit=${limit}`;
      const { data } = await api.get(`/idsips/logs${qs}`);
      setLogs((data.logs || []).filter(isIdsIpsThreatEvent));
    } catch { /* silent */ }
    finally { setLoading(false); }
  }, [level, limit]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (!collapsed) bottomRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [logs, collapsed]);

  const LEVELS = filterLevel ? [filterLevel] : ['ALL', 'BLOCK', 'UNBLOCK', 'ERROR', 'WARN', 'INFO'];

  return (
    <div style={{ marginTop: 24, border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
      {/* Header bar */}
      <div
        style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 16px', background: '#060e1a', cursor: 'pointer', userSelect: 'none' }}
        onClick={() => setCollapsed(c => !c)}
      >
        <span style={{ fontSize: 13, fontWeight: 700, color: '#93c5fd' }}>{title}</span>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
          {LEVELS.length > 1 && (
            <div style={{ display: 'flex', gap: 3 }}>
              {LEVELS.map(l => (
                <button key={l} onClick={() => setLevel(l)} style={{ ...C.btn(), padding: '2px 8px', fontSize: 10, background: level === l ? `${LEVEL_COLOR[l] || '#3b82f6'}22` : 'transparent', color: LEVEL_COLOR[l] || '#94a3b8', border: `1px solid ${level === l ? (LEVEL_COLOR[l] || '#3b82f6') : '#1e3a5f'}` }}>{l}</button>
              ))}
            </div>
          )}
          <select value={limit} onChange={e => setLimit(Number(e.target.value))} style={{ ...C.inp, width: 'auto', padding: '2px 6px', fontSize: 11 }}>
            {[25, 50, 100, 200].map(v => <option key={v} value={v}>Last {v}</option>)}
          </select>
          <button onClick={load} disabled={loading} style={{ ...C.btn(), padding: '2px 8px', fontSize: 11 }}>{loading ? '⏳' : '🔄'}</button>
          <button onClick={() => setCollapsed(c => !c)} style={{ ...C.btn(), padding: '2px 8px', fontSize: 11 }}>{collapsed ? '▼ Show' : '▲ Hide'}</button>
        </div>
      </div>
      {/* Log body */}
      {!collapsed && (
        <div style={{ background: '#070f1d', height: 260, overflowY: 'auto', fontFamily: 'monospace', fontSize: 11, padding: '8px 12px' }}>
          {loading ? <div style={{ color: '#64748b', textAlign: 'center', padding: 20 }}>⏳ Loading logs…</div>
            : logs.length === 0 ? <div style={{ color: '#475569', textAlign: 'center', padding: 20 }}>No IDS/IPS logs found.</div>
              : [...logs].reverse().map((log, i) => (
                <div key={i} style={{ padding: '3px 0', borderBottom: '1px solid #0a1628', display: 'flex', gap: 10, alignItems: 'flex-start' }}>
                  <span style={{ color: '#475569', minWidth: 72, flexShrink: 0 }}>{log.ts ? new Date(log.ts).toLocaleTimeString() : '—'}</span>
                  <span style={{ color: LEVEL_COLOR[log.level] || '#94a3b8', minWidth: 54, flexShrink: 0, fontWeight: 700 }}>[{log.level || 'INFO'}]</span>
                  <span style={{ color: '#e2e8f0', wordBreak: 'break-all' }}>{log.message || JSON.stringify(log)}</span>
                </div>
              ))}
          <div ref={bottomRef} />
        </div>
      )}
      {!collapsed && <div style={{ padding: '4px 16px', fontSize: 10, color: '#475569', borderTop: '1px solid #1e3a5f', background: '#060e1a' }}>{logs.length} entries · click header to collapse</div>}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  BLOCKLIST  — from IPS Webhook Server (5050) + block/unblock via backend
// ══════════════════════════════════════════════════════════════════════════════
function BlocklistTab({ onTabChange }) {
  const authorizationContext = getStoredAuthorizationContext();
  const [list, setList] = useState([]);
  const [agents, setAgents] = useState([]);
  const [status, setStatus] = useState(null);
  const [filter, setFilter] = useState('');
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ ip: '', port: '', domain: '', application: '', protocol: 'tcp', reason: '', attackType: '', ttlHours: '24', systemId: '' });
  const [manualOverride, setManualOverride] = useState(false);
  const [pendingRestore, setPendingRestore] = useState(null);

  useEffect(() => {
    const prefill = sessionStorage.getItem('ips:block-prefill');
    if (!prefill) return;
    sessionStorage.removeItem('ips:block-prefill');
    try {
      const target = JSON.parse(prefill);
      setForm(current => ({
        ...current,
        ip: target.type === 'domain' ? '' : String(target.value || ''),
        domain: target.type === 'domain' ? String(target.value || '') : '',
      }));
    } catch {
      setForm(current => ({ ...current, ip: prefill }));
    }
  }, []);
  const [overrideForm, setOverrideForm] = useState({
    company: authorizationContext.company, department: authorizationContext.department, systemId: '', serverName: '', hostname: '', ipAddress: '',
    reason: '', approvedBy: '', employeeId: '', designation: '', digitalSignature: '',
  });
  const [overrideReasons, setOverrideReasons] = useState({
    businessCritical: false,
    productionIssue: false,
    falsePositive: false,
    testing: false,
    emergency: false,
    customerImpact: false,
    other: false,
  });
  const [overrideChecks, setOverrideChecks] = useState({
    activeAttack: false,
    acceptSecurityRisks: false,
    authorizeRestore: false,
    dataLossMayOccur: false,
    ransomwareMaySpread: false,
    socNotResponsible: false,
  });
  const [overrideError, setOverrideError] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [showForm, setShowForm] = useState(true);
  const [msg, setMsg] = useState('');
  const [blockType, setBlockType] = useState('IP Address');
  const [page, setPage] = useState(1);

  const blockTimeValue = (block = {}) => {
    const raw = block.updatedAt || block.ts || block.blockedAt || block.createdAt || block.timestamp;
    const time = raw ? new Date(raw).getTime() : 0;
    return Number.isFinite(time) ? time : 0;
  };

  const blockAgeLabel = (block = {}) => {
    const time = block._sortTime || blockTimeValue(block);
    if (!time) return '—';
    const diffMs = Math.max(0, Date.now() - time);
    const minutes = Math.floor(diffMs / 60000);
    if (minutes < 1) return 'now';
    if (minutes < 60) return `${minutes}m`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h`;
    return `${Math.floor(hours / 24)}d`;
  };

  const blockAgentLabel = (block = {}, agentRows = agents) => {
    const existing = [block.agentName, block.agentHostname]
      .map(v => String(v || '').trim())
      .find(v => v && !/^all agents$/i.test(v));
    if (existing) return existing;

    const systemId = String(block.systemId || '').trim();
    const agentId = String(block.agentId || '').trim();
    const agentIp = String(block.agentIp || block.ip || '').trim();
    const matched = (agentRows || []).find(agent => {
      const ids = [agent._id, agent.agentId, agent.id].map(v => String(v || '').trim()).filter(Boolean);
      const ips = [agent.ip, agent.ipAddress, agent.privateIp, agent.agentIP].map(v => String(v || '').trim()).filter(Boolean);
      return (systemId && ids.includes(systemId)) || (agentId && ids.includes(agentId)) || (agentIp && ips.includes(agentIp));
    });
    if (matched) return matched.name || matched.hostname || matched.agentId || 'Agent';

    return 'Central Firewall';
  };

  const normalizeBlock = (block = {}, agentRows = agents) => {
    const ts = block.updatedAt || block.ts || block.blockedAt || block.createdAt || block.timestamp || null;
    const agentLabel = blockAgentLabel(block, agentRows);
    const detectedType = block.domain ? 'Domain'
      : block.application ? 'Application'
        : block.port && !block.ip ? 'Port'
          : block.protocol && !block.ip ? 'Protocol'
            : 'IP Address';
    return {
      ...block,
      type: detectedType,
      ts,
      _sortTime: blockTimeValue({ ...block, ts }),
      _agentLabel: agentLabel,
      agentName: /^all agents$/i.test(String(block.agentName || '').trim()) ? agentLabel : block.agentName,
    };
  };

  const load = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true);
    try {
      // MongoDB is the durable source for active blocks. Do not make the page
      // wait for the optional IPS webhook service, and do not merge historical
      // block events back into the active blocklist.
      const [backendBlocks, st, systemList] = await Promise.allSettled([
        api.get('/ips/blocklist'),
        api.get('/ips/status'),
        api.get('/system'),
      ]);
      const agentRows = systemList.status === 'fulfilled'
        ? (Array.isArray(systemList.value?.data) ? systemList.value.data : (systemList.value?.data?.systems || []))
        : [];
      const backendBlockRows = backendBlocks.status === 'fulfilled' ? (backendBlocks.value?.data?.blocked || []) : [];
      const normalizedBackendBlocks = backendBlockRows.map(row => ({
        ...row,
        ip: row.ip,
        blockKey: row.ip,
        source: row.blockedBy || 'auto',
        blockedBy: row.blockedBy || 'auto',
        attackType: row.attackType || (String(row.reason || '').includes('TI auto-block') ? 'Threat Intelligence Auto-Block' : ''),
        reason: row.reason || 'Backend IPS block',
        ts: row.blockedAt || row.createdAt,
        blockedAt: row.blockedAt || row.createdAt,
        ttlHours: row.expiresAt ? Math.max(1, Math.round((new Date(row.expiresAt).getTime() - Date.now()) / 3600000)) : undefined,
        _sourceSystem: 'backend',
      }));
      const mergedByKey = new Map();
      normalizedBackendBlocks.forEach(block => {
        // IPS server prefixes IP keys with `ip:` while the backend stores the
        // raw address. Canonicalize them so the same firewall target cannot be
        // displayed twice. Log-only records are audit evidence, not active
        // endpoint firewall blocks.
        const rawKey = block.ip || block.blockKey || block.domain || block.application || `${block.port || ''}:${block.protocol || ''}`;
        const key = String(rawKey || '').replace(/^ip:/i, '').toLowerCase();
        if (!key) return;
        if (String(block.method || '').toLowerCase() === 'log-only') {
          mergedByKey.delete(key);
          return;
        }
        const previous = mergedByKey.get(key);
        mergedByKey.set(key, previous ? { ...previous, ...block, _sourceSystem: previous._sourceSystem === 'backend' ? previous._sourceSystem : block._sourceSystem } : block);
      });
      const mergedBlocks = [...mergedByKey.values()]
        .map(block => normalizeBlock(block, agentRows))
        .sort((a, b) => (b._sortTime || 0) - (a._sortTime || 0));
      setList(mergedBlocks);
      if (systemList.status === 'fulfilled') {
        setAgents(agentRows);
      }
      // Backend config and durable block records remain available even when the
      // optional IPS webhook process is offline.
      const backendStatus = st.status === 'fulfilled' ? st.value?.data : null;
      const blocklistData = mergedBlocks;
      setStatus({
        mode: backendStatus?.mode || 'log',
        autoBlock: backendStatus?.autoBlock ?? false,
        ttlHours: backendStatus?.ttlHours ?? 24,
        blocklistActive: blocklistData.length,
      });
    } catch { }
    if (!silent) setLoading(false);
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => load({ silent: true }), 60000);
    return () => clearInterval(timer);
  }, [load]);

  const isManualBlock = (block) => {
    const source = String(block?.blockedBy || block?.source || '').trim().toLowerCase();
    if (source) return ['manual', 'analyst', 'soar', 'admin'].includes(source);
    return block?.blockState === 'manual-block';
  };

  const getUnblockPayload = (block) => {
    const payload = {};
    if (block.ip) payload.ip = block.ip;
    if (block.domain) payload.domain = block.domain;
    if (block.application) payload.application = block.application;
    if (block.port) payload.port = block.port;
    if (block.protocol) payload.protocol = block.protocol;
    if (Object.keys(payload).length === 0 && block.blockKey) payload.ip = block.blockKey;
    if (block.systemId) payload.systemId = block.systemId;
    if (block.agentId) payload.agentId = block.agentId;
    if (block.agentName) payload.agentName = block.agentName;
    return payload;
  };

  const blockTarget = async (e) => {
    e.preventDefault();
    setSubmitting(true); setMsg('');
    try {
      const value = blockType === 'IP Address' ? form.ip.trim()
        : blockType === 'Domain' ? form.domain.trim()
          : blockType === 'Port' ? String(form.port).trim()
            : blockType === 'Application' ? form.application.trim()
              : form.protocol.trim().toLowerCase();
      if (!value) throw new Error(`${blockType} value is required`);

      if (blockType === 'IP Address') {
        const ipv4 = value.match(/^(\d{1,3}\.){3}\d{1,3}(?:\/\d{1,2})?$/);
        const validIpv4 = ipv4 && value.split('/')[0].split('.').every(part => Number(part) >= 0 && Number(part) <= 255);
        const validIpv6 = value.includes(':');
        if (!validIpv4 && !validIpv6) throw new Error('Enter a valid IPv4, IPv6, or CIDR address');
      }
      if (blockType === 'Port' && (!Number.isInteger(Number(value)) || Number(value) < 1 || Number(value) > 65535)) {
        throw new Error('Port must be between 1 and 65535');
      }

      const body = {
        reason: form.reason.trim() || 'Manual block by administrator',
        attackType: form.attackType || undefined,
        ttlHours: form.ttlHours,
      };
      if (blockType === 'IP Address') body.ip = value;
      if (blockType === 'Domain') body.domain = value;
      if (blockType === 'Port') {
        body.port = value;
        body.protocol = 'tcp';
      }
      if (blockType === 'Application') body.application = value;
      if (blockType === 'Protocol') body.protocol = value;

      const selectedAgent = agents.find(agent => String(agent._id) === String(form.systemId));
      if (selectedAgent) {
        body.systemId = selectedAgent._id;
        body.agentId = selectedAgent.agentId || selectedAgent._id;
        body.agentName = selectedAgent.name || selectedAgent.hostname || 'Agent';
        body.agentHostname = selectedAgent.hostname || '';
        body.agentIp = selectedAgent.ip || '';
      } else {
        delete body.systemId;
        body.agentName = 'Central Firewall';
      }
      body.source = 'Manual'; // Mark as manual block so Source column shows '👤 Manual'
      await api.post('/ips-proxy/block', body);
      setMsg('✅ Block applied');
      setForm({ ip: '', port: '', domain: '', application: '', protocol: 'tcp', reason: '', attackType: '', ttlHours: '24', systemId: '' });
      setShowForm(false); setTimeout(load, 800);
    } catch (e) {
      setMsg(`❌ ${e.response?.data?.message || e.response?.data?.error || e.response?.data?.details || e.message}`);
    }
    finally { setSubmitting(false); }
  };

  const unblock = async (block) => {
    const label = block.ip || block.domain || block.application || block.port || block.blockKey || 'entry';

    if (isManualBlock(block)) {
      const payload = getUnblockPayload(block);
      if (Object.keys(payload).length === 0) {
        setMsg('❌ Cannot unblock: no IP, domain, or port found in block entry');
        return;
      }

      setSubmitting(true);
      setMsg('');
      try {
        await api.post('/ips-proxy/unblock', payload);
        const target = block.ip || block.blockKey || block.domain || label;
        const approvalResult = await api.post('/ips-engine/audit/manual', {
          action: 'Manual Override Approved',
          severity: 'high',
          target,
          srcIp: block.ip || block.blockKey,
          systemId: block.systemId || '',
          detail: `Manual block removed by administrator: ${label}. Server restored by manual override.`,
          emailSubject: 'Manual Override Approved',
          emailMessage: `Manual block removed by administrator.\n\nTarget: ${label}\nServer Live: Yes\nRisk acceptance has been recorded in Audit Log.`,
          manualOverride: {
            approvalStatus: 'Manual Override Approved',
            reason: block.reason || 'Manual unblock requested by administrator',
            serverName: block.agentName || 'Central Firewall',
            hostname: block.agentHostname || '',
            ipAddress: block.agentIp || block.ip || block.blockKey || '',
            systemId: block.systemId || '',
          },
        }).catch(error => ({
          data: {
            event: {
              emailSent: false,
              emailTo: null,
              emailError: error.response?.data?.message || error.message,
            },
          },
        }));
        await api.post('/ips-engine/audit/manual', {
          action: 'Server Restored',
          severity: 'high',
          target,
          srcIp: block.ip || block.blockKey,
          systemId: block.systemId || '',
          detail: `Server Live after manual block removal: ${label}`,
        }).catch(() => { });
        const emailResult = approvalResult?.data?.event;
        setMsg(emailResult?.emailSent
          ? `✅ Manual block removed: ${label}. Email sent to ${emailResult.emailTo}`
          : `⚠️ Manual block removed: ${label}, but email delivery failed${emailResult?.emailTo ? ` (${emailResult.emailTo})` : ''}`);
        setPendingRestore(null);
        setTimeout(load, 600);
      } catch (e) {
        setMsg(`❌ ${e.response?.data?.message || e.message}`);
      } finally {
        setSubmitting(false);
      }
      return;
    }

    setPendingRestore({ ...block, label });
    setManualOverride(false);
    setOverrideError('');
    const selectedAgent = agents.find(agent => String(agent._id) === String(block.systemId));
    setOverrideForm({
      company: authorizationContext.company,
      department: selectedAgent?.departmentId?.name || authorizationContext.department || 'Company-wide',
      systemId: block.systemId || '',
      serverName: block.agentName || selectedAgent?.name || '',
      hostname: block.agentHostname || selectedAgent?.hostname || '',
      ipAddress: block.agentIp || selectedAgent?.ip || '',
      reason: '', approvedBy: '', employeeId: '', designation: '', digitalSignature: '',
    });
    setOverrideReasons({
      businessCritical: false,
      productionIssue: false,
      falsePositive: false,
      testing: false,
      emergency: false,
      customerImpact: false,
      other: false,
    });
    setOverrideChecks({
      activeAttack: false,
      acceptSecurityRisks: false,
      authorizeRestore: false,
      dataLossMayOccur: false,
      ransomwareMaySpread: false,
      socNotResponsible: false,
    });
    setMsg(`⚠️ Manual Override required before restoring ${label}`);
    api.post('/ips-engine/audit/manual', {
      action: 'Manual Override Requested',
      severity: 'high',
      target: block.ip || block.blockKey || block.domain || label,
      detail: `Administrator requested server live/restore before automated recovery completed: ${label}`,
    }).catch(() => { });
  };

  const submitManualRestore = async (e) => {
    e.preventDefault();
    if (!pendingRestore) return;
    setOverrideError('');
    if (!manualOverride) {
      const error = 'Select Manual Override before restoring the server.';
      setOverrideError(error);
      setMsg(`❌ ${error}`);
      return;
    }
    const requiredFields = ['company', 'department', 'systemId', 'serverName', 'hostname', 'ipAddress', 'reason', 'approvedBy', 'employeeId', 'designation', 'digitalSignature'];
    const missing = requiredFields.some(field => !String(overrideForm[field] || '').trim());
    const hasReason = Object.values(overrideReasons).some(Boolean);
    const allChecked = Object.values(overrideChecks).every(Boolean);
    if (missing) {
      const error = 'Complete every Authorization field and choose a registered agent.';
      setOverrideError(error);
      setMsg(`❌ ${error}`);
      return;
    }
    if (!hasReason) {
      const error = 'Select at least one override reason.';
      setOverrideError(error);
      setMsg(`❌ ${error}`);
      return;
    }
    if (!allChecked) {
      const error = 'Accept all 6 Risk Acceptance statements before unblock.';
      setOverrideError(error);
      setMsg(`❌ ${error}`);
      return;
    }

    const payload = getUnblockPayload(pendingRestore);
    if (Object.keys(payload).length === 0) {
      setMsg('❌ Cannot restore: no IP, domain, or port found in block entry'); return;
    }
    payload.systemId = overrideForm.systemId;
    payload.agentName = overrideForm.serverName;
    payload.agentHostname = overrideForm.hostname;
    payload.agentIp = overrideForm.ipAddress;

    const selectedReasons = Object.entries(overrideReasons)
      .filter(([, checked]) => checked)
      .map(([key]) => key.replace(/([A-Z])/g, ' $1').replace(/^./, ch => ch.toUpperCase()));
    const approvalTime = new Date();
    payload.manualOverride = {
      ...overrideForm,
      reasonCategories: selectedReasons,
      riskAcceptance: overrideChecks,
      approvalStatus: 'Manual Override Approved',
      date: approvalTime.toLocaleDateString(),
      time: approvalTime.toLocaleTimeString(),
      auditLog: true,
      emailSubject: 'Manual Override Approved',
      emailMessage: 'Administrator has manually restored the server while the attack is still active. Risk acceptance has been recorded.',
    };
    payload.reason = `Manual Override Approved | Approved By: ${overrideForm.approvedBy} | Reason: ${overrideForm.reason} | Categories: ${selectedReasons.join(', ')}`;
    setSubmitting(true);
    try {
      await api.post('/ips-proxy/unblock', payload);
      await api.post('/ips-engine/audit/manual', {
        action: 'Checklist Submitted',
        severity: 'high',
        target: overrideForm.ipAddress || pendingRestore.ip || pendingRestore.blockKey,
        srcIp: pendingRestore.ip || pendingRestore.blockKey || overrideForm.ipAddress,
        systemId: overrideForm.systemId,
        detail: `Manual Override Authorization Checklist submitted by ${overrideForm.approvedBy}`,
        manualOverride: payload.manualOverride,
      }).catch(() => { });
      const approvalResult = await api.post('/ips-engine/audit/manual', {
        action: 'Manual Override Approved',
        severity: 'high',
        target: overrideForm.ipAddress || pendingRestore.ip || pendingRestore.blockKey,
        srcIp: pendingRestore.ip || pendingRestore.blockKey || overrideForm.ipAddress,
        systemId: overrideForm.systemId,
        detail: payload.manualOverride.emailMessage,
        emailSubject: payload.manualOverride.emailSubject,
        emailMessage: payload.manualOverride.emailMessage,
        manualOverride: payload.manualOverride,
      }).catch(error => ({
        data: {
          event: {
            emailSent: false,
            emailTo: null,
            emailError: error.response?.data?.message || error.message,
          },
        },
      }));
      await api.post('/ips-engine/audit/manual', {
        action: 'Server Restored',
        severity: 'high',
        target: overrideForm.ipAddress || pendingRestore.ip || pendingRestore.blockKey,
        srcIp: pendingRestore.ip || pendingRestore.blockKey || overrideForm.ipAddress,
        systemId: overrideForm.systemId,
        detail: `Server Live after manual override approval by ${overrideForm.approvedBy} (Employee ID: ${overrideForm.employeeId})`,
        manualOverride: payload.manualOverride,
      }).catch(() => { });
      const emailResult = approvalResult?.data?.event;
      setMsg(emailResult?.emailSent
        ? `✅ Manual Override Approved — Server Live: ${pendingRestore.label}. Email sent to ${emailResult.emailTo}`
        : `⚠️ Server Live: ${pendingRestore.label}, but admin email delivery failed${emailResult?.emailTo ? ` (${emailResult.emailTo})` : ''}`);
      setOverrideError('');
      setPendingRestore(null);
      setManualOverride(false);
      await load();
    } catch (e) {
      const error = e.response?.data?.message || e.message;
      setOverrideError(error);
      setMsg(`❌ ${error}`);
    } finally {
      setSubmitting(false);
    }
  };

  const cancelManualOverride = async () => {
    if (!pendingRestore) return;
    const actor = overrideForm.approvedBy?.trim() || 'Administrator';
    const employee = overrideForm.employeeId?.trim()
      ? ` (Employee ID: ${overrideForm.employeeId.trim()})`
      : '';
    setSubmitting(true);
    setOverrideError('');
    try {
      await api.post('/ips-engine/audit/manual', {
        action: 'Manual Override Cancelled',
        severity: 'medium',
        target: pendingRestore.ip || pendingRestore.blockKey || pendingRestore.domain || pendingRestore.label,
        detail: `Manual Override Authorization Checklist opened but not approved. Cancelled by ${actor}${employee}. Unblock was not performed; block remains active.`,
      });
      setMsg(`↩️ Manual Override cancelled — block remains active: ${pendingRestore.label}`);
      setPendingRestore(null);
      setManualOverride(false);
    } catch (e) {
      const error = e.response?.data?.message || e.message;
      setOverrideError(`Cancellation audit failed: ${error}`);
      setMsg(`❌ Cancellation audit failed: ${error}`);
    } finally {
      setSubmitting(false);
    }
  };

  const cutoff24h = Date.now() - (24 * 60 * 60 * 1000);
  const recent24hBlocks = list.filter(block => {
    const time = block._sortTime || blockTimeValue(block);
    return time && time >= cutoff24h;
  });
  const newestFirst = [...recent24hBlocks].sort((a, b) => (b._sortTime || blockTimeValue(b)) - (a._sortTime || blockTimeValue(a)));
  const blockedTarget = (block = {}) => {
    if (block.domain) return { type: 'Domain', value: block.domain, color: '#a78bfa' };
    if (block.application) return { type: 'Application', value: block.application, color: '#fbbf24' };
    if (block.port && !block.ip) return { type: 'Port', value: `${block.protocol || 'tcp'}:${block.port}`, color: '#94a3b8' };
    if (block.protocol && !block.ip) return { type: 'Protocol', value: block.protocol, color: '#38bdf8' };
    return { type: 'IP Address', value: block.ip || block.blockKey || '—', color: '#60a5fa' };
  };
  const filtered = newestFirst.filter(b => {
    const q = filter.toLowerCase();
    const searchable = [b.ip, b.domain, b.reason, b.attackType, b.application, b.blockKey, b.source, b.blockedBy, b.agentName, b.agentHostname, b.agentId]
      .filter(Boolean)
      .join(' ')
      .toLowerCase();
    return !q || searchable.includes(q);
  });
  const pageSize = 10;
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pagedBlocks = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const autoBlockCount = recent24hBlocks.filter(b => !isManualBlock(b)).length;
  const manualBlockCount = Math.max(0, recent24hBlocks.length - autoBlockCount);
  const sourceCount = new Set(recent24hBlocks.map(b => {
    if (b.ip) return `ip:${b.ip}`;
    if (b.domain) return `domain:${b.domain}`;
    if (b.application) return `app:${b.application}`;
    if (b.port) return `port:${b.protocol || 'tcp'}:${b.port}`;
    if (b.protocol) return `protocol:${b.protocol}`;
    return b.blockKey || null;
  }).filter(Boolean)).size;

  const IP_ADDRESSES = [
    '203.0.113.45',
    '192.0.2.100',
    '198.51.100.75',
    '203.0.113.200',
    '192.0.2.55',
    '10.0.0.0/8',
    '172.16.0.0/12',
    '192.168.0.0/16',
  ];

  const PORTS = [
    '22',
    '80',
    '443',
    '3306',
    '5432',
    '8080',
    '8443',
    '27017',
    '5050',
    '5060',
    '3389',
    '1433',
  ];

  const DOMAINS = [
    'evil.com',
    'malware.net',
    'c2-server.com',
    'ads-tracker.io',
    'suspicious.org',
    'botnet.ru',
    'phishing-site.tk',
    'ransomware.xyz',
  ];

  const APPLICATIONS = [
    '/usr/bin/app',
    '/usr/sbin/sshd',
    '/usr/bin/wget',
    '/usr/bin/curl',
    '/bin/bash',
    '/usr/bin/python',
    '/opt/soc-agent/agent.py',
    '/usr/local/bin/scanner',
  ];

  const BLOCK_TYPES = [
    'IP Address',
    'Domain',
    'Port',
    'Application',
    'Protocol',
  ];

  const ATTACK_TYPES = [
    'SQL Injection (SQLi)',
    'Cross-Site Scripting (XSS)',
    'Log4Shell',
    'Server-Side Request Forgery (SSRF)',
    'Command Injection',
    'DNS Tunneling',
    'Remote File Inclusion (RFI)',
    'Local File Inclusion (LFI)',
    'Directory Traversal',
    'Cross-Site Request Forgery (CSRF)',
    'Brute Force Attack',
    'DDoS Attack',
    'XML External Entity (XXE)',
    'Insecure Deserialization',
    'Open Redirect',
    'File Upload Attack',
  ];

  return (
    <div>
      {/* Status banner */}
      {status && (
        <div className="ids-block-kpis">
          {[
            { icon: '♙', label: 'Mode', val: status.mode?.toUpperCase() || 'HOST-FIREWALL', sub: 'Enforcement mode', color: '#2f8cff' },
            { icon: '♜', label: 'Blocks (24H)', val: recent24hBlocks.length, sub: 'Blocked in last 24h', color: '#ff414f' },
            { icon: '♙', label: 'Auto-Block', val: status.autoBlock ? 'ON' : 'OFF', sub: status.autoBlock ? 'Auto-blocking enabled' : 'Manual review mode', color: status.autoBlock ? '#28d986' : '#64748b' },
            { icon: '◎', label: 'Block Sources', val: sourceCount, sub: 'Threat sources', color: '#45a5ff' },
            { icon: '◷', label: 'TTL', val: `${status.ttlHours}h`, sub: 'Default block duration', color: '#9b67ff' },
          ].map((s, i) => (
            <div className="ids-block-kpi" key={s.label}>
              <span className="ids-block-kpi-icon" style={{ color: s.color, textShadow: `0 0 12px ${s.color}55` }}>{s.icon}</span>
              <span>
                <span className="ids-block-kpi-label">{s.label}</span>
                <strong style={{ color: s.color }}>{s.val ?? '—'}</strong>
                <small>{s.sub}</small>
              </span>
            </div>
          ))}
        </div>
      )}

      {msg && <div style={{ marginBottom: 12, fontSize: 13, color: msg.startsWith('✅') || msg.startsWith('↩️') ? '#34d399' : '#f87171' }}>{msg}</div>}

      {/* Block Form */}
      {showForm && (
        <form onSubmit={blockTarget} className="ids-add-block">
          <div className="ids-add-block-head">
            <strong>Add New Block</strong>
          </div>
          <div className="ids-add-block-fields">
            <label>AGENT
              <select value={form.systemId} onChange={e => setForm(p => ({ ...p, systemId: e.target.value }))}>
                <option value="">Central Firewall</option>
                {agents.map(agent => (
                  <option key={agent._id} value={agent._id}>
                    {agent.name || agent.hostname || agent.agentId || 'Unnamed Agent'}
                    {agent.hostname && agent.hostname !== agent.name ? ` · ${agent.hostname}` : ''}
                    {agent.ip ? ` · ${agent.ip}` : ''}
                    {agent.isOnline ? ' · Online' : ' · Offline'}
                  </option>
                ))}
              </select>
            </label>
            <label>BLOCK TYPE
              <select value={blockType} onChange={e => setBlockType(e.target.value)}>
                {BLOCK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label>VALUE
              <input
                value={blockType === 'IP Address' ? form.ip : blockType === 'Domain' ? form.domain : blockType === 'Port' ? form.port : blockType === 'Application' ? form.application : form.protocol}
                onChange={e => {
                  const val = e.target.value;
                  if (blockType === 'IP Address') setForm(p => ({ ...p, ip: val }));
                  else if (blockType === 'Domain') setForm(p => ({ ...p, domain: val }));
                  else if (blockType === 'Port') setForm(p => ({ ...p, port: val }));
                  else if (blockType === 'Application') setForm(p => ({ ...p, application: val }));
                  else setForm(p => ({ ...p, protocol: val }));
                }}
                placeholder={blockType === 'IP Address' ? 'e.g., 192.168.1.100' : blockType === 'Domain' ? 'e.g., evil.com' : blockType === 'Port' ? 'e.g., 22' : blockType === 'Application' ? '/usr/bin/app' : 'e.g., tcp'}
              />
            </label>
            <label>ATTACK TYPE
              <select value={form.attackType} onChange={e => setForm(p => ({ ...p, attackType: e.target.value }))}>
                <option value="">Select attack type</option>
                {ATTACK_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </label>
            <label>BLOCK REASON
              <input value={form.reason} onChange={e => setForm(p => ({ ...p, reason: e.target.value }))} placeholder="e.g., TI verified malicious, active attack…" />
            </label>
            <label>TTL
              <select value={form.ttlHours} onChange={e => setForm(p => ({ ...p, ttlHours: e.target.value }))}>
                {[['1', '1 Hour'], ['6', '6 Hours'], ['12', '12 Hours'], ['24', '24 Hours'], ['72', '3 Days'], ['168', '7 Days']].map(([value, label]) => <option key={value} value={value}>{label}</option>)}
              </select>
            </label>
          </div>
          <div className="ids-add-block-actions">
            <input value={filter} onChange={e => { setFilter(e.target.value); setPage(1); }} placeholder="⌕ Search IP, domain, reason, attack type…" />
            <button type="button" className="danger" onClick={() => { setFilter(''); setPage(1); }}>× Clear</button>
            <button type="button" onClick={load}>↻ Refresh</button>
            {list.length > 0 && <Badge text={`${list.length} blocks`} color="#f5b80b" />}
            <i />
            <button type="button" onClick={() => setShowForm(false)}>Cancel</button>
            <button type="submit" className="apply" disabled={submitting}>{submitting ? 'Blocking…' : '♜ Apply Block'}</button>
          </div>
        </form>
      )}
      {!showForm && <button type="button" onClick={() => setShowForm(true)} style={{ ...C.btn(), marginBottom: 12 }}>＋ Add New Block</button>}

      {pendingRestore && (
        <form className="ids-manual-override ids-restore-override" onSubmit={submitManualRestore}>
          <div className="ids-manual-override-title">
            <strong>Manual Override Authorization Checklist</strong>
            <span>Required before Server Live / Restore: {pendingRestore.label}</span>
          </div>
          <div className="ids-manual-override-toggle">
            <label>
              <input type="checkbox" checked={manualOverride} onChange={e => setManualOverride(e.target.checked)} />
              Manual Override
            </label>
            <span>Admin wants to restore server before the 20 minute recovery process is complete.</span>
          </div>
          {manualOverride && (
            <>
              <div className="ids-manual-section-title">Reason</div>
              <div className="ids-manual-checks">
                {[
                  ['businessCritical', 'Business Critical'],
                  ['productionIssue', 'Production Issue'],
                  ['falsePositive', 'False Positive'],
                  ['testing', 'Testing'],
                  ['emergency', 'Emergency'],
                  ['customerImpact', 'Customer Impact'],
                  ['other', 'Other'],
                ].map(([key, label]) => (
                  <label key={key}>
                    <input type="checkbox" checked={overrideReasons[key]} onChange={e => setOverrideReasons(prev => ({ ...prev, [key]: e.target.checked }))} />
                    {label}
                  </label>
                ))}
              </div>

              <div className="ids-manual-section-title">Risk Acceptance</div>
              <div className="ids-manual-checks">
                <label className="ids-manual-check-all">
                  <input
                    type="checkbox"
                    checked={Object.values(overrideChecks).every(Boolean)}
                    onChange={e => {
                      const checked = e.target.checked;
                      setOverrideChecks(prev => Object.fromEntries(Object.keys(prev).map(key => [key, checked])));
                      setOverrideError('');
                    }}
                  />
                  Select all required acknowledgements
                </label>
                {[
                  ['activeAttack', 'I understand the attack is still active.'],
                  ['acceptSecurityRisks', 'I accept all security risks.'],
                  ['authorizeRestore', 'I authorize restoring this server.'],
                  ['dataLossMayOccur', 'I understand data loss may occur.'],
                  ['ransomwareMaySpread', 'I understand ransomware may spread.'],
                  ['socNotResponsible', 'SOC is not responsible for any damage after manual override.'],
                ].map(([key, label]) => (
                  <label key={key}>
                    <input type="checkbox" checked={overrideChecks[key]} onChange={e => setOverrideChecks(prev => ({ ...prev, [key]: e.target.checked }))} />
                    {label}
                  </label>
                ))}
              </div>

              <div className="ids-manual-section-title">Authorization</div>
              <div className="ids-manual-grid">
                <label>Server Name / Agent
                  <select
                    value={overrideForm.systemId}
                    onChange={e => {
                      const systemId = e.target.value;
                      const agent = agents.find(item => String(item._id) === String(systemId));
                      setOverrideForm(prev => ({
                        ...prev,
                        systemId,
                        company: authorizationContext.company,
                        department: agent?.departmentId?.name || authorizationContext.department || 'Company-wide',
                        serverName: agent?.name || agent?.hostname || '',
                        hostname: agent?.hostname || '',
                        ipAddress: agent?.ip || '',
                      }));
                    }}
                  >
                    <option value="">Choose registered agent</option>
                    {agents.map(agent => (
                      <option key={agent._id} value={agent._id}>
                        {agent.name || agent.hostname || agent.agentId || 'Unnamed Agent'}
                        {agent.hostname && agent.hostname !== agent.name ? ` · ${agent.hostname}` : ''}
                        {agent.ip ? ` · ${agent.ip}` : ''}
                        {agent.isOnline ? ' · Online' : ' · Offline'}
                      </option>
                    ))}
                  </select>
                </label>
                {[
                  ['company', 'Company'],
                  ['department', 'Department'],
                  ['hostname', 'Hostname'],
                  ['ipAddress', 'IP Address'],
                  ['reason', 'Reason'],
                  ['approvedBy', 'Approved By'],
                  ['designation', 'Designation'],
                  ['employeeId', 'Employee ID'],
                  ['digitalSignature', 'Digital Signature'],
                ].map(([field, label]) => (
                  <label key={field} className={field === 'reason' ? 'wide' : ''}>{label}
                    <input
                      value={overrideForm[field]}
                      onChange={e => setOverrideForm(prev => ({ ...prev, [field]: e.target.value }))}
                      placeholder={label}
                      readOnly={field === 'company' || field === 'department'}
                    />
                  </label>
                ))}
                <label>Date<input value={new Date().toLocaleDateString()} readOnly /></label>
                <label>Time<input value={new Date().toLocaleTimeString()} readOnly /></label>
              </div>
              <div className="ids-manual-approval-note">
                Manual Override Approved: Administrator has manually restored the server while the attack is still active. Risk acceptance will be recorded in Audit Log and notification payload.
              </div>
            </>
          )}
          {overrideError && <div className="ids-manual-error">⚠ {overrideError}</div>}
          <div className="ids-add-block-actions">
            <button type="button" onClick={cancelManualOverride} disabled={submitting}>Cancel</button>
            <i />
            <button type="submit" className="apply" disabled={submitting}>
              {submitting ? 'Unblocking…' : 'Approve & Unblock'}
            </button>
          </div>
        </form>
      )}

      {/* 🚨 Block Activity Feed - TABLE */}
      <div className="ids-block-table-card">
        <div className="ids-block-table-head">
          <span><strong>♜ Active Block List (24H)</strong><small>Only the actual blocked target type is shown for each entry</small></span>
          <span className="ids-block-counts">
            <b>24H Blocks: {recent24hBlocks.length}</b>
            <b>Auto-blocked: {autoBlockCount}</b>
            <b>Manual: {manualBlockCount}</b>
          </span>
        </div>

        {loading ? (
          <Empty icon="⏳" msg="Loading blocklist…" />
        ) : (
          <div style={{ overflowX: 'hidden' }}>
            <table className="ids-block-table">
              <colgroup>
                <col className="ids-block-col-type" />
                <col className="ids-block-col-source" />
                <col className="ids-block-col-agent" />
                <col className="ids-block-col-ip" />
                <col className="ids-block-col-attack" />
                <col className="ids-block-col-reason" />
                <col className="ids-block-col-time" />
                <col className="ids-block-col-age" />
                <col className="ids-block-col-action" />
              </colgroup>
              {/* Table Header */}
              <thead>
                <tr style={{ borderBottom: '2px solid #1e3a5f', background: '#060e1a' }}>
                  <th style={{ ...C.th, textAlign: 'center', width: '5%' }}>Type</th>
                  <th style={{ ...C.th, textAlign: 'center', width: '8%' }}>Source</th>
                  <th style={C.th}>Agent</th>
                  <th style={C.th}>Blocked Target</th>
                  <th style={C.th}>Attack Type</th>
                  <th style={C.th}>Reason</th>
                  <th style={C.th}>Time</th>
                  <th style={C.th}>Age</th>
                  <th style={{ ...C.th, textAlign: 'center', width: '8%' }}>Action</th>
                </tr>
              </thead>
              {/* Table Body */}
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td colSpan={9} style={{ textAlign: 'center', padding: '40px 20px', color: '#475569', fontSize: 14 }}>
                      <div style={{ fontSize: 40, marginBottom: 8 }}>🎉</div>
                      {recent24hBlocks.length === 0 ? 'No blocked IPs in the last 24 hours' : 'No results match your filter'}
                    </td>
                  </tr>
                ) : (
                  pagedBlocks.map((b, i) => (
                    <tr key={b.blockKey || i} style={{ borderBottom: '1px solid #0a1628', background: '#0c1a2e' }}>
                      {/* Type */}
                      <td style={{ ...C.td, textAlign: 'center' }}>
                        <Badge text={blockedTarget(b).type.toUpperCase()} color="#8b5cf6" />
                      </td>
                      {/* Source */}
                      <td style={{ ...C.td, textAlign: 'center' }}>
                        <Badge
                          text={isManualBlock(b) ? '👤 Manual' : '🤖 Auto'}
                          color={isManualBlock(b) ? '#f59e0b' : '#34d399'}
                        />
                      </td>
                      {/* Agent */}
                      <td style={C.td}>
                        <span title={b.agentId || b.systemId || ''} style={{ color: '#7dd3fc' }}>
                          {b._agentLabel || blockAgentLabel(b)}
                        </span>
                      </td>
                      {/* Auto-detected blocked target: IP, domain, port, application or protocol */}
                      <td style={C.td}>
                        <code style={{ color: blockedTarget(b).color, fontSize: 11, fontFamily: 'monospace', background: '#0f1f3d', padding: '2px 6px', borderRadius: 4 }}>
                          {blockedTarget(b).value}
                        </code>
                      </td>
                      {/* Attack Type */}
                      <td style={C.td}>
                        {b.attackType ? <Badge text={b.attackType} color="#f59e0b" /> : '—'}
                      </td>
                      {/* Reason */}
                      <td className="ids-block-reason-cell" style={C.td}>
                        {(() => {
                          const reason = b.reason || '';
                          const isTI = /TI auto-block|Threat Intel|AbuseIPDB|OTX|malicious/i.test(reason);
                          const tiMeta = b.tiMeta || b.threatIntelMeta || {};
                          const abuseScore = b.abuseScore ?? b.tiAbuseScore ?? tiMeta.abuseScore ?? null;
                          const otxPulses = b.otxPulses ?? b.tiOtxPulses ?? tiMeta.otxPulses ?? null;
                          const malwareFamilies = b.malwareFamilies ?? b.tiMalwareFamilies ?? tiMeta.malwareFamilies ?? [];
                          const country = b.geoCountry ?? b.country ?? tiMeta.country ?? null;
                          const feedSource = b.feedSource ?? b.tiFeedSource ?? tiMeta.feedSource ?? null;
                          const hasMeta = isTI && (abuseScore !== null || otxPulses !== null || malwareFamilies?.length || country || feedSource);

                          if (hasMeta) {
                            return (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                                <span style={{ color: '#f87171', fontWeight: 700, fontSize: 11 }}>🚨 TI Auto-Block</span>
                                {abuseScore !== null && (
                                  <span style={{ fontSize: 10, color: '#fbbf24' }}>
                                    AbuseIPDB: <b style={{ color: abuseScore >= 80 ? '#ef4444' : abuseScore >= 40 ? '#f97316' : '#eab308' }}>{abuseScore}%</b> confidence
                                  </span>
                                )}
                                {otxPulses !== null && (
                                  <span style={{ fontSize: 10, color: '#a78bfa' }}>OTX Pulses: <b>{otxPulses}</b></span>
                                )}
                                {malwareFamilies?.length > 0 && (
                                  <span style={{ fontSize: 10, color: '#f87171' }}>Families: <b>{malwareFamilies.slice(0, 2).join(', ')}</b></span>
                                )}
                                {country && (
                                  <span style={{ fontSize: 10, color: '#94a3b8' }}>Country: <b>{country}</b></span>
                                )}
                                {feedSource && (
                                  <span style={{ fontSize: 10, color: '#64748b' }}>Feed: {feedSource}</span>
                                )}
                              </div>
                            );
                          }

                          if (isTI) {
                            return (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                                <span style={{ color: '#f87171', fontWeight: 700, fontSize: 11 }}>🚨 TI Auto-Block</span>
                                <span style={{ fontSize: 10, color: '#94a3b8', wordBreak: 'break-word' }}>{reason.replace(/TI auto-block[:\s]*/i, '').trim() || 'Malicious IP detected by Threat Intelligence'}</span>
                              </div>
                            );
                          }

                          return b.reason ? <span className="ids-block-reason-text" title={b.reason}>📝 {b.reason}</span> : '—';
                        })()}
                      </td>
                      {/* Time */}
                      <td className="ids-block-time-cell" style={C.td}>
                        {b.ts ? new Date(b.ts).toLocaleTimeString() : '—'}
                      </td>
                      <td style={{ ...C.td, color: '#9aacbf', fontSize: 10 }}>{blockAgeLabel(b)}</td>
                      {/* Unblock Button */}
                      <td style={{ ...C.td, textAlign: 'center' }}>
                        <button
                          onClick={() => unblock(b)}
                          disabled={submitting}
                          style={{ ...C.btn('success'), padding: '5px 10px', fontSize: '9px', fontWeight: 700, display: 'inline-flex', alignItems: 'center', gap: 4, borderRadius: 5 }}
                        >
                          ♙ Unblock
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        )}
        {!loading && filtered.length > 0 && (
          <div className="ids-block-pagination">
            <span>Showing {(currentPage - 1) * pageSize + 1} to {Math.min(currentPage * pageSize, filtered.length)} of {filtered.length} entries</span>
            <div>
              <button onClick={() => setPage(1)} disabled={currentPage === 1}>«</button>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>‹</button>
              {Array.from({ length: Math.min(3, totalPages) }, (_, i) => i + 1).map(n => <button key={n} className={n === currentPage ? 'active' : ''} onClick={() => setPage(n)}>{n}</button>)}
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>›</button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  THREATS
// ══════════════════════════════════════════════════════════════════════════════
function ThreatsTab({ onTabChange }) {
  const [hours, setHours] = useState(24);
  const [stats, setStats] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [showFullFeed, setShowFullFeed] = useState(false);
  const [viewingAllAttackTypes, setViewingAllAttackTypes] = useState(false);
  const [viewingAllAttackers, setViewingAllAttackers] = useState(false);

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setErr('');
    try {
      const [idsipsThreats, idsipsLogs, idsStats] = await Promise.allSettled([
        api.get(`/idsips/threats?hours=${hours}`),
        api.get(`/idsips/logs?limit=200`),
        api.get(`/ids/stats?recentLimit=100&topLimit=25`),
      ]);
      const idsips = idsipsThreats.status === 'fulfilled' ? idsipsThreats.value.data : {};
      const idsipsLogRows = idsipsLogs.status === 'fulfilled' ? (idsipsLogs.value.data?.logs || []).filter(isIdsIpsThreatEvent) : [];
      const ids = idsStats.status === 'fulfilled' ? idsStats.value.data : {};
      const idsRecent = (ids.recentAlerts || []).filter(isIdsIpsThreatEvent);
      const idsipsAlerts = (idsips.recentAlerts || idsips.recentCritical || []).filter(isIdsIpsThreatEvent);

      const statByType = (idsips.byType || [])
        .map(row => ({ type: row.type || row._id || 'Security Event', count: Number(row.count || 0), level: row.level || row.severity }))
        .filter(row => row.count > 0 && row.type)
        .sort((a, b) => b.count - a.count);
      const statTopIPs = (idsips.topIPs?.length ? idsips.topIPs : (ids.topSrcIps || []))
        .map(row => ({ ip: normalizeThreatIndicator(row.ip || row._id || row.srcip), count: Number(row.count || 0) }))
        .filter(row => row.count > 0 && !isLocalThreatIndicator(row.ip))
        .sort((a, b) => b.count - a.count);
      const liveAttacks = [
        ...idsipsAlerts,
      ].map((item, index) => {
        const sourceIp = item.srcIp || item.sourceIp || item.srcip || item.ip || item.target;
        const externalIp = !isLocalThreatIndicator(sourceIp) ? sourceIp : item.destip;
        return {
          ...item,
          id: item.id || item._id || `live-threat-${index}`,
          ts: liveEventTime(item),
          threatLevel: normalizeLiveSeverity(item.threatLevel || item.severity || item.level),
          srcIp: externalIp,
          attackType: item.attackType || item.type || item.ruleId || item.eventCategory || item.source || 'Security Event',
          indicator: item.domain || externalIp || 'unknown',
          indicatorType: item.domain ? 'Domain' : 'IP Address',
          feedSource: idsIpsSourceLabel(item),
          country: item.geoCountry || item.country || item.destGeoCountry || '',
          description: liveEventMessage(item),
        };
      }).filter((item) => {
        if (isUnknownThreatIndicator(item.indicator) && isUnknownThreatIndicator(item.srcIp)) return false;
        return isIdsIpsThreatEvent(item);
      }).reduce((rows, item) => {
        const key = [
          item.id,
          item.ts,
          item.attackType,
          item.indicator,
          item.description,
        ].filter(Boolean).join('|');
        if (!rows.seen.has(key)) {
          rows.seen.add(key);
          rows.items.push(item);
        }
        return rows;
      }, { seen: new Set(), items: [] }).items.sort((a, b) => new Date(b.ts || 0) - new Date(a.ts || 0));

      const liveLevelCounts = liveAttacks.reduce((acc, item) => {
        const sev = normalizeLiveSeverity(item.threatLevel || item.severity || item.level);
        acc[sev] = (acc[sev] || 0) + 1;
        return acc;
      }, { critical: 0, high: 0, medium: 0, low: 0 });
      const primaryLevels = idsips.byLevel || {};
      const statsLevelCounts = {
        low: Number(primaryLevels.low || 0),
        medium: Number(primaryLevels.medium || 0),
        high: Number(primaryLevels.high || 0),
        critical: Number(primaryLevels.critical || 0),
      };
      const liveTotal = Object.values(liveLevelCounts).reduce((sum, value) => sum + Number(value || 0), 0);
      const statsTotal = Object.values(statsLevelCounts).reduce((sum, value) => sum + Number(value || 0), 0);
      const byTypeTotal = statByType.reduce((sum, row) => sum + Number(row.count || 0), 0);
      const primaryTotal = Number(statsTotal || byTypeTotal || liveTotal || 0);
      setStats({
        total: primaryTotal,
        byLevel: statsTotal ? statsLevelCounts : liveLevelCounts,
        byType: statByType,
        topIPs: statTopIPs,
      });
      setAttacks(liveAttacks);
      const errors = [idsipsThreats, idsipsLogs, idsStats].filter(r => r.status === 'rejected');
      setErr(errors.length === 3 ? 'Unable to load IDS/IPS threat sources' : '');
    } catch (e) { setErr(e.message); }
    finally { if (!silent) setLoading(false); }
  }, [hours]);

  useEffect(() => { load(false); }, [load]);
  useEffect(() => {
    const timer = setInterval(() => load(true), 60000);
    return () => clearInterval(timer);
  }, [load]);

  const LC = { critical: '#a855f7', high: '#ef4444', medium: '#f59e0b', low: '#22c55e' };
  const byLevel = stats?.byLevel || {};
  const byType = stats?.byType || [];
  const topIPs = stats?.topIPs || [];
  const total = stats?.total || Object.values(byLevel).reduce((sum, value) => sum + Number(value || 0), 0);
  const levelCards = [
    { key: 'low', label: 'Low Threats', icon: '⌁', color: '#22c55e' },
    { key: 'medium', label: 'Medium Threats', icon: '⚠', color: '#f59e0b' },
    { key: 'high', label: 'High Threats', icon: '♜', color: '#ef4444' },
    { key: 'critical', label: 'Critical Threats', icon: '☣', color: '#a855f7' },
  ];
  const rangeLabels = { 1: '1H', 6: '6H', 24: '1D', 48: '2D', 168: '7D', 720: '30D' };
  const liveTypeRows = [...attacks.reduce((map, item) => {
    const type = item.attackType || item.type || item.ruleId || 'Security Event';
    const prev = map.get(type) || { type, count: 0, level: item.threatLevel };
    prev.count += 1;
    if (!prev.level || ['critical', 'high'].includes(item.threatLevel)) prev.level = item.threatLevel;
    map.set(type, prev);
    return map;
  }, new Map()).values()].sort((a, b) => b.count - a.count);
  const typeRows = byType.length ? byType.slice(0, 6) : liveTypeRows.slice(0, 6);
  const maxType = Math.max(1, ...typeRows.map(t => t.count || 0));
  const typeTotal = Math.max(1, typeRows.reduce((sum, row) => sum + Number(row.count || 0), 0));
  const liveAttackerRows = [...attacks.reduce((map, item) => {
    const ip = item.srcIp || item.sourceIp || item.srcip || item.ip;
    if (isLocalThreatIndicator(ip)) return map;
    const prev = map.get(ip) || { ip, count: 0 };
    prev.count += 1;
    map.set(ip, prev);
    return map;
  }, new Map()).values()].sort((a, b) => b.count - a.count);
  const attackerRows = topIPs.length ? topIPs.slice(0, 9) : liveAttackerRows.slice(0, 9);
  const maxAttacker = Math.max(1, ...attackerRows.map(ip => ip.count || 0));
  const totalByLevels = Math.max(1, levelCards.reduce((sum, level) => sum + (byLevel[level.key] || 0), 0));
  const fullFeedRows = attacks.filter(item => !isUnknownThreatIndicator(item.indicator || item.srcIp || item.sourceIp || item.domain));
  const feedRows = fullFeedRows.slice(0, 6);
  const formatTime = (ts) => ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
  const sourceFor = (item) => item.feedSource || idsIpsSourceLabel(item);
  const descriptionFor = (a) => {
    return a.description || liveEventMessage(a);
  };
  const exportReport = () => {
    const rows = [['time', 'severity', 'indicator', 'type', 'source', 'description']]
      .concat((showFullFeed ? fullFeedRows : feedRows).map((a) => [
        formatTime(a.ts),
        a.threatLevel || 'low',
        a.indicator || a.srcIp || a.sourceIp || a.domain || 'unknown',
        a.indicatorType || (a.domain ? 'Domain' : 'IP Address'),
        sourceFor(a),
        descriptionFor(a),
      ]));
    const csv = rows.map(row => row.map(cell => `"${String(cell).replaceAll('"', '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `ids-threats-${hours}h.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const renderFeedTable = (rows) => (
    <div className="ids-threat-table-wrap">
      <table className="ids-threat-feed-table">
        <thead><tr>{['Time', 'Severity', 'Indicator', 'Type', 'Country', 'Source', 'Description', 'Action'].map(h => <th key={h}>{h}</th>)}</tr></thead>
        <tbody>
          {rows.map((a, i) => {
            const severity = (a.threatLevel || 'low').toLowerCase();
            const indicator = a.indicator || a.srcIp || a.sourceIp || a.domain || a.attackType || 'unknown';
            return (
              <tr key={`${a.id || a._id || indicator}-${a.ts || i}-${i}`}>
                <td>{formatTime(a.ts)}</td>
                <td><span className={`ids-threat-pill ${severity}`}>{severity}</span></td>
                <td>{indicator}</td>
                <td>{a.indicatorType || (a.domain ? 'Domain' : 'IP Address')}</td>
                <td><span className="ids-country">{a.country || '—'}</span></td>
                <td><span className="ids-source-dot">◉</span>{sourceFor(a)}</td>
                <td>{descriptionFor(a)}</td>
                <td><button onClick={() => {
                  sessionStorage.setItem('ips:block-prefill', JSON.stringify({
                    type: a.domain ? 'domain' : 'ip', value: indicator,
                  }));
                  onTabChange?.('blocklist');
                }}>Block</button><span className="ids-more">⋮</span></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );

  if (viewingAllAttackTypes) {
    const allTypeRows = byType.length ? byType : liveTypeRows;
    const maxAllType = Math.max(1, ...allTypeRows.map(t => t.count || 0));
    const allTypeTotal = Math.max(1, allTypeRows.reduce((sum, row) => sum + Number(row.count || 0), 0));

    return (
      <div className="ids-threats">
        <section className="ids-threat-full-page">
          <div className="ids-threat-full-head">
            <div>
              <button className="ids-threat-back" onClick={() => setViewingAllAttackTypes(false)}>← Back</button>
              <h2>All Detected Attack Types</h2>
              <p>Breakdown of all signature classes and attack types detected in the selected {rangeLabels[hours] || `${hours}H`} range.</p>
            </div>
            <div className="ids-threat-full-actions">
              <button onClick={() => setViewingAllAttackTypes(false)}>Close</button>
            </div>
          </div>

          <div style={{ padding: '24px 20px' }}>
            <div className="ids-attack-type-list" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {allTypeRows.map((t, i) => {
                const count = t.count || 0;
                const pct = (count / allTypeTotal) * 100;
                const color = LC[(t.level || '').toLowerCase()] || '#22c55e';
                return (
                  <div key={`${t.type}-${i}`} style={{
                    background: '#091827',
                    border: '1px solid #142f4c',
                    borderRadius: '8px',
                    padding: '16px 20px',
                    display: 'grid',
                    gridTemplateColumns: '1.5fr 3fr 1fr 1fr',
                    alignItems: 'center',
                    gap: '20px'
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <span style={{
                        width: '10px',
                        height: '10px',
                        borderRadius: '50%',
                        background: color,
                        display: 'inline-block'
                      }} />
                      <strong style={{ color: '#e2edfa', fontSize: '13px' }}>{t.type || 'Security Event'}</strong>
                    </div>

                    <div style={{ background: '#07121e', borderRadius: '4px', height: '10px', overflow: 'hidden', width: '100%' }}>
                      <div style={{
                        background: `linear-gradient(90deg, ${color}dd, ${color})`,
                        width: `${Math.min(100, count / maxAllType * 100)}%`,
                        height: '100%',
                        borderRadius: '4px',
                        transition: 'width 0.4s ease'
                      }} />
                    </div>

                    <div style={{ color: '#fff', fontWeight: 'bold', fontSize: '14px', textAlign: 'right' }}>
                      {count} <span style={{ fontSize: '10px', color: '#748ca6', fontWeight: 'normal' }}>alerts</span>
                    </div>

                    <div style={{ color: color, fontWeight: '600', fontSize: '13px', textAlign: 'right' }}>
                      {pct.toFixed(1)}%
                    </div>
                  </div>
                );
              })}

              {!allTypeRows.length && (
                <Empty icon="🛡" msg="No attack types recorded in this time range." />
              )}
            </div>
          </div>
        </section>
      </div>
    );
  }

  if (viewingAllAttackers) {
    const allAttackerRows = topIPs.length ? topIPs : liveAttackerRows;
    const maxAllAttacker = Math.max(1, ...allAttackerRows.map(item => item.count || 0));
    return (
      <div className="ids-threats">
        <section className="ids-threat-full-page">
          <div className="ids-threat-full-head">
            <div>
              <button className="ids-threat-back" onClick={() => setViewingAllAttackers(false)}>← Back</button>
              <h2>All Attackers</h2>
              <p>Source IPs observed in the selected {rangeLabels[hours] || `${hours}H`} range.</p>
            </div>
            <div className="ids-threat-full-actions"><button onClick={() => setViewingAllAttackers(false)}>Close</button></div>
          </div>
          <div style={{ padding: '24px 20px' }} className="ids-attacker-table">
            <div className="head"><span>Rank</span><span>IP Address</span><span>Threats</span><span></span><span>Action</span></div>
            {allAttackerRows.map((item, index) => (
              <div className="row" key={`${item.ip}-${index}`}>
                <span className="rank">{index + 1}</span><code>{item.ip}</code><strong>{item.count || 0}</strong>
                <em><b style={{ width: `${Math.min(100, Number(item.count || 0) / maxAllAttacker * 100)}%` }} /></em>
                <button onClick={() => { sessionStorage.setItem('ips:block-prefill', JSON.stringify({ type: 'ip', value: item.ip })); setViewingAllAttackers(false); onTabChange?.('blocklist'); }}>Block</button>
              </div>
            ))}
            {!allAttackerRows.length && <Empty icon="🛡" msg="No attacker source IPs in this time range." />}
          </div>
        </section>
      </div>
    );
  }

  if (showFullFeed) {
    return (
      <div className={`ids-threats ${loading ? 'is-loading' : ''}`}>
        <section className="ids-threat-full-page">
          <div className="ids-threat-full-head">
            <div>
              <button className="ids-threat-back" onClick={() => setShowFullFeed(false)}>← Back</button>
              <h2>IDS/IPS Threat Feed</h2>
              <p>Latest IDS and IPS threat indicators for the selected {rangeLabels[hours] || `${hours}H`} range.</p>
            </div>
            <div className="ids-threat-full-actions">
              <button onClick={() => load(false)}>↻ Refresh</button>
              <button onClick={exportReport} disabled={!fullFeedRows.length}>⇩ Export</button>
              <button onClick={() => setShowFullFeed(false)}>Close</button>
            </div>
          </div>

          <div className="ids-threat-ranges ids-threat-full-ranges">
            {[1, 6, 24, 48, 168, 720].map(h => (
              <button key={h} onClick={() => setHours(h)} className={hours === h ? 'active' : ''}>
                {rangeLabels[h]}
              </button>
            ))}
          </div>

          <div className="ids-threat-full-stats">
            <div><label>Total Feed</label><strong>{fullFeedRows.length}</strong></div>
            <div><label>Critical</label><strong>{byLevel.critical || 0}</strong></div>
            <div><label>High</label><strong>{byLevel.high || 0}</strong></div>
            <div><label>Medium</label><strong>{byLevel.medium || 0}</strong></div>
            <div><label>Low</label><strong>{byLevel.low || 0}</strong></div>
          </div>

          {loading ? <Empty icon="⏳" msg="Loading full threat feed…" /> : err ? (
            <div style={{ color: '#f87171', fontSize: 13 }}>❌ {err}</div>
          ) : fullFeedRows.length === 0 ? (
            <Empty icon="✅" msg={`No IDS/IPS threat feed events in the last ${hours}h`} />
          ) : renderFeedTable(fullFeedRows)}
        </section>
      </div>
    );
  }

  return (
    <div className={`ids-threats ${loading ? 'is-loading' : ''}`}>
      <div className="ids-threat-toolbar">
        <div className="ids-threat-ranges">
          {[1, 6, 24, 48, 168, 720].map(h => (
            <button key={h} onClick={() => setHours(h)} className={hours === h ? 'active' : ''}>
              {rangeLabels[h]}
            </button>
          ))}
          <button onClick={load} title="Refresh threats">▣</button>
        </div>
        <button className="ids-threat-export" onClick={exportReport} disabled={!feedRows.length}>⇩ Export Report</button>
      </div>

      {loading ? <Empty icon="⏳" msg="Loading threat data…" /> : err ? (
        <div style={{ color: '#f87171', fontSize: 13 }}>❌ {err} — Is IPS server at port 5050 running?</div>
      ) : (
        <>
          <div className="ids-threat-kpis">
            {levelCards.map(level => {
              const count = byLevel[level.key] || 0;
              const pct = total ? count / total * 100 : 0;
              return (
                <div className="ids-threat-kpi" key={level.key}>
                  <span className="ids-threat-kpi-icon" style={{ background: `${level.color}22`, color: level.color, boxShadow: `0 0 22px ${level.color}33` }}>{level.icon}</span>
                  <div>
                    <label>{level.label}</label>
                    <strong>{count}</strong>
                    <small style={{ color: level.color }}>{pct.toFixed(1)}% <em>of total</em></small>
                  </div>
                  <Sparkline color={level.color} />
                </div>
              );
            })}
            <div className="ids-threat-kpi total">
              <span className="ids-threat-kpi-icon">⌘</span>
              <div>
                <label>Total Threats</label>
                <strong>{total}</strong>
                <small className="up">↑ 12.6% <em>vs last 7 days</em></small>
              </div>
              <Sparkline color="#60a5fa" />
            </div>
          </div>

          <div className="ids-threat-grid">
            <section className="ids-threat-card ids-attack-types">
              <div className="ids-threat-card-title"><span>🎯</span><div><strong>Top Attack Types</strong><small>Breakdown of attack types detected</small></div></div>
              <div className="ids-attack-type-body">
                <div className="ids-threat-donut" style={{ '--total': `"${total}"`, background: `radial-gradient(circle,#0b1b2e 55%,transparent 57%),conic-gradient(#22c55e 0 ${(byLevel.low || 0) / totalByLevels * 100}%,#f59e0b ${(byLevel.low || 0) / totalByLevels * 100}% ${((byLevel.low || 0) + (byLevel.medium || 0)) / totalByLevels * 100}%,#ef4444 ${((byLevel.low || 0) + (byLevel.medium || 0)) / totalByLevels * 100}% ${((byLevel.low || 0) + (byLevel.medium || 0) + (byLevel.high || 0)) / totalByLevels * 100}%,#a855f7 ${((byLevel.low || 0) + (byLevel.medium || 0) + (byLevel.high || 0)) / totalByLevels * 100}% 100%)` }}>
                  <span>TOTAL</span>
                </div>
                <div className="ids-attack-type-table">
                  <div className="head"><span>Attack Type</span><span>Count</span><span>Percentage</span></div>
                  {typeRows.map((t, i) => {
                    const count = t.count || 0;
                    const pct = count / typeTotal * 100;
                    return (
                      <div className="row" key={`${t.type || 'unknown'}-${i}`}>
                        <span><i style={{ background: LC[(t.level || '').toLowerCase()] || '#22c55e' }} />{t.type || 'Unknown'}</span>
                        <em><b style={{ width: `${Math.min(100, count / maxType * 100)}%` }} /></em>
                        <strong>{count}</strong>
                        <small>{pct.toFixed(1)}%</small>
                      </div>
                    );
                  })}
                  {!typeRows.length && <div className="row"><span>No live attack types</span><em><b style={{ width: '0%' }} /></em><strong>0</strong><small>0.0%</small></div>}
                </div>
              </div>
              <button className="ids-threat-footer-btn" onClick={() => setViewingAllAttackTypes(true)}>View All Attack Types <span>›</span></button>
            </section>

            <section className="ids-threat-card ids-top-attackers">
              <div className="ids-threat-card-title"><span>🌐</span><div><strong>Top Attackers</strong><small>Top source IPs generating threats</small></div></div>
              <div className="ids-attacker-table">
                <div className="head"><span>Rank</span><span>IP Address</span><span>Threats</span><span></span><span>Trend</span></div>
                {attackerRows.map((ip, i) => (
                  <div className="row" key={`${ip.ip || 'unknown'}-${i}`}>
                    <span className="rank">{i + 1}</span>
                    <code>{ip.ip || 'unknown'}</code>
                    <strong>{ip.count || 0}</strong>
                    <em><b style={{ width: `${Math.min(100, (ip.count || 0) / maxAttacker * 100)}%` }} /></em>
                    <Sparkline color="#ef4444" />
                  </div>
                ))}
                {!attackerRows.length && <div className="row"><span className="rank">—</span><code>No live attacker IPs</code><strong>0</strong><em><b style={{ width: '0%' }} /></em><Sparkline color="#64748b" /></div>}
              </div>
              <button className="ids-threat-footer-btn" onClick={() => setViewingAllAttackers(true)}>View All Attackers <span>›</span></button>
            </section>
          </div>

          <section className="ids-threat-card ids-threat-feed-card">
            <div className="ids-threat-card-title"><span>🛡️</span><div><strong>IDS/IPS Threat Feed</strong><small>Latest IDS and IPS threat indicators</small></div></div>
            {feedRows.length === 0 ? (
              <Empty icon="✅" msg={`No threats detected in the last ${hours}h`} />
            ) : (
              <div>
                {renderFeedTable(feedRows)}
                <button className="ids-threat-footer-btn feed" onClick={() => setShowFullFeed(true)}>View Full Threat Feed <span>›</span></button>
              </div>
            )}
          </section>
        </>
      )}
    </div>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
//  COVERAGE
// ══════════════════════════════════════════════════════════════════════════════
function CoverageTab() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');

  const load = useCallback(async () => {
    setLoading(true); setErr('');
    try {
      const { data: payload } = await api.get('/idsips/capabilities');
      setData(payload);
    } catch (e) {
      setErr(e.message || 'Unable to load IDS/IPS coverage');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const groups = data?.groups || [];
  const totals = data?.totals || {};

  return (
    <div className="ids-tab-page">
      <section className="ids-coverage-hero">
        <div>
          <h2>IDS/IPS Monitoring Coverage</h2>
          <p>Real logs and dashboard counts stay filtered to IDS/IPS only. This page shows what the agent, IDS sensors, IPS server, and threat-intel gate are configured to monitor.</p>
        </div>
        <button onClick={load}>↻ Refresh</button>
      </section>

      {err && <div className="ids-error">{err}</div>}
      {loading ? <Empty icon="⏳" msg="Loading IDS/IPS coverage..." /> : (
        <>
          <div className="ids-coverage-stats">
            <div><label>Groups</label><strong>{totals.groups || groups.length}</strong></div>
            <div><label>Capabilities</label><strong>{totals.capabilities || 0}</strong></div>
            <div><label>Attack Types</label><strong>{totals.attackTypes || data?.attackTypes?.length || 0}</strong></div>
            <div><label>Mode</label><strong>Real Data Only</strong></div>
          </div>

          <div className="ids-coverage-grid">
            {groups.map(group => (
              <article className="ids-coverage-card" key={group.id}>
                <div className="ids-coverage-head">
                  <strong>{group.title}</strong>
                  <span>{group.capabilities?.length || 0}</span>
                </div>
                <small>{group.sensor}</small>
                <div className="ids-coverage-tags">
                  {(group.capabilities || []).map(item => <b key={item}>{item}</b>)}
                </div>
              </article>
            ))}
          </div>

          <section className="ids-coverage-note">
            {(data?.notes || []).map(note => <p key={note}>{note}</p>)}
          </section>
        </>
      )}
    </div>
  );
}


// ══════════════════════════════════════════════════════════════════════════════
//  LOGS
// ══════════════════════════════════════════════════════════════════════════════
function LogsTab({ onTabChange, initLevel, companyId }) {
  const LOG_WINDOW_HOURS = 24;
  const [logs, setLogs] = useState([]);
  const [dbTotal, setDbTotal] = useState(0);
  const [filteredTotal, setFilteredTotal] = useState(0);
  const [dbCounts, setDbCounts] = useState({ low: 0, medium: 0, high: 0, critical: 0 });
  const [dbAgents, setDbAgents] = useState(['ALL']);
  const [level, setLevel] = useState(initLevel && initLevel !== 'ALL' ? initLevel : 'ALL');
  const [loading, setLoading] = useState(true);
  const [err, setErr] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [search, setSearch] = useState('');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [agentFilter, setAgentFilter] = useState('ALL');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [pageSize, setPageSize] = useState(50);
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const [viewingLogDetail, setViewingLogDetail] = useState(null);
  const [aiBusy, setAiBusy] = useState(null);
  const [aiMessage, setAiMessage] = useState('');
  const [enrichedData, setEnrichedData] = useState({ src: null, dest: null });
  const [activeIpTab, setActiveIpTab] = useState('src');
  const [ipinfoActiveSection, setIpinfoActiveSection] = useState('summary');
  const loadSequenceRef = useRef(0);

  useEffect(() => {
    if (!viewingLogDetail) {
      setEnrichedData({ src: null, dest: null });
      return;
    }

    const isPrivateIp = (ip) => {
      if (!ip || ip === '—') return true;
      const parts = ip.split('.');
      if (parts.length === 4) {
        const a = parseInt(parts[0], 10);
        const b = parseInt(parts[1], 10);
        if (a === 10) return true;
        if (a === 127) return true;
        if (a === 172 && (b >= 16 && b <= 31)) return true;
        if (a === 192 && b === 168) return true;
        if (a === 169 && b === 254) return true;
      }
      return false;
    };

    const srcIsPrivate = isPrivateIp(viewingLogDetail.srcIp);
    setActiveIpTab(srcIsPrivate ? 'dest' : 'src');
    setIpinfoActiveSection('summary');

    const fetchEnrichment = async () => {
      const src = viewingLogDetail.srcIp;
      const dest = viewingLogDetail.destIp;

      const payload = { src: null, dest: null };

      if (!isPrivateIp(src)) {
        if (viewingLogDetail.raw.asn || viewingLogDetail.raw.asnOrg) {
          payload.src = {
            asn: viewingLogDetail.raw.asn,
            organization: viewingLogDetail.raw.asnOrg,
            domain: viewingLogDetail.raw.asnDomain,
            country: viewingLogDetail.raw.geoCountry,
            countryCode: viewingLogDetail.raw.geoCountryCode,
            continent: viewingLogDetail.raw.geoContinent,
            city: viewingLogDetail.raw.geoCity,
            region: viewingLogDetail.raw.geoRegion,
            postal: viewingLogDetail.raw.geoPostal,
            timezone: viewingLogDetail.raw.geoTimezone,
            loc: viewingLogDetail.raw.geoLoc,
            privacy: {
              proxy: viewingLogDetail.raw.geoProxy || false,
              hosting: viewingLogDetail.raw.geoHosting || false,
              vpn: viewingLogDetail.raw.geoVpn || false,
              tor: viewingLogDetail.raw.geoTor || false,
              relay: viewingLogDetail.raw.geoRelay || false
            },
            anycast: viewingLogDetail.raw.geoAnycast || false,
            hostname: viewingLogDetail.raw.geoHostname || '',
            abuse: {
              email: viewingLogDetail.raw.geoAbuseEmail || '',
              phone: viewingLogDetail.raw.geoAbusePhone || '',
              address: viewingLogDetail.raw.geoAbuseAddress || '',
              network: viewingLogDetail.raw.geoAbuseNetwork || ''
            },
            domainsCount: viewingLogDetail.raw.geoDomainsCount || 0,
            asnRoute: viewingLogDetail.raw.geoAsnRoute || ''
          };
        }
      } else {
        payload.src = 'private';
      }

      if (!isPrivateIp(dest)) {
        if (viewingLogDetail.raw.destAsn || viewingLogDetail.raw.destAsnOrg) {
          payload.dest = {
            asn: viewingLogDetail.raw.destAsn,
            organization: viewingLogDetail.raw.destAsnOrg,
            domain: viewingLogDetail.raw.destAsnDomain,
            country: viewingLogDetail.raw.destGeoCountry,
            countryCode: viewingLogDetail.raw.destGeoCountryCode,
            continent: viewingLogDetail.raw.destGeoContinent,
            city: viewingLogDetail.raw.destGeoCity,
            region: viewingLogDetail.raw.destGeoRegion,
            postal: viewingLogDetail.raw.destGeoPostal,
            timezone: viewingLogDetail.raw.destGeoTimezone,
            loc: viewingLogDetail.raw.destGeoLoc,
            privacy: {
              proxy: viewingLogDetail.raw.destGeoProxy || false,
              hosting: viewingLogDetail.raw.destGeoHosting || false,
              vpn: viewingLogDetail.raw.destGeoVpn || false,
              tor: viewingLogDetail.raw.destGeoTor || false,
              relay: viewingLogDetail.raw.destGeoRelay || false
            },
            anycast: viewingLogDetail.raw.destGeoAnycast || false,
            hostname: viewingLogDetail.raw.destGeoHostname || '',
            abuse: {
              email: viewingLogDetail.raw.destGeoAbuseEmail || '',
              phone: viewingLogDetail.raw.destGeoAbusePhone || '',
              address: viewingLogDetail.raw.destGeoAbuseAddress || '',
              network: viewingLogDetail.raw.destGeoAbuseNetwork || ''
            },
            domainsCount: viewingLogDetail.raw.destGeoDomainsCount || 0,
            asnRoute: viewingLogDetail.raw.destGeoAsnRoute || ''
          };
        }
      } else {
        payload.dest = 'private';
      }

      setEnrichedData({ ...payload });

      const srcNeedsEnrichment = payload.src === null || (typeof payload.src === 'object' && !payload.src.countrySource);
      const destNeedsEnrichment = payload.dest === null || (typeof payload.dest === 'object' && !payload.dest.countrySource);

      if (srcNeedsEnrichment && src && src !== '—') {
        try {
          const res = await api.get(`/ip/${src}`);
          if (res.data && res.data.success) {
            payload.src = res.data.data;
            setEnrichedData(prev => ({ ...prev, src: res.data.data }));
          }
        } catch (e) {
          console.warn('[Frontend] Failed to enrich source IP:', e.message);
        }
      }

      if (destNeedsEnrichment && dest && dest !== '—') {
        try {
          const res = await api.get(`/ip/${dest}`);
          if (res.data && res.data.success) {
            payload.dest = res.data.data;
            setEnrichedData(prev => ({ ...prev, dest: res.data.data }));
          }
        } catch (e) {
          console.warn('[Frontend] Failed to enrich dest IP:', e.message);
        }
      }
    };

    fetchEnrichment();
  }, [viewingLogDetail]);

  useEffect(() => {
    const timer = setTimeout(() => {
      setSearch(searchInput);
      setPage(1);
    }, 400);
    return () => clearTimeout(timer);
  }, [searchInput]);

  const load = useCallback(async (quiet = false) => {
    const requestSequence = ++loadSequenceRef.current;
    if (!quiet) setLoading(true);
    setErr('');
    try {
      const params = new URLSearchParams({
        page,
        limit: pageSize,
        // IDS Logs must contain detections/actions, not network heartbeat or
        // summary envelopes. Network telemetry has its own Capability 3 UI.
        includeTelemetry: 'false',
        range: '24h',
        severity: level === 'ALL' ? 'all' : level.toLowerCase(),
      });
      if (search) params.append('search', search);
      if (sourceFilter !== 'ALL') params.append('sourceType', sourceFilter);
      if (agentFilter !== 'ALL') params.append('agent', agentFilter);

      const countParams = new URLSearchParams(params);
      params.set('skipCount', 'true');
      countParams.set('countOnly', 'true');
      countParams.delete('page');
      countParams.delete('limit');

      // The 24-hour count is intentionally separate so count aggregation never
      // delays fresh rows appearing in the live table.
      api.get(`/idsips/logs?${countParams.toString()}`).then(({ data: resData }) => {
        if (requestSequence !== loadSequenceRef.current) return;
        setDbTotal(resData?.overallTotal ?? resData?.total ?? 0);
        setFilteredTotal(resData?.total || 0);
        if (resData?.severityCounts) setDbCounts(resData.severityCounts);
        if (resData?.agents) setDbAgents(['ALL', ...resData.agents]);
      }).catch(() => { /* Keep the last known count while rows remain live. */ });

      const idsipsLogs = await api.get(`/idsips/logs?${params.toString()}`);
      if (requestSequence !== loadSequenceRef.current) return;
      const merged = [
        ...((idsipsLogs.data?.logs || []).map(item => ({ ...item, liveSource: 'IDS/IPS Alerts' }))),
      ].sort((a, b) => new Date(liveEventTime(b) || 0) - new Date(liveEventTime(a) || 0));
      if (idsipsLogs.data?.agents?.length) setDbAgents(['ALL', ...idsipsLogs.data.agents]);
      setLogs(merged);
      setSelected(merged[0] || null);
      setErr('');
    } catch (e) {
      if (requestSequence === loadSequenceRef.current) setErr(e.message || 'Unable to load IDS/IPS logs');
    } finally {
      if (requestSequence === loadSequenceRef.current) setLoading(false);
    }
  }, [level, page, pageSize, search, sourceFilter, agentFilter]);

  const analyseWithAi = async (row) => {
    setAiBusy(row.id);
    setAiMessage('');
    try {
      const { data } = await api.post(`/ai/alerts/${row.id}/analyze`);
      const jobId = data?.job?._id;
      setViewingLogDetail(current => current?.id === row.id
        ? { ...current, aiInvestigation: { ...current.aiInvestigation, status: 'queued' } }
        : current);
      setAiMessage('AI investigation queued. Result will appear automatically.');
      if (!jobId) {
        return;
      }

      // The detail view is a snapshot, so refreshing the table alone does not
      // update it. Poll the returned job and apply its result directly.
      for (let attempt = 0; attempt < 80; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        const { data: job } = await api.get(`/ai/jobs/${jobId}`);
        if (job.status === 'completed') {
          const output = job.output || {};
          setViewingLogDetail(current => current?.id === row.id
            ? {
                ...current,
                aiInvestigation: {
                  status: 'completed',
                  jobId,
                  summary: output.summary || '',
                  rootCause: output.rootCause || '',
                  confidence: job.confidence ?? output.confidence ?? 0,
                  reasoning: output.reasoning || '',
                  recommendedSteps: output.recommendedInvestigationSteps || [],
                },
              }
            : current);
          setLogs(current => current.map(item => item.id === row.id
            ? {
                ...item,
                aiInvestigation: {
                  status: 'completed',
                  jobId,
                  summary: output.summary || '',
                  rootCause: output.rootCause || '',
                  confidence: job.confidence ?? output.confidence ?? 0,
                  reasoning: output.reasoning || '',
                  recommendedSteps: output.recommendedInvestigationSteps || [],
                },
              }
            : item));
          setAiMessage('AI investigation completed.');
          return;
        }
        if (job.status === 'failed') {
          setViewingLogDetail(current => current?.id === row.id
            ? { ...current, aiInvestigation: { ...current.aiInvestigation, status: 'failed' } }
            : current);
          setAiMessage(job.error || 'AI analysis failed');
          return;
        }
        setViewingLogDetail(current => current?.id === row.id
          ? { ...current, aiInvestigation: { ...current.aiInvestigation, status: job.status || 'processing' } }
          : current);
      }
      setAiMessage('AI analysis is still processing. The result will refresh automatically.');
    } catch (error) {
      setAiMessage(error.response?.data?.message || error.message || 'AI analysis failed');
    } finally {
      setAiBusy(null);
    }
  };

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!companyId || !autoRefresh || page !== 1 || viewingLogDetail) return undefined;

    const socket = io(SOCKET_URL, socketOptions);
    const joinCompany = () => socket.emit('join:company', companyId);
    let refreshTimer = null;
    const refreshLatestRows = () => {
      window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(() => load(true), 900);
    };

    socket.on('connect', joinCompany);
    socket.on('alert:new', refreshLatestRows);
    socket.on('alert:updated', refreshLatestRows);
    socket.on('ips:block', refreshLatestRows);
    joinCompany();
    const disconnectSocket = connectSocket(socket);

    return () => {
      window.clearTimeout(refreshTimer);
      socket.off('connect', joinCompany);
      socket.off('alert:new', refreshLatestRows);
      socket.off('alert:updated', refreshLatestRows);
      socket.off('ips:block', refreshLatestRows);
      disconnectSocket();
    };
  }, [companyId, autoRefresh, page, viewingLogDetail, load]);
  useEffect(() => {
    // Keep the open detail/AI investigation stable. Normal list auto-refresh
    // resumes as soon as the user returns to the table.
    if (!autoRefresh || viewingLogDetail) return undefined;
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, [autoRefresh, load, viewingLogDetail]);

  const parseLog = (log, index = 0) => {
    const msg = log.message || log.msg || JSON.stringify(log);
    const ts = liveEventTime(log);
    const agent = log.agent || log.agentName || log.hostname || log.sensor || msg.match(/agent=([^\s]+)/)?.[1] || msg.match(/agentId=([^\s]+)/)?.[1] || '—';
    const srcIp = log.srcIp || log.sourceIp || log.srcip || log.ip || msg.match(/src(?:ip)?=([^\s]+)/i)?.[1] || '—';
    const destIp = log.destIp || log.destinationIp || log.destip || msg.match(/dest(?:ip)?=([^\s]+)/i)?.[1] || '—';
    const severity = normalizeLiveSeverity(log.severity || log.threatLevel || log.level);
    const source = /ips/i.test(`${log.module || ''} ${log.source_type || ''} ${log.event_category || ''} ${log.source || ''} ${log.type || ''}`) || log.blocked ? 'IPS' : 'IDS';
    const action = log.action || log.actionTaken || (log.blocked ? 'Blocked' : 'Detected');
    const status = log.status || log.containmentStatus || (log.blocked ? 'blocked' : 'open');
    return {
      id: log.id || log._id || `log_${ts ? new Date(ts).toISOString().replace(/\D/g, '').slice(0, 14) : 'entry'}_${index + 1}`,
      time: ts ? new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—',
      date: ts ? new Date(ts).toLocaleDateString([], { month: 'short', day: '2-digit' }) : '—',
      level: severity.toUpperCase(),
      source,
      agent,
      srcIp,
      destIp,
      srcPort: log.srcPort ?? log.sourcePort ?? log.src_port ?? '—',
      destPort: log.destPort ?? log.destinationPort ?? log.dest_port ?? '—',
      protocol: String(log.protocol || log.proto || '—').toUpperCase(),
      processName: log.processName || log.process || 'Not attributed',
      pid: log.pid ?? log.processId ?? '—',
      domain: log.domain || log.dnsQuery || '—',
      packetCount: log.packetCount ?? log.packets ?? '—',
      occurrenceCount: Math.max(1, Number(log.occurrenceCount || 1)),
      idsType: log.type || log.eventCategory || log.source || source,
      rule: log.signatureName || log.signature || log.ruleId || log.description || 'IDS/IPS rule',
      ruleId: log.ruleId || '—',
      action,
      status,
      message: log.description || log.message || log.detail || log.raw_log || log.raw || liveEventMessage(log),
      aiInvestigation: log.aiInvestigation || null,
      raw: log,
    };
  };
  const rows = logs.map(parseLog);
  const sources = ['ALL', 'IDS', 'IPS'];
  const agents = dbAgents;
  const filtered = rows;
  const totalPages = Math.max(1, Math.ceil(filteredTotal / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageRows = rows;
  const selectedRow = selected ? parseLog(selected) : pageRows[0];
  const statCards = [
    [`Total IDS/IPS Logs (${LOG_WINDOW_HOURS}H)`, dbTotal, '▤', '#60a5fa'],
    ['Low', dbCounts.low || 0, 'ⓘ', '#3b82f6'],
    ['Medium', dbCounts.medium || 0, '⚠', '#eab308'],
    ['High', dbCounts.high || 0, '⦿', '#ef4444'],
    ['Critical', dbCounts.critical || 0, '♜', '#a855f7'],
  ];

  const getPageNumbers = () => {
    const pages = [];
    const maxVisible = 5;
    let start = Math.max(1, currentPage - 2);
    let end = Math.min(totalPages, start + maxVisible - 1);
    if (end - start + 1 < maxVisible) {
      start = Math.max(1, end - maxVisible + 1);
    }
    for (let i = start; i <= end; i++) {
      pages.push(i);
    }
    return pages;
  };

  const LEVELS = ['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];
  const liveWindowLabel = `Last ${LOG_WINDOW_HOURS} hours`;
  const exportLogs = () => {
    const csvRows = [['timestamp', 'source_ip', 'destination_ip', 'ids_ips_type', 'signature_rule_name', 'severity', 'action', 'status', 'sensor_server']]
      .concat(filtered.map(row => [row.time, row.srcIp, row.destIp, row.idsType, row.rule, row.level, row.action, row.status, row.agent]));
    const csv = csvRows.map(row => row.map(cell => `"${String(cell).replaceAll('"', '""')}"`).join(',')).join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'ids-logs.csv';
    a.click();
    URL.revokeObjectURL(url);
  };

  if (viewingLogDetail) {
    return (
      <div className="ids-log-detail-page">
        <div className="ids-log-detail-back-bar">
          <h2>🔍 Log Incident Details</h2>
          <button className="ids-log-detail-back-btn" onClick={() => setViewingLogDetail(null)}>
            ← Close Detail & Back to Logs
          </button>
        </div>

        <div className="ids-log-detail-content">
          <div className="ids-log-detail-grid">
            <div className="ids-log-detail-card main-info">
              <h3>Incident Overview</h3>
              <div className="detail-field">
                <label>Signature / Rule Name</label>
                <div className="detail-value rule-val"><code>{viewingLogDetail.rule}</code></div>
              </div>
              <div className="detail-field-group">
                <div className="detail-field">
                  <label>Severity Level</label>
                  <div className="detail-value"><span className={`ids-log-level ${viewingLogDetail.level.toLowerCase()}`}>{viewingLogDetail.level}</span></div>
                </div>
                <div className="detail-field">
                  <label>Action Taken</label>
                  <div className="detail-value">{viewingLogDetail.action}</div>
                </div>
                <div className="detail-field">
                  <label>Status</label>
                  <div className="detail-value">{viewingLogDetail.status}</div>
                </div>
              </div>
            </div>

            <div className="ids-log-detail-card network-info">
              <h3>Network Telemetry</h3>
              <div className="detail-field-group">
                <div className="detail-field">
                  <label>Source IP Address</label>
                  <div className="detail-value ip-val"><IPTag v={`${viewingLogDetail.srcIp}:${viewingLogDetail.srcPort}`} /></div>
                </div>
                <div className="detail-field">
                  <label>Destination IP Address</label>
                  <div className="detail-value ip-val"><IPTag v={`${viewingLogDetail.destIp}:${viewingLogDetail.destPort}`} /></div>
                </div>
              </div>
              <div className="detail-field-group">
                <div className="detail-field">
                  <label>Sensor / Server</label>
                  <div className="detail-value">{viewingLogDetail.agent}</div>
                </div>
                <div className="detail-field">
                  <label>IDS/IPS Type</label>
                  <div className="detail-value">🛡 {viewingLogDetail.idsType}</div>
                </div>
                <div className="detail-field">
                  <label>Protocol / Packets</label>
                  <div className="detail-value">{viewingLogDetail.protocol} · {viewingLogDetail.packetCount} packet(s)</div>
                </div>
                <div className="detail-field">
                  <label>Process / PID</label>
                  <div className="detail-value">{viewingLogDetail.processName} · PID {viewingLogDetail.pid}</div>
                </div>
                <div className="detail-field">
                  <label>Domain / DNS</label>
                  <div className="detail-value">{viewingLogDetail.domain}</div>
                </div>
              </div>
            </div>

            <div className="ids-log-detail-card time-info">
              <h3>Timestamp Details</h3>
              <div className="detail-field-group">
                <div className="detail-field">
                  <label>Time</label>
                  <div className="detail-value">{viewingLogDetail.time}</div>
                </div>
                <div className="detail-field">
                  <label>Date</label>
                  <div className="detail-value">{viewingLogDetail.date}</div>
                </div>
              </div>
              <div className="detail-field">
                <label>Unique Event ID</label>
                <div className="detail-value"><code>{viewingLogDetail.id}</code></div>
              </div>
              <div className="detail-field">
                <label>Rule ID / Occurrences</label>
                <div className="detail-value"><code>{viewingLogDetail.ruleId}</code> · {viewingLogDetail.occurrenceCount} occurrence(s)</div>
              </div>
            </div>


          </div>

          {(() => {
            const showSrc = enrichedData.src && enrichedData.src !== 'private';
            const showDest = enrichedData.dest && enrichedData.dest !== 'private';

            if (!showSrc && !showDest) return null;

            const activeTab = activeIpTab === 'src' && showSrc ? 'src' : (showDest ? 'dest' : 'src');
            const ipData = enrichedData[activeTab];
            const currentIp = activeTab === 'src' ? viewingLogDetail.srcIp : viewingLogDetail.destIp;

            const getFlag = (code) => {
              if (!code || code.length !== 2) return '';
              try {
                const codePoints = code.toUpperCase().split('').map(c => 127397 + c.charCodeAt(0));
                return String.fromCodePoint(...codePoints);
              } catch (e) {
                return '';
              }
            };

            const renderSummaryTab = (data) => {
              if (!data) return <div style={{ padding: '20px', color: '#64748b' }}>Loading IP metadata...</div>;
              const isPrivacyTrue = data.privacy && (data.privacy.vpn || data.privacy.proxy || data.privacy.tor || data.privacy.relay || data.privacy.hosting);

              const rows = [
                { label: 'Location', value: `${data.city ? data.city + ', ' : ''}${data.region ? data.region + ', ' : ''}${data.country ? data.country : ''} ${data.countryCode ? getFlag(data.countryCode) : ''}` },
                { label: 'Country source', value: data.countrySource === 'ipinfo' ? 'IPinfo Lite' : data.countrySource === 'ip-api' ? 'ip-api.com (fallback)' : data.countrySource === 'local' ? 'Non-public address' : 'Not recorded' },
                { label: 'Country checked', value: data.countryCheckedAt ? new Date(data.countryCheckedAt).toLocaleString() : 'Not recorded' },
                { label: 'ASN', value: data.asn ? `${data.asn} — ${data.organization || ''}` : '—' },
                { label: 'Hostname', value: data.hostname || '—' },
                { label: 'Range', value: data.asnRoute || '—', isLink: true },
                { label: 'Company', value: data.organization || '—' },
                { label: 'Hosted domains', value: data.domainsCount ?? 'Unknown' },
                { label: 'Privacy', value: !data.privacy ? 'Unknown' : isPrivacyTrue ? '✓ true' : '✗ false', isBadge: true, badgeColor: isPrivacyTrue ? '#10b981' : '#6b7280' },
                { label: 'Anycast', value: data.anycast == null ? 'Unknown' : data.anycast ? '✓ true' : '✗ false', isBadge: true, badgeColor: data.anycast ? '#10b981' : '#6b7280' },
                { label: 'AS Type', value: data.privacy?.hosting ? 'Hosting' : 'Unknown' },
                { label: 'Abuse contact', value: data.abuse?.email || '—', isAbuse: true }
              ];

              return (
                <div style={{ background: '#090d16', borderRadius: '8px', overflow: 'hidden', border: '1px solid #1e293b' }}>
                  {rows.map((row, idx) => (
                    <div key={idx} style={{
                      display: 'grid',
                      gridTemplateColumns: '200px 1fr',
                      padding: '10px 16px',
                      background: idx % 2 === 0 ? '#0f172a' : '#0b1329',
                      borderBottom: idx === rows.length - 1 ? 'none' : '1px solid #1e293b',
                      alignItems: 'center',
                      fontSize: '0.85rem'
                    }}>
                      <div style={{ color: '#94a3b8', fontWeight: '500' }}>{row.label}</div>
                      <div style={{ color: '#f1f5f9' }}>
                        {row.isLink ? (
                          <a href="#" onClick={(e) => e.preventDefault()} style={{ color: '#3b82f6', textDecoration: 'underline' }}>{row.value}</a>
                        ) : row.isBadge ? (
                          <span style={{ color: row.badgeColor, fontWeight: 'bold' }}>{row.value}</span>
                        ) : row.isAbuse ? (
                          <span style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <span style={{ color: '#3b82f6' }}>{row.value}</span>
                            {row.value !== '—' && (
                              <span
                                style={{ cursor: 'pointer', opacity: 0.7 }}
                                onClick={() => {
                                  navigator.clipboard.writeText(row.value);
                                  alert('Abuse email copied to clipboard!');
                                }}
                                title="Copy"
                              >
                                📋
                              </span>
                            )}
                          </span>
                        ) : (
                          row.value || '—'
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              );
            };

            const renderGeoTab = (data) => {
              if (!data) return <div style={{ padding: '20px', color: '#64748b' }}>Loading IP metadata...</div>;
              const [latStr, lonStr] = (data.loc || '0,0').split(',');
              const lat = parseFloat(latStr || '0');
              const lon = parseFloat(lonStr || '0');

              const mapUrl = data.loc && data.loc !== 'Local'
                ? `https://www.openstreetmap.org/export/embed.html?bbox=${lon - 0.02}%2C${lat - 0.02}%2C${lon + 0.02}%2C${lat + 0.02}&layer=mapnik&marker=${lat}%2C${lon}`
                : null;

              return (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                    {[
                      { label: 'City', value: data.city || '—' },
                      { label: 'State', value: data.region || '—' },
                      { label: 'Country', value: data.country ? `${getFlag(data.countryCode)} ${data.country}` : '—' },
                      { label: 'Postal', value: data.postal || '—' },
                      { label: 'Local time', value: new Date().toLocaleString('en-US', { timeZone: data.timezone || undefined }) || '—' },
                      { label: 'Timezone', value: data.timezone || '—' },
                      { label: 'Coordinates', value: data.loc || '—' }
                    ].map((item, idx) => (
                      <div key={idx} style={{ display: 'grid', gridTemplateColumns: '150px 1fr', padding: '6px 0', borderBottom: '1px solid #1e293b', fontSize: '0.85rem' }}>
                        <div style={{ color: '#94a3b8', fontWeight: '500' }}>{item.label}</div>
                        <div style={{ color: '#f1f5f9' }}>{item.value}</div>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                    {mapUrl ? (
                      <div style={{ border: '1px solid #1e293b', borderRadius: '8px', overflow: 'hidden', background: '#0b1329', height: '240px', position: 'relative' }}>
                        <iframe
                          width="100%"
                          height="100%"
                          frameBorder="0"
                          scrolling="no"
                          marginHeight="0"
                          marginWidth="0"
                          src={mapUrl}
                          style={{ border: 'none', filter: 'invert(90%) hue-rotate(180deg) brightness(0.9) contrast(1.1)' }}
                        />
                        <div style={{ position: 'absolute', top: '10px', right: '10px' }}>
                          <a
                            href={`https://www.google.com/maps/search/?api=1&query=${lat},${lon}`}
                            target="_blank"
                            rel="noreferrer"
                            style={{
                              background: '#0f172a',
                              color: '#60a5fa',
                              border: '1px solid #3b82f6',
                              padding: '6px 10px',
                              borderRadius: '4px',
                              fontSize: '0.75rem',
                              textDecoration: 'none',
                              display: 'flex',
                              alignItems: 'center',
                              gap: '4px',
                              boxShadow: '0 2px 4px rgba(0,0,0,0.5)',
                              fontWeight: '600'
                            }}
                          >
                            Open in Maps ↗
                          </a>
                        </div>
                      </div>
                    ) : (
                      <div style={{ height: '240px', border: '1px solid #1e293b', borderRadius: '8px', display: 'flex', alignItems: 'center', justifyContent: 'center', background: '#0f172a', color: '#64748b', fontSize: '0.85rem' }}>
                        No map coordinates available for private IP
                      </div>
                    )}
                    <div style={{ textAlign: 'center', fontSize: '0.75rem', color: '#94a3b8' }}>
                      <code>Coordinates: {data.loc || '—'}</code>
                    </div>
                  </div>
                </div>
              );
            };

            const renderAnonTab = (data) => {
              if (!data) return <div style={{ padding: '20px', color: '#64748b' }}>Loading IP metadata...</div>;
              const privacy = data.privacy || { vpn: false, proxy: false, tor: false, relay: false, hosting: false };
              const anyDetected = privacy.vpn || privacy.proxy || privacy.tor || privacy.relay || privacy.hosting;

              let statusTitle = 'Clean Connection';
              let statusDesc = 'No anonymization proxies, hosting ranges, or VPN networks detected.';
              let statusColor = '#10b981';
              let statusBg = 'rgba(16, 185, 129, 0.1)';

              if (privacy.vpn) {
                statusTitle = 'VPN Detected';
                statusDesc = 'This IP address belongs to a virtual private network service provider.';
                statusColor = '#f59e0b';
                statusBg = 'rgba(245, 158, 11, 0.1)';
              } else if (privacy.tor) {
                statusTitle = 'Tor Exit Node Detected';
                statusDesc = 'This IP address is identified as an active Tor network exit node.';
                statusColor = '#ef4444';
                statusBg = 'rgba(239, 68, 68, 0.1)';
              } else if (privacy.proxy) {
                statusTitle = 'Proxy Detected';
                statusDesc = 'This IP is operating as a public or private web proxy server.';
                statusColor = '#f59e0b';
                statusBg = 'rgba(245, 158, 11, 0.1)';
              } else if (privacy.hosting) {
                statusTitle = 'Hosting/Datacenter';
                statusDesc = 'This IP address originates from a known cloud provider or datacenter.';
                statusColor = '#3b82f6';
                statusBg = 'rgba(59, 130, 246, 0.1)';
              }

              const pills = [
                { label: 'VPN', active: privacy.vpn },
                { label: 'Proxy', active: privacy.proxy },
                { label: 'Tor', active: privacy.tor },
                { label: 'Relay', active: privacy.relay },
                { label: 'Hosting', active: privacy.hosting }
              ];

              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                  <div style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '16px',
                    borderRadius: '8px',
                    background: statusBg,
                    border: `1px solid ${statusColor}`
                  }}>
                    <div>
                      <h4 style={{ color: statusColor, margin: '0 0 4px 0', fontSize: '1rem', fontWeight: 'bold' }}>{statusTitle}</h4>
                      <p style={{ color: '#cbd5e1', margin: 0, fontSize: '0.8rem' }}>{statusDesc}</p>
                    </div>
                    <span style={{
                      background: statusColor,
                      color: '#ffffff',
                      padding: '4px 10px',
                      borderRadius: '20px',
                      fontSize: '0.75rem',
                      fontWeight: 'bold',
                      textTransform: 'uppercase'
                    }}>
                      {anyDetected ? 'Detected' : 'Clear'}
                    </span>
                  </div>

                  <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '8px' }}>
                    {pills.map((pill, idx) => (
                      <div key={idx} style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '8px',
                        background: pill.active ? 'rgba(239, 68, 68, 0.1)' : '#0f172a',
                        border: `1px solid ${pill.active ? '#ef4444' : '#1e293b'}`,
                        padding: '8px 16px',
                        borderRadius: '20px',
                        fontSize: '0.8rem',
                        color: pill.active ? '#f87171' : '#94a3b8',
                        fontWeight: '500'
                      }}>
                        <span>{pill.active ? '🚫' : '✅'}</span>
                        {pill.label}
                      </div>
                    ))}
                  </div>
                </div>
              );
            };

            const renderAsnTab = (data) => {
              if (!data) return <div style={{ padding: '20px', color: '#64748b' }}>Loading IP metadata...</div>;
              return (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                  <div style={{ background: '#0b1329', padding: '16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                    <h4 style={{ color: '#3b82f6', margin: '0 0 6px 0', fontSize: '1.1rem', fontWeight: 'bold' }}>
                      {data.asn || '—'} <span style={{ color: '#94a3b8', fontWeight: 'normal' }}>— {data.organization || '—'}</span>
                    </h4>
                    <div style={{ fontSize: '0.8rem', color: '#64748b' }}>
                      ISP / Autonomous System Registry Information
                    </div>
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
                    {[
                      { label: 'DOMAIN', value: data.domain || '—', isLink: true, href: data.domain ? `https://${data.domain}` : '#' },
                      { label: 'ASN TYPE', value: data.privacy?.hosting ? 'Hosting' : 'Unknown', isLink: false },
                      { label: 'ROUTE', value: data.asnRoute || '—', isLink: true, href: '#' }
                    ].map((col, idx) => (
                      <div key={idx} style={{ background: '#0f172a', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                        <div style={{ fontSize: '0.7rem', color: '#94a3b8', fontWeight: 'bold', letterSpacing: '0.05em', marginBottom: '6px' }}>{col.label}</div>
                        <div style={{ fontSize: '0.9rem', color: '#f1f5f9', fontWeight: '500' }}>
                          {col.isLink ? (
                            <a href={col.href} target="_blank" rel="noreferrer" style={{ color: '#3b82f6', textDecoration: 'underline' }}>{col.value}</a>
                          ) : col.value}
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ background: '#0f172a', padding: '16px', borderRadius: '8px', border: '1px solid #1e293b' }}>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 'bold', marginBottom: '8px', textTransform: 'uppercase' }}>Company Profile</div>
                    <div style={{ fontSize: '1rem', color: '#f1f5f9', fontWeight: '600' }}>{data.organization || '—'}</div>
                    <div style={{ fontSize: '0.8rem', color: '#64748b', marginTop: '4px' }}>
                      Autonomous System Organization: {data.organization || '—'}
                    </div>
                  </div>
                </div>
              );
            };

            const renderAbuseTab = (data) => {
              if (!data) return <div style={{ padding: '20px', color: '#64748b' }}>Loading IP metadata...</div>;
              const abuse = data.abuse || { address: '', email: '', name: 'Abuse', network: '', phone: '' };

              return (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px' }}>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
                    {[
                      { icon: '📍', label: 'Address', value: abuse.address || '—' },
                      { icon: '📞', label: 'Phone', value: abuse.phone || '—' },
                      { icon: '✉️', label: 'Email', value: abuse.email || '—' }
                    ].map((item, idx) => (
                      <div key={idx} style={{ background: '#0f172a', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1e293b', display: 'flex', gap: '12px', alignItems: 'center' }}>
                        <span style={{ fontSize: '1.2rem' }}>{item.icon}</span>
                        <div style={{ display: 'flex', flexDirection: 'column', width: '100%' }}>
                          <span style={{ fontSize: '0.7rem', color: '#94a3b8', fontWeight: 'bold' }}>{item.label}</span>
                          <span style={{ fontSize: '0.85rem', color: '#f1f5f9', wordBreak: 'break-all', display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                            {item.value}
                            {item.value !== '—' && (
                              <span
                                style={{ cursor: 'pointer', opacity: 0.7 }}
                                onClick={() => {
                                  navigator.clipboard.writeText(item.value);
                                  alert('Copied to clipboard!');
                                }}
                                title="Copy"
                              >
                                📋
                              </span>
                            )}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <div style={{ background: '#0f172a', borderRadius: '8px', border: '1px solid #1e293b', overflow: 'hidden' }}>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', background: '#1e293b', padding: '8px 12px', fontSize: '0.75rem', fontWeight: 'bold', color: '#94a3b8' }}>
                        <div>NAME</div>
                        <div>NETWORK</div>
                      </div>
                      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', padding: '12px', fontSize: '0.85rem', color: '#f1f5f9' }}>
                        <div>{abuse.name || 'Abuse'}</div>
                        <div>{abuse.network || data.asnRoute || '—'}</div>
                      </div>
                    </div>

                    <div style={{ background: 'rgba(239, 68, 68, 0.05)', border: '1px dashed #ef4444', borderRadius: '8px', padding: '12px', fontSize: '0.8rem', color: '#cbd5e1' }}>
                      <strong>⚠️ Note:</strong> Use these contact details to report unauthorized or malicious network activity originating from this IP address block.
                    </div>
                  </div>
                </div>
              );
            };

            return (
              <div className="ids-log-detail-card ipinfo-info" style={{ marginTop: '16px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e293b', paddingBottom: '12px', marginBottom: '16px', flexWrap: 'wrap', gap: '12px' }}>
                  <h3 style={{ margin: 0 }}>IP Intelligence (IPinfo Lite)</h3>

                  <div style={{ display: 'flex', gap: '8px' }}>
                    {showSrc && (
                      <button
                        onClick={() => setActiveIpTab('src')}
                        style={{
                          background: activeTab === 'src' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                          border: '1px solid',
                          borderColor: activeTab === 'src' ? '#3b82f6' : '#1e293b',
                          color: activeTab === 'src' ? '#60a5fa' : '#94a3b8',
                          padding: '4px 10px',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 'bold',
                          cursor: 'pointer',
                          transition: 'all 0.2s'
                        }}
                      >
                        Source: {viewingLogDetail.srcIp}
                      </button>
                    )}
                    {showDest && (
                      <button
                        onClick={() => setActiveIpTab('dest')}
                        style={{
                          background: activeTab === 'dest' ? 'rgba(59, 130, 246, 0.15)' : 'transparent',
                          border: '1px solid',
                          borderColor: activeTab === 'dest' ? '#3b82f6' : '#1e293b',
                          color: activeTab === 'dest' ? '#60a5fa' : '#94a3b8',
                          padding: '4px 10px',
                          borderRadius: '6px',
                          fontSize: '0.8rem',
                          fontWeight: 'bold',
                          cursor: 'pointer',
                          transition: 'all 0.2s'
                        }}
                      >
                        Destination: {viewingLogDetail.destIp}
                      </button>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '8px', borderBottom: '1px solid #1e293b', paddingBottom: '12px', marginBottom: '16px', overflowX: 'auto' }}>
                  {[
                    { id: 'summary', label: 'Summary', icon: '📊' },
                    { id: 'geo', label: 'IP Geolocation', icon: '📍' },
                    { id: 'anon', label: 'Anonymization', icon: '🛡️' },
                    { id: 'asn', label: 'ASN & Company', icon: '🌐' },
                    { id: 'abuse', label: 'Abuse Contacts', icon: '✉️' }
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setIpinfoActiveSection(tab.id)}
                      style={{
                        background: ipinfoActiveSection === tab.id ? '#1e293b' : 'transparent',
                        border: '1px solid',
                        borderColor: ipinfoActiveSection === tab.id ? '#3b82f6' : '#1e293b',
                        color: ipinfoActiveSection === tab.id ? '#60a5fa' : '#94a3b8',
                        padding: '6px 12px',
                        borderRadius: '6px',
                        cursor: 'pointer',
                        fontSize: '0.8rem',
                        fontWeight: '500',
                        display: 'flex',
                        alignItems: 'center',
                        gap: '6px',
                        transition: 'all 0.2s ease',
                        whiteSpace: 'nowrap'
                      }}
                    >
                      <span>{tab.icon}</span>
                      {tab.label}
                    </button>
                  ))}
                </div>

                <div style={{ minHeight: '200px' }}>
                  {ipinfoActiveSection === 'summary' && renderSummaryTab(ipData)}
                  {ipinfoActiveSection === 'geo' && renderGeoTab(ipData)}
                  {ipinfoActiveSection === 'anon' && renderAnonTab(ipData)}
                  {ipinfoActiveSection === 'asn' && renderAsnTab(ipData)}
                  {ipinfoActiveSection === 'abuse' && renderAbuseTab(ipData)}
                </div>

                {viewingLogDetail.raw.tiSummary && (
                  <div style={{ marginTop: '20px', borderTop: '1px solid #1e293b', paddingTop: '12px' }}>
                    <div style={{ fontSize: '0.75rem', color: '#94a3b8', fontWeight: 'bold', textTransform: 'uppercase', marginBottom: '4px' }}>Threat Intel Analysis</div>
                    <div style={{ fontWeight: '500', color: '#f87171', background: 'rgba(239, 68, 68, 0.05)', padding: '10px 14px', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.2)', fontSize: '0.85rem' }}>
                      🚨 {viewingLogDetail.raw.tiSummary}
                    </div>
                  </div>
                )}
              </div>
            );
          })()}
        </div>
      </div>
    );
  }

  return (
    <div className="ids-logs">
      <div className="ids-log-head">
        <div>
          <h3>Logs</h3>
          <p>IDS/IPS logs from the last {LOG_WINDOW_HOURS} hours</p>
        </div>
        <div className="ids-log-actions">
          <button className={autoRefresh ? 'live' : ''} onClick={() => setAutoRefresh(v => !v)}>● Live⌄</button>
          <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}>
            {[25, 50, 100, 200, 500].map(v => <option key={v} value={v}>{v} / page</option>)}
          </select>
          <button>▽ Filters⌄</button>
          <button onClick={exportLogs}>⇩ Export</button>
          <button onClick={load} disabled={loading}>{loading ? '⏳' : '⟳'}</button>
        </div>
      </div>

      {err && <div style={{ color: '#f87171', fontSize: 13, marginBottom: 12 }}>❌ {err} — Is IPS server running on port 5050?</div>}
      {aiMessage && <div style={{ color: aiMessage.toLowerCase().includes('failed') ? '#f87171' : '#86efac', fontSize: 13, marginBottom: 12 }}>✦ {aiMessage}</div>}

      <div className="ids-log-stats">
        {statCards.map(([label, value, icon, color]) => (
          <div className="ids-log-stat" key={label}>
            <i style={{ color, background: `${color}18` }}>{icon}</i>
            <span>{label}</span>
            <strong>{Number(value).toLocaleString()}</strong>
            <small style={{ color: '#94a3b8' }}>last {LOG_WINDOW_HOURS} hours</small>
          </div>
        ))}
      </div>

      <div className="ids-log-filterbar">
        <input value={searchInput} onChange={e => setSearchInput(e.target.value)} placeholder="Search logs..." />
        <select value={level} onChange={e => { setLevel(e.target.value); setPage(1); }}>
          <option value="ALL">All Log Levels</option>
          <option value="LOW">Low</option>
          <option value="MEDIUM">Medium</option>
          <option value="HIGH">High</option>
          <option value="CRITICAL">Critical</option>
        </select>
        <select value={agentFilter} onChange={e => { setAgentFilter(e.target.value); setPage(1); }}>
          {agents.map(agent => <option key={agent} value={agent}>{agent === 'ALL' ? 'Any Agent' : agent}</option>)}
        </select>
        <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1); }}>
          {sources.map(source => <option key={source} value={source}>{source === 'ALL' ? 'All Sources' : source}</option>)}
        </select>
        <div className="ids-log-date">{liveWindowLabel} 📅</div>
        <button onClick={() => { setSearchInput(''); setSearch(''); setSourceFilter('ALL'); setAgentFilter('ALL'); setLevel('ALL'); }}>Clear All</button>
      </div>

      <div className="ids-log-workbench">
        <section className="ids-log-table-card">
          <div className="ids-log-level-tabs">
            {LEVELS.map(l => (
              <button key={l} className={level === l ? 'active' : ''} onClick={() => { setLevel(l); setPage(1); }}>
                {l} <b>{l === 'ALL' ? dbTotal : dbCounts[l.toLowerCase()] || 0}</b>
              </button>
            ))}
            <label>Auto Refresh <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} /></label>
            <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1); }}>
              {[25, 50, 100].map(v => <option key={v} value={v}>{v} / page</option>)}
            </select>
          </div>
          <div className="ids-log-table-wrap">
            <table className="ids-log-table">
              <thead><tr>{['', 'Timestamp ↕', 'Source IP : Port', 'Destination IP : Port', 'Proto', 'IDS/IPS Type', 'Signature / Rule Name', 'Count', 'Severity', 'Action', 'Status', 'Sensor / Server'].map(h => <th key={h}>{h}</th>)}</tr></thead>
              <tbody style={{ opacity: loading ? 0.6 : 1, transition: 'opacity 0.15s ease' }}>
                {loading && pageRows.length === 0 ? (
                  <tr><td colSpan="12"><Empty icon="⏳" msg="Loading IDS/IPS logs…" /></td></tr>
                ) : pageRows.length === 0 ? (
                  <tr><td colSpan="12"><Empty icon="📋" msg="No IDS/IPS logs found" /></td></tr>
                ) : pageRows.map((row, i) => (
                  <tr key={`${row.id}-${i}`} className={selectedRow?.id === row.id ? 'selected' : ''} onClick={() => setViewingLogDetail(row)}>
                    <td>›</td>
                    <td>{row.time}</td>
                    <td>{row.srcIp}:{row.srcPort}</td>
                    <td>{row.destIp}:{row.destPort}</td>
                    <td>{row.protocol}</td>
                    <td><span className="ids-log-source">🛡 {row.idsType}</span></td>
                    <td><code>{row.rule}</code></td>
                    <td>{row.occurrenceCount > 1 ? `×${row.occurrenceCount}` : '1'}</td>
                    <td><span className={`ids-log-level ${row.level.toLowerCase()}`}>{row.level}</span></td>
                    <td>{row.action}</td>
                    <td>{row.status}</td>
                    <td>{row.agent}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="ids-log-pagination">
            <span>Showing {filteredTotal ? (currentPage - 1) * pageSize + 1 : 0} to {Math.min(currentPage * pageSize, filteredTotal)} of {filteredTotal} filtered logs ({dbTotal} total)</span>
            <div>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>‹</button>
              {getPageNumbers().map(n => <button key={n} className={currentPage === n ? 'active' : ''} onClick={() => setPage(n)}>{n}</button>)}
              <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>›</button>
            </div>
            <label>Go to page <input value={currentPage} onChange={e => setPage(Math.max(1, Math.min(totalPages, Number(e.target.value) || 1)))} /></label>
          </div>
        </section>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  WHITELIST
// ══════════════════════════════════════════════════════════════════════════════
function WhitelistTab({ onTabChange }) {
  const [list, setList] = useState([]);
  const [loading, setLoading] = useState(true);
  const [form, setForm] = useState({ value: '', type: 'ip', reason: '' });
  const [submitting, setSubmitting] = useState(false);
  const [bulkImportOpen, setBulkImportOpen] = useState(false);
  const [removing, setRemoving] = useState(null);
  const removeDialogOpen = useRef(false);
  const [msg, setMsg] = useState('');
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [page, setPage] = useState(1);

  const load = useCallback(async () => {
    setLoading(true);
    try { const { data } = await api.get('/ips-proxy/whitelist', { skipCache: true }); setList(data.whitelist || []); }
    catch (e) { setMsg(`❌ ${e.message}`); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const add = async (e) => {
    e.preventDefault();
    if (!form.value.trim()) return;
    setSubmitting(true); setMsg('');
    try {
      await api.post('/ips-proxy/whitelist', form);
      setMsg(`✅ ${form.value} added to whitelist`);
      setForm({ value: '', type: 'ip', reason: '' }); load();
    } catch (e) { setMsg(`❌ ${e.response?.data?.message || e.message}`); }
    finally { setSubmitting(false); }
  };

  const remove = async (value) => {
    if (removeDialogOpen.current) return;
    removeDialogOpen.current = true;
    try {
      const confirmation = await Swal.fire({
        titleText: 'Remove from whitelist?',
        text: `Remove "${value}" from the whitelist? Applicable security rules can block this entry after removal.`,
        icon: 'warning',
        position: 'center',
        background: '#0b192a',
        color: '#e2e8f0',
        confirmButtonColor: '#dc2626',
        cancelButtonColor: '#334155',
        confirmButtonText: 'Remove',
        cancelButtonText: 'Cancel',
        showCancelButton: true,
        showCloseButton: true,
        closeButtonAriaLabel: 'Close removal confirmation',
        reverseButtons: true,
        focusCancel: true,
        showLoaderOnConfirm: true,
        allowOutsideClick: () => !Swal.isLoading(),
        allowEscapeKey: () => !Swal.isLoading(),
        customClass: { popup: 'ids-white-confirm', validationMessage: 'ids-white-confirm-error' },
        preConfirm: async () => {
          setRemoving(value);
          Swal.getCloseButton().disabled = true;
          try {
            const { data } = await api.delete(`/ips-proxy/whitelist/${encodeURIComponent(value)}`);
            if (data?.ok === false || data?.success === false) throw new Error(data.message || data.error || 'Removal rejected');
            return true;
          } catch (error) {
            const message = error.response?.data?.message || error.response?.data?.error || error.message || 'Removal failed. Please retry.';
            // SweetAlert validation accepts HTML; keep backend errors as plain text.
            Swal.showValidationMessage('Removal failed.');
            Swal.getValidationMessage().textContent = String(message);
            return false;
          } finally {
            setRemoving(null);
            Swal.getCloseButton().disabled = false;
          }
        },
      });
      if (confirmation.isConfirmed) {
        setMsg(`↩️ ${value} removed`);
        await load();
      }
    } finally { removeDialogOpen.current = false; }
  };

  const exportWhitelist = () => {
    const rows = [['type', 'value', 'source', 'reason', 'added_on'], ...filtered.map(entry => [
      entry.type || 'ip', entry.value, sourceLabel(entry), entry.reason || '', entry.addedAt || entry.createdAt || '',
    ])];
    const csv = rows.map(row => row.map(cell => `"${String(cell || '').replaceAll('"', '""')}"`).join(',')).join('\n');
    const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8;' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'ips-whitelist.csv'; link.click(); URL.revokeObjectURL(url);
  };

  const filtered = list.filter(entry => {
    const q = search.trim().toLowerCase();
    const entryType = (entry.type || 'ip').toLowerCase();
    const source = (entry.source || entry.addedBy || 'manual').toLowerCase();
    const matchesSearch = !q || [entry.value, entry.reason, entry.type, entry.source, entry.addedBy].some(v => String(v || '').toLowerCase().includes(q));
    const matchesType = typeFilter === 'all' || entryType === typeFilter;
    const matchesSource = sourceFilter === 'all' || source.includes(sourceFilter);
    return matchesSearch && matchesType && matchesSource;
  });
  const pageSize = 8;
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const currentPage = Math.min(page, totalPages);
  const pageRows = filtered.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const ipCount = list.filter(e => ['ip', 'cidr'].includes((e.type || '').toLowerCase())).length;
  const domainCount = list.filter(e => (e.type || '').toLowerCase() === 'domain').length;
  const typeLabel = (type) => ({ ip: 'IP Address', domain: 'Domain', cidr: 'CIDR Range' }[(type || 'ip').toLowerCase()] || type || 'IP Address');
  const sourceLabel = (entry) => entry.source || entry.addedBy || 'Manual';

  return (
    <div className="ids-whitelist">
      <div className="ids-white-hero">
        <div className="ids-white-hero-copy">
          <span>🛡</span>
          <p>IPs and domains on the whitelist are <strong>never blocked</strong>,<br />even if a rule targets them.</p>
        </div>
        <div className="ids-white-stats">
          <div><i>🌐</i><label>Total Whitelisted</label><strong>{list.length}</strong></div>
          <div><i>▦</i><label>IP Addresses</label><strong>{ipCount}</strong></div>
          <div><i>☁</i><label>Domains</label><strong>{domainCount}</strong></div>
        </div>
      </div>

      <form onSubmit={add} className="ids-white-add">
        <div className="ids-white-add-head">
          <strong>Add Whitelisted Entry</strong>
          <button type="button" onClick={() => { setMsg(''); setBulkImportOpen(true); }} disabled={submitting || loading}>⇧ Bulk Import</button>
        </div>
        <div className="ids-white-add-grid">
          <label>Type
            <select value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value }))}>
              <option value="ip">IP Address</option>
              <option value="domain">Domain</option>
              <option value="cidr">CIDR Range</option>
            </select>
          </label>
          <label>Value
            <input value={form.value} onChange={e => setForm(p => ({ ...p, value: e.target.value }))} placeholder={form.type === 'ip' ? 'e.g., 192.168.1.100' : form.type === 'domain' ? 'e.g., trusted.example.com' : 'e.g., 10.0.0.0/8'} required />
          </label>
          <label>Reason <span>(Optional)</span>
            <input value={form.reason} onChange={e => setForm(p => ({ ...p, reason: e.target.value }))} placeholder="e.g., Office network, Trusted partner..." />
          </label>
        </div>
        <div className="ids-white-add-actions">
          <i />
          <button type="submit" disabled={submitting}>{submitting ? 'Adding…' : '+ Add to Whitelist'}</button>
        </div>
      </form>

      {bulkImportOpen && <WhitelistBulkImport existingEntries={list} onClose={() => setBulkImportOpen(false)} onImported={load} />}
      {msg && <div className={`ids-white-msg ${msg.startsWith('✅') || msg.startsWith('↩️') ? 'ok' : 'err'}`}>{msg}</div>}

      <section className="ids-white-table-card">
        <div className="ids-white-table-head">
          <div><strong>🛡 Whitelisted Entries</strong></div>
          <div className="ids-white-head-actions">
            <span>{loading ? 'Loading…' : `${filtered.length} trusted entries`}</span>
            <button type="button" onClick={exportWhitelist} disabled={!filtered.length} title="Export filtered whitelist">⇩</button>
            <button type="button" onClick={() => document.querySelector('.ids-white-filters input')?.focus()} title="Focus filters">▽</button>
          </div>
        </div>
        <div className="ids-white-filters">
          <input value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} placeholder="⌕  Search IP address or domain..." />
          <select value={typeFilter} onChange={e => { setTypeFilter(e.target.value); setPage(1); }}>
            <option value="all">All Types</option>
            <option value="ip">IP Address</option>
            <option value="domain">Domain</option>
            <option value="cidr">CIDR Range</option>
          </select>
          <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(1); }}>
            <option value="all">All Sources</option>
            <option value="manual">Manual</option>
            <option value="api">API</option>
            <option value="system">System</option>
          </select>
        </div>

        <div className="ids-white-table-wrap">
          <table className="ids-white-table">
            <thead><tr>{['Type', 'Value', 'Source', 'Reason', 'Added By', 'Added On', 'Action'].map(h => <th key={h}>{h}</th>)}</tr></thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="7"><Empty icon="⏳" msg="Loading whitelist…" /></td></tr>
              ) : pageRows.length === 0 ? (
                <tr>
                  <td colSpan="7">
                    <div className="ids-white-empty">
                      <div className="ids-white-empty-art"><span>✓</span></div>
                      <strong>No whitelisted entries found</strong>
                      <p>Add trusted IPs or domains to ensure they are never blocked by your security rules.</p>
                      <button onClick={() => document.querySelector('.ids-white-add input')?.focus()}>＋ Add Your First Entry</button>
                    </div>
                  </td>
                </tr>
              ) : pageRows.map((e, i) => (
                <tr key={`${e.value}-${i}`}>
                  <td><span className="ids-white-type">{typeLabel(e.type)}</span></td>
                  <td><code>{e.value}</code></td>
                  <td>{sourceLabel(e)}</td>
                  <td>{e.reason || '—'}</td>
                  <td>{e.addedBy || 'Admin'}</td>
                  <td>{e.addedAt ? new Date(e.addedAt).toLocaleDateString() : '—'}</td>
                  <td><button className="ids-white-remove" onClick={() => remove(e.value)} disabled={removing === e.value}>{removing === e.value ? 'Removing…' : 'Remove'}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div className="ids-white-pagination">
          <span>Showing {filtered.length ? (currentPage - 1) * pageSize + 1 : 0} to {Math.min(currentPage * pageSize, filtered.length)} of {filtered.length} entries</span>
          <div>
            <button onClick={() => setPage(1)} disabled={currentPage === 1}>‹</button>
            <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>‹</button>
            <button className="active">{currentPage}</button>
            <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>›</button>
            <button onClick={() => setPage(totalPages)} disabled={currentPage === totalPages}>›</button>
          </div>
        </div>
      </section>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  SERVER STATUS
// ══════════════════════════════════════════════════════════════════════════════
function ServerTab({ serverStatus, onTabChange }) {
  if (!serverStatus) return <Empty icon="🔴" msg="IPS Server offline or not reachable at port 5050" />;
  const fmt = (s) => `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m ${Math.floor(s % 60)}s`;
  const items = [
    { label: 'Status', val: serverStatus.status, color: '#34d399' },
    { label: 'Platform', val: serverStatus.platform, color: '#60a5fa' },
    { label: 'Architecture', val: serverStatus.architecture, color: '#60a5fa' },
    { label: 'Enforcement', val: serverStatus.enforcement, color: '#f59e0b' },
    { label: 'Uptime', val: fmt(serverStatus.uptime || 0), color: '#a78bfa' },
    { label: 'Blocked', val: serverStatus.blockedCount, color: '#f87171' },
  ];
  return (
    <div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(220px,1fr))', gap: 14, marginBottom: 20 }}>
        {items.map(it => (
          <div key={it.label} style={{ background: '#0c1a2e', border: `1px solid ${it.color}33`, borderRadius: 10, padding: '14px 18px' }}>
            <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', marginBottom: 6 }}>{it.label}</div>
            <div style={{ fontSize: 18, fontWeight: 700, color: it.color }}>{it.val ?? '—'}</div>
          </div>
        ))}
      </div>

      <div style={C.card}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#93c5fd', marginBottom: 14 }}>📝 Quick API Commands</div>
        {[
          { label: 'Block IP', code: `curl -X POST http://localhost:5050/webhook \\\n  -H "Content-Type: application/json" \\\n  -d '{"action":"block","ip":"203.0.113.45","reason":"Port scan"}'` },
          { label: 'Unblock IP', code: `curl -X POST http://localhost:5050/webhook \\\n  -H "Content-Type: application/json" \\\n  -d '{"action":"unblock","ip":"203.0.113.45"}'` },
          { label: 'Get Status', code: `curl http://localhost:5050/status` },
        ].map((cmd, i) => (
          <div key={i} style={{ marginBottom: 14 }}>
            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 6 }}>{cmd.label}</div>
            <pre style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 6, padding: '10px 14px', fontSize: 11, color: '#94a3b8', overflowX: 'auto', margin: 0 }}>{cmd.code}</pre>
          </div>
        ))}
      </div>

      <div style={{ ...C.card, marginTop: 16 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#93c5fd', marginBottom: 12 }}>✨ Features</div>
        <ul style={{ margin: 0, paddingLeft: 20, fontSize: 12, color: '#94a3b8', lineHeight: 1.8 }}>
          {['Real-time blocklist monitoring', 'Multi-criteria blocking (IP, port, domain, app, protocol)', 'Attack type detection & classification', 'Threat analysis & statistics', 'Block/unblock management', 'Host firewall support (nftables + Windows Defender)', 'MongoDB persistence', 'Webhook authentication'].map((f, i) => <li key={i}>{f}</li>)}
        </ul>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  MAIN PAGE
// ══════════════════════════════════════════════════════════════════════════════
export default function IDSPage({ initialModule = 'ids' }) {
  const { user, company } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [activeModule, setActiveModule] = useState(initialModule);
  const [countryRuleCount, setCountryRuleCount] = useState(null);
  const [activeTab, setActiveTab] = useState(initialModule === 'ips' ? 'blocklist' : 'overview');
  const [reportFocus, setReportFocus] = useState('sources');
  const [logsSeverityInit, setLogsSeverityInit] = useState('ALL');
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [ipsOnline, setIpsOnline] = useState(null); // null=checking, true=online, false=offline
  const [summary, setSummary] = useState(null); // live KPI summary
  const [idsKpis, setIdsKpis] = useState(null);
  const [tabMetrics, setTabMetrics] = useState({
    overview: { value: 0, status: 'OK' },
    blocklist: { value: 0, status: 'OK' },
    threats: { value: 0, status: 'OK' },
    logs: { value: 0, status: 'OK' },
    coverage: { value: 0, status: 'OK' },
    whitelist: { value: 0, status: 'OK' },
    waf: { value: 0, status: 'OK' },
    policy: { value: 0, status: 'OK' },
    audit: { value: 0, status: 'OK' },
    isolationFlow: { value: 0, status: 'OK' },
  });
  const summaryRef = useRef(null);
  const workspaceRef = useRef(null);
  const shellRef = useRef(null);

  // IDS and IPS have distinct sidebar routes. Keep the displayed workspace in
  // sync when React reuses this component while navigating between them.
  useEffect(() => {
    setActiveModule(initialModule === 'ips' ? 'ips' : 'ids');
    setActiveTab(initialModule === 'ips' ? 'blocklist' : 'overview');
  }, [initialModule]);

  // ── Fetch the single lightweight KPI summary. Detailed tab data is loaded
  // only when that tab is opened, instead of firing 13 API requests up front. ──
  const summaryCache = useRef(null);
  useEffect(() => {
    if (activeModule !== 'ips') return undefined;
    let active = true;
    const refresh = () => api.get('/ips/country-blocks/summary').then(({ data }) => {
      if (active) setCountryRuleCount(data.enabled);
    }).catch(() => {});
    refresh();
    const timer = autoRefresh ? setInterval(refresh, 60000) : null;
    return () => { active = false; if (timer) clearInterval(timer); };
  }, [activeModule, autoRefresh]);
  const fetchSummary = useCallback(async () => {
    try {
      let nextSummary;
      try {
        const { data } = await api.get('/idsips/summary');
        nextSummary = data;
      } catch {
        // Keep the IDS workspace useful when the combined widget endpoint is
        // temporarily unavailable. The dedicated IDS stats route has the same
        // tenant/time scope and is a reliable fallback for the KPI shell.
        const { data } = await api.get('/ids/stats?summary=true');
        nextSummary = {
          ...data,
          ipsBlocked: data.blocked ?? 0,
          ipsOnline: false,
          ipsStatus: 'unknown',
        };
      }
      const newJson = JSON.stringify(nextSummary);
      if (summaryCache.current === newJson) return;
      summaryCache.current = newJson;

      setSummary(nextSummary);
      setIpsOnline(nextSummary?.ipsOnline === true);
      const nextIds = {
        total: nextSummary?.total ?? 0,
        severity: {
          critical: nextSummary?.critical ?? 0,
          high: nextSummary?.high ?? 0,
        },
      };
      setIdsKpis(nextIds);

      const criticalCount = nextIds.severity.critical;
      const highCount = nextIds.severity.high;

      const getStatus = (crit, high) => {
        if (crit > 0) return 'Danger';
        if (high > 0) return 'Warning';
        return 'OK';
      };

      setTabMetrics(previous => ({
        ...previous,
        overview: {
          value: nextIds.total,
          status: getStatus(criticalCount, highCount)
        },
        blocklist: {
          value: nextSummary?.ipsBlocked ?? 0,
          status: getStatus(0, (nextSummary?.ipsBlocked ?? 0) > 0 ? 1 : 0)
        },
        threats: {
          value: nextIds.total,
          status: getStatus(criticalCount, highCount)
        },
        logs: {
          value: nextIds.total,
          status: 'OK'
        },
        coverage: {
          value: nextSummary?.capabilities ?? previous.coverage.value,
          status: 'OK'
        },
      }));
    } catch { /* silent — summary is optional */ }
  }, []);

  useEffect(() => { fetchSummary(); }, [fetchSummary]);

  // One coalesced summary poll keeps KPIs current without request bursts.
  useEffect(() => {
    if (summaryRef.current) clearInterval(summaryRef.current);
    if (autoRefresh) {
      summaryRef.current = setInterval(fetchSummary, 60000);
    }
    return () => { clearInterval(summaryRef.current); };
  }, [autoRefresh, fetchSummary]);

  const resetPageScroll = useCallback(() => {
    requestAnimationFrame(() => {
      shellRef.current?.scrollTo({ top: 0, behavior: 'auto' });
      workspaceRef.current?.scrollTo({ top: 0, behavior: 'auto' });
      window.scrollTo({ top: 0, behavior: 'auto' });
    });
  }, []);

  const changeTab = useCallback((tab) => {
    setActiveTab(tab);
    resetPageScroll();
  }, [resetPageScroll]);

  const openReport = useCallback((focus = 'sources') => {
    setReportFocus(focus);
    setActiveTab('report');
    resetPageScroll();
  }, [resetPageScroll]);


  return (
    <div className="ids-fullscreen">
      <main className="ids-workspace" ref={workspaceRef}>
        <div className="ids-shell" ref={shellRef}>
          <div className="ids-topline">
            <div>
              <div className="ids-title">{activeModule === 'ids' ? 'Intrusion Detection System' : 'Intrusion Prevention System'}</div>
              <div className="ids-subtitle">{activeModule === 'ids' ? 'Detection, investigation and security telemetry' : 'Blocking, containment and response enforcement'}</div>
            </div>
            <div className="ids-actions">
              <label className="ids-live-toggle">
                <input type="checkbox" checked={autoRefresh} onChange={e => setAutoRefresh(e.target.checked)} />
                Live monitoring
              </label>
              <button className="ids-refresh" title="Refresh data" onClick={fetchSummary}>↻</button>
            </div>
          </div>

          <div className="ids-kpis">
            {[
              { id: 'overview', icon: '📡', label: 'IDS Overview', color: '#3b82f6', value: tabMetrics.overview.value, sub: `${idsKpis?.severity?.critical ?? 0} critical` },
              { id: 'blocklist', icon: '🛡️', label: 'Blocklist', color: '#ef4444', value: tabMetrics.blocklist.value, sub: '24H blocks' },
              { id: 'country', icon: '🌐', label: 'Block Country', color: '#38bdf8', value: countryRuleCount, sub: 'Enabled country rules' },
              { id: 'threats', icon: '⚠️', label: 'Threats', color: '#f97316', value: tabMetrics.threats.value, sub: `${idsKpis?.severity?.high ?? 0} high alerts` },
              { id: 'logs', icon: '📋', label: 'Logs', color: '#60a5fa', value: tabMetrics.logs.value, sub: 'All IDS/IPS logs' },
              { id: 'coverage', icon: '🧭', label: 'Coverage', color: '#14b8a6', value: tabMetrics.coverage.value, sub: 'Monitored classes' },
              { id: 'whitelist', icon: '✅', label: 'Whitelist', color: '#22c55e', value: tabMetrics.whitelist.value, sub: 'Trusted entries' },
              { id: 'waf', icon: '🔥', label: 'WAF', color: '#f59e0b', value: tabMetrics.waf.value, sub: 'Blocked requests' },
              { id: 'policy', icon: '🛡️', label: 'Policy IDS&IPS', color: '#a855f7', value: tabMetrics.policy.value, sub: 'Violations logged' },
              { id: 'audit', icon: '🧾', label: 'Audit Log', color: '#34d399', value: tabMetrics.audit.value, sub: 'Audit events' },
              { id: 'isolationFlow', icon: '🔓', label: 'Isolation Flow', color: '#38bdf8', value: tabMetrics.isolationFlow.value, sub: 'Active workflows' },
            ].filter(tab => activeModule === 'ids' ? IDS_TAB_IDS.has(tab.id) : IPS_TAB_IDS.has(tab.id)).map(tab => {
              const isActive = activeTab === tab.id;
              const statusStr = tabMetrics[tab.id]?.status || 'OK';
              const statusIndicator = statusStr === 'Danger' ? '🔴' : statusStr === 'Warning' ? '🟡' : '🟢';

              return (
                <button
                  key={tab.id}
                  className={`ids-kpi ${isActive ? 'active' : ''}`}
                  style={{
                    cursor: 'pointer',
                    transition: 'all 0.22s cubic-bezier(0.4, 0, 0.2, 1)',
                    border: isActive ? `1px solid ${tab.color}` : '1px solid #172d47',
                    background: isActive ? `${tab.color}15` : 'linear-gradient(145deg, #0d1e33, #0a1728)',
                    boxShadow: isActive ? `0 8px 24px ${tab.color}1c` : '0 8px 22px #02081240',
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                  }}
                  onClick={() => changeTab(tab.id)}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', width: '100%', alignItems: 'center' }}>
                    <label style={{ margin: 0, textTransform: 'uppercase', fontSize: '8px', fontWeight: 650, color: '#7186a2' }}>
                      {tab.icon} {tab.label}
                    </label>
                    <span style={{ fontSize: '9px' }}>{statusIndicator}</span>
                  </div>
                  <strong style={{ color: isActive ? tab.color : '#e7f0fb', fontSize: '23px', margin: '4px 0 2px 0', fontWeight: '800' }}>
                    {tab.id === 'country' && tab.value === null ? '—' : Number(tab.value || 0).toLocaleString()}
                  </strong>
                  <small style={{ color: '#71839b', fontSize: '8px' }}>{tab.sub}</small>
                </button>
              );
            })}
          </div>

          <div className="ids-tabs">
            {TABS.filter(t => activeModule === 'ids' ? IDS_TAB_IDS.has(t.id) : IPS_TAB_IDS.has(t.id)).map(t => (
              <button className={`ids-tab ${activeTab === t.id ? 'active' : ''}`} key={t.id} onClick={() => changeTab(t.id)}>{t.label}</button>
            ))}
          </div>

          {activeTab === 'overview' && <OverviewTab onTabChange={setActiveTab} onOpenReport={openReport} onSeverityFilter={(sev) => { setLogsSeverityInit(sev); changeTab('logs'); }} summary={summary} ipsOnline={ipsOnline} />}
          {activeTab === 'report' && <FullReportTab focus={reportFocus} onBack={() => changeTab('overview')} />}
          {activeTab === 'blocklist' && <BlocklistTab onTabChange={setActiveTab} />}
          {activeTab === 'country' && <CountryBlockTab onRulesChange={setCountryRuleCount} autoRefresh={autoRefresh} />}
          {activeTab === 'threats' && <ThreatsTab onTabChange={setActiveTab} />}
          {activeTab === 'logs' && <LogsTab onTabChange={setActiveTab} initLevel={logsSeverityInit} companyId={companyId} />}
          {activeTab === 'coverage' && <CoverageTab />}
          {activeTab === 'whitelist' && <WhitelistTab onTabChange={setActiveTab} />}
          {activeTab === 'waf' && <WAFTab />}
          {activeTab === 'policy' && <PolicyTab />}
          {activeTab === 'audit' && <AuditLogTab />}
          {activeTab === 'isolationFlow' && <IsolationFlowTab />}
        </div>
      </main>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  POLICY IDS &amp; IPS TAB
// ══════════════════════════════════════════════════════════════════════════════
const POLICY_MODE_COLOR = { block: '#ef4444', detect: '#22c55e' };
const POLICY_SEV_COLOR = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6' };

function PolicyBadge({ label, color }) {
  return (
    <span style={{
      fontSize: 10, fontWeight: 700, padding: '2px 8px', borderRadius: 20,
      color, background: `${color}18`, border: `1px solid ${color}40`,
      letterSpacing: '0.4px', whiteSpace: 'nowrap',
    }}>{label}</span>
  );
}

function PolicyToggle({ enabled, onChange }) {
  return (
    <button
      onClick={onChange}
      title={enabled ? 'Click to disable policy' : 'Click to enable policy'}
      style={{
        position: 'relative', width: 44, height: 24, borderRadius: 12,
        border: 'none', cursor: 'pointer', flexShrink: 0,
        background: enabled ? '#22c55e' : '#1e3a5f',
        transition: 'background 0.2s',
        boxShadow: enabled ? '0 0 8px #22c55e44' : 'none',
      }}
    >
      <span style={{
        position: 'absolute', top: 3, left: enabled ? 23 : 3,
        width: 18, height: 18, borderRadius: '50%', background: '#fff',
        transition: 'left 0.2s', boxShadow: '0 1px 3px #0004',
      }} />
    </button>
  );
}

function PolicyTab() {
  const [data, setData] = useState(null);
  const [policies, setPolicies] = useState([]);
  const [presets, setPresets] = useState([]);
  const [policyAgents, setPolicyAgents] = useState([]);
  const [selectedPresets, setSelectedPresets] = useState([]);
  const [presetMode, setPresetMode] = useState('recommended');
  const [presetSeverity, setPresetSeverity] = useState('recommended');
  const [presetTargetSystemId, setPresetTargetSystemId] = useState('');
  const [applyingPresets, setApplyingPresets] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [actFilter, setActFilter] = useState('all');
  const [showForm, setShowForm] = useState(false);
  const [saving, setSaving] = useState(false);
  const [expandId, setExpandId] = useState(null);
  const [form, setForm] = useState({
    name: '', description: '', sensor: 'any', mode: 'detect', minimumSeverity: 'medium',
    attackPattern: '', protocol: 'any', sourceIp: '', destinationPort: '',
    targetScope: 'all', targetPlatform: 'all', targetSystemId: '',
  });

  const agentPlatform = agent => {
    const value = `${agent?.osType || ''} ${agent?.os || ''} ${agent?.platform || ''} ${agent?.preferredPackageType || ''} ${agent?.agentType || ''}`.toLowerCase();
    if (/win|\.exe|\bexe\b|\bmsi\b/.test(value)) return 'windows';
    if (/android|phone|\bapk\b/.test(value)) return 'android';
    if (/darwin|mac\s*os|macos|os\s*x|macpkg|dmg/.test(value)) return 'macos';
    if (/linux|ubuntu|debian|centos|fedora|rhel|red hat|suse|deb|rpm/.test(value)) return 'linux';
    return 'all';
  };
  const sensorForPlatform = platform => ['windows', 'macos'].includes(platform) ? 'suricata' : 'any';

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError('');
    try {
      const [eventsRes, policiesRes, presetsRes, systemsRes] = await Promise.all([
        api.get('/ids/policy-violations?hours=24&limit=200'),
        api.get('/ids/policies'),
        api.get('/ids/policy-presets'),
        api.get('/system').catch(() => ({ data: [] })),
      ]);
      setData(eventsRes.data);
      setPolicies(policiesRes.data?.policies || []);
      setPresets(presetsRes.data?.presets || []);
      setPolicyAgents((Array.isArray(systemsRes.data) ? systemsRes.data : systemsRes.data?.systems || []).filter(agent => agent.isActive !== false));
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => { load(); const t = setInterval(() => load(true), 30000); return () => clearInterval(t); }, [load]);

  const createPolicy = async e => {
    e.preventDefault();
    if (!form.name.trim()) return;
    if (!form.attackPattern.trim() && !form.sourceIp.trim() && !form.destinationPort) {
      setError('Attack Pattern, Source IP, ya Destination Port me se kam se kam ek match condition required hai.');
      return;
    }
    setSaving(true); setError(''); setNotice('');
    try {
      const { targetScope: _targetScope, ...policyForm } = form;
      await api.post('/ids/policies', { ...policyForm, destinationPort: form.destinationPort ? Number(form.destinationPort) : undefined });
      setForm({ name: '', description: '', sensor: 'any', mode: 'detect', minimumSeverity: 'medium', attackPattern: '', protocol: 'any', sourceIp: '', destinationPort: '', targetScope: 'all', targetPlatform: 'all', targetSystemId: '' });
      setShowForm(false);
      setNotice('Custom policy saved and queued for synchronization to the selected agent OS.');
      await load(true);
    } catch (err) { setError(err.response?.data?.message || err.message); }
    finally { setSaving(false); }
  };

  const applySelectedPresets = async () => {
    if (!selectedPresets.length) return;
    setApplyingPresets(true); setError(''); setNotice('');
    try {
      const targetAgent = policyAgents.find(agent => String(agent._id) === presetTargetSystemId);
      const response = await api.post('/ids/policy-presets/apply', {
        presetIds: selectedPresets,
        ...(presetMode !== 'recommended' ? { mode: presetMode } : {}),
        ...(presetSeverity !== 'recommended' ? { minimumSeverity: presetSeverity } : {}),
        targetPlatform: targetAgent ? agentPlatform(targetAgent) : 'all',
        ...(targetAgent ? { targetSystemId: targetAgent._id } : {}),
      });
      setNotice(`${response.data?.applied || selectedPresets.length} policy preset(s) queued for ${targetAgent ? targetAgent.name || targetAgent.hostname || 'selected agent' : 'compatible AJNAT agents'}.`);
      setSelectedPresets([]);
      setPresetTargetSystemId('');
      await load(true);
    } catch (err) { setError(err.response?.data?.message || err.message); }
    finally { setApplyingPresets(false); }
  };

  const togglePolicy = async policy => {
    try {
      await api.patch(`/ids/policies/${policy._id}`, { enabled: !policy.enabled });
      setPolicies(cur => cur.map(item => item._id === policy._id ? { ...item, enabled: !item.enabled } : item));
    } catch (err) { setError(err.response?.data?.message || err.message); }
  };

  const deletePolicy = async policy => {
    if (!window.confirm(`Delete policy "${policy.name}"?`)) return;
    try {
      await api.delete(`/ids/policies/${policy._id}`);
      setPolicies(cur => cur.filter(item => item._id !== policy._id));
    } catch (err) { setError(err.response?.data?.message || err.message); }
  };

  const events = (data?.events || []).filter(ev => {
    if (sevFilter !== 'all' && ev.severity !== sevFilter) return false;
    if (actFilter === 'blocked' && !ev.blocked) return false;
    if (actFilter === 'detected' && ev.blocked) return false;
    return true;
  });

  const activeCount = policies.filter(p => p.enabled).length;
  const visiblePresets = presets;
  const unappliedPresetIds = visiblePresets
    .filter(preset => !policies.some(policy => policy.presetId === preset.id && policy.enabled))
    .map(preset => preset.id);
  const selectedZeekCount = selectedPresets.filter(id => presets.find(preset => preset.id === id)?.sensor === 'zeek').length;
  const hasCustomMatch = Boolean(form.attackPattern.trim() || form.sourceIp.trim() || form.destinationPort);
  const selectedPresetRows = selectedPresets.map(id => presets.find(preset => preset.id === id)).filter(Boolean);
  const commonPresetPlatforms = selectedPresetRows.length
    ? selectedPresetRows.slice(1).reduce(
      (common, preset) => common.filter(platform => (preset.supportedPlatforms || []).includes(platform)),
      [...(selectedPresetRows[0].supportedPlatforms || [])],
    )
    : [];
  const compatiblePresetAgents = policyAgents.filter(agent => commonPresetPlatforms.includes(agentPlatform(agent)));
  const targetOptions = [
    ['all', 'All AJNAT Agents'],
    ...policyAgents.map(agent => [
      `agent:${agent._id}`,
      agent.name || agent.hostname || agent.systemId || 'Unnamed AJNAT Agent',
    ]),
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 24 }}>

      {/* ── Header ──────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#e2e8f0' }}>🛡️ Policy IDS &amp; IPS</h3>
          <p style={{ margin: '4px 0 0', fontSize: 13, color: '#64748b' }}>
            Predefined policies select karo, phir manually apply karo. Sirf enabled policies hi agents ko synchronize hoti hain.
          </p>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <span style={{ fontSize: 12, color: '#22c55e', fontWeight: 700, background: '#22c55e18', border: '1px solid #22c55e40', borderRadius: 20, padding: '3px 12px' }}>
            ● {activeCount} Active
          </span>
          <button
            onClick={() => setShowForm(v => !v)}
            style={{ padding: '7px 16px', borderRadius: 8, border: '1px solid #3b82f6', background: showForm ? '#1e3a5f' : '#3b82f6', color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer' }}
          >{showForm ? '✕ Cancel' : '+ New Policy'}</button>
          <button onClick={() => load()} disabled={loading} style={{ padding: '7px 14px', borderRadius: 8, border: '1px solid #1e3a5f', background: 'transparent', color: '#94a3b8', fontSize: 13, cursor: 'pointer' }}>↻</button>
        </div>
      </div>


      {error && <div style={{ background: '#ef444418', border: '1px solid #ef4444', borderRadius: 8, padding: '10px 16px', color: '#ef4444', fontSize: 13 }}>{error}</div>}
      {notice && <div style={{ background: '#22c55e18', border: '1px solid #22c55e55', borderRadius: 8, padding: '10px 16px', color: '#86efac', fontSize: 13 }}>{notice}</div>}

      {/* ── Create Policy Form ──────────────────────────────────────────────── */}
      {showForm && (
        <form onSubmit={createPolicy} style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, padding: 20 }}>
          <div style={{ fontSize: 14, fontWeight: 700, color: '#93c5fd', marginBottom: 16 }}>✏️ New Enforcement Policy</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 12 }}>
            {[
              ['Policy Name *', 'text', 'name', 'Block SQL Injection', true, null],
              ['Target OS / Agent', 'select', 'targetScope', null, false, targetOptions],
              ...(form.targetPlatform === 'all' ? [] : [['Sensor', 'select', 'sensor', null, false,
                form.targetPlatform === 'windows' ? [['suricata', 'Suricata + WinDivert']]
                  : form.targetPlatform === 'linux' ? [['any', 'Suricata + Zeek']]
                    : form.targetPlatform === 'macos' ? [['suricata', 'Suricata']]
                      : [['any', 'AJNAT Android VPN IPS']]]]),
              ['Mode', 'select', 'mode', null, false, [['detect', 'IDS: Detect Only'], ['block', 'IDS+IPS: Block']]],
              ['Min. Severity', 'select', 'minimumSeverity', null, false, [['low', 'Low'], ['medium', 'Medium'], ['high', 'High'], ['critical', 'Critical']]],
              ['Attack Pattern', 'text', 'attackPattern', 'sql injection|xss', false, null],
              ['Protocol', 'select', 'protocol', null, false, [['any', 'Any'], ['tcp', 'TCP'], ['udp', 'UDP'], ['http', 'HTTP'], ['https', 'HTTPS'], ['dns', 'DNS']]],
              ['Source IP', 'text', 'sourceIp', '203.0.113.10 (optional)', false, null],
              ['Dest. Port', 'number', 'destinationPort', '443 (optional)', false, null],
              ['Description', 'text', 'description', 'Why this policy is needed', false, null],
            ].map(([label, type, key, placeholder, required, options]) => (
              <label key={key} style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 12, color: '#64748b', fontWeight: 600 }}>
                {label}
                {options ? (
                  <select value={form[key]} onChange={e => {
                    if (key !== 'targetScope') {
                      setForm({ ...form, [key]: e.target.value });
                      return;
                    }
                    const scope = e.target.value;
                    const directAgent = scope.startsWith('agent:')
                      ? policyAgents.find(agent => String(agent._id) === scope.slice(6))
                      : null;
                    const platform = directAgent ? agentPlatform(directAgent) : scope;
                    setForm({
                      ...form,
                      targetScope: scope,
                      targetSystemId: directAgent?._id || '',
                      targetPlatform: platform,
                      sensor: sensorForPlatform(platform),
                    });
                  }}
                    style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 6, color: '#e2e8f0', padding: '6px 10px', fontSize: 13 }}>
                    {options.map(([value, optionLabel]) => <option key={value} value={value}>{optionLabel}</option>)}
                  </select>
                ) : (
                  <input required={required} type={type} value={form[key]} onChange={e => setForm({ ...form, [key]: e.target.value })}
                    placeholder={placeholder}
                    style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 6, color: '#e2e8f0', padding: '6px 10px', fontSize: 13 }} />
                )}
              </label>
            ))}
          </div>
          <div style={{ marginTop: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 12, color: form.mode === 'block' ? '#ef4444' : '#22c55e' }}>
              {form.mode === 'block' ? '⚡ Matching traffic → IPS will BLOCK' : '👁 Matching traffic → IDS alert only'}
            </span>
            <button type="submit" disabled={saving || !form.name.trim() || !hasCustomMatch} style={{ padding: '8px 20px', borderRadius: 8, border: 'none', background: hasCustomMatch ? '#22c55e' : '#243244', color: '#fff', fontWeight: 700, cursor: hasCustomMatch ? 'pointer' : 'not-allowed', fontSize: 13 }}>
              {saving ? 'Saving…' : '✓ Save Policy'}
            </button>
          </div>
        </form>
      )}

      {/* ── Predefined Zeek and Suricata policy catalog ──────────────────── */}
      <section style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', background: '#0c1a2e', borderBottom: '1px solid #1e3a5f' }}>
          <strong style={{ color: '#e2e8f0', fontSize: 15 }}>⚙️ Predefined Zeek, Suricata &amp; WinDivert Policies</strong>
          <div style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>Rule type ke hisaab se automatic deployment: WinDivert → Windows, Zeek → Linux, Suricata → supported desktop agents.</div>
        </div>
        <div style={{ padding: 16, display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(285px, 1fr))', gap: 10 }}>
          {visiblePresets.map(preset => {
            const selected = selectedPresets.includes(preset.id);
            const presetPolicy = policies.find(policy => policy.presetId === preset.id);
            const color = preset.enforcement === 'windivert' ? '#a855f7' : preset.sensor === 'suricata' ? '#f97316' : '#38bdf8';
            const supportedPlatforms = preset.supportedPlatforms || ['linux', 'windows'];
            const platformLabel = supportedPlatforms.length === 1
              ? `${supportedPlatforms[0].toUpperCase()} ONLY`
              : supportedPlatforms.map(platform => platform.toUpperCase()).join(' + ');
            return (
              <label key={preset.id} style={{ padding: 12, borderRadius: 9, cursor: 'pointer', background: selected ? `${color}18` : '#081423', border: `1px solid ${selected ? color : '#172b46'}` }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                  <input type="checkbox" checked={selected} onChange={() => {
                    setSelectedPresets(current => selected ? current.filter(id => id !== preset.id) : [...current, preset.id]);
                    setPresetTargetSystemId('');
                  }} style={{ marginTop: 3 }} />
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                      <b style={{ color, fontSize: 13 }}>{preset.name}</b>
                      {presetPolicy && <PolicyBadge label={presetPolicy.enabled ? 'Active' : 'Disabled'} color={presetPolicy.enabled ? '#22c55e' : '#64748b'} />}
                    </div>
                    <div style={{ color: '#94a3b8', fontSize: 11, lineHeight: 1.45, marginTop: 4 }}>{preset.description}</div>
                    <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                      <PolicyBadge label={preset.defaultMode === 'block' ? '⚡ Block' : '👁 Detect'} color={preset.defaultMode === 'block' ? '#ef4444' : '#22c55e'} />
                      <PolicyBadge label={`${preset.minimumSeverity}+`} color={POLICY_SEV_COLOR[preset.minimumSeverity]} />
                      <PolicyBadge label={String(preset.protocol).toUpperCase()} color="#60a5fa" />
                      {preset.enforcement === 'windivert' && <PolicyBadge label="WINDIVERT" color="#a855f7" />}
                      <PolicyBadge label={platformLabel} color="#a78bfa" />
                    </div>
                  </div>
                </div>
              </label>
            );
          })}
        </div>
        <div style={{ padding: '12px 16px', borderTop: '1px solid #1e3a5f', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span style={{ marginRight: 'auto', color: '#64748b', fontSize: 12 }}>{selectedPresets.length} selected</span>
          {selectedZeekCount > 0 && <span style={{ color: '#fbbf24', fontSize: 12 }}>Zeek selections remain detect-only.</span>}
          <button onClick={() => { setSelectedPresets(unappliedPresetIds); setPresetTargetSystemId(''); }} disabled={!unappliedPresetIds.length} style={{ padding: '7px 10px', border: '1px solid #1e3a5f', borderRadius: 7, background: 'transparent', color: '#93c5fd', cursor: unappliedPresetIds.length ? 'pointer' : 'not-allowed' }}>Select unapplied</button>
          <button onClick={() => { setSelectedPresets([]); setPresetTargetSystemId(''); }} disabled={!selectedPresets.length} style={{ padding: '7px 10px', border: '1px solid #1e3a5f', borderRadius: 7, background: 'transparent', color: '#94a3b8', cursor: selectedPresets.length ? 'pointer' : 'not-allowed' }}>Clear</button>
          <select value={presetMode} onChange={e => setPresetMode(e.target.value)} style={{ background: '#081423', border: '1px solid #1e3a5f', color: '#e2e8f0', borderRadius: 7, padding: '7px 9px' }}>
            <option value="recommended">Recommended mode</option><option value="detect">Detect only</option><option value="block">Block</option>
          </select>
          <select value={presetSeverity} onChange={e => setPresetSeverity(e.target.value)} style={{ background: '#081423', border: '1px solid #1e3a5f', color: '#e2e8f0', borderRadius: 7, padding: '7px 9px' }}>
            <option value="recommended">Recommended severity</option><option value="low">Low+</option><option value="medium">Medium+</option><option value="high">High+</option><option value="critical">Critical</option>
          </select>
          <select value={presetTargetSystemId} onChange={e => setPresetTargetSystemId(e.target.value)} disabled={!selectedPresets.length} title="Choose all compatible agents or one matching agent" style={{ background: '#081423', border: '1px solid #1e3a5f', color: '#e2e8f0', borderRadius: 7, padding: '7px 9px', minWidth: 190 }}>
            <option value="">All AJNAT Agents</option>
            {compatiblePresetAgents.map(agent => <option key={agent._id} value={agent._id}>{agent.name || agent.hostname || agent.systemId || 'Unnamed AJNAT Agent'}</option>)}
          </select>
          <button onClick={applySelectedPresets} disabled={!selectedPresets.length || applyingPresets} style={{ padding: '8px 16px', border: 0, borderRadius: 8, background: selectedPresets.length ? '#22c55e' : '#243244', color: '#fff', fontWeight: 700, cursor: selectedPresets.length ? 'pointer' : 'not-allowed' }}>
            {applyingPresets ? 'Applying…' : '✓ Apply Selected to Agents'}
          </button>
        </div>
      </section>

      {/* ── Policy List ─────────────────────────────────────────────────────── */}
      <section style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', background: '#0c1a2e', borderBottom: '1px solid #1e3a5f', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <strong style={{ fontSize: 14, color: '#93c5fd' }}>📋 Policies — Complete List</strong>
          <span style={{ fontSize: 12, color: '#475569' }}>{policies.length} total · {activeCount} active</span>
        </div>

        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#475569' }}>⏳ Loading policies…</div>
        ) : policies.length === 0 ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#475569' }}>
            <div style={{ fontSize: 36 }}>🛡️</div>
            <div style={{ marginTop: 8 }}>No native IDS/IPS policy is applied yet.</div>
            <div style={{ marginTop: 4, fontSize: 12 }}>Select predefined rules above, then use “Apply Selected to Agents”.</div>
          </div>
        ) : (
          <div>
            {policies.map((policy, idx) => {
              const isExpanded = expandId === policy._id;
              const modeColor = POLICY_MODE_COLOR[policy.mode] || '#64748b';
              const sevColor = POLICY_SEV_COLOR[policy.minimumSeverity] || '#64748b';
              return (
                <div
                  key={policy._id}
                  style={{
                    borderBottom: idx < policies.length - 1 ? '1px solid #0a1628' : 'none',
                    background: policy.enabled ? '#0a1e3a' : 'transparent',
                    transition: 'background 0.2s',
                  }}
                >
                  {/* ── Row ── */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 20px' }}>

                    {/* Toggle */}
                    <PolicyToggle enabled={policy.enabled} onChange={() => togglePolicy(policy)} />

                    {/* Name + summary */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                        <span style={{ fontWeight: 700, fontSize: 14, color: policy.enabled ? '#e2e8f0' : '#64748b' }}>{policy.name}</span>
                        <PolicyBadge label={policy.mode === 'block' ? '⚡ Block' : '👁 Detect'} color={modeColor} />
                        <PolicyBadge label={`${policy.minimumSeverity}+`} color={sevColor} />
                        {policy.sensor && policy.sensor !== 'any' && <PolicyBadge label={policy.sensor === 'zeek' ? 'ZEEK' : 'SURICATA'} color={policy.sensor === 'zeek' ? '#38bdf8' : '#f97316'} />}
                        <PolicyBadge label={policy.targetSystemId
                          ? `🎯 ${policyAgents.find(agent => String(agent._id) === String(policy.targetSystemId))?.name || 'DIRECT AGENT'}`
                          : (policy.targetPlatform || 'all') === 'windows' ? '🪟 WINDOWS' : (policy.targetPlatform || 'all') === 'linux' ? '🐧 LINUX' : policy.targetPlatform === 'macos' ? '🍎 MACOS' : policy.targetPlatform === 'android' ? '🤖 ANDROID' : 'ALL AJNAT AGENTS'} color="#a78bfa" />
                        {policy.protocol && policy.protocol !== 'any' && <PolicyBadge label={String(policy.protocol).toUpperCase()} color="#60a5fa" />}
                        {policy.matchCount > 0 && <PolicyBadge label={`${policy.matchCount} matches`} color="#a855f7" />}
                        <PolicyBadge
                          label={`Deploy: ${policy.deploymentStatus || 'pending'}`}
                          color={({ deployed: '#22c55e', server_enforced: '#22c55e', failed: '#ef4444', partial: '#f59e0b', pending: '#60a5fa' })[policy.deploymentStatus] || '#64748b'}
                        />
                      </div>
                      <div style={{ fontSize: 12, color: '#475569', marginTop: 3 }}>
                        {[
                          policy.attackPattern && `Pattern: "${policy.attackPattern}"`,
                          policy.sourceIp && `Src IP: ${policy.sourceIp}`,
                          policy.destinationPort && `Port: ${policy.destinationPort}`,
                          policy.description,
                        ].filter(Boolean).join(' · ') || 'All traffic — no specific pattern filter'}
                      </div>
                    </div>

                    {/* Status */}
                    <span style={{ fontSize: 12, color: policy.enabled ? '#22c55e' : '#475569', fontWeight: 700, minWidth: 60, textAlign: 'center' }}>
                      {policy.enabled ? '● ON' : '○ OFF'}
                    </span>

                    {/* Expand + Delete */}
                    <button onClick={() => setExpandId(isExpanded ? null : policy._id)}
                      title="Details" style={{ background: 'none', border: 'none', color: '#475569', cursor: 'pointer', fontSize: 16, padding: '0 4px' }}>
                      {isExpanded ? '▲' : '▼'}
                    </button>
                    <button onClick={() => deletePolicy(policy)} title="Delete policy"
                      style={{ background: 'none', border: 'none', color: '#ef4444', cursor: 'pointer', fontSize: 18, padding: '0 4px', opacity: 0.7 }}>×</button>
                  </div>

                  {/* ── Expanded detail ── */}
                  {isExpanded && (
                    <div style={{ padding: '0 20px 16px 78px', display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 10 }}>
                      {[
                        ['Mode', policy.mode === 'block' ? 'Block (IDS+IPS)' : 'Detect Only (IDS)', modeColor],
                        ['Min. Severity', policy.minimumSeverity || '—', sevColor],
                        ['Protocol', String(policy.protocol || 'any').toUpperCase(), '#60a5fa'],
                        ['Sensor', String(policy.sensor || 'any').toUpperCase(), policy.sensor === 'zeek' ? '#38bdf8' : policy.sensor === 'suricata' ? '#f97316' : '#94a3b8'],
                        ['Target', policy.targetSystemId
                          ? policyAgents.find(agent => String(agent._id) === String(policy.targetSystemId))?.name || 'Direct Agent'
                          : `${String(policy.targetPlatform || 'all').toUpperCase()} AGENTS`, '#a78bfa'],
                        ['Attack Pattern', policy.attackPattern || 'Any', '#e2e8f0'],
                        ['Source IP', policy.sourceIp || 'Any', '#e2e8f0'],
                        ['Dest. Port', policy.destinationPort || 'Any', '#e2e8f0'],
                        ['Total Matches', policy.matchCount || 0, '#a855f7'],
                        ['Revision', policy.revision || 1, '#60a5fa'],
                        ['Deployment', policy.deploymentStatus || 'pending', ({ deployed: '#22c55e', server_enforced: '#22c55e', failed: '#ef4444', partial: '#f59e0b' })[policy.deploymentStatus] || '#60a5fa'],
                        ['Agent ACKs', (policy.deploymentAcks || []).length, '#38bdf8'],
                        ['Last Match', policy.lastMatchAt ? new Date(policy.lastMatchAt).toLocaleString() : 'Never', '#64748b'],
                        ['Created', policy.createdAt ? new Date(policy.createdAt).toLocaleDateString() : '—', '#64748b'],
                        ['Status', policy.enabled ? 'Active' : 'Disabled', policy.enabled ? '#22c55e' : '#64748b'],
                      ].map(([label, value, color]) => (
                        <div key={label} style={{ background: '#060e1a', borderRadius: 8, padding: '8px 12px', border: '1px solid #0a1628' }}>
                          <div style={{ fontSize: 10, color: '#475569', marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.4px' }}>{label}</div>
                          <div style={{ fontSize: 13, fontWeight: 600, color }}>{String(value)}</div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* ── KPI Bar ─────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {[
          ['Total Violations (24h)', data?.total || 0, '#60a5fa'],
          ['Blocked by IPS', data?.blocked || 0, '#ef4444'],
          ['Detected by IDS', data?.detected || 0, '#f59e0b'],
          ['Open / Investigating', data?.open || 0, '#c084fc'],
        ].map(([label, value, color]) => (
          <div key={label} style={{ flex: 1, minWidth: 140, background: '#060e1a', border: `1px solid ${color}30`, borderRadius: 10, padding: '12px 16px' }}>
            <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>{label}</div>
            <div style={{ fontSize: 22, fontWeight: 800, color }}>{Number(value).toLocaleString()}</div>
          </div>
        ))}
      </div>

      {/* ── Policy Events Table ─────────────────────────────────────────────── */}
      <section style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 12, overflow: 'hidden' }}>
        <div style={{ padding: '14px 20px', background: '#0c1a2e', borderBottom: '1px solid #1e3a5f', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
          <strong style={{ fontSize: 14, color: '#93c5fd' }}>📊 Policy Violation Events (Last 24h)</strong>
          <div style={{ display: 'flex', gap: 8 }}>
            {[
              [sevFilter, setSevFilter, [['all', 'All Severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]],
              [actFilter, setActFilter, [['all', 'All Actions'], ['blocked', 'Blocked'], ['detected', 'Detected Only']]],
            ].map(([val, setter, opts], i) => (
              <select key={i} value={val} onChange={e => setter(e.target.value)}
                style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 6, color: '#94a3b8', padding: '5px 10px', fontSize: 12 }}>
                {opts.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
              </select>
            ))}
          </div>
        </div>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#060e1a' }}>
                {['Time', 'Severity', 'Rule / Policy', 'Source IP', 'Destination', 'Protocol', 'Status'].map(h => (
                  <th key={h} style={{ padding: '8px 14px', color: '#3b82f6', fontWeight: 700, fontSize: 10, textAlign: 'left', textTransform: 'uppercase', letterSpacing: '0.5px', borderBottom: '1px solid #0a1628' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev._id} style={{ borderBottom: '1px solid #0a1628' }}>
                  <td style={{ padding: '8px 14px', color: '#64748b' }}>{ev.createdAt ? new Date(ev.createdAt).toLocaleString() : '—'}</td>
                  <td style={{ padding: '8px 14px' }}>
                    <PolicyBadge label={ev.severity || 'low'} color={POLICY_SEV_COLOR[ev.severity] || '#64748b'} />
                  </td>
                  <td style={{ padding: '8px 14px' }}>
                    <div style={{ fontWeight: 700, color: '#e2e8f0' }}>{ev.ruleId || 'POLICY_MATCH'}</div>
                    <div style={{ color: '#475569', fontSize: 11 }}>{ev.description || '—'}</div>
                  </td>
                  <td style={{ padding: '8px 14px' }}><code style={{ background: '#0f2040', color: '#60a5fa', padding: '1px 6px', borderRadius: 4 }}>{ev.srcip || ev.agentName || '—'}</code></td>
                  <td style={{ padding: '8px 14px' }}><code style={{ background: '#0f2040', color: '#60a5fa', padding: '1px 6px', borderRadius: 4 }}>{ev.destip ? `${ev.destip}${ev.destPort ? `:${ev.destPort}` : ''}` : '—'}</code></td>
                  <td style={{ padding: '8px 14px', color: '#94a3b8' }}>{String(ev.protocol || '—').toUpperCase()}</td>
                  <td style={{ padding: '8px 14px' }}>
                    <PolicyBadge label={ev.blocked ? '⚡ Blocked' : '👁 Detected'} color={ev.blocked ? '#ef4444' : '#22c55e'} />
                  </td>
                </tr>
              ))}
              {!events.length && (
                <tr><td colSpan={7} style={{ padding: 32, textAlign: 'center', color: '#475569' }}>✓ No policy violations in selected filter</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}

function AuditLogTab() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const auditActions = [
    'Attack Detected',
    'Email Sent',
    'Email Failed',
    'Reminder Sent',
    'Auto Isolation',
    'Recovery Check',
    'Attack Still Active',
    'Isolation Again',
    'Attack Cleared',
    'Server Restored',
    'Manual Override Requested',
    'Manual Override Cancelled',
    'Checklist Submitted',
    'Manual Override Approved',
    'User Actions',
  ];

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/ips-engine/audit?limit=500');
      const auditEvents = data?.events || [];

      const nextRows = auditEvents.map(event => ({
        id: `audit-${event.id || event.ts}`,
        time: event.ts,
        action: event.action || 'User Actions',
        category: ['Auto Isolation', 'Isolation Again', 'Isolation Completed'].includes(event.action) ? 'isolation'
          : ['Recovery Check', 'Attack Still Active', 'Attack Cleared', 'Server Restored', 'Incident Closed'].includes(event.action) ? 'recovery'
            : ['Email Sent', 'Email Failed', 'Reminder Sent'].includes(event.action) ? 'email'
              : ['Manual Override Requested', 'Manual Override Cancelled', 'Checklist Submitted', 'Manual Override Approved'].includes(event.action) ? 'manual'
                : event.action === 'Attack Detected' ? 'detect'
                  : 'user',
        actor: event.actor || 'IPS Engine',
        target: event.target || event.srcIp || '—',
        severity: event.severity || 'info',
        detail: event.detail || event.attackType || event.phase || event.action,
      })).sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0)).slice(0, 500);

      setRows(nextRows);
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => load(true), 30000);
    return () => clearInterval(timer);
  }, [load]);

  const filteredRows = rows.filter(row => filter === 'all' || row.action === filter || row.category === filter);
  const counts = {
    total: rows.length,
    detect: rows.filter(row => row.category === 'detect').length,
    isolation: rows.filter(row => row.category === 'isolation').length,
    recovery: rows.filter(row => row.category === 'recovery').length,
    manual: rows.filter(row => row.category === 'manual').length,
  };
  const actionCounts = Object.fromEntries(auditActions.map(action => [
    action,
    rows.filter(row => row.action === action).length,
  ]));

  return (
    <div className="ids-policy-page ids-audit-page">
      <div className="ids-policy-head">
        <div>
          <h3>Audit Log</h3>
          <p>IDS/IPS detection, blocking, isolation, recovery, email, and manual-response audit events only.</p>
        </div>
        <div className="ids-policy-head-actions">
          <select value={filter} onChange={event => setFilter(event.target.value)}>
            <option value="all">All Audit Events</option>
            {auditActions.map(action => <option key={action} value={action}>{action}</option>)}
            <option value="email">Email / Reminders</option>
            <option value="isolation">Isolation Flow</option>
            <option value="recovery">Recovery Flow</option>
            <option value="manual">Manual Override</option>
          </select>
          <button onClick={() => load()} disabled={loading}>↻ Refresh</button>
        </div>
      </div>

      <div className="ids-policy-kpis">
        {[
          ['Audit Events', counts.total, '#60a5fa', '📋', 'Engine audit trail'],
          ['Attack Detected', counts.detect, '#f59e0b', '🚨', 'Threats detected'],
          ['Isolation Events', counts.isolation, '#ef4444', '🔒', 'Auto-isolated systems'],
          ['Recovery Checks', counts.recovery, '#22c55e', '🔄', 'Recovery checks run'],
          ['Manual Override', counts.manual, '#c084fc', '🛡️', 'Manual override actions'],
        ].map(([label, value, color, icon, sub]) => (
          <div className="ids-policy-kpi" key={label}
            style={label === 'Isolation Events' ? { border: `1px solid ${color}44`, boxShadow: `0 0 12px ${color}22` } : {}}
          >
            <span style={{ fontSize: 16 }}>{icon}</span>
            <span>{label}</span>
            <strong style={{ color, fontSize: label === 'Isolation Events' ? 22 : undefined }}>
              {Number(value).toLocaleString()}
            </strong>
            <small style={{ color: label === 'Isolation Events' && value > 0 ? color : undefined }}>
              {label === 'Isolation Events' && value > 0 ? `⚠ ${value} system${value !== 1 ? 's' : ''} isolated` : sub}
            </small>
          </div>
        ))}
      </div>

      <section className="ids-audit-actions">
        {auditActions.map(action => (
          <button
            type="button"
            key={action}
            className={filter === action ? 'active' : ''}
            onClick={() => setFilter(action)}
          >
            <span>{action}</span>
            <b>{actionCounts[action] || 0}</b>
          </button>
        ))}
      </section>

      <section className="ids-policy-card">
        <div className="ids-policy-toolbar">
          <strong>Automated Response Audit Trail</strong>
          <span>{filteredRows.length} records</span>
        </div>
        {loading ? <Empty icon="⏳" msg="Loading audit log…" /> : error ? (
          <div className="ids-policy-error">{error}</div>
        ) : (
          <div className="ids-policy-table-wrap">
            <table className="ids-policy-table">
              <thead>
                <tr><th>Time</th><th>Action</th><th>Severity</th><th>Actor</th><th>Target</th><th>Details</th></tr>
              </thead>
              <tbody>
                {filteredRows.map(row => (
                  <tr key={row.id}>
                    <td>{row.time ? new Date(row.time).toLocaleString() : '—'}</td>
                    <td><strong>{row.action}</strong><small>{row.category}</small></td>
                    <td><span className={`ids-policy-severity ${String(row.severity || 'low').toLowerCase()}`}>{row.severity || 'info'}</span></td>
                    <td>{row.actor}</td>
                    <td><code>{row.target}</code></td>
                    <td><small>{row.detail}</small></td>
                  </tr>
                ))}
                {!filteredRows.length && <tr><td colSpan="6"><Empty icon="✅" msg="No audit events found" /></td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

function IsolationFlowTab() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [restoringId, setRestoringId] = useState('');

  const load = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    setError('');
    try {
      const { data } = await api.get('/system');
      const nextRows = (Array.isArray(data) ? data : (data?.systems || []))
        .filter(system => system.isIsolated === true || ['pending', 'isolated', 'reconnecting', 'failed'].includes(system.isolationStatus))
        .map(system => ({
          id: system._id,
          time: system.isolatedAt || system.lastIpsCommand?.queuedAt || system.updatedAt,
          status: system.isolationStatus || (system.isIsolated ? 'isolated' : 'none'),
          actor: 'IDS/IPS',
          target: system.ip || system.ipAddress || '—',
          system: system.name || system.hostname || system.agentId || '—',
          reason: system.isolationReason || 'Security isolation',
          error: system.isolationError || '',
          online: system.isOnline,
        }))
        .sort((a, b) => new Date(b.time || 0) - new Date(a.time || 0));
      setRows(nextRows);
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    } finally {
      if (!silent) setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(() => load(true), 30000);
    return () => clearInterval(timer);
  }, [load]);

  useEffect(() => {
    const socket = io(SOCKET_URL, socketOptions);
    const companyId = getCompanyIdFromStorage();
    if (companyId) socket.emit('join:company', companyId);
    const refresh = () => load(true);
    const events = [
      'system:isolated', 'system:isolation_failed', 'system:reconnected',
      'system:reconnect_failed', 'ips:isolationPending', 'ips:isolated',
      'ips:isolationFailed', 'ips:recovered',
    ];
    events.forEach(event => socket.on(event, refresh));
    const releaseSocket = connectSocket(socket);
    return () => {
      events.forEach(event => socket.off(event, refresh));
      releaseSocket();
    };
  }, [load]);

  const restore = async (row) => {
    if (!window.confirm(`Manually remove isolation from ${row.system}?`)) return;
    setRestoringId(row.id);
    setError('');
    try {
      await api.delete(`/system/${row.id}/isolate`);
      await load(true);
    } catch (err) {
      setError(err.response?.data?.message || err.message);
    } finally {
      setRestoringId('');
    }
  };

  const filtered = rows;
  const counts = {
    total: rows.length,
    isolation: rows.filter(row => row.status === 'isolated').length,
    pending: rows.filter(row => row.status === 'pending' || row.status === 'reconnecting').length,
    failed: rows.filter(row => row.status === 'failed').length,
  };

  return (
    <div className="ids-policy-page ids-audit-page">
      <div className="ids-policy-head">
        <div>
          <h3>Isolation Flow</h3>
          <p>Live endpoint isolation state, including commands waiting for agent acknowledgement and failed enforcement.</p>
        </div>
        <div className="ids-policy-head-actions">
          <button onClick={() => load()} disabled={loading}>↻ Refresh</button>
        </div>
      </div>

      <div className="ids-policy-kpis">
        {[
          ['Currently Isolated', counts.isolation, '#ef4444', '🔒', 'Endpoints requiring review'],
          ['Pending Agent ACK', counts.pending, '#f59e0b', '⏳', 'Queued or reconnecting'],
          ['Failed', counts.failed, '#f87171', '⚠️', 'Agent enforcement failed'],
        ].map(([label, value, color, icon, sub]) => (
          <div className="ids-policy-kpi" key={label}>
            <span style={{ fontSize: 16 }}>{icon}</span>
            <span>{label}</span>
            <strong style={{ color }}>{Number(value).toLocaleString()}</strong>
            <small>{sub}</small>
          </div>
        ))}
      </div>

      <section className="ids-policy-card">
        <div className="ids-policy-toolbar">
          <strong>Endpoint Isolation Lifecycle</strong>
          <span>{filtered.length} active records</span>
        </div>
        {loading ? <Empty icon="⏳" msg="Loading isolation flow…" /> : error ? (
          <div className="ids-policy-error">{error}</div>
        ) : (
          <div className="ids-policy-table-wrap">
            <table className="ids-policy-table">
              <thead>
                <tr><th>Isolated At</th><th>Status</th><th>System</th><th>Target/IP</th><th>Reason</th><th>Action</th></tr>
              </thead>
              <tbody>
                {filtered.map(row => (
                  <tr key={row.id}>
                    <td>{row.time ? new Date(row.time).toLocaleString() : '—'}</td>
                    <td><span className={`ids-policy-action ${row.status === 'isolated' ? 'blocked' : ''}`}>{({ pending: 'Pending Agent ACK', isolated: 'Isolated', reconnecting: 'Reconnecting', failed: 'Failed' })[row.status] || row.status}</span></td>
                    <td>{row.system}</td>
                    <td><code>{row.target}</code></td>
                    <td><small>{row.error || row.reason}</small></td>
                    <td><button onClick={() => restore(row)} disabled={restoringId === row.id || row.status !== 'isolated'}>{restoringId === row.id ? 'Restoring…' : '🔓 Manual Unisolate'}</button></td>
                  </tr>
                ))}
                {!filtered.length && <tr><td colSpan="6"><Empty icon="✅" msg="No systems are currently isolated" /></td></tr>}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
//  WAF TAB — Smart WAF status + blocked attacks
// ══════════════════════════════════════════════════════════════════════════════
function WAFTab() {
  const { user, company } = useAuth();
  const companyId = String(company?._id || user?.companyId?._id || user?.companyId || getCompanyIdFromStorage() || '');
  const WAF_WINDOW_HOURS = 24;
  const WAF_WINDOW_LABEL = '24h';
  const WAF_WINDOW_MS = WAF_WINDOW_HOURS * 60 * 60 * 1000;
  const isCurrentWafEvent = useCallback((event = {}) => {
    const timestamp = new Date(event.ts || event.createdAt || event.timestamp || 0).getTime();
    return Number.isFinite(timestamp) && timestamp >= Date.now() - WAF_WINDOW_MS;
  }, [WAF_WINDOW_MS]);
  const [status, setStatus] = useState(null);
  const [attacks, setAttacks] = useState([]);
  const [loading, setLoading] = useState(true);  // true only on first load
  const [err, setErr] = useState('');
  const [autoRefreshSec, setAutoRefreshSec] = useState(10);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [servicePage, setServicePage] = useState(1);
  const [serviceFilter, setServiceFilter] = useState('all');
  const [eventFilter, setEventFilter] = useState('all');
  const [showAllEvents, setShowAllEvents] = useState(false);
  const [showAllAgents, setShowAllAgents] = useState(false);
  const [showIntegration, setShowIntegration] = useState(false);
  const [showWebhookDetails, setShowWebhookDetails] = useState(true);
  const [wafProvider, setWafProvider] = useState('Cloudflare');
  const [integrationMsg, setIntegrationMsg] = useState('');
  const [savingIntegration, setSavingIntegration] = useState(false);
  const [savedIntegration, setSavedIntegration] = useState(null);
  const [connectorToken, setConnectorToken] = useState('');
  const [attackPolicy, setAttackPolicy] = useState({ enabled: true, webAttackBlocking: true, networkAttackBlocking: true, webMinimumSeverity: 'medium', networkMinimumSeverity: 'high' });
  const [savedAttackPolicy, setSavedAttackPolicy] = useState(null);
  const [attackPolicyMsg, setAttackPolicyMsg] = useState('');
  const [savingAttackPolicy, setSavingAttackPolicy] = useState(false);
  const [integrationForm, setIntegrationForm] = useState({
    deploymentType: 'Local / On-server', protectedDomain: '', webServer: 'Nginx',
    logPaths: '', protectedPorts: '80, 443', logFormat: 'JSON', hostname: '', internalIp: '', notes: '', enabled: true,
  });
  const servicePageSize = 5;
  const validWebhookPath = savedIntegration?.webhookPath && !savedIntegration.webhookPath.includes('undefined');
  const webhookEndpoint = validWebhookPath
    ? `${API_BASE_URL.replace(/\/api\/?$/, '')}${savedIntegration.webhookPath}`
    : 'Save configuration to generate a secure webhook URL';
  const providerHelp = {
    Cloudflare: 'Use Logpush to an HTTP destination (or a Worker) and POST each firewall event to this webhook.',
    'AWS WAF': 'Send WAF logs through Firehose/Lambda; the Lambda must POST each JSON event to this webhook.',
    'Azure WAF': 'Route Diagnostic Logs through Event Hub/Function and POST normalized or original JSON events here.',
    'ModSecurity / Nginx': 'Use the AJNAT agent, Filebeat/Fluent Bit, or a small forwarder to POST audit-log events here.',
    'Other / Custom': 'Configure your SIEM/forwarder to POST JSON. A single object, an array, or { events: [...] } is accepted.',
  };

  const copyIntegrationValue = async (value, label) => {
    try {
      await navigator.clipboard.writeText(value);
      setIntegrationMsg(`✅ ${label} copied`);
    } catch {
      setIntegrationMsg(`Copy failed — select and copy the ${label.toLowerCase()} manually.`);
    }
  };

  const sendTestWafEvent = async () => {
    setIntegrationMsg('Sending test event…');
    try {
      await api.post('/waf/integration/test');
      setIntegrationMsg('✅ Bridge test passed. Check Recent WAF Events below.');
      await load();
    } catch (error) {
      setIntegrationMsg(`❌ ${error.response?.data?.message || error.message}`);
    }
  };

  const saveWafIntegration = async () => {
    setSavingIntegration(true);
    setIntegrationMsg('Saving configuration…');
    try {
      const response = await api.put('/waf/integration', { ...integrationForm, provider: wafProvider });
      setSavedIntegration(response.data?.integration || null);
      if (response.data?.connectorToken) {
        setConnectorToken(response.data.connectorToken);
        setShowWebhookDetails(true);
        setIntegrationMsg('✅ Connected. Copy the token now; it will be hidden after you leave this page.');
      } else {
        setIntegrationMsg('✅ Existing WAF configuration updated.');
      }
      setServicePage(1);
      await load();
    } catch (error) {
      setIntegrationMsg(`❌ ${error.response?.data?.message || error.message}`);
    } finally {
      setSavingIntegration(false);
    }
  };

  const rotateConnectorToken = async () => {
    const confirmation = await Swal.fire({
      icon: 'warning',
      title: 'Rotate Connector Token?',
      html: '<div style="text-align:left;line-height:1.6"><p>Naya security token generate hoga aur <b>purana token turant disable</b> ho jayega.</p><p>Is option ko sirf tab use karein jab token leak, lost ya replace karna ho.</p><p style="color:#fbbf24">Rotate karne ke baad naya token apne WAF/forwarder mein update karna zaroori hai.</p></div>',
      showCancelButton: true,
      confirmButtonText: 'Rotate Token',
      cancelButtonText: 'Cancel',
      confirmButtonColor: '#dc2626',
      cancelButtonColor: '#334155',
      background: '#0c1a2e',
      color: '#e2e8f0',
      reverseButtons: true,
      focusCancel: true,
    });
    if (!confirmation.isConfirmed) return;
    setIntegrationMsg('Rotating connector token…');
    try {
      const response = await api.post('/waf/integration/rotate-token');
      setConnectorToken(response.data.connectorToken || '');
      setSavedIntegration(current => ({ ...(current || {}), webhookPath: response.data.webhookPath, tokenConfigured: true }));
      setShowWebhookDetails(true);
      setIntegrationMsg('✅ New token created. Copy it now; it is shown only once.');
    } catch (error) {
      setIntegrationMsg(`❌ ${error.response?.data?.message || error.message}`);
    }
  };

  const saveAttackProtectionPolicy = async () => {
    setSavingAttackPolicy(true);
    setAttackPolicyMsg('Applying attack protection…');
    try {
      const response = await api.put('/waf/attack-protection-policy', attackPolicy);
      setAttackPolicy(current => ({ ...current, ...(response.data?.policy || {}) }));
      setSavedAttackPolicy(response.data?.policy || attackPolicy);
      setAttackPolicyMsg('✅ Saved. Agents receive it on the next heartbeat. Ports stay open; malicious source traffic is blocked.');
    } catch (error) {
      setAttackPolicyMsg(`❌ ${error.response?.data?.message || error.message}`);
    } finally {
      setSavingAttackPolicy(false);
    }
  };

  const deleteAttackRule = async (ruleId, label) => {
    const confirmation = await Swal.fire({
      icon: 'warning',
      title: `Delete ${label}?`,
      text: 'Attack detection and port monitoring continue, but this automatic blocking rule will be disabled.',
      showCancelButton: true,
      confirmButtonText: 'Delete Rule',
      cancelButtonText: 'Cancel',
      confirmButtonColor: '#dc2626',
      background: '#0c1a2e',
      color: '#e2e8f0',
    });
    if (!confirmation.isConfirmed) return;
    setAttackPolicyMsg(`Deleting ${ruleId}…`);
    try {
      const response = await api.delete(`/waf/attack-protection-policy/${encodeURIComponent(ruleId)}`);
      const policy = response.data?.policy || {};
      setAttackPolicy(current => ({ ...current, ...policy }));
      setSavedAttackPolicy(current => ({ ...(current || {}), ...policy }));
      setAttackPolicyMsg(`✅ ${ruleId} deleted. Agents will stop applying it after the next heartbeat.`);
    } catch (error) {
      setAttackPolicyMsg(`❌ ${error.response?.data?.message || error.message}`);
    }
  };

  // Stable refs — never change, avoids useEffect re-trigger
  const hasLoaded = useRef(false); // track if first load is done
  const integrationLoaded = useRef(false);
  const attackPolicyLoaded = useRef(false);

  // load defined with useCallback([]) — stable forever
  const load = useCallback(async () => {
    // On first load: show spinner. On subsequent polls: silent update (keep old data visible)
    if (!hasLoaded.current) setLoading(true);
    setErr('');
    try {
      // ── Use direct backend WAF endpoints (works for all company users) ────────
      // Falls back to IDS alert data if no dedicated WAF events exist
      const [st, atk, integration, attackProtectionPolicy] = await Promise.allSettled([
        api.get(`/waf/status?hours=${WAF_WINDOW_HOURS}`),
        api.get(`/waf/attacks?limit=50&hours=${WAF_WINDOW_HOURS}`),
        integrationLoaded.current ? Promise.resolve(null) : api.get('/waf/integration'),
        attackPolicyLoaded.current ? Promise.resolve(null) : api.get('/waf/attack-protection-policy'),
      ]);
      if (st.status === 'fulfilled') setStatus(st.value.data);
      const directAttacks = atk.status === 'fulfilled' && Array.isArray(atk.value.data?.attacks)
        ? atk.value.data.attacks.filter(isCurrentWafEvent)
        : [];
      const attackRows = directAttacks.length
        ? directAttacks
        : st.status === 'fulfilled' && Array.isArray(st.value.data?.recentAttacks)
          ? st.value.data.recentAttacks.filter(isCurrentWafEvent)
          : null;
      if (attackRows) setAttacks(attackRows);
      if (integration.status === 'fulfilled' && integration.value) {
        integrationLoaded.current = true;
        if (integration.value.data?.integration) {
          const saved = integration.value.data.integration;
          setSavedIntegration(saved);
          setWafProvider(saved.provider || 'Cloudflare');
          setIntegrationForm(current => ({ ...current, ...saved }));
        }
      }
      if (!attackPolicyLoaded.current && attackProtectionPolicy.status === 'fulfilled' && attackProtectionPolicy.value.data?.policy) {
        const policy = attackProtectionPolicy.value.data.policy;
        setAttackPolicy(current => ({ ...current, ...policy }));
        setSavedAttackPolicy(policy);
        attackPolicyLoaded.current = true;
      }
      if (st.status === 'rejected' && atk.status === 'rejected') {
        throw st.reason || atk.reason;
      }
      setLastUpdated(new Date());
      hasLoaded.current = true;  // mark first load done
    } catch (e) {
      setErr(`Cannot reach WAF realtime feed — ${e.response?.data?.message || e.message}`);
    } finally { setLoading(false); }
  }, [companyId, isCurrentWafEvent]);

  // Empty deps [] — runs once on mount, cleans up on unmount
  useEffect(() => {
    load();
    const t = setInterval(load, Math.max(10, autoRefreshSec) * 1000);
    return () => clearInterval(t);
  }, [load, autoRefreshSec]);

  // Enforce a strict rolling window in the browser as well. This removes a
  // row automatically when it becomes 24 hours old, without waiting for a
  // navigation or manual refresh. MongoDB keeps the event for audit history.
  useEffect(() => {
    const pruneExpiredEvents = () => {
      const cutoff = Date.now() - WAF_WINDOW_MS;
      setAttacks(current => current.filter(event => {
        const timestamp = new Date(event.ts || event.createdAt || event.timestamp || 0).getTime();
        return Number.isFinite(timestamp) && timestamp >= cutoff;
      }));
    };
    pruneExpiredEvents();
    const timer = setInterval(pruneExpiredEvents, 60 * 1000);
    return () => clearInterval(timer);
  }, [WAF_WINDOW_MS]);

  useEffect(() => {
    const sock = io(SOCKET_URL);
    
    const blockBuffer = createEventBuffer((blockedEvents) => {
      setAttacks(prev => {
        const cutoff = Date.now() - WAF_WINDOW_MS;
        const liveEvents = blockedEvents.filter(event => {
          const timestamp = new Date(event.ts || event.createdAt || event.timestamp || 0).getTime();
          return Number.isFinite(timestamp) && timestamp >= cutoff;
        });
        const existingIds = new Set(liveEvents.map(x => x._id));
        const filteredPrev = prev.filter(item => !existingIds.has(item._id));
        return [...liveEvents, ...filteredPrev].slice(0, 50);
      });
      setLastUpdated(new Date());
      load();
    }, 1200);

    const onAgent = () => {
      setLastUpdated(new Date());
      load();
    };

    if (companyId) sock.emit('join:company', companyId);
    sock.on('waf:block', blockBuffer.add);
    sock.on('waf:agent', onAgent);
    const disconnectSocket = connectSocket(sock);

    return () => {
      sock.off('waf:block', blockBuffer.add);
      sock.off('waf:agent', onAgent);
      blockBuffer.clear();
      disconnectSocket();
    };
  }, [companyId, load, WAF_WINDOW_MS]);

  const LC = { critical: '#f87171', high: '#f59e0b', medium: '#fbbf24', low: '#34d399', info: '#60a5fa' };
  const byType = status?.stats24h?.byType || [];
  const topIPs = status?.stats24h?.topIPs || [];
  const PORT_NAMES = { 80: 'HTTP', 443: 'HTTPS', 3000: 'Node.js', 3001: 'Superadmin', 3002: 'IPS Dashboard', 4000: 'Node.js', 5000: 'Backend API', 5050: 'IPS Server', 5173: 'Vite', 8000: 'Django/Flask', 8080: 'HTTP Alt', 8443: 'HTTPS Alt', 8834: 'Nessus', 9000: 'PHP-FPM', 9090: 'Prometheus', 9392: 'Greenbone/OpenVAS' };
  const services = (status?.agents || []).flatMap((agent, ai) => {
    const allPorts = agent.allPorts || agent.ports || [];
    const serviceDetails = Array.isArray(agent.services) ? agent.services : [];
    const listenerDetails = Array.isArray(agent.listeners) ? agent.listeners : [];
    const detailsByPort = new Map(serviceDetails.map(detail => [Number(detail.port), detail]));
    const portStatus = agent.portStatus || [];
    const statusMap = Object.fromEntries(portStatus.map(p => [p.port, p.alive]));
    const hasReportedPortStatus = port => Object.prototype.hasOwnProperty.call(statusMap, port);
    if (listenerDetails.length) return listenerDetails.map((detail, pi) => ({
      agent, ai, pi, port: Number(detail.port), detail,
      alive: agent.online !== false,
      observedAt: agent.listenerInventoryAt || agent.lastWafReportAt || agent.lastSeen,
      isWebMonitored: (agent.ports || []).map(Number).includes(Number(detail.port)),
      portName: `${String(detail.protocol || 'tcp').toUpperCase()} Listener`,
    }));
    if (!allPorts.length) return [{ agent, ai, empty: true }];
    return allPorts.map((port, pi) => ({
      agent, ai, pi, port,
      detail: detailsByPort.get(Number(port)) || null,
      isWebMonitored: true,
      alive: agent.online !== false && (!hasReportedPortStatus(port) || statusMap[port] !== false),
      observedAt: portStatus.find(report => Number(report.port) === Number(port))?.observedAt || agent.lastWafReportAt || agent.lastSeen,
      portName: detailsByPort.get(Number(port))?.scheme?.toUpperCase() || PORT_NAMES[port] || 'HTTP Service',
    }));
  });
  const filteredServices = services.filter(service => {
    if (serviceFilter === 'waf') return !service.empty && service.isWebMonitored;
    if (serviceFilter === 'host') return !service.empty && !service.isWebMonitored;
    if (serviceFilter === 'online') return !service.empty && service.alive;
    if (serviceFilter === 'offline') return service.empty || !service.alive;
    return true;
  });
  const activeAgents = status?.activeAgents ?? (status?.agents || []).length;
  const protectedPorts = status?.totalPortsProtected ?? services.filter(s => !s.empty && s.alive && s.isWebMonitored).length;
  const listeningPorts = status?.totalListeningPorts ?? services.filter(s => !s.empty && s.alive).length;
  const blocked24h = status?.stats24h?.blocked ?? attacks.filter(a => a.blocked !== false).length;
  const requests24h = status?.stats24h?.requests ?? status?.requests24h ?? status?.totalRequests24h ?? 0;
  const blockedPct = requests24h ? (blocked24h / requests24h) * 100 : 0;
  const agentHealth = activeAgents > 0 && (status?.agents || []).every(agent => agent.online !== false);
  const attackColors = ['#ef4444', '#f97316', '#facc15', '#22c55e', '#6366f1'];
  const sortedAttackTypes = byType
    .map(row => ({ label: String(row.type || 'Unknown Attack'), count: Number(row.count || 0) }))
    .filter(row => row.count > 0)
    .sort((a, b) => b.count - a.count);
  const attackTypes = sortedAttackTypes.slice(0, 4).map((row, index) => ({ ...row, color: attackColors[index] }));
  const otherAttackCount = sortedAttackTypes.slice(4).reduce((sum, row) => sum + row.count, 0);
  if (otherAttackCount > 0) attackTypes.push({ label: 'Other Attacks', count: otherAttackCount, color: attackColors[4] });
  const currentAttacks = attacks.filter(isCurrentWafEvent);
  const filteredAttacks = currentAttacks.filter(event => (
    eventFilter === 'blocked' ? event.blocked !== false
      : eventFilter === 'detected' ? event.blocked === false
        : true
  ));
  const recentEvents = filteredAttacks.length ? filteredAttacks.slice(0, showAllEvents ? 50 : 5).map(a => ({
    time: a.ts ? new Date(a.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—',
    event: a.attackType || 'Blocked Attack',
    source: a.ip || a.srcIp || '—',
    url: a.requestPath || '/',
    rule: a.ruleId || a.id || 'WAF',
    action: a.blocked === false ? 'Detected' : 'Blocked',
    severity: a.severity || 'high',
  })) : [];
  const trafficSeries = status?.stats24h?.traffic || status?.traffic24h || status?.traffic || [];
  const maxTraffic = Math.max(1, ...trafficSeries.map(p => p.requests || p.total || p.allowed || 0));
  const trafficLine = trafficSeries.length
    ? trafficSeries.map((p, i) => `${i / Math.max(1, trafficSeries.length - 1) * 360},${110 - ((p.requests || p.total || p.allowed || 0) / maxTraffic) * 88}`).join(' ')
    : `0,110 360,110`;
  const trafficArea = `M${trafficLine.replaceAll(' ', 'L')}L360,120L0,120Z`;
  const fmtUptime = (agent) => {
    if (agent.uptime) return agent.uptime;
    if (!agent.lastSeen) return '—';
    const mins = Math.max(0, Math.floor((Date.now() - new Date(agent.lastSeen).getTime()) / 60000));
    return mins < 60 ? `${mins}m since seen` : `${Math.floor(mins / 60)}h ${mins % 60}m since seen`;
  };

  useEffect(() => { setServicePage(1); }, [serviceFilter]);
  useEffect(() => { setShowAllEvents(false); }, [eventFilter]);

  return (
    <div className="ids-waf">
      <div className="ids-waf-head">
        <div>
          <h3>🔥 Web Application Firewall</h3>
          <p>AJNAT WAF + Suricata web signatures; external/cloud WAF connections are optional.</p>
        </div>
        <div className="ids-waf-actions">
          <button onClick={() => setShowIntegration(value => !value)}>{showIntegration ? 'Close Setup' : '＋ Add Existing WAF'}</button>
          <button onClick={load}>↻ Refresh</button>
          <select value={autoRefreshSec} onChange={e => setAutoRefreshSec(Number(e.target.value))}>
            <option value="10">Auto Refresh: 10s</option>
            <option value="30">Auto Refresh: 30s</option>
            <option value="60">Auto Refresh: 60s</option>
          </select>
        </div>
      </div>

      <section className="ids-waf-card ids-waf-port-policy">
        <div className="ids-waf-card-head">
          <div><strong>🛡 Attack Protection</strong><small>Choose which threats agents should block automatically</small></div>
          <em className={attackPolicy.enabled ? 'block' : 'off'}>● {attackPolicy.enabled ? 'PREVENTION ACTIVE' : 'DETECT ONLY'}</em>
        </div>
        <div className="ids-waf-port-policy-body">
          <label className="ids-waf-switch-row ids-waf-protection-master">
            <input type="checkbox" checked={attackPolicy.enabled} onChange={event => setAttackPolicy(policy => ({ ...policy, enabled: event.target.checked }))} />
            <span><b>Automatically block threats</b><small>Off karne par agents sirf detect aur alert karenge.</small></span>
          </label>
          <div className="ids-waf-protection-options">
            <div className={!attackPolicy.enabled ? 'disabled' : ''}>
              <label className="ids-waf-switch-row">
                <input type="checkbox" checked={attackPolicy.webAttackBlocking} disabled={!attackPolicy.enabled} onChange={event => setAttackPolicy(policy => ({ ...policy, webAttackBlocking: event.target.checked }))} />
                <span><b>Web attacks</b><small>SQLi, XSS, LFI/RFI and command injection</small></span>
              </label>
              <label>Block severity
                <select value={attackPolicy.webMinimumSeverity} disabled={!attackPolicy.enabled || !attackPolicy.webAttackBlocking} onChange={event => setAttackPolicy(policy => ({ ...policy, webMinimumSeverity: event.target.value }))}>
                  <option value="low">Low and above</option><option value="medium">Medium and above</option><option value="high">High and critical</option><option value="critical">Critical only</option>
                </select>
              </label>
            </div>
            <div className={!attackPolicy.enabled ? 'disabled' : ''}>
              <label className="ids-waf-switch-row">
                <input type="checkbox" checked={attackPolicy.networkAttackBlocking} disabled={!attackPolicy.enabled} onChange={event => setAttackPolicy(policy => ({ ...policy, networkAttackBlocking: event.target.checked }))} />
                <span><b>Network attacks</b><small>Exploit, C2, malware, scan and brute-force</small></span>
              </label>
              <label>Block severity
                <select value={attackPolicy.networkMinimumSeverity} disabled={!attackPolicy.enabled || !attackPolicy.networkAttackBlocking} onChange={event => setAttackPolicy(policy => ({ ...policy, networkMinimumSeverity: event.target.value }))}>
                  <option value="low">Low and above</option><option value="medium">Medium and above</option><option value="high">High and critical</option><option value="critical">Critical only</option>
                </select>
              </label>
            </div>
          </div>
          <div className="ids-waf-port-policy-actions">
            <button onClick={saveAttackProtectionPolicy} disabled={savingAttackPolicy}>{savingAttackPolicy ? 'Applying…' : 'Save Policy'}</button>
            <span>Applies on next agent heartbeat · Service ports remain open</span>
            {attackPolicyMsg && <span>{attackPolicyMsg}</span>}
          </div>
          <div className="ids-waf-active-rules">
            <div className="ids-waf-active-rules-head">
              <b>Active Attack-Blocking Rules</b>
              <span>{savedAttackPolicy?.enabled !== false ? '● Applied' : '● Detection only'}</span>
            </div>
            {savedAttackPolicy?.webAttackBlocking !== false && <div className="ids-waf-rule-row">
              <code>WAF-WEB-AUTO-BLOCK</code>
              <span>HTTP/HTTPS · SQLi, XSS, LFI/RFI, command injection and web signatures</span>
              <em>≥ {(savedAttackPolicy?.webMinimumSeverity || 'medium').toUpperCase()}</em>
              <strong>{savedAttackPolicy?.enabled !== false && savedAttackPolicy?.webAttackBlocking !== false ? 'BLOCK SOURCE IP' : 'DETECT ONLY'}</strong>
              <button className="ids-waf-rule-delete" onClick={() => deleteAttackRule('WAF-WEB-AUTO-BLOCK', 'Web Auto-Block Rule')}>Delete</button>
            </div>}
            {savedAttackPolicy?.networkAttackBlocking !== false && <div className="ids-waf-rule-row">
              <code>IPS-NETWORK-AUTO-BLOCK</code>
              <span>All monitored TCP/UDP ports · exploit, C2, malware, scan and brute-force signatures</span>
              <em>≥ {(savedAttackPolicy?.networkMinimumSeverity || 'high').toUpperCase()}</em>
              <strong>{savedAttackPolicy?.enabled !== false ? 'BLOCK SOURCE IP' : 'DETECT ONLY'}</strong>
              <button className="ids-waf-rule-delete" onClick={() => deleteAttackRule('IPS-NETWORK-AUTO-BLOCK', 'Network Auto-Block Rule')}>Delete</button>
            </div>}
            {savedAttackPolicy?.webAttackBlocking === false && savedAttackPolicy?.networkAttackBlocking === false && <div className="ids-waf-rules-empty">No automatic blocking rules active. Enable a rule above and save to restore it.</div>}
            <div className="ids-waf-rule-note">Destination service port remains open. Loopback, private and protected infrastructure addresses are not automatically blocked.</div>
          </div>
        </div>
      </section>

      {showIntegration && (
        <section className="ids-waf-card ids-waf-integration">
          <div className="ids-waf-card-head">
            <div><strong>Connect Existing WAF</strong><small>Forward blocked-request events; your current WAF remains the enforcement layer.</small></div>
            {savedIntegration && <small className="ids-waf-connection-state">● {savedIntegration.enabled === false ? 'Disabled' : 'Configured'}{savedIntegration.lastEventAt ? ` · Last event ${new Date(savedIntegration.lastEventAt).toLocaleString()}` : ''}</small>}
          </div>
          <div className="ids-waf-integration-body">
            <div className="ids-waf-connect-steps">
              <strong>How to connect</strong>
              <span><b>1</b> Provider aur protected system details fill karein.</span>
              <span><b>2</b> <em>Save & Generate Connection</em> click karein.</span>
              <span><b>3</b> Generated Webhook URL aur one-time token apne WAF/forwarder mein paste karein.</span>
              <span><b>4</b> <em>Test Connection</em> click karke event verify karein.</span>
            </div>
            <label>WAF Provider
              <select value={wafProvider} onChange={event => setWafProvider(event.target.value)}>
                {['Cloudflare', 'AWS WAF', 'ModSecurity / Nginx', 'Azure WAF', 'Other / Custom'].map(provider => <option key={provider}>{provider}</option>)}
              </select>
            </label>
            <label>Deployment
              <select value={integrationForm.deploymentType} onChange={event => setIntegrationForm(form => ({ ...form, deploymentType: event.target.value }))}>
                <option>Local / On-server</option><option>Cloud / Managed</option><option>Reverse Proxy</option>
              </select>
            </label>
            <label>Protected Domain
              <input value={integrationForm.protectedDomain} onChange={event => setIntegrationForm(form => ({ ...form, protectedDomain: event.target.value }))} placeholder="app.example.com" />
            </label>
            <label>Web Server
              <select value={integrationForm.webServer} onChange={event => setIntegrationForm(form => ({ ...form, webServer: event.target.value }))}>
                {['Nginx', 'Apache', 'IIS', 'Cloud managed', 'Other'].map(value => <option key={value}>{value}</option>)}
              </select>
            </label>
            <label>WAF Log Path(s)
              <input value={integrationForm.logPaths} onChange={event => setIntegrationForm(form => ({ ...form, logPaths: event.target.value }))} placeholder="/var/log/modsec_audit.log" />
            </label>
            <label>Protected Ports
              <input value={integrationForm.protectedPorts} onChange={event => setIntegrationForm(form => ({ ...form, protectedPorts: event.target.value }))} placeholder="80, 443" />
              <small>Comma-separated ports save hote hi Monitored Services mein add honge. Koi proxy listener create nahi hoga.</small>
            </label>
            <label>Log Format
              <select value={integrationForm.logFormat} onChange={event => setIntegrationForm(form => ({ ...form, logFormat: event.target.value }))}>
                {['JSON', 'ModSecurity Audit', 'Nginx', 'Apache', 'CEF', 'Plain text'].map(value => <option key={value}>{value}</option>)}
              </select>
            </label>
            <label>Server Hostname
              <input value={integrationForm.hostname} onChange={event => setIntegrationForm(form => ({ ...form, hostname: event.target.value }))} placeholder="web-server-01" />
            </label>
            <label>Internal IP
              <input value={integrationForm.internalIp} onChange={event => setIntegrationForm(form => ({ ...form, internalIp: event.target.value }))} placeholder="10.0.0.20" />
            </label>
            <label className="ids-waf-integration-notes">Notes
              <textarea value={integrationForm.notes} onChange={event => setIntegrationForm(form => ({ ...form, notes: event.target.value }))} placeholder="Customer-specific log forwarding notes (no passwords or secrets)" />
            </label>
            <div className="ids-waf-advanced-toggle">
              <button onClick={() => setShowWebhookDetails(value => !value)}>{showWebhookDetails ? 'Hide Connection Details' : 'Show Connection Details'}</button>
              <span>Cloud WAF ke liye webhook use karein; local ModSecurity/Nginx ke liye agent ya log forwarder use ho sakta hai.</span>
            </div>
            {showWebhookDetails && (
              <div className="ids-waf-webhook-details">
                <div><span>Secure Webhook URL</span><code>{webhookEndpoint}</code><button disabled={!validWebhookPath} onClick={() => copyIntegrationValue(webhookEndpoint, 'Webhook URL')}>Copy</button></div>
                <div className="ids-waf-token-card">
                  <span>Connector Token <small>Shown only when generated</small></span>
                  <code>{connectorToken || (savedIntegration ? 'Token hidden for security' : 'Save configuration first')}</code>
                  <div className="ids-waf-card-actions">
                    {connectorToken && <button onClick={() => copyIntegrationValue(connectorToken, 'Connector Token')}>Copy Token</button>}
                    {savedIntegration && <button className="danger" onClick={rotateConnectorToken}>Rotate Token</button>}
                  </div>
                </div>
                <div className="ids-waf-headers-card">
                  <span>Required Headers</span>
                  <code><b>Authorization</b><i>{`Bearer ${connectorToken || '<CONNECTOR_TOKEN>'}`}</i><b>Content-Type</b><i>application/json</i></code>
                  <button onClick={() => copyIntegrationValue(`Authorization: Bearer ${connectorToken || '<CONNECTOR_TOKEN>'}\nContent-Type: application/json`, 'Required Headers')}>Copy Headers</button>
                </div>
                <div className="ids-waf-payload-example"><span>Example JSON</span><code>{`{\n  "id": "provider-event-id",\n  "timestamp": "${new Date().toISOString()}",\n  "clientIp": "203.0.113.10",\n  "action": "blocked",\n  "ruleId": "SQLI-001",\n  "attackType": "SQL Injection",\n  "requestPath": "/login",\n  "method": "POST",\n  "severity": "high"\n}`}</code></div>
              </div>
            )}
            <p><strong>{wafProvider}:</strong> {providerHelp[wafProvider]} Company identity is resolved from the connector token, so the sender cannot choose another tenant.</p>
            <div className="ids-waf-integration-actions">
              <button onClick={saveWafIntegration} disabled={savingIntegration}>{savingIntegration ? 'Generating…' : savedIntegration?.tokenConfigured ? 'Update Configuration' : 'Save & Generate Connection'}</button>
              <button onClick={sendTestWafEvent} disabled={!savedIntegration}>Test Connection</button>
              {integrationMsg && <span>{integrationMsg}</span>}
            </div>
          </div>
        </section>
      )}

      {loading && <Empty icon="⏳" msg="Loading WAF status…" />}
      {err && <div style={{ color: '#f87171', fontSize: 13, marginBottom: 12 }}>❌ {err}</div>}

      {!loading && status && (
        <>
          <div className="ids-waf-kpis">
            {[
              { icon: '🤖', label: 'Active WAF Agents', val: activeAgents, color: '#22c55e', note: agentHealth ? 'All agents are healthy' : 'Some agents need attention' },
              { icon: '🌐', label: 'Open Ports Monitored', val: listeningPorts, color: '#0ea5e9', note: `${protectedPorts} web port(s) under WAF inspection` },
              { icon: '🛡', label: `Attacks Blocked (${WAF_WINDOW_LABEL})`, val: blocked24h, color: '#ef4444', note: blocked24h ? 'Threats blocked' : 'No attacks blocked' },
              { icon: '▣', label: `WAF Events (${WAF_WINDOW_LABEL})`, val: requests24h.toLocaleString(), color: '#a855f7', note: requests24h ? 'Stored WAF reports' : 'Waiting for WAF reports' },
            ].map((k, i) => (
              <div className="ids-waf-kpi" key={i} style={{ borderColor: `${k.color}45` }}>
                <i style={{ color: k.color, borderColor: `${k.color}66`, boxShadow: `0 0 20px ${k.color}22` }}>{k.icon}</i>
                <div><span>{k.label}</span><strong>{k.val}</strong><small style={{ color: k.color }}>↳ {k.note}</small></div>
              </div>
            ))}
          </div>

          <div className="ids-waf-layout">
            <div className="ids-waf-left">
              <section className="ids-waf-card ids-waf-services">
                <div className="ids-waf-card-head">
                  <div><strong>🛡 Port Monitoring</strong><small>Current listeners and recent inventory ({WAF_WINDOW_LABEL}). Offline entries show history, not active monitoring.</small></div>
                  <select value={serviceFilter} onChange={event => setServiceFilter(event.target.value)}>
                    <option value="all">All Services</option>
                    <option value="waf">WAF Protected</option>
                    <option value="host">Host Monitor Only</option>
                    <option value="online">Online</option>
                    <option value="offline">Offline / Stopped</option>
                  </select>
                </div>
                <div className="ids-waf-table-wrap">
                  <table className="ids-waf-table">
                    <thead><tr>{['Server / Hostname', 'IP Address', 'Port', 'Process / Bind', 'Monitoring Mode', 'Status', 'Last Port Report'].map(h => <th key={h}>{h}</th>)}</tr></thead>
                    <tbody>
                      {filteredServices.length === 0 ? (
                        <tr><td colSpan="7"><Empty icon="🔍" msg="No ports match this filter in the current time window" /></td></tr>
                      ) : filteredServices.slice((servicePage - 1) * servicePageSize, servicePage * servicePageSize).map((s, i) => s.empty ? (
                        <tr key={`empty-${s.ai}`}><td>▱ {s.agent.hostname || s.agent.systemId || `Agent ${s.ai + 1}`}</td><td>{s.agent.agentIP || '—'}</td><td colSpan="5">No active HTTP/HTTPS listener detected on this agent</td></tr>
                      ) : (
                        <tr key={`${s.ai}-${s.pi}`}>
                          <td>{s.pi === 0 ? `▱ ${s.agent.hostname || s.agent.systemId || `Agent ${s.ai + 1}`}` : ''}{s.pi === 0 && s.agent.autoConnected && <b>AUTO-CONNECTED</b>}</td>
                          <td>{s.pi === 0 ? s.agent.agentIP || '—' : ''}</td>
                          <td><code className="blue">:{s.port}</code><span>{s.portName}</span>{s.alive && <i />}</td>
                          <td><strong>{s.detail?.processName || (s.agent.configuredIntegration ? s.agent.agentVersion : 'Process pending')}</strong><small>{s.detail?.bindAddress || s.agent.agentIP || 'Bind address pending'}{s.detail?.pid ? ` · PID ${s.detail.pid}` : ''}</small></td>
                          <td><strong>{!s.alive ? 'Not currently monitoring' : s.agent.configuredIntegration ? 'Configured WAF' : s.isWebMonitored ? 'WAF + Host Monitor' : 'Host Port Monitor'}</strong><small>{s.agent.online === false ? 'Last reported inventory; current port state is unknown' : !s.alive ? 'Port reported closed' : s.isWebMonitored ? 'HTTP/HTTPS inspection active' : 'Listener exposure and policy monitoring'}</small></td>
                          <td><em className={s.alive ? 'ok' : 'bad'}>{s.agent.online === false ? '● Agent offline' : s.alive ? '● Monitoring' : '● Stopped'}</em></td>
                          <td>{s.observedAt ? new Date(s.observedAt).toLocaleString() : '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="ids-waf-table-foot">
                  <span>Showing {filteredServices.length === 0 ? 0 : (servicePage - 1) * servicePageSize + 1} to {Math.min(servicePage * servicePageSize, filteredServices.length)} of {filteredServices.length} services</span>
                  <div>
                    <button onClick={() => setServicePage(p => Math.max(1, p - 1))} disabled={servicePage === 1}>‹</button>
                    {Array.from({ length: Math.ceil(filteredServices.length / servicePageSize) || 1 }, (_, i) => i + 1).map(n => (
                      <button key={n} className={n === servicePage ? 'active' : ''} onClick={() => setServicePage(n)}>{n}</button>
                    ))}
                    <button onClick={() => setServicePage(p => Math.min(Math.ceil(filteredServices.length / servicePageSize) || 1, p + 1))} disabled={servicePage === (Math.ceil(filteredServices.length / servicePageSize) || 1)}>›</button>
                  </div>
                </div>
              </section>

              <section className="ids-waf-card ids-waf-events">
                <div className="ids-waf-card-head">
                  <div><strong>♻ Recent WAF Events</strong><small>Latest firewall events and detections</small></div>
                  <select value={eventFilter} onChange={event => setEventFilter(event.target.value)}>
                    <option value="all">All Events</option>
                    <option value="blocked">Blocked</option>
                    <option value="detected">Detected Only</option>
                  </select>
                </div>
                <div className="ids-waf-table-wrap">
                  <table className="ids-waf-table ids-waf-events-table">
                    <thead><tr>{['Time', 'Event', 'Source IP', 'URL', 'Rule / ID', 'Action', 'Severity'].map(h => <th key={h}>{h}</th>)}</tr></thead>
                    <tbody>
                      {recentEvents.map((event, i) => (
                        <tr key={i}>
                          <td>{event.time}</td>
                          <td><span className={event.action === 'Blocked' ? 'blocked' : 'allowed'}>♙ {event.event}</span></td>
                          <td>{event.source}</td>
                          <td>{event.url}</td>
                          <td>{event.rule}</td>
                          <td>{event.action}</td>
                          <td><em className={`sev ${event.severity}`}>{event.severity}</em></td>
                        </tr>
                      ))}
                      {recentEvents.length === 0 && (
                        <tr><td colSpan="7"><Empty icon="✅" msg="No WAF events received yet" /></td></tr>
                      )}
                    </tbody>
                  </table>
                  {filteredAttacks.length > 5 && <button className="ids-waf-view-all" onClick={() => setShowAllEvents(value => !value)}>{showAllEvents ? 'Show Latest 5' : `View All ${filteredAttacks.length} Events →`}</button>}
                </div>
              </section>
            </div>

            <div className="ids-waf-right">
              <section className="ids-waf-card ids-waf-summary">
                <div className="ids-waf-card-head"><div><strong>Attack Summary ({WAF_WINDOW_LABEL})</strong></div><select><option>Last 24 Hours</option></select></div>
                <div className="ids-waf-summary-body">
                  <div className="ids-waf-donut" style={{ '--total': `"${blocked24h}"` }}><span>Attacks Blocked</span></div>
                  <div className="ids-waf-legend">
                    {attackTypes.length ? attackTypes.map(t => <div key={t.label}><i style={{ background: t.color }} /> <span>{t.label}</span><b>{t.count} ({blocked24h ? Math.round(t.count / blocked24h * 100) : 0}%)</b></div>) : <p className="ids-muted-note">No blocked attack types</p>}
                  </div>
                </div>
              </section>

              <section className="ids-waf-card ids-waf-traffic">
                <div className="ids-waf-card-head"><div><strong>Traffic Overview ({WAF_WINDOW_LABEL})</strong></div></div>
                <div className="ids-waf-traffic-stats">
                  <div><span>♧ WAF Events ({WAF_WINDOW_LABEL})</span><strong>{requests24h.toLocaleString()}</strong><small>{trafficSeries.length ? 'event series' : 'no series'}</small></div>
                  <div className="blocked"><span>Attacks Blocked ({WAF_WINDOW_LABEL})</span><strong>{blocked24h}</strong><small>{blockedPct.toFixed(1)}%</small></div>
                </div>
                <svg viewBox="0 0 360 120" preserveAspectRatio="none" className="ids-waf-chart">
                  <path d={trafficArea} fill="#2563eb55" />
                  <polyline points={trafficLine} fill="none" stroke="#2f77ff" strokeWidth="2" />
                </svg>
                <div className="ids-waf-chart-legend"><span><i /> WAF events received</span></div>
              </section>

              <section className="ids-waf-card ids-waf-agents">
                <div className="ids-waf-card-head"><div><strong>WAF Agents</strong><small>{agentHealth ? 'All agents are running healthy' : activeAgents ? 'Some agents need attention' : 'No online WAF agent'}</small></div></div>
                <table className="ids-waf-table">
                  <thead><tr>{['Agent Name', 'IP Address', 'Status', 'Uptime'].map(h => <th key={h}>{h}</th>)}</tr></thead>
                  <tbody>
                    {(status.agents || []).slice(0, showAllAgents ? undefined : 4).map((agent, i) => (
                      <tr key={i}>
                        <td>{agent.hostname || agent.systemId || `WAF-AGENT-0${i + 1}`}</td>
                        <td>{agent.agentIP || '—'}</td>
                        <td><em className={agent.online === false ? 'bad' : 'ok'}>● {agent.online === false ? 'Offline' : 'Online'}</em></td>
                        <td>{fmtUptime(agent)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {(status.agents || []).length > 4 && <button className="ids-waf-view-all" onClick={() => setShowAllAgents(value => !value)}>{showAllAgents ? 'Show Latest 4' : `View All ${(status.agents || []).length} Agents →`}</button>}
              </section>
            </div>
          </div>
        </>
      )}

      {!loading && !status && !err && (
        <div style={{ ...C.card, textAlign: 'center', border: '1px solid #22c55e33' }}>
          <div style={{ fontSize: 36, margin: '8px 0' }}>🔥</div>
          <div style={{ color: '#60a5fa', fontWeight: 700 }}>WAF is active on agent systems</div>
          <div style={{ color: '#64748b', fontSize: 12, marginTop: 4 }}>Auto-detecting web services. Attacks will appear here in real-time.</div>
        </div>
      )}
      <div className="ids-waf-footer"><span>● {agentHealth ? 'All systems are operational' : 'Realtime feed active'}</span><span>◷ Data updated: {lastUpdated ? lastUpdated.toLocaleTimeString() : '—'}</span></div>
    </div>
  );
}
