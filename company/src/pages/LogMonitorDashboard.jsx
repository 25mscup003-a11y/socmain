import { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io, createEventBuffer, throttle } from '../api/config';
import { useAuth } from '../context/AuthContext';

// ── Palette ────────────────────────────────────────────────────────────────────
const SEV   = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
const SEVBG = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b' };

// ── Source label mapping (eventCategory → display label) ─────────────────────
const SOURCE_LABELS = {
  network:  'Firewall',
  ids:      'IDS',
  ips:      'IPS',
  edr:      'EDR',
  malware:  'EDR',
  file:     'EDR',
  usb:      'EDR',
  system:   'Syslog',
  auth:     'IDS',
  siem:     'SIEM',
};
function getSourceLabel(eventCategory, source) {
  if (source) {
    const s = source.toLowerCase();
    if (s.includes('firewall') || s.includes('pfsense') || s.includes('opnsense') || s.includes('ufw') || s.includes('iptables')) return 'Firewall';
    if (s.includes('ids') || s.includes('suricata') || s.includes('zeek')) return 'IDS';
    if (s.includes('ips')) return 'IPS';
    if (s.includes('edr') || s.includes('agent')) return 'EDR';
    if (s.includes('siem')) return 'SIEM';
  }
  return SOURCE_LABELS[eventCategory] || eventCategory || '—';
}

const ALL_SOURCES = ['All', 'Firewall', 'IDS', 'IPS', 'EDR', 'Syslog', 'SIEM'];
const ALL_SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

// ── Mini sparkline ────────────────────────────────────────────────────────────
function Timeline({ data = [] }) {
  if (!data || data.length < 2) return (
    <div style={{ color: '#1e3a5f', fontSize: 11, padding: '12px 0' }}>No data for selected period</div>
  );
  const vals = data.map(d => d.count || 0);
  const max  = Math.max(...vals, 1);
  const H = 60;
  return (
    <div style={{ overflowX: 'auto' }}>
      <svg width="100%" height={H + 24} style={{ display: 'block' }} viewBox={`0 0 100 ${H + 24}`} preserveAspectRatio="none">
        <defs>
          <linearGradient id="lmGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#3b82f6" stopOpacity="0.35" />
            <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polyline
          points={vals.map((v, i) => `${(i / (vals.length - 1)) * 100} ${H - (v / max) * H}`).join(' ')}
          fill="none" stroke="#3b82f6" strokeWidth="1.5" strokeLinejoin="round"
        />
        <polygon
          points={[
            ...vals.map((v, i) => `${(i / (vals.length - 1)) * 100} ${H - (v / max) * H}`),
            `100 ${H}`, `0 ${H}`,
          ].join(' ')}
          fill="url(#lmGrad)"
        />
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#1e3a5f', marginTop: 4 }}>
        {[data[0]?._id, data[Math.floor(data.length / 2)]?._id, data[data.length - 1]?._id]
          .filter(Boolean).map((t, i) => (
            <span key={i}>{String(t).replace('T', ' ').replace(':00', '')}</span>
          ))}
      </div>
    </div>
  );
}

function HBar({ label, value, max, color }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 6 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>
        <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '70%' }}>{label}</span>
        <span style={{ color, fontWeight: 600 }}>{value}</span>
      </div>
      <div style={{ height: 5, background: '#0a1220', borderRadius: 4, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: color, borderRadius: 4, transition: 'width .4s' }} />
      </div>
    </div>
  );
}

function SevBadge({ sev }) {
  return (
    <span style={{
      fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 600,
      background: SEVBG[sev] || '#1e3a5f', color: SEV[sev] || '#93c5fd',
    }}>{sev || '—'}</span>
  );
}

function SourceBadge({ label }) {
  const colors = {
    Firewall: { bg:'#1e3a5f', fg:'#93c5fd' },
    IDS:      { bg:'#3b0764', fg:'#d8b4fe' },
    IPS:      { bg:'#7f1d1d', fg:'#fca5a5' },
    EDR:      { bg:'#064e3b', fg:'#6ee7b7' },
    Syslog:   { bg:'#1e293b', fg:'#94a3b8' },
    SIEM:     { bg:'#1c1917', fg:'#d6d3d1' },
  };
  const c = colors[label] || { bg: '#1e293b', fg: '#94a3b8' };
  return (
    <span style={{ fontSize:9, padding:'2px 6px', borderRadius:4, background:c.bg, color:c.fg, fontWeight:600 }}>
      {label}
    </span>
  );
}

function Panel({ title, icon, badge, children, minW = 240 }) {
  return (
    <div style={{
      background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
      padding: '14px 16px', flex: '1', minWidth: minW,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: '#e2e8f0' }}>{icon} {title}</span>
        {badge && (
          <span style={{
            fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
            background: 'rgba(239,68,68,.18)', color: '#f87171', border: '1px solid rgba(239,68,68,.35)',
          }}>{badge}</span>
        )}
      </div>
      {children}
    </div>
  );
}

const ROLE_LABEL = {
  superadmin:       '🌐 Super Admin — all companies',
  company_admin:    '🏢 Company Admin — company-wide logs',
  department_admin: '🏬 Department Admin — department logs',
  analyst:          '🔍 Analyst — read-only filtered view',
};
const ROLE_COLOR = {
  superadmin: '#f59e0b', company_admin: '#60a5fa', department_admin: '#a78bfa', analyst: '#34d399',
};

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function LogMonitorDashboard() {
  const { user } = useAuth();

  // Filters
  const [hours,    setHours]    = useState(24);
  const [ip,       setIp]       = useState('');
  const [status,   setStatus]   = useState('');
  const [severity, setSeverity] = useState('');      // NEW: severity filter
  const [source,   setSource]   = useState('All');   // NEW: source/type filter
  const [dateFrom, setDateFrom] = useState('');      // NEW: date-from filter
  const [dateTo,   setDateTo]   = useState('');      // NEW: date-to filter

  // Data
  const [stats,   setStats]   = useState(null);
  const [live,    setLive]    = useState(false);
  const [liveLog, setLiveLog] = useState([]);

  // ── Build query params ────────────────────────────────────────────────────
  const buildQuery = useCallback(() => {
    const params = { hours };
    if (ip)       params.ip     = ip;
    if (status)   params.status = status;
    if (severity) params.severity = severity;
    // Map source to eventCategory for backend filter
    const srcMap = { Firewall:'network', IDS:'ids', IPS:'ips', EDR:'edr', Syslog:'system', SIEM:'siem' };
    if (source !== 'All') params.eventCategory = srcMap[source] || source.toLowerCase();
    if (dateFrom) params.fromDate = dateFrom;
    if (dateTo)   params.toDate   = dateTo;
    return new URLSearchParams(params);
  }, [hours, ip, status, severity, source, dateFrom, dateTo]);

  // ── Fetch stats ───────────────────────────────────────────────────────────
  const fetchStats = useCallback(async () => {
    try {
      const r = await api.get(`/log-monitor/stats?${buildQuery()}`);
      setStats(r.data);
    } catch (e) { console.error('[log-monitor]', e); }
  }, [buildQuery]);

  // ── Auto-refresh ──────────────────────────────────────────────────────────
  useEffect(() => {
    fetchStats();
    const t = setInterval(fetchStats, 30000);
    return () => clearInterval(t);
  }, [fetchStats]);

  const throttledFetchStats = useCallback(
    throttle(fetchStats, 10000),
    [fetchStats]
  );

  // ── Socket.IO ─────────────────────────────────────────────────────────────
  useEffect(() => {
    const sock = io(SOCKET_URL);
    sock.on('connect',    () => setLive(true));
    sock.on('disconnect', () => setLive(false));
    sock.emit('join:company', user?.companyId);

    const liveLogBuffer = createEventBuffer((newAlerts) => {
      setLiveLog(prev => [...newAlerts, ...prev].slice(0, 10));
      throttledFetchStats();
    }, 1200);

    sock.on('alert:new', liveLogBuffer.add);

    // Initialize live log with recent stream data
    const initializeLiveLog = async () => {
      try {
        const q = new URLSearchParams({ ...Object.fromEntries(buildQuery()), page: 1, limit: 10 });
        const r = await api.get(`/log-monitor/stream?${q}`);
        if (r.data.alerts && r.data.alerts.length > 0) {
          setLiveLog(r.data.alerts);
        }
      } catch (e) {
        console.error('[live-log] init error:', e);
      }
    };
    initializeLiveLog();

    const disconnectSocket = connectSocket(sock);
    return () => {
      sock.off('alert:new', liveLogBuffer.add);
      liveLogBuffer.clear();
      disconnectSocket();
    };
  }, [user, buildQuery, throttledFetchStats]);

  const isAnalyst = user?.role === 'analyst';

  return (
    <div style={{ fontFamily: 'system-ui, sans-serif', color: '#e2e8f0' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, color: '#e0f2fe' }}>🖥️ Log Monitoring</h2>
          <div style={{ fontSize: 11, color: ROLE_COLOR[user?.role] || '#60a5fa', marginTop: 4 }}>
            {ROLE_LABEL[user?.role] || user?.role}
            {isAnalyst && <span style={{ marginLeft: 8, color: '#64748b' }}>· Read-only</span>}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', display: 'inline-block',
                          background: live ? '#34d399' : '#6b7280' }} />
            <span style={{ color: live ? '#34d399' : '#6b7280' }}>{live ? 'Live' : 'Connecting…'}</span>
          </div>

          <button onClick={() => { fetchStats(); fetchStream(stPage); }}
            style={{ fontSize: 11, padding: '4px 10px', borderRadius: 4, border: '1px solid #1e3a5f',
                     background: 'none', color: '#60a5fa', cursor: 'pointer' }}>↺ Refresh</button>
        </div>
      </div>

      {/* ── Filters Bar ── */}
      <div style={{
        background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
        padding: '14px 16px', marginBottom: 18,
        display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center',
      }}>

        {/* Time range */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>⏱ Time:</span>
          {[1, 6, 24, 48, 168].map(h => (
            <button key={h} onClick={() => setHours(h)} style={{
              fontSize: 10, padding: '3px 9px', borderRadius: 4, cursor: 'pointer',
              background: hours === h ? '#1d4ed8' : 'transparent',
              border: `1px solid ${hours === h ? '#1d4ed8' : '#1e3a5f'}`,
              color: hours === h ? '#fff' : '#64748b',
            }}>{h === 168 ? '7d' : `${h}h`}</button>
          ))}
        </div>

        {/* Severity filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>🔴 Severity:</span>
          {ALL_SEVERITIES.map(s => (
            <button key={s || 'all'} onClick={() => setSeverity(s)} style={{
              fontSize: 10, padding: '3px 9px', borderRadius: 4, cursor: 'pointer',
              background: severity === s ? (SEV[s] || '#1d4ed8') : 'transparent',
              border: `1px solid ${severity === s ? (SEV[s] || '#1e3a5f') : '#1e3a5f'}`,
              color: severity === s ? '#fff' : (SEV[s] || '#64748b'),
            }}>{s || 'All'}</button>
          ))}
        </div>

        {/* Source / type filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>📡 Source:</span>
          {ALL_SOURCES.map(s => (
            <button key={s} onClick={() => setSource(s)} style={{
              fontSize: 10, padding: '3px 9px', borderRadius: 4, cursor: 'pointer',
              background: source === s ? '#1d4ed8' : 'transparent',
              border: `1px solid ${source === s ? '#1d4ed8' : '#1e3a5f'}`,
              color: source === s ? '#fff' : '#64748b',
            }}>{s}</button>
          ))}
        </div>

        {/* IP filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>🌐 IP:</span>
          <input value={ip} onChange={e => setIp(e.target.value)} placeholder="Filter by IP…"
            style={{ fontSize: 11, padding: '4px 8px', borderRadius: 4,
                     background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0', width: 120 }} />
        </div>

        {/* Date range */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>📅 From:</span>
          <input type="date" value={dateFrom} onChange={e => setDateFrom(e.target.value)}
            style={{ fontSize: 11, padding: '3px 6px', borderRadius: 4,
                     background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0' }} />
          <span style={{ fontSize: 11, color: '#64748b' }}>To:</span>
          <input type="date" value={dateTo} onChange={e => setDateTo(e.target.value)}
            style={{ fontSize: 11, padding: '3px 6px', borderRadius: 4,
                     background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0' }} />
        </div>

        {/* Status filter */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 11, color: '#64748b' }}>📌 Status:</span>
          {['', 'success', 'failed'].map(s => (
            <button key={s} onClick={() => setStatus(s)} style={{
              fontSize: 10, padding: '3px 9px', borderRadius: 4, cursor: 'pointer',
              background: status === s ? '#1d4ed8' : 'transparent',
              border: `1px solid ${status === s ? '#1d4ed8' : '#1e3a5f'}`,
              color: status === s ? '#fff' : '#64748b',
            }}>{s || 'All'}</button>
          ))}
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
        {[
          { icon: '📄', label: 'Total Logs',     val: stats?.total,                 color: '#93c5fd' },
          { icon: '🔴', label: 'Critical',        val: stats?.severity?.critical,    color: SEV.critical },
          { icon: '🟠', label: 'High',            val: stats?.severity?.high,        color: SEV.high },
          { icon: '🟡', label: 'Medium',          val: stats?.severity?.medium,      color: SEV.medium },
          { icon: '🟢', label: 'Low',             val: stats?.severity?.low,         color: SEV.low },
          { icon: '🚫', label: 'Failed Logins',   val: stats?.failedLogins,          color: '#f59e0b' },
        ].map(({ icon, label, val, color }) => (
          <div key={label} style={{
            flex:'1', minWidth:110, background:'#0c1a2e',
            border:`1px solid ${color}33`, borderRadius:10, padding:'12px 14px',
          }}>
            <div style={{ fontSize: 24, fontWeight: 700, color }}>{val ?? '—'}</div>
            <div style={{ fontSize: 10, color: '#1e40af', marginTop: 2 }}>{icon} {label}</div>
          </div>
        ))}
      </div>

      {/* ── Charts Row ── */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>

        <Panel title="Alerts Over Time" icon="📈" minW={320}
          badge={stats?.total > 0 ? `${stats.total} events` : null}>
          <Timeline data={stats?.overTime} />
        </Panel>

        <Panel title="By Source Type" icon="📡" minW={220}>
          {(stats?.byCategory || []).length === 0
            ? <div style={{ color: '#1e3a5f', fontSize: 12 }}>No data.</div>
            : (stats.byCategory || []).map(({ _id, count }) => (
              <HBar key={_id} label={getSourceLabel(_id, '')} value={count}
                    max={stats.byCategory[0]?.count || 1} color="#a78bfa" />
            ))}
        </Panel>

        <Panel title="Top Source IPs" icon="🌐" minW={220}>
          {(stats?.topIps || []).length === 0
            ? <div style={{ color: '#1e3a5f', fontSize: 12 }}>No IP data.</div>
            : (stats.topIps || []).map(({ _id, count }) => (
              <HBar key={_id} label={_id} value={count} max={stats.topIps[0]?.count || 1} color="#3b82f6" />
            ))}
        </Panel>
      </div>

      {/* ── Alerts + Live Feed ── */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>

        <Panel title="Suspicious Activity" icon="⚠️"
          badge={stats?.suspiciousCount > 0 ? `${stats.suspiciousCount} suspicious` : null} minW={280}>
          <div style={{ display: 'flex', gap: 16, marginBottom: 14, flexWrap: 'wrap' }}>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: '#f87171' }}>{stats?.failedLogins ?? '—'}</div>
              <div style={{ fontSize: 10, color: '#64748b' }}>Failed logins</div>
            </div>
            <div style={{ textAlign: 'center' }}>
              <div style={{ fontSize: 32, fontWeight: 700, color: '#f59e0b' }}>{stats?.suspiciousCount ?? '—'}</div>
              <div style={{ fontSize: 10, color: '#64748b' }}>Critical + High</div>
            </div>
          </div>
          {(stats?.suspiciousCount ?? 0) > 5 && (
            <div style={{ background:'rgba(239,68,68,.12)', border:'1px solid rgba(239,68,68,.3)',
                          borderRadius:8, padding:'8px 12px', fontSize:11, color:'#fca5a5' }}>
              🚨 High suspicious activity — review immediately.
            </div>
          )}
          {(stats?.failedLogins ?? 0) > 10 && (
            <div style={{ background:'rgba(245,158,11,.12)', border:'1px solid rgba(245,158,11,.3)',
                          borderRadius:8, padding:'8px 12px', fontSize:11, color:'#fcd34d', marginTop:8 }}>
              ⚠️ Possible brute-force: {stats.failedLogins} failed logins in {hours}h.
            </div>
          )}
        </Panel>

        <Panel title="Live Event Feed" icon="🔴" minW={320}
          badge={liveLog.length > 0 ? `${liveLog.length} new` : null}>
          {liveLog.length === 0
            ? <div style={{ color:'#1e3a5f', fontSize:11 }}>Waiting for live events… (WebSocket: {live ? '✅' : '⏳'})</div>
            : liveLog.map((a, i) => (
              <div key={i} style={{ borderBottom:'1px solid #060e1a', padding:'5px 0',
                                    display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:6 }}>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:11, color:'#e2e8f0', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                    {a.description || 'Security event'}
                  </div>
                  <div style={{ fontSize:9, color:'#1e40af', marginTop:1 }}>
                    {a.agentName || '—'} · {new Date(a.createdAt || Date.now()).toLocaleTimeString()}
                  </div>
                </div>
                <div style={{ display:'flex', gap:4, alignItems:'center' }}>
                  <SourceBadge label={getSourceLabel(a.eventCategory, a.source)} />
                  <SevBadge sev={a.severity} />
                </div>
              </div>
            ))}
        </Panel>
      </div>

      {isAnalyst && (
        <div style={{ background:'rgba(52,211,153,.08)', border:'1px solid rgba(52,211,153,.25)',
                      borderRadius:8, padding:'10px 14px', fontSize:11, color:'#6ee7b7' }}>
          🔍 Analyst mode: data is scoped to your department. Read-only.
        </div>
      )}
    </div>
  );
}
