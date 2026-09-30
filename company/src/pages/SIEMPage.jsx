import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io, createEventBuffer, throttle } from '../api/config';
import { useAuth } from '../context/AuthContext';

const SOURCE_META = {
  agent:      { icon: '🖥️', label: 'Agent',       color: '#60a5fa' },
  suricata:   { icon: '🔍', label: 'Suricata IDS', color: '#f59e0b' },
  zeek:       { icon: '🦈', label: 'Zeek NSM',     color: '#60a5fa' },
  pfsense:    { icon: '🔥', label: 'pfSense FW',   color: '#f87171' },
  opnsense:   { icon: '🔥', label: 'OPNsense',     color: '#f87171' },
  iptables:   { icon: '🧱', label: 'iptables',     color: '#f97316' },
  nginx:      { icon: '🌐', label: 'Nginx',        color: '#34d399' },
  apache:     { icon: '🌐', label: 'Apache',       color: '#34d399' },
  syslog:     { icon: '📋', label: 'Syslog',       color: '#64748b' },
  default:    { icon: '📡', label: 'Source',       color: '#1e40af' },
};

function sourceMeta(src = '') {
  const s = src.toLowerCase();
  for (const [key, v] of Object.entries(SOURCE_META)) {
    if (s.includes(key)) return v;
  }
  return SOURCE_META.default;
}

function LiveFeed({ logs = [], hasFilters = false }) {
  const ref = useRef(null);
  
  // Auto-scroll to top when new logs arrive
  useEffect(() => { 
    if (ref.current && logs.length > 0) {
      ref.current.scrollTop = 0;
    }
  }, [logs]);

  return (
    <div ref={ref} style={{ height: 340, overflowY: 'auto', fontFamily: 'monospace', fontSize: 10.5 }}>
      {logs.length === 0 && (
        <div style={{ color: '#1e3a5f', textAlign: 'center', paddingTop: 60 }}>
          {hasFilters ? 'No logs match the selected filters…' : 'No logs yet — waiting for events…'}
        </div>
      )}
      {logs.map((l, i) => {
        const m = sourceMeta(l.source || l.logType);
        const levelColor = { critical: '#f87171', error: '#f87171', warning: '#f59e0b',
          info: '#64748b', debug: '#475569' }[l.level] || '#64748b';
        return (
          <div key={l._id || `log-${i}`} style={{ display: 'flex', gap: 8, padding: '4px 10px',
            background: i % 2 === 0 ? '#04090f' : 'transparent',
            borderLeft: `2px solid ${m.color}44` }}>
            <span style={{ color: '#475569', minWidth: 56, flexShrink: 0 }}>
              {new Date(l.receivedAt || l.createdAt || l.logTime).toLocaleTimeString('en-GB', { hour12: false })}
            </span>
            <span style={{ color: m.color, minWidth: 14, textAlign: 'center' }}>{m.icon}</span>
            <span style={{ color: levelColor, minWidth: 46, flexShrink: 0, textTransform: 'uppercase', fontSize: 9 }}>[{l.level?.slice(0,4) || 'INFO'}]</span>
            <span style={{ color: '#94a3b8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {l.message || l.description || ''}
            </span>
            <span style={{ color: m.color, fontSize: 9, flexShrink: 0 }}>{l.source || l.logType}</span>
          </div>
        );
      })}
    </div>
  );
}

function SourceTile({ source, count, meta }) {
  const m = meta || sourceMeta(source);
  return (
    <div style={{ background: '#0c1a2e', border: `1px solid ${m.color}33`, borderRadius: 8,
      padding: '10px 14px', textAlign: 'center' }}>
      <div style={{ fontSize: 20, marginBottom: 4 }}>{m.icon}</div>
      <div style={{ fontSize: 20, fontWeight: 800, color: m.color }}>{count || 0}</div>
      <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>{m.label}</div>
    </div>
  );
}

const CATEGORIES = [
  { id: 'edr',      label: 'EDR Agent',       icon: '💻', color: '#38bdf8', match: ['edr', 'agent', 'winlog', 'process', 'hash', 'script'] },
  { id: 'ids_ips',  label: 'IDS / IPS',       icon: '🛡️', color: '#f59e0b', match: ['ids', 'suricata', 'zeek', 'ips', 'snort'] },
  { id: 'firewall', label: 'Firewall',        icon: '🔥', color: '#f87171', match: ['firewall', 'pfsense', 'opnsense', 'iptables', 'fw'] },
  { id: 'web_net',  label: 'Web & Network',   icon: '🌐', color: '#34d399', match: ['web', 'webserver', 'nginx', 'apache', 'network', 'http', 'dns'] },
  { id: 'auth',     label: 'Auth & Access',   icon: '🔑', color: '#c084fc', match: ['auth', 'ssh', 'login', 'iam', 'sudo'] },
  { id: 'system',   label: 'System & Syslog', icon: '⚙️', color: '#94a3b8', match: ['system', 'syslog', 'kernel', 'os', 'cloud', 'database'] },
];

function getCategoryCounts(logs = [], logStats = null) {
  const counts = { edr: 0, ids_ips: 0, firewall: 0, web_net: 0, auth: 0, system: 0 };
  const sources = logStats?.bySource || [];
  const types = logStats?.byType || [];

  if (sources.length > 0 || types.length > 0) {
    [...sources, ...types].forEach(item => {
      const name = (item._id || '').toLowerCase();
      const val = item.count || 0;
      let matched = false;
      for (const cat of CATEGORIES) {
        if (cat.match.some(m => name.includes(m))) {
          counts[cat.id] += val;
          matched = true;
          break;
        }
      }
      if (!matched && val > 0) {
        counts.system += val;
      }
    });
  }

  const totalFromStats = Object.values(counts).reduce((a, b) => a + b, 0);
  if (totalFromStats === 0 && logs.length > 0) {
    logs.forEach(l => {
      const src = (l.source || l.logType || l.eventCategory || '').toLowerCase();
      let matched = false;
      for (const cat of CATEGORIES) {
        if (cat.match.some(m => src.includes(m))) {
          counts[cat.id]++;
          matched = true;
          break;
        }
      }
      if (!matched) {
        counts.system++;
      }
    });
  }

  return counts;
}

function CategoryDistributionChart({ categoryCounts = {}, totalLogs = 1, onCategoryClick }) {
  const total = Math.max(Object.values(categoryCounts).reduce((a, b) => a + b, 0), 1);

  return (
    <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', flex: 1, minWidth: 300 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#e0f2fe', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 15 }}>📊</span> Category Log Breakdown
        </div>
        <span style={{ fontSize: 10, color: '#64748b' }}>Live Distribution</span>
      </div>

      {/* Stacked Percentage Bar */}
      <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', background: '#060e1a', marginBottom: 14, border: '1px solid #1e3a5f' }}>
        {CATEGORIES.map(cat => {
          const count = categoryCounts[cat.id] || 0;
          const pct = ((count / total) * 100).toFixed(1);
          if (count === 0) return null;
          return (
            <div key={cat.id} title={`${cat.label}: ${count} (${pct}%)`} style={{ width: `${pct}%`, background: cat.color, transition: 'width 0.4s ease' }} />
          );
        })}
      </div>

      {/* Category Horizontal Bars */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 14px' }}>
        {CATEGORIES.map(cat => {
          const count = categoryCounts[cat.id] || 0;
          const pct = Math.round((count / total) * 100);
          return (
            <div key={cat.id} onClick={() => onCategoryClick(cat.id)}
              style={{ cursor: 'pointer', padding: '5px 8px', borderRadius: 6, background: '#060e1a44', border: '1px solid #1e3a5f44', transition: 'all 0.2s' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 12 }}>{cat.icon}</span>
                  <strong style={{ fontWeight: 600, fontSize: 11 }}>{cat.label}</strong>
                </span>
                <span style={{ color: cat.color, fontWeight: 700, fontFamily: 'monospace', fontSize: 11 }}>
                  {count} <span style={{ color: '#64748b', fontSize: 9, fontWeight: 400 }}>({pct}%)</span>
                </span>
              </div>
              <div style={{ height: 4, background: '#060e1a', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: cat.color, borderRadius: 2, transition: 'width 0.4s ease' }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function IngestionTrendChart({ perHour = [], logs = [] }) {
  const hoursData = Array.from({ length: 24 }, (_, h) => {
    const found = perHour.find(p => p._id === h);
    if (found) return found.count;
    return logs.filter(l => new Date(l.receivedAt || l.createdAt).getHours() === h).length;
  });

  const max = Math.max(...hoursData, 10);
  const width = 450;
  const height = 120;
  const padding = 20;

  const points = hoursData.map((val, idx) => {
    const x = padding + (idx / 23) * (width - padding * 2);
    const y = height - padding - (val / max) * (height - padding * 2);
    return `${x},${y}`;
  });

  const pathD = `M ${points[0]} ` + points.slice(1).map(p => `L ${p}`).join(' ');
  const areaD = `M ${padding},${height - padding} L ${points[0]} ` + points.slice(1).map(p => `L ${p}`).join(' ') + ` L ${width - padding},${height - padding} Z`;

  return (
    <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', flex: 1, minWidth: 300 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#e0f2fe', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 15 }}>📈</span> 24H Ingestion Velocity Graph
        </div>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 12, background: '#3b82f618', color: '#60a5fa', border: '1px solid #3b82f644' }}>
          Peak: {max} events/hr
        </span>
      </div>

      <div style={{ position: 'relative', width: '100%', height: 110 }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: '100%', overflow: 'visible' }}>
          <defs>
            <linearGradient id="siemAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map(r => (
            <line key={r} x1={padding} y1={padding + r * (height - padding * 2)} x2={width - padding} y2={padding + r * (height - padding * 2)} stroke="#1e3a5f" strokeDasharray="3 3" strokeWidth="0.8" />
          ))}
          <path d={areaD} fill="url(#siemAreaGrad)" />
          <path d={pathD} fill="none" stroke="#60a5fa" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          {points.map((p, i) => {
            const [cx, cy] = p.split(',');
            if (hoursData[i] === 0) return null;
            return <circle key={i} cx={cx} cy={cy} r="3" fill="#60a5fa" stroke="#0c1a2e" strokeWidth="1.5" />;
          })}
        </svg>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9, color: '#64748b', marginTop: 2, paddingLeft: padding, paddingRight: padding }}>
        <span>00:00</span>
        <span>06:00</span>
        <span>12:00</span>
        <span>18:00</span>
        <span>23:00</span>
      </div>
    </div>
  );
}

export default function SIEMPage() {
  const { user } = useAuth();
  const [logs,     setLogs]     = useState([]);
  const [alerts,   setAlerts]   = useState([]);
  const [logStats, setLogStats] = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [activeTab,setActiveTab]= useState('feed');
  const [logFilter,setLogFilter]= useState({ logType: '', source: '', level: '' });
  const socketRef = useRef(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [lRes, lStats, aRes] = await Promise.all([
        api.get('/logs?limit=80&page=1'),
        api.get('/logs/stats'),
        api.get('/alerts?limit=80&page=1'),
      ]);
      console.log('[SIEMPage] lStats.data:', lStats.data);
      console.log('[SIEMPage] alerts count:', aRes.data.alerts?.length);

      const rawLogs = lRes.data.logs || [];
      const alertsAsLogs = (aRes.data.alerts || []).map(a => ({
        _id: a._id,
        source: a.source || 'agent',
        agentName: a.agentName,
        hostname: a.agentName,
        logType: a.eventCategory || 'system',
        level: a.severity || 'info',
        message: a.description || `[${a.ruleId}] ${a.type || ''}`,
        receivedAt: a.createdAt,
        createdAt: a.createdAt,
        format: 'alert',
        tags: [a.eventCategory, a.severity],
      }));

      const combined = [...rawLogs, ...alertsAsLogs]
        .sort((a, b) => new Date(b.receivedAt || b.createdAt) - new Date(a.receivedAt || a.createdAt))
        .slice(0, 80);

      setLogs(combined);

      const alertTotal = aRes.data.total || 0;
      const mergedStats = {
        ...lStats.data,
        total: (lStats.data?.total || 0) + alertTotal,
        bySource: lStats.data?.bySource || [],
      };
      if ((lStats.data?.total || 0) === 0 && alertTotal > 0) {
        const sourceCounts = {};
        (aRes.data.alerts || []).forEach(a => {
          const src = a.source || a.eventCategory || 'agent';
          sourceCounts[src] = (sourceCounts[src] || 0) + 1;
        });
        mergedStats.bySource = Object.entries(sourceCounts).map(([_id, count]) => ({ _id, count }))
          .sort((a, b) => b.count - a.count);
      }
      setLogStats(mergedStats);
      setAlerts(aRes.data.alerts || []);
    } catch (err) { console.error('[SIEMPage] Error:', err.message); }
    finally { setLoading(false); }
  }, []);

  const loadFiltered = useCallback(async () => {
    try {
      const q = new URLSearchParams({ limit: 80 });
      if (logFilter.logType) q.set('logType', logFilter.logType);
      if (logFilter.source)  q.set('source', logFilter.source);
      if (logFilter.level)   q.set('level', logFilter.level);

      const [logRes, alertRes] = await Promise.all([
        api.get(`/logs?${q}`),
        api.get(`/alerts?limit=80&page=1${logFilter.level ? '&severity=' + logFilter.level : ''}${logFilter.logType ? '&category=' + logFilter.logType : ''}`),
      ]);

      const rawLogs = logRes.data.logs || [];
      const alertsAsLogs = (alertRes.data.alerts || []).map(a => ({
        _id: a._id,
        source: a.source || 'agent',
        agentName: a.agentName,
        hostname: a.agentName,
        logType: a.eventCategory || 'system',
        level: a.severity || 'info',
        message: a.description || `[${a.ruleId}] ${a.type || ''}`,
        receivedAt: a.createdAt,
        createdAt: a.createdAt,
        format: 'alert',
      }));

      const combined = [...rawLogs, ...alertsAsLogs]
        .sort((a, b) => new Date(b.receivedAt || b.createdAt) - new Date(a.receivedAt || a.createdAt))
        .slice(0, 80);

      setLogs(combined);
    } catch {}
  }, [logFilter]);

  useEffect(() => {
    if (!user) return;
    
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    socketRef.current = socket;
    
    socket.on('connect', () => {
      console.log('[Socket] Connected ✓ socketId:', socket.id);
      socket.emit('join:company', user.companyId);
    });

    const throttledFetchLogStats = throttle(() => {
      api.get('/logs/stats').then(r => setLogStats(r.data)).catch(() => {});
    }, 10000);

    const siemFeedBuffer = createEventBuffer((events) => {
      if (!logFilter.logType && !logFilter.source && !logFilter.level) {
        setLogs(prev => [...events, ...prev].slice(0, 80));
      }
      throttledFetchLogStats();
    }, 1200);
    
    const handleNewEvent = (newLog) => {
      siemFeedBuffer.add(newLog);
    };

    socket.on('log:new', handleNewEvent);

    const handleNewAlert = (alert) => {
      const logEntry = {
        _id: alert._id,
        source: alert.source || 'agent',
        agentName: alert.agentName,
        hostname: alert.agentName,
        logType: alert.eventCategory || 'system',
        level: alert.severity || 'info',
        message: alert.description || `[${alert.ruleId}] ${alert.type || ''}`,
        receivedAt: alert.createdAt || new Date().toISOString(),
        createdAt: alert.createdAt || new Date().toISOString(),
        format: 'alert',
      };
      siemFeedBuffer.add(logEntry);
    };

    socket.on('alert:new', handleNewAlert);

    const disconnectSocket = connectSocket(socket);
    return () => {
      socket.off('log:new', handleNewEvent);
      socket.off('alert:new', handleNewAlert);
      siemFeedBuffer.clear();
      disconnectSocket();
    };
  }, [user, logFilter]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { if (activeTab === 'feed') loadFiltered(); }, [logFilter, loadFiltered, activeTab]);

  const hasFilters = !!(logFilter.logType || logFilter.source || logFilter.level);
  const categoryCounts = getCategoryCounts(logs, logStats);
  const totalCategoryLogs = Math.max(Object.values(categoryCounts).reduce((a, b) => a + b, 0), 1);

  const handleCategorySelect = (catId) => {
    const mapFilter = {
      edr: 'edr',
      ids_ips: 'ids',
      firewall: 'firewall',
      web_net: 'webserver',
      auth: 'auth',
      system: 'system',
    };
    const target = mapFilter[catId] || catId;
    if (logFilter.logType === target) {
      setLogFilter(p => ({ ...p, logType: '', source: '' }));
    } else {
      setLogFilter(p => ({ ...p, logType: target, source: '' }));
    }
  };

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, color: '#e0f2fe' }}>📡 SIEM — Security Information & Event Management</h2>
          <div style={{ fontSize: 11, color: '#60a5fa', marginTop: 3 }}>
            All-source log ingestion · EDR, IDS/IPS & Firewall Analytics · Alert correlation
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <button onClick={load} style={{ fontSize: 11, padding: '5px 14px', borderRadius: 6,
            border: '1px solid #1e3a5f', background: 'none', color: '#60a5fa', cursor: 'pointer' }}>
            ↺ Refresh
          </button>
        </div>
      </div>

      {/* Top Category KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10, marginBottom: 16 }}>
        {CATEGORIES.map(cat => {
          const count = categoryCounts[cat.id] || 0;
          const pct = Math.round((count / totalCategoryLogs) * 100);
          const isSelected = logFilter.logType === (cat.id === 'ids_ips' ? 'ids' : cat.id === 'web_net' ? 'webserver' : cat.id);

          return (
            <div key={cat.id} onClick={() => handleCategorySelect(cat.id)}
              style={{
                background: isSelected ? '#0f2442' : '#0c1a2e',
                border: `1px solid ${isSelected ? cat.color : cat.color + '33'}`,
                borderRadius: 10,
                padding: '12px 14px',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                boxShadow: isSelected ? `0 0 12px ${cat.color}33` : 'none',
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 18 }}>{cat.icon}</span>
                <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 10, color: cat.color, background: `${cat.color}18`, fontWeight: 700 }}>
                  {pct}%
                </span>
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, color: cat.color, fontFamily: 'monospace' }}>{count}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', marginTop: 2 }}>{cat.label}</div>
              <div style={{ height: 3, background: '#060e1a', borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: cat.color, borderRadius: 2, transition: 'width 0.4s ease' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section: Distribution + 24H Ingestion Trend */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 18, flexWrap: 'wrap' }}>
        <CategoryDistributionChart categoryCounts={categoryCounts} totalLogs={totalCategoryLogs} onCategoryClick={handleCategorySelect} />
        <IngestionTrendChart perHour={logStats?.perHour || []} logs={logs} />
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid #1e3a5f', marginBottom: 16 }}>
        {[
          ['feed','📺 Live Feed'], ['alerts','🔔 Alerts']
        ].map(([t,l]) => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '7px 16px', fontSize: 12, cursor: 'pointer', border: 'none', background: 'none',
            fontWeight: activeTab === t ? 700 : 400,
            color: activeTab === t ? '#60a5fa' : '#64748b',
            borderBottom: activeTab === t ? '2px solid #3b82f6' : '2px solid transparent', marginBottom: -1,
          }}>{l}</button>
        ))}
      </div>

      {/* Live Feed Tab */}
      {activeTab === 'feed' && (
        <>
          {/* Filter bar */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap' }}>
            {[
              ['logType', 'Log Type', ['','system','auth','network','file','usb','webserver','database','cloud','ids','edr','firewall']],
              ['level',   'Level',    ['','critical','error','warning','info','debug']],
            ].map(([key, label, opts]) => (
              <select key={key} value={logFilter[key]}
                onChange={e => setLogFilter(p => ({ ...p, [key]: e.target.value }))}
                style={{ padding: '5px 10px', borderRadius: 6, fontSize: 11, background: '#060e1a',
                  border: '1px solid #1e3a5f', color: logFilter[key] ? '#e2e8f0' : '#64748b' }}>
                {opts.map(o => <option key={o} value={o}>{o || label}</option>)}
              </select>
            ))}
            <input value={logFilter.source} onChange={e => setLogFilter(p => ({ ...p, source: e.target.value }))}
              placeholder="Filter by source (nginx, suricata…)"
              style={{ padding: '5px 10px', borderRadius: 6, fontSize: 11, background: '#060e1a',
                border: '1px solid #1e3a5f', color: '#e2e8f0', minWidth: 200 }} />
            {(logFilter.logType || logFilter.level || logFilter.source) && (
              <button onClick={() => setLogFilter({ logType:'', source:'', level:'' })}
                style={{ fontSize: 11, padding: '4px 10px', borderRadius: 6, border: '1px solid #f87171',
                  background: 'none', color: '#f87171', cursor: 'pointer' }}>✕ Clear</button>
            )}
          </div>
          <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center',
              padding: '8px 14px', borderBottom: '1px solid #1e3a5f', background: '#060e1a' }}>
              <span style={{ fontSize: 11, color: '#93c5fd', fontWeight: 600 }}>📺 Real-time Log Feed</span>
              <span style={{ fontSize: 10, color: '#1e40af' }}>{logs.length} events shown</span>
            </div>
            {loading ? (
              <div style={{ color: '#1e40af', textAlign: 'center', padding: 40 }}>Loading logs…</div>
            ) : <LiveFeed logs={logs} hasFilters={hasFilters} />}
          </div>
        </>
      )}

      {/* Recent Alerts Tab */}
      {activeTab === 'alerts' && (
        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#060e1a' }}>
                {['Time','Severity','Category','Source','Description','Status'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '9px 12px', color: '#1e40af', fontWeight: 600, fontSize: 11 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {alerts.map((a, i) => {
                const sevColor = { critical:'#f87171', high:'#f59e0b', medium:'#60a5fa', low:'#34d399' }[a.severity] || '#64748b';
                const meta = sourceMeta(a.source || a.eventCategory);
                return (
                  <tr key={i} style={{ borderBottom: '1px solid #060e1a' }}>
                    <td style={{ padding: '7px 12px', color: '#64748b', fontSize: 10, fontFamily: 'monospace' }}>
                      {new Date(a.createdAt).toLocaleTimeString()}
                    </td>
                    <td style={{ padding: '7px 12px' }}>
                      <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
                        color: sevColor, background: `${sevColor}18` }}>{a.severity?.toUpperCase()}</span>
                    </td>
                    <td style={{ padding: '7px 12px', color: meta.color }}>{meta.icon} {a.eventCategory}</td>
                    <td style={{ padding: '7px 12px', color: '#64748b', fontSize: 10 }}>{a.source || '—'}</td>
                    <td style={{ padding: '7px 12px', color: '#e2e8f0', maxWidth: 300,
                      overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description}</td>
                    <td style={{ padding: '7px 12px' }}>
                      <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 6,
                        color: a.status === 'resolved' ? '#22c55e' : '#60a5fa',
                        background: a.status === 'resolved' ? '#14532d22' : '#1e3a5f' }}>
                        {a.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
