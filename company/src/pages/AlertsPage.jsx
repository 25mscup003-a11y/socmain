import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';

const SEV_COLOR = { critical:'#f87171', high:'#f59e0b', medium:'#60a5fa', low:'#34d399' };
const SEV_BG    = { critical:'#7f1d1d', high:'#78350f', medium:'#1e3a5f', low:'#064e3b' };

function AlertSeverityChart({ alerts = [], total = 0, onFilterSelect }) {
  const crit = alerts.filter(a => a.severity === 'critical').length;
  const high = alerts.filter(a => a.severity === 'high').length;
  const med  = alerts.filter(a => a.severity === 'medium').length;
  const low  = alerts.filter(a => a.severity === 'low').length;
  const res  = alerts.filter(a => a.status === 'resolved').length;

  const countTotal = Math.max(alerts.length, 1);

  const items = [
    { label: 'Critical', count: crit, color: '#f87171', icon: '🚨', type: 'sev', val: 'critical' },
    { label: 'High',     count: high, color: '#f59e0b', icon: '⚠️', type: 'sev', val: 'high' },
    { label: 'Medium',   count: med,  color: '#60a5fa', icon: '⚡', type: 'sev', val: 'medium' },
    { label: 'Low',      count: low,  color: '#34d399', icon: '🔹', type: 'sev', val: 'low' },
    { label: 'Resolved', count: res,  color: '#22c55e', icon: '✅', type: 'stat', val: 'resolved' },
  ];

  return (
    <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', flex: 1, minWidth: 300 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: '#e0f2fe', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ fontSize: 15 }}>📊</span> Alert Severity & Status Breakdown
        </div>
        <span style={{ fontSize: 10, color: '#64748b' }}>Live Distribution</span>
      </div>

      <div style={{ display: 'flex', height: 8, borderRadius: 4, overflow: 'hidden', background: '#060e1a', marginBottom: 14, border: '1px solid #1e3a5f' }}>
        {items.map(it => {
          const pct = ((it.count / countTotal) * 100).toFixed(1);
          if (it.count === 0) return null;
          return <div key={it.label} title={`${it.label}: ${it.count} (${pct}%)`} style={{ width: `${pct}%`, background: it.color, transition: 'width 0.4s ease' }} />;
        })}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px 14px' }}>
        {items.map(it => {
          const pct = Math.round((it.count / countTotal) * 100);
          return (
            <div key={it.label} onClick={() => onFilterSelect(it.type, it.val)}
              style={{ cursor: 'pointer', padding: '5px 8px', borderRadius: 6, background: '#060e1a44', border: '1px solid #1e3a5f44', transition: 'all 0.2s' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                <span style={{ color: '#e2e8f0', display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 12 }}>{it.icon}</span>
                  <strong style={{ fontWeight: 600, fontSize: 11 }}>{it.label}</strong>
                </span>
                <span style={{ color: it.color, fontWeight: 700, fontFamily: 'monospace', fontSize: 11 }}>
                  {it.count} <span style={{ color: '#64748b', fontSize: 9, fontWeight: 400 }}>({pct}%)</span>
                </span>
              </div>
              <div style={{ height: 4, background: '#060e1a', borderRadius: 2, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: it.color, borderRadius: 2, transition: 'width 0.4s ease' }} />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function AlertTrendChart({ alerts = [] }) {
  const hoursData = Array.from({ length: 24 }, (_, h) => {
    return alerts.filter(a => new Date(a.createdAt).getHours() === h).length;
  });

  const max = Math.max(...hoursData, 5);
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
          <span style={{ fontSize: 15 }}>📈</span> 24H Alert Frequency Graph
        </div>
        <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 12, background: '#f8717118', color: '#f87171', border: '1px solid #f8717144' }}>
          Peak: {max} alerts/hr
        </span>
      </div>

      <div style={{ position: 'relative', width: '100%', height: 110 }}>
        <svg viewBox={`0 0 ${width} ${height}`} style={{ width: '100%', height: '100%', overflow: 'visible' }}>
          <defs>
            <linearGradient id="alertAreaGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#f87171" stopOpacity="0.4" />
              <stop offset="100%" stopColor="#f87171" stopOpacity="0.0" />
            </linearGradient>
          </defs>
          {[0.25, 0.5, 0.75].map(r => (
            <line key={r} x1={padding} y1={padding + r * (height - padding * 2)} x2={width - padding} y2={padding + r * (height - padding * 2)} stroke="#1e3a5f" strokeDasharray="3 3" strokeWidth="0.8" />
          ))}
          <path d={areaD} fill="url(#alertAreaGrad)" />
          <path d={pathD} fill="none" stroke="#f87171" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" />
          {points.map((p, i) => {
            const [cx, cy] = p.split(',');
            if (hoursData[i] === 0) return null;
            return <circle key={i} cx={cx} cy={cy} r="3" fill="#f87171" stroke="#0c1a2e" strokeWidth="1.5" />;
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

export default function AlertsPage() {
  const [params] = useSearchParams();
  const [alerts,   setAlerts]   = useState([]);
  const [total,    setTotal]    = useState(0);
  const [page,     setPage]     = useState(1);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState('');
  const [severity, setSeverity] = useState(params.get('severity') || '');
  const [status,   setStatus]   = useState('');
  const [category, setCategory] = useState('');
  const [aiBusy, setAiBusy] = useState('');

  const load = useCallback(async () => {
    setLoading(true); setError('');
    const q = new URLSearchParams({ page, limit: 25 });
    if (severity) q.set('severity', severity);
    if (status)   q.set('status',   status);
    if (category) q.set('category', category);
    try {
      const { data } = await api.get(`/alerts?${q}`);
      setAlerts(data.alerts || []);
      setTotal(data.total   || 0);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [page, severity, status, category]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    const socket = io(SOCKET_URL);
    const release = connectSocket(socket);
    let timer;
    const refresh = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(load, 800);
    };
    socket.on('alert:ai-updated', refresh);
    socket.on('alert:new', refresh);
    socket.on('alert:updated', refresh);
    socket.on('alert:deleted', refresh);
    return () => {
      window.clearTimeout(timer);
      socket.off('alert:ai-updated', refresh);
      socket.off('alert:new', refresh);
      socket.off('alert:updated', refresh);
      socket.off('alert:deleted', refresh);
      release();
    };
  }, [load]);

  const setFilter = (setter) => (val) => {
    setter(prev => prev === val ? '' : val);
    setPage(1);
  };

  const handleCardFilterSelect = (type, val) => {
    if (type === 'sev') setFilter(setSeverity)(val);
    else if (type === 'stat') setFilter(setStatus)(val);
  };

  const updateStatus = async (id, newStatus) => {
    try {
      const { data } = await api.patch(`/alerts/${id}`, { status: newStatus });
      setAlerts(prev => prev.map(a => a._id === id ? { ...a, status: data.status } : a));
    } catch (err) {
      alert(err.response?.data?.message || 'Update failed');
    }
  };

  const analyseAlert = async (alert) => {
    setAiBusy(alert._id);
    try {
      await api.post(`/ai/alerts/${alert._id}/analyze`);
      setAlerts(prev => prev.map(item => item._id === alert._id
        ? { ...item, aiInvestigation: { ...item.aiInvestigation, status: 'queued' } }
        : item));
    } catch (err) {
      window.alert(err.response?.data?.message || 'AI analysis failed');
    } finally {
      setAiBusy('');
    }
  };

  const clearFilters = () => {
    setSeverity(''); setStatus(''); setCategory(''); setPage(1);
  };

  const FilterBtn = ({ active, onClick, label, color }) => (
    <button onClick={onClick} style={{
      fontSize: 11, padding: '4px 10px', borderRadius: 6, cursor: 'pointer',
      border: `1px solid ${active ? (color || '#2563eb') : '#1e3a5f'}`,
      background: active ? (color ? color + '22' : '#1e3a5f') : 'transparent',
      color: active ? (color || '#93c5fd') : '#60a5fa',
      marginRight: 4, marginBottom: 4,
    }}>{label}</button>
  );

  const hasFilter = severity || status || category;
  const critCount = alerts.filter(a => a.severity === 'critical').length;
  const highCount = alerts.filter(a => a.severity === 'high').length;
  const medCount  = alerts.filter(a => a.severity === 'medium' || a.severity === 'low').length;
  const openCount = alerts.filter(a => a.status === 'open' || a.status === 'investigating').length;
  const resCount  = alerts.filter(a => a.status === 'resolved').length;

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div>
          <h2 style={{ fontSize: 20, color: '#e0f2fe', margin: 0 }}>
            🔔 Security Alerts Center{' '}
            <span style={{ fontSize: 13, color: '#60a5fa', fontWeight: 400 }}>({total} total)</span>
          </h2>
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 3 }}>
            Real-time threat alerts · Severity categorization · Incident response status
          </div>
        </div>
        <button onClick={load} style={{
          fontSize: 11, padding: '5px 14px', borderRadius: 6, border: '1px solid #1e3a5f',
          background: 'none', color: '#60a5fa', cursor: 'pointer',
        }}>↺ Refresh</button>
      </div>

      {/* Top KPI Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: 10, marginBottom: 16 }}>
        {[
          { label: 'Critical', count: critCount, icon: '🚨', color: '#f87171', type: 'sev', val: 'critical' },
          { label: 'High',     count: highCount, icon: '⚠️', color: '#f59e0b', type: 'sev', val: 'high' },
          { label: 'Medium/Low', count: medCount, icon: '⚡', color: '#60a5fa', type: 'sev', val: 'medium' },
          { label: 'Open',     count: openCount, icon: '🔍', color: '#c084fc', type: 'stat', val: 'open' },
          { label: 'Resolved', count: resCount,  icon: '✅', color: '#34d399', type: 'stat', val: 'resolved' },
          { label: 'Total 24h', count: total,    icon: '🔔', color: '#818cf8', type: 'clear', val: '' },
        ].map(card => {
          const isSel = (card.type === 'sev' && severity === card.val) || (card.type === 'stat' && status === card.val);
          const pct = Math.round((card.count / Math.max(alerts.length, 1)) * 100);

          return (
            <div key={card.label} onClick={() => {
              if (card.type === 'sev') setFilter(setSeverity)(card.val);
              else if (card.type === 'stat') setFilter(setStatus)(card.val);
              else clearFilters();
            }}
              style={{
                background: isSel ? '#0f2442' : '#0c1a2e',
                border: `1px solid ${isSel ? card.color : card.color + '33'}`,
                borderRadius: 10,
                padding: '12px 14px',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                boxShadow: isSel ? `0 0 12px ${card.color}33` : 'none',
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 18 }}>{card.icon}</span>
                <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 10, color: card.color, background: `${card.color}18`, fontWeight: 700 }}>
                  {pct}%
                </span>
              </div>
              <div style={{ fontSize: 20, fontWeight: 800, color: card.color, fontFamily: 'monospace' }}>{card.count}</div>
              <div style={{ fontSize: 11, fontWeight: 600, color: '#e2e8f0', marginTop: 2 }}>{card.label}</div>
              <div style={{ height: 3, background: '#060e1a', borderRadius: 2, marginTop: 8, overflow: 'hidden' }}>
                <div style={{ width: `${pct}%`, height: '100%', background: card.color, borderRadius: 2, transition: 'width 0.4s ease' }} />
              </div>
            </div>
          );
        })}
      </div>

      {/* Charts Section: Breakdown + Frequency Trend */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 18, flexWrap: 'wrap' }}>
        <AlertSeverityChart alerts={alerts} total={total} onFilterSelect={handleCardFilterSelect} />
        <AlertTrendChart alerts={alerts} />
      </div>



      {error && (
        <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '10px 14px',
                      borderRadius: 6, marginBottom: 14, fontSize: 13 }}>{error}</div>
      )}

      {loading ? (
        <p style={{ color: '#1e40af', fontSize: 13 }}>Loading…</p>
      ) : alerts.length === 0 ? (
        <p style={{ color: '#1e3a5f', fontSize: 13 }}>
          {hasFilter ? 'No alerts match these filters.' : 'No alerts yet. Install the SOC Agent on your systems.'}
        </p>
      ) : (
        alerts.map(a => (
          <div key={a._id} style={{
            background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 8,
            padding: '12px 16px', marginBottom: 8,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10 }}>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, color: '#e2e8f0', marginBottom: 5 }}>
                  {a.description || 'Security event'}
                </div>
                <div style={{ fontSize: 11, color: '#1e40af', display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  {a.agentName   && <span>🖥 {a.agentName}</span>}
                  {a.departmentId?.name && <span>🏬 {a.departmentId.name}</span>}
                  {a.srcip       && <span>🌐 {a.srcip}</span>}
                  {a.filePath    && <span>📁 {a.filePath}</span>}
                  {a.eventCategory && (
                    <span style={{ background: '#1e1060', color: '#c4b5fd',
                                   padding: '1px 6px', borderRadius: 4 }}>
                      {a.eventCategory}
                    </span>
                  )}
                  <span style={{ color: '#1e3a5f' }}>{new Date(a.createdAt).toLocaleString()}</span>
                </div>
                {/* VT score if present */}
                {a.vtScore > 0 && (
                  <div style={{ marginTop: 4, fontSize: 11 }}>
                    <span style={{ color: a.vtScore >= 70 ? '#f87171' : a.vtScore >= 10 ? '#f59e0b' : '#34d399' }}>
                      🔬 VT: {a.vtScore}% ({a.vtDetections}/{a.vtTotal} engines)
                    </span>
                  </div>
                )}
                {a.aiInvestigation?.status && a.aiInvestigation.status !== 'not_required' && (
                  <div style={{ marginTop: 8, padding: '8px 10px', borderRadius: 6, background: 'rgba(76,29,149,.14)', border: '1px solid #5b21b6', fontSize: 11 }}>
                    <b style={{ color: '#c4b5fd' }}>✦ AI investigation · {a.aiInvestigation.status}</b>
                    {a.aiInvestigation.status === 'completed' && <>
                      <div style={{ color: '#cbd5e1', marginTop: 4 }}>{a.aiInvestigation.summary}</div>
                      <div style={{ color: '#a5b4fc', marginTop: 3 }}>Confidence {a.aiInvestigation.confidence}% · {a.aiInvestigation.rootCause || 'Root cause requires analyst validation'}</div>
                    </>}
                  </div>
                )}
              </div>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <span style={{
                  fontSize: 11, padding: '2px 8px', borderRadius: 10,
                  background: SEV_BG[a.severity]   || '#1e3a5f',
                  color:      SEV_COLOR[a.severity] || '#93c5fd',
                }}>{a.severity}</span>
                <select
                  value={a.status}
                  onChange={e => updateStatus(a._id, e.target.value)}
                  style={{
                    fontSize: 11, padding: '3px 6px', borderRadius: 6,
                    background: '#060e1a', border: '1px solid #1e3a5f',
                    color: '#93c5fd', cursor: 'pointer',
                  }}>
                  <option value="open">open</option>
                  <option value="investigating">investigating</option>
                  <option value="resolved">resolved</option>
                  <option value="false_positive">false positive</option>
                </select>
              </div>
            </div>
          </div>
        ))
      )}

      {/* Pagination */}
      {total > 25 && (
        <div style={{ display: 'flex', gap: 8, marginTop: 20, justifyContent: 'center', alignItems: 'center' }}>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
            style={{ padding: '6px 14px', background: '#0c1a2e', border: '1px solid #1e3a5f',
                     color: page === 1 ? '#1e3a5f' : '#60a5fa', borderRadius: 6, cursor: page === 1 ? 'not-allowed' : 'pointer' }}>
            ← Prev
          </button>
          <span style={{ padding: '6px 12px', color: '#1e40af', fontSize: 13 }}>
            Page {page} of {Math.ceil(total / 25)}
          </span>
          <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / 25)}
            style={{ padding: '6px 14px', background: '#0c1a2e', border: '1px solid #1e3a5f',
                     color: page >= Math.ceil(total/25) ? '#1e3a5f' : '#60a5fa', borderRadius: 6, cursor: page >= Math.ceil(total/25) ? 'not-allowed' : 'pointer' }}>
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
