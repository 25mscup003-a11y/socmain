import { useEffect, useState, useCallback } from 'react';
import { useSearchParams } from 'react-router-dom';
import api from '../../api/axios';
import { useAuth } from '../../context/AuthContext';

const SEV_COLOR = { critical:'#f87171', high:'#f59e0b', medium:'#60a5fa', low:'#34d399' };
const SEV_BG    = { critical:'#7f1d1d', high:'#78350f', medium:'#1e3a5f', low:'#064e3b' };

export default function AnalystAlerts() {
  const { selectedDeptId } = useAuth();
  const [params]  = useSearchParams();
  const [alerts,  setAlerts]  = useState([]);
  const [total,   setTotal]   = useState(0);
  const [page,    setPage]    = useState(1);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [aiBusy,  setAiBusy]  = useState('');
  const [filters, setFilters] = useState({
    severity: params.get('severity') || '',
    status:   '',
  });

  const load = useCallback(() => {
    setLoading(true); setError('');
    const q = new URLSearchParams({ page, limit:20 });
    if (filters.severity) q.set('severity', filters.severity);
    if (filters.status)   q.set('status',   filters.status);
    api.get(`/alerts?${q}`)
      .then(r => { setAlerts(r.data.alerts || []); setTotal(r.data.total || 0); })
      .catch(err => setError(err.response?.data?.message || 'Failed to load alerts'))
      .finally(() => setLoading(false));
  }, [page, filters]);

  useEffect(() => { load(); }, [load]);

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

  const FilterBtn = ({ field, value, label }) => (
    <button
      onClick={() => { setFilters(f => ({ ...f, [field]: f[field]===value ? '' : value })); setPage(1); }}
      style={{
        fontSize:11, padding:'4px 10px', borderRadius:6, cursor:'pointer',
        border:'none', marginRight:6,
        background: filters[field]===value ? '#1e3a5f' : '#0c1a2e',
        color:      filters[field]===value ? '#93c5fd' : '#1e40af',
      }}>{label}
    </button>
  );

  return (
    <div>
      <h2 style={{ fontSize:20, color:'#e0f2fe', marginBottom:20 }}>
        Alerts <span style={{ fontSize:13, color:'#1e40af', fontWeight:400 }}>({total})</span>
      </h2>

      {/* Filters */}
      <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8,
                    padding:'12px 16px', marginBottom:18, display:'flex', gap:16, flexWrap:'wrap' }}>
        <div>
          <span style={{ fontSize:11, color:'#1e40af', marginRight:6 }}>Severity:</span>
          {['critical','high','medium','low'].map(s => <FilterBtn key={s} field="severity" value={s} label={s}/>)}
        </div>
        <div>
          <span style={{ fontSize:11, color:'#1e40af', marginRight:6 }}>Status:</span>
          {['open','investigating','resolved'].map(s => <FilterBtn key={s} field="status" value={s} label={s}/>)}
        </div>
        {(filters.severity || filters.status) && (
          <button onClick={() => { setFilters({ severity:'', status:'' }); setPage(1); }}
            style={{ fontSize:11, padding:'4px 10px', borderRadius:6, border:'none',
                     background:'#7f1d1d', color:'#fca5a5', cursor:'pointer' }}>Clear</button>
        )}
      </div>

      {error && (
        <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'10px 14px',
                      borderRadius:6, marginBottom:14, fontSize:13 }}>{error}</div>
      )}

      {loading
        ? <p style={{ color:'#1e40af', fontSize:13 }}>Loading…</p>
        : alerts.length === 0
          ? <p style={{ color:'#1e3a5f', fontSize:13 }}>No alerts found.</p>
          : alerts.map(a => (
            <div key={a._id} style={{
              background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8,
              padding:'12px 16px', marginBottom:8,
            }}>
              <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:10 }}>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:13, color:'#e2e8f0', marginBottom:4 }}>
                    {a.description || 'Security event'}
                  </div>
                  <div style={{ fontSize:11, color:'#1e40af', display:'flex', gap:10, flexWrap:'wrap' }}>
                    <span>Agent: {a.agentName || '—'}</span>
                    {a.srcip && <span>SrcIP: {a.srcip}</span>}
                    <span>Rule: {a.ruleId || '—'}</span>
                    <span>{new Date(a.createdAt).toLocaleString()}</span>
                  </div>
                  {/* Notes — read only for analyst */}
                  {a.notes?.length > 0 && (
                    <div style={{ marginTop:8 }}>
                      {a.notes.map((n, i) => (
                        <div key={i} style={{ fontSize:11, color:'#60a5fa', marginTop:3 }}>
                          💬 {n.text}
                        </div>
                      ))}
                    </div>
                  )}
                  {a.aiInvestigation?.status && a.aiInvestigation.status !== 'not_required' && (
                    <div style={{ marginTop:8, padding:'8px 10px', borderRadius:6, background:'rgba(76,29,149,.14)', border:'1px solid #5b21b6', fontSize:11 }}>
                      <b style={{ color:'#c4b5fd' }}>✦ AI investigation · {a.aiInvestigation.status}</b>
                      {a.aiInvestigation.summary && <div style={{ color:'#cbd5e1', marginTop:4 }}>{a.aiInvestigation.summary}</div>}
                    </div>
                  )}
                </div>
                <div style={{ display:'flex', gap:6, flexShrink:0, flexDirection:'column', alignItems:'flex-end' }}>
                  <span style={{
                    fontSize:11, padding:'2px 10px', borderRadius:10,
                    background: SEV_BG[a.severity]   || '#1e3a5f',
                    color:      SEV_COLOR[a.severity] || '#93c5fd',
                  }}>{a.severity}</span>
                  <span style={{
                    fontSize:11, padding:'2px 10px', borderRadius:10, background:'#0c1a2e',
                    color: a.status==='resolved' ? '#34d399'
                         : a.status==='investigating' ? '#f59e0b' : '#93c5fd',
                    border:'1px solid #1e3a5f',
                  }}>{a.status}</span>
                </div>
              </div>
            </div>
          ))
      }

      {/* Pagination */}
      {total > 20 && (
        <div style={{ display:'flex', gap:8, marginTop:20, justifyContent:'center', alignItems:'center' }}>
          <button onClick={() => setPage(p => Math.max(1,p-1))} disabled={page===1}
            style={{ padding:'6px 14px', background:'#0c1a2e', border:'1px solid #1e3a5f',
                     color:'#60a5fa', borderRadius:6, cursor:'pointer', fontSize:13 }}>← Prev</button>
          <span style={{ padding:'6px 12px', color:'#1e40af', fontSize:13 }}>
            Page {page} of {Math.ceil(total/20)}
          </span>
          <button onClick={() => setPage(p=>p+1)} disabled={page>=Math.ceil(total/20)}
            style={{ padding:'6px 14px', background:'#0c1a2e', border:'1px solid #1e3a5f',
                     color:'#60a5fa', borderRadius:6, cursor:'pointer', fontSize:13 }}>Next →</button>
        </div>
      )}

      <p style={{ fontSize:11, color:'#1e3a5f', textAlign:'center', marginTop:16 }}>
        Read-only view · Contact your company admin to change alert status
      </p>
    </div>
  );
}
