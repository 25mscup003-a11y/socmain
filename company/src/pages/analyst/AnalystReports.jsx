import { useEffect, useState } from 'react';
import api from '../../api/axios';
import { useAuth } from '../../context/AuthContext';

const TODAY     = new Date().toISOString().slice(0,10);
const MONTH_AGO = new Date(Date.now() - 30*24*60*60*1000).toISOString().slice(0,10);

const SEV_COLORS = { critical:'#f87171', high:'#f59e0b', medium:'#60a5fa', low:'#34d399' };

export default function AnalystReports() {
  const { selectedDeptId } = useAuth();
  const [report,  setReport]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [from,    setFrom]    = useState(MONTH_AGO);
  const [to,      setTo]      = useState(TODAY);
  const [error,   setError]   = useState('');

  const load = async () => {
    setLoading(true); setError('');
    try {
      const deptQ = selectedDeptId ? `&departmentId=${selectedDeptId}` : '';
      const { data } = await api.get(`/reports?from=${from}&to=${to}${deptQ}`);
      setReport(data);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load report');
    } finally { setLoading(false); }
  };

  useEffect(() => { load(); }, [from, to, selectedDeptId]);

  const downloadCsv = () => {
    window.open(`${import.meta.env.VITE_API_URL}/reports/csv?from=${from}&to=${to}`, '_blank');
  };

  const BarChart = ({ data, labelKey, valueKey, color='#2563eb' }) => {
    const max = Math.max(...data.map(d=>d[valueKey]),1);
    return (
      <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
        {data.map((d,i) => (
          <div key={i} style={{ display:'flex', alignItems:'center', gap:10 }}>
            <span style={{ fontSize:11, color:'#60a5fa', width:90, textAlign:'right',
                           whiteSpace:'nowrap', overflow:'hidden', textOverflow:'ellipsis' }}>
              {d[labelKey]||'—'}
            </span>
            <div style={{ flex:1, height:14, background:'#060e1a', borderRadius:4, overflow:'hidden' }}>
              <div style={{ width:`${(d[valueKey]/max)*100}%`, height:'100%',
                            background:color, borderRadius:4, minWidth:4, transition:'width .5s' }}/>
            </div>
            <span style={{ fontSize:11, color:'#93c5fd', width:28, textAlign:'right' }}>{d[valueKey]}</span>
          </div>
        ))}
      </div>
    );
  };

  const Section = ({ title, children }) => (
    <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:10,
                  padding:'18px 22px', marginBottom:18 }}>
      <h3 style={{ fontSize:13, color:'#60a5fa', marginBottom:14 }}>{title}</h3>
      {children}
    </div>
  );

  return (
    <div>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:20 }}>
        <h2 style={{ fontSize:20, color:'#e0f2fe' }}>Reports</h2>
        {report && (
          <button onClick={downloadCsv} style={{
            fontSize:12, padding:'6px 14px', borderRadius:6, border:'none',
            background:'#064e3b', color:'#34d399', cursor:'pointer',
          }}>↓ Export CSV</button>
        )}
      </div>

      {/* Date picker */}
      <div style={{ display:'flex', gap:12, alignItems:'center', marginBottom:22,
                    background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8,
                    padding:'12px 16px', flexWrap:'wrap' }}>
        <span style={{ fontSize:12, color:'#1e40af' }}>From</span>
        <input type="date" value={from} onChange={e=>setFrom(e.target.value)}
          style={{ background:'#060e1a', border:'1px solid #1e3a5f', color:'#93c5fd',
                   padding:'5px 8px', borderRadius:4, fontSize:12 }}/>
        <span style={{ fontSize:12, color:'#1e40af' }}>To</span>
        <input type="date" value={to} onChange={e=>setTo(e.target.value)}
          style={{ background:'#060e1a', border:'1px solid #1e3a5f', color:'#93c5fd',
                   padding:'5px 8px', borderRadius:4, fontSize:12 }}/>
        <button onClick={load} disabled={loading} style={{
          fontSize:12, padding:'6px 16px', borderRadius:6, border:'none',
          background: loading ? '#1e3a5f' : '#2563eb', color:'#fff', cursor:'pointer',
        }}>{loading ? 'Loading…' : 'Generate'}</button>
      </div>

      {error && (
        <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'10px 14px',
                      borderRadius:6, marginBottom:16, fontSize:13 }}>{error}</div>
      )}

      {loading && !report && <p style={{ color:'#1e40af', fontSize:13 }}>Generating report…</p>}

      {report && (
        <>
          {/* Summary */}
          <div style={{ display:'flex', gap:12, marginBottom:18, flexWrap:'wrap' }}>
            {[
              { label:'Total alerts',         value:report.summary.totalAlerts,            color:'#60a5fa' },
              { label:'SOAR actions',          value:report.summary.soarActionsExecuted,    color:'#a78bfa' },
              { label:'Avg resolution (min)',  value:report.summary.avgResolutionMinutes??'N/A', color:'#f59e0b' },
            ].map(({ label, value, color }) => (
              <div key={label} style={{ flex:1, minWidth:120, background:'#0c1a2e',
                                        border:`1px solid ${color}22`, borderRadius:10, padding:'16px 18px' }}>
                <div style={{ fontSize:26, fontWeight:600, color }}>{String(value)}</div>
                <div style={{ fontSize:11, color:'#1e40af', marginTop:2 }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Severity breakdown */}
          <Section title="Alerts by severity">
            <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
              {report.bySeverity.map(s => (
                <div key={s.severity} style={{ flex:1, minWidth:80, background:'#060e1a',
                                               borderRadius:8, padding:'10px 12px', textAlign:'center',
                                               border:`1px solid ${SEV_COLORS[s.severity]||'#1e3a5f'}33` }}>
                  <div style={{ fontSize:22, fontWeight:600, color:SEV_COLORS[s.severity]||'#93c5fd' }}>
                    {s.count}
                  </div>
                  <div style={{ fontSize:11, color:'#1e40af', marginTop:2 }}>{s.severity}</div>
                </div>
              ))}
              {report.bySeverity.length===0 && (
                <p style={{ fontSize:13, color:'#1e3a5f' }}>No alerts in this period.</p>
              )}
            </div>
          </Section>

          {/* Alerts per day */}
          {report.byDay.length > 0 && (
            <Section title="Alerts per day">
              <BarChart data={report.byDay} labelKey="date" valueKey="count" color="#2563eb"/>
            </Section>
          )}

          {/* Top agents */}
          {report.topAgents.length > 0 && (
            <Section title="Top alerting agents">
              <BarChart data={report.topAgents} labelKey="agent" valueKey="count" color="#7c3aed"/>
            </Section>
          )}

          <div style={{ fontSize:11, color:'#1e3a5f', textAlign:'right', marginTop:8 }}>
            Generated {new Date(report.meta.generatedAt).toLocaleString()}
          </div>
        </>
      )}
    </div>
  );
}
