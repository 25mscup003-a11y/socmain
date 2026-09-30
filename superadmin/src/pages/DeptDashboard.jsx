import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../api/axios';
import DailyReportCard from '../components/DailyReportCard';

const RISK = {
  high:   { color:'#f87171', bg:'#7f1d1d', label:'HIGH' },
  medium: { color:'#fcd34d', bg:'#78350f', label:'MED'  },
  low:    { color:'#6ee7c6', bg:'#064e3b', label:'LOW'  },
};
const SEV_BG    = { critical:'#7f1d1d', high:'#78350f', medium:'#1e3a5f', low:'#064e3b' };
const SEV_COLOR = { critical:'#f87171', high:'#fcd34d', medium:'#93c5fd', low:'#6ee7c6' };

function Spark({ data=[] }) {
  if (!data || data.length < 2) return null;
  const vals = data.map(d=>d.count); const max=Math.max(...vals,1);
  const W=70,H=22; const pts=vals.map((v,i)=>`${(i/(vals.length-1))*W},${H-(v/max)*H}`).join(' ');
  return <svg width={W} height={H} style={{display:'block'}}><polyline points={pts} fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinejoin="round"/></svg>;
}

function RiskBadge({risk='low'}) {
  const r=RISK[risk]||RISK.low;
  return <span style={{fontSize:9,padding:'2px 6px',borderRadius:4,fontWeight:600,background:r.bg,color:r.color}}>{r.label}</span>;
}

function BigCard({ icon, title, main, sub, risk, spark, onClick, children }) {
  return (
    <div onClick={onClick} style={{
      background:'#1e1b4b', border:`1px solid ${RISK[risk]?.color||'#312e81'}44`,
      borderRadius:10, padding:'14px 16px', flex:1, minWidth:155,
      cursor: onClick ? 'pointer' : 'default',
    }}
    onMouseEnter={e => onClick && (e.currentTarget.style.borderColor = RISK[risk]?.color||'#7c3aed')}
    onMouseLeave={e => onClick && (e.currentTarget.style.borderColor = `${RISK[risk]?.color||'#312e81'}44`)}>
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginBottom:8}}>
        <div style={{display:'flex',alignItems:'center',gap:7}}>
          <span style={{fontSize:16}}>{icon}</span>
          <span style={{fontSize:11,color:'#4c1d95'}}>{title}</span>
        </div>
        <RiskBadge risk={risk}/>
      </div>
      <div style={{fontSize:26,fontWeight:600,color:'#e9d5ff',marginBottom:4}}>{main}</div>
      <div style={{fontSize:11,color:'#4c1d95',marginBottom:8}}>{sub}</div>
      {children && <div style={{fontSize:10,color:'#7c3aed',marginBottom:6}}>{children}</div>}
      <Spark data={spark}/>
      {onClick && <div style={{fontSize:10,color:'#4c1d95',marginTop:4}}>Click to view details →</div>}
    </div>
  );
}

// ── Detail Modal with full actions ────────────────────────────────────────────
function DetailModal({ companyId, category, deptId, title, onClose }) {
  const [alerts,   setAlerts]   = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [page,     setPage]     = useState(1);
  const [total,    setTotal]    = useState(0);
  const [selected, setSelected] = useState(null);

  useEffect(() => {
    setLoading(true);
    api.get(`/dashboard/company/${companyId}/alerts/${category}?departmentId=${deptId}&page=${page}&limit=20`)
      .then(r => { setAlerts(r.data.alerts||[]); setTotal(r.data.total||0); })
      .finally(() => setLoading(false));
  }, [companyId, category, deptId, page]);

  const doAction = async (alertId, action) => {
    try {
      const res = await api.patch(`/dashboard/company/${companyId}/alerts/${alertId}/action`, { action });
      if (res.data.deleted) {
        setAlerts(prev => prev.filter(a => a._id !== alertId));
        setSelected(null);
      } else {
        setAlerts(prev => prev.map(a => a._id === alertId ? res.data : a));
        setSelected(res.data);
      }
    } catch(err) { alert(err.response?.data?.message||'Action failed'); }
  };

  const ActionBtn = ({ id, action, label, color }) => (
    <button onClick={() => doAction(id, action)} style={{
      fontSize:11, padding:'4px 10px', borderRadius:4, border:'none', cursor:'pointer',
      background: color+'33', color,
    }}>{label}</button>
  );

  const Field = ({ label, value }) => value ? (
    <div style={{ marginBottom:6 }}>
      <span style={{ fontSize:10, color:'#4c1d95' }}>{label}: </span>
      <span style={{ fontSize:12, color:'#c4b5fd', wordBreak:'break-all' }}>{value}</span>
    </div>
  ) : null;

  return (
    <div onClick={e => { if(e.target===e.currentTarget) onClose(); }}
      style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.75)', zIndex:1000,
               display:'flex', alignItems:'center', justifyContent:'center', padding:20 }}>
      <div style={{ background:'#1a1730', borderRadius:12, border:'1px solid #312e81',
                    width:'100%', maxWidth:860, maxHeight:'88vh', display:'flex', flexDirection:'column' }}>
        {/* Header */}
        <div style={{ padding:'14px 20px', borderBottom:'1px solid #312e81',
                      display:'flex', justifyContent:'space-between', alignItems:'center' }}>
          <div style={{ fontSize:15, fontWeight:500, color:'#e9d5ff' }}>{title}</div>
          <button onClick={onClose} style={{ fontSize:18, background:'none', border:'none',
            color:'#4c1d95', cursor:'pointer', padding:'0 4px' }}>✕</button>
        </div>

        <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
          {/* Alert list */}
          <div style={{ width:340, borderRight:'1px solid #312e81', overflowY:'auto', padding:12 }}>
            {loading ? <p style={{color:'#4c1d95',fontSize:13}}>Loading…</p>
            : alerts.length === 0 ? <p style={{color:'#312e81',fontSize:13}}>No alerts found.</p>
            : alerts.map(a => (
              <div key={a._id}
                onClick={() => setSelected(a)}
                style={{
                  padding:'9px 12px', borderRadius:6, marginBottom:6, cursor:'pointer',
                  background: selected?._id===a._id ? '#2e1065' : '#1e1b4b',
                  border: `1px solid ${selected?._id===a._id ? '#7c3aed' : '#312e81'}`,
                }}>
                <div style={{fontSize:12,color:'#e2e8f0',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',marginBottom:3}}>
                  {a.description||'Security event'}
                </div>
                <div style={{display:'flex',gap:6,alignItems:'center'}}>
                  <span style={{fontSize:9,padding:'1px 6px',borderRadius:4,
                    background:SEV_BG[a.severity]||'#1e3a5f',color:SEV_COLOR[a.severity]||'#93c5fd'}}>
                    {a.severity}
                  </span>
                  <span style={{fontSize:10,color:'#4c1d95'}}>{new Date(a.createdAt).toLocaleString()}</span>
                </div>
              </div>
            ))}
            {/* Pagination */}
            {total > 20 && (
              <div style={{display:'flex',gap:6,marginTop:8,justifyContent:'center'}}>
                <button onClick={()=>setPage(p=>Math.max(1,p-1))} disabled={page===1}
                  style={{fontSize:11,padding:'3px 8px',background:'#1e1b4b',border:'1px solid #312e81',color:'#a78bfa',borderRadius:4,cursor:'pointer'}}>←</button>
                <span style={{fontSize:11,color:'#4c1d95',padding:'3px 6px'}}>{page}/{Math.ceil(total/20)}</span>
                <button onClick={()=>setPage(p=>p+1)} disabled={page>=Math.ceil(total/20)}
                  style={{fontSize:11,padding:'3px 8px',background:'#1e1b4b',border:'1px solid #312e81',color:'#a78bfa',borderRadius:4,cursor:'pointer'}}>→</button>
              </div>
            )}
          </div>

          {/* Detail pane */}
          <div style={{ flex:1, overflowY:'auto', padding:16 }}>
            {!selected
              ? <p style={{color:'#312e81',fontSize:13}}>← Click an alert to see details</p>
              : (
                <>
                  <div style={{fontSize:14,color:'#e9d5ff',fontWeight:500,marginBottom:12}}>
                    {selected.description||'Security event'}
                  </div>

                  {/* Mandatory fields */}
                  <div style={{background:'#0f172a',borderRadius:8,padding:'12px 14px',marginBottom:12,border:'1px solid #312e81'}}>
                    <Field label="File name"      value={selected.fileName || (selected.filePath ? selected.filePath.split(/[/\\]/).pop() : null)}/>
                    <Field label="File location"  value={selected.filePath}/>
                    <Field label="IP address"     value={selected.srcip || selected.destip}/>
                    <Field label="User"           value={selected.username}/>
                    <Field label="Timestamp"      value={new Date(selected.createdAt).toLocaleString()}/>
                    <Field label="Agent"          value={selected.agentName || selected.agentId}/>
                    <Field label="System"         value={selected.systemId?.name}/>
                    <Field label="Department"     value={selected.departmentId?.name}/>
                    <Field label="Process"        value={selected.processName ? `${selected.processName} (PID ${selected.pid||'?'})` : null}/>
                    <Field label="Protocol"       value={selected.protocol}/>
                    <Field label="Source port"    value={selected.srcPort}/>
                    <Field label="Dest port"      value={selected.destPort}/>
                    <Field label="Geo"            value={selected.geoCountry ? `${selected.geoCountry} ${selected.geoCity||''}` : null}/>
                    <Field label="Rule ID"        value={selected.ruleId}/>
                    <Field label="Status"         value={selected.status}/>
                    {selected.vtScore > 0 && <Field label="VT score" value={`${selected.vtScore}/100 (${selected.vtDetections||0}/${selected.vtTotal||0} engines)`}/>}
                  </div>

                  {/* Raw log */}
                  {selected.full_log && (
                    <details style={{marginBottom:12}}>
                      <summary style={{fontSize:11,color:'#4c1d95',cursor:'pointer'}}>Raw log</summary>
                      <pre style={{fontSize:10,color:'#7dd3fc',background:'#020b14',padding:10,borderRadius:6,
                                   marginTop:6,overflowX:'auto',whiteSpace:'pre-wrap'}}>
                        {selected.full_log}
                      </pre>
                    </details>
                  )}

                  {/* Action buttons */}
                  <div style={{background:'#1e1b4b',borderRadius:8,padding:'12px 14px',border:'1px solid #312e81'}}>
                    <div style={{fontSize:11,color:'#4c1d95',marginBottom:8}}>Actions</div>
                    <div style={{display:'flex',gap:6,flexWrap:'wrap'}}>
                      <ActionBtn id={selected._id} action="quarantine" label="⚠ Quarantine" color="#f59e0b"/>
                      <ActionBtn id={selected._id} action="block_ip"   label="🚫 Block IP"   color="#f87171"/>
                      <ActionBtn id={selected._id} action="isolate"    label="🔒 Isolate"    color="#f87171"/>
                      <ActionBtn id={selected._id} action="reconnect"  label="🔓 Reconnect"  color="#34d399"/>
                      <ActionBtn id={selected._id} action="block_usb"  label="🔌 Block USB"  color="#f59e0b"/>
                      <ActionBtn id={selected._id} action="ignore"     label="✓ Ignore"      color="#6b7280"/>
                      <ActionBtn id={selected._id} action="delete"     label="🗑 Delete"      color="#f87171"/>
                    </div>
                  </div>
                </>
              )
            }
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Main DeptDashboard ────────────────────────────────────────────────────────
export default function DeptDashboard() {
  const { companyId, deptId } = useParams();
  const navigate = useNavigate();
  const [data,   setData]   = useState(null);
  const [dept,   setDept]   = useState(null);
  const [co,     setCo]     = useState(null);
  const [loading,setLoading]= useState(true);
  const [error,  setError]  = useState('');
  const [modal,  setModal]  = useState(null); // { category, title }

  // Report date range
  const today    = new Date().toISOString().slice(0,10);
  const monthAgo = new Date(Date.now()-30*86400000).toISOString().slice(0,10);
  const [from, setFrom] = useState(monthAgo);
  const [to,   setTo]   = useState(today);

  const load = useCallback(() => {
    setLoading(true); setError('');
    Promise.all([
      api.get(`/dashboard/company/${companyId}/overview?departmentId=${deptId}`),
      api.get(`/superadmin/companies/${companyId}/departments/${deptId}`),
      api.get(`/superadmin/companies/${companyId}`),
    ])
    .then(([dashRes, deptRes, coRes]) => {
      setData(dashRes.data);
      setDept(deptRes.data);
      setCo(coRes.data);
    })
    .catch(err => setError(err.response?.data?.message||'Failed to load'))
    .finally(() => setLoading(false));
  }, [companyId, deptId]);

  useEffect(() => { load(); }, [load]);

  const c     = data?.cards || {};
  const spark = data?.sparkline || [];

  const downloadCsv = async () => {
    try {
      const { data } = await api.get(`/reports/company/${companyId}/csv?departmentId=${deptId}&from=${from}&to=${to}`, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([data], { type: 'text/csv' }));
      const a = document.createElement('a'); a.href = url;
      a.download = `soc-report-${from}-to-${to}.csv`; a.click();
      URL.revokeObjectURL(url);
    } catch (err) { alert('CSV export failed: ' + err.message); }
  };
  const downloadPdf = async () => {
    try {
      const { data } = await api.get(`/reports/company/${companyId}/pdf?departmentId=${deptId}&from=${from}&to=${to}`, { responseType: 'blob' });
      const url = URL.createObjectURL(new Blob([data], { type: 'text/html' }));
      window.open(url, '_blank');
    } catch (err) { alert('PDF export failed: ' + err.message); }
  };

  if (loading) return <p style={{color:'#4c1d95',fontSize:13}}>Loading…</p>;
  if (error)   return <p style={{color:'#fca5a5',fontSize:13}}>{error}</p>;

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{fontSize:12,color:'#4c1d95',marginBottom:16,display:'flex',alignItems:'center',gap:6}}>
        <Link to="/" style={{color:'#7c3aed',textDecoration:'none'}}>Dashboard</Link>
        <span>›</span>
        <Link to={`/companies/${companyId}/dashboard`} style={{color:'#7c3aed',textDecoration:'none'}}>{co?.name}</Link>
        <span>›</span>
        <span style={{color:'#c4b5fd'}}>📁 {dept?.name}</span>
      </div>

      {/* Dept header */}
      <div style={{background:'#1e1b4b',border:'1px solid #312e81',borderRadius:12,
                   padding:'14px 20px',marginBottom:20,
                   display:'flex',justifyContent:'space-between',alignItems:'center',flexWrap:'wrap',gap:12}}>
        <div>
          <h2 style={{fontSize:18,color:'#e9d5ff',marginBottom:3}}>📁 {dept?.name}</h2>
          <div style={{fontSize:11,color:'#4c1d95'}}>
            Company: {co?.name} · {dept?.systemCount||0} systems
            {dept?.adminId?.name && ` · Admin: ${dept.adminId.name}`}
          </div>
        </div>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          <span style={{fontSize:11,color:'#4c1d95'}}>🎯 Showing only {dept?.name} data</span>
          <button onClick={load} style={{fontSize:11,padding:'4px 10px',borderRadius:4,
            border:'1px solid #312e81',background:'none',color:'#a78bfa',cursor:'pointer'}}>↺</button>
        </div>
      </div>

      {/* ── Dept-filtered security cards (all clickable) ── */}
      <div style={{display:'flex',gap:10,marginBottom:10,flexWrap:'wrap'}}>
        <BigCard icon="🦠" title="Malware (7d)"     risk={c.malware?.risk}    main={c.malware?.total??'—'}     sub={`Trojan:${c.malware?.types?.trojan||0} Ransomware:${c.malware?.types?.ransomware||0}`} spark={spark} onClick={() => setModal({category:'malware',title:'Malware — '+dept?.name})}>VT avg: {c.malware?.avgVtScore||0}</BigCard>
        <BigCard icon="🌐" title="Network (7d)"     risk={c.network?.risk}    main={c.network?.total??'—'}     sub={`Blocked:${c.network?.blocked||0} · IPs:${c.network?.suspIps||0}`}              spark={spark} onClick={() => setModal({category:'network',title:'Network — '+dept?.name})}/>
        <BigCard icon="📁" title="Files (7d)"       risk={c.file?.risk}       main={c.file?.total??'—'}        sub={`+${c.file?.created||0} ~${c.file?.modified||0} -${c.file?.deleted||0}`}         spark={spark} onClick={() => setModal({category:'file',title:'Files — '+dept?.name})}/>
        <BigCard icon="🖥" title="System logs (7d)" risk={c.system?.risk}     main={c.system?.total??'—'}      sub={`Errors:${c.system?.errors||0} Warnings:${c.system?.warnings||0}`}               spark={spark} onClick={() => setModal({category:'system',title:'System Logs — '+dept?.name})}/>
      </div>
      <div style={{display:'flex',gap:10,marginBottom:22,flexWrap:'wrap'}}>
        <BigCard icon="🚫" title="Isolated"         risk={c.isolation?.risk}  main={c.isolation?.isolated??'—'} sub={`Total:${c.isolation?.total||0} Active:${c.isolation?.active||0}`}              spark={spark} onClick={() => setModal({category:'isolation',title:'Isolated Systems — '+dept?.name})}/>
        <BigCard icon="👤" title="EDR (7d)"          risk={c.edr?.risk}        main={c.edr?.total??'—'}         sub={`Logins:${c.edr?.logins||0} Suspicious:${c.edr?.suspicious||0}`}                spark={spark} onClick={() => setModal({category:'edr',title:'EDR Activity — '+dept?.name})}/>
        <BigCard icon="🔌" title="USB (7d)"          risk={c.usb?.risk}        main={c.usb?.total??'—'}         sub={`Connected:${c.usb?.connected||0} Blocked:${c.usb?.blocked||0}`}                spark={spark} onClick={() => setModal({category:'usb',title:'USB Events — '+dept?.name})}/>
        <BigCard icon="🔥" title="Threat Intel"     risk={c.threatIntel?.risk} main={c.threatIntel?.total??'—'} sub={`High:${c.threatIntel?.highRisk||0} Score:${c.threatIntel?.maxScore||0}`}       spark={spark} onClick={() => setModal({category:'malware',title:'Threat Intel — '+dept?.name})}/>
      </div>

      {/* ── Report section ── */}
      <div style={{background:'#1e1b4b',border:'1px solid #312e81',borderRadius:10,padding:'16px 18px',marginBottom:22}}>
        <div style={{fontSize:13,color:'#a78bfa',fontWeight:500,marginBottom:12}}>📄 Generate Report — {dept?.name}</div>
        <div style={{display:'flex',gap:10,alignItems:'center',flexWrap:'wrap'}}>
          <span style={{fontSize:12,color:'#4c1d95'}}>From</span>
          <input type="date" value={from} onChange={e=>setFrom(e.target.value)}
            style={{background:'#0f172a',border:'1px solid #312e81',color:'#c4b5fd',padding:'5px 8px',borderRadius:4,fontSize:12}}/>
          <span style={{fontSize:12,color:'#4c1d95'}}>To</span>
          <input type="date" value={to} onChange={e=>setTo(e.target.value)}
            style={{background:'#0f172a',border:'1px solid #312e81',color:'#c4b5fd',padding:'5px 8px',borderRadius:4,fontSize:12}}/>
          <span onClick={downloadCsv} style={{cursor:'pointer'}}>
            <button style={{fontSize:12,padding:'6px 14px',borderRadius:6,border:'none',
              background:'#064e3b',color:'#34d399',cursor:'pointer'}}>↓ CSV</button>
          </span>
          <span onClick={downloadPdf} style={{cursor:'pointer'}}>
            <button style={{fontSize:12,padding:'6px 14px',borderRadius:6,border:'none',
              background:'#2e1065',color:'#c4b5fd',cursor:'pointer'}}>🖨 PDF</button>
          </span>
        </div>
        <p style={{fontSize:11,color:'#312e81',marginTop:8}}>Report includes only {dept?.name} department data</p>
      </div>

      {/* Modal */}
      {modal && (
        <DetailModal
          companyId={companyId}
          deptId={deptId}
          category={modal.category}
          title={modal.title}
          onClose={() => setModal(null)}
        />
      )}
      <DailyReportCard departmentId={deptId} companyApiPrefix={`/daily-report/company/${companyId}`} />
    </div>
  );
}
