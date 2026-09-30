const card = { background:'#0c192c', border:'1px solid #1e3a5f', borderRadius:12, padding:16, boxShadow:'0 12px 30px rgba(0,0,0,.18)' };
const btn = { border:'1px solid #2563eb', background:'#1d4ed8', color:'#fff', borderRadius:7, padding:'8px 14px', fontWeight:700, cursor:'pointer', fontSize:12 };

export default function SocManagerDashboardPreview({ workMetrics = {}, dateRange = 'today', onDateRangeChange, onRefresh, loading=false, error='', lastUpdated=null }) {
  const rangeLabel = dateRange === '30d' ? 'Last 30 Days' : dateRange === '7d' ? 'Last 7 Days' : 'Today';
  const cards = [
    [`Assigned Work ${rangeLabel}`,workMetrics.assignedWorkToday??0,'#a78bfa'],
    [`Pending Work ${rangeLabel}`,workMetrics.pendingWorkToday??0,'#facc15'],
    [`Completed Work ${rangeLabel}`,workMetrics.completedWorkToday??0,'#34d399'],
    [`Completion Rate ${rangeLabel}`,`${workMetrics.completionRateToday??0}%`,'#22d3ee'],
    [`TI Incidents ${rangeLabel}`,workMetrics.tiIncidentsToday??0,'#c084fc'],
    [`EDR Incidents ${rangeLabel}`,workMetrics.edrIncidentsToday??0,'#f472b6'],
    [`Assigned Tickets ${rangeLabel}`,workMetrics.assignedTicketsToday??0,'#60a5fa'],
    [`Open Work ${rangeLabel}`,workMetrics.openWorkToday??0,'#fb923c'],
    [`Investigating ${rangeLabel}`,workMetrics.investigatingToday??0,'#38bdf8'],
    [`Critical Pending ${rangeLabel}`,workMetrics.criticalPendingToday??0,'#fb7185'],
    ['On Shift Now',workMetrics.onShiftNow??0,'#2dd4bf'],
  ];
  return <div>
    <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',gap:12,flexWrap:'wrap',marginBottom:20}}>
      <div>
        <h1 style={{margin:0,fontSize:24,color:'#f8fafc'}}>SOC Manager Dashboard</h1>
        <p style={{margin:'4px 0 0',color:'#94a3b8',fontSize:13}}>Backend-verified role scope · Real-time SOC metrics & incident queue <span style={{marginLeft:10,color:error?'#facc15':'#34d399',fontWeight:700}}>{error?'● Reconnecting':'● Live'}</span>{lastUpdated&&<span style={{marginLeft:8}}>· Synced {lastUpdated.toLocaleTimeString()}</span>}</p>
      </div>
      <div style={{display:'flex',gap:10,alignItems:'center'}}>
        <select value={dateRange} onChange={e=>onDateRangeChange?.(e.target.value)} disabled={loading} style={{padding:'8px 12px',background:'#07111f',border:'1px solid #294765',borderRadius:7,color:'#e2e8f0',fontSize:12}}><option value="today">Today</option><option value="7d">Last 7 Days</option><option value="30d">Last 30 Days</option></select>
        <button onClick={onRefresh} disabled={loading} style={{...btn,opacity:loading?.65:1}}>{loading?'Refreshing…':'↻ Refresh'}</button>
      </div>
    </div>

    {(loading||error)&&<div style={{...card,padding:'10px 14px',marginBottom:14,color:error?'#fca5a5':'#94a3b8',display:'flex',justifyContent:'space-between',gap:12}}><span>{error||`Refreshing ${rangeLabel.toLowerCase()} live KPI values…`}</span>{error&&<button onClick={onRefresh} style={btn}>Retry</button>}</div>}

    <div data-testid="dashboard-kpi-grid" style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(180px,1fr))',gap:12}}>
      {cards.map(([label,value,color])=><div key={label} style={{...card,textDecoration:'none',transition:'transform .15s,border-color .15s'}}><small style={{color:'#94a3b8',fontSize:12,fontWeight:600}}>{label}</small><div style={{fontSize:28,fontWeight:900,color,marginTop:8}}>{value}</div></div>)}
    </div>

  </div>;
}
