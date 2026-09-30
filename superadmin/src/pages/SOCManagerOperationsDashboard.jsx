import { useEffect, useState } from 'react';
import api from '../api/axios';
import SocManagerDashboardPreview from './SocManagerDashboardPreview';

const panel = { background:'#0b1727', border:'1px solid #1e3a5f', borderRadius:12, padding:18 };
const input = { width:'100%', boxSizing:'border-box', padding:'9px 12px', borderRadius:7, border:'1px solid #294765', background:'#07111e', color:'#f8fafc' };
const button = (background='#0369a1') => ({ border:0, borderRadius:8, padding:'9px 14px', background, color:'#fff', fontWeight:800, cursor:'pointer' });
const WEEKDAY_LABELS = ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'];

export default function SOCManagerOperationsDashboard({ managerId, initialManager, onBack, onLogin, onChat, impersonating=false }) {
  const [data,setData] = useState(null);
  const [busy,setBusy] = useState(false);
  const [notice,setNotice] = useState('');
  const [dateRange,setDateRange] = useState('today');
  const [liveLoading,setLiveLoading] = useState(false);
  const [liveError,setLiveError] = useState('');
  const [lastUpdated,setLastUpdated] = useState(null);
  const [editingShiftId,setEditingShiftId] = useState('');
  const [form,setForm] = useState({ maxWorkload:10, companyId:'', name:'Day Shift', startTime:'09:00', endTime:'18:00', timezone:'Asia/Kolkata', weekdays:[1,2,3,4,5] });
  const load = async (range=dateRange) => {
    const { data:next } = await api.get(`/super-admin/soc-managers/${managerId}`,{params:{range},skipCache:true});
    setData(next);
    setLiveError('');
    setLastUpdated(new Date(next.workMetrics?.updatedAt || next.updatedAt || Date.now()));
    setForm({ maxWorkload:next.manager?.maxWorkload || 10, companyId:next.assignedCompanies?.[0]?._id || '', name:'Day Shift', startTime:'09:00', endTime:'18:00', timezone:'Asia/Kolkata', weekdays:[1,2,3,4,5] });
  };
  useEffect(()=>{ setDateRange('today'); load('today').catch(e=>setNotice(e.response?.data?.message || e.message || 'Failed to load manager')); },[managerId]);
  useEffect(()=>{
    let active=true;
    const refreshLiveData=()=>{
      if(document.visibilityState!=='visible'||editingShiftId||busy)return;
      api.get(`/super-admin/soc-managers/${managerId}`,{params:{range:dateRange},skipCache:true})
        .then(({data:next})=>{if(active){setData(next);setLiveError('');setLastUpdated(new Date(next.workMetrics?.updatedAt || next.updatedAt || Date.now()));}})
        .catch(e=>{if(active)setLiveError(e.response?.data?.message || 'Live refresh failed');});
    };
    const timer=window.setInterval(refreshLiveData,5000);
    const refreshOnFocus=()=>refreshLiveData();
    window.addEventListener('focus',refreshOnFocus);
    return()=>{active=false;window.clearInterval(timer);window.removeEventListener('focus',refreshOnFocus);};
  },[managerId,dateRange,editingShiftId,busy]);
  const changeDateRange = async range => {
    setDateRange(range);
    setLiveLoading(true);
    setLiveError('');
    try {
      const { data:next } = await api.get(`/super-admin/soc-managers/${managerId}`,{params:{range},skipCache:true});
      setData(next);
      setLastUpdated(new Date(next.workMetrics?.updatedAt || next.updatedAt || Date.now()));
    } catch(e) {
      setLiveError(e.response?.data?.message || 'Dashboard filter failed');
    } finally {
      setLiveLoading(false);
    }
  };
  const refreshDashboard = () => changeDateRange(dateRange);
  const shiftPayload = () => ({ companyId:form.companyId, name:form.name, startTime:form.startTime, endTime:form.endTime, timezone:form.timezone, weekdays:form.weekdays });
  const save = async e => { e.preventDefault(); setBusy(true); setNotice(''); try { if(editingShiftId) await api.patch(`/super-admin/soc-managers/${managerId}/shifts/${editingShiftId}`,shiftPayload()); else await api.put(`/super-admin/soc-managers/${managerId}/operations`, { maxWorkload:Number(form.maxWorkload), shift:shiftPayload() }); setNotice(editingShiftId?'Shift updated successfully.':'Shift saved successfully.'); setEditingShiftId(''); await load(); } catch(e){ setNotice(e.response?.data?.message || 'Update failed'); } finally { setBusy(false); } };
  const editShift = shift => { setEditingShiftId(shift._id); setForm(current=>({...current,companyId:shift.companyId?._id || shift.companyId,name:shift.name,startTime:shift.startTime,endTime:shift.endTime,timezone:shift.timezone,weekdays:shift.weekdays?.length?shift.weekdays:[1,2,3,4,5]})); setNotice(''); };
  const cancelEdit = () => { setEditingShiftId(''); setForm(current=>({...current,companyId:data.assignedCompanies?.[0]?._id || '',name:'Day Shift',startTime:'09:00',endTime:'18:00',timezone:'Asia/Kolkata',weekdays:[1,2,3,4,5]})); };
  const deleteShift = async shift => { if(!confirm(`Delete assigned shift "${shift.name}"?`)) return; setBusy(true); setNotice(''); try { await api.delete(`/super-admin/soc-managers/${managerId}/shifts/${shift._id}`); if(editingShiftId===shift._id)setEditingShiftId(''); setNotice('Shift deleted successfully.'); await load(); } catch(e){setNotice(e.response?.data?.message || 'Shift could not be deleted');} finally{setBusy(false);} };
  if(!data) return <div>
    <button onClick={onBack} style={{...button('#1e293b'),marginBottom:14}}>← Back to Managers</button>
    {initialManager&&<div style={{...panel,display:'flex',justifyContent:'space-between',alignItems:'center',gap:12,flexWrap:'wrap',marginBottom:14}}>
      <div><h2 style={{margin:0,color:'#f8fafc'}}>{initialManager.name}</h2><div style={{color:'#64748b',fontSize:12}}>{initialManager.email}</div></div>
      <div style={{display:'flex',gap:8,flexWrap:'wrap'}}>
        <button disabled={impersonating} onClick={event=>onLogin?.(event,initialManager)} style={button('#059669')}>🔑 {impersonating?'Logging in…':'Login as Manager'}</button>
        <button onClick={()=>onChat?.(initialManager)} style={button('#0f766e')}>💬 Chat</button>
      </div>
    </div>}
    <div style={{...panel,color:notice?'#fca5a5':'#94a3b8',display:'flex',justifyContent:'space-between',alignItems:'center',gap:12}}><span>{notice || 'Loading manager operations…'}</span>{notice&&<button onClick={()=>{setNotice('');load('today').catch(e=>setNotice(e.response?.data?.message || e.message || 'Failed to load manager'));}} style={button('#0369a1')}>Retry</button>}</div>
  </div>;
  const { manager, assignedCompanies:companies=[], shifts=[] } = data;
  const shift=shifts[0], working=shifts.some(s=>s.isWorkingNow);
  const open=data.activeAlerts?.length || 0, limit=manager.maxWorkload || 10, pct=Math.min(100,Math.round(open/limit*100));
  return <div>
    <button onClick={onBack} style={{...button('#1e293b'),marginBottom:14}}>← Back to Managers</button>
    <div style={{...panel,display:'flex',justifyContent:'space-between',gap:12,alignItems:'center',marginBottom:14,flexWrap:'wrap'}}>
      <div><h2 style={{margin:0,color:'#f8fafc'}}>{manager.name}</h2><div style={{color:'#64748b',fontSize:12}}>{manager.email}</div></div>
      <div style={{display:'flex',alignItems:'center',gap:8,flexWrap:'wrap'}}>
        <span style={{padding:'7px 12px',borderRadius:999,fontWeight:900,color:working?'#34d399':'#94a3b8',background:working?'#064e3b':'#334155'}}>{working?'● WORKING NOW':'○ NOT WORKING'}</span>
        <button disabled={impersonating} onClick={event=>onLogin?.(event,manager)} style={button('#059669')}>🔑 {impersonating?'Logging in…':'Login as Manager'}</button>
        <button onClick={()=>onChat?.(manager)} style={button('#0f766e')}>💬 Chat</button>
      </div>
    </div>
    {notice&&<div style={{...panel,color:notice.includes('successfully')?'#34d399':'#fca5a5',marginBottom:14,padding:11}}>{notice}</div>}
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(150px,1fr))',gap:10,marginBottom:14}}>
      {[['Company Scope',companies.length],['Assigned Shifts',shifts.length],['Open Workload',`${open}/${limit}`],['Capacity Used',`${pct}%`],['Account',manager.accountStatus||'active']].map(([l,v])=><div key={l} style={panel}><small style={{color:'#64748b'}}>{l}</small><div style={{color:'#38bdf8',fontSize:22,fontWeight:900,marginTop:5}}>{v}</div></div>)}
    </div>
    <section style={{margin:'24px 0',padding:'22px 0',borderTop:'1px solid #1e3a5f',borderBottom:'1px solid #1e3a5f'}}>
      <SocManagerDashboardPreview workMetrics={data.workMetrics} dateRange={dateRange} onDateRangeChange={changeDateRange} onRefresh={refreshDashboard} loading={liveLoading} error={liveError} lastUpdated={lastUpdated} />
    </section>
    <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(330px,1fr))',gap:14}}>
      <form onSubmit={save} style={panel}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:10}}><h3 style={{color:'#f8fafc',marginTop:0}}>{editingShiftId?'Edit Shift':'Shift Assignment'}</h3>{editingShiftId&&<button type="button" onClick={cancelEdit} style={{...button('#334155'),padding:'6px 10px'}}>Cancel Edit</button>}</div>
        {!companies.length&&<div style={{color:'#fca5a5',marginBottom:10}}>Assign company scope before assigning a shift.</div>}
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
          <label><small style={{color:'#94a3b8'}}>Company</small><select required style={input} value={form.companyId} onChange={e=>setForm({...form,companyId:e.target.value})}><option value="">Select</option>{companies.map(c=><option key={c._id} value={c._id}>{c.name}</option>)}</select></label>
          <label><small style={{color:'#94a3b8'}}>Shift Name</small><input required style={input} value={form.name} onChange={e=>setForm({...form,name:e.target.value})}/></label>
          <label><small style={{color:'#94a3b8'}}>Start</small><input required type="time" style={input} value={form.startTime} onChange={e=>setForm({...form,startTime:e.target.value})}/></label>
          <label><small style={{color:'#94a3b8'}}>End</small><input required type="time" style={input} value={form.endTime} onChange={e=>setForm({...form,endTime:e.target.value})}/></label>
          <label><small style={{color:'#94a3b8'}}>Timezone</small><select style={input} value={form.timezone} onChange={e=>setForm({...form,timezone:e.target.value})}><option>Asia/Kolkata</option><option>UTC</option><option>Europe/London</option><option>America/New_York</option></select></label>
        </div>
        <div style={{margin:'12px 0'}}>{['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((d,i)=><label key={d} style={{color:'#cbd5e1',fontSize:11,marginRight:9}}><input type="checkbox" checked={form.weekdays.includes(i)} onChange={e=>setForm({...form,weekdays:e.target.checked?[...form.weekdays,i]:form.weekdays.filter(x=>x!==i)})}/> {d}</label>)}</div>
        <button disabled={busy||!companies.length||!form.weekdays.length} style={button('#b45309')}>{busy?'Saving…':editingShiftId?'Update Shift':'Save Shift'}</button>
        {shift&&<div style={{color:'#94a3b8',fontSize:11,marginTop:12}}>Current: {shift.name} · {shift.startTime}–{shift.endTime} · {shift.timezone}</div>}
      </form>
      <div style={{...panel,minWidth:0,background:'linear-gradient(145deg,#0b1727,#10233c)'}}>
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',gap:12,marginBottom:14}}>
          <h3 style={{color:'#f8fafc',margin:0}}>Assigned Shifts</h3>
          <span style={{padding:'5px 10px',borderRadius:999,background:'rgba(37,99,235,.18)',border:'1px solid #2563eb',color:'#67e8f9',fontSize:12,fontWeight:900}}>Total: {shifts.length}</span>
        </div>
        <div style={{overflowX:'auto',border:'1px solid #1e3a5f',borderRadius:9}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:11}}>
            <thead><tr style={{background:'#091525',color:'#7dd3fc',textAlign:'left'}}>
              {['Shift','Company','Schedule','Status','Actions'].map(label=><th key={label} style={{padding:'10px 9px',fontWeight:800}}>{label}</th>)}
            </tr></thead>
            <tbody>
              {!shifts.length&&<tr><td colSpan="5" style={{padding:24,textAlign:'center',color:'#64748b'}}>No shift assigned</td></tr>}
              {shifts.map(item=><tr key={item._id} style={{borderTop:'1px solid #1e3a5f',color:'#cbd5e1'}}>
                <td style={{padding:'10px 9px',fontWeight:800,color:'#f8fafc'}}>{item.name}</td>
                <td style={{padding:'10px 9px'}}>{item.companyId?.name || '—'}</td>
                <td style={{padding:'10px 9px'}}>{item.startTime}–{item.endTime}<small style={{display:'block',color:'#64748b',marginTop:3}}>{item.weekdays?.map(day=>WEEKDAY_LABELS[day]).join(', ') || '—'}</small></td>
                <td style={{padding:'10px 9px'}}><span style={{color:item.isWorkingNow?'#34d399':'#94a3b8',fontWeight:900,whiteSpace:'nowrap'}}>{item.isWorkingNow?'● ACTIVE NOW':'○ INACTIVE'}</span></td>
                <td style={{padding:'10px 9px'}}><div style={{display:'flex',gap:6}}><button type="button" disabled={busy} onClick={()=>editShift(item)} style={{...button('#0369a1'),padding:'6px 9px',fontSize:10}}>✎ Edit</button><button type="button" disabled={busy} onClick={()=>deleteShift(item)} style={{...button('#7f1d1d'),padding:'6px 9px',fontSize:10}}>Delete</button></div></td>
              </tr>)}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    <ManagerActivityAudit authAudit={data.authAudit} attendanceReport={data.attendanceReport} />
  </div>;
}

function ManagerActivityAudit({authAudit={},attendanceReport=[]}) {
  const auth=authAudit.metrics||{};
  const metrics=[
    ['Successful Logins',auth.loginCount||0,'#34d399'],['Logouts',auth.logoutCount||0,'#f87171'],
    ['30m Auto Logouts',auth.autoLogoutCount||0,'#ef4444'],['Failed Authentication',auth.failedLoginCount||0,'#fb923c'],
    ['Account Locks',auth.accountLockCount||0,'#fb7185'],['10m Screen Locks',auth.screenLockCount||0,'#e879f9'],
    ['Total Session Time',formatAuditMinutes(auth.totalSessionMinutes),'#60a5fa'],['Working-Hours Session',formatAuditMinutes(auth.workingSessionMinutes),'#2dd4bf'],
    ['Outside-Shift Time',formatAuditMinutes(auth.outsideShiftMinutes),'#facc15'],['Screen Locked Time',formatAuditMinutes(auth.screenLockedMinutes),'#d946ef'],
    ['Locked During Working Hours',formatAuditMinutes(auth.lockedWorkingMinutes),'#f43f5e'],['After-Hours Logins',auth.afterHoursLoginCount||0,'#c084fc'],
    ['Active Sessions',auth.activeSessionCount||0,'#22c55e'],
  ];
  return <>
    <section style={{...panel,marginTop:24,padding:20}}>
      <h3 style={{margin:'0 0 6px',color:'#67e8f9',fontSize:16}}>🔐 Live Login, Session & Account Lock Audit</h3>
      <div style={{color:'#64748b',fontSize:11,marginBottom:16}}>Calculated from LoginActivity, SOC audit events and assigned shift windows—not placeholder values.</div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(180px,1fr))',gap:12}}>
        {metrics.map(([label,value,color])=><div key={label} style={{...panel,padding:14}}><small style={{color:'#94a3b8',fontSize:11,fontWeight:700}}>{label}</small><div style={{color,fontSize:21,fontWeight:900,marginTop:7}}>{value}</div></div>)}
      </div>
      <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fit,minmax(340px,1fr))',gap:16,marginTop:18}}>
        <AuditTable title="Login / Logout Sessions" empty="No login session was recorded in this range." columns={['Login','Logout','Logout Type','Duration','In Shift','Outside Shift','Source IP']} rows={(authAudit.sessions||[]).map(session=>[formatAuditDate(session.loginAt),session.logoutAt?formatAuditDate(session.logoutAt):session.active?'Active now':'No logout recorded',session.logoutAction==='auto_logout'?'30m inactivity':session.logoutAction==='logout'?'Manual':'—',formatAuditMinutes(session.durationMinutes),formatAuditMinutes(session.workingMinutes),formatAuditMinutes(session.outsideShiftMinutes),session.ipAddress||'—'])}/>
        <AuditTable title="Account Lock Timeline" empty="No account lock or manager suspension occurred in this range." columns={['Type','Locked At','Unlocked At','Total','During Shift','Reason']} rows={(authAudit.locks||[]).map(lock=>[lock.type==='screen_lock'?'Screen lock':lock.type==='manager_suspension'?'Account suspended':'Account lock',formatAuditDate(lock.start),formatAuditDate(lock.end),formatAuditMinutes(lock.durationMinutes),formatAuditMinutes(lock.workingMinutes),lock.reason||'Account lock'])}/>
      </div>
      <div style={{marginTop:18}}><AuditTable title="Complete SOC Manager Audit Timeline" maxVisibleRows={10} empty="No authentication or SOC audit activity was recorded in this range." columns={['Time','Source','Action','Result / Reason','IP / Actor']} rows={(authAudit.activityTimeline||[]).map(event=>[formatAuditDate(event.at),event.source==='authentication'?'Authentication':'SOC Audit',String(event.action||'activity').replace(/_/g,' '),event.reason||(event.success===false?'Failed':'Success'),event.ipAddress||event.actor?.name||event.actor?.email||'System'])}/></div>
    </section>

    <section style={{...panel,marginTop:24,padding:20}}>
      <h3 style={{margin:'0 0 16px',color:'#67e8f9',fontSize:16}}>📅 Shift Adherence & Session Attendance (Last 7 Days)</h3>
      {!attendanceReport.length?<div style={{color:'#64748b',fontSize:13,fontStyle:'italic',textAlign:'center',padding:'24px 0',border:'1px dashed #1e3a5f',borderRadius:8}}>No shifts or attendance logs recorded in the last 7 days for this SOC Manager.</div>:<div style={{overflowX:'auto'}}><table style={{width:'100%',minWidth:1050,borderCollapse:'collapse',fontSize:13,textAlign:'left'}}><thead><tr style={{borderBottom:'2px solid #1e3a5f',color:'#7dd3fc'}}>{['Date / Day','Shift Details','Shift Timing','Login Time','Logout Time','Lateness','Working Session','Locked in Shift','Failed Auth','Logouts (In Shift)','Status'].map(label=><th key={label} style={{padding:'12px 8px'}}>{label}</th>)}</tr></thead><tbody>{attendanceReport.map((item,index)=><tr key={`${item.date}-${item.shiftName}-${index}`} style={{borderBottom:'1px solid #1e3a5f',background:index%2===0?'rgba(30,58,95,.15)':'transparent'}}><td style={{padding:'12px 8px',fontWeight:600,color:'#f8fafc'}}>{item.date}<small style={{display:'block',color:'#94a3b8',marginTop:2}}>{item.dayName}</small></td><td style={{padding:'12px 8px',color:'#cbd5e1'}}>{item.shiftName}</td><td style={{padding:'12px 8px',color:'#94a3b8',fontSize:12}}>{item.shiftTime}</td><td style={{padding:'12px 8px',color:'#34d399',fontWeight:700}}>{item.loginTime}</td><td style={{padding:'12px 8px',color:'#f87171',fontWeight:700}}>{item.logoutTime}</td><td style={{padding:'12px 8px',color:item.lateTime==='On Time'?'#34d399':'#fbbf24'}}>{item.lateTime}</td><td style={{padding:'12px 8px',color:'#2dd4bf',fontWeight:700}}>{formatAuditMinutes(item.sessionMinutes)}</td><td style={{padding:'12px 8px',color:item.lockMinutes?'#fb7185':'#64748b',fontWeight:700}}>{formatAuditMinutes(item.lockMinutes)}</td><td style={{padding:'12px 8px',color:item.failedLoginCount?'#fb923c':'#64748b'}}>{item.failedLoginCount||0}</td><td style={{padding:'12px 8px',textAlign:'center',color:item.logoutCount?'#f87171':'#94a3b8'}}>{item.logoutCount||0}</td><td style={{padding:'12px 8px',color:item.status==='Present'?'#10b981':'#f87171',fontWeight:800}}>{item.status}</td></tr>)}</tbody></table></div>}
    </section>
  </>;
}

function AuditTable({title,empty,columns,rows,maxVisibleRows=0}) {
  return <div style={{...panel,padding:0,minWidth:0,overflow:'hidden'}}><div style={{padding:'12px 14px',color:'#bae6fd',fontSize:12,fontWeight:900,borderBottom:'1px solid #1e3a5f',display:'flex',justifyContent:'space-between',gap:10}}><span>{title}</span>{maxVisibleRows>0&&<span style={{color:'#64748b',fontWeight:700}}>{rows.length} logs · {Math.min(maxVisibleRows,rows.length)} visible</span>}</div>{rows.length?<div style={{overflowX:'auto',overflowY:maxVisibleRows>0?'scroll':'visible',maxHeight:maxVisibleRows>0?424:'none'}}><table style={{width:'100%',minWidth:Math.max(560,columns.length*115),borderCollapse:'collapse'}}><thead><tr>{columns.map(column=><th key={column} style={{padding:'9px 10px',color:'#7dd3fc',fontSize:11,textAlign:'left',whiteSpace:'nowrap',position:maxVisibleRows>0?'sticky':'static',top:0,background:'#0c192c'}}>{column}</th>)}</tr></thead><tbody>{rows.map((values,rowIndex)=><tr key={`${title}-${rowIndex}`}>{values.map((value,columnIndex)=><td key={`${rowIndex}-${columnIndex}`} style={{padding:10,color:'#cbd5e1',fontSize:11,borderTop:'1px solid #162c47',verticalAlign:'top',whiteSpace:maxVisibleRows>0?'nowrap':'normal'}}>{value}</td>)}</tr>)}</tbody></table></div>:<div style={{padding:20,color:'#64748b',fontSize:11}}>{empty}</div>}</div>;
}

function formatAuditMinutes(value) { const minutes=Math.max(0,Math.round(Number(value)||0)); if(!minutes)return '—'; const hours=Math.floor(minutes/60); const remainder=minutes%60; return hours?`${hours}h${remainder?` ${remainder}m`:''}`:`${remainder}m`; }
function formatAuditDate(value) { if(!value)return '—'; const date=new Date(value); return Number.isNaN(date.getTime())?'—':date.toLocaleString(); }
