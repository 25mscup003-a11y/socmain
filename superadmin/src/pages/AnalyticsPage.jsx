import { useEffect, useState } from 'react';
import api from '../api/axios';

export default function AnalyticsPage() {
  const [data, setData] = useState(null);

  useEffect(() => {
    api.get('/superadmin/overview').then(r => setData(r.data));
  }, []);

  if (!data) return <p style={{ color:'#4c1d95', fontSize:13 }}>Loading…</p>;

  const max = Math.max(...(data.alertsByDay || []).map(d => d.count), 1);

  return (
    <div>
      <h2 style={{ fontSize:20, color:'#e9d5ff', marginBottom:24 }}>Analytics</h2>

      <div style={{ display:'flex', gap:14, marginBottom:28, flexWrap:'wrap' }}>
        {[
          { label:'Companies', value:data.companies, color:'#a78bfa' },
          { label:'Users',     value:data.users,     color:'#34d399' },
          { label:'Systems',   value:data.systems,   color:'#60a5fa' },
          { label:'Alerts',    value:data.alerts,    color:'#f59e0b' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{
            background:'#1e1b4b', border:`1px solid ${color}33`,
            borderRadius:10, padding:'18px 20px', flex:1, minWidth:120,
          }}>
            <div style={{ fontSize:28, fontWeight:600, color }}>{value}</div>
            <div style={{ fontSize:11, color:'#4c1d95', marginTop:3 }}>{label}</div>
          </div>
        ))}
      </div>

      <div style={{ background:'#1e1b4b', borderRadius:10, padding:'20px 22px', border:'1px solid #312e81' }}>
        <h3 style={{ fontSize:13, color:'#c4b5fd', marginBottom:16 }}>Alerts per day (last 30)</h3>
        {(data.alertsByDay || []).map(d => (
          <div key={d._id} style={{ display:'flex', alignItems:'center', gap:10, marginBottom:6 }}>
            <span style={{ fontSize:11, color:'#4c1d95', width:90, textAlign:'right' }}>{d._id}</span>
            <div style={{ flex:1, height:14, background:'#0f172a', borderRadius:4, overflow:'hidden' }}>
              <div style={{
                width:`${(d.count/max)*100}%`, height:'100%',
                background:'#7c3aed', borderRadius:4, minWidth:4,
              }}/>
            </div>
            <span style={{ fontSize:11, color:'#a78bfa', width:28, textAlign:'right' }}>{d.count}</span>
          </div>
        ))}
        {(!data.alertsByDay || data.alertsByDay.length === 0) && (
          <p style={{ color:'#312e81', fontSize:13 }}>No alert data yet.</p>
        )}
      </div>
    </div>
  );
}
