import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../api/axios';
import DailyReportCard from '../components/DailyReportCard';
import DashboardToolsCard, { DashboardToast } from '../components/DashboardToolsCard';
import { useDashboardConfig } from '../hooks/useDashboardConfig';

const RISK = {
  high:   { color:'#f87171', bg:'#7f1d1d', label:'HIGH' },
  medium: { color:'#fcd34d', bg:'#78350f', label:'MED'  },
  low:    { color:'#6ee7c6', bg:'#064e3b', label:'LOW'  },
};

function Spark({ data = [] }) {
  if (!data.length) return null;
  const vals = data.map(d => d.count);
  const max  = Math.max(...vals, 1);
  const W = 70, H = 22;
  const pts = vals.map((v,i) => `${(i/(vals.length-1))*W},${H-(v/max)*H}`).join(' ');
  return <svg width={W} height={H} style={{ display:'block' }}>
    <polyline points={pts} fill="none" stroke="#7c3aed" strokeWidth="1.5" strokeLinejoin="round"/>
  </svg>;
}

function RiskBadge({ risk = 'low' }) {
  const r = RISK[risk] || RISK.low;
  return <span style={{ fontSize:9, padding:'2px 6px', borderRadius:4, fontWeight:600, background:r.bg, color:r.color }}>{r.label}</span>;
}

function BigCard({ icon, title, main, sub, risk, spark, children }) {
  return (
    <div style={{ background:'#1e1b4b', border:`1px solid ${RISK[risk]?.color||'#312e81'}44`,
                  borderRadius:10, padding:'14px 16px', flex:1, minWidth:155 }}>
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', marginBottom:8 }}>
        <div style={{ display:'flex', alignItems:'center', gap:7 }}>
          <span style={{ fontSize:16 }}>{icon}</span>
          <span style={{ fontSize:11, color:'#4c1d95' }}>{title}</span>
        </div>
        <RiskBadge risk={risk}/>
      </div>
      <div style={{ fontSize:26, fontWeight:600, color:'#e9d5ff', marginBottom:4 }}>{main}</div>
      <div style={{ fontSize:11, color:'#4c1d95', marginBottom:8 }}>{sub}</div>
      {children && <div style={{ fontSize:10, color:'#7c3aed', marginBottom:6 }}>{children}</div>}
      <Spark data={spark}/>
    </div>
  );
}

export default function CompanyDashboard() {
  const { companyId } = useParams();
  const navigate      = useNavigate();
  const [data,  setData]  = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,  setError] = useState('');
  const [payData, setPayData] = useState(null);
  const [agentStats, setAgentStats] = useState(null);

  const load = useCallback(() => {
    setLoading(true); setError('');
    Promise.all([
      api.get(`/dashboard/company/${companyId}/overview`),
      api.get(`/superadmin/companies/${companyId}`),
    ])
    .then(([dashRes, coRes]) => {
      setData({ ...dashRes.data, company: dashRes.data.company || coRes.data });
    })
    .catch(err => setError(err.response?.data?.message || 'Failed to load'))
    .finally(() => setLoading(false));

    // Agent/system stats
    api.get(`/superadmin/companies/${companyId}/departments`).then(r => setAgentStats(r.data));
  }, [companyId]);

  // ── Centralized dashboard config (read-only view for superadmin, can edit via override) ──
  const { config: dashCfg, save: saveDashCfg, saving: savingCfg } = useDashboardConfig({
    companyId,
  });

  useEffect(() => { load(); }, [load]);

  const co    = data?.company;
  const c     = data?.cards || {};
  const spark = data?.sparkline || [];
  const depts = data?.departments || [];

  if (loading) return <p style={{ color:'#4c1d95', fontSize:13 }}>Loading…</p>;
  if (error)   return <p style={{ color:'#fca5a5', fontSize:13 }}>{error}</p>;

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ fontSize:12, color:'#4c1d95', marginBottom:16, display:'flex', alignItems:'center', gap:6 }}>
        <Link to="/" style={{ color:'#7c3aed', textDecoration:'none' }}>Dashboard</Link>
        <span>›</span>
        <span style={{ color:'#c4b5fd' }}>{co?.name}</span>
      </div>

      {/* Company header */}
      <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:12,
                    padding:'16px 20px', marginBottom:20, display:'flex',
                    justifyContent:'space-between', alignItems:'center', flexWrap:'wrap', gap:12 }}>
        <div>
          <h2 style={{ fontSize:18, color:'#e9d5ff', marginBottom:3 }}>🏢 {co?.name}</h2>
          <div style={{ fontSize:11, color:'#4c1d95', display:'flex', gap:14 }}>
            <span>Plan: <strong style={{ color:'#a78bfa' }}>{co?.plan?.type || 'trial'}</strong></span>
            <span>Status: <strong style={{ color: co?.status==='active' ? '#34d399' : '#f59e0b' }}>{co?.status}</strong></span>
            <span>Systems: <strong style={{ color:'#c4b5fd' }}>{c.isolation?.total || 0}</strong></span>
          </div>
        </div>
        <div style={{ display:'flex', gap:8 }}>
          <button onClick={load} style={{ fontSize:11, padding:'4px 10px', borderRadius:4,
            border:'1px solid #312e81', background:'none', color:'#a78bfa', cursor:'pointer' }}>↺ Refresh</button>
          <Link to={`/companies/${companyId}`}>
            <button style={{ fontSize:11, padding:'4px 12px', borderRadius:4, border:'none',
              background:'#312e81', color:'#c4b5fd', cursor:'pointer' }}>Manage →</button>
          </Link>
        </div>
      </div>

      {/* ── 8 Security cards ── */}
      <div style={{ display:'flex', gap:10, marginBottom:10, flexWrap:'wrap' }}>
        <BigCard icon="🦠" title="Malware (7d)"    risk={c.malware?.risk}    main={c.malware?.total??'—'}    sub={`Trojan:${c.malware?.types?.trojan||0} Ransomware:${c.malware?.types?.ransomware||0}`} spark={spark}>VT avg: {c.malware?.avgVtScore||0}</BigCard>
        <BigCard icon="🌐" title="Network (7d)"    risk={c.network?.risk}    main={c.network?.total??'—'}    sub={`Blocked:${c.network?.blocked||0} · IPs:${c.network?.suspIps||0}`} spark={spark}/>
        <BigCard icon="📁" title="Files (7d)"      risk={c.file?.risk}       main={c.file?.total??'—'}       sub={`+${c.file?.created||0} ~${c.file?.modified||0} -${c.file?.deleted||0}`} spark={spark}/>
        <BigCard icon="🖥" title="System logs (7d)" risk={c.system?.risk}    main={c.system?.total??'—'}     sub={`Errors:${c.system?.errors||0} Warnings:${c.system?.warnings||0}`} spark={spark}/>
      </div>
      <div style={{ display:'flex', gap:10, marginBottom:20, flexWrap:'wrap' }}>
        <BigCard icon="🚫" title="Isolated"        risk={c.isolation?.risk}  main={c.isolation?.isolated??'—'} sub={`Total:${c.isolation?.total||0} Active:${c.isolation?.active||0}`} spark={spark}/>
        <BigCard icon="👤" title="EDR (7d)"         risk={c.edr?.risk}        main={c.edr?.total??'—'}        sub={`Logins:${c.edr?.logins||0} Suspicious:${c.edr?.suspicious||0}`} spark={spark}/>
        <BigCard icon="🔌" title="USB (7d)"         risk={c.usb?.risk}        main={c.usb?.total??'—'}        sub={`Connected:${c.usb?.connected||0} Blocked:${c.usb?.blocked||0}`} spark={spark}/>
        <BigCard icon="🔥" title="Threat Intel"    risk={c.threatIntel?.risk} main={c.threatIntel?.total??'—'} sub={`High risk:${c.threatIntel?.highRisk||0} · Score:${c.threatIntel?.maxScore||0}`} spark={spark}/>
      </div>

      {/* ── 3 extra cards: Plan, Installation, Report ── */}
      <div style={{ display:'flex', gap:12, marginBottom:22, flexWrap:'wrap' }}>
        {/* Plan & Payments */}
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
                      padding:'16px 18px', flex:1, minWidth:200 }}>
          <div style={{ fontSize:13, color:'#a78bfa', fontWeight:500, marginBottom:10 }}>💳 Plan &amp; Payments</div>
          {[
            { label:'Plan',     value: co?.plan?.type || 'none' },
            { label:'Status',   value: co?.plan?.isActive ? 'Active' : 'Inactive', color: co?.plan?.isActive ? '#34d399' : '#f59e0b' },
            { label:'Systems',  value: `${c.isolation?.total||0} / ${co?.plan?.systemLimit||0}` },
            { label:'Expires',  value: co?.plan?.expiresAt ? new Date(co.plan.expiresAt).toLocaleDateString() : '—' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{ display:'flex', justifyContent:'space-between', padding:'4px 0',
                                      borderBottom:'1px solid #312e81', fontSize:12 }}>
              <span style={{ color:'#4c1d95' }}>{label}</span>
              <span style={{ color: color || '#c4b5fd', fontWeight:500 }}>{value}</span>
            </div>
          ))}
          <Link to={`/companies/${companyId}`}>
            <button style={{ marginTop:10, fontSize:11, padding:'4px 10px', borderRadius:4,
              border:'none', background:'#312e81', color:'#c4b5fd', cursor:'pointer', width:'100%' }}>
              Manage plan →
            </button>
          </Link>
        </div>

        {/* Installation Overview */}
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
                      padding:'16px 18px', flex:1, minWidth:200 }}>
          <div style={{ fontSize:13, color:'#a78bfa', fontWeight:500, marginBottom:10 }}>📦 Installation</div>
          {[
            { label:'Registered',    value: c.isolation?.total || 0 },
            { label:'Active now',    value: c.isolation?.active || 0 },
            { label:'Disconnected',  value: c.isolation?.isolated || 0 },
            { label:'Departments',   value: depts.length },
          ].map(({ label, value }) => (
            <div key={label} style={{ display:'flex', justifyContent:'space-between', padding:'4px 0',
                                      borderBottom:'1px solid #312e81', fontSize:12 }}>
              <span style={{ color:'#4c1d95' }}>{label}</span>
              <span style={{ color:'#c4b5fd', fontWeight:500 }}>{value}</span>
            </div>
          ))}
          <Link to={`/companies/${companyId}`}>
            <button style={{ marginTop:10, fontSize:11, padding:'4px 10px', borderRadius:4,
              border:'none', background:'#312e81', color:'#c4b5fd', cursor:'pointer', width:'100%' }}>
              View systems →
            </button>
          </Link>
        </div>

        {/* Report */}
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
                      padding:'16px 18px', flex:1, minWidth:200 }}>
          <div style={{ fontSize:13, color:'#a78bfa', fontWeight:500, marginBottom:10 }}>📄 Report</div>
          <p style={{ fontSize:12, color:'#4c1d95', marginBottom:12 }}>
            Generate a security report for {co?.name}
          </p>
          <div style={{ display:'flex', flexDirection:'column', gap:6 }}>
            <button onClick={async () => {
              try {
                const from = new Date(Date.now()-30*86400000).toISOString().slice(0,10);
                const to   = new Date().toISOString().slice(0,10);
                const { data } = await api.get(`/reports/company/${companyId}/csv?from=${from}&to=${to}`, { responseType:'blob' });
                const url = URL.createObjectURL(new Blob([data],{type:'text/csv'}));
                const a = document.createElement('a'); a.href=url; a.download=`report-${co?.name}-${from}.csv`; a.click();
                URL.revokeObjectURL(url);
              } catch(err) { alert('CSV failed: '+err.message); }
            }} style={{ fontSize:11, padding:'6px 10px', borderRadius:4, border:'none',
              background:'#064e3b', color:'#34d399', cursor:'pointer', width:'100%' }}>
              ↓ Download CSV
            </button>
            <button onClick={async () => {
              try {
                const from = new Date(Date.now()-30*86400000).toISOString().slice(0,10);
                const to   = new Date().toISOString().slice(0,10);
                const { data } = await api.get(`/reports/company/${companyId}/pdf?from=${from}&to=${to}`, { responseType:'blob' });
                const url = URL.createObjectURL(new Blob([data],{type:'text/html'}));
                const a = document.createElement('a'); a.href=url; a.download=`report-${co?.name}-${from}.html`; a.click();
                URL.revokeObjectURL(url);
              } catch(err) { alert('PDF failed: '+err.message); }
            }} style={{ fontSize:11, padding:'6px 10px', borderRadius:4, border:'none',
              background:'#2e1065', color:'#c4b5fd', cursor:'pointer', width:'100%' }}>
              🖨 Download PDF
            </button>
          </div>
        </div>
      </div>

      {/* ── Choose Department card ── */}
      <div style={{ background:'#2e1065', border:'2px solid #7c3aed', borderRadius:12,
                    padding:'18px 20px', marginBottom:22 }}>
        <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:14 }}>
          <span style={{ fontSize:20 }}>🏬</span>
          <div>
            <div style={{ fontSize:15, fontWeight:600, color:'#e9d5ff' }}>Choose Department</div>
            <div style={{ fontSize:11, color:'#7c3aed' }}>Select a department to view filtered security data and take actions</div>
          </div>
        </div>
        <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>
          {depts.map(d => (
            <button key={d._id}
              onClick={() => navigate(`/companies/${companyId}/dept-dashboard/${d._id}`)}
              style={{
                fontSize:13, padding:'10px 18px', borderRadius:8, border:'1px solid #4c1d95',
                background:'#1e1b4b', color:'#c4b5fd', cursor:'pointer',
                display:'flex', flexDirection:'column', alignItems:'flex-start', gap:2,
              }}>
              <span style={{ fontWeight:500 }}>📁 {d.name}</span>
              <span style={{ fontSize:10, color:'#4c1d95' }}>{d.systemCount || 0} systems</span>
            </button>
          ))}
          {depts.length === 0 && (
            <p style={{ fontSize:13, color:'#4c1d95' }}>No departments yet.</p>
          )}
        </div>
      </div>


      <DailyReportCard companyApiPrefix={`/daily-report/company/${companyId}`} />

      {/* ── Centralized tools card — reflects company admin config in real-time ── */}
      <div style={{ marginTop: 20 }}>
        <div style={{ fontSize: 12, color: '#7c3aed', marginBottom: 8 }}>📋 Log Monitoring Tools (synced from company config)</div>
        <DashboardToolsCard
          config={dashCfg}
          canEdit={true}
          onSave={saveDashCfg}
          saving={savingCfg}
          basePath={`/companies/${companyId}/`}
          navigate={navigate}
        />
      </div>
      <DashboardToast />
    </div>
  );
}
