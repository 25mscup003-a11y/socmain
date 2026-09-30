import { useEffect, useState } from 'react';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';

export default function SettingsPage() {
  const { user } = useAuth();
  const [tab, setTab] = useState('general');
  const [integrations, setIntegrations] = useState([]);
  const [integrationSummary, setIntegrationSummary] = useState(null);
  const [integrationLoading, setIntegrationLoading] = useState(false);
  const [integrationError, setIntegrationError] = useState('');

  async function loadIntegrations() {
    setIntegrationLoading(true);
    setIntegrationError('');
    try {
      const { data } = await api.get('/superadmin/integrations/status');
      setIntegrations(data.integrations || []);
      setIntegrationSummary(data.summary || null);
    } catch (error) {
      setIntegrationError(error.response?.data?.message || 'Unable to load integration status');
    } finally {
      setIntegrationLoading(false);
    }
  }

  useEffect(() => {
    if (tab === 'integrations') loadIntegrations();
  }, [tab]);

  const S = { input: { fontSize:12, padding:'8px 12px', borderRadius:6, border:'1px solid #312e81', background:'#2e1065', color:'#e9d5ff', width:'100%' } };

  return (
    <div>
      <h2 style={{ fontSize:20, color:'#e9d5ff', marginBottom:6 }}>⚙️ Settings</h2>
      <div style={{ fontSize:11, color:'#4c1d95', marginBottom:20 }}>Platform configuration and role-based access</div>

      <div style={{ display:'flex', gap:0, borderBottom:'1px solid #312e81', marginBottom:20 }}>
        {[{k:'general',l:'General'},{k:'roles',l:'Role Access'},{k:'integrations',l:'Integrations'}].map(t => (
          <button key={t.k} onClick={() => setTab(t.k)} style={{
            padding:'10px 20px', border:'none', background:'transparent', cursor:'pointer', fontSize:13,
            color: tab===t.k ? '#e9d5ff' : '#4c1d95', borderBottom: tab===t.k ? '2px solid #7c3aed' : '2px solid transparent',
          }}>{t.l}</button>
        ))}
      </div>

      {tab === 'general' && (
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10, padding:'20px 24px' }}>
          <h3 style={{ fontSize:14, color:'#e9d5ff', marginBottom:16 }}>Platform Settings</h3>
          <div style={{ display:'grid', gap:12, maxWidth:500 }}>
            <div><label style={{ fontSize:10, color:'#4c1d95', display:'block', marginBottom:4 }}>Admin Name</label><input defaultValue={user?.name} style={S.input} /></div>
            <div><label style={{ fontSize:10, color:'#4c1d95', display:'block', marginBottom:4 }}>Admin Email</label><input defaultValue={user?.email} style={S.input} /></div>
            <div><label style={{ fontSize:10, color:'#4c1d95', display:'block', marginBottom:4 }}>Log Retention (days)</label><input defaultValue="90" type="number" style={S.input} /></div>
            <div><label style={{ fontSize:10, color:'#4c1d95', display:'block', marginBottom:4 }}>Correlation Interval (min)</label><input defaultValue="5" type="number" style={S.input} /></div>
          </div>
        </div>
      )}

      {tab === 'roles' && (
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10, padding:'20px 24px' }}>
          <h3 style={{ fontSize:14, color:'#e9d5ff', marginBottom:16 }}>Role-Based Access Control</h3>
          <table style={{ width:'100%', borderCollapse:'collapse', fontSize:12 }}>
            <thead>
              <tr style={{ borderBottom:'1px solid #312e81' }}>
                {['Feature','SuperAdmin','Company Admin','Dept Admin','Analyst'].map(h => (
                  <th key={h} style={{ padding:'8px 10px', color:'#7c3aed', textAlign:'left', fontWeight:600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ['System Management','✅','✅','👁','👁'],
                ['Alert Management','✅','✅','✅','📝'],
                ['EDR/IDS/IPS Config','✅','✅','👁','❌'],
                ['Firewall Rules','✅','✅','👁','❌'],
                ['User Management','✅','✅','❌','❌'],
                ['Compliance Reports','✅','✅','✅','✅'],
                ['Security Score','✅','✅','✅','✅'],
                ['Revenue/Billing','✅','❌','❌','❌'],
                ['Dashboard Config','✅','✅','❌','❌'],
              ].map(row => (
                <tr key={row[0]} style={{ borderBottom:'1px solid #2e1065' }}>
                  {row.map((cell, i) => (
                    <td key={i} style={{ padding:'8px 10px', color: i===0 ? '#c4b5fd' : '#e9d5ff' }}>{cell}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {tab === 'integrations' && (
        <div style={{ background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10, padding:'20px 24px' }}>
          <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
            <div>
              <h3 style={{ fontSize:14, color:'#e9d5ff', margin:0 }}>Live Integration Status</h3>
              <div style={{ fontSize:10, color:'#7c3aed', marginTop:4 }}>
                Configuration is read from the backend environment; secret values are never displayed.
              </div>
            </div>
            <button onClick={loadIntegrations} disabled={integrationLoading} style={{
              padding:'6px 10px', borderRadius:6, border:'1px solid #4c1d95',
              background:'#2e1065', color:'#c4b5fd', cursor:'pointer', fontSize:11,
            }}>{integrationLoading ? 'Checking…' : '↻ Refresh'}</button>
          </div>

          {integrationSummary && (
            <div style={{ display:'flex', gap:10, marginBottom:14 }}>
              {[
                ['Total', integrationSummary.total, '#c4b5fd'],
                ['Configured', integrationSummary.configured, '#60a5fa'],
                ['Active', integrationSummary.active, '#34d399'],
              ].map(([label, value, color]) => (
                <div key={label} style={{ background:'#2e1065', border:'1px solid #312e81', borderRadius:7, padding:'8px 12px', minWidth:90 }}>
                  <div style={{ color, fontSize:16, fontWeight:700 }}>{value}</div>
                  <div style={{ color:'#7c3aed', fontSize:9 }}>{label}</div>
                </div>
              ))}
            </div>
          )}

          {integrationError && (
            <div style={{ color:'#f87171', fontSize:11, padding:'10px 0' }}>{integrationError}</div>
          )}
          {integrationLoading && integrations.length === 0 && (
            <div style={{ color:'#a78bfa', fontSize:12, padding:'12px 0' }}>Reading backend configuration…</div>
          )}
          {integrations.map(item => {
            const active = item.configured && item.enabled;
            const status = !item.configured ? 'Not configured' : active ? 'Active' : 'Configured, disabled';
            const color = !item.configured ? '#f87171' : active ? '#34d399' : '#fcd34d';
            return (
              <div key={item.id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', gap:20, padding:'11px 0', borderBottom:'1px solid #2e1065' }}>
                <div>
                  <div style={{ color:'#c4b5fd', fontSize:13 }}>{item.name}</div>
                  <div style={{ color:'#7c3aed', fontSize:10, marginTop:3 }}>{item.detail}</div>
                </div>
                <span style={{ color, fontSize:11, whiteSpace:'nowrap' }}>
                  {active ? '●' : item.configured ? '◐' : '○'} {status}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
