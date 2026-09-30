import { useState } from 'react';
import { useAuth } from '../../context/AuthContext';
import api from '../../api/axios';

export default function AnalystSettings() {
  const { user, company } = useAuth();
  const [pwForm, setPwForm] = useState({ currentPassword:'', newPassword:'', confirm:'' });
  const [pwMsg,  setPwMsg]  = useState('');
  const [pwErr,  setPwErr]  = useState('');
  const [pwBusy, setPwBusy] = useState(false);

  const changePassword = async (e) => {
    e.preventDefault();
    if (pwForm.newPassword.length < 8) {
      setPwErr('New password must be at least 8 characters'); return;
    }
    if (pwForm.newPassword !== pwForm.confirm) {
      setPwErr('Passwords do not match'); return;
    }
    setPwBusy(true); setPwMsg(''); setPwErr('');
    try {
      await api.post('/users/change-password', {
        currentPassword: pwForm.currentPassword,
        newPassword:     pwForm.newPassword,
      });
      setPwMsg('Password updated successfully.');
      setPwForm({ currentPassword:'', newPassword:'', confirm:'' });
    } catch (err) {
      setPwErr(err.response?.data?.message || 'Failed to update password');
    } finally { setPwBusy(false); }
  };

  const Row = ({ label, value }) => (
    <div style={{ display:'flex', justifyContent:'space-between', padding:'8px 0',
                  borderBottom:'1px solid #060e1a', fontSize:13 }}>
      <span style={{ color:'#1e40af' }}>{label}</span>
      <span style={{ color:'#93c5fd' }}>{value||'—'}</span>
    </div>
  );

  const Section = ({ title, children }) => (
    <div style={{ background:'#0c1a2e', borderRadius:10, padding:'20px 22px',
                  border:'1px solid #1e3a5f', marginBottom:20 }}>
      <h3 style={{ fontSize:13, color:'#60a5fa', marginBottom:14 }}>{title}</h3>
      {children}
    </div>
  );

  return (
    <div>
      <h2 style={{ fontSize:20, color:'#e0f2fe', marginBottom:24 }}>Settings</h2>

      <Section title="Your account">
        <Row label="Name"    value={user?.name}/>
        <Row label="Email"   value={user?.email}/>
        <Row label="Role"    value="Analyst"/>
        <Row label="Company" value={company?.name}/>
      </Section>

      <Section title="Change password">
        {pwMsg && (
          <div style={{ background:'#064e3b', color:'#34d399', padding:'7px 12px',
                        borderRadius:6, marginBottom:12, fontSize:13 }}>{pwMsg}</div>
        )}
        {pwErr && (
          <div style={{ background:'#1c0a0a', color:'#fca5a5', padding:'7px 12px',
                        borderRadius:6, marginBottom:12, fontSize:13 }}>{pwErr}</div>
        )}
        <form onSubmit={changePassword}>
          {[
            { key:'currentPassword', label:'Current password' },
            { key:'newPassword',     label:'New password (min 8 chars)' },
            { key:'confirm',         label:'Confirm new password' },
          ].map(({ key, label }) => (
            <div key={key} style={{ marginBottom:12 }}>
              <label style={{ display:'block', color:'#1e40af', fontSize:12, marginBottom:3 }}>
                {label}
              </label>
              <input type="password" required value={pwForm[key]}
                onChange={e => setPwForm(f=>({...f,[key]:e.target.value}))}
                style={{ width:'100%', maxWidth:320, padding:'8px 10px', borderRadius:6,
                         background:'#060e1a', border:'1px solid #1e3a5f',
                         color:'#e2e8f0', fontSize:13, boxSizing:'border-box', outline:'none' }}/>
            </div>
          ))}
          <button type="submit" disabled={pwBusy} style={{
            marginTop:6, padding:'8px 18px', borderRadius:6, border:'none',
            background: pwBusy ? '#1e3a5f' : '#2563eb', color:'#fff',
            fontSize:13, cursor:'pointer',
          }}>
            {pwBusy ? 'Updating…' : 'Update password'}
          </button>
        </form>
      </Section>

      <Section title="Access level">
        <p style={{ fontSize:12, color:'#1e40af', marginBottom:12 }}>
          As an analyst, you have read access to:
        </p>
        {[
          { icon:'📊', label:'Dashboard',  desc:'Live alert feed and summary stats' },
          { icon:'🔔', label:'Alerts',     desc:'View all alerts (read-only)' },
          { icon:'📈', label:'Reports',    desc:'Generate and export security reports' },
        ].map(({ icon, label, desc }) => (
          <div key={label} style={{ display:'flex', gap:10, alignItems:'center',
                                    padding:'8px 0', borderBottom:'1px solid #060e1a' }}>
            <span style={{ fontSize:16 }}>{icon}</span>
            <div>
              <div style={{ fontSize:13, color:'#e2e8f0' }}>{label}</div>
              <div style={{ fontSize:11, color:'#1e40af' }}>{desc}</div>
            </div>
          </div>
        ))}
        <p style={{ fontSize:11, color:'#1e3a5f', marginTop:10 }}>
          To request additional access, contact your company admin.
        </p>
      </Section>
    </div>
  );
}
