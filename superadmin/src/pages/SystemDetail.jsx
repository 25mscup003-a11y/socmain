import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/axios';

const SEV_BG    = { critical:'#7f1d1d', high:'#78350f', medium:'#1e3a5f', low:'#064e3b' };
const SEV_COLOR = { critical:'#fca5a5', high:'#fcd34d', medium:'#93c5fd', low:'#6ee7c6' };

export default function SystemDetail() {
  const { companyId, deptId, systemId } = useParams();
  const [system,  setSystem]  = useState(null);
  const [company, setCompany] = useState(null);
  const [dept,    setDept]    = useState(null);
  const [alerts,  setAlerts]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.get(`/superadmin/companies/${companyId}`),
      api.get(`/superadmin/companies/${companyId}/departments/${deptId}`),
      api.get(`/superadmin/companies/${companyId}/departments/${deptId}/systems/${systemId}`),
      api.get(`/superadmin/companies/${companyId}/systems/${systemId}/alerts`),
    ])
    .then(([compRes, deptRes, sysRes, alertRes]) => {
      setCompany(compRes.data);
      setDept(deptRes.data);
      setSystem(sysRes.data);
      setAlerts(alertRes.data.alerts || []);
    })
    .catch(err => setError(err.response?.data?.message || 'Failed to load system'))
    .finally(() => setLoading(false));
  }, [companyId, deptId, systemId]);

  if (loading) return <p style={{ color:'#4c1d95', fontSize:13 }}>Loading…</p>;
  if (error)   return <p style={{ color:'#fca5a5', fontSize:13 }}>{error}</p>;
  if (!system) return <p style={{ color:'#fca5a5', fontSize:13 }}>System not found.</p>;

  const Row = ({ label, value, mono = false }) => (
    <div style={{
      display:'flex', justifyContent:'space-between', alignItems:'center',
      padding:'8px 0', borderBottom:'1px solid #1e1b4b', fontSize:13,
    }}>
      <span style={{ color:'#4c1d95', minWidth:140 }}>{label}</span>
      <span style={{
        color:'#c4b5fd',
        fontFamily: mono ? 'monospace' : 'inherit',
        fontSize: mono ? 11 : 13,
        wordBreak:'break-all', textAlign:'right',
      }}>{value || '—'}</span>
    </div>
  );

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ fontSize:12, color:'#4c1d95', marginBottom:16 }}>
        <Link to="/companies" style={{ color:'#7c3aed', textDecoration:'none' }}>Companies</Link>
        {' › '}
        <Link to={`/companies/${companyId}`} style={{ color:'#7c3aed', textDecoration:'none' }}>
          {company?.name || 'Company'}
        </Link>
        {' › '}
        <Link to={`/companies/${companyId}/departments/${deptId}`} style={{ color:'#7c3aed', textDecoration:'none' }}>
          {dept?.name || 'Department'}
        </Link>
        {' › '}<span style={{ color:'#c4b5fd' }}>{system.name}</span>
      </div>

      {/* System info */}
      <div style={{
        background:'#1e1b4b', border:'1px solid #312e81', borderRadius:12,
        padding:'20px 24px', marginBottom:24,
      }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:16 }}>
          <h2 style={{ fontSize:18, color:'#e9d5ff' }}>🖥 {system.name}</h2>
          <span style={{
            fontSize:12, padding:'4px 14px', borderRadius:10,
            background: system.status === 'active' ? '#064e3b'
                      : system.status === 'pending' ? '#78350f'
                      : system.status === 'disconnected' ? '#7f1d1d'
                      : '#1f2937',
            color:      system.status === 'active' ? '#34d399'
                      : system.status === 'pending' ? '#fcd34d'
                      : system.status === 'disconnected' ? '#fb923c'
                      : '#6b7280',
          }}>{system.status === 'pending' ? '⏳ Pending Check' : system.status}</span>
        </div>

        <Row label="Hostname"       value={system.hostname}/>
        <Row label="IP Address"     value={system.ip} mono/>
        <Row label="MAC Address"    value={system.macAddress} mono/>
        <Row label="OS"             value={system.os}/>
        <Row label="OS Type"        value={system.osType}/>
        <Row label="Architecture"   value={system.arch}/>
        <Row label="Agent Version"  value={system.agentVersion}/>

        <Row label="EDR Enabled"       value={system.edrEnabled      ? '✓ Yes' : '✗ No'}/>
        <Row label="IDS Enabled"       value={system.idsEnabled      ? '✓ Yes' : '✗ No'}/>
        <Row label="IPS Enabled"       value={system.ipsEnabled      ? '✓ Yes' : '✗ No'}/>
        <Row label="Firewall Enabled"  value={system.firewallEnabled ? '✓ Yes' : '✗ No'}/>
        <Row label="YARA Enabled"      value={system.yaraEnabled     ? '✓ Yes' : '✗ No'}/>

        <Row label="Last Seen"      value={system.lastSeen ? new Date(system.lastSeen).toLocaleString() : null}/>
        <Row label="Installed"      value={system.installDate ? new Date(system.installDate).toLocaleString() : null}/>
        <Row label="Registered"     value={new Date(system.createdAt).toLocaleString()}/>
        <Row label="Department"     value={dept?.name}/>
        <Row label="Company"        value={company?.name}/>

        <div style={{ marginTop:16, background:'#0f172a', borderRadius:8,
                      padding:'12px 14px', border:'1px solid #312e81' }}>
          <div style={{ fontSize:10, color:'#4c1d95', marginBottom:6 }}>Agent key (for soc-integration config)</div>
          <code style={{ fontSize:11, color:'#7c3aed', wordBreak:'break-all' }}>{system.agentKey}</code>
        </div>
      </div>

      {/* Alerts */}
      <h3 style={{ fontSize:14, color:'#c4b5fd', marginBottom:14 }}>
        Alerts from this system
        <span style={{ fontSize:11, color:'#4c1d95', fontWeight:400, marginLeft:8 }}>({alerts.length})</span>
      </h3>

      {alerts.length === 0
        ? <p style={{ color:'#312e81', fontSize:13 }}>No alerts from this system yet.</p>
        : alerts.map((a, i) => (
          <div key={a._id || i} style={{
            background:'#1e1b4b', border:'1px solid #312e81', borderRadius:8,
            padding:'10px 14px', marginBottom:8,
            display:'flex', justifyContent:'space-between', alignItems:'center', gap:10,
          }}>
            <div style={{ flex:1, minWidth:0 }}>
              <div style={{ fontSize:13, color:'#e2e8f0', overflow:'hidden',
                            textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                {a.description || 'Security event'}
              </div>
              <div style={{ fontSize:11, color:'#4c1d95', marginTop:2 }}>
                Rule {a.ruleId || '—'} · Level {a.ruleLevel || '—'} · {new Date(a.createdAt).toLocaleString()}
              </div>
            </div>
            <div style={{ display:'flex', gap:6, flexShrink:0 }}>
              <span style={{
                fontSize:11, padding:'2px 8px', borderRadius:10,
                background: SEV_BG[a.severity]   || '#1e1b4b',
                color:      SEV_COLOR[a.severity] || '#c4b5fd',
              }}>{a.severity}</span>
              <span style={{
                fontSize:11, padding:'2px 8px', borderRadius:10,
                background: a.status === 'resolved' ? '#064e3b' : '#1e1b4b',
                color:      a.status === 'resolved' ? '#34d399' : '#c4b5fd',
              }}>{a.status}</span>
            </div>
          </div>
        ))
      }
    </div>
  );
}
