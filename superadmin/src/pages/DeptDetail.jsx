import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/axios';

const STATUS_COLOR = { active:'#34d399', pending:'#f59e0b', inactive:'#f87171', disconnected:'#6b7280' };
const STATUS_BG    = { active:'#064e3b', pending:'#78350f', inactive:'#7f1d1d', disconnected:'#1f2937' };

export default function DeptDetail() {
  const { companyId, deptId } = useParams();
  const [dept,    setDept]    = useState(null);
  const [company, setCompany] = useState(null);
  const [systems, setSystems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    setLoading(true);
    Promise.all([
      api.get(`/superadmin/companies/${companyId}`),
      api.get(`/superadmin/companies/${companyId}/departments/${deptId}`),
      api.get(`/superadmin/companies/${companyId}/departments/${deptId}/systems`),
    ])
    .then(([compRes, deptRes, sysRes]) => {
      setCompany(compRes.data);
      setDept(deptRes.data);
      setSystems(sysRes.data || []);
    })
    .catch(err => setError(err.response?.data?.message || 'Failed to load department'))
    .finally(() => setLoading(false));
  }, [companyId, deptId]);

  if (loading) return <p style={{ color:'#4c1d95', fontSize:13 }}>Loading…</p>;
  if (error)   return <p style={{ color:'#fca5a5', fontSize:13 }}>{error}</p>;

  return (
    <div>
      {/* Breadcrumb */}
      <div style={{ fontSize:12, color:'#4c1d95', marginBottom:16 }}>
        <Link to="/companies" style={{ color:'#7c3aed', textDecoration:'none' }}>Companies</Link>
        {' › '}
        <Link to={`/companies/${companyId}`} style={{ color:'#7c3aed', textDecoration:'none' }}>
          {company?.name || 'Company'}
        </Link>
        {' › '}<span style={{ color:'#c4b5fd' }}>{dept?.name}</span>
      </div>

      {/* Dept header */}
      <div style={{
        background:'#1e1b4b', border:'1px solid #312e81', borderRadius:12,
        padding:'18px 22px', marginBottom:22,
      }}>
        <h2 style={{ fontSize:18, color:'#e9d5ff', marginBottom:4 }}>📁 {dept?.name}</h2>
        {dept?.description && (
          <div style={{ fontSize:12, color:'#4c1d95', marginBottom:6 }}>{dept.description}</div>
        )}
        <div style={{ display:'flex', gap:16, fontSize:11, color:'#6d28d9' }}>
          <span>{systems.length} system{systems.length !== 1 ? 's' : ''}</span>
          {dept?.adminId && <span>Admin: {dept.adminId.name || dept.adminId.email}</span>}
          <span>Company: {company?.name}</span>
        </div>
      </div>

      {/* Systems */}
      <h3 style={{ fontSize:14, color:'#c4b5fd', marginBottom:14 }}>
        Systems
        <span style={{ fontSize:11, color:'#4c1d95', fontWeight:400, marginLeft:8 }}>
          ({systems.length})
        </span>
      </h3>

      {systems.length === 0
        ? (
          <div style={{
            background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
            padding:32, textAlign:'center',
          }}>
            <p style={{ color:'#312e81', fontSize:13 }}>No systems registered in this department.</p>
          </div>
        )
        : systems.map(s => (
          <div key={s._id} style={{
            background:'#1e1b4b', border:'1px solid #312e81', borderRadius:10,
            padding:'14px 16px', marginBottom:10,
          }}>
            <div style={{ display:'flex', justifyContent:'space-between', alignItems:'flex-start', gap:12 }}>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:14, fontWeight:500, color:'#e9d5ff', marginBottom:4 }}>
                  🖥 {s.name}
                  {s.hostname && <span style={{ fontSize:11, color:'#4c1d95', marginLeft:8 }}>({s.hostname})</span>}
                </div>
                <div style={{ display:'flex', gap:14, fontSize:11, color:'#6d28d9', flexWrap:'wrap' }}>
                  {s.ip           && <span>IP: {s.ip}</span>}
                  {s.os           && <span>OS: {s.os}</span>}
                  {s.agentVersion && <span>Agent v{s.agentVersion}</span>}
                  {s.lastSeen     && <span>Last seen: {new Date(s.lastSeen).toLocaleString()}</span>}
                  {s.yaraEnabled  && <span style={{ color:'#a78bfa' }}>YARA ✓</span>}
                </div>
                <div style={{ marginTop:6, fontSize:10, color:'#312e81' }}>
                  Agent key: <code style={{ color:'#4c1d95', fontSize:10 }}>{s.agentKey?.slice(0,24)}…</code>
                </div>
              </div>
              <div style={{ display:'flex', flexDirection:'column', gap:6, alignItems:'flex-end' }}>
                <span style={{
                  fontSize:11, padding:'3px 10px', borderRadius:10,
                  background: STATUS_BG[s.status]   || '#1e1b4b',
                  color:      STATUS_COLOR[s.status] || '#c4b5fd',
                }}>{s.status}</span>
                <Link to={`/companies/${companyId}/departments/${deptId}/systems/${s._id}`}>
                  <button style={{
                    fontSize:11, padding:'4px 12px', borderRadius:4, border:'none',
                    background:'#312e81', color:'#c4b5fd', cursor:'pointer',
                  }}>Details →</button>
                </Link>
              </div>
            </div>
          </div>
        ))
      }
    </div>
  );
}
