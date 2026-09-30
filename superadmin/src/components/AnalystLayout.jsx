import { useEffect, useState } from 'react';
import { Outlet, NavLink, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';

const nav = [
  { to: '/',            label: '🏠 Dashboard'        },
  { to: '/system-monitoring', label: '📊 System Monitoring' },
  { to: '/alerts',      label: '🔔 Alerts'           },
  { to: '/siem',        label: '📡 SIEM'             },
  { to: '/edr',         label: '🛡 EDR'              },
  { to: '/ids',         label: '🔍 IDS/IPS'          },
  { to: '/firewall',    label: '🔥 Firewall'          },
  { to: '/dns-sinkhole', label: '🛡️ DNS Sinkhole'     },
  { to: '/security-score', label: '📊 Security Score' },
  { to: '/investigate', label: '🔎 Investigate'       },
  { to: '/log-monitor', label: '📈 Log Monitor'       },
  { to: '/compliance',  label: '✅ Compliance'        },
  { to: '/reports',     label: '📄 Reports'           },
  { to: '/settings',    label: '⚙ Settings'           },
];

export default function AnalystLayout() {
  const { user, company, logout, selectedDeptId, setSelectedDeptId } = useAuth();
  const location = useLocation();
  const [depts,      setDepts]      = useState([]);
  const [loadingDepts, setLoadingDepts] = useState(true);

  // Load departments this analyst is assigned to
  useEffect(() => {
    api.get('/department?analyst=1')
      .then(r => {
        const list = r.data?.departments || r.data || [];
        setDepts(list);
        // Auto-select first dept if none selected
        if (list.length > 0 && !selectedDeptId) {
          setSelectedDeptId(list[0]._id);
        }
      })
      .catch(() => setDepts([]))
      .finally(() => setLoadingDepts(false));
  }, []);

  const selectedDept = depts.find(d => d._id === selectedDeptId);

  return (
    <div style={{ display:'flex', minHeight:'100vh', fontFamily:'system-ui,sans-serif', background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)' }}>
      {/* Sidebar */}
      <aside style={{
        width: 250,
        background: 'linear-gradient(180deg, rgba(12, 26, 46, 0.95) 0%, rgba(15, 21, 53, 0.95) 100%)',
        display:'flex',
        flexDirection:'column',
        padding:'24px 0',
        borderRight:'1px solid rgba(30, 58, 95, 0.6)',
        backdropFilter: 'blur(10px)',
        boxShadow: 'inset -1px 0 0 rgba(255, 255, 255, 0.05)',
        overflowY: 'auto',
      }}>
        {/* Company name */}
        <div style={{ padding:'0 20px 16px', borderBottom: '1px solid rgba(30, 58, 95, 0.4)' }}>
          <div style={{ fontSize:15, fontWeight:700, color:'#e0f2fe',
                        overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', letterSpacing: '-0.5px' }}>
            {company?.name || 'SOC'}
          </div>
          <div style={{
            fontSize:11, marginTop:8, padding:'4px 9px', borderRadius:6,
            display:'inline-block', background:'rgba(37, 99, 235, 0.15)', color:'#93c5fd', border: '1px solid rgba(37, 99, 235, 0.3)', fontWeight: 600,
          }}>👤 Analyst</div>
        </div>

        {/* Department selector */}
        {!loadingDepts && depts.length > 0 && (
          <div style={{ padding:'12px 20px', borderBottom:'1px solid rgba(30, 58, 95, 0.4)', marginBottom:8 }}>
            <div style={{ fontSize:10, color:'#60a5fa', marginBottom:8, fontWeight: 700, letterSpacing: '0.5px' }}>
              DEPARTMENTS ({depts.length})
            </div>
            {depts.map(d => (
              <button key={d._id} onClick={() => setSelectedDeptId(d._id)} style={{
                display:'block', width:'100%', textAlign:'left',
                padding:'8px 12px', borderRadius:6, marginBottom:4,
                border:`1px solid ${selectedDeptId === d._id ? 'rgba(37, 99, 235, 0.6)' : 'rgba(30, 58, 95, 0.4)'}`,
                background: selectedDeptId === d._id ? 'rgba(37, 99, 235, 0.15)' : 'transparent',
                color: selectedDeptId === d._id ? '#e0f2fe' : '#60a5fa',
                cursor:'pointer', fontSize:12, fontWeight: selectedDeptId === d._id ? 600 : 500, transition: 'all 0.2s ease',
              }}
              onMouseEnter={(e) => {
                if (selectedDeptId !== d._id) {
                  e.target.style.background = 'rgba(37, 99, 235, 0.1)';
                  e.target.style.borderColor = 'rgba(37, 99, 235, 0.4)';
                }
              }}
              onMouseLeave={(e) => {
                if (selectedDeptId !== d._id) {
                  e.target.style.background = 'transparent';
                  e.target.style.borderColor = 'rgba(30, 58, 95, 0.4)';
                }
              }}>
                {selectedDeptId === d._id ? '✓ ' : ''}{d.name}
              </button>
            ))}
            {selectedDept && (
              <div style={{ fontSize:11, color:'#60a5fa', marginTop:6, padding: '6px 10px', background: 'rgba(52, 211, 153, 0.1)', borderRadius: 6, border: '1px solid rgba(52, 211, 153, 0.3)' }}>
                📍 Viewing: <span style={{ color:'#34d399', fontWeight: 600 }}>{selectedDept.name}</span>
              </div>
            )}
          </div>
        )}

        {/* Nav links */}
        <nav style={{ flex:1, padding: '12px 8px', overflow: 'hidden' }}>
          {nav.map(({ to, label }) => (
            <NavLink key={to} to={to} end={to==='/'}
              style={({ isActive }) => ({
                display:'flex', alignItems:'center', padding:'10px 16px', textDecoration:'none', fontSize:13,
                color: isActive ? '#e0f2fe' : '#60a5fa',
                background: isActive ? 'rgba(37, 99, 235, 0.2)' : 'transparent',
                borderLeft: isActive ? '3px solid #3b82f6' : '3px solid transparent',
                borderRadius: '0 8px 8px 0',
                margin: '2px 0',
                transition: 'all 0.2s ease',
                fontWeight: isActive ? 600 : 500,
              })}
              onMouseEnter={(e) => {
                if (!e.currentTarget.className.includes('active')) {
                  e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)';
                }
              }}
              onMouseLeave={(e) => {
                if (!e.currentTarget.className.includes('active')) {
                  e.currentTarget.style.background = 'transparent';
                }
              }}>
              <span style={{ marginRight: 10 }}>{label.split(' ')[0]}</span>
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                {label.split(' ').slice(1).join(' ')}
              </span>
            </NavLink>
          ))}
        </nav>

        {/* User info */}
        <div style={{ padding:'16px 20px', borderTop:'1px solid rgba(30, 58, 95, 0.4)', background: 'rgba(15, 23, 42, 0.6)' }}>
          <div style={{ fontSize:13, color:'#93c5fd', marginBottom:4,
                        overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap', fontWeight: 600 }}>
            {user?.name}
          </div>
          <div style={{ fontSize:11, color:'#60a5fa', marginBottom:12, opacity: 0.85 }}>
            {user?.email}
          </div>
          <button onClick={() => { logout(); window.location.href = '/'; }} style={{
            width: '100%',
            background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(37, 99, 235, 0.1) 100%)',
            border: '1px solid rgba(59, 130, 246, 0.4)',
            color: '#60a5fa',
            padding: '8px 12px',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 12,
            fontWeight: 600,
            transition: 'all 0.2s ease',
          }}
          onMouseEnter={(e) => {
            e.target.style.background = 'linear-gradient(135deg, rgba(59, 130, 246, 0.25) 0%, rgba(37, 99, 235, 0.2) 100%)';
            e.target.style.borderColor = 'rgba(59, 130, 246, 0.6)';
            e.target.style.boxShadow = '0 0 12px rgba(59, 130, 246, 0.2)';
          }}
          onMouseLeave={(e) => {
            e.target.style.background = 'linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(37, 99, 235, 0.1) 100%)';
            e.target.style.borderColor = 'rgba(59, 130, 246, 0.4)';
            e.target.style.boxShadow = 'none';
          }}>
            🚪 Logout
          </button>
        </div>
      </aside>

      {/* Main content — pass selectedDeptId via context */}
      <main style={{ 
        flex:1,
        minWidth:0,
        minHeight:0,
        height:location.pathname === '/ids' ? '100vh' : 'auto',
        background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', 
        color:'#e2e8f0', 
        padding:location.pathname === '/ids' ? 0 : 32,
        overflowY:location.pathname === '/ids' ? 'hidden' : 'auto',
        position: 'relative',
        boxSizing:'border-box',
      }}>
        {/* Background decorative elements */}
        <div style={{
          position: 'fixed',
          top: 0,
          right: 0,
          width: '500px',
          height: '500px',
          background: 'radial-gradient(circle, rgba(59, 130, 246, 0.05) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }} />
        <div style={{
          position: 'fixed',
          bottom: 0,
          left: '50%',
          width: '800px',
          height: '400px',
          background: 'radial-gradient(circle, rgba(139, 92, 246, 0.03) 0%, transparent 70%)',
          pointerEvents: 'none',
          zIndex: 0,
        }} />
        
        {selectedDept && location.pathname !== '/ids' && (
          <div style={{
            display:'inline-flex', alignItems:'center', gap:8, marginBottom:24,
            padding:'8px 16px', borderRadius:8,
            background:'linear-gradient(135deg, rgba(37, 99, 235, 0.15) 0%, rgba(29, 78, 216, 0.1) 100%)', 
            border:'1px solid rgba(37, 99, 235, 0.4)',
            fontSize:12, color:'#93c5fd', fontWeight: 600, position: 'relative', zIndex: 1,
          }}>
            📍 {selectedDept.name}
          </div>
        )}
        <div style={{ position: 'relative', zIndex: 1, height:location.pathname === '/ids' ? '100%' : 'auto' }}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
