import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  LayoutGrid,
  Building2,
  UserCheck,
  Users,
  CreditCard,
  Handshake,
  BarChart3,
  ShieldAlert,
  Lock,
  LogOut,
  ShieldCheck,
  Activity,
  Radio
} from 'lucide-react';

export default function Layout() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  const navItems = [
    { to: '/superadmin/dashboard', Icon: LayoutGrid, label: 'SOC Dashboard' },
    { to: '/superadmin/companies', Icon: Building2, label: 'Companies' },
    { to: '/superadmin/soc-managers', Icon: UserCheck, label: 'SOC Managers' },
    { to: '/superadmin/users?role=analyst', Icon: Users, label: 'Analysts' },
    { to: '/superadmin/payment-management', Icon: CreditCard, label: 'Payment Control' },
    { to: '/superadmin/partners', Icon: Handshake, label: 'Partners' },
    { to: '/superadmin/partner-dashboard', Icon: BarChart3, label: 'Partner Metrics' },
    { to: '/superadmin/partner-company', Icon: Building2, label: 'Partner Companies' },
    { to: '/superadmin/fraud-intelligence', Icon: ShieldAlert, label: 'Fraud Intel' },
    { to: '/superadmin/agent-security', Icon: Lock, label: 'AJNAT Security' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', minHeight: '100vh', background: '#070b14', color: '#f1f5f9' }}>
      {user?.role === 'superadmin' && (
        <header style={{
          position: 'sticky', top: 0, zIndex: 50, padding: '10px 24px',
          borderBottom: '1px solid #1e2a42', background: 'rgba(7, 11, 20, 0.92)',
          backdropFilter: 'blur(16px)', boxShadow: '0 8px 32px rgba(0,0,0,0.4)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16
        }}>
          {/* Brand Logo & Status */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexShrink: 0 }}>
            <div style={{
              width: 36, height: 36, borderRadius: 10,
              background: 'linear-gradient(135deg, #00f2fe 0%, #3b82f6 100%)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              boxShadow: '0 0 16px rgba(0, 242, 254, 0.35)',
              color: '#070b14', fontWeight: 900
            }}>
              <ShieldCheck size={22} strokeWidth={2.5} />
            </div>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: '0.6px', color: '#f8fafc', display: 'flex', alignItems: 'center', gap: 6 }}>
                AJNAT <span style={{ color: '#00f2fe', fontSize: 11, background: 'rgba(0, 242, 254, 0.12)', padding: '1px 6px', borderRadius: 4, border: '1px solid rgba(0, 242, 254, 0.3)' }}>SOC HQ</span>
              </div>
              <div style={{ fontSize: 10, color: '#64748b', letterSpacing: '0.4px', display: 'flex', alignItems: 'center', gap: 4 }}>
                <Activity size={10} color="#10b981" /> Command & Control Platform
              </div>
            </div>
          </div>

          {/* Navigation links */}
          <nav aria-label="Superadmin primary navigation" style={{ display: 'flex', gap: 5, alignItems: 'center', overflowX: 'auto', scrollbarWidth: 'none', padding: '2px 0' }}>
            {navItems.map(({ to, Icon, label }) => {
              const path = to.split('?')[0];
              const active = location.pathname === path || (path === '/superadmin/dashboard' && (location.pathname === '/superadmin' || location.pathname === '/superadmin/'));
              return (
                <NavLink key={to} to={to} style={{
                  display: 'inline-flex', alignItems: 'center', gap: 7, whiteSpace: 'nowrap',
                  padding: '8px 12px', borderRadius: 8, textDecoration: 'none', fontSize: 12, fontWeight: 600,
                  color: active ? '#00f2fe' : '#94a3b8',
                  background: active ? 'rgba(0, 242, 254, 0.1)' : 'transparent',
                  border: `1px solid ${active ? 'rgba(0, 242, 254, 0.3)' : 'transparent'}`,
                  transition: 'all 0.18s ease',
                  boxShadow: active ? '0 0 12px rgba(0, 242, 254, 0.15)' : 'none',
                }}>
                  <Icon size={15} color={active ? '#00f2fe' : '#64748b'} />
                  {label}
                </NavLink>
              );
            })}
          </nav>

          {/* User profile & logout */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 8, padding: '4px 10px',
              borderRadius: 8, background: '#0e1726', border: '1px solid #1b2a42'
            }}>
              <div style={{
                width: 8, height: 8, borderRadius: '50%', background: '#10b981',
                boxShadow: '0 0 8px #10b981'
              }} />
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 12, fontWeight: 700, color: '#f1f5f9', lineHeight: 1.2 }}>{user?.name || 'Superadmin'}</div>
                <div style={{ fontSize: 9, color: '#00f2fe', textTransform: 'uppercase', letterSpacing: '0.6px', fontWeight: 700 }}>SUPERADMIN</div>
              </div>
            </div>

            <button
              onClick={() => { logout(); navigate('/login'); }}
              title="Logout"
              style={{
                background: 'rgba(239, 68, 68, 0.08)', border: '1px solid rgba(239, 68, 68, 0.25)',
                color: '#f87171', padding: '7px 12px', borderRadius: 8, cursor: 'pointer',
                fontSize: 12, fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6,
                transition: 'all 0.2s ease',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.2)';
                e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.5)';
              }}
              onMouseLeave={e => {
                e.currentTarget.style.background = 'rgba(239, 68, 68, 0.08)';
                e.currentTarget.style.borderColor = 'rgba(239, 68, 68, 0.25)';
              }}
            >
              <LogOut size={14} />
              <span>Exit</span>
            </button>
          </div>
        </header>
      )}

      <main style={{ flex: 1, minWidth: 0, background: '#070b14', color: '#f1f5f9', overflowY: 'auto' }}>
        <div style={{ padding: '24px 28px', maxWidth: 1600, margin: '0 auto' }}>
          <Outlet />
        </div>
      </main>
    </div>
  );
}
