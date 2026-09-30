import { useEffect, useRef, useState } from 'react';
import { Outlet, NavLink, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';

// ── PartnerNavItem: custom active check using location + search params ────
function PartnerNavItem({ item, onClick }) {
  const loc = useLocation();
  const isActive = item.matchActive
    ? item.matchActive({ pathname: loc.pathname, search: loc.search })
    : loc.pathname === item.to || (item.end === false && loc.pathname.startsWith(item.to));

  return (
    <NavLink
      to={item.to}
      end
      onClick={onClick}
      style={() => ({
        display: 'flex', alignItems: 'center', gap: 12, minHeight: 38,
        padding: '0 12px', borderRadius: 7, textDecoration: 'none',
        color: isActive ? '#fff' : '#c6d4e5',
        background: isActive ? 'linear-gradient(90deg,#4259ff,#6847ea)' : 'transparent',
        fontSize: 13, fontWeight: isActive ? 800 : 650,
      })}
    >
      <span style={{ width: 18, textAlign: 'center', fontSize: 14 }}>{item.icon}</span>
      <span>{item.label}</span>
    </NavLink>
  );
}

export default function Layout() {
  const { user, company, logout, isAdmin, isDeptAdmin, isAnalyst, impersonation, isImpersonating } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [openSection, setOpenSection] = useState('System Setup');
  const [partnerOpenSections, setPartnerOpenSections] = useState(['Business']);
  const [notificationCount, setNotificationCount] = useState(0);
  const [alertCount, setAlertCount] = useState(0);
  const alertCountRequestRef = useRef(null);
  const settingsBase = user?.role === 'company_admin'
    ? '/company-admin/settings'
    : user?.role === 'department_admin'
      ? '/department-admin/settings'
      : '/settings';
  const routeParams = new URLSearchParams(location.search);
  const systemReturnTo = routeParams.get('returnTo');
  const systemReturnId = routeParams.get('systemId');

  useEffect(() => {
    if (!user || user.role === 'partner_admin') return undefined;
    let active = true;
    let refreshTimer = null;
    const fetchCount = () => {
      // Never allow overlapping count requests. Alert bursts can emit multiple
      // socket event names for the same change.
      if (alertCountRequestRef.current) return alertCountRequestRef.current.request;
      const controller = new AbortController();
      const request = api.get('/alerts?status=open&limit=1', { signal: controller.signal })
        .then(({ data }) => {
          if (active) setAlertCount(data.total || 0);
        })
        .catch(err => {
          if (err?.code !== 'ERR_CANCELED' && import.meta.env.DEV) {
            console.debug('[alert-count] refresh failed:', err?.message);
          }
        })
        .finally(() => {
          if (alertCountRequestRef.current?.controller === controller) {
            alertCountRequestRef.current = null;
          }
        });
      alertCountRequestRef.current = { request, controller };
      return request;
    };
    const scheduleFetch = () => {
      if (refreshTimer) window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(fetchCount, 1000);
    };
    fetchCount();

    let disconnectSocket = () => { };
    let socket = null;
    if (user?.companyId) {
      socket = io(SOCKET_URL);
      socket.emit('join:company', user.companyId);
      socket.on('alert:new', scheduleFetch);
      socket.on('alert:updated', scheduleFetch);
      socket.on('alert:update', scheduleFetch);
      disconnectSocket = connectSocket(socket);
    }
    const interval = window.setInterval(() => {
      if (document.visibilityState === 'visible') fetchCount();
    }, 60000);
    return () => {
      active = false;
      window.clearInterval(interval);
      if (refreshTimer) window.clearTimeout(refreshTimer);
      if (socket) {
        socket.off('alert:new', scheduleFetch);
        socket.off('alert:updated', scheduleFetch);
        socket.off('alert:update', scheduleFetch);
      }
      alertCountRequestRef.current?.controller?.abort();
      alertCountRequestRef.current = null;
      disconnectSocket();
    };
  }, [user?._id, user?.role, user?.companyId]);

  useEffect(() => {
    if (user?.role === 'partner_admin') {
      api.get('/partner/notifications').then(({ data }) => setNotificationCount(data.unread || 0)).catch(() => { });
      if (!user?.partnerId) return undefined;
      const socket = io(SOCKET_URL);
      socket.emit('join:partner', user.partnerId);
      socket.on('partner:notification', () => setNotificationCount(count => count + 1));
      socket.on('partner:update', () => api.get('/partner/notifications').then(({ data }) => setNotificationCount(data.unread || 0)).catch(() => { }));
      const onUnreadChange = event => setNotificationCount(Number(event.detail?.unread || 0));
      window.addEventListener('partner-notifications:unread', onUnreadChange);
      const disconnectSocket = connectSocket(socket);
      return () => {
        window.removeEventListener('partner-notifications:unread', onUnreadChange);
        disconnectSocket();
      };
    } else if (user?.companyId || user?.role === 'company_admin') {
      api.get('/company/notifications').then(({ data }) => setNotificationCount(data.unread || 0)).catch(() => { });
      const socket = io(SOCKET_URL);
      if (user?.companyId) socket.emit('join:company', user.companyId);
      if (user?._id) socket.emit('join:user', user._id);
      socket.on('company:notification', () => setNotificationCount(count => count + 1));
      socket.on('company:update', () => api.get('/company/notifications').then(({ data }) => setNotificationCount(data.unread || 0)).catch(() => { }));
      const onUnreadChange = event => setNotificationCount(Number(event.detail?.unread || 0));
      window.addEventListener('company-notifications:unread', onUnreadChange);
      const disconnectSocket = connectSocket(socket);
      return () => {
        window.removeEventListener('company-notifications:unread', onUnreadChange);
        disconnectSocket();
      };
    }
  }, [user?.role, user?.partnerId, user?.companyId, user?._id]);

  useEffect(() => {
    if (user?.role !== 'partner_admin') return;
    const params = new URLSearchParams(location.search);
    const view = params.get('view');
    const path = location.pathname;
    const businessPaths = [
      '/partner-companies', '/partner/companies',
      '/partner/dashboard',
      '/users', '/partner/users',
      '/partner-soc-managers', '/partner/soc-managers',
      '/fraud-intelligence', '/partner/fraud-intelligence',
      '/partner-company-support', '/partner/company-support', '/partner/support',
      '/partner/revenue', '/partner/payment-control'
    ];
    const monitoringPaths = ['/system-monitoring', '/alerts', '/edr', '/ids', '/ips', '/firewall', '/dns-sinkhole', '/security-score', '/investigate', '/log-monitor', '/soar', '/compliance', '/reports'];

    if ((path === '/' && (view === 'revenue' || view === 'payment-control')) || businessPaths.some(p => path.startsWith(p))) {
      setPartnerOpenSections(prev => prev.includes('Business') ? prev : [...prev, 'Business']);
    } else if (monitoringPaths.some(p => path.startsWith(p))) {
      setPartnerOpenSections(prev => prev.includes('Monitoring') ? prev : [...prev, 'Monitoring']);
    } else if (path === '/' && !view) {
      setPartnerOpenSections(prev => prev.includes('Business') ? prev : [...prev, 'Business']);
    }
  }, [user?.role, location.pathname, location.search]);

  if (user?.role === 'partner_admin') {
    const partnerEmail = encodeURIComponent(user?.email || '');
    const partnerNavSections = [
      {
        title: '',
        items: [
          {
            to: '/partner/dashboard', label: 'Dashboard', icon: '🏠', end: true,
            matchActive: (loc) => loc.pathname === '/partner/dashboard' || (loc.pathname === '/' && !new URLSearchParams(loc.search).get('view'))
          },
        ],
      },
      {
        title: 'Business',
        items: [
          {
            to: '/partner/companies', label: 'Companies', icon: '🏢',
            matchActive: (loc) => (loc.pathname === '/partner/companies' || loc.pathname === '/partner-companies') && !new URLSearchParams(loc.search).get('invite')
          },
          {
            to: '/partner/users', label: 'Users', icon: '👥',
            matchActive: (loc) => (loc.pathname === '/partner/users' || loc.pathname === '/users') && !new URLSearchParams(loc.search).get('invite')
          },
          {
            to: '/partner/soc-managers', label: 'SOC Manager', icon: '+',
            matchActive: (loc) => loc.pathname === '/partner/soc-managers' || loc.pathname === '/partner-soc-managers'
          },
          {
            to: '/partner/revenue', label: 'Revenue', icon: '💰',
            matchActive: (loc) => loc.pathname === '/partner/revenue' || (loc.pathname === '/' && new URLSearchParams(loc.search).get('view') === 'revenue')
          },
          {
            to: '/partner/payment-control', label: 'Payment Control', icon: '💳',
            matchActive: (loc) => loc.pathname === '/partner/payment-control' || (loc.pathname === '/' && new URLSearchParams(loc.search).get('view') === 'payment-control')
          },
          {
            to: '/partner/fraud-intelligence', label: 'Fraud Intelligence', icon: '🛡️',
            matchActive: (loc) => loc.pathname === '/partner/fraud-intelligence' || loc.pathname === '/fraud-intelligence'
          },
          {
            to: '/partner/company-support', label: 'Support', icon: '❓',
            matchActive: (loc) => loc.pathname === '/partner/company-support' || loc.pathname === '/partner/support' || loc.pathname === '/partner-company-support'
          },
        ],
      },
      {
        title: 'Monitoring',
        items: [
          { to: '/system-monitoring', label: 'System Monitoring', icon: '📊' },
          { to: '/alerts', label: 'Alerts', icon: '🔔' },
          { to: '/edr', label: 'EDR', icon: '🛡' },
          { to: '/ids', label: 'IDS', icon: '🔍' },
          { to: '/ips', label: 'IPS', icon: '🛡️' },
          { to: '/firewall', label: 'Firewall', icon: '🔥' },
          { to: '/dns-sinkhole', label: 'DNS Sinkhole', icon: '🛡️' },
          { to: '/security-score', label: 'Security Score', icon: '📊' },
          { to: '/investigate', label: 'Investigate', icon: '🔎' },
          { to: '/log-monitor', label: 'Log Monitor', icon: '🖥️' },
          { to: '/soar', label: 'SOAR Rule', icon: '⚡' },
          { to: '/compliance', label: 'Compliance', icon: '✅' },
          { to: '/reports', label: 'Reports', icon: '📄' },
          { to: '/reports?tab=analytics', label: 'Analytics', icon: '📈' },
        ],
      },
    ];

    return (
      <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', fontFamily: 'Inter, system-ui, sans-serif', background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', color: '#e2e8f0' }}>
        <aside style={{ width: 250, background: 'linear-gradient(180deg, rgba(12, 26, 46, 0.95) 0%, rgba(15, 21, 53, 0.95) 100%)', color: '#dce8f7', display: 'flex', flexDirection: 'column', padding: '14px 0', flexShrink: 0, borderRight: '1px solid rgba(30, 58, 95, 0.6)', minHeight: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '0 22px 22px', fontWeight: 900, letterSpacing: .2 }}>
            <span style={{ width: 28, height: 28, border: '1px solid #8fb2d9', borderRadius: 9, display: 'grid', placeItems: 'center' }}>◇</span>
            <span>SCDC PLATFORM</span>
          </div>
          <nav style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '0 14px', flex: 1, minHeight: 0, overflowY: 'auto' }}>
            {partnerNavSections.map((section, sectionIdx) => {
              const isGroup = Boolean(section.title);
              const isOpen = !isGroup || partnerOpenSections.includes(section.title);
              return (
                <div key={`${section.title || 'main'}-${sectionIdx}`} style={{ display: 'grid', gap: 4 }}>
                  {isGroup && (
                    <button
                      type="button"
                      onClick={() => {
                        setPartnerOpenSections(prev =>
                          prev.includes(section.title)
                            ? prev.filter(t => t !== section.title)
                            : [...prev, section.title]
                        );
                      }}
                      style={partnerNavTitleButton}
                    >
                      <span>{section.title}</span>
                      <span style={{ transform: isOpen ? 'rotate(90deg)' : 'rotate(0deg)', transition: 'transform .15s' }}>›</span>
                    </button>
                  )}
                  {isOpen && section.items.map((item, idx) => (
                    <PartnerNavItem
                      key={`${item.label}-${idx}`}
                      item={item}
                    />
                  ))}
                </div>
              );
            })}
            <button onClick={() => { logout(); window.location.href = '/'; }} style={{ display: 'flex', alignItems: 'center', gap: 12, minHeight: 42, padding: '0 12px', borderRadius: 7, border: 'none', background: 'transparent', color: '#c6d4e5', fontSize: 13, fontWeight: 650, cursor: 'pointer', textAlign: 'left' }}>
              <span style={{ width: 18, textAlign: 'center', fontSize: 15 }}>↪</span>
              <span>Logout</span>
            </button>
          </nav>
        </aside>

        <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          {isImpersonating && (
            <div style={impersonationBanner}>
              <span>{impersonation?.banner || 'You are logged in as Partner Admin via Super Admin'}</span>
              <button type="button" onClick={() => { logout(); window.location.href = 'http://localhost:3001/partners'; }} style={bannerButton}>
                Back to Super Admin
              </button>
            </div>
          )}
          <header style={{ height: 58, background: '#0c1a2e', borderBottom: '1px solid #1e3a5f', display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', padding: '0 28px' }}>
            <div />
            <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 16 }}>
              <NavLink to="/partner-profile?section=notifications" title="Notifications" style={{ position: 'relative', color: '#93c5fd', fontSize: 20, textDecoration: 'none', width: 28, height: 28, display: 'grid', placeItems: 'center' }}>
                ♢{notificationCount > 0 && <span style={{ position: 'absolute', top: -5, right: -5, background: '#ef4444', color: '#fff', borderRadius: 8, fontSize: 10, minWidth: 16, height: 16, display: 'grid', placeItems: 'center' }}>{notificationCount > 9 ? '9+' : notificationCount}</span>}
              </NavLink>
              <NavLink to="/partner-profile?section=dashboard" title="Profile Dashboard" style={{ display: 'flex', alignItems: 'center', gap: 12, textDecoration: 'none' }}>
                <div style={{ width: 36, height: 36, borderRadius: '50%', background: '#1e3a5f', display: 'grid', placeItems: 'center', color: '#93c5fd' }}>●</div>
                <div style={{ lineHeight: 1.2 }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: '#e0f2fe' }}>{user?.name || 'Account'}</div>
                </div>
                <span style={{ color: '#60a5fa' }}>⌄</span>
              </NavLink>
            </div>
          </header>

          <main style={{ flex: 1, minHeight: 0, overflowY: location.pathname === '/ids' ? 'hidden' : 'auto', background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', padding: location.pathname === '/ids' ? 0 : '20px 30px 30px' }}>
            <Outlet />
          </main>
        </div>
      </div>
    );
  }

  const navSections = [
    {
      title: '',
      items: [
        { to: '/dashboard/company-admin', label: '🏠 Dashboard', roles: ['company_admin'] },
        { to: '/department-admin/dashboard', label: '🏠 Dashboard', roles: ['department_admin'] },
        { to: '/partner-resources', label: '📦 Request Resources', roles: ['partner_admin'] },
      ],
    },
    {
      title: 'Business',
      items: [
        { to: '/fraud-intelligence', label: '🛡️ Fraud Intelligence', roles: ['superadmin', 'partner_admin'] },
      ],
    },
    {
      title: 'System Setup',
      collapsible: true,
      items: [
        { to: '/soc-manager', label: '💬 SOC Manager', roles: ['company_admin', 'department_admin'] },
        { to: '/profile-locks', label: '🔐 Lock / Unlock', roles: ['company_admin', 'department_admin'] },
        { to: '/edrsystemstupe', label: '🛡 EDR Setup', roles: ['company_admin', 'department_admin'] },
        { to: '/departments', label: '🏢 Departments', roles: ['company_admin'] },
        { to: '/systems', label: '🖥 Systems', roles: ['company_admin', 'department_admin'] },
        { to: '/download-agent', label: '⬇ Download Agent', roles: ['company_admin'] },
        { to: '/team', label: '👥 Team', roles: ['company_admin'] },
        { to: '/payments', label: '💳 Payments', roles: ['company_admin'] },
      ],
    },
    {
      title: 'Monitoring',
      collapsible: true,
      items: [
        { to: '/system-monitoring', label: '📊 System Monitoring', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/alerts', label: '🔔 Alerts', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/siem', label: '📡 SIEM', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/soar', label: '⚡ SOAR', roles: ['company_admin', 'department_admin'] },
        { to: '/correlation', label: '🔗 Correlation', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/edr', label: '🛡 EDR', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/ids', label: '🔍 IDS', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/ips', label: '🛡️ IPS', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/firewall', label: '🔥 Firewall', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/threat-intelligence', label: '⌾ Threat Intelligence', roles: ['company_admin', 'department_admin'] },
        { to: '/incidents', label: '⚠️ Incidents', roles: ['company_admin', 'department_admin'] },
        { to: '/investigate', label: '🔍 Investigate', roles: ['analyst'] },
        { to: '/forensics', label: '🔬 Forensics', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/log-monitor', label: '📈 Log Monitor', roles: ['analyst'] },
        { to: '/compliance', label: '✅ Compliance', roles: ['analyst'] },
        { to: '/security-score', label: '📊 Security Score', roles: ['company_admin', 'department_admin', 'analyst'] },
        { to: '/reports', label: '📄 Reports', roles: ['company_admin', 'department_admin', 'analyst'] },
      ],
    },
  ].map(section => ({
    ...section,
    items: section.items
      .filter(n => n.roles.includes(user?.role))
      .map(n => {
        if (user?.role === 'company_admin' && n.to !== '/' && !n.to.startsWith('/company-admin') && !n.to.startsWith('/dashboard/company-admin')) {
          return { ...n, to: `/company-admin${n.to}` };
        }
        if (user?.role === 'department_admin' && !n.to.startsWith('/department-admin')) {
          return { ...n, to: `/department-admin${n.to}` };
        }
        return n;
      }),
  })).filter(section => section.items.length > 0);

  // \u2705 FIX: Check BOTH isActive flag AND expiry date (same logic as PaymentsPage)
  // Previously only checked isActive — plan could be "active" but expired
  const _now = new Date();
  const _exp = new Date(company?.plan?.expiresAt || 0);
  const planActive = company?.plan?.isActive && _now < _exp;
  const hasSystemLicense = Number(company?.plan?.systemCount || company?.plan?.systemLimit || 0) > 0;
  const addSystemBatchActive = company?.entitlement?.batchActive === true;
  const licenseActive = planActive || addSystemBatchActive || hasSystemLicense;
  const planLabel = planActive ? 'Active' : addSystemBatchActive ? 'Add-System Active' : hasSystemLicense ? 'License Active' : 'Unpaid';

  return (
    <div style={{ display: 'flex', minHeight: '100vh', fontFamily: 'system-ui,sans-serif', background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)' }}>
      <aside style={{
        width: 250,
        background: 'linear-gradient(180deg, rgba(12, 26, 46, 0.95) 0%, rgba(15, 21, 53, 0.95) 100%)',
        display: 'flex',
        flexDirection: 'column',
        padding: '24px 0',
        borderRight: '1px solid rgba(30, 58, 95, 0.6)',
        backdropFilter: 'blur(10px)',
        boxShadow: 'inset -1px 0 0 rgba(255, 255, 255, 0.05)',
        overflowY: 'auto',
      }}>
        {/* Header */}
        <div style={{ padding: '0 20px 24px', borderBottom: '1px solid rgba(30, 58, 95, 0.4)' }}>
          <div style={{
            fontSize: 15,
            fontWeight: 700,
            color: '#e0f2fe',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            letterSpacing: '-0.5px',
          }}>
            {company?.name || 'SOC Dashboard'}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
            <span style={{
              width: 8,
              height: 8,
              borderRadius: '50%',
              display: 'inline-block',
              background: licenseActive ? '#10b981' : '#f59e0b',
              boxShadow: `0 0 10px ${licenseActive ? 'rgba(16, 185, 129, 0.5)' : 'rgba(245, 158, 11, 0.5)'}`,
              animation: licenseActive ? 'pulse 2s infinite' : 'none',
            }} />
            <span style={{ fontSize: 11, color: licenseActive ? '#10b981' : '#f59e0b', fontWeight: 600 }}>
              {company?.plan?.type || 'trial'} · {planLabel}
            </span>
          </div>
          {isDeptAdmin && (
            <div style={{ marginTop: 8, color: '#7dd3fc', fontSize: 10, fontWeight: 800, letterSpacing: '.04em', textTransform: 'uppercase' }}>
              Department-scoped access
            </div>
          )}
        </div>

        {/* Navigation */}
        <nav style={{ flex: '0 0 auto', padding: '12px 8px', minHeight: 0 }}>
          {navSections.map(section => (
            <div key={section.title || 'main'} style={{ marginBottom: section.title ? 12 : 6 }}>
              {section.title && (
                <button
                  type="button"
                  onClick={() => section.collapsible && setOpenSection(prev => (prev === section.title ? null : section.title))}
                  style={{
                    width: '100%',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontSize: 10,
                    color: '#3b82f6',
                    fontWeight: 800,
                    letterSpacing: '0.7px',
                    textTransform: 'uppercase',
                    padding: '10px 16px 5px',
                    border: 'none',
                    background: 'transparent',
                    cursor: section.collapsible ? 'pointer' : 'default',
                    textAlign: 'left',
                  }}
                >
                  <span>{section.title}</span>
                  {section.collapsible && (
                    <span style={{ color: '#60a5fa', fontSize: 11 }}>
                      {openSection === section.title ? '⌃' : '⌄'}
                    </span>
                  )}
                </button>
              )}
              {(!section.collapsible || openSection === section.title) && section.items.map(({ to, label }) => (
                <NavLink key={to} to={to} end={to === '/'}
                  style={({ isActive }) => {
                    const dnsSelected = location.pathname.endsWith('/edr') && new URLSearchParams(location.search).get('capabilityId') === '31';
                    const active = to.includes('capabilityId=31') ? dnsSelected : (isActive && !(label.includes(' EDR') && dnsSelected));
                    return ({
                    display: 'flex',
                    alignItems: 'center',
                    padding: section.title ? '8px 16px' : '10px 16px',
                    textDecoration: 'none',
                    fontSize: 13,
                    color: active ? '#e0f2fe' : '#60a5fa',
                    background: active ? 'rgba(37, 99, 235, 0.2)' : 'transparent',
                    borderLeft: active ? '3px solid #3b82f6' : '3px solid transparent',
                    borderRadius: '0 8px 8px 0',
                    margin: '2px 0',
                    transition: 'all 0.2s ease',
                    position: 'relative',
                    fontWeight: active ? 600 : 500,
                  }); }}
                  onMouseEnter={(e) => {
                    if (e.currentTarget.style.background === 'transparent') {
                      e.currentTarget.style.background = 'rgba(59, 130, 246, 0.1)';
                    }
                  }}
                  onMouseLeave={(e) => {
                    if (!e.currentTarget.className.includes('active')) {
                      e.currentTarget.style.background = 'transparent';
                    }
                  }}
                >
                  <span style={{ marginRight: 10 }}>{label.split(' ')[0]}</span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                    {label.split(' ').slice(1).join(' ')}
                  </span>
                  {label.includes('Payments') && !planActive && (
                    <span style={{ marginLeft: 6, fontSize: 10, color: '#f59e0b', fontWeight: 700 }}>!</span>
                  )}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>

        {/* User Profile */}
        <div style={{ padding: '12px 20px', borderTop: '1px solid rgba(30, 58, 95, 0.4)', background: 'rgba(15, 23, 42, 0.6)', flexShrink: 0 }}>
          <button onClick={() => { logout(); window.location.href = '/'; }} style={{
            width: '100%',
            background: 'linear-gradient(135deg, rgba(59, 130, 246, 0.15) 0%, rgba(37, 99, 235, 0.1) 100%)',
            border: '1px solid rgba(59, 130, 246, 0.4)',
            color: '#60a5fa',
            padding: '7px 12px',
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
            }}
          >
            🚪 Logout
          </button>
        </div>
      </aside>

      <div style={{ flex: 1, minWidth: 0, minHeight: 0, display: 'flex', flexDirection: 'column' }}>
        {isImpersonating && (
          <div style={{ ...impersonationBanner, marginBottom: 18, borderRadius: 8 }}>
            <span>{impersonation?.banner || 'You are logged in as Partner Admin via Super Admin'}</span>
            <button type="button" onClick={() => { logout(); window.location.href = 'http://localhost:3001/partners'; }} style={bannerButton}>
              Back to Super Admin
            </button>
          </div>
        )}
        <header style={{ height: 58, background: '#0c1a2e', borderBottom: '1px solid #1e3a5f', display: 'grid', gridTemplateColumns: '1fr auto', alignItems: 'center', padding: '0 28px', flexShrink: 0 }}>
          <div />
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 16 }}>
            <NavLink
              to={`${settingsBase}?section=notifications`}
              title="Notifications"
              style={{ position: 'relative', color: '#93c5fd', fontSize: 20, textDecoration: 'none', width: 28, height: 28, display: 'grid', placeItems: 'center' }}
            >
              ♢{notificationCount > 0 && <span style={{ position: 'absolute', top: -5, right: -5, background: '#ef4444', color: '#fff', borderRadius: 8, fontSize: 10, minWidth: 16, height: 16, display: 'grid', placeItems: 'center' }}>{notificationCount > 9 ? '9+' : notificationCount}</span>}
            </NavLink>
            <NavLink to={settingsBase} title="Settings & Profile" style={{ display: 'flex', alignItems: 'center', gap: 12, textDecoration: 'none' }}>
              <div style={{ width: 36, height: 36, borderRadius: '50%', background: '#1e3a5f', display: 'grid', placeItems: 'center', color: '#93c5fd' }}>●</div>
              <div style={{ lineHeight: 1.2 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#e0f2fe' }}>{user?.name || 'Account'}</div>
              </div>
              <span style={{ color: '#60a5fa' }}>⌄</span>
            </NavLink>
          </div>
        </header>

        <main style={{
          flex: 1,
          minWidth: 0,
          minHeight: 0,
          height: location.pathname === '/ids' ? '100vh' : 'auto',
          background: 'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)',
          color: '#e2e8f0',
          padding: location.pathname === '/ids' ? 0 : 32,
          overflowY: location.pathname === '/ids' ? 'hidden' : 'auto',
          position: 'relative',
          boxSizing: 'border-box',
        }}>
          {systemReturnTo && systemReturnId && (
            <div style={{ position: 'sticky', top: -32, zIndex: 20, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, margin: '-20px -12px 18px', padding: '9px 14px', background: 'linear-gradient(90deg, rgba(8,35,58,.98), rgba(14,36,63,.96))', border: '1px solid rgba(56,189,248,.35)', borderRadius: 9, boxShadow: '0 8px 20px rgba(0,0,0,.2)' }}>
              <span style={{ color: '#bae6fd', fontSize: 11, fontWeight: 800 }}>System-scoped module · {systemReturnId}</span>
              <button type="button" onClick={() => navigate(systemReturnTo)} style={{ border: '1px solid #38bdf866', borderRadius: 6, background: '#38bdf814', color: '#7dd3fc', padding: '6px 10px', fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>← Back to System Monitoring</button>
            </div>
          )}
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
          <div style={{ position: 'relative', zIndex: 1, height: location.pathname === '/ids' ? '100%' : 'auto' }}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

const impersonationBanner = {
  minHeight: 42,
  background: '#7f1d1d',
  borderBottom: '1px solid #fca5a5',
  color: '#fff',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  gap: 12,
  padding: '8px 18px',
  fontSize: 13,
  fontWeight: 900,
  boxSizing: 'border-box',
};

const bannerButton = {
  border: '1px solid rgba(255,255,255,.55)',
  borderRadius: 6,
  background: 'rgba(255,255,255,.12)',
  color: '#fff',
  padding: '7px 10px',
  fontSize: 12,
  fontWeight: 900,
  cursor: 'pointer',
};

const partnerNavTitle = {
  padding: '9px 12px 4px',
  color: '#60a5fa',
  fontSize: 10,
  fontWeight: 900,
  letterSpacing: '.8px',
  textTransform: 'uppercase',
};

const partnerNavTitleButton = {
  ...partnerNavTitle,
  minHeight: 30,
  width: '100%',
  border: 'none',
  background: 'transparent',
  display: 'flex',
  alignItems: 'center',
  justifyContent: 'space-between',
  cursor: 'pointer',
  textAlign: 'left',
  boxSizing: 'border-box',
};
