import { useEffect, useState } from 'react';
import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ROLE_LABELS, DASHBOARD_ROUTES, ROLE_MENUS } from '../config/menuConfig';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';

export default function SocDashboardLayout() {
  const { user, company, logout, lockSession } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [online, setOnline] = useState(navigator.onLine);
  const [searchQuery, setSearchQuery] = useState('');
  const [profileOpen, setProfileOpen] = useState(false);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [notifications, setNotifications] = useState([]);
  const [unreadNotifications, setUnreadNotifications] = useState(0);
  const accountId = user?._id || user?.id;
  const notificationBadgeCount = Math.max(0, Number(unreadNotifications) || 0);

  useEffect(() => {
    const on = () => setOnline(true), off = () => setOnline(false);
    window.addEventListener('online', on);
    window.addEventListener('offline', off);
    return () => {
      window.removeEventListener('online', on);
      window.removeEventListener('offline', off);
    };
  }, []);

  useEffect(() => {
    if (!accountId) return undefined;
    let active = true;
    const loadNotifications = () => api.get('/soc-dashboard/notifications', { params: { limit: 12 }, skipCache: true })
      .then(({ data }) => {
        if (!active) return;
        setNotifications(data?.items || []);
        setUnreadNotifications(data?.unread || 0);
      })
      .catch(() => {});
    loadNotifications();
    const timer = window.setInterval(loadNotifications, 30000);
    return () => {
      active = false;
      window.clearInterval(timer);
    };
  }, [accountId, location.pathname]);

  useEffect(() => {
    if (!accountId) return undefined;
    const socket = io(SOCKET_URL);
    const onNotification = notification => {
      const visibleNotification = notificationOpen ? { ...notification, read: true, readAt: new Date().toISOString() } : notification;
      setNotifications(items => [visibleNotification, ...items.filter(item => item._id !== notification._id)].slice(0, 12));
      if (notificationOpen) {
        api.patch('/soc-dashboard/notifications/read', { notificationId: notification._id }).catch(() => {});
      } else if (!notification.read) {
        setUnreadNotifications(count => count + 1);
      }
    };
    const onNotificationsRead = event => {
      setUnreadNotifications(Number(event?.unread || 0));
      if (!event?.unread) setNotifications(items => items.map(item => ({ ...item, read: true })));
    };
    const onUnreadChange = event => setUnreadNotifications(Number(event.detail?.unread || 0));
    socket.on('soc:notification', onNotification);
    socket.on('soc:notifications:read', onNotificationsRead);
    window.addEventListener('soc-notifications:unread', onUnreadChange);
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('soc:notification', onNotification);
      socket.off('soc:notifications:read', onNotificationsRead);
      window.removeEventListener('soc-notifications:unread', onUnreadChange);
      disconnect();
    };
  }, [accountId, notificationOpen]);

  const roleKey = user?.role || 'l1_analyst';
  const menu = ROLE_MENUS[roleKey] || ROLE_MENUS.l1_analyst;
  const roleTitle = ROLE_LABELS[roleKey] || 'Analyst';
  const ROLE_PREFIX = { soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4' };
  const wsBase = ROLE_PREFIX[roleKey] || '/soc-workspace';
  const settingsBase = ROLE_PREFIX[roleKey] ? `${ROLE_PREFIX[roleKey]}/settings` : '/settings';

  const pathParts = location.pathname.split('/').filter(Boolean);
  const currentCrumb = pathParts.pop() || 'dashboard';

  const handleSearch = (e) => {
    if (e.key === 'Enter' && searchQuery.trim()) {
      navigate(`${wsBase}/alerts?search=${encodeURIComponent(searchQuery.trim())}`);
    }
  };

  const openNotifications = () => {
    setNotificationOpen(false);
    setProfileOpen(false);
    navigate(`${settingsBase}?section=notifications`);
  };

  const openNotification = (notification) => {
    setNotificationOpen(false);
    if (notification.link) return navigate(notification.link);
    if (notification.ticketId) navigate(`${wsBase}/tickets/${notification.ticketId}`);
  };

  return (
    <div style={{ minHeight: '100vh', display: 'flex', background: 'linear-gradient(135deg,#070e1d,#101936)', color: '#e2e8f0', fontFamily: 'Inter,system-ui,sans-serif' }}>
      {mobileOpen && (
        <button
          aria-label="Close menu"
          onClick={() => setMobileOpen(false)}
          style={{ position: 'fixed', inset: 0, border: 0, background: 'rgba(0,0,0,.6)', zIndex: 20 }}
        />
      )}

      {/* Sidebar */}
      <aside
        style={{
          width: collapsed ? 76 : 260,
          position: 'fixed',
          inset: '0 auto 0 0',
          zIndex: 30,
          background: '#0a1628',
          borderRight: '1px solid #1e3a5f',
          display: 'flex',
          flexDirection: 'column',
          transform: mobileOpen ? 'translateX(0)' : undefined,
          transition: 'width .2s,transform .2s'
        }}
        className="soc-role-sidebar"
      >
        <div style={{ padding: '18px 16px', borderBottom: '1px solid #1e3a5f', display: 'flex', gap: 10, alignItems: 'center' }}>
          <b style={{ color: '#38bdf8', fontSize: 20 }}>◈</b>
          {!collapsed && <span style={{ fontWeight: 900, fontSize: 15, letterSpacing: '0.5px' }}>SCDC PLATFORM</span>}
          <button onClick={() => setCollapsed(v => !v)} style={{ marginLeft: 'auto', background: 'none', border: 0, color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}>
            ☰
          </button>
        </div>

        {!collapsed && (
          <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e3a5f', background: 'rgba(15, 23, 42, 0.4)' }}>
            <b style={{ display: 'block', color: '#f8fafc', fontSize: 13, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {company?.name || 'Assigned Scope'}
            </b>
            <small style={{ color: '#67e8f9', fontWeight: 600, fontSize: 11 }}>{roleTitle}</small>
            <div style={{ fontSize: 11, color: online ? '#34d399' : '#f87171', marginTop: 5, display: 'flex', alignItems: 'center', gap: 6 }}>
              <span>● {online ? 'Online' : 'Offline'}</span>
              <span style={{ color: '#64748b' }}>·</span>
              <span style={{ color: '#a78bfa' }}>Shift Active</span>
            </div>
          </div>
        )}

        <nav style={{ padding: 10, overflowY: 'auto', flex: 1 }}>
          {menu.map((item) => (
            <NavLink
              key={item.label}
              to={item.to}
              onClick={() => setMobileOpen(false)}
              style={({ isActive }) => ({
                display: 'flex',
                gap: 12,
                alignItems: 'center',
                padding: '10px 12px',
                margin: '3px 0',
                borderRadius: 8,
                textDecoration: 'none',
                color: isActive ? '#fff' : '#94a3b8',
                background: isActive ? 'linear-gradient(90deg,#2563eb,#6d28d9)' : 'transparent',
                fontSize: 13,
                fontWeight: isActive ? 800 : 600
              })}
            >
              <span style={{ width: 20, textAlign: 'center', fontSize: 15 }}>{item.icon}</span>
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          ))}
        </nav>

        <div style={{ padding: 12, borderTop: '1px solid #1e3a5f', background: '#07111f' }}>
          {!collapsed && (
            <small style={{ display: 'block', color: '#94a3b8', overflow: 'hidden', textOverflow: 'ellipsis', marginBottom: 8, fontSize: 11 }}>
              {user?.email}
            </small>
          )}
          <button
            onClick={async () => {
              await logout();
              window.location.href = '/login';
            }}
            style={{ width: '100%', padding: 8, border: '1px solid #334155', borderRadius: 7, background: '#111c2e', color: '#fca5a5', cursor: 'pointer', fontWeight: 600, fontSize: 12 }}
          >
            ↪ {!collapsed && 'Logout'}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div style={{ marginLeft: collapsed ? 76 : 260, minWidth: 0, flex: 1, transition: 'margin .2s' }} className="soc-role-main">
        {/* Top Navbar */}
        <header
          style={{
            height: 64,
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            gap: 14,
            borderBottom: '1px solid #1e3a5f',
            background: 'rgba(10,22,40,.95)',
            backdropFilter: 'blur(8px)',
            position: 'sticky',
            top: 0,
            zIndex: 10
          }}
        >
          <button onClick={() => setMobileOpen(true)} style={{ background: 'none', border: 0, color: '#fff', fontSize: 20, cursor: 'pointer', display: 'none' }} className="mobile-menu-btn">
            ☰
          </button>

          <div>
            <b style={{ fontSize: 16, color: '#f8fafc' }}>{roleTitle} Dashboard</b>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#64748b', marginTop: 2 }}>
              <NavLink to="/" style={{ color: '#38bdf8', textDecoration: 'none' }}>Home</NavLink>
              <span>/</span>
              <span>Dashboard</span>
              <span>/</span>
              <span style={{ color: '#cbd5e1', textTransform: 'capitalize' }}>{currentCrumb.replaceAll('-', ' ')}</span>
            </div>
          </div>

          <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 14 }}>
            <input
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={handleSearch}
              placeholder="Global search (press Enter)…"
              style={{ width: 'min(320px,35vw)', padding: '8px 12px', background: '#07111f', border: '1px solid #294765', borderRadius: 8, color: '#fff', fontSize: 12 }}
            />

            <div style={{ position: 'relative' }}>
              <button type="button" onClick={openNotifications} title="Notifications" aria-label={`Notifications (${notificationBadgeCount} unread)`} style={{ width: 36, height: 36, display: 'grid', placeItems: 'center', color: '#fbbf24', background: notificationOpen ? '#17243a' : 'transparent', border: '1px solid #294765', borderRadius: 9, fontSize: 19, cursor: 'pointer', position: 'relative' }}>
                ◇
                <span style={{ position: 'absolute', top: -7, right: -7, minWidth: 18, height: 18, padding: '0 4px', display: 'grid', placeItems: 'center', borderRadius: 10, background: notificationBadgeCount > 0 ? '#ef4444' : '#334155', color: notificationBadgeCount > 0 ? '#fff' : '#cbd5e1', border: '2px solid #0a1628', fontSize: 9, lineHeight: 1, fontWeight: 900, boxSizing: 'border-box' }}>{notificationBadgeCount > 99 ? '99+' : notificationBadgeCount}</span>
              </button>
              {notificationOpen && (
                <div style={{ position: 'absolute', top: 44, right: 0, width: 'min(380px,88vw)', maxHeight: 430, overflowY: 'auto', background: '#0c192c', border: '1px solid #294765', borderRadius: 12, boxShadow: '0 18px 45px rgba(0,0,0,.55)', zIndex: 60 }}>
                  <div style={{ position: 'sticky', top: 0, padding: '12px 14px', background: '#0c192c', borderBottom: '1px solid #1e3a5f', zIndex: 1 }}>
                    <b style={{ fontSize: 13, color: '#f8fafc' }}>Notifications</b>
                    <div style={{ color: '#64748b', fontSize: 10, marginTop: 2 }}>Tickets, administrative updates and SOC chat</div>
                  </div>
                  {notifications.length ? notifications.map(notification => (
                    <button key={notification._id} type="button" onClick={() => openNotification(notification)} style={{ width: '100%', padding: '12px 14px', display: 'block', textAlign: 'left', border: 0, borderBottom: '1px solid #172a43', background: notification.read ? '#0c192c' : 'rgba(37,99,235,.12)', color: '#cbd5e1', cursor: 'pointer' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ color: notification.type === 'ticket_assigned' ? '#34d399' : '#facc15', fontSize: 15 }}>{notification.type === 'chat_message' ? '💬' : notification.type === 'admin_change' ? '⚙' : notification.type === 'ticket_assigned' ? '🎟' : '◇'}</span>
                        <b style={{ minWidth: 0, color: '#e0f2fe', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{notification.title}</b>
                      </div>
                      <div style={{ marginTop: 5, color: '#94a3b8', fontSize: 11, lineHeight: 1.45 }}>{notification.message}</div>
                      <div style={{ marginTop: 6, color: '#64748b', fontSize: 9 }}>{new Date(notification.createdAt).toLocaleString()} · {notification.companyId?.name || 'Assigned company'}</div>
                    </button>
                  )) : <div style={{ padding: 24, color: '#71839b', textAlign: 'center', fontSize: 12 }}>No notifications yet.</div>}
                </div>
              )}
            </div>

            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setProfileOpen(v => !v)}
                style={{
                  width: 36,
                  height: 36,
                  borderRadius: '50%',
                  display: 'grid',
                  placeItems: 'center',
                  background: 'linear-gradient(135deg,#1d4ed8,#6d28d9)',
                  color: '#fff',
                  fontWeight: 900,
                  border: '1px solid rgba(255,255,255,0.2)',
                  cursor: 'pointer'
                }}
              >
                {String(user?.name || 'U')[0].toUpperCase()}
              </button>

              {profileOpen && (
                <div
                  style={{
                    position: 'absolute',
                    top: 44,
                    right: 0,
                    width: 220,
                    background: '#0c192c',
                    border: '1px solid #1e3a5f',
                    borderRadius: 8,
                    padding: 10,
                    boxShadow: '0 10px 25px rgba(0,0,0,0.5)',
                    zIndex: 50
                  }}
                >
                  <div style={{ padding: '6px 8px', borderBottom: '1px solid #1e3a5f', marginBottom: 6 }}>
                    <b style={{ display: 'block', fontSize: 13, color: '#f8fafc' }}>{user?.name || 'User'}</b>
                    <small style={{ color: '#64748b', fontSize: 11 }}>{user?.email}</small>
                    <div style={{ fontSize: 10, color: '#38bdf8', marginTop: 4, fontWeight: 700 }}>{roleTitle}</div>
                  </div>
                  <NavLink
                    to={settingsBase}
                    onClick={() => setProfileOpen(false)}
                    style={{ display: 'block', padding: '7px 8px', color: '#cbd5e1', textDecoration: 'none', fontSize: 12, borderRadius: 5 }}
                  >
                    ⚙ My Profile
                  </NavLink>
                  <button
                    type="button"
                    onClick={() => {
                      setProfileOpen(false);
                      lockSession();
                    }}
                    style={{
                      width: '100%', textAlign: 'left', padding: '7px 8px', color: '#e879f9',
                      background: 'none', border: 0, cursor: 'pointer', fontSize: 12, marginTop: 2,
                    }}
                  >
                    🔐 Lock screen
                  </button>
                  <button
                    onClick={async () => {
                      await logout();
                      window.location.href = '/login';
                    }}
                    style={{
                      width: '100%',
                      textAlign: 'left',
                      padding: '7px 8px',
                      color: '#f87171',
                      background: 'none',
                      border: 0,
                      cursor: 'pointer',
                      fontSize: 12,
                      marginTop: 4
                    }}
                  >
                    ↪ Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page Content */}
        <main style={{ padding: 'clamp(14px,3vw,30px)' }}>
          <Outlet />
        </main>
      </div>

      <style>{`
        @media(max-width:760px){
          .soc-role-sidebar{transform:translateX(-100%);width:260px!important}
          .soc-role-main{margin-left:0!important}
          .mobile-menu-btn{display:block!important}
        }
      `}</style>
    </div>
  );
}

const DASHBOARD = DASHBOARD_ROUTES;
export { ROLE_LABELS, DASHBOARD_ROUTES, DASHBOARD };
