import { useEffect, useRef } from 'react';
import { Link, Outlet, useLocation } from 'react-router-dom';
import './PartnerLayout.css';

const iconPaths = {
  Dashboard: 'M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z',
  Companies: 'M4 21V3h12v18 M16 9h4v12 M2 21h20 M8 7h4 M8 11h4 M8 15h4 M9 21v-3h2v3',
  Users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  'SOC Manager': 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0 M16 11l2 2 4-4',
  Revenue: 'M3 3v18h18 M7 16v-5 M12 16V7 M17 16V4',
  'Payment Control': 'M3 4h18v16H3z M3 9h18 M7 15h4',
  'Fraud Intelligence': 'M12 3l9 4v5c0 5-9 9-9 9s-9-4-9-9V7z M12 8v5 M12 16h.01',
  Support: 'M3 14v-3a9 9 0 0 1 18 0v3 M3 11h3v7H3z M18 11h3v7h-3z M21 18a3 3 0 0 1-3 3h-4',
  shield: 'M12 3l9 4v5c0 5-9 9-9 9s-9-4-9-9V7z M8 12l3 3 5-6',
  bell: 'M18 8a6 6 0 0 0-12 0c0 7-3 7-3 9h18c0-2-3-2-3-9 M10 21h4',
  user: 'M20 21v-2a7 7 0 0 0-7-7h-2a7 7 0 0 0-7 7v2 M16 5a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  exit: 'M9 21H3V3h6 M10 12h11 M17 8l4 4-4 4',
};

function Icon({ name }) {
  return <svg className="partner-layout-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={iconPaths[name]} /></svg>;
}

function isItemActive(item, location) {
  if (item.matchActive) return item.matchActive(location);
  const [path, search = ''] = item.to.split('?');
  if (location.pathname !== path && !(item.end === false && location.pathname.startsWith(`${path}/`))) return false;
  const currentParams = new URLSearchParams(location.search);
  const targetParams = new URLSearchParams(search);
  return [...targetParams].every(([key, value]) => currentParams.get(key) === value);
}

function NavigationLink({ item, location }) {
  const active = isItemActive(item, location);
  return (
    <Link to={item.to} className={`partner-layout-link${active ? ' is-active' : ''}`} aria-current={active ? 'page' : undefined}>
      {iconPaths[item.label] ? <Icon name={item.label} /> : <span className="partner-layout-tool-icon" aria-hidden="true">{item.icon}</span>}
      <span>{item.label}</span>
    </Link>
  );
}

export default function PartnerLayout({ sections, user, notificationCount, logout }) {
  const location = useLocation();
  const navigation = useRef(null);
  const primaryItems = sections.flatMap(section => section.items);
  const profileSection = new URLSearchParams(location.search).get('section');
  const onProfile = location.pathname === '/partner-profile';

  useEffect(() => {
    const nav = navigation.current;
    if (!nav) return undefined;
    const revealActiveLink = () => {
      const activeLink = nav.querySelector('[aria-current="page"]');
      if (!activeLink) return;
      const bounds = activeLink.getBoundingClientRect();
      const navBounds = nav.getBoundingClientRect();
      if (bounds.right > navBounds.right) nav.scrollLeft += bounds.right - navBounds.right;
      else if (bounds.left < navBounds.left) nav.scrollLeft += bounds.left - navBounds.left;
    };
    revealActiveLink();
    const observer = new ResizeObserver(revealActiveLink);
    observer.observe(nav);
    return () => observer.disconnect();
  }, [location.pathname, location.search]);

  return (
    <div className="partner-layout">
      <header className="partner-layout-header">
        <Link to="/partner/dashboard" className="partner-layout-brand" aria-label="SCDC Platform partner home">
          <span className="partner-layout-brand-mark"><Icon name="shield" /></span>
          <span>
            <span className="partner-layout-brand-title">SCDC <span className="partner-layout-brand-badge">PARTNER</span></span>
            <span className="partner-layout-brand-subtitle">Command &amp; Control Platform</span>
          </span>
        </Link>

        <nav className="partner-layout-navigation" aria-label="Partner primary navigation">
          <div className="partner-layout-links" ref={navigation}>
            {primaryItems.map(item => <NavigationLink key={item.to} item={item} location={location} />)}
          </div>
        </nav>

        <div className="partner-layout-actions">
          <Link to="/partner-profile?section=notifications" className={`partner-layout-notifications${onProfile && profileSection === 'notifications' ? ' is-active' : ''}`} aria-label={`Notifications${notificationCount > 0 ? `, ${notificationCount} unread` : ''}`} title="Notifications">
            <Icon name="bell" />
            {notificationCount > 0 && <span className="partner-layout-notification-count" aria-hidden="true">{notificationCount > 9 ? '9+' : notificationCount}</span>}
          </Link>
          <Link to="/partner-profile?section=dashboard" className={`partner-layout-profile${onProfile && profileSection !== 'notifications' ? ' is-active' : ''}`} aria-label="Profile Dashboard" title={user?.name || 'Profile Dashboard'}>
            <span className="partner-layout-profile-avatar"><Icon name="user" /><span className="partner-layout-status-dot" /></span>
            <span className="partner-layout-identity"><strong>{user?.name || 'Account'}</strong><small>PARTNER ADMIN</small></span>
          </Link>
          <button type="button" className="partner-layout-logout" onClick={async () => { await logout(); window.location.href = '/'; }} aria-label="Logout" title="Logout"><Icon name="exit" /><span>Exit</span></button>
        </div>
      </header>

      <main className={`partner-layout-content${location.pathname === '/ids' ? ' partner-layout-content-flush' : ''}${location.pathname === '/partner/dashboard' ? ' partner-layout-content-summary' : ''}`}>
        <Outlet />
      </main>
    </div>
  );
}
