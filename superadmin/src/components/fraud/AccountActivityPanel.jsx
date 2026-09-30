import { useEffect, useMemo, useState } from 'react';
import api from '../../api/axios';
import PaginationControls from '../common/PaginationControls';

const PAGE_SIZE = 10;
const EMPTY_LIST = [];

const COLORS = {
  panel: '#060e1a', surface: '#0c1a2e', border: '#1e3a5f', muted: '#64748b', text: '#e2e8f0', blue: '#60a5fa', green: '#10b981', red: '#ef4444', amber: '#f59e0b', purple: '#a78bfa',
};

const formatDateTime = value => value
  ? new Date(value).toLocaleString([], { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' })
  : 'Not recorded';

const formatDuration = value => {
  const minutes = Math.max(0, Number(value) || 0);
  if (minutes < 60) return `${minutes} min`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h ${minutes % 60}m`;
};

const locationText = location => {
  const text = [location?.city, location?.region, location?.country].filter(Boolean).join(', ');
  return text || 'Not captured';
};

const coordinatesText = location => location?.lat != null && location?.lon != null
  ? `${location.source === 'browser_geolocation' ? 'Browser GPS' : 'IP coordinates'}: ${location.lat}, ${location.lon}${location.accuracyMeters != null ? ` (±${location.accuracyMeters} m)` : ''}`
  : '';

const roleLabel = value => String(value || 'user').replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());
const actionLabel = value => String(value || '').replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase());

function Pill({ children, color = COLORS.blue }) {
  return <span style={{ color, background: `${color}18`, border: `1px solid ${color}44`, padding: '3px 8px', borderRadius: 999, fontSize: 10, fontWeight: 800, whiteSpace: 'nowrap' }}>{children}</span>;
}

function EmptyState({ children }) {
  return <div style={{ padding: 30, textAlign: 'center', color: '#475569', fontSize: 13 }}>{children}</div>;
}

function InfoItem({ label, value, mono = false }) {
  return (
    <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 9, padding: '10px 12px', minWidth: 0 }}>
      <div style={{ color: '#475569', fontSize: 10, textTransform: 'uppercase', letterSpacing: '.06em', marginBottom: 5 }}>{label}</div>
      <div style={{ color: COLORS.text, fontSize: 12, fontWeight: 650, overflowWrap: 'anywhere', fontFamily: mono ? 'ui-monospace,monospace' : 'inherit' }}>{value || 'Not recorded'}</div>
    </div>
  );
}

function Metric({ label, value, color = COLORS.blue }) {
  return (
    <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 10, padding: 13 }}>
      <div style={{ fontSize: 20, fontWeight: 850, color }}>{value}</div>
      <div style={{ color: COLORS.muted, fontSize: 10, marginTop: 3 }}>{label}</div>
    </div>
  );
}

function TableShell({ headers, children, empty, colSpan }) {
  return (
    <div style={{ overflowX: 'auto', border: `1px solid ${COLORS.border}`, borderRadius: 10 }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
        <thead><tr style={{ background: COLORS.surface }}>{headers.map(header => <th key={header} style={{ padding: '10px 12px', color: COLORS.blue, textAlign: 'left', whiteSpace: 'nowrap' }}>{header}</th>)}</tr></thead>
        <tbody>{children || <tr><td colSpan={colSpan} style={{ padding: 24, color: '#475569', textAlign: 'center' }}>{empty}</td></tr>}</tbody>
      </table>
    </div>
  );
}

function TableFilters({ search, onSearchChange, placeholder, filters = [] }) {
  const controlStyle = {
    minHeight: 34, boxSizing: 'border-box', padding: '7px 10px', background: COLORS.surface,
    color: COLORS.text, border: `1px solid ${COLORS.border}`, borderRadius: 7, outline: 'none', fontSize: 11,
  };
  return (
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 10 }}>
      <input
        value={search}
        onChange={event => onSearchChange(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        style={{ ...controlStyle, flex: '1 1 250px', minWidth: 180 }}
      />
      {filters.map(filter => (
        <select key={filter.label} value={filter.value} onChange={event => filter.onChange(event.target.value)} aria-label={filter.label} style={{ ...controlStyle, minWidth: 135, cursor: 'pointer' }}>
          {filter.options.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      ))}
    </div>
  );
}

function AccountDetailModal({ detail, loading, error, onClose }) {
  const [sessionsPage, setSessionsPage] = useState(1);
  const [activityPage, setActivityPage] = useState(1);
  const [fraudPage, setFraudPage] = useState(1);
  const [sessionSearch, setSessionSearch] = useState('');
  const [sessionStatus, setSessionStatus] = useState('all');
  const [activitySearch, setActivitySearch] = useState('');
  const [activityResult, setActivityResult] = useState('all');
  const [activityAction, setActivityAction] = useState('all');
  const [fraudSearch, setFraudSearch] = useState('');
  const [fraudDecision, setFraudDecision] = useState('all');
  const [fraudRisk, setFraudRisk] = useState('all');

  useEffect(() => {
    const closeOnEscape = event => event.key === 'Escape' && onClose();
    document.addEventListener('keydown', closeOnEscape);
    return () => document.removeEventListener('keydown', closeOnEscape);
  }, [onClose]);

  useEffect(() => {
    setSessionsPage(1);
    setActivityPage(1);
    setFraudPage(1);
    setSessionSearch('');
    setSessionStatus('all');
    setActivitySearch('');
    setActivityResult('all');
    setActivityAction('all');
    setFraudSearch('');
    setFraudDecision('all');
    setFraudRisk('all');
  }, [detail?.account?._id]);

  const sessions = detail?.sessions || EMPTY_LIST;
  const activities = detail?.activities || EMPTY_LIST;
  const fraudEvents = detail?.fraudEvents || EMPTY_LIST;
  const activityActions = useMemo(() => [...new Set(activities.map(event => event.action).filter(Boolean))].sort(), [activities]);
  const filteredSessions = useMemo(() => {
    const query = sessionSearch.trim().toLowerCase();
    return sessions.filter(session => {
      const status = session.active ? 'active' : session.inferredLogout ? 'not_recorded' : 'logged_out';
      const location = session.location || {};
      const matchesSearch = !query || [session.ipAddress, session.browser, session.os, session.device, session.userAgent, location.city, location.region, location.country, location.isp]
        .some(value => String(value || '').toLowerCase().includes(query));
      return matchesSearch && (sessionStatus === 'all' || status === sessionStatus);
    });
  }, [sessions, sessionSearch, sessionStatus]);
  const filteredActivities = useMemo(() => {
    const query = activitySearch.trim().toLowerCase();
    return activities.filter(event => {
      const location = event.location || {};
      const matchesSearch = !query || [event.action, event.ipAddress, event.browser, event.os, event.device, event.failReason, location.city, location.region, location.country, location.isp]
        .some(value => String(value || '').toLowerCase().includes(query));
      const matchesResult = activityResult === 'all' || (activityResult === 'success' ? event.success : !event.success);
      return matchesSearch && matchesResult && (activityAction === 'all' || event.action === activityAction);
    });
  }, [activities, activityAction, activityResult, activitySearch]);
  const filteredFraudEvents = useMemo(() => {
    const query = fraudSearch.trim().toLowerCase();
    return fraudEvents.filter(event => {
      const matchesSearch = !query || [event.ipAddress, event.location, event.decision, event.riskLevel, ...(event.matchedRules || [])]
        .some(value => String(value || '').toLowerCase().includes(query));
      return matchesSearch
        && (fraudDecision === 'all' || event.decision === fraudDecision)
        && (fraudRisk === 'all' || event.riskLevel === fraudRisk);
    });
  }, [fraudDecision, fraudEvents, fraudRisk, fraudSearch]);
  const visibleSessions = filteredSessions.slice((sessionsPage - 1) * PAGE_SIZE, sessionsPage * PAGE_SIZE);
  const visibleActivities = filteredActivities.slice((activityPage - 1) * PAGE_SIZE, activityPage * PAGE_SIZE);
  const visibleFraudEvents = filteredFraudEvents.slice((fraudPage - 1) * PAGE_SIZE, fraudPage * PAGE_SIZE);

  useEffect(() => setSessionsPage(1), [sessionSearch, sessionStatus]);
  useEffect(() => setActivityPage(1), [activitySearch, activityResult, activityAction]);
  useEffect(() => setFraudPage(1), [fraudSearch, fraudDecision, fraudRisk]);

  return (
    <div onMouseDown={event => event.target === event.currentTarget && onClose()} style={{ position: 'fixed', inset: 0, zIndex: 10000, background: 'rgba(1,6,15,.86)', backdropFilter: 'blur(5px)', padding: 18, display: 'flex', justifyContent: 'center', alignItems: 'center' }}>
      <div role="dialog" aria-modal="true" aria-label="Account activity details" style={{ width: 'min(1180px, 98vw)', maxHeight: '94vh', overflowY: 'auto', background: '#081426', border: `1px solid ${COLORS.border}`, borderRadius: 16, boxShadow: '0 30px 90px rgba(0,0,0,.55)' }}>
        <div style={{ position: 'sticky', top: 0, zIndex: 2, background: 'rgba(8,20,38,.97)', borderBottom: `1px solid ${COLORS.border}`, padding: '16px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 16 }}>
          <div>
            <div style={{ color: '#e0f2fe', fontWeight: 850, fontSize: 18 }}>{detail?.account?.name || 'Account activity'}</div>
            <div style={{ color: COLORS.muted, fontSize: 12, marginTop: 3 }}>{detail?.account?.email || 'Loading complete audit record…'}</div>
          </div>
          <button onClick={onClose} aria-label="Close account details" style={{ width: 34, height: 34, borderRadius: 8, border: `1px solid ${COLORS.border}`, background: COLORS.surface, color: '#cbd5e1', cursor: 'pointer', fontSize: 18 }}>×</button>
        </div>

        {loading && <EmptyState>Loading account, session, IP and location records…</EmptyState>}
        {error && <div style={{ margin: 20, padding: 14, color: '#fca5a5', background: '#3f101a', border: '1px solid #7f1d1d', borderRadius: 9 }}>{error}</div>}
        {!loading && detail && (
          <div style={{ padding: 20 }}>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8, marginBottom: 16 }}>
              <Pill color={detail.account.isActive ? COLORS.green : COLORS.red}>{detail.account.isActive ? 'ACTIVE' : 'INACTIVE'}</Pill>
              <Pill color={COLORS.purple}>{roleLabel(detail.account.role)}</Pill>
              <Pill color={detail.account.accountStatus === 'active' ? COLORS.green : COLORS.amber}>{String(detail.account.accountStatus || 'unknown').toUpperCase()}</Pill>
              {detail.account.twoFactorEnabled && <Pill color={COLORS.green}>2FA ENABLED</Pill>}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 9, marginBottom: 20 }}>
              <InfoItem label="Account ID" value={detail.account._id} mono />
              <InfoItem label="Company" value={detail.account.company?.name || 'Platform account'} />
              <InfoItem label="Phone" value={detail.account.phone} />
              <InfoItem label="Created" value={formatDateTime(detail.account.createdAt)} />
              <InfoItem label="Email verified" value={detail.account.isEmailVerified ? 'Yes' : 'No'} />
              <InfoItem label="Departments" value={(detail.account.departmentIds || []).map(item => item.name).join(', ') || detail.account.departmentId?.name} />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(135px,1fr))', gap: 9, marginBottom: 24 }}>
              <Metric label="Successful logins" value={detail.summary.totalLogins} color={COLORS.green} />
              <Metric label="Recorded logouts" value={detail.summary.totalLogouts} color={COLORS.blue} />
              <Metric label="Failed attempts" value={detail.summary.failedAttempts} color={detail.summary.failedAttempts ? COLORS.red : COLORS.green} />
              <Metric label="Unique IPs" value={detail.summary.uniqueIps.length} color={COLORS.purple} />
              <Metric label="Known locations" value={detail.summary.uniqueLocations.length} color={COLORS.amber} />
            </div>

            <section style={{ marginBottom: 26 }}>
              <h3 style={{ color: '#dbeafe', fontSize: 14, margin: '0 0 10px' }}>Login / logout sessions</h3>
              <TableFilters
                search={sessionSearch}
                onSearchChange={setSessionSearch}
                placeholder="Search session IP, location or device…"
                filters={[{ label: 'Session status', value: sessionStatus, onChange: setSessionStatus, options: [
                  { value: 'all', label: 'All statuses' }, { value: 'active', label: 'Active' }, { value: 'logged_out', label: 'Logged out' }, { value: 'not_recorded', label: 'Logout not recorded' },
                ] }]}
              />
              <TableShell headers={['Login time', 'Logout time', 'Duration', 'IP address', 'Location', 'Client', 'Session status']} empty="No completed login session has been recorded for this account." colSpan={7}>
                {visibleSessions.length ? visibleSessions.map((session, index) => (
                  <tr key={`${session.loginAt}-${index}`} style={{ borderTop: `1px solid ${COLORS.border}` }}>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap', color: COLORS.text }}>{formatDateTime(session.loginAt)}</td>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap', color: session.logoutAt ? COLORS.text : COLORS.amber }}>{session.logoutAt ? formatDateTime(session.logoutAt) : 'Not recorded'}</td>
                    <td style={{ padding: '10px 12px', whiteSpace: 'nowrap', color: COLORS.muted }}>{session.inferredLogout ? '~' : ''}{formatDuration(session.durationMinutes)}</td>
                    <td style={{ padding: '10px 12px', color: COLORS.blue, fontFamily: 'ui-monospace,monospace', whiteSpace: 'nowrap' }}>{session.ipAddress}</td>
                    <td style={{ padding: '10px 12px', minWidth: 150 }}>
                      <div>{locationText(session.location)}</div>
                      {session.location?.isp && <div style={{ color: '#475569', fontSize: 10, marginTop: 2 }}>{session.location.isp}</div>}
                      {coordinatesText(session.location) && <div style={{ color: session.location.source === 'browser_geolocation' ? COLORS.green : '#475569', fontSize: 10, marginTop: 2 }}>{coordinatesText(session.location)}</div>}
                      {session.location?.timezone && <div style={{ color: '#475569', fontSize: 10, marginTop: 2 }}>{session.location.timezone}</div>}
                    </td>
                    <td title={session.userAgent || ''} style={{ padding: '10px 12px', minWidth: 150 }}><div>{session.browser}</div><div style={{ color: '#475569', marginTop: 2 }}>{session.os} · {session.device}</div></td>
                    <td style={{ padding: '10px 12px' }}>{session.active ? <Pill color={COLORS.green}>ACTIVE</Pill> : session.inferredLogout ? <Pill color={COLORS.amber}>LOGOUT NOT RECORDED</Pill> : <Pill color={COLORS.blue}>{session.logoutAction === 'auto_logout' ? 'AUTO LOGOUT' : 'LOGGED OUT'}</Pill>}</td>
                  </tr>
                )) : null}
              </TableShell>
              <PaginationControls page={sessionsPage} total={filteredSessions.length} pageSize={PAGE_SIZE} onPageChange={setSessionsPage} />
            </section>

            <section style={{ marginBottom: 26 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', gap: 12, marginBottom: 10 }}>
                <h3 style={{ color: '#dbeafe', fontSize: 14, margin: 0 }}>Complete authentication timeline</h3>
                <span style={{ color: '#475569', fontSize: 10 }}>Loaded latest {activities.length} of {detail.totalActivity}</span>
              </div>
              <TableFilters
                search={activitySearch}
                onSearchChange={setActivitySearch}
                placeholder="Search event, IP, location or device…"
                filters={[
                  { label: 'Authentication result', value: activityResult, onChange: setActivityResult, options: [{ value: 'all', label: 'All results' }, { value: 'success', label: 'Success' }, { value: 'failed', label: 'Failed' }] },
                  { label: 'Authentication event', value: activityAction, onChange: setActivityAction, options: [{ value: 'all', label: 'All events' }, ...activityActions.map(action => ({ value: action, label: actionLabel(action) }))] },
                ]}
              />
              <TableShell headers={['Date & time', 'Event', 'Result', 'IP address', 'Location', 'Browser / device', 'Reason']} empty="No authentication activity has been captured." colSpan={7}>
                {visibleActivities.length ? visibleActivities.map(event => (
                  <tr key={event._id} style={{ borderTop: `1px solid ${COLORS.border}` }}>
                    <td style={{ padding: '9px 12px', color: COLORS.muted, whiteSpace: 'nowrap' }}>{formatDateTime(event.at)}</td>
                    <td style={{ padding: '9px 12px', color: COLORS.text, whiteSpace: 'nowrap', fontWeight: 700 }}>{actionLabel(event.action)}</td>
                    <td style={{ padding: '9px 12px' }}><Pill color={event.success ? COLORS.green : COLORS.red}>{event.success ? 'SUCCESS' : 'FAILED'}</Pill></td>
                    <td style={{ padding: '9px 12px', color: COLORS.blue, fontFamily: 'ui-monospace,monospace', whiteSpace: 'nowrap' }}>{event.ipAddress}</td>
                    <td style={{ padding: '9px 12px', minWidth: 130 }}><div>{locationText(event.location)}</div>{coordinatesText(event.location) && <div style={{ color: event.location.source === 'browser_geolocation' ? COLORS.green : '#475569', marginTop: 2 }}>{coordinatesText(event.location)}</div>}{event.location?.timezone && <div style={{ color: '#475569', marginTop: 2 }}>{event.location.timezone}</div>}{event.location?.permission && event.location.permission !== 'granted' && <div style={{ color: COLORS.amber, marginTop: 2 }}>Permission: {event.location.permission}</div>}</td>
                    <td title={event.userAgent || ''} style={{ padding: '9px 12px', minWidth: 150 }}><div>{event.browser}</div><div style={{ color: '#475569', marginTop: 2 }}>{event.os} · {event.device}</div></td>
                    <td style={{ padding: '9px 12px', color: event.failReason ? '#fca5a5' : '#475569' }}>{event.failReason ? actionLabel(event.failReason) : '—'}</td>
                  </tr>
                )) : null}
              </TableShell>
              <PaginationControls page={activityPage} total={filteredActivities.length} pageSize={PAGE_SIZE} onPageChange={setActivityPage} />
            </section>

            <section>
              <h3 style={{ color: '#dbeafe', fontSize: 14, margin: '0 0 10px' }}>Fraud and risk checks</h3>
              <TableFilters
                search={fraudSearch}
                onSearchChange={setFraudSearch}
                placeholder="Search IP, location or matched rule…"
                filters={[
                  { label: 'Fraud decision', value: fraudDecision, onChange: setFraudDecision, options: [{ value: 'all', label: 'All decisions' }, ...['ALLOW', 'BLOCK', 'CHALLENGE', 'MANUAL_REVIEW', 'AUTH_FAILED'].map(value => ({ value, label: actionLabel(value) }))] },
                  { label: 'Risk level', value: fraudRisk, onChange: setFraudRisk, options: [{ value: 'all', label: 'All risk levels' }, ...['low', 'medium', 'high', 'critical'].map(value => ({ value, label: actionLabel(value) }))] },
                ]}
              />
              <TableShell headers={['Date & time', 'Decision', 'Risk', 'IP / location', 'Signals', 'Matched rules']} empty="No Stytch fraud check is linked to this account yet." colSpan={6}>
                {visibleFraudEvents.length ? visibleFraudEvents.map(event => (
                  <tr key={event._id} style={{ borderTop: `1px solid ${COLORS.border}` }}>
                    <td style={{ padding: '9px 12px', color: COLORS.muted, whiteSpace: 'nowrap' }}>{formatDateTime(event.at)}</td>
                    <td style={{ padding: '9px 12px' }}><Pill color={event.decision === 'ALLOW' ? COLORS.green : event.decision === 'BLOCK' ? COLORS.red : COLORS.amber}>{event.decision}</Pill></td>
                    <td style={{ padding: '9px 12px', color: event.riskScore >= 70 ? COLORS.red : event.riskScore >= 40 ? COLORS.amber : COLORS.green }}>{event.riskScore ?? '—'} {event.riskLevel ? `· ${event.riskLevel}` : ''}</td>
                    <td style={{ padding: '9px 12px' }}><div style={{ color: COLORS.blue, fontFamily: 'ui-monospace,monospace' }}>{event.ipAddress || '—'}</div><div style={{ color: COLORS.muted, marginTop: 2 }}>{event.location || 'Not captured'}</div></td>
                    <td style={{ padding: '9px 12px', color: COLORS.amber }}>{[event.isVpn && 'VPN', event.isTor && 'TOR', event.isProxy && 'Proxy'].filter(Boolean).join(', ') || 'None'}</td>
                    <td style={{ padding: '9px 12px', color: COLORS.muted, minWidth: 140 }}>{event.matchedRules.join(', ') || '—'}</td>
                  </tr>
                )) : null}
              </TableShell>
              <PaginationControls page={fraudPage} total={filteredFraudEvents.length} pageSize={PAGE_SIZE} onPageChange={setFraudPage} />
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

export default function AccountActivityPanel({ companyId = '' }) {
  const [accounts, setAccounts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [search, setSearch] = useState('');
  const [detail, setDetail] = useState(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    let active = true;
    setLoading(true);
    setError('');
    const query = companyId ? `&companyId=${encodeURIComponent(companyId)}` : '';
    api.get(`/fraud/accounts?limit=1000${query}`)
      .then(async response => {
        if (!active) return;
        const firstPage = response.data.accounts || [];
        const remainingPages = Math.max(0, Number(response.data.pages || 1) - 1);
        const remainingResponses = remainingPages
          ? await Promise.all(Array.from({ length: remainingPages }, (_, index) => api.get(`/fraud/accounts?limit=1000&page=${index + 2}${query}`)))
          : [];
        if (!active) return;
        setAccounts([firstPage, ...remainingResponses.map(item => item.data.accounts || [])].flat());
        setTotal(response.data.total || 0);
      })
      .catch(requestError => active && setError(requestError.response?.data?.message || 'Account activity could not be loaded.'))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [companyId]);

  const filteredAccounts = useMemo(() => {
    const value = search.trim().toLowerCase();
    if (!value) return accounts;
    return accounts.filter(account => [account.name, account.email, account.role, account.company?.name, account.activity?.lastIp].some(field => String(field || '').toLowerCase().includes(value)));
  }, [accounts, search]);
  const visibleAccounts = filteredAccounts.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => setPage(1), [search, companyId]);

  const openAccount = async account => {
    setDetailOpen(true);
    setDetail(null);
    setDetailError('');
    setDetailLoading(true);
    try {
      const query = companyId ? `&companyId=${encodeURIComponent(companyId)}` : '';
      const response = await api.get(`/fraud/account/${account._id}?limit=1000${query}`);
      setDetail(response.data);
    } catch (requestError) {
      setDetailError(requestError.response?.data?.message || 'Account details could not be loaded.');
    } finally {
      setDetailLoading(false);
    }
  };

  return (
    <div>
      <div style={{ background: COLORS.panel, border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 16, marginBottom: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
        <div>
          <div style={{ color: '#dbeafe', fontWeight: 800, fontSize: 15 }}>👤 User account activity</div>
          <div style={{ color: COLORS.muted, fontSize: 11, marginTop: 4 }}>{total} accounts · login, logout, IP, location and device audit</div>
        </div>
        <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search name, email, role, company or IP…" aria-label="Search user accounts" style={{ width: 'min(360px,100%)', boxSizing: 'border-box', padding: '9px 12px', background: COLORS.surface, color: COLORS.text, border: `1px solid ${COLORS.border}`, borderRadius: 8, outline: 'none', fontSize: 12 }} />
      </div>

      {loading && <EmptyState>Loading user account cards…</EmptyState>}
      {error && <div style={{ padding: 14, color: '#fca5a5', background: '#3f101a', border: '1px solid #7f1d1d', borderRadius: 9 }}>{error}</div>}
      {!loading && !error && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill,minmax(285px,1fr))', gap: 13 }}>
          {visibleAccounts.map(account => {
            const activity = account.activity || {};
            const initials = String(account.name || account.email || '?').split(/\s+/).slice(0, 2).map(part => part[0]).join('').toUpperCase();
            return (
              <button key={account._id} onClick={() => openAccount(account)} style={{ textAlign: 'left', font: 'inherit', color: 'inherit', cursor: 'pointer', background: 'linear-gradient(145deg,#071222,#0c1a2e)', border: `1px solid ${COLORS.border}`, borderRadius: 12, padding: 16, minWidth: 0 }}>
                <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 14 }}>
                  <div style={{ flex: '0 0 auto', width: 42, height: 42, borderRadius: 11, display: 'grid', placeItems: 'center', background: 'linear-gradient(135deg,#2563eb,#7c3aed)', color: 'white', fontSize: 14, fontWeight: 900 }}>{initials}</div>
                  <div style={{ minWidth: 0, flex: 1 }}>
                    <div style={{ color: '#e0f2fe', fontSize: 13, fontWeight: 800, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{account.name}</div>
                    <div style={{ color: COLORS.muted, fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginTop: 2 }}>{account.email}</div>
                  </div>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: account.isActive ? COLORS.green : COLORS.red, boxShadow: `0 0 10px ${account.isActive ? COLORS.green : COLORS.red}` }} />
                </div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 13 }}><Pill color={COLORS.purple}>{roleLabel(account.role)}</Pill><Pill color={account.isActive ? COLORS.green : COLORS.red}>{account.isActive ? 'ACTIVE' : 'INACTIVE'}</Pill></div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 13 }}>
                  <InfoItem label="Last login" value={formatDateTime(activity.lastLogin)} />
                  <InfoItem label="Last logout" value={formatDateTime(activity.lastLogout)} />
                  <InfoItem label="Last IP" value={activity.lastIp} mono />
                  <InfoItem label="Last location" value={activity.lastLocation || 'Not captured'} />
                </div>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8, paddingTop: 11, borderTop: `1px solid ${COLORS.border}` }}>
                  <span style={{ color: '#475569', fontSize: 10 }}>{account.company?.name || 'Platform account'}</span>
                  <span style={{ color: COLORS.blue, fontSize: 10, fontWeight: 800 }}>{activity.totalLogins || 0} logins · {activity.failedAttempts || 0} failed →</span>
                </div>
              </button>
            );
          })}
        </div>
      )}
      {!loading && !error && !filteredAccounts.length && <EmptyState>No user account matches this filter.</EmptyState>}
      {!loading && !error && <PaginationControls page={page} total={filteredAccounts.length} pageSize={PAGE_SIZE} onPageChange={setPage} />}
      {detailOpen && <AccountDetailModal detail={detail} loading={detailLoading} error={detailError} onClose={() => setDetailOpen(false)} />}
    </div>
  );
}
