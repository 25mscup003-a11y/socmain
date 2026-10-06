import { useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { ROLE_LABELS } from '../config/menuConfig';
import PaginationControls from '../components/PaginationControls';
import '../components/PartnerUserPasswords.css';
import './PartnerAuditPage.css';

const ACTIONS = {
  partner_impersonation_started: 'Login as User',
  partner_impersonation_ended: 'User session logout',
  password_changed: 'Password changed',
  partner_impersonation_blocked: 'Action blocked',
};
const emptyAudit = { entries: [], total: 0, page: 1, pageSize: 6 };

export default function PartnerAuditPage() {
  const { user } = useAuth();
  const [audit, setAudit] = useState(emptyAudit);
  const [page, setPage] = useState(1);
  const [action, setAction] = useState('all');
  const [reload, setReload] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    api.get('/partner/user-accounts/audit', {
      params: { page, action }, signal: controller.signal, skipCache: true,
    }).then(({ data }) => {
      if (!controller.signal.aborted) setAudit(data);
    }).catch(err => {
      if (!controller.signal.aborted) setError(err.response?.data?.message || 'Unable to load audit logs. Please retry.');
    }).finally(() => {
      if (!controller.signal.aborted) setLoading(false);
    });
    return () => controller.abort();
  }, [page, action, reload, user?._id, user?.partnerId]);

  useEffect(() => {
    const refresh = () => setReload(value => value + 1);
    window.addEventListener('focus', refresh);
    return () => window.removeEventListener('focus', refresh);
  }, []);

  return (
    <div className="partner-user-passwords partner-audit">
      <header className="up-header">
        <div>
          <div className="up-eyebrow">Partner account access</div>
          <h1>Audit</h1>
          <p>Track user logins, session logouts and password changes made by your partner admins.</p>
        </div>
        <button type="button" className="up-button" disabled={loading} onClick={() => setReload(value => value + 1)}>
          <span aria-hidden="true">↻</span> Refresh logs
        </button>
      </header>

      <section className="up-card" aria-label="Account access audit logs" aria-busy={loading}>
        <div className="up-card-heading">
          <h2>Account access history</h2>
          <span>{loading ? 'Loading…' : error ? 'Unavailable' : `${audit.total} records`}</span>
        </div>
        <div className="up-filters">
          <select aria-label="Filter audit by action" value={action} onChange={event => { setAction(event.target.value); setPage(1); }}>
            <option value="all">All actions</option>
            {Object.entries(ACTIONS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select>
        </div>

        {error ? (
          <div className="up-empty" role="alert">
            <p>{error}</p>
            <button type="button" className="up-button" onClick={() => setReload(value => value + 1)}>Retry</button>
          </div>
        ) : loading ? <div className="up-empty" role="status">Loading audit logs…</div> : audit.entries.length ? (
          <>
            <div className="up-table-scroll">
              <table>
                <thead><tr><th scope="col">Time</th><th scope="col">Partner admin</th><th scope="col">User account</th><th scope="col">Action</th><th scope="col">Result</th><th scope="col">IP address</th></tr></thead>
                <tbody>
                  {audit.entries.map(entry => (
                    <tr key={entry._id}>
                      <td><time dateTime={entry.createdAt}>{new Date(entry.createdAt).toLocaleString()}</time></td>
                      <td><strong>{entry.actor.name || 'Partner Admin'}</strong><span>{entry.actor.email}</span></td>
                      <td>
                        <strong>{entry.target.name || entry.target.email || 'User account'}</strong>
                        <span>{entry.target.email || entry.target._id}</span>
                        {entry.target.role && <span>{ROLE_LABELS[entry.target.role] || entry.target.role}</span>}
                      </td>
                      <td>{ACTIONS[entry.action] || entry.action}</td>
                      <td><span className={`up-status${entry.success ? ' up-active' : ''}`}>{entry.success ? 'Success' : 'Blocked'}</span></td>
                      <td>{entry.ipAddress || 'Not recorded'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="up-pagination">
              <PaginationControls page={audit.page} total={audit.total} pageSize={audit.pageSize} onPageChange={setPage} ariaLabel="Audit log pagination" />
            </div>
          </>
        ) : <div className="up-empty">{action === 'all' ? 'No account access activity recorded yet.' : 'No audit logs match this action.'}</div>}
      </section>
    </div>
  );
}
