import { useEffect, useState } from 'react';
import { Handshake, RefreshCw, ClipboardList } from 'lucide-react';
import api from '../api/axios';
import PaginationControls from '../components/common/PaginationControls';
import './UserPasswordsPage.css';
import './PartnerAccessAccountsPage.css';

const ROLES = {
  company_admin: 'Company Admin', department_admin: 'Department Admin', soc_manager: 'SOC Manager',
  analyst: 'Analyst', l1_analyst: 'L1 Analyst', l2_analyst: 'L2 Analyst', l3_analyst: 'L3 Analyst', l4_analyst: 'L4 Analyst',
};
const dateLabel = value => value ? new Date(value).toLocaleString() : 'Not recorded';

export default function PartnerAccessAccountsPage() {
  const [audit, setAudit] = useState({ entries: [], page: 1, pageSize: 6, total: 0 });
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    setError('');
    const refresh = (showLoading = false) => {
      if (pending || controller.signal.aborted) return;
      pending = true;
      if (showLoading) setLoading(true);
      api.get('/superadmin/partner-access-accounts', { params: { page }, signal: controller.signal, skipCache: true })
        .then(({ data }) => {
          if (controller.signal.aborted) return;
          setAudit(data);
          setError('');
        })
        .catch(err => {
          if (!controller.signal.aborted) setError(err.response?.data?.message || 'Unable to load partner account access logs.');
        })
        .finally(() => { pending = false; if (!controller.signal.aborted) setLoading(false); });
    };
    const refreshVisible = () => { if (document.visibilityState === 'visible') refresh(); };
    refresh(true);
    window.addEventListener('focus', refreshVisible);
    document.addEventListener('visibilitychange', refreshVisible);
    const timer = window.setInterval(refreshVisible, 15000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
      window.removeEventListener('focus', refreshVisible);
      document.removeEventListener('visibilitychange', refreshVisible);
    };
  }, [page, reload]);

  return (
    <div className="user-passwords partner-access-accounts">
      <header className="up-header">
        <div>
          <div className="up-eyebrow"><Handshake size={14} /> Partner access history</div>
          <h1>Partner Access Account</h1>
          <p>Partner access to company and user accounts, with login and logout times.</p>
        </div>
        <button type="button" className="up-button" disabled={loading} onClick={() => setReload(value => value + 1)}>
          <RefreshCw size={15} /> Refresh logs
        </button>
      </header>

      <section className="up-card" aria-label="Partner account access logs" aria-busy={loading}>
        <div className="up-card-heading"><h2><ClipboardList size={18} /> Account access logs</h2><span>{loading ? 'Loading…' : error ? 'Unavailable' : `${audit.total} sessions`}</span></div>
        {loading ? <div className="up-empty" role="status">Loading partner access logs…</div>
          : error ? <div className="up-empty" role="alert">
            <p>{error}</p><button type="button" className="up-button" onClick={() => setReload(value => value + 1)}>Retry</button>
          </div>
          : !audit.entries.length ? <div className="up-empty">No partner account access recorded yet.</div>
          : <>
            <div className="up-table-scroll"><table>
              <thead><tr><th scope="col">Partner</th><th scope="col">Account accessed</th><th scope="col">Company</th><th scope="col">Role</th><th scope="col">Login time</th><th scope="col">Logout time</th><th scope="col">IP address</th></tr></thead>
              <tbody>{audit.entries.map(entry => <tr key={entry._id}>
                <td><strong>{entry.partnerName || entry.partnerId || 'Partner'}</strong><span>{entry.actorName || 'Partner Admin'}</span><span>{entry.actorEmail}</span></td>
                <td><strong>{entry.targetName || entry.targetEmail || 'User account'}</strong><span>{entry.targetEmail || entry.targetUserId}</span></td>
                <td>{entry.companyName || entry.companyId || '—'}</td>
                <td>{ROLES[entry.targetRole] || entry.targetRole || 'Not recorded'}</td>
                <td><time dateTime={entry.loginAt || undefined}>{dateLabel(entry.loginAt)}</time></td>
                <td>{entry.logoutAt ? <time dateTime={entry.logoutAt}>{dateLabel(entry.logoutAt)}</time> : 'Not recorded'}</td>
                <td>{entry.ipAddress || 'Not recorded'}</td>
              </tr>)}</tbody>
            </table></div>
            <div className="up-pagination"><PaginationControls page={audit.page} total={audit.total} pageSize={audit.pageSize} onPageChange={setPage} /></div>
          </>}
      </section>
    </div>
  );
}
