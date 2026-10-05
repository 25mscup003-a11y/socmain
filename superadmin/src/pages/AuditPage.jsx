import { useEffect, useState } from 'react';
import { ClipboardList, RefreshCw, ShieldCheck } from 'lucide-react';
import api from '../api/axios';
import './UserPasswordsPage.css';

const ROLES = {
  superadmin: 'Superadmin',
  partner_admin: 'Partner Admin',
  company_admin: 'Company Admin',
  department_admin: 'Department Admin',
  soc_manager: 'SOC Manager',
  analyst: 'Analyst',
  l1_analyst: 'L1 Analyst',
  l2_analyst: 'L2 Analyst',
  l3_analyst: 'L3 Analyst',
  l4_analyst: 'L4 Analyst',
};
const dateLabel = value => value ? new Date(value).toLocaleString() : 'Not recorded';

export default function AuditPage() {
  const [audits, setAudits] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [reload, setReload] = useState(0);

  useEffect(() => {
    const controller = new AbortController();
    let pending = false;
    const refresh = (showLoading = false) => {
      if (pending || controller.signal.aborted) return;
      pending = true;
      if (showLoading) setLoading(true);
      api.get('/superadmin/user-login-audits', { signal: controller.signal })
        .then(({ data }) => {
          if (controller.signal.aborted) return;
          setAudits(Array.isArray(data) ? data : []);
          setError('');
        })
        .catch(err => {
          if (!controller.signal.aborted) setError(err.response?.data?.message || 'Unable to refresh audit logs.');
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
  }, [reload]);

  return (
    <div className="user-passwords">
      <header className="up-header">
        <div>
          <div className="up-eyebrow"><ShieldCheck size={14} /> Superadmin access</div>
          <h1>Audit</h1>
          <p>View superadmin sign-ins and account logins with login time, logout time, and IP address.</p>
        </div>
        <button type="button" className="up-button" disabled={loading} onClick={() => setReload(value => value + 1)}>
          <RefreshCw size={15} /> Refresh logs
        </button>
      </header>

      <section className="up-card" aria-label="Superadmin login activity">
        <div className="up-card-heading"><h2><ClipboardList size={18} /> Superadmin login logs</h2><span>Latest 50 events</span></div>
        {error && audits.length > 0 && <div className="up-error" role="alert">{error} Previous records are still shown.</div>}
        {loading ? <div className="up-empty" role="status">Loading audit logs…</div>
          : error && !audits.length ? <div className="up-empty" role="alert">
            <p>{error}</p><button type="button" className="up-button" onClick={() => setReload(value => value + 1)}>Retry</button>
          </div>
          : !audits.length ? <div className="up-empty">No superadmin logins recorded yet.</div>
          : <div className="up-table-scroll"><table>
            <thead><tr><th>Superadmin</th><th>Activity</th><th>Account opened</th><th>Role</th><th>Login time</th><th>Logout time</th><th>IP address</th></tr></thead>
            <tbody>{audits.map(audit => <tr key={`${audit.eventType || 'user_login'}:${audit._id}`}>
              <td><strong>{audit.actorName}</strong><span>{audit.actorEmail}</span></td>
              <td>{audit.eventType === 'superadmin_login' ? 'Superadmin login'
                : audit.eventType === 'superadmin_logout' ? 'Superadmin logout' : 'Login as User'}</td>
              <td><strong>{audit.targetName}</strong><span>{audit.targetEmail}</span></td>
              <td>{ROLES[audit.targetRole] || audit.targetRole}</td>
              <td>{dateLabel(audit.loginAt)}</td>
              <td>{dateLabel(audit.logoutAt)}</td>
              <td>{audit.ipAddress || '—'}</td>
            </tr>)}</tbody>
          </table></div>}
      </section>
    </div>
  );
}
