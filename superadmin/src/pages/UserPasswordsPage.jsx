import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Eye, EyeOff, KeyRound, LogIn, RefreshCw, Search, ShieldCheck } from 'lucide-react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { useToast } from '../components/Toast';
import PaginationControls from '../components/common/PaginationControls';
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
const PAGE_SIZE = 10;
const statusOf = account => account.isActive === false ? 'disabled' : account.accountStatus || 'active';
const dateLabel = value => value ? new Date(value).toLocaleString() : 'Not recorded';

export default function UserPasswordsPage() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const toast = useToast();
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [reload, setReload] = useState(0);
  const [search, setSearch] = useState('');
  const [role, setRole] = useState('all');
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState(null);
  const [newPassword, setNewPassword] = useState('');
  const [confirmation, setConfirmation] = useState('');
  const [visible, setVisible] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [impersonatingId, setImpersonatingId] = useState('');
  const [loginError, setLoginError] = useState('');
  const loggingIn = useRef(false);
  const passwordInput = useRef(null);
  const submitting = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setLoadError('');
    api.get('/superadmin/users', { signal: controller.signal })
      .then(({ data }) => {
        if (controller.signal.aborted) return;
        setUsers(Array.isArray(data) ? data : []);
      })
      .catch(err => {
        if (!controller.signal.aborted) setLoadError(err.response?.data?.message || 'Unable to load user accounts.');
      })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [reload]);

  useEffect(() => {
    if (selected) passwordInput.current?.focus();
  }, [selected]);

  const selectAccount = account => {
    if (submitting.current) return;
    setNewPassword('');
    setConfirmation('');
    setVisible(false);
    setError('');
    setSuccess('');
    setSelected(account);
  };

  const isOwnAccount = selected && String(selected._id) === String(user?._id || user?.id);
  const query = search.trim().toLowerCase();
  const filtered = users.filter(account => (
    (role === 'all' || account.role === role)
    && (!query || [account.name, account.email, ROLES[account.role], account.companyId?.name,
      account.partnerId?.name, account.tenantId?.name].some(value => value?.toLowerCase().includes(query)))
  ));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)));
  const rows = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  const changePassword = async event => {
    event.preventDefault();
    if (!selected || submitting.current || loggingIn.current) return;
    setError('');
    setSuccess('');
    if (newPassword.length < 8 || newPassword.length > 128) {
      setError('Password must be between 8 and 128 characters.');
      return;
    }
    if (newPassword !== confirmation) {
      setError('Passwords do not match.');
      return;
    }
    submitting.current = true;
    setSaving(true);
    try {
      const { data } = await api.post(`/superadmin/users/${selected._id}/password`, { newPassword });
      setUsers(previous => previous.map(account => account._id === selected._id
        ? { ...account, passwordChangedAt: data.passwordChangedAt, forcePasswordReset: false }
        : account));
      setNewPassword('');
      setConfirmation('');
      setVisible(false);
      setSelected(null);
      if (isOwnAccount) {
        toast.success('Your password has changed. Sign in with your new password.', 7000);
        logout();
        navigate('/login', { replace: true });
      } else {
        setSuccess(`Password changed for ${selected.email}.`);
      }
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to change password. Please try again.');
    } finally {
      submitting.current = false;
      setSaving(false);
    }
  };

  const loginAsUser = async account => {
    if (loggingIn.current || submitting.current) return;
    setLoginError('');
    setSuccess('');
    const loginWindow = window.open('about:blank', '_blank');
    if (!loginWindow) {
      setLoginError('Allow pop-ups for this site, then click Login as User again.');
      return;
    }
    loginWindow.opener = null;
    loginWindow.document.title = 'Logging in…';
    loginWindow.document.body.textContent = `Opening ${account.email}…`;
    loggingIn.current = true;
    setImpersonatingId(account._id);
    try {
      const { data } = await api.post(`/superadmin/users/${account._id}/impersonate`);
      if (loginWindow.closed) return;
      const portalUrl = data.user.role === 'superadmin' ? window.location.origin
        : (import.meta.env.VITE_COMPANY_ORIGIN || data.portalUrl);
      const url = new URL(portalUrl);
      url.pathname = data.user.role === 'superadmin' ? '/superadmin' : '/';
      url.search = '';
      url.hash = new URLSearchParams({ impersonationToken: data.token }).toString();
      loginWindow.location.replace(url.toString());
      setSuccess(`Login opened for ${account.email} in a new tab.`);
    } catch (err) {
      loginWindow.close();
      setLoginError(err.response?.data?.message || 'Unable to log in as this user. Please try again.');
    } finally {
      loggingIn.current = false;
      setImpersonatingId('');
    }
  };

  return (
    <div className="user-passwords">
      <header className="up-header">
        <div>
          <div className="up-eyebrow"><ShieldCheck size={14} /> Superadmin access</div>
          <h1>User Passwords</h1>
          <p>Change passwords or log in as a user across partners, companies, and SOC teams.</p>
        </div>
        <button type="button" className="up-button" disabled={loading || saving} onClick={() => setReload(value => value + 1)}>
          <RefreshCw size={15} /> Refresh accounts
        </button>
      </header>

      {success && <div className="up-success" role="status">{success}</div>}
      {loginError && <div className="up-error" role="alert">{loginError}</div>}
      <div className="up-layout">
        <section className="up-card up-accounts" aria-label="User accounts">
          <div className="up-card-heading"><h2>All accounts</h2><span>{loading ? 'Loading…' : `${users.length} users`}</span></div>
          <div className="up-filters">
            <label className="up-search">
              <Search size={16} />
              <input aria-label="Search accounts" placeholder="Search name, email, or company…" value={search}
                onChange={event => { setSearch(event.target.value); setPage(1); }} />
            </label>
            <select aria-label="Filter by role" value={role} onChange={event => { setRole(event.target.value); setPage(1); }}>
              <option value="all">All roles</option>
              {Object.entries(ROLES).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </div>

          {loadError ? (
            <div className="up-empty" role="alert"><p>{loadError}</p><button className="up-button" type="button" onClick={() => setReload(value => value + 1)}>Retry</button></div>
          ) : loading ? <div className="up-empty" role="status">Loading user accounts…</div> : (
            <>
              <div className="up-table-scroll">
                <table>
                  <thead><tr><th>User</th><th>Role / Organization</th><th>Status</th><th><span className="up-sr-only">Action</span></th></tr></thead>
                  <tbody>
                    {rows.map(account => (
                      <tr key={account._id} className={selected?._id === account._id ? 'up-selected' : ''}>
                        <td><strong>{account.name}</strong><span>{account.email}</span></td>
                        <td><strong>{ROLES[account.role] || account.role}</strong><span>{account.companyId?.name || account.partnerId?.name || account.tenantId?.name || 'Platform'}</span></td>
                        <td><span className={`up-status ${statusOf(account) === 'active' ? 'up-active' : ''}`}>{statusOf(account)}</span></td>
                        <td><div className="up-account-actions">
                          <button type="button" className="up-button" disabled={saving || !!impersonatingId} aria-label={`Change password for ${account.email}`}
                            onClick={() => selectAccount(account)}><KeyRound size={14} /> Change password</button>
                          <button type="button" className="up-button up-primary" disabled={saving || !!impersonatingId || statusOf(account) !== 'active'}
                            title={statusOf(account) !== 'active' ? 'Activate this account before logging in' : 'Open this account in a new tab'}
                            aria-label={`Login as ${account.email}`} onClick={() => loginAsUser(account)}>
                            <LogIn size={14} /> {impersonatingId === account._id ? 'Logging in…' : 'Login as User'}
                          </button>
                        </div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {!rows.length && <div className="up-empty">{users.length ? 'No accounts match your search.' : 'No user accounts found.'}</div>}
              </div>
              <div className="up-pagination"><PaginationControls page={currentPage} total={filtered.length} pageSize={PAGE_SIZE} onPageChange={setPage} /></div>
            </>
          )}
        </section>

        <section className={`up-card up-editor ${selected ? 'up-editor-open' : ''}`} aria-labelledby="up-editor-title">
          <div className="up-card-heading"><h2 id="up-editor-title"><KeyRound size={18} /> Change password</h2></div>
          {selected ? (
            <form onSubmit={changePassword} className="up-form">
              <div className="up-target"><strong>{selected.name}</strong><span>{selected.email}</span><small>{ROLES[selected.role] || selected.role}</small></div>
              <p className="up-last-changed">Last changed: {dateLabel(selected.passwordChangedAt)}</p>
              {isOwnAccount && <p className="up-notice">Changing your own password will sign you out.</p>}
              <label htmlFor="up-password">New password</label>
              <input ref={passwordInput} id="up-password" type={visible ? 'text' : 'password'} autoComplete="new-password"
                spellCheck={false} autoCapitalize="none"
                minLength={8} maxLength={128} required disabled={saving} value={newPassword}
                aria-describedby="up-password-help" onChange={event => { setNewPassword(event.target.value); setError(''); }} />
              <p id="up-password-help" className="up-help">Use 8–128 characters.</p>
              <label htmlFor="up-confirm">Confirm new password</label>
              <input id="up-confirm" type={visible ? 'text' : 'password'} autoComplete="new-password"
                spellCheck={false} autoCapitalize="none"
                minLength={8} maxLength={128} required disabled={saving} value={confirmation}
                onChange={event => { setConfirmation(event.target.value); setError(''); }} />
              <button type="button" className="up-visibility" disabled={saving} aria-pressed={visible} onClick={() => setVisible(value => !value)}>
                {visible ? <EyeOff size={15} /> : <Eye size={15} />} {visible ? 'Hide passwords' : 'Show passwords'}
              </button>
              {error && <p className="up-error" role="alert">{error}</p>}
              <div className="up-form-actions">
                <button className="up-button" type="button" disabled={saving} onClick={() => selectAccount(null)}>Cancel</button>
                <button className="up-button up-primary" type="submit" disabled={saving || !!impersonatingId}>{saving ? 'Saving…' : 'Save password'}</button>
              </div>
            </form>
          ) : (
            <div className="up-empty up-editor-placeholder"><KeyRound size={32} /><h3>Select an account</h3><p>Choose “Change password” next to a user to set their new login password.</p></div>
          )}
        </section>
      </div>
    </div>
  );
}
