import { useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import SOCManagerDashboard from './SOCManagerDashboard';

/* ── Same design tokens as superadmin SOCManagersPage ── */
const panel = {
  background: 'rgba(15, 27, 46, 0.85)',
  backdropFilter: 'blur(12px)',
  border: '1px solid #1e3a5f',
  borderRadius: 12,
  padding: 18,
};
const input = {
  width: '100%',
  boxSizing: 'border-box',
  padding: '10px 14px',
  borderRadius: 8,
  border: '1px solid #294765',
  background: '#091525',
  color: '#f8fafc',
  outline: 'none',
  fontSize: 13,
  transition: 'all 0.2s',
};
const button = {
  border: 0,
  borderRadius: 8,
  padding: '9px 16px',
  background: 'linear-gradient(135deg, #0891b2 0%, #0284c7 100%)',
  color: '#fff',
  fontWeight: 700,
  cursor: 'pointer',
  fontSize: 12,
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  transition: 'all 0.2s',
};
const badgeStyle = (bg, color, border = 'transparent') => ({
  background: bg,
  color,
  border: '1px solid ' + border,
  borderRadius: 999,
  padding: '4px 10px',
  fontSize: 11,
  fontWeight: 800,
  letterSpacing: 0.3,
  whiteSpace: 'nowrap',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 5,
});

function MetricCard({ label, value, onClick, color, icon }) {
  return (
    <div onClick={onClick} style={{ ...panel, background: 'linear-gradient(135deg, rgba(15, 27, 46, 0.9) 0%, rgba(9, 21, 37, 0.9) 100%)', padding: 14, cursor: 'pointer', transition: 'all 0.2s', border: '1px solid #1e3a5f' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <small style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</small>
        <span style={{ fontSize: 14 }}>{icon}</span>
      </div>
      <div style={{ color, fontSize: 22, fontWeight: 900, marginTop: 6 }}>{value}</div>
    </div>
  );
}

export default function PartnerSocManagerPage() {
  const { user: me } = useAuth();

  const [metrics, setMetrics] = useState({});
  const [state, setState] = useState({ items: [], total: 0, page: 1, pages: 1 });
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [limit, setLimit] = useState(15);
  const [page, setPage] = useState(1);
  const [notice, setNotice] = useState({ type: '', text: '' });

  // Full-page dashboard view
  const [dashboardManagerId, setDashboardManagerId] = useState(null);
  const [chatManager, setChatManager] = useState(null);

  // Invite SOC Manager Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({ name: '', email: '', temporaryPassword: '', companyIds: [], maxWorkload: 10 });
  const [createBusy, setCreateBusy] = useState(false);

  // Invite Analyst Modal
  const [showAnalystModal, setShowAnalystModal] = useState(false);
  const [analystForm, setAnalystForm] = useState({ name: '', email: '', role: 'l1_analyst' });
  const [analystBusy, setAnalystBusy] = useState(false);

  // Bulk Company Scope Modal
  const [bulkAssignModal, setBulkAssignModal] = useState(null);
  const [bulkCompanyIds, setBulkCompanyIds] = useState([]);
  const [bulkBusy, setBulkBusy] = useState(false);

  const loadMetrics = async () => {
    try {
      const res = await api.get('/soc/managers/metrics');
      setMetrics(res.data || {});
    } catch (e) {
      console.error('Metrics fetch error:', e);
    }
  };

  const loadTable = async () => {
    setLoading(true);
    try {
      const res = await api.get('/soc/managers', {
        params: { page, limit, search, status: statusFilter },
      });
      setState(res.data || { items: [], total: 0, page: 1, pages: 1 });
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to load SOC Managers' });
    } finally {
      setLoading(false);
    }
  };

  const loadCompanies = async () => {
    try {
      const res = await api.get('/soc/companies');
      setCompanies(res.data || []);
    } catch (e) {
      console.error('Companies fetch error:', e);
    }
  };

  useEffect(() => {
    loadMetrics();
    loadCompanies();
  }, []);

  useEffect(() => {
    loadTable();
  }, [page, limit, search, statusFilter]);

  // Full dashboard view — render instead of page
  if (dashboardManagerId) {
    return (
      <SOCManagerDashboard
        managerId={dashboardManagerId}
        apiBase="/soc/staff"
        canControl={true}
        onBack={() => { setDashboardManagerId(null); loadTable(); loadMetrics(); }}
      />
    );
  }

  const handleSuspend = async (mgr) => {
    const reason = prompt('Enter suspension reason for ' + mgr.name + ':');
    if (!reason) return;
    try {
      await api.patch('/soc/staff/' + mgr._id + '/status', { status: 'suspended' });
      setNotice({ type: 'success', text: 'SOC Manager ' + mgr.name + ' suspended.' });
      loadTable(); loadMetrics();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Suspension failed' });
    }
  };

  const handleReactivate = async (mgr) => {
    try {
      await api.patch('/soc/staff/' + mgr._id + '/status', { status: 'active' });
      setNotice({ type: 'success', text: 'SOC Manager ' + mgr.name + ' reactivated.' });
      loadTable(); loadMetrics();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Reactivation failed' });
    }
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setCreateBusy(true);
    setNotice({ type: '', text: '' });
    try {
      await api.post('/soc/invitations', {
        name: createForm.name,
        email: createForm.email,
        role: 'soc_manager',
        companyIds: createForm.companyIds,
        temporaryPassword: createForm.temporaryPassword || undefined,
      });
      setNotice({ type: 'success', text: 'SOC Manager invitation sent to ' + createForm.email });
      setShowCreateModal(false);
      setCreateForm({ name: '', email: '', temporaryPassword: '', companyIds: [], maxWorkload: 10 });
      loadTable(); loadMetrics();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to invite SOC Manager' });
    } finally {
      setCreateBusy(false);
    }
  };

  const handleAnalystInvite = async (e) => {
    e.preventDefault();
    const companyId = companies[0]?._id;
    if (!companyId) {
      setNotice({ type: 'error', text: 'No company scope available.' });
      return;
    }
    setAnalystBusy(true);
    try {
      await api.post('/soc/invitations', {
        name: analystForm.name,
        email: analystForm.email,
        role: analystForm.role,
        companyIds: [companyId],
      });
      setNotice({ type: 'success', text: 'Analyst invitation sent to ' + analystForm.email });
      setShowAnalystModal(false);
      setAnalystForm({ name: '', email: '', role: 'l1_analyst' });
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to invite analyst' });
    } finally {
      setAnalystBusy(false);
    }
  };

  const handleBulkAssignSubmit = async (e) => {
    e.preventDefault();
    if (!bulkCompanyIds.length) return;
    setBulkBusy(true);
    try {
      await api.put('/soc/staff/' + bulkAssignModal._id + '/assignments', { companyIds: bulkCompanyIds });
      setNotice({ type: 'success', text: 'Companies assigned to ' + bulkAssignModal.name + '.' });
      setBulkAssignModal(null);
      setBulkCompanyIds([]);
      loadTable();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Company assignment failed' });
    } finally {
      setBulkBusy(false);
    }
  };

  return (
    <div>
      {/* ── Page Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, color: '#f8fafc', fontSize: 24, fontWeight: 900, letterSpacing: -0.5 }}>SOC Manager Monitoring</h2>
          <div style={{ color: '#38bdf8', fontSize: 13, marginTop: 4 }}>Monitor workforce, workload capacity, company scope, and active security operations.</div>
        </div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button style={button} onClick={() => setShowCreateModal(true)}>
            <span>+</span> Invite SOC Manager
          </button>
          <button style={{ ...button, background: 'linear-gradient(135deg, #7c3aed 0%, #6d28d9 100%)' }} onClick={() => setShowAnalystModal(true)}>
            <span>+</span> Invite Analysts
          </button>
          <button style={{ ...button, background: '#1e293b', border: '1px solid #334155' }} onClick={() => { loadMetrics(); loadTable(); }}>
            🔄 Refresh Metrics
          </button>
        </div>
      </div>

      {/* ── 12 Metric Cards ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 20 }}>
        <MetricCard label="Total Managers" value={metrics.total || 0} onClick={() => setStatusFilter('all')} color="#67e8f9" icon="🧑‍💼" />
        <MetricCard label="Active" value={metrics.active || 0} onClick={() => setStatusFilter('active')} color="#34d399" icon="🟢" />
        <MetricCard label="On-Shift" value={metrics.onShift || 0} onClick={() => setStatusFilter('active')} color="#38bdf8" icon="⏱️" />
        <MetricCard label="Online" value={metrics.online || 0} onClick={() => setStatusFilter('active')} color="#34d399" icon="🌐" />
        <MetricCard label="Offline" value={metrics.offline || 0} onClick={() => setStatusFilter('active')} color="#94a3b8" icon="🌙" />
        <MetricCard label="Overloaded" value={metrics.overloaded || 0} onClick={() => {}} color="#fb7185" icon="🔥" />
        <MetricCard label="Pending Invites" value={metrics.pendingInvitations || 0} onClick={() => setStatusFilter('invited')} color="#facc15" icon="📩" />
        <MetricCard label="Expired Invites" value={metrics.expiredInvitations || 0} onClick={() => setStatusFilter('expired')} color="#f87171" icon="⏳" />
        <MetricCard label="Suspended" value={metrics.suspended || 0} onClick={() => setStatusFilter('suspended')} color="#fb923c" icon="⛔" />
        <MetricCard label="No Companies" value={metrics.withoutCompanies || 0} onClick={() => {}} color="#e9d5ff" icon="🏢" />
        <MetricCard label="SLA Breaches" value={metrics.slaBreaches || 0} onClick={() => {}} color="#f87171" icon="⚠️" />
        <MetricCard label="Critical Cases" value={metrics.criticalIncidents || 0} onClick={() => {}} color="#fb7185" icon="🚨" />
      </div>

      {notice.text && (
        <div style={{ padding: '12px 16px', borderRadius: 8, marginBottom: 16, color: notice.type === 'error' ? '#fca5a5' : '#34d399', background: notice.type === 'error' ? 'rgba(53, 13, 22, 0.9)' : 'rgba(5, 46, 43, 0.9)', border: '1px solid ' + (notice.type === 'error' ? '#7f1d1d' : '#059669'), fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>{notice.type === 'error' ? '⚠️' : '✅'}</span> {notice.text}
        </div>
      )}

      {/* ── Toolbar ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12, marginBottom: 16 }}>
        <div style={{ display: 'flex', gap: 12, flex: 1, minWidth: 280 }}>
          <input
            value={search}
            onChange={e => { setSearch(e.target.value); setPage(1); }}
            placeholder="🔍 Search Manager name, email or company…"
            style={{ ...input, width: 300 }}
          />
          <select value={statusFilter} onChange={e => { setStatusFilter(e.target.value); setPage(1); }} style={{ ...input, width: 'auto' }}>
            <option value="all">All Account Statuses</option>
            <option value="active">Active</option>
            <option value="suspended">Suspended</option>
            <option value="invited">Invited</option>
            <option value="locked">Locked</option>
            <option value="deactivated">Deactivated</option>
          </select>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <small style={{ color: '#94a3b8', fontSize: 12 }}>Per Page:</small>
          <select value={limit} onChange={e => { setLimit(Number(e.target.value)); setPage(1); }} style={{ ...input, width: 'auto' }}>
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
        </div>
      </div>

      {/* ── Monitoring Table ── */}
      {loading ? (
        <div style={{ ...panel, padding: 40, color: '#94a3b8', textAlign: 'center', fontSize: 13 }}>Loading SOC Manager Records…</div>
      ) : !state.items || state.items.length === 0 ? (
        <div style={{ ...panel, padding: 40, color: '#94a3b8', textAlign: 'center', fontSize: 13 }}>No SOC Managers found matching filter.</div>
      ) : (
        <div style={{ ...panel, padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'linear-gradient(180deg, #13243c 0%, #0d192b 100%)', color: '#7dd3fc', textAlign: 'left', borderBottom: '1px solid #1e3a5f' }}>
                {['SOC Manager', 'Registered Email', 'Company Scope', 'Managed Analysts', 'Active Alerts', 'Workload Bar', 'Status', 'Actions'].map(x => (
                  <th key={x} style={{ padding: '14px 16px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, fontSize: 11 }}>{x}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.items.map(mgr => {
                const initial = (mgr.name || mgr.email || 'M').charAt(0).toUpperCase();
                const pct = mgr.workload?.percentage || 0;
                return (
                  <tr key={mgr._id} style={{ borderTop: '1px solid #1a2f4c', transition: 'background 0.15s' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(37,99,235,0.04)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{ width: 34, height: 34, borderRadius: 8, background: 'linear-gradient(135deg, #1e3a5f 0%, #0f2b48 100%)', color: '#67e8f9', border: '1px solid #2563eb', display: 'grid', placeItems: 'center', fontWeight: 900, fontSize: 14 }}>{initial}</div>
                        <div>
                          <b style={{ color: '#f8fafc', fontSize: 13 }}>{mgr.name}</b>
                          <div style={{ color: '#64748b', fontSize: 10, marginTop: 1 }}>ID: {mgr._id?.slice(-6)}</div>
                        </div>
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={{ color: '#cbd5e1', fontWeight: 500 }}>{mgr.email}</span>
                      <span style={{ display: 'block', color: '#475569', fontSize: 10, marginTop: 2 }}>🔒 Read-only</span>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#e2e8f0' }}>
                      <span style={{ background: '#091829', border: '1px solid #1e3a5f', padding: '4px 9px', borderRadius: 6, fontSize: 11, fontWeight: 700, color: '#38bdf8' }}>
                        {mgr.assignedCompaniesCount || 0} companies
                      </span>
                    </td>
                    <td style={{ padding: '12px 16px', color: '#94a3b8' }}>
                      <span style={{ color: '#c4b5fd', fontWeight: 700 }}>{mgr.analystCounts?.total || 0}</span> total
                      <small style={{ color: '#64748b', display: 'block', fontSize: 10 }}>L1:{mgr.analystCounts?.l1 || 0} · L2:{mgr.analystCounts?.l2 || 0} · L3:{mgr.analystCounts?.l3 || 0}</small>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <b style={{ color: '#f8fafc' }}>{mgr.workload?.open || 0} open</b>
                      {mgr.workload?.critical > 0 && <span style={{ color: '#fb7185', marginLeft: 6, fontWeight: 800 }}>({mgr.workload.critical} crit)</span>}
                    </td>
                    <td style={{ padding: '12px 16px', width: 130 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 3, display: 'flex', justifyContent: 'space-between' }}>
                        <span>Capacity</span> <b>{pct}%</b>
                      </div>
                      <div style={{ background: '#091525', height: 6, borderRadius: 3, overflow: 'hidden', border: '1px solid #1e3a5f' }}>
                        <div style={{ background: pct > 80 ? 'linear-gradient(90deg, #f87171, #ef4444)' : pct > 50 ? 'linear-gradient(90deg, #facc15, #eab308)' : 'linear-gradient(90deg, #34d399, #10b981)', height: '100%', width: pct + '%', transition: 'width 0.3s' }} />
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      {mgr.accountStatus === 'suspended' ? (
                        <span style={badgeStyle('rgba(127, 29, 29, 0.5)', '#fca5a5', '#991b1b')}>⛔ SUSPENDED</span>
                      ) : mgr.accountStatus === 'locked' ? (
                        <span style={badgeStyle('rgba(124, 45, 18, 0.5)', '#fdba74', '#9a3412')}>🔒 LOCKED</span>
                      ) : mgr.accountStatus === 'invited' ? (
                        <span style={badgeStyle('rgba(113, 63, 18, 0.5)', '#fde047', '#854d0e')}>📩 INVITED</span>
                      ) : (
                        <span style={badgeStyle('rgba(6, 78, 59, 0.5)', '#34d399', '#065f46')}>🟢 ACTIVE</span>
                      )}
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                        <button style={{ ...button, padding: '5px 10px', background: 'linear-gradient(135deg, #2563eb, #1d4ed8)', fontSize: 11 }} onClick={() => setDashboardManagerId(mgr._id)}>
                          🔍 Inspect
                        </button>
                        <button style={{ ...button, padding: '5px 10px', background: '#091d36', border: '1px solid #1d4ed8', color: '#60a5fa', fontSize: 11 }} onClick={() => { setBulkAssignModal(mgr); setBulkCompanyIds([]); }}>
                          🏢 Scope
                        </button>
                        {mgr.accountStatus === 'suspended' ? (
                          <button style={{ ...button, padding: '5px 10px', background: '#166534', fontSize: 11 }} onClick={() => handleReactivate(mgr)}>Reactivate</button>
                        ) : (
                          <button style={{ ...button, padding: '5px 10px', background: '#7f1d1d', fontSize: 11 }} onClick={() => handleSuspend(mgr)}>Suspend</button>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Pagination ── */}
      {state.pages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: 12, alignItems: 'center', marginTop: 20 }}>
          <button disabled={page <= 1} onClick={() => setPage(p => p - 1)} style={{ ...button, background: '#1e293b' }}>Previous</button>
          <span style={{ color: '#94a3b8', fontSize: 12 }}>Page {page} of {state.pages}</span>
          <button disabled={page >= state.pages} onClick={() => setPage(p => p + 1)} style={{ ...button, background: '#1e293b' }}>Next</button>
        </div>
      )}

      {/* ── Invite SOC Manager Modal ── */}
      {showCreateModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'rgba(2, 6, 23, 0.8)', backdropFilter: 'blur(6px)', display: 'grid', placeItems: 'center' }}>
          <form onSubmit={handleCreateSubmit} style={{ ...panel, background: '#091728', border: '1px solid #2563eb', width: 'min(520px, 92vw)', padding: 26, boxShadow: '0 0 32px rgba(0,0,0,0.8)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#f8fafc', fontSize: 18, fontWeight: 800 }}>Invite SOC Manager</h3>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>Full Name *</small>
              <input required style={input} value={createForm.name} onChange={e => setCreateForm({ ...createForm, name: e.target.value })} placeholder="e.g. Alex SOC Manager" />
            </label>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>Official Email * (Read-only on profile)</small>
              <input required type="email" style={input} value={createForm.email} onChange={e => setCreateForm({ ...createForm, email: e.target.value })} placeholder="e.g. manager@soc.com" />
            </label>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>Temporary Password (Optional — auto-generated if blank)</small>
              <input type="password" placeholder="e.g. TempPass123! (optional)" style={input} value={createForm.temporaryPassword || ''} onChange={e => setCreateForm({ ...createForm, temporaryPassword: e.target.value })} />
            </label>

            <label style={{ display: 'block', marginBottom: 8 }}>
              <small style={{ color: '#7dd3fc', fontSize: 11, fontWeight: 700 }}>Assign Partner Companies *</small>
            </label>
            <div style={{ maxHeight: 140, overflowY: 'auto', background: '#040d1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 18 }}>
              {companies.length === 0 ? (
                <div style={{ color: '#64748b', fontSize: 12, padding: 10 }}>No companies available for scope assignment.</div>
              ) : companies.map(c => (
                <label key={c._id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#e2e8f0', marginBottom: 6, cursor: 'pointer' }}>
                  <input type="checkbox" checked={createForm.companyIds.includes(c._id)} onChange={e => setCreateForm({
                    ...createForm,
                    companyIds: e.target.checked ? [...createForm.companyIds, c._id] : createForm.companyIds.filter(id => id !== c._id)
                  })} />
                  <b>{c.name}</b> <small style={{ color: '#34d399', fontSize: 10 }}>(Partner Company)</small>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => setShowCreateModal(false)} style={{ ...button, background: '#1e293b', border: '1px solid #334155' }}>Cancel</button>
              <button type="submit" disabled={createBusy || !createForm.companyIds.length} style={button}>
                {createBusy ? 'Sending…' : 'Send Invitation'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Invite Analyst Modal ── */}
      {showAnalystModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'rgba(2, 6, 23, 0.8)', backdropFilter: 'blur(6px)', display: 'grid', placeItems: 'center' }}>
          <form onSubmit={handleAnalystInvite} style={{ ...panel, background: '#091728', border: '1px solid #7c3aed', width: 'min(520px, 92vw)', padding: 26, boxShadow: '0 0 32px rgba(0,0,0,0.8)' }}>
            <h3 style={{ margin: '0 0 16px', color: '#f8fafc', fontSize: 18, fontWeight: 800 }}>Invite Analyst</h3>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>Full Name *</small>
              <input required style={input} value={analystForm.name} onChange={e => setAnalystForm({ ...analystForm, name: e.target.value })} placeholder="e.g. Priya Sharma" />
            </label>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>Official Email *</small>
              <input required type="email" style={input} value={analystForm.email} onChange={e => setAnalystForm({ ...analystForm, email: e.target.value })} placeholder="e.g. analyst@soc.com" />
            </label>

            <label style={{ display: 'block', marginBottom: 12 }}>
              <small style={{ color: '#c4b5fd', fontSize: 11, fontWeight: 700 }}>Analyst Level *</small>
              <select required style={input} value={analystForm.role} onChange={e => setAnalystForm({ ...analystForm, role: e.target.value })}>
                <option value="l1_analyst">L1 Analyst</option>
                <option value="l2_analyst">L2 Analyst</option>
                <option value="l3_analyst">L3 Analyst</option>
                <option value="l4_analyst">L4 Threat Intelligence Analyst</option>
              </select>
            </label>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => setShowAnalystModal(false)} style={{ ...button, background: '#1e293b', border: '1px solid #334155' }}>Cancel</button>
              <button type="submit" disabled={analystBusy || !companies.length} style={{ ...button, background: '#7c3aed' }}>
                {analystBusy ? 'Sending…' : 'Send Invitation'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ── Bulk Company Scope Modal ── */}
      {bulkAssignModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'rgba(2, 6, 23, 0.8)', backdropFilter: 'blur(6px)', display: 'grid', placeItems: 'center' }}>
          <form onSubmit={handleBulkAssignSubmit} style={{ ...panel, background: '#091728', border: '1px solid #2563eb', width: 'min(520px, 92vw)', padding: 26 }}>
            <h3 style={{ margin: '0 0 16px', color: '#f8fafc', fontSize: 18, fontWeight: 800 }}>Assign Scope: {bulkAssignModal.name}</h3>
            <div style={{ maxHeight: 180, overflowY: 'auto', background: '#040d1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 18 }}>
              {companies.map(c => (
                <label key={c._id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#e2e8f0', marginBottom: 6, cursor: 'pointer' }}>
                  <input type="checkbox" checked={bulkCompanyIds.includes(c._id)} onChange={e => setBulkCompanyIds(
                    e.target.checked ? [...bulkCompanyIds, c._id] : bulkCompanyIds.filter(id => id !== c._id)
                  )} />
                  <b>{c.name}</b> <small style={{ color: '#34d399', fontSize: 10 }}>(Partner Company)</small>
                </label>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => setBulkAssignModal(null)} style={{ ...button, background: '#1e293b', border: '1px solid #334155' }}>Cancel</button>
              <button type="submit" disabled={bulkBusy} style={button}>{bulkBusy ? 'Saving…' : 'Save Company Scope'}</button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
