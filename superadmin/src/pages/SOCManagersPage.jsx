import { useEffect, useState } from 'react';
import api from '../api/axios';
import SocChatModal from '../components/SocChatModal';
import SOCManagerOperationsDashboard from './SOCManagerOperationsDashboard';

const panel = { background: 'rgba(15, 27, 46, 0.85)', backdropFilter: 'blur(12px)', border: '1px solid #1e3a5f', borderRadius: 12, padding: 18 };
const input = { width: '100%', boxSizing: 'border-box', padding: '10px 14px', borderRadius: 8, border: '1px solid #294765', background: '#091525', color: '#f8fafc', outline: 'none', fontSize: 13, transition: 'all 0.2s' };
const button = { border: 0, borderRadius: 8, padding: '9px 16px', background: 'linear-gradient(135deg, #0891b2 0%, #0284c7 100%)', color: '#fff', fontWeight: 700, cursor: 'pointer', fontSize: 12, display: 'inline-flex', alignItems: 'center', gap: 6, transition: 'all 0.2s' };
const badgeStyle = (bg, color, border = 'transparent') => ({ background: bg, color, border: `1px solid ${border}`, borderRadius: 999, padding: '4px 10px', fontSize: 11, fontWeight: 800, letterSpacing: 0.3, whiteSpace: 'nowrap', display: 'inline-flex', alignItems: 'center', gap: 5 });

export default function SOCManagersPage() {
  const [metrics, setMetrics] = useState({});
  const [state, setState] = useState({ items: [], total: 0, page: 1, pages: 1 });
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [limit, setLimit] = useState(15);
  const [page, setPage] = useState(1);
  const [notice, setNotice] = useState({ type: '', text: '' });
  const [viewMode, setViewMode] = useState('cards');
  const [impersonatingId, setImpersonatingId] = useState('');

  const handleImpersonate = async (e, id) => {
    if (e && e.stopPropagation) e.stopPropagation();
    const newWindow = window.open('about:blank', '_blank');
    try {
      setImpersonatingId(id);
      const { data } = await api.post(`/super-admin/soc-managers/${id}/impersonate`);
      const targetUrl = data.redirectUrl || `http://localhost:3000/?impersonationToken=${data.token}`;
      if (newWindow) {
        newWindow.location.href = targetUrl;
      } else {
        window.location.href = targetUrl;
      }
    } catch (err) {
      if (newWindow) newWindow.close();
      console.error('Error logging in as SOC Manager:', err);
      alert(err.response?.data?.message || 'Failed to login as SOC Manager');
    } finally {
      setImpersonatingId('');
    }
  };

  // Full-page detail dashboard state
  const [selectedManagerId, setSelectedManagerId] = useState(null);
  const [detailData, setDetailData] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [drawerTab, setDrawerTab] = useState('overview');
  const [dashboardManagerId, setDashboardManagerId] = useState(null);
  const [chatManager, setChatManager] = useState(null);

  // Create Modal
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [createForm, setCreateForm] = useState({ name: '', email: '', temporaryPassword: '', companyIds: [], maxWorkload: 10 });
  const [createBusy, setCreateBusy] = useState(false);

  // Analyst invitation modal
  const [showAnalystModal, setShowAnalystModal] = useState(false);
  const [analystForm, setAnalystForm] = useState({ name: '', email: '', role: 'l1_analyst' });
  const [analystBusy, setAnalystBusy] = useState(false);

  // Bulk Company Modal
  const [bulkAssignModal, setBulkAssignModal] = useState(null);
  const [bulkCompanyIds, setBulkCompanyIds] = useState([]);
  const [bulkBusy, setBulkBusy] = useState(false);
  const [operationsManager, setOperationsManager] = useState(null);
  const [operationsBusy, setOperationsBusy] = useState(false);
  const [operationsForm, setOperationsForm] = useState({
    maxWorkload: 10, companyId: '', name: 'Day Shift', startTime: '09:00',
    endTime: '18:00', timezone: 'Asia/Kolkata', weekdays: [1, 2, 3, 4, 5],
  });

  const openOperations = (manager) => {
    const shift = manager.currentShift || {};
    setOperationsManager(manager);
    setOperationsForm({
      maxWorkload: manager.workload?.maxLimit || 10,
      companyId: manager.assignedCompanies?.[0]?._id || '',
      name: shift.name || 'Day Shift',
      startTime: shift.startTime || '09:00',
      endTime: shift.endTime || '18:00',
      timezone: shift.timezone || 'Asia/Kolkata',
      weekdays: shift.weekdays?.length ? shift.weekdays : [1, 2, 3, 4, 5],
    });
  };

  const handleOperationsSubmit = async (e) => {
    e.preventDefault();
    setOperationsBusy(true);
    try {
      await api.put(`/super-admin/soc-managers/${operationsManager._id}/operations`, {
        maxWorkload: Number(operationsForm.maxWorkload),
        shift: {
          companyId: operationsForm.companyId, name: operationsForm.name,
          startTime: operationsForm.startTime, endTime: operationsForm.endTime,
          timezone: operationsForm.timezone, weekdays: operationsForm.weekdays,
        },
      });
      setNotice({ type:'success', text:`Shift and workload updated for ${operationsManager.name}.` });
      setOperationsManager(null);
      loadTable(); loadMetrics();
    } catch (e) {
      setNotice({ type:'error', text:e.response?.data?.message || 'Failed to update manager controls' });
    } finally { setOperationsBusy(false); }
  };

  const loadMetrics = async () => {
    try {
      const res = await api.get('/super-admin/soc-managers/metrics');
      setMetrics(res.data || {});
    } catch (e) {
      console.error('Metrics fetch error:', e);
    }
  };

  const loadTable = async () => {
    setLoading(true);
    try {
      const res = await api.get('/super-admin/soc-managers', {
        params: { page, limit, search, status: statusFilter }
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
      const res = await api.get('/super-admin/direct-companies');
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

  const loadManagerDetail = async (id) => {
    setSelectedManagerId(id);
    setDetailLoading(true);
    setDrawerTab('overview');
    try {
      const res = await api.get(`/super-admin/soc-managers/${id}`);
      setDetailData(res.data);
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to inspect SOC Manager' });
    } finally {
      setDetailLoading(false);
    }
  };

  const handleSuspend = async (mgr) => {
    const reason = prompt(`Enter suspension reason for SOC Manager ${mgr.name}:`);
    if (!reason) return;
    try {
      await api.post(`/super-admin/soc-managers/${mgr._id}/suspend`, { reason });
      setNotice({ type: 'success', text: `SOC Manager ${mgr.name} suspended successfully.` });
      loadTable(); loadMetrics();
      if (selectedManagerId === mgr._id) loadManagerDetail(mgr._id);
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Suspension failed' });
    }
  };

  const handleReactivate = async (mgr) => {
    try {
      await api.post(`/super-admin/soc-managers/${mgr._id}/reactivate`);
      setNotice({ type: 'success', text: `SOC Manager ${mgr.name} reactivated.` });
      loadTable(); loadMetrics();
      if (selectedManagerId === mgr._id) loadManagerDetail(mgr._id);
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Reactivation failed' });
    }
  };

  const handleRevokeSessions = async (mgr) => {
    if (!confirm(`Revoke all active login sessions for ${mgr.name}?`)) return;
    try {
      await api.post(`/super-admin/soc-managers/${mgr._id}/revoke-sessions`);
      setNotice({ type: 'success', text: `All active sessions revoked for ${mgr.name}.` });
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Session revocation failed' });
    }
  };

  const handleCreateSubmit = async (e) => {
    e.preventDefault();
    setCreateBusy(true);
    setNotice({ type: '', text: '' });
    try {
      await api.post('/super-admin/soc-managers', createForm);
      setNotice({ type: 'success', text: `SOC Manager invitation sent to ${createForm.email}` });
      setShowCreateModal(false);
      setCreateForm({ name: '', email: '', temporaryPassword: '', companyIds: [], maxWorkload: 10 });
      loadTable(); loadMetrics();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to create SOC Manager' });
    } finally {
      setCreateBusy(false);
    }
  };

  const handleAnalystInvite = async (e) => {
    e.preventDefault();
    const companyId = companies[0]?._id;
    if (!companyId) {
      setNotice({ type: 'error', text: 'No company scope is available for this invitation.' });
      return;
    }
    setAnalystBusy(true);
    setNotice({ type: '', text: '' });
    try {
      await api.post('/soc/invitations', {
        name: analystForm.name.trim(),
        email: analystForm.email.trim().toLowerCase(),
        role: analystForm.role,
        companyIds: [companyId],
      });
      setNotice({ type: 'success', text: `Analyst invitation sent to ${analystForm.email}` });
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
      await api.post(`/super-admin/soc-managers/${bulkAssignModal._id}/companies/bulk`, {
        companyIds: bulkCompanyIds
      });
      setNotice({ type: 'success', text: `Companies assigned to ${bulkAssignModal.name}.` });
      setBulkAssignModal(null);
      setBulkCompanyIds([]);
      loadTable();
      if (selectedManagerId === bulkAssignModal._id) loadManagerDetail(bulkAssignModal._id);
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Company assignment failed' });
    } finally {
      setBulkBusy(false);
    }
  };

  if (dashboardManagerId) {
    const manager = state.items?.find(item => item._id === dashboardManagerId);
    return (
      <>
        <SOCManagerOperationsDashboard
          managerId={dashboardManagerId}
          initialManager={manager}
          onBack={() => setDashboardManagerId(null)}
          onLogin={(event, selectedManager) => handleImpersonate(event, selectedManager._id)}
          onChat={selectedManager => setChatManager(selectedManager)}
          impersonating={impersonatingId === dashboardManagerId}
        />
        {chatManager && <SocChatModal contact={chatManager} onClose={() => setChatManager(null)} />}
      </>
    );
  }

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

      {/* ── SOC Manager account and assignment KPIs ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, marginBottom: 20 }}>
        <MetricCard label="Total Managers" value={metrics.total || 0} onClick={() => setStatusFilter('all')} color="#67e8f9" icon="🧑‍💼" />
        <MetricCard label="Active" value={metrics.active || 0} onClick={() => setStatusFilter('active')} color="#34d399" icon="🟢" />
        <MetricCard label="Working Now" value={metrics.onShift || 0} onClick={() => {}} color="#34d399" icon="⏱️" />
        <MetricCard label="Not Working" value={metrics.offShift || 0} onClick={() => {}} color="#94a3b8" icon="🌙" />
        <MetricCard label="Assigned" value={metrics.assigned || 0} onClick={() => {}} color="#38bdf8" icon="🏢" />
        <MetricCard label="Unassigned" value={metrics.unassigned || 0} onClick={() => {}} color="#e9d5ff" icon="📭" />
        <MetricCard label="Pending Invites" value={metrics.pendingInvitations || 0} onClick={() => setStatusFilter('invited')} color="#facc15" icon="📩" />
        <MetricCard label="Expired Invites" value={metrics.expiredInvitations || 0} onClick={() => setStatusFilter('expired')} color="#f87171" icon="⏳" />
        <MetricCard label="Suspended" value={metrics.suspended || 0} onClick={() => setStatusFilter('suspended')} color="#fb923c" icon="⛔" />
        <MetricCard label="Disabled" value={metrics.disabled || 0} onClick={() => {}} color="#94a3b8" icon="🔒" />
      </div>

      {notice.text && (
        <div style={{ padding: '12px 16px', borderRadius: 8, marginBottom: 16, color: notice.type === 'error' ? '#fca5a5' : '#34d399', background: notice.type === 'error' ? 'rgba(53, 13, 22, 0.9)' : 'rgba(5, 46, 43, 0.9)', border: `1px solid ${notice.type === 'error' ? '#7f1d1d' : '#059669'}`, fontSize: 13, display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>{notice.type === 'error' ? '⚠️' : '✅'}</span> {notice.text}
        </div>
      )}

      {/* ── Toolbar: Search & Multi-Filters ── */}
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
          {/* View Mode Toggle */}
          <div style={{ display: 'flex', background: '#091525', borderRadius: 8, padding: 3, border: '1px solid #1e3a5f' }}>
            <button
              onClick={() => setViewMode('cards')}
              style={{
                border: 0,
                borderRadius: 6,
                padding: '6px 12px',
                background: viewMode === 'cards' ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' : 'transparent',
                color: viewMode === 'cards' ? '#fff' : '#94a3b8',
                fontWeight: 700,
                cursor: 'pointer',
                fontSize: 12
              }}
            >
              🎴 Cards Grid
            </button>
            <button
              onClick={() => setViewMode('table')}
              style={{
                border: 0,
                borderRadius: 6,
                padding: '6px 12px',
                background: viewMode === 'table' ? 'linear-gradient(135deg, #0284c7 0%, #0369a1 100%)' : 'transparent',
                color: viewMode === 'table' ? '#fff' : '#94a3b8',
                fontWeight: 700,
                cursor: 'pointer',
                fontSize: 12
              }}
            >
              ☰ Table View
            </button>
          </div>

          <small style={{ color: '#94a3b8', fontSize: 12 }}>Per Page:</small>
          <select value={limit} onChange={e => { setLimit(Number(e.target.value)); setPage(1); }} style={{ ...input, width: 'auto' }}>
            <option value={10}>10</option>
            <option value={15}>15</option>
            <option value={25}>25</option>
            <option value={50}>50</option>
          </select>
        </div>
      </div>

      {/* ── SOC Managers Grid / Table ── */}
      {loading ? (
        <div style={{ ...panel, padding: 40, color: '#94a3b8', textAlign: 'center', fontSize: 13 }}>Loading SOC Manager Records…</div>
      ) : !state.items || state.items.length === 0 ? (
        <div style={{ ...panel, padding: 40, color: '#94a3b8', textAlign: 'center', fontSize: 13 }}>No SOC Managers found matching filter.</div>
      ) : viewMode === 'cards' ? (
        /* ── Cards Grid View ── */
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 16 }}>
          {state.items.map(mgr => {
            const initial = (mgr.name || mgr.email || 'M').charAt(0).toUpperCase();
            const pct = mgr.workload?.percentage || 0;
            const statusBadge = mgr.accountStatus === 'suspended'
              ? { bg: 'rgba(127, 29, 29, 0.4)', text: '#fca5a5', border: '#991b1b', label: '⛔ SUSPENDED' }
              : mgr.accountStatus === 'invited'
              ? { bg: 'rgba(113, 63, 18, 0.4)', text: '#fde047', border: '#854d0e', label: '📩 INVITED' }
              : { bg: 'rgba(6, 78, 59, 0.4)', text: '#34d399', border: '#065f46', label: '🟢 ACTIVE' };

            return (
              <div
                key={mgr._id}
                onClick={() => setDashboardManagerId(mgr._id)}
                style={{
                  background: 'linear-gradient(145deg, #0b1727 0%, #07111e 100%)',
                  border: '1px solid #1e3a5f',
                  borderRadius: 16,
                  padding: 18,
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  justify: 'space-between',
                  position: 'relative',
                  transition: 'all 0.2s ease',
                  boxShadow: '0 8px 24px rgba(0,0,0,0.3)'
                }}
              >
                <div>
                  {/* Card Header */}
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, marginBottom: 16 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div style={{
                        width: 44,
                        height: 44,
                        borderRadius: 12,
                        background: 'linear-gradient(135deg, #1e3a5f 0%, #0f2b48 100%)',
                        border: '1px solid #2563eb',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        color: '#67e8f9',
                        fontWeight: 900,
                        fontSize: 16,
                        boxShadow: '0 4px 12px rgba(0,0,0,0.3)'
                      }}>
                        {initial}
                      </div>
                      <div>
                        <h3 style={{ fontSize: 16, color: '#f8fafc', margin: '0 0 2px 0', fontWeight: 800, lineHeight: 1.2 }}>
                          {mgr.name}
                        </h3>
                        <div style={{ fontSize: 11, color: '#64748b', display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span>✉️</span> {mgr.email}
                        </div>
                      </div>
                    </div>

                    <span style={{
                      background: statusBadge.bg,
                      color: statusBadge.text,
                      border: `1px solid ${statusBadge.border}`,
                      padding: '3px 9px',
                      borderRadius: 20,
                      fontSize: 10,
                      fontWeight: 800,
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 5,
                      whiteSpace: 'nowrap'
                    }}>
                      {statusBadge.label}
                    </span>
                  </div>

                  <div style={{ marginBottom: 12 }}>
                    <span style={badgeStyle(
                      mgr.shiftStatus === 'on_shift' ? 'rgba(6, 78, 59, 0.45)' : 'rgba(51, 65, 85, 0.45)',
                      mgr.shiftStatus === 'on_shift' ? '#34d399' : '#94a3b8',
                      mgr.shiftStatus === 'on_shift' ? '#065f46' : '#475569'
                    )}>
                      {mgr.shiftStatus === 'on_shift'
                        ? `🟢 WORKING · ${mgr.currentShift?.name || 'Active shift'}`
                        : `🌙 NOT WORKING${mgr.assignedShiftsCount ? ' · Outside shift time' : ' · No shift assigned'}`}
                    </span>
                    {mgr.currentShift && (
                      <div style={{ color:'#94a3b8', fontSize:10, marginTop:6 }}>
                        {mgr.currentShift.startTime}–{mgr.currentShift.endTime} · {mgr.currentShift.timezone}
                      </div>
                    )}
                  </div>

                  {/* Card Grid Details */}
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: 10,
                    padding: 12,
                    borderRadius: 12,
                    background: 'rgba(7, 17, 31, 0.7)',
                    border: '1px solid #1e293b',
                    marginBottom: 16
                  }}>
                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Company Scope</div>
                      <div style={{ fontSize: 12, color: '#38bdf8', fontWeight: 800, marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                        🏢 {mgr.assignedCompaniesCount || 0} Companies
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Managed Analysts</div>
                      <div style={{ fontSize: 12, color: '#c4b5fd', fontWeight: 800, marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                        👥 {mgr.analystCounts?.total || 0} Analysts
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Active Alerts</div>
                      <div style={{ fontSize: 11, color: mgr.workload?.open ? '#f87171' : '#34d399', fontWeight: 800, marginTop: 2, display: 'flex', alignItems: 'center', gap: 4 }}>
                        {mgr.workload?.open ? `⚡ ${mgr.workload.open} Open` : '🟢 0 Alerts'}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Manager ID</div>
                      <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 700, marginTop: 2 }}>
                        🆔 {mgr._id?.slice(-6)}
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Shift Assignment</div>
                      <div style={{ fontSize: 11, color: mgr.assignedShiftsCount ? '#38bdf8' : '#94a3b8', fontWeight: 800, marginTop: 2 }}>
                        ⏱️ {mgr.assignedShiftsCount || 0} shift{mgr.assignedShiftsCount === 1 ? '' : 's'} assigned
                      </div>
                    </div>

                    <div>
                      <div style={{ fontSize: 10, color: '#64748b', textTransform: 'uppercase', fontWeight: 700 }}>Work Status</div>
                      <div style={{ fontSize: 11, color: mgr.shiftStatus === 'on_shift' ? '#34d399' : '#94a3b8', fontWeight: 800, marginTop: 2 }}>
                        {mgr.shiftStatus === 'on_shift' ? '● WORKING NOW' : '○ NOT WORKING'}
                      </div>
                    </div>
                  </div>

                  {/* Workload Capacity Bar */}
                  <div style={{ marginBottom: 16 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#94a3b8', fontWeight: 700, marginBottom: 4 }}>
                      <span>Workload Capacity</span>
                      <span style={{ color: pct > 80 ? '#f87171' : pct > 50 ? '#facc15' : '#34d399' }}>
                        {pct}% Capacity
                      </span>
                    </div>
                    <div style={{ width: '100%', height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min(100, Math.max(5, pct))}%`,
                        height: '100%',
                        background: pct > 80 ? '#ef4444' : pct > 50 ? '#facc15' : 'linear-gradient(90deg, #10b981, #38bdf8)',
                        borderRadius: 3
                      }} />
                    </div>
                  </div>
                </div>

                {/* Card Action Buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 8 }}>
                    <button
                      onClick={(e) => handleImpersonate(e, mgr._id)}
                      disabled={impersonatingId === mgr._id}
                      style={{
                        padding: '9px 10px',
                        borderRadius: 10,
                        background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                        border: '1px solid #34d399',
                        color: '#ffffff',
                        fontWeight: 800,
                        fontSize: 11,
                        cursor: 'pointer',
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        gap: 4
                      }}
                    >
                      🔑 {impersonatingId === mgr._id ? 'Logging in...' : 'Login as Manager'}
                    </button>

                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6 }}>
                    <button
                      onClick={(e) => { e.stopPropagation(); openOperations(mgr); }}
                      style={{ ...button, padding: '6px 8px', background: '#854d0e', fontSize: 10, justifyContent: 'center' }}
                    >
                      ⏱️ Shift & Load
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); setChatManager(mgr); }}
                      style={{ ...button, padding: '6px 8px', background: '#0f766e', fontSize: 10, justifyContent: 'center' }}
                    >
                      💬 Chat
                    </button>

                    <button
                      onClick={(e) => { e.stopPropagation(); setBulkAssignModal(mgr); setBulkCompanyIds(mgr.assignedCompanies?.map(c => c._id) || []); }}
                      style={{ ...button, padding: '6px 8px', background: '#091d36', border: '1px solid #1d4ed8', color: '#60a5fa', fontSize: 10, justifyContent: 'center' }}
                    >
                      🏢 Scope
                    </button>

                    {mgr.accountStatus === 'suspended' ? (
                      <button
                        onClick={(e) => { e.stopPropagation(); handleReactivate(mgr); }}
                        style={{ ...button, padding: '6px 8px', background: '#166534', fontSize: 10, justifyContent: 'center' }}
                      >
                        Reactivate
                      </button>
                    ) : (
                      <button
                        onClick={(e) => { e.stopPropagation(); handleSuspend(mgr); }}
                        style={{ ...button, padding: '6px 8px', background: '#7f1d1d', fontSize: 10, justifyContent: 'center' }}
                      >
                        Suspend
                      </button>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        /* ── Table View ── */
        <div style={{ ...panel, padding: 0, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: 'linear-gradient(180deg, #13243c 0%, #0d192b 100%)', color: '#7dd3fc', textAlign: 'left', borderBottom: '1px solid #1e3a5f' }}>
                {['SOC Manager', 'Registered Email', 'Company Scope', 'Managed Analysts', 'Active Alerts', 'Workload Bar', 'Shift', 'Status', 'Actions'].map(x => (
                  <th key={x} style={{ padding: '14px 16px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5, fontSize: 11 }}>{x}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.items.map(mgr => {
                const initial = (mgr.name || mgr.email || 'M').charAt(0).toUpperCase();
                const pct = mgr.workload?.percentage || 0;
                return (
                  <tr key={mgr._id} style={{ borderTop: '1px solid #1a2f4c', transition: 'background 0.15s' }}>
                    <td onClick={() => setDashboardManagerId(mgr._id)} title="Open manager dashboard" style={{ padding: '12px 16px', cursor:'pointer' }}>
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
                        <div style={{ background: pct > 80 ? 'linear-gradient(90deg, #f87171, #ef4444)' : pct > 50 ? 'linear-gradient(90deg, #facc15, #eab308)' : 'linear-gradient(90deg, #34d399, #10b981)', height: '100%', width: `${pct}%`, transition: 'width 0.3s' }} />
                      </div>
                    </td>
                    <td style={{ padding: '12px 16px' }}>
                      <span style={badgeStyle(
                        mgr.shiftStatus === 'on_shift' ? 'rgba(6, 78, 59, 0.45)' : 'rgba(51, 65, 85, 0.45)',
                        mgr.shiftStatus === 'on_shift' ? '#34d399' : '#94a3b8'
                      )}>
                        {mgr.shiftStatus === 'on_shift' ? '🟢 WORKING' : '🌙 NOT WORKING'}
                      </span>
                      {mgr.currentShift && (
                        <small style={{ color:'#64748b', display:'block', marginTop:4 }}>
                          {mgr.currentShift.name} · {mgr.currentShift.startTime}–{mgr.currentShift.endTime}
                        </small>
                      )}
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
                        <button style={{ ...button, padding: '5px 10px', background:'#854d0e', fontSize:11 }} onClick={() => openOperations(mgr)}>
                          ⏱️ Shift & Load
                        </button>
                        <button
                          style={{ ...button, padding: '5px 10px', background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)', fontSize: 11 }}
                          onClick={(e) => handleImpersonate(e, mgr._id)}
                          disabled={impersonatingId === mgr._id}
                        >
                          🔑 Login
                        </button>
                        <button style={{ ...button, padding: '5px 10px', background: '#0f766e', fontSize: 11 }} onClick={() => setChatManager(mgr)}>
                          💬 Chat
                        </button>
                        <button style={{ ...button, padding: '5px 10px', background: '#091d36', border: '1px solid #1d4ed8', color: '#60a5fa', fontSize: 11 }} onClick={() => { setBulkAssignModal(mgr); setBulkCompanyIds(mgr.assignedCompanies?.map(c => c._id) || []); }}>
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

      {/* ── (legacy drawer removed – now using full-page SOCManagerDashboard) ── */}
      {false && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 300, background: 'rgba(2, 6, 23, 0.75)', backdropFilter: 'blur(6px)', display: 'flex', justifyContent: 'flex-end', animation: 'fadeIn 0.2s' }}>
          <div style={{ width: 'min(720px, 92vw)', background: '#07111e', borderLeft: '1px solid #1e3a5f', padding: '24px 28px', height: '100%', overflowY: 'auto', boxSizing: 'border-box', boxShadow: '-12px 0 32px rgba(0,0,0,0.6)' }}>
            
            {/* Drawer Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', borderBottom: '1px solid #1a2f4c', paddingBottom: 18, marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                <div style={{ width: 48, height: 48, borderRadius: 12, background: 'linear-gradient(135deg, #1d4ed8 0%, #0284c7 100%)', color: '#fff', display: 'grid', placeItems: 'center', fontSize: 20, fontWeight: 900, boxShadow: '0 0 16px rgba(37,99,235,0.4)' }}>
                  {(detailData?.manager?.name || 'S').charAt(0).toUpperCase()}
                </div>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <h3 style={{ margin: 0, color: '#f8fafc', fontSize: 20, fontWeight: 800 }}>{detailData?.manager?.name || 'SOC Manager Details'}</h3>
                    <span style={badgeStyle('#0f2b48', '#38bdf8', '#1d4ed8')}>SOC Manager</span>
                  </div>
                  <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 3, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>{detailData?.manager?.email}</span>
                    <span style={{ color: '#34d399', fontSize: 11 }}>● Online</span>
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                {detailData?.manager && (
                  <button style={{ ...button, padding: '6px 12px', background: '#0f766e', fontSize: 11 }} onClick={() => setChatManager(detailData.manager)}>💬 Chat</button>
                )}
                {detailData?.manager && (
                  detailData.manager.accountStatus === 'suspended' ? (
                    <button style={{ ...button, padding: '6px 12px', background: '#166534', fontSize: 11 }} onClick={() => handleReactivate(detailData.manager)}>Reactivate</button>
                  ) : (
                    <button style={{ ...button, padding: '6px 12px', background: '#7f1d1d', fontSize: 11 }} onClick={() => handleSuspend(detailData.manager)}>Suspend</button>
                  )
                )}
                <button onClick={() => setSelectedManagerId(null)} style={{ ...button, background: '#1e293b', border: '1px solid #334155', padding: '6px 12px', fontSize: 12 }}>
                  ✕ Close
                </button>
              </div>
            </div>

            {detailLoading ? (
              <div style={{ color: '#94a3b8', padding: 40, textAlign: 'center', fontSize: 13 }}>Fetching full SOC Manager telemetry & audit history…</div>
            ) : detailData && (
              <div>
                {/* Executive Tabs Bar */}
                <div style={{ display: 'flex', gap: 8, marginBottom: 20, borderBottom: '1px solid #1a2f4c', paddingBottom: 10, overflowX: 'auto' }}>
                  {[
                    { id: 'overview', label: '📊 Overview' },
                    { id: 'companies', label: `🏢 Company Scope (${detailData.assignedCompanies?.length || 0})` },
                    { id: 'analysts', label: `👥 Managed Analysts (${detailData.analysts?.length || 0})` },
                    { id: 'audit', label: '🛡️ Audit & Security Trail' }
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => setDrawerTab(tab.id)}
                      style={{
                        ...button,
                        background: drawerTab === tab.id ? 'linear-gradient(135deg, #1d4ed8, #2563eb)' : '#0d1d33',
                        border: `1px solid ${drawerTab === tab.id ? '#3b82f6' : '#1e3a5f'}`,
                        color: drawerTab === tab.id ? '#fff' : '#94a3b8',
                        padding: '8px 14px',
                        fontSize: 12
                      }}
                    >
                      {tab.label}
                    </button>
                  ))}
                </div>

                {/* Tab 1: OVERVIEW */}
                {drawerTab === 'overview' && (
                  <div style={{ display: 'grid', gap: 16 }}>
                    
                    {/* 4 Metric Cards Grid */}
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
                      <div style={{ ...panel, background: '#0c1a2e', border: '1px solid #1e3a5f' }}>
                        <small style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Account Status</small>
                        <div style={{ marginTop: 6 }}>
                          {detailData.manager?.accountStatus === 'suspended' ? (
                            <span style={badgeStyle('rgba(127, 29, 29, 0.5)', '#fca5a5', '#991b1b')}>⛔ SUSPENDED</span>
                          ) : (
                            <span style={badgeStyle('rgba(6, 78, 59, 0.5)', '#34d399', '#065f46')}>🟢 ACTIVE & OPERATIONAL</span>
                          )}
                        </div>
                      </div>

                      <div style={{ ...panel, background: '#0c1a2e', border: '1px solid #1e3a5f' }}>
                        <small style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Workload Capacity</small>
                        <div style={{ color: '#38bdf8', fontSize: 18, fontWeight: 900, marginTop: 4 }}>
                          {detailData.activeAlerts?.length || 0} / {detailData.manager?.maxWorkload || 10} Max Capacity
                        </div>
                      </div>

                      <div style={{ ...panel, background: '#0c1a2e', border: '1px solid #1e3a5f' }}>
                        <small style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Direct Company Scope</small>
                        <div style={{ color: '#67e8f9', fontSize: 18, fontWeight: 900, marginTop: 4 }}>
                          {detailData.assignedCompanies?.length || 0} Superadmin Companies
                        </div>
                      </div>

                      <div style={{ ...panel, background: '#0c1a2e', border: '1px solid #1e3a5f' }}>
                        <small style={{ color: '#64748b', fontSize: 11, fontWeight: 700, textTransform: 'uppercase' }}>Managed Analyst Team</small>
                        <div style={{ color: '#c4b5fd', fontSize: 18, fontWeight: 900, marginTop: 4 }}>
                          {detailData.analysts?.length || 0} Analysts Managed
                        </div>
                      </div>
                    </div>

                    {/* Full Account Details Box */}
                    <div style={panel}>
                      <h4 style={{ margin: '0 0 14px', color: '#7dd3fc', fontSize: 14, textTransform: 'uppercase', letterSpacing: 0.5 }}>Account & Governance Metadata</h4>
                      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14, fontSize: 12 }}>
                        <div>
                          <small style={{ color: '#64748b', display: 'block' }}>Official Registered Email</small>
                          <b style={{ color: '#f8fafc' }}>{detailData.manager?.email}</b>
                          <small style={{ color: '#38bdf8', display: 'block', marginTop: 2 }}>🔒 Read-only enforcement</small>
                        </div>
                        <div>
                          <small style={{ color: '#64748b', display: 'block' }}>Platform Role</small>
                          <b style={{ color: '#67e8f9' }}>SOC Manager (`soc_manager`)</b>
                        </div>
                        <div>
                          <small style={{ color: '#64748b', display: 'block' }}>Active Sessions Control</small>
                          <button style={{ ...button, padding: '4px 10px', background: '#7f1d1d', marginTop: 4, fontSize: 11 }} onClick={() => handleRevokeSessions(detailData.manager)}>
                            Revoke Active Sessions
                          </button>
                        </div>
                        <div>
                          <small style={{ color: '#64748b', display: 'block' }}>Account Created</small>
                          <b style={{ color: '#cbd5e1' }}>{new Date(detailData.manager?.createdAt).toLocaleString()}</b>
                        </div>
                      </div>
                    </div>

                  </div>
                )}

                {/* Tab 2: ASSIGNED COMPANIES */}
                {drawerTab === 'companies' && (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <span style={{ color: '#7dd3fc', fontSize: 13, fontWeight: 700 }}>Direct Superadmin Companies in Scope</span>
                      <button style={{ ...button, padding: '5px 10px', fontSize: 11 }} onClick={() => { setBulkAssignModal(detailData.manager); setBulkCompanyIds(detailData.assignedCompanies?.map(c => c._id) || []); }}>
                        + Modify Scope
                      </button>
                    </div>
                    {detailData.assignedCompanies?.length === 0 ? (
                      <div style={{ ...panel, textAlign: 'center', color: '#94a3b8', padding: 24 }}>No direct Superadmin companies assigned yet.</div>
                    ) : (
                      detailData.assignedCompanies?.map(c => (
                        <div key={c._id} style={{ ...panel, background: '#091627', padding: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center', border: '1px solid #1e3a5f' }}>
                          <div>
                            <b style={{ color: '#f8fafc', fontSize: 14 }}>{c.name}</b>
                            <small style={{ color: '#94a3b8', display: 'block', marginTop: 2 }}>Tenant ID: {c.tenantId || 'Main Tenant'}</small>
                          </div>
                          <span style={badgeStyle('#064e3b', '#34d399', '#065f46')}>ACTIVE SCOPE</span>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Tab 3: MANAGED ANALYSTS */}
                {drawerTab === 'analysts' && (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <span style={{ color: '#7dd3fc', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>Analysts Operating Under This Manager</span>
                    {detailData.analysts?.length === 0 ? (
                      <div style={{ ...panel, textAlign: 'center', color: '#94a3b8', padding: 24 }}>No analysts currently assigned under this scope.</div>
                    ) : (
                      detailData.analysts?.map(a => (
                        <div key={a._id} style={{ ...panel, background: '#091627', padding: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center', border: '1px solid #1e3a5f' }}>
                          <div>
                            <b style={{ color: '#f8fafc', fontSize: 13 }}>{a.name}</b>
                            <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 2 }}>{a.email}</div>
                          </div>
                          <span style={{ background: '#1e3a5f', color: '#93c5fd', border: '1px solid #2563eb', borderRadius: 999, padding: '4px 10px', fontSize: 11, fontWeight: 800, textTransform: 'uppercase' }}>
                            {a.role}
                          </span>
                        </div>
                      ))
                    )}
                  </div>
                )}

                {/* Tab 4: AUDIT & SECURITY LOGS */}
                {drawerTab === 'audit' && (
                  <div style={{ display: 'grid', gap: 10 }}>
                    <span style={{ color: '#7dd3fc', fontSize: 13, fontWeight: 700, marginBottom: 4 }}>Recent Audit Events & Security Trail</span>
                    {detailData.auditLogs?.length === 0 ? (
                      <div style={{ ...panel, textAlign: 'center', color: '#94a3b8', padding: 24 }}>No audit logs recorded for this account.</div>
                    ) : (
                      detailData.auditLogs?.map(log => (
                        <div key={log._id} style={{ ...panel, background: '#091627', padding: 12, fontSize: 12, border: '1px solid #1e3a5f' }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <b style={{ color: '#38bdf8' }}>{log.action}</b>
                            <span style={{ color: '#64748b', fontSize: 11 }}>{new Date(log.createdAt).toLocaleString()}</span>
                          </div>
                          {log.metadata?.reason && (
                            <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 2 }}>Reason: {log.metadata.reason}</div>
                          )}
                        </div>
                      ))
                    )}
                  </div>
                )}

              </div>
            )}
          </div>
        </div>
      )}

      {/* ── Create SOC Manager Modal ── */}
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
              <input
                type="password"
                placeholder="e.g. TempPass123! (optional)"
                style={input}
                value={createForm.temporaryPassword || ''}
                onChange={e => setCreateForm({ ...createForm, temporaryPassword: e.target.value })}
              />
            </label>

            <label style={{ display: 'block', marginBottom: 8 }}>
              <small style={{ color: '#7dd3fc', fontSize: 11, fontWeight: 700 }}>Assign Direct Superadmin Companies *</small>
            </label>
            <div style={{ maxHeight: 140, overflowY: 'auto', background: '#040d1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 18 }}>
              {companies.map(c => (
                <label key={c._id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#e2e8f0', marginBottom: 6, cursor: 'pointer' }}>
                  <input type="checkbox" checked={createForm.companyIds.includes(c._id)} onChange={e => setCreateForm({
                    ...createForm,
                    companyIds: e.target.checked ? [...createForm.companyIds, c._id] : createForm.companyIds.filter(id => id !== c._id)
                  })} />
                  <b>{c.name}</b> <small style={{ color: '#34d399', fontSize: 10 }}>(Direct Superadmin Company)</small>
                </label>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
              <button type="button" onClick={() => setShowCreateModal(false)} style={{ ...button, background: '#1e293b', border: '1px solid #334155' }}>Cancel</button>
              <button type="submit" disabled={createBusy || !createForm.companyIds.length} style={button}>{createBusy ? 'Sending…' : 'Send Invitation'}</button>
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
              <button type="submit" disabled={analystBusy || !companies.length} style={{ ...button, background: '#7c3aed' }}>{analystBusy ? 'Sending…' : 'Send Invitation'}</button>
            </div>
          </form>
        </div>
      )}

      {/* ── Bulk Assign Scope Modal ── */}
      {bulkAssignModal && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 400, background: 'rgba(2, 6, 23, 0.8)', backdropFilter: 'blur(6px)', display: 'grid', placeItems: 'center' }}>
          <form onSubmit={handleBulkAssignSubmit} style={{ ...panel, background: '#091728', border: '1px solid #2563eb', width: 'min(520px, 92vw)', padding: 26 }}>
            <h3 style={{ margin: '0 0 16px', color: '#f8fafc', fontSize: 18, fontWeight: 800 }}>Assign Direct Scope: {bulkAssignModal.name}</h3>
            <div style={{ maxHeight: 180, overflowY: 'auto', background: '#040d1a', border: '1px solid #1e3a5f', borderRadius: 8, padding: 10, marginBottom: 18 }}>
              {companies.map(c => (
                <label key={c._id} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#e2e8f0', marginBottom: 6, cursor: 'pointer' }}>
                  <input type="checkbox" checked={bulkCompanyIds.includes(c._id)} onChange={e => setBulkCompanyIds(
                    e.target.checked ? [...bulkCompanyIds, c._id] : bulkCompanyIds.filter(id => id !== c._id)
                  )} />
                  <b>{c.name}</b> <small style={{ color: '#34d399', fontSize: 10 }}>(Direct Superadmin Company)</small>
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
      {operationsManager && (
        <div style={{ position:'fixed', inset:0, zIndex:450, background:'rgba(2, 6, 23, 0.82)', backdropFilter:'blur(6px)', display:'grid', placeItems:'center' }}>
          <form onSubmit={handleOperationsSubmit} style={{ ...panel, background:'#091728', border:'1px solid #d97706', width:'min(600px, 94vw)', padding:26 }}>
            <h3 style={{ margin:'0 0 4px', color:'#f8fafc' }}>Shift & Workload Control</h3>
            <div style={{ color:'#fbbf24', fontSize:12, marginBottom:18 }}>{operationsManager.name}</div>
            {!operationsManager.assignedCompanies?.length && (
              <div style={{ color:'#fca5a5', background:'#2b1116', padding:10, borderRadius:7, marginBottom:14, fontSize:12 }}>
                Assign a company using Scope before assigning a shift.
              </div>
            )}
            <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
              <label><small style={{ color:'#94a3b8' }}>Company</small><select required style={input} value={operationsForm.companyId} onChange={e=>setOperationsForm(v=>({...v,companyId:e.target.value}))}><option value="">Select company</option>{operationsManager.assignedCompanies?.map(c=><option key={c._id} value={c._id}>{c.name}</option>)}</select></label>
              <label><small style={{ color:'#94a3b8' }}>Shift Name</small><input required style={input} value={operationsForm.name} onChange={e=>setOperationsForm(v=>({...v,name:e.target.value}))}/></label>
              <label><small style={{ color:'#94a3b8' }}>Timezone</small><select style={input} value={operationsForm.timezone} onChange={e=>setOperationsForm(v=>({...v,timezone:e.target.value}))}><option value="Asia/Kolkata">Asia/Kolkata</option><option value="UTC">UTC</option><option value="America/New_York">America/New_York</option><option value="Europe/London">Europe/London</option></select></label>
              <label><small style={{ color:'#94a3b8' }}>Start Time</small><input type="time" required style={input} value={operationsForm.startTime} onChange={e=>setOperationsForm(v=>({...v,startTime:e.target.value}))}/></label>
              <label><small style={{ color:'#94a3b8' }}>End Time</small><input type="time" required style={input} value={operationsForm.endTime} onChange={e=>setOperationsForm(v=>({...v,endTime:e.target.value}))}/></label>
            </div>
            <div style={{ marginTop:14 }}><small style={{ color:'#94a3b8' }}>Working Days</small><div style={{ display:'flex', gap:8, flexWrap:'wrap', marginTop:6 }}>{['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((day,index)=><label key={day} style={{ color:'#cbd5e1', fontSize:11 }}><input type="checkbox" checked={operationsForm.weekdays.includes(index)} onChange={e=>setOperationsForm(v=>({...v,weekdays:e.target.checked?[...v.weekdays,index]:v.weekdays.filter(d=>d!==index)}))}/> {day}</label>)}</div></div>
            <div style={{ display:'flex', justifyContent:'flex-end', gap:10, marginTop:20 }}>
              <button type="button" onClick={()=>setOperationsManager(null)} style={{ ...button, background:'#1e293b' }}>Cancel</button>
              <button type="submit" disabled={operationsBusy || !operationsManager.assignedCompanies?.length || !operationsForm.weekdays.length} style={{ ...button, background:'#b45309' }}>{operationsBusy?'Saving…':'Save Shift & Workload'}</button>
            </div>
          </form>
        </div>
      )}
      {chatManager && <SocChatModal contact={chatManager} onClose={() => setChatManager(null)} />}
    </div>
  );
}

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
