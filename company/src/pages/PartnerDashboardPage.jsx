import { useEffect, useMemo, useRef, useState } from 'react';
import { useLocation, useSearchParams, useParams, useNavigate, Link, Navigate } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';
import { useAuth } from '../context/AuthContext';
import Swal from 'sweetalert2';
import PartnerCompaniesSummary from '../components/PartnerCompaniesSummary';
import EnterpriseManagement from '../components/EnterpriseManagement';

const emptyRequest = {
  numberOfCompanies: '',
  numberOfAgents: '',
  proposedCommission: '',
};

export default function PartnerDashboardPage({ embedded = false, viewOverride = '', initialPlanData = null }) {
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const { companyId } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const loadRef = useRef(null);
  const loadSequence = useRef(0);
  const [companies, setCompanies] = useState([]);
  const [companiesLoaded, setCompaniesLoaded] = useState(false);
  const [summaryError, setSummaryError] = useState('');
  const [companiesError, setCompaniesError] = useState('');
  const [request, setRequest] = useState(emptyRequest);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [requestTab, setRequestTab] = useState('resource');
  const [showRequestForm, setShowRequestForm] = useState(false);

  // ── Invite Company ────────────────────────────────────
  const showInviteModal = searchParams.get('invite') === 'company';
  const [inviteForm, setInviteForm] = useState({ companyName: '', email: '', adminName: '', tempPassword: '' });
  const [inviting, setInviting] = useState(false);
  const [inviteMsg, setInviteMsg] = useState('');
  const [inviteSuccess, setInviteSuccess] = useState(false);

  const closeInviteModal = () => {
    setSearchParams(prev => { const next = new URLSearchParams(prev); next.delete('invite'); return next; });
    setInviteForm({ companyName: '', email: '', adminName: '', tempPassword: '' });
    setInviteMsg('');
    setInviteSuccess(false);
  };

  const sendInvite = async (e) => {
    e.preventDefault();
    const email = inviteForm.email.trim().toLowerCase();
    const companyName = inviteForm.companyName.trim();
    const adminName = inviteForm.adminName.trim();
    const tempPassword = inviteForm.tempPassword.trim();
    if (!email || !companyName) { setInviteMsg('Company name aur email required hain.'); return; }
    setInviting(true); setInviteMsg('');
    try {
      const { data } = await api.post('/partner/invite-company', { email, companyName, adminName, tempPassword });
      setInviteMsg(`✅ Invitation sent to ${email}. Registration link: ${data.registrationUrl || data.acceptUrl || ''}`);
      setInviteSuccess(true);
      setInviteForm({ companyName: '', email: '', adminName: '', tempPassword: '' });
    } catch (err) {
      setInviteMsg(`❌ ${err.response?.data?.message || 'Invitation send nahi ho payi.'}`);
      setInviteSuccess(false);
    } finally {
      setInviting(false);
    }
  };

  const view = viewOverride || (
    (location.pathname.includes('/partner/payment-control') || searchParams.get('view') === 'payment-control') ? 'payment-control' :
    (location.pathname.includes('/partner/revenue') || searchParams.get('view') === 'revenue') ? 'revenue' :
    (location.pathname.includes('partner-subscription') || location.pathname.includes('/partner/subscription')) ? 'subscription' :
    (location.pathname.includes('partner-resources') || location.pathname.includes('/partner/resources')) ? 'requests' :
    (location.pathname.includes('partner-company-support') || location.pathname.includes('/partner/company-support') || location.pathname.includes('/partner/support')) ? 'tenant-support' :
    (location.pathname.includes('partner-dashboard') || location.pathname.includes('/partner/dashboard')) ? 'dashboard' :
    ((location.pathname.includes('partner-companies') || location.pathname.includes('/partner/companies')) && !searchParams.get('invite')) ? 'companies' :
    'companies'
  );

  const load = async (cachedPlanData = null, forceRefresh = true) => {
    const sequence = ++loadSequence.current;
    setLoading(true);
    try {
      // If planData was pre-fetched by the gate, skip /payment/partner-plan call
      const planFetch = cachedPlanData
        ? Promise.resolve({ data: cachedPlanData })
        : api.get('/payment/partner-plan', { skipCache: forceRefresh });

      const [dashboardResult, planResult, companiesResult] = await Promise.allSettled([
        api.get('/partner/dashboard', { timeout: 8000, skipCache: forceRefresh }),
        planFetch,
        api.get('/partner/companies', { timeout: 8000, skipCache: forceRefresh }),
      ]);
      if (sequence !== loadSequence.current) return;
      const dashboardData = dashboardResult.status === 'fulfilled' ? dashboardResult.value.data : null;
      const planPartner = planResult.status === 'fulfilled' ? planResult.value.data?.partner : null;
      setSummaryError(dashboardResult.status === 'rejected'
        ? 'Could not refresh the partner summary. Any previous data is still shown. Use Sync to retry.'
        : dashboardData?.partial ? 'Some partner summary data is unavailable. Use Sync to retry.' : '');
      if (companiesResult.status === 'fulfilled' && Array.isArray(companiesResult.value.data)) {
        setCompanies(companiesResult.value.data);
        setCompaniesLoaded(true);
        setCompaniesError('');
      } else {
        setCompaniesError('Could not refresh companies. Any previous list is still shown. Use Sync to retry.');
      }
      if (dashboardResult.status === 'rejected' && !planPartner) throw dashboardResult.reason;
      setStats(prev => ({
        ...(dashboardData || prev || {}),
        partner: { ...(planPartner || {}), ...(dashboardData?.partner || prev?.partner || {}) },
      }));
    } catch (err) {
      if (sequence !== loadSequence.current) return;
      setSummaryError('Could not refresh the partner summary. Any previous data is still shown. Use Sync to retry.');
      setStats(prev => prev || { partner: { name: user?.name || 'Partner Admin' } });
    } finally {
      if (sequence === loadSequence.current) setLoading(false);
    }
  };
  loadRef.current = load;

  useEffect(() => { load(initialPlanData); return () => { loadSequence.current++; }; }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (user?.role !== 'partner_admin' || !user?.partnerId) return undefined;
    const socket = io(SOCKET_URL, socketOptions);
    let timer;
    let running = false;
    let queued = false;
    let disposed = false;
    const run = async () => {
      if (disposed) return;
      if (running) { queued = true; return; }
      running = true;
      await loadRef.current(null, true);
      running = false;
      if (queued && !disposed) { queued = false; schedule(); }
    };
    const schedule = () => { clearTimeout(timer); timer = setTimeout(run, 250); };
    const onConnect = () => { socket.emit('join:partner', user.partnerId); schedule(); };
    const onUpdate = event => { if (String(event?.partnerId) === String(user.partnerId)) schedule(); };
    const onVisible = () => { if (document.visibilityState === 'visible') schedule(); };
    socket.emit('join:partner', user.partnerId);
    socket.on('connect', onConnect);
    socket.on('partner:update', onUpdate);
    const disconnect = connectSocket(socket);
    const interval = setInterval(onVisible, 30000);
    window.addEventListener('focus', onVisible);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      disposed = true;
      clearTimeout(timer);
      clearInterval(interval);
      socket.off('connect', onConnect);
      socket.off('partner:update', onUpdate);
      window.removeEventListener('focus', onVisible);
      document.removeEventListener('visibilitychange', onVisible);
      disconnect();
    };
  }, [user?.role, user?.partnerId]);

  const submitRequest = async e => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    try {
      await api.post('/partner/resource-request', request);
      setRequest(emptyRequest);
      setShowRequestForm(false);
      setMessage('Resource request submitted. Status: Pending Approval');
      await load();
    } catch (err) {
      setMessage(err.response?.data?.message || 'Resource request submit nahi ho paya');
    } finally {
      setSaving(false);
    }
  };

  if (loading && !stats) return <div className="loading" role="status">Loading...</div>;

  const partner = stats?.partner || {};
  const resource = stats?.resourceRequest || {};
  const plan = partner.plan || {};
  const companyLimit = resource.status === 'approved' ? Number(resource.numberOfCompanies || 0) : 0;
  const agentLimit = resource.status === 'approved' ? Number(resource.numberOfAgents || 0) : 0;
  const totalCompanies = stats?.companies || 0;
  const totalAgents = stats?.totalAgents || 0;
  const paidRevenue = Number(stats?.paidRevenue || stats?.monthlyRevenue || 0);
  const pendingRevenue = Number(stats?.pendingRevenue || 0);
  const settlement = stats?.settlement || {};
  const requestRows = buildRequestRows(stats?.resourceRequestHistory || [], resource, partner);

  const summary = {
    totalCompanies,
    activeCompanies: stats?.activeCompanies || 0,
    totalAgents,
    activeAgents: stats?.activeAgents || 0,
    activePlans: stats?.activePlans || 0,
    expiringPlans: stats?.expiringPlans || 0,
    companyLimit,
    agentLimit,
    paidRevenue,
    pendingRevenue,
    totalCollection: Number(settlement.totalCollection ?? paidRevenue) || 0,
    platformCommission: Number(settlement.platformCommission || 0),
    partnerPayout: Number(settlement.partnerPayout || 0),
    payoutStatus: settlement.payoutStatus || 'pending',
    settlementDate: settlement.settlementDate || null,
    platformPayments: stats?.platformPayments || [],
  };

  return (
    <div style={embedded ? embeddedPage : view === 'dashboard' ? { minWidth: 0 } : page}>
      {/* ── Invite Company Modal — portal-level overlay ── */}
      {showInviteModal && (
        <div style={{ position:'fixed', inset:0, zIndex:9999, background:'rgba(5,10,30,0.82)', backdropFilter:'blur(8px)', display:'flex', alignItems:'center', justifyContent:'center', padding:20 }}
          onClick={(e) => { if (e.target === e.currentTarget) closeInviteModal(); }}>
          <div style={{ background:'linear-gradient(135deg,#0c1a2e 0%,#0f1e45 100%)', border:'1px solid rgba(99,102,241,0.35)', borderRadius:16, padding:'32px 36px', width:'100%', maxWidth:480, boxShadow:'0 24px 64px rgba(0,0,0,0.6)', position:'relative' }}>
            <button onClick={closeInviteModal} style={{ position:'absolute', top:16, right:18, background:'transparent', border:'none', color:'#94a3b8', fontSize:20, cursor:'pointer', lineHeight:1 }}>✕</button>
            <h2 style={{ margin:'0 0 6px', fontSize:20, fontWeight:900, color:'#e0f2fe', letterSpacing:-0.5 }}>+ Invite Company</h2>
            <p style={{ margin:'0 0 22px', fontSize:13, color:'#64748b' }}>Company ko invitation email bhejo. Registration ke baad automatically partner account se link ho jaayega.</p>
            <form onSubmit={sendInvite} style={{ display:'grid', gap:14 }}>
              <InviteField label="Company Name *" value={inviteForm.companyName} onChange={v => setInviteForm(p => ({ ...p, companyName: v }))} placeholder="e.g. Acme Corp Pvt Ltd" />
              <InviteField label="Company Admin Email *" type="email" value={inviteForm.email} onChange={v => setInviteForm(p => ({ ...p, email: v }))} placeholder="admin@acmecorp.com" />
              <InviteField label="Admin Name" value={inviteForm.adminName} onChange={v => setInviteForm(p => ({ ...p, adminName: v }))} placeholder="e.g. Rahul Sharma" />
              <InviteField label="Temporary Password" type="password" value={inviteForm.tempPassword} onChange={v => setInviteForm(p => ({ ...p, tempPassword: v }))} placeholder="Leave blank to auto-generate" />
              {inviteMsg && (
                <div style={{ fontSize:12, padding:'10px 14px', borderRadius:8, background: inviteSuccess ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)', color: inviteSuccess ? '#34d399' : '#f87171', border:`1px solid ${inviteSuccess ? 'rgba(52,211,153,0.3)' : 'rgba(248,113,113,0.3)'}`, wordBreak:'break-all' }}>
                  {inviteMsg}
                </div>
              )}
              <div style={{ display:'flex', gap:10, marginTop:4 }}>
                <button type="submit" disabled={inviting} style={{ flex:1, padding:'11px 0', borderRadius:9, border:'none', background:'linear-gradient(135deg,#4f46e5,#7c3aed)', color:'#fff', fontWeight:800, fontSize:14, cursor: inviting ? 'not-allowed' : 'pointer', opacity: inviting ? 0.7 : 1 }}>
                  {inviting ? 'Sending...' : '✉ Send Invitation'}
                </button>
                <button type="button" onClick={closeInviteModal} style={{ padding:'11px 18px', borderRadius:9, border:'1px solid rgba(99,102,241,0.3)', background:'transparent', color:'#94a3b8', fontWeight:700, fontSize:13, cursor:'pointer' }}>
                  Cancel
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {companyId ? (
        <PartnerCompanyDetailView companyId={companyId} />
      ) : (
        <>
          {message && <div style={liveNotice}>{message}</div>}
          {embedded && (summaryError || companiesError) && <div style={liveNotice} role="status">{summaryError || companiesError} <button type="button" onClick={() => load(null, true)}>Retry</button></div>}
          {view === 'dashboard' && (embedded
            ? <div style={embeddedDashboardShell}><DashboardView embedded partner={partner} companies={companies} summary={summary} setMessage={setMessage} /></div>
            : <PartnerCompaniesSummary partner={partner} companies={companies} companiesLoaded={companiesLoaded} loading={loading} error={summaryError} companiesError={companiesError} onRefresh={() => load(null, true)} />)}
          {view === 'revenue' && <RevenueView key={user?.partnerId} partnerId={user?.partnerId} companies={companies} companiesLoaded={companiesLoaded} companiesError={companiesError} onRefresh={() => load(null, true)} />}
          {view === 'payment-control' && <PaymentControlView partner={partner} summary={summary} companies={companies} onRefresh={load} setMessage={setMessage} />}
          {view === 'companies' && <CompaniesView companies={companies} partner={partner} summary={summary} />}
          {view === 'subscription' && <SubscriptionView embedded={embedded} partner={partner} summary={summary} requestRows={requestRows} onRefresh={load} />}
          {view === 'tenant-support' && <PartnerCompanySupportView partner={partner} user={user} />}
          {view === 'requests' && (
            <RequestsView
              embedded={embedded}
              requestTab={requestTab}
              setRequestTab={setRequestTab}
              requestRows={requestRows}
              showRequestForm={showRequestForm}
              setShowRequestForm={setShowRequestForm}
              request={request}
              setRequestField={(key, value) => setRequest(prev => ({ ...prev, [key]: value }))}
              submitRequest={submitRequest}
              saving={saving}
            />
          )}
        </>
      )}
    </div>
  );
}


// ── PartnerCompanyDetailView ──────────────────────────────────────────────────
function PartnerCompanyDetailView({ companyId }) {
  const navigate = useNavigate();
  const [company, setCompany] = useState(null);
  const [depts,   setDepts]   = useState([]);
  const [users,   setUsers]   = useState([]);
  const [alerts,  setAlerts]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [tab,     setTab]     = useState('dashboard');

  const [systems, setSystems] = useState([]);
  const [addSubs, setAddSubs] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [loadingSystems, setLoadingSystems] = useState(false);
  const [loadingAddSubs, setLoadingAddSubs] = useState(false);
  const [loadingAudit, setLoadingAudit] = useState(false);

  // Support Ticketing
  const [supportTickets, setSupportTickets] = useState([]);
  const [loadingSupport, setLoadingSupport] = useState(false);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyMessage, setReplyMessage] = useState('');
  const [replyBusy, setReplyBusy] = useState(false);

  // For Edit Payment Status
  const [editPaymentStatus, setEditPaymentStatus] = useState('paid');
  const [editAmountPaid, setEditAmountPaid] = useState('');
  const [editBillingCycle, setEditBillingCycle] = useState('monthly');
  const [editReason, setEditReason] = useState('');
  const [updatingPayment, setUpdatingPayment] = useState(false);
  const [updatingAutopay, setUpdatingAutopay] = useState(false);

  const loadSystems = () => {
    setLoadingSystems(true);
    api.get(`/partner/companies/${companyId}/systems`)
      .then(res => setSystems(res.data || []))
      .catch(() => {})
      .finally(() => setLoadingSystems(false));
  };

  const loadAddSubs = () => {
    setLoadingAddSubs(true);
    api.get(`/partner/companies/${companyId}/add-system-subscriptions`)
      .then(res => setAddSubs(res.data || []))
      .catch(() => {})
      .finally(() => setLoadingAddSubs(false));
  };

  const loadAuditLogs = () => {
    setLoadingAudit(true);
    api.get(`/partner/companies/${companyId}/audit?limit=200`)
      .then(res => setAuditLogs(res.data?.events || []))
      .catch(() => {})
      .finally(() => setLoadingAudit(false));
  };

  const loadSupportTickets = () => {
    setLoadingSupport(true);
    api.get(`/partner/company-support-tickets?companyId=${companyId}`)
      .then(res => {
        const tickets = res.data || [];
        setSupportTickets(tickets);
        if (selectedTicket) {
          const updated = tickets.find(t => t._id === selectedTicket._id);
          if (updated) setSelectedTicket(updated);
        }
      })
      .catch(() => {})
      .finally(() => setLoadingSupport(false));
  };

  const sendReply = async (e) => {
    e.preventDefault();
    if (!replyMessage.trim() || !selectedTicket) return;
    setReplyBusy(true);
    try {
      const { data } = await api.post(`/partner/company-support-tickets/${selectedTicket._id}/messages`, {
        message: replyMessage
      });
      setReplyMessage('');
      setSelectedTicket(data);
      loadSupportTickets();
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Reply send failed', 'error');
    } finally {
      setReplyBusy(false);
    }
  };

  const updateStatus = async (newStatus) => {
    if (!selectedTicket) return;
    try {
      const { data } = await api.patch(`/partner/company-support-tickets/${selectedTicket._id}/status`, {
        status: newStatus
      });
      setSelectedTicket(data);
      loadSupportTickets();
      Swal.fire('Success', `Ticket status updated to ${newStatus}`, 'success');
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Status update failed', 'error');
    }
  };

  const loadData = (silent = false) => {
    if (!silent) setLoading(true);
    Promise.all([
      api.get(`/partner/companies/${companyId}`),
      api.get(`/partner/companies/${companyId}/departments`),
      api.get(`/partner/companies/${companyId}/users`),
      api.get(`/partner/companies/${companyId}/alerts`),
    ])
    .then(([compRes, deptRes, userRes, alertRes]) => {
      setCompany(compRes.data);
      setDepts(deptRes.data || []);
      setUsers(userRes.data || []);
      setAlerts(alertRes.data || []);
      if (compRes.data) {
        setEditPaymentStatus(compRes.data.plan?.paymentStatus || 'paid');
        setEditAmountPaid(compRes.data.plan?.amountPaid || '');
        setEditBillingCycle(compRes.data.plan?.billingCycle || 'monthly');
      }
    })
    .catch(err => setError(err.response?.data?.message || 'Failed to load company'))
    .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadData(false);
  }, [companyId]);

  useEffect(() => {
    if (tab === 'agents') loadSystems();
    if (tab === 'requests') loadAddSubs();
    if (tab === 'activity') loadAuditLogs();
    if (tab === 'support') loadSupportTickets();
  }, [tab, companyId]);

  useEffect(() => {
    const socket = io(SOCKET_URL, socketOptions);
    socket.emit('join:company', companyId);

    const handleUpdate = () => {
      loadData(true);
      if (tab === 'agents') loadSystems();
      if (tab === 'requests') loadAddSubs();
      if (tab === 'activity') loadAuditLogs();
      if (tab === 'support') loadSupportTickets();
    };

    socket.on('company:update', handleUpdate);
    socket.on('department:update', handleUpdate);
    socket.on('user:update', handleUpdate);
    socket.on('alert:new', handleUpdate);
    socket.on('alert:updated', handleUpdate);
    socket.on('alert:deleted', handleUpdate);

    const handleSupportUpdate = () => {
      if (tab === 'support') loadSupportTickets();
    };
    socket.on('support:ticket_new', handleSupportUpdate);
    socket.on('support:message_new', handleSupportUpdate);
    socket.on('support:ticket_updated', handleSupportUpdate);

    const disconnectSocket = connectSocket(socket);
    return () => {
      socket.off('company:update', handleUpdate);
      socket.off('department:update', handleUpdate);
      socket.off('user:update', handleUpdate);
      socket.off('alert:new', handleUpdate);
      socket.off('alert:updated', handleUpdate);
      socket.off('alert:deleted', handleUpdate);
      socket.off('support:ticket_new', handleSupportUpdate);
      socket.off('support:message_new', handleSupportUpdate);
      socket.off('support:ticket_updated', handleSupportUpdate);
      disconnectSocket();
    };
  }, [companyId, tab]);

  const handleUpdatePayment = async (e) => {
    e.preventDefault();
    if (editPaymentStatus === 'paid' && !editAmountPaid) {
      Swal.fire('Error', 'Paid status ke liye amount Paid required hai', 'error');
      return;
    }
    setUpdatingPayment(true);
    try {
      const { data } = await api.patch(`/partner/companies/${companyId}/payment`, {
        paymentStatus: editPaymentStatus,
        amountPaid: Number(editAmountPaid),
        billingCycle: editBillingCycle,
        reason: editReason
      });
      if (data.success) {
        Swal.fire('Success', 'Payment status updated successfully', 'success');
        setCompany(data.company);
        setEditReason('');
      }
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Update failed', 'error');
    } finally {
      setUpdatingPayment(false);
    }
  };

  const handleToggleAutopay = async () => {
    const nextVal = !company.plan?.autoPay;
    setUpdatingAutopay(true);
    try {
      const { data } = await api.patch(`/partner/companies/${companyId}/autopay`, {
        enabled: nextVal
      });
      if (data.success) {
        Swal.fire('Success', `AutoPay ${nextVal ? 'enabled' : 'disabled'} successfully`, 'success');
        setCompany(data.company);
      }
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Toggle AutoPay failed', 'error');
    } finally {
      setUpdatingAutopay(false);
    }
  };

  if (loading) return <p style={{ color:'#a78bfa', fontSize:13 }}>Loading…</p>;
  if (error)   return <p style={{ color:'#fca5a5', fontSize:13 }}>{error}</p>;
  if (!company) return <p style={{ color:'#fca5a5', fontSize:13 }}>Company not found.</p>;

  const localMetricGrid = { display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(185px, 1fr))', gap:14, marginBottom:18 };
  const localTabsWrap = { display:'flex', gap:14, flexWrap:'wrap', borderBottom:'1px solid #1e3a5f', marginBottom:16 };
  const localTabButton = active => ({ border:'none', borderBottom:`3px solid ${active ? '#3b82f6' : 'transparent'}`, background:'transparent', color:active ? '#e0f2fe' : '#94a3b8', padding:'10px 0', cursor:'pointer', fontSize:13, fontWeight:900 });

  return (
    <div>
      {/* Top Bar */}
      <div style={{ display:'flex', justifyContent:'space-between', gap:18, alignItems:'flex-start', marginBottom:18 }}>
        <div>
          <button type="button" onClick={() => navigate('/partner/companies')} style={{ border:'none', background:'transparent', color:'#93c5fd', fontSize:13, fontWeight:900, cursor:'pointer', padding:0, marginBottom:8 }}>
            ← Back to Companies
          </button>
          <h2 style={{ fontSize:24, color:'#e0f2fe', margin:'0 0 5px', fontWeight:950 }}>🏢 {company.name}</h2>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', color:'#94a3b8', fontSize:13, marginTop:3 }}>
            <span>{company.email}</span>
            <span>•</span>
            <span>Plan: {company.plan?.type || company.plan?.planName || 'none'} (Limit: {company.plan?.systemLimit ?? company.plan?.systemCount ?? 0})</span>
            <span>•</span>
            <span>Status: <b style={{ color: company.status === 'active' ? '#34d399' : '#ef4444' }}>{company.status}</b></span>
          </div>
          <div style={{ display:'flex', gap:8, flexWrap:'wrap', color:'#94a3b8', fontSize:13, marginTop:3 }}>
            Created On: {new Date(company.createdAt).toLocaleDateString()}
          </div>
        </div>

        <div style={{ display:'flex', gap:10, alignItems:'flex-start', flexWrap:'wrap', justifyContent:'flex-end' }}>
          <button type="button" onClick={() => setTab('editPlan')} style={outlineButton}>Edit Plan & Status</button>
        </div>
      </div>

      {/* Metric Cards Grid */}
      <div style={localMetricGrid}>
        <MetricItem label="Total Departments" value={depts.length} sub="Active organizational units" color="#60a5fa" icon="📁" />
        <MetricItem label="Total Users" value={users.length} sub="Registered member accounts" color="#818cf8" icon="👥" />
        <MetricItem label="Total Alerts" value={alerts.length} sub="Logged security events" color="#ef4444" icon="🔔" />
        <MetricItem label="System Limit" value={company.plan?.systemLimit ?? company.plan?.systemCount ?? 0} sub="Maximum allowed systems" color="#34d399" icon="🖥️" />
        <MetricItem label="Plan Type" value={(company.plan?.type || company.plan?.planName || 'NONE').toUpperCase()} sub="Active subscription plan" color="#c084fc" icon="💎" />
      </div>

      {/* Tabs */}
      <div style={localTabsWrap}>
        {[
          ['dashboard', '⌂ Dashboard'],
          ['agents', '◫ Agent'],
          ['departments', '📁 Departments'],
          ['subscription', '▤ Subscription & Payments'],
          ['requests', '▱ Buy Agent License'],
          ['profile', '♙ My Profile'],
          ['company', '▥ Company Information'],
          ['kyc', '▧ KYC Documents'],
          ['bank', '⌂ Bank & Payout Details'],
          ['users', '♧ Users & Permissions'],
          ['notifications', '♢ Notifications'],
          ['security', '⬡ Security'],
          ['activity', '◷ Activity Log'],
          ['support', '? Support'],
          ['editPlan', '⚙️ Edit Plan & Status']
        ].map(([tabId, label]) => (
          <button key={tabId} onClick={() => setTab(tabId)} style={localTabButton(tab === tabId)}>
            {label}
          </button>
        ))}
      </div>

      {/* Tab Content Panels */}
      <div style={{ marginTop: 10 }}>
        {tab === 'dashboard' && (
          <>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
              {[
                { label: 'Registered Systems', value: `${systems.length} / ${company.plan?.systemLimit || company.plan?.systemCount || 0}`, color: '#3b82f6', icon: '🖥️' },
                { label: 'Active Alerts', value: alerts.filter(a => a.status !== 'resolved').length, color: '#ef4444', icon: '🔔' },
                { label: 'AutoPay Status', value: company.plan?.autoPay ? 'Enabled' : 'Disabled', color: '#10b981', icon: '🔄' },
                { label: 'Next Renewal', value: company.plan?.expiresAt ? new Date(company.plan.expiresAt).toLocaleDateString() : '—', color: '#f59e0b', icon: '📅' }
              ].map(kpi => (
                <div key={kpi.label} style={{
                  background: 'linear-gradient(135deg, rgba(12,26,46,0.9) 0%, rgba(7,17,31,0.8) 100%)',
                  borderRadius: 12, padding: '20px', border: '1px solid #1e3a5f',
                  boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.05), 0 4px 12px rgba(0,0,0,0.3)',
                  display: 'flex', alignItems: 'center', gap: 16
                }}>
                  <span style={{ fontSize: 32 }}>{kpi.icon}</span>
                  <div>
                    <div style={{ fontSize: 11, color: '#93c5fd', textTransform: 'uppercase', marginBottom: 4 }}>{kpi.label}</div>
                    <div style={{ fontSize: 20, color: '#e0f2fe', fontWeight: 800 }}>{kpi.value}</div>
                  </div>
                </div>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr', gap: 20, alignItems: 'start' }}>
              <PanelSection title="Quick Access Operations">
                <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 20 }}>
                  Manage threat monitoring, users, and billing shortcuts for this company:
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  {[
                    { title: 'Endpoints & Agents', desc: 'Deploy security telemetry agents.', path: 'agents', icon: '🖥️' },
                    { title: 'Company Team', desc: 'Manage users and roles.', path: 'users', icon: '👥' },
                    { title: 'Subscription Status', desc: 'View billing cycle and renewal.', path: 'subscription', icon: '🔄' },
                    { title: 'Security & 2FA', desc: 'Verify account login security.', path: 'security', icon: '🔐' },
                  ].map(action => (
                    <button key={action.title} onClick={() => setTab(action.path)} style={{
                      textAlign: 'left', padding: 14, borderRadius: 8, border: '1px solid #1e3a5f',
                      background: 'rgba(30,41,59,0.2)', color: '#93c5fd', cursor: 'pointer', transition: 'all 0.2s',
                      outline: 'none'
                    }}>
                      <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span>{action.icon}</span> {action.title}
                      </div>
                      <div style={{ fontSize: 11, color: '#64748b' }}>{action.desc}</div>
                    </button>
                  ))}
                </div>
              </PanelSection>

              <PanelSection title="Account Tier & Details">
                <DetailRow label="Enterprise Account" value={company.name} />
                <DetailRow label="Portal ID" value={company._id} />
                <DetailRow label="Plan Status" value={company.plan?.isActive ? '✅ Active' : '⏸️ Inactive'} good={company.plan?.isActive} />
                <DetailRow label="Subscribed On" value={company.createdAt ? new Date(company.createdAt).toLocaleDateString() : '—'} />
              </PanelSection>
            </div>
          </>
        )}

        {tab === 'agents' && (
          <div style={{ display: 'grid', gap: 20 }}>
            <PanelSection title="Endpoint Telemetry Agent Installer Guide">
              <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 16 }}>
                Run the corresponding command below on target servers or machines to install the threat detection agent and connect it automatically to this company:
              </p>
              <div style={{ display: 'grid', gap: 14 }}>
                {[
                  { os: 'Linux (Ubuntu / Debian / CentOS)', cmd: `curl -sSL ${SOCKET_URL}/api/agent/install | bash -s -- --token ${company._id}` },
                  { os: 'Windows (PowerShell Admin)', cmd: `iex ((New-Object System.Net.WebClient).DownloadString('${SOCKET_URL}/api/agent/install/win'))` },
                  { os: 'macOS (Terminal)', cmd: `curl -sSL ${SOCKET_URL}/api/agent/install/mac | bash -s -- --token ${company._id}` }
                ].map(installer => (
                  <div key={installer.os} style={{ background: '#07111f', border: '1px solid #1e3a5f', borderRadius: 8, padding: 12 }}>
                    <div style={{ fontSize: 12, color: '#818cf8', fontWeight: 700, marginBottom: 6 }}>{installer.os}</div>
                    <code style={{ fontSize: 11, color: '#34d399', wordBreak: 'break-all', fontFamily: 'monospace', background: 'rgba(0,0,0,0.4)', padding: '4px 8px', borderRadius: 4, display: 'block' }}>
                      {installer.cmd}
                    </code>
                  </div>
                ))}
              </div>
            </PanelSection>

            <PanelSection title="Registered Agent Roster">
              {loadingSystems ? (
                <div style={{ textAlign: 'center', color: '#cbd5e1', padding: 20 }}>Loading endpoints...</div>
              ) : (
                <LocalDarkTable
                  headers={['Host Name', 'Operating System', 'IP Address', 'Agent Version', 'Status']}
                  rows={systems}
                  empty="No endpoints connected. Install the agent using the instructions above."
                  renderRow={(s, idx) => (
                    <tr key={s._id}>
                      <LocalCell>🖥️ {s.hostname || s.name || 'Unknown Host'}</LocalCell>
                      <LocalCell>{s.os || s.platform || 'Linux'}</LocalCell>
                      <LocalCell>{s.ipAddress || s.ip || '—'}</LocalCell>
                      <LocalCell>v{s.version || '1.0.0'}</LocalCell>
                      <LocalCell>
                        <LocalBadge good={s.status === 'online'} danger={s.status !== 'online'}>{s.status?.toUpperCase() || 'OFFLINE'}</LocalBadge>
                      </LocalCell>
                    </tr>
                  )}
                />
              )}
            </PanelSection>
          </div>
        )}

        {tab === 'departments' && (
          <LocalDarkTable
            headers={['Department Name', 'System Count', 'Admin', 'Description']}
            rows={depts}
            empty="No departments found for this company."
            renderRow={d => (
              <tr key={d._id}>
                <LocalCell>📁 {d.name}</LocalCell>
                <LocalCell>{d.systemCount || 0} systems</LocalCell>
                <LocalCell>{d.adminId ? (d.adminId.name || d.adminId.email) : '—'}</LocalCell>
                <LocalCell>{d.description || '—'}</LocalCell>
              </tr>
            )}
          />
        )}

        {tab === 'subscription' && (
          <PanelSection title="Subscription Details">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12, marginBottom: 20 }}>
              {[
                { label: 'Systems Count', value: `${company.plan?.systemCount || company.plan?.systemLimit || 0}`, unit: 'systems', color: '#60a5fa' },
                { label: 'Servers Count', value: `${company.plan?.serverCount || 0}`, unit: 'servers', color: '#818cf8' },
                { label: 'Phones Count', value: `${company.plan?.phoneCount || 0}`, unit: 'phones', color: '#f472b6' },
              ].map(({ label, value, unit, color }) => (
                <div key={label} style={{ background: 'rgba(0,0,0,0.3)', borderRadius: 10, padding: 16, textAlign: 'center', border: '1px solid #1e3a5f' }}>
                  <div style={{ fontSize: 11, color: '#93c5fd', marginBottom: 6, textTransform: 'uppercase' }}>{label}</div>
                  <div style={{ fontSize: 28, color, fontWeight: 800 }}>{value}</div>
                  <div style={{ fontSize: 11, color: '#64748b' }}>{unit}</div>
                </div>
              ))}
            </div>
            <DetailRow label="Status" value={(company.plan?.isActive ? 'ACTIVE' : 'INACTIVE')} good={company.plan?.isActive} />
            <DetailRow label="Billing Cycle" value={company.plan?.billingCycle || 'monthly'} />
            <DetailRow label="Amount Paid" value={`₹${Number(company.plan?.amountPaid || 0).toLocaleString('en-IN')}`} />
            <DetailRow label="Payment Status" value={company.plan?.paymentStatus?.toUpperCase() || 'PAID'} good={company.plan?.paymentStatus === 'paid'} />
            <DetailRow label="Start Date" value={company.plan?.startDate ? new Date(company.plan.startDate).toLocaleDateString() : '—'} />
            <DetailRow label="Expiry Date" value={company.plan?.expiresAt ? new Date(company.plan.expiresAt).toLocaleDateString() : '—'} />
            <DetailRow label="AutoPay" value={company.plan?.autoPay ? 'Enabled' : 'Disabled'} good={company.plan?.autoPay} />
          </PanelSection>
        )}

        {tab === 'requests' && (
          <PanelSection title="Add System Subscription History">
            {loadingAddSubs ? (
              <div style={{ textAlign: 'center', color: '#cbd5e1', padding: 20 }}>Loading subscription history...</div>
            ) : (
              <LocalDarkTable
                headers={['Add Date', 'Systems', 'Servers/Details', 'Start', 'End', 'Billing', 'Amount', 'Payment ID', 'Status']}
                rows={addSubs}
                empty="No add-system subscriptions yet."
                renderRow={(b, idx) => {
                  const bEnd = new Date(b.endDate || 0);
                  const bNow = new Date();
                  const bActive = b.status === 'active' && bNow < bEnd;
                  return (
                    <tr key={b._id}>
                      <LocalCell>{new Date(b.addedDate || b.createdAt).toLocaleDateString()}</LocalCell>
                      <LocalCell style={{ color: '#60a5fa', fontWeight: 'bold' }}>+{b.addedSystemCount}</LocalCell>
                      <LocalCell>{b.addedServerCount || b.addedPhoneCount ? `+${b.addedServerCount || 0} srv · +${b.addedPhoneCount || 0} phone` : '—'}</LocalCell>
                      <LocalCell>{b.startDate ? new Date(b.startDate).toLocaleDateString() : '—'}</LocalCell>
                      <LocalCell>{b.endDate ? new Date(b.endDate).toLocaleDateString() : '—'}</LocalCell>
                      <LocalCell>{b.billingCycle || '—'}</LocalCell>
                      <LocalCell style={{ color: '#34d399', fontWeight: 'bold' }}>₹{Number(b.amountPaid || 0).toLocaleString('en-IN')}</LocalCell>
                      <LocalCell style={{ fontFamily: 'monospace', fontSize: 10 }}>{b.paymentId || '—'}</LocalCell>
                      <LocalCell>
                        <LocalBadge good={bActive} danger={!bActive}>{bActive ? 'Active' : 'Expired'}</LocalBadge>
                      </LocalCell>
                    </tr>
                  );
                }}
              />
            )}
          </PanelSection>
        )}

        {tab === 'profile' && (
          <PanelSection title="Company Administrator Profile">
            {users.find(u => u.role === 'company_admin') ? (
              (() => {
                const admin = users.find(u => u.role === 'company_admin');
                return (
                  <>
                    <DetailRow label="Full Name" value={admin.name} />
                    <DetailRow label="Email Address" value={admin.email} />
                    <DetailRow label="Mobile Phone" value={admin.phone || '—'} />
                    <DetailRow label="Role Badge" value="Company Admin" />
                    <DetailRow label="Account Status" value={admin.isActive ? 'Active' : 'Disabled'} good={admin.isActive} />
                  </>
                );
              })()
            ) : (
              <p style={{ color: '#cbd5e1', fontSize: 12 }}>No designated Company Admin user found.</p>
            )}
          </PanelSection>
        )}

        {tab === 'company' && (
          <PanelSection title="Company Information">
            <DetailRow label="Company Name" value={company.name} />
            <DetailRow label="Company Email" value={company.email} />
            <DetailRow label="Phone Number" value={company.phone || '—'} />
            <DetailRow label="Agent Key" value={company.agentKey || '—'} />
            <DetailRow label="Risk Score" value={company.riskScore ?? 0} />
            <DetailRow label="Created At" value={new Date(company.createdAt).toLocaleString()} />
          </PanelSection>
        )}

        {tab === 'kyc' && (
          <PanelSection title="Corporate KYC Verification Status">
            <div style={{ display: 'flex', gap: 14, alignItems: 'center', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: 8, padding: 16, marginBottom: 20 }}>
              <span style={{ fontSize: 32 }}>✅</span>
              <div>
                <div style={{ color: '#34d399', fontWeight: 800, fontSize: 15, marginBottom: 4 }}>KYC Verified & Active</div>
                <p style={{ color: '#cbd5e1', fontSize: 12, margin: 0 }}>
                  This enterprise tenant account has passed identity compliance checks. GSTIN, PAN, and corporate identity certificates are verified.
                </p>
              </div>
            </div>
            <DetailRow label="GSTIN Status" value="Verified & Active" good={true} />
            <DetailRow label="PAN Status" value="Verified & Checked" good={true} />
            <DetailRow label="Identity Certificate" value="Verified" good={true} />
          </PanelSection>
        )}

        {tab === 'bank' && (
          <PanelSection title="Bank & Payout Information">
            <p style={{ color: '#94a3b8', fontSize: 13, marginBottom: 20 }}>
              This customer tenant pays for monthly security intelligence subscriptions. Payout details are not applicable.
            </p>
            <DetailRow label="Billing AutoPay" value={company.plan?.autoPay ? 'Mandate Active' : 'Not Active'} good={company.plan?.autoPay} />
            <DetailRow label="Payment Gateway" value="Razorpay Subscription Mandate" />
            <DetailRow label="Billing Receipt Delivery" value="Sent automatically to admin email" />
          </PanelSection>
        )}

        {tab === 'users' && (
          <LocalDarkTable
            headers={['Name', 'Email', 'Role', 'Status']}
            rows={users}
            empty="No users found for this company."
            renderRow={u => (
              <tr key={u._id}>
                <LocalCell>{u.name || '—'}</LocalCell>
                <LocalCell>{u.email}</LocalCell>
                <LocalCell>
                  <LocalBadge>{u.role?.replace(/_/g, ' ') || 'N/A'}</LocalBadge>
                </LocalCell>
                <LocalCell>
                  <LocalBadge good={u.isActive} danger={!u.isActive}>{u.isActive ? 'active' : 'disabled'}</LocalBadge>
                </LocalCell>
              </tr>
            )}
          />
        )}

        {tab === 'notifications' && (
          <PanelSection title="Notification Settings">
            <DetailRow label="Security Alert Emails" value="Enabled" good={true} />
            <DetailRow label="Critical SMS Alerts" value="Enabled" good={true} />
            <DetailRow label="Weekly Audit Reports" value="Enabled" good={true} />
          </PanelSection>
        )}

        {tab === 'security' && (
          <PanelSection title="Security & Multi-Factor Authentication">
            <DetailRow label="2FA Auth" value={company.twoFactorEnabled ? '🔐 Enabled' : '⚠️ Disabled'} good={company.twoFactorEnabled} />
            <DetailRow label="Email Verification" value="Verified" good={true} />
            <DetailRow label="OTP Login" value="Enabled" good={true} />
            <DetailRow label="Risk Score Assessment" value={company.riskScore ?? 0} />
          </PanelSection>
        )}

        {tab === 'activity' && (
          <PanelSection title="Portal Security Activity Log">
            {loadingAudit ? (
              <div style={{ textAlign: 'center', color: '#cbd5e1', padding: 20 }}>Loading activity logs...</div>
            ) : (
              <LocalDarkTable
                headers={['Timestamp', 'Action / Log Source', 'Target', 'Description']}
                rows={auditLogs}
                empty="No activity logs found."
                renderRow={(log, idx) => (
                  <tr key={log._id || idx}>
                    <LocalCell>{log.ts ? new Date(log.ts).toLocaleString() : log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'}</LocalCell>
                    <LocalCell>{log.action || log.actionType || log.source || 'IPS Manual Rule'}</LocalCell>
                    <LocalCell>{log.target || log.ip || log.userEmail || '—'}</LocalCell>
                    <LocalCell>{log.detail || log.description || log.message || '—'}</LocalCell>
                  </tr>
                )}
              />
            )}
          </PanelSection>
        )}

        {tab === 'support' && (
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 20, alignItems: 'start' }}>
            <PanelSection title="Technical Support Tickets">
              {loadingSupport ? (
                <div style={{ textAlign: 'center', color: '#cbd5e1', padding: 20 }}>Loading tickets...</div>
              ) : supportTickets.length === 0 ? (
                <div style={{ color: '#cbd5e1', fontSize: 13, padding: 10 }}>No support tickets found for this tenant.</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 450, overflowY: 'auto' }}>
                  {supportTickets.map(t => {
                    const isSelected = selectedTicket?._id === t._id;
                    const severityColors = {
                      low: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1' },
                      medium: { bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
                      high: { bg: 'rgba(239,68,68,0.1)', text: '#ef4444' },
                      payment: { bg: 'rgba(16,185,129,0.1)', text: '#10b981' }
                    };
                    const statusColors = {
                      'Open': '#eab308',
                      'In Progress': '#3b82f6',
                      'Resolved': '#10b981',
                      'Closed': '#64748b'
                    };
                    const sev = severityColors[t.severity] || severityColors.low;
                    return (
                      <div
                        key={t._id}
                        onClick={() => setSelectedTicket(t)}
                        style={{
                          padding: 12, borderRadius: 8, cursor: 'pointer',
                          background: isSelected ? 'rgba(59,130,246,0.15)' : '#07111f',
                          border: isSelected ? '1px solid #3b82f6' : '1px solid #1e3a5f',
                          transition: 'all 0.2s'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                          <span style={{ fontSize: 11, color: '#60a5fa', fontWeight: 'bold' }}>{t.ticketId}</span>
                          <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: sev.bg, color: sev.text, fontWeight: 700 }}>
                            {t.severity?.toUpperCase()}
                          </span>
                        </div>
                        <div style={{ fontSize: 13, fontWeight: 'bold', color: '#f8fafc', marginBottom: 6 }}>{t.subject}</div>
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, color: '#94a3b8' }}>
                          <span>{new Date(t.createdAt).toLocaleDateString()}</span>
                          <span style={{ fontWeight: 700, color: statusColors[t.status] || '#cbd5e1' }}>{t.status}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </PanelSection>

            {selectedTicket ? (
              <PanelSection title={`Ticket: ${selectedTicket.ticketId}`}>
                <div style={{ borderBottom: '1px solid #1e3a5f', paddingBottom: 12, marginBottom: 14 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>{selectedTicket.subject}</h3>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 12, color: '#94a3b8' }}>Status:</span>
                      <select
                        value={selectedTicket.status}
                        onChange={(e) => updateStatus(e.target.value)}
                        style={{
                          background: '#07111f', color: '#e0f2fe', border: '1px solid #1e3a5f',
                          borderRadius: 6, padding: '4px 8px', fontSize: 12, fontWeight: 700, cursor: 'pointer'
                        }}
                      >
                        <option value="Open">Open</option>
                        <option value="In Progress">In Progress</option>
                        <option value="Resolved">Resolved</option>
                        <option value="Closed">Closed</option>
                      </select>
                    </div>
                  </div>
                  <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>
                    {selectedTicket.description}
                  </p>
                </div>

                {/* Message Log */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 250, overflowY: 'auto', marginBottom: 14, paddingRight: 4 }}>
                  {(selectedTicket.messages || []).map((msg, idx) => {
                    const isMe = msg.senderRole === 'partner_admin';
                    return (
                      <div
                        key={msg._id || idx}
                        style={{
                          alignSelf: isMe ? 'flex-end' : 'flex-start',
                          maxWidth: '85%',
                          background: isMe ? 'linear-gradient(135deg, #1e3a8a, #1d4ed8)' : 'rgba(30,41,59,0.4)',
                          border: isMe ? 'none' : '1px solid #1e3a5f',
                          padding: '10px 14px', borderRadius: 12,
                          color: '#f8fafc', fontSize: 13, lineHeight: 1.4
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 10, color: isMe ? '#bfdbfe' : '#94a3b8', fontWeight: 600 }}>
                          <span>{msg.senderName} ({msg.senderRole === 'superadmin' ? 'Super Admin' : msg.senderRole === 'company_admin' ? 'Company Admin' : 'Partner Admin'})</span>
                          <span>{new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                        </div>
                        <div style={{ whiteSpace: 'pre-wrap' }}>{msg.message}</div>
                      </div>
                    );
                  })}
                </div>

                {/* Reply Form */}
                {selectedTicket.status === 'Closed' ? (
                  <div style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '10px 14px', borderRadius: 8, fontSize: 12, textAlign: 'center' }}>
                    This ticket has been closed.
                  </div>
                ) : (
                  <form onSubmit={sendReply} style={{ display: 'flex', gap: 10 }}>
                    <input
                      type="text"
                      required
                      placeholder="Type your response..."
                      value={replyMessage}
                      onChange={e => setReplyMessage(e.target.value)}
                      style={{
                        flex: 1, padding: '10px 14px', borderRadius: 8, border: '1px solid #1e3a5f',
                        background: '#07111f', color: '#f8fafc', fontSize: 13, outline: 'none'
                      }}
                    />
                    <button
                      type="submit"
                      disabled={replyBusy}
                      style={{
                        padding: '0 20px', borderRadius: 8, border: 'none',
                        background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                        color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                      }}
                    >
                      {replyBusy ? 'Sending...' : 'Send'}
                    </button>
                  </form>
                )}
              </PanelSection>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', border: '1px dashed #1e3a5f', borderRadius: 8, padding: 40, color: '#94a3b8', fontSize: 13, minHeight: 180 }}>
                Select a ticket from the list to view conversation history.
              </div>
            )}
          </div>
        )}

        {tab === 'editPlan' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 20 }}>
            <PanelSection title="Edit Company Payment Status">
              <form onSubmit={handleUpdatePayment} style={{ display: 'grid', gap: 14 }}>
                <label style={{ display: 'grid', gap: 5 }}>
                  <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 800 }}>Payment Status</span>
                  <select
                    value={editPaymentStatus}
                    onChange={e => setEditPaymentStatus(e.target.value)}
                    style={{ ...inputStyle, width: '100%' }}
                  >
                    <option value="paid">Paid</option>
                    <option value="unpaid">Unpaid</option>
                    <option value="failed">Failed</option>
                  </select>
                </label>
                <label style={{ display: 'grid', gap: 5 }}>
                  <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 800 }}>Amount Paid (INR)</span>
                  <input
                    type="number"
                    value={editAmountPaid}
                    onChange={e => setEditAmountPaid(e.target.value)}
                    placeholder="Enter amount"
                    style={inputStyle}
                  />
                </label>
                <label style={{ display: 'grid', gap: 5 }}>
                  <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 800 }}>Billing Cycle</span>
                  <select
                    value={editBillingCycle}
                    onChange={e => setEditBillingCycle(e.target.value)}
                    style={{ ...inputStyle, width: '100%' }}
                  >
                    <option value="monthly">Monthly</option>
                    <option value="yearly">Yearly</option>
                  </select>
                </label>
                <label style={{ display: 'grid', gap: 5 }}>
                  <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 800 }}>Update Reason / Note</span>
                  <input
                    type="text"
                    value={editReason}
                    onChange={e => setEditReason(e.target.value)}
                    placeholder="Reason for payment update"
                    style={inputStyle}
                  />
                </label>
                <button
                  type="submit"
                  disabled={updatingPayment}
                  style={{ ...primaryButton, width: '100%', marginTop: 8 }}
                >
                  {updatingPayment ? 'Updating...' : 'Update Payment Settings'}
                </button>
              </form>
            </PanelSection>

            <PanelSection title="Manage AutoPay Mandate">
              <p style={{ color: '#cbd5e1', fontSize: 13, marginBottom: 16 }}>
                Directly toggle Razorpay billing subscription mandate for this tenant. When active, recurring payments are processed automatically.
              </p>
              <div style={{ padding: 16, border: '1px solid #1e3a5f', borderRadius: 8, background: '#07111f', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 900, color: '#e0f2fe' }}>AutoPay Status</div>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 4 }}>
                    Current: <b style={{ color: company.plan?.autoPay ? '#34d399' : '#ef4444' }}>{company.plan?.autoPay ? 'Enabled' : 'Disabled'}</b>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={handleToggleAutopay}
                  disabled={updatingAutopay}
                  style={company.plan?.autoPay ? dangerButton : primaryButton}
                >
                  {updatingAutopay ? 'Processing...' : company.plan?.autoPay ? 'Disable AutoPay' : 'Enable AutoPay'}
                </button>
              </div>
            </PanelSection>
          </div>
        )}
      </div>
    </div>
  );
}

function MetricItem({ label, value, sub, color, icon }) {
  return (
    <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:10, padding:'15px 16px', display:'flex', justifyContent:'space-between', gap:12, alignItems:'center', boxShadow:'0 10px 24px rgba(15, 23, 42, .22)' }}>
      <div>
        <div style={{ color:'#93c5fd', fontSize:12, fontWeight:800 }}>{label}</div>
        <div style={{ color, fontSize:24, fontWeight:900, marginTop:6 }}>{value}</div>
        <div style={{ color:'#60a5fa', fontSize:11, marginTop:4 }}>{sub}</div>
      </div>
      <div style={{ width:46, height:46, borderRadius:'50%', background:`${color}22`, color, display:'grid', placeItems:'center', fontSize:23 }}>{icon}</div>
    </div>
  );
}

function PanelSection({ title, children }) {
  return (
    <section style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:10, padding:16, boxShadow:'0 10px 24px rgba(15, 23, 42, .22)', marginBottom: 20 }}>
      <h3 style={{ color:'#e0f2fe', fontSize:14, margin:'0 0 12px', fontWeight:950 }}>{title}</h3>
      {children}
    </section>
  );
}

function DetailRow({ label, value, good }) {
  return (
    <div style={{ display:'grid', gridTemplateColumns:'130px 1fr', gap:12, margin:'10px 0', color:'#cbd5e1', fontSize:12 }}>
      <span style={{ color:'#94a3b8' }}>{label}</span>
      <b style={{ color: good === true ? '#34d399' : good === false ? '#ef4444' : '#cbd5e1' }}>{String(value)}</b>
    </div>
  );
}

function LocalDarkTable({ headers, rows, renderRow, empty }) {
  const pageSize = 10;
  const [page, setPage] = useState(0);
  const totalPages = Math.max(Math.ceil((rows?.length || 0) / pageSize), 1);
  const currentPage = Math.min(page, totalPages - 1);
  const pageRows = (rows || []).slice(currentPage * pageSize, currentPage * pageSize + pageSize);

  const tablePagerButton = disabled => ({ minWidth:74, height:34, borderRadius:8, border:'1px solid #1e3a5f', background:'#07111f', color:disabled ? '#475569' : '#93c5fd', fontSize:13, fontWeight:850, cursor:disabled ? 'not-allowed' : 'pointer' });

  useEffect(() => {
    setPage(0);
  }, [rows?.length]);

  return (
    <div style={{ border:'1px solid #1e3a5f', borderRadius:10, overflow:'hidden', marginBottom: 20 }}>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', background:'#0c1a2e' }}>
          <thead><tr>{headers.map(header => <th key={header} style={{ textAlign:'left', padding:'10px 12px', color:'#93c5fd', fontSize:11, borderBottom:'1px solid #1e3a5f', background:'#07111f' }}>{header}</th>)}</tr></thead>
          <tbody>
            {(rows || []).length === 0 ? (
              <tr><td colSpan={headers.length} style={{ color:'#cbd5e1', fontSize:12, borderBottom:'1px solid #1e3a5f', textAlign:'center', padding: 24 }}>{empty}</td></tr>
            ) : pageRows.map(renderRow)}
          </tbody>
        </table>
      </div>
      {(rows || []).length > pageSize && (
        <div style={{ display:'flex', justifyContent:'flex-end', gap:10, padding:'14px 18px', background:'#07111f', borderTop:'1px solid #1e3a5f' }}>
          <button type="button" disabled={currentPage === 0} onClick={() => setPage(prev => Math.max(prev - 1, 0))} style={tablePagerButton(currentPage === 0)}>Prev</button>
          <button type="button" disabled={currentPage >= totalPages - 1} onClick={() => setPage(prev => Math.min(prev + 1, totalPages - 1))} style={tablePagerButton(currentPage >= totalPages - 1)}>Next</button>
        </div>
      )}
    </div>
  );
}

function LocalCell({ children, style }) {
  return <td style={{ padding:'10px 12px', color:'#e2e8f0', fontSize:12, borderBottom:'1px solid #1e3a5f', ...style }}>{children}</td>;
}

function LocalBadge({ children, good, danger }) {
  const bg = good ? '#064e3b' : danger ? '#7f1d1d' : '#07111f';
  const color = good ? '#34d399' : danger ? '#fca5a5' : '#93c5fd';
  const border = good ? '1px solid #064e3b' : danger ? '1px solid #7f1d1d' : '1px solid #1e3a5f';
  return <span style={{ padding:'3px 9px', borderRadius:99, background:bg, color, border, fontSize:10, fontWeight:900 }}>{children || 'none'}</span>;
}

// ── CompaniesView — Partner Admin Companies List ─────────────────────────────
function CompaniesView({ companies, partner, summary }) {
  const navigate = useNavigate();
  const [searchQ, setSearchQ] = useState('');
  const filtered = companies.filter(c =>
    !searchQ || c.name?.toLowerCase().includes(searchQ.toLowerCase()) || c.email?.toLowerCase().includes(searchQ.toLowerCase())
  );
  const statusColor = s => s === 'active' ? '#34d399' : s === 'inactive' ? '#f87171' : '#f59e0b';
  const statusBg = s => s === 'active' ? 'rgba(52,211,153,0.1)' : s === 'inactive' ? 'rgba(248,113,113,0.1)' : 'rgba(245,158,11,0.1)';
  const fmtDate = d => d ? new Date(d).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }) : '—';

  return (
    <div style={{ padding:'0 0 24px' }}>
      {/* Header */}
      <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:22, flexWrap:'wrap', gap:12 }}>
        <div>
          <h2 style={{ margin:0, fontSize:20, fontWeight:900, color:'#e0f2fe' }}>🏢 Companies</h2>
          <p style={{ margin:'4px 0 0', fontSize:13, color:'#64748b' }}>
            {partner.name} ke under registered companies · Total: <b style={{ color:'#60a5fa' }}>{summary.totalCompanies}</b>
            {' '}· Active: <b style={{ color:'#34d399' }}>{summary.activeCompanies}</b>
          </p>
        </div>
        <a href={`?invite=company`} style={{ padding:'10px 20px', borderRadius:9, border:'none', background:'linear-gradient(135deg,#4f46e5,#7c3aed)', color:'#fff', fontWeight:800, fontSize:13, cursor:'pointer', textDecoration:'none', display:'inline-block' }}>
          + Invite Company
        </a>
      </div>

      {/* Search */}
      <div style={{ marginBottom:16 }}>
        <input
          placeholder="Search by company name or email..."
          value={searchQ}
          onChange={e => setSearchQ(e.target.value)}
          style={{ width:'100%', maxWidth:380, padding:'9px 14px', borderRadius:8, border:'1px solid #1e3a5f', background:'#07111f', color:'#e2e8f0', fontSize:13, boxSizing:'border-box' }}
        />
      </div>

      {/* Stats row */}
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(130px, 1fr))', gap:12, marginBottom:22 }}>
        {[
          { label:'Total', value: summary.totalCompanies, color:'#60a5fa' },
          { label:'Active', value: summary.activeCompanies, color:'#34d399' },
          { label:'Inactive', value: Math.max(summary.totalCompanies - summary.activeCompanies, 0), color:'#f87171' },
          { label:'Active Plans', value: summary.activePlans, color:'#a78bfa' },
          { label:'Expiring Soon', value: summary.expiringPlans, color:'#f59e0b' },
        ].map(({ label, value, color }) => (
          <div key={label} style={{ background:'#0c1a2e', border:`1px solid ${color}22`, borderRadius:10, padding:'14px 16px' }}>
            <div style={{ fontSize:22, fontWeight:800, color }}>{value}</div>
            <div style={{ fontSize:11, color:'#64748b', marginTop:3 }}>{label}</div>
          </div>
        ))}
      </div>

      {/* Table */}
      {companies.length === 0 ? (
        <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:12, padding:'40px', textAlign:'center' }}>
          <div style={{ fontSize:36, marginBottom:12 }}>🏢</div>
          <div style={{ fontSize:15, fontWeight:700, color:'#60a5fa', marginBottom:6 }}>Abhi koi company nahi</div>
          <div style={{ fontSize:13, color:'#64748b', marginBottom:20 }}>Apni pehli company ko invite karo</div>
          <a href="?invite=company" style={{ padding:'10px 24px', borderRadius:8, background:'linear-gradient(135deg,#4f46e5,#7c3aed)', color:'#fff', fontWeight:700, textDecoration:'none', fontSize:13 }}>
            + Invite Company
          </a>
        </div>
      ) : (
        <div style={{ background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:12, overflow:'hidden' }}>
          <table style={{ width:'100%', borderCollapse:'collapse' }}>
            <thead>
              <tr style={{ background:'#07111f' }}>
                {['#', 'Company', 'Email', 'Status', 'Plan', 'Joined'].map(h => (
                   <th key={h} style={{ padding:'12px 16px', textAlign:'left', color:'#60a5fa', fontSize:11, fontWeight:900, borderBottom:'1px solid #1e3a5f' }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(filtered.length > 0 ? filtered : companies).map((c, i) => (
                <tr key={c._id} 
                  style={{ borderBottom:'1px solid rgba(30,58,95,0.5)', transition:'background .15s', cursor:'pointer' }}
                  onClick={() => navigate(`/partner/companies/${c._id}`)}
                  onMouseEnter={e => e.currentTarget.style.background = 'rgba(37,99,235,0.06)'}
                  onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                  <td style={{ padding:'12px 16px', color:'#475569', fontSize:12 }}>{i + 1}</td>
                  <td style={{ padding:'12px 16px' }}>
                    <div style={{ fontSize:13, fontWeight:700, color:'#e2e8f0' }}>{c.name || '—'}</div>
                    {c.adminName && <div style={{ fontSize:11, color:'#64748b', marginTop:2 }}>{c.adminName}</div>}
                  </td>
                  <td style={{ padding:'12px 16px', color:'#93c5fd', fontSize:12 }}>{c.email || '—'}</td>
                  <td style={{ padding:'12px 16px' }}>
                    <span style={{ fontSize:11, padding:'3px 10px', borderRadius:20, fontWeight:700, background: statusBg(c.status), color: statusColor(c.status), textTransform:'capitalize' }}>
                      {c.status || 'unknown'}
                    </span>
                  </td>
                  <td style={{ padding:'12px 16px', color: c.plan?.isActive ? '#34d399' : '#f59e0b', fontSize:12, fontWeight:700 }}>
                    {c.plan?.isActive ? '✓ Active' : c.plan?.planName || '—'}
                  </td>
                  <td style={{ padding:'12px 16px', color:'#475569', fontSize:12 }}>{fmtDate(c.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && searchQ && (
            <div style={{ padding:'20px', textAlign:'center', color:'#64748b', fontSize:13 }}>
              "{searchQ}" se koi company nahi mili
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function DashboardView({ embedded, partner, companies, summary, setMessage }) {
  const inactiveAgents = Math.max(summary.totalAgents - summary.activeAgents, 0);
  const rows = dashboardActivity(companies);
  const agreementFilePath = partner.agreementFilePath || '';
  const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:5000/api').replace(/\/api\/?$/, '');
  const agreementUrl = agreementFilePath ? `${apiBase}/uploads/${agreementFilePath}` : '';

  const openAgreement = () => {
    if (!agreementUrl) return;
    const opened = window.open(agreementUrl, '_blank', 'noopener,noreferrer');
    if (!opened) {
      setMessage?.('Please allow popups to open the Agreement PDF.');
      window.setTimeout(() => setMessage?.(''), 4000);
    }
  };

  if (embedded) {
    return (
      <>
        <header style={dashboardHeader}>
          <h1 style={dashboardTitle}>Welcome, Partner Admin</h1>
          <p style={dashboardSubtitle}>Partner Company: {partner.name || 'Partner account'}</p>
        </header>

        <div style={dashboardStats}>
          <DashboardMetric icon="▦" tone="#5b5ff7" title="Total Companies" value={summary.totalCompanies} sub={<>Active: <b style={{ color:'#34d399' }}>{summary.activeCompanies}</b> <span>|</span> Inactive: <b>{Math.max(summary.totalCompanies - summary.activeCompanies, 0)}</b></>} />
          <DashboardMetric icon="▰" tone="#2563eb" title="Total Agents" value={summary.totalAgents} sub={<>Active: <b style={{ color:'#34d399' }}>{summary.activeAgents}</b> <span>|</span> Inactive: <b>{inactiveAgents}</b></>} />
          <DashboardMetric icon="□" tone="#3b82f6" title="Active Subscriptions" value={summary.activePlans} sub={<>Expiring Soon: <b style={{ color:'#34d399' }}>{summary.expiringPlans}</b></>} />
          <DashboardMetric icon="▣" tone="#16a34a" title="Total Collection" value={fmtInr(summary.totalCollection)} sub={<>Commission: <b>{fmtInr(summary.platformCommission)}</b></>} />
          <DashboardMetric icon="◆" tone="#16a34a" title="Account Status" value={statusLabel(partner.status)} sub="Full Access (Limited)" success />
          <button type="button" onClick={openAgreement} disabled={!agreementUrl} style={agreementMetric}>
            <span style={dashboardMetricLabel}>Agreement PDF</span>
            <strong style={agreementFileName}>{agreementUrl ? 'PDF Available' : 'Not Available'}</strong>
            <small style={dashboardMetricSub}>{agreementUrl ? 'Click to open' : 'Upload pending'}</small>
          </button>
        </div>

        <div style={dashboardMiddle}>
          <section style={dashboardCard}>
            <h2 style={dashboardCardTitle}>Agent Status Overview</h2>
            <div style={dashboardAgent}>
              <div style={dashboardDonut(summary.activeAgents, summary.totalAgents)}>
                <div style={dashboardDonutInner}>
                  <strong>{summary.totalAgents}</strong>
                  <span>Total</span>
                </div>
              </div>
              <div style={dashboardLegend}>
                <Legend color="#16a34a" text={`Active (${summary.activeAgents})`} />
                <Legend color="#ef4444" text={`Inactive (${inactiveAgents})`} />

              </div>
            </div>
          </section>

          <section style={dashboardCard}>
            <h2 style={dashboardCardTitle}>Resource Usage</h2>
            <CompactUsage label="Companies" value={summary.totalCompanies} total={summary.companyLimit} />
            <CompactUsage label="Agents" value={summary.totalAgents} total={summary.agentLimit} />

          </section>

          <section style={{ ...dashboardCard, ...noteCard }}>
            <h2 style={{ ...dashboardCardTitle, color:'#f59e0b' }}><span>ⓘ</span> Important Notes</h2>
            <p style={noteText}>You can request more companies, agents and change in commission from Requests section.</p>
            <p style={noteTextStrong}>Agent download and Company creation is allowed as per Super Admin approval.</p>
          </section>
        </div>

        <div style={settlementGrid}>
          <section style={dashboardCard}>
            <h2 style={dashboardCardTitle}>Partner Settlement</h2>
            <SettlementLine label="Total Collection" value={fmtInr(summary.totalCollection)} />
            <SettlementLine label="Platform Commission" value={fmtInr(summary.platformCommission)} />
            <SettlementLine label="Partner Payout" value={fmtInr(summary.partnerPayout)} />
            <SettlementLine label="Payout Status" value={titleCase(summary.payoutStatus)} />
            <SettlementLine label="Settlement Date" value={fmtDate(summary.settlementDate)} />
          </section>
        </div>

        <div style={dashboardBottom}>
          <section style={dashboardCard}>
            <h2 style={dashboardCardTitle}>Recent Activities</h2>
            <table style={compactTable}>
              <thead>
                <tr>
                  <th style={compactTh}>Activity</th>
                  <th style={compactTh}>Details</th>
                  <th style={compactTh}>Date</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row, index) => (
                  <tr key={`${row.activity}-${index}`}>
                    <td style={compactTd}>{row.activity}</td>
                    <td style={compactTd}>{row.details}</td>
                    <td style={compactTd}>{row.date}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </div>
      </>
    );
  }

  return null;
}

function RevenueView({ partnerId, companies = [], companiesLoaded = false, companiesError = '', onRefresh }) {
  const [revenueTab, setRevenueTab] = useState('overview');
  const [allHistoryRows, setAllHistoryRows] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyError, setHistoryError] = useState('');
  useEffect(() => {
    let mounted = true;
    setAllHistoryRows([]);
    setHistoryError('');
    if (!companiesLoaded || !companies.length) {
      setHistoryLoading(false);
      return () => { mounted = false; };
    }
    setHistoryLoading(true);
    api.get('/partner/revenue/history', { skipCache: true })
      .then(({ data }) => { if (mounted) setAllHistoryRows(Array.isArray(data) ? data : []); })
      .catch(() => { if (mounted) setHistoryError('Payment history could not be loaded. Please retry.'); })
      .finally(() => { if (mounted) setHistoryLoading(false); });
    return () => { mounted = false; };
  }, [partnerId, companiesLoaded, companies]);
  const companyRows = companies.map(company => {
    const systemLicenses = Number(company.plan?.systemCount || company.systemCount || 0);
    const serverLicenses = Number(company.plan?.serverCount || company.serverCount || 0);
    const phoneLicenses = Number(company.plan?.phoneCount || company.phoneCount || 0);
    const planAgentTotal = systemLicenses + serverLicenses + phoneLicenses;
    const installedAgentTotal = Number(company.systemCount || 0) +
      Number(company.serverCount || 0) +
      Number(company.phoneCount || 0);
    const totalAgents = Math.max(
      Number(company.totalAgents || 0),
      installedAgentTotal,
      planAgentTotal,
      Number(company.agentLicenseAllocation || 0)
    );
    return {
      id: company._id,
      name: company.name || 'Company',
      email: company.email || '',
      plan: company.plan?.type || company.plan?.planName || 'custom',
      systems: totalAgents,
      licenseText: formatLicenseBreakdown(systemLicenses, serverLicenses, phoneLicenses),
      monthlyRevenue: company.plan?.billingCycle === 'monthly' ? Number(company.plan?.amountPaid || 0) : 0,
      agents: totalAgents,
      collected: Number(company.revenue || 0),
      pending: Number(company.pendingRevenue || 0),
      status: company.paymentStatus || company.plan?.paymentStatus || 'unpaid',
      subscription: company.subscriptionStatus || (company.plan?.isActive ? 'active' : 'pending'),
      lastPaidAt: company.lastPaidAt || company.latestPayment?.paidAt,
      joined: company.createdAt,
    };
  });
  const rows = companyRows;
  const companyIds = new Set(companies.map(company => String(company._id)));
  const historyRows = allHistoryRows.filter(row => row.companyId && companyIds.has(String(row.companyId)));
  const overviewCollected = rows.reduce((sum, row) => sum + row.collected, 0);
  const overviewPendingTotal = rows.reduce((sum, row) => sum + row.pending, 0);
  const overviewPaidCompanies = rows.filter(row => row.collected > 0 || ['paid', 'captured'].includes(row.status)).length;
  const overviewChartRows = rows
    .map(row => ({ ...row, chartValue: Number(row.collected || 0) }))
    .sort((a, b) => b.chartValue - a.chartValue)
    .slice(0, 8);
  const maxChartValue = Math.max(...overviewChartRows.map(row => row.chartValue), 1);
  return (
    <div style={dashboardShell}>
      <section style={dashboardCard}>
        <div style={revenueTabHeader}>
          {[
            ['overview', '📊 Overview'],
            ['companies', '🏢 Companies'],
            ['history', '📜 History'],
          ].map(([id, label]) => (
            <button key={id} type="button" onClick={() => setRevenueTab(id)} style={revenueTab === id ? revenueTabActive : revenueTabButton}>{label}</button>
          ))}
        </div>
        {companiesError && <div style={liveNotice} role="alert">{companiesError.replace('Use Sync to retry.', 'Reload to retry.')}</div>}
        {!companiesLoaded ? (
          <div style={revenueChartEmpty} role="status">{companiesError ? 'Company revenue is unavailable. Reload to retry.' : 'Loading company revenue…'}</div>
        ) : (
        <>
        {revenueTab === 'overview' && (
          <>
            <div style={paymentStatusGrid}>
              <DashboardMetric icon="▣" tone="#16a34a" title="Total Collection" value={fmtInr(overviewCollected)} sub="All time collection" />
              <DashboardMetric icon="▥" tone="#60a5fa" title="Paid Companies" value={overviewPaidCompanies} sub="Payment completed" />
              <DashboardMetric icon="□" tone="#f59e0b" title="Pending Collection" value={fmtInr(overviewPendingTotal)} sub="Awaiting payment" />
              <DashboardMetric icon="▥" tone="#f59e0b" title="Total Companies" value={rows.length} sub="Registered companies" />
            </div>
            <div style={revenueChartGrid}>
              <section style={revenueChartPanel}>
                <div style={revenueChartHead}>
                  <h2 style={dashboardCardTitle}>Company Revenue Chart</h2>
                  <span style={revenueChartBadge}>{fmtInr(overviewCollected)} total</span>
                </div>
                <div style={revenueBarChart}>
                  {overviewChartRows.map(row => (
                    <div key={row.id || row.name} style={revenueBarRow}>
                      <span style={revenueBarLabel}>{row.name}</span>
                      <div style={revenueBarTrack}>
                        <span style={{ ...revenueBarFill, width:`${Math.max((row.chartValue / maxChartValue) * 100, row.chartValue > 0 ? 5 : 0)}%` }} />
                      </div>
                      <b style={revenueBarValue}>{fmtInr(row.chartValue)}</b>
                    </div>
                  ))}
                  {!overviewChartRows.length && <div style={revenueChartEmpty}>No revenue data found.</div>}
                </div>
              </section>
              <section style={revenueChartPanel}>
                <div style={revenueChartHead}>
                  <h2 style={dashboardCardTitle}>Collection Split</h2>
                  <span style={revenueChartBadge}>{overviewPaidCompanies}/{rows.length} paid</span>
                </div>
                <div style={revenueSplitWrap}>
                  <div style={revenueDonut(overviewCollected, overviewPendingTotal)}>
                    <div style={revenueDonutInner}>
                      <strong>{fmtInr(overviewCollected)}</strong>
                      <span>Collected</span>
                    </div>
                  </div>
                  <div style={dashboardLegend}>
                    <Legend color="#22c55e" text={`Collected ${fmtInr(overviewCollected)}`} />
                    <Legend color="#f59e0b" text={`Pending ${fmtInr(overviewPendingTotal)}`} />
                    <Legend color="#60a5fa" text={`Companies ${rows.length}`} />
                  </div>
                </div>
              </section>
            </div>
          </>
        )}
        {revenueTab !== 'overview' && (
          <div style={revenueTableWrap}>
            <table style={revenueTableStyle}>
            {revenueTab === 'history' ? (
              <>
                <thead><tr>{['Company', 'Payment ID', 'Amount', 'Status', 'Billing', 'Date'].map(header => <th key={header} style={revenueTableTh}>{header}</th>)}</tr></thead>
                <tbody>
                  {historyLoading ? <tr><td style={revenueTableTd} colSpan="6" role="status">Loading payment history…</td></tr>
                    : historyError ? <tr><td style={revenueTableTd} colSpan="6" role="alert">{historyError} <button type="button" onClick={onRefresh}>Retry</button></td></tr>
                    : historyRows.length ? historyRows.map(row => (
                    <tr key={row.id || `${row.company}-${row.paymentId}`}>
                      <td style={revenueTableTd}>{row.company}</td>
                      <td style={revenueTableTd}>{row.paymentId}</td>
                      <td style={{ ...revenueTableTd, color:'#f59e0b', fontWeight:950 }}>{fmtInr(row.amount)}</td>
                      <td style={revenueTableTd}><span style={revenueStatusPill(row.status === 'captured' || row.status === 'paid')}>{titleCase(row.status)}</span></td>
                      <td style={revenueTableTd}>{titleCase(row.cycle)}</td>
                      <td style={revenueTableTd}>{fmtDate(row.date)}</td>
                    </tr>
                  )) : <tr><td style={{ ...revenueTableTd, textAlign:'center', color:'#64748b' }} colSpan="6">No payment history found.</td></tr>}
                </tbody>
              </>
            ) : (
              <>
                <thead><tr>{['Company', 'Plan', 'LICENSES', 'Monthly Revenue', 'Status', 'Joined'].map(header => <th key={header} style={revenueTableTh}>{header}</th>)}</tr></thead>
                <tbody>
                  {rows.map(row => (
                    <tr key={row.id || row.name}>
                      <td style={revenueTableTd}>
                        <strong style={{ display:'block', color:'#e2e8f0' }}>{row.name}</strong>
                        <span style={{ color:'#64748b', fontSize:12 }}>{row.email || '-'}</span>
                      </td>
                      <td style={revenueTableTd}><span style={revenuePlanPill}>{row.plan || 'custom'}</span></td>
                      <td style={{ ...revenueTableTd, color:'#93c5fd', fontWeight:950 }}>{row.licenseText || formatLicenseBreakdown(row.systems ?? row.agents ?? 0, 0, 0)}</td>
                      <td style={{ ...revenueTableTd, color:'#22c55e', fontWeight:950 }}>{fmtInr(row.monthlyRevenue || 0)}/mo</td>
                      <td style={revenueTableTd}><span style={revenueStatusPill(row.status === 'paid')}>{row.status === 'paid' ? 'ACTIVE' : titleCase(row.status)}</span></td>
                      <td style={revenueTableTd}>{fmtDate(row.joined)}</td>
                    </tr>
                  ))}
                  {!rows.length && <tr><td style={{ ...revenueTableTd, textAlign:'center', color:'#64748b' }} colSpan="6">No companies found for your partner account.</td></tr>}
                </tbody>
              </>
            )}
          </table>
          </div>
        )}
        </>
        )}
      </section>
    </div>
  );
}

function PaymentControlView({ partner, summary, companies = [], onRefresh, setMessage }) {
  const [searchParams] = useSearchParams();
  const [activeTab, setActiveTab] = useState(searchParams.get('tab') === 'enterprise' ? 'enterprise' : 'pricing');
  useEffect(() => { if (searchParams.get('tab') === 'enterprise') setActiveTab('enterprise'); }, [searchParams]);
  const [selectedType, setSelectedType] = useState('new');
  const [livePricing, setLivePricing] = useState(null);
  const [editablePricing, setEditablePricing] = useState({ newUser: null, renewal: null });
  const [pricingHistory, setPricingHistory] = useState([]);
  const [paymentHistoryRows, setPaymentHistoryRows] = useState([]);
  const [savingPricing, setSavingPricing] = useState(false);
  const [deletingPricingIndex, setDeletingPricingIndex] = useState(null);
  const [updatingAutoPayCompanyId, setUpdatingAutoPayCompanyId] = useState('');
  useEffect(() => {
    let mounted = true;
    api.get('/partner/pricing')
      .then(({ data }) => { if (mounted) setLivePricing(data || null); })
      .catch(() => { if (mounted) setLivePricing(null); });
    api.get('/partner/pricing/history')
      .then(({ data }) => { if (mounted) setPricingHistory(data?.history || []); })
      .catch(() => { if (mounted) setPricingHistory([]); });
    api.get('/partner/revenue/history')
      .then(({ data }) => { if (mounted) setPaymentHistoryRows(Array.isArray(data) ? data : []); })
      .catch(() => { if (mounted) setPaymentHistoryRows([]); });
    return () => { mounted = false; };
  }, []);
  const agentPricing = partner.agentPricing || {};
  const fallbackNewUser = {
    pricePerSystemMonthly: Number(agentPricing.system?.monthly ?? agentPricing.monthly ?? 0),
    pricePerSystemYearly: Number(agentPricing.system?.yearly ?? agentPricing.yearly ?? 0),
    pricePerPhoneMonthly: Number(agentPricing.android?.monthly ?? agentPricing.monthly ?? 0),
    pricePerPhoneYearly: Number(agentPricing.android?.yearly ?? agentPricing.yearly ?? 0),
    pricePerServerMonthly: Number(agentPricing.server?.monthly ?? agentPricing.monthly ?? 0),
    pricePerServerYearly: Number(agentPricing.server?.yearly ?? agentPricing.yearly ?? 0),
  };
  useEffect(() => {
    setEditablePricing({
      newUser: { ...(livePricing?.newUser || fallbackNewUser) },
      renewal: { ...(livePricing?.renewal || fallbackNewUser) },
    });
  }, [livePricing, agentPricing.updatedAt]);
  const selectedPricingKey = selectedType === 'renewal' ? 'renewal' : 'newUser';
  const liveRows = [
    { title:'New User', icon:'👤', tone:'#60a5fa', set: livePricing?.newUser || fallbackNewUser },
    { title:'Renewal for Existing User', icon:'🔄', tone:'#a78bfa', set: livePricing?.renewal || fallbackNewUser },
  ];
  const pricingDevices = [
    { name:'System', icon:'▦', tone:'#3b82f6', monthly:'pricePerSystemMonthly', yearly:'pricePerSystemYearly' },
    { name:'Phone', icon:'▯', tone:'#22c55e', monthly:'pricePerPhoneMonthly', yearly:'pricePerPhoneYearly' },
    { name:'Server', icon:'▤', tone:'#8b5cf6', monthly:'pricePerServerMonthly', yearly:'pricePerServerYearly' },
  ];
  const companyPaymentRows = companies
    .map(company => {
      const payment = company.latestPayment || {};
      const amount = Number(payment.amountInr || company.revenue || company.plan?.amountPaid || 0);
      const paymentId = payment.paymentId || payment.orderId || company.razorpay?.paymentId || company.razorpay?.orderId || '';
      if (!amount && !paymentId) return null;
      return {
        id: payment._id || paymentId || company._id,
        company: company.name || 'Company',
        paymentId: paymentId || '-',
        amountInr: amount,
        status: payment.status || company.paymentStatus || company.plan?.paymentStatus || '-',
        paidAt: payment.paidAt || company.lastPaidAt || company.razorpay?.paidAt || payment.createdAt || company.plan?.startDate,
        autoPay: Boolean(payment.autoPay || company.plan?.autoPay || company.autoKeyEnabled),
      };
    })
    .filter(Boolean);
  const platformPaymentRows = (summary.platformPayments || []).map(payment => ({
    id: payment._id || payment.paymentId || payment.orderId,
    company: 'Partner Platform',
    paymentId: payment.paymentId || payment.orderId || '-',
    amountInr: Number(payment.amountInr || 0),
    status: payment.status || '-',
    paidAt: payment.paidAt || payment.createdAt,
    autoPay: Boolean(payment.autoPay),
  }));
  const fullHistoryPaymentRows = paymentHistoryRows.map(payment => ({
    id: payment.id || payment.paymentId,
    company: payment.company || 'Company',
    paymentId: payment.paymentId || '-',
    amountInr: Number(payment.amount || 0),
    status: payment.status || '-',
    paidAt: payment.date,
    autoPay: Boolean(payment.autoPay),
  }));
  const paymentRows = fullHistoryPaymentRows.length ? fullHistoryPaymentRows : (companyPaymentRows.length ? companyPaymentRows : platformPaymentRows);
  const selectedPricingSet = editablePricing[selectedPricingKey] || fallbackNewUser;
  const selectedUserLabel = selectedType === 'renewal' ? 'Renewal Pricing' : 'New User Pricing';
  const setPricingField = (key, value) => {
    const cleanValue = value === '' ? '' : Math.max(Number(value || 0), 0);
    setEditablePricing(prev => ({
      ...prev,
      [selectedPricingKey]: {
        ...(prev[selectedPricingKey] || fallbackNewUser),
        [key]: cleanValue,
      },
    }));
  };
  const impactMonthly = (Number(selectedPricingSet.pricePerSystemMonthly || 0) * 10) +
    (Number(selectedPricingSet.pricePerPhoneMonthly || 0) * 5) +
    Number(selectedPricingSet.pricePerServerMonthly || 0);
  const impactYearly = (Number(selectedPricingSet.pricePerSystemYearly || 0) * 10) +
    (Number(selectedPricingSet.pricePerPhoneYearly || 0) * 5) +
    Number(selectedPricingSet.pricePerServerYearly || 0);
  const savePricing = async () => {
    setSavingPricing(true);
    setMessage?.('');
    try {
      const payload = {
        pricePerSystemMonthly: Number(selectedPricingSet.pricePerSystemMonthly || 0),
        pricePerSystemYearly: Number(selectedPricingSet.pricePerSystemYearly || 0),
        pricePerPhoneMonthly: Number(selectedPricingSet.pricePerPhoneMonthly || 0),
        pricePerPhoneYearly: Number(selectedPricingSet.pricePerPhoneYearly || 0),
        pricePerServerMonthly: Number(selectedPricingSet.pricePerServerMonthly || 0),
        pricePerServerYearly: Number(selectedPricingSet.pricePerServerYearly || 0),
        note: selectedType === 'renewal' ? 'renewal-existing' : 'new-user',
      };
      const { data } = await api.put('/partner/pricing', payload);
      if (data?.pricing) setLivePricing(data.pricing);
      const historyRes = await api.get('/partner/pricing/history').catch(() => ({ data: { history: [] } }));
      setPricingHistory(historyRes.data?.history || []);
      setMessage?.(`${selectedUserLabel} update ho gaya.`);
    } catch (err) {
      setMessage?.(err.response?.data?.message || 'Pricing update nahi ho payi.');
    } finally {
      setSavingPricing(false);
    }
  };
  const deletePricingChange = async (index) => {
    const result = await Swal.fire({
      icon: 'warning',
      title: 'Delete recent change?',
      text: 'Ye history entry remove ho jayegi. Current live pricing change nahi hoga.',
      showCancelButton: true,
      confirmButtonText: 'Delete',
      cancelButtonText: 'Cancel',
      confirmButtonColor: '#dc2626',
      background: '#0c1a2e',
      color: '#e2e8f0',
    });
    if (!result.isConfirmed) return;
    setDeletingPricingIndex(index);
    setMessage?.('');
    try {
      const { data } = await api.delete(`/partner/pricing/history/${index}`);
      setPricingHistory(data?.history || []);
      setMessage?.('Recent change delete ho gaya.');
    } catch (err) {
      setMessage?.(err.response?.data?.message || 'Recent change delete nahi ho paya.');
    } finally {
      setDeletingPricingIndex(null);
    }
  };
  const autoPayEnabledCount = companies.filter(company => company.plan?.autoPay || company.autoKeyEnabled).length;
  const autoPayDisabledCount = Math.max(companies.length - autoPayEnabledCount, 0);
  const autoPayPct = companies.length ? Math.round((autoPayEnabledCount / companies.length) * 100) : 0;
  const updateCompanyAutoPay = async (company, enabled) => {
    setUpdatingAutoPayCompanyId(company._id);
    setMessage?.('');
    try {
      await api.patch(`/partner/companies/${company._id}/autopay`, { enabled });
      setMessage?.(`${company.name} AutoPay ${enabled ? 'enabled' : 'disabled'} ho gaya.`);
      await onRefresh?.();
    } catch (err) {
      setMessage?.(err.response?.data?.message || 'AutoPay update nahi ho paya.');
    } finally {
      setUpdatingAutoPayCompanyId('');
    }
  };

  return (
    <div style={dashboardShell}>
      <header style={dashboardHeader}>
        <h1 style={{ ...dashboardTitle, fontSize:26 }}>💳 Payment Management</h1>
        <p style={{ ...dashboardSubtitle, color:'#64748b' }}>Control dynamic pricing, view subscriptions, manage AutoPay</p>
      </header>

      <div style={paymentControlTabs}>
        {[
          ['pricing', '💵 Dynamic Pricing'],
          ['enterprise', '🏢 Enterprise'],
          ['subscriptions', '📋 Subscriptions'],
          ['payments', '💰 Payments'],
          ['autopay', '🔄 AutoPay Control'],
        ].map(([id, label]) => (
          <button key={id} type="button" onClick={() => setActiveTab(id)} style={activeTab === id ? paymentControlTabActive : paymentControlTab}>{label}</button>
        ))}
      </div>

      {activeTab === 'enterprise' && <EnterpriseManagement baseUrl="/partner/enterprise-plans" initialCompanyId={searchParams.get('companyId')} />}
      {activeTab === 'pricing' && (
        <div style={paymentControlGrid}>
          <div style={paymentControlLeftColumn}>
            <section style={paymentPanel}>
              <h2 style={paymentPanelTitle}>⚡ Current Live Pricing <span style={liveBadge}>● LIVE</span></h2>
              {liveRows.map(row => (
                <div key={row.title} style={livePricingBlock}>
                  <div style={livePricingHeader}>
                    <span style={{ ...livePricingAvatar, background:`${row.tone}22`, color:row.tone }}>{row.icon}</span>
                    <span>
                      <b style={{ color:row.tone }}>{row.title}</b>
                      <small>{row.title === 'New User' ? 'First-time checkout pricing' : 'Existing company renewal pricing'}</small>
                    </span>
                  </div>
                  <div style={pricingMatrix}>
                    <div />
                    <div style={matrixColHead}>1 MONTH<br /><span>(PER UNIT)</span></div>
                    <div style={matrixColHead}>1 YEAR<br /><span>(PER UNIT)</span></div>
                    {pricingDevices.map(device => (
                      <div key={`${row.title}-${device.name}`} style={matrixRow}>
                        <div style={matrixDevice}>
                          <span style={{ ...matrixDeviceIcon, background:`${device.tone}24`, color:device.tone }}>{device.icon}</span>
                          <b>{device.name}</b>
                        </div>
                        {[
                          [fmtInr(row.set?.[device.monthly]), 'per month'],
                          [fmtInr(row.set?.[device.yearly]), 'per year'],
                        ].map(([price, note]) => (
                          <div key={`${device.name}-${note}`} style={matrixPrice}>
                            <strong style={{ color:row.tone }}>{price}</strong>
                            <span>{note}</span>
                            <span>per {device.name.toLowerCase()}</span>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                  <p style={pricingHint}>ⓘ All prices are in Indian Rupees (₹)</p>
                </div>
              ))}
              <p style={pricingUpdated}>Last updated: {livePricing?.updatedAt ? new Date(livePricing.updatedAt).toLocaleString('en-IN') : '-'}</p>
            </section>

            <section style={paymentPanel}>
              <h2 style={paymentPanelTitle}>📊 Recent Changes <span style={changeCountBadge}>{pricingHistory.length}</span></h2>
              {pricingHistory.length ? pricingHistory.slice(0, 6).map((change, idx) => (
                <div key={`${change.changedAt || idx}-${change.note || change.userType}`} style={recentChangeCard}>
                  <div style={recentChangeHead}>
                    <span style={recentDot} />
                    <span>{change.changedAt ? new Date(change.changedAt).toLocaleString('en-IN') : '-'}</span>
                    <span>by {change.changedBy?.name || change.changedBy?.email || 'Admin'}</span>
                    <span style={change.note === 'new-user' || change.userType === 'new-user' ? recentTypeBadge : recentRenewalBadge}>
                      {change.note === 'new-user' || change.userType === 'new-user' ? 'New User' : 'Renewal'}
                    </span>
                    <button
                      type="button"
                      disabled={deletingPricingIndex === idx}
                      onClick={() => deletePricingChange(idx)}
                      style={recentDeleteButton}
                    >
                      {deletingPricingIndex === idx ? 'Deleting...' : 'Delete'}
                    </button>
                  </div>
                  <div style={recentChangeList}>
                    <span>▦ System: {fmtInr(change.pricePerSystemMonthly)}/mo → {fmtInr(change.pricePerSystemYearly)}/yr</span>
                    <span>▯ Phone: {fmtInr(change.pricePerPhoneMonthly)}/mo → {fmtInr(change.pricePerPhoneYearly)}/yr</span>
                    <span>▤ Server: {fmtInr(change.pricePerServerMonthly)}/mo → {fmtInr(change.pricePerServerYearly)}/yr</span>
                  </div>
                </div>
              )) : (
                <div style={recentEmptyState}>No recent pricing changes found.</div>
              )}
              <button type="button" style={viewAllChangesButton}>View all changes ›</button>
            </section>
          </div>

          <div style={paymentControlRightColumn}>
            <section style={updatePricingPanel}>
              <h2 style={updatePricingTitle}>▣ Update Pricing</h2>
              <p style={muted}>Select the user type first. Changes are controlled by Super Admin and go live instantly.</p>
              <div style={stepLabel}>STEP 1 — CHOOSE USER TYPE</div>
              <button type="button" onClick={() => setSelectedType('new')} style={selectedType === 'new' ? userTypeActive : userTypeCard}>
                <span style={userTypeIcon}>👤</span>
                <span><b>New User</b><small>First-time checkout pricing</small></span>
                <span style={radioDot(selectedType === 'new')} />
              </button>
              <button type="button" onClick={() => setSelectedType('renewal')} style={selectedType === 'renewal' ? userTypeActive : userTypeCard}>
                <span style={userTypeIcon}>💵</span>
                <span><b>Renewal Pricing (Latest)</b><small>Existing company renewal pricing</small></span>
                <span style={radioDot(selectedType === 'renewal')} />
              </button>
              {selectedType ? (
                <>
                  <div style={stepLabel}>STEP 2 — EDIT & VIEW USER PRICES</div>
                  {pricingDevices.map(device => (
                    <div key={device.name} style={editPricingCard(device.tone)}>
                      <h3 style={editPricingTitle}><span style={{ ...matrixDeviceIcon, background:`${device.tone}24`, color:device.tone }}>{device.icon}</span>{device.name} Pricing <small>(per {device.name.toLowerCase()}, changeable)</small></h3>
                      <div style={editPricingGrid}>
                        {[
                          ['1 MONTH', `PER ${device.name.toUpperCase()}`, device.monthly],
                          ['1 YEAR', `PER ${device.name.toUpperCase()}`, device.yearly],
                        ].map(([label, sub, key]) => {
                          const value = selectedPricingSet?.[key] ?? 0;
                          return (
                          <label key={`${device.name}-${label}`} style={editPriceLabel}>
                            <span>{label}<small>{sub}</small></span>
                            <input
                              type="number"
                              min="0"
                              value={value}
                              onChange={event => setPricingField(key, event.target.value)}
                              style={editPriceInput}
                            />
                            <em>≈ {fmtInr(value)} per {label.toLowerCase()}</em>
                          </label>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                  <div style={impactPreview}>
                    <b>📊 Impact Preview (10 systems + 5 phones + 1 server)</b>
                    <span>Monthly <strong>{fmtInr(impactMonthly)}</strong></span>
                    <span>Yearly <strong>{fmtInr(impactYearly)}</strong></span>
                  </div>
                  <button type="button" onClick={savePricing} disabled={savingPricing} style={{ ...savePricingButton, opacity:savingPricing ? .65 : 1, cursor:savingPricing ? 'not-allowed' : 'pointer' }}>
                    ▣ {savingPricing ? 'Saving...' : `Save ${selectedUserLabel}`}
                  </button>
                </>
              ) : (
                <div style={selectNotice}>☝ Select a user type above to edit pricing</div>
              )}
            </section>
          </div>
        </div>
      )}

      {activeTab === 'subscriptions' && (
        <section style={paymentPanel}>
          <h2 style={paymentPanelTitle}>📋 Subscriptions</h2>
          <div style={tableWrap}>
            <table style={tableStyle}>
              <thead><tr>{['Company', 'Status', 'Billing', 'Amount', 'Expires At', 'AutoPay'].map(h => <th key={h} style={tableTh}>{h}</th>)}</tr></thead>
              <tbody>
                {companies.length ? companies.map(company => (
                  <tr key={company._id}>
                    <td style={tableTd}>{company.name}</td>
                    <td style={tableTd}><Badge tone={company.plan?.isActive ? 'green' : 'orange'}>{company.plan?.isActive ? 'Active' : 'Inactive'}</Badge></td>
                    <td style={tableTd}>{titleCase(company.plan?.billingCycle || 'Monthly')}</td>
                    <td style={tableTd}>{fmtInr(company.plan?.amountPaid || company.latestPayment?.amountInr || 0)}</td>
                    <td style={tableTd}>{fmtDate(company.plan?.expiresAt || company.latestPayment?.periodEnd)}</td>
                    <td style={tableTd}>{company.plan?.autoPay ? 'Enabled' : 'Disabled'}</td>
                  </tr>
                )) : <tr><td style={{ ...tableTd, textAlign:'center', color:'#64748b' }} colSpan="6">No company subscriptions found.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === 'payments' && (
        <section style={paymentPanel}>
          <h2 style={paymentPanelTitle}>💰 Payments</h2>
          <div style={tableWrap}>
            <table style={tableStyle}>
              <thead><tr>{['Company', 'Payment ID', 'Amount', 'Status', 'Paid At', 'AutoPay'].map(h => <th key={h} style={tableTh}>{h}</th>)}</tr></thead>
              <tbody>
                {paymentRows.length ? paymentRows.map(payment => (
                  <tr key={payment.id || payment.paymentId}>
                    <td style={tableTd}>{payment.company}</td>
                    <td style={tableTd}>{payment.paymentId}</td>
                    <td style={tableTd}>{fmtInr(payment.amountInr || 0)}</td>
                    <td style={tableTd}>{payment.status || '-'}</td>
                    <td style={tableTd}>{fmtDate(payment.paidAt)}</td>
                    <td style={tableTd}>{payment.autoPay ? 'Enabled' : 'Disabled'}</td>
                  </tr>
                )) : <tr><td style={{ ...tableTd, textAlign:'center', color:'#64748b' }} colSpan="6">No payment records yet.</td></tr>}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {activeTab === 'autopay' && (
        <div style={autoPayControlWrap}>
          <div style={autoPayStatsGrid}>
            <div style={autoPayStatCard}>
              <span style={autoPayStatWatermark}>▦</span>
              <span style={autoPayStatLabel}>TOTAL SUBSCRIPTIONS</span>
              <strong style={{ ...autoPayStatValue, color:'#60a5fa' }}>{companies.length}</strong>
            </div>
            <div style={autoPayStatCard}>
              <span style={{ ...autoPayStatWatermark, color:'rgba(34,197,94,.12)' }}>✓</span>
              <span style={autoPayStatLabel}>AUTOPAY ENABLED</span>
              <strong style={{ ...autoPayStatValue, color:'#10b981' }}>{autoPayEnabledCount}</strong>
              <small style={autoPayStatSub}>{autoPayPct}% of total</small>
            </div>
            <div style={autoPayStatCard}>
              <span style={{ ...autoPayStatWatermark, color:'rgba(239,68,68,.12)' }}>×</span>
              <span style={autoPayStatLabel}>AUTOPAY DISABLED</span>
              <strong style={{ ...autoPayStatValue, color:'#ef4444' }}>{autoPayDisabledCount}</strong>
            </div>
          </div>

          <section style={autoPayMandateBox}>
            <span style={autoPayBulb}>💡</span>
            <div>
              <h3 style={autoPayMandateTitle}>AutoPay Mandate</h3>
              <p style={autoPayMandateText}>
                Company Admins can enable AutoPay from their Payments page by authorizing a Razorpay Subscription / UPI AutoPay mandate.
                Partner Admin can enable or disable AutoPay here only for companies registered under this partner.
              </p>
            </div>
          </section>

          <section style={autoPayTableWrap}>
            <table style={autoPayTable}>
              <thead>
                <tr>{['COMPANY', 'LICENSES', 'EXPIRY', 'AUTOPAY', 'ACTION'].map(header => <th key={header} style={autoPayTh}>{header}</th>)}</tr>
              </thead>
              <tbody>
                {companies.length ? companies.map(company => {
                  const enabled = Boolean(company.plan?.autoPay || company.autoKeyEnabled);
                  const busy = updatingAutoPayCompanyId === company._id;
                  const licenses = [
                    Number(company.plan?.systemCount || company.systemCount || 0) ? `${Number(company.plan?.systemCount || company.systemCount || 0)} sys` : '',
                    Number(company.plan?.serverCount || company.serverCount || 0) ? `${Number(company.plan?.serverCount || company.serverCount || 0)} srv` : '',
                    Number(company.plan?.phoneCount || company.phoneCount || 0) ? `${Number(company.plan?.phoneCount || company.phoneCount || 0)} ph` : '',
                  ].filter(Boolean).join(' · ') || '0';
                  return (
                    <tr key={company._id}>
                      <td style={autoPayTd}>
                        <strong style={{ display:'block', color:'#e2e8f0' }}>{company.name}</strong>
                        <span style={{ color:'#64748b', fontSize:12 }}>{company.email || '-'}</span>
                      </td>
                      <td style={{ ...autoPayTd, color:'#60a5fa', fontWeight:950 }}>{licenses}</td>
                      <td style={autoPayTd}>{fmtDate(company.plan?.expiresAt || company.latestPayment?.periodEnd)}</td>
                      <td style={autoPayTd}><span style={enabled ? autoPayOnPill : autoPayOffPill}>{enabled ? '✓ ON' : '× OFF'}</span></td>
                      <td style={autoPayTd}>
                        <button
                          type="button"
                          disabled={busy}
                          onClick={() => updateCompanyAutoPay(company, !enabled)}
                          style={enabled ? autoPayDisableButton : autoPayEnableButton}
                        >
                          {busy ? 'Updating...' : enabled ? 'Disable' : 'Enable'}
                        </button>
                      </td>
                    </tr>
                  );
                }) : <tr><td style={{ ...autoPayTd, textAlign:'center', color:'#64748b' }} colSpan="5">No companies found under this partner.</td></tr>}
              </tbody>
            </table>
          </section>
        </div>
      )}
    </div>
  );
}

function SubscriptionView({ embedded, partner, summary, requestRows, onRefresh }) {
  const [searchParams] = useSearchParams();
  const [subscriptionTab, setSubscriptionTab] = useState(searchParams.get('tab') === 'payments' ? 'payments' : 'subscription');
  const plan = partner.plan || {};
  const platformPayment = (summary.platformPayments || [])[0] || null;
  const startDate = plan.startDate || partner.approvedAt || partner.createdAt;
  const endDate = plan.expiresAt || platformPayment?.periodEnd || addYear(startDate);
  const isPaid = (plan.paymentStatus === 'paid' && plan.isActive) || platformPayment?.status === 'captured' || Boolean(partner.razorpay?.paymentId);
  const platformFee = Number(plan.quote?.amountInr || 0);
  const displayAmount = Number(platformPayment?.amountInr || plan.amountPaid || plan.quote?.amountInr || 0);
  const totalPaid = isPaid ? displayAmount : 0;
  const pendingAmount = isPaid ? 0 : Number(platformFee || summary.pendingRevenue || 0);
  const invoices = buildInvoiceRows(summary, partner);
  const partnerAutoPayEnabled = Boolean(plan.autoPay);

  const disablePartnerAutoPay = async () => {
    try {
      await api.post('/payment/partner-autopay', { enabled: false });
      await Swal.fire({ icon:'success', title:'AutoPay Disabled', timer:1600, showConfirmButton:false, background:'#0c1a2e', color:'#e0f2fe' });
      await onRefresh?.();
    } catch (err) {
      Swal.fire({ icon:'error', title:'AutoPay Error', text:err.response?.data?.message || err.message, background:'#0c1a2e', color:'#e0f2fe' });
    }
  };

  return (
    <>
      <PageHeader embedded={embedded} title="Subscription & Payments" subtitle="Home > Subscription & Payments" />
      <div style={tabs}>
        <button type="button" onClick={() => setSubscriptionTab('subscription')} style={subscriptionTab === 'subscription' ? tabActive : tab}>Subscription</button>
        <button type="button" onClick={() => setSubscriptionTab('payments')} style={subscriptionTab === 'payments' ? tabActive : tab}>Payments & Invoices</button>
      </div>

      {subscriptionTab === 'subscription' && (
        <div style={twoCol}>
          <Card title="Current Plan">
            <div style={planGrid}>
              <div style={planBox}>
                <div style={planIcon}>□</div>
                <div>
                  <h3 style={planName}>{titleCase(plan.type || 'Business Plan')}</h3>
                  <p style={muted}>Ideal for growing businesses</p>
                </div>
                <Badge tone={plan.isActive ? 'green' : 'orange'}>{plan.isActive ? 'Active' : statusLabel(partner.status)}</Badge>
              </div>
              <div style={amountBox}>
                <span>Platform Fee</span>
                <strong>{displayAmount ? fmtInr(displayAmount) : '-'}</strong>
                {partnerAutoPayEnabled ? (
                  <button type="button" onClick={disablePartnerAutoPay} style={dangerButton}>AutoPay Disabled</button>
                ) : (
                  <button type="button" disabled style={autoPayDisabledButton}>AutoPay Disabled</button>
                )}
              </div>
              <div style={detailGrid}>
                <Info label="Start Date" value={fmtDate(startDate)} />
                <Info label="End Date" value={fmtDate(endDate)} />
                <Info label="Next Renewal" value={fmtDate(endDate)} />
                <Info label="Billing Cycle" value={titleCase(plan.billingCycle || 'yearly')} />
                <Info label="AutoPay" value={partnerAutoPayEnabled ? 'Enabled' : 'Disabled'} />
                <Info label="Subscription ID" value={`SUB-${String(partner._id || '2025').slice(-6).toUpperCase()}`} />
              </div>
            </div>
          </Card>

          <Card title="Usage Summary">
            <UsageRow label="Companies" value={summary.totalCompanies} total={summary.companyLimit} tone="#2563eb" />
            <UsageRow label="Agents" value={summary.totalAgents} total={summary.agentLimit} tone="#16a34a" />
            <UsageRow label="Logs Retention" value={60} total={90} suffix=" Days" tone="#f97316" />
          </Card>
        </div>
      )}

      {subscriptionTab === 'payments' && (
        <Card
          title="Payments & Invoices"
          subtitle="View your payment summary and invoice history"
        >
          <div style={paymentStats}>
            <MiniStat label="Total Paid" value={fmtInr(totalPaid)} tone="#16a34a" sub="All time payments" />
            <MiniStat label="Last Payment" value={isPaid ? fmtInr(totalPaid) : '-'} tone="#2563eb" sub={isPaid ? fmtDate(partner.razorpay?.paidAt || platformPayment?.paidAt || plan.startDate) : 'No payment yet'} />
            <MiniStat label="Next Due Date" value={fmtDate(endDate)} tone="#7c3aed" sub="Subscription renewal" />
          </div>
          <DataTable
            headers={['Payment ID', 'Date', 'Amount', 'Status', 'Due Date', 'Payment Date', 'AutoPay']}
            rows={invoices}
            empty="No invoices yet."
            renderRow={invoice => (
              <tr key={invoice.id}>
                <td style={tableTd}>{invoice.paymentId || '-'}</td>
                <td style={tableTd}>{invoice.date}</td>
                <td style={tableTd}>{invoice.amount}</td>
                <td style={tableTd}><Badge tone={invoice.statusTone}>{invoice.status}</Badge></td>
                <td style={tableTd}>{invoice.dueDate}</td>
                <td style={tableTd}>{invoice.paymentDate}</td>
                <td style={tableTd}>{invoice.method}</td>
              </tr>
            )}
          />
        </Card>
      )}
    </>
  );
}

function RequestsView({ embedded, requestTab, setRequestTab, requestRows, showRequestForm, setShowRequestForm, request, setRequestField, submitRequest, saving }) {
  const pending = requestRows.filter(row => row.status === 'Pending').length;
  const approved = requestRows.filter(row => row.status === 'Approved').length;
  const rejected = requestRows.filter(row => row.status === 'Rejected').length;
  const openRows = requestRows.filter(row => ['Pending', 'Negotiation'].includes(row.status));
  const approvedRows = requestRows.filter(row => row.status === 'Approved');
  const activeRequestTab = requestTab === 'approved' || (!openRows.length && approvedRows.length) ? 'approved' : 'resource';
  const visibleRows = activeRequestTab === 'approved' ? approvedRows : openRows;

  return (
    <>
      <PageHeader embedded={embedded} title="Requests" subtitle="Track and manage all your requests" />
      <div style={embedded ? embeddedRequestLayout : requestLayout}>
        <main>
          <div style={statGrid}>
            <StatCard tone="#2563eb" icon="▤" label="Total Requests" value={requestRows.length} sub="All time requests" />
            <StatCard tone="#f59e0b" icon="◷" label="Pending" value={pending} sub="Awaiting approval" />
            <StatCard tone="#16a34a" icon="✓" label="Approved" value={approved} sub="Requests approved" />
            <StatCard tone="#ef4444" icon="×" label="Rejected" value={rejected} sub="Requests rejected" />
          </div>

          <Card>
            <div style={requestTabs}>
              <button type="button" onClick={() => setRequestTab('resource')} style={activeRequestTab === 'resource' ? tabActive : tab}>Resource Requests <Badge tone="blue">{openRows.length}</Badge></button>
              <button type="button" onClick={() => setRequestTab('approved')} style={activeRequestTab === 'approved' ? tabActive : tab}>Approved Requests <Badge tone="green">{approved}</Badge></button>
            </div>
            <h3 style={sectionTitle}>{activeRequestTab === 'approved' ? 'Approved Requests' : 'Resource Requests'}</h3>
            <p style={muted}>{activeRequestTab === 'approved' ? 'Approved company, agent and commission requests' : 'Request additional companies, agents or other resources'}</p>
            <div style={filters}>
              <select style={filterInput}><option>All Status</option></select>
              <select style={filterInput}><option>All Types</option></select>
              <input style={filterInput} placeholder="Select Date Range" />
            </div>
            <DataTable
              headers={['Request ID', 'Agent Limit', 'Company Limit', 'Commission', 'Details', 'Requested', 'Status', 'Last Updated', 'Action']}
              rows={visibleRows}
              empty={activeRequestTab === 'approved' ? 'No approved requests yet.' : 'No open requests yet. Create a new request from the right panel.'}
              renderRow={row => (
                <tr key={row.id}>
                  <td style={tableTd}>{row.id}</td>
                  <td style={tableTd}>{row.agentLimit}</td>
                  <td style={tableTd}>{row.companyLimit}</td>
                  <td style={tableTd}>{row.commission}</td>
                  <td style={tableTd}>{row.details}</td>
                  <td style={tableTd}>{row.requested}</td>
                  <td style={tableTd}><Badge tone={row.statusTone}>{row.status}</Badge></td>
                  <td style={tableTd}>{row.updated}</td>
                  <td style={tableTd}><button style={linkButton}>View</button></td>
                </tr>
              )}
            />
          </Card>
        </main>

        <aside style={embedded ? embeddedRequestAside : requestAside}>
          <Card title="New Request">
            <p style={muted}>Need more resources or have any special requirements?</p>
            <button onClick={() => setShowRequestForm(!showRequestForm)} style={{ ...primaryButton, width:'100%' }}>Create New Request +</button>
            {showRequestForm && (
              <form onSubmit={submitRequest} style={{ display:'grid', gap:10, marginTop:14 }}>
                <Input label="Company Limit Increase" type="number" value={request.numberOfCompanies} onChange={value => setRequestField('numberOfCompanies', value)} />
                <Input label="Agent Limit Increase" type="number" value={request.numberOfAgents} onChange={value => setRequestField('numberOfAgents', value)} />
                <Input label="Commission %" type="number" value={request.proposedCommission} onChange={value => setRequestField('proposedCommission', value)} />
                <button disabled={saving} style={primaryButton}>{saving ? 'Submitting...' : 'Submit Request'}</button>
              </form>
            )}
          </Card>
          <Card title="Request Process">
            <ProcessStep n="1" text="Submit your request with details" />
            <ProcessStep n="2" text="Our team will review it" />
            <ProcessStep n="3" text="You will be notified about the status" />
          </Card>
        </aside>
      </div>
    </>
  );
}

function PageHeader({ embedded, title, subtitle }) {
  return (
    <header style={pageHeader}>
      <div>
        <h1 style={pageTitle}>{title}</h1>
        <p style={pageSubtitle}>{subtitle}</p>
      </div>
      {!embedded && <div style={profilePill}>
        <span style={{ fontSize:20 }}>♢</span>
        <span style={avatar}>A</span>
        <div>
          <b>Abhi Tech Pvt. Ltd.</b>
          <small>Partner Admin</small>
        </div>
        <span>⌄</span>
      </div>}
    </header>
  );
}

function Card({ title, subtitle, actions, children }) {
  return (
    <section style={card}>
      {(title || actions) && (
        <div style={cardHeader}>
          <div>
            {title && <h2 style={cardTitle}>{title}</h2>}
            {subtitle && <p style={muted}>{subtitle}</p>}
          </div>
          {actions && <div style={{ display:'flex', gap:10, flexWrap:'wrap' }}>{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

function StatCard({ tone, icon, label, value, sub }) {
  return (
    <section style={statCard}>
      <span style={{ ...statIcon, background:`${tone}16`, color:tone }}>{icon}</span>
      <div>
        <p style={statLabel}>{label}</p>
        <strong style={statValue}>{value}</strong>
        <p style={statSub}>{sub}</p>
      </div>
    </section>
  );
}

function DashboardMetric({ tone, icon, title, value, sub, success }) {
  return (
    <section style={dashboardMetric}>
      <div style={dashboardMetricContent}>
        <p style={dashboardMetricLabel}>{title}</p>
        <strong style={{ ...dashboardMetricValue, color:success ? '#34d399' : '#e0f2fe' }}>{value}</strong>
        <small style={dashboardMetricSub}>{sub}</small>
      </div>
      <span style={{ ...dashboardMetricIcon, background:`${tone}14`, color:tone }}>{icon}</span>
    </section>
  );
}

function CompactUsage({ label, value, total, suffix = '' }) {
  const pct = percent(value, total);
  return (
    <div style={compactUsage}>
      <span>{label}</span>
      <b>{value}{suffix} / {total}{suffix}</b>
      <div style={compactTrack}><i style={{ ...compactFill, width:`${pct}%` }} /></div>
      <em>{pct}%</em>
    </div>
  );
}

function SettlementLine({ label, value }) {
  return (
    <div style={settlementLine}>
      <span>{label}</span>
      <b>{value || '-'}</b>
    </div>
  );
}

function MiniStat({ label, value, sub, tone }) {
  return (
    <div style={miniStat}>
      <span>{label}</span>
      <strong style={{ color:tone }}>{value}</strong>
      <small>{sub}</small>
    </div>
  );
}

function UsageRow({ label, value, total, suffix = '', tone }) {
  const pct = percent(value, total);
  return (
    <div style={usageRow}>
      <span style={usageIcon(tone)}>{label[0]}</span>
      <div style={{ flex:1 }}>
        <div style={usageMeta}>
          <b>{label}</b>
          <span>{value}{suffix} / {total}{suffix}</span>
          <em style={{ color:tone }}>{pct}% Used</em>
        </div>
        <div style={usageTrack}><span style={{ width:`${pct}%`, background:tone }} /></div>
      </div>
    </div>
  );
}

function DataTable({ headers, rows, renderRow, empty }) {
  return (
    <div style={tableWrap}>
      <table style={tableStyle}>
        <thead>
          <tr>{headers.map(header => <th key={header} style={tableTh}>{header}</th>)}</tr>
        </thead>
        <tbody>
          {rows.length ? rows.map(renderRow) : (
            <tr><td colSpan={headers.length} style={{ textAlign:'center', color:'#64748b', padding:28 }}>{empty}</td></tr>
          )}
        </tbody>
      </table>
    </div>
  );
}

function Badge({ tone = 'gray', children }) {
  const colors = {
    green: ['#dcfce7', '#16a34a'],
    orange: ['#ffedd5', '#f97316'],
    blue: ['#dbeafe', '#2563eb'],
    purple: ['#ede9fe', '#7c3aed'],
    red: ['#ffe4e6', '#e11d48'],
    gray: ['#f1f5f9', '#475569'],
  }[tone] || ['#f1f5f9', '#475569'];
  return <span style={{ borderRadius:6, background:colors[0], color:colors[1], padding:'4px 8px', fontSize:11, fontWeight:900 }}>{children}</span>;
}

function Info({ label, value }) {
  return (
    <div style={infoRow}>
      <span>{label}</span>
      <b>{value}</b>
    </div>
  );
}

function Input({ label, value, onChange, type = 'text' }) {
  return (
    <label style={labelStyle}>
      {label}
      <input type={type} value={value} onChange={e => onChange(e.target.value)} style={inputStyle} />
    </label>
  );
}

function RequestType({ tone, icon, title, text }) {
  return (
    <div style={requestType}>
      <span style={{ ...requestTypeIcon, background:`${tone}16`, color:tone }}>{icon}</span>
      <div>
        <b>{title}</b>
        <p>{text}</p>
      </div>
    </div>
  );
}

function ProcessStep({ n, text }) {
  return (
    <div style={processStep}>
      <span>{n}</span>
      <p>{text}</p>
    </div>
  );
}

function Legend({ color, text }) {
  return <div style={legend}><span style={{ background:color }} />{text}</div>;
}

function buildRequestRows(history, resource, partner) {
  const rows = Array.isArray(history) && history.length ? history : (
    resource?.status && resource.status !== 'none' ? [{
      requestId: `REQ-${String(partner?._id || '000001').slice(-6).toUpperCase()}`,
      ...resource,
    }] : []
  );
  return rows
    .slice()
    .sort((a, b) => new Date(b.requestedAt || 0) - new Date(a.requestedAt || 0))
    .map((item, index) => {
      const status = item.status === 'approved' ? 'Approved' : item.status === 'rejected' ? 'Rejected' : item.status === 'negotiation' ? 'Negotiation' : 'Pending';
      return {
        id: item.requestId || `REQ-${String(partner?._id || '000001').slice(-4).toUpperCase()}-${index + 1}`,
        agentLimit: Number(item.numberOfAgents || 0),
        companyLimit: Number(item.numberOfCompanies || 0),
        commission: `${Number(item.proposedCommission || 0)}%`,
        details: item.additionalNotes || item.adminNote || 'Resource limit request',
        requested: fmtDate(item.requestedAt || partner.createdAt),
        updated: fmtDate(item.reviewedAt || item.requestedAt || partner.updatedAt),
        status,
        statusTone: status === 'Approved' ? 'green' : status === 'Rejected' ? 'red' : status === 'Negotiation' ? 'purple' : 'orange',
      };
    });
}

function buildInvoiceRows(summary, partner) {
  const plan = partner.plan || {};
  const platformPayments = summary.platformPayments || [];
  if (platformPayments.length) {
    return platformPayments.map((payment, index) => ({
      id:`INV-${String(payment.paymentId || payment.orderId || partner._id || index).slice(-8).toUpperCase()}`,
      paymentId:payment.paymentId || payment.orderId || '-',
      date:fmtDate(payment.createdAt),
      amount:fmtInr(payment.amountInr),
      status:payment.status === 'captured' ? 'Paid' : titleCase(payment.status || 'Pending'),
      statusTone:payment.status === 'captured' ? 'green' : 'orange',
      dueDate:fmtDate(payment.periodEnd || plan.expiresAt),
      paymentDate:payment.paidAt ? fmtDate(payment.paidAt) : '-',
      method:payment.autoPay || payment.notes?.autoPay || plan.autoPay ? 'Enabled' : 'Disabled',
    }));
  }
  const isPaid = plan.paymentStatus === 'paid' && plan.isActive;
  const paid = Number(plan.amountPaid || summary.paidRevenue || 0);
  const pending = Number(plan.quote?.amountInr || summary.pendingRevenue || 0);
  const invoiceDate = plan.quote?.quotedAt || partner.approvedAt || partner.createdAt;
  const paidAt = partner.razorpay?.paidAt || plan.startDate;
  if (isPaid) {
    return [{
      id:`INV-${String(partner._id || '2026').slice(-6).toUpperCase()}`,
      paymentId:partner.razorpay?.paymentId || partner.razorpay?.orderId || '-',
      date:fmtDate(paidAt || invoiceDate),
      amount:fmtInr(paid),
      status:'Paid',
      statusTone:'green',
      dueDate:fmtDate(plan.expiresAt || addYear(paidAt || invoiceDate)),
      paymentDate:fmtDate(paidAt),
      method:plan.autoPay ? 'Enabled' : 'Disabled',
    }];
  }
  if (pending > 0) {
    return [{
      id:`INV-${String(partner._id || '2026').slice(-6).toUpperCase()}`,
      paymentId:'-',
      date:fmtDate(invoiceDate),
      amount:fmtInr(pending),
      status:'Pending',
      statusTone:'orange',
      dueDate:fmtDate(plan.quote?.quotedAt || partner.updatedAt || partner.createdAt),
      paymentDate:'-',
      method:plan.autoPay ? 'Enabled' : 'Disabled',
    }];
  }
  return [];
}

function dashboardActivity(companies) {
  const rows = companies.slice(0, 1).map(company => ({
    activity: 'Company Created',
    details: company.name,
    date: company.createdAt ? new Date(company.createdAt).toLocaleString('en-IN', { day:'2-digit', month:'short', year:'numeric', hour:'2-digit', minute:'2-digit' }) : '-',
  }));
  return [
    ...rows,
    { activity:'Agent Installed', details:'Agent installed on DESKTOP-01', date:'20 May 2024 11:15 AM' },
  ].slice(0, 2);
}

function fmtInr(value) {
  return `₹${Number(value || 0).toLocaleString('en-IN')}`;
}

function fmtDate(value) {
  return value ? new Date(value).toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' }) : '-';
}

function formatLicenseBreakdown(systemCount = 0, serverCount = 0, phoneCount = 0) {
  const items = [
    [Number(systemCount || 0), 'sys'],
    [Number(serverCount || 0), 'srv'],
    [Number(phoneCount || 0), 'ph'],
  ];
  return items
    .filter(([value]) => value > 0)
    .map(([value, label]) => `${value} ${label}`)
    .join(' · ') || '0';
}

function addYear(value) {
  const date = value ? new Date(value) : new Date();
  date.setFullYear(date.getFullYear() + 1);
  return date;
}

function percent(value, total) {
  return Math.min(100, Math.round((Number(value || 0) / Math.max(Number(total || 1), 1)) * 100));
}

function titleCase(value = '') {
  return String(value).replace(/[_-]/g, ' ').replace(/\b\w/g, char => char.toUpperCase());
}

function statusLabel(status) {
  if (['approved', 'active', 'pending_payment'].includes(status)) return 'Active';
  if (status === 'pending_request') return 'Pending';
  if (status === 'suspended') return 'Suspended';
  return titleCase(status || 'Pending');
}

function typeIcon(tone) {
  return { display:'inline-grid', placeItems:'center', width:30, height:30, borderRadius:7, background:`${tone}14`, color:tone, marginRight:8, fontWeight:900 };
}

function usageIcon(tone) {
  return { display:'grid', placeItems:'center', width:42, height:42, borderRadius:14, background:`${tone}14`, color:tone, fontWeight:900 };
}

function donut(active, total) {
  const pct = percent(active, total);
  return {
    width:154,
    height:154,
    borderRadius:'50%',
    background:`conic-gradient(#16a34a 0 ${pct}%, #e2e8f0 ${pct}% 100%)`,
    display:'grid',
    placeItems:'center',
  };
}

function dashboardDonut(active, total) {
  const activePct = percent(active, total);
  const inactivePct = Math.min(100, activePct + Math.max(10, 100 - activePct));
  return {
    width:154,
    height:154,
    borderRadius:'50%',
    background:`conic-gradient(#16a34a 0 ${activePct}%, #ef4444 ${activePct}% ${inactivePct}%, #e2e8f0 ${inactivePct}% 100%)`,
    display:'grid',
    placeItems:'center',
  };
}

function revenueDonut(collected, pending) {
  const total = Math.max(Number(collected || 0) + Number(pending || 0), 1);
  const collectedPct = Math.max(0, Math.min(100, (Number(collected || 0) / total) * 100));
  return {
    width:164,
    height:164,
    borderRadius:'50%',
    background:`conic-gradient(#22c55e 0 ${collectedPct}%, #f59e0b ${collectedPct}% 100%)`,
    display:'grid',
    placeItems:'center',
  };
}

const page = { minHeight:'100%', background:'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', color:'#e2e8f0', margin:-30, padding:'26px 30px 34px', fontFamily:'Inter, system-ui, sans-serif' };
const embeddedPage = { minHeight:'100%', background:'transparent', color:'#e2e8f0', margin:0, padding:0, fontFamily:'Inter, system-ui, sans-serif', position:'relative', zIndex:2, overflow:'visible', isolation:'isolate' };
const pageHeader = { display:'flex', justifyContent:'space-between', gap:20, alignItems:'flex-start', marginBottom:22 };
const pageTitle = { margin:'0 0 8px', fontSize:28, lineHeight:1, fontWeight:950, color:'#e0f2fe' };
const pageSubtitle = { margin:0, color:'#60a5fa', fontSize:14 };
const profilePill = { display:'flex', alignItems:'center', gap:14, color:'#e0f2fe', fontSize:13, background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8, padding:'8px 10px', boxShadow:'0 10px 24px rgba(0,0,0,.24)' };
const avatar = { width:44, height:44, borderRadius:'50%', background:'linear-gradient(135deg,#102a56,#2563eb)', color:'#fff', display:'grid', placeItems:'center', fontWeight:900 };
const statGrid = { display:'grid', gridTemplateColumns:'repeat(4, minmax(160px, 1fr))', gap:18, marginBottom:22 };
const statCard = { background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8, padding:'22px 24px', display:'flex', alignItems:'center', gap:18, boxShadow:'0 10px 24px rgba(0,0,0,.24)' };
const statIcon = { width:56, height:56, borderRadius:8, display:'grid', placeItems:'center', fontSize:26, fontWeight:900 };
const statLabel = { margin:'0 0 6px', color:'#93c5fd', fontSize:13, fontWeight:850 };
const statValue = { display:'block', color:'#e0f2fe', fontSize:29, lineHeight:1, fontWeight:950 };
const statSub = { margin:'8px 0 0', color:'#60a5fa', fontSize:13 };
const twoCol = { display:'grid', gridTemplateColumns:'1fr 1fr', gap:20, marginBottom:20 };
const card = { background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8, padding:22, boxShadow:'0 10px 24px rgba(0,0,0,.24)', marginBottom:20 };
const cardHeader = { display:'flex', justifyContent:'space-between', gap:16, alignItems:'flex-start', marginBottom:18 };
const cardTitle = { margin:'0 0 4px', fontSize:18, color:'#e0f2fe', fontWeight:950 };
const muted = { margin:0, color:'#94a3b8', fontSize:13, lineHeight:1.5 };
const tabs = { display:'flex', gap:22, borderBottom:'1px solid #1e3a5f', marginBottom:20 };
const tab = { border:'none', background:'transparent', color:'#94a3b8', padding:'13px 0', fontSize:13, fontWeight:900, cursor:'pointer' };
const tabActive = { ...tab, color:'#60a5fa', borderBottom:'3px solid #60a5fa' };
const paymentControlTabs = { display:'flex', gap:42, borderBottom:'1px solid #1e3a5f', margin:'22px 0', overflowX:'auto' };
const paymentControlTab = { border:'none', background:'transparent', color:'#64748b', padding:'13px 0', fontSize:14, fontWeight:900, cursor:'pointer', whiteSpace:'nowrap' };
const paymentControlTabActive = { ...paymentControlTab, color:'#60a5fa', borderBottom:'3px solid #60a5fa' };
const paymentControlGrid = { display:'grid', gridTemplateColumns:'minmax(460px, .95fr) minmax(480px, 1.05fr)', gap:24, alignItems:'start' };
const paymentControlLeftColumn = { display:'grid', gap:20 };
const paymentControlRightColumn = { display:'grid', gap:20 };
const paymentPanel = { background:'rgba(30,41,59,.72)', border:'1px solid #1e3a5f', borderRadius:18, padding:28, boxShadow:'0 14px 32px rgba(0,0,0,.28)' };
const paymentPanelTitle = { margin:'0 0 18px', color:'#f1f5f9', fontSize:20, fontWeight:950, display:'flex', alignItems:'center', gap:8 };
const autoPayControlWrap = { display:'grid', gap:28 };
const autoPayStatsGrid = { display:'grid', gridTemplateColumns:'repeat(3, minmax(220px, 1fr))', gap:20 };
const autoPayStatCard = { position:'relative', overflow:'hidden', minHeight:128, border:'1px solid #1e3a5f', borderRadius:18, background:'rgba(30,41,59,.72)', padding:'28px 32px', boxSizing:'border-box' };
const autoPayStatWatermark = { position:'absolute', right:20, top:4, color:'rgba(96,165,250,.12)', fontSize:82, lineHeight:1, fontWeight:950 };
const autoPayStatLabel = { display:'block', color:'#64748b', fontSize:13, fontWeight:950, letterSpacing:.7 };
const autoPayStatValue = { display:'block', marginTop:12, fontSize:34, lineHeight:1, fontWeight:950 };
const autoPayStatSub = { display:'block', marginTop:8, color:'#94a3b8', fontSize:13, fontWeight:800 };
const autoPayMandateBox = { display:'grid', gridTemplateColumns:'54px 1fr', gap:18, alignItems:'start', border:'1px solid rgba(245,158,11,.55)', borderRadius:18, background:'rgba(15,23,42,.72)', padding:'28px 34px' };
const autoPayBulb = { fontSize:34, lineHeight:1 };
const autoPayMandateTitle = { margin:'0 0 8px', color:'#facc15', fontSize:17, fontWeight:950 };
const autoPayMandateText = { margin:0, color:'#94a3b8', fontSize:15, lineHeight:1.65, fontWeight:750 };
const autoPayTableWrap = { border:'1px solid #1e3a5f', borderRadius:18, overflow:'hidden', background:'rgba(30,41,59,.72)' };
const autoPayTable = { width:'100%', borderCollapse:'collapse', fontSize:14 };
const autoPayTh = { textAlign:'left', padding:'16px 28px', color:'#64748b', background:'#081525', borderBottom:'1px solid #1e3a5f', fontSize:13, fontWeight:950, letterSpacing:.7 };
const autoPayTd = { padding:'16px 28px', color:'#94a3b8', borderBottom:'1px solid rgba(30,58,95,.72)', verticalAlign:'middle' };
const autoPayOnPill = { display:'inline-flex', minWidth:76, justifyContent:'center', borderRadius:999, background:'rgba(16,185,129,.16)', color:'#34d399', border:'1px solid rgba(16,185,129,.38)', padding:'5px 12px', fontSize:13, fontWeight:950 };
const autoPayOffPill = { ...autoPayOnPill, background:'rgba(239,68,68,.16)', color:'#ff5b5b', border:'1px solid rgba(239,68,68,.42)' };
const autoPayEnableButton = { minWidth:160, height:34, border:'none', borderRadius:8, background:'rgba(20,184,166,.22)', color:'#34d399', fontWeight:950, cursor:'pointer' };
const autoPayDisableButton = { ...autoPayEnableButton, background:'rgba(239,68,68,.18)', color:'#fecaca' };
const liveBadge = { marginLeft:2, border:'1px solid rgba(16,185,129,.35)', background:'rgba(16,185,129,.12)', color:'#34d399', borderRadius:999, padding:'3px 10px', fontSize:11, fontWeight:950 };
const livePricingBlock = { border:'1px solid #1e3a5f', borderRadius:10, background:'#0c1a2e', padding:14, marginBottom:14 };
const livePricingHeader = { display:'flex', alignItems:'center', gap:10, marginBottom:12 };
const livePricingAvatar = { width:34, height:34, borderRadius:8, display:'grid', placeItems:'center', fontSize:18, fontWeight:950 };
const pricingMatrix = { display:'grid', gridTemplateColumns:'82px repeat(2, minmax(0,1fr))', gap:8, alignItems:'stretch' };
const matrixColHead = { color:'#93c5fd', fontSize:10, fontWeight:950, textAlign:'center', lineHeight:1.25 };
const matrixRow = { display:'contents' };
const matrixDevice = { display:'grid', placeItems:'center', gap:5, color:'#cbd5e1', fontSize:11, fontWeight:900 };
const matrixDeviceIcon = { width:30, height:30, borderRadius:7, display:'grid', placeItems:'center', fontSize:14, fontWeight:950 };
const matrixPrice = { minHeight:74, borderRadius:8, background:'rgba(0,0,0,.28)', display:'grid', placeItems:'center', alignContent:'center', gap:2, textAlign:'center', padding:'8px 6px' };
const pricingHint = { margin:'10px 0 0', color:'#64748b', fontSize:10, fontWeight:800 };
const pricingGroup = { border:'1px solid #1e3a5f', borderRadius:14, background:'#0c1a2e', padding:18, marginBottom:18 };
const pricingGroupTitle = { margin:'0 0 14px', fontSize:14, fontWeight:950 };
const pricingCards = { display:'grid', gridTemplateColumns:'repeat(2, minmax(0,1fr))', gap:10 };
const pricingBox = { minHeight:58, borderRadius:10, background:'rgba(0,0,0,.28)', padding:'10px 12px', display:'grid', alignContent:'center', gap:3 };
const pricingLabel = { color:'#475569', fontSize:11, fontWeight:900 };
const pricingUpdated = { margin:'12px 0 0', color:'#475569', fontSize:12, fontWeight:700 };
const updatePricingPanel = { ...paymentPanel, border:'2px solid #2563eb' };
const updatePricingTitle = { margin:'0 0 8px', color:'#60a5fa', fontSize:21, fontWeight:950 };
const stepLabel = { color:'#fbbf24', fontSize:12, fontWeight:950, margin:'24px 0 10px', letterSpacing:.5 };
const userTypeCard = { width:'100%', minHeight:70, display:'flex', alignItems:'center', gap:14, border:'1px solid #1e3a5f', borderRadius:10, background:'#0c1a2e', color:'#94a3b8', padding:'0 16px', marginBottom:12, textAlign:'left', cursor:'pointer' };
const userTypeActive = { ...userTypeCard, border:'1px solid #2563eb', color:'#e0f2fe', background:'rgba(37,99,235,.14)' };
const userTypeIcon = { width:42, fontSize:28 };
const selectNotice = { minHeight:76, border:'1px dashed #1e3a5f', borderRadius:12, background:'#07111f', color:'#475569', display:'grid', placeItems:'center', fontSize:14, fontWeight:800, marginTop:18 };
const changeCountBadge = { background:'#1e3a5f', color:'#94a3b8', borderRadius:999, minWidth:22, height:22, padding:'0 8px', display:'inline-grid', placeItems:'center', fontSize:12, fontWeight:950 };
const recentChangeCard = { background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:12, padding:18 };
const recentChangeHead = { display:'flex', alignItems:'center', gap:9, color:'#64748b', fontSize:12, fontWeight:800, marginBottom:12, flexWrap:'wrap' };
const recentDot = { width:9, height:9, borderRadius:'50%', background:'#7c3aed', display:'inline-block' };
const recentTypeBadge = { border:'1px solid rgba(124,58,237,.35)', background:'rgba(124,58,237,.16)', color:'#c4b5fd', borderRadius:999, padding:'2px 9px', fontSize:11, fontWeight:950 };
const recentRenewalBadge = { ...recentTypeBadge, color:'#a78bfa', background:'rgba(167,139,250,.14)' };
const recentChangeGrid = { display:'grid', gridTemplateColumns:'repeat(2, minmax(0, 1fr))', gap:10, color:'#93c5fd', fontSize:13, fontWeight:850 };
const recentChangeList = { display:'grid', gap:7, color:'#93c5fd', fontSize:12, fontWeight:850 };
const recentDeleteButton = { marginLeft:'auto', minHeight:28, border:'1px solid rgba(239,68,68,.35)', borderRadius:7, background:'rgba(239,68,68,.12)', color:'#fecaca', padding:'0 10px', fontSize:11, fontWeight:950, cursor:'pointer' };
const recentEmptyState = { minHeight:92, border:'1px dashed #1e3a5f', borderRadius:12, display:'grid', placeItems:'center', color:'#64748b', fontSize:13, fontWeight:850, background:'#0c1a2e' };
const viewAllChangesButton = { width:'100%', marginTop:12, height:34, border:'1px solid #1e3a5f', borderRadius:8, background:'#07111f', color:'#93c5fd', fontWeight:950, cursor:'pointer' };
const radioDot = (on) => ({ marginLeft:'auto', width:16, height:16, borderRadius:'50%', border:`2px solid ${on ? '#3b82f6' : '#334155'}`, background:on ? 'radial-gradient(circle, #3b82f6 0 42%, transparent 45%)' : 'transparent', flexShrink:0 });
const editPricingCard = (tone) => ({ border:`1px solid ${tone}33`, background:`${tone}0f`, borderRadius:10, padding:14, marginBottom:12 });
const editPricingTitle = { display:'flex', alignItems:'center', gap:9, margin:'0 0 12px', color:'#e0f2fe', fontSize:13, fontWeight:950 };
const editPricingGrid = { display:'grid', gridTemplateColumns:'repeat(2, minmax(0,1fr))', gap:10 };
const editPriceLabel = { display:'grid', gap:7, color:'#94a3b8', fontSize:10, fontWeight:950 };
const editPriceInput = { height:38, border:'1px solid #0f172a', borderRadius:5, background:'#07111f', color:'#e0f2fe', padding:'0 10px', fontWeight:900, outline:'none' };
const impactPreview = { display:'grid', gridTemplateColumns:'1fr repeat(2, auto)', gap:12, alignItems:'center', border:'1px solid rgba(245,158,11,.25)', background:'rgba(245,158,11,.08)', borderRadius:10, padding:14, color:'#fbbf24', fontSize:12, fontWeight:850, margin:'12px 0' };
const savePricingButton = { width:'100%', height:44, border:'none', borderRadius:8, background:'#16a34a', color:'#ecfdf5', fontSize:13, fontWeight:950, cursor:'pointer' };
const paymentStatusGrid = { display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:16 };
const companyPaymentCard = { background:'#081525', border:'1px solid #1e3a5f', borderRadius:8, padding:16, minHeight:154, boxSizing:'border-box' };
const revenueTabHeader = { display:'flex', gap:28, flexWrap:'wrap', margin:'-2px 0 28px', borderBottom:'1px solid #1e3a5f', padding:'0 18px' };
const revenueTabButton = { minHeight:44, border:'none', borderBottom:'2px solid transparent', background:'transparent', color:'#64748b', padding:'0 6px', fontSize:14, fontWeight:850, cursor:'pointer' };
const revenueTabActive = { ...revenueTabButton, color:'#60a5fa', borderBottom:'2px solid #3b82f6' };
const revenueTableWrap = { border:'1px solid #1e3a5f', borderRadius:10, overflow:'hidden', background:'#081525' };
const revenueTableStyle = { width:'100%', borderCollapse:'collapse', fontSize:14 };
const revenueTableTh = { textAlign:'left', padding:'14px 18px', color:'#2563eb', background:'#07111f', borderBottom:'1px solid #1e3a5f', fontSize:13, fontWeight:950 };
const revenueTableTd = { padding:'14px 18px', color:'#94a3b8', borderBottom:'1px solid rgba(30,58,95,.72)', verticalAlign:'middle' };
const revenuePlanPill = { display:'inline-flex', minWidth:68, justifyContent:'center', borderRadius:999, background:'#1d4e89', color:'#93c5fd', padding:'4px 10px', fontSize:11, fontWeight:950 };
const revenueStatusPill = active => ({ display:'inline-flex', minWidth:68, justifyContent:'center', borderRadius:999, background:active ? 'rgba(34,197,94,.08)' : 'rgba(245,158,11,.1)', color:active ? '#22c55e' : '#f59e0b', padding:'4px 10px', fontSize:12, fontWeight:950 });
const revenueChartGrid = { display:'grid', gridTemplateColumns:'minmax(0,1.35fr) minmax(300px,.65fr)', gap:20, marginTop:20 };
const revenueChartPanel = { background:'#081525', border:'1px solid #1e3a5f', borderRadius:10, padding:18, minHeight:260, boxSizing:'border-box' };
const revenueChartHead = { display:'flex', justifyContent:'space-between', gap:12, alignItems:'center', marginBottom:18 };
const revenueChartBadge = { color:'#22c55e', background:'rgba(34,197,94,.1)', border:'1px solid rgba(34,197,94,.22)', borderRadius:999, padding:'5px 10px', fontSize:12, fontWeight:950 };
const revenueBarChart = { display:'grid', gap:14 };
const revenueBarRow = { display:'grid', gridTemplateColumns:'150px 1fr 90px', gap:14, alignItems:'center' };
const revenueBarLabel = { color:'#cbd5e1', fontSize:13, fontWeight:900, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' };
const revenueBarTrack = { height:13, borderRadius:999, background:'#07111f', border:'1px solid #12345c', overflow:'hidden' };
const revenueBarFill = { display:'block', height:'100%', borderRadius:999, background:'linear-gradient(90deg,#2563eb,#22c55e)' };
const revenueBarValue = { color:'#f59e0b', fontSize:13, textAlign:'right' };
const revenueChartEmpty = { minHeight:160, display:'grid', placeItems:'center', color:'#64748b', fontSize:13, fontWeight:850 };
const revenueSplitWrap = { minHeight:190, display:'grid', gridTemplateColumns:'176px 1fr', gap:22, alignItems:'center' };
const revenueDonutInner = { width:104, height:104, borderRadius:'50%', background:'#07111f', border:'1px solid #1e3a5f', display:'grid', placeItems:'center', textAlign:'center', color:'#e0f2fe', boxSizing:'border-box' };
const planGrid = { display:'grid', gridTemplateColumns:'1.05fr .95fr', gap:22 };
const planBox = { gridColumn:'1 / 2', display:'grid', gridTemplateColumns:'56px 1fr auto', gap:14, alignItems:'center', padding:18, border:'1px solid #1e3a5f', borderRadius:8, background:'#07111f' };
const planIcon = { width:46, height:46, borderRadius:8, background:'linear-gradient(135deg,#155eef,#7c3aed)', color:'#fff', display:'grid', placeItems:'center', fontSize:22, fontWeight:900 };
const planName = { margin:'0 0 4px', fontSize:17, color:'#e0f2fe' };
const amountBox = { gridColumn:'1 / 2', display:'grid', gap:10, padding:'0 18px 18px', color:'#94a3b8', fontSize:13 };
const detailGrid = { gridColumn:'2 / 3', gridRow:'1 / 3', display:'grid', gap:16, alignContent:'start', paddingTop:10 };
const infoRow = { display:'grid', gridTemplateColumns:'1fr 1fr', gap:16, color:'#94a3b8', fontSize:13 };
const usageRow = { display:'flex', alignItems:'center', gap:15, margin:'18px 0' };
const usageMeta = { display:'grid', gridTemplateColumns:'1fr auto auto', gap:18, alignItems:'center', fontSize:13, marginBottom:8 };
const usageTrack = { height:6, background:'#1e3a5f', borderRadius:999, overflow:'hidden' };
const tableWrap = { overflowX:'auto', border:'1px solid #1e3a5f', borderRadius:8 };
const tableStyle = { width:'100%', borderCollapse:'collapse', fontSize:13 };
const tableTh = { textAlign:'left', padding:'13px 16px', color:'#93c5fd', background:'#07111f', borderBottom:'1px solid #1e3a5f', fontSize:12, fontWeight:950 };
const tableTd = { padding:'14px 16px', color:'#e2e8f0', borderBottom:'1px solid #1e3a5f', verticalAlign:'middle' };
const paymentStats = { display:'grid', gridTemplateColumns:'repeat(4, minmax(150px, 1fr))', gap:16, marginBottom:18 };
const miniStat = { border:'1px solid #1e3a5f', borderRadius:8, padding:16, display:'grid', gap:7, background:'#07111f' };
const requestLayout = { display:'grid', gridTemplateColumns:'minmax(0, 1fr) 320px', gap:22 };
const embeddedRequestLayout = { display:'grid', gridTemplateColumns:'minmax(0, 1fr)', gap:18 };
const requestAside = { display:'grid', gap:18, alignContent:'start' };
const embeddedRequestAside = { display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))', gap:18, alignContent:'start', minWidth:0 };
const requestTabs = { display:'flex', gap:30, borderBottom:'1px solid #1e3a5f', margin:'-6px -4px 22px', padding:'0 4px' };
const sectionTitle = { margin:'0 0 8px', color:'#e0f2fe', fontSize:17 };
const filters = { display:'flex', gap:14, margin:'24px 0', flexWrap:'wrap' };
const filterInput = { height:42, minWidth:170, border:'1px solid #1e3a5f', borderRadius:7, background:'#07111f', color:'#e2e8f0', padding:'0 14px', fontSize:13 };
const requestType = { display:'grid', gridTemplateColumns:'42px 1fr', gap:12, marginBottom:18, alignItems:'start' };
const requestTypeIcon = { width:42, height:42, borderRadius:8, display:'grid', placeItems:'center', fontWeight:900 };
const processStep = { display:'flex', gap:12, alignItems:'center', margin:'18px 0', color:'#cbd5e1', fontSize:13 };
const labelStyle = { display:'grid', gap:6, color:'#93c5fd', fontSize:12, fontWeight:900 };
const inputStyle = { width:'100%', minHeight:40, border:'1px solid #1e3a5f', borderRadius:7, padding:'9px 11px', color:'#e2e8f0', boxSizing:'border-box', fontFamily:'inherit', background:'#07111f' };
const primaryButton = { height:42, border:'none', borderRadius:7, background:'linear-gradient(135deg,#155eef,#2563eb)', color:'#fff', padding:'0 18px', fontSize:13, fontWeight:950, cursor:'pointer', boxShadow:'0 10px 20px rgba(37,99,235,.18)' };
const successButton = { ...primaryButton, background:'rgba(16,185,129,.16)', color:'#86efac', border:'1px solid #10b981', boxShadow:'none' };
const dangerButton = { ...primaryButton, background:'rgba(239,68,68,.16)', color:'#fecaca', border:'1px solid #ef4444', boxShadow:'none' };
const disabledActionButton = { ...primaryButton, background:'rgba(71,85,105,.18)', color:'#64748b', border:'1px solid #334155', boxShadow:'none', cursor:'not-allowed' };
const autoPayDisabledPill = { height:36, borderRadius:7, border:'1px solid #475569', background:'rgba(71,85,105,.18)', color:'#94a3b8', padding:'0 14px', display:'inline-flex', alignItems:'center', fontSize:12, fontWeight:950 };
const autoPayDisabledButton = { ...dangerButton, border:'1px solid #475569', background:'rgba(71,85,105,.18)', color:'#94a3b8', cursor:'not-allowed' };
const outlineButton = { height:40, border:'1px solid #1e3a5f', borderRadius:7, background:'#07111f', color:'#93c5fd', padding:'0 14px', fontSize:13, fontWeight:900, cursor:'pointer' };
const linkButton = { border:'none', background:'transparent', color:'#60a5fa', cursor:'pointer', fontWeight:900 };
const notice = { background:'#102a43', border:'1px solid #2563eb', color:'#bfdbfe', borderRadius:8, padding:12, marginBottom:18, fontSize:13, fontWeight:900 };
const liveNotice = { background:'#063b31', border:'1px solid #047857', color:'#86efac', borderRadius:8, padding:'12px 14px', marginBottom:18, fontSize:13, fontWeight:950 };
const agentSplit = { minHeight:180, display:'flex', justifyContent:'center', alignItems:'center', gap:40 };
const donutInner = { width:82, height:82, borderRadius:'50%', background:'#07111f', color:'#e0f2fe', display:'grid', placeItems:'center', boxShadow:'inset 0 0 0 1px #1e3a5f', textAlign:'center' };
const legend = { display:'flex', alignItems:'center', gap:10, color:'#cbd5e1', fontSize:13, fontWeight:800 };
const dashboardShell = { margin:-30, padding:'26px 30px 34px', minHeight:'100%', background:'linear-gradient(135deg, #0a0e27 0%, #0f1535 100%)', color:'#e2e8f0' };
const embeddedDashboardShell = { margin:0, padding:0, minHeight:'100%', background:'transparent', color:'#e2e8f0', position:'relative', zIndex:2, overflow:'visible' };
const dashboardHeader = { marginBottom:18 };
const dashboardTitle = { margin:'0 0 5px', color:'#e0f2fe', fontSize:18, lineHeight:1.15, fontWeight:950 };
const dashboardSubtitle = { margin:0, color:'#60a5fa', fontSize:12 };
const dashboardStats = { display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(150px, 1fr))', gap:16, marginBottom:18 };
const dashboardMetric = { minHeight:84, background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8, padding:'16px 18px', display:'flex', justifyContent:'space-between', alignItems:'center', gap:12, boxShadow:'0 10px 24px rgba(0,0,0,.24)', position:'relative', overflow:'hidden' };
const agreementMetric = { ...dashboardMetric, display:'grid', alignContent:'center', textAlign:'left', width:'100%', cursor:'pointer', color:'#e2e8f0' };
const dashboardMetricContent = { position:'relative', zIndex:2, minWidth:0 };
const dashboardMetricIcon = { width:50, height:50, borderRadius:'50%', display:'grid', placeItems:'center', fontSize:23, fontWeight:950, flexShrink:0, position:'relative', zIndex:1 };
const dashboardMetricLabel = { margin:'0 0 6px', color:'#93c5fd', fontSize:12, fontWeight:900 };
const dashboardMetricValue = { display:'block', fontSize:20, lineHeight:1, fontWeight:950, marginBottom:6 };
const dashboardMetricSub = { display:'flex', gap:5, color:'#60a5fa', fontSize:11, fontWeight:800 };
const agreementFileName = { display:'block', color:'#e0f2fe', fontSize:18, lineHeight:1.2, fontWeight:950, marginBottom:6, minWidth:0 };
const dashboardMiddle = { display:'grid', gridTemplateColumns:'1.08fr 1fr .8fr', gap:18, marginBottom:18 };
const settlementGrid = { display:'grid', gridTemplateColumns:'1fr', gap:18, marginBottom:18 };
const dashboardBottom = { display:'grid', gridTemplateColumns:'1.35fr .8fr .72fr', gap:18 };
const dashboardCard = { background:'#0c1a2e', border:'1px solid #1e3a5f', borderRadius:8, padding:'16px 18px', boxShadow:'0 10px 24px rgba(0,0,0,.24)', minWidth:0 };
const dashboardCardTitle = { margin:'0 0 14px', color:'#e0f2fe', fontSize:13, fontWeight:950 };
const dashboardAgent = { minHeight:150, display:'flex', alignItems:'center', justifyContent:'center', gap:32 };
const dashboardDonutInner = { width:78, height:78, borderRadius:'50%', background:'#07111f', color:'#e0f2fe', display:'grid', placeItems:'center', boxShadow:'inset 0 0 0 1px #1e3a5f', textAlign:'center' };
const dashboardLegend = { display:'grid', gap:10 };
const compactUsage = { display:'grid', gridTemplateColumns:'120px 80px 1fr 42px', alignItems:'center', gap:14, minHeight:38, color:'#e2e8f0', fontSize:12, fontWeight:750 };
const compactTrack = { height:6, background:'#1e3a5f', borderRadius:99, overflow:'hidden' };
const compactFill = { display:'block', height:'100%', background:'#1478f2', borderRadius:99 };
const noteCard = { background:'#171b22', borderColor:'#7c5b1d', color:'#f59e0b' };
const noteText = { margin:'0 0 13px', color:'#cbd5e1', fontSize:11, lineHeight:1.55, fontWeight:700 };
const noteTextStrong = { margin:0, color:'#f59e0b', fontSize:11, lineHeight:1.55, fontWeight:850 };
const compactTable = { width:'100%', borderCollapse:'collapse', fontSize:11 };
const compactTh = { textAlign:'left', padding:'9px 12px', color:'#93c5fd', borderBottom:'1px solid #1e3a5f', fontWeight:950 };
const compactTd = { padding:'9px 12px', color:'#e2e8f0', borderBottom:'1px solid #1e3a5f', fontWeight:650 };
const quickGrid = { display:'grid', gridTemplateColumns:'1fr 1fr', gap:14, margin:'20px 0 16px' };
const quickButton = { height:38, border:'1px solid #1e3a5f', borderRadius:4, background:'#07111f', color:'#64748b', fontSize:11, fontWeight:850, cursor:'not-allowed' };
const quickPrimary = { height:38, border:'none', borderRadius:4, background:'linear-gradient(90deg,#4259ff,#6847ea)', color:'#fff', padding:'0 16px', fontSize:12, fontWeight:900, cursor:'pointer' };
const dashboardSmallText = { color:'#94a3b8', fontSize:12, lineHeight:1.5, margin:'0 0 18px' };
const settlementLine = { display:'grid', gridTemplateColumns:'180px 1fr', gap:16, minHeight:28, alignItems:'center', color:'#94a3b8', fontSize:12, fontWeight:800 };

function InviteField({ label, value, onChange, placeholder, type = 'text' }) {
  return (
    <label style={{ display:'grid', gap:6 }}>
      <span style={{ fontSize:12, fontWeight:800, color:'#93c5fd' }}>{label}</span>
      <input
        type={type}
        value={value}
        onChange={e => onChange(e.target.value)}
        placeholder={placeholder}
        style={{ width:'100%', padding:'10px 13px', borderRadius:8, border:'1px solid rgba(99,102,241,0.25)', background:'rgba(15,30,69,0.7)', color:'#e2e8f0', fontSize:13, fontFamily:'inherit', boxSizing:'border-box', outline:'none' }}
        onFocus={e => { e.target.style.borderColor = 'rgba(99,102,241,0.6)'; e.target.style.boxShadow = '0 0 0 3px rgba(99,102,241,0.15)'; }}
        onBlur={e => { e.target.style.borderColor = 'rgba(99,102,241,0.25)'; e.target.style.boxShadow = 'none'; }}
      />
    </label>
  );
}

function PartnerCompanySupportView({ partner, user }) {
  const [searchParams] = useSearchParams();
  if (searchParams.get('tab') === 'user-passwords') {
    return <Navigate to="/partner/user-passwords" replace />;
  }
  return <PartnerCompanySupportPanel partner={partner} user={user} />;
}

function PartnerCompanySupportPanel({ partner, user }) {
  const [tickets, setTickets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyMessage, setReplyMessage] = useState('');
  const [replyBusy, setReplyBusy] = useState(false);

  const loadTickets = () => {
    setLoading(true);
    api.get('/partner/company-support-tickets')
      .then(({ data }) => {
        const list = Array.isArray(data) ? data : [];
        setTickets(list);
        if (selectedTicket) {
          const updated = list.find(t => t._id === selectedTicket._id);
          if (updated) setSelectedTicket(updated);
        }
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadTickets();
    const socket = io(SOCKET_URL, socketOptions);
    if (partner?._id) {
      socket.emit('join:partner', partner._id);
    }
    
    const handleUpdate = () => {
      loadTickets();
    };

    socket.on('support:ticket_new', handleUpdate);
    socket.on('support:message_new', handleUpdate);
    socket.on('support:ticket_updated', handleUpdate);

    return connectSocket(socket);
  }, [partner?._id]);

  const sendReply = async (e) => {
    e.preventDefault();
    if (!replyMessage.trim() || !selectedTicket) return;
    setReplyBusy(true);
    try {
      const { data } = await api.post(`/partner/company-support-tickets/${selectedTicket._id}/messages`, {
        message: replyMessage
      });
      setReplyMessage('');
      setSelectedTicket(data);
      loadTickets();
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Reply send failed', 'error');
    } finally {
      setReplyBusy(false);
    }
  };

  const updateStatus = async (newStatus) => {
    if (!selectedTicket) return;
    try {
      const { data } = await api.patch(`/partner/company-support-tickets/${selectedTicket._id}/status`, {
        status: newStatus
      });
      setSelectedTicket(data);
      loadTickets();
      Swal.fire('Success', `Ticket status updated to ${newStatus}`, 'success');
    } catch (err) {
      Swal.fire('Error', err.response?.data?.message || 'Status update failed', 'error');
    }
  };

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 20, alignItems: 'start', marginTop: 14 }}>
      <section style={{ ...card, padding: 20 }}>
        <h3 style={{ ...cardTitle, marginBottom: 14 }}>Tenant Tickets</h3>
        {loading ? (
          <div style={{ textAlign: 'center', color: '#cbd5e1', padding: 20 }}>Loading tickets...</div>
        ) : tickets.length === 0 ? (
          <div style={{ color: '#cbd5e1', fontSize: 13, padding: 10 }}>No support tickets found for your tenants.</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 450, overflowY: 'auto' }}>
            {tickets.map(t => {
              const isSelected = selectedTicket?._id === t._id;
              const severityColors = {
                low: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1' },
                medium: { bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
                high: { bg: 'rgba(239,68,68,0.1)', text: '#ef4444' },
                payment: { bg: 'rgba(16,185,129,0.1)', text: '#10b981' }
              };
              const statusColors = {
                'Open': '#eab308',
                'In Progress': '#3b82f6',
                'Resolved': '#10b981',
                'Closed': '#64748b'
              };
              const sev = severityColors[t.severity] || severityColors.low;
              const compName = t.companyId?.name || 'Unknown Company';
              return (
                <div
                  key={t._id}
                  onClick={() => setSelectedTicket(t)}
                  style={{
                    padding: 12, borderRadius: 8, cursor: 'pointer',
                    background: isSelected ? 'rgba(59,130,246,0.15)' : '#07111f',
                    border: isSelected ? '1px solid #3b82f6' : '1px solid #1e3a5f',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: '#60a5fa', fontWeight: 'bold' }}>{t.ticketId}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: sev.bg, color: sev.text, fontWeight: 700 }}>
                      {t.severity?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 'bold', color: '#f8fafc', marginBottom: 4 }}>{t.subject}</div>
                  <div style={{ fontSize: 11, color: '#93c5fd', marginBottom: 6, fontWeight: 700 }}>🏢 {compName}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, color: '#94a3b8' }}>
                    <span>{new Date(t.createdAt).toLocaleDateString()}</span>
                    <span style={{ fontWeight: 700, color: statusColors[t.status] || '#cbd5e1' }}>{t.status}</span>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {selectedTicket ? (
        <section style={{ ...card, padding: 20 }}>
          <div style={{ borderBottom: '1px solid #1e3a5f', paddingBottom: 12, marginBottom: 14 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
              <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>Ticket: {selectedTicket.ticketId}</h3>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 12, color: '#94a3b8' }}>Status:</span>
                <select
                  value={selectedTicket.status}
                  onChange={(e) => updateStatus(e.target.value)}
                  style={{
                    background: '#07111f', color: '#e0f2fe', border: '1px solid #1e3a5f',
                    borderRadius: 6, padding: '4px 8px', fontSize: 12, fontWeight: 700, cursor: 'pointer'
                  }}
                >
                  <option value="Open">Open</option>
                  <option value="In Progress">In Progress</option>
                  <option value="Resolved">Resolved</option>
                  <option value="Closed">Closed</option>
                </select>
              </div>
            </div>
            <div style={{ fontSize: 14, fontWeight: 'bold', color: '#fff', marginBottom: 6 }}>{selectedTicket.subject}</div>
            <p style={{ margin: 0, fontSize: 12, color: '#94a3b8', lineHeight: 1.4 }}>
              {selectedTicket.description}
            </p>
          </div>

          {/* Message Log */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 250, overflowY: 'auto', marginBottom: 14, paddingRight: 4 }}>
            {(selectedTicket.messages || []).map((msg, idx) => {
              const isMe = msg.senderRole === 'partner_admin';
              return (
                <div
                  key={msg._id || idx}
                  style={{
                    alignSelf: isMe ? 'flex-end' : 'flex-start',
                    maxWidth: '85%',
                    background: isMe ? 'linear-gradient(135deg, #1e3a8a, #1d4ed8)' : 'rgba(30,41,59,0.4)',
                    border: isMe ? 'none' : '1px solid #1e3a5f',
                    padding: '10px 14px', borderRadius: 12,
                    color: '#f8fafc', fontSize: 13, lineHeight: 1.4
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 10, color: isMe ? '#bfdbfe' : '#94a3b8', fontWeight: 600 }}>
                    <span>{msg.senderName} ({msg.senderRole === 'superadmin' ? 'Super Admin' : msg.senderRole === 'company_admin' ? 'Company Admin' : 'Partner Admin'})</span>
                    <span>{new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                  </div>
                  <div style={{ whiteSpace: 'pre-wrap' }}>{msg.message}</div>
                </div>
              );
            })}
          </div>

          {/* Reply Form */}
          {selectedTicket.status === 'Closed' ? (
            <div style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '10px 14px', borderRadius: 8, fontSize: 12, textAlign: 'center' }}>
              This ticket has been closed.
            </div>
          ) : (
            <form onSubmit={sendReply} style={{ display: 'flex', gap: 10 }}>
              <input
                type="text"
                required
                placeholder="Type your response..."
                value={replyMessage}
                onChange={e => setReplyMessage(e.target.value)}
                style={{
                  flex: 1, padding: '10px 14px', borderRadius: 8, border: '1px solid #1e3a5f',
                  background: '#07111f', color: '#f8fafc', fontSize: 13, outline: 'none'
                }}
              />
              <button
                type="submit"
                disabled={replyBusy}
                style={{
                  padding: '0 20px', borderRadius: 8, border: 'none',
                  background: 'linear-gradient(135deg, #3b82f6, #1d4ed8)',
                  color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                }}
              >
                {replyBusy ? 'Sending...' : 'Send'}
              </button>
            </form>
          )}
        </section>
      ) : (
        <section style={{ ...card, padding: 40, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#cbd5e1', fontSize: 13, border: '1px dashed #1e3a5f', width: '100%', boxSizing: 'border-box' }}>
          Select a ticket from the list to view conversation history.
        </section>
      )}
    </div>
  );
}
