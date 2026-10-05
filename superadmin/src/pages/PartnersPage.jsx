import { useEffect, useMemo, useRef, useState } from 'react';
import { Activity as ActivityIcon, ArrowLeft, ArrowUpRight, Building2, CalendarDays, CheckCircle2, ChevronRight, Clock3, CreditCard, FileText, Handshake, Headphones, IndianRupee, LayoutDashboard, LogIn, Mail, Monitor, MoreHorizontal, Pencil, Plus, RefreshCw, ShieldCheck, ShieldOff, UserRound, Wallet } from 'lucide-react';
import api from '../api/axios';
import PartnerOverviewSummaries from '../components/PartnerOverviewSummaries';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';
import './PartnersPage.css';

const partnerTabs = [
  ['overview', 'Overview', LayoutDashboard],
  ['edit', 'Edit', Pencil],
  ['companies', 'Companies', Building2],
  ['agents', 'Agents', Monitor],
  ['requests', 'Total Agent', ShieldCheck],
  ['agentAutoPay', 'Auto Pay', RefreshCw],
  ['approvedRequests', 'Agent Payment Control System', Wallet],
  ['subscriptions', 'Subscriptions', CreditCard],
  ['documents', 'Documents', FileText],
  ['activity', 'Activity', ActivityIcon],
  ['support', 'Support', Headphones],
];

const agentPricingTypes = [
  { type: 'system', label: 'System', tone: '#60a5fa' },
  { type: 'server', label: 'Server', tone: '#a78bfa' },
  { type: 'android', label: 'Android', tone: '#34d399' },
];
const agentPriceField = (type, period) => `agentPrice_${type}_${period}`;
const agentPricingPayload = form => Object.fromEntries(agentPricingTypes.map(({ type }) => [type,
  Object.fromEntries(['monthly', 'yearly'].map(period => [period, form[agentPriceField(type, period)]])),
]));

const initialForm = {
  name: '',
  slug: '',
  adminName: '',
  adminEmail: '',
  phone: '',
  adminPassword: '',
};

const initialEditForm = {
  name: '',
  adminName: '',
  adminEmail: '',
  phone: '',
  status: 'pending',
  companyLimit: '',
  agentLimit: '',
  commissionPercent: '',
  platformPaymentAmount: '',
  pricingPlan: 'enterprise',
  razorpayStatus: 'not_connected',
  partnerLinkedAccountId: '',
  kycStatus: 'not_submitted',
  notes: '',
  agreementDetails: '',
  agreementFileName: '',
  agreementFileType: '',
  agreementFilePath: '',
  ...Object.fromEntries(agentPricingTypes.flatMap(({ type }) => ['monthly', 'yearly'].map(period => [agentPriceField(type, period), '']))),
};

const displayFileName = value => {
  let name = String(value || '');
  if (/[ÃÂâðï]/.test(name)) {
    try {
      name = decodeURIComponent([...name].map(char => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
    } catch {}
  }
  return name
    .replace(/^(?:[\s"'`*_.,:;|/\\-]|[^\x20-\x7E]|[^\p{L}\p{N}._-])+/u, '')
    .replace(/^(?:ðŸ|ï¸|¿|¢|â|Ã|Â|[^\p{L}\p{N}._-])+/u, '')
    .trim() || 'Uploaded document';
};

const settingsFields = ['name', 'adminName', 'adminEmail', 'phone', 'status', 'platformPaymentAmount', 'pricingPlan', 'razorpayStatus', 'partnerLinkedAccountId', 'kycStatus'];
const pricingFields = agentPricingTypes.flatMap(({ type }) => ['monthly', 'yearly'].map(period => agentPriceField(type, period)));
const tabFields = { edit: settingsFields, approvedRequests: pricingFields };

function partnerEditValues(partner) {
  return {
    name: partner.name || '',
    adminName: partner.ownerUserId?.name || '',
    adminEmail: partner.ownerUserId?.email || '',
    phone: partner.ownerUserId?.phone || partner.mobile || '',
    status: statusForEdit(partner.status),
    companyLimit: partner.resourceRequest?.numberOfCompanies ?? '',
    agentLimit: partner.resourceRequest?.numberOfAgents ?? '',
    commissionPercent: partner.commissionPercent ?? partner.resourceRequest?.proposedCommission ?? '',
    platformPaymentAmount: partner.plan?.quote?.amountInr ?? '',
    pricingPlan: partner.plan?.type || 'enterprise',
    razorpayStatus: partner.profile?.razorpayKeyId ? 'connected' : 'not_connected',
    partnerLinkedAccountId: partner.partner_linked_account_id || '',
    kycStatus: partner.profile?.kycStatus || 'not_submitted',
    notes: partner.notes || '',
    agreementDetails: partner.agreementDetails || '',
    agreementFileName: partner.agreementFileName || '',
    agreementFileType: partner.agreementFileType || '',
    agreementFilePath: partner.agreementFilePath || '',
    ...Object.fromEntries(agentPricingTypes.flatMap(({ type }) => ['monthly', 'yearly'].map(period => [agentPriceField(type, period), partner.agentPricing?.[type]?.[period] ?? partner.agentPricing?.[period] ?? 0]))),
  };
}

export default function PartnersPage() {
  const [partners, setPartners] = useState([]);
  const [form, setForm] = useState(initialForm);
  const [editForm, setEditForm] = useState(initialEditForm);
  const [activeTab, setActiveTab] = useState('overview');
  const [selectedId, setSelectedId] = useState('');
  const [partnerDetail, setPartnerDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [search, setSearch] = useState('');
  const [editingTabs, setEditingTabs] = useState({});
  const selectedIdRef = useRef('');
  const agreementInputRef = useRef(null);
  const listSequence = useRef(0);
  const detailSequence = useRef(0);
  const dirtyFields = useRef(new Set());
  const editPartnerId = useRef('');
  const refreshRef = useRef(() => {});
  const [refreshing, setRefreshing] = useState(false);
  const [dataError, setDataError] = useState('');
  const [detailError, setDetailError] = useState('');

  const load = async ({ silent = false } = {}) => {
    const sequence = ++listSequence.current;
    if (!silent && !selectedIdRef.current) setLoading(true);
    try {
      const { data } = await api.get('/superadmin/partners');
      if (sequence !== listSequence.current) return;
      if (!Array.isArray(data)) throw new Error('Invalid partner list');
      setPartners(data);
      setDataError('');
    } catch (err) {
      if (sequence === listSequence.current) setDataError(err.response?.data?.message || 'Unable to refresh partners. Please retry.');
    } finally {
      if (sequence === listSequence.current) setLoading(false);
    }
  };

  const loadPartnerOverview = async (partnerId, { silent = false } = {}) => {
    if (!partnerId) return null;
    const sequence = ++detailSequence.current;
    if (partners.length && !partners.some(partner => String(partner._id) === String(partnerId))) {
      setSelectedId('');
      selectedIdRef.current = '';
      setPartnerDetail(null);
      setMessage('');
      return null;
    }
    if (!silent) setDetailLoading(true);
    try {
      const { data } = await api.get(`/superadmin/partners/${partnerId}/overview`);
      if (sequence !== detailSequence.current || String(selectedIdRef.current) !== String(partnerId)) return null;
      setPartnerDetail(data);
      setDetailError('');
      return data;
    } catch (err) {
      if (sequence !== detailSequence.current || String(selectedIdRef.current) !== String(partnerId)) return null;
      if (err.response?.status === 404) {
        setSelectedId('');
        selectedIdRef.current = '';
        setPartnerDetail(null);
        await load();
        setMessage('');
        return null;
      }
      setDetailError(err.response?.data?.message || 'Unable to refresh partner details. Previously loaded data is still shown.');
      return null;
    } finally {
      if (sequence === detailSequence.current && String(selectedIdRef.current) === String(partnerId)) setDetailLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  useEffect(() => {
    selectedIdRef.current = selectedId;
  }, [selectedId]);

  const refreshAll = async () => {
    setRefreshing(true);
    await Promise.allSettled([
      load({ silent: true }),
      selectedIdRef.current ? loadPartnerOverview(selectedIdRef.current, { silent: true }) : Promise.resolve(),
    ]);
    setRefreshing(false);
  };
  refreshRef.current = refreshAll;

  useEffect(() => {
    const socket = io(SOCKET_URL);
    let disposed = false;
    let timer;
    let running = false;
    let queued = false;
    const run = async () => {
      if (disposed) return;
      if (running) { queued = true; return; }
      running = true;
      await refreshRef.current();
      running = false;
      if (queued && !disposed) { queued = false; schedule(); }
    };
    const schedule = () => { clearTimeout(timer); timer = setTimeout(run, 250); };
    const onConnect = () => { socket.emit('join:superadmin'); schedule(); };
    const onVisible = () => { if (document.visibilityState === 'visible') schedule(); };
    const events = ['partner:update', 'company:update', 'support:ticket_new', 'support:message_new', 'support:ticket_updated'];
    socket.emit('join:superadmin');
    socket.on('connect', onConnect);
    events.forEach(event => socket.on(event, schedule));
    const disconnectSocket = connectSocket(socket);
    const interval = setInterval(onVisible, 30000);
    window.addEventListener('focus', onVisible);
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      disposed = true;
      clearTimeout(timer);
      clearInterval(interval);
      listSequence.current++;
      detailSequence.current++;
      events.forEach(event => socket.off(event, schedule));
      socket.off('connect', onConnect);
      window.removeEventListener('focus', onVisible);
      document.removeEventListener('visibilitychange', onVisible);
      disconnectSocket();
    };
  }, []);

  useEffect(() => {
    if (!selectedId) {
      setPartnerDetail(null);
      return;
    }
    loadPartnerOverview(selectedId);
  }, [selectedId]);

  useEffect(() => {
    if (!selectedId || loading || !partners.length) return;
    if (partners.some(partner => String(partner._id) === String(selectedId))) return;
    setSelectedId('');
    setPartnerDetail(null);
    setMessage('Selected partner no longer exists. Partner list refreshed.');
  }, [selectedId, loading, partners]);

  const filtered = partners.filter(p => {
    const q = search.trim().toLowerCase();
    return !q || [p.name, p.ownerUserId?.email, p.ownerUserId?.phone, p.mobile, p.status]
      .some(value => String(value || '').toLowerCase().includes(q));
  });

  const selected = partners.find(p => p._id === selectedId) || null;
  const detailPartner = partnerDetail?.partner || selected;
  const summary = partnerDetail?.summary || {};
  const pendingPartners = filtered.filter(p => p.status === 'pending_request');
  const openResourceStatuses = ['pending', 'negotiation'];
  const resourceRequestRows = (partnerDetail?.resourceRequests || (
    detailPartner?.resourceRequest?.status && detailPartner.resourceRequest.status !== 'none'
      ? [{ ...detailPartner.resourceRequest, requestId: `REQ-${String(detailPartner?._id || '000001').slice(-6).toUpperCase()}` }]
      : []
  )).map((request, index) => ({
    ...request,
    rowId: request._id || request.requestId || `${detailPartner?._id || 'request'}-${index}`,
    partnerName: detailPartner?.name || '-',
  })).sort((a, b) => new Date(b.requestedAt || 0) - new Date(a.requestedAt || 0));
  const selectedResourceRequests = resourceRequestRows.filter(request => openResourceStatuses.includes(request.status));
  const nonPlatformPayments = (partnerDetail?.payments || []).filter(payment => payment.source !== 'partner_checkout' && payment.planType !== 'partner_enterprise');
  const selectedNonPlatformRevenue = nonPlatformPayments
    .filter(payment => payment.status === 'captured')
    .reduce((sum, payment) => sum + Number(payment.amountInr || 0), 0);

  const stats = useMemo(() => ({
    total: partners.length,
    active: partners.filter(p => ['approved', 'active', 'pending_payment'].includes(p.status)).length,
    pending: partners.filter(p => p.status === 'pending_request').length,
    requests: partners.filter(p => p.resourceRequest?.status === 'pending').length,
    collected: partners.reduce((sum, p) => sum + Number(p.nonPlatformRevenue || 0), 0),
  }), [partners]);

  useEffect(() => {
    if (!detailPartner) return;
    if (editPartnerId.current !== detailPartner._id) {
      dirtyFields.current.clear();
      setEditingTabs({});
      editPartnerId.current = detailPartner._id;
    }
    const nextForm = partnerEditValues(detailPartner);
    setEditForm(previous => Object.fromEntries(Object.entries(nextForm).map(([key, value]) => [key, dirtyFields.current.has(key) ? previous[key] : value])));
  }, [detailPartner?._id, detailPartner?.updatedAt]);

  const createPartner = async e => {
    e.preventDefault();
    setSaving(true);
    setMessage('');
    try {
      await api.post('/superadmin/partners', form);
      setForm(initialForm);
      setMessage('Partner created. Invitation email queued.');
      await load();
      if (selectedId) await loadPartnerOverview(selectedId, { silent: true });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Could not create partner');
    } finally {
      setSaving(false);
    }
  };

  const partnerAction = async (partnerId, action) => {
    setSaving(true);
    setMessage('');
    try {
      await api.patch(`/superadmin/partners/${partnerId}/${action}`);
      setMessage(action === 'approve' ? 'Partner approved. Email queued.' : 'Partner rejected.');
      await load();
      if (selectedId) await loadPartnerOverview(selectedId, { silent: true });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Action failed');
    } finally {
      setSaving(false);
    }
  };

  const resourceAction = async (partnerId, action) => {
    const note = action === 'negotiate' ? window.prompt('Negotiation note') || '' : '';
    setSaving(true);
    setMessage('');
    try {
      await api.patch(`/superadmin/partners/${partnerId}/resources/${action}`, { note });
      setMessage(`Resource request ${action}d.`);
      await load();
      if (selectedId) await loadPartnerOverview(selectedId, { silent: true });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Resource action failed');
    } finally {
      setSaving(false);
    }
  };

  const savePartnerSettings = async e => {
    e.preventDefault();
    if (!selectedId || !editingTabs.edit || saving) return;
    setSaving(true);
    setMessage('');
    try {
      const payload = Object.fromEntries(settingsFields.filter(key => dirtyFields.current.has(key)).map(key => [key, editForm[key]]));
      if (!Object.keys(payload).length) {
        setEditingTabs(prev => ({ ...prev, edit: false }));
        setMessage('No changes to save.');
        return;
      }

      const { data } = await api.patch(`/superadmin/partners/${selectedId}`, payload);
      setPartnerDetail(prev => prev ? { ...prev, partner: { ...prev.partner, ...data } } : prev);
      setPartners(prev => prev.map(partner => partner._id === selectedId ? { ...partner, ...data } : partner));
      Object.keys(payload).forEach(key => dirtyFields.current.delete(key));
      setEditingTabs(prev => ({ ...prev, edit: false }));
      setMessage('Partner settings saved.');
      await loadPartnerOverview(selectedId, { silent: true });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Partner settings save nahi ho payi');
    } finally {
      setSaving(false);
    }
  };

  const saveDocuments = async (payload, successMessage = 'Document settings saved.') => {
    if (!selectedId || saving) return false;
    const partnerId = selectedId;
    setSaving(true);
    setMessage('');
    try {
      const { data } = await api.patch(`/superadmin/partners/${partnerId}`, payload);
      setPartners(prev => prev.map(partner => partner._id === partnerId ? { ...partner, ...data } : partner));
      if (selectedIdRef.current === partnerId) {
        setPartnerDetail(prev => prev ? { ...prev, partner: { ...prev.partner, ...data } } : prev);
        setMessage(successMessage);
        await loadPartnerOverview(partnerId, { silent: true });
      }
      return true;
    } catch (err) {
      if (selectedIdRef.current === partnerId) setMessage(err.response?.data?.message || 'Document settings save nahi ho payi');
      return false;
    } finally {
      setSaving(false);
    }
  };

  const saveAgentPricing = async () => {
    if (!selectedId || !editingTabs.approvedRequests || saving) return;
    setSaving(true);
    setMessage('');
    try {
      const { data } = await api.patch(`/superadmin/partners/${selectedId}`, {
        agentPricing: agentPricingPayload(editForm),
      });
      setPartnerDetail(prev => prev ? { ...prev, partner: data } : prev);
      setPartners(prev => prev.map(partner => partner._id === selectedId ? { ...partner, ...data } : partner));
      agentPricingTypes.forEach(({ type }) => ['monthly', 'yearly'].forEach(period => dirtyFields.current.delete(agentPriceField(type, period))));
      setEditingTabs(prev => ({ ...prev, approvedRequests: false }));
      setMessage('Agent payment pricing saved for this partner.');
      await load();
      await loadPartnerOverview(selectedId, { silent: true });
    } catch (err) {
      setMessage(err.response?.data?.message || 'Agent pricing save nahi ho payi');
    } finally {
      setSaving(false);
    }
  };

  const handleAgreementUpload = async file => {
    if (!file || !editingTabs.edit || saving) return;
    if (file.type !== 'application/pdf') {
      setMessage('Agreement Details me sirf PDF upload kar sakte ho.');
      return;
    }
    if (file.size > 8 * 1024 * 1024) {
      setMessage('Agreement PDF 8 MB ya usse chhota hona chahiye.');
      return;
    }
    if (!selectedId) {
      setMessage('Pehle ek partner select karo.');
      return;
    }
    setSaving(true);
    setMessage(`Uploading ${file.name}...`);
    try {
      const formData = new FormData();
      formData.append('agreement', file);
      const { data } = await api.post(`/superadmin/partners/${selectedId}/agreement`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      setEditForm(prev => ({
        ...prev,
        agreementFileName: data.agreementFileName || file.name,
        agreementFileType: data.agreementFileType || file.type,
        agreementFilePath: data.agreementFilePath || '',
      }));
      setPartnerDetail(prev => prev ? { ...prev, partner: { ...prev.partner, ...(data.partner || {}) } } : prev);
        setMessage(`Agreement PDF uploaded: ${file.name}`);
    } catch (err) {
      setMessage(err.response?.data?.message || 'Agreement upload fail ho gaya');
    } finally {
      setSaving(false);
    }
  };

  const resetPartnerPassword = async () => {
    if (!selectedId || !window.confirm('Reset partner admin password?')) return;
    setSaving(true);
    setMessage('');
    try {
      const { data } = await api.post(`/superadmin/partners/${selectedId}/reset-password`);
      setMessage(`Password reset. Temporary password: ${data.temporaryPassword}`);
    } catch (err) {
      setMessage(err.response?.data?.message || 'Password reset failed');
    } finally {
      setSaving(false);
    }
  };

  const loginAsPartner = async () => {
    if (!selectedId || saving) return;
    const newWindow = window.open('about:blank', '_blank');
    if (!newWindow) {
      setMessage('Allow pop-ups for this site, then click Login as Partner again.');
      return;
    }
    newWindow.opener = null;
    setSaving(true);
    setMessage('');
    try {
      const { data } = await api.post(`/superadmin/partners/${selectedId}/impersonate`);
      const companyOrigin = import.meta.env.VITE_COMPANY_ORIGIN || 'http://localhost:3000';
      const url = new URL(companyOrigin);
      url.hash = new URLSearchParams({ impersonationToken: data.token }).toString();
      if (!newWindow.closed) newWindow.location.replace(url.toString());
      setMessage('Partner support login opened in a new tab.');
    } catch (err) {
      newWindow.close();
      setMessage(err.response?.data?.message || 'Login as Partner failed');
    } finally {
      setSaving(false);
    }
  };

  const totalCompanies = summary.companyCount ?? 0;
  const totalAgents = summary.totalAgents ?? 0;
  const totalRevenue = Number(summary.totalRevenue ?? selectedNonPlatformRevenue) || 0;
  const totalCollected = Number(summary.totalCollected ?? totalRevenue) || 0;
  const totalDue = Number(summary.totalDue ?? (selected?.status === 'pending_payment' ? selected?.plan?.quote?.amountInr : 0) ?? 0) || 0;
  const platformFee = Number(detailPartner?.plan?.quote?.amountInr || detailPartner?.plan?.amountPaid || selected?.plan?.quote?.amountInr || selected?.plan?.amountPaid || 0) || 0;
  const capabilities = detailPartner?.capabilities || {};
  const planPaid = detailPartner?.plan?.paymentStatus === 'paid' && detailPartner?.plan?.isActive === true;

  const startEditing = tab => {
    if (saving || !partnerDetail) return;
    setEditingTabs(prev => ({ ...prev, [tab]: true }));
  };
  const cancelEditing = tab => {
    if (saving) return;
    const saved = partnerEditValues(detailPartner);
    tabFields[tab].forEach(key => dirtyFields.current.delete(key));
    setEditForm(prev => ({ ...prev, ...Object.fromEntries(tabFields[tab].map(key => [key, saved[key]])) }));
    setEditingTabs(prev => ({ ...prev, [tab]: false }));
    setMessage('');
  };

  const closePartner = () => {
    setEditingTabs({});
    selectedIdRef.current = '';
    detailSequence.current++;
    dirtyFields.current.clear();
    editPartnerId.current = '';
    setDetailError('');
    setSelectedId('');
    setPartnerDetail(null);
    setActiveTab('overview');
    setMessage('');
  };

  const openPartner = partnerId => {
    setEditingTabs({});
    dirtyFields.current.clear();
    if (!partners.some(partner => String(partner._id) === String(partnerId))) {
      setMessage('Selected partner no longer exists. Partner list refreshed.');
      setSelectedId('');
      setPartnerDetail(null);
      load();
      return;
    }
    selectedIdRef.current = partnerId;
    setPartnerDetail(null);
    setSelectedId(partnerId);
    setDetailLoading(true);
    setDetailError('');
    setMessage('');
    setActiveTab('overview');
  };

  if (!selectedId) {
    return (
      <div className="partners-page">
        <div style={topBar}>
          <div>
            <h2 style={pageTitle}>Partner Management</h2>
            <div style={metaLine}>Select a partner to open the super admin partner dashboard.</div>
          </div>
          <div style={{ display:'flex', gap:10, alignItems:'flex-start', flexWrap:'wrap', justifyContent:'flex-end' }}>
            <input placeholder="Search partner..." value={search} onChange={e => setSearch(e.target.value)} style={{ ...inputStyle, width:260 }} />
            <button onClick={() => setActiveTab(tab => tab === 'create' ? 'overview' : 'create')} style={outlineButton}>
              {activeTab === 'create' ? 'Close Create Partner' : 'Create Partner'}
            </button>
          </div>
        </div>

        {message && <div style={noticeStyle}>{message}</div>}
        {dataError && <div style={noticeStyle}>{dataError} <button type="button" onClick={() => load()}>Retry</button></div>}

        <div className="partner-metric-grid">
          <Metric label="Total Partners" value={stats.total} sub={`Active: ${stats.active} | Pending: ${stats.pending}`} color="#c084fc" icon="▦" />
          <Metric label="Active Partners" value={stats.active} sub="Approved or active" color="#34d399" icon="◆" />
          <Metric label="Pending Partners" value={stats.pending} sub="Awaiting approval" color="#f59e0b" icon="◉" />
          <Metric label="Partner Requests" value={stats.requests} sub="Resource requests" color="#22d3ee" icon="▱" />
          <Metric label="Total Revenue" value={`₹${stats.collected.toLocaleString('en-IN')}`} sub="All partners" color="#a7f3d0" icon="▣" />
        </div>

        {activeTab === 'create' ? (
          <form onSubmit={createPartner} style={panelStyle}>
            <h3 style={panelTitle}>Create Partner</h3>
            <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(210px, 1fr))', gap:12 }}>
              <Input label="Partner Company Name" value={form.name} onChange={value => setField('name', value)} required />
              <Input label="Partner Subdomain" value={form.slug} onChange={value => setField('slug', value.toLowerCase().replace(/[^a-z0-9-]/g, '-'))} required />
              <Input label="Admin Name" value={form.adminName} onChange={value => setField('adminName', value)} required />
              <Input label="Admin Email" type="email" value={form.adminEmail} onChange={value => setField('adminEmail', value)} required />
              <Input label="Mobile Number" value={form.phone} onChange={value => setField('phone', value)} required />
              <Input label="Temporary Password" type="password" value={form.adminPassword} onChange={value => setField('adminPassword', value)} required />
            </div>
            <button disabled={saving} style={primaryButton}>{saving ? 'Creating...' : 'Create Partner'}</button>
          </form>
        ) : (
          <PartnerDirectory
            partners={filtered}
            loading={loading}
            saving={saving}
            onOpen={openPartner}
            onApprove={partnerId => partnerAction(partnerId, 'approve')}
            onReject={partnerId => partnerAction(partnerId, 'reject')}
          />
        )}
      </div>
    );
  }

  return (
    <div className="partners-page">
      <header className="partner-detail-header">
        <button type="button" onClick={closePartner} style={{ ...backButton, marginBottom:0, justifySelf:'start' }}>← Back to Partners</button>
        <div className="partner-detail-header-row">
          <div className="partner-detail-identity">
            <h2>{detailPartner?.name || 'Partner Management'}</h2>
            <span aria-hidden="true">•</span>
            <span>{detailPartner?.ownerUserId?.name || '-'}</span>
            <span aria-hidden="true">•</span>
            <span>{detailPartner?.ownerUserId?.email || '-'}</span>
            <span aria-hidden="true">•</span>
            <span>{detailPartner?.ownerUserId?.phone || detailPartner?.mobile || '-'}</span>
            <span aria-hidden="true">•</span>
            <span>Registered On: {formatDate(detailPartner?.createdAt)}</span>
            {detailLoading && <span>· Loading API data...</span>}
          </div>

          <div className="partner-detail-actions">
            <input placeholder="Search partner..." value={search} onChange={e => setSearch(e.target.value)} style={{ ...inputStyle, width:220, maxWidth:'100%' }} />
            <button type="button" disabled={saving} onClick={loginAsPartner} style={outlineButton}>Login as Partner</button>
            {selected && <button disabled={saving} onClick={() => partnerAction(selected._id, 'reject')} style={dangerOutline}>Suspend Partner</button>}
          </div>
        </div>
      </header>

      <nav className="partner-detail-tabs" aria-label="Partner sections">
        {partnerTabs.map(([tab, label, Icon]) => (
          <button key={tab} type="button" aria-pressed={activeTab === tab} onClick={() => setActiveTab(tab)}>
            <Icon size={15} aria-hidden="true" />{label}
          </button>
        ))}
      </nav>
      {(dataError || detailError) && <div style={noticeStyle} role="alert">
        {detailError || dataError} <button type="button" disabled={refreshing} onClick={refreshAll}>Retry</button>
      </div>}

      {message && <div style={noticeStyle}>{message}</div>}

      {!partnerDetail ? <div className="partner-empty-state" role="status">{detailLoading ? 'Loading partner details…' : 'Partner details are unavailable. Please retry.'}</div> : (
        <>
          {activeTab === 'overview' && (
            <>
              <div className="partner-metric-grid">
                <Metric label="Total Companies" value={totalCompanies} sub="Registered companies" color="#60a5fa" icon="▥" />
                <Metric label="Total Agents" value={totalAgents} sub={`${summary.activeAgents || 0} online · ${summary.offlineAgents || 0} offline`} color="#818cf8" icon="▰" />
                <Metric label="Total Revenue" value={`₹${totalRevenue.toLocaleString('en-IN')}`} sub="Company payments received" color="#34d399" icon="▣" />
                <Metric label="Total Due" value={`₹${totalDue.toLocaleString('en-IN')}`} sub="Pending" color="#f87171" icon="▢" />
                <Metric label="Platform Fee" value={`₹${platformFee.toLocaleString('en-IN')}`} sub={detailPartner?.plan?.paymentStatus === 'paid' ? 'Paid' : 'Pending'} color="#34d399" icon="◆" />
              </div>

              <PartnerOverviewSummaries detail={partnerDetail} tabs={partnerTabs} onOpenTab={setActiveTab} displayFileName={displayFileName} />

            </>
          )}

          {activeTab === 'edit' && (
            <form id="partner-settings-form" onSubmit={savePartnerSettings} style={panelStyle}>
              <div className="partner-edit-heading">
                <h3 style={panelTitle}>Partner Settings</h3>
                <PartnerEditActions editing={editingTabs.edit} saving={saving} onEdit={() => startEditing('edit')} onCancel={() => cancelEditing('edit')} formId="partner-settings-form" />
              </div>
              <div style={{ color:'#a78bfa', fontSize:12, marginBottom:14 }}>
                Click Edit to update partner settings. Save Changes applies your edits.
              </div>
              <fieldset className="partner-edit-fields" disabled={!editingTabs.edit || saving}>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:12 }}>
                <Input label="Partner Company Name" value={editForm.name} onChange={value => setEditField('name', value)} required />
                <Input label="Admin Name" value={editForm.adminName} onChange={value => setEditField('adminName', value)} required />
                <Input label="Admin Email" type="email" value={editForm.adminEmail} onChange={value => setEditField('adminEmail', value)} required />
                <Input label="Phone Number" value={editForm.phone} onChange={value => setEditField('phone', value)} />
                <Select label="Status" value={editForm.status} onChange={value => setEditField('status', value)} options={[
                  ['active', 'Active'],
                  ['suspended', 'Suspended'],
                  ['pending', 'Pending'],
                ]} />
                <Input label="Platform Payment Amount" type="number" value={editForm.platformPaymentAmount} onChange={value => setEditField('platformPaymentAmount', value)} />
                <Input label="Pricing Plan" value={editForm.pricingPlan} onChange={value => setEditField('pricingPlan', value)} />
                <Select label="Razorpay Status" value={editForm.razorpayStatus} onChange={value => setEditField('razorpayStatus', value)} options={[
                  ['connected', 'Connected'],
                  ['not_connected', 'Not Connected'],
                ]} />
                <Input
                  label="Partner Linked Account ID"
                  value={editForm.partnerLinkedAccountId}
                  onChange={value => setEditField('partnerLinkedAccountId', value)}
                  placeholder="acc_xxxxxxxxxxxxxx"
                  help="Razorpay Route linked account ID. Add this to enable automatic partner payout transfers; keep blank for manual or pending payout."
                />
                <Select label="KYC Status" value={editForm.kycStatus} onChange={value => setEditField('kycStatus', value)} options={[
                  ['not_submitted', 'Not Submitted'],
                  ['pending', 'Pending'],
                  ['verified', 'Verified'],
                  ['rejected', 'Rejected'],
                ]} />
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))', gap:12, marginTop:12 }}>
                <div>
                  <div style={{ color:'#c4b5fd', fontSize:12, fontWeight:800, marginBottom:5 }}>Agreement PDF</div>
                  <input
                    ref={agreementInputRef}
                    type="file"
                    accept="application/pdf,.pdf"
                    onChange={e => handleAgreementUpload(e.target.files?.[0])}
                    style={{ display:'none' }}
                  />
                  <div style={{ display:'flex', gap:10, alignItems:'center', flexWrap:'wrap', marginTop:10 }}>
                    <button type="button" disabled={saving} onClick={() => agreementInputRef.current?.click()} style={outlineButton}>
                      {editForm.agreementFileName ? 'Replace Agreement PDF' : 'Upload Agreement PDF'}
                    </button>
                    <span style={{ color:'#a78bfa', fontSize:12, fontWeight:800, wordBreak:'break-word' }}>
                      {editForm.agreementFileName || 'No PDF uploaded'}
                    </span>
                  </div>
                </div>
              </div>
              <div style={editActionsRow}>
                <button type="button" disabled={saving} onClick={() => partnerAction(selectedId, 'reject')} style={editDangerButton}>Suspend Partner</button>
                <button type="button" disabled={saving} onClick={resetPartnerPassword} style={editOutlineButton}>Reset Password</button>
              </div>
              </fieldset>
            </form>
          )}

          {activeTab === 'requests' && (
            <TotalAgentPanel partner={detailPartner} activeAgents={summary.activeAgents || 0} inactiveAgents={summary.offlineAgents || 0} />
          )}

          {activeTab === 'agentAutoPay' && (
            <AgentAutoPayPanel partner={detailPartner} payments={partnerDetail?.payments || []} />
          )}

          {activeTab === 'approvedRequests' && (
            <AgentPaymentControlPanel
              partner={detailPartner}
              editForm={editForm}
              setEditField={setEditField}
              saving={saving}
              onSave={saveAgentPricing}
              editing={editingTabs.approvedRequests}
              onEdit={() => startEditing('approvedRequests')}
              onCancel={() => cancelEditing('approvedRequests')}
              capabilities={capabilities}
              planPaid={planPaid}
            />
          )}

          {activeTab === 'companies' && <CompaniesTable companies={partnerDetail?.companies || []} />}
          {activeTab === 'agents' && <AgentsTable agents={partnerDetail?.agents || []} />}
          {activeTab === 'subscriptions' && <SubscriptionsTable companies={partnerDetail?.companies || []} partner={detailPartner} payments={partnerDetail?.payments || []} />}
          {activeTab === 'documents' && <DocumentsPanel key={selectedId} partner={detailPartner} saving={saving} onSave={saveDocuments} />}
          {activeTab === 'activity' && <ActivityTable activity={partnerDetail?.activity || []} partner={detailPartner} />}
          {activeTab === 'support' && <SupportPanel partner={detailPartner} tickets={partnerDetail?.supportTickets || []} />}

          {activeTab === 'create' && (
            <form onSubmit={createPartner} style={panelStyle}>
              <h3 style={panelTitle}>Create Partner</h3>
              <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(210px, 1fr))', gap:12 }}>
                <Input label="Partner Company Name" value={form.name} onChange={value => setField('name', value)} required />
                <Input label="Partner Subdomain" value={form.slug} onChange={value => setField('slug', value.toLowerCase().replace(/[^a-z0-9-]/g, '-'))} required />
                <Input label="Admin Name" value={form.adminName} onChange={value => setField('adminName', value)} required />
                <Input label="Admin Email" type="email" value={form.adminEmail} onChange={value => setField('adminEmail', value)} required />
                <Input label="Mobile Number" value={form.phone} onChange={value => setField('phone', value)} required />
                <Input label="Temporary Password" type="password" value={form.adminPassword} onChange={value => setField('adminPassword', value)} required />
              </div>
              <button disabled={saving} style={primaryButton}>{saving ? 'Creating...' : 'Create Partner'}</button>
            </form>
          )}

          {activeTab === 'overview' && pendingPartners.length > 0 && (
            <div style={{ marginTop:18 }}>
              <Panel title="Pending Requests">
                <DarkTable
                  headers={['Partner', 'Email', 'Subdomain', 'Mobile', 'Date', 'Status', 'Actions']}
                  rows={pendingPartners}
                  empty="No pending partner requests."
                  renderRow={p => (
                    <tr key={p._id}>
                      <Cell>{p.name}</Cell>
                      <Cell>{p.ownerUserId?.email || '-'}</Cell>
                      <Cell>{partnerSubdomain(p)}</Cell>
                      <Cell>{p.ownerUserId?.phone || p.mobile || '-'}</Cell>
                      <Cell>{formatDate(p.createdAt)}</Cell>
                      <Cell><Badge>{p.status}</Badge></Cell>
                      <Cell>
                        <SmallButton onClick={() => openPartner(p._id)}>View Details</SmallButton>
                        <SmallButton disabled={saving} good onClick={() => partnerAction(p._id, 'approve')}>Approve</SmallButton>
                        <SmallButton disabled={saving} danger onClick={() => partnerAction(p._id, 'reject')}>Reject</SmallButton>
                      </Cell>
                    </tr>
                  )}
                />
              </Panel>
            </div>
          )}
        </>
      )}
    </div>
  );

  function setField(key, value) {
    setForm(prev => ({ ...prev, [key]: value }));
  }

  function setEditField(key, value) {
    if (!editingTabs[activeTab] || saving) return;
    dirtyFields.current.add(key);
    setEditForm(prev => ({ ...prev, [key]: value }));
  }
}

function PartnerList({ partners, onSelect }) {
  return (
    <DarkTable
      headers={['Partner', 'Email', 'Subdomain', 'Mobile', 'Status', 'Created']}
      rows={partners}
      empty="No partners found."
      renderRow={p => (
        <tr key={p._id} onClick={() => onSelect(p._id)} style={{ cursor:'pointer' }}>
          <Cell>{p.name}</Cell>
          <Cell>{p.ownerUserId?.email || '-'}</Cell>
          <Cell>{partnerSubdomain(p)}</Cell>
          <Cell>{p.ownerUserId?.phone || p.mobile || '-'}</Cell>
          <Cell><Badge>{p.status}</Badge></Cell>
          <Cell>{formatDate(p.createdAt)}</Cell>
        </tr>
      )}
    />
  );
}

function PartnerDirectory({ partners, loading, saving, onOpen, onApprove, onReject }) {
  const [openMenuId, setOpenMenuId] = useState('');
  if (loading) return <p style={{ color:'#a78bfa', fontSize:13 }}>Loading partners...</p>;

  return (
    <section style={directoryCard}>
      <div style={directoryHeader}>
        <span>Partner</span>
        <span>Email</span>
        <span>Subdomain</span>
        <span>Mobile</span>
        <span>Date</span>
        <span>Status</span>
        <span style={{ textAlign:'center' }}>Actions</span>
      </div>
      {partners.length === 0 ? (
        <div style={{ padding:28, color:'#a78bfa', textAlign:'center' }}>No partners found.</div>
      ) : partners.map((partner, index) => (
        <div key={partner._id} style={directoryRow}>
          <button type="button" onClick={() => onOpen(partner._id)} style={partnerIdentity}>
            <span style={{ ...avatarStyle, background: avatarBg(index), color: avatarColor(index) }}>{initials(partner.name)}</span>
            <span>
              <b style={{ color:'#e9d5ff', display:'block', fontSize:14 }}>{partner.name}</b>
            </span>
          </button>
          <span style={directoryText}>{partner.ownerUserId?.email || '-'}</span>
          <span style={directoryText}>{partnerSubdomain(partner)}</span>
          <span style={directoryText}>{partner.ownerUserId?.phone || partner.mobile || '-'}</span>
          <span style={directoryText}>{formatDate(partner.createdAt)}</span>
          <span><StatusBadge status={partner.status} /></span>
          <span style={{ display:'flex', gap:8, justifyContent:'center', alignItems:'center', flexWrap:'wrap', position:'relative' }}>
            <button type="button" onClick={() => onOpen(partner._id)} style={iconButton} title="Open partner dashboard">◉</button>
            <button
              type="button"
              onClick={() => setOpenMenuId(current => current === partner._id ? '' : partner._id)}
              style={iconButton}
              title="More actions"
            >
              ⋮
            </button>
            {openMenuId === partner._id && (
              <div style={actionMenu}>
                <button style={{ ...actionMenuButton, color:'#86efac' }} type="button" onClick={() => { setOpenMenuId(''); onApprove(partner._id); }} disabled={saving}>Approve</button>
                <button style={{ ...actionMenuButton, color:'#fca5a5' }} type="button" onClick={() => { setOpenMenuId(''); onReject(partner._id); }} disabled={saving}>Reject / Suspend</button>
              </div>
            )}
          </span>
        </div>
      ))}
      <div style={directoryFooter}>
        <span>Showing 1 to {partners.length} of {partners.length} partners</span>
        <div style={{ display:'flex', gap:8 }}>
          <button style={pagerButton}>‹</button>
          <button style={{ ...pagerButton, borderColor:'#7c3aed', color:'#e9d5ff' }}>1</button>
          <button style={pagerButton}>›</button>
        </div>
      </div>
    </section>
  );
}

function StatusBadge({ status }) {
  const normalized = status === 'pending_request' ? 'Pending' : status === 'approved' || status === 'active' || status === 'pending_payment' ? 'Approved' : status === 'rejected' ? 'Rejected' : status || 'Pending';
  const color = normalized === 'Approved' ? '#34d399' : normalized === 'Rejected' ? '#f87171' : '#f59e0b';
  return (
    <span style={{ display:'inline-flex', alignItems:'center', gap:6, padding:'5px 10px', borderRadius:7, background:`${color}22`, color, fontSize:12, fontWeight:900 }}>
      <span style={{ width:8, height:8, borderRadius:'50%', background:color }} />
      {normalized}
    </span>
  );
}

function CompaniesTable({ companies }) {
  return (
    <DarkTable
      headers={['Company', 'Email', 'Phone', 'Status', 'Plan', 'Created']}
      rows={companies}
      empty="No companies found for this partner."
      renderRow={company => (
        <tr key={company._id}>
          <Cell>{company.name}</Cell>
          <Cell>{company.email || '-'}</Cell>
          <Cell>{company.phone || '-'}</Cell>
          <Cell><Badge>{company.status}</Badge></Cell>
          <Cell>{company.plan?.isActive ? 'Active' : 'Inactive'}</Cell>
          <Cell>{formatDate(company.createdAt)}</Cell>
        </tr>
      )}
    />
  );
}

function AgentsTable({ agents }) {
  return (
    <DarkTable
      headers={['Agent', 'Company', 'OS', 'IP', 'Status', 'Last Seen']}
      rows={agents}
      empty="No agents found for this partner."
      renderRow={agent => (
        <tr key={agent._id}>
          <Cell>{agent.name || agent.hostname || '-'}</Cell>
          <Cell>{agent.companyId?.name || '-'}</Cell>
          <Cell>{agent.os || agent.osType || '-'}</Cell>
          <Cell>{agent.ip || '-'}</Cell>
          <Cell><Badge>{agent.isOnline ? 'online' : agent.status === 'pending' ? 'pending' : 'offline'}</Badge></Cell>
          <Cell>{formatDateTime(agent.lastSeen)}</Cell>
        </tr>
      )}
    />
  );
}

function PaymentsTable({ payments }) {
  return (
    <DarkTable
      headers={['Account', 'Amount', 'Status', 'Plan', 'Payment ID', 'Paid At']}
      rows={payments}
      empty="No payments found for this partner."
      renderRow={payment => (
        <tr key={payment._id}>
          <Cell>{payment.companyId?.name || payment.companyName || payment.partnerName || 'Platform Fee'}</Cell>
          <Cell>₹{Number(payment.amountInr || 0).toLocaleString('en-IN')}</Cell>
          <Cell><Badge>{payment.status}</Badge></Cell>
          <Cell>{payment.planType === 'partner_enterprise' ? 'Platform Fee' : payment.planType || '-'}</Cell>
          <Cell>{payment.paymentId || payment.orderId || '-'}</Cell>
          <Cell>{formatDateTime(payment.paidAt || payment.createdAt)}</Cell>
        </tr>
      )}
    />
  );
}

function SubscriptionsTable({ companies, partner, payments = [] }) {
  const licenseTotal = plan => {
    const systems = Number(plan?.systemCount ?? plan?.request?.systemCount ?? 0) || 0;
    const servers = Number(plan?.serverCount ?? plan?.request?.serverCount ?? 0) || 0;
    const phones = Number(plan?.phoneCount ?? plan?.request?.phoneCount ?? 0) || 0;
    const total = systems + servers + phones;
    return total || Number(plan?.systemLimit || 0) || 0;
  };
  const partnerPlan = partner?.plan || {};
  const partnerPayments = payments
    .filter(payment => payment.source === 'partner_checkout' || payment.planType === 'partner_enterprise')
    .sort((a, b) => new Date(b.paidAt || b.createdAt || 0) - new Date(a.paidAt || a.createdAt || 0));
  const partnerPayment = partnerPayments[0];
  const isPartnerPaid = partnerPlan.paymentStatus === 'paid' && partnerPlan.isActive === true;
  const partnerAmount = isPartnerPaid
    ? Number(partnerPlan.amountPaid || partnerPayment?.amountInr || 0)
    : Number(partnerPlan.quote?.amountInr || 0);
  const partnerPlanRow = partner ? [{
    _id: `partner-${partner._id}`,
    name: `${partner.name} Partner Plan`,
    plan: partnerPlan,
    isPartnerPlan: true,
    amount: partnerAmount,
    paymentStatus: isPartnerPaid ? 'Paid' : partnerAmount ? 'Pending' : 'Amount Pending',
    paymentId: partner?.razorpay?.paymentId || partnerPayment?.paymentId || partner?.razorpay?.orderId || partnerPayment?.orderId || '-',
    autoPay: partnerPlan.autoPay || partnerPayment?.autoPay || false,
    expiresAt: partnerPlan.expiresAt || partnerPayment?.periodEnd,
    status: isPartnerPaid ? 'Active' : partnerAmount ? 'Pending Payment' : 'Pending Amount',
  }] : [];
  const rows = [...partnerPlanRow, ...companies];
  return (
    <DarkTable
      headers={['Account', 'Plan', 'LICENSES', 'Amount', 'Payment', 'Payment ID', 'Autopay', 'Expires At', 'Status']}
      rows={rows}
      empty="No subscriptions found for this partner."
      renderRow={row => (
        <tr key={row._id}>
          <Cell>{row.name}</Cell>
          <Cell>{row.isPartnerPlan ? 'Platform Fee' : row.plan?.type || 'custom'}</Cell>
          <Cell>{licenseTotal(row.plan)}</Cell>
          <Cell>{row.isPartnerPlan ? (row.amount ? `₹${row.amount.toLocaleString('en-IN')}` : '-') : `₹${Number(row.plan?.amountPaid || 0).toLocaleString('en-IN')}`}</Cell>
          <Cell><Badge>{row.isPartnerPlan ? row.paymentStatus : row.plan?.paymentStatus || 'unpaid'}</Badge></Cell>
          <Cell>{row.isPartnerPlan ? row.paymentId : row.razorpay?.paymentId || row.razorpay?.orderId || '-'}</Cell>
          <Cell><Badge>{row.isPartnerPlan ? (row.autoPay ? 'Enabled' : 'Disabled') : row.plan?.autoPay ? 'Enabled' : 'Disabled'}</Badge></Cell>
          <Cell>{formatDate(row.isPartnerPlan ? row.expiresAt : row.plan?.expiresAt)}</Cell>
          <Cell><Badge>{row.isPartnerPlan ? row.status : row.plan?.isActive ? 'active' : row.plan?.requestStatus || 'inactive'}</Badge></Cell>
        </tr>
      )}
    />
  );
}

function TotalAgentPanel({ partner, activeAgents = 0, inactiveAgents = 0 }) {
  const summary = partner?.agentLicenseSummary || {};
  const purchases = partner?.agentLicensePurchases || [];
  const cards = [
    ['Total Purchased Agents', summary.totalPurchased || 0],
    ['Active Agents', activeAgents || 0],
    ['Inactive Agents', inactiveAgents || 0],
    ['Available Licenses', summary.activeLicenses || 0],
    ['Consumed Licenses', summary.consumedLicenses || 0],
    ['Remaining Licenses', summary.remainingLicenses || 0],
  ];
  return (
    <div style={{ display:'grid', gap:14 }}>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(170px, 1fr))', gap:12 }}>
        {cards.map(([label, value]) => (
          <div key={label} style={supportInfoCard}>
            <span style={{ color:'#a78bfa', fontSize:11, fontWeight:900 }}>{label}</span>
            <b style={{ color:'#e9d5ff', fontSize:22 }}>{value}</b>
          </div>
        ))}
      </div>
      <DarkTable
        headers={['Invoice ID', 'Payment ID', 'Agent Quantity', 'Plan Type', 'Buy Date', 'Expiry Date', 'License Status', 'Auto Pay']}
        rows={purchases}
        empty="No agent license purchases yet."
        renderRow={item => (
          <tr key={item._id || item.invoiceId || item.paymentId}>
            <Cell>{item.invoiceId || '-'}</Cell>
            <Cell>{item.paymentId || '-'}</Cell>
            <Cell>{item.agentQuantity || 0}</Cell>
            <Cell>{title(String(item.planType || 'monthly').replace('_', ' '))}</Cell>
            <Cell>{formatDateTime(item.buyDate)}</Cell>
            <Cell>{formatDateTime(item.expiryDate)}</Cell>
            <Cell><Badge>{item.status || 'inactive'}</Badge></Cell>
            <Cell><Badge>{item.autoPay ? 'Enabled' : 'Disabled'}</Badge></Cell>
          </tr>
        )}
      />
    </div>
  );
}

function AgentAutoPayPanel({ partner, payments = [] }) {
  const agentAutoPay = partner?.agentLicenseAutoPay || {};
  const planAutoPay = partner?.plan?.autoPay || false;
  const purchases = partner?.agentLicensePurchases || [];
  const agentEnabled = !!agentAutoPay.enabled || purchases.some(item => item.autoPay);
  const autoPayFee = Number(agentAutoPay.feeInr || purchases.find(item => item.autoPayFeeInr)?.autoPayFeeInr || 0);
  const latestAutoPayPayment = payments
    .filter(payment => payment.autoPay || payment.notes?.autoPay || payment.source === 'agent_license_autopay')
    .sort((a, b) => new Date(b.paidAt || b.createdAt || 0) - new Date(a.paidAt || a.createdAt || 0))[0];
  const rows = purchases.length ? purchases : [];

  return (
    <section style={{ display:'grid', gap:14 }}>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(220px, 1fr))', gap:12 }}>
        <div style={supportInfoCard}>
          <span style={{ color:'#a78bfa', fontSize:11, fontWeight:900 }}>Agent License Auto Pay</span>
          <b style={{ color:agentEnabled ? '#34d399' : '#f87171', fontSize:24 }}>{agentEnabled ? 'Enabled' : 'Disabled'}</b>
          <span style={{ color:'#94a3b8', fontSize:12 }}>Only for Buy Agent License payments</span>
        </div>
        <div style={supportInfoCard}>
          <span style={{ color:'#a78bfa', fontSize:11, fontWeight:900 }}>Subscription Auto Pay</span>
          <b style={{ color:planAutoPay ? '#34d399' : '#f87171', fontSize:24 }}>{planAutoPay ? 'Enabled' : 'Disabled'}</b>
          <span style={{ color:'#94a3b8', fontSize:12 }}>Partner platform subscription</span>
        </div>
        <div style={supportInfoCard}>
          <span style={{ color:'#a78bfa', fontSize:11, fontWeight:900 }}>Auto Pay Fee</span>
          <b style={{ color:'#e9d5ff', fontSize:24 }}>{autoPayFee ? `₹${autoPayFee.toLocaleString('en-IN')}` : '-'}</b>
          <span style={{ color:'#94a3b8', fontSize:12 }}>Enable charge</span>
        </div>
        <div style={supportInfoCard}>
          <span style={{ color:'#a78bfa', fontSize:11, fontWeight:900 }}>Last Auto Pay Payment</span>
          <b style={{ color:'#e9d5ff', fontSize:18 }}>{latestAutoPayPayment?.paymentId || '-'}</b>
          <span style={{ color:'#94a3b8', fontSize:12 }}>{formatDateTime(latestAutoPayPayment?.paidAt || latestAutoPayPayment?.createdAt)}</span>
        </div>
      </div>

      <DarkTable
        headers={['Invoice ID', 'Payment ID', 'Plan Type', 'Agent Quantity', 'Auto Pay', 'Enabled At', 'Disabled At']}
        rows={rows}
        empty="No agent license auto pay records yet."
        renderRow={item => (
          <tr key={item._id || item.invoiceId || item.paymentId}>
            <Cell>{item.invoiceId || '-'}</Cell>
            <Cell>{item.paymentId || '-'}</Cell>
            <Cell>{title(String(item.planType || 'monthly').replace('_', ' '))}</Cell>
            <Cell>{item.agentQuantity || 0}</Cell>
            <Cell><Badge>{item.autoPay ? 'Enabled' : 'Disabled'}</Badge></Cell>
            <Cell>{formatDateTime(item.autoPayEnabledAt || agentAutoPay.enabledAt)}</Cell>
            <Cell>{formatDateTime(item.autoPayDisabledAt || agentAutoPay.disabledAt)}</Cell>
          </tr>
        )}
      />
    </section>
  );
}

function PartnerEditActions({ editing, saving, onEdit, onCancel, formId, onSave }) {
  return (
    <div className="partner-edit-actions">
      {editing ? <>
        <button type="button" disabled={saving} onClick={onCancel}>Cancel</button>
        <button type={formId ? 'submit' : 'button'} form={formId} disabled={saving} onClick={onSave} className="partner-edit-save">{saving ? 'Saving…' : 'Save Changes'}</button>
      </> : <button type="button" disabled={saving} onClick={onEdit}><Pencil size={14} aria-hidden="true" /> Edit</button>}
    </div>
  );
}

function AgentPaymentControlPanel({ editForm, setEditField, saving, onSave, editing, onEdit, onCancel, capabilities = {}, planPaid }) {
  return (
    <section style={agentPaymentShell}>
      <form id="partner-agent-pricing-form" onSubmit={event => { event.preventDefault(); onSave(); }}>
        <div className="partner-edit-heading">
          <h3 style={panelTitle}>Agent Pricing</h3>
          <PartnerEditActions editing={editing} saving={saving} onEdit={onEdit} onCancel={onCancel} formId="partner-agent-pricing-form" />
        </div>
        <div className="partner-agent-pricing" style={agentPricingCard}>
          {agentPricingTypes.map(({ type, label, tone }) => (
            <fieldset className="partner-device-pricing" key={type} disabled={!editing || saving}>
              <legend style={{ color: tone }}>{label}</legend>
              {['monthly', 'yearly'].map(period => (
                <PaymentPlanInput
                  key={period}
                  icon="₹"
                  tone={tone}
                  label={`${label} ${title(period)} / Agent`}
                  value={editForm[agentPriceField(type, period)]}
                  onChange={value => setEditField(agentPriceField(type, period), value)}
                  help={`Price per ${label.toLowerCase()} agent for ${period === 'monthly' ? '1 month' : '1 year'}`}
                />
              ))}
            </fieldset>
          ))}
        </div>
        <div style={{ ...agentPaymentActions, marginTop: 16 }}>
          <PaymentStatusChip tone="#22c55e">Payment Control: {planPaid || capabilities.subscriptionPurchase ? 'Allowed' : 'Pending'}</PaymentStatusChip>
          <PaymentStatusChip tone="#238bff">System Control: {capabilities.createCompany ? 'Allowed' : 'Pending'}</PaymentStatusChip>
        </div>
      </form>
      <div style={agentSummaryCard}>
        <h3 style={agentSummaryTitle}>Agent Pricing Summary</h3>
        <div style={agentSummaryTableWrap}>
          <table style={agentSummaryTable}>
            <thead><tr>{['Agent Type', 'Monthly / Agent', 'Yearly / Agent'].map(header => <th key={header} style={agentSummaryTh}>{header}</th>)}</tr></thead>
            <tbody>
              {agentPricingTypes.map(({ type, label, tone }) => (
                <tr key={type}>
                  <td style={{ ...agentSummaryTd, color: tone }}><b>{label}</b></td>
                  {['monthly', 'yearly'].map(period => (
                    <td key={period} style={agentSummaryTd}>₹{Number(editForm[agentPriceField(type, period)] || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

function PaymentPlanInput({ icon, tone, label, value, onChange, help }) {
  return (
    <label style={{ ...agentPlanInputWrap, borderRightColor:`${tone}22` }}>
      <span style={{ ...agentPlanInputLabel, color:tone }}>{icon} {label}</span>
      <input
        type="number"
        min="0"
        step="0.01"
        required
        aria-label={label}
        value={value}
        onChange={event => onChange(event.target.value)}
        style={agentPlanInput}
      />
      <small style={agentPlanHelp}>{help}</small>
    </label>
  );
}

function PaymentStatusChip({ children, tone }) {
  return <span style={{ ...agentPaymentChip, color:tone, borderColor:`${tone}22`, background:`${tone}10` }}>{children}</span>;
}

function DocumentsPanel({ partner, saving, onSave }) {
  const [openDoc, setOpenDoc] = useState(null);
  const [kycAction, setKycAction] = useState('');

  if (!partner) return <EmptyPanel text="Partner details loading. Select a partner again if this stays empty." />;

  const profile = partner.profile || {};
  const kycStatus = profile.kycStatus || 'not_submitted';
  const docs = [
    { name: 'Profile Image', id: profile.avatarFileName ? displayFileName(profile.avatarFileName) : '-', type: 'image', previewUrl: profile.avatarFilePath ? `${SOCKET_URL}/uploads/${profile.avatarFilePath}` : profile.avatarDataUrl || '', status: profile.avatarFileName ? 'Uploaded' : 'Not uploaded', tone: profile.avatarFileName ? 'good' : 'warn' },
    { name: 'GST Certificate', id: profile.kycDocuments?.gstCertificateName ? displayFileName(profile.kycDocuments.gstCertificateName) : profile.gstNumber || '-', type: profile.kycDocuments?.gstCertificateType || '', previewUrl: profile.kycDocuments?.gstCertificateFilePath ? `${SOCKET_URL}/uploads/${profile.kycDocuments.gstCertificateFilePath}` : profile.kycDocuments?.gstCertificateDataUrl || '', status: profile.gstVerified ? 'Verified' : profile.kycDocuments?.gstCertificateName ? 'Uploaded' : 'Not uploaded', tone: profile.gstVerified || profile.kycDocuments?.gstCertificateName ? 'good' : 'warn' },
    { name: 'PAN Card', id: profile.kycDocuments?.panCardName ? displayFileName(profile.kycDocuments.panCardName) : profile.panNumber || '-', type: profile.kycDocuments?.panCardType || '', previewUrl: profile.kycDocuments?.panCardFilePath ? `${SOCKET_URL}/uploads/${profile.kycDocuments.panCardFilePath}` : profile.kycDocuments?.panCardDataUrl || '', status: profile.panVerified ? 'Verified' : profile.kycDocuments?.panCardName ? 'Uploaded' : 'Not uploaded', tone: profile.panVerified || profile.kycDocuments?.panCardName ? 'good' : 'warn' },
    { name: 'Business Registration', id: profile.kycDocuments?.businessRegistrationName ? displayFileName(profile.kycDocuments.businessRegistrationName) : partner.agreementDetails || '-', type: profile.kycDocuments?.businessRegistrationType || '', previewUrl: profile.kycDocuments?.businessRegistrationFilePath ? `${SOCKET_URL}/uploads/${profile.kycDocuments.businessRegistrationFilePath}` : profile.kycDocuments?.businessRegistrationDataUrl || '', status: profile.businessVerified ? 'Verified' : profile.kycDocuments?.businessRegistrationName ? 'Uploaded' : 'Not uploaded', tone: profile.businessVerified || profile.kycDocuments?.businessRegistrationName ? 'good' : 'warn' },
    { name: 'Agreement PDF', id: partner.agreementFileName ? displayFileName(partner.agreementFileName) : partner.agreementDetails || '-', type: partner.agreementFileType || 'application/pdf', previewUrl: partner.agreementFilePath ? `${SOCKET_URL}/uploads/${partner.agreementFilePath}` : '', status: partner.agreementFilePath ? 'Uploaded' : partner.agreementFileName ? 'Re-upload required' : partner.agreementDetails ? 'Added' : 'Not uploaded', tone: partner.agreementFilePath || partner.agreementDetails ? 'good' : 'warn' },
    { name: 'Bank Account', id: profile.accountNumber || profile.bankAccount || '-', status: profile.accountNumber || profile.bankAccount ? 'Submitted' : 'Not submitted', tone: profile.accountNumber || profile.bankAccount ? 'good' : 'warn' },
    { name: 'Razorpay Linked Account', id: partner.partner_linked_account_id || '-', status: partner.partner_linked_account_id ? 'Connected' : 'Not connected', tone: partner.partner_linked_account_id ? 'good' : 'warn' },
  ];
  const updateKycStatus = async status => {
    if (saving || kycAction || status === kycStatus) return;
    setKycAction(status);
    try {
      await onSave({ kycStatus: status }, status === 'verified' ? 'KYC approved.' : 'KYC rejected.');
    } finally {
      setKycAction('');
    }
  };

  return (
    <section style={panelStyle}>
      <div style={{ display:'flex', justifyContent:'space-between', gap:12, alignItems:'center', marginBottom:16, flexWrap:'wrap' }}>
        <h3 style={{ ...panelTitle, margin:0 }}>Documents</h3>
        <div style={{ display:'flex', gap:8, alignItems:'center', flexWrap:'wrap' }}>
          <Badge>KYC: {kycStatus}</Badge>
          <button
            type="button"
            disabled={saving || Boolean(kycAction) || kycStatus === 'verified'}
            onClick={() => updateKycStatus('verified')}
            style={{ ...outlineButton, height:32, color:'#86efac', border:'1px solid #047857', opacity:saving || kycAction || kycStatus === 'verified' ? .6 : 1 }}
          >
            {kycAction === 'verified' ? 'Approving...' : 'Approve KYC'}
          </button>
          <button
            type="button"
            disabled={saving || Boolean(kycAction) || kycStatus === 'rejected'}
            onClick={() => updateKycStatus('rejected')}
            style={{ ...outlineButton, height:32, color:'#fca5a5', border:'1px solid #991b1b', opacity:saving || kycAction || kycStatus === 'rejected' ? .6 : 1 }}
          >
            {kycAction === 'rejected' ? 'Rejecting...' : 'Reject KYC'}
          </button>
        </div>
      </div>

      <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(230px, 1fr))', gap:12, marginBottom:18 }}>
	        {docs.map(doc => {
	          const isRazorpayDoc = doc.name === 'Razorpay Linked Account';
	          const canOpen = Boolean(doc.previewUrl);
	          return (
	          <div
	            key={doc.name}
            role={canOpen ? 'button' : undefined}
            tabIndex={canOpen ? 0 : undefined}
            onClick={() => canOpen && setOpenDoc(doc)}
            onKeyDown={e => {
              if (!canOpen) return;
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                setOpenDoc(doc);
              }
            }}
            style={{
              border:'1px solid #312e81',
              borderRadius:10,
              padding:14,
              background:'#0f172a',
              minHeight:94,
              textAlign:'left',
              cursor:canOpen ? 'pointer' : 'default',
              opacity:canOpen ? 1 : .86,
            }}
          >
            <div style={{ display:'flex', justifyContent:'space-between', gap:10, alignItems:'flex-start' }}>
              <div style={{ color:'#e9d5ff', fontSize:14, fontWeight:900 }}>{doc.name}</div>
              <span style={{ color:doc.tone === 'good' ? '#34d399' : '#f59e0b', fontSize:11, fontWeight:900 }}>{doc.status}</span>
            </div>
            <div style={{ color:'#a78bfa', fontSize:12, fontWeight:800, marginTop:12 }}>Reference</div>
            {isRazorpayDoc ? (
              <div style={{ display:'grid', gap:8, marginTop:7 }}>
                <div style={{ color:'#e9d5ff', fontSize:13, fontWeight:850, wordBreak:'break-word' }}>{doc.id}</div>
                <div style={{ color:'#a78bfa', fontSize:11, fontWeight:750, lineHeight:1.4 }}>
                  Razorpay Route linked account ID. Blank rakhne par payout manual/pending rahega.
                </div>

              </div>
	            ) : (
	              <>
	                <div style={{ color:'#e9d5ff', fontSize:13, fontWeight:850, marginTop:5, wordBreak:'break-word' }}>{doc.id}</div>
		                {!canOpen && !isRazorpayDoc && <div style={{ color:'#64748b', fontSize:11, fontWeight:850, marginTop:10 }}>No uploaded file</div>}

              </>
            )}
          </div>
          );
        })}
      </div>

      <DarkTable
        headers={['Document', 'Reference / Value', 'Status', 'Open']}
        rows={docs}
        empty="No document data found."
        renderRow={doc => (
          <tr key={`${doc.name}-row`}>
            <Cell>{doc.name}</Cell>
          <Cell>{doc.id}</Cell>
          <Cell><Badge>{doc.status}</Badge></Cell>
	          <Cell>{doc.previewUrl ? <SmallButton onClick={() => setOpenDoc(doc)}>Open Preview</SmallButton> : <span style={{ color:'#64748b' }}>No file</span>}</Cell>
        </tr>
        )}
      />
      {openDoc && (
        <DocumentPreviewModal
          doc={openDoc}
          onClose={() => setOpenDoc(null)}
        />
      )}
    </section>
  );
}

function DocumentPreviewModal({ doc, onClose }) {
  const openInBrowser = () => {
    if (!doc.previewUrl) return;
    window.open(doc.previewUrl, '_blank', 'noopener,noreferrer');
  };
  return (
    <div style={modalBackdrop} onClick={onClose}>
      <div style={modalPanel} onClick={e => e.stopPropagation()}>
        <div style={{ display:'flex', justifyContent:'space-between', gap:12, alignItems:'flex-start', marginBottom:14 }}>
          <div>
            <h3 style={{ ...panelTitle, margin:0 }}>{doc.name}</h3>
            <div style={{ color:'#a78bfa', fontSize:12, fontWeight:850, marginTop:4 }}>{doc.status}</div>
          </div>
	          <div style={{ display:'flex', gap:8, alignItems:'center' }}>
	            {doc.previewUrl && <button type="button" onClick={openInBrowser} style={outlineButton}>Open File</button>}
	            <button type="button" onClick={onClose} style={iconButton}>x</button>
	          </div>
	        </div>
        <div style={previewBox}>
          <div style={{ color:'#c4b5fd', fontSize:12, fontWeight:900 }}>Reference / Value</div>
          <div style={{ color:'#e9d5ff', fontSize:15, fontWeight:900, marginTop:8, wordBreak:'break-word' }}>{doc.id}</div>
        </div>
	        {doc.previewUrl ? (
	          <>
	            <div style={{ display:'flex', justifyContent:'flex-end', marginTop:12 }}>
	              <button type="button" onClick={openInBrowser} style={{ ...outlineButton, color:'#93c5fd', border:'1px solid #2563eb' }}>Open File</button>
	            </div>
	            <div style={documentFrame}>
	              {String(doc.type || '').includes('pdf') || String(doc.previewUrl).startsWith('data:application/pdf') ? (
	                <iframe title={`${doc.name} preview`} src={doc.previewUrl} style={pdfPreview} />
	              ) : (
	                <img src={doc.previewUrl} alt={`${doc.name} preview`} style={imagePreview} />
	              )}
	            </div>
	          </>
	        ) : (
          <div style={{ color:'#a78bfa', fontSize:12, lineHeight:1.55, marginTop:12 }}>
            Is document ka preview abhi backend me saved nahi hai. Partner ko document dobara upload/save karna hoga, phir yahan image/PDF show hogi.
          </div>
        )}
      </div>
    </div>
  );
}

function ActivityTable({ activity, partner }) {
  const fallbackActivity = partner ? [
    {
      type: 'Partner Created',
      detail: `${partner.name || 'Partner'} account created${partner.ownerUserId?.email ? ` for ${partner.ownerUserId.email}` : ''}`,
      date: partner.createdAt,
    },
    {
      type: 'Partner Updated',
      detail: `Current status: ${partner.status || 'unknown'}`,
      date: partner.updatedAt,
    },
    ...(partner.resourceRequest?.status && partner.resourceRequest.status !== 'none' ? [{
      type: `Resource Request ${partner.resourceRequest.status}`,
      detail: `${partner.resourceRequest.numberOfCompanies || 0} companies, ${partner.resourceRequest.numberOfAgents || 0} agents, ${partner.resourceRequest.proposedCommission || 0}% commission`,
      date: partner.resourceRequest.reviewedAt || partner.resourceRequest.requestedAt || partner.updatedAt,
    }] : []),
  ].filter(item => item.date) : [];
  const rows = activity.length ? activity : fallbackActivity;
  return (
    <DarkTable
      headers={['Activity', 'Details', 'Date']}
      rows={rows}
      empty="No activity found for this partner."
      renderRow={(item, index) => (
        <tr key={`${item.type}-${index}`}>
          <Cell>{item.type}</Cell>
          <Cell>{item.detail}</Cell>
          <Cell>{formatDateTime(item.date)}</Cell>
        </tr>
      )}
    />
  );
}

function SupportPanel({ partner, tickets = [] }) {
  const [supportRows, setSupportRows] = useState(tickets);
  const [selectedTicket, setSelectedTicket] = useState(null);
  const [replyMessage, setReplyMessage] = useState('');
  const [replyBusy, setReplyBusy] = useState(false);
  const [editingStatus, setEditingStatus] = useState(false);
  const [statusDraft, setStatusDraft] = useState('');
  const [statusBusy, setStatusBusy] = useState(false);

  useEffect(() => { setEditingStatus(false); }, [selectedTicket?._id]);

  useEffect(() => {
    setSupportRows(tickets);
    setSelectedTicket(prev => prev ? (tickets.find(t => t._id === prev._id) || prev) : null);
  }, [tickets]);

  const sendReply = async (e) => {
    e.preventDefault();
    if (!replyMessage.trim() || !selectedTicket) return;
    setReplyBusy(true);
    try {
      const { data } = await api.post(`/superadmin/support-tickets/${selectedTicket._id}/messages`, {
        message: replyMessage
      });
      setReplyMessage('');
      setSelectedTicket(data);
      setSupportRows(prev => prev.map(t => t._id === data._id ? data : t));
    } catch (err) {
      alert(err.response?.data?.message || 'Failed to send response');
    } finally {
      setReplyBusy(false);
    }
  };

  const updateStatus = async (newStatus) => {
    if (!selectedTicket || !editingStatus || statusBusy) return;
    setStatusBusy(true);
    try {
      const { data } = await api.patch(`/superadmin/support-tickets/${selectedTicket._id}`, {
        status: newStatus
      });
      setSelectedTicket(data);
      setSupportRows(prev => prev.map(t => t._id === data._id ? data : t));
      setEditingStatus(false);
    } catch (err) {
      alert(err.response?.data?.message || 'Status update failed');
    } finally {
      setStatusBusy(false);
    }
  };

  const openCount = supportRows.filter(ticket => ['Open', 'In Progress'].includes(ticket.status)).length;
  const highestPriority = supportRows.find(ticket => ['Critical', 'High'].includes(ticket.priority))?.priority || supportRows[0]?.priority || '-';

  return (
    <section style={panelStyle}>
      <div className="partner-support-summary" role="region" aria-label="Support summary" tabIndex={0}>
        <div className="partner-support-heading">
          <div><h3 style={{ ...panelTitle, margin:0 }}>Support</h3><Badge>{supportRows.length} Tickets</Badge></div>
          <p>{partner?.name || 'Partner'} support tickets</p>
        </div>
        <div className="partner-support-stat">
          <div><span>Priority</span><strong>{highestPriority}</strong></div>
          <p>{highestPriority === '-' ? 'No active issue priority' : 'Highest visible priority'}</p>
        </div>
        <div className="partner-support-stat">
          <div><span>Partner Status</span><strong>{title(partner?.status || 'approved')}</strong></div>
          <p>{partner?.ownerUserId?.email || '-'}</p>
        </div>
        <div className="partner-support-stat">
          <div><span>Open Tickets</span><strong>{openCount}</strong></div>
          <p>{openCount ? 'Needs review' : 'No open tickets'}</p>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr', gap: 20, alignItems: 'start', marginTop: 14 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 450, overflowY: 'auto' }}>
          {supportRows.length === 0 ? (
            <div style={{ color: '#cbd5e1', fontSize: 13, padding: 10 }}>No support tickets found.</div>
          ) : (
            supportRows.map(t => {
              const isSelected = selectedTicket?._id === t._id;
              const priorityColors = {
                Low: { bg: 'rgba(148,163,184,0.1)', text: '#cbd5e1' },
                Medium: { bg: 'rgba(249,115,22,0.1)', text: '#f97316' },
                High: { bg: 'rgba(239,68,68,0.1)', text: '#ef4444' },
                Critical: { bg: 'rgba(220,38,38,0.2)', text: '#f87171' }
              };
              const statusColors = {
                'Open': '#eab308',
                'In Progress': '#3b82f6',
                'Resolved': '#10b981',
                'Closed': '#64748b'
              };
              const prio = priorityColors[t.priority] || priorityColors.Medium;
              return (
                <div
                  key={t._id}
                  onClick={() => setSelectedTicket(t)}
                  style={{
                    padding: 12, borderRadius: 8, cursor: 'pointer',
                    background: isSelected ? 'rgba(139,92,246,0.15)' : '#0f172a',
                    border: isSelected ? '1px solid #8b5cf6' : '1px solid #312e81',
                    transition: 'all 0.2s'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: '#60a5fa', fontWeight: 'bold' }}>{t.ticketId}</span>
                    <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 4, background: prio.bg, color: prio.text, fontWeight: 700 }}>
                      {t.priority?.toUpperCase()}
                    </span>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 'bold', color: '#f8fafc', marginBottom: 4 }}>{t.subject}</div>
                  <div style={{ fontSize: 11, color: '#93c5fd', marginBottom: 6 }}>Category: {t.category}</div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 11, color: '#94a3b8' }}>
                    <span>{new Date(t.createdAt).toLocaleDateString()}</span>
                    <span style={{ fontWeight: 700, color: statusColors[t.status] || '#cbd5e1' }}>{t.status}</span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {selectedTicket ? (
          <div style={{ background: '#0f172a', border: '1px solid #312e81', borderRadius: 10, padding: 20 }}>
            <div style={{ borderBottom: '1px solid #312e81', paddingBottom: 12, marginBottom: 14 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 6 }}>
                <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>Ticket: {selectedTicket.ticketId}</h3>
                <PartnerEditActions editing={editingStatus} saving={statusBusy} onEdit={() => { setStatusDraft(selectedTicket.status); setEditingStatus(true); }} onCancel={() => setEditingStatus(false)} onSave={() => updateStatus(statusDraft)} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <span style={{ fontSize: 12, color: '#94a3b8' }}>Status:</span>
                  <select
                    aria-label="Ticket status"
                    disabled={!editingStatus || statusBusy}
                    value={editingStatus ? statusDraft : selectedTicket.status}
                    onChange={(e) => setStatusDraft(e.target.value)}
                    style={{
                      background: '#1e1b4b', color: '#e0f2fe', border: '1px solid #312e81',
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

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 250, overflowY: 'auto', marginBottom: 14, paddingRight: 4 }}>
              {(selectedTicket.messages || []).map((msg, idx) => {
                const isMe = msg.senderRole === 'superadmin';
                return (
                  <div
                    key={msg._id || idx}
                    style={{
                      alignSelf: isMe ? 'flex-end' : 'flex-start',
                      maxWidth: '85%',
                      background: isMe ? 'linear-gradient(135deg, #7c3aed, #8b5cf6)' : 'rgba(30,41,59,0.4)',
                      border: isMe ? 'none' : '1px solid #312e81',
                      padding: '10px 14px', borderRadius: 12,
                      color: '#f8fafc', fontSize: 13, lineHeight: 1.4
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, marginBottom: 4, fontSize: 10, color: isMe ? '#ddd6fe' : '#94a3b8', fontWeight: 600 }}>
                      <span>{msg.senderName} ({msg.senderRole === 'superadmin' ? 'Super Admin' : msg.senderRole === 'company_admin' ? 'Company Admin' : 'Partner Admin'})</span>
                      <span>{new Date(msg.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
                    </div>
                    <div style={{ whiteSpace: 'pre-wrap' }}>{msg.message}</div>
                  </div>
                );
              })}
            </div>

            {selectedTicket.status === 'Closed' ? (
              <div style={{ background: 'rgba(239,68,68,0.1)', color: '#f87171', padding: '10px 14px', borderRadius: 8, fontSize: 12, textAlign: 'center' }}>
                This ticket has been closed.
              </div>
            ) : (
              <form onSubmit={sendReply} style={{ display: 'flex', gap: 10 }}>
                <textarea
                  required
                  placeholder="Type administrative response..."
                  value={replyMessage}
                  onChange={e => setReplyMessage(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      sendReply(e);
                    }
                  }}
                  rows={1}
                  style={{
                    flex: 1, padding: '10px 14px', borderRadius: 8, border: '1px solid #312e81',
                    background: '#1e1b4b', color: '#f8fafc', fontSize: 13, outline: 'none',
                    resize: 'vertical', fontFamily: 'inherit', lineHeight: '1.4', minHeight: '38px'
                  }}
                />
                <button
                  type="submit"
                  disabled={replyBusy}
                  style={{
                    padding: '0 20px', borderRadius: 8, border: 'none',
                    background: 'linear-gradient(135deg, #8b5cf6, #7c3aed)',
                    color: '#fff', fontSize: 13, fontWeight: 700, cursor: 'pointer'
                  }}
                >
                  {replyBusy ? 'Sending...' : 'Send'}
                </button>
              </form>
            )}
          </div>
        ) : (
          <div style={{ background: '#0f172a', padding: 40, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#cbd5e1', fontSize: 13, border: '1px dashed #312e81', borderRadius: 10, width: '100%', boxSizing: 'border-box' }}>
            Select a ticket from the list to view conversation history.
          </div>
        )}
      </div>
    </section>
  );
}

function RevenueTable({ partners }) {
  return (
    <DarkTable
      headers={['Partner Wise', 'Total Companies', 'Total Agents', 'Total Collection', 'Platform Commission', 'Partner Profit']}
      rows={partners}
      empty="No partners found."
      renderRow={p => {
        const collected = Number(p.plan?.amountPaid || 0);
        const platform = Math.round(collected * 0.2);
        return (
          <tr key={p._id}>
            <Cell>{p.name}</Cell>
            <Cell>{p.resourceRequest?.numberOfCompanies || 0}</Cell>
            <Cell>{p.resourceRequest?.numberOfAgents || 0}</Cell>
            <Cell>₹{collected.toLocaleString('en-IN')}</Cell>
            <Cell>₹{platform.toLocaleString('en-IN')}</Cell>
            <Cell>₹{(collected - platform).toLocaleString('en-IN')}</Cell>
          </tr>
        );
      }}
    />
  );
}

function Metric({ label, value, sub, color, icon }) {
  return (
    <div style={metricCard}>
      <div>
        <div style={{ color:'#c4b5fd', fontSize:12, fontWeight:800 }}>{label}</div>
        <div style={{ color, fontSize:24, fontWeight:900, marginTop:6 }}>{value}</div>
        <div style={{ color:'#8b5cf6', fontSize:11, marginTop:4 }}>{sub}</div>
      </div>
      <div style={{ width:46, height:46, borderRadius:'50%', background:`${color}22`, color, display:'grid', placeItems:'center', fontSize:23 }}>{icon}</div>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <section style={panelStyle}>
      <h3 style={panelTitle}>{title}</h3>
      {children}
    </section>
  );
}

function attachmentUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (/^https?:\/\//i.test(raw) || raw.startsWith('data:image/')) return raw;
  if (raw.includes('/')) return `${SOCKET_URL}/uploads/${raw.replace(/^\/+/, '').replace(/^uploads\//, '')}`;
  return '';
}

function DarkTable({ headers, rows, renderRow, empty }) {
  const pageSize = 10;
  const [page, setPage] = useState(0);
  const totalPages = Math.max(Math.ceil((rows?.length || 0) / pageSize), 1);
  const currentPage = Math.min(page, totalPages - 1);
  const pageRows = (rows || []).slice(currentPage * pageSize, currentPage * pageSize + pageSize);

  useEffect(() => {
    setPage(0);
  }, [rows?.length]);

  return (
    <div className="partner-table" style={{ border:'1px solid #293451', borderRadius:10, overflow:'hidden' }}>
      <div style={{ overflowX:'auto' }}>
        <table style={{ width:'100%', borderCollapse:'collapse', background:'#141c31' }}>
          <thead><tr>{headers.map(header => <th key={header} style={thStyle}>{header}</th>)}</tr></thead>
          <tbody>
            {(rows || []).length === 0 ? (
              <tr><td colSpan={headers.length} style={{ ...tdStyle, textAlign:'center', color:'#a78bfa', padding:24 }}>{empty}</td></tr>
            ) : pageRows.map(renderRow)}
          </tbody>
        </table>
      </div>
      {(rows || []).length > pageSize && (
        <div style={tablePager}>
          <button type="button" disabled={currentPage === 0} onClick={() => setPage(prev => Math.max(prev - 1, 0))} style={tablePagerButton(currentPage === 0)}>Prev</button>
          <button type="button" disabled={currentPage >= totalPages - 1} onClick={() => setPage(prev => Math.min(prev + 1, totalPages - 1))} style={tablePagerButton(currentPage >= totalPages - 1)}>Next</button>
        </div>
      )}
    </div>
  );
}

function Input({ label, value, onChange, type = 'text', required, placeholder = '', help = '' }) {
  return (
    <label style={{ color:'#c4b5fd', fontSize:12, fontWeight:800 }}>
      {label}
      <input aria-label={label} type={type} value={value} onChange={e => onChange(e.target.value)} required={required} placeholder={placeholder} style={{ ...inputStyle, width:'100%', marginTop:5 }} />
      {help && <span style={{ display:'block', color:'#a78bfa', fontSize:11, fontWeight:700, lineHeight:1.45, marginTop:5 }}>{help}</span>}
    </label>
  );
}

function Select({ label, value, onChange, options }) {
  return (
    <label style={{ color:'#c4b5fd', fontSize:12, fontWeight:800 }}>
      {label}
      <select aria-label={label} value={value} onChange={e => onChange(e.target.value)} style={{ ...inputStyle, width:'100%', marginTop:5 }}>
        {options.map(([optionValue, labelText]) => <option key={optionValue} value={optionValue}>{labelText}</option>)}
      </select>
    </label>
  );
}

function Textarea({ label, value, onChange }) {
  return (
    <label style={{ color:'#c4b5fd', fontSize:12, fontWeight:800 }}>
      {label}
      <textarea value={value} onChange={e => onChange(e.target.value)} rows={4} style={{ ...inputStyle, width:'100%', marginTop:5, resize:'vertical' }} />
    </label>
  );
}

function Cell({ children }) {
  return <td style={tdStyle}>{children}</td>;
}

function SmallButton({ children, onClick, good, danger, disabled }) {
  const bg = good ? '#047857' : danger ? '#991b1b' : '#312e81';
  return <button type="button" disabled={disabled} onClick={onClick} style={{ marginRight:6, marginBottom:4, padding:'6px 9px', border:'none', borderRadius:6, background:bg, color:'#fff', cursor:disabled ? 'not-allowed' : 'pointer', fontSize:11, fontWeight:800 }}>{children}</button>;
}

function Badge({ children }) {
  return <span style={{ padding:'3px 9px', borderRadius:99, background:'#0f172a', color:'#c4b5fd', border:'1px solid #312e81', fontSize:10, fontWeight:900 }}>{children || 'none'}</span>;
}

function EmptyPanel({ text }) {
  return <section style={panelStyle}><div style={{ color:'#a78bfa', fontSize:13 }}>{text}</div></section>;
}

function formatDate(value) {
  return value ? new Date(value).toLocaleDateString() : '-';
}

function formatDateTime(value) {
  return value ? new Date(value).toLocaleString() : '-';
}

function initials(name = '') {
  const parts = String(name || 'P').trim().split(/\s+/).slice(0, 2);
  return parts.map(part => part[0]?.toUpperCase()).join('') || 'P';
}

function partnerSubdomain(partner = {}) {
  return partner.tenantId?.subdomain || partner.tenantId?.slug || partner.slug || '-';
}

function avatarBg(index) {
  return ['#312e81', '#064e3b', '#7f1d1d', '#1e3a8a', '#78350f'][index % 5];
}

function avatarColor(index) {
  return ['#c4b5fd', '#6ee7b7', '#fecaca', '#bfdbfe', '#fde68a'][index % 5];
}

function title(value) {
  return value.charAt(0).toUpperCase() + value.slice(1);
}

function statusForEdit(status) {
  if (status === 'suspended' || status === 'rejected') return 'suspended';
  if (status === 'pending_request') return 'pending';
  return 'active';
}

const topBar = { display:'flex', justifyContent:'space-between', gap:18, alignItems:'flex-start', marginBottom:18 };
const backButton = { border:'none', background:'transparent', color:'#a78bfa', fontSize:12, fontWeight:900, cursor:'pointer', padding:0, marginBottom:8 };
const pageTitle = { fontSize:24, color:'#e9d5ff', margin:'0 0 5px', fontWeight:900 };
const metaLine = { display:'flex', gap:8, flexWrap:'wrap', color:'#a78bfa', fontSize:12, marginTop:3 };
const metricGrid = { display:'grid', gridTemplateColumns:'repeat(auto-fit, minmax(185px, 1fr))', gap:14, marginBottom:18 };
const metricCard = { background:'#141c31', border:'1px solid #312e81', borderRadius:10, padding:'15px 16px', display:'flex', justifyContent:'space-between', gap:12, alignItems:'center', boxShadow:'0 10px 24px rgba(15, 23, 42, .22)' };
const overviewGrid = { display:'grid', gridTemplateColumns:'1.25fr .9fr .85fr .85fr', gap:14 };
const panelStyle = { background:'#141c31', border:'1px solid #312e81', borderRadius:10, padding:16, boxShadow:'0 10px 24px rgba(15, 23, 42, .22)' };
const panelTitle = { color:'#e9d5ff', fontSize:14, margin:'0 0 12px', fontWeight:900 };
const inputStyle = { padding:'9px 11px', borderRadius:6, background:'#0f172a', border:'1px solid #312e81', color:'#e2e8f0', fontSize:13, boxSizing:'border-box' };
const primaryButton = { marginTop:12, padding:'9px 14px', borderRadius:6, border:'none', background:'#7c3aed', color:'#fff', cursor:'pointer', fontWeight:800 };
const agentPaymentShell = { display:'grid', gap:18 };
const agentPricingCard = { display:'grid', gridTemplateColumns:'repeat(3, minmax(220px, 1fr))', gap:18, background:'linear-gradient(180deg, rgba(15,23,42,.9), rgba(30,27,75,.75))', border:'1px solid #312e81', borderRadius:10, padding:18, boxShadow:'0 16px 35px rgba(2,6,23,.28)' };
const agentPlanInputWrap = { display:'grid', gap:9, paddingRight:18, borderRight:'1px solid rgba(49,46,129,.65)', color:'#c4b5fd', fontSize:12, fontWeight:900 };
const agentPlanInputLabel = { display:'flex', alignItems:'center', gap:8, fontSize:12, fontWeight:950 };
const agentPlanInput = { height:40, border:'1px solid #1e3a5f', borderRadius:6, background:'#050c1d', color:'#e2e8f0', padding:'0 12px', fontSize:16, fontWeight:800, boxSizing:'border-box', width:'100%' };
const agentPlanHelp = { color:'#c4b5fd', fontSize:12, fontWeight:750, lineHeight:1.4 };
const agentPaymentActions = { display:'flex', gap:10, alignItems:'center', flexWrap:'wrap' };
const agentPaymentChip = { minHeight:34, display:'inline-flex', alignItems:'center', border:'1px solid', borderRadius:999, padding:'0 14px', fontSize:12, fontWeight:900 };
const agentSummaryCard = { background:'linear-gradient(180deg, rgba(30,27,75,.92), rgba(15,23,42,.92))', border:'1px solid #4c1d95', borderRadius:10, padding:14, boxShadow:'0 16px 35px rgba(2,6,23,.24)' };
const agentSummaryTitle = { margin:'0 0 12px', color:'#e9d5ff', fontSize:14, fontWeight:950 };
const agentSummaryTableWrap = { overflowX:'auto', border:'1px solid #312e81', borderRadius:8 };
const agentSummaryTable = { width:'100%', minWidth:760, borderCollapse:'collapse', background:'#11173a' };
const agentSummaryTh = { textAlign:'left', padding:'12px 14px', color:'#c4b5fd', background:'#0f172a', borderBottom:'1px solid #312e81', fontSize:12, fontWeight:950 };
const agentSummaryTd = { padding:'14px', color:'#e2e8f0', borderBottom:'1px solid #312e81', fontSize:13, verticalAlign:'middle' };
const agentPlanIcon = { width:24, height:24, border:'1px solid', borderRadius:5, display:'inline-grid', placeItems:'center', marginRight:10, fontSize:13, fontWeight:950, verticalAlign:'middle' };
const noticeStyle = { background:'#2e1065', border:'1px solid #7c3aed', color:'#e9d5ff', padding:10, borderRadius:8, marginBottom:14, fontSize:13 };
const outlineButton = { height:36, border:'1px solid #312e81', borderRadius:7, background:'#141c31', color:'#e9d5ff', padding:'0 14px', fontWeight:900, cursor:'pointer' };
const dangerOutline = { ...outlineButton, border:'1px solid #ef4444', color:'#fca5a5' };
const editActionsRow = { display:'flex', gap:12, flexWrap:'wrap', alignItems:'center', marginTop:18 };
const editOutlineButton = { ...outlineButton, height:44, minWidth:175, padding:'0 18px', display:'inline-flex', alignItems:'center', justifyContent:'center', fontSize:16 };
const editDangerButton = { ...editOutlineButton, border:'1px solid #ef4444', color:'#fca5a5' };
const modalBackdrop = { position:'fixed', inset:0, background:'rgba(2, 6, 23, .72)', display:'grid', placeItems:'center', padding:18, zIndex:50 };
const modalPanel = { width:'min(760px, 100%)', maxHeight:'92vh', overflow:'auto', background:'#141c31', border:'1px solid #4c1d95', borderRadius:10, padding:18, boxShadow:'0 24px 60px rgba(2, 6, 23, .45)' };
const previewBox = { border:'1px solid #312e81', borderRadius:8, background:'#0f172a', padding:16, minHeight:110 };
const documentFrame = { marginTop:14, border:'1px solid #312e81', borderRadius:8, background:'#0f172a', minHeight:360, overflow:'hidden', display:'grid', placeItems:'center' };
const imagePreview = { display:'block', maxWidth:'100%', maxHeight:'70vh', objectFit:'contain' };
const pdfPreview = { width:'100%', height:'70vh', border:0, background:'#0f172a' };
const supportInfoCard = { border:'1px solid #312e81', borderRadius:10, background:'#0f172a', padding:14, display:'grid', gap:6 };
const thStyle = { textAlign:'left', padding:'10px 12px', color:'#c4b5fd', fontSize:11, borderBottom:'1px solid #312e81', background:'#2e1065' };
const tdStyle = { padding:'10px 12px', color:'#e2e8f0', fontSize:12, borderBottom:'1px solid #312e81' };
const tablePager = { display:'flex', justifyContent:'flex-end', gap:10, padding:'14px 18px', background:'#0f172a', borderTop:'1px solid #312e81' };
const tablePagerButton = disabled => ({ minWidth:74, height:34, borderRadius:8, border:'1px solid #1e3a8a', background:'#0b1220', color:disabled ? '#475569' : '#93c5fd', fontSize:13, fontWeight:850, cursor:disabled ? 'not-allowed' : 'pointer' });
const directoryCard = { background:'#141c31', border:'1px solid #312e81', borderRadius:10, overflow:'hidden', boxShadow:'0 10px 24px rgba(15, 23, 42, .22)' };
const directoryHeader = { display:'grid', gridTemplateColumns:'1.7fr 1.4fr 1fr 1fr .9fr .9fr 1.15fr', gap:12, padding:'16px 20px', background:'#2e1065', borderBottom:'1px solid #312e81', color:'#c4b5fd', fontSize:13, fontWeight:900 };
const directoryRow = { display:'grid', gridTemplateColumns:'1.7fr 1.4fr 1fr 1fr .9fr .9fr 1.15fr', gap:12, alignItems:'center', padding:'16px 20px', borderBottom:'1px solid #312e81' };
const partnerIdentity = { border:'none', background:'transparent', display:'flex', gap:14, alignItems:'center', textAlign:'left', cursor:'pointer', padding:0 };
const avatarStyle = { width:48, height:48, borderRadius:8, display:'grid', placeItems:'center', fontWeight:900, fontSize:16 };
const directoryText = { color:'#e2e8f0', fontSize:13, fontWeight:700, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' };
const iconButton = { width:40, height:36, borderRadius:7, border:'1px solid #312e81', background:'#0f172a', color:'#93c5fd', cursor:'pointer', fontWeight:900 };
const linkButton = { border:'none', background:'transparent', color:'#e9d5ff', padding:0, fontSize:12, fontWeight:900, cursor:'pointer', textAlign:'left', textDecoration:'underline' };
const supportImagePreviewWrap = { marginTop:12, border:'1px solid #2563eb', borderRadius:10, background:'#020617', padding:12 };
const supportImageClose = { marginBottom:10, border:'1px solid #2563eb', background:'#141c31', color:'#bfdbfe', borderRadius:8, padding:'7px 12px', fontSize:12, fontWeight:900, cursor:'pointer' };
const supportImagePreview = { display:'block', maxWidth:'100%', maxHeight:'65vh', objectFit:'contain', borderRadius:8, background:'#fff' };
const miniGood = { padding:'7px 9px', borderRadius:7, border:'none', background:'#047857', color:'#fff', fontSize:11, fontWeight:900, cursor:'pointer' };
const miniDanger = { padding:'7px 9px', borderRadius:7, border:'none', background:'#991b1b', color:'#fff', fontSize:11, fontWeight:900, cursor:'pointer' };
const actionMenu = {
  position:'absolute',
  right:0,
  top:42,
  zIndex:20,
  width:210,
  background:'#0f172a',
  border:'1px solid #312e81',
  borderRadius:10,
  padding:8,
  boxShadow:'0 18px 40px rgba(0,0,0,.35)',
  display:'grid',
  gap:6,
};
const actionMenuButton = {
  width:'100%',
  border:'none',
  borderRadius:7,
  background:'#141c31',
  color:'#e9d5ff',
  padding:'8px 10px',
  textAlign:'left',
  fontSize:12,
  fontWeight:900,
  cursor:'pointer',
};
const actionMenuInfo = {
  display:'grid',
  gap:2,
  borderTop:'1px solid #312e81',
  padding:'7px 4px 2px',
  color:'#a78bfa',
  fontSize:11,
  wordBreak:'break-word',
};
const directoryFooter = { display:'flex', justifyContent:'space-between', alignItems:'center', gap:12, padding:'14px 20px', color:'#a78bfa', fontSize:12 };
const pagerButton = { minWidth:34, height:32, borderRadius:7, border:'1px solid #312e81', background:'#0f172a', color:'#a78bfa', cursor:'pointer' };
