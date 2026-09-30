import { useEffect, useRef, useState } from 'react';
import { useParams, useSearchParams, Link } from 'react-router-dom';
import api from '../../../api/axios';
import { useAuth } from '../../../context/AuthContext';

export default function SocWorkspacePage({ viewOverride }) {
  const { view: routeView } = useParams();
  const view = viewOverride || routeView;
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState({ items: [], total: 0, page: 1, pages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const requestIdRef = useRef(0);
  const [success, setSuccess] = useState('');
  const [showCreateAnalyst, setShowCreateAnalyst] = useState(false);
  const [showCreateShift, setShowCreateShift] = useState(false);
  const [editingShiftId, setEditingShiftId] = useState('');
  const [analystCompanies, setAnalystCompanies] = useState([]);
  const [availableAnalysts, setAvailableAnalysts] = useState([]);
  const [shiftCompanies, setShiftCompanies] = useState([]);
  const [shiftAnalysts, setShiftAnalysts] = useState([]);
  const [selectedAnalystId, setSelectedAnalystId] = useState(null);
  const [analystRange, setAnalystRange] = useState('today');
  const [modalTab, setModalTab] = useState('ops');
  const [analystDetail, setAnalystDetail] = useState(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  useEffect(() => {
    if (!selectedAnalystId) return;
    let active = true;

    const fetchDetail = (quiet = false) => {
      if (!quiet) setLoadingDetail(true);
      api.get(`/soc-manager/analysts/${selectedAnalystId}`, { params: { range: analystRange }, skipCache: true })
        .then(r => {
          if (active) setAnalystDetail(r.data);
        })
        .catch(e => {
          if (active && !quiet) setError(e.response?.data?.message || 'Unable to load analyst details');
        })
        .finally(() => {
          if (active && !quiet) setLoadingDetail(false);
        });
    };

    fetchDetail(false);

    const interval = setInterval(() => {
      fetchDetail(true);
    }, 5000);

    return () => {
      active = false;
      clearInterval(interval);
    };
  }, [selectedAnalystId, analystRange]);

  // New analyst form state
  const [newAnalyst, setNewAnalyst] = useState({
    analystId: '', role: 'l1_analyst', companyId: ''
  });
  const [newShift, setNewShift] = useState({
    name: '', companyId: '', timezone: 'UTC', startTime: '09:00', endTime: '17:00', weekdays: [1, 2, 3, 4, 5], analystIds: []
  });

  // Escalation Modal States
  const [showEscalateModal, setShowEscalateModal] = useState(false);
  const [selectedAlertForEscalate, setSelectedAlertForEscalate] = useState(null);
  const [escalateForm, setEscalateForm] = useState({
    reason: '',
    summary: '',
    observedIoc: '',
    affectedAsset: '',
    priority: 'high'
  });

  const page = Number(params.get('page') || 1);
  const search = params.get('search') || '';
  const escalationDirection = params.get('direction') || '';
  const isEscalationHistoryView = ['escalations', 'escalate-to-l3', 'l3-incoming-escalations'].includes(view);
  const effectiveEscalationDirection = view === 'l3-incoming-escalations'
    ? 'incoming'
    : view === 'escalate-to-l3' ? 'outgoing' : escalationDirection;

  const isSocManager = user?.role === 'soc_manager';
  const analystTab = {
    'l1-analysts': 'l1',
    'l2-analysts': 'l2',
    'l3-analysts': 'l3',
    'l4-analysts': 'l4',
  }[view];
  const isAnalystPage = view === 'analysts' || view === 'team' || Boolean(analystTab);
  const forcedSource = view === 'ids' ? 'ids_ips' : view === 'firewall' ? 'firewall' : '';
  const managerEndpoint =
    view === 'escalations' ? '/soc-manager/escalations' :
      view === 'audit' ? '/soc/audit' :
        view === 'companies' ? '/soc-manager/companies' :
          view === 'shifts' ? '/soc-manager/shifts' :
            isAnalystPage ? '/soc-manager/analysts' :
              view === 'queue' ? '/soc-manager/assignment-queue' :
                view === 'tickets' ? '/soc-manager/tickets' :
                  view === 'incidents' ? '/soc-manager/incidents' :
                    view === 'threat-intelligence' ? '/soc-manager/threat-intelligence' :
                      '/soc-manager/alerts';
  const analystEndpoint = isEscalationHistoryView
    ? '/soc-dashboard/escalations'
    : view === 'shifts' ? '/soc-dashboard/shifts'
      : view === 'incidents' ? '/soc-dashboard/incidents'
        : view === 'queue' ? '/soc-dashboard/queue'
          : view === 'tickets' ? '/soc-dashboard/tickets'
            : '/soc-dashboard/alerts';
  const endpoint = isSocManager ? managerEndpoint : analystEndpoint;

  const load = ({ quiet = false } = {}) => {
    if (!user?.role) return;
    const requestId = ++requestIdRef.current;
    if (!quiet) setLoading(true);
    setError('');
    if (!quiet) setState({ items: [], total: 0, page: 1, pages: 1 });
    api.get(endpoint, {
      skipCache: view === 'tickets',
      params: {
        ...Object.fromEntries(params),
        ...(effectiveEscalationDirection ? { direction: effectiveEscalationDirection } : {}),
        ...(forcedSource ? { source: forcedSource } : {}),
        ...(analystTab ? { tab: analystTab } : {}),
        page,
        limit: 20,
      },
    })
      .then(r => {
        if (requestId !== requestIdRef.current) return;
        const d = r.data;
        setState(Array.isArray(d) ? { items: d, total: d.length, page: 1, pages: 1 } : d);
      })
      .catch(e => {
        if (requestId === requestIdRef.current) {
          setError(e.response?.data?.message || 'Unable to load workspace data');
        }
      })
      .finally(() => {
        if (requestId === requestIdRef.current && !quiet) setLoading(false);
      });
  };

  useEffect(() => {
    load();
    return () => {
      requestIdRef.current += 1;
    };
  }, [endpoint, analystTab, forcedSource, params.toString(), user?.role]);

  useEffect(() => {
    if ((!isSocManager || !isAnalystPage) && view !== 'tickets') return undefined;
    const timer = setInterval(() => load({ quiet: true }), 5000);
    return () => clearInterval(timer);
  }, [isSocManager, isAnalystPage, view, endpoint, analystTab, forcedSource, params.toString(), user?.role]);

  const handleAction = async (alert, action) => {
    setError(''); setSuccess('');
    let payload = { action };
    if (action === 'note') {
      const note = prompt('Enter investigation note:');
      if (!note) return;
      payload.note = note;
    }
    if (action === 'escalate') {
      setSelectedAlertForEscalate(alert);
      setEscalateForm({
        reason: '',
        summary: '',
        observedIoc: alert.srcip || alert.fileHash || '',
        affectedAsset: alert.agentName || alert.hostname || '',
        priority: alert.severity || 'high'
      });
      setShowEscalateModal(true);
      return;
    }
    try {
      let assignmentResult = null;
      if (action === 'auto_assign') {
        const reason = prompt('Reason for manual assignment / reassignment:') || 'Manager manual assignment';
        if (alert.resourceType) {
          assignmentResult = await api.post(`/soc-manager/work-items/${alert.resourceType}/${alert.resourceId || alert._id}/assign`, { userId: prompt('Enter Analyst User ID (or leave blank for shift-based auto assignment):') || undefined, reason });
        } else {
          await api.post(`/soc/alerts/${alert._id}/assign`, { userId: prompt('Enter Analyst User ID (or leave blank for auto):') || undefined, reason });
        }
      } else {
        await api.post(alert.resourceType === 'incident'
          ? `/soc-dashboard/work-items/incident/${alert.resourceId || alert._id}/action`
          : `/soc-dashboard/alerts/${alert._id}/action`, payload);
      }
      setSuccess(assignmentResult?.data?.assignee
        ? `${assignmentResult.data.automatic ? 'Auto-assigned' : 'Assigned'} to ${assignmentResult.data.assignee.name} (${assignmentResult.data.assignee.role.replace(/_/g, ' ').toUpperCase()}).`
        : `Action '${action}' performed successfully.`);
      load();
    } catch (e) {
      setError(e.response?.data?.message || 'Action failed');
    }
  };

  const handleEscalateSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    try {
      const payload = {
        action: 'escalate',
        reason: escalateForm.reason,
        summary: escalateForm.summary,
        observedIoc: escalateForm.observedIoc,
        affectedAsset: escalateForm.affectedAsset,
        priority: escalateForm.priority
      };
      await api.post(selectedAlertForEscalate.resourceType === 'incident'
        ? `/soc-dashboard/work-items/incident/${selectedAlertForEscalate.resourceId || selectedAlertForEscalate._id}/action`
        : `/soc-dashboard/alerts/${selectedAlertForEscalate._id}/action`, payload);
      setSuccess('Alert escalated successfully.');
      setShowEscalateModal(false);
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Escalation failed');
    }
  };

  const handleEscalationDecision = async (item, status) => {
    setError(''); setSuccess('');
    const note = prompt(`${status.toUpperCase()} reason / manager note:`) || '';
    if (!note) return;
    try {
      await api.patch(`/soc-dashboard/escalations/${item._id}`, { status, note });
      setSuccess(`Escalation ${status}.`);
      load();
    } catch (e) {
      setError(e.response?.data?.message || 'Escalation update failed');
    }
  };

  const handleCreateAnalystSubmit = async (e) => {
    e.preventDefault();
    setError(''); setSuccess('');
    try {
      const { data } = await api.put(`/soc/staff/${newAnalyst.analystId}/assignments`, {
        companyIds: [newAnalyst.companyId],
        departmentIds: [],
      });
      if (!data.assignmentConfirmed || !data.emailSent) throw new Error('Assignment or email confirmation missing');
      setSuccess(`Analyst assigned successfully. Email sent to ${data.email}.`);
      setShowCreateAnalyst(false);
      setNewAnalyst({ analystId: '', role: 'l1_analyst', companyId: '' });
      load();
    } catch (err) {
      const result = err.response?.data;
      setError(result?.message || err.message || 'Failed to assign analyst');
      if (result?.assignmentConfirmed) {
        setShowCreateAnalyst(false);
        load();
      }
    }
  };

  const openCreateAnalyst = async () => {
    setError('');
    try {
      const [companyResponse, analystResponse] = await Promise.all([
        api.get('/soc-manager/companies', { params: { limit: 100 } }),
        api.get('/soc-manager/analysts', { params: { limit: 100 } }),
      ]);
      const companies = companyResponse.data?.items || companyResponse.data || [];
      const analysts = analystResponse.data?.items || analystResponse.data || [];
      setAnalystCompanies(companies);
      setAvailableAnalysts(analysts.filter(analyst => analyst.socManagerPool && !analyst.socManagerId));
      setNewAnalyst(current => ({ ...current, analystId: '', companyId: current.companyId || companies[0]?._id || '' }));
      setShowCreateAnalyst(true);
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to load your assigned companies');
    }
  };

  const openAnalystDashboard = (analystId) => {
    setAnalystRange('today');
    setModalTab('ops');
    setSelectedAnalystId(analystId);
  };

  const openCreateShift = async () => {
    setError('');
    try {
      const [companiesResponse, analystsResponse] = await Promise.all([
        api.get('/soc-manager/companies', { params: { limit: 100 } }),
        api.get('/soc-manager/analysts', { params: { limit: 100 } }),
      ]);
      const companies = companiesResponse.data?.items || companiesResponse.data || [];
      const analysts = analystsResponse.data?.items || analystsResponse.data || [];
      setShiftCompanies(companies);
      setShiftAnalysts(analysts);
      setNewShift(current => ({ ...current, companyId: current.companyId || companies[0]?._id || '' }));
      setEditingShiftId('');
      setShowCreateShift(true);
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to load companies and analysts for this shift');
    }
  };

  const openEditShift = async (shift) => {
    setError('');
    try {
      const [companiesResponse, analystsResponse] = await Promise.all([
        api.get('/soc-manager/companies', { params: { limit: 100 } }),
        api.get('/soc-manager/analysts', { params: { limit: 100 } }),
      ]);
      setShiftCompanies(companiesResponse.data?.items || companiesResponse.data || []);
      setShiftAnalysts(analystsResponse.data?.items || analystsResponse.data || []);
      setNewShift({
        name: shift.name || '',
        companyId: String(shift.companyId?._id || shift.companyId || ''),
        timezone: shift.timezone || 'UTC',
        startTime: shift.startTime || '09:00',
        endTime: shift.endTime || '17:00',
        weekdays: shift.weekdays || [],
        analystIds: (shift.analystIds || []).map(analyst => String(analyst?._id || analyst)),
      });
      setEditingShiftId(String(shift._id));
      setShowCreateShift(true);
    } catch (err) {
      setError(err.response?.data?.message || 'Unable to open shift controls');
    }
  };

  const handleCreateShiftSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    try {
      if (editingShiftId) {
        await api.patch(`/soc-manager/shifts/${editingShiftId}`, { ...newShift, analystIds: newShift.analystIds });
      } else {
        await api.post('/soc-manager/shifts', { ...newShift, analystIds: newShift.analystIds });
      }
      setSuccess(`Shift "${newShift.name}" ${editingShiftId ? 'updated' : 'created'} successfully.`);
      setShowCreateShift(false);
      setEditingShiftId('');
      setNewShift({ name: '', companyId: '', timezone: 'UTC', startTime: '09:00', endTime: '17:00', weekdays: [1, 2, 3, 4, 5], analystIds: [] });
      load();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create shift');
    }
  };

  const title = {
    alerts: 'Alerts Management',
    ids: '📡 Company IDS / IPS',
    firewall: '🔥 Company Firewall',
    queue: user?.role === 'soc_manager' ? 'Unassigned Assignment Queue' : `${ROLE_QUEUE_LABEL[user?.role] || 'Analyst'} Assignment Queue`,
    escalations: escalationDirection === 'incoming' ? 'Escalated Alerts from L1' : escalationDirection === 'outgoing' ? 'Escalations Sent to L3' : 'Incident Escalations',
    'escalate-to-l3': 'Escalations Sent to L3',
    'l3-incoming-escalations': 'Escalations Sent to L3',
    companies: 'Assigned Companies',
    shifts: isSocManager ? 'Shift Control Panel' : 'My Shift Queue',
    audit: 'Audit Trail',
    analysts: 'Analyst Management',
    'l1-analysts': 'L1 Analysts',
    'l2-analysts': 'L2 Analysts',
    'l3-analysts': 'L3 Analysts',
    'l4-analysts': 'L4 Threat Intelligence Analysts',
    tickets: 'SOAR Tickets Queue',
    incidents: 'EDR Correlation Incidents',
    'threat-intelligence': '⌾ Threat Intelligence Incidents'
  }[view] || 'SOC Workspace';

  const description = {
    alerts: 'Security detections only. Routine telemetry remains in Log Monitor.',
    ids: 'IDS and IPS security detections across companies assigned to this SOC Manager.',
    firewall: 'Firewall security events across companies assigned to this SOC Manager.',
    queue: 'Unassigned actionable alerts and correlation incidents awaiting ownership.',
    escalations: escalationDirection === 'incoming'
      ? 'Alerts escalated by L1 analysts into the L2 investigation tier.'
      : escalationDirection === 'outgoing'
        ? 'Escalations you have already submitted to L3 analysts.'
        : 'Escalations in your authorized SOC workflow.',
    'escalate-to-l3': 'Only alerts you have actually escalated from L2 to L3 are shown here.',
    'l3-incoming-escalations': 'Alerts and incidents actually escalated by L2 analysts to your L3 investigation tier.',
    tickets: 'Only tickets created by SOAR are shown here. Incidents and manually created work remain in their own workspaces.',
    incidents: 'EDR correlated security cases built from endpoint detection evidence.',
    'threat-intelligence': 'IOC and threat-feed correlated incidents across authorized companies.',
    shifts: isSocManager
      ? 'Create shifts and assign or update analysts across your authorized companies.'
      : 'Your active shift assignments and scheduled coverage windows.'
  }[view];

  return (
    <div className="soc-workspace-page">
      <div className="soc-workspace-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 22 }}>{title}</h1>
          {description && <div style={{ marginTop: 5, color: '#94a3b8', fontSize: 12 }}>{description}</div>}
        </div>
        {(view === 'analysts' || view === 'team') && user.role === 'soc_manager' && (
          <button onClick={openCreateAnalyst} style={btnPrimary}>+ Create Analyst Account</button>
        )}
        {view === 'shifts' && isSocManager && (
          <button onClick={openCreateShift} style={btnPrimary}>+ Create Shift</button>
        )}
      </div>

      {/* Toolbar / Search / Filter */}
      <div className="soc-workspace-tools" style={tools}>
        <input
          defaultValue={search}
          placeholder="Search items…"
          onKeyDown={e => {
            if (e.key === 'Enter') {
              params.set('search', e.currentTarget.value);
              params.set('page', '1');
              setParams(params);
            }
          }}
          style={input}
        />
        {['alerts', 'ids', 'firewall', 'queue', 'tickets', 'incidents', 'threat-intelligence'].includes(view) && (
          <>
            <select
              value={params.get('severity') || ''}
              onChange={e => { e.target.value ? params.set('severity', e.target.value) : params.delete('severity'); setParams(params); }}
              style={input}
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>

            <select
              value={params.get('status') || ''}
              onChange={e => { e.target.value ? params.set('status', e.target.value) : params.delete('status'); setParams(params); }}
              style={input}
            >
              <option value="">All Status</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
            </select>
          </>
        )}
        {isEscalationHistoryView && (
          <select
            value={params.get('status') || ''}
            onChange={e => { e.target.value ? params.set('status', e.target.value) : params.delete('status'); setParams(params); }}
            style={input}
          >
            <option value="">All Status</option>
            <option value="pending">Pending</option>
            <option value="accepted">Accepted</option>
            <option value="rejected">Rejected</option>
            <option value="resolved">Resolved</option>
          </select>
        )}
      </div>

      {error && <div style={errorBox}>{error}</div>}
      {success && <div style={successBox}>{success}</div>}

      {/* Analyst Dashboard Modal */}
      {selectedAnalystId && (
        <div style={modalOverlay} onClick={() => { setSelectedAnalystId(null); setAnalystDetail(null); }}>
          <div
            style={{
              ...modalBox,
              position: 'fixed',
              inset: 0,
              width: '100vw',
              height: '100vh',
              maxHeight: '100vh',
              maxWidth: '100vw',
              borderRadius: 0,
              border: 0,
              overflowY: 'auto',
              background: '#070e1d',
              boxShadow: 'none',
              padding: '24px 32px',
              boxSizing: 'border-box'
            }}
            onClick={e => e.stopPropagation()}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20, borderBottom: '1px solid #1e3a5f', paddingBottom: 12 }}>
              <h2 style={{ margin: 0, color: '#67e8f9', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>👤</span> Analyst Performance Dashboard
              </h2>
              <button
                onClick={() => { setSelectedAnalystId(null); setAnalystDetail(null); }}
                style={{
                  background: 'none',
                  border: 0,
                  color: '#94a3b8',
                  fontSize: 24,
                  cursor: 'pointer',
                  padding: 4,
                  lineHeight: 1
                }}
              >
                &times;
              </button>
            </div>

            {loadingDetail ? (
              <div style={{ padding: 50, textAlign: 'center', color: '#cbd5e1' }}>
                <div style={{ border: '4px solid #1e3a5f', borderTop: '4px solid #67e8f9', borderRadius: '50%', width: 36, height: 36, animation: 'spin 1s linear infinite', margin: '0 auto 12px' }} />
                Loading analyst performance data…
              </div>
            ) : analystDetail ? (
              <div>
                {/* Profile Header card */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 16, background: 'linear-gradient(135deg, #0c1a2e, #101d35)', border: '1px solid #1e3a5f', borderRadius: 12, padding: 16, marginBottom: 20, flexWrap: 'wrap' }}>
                  <div style={{
                    width: 54,
                    height: 54,
                    borderRadius: '50%',
                    background: 'linear-gradient(135deg, #2563eb, #6d28d9)',
                    color: '#fff',
                    fontSize: 22,
                    fontWeight: 900,
                    display: 'grid',
                    placeItems: 'center',
                    border: '2px solid #1e3a5f',
                  }}>
                    {String(analystDetail.user?.name || 'A')[0].toUpperCase()}
                  </div>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <h3 style={{ margin: 0, fontSize: 16, color: '#f8fafc' }}>{analystDetail.user?.name}</h3>
                    <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 3, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                      <span>{analystDetail.user?.email}</span>
                      <span>·</span>
                      <span style={{ color: '#67e8f9', fontWeight: 700 }}>{String(analystDetail.user?.role || 'Analyst').replace(/_/g, ' ').toUpperCase()}</span>
                      <span>·</span>
                      <span style={{ color: analystDetail.user?.accountStatus === 'suspended' ? '#f87171' : '#34d399', fontWeight: 700 }}>{analystDetail.user?.accountStatus || 'active'}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <label style={{ fontSize: 12, color: '#94a3b8', margin: 0 }}>Range:</label>
                      <select
                        value={analystRange}
                        onChange={(e) => setAnalystRange(e.target.value)}
                        style={{ padding: '6px 10px', background: '#07111f', border: '1px solid #294765', borderRadius: 7, color: '#e2e8f0', fontSize: 12 }}
                      >
                        <option value="today">Today</option>
                        <option value="7d">Last 7 Days</option>
                        <option value="30d">Last 30 Days</option>
                      </select>
                    </div>
                    <span style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 6,
                      fontSize: 11,
                      fontWeight: 800,
                      color: '#10b981',
                      padding: '4px 8px',
                      background: 'rgba(16, 185, 129, 0.1)',
                      borderRadius: 6,
                      border: '1px solid rgba(16, 185, 129, 0.2)',
                      animation: 'pulse 2s infinite'
                    }}>
                      <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#10b981' }} />
                      LIVE FEED
                    </span>
                    <style dangerouslySetInnerHTML={{
                      __html: `
                      .analyst-metrics-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
                        gap: 16px;
                      }
                      @keyframes pulse {
                        0% { opacity: 0.7; }
                        50% { opacity: 1; }
                        100% { opacity: 0.7; }
                      }
                      @media (max-width: 768px) {
                        .analyst-metrics-grid {
                          grid-template-columns: repeat(2, 1fr) !important;
                        }
                      }
                      @media (max-width: 480px) {
                        .analyst-metrics-grid {
                          grid-template-columns: 1fr !important;
                        }
                      }
                    ` }} />
                  </div>
                </div>

                <div style={{ color: '#64748b', fontSize: 11, margin: '-8px 0 12px' }}>
                  Showing {analystDetail.selectedRange === 'today' ? 'today' : analystDetail.selectedRange === '7d' ? 'last 7 days' : 'last 30 days'} data
                  {analystDetail.dashboardData?.refreshedAt ? ` · refreshed ${new Date(analystDetail.dashboardData.refreshedAt).toLocaleTimeString()}` : ''}
                </div>

                <div className="analyst-metrics-grid" key={`${selectedAnalystId}-${analystRange}-${analystDetail.dashboardData?.refreshedAt || ''}`}>
                  {(() => {
                    const m = analystDetail.dashboardData?.metrics || {};
                    const roleKey = analystDetail.user?.role || 'l1_analyst';
                    const rangeLabel = analystRange === 'today' ? 'Today' : analystRange === '7d' ? 'Last 7 Days' : 'Last 30 Days';

                    let cardList = [];
                    if (roleKey === 'l4_analyst') {
                      cardList = [
                        [`Assigned Work ${rangeLabel}`, m.assignedWorkInRange ?? 0, '#a78bfa'],
                        [`Pending Work ${rangeLabel}`, m.pendingWorkInRange ?? 0, '#facc15'],
                        [`Completed Work ${rangeLabel}`, m.completedWorkInRange ?? 0, '#34d399'],
                        [`Completion Rate ${rangeLabel}`, `${m.completionRateInRange ?? 0}%`, '#22d3ee'],
                        [`TI Incidents ${rangeLabel}`, m.newIncidentsInRange ?? 0, '#c084fc'],
                        [`Assigned Tickets ${rangeLabel}`, m.newTicketsInRange ?? 0, '#60a5fa'],
                        [`Open Work ${rangeLabel}`, m.openWorkInRange ?? 0, '#fb923c'],
                        [`Investigating ${rangeLabel}`, m.investigatingWorkInRange ?? 0, '#38bdf8'],
                        [`Critical Pending ${rangeLabel}`, m.criticalPendingInRange ?? 0, '#fb7185'],
                        ['On Shift Now', m.onShiftNow ?? 0, '#2dd4bf']
                      ];
                    } else {
                      cardList = [
                        [`Incidents Received ${rangeLabel}`, m.newIncidentsInRange ?? 0, '#818cf8'],
                        [`Incidents Closed ${rangeLabel}`, m.closedIncidentsInRange ?? 0, '#22c55e'],
                        ['Incidents Pending', m.pendingIncidents ?? 0, '#c084fc'],
                        [`My Tickets Received ${rangeLabel}`, m.newTicketsInRange ?? 0, '#38bdf8'],
                        [`My Tickets Closed ${rangeLabel}`, m.closedTicketsInRange ?? 0, '#34d399'],
                        ['My Tickets Pending', m.pendingTickets ?? 0, '#facc15'],
                        [`Logs Received ${rangeLabel}`, m.logsInRange ?? 0, '#94a3b8'],
                        ['Completion Rate', `${m.completionRate ?? 0}%`, '#22d3ee'],
                        ['On Shift Now', m.onShiftNow ?? 0, '#2dd4bf']
                      ];
                      if (['l2_analyst', 'l3_analyst'].includes(roleKey)) {
                        cardList.push(
                          ['Escalated Assigned to me', m.myAssignedEscalationsIncoming ?? 0, '#38bdf8'],
                          ['Escalated Pending', m.pendingEscalationsIncoming ?? 0, '#facc15'],
                          ['Escalated Closed', m.closedEscalationsIncoming ?? 0, '#34d399']
                        );
                      }
                    }

                    return cardList.map(([label, value, color]) => (
                      <div key={label} style={dashboardCard}>
                        <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 600 }}>{label}</small>
                        <div style={{ fontSize: 24, fontWeight: 900, color, marginTop: 8 }}>{value ?? 0}</div>
                      </div>
                    ));
                  })()}
                </div>

                {/* Live authentication, session and account-lock audit */}
                <div style={{ ...dashboardCard, marginTop: 24, padding: 20 }}>
                  <h3 style={{ margin: '0 0 6px', color: '#67e8f9', fontSize: 16 }}>🔐 Live Login, Session & Account Lock Audit</h3>
                  <div style={{ color: '#64748b', fontSize: 11, marginBottom: 16 }}>
                    Calculated from LoginActivity, SOC audit events and assigned shift windows—not placeholder values.
                  </div>
                  <div className="analyst-metrics-grid">
                    {(() => {
                      const auth = analystDetail.authAudit?.metrics || {};
                      return [
                        ['Successful Logins', auth.loginCount || 0, '#34d399'],
                        ['Logouts', auth.logoutCount || 0, '#f87171'],
                        ['30m Auto Logouts', auth.autoLogoutCount || 0, '#ef4444'],
                        ['Failed Authentication', auth.failedLoginCount || 0, '#fb923c'],
                        ['Account Locks', auth.accountLockCount || 0, '#fb7185'],
                        ['10m Screen Locks', auth.screenLockCount || 0, '#e879f9'],
                        ['Total Session Time', formatAuditMinutes(auth.totalSessionMinutes), '#60a5fa'],
                        ['Working-Hours Session', formatAuditMinutes(auth.workingSessionMinutes), '#2dd4bf'],
                        ['Outside-Shift Time', formatAuditMinutes(auth.outsideShiftMinutes), '#facc15'],
                        ['Screen Locked Time', formatAuditMinutes(auth.screenLockedMinutes), '#d946ef'],
                        ['Locked During Working Hours', formatAuditMinutes(auth.lockedWorkingMinutes), '#f43f5e'],
                        ['After-Hours Logins', auth.afterHoursLoginCount || 0, '#c084fc'],
                        ['Active Sessions', auth.activeSessionCount || 0, '#22c55e'],
                      ].map(([label, value, color]) => (
                        <div key={label} style={{ ...dashboardCard, padding: 14 }}>
                          <small style={{ color: '#94a3b8', fontSize: 11, fontWeight: 700 }}>{label}</small>
                          <div style={{ color, fontSize: 21, fontWeight: 900, marginTop: 7 }}>{value}</div>
                        </div>
                      ));
                    })()}
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1.35fr) minmax(320px,.65fr)', gap: 16, marginTop: 18 }} className="analyst-audit-split">
                    <AuditTable
                      title="Login / Logout Sessions"
                      empty="No login session was recorded in this range."
                      columns={['Login', 'Logout', 'Logout Type', 'Duration', 'In Shift', 'Outside Shift', 'Source IP']}
                      rows={(analystDetail.authAudit?.sessions || []).map(session => [
                        formatAuditDate(session.loginAt),
                        session.logoutAt ? formatAuditDate(session.logoutAt) : session.active ? 'Active now' : 'No logout recorded',
                        session.logoutAction === 'auto_logout' ? '30m inactivity' : session.logoutAction === 'logout' ? 'Manual' : '—',
                        formatAuditMinutes(session.durationMinutes),
                        formatAuditMinutes(session.workingMinutes),
                        formatAuditMinutes(session.outsideShiftMinutes),
                        session.ipAddress || '—',
                      ])}
                    />
                    <AuditTable
                      title="Account Lock Timeline"
                      empty="No account lock or manager suspension occurred in this range."
                      columns={['Type', 'Locked At', 'Unlocked At', 'Total', 'During Shift', 'Reason']}
                      rows={(analystDetail.authAudit?.locks || []).map(lock => [
                        lock.type === 'screen_lock' ? 'Screen lock' : lock.type === 'manager_suspension' ? 'Account suspended' : 'Account lock',
                        formatAuditDate(lock.start), formatAuditDate(lock.end),
                        formatAuditMinutes(lock.durationMinutes), formatAuditMinutes(lock.workingMinutes), lock.reason || 'Account lock',
                      ])}
                    />
                  </div>

                  <div style={{ marginTop: 18 }}>
                    <AuditTable
                      title="Complete Analyst Audit Timeline"
                      maxVisibleRows={10}
                      empty="No authentication or SOC audit activity was recorded in this range."
                      columns={['Time', 'Source', 'Action', 'Result / Reason', 'IP / Actor']}
                      rows={(analystDetail.authAudit?.activityTimeline || []).map(event => [
                        formatAuditDate(event.at),
                        event.source === 'authentication' ? 'Authentication' : 'SOC Audit',
                        String(event.action || 'activity').replace(/_/g, ' '),
                        event.reason || (event.success === false ? 'Failed' : 'Success'),
                        event.ipAddress || event.actor?.name || event.actor?.email || 'System',
                      ])}
                    />
                  </div>
                </div>

                {/* Shift Adherence & Session Attendance Adherence Report */}
                <div style={{ ...dashboardCard, marginTop: 24, padding: 20 }}>
                  <h3 style={{ margin: '0 0 16px', color: '#67e8f9', fontSize: 16, display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>📅</span> Shift Adherence & Session Attendance (Last 7 Days)
                  </h3>

                  {!analystDetail.attendanceReport || !analystDetail.attendanceReport.length ? (
                    <div style={{ color: '#64748b', fontSize: 13, fontStyle: 'italic', textAlign: 'center', padding: '24px 0', border: '1px dashed #1e3a5f', borderRadius: 8 }}>
                      No shifts or attendance logs recorded in the last 7 days for this analyst.
                    </div>
                  ) : (
                    <div style={{ overflowX: 'auto' }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, textAlign: 'left' }}>
                        <thead>
                          <tr style={{ borderBottom: '2px solid #1e3a5f', color: '#7dd3fc', fontWeight: 600 }}>
                            <th style={{ padding: '12px 8px' }}>Date / Day</th>
                            <th style={{ padding: '12px 8px' }}>Shift Details</th>
                            <th style={{ padding: '12px 8px' }}>Shift Timing</th>
                            <th style={{ padding: '12px 8px' }}>Login Time</th>
                            <th style={{ padding: '12px 8px' }}>Logout Time</th>
                            <th style={{ padding: '12px 8px' }}>Lateness</th>
                            <th style={{ padding: '12px 8px' }}>Working Session</th>
                            <th style={{ padding: '12px 8px' }}>Locked in Shift</th>
                            <th style={{ padding: '12px 8px' }}>Failed Auth</th>
                            <th style={{ padding: '12px 8px', textAlign: 'center' }}>Logouts (In Shift)</th>
                            <th style={{ padding: '12px 8px' }}>Status</th>
                          </tr>
                        </thead>
                        <tbody>
                          {analystDetail.attendanceReport.map((row, idx) => (
                            <tr key={idx} style={{ borderBottom: '1px solid #1e3a5f', background: idx % 2 === 0 ? 'rgba(30, 58, 95, 0.15)' : 'transparent' }}>
                              <td style={{ padding: '12px 8px', fontWeight: 600 }}>
                                <div style={{ color: '#f8fafc' }}>{row.date}</div>
                                <div style={{ fontSize: 11, color: '#94a3b8', marginTop: 2 }}>{row.dayName}</div>
                              </td>
                              <td style={{ padding: '12px 8px', color: '#cbd5e1' }}>{row.shiftName}</td>
                              <td style={{ padding: '12px 8px', color: '#94a3b8', fontSize: 12 }}>{row.shiftTime}</td>
                              <td style={{ padding: '12px 8px', color: '#34d399', fontWeight: 700 }}>{row.loginTime}</td>
                              <td style={{ padding: '12px 8px', color: '#f87171', fontWeight: 700 }}>{row.logoutTime}</td>
                              <td style={{ padding: '12px 8px' }}>
                                <span style={{
                                  padding: '4px 8px',
                                  borderRadius: 6,
                                  fontSize: 11,
                                  fontWeight: 700,
                                  background: row.lateTime === 'On Time' ? 'rgba(52, 211, 153, 0.12)' : row.lateTime === '—' ? 'transparent' : 'rgba(245, 158, 11, 0.15)',
                                  color: row.lateTime === 'On Time' ? '#34d399' : row.lateTime === '—' ? '#64748b' : '#fbbf24',
                                  border: row.lateTime === '—' ? 0 : `1px solid ${row.lateTime === 'On Time' ? 'rgba(52, 211, 153, 0.28)' : 'rgba(245, 158, 11, 0.3)'}`
                                }}>
                                  {row.lateTime}
                                </span>
                              </td>
                              <td style={{ padding: '12px 8px', color: '#2dd4bf', fontWeight: 700 }}>{formatAuditMinutes(row.sessionMinutes)}</td>
                              <td style={{ padding: '12px 8px', color: row.lockMinutes ? '#fb7185' : '#64748b', fontWeight: 700 }}>{formatAuditMinutes(row.lockMinutes)}</td>
                              <td style={{ padding: '12px 8px', color: row.failedLoginCount ? '#fb923c' : '#64748b', fontWeight: 700 }}>{row.failedLoginCount || 0}</td>
                              <td style={{ padding: '12px 8px', textAlign: 'center' }}>
                                <span style={{
                                  padding: '2px 8px',
                                  borderRadius: 999,
                                  fontSize: 12,
                                  fontWeight: 700,
                                  background: row.logoutCount > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(148, 163, 184, 0.1)',
                                  color: row.logoutCount > 0 ? '#f87171' : '#94a3b8'
                                }}>
                                  {row.logoutCount}
                                </span>
                              </td>
                              <td style={{ padding: '12px 8px' }}>
                                <span style={{
                                  padding: '4px 8px',
                                  borderRadius: 6,
                                  fontSize: 11,
                                  fontWeight: 700,
                                  background: row.status === 'Present' ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.12)',
                                  color: row.status === 'Present' ? '#10b981' : '#f87171',
                                  border: `1px solid ${row.status === 'Present' ? 'rgba(16, 185, 129, 0.28)' : 'rgba(239, 68, 68, 0.28)'}`
                                }}>
                                  {row.status}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              </div>)
              : (
                <div style={{ padding: 30, textAlign: 'center', color: '#f87171' }}>
                  Failed to load analyst performance dashboard.
                </div>
              )}
          </div>
        </div>
      )}

      {/* Create Analyst Modal */}
      {showCreateAnalyst && (
        <div style={modalOverlay}>
          <div style={modalBox}>
            <h2 style={{ marginTop: 0 }}>Assign Available Analyst</h2>
            <form onSubmit={handleCreateAnalystSubmit}>
              <label style={label}>Available Analyst Role</label>
              <select value={newAnalyst.role} onChange={e => setNewAnalyst({ ...newAnalyst, role: e.target.value, analystId: '' })} style={{ ...input, width: '100%', marginBottom: 12 }}>
                <option value="l1_analyst">L1 Analyst</option>
                <option value="l2_analyst">L2 Analyst</option>
                <option value="l3_analyst">L3 Analyst</option>
                <option value="l4_analyst">L4 Threat Intelligence Analyst</option>
              </select>

              <label style={label}>Available Analyst</label>
              <select required value={newAnalyst.analystId} onChange={e => setNewAnalyst({ ...newAnalyst, analystId: e.target.value })} style={{ ...input, width: '100%', marginBottom: 12 }}>
                {availableAnalysts.some(analyst => analyst.role === newAnalyst.role) ? (
                  <>
                    <option value="">Select analyst name</option>
                    {availableAnalysts
                      .filter(analyst => analyst.role === newAnalyst.role)
                      .sort((a, b) => (a.name || '').localeCompare(b.name || ''))
                      .map(analyst => (
                        <option key={analyst._id} value={analyst._id}>{analyst.name}</option>
                      ))}
                  </>
                ) : (
                  <option value="">No available analyst in this role</option>
                )}
              </select>

              <label style={label}>Company</label>
              <select required value={newAnalyst.companyId} onChange={e => setNewAnalyst({ ...newAnalyst, companyId: e.target.value })} style={{ ...input, width: '100%', marginBottom: 16 }}>
                <option value="">Select company</option>
                {analystCompanies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}
              </select>

              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setShowCreateAnalyst(false)} style={{ ...btn, background: '#475569' }}>Cancel</button>
                <button type="submit" disabled={!newAnalyst.analystId || !newAnalyst.companyId} style={btnPrimary}>Assign Analyst</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Create Shift Modal */}
      {showCreateShift && (
        <div style={modalOverlay}>
          <div style={modalBox}>
            <h2 style={{ marginTop: 0 }}>{editingShiftId ? 'Assign Analysts & Edit Shift' : 'Create Shift'}</h2>
            <form onSubmit={handleCreateShiftSubmit}>
              <label style={label}>Shift Name</label>
              <input required value={newShift.name} onChange={e => setNewShift({ ...newShift, name: e.target.value })} style={{ ...input, width: '100%', marginBottom: 12 }} />

              <label style={label}>Company</label>
              <select required value={newShift.companyId} onChange={e => setNewShift({ ...newShift, companyId: e.target.value, analystIds: [] })} style={{ ...input, width: '100%', marginBottom: 12 }}>
                <option value="">Select company</option>
                {shiftCompanies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}
              </select>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <label style={label}>Start Time</label>
                  <input required type="time" value={newShift.startTime} onChange={e => setNewShift({ ...newShift, startTime: e.target.value })} style={{ ...input, width: '100%', marginBottom: 12 }} />
                </div>
                <div>
                  <label style={label}>End Time</label>
                  <input required type="time" value={newShift.endTime} onChange={e => setNewShift({ ...newShift, endTime: e.target.value })} style={{ ...input, width: '100%', marginBottom: 12 }} />
                </div>
              </div>

              <label style={label}>Timezone</label>
              <input required value={newShift.timezone} onChange={e => setNewShift({ ...newShift, timezone: e.target.value })} placeholder="UTC" style={{ ...input, width: '100%', marginBottom: 12 }} />

              <label style={label}>Assigned Analysts in Your Team</label>
              <div style={{ ...input, width: '100%', maxHeight: 144, overflowY: 'auto', marginBottom: 12 }}>
                {shiftAnalysts
                  .filter(analyst => !newShift.companyId || analyst.companies?.some(company => String(company?._id || company) === newShift.companyId))
                  .map(analyst => {
                    const selected = newShift.analystIds.includes(String(analyst._id));
                    return (
                      <label key={analyst._id} style={{ display: 'flex', alignItems: 'center', gap: 7, padding: '5px 0', color: '#cbd5e1', fontSize: 12 }}>
                        <input
                          type="checkbox"
                          checked={selected}
                          onChange={e => setNewShift({
                            ...newShift,
                            analystIds: e.target.checked
                              ? [...newShift.analystIds, String(analyst._id)]
                              : newShift.analystIds.filter(id => id !== String(analyst._id)),
                          })}
                        />
                        {analyst.name || analyst.email} ({analyst.role})
                      </label>
                    );
                  })}
                {!shiftAnalysts.some(analyst => !newShift.companyId || analyst.companies?.some(company => String(company?._id || company) === newShift.companyId)) && (
                  <span style={{ color: '#94a3b8', fontSize: 12 }}>No active analysts are assigned to this company.</span>
                )}
              </div>

              <fieldset style={{ border: 0, padding: 0, margin: '0 0 16px' }}>
                <legend style={label}>Active Days</legend>
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                  {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].map((day, index) => {
                    const dayValue = index === 6 ? 0 : index + 1;
                    return (
                      <label key={day} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 12, color: '#cbd5e1' }}>
                        <input
                          type="checkbox"
                          checked={newShift.weekdays.includes(dayValue)}
                          onChange={e => setNewShift({
                            ...newShift,
                            weekdays: e.target.checked
                              ? [...newShift.weekdays, dayValue].sort((a, b) => a - b)
                              : newShift.weekdays.filter(value => value !== dayValue),
                          })}
                        />
                        {day}
                      </label>
                    );
                  })}
                </div>
              </fieldset>

              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => { setShowCreateShift(false); setEditingShiftId(''); }} style={{ ...btn, background: '#475569' }}>Cancel</button>
                <button type="submit" style={btnPrimary}>{editingShiftId ? 'Save Assignments' : 'Create Shift'}</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Escalate Alert Modal */}
      {showEscalateModal && selectedAlertForEscalate && (
        <div style={modalOverlay}>
          <div style={modalBox}>
            <h2 style={{ marginTop: 0, color: '#fca5a5', fontSize: 18 }}>Escalate Alert to Next Level</h2>
            <p style={{ fontSize: 12, color: '#94a3b8', margin: '-10px 0 16px 0' }}>
              Escalating: <b>{selectedAlertForEscalate.signatureName || selectedAlertForEscalate.ruleId || 'Alert'}</b>
            </p>
            <form onSubmit={handleEscalateSubmit}>
              <label style={label}>Escalation Target Tier</label>
              <div style={{ ...input, width: '100%', boxSizing: 'border-box', border: '1px solid #1e3a5f', padding: '9px 12px', background: '#0e243a', color: '#60a5fa', fontWeight: 'bold', marginBottom: 12 }}>
                {user.role === 'l1_analyst' ? 'Level 2 Analyst (L2)' : user.role === 'l2_analyst' ? 'Level 3 Analyst (L3)' : 'SOC Manager'}
              </div>

              <label style={label}>Escalation Reason <span style={{ color: '#ef4444' }}>*</span></label>
              <textarea
                required
                rows={3}
                placeholder="Provide details on why this alert requires higher tier investigation..."
                value={escalateForm.reason}
                onChange={e => setEscalateForm({ ...escalateForm, reason: e.target.value })}
                style={{ ...input, width: '100%', boxSizing: 'border-box', marginBottom: 12, resize: 'vertical', fontFamily: 'inherit' }}
              />

              <label style={label}>Investigation Summary</label>
              <textarea
                rows={3}
                placeholder="Summary of findings, pattern logs, or context..."
                value={escalateForm.summary}
                onChange={e => setEscalateForm({ ...escalateForm, summary: e.target.value })}
                style={{ ...input, width: '100%', boxSizing: 'border-box', marginBottom: 12, resize: 'vertical', fontFamily: 'inherit' }}
              />

              <label style={label}>Observed IOCs (e.g. IPs, Hashes)</label>
              <input
                placeholder="e.g. 192.168.1.100, compromised_file.exe"
                value={escalateForm.observedIoc}
                onChange={e => setEscalateForm({ ...escalateForm, observedIoc: e.target.value })}
                style={{ ...input, width: '100%', boxSizing: 'border-box', marginBottom: 12 }}
              />

              <label style={label}>Affected Asset Name</label>
              <input
                placeholder="e.g. Endpoint Hostname or Username"
                value={escalateForm.affectedAsset}
                onChange={e => setEscalateForm({ ...escalateForm, affectedAsset: e.target.value })}
                style={{ ...input, width: '100%', boxSizing: 'border-box', marginBottom: 12 }}
              />

              <label style={label}>Escalation Priority</label>
              <select
                value={escalateForm.priority}
                onChange={e => setEscalateForm({ ...escalateForm, priority: e.target.value })}
                style={{ ...input, width: '100%', boxSizing: 'border-box', marginBottom: 16 }}
              >
                <option value="low">Low</option>
                <option value="medium">Medium</option>
                <option value="high">High</option>
                <option value="critical">Critical</option>
              </select>

              <div style={{ display: 'flex', gap: 10, justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setShowEscalateModal(false)} style={{ ...btn, background: '#475569' }}>Cancel</button>
                <button type="submit" style={{ ...btnPrimary, background: '#7c3aed' }}>Confirm Escalation</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {view === 'tickets' && (
        <div className="soc-ticket-flow" style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 10, marginBottom: 14 }}>
          <div style={ticketFlowCard}>
            <b style={{ color: '#67e8f9' }}>1 · Ticket Created</b>
            <span>SOAR promotes an actionable alert into a ticket and sends it through the SOC Manager queue.</span>
          </div>
          <div style={ticketFlowCard}>
            <b style={{ color: '#a7f3d0' }}>2 · Auto-Assigned</b>
            <span>IDS, IPS and Firewall tickets go only to an on-shift SOC Manager or L4 analyst; lowest workload decides between eligible users.</span>
          </div>
          <div style={ticketFlowCard}>
            <b style={{ color: '#fcd34d' }}>3 · System Lifetime</b>
            <span>It stays in this active queue while open/investigating; the record remains until company retention expiry (default 90 days).</span>
          </div>
        </div>
      )}

      {/* Main Table */}
      {loading ? (
        <State text="Loading workspace records…" />
      ) : !state.items?.length ? (
        <State text={view === 'tickets' ? 'No active SOAR tickets found in your authorized scope.' : 'No records found in your authorized scope.'} />
      ) : (
        <div className="soc-workspace-table-wrap" style={tableWrap}>
          <table className={`soc-workspace-table ${view === 'queue' ? 'queue-workspace-table' : ''} ${view === 'shifts' ? 'shift-workspace-table' : ''} ${isEscalationHistoryView ? 'escalation-workspace-table' : ''} ${['incidents', 'threat-intelligence'].includes(view) ? 'incident-workspace-table' : ''} ${isAnalystView(view) ? 'analyst-workspace-table' : ''}`} style={table}>
            <thead>
              <tr>
                {getColumns(view, user.role).map(c => (
                  <th key={c} style={th}>{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.items.map(item => (
                <Row key={item._id} view={view} item={item} role={user.role} act={handleAction} decide={handleEscalationDecision} reload={load} editShift={openEditShift} onViewDashboard={openAnalystDashboard} />
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {state.pages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, marginTop: 16 }}>
          <button disabled={page <= 1} onClick={() => { params.set('page', String(page - 1)); setParams(params); }} style={btn}>Previous</button>
          <span style={{ padding: 8, fontSize: 13, color: '#94a3b8' }}>Page {page} of {state.pages}</span>
          <button disabled={page >= state.pages} onClick={() => { params.set('page', String(page + 1)); setParams(params); }} style={btn}>Next</button>
        </div>
      )}
      <style>{`
        .soc-workspace-page{min-width:0;max-width:100%;color:#dbeafe}
        .soc-workspace-header{padding:14px 16px;border:1px solid #1e3a5f;border-radius:12px;background:linear-gradient(135deg,#0c1a2e,#101d35);box-shadow:0 12px 28px rgba(0,0,0,.18)}
        .soc-workspace-tools{padding:10px;border:1px solid #1e3a5f;border-radius:10px;background:#091624}
        .soc-workspace-table-wrap{max-width:100%;box-shadow:0 16px 34px rgba(0,0,0,.22)}
        .soc-workspace-table{min-width:1120px;table-layout:fixed}
        .soc-workspace-table th,.soc-workspace-table td{box-sizing:border-box}
        .soc-workspace-table th:first-child{width:28%}.soc-workspace-table th:nth-child(2){width:8%}.soc-workspace-table th:nth-child(3){width:8%}.soc-workspace-table th:nth-child(4){width:14%;text-align:center}.soc-workspace-table th:nth-child(5){width:19%}.soc-workspace-table th:nth-child(6){width:12%}.soc-workspace-table th:last-child{width:11%;text-align:center}
        .soc-workspace-table .soc-title-cell{min-width:0;overflow:hidden}
        .soc-workspace-table .soc-record-title{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .soc-workspace-table .soc-status-cell{text-align:center;overflow:hidden}.soc-workspace-table .soc-status-cell span{display:inline-flex;max-width:100%;box-sizing:border-box;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .soc-workspace-table .soc-analyst-cell{overflow:hidden}.soc-workspace-table .soc-analyst-cell b,.soc-workspace-table .soc-analyst-cell div{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .queue-workspace-table .soc-company-cell,.queue-workspace-table .soc-analyst-cell,.queue-workspace-table .soc-created-cell,.queue-workspace-table .soc-workspace-actions{overflow:hidden}
        .queue-workspace-table .soc-analyst-cell span{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .queue-workspace-table .soc-workspace-actions{padding-left:8px;padding-right:8px}
        .queue-workspace-table .soc-assign-button{display:block;width:100%;max-width:148px;margin:0;padding:8px 7px;box-sizing:border-box;white-space:normal;line-height:1.2}
        .escalation-workspace-table{width:100%;min-width:940px;table-layout:fixed}
        .escalation-workspace-table th:first-child{width:22%}.escalation-workspace-table th:nth-child(2){width:10%}.escalation-workspace-table th:nth-child(3){width:14%}.escalation-workspace-table th:nth-child(4){width:8%}.escalation-workspace-table th:nth-child(5){width:20%}.escalation-workspace-table th:nth-child(6){width:10%;text-align:center}.escalation-workspace-table th:last-child{width:16%;text-align:center}
        .escalation-workspace-table td{overflow:hidden;vertical-align:middle}
        .escalation-resource-link{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .escalation-company{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1}
        .escalation-analyst{display:grid;gap:3px;min-width:0}.escalation-analyst b{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#e2e8f0}.escalation-analyst small{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#64748b;font-size:9px;text-transform:uppercase}
        .escalation-level,.escalation-status{display:inline-flex;align-items:center;justify-content:center;padding:5px 9px;border-radius:999px;border:1px solid #294765;background:#071524;font-size:10px;font-weight:800;text-transform:uppercase;white-space:nowrap}
        .escalation-reason{display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;color:#cbd5e1;line-height:1.45;overflow-wrap:anywhere}
        .escalation-status-cell,.escalation-action-cell{text-align:center}
        .escalation-actions{display:flex;align-items:center;justify-content:center;gap:7px;flex-wrap:wrap}.escalation-actions button,.escalation-actions a{margin:0!important;min-width:70px;box-sizing:border-box;text-align:center;white-space:nowrap}
        .incident-workspace-table{width:100%;min-width:0}
        .incident-workspace-table th:first-child{width:28%}.incident-workspace-table th:nth-child(2){width:8%}.incident-workspace-table th:nth-child(3){width:8%;text-align:center}.incident-workspace-table th:nth-child(4){width:14%;text-align:center}.incident-workspace-table th:nth-child(5){width:19%}.incident-workspace-table th:nth-child(6){width:12%}.incident-workspace-table th:last-child{width:11%;text-align:center}
        .incident-workspace-table td{overflow:hidden}
        .incident-workspace-table .soc-company-cell{overflow-wrap:anywhere}
        .incident-workspace-table .soc-status-cell span{max-width:100%;box-sizing:border-box;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .incident-workspace-table .soc-analyst-cell b{display:block;max-width:100%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;line-height:1.35}
        .incident-workspace-table .soc-workspace-actions{padding-left:8px;padding-right:8px;text-align:left}
        .incident-workspace-table .soc-assign-button{display:block;width:100%;max-width:138px;margin:0;padding:7px 7px;box-sizing:border-box;white-space:normal;line-height:1.2}
        .analyst-workspace-table{width:100%;min-width:0}
        .analyst-workspace-table th:first-child{width:22%}.analyst-workspace-table th:nth-child(2){width:22%}.analyst-workspace-table th:nth-child(3){width:13%}.analyst-workspace-table th:nth-child(4){width:10%}.analyst-workspace-table th:nth-child(5){width:10%}.analyst-workspace-table th:last-child{width:23%}
        .analyst-workspace-table td{min-width:0;overflow:hidden;overflow-wrap:anywhere}
        .soc-analyst-email{display:block;min-width:0;color:#94a3b8;overflow-wrap:anywhere;line-height:1.4}.soc-analyst-email small{display:block;margin-top:3px;color:#64748b;font-size:9px;text-transform:uppercase}
        .soc-analyst-role{display:block;max-width:100%;color:#67e8f9;text-transform:capitalize;overflow-wrap:anywhere}
        .soc-analyst-actions{display:flex;align-items:center;gap:8px;flex-wrap:nowrap}.soc-analyst-actions button{margin:0!important;white-space:nowrap;line-height:1.2}
        .shift-workspace-table{width:100%;min-width:850px;table-layout:fixed}
        .shift-workspace-table th:first-child{width:18%}.shift-workspace-table th:nth-child(2){width:17%}.shift-workspace-table th:nth-child(3){width:15%}.shift-workspace-table th:nth-child(4){width:14%}.shift-workspace-table th:nth-child(5){width:24%}.shift-workspace-table th:last-child{width:12%}
        .shift-workspace-table th{white-space:nowrap}
        .shift-workspace-table td{height:72px;overflow:hidden}
        .shift-name-cell{display:flex;align-items:center;gap:10px;min-width:0}
        .shift-icon{display:grid;place-items:center;width:34px;height:34px;flex:0 0 34px;border-radius:9px;background:rgba(56,189,248,.12);border:1px solid rgba(56,189,248,.28);color:#7dd3fc;font-size:17px}
        .shift-name-text{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#e0f2fe;font-size:13px}
        .shift-pill{display:inline-flex;align-items:center;max-width:100%;padding:5px 9px;border-radius:999px;border:1px solid #294765;background:#0a1a2c;color:#cbd5e1;line-height:1.2;box-sizing:border-box}
        .shift-company-pill{color:#7dd3fc;border-color:rgba(56,189,248,.3);background:rgba(56,189,248,.08);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .shift-time-pill{color:#c4b5fd;border-color:rgba(167,139,250,.3);background:rgba(167,139,250,.08);white-space:nowrap;font-variant-numeric:tabular-nums}
        .shift-timezone-pill{color:#fcd34d;border-color:rgba(250,204,21,.25);background:rgba(250,204,21,.07);white-space:nowrap}
        .shift-analyst-list{display:flex;align-items:center;gap:5px;min-width:0;flex-wrap:wrap}
        .shift-analyst-chip{display:inline-flex;align-items:center;min-width:0;max-width:100%;padding:5px 8px;border-radius:7px;background:rgba(52,211,153,.08);border:1px solid rgba(52,211,153,.2);color:#a7f3d0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
        .shift-empty{color:#71839b;font-style:italic}
        .shift-created-by{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#cbd5e1}
        .soc-workspace-table tbody tr{background:#0c192c;transition:background .15s ease}
        .soc-workspace-table tbody tr:nth-child(even){background:#0e1d31}
        .soc-workspace-table tbody tr:hover{background:#132842}
        .soc-workspace-table td{min-width:0;vertical-align:middle}
        @media(max-width:1000px){.incident-workspace-table,.analyst-workspace-table{min-width:900px}.shift-workspace-table{min-width:850px}}
        @media(max-width:760px){.soc-workspace-header{align-items:flex-start!important;flex-direction:column;gap:10px}.soc-workspace-tools input,.soc-workspace-tools select{width:100%;box-sizing:border-box}.soc-ticket-flow{grid-template-columns:1fr!important}.soc-workspace-table{min-width:1050px}.incident-workspace-table,.analyst-workspace-table{min-width:900px}.shift-workspace-table{min-width:850px}.escalation-workspace-table{min-width:940px}}
        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        @media(max-width:800px){
          .analyst-dashboard-grid {
            grid-template-columns: 1fr !important;
          }
          .analyst-audit-split {
            grid-template-columns: 1fr !important;
          }
        }
      `}</style>
    </div>
  );
}

const ROLE_QUEUE_LABEL = { l1_analyst: 'L1 Low / Medium', l2_analyst: 'L2 High', l3_analyst: 'L3 Critical', l4_analyst: 'L4 Threat Intelligence' };

function isAnalystView(view) {
  return ['analysts', 'team', 'l1-analysts', 'l2-analysts', 'l3-analysts', 'l4-analysts'].includes(view);
}

function getColumns(view, role) {
  if (['escalations', 'escalate-to-l3', 'l3-incoming-escalations'].includes(view)) return ['Alert / Incident', 'Company', 'From Analyst', 'To Level', 'Reason', 'Status', 'Actions'];
  if (view === 'companies') return ['Company Name', 'Status', 'Partner', 'Actions'];
  if (view === 'shifts') return ['Shift Name', 'Company', 'Time Window', 'Timezone', 'Assigned Analysts', role === 'soc_manager' ? 'Controls' : 'Created By'];
  if (view === 'audit') return ['Action', 'Actor', 'Target Type', 'IP Address', 'Timestamp'];
  if (isAnalystView(view)) return ['Analyst Name', 'Email (Read-only)', 'Role', 'Status', 'Workload', 'Actions'];
  if (view === 'tickets') return ['SOAR Ticket / ID', 'Category / Company', 'Severity', 'Status', 'SOAR Assignment', 'Age / Retention', 'Actions'];
  return ['Title / ID', 'Company', 'Severity', 'Status', 'Auto-Assigned Analyst', 'Created Time', 'Actions'];
}

function Row({ view, item, role, act, decide, reload, editShift, onViewDashboard }) {
  const tdStyle = { padding: '14px 12px', borderTop: '1px solid #1e3a5f', fontSize: 12 };

  if (['escalations', 'escalate-to-l3', 'l3-incoming-escalations'].includes(view)) {
    const rolePrefix = {
      soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4',
    }[role] || '/l1';
    const resource = item.incidentId || item.alertId;
    const resourceId = resource?._id;
    const resourcePath = item.incidentId
      ? `${rolePrefix}/incidents/${resourceId}`
      : resourceId ? `${rolePrefix}/alerts/${resourceId}` : '';
    const resourceTitle = item.alertId?.signatureName || item.alertId?.eventId || item.alertId?._id
      || item.incidentId?.title || item.incidentId?._id || 'Incident';
    return (
      <tr className="escalation-row">
        <td style={tdStyle}>
          {resourcePath
            ? <Link className="escalation-resource-link" title={resourceTitle} to={resourcePath} style={{ color: '#38bdf8', textDecoration: 'none', fontWeight: 800 }}>{resourceTitle}</Link>
            : <b>{resourceTitle}</b>}
        </td>
        <td style={tdStyle}><span className="escalation-company" title={item.companyId?.name || 'Company'}>{item.companyId?.name || 'Company'}</span></td>
        <td style={tdStyle}>
          <span className="escalation-analyst">
            <b title={item.fromUserId?.name || item.fromUserId?.email || 'Analyst'}>{item.fromUserId?.name || item.fromUserId?.email || 'Analyst'}</b>
            {item.fromUserId?.role && <small>{String(item.fromUserId.role).replace(/_/g, ' ')}</small>}
          </span>
        </td>
        <td style={tdStyle}><span className="escalation-level" style={{ color: '#38bdf8' }}>{item.toLevel}</span></td>
        <td style={tdStyle}><span className="escalation-reason" title={item.reason || 'No reason provided'}>{item.reason || 'No reason provided'}</span></td>
        <td className="escalation-status-cell" style={tdStyle}><span className="escalation-status" style={{ color: item.status === 'accepted' ? '#34d399' : item.status === 'rejected' ? '#f87171' : '#facc15' }}>{item.status}</span></td>
        <td className="escalation-action-cell" style={tdStyle}>
          <div className="escalation-actions">
            {role === 'soc_manager' && item.status === 'pending' && (
              <>
                <button style={btnSuccess} onClick={() => decide(item, 'accepted')}>Approve</button>
                <button style={btnDanger} onClick={() => decide(item, 'rejected')}>Reject</button>
              </>
            )}
            {role !== 'soc_manager' && resourcePath && (
              <Link to={resourcePath} style={{ ...btn, display: 'inline-block', marginRight: 0, textDecoration: 'none' }}>Open Investigation →</Link>
            )}
          </div>
        </td>
      </tr>
    );
  }

  if (view === 'companies') {
    return (
      <tr>
        <td style={tdStyle}><b>{item.name}</b></td>
        <td style={tdStyle}><span style={{ color: item.status === 'active' ? '#34d399' : '#94a3b8' }}>{item.status}</span></td>
        <td style={tdStyle}>{item.partnerId?.name || 'Direct'}</td>
        <td style={tdStyle}>Scope Active</td>
      </tr>
    );
  }

  if (view === 'shifts') {
    const assignedAnalysts = (item.analystIds || []).filter(analyst => ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst', 'analyst'].includes(analyst.role));
    return (
      <tr>
        <td style={tdStyle}>
          <div className="shift-name-cell">
            <span className="shift-icon" aria-hidden="true">◷</span>
            <b className="shift-name-text" title={item.name}>{item.name || 'Unnamed Shift'}</b>
          </div>
        </td>
        <td style={tdStyle}><span className="shift-pill shift-company-pill" title={item.companyId?.name || 'All companies'}>{item.companyId?.name || 'All companies'}</span></td>
        <td style={tdStyle}><span className="shift-pill shift-time-pill">{item.startTime} – {item.endTime}</span></td>
        <td style={tdStyle}><span className="shift-pill shift-timezone-pill">{item.timezone || 'UTC'}</span></td>
        <td style={tdStyle}>
          {assignedAnalysts.length ? (
            <div className="shift-analyst-list">
              {assignedAnalysts.slice(0, 2).map(analyst => (
                <span key={analyst._id || analyst.email} className="shift-analyst-chip" title={`${analyst.name || analyst.email} · ${String(analyst.role || '').replace(/_/g, ' ')}`}>
                  {analyst.name || analyst.email || 'SOC team member'}
                </span>
              ))}
              {assignedAnalysts.length > 2 && <span className="shift-pill">+{assignedAnalysts.length - 2}</span>}
            </div>
          ) : <span className="shift-empty">No analysts assigned</span>}
        </td>
        <td style={tdStyle}>{role === 'soc_manager'
          ? <button style={{ ...btnPrimary, margin: 0 }} onClick={() => editShift(item)}>Assign / Edit</button>
          : <span className="shift-created-by" title={item.createdBy?.name || item.createdBy?.email || 'SOC Manager'}>{item.createdBy?.name || item.createdBy?.email || 'SOC Manager'}</span>}</td>
      </tr>
    );
  }

  if (view === 'audit') {
    return (
      <tr>
        <td style={tdStyle}><b style={{ color: '#38bdf8' }}>{item.action}</b></td>
        <td style={tdStyle}>{item.actorId?.email || item.actorId?.name || 'System'}</td>
        <td style={tdStyle}>{item.targetType}</td>
        <td style={tdStyle}>{item.ipAddress || '—'}</td>
        <td style={tdStyle}>{new Date(item.createdAt).toLocaleString()}</td>
      </tr>
    );
  }

  if (isAnalystView(view)) {
    const handleSuspend = async () => {
      if (!confirm(`Suspend analyst ${item.name}?`)) return;
      await api.post(`/soc-manager/analysts/${item._id}/suspend`);
      reload();
    };
    const handleReactivate = async () => {
      await api.post(`/soc-manager/analysts/${item._id}/reactivate`);
      reload();
    };
    const handleCompanyAssignment = async () => {
      const response = await api.get('/soc-manager/companies', { params: { limit: 100 } });
      const companies = response.data?.items || response.data || [];
      if (!companies.length) return alert('No companies are assigned to your SOC Manager account.');
      const choices = companies.map((company, index) => `${index + 1}. ${company.name}`).join('\n');
      const selected = Number(prompt(`Assign ${item.name} to which company?\n\n${choices}`));
      const company = companies[selected - 1];
      if (!company) return;
      await api.put(`/soc/staff/${item._id}/assignments`, { companyIds: [company._id], departmentIds: [] });
      reload();
    };
    return (
      <tr>
        <td style={tdStyle}>
          <button
            onClick={() => onViewDashboard(item._id)}
            style={{
              background: 'none',
              border: 0,
              padding: 0,
              color: '#38bdf8',
              textDecoration: 'underline',
              cursor: 'pointer',
              fontWeight: 'bold',
              textAlign: 'left',
              fontFamily: 'inherit',
              fontSize: 'inherit'
            }}
            title="Click to view full analyst dashboard"
          >
            {item.name}
          </button>
        </td>
        <td style={tdStyle}><span className="soc-analyst-email">{item.email}<small>Read-only</small></span></td>
        <td style={tdStyle}><span className="soc-analyst-role">{String(item.role || 'analyst').replace(/_/g, ' ')}</span></td>
        <td style={tdStyle}><span style={{ color: item.accountStatus === 'active' ? '#34d399' : '#f87171' }}>{item.accountStatus || 'active'}</span></td>
        <td style={tdStyle}>
          <div style={{ display: 'grid', gap: 3 }}>
            <span>{item.workload || 0} / {item.maxWorkload || 10}</span>
            <small style={{ color: item.onShiftNow ? '#34d399' : '#64748b', fontWeight: 700 }}>
              {item.onShiftNow ? 'Live shift' : 'Off shift'} · {item.completedToday || 0} closed today
            </small>
          </div>
        </td>
        <td style={tdStyle}>
          <div className="soc-analyst-actions">
            <button style={{ ...btn, marginRight: 0 }} onClick={handleCompanyAssignment}>Assign Company</button>
            {item.accountStatus === 'suspended' ? (
              <button style={{ ...btnSuccess, marginRight: 0 }} onClick={handleReactivate}>Reactivate</button>
            ) : (
              <button style={{ ...btnDanger, marginRight: 0 }} onClick={handleSuspend}>Suspend</button>
            )}
          </div>
        </td>
      </tr>
    );
  }

  const prefix = {
    soc_manager: '/soc-manager',
    l1_analyst: '/l1',
    l2_analyst: '/l2',
    l3_analyst: '/l3',
    l4_analyst: '/l4'
  }[role] || '/l1';
  const alertDetailPath = view === 'queue'
    ? `${prefix}/queue/alerts/${item._id}`
    : view === 'tickets'
      ? `${prefix}/tickets/${item._id}`
      : `${prefix}/alerts/${item._id}`;
  const recordTitle = item.resourceType === 'incident'
    ? (item.title || item.eventId || 'Correlation Incident')
    : (item.signatureName || item.ruleId || item.eventId || 'Alert');
  const ticketOpenedAt = item.ticketOpenedAt || item.createdAt;
  const ticketSourceLabel = 'SOAR created';
  const ticketAssignmentLabel = {
    auto: item.ticketSource === 'soar' ? 'SOAR auto-routing' : 'Automatic routing',
    manual: 'Manual assignment',
    self: 'Self-assigned',
  }[item.ticketAssignmentMode] || 'Assignment recorded';

  return (
    <tr className="soc-work-row">
      <td className="soc-title-cell" style={tdStyle}>
        {item.resourceType === 'incident'
          ? <Link className="soc-record-title" title={recordTitle} to={`${prefix}/incidents/${item.resourceId || item._id}`} style={{ color: '#c4b5fd', textDecoration: 'none', fontWeight: 800, lineHeight: 1.35 }}>{recordTitle}</Link>
          : <Link className="soc-record-title" title={recordTitle} to={alertDetailPath} style={{ color: '#38bdf8', textDecoration: 'none', fontWeight: 800, lineHeight: 1.35 }}>{recordTitle}</Link>}
        <div title={item.description || ''} style={{ color: '#71839b', fontSize: 11, marginTop: 5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.description?.slice(0, 120)}</div>
      </td>
      <td className="soc-company-cell" style={tdStyle}>{view === 'tickets' ? (
        <div>
          <span style={{ display: 'inline-flex', padding: '4px 8px', borderRadius: 999, color: '#c4b5fd', background: 'rgba(167,139,250,.1)', border: '1px solid rgba(167,139,250,.25)', fontSize: 10, fontWeight: 800, textTransform: 'uppercase' }}>
            {String(item.ticketCategory || (item.iocMatched ? 'threat_intelligence' : item.eventCategory) || 'general').replace(/_/g, ' ')}
          </span>
          <div style={{ color: '#71839b', fontSize: 10, marginTop: 4 }}>{item.companyId?.name || 'Company'}</div>
        </div>
      ) : (item.companyId?.name || 'Company')}</td>
      <td style={tdStyle}><span style={{ display: 'inline-flex', padding: '4px 8px', borderRadius: 999, color: severityColor[item.severity] || '#38bdf8', background: `${severityColor[item.severity] || '#38bdf8'}18`, border: `1px solid ${severityColor[item.severity] || '#38bdf8'}44`, fontWeight: 800, textTransform: 'uppercase', fontSize: 10 }}>{item.severity}</span></td>
      <td className="soc-status-cell" style={tdStyle}><span style={{ display: 'inline-flex', padding: '4px 8px', borderRadius: 999, color: item.status === 'resolved' ? '#34d399' : item.status === 'investigating' ? '#60a5fa' : '#facc15', background: '#071524', border: '1px solid #294765', fontSize: 10, textTransform: 'uppercase' }}>{item.status}</span></td>
      <td className="soc-analyst-cell" style={tdStyle}>
        {item.assignedTo?.name ? (
          <div>
            <b style={{ color: '#67e8f9' }}>{item.assignedTo.name}</b>
            <div style={{ color: '#64748b', fontSize: 10, marginTop: 2 }}>{String(item.assignedTo.role || 'analyst').replace(/_/g, ' ').toUpperCase()}</div>
            {view === 'tickets' && (
              <>
                <div style={{ color: '#34d399', fontSize: 9, marginTop: 4, textTransform: 'uppercase' }}>{ticketSourceLabel}</div>
                <div style={{ color: '#94a3b8', fontSize: 9, marginTop: 2 }}>{ticketAssignmentLabel}</div>
                {item.ticketOpenedBy?.name && <div style={{ color: '#64748b', fontSize: 9, marginTop: 2 }}>Opened by {item.ticketOpenedBy.name}</div>}
              </>
            )}
          </div>
        ) : <span style={{ color: '#f59e0b' }}>{view === 'queue' ? 'Pending auto-assignment' : 'Unassigned'}</span>}
      </td>
      <td className="soc-created-cell" style={tdStyle}>{(view === 'tickets' ? ticketOpenedAt : item.createdAt) ? (() => {
        const timestamp = view === 'tickets' ? ticketOpenedAt : item.createdAt;
        if (view !== 'tickets') return <><div style={{ color: '#cbd5e1', whiteSpace: 'nowrap' }}>{new Date(timestamp).toLocaleDateString()}</div><div style={{ color: '#71839b', fontSize: 10, marginTop: 3 }}>{new Date(timestamp).toLocaleTimeString()}</div></>;
        const assignmentMs = item.ticketQueuedAt && item.ticketRoutedAt
          ? new Date(item.ticketRoutedAt).getTime() - new Date(item.ticketQueuedAt).getTime()
          : null;
        const retentionMs = item.expiresAt ? new Date(item.expiresAt).getTime() - Date.now() : null;
        return <>
          <div style={{ color: '#cbd5e1', whiteSpace: 'nowrap', fontWeight: 700 }}>Age: {formatDuration(Date.now() - new Date(timestamp).getTime())}</div>
          {assignmentMs !== null && <div style={{ color: '#67e8f9', fontSize: 9, marginTop: 3 }}>Assigned in {formatDuration(assignmentMs)}</div>}
          <div style={{ color: retentionMs === null ? '#94a3b8' : retentionMs > 0 ? '#fcd34d' : '#fb7185', fontSize: 9, marginTop: 3 }}>
            {retentionMs === null ? 'No expiry set / legal hold' : retentionMs > 0 ? `${formatDuration(retentionMs)} retention left` : 'Retention expiry reached'}
          </div>
          <div style={{ color: '#64748b', fontSize: 9, marginTop: 3 }}>{new Date(timestamp).toLocaleString()}</div>
        </>;
      })() : '—'}</td>
      <td className="soc-workspace-actions" style={tdStyle}>
        {role === 'soc_manager' ? (
          <button className="soc-assign-button" style={{ ...btn, marginRight: 0 }} onClick={() => act(item, 'auto_assign')}>Assign / Reassign</button>
        ) : role === 'l4_analyst' && item.resourceType === 'incident' ? (
          <Link to={`${prefix}/incidents/${item.resourceId || item._id}`} style={{ ...btn, display: 'inline-block', marginRight: 0, textDecoration: 'none' }}>Open Incident</Link>
        ) : view === 'escalate-to-l3' ? (
          <button style={{ ...btn, background: '#7c3aed', marginRight: 0 }} onClick={() => act(item, 'escalate')}>🚀 Escalate to L3</button>
        ) : (
          <>
            {!item.assignedTo && (
              <button style={btn} onClick={() => act(item, 'acknowledge')}>Acknowledge</button>
            )}
            <button style={{ ...btn, background: '#7c3aed' }} onClick={() => act(item, 'escalate')}>Escalate</button>
          </>
        )}
      </td>
    </tr>
  );
}

function formatDuration(milliseconds) {
  const totalMinutes = Math.max(0, Math.floor(Number(milliseconds || 0) / 60000));
  const days = Math.floor(totalMinutes / 1440);
  const hours = Math.floor((totalMinutes % 1440) / 60);
  const minutes = totalMinutes % 60;
  if (days) return `${days}d ${hours}h`;
  if (hours) return `${hours}h ${minutes}m`;
  return `${minutes}m`;
}

function formatAuditMinutes(value) {
  const totalMinutes = Math.max(0, Math.round(Number(value) || 0));
  if (!totalMinutes) return '—';
  const hours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return hours ? `${hours}h${minutes ? ` ${minutes}m` : ''}` : `${minutes}m`;
}

function formatAuditDate(value) {
  if (!value) return '—';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString();
}

function AuditTable({ title, empty, columns, rows, maxVisibleRows = 0 }) {
  return (
    <div style={{ ...dashboardCard, padding: 0, minWidth: 0, overflow: 'hidden' }}>
      <div style={{ padding: '12px 14px', color: '#bae6fd', fontSize: 12, fontWeight: 900, borderBottom: '1px solid #1e3a5f', display: 'flex', justifyContent: 'space-between', gap: 10 }}>
        <span>{title}</span>
        {maxVisibleRows > 0 && <span style={{ color: '#64748b', fontWeight: 700 }}>{rows.length} logs · {Math.min(maxVisibleRows, rows.length)} visible</span>}
      </div>
      {rows.length ? (
        <div style={{
          overflowX: 'auto',
          overflowY: maxVisibleRows > 0 ? 'scroll' : 'visible',
          maxHeight: maxVisibleRows > 0 ? 424 : 'none',
          scrollbarGutter: maxVisibleRows > 0 ? 'stable' : 'auto',
        }}>
          <table style={{ width: '100%', minWidth: Math.max(560, columns.length * 115), borderCollapse: 'collapse' }}>
            <thead><tr>{columns.map(column => <th key={column} style={{ ...th, padding: '9px 10px', whiteSpace: 'nowrap', position: maxVisibleRows > 0 ? 'sticky' : 'static', top: 0, zIndex: 2, background: '#0c192c' }}>{column}</th>)}</tr></thead>
            <tbody>{rows.map((row, rowIndex) => (
              <tr key={`${title}-${rowIndex}`} style={maxVisibleRows > 0 ? { height: 39 } : undefined}>
                {row.map((cell, cellIndex) => <td key={`${rowIndex}-${cellIndex}`} style={{ padding: '10px', color: '#cbd5e1', fontSize: 11, borderTop: '1px solid #162c47', verticalAlign: 'top', whiteSpace: maxVisibleRows > 0 ? 'nowrap' : 'normal' }}>{cell}</td>)}
              </tr>
            ))}</tbody>
          </table>
        </div>
      ) : <div style={{ padding: 20, color: '#64748b', fontSize: 11 }}>{empty}</div>}
    </div>
  );
}

function State({ text }) {
  return <div style={{ padding: 42, textAlign: 'center', border: '1px solid #1e3a5f', borderRadius: 10, color: '#64748b', background: '#0c192c' }}>{text}</div>;
}

const severityColor = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };
const tools = { display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 14 };
const input = { padding: '9px 12px', background: '#07111f', border: '1px solid #294765', borderRadius: 7, color: '#e2e8f0', fontSize: 12 };
const label = { display: 'block', fontSize: 12, color: '#94a3b8', marginBottom: 4 };
const errorBox = { padding: 12, background: '#350d16', color: '#fca5a5', borderRadius: 7, marginBottom: 12, fontSize: 12 };
const successBox = { padding: 12, background: '#064e3b', color: '#6ee7b7', borderRadius: 7, marginBottom: 12, fontSize: 12 };
const ticketFlowCard = { display: 'grid', gap: 5, padding: 12, border: '1px solid #1e3a5f', borderRadius: 10, background: '#091624', color: '#94a3b8', fontSize: 10, lineHeight: 1.45 };
const tableWrap = { overflowX: 'auto', background: '#0c192c', border: '1px solid #1e3a5f', borderRadius: 10 };
const table = { width: '100%', borderCollapse: 'collapse' };
const th = { padding: 11, textAlign: 'left', color: '#7dd3fc', fontSize: 11, background: '#10233c', fontWeight: 700 };
const btn = { padding: '6px 10px', marginRight: 5, border: 0, borderRadius: 6, background: '#1d4ed8', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 };
const btnPrimary = { padding: '8px 14px', border: 0, borderRadius: 6, background: '#2563eb', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 700 };
const btnSuccess = { padding: '6px 10px', marginRight: 5, border: 0, borderRadius: 6, background: '#16a34a', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 };
const btnDanger = { padding: '6px 10px', marginRight: 5, border: 0, borderRadius: 6, background: '#dc2626', color: '#fff', cursor: 'pointer', fontSize: 12, fontWeight: 600 };
const modalOverlay = { position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.75)', zIndex: 100, display: 'grid', placeItems: 'center' };
const modalBox = { background: '#0c192c', border: '1px solid #1e3a5f', borderRadius: 12, padding: 24, width: 'min(480px, 90vw)' };

function L1WorkSummary({ metrics = {}, shifts = [], dateRange = 'today', basePath = '/l1' }) {
  const completionRate = Math.max(0, Math.min(100, Number(metrics.completionRate || 0)));
  const rangeLabel = dateRange === 'today' ? 'today' : dateRange === '7d' ? 'in the last 7 days' : 'in the last 30 days';
  const nextLevelName = basePath === '/l2' ? 'L3' : basePath === '/l3' ? 'Manager' : 'L2';

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={dashboardCard}>
          <Header title="Work Completion" />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 18 }}>
            <strong style={{ color: '#22d3ee', fontSize: 34 }}>{completionRate}%</strong>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>{metrics.completedWork || 0} of {metrics.totalAssignedWork || 0} completed</span>
          </div>
          <div style={{ height: 10, borderRadius: 999, background: '#17243a', overflow: 'hidden', margin: '12px 0 18px' }}>
            <div style={{ width: `${completionRate}%`, height: '100%', borderRadius: 999, background: 'linear-gradient(90deg,#0ea5e9,#22c55e)', transition: 'width .25s ease' }} />
          </div>
          <SummaryPair label="Pending workload" value={metrics.pendingWork || 0} color="#facc15" />
          <SummaryPair label={`New ${rangeLabel}`} value={metrics.newInRange || 0} color="#818cf8" />
          <SummaryPair label={`Completed ${rangeLabel}`} value={metrics.completedInRange || 0} color="#34d399" />
        </section>

        <section style={dashboardCard}>
          <Header title="Workload by Type" />
          <WorkTypeRow
            label="My Tickets"
            total={metrics.totalTickets || 0}
            pending={metrics.pendingTickets || 0}
            completed={metrics.completedTickets || 0}
            color="#60a5fa"
          />
          <WorkTypeRow
            label="Incidents"
            total={metrics.totalAssignedIncidents || 0}
            pending={metrics.pendingIncidents || 0}
            completed={metrics.completedIncidents || 0}
            color="#c084fc"
          />
          {['/l2', '/l3'].includes(basePath) && (
            <WorkTypeRow
              label="Escalated Alerts"
              total={metrics.totalEscalationsIncoming || 0}
              pending={metrics.pendingEscalationsIncoming || 0}
              completed={metrics.closedEscalationsIncoming || 0}
              color="#fb923c"
            />
          )}
          <SummaryPair label="High-priority pending" value={metrics.highPriorityOpen || 0} color="#fb7185" />
        </section>

        <section style={dashboardCard}>
          <Header title="Shift Coverage" />
          <div style={{ display: 'flex', gap: 10, margin: '14px 0' }}>
            <MiniMetric label="Assigned" value={metrics.activeShifts || 0} color="#60a5fa" />
            <MiniMetric label="Active now" value={metrics.onShiftNow || 0} color="#2dd4bf" />
          </div>
          {shifts.length ? shifts.slice(0, 3).map(shift => (
            <div key={shift._id} style={{ ...dashboardRow, padding: '9px 2px' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: shift.isCurrent ? '#34d399' : '#475569', flexShrink: 0 }} />
              <span style={{ minWidth: 0, flex: 1 }}>
                <b style={{ color: '#e2e8f0', display: 'block' }}>{shift.name}</b>
                <small style={{ color: '#64748b' }}>{shift.companyId?.name || 'Assigned Company'} · {shift.timezone}</small>
              </span>
              <b style={{ color: shift.isCurrent ? '#34d399' : '#94a3b8', fontSize: 11, whiteSpace: 'nowrap' }}>{shift.startTime}–{shift.endTime}</b>
            </div>
          )) : <EmptyState />}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={dashboardCard}>
          <Header title="Incident Lifecycle" />
          <SummaryPair label={`Received ${rangeLabel}`} value={metrics.newIncidentsInRange || 0} color="#818cf8" />
          <SummaryPair label={`Closed ${rangeLabel}`} value={metrics.closedIncidentsInRange || 0} color="#22c55e" />
          <SummaryPair label="Pending now" value={metrics.pendingIncidents || 0} color="#facc15" />
          <SummaryPair label="Total assigned" value={metrics.totalAssignedIncidents || 0} color="#c084fc" />
        </section>

        <section style={dashboardCard}>
          <Header title="My Ticket Lifecycle" />
          <SummaryPair label={`Received ${rangeLabel}`} value={metrics.newTicketsInRange || 0} color="#38bdf8" />
          <SummaryPair label={`Closed ${rangeLabel}`} value={metrics.closedTicketsInRange || 0} color="#22c55e" />
          <SummaryPair label="Pending now" value={metrics.pendingTickets || 0} color="#facc15" />
          <SummaryPair label="Total assigned" value={metrics.totalTickets || 0} color="#60a5fa" />
        </section>

        {['/l2', '/l3'].includes(basePath) ? (
          <section style={dashboardCard}>
            <Header title="Escalated Alerts" />
            <SummaryPair label="Assigned to me" value={metrics.myAssignedEscalationsIncoming || 0} color="#38bdf8" />
            <SummaryPair label="Total assigned" value={metrics.assignedEscalationsIncoming || 0} color="#60a5fa" />
            <SummaryPair label="Pending now" value={metrics.pendingEscalationsIncoming || 0} color="#facc15" />
            <SummaryPair label="Closed / Resolved" value={metrics.closedEscalationsIncoming || 0} color="#34d399" />
          </section>
        ) : (
          <section style={dashboardCard}>
            <Header title="Escalation & Priority" />
            <SummaryPair label={`Escalated to ${nextLevelName} ${rangeLabel}`} value={metrics.escalatedToL2 || 0} color="#fb923c" />
            <SummaryPair label={`Pending ${nextLevelName} escalations`} value={metrics.pendingEscalations || 0} color="#facc15" />
            <SummaryPair label="High-priority pending" value={metrics.highPriorityOpen || 0} color="#fb7185" />
            <SummaryPair label="Completed today" value={metrics.resolvedToday || 0} color="#34d399" />
            <SummaryPair label="False positives" value={metrics.falsePositives || 0} color="#94a3b8" />
          </section>
        )}
      </div>
    </>
  );
}

function L4WorkSummary({ metrics = {}, status = {}, categories = {}, shifts = [], dateRange = 'today' }) {
  const completionRate = Math.max(0, Math.min(100, Number(metrics.completionRate || 0)));
  const rangeLabel = dateRange === 'today' ? 'today' : dateRange === '7d' ? 'in the last 7 days' : 'in the last 30 days';
  const statusItems = [
    ['Open', status.open || 0, '#fb923c'],
    ['Investigating', status.investigating || 0, '#38bdf8'],
    ['Contained', status.contained || 0, '#a78bfa'],
    ['Under Observation', status.under_observation || 0, '#facc15'],
    ['Resolved', status.resolved || 0, '#34d399'],
    ['False Positive', status.false_positive || 0, '#94a3b8'],
  ];
  const categoryItems = Object.entries(categories)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, 6);

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={dashboardCard}>
          <Header title="Work Completion" />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 18 }}>
            <strong style={{ color: '#22d3ee', fontSize: 34 }}>{completionRate}%</strong>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>{metrics.completedWork || 0} of {metrics.totalAssignedWork || 0} completed</span>
          </div>
          <div style={{ height: 10, borderRadius: 999, background: '#17243a', overflow: 'hidden', margin: '12px 0 18px' }}>
            <div style={{ width: `${completionRate}%`, height: '100%', borderRadius: 999, background: 'linear-gradient(90deg,#0ea5e9,#22c55e)', transition: 'width .25s ease' }} />
          </div>
          <SummaryPair label="Pending workload" value={metrics.pendingWork || 0} color="#facc15" />
          <SummaryPair label={`New ${rangeLabel}`} value={metrics.newInRange || 0} color="#818cf8" />
          <SummaryPair label={`Completed ${rangeLabel}`} value={metrics.completedInRange || 0} color="#34d399" />
        </section>

        <section style={dashboardCard}>
          <Header title="Workload by Type" />
          <WorkTypeRow
            label="Threat Intelligence Incidents"
            total={metrics.assignedIncidents || 0}
            pending={metrics.pendingIncidents || 0}
            completed={metrics.completedIncidents || 0}
            color="#c084fc"
          />
          <WorkTypeRow
            label="Tickets"
            total={metrics.assignedTickets || 0}
            pending={metrics.pendingTickets || 0}
            completed={metrics.completedTickets || 0}
            color="#60a5fa"
          />
          <SummaryPair label="Critical pending" value={metrics.criticalPending || 0} color="#fb7185" />
          <SummaryPair label="Completed today" value={metrics.completedToday || 0} color="#22c55e" />
          <SummaryPair label="False positives" value={metrics.falsePositives || 0} color="#94a3b8" />
        </section>

        <section style={dashboardCard}>
          <Header title="Shift Coverage" />
          <div style={{ display: 'flex', gap: 10, margin: '14px 0' }}>
            <MiniMetric label="Assigned" value={metrics.activeShifts || 0} color="#60a5fa" />
            <MiniMetric label="Active now" value={metrics.onShiftNow || 0} color="#2dd4bf" />
          </div>
          {shifts.length ? shifts.slice(0, 3).map(shift => (
            <div key={shift._id} style={{ ...dashboardRow, padding: '9px 2px' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: shift.isCurrent ? '#34d399' : '#475569', flexShrink: 0 }} />
              <span style={{ minWidth: 0, flex: 1 }}>
                <b style={{ color: '#e2e8f0', display: 'block' }}>{shift.name}</b>
                <small style={{ color: '#64748b' }}>{shift.companyId?.name || 'Assigned Company'} · {shift.timezone}</small>
              </span>
              <b style={{ color: shift.isCurrent ? '#34d399' : '#94a3b8', fontSize: 11, whiteSpace: 'nowrap' }}>{shift.startTime}–{shift.endTime}</b>
            </div>
          )) : <EmptyState />}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,2fr) minmax(280px,1fr)', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={dashboardCard}>
          <Header title="Complete Status Summary" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))', gap: 10 }}>
            {statusItems.map(([label, value, color]) => (
              <div key={label} style={{ border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 12 }}>
                <small style={{ color: '#94a3b8' }}>{label}</small>
                <div style={{ color, fontWeight: 900, fontSize: 22, marginTop: 5 }}>{value}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={dashboardCard}>
          <Header title="Pending TI Categories" />
          {categoryItems.length ? categoryItems.map(([name, value]) => (
            <SummaryPair key={name} label={humanize(name)} value={value} color="#c084fc" />
          )) : <EmptyState />}
        </section>
      </div>
    </>
  );
}

function WorkTypeRow({ label, total, pending, completed, color }) {
  return (
    <div style={{ border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 12, marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <b style={{ color: '#e2e8f0', fontSize: 12 }}>{label}</b>
        <b style={{ color, fontSize: 16 }}>{total}</b>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, color: '#94a3b8', fontSize: 11 }}>
        <span>Pending <b style={{ color: '#facc15' }}>{pending}</b></span>
        <span>Completed <b style={{ color: '#34d399' }}>{completed}</b></span>
      </div>
    </div>
  );
}

function SummaryPair({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #17243a', fontSize: 12 }}>
      <span style={{ color: '#94a3b8' }}>{label}</span>
      <b style={{ color }}>{value}</b>
    </div>
  );
}

function MiniMetric({ label, value, color }) {
  return (
    <div style={{ flex: 1, border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 10, textAlign: 'center' }}>
      <b style={{ display: 'block', color, fontSize: 22 }}>{value}</b>
      <small style={{ color: '#94a3b8' }}>{label}</small>
    </div>
  );
}

function humanize(value) {
  return String(value || 'Other').replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}

function AlertRows({ items = [], base = '/soc-workspace' }) {
  const tone = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };
  if (!items.length) return <EmptyState />;
  return items.map(a => {
    const id = a.resourceId || a._id;
    const destination = a.resourceType === 'incident'
      ? `${base}/incidents/${id}`
      : a.resourceType === 'ticket' ? `${base}/tickets/${id}` : `${base}/alerts/${id}`;
    return (
      <Link
        to={destination}
        key={`${a.resourceType || 'alert'}:${id}`}
        style={{ ...dashboardRow, textDecoration: 'none', color: '#e2e8f0' }}
      >
        <span style={{ width: 10, height: 10, borderRadius: '50%', background: tone[a.severity] || '#38bdf8', flexShrink: 0 }} />
        <span style={{ minWidth: 0, flex: 1 }}>
          <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {a.title || a.signatureName || a.description || a.ruleId || 'Security alert'}
          </b>
          <small style={{ color: '#64748b', display: 'block', marginTop: 2 }}>
            {a.companyId?.name || 'Assigned Company'} · {a.resourceType === 'incident' ? 'TI Incident' : a.resourceType === 'ticket' ? 'Ticket' : 'Alert'} · {new Date(a.ticketOpenedAt || a.createdAt).toLocaleString()}
          </small>
        </span>
        <span style={{ marginLeft: 'auto', color: tone[a.severity] || '#38bdf8', textTransform: 'uppercase', fontSize: 11, fontWeight: 700 }}>
          {a.severity || 'low'}
        </span>
      </Link>
    );
  });
}

function SeverityBars({ values }) {
  const tone = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };
  const total = Math.max(1, Object.values(values).reduce((a, b) => a + Number(b || 0), 0));
  return ['critical', 'high', 'medium', 'low'].map(k => (
    <div key={k} style={{ margin: '14px 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, textTransform: 'capitalize', color: '#cbd5e1' }}>
        <span>{k}</span>
        <b>{values[k] || 0}</b>
      </div>
      <div style={{ height: 7, background: '#17243a', borderRadius: 6, marginTop: 6 }}>
        <div style={{ height: '100%', width: `${((values[k] || 0) / total) * 100}%`, background: tone[k], borderRadius: 6 }} />
      </div>
    </div>
  ));
}

function Header({ title, to }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e3a5f', paddingBottom: 11, marginBottom: 8 }}>
      <b style={{ color: '#f8fafc', fontSize: 14 }}>{title}</b>
      {to && <Link to={to} style={{ color: '#38bdf8', fontSize: 12, textDecoration: 'none' }}>View all →</Link>}
    </div>
  );
}

function EmptyState() {
  return <div style={{ padding: 24, textAlign: 'center', color: '#64748b', fontSize: 13 }}>No items in analyst's scope.</div>;
}

const dashboardCard = { background: '#0c192c', border: '1px solid #1e3a5f', borderRadius: 12, padding: 16, boxShadow: '0 12px 30px rgba(0,0,0,.18)' };
const dashboardRow = { display: 'flex', alignItems: 'center', gap: 10, padding: '11px 4px', borderBottom: '1px solid #17243a', fontSize: 12 };
