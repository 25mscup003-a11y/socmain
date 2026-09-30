import { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';
import { useAuth } from '../context/AuthContext';

const SEV   = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
const SEVBG = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b' };

const formatIst = value => {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '—';
  return `${new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata', day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
  }).format(date)} IST`;
};

function Badge({ text, color = '#3b82f6', bg }) {
  return (
    <span style={{
      fontSize: 10, padding: '3px 10px', borderRadius: 12, fontWeight: 700,
      background: bg || `${color}22`, color, border: `1px solid ${color}44`
    }}>{text}</span>
  );
}

export default function CorrelationPage() {
  const { user } = useAuth();
  const canChooseCompany = ['superadmin', 'partner_admin'].includes(String(user?.role || '').toLowerCase());
  const [severity, setSeverity] = useState('');
  // Show the complete correlation history by default. A company can have only
  // resolved/rejected matches, in which case defaulting to "open" makes the
  // page incorrectly appear to have no correlation data at all.
  const [status, setStatus] = useState('all');
  const [correlation, setCorrelation] = useState([]);
  const [corrStats, setCorrStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [search, setSearch] = useState('');
  const [sort, setSort] = useState('newest');
  const [page, setPage] = useState(1);
  const [pagination, setPagination] = useState({ total: 0, totalPages: 1 });
  const [selectedId, setSelectedId] = useState('');
  const [error, setError] = useState('');
  const [aiResults, setAiResults] = useState({});
  const [aiBusy, setAiBusy] = useState('');
  const [detailTab, setDetailTab] = useState('overview');
  const [actionBusy, setActionBusy] = useState('');
  const [ruleSetupOpen, setRuleSetupOpen] = useState(false);
  const [companies, setCompanies] = useState([]);
  const [companyId, setCompanyId] = useState('');
  const refreshTimerRef = useRef(null);

  useEffect(() => {
    if (!canChooseCompany && user?.companyId) {
      const ownCompanyId = typeof user.companyId === 'object' ? user.companyId?._id : user.companyId;
      setCompanyId(String(ownCompanyId));
      setCompanies([]);
      return undefined;
    }
    let active = true;
    api.get('/correlation/companies')
      .then(({ data }) => {
        if (!active) return;
        const allowed = data?.companies || [];
        setCompanies(allowed);
        const preferred = allowed.find(company => String(company._id) === String(user?.companyId)) || allowed[0];
        if (preferred) setCompanyId(String(preferred._id));
      })
      .catch(err => {
        if (active) setError(err.response?.data?.message || 'Assigned companies could not be loaded.');
      });
    return () => { active = false; };
  }, [canChooseCompany, user?.companyId]);

  const loadCorrelation = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      if (severity) params.set('severity', severity);
      if (status) params.set('status', status);
      if (search) params.set('search', search);
      if (companyId) params.set('companyId', companyId);
      params.set('sort', sort);
      params.set('page', page);
      params.set('limit', 10);

      const [evRes, stRes] = await Promise.all([
        api.get(`/correlation?${params.toString()}`),
        api.get('/correlation/stats', { params: companyId ? { companyId } : {} }),
      ]);
      setCorrelation(evRes.data?.events || []);
      setPagination({ total: evRes.data?.total || 0, totalPages: evRes.data?.totalPages || 1 });
      setCorrStats(stRes.data);
      setError('');
    } catch (err) {
      console.error('[Company CorrelationPage] load error:', err);
      setError(err.response?.data?.message || 'Correlation data could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [severity, status, search, sort, page, companyId]);

  useEffect(() => {
    loadCorrelation();
  }, [loadCorrelation]);

  useEffect(() => {
    const socket = io(SOCKET_URL);
    const release = connectSocket(socket);
    const refresh = (payload = {}) => {
      if (payload?.change === 'updated') return;
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
      refreshTimerRef.current = setTimeout(() => loadCorrelation(), 1200);
    };
    socket.on('correlation:new', refresh);
    socket.on('correlation:updated', refresh);
    const onAi = job => {
      if (job?.resourceId) setAiResults(current => ({ ...current, [job.resourceId]: job }));
      setAiBusy('');
    };
    socket.on('ai:analysis-completed', onAi);
    socket.on('ai:analysis-failed', onAi);
    return () => {
      if (refreshTimerRef.current) clearTimeout(refreshTimerRef.current);
      socket.off('correlation:new', refresh);
      socket.off('correlation:updated', refresh);
      socket.off('ai:analysis-completed', onAi);
      socket.off('ai:analysis-failed', onAi);
      release();
    };
  }, [loadCorrelation]);

  const triggerEngine = async () => {
    setRunning(true);
    try {
      const res = await api.post('/correlation/run', companyId ? { companyId } : {});
      alert(`⚡ Correlation Engine run complete for ${res.data.companiesProcessed || 1} company. ${res.data.detected || 0} new attack chain(s) identified.`);
      loadCorrelation();
    } catch (err) {
      setError(err.response?.data?.message || 'Correlation engine could not be run.');
    } finally {
      setRunning(false);
    }
  };

  const updateCorrelation = async (ev, payload) => {
    setActionBusy(ev._id);
    try {
      await api.patch(`/correlation/${ev._id}`, { ...payload, ...(companyId ? { companyId } : {}) });
      await loadCorrelation();
    } catch (err) {
      setError(err.response?.data?.message || 'Correlation could not be updated.');
    } finally { setActionBusy(''); }
  };

  const setDisposition = async (ev, verdict) => {
    const reason = window.prompt(`Reason for marking this correlation ${verdict.replace('_', ' ')}:`);
    if (!reason?.trim()) return;
    await updateCorrelation(ev, { verdict, reason });
  };

  const analyzeWithAi = async (ev, clickEvent) => {
    clickEvent.stopPropagation();
    setAiBusy(ev._id);
    try {
      const { data } = await api.post(`/ai/correlation/${ev._id}/analyze`, companyId ? { companyId } : {});
      setAiResults(current => ({ ...current, [ev._id]: data.job }));
      if (data.job?.status !== 'completed') {
        window.setTimeout(async () => {
          try {
            const latest = await api.get(`/ai/correlation/${ev._id}/latest`, { params: companyId ? { companyId } : {} });
            setAiResults(current => ({ ...current, [ev._id]: latest.data }));
          } catch { /* real-time socket remains the primary completion path */ }
          setAiBusy('');
        }, 2500);
      } else setAiBusy('');
    } catch (err) {
      setAiResults(current => ({ ...current, [ev._id]: { status: 'failed', error: err.response?.data?.message || 'AI analysis failed' } }));
      setAiBusy('');
    }
  };

  return (
    <div style={{ maxWidth: 1350, margin: '0 auto' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24, paddingBottom: 16, borderBottom: '1px solid #1e3a5f' }}>
        <div>
          <h2 style={{ fontSize: 24, fontWeight: 700, color: '#e0f2fe', margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>🔗</span> Attack Chain & Event Correlation
          </h2>
          <p style={{ fontSize: 13, color: '#60a5fa', marginTop: 6, marginBottom: 0 }}>
            Automated multi-step threat correlation engine and incident pattern analysis
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
        {canChooseCompany && (
          <select value={companyId} onChange={event => { setCompanyId(event.target.value); setPage(1); }} style={{
            minWidth: 190, background: '#071426', color: '#dbeafe', border: '1px solid #315377',
            padding: '8px 11px', borderRadius: 8, fontSize: 12,
          }}>
            {!companies.length && <option value="">No assigned company</option>}
            {companies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}
          </select>
        )}
        <button disabled={!companyId} onClick={() => setRuleSetupOpen(true)} title={!companyId ? 'Select an assigned company first' : ''} style={{
          background: 'linear-gradient(135deg, #7c3aed, #5b21b6)', color: '#fff',
          border: '1px solid #8b5cf6', padding: '8px 16px', borderRadius: 8,
          fontSize: 13, fontWeight: 700, cursor: companyId ? 'pointer' : 'not-allowed', opacity: companyId ? 1 : .55,
        }}>⚙ Correlation Rule Setup</button>
        <button onClick={loadCorrelation} style={{
          background: 'rgba(96, 165, 250, 0.12)',
          color: '#60a5fa',
          border: '1px solid rgba(96, 165, 250, 0.3)',
          padding: '8px 16px',
          borderRadius: 8,
          fontSize: 13,
          fontWeight: 600,
          cursor: 'pointer'
        }}>
          🔄 Refresh
        </button>
        </div>
      </div>

      {ruleSetupOpen && companyId && <RuleSetup companyId={companyId} onClose={() => setRuleSetupOpen(false)} onChanged={loadCorrelation} />}

      {/* Metrics Banner Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16, marginBottom: 24 }}>
        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 18 }}>
          <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: 0.5 }}>Security Signals Analysed (24h)</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#60a5fa', marginTop: 6 }}>{corrStats?.eventsAnalyzed24h ?? 0}</div>
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>{corrStats?.lastEventAt ? `Last log ${formatIst(corrStats.lastEventAt)}` : 'No telemetry received'}</div>
        </div>

        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 18 }}>
          <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: 0.5 }}>Open Correlation Chains</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: (corrStats?.active ?? 0) > 0 ? '#60a5fa' : '#34d399', marginTop: 6 }}>{corrStats?.active ?? 0}</div>
          <div style={{ fontSize: 11, color: (corrStats?.openCritical ?? 0) > 0 ? '#f87171' : '#94a3b8', marginTop: 4 }}>
            {(corrStats?.openCritical ?? 0) > 0
              ? `${corrStats.openCritical} critical chain${corrStats.openCritical === 1 ? '' : 's'} need immediate review`
              : `${corrStats?.active ?? 0} active chain${(corrStats?.active ?? 0) === 1 ? '' : 's'} awaiting analyst review`}
          </div>
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginTop: 9, fontSize: 10, fontWeight: 700 }}>
            <span style={{ color: '#34d399' }}>LOW {(corrStats?.bySeverity || []).find(item => item._id === 'low')?.count || 0}</span>
            <span style={{ color: '#60a5fa' }}>MEDIUM {(corrStats?.bySeverity || []).find(item => item._id === 'medium')?.count || 0}</span>
            <span style={{ color: '#f59e0b' }}>HIGH {(corrStats?.bySeverity || []).find(item => item._id === 'high')?.count || 0}</span>
            <span style={{ color: '#f87171' }}>CRITICAL {corrStats?.openCritical ?? 0}</span>
          </div>
        </div>

        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 18 }}>
          <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, letterSpacing: 0.5 }}>Active Patterns</div>
          <div style={{ fontSize: 28, fontWeight: 700, color: '#a78bfa', marginTop: 6 }}>{corrStats?.ruleCount ?? (corrStats?.byPattern || []).length}</div>
          <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
            EDR coverage: {corrStats?.edrCapabilityCoverage ?? 0}/{corrStats?.edrCapabilityTotal ?? 31} capabilities
          </div>
        </div>

        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 18, display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <button onClick={triggerEngine} disabled={running || !companyId} style={{
            background: 'linear-gradient(135deg, #1d4ed8 0%, #1e40af 100%)',
            color: '#fff',
            border: 'none',
            padding: '12px 18px',
            borderRadius: 8,
            fontSize: 13,
            fontWeight: 700,
            cursor: 'pointer'
          }}>
            {running ? '⟳ Running Engine...' : '⚡ Trigger Correlation Engine'}
          </button>
        </div>
      </div>

      {/* Control & Filtering Bar */}
      <div style={{
        background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
        padding: '14px 20px', marginBottom: 24, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12
      }}>
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#e0f2fe', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span>🛡️</span> Correlation Matches <span style={{ color: '#60a5fa', fontSize: 12 }}>({pagination.total})</span>
        </h3>

        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          <input value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} placeholder="Search incident, pattern, endpoint"
            style={{ width: 230, fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f', background: '#060e1a', color: '#e2e8f0' }} />
          <select value={severity} onChange={e => setSeverity(e.target.value)}
            style={{ fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f', background: '#060e1a', color: '#e2e8f0' }}>
            <option value="">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select value={status} onChange={e => setStatus(e.target.value)}
            style={{ fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f', background: '#060e1a', color: '#e2e8f0' }}>
            <option value="all">All Statuses</option>
            <option value="open">Open</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
            <option value="benign">Benign</option>
          </select>
          <select value={sort} onChange={e => { setSort(e.target.value); setPage(1); }}
            style={{ fontSize: 12, padding: '6px 12px', borderRadius: 6, border: '1px solid #1e3a5f', background: '#060e1a', color: '#e2e8f0' }}>
            <option value="newest">Latest activity</option><option value="risk">Highest risk</option>
          </select>
        </div>
      </div>
      {error && <div style={{ color: '#fecaca', background: '#450a0a', border: '1px solid #991b1b', padding: 12, borderRadius: 8, marginBottom: 14 }}>{error}</div>}

      {/* Correlation Event Cards List */}
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 20 }}>
        {loading ? (
          <div style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>Loading correlation attack chains...</div>
        ) : correlation.length === 0 ? (
          <div style={{ padding: 50, textAlign: 'center' }}>
            <div style={{ fontSize: 42, marginBottom: 12 }}>🔗</div>
            <div style={{ fontSize: 16, color: '#e0f2fe', fontWeight: 600 }}>No correlation records match the selected filters</div>
            <div style={{ fontSize: 13, color: '#64748b', marginTop: 6 }}>
              {(corrStats?.eventsAnalyzed24h ?? 0).toLocaleString()} correlation-eligible security signals were analysed in the last 24 hours; none formed a verified attack chain.
            </div>
          </div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {correlation.map(ev => (
              <div key={ev._id} onClick={() => { setSelectedId(id => id === ev._id ? '' : ev._id); setDetailTab('overview'); }} style={{
                background: '#060e1a',
                border: `1px solid ${ev.status === 'false_positive' ? '#475569' : (SEV[ev.severity] || '#1e3a5f')}`,
                borderRadius: 10,
                padding: 20, cursor: 'pointer'
              }}>
                <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', alignItems: 'start', gap: '16px 28px' }}>
                  <div style={{ minWidth: 0 }}>
                    <div style={{ fontSize: 16, fontWeight: 700, color: '#e0f2fe', display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span>{ev.status === 'false_positive' ? '⊘' : '⚠️'}</span>
                      {ev.status === 'false_positive'
                        ? 'Rejected Correlation Match'
                        : (ev.patternName || 'Multi-Step Attack Pattern')}
                      {ev.status === 'false_positive' && <Badge text="REJECTED MATCH" color="#94a3b8" />}
                    </div>
                    <div style={{ fontSize: 13, color: '#94a3b8', marginTop: 6, lineHeight: 1.5 }}>
                      {ev.status === 'false_positive'
                        ? 'Historical correlation candidate rejected — available evidence did not verify an attack chain.'
                        : (ev.description || 'Automated multi-event correlation rule trigger')}
                    </div>
                    <div style={{ display: 'flex', gap: '8px 20px', fontSize: 12, color: '#64748b', marginTop: 12, flexWrap: 'wrap', alignItems: 'center' }}>
                      <span style={{ whiteSpace: 'nowrap' }}>Target Host/Agent: <strong style={{ color: '#e0f2fe' }}>{ev.agentName || 'System'}</strong></span>
                      <span style={{ whiteSpace: 'nowrap' }}>Incident: <strong style={{ color: '#c4b5fd' }}>{ev.incidentId || String(ev._id).slice(-8)}</strong></span>
                      {ev.status === 'false_positive'
                        ? <span>Assessment: <strong style={{ color: '#94a3b8' }}>Not a verified threat</strong></span>
                        : <>
                          <span>Confidence Score: <strong style={{ color: '#34d399' }}>{ev.confidence || 85}%</strong></span>
                          <span>Risk: <strong style={{ color: SEV[ev.severity] }}>{ev.riskScore ?? ev.confidence ?? 0}/100</strong></span>
                        </>}
                      <span style={{ whiteSpace: 'nowrap' }}>Occurrences: <strong style={{ color: '#22d3ee' }}>{ev.occurrenceCount || 1}</strong></span>
                      {ev.status !== 'false_positive' && <span style={{ whiteSpace: 'nowrap' }}>Pattern Code: <code style={{ color: '#f59e0b', background: '#1e3a5f', padding: '3px 7px', borderRadius: 4 }}>{ev.patternId || 'ATTACK-CHAIN-01'}</code></span>}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 10, minWidth: 230 }}>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap' }}>
                      {ev.status === 'false_positive'
                        ? <Badge text="NOT A THREAT" color="#94a3b8" bg="#1e293b" />
                        : <Badge text={ev.severity?.toUpperCase()} color={SEV[ev.severity]} bg={SEVBG[ev.severity]} />}
                      <Badge text={ev.status?.toUpperCase()} color="#60a5fa" />
                    </div>
                    <span style={{ fontSize: 11, color: '#94a3b8', whiteSpace: 'nowrap' }}>
                      Last activity: {formatIst(ev.lastActivityAt || ev.createdAt)}
                    </span>
                  </div>
                </div>

                {/* Linked Alerts Details */}
                {ev.alertIds && ev.alertIds.length > 0 && (
                  <div style={{ marginTop: 16, paddingTop: 14, borderTop: '1px solid #1e3a5f' }}>
                    <div style={{ fontSize: 11, color: '#64748b', textTransform: 'uppercase', fontWeight: 600, marginBottom: 8 }}>
                      {ev.status === 'false_positive' ? 'Rejected Candidate Evidence' : 'Latest Verified Evidence'} ({ev.alertIds.length})
                    </div>
                    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                      {ev.alertIds.slice(0, 20).map((alertItem, idx) => (
                        <div key={idx} style={{
                          background: '#0c1a2e', border: '1px solid #1e3a5f', padding: '6px 12px',
                          borderRadius: 6, fontSize: 12, color: '#94a3b8', display: 'flex', alignItems: 'center', gap: 6
                        }}>
                          <span style={{ color: SEV[alertItem.severity] || '#60a5fa' }}>●</span>
                          <span>{alertItem.description || `Alert #${idx + 1}`}</span>
                        </div>
                      ))}
                      {ev.alertIds.length > 20 && <div style={{ color: '#64748b', fontSize: 12 }}>Only the first 20 evidence events are displayed.</div>}
                    </div>
                  </div>
                )}
                {selectedId === ev._id && <div onClick={e => e.stopPropagation()} style={{ marginTop: 14, padding: 14, borderRadius: 8, background: '#030a13', border: '1px solid #1e3a5f' }}>
                  <button onClick={clickEvent => analyzeWithAi(ev, clickEvent)} disabled={aiBusy === ev._id}
                    style={{ float: 'right', border: '1px solid #7c3aed', background: 'rgba(124,58,237,.18)', color: '#ddd6fe', borderRadius: 7, padding: '7px 11px', cursor: 'pointer', fontWeight: 800 }}>
                    {aiBusy === ev._id ? 'AI analysing…' : '✦ AI Analyse Incident'}
                  </button>
                  <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', clear: 'both', paddingTop: 12, marginBottom: 14 }}>
                    {['overview','evidence','timeline','entities','mitre','audit'].map(tab => <button key={tab} onClick={() => setDetailTab(tab)} style={{ background: detailTab === tab ? '#1d4ed8' : '#0c1a2e', color: '#dbeafe', border: '1px solid #1e40af', borderRadius: 6, padding: '6px 9px', cursor: 'pointer', textTransform: 'capitalize' }}>{tab}</button>)}
                  </div>
                  {detailTab === 'overview' && <div style={{ color: '#cbd5e1', fontSize: 12, lineHeight: 1.6 }}>
                    <b style={{ color: '#e0f2fe' }}>What happened?</b><div>{ev.description}</div>
                    <b style={{ color: '#e0f2fe' }}>Why correlated?</b><div>{ev.eventCount || ev.alertIds?.length || 0} matching events on {ev.agentName || 'the affected asset'} satisfied rule {ev.patternName} between {formatIst(ev.windowStart || ev.createdAt)} and {formatIst(ev.windowEnd || ev.lastActivityAt)}.</div>
                    <div style={{ marginTop: 10 }}>Disposition: <b>{ev.verdict || 'undetermined'}</b>{ev.dispositionReason ? ` — ${ev.dispositionReason}` : ''}</div>
                  </div>}
                  {detailTab === 'evidence' && (ev.alertIds || []).map((item, idx) => <div key={item._id || idx} style={{ borderBottom: '1px solid #172554', padding: 8, color: '#cbd5e1', fontSize: 12 }}><b>{formatIst(item.createdAt)}</b> · {item.source || item.eventCategory} · {item.description}</div>)}
                  {detailTab === 'timeline' && (ev.timeline || []).map((item, idx) => <div key={`${item.alertId}-${idx}`} style={{ borderLeft: '2px solid #2563eb', padding: '3px 0 9px 10px', color: '#94a3b8', fontSize: 11 }}><b style={{ color: '#e2e8f0' }}>{formatIst(item.timestamp)}</b> · {item.category} · {item.description}</div>)}
                  {detailTab === 'entities' && <div style={{ color: '#cbd5e1', fontSize: 12 }}>Asset/agent: <b>{ev.agentName || 'Unknown'}</b><br />IOCs: {(ev.iocs || []).join(' · ') || 'None extracted'}</div>}
                  {detailTab === 'mitre' && <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>{(ev.mitreTechniques || []).map(x => <Badge key={x} text={x} color="#c084fc" />)} {(ev.mitreTactics || []).map(x => <Badge key={x} text={x} color="#60a5fa" />)}</div>}
                  {detailTab === 'audit' && <div>{(ev.resolutionHistory || []).length ? ev.resolutionHistory.map((entry, idx) => <div key={idx} style={{ color: '#94a3b8', fontSize: 11, padding: 6 }}>{formatIst(entry.changedAt)} · {entry.status} · {entry.notes || 'No note'}</div>) : <span style={{ color: '#64748b' }}>No analyst actions recorded.</span>}</div>}
                  <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginTop: 16, borderTop: '1px solid #1e3a5f', paddingTop: 12 }}>
                    <button disabled={actionBusy === ev._id} onClick={() => updateCorrelation(ev, { status: 'investigating' })}>Investigate</button>
                    <button disabled={actionBusy === ev._id} onClick={() => setDisposition(ev, 'true_positive')}>True positive</button>
                    <button disabled={actionBusy === ev._id} onClick={() => setDisposition(ev, 'false_positive')}>False positive</button>
                    <button disabled={actionBusy === ev._id} onClick={() => setDisposition(ev, 'benign')}>Benign</button>
                    <button disabled={actionBusy === ev._id} onClick={() => updateCorrelation(ev, { status: 'resolved' })}>Resolve</button>
                  </div>
                  {(ev.suppressedDuplicateCount || 0) > 0 && <div style={{ color: '#64748b', fontSize: 10, marginTop: 7 }}>{ev.suppressedDuplicateCount} duplicate/overflow event references suppressed.</div>}
                  {aiResults[ev._id] && <AiResult job={aiResults[ev._id]} />}
                </div>}
              </div>
            ))}
          </div>
        )}
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 14, color: '#64748b', fontSize: 12 }}>
        <span>{pagination.total} correlation matches · Page {page} of {pagination.totalPages}</span>
        <div style={{ display: 'flex', gap: 8 }}>
          <button disabled={page <= 1} onClick={() => setPage(p => Math.max(1, p - 1))}>← Previous</button>
          <button disabled={page >= pagination.totalPages} onClick={() => setPage(p => p + 1)}>Next →</button>
        </div>
      </div>
    </div>
  );
}

const FIELD_OPTIONS = ['eventCategory', 'eventType', 'normalizedEventType', 'source', 'sourceType', 'module', 'ruleId', 'severity', 'userAction', 'srcip', 'destip', 'domain', 'processName', 'username', 'hostname', 'agentId', 'endpointId', 'actionable', 'blocked', 'action', 'actionTaken', 'iocMatched', 'vtVerdict', 'capabilityId', 'riskScore', 'confidenceScore'];
const FIELD_VALUES = {
  eventCategory: ['malware', 'network', 'file', 'system', 'registry', 'memory', 'systemchanges', 'persistence', 'edr', 'usb', 'isolation', 'other'],
  severity: ['low', 'medium', 'high', 'critical'],
  source: ['edr', 'suricata', 'zeek', 'ips', 'firewall', 'iam', 'threat_feed'],
  sourceType: ['IAM', 'IDS', 'IPS', 'ZEEK', 'THREAT_FEED'],
  module: ['EDR', 'IDS', 'IPS', 'FIREWALL', 'IAM'],
  actionable: ['true', 'false'],
  blocked: ['true', 'false'],
  iocMatched: ['true', 'false'],
  action: ['detected', 'allowed', 'blocked', 'dropped', 'rejected', 'quarantined'],
  actionTaken: ['Blocked', 'Allowed', 'Quarantined', 'Deleted', 'None'],
  vtVerdict: ['malicious', 'suspicious', 'clean', 'not_found'],
};
const inputStyle = { width: '100%', boxSizing: 'border-box', background: '#071426', color: '#e2e8f0', border: '1px solid #29466b', borderRadius: 7, padding: '9px 10px' };
const ruleSeverityFromRisk = score => Number(score) >= 90 ? 'critical' : Number(score) >= 75 ? 'high' : Number(score) >= 65 ? 'medium' : 'low';
const customRuleId = rule => String(rule?.name || 'CUSTOM_RULE')
  .trim().toUpperCase().replace(/[^A-Z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 48) || 'CUSTOM_RULE';
const formatRuleWindow = seconds => Number(seconds) >= 3600
  ? `${Number(seconds) / 3600} hour${Number(seconds) === 3600 ? '' : 's'}`
  : `${Math.max(1, Math.round(Number(seconds || 60) / 60))} min`;
const customRuleEdrPoints = rule => (rule?.conditions || [])
  .filter(condition => condition.field === 'capabilityId' && condition.operator === 'equals' && condition.value !== '')
  .map(condition => String(condition.value));
const RULE_PRESETS = [
  { id: 'edr', label: 'EDR', help: 'All 31 EDR capabilities: process, file/FIM, memory, registry, authentication, malware, persistence, USB, system, network, scripts, services and behavioral detections.', field: 'capabilityId', operator: 'exists', value: '' },
  { id: 'ids', label: 'IDS', help: 'All IDS detections: Suricata, Snort and Zeek signatures, scans, exploits, C2, malware traffic, DNS anomalies and reconnaissance.', field: 'module', operator: 'equals', value: 'IDS' },
  { id: 'ips', label: 'IPS', help: 'All IPS outcomes: allowed, blocked, dropped, rejected, quarantined, automatic blocks, manual blocks and SOAR prevention.', field: 'sourceType', operator: 'equals', value: 'IPS' },
  { id: 'firewall', label: 'Firewall', help: 'All endpoint-firewall actions: IP/domain/application/protocol blocks, closed ports and applied prevention rules.', field: 'source', operator: 'equals', value: 'firewall' },
];
const DETECTION_CATEGORIES = {
  edr: [
    ['all', 'All EDR capabilities', 'capabilityId', 'exists', ''],
    ...['Process activity','File activity / FIM','Network activity','User & authentication','Memory activity','Registry monitoring','System changes','Persistence','Web & DNS','USB devices','Behavior analytics','Data security','Credential security','Lateral movement','Email threats','Insider threats','Patch & vulnerability','Sandbox analysis','Kernel monitoring','API calls','Script execution','Time anomaly','Geolocation anomaly','Service monitoring','Hash/signature analysis','Beaconing','Encryption / ransomware','Living-off-the-Land','Memory overflow','DNS cache poisoning','DNS sinkhole'].map((label, index) => [String(index + 1), label, 'capabilityId', 'equals', String(index + 1)]),
  ],
  ids: [
    ['all', 'All IDS detections', 'module', 'equals', 'IDS'],
    ['suricata', 'Suricata alerts', 'source', 'equals', 'suricata'],
    ['zeek', 'Zeek network detections', 'source', 'equals', 'zeek'],
    ['scan', 'Port scan / reconnaissance', 'normalizedEventType', 'contains', 'scan'],
    ['exploit', 'Exploit attempts', 'normalizedEventType', 'contains', 'exploit'],
    ['c2', 'C2 / beaconing', 'normalizedEventType', 'contains', 'c2'],
  ],
  ips: [
    ['all', 'All IPS activity', 'sourceType', 'equals', 'IPS'],
    ['blocked', 'Blocked', 'action', 'equals', 'blocked'],
    ['dropped', 'Dropped', 'action', 'equals', 'dropped'],
    ['rejected', 'Rejected', 'action', 'equals', 'rejected'],
    ['allowed', 'Allowed / prevention failed', 'action', 'equals', 'allowed'],
    ['quarantined', 'Quarantined', 'action', 'equals', 'quarantined'],
  ],
  firewall: [
    ['all', 'All firewall activity', 'source', 'equals', 'firewall'],
    ['ip', 'IP block', 'ruleId', 'contains', 'FIREWALL_BLOCK_IP'],
    ['domain', 'Domain block', 'ruleId', 'contains', 'FIREWALL_BLOCK_DOMAIN'],
    ['port', 'Port closed', 'ruleId', 'contains', 'FIREWALL_CLOSE_PORT'],
    ['protocol', 'Protocol block', 'ruleId', 'contains', 'FIREWALL_BLOCK_PROTOCOL'],
    ['application', 'Application block', 'ruleId', 'contains', 'FIREWALL_BLOCK_APP'],
  ],
};

function RuleSetup({ companyId, onClose, onChanged }) {
  const { user } = useAuth();
  const isDepartmentAdmin = user?.role === 'department_admin';
  const assignedDepartmentId = String(user?.departmentId?._id || user?.departmentId || '');
  const [rules, setRules] = useState([]);
  const [builtInRules, setBuiltInRules] = useState([]);
  const [departments, setDepartments] = useState([]);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState('');
  const [editingRule, setEditingRule] = useState(null);
  const [editingBuiltIn, setEditingBuiltIn] = useState(null);
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [presetId, setPresetId] = useState('edr');
  const [form, setForm] = useState({ name: '', description: '', departmentId: isDepartmentAdmin ? assignedDepartmentId : '', riskScoreMin: 60, riskScoreMax: 70, threshold: 2, timeWindowSeconds: 300, field: 'capabilityId', operator: 'exists', value: '' });
  const visibleDepartments = isDepartmentAdmin
    ? departments.filter(department => String(department._id) === assignedDepartmentId)
    : departments;
  const selectedDetectionCategory = (DETECTION_CATEGORIES[presetId] || []).find(item => (
    item[2] === form.field
    && item[3] === form.operator
    && String(item[4] ?? '') === String(form.value ?? '')
  ))?.[0] || 'all';

  const resetForm = () => {
    setEditingRule(null);
    setPresetId('edr');
    setForm({ name: '', description: '', departmentId: isDepartmentAdmin ? assignedDepartmentId : '', riskScoreMin: 60, riskScoreMax: 70, threshold: 2, timeWindowSeconds: 300, field: 'capabilityId', operator: 'exists', value: '' });
  };

  const loadRules = useCallback(async () => {
    try {
      const [{ data }, departmentsRes] = await Promise.all([
        api.get('/correlation/rules', { params: { companyId } }),
        api.get('/department', { params: { companyId } }),
      ]);
      setRules(data.rules || []); setBuiltInRules(data.builtInRules || []);
      setDepartments(Array.isArray(departmentsRes.data) ? departmentsRes.data : (departmentsRes.data?.departments || []));
    }
    catch (err) { setMessage(err.response?.data?.message || 'Rules could not be loaded.'); }
  }, [companyId]);
  useEffect(() => { loadRules(); }, [loadRules]);

  const saveRule = async e => {
    e.preventDefault(); setBusy(true); setMessage('');
    if (Number(form.riskScoreMin) > Number(form.riskScoreMax)) {
      setMessage('Start score must be less than or equal to End score.');
      setBusy(false);
      return;
    }
    try {
      const condition = {
        field: form.field, operator: form.operator,
        value: ['riskScore', 'confidenceScore'].includes(form.field) ? Number(form.value)
          : ['actionable', 'blocked', 'iocMatched'].includes(form.field) ? form.value === 'true' : form.value,
      };
      const payload = {
        name: form.name.trim(), description: form.description.trim(), severity: ruleSeverityFromRisk(form.riskScoreMax),
        companyId, departmentId: form.departmentId || null,
        riskScoreMin: Number(form.riskScoreMin), riskScoreMax: Number(form.riskScoreMax), threshold: Number(form.threshold),
        timeWindowSeconds: Number(form.timeWindowSeconds), logic: 'AND', entityFields: ['endpointId', 'agentId', 'systemId'],
        conditions: editingRule ? [condition, ...(editingRule.conditions || []).slice(1)] : [condition],
      };
      if (editingRule) await api.patch(`/correlation/rules/${editingRule._id}`, payload, { params: { companyId } });
      else await api.post('/correlation/rules', payload);
      setMessage(editingRule ? 'Correlation rule updated successfully.' : 'Correlation rule created successfully.');
      resetForm(); await loadRules(); await onChanged();
    } catch (err) { setMessage(err.response?.data?.message || `Rule could not be ${editingRule ? 'updated' : 'created'}.`); }
    finally { setBusy(false); }
  };

  const editRule = rule => {
    const condition = rule.conditions?.[0] || { field: 'capabilityId', operator: 'exists', value: '' };
    let selection = null;
    for (const [preset, categories] of Object.entries(DETECTION_CATEGORIES)) {
      const category = categories.find(item => item[2] === condition.field
        && item[3] === condition.operator && String(item[4] ?? '') === String(condition.value ?? ''));
      if (category) { selection = { preset, category: category[0] }; break; }
    }
    setEditingRule(rule);
    setPresetId(selection?.preset || (condition.field === 'capabilityId' ? 'edr' : 'edr'));
    setForm({
      name: rule.name || '', description: rule.description || '',
      departmentId: String(rule.departmentId?._id || rule.departmentId || ''),
      riskScoreMin: rule.riskScoreMin ?? rule.riskScore ?? 60,
      riskScoreMax: rule.riskScoreMax ?? rule.riskScore ?? 70,
      threshold: rule.threshold ?? 1, timeWindowSeconds: rule.timeWindowSeconds ?? 300,
      field: condition.field || 'capabilityId', operator: condition.operator || 'exists', value: condition.value ?? '',
    });
    setMessage(`Editing “${rule.name}”`);
  };

  const deleteRule = async rule => {
    setBusy(true); setMessage('');
    try {
      await api.delete(`/correlation/rules/${rule._id}`, { params: { companyId } });
      if (editingRule?._id === rule._id) resetForm();
      setDeleteTarget(null);
      setMessage('Correlation rule deleted successfully.');
      await loadRules(); await onChanged();
    } catch (err) { setMessage(err.response?.data?.message || 'Rule could not be deleted.'); }
    finally { setBusy(false); }
  };

  const beginBuiltInEdit = rule => {
    setEditingBuiltIn({
      id: rule.id, name: rule.name || '', description: rule.description || '',
      severity: rule.severity || 'high', confidence: rule.confidence ?? 75,
      riskScoreMin: rule.riskScoreMin ?? rule.riskScore ?? 60,
      riskScoreMax: rule.riskScoreMax ?? rule.riskScore ?? 70,
      timeWindowSeconds: rule.timeWindowSeconds ?? 3600,
      enabled: rule.enabled !== false,
    });
    setMessage(`Editing built-in rule “${rule.name}” for this company.`);
  };

  const saveBuiltIn = async event => {
    event.preventDefault();
    if (!editingBuiltIn) return;
    if (Number(editingBuiltIn.riskScoreMin) > Number(editingBuiltIn.riskScoreMax)) {
      setMessage('Start score must be less than or equal to End score.');
      return;
    }
    setBusy(true); setMessage('');
    try {
      await api.patch(`/correlation/rules/built-in/${editingBuiltIn.id}`, {
        name: editingBuiltIn.name.trim(), description: editingBuiltIn.description.trim(),
        enabled: editingBuiltIn.enabled, severity: editingBuiltIn.severity,
        confidence: Number(editingBuiltIn.confidence),
        riskScoreMin: Number(editingBuiltIn.riskScoreMin), riskScoreMax: Number(editingBuiltIn.riskScoreMax),
        timeWindowSeconds: Number(editingBuiltIn.timeWindowSeconds), companyId,
      }, { params: { companyId } });
      setEditingBuiltIn(null);
      setMessage('Built-in rule updated for this company.');
      await loadRules(); await onChanged();
    } catch (err) { setMessage(err.response?.data?.message || 'Built-in rule could not be updated.'); }
    finally { setBusy(false); }
  };

  const toggleBuiltIn = async rule => {
    setBusy(true); setMessage('');
    try {
      await api.patch(`/correlation/rules/built-in/${rule.id}`, {
        enabled: rule.enabled === false,
        name: rule.name, description: rule.description, severity: rule.severity,
        confidence: rule.confidence, riskScoreMin: rule.riskScoreMin ?? rule.riskScore ?? 60,
        riskScoreMax: rule.riskScoreMax ?? rule.riskScore ?? 70,
        timeWindowSeconds: rule.timeWindowSeconds, companyId,
      }, { params: { companyId } });
      setMessage(`Built-in rule ${rule.enabled === false ? 'enabled' : 'disabled'} for this company.`);
      await loadRules(); await onChanged();
    } catch (err) { setMessage(err.response?.data?.message || 'Built-in rule could not be updated.'); }
    finally { setBusy(false); }
  };

  const resetBuiltIn = async rule => {
    if (!window.confirm(`Restore “${rule.name}” to production defaults?`)) return;
    setBusy(true); setMessage('');
    try {
      await api.delete(`/correlation/rules/built-in/${rule.id}`, { params: { companyId } });
      if (editingBuiltIn?.id === rule.id) setEditingBuiltIn(null);
      setMessage('Built-in rule restored to production defaults.');
      await loadRules(); await onChanged();
    } catch (err) { setMessage(err.response?.data?.message || 'Built-in rule could not be reset.'); }
    finally { setBusy(false); }
  };

  const toggleRule = async rule => {
    setBusy(true); setMessage('');
    try { await api.patch(`/correlation/rules/${rule._id}`, { enabled: !rule.enabled, companyId }, { params: { companyId } }); await loadRules(); await onChanged(); }
    catch (err) { setMessage(err.response?.data?.message || 'Rule could not be updated.'); }
    finally { setBusy(false); }
  };

  return <div onClick={onClose} style={{ position: 'fixed', inset: 0, zIndex: 1000, background: 'rgba(2,6,23,.82)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
    {deleteTarget && <div onClick={event => { event.stopPropagation(); if (!busy) setDeleteTarget(null); }} style={{ position: 'fixed', inset: 0, zIndex: 1100, background: 'rgba(2,6,23,.86)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20 }}>
      <div role="dialog" aria-modal="true" aria-labelledby="delete-correlation-rule-title" onClick={event => event.stopPropagation()} style={{ width: 'min(470px, 94vw)', background: '#0b192c', border: '1px solid #ef444466', borderRadius: 12, padding: 22, boxShadow: '0 24px 70px #000' }}>
        <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
          <div style={{ width: 38, height: 38, flex: '0 0 38px', borderRadius: 10, display: 'grid', placeItems: 'center', background: '#7f1d1d55', border: '1px solid #ef444466', fontSize: 18 }}>⚠</div>
          <div>
            <h3 id="delete-correlation-rule-title" style={{ color: '#fee2e2', margin: '1px 0 7px', fontSize: 17 }}>Delete correlation rule?</h3>
            <div style={{ color: '#cbd5e1', fontSize: 13, lineHeight: 1.55 }}>You are about to delete <b style={{ color: '#fff' }}>“{deleteTarget.name}”</b>. This rule will stop detecting new matching activity.</div>
          </div>
        </div>
        <div style={{ margin: '16px 0', padding: 11, borderRadius: 8, background: '#111f33', border: '1px solid #2b405e', color: '#94a3b8', fontSize: 12 }}>Existing incidents and correlation history will remain preserved and will not be deleted.</div>
        <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 9 }}>
          <button type="button" disabled={busy} onClick={() => setDeleteTarget(null)} style={{ background: '#172a44', color: '#cbd5e1', border: '1px solid #40597a', borderRadius: 7, padding: '9px 14px', cursor: 'pointer' }}>Cancel</button>
          <button type="button" disabled={busy} onClick={() => deleteRule(deleteTarget)} style={{ background: '#dc2626', color: '#fff', border: '1px solid #ef4444', borderRadius: 7, padding: '9px 14px', fontWeight: 800, cursor: 'pointer' }}>{busy ? 'Deleting…' : '🗑 Delete Rule'}</button>
        </div>
      </div>
    </div>}
    <div onClick={e => e.stopPropagation()} style={{ width: 'min(1050px, 96vw)', maxHeight: '90vh', overflowY: 'auto', background: '#0b192c', border: '1px solid #334e75', borderRadius: 12, padding: 22, boxShadow: '0 24px 70px #000' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 18 }}>
        <div><h3 style={{ color: '#e0f2fe', margin: 0 }}>⚙ Correlation Rule Setup</h3><div style={{ color: '#7890ad', fontSize: 12, marginTop: 5 }}>Create company-wide or department-specific threshold and time-window rules.</div></div>
        <button onClick={onClose} style={{ background: '#172a44', color: '#cbd5e1', border: '1px solid #40597a', borderRadius: 7, padding: '7px 11px', cursor: 'pointer' }}>✕ Close</button>
      </div>
      {message && <div style={{ background: '#132944', color: '#93c5fd', border: '1px solid #24578c', padding: 10, borderRadius: 7, marginBottom: 14 }}>{message}</div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 360px), 1fr))', gap: 20 }}>
        <form onSubmit={saveRule} style={{ background: '#071426', border: `1px solid ${editingRule ? '#7c3aed' : '#213b5d'}`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10, marginBottom: 14 }}>
            <h4 style={{ color: '#c4b5fd', margin: 0 }}>{editingRule ? 'Edit Custom Rule' : 'Create New Rule'}</h4>
            {editingRule && <button type="button" disabled={busy} onClick={resetForm} style={{ background: '#172a44', color: '#cbd5e1', border: '1px solid #40597a', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>Cancel Edit</button>}
          </div>
          <div style={{ display: 'grid', gap: 11 }}>
            <label style={{ color: '#94a3b8', fontSize: 11 }}>Rule name<input required maxLength={200} placeholder="Example: Repeated Firewall Blocks" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} style={{ ...inputStyle, marginTop: 5 }} /></label>
            <label style={{ color: '#94a3b8', fontSize: 11 }}>Description<textarea maxLength={2000} placeholder="What security behavior should this rule identify?" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} style={{ ...inputStyle, minHeight: 70, marginTop: 5 }} /></label>
            <label style={{ color: '#94a3b8', fontSize: 11 }}>Department
              <select required={isDepartmentAdmin} disabled={isDepartmentAdmin} value={form.departmentId} onChange={e => setForm({ ...form, departmentId: e.target.value })} style={{ ...inputStyle, marginTop: 5 }}>
                {!isDepartmentAdmin && <option value="">All Departments</option>}
                {visibleDepartments.map(department => <option key={department._id} value={department._id}>{department.name}</option>)}
              </select>
              <span style={{ display: 'block', color: '#64748b', fontSize: 10, marginTop: 5 }}>{isDepartmentAdmin ? 'Rules are restricted to your assigned department.' : 'Select one department, or keep All Departments to apply the rule company-wide.'}</span>
            </label>
            <label style={{ color: '#94a3b8', fontSize: 11 }}>What do you want to detect?
              <select value={presetId} onChange={e => {
                const preset = RULE_PRESETS.find(item => item.id === e.target.value);
                setPresetId(e.target.value);
                if (preset) setForm({ ...form, field: preset.field, operator: preset.operator, value: preset.value });
              }} style={{ ...inputStyle, marginTop: 5 }}>
                {RULE_PRESETS.map(item => <option key={item.id} value={item.id}>{item.label}</option>)}
              </select>
            </label>
            {presetId === 'edr' && (
              <label style={{ color: '#94a3b8', fontSize: 11 }}>Select EDR detection point (31 capabilities)
                <select value={selectedDetectionCategory} onChange={e => {
                  const category = DETECTION_CATEGORIES.edr.find(item => item[0] === e.target.value);
                  if (category) setForm({ ...form, field: category[2], operator: category[3], value: category[4] });
                }} style={{ ...inputStyle, marginTop: 5 }}>
                  {DETECTION_CATEGORIES.edr.map(([id, label], index) => (
                    <option key={id} value={id}>{id === 'all' ? label : `${index}. ${label}`}</option>
                  ))}
                </select>
              </label>
            )}
            <div style={{ background: '#0b2138', border: '1px solid #1d4b73', borderRadius: 7, padding: 10, color: '#93c5fd', fontSize: 11 }}>
              {presetId === 'edr' && selectedDetectionCategory !== 'all'
                ? `EDR capability ${selectedDetectionCategory}: ${DETECTION_CATEGORIES.edr.find(item => item[0] === selectedDetectionCategory)?.[1]}`
                : RULE_PRESETS.find(item => item.id === presetId)?.help}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 9 }}>
              <label style={{ color: '#94a3b8', fontSize: 11 }}>Required events<input type="number" min="1" max="1000" value={form.threshold} onChange={e => setForm({ ...form, threshold: e.target.value })} style={{ ...inputStyle, marginTop: 5 }} /></label>
              <label style={{ color: '#94a3b8', fontSize: 11 }}>Time window<select value={form.timeWindowSeconds} onChange={e => setForm({ ...form, timeWindowSeconds: e.target.value })} style={{ ...inputStyle, marginTop: 5 }}><option value="60">1 minute</option><option value="300">5 minutes</option><option value="600">10 minutes</option><option value="1800">30 minutes</option><option value="3600">1 hour</option><option value="86400">24 hours</option></select></label>
            </div>
            <div style={{ color: '#94a3b8', fontSize: 11 }}>Risk score range (0–100)</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr auto 1fr', gap: 9, alignItems: 'end' }}>
              <label style={{ color: '#94a3b8', fontSize: 11 }}>Start score<input type="number" min="0" max="100" value={form.riskScoreMin} onChange={e => setForm({ ...form, riskScoreMin: e.target.value })} style={{ ...inputStyle, marginTop: 5 }} /></label>
              <span style={{ color: '#64748b', paddingBottom: 10 }}>to</span>
              <label style={{ color: '#94a3b8', fontSize: 11 }}>End score<input type="number" min="0" max="100" value={form.riskScoreMax} onChange={e => setForm({ ...form, riskScoreMax: e.target.value })} style={{ ...inputStyle, marginTop: 5 }} /></label>
            </div>
            <div style={{ background: '#0b2138', border: '1px solid #1d4b73', borderRadius: 7, padding: 10, color: '#67e8f9', fontSize: 11 }}>Confidence: Auto-calculated from matched data, final risk, event count, evidence diversity, IOC/malware evidence and prevention outcome.</div>
            <div style={{ ...inputStyle, color: SEV[ruleSeverityFromRisk(form.riskScoreMax)], fontWeight: 800, textAlign: 'center' }}>Matched score category: {ruleSeverityFromRisk(form.riskScoreMin).toUpperCase()} → {ruleSeverityFromRisk(form.riskScoreMax).toUpperCase()}</div>
            <div style={{ color: '#64748b', fontSize: 10 }}>Risk range: 0–64 Low · 65–74 Medium · 75–89 High · 90–100 Critical.</div>
            <button disabled={busy} style={{ background: '#6d28d9', color: '#fff', border: 0, borderRadius: 8, padding: 11, fontWeight: 800, cursor: 'pointer' }}>{busy ? 'Saving…' : editingRule ? '✓ Save Rule Changes' : '+ Create Correlation Rule'}</button>
          </div>
        </form>
        <div style={{ background: '#071426', border: '1px solid #213b5d', borderRadius: 10, padding: 16 }}>
          <h4 style={{ color: '#93c5fd', margin: '0 0 14px' }}>Company Custom Rules ({rules.length})</h4>
          {!rules.length ? <div style={{ color: '#64748b', padding: 20, textAlign: 'center' }}>No custom rules configured.</div> : rules.map(rule => <div key={rule._id} style={{ background: '#09182a', border: `1px solid ${rule.enabled ? '#314565' : '#26364d'}`, borderRadius: 9, padding: 14, marginBottom: 10, opacity: rule.enabled ? 1 : .72 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'flex-start' }}>
              <b style={{ color: '#e2e8f0', fontSize: 14, lineHeight: 1.35 }}>{rule.name}</b>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
                <Badge text={rule.severity?.toUpperCase() || 'HIGH'} color={SEV[rule.severity] || '#f59e0b'} />
                <Badge text={rule.departmentId?.name || 'ALL DEPARTMENTS'} color={rule.departmentId ? '#8b5cf6' : '#60a5fa'} />
                {!rule.enabled && <Badge text="DISABLED" color="#94a3b8" />}
              </div>
            </div>
            <div style={{ color: '#7890ad', fontSize: 11, lineHeight: 1.55, margin: '10px 0' }}>{rule.description || 'No description'}</div>
            <div style={{ color: '#93c5fd', fontSize: 10 }}>ID: {customRuleId(rule)}</div>
            <div style={{ color: '#94a3b8', fontSize: 10, marginTop: 6 }}>Steps: {rule.threshold || 1} · Window: {formatRuleWindow(rule.timeWindowSeconds)} · Confidence: {rule.confidence ?? 75}%</div>
            {customRuleEdrPoints(rule).length > 0 && <div style={{ color: '#67e8f9', fontSize: 10, marginTop: 7 }}>EDR points: {customRuleEdrPoints(rule).join(', ')}</div>}
            {(rule.mitreTechniques || []).length > 0 && <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', marginTop: 9 }}>{rule.mitreTechniques.map(item => <Badge key={item} text={item} color="#a78bfa" />)}</div>}
            <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginTop: 12, paddingTop: 10, borderTop: '1px solid #1e3049' }}>
              <button disabled={busy} onClick={() => toggleRule(rule)} style={{ background: rule.enabled ? '#3f1d2c' : '#123c35', color: rule.enabled ? '#fca5a5' : '#6ee7b7', border: '1px solid currentColor', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>{rule.enabled ? 'Disable' : 'Enable'}</button>
              <button disabled={busy} onClick={() => editRule(rule)} style={{ background: '#172554', color: '#93c5fd', border: '1px solid #3b82f6', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>✎ Edit</button>
              <button disabled={busy} onClick={() => setDeleteTarget(rule)} style={{ background: '#3f111a', color: '#fca5a5', border: '1px solid #ef4444', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>🗑 Delete</button>
            </div>
          </div>)}
        </div>
      </div>
      <div style={{ background: '#071426', border: '1px solid #213b5d', borderRadius: 10, padding: 16, marginTop: 20 }}>
        <h4 style={{ color: '#c4b5fd', margin: '0 0 5px' }}>Built-in SOC / SIEM / EDR Rules ({builtInRules.length})</h4>
        <div style={{ color: '#64748b', fontSize: 11, marginBottom: 14 }}>Production rules · EDR coverage 31/31 · IDS, IPS, Firewall, IAM, Zeek and Threat Intelligence supported.</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 10 }}>
          {builtInRules.map(rule => <div key={rule.id} style={{ border: `1px solid ${rule.overridden ? '#7c3aed' : '#314565'}`, background: '#09182a', borderRadius: 8, padding: 12, opacity: rule.enabled === false ? .68 : 1 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'flex-start' }}>
              <b style={{ color: '#e2e8f0', fontSize: 13 }}>{rule.name}</b>
              <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap', justifyContent: 'flex-end' }}><Badge text={rule.enabled === false ? 'DISABLED' : rule.severity?.toUpperCase()} color={rule.enabled === false ? '#94a3b8' : SEV[rule.severity] || '#60a5fa'} />{rule.overridden && <Badge text="UPDATED" color="#a78bfa" />}</div>
            </div>
            <div style={{ color: '#7890ad', fontSize: 11, lineHeight: 1.45, margin: '8px 0' }}>{rule.description}</div>
            <div style={{ color: '#93c5fd', fontSize: 10 }}>ID: {rule.id}</div>
            <div style={{ color: '#94a3b8', fontSize: 10, marginTop: 5 }}>Steps: {rule.threshold} · Window: {rule.timeWindowSeconds >= 3600 ? `${rule.timeWindowSeconds / 3600} hour` : `${rule.timeWindowSeconds / 60} min`} · Confidence: {rule.confidence}%</div>
            {(rule.coveredCapabilityIds || []).length > 0 && <div style={{ color: '#67e8f9', fontSize: 10, marginTop: 6 }}>EDR points: {rule.coveredCapabilityIds.join(', ')}</div>}
            {(rule.mitreTechniques || []).length > 0 && <div style={{ display: 'flex', gap: 4, flexWrap: 'wrap', marginTop: 8 }}>{rule.mitreTechniques.map(item => <Badge key={item} text={item} color="#a78bfa" />)}</div>}
            <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginTop: 10 }}>
              {!isDepartmentAdmin && <button disabled={busy} onClick={() => beginBuiltInEdit(rule)} style={{ background: '#172554', color: '#93c5fd', border: '1px solid #3b82f6', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>✎ Edit / Update</button>}
              {!isDepartmentAdmin && <button disabled={busy} onClick={() => toggleBuiltIn(rule)} style={{ background: rule.enabled === false ? '#123c35' : '#3f1d2c', color: rule.enabled === false ? '#6ee7b7' : '#fca5a5', border: '1px solid currentColor', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>{rule.enabled === false ? 'Enable' : 'Disable'}</button>}
              {!isDepartmentAdmin && rule.overridden && <button disabled={busy} onClick={() => resetBuiltIn(rule)} style={{ background: '#29213b', color: '#c4b5fd', border: '1px solid #8b5cf6', borderRadius: 6, padding: '5px 9px', cursor: 'pointer' }}>↺ Reset Default</button>}
              {isDepartmentAdmin && <Badge text="COMPANY POLICY · READ ONLY" color="#94a3b8" />}
            </div>
            {editingBuiltIn?.id === rule.id && <form onSubmit={saveBuiltIn} style={{ marginTop: 12, padding: 12, border: '1px solid #7c3aed', borderRadius: 8, background: '#0d1830', display: 'grid', gap: 9 }}>
              <div style={{ color: '#c4b5fd', fontWeight: 800, fontSize: 12 }}>Company override · Detection logic and MITRE mapping remain protected</div>
              <label style={{ color: '#94a3b8', fontSize: 10 }}>Name<input required maxLength={200} value={editingBuiltIn.name} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, name: e.target.value })} style={{ ...inputStyle, marginTop: 4 }} /></label>
              <label style={{ color: '#94a3b8', fontSize: 10 }}>Description<textarea maxLength={2000} value={editingBuiltIn.description} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, description: e.target.value })} style={{ ...inputStyle, minHeight: 62, marginTop: 4 }} /></label>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,minmax(0,1fr))', gap: 8 }}>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Severity<select value={editingBuiltIn.severity} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, severity: e.target.value })} style={{ ...inputStyle, marginTop: 4 }}>{['low','medium','high','critical'].map(value => <option key={value}>{value}</option>)}</select></label>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Confidence<input type="number" min="0" max="100" value={editingBuiltIn.confidence} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, confidence: e.target.value })} style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Risk start<input type="number" min="0" max="100" value={editingBuiltIn.riskScoreMin} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, riskScoreMin: e.target.value })} style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Risk end<input type="number" min="0" max="100" value={editingBuiltIn.riskScoreMax} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, riskScoreMax: e.target.value })} style={{ ...inputStyle, marginTop: 4 }} /></label>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Time window<select value={editingBuiltIn.timeWindowSeconds} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, timeWindowSeconds: e.target.value })} style={{ ...inputStyle, marginTop: 4 }}><option value="60">1 minute</option><option value="300">5 minutes</option><option value="600">10 minutes</option><option value="1800">30 minutes</option><option value="3600">1 hour</option><option value="86400">24 hours</option></select></label>
                <label style={{ color: '#94a3b8', fontSize: 10 }}>Status<select value={editingBuiltIn.enabled ? 'enabled' : 'disabled'} onChange={e => setEditingBuiltIn({ ...editingBuiltIn, enabled: e.target.value === 'enabled' })} style={{ ...inputStyle, marginTop: 4 }}><option value="enabled">Enabled</option><option value="disabled">Disabled</option></select></label>
              </div>
              <div style={{ color: '#64748b', fontSize: 10 }}>Steps/conditions are code-reviewed and locked. This edit changes company-specific scoring and execution settings only.</div>
              <div style={{ display: 'flex', gap: 8 }}><button disabled={busy} style={{ flex: 1, background: '#6d28d9', color: '#fff', border: 0, borderRadius: 7, padding: 9, fontWeight: 800, cursor: 'pointer' }}>{busy ? 'Saving…' : '✓ Save Built-in Update'}</button><button type="button" onClick={() => setEditingBuiltIn(null)} style={{ background: '#172a44', color: '#cbd5e1', border: '1px solid #40597a', borderRadius: 7, padding: '7px 12px', cursor: 'pointer' }}>Cancel</button></div>
            </form>}
          </div>)}
        </div>
      </div>
    </div>
  </div>;
}

function AiResult({ job }) {
  if (['queued', 'processing'].includes(job.status)) return <div style={{ clear: 'both', marginTop: 18, color: '#c4b5fd' }}>AI analysis is processing asynchronously…</div>;
  if (job.status === 'failed') return <div style={{ clear: 'both', marginTop: 18, color: '#fca5a5' }}>AI analysis failed: {job.error}</div>;
  const out = job.output || {};
  return <div style={{ clear: 'both', marginTop: 18, padding: 14, borderRadius: 8, background: 'rgba(76,29,149,.12)', border: '1px solid #5b21b6' }}>
    <div style={{ color: '#ddd6fe', fontWeight: 900 }}>✦ AI Incident Analysis · Confidence {job.confidence ?? out.confidence ?? 0}%</div>
    <p style={{ color: '#cbd5e1', fontSize: 12 }}><b>Summary:</b> {out.summary || 'No summary returned'}</p>
    <p style={{ color: '#cbd5e1', fontSize: 12 }}><b>Root cause:</b> {out.rootCause || 'Insufficient evidence'}</p>
    <div style={{ color: '#a5b4fc', fontSize: 11 }}><b>Reasoning:</b> {job.reasoning || out.reasoning}</div>
    {(out.recommendedInvestigationSteps || []).length > 0 && <ol style={{ color: '#cbd5e1', fontSize: 12 }}>{out.recommendedInvestigationSteps.map((step, i) => <li key={i}>{step}</li>)}</ol>}
    <div style={{ color: '#fbbf24', fontSize: 10 }}>Advisory only · Response actions require analyst/SOAR approval.</div>
  </div>;
}
