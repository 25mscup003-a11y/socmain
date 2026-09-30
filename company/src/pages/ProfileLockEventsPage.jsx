import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import toast from 'react-hot-toast';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';

const COLORS = {
  locked: '#f87171', lock_pending: '#fbbf24', lock_dispatching: '#fbbf24', detected: '#60a5fa',
  response_pending: '#fbbf24', response_success: '#34d399', response_failed: '#fb7185',
  unlocked: '#34d399', unlock_pending: '#22d3ee', lock_failed: '#fb7185', unlock_failed: '#fb7185', lock_skipped: '#94a3b8',
};
const LABELS = {
  locked: 'Locked', lock_pending: 'Lock Pending', lock_dispatching: 'Dispatching', detected: 'Detected',
  response_pending: 'Response Pending', response_success: 'Response Complete', response_failed: 'Response Failed',
  unlocked: 'Unlocked', unlock_pending: 'Unlock Pending', lock_failed: 'Lock Failed', unlock_failed: 'Unlock Failed', lock_skipped: 'Lock Skipped',
};

const dateTime = value => value ? new Date(value).toLocaleString() : '—';
const titleCase = value => String(value || '').replaceAll('_', ' ').replace(/\b\w/g, character => character.toUpperCase());

function Status({ value }) {
  const color = COLORS[value] || '#94a3b8';
  return <span style={{ color, background: `${color}18`, border: `1px solid ${color}55`, padding: '4px 8px', borderRadius: 999, fontSize: 10, fontWeight: 900, whiteSpace: 'nowrap' }}>{LABELS[value] || titleCase(value)}</span>;
}

function MetricCard({ icon, label, value, color }) {
  return <div className="pl-card"><span style={{ color }}>{icon}</span><div><b>{Number(value || 0).toLocaleString()}</b><small>{label}</small></div></div>;
}

function DetailPanel({ event, loading, onClose, onUnlock }) {
  if (!event && !loading) return null;
  const alert = event?.alertId || {};
  const system = event?.systemId || {};
  const deviations = Object.entries(event?.featureDeviation || {});
  const geolocation = event?.sourceType === 'geolocation_response';
  const trackedActions = event?.responseActions || [];
  const responseAudit = [...(event?.lockResponseId?.auditTrail || []), ...(event?.unlockResponseId?.auditTrail || []), ...trackedActions.flatMap(item => item.responseId?.auditTrail || [])];
  return <div className="pl-overlay" onMouseDown={e => e.target === e.currentTarget && onClose()}>
    <section className="pl-detail">
      <header><div><small>{geolocation ? 'GEOLOCATION RESPONSE REVIEW' : 'UEBA FORENSIC REVIEW'}</small><h2>Identity Protection Details</h2><p>{event?.verificationMessage || 'Verify identity and endpoint evidence before account recovery.'}</p></div><button onClick={onClose}>×</button></header>
      {loading || !event ? <div className="pl-loading">Loading protection evidence…</div> : <>
        <div className="pl-detail-status"><Status value={event.status} /><span>Event {event._id}</span></div>
        <div className="pl-grid">
          <div><small>Endpoint</small><b>{event.hostname}</b><em>{system.ip || alert.srcip || 'No IP'} · {system.os || system.osType || alert.osType || 'Unknown OS'}</em></div>
          <div><small>Protected account</small><b>{event.username}</b><em>Verified interactive session at collection time</em></div>
          <div><small>{geolocation ? 'Detection source' : 'Profile confidence'}</small><b>{geolocation ? 'Capability 23 · Geolocation' : `${Number(event.confidence || 0)}%`}</b><em>{geolocation ? (event.detectionName || 'Geolocation anomaly') : `${event.baselineDays}/30 learned days`}</em></div>
          <div><small>Risk score</small><b>{Number(event.riskScore || 0)}/100</b><em>{alert.severity || 'high'} severity</em></div>
        </div>
        {!geolocation && <div className="pl-section"><h3>What mismatched</h3><div className="pl-tags">{(event.mismatchFeatures || []).length ? event.mismatchFeatures.map(feature => <span key={feature}>{titleCase(feature)}</span>) : <i>No feature list was supplied.</i>}</div>
          {deviations.length > 0 && <div className="pl-deviations">{deviations.map(([name, score]) => <div key={name}><span>{titleCase(name)}</span><b>{Number(score).toFixed(2)}σ</b></div>)}</div>}
        </div>}
        <div className="pl-section"><h3>{geolocation ? 'Geolocation evidence' : 'Privacy & evidence'}</h3>{!geolocation && <p>Only aggregate typing rate, pointer speed, clicks, scrolling and active/idle percentage are compared. Key values, typed text, cursor coordinates, clipboard content, screenshots and passwords are not collected.</p>}<div className="pl-evidence"><span>Rule</span><b>{alert.ruleId || event.detectionName || 'UEBA_INPUT_PROFILE_MISMATCH'}</b>{geolocation ? <><span>Source</span><b>{[event.sourceIp, event.geoCity, event.geoCountry].filter(Boolean).join(' · ') || 'Not reported'}</b></> : <><span>Privacy mode</span><b>{event.privacyMode}</b></>}<span>Detected</span><b>{dateTime(event.createdAt)}</b><span>Notification</span><b>{titleCase(event.notificationStatus)}</b></div></div>
        {trackedActions.length > 0 && <div className="pl-section"><h3>Action Engine Responses</h3><div className="pl-evidence">{trackedActions.flatMap((item, index) => [<span key={`action-label-${index}`}>{titleCase(item.actionType)}</span>, <b key={`action-value-${index}`}>{titleCase(item.responseId?.status || item.status)} · {item.responseId?.commandId || 'Awaiting approval/dispatch'}{(item.responseId?.actionResult || item.responseId?.errorDetail || item.result) ? ` · ${item.responseId?.actionResult || item.responseId?.errorDetail || item.result}` : ''}</b>])}</div></div>}
        <div className="pl-section"><h3>Lock / unlock execution</h3><div className="pl-evidence"><span>Lock command</span><b>{event.lockResponseId?.commandId || 'Not dispatched'}</b><span>Lock result</span><b>{event.lockResponseId?.actionResult || event.lockResponseId?.errorDetail || titleCase(event.lockResponseId?.status || event.status)}</b><span>Unlock command</span><b>{event.unlockResponseId?.commandId || 'Not requested'}</b><span>Unlock result</span><b>{event.unlockResponseId?.actionResult || event.unlockResponseId?.errorDetail || titleCase(event.unlockResponseId?.status || '') || '—'}</b></div></div>
        <div className="pl-section"><h3>Audit timeline</h3><div className="pl-timeline">{[...(event.auditTrail || []), ...responseAudit].sort((a, b) => new Date(a.at) - new Date(b.at)).map((item, index) => <div key={`${item.at}-${index}`}><i /><time>{dateTime(item.at)}</time><b>{titleCase(item.action || item.status)}</b><p>{item.message || 'Endpoint response state updated'}</p></div>)}</div></div>
        <footer><button className="secondary" onClick={onClose}>Close</button><button className="unlock" disabled={!['locked', 'unlock_failed'].includes(event.status)} onClick={() => onUnlock(event)}>{event.status === 'locked' ? 'Unlock Account' : event.status === 'unlock_failed' ? 'Retry Unlock' : event.status === 'unlocked' ? 'Account Unlocked' : 'Awaiting Lock Confirmation'}</button></footer>
      </>}
    </section>
  </div>;
}

export default function ProfileLockEventsPage() {
  const [params, setParams] = useSearchParams();
  const [data, setData] = useState({ events: [], counts: {}, total: 0, pages: 0 });
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState('');
  const [status, setStatus] = useState('');
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const selectedId = params.get('event') || '';

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const { data: result } = await api.get('/ueba/profile-locks', { params: { page, limit: 30, search: search || undefined, status: status || undefined }, skipCache: true });
      setData(result);
    } catch (error) { if (!quiet) toast.error(error.response?.data?.message || 'Unable to load profile lock events'); }
    finally { if (!quiet) setLoading(false); }
  }, [page, search, status]);

  const loadDetail = useCallback(async id => {
    if (!id) { setDetail(null); return; }
    setDetailLoading(true);
    try {
      const { data: result } = await api.get(`/ueba/profile-locks/${id}`, { skipCache: true });
      setDetail(result.event);
    } catch (error) { toast.error(error.response?.data?.message || 'Unable to load mismatch details'); setParams({}, { replace: true }); }
    finally { setDetailLoading(false); }
  }, [setParams]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => { loadDetail(selectedId); }, [selectedId, loadDetail]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const refresh = payload => { load(true); if (selectedId && String(payload?.id || '') === selectedId) loadDetail(selectedId); };
    socket.on('ueba:profile-lock', refresh);
    const disconnect = connectSocket(socket);
    return () => { socket.off('ueba:profile-lock', refresh); disconnect(); };
  }, [load, loadDetail, selectedId]);

  const open = id => { const next = new URLSearchParams(params); next.set('event', id); setParams(next); };
  const close = () => { const next = new URLSearchParams(params); next.delete('event'); setParams(next, { replace: true }); setDetail(null); };
  const unlock = async event => {
    const reason = window.prompt(`Unlock ${event.username} on ${event.hostname}?\nEnter verified reason (minimum 5 characters):`, 'Identity verified by administrator');
    if (!reason) return;
    if (reason.trim().length < 5) return toast.error('Please enter a valid unlock reason');
    if (!window.confirm(`Confirm account unlock for ${event.username}?`)) return;
    try {
      await api.post(`/ueba/profile-locks/${event._id}/unlock`, { confirmed: true, reason: reason.trim() });
      toast.success('Signed unlock command sent to endpoint');
      await Promise.all([load(true), loadDetail(event._id)]);
    } catch (error) { toast.error(error.response?.data?.message || 'Unlock request failed'); }
  };

  const cards = useMemo(() => [
    ['◎', 'Protection Events', data.counts?.detected, '#60a5fa'],
    ['🔒', 'Active Protection', data.counts?.activeLocked, '#f87171'],
    ['✓', 'Confirmed Lock Actions', data.counts?.lockCount, '#fbbf24'],
    ['🔓', 'Unlocked', data.counts?.unlocked, '#34d399'],
    ['!', 'Failed Actions', data.counts?.failed, '#fb7185'],
  ], [data.counts]);

  return <div className="pl-page">
    <header className="pl-header"><div><span>IDENTITY PROTECTION</span><h1>🔐 Profile Lock / Unlock</h1><p>UEBA and geolocation action logs with endpoint-confirmed account recovery</p></div><button onClick={() => load()}>↻ Refresh</button></header>
    <div className="pl-cards">{cards.map(([icon, label, value, color]) => <MetricCard key={label} icon={icon} label={label} value={value} color={color} />)}</div>
    <section className="pl-panel">
      <div className="pl-toolbar"><div><h2>Identity Protection Response Events</h2><small>{Number(data.total || 0).toLocaleString()} scoped records</small></div><div><input value={search} onChange={e => { setSearch(e.target.value); setPage(1); }} placeholder="Search hostname, account or agent…"/><select value={status} onChange={e => { setStatus(e.target.value); setPage(1); }}><option value="">All statuses</option><option value="response_pending,locked,lock_pending,lock_dispatching,unlock_pending">Active protection</option><option value="response_success,unlocked">Completed</option><option value="response_failed,lock_failed,unlock_failed">Failed</option><option value="lock_skipped">Skipped safely</option></select></div></div>
      <div className="pl-table-wrap"><table><thead><tr><th>Detected</th><th>Source</th><th>Endpoint / Agent</th><th>Account</th><th>Risk</th><th>Action Engine</th><th>Protection</th><th>Notification</th></tr></thead><tbody>
        {loading ? <tr><td colSpan="8" className="empty">Loading real-time protection events…</td></tr> : !data.events?.length ? <tr><td colSpan="8" className="empty">No identity protection response events found.</td></tr> : data.events.map(event => <tr key={event._id} onClick={() => open(event._id)}><td>{dateTime(event.createdAt)}</td><td><b>{event.sourceType === 'geolocation_response' ? 'Geolocation' : 'UEBA'}</b><small>Capability {event.sourceCapabilityId || 11}</small></td><td><b>{event.hostname}</b><small>{event.agentId || String(event.systemId || '')}</small></td><td><b>{event.username}</b><small>{event.sourceType === 'geolocation_response' ? (event.geoCountry || event.sourceIp || 'Geo event') : `${event.baselineDays}/30 baseline days`}</small></td><td><strong>{Number(event.riskScore || 0)}/100</strong><small>{event.sourceType === 'geolocation_response' ? event.detectionName : `${Number(event.confidence || 0)}% confidence`}</small></td><td><div className="pl-tags compact">{event.responseActions?.length ? event.responseActions.map(item => <span key={`${item.actionType}-${item.responseId?._id || item.responseId}`}>{titleCase(item.actionType)}</span>) : (event.mismatchFeatures || []).slice(0, 3).map(feature => <span key={feature}>{titleCase(feature)}</span>)}</div></td><td><Status value={event.status} /></td><td>{titleCase(event.notificationStatus)}</td></tr>)}</tbody></table></div>
      <div className="pl-pager"><button disabled={page <= 1} onClick={() => setPage(value => value - 1)}>Previous</button><span>Page {page} of {Math.max(1, data.pages || 1)}</span><button disabled={page >= (data.pages || 1)} onClick={() => setPage(value => value + 1)}>Next</button></div>
    </section>
    <DetailPanel event={detail} loading={detailLoading} onClose={close} onUnlock={unlock} />
    <style>{`
      .pl-page{color:#dbeafe;min-width:0}.pl-header{display:flex;justify-content:space-between;gap:20px;align-items:center;margin-bottom:14px;padding:18px 20px;border:1px solid #1e3a5f;border-radius:14px;background:linear-gradient(135deg,#0b1a2f,#101d35)}.pl-header span{font-size:10px;color:#22d3ee;font-weight:900;letter-spacing:1.2px}.pl-header h1{font-size:23px;margin:5px 0}.pl-header p{font-size:12px;color:#94a3b8;margin:0}.pl-header button,.pl-pager button,.pl-detail footer button{border:1px solid #2563eb;background:#102c55;color:#bfdbfe;border-radius:8px;padding:9px 13px;font-weight:800;cursor:pointer}.pl-cards{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin-bottom:14px}.pl-card{display:flex;gap:12px;align-items:center;border:1px solid #1e3a5f;border-radius:11px;background:#0b1728;padding:14px}.pl-card>span{font-size:22px}.pl-card b,.pl-card small{display:block}.pl-card b{font-size:22px;color:#f8fafc}.pl-card small{font-size:10px;color:#7c8da5;text-transform:uppercase;font-weight:900}.pl-panel{border:1px solid #1e3a5f;border-radius:14px;background:#081522;overflow:hidden}.pl-toolbar{display:flex;justify-content:space-between;align-items:center;gap:15px;padding:14px 16px;border-bottom:1px solid #1e3a5f}.pl-toolbar h2{font-size:15px;margin:0}.pl-toolbar small{color:#64748b}.pl-toolbar>div:last-child{display:flex;gap:8px}.pl-toolbar input,.pl-toolbar select{background:#06101d;border:1px solid #294765;border-radius:7px;color:#dbeafe;padding:8px 10px;min-width:180px}.pl-table-wrap{overflow:auto}.pl-panel table{width:100%;border-collapse:collapse;font-size:11px}.pl-panel th{padding:10px;text-align:left;color:#7dd3fc;background:#0d1d31;white-space:nowrap}.pl-panel td{padding:11px 10px;border-top:1px solid #172b45;color:#aebfd3;vertical-align:middle}.pl-panel tbody tr{cursor:pointer}.pl-panel tbody tr:hover{background:#10233c}.pl-panel td b,.pl-panel td small{display:block}.pl-panel td b,.pl-panel td strong{color:#e2e8f0}.pl-panel td small{margin-top:3px;color:#64748b}.pl-panel .empty{text-align:center;padding:38px;color:#64748b}.pl-tags{display:flex;gap:6px;flex-wrap:wrap}.pl-tags span{padding:4px 7px;border-radius:6px;border:1px solid #155e75;background:#083344;color:#67e8f9;font-size:10px;font-weight:800}.pl-tags.compact{max-width:290px}.pl-pager{display:flex;justify-content:flex-end;align-items:center;gap:10px;padding:12px 16px;border-top:1px solid #1e3a5f;color:#94a3b8;font-size:11px}.pl-pager button:disabled{opacity:.35;cursor:not-allowed}.pl-overlay{position:fixed;inset:0;z-index:10000;background:rgba(2,6,23,.82);backdrop-filter:blur(5px);display:flex;justify-content:flex-end}.pl-detail{width:min(780px,96vw);height:100%;overflow:auto;background:#07111f;border-left:1px solid #2563eb;box-shadow:-20px 0 60px #020617;padding:20px}.pl-detail>header{display:flex;justify-content:space-between;gap:20px;border-bottom:1px solid #1e3a5f;padding-bottom:14px}.pl-detail header small{color:#22d3ee;font-weight:900}.pl-detail header h2{margin:5px 0;font-size:22px}.pl-detail header p{margin:0;color:#fbbf24;font-size:11px}.pl-detail header button{width:36px;height:36px;border:1px solid #334155;border-radius:8px;background:#0f172a;color:white;font-size:23px;cursor:pointer}.pl-detail-status{display:flex;justify-content:space-between;align-items:center;color:#64748b;font-size:10px;padding:14px 0}.pl-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px}.pl-grid>div,.pl-section{border:1px solid #1e3a5f;border-radius:10px;background:#0b1728;padding:13px}.pl-grid small,.pl-grid b,.pl-grid em{display:block}.pl-grid small{color:#64748b;text-transform:uppercase;font-size:9px;font-weight:900}.pl-grid b{color:#f8fafc;margin:4px 0;font-size:15px}.pl-grid em{color:#8ba3bd;font-size:10px;font-style:normal}.pl-section{margin-top:10px}.pl-section h3{font-size:12px;color:#7dd3fc;margin:0 0 10px;text-transform:uppercase}.pl-section>p{color:#a8b8ca;font-size:11px;line-height:1.6}.pl-deviations{display:grid;grid-template-columns:repeat(2,1fr);gap:7px;margin-top:10px}.pl-deviations div{display:flex;justify-content:space-between;background:#07111f;padding:8px;border-radius:7px;color:#94a3b8;font-size:11px}.pl-deviations b{color:#fb7185}.pl-evidence{display:grid;grid-template-columns:130px minmax(0,1fr);gap:7px;font-size:11px}.pl-evidence span{color:#64748b}.pl-evidence b{color:#dbeafe;overflow-wrap:anywhere}.pl-timeline>div{display:grid;grid-template-columns:10px 145px 150px 1fr;gap:8px;align-items:start;padding:7px 0;border-top:1px solid #172b45}.pl-timeline i{width:7px;height:7px;border-radius:50%;background:#22d3ee;margin-top:4px}.pl-timeline time{color:#64748b;font-size:9px}.pl-timeline b{color:#bfdbfe;font-size:10px}.pl-timeline p{margin:0;color:#94a3b8;font-size:10px}.pl-detail footer{display:flex;justify-content:flex-end;gap:9px;padding:16px 0}.pl-detail footer .unlock{background:#065f46;border-color:#10b981;color:#d1fae5}.pl-detail footer button:disabled{opacity:.42;cursor:not-allowed}.pl-loading{padding:50px;text-align:center;color:#94a3b8}@media(max-width:1050px){.pl-cards{grid-template-columns:repeat(3,1fr)}}@media(max-width:720px){.pl-header,.pl-toolbar{align-items:flex-start;flex-direction:column}.pl-toolbar>div:last-child{width:100%;flex-direction:column}.pl-toolbar input,.pl-toolbar select{width:100%;box-sizing:border-box}.pl-cards{grid-template-columns:repeat(2,1fr)}.pl-grid{grid-template-columns:1fr}.pl-timeline>div{grid-template-columns:10px 1fr}.pl-timeline time,.pl-timeline b,.pl-timeline p{grid-column:2}.pl-evidence{grid-template-columns:1fr}.pl-detail{box-sizing:border-box}}
    `}</style>
  </div>;
}
