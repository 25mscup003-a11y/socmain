import { useCallback, useEffect, useRef, useState } from 'react';
import { Link, useSearchParams } from 'react-router-dom';
import api from '../../../api/axios';
import { SOCKET_URL, connectSocket, io } from '../../../api/config';
import { useAuth } from '../../../context/AuthContext';

const PREFIX = { soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4' };
const REVIEWER = ['soc_manager', 'l2_analyst', 'l3_analyst'];

export default function IncidentAuditPage({ auditType = 'standard' }) {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const [state, setState] = useState({ items: [], total: 0, page: 1, pages: 1 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [reviewDialog, setReviewDialog] = useState(null);
  const [reviewNote, setReviewNote] = useState('');
  const [reviewError, setReviewError] = useState('');
  const [reviewBusy, setReviewBusy] = useState(false);
  const requestRef = useRef(0);
  const page = Number(params.get('page') || 1);
  const status = params.get('status') || '';
  const canReview = REVIEWER.includes(user?.role);

  const load = useCallback(async () => {
    const requestId = ++requestRef.current;
    setLoading(true); setError('');
    try {
      const { data } = await api.get('/soc-dashboard/audit-reviews', { params: { type: auditType, status: status || undefined, page, limit: 20 }, skipCache: true });
      if (requestId === requestRef.current) setState(data);
    } catch (e) { if (requestId === requestRef.current) setError(e.response?.data?.message || 'Unable to load incident audit queue'); }
    finally { if (requestId === requestRef.current) setLoading(false); }
  }, [auditType, page, status]);

  useEffect(() => { load(); return () => { requestRef.current += 1; }; }, [load]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const refresh = () => document.visibilityState === 'visible' && load();
    socket.on('soc:audit:update', refresh);
    const disconnect = connectSocket(socket);
    return () => { socket.off('soc:audit:update', refresh); disconnect(); };
  }, [load]);

  const openReviewDialog = (item, action) => {
    setReviewDialog({ item, action });
    setReviewNote('');
    setReviewError('');
  };

  const closeReviewDialog = () => {
    if (reviewBusy) return;
    setReviewDialog(null);
    setReviewNote('');
    setReviewError('');
  };

  const review = async () => {
    if (!reviewDialog) return;
    const { item, action } = reviewDialog;
    const note = reviewNote.trim();
    if (action === 'request_changes' && !note) {
      setReviewError('Changes reason is required.');
      return;
    }
    setReviewBusy(true);
    setError(''); setNotice('');
    try {
      const { data } = await api.post(`/soc-dashboard/audit-reviews/${item._id}/action`, { action, note });
      setNotice(data.message);
      setReviewDialog(null);
      setReviewNote('');
      await load();
    } catch (e) {
      setReviewError(e.response?.data?.message || 'Audit action failed');
    } finally {
      setReviewBusy(false);
    }
  };
  const prefix = PREFIX[user?.role] || '/l1';
  const title = auditType === 'threat' ? 'Threat Incident Audit' : 'Incident Closure Audit';
  const description = auditType === 'threat'
    ? 'Threat Intelligence incidents closed by L4 and awaiting SOC Manager verification.'
    : user?.role === 'l1_analyst' ? 'Your closed incidents and their L2 audit status.'
      : user?.role === 'l2_analyst' ? 'Incidents closed by L1 and submitted to L2 for audit.'
        : user?.role === 'l3_analyst' ? 'Incidents closed by L2 and submitted to L3 for audit.'
          : user?.role === 'l4_analyst' ? 'Your closed Threat Intelligence incidents and audit status.'
            : 'Incidents closed by L3 and submitted to the SOC Manager for audit.';

  return <div className="incident-audit-page">
    <header className="audit-head"><div><h1>{auditType === 'threat' ? '⌾' : '🛡'} {title}</h1><p>{description}</p></div><div className="audit-total"><b>{state.total || 0}</b><span>Audit records</span></div></header>
    <div className="audit-tools"><select value={status} onChange={e => { e.target.value ? params.set('status', e.target.value) : params.delete('status'); params.set('page', '1'); setParams(params); }}><option value="">All Status</option><option value="pending">Pending</option><option value="approved">Approved</option><option value="changes_requested">Changes Requested</option></select><button onClick={load}>↻ Refresh</button></div>
    {error && <div className="audit-error">{error}</div>}{notice && <div className="audit-ok">{notice}</div>}
    {loading ? <div className="audit-state">Loading audit queue…</div> : !state.items?.length ? <div className="audit-state">No incident closures are waiting in this audit scope.</div> : <div className="audit-table-wrap"><table><thead><tr><th>Incident</th><th>Company</th><th>Closed By</th><th>Closure</th><th>Submitted</th><th>Audit Status</th><th>Action</th></tr></thead><tbody>{state.items.map(item => {
      const incident = item.incidentId || {};
      return <tr key={item._id}><td><Link to={`${prefix}/incidents/${incident._id}`}>{incident.title || 'Incident unavailable'}</Link><small>{incident.affectedEndpoint || incident.description || 'No endpoint details'}</small></td><td>{item.companyId?.name || 'Company'}</td><td><b>{item.submittedBy?.name || 'Analyst'}</b><small>{String(item.sourceRole || '').replace(/_/g, ' ').toUpperCase()}</small></td><td><span className={`sev ${incident.severity}`}>{incident.severity || 'unknown'}</span><small>{item.closureAction === 'false_positive' ? 'False positive' : 'Resolved'}</small></td><td>{new Date(item.submittedAt).toLocaleDateString()}<small>{new Date(item.submittedAt).toLocaleTimeString()}</small></td><td><span className={`status ${item.status}`}>{String(item.status).replace(/_/g, ' ')}</span>{item.reviewNote && <small title={item.reviewNote}>{item.reviewNote}</small>}</td><td>{canReview && item.status === 'pending' ? <div className="audit-actions"><button className="approve" onClick={() => openReviewDialog(item, 'approve')}>✓ Approve</button><button className="changes" onClick={() => openReviewDialog(item, 'request_changes')}>↩ Changes</button></div> : <span className="audit-done">{item.reviewedBy?.name ? `Reviewed by ${item.reviewedBy.name}` : 'Tracking'}</span>}</td></tr>;
    })}</tbody></table></div>}
    {state.pages > 1 && <div className="audit-pages"><button disabled={page <= 1} onClick={() => { params.set('page', page - 1); setParams(params); }}>Previous</button><span>Page {page} / {state.pages}</span><button disabled={page >= state.pages} onClick={() => { params.set('page', page + 1); setParams(params); }}>Next</button></div>}
    {reviewDialog && <div className="audit-modal-backdrop" role="presentation" onMouseDown={closeReviewDialog}>
      <section className="audit-modal" role="dialog" aria-modal="true" aria-labelledby="audit-review-title" onMouseDown={event => event.stopPropagation()}>
        <header>
          <div><span className={`audit-modal-icon ${reviewDialog.action}`}>{reviewDialog.action === 'approve' ? '✓' : '↩'}</span><div><h2 id="audit-review-title">{reviewDialog.action === 'approve' ? 'Approve Threat Closure' : 'Request Investigation Changes'}</h2><p>{reviewDialog.item?.incidentId?.title || 'Threat intelligence incident'}</p></div></div>
          <button type="button" aria-label="Close dialog" onClick={closeReviewDialog} disabled={reviewBusy}>×</button>
        </header>
        <div className="audit-modal-body">
          <label htmlFor="audit-review-note">{reviewDialog.action === 'approve' ? 'Approval Note (Optional)' : 'Required Changes / Reason'}</label>
          <textarea id="audit-review-note" autoFocus rows="5" maxLength="3000" value={reviewNote} onChange={event => { setReviewNote(event.target.value); setReviewError(''); }} placeholder={reviewDialog.action === 'approve' ? 'Add verification details or approval context…' : 'Explain what must be corrected before approval…'} />
          <div className="audit-modal-meta"><span className={reviewError ? 'error' : ''}>{reviewError || (reviewDialog.action === 'approve' ? 'This note will be saved in the audit trail.' : 'A reason is required to return this incident.')}</span><b>{reviewNote.length}/3000</b></div>
        </div>
        <footer><button type="button" className="cancel" onClick={closeReviewDialog} disabled={reviewBusy}>Cancel</button><button type="button" className={reviewDialog.action === 'approve' ? 'confirm approve' : 'confirm changes'} onClick={review} disabled={reviewBusy || (reviewDialog.action === 'request_changes' && !reviewNote.trim())}>{reviewBusy ? 'Saving…' : reviewDialog.action === 'approve' ? '✓ Approve Closure' : '↩ Request Changes'}</button></footer>
      </section>
    </div>}
    <style>{`
      .incident-audit-page{min-width:0;color:#dbeafe}.audit-head{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:18px 20px;border:1px solid #1e3a5f;border-radius:14px;background:linear-gradient(135deg,#0c1a2e,#101d35)}.audit-head h1{font-size:22px;margin:0}.audit-head p{font-size:12px;color:#94a3b8;margin:5px 0 0}.audit-total{min-width:110px;padding:10px 14px;text-align:center;border-radius:10px;background:#071524;border:1px solid #294765}.audit-total b,.audit-total span{display:block}.audit-total b{font-size:22px;color:#67e8f9}.audit-total span{font-size:9px;color:#71839b;text-transform:uppercase}.audit-tools{display:flex;gap:10px;margin:14px 0;padding:10px;border:1px solid #1e3a5f;border-radius:10px;background:#091624}.audit-tools select,.audit-tools button,.audit-pages button{padding:8px 12px;border:1px solid #294765;border-radius:7px;background:#07111f;color:#e2e8f0}.audit-tools button,.audit-pages button{cursor:pointer}.audit-error,.audit-ok{padding:11px 14px;margin-bottom:12px;border-radius:8px}.audit-error{background:#350d16;color:#fca5a5}.audit-ok{background:#064e3b;color:#6ee7b7}.audit-state{padding:50px;text-align:center;border:1px solid #1e3a5f;border-radius:12px;background:#0c192c;color:#71839b}.audit-table-wrap{max-width:100%;overflow-x:auto;border:1px solid #1e3a5f;border-radius:12px;background:#0c192c}.audit-table-wrap table{width:100%;min-width:1100px;border-collapse:collapse;table-layout:fixed}.audit-table-wrap th{padding:12px;text-align:left;color:#7dd3fc;background:#10233c;font-size:11px}.audit-table-wrap td{padding:13px 12px;border-top:1px solid #1e3a5f;vertical-align:middle;font-size:12px;overflow:hidden}.audit-table-wrap th:first-child{width:25%}.audit-table-wrap th:last-child{width:16%}.audit-table-wrap td a{display:block;color:#c4b5fd;font-weight:800;text-decoration:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.audit-table-wrap small{display:block;color:#71839b;font-size:10px;margin-top:4px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.sev,.status{display:inline-flex;padding:4px 8px;border-radius:999px;text-transform:uppercase;font-size:9px;font-weight:900;border:1px solid #294765}.sev.critical{color:#fb7185}.sev.high{color:#fb923c}.sev.medium{color:#facc15}.sev.low{color:#38bdf8}.status.pending{color:#facc15}.status.approved{color:#34d399}.status.changes_requested{color:#fb7185}.audit-actions{display:flex;gap:6px;flex-wrap:wrap}.audit-actions button{padding:6px 8px;border:0;border-radius:6px;color:white;font-weight:800;font-size:10px;cursor:pointer}.audit-actions .approve{background:#15803d}.audit-actions .changes{background:#b45309}.audit-done{color:#71839b;font-size:10px}.audit-pages{display:flex;align-items:center;justify-content:center;gap:10px;margin-top:14px;color:#94a3b8;font-size:11px}.audit-modal-backdrop{position:fixed;inset:0;z-index:2000;display:grid;place-items:center;padding:20px;background:rgba(1,7,18,.78);backdrop-filter:blur(6px)}.audit-modal{width:min(520px,100%);overflow:hidden;border:1px solid #315270;border-radius:14px;background:linear-gradient(145deg,#0d1c30,#081322);box-shadow:0 28px 90px rgba(0,0,0,.65)}.audit-modal>header{display:flex;align-items:flex-start;justify-content:space-between;padding:17px 19px;border-bottom:1px solid #1e3a5f}.audit-modal>header>div{display:flex;align-items:center;gap:11px}.audit-modal-icon{display:grid;place-items:center;width:34px;height:34px;border-radius:50%;font-size:17px;font-weight:900}.audit-modal-icon.approve{color:#86efac;background:#14532d;border:1px solid #22c55e}.audit-modal-icon.request_changes{color:#fdba74;background:#431407;border:1px solid #f97316}.audit-modal h2{margin:0;color:#eef6ff;font-size:16px}.audit-modal header p{margin:4px 0 0;max-width:365px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#8295aa;font-size:11px}.audit-modal>header>button{border:0;background:transparent;color:#94a3b8;font-size:25px;line-height:1;cursor:pointer}.audit-modal-body{padding:18px 19px}.audit-modal-body label{display:block;margin-bottom:7px;color:#bfdbfe;font-size:11px;font-weight:850}.audit-modal-body textarea{display:block;width:100%;box-sizing:border-box;resize:vertical;min-height:120px;padding:11px 12px;border:1px solid #294765;border-radius:8px;outline:none;background:#050e19;color:#e5edf7;font:inherit;font-size:12px;line-height:1.55}.audit-modal-body textarea:focus{border-color:#38bdf8;box-shadow:0 0 0 3px rgba(56,189,248,.1)}.audit-modal-meta{display:flex;justify-content:space-between;gap:12px;margin-top:7px;color:#64748b;font-size:9px}.audit-modal-meta .error{color:#fca5a5}.audit-modal-meta b{white-space:nowrap}.audit-modal>footer{display:flex;justify-content:flex-end;gap:9px;padding:13px 19px;border-top:1px solid #1e3a5f;background:#07111e}.audit-modal>footer button{padding:8px 14px;border-radius:7px;font-size:11px;font-weight:850;cursor:pointer}.audit-modal>footer button:disabled{opacity:.5;cursor:not-allowed}.audit-modal .cancel{border:1px solid #334e68;background:#0a1726;color:#b8c7d6}.audit-modal .confirm{border:0;color:white}.audit-modal .confirm.approve{background:#15803d}.audit-modal .confirm.changes{background:#c2410c}@media(max-width:700px){.audit-head{align-items:flex-start}.audit-total{min-width:80px}.audit-tools select,.audit-tools button{flex:1}.audit-modal{max-height:calc(100vh - 24px)}}
    `}</style>
  </div>;
}
