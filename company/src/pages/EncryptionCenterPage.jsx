import { useCallback, useEffect, useMemo, useState } from 'react';
import toast from 'react-hot-toast';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';
import { useAuth } from '../context/AuthContext';
import './EncryptionCenterPage.css';

const fmt = value => new Intl.NumberFormat().format(Number(value || 0));
const when = value => value ? new Date(value).toLocaleString() : '—';

function Status({ value }) {
  const normalized = String(value || 'unknown').toLowerCase();
  const good = ['healthy', 'active', 'completed', 'success', 'approved', 'enabled', 'aes-256-gcm', 'field-encryption-active', 'tls-active'].some(item => normalized.includes(item));
  return <span className={`enc-status ${good ? 'ok' : normalized.includes('fail') || normalized.includes('denied') ? 'bad' : 'warn'}`}>{value || 'unknown'}</span>;
}

export default function EncryptionCenterPage() {
  const { user, company } = useAuth();
  const [data, setData] = useState(null);
  const [keys, setKeys] = useState([]);
  const [jobs, setJobs] = useState([]);
  const [requests, setRequests] = useState([]);
  const [audit, setAudit] = useState([]);
  const [busy, setBusy] = useState(false);
  const companyId = company?._id || user?.companyId || '';
  const query = companyId ? `?companyId=${encodeURIComponent(companyId)}` : '';

  const load = useCallback(async () => {
    try {
      const [overview, keyData, jobData, requestData, auditData] = await Promise.all([
        api.get(`/encryption/overview${query}`, { skipCache: true }),
        api.get(`/encryption/keys${query}`, { skipCache: true }),
        api.get(`/encryption/jobs${query}`, { skipCache: true }),
        api.get(`/encryption/decrypt/requests${query}`, { skipCache: true }),
        api.get('/encryption/audit', { params: { ...(companyId ? { companyId } : {}), limit: 100 }, skipCache: true }),
      ]);
      setData(overview.data); setKeys(keyData.data.keys || []); setJobs(jobData.data.jobs || []);
      setRequests(requestData.data.requests || []); setAudit(auditData.data.audit || []);
    } catch (error) {
      toast.error(error.response?.data?.message || 'Encryption status could not be loaded');
    }
  }, [query, companyId]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const socket = io(SOCKET_URL);
    const disconnect = connectSocket(socket);
    if (companyId) socket.emit('join:company', companyId);
    const refresh = () => load();
    socket.on('encryption:key-updated', refresh);
    socket.on('encryption:job-updated', refresh);
    socket.on('encryption:decryption-request', refresh);
    return () => {
      socket.off('encryption:key-updated', refresh);
      socket.off('encryption:job-updated', refresh);
      socket.off('encryption:decryption-request', refresh);
      disconnect();
    };
  }, [companyId, load]);

  const cards = data?.cards || {};
  const cardList = [
    ['Encryption Status', cards.encryptionStatus],
    ['Encrypted Evidence', fmt(cards.totalEncryptedEvidence)],
    ['Decryption Requests', fmt(cards.totalDecryptionRequests)],
    ['Failed Decryptions', fmt(cards.failedDecryptionAttempts)],
    ['Active Jobs', fmt(cards.activeEncryptionJobs)],
    ['Active Keys', fmt(cards.activeKeys)],
    ['Expiring Keys', fmt(cards.expiringKeys)],
    ['Database Encryption', cards.databaseEncryption],
    ['Backup Encryption', cards.backupEncryption],
    ['Communication', cards.communicationEncryption],
    ['Configuration', cards.configurationEncryption],
    ['Provider', data?.provider?.provider || 'unavailable'],
  ];
  const maxTrend = useMemo(() => Math.max(1, ...(data?.trends || []).map(row => row.count)), [data]);
  const canManage = ['superadmin', 'soc_manager'].includes(user?.role);

  const keyAction = async action => {
    const reason = window.prompt(`Reason for key ${action}:`);
    if (!reason) return;
    setBusy(true);
    try {
      await api.post(`/encryption/keys${action === 'rotation' ? '/rotate' : ''}`, { companyId, reason });
      toast.success(`Key ${action} completed`); await load();
    } catch (error) { toast.error(error.response?.data?.message || `Key ${action} failed`); }
    finally { setBusy(false); }
  };

  const decide = async (requestId, decision) => {
    setBusy(true);
    try {
      await api.post(`/encryption/decrypt/requests/${requestId}/decision`, { companyId, decision, reason: `${decision} in Encryption Center` });
      toast.success(`Request ${decision}`); await load();
    } catch (error) { toast.error(error.response?.data?.message || 'Decision failed'); }
    finally { setBusy(false); }
  };

  return (
    <main className="enc-page">
      <header className="enc-hero">
        <div><p className="enc-eyebrow">Security Operations</p><h1>Encryption &amp; Key Management Center</h1><p>Tenant-isolated AES-256-GCM, evidence custody, approvals and cryptographic health.</p></div>
        <div className="enc-actions">
          <button onClick={load} disabled={busy}>Refresh</button>
          {canManage && !keys.some(key => key.status === 'active') && <button className="primary" onClick={() => keyAction('creation')} disabled={busy}>Create tenant key</button>}
          {canManage && keys.some(key => key.status === 'active') && <button className="primary" onClick={() => keyAction('rotation')} disabled={busy}>Rotate active key</button>}
        </div>
      </header>

      <section className="enc-cards">
        {cardList.map(([label, value]) => <article className="enc-card" key={label}><span>{label}</span>{typeof value === 'string' ? <Status value={value} /> : <strong>{value ?? '—'}</strong>}</article>)}
      </section>

      <section className="enc-grid">
        <article className="enc-panel enc-chart"><h2>30-day cryptographic activity</h2>
          {(data?.trends || []).length ? data.trends.slice(-20).map((row, index) => <div className="enc-bar-row" key={`${row.day}-${row.action}-${index}`}><span>{row.day}<small>{row.action}</small></span><i style={{ width: `${Math.max(3, row.count / maxTrend * 100)}%` }} /><b>{row.count}</b></div>) : <p className="enc-empty">No activity recorded for this scope.</p>}
        </article>
        <article className="enc-panel"><h2>Key inventory</h2><div className="enc-table-wrap"><table><thead><tr><th>Version</th><th>Key ID</th><th>Status</th><th>Expires</th></tr></thead><tbody>{keys.map(key => <tr key={key.keyId}><td>v{key.version}</td><td className="mono">{key.keyId}</td><td><Status value={key.status} /></td><td>{when(key.expiresAt)}</td></tr>)}</tbody></table></div></article>
      </section>

      <section className="enc-panel"><h2>Decryption approval queue</h2><div className="enc-table-wrap"><table><thead><tr><th>Request</th><th>Target</th><th>Requester</th><th>Reason</th><th>Status</th><th>Expires</th><th>Decision</th></tr></thead><tbody>{requests.map(item => <tr key={item.requestId}><td className="mono">{item.requestId}</td><td>{item.targetType}<small className="block mono">{item.targetId}</small></td><td>{item.requestedBy?.name || item.requestedByRole}</td><td>{item.reason}</td><td><Status value={item.status} /></td><td>{when(item.expiresAt)}</td><td>{canManage && item.status === 'pending' ? <div className="row-actions"><button onClick={() => decide(item.requestId, 'approved')}>Approve</button><button className="danger" onClick={() => decide(item.requestId, 'denied')}>Deny</button></div> : '—'}</td></tr>)}</tbody></table></div></section>

      <section className="enc-grid">
        <article className="enc-panel"><h2>Recent encryption jobs</h2><div className="enc-table-wrap"><table><thead><tr><th>Operation</th><th>Status</th><th>Progress</th><th>Updated</th></tr></thead><tbody>{jobs.slice(0, 12).map(job => <tr key={job._id}><td>{job.operation}</td><td><Status value={job.status} /></td><td>{job.progress}%</td><td>{when(job.updatedAt)}</td></tr>)}</tbody></table></div></article>
        <article className="enc-panel"><h2>Immutable audit activity</h2><div className="enc-table-wrap"><table><thead><tr><th>Time</th><th>Action</th><th>Outcome</th><th>Risk</th></tr></thead><tbody>{audit.slice(0, 12).map(item => <tr key={item.entryHash}><td>{when(item.createdAt)}</td><td>{item.action}</td><td><Status value={item.outcome} /></td><td>{item.riskScore}</td></tr>)}</tbody></table></div></article>
      </section>
      <p className="enc-footnote">Key material and decrypted values are never returned by this dashboard. Decryption requires an approved, unexpired, single-use request and fresh MFA.</p>
    </main>
  );
}
