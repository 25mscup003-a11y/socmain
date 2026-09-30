import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/axios';
import { GeoPolicyEngine } from './edrdashbordpage/Geolocation Anomaly Detection';

export default function EDRSystemSystemsPage() {
  const [systems, setSystems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [savingId, setSavingId] = useState('');
  const [error, setError] = useState('');
  const [actionMessage, setActionMessage] = useState('');

  useEffect(() => {
    let active = true;
    setLoading(true);
    api.get('/system').then(response => {
      if (!active) return;
      const data = response.data;
      setSystems(Array.isArray(data) ? data : (data?.systems || []));
    }).catch(err => {
      if (active) setError(err.response?.data?.message || err.message || 'Failed to load systems');
    }).finally(() => {
      if (active) setLoading(false);
    });
    return () => { active = false; };
  }, []);

  const toggleLock = async (system) => {
    const hostname = system.hostname || system.name || 'this system';
    const action = system.isIsolated ? 'unlock and reconnect' : 'lock and isolate';
    if (!window.confirm(`Are you sure you want to ${action} ${hostname}?`)) return;
    setSavingId(system._id);
    setError('');
    setActionMessage('');
    try {
      const { data } = system.isIsolated
        ? await api.delete(`/system/${system._id}/isolate`)
        : await api.post(`/system/${system._id}/isolate`, { reason: 'Geo-fence admin lock' });
      setSystems(previous => previous.map(item => item._id === system._id ? { ...item, ...data.system } : item));
      setActionMessage(data.message || `${hostname} ${system.isIsolated ? 'unlock' : 'lock'} request submitted.`);
    } catch (err) {
      setError(err.response?.data?.message || err.message || 'Failed to update system lock');
    } finally {
      setSavingId('');
    }
  };

  return (
    <div>
      <div style={{ marginBottom: 18, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <h2 style={{ fontSize: 20, color: '#e0f2fe', margin: '0 0 6px' }}>Geolocation Policy Engine</h2>
          <div style={{ fontSize: 12, color: '#60a5fa' }}>Configure agent rules and control endpoint isolation.</div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <Link to="/company-admin/edr?capabilityId=23&capability=geolocation-anomaly-detection&view=policy" style={{ color: '#67e8f9', border: '1px solid rgba(34,211,238,.5)', borderRadius: 8, padding: '8px 12px', textDecoration: 'none', fontSize: 12, fontWeight: 900 }}>🛡️ Open Full Policy Engine</Link>
          <Link to=".." relative="path" style={{ color: '#93c5fd', border: '1px solid rgba(59,130,246,.4)', borderRadius: 8, padding: '8px 12px', textDecoration: 'none', fontSize: 12, fontWeight: 800 }}>Back</Link>
        </div>
      </div>

      <div style={{ display: 'grid', gap: 16 }}>
        <GeoPolicyEngine />

        <section style={{ border: '1px solid rgba(248,113,113,.4)', borderRadius: 8, background: 'rgba(8,18,34,.82)', overflow: 'hidden' }}>
          <div style={{ padding: '13px 16px', borderBottom: '1px solid rgba(248,113,113,.25)' }}>
            <div style={{ color: '#fecaca', fontWeight: 900 }}>🔒 Manual System Lock Controls</div>
            <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 4 }}>Selected AJNAT agent ko isolate ya reconnect karein. Command endpoint acknowledgement ke through apply hota hai.</div>
          </div>
          {actionMessage && <div style={{ margin: 12, color: '#86efac', background: 'rgba(34,197,94,.12)', border: '1px solid rgba(34,197,94,.35)', padding: 10, borderRadius: 7 }}>{actionMessage}</div>}
          {error && <div style={{ margin: 12, color: '#fecaca', background: '#7f1d1d55', border: '1px solid #ef444455', padding: 10, borderRadius: 7 }}>{error}</div>}
          {loading ? (
            <div style={{ color: '#93c5fd', padding: 16 }}>Loading systems...</div>
          ) : systems.length === 0 ? (
            <div style={{ color: '#93c5fd', padding: 16 }}>No systems found</div>
          ) : (
            <div>
              {systems.map(system => (
                <div key={system._id} style={{ display: 'grid', gridTemplateColumns: '1fr .7fr .7fr 150px', gap: 12, alignItems: 'center', padding: '12px 16px', borderTop: '1px solid rgba(37,99,235,.14)' }}>
                  <div>
                    <div style={{ color: '#e0f2fe', fontWeight: 800 }}>{system.hostname || system.name || 'Unnamed system'}</div>
                    <div style={{ color: '#64748b', fontSize: 11 }}>{system._id}</div>
                  </div>
                  <div style={{ color: '#93c5fd', fontSize: 12 }}>{system.osType || system.os || 'Unknown OS'}</div>
                  <div style={{ color: system.isIsolated ? '#f87171' : '#86efac', fontSize: 12, fontWeight: 900 }}>{system.isIsolated ? 'Locked / Isolated' : 'Connected'}</div>
                  <button
                    type="button"
                    onClick={() => toggleLock(system)}
                    disabled={savingId === system._id}
                    style={{ border: `1px solid ${system.isIsolated ? '#60a5fa' : '#f87171'}`, background: system.isIsolated ? 'rgba(37,99,235,.16)' : 'rgba(127,29,29,.28)', color: system.isIsolated ? '#bfdbfe' : '#fecaca', borderRadius: 7, padding: '8px 10px', fontWeight: 900, cursor: savingId === system._id ? 'wait' : 'pointer' }}
                  >
                    {savingId === system._id ? 'Submitting…' : system.isIsolated ? '🔓 Unlock System' : '🔒 Lock System'}
                  </button>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
