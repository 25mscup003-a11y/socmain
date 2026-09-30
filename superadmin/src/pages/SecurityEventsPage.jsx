import { useEffect, useState } from 'react';
import api from '../api/axios';

const panel = { background: '#0f1b2e', border: '1px solid #1e3a5f', borderRadius: 10 };

export default function SecurityEventsPage() {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  const load = async () => {
    setLoading(true);
    setError('');
    try {
      const res = await api.get('/super-admin/security-events');
      setEvents(Array.isArray(res.data) ? res.data : []);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load security & fraud events stream');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h2 style={{ margin: 0, color: '#f8fafc' }}>Platform Security & Fraud Events Stream</h2>
          <small style={{ color: '#7dd3fc' }}>Real-time detection of logins, risk scores, decision engine outputs, and device telemetry</small>
        </div>
        <button onClick={load} style={{ border: 0, borderRadius: 6, padding: '8px 14px', background: '#0891b2', color: '#fff', fontWeight: 700, cursor: 'pointer', fontSize: 12 }}>
          🔄 Refresh Security Stream
        </button>
      </div>

      {loading ? (
        <div style={{ color: '#94a3b8', padding: 24, fontSize: 13 }}>Loading security events stream…</div>
      ) : error ? (
        <div style={{ padding: 16, background: '#350d16', color: '#fca5a5', borderRadius: 8 }}>{error}</div>
      ) : events.length === 0 ? (
        <div style={{ ...panel, padding: 36, textAlign: 'center', color: '#34d399' }}>
          <h3>🛡️ No Critical Security Violations Detected</h3>
          <p style={{ color: '#94a3b8', fontSize: 13 }}>Platform security monitoring active. All login attempts, token verifications, and tenant guards are operating within parameters.</p>
        </div>
      ) : (
        <div style={{ ...panel, overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#12243a', color: '#7dd3fc', textAlign: 'left' }}>
                {['Action / Event', 'Decision', 'Risk Score', 'Email / User', 'IP Address', 'OS / Browser', 'Timestamp'].map(x => (
                  <th key={x} style={{ padding: 12 }}>{x}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map(ev => (
                <tr key={ev._id} style={{ borderTop: '1px solid #1e3a5f' }}>
                  <td style={{ padding: 12 }}><b style={{ color: '#f8fafc', textTransform: 'uppercase' }}>{ev.action || 'LOGIN'}</b></td>
                  <td style={{ padding: 12 }}>
                    <span style={{
                      background: ev.decision === 'BLOCK' ? '#7f1d1d' : ev.decision === 'CHALLENGE' ? '#7c2d12' : '#064e3b',
                      color: ev.decision === 'BLOCK' ? '#fca5a5' : ev.decision === 'CHALLENGE' ? '#fde047' : '#34d399',
                      padding: '3px 8px', borderRadius: 999, fontSize: 10, fontWeight: 800
                    }}>
                      {ev.decision || 'ALLOW'}
                    </span>
                  </td>
                  <td style={{ padding: 12, color: ev.riskScore > 70 ? '#f87171' : '#34d399', fontWeight: 700 }}>
                    {ev.riskScore || 0} / 100
                  </td>
                  <td style={{ padding: 12, color: '#e2e8f0' }}>{ev.email || 'System'}</td>
                  <td style={{ padding: 12, color: '#94a3b8' }}>{ev.ipAddress || '—'}</td>
                  <td style={{ padding: 12, color: '#94a3b8' }}>{ev.os || '—'} / {ev.browser || '—'}</td>
                  <td style={{ padding: 12, color: '#64748b' }}>{new Date(ev.createdAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
