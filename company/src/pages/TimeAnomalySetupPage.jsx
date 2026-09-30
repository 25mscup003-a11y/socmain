import { useCallback, useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { TimeAnomalyConfigureTab, TimeAnomalyExceptionsTab } from './edrdashbordpage/Time-Based Anomaly Detection';

export default function TimeAnomalySetupPage() {
  const navigate = useNavigate();
  const [systems, setSystems] = useState([]);
  const [error, setError] = useState('');

  const loadSystems = useCallback(async () => {
    try {
      const response = await api.get('/system', { skipCache: true });
      const rows = response.data?.systems || response.data?.agents || response.data || [];
      setSystems(Array.isArray(rows) ? rows : []);
      setError('');
    } catch (requestError) {
      setError(requestError.response?.data?.message || 'AJNAT agents could not be loaded');
    }
  }, []);

  useEffect(() => {
    loadSystems();
    const timer = window.setInterval(loadSystems, 30000);
    return () => window.clearInterval(timer);
  }, [loadSystems]);

  return (
    <div style={{ color: '#e2e8f0', display: 'grid', gap: 15, minWidth: 0 }}>
      <header style={{ background: 'linear-gradient(135deg, rgba(8,28,48,.98), rgba(12,22,45,.98))', border: '1px solid #1d3655', borderRadius: 12, padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14, flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#34d399', fontSize: 11, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>EDR System Setup</div>
          <h2 style={{ color: '#f8fafc', fontSize: 22, margin: '5px 0' }}>⚙️ Time-Based Anomaly Configuration</h2>
          <div style={{ color: '#8ea0b8', fontSize: 11 }}>Configure schedules, agent-scoped detection rules and temporary approved exceptions.</div>
        </div>
        <button type="button" onClick={() => navigate(-1)} style={{ color: '#e2e8f0', background: '#0f233a', border: '1px solid #1d3655', borderRadius: 7, padding: '8px 13px', fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>← EDR Setup</button>
      </header>
      {error && <div style={{ color: '#fecaca', background: '#7f1d1d55', border: '1px solid #ef444455', padding: 10, borderRadius: 8 }}>{error}</div>}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 14, alignItems: 'start' }}>
        <TimeAnomalyConfigureTab systems={systems} onRefresh={loadSystems} embedded />
        <TimeAnomalyExceptionsTab systems={systems} onRefresh={loadSystems} embedded />
      </div>
    </div>
  );
}
