import { useEffect, useState } from 'react';
import api from '../../../api/axios';
import { GeoPolicyEngine } from '../../edrdashbordpage/Geolocation Anomaly Detection';

export default function SocManagerGeolocationPage() {
  const [companies, setCompanies] = useState([]);
  const [companyId, setCompanyId] = useState('');
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    api.get('/soc-manager/companies', { params: { limit: 100 }, skipCache: true })
      .then(({ data }) => {
        if (!active) return;
        const items = data?.items || [];
        setCompanies(items);
        setCompanyId(current => current || String(items[0]?._id || ''));
      })
      .catch(err => active && setError(err.response?.data?.message || 'Assigned companies load nahi hui.'));
    return () => { active = false; };
  }, []);

  return (
    <div style={{ minHeight: '100%', padding: 20, background: '#06101d' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 16, marginBottom: 16 }}>
        <div>
          <h2 style={{ margin: 0, color: '#e0f2fe', fontSize: 20 }}>🌍 Geolocation Anomaly Detection</h2>
          <p style={{ margin: '5px 0 0', color: '#7890aa', fontSize: 12 }}>Selected company ke AJNAT agents ke liye geolocation policies configure karein.</p>
        </div>
        <select value={companyId} onChange={event => setCompanyId(event.target.value)} style={{ minWidth: 240, padding: '9px 12px', borderRadius: 6, border: '1px solid #245071', background: '#0b1b2d', color: '#e0f2fe' }}>
          {!companies.length && <option value="">No assigned company</option>}
          {companies.map(item => <option key={item._id} value={item._id}>{item.name}</option>)}
        </select>
      </div>
      {error ? <div style={{ color: '#fb7185' }}>{error}</div> : companyId ? <GeoPolicyEngine key={companyId} companyId={companyId} /> : <div style={{ color: '#94a3b8', padding: 24 }}>Policy Engine use karne ke liye SOC Manager ko company assignment required hai.</div>}
    </div>
  );
}
