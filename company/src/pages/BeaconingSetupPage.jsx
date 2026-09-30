import { useNavigate } from 'react-router-dom';
import { BeaconingConfigurationTab } from './edrdashbordpage/Beaconing Detection';

export default function BeaconingSetupPage() {
  const navigate = useNavigate();

  return (
    <div style={{ color: '#e2e8f0', display: 'grid', gap: 15, minWidth: 0 }}>
      <header style={{ background: 'linear-gradient(135deg, rgba(8,28,48,.98), rgba(12,22,45,.98))', border: '1px solid #1d3655', borderRadius: 12, padding: 16, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14, flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: '#22d3ee', fontSize: 11, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>EDR System Setup</div>
          <h2 style={{ color: '#f8fafc', fontSize: 22, margin: '5px 0' }}>📡 Beaconing Detection</h2>
          <div style={{ color: '#8ea0b8', fontSize: 11 }}>Configure beaconing rules and approval-gated C2 containment for enrolled SOC agents.</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => navigate(-1)} style={{ color: '#e2e8f0', background: '#0f233a', border: '1px solid #1d3655', borderRadius: 7, padding: '8px 13px', fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>← EDR Setup</button>
          <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=26&capability=beaconing-detection')} style={{ color: '#001018', background: '#22d3ee', border: 0, borderRadius: 7, padding: '8px 13px', fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>Open Monitoring</button>
        </div>
      </header>
      <BeaconingConfigurationTab />
    </div>
  );
}
