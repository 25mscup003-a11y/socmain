import { useState, useEffect, useCallback } from 'react';
import api from '../api/axios';

const SEV   = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
const SEVBG = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b' };
const CAT_ICON = {
  malware: '🦠', network: '🌐', file: '📁', system: '🖥', edr: '👤',
  usb: '🔌', isolation: '🚫', other: '●',
};

function Badge({ text, color = '#38bdf8', bg }) {
  return (
    <span style={{
      fontSize: 10, padding: '2px 8px', borderRadius: 10, fontWeight: 700,
      background: bg || `${color}22`, color, border: `1px solid ${color}44`
    }}>{text}</span>
  );
}

export default function InvestigatePage() {
  const [activeTab, setActiveTab] = useState('timeline');
  const [companies, setCompanies] = useState([]);
  const [companyId, setCompanyId] = useState('');
  const [query, setQuery] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [selectedAlert, setSelectedAlert] = useState(null);

  useEffect(() => {
    api.get('/superadmin/companies').then(r => setCompanies(r.data || [])).catch(() => {});
  }, []);

  const search = useCallback(async (p = 1) => {
    setLoading(true);
    try {
      const params = new URLSearchParams({ page: p, limit: 30 });
      if (companyId) params.set('companyId', companyId);
      if (severity) params.set('severity', severity);
      if (category) params.set('category', category);
      const r = await api.get(`/superadmin/alerts?${params}`);
      let results = r.data?.alerts || [];
      if (query.trim()) {
        const q = query.toLowerCase();
        results = results.filter(a =>
          (a.description || '').toLowerCase().includes(q) ||
          (a.srcip || '').includes(q) ||
          (a.ruleId || '').toLowerCase().includes(q) ||
          (a.filePath || '').toLowerCase().includes(q) ||
          (a.username || '').toLowerCase().includes(q)
        );
      }
      setAlerts(results);
      setTotal(r.data?.total || 0);
      setPage(p);
    } catch {}
    setLoading(false);
  }, [companyId, severity, category, query]);

  useEffect(() => {
    search(1);
  }, [companyId, search]);

  return (
    <div style={{ maxWidth: 1350, margin: '0 auto' }}>
      {/* Page Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
        <div>
          <h2 style={{ fontSize: 22, fontWeight: 700, color: '#f8fafc', margin: 0, display: 'flex', alignItems: 'center', gap: 10 }}>
            <span>🔎</span> Threat Investigation
          </h2>
          <p style={{ fontSize: 13, color: '#38bdf8', marginTop: 4, marginBottom: 0 }}>
            Search security logs, forensic timelines, and telemetry across all enterprises
          </p>
        </div>

        <div>
          <select value={companyId} onChange={e => setCompanyId(e.target.value)}
            style={{ fontSize: 13, padding: '7px 12px', borderRadius: 8, border: '1px solid #1e2d45', background: '#0f1b2e', color: '#e2e8f0' }}>
            <option value="">🏢 All Companies</option>
            {companies.map(c => <option key={c._id} value={c._id}>{c.name}</option>)}
          </select>
        </div>
      </div>

      {/* Navigation Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 20, borderBottom: '1px solid #1e2d45', paddingBottom: 10 }}>
        {[
          ['timeline', '📋 Timeline View'],
          ['search', '🔍 Log Search']
        ].map(([tabKey, label]) => (
          <button
            key={tabKey}
            onClick={() => setActiveTab(tabKey)}
            style={{
              padding: '8px 18px',
              fontSize: 13,
              fontWeight: 600,
              borderRadius: 6,
              border: activeTab === tabKey ? '1px solid #38bdf8' : '1px solid #1e2d45',
              background: activeTab === tabKey ? 'rgba(56, 189, 248, 0.15)' : '#0f1b2e',
              color: activeTab === tabKey ? '#38bdf8' : '#94a3b8',
              cursor: 'pointer',
              transition: 'all .15s'
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {/* Filters Bar */}
      <div style={{
        background: '#0f1b2e', border: '1px solid #1e2d45', borderRadius: 10,
        padding: '14px 18px', marginBottom: 20, display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'flex-end'
      }}>
        <div style={{ flex: 1, minWidth: 220 }}>
          <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>🔍 Search Query</label>
          <input value={query} onChange={e => setQuery(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && search(1)}
            placeholder="IP, filename, rule, username…"
            style={{ width: '100%', fontSize: 13, padding: '8px 12px', borderRadius: 6, border: '1px solid #1e2d45', background: '#0b1220', color: '#e2e8f0' }} />
        </div>

        <div>
          <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>Category</label>
          <select value={category} onChange={e => setCategory(e.target.value)}
            style={{ fontSize: 13, padding: '8px 12px', borderRadius: 6, border: '1px solid #1e2d45', background: '#0b1220', color: '#e2e8f0' }}>
            <option value="">All Categories</option>
            {['malware','network','file','system','edr','usb','isolation','other'].map(c =>
              <option key={c} value={c}>{c}</option>
            )}
          </select>
        </div>

        <div>
          <label style={{ fontSize: 11, color: '#64748b', display: 'block', marginBottom: 4 }}>Severity</label>
          <select value={severity} onChange={e => setSeverity(e.target.value)}
            style={{ fontSize: 13, padding: '8px 12px', borderRadius: 6, border: '1px solid #1e2d45', background: '#0b1220', color: '#e2e8f0' }}>
            <option value="">All Severities</option>
            {['critical','high','medium','low'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>

        <button onClick={() => search(1)} disabled={loading} style={{
          padding: '8px 20px', borderRadius: 6, border: 'none', cursor: 'pointer', fontSize: 13,
          fontWeight: 600, background: '#38bdf8', color: '#0b1220'
        }}>
          {loading ? 'Searching…' : '🔍 Search'}
        </button>
      </div>

      {/* Results Table */}
      <div style={{ background: '#0f1b2e', border: '1px solid #1e2d45', borderRadius: 10, overflow: 'hidden' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e2d45', display: 'flex', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 15, fontWeight: 600, color: '#e2e8f0' }}>Investigation Security Events</span>
          <span style={{ fontSize: 12, color: '#64748b' }}>{total} total matches</span>
        </div>

        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: '#0b1220', borderBottom: '1px solid #1e2d45', color: '#64748b' }}>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Description</th>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Severity</th>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Category</th>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Source IP</th>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Company</th>
              <th style={{ padding: '12px 16px', fontWeight: 600 }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {alerts.length === 0 ? (
              <tr>
                <td colSpan={6} style={{ padding: 40, textAlign: 'center', color: '#64748b' }}>
                  {loading ? 'Searching...' : 'No security events found matching criteria.'}
                </td>
              </tr>
            ) : alerts.map((a, i) => (
              <tr key={a._id || i} onClick={() => setSelectedAlert(a)} style={{
                borderBottom: '1px solid #1e2d45', color: '#cbd5e1', cursor: 'pointer',
                background: selectedAlert?._id === a._id ? 'rgba(56, 189, 248, 0.1)' : 'transparent'
              }}>
                <td style={{ padding: '12px 16px', color: '#f1f5f9', fontWeight: 500 }}>
                  {CAT_ICON[a.eventCategory] || '●'} {a.description || 'Security Event'}
                </td>
                <td style={{ padding: '12px 16px' }}>
                  <Badge text={a.severity?.toUpperCase()} color={SEV[a.severity]} bg={SEVBG[a.severity]} />
                </td>
                <td style={{ padding: '12px 16px', color: '#94a3b8' }}>{a.eventCategory || '—'}</td>
                <td style={{ padding: '12px 16px', fontFamily: 'monospace', color: '#38bdf8' }}>{a.srcip || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#cbd5e1' }}>{a.companyId?.name || '—'}</td>
                <td style={{ padding: '12px 16px', color: '#64748b' }}>{new Date(a.createdAt).toLocaleString()}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
