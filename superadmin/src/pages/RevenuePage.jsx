import React, { useEffect, useState, useCallback } from 'react';
import api from '../api/axios';

const formatINR = n => `₹${Number(n || 0).toLocaleString('en-IN')}`;
const paymentCounts = p => {
  const useAdded = p?.isUpgrade || ['upgrade', 'renewal'].includes(p?.source);
  return {
    systems: Number(useAdded ? p?.addedSystems : p?.systemCount) || 0,
    servers: Number(useAdded ? p?.addedServers : p?.serverCount) || 0,
    phones: Number(useAdded ? p?.addedPhones : p?.phoneCount) || 0,
  };
};
const formatPaymentCounts = p => {
  const c = paymentCounts(p);
  return [
    c.systems > 0 ? `${c.systems} sys` : '',
    c.servers > 0 ? `${c.servers} srv` : '',
    c.phones > 0 ? `${c.phones} ph` : '',
  ].filter(Boolean).join(' · ') || '0';
};
const formatCompanyLicenses = c => {
  const sys = Number(c.plan?.systemCount || c.systemCount || 0);
  const srv = Number(c.plan?.serverCount || c.serverCount || 0);
  const phn = Number(c.plan?.phoneCount || c.phoneCount || 0);
  return [
    sys > 0 ? `${sys} sys` : '',
    srv > 0 ? `${srv} srv` : '',
    phn > 0 ? `${phn} ph` : '',
  ].filter(Boolean).join(' · ') || '0';
};

// ── Mini bar chart ─────────────────────────────────────────────────────────────
function BarChart({ data = [], valueKey = 'revenue', labelKey = '_id', color = '#3b82f6' }) {
  if (!data.length) return <div style={{ color: '#1e3a5f', fontSize: 12, textAlign: 'center', padding: 20 }}>No data</div>;
  const max = Math.max(...data.map(d => d[valueKey] || 0), 1);
  return (
    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 100, padding: '0 4px' }}>
      {data.map((d, i) => (
        <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
          <div style={{ fontSize: 9, color: '#1e40af' }}>
            {d[valueKey] >= 1000 ? `${Math.round(d[valueKey]/1000)}k` : d[valueKey] || 0}
          </div>
          <div style={{ width: '100%', height: `${Math.max(4, ((d[valueKey]||0)/max)*80)}px`,
            background: color, borderRadius: '2px 2px 0 0',
            transition: 'height .5s ease' }} />
          <div style={{ fontSize: 8, color: '#64748b', textAlign: 'center' }}>
            {String(d[labelKey] || '').slice(-7)}
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Stat card ──────────────────────────────────────────────────────────────────
function StatCard({ icon, label, value, sub, color = '#3b82f6', growth }) {
  return (
    <div style={{ background: '#0c1a2e', border: `1px solid ${color}33`, borderRadius: 10, padding: '18px 20px', flex: '1', minWidth: 160 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
        <span style={{ fontSize: 22 }}>{icon}</span>
        {growth != null && (
          <span style={{ fontSize: 11, fontWeight: 700,
            color: growth >= 0 ? '#22c55e' : '#f87171',
            background: growth >= 0 ? '#14532d22' : '#7f1d1d22',
            padding: '2px 6px', borderRadius: 4 }}>
            {growth >= 0 ? '+' : ''}{growth}%
          </span>
        )}
      </div>
      <div style={{ fontSize: 28, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 11, color: '#1e40af', marginTop: 4 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

// ── Main Revenue Page ──────────────────────────────────────────────────────────
export default function RevenuePage() {
  const [analytics,   setAnalytics]   = useState(null);
  const [topCompanies,setTopCompanies]= useState([]);
  const [history,     setHistory]     = useState([]);
  const [loading,     setLoading]     = useState(true);
  const [activeTab,   setActiveTab]   = useState('overview');
  const [error,       setError]       = useState('');

  const loadData = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const [aRes, tRes, hRes] = await Promise.all([
        api.get('/superadmin/revenue/analytics'),
        api.get('/superadmin/revenue/top-companies'),
        api.get('/superadmin/revenue/history?limit=20'),
      ]);
      setAnalytics(aRes.data);
      setTopCompanies(tRes.data || []);
      setHistory(hRes.data.payments || []);
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load revenue data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadData(); }, [loadData]);

  const a = analytics || {};

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 300, color: '#1e40af' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 10 }}>💰</div>
        <div>Loading revenue analytics…</div>
      </div>
    </div>
  );

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 22, color: '#e9d5ff' }}>SOC Revenue Command</h2>
          <div style={{ fontSize: 12, color: '#8b5cf6', marginTop: 4 }}>
            Platform MRR, ARR, collections, company revenue, and payment history
          </div>
        </div>
        <button onClick={loadData} style={{ fontSize: 11, padding: '6px 14px', borderRadius: 6,
          border: '1px solid #312e81', background: '#1e1b4b', color: '#c4b5fd', cursor: 'pointer' }}>
          ↺ Refresh
        </button>
      </div>

      {error && <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '10px 14px',
        borderRadius: 6, marginBottom: 16, fontSize: 13 }}>⚠ {error}</div>}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 20, borderBottom: '1px solid #1e3a5f' }}>
        {[['overview','📊 Overview'],['companies','🏢 Companies'],['history','📜 History']].map(([t,l]) => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '9px 18px', fontSize: 12, cursor: 'pointer', border: 'none', background: 'none',
            fontWeight: activeTab === t ? 700 : 400,
            color: activeTab === t ? '#60a5fa' : '#64748b',
            borderBottom: activeTab === t ? '2px solid #3b82f6' : '2px solid transparent', marginBottom: -1,
          }}>{l}</button>
        ))}
      </div>

      {/* Overview Tab */}
      {activeTab === 'overview' && (
        <>
          {/* KPI Cards */}
          <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
            <StatCard icon="📈" label="MRR (Monthly Recurring Revenue)"
              value={formatINR(a.mrr)} sub={`${a.currentMonthPayments || 0} captured payment${a.currentMonthPayments === 1 ? '' : 's'} this month`}
              color="#22c55e" growth={a.mrrGrowth} />
            <StatCard icon="📅" label="ARR (Annual Recurring Revenue)"
              value={formatINR(a.arr)} sub="Projected from current month collection"
              color="#3b82f6" />
            <StatCard icon="🏢" label="Active Companies"
              value={a.activeCompanies ?? '—'} sub={`${a.activeLicenses || 0} active licenses`}
              color="#a78bfa" />
            <StatCard icon="💳" label="Collected This Year"
              value={formatINR(a.yearlyRevenue)} sub={`${a.yearlyPayments || 0} captured payments`}
              color="#f59e0b" />
          </div>

          {/* Revenue trend chart */}
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', marginBottom: 20 }}>
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
              padding: '16px 20px', flex: 2, minWidth: 300 }}>
              <div style={{ fontSize: 13, color: '#93c5fd', fontWeight: 600, marginBottom: 12 }}>
                Monthly Revenue Trend (Last 12 months)
              </div>
              <BarChart data={a.monthlyTrend || []} valueKey="revenue" labelKey="_id" color="#22c55e" />
              {(!a.monthlyTrend?.length) && (
                <div style={{ fontSize: 11, color: '#1e3a5f', textAlign: 'center', marginTop: 8 }}>
                  No payment history yet — charts will populate as payments are made
                </div>
              )}
            </div>

            {/* By plan breakdown */}
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
              padding: '16px 20px', flex: 1, minWidth: 200 }}>
              <div style={{ fontSize: 13, color: '#93c5fd', fontWeight: 600, marginBottom: 16 }}>Companies by Plan</div>
              {(a.byPlan || []).map(p => (
                <div key={p._id} style={{ marginBottom: 12 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 12, color: '#e2e8f0', textTransform: 'capitalize' }}>{p._id || 'None'}</span>
                    <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 600 }}>{p.count} co.</span>
                  </div>
                  <div style={{ height: 6, background: '#1e3a5f', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{ height: '100%', borderRadius: 3, background: '#3b82f6',
                      width: `${Math.max(4, ((p.count / Math.max(...(a.byPlan||[]).map(x=>x.count),1))*100))}%` }} />
                  </div>
                  <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                    Licenses: {(p.systems || 0) + (p.servers || 0) + (p.phones || 0)} total
                  </div>
                </div>
              ))}
              {!a.byPlan?.length && (
                <div style={{ fontSize: 12, color: '#1e3a5f' }}>No active companies yet</div>
              )}
            </div>
          </div>
        </>
      )}

      {/* Companies Tab */}
      {activeTab === 'companies' && (
        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#060e1a', borderBottom: '1px solid #1e3a5f' }}>
                {['Company', 'Plan', 'LICENSES', 'Monthly Revenue', 'Total Revenue', 'Status', 'Joined'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '10px 14px', color: '#1e40af', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {topCompanies.length === 0 ? (
                <tr><td colSpan={7} style={{ padding: 30, textAlign: 'center', color: '#1e3a5f' }}>
                  No companies yet
                </td></tr>
              ) : topCompanies.map((c, i) => (
                <tr key={c._id} style={{ borderBottom: '1px solid #060e1a' }}>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ color: '#e2e8f0', fontWeight: 600 }}>{c.name}</div>
                    <div style={{ fontSize: 10, color: '#64748b' }}>{c.email}</div>
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, fontWeight: 700,
                      color: c.plan?.type === 'enterprise' ? '#f59e0b' : c.plan?.type === 'pro' ? '#a78bfa' : '#60a5fa',
                      background: '#1e3a5f' }}>
                      {c.plan?.type || 'none'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: '#93c5fd', fontWeight: 700 }}>{formatCompanyLicenses(c)}</td>
                  <td style={{ padding: '10px 14px', color: '#22c55e', fontWeight: 700 }}>
                    {formatINR(c.monthlyRevenue)}/mo
                  </td>
                  <td style={{ padding: '10px 14px', color: '#f59e0b' }}>{formatINR(c.totalRevenue)}</td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, fontWeight: 700,
                      color: c.status === 'active' ? '#22c55e' : '#f87171',
                      background: c.status === 'active' ? '#14532d22' : '#7f1d1d22' }}>
                      {c.status?.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: '#64748b', fontSize: 11 }}>
                    {new Date(c.createdAt).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* History Tab */}
      {activeTab === 'history' && (
        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ background: '#060e1a', borderBottom: '1px solid #1e3a5f' }}>
                {['Company', 'Plan', 'Amount', 'Licenses', 'Payment ID', 'Date'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '10px 14px', color: '#1e40af', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {history.length === 0 ? (
                <tr><td colSpan={6} style={{ padding: 30, textAlign: 'center', color: '#1e3a5f' }}>
                  No payment history yet
                </td></tr>
              ) : history.map((p, i) => (
                <tr key={i} style={{ borderBottom: '1px solid #060e1a' }}>
                  <td style={{ padding: '10px 14px' }}>
                    <div style={{ color: '#e2e8f0' }}>{p.companyId?.name || p.companyName || '—'}</div>
                    <div style={{ fontSize: 10, color: '#64748b' }}>{p.companyId?.email || ''}</div>
                  </td>
                  <td style={{ padding: '10px 14px' }}>
                    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10,
                      background: '#1e3a5f', color: '#93c5fd', fontWeight: 700 }}>
                      {p.planType || '—'}
                    </span>
                  </td>
                  <td style={{ padding: '10px 14px', color: '#22c55e', fontWeight: 700, fontSize: 14 }}>
                    {formatINR(p.amountInr || (p.amountPaise / 100))}
                  </td>
                  <td style={{ padding: '10px 14px', color: '#93c5fd', fontWeight: 700 }}>{formatPaymentCounts(p)}</td>
                  <td style={{ padding: '10px 14px', color: '#64748b', fontSize: 10, fontFamily: 'monospace' }}>
                    {p.paymentId?.slice(0, 20) || '—'}
                  </td>
                  <td style={{ padding: '10px 14px', color: '#64748b', fontSize: 11 }}>
                    {p.paidAt ? new Date(p.paidAt).toLocaleString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
