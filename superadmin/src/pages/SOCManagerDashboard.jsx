import { useEffect, useState } from 'react';
import api from '../api/axios';

/* ── Shared design tokens ── */
const clr = {
  bg: '#050e1d',
  panel: 'rgba(13,24,42,0.92)',
  border: '#1a3356',
  borderBright: '#2563eb',
  accent: '#38bdf8',
  accentPurple: '#a78bfa',
  accentGreen: '#34d399',
  accentRed: '#fb7185',
  accentYellow: '#facc15',
  accentOrange: '#fb923c',
  text: '#f1f5f9',
  muted: '#64748b',
  sub: '#94a3b8',
};

const panel = {
  background: clr.panel,
  backdropFilter: 'blur(14px)',
  border: '1px solid #1a3356',
  borderRadius: 14,
  padding: 20,
};

const inp = {
  width: '100%',
  boxSizing: 'border-box',
  padding: '10px 14px',
  borderRadius: 8,
  border: '1px solid #1a3356',
  background: '#040c1a',
  color: '#f1f5f9',
  outline: 'none',
  fontSize: 13,
  transition: 'all 0.2s',
};

const btn = (extra = {}) => ({
  border: 0,
  borderRadius: 8,
  padding: '8px 16px',
  background: 'linear-gradient(135deg, #0891b2 0%, #0284c7 100%)',
  color: '#fff',
  fontWeight: 700,
  cursor: 'pointer',
  fontSize: 12,
  display: 'inline-flex',
  alignItems: 'center',
  gap: 6,
  transition: 'all 0.2s',
  ...extra,
});

const badge = (bg, color, border = 'transparent') => ({
  background: bg,
  color,
  border: '1px solid ' + border,
  borderRadius: 999,
  padding: '3px 10px',
  fontSize: 11,
  fontWeight: 800,
  whiteSpace: 'nowrap',
  display: 'inline-flex',
  alignItems: 'center',
  gap: 4,
});

const statusBadge = (status) => {
  if (status === 'suspended') return badge('rgba(127,29,29,0.55)', '#fca5a5', '#991b1b');
  if (status === 'locked') return badge('rgba(124,45,18,0.55)', '#fdba74', '#9a3412');
  if (status === 'invited') return badge('rgba(113,63,18,0.55)', '#fde047', '#854d0e');
  if (status === 'expired') return badge('rgba(50,20,80,0.55)', '#e9d5ff', '#6d28d9');
  return badge('rgba(6,78,59,0.55)', '#34d399', '#065f46');
};

function StatCard({ label, value, color, icon, sub }) {
  return (
    <div style={{ ...panel, padding: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <small style={{ color: clr.muted, fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>{label}</small>
        <span style={{ fontSize: 16 }}>{icon}</span>
      </div>
      <div style={{ color: color || clr.accent, fontSize: 26, fontWeight: 900, lineHeight: 1.1 }}>{value}</div>
      {sub && <small style={{ color: clr.muted, fontSize: 10 }}>{sub}</small>}
    </div>
  );
}

function SectionHead({ title, right }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
      <h4 style={{ margin: 0, color: '#38bdf8', fontSize: 13, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.5 }}>{title}</h4>
      {right}
    </div>
  );
}

const sevColor = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8', info: '#a78bfa' };
function SevPill({ sev }) {
  const c = sevColor[sev?.toLowerCase()] || '#94a3b8';
  return <span style={{ background: c + '22', color: c, border: '1px solid ' + c + '44', borderRadius: 999, padding: '2px 9px', fontSize: 10, fontWeight: 800, textTransform: 'uppercase' }}>{sev || 'info'}</span>;
}

function WorkloadBar({ pct }) {
  const barColor = pct > 80 ? 'linear-gradient(90deg, #f87171, #ef4444)' : pct > 50 ? 'linear-gradient(90deg, #facc15, #eab308)' : 'linear-gradient(90deg, #34d399, #10b981)';
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: '#64748b', marginBottom: 3 }}>
        <span>Capacity used</span><b style={{ color: pct > 80 ? '#fb7185' : pct > 50 ? '#facc15' : '#34d399' }}>{pct}%</b>
      </div>
      <div style={{ background: '#091525', height: 7, borderRadius: 4, overflow: 'hidden', border: '1px solid #1a3356' }}>
        <div style={{ background: barColor, height: '100%', width: Math.min(pct, 100) + '%', transition: 'width 0.4s' }} />
      </div>
    </div>
  );
}

export default function SOCManagerDashboard({ managerId, companyId, onBack, apiBase = '/super-admin/soc-managers', canControl = true }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [tab, setTab] = useState('overview');
  const [notice, setNotice] = useState({ type: '', text: '' });
  const [busy, setBusy] = useState('');
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMsg, setChatMsg] = useState('');
  const [chatBusy, setChatBusy] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      let endpoint = (managerId && managerId !== 'undefined') ? `${apiBase}/${managerId}` : '/soc-manager/dashboard';
      const res = await api.get(endpoint);
      setData(res.data);
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Failed to load SOC Manager details' });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, [managerId, companyId]);

  const act = async (endpoint, method = 'post', body = {}, label = '') => {
    setBusy(label);
    setNotice({ type: '', text: '' });
    try {
      await api[method](endpoint, body);
      setNotice({ type: 'success', text: 'Action completed successfully.' });
      load();
    } catch (e) {
      setNotice({ type: 'error', text: e.response?.data?.message || 'Action failed' });
    } finally {
      setBusy('');
    }
  };

  const handleSuspend = () => {
    const reason = prompt('Enter suspension reason:');
    if (!reason) return;
    act(apiBase + '/' + managerId + '/suspend', 'post', { reason }, 'suspend');
  };

  const handleReactivate = () => act(apiBase + '/' + managerId + '/reactivate', 'post', {}, 'reactivate');
  const handleRevoke = () => {
    if (!confirm('Revoke all active login sessions?')) return;
    act(apiBase + '/' + managerId + '/revoke-sessions', 'post', {}, 'revoke');
  };

  const mgr = data?.manager;
  const companies = data?.assignedCompanies || [];
  const analysts = data?.analysts || [];
  const auditLogs = data?.auditLogs || [];
  const activeAlerts = data?.activeAlerts || [];
  const pct = mgr ? Math.round((activeAlerts.length / (mgr.maxWorkload || 10)) * 100) : 0;

  const l1 = analysts.filter(a => a.role === 'l1_analyst').length;
  const l2 = analysts.filter(a => a.role === 'l2_analyst').length;
  const l3 = analysts.filter(a => a.role === 'l3_analyst').length;
  const l4 = analysts.filter(a => a.role === 'l4_analyst').length;
  const critAlerts = activeAlerts.filter(a => a.severity === 'critical').length;

  const TABS = [
    { id: 'overview', label: '📊 Overview' },
    { id: 'companies', label: '🏢 Companies (' + companies.length + ')' },
    { id: 'analysts', label: '👥 Analysts (' + analysts.length + ')' },
    { id: 'alerts', label: '🚨 Active Alerts (' + activeAlerts.length + ')' },
    { id: 'audit', label: '🛡️ Audit Trail (' + auditLogs.length + ')' },
  ];

  return (
    <div style={{ minHeight: '100vh', background: 'transparent', padding: 0 }}>
      {/* Back bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 22 }}>
        <button onClick={onBack} style={btn({ background: '#0d1e35', border: '1px solid #1a3356', color: '#94a3b8' })}>
          ← Back to SOC Managers
        </button>
        {mgr && (
          <>
            <div style={{ width: 1, height: 24, background: '#1a3356' }} />
            <span style={{ color: '#64748b', fontSize: 13 }}>SOC Manager</span>
            <span style={{ color: '#60a5fa', fontSize: 13 }}>›</span>
            <b style={{ color: '#f1f5f9', fontSize: 14 }}>{mgr.name || mgr.email}</b>
          </>
        )}
        <div style={{ flex: 1 }} />
        <button onClick={load} style={btn({ background: '#0d1e35', border: '1px solid #1a3356', color: '#94a3b8' })}>
          🔄 Refresh
        </button>
      </div>

      {notice.text && (
        <div style={{ padding: '12px 16px', borderRadius: 9, marginBottom: 16, fontSize: 13, fontWeight: 700, color: notice.type === 'error' ? '#fca5a5' : '#34d399', background: notice.type === 'error' ? 'rgba(127,29,29,0.4)' : 'rgba(6,78,59,0.4)', border: '1px solid ' + (notice.type === 'error' ? '#7f1d1d' : '#059669') }}>
          {notice.text}
        </div>
      )}

      {loading ? (
        <div style={{ ...panel, padding: 60, textAlign: 'center', color: '#64748b' }}>
          <div style={{ fontSize: 32, marginBottom: 12 }}>⏳</div>
          Loading full SOC Manager telemetry…
        </div>
      ) : !mgr ? (
        <div style={{ ...panel, padding: 60, textAlign: 'center', color: '#64748b' }}>SOC Manager not found.</div>
      ) : (
        <>
          {/* HERO HEADER */}
          <div style={{ ...panel, marginBottom: 20, background: 'linear-gradient(135deg, #0a1628 0%, #071020 100%)', border: '1px solid rgba(37,99,235,0.3)', boxShadow: '0 0 40px rgba(37,99,235,0.12)' }}>
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 20, flexWrap: 'wrap' }}>
              <div style={{ width: 70, height: 70, borderRadius: 16, background: 'linear-gradient(135deg, #1d4ed8 0%, #0284c7 100%)', color: '#fff', display: 'grid', placeItems: 'center', fontSize: 28, fontWeight: 900, boxShadow: '0 0 24px rgba(37,99,235,0.45)', flexShrink: 0 }}>
                {(mgr.name || mgr.email || 'S').charAt(0).toUpperCase()}
              </div>
              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 4 }}>
                  <h2 style={{ margin: 0, color: '#f1f5f9', fontSize: 22, fontWeight: 900 }}>{mgr.name || '—'}</h2>
                  <span style={badge('#0f2b48', '#38bdf8', '#1d4ed8')}>SOC Manager</span>
                  <span style={statusBadge(mgr.accountStatus)}>{(mgr.accountStatus || 'active').toUpperCase()}</span>
                </div>
                <div style={{ color: '#94a3b8', fontSize: 13, marginBottom: 6 }}>
                  ✉️ {mgr.email} · 🆔 {String(mgr._id).slice(-8)}
                  {mgr.createdAt && (' · 📅 Joined ' + new Date(mgr.createdAt).toLocaleDateString())}
                </div>
                <WorkloadBar pct={pct} />
              </div>
              {canControl && (
                <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignSelf: 'flex-start' }}>
                  <button onClick={() => setChatOpen(true)} style={btn({ background: '#0f766e' })}>💬 Chat</button>
                  {mgr.accountStatus === 'suspended' ? (
                    <button disabled={busy === 'reactivate'} onClick={handleReactivate} style={btn({ background: '#166534' })}>
                      {busy === 'reactivate' ? '…' : '✅ Reactivate'}
                    </button>
                  ) : (
                    <button disabled={busy === 'suspend'} onClick={handleSuspend} style={btn({ background: '#7f1d1d' })}>
                      {busy === 'suspend' ? '…' : '⛔ Suspend'}
                    </button>
                  )}
                  <button disabled={busy === 'revoke'} onClick={handleRevoke} style={btn({ background: '#450a0a', border: '1px solid #7f1d1d', color: '#fca5a5' })}>
                    {busy === 'revoke' ? '…' : '🔑 Revoke Sessions'}
                  </button>
                </div>
              )}
            </div>
          </div>

          {/* STAT CARDS */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12, marginBottom: 20 }}>
            <StatCard label="Companies" value={companies.length} icon="🏢" color="#67e8f9" sub="Active scope" />
            <StatCard label="Total Analysts" value={analysts.length} icon="👥" color="#c4b5fd" sub={'L1:' + l1 + ' L2:' + l2 + ' L3:' + l3 + ' L4:' + l4} />
            <StatCard label="Active Alerts" value={activeAlerts.length} icon="🚨" color="#fb7185" sub={critAlerts + ' critical'} />
            <StatCard label="Capacity" value={activeAlerts.length + '/' + (mgr.maxWorkload || 10)} icon="📊" color={pct > 80 ? '#fb7185' : '#34d399'} sub={pct + '% used'} />
            <StatCard label="Audit Events" value={auditLogs.length} icon="🛡️" color="#facc15" sub="Last 20 events" />
            <StatCard label="Account Status" value={mgr.accountStatus || 'active'} icon="🔒" color={mgr.accountStatus === 'suspended' ? '#fca5a5' : '#34d399'} />
          </div>

          {/* TABS */}
          <div style={{ display: 'flex', gap: 6, marginBottom: 18, overflowX: 'auto', paddingBottom: 2 }}>
            {TABS.map(t => (
              <button key={t.id} onClick={() => setTab(t.id)} style={btn({
                background: tab === t.id ? 'linear-gradient(135deg, #1d4ed8, #2563eb)' : '#0a1828',
                border: '1px solid ' + (tab === t.id ? '#3b82f6' : '#1a3356'),
                color: tab === t.id ? '#fff' : '#94a3b8',
                padding: '8px 14px',
                fontSize: 12,
                whiteSpace: 'nowrap',
              })}>
                {t.label}
              </button>
            ))}
          </div>

          {/* TAB: OVERVIEW */}
          {tab === 'overview' && (
            <div style={{ display: 'grid', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
                <div style={panel}>
                  <SectionHead title="Account & Governance" />
                  <div style={{ display: 'grid', gap: 12, fontSize: 13 }}>
                    {[
                      { label: 'Official Email', value: mgr.email, note: '🔒 Read-only, cannot be changed' },
                      { label: 'Platform Role', value: 'SOC Manager (soc_manager)', color: '#67e8f9' },
                      { label: 'Account Status', value: mgr.accountStatus || 'active', color: mgr.accountStatus === 'suspended' ? '#fca5a5' : '#34d399' },
                      { label: 'Max Workload Capacity', value: (mgr.maxWorkload || 10) + ' items', color: '#a78bfa' },
                      { label: 'Account Created', value: mgr.createdAt ? new Date(mgr.createdAt).toLocaleString() : '—' },
                      { label: 'Last Updated', value: mgr.updatedAt ? new Date(mgr.updatedAt).toLocaleString() : '—' },
                    ].map(({ label, value, note, color }) => (
                      <div key={label} style={{ borderBottom: '1px solid rgba(26,51,86,0.4)', paddingBottom: 10 }}>
                        <div style={{ color: '#64748b', fontSize: 10, fontWeight: 700, textTransform: 'uppercase', marginBottom: 3 }}>{label}</div>
                        <div style={{ color: color || '#f1f5f9', fontWeight: 700 }}>{value}</div>
                        {note && <div style={{ color: '#38bdf888', fontSize: 10, marginTop: 2 }}>{note}</div>}
                      </div>
                    ))}
                  </div>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <div style={panel}>
                    <SectionHead title="Workload Analytics" />
                    <WorkloadBar pct={pct} />
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, marginTop: 14 }}>
                      {[
                        { label: 'Open Alerts', val: activeAlerts.length, c: '#fb7185' },
                        { label: 'Critical', val: critAlerts, c: '#f87171' },
                        { label: 'Analysts', val: analysts.length, c: '#c4b5fd' },
                        { label: 'Companies', val: companies.length, c: '#67e8f9' },
                      ].map(({ label, val, c }) => (
                        <div key={label} style={{ background: '#091525', borderRadius: 10, padding: 12, border: '1px solid #1a3356' }}>
                          <div style={{ color: '#64748b', fontSize: 10, fontWeight: 700, textTransform: 'uppercase' }}>{label}</div>
                          <div style={{ color: c, fontSize: 22, fontWeight: 900 }}>{val}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div style={panel}>
                    <SectionHead title="Analyst Team Breakdown" />
                    <div style={{ display: 'grid', gap: 8 }}>
                      {[
                        { role: 'L1 Analyst', count: l1, color: '#38bdf8' },
                        { role: 'L2 Analyst', count: l2, color: '#a78bfa' },
                        { role: 'L3 Analyst', count: l3, color: '#fb923c' },
                        { role: 'L4 Threat Intel', count: l4, color: '#fb7185' },
                      ].map(({ role, count, color }) => (
                        <div key={role} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#091525', borderRadius: 8, padding: '8px 12px', border: '1px solid #1a3356' }}>
                          <span style={{ color: '#94a3b8', fontSize: 12 }}>{role}</span>
                          <span style={{ color, fontWeight: 900, fontSize: 14 }}>{count}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>

              {activeAlerts.length > 0 && (
                <div style={panel}>
                  <SectionHead title="Recent Active Alerts (Preview)" right={<button onClick={() => setTab('alerts')} style={btn({ padding: '4px 10px', fontSize: 11 })}>View All</button>} />
                  <div style={{ display: 'grid', gap: 8 }}>
                    {activeAlerts.slice(0, 5).map(a => (
                      <div key={a._id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#070f1e', padding: '10px 14px', borderRadius: 9, border: '1px solid #1a3356' }}>
                        <div>
                          <b style={{ color: '#f1f5f9', fontSize: 13 }}>{a.title || a.event || a.type || 'Alert'}</b>
                          <div style={{ color: '#64748b', fontSize: 11, marginTop: 2 }}>{a.companyId?.name || String(a.companyId || '') || '—'}</div>
                        </div>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          <SevPill sev={a.severity} />
                          <span style={{ color: '#64748b', fontSize: 10 }}>{a.createdAt ? new Date(a.createdAt).toLocaleDateString() : ''}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB: COMPANIES */}
          {tab === 'companies' && (
            <div style={panel}>
              <SectionHead title={'Assigned Companies (' + companies.length + ')'} />
              {companies.length === 0 ? (
                <div style={{ color: '#64748b', padding: 30, textAlign: 'center', fontSize: 13 }}>No companies assigned to this SOC Manager yet.</div>
              ) : (
                <div style={{ display: 'grid', gap: 10 }}>
                  {companies.map(c => (
                    <div key={c._id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, background: '#070f1e', padding: '14px 18px', borderRadius: 10, border: '1px solid #1a3356' }}>
                      <div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                          <div style={{ width: 36, height: 36, borderRadius: 9, background: 'linear-gradient(135deg, #1e3a5f, #0f2748)', color: '#38bdf8', display: 'grid', placeItems: 'center', fontWeight: 900, fontSize: 15, border: '1px solid #1a3356' }}>
                            {(c.name || 'C').charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <b style={{ color: '#f1f5f9', fontSize: 14 }}>{c.name}</b>
                            <div style={{ color: '#64748b', fontSize: 11, marginTop: 1 }}>Tenant: {c.tenantId || 'Main'} · ID: {String(c._id).slice(-6)}</div>
                          </div>
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <span style={badge('#064e3b', '#34d399', '#065f46')}>✅ Active Scope</span>
                        <span style={badge('#0f2b48', '#38bdf8', '#1e3a5f')}>{c.status || 'active'}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB: ANALYSTS */}
          {tab === 'analysts' && (
            <div style={panel}>
              <SectionHead title={'Managed Analyst Team (' + analysts.length + ')'} />
              {analysts.length === 0 ? (
                <div style={{ color: '#64748b', padding: 30, textAlign: 'center', fontSize: 13 }}>No analysts currently operating under this manager.</div>
              ) : (
                <div style={{ display: 'grid', gap: 8 }}>
                  {analysts.map(a => {
                    const roleColor = { l1_analyst: '#38bdf8', l2_analyst: '#a78bfa', l3_analyst: '#fb923c', l4_analyst: '#fb7185' };
                    const rc = roleColor[a.role] || '#94a3b8';
                    return (
                      <div key={a._id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, background: '#070f1e', padding: '12px 16px', borderRadius: 10, border: '1px solid #1a3356' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                          <div style={{ width: 38, height: 38, borderRadius: 10, background: rc + '22', border: '1px solid ' + rc + '55', color: rc, display: 'grid', placeItems: 'center', fontWeight: 900, fontSize: 16 }}>
                            {(a.name || a.email || 'A').charAt(0).toUpperCase()}
                          </div>
                          <div>
                            <b style={{ color: '#f1f5f9', fontSize: 13 }}>{a.name || '—'}</b>
                            <div style={{ color: '#64748b', fontSize: 11, marginTop: 1 }}>{a.email}</div>
                          </div>
                        </div>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                          <span style={badge(rc + '22', rc, rc + '55')}>{(a.role || '').replace('_', ' ').toUpperCase()}</span>
                          <span style={statusBadge(a.accountStatus)}>{(a.accountStatus || 'active').toUpperCase()}</span>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          )}

          {/* TAB: ACTIVE ALERTS */}
          {tab === 'alerts' && (
            <div style={panel}>
              <SectionHead title={'Active Alerts (' + activeAlerts.length + ')'} />
              {activeAlerts.length === 0 ? (
                <div style={{ color: '#64748b', padding: 30, textAlign: 'center', fontSize: 13 }}>🟢 No active alerts in this manager's company scope.</div>
              ) : (
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                    <thead>
                      <tr style={{ background: 'linear-gradient(180deg, #0f1f38 0%, #091829 100%)', color: '#7dd3fc', textAlign: 'left', borderBottom: '1px solid #1a3356' }}>
                        {['Alert', 'Severity', 'Status', 'Company', 'Time', 'Assigned'].map(h => (
                          <th key={h} style={{ padding: '12px 14px', fontWeight: 800, textTransform: 'uppercase', fontSize: 10, letterSpacing: 0.5 }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {activeAlerts.map(a => (
                        <tr key={a._id} style={{ borderTop: '1px solid rgba(26,51,86,0.4)' }}>
                          <td style={{ padding: '11px 14px' }}>
                            <b style={{ color: '#f1f5f9' }}>{a.title || a.event || a.type || 'Alert'}</b>
                            <div style={{ color: '#64748b', fontSize: 10, marginTop: 2 }}>ID: {String(a._id).slice(-6)}</div>
                          </td>
                          <td style={{ padding: '11px 14px' }}><SevPill sev={a.severity} /></td>
                          <td style={{ padding: '11px 14px' }}>
                            <span style={badge(a.status === 'investigating' ? 'rgba(37,99,235,0.3)' : 'rgba(6,78,59,0.3)', a.status === 'investigating' ? '#93c5fd' : '#34d399')}>
                              {a.status || 'open'}
                            </span>
                          </td>
                          <td style={{ padding: '11px 14px', color: '#94a3b8' }}>{a.companyId?.name || String(a.companyId || '').slice(-6) || '—'}</td>
                          <td style={{ padding: '11px 14px', color: '#64748b', fontSize: 11 }}>{a.createdAt ? new Date(a.createdAt).toLocaleString() : '—'}</td>
                          <td style={{ padding: '11px 14px' }}>
                            {a.assignedTo ? (
                              <span style={badge('#1e3a5f', '#93c5fd', '#2563eb')}>Assigned</span>
                            ) : (
                              <span style={badge('rgba(127,29,29,0.3)', '#fca5a5')}>Unassigned</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* TAB: AUDIT TRAIL */}
          {tab === 'audit' && (
            <div style={panel}>
              <SectionHead title="Audit & Security Trail" />
              {auditLogs.length === 0 ? (
                <div style={{ color: '#64748b', padding: 30, textAlign: 'center', fontSize: 13 }}>No audit events recorded for this account.</div>
              ) : (
                <div style={{ display: 'grid', gap: 8 }}>
                  {auditLogs.map((log, i) => (
                    <div key={log._id || i} style={{ background: '#070f1e', padding: '12px 16px', borderRadius: 9, border: '1px solid #1a3356', fontSize: 12 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, flexWrap: 'wrap' }}>
                        <div>
                          <b style={{ color: '#38bdf8' }}>{log.action}</b>
                          {log.actorId && <span style={{ color: '#64748b', marginLeft: 8 }}>by {log.actorId?.name || log.actorId?.email || String(log.actorId).slice(-6)}</span>}
                        </div>
                        <span style={{ color: '#64748b', fontSize: 11, whiteSpace: 'nowrap' }}>{log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'}</span>
                      </div>
                      {log.metadata?.reason && <div style={{ color: '#fca5a5', fontSize: 11, marginTop: 5 }}>Reason: {log.metadata.reason}</div>}
                      {log.ipAddress && <div style={{ color: '#64748b', fontSize: 10, marginTop: 3 }}>IP: {log.ipAddress}</div>}
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      {/* Chat Modal */}
      {chatOpen && (
        <div style={{ position: 'fixed', inset: 0, zIndex: 500, background: 'rgba(2,6,23,0.8)', backdropFilter: 'blur(6px)', display: 'grid', placeItems: 'center' }}>
          <div style={{ ...panel, background: '#091728', border: '1px solid #0f766e', width: 'min(480px, 92vw)', padding: 26, boxShadow: '0 0 32px rgba(0,0,0,0.8)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 16 }}>
              <h3 style={{ margin: 0, color: '#f1f5f9', fontSize: 16, fontWeight: 900 }}>💬 Message {mgr?.name}</h3>
              <button onClick={() => setChatOpen(false)} style={btn({ background: '#1e293b', border: '1px solid #334155', padding: '4px 10px', fontSize: 11 })}>✕</button>
            </div>
            <textarea
              rows={4}
              value={chatMsg}
              onChange={e => setChatMsg(e.target.value)}
              placeholder="Type your message…"
              style={{ ...inp, resize: 'vertical', height: 100 }}
            />
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 14, gap: 10 }}>
              <button onClick={() => setChatOpen(false)} style={btn({ background: '#1e293b', border: '1px solid #334155' })}>Cancel</button>
              <button disabled={!chatMsg.trim() || chatBusy} onClick={async () => {
                setChatBusy(true);
                try {
                  await api.post('/soc-chat/messages', { recipientId: mgr._id, message: chatMsg.trim() });
                  setChatMsg(''); setChatOpen(false);
                  setNotice({ type: 'success', text: 'Message sent successfully.' });
                } catch (e) {
                  setNotice({ type: 'error', text: e.response?.data?.message || 'Message failed' });
                  setChatOpen(false);
                } finally { setChatBusy(false); }
              }} style={btn({ background: '#0f766e' })}>
                {chatBusy ? 'Sending…' : 'Send Message'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
