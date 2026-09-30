import { useState, useEffect, useRef, useCallback } from 'react';
import api from '../api/axios';
import { io, connectSocket } from '../api/config';
import { useAuth } from '../context/AuthContext';

const DECISION_COLOR = {
  ALLOW: '#10b981', BLOCK: '#ef4444',
  CHALLENGE: '#f59e0b', MANUAL_REVIEW: '#8b5cf6',
};
const RISK_COLOR = { low: '#10b981', medium: '#f59e0b', high: '#f97316', critical: '#ef4444' };

function KpiCard({ label, value, icon, color = '#60a5fa', sub }) {
  return (
    <div style={{ background: 'linear-gradient(135deg,#0c1a2e,#0f2040)', border: '1px solid #1e3a5f', borderRadius: 12, padding: '18px 20px', minWidth: 140 }}>
      <div style={{ fontSize: 22, marginBottom: 6 }}>{icon}</div>
      <div style={{ fontSize: 26, fontWeight: 800, color }}>{value ?? '—'}</div>
      <div style={{ fontSize: 11, color: '#64748b', marginTop: 3 }}>{label}</div>
      {sub && <div style={{ fontSize: 10, color: '#475569', marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function Badge({ text, color }) {
  return (
    <span style={{ background: color + '22', color, border: `1px solid ${color}44`, borderRadius: 5, padding: '2px 8px', fontSize: 11, fontWeight: 700 }}>
      {text}
    </span>
  );
}

export default function FraudDashboardPage() {
  const { user } = useAuth();
  const [selectedCompany, setSelectedCompany] = useState('');
  const [companies, setCompanies] = useState([]);
  const [dash, setDash]         = useState(null);
  const [events, setEvents]     = useState([]);
  const [alerts, setAlerts]     = useState([]);
  const [rules, setRules]       = useState([]);
  const [devices, setDevices]   = useState([]);
  const [loading, setLoading]   = useState(true);
  const [tab, setTab]           = useState('live');
  const [connected, setConnected] = useState(false);
  const [ruleModal, setRuleModal] = useState(false);
  const [newRule, setNewRule]     = useState({ name: '', conditionField: 'riskScore', conditionOperator: 'gte', conditionValue: 70, action: 'CHALLENGE', severity: 'medium', priority: 50 });
  const socketRef = useRef(null);
  const selectedCompanyRef = useRef('');
  const companiesRef = useRef([]);

  useEffect(() => {
    selectedCompanyRef.current = selectedCompany;
  }, [selectedCompany]);

  useEffect(() => {
    companiesRef.current = companies;
  }, [companies]);

  useEffect(() => {
    if (user?.role === 'superadmin') {
      api.get('/superadmin/companies')
        .then(res => {
          const allCompanies = res.data || [];
          const directCompanies = allCompanies.filter(c => !c.partnerId);
          setCompanies(directCompanies);
        })
        .catch(err => console.error('Error fetching companies:', err));
    } else if (user?.role === 'partner_admin') {
      api.get('/partner/companies')
        .then(res => setCompanies(res.data || []))
        .catch(err => console.error('Error fetching companies:', err));
    }
  }, [user]);

  const load = useCallback(async () => {
    try {
      const q = selectedCompany ? `?companyId=${selectedCompany}` : '';
      const qAnd = selectedCompany ? `&companyId=${selectedCompany}` : '';
      const [d, e, a, r, dv] = await Promise.all([
        api.get(`/fraud/dashboard${q}`),
        api.get(`/fraud/events?limit=50${qAnd}`),
        api.get(`/fraud/alerts?limit=30${qAnd}`),
        api.get('/fraud/rules'),
        api.get(`/fraud/devices?limit=30${qAnd}`),
      ]);
      setDash(d.data);
      setEvents(e.data.events || []);
      setAlerts(a.data.alerts || []);
      setRules(r.data.rules || []);
      setDevices(dv.data.devices || []);
    } catch (err) { console.error('[FraudDash]', err.message); }
    finally { setLoading(false); }
  }, [selectedCompany]);

  useEffect(() => {
    load();
    const s = io();
    socketRef.current = s;
    s.emit('join:fraud', { partnerId: user?.partnerId });
    s.on('connect', () => {
      setConnected(true);
      s.emit('join:fraud', { partnerId: user?.partnerId });
    });
    s.on('disconnect', () => setConnected(false));
    s.on('fraud:event', (ev) => {
      const isMatch = selectedCompanyRef.current
        ? ev.companyId === selectedCompanyRef.current
        : companiesRef.current.some(c => c._id === ev.companyId);
      if (isMatch) {
        setEvents(prev => [ev, ...prev].slice(0, 100));
      }
    });
    s.on('fraud:alert', (al) => {
      const isMatch = selectedCompanyRef.current
        ? al.companyId === selectedCompanyRef.current
        : companiesRef.current.some(c => c._id === al.companyId);
      if (isMatch) {
        setAlerts(prev => [al, ...prev].slice(0, 50));
      }
    });
    const disconnectSocket = connectSocket(s);
    return () => {
      s.off('fraud:event').off('fraud:alert');
      disconnectSocket();
    };
  }, [load, user?.partnerId]);

  const deleteRule = async (id) => {
    if (!window.confirm('Delete this rule?')) return;
    await api.delete(`/fraud/rule/${id}`);
    setRules(r => r.filter(x => x._id !== id));
  };

  const saveRule = async () => {
    const { data } = await api.post('/fraud/rule', newRule);
    setRules(r => [...r, data.rule]);
    setRuleModal(false);
    setNewRule({ name: '', conditionField: 'riskScore', conditionOperator: 'gte', conditionValue: 70, action: 'CHALLENGE', severity: 'medium', priority: 50 });
  };

  const k = dash?.kpis || {};

  const tabs = ['live', 'devices', 'alerts', 'rules'];

  return (
    <div style={{ fontFamily: 'Inter,system-ui,sans-serif', color: '#e2e8f0', minHeight: '100vh' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 24 }}>
        <div>
          <h1 style={{ fontSize: 24, fontWeight: 800, color: '#e0f2fe', margin: 0 }}>🛡️ Fraud Intelligence</h1>
          <p style={{ color: '#475569', fontSize: 13, margin: '4px 0 0' }}>Stytch Device Fingerprinting · Real-time Risk Analysis</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          {/* Company Filter Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 12, color: '#94a3b8', fontWeight: 600 }}>Company:</span>
            <select
              value={selectedCompany}
              onChange={e => setSelectedCompany(e.target.value)}
              style={{
                padding: '7px 12px',
                borderRadius: 8,
                border: '1px solid #1e3a5f',
                background: '#0c1a2e',
                color: '#e2e8f0',
                fontSize: 13,
                fontWeight: 600,
                outline: 'none',
                cursor: 'pointer'
              }}
            >
              <option value="">All Companies</option>
              {companies.map(c => (
                <option key={c._id} value={c._id}>{c.name}</option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: connected ? '#10b981' : '#ef4444', display: 'inline-block' }} />
            <span style={{ fontSize: 12, color: connected ? '#10b981' : '#ef4444' }}>{connected ? 'Live' : 'Disconnected'}</span>
          </div>
          {dash?.kpis && <span style={{ fontSize: 11, color: '#334155' }}>Sim mode: {dash.recentEvents?.[0]?.simulatedData ? 'ON' : 'OFF'}</span>}
        </div>
      </div>

      {/* KPI Grid */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, marginBottom: 28 }}>
        <KpiCard label="Total Devices"    value={k.totalDevices}    icon="💻" />
        <KpiCard label="Blocked Devices"  value={k.blockedDevices}  icon="🚫" color="#ef4444" />
        <KpiCard label="High Risk"        value={k.highRiskDevices} icon="⚠️" color="#f97316" />
        <KpiCard label="Trusted"          value={k.trustedDevices}  icon="✅" color="#10b981" />
        <KpiCard label="Open Alerts"      value={k.openAlerts}      icon="🔔" color="#f59e0b" />
        <KpiCard label="Today Logins"     value={k.todayLogins}     icon="🔑" color="#60a5fa" />
        <KpiCard label="Today Blocks"     value={k.todayBlocks}     icon="⛔" color="#ef4444" />
        <KpiCard label="Challenged"       value={k.challengeRequests} icon="🔐" color="#8b5cf6" />
        <KpiCard label="VPN Detected"     value={k.vpnDetected}     icon="🌐" color="#f59e0b" sub="7d" />
        <KpiCard label="TOR Detected"     value={k.torDetected}     icon="🕵️" color="#ef4444" sub="7d" />
        <KpiCard label="New Devices/Day"  value={k.todayNewDevices} icon="📱" color="#34d399" />
        <KpiCard label="MFA Requests"     value={k.todayMfa}        icon="🔢" color="#a78bfa" />
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 6, marginBottom: 20 }}>
        {tabs.map(t => (
          <button key={t} onClick={() => setTab(t)} style={{
            padding: '8px 18px', borderRadius: 8, border: 'none', cursor: 'pointer', fontSize: 13, fontWeight: 600,
            background: tab === t ? 'linear-gradient(135deg,#2563eb,#1d4ed8)' : '#0c1a2e',
            color: tab === t ? '#fff' : '#60a5fa',
          }}>
            {t === 'live' ? '⚡ Live Stream' : t === 'devices' ? '💻 Devices' : t === 'alerts' ? '🔔 Alerts' : '⚙️ Rules'}
          </button>
        ))}
      </div>

      {/* Live Stream Tab */}
      {tab === 'live' && (
        <div style={{ background: '#060e1a', borderRadius: 12, border: '1px solid #1e3a5f', overflow: 'hidden' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid #1e3a5f', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981', animation: 'pulse 2s infinite', display: 'inline-block' }} />
            <span style={{ fontWeight: 700, fontSize: 14 }}>Live Event Stream</span>
            <span style={{ color: '#475569', fontSize: 12 }}>({events.length} events)</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: '#0c1a2e' }}>
                  {['Time','Email','IP','Country','Browser','Risk','Decision','Rules'].map(h => (
                    <th key={h} style={{ padding: '10px 14px', textAlign: 'left', color: '#3b82f6', fontWeight: 700, fontSize: 11, whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {events.map((ev, i) => (
                  <tr key={ev.requestId || ev._id || i} style={{ borderTop: '1px solid #0c1a2e', background: i % 2 === 0 ? 'transparent' : '#060e1a' }}>
                    <td style={{ padding: '9px 14px', color: '#475569', whiteSpace: 'nowrap' }}>{new Date(ev.ts || ev.createdAt).toLocaleTimeString()}</td>
                    <td style={{ padding: '9px 14px', color: '#93c5fd', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ev.email || '—'}</td>
                    <td style={{ padding: '9px 14px', color: '#60a5fa', whiteSpace: 'nowrap' }}>{ev.ip || ev.ipAddress || '—'}</td>
                    <td style={{ padding: '9px 14px', whiteSpace: 'nowrap' }}>{ev.country || '—'}</td>
                    <td style={{ padding: '9px 14px', color: '#94a3b8', whiteSpace: 'nowrap', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis' }}>{ev.browser || '—'}</td>
                    <td style={{ padding: '9px 14px' }}>
                      <span style={{ color: RISK_COLOR[ev.riskLevel] || '#60a5fa', fontWeight: 700 }}>{ev.riskScore ?? '—'}</span>
                    </td>
                    <td style={{ padding: '9px 14px' }}>
                      <Badge text={ev.decision || 'ALLOW'} color={DECISION_COLOR[ev.decision] || '#10b981'} />
                    </td>
                    <td style={{ padding: '9px 14px', color: '#64748b', fontSize: 11, maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.matchedRules?.join(', ') || '—'}
                    </td>
                  </tr>
                ))}
                {events.length === 0 && (
                  <tr><td colSpan={8} style={{ padding: 32, textAlign: 'center', color: '#334155' }}>Waiting for events… Trigger a login to see live data.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Devices Tab */}
      {tab === 'devices' && (
        <div style={{ background: '#060e1a', borderRadius: 12, border: '1px solid #1e3a5f', overflow: 'hidden' }}>
          <div style={{ padding: '14px 20px', borderBottom: '1px solid #1e3a5f' }}>
            <span style={{ fontWeight: 700, fontSize: 14 }}>💻 Device Registry</span>
            <span style={{ color: '#475569', fontSize: 12, marginLeft: 8 }}>({devices.length} devices)</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: '#0c1a2e' }}>
                  {['Fingerprint','Browser','OS','Country','IP','Risk','Status','Logins','Blocks'].map(h => (
                    <th key={h} style={{ padding: '10px 14px', textAlign: 'left', color: '#3b82f6', fontWeight: 700, fontSize: 11, whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {devices.map((d, i) => {
                  const statusColors = { new: '#60a5fa', known: '#10b981', trusted: '#34d399', suspicious: '#f59e0b', blocked: '#ef4444' };
                  return (
                    <tr key={d._id} style={{ borderTop: '1px solid #0c1a2e', background: i % 2 === 0 ? 'transparent' : '#060e1a' }}>
                      <td style={{ padding: '9px 14px', color: '#94a3b8', fontFamily: 'monospace', fontSize: 11 }}>{d.deviceFingerprint?.slice(0, 18)}…</td>
                      <td style={{ padding: '9px 14px', color: '#e2e8f0' }}>{d.browser || '—'}</td>
                      <td style={{ padding: '9px 14px', color: '#94a3b8' }}>{d.os || '—'}</td>
                      <td style={{ padding: '9px 14px' }}>{d.country || '—'}</td>
                      <td style={{ padding: '9px 14px', color: '#60a5fa' }}>{d.lastSeenIp || '—'}</td>
                      <td style={{ padding: '9px 14px' }}>
                        <span style={{ color: RISK_COLOR[d.riskScoreLast >= 90 ? 'critical' : d.riskScoreLast >= 70 ? 'high' : d.riskScoreLast >= 50 ? 'medium' : 'low'] }}>{d.riskScoreLast ?? 0}</span>
                      </td>
                      <td style={{ padding: '9px 14px' }}>
                        <Badge text={d.status || 'new'} color={statusColors[d.status] || '#60a5fa'} />
                      </td>
                      <td style={{ padding: '9px 14px', color: '#60a5fa' }}>{d.totalLogins || 0}</td>
                      <td style={{ padding: '9px 14px', color: '#ef4444' }}>{d.totalBlocks || 0}</td>
                    </tr>
                  );
                })}
                {devices.length === 0 && (
                  <tr><td colSpan={9} style={{ padding: 32, textAlign: 'center', color: '#334155' }}>No devices yet. Devices appear after the first login.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Alerts Tab */}
      {tab === 'alerts' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span style={{ fontWeight: 700, fontSize: 14 }}>🔔 Fraud Alerts ({alerts.length})</span>
          </div>
          {alerts.map(a => {
            const sc = { low: '#10b981', medium: '#f59e0b', high: '#f97316', critical: '#ef4444' };
            const c = sc[a.severity] || '#60a5fa';
            return (
              <div key={a._id} style={{ background: '#060e1a', border: `1px solid ${c}44`, borderLeft: `4px solid ${c}`, borderRadius: 10, padding: '14px 18px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontWeight: 700, color: c, fontSize: 14 }}>{a.title}</span>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <Badge text={a.severity.toUpperCase()} color={c} />
                    <Badge text={a.status} color={a.status === 'open' ? '#f59e0b' : '#10b981'} />
                    <span style={{ color: '#334155', fontSize: 11 }}>{new Date(a.createdAt).toLocaleString()}</span>
                  </div>
                </div>
                <p style={{ color: '#64748b', fontSize: 12, margin: 0 }}>{a.description}</p>
                <div style={{ display: 'flex', gap: 16, marginTop: 8, fontSize: 11, color: '#475569' }}>
                  {a.ipAddress && <span>🌐 {a.ipAddress}</span>}
                  {a.country   && <span>📍 {a.country}</span>}
                  {a.riskScore != null && <span>Risk: <strong style={{ color: c }}>{a.riskScore}</strong></span>}
                  {a.isVpn && <span>🌐 VPN</span>}
                  {a.isTor && <span>🕵️ TOR</span>}
                </div>
              </div>
            );
          })}
          {alerts.length === 0 && (
            <div style={{ textAlign: 'center', color: '#334155', padding: 40 }}>No open alerts. System is clean ✅</div>
          )}
        </div>
      )}

      {/* Rules Tab */}
      {tab === 'rules' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <span style={{ fontWeight: 700, fontSize: 14 }}>⚙️ Rules Engine ({rules.length} rules)</span>
            <button onClick={() => setRuleModal(true)} style={{ padding: '8px 16px', background: 'linear-gradient(135deg,#2563eb,#1d4ed8)', color: '#fff', border: 'none', borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: 600 }}>+ Add Rule</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {rules.map(r => {
              const ac = DECISION_COLOR[r.action] || DECISION_COLOR.CHALLENGE;
              return (
                <div key={r._id} style={{ background: '#060e1a', border: '1px solid #1e3a5f', borderRadius: 10, padding: '12px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4 }}>
                      {r.name}
                      {r.isBuiltIn && <span style={{ marginLeft: 8, fontSize: 10, color: '#475569', background: '#1e3a5f', padding: '2px 6px', borderRadius: 4 }}>built-in</span>}
                    </div>
                    <div style={{ fontSize: 12, color: '#64748b' }}>
                      IF <code style={{ color: '#93c5fd' }}>{r.conditionField}</code> {r.conditionOperator} <code style={{ color: '#34d399' }}>{String(r.conditionValue)}</code>
                      {' → '}<Badge text={r.action} color={ac} />
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <span style={{ fontSize: 11, color: '#475569' }}>P:{r.priority} · Fired:{r.triggerCount || 0}</span>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: r.isActive ? '#10b981' : '#ef4444', display: 'inline-block' }} />
                    {!r.isBuiltIn && (
                      <button onClick={() => deleteRule(r._id)} style={{ background: 'none', border: '1px solid #3b1020', color: '#f87171', padding: '4px 10px', borderRadius: 6, cursor: 'pointer', fontSize: 11 }}>Delete</button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Add Rule Modal */}
      {ruleModal && (
        <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 9999 }}>
          <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 14, padding: 28, width: 440, maxWidth: '95vw' }}>
            <h3 style={{ color: '#e0f2fe', margin: '0 0 20px' }}>Add Fraud Rule</h3>
            {[
              { label: 'Rule Name', key: 'name', type: 'text', placeholder: 'e.g. Block High Risk' },
            ].map(f => (
              <div key={f.key} style={{ marginBottom: 14 }}>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>{f.label}</label>
                <input type={f.type} value={newRule[f.key]} placeholder={f.placeholder}
                  onChange={e => setNewRule(p => ({ ...p, [f.key]: e.target.value }))}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '9px 12px', background: '#060e1a', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, fontSize: 13 }} />
              </div>
            ))}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>Condition Field</label>
                <select value={newRule.conditionField} onChange={e => setNewRule(p => ({ ...p, conditionField: e.target.value }))}
                  style={{ width: '100%', padding: '9px 12px', background: '#060e1a', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, fontSize: 13 }}>
                  {['riskScore','isVpn','isTor','isProxy','isBot','isNewDevice','isNewCountry','multipleAccounts','velocity'].map(f => <option key={f}>{f}</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>Operator</label>
                <select value={newRule.conditionOperator} onChange={e => setNewRule(p => ({ ...p, conditionOperator: e.target.value }))}
                  style={{ width: '100%', padding: '9px 12px', background: '#060e1a', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, fontSize: 13 }}>
                  {['gt','lt','gte','lte','eq','is_true','is_false'].map(o => <option key={o}>{o}</option>)}
                </select>
              </div>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 20 }}>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>Value</label>
                <input type="text" value={newRule.conditionValue} onChange={e => setNewRule(p => ({ ...p, conditionValue: e.target.value }))}
                  style={{ width: '100%', boxSizing: 'border-box', padding: '9px 12px', background: '#060e1a', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, fontSize: 13 }} />
              </div>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 12, marginBottom: 4 }}>Action</label>
                <select value={newRule.action} onChange={e => setNewRule(p => ({ ...p, action: e.target.value }))}
                  style={{ width: '100%', padding: '9px 12px', background: '#060e1a', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, fontSize: 13 }}>
                  {['ALLOW','BLOCK','CHALLENGE','MANUAL_REVIEW','ALERT','REQUIRE_MFA'].map(a => <option key={a}>{a}</option>)}
                </select>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button onClick={() => setRuleModal(false)} style={{ flex: 1, padding: 10, background: 'none', color: '#60a5fa', border: '1px solid #1e3a5f', borderRadius: 8, cursor: 'pointer' }}>Cancel</button>
              <button onClick={saveRule} style={{ flex: 2, padding: 10, background: 'linear-gradient(135deg,#2563eb,#1d4ed8)', color: '#fff', border: 'none', borderRadius: 8, cursor: 'pointer', fontWeight: 700 }}>Save Rule</button>
            </div>
          </div>
        </div>
      )}

      <style>{`@keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }`}</style>
    </div>
  );
}
