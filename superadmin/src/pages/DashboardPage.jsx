import { useEffect, useState, useMemo } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io, createEventBuffer } from '../api/config';
import DailyReportCard from '../components/DailyReportCard';
import PartnerAdminOverview from '../components/PartnerAdminOverview';
import { useAuth } from '../context/AuthContext';
import './DashboardPage.css';
import {
  ShieldAlert,
  Activity,
  Building2,
  Users,
  Handshake,
  Search,
  RefreshCw,
  AlertTriangle,
  ArrowUpRight,
  FileSpreadsheet,
  BarChart3,
  Layers,
  Cpu,
  Server,
  ShieldCheck,
  ChevronRight
} from 'lucide-react';

/* ── SOC Theme Palette ───────────────────────────────────────────── */
const T = {
  bg: '#070b14',
  card: '#0e1726',
  cardHi: '#131f33',
  border: '#1b2a42',
  borderHi: '#2a3e5e',
  text: '#f1f5f9',
  textDim: '#94a3b8',
  textMute: '#475569',
  cyan: '#00f2fe',
  blue: '#3b82f6',
  purple: '#8b5cf6',
};

const SEV = {
  critical: { color: '#f87171', bg: 'rgba(248,113,113,0.14)', bar: '#ef4444', label: 'CRITICAL' },
  high: { color: '#fb923c', bg: 'rgba(251,146,60,0.14)', bar: '#f97316', label: 'HIGH' },
  medium: { color: '#fbbf24', bg: 'rgba(251,191,36,0.14)', bar: '#f59e0b', label: 'MEDIUM' },
  low: { color: '#34d399', bg: 'rgba(52,211,153,0.14)', bar: '#10b981', label: 'LOW' },
  info: { color: '#38bdf8', bg: 'rgba(56,189,248,0.14)', bar: '#0ea5e9', label: 'INFO' },
};
const sev = (s) => SEV[s?.toLowerCase()] || SEV.info;

/* ── Custom Panel Component ───────────────────────────────────────── */
function SocPanel({ title, icon: Icon, action, children, style, glowColor }) {
  return (
    <div
      className="soc-glass-panel"
      style={{
        background: 'rgba(14, 23, 38, 0.85)',
        border: `1px solid ${T.border}`,
        borderRadius: 12,
        padding: '18px 20px',
        position: 'relative',
        boxShadow: glowColor ? `0 0 20px ${glowColor}15` : 'none',
        ...style,
      }}
    >
      {title && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 12, justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {Icon && <Icon size={16} color={T.cyan} />}
            <h3 style={{
              fontSize: 12, letterSpacing: '0.8px', textTransform: 'uppercase',
              color: T.text, margin: 0, fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6
            }}>
              {title}
            </h3>
          </div>
          {action}
        </div>
      )}
      {children}
    </div>
  );
}

function SevBadge({ severity }) {
  const s = sev(severity);
  return (
    <span style={{
      fontSize: 9, fontWeight: 800, letterSpacing: '0.6px', padding: '3px 8px', borderRadius: 4,
      background: s.bg, color: s.color, border: `1px solid ${s.color}55`, whiteSpace: 'nowrap',
      display: 'inline-flex', alignItems: 'center', gap: 4, boxShadow: `0 0 8px ${s.color}22`
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: s.color }} />
      {s.label}
    </span>
  );
}

export default function DashboardPage() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [stats, setStats] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [companies, setCompanies] = useState([]);
  const [live, setLive] = useState(false);
  const [error, setError] = useState('');
  const [companySearch, setCompanySearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [refreshVersion, setRefreshVersion] = useState(0);
  const [reportCompanyId, setReportCompanyId] = useState('');
  const [currentTime, setCurrentTime] = useState(new Date());

  // Clock tick
  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    Promise.allSettled([
      api.get('/superadmin/companies', { signal: controller.signal, timeout: 20000 }),
      api.get('/superadmin/overview', { signal: controller.signal, timeout: 20000 }),
    ]).then(([companyResult, overviewResult]) => {
      if (controller.signal.aborted) return;
      if (companyResult.status === 'fulfilled') setCompanies(companyResult.value.data || []);
      if (overviewResult.status === 'fulfilled') setStats(overviewResult.value.data);
      const failed = [
        companyResult.status === 'rejected' && 'companies',
        overviewResult.status === 'rejected' && 'overview',
      ].filter(Boolean);
      if (failed.length) setError(`Could not refresh ${failed.join(' and ')}. Any previous values are still shown. Use Sync to retry.`);
      setLoading(false);
    });
    return () => controller.abort();
  }, [refreshVersion]);

  useEffect(() => {

    const alertBuffer = createEventBuffer((newAlerts) => {
      setAlerts(p => [...newAlerts, ...p].slice(0, 25));
    }, 1200);

    const socket = io(SOCKET_URL);
    setLive(socket.connected);
    const onConnect = () => setLive(true);
    const onDisconnect = () => setLive(false);
    socket.on('connect', onConnect);
    socket.on('disconnect', onDisconnect);
    socket.emit('join:superadmin');
    socket.on('alert:new', alertBuffer.add);
    const onPartnerUpdate = () => setRefreshVersion(value => value + 1);
    socket.on('partner:update', onPartnerUpdate);

    const disconnectSocket = connectSocket(socket);
    return () => {
      socket.off('connect', onConnect);
      socket.off('disconnect', onDisconnect);
      socket.off('alert:new', alertBuffer.add);
      socket.off('partner:update', onPartnerUpdate);
      alertBuffer.clear();
      disconnectSocket();
    };
  }, []);

  const directCompanies = useMemo(() => companies.filter(company =>
    !company.partnerId && company.source !== 'partner_referral'
  ), [companies]);
  const selectedReportCompanyId = directCompanies.some(company => company._id === reportCompanyId)
    ? reportCompanyId : directCompanies[0]?._id || '';

  // Filtered companies
  const filteredCompanies = useMemo(() => {
    if (!companySearch.trim()) return directCompanies;
    const q = companySearch.trim().toLowerCase();
    return directCompanies.filter(c => c.name?.toLowerCase().includes(q) || c.plan?.type?.toLowerCase().includes(q));
  }, [directCompanies, companySearch]);

  // Calculate Threat Level
  const threatLevel = useMemo(() => {
    const criticalCount = alerts.filter(a => a.severity === 'critical').length;
    const highCount = alerts.filter(a => a.severity === 'high').length;

    if (criticalCount >= 3 || alerts.length >= 20) {
      return { level: 'DEFCON 1 · CRITICAL', color: '#f87171', bg: 'rgba(248,113,113,0.18)', border: '#ef4444' };
    } else if (criticalCount > 0 || highCount >= 3) {
      return { level: 'DEFCON 2 · ELEVATED', color: '#fb923c', bg: 'rgba(251,146,60,0.18)', border: '#f97316' };
    } else if (highCount > 0 || alerts.length > 5) {
      return { level: 'DEFCON 3 · GUARDED', color: '#fbbf24', bg: 'rgba(251,191,36,0.18)', border: '#f59e0b' };
    }
    return { level: 'DEFCON 4 · NORMAL', color: '#10b981', bg: 'rgba(16,185,129,0.18)', border: '#10b981' };
  }, [alerts]);

  return (
    <div className="admin-dashboard" style={{ display: 'flex', flexDirection: 'column', gap: 22 }}>
      {/* ── Top SOC Header & Command Bar ── */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(14,23,38,0.95) 0%, rgba(19,31,51,0.95) 100%)',
        border: `1px solid ${T.borderHi}`,
        borderRadius: 14,
        padding: '20px 24px',
        boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        gap: 16
      }}>
        {/* Title & Status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, minWidth: 0 }}>
          <div style={{
            width: 46, height: 46, borderRadius: 12, flexShrink: 0,
            background: 'linear-gradient(135deg, rgba(0,242,254,0.15), rgba(59,130,246,0.25))',
            border: '1px solid rgba(0,242,254,0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 20px rgba(0,242,254,0.2)'
          }}>
            <ShieldAlert size={26} color={T.cyan} />
          </div>
          <div>
            <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
              <h1 style={{ fontSize: 20, color: T.text, margin: 0, fontWeight: 800, letterSpacing: '0.4px' }}>
                Superadmin & Partner Admin Dashboard
              </h1>
              <span style={{
                fontSize: 10, fontWeight: 800, padding: '3px 9px', borderRadius: 20,
                background: threatLevel.bg, color: threatLevel.color, border: `1px solid ${threatLevel.border}`,
                boxShadow: `0 0 10px ${threatLevel.color}33`, letterSpacing: '0.5px'
              }}>
                {threatLevel.level}
              </span>
            </div>
            <div style={{ fontSize: 12, color: T.textDim, marginTop: 4, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
              <span>Platform management & partner operations</span>
              <span>•</span>
              <span className="soc-font-mono" style={{ color: T.cyan, fontSize: 11 }}>
                {currentTime.toISOString().replace('T', ' ').substring(0, 19)} UTC
              </span>
            </div>
          </div>
        </div>

        {/* Status Indicators & Control Buttons */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          {/* Socket status */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, fontWeight: 700,
            background: T.bg, border: `1px solid ${T.border}`, borderRadius: 20, padding: '6px 14px',
          }}>
            <span style={{
              width: 8, height: 8, borderRadius: '50%', display: 'inline-block',
              background: live ? '#10b981' : '#64748b',
              boxShadow: live ? '0 0 10px #10b981' : 'none',
              animation: live ? 'pulseGlow 2s infinite' : 'none'
            }} />
            <span style={{ color: live ? '#10b981' : T.textMute, letterSpacing: '0.5px' }}>
              {live ? 'TELEMETRY LIVE' : 'RECONNECTING…'}
            </span>
          </div>

          <button
            onClick={() => setRefreshVersion(value => value + 1)}
            disabled={loading}
            title="Refresh Telemetry Data"
            style={{
              background: T.cardHi, border: `1px solid ${T.borderHi}`, color: T.text,
              padding: '8px 14px', borderRadius: 8, cursor: 'pointer', fontSize: 12, fontWeight: 600,
              display: 'flex', alignItems: 'center', gap: 6, transition: 'all 0.2s ease'
            }}
            onMouseEnter={e => e.currentTarget.style.borderColor = T.cyan}
            onMouseLeave={e => e.currentTarget.style.borderColor = T.borderHi}
          >
            <RefreshCw size={14} color={T.cyan} />
            <span>{loading ? 'Syncing…' : 'Sync'}</span>
          </button>
        </div>
      </div>

      {error && (
        <div role="alert" style={{
          background: 'rgba(248,113,113,0.12)', color: '#fca5a5',
          border: '1px solid rgba(248,113,113,0.3)', padding: '12px 16px',
          borderRadius: 10, fontSize: 13, display: 'flex', alignItems: 'center', gap: 10
        }}>
          <AlertTriangle size={18} color="#ef4444" />
          <span>{error}</span>
        </div>
      )}

      <div className="admin-dashboard__split">
      <section className="admin-dashboard__column admin-dashboard__column--superadmin" aria-labelledby="superadmin-section-title">
        <div className="admin-dashboard__section-heading">
          <div className="admin-dashboard__section-icon"><ShieldCheck size={24} /></div>
          <div>
            <span className="admin-dashboard__eyebrow">PLATFORM CONTROL</span>
            <h2 id="superadmin-section-title">Superadmin</h2>
            <p>Direct companies, platform totals & security operations</p>
          </div>
        </div>

        <SocPanel title="Superadmin Account" icon={ShieldCheck} action={<Link className="admin-dashboard__link" to="/superadmin/settings">Settings <ArrowUpRight size={13} /></Link>}>
          <div className="admin-dashboard__account">
            <div><strong>{user?.name || 'Superadmin'}</strong><p>{user?.email || 'Email unavailable'}</p></div>
            <span className="admin-dashboard__badge">Superadmin</span>
          </div>
        </SocPanel>

      {/* ── Executive Stat Cards Grid ── */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(min(145px, 100%), 1fr))',
        gap: 14,
      }}>
        {[
          { label: 'Direct Companies', value: stats?.directCompanies, color: '#00f2fe', Icon: Building2, to: '/superadmin/companies' },
          { label: 'Direct Active', value: stats?.directActiveCompanies, color: '#10b981', Icon: ShieldCheck, to: '/superadmin/companies' },
          { label: 'Direct Suspended', value: stats?.directSuspendedCompanies, color: '#fb923c', Icon: AlertTriangle, to: '/superadmin/companies' },
          { label: 'All Companies', value: stats?.totalCompaniesCount, color: '#a78bfa', Icon: Building2, to: '/superadmin/companies' },
          { label: 'Global Tenants', value: stats?.tenants, color: '#818cf8', Icon: Layers, to: '/superadmin/partners' },
          { label: 'All Users', value: stats?.users, color: '#60a5fa', Icon: Users, to: '/superadmin/users' },
          { label: 'SOC Managers', value: stats?.socManagers, color: '#38bdf8', Icon: ShieldCheck, to: '/superadmin/soc-managers' },
          { label: 'Analysts / Dept Admins', value: stats?.agents, color: '#a78bfa', Icon: Cpu, to: '/superadmin/users' },
          { label: 'Global Active Systems', value: stats?.systems, color: '#10b981', Icon: Server, to: '/superadmin/system-monitoring' },
          { label: 'Global Alerts', value: stats?.alerts, color: '#f59e0b', Icon: AlertTriangle, to: '/superadmin/alerts' },
        ].map(({ label, value, color, Icon, to }) => {
          const content = (
            <div
              className="soc-glass-panel soc-glowing-card"
              style={{
                padding: '16px 18px',
                height: '100%',
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                transition: 'transform 0.2s ease, border-color 0.2s ease',
              }}
              onMouseEnter={e => {
                e.currentTarget.style.transform = 'translateY(-2px)';
                e.currentTarget.style.borderColor = color;
              }}
              onMouseLeave={e => {
                e.currentTarget.style.transform = 'none';
                e.currentTarget.style.borderColor = T.border;
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: T.textDim, fontWeight: 700, letterSpacing: '0.6px', textTransform: 'uppercase' }}>
                  {label}
                </span>
                <div style={{
                  width: 28, height: 28, borderRadius: 6, background: `${color}15`,
                  border: `1px solid ${color}33`, display: 'flex', alignItems: 'center', justifyContent: 'center'
                }}>
                  <Icon size={14} color={color} />
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span className="soc-font-mono" style={{
                  fontSize: 26, fontWeight: 800, color, lineHeight: 1.1,
                  textShadow: `0 0 16px ${color}33`
                }}>
                  {value ?? '—'}
                </span>
                {to && <ArrowUpRight size={12} color={T.textMute} />}
              </div>
            </div>
          );

          return to ? (
            <Link key={label} to={to} style={{ textDecoration: 'none' }}>
              {content}
            </Link>
          ) : (
            <div key={label}>{content}</div>
          );
        })}
      </div>

      <SocPanel title="Superadmin Management" icon={Layers}>
        <div className="admin-dashboard__shortcuts">
          {[
            ['Companies', 'companies', Building2], ['Users & Access', 'users', Users],
            ['SOC Managers', 'soc-managers', ShieldCheck], ['Partners', 'partners', Handshake],
            ['Revenue', 'revenue', BarChart3], ['Payments', 'payment-management', FileSpreadsheet],
            ['Security Alerts', 'alerts', ShieldAlert], ['Reports', 'reports', FileSpreadsheet],
          ].map(([label, route, Icon]) => (
            <Link key={route} to={`/superadmin/${route}`}><Icon size={15} /><span>{label}</span><ArrowUpRight size={13} /></Link>
          ))}
        </div>
      </SocPanel>

      {/* ── Choose Company Launcher Matrix ── */}
      <SocPanel
        title="Superadmin Direct Companies"
        icon={Building2}
        action={
          <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
            <div style={{
              display: 'flex', alignItems: 'center', gap: 6, background: T.bg,
              border: `1px solid ${T.border}`, borderRadius: 8, padding: '4px 10px', fontSize: 12
            }}>
              <Search size={14} color={T.textMute} />
              <input
                type="text"
                aria-label="Search direct companies"
                placeholder="Search company..."
                value={companySearch}
                onChange={e => setCompanySearch(e.target.value)}
                style={{ background: 'transparent', border: 'none', color: T.text, fontSize: 12, width: 140 }}
              />
            </div>
            <span style={{ fontSize: 11, color: T.textMute }}>{filteredCompanies.length} {filteredCompanies.length === 1 ? 'company' : 'companies'}</span>
          </div>
        }
      >
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(min(220px, 100%), 1fr))',
          gap: 12,
          maxHeight: 220,
          overflowY: 'auto',
          paddingRight: 4
        }}>
          {filteredCompanies.map(co => {
            const isActive = co.status === 'active';
            return (
              <button
                key={co._id}
                onClick={() => navigate(`/superadmin/companies/${co._id}/dashboard`)}
                style={{
                  padding: '12px 14px', borderRadius: 10, border: `1px solid ${T.border}`,
                  background: T.cardHi, color: T.text, cursor: 'pointer', textAlign: 'left',
                  display: 'flex', flexDirection: 'column', gap: 6, transition: 'all 0.2s ease',
                  position: 'relative', overflow: 'hidden'
                }}
                onMouseEnter={e => {
                  e.currentTarget.style.borderColor = T.cyan;
                  e.currentTarget.style.boxShadow = `0 0 16px rgba(0, 242, 254, 0.15)`;
                }}
                onMouseLeave={e => {
                  e.currentTarget.style.borderColor = T.border;
                  e.currentTarget.style.boxShadow = 'none';
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%', display: 'inline-block', flexShrink: 0,
                      background: isActive ? '#10b981' : '#f59e0b',
                      boxShadow: isActive ? '0 0 8px #10b981' : 'none'
                    }} />
                    <span style={{ fontSize: 13, fontWeight: 700, color: T.text, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 120 }}>
                      {co.name}
                    </span>
                  </div>
                  <ChevronRight size={14} color={T.textMute} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', width: '100%', marginTop: 2 }}>
                  <span style={{
                    fontSize: 9, fontWeight: 700, letterSpacing: '0.4px', textTransform: 'uppercase',
                    color: T.cyan, background: 'rgba(0,242,254,0.1)', padding: '2px 6px', borderRadius: 4,
                    border: '1px solid rgba(0,242,254,0.2)'
                  }}>
                    {co.plan?.type || 'trial'}
                  </span>
                  <span style={{ fontSize: 10, color: T.textMute }}>
                    Open Security Hub →
                  </span>
                </div>
              </button>
            );
          })}
          {filteredCompanies.length === 0 && (
            <div style={{ fontSize: 13, color: T.textMute, padding: '16px 0', gridColumn: '1 / -1', textAlign: 'center' }}>
              {loading ? 'Loading direct companies…' : companySearch.trim() ? 'No matching companies found.' : 'No direct companies available.'}
            </div>
          )}
        </div>
      </SocPanel>

      {/* ── Security Analytics Section: Tenant Distribution & Severity Meters ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr)', gap: 16 }}>
        {/* Tenant Distribution */}
        <SocPanel
          title="Global Company Distribution by Tenant"
          icon={Layers}
          action={<Link to="/superadmin/partners" style={{ color: T.cyan, fontSize: 12, textDecoration: 'none', fontWeight: 600 }}>Manage Partners →</Link>}
        >
          {(stats?.companiesByTenant || []).length === 0 ? (
            <div style={{ color: T.textMute, fontSize: 13, padding: '16px 0' }}>No tenant telemetry available.</div>
          ) : stats.companiesByTenant.map((row, idx) => {
            const max = Math.max(...stats.companiesByTenant.map(x => x.companies), 1);
            const tenantName = row.tenant?.name || 'Main / Global Workspace';
            const pct = Math.round((row.companies / max) * 100);
            return (
              <div key={row.tenant?._id || idx} style={{ marginBottom: 14 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', color: T.text, fontSize: 12.5, marginBottom: 6 }}>
                  <span style={{ fontWeight: 600, display: 'flex', alignItems: 'center', gap: 6 }}>
                    <Building2 size={13} color={T.cyan} />
                    {tenantName}
                    <span style={{ fontSize: 10, color: T.textMute }}>({row.tenant?.type || 'main'})</span>
                  </span>
                  <span className="soc-font-mono" style={{ color: T.cyan, fontWeight: 700 }}>
                    {row.companies} {row.companies === 1 ? 'company' : 'companies'}
                  </span>
                </div>
                <div style={{ height: 8, background: T.bg, borderRadius: 8, overflow: 'hidden', border: `1px solid ${T.border}` }}>
                  <div style={{
                    width: `${Math.max(pct, 6)}%`, height: '100%',
                    background: `linear-gradient(90deg, #3b82f6, ${T.cyan})`, borderRadius: 8,
                    boxShadow: `0 0 10px ${T.cyan}55`
                  }} />
                </div>
              </div>
            );
          })}
        </SocPanel>

        {/* User Roles Breakdown */}
        <SocPanel title="Global User Roles & Access" icon={Users}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {(stats?.usersByRole || []).map(role => (
              <div key={role._id || 'none'} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                padding: '10px 12px', background: T.bg, border: `1px solid ${T.border}`, borderRadius: 8,
              }}>
                <span style={{ color: T.textDim, fontSize: 13, fontWeight: 600, textTransform: 'capitalize', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <ShieldCheck size={14} color={T.cyan} />
                  {role._id ? role._id.replaceAll('_', ' ') : 'unassigned'}
                </span>
                <span className="soc-font-mono" style={{
                  color: T.cyan, fontWeight: 800, fontSize: 13,
                  background: 'rgba(0,242,254,0.1)', padding: '3px 10px', borderRadius: 6, border: '1px solid rgba(0,242,254,0.2)'
                }}>
                  {role.count}
                </span>
              </div>
            ))}
            {(stats?.usersByRole || []).length === 0 && (
              <div style={{ color: T.textMute, fontSize: 13, padding: '16px 0' }}>No role breakdown available.</div>
            )}
          </div>
        </SocPanel>
      </div>

      {/* ── 30-Day Alert Volume Timeline ── */}
      {stats?.alertsByDay?.length > 0 && (
        <SocPanel title="Alert Ingestion Volume · 30-Day Histogram" icon={Activity}>
          <div style={{ display: 'flex', alignItems: 'flex-end', gap: 4, height: 80, paddingTop: 10 }}>
            {(() => {
              const days = [...stats.alertsByDay].sort((a, b) => a._id > b._id ? 1 : -1).slice(-30);
              const max = Math.max(...days.map(d => d.count), 1);
              return days.map((d, i) => {
                const heightPct = Math.max((d.count / max) * 100, 5);
                return (
                  <div
                    key={i}
                    title={`${d._id}: ${d.count} alerts`}
                    style={{
                      flex: 1, minWidth: 6,
                      background: `linear-gradient(180deg, ${T.cyan}, #3b82f6)`,
                      height: `${heightPct}%`,
                      borderRadius: '4px 4px 0 0', opacity: 0.85, transition: 'all 0.2s ease',
                      cursor: 'pointer'
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.opacity = '1';
                      e.currentTarget.style.boxShadow = `0 0 10px ${T.cyan}`;
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.opacity = '0.85';
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                  />
                );
              });
            })()}
          </div>
        </SocPanel>
      )}

      {/* ── Daily Report Card Integration ── */}
      <SocPanel title="Direct Company Daily Report" icon={FileSpreadsheet}>
        <label className="admin-dashboard__field">
          <span>Choose a direct company</span>
          <select value={selectedReportCompanyId} onChange={event => setReportCompanyId(event.target.value)} disabled={!directCompanies.length}>
            {!directCompanies.length && <option value="">No direct companies available</option>}
            {directCompanies.map(company => <option key={company._id} value={company._id}>{company.name}</option>)}
          </select>
        </label>
        {selectedReportCompanyId && <DailyReportCard key={`${selectedReportCompanyId}-${refreshVersion}`} companyApiPrefix={`/daily-report/company/${selectedReportCompanyId}`} />}
      </SocPanel>
      </section>

      <PartnerAdminOverview stats={stats} refreshVersion={refreshVersion} />
      </div>
    </div>
  );
}
