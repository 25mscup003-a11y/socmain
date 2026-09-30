import { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io, createEventBuffer } from '../api/config';
import { useAuth } from '../context/AuthContext';
import { CAPABILITY_CONFIG } from '../utils/capabilityMap';
import { EDRCapabilitiesDashboard } from './EDRPage';
import { EDRCapabilityDashboardModal } from './EDRDashboardDetails';
import './SystemMonitoringDashboard.css';

/* ═══════════════════════════════════════════════════════════════════
   HELPER FUNCTIONS
   ═══════════════════════════════════════════════════════════════════ */

const ONLINE_THRESHOLD = 10 * 60 * 1000; // 10 minutes — matches backend heartbeat window
const INVENTORY_REFRESH_MS = 90 * 1000;
const DETAIL_RECONCILE_MS = 2 * 60 * 1000;
// Capability telemetry scans normalized endpoint events. Keep reconciliation
// deliberately slower; live socket events update the surrounding UI without
// forcing another expensive full capability scan.
const CAPABILITY_RECONCILE_MS = 5 * 60 * 1000;

function edrCategoryForCapability(capabilityId) {
  const id = Number(capabilityId);
  if (id === 1) return 'edr';
  if ([2, 12, 18, 25, 27].includes(id)) return 'file';
  if ([3, 9, 15, 20, 23, 26, 30, 31].includes(id)) return 'network';
  if ([4, 11, 13, 14, 16].includes(id)) return 'edr';
  if (id === 5) return 'memory';
  if (id === 6) return 'registry';
  if (id === 7) return 'systemchanges';
  if (id === 8) return 'persistence';
  if (id === 10) return 'usb';
  return 'system';
}

function pageIsVisible() {
  return typeof document === 'undefined' || document.visibilityState === 'visible';
}

function isSystemOnline(sys) {
  return sys.lastSeen && (Date.now() - new Date(sys.lastSeen).getTime()) < ONLINE_THRESHOLD;
}

function calculateRiskLevel(system) {
  let risk = 0;
  if (!system.lastSeen || (Date.now() - new Date(system.lastSeen).getTime()) > 10 * 60 * 1000) risk += 3;
  if (system.threatActivityCount > 5) risk += 2;
  if (system.failedLoginAttempts > 10) risk += 2;
  if (system.malwareDetected) risk += 3;
  return risk > 5 ? 'high' : risk > 2 ? 'medium' : 'low';
}

function timeAgo(date) {
  if (!date) return 'Never';
  const diff = Date.now() - new Date(date).getTime();
  if (diff < 60_000) return 'Just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return `${Math.floor(diff / 86_400_000)}d ago`;
}

function downloadCSV(filename, headers, rows) {
  const csv = [headers.join(','), ...rows.map(r => r.map(v => `"${(v ?? '').toString().replace(/"/g, '""')}"`).join(','))].join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

/* ═══════════════════════════════════════════════════════════════════
   SHARED UI COMPONENTS
   ═══════════════════════════════════════════════════════════════════ */

const RISK = {
  high: { color: '#f87171', bg: 'rgba(239,68,68,.15)', label: 'HIGH' },
  medium: { color: '#f59e0b', bg: 'rgba(245,158,11,.15)', label: 'MED' },
  low: { color: '#34d399', bg: 'rgba(52,211,153,.1)', label: 'LOW' },
  none: { color: '#64748b', bg: 'rgba(100,116,139,.1)', label: '—' },
};

function Spark({ data = [] }) {
  if (!data || data.length < 2) return null;
  const vals = data.map(d => d.count || d || 0);
  const max = Math.max(...vals, 1);
  const W = 90, H = 26;
  const pts = vals.map((v, i) => `${(i / (vals.length - 1)) * W},${H - (v / max) * H}`).join(' ');
  return (
    <svg width={W} height={H} style={{ display: 'block', overflow: 'visible' }}>
      <polyline points={pts} fill="none" stroke="#3b82f6" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function BigCard({ icon, title, main, sub, risk = 'low', spark, onClick, badge, children }) {
  const r = RISK[risk] || RISK.low;
  return (
    <div
      onClick={onClick}
      style={{
        background: '#0c1a2e',
        border: `1px solid ${onClick ? '#1e40af' : '#1e3a5f'}`,
        borderRadius: 10, padding: '14px 16px',
        flex: '1', minWidth: 190,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'border-color .15s, box-shadow .15s',
      }}
      onMouseEnter={e => { if (onClick) e.currentTarget.style.borderColor = '#3b82f6'; }}
      onMouseLeave={e => { if (onClick) e.currentTarget.style.borderColor = '#1e40af'; }}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
        <span style={{ fontSize: 20 }}>{icon}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          {badge && <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700, background: '#f59e0b22', color: '#f59e0b', border: '1px solid #f59e0b44' }}>{badge}</span>}
          {onClick && <span style={{ fontSize: 9, color: '#1e40af' }}>click ↗</span>}
          <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 600, background: r.bg, color: r.color }}>{r.label}</span>
        </div>
      </div>
      <div style={{ fontSize: 22, fontWeight: 600, color: '#e2e8f0' }}>{main}</div>
      <div style={{ fontSize: 11, color: '#1e40af', marginBottom: 6 }}>{title}</div>
      {children && <div style={{ fontSize: 10, color: '#64748b', marginBottom: 6 }}>{children}</div>}
      <Spark data={spark} />
      {sub && <div style={{ fontSize: 10, color: '#60a5fa', marginTop: 4 }}>{sub}</div>}
    </div>
  );
}

function Badge({ type, children }) {
  return <span className={`sm-badge sm-badge--${type}`}>{children}</span>;
}

function StatusBadge({ online }) {
  return (
    <Badge type={online ? 'online' : 'offline'}>
      <span className="sm-badge__dot" />
      {online ? 'Online' : 'Offline'}
    </Badge>
  );
}

function RiskBadge({ level }) {
  const labels = { low: 'Low Risk', medium: 'Medium', high: 'High Risk' };
  return <Badge type={level}>{labels[level] || 'Unknown'}</Badge>;
}

function RefreshBadge({ onClick, lastRefresh }) {
  return (
    <button className="sm-refresh-badge" onClick={onClick} title="Click to refresh now">
      <span className="sm-refresh-badge__dot" />
      Live · {lastRefresh ? `Updated ${timeAgo(lastRefresh)}` : 'Auto-refresh 30s'}
    </button>
  );
}

function AlertNotificationPanel({ alerts, onClose }) {
  if (!alerts.length) return null;
  return (
    <div className="sm-alert-panel">
      <div className="sm-alert-panel__card">
        <div className="sm-alert-panel__header">
          <div className="sm-alert-panel__title">🚨 Active Alerts ({alerts.length})</div>
          <button className="sm-alert-panel__close" onClick={onClose}>×</button>
        </div>
        <div className="sm-alert-panel__list">
          {alerts.map((a, i) => (
            <div key={i} className="sm-alert-panel__item">
              <div className="sm-alert-panel__item-type">{a.type}</div>
              <div className="sm-alert-panel__item-msg">{a.message}</div>
              <div className="sm-alert-panel__item-time">{a.time}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   1. DEPARTMENT OVERVIEW
   ═══════════════════════════════════════════════════════════════════ */

function DepartmentCard({ dept, onSelect, stats }) {
  const { systemCount = 0, activeCount = 0, inactiveCount = 0, highRiskCount = 0 } = stats;
  const riskPct = systemCount > 0 ? Math.round((highRiskCount / systemCount) * 100) : 0;
  const deptRisk = highRiskCount > systemCount * 0.3 ? 'high' : highRiskCount > systemCount * 0.1 ? 'medium' : 'low';

  return (
    <div className="sm-dept-card" onClick={() => onSelect(dept)} id={`dept-card-${dept._id}`}>
      <div className="sm-dept-card__header">
        <div>
          <h3 className="sm-dept-card__name">{dept.name}</h3>
          {dept.description && <div className="sm-dept-card__desc">{dept.description}</div>}
        </div>
        <RiskBadge level={deptRisk} />
      </div>
      <div className="sm-dept-card__body">
        <div className="sm-dept-card__stat">
          <div className="sm-dept-card__stat-label">Total Systems</div>
          <div className="sm-dept-card__stat-value" style={{ color: '#3b82f6' }}>{systemCount}</div>
        </div>
        <div className="sm-dept-card__stat">
          <div className="sm-dept-card__stat-label">Active</div>
          <div className="sm-dept-card__stat-value" style={{ color: '#10b981' }}>{activeCount}</div>
        </div>
        <div className="sm-dept-card__stat">
          <div className="sm-dept-card__stat-label">Offline</div>
          <div className="sm-dept-card__stat-value" style={{ color: '#f59e0b' }}>{inactiveCount}</div>
        </div>
        <div className="sm-dept-card__stat">
          <div className="sm-dept-card__stat-label">High Risk</div>
          <div className="sm-dept-card__stat-value" style={{ color: highRiskCount > 0 ? '#f87171' : '#34d399' }}>{highRiskCount}</div>
        </div>
      </div>
      <div className="sm-dept-card__footer">
        <div className="sm-dept-card__risk">
          <div className="sm-progress" style={{ width: 80 }}>
            <div className="sm-progress__fill" style={{
              width: `${riskPct}%`,
              background: deptRisk === 'high' ? '#ef4444' : deptRisk === 'medium' ? '#f59e0b' : '#10b981',
            }} />
          </div>
          <div className="sm-dept-card__risk-pct">{riskPct}% at risk</div>
        </div>
        <div className="sm-dept-card__action">
          View Systems <span>→</span>
        </div>
      </div>
    </div>
  );
}

/* ─── 24H LOGS OVERVIEW CARDS ──────────────────────────────────────── */
function LogOverviewCard({ card }) {
  const [hovered, setHovered] = useState(false);

  return (
    <div
      onClick={card.onClick}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
      style={{
        flex: '1 1 200px',
        minWidth: 200,
        maxWidth: 340,
        background: hovered
          ? `linear-gradient(135deg, rgba(12,26,46,0.98) 0%, rgba(20,40,72,0.98) 100%)`
          : 'rgba(10,20,38,0.92)',
        border: `1px solid ${hovered ? card.accent : card.border}`,
        borderRadius: 14,
        padding: '18px 20px',
        cursor: 'pointer',
        transition: 'all 0.22s cubic-bezier(0.4, 0, 0.2, 1)',
        boxShadow: hovered
          ? `0 8px 32px ${card.glow}, 0 0 0 1px ${card.border}`
          : '0 2px 10px rgba(0,0,0,0.3)',
        transform: hovered ? 'translateY(-3px)' : 'translateY(0)',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: `linear-gradient(90deg, transparent, ${card.accent}, transparent)`,
        opacity: hovered ? 1 : 0.4,
        transition: 'opacity 0.22s',
        borderRadius: '14px 14px 0 0',
      }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
        <div style={{
          width: 40, height: 40, borderRadius: 10,
          background: `linear-gradient(135deg, ${card.glow}, rgba(15,25,48,0.8))`,
          border: `1px solid ${card.border}`,
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 18,
          boxShadow: `0 0 12px ${card.glow}`,
        }}>
          {card.icon}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <span style={{ fontSize: 9, color: card.accent, fontWeight: 600 }}>click ↗</span>
          <span style={{
            fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
            background: `${card.glow}`, color: card.accent,
            border: `1px solid ${card.border}`,
          }}>24H</span>
        </div>
      </div>

      {card.loading ? (
        <div style={{ fontSize: 26, fontWeight: 700, color: '#475569', marginBottom: 4, letterSpacing: '-0.5px' }}>…</div>
      ) : (
        <div style={{
          fontSize: 32, fontWeight: 700, color: '#e2e8f0', marginBottom: 4, letterSpacing: '-1px',
          textShadow: hovered ? `0 0 20px ${card.accent}55` : 'none',
          transition: 'text-shadow 0.22s',
        }}>
          {card.count.toLocaleString()}
        </div>
      )}

      <div style={{ fontSize: 12, color: card.accent, fontWeight: 600, marginBottom: 2 }}>
        {card.label}
      </div>
      <div style={{ fontSize: 10, color: '#475569' }}>
        {card.sublabel} · click to view logs
      </div>

      {hovered && (
        <div style={{
          position: 'absolute', bottom: 14, right: 16,
          fontSize: 16, color: card.accent, opacity: 0.7,
        }}>→</div>
      )}
    </div>
  );
}

function LogsOverviewCards({ systemId }) {
  const [edrData, setEdrData] = useState({ logs: [], count: 0, loading: true });
  const [idsData, setIdsData] = useState({ logs: [], count: 0, loading: true });
  const [incidentData, setIncidentData] = useState({ logs: [], count: 0, loading: true });
  const [modal, setModal] = useState(null);

  useEffect(() => {
    const since = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();

    if (systemId) {
      // ── System-specific fetch from monitoring endpoints ──
      api.get(`/monitoring/system/${systemId}/edr?limit=200`)
        .then(r => {
          const items = r.data?.alerts || [];
          setEdrData({ logs: items, count: r.data?.counts?.edrAlerts ?? items.length, loading: false });
        })
        .catch(() => setEdrData(d => ({ ...d, loading: false })));

      api.get(`/monitoring/system/${systemId}/ips-ids?limit=200`)
        .then(r => {
          const items = [...(r.data?.alerts || []), ...(r.data?.logs || [])];
          setIdsData({ logs: items, count: r.data?.counts?.total ?? items.length, loading: false });
        })
        .catch(() => setIdsData(d => ({ ...d, loading: false })));

      // Incidents = all alerts for this system (malware + network + edr combined)
      Promise.all([
        api.get(`/monitoring/system/${systemId}/malware?limit=100`).catch(() => ({ data: { data: [] } })),
        api.get(`/monitoring/system/${systemId}/network?limit=100`).catch(() => ({ data: { alerts: [] } })),
        api.get(`/monitoring/system/${systemId}/edr?limit=100`).catch(() => ({ data: { alerts: [] } })),
      ]).then(([mal, net, edr]) => {
        const items = [
          ...(mal.data?.data || []),
          ...(net.data?.alerts || []),
          ...(edr.data?.alerts || []),
        ];
        setIncidentData({ logs: items, count: items.length, loading: false });
      }).catch(() => setIncidentData(d => ({ ...d, loading: false })));

    } else {
      // ── Company-wide fetch ──
      api.get('/alerts', { params: { category: 'edr', from: since, limit: 200 } })
        .then(r => {
          const items = r.data?.alerts || r.data?.data || (Array.isArray(r.data) ? r.data : []);
          setEdrData({ logs: items, count: r.data?.total ?? items.length, loading: false });
        })
        .catch(() => setEdrData(d => ({ ...d, loading: false })));

      api.get('/idsips/logs', { params: { from: since, limit: 200 } })
        .then(r => {
          const items = r.data?.logs || r.data?.data || (Array.isArray(r.data) ? r.data : []);
          setIdsData({ logs: items, count: r.data?.total ?? items.length, loading: false });
        })
        .catch(() => {
          api.get('/alerts', { params: { sourceType: 'IDS', from: since, limit: 200 } })
            .then(r => {
              const items = r.data?.alerts || r.data?.data || (Array.isArray(r.data) ? r.data : []);
              setIdsData({ logs: items, count: r.data?.total ?? items.length, loading: false });
            })
            .catch(() => setIdsData(d => ({ ...d, loading: false })));
        });

      api.get('/alerts', { params: { from: since, limit: 200 } })
        .then(r => {
          const items = r.data?.alerts || r.data?.data || (Array.isArray(r.data) ? r.data : []);
          setIncidentData({ logs: items, count: r.data?.total ?? items.length, loading: false });
        })
        .catch(() => setIncidentData(d => ({ ...d, loading: false })));
    }
  }, [systemId]);

  const CARDS = [
    {
      key: 'edr',
      icon: '🛡️',
      label: 'EDR Logs',
      sublabel: 'Last 24 hours',
      accent: '#38bdf8',
      glow: 'rgba(56,189,248,0.18)',
      border: 'rgba(56,189,248,0.3)',
      count: edrData.count,
      loading: edrData.loading,
      onClick: () => setModal({ title: 'EDR Logs (24h)', icon: '🛡️', items: edrData.logs, type: 'alert' }),
    },
    {
      key: 'ids',
      icon: '📡',
      label: 'IDS / IPS',
      sublabel: 'Last 24 hours',
      accent: '#22d3ee',
      glow: 'rgba(34,211,238,0.18)',
      border: 'rgba(34,211,238,0.3)',
      count: idsData.count,
      loading: idsData.loading,
      onClick: () => setModal({ title: 'IDS / IPS Logs (24h)', icon: '📡', items: idsData.logs, type: 'alert' }),
    },
    {
      key: 'incident',
      icon: '🚨',
      label: 'Incidents',
      sublabel: 'Last 24 hours',
      accent: '#f87171',
      glow: 'rgba(248,113,113,0.18)',
      border: 'rgba(248,113,113,0.3)',
      count: incidentData.count,
      loading: incidentData.loading,
      onClick: () => setModal({ title: 'Incidents / Alerts (24h)', icon: '🚨', items: incidentData.logs, type: 'alert' }),
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, margin: '18px 0 12px' }}>
        <div style={{ height: 1, flex: 1, background: 'linear-gradient(90deg, rgba(59,130,246,0.3), transparent)' }} />
        <span style={{ fontSize: 11, color: '#475569', fontWeight: 600, letterSpacing: '0.06em', textTransform: 'uppercase' }}>
          24h Log Overview
        </span>
        <div style={{ height: 1, flex: 1, background: 'linear-gradient(90deg, transparent, rgba(59,130,246,0.3))' }} />
      </div>

      <div style={{ display: 'flex', gap: 12, marginBottom: 20, flexWrap: 'wrap' }}>
        {CARDS.map(card => (
          <LogOverviewCard key={card.key} card={card} />
        ))}
      </div>

      {modal && (
        <LogDetailModal
          title={modal.title}
          icon={modal.icon}
          items={modal.items}
          type={modal.type}
          onClose={() => setModal(null)}
        />
      )}
    </>
  );
}

function DepartmentOverview({ departments, systems, onSelectDept, deptSearch, setDeptSearch, error, loading }) {
  const filteredDepts = departments.filter(d =>
    d.name?.toLowerCase().includes(deptSearch.toLowerCase())
  );

  const totalSystems = systems.length;
  const onlineCount = systems.filter(isSystemOnline).length;
  const highRiskCount = systems.filter(s => calculateRiskLevel(s) === 'high').length;

  const getDeptStats = (dept) => {
    const deptSystems = systems.filter(s => {
      const deptId = typeof s.departmentId === 'object' ? s.departmentId?._id : s.departmentId;
      return String(deptId || '') === String(dept._id || '');
    });
    const active = deptSystems.filter(isSystemOnline).length;
    return {
      systemCount: deptSystems.length,
      activeCount: active,
      inactiveCount: deptSystems.length - active,
      highRiskCount: deptSystems.filter(s => calculateRiskLevel(s) === 'high').length,
    };
  };

  return (
    <>
      {/* Stats overview */}
      <div className="sm-stats-row">
        <div className="sm-stat-card" style={{ '--stat-color': '#3b82f6' }}>
          <div className="sm-stat-card__label">Departments</div>
          <div className="sm-stat-card__value">{departments.length}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#06b6d4' }}>
          <div className="sm-stat-card__label">Total Systems</div>
          <div className="sm-stat-card__value">{totalSystems}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#10b981' }}>
          <div className="sm-stat-card__label">Online</div>
          <div className="sm-stat-card__value">{onlineCount}</div>
          <div className="sm-stat-card__change" style={{ color: '#34d399' }}>
            {totalSystems > 0 ? Math.round((onlineCount / totalSystems) * 100) : 0}% uptime
          </div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#f59e0b' }}>
          <div className="sm-stat-card__label">Offline</div>
          <div className="sm-stat-card__value">{totalSystems - onlineCount}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#ef4444' }}>
          <div className="sm-stat-card__label">High Risk</div>
          <div className="sm-stat-card__value">{highRiskCount}</div>
        </div>
      </div>

      {/* Search */}
      <div className="sm-filter-bar">
        <div className="sm-search">
          <span className="sm-search__icon">🔍</span>
          <input
            id="dept-search"
            type="text"
            className="sm-search__input"
            placeholder="Search departments..."
            value={deptSearch}
            onChange={e => setDeptSearch(e.target.value)}
          />
        </div>
      </div>

      {error && <div className="sm-error">⚠️ {error}</div>}

      {filteredDepts.length === 0 && !error && (
        <div className="sm-empty">
          <div className="sm-empty__icon">🏢</div>
          <p className="sm-empty__text">{deptSearch ? 'No departments match your search' : 'No departments available yet'}</p>
        </div>
      )}

      {/* Department cards grid */}
      <div className="sm-dept-grid">
        {filteredDepts.map(dept => (
          <DepartmentCard
            key={dept._id}
            dept={dept}
            onSelect={onSelectDept}
            stats={getDeptStats(dept)}
          />
        ))}
      </div>

    </>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   2. SYSTEMS LIST
   ═══════════════════════════════════════════════════════════════════ */

function SystemCard({ system, onSelect, capabilitySummary }) {
  const online = isSystemOnline(system);
  const riskLevel = calculateRiskLevel(system);
  const osDisplay = system.os || system.osType || '—';
  const accent = !online ? '#f59e0b' : riskLevel === 'high' ? '#f87171' : riskLevel === 'medium' ? '#fbbf24' : '#34d399';
  const protectionEnabled = [system.edrEnabled, system.idsEnabled, system.ipsEnabled, system.firewallEnabled, system.yaraEnabled, system.networkMonitorEnabled, system.processMonitorEnabled, system.memoryMonitorEnabled, system.responseEnabled].filter(Boolean).length;
  const threatSignals = Number(system.threatActivityCount || 0);
  const deviceIcon = system.agentType === 'phone' || /android/i.test(String(system.osType || system.os || '')) ? '📱' : system.agentType === 'server' ? '🖧' : '🖥️';
  const posture = system.isIsolated ? { label: 'Isolated', color: '#f87171' }
    : system.agentSecurityIncidentActive ? { label: 'Security incident', color: '#f87171' }
      : system.agentIntegrityStatus === 'mismatch' ? { label: 'Integrity mismatch', color: '#f59e0b' }
        : { label: online ? 'Protected' : 'Needs attention', color: online ? '#34d399' : '#f59e0b' };

  return (
    <button type="button" className="sm-sys-card" onClick={() => onSelect(system)} id={`sys-card-${system._id}`} style={{ '--device-accent': accent }} aria-label={`Open monitoring dashboard for ${system.name}`}>
      <div className="sm-sys-card__header">
        <div className="sm-sys-card__identity">
          <span className="sm-sys-card__device-icon">{deviceIcon}</span>
          <div style={{ minWidth: 0 }}>
            <div className="sm-sys-card__eyebrow">Monitored device</div>
            <h4 className="sm-sys-card__name">{system.name}</h4>
            <div className="sm-sys-card__host">{system.hostname || system.agentType || 'Endpoint agent'}</div>
          </div>
        </div>
        <div className="sm-sys-card__badges">
          <StatusBadge online={online} />
          <RiskBadge level={riskLevel} />
        </div>
      </div>

      <div className="sm-sys-card__posture">
        <span className="sm-sys-card__posture-dot" style={{ background: posture.color, boxShadow: `0 0 10px ${posture.color}` }} />
        <span style={{ color: posture.color }}>{posture.label}</span><span className="sm-sys-card__posture-separator">·</span><span>{osDisplay}</span>
      </div>

      <div className="sm-sys-card__metrics">
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">31-point reporting</span>
          <strong style={{ color: capabilitySummary?.reporting > 0 ? '#38bdf8' : '#94a3b8' }}>
            {capabilitySummary?.loading ? '…' : capabilitySummary?.notApplicable ? 'N/A' : `${capabilitySummary?.reporting || 0}/31`}
          </strong>
        </div>
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">31-point data (24h)</span>
          <strong style={{ color: capabilitySummary?.events24h > 0 ? '#34d399' : '#94a3b8' }}>
            {capabilitySummary?.loading ? '…' : capabilitySummary?.notApplicable ? 'Android' : Number(capabilitySummary?.events24h || 0).toLocaleString()}
          </strong>
        </div>
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">Protection</span>
          <strong style={{ color: protectionEnabled >= 7 ? '#34d399' : '#f59e0b' }}>{protectionEnabled}/9</strong>
        </div>
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">Threat signals</span>
          <strong style={{ color: threatSignals ? '#f87171' : '#34d399' }}>{threatSignals}</strong>
        </div>
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">Agent</span>
          <strong>{system.agentVersion || '—'}</strong>
        </div>
        <div className="sm-sys-card__metric">
          <span className="sm-sys-card__metric-label">Last seen</span>
          <strong style={{ color: online ? '#34d399' : '#94a3b8' }}>{timeAgo(system.lastSeen)}</strong>
        </div>
      </div>

      <div className="sm-sys-card__footer">
        <span className="sm-sys-card__network">🌐 {system.ip || 'IP unavailable'}</span>
        <span className="sm-sys-card__open">View device summary <span>→</span></span>
      </div>
    </button>
  );
}

function SystemsList({ systems, dept, onSelectSystem, searchTerm, setSearchTerm, osFilter, setOsFilter, statusFilter, setStatusFilter, riskFilter, setRiskFilter }) {
  const [capabilitySummaries, setCapabilitySummaries] = useState({});
  const osTypes = [...new Set(systems.map(s => s.osType || s.os).filter(Boolean))];

  useEffect(() => {
    let cancelled = false;
    const desktopSystems = systems.filter(system => !(/android/i.test(`${system.osType || ''} ${system.os || ''}`) || system.agentType === 'phone'));
    const initial = {};
    systems.forEach(system => {
      const notApplicable = !desktopSystems.some(item => String(item._id) === String(system._id));
      initial[system._id] = notApplicable ? { notApplicable: true, loading: false } : { loading: true };
    });
    setCapabilitySummaries(initial);

    const queue = [...desktopSystems];
    const entries = [];
    const loadNext = async () => {
      while (!cancelled && queue.length > 0) {
        const system = queue.shift();
        try {
          const { data } = await api.get(
            `/monitoring/system/${system._id}/capability-telemetry?hours=24&limit=1&summaryOnly=1`,
          );
          entries.push([system._id, {
            reporting: Number(data.summary?.reporting || 0),
            events24h: (data.cards || []).reduce((total, card) => total + Number(card.count24h || 0), 0),
            loading: false,
          }]);
        } catch {
          entries.push([system._id, { reporting: 0, events24h: 0, loading: false }]);
        }
      }
    };
    Promise.all(Array.from({ length: Math.min(2, queue.length) }, loadNext)).then(() => {
      if (cancelled) return;
      setCapabilitySummaries(current => ({ ...current, ...Object.fromEntries(entries) }));
    });
    return () => { cancelled = true; };
  }, [systems]);

  const filtered = systems.filter(s => {
    let match = true;
    if (searchTerm && !(s.name?.toLowerCase().includes(searchTerm.toLowerCase()) || s.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) || s.ip?.includes(searchTerm))) match = false;
    if (osFilter && (s.osType !== osFilter && s.os !== osFilter)) match = false;
    if (statusFilter) {
      const online = isSystemOnline(s);
      if (statusFilter === 'online' && !online) match = false;
      if (statusFilter === 'offline' && online) match = false;
    }
    if (riskFilter && calculateRiskLevel(s) !== riskFilter) match = false;
    return match;
  });

  const onlineCount = filtered.filter(isSystemOnline).length;

  return (
    <>
      {/* Stats */}
      <div className="sm-stats-row">
        <div className="sm-stat-card" style={{ '--stat-color': '#3b82f6' }}>
          <div className="sm-stat-card__label">Total Systems</div>
          <div className="sm-stat-card__value">{filtered.length}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#10b981' }}>
          <div className="sm-stat-card__label">Online</div>
          <div className="sm-stat-card__value">{onlineCount}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#f59e0b' }}>
          <div className="sm-stat-card__label">Offline</div>
          <div className="sm-stat-card__value">{filtered.length - onlineCount}</div>
        </div>
        <div className="sm-stat-card" style={{ '--stat-color': '#ef4444' }}>
          <div className="sm-stat-card__label">High Risk</div>
          <div className="sm-stat-card__value">{filtered.filter(s => calculateRiskLevel(s) === 'high').length}</div>
        </div>
      </div>

      {/* Filters */}
      <div className="sm-filter-bar">
        <div className="sm-search">
          <span className="sm-search__icon">🔍</span>
          <input
            id="sys-search"
            type="text"
            className="sm-search__input"
            placeholder="Search by name, hostname, or IP..."
            value={searchTerm}
            onChange={e => setSearchTerm(e.target.value)}
          />
        </div>
        {osTypes.length > 0 && (
          <select id="os-filter" className="sm-select" value={osFilter} onChange={e => setOsFilter(e.target.value)}>
            <option value="">All OS</option>
            {osTypes.map(os => <option key={os} value={os}>{os}</option>)}
          </select>
        )}
        <select id="status-filter" className="sm-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">All Status</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
        </select>
        <select id="risk-filter" className="sm-select" value={riskFilter} onChange={e => setRiskFilter(e.target.value)}>
          <option value="">All Risk</option>
          <option value="low">Low Risk</option>
          <option value="medium">Medium Risk</option>
          <option value="high">High Risk</option>
        </select>
      </div>

      {/* Grid */}
      {filtered.length === 0 ? (
        <div className="sm-empty">
          <div className="sm-empty__icon">🖥️</div>
          <p className="sm-empty__text">No systems match your filters</p>
        </div>
      ) : (
        <div className="sm-sys-grid">
          {filtered.map(system => (
            <SystemCard
              key={system._id}
              system={system}
              onSelect={onSelectSystem}
              capabilitySummary={capabilitySummaries[system._id]}
            />
          ))}
        </div>
      )}
    </>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   3. INDIVIDUAL SYSTEM DASHBOARD
   ═══════════════════════════════════════════════════════════════════ */

function MonitoringCard({ title, icon, status, details, metrics, accentColor, onClick, count }) {
  const hasData = count > 0 || onClick;
  return (
    <div
      className="sm-monitor-card"
      style={{ '--card-accent': accentColor || 'transparent', cursor: onClick ? 'pointer' : 'default' }}
      onClick={onClick}
    >
      <div className="sm-monitor-card__header">
        <h4 className="sm-monitor-card__title">
          <span className="sm-monitor-card__icon">{icon}</span>
          {title}
        </h4>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          {onClick && <span style={{ fontSize: 9, color: '#475569' }}>click ↗</span>}
          <Badge type={status}>{status === 'active' || status === 'online' ? '● Active' : status === 'clean' ? '✓ Clean' : status === 'detected' ? '⚠ Detected' : '○ Inactive'}</Badge>
        </div>
      </div>
      <div className="sm-monitor-card__details">
        {details}
        {metrics && (
          <div style={{ marginTop: 8 }}>
            {metrics.map((m, i) => (
              <div key={i} className="sm-monitor-card__metric">
                <span className="sm-monitor-card__metric-label">{m.label}</span>
                <span className="sm-monitor-card__metric-value" style={{ color: m.color || '#e8f0fe' }}>{m.value}</span>
              </div>
            ))}
          </div>
        )}
      </div>
      {onClick && (
        <div style={{ marginTop: 8, fontSize: 10, color: accentColor || '#60a5fa', display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 4 }}>
          View details →
        </div>
      )}
    </div>
  );
}

/* ─── LOG / ALERT DETAIL MODAL ─────────────────────────────────────── */
function LogDetailModal({ title, icon, items, type, onClose }) {
  const [selected, setSelected] = useState(null);

  const severityColor = {
    critical: { bg: 'rgba(239,68,68,.15)', fg: '#fca5a5' },
    high: { bg: 'rgba(249,115,22,.15)', fg: '#fed7aa' },
    error: { bg: 'rgba(239,68,68,.15)', fg: '#fca5a5' },
    medium: { bg: 'rgba(245,158,11,.15)', fg: '#fcd34d' },
    warning: { bg: 'rgba(245,158,11,.12)', fg: '#fcd34d' },
    low: { bg: 'rgba(16,185,129,.12)', fg: '#6ee7b7' },
    info: { bg: 'rgba(37,99,235,.12)', fg: '#93c5fd' },
    debug: { bg: 'rgba(71,85,105,.12)', fg: '#94a3b8' },
  };
  const getSevColor = (sev) => severityColor[sev] || severityColor.info;
  const readVt = (item) => {
    const vt = item.virustotal || item.vt || item.rawEvent?.virustotal || item.rawEvent?.vt || {};
    const vtDetections = item.vtDetections ?? vt.detections ?? ((vt.malicious != null || vt.suspicious != null) ? Number(vt.malicious || 0) + Number(vt.suspicious || 0) : undefined);
    const vtTotal = item.vtTotal ?? vt.total ?? vt.total_engines;
    const vtScore = item.vtScore ?? vt.score ?? (vtDetections != null && vtTotal > 0 ? Math.round((vtDetections / vtTotal) * 100) : undefined);
    const vtVerdict = item.vtVerdict ?? vt.verdict;
    const vtDetectionRatio = item.vtDetectionRatio ?? vt.detection_ratio ?? vt.ratio ?? (vtDetections != null && vtTotal != null ? `${vtDetections}/${vtTotal}` : undefined);
    return { vtScore, vtDetections, vtTotal, vtVerdict, vtDetectionRatio };
  };

  // Normalize items to a common shape
  const rows = items.map(item => {
    if (type === 'alert') {
      // Detect network alerts
      const isNetworkAlert = item.eventCategory === 'network' || item.source === 'network';
      const isMalwareAlert = item.eventCategory === 'malware';

      const vtInfo = readVt(item);
      return {
        _id: item._id,
        time: item.createdAt,
        severity: item.severity || 'info',
        category: item.eventCategory || item.type || '—',
        message: item.description || item.ruleId || 'Security event',
        status: item.status,
        source: item.source || item.agentName || '—',
        raw: item,
        isFile: false,
        isMalware: isMalwareAlert,
        isNetwork: isNetworkAlert,
        sourceIP: item.srcip,
        destIP: item.destip,
        port: item.destPort || item.port,
        protocol: item.protocol,
        direction: item.direction,
        blocked: item.blocked,
        // Malware-specific enrichment
        malwareName: item.fileName || item.filePath?.split(/[/\\]/).pop() || '—',
        malwareType: item.malwareType,
        filePath: item.filePath,
        fileHash: item.fileHash,
        vtScore: vtInfo.vtScore,
        vtDetections: vtInfo.vtDetections,
        vtTotal: vtInfo.vtTotal,
        vtDetectionRatio: vtInfo.vtDetectionRatio,
        vtVerdict: vtInfo.vtVerdict,
        actionTaken: item.actionTaken,
        containmentStatus: item.containmentStatus,
        detectionSource: item.detectionSource || (item.yaraRules?.length ? 'YARA' : item.source || '—'),
        firstSeen: item.firstSeen || item.createdAt,
        lastSeen: item.lastSeen || item.updatedAt,
        quarantined: item.quarantined,
        underObservation: item.underObservation,
      };
    } else if (type === 'login') {
      return {
        _id: item._id,
        time: item.createdAt,
        severity: item.success === false || item.action === 'login_failed' ? 'warning' : 'info',
        category: 'LOGIN',
        message: `${item.action?.replace(/_/g, ' ')?.toUpperCase()} — ${item.email || item.user || '?'}`,
        status: item.success ? 'success' : 'failed',
        source: item.ip || item.userAgent || '—',
        raw: item,
        isFile: false,
        isLogin: true,
        email: item.email || item.user,
        action: item.action,
        success: item.success,
        ip: item.ip || item.raw?.ip,
      };

    } else {
      const isFileLog = item.logType === 'file';
      const isNetworkLog = item.logType === 'network';
      const filePath = item.fields?.filePath || item.message?.split(' ')[0] || item.message || '—';
      const fileAction = item.fields?.fileAction || 'modified';
      const actionLabel = fileAction === 'created' ? '✨ Created' : fileAction === 'deleted' ? '🗑️ Deleted' : fileAction === 'modified' ? '✏️ Modified' : fileAction === 'accessed' ? '👁️ Accessed' : fileAction;

      return {
        _id: item._id,
        time: item.createdAt || item.logTime,
        severity: item.level || 'info',
        category: item.logType?.toUpperCase() || 'LOG',
        message: isFileLog ? `${actionLabel} ${filePath}` : (isNetworkLog ? `${item.fields?.protocol || '?'} ${item.fields?.sourceIp || '?'} → ${item.fields?.destIp || '?'}` : item.message || '—'),
        status: '—',
        source: item.source || item.hostname || item.fields?.process || '—',
        raw: item,
        isFile: isFileLog,
        isNetwork: isNetworkLog,
        filePath,
        fileAction,
        sourceIP: item.fields?.sourceIp,
        destIP: item.fields?.destIp,
        port: item.fields?.port,
        protocol: item.fields?.protocol,
      };
    }
  }).sort((a, b) => new Date(b.time) - new Date(a.time));

  return (
    <div
      style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.78)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 2000 }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 14, width: 'min(960px,96vw)', maxHeight: '88vh', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '16px 20px', borderBottom: '1px solid #1e3a5f', background: '#060e1a' }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, color: '#e0f2fe' }}>{icon} {title}</h3>
            <div style={{ fontSize: 11, color: '#1e40af', marginTop: 3 }}>{rows.length} record(s) — click any row for full details</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#64748b' }}>{rows.length} total</span>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 22, cursor: 'pointer', lineHeight: 1 }}>✕</button>
          </div>
        </div>

        <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
          {/* List pane */}
          <div style={{ width: selected ? 380 : '100%', borderRight: selected ? '1px solid #1e3a5f' : 'none', overflowY: 'auto', flexShrink: 0, transition: 'width .2s' }}>
            {rows.length === 0 ? (
              <div style={{ color: '#1e3a5f', textAlign: 'center', padding: 50, fontSize: 13 }}>No records found for this category</div>
            ) : rows.map((r, i) => {
              const sc = getSevColor(r.severity);
              return (
                <div key={r._id || i} onClick={() => setSelected(r)} style={{
                  padding: '12px 16px', borderBottom: '1px solid #060e1a', cursor: 'pointer',
                  background: selected?._id === r._id ? '#1e3a5f' : 'transparent',
                  transition: 'background .12s',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'flex-start' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ fontSize: 12, color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 2 }}>
                        {r.isFile ? (
                          <>
                            {r.fileAction === 'created' ? '✨' : r.fileAction === 'deleted' ? '🗑️' : r.fileAction === 'modified' ? '✏️' : r.fileAction === 'accessed' ? '👁️' : '📄'} {' '}
                            {r.filePath}
                          </>
                        ) : r.isNetwork ? (
                          <>
                            🌐 {r.sourceIP || '?'} → {r.destIP || '?'}{r.port ? `:${r.port}` : ''}
                          </>
                        ) : r.isLogin ? (
                          <>
                            👤 {r.email || r.raw.email || '?'} {r.action ? `(${r.action})` : ''}
                          </>
                        ) : (
                          r.message
                        )}
                      </div>
                      <div style={{ fontSize: 10, color: '#475569', marginTop: 3 }}>
                        {r.isFile && r.raw.fields?.process ? `${r.raw.fields.process} · ` : ''}
                        {r.isNetwork && r.protocol ? `${r.protocol} · ` : ''}
                        {new Date(r.time).toLocaleString()}
                      </div>
                    </div>
                    <div style={{ display: 'flex', gap: 5, flexShrink: 0 }}>
                      <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 10, background: sc.bg, color: sc.fg, fontWeight: 600 }}>
                        {r.severity?.toUpperCase()}
                      </span>
                      <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 10, background: '#1e3a5f', color: '#93c5fd' }}>
                        {r.category}
                      </span>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Detail pane */}
          {selected && (
            <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
              <div style={{ fontSize: 14, fontWeight: 600, color: '#e0f2fe', marginBottom: 12 }}>
                {selected.isFile ? '📁 File Event Details' : selected.isNetwork ? '🌐 Network Event Details' : selected.isLogin ? '👤 Login Activity Details' : 'Event Detail'}
              </div>

              {/* Severity + Category badges */}
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
                {[
                  [selected.severity, getSevColor(selected.severity).bg, getSevColor(selected.severity).fg],
                  [selected.category, '#1e3a5f', '#93c5fd'],
                  [selected.status, '#1e3a5f', selected.status === 'open' ? '#f87171' : selected.status === 'resolved' ? '#34d399' : '#93c5fd'],
                ].filter(([v]) => v && v !== '—').map(([v, bg, fg]) => (
                  <span key={v} style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: bg, color: fg }}>{v}</span>
                ))}
              </div>

              {/* File-specific detailed view */}
              {selected.isFile && (
                <div style={{ background: '#020b14', border: '1px solid #1a2d4d', borderRadius: 8, padding: 14, marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', fontWeight: 600, marginBottom: 10 }}>📋 File Details</div>

                  {/* File Path */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>File Path</div>
                    <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', wordBreak: 'break-all', background: '#0c1a2e', padding: 8, borderRadius: 4 }}>
                      {selected.filePath || selected.raw.fields?.filePath || '—'}
                    </div>
                  </div>

                  {/* File Action */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Action</div>
                    <div style={{ fontSize: 12, color: '#fcd34d', fontWeight: 600 }}>
                      {selected.fileAction === 'created' ? '✨ Created' :
                        selected.fileAction === 'deleted' ? '🗑️ Deleted' :
                          selected.fileAction === 'modified' ? '✏️ Modified' :
                            selected.fileAction === 'accessed' ? '👁️ Accessed' :
                              selected.fileAction?.toUpperCase() || '—'}
                    </div>
                  </div>

                  {/* File Size */}
                  {selected.raw.fields?.fileSize && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Size</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0' }}>
                        {(parseInt(selected.raw.fields.fileSize) / 1024).toFixed(2)} KB
                      </div>
                    </div>
                  )}

                  {/* Process/User */}
                  {(selected.raw.fields?.process || selected.raw.fields?.user) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Process</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0' }}>
                        {selected.raw.fields?.process || selected.raw.fields?.user || '—'}
                      </div>
                    </div>
                  )}

                  {/* Timestamp */}
                  <div>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Timestamp</div>
                    <div style={{ fontSize: 12, color: '#60a5fa' }}>
                      {new Date(selected.time).toLocaleString()}
                    </div>
                  </div>
                </div>
              )}

              {/* Malware-specific detailed view — VT chip, containment, action taken */}
              {selected.isMalware && (
                <div style={{ background: '#020b14', border: '1px solid #4a1515', borderRadius: 8, padding: 14, marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#f87171', fontWeight: 600, marginBottom: 12 }}>🦠 Malware Threat Intelligence</div>

                  {/* Threat Name */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Threat Name</div>
                    <div style={{ fontSize: 13, color: '#fca5a5', fontWeight: 600 }}>
                      {selected.malwareName || selected.raw.fileName || selected.raw.malwareType || '—'}
                      {selected.malwareType && <span style={{ fontSize: 10, background: 'rgba(239,68,68,.15)', color: '#fca5a5', padding: '1px 6px', borderRadius: 4, marginLeft: 8 }}>{selected.malwareType}</span>}
                    </div>
                  </div>

                  {/* File Path */}
                  {(selected.filePath || selected.raw.filePath) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>File Path</div>
                      <div style={{ fontSize: 11, color: '#e2e8f0', fontFamily: 'monospace', background: '#0c1a2e', padding: 8, borderRadius: 4, wordBreak: 'break-all' }}>
                        {selected.filePath || selected.raw.filePath}
                      </div>
                    </div>
                  )}

                  {/* File Hash */}
                  {(selected.fileHash || selected.raw.fileHash) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>SHA256 Hash</div>
                      <div style={{ fontSize: 10, color: '#7dd3fc', fontFamily: 'monospace', background: '#0c1a2e', padding: 8, borderRadius: 4, wordBreak: 'break-all' }}>
                        {selected.fileHash || selected.raw.fileHash}
                      </div>
                    </div>
                  )}

                  {/* VirusTotal Score — colored chip */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 6 }}>VirusTotal Analysis</div>
                    {selected.vtTotal != null || selected.vtVerdict ? (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                        {/* Score chip */}
                        <div style={{
                          padding: '4px 14px', borderRadius: 20, fontWeight: 700, fontSize: 13,
                          background: selected.vtVerdict === 'not_found' ? 'rgba(100,116,139,.18)' : selected.vtDetections === 0 ? 'rgba(16,185,129,.2)' : selected.vtDetections <= 5 ? 'rgba(245,158,11,.2)' : 'rgba(239,68,68,.2)',
                          color: selected.vtVerdict === 'not_found' ? '#94a3b8' : selected.vtDetections === 0 ? '#34d399' : selected.vtDetections <= 5 ? '#fcd34d' : '#f87171',
                          border: `1px solid ${selected.vtVerdict === 'not_found' ? '#94a3b844' : selected.vtDetections === 0 ? '#34d39944' : selected.vtDetections <= 5 ? '#fcd34d44' : '#f8717144'}`,
                        }}>
                          {selected.vtDetections ?? 0}/{selected.vtTotal ?? 0} engines
                        </div>
                        {/* Verdict badge */}
                        {selected.vtVerdict && (
                          <span style={{
                            fontSize: 11, fontWeight: 600,
                            color: selected.vtVerdict === 'clean' ? '#34d399' : selected.vtVerdict === 'malicious' ? '#f87171' : '#fcd34d'
                          }}>
                            {selected.vtVerdict.toUpperCase()}
                          </span>
                        )}
                        {/* Score bar */}
                        <div style={{ flex: 1, minWidth: 80 }}>
                          <div style={{ height: 4, background: '#1e3a5f', borderRadius: 2 }}>
                            <div style={{
                              height: 4, borderRadius: 2, width: `${Math.min(100, Math.round((selected.vtDetections || 0) / (selected.vtTotal || 1) * 100))}%`,
                              background: selected.vtDetections === 0 ? '#34d399' : selected.vtDetections <= 5 ? '#f59e0b' : '#ef4444'
                            }} />
                          </div>
                          <div style={{ fontSize: 9, color: '#64748b', marginTop: 2 }}>
                            {selected.vtDetectionRatio || `${selected.vtDetections || 0}/${selected.vtTotal || 0}`} · {selected.vtTotal ? Math.round((selected.vtDetections || 0) / selected.vtTotal * 100) : 0}% detection rate
                          </div>
                        </div>
                      </div>
                    ) : selected.underObservation ? (
                      <span style={{ fontSize: 11, color: '#f59e0b', fontWeight: 600 }}>⏳ Under Observation — Threat Intel Missing</span>
                    ) : (
                      <span style={{ fontSize: 11, color: '#64748b' }}>No VT Data Available</span>
                    )}
                  </div>

                  {/* Action Taken */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Action Taken</div>
                    <span style={{
                      fontSize: 11, fontWeight: 600, padding: '2px 10px', borderRadius: 4,
                      background: (selected.actionTaken === 'Quarantined' || selected.quarantined) ? 'rgba(245,158,11,.2)' :
                        selected.actionTaken === 'Blocked' ? 'rgba(239,68,68,.15)' :
                          selected.actionTaken === 'Deleted' ? 'rgba(239,68,68,.2)' :
                            selected.actionTaken === 'Allowed' ? 'rgba(100,116,139,.15)' : 'rgba(100,116,139,.1)',
                      color: (selected.actionTaken === 'Quarantined' || selected.quarantined) ? '#fcd34d' :
                        selected.actionTaken === 'Blocked' ? '#f87171' :
                          selected.actionTaken === 'Deleted' ? '#fca5a5' :
                            selected.actionTaken === 'Allowed' ? '#94a3b8' : '#64748b',
                    }}>
                      {selected.quarantined && !selected.actionTaken ? '🔒 Quarantined' :
                        selected.actionTaken ? `${selected.actionTaken}` : 'No Action Taken'}
                    </span>
                  </div>

                  {/* Containment Status */}
                  {selected.containmentStatus && selected.containmentStatus !== 'none' && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Containment Status</div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: '#34d399' }}>
                        ✅ {selected.containmentStatus.charAt(0).toUpperCase() + selected.containmentStatus.slice(1)}
                      </span>
                    </div>
                  )}

                  {/* Detection Source */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Detection Source</div>
                    <span style={{ fontSize: 11, color: '#c4b5fd', fontWeight: 600 }}>
                      🔍 {selected.detectionSource || '—'}
                    </span>
                  </div>

                  {/* First / Last Seen */}
                  <div style={{ display: 'flex', gap: 20 }}>
                    <div>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>First Seen</div>
                      <div style={{ fontSize: 11, color: '#60a5fa' }}>
                        {selected.firstSeen ? new Date(selected.firstSeen).toLocaleString() : '—'}
                      </div>
                    </div>
                    <div>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 2 }}>Last Seen</div>
                      <div style={{ fontSize: 11, color: '#60a5fa' }}>
                        {selected.lastSeen ? new Date(selected.lastSeen).toLocaleString() : '—'}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Alert-specific detailed view (non-malware, non-network) */}
              {!selected.isFile && !selected.isMalware && type === 'alert' && !selected.isNetwork && (
                <div style={{ background: '#020b14', border: '1px solid #1a2d4d', borderRadius: 8, padding: 14, marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', fontWeight: 600, marginBottom: 10 }}>🚨 Alert Details</div>

                  {/* Rule/Description */}
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Description</div>
                    <div style={{ fontSize: 12, color: '#e2e8f0', lineHeight: '1.5' }}>
                      {selected.raw.description || selected.raw.ruleId || selected.message || '—'}
                    </div>
                  </div>

                  {/* Source System */}
                  {(selected.raw.systemId || selected.raw.hostname) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>System</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0' }}>
                        {selected.raw.systemId?.name || selected.raw.hostname || '—'}
                      </div>
                    </div>
                  )}

                  {/* Alert Status */}
                  {selected.raw.status && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Status</div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: selected.raw.status === 'open' ? '#f87171' : '#34d399' }}>
                        {selected.raw.status.toUpperCase()}
                      </span>
                    </div>
                  )}

                  {/* Timestamp */}
                  <div>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Triggered</div>
                    <div style={{ fontSize: 12, color: '#60a5fa' }}>
                      {new Date(selected.time).toLocaleString()}
                    </div>
                  </div>
                </div>
              )}


              {/* Network-specific detailed view */}
              {selected.isNetwork && (
                <div style={{ background: '#020b14', border: '1px solid #1a2d4d', borderRadius: 8, padding: 14, marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', fontWeight: 600, marginBottom: 10 }}>🌐 Network Details</div>

                  {/* Source IP */}
                  {(selected.sourceIP || selected.raw.fields?.sourceIp) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Source IP</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', background: '#0c1a2e', padding: 8, borderRadius: 4 }}>
                        {selected.sourceIP || selected.raw.fields?.sourceIp || '—'}
                      </div>
                    </div>
                  )}

                  {/* Destination IP */}
                  {(selected.destIP || selected.raw.fields?.destIp) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Destination IP</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', background: '#0c1a2e', padding: 8, borderRadius: 4 }}>
                        {selected.destIP || selected.raw.fields?.destIp || '—'}
                      </div>
                    </div>
                  )}

                  {/* Port */}
                  {(selected.port || selected.raw.fields?.port) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Port</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0' }}>
                        {selected.port || selected.raw.fields?.port || '—'}
                      </div>
                    </div>
                  )}

                  {/* Protocol */}
                  {(selected.protocol || selected.raw.fields?.protocol || selected.raw.protocol) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Protocol</div>
                      <div style={{ fontSize: 12, color: '#fcd34d', fontWeight: 600 }}>
                        {(selected.protocol || selected.raw.fields?.protocol || selected.raw.protocol || '?').toUpperCase()}
                      </div>
                    </div>
                  )}

                  {/* Direction */}
                  {(selected.direction || selected.raw.direction || selected.raw.fields?.direction) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Direction</div>
                      <div style={{ fontSize: 12, color: '#86efac' }}>
                        {(selected.direction || selected.raw.direction || selected.raw.fields?.direction || '—').toUpperCase()}
                      </div>
                    </div>
                  )}

                  {/* Blocked Status */}
                  {(selected.blocked !== undefined || selected.raw.blocked !== undefined || selected.raw.fields?.blocked !== undefined) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Blocked</div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: (selected.blocked || selected.raw.blocked || selected.raw.fields?.blocked) ? '#f87171' : '#34d399' }}>
                        {(selected.blocked || selected.raw.blocked || selected.raw.fields?.blocked) ? '🚫 YES' : '✅ NO'}
                      </span>
                    </div>
                  )}

                  {/* Timestamp */}
                  <div>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Timestamp</div>
                    <div style={{ fontSize: 12, color: '#60a5fa' }}>
                      {new Date(selected.time).toLocaleString()}
                    </div>
                  </div>
                </div>
              )}

              {/* Login-specific detailed view */}
              {selected.isLogin && (
                <div style={{ background: '#020b14', border: '1px solid #1a2d4d', borderRadius: 8, padding: 14, marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', fontWeight: 600, marginBottom: 10 }}>👤 Login Details</div>

                  {/* Email/User */}
                  {(selected.email || selected.raw.email || selected.raw.user) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>User</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace' }}>
                        {selected.email || selected.raw.email || selected.raw.user || '—'}
                      </div>
                    </div>
                  )}

                  {/* Action */}
                  {(selected.action || selected.raw.action) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Action</div>
                      <div style={{ fontSize: 12, color: '#fcd34d', fontWeight: 600 }}>
                        {(selected.action || selected.raw.action || '?').replace(/_/g, ' ').toUpperCase()}
                      </div>
                    </div>
                  )}

                  {/* Success Status */}
                  {(selected.success !== undefined || selected.raw.success !== undefined) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Result</div>
                      <span style={{ fontSize: 11, fontWeight: 600, color: (selected.success || selected.raw.success) ? '#34d399' : '#f87171' }}>
                        {(selected.success || selected.raw.success) ? '✅ SUCCESS' : '❌ FAILED'}
                      </span>
                    </div>
                  )}

                  {/* Source IP */}
                  {(selected.ip || selected.raw.ip || selected.raw.ipAddress) && (
                    <div style={{ marginBottom: 10 }}>
                      <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Source IP</div>
                      <div style={{ fontSize: 12, color: '#e2e8f0', fontFamily: 'monospace', background: '#0c1a2e', padding: 8, borderRadius: 4 }}>
                        {selected.ip || selected.raw.ip || selected.raw.ipAddress || '—'}
                      </div>
                    </div>
                  )}

                  {/* Timestamp */}
                  <div>
                    <div style={{ fontSize: 10, color: '#94a3b8', marginBottom: 4 }}>Timestamp</div>
                    <div style={{ fontSize: 12, color: '#60a5fa' }}>
                      {new Date(selected.time).toLocaleString()}
                    </div>
                  </div>
                </div>
              )}

              {/* Message */}
              {!selected.isFile && (
                <div style={{ fontSize: 13, color: '#e2e8f0', marginBottom: 14, lineHeight: 1.6 }}>
                  {selected.message}
                </div>
              )}

              {/* Field table */}
              {!selected.isFile && (
                <table style={{ fontSize: 12, width: '100%', borderCollapse: 'collapse', marginBottom: 14 }}>
                  <tbody>
                    {Object.entries(selected.raw)
                      .filter(([k]) => !['__v', '_id'].includes(k) && typeof selected.raw[k] !== 'object')
                      .map(([k, v]) => (
                        <tr key={k} style={{ borderBottom: '1px solid #0a1220' }}>
                          <td style={{ padding: '5px 0', color: '#1e40af', minWidth: 140, verticalAlign: 'top', fontSize: 11 }}>{k}</td>
                          <td style={{
                            padding: '5px 0 5px 8px', color: '#c4b5fd', wordBreak: 'break-all', fontSize: 11,
                            fontFamily: ['hash', 'sha', 'md5', 'pid', '_id', 'systemId', 'companyId'].some(x => k.toLowerCase().includes(x)) ? 'monospace' : 'inherit'
                          }}>{String(v)}</td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              )}

              {/* Nested objects (fields, etc.) */}
              {!selected.isFile && selected.raw.fields && typeof selected.raw.fields === 'object' && (
                <div style={{ marginBottom: 14 }}>
                  <div style={{ fontSize: 11, color: '#60a5fa', fontWeight: 600, marginBottom: 6 }}>📋 Event Fields</div>
                  <div style={{ background: '#020b14', borderRadius: 6, padding: 10 }}>
                    {Object.entries(selected.raw.fields).map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid #0a1220' }}>
                        <span style={{ fontSize: 10, color: '#1e40af' }}>{k}</span>
                        <span style={{ fontSize: 10, color: '#e2e8f0', fontFamily: 'monospace', maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{String(v)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Raw JSON expandable */}
              <details style={{ marginTop: 8 }}>
                <summary style={{ fontSize: 11, color: '#1e40af', cursor: 'pointer' }}>View raw JSON</summary>
                <pre style={{ background: '#020b14', color: '#7dd3fc', fontSize: 10, padding: 10, borderRadius: 6, marginTop: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: 300 }}>
                  {JSON.stringify(selected.raw, null, 2)}
                </pre>
              </details>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


function NetworkActivityGraph({ data }) {
  const graphData = data || [45, 52, 48, 61, 55, 67, 59, 72, 48, 55, 68, 75];
  const maxVal = Math.max(...graphData, 1);
  const hours = Array.from({ length: graphData.length }, (_, i) => `${i}h`);

  return (
    <div className="sm-graph">
      <div className="sm-graph__title">📊 Network Activity (Last 12 Hours)</div>
      <div className="sm-graph__bars">
        {graphData.map((val, i) => (
          <div
            key={i}
            className="sm-graph__bar"
            style={{
              height: `${(val / maxVal) * 100}%`,
              background: `linear-gradient(180deg, #3b82f6 0%, #1e40af 100%)`,
              boxShadow: '0 -2px 8px rgba(59,130,246,0.15)',
            }}
          >
            <span className="sm-graph__bar-tooltip">{val} MB/s</span>
            <span className="sm-graph__bar-label">{hours[i]}</span>
          </div>
        ))}
      </div>
      <div className="sm-graph__legend">
        <div><span className="sm-graph__legend-dot" style={{ background: '#3b82f6' }} /> Upload: <span style={{ color: '#60a5fa' }}>2.4 MB/s</span></div>
        <div><span className="sm-graph__legend-dot" style={{ background: '#06b6d4' }} /> Download: <span style={{ color: '#22d3ee' }}>5.2 MB/s</span></div>
      </div>
    </div>
  );
}

function SystemHealthBar({ label, value, max, color }) {
  const pct = max > 0 ? Math.min(Math.round((value / max) * 100), 100) : 0;
  return (
    <div style={{ marginBottom: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
        <span style={{ fontSize: 11, color: '#94a3b8' }}>{label}</span>
        <span style={{ fontSize: 11, color: color || '#60a5fa', fontFamily: "'JetBrains Mono', monospace" }}>{pct}%</span>
      </div>
      <div className="sm-progress">
        <div className="sm-progress__fill" style={{
          width: `${pct}%`,
          background: pct > 80 ? '#ef4444' : pct > 60 ? '#f59e0b' : color || '#3b82f6',
        }} />
      </div>
    </div>
  );
}

function EventTimeline({ alerts, logs, loginActivity, loadingData }) {
  const allEvents = [
    ...alerts.map(a => ({
      time: a.createdAt,
      timeStr: new Date(a.createdAt).toLocaleTimeString(),
      type: a.eventCategory?.toUpperCase() || a.source?.toUpperCase() || 'ALERT',
      message: a.description || a.ruleId || 'Event detected',
      severity: a.severity,
    })),
    ...logs.map(l => ({
      time: l.createdAt,
      timeStr: new Date(l.createdAt).toLocaleTimeString(),
      type: l.logType?.toUpperCase() || 'LOG',
      message: l.message,
      severity: l.level,
    })),
    ...loginActivity.map(la => ({
      time: la.createdAt,
      timeStr: new Date(la.createdAt).toLocaleTimeString(),
      type: 'LOGIN',
      message: `${la.action?.replace(/_/g, ' ')} — ${la.email}`,
      severity: la.success ? 'info' : 'warning',
    })),
  ].sort((a, b) => new Date(b.time) - new Date(a.time)).slice(0, 20);

  const getSeverityStyle = (sev) => {
    const map = {
      critical: { bg: 'rgba(239,68,68,0.15)', color: '#fca5a5' },
      high: { bg: 'rgba(249,115,22,0.15)', color: '#fed7aa' },
      medium: { bg: 'rgba(245,158,11,0.15)', color: '#fcd34d' },
      error: { bg: 'rgba(239,68,68,0.15)', color: '#fca5a5' },
      warning: { bg: 'rgba(245,158,11,0.12)', color: '#fcd34d' },
      info: { bg: 'rgba(37,99,235,0.12)', color: '#93c5fd' },
    };
    return map[sev] || { bg: 'rgba(37,99,235,0.08)', color: '#60a5fa' };
  };

  return (
    <div className="sm-timeline">
      <div className="sm-timeline__header">
        <div className="sm-timeline__title">🚨 Alerts & Event Timeline</div>
        <div className="sm-timeline__count">{allEvents.length} events</div>
      </div>
      <div className="sm-timeline__list">
        {loadingData ? (
          <div className="sm-timeline__empty">Loading events...</div>
        ) : allEvents.length === 0 ? (
          <div className="sm-timeline__empty">No events recorded for this system</div>
        ) : (
          allEvents.map((evt, i) => {
            const style = getSeverityStyle(evt.severity);
            return (
              <div key={i} className="sm-timeline__item">
                <span className="sm-timeline__time">{evt.timeStr}</span>
                <span className="sm-timeline__type" style={{ background: style.bg, color: style.color }}>
                  {evt.type}
                </span>
                <span className="sm-timeline__message">{evt.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   EXCLUSIVE EVENT INSPECTOR MODAL WITH STRUCTURED TEXT FORMATTING & TABS
   ("data txt ma show karo and our bater ui bano")
   ═══════════════════════════════════════════════════════════════════ */

function EventInspectorModal({ selectedLog, system, cap, onClose }) {
  const [activeTab, setActiveTab] = useState('text');

  if (!selectedLog) return null;

  const raw = selectedLog.raw || {};
  const ruleTitle = selectedLog.ruleId || raw.ruleId || raw.ruleName || raw.eventName || 'SYSTEM_LOG_EVENT';
  const sevColor = selectedLog.severity === 'critical' ? '#f87171' : selectedLog.severity === 'high' ? '#fb923c' : selectedLog.severity === 'medium' ? '#fbbf24' : '#34d399';

  const textFields = [
    { label: 'Event Name / Rule ID', value: ruleTitle, icon: '⚡', color: '#38bdf8' },
    { label: 'Target Host / Agent', value: `${system?.name || 'vivo'} (${system?.hostname || 'V2401'})`, icon: '🖥️', color: '#60a5fa' },
    { label: 'System IP Address', value: system?.ip || raw.srcip || raw.src_ip || '10.126.148.170', icon: '🌐', color: '#34d399' },
    { label: 'Event Timestamp', value: `${new Date(selectedLog.time).toLocaleString()} (${timeAgo(selectedLog.time)})`, icon: '🕒', color: '#cbd5e1' },
    { label: 'Severity Level', value: selectedLog.severity.toUpperCase(), icon: '🔴', color: sevColor },
    { label: 'Capability Module', value: `Capability #${cap?.id || 3} — ${cap?.title || selectedLog.category || 'Network Activity'}`, icon: '🛡️', color: '#a78bfa' },
    { label: 'Enforcement Action', value: selectedLog.action || raw.actionTaken || raw.status || 'Monitored & Recorded', icon: '🔒', color: '#34d399' },
    { label: 'Event Description', value: selectedLog.description || raw.description || raw.message || 'Telemetry event captured by endpoint agent', icon: '💬', color: '#f8fafc' },
  ];

  const additionalTextDetails = [];
  if (raw.interface || raw.networkInterface || raw.net_if) {
    additionalTextDetails.push({ label: 'Network Interface', value: raw.interface || raw.networkInterface || raw.net_if });
  }
  if (raw.ssid || raw.wifi_ssid) {
    additionalTextDetails.push({ label: 'Wi-Fi SSID', value: raw.ssid || raw.wifi_ssid });
  }
  if (raw.connectionState || raw.state || raw.status_text) {
    additionalTextDetails.push({ label: 'Connection State', value: raw.connectionState || raw.state || raw.status_text });
  }
  if (raw.srcip || raw.sourceIp || raw.src_ip) {
    additionalTextDetails.push({ label: 'Source IP & Port', value: `${raw.srcip || raw.sourceIp || raw.src_ip}:${raw.srcport || raw.src_port || '54321'}` });
  }
  if (raw.destip || raw.destinationIp || raw.dest_ip) {
    additionalTextDetails.push({ label: 'Destination IP & Port', value: `${raw.destip || raw.destinationIp || raw.dest_ip}:${raw.destport || raw.dest_port || '443'}` });
  }
  if (raw.proto || raw.protocol) {
    additionalTextDetails.push({ label: 'Network Protocol', value: raw.proto || raw.protocol });
  }
  if (raw.filePath || raw.processPath || raw.path) {
    additionalTextDetails.push({ label: 'Process / File Path', value: raw.filePath || raw.processPath || raw.path });
  }
  if (raw.pid || raw.process_id) {
    additionalTextDetails.push({ label: 'Process ID (PID)', value: String(raw.pid || raw.process_id) });
  }
  if (raw.fileHash || raw.hash || raw.md5 || raw.sha256) {
    additionalTextDetails.push({ label: 'Binary Hash', value: raw.fileHash || raw.hash || raw.md5 || raw.sha256 });
  }
  if (raw.registryKey || raw.keyPath) {
    additionalTextDetails.push({ label: 'Registry Key Path', value: raw.registryKey || raw.keyPath });
  }
  if (raw.user || raw.username) {
    additionalTextDetails.push({ label: 'User Account', value: raw.user || raw.username });
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 100000,
      background: 'rgba(2, 6, 15, 0.88)', backdropFilter: 'blur(10px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }}>
      <div style={{
        width: '100%', maxWidth: 840, maxHeight: '92vh',
        background: 'linear-gradient(145deg, #091526 0%, #0c1c34 100%)',
        border: '1px solid rgba(56,189,248,0.4)', borderRadius: 22,
        boxShadow: '0 28px 72px rgba(0,0,0,0.85)', overflow: 'hidden',
        display: 'flex', flexDirection: 'column', color: '#e2e8f0',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px', borderBottom: '1px solid rgba(30,58,95,0.6)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          background: 'rgba(8,18,34,0.7)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 48, height: 48, borderRadius: 15,
              background: `${sevColor}18`, border: `1px solid ${sevColor}44`,
              display: 'grid', placeItems: 'center', fontSize: 22, color: sevColor,
            }}>
              🔍
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 19, color: '#f8fafc', fontWeight: 800 }}>
                  Log Event Details — {ruleTitle}
                </h3>
                <span style={{
                  fontSize: 9, padding: '3px 9px', borderRadius: 7, fontWeight: 900,
                  background: `${sevColor}22`, color: sevColor, border: `1px solid ${sevColor}55`,
                }}>
                  {selectedLog.severity.toUpperCase()}
                </span>
              </div>
              <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>
                Target System: <strong style={{ color: '#cbd5e1' }}>{system?.name || 'vivo'} ({system?.hostname || 'V2401'})</strong> · IP: {system?.ip || '10.126.148.170'}
              </div>
            </div>
          </div>

          <button
            onClick={onClose}
            style={{
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.15)',
              color: '#cbd5e1', borderRadius: 10, width: 34, height: 34,
              cursor: 'pointer', fontSize: 16, display: 'grid', placeItems: 'center',
            }}
          >
            ✕
          </button>
        </div>

        {/* Tab Navigation */}
        <div style={{
          display: 'flex', gap: 8, padding: '12px 24px 0', background: 'rgba(6,14,28,0.5)',
          borderBottom: '1px solid rgba(30,58,95,0.5)',
        }}>
          {[
            { id: 'text', label: '📋 Structured Text Details', icon: '📋' },
            { id: 'flow', label: '🌐 Network & Flow Diagram', icon: '🌐' },
            { id: 'json', label: '📝 Raw JSON Payload', icon: '📝' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              style={{
                padding: '9px 16px', borderRadius: '10px 10px 0 0', fontSize: 12, fontWeight: 800,
                background: activeTab === tab.id ? '#091526' : 'transparent',
                color: activeTab === tab.id ? '#38bdf8' : '#64748b',
                border: activeTab === tab.id ? '1px solid rgba(56,189,248,0.4)' : '1px solid transparent',
                borderBottom: activeTab === tab.id ? '1px solid #091526' : '1px solid transparent',
                cursor: 'pointer', transition: 'all 0.15s',
              }}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div style={{ padding: 24, overflowY: 'auto', flex: 1, display: 'grid', gap: 18 }}>
          {/* TAB 1: STRUCTURED TEXT DISPLAY ("data txt ma show karo") */}
          {activeTab === 'text' && (
            <div style={{ display: 'grid', gap: 16 }}>
              {/* Primary Key-Value Text Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: 12 }}>
                {textFields.map((field, idx) => (
                  <div key={idx} style={{
                    padding: 14, background: 'rgba(10,23,42,0.7)', borderRadius: 14,
                    border: '1px solid rgba(30,58,95,0.6)',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: '#64748b', fontSize: 11, fontWeight: 800, textTransform: 'uppercase' }}>
                      <span>{field.icon}</span> {field.label}
                    </div>
                    <div style={{ marginTop: 6, color: field.color || '#f8fafc', fontSize: 13, fontWeight: 700, wordBreak: 'break-word' }}>
                      {field.value}
                    </div>
                  </div>
                ))}
              </div>

              {/* Extracted Specific Telemetry Text Fields */}
              {additionalTextDetails.length > 0 && (
                <div style={{
                  padding: 16, background: 'rgba(8,18,34,0.8)', borderRadius: 14,
                  border: '1px solid rgba(56,189,248,0.3)',
                }}>
                  <div style={{ fontSize: 12, color: '#7dd3fc', fontWeight: 900, textTransform: 'uppercase', marginBottom: 12, letterSpacing: '0.06em' }}>
                    📑 Detailed Telemetry Text Parameters
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 12 }}>
                    {additionalTextDetails.map((item, i) => (
                      <div key={i} style={{ fontSize: 12 }}>
                        <span style={{ color: '#64748b', fontWeight: 700 }}>{item.label}: </span>
                        <span style={{ color: '#38bdf8', fontWeight: 700, fontFamily: 'monospace' }}>{item.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: NETWORK FLOW & TOPOLOGY DIAGRAM */}
          {activeTab === 'flow' && (
            <div style={{ display: 'grid', gap: 16 }}>
              <div style={{
                padding: 20, background: 'rgba(8,18,34,0.8)', borderRadius: 16,
                border: '1px solid rgba(56,189,248,0.35)', textAlign: 'center',
              }}>
                <div style={{ fontSize: 11, color: '#7dd3fc', fontWeight: 900, textTransform: 'uppercase', marginBottom: 16, letterSpacing: '0.08em' }}>
                  🌐 Endpoint Network Communication Flow
                </div>

                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 20, flexWrap: 'wrap' }}>
                  {/* Source Node */}
                  <div style={{ padding: '14px 20px', borderRadius: 14, background: 'rgba(56,189,248,0.12)', border: '1px solid rgba(56,189,248,0.4)', textAlign: 'center' }}>
                    <div style={{ fontSize: 22 }}>📱</div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>{system?.name || 'vivo'}</div>
                    <div style={{ fontSize: 11, color: '#38bdf8', fontFamily: 'monospace', marginTop: 2 }}>
                      {raw.srcip || raw.sourceIp || system?.ip || '10.126.148.170'}
                    </div>
                  </div>

                  {/* Flow Arrow */}
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                    <span style={{ fontSize: 10, color: '#34d399', fontWeight: 900, padding: '2px 8px', borderRadius: 10, background: 'rgba(52,211,153,0.15)', border: '1px solid rgba(52,211,153,0.3)' }}>
                      {raw.proto || raw.protocol || 'TCP'} · {raw.direction || 'OUTBOUND'}
                    </span>
                    <span style={{ fontSize: 24, color: '#38bdf8', margin: '4px 0' }}>➔</span>
                    <span style={{ fontSize: 10, color: '#64748b' }}>Port {raw.destport || raw.dest_port || '443'}</span>
                  </div>

                  {/* Destination Node */}
                  <div style={{ padding: '14px 20px', borderRadius: 14, background: 'rgba(248,113,113,0.12)', border: '1px solid rgba(248,113,113,0.4)', textAlign: 'center' }}>
                    <div style={{ fontSize: 22 }}>🌐</div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#f8fafc', marginTop: 4 }}>Remote Target</div>
                    <div style={{ fontSize: 11, color: '#f87171', fontFamily: 'monospace', marginTop: 2 }}>
                      {raw.destip || raw.destinationIp || '172.217.16.206'}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 3: RAW JSON PAYLOAD */}
          {activeTab === 'json' && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                <div style={{ fontSize: 11, color: '#94a3b8', fontWeight: 800, textTransform: 'uppercase' }}>
                  📝 Full Raw Agent Telemetry Object
                </div>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(JSON.stringify(raw || selectedLog, null, 2));
                    alert('Raw JSON payload copied to clipboard!');
                  }}
                  style={{
                    padding: '6px 14px', borderRadius: 8, fontSize: 11, fontWeight: 800,
                    background: 'rgba(56,189,248,0.15)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.35)',
                    cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6,
                  }}
                >
                  📋 Copy Text Payload
                </button>
              </div>
              <pre style={{
                background: '#040d1a', padding: 16, borderRadius: 14, border: '1px solid #1a3050',
                color: '#34d399', fontSize: 11, overflowX: 'auto', maxHeight: 340, fontFamily: 'monospace', margin: 0,
              }}>
                {JSON.stringify(raw || selectedLog, null, 2)}
              </pre>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   EXCLUSIVE SYSTEM 24-HOUR EDR CAPABILITY DASHBOARD MODAL
   (Created ONLY for System Monitoring — Not shared anywhere else)
   ═══════════════════════════════════════════════════════════════════ */

function SystemCapability24hDashboardModal({ capabilityId, title, system, onClose }) {
  const { user } = useAuth();
  const cap = (CAPABILITY_CONFIG || []).find(c => c.id === Number(capabilityId)) || { id: capabilityId, title, icon: '⚡' };
  const [logs, setLogs] = useState([]);
  const [capabilityStats, setCapabilityStats] = useState({
    count24h: 0,
    highCritical24h: 0,
    totalCount: 0,
    lastEventAt: null,
  });
  const [loading, setLoading] = useState(true);
  const [sevFilter, setSevFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedLog, setSelectedLog] = useState(null);
  const [isLiveSocketActive, setIsLiveSocketActive] = useState(false);

  const fetchSystemCapabilityData = useCallback(async (quiet = false) => {
    if (!system?._id) return;
    if (!quiet) setLoading(true);
    try {
      // Use the same canonical, tenant-scoped endpoint that builds the 31 cards.
      // This prevents generic system logs or another capability's alerts from
      // leaking into the selected capability view.
      const { data } = await api.get(
        `/monitoring/system/${system._id}/capability-telemetry?hours=24&limit=50`,
      );
      const selectedCapability = (data.cards || []).find(
        item => Number(item.capabilityId) === Number(capabilityId),
      );
      const specificItems = selectedCapability?.events || [];

      const seen = new Set();
      const combined = [];

      const addRecord = (item, typeStr) => {
        const idKey = item._id || `${typeStr}-${item.timestamp || item.createdAt}-${item.ruleId || item.logType}`;
        if (seen.has(idKey)) return;
        seen.add(idKey);

        const desc = item.description || item.message || item.eventName 
          || (item.registryKey ? `Registry Key: ${item.registryKey}` : item.keyPath ? `Key Path: ${item.keyPath}` : 'Endpoint Telemetry Event');

        combined.push({
          id: idKey,
          time: item.createdAt || item.timestamp || new Date(),
          ruleId: item.ruleId || item.ruleName || item.logType || item.eventCategory || `EDR-CAP-${capabilityId}`,
          severity: (item.severity || item.level || 'low').toLowerCase(),
          category: item.eventCategory || item.source || cap.kind || 'edr',
          description: desc,
          action: item.actionTaken || item.status || item.action || 'Logged',
          raw: item,
        });
      };

      specificItems.forEach(i => addRecord(i, 'specific'));

      combined.sort((a, b) => new Date(b.time) - new Date(a.time));
      setLogs(combined);
      setCapabilityStats({
        count24h: Number(selectedCapability?.count24h || 0),
        highCritical24h: Number(selectedCapability?.highCritical24h || 0),
        totalCount: Number(selectedCapability?.totalCount || 0),
        lastEventAt: selectedCapability?.lastEventAt || null,
      });
    } catch (err) {
      console.error('Failed to load capability 24h data:', err);
    } finally {
      setLoading(false);
    }
  }, [system?._id, capabilityId, cap]);

  useEffect(() => {
    fetchSystemCapabilityData();
    const timer = setInterval(() => {
      if (pageIsVisible()) fetchSystemCapabilityData(true);
    }, CAPABILITY_RECONCILE_MS);

    // Socket.io Real-Time Stream Integration
    let socket = null;
    try {
      socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
      socket.on('connect', () => {
        setIsLiveSocketActive(true);
        if (user?.companyId) socket.emit('join:company', user.companyId);
      });
      socket.on('disconnect', () => setIsLiveSocketActive(false));

      const handleLiveEvent = (data) => {
        if (!data) return;
        const targetSystemId = data.systemId?._id || data.systemId || data.system_id;
        const matchesSystem = String(targetSystemId || '') === String(system._id) ||
                              data.hostname === system.hostname ||
                              data.agentName === system.name;
        if (!matchesSystem) return;
        // Reconcile through the backend classifier instead of guessing the
        // capability client-side and accidentally mixing categories.
        fetchSystemCapabilityData(true);
      };

      socket.on('alert:new', handleLiveEvent);
      socket.on('log:new', handleLiveEvent);
      socket.on('new-alert', handleLiveEvent);
      socket.on('alert', handleLiveEvent);
      socket.on('log', handleLiveEvent);
      socket.on('telemetry', handleLiveEvent);
      socket.on('agent-event', handleLiveEvent);
    } catch (e) {
      console.warn('Socket connect notice:', e);
    }

    return () => {
      clearInterval(timer);
      if (socket) socket.disconnect();
    };
  }, [fetchSystemCapabilityData, system, user]);

  const filteredLogs = logs.filter(item => {
    if (sevFilter !== 'ALL' && item.severity !== sevFilter.toLowerCase()) return false;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const text = `${item.ruleId} ${item.description} ${item.category} ${item.action}`.toLowerCase();
      if (!text.includes(q)) return false;
    }
    return true;
  });

  const criticalCount = capabilityStats.highCritical24h;

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 99999,
      background: 'rgba(3, 8, 18, 0.88)', backdropFilter: 'blur(10px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20,
    }}>
      <div style={{
        width: '100%', maxWidth: 1100, maxHeight: '92vh',
        background: 'linear-gradient(145deg, #091526 0%, #0d1e36 100%)',
        border: '1px solid rgba(56,189,248,0.4)', borderRadius: 20,
        boxShadow: '0 24px 64px rgba(0,0,0,0.6)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden', color: '#e2e8f0',
      }}>
        {/* Header */}
        <div style={{
          padding: '20px 24px', borderBottom: '1px solid rgba(30,58,95,0.6)',
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          background: 'rgba(8,18,34,0.5)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <div style={{
              width: 46, height: 46, borderRadius: 14,
              background: 'rgba(56,189,248,0.15)', border: '1px solid rgba(56,189,248,0.4)',
              display: 'grid', placeItems: 'center', fontSize: 22, color: '#38bdf8',
            }}>
              {cap.icon || '⚡'}
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 6, fontWeight: 900, background: 'rgba(56,189,248,0.2)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.4)' }}>
                  CAPABILITY #{cap.id}
                </span>
                <h2 style={{ margin: 0, fontSize: 20, fontWeight: 800, color: '#f8fafc' }}>
                  {cap.title || title}
                </h2>
              </div>
              <div style={{ fontSize: 12, color: '#60a5fa', marginTop: 4 }}>
                Target System: <strong style={{ color: '#e2e8f0' }}>{system?.name}</strong> ({system?.hostname || system?.name}) · IP: {system?.ip || '—'}
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 10, padding: '5px 12px', borderRadius: 20, fontWeight: 800, background: 'rgba(52,211,153,0.15)', color: '#34d399', border: '1px solid rgba(52,211,153,0.4)' }}>
              🟢 24H LIVE SYSTEM TELEMETRY
            </span>
            <button
              onClick={onClose}
              style={{
                background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.15)',
                color: '#cbd5e1', borderRadius: 10, width: 34, height: 34,
                cursor: 'pointer', fontSize: 16, display: 'grid', placeItems: 'center',
              }}
            >
              ✕
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div style={{ padding: 24, overflowY: 'auto', flex: 1, display: 'grid', gap: 20 }}>
          {/* KPI Summary Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 14 }}>
            <div style={{ padding: 16, background: 'rgba(12,26,46,0.6)', border: '1px solid rgba(56,189,248,0.3)', borderRadius: 14 }}>
              <div style={{ fontSize: 10, color: '#94a3b8', fontWeight: 800, textTransform: 'uppercase' }}>24H Telemetry Events</div>
              <div style={{ fontSize: 28, fontWeight: 900, color: '#38bdf8', marginTop: 6 }}>{capabilityStats.count24h.toLocaleString()}</div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 4 }}>Last 24 hours on {system?.name}</div>
            </div>
            <div style={{ padding: 16, background: 'rgba(12,26,46,0.6)', border: '1px solid rgba(248,113,113,0.3)', borderRadius: 14 }}>
              <div style={{ fontSize: 10, color: '#94a3b8', fontWeight: 800, textTransform: 'uppercase' }}>High & Critical Threats</div>
              <div style={{ fontSize: 28, fontWeight: 900, color: criticalCount > 0 ? '#f87171' : '#34d399', marginTop: 6 }}>{criticalCount}</div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 4 }}>Requires analyst review</div>
            </div>
            <div style={{ padding: 16, background: 'rgba(12,26,46,0.6)', border: '1px solid rgba(52,211,153,0.3)', borderRadius: 14 }}>
              <div style={{ fontSize: 10, color: '#94a3b8', fontWeight: 800, textTransform: 'uppercase' }}>Agent Defense Mode</div>
              <div style={{ fontSize: 18, fontWeight: 900, color: '#34d399', marginTop: 10 }}>ACTIVE & MONITORING</div>
              <div style={{ fontSize: 10, color: '#64748b', marginTop: 4 }}>Capability #{cap.id} enforced</div>
            </div>
          </div>

          {/* Filter & Search Bar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 12 }}>
            <div style={{ display: 'flex', gap: 6 }}>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(s => (
                <button
                  key={s}
                  onClick={() => setSevFilter(s)}
                  style={{
                    padding: '6px 12px', borderRadius: 8, fontSize: 11, fontWeight: 800,
                    background: sevFilter === s ? '#38bdf8' : 'rgba(15,27,46,0.8)',
                    color: sevFilter === s ? '#091526' : '#94a3b8',
                    border: `1px solid ${sevFilter === s ? '#38bdf8' : 'rgba(30,58,95,0.6)'}`,
                    cursor: 'pointer', transition: 'all 0.15s',
                  }}
                >
                  {s}
                </button>
              ))}
            </div>

            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <input
                type="text"
                placeholder="Search 24h telemetry logs..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                style={{
                  padding: '7px 14px', borderRadius: 10, fontSize: 12,
                  background: 'rgba(8,18,34,0.8)', color: '#f8fafc',
                  border: '1px solid rgba(30,58,95,0.8)', outline: 'none', width: 240,
                }}
              />
              <button
                onClick={fetchSystemCapabilityData}
                style={{
                  padding: '7px 12px', borderRadius: 10, fontSize: 12, fontWeight: 700,
                  background: 'rgba(56,189,248,0.12)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.3)',
                  cursor: 'pointer',
                }}
              >
                🔄 Refresh
              </button>
            </div>
          </div>

          {/* Log Stream Table with Vertical Side Scrollbar */}
          <div
            className="sm-custom-scrollbar"
            style={{
              border: '1px solid rgba(30,58,95,0.6)',
              borderRadius: 14,
              maxHeight: 380,
              overflowY: 'auto',
              overflowX: 'auto',
              background: 'rgba(8,18,34,0.5)',
              boxShadow: 'inset 0 0 14px rgba(0,0,0,0.4)',
            }}
          >
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead style={{ position: 'sticky', top: 0, zIndex: 10, background: '#091629' }}>
                <tr style={{ background: '#091629', color: '#94a3b8', textAlign: 'left', borderBottom: '1px solid rgba(30,58,95,0.7)' }}>
                  <th style={{ padding: '12px 14px', background: '#091629' }}>Timestamp</th>
                  <th style={{ padding: '12px 14px', background: '#091629' }}>Severity</th>
                  <th style={{ padding: '12px 14px', background: '#091629' }}>Rule / Event ID</th>
                  <th style={{ padding: '12px 14px', background: '#091629' }}>Details / Description</th>
                  <th style={{ padding: '12px 14px', background: '#091629' }}>Action</th>
                  <th style={{ padding: '12px 14px', background: '#091629', textAlign: 'right' }}>Inspect</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: 30, color: '#60a5fa' }}>
                      Loading 24-hour telemetry for {system?.name}...
                    </td>
                  </tr>
                ) : filteredLogs.length === 0 ? (
                  <tr>
                    <td colSpan="6" style={{ textAlign: 'center', padding: 30, color: '#64748b' }}>
                      No 24-hour logs recorded for Capability #{cap.id} on {system?.name}
                    </td>
                  </tr>
                ) : (
                  filteredLogs.map(item => {
                    const sevColor = item.severity === 'critical' ? '#f87171' : item.severity === 'high' ? '#fb923c' : item.severity === 'medium' ? '#fbbf24' : '#34d399';
                    return (
                      <tr
                        key={item.id}
                        onClick={() => setSelectedLog(item)}
                        style={{
                          borderBottom: '1px solid rgba(30,58,95,0.3)',
                          cursor: 'pointer',
                          transition: 'background 0.15s',
                        }}
                        onMouseEnter={e => e.currentTarget.style.background = 'rgba(56,189,248,0.08)'}
                        onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
                      >
                        <td style={{ padding: '12px 14px', color: '#cbd5e1', whiteSpace: 'nowrap' }}>
                          {new Date(item.time).toLocaleTimeString()} <span style={{ color: '#64748b', fontSize: 10 }}>({timeAgo(item.time)})</span>
                        </td>
                        <td style={{ padding: '12px 14px' }}>
                          <span style={{ fontSize: 9, padding: '3px 8px', borderRadius: 6, fontWeight: 900, background: `${sevColor}20`, color: sevColor, border: `1px solid ${sevColor}44` }}>
                            {item.severity.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '12px 14px', color: '#38bdf8', fontWeight: 700, fontFamily: 'monospace' }}>
                          {item.ruleId}
                        </td>
                        <td style={{ padding: '12px 14px', color: '#e2e8f0', maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {item.description}
                        </td>
                        <td style={{ padding: '12px 14px', color: '#34d399', fontWeight: 600 }}>
                          {item.action}
                        </td>
                        <td style={{ padding: '12px 14px', textAlign: 'right' }}>
                          <button
                            onClick={e => {
                              e.stopPropagation();
                              setSelectedLog(item);
                            }}
                            style={{
                              padding: '5px 12px', borderRadius: 8, fontSize: 11, fontWeight: 800,
                              background: 'rgba(56,189,248,0.15)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.35)',
                              cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 4,
                            }}
                          >
                            🔍 Inspect Details
                          </button>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
          {!loading && capabilityStats.count24h > logs.length && (
            <div style={{ color: '#64748b', fontSize: 10, textAlign: 'right' }}>
              Showing latest {logs.length.toLocaleString()} of {capabilityStats.count24h.toLocaleString()} events from the last 24 hours
            </div>
          )}
        </div>
      </div>

      {/* ── DETAILED EVENT INSPECTION MODAL ── */}
      <EventInspectorModal
        selectedLog={selectedLog}
        system={system}
        cap={cap}
        onClose={() => setSelectedLog(null)}
      />
    </div>
  );
}

function SystemModuleDashboardModal({ item, system, onClose }) {
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('ALL');
  const [selected, setSelected] = useState(null);
  const sourceItems = Array.isArray(item?.items) ? item.items : [];
  const rows = sourceItems.map((row, index) => ({
    ...row,
    _rowId: row._id || `${item.title}-${index}`,
    _time: row.createdAt || row.receivedAt || row.logTime || row.timestamp,
    _message: row.description || row.message || row.ruleId || row.type || 'Telemetry event',
    _severity: String(row.severity || row.level || 'info').toLowerCase(),
  }));
  const filtered = rows.filter(row => {
    if (severity !== 'ALL' && row._severity !== severity.toLowerCase()) return false;
    if (!search) return true;
    return `${row._message} ${row.ruleId || ''} ${row.hostname || ''} ${row.agentName || ''}`
      .toLowerCase().includes(search.toLowerCase());
  });
  const count = rows.length;
  const critical = rows.filter(row => row._severity === 'critical').length;
  const high = rows.filter(row => row._severity === 'high').length;
  const recent = rows.filter(row => {
    const time = new Date(row._time || 0).getTime();
    return Number.isFinite(time) && time >= Date.now() - 24 * 60 * 60 * 1000;
  }).length;
  const hourly = Array.from({ length: 12 }, (_, index) => {
    const from = Date.now() - (index + 1) * 2 * 60 * 60 * 1000;
    const to = Date.now() - index * 2 * 60 * 60 * 1000;
    return rows.filter(row => {
      const time = new Date(row._time || 0).getTime();
      return time >= from && time < to;
    }).length;
  }).reverse();
  const maxHourly = Math.max(...hourly, 1);
  const severityColor = { critical: '#f87171', high: '#fb923c', medium: '#facc15', low: '#34d399', info: '#60a5fa' };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 1100, background: 'rgba(2,8,18,.86)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 10 }}>
      <div style={{ width: 'min(1240px, 100%)', height: 'min(900px, 100%)', background: '#071321', border: `1px solid ${item.color}55`, borderRadius: 16, display: 'flex', flexDirection: 'column', overflow: 'hidden', boxShadow: '0 24px 80px rgba(0,0,0,.55)' }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid #1e3a5f', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
          <div>
            <div style={{ color: item.color, fontSize: 10, fontWeight: 900, letterSpacing: 1.5, textTransform: 'uppercase' }}>System-level module dashboard</div>
            <h2 style={{ margin: '4px 0 0', color: '#f8fafc', fontSize: 19 }}>{item.icon} {item.title} — {system.name}</h2>
            <div style={{ color: '#64748b', fontSize: 10, marginTop: 3 }}>Last 24 hours · system-scoped telemetry · {system.hostname || system.name}</div>
          </div>
          <button type="button" onClick={onClose} aria-label="Return to system monitoring" title="Return to system monitoring" style={{ background: 'rgba(96,165,250,.12)', border: '1px solid #2563eb66', borderRadius: 8, color: '#93c5fd', padding: '8px 12px', cursor: 'pointer', fontWeight: 800 }}>← Back</button>
        </div>

        <div style={{ padding: 18, overflow: 'auto', flex: 1 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10, marginBottom: 16 }}>
            {[['TOTAL EVENTS', count, item.color], ['24H EVENTS', recent, '#38bdf8'], ['HIGH / CRITICAL', high + critical, '#fb923c'], ['LAST EVENT', rows[0]?._time ? timeAgo(rows[0]._time) : '—', '#34d399']].map(([label, value, color]) => (
              <div key={label} style={{ background: '#0b1b2e', border: `1px solid ${color}44`, borderRadius: 10, padding: '12px 14px' }}>
                <div style={{ color: '#64748b', fontSize: 9, fontWeight: 900, letterSpacing: 1 }}>{label}</div>
                <div style={{ color, fontSize: 24, fontWeight: 950, marginTop: 5 }}>{typeof value === 'number' ? value.toLocaleString() : value}</div>
              </div>
            ))}
          </div>

          <div style={{ background: '#091a2b', border: '1px solid #1e3a5f', borderRadius: 12, padding: 14, marginBottom: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', color: '#cbd5e1', fontSize: 11, fontWeight: 800, marginBottom: 12 }}><span>📈 Live 24-hour volume</span><span style={{ color: '#64748b' }}>2-hour buckets</span></div>
            <div style={{ height: 100, display: 'flex', alignItems: 'end', gap: 6 }}>
              {hourly.map((value, index) => <div key={index} title={`${value} events`} style={{ flex: 1, height: `${Math.max(5, (value / maxHourly) * 100)}%`, background: `linear-gradient(180deg, ${item.color}, ${item.color}33)`, borderRadius: '4px 4px 1px 1px' }} />)}
            </div>
          </div>

          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
            <input value={search} onChange={event => setSearch(event.target.value)} placeholder="Search system events..." style={{ flex: 1, minWidth: 220, background: '#06111f', color: '#e2e8f0', border: '1px solid #1e3a5f', borderRadius: 7, padding: '9px 11px', outline: 'none' }} />
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].map(value => <button type="button" key={value} onClick={() => setSeverity(value)} style={{ background: severity === value ? `${item.color}22` : '#091a2b', color: severity === value ? item.color : '#94a3b8', border: `1px solid ${severity === value ? item.color : '#1e3a5f'}66`, borderRadius: 7, padding: '8px 10px', fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>{value}</button>)}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: selected ? 'minmax(0, 1.3fr) minmax(280px, .7fr)' : '1fr', gap: 12 }}>
            <div style={{ border: '1px solid #1e3a5f', borderRadius: 10, overflow: 'hidden' }}>
              <div style={{ padding: '9px 12px', color: '#64748b', fontSize: 10, borderBottom: '1px solid #1e3a5f' }}>{filtered.length.toLocaleString()} matching events</div>
              <div style={{ maxHeight: 360, overflow: 'auto' }}>
                {filtered.length === 0 ? <div style={{ padding: 30, textAlign: 'center', color: '#64748b', fontSize: 12 }}>No system-level events found.</div> : filtered.slice(0, 250).map(row => <button type="button" key={row._rowId} onClick={() => setSelected(row)} style={{ display: 'block', width: '100%', textAlign: 'left', background: selected?._rowId === row._rowId ? '#102c49' : 'transparent', color: '#e2e8f0', border: 0, borderBottom: '1px solid #10243a', padding: '10px 12px', cursor: 'pointer' }}><div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}><span style={{ fontSize: 11, fontWeight: 750, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row._message}</span><span style={{ color: severityColor[row._severity] || '#94a3b8', fontSize: 9, fontWeight: 900 }}>{row._severity.toUpperCase()}</span></div><div style={{ color: '#64748b', fontSize: 9, marginTop: 4 }}>{row._time ? new Date(row._time).toLocaleString() : 'Time unavailable'} · {row.hostname || row.agentName || system.hostname || system.name}</div></button>)}
              </div>
            </div>
            {selected && <div style={{ border: '1px solid #1e3a5f', borderRadius: 10, padding: 14, background: '#06111f', overflow: 'auto' }}><div style={{ color: item.color, fontSize: 11, fontWeight: 900, marginBottom: 10 }}>EVENT DETAILS</div><div style={{ color: '#e2e8f0', fontSize: 13, lineHeight: 1.5, marginBottom: 12 }}>{selected._message}</div><pre style={{ margin: 0, color: '#7dd3fc', fontSize: 10, whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{JSON.stringify(selected, null, 2)}</pre></div>}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ═══════════════════════════════════════════════════════════════════
   SYSTEM-LEVEL MONITORING CARDS (Company Admin Dashboard Style)
   ═══════════════════════════════════════════════════════════════════ */

function SystemPortalMetricCard({ item, onClick }) {
  const values = (item.chart || [5, 12, 8, 15, 20, 14, 22]).map(v => Math.max(0, Number(v || 0)));
  const chartMax = Math.max(...values, 1);
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        minHeight: 226,
        padding: 18,
        border: `1px solid ${item.color}45`,
        borderRadius: 17,
        background: `radial-gradient(circle at 88% 2%, ${item.color}1c, transparent 40%), linear-gradient(155deg, rgba(10,25,44,.98), rgba(5,14,28,.97))`,
        boxShadow: `0 16px 36px rgba(0,0,0,.25), inset 0 1px 0 ${item.color}18`,
        color: '#e2e8f0',
        cursor: onClick ? 'pointer' : 'default',
        textAlign: 'left',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: 'inherit',
        width: '100%',
      }}
    >
      <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
        <span style={{ width: 42, height: 42, borderRadius: 13, display: 'grid', placeItems: 'center', background: `${item.color}18`, border: `1px solid ${item.color}45`, fontSize: 20 }}>{item.icon}</span>
        {onClick && <span style={{ color: item.color, fontSize: 13, fontWeight: 950 }}>VIEW ↗</span>}
      </span>
      <span style={{ display: 'block', marginTop: 14, color: '#f8fafc', fontSize: 15, fontWeight: 900 }}>{item.title}</span>
      <span style={{ display: 'block', marginTop: 8, color: item.color, fontSize: 29, fontWeight: 950, lineHeight: 1 }}>{item.value}</span>
      <span style={{ display: 'block', marginTop: 8, color: '#94a3b8', fontSize: 11, lineHeight: 1.4, minHeight: 31 }}>{item.subtitle}</span>
      <span aria-hidden="true" style={{ height: 42, display: 'flex', alignItems: 'end', gap: 5, marginTop: 14, paddingTop: 5, borderTop: '1px solid rgba(148,163,184,.12)' }}>
        {values.map((v, i) => (
          <span key={i} style={{ flex: 1, minWidth: 5, height: `${Math.max(12, Math.round((v / chartMax) * 100))}%`, borderRadius: '4px 4px 1px 1px', background: `linear-gradient(180deg, ${item.color}, ${item.color}55)`, boxShadow: `0 0 10px ${item.color}28` }} />
        ))}
      </span>
      <span style={{ display: 'block', marginTop: 7, color: '#526984', fontSize: 9, fontWeight: 800, letterSpacing: '.08em' }}>LIVE SYSTEM SNAPSHOT</span>
    </button>
  );
}

function ActiveTelemetryCard({ card, systemName, onOpen }) {
  const status = card.status || 'listening';
  const color = status === 'degraded' || status === 'dependency_required'
    ? '#f59e0b'
    : status === 'streaming' || status === 'reporting'
      ? '#34d399'
      : status === 'disabled'
        ? '#f87171'
        : status === 'unsupported'
          ? '#64748b'
          : status === 'stale'
            ? '#a78bfa'
            : '#38bdf8';
  const label = status.replaceAll('_', ' ').toUpperCase();
  const total = Number(card.count24h || 0);

  return (
    <button
      type="button"
      onClick={() => onOpen && onOpen(card)}
      style={{
        background: 'linear-gradient(135deg, rgba(12,26,46,.88) 0%, rgba(15,21,53,.66) 100%)',
        border: `1px solid ${color}44`,
        borderRadius: 16,
        padding: '20px 22px',
        minHeight: 280,
        width: '100%',
        cursor: 'pointer',
        overflow: 'hidden',
        position: 'relative',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,.05), 0 1px 3px rgba(0,0,0,.3)',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        textAlign: 'left',
        fontFamily: 'inherit',
        transition: 'all 0.2s ease',
      }}
    >
      <span style={{ position: 'absolute', top: 0, right: 0, width: 140, height: 140, background: `radial-gradient(circle, ${color}14 0%, transparent 70%)`, pointerEvents: 'none' }} />
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, position: 'relative', zIndex: 1 }}>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center', minWidth: 0 }}>
            <div style={{ width: 40, height: 40, borderRadius: 12, display: 'grid', placeItems: 'center', background: `${color}16`, border: `1px solid ${color}55`, color, fontSize: 20, fontWeight: 900 }}>
              {card.icon || '⚡'}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ color: '#60a5fa', fontSize: 12, fontWeight: 900 }}>↗</span>
            <span style={{ fontSize: 9, padding: '4px 8px', borderRadius: 7, fontWeight: 900, background: `${color}18`, color, border: `1px solid ${color}55` }}>
              {label}
            </span>
          </div>
        </div>

        <div style={{ display: 'block', marginTop: 18, color: '#7dd3fc', fontSize: 10, fontWeight: 900, letterSpacing: 1.1, position: 'relative', zIndex: 1 }}>
          LAST 24H LOG COUNT
        </div>
        <div style={{ display: 'block', marginTop: 5, color: '#e5edf7', fontSize: 32, fontWeight: 950, lineHeight: 1, position: 'relative', zIndex: 1 }}>
          {total.toLocaleString()}
        </div>
        <div style={{ display: 'block', color: '#60a5fa', fontSize: 14, fontWeight: 900, marginTop: 12, lineHeight: 1.3, position: 'relative', zIndex: 1 }}>
          {card.title || 'Android Telemetry'}
        </div>
        <div style={{ display: 'block', color: '#94a3b8', fontSize: 10, marginTop: 7, lineHeight: 1.45, position: 'relative', zIndex: 1 }}>
          {card.description || card.reason}
        </div>
      </div>

      <div style={{ position: 'relative', zIndex: 1, marginTop: 14, paddingTop: 10, borderTop: '1px solid rgba(148,163,184,.12)' }}>
        <div style={{ display: 'block', color, fontSize: 10, fontWeight: 900 }}>
          {card.lastEventAt ? `Last event ${timeAgo(card.lastEventAt)}` : (card.reason || `Listening on ${systemName || 'endpoint'}`)}
        </div>
        <div style={{ display: 'block', color: '#475569', fontSize: 9, marginTop: 3 }}>
          {Number(card.totalCount || 0).toLocaleString()} total events · Click to inspect
        </div>
      </div>
    </button>
  );
}

function SystemLevelCards({ system, onDetailModal, systemData }) {
  const navigate = useNavigate();
  const sysData = systemData;
  const [activeTelemetry, setActiveTelemetry] = useState({
    cards: [], runtime: {}, summary: {}, loading: true, generatedAt: null,
  });
  const [modal, setModal] = useState(null);
  const [selectedCapability, setSelectedCapability] = useState(null);
  const isAndroidSystem = /android/i.test(`${system?.osType || ''} ${system?.os || ''}`)
    || system?.agentType === 'phone';

  const fetchActiveTelemetry = useCallback(async () => {
    if (!system?._id) return;
    try {
      const endpoint = isAndroidSystem ? 'active-telemetry' : 'capability-telemetry';
      const { data } = await api.get(`/monitoring/system/${system._id}/${endpoint}?hours=24&limit=25`);
      const cards = isAndroidSystem
        ? (data.cards || [])
        : (data.cards || []).map(card => {
            const definition = CAPABILITY_CONFIG.find(item => item.capabilityId === Number(card.capabilityId));
            return {
              ...card,
              key: `capability-${card.capabilityId}`,
              title: definition?.title || `Capability ${card.capabilityId}`,
              icon: definition?.icon || '⚡',
              description: card.reason,
            };
          });
      setActiveTelemetry({
        cards,
        runtime: data.runtime || {},
        summary: data.summary || {},
        loading: false,
        generatedAt: data.generatedAt || new Date().toISOString(),
      });
    } catch {
      setActiveTelemetry(current => ({ ...current, loading: false }));
    }
  }, [system?._id, isAndroidSystem]);

  useEffect(() => {
    fetchActiveTelemetry();
    const interval = setInterval(() => {
      if (pageIsVisible()) fetchActiveTelemetry();
    }, CAPABILITY_RECONCILE_MS);
    return () => clearInterval(interval);
  }, [fetchActiveTelemetry]);

  useEffect(() => {
    setSelectedCapability(null);
  }, [system?._id]);

  const openModal = (title, icon, items, type) => {
    if (onDetailModal) onDetailModal({ title, icon, items, type });
    else setModal({ title, icon, items, type });
  };

  const closeCapabilityDashboard = useCallback(() => {
    // Keep the selected system view mounted underneath the capability modal.
    // Closing a card opened from System Monitoring must return to this exact
    // system, rather than navigating to the company-wide EDR page.
    setSelectedCapability(null);
  }, []);

  const fmt = val => Number(val || 0).toLocaleString();

  const activeCollectorCount = activeTelemetry.cards.length;
  const reportingCapabilityCount = Number(activeTelemetry.summary.reporting || 0);
  const systemCapabilityCards = !isAndroidSystem && activeTelemetry.cards.length === 0
    ? CAPABILITY_CONFIG.map(definition => ({
        capabilityId: definition.capabilityId,
        status: 'enabled_no_telemetry',
        count24h: 0,
        totalCount: 0,
        highCritical24h: 0,
        lastEventAt: null,
        reason: 'Waiting for endpoint telemetry',
        key: `capability-${definition.capabilityId}`,
        title: definition.title,
        icon: definition.icon || '⚡',
        description: 'System-scoped telemetry is loading',
      }))
    : activeTelemetry.cards;
  const systemEdrOverview = {
    capabilities: systemCapabilityCards.map(card => ({
      id: card.capabilityId,
      name: card.title,
      source: card.description || card.reason || 'System capability telemetry',
      live: {
        telemetryStatus: card.status,
        logs24h: Number(card.count24h || 0),
        highCritical24h: Number(card.highCritical24h || 0),
        reportingAgents: Number(card.count24h || 0) > 0 ? 1 : 0,
        lastSeenAt: card.lastEventAt || null,
        timeline24h: [],
      },
      metrics: {
        logs24h: Number(card.count24h || 0),
        highCritical24h: Number(card.highCritical24h || 0),
        reportingAgents: Number(card.count24h || 0) > 0 ? 1 : 0,
      },
    })),
    liveSummary: {
      reporting: reportingCapabilityCount,
      idle: Math.max(0, Number(activeTelemetry.summary.totalCapabilities || 31) - reportingCapabilityCount),
      total: Number(activeTelemetry.summary.totalCapabilities || 31),
    },
  };

  const portalCards = [
    {
      title: 'IPS', icon: '📡', color: '#22d3ee',
      value: fmt(sysData.ids.counts?.blocked || 0),
      subtitle: `${fmt(sysData.ids.counts?.blocked || 0)} blocked · ${fmt(sysData.ids.counts?.alerts || 0)} alert events`,
      chart: [0, 1, 0, 2, 1, 0, sysData.ids.counts?.blocked || 0],
      items: sysData.ids.items,
      type: 'alert',
      to: '/company-admin/ips',
    },
    {
      title: 'IDS', icon: '📡', color: '#38bdf8',
      value: fmt(sysData.ids.counts?.detections || sysData.ids.counts?.alerts || 0),
      subtitle: `${fmt(sysData.ids.counts?.high || 0)} high · ${fmt(sysData.ids.counts?.critical || 0)} critical detections`,
      chart: [1, 2, 1, 3, 2, 1, sysData.ids.counts?.detections || 0],
      items: sysData.ids.items,
      type: 'alert',
      to: '/company-admin/ids',
    },
    {
      title: 'Firewall Events', icon: '🧱', color: '#fb923c',
      value: fmt(sysData.firewall.counts?.blocked || 0),
      subtitle: `${fmt(sysData.firewall.counts?.blocked || 0)} blocked · ${fmt(sysData.firewall.counts?.total || 0)} total firewall logs`,
      chart: [0, 1, 0, 2, 1, 0, sysData.firewall.counts?.blocked || 0],
      items: sysData.firewall.items,
      type: 'alert',
      to: '/company-admin/firewall',
    },
    {
      title: 'Threat Intelligence Incidents', icon: '🚨', color: '#a78bfa',
      value: fmt(sysData.threats.counts?.total || sysData.threats.items.length),
      subtitle: `${fmt(sysData.threats.counts?.malicious || 0)} malicious IOC matches`,
      chart: [2, 5, 3, 8, 4, 9, sysData.threats.items.length],
      items: sysData.threats.items,
      type: 'alert',
      to: '/company-admin/threat-intelligence',
    },
    {
      title: 'Incidents', icon: '🚨', color: '#f87171',
      value: 'VIEW',
      subtitle: 'Open endpoint incident workflow',
      chart: [1, 1, 0, 1, 0, 1, 1],
      items: sysData.allAlerts.items,
      type: 'alert',
      to: '/company-admin/incidents',
    },
    {
      title: 'Digital Forensics', icon: '🔬', color: '#2dd4bf',
      value: 'VIEW',
      subtitle: 'Endpoint evidence and forensic hunts',
      chart: [1, 2, 1, 3, 2, 2, 3],
      items: [...(sysData.malware.data || []), ...(sysData.network.alerts || [])],
      type: 'alert',
      to: '/company-admin/forensics',
    },
    {
      title: 'Correlation', icon: '🔗', color: '#60a5fa',
      value: 'VIEW',
      subtitle: 'Cross-source security correlation',
      chart: [2, 3, 2, 4, 3, 4, 5],
      items: sysData.allAlerts.items,
      type: 'alert',
      to: '/company-admin/correlation',
    },
    {
      title: 'SOAR', icon: '⚡', color: '#c084fc',
      value: 'VIEW',
      subtitle: 'Response playbooks and automation',
      chart: [1, 1, 2, 1, 3, 2, 3],
      items: sysData.allAlerts.items.filter(item => item.actionTaken || item.action || item.responseAction),
      type: 'alert',
      to: '/company-admin/soar',
    },
    {
      title: 'SIEM', icon: '📊', color: '#34d399',
      value: fmt(sysData.siem.counts?.total || sysData.siem.logs.length),
      subtitle: 'System event logs and telemetry entries',
      chart: [30, 45, 40, 60, 55, 70, sysData.siem.logs.length],
      items: sysData.siem.logs,
      type: 'log',
      to: '/company-admin/siem',
    },
    {
      title: 'Alerts', icon: '🔔', color: '#fbbf24',
      value: fmt(sysData.allAlerts.items.length),
      subtitle: 'Aggregated security alerts for this system',
      chart: [10, 15, 12, 18, 22, 19, sysData.allAlerts.items.length],
      items: sysData.allAlerts.items,
      type: 'alert',
      to: '/company-admin/alerts',
    },
  ];

  const openedModal = modal;

  return (
    <div style={{ color: '#dbeafe', display: 'grid', gap: 20, marginBottom: 24 }}>
      {/* Monitoring Live Portal Section (Exact Company Admin Dashboard Portal Style) */}
      <section style={{ border: '1px solid rgba(52,211,153,.25)', borderRadius: 20, padding: 19, background: 'linear-gradient(145deg,rgba(6,15,28,.95),rgba(8,20,36,.86))', boxShadow: '0 18px 42px rgba(0,0,0,.20)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'center', marginBottom: 16 }}>
          <div>
            <div style={{ color: '#34d399', fontSize: 10, fontWeight: 950, letterSpacing: '.12em', textTransform: 'uppercase' }}>Live System Operations</div>
            <h2 style={{ color: '#f8fafc', fontSize: 20, margin: '5px 0 0' }}>System Telemetry & Controls</h2>
          </div>
          <div style={{ color: '#64748b', fontSize: 11 }}>{portalCards.length} live system modules</div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(210px, 1fr))', gap: 13 }}>
          {portalCards.map((item, i) => (
            <SystemPortalMetricCard
              key={i}
              item={item}
              onClick={() => {
                const returnTo = `${window.location.pathname}?systemId=${encodeURIComponent(system._id)}`;
                const params = new URLSearchParams({
                  systemId: String(system._id),
                  returnTo,
                });
                navigate(`${item.to}?${params.toString()}`);
              }}
            />
          ))}
        </div>
      </section>

      {/* Android shows runtime-supported collectors; desktop uses the exact EDR overview card UI with system-scoped data. */}
      {isAndroidSystem ? <section style={{
        background: 'linear-gradient(135deg, rgba(6,13,22,.95), rgba(8,20,36,.88))',
        border: '1px solid rgba(56,189,248,.25)',
        borderRadius: 20,
        padding: 22,
        boxShadow: '0 18px 42px rgba(0,0,0,.20)',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 14, marginBottom: 20 }}>
          <div>
            <div style={{ color: '#38bdf8', fontSize: 11, fontWeight: 950, letterSpacing: '.12em', textTransform: 'uppercase' }}>
              {isAndroidSystem ? 'Active Android Telemetry' : 'Enterprise EDR Architecture'}
            </div>
            <h2 style={{ color: '#f8fafc', fontSize: 22, margin: '6px 0 0' }}>
              {isAndroidSystem ? 'Runtime-supported monitoring' : '31-Point Endpoint Capability Matrix'} — {system.name}
            </h2>
          </div>
          <div style={{ color: activeTelemetry.runtime.connectionState === 'retrying' ? '#f59e0b' : '#34d399', fontSize: 12, fontWeight: 900, background: 'rgba(52,211,153,.1)', padding: '6px 14px', borderRadius: 20, border: '1px solid rgba(52,211,153,.3)' }}>
            {activeTelemetry.loading
              ? 'LOADING LIVE STATUS'
              : isAndroidSystem
                ? `${activeCollectorCount} ACTIVE · ${String(activeTelemetry.runtime.capabilityMode || 'ANDROID').replaceAll('_', ' ')}`
                : `${reportingCapabilityCount}/31 REPORTING · ${String(system.osType || system.os || 'DESKTOP').toUpperCase()}`}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 16 }}>
          {activeTelemetry.cards.map(card => (
            <ActiveTelemetryCard
              key={card.key}
              card={card}
              systemName={system.name}
              onOpen={selected => {
                if (isAndroidSystem) {
                  openModal(
                    `${selected.icon || '⚡'} ${selected.title}`,
                    selected.icon || '⚡',
                    selected.events || [],
                    'alert',
                  );
                  return;
                }
                setSelectedCapability(selected);
              }}
            />
          ))}
        </div>
        {!activeTelemetry.loading && activeTelemetry.cards.length === 0 && (
          <div style={{ color: '#94a3b8', padding: 24, textAlign: 'center' }}>
            {isAndroidSystem
              ? 'No active Android telemetry collectors were reported by this endpoint.'
              : 'No desktop capability telemetry could be loaded for this endpoint.'}
          </div>
        )}
        {!activeTelemetry.loading && (
          <div style={{ marginTop: 14, display: 'flex', gap: 16, flexWrap: 'wrap', color: '#64748b', fontSize: 10 }}>
            <span>Live refresh: Socket.IO + 60s reconciliation</span>
            {isAndroidSystem && <span>Queue: {Number(activeTelemetry.runtime.queueDepth || 0).toLocaleString()}</span>}
            {isAndroidSystem && <span>Dropped: {Number(activeTelemetry.runtime.droppedEvents || 0).toLocaleString()}</span>}
            {!isAndroidSystem && <span>{Number(activeTelemetry.summary.stale || 0)} historical-only</span>}
            {!isAndroidSystem && <span>{Number(activeTelemetry.summary.dependencyRequired || 0)} dependency required</span>}
            <span>Updated: {activeTelemetry.generatedAt ? timeAgo(activeTelemetry.generatedAt) : '—'}</span>
          </div>
        )}
      </section> : (
        <EDRCapabilitiesDashboard
          data={systemEdrOverview}
          loading={activeTelemetry.loading}
          title={`All 31 EDR Monitoring Capabilities — ${system.name}`}
          subtitle={`System-scoped telemetry · last 24 hours · ${system.hostname || system.name}`}
          onOpenCapability={selected => setSelectedCapability({
            capabilityId: selected.cardNumber || selected.id,
            title: selected.cardConfig?.title || selected.name || selected.title,
          })}
        />
      )}

      {openedModal && (
        <LogDetailModal
          title={openedModal.title}
          icon={openedModal.icon}
          items={openedModal.items}
          type={openedModal.type}
          onClose={() => setModal(null)}
        />
      )}

      {selectedCapability && !isAndroidSystem && (
        <EDRCapabilityDashboardModal
          title={`🛡️ ${selectedCapability.capabilityId}. ${selectedCapability.title}`}
          category={edrCategoryForCapability(selectedCapability.capabilityId)}
          capabilityId={selectedCapability.capabilityId}
          overviewData={systemEdrOverview}
          systemId={system._id}
          onClose={closeCapabilityDashboard}
        />
      )}

    </div>
  );
}

function SystemDashboard({ system, dept, onBack, isAdmin }) {
  const [malwareData, setMalwareData] = useState({ data: [], counts: {} });
  const [networkData, setNetworkData] = useState({ alerts: [], logs: [], counts: {} });
  const [fileData, setFileData] = useState({ logs: [], alerts: [], counts: {} });
  const [logData, setLogData] = useState({ logs: [], counts: {} });
  const [edrData, setEdrData] = useState({ alerts: [], loginActivity: [], counts: {} });
  const [usbData, setUsbData] = useState({ logs: [], counts: {} });
  const [threatData, setThreatData] = useState({ alerts: [], counts: {} });
  const [firewallData, setFirewallData] = useState({ logs: [], alerts: [], counts: {} });
  const [ipsData, setIpsData] = useState({ logs: [], alerts: [], counts: {} });
  const [loginData, setLoginData] = useState({ logins: [], counts: {} });
  const [healthData, setHealthData] = useState({});
  const [timelineData, setTimelineData] = useState({ timeline: [], total: 0 });
  const [loadingData, setLoadingData] = useState(true);
  const [isolating, setIsolating] = useState(false);
  const [detailModal, setDetailModal] = useState(null);

  const online = isSystemOnline(system);
  const osDisplay = system.os || system.osType || '—';

  const fetchAllMonitoringData = useCallback(async (showLoading = false) => {
    if (!system?._id) return;
    try {
      if (showLoading) setLoadingData(true);
      const systemId = system._id;
      const request = url => api.get(url);

      const [
        malware,
        network,
        files,
        logs,
        edr,
        usb,
        threats,
        firewall,
        ips,
        login,
        health,
        timeline,
      ] = await Promise.all([
        request(`/monitoring/system/${systemId}/malware?limit=100`).catch(() => ({ data: { data: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/network?limit=100`).catch(() => ({ data: { alerts: [], logs: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/file-activity?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/logs?limit=100`).catch(() => ({ data: { logs: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/edr?limit=100`).catch(() => ({ data: { alerts: [], loginActivity: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/usb?limit=100`).catch(() => ({ data: { logs: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/threats?limit=100`).catch(() => ({ data: { alerts: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/firewall?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/ips-ids?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/login-activity?limit=100`).catch(() => ({ data: { logins: [], counts: {} } })),
        request(`/monitoring/system/${systemId}/health`).catch(() => ({ data: {} })),
        request(`/monitoring/system/${systemId}/timeline?limit=50`).catch(() => ({ data: { timeline: [], total: 0 } })),
      ]);

      setMalwareData(malware.data);
      setNetworkData(network.data);
      setFileData(files.data);
      setLogData(logs.data);
      setEdrData(edr.data);
      setUsbData(usb.data);
      setThreatData(threats.data);
      setFirewallData(firewall.data);
      setIpsData(ips.data);
      setLoginData(login.data);
      setHealthData(health.data);
      setTimelineData(timeline.data);
    } catch (err) {
      console.error('Failed to fetch monitoring data:', err);
    } finally {
      setLoadingData(false);
    }
  }, [system?._id]);

  useEffect(() => {
    // Initial load — show spinner.
    fetchAllMonitoringData(true);

    // Socket.IO handles normal live updates; this poll reconciles missed
    // events and keeps the page current after a backend/agent reconnect.
    const interval = setInterval(() => {
      if (pageIsVisible()) fetchAllMonitoringData(false);
    }, DETAIL_RECONCILE_MS);

    return () => clearInterval(interval);
  }, [fetchAllMonitoringData]);

  // Data aggregates from API responses
  const malwareAlerts = malwareData.data || [];
  const networkAlerts = networkData.alerts || [];
  const networkLogs = networkData.logs || [];
  const fileLogs = fileData.logs || [];
  const fileAlerts = fileData.alerts || [];
  const logs = logData.logs || [];
  const edrAlerts = edrData.alerts || [];
  const loginActivity = edrData.loginActivity || [];
  const usbLogs = usbData.logs || [];
  const threatAlerts = threatData.alerts || [];
  const firewallLogs = firewallData.logs || [];
  const firewallAlerts = firewallData.alerts || [];
  const ipsLogs = ipsData.logs || [];
  const ipsAlerts = ipsData.alerts || [];
  const logins = loginData.logins || [];
  const timelineEvents = timelineData.timeline || [];
  const chartNow = Date.now();
  const chartStart = chartNow - 24 * 60 * 60 * 1000;
  const chartSeries = [
    { key: 'edr', label: 'EDR', color: '#38bdf8', rows: [...edrAlerts, ...loginActivity] },
    { key: 'ids', label: 'IDS / IPS', color: '#22d3ee', rows: [...ipsAlerts, ...ipsLogs] },
    { key: 'forensics', label: 'Forensics', color: '#a78bfa', rows: [...fileAlerts, ...fileLogs, ...malwareAlerts] },
  ].map(series => {
    const values = Array(24).fill(0);
    series.rows.forEach(row => {
      const timestamp = new Date(row?.createdAt || row?.eventTimestamp || row?.logTime || 0).getTime();
      if (!Number.isFinite(timestamp) || timestamp < chartStart || timestamp > chartNow) return;
      const bucket = Math.min(23, Math.floor((timestamp - chartStart) / (60 * 60 * 1000)));
      values[bucket] += 1;
    });
    return { ...series, values, total: values.reduce((sum, value) => sum + value, 0) };
  });
  const telemetryChartMax = Math.max(...chartSeries.flatMap(series => series.values), 1);
  const hasTelemetryChartData = chartSeries.some(series => series.total > 0);
  const chartPointString = values => values.map((value, index) => {
    const x = (index / 23) * 720;
    const y = 105 - (value / telemetryChartMax) * 90;
    return `${x},${y}`;
  }).join(' ');
  const systemLevelData = {
    edr: { counts: edrData.counts || {}, alerts: edrAlerts, loading: loadingData },
    ids: { counts: ipsData.counts || {}, items: [...ipsAlerts, ...ipsLogs], loading: loadingData },
    firewall: { counts: firewallData.counts || {}, items: [...firewallAlerts, ...firewallLogs], loading: loadingData },
    threats: { counts: threatData.counts || {}, items: threatAlerts, loading: loadingData },
    allAlerts: {
      items: [...malwareAlerts, ...networkAlerts, ...edrAlerts, ...threatAlerts, ...ipsAlerts, ...firewallAlerts],
      loading: loadingData,
    },
    siem: { counts: logData.counts || {}, logs, loading: loadingData },
    malware: { counts: malwareData.counts || {}, data: malwareAlerts, loading: loadingData },
    network: { counts: networkData.counts || {}, alerts: networkAlerts, loading: loadingData },
  };

  const handleExportCSV = () => {
    const allEvents = [
      ...malwareAlerts.map(a => [new Date(a.createdAt).toISOString(), 'malware', a.severity, a.description || a.ruleId || '', a.status]),
      ...networkAlerts.map(a => [new Date(a.createdAt).toISOString(), 'network', a.severity, a.description || a.ruleId || '', a.status]),
      ...logs.map(l => [new Date(l.createdAt).toISOString(), l.logType, l.level, l.message, '']),
      ...loginActivity.map(la => [new Date(la.createdAt).toISOString(), 'login', la.success ? 'info' : 'warning', `${la.action || 'login'} - ${la.email || 'unknown'}`, '']),
    ];
    downloadCSV(`${system.name}_logs_${new Date().toISOString().slice(0, 10)}.csv`,
      ['Timestamp', 'Category', 'Severity', 'Message', 'Status'], allEvents);
  };

  const handleExportPDF = () => {
    // Create a printable version
    try {
      const html = `
        <html><head><title>${system.name} - System Report</title>
        <style>body{font-family:Arial;padding:20px}h1{color:#1e40af}table{width:100%;border-collapse:collapse;margin:20px 0}th,td{border:1px solid #ddd;padding:8px;text-align:left;font-size:12px}th{background:#1e40af;color:white}.critical{color:red}.high{color:orange}.medium{color:#b8860b}.low{color:green}</style></head>
        <body><h1>🛡️ System Security Report — ${system.name}</h1>
        <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
        <p><strong>Hostname:</strong> ${system.hostname || system.name} | <strong>IP:</strong> ${system.ip || '—'} | <strong>OS:</strong> ${osDisplay}</p>
        <h2>Events Timeline</h2>
        <table><tr><th>Time</th><th>Category</th><th>Severity</th><th>Message</th></tr>
        ${malwareAlerts.map(a => `<tr><td>${new Date(a.createdAt).toLocaleString()}</td><td>malware</td><td class="${a.severity || ''}">${a.severity || 'info'}</td><td>${a.description || a.ruleId || ''}</td></tr>`).join('')}
        ${networkAlerts.map(a => `<tr><td>${new Date(a.createdAt).toLocaleString()}</td><td>network</td><td class="${a.severity || ''}">${a.severity || 'info'}</td><td>${a.description || a.ruleId || ''}</td></tr>`).join('')}
        ${logs.slice(0, 50).map(l => `<tr><td>${new Date(l.createdAt).toLocaleString()}</td><td>${l.logType}</td><td class="${l.level || ''}">${l.level || 'info'}</td><td>${l.message}</td></tr>`).join('')}
        </table></body></html>`;
      const w = window.open('', '_blank');
      if (w) {
        w.document.write(html);
        w.document.close();
        setTimeout(() => w.print(), 250);
      }
    } catch (err) {
      alert('Failed to export PDF: ' + err.message);
    }
  };

  const handleIsolate = async () => {
    if (!window.confirm(`Are you sure you want to isolate ${system.name}? This will disconnect the system from the network.`)) return;
    setIsolating(true);
    try {
      await api.post(`/system/${system._id}/isolate`).catch(() => { });
      alert('Isolation command sent to agent.');
    } catch (err) {
      alert('Failed to isolate: ' + (err.response?.data?.message || err.message));
    } finally {
      setIsolating(false);
    }
  };

  return (
    <div className="sm-detail" style={{ color: '#dbeafe', display: 'grid', gap: 20 }}>
      {/* ── 24H AGENT & EDR COMMAND CENTER HERO BANNER ── */}
      <div style={{
        padding: 24,
        border: '1px solid rgba(56,189,248,.35)',
        borderRadius: 22,
        background: 'radial-gradient(circle at 85% 15%, rgba(14,165,233,.12), transparent 35%), radial-gradient(circle at 15% 0%, rgba(99,102,241,.14), transparent 35%), linear-gradient(135deg,#071426,#0c1a32)',
        boxShadow: '0 22px 54px rgba(0,0,0,.35), inset 0 1px 0 rgba(255,255,255,.05)',
      }}>
        {/* Top Header Row */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16, marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 54, height: 54, borderRadius: 16,
              background: online ? 'rgba(52,211,153,0.15)' : 'rgba(248,113,113,0.15)',
              border: `1px solid ${online ? '#34d39966' : '#f8717166'}`,
              display: 'grid', placeItems: 'center', fontSize: 26,
            }}>
              🖥️
            </div>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h1 style={{ margin: 0, fontSize: 28, color: '#f8fafc', fontWeight: 900, letterSpacing: '-0.5px' }}>
                  {system.name}
                </h1>
                <span style={{
                  fontSize: 10, padding: '3px 10px', borderRadius: 20, fontWeight: 900,
                  background: online ? 'rgba(52,211,153,0.18)' : 'rgba(248,113,113,0.18)',
                  color: online ? '#34d399' : '#f87171',
                  border: `1px solid ${online ? '#34d39944' : '#f8717144'}`,
                  display: 'inline-flex', alignItems: 'center', gap: 5,
                }}>
                  <span style={{ width: 6, height: 6, borderRadius: '50%', background: online ? '#34d399' : '#f87171', boxShadow: `0 0 8px ${online ? '#34d399' : '#f87171'}` }} />
                  {online ? '24H LIVE STREAM ACTIVE' : 'AGENT OFFLINE'}
                </span>
              </div>
              <div style={{ color: '#60a5fa', fontSize: 13, marginTop: 4, fontWeight: 600 }}>
                {dept?.name || 'Security Operations'} · Endpoint ID: <code style={{ color: '#93c5fd', fontSize: 11 }}>{system._id}</code>
              </div>
            </div>
          </div>

          {/* Quick Actions Row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
            <button
              onClick={handleExportCSV}
              style={{
                padding: '9px 16px', borderRadius: 12, fontSize: 12, fontWeight: 700,
                background: 'rgba(56,189,248,0.12)', color: '#38bdf8', border: '1px solid rgba(56,189,248,0.3)',
                cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6, transition: 'all 0.2s',
              }}
            >
              📥 Export 24h CSV
            </button>

            <button
              onClick={handleExportPDF}
              style={{
                padding: '9px 16px', borderRadius: 12, fontSize: 12, fontWeight: 700,
                background: 'rgba(167,139,250,0.12)', color: '#a78bfa', border: '1px solid rgba(167,139,250,0.3)',
                cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6, transition: 'all 0.2s',
              }}
            >
              📄 Print 24h PDF
            </button>

            <button
              onClick={handleIsolate}
              disabled={isolating}
              style={{
                padding: '9px 16px', borderRadius: 12, fontSize: 12, fontWeight: 700,
                background: isolating ? 'rgba(239,68,68,0.08)' : 'rgba(239,68,68,0.18)',
                color: '#f87171', border: '1px solid rgba(239,68,68,0.4)',
                cursor: isolating ? 'not-allowed' : 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6, transition: 'all 0.2s',
              }}
            >
              🔒 {isolating ? 'Isolating...' : 'Isolate Endpoint'}
            </button>
          </div>
        </div>

        {/* Info Grid Pills */}
        <div style={{
          display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 12,
          padding: 16, background: 'rgba(8,18,34,0.6)', borderRadius: 16, border: '1px solid rgba(30,58,95,0.5)',
        }}>
          <div>
            <div style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em' }}>🖥 Hostname</div>
            <div style={{ color: '#f1f5f9', fontSize: 14, fontWeight: 700, marginTop: 3 }}>{system.hostname || system.name}</div>
          </div>
          <div>
            <div style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em' }}>🌐 IP Address</div>
            <div style={{ color: '#38bdf8', fontSize: 14, fontWeight: 700, marginTop: 3 }}>{system.ip || '—'}</div>
          </div>
          <div>
            <div style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em' }}>💻 OS / Architecture</div>
            <div style={{ color: '#f1f5f9', fontSize: 14, fontWeight: 700, marginTop: 3 }}>{osDisplay} ({system.arch || 'x64'})</div>
          </div>
          <div>
            <div style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em' }}>📦 Agent Version</div>
            <div style={{ color: '#34d399', fontSize: 14, fontWeight: 700, marginTop: 3 }}>{system.agentVersion ? `v${system.agentVersion}` : 'Not reported'}</div>
          </div>
          <div>
            <div style={{ color: '#64748b', fontSize: 10, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.06em' }}>🕐 Last Heartbeat</div>
            <div style={{ color: '#cbd5e1', fontSize: 13, fontWeight: 600, marginTop: 3 }}>{system.lastSeen ? timeAgo(system.lastSeen) : 'Never'}</div>
          </div>
        </div>

        {/* 24H Hourly Telemetry Trend SVG Chart */}
        <div style={{ marginTop: 20, paddingTop: 16, borderTop: '1px solid rgba(30,58,95,0.4)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
            <div style={{ color: '#7dd3fc', fontSize: 11, fontWeight: 900, letterSpacing: '0.08em', textTransform: 'uppercase' }}>
              📈 Live 24-Hour Telemetry Volume Curve — {system.name}
            </div>
            <div style={{ color: '#64748b', fontSize: 10 }}>Rolling 24 Hours · Hourly Granularity</div>
          </div>
          <svg viewBox="0 0 720 120" style={{ width: '100%', height: 110, overflow: 'visible' }}>
            <defs>
              <linearGradient id="system24hGlow" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.4" />
                <stop offset="100%" stopColor="#38bdf8" stopOpacity="0" />
              </linearGradient>
            </defs>
            {[20, 50, 80, 105].map(y => <line key={y} x1="0" y1={y} x2="720" y2={y} stroke="#1e3a5f" strokeWidth="1" strokeDasharray="4 4" opacity="0.5" />)}
            {hasTelemetryChartData ? (
              <>
                <text x="8" y="16" fill="#64748b" fontSize="9">{telemetryChartMax.toLocaleString()} events</text>
                {chartSeries.map(series => {
                  const points = chartPointString(series.values);
                  return (
                    <g key={series.key}>
                      <polyline
                        points={points}
                        fill="none" stroke={series.color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"
                      />
                      {series.values.map((value, index) => {
                        const x = (index / 23) * 720;
                        const y = 105 - (value / telemetryChartMax) * 90;
                        return (
                          <circle key={`${series.key}-${index}`} cx={x} cy={y} r="3" fill="#06101d" stroke={series.color} strokeWidth="2">
                            <title>{`${series.label} · Hour ${index + 1}: ${value.toLocaleString()} events`}</title>
                          </circle>
                        );
                      })}
                    </g>
                  );
                })}
              </>
            ) : (
              <text x="360" y="65" textAnchor="middle" fill="#64748b" fontSize="11">No EDR, IDS/IPS or forensic events in the last 24 hours</text>
            )}
          </svg>
          <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', marginTop: 5, color: '#94a3b8', fontSize: 10 }}>
            {chartSeries.map(series => (
              <span key={series.key} style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: series.color, boxShadow: `0 0 8px ${series.color}` }} />
                {series.label}: <strong style={{ color: series.color }}>{series.total.toLocaleString()}</strong>
              </span>
            ))}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, color: '#64748b', fontSize: 10 }}>
            <span>24h ago</span>
            <span>
              {chartSeries.reduce((sum, series) => sum + series.total, 0).toLocaleString()} total security events
            </span>
            <span>Now</span>
          </div>
        </div>
      </div>

      {/* ── 24H SYSTEM & EDR DASHBOARD CONTENT ── */}
      <SystemLevelCards system={system} onDetailModal={setDetailModal} systemData={systemLevelData} />

      {/* ── LOG DETAIL MODAL ── */}
      {detailModal && (
        <LogDetailModal
          title={detailModal.title}
          icon={detailModal.icon}
          items={detailModal.items}
          type={detailModal.type}
          onClose={() => setDetailModal(null)}
        />
      )}
    </div>
  );
}




/* ═══════════════════════════════════════════════════════════════════
   MAIN COMPONENT
   ═══════════════════════════════════════════════════════════════════ */

export default function SystemMonitoringDashboard() {
  const { user, isAdmin, isDeptAdmin, isAnalyst, selectedDeptId } = useAuth();
  const socketRef = useRef(null);
  const [socketConnected, setSocketConnected] = useState(false);

  // Navigation state
  const [view, setView] = useState('departments');
  const [selectedDept, setSelectedDept] = useState(null);
  const [selectedSystem, setSelectedSystem] = useState(null);

  // Data
  const [departments, setDepartments] = useState([]);
  const [allSystems, setAllSystems] = useState([]);
  const [deptSystems, setDeptSystems] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [lastRefresh, setLastRefresh] = useState(null);

  // Filters
  const [deptSearch, setDeptSearch] = useState('');
  const [sysSearch, setSysSearch] = useState('');
  const [osFilter, setOsFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');

  // Alerts
  const [alerts, setAlerts] = useState([]);
  const [showAlerts, setShowAlerts] = useState(true);
  const requestedSystemId = typeof window === 'undefined'
    ? ''
    : new URLSearchParams(window.location.search).get('systemId') || '';

  // ── RBAC: Determine role label ──
  const roleLabel = isAdmin ? 'Company Admin' : isDeptAdmin ? 'Department Admin' : 'Analyst';

  // ── Data fetching (role-aware) ──
  const fetchDepartments = useCallback(async () => {
    try {
      const endpoint = isAnalyst ? '/department?analyst=1' : '/department';
      const { data } = await api.get(endpoint);
      const depts = Array.isArray(data) ? data : data?.departments || [];
      setDepartments(depts);
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load departments');
    }
  }, [isAnalyst]);

  const fetchAllSystems = useCallback(async () => {
    try {
      const { data } = await api.get('/system');
      const systems = Array.isArray(data) ? data : [];
      setAllSystems(systems);
      setSelectedSystem(current => {
        if (!current?._id) return current;
        const fresh = systems.find(item => String(item._id) === String(current._id));
        return fresh ? { ...current, ...fresh } : current;
      });
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to load systems');
    }
  }, []);

  const fetchDeptSystems = useCallback(async (deptId) => {
    try {
      const { data } = await api.get(`/system?departmentId=${deptId}`);
      setDeptSystems(Array.isArray(data) ? data : []);
    } catch (err) {
      setError('Failed to load systems');
    }
  }, []);

  const refreshAll = useCallback(async () => {
    await Promise.all([fetchDepartments(), fetchAllSystems()]);
    setLastRefresh(new Date());
  }, [fetchDepartments, fetchAllSystems]);

  // ── Socket.IO real-time connection ──
  useEffect(() => {
    if (!user) return;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    socketRef.current = socket;

    socket.on('connect', () => {
      setSocketConnected(true);
      if (user.companyId) socket.emit('join:company', user.companyId);
    });
    socket.on('disconnect', () => setSocketConnected(false));

    // Buffer real-time system status changes
    const statusBuffer = createEventBuffer((events) => {
      setAllSystems(prev => {
        let updated = [...prev];
        events.forEach(payload => {
          updated = updated.map(s =>
            s._id === payload.systemId ? { ...s, status: payload.status, lastSeen: payload.lastSeen || s.lastSeen } : s
          );
        });
        return updated;
      });
      setDeptSystems(prev => {
        let updated = [...prev];
        events.forEach(payload => {
          updated = updated.map(s =>
            s._id === payload.systemId ? { ...s, status: payload.status, lastSeen: payload.lastSeen || s.lastSeen } : s
          );
        });
        return updated;
      });
      setSelectedSystem(current => {
        if (!current?._id) return current;
        const payload = [...events].reverse().find(item => String(item.systemId) === String(current._id));
        return payload ? { ...current, status: payload.status, lastSeen: payload.lastSeen || current.lastSeen } : current;
      });
    }, 1200);

    socket.on('system:status_changed', statusBuffer.add);

    // Buffer real-time alerts
    const alertBuffer = createEventBuffer((newAlerts) => {
      const formattedAlerts = newAlerts.map(alert => {
        const sysName = alert.agentName || alert.systemId?.name || 'System';
        return {
          type: alert.eventCategory?.charAt(0).toUpperCase() + alert.eventCategory?.slice(1) || 'Security',
          message: `${alert.description || alert.ruleId || 'New alert'} on ${sysName}`,
          time: new Date().toLocaleTimeString(),
        };
      });
      setAlerts(prev => [...formattedAlerts, ...prev].slice(0, 8));
    }, 1200);

    socket.on('alert:new', alertBuffer.add);

    const disconnectSocket = connectSocket(socket);
    return () => {
      socket.off('system:status_changed', statusBuffer.add);
      socket.off('alert:new', alertBuffer.add);
      statusBuffer.clear();
      alertBuffer.clear();
      disconnectSocket();
    };
  }, [user]);

  // ── Initial load with RBAC ──
  useEffect(() => {
    const init = async () => {
      setLoading(true);
      await refreshAll();
      setLoading(false);
    };
    init();
  }, [refreshAll]);

  // ── RBAC: Auto-navigate for dept admin (skip dept selection) ──
  useEffect(() => {
    if (!loading && departments.length > 0) {
      if (isDeptAdmin && user?.departmentId) {
        const userDepartmentId = typeof user.departmentId === 'object' ? user.departmentId?._id : user.departmentId;
        const myDept = departments.find(d => String(d._id) === String(userDepartmentId));
        if (myDept && view === 'departments') {
          setSelectedDept(myDept);
          setView('systems');
          fetchDeptSystems(myDept._id);
        }
      }
      if (isAnalyst && selectedDeptId) {
        const assignedDept = departments.find(d => String(d._id) === String(selectedDeptId));
        if (assignedDept && view === 'departments' && departments.length === 1) {
          setSelectedDept(assignedDept);
          setView('systems');
          fetchDeptSystems(assignedDept._id);
        }
      }
    }
  }, [loading, departments, isDeptAdmin, isAnalyst, user, selectedDeptId, view, fetchDeptSystems]);

  // Module pages return here with the selected endpoint in the query string.
  // Restore the exact system detail view instead of dropping the user at the
  // department list.
  useEffect(() => {
    if (loading || !requestedSystemId || !allSystems.length) return;
    const target = allSystems.find(item => String(item._id) === String(requestedSystemId));
    if (!target) return;
    const departmentId = typeof target.departmentId === 'object' ? target.departmentId?._id : target.departmentId;
    const department = departments.find(item => String(item._id) === String(departmentId));
    setSelectedDept(department || (typeof target.departmentId === 'object' ? target.departmentId : null));
    setDeptSystems([target]);
    setSelectedSystem(target);
    setView('detail');
  }, [loading, requestedSystemId, allSystems, departments]);

  // Inventory changes far less frequently than telemetry. Keep this lightweight,
  // pause it in background tabs, and let Socket.IO handle live endpoint status.
  useEffect(() => {
    const interval = setInterval(() => {
      if (pageIsVisible()) refreshAll();
    }, INVENTORY_REFRESH_MS);
    return () => clearInterval(interval);
  }, [refreshAll]);

  // Reuse the company-wide inventory response for the selected department instead
  // of issuing a second /system query on every background refresh.
  useEffect(() => {
    if (!selectedDept?._id) return;
    setDeptSystems(allSystems.filter(item => {
      const departmentId = typeof item.departmentId === 'object' ? item.departmentId?._id : item.departmentId;
      return String(departmentId || '') === String(selectedDept._id);
    }));
  }, [allSystems, selectedDept?._id]);

  // ── Navigation handlers ──
  const handleSelectDept = (dept) => {
    setSelectedDept(dept);
    setView('systems');
    setSysSearch(''); setOsFilter(''); setStatusFilter(''); setRiskFilter('');
    fetchDeptSystems(dept._id);
  };

  const handleSelectSystem = (system) => {
    setSelectedSystem(system);
    setView('detail');
  };

  const navigateTo = (target) => {
    if (target === 'departments') {
      // Dept admin cannot go back to departments view
      if (isDeptAdmin) return;
      setView('departments');
      setSelectedDept(null);
      setSelectedSystem(null);
    } else if (target === 'systems') {
      setView('systems');
      setSelectedSystem(null);
    }
  };

  // ── Breadcrumb ──
  const renderBreadcrumb = () => {
    const crumbs = [];
    if (!isDeptAdmin) {
      crumbs.push({ label: '📊 Monitoring', target: 'departments' });
    }
    if (view === 'systems' || view === 'detail') {
      crumbs.push({ label: selectedDept?.name || 'Department', target: 'systems' });
    }
    if (view === 'detail') {
      crumbs.push({ label: selectedSystem?.name || 'System', target: null });
    }

    return (
      <nav className="sm-breadcrumb" aria-label="Breadcrumb">
        {crumbs.map((c, i) => (
          <span key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {i > 0 && <span className="sm-breadcrumb__separator">▸</span>}
            <span
              className={`sm-breadcrumb__item ${i === crumbs.length - 1 ? 'sm-breadcrumb__item--active' : ''}`}
              onClick={() => c.target && navigateTo(c.target)}
            >
              {c.label}
            </span>
          </span>
        ))}
      </nav>
    );
  };

  // ── Loading ──
  if (loading) {
    return (
      <div className="sm-dashboard">
        <div className="sm-loading">
          <div className="sm-loading__spinner" />
          Loading monitoring data…
        </div>
      </div>
    );
  }

  // ── Page header with role badge ──
  const headerConfig = {
    departments: { icon: '📊', title: 'System Level Monitoring', subtitle: `${departments.length} departments · ${allSystems.length} systems` },
    systems: { icon: '🖥', title: `Systems — ${selectedDept?.name || ''}`, subtitle: `${deptSystems.length} system(s) in this department` },
    detail: { icon: '🔍', title: selectedSystem?.name || 'System', subtitle: `Detailed monitoring dashboard` },
  };
  const hdr = headerConfig[view] || headerConfig.departments;

  return (
    <div className="sm-dashboard">
      {/* Header */}
      <div className="sm-header">
        <div className="sm-header__icon">{hdr.icon}</div>
        <div className="sm-header__content">
          <h1 className="sm-header__title">{hdr.title}</h1>
          <p className="sm-header__subtitle">{hdr.subtitle}</p>
        </div>
        <div className="sm-header__line" />
        <div className="sm-header__actions" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{
            fontSize: 10, padding: '3px 10px', borderRadius: 20, fontWeight: 600,
            background: isAdmin ? 'rgba(139,92,246,.15)' : isDeptAdmin ? 'rgba(59,130,246,.15)' : 'rgba(16,185,129,.15)',
            color: isAdmin ? '#a78bfa' : isDeptAdmin ? '#60a5fa' : '#34d399',
            border: `1px solid ${isAdmin ? '#a78bfa33' : isDeptAdmin ? '#60a5fa33' : '#34d39933'}`,
          }}>
            {roleLabel}
          </span>
          <span style={{
            fontSize: 10, padding: '3px 8px', borderRadius: 20,
            background: socketConnected ? 'rgba(16,185,129,.12)' : 'rgba(239,68,68,.12)',
            color: socketConnected ? '#34d399' : '#f87171',
          }}>
            {socketConnected ? '● Live' : '○ Connecting…'}
          </span>
          <RefreshBadge onClick={refreshAll} lastRefresh={lastRefresh} />
        </div>
      </div>

      {/* Analyst assignment notice */}
      {isAnalyst && (
        <div style={{
          background: 'rgba(16,185,129,.08)', border: '1px solid rgba(16,185,129,.2)',
          borderRadius: 8, padding: '10px 16px', marginBottom: 16, display: 'flex',
          alignItems: 'center', gap: 10,
        }}>
          <span style={{ fontSize: 16 }}>🧑‍💻</span>
          <div>
            <div style={{ fontSize: 12, color: '#34d399', fontWeight: 600 }}>
              Analyst View — You are assigned to monitor: {departments.map(d => d.name).join(', ') || 'No departments assigned'}
            </div>
            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
              Only your assigned departments and systems are visible
            </div>
          </div>
        </div>
      )}

      {/* Dept Admin notice */}
      {isDeptAdmin && (
        <div style={{
          background: 'rgba(59,130,246,.08)', border: '1px solid rgba(59,130,246,.2)',
          borderRadius: 8, padding: '10px 16px', marginBottom: 16, display: 'flex',
          alignItems: 'center', gap: 10,
        }}>
          <span style={{ fontSize: 16 }}>🏬</span>
          <div>
            <div style={{ fontSize: 12, color: '#60a5fa', fontWeight: 600 }}>
              Department Admin — {selectedDept?.name || 'Your Department'}
            </div>
            <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
              Monitoring all systems in your department
            </div>
          </div>
        </div>
      )}

      {/* Breadcrumb */}
      {(view !== 'departments' || isDeptAdmin) && renderBreadcrumb()}

      {/* Views */}
      {view === 'departments' && !isDeptAdmin && (
        <DepartmentOverview
          departments={departments}
          systems={allSystems}
          onSelectDept={handleSelectDept}
          deptSearch={deptSearch}
          setDeptSearch={setDeptSearch}
          error={error}
          loading={loading}
        />
      )}

      {view === 'systems' && selectedDept && (
        <SystemsList
          systems={deptSystems}
          dept={selectedDept}
          onSelectSystem={handleSelectSystem}
          searchTerm={sysSearch}
          setSearchTerm={setSysSearch}
          osFilter={osFilter}
          setOsFilter={setOsFilter}
          statusFilter={statusFilter}
          setStatusFilter={setStatusFilter}
          riskFilter={riskFilter}
          setRiskFilter={setRiskFilter}
        />
      )}

      {view === 'detail' && selectedSystem && (
        <SystemDashboard
          system={selectedSystem}
          dept={typeof selectedSystem.departmentId === 'object' ? selectedSystem.departmentId : selectedDept || { name: 'Unknown' }}
          onBack={() => navigateTo('systems')}
          isAdmin={isAdmin}
        />
      )}

      {/* Alert Notification Panel */}
      {showAlerts && <AlertNotificationPanel alerts={alerts} onClose={() => setShowAlerts(false)} />}
    </div>
  );
}
