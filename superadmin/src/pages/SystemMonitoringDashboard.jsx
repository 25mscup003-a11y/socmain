import { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io, createEventBuffer } from '../api/config';
import { useAuth } from '../context/AuthContext';
import './SystemMonitoringDashboard.css';

/* ═══════════════════════════════════════════════════════════════════
   HELPER FUNCTIONS
   ═══════════════════════════════════════════════════════════════════ */

const ONLINE_THRESHOLD = 10 * 60 * 1000; // 10 minutes — matches backend heartbeat window

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
      return deptId === dept._id;
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

function SystemCard({ system, onSelect }) {
  const online = isSystemOnline(system);
  const riskLevel = calculateRiskLevel(system);
  const osDisplay = system.os || system.osType || '—';

  return (
    <div className="sm-sys-card" onClick={() => onSelect(system)} id={`sys-card-${system._id}`}>
      <div className="sm-sys-card__header">
        <h4 className="sm-sys-card__name">{system.name}</h4>
        <div className="sm-sys-card__badges">
          <StatusBadge online={online} />
          <RiskBadge level={riskLevel} />
        </div>
      </div>
      <div className="sm-sys-card__info">
        <div className="sm-sys-card__info-row">
          <span className="sm-sys-card__info-icon">🌐</span>
          <span className="sm-sys-card__info-label">IP</span>
          <span className="sm-sys-card__info-value">{system.ip || '—'}</span>
        </div>
        <div className="sm-sys-card__info-row">
          <span className="sm-sys-card__info-icon">💻</span>
          <span className="sm-sys-card__info-label">OS</span>
          <span className="sm-sys-card__info-value">{osDisplay}</span>
        </div>
        <div className="sm-sys-card__info-row">
          <span className="sm-sys-card__info-icon">🕐</span>
          <span className="sm-sys-card__info-label">Last Seen</span>
          <span className="sm-sys-card__info-value" style={{ color: online ? '#34d399' : '#94a3b8' }}>
            {timeAgo(system.lastSeen)}
          </span>
        </div>
        {system.hostname && (
          <div className="sm-sys-card__info-row">
            <span className="sm-sys-card__info-icon">🖥</span>
            <span className="sm-sys-card__info-label">Host</span>
            <span className="sm-sys-card__info-value">{system.hostname}</span>
          </div>
        )}
      </div>
      <button className="sm-sys-card__btn">
        View Dashboard <span>→</span>
      </button>
    </div>
  );
}

function SystemsList({ systems, dept, onSelectSystem, searchTerm, setSearchTerm, osFilter, setOsFilter, statusFilter, setStatusFilter, riskFilter, setRiskFilter }) {
  const osTypes = [...new Set(systems.map(s => s.osType || s.os).filter(Boolean))];

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
            <SystemCard key={system._id} system={system} onSelect={onSelectSystem} />
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
  const [networkActivityData, setNetworkActivityData] = useState({ hourly: [], stats: {} });
  const [loadingData, setLoadingData] = useState(true);
  const [isolating, setIsolating] = useState(false);
  const [detailModal, setDetailModal] = useState(null);

  const online = isSystemOnline(system);
  const osDisplay = system.os || system.osType || '—';

  useEffect(() => {
    const fetchAllMonitoringData = async () => {
      try {
        setLoadingData(true);
        const systemId = system._id;

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
          networkActivity,
        ] = await Promise.all([
          api.get(`/monitoring/system/${systemId}/malware?limit=100`).catch(() => ({ data: { data: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/network?limit=100`).catch(() => ({ data: { alerts: [], logs: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/file-activity?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/logs?limit=100`).catch(() => ({ data: { logs: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/edr?limit=100`).catch(() => ({ data: { alerts: [], loginActivity: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/usb?limit=100`).catch(() => ({ data: { logs: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/threats?limit=100`).catch(() => ({ data: { alerts: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/firewall?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/ips-ids?limit=100`).catch(() => ({ data: { logs: [], alerts: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/login-activity?limit=100`).catch(() => ({ data: { logins: [], counts: {} } })),
          api.get(`/monitoring/system/${systemId}/health`).catch(() => ({ data: {} })),
          api.get(`/monitoring/system/${systemId}/timeline?limit=50`).catch(() => ({ data: { timeline: [], total: 0 } })),
          api.get(`/monitoring/system/${systemId}/network-activity`).catch(() => ({ data: { hourly: [], stats: {} } })),
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
        setNetworkActivityData(networkActivity.data);
      } catch (err) {
        console.error('Failed to fetch monitoring data:', err);
      } finally {
        setLoadingData(false);
      }
    };

    if (system?._id) fetchAllMonitoringData();

    // Auto-refresh every 30s
    const interval = setInterval(() => {
      if (system?._id) fetchAllMonitoringData();
    }, 30000);

    return () => clearInterval(interval);
  }, [system?._id]);

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
  const networkActivityChart = networkActivityData.hourly || [];

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
    <div className="sm-detail">
      {/* Hero system info */}
      <div className="sm-detail__hero">
        <div className="sm-detail__hero-header">
          <div>
            <h2 className="sm-detail__hero-title">{system.name}</h2>
            <div className="sm-detail__hero-dept">{dept?.name || 'Unknown Department'}</div>
          </div>
          <div className="sm-detail__hero-badges">
            <StatusBadge online={online} />
            <RiskBadge level={calculateRiskLevel(system)} />
          </div>
        </div>
        <div className="sm-detail__info-grid">
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">🖥 Hostname</div>
            <div className="sm-detail__info-value">{system.hostname || system.name}</div>
          </div>
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">🌐 IP Address</div>
            <div className="sm-detail__info-value">{system.ip || '—'}</div>
          </div>
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">💻 Operating System</div>
            <div className="sm-detail__info-value">{osDisplay}</div>
          </div>
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">🏗️ Architecture</div>
            <div className="sm-detail__info-value">{system.arch || '—'}</div>
          </div>
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">📦 Agent Version</div>
            <div className="sm-detail__info-value" style={{ color: '#34d399' }}>{system.agentVersion ? `v${system.agentVersion}` : '—'}</div>
          </div>
          <div className="sm-detail__info-item">
            <div className="sm-detail__info-label">🕐 Last Seen</div>
            <div className="sm-detail__info-value">{system.lastSeen ? new Date(system.lastSeen).toLocaleString() : 'Never'}</div>
          </div>
        </div>
      </div>

      {/* ── DASHBOARD CARDS (BigCard style — real data) ── */}
      {loadingData ? (
        <div style={{ textAlign: 'center', padding: 40, color: '#64748b' }}>Loading monitoring data…</div>
      ) : (
        <>
          {/* Row 1 — Core events */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
            <BigCard icon="🦠" title="Malware" risk={malwareData.counts.critical > 0 ? 'high' : malwareData.counts.high > 0 ? 'medium' : 'low'}
              main={malwareData.counts.total || 0}
              spark={malwareAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🦠 Malware Events', icon: '🦠', items: malwareAlerts, type: 'alert' })}
              sub={[
                malwareData.counts.vtAvgRatio ? `VT: ${malwareData.counts.vtAvgRatio}` : (malwareData.counts.vtAvgScore !== null ? `VT: ${malwareData.counts.vtAvgScore}` : 'VT: No Data'),
                `Quarantined: ${malwareData.counts.quarantined ?? 'No Data'}`,
                `Contained: ${(malwareData.counts.containmentStatus?.quarantined || 0) + (malwareData.counts.containmentStatus?.blocked || 0)}`,
              ].join('  ·  ')}>
              Trojan: {malwareData.counts.byType?.trojan || 0} · Ransomware: {malwareData.counts.byType?.ransomware || 0} · Worm: {malwareData.counts.byType?.worm || 0}
            </BigCard>

            <BigCard icon="🌐" title="Network Activity" risk={networkData.counts.suspicious > 0 ? 'high' : networkData.counts.alerts > 0 ? 'medium' : 'low'}
              main={networkData.counts.total || 0}
              spark={networkAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🌐 Network Events', icon: '🌐', items: [...networkAlerts, ...networkLogs], type: 'alert' })}
              sub={`Blocked: ${networkData.counts.blocked || 0} · Suspicious: ${networkData.counts.suspicious || 0}`}>
              In: {networkData.counts.inbound || 0} · Out: {networkData.counts.outbound || 0}
            </BigCard>

            <BigCard icon="📁" title="File Activity" risk={fileData.counts.suspicious > 0 ? 'high' : fileData.counts.total > 50 ? 'medium' : 'low'}
              main={fileData.counts.total ?? 'No Data'}
              spark={fileLogs.slice(0, 12).map((l, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '📁 File Events', icon: '📁', items: [...fileLogs, ...fileAlerts], type: 'log' })}
              sub={[
                `✨ Created: ${fileData.counts.created ?? 'No Data'}`,
                `✏️ Modified: ${fileData.counts.modified ?? 'No Data'}`,
                `🗑️ Deleted: ${fileData.counts.deleted ?? 'No Data'}`,
                fileData.counts.renamed ? `Renamed: ${fileData.counts.renamed}` : null,
              ].filter(Boolean).join('  ·  ')} />

            <BigCard icon="🖥" title="System Logs" risk={logData.counts.errors > 5 ? 'high' : logData.counts.warnings > 0 ? 'medium' : 'low'}
              main={logData.counts.total || 0}
              spark={logs.slice(0, 12).map((l, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🖥 System Logs', icon: '📋', items: logs, type: 'log' })}
              sub={`Errors (1h): ${logData.counts.last1h?.errors || 0} · Warnings (1h): ${logData.counts.last1h?.warnings || 0}`} />
          </div>

          {/* Row 2 — Security status */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
            <BigCard icon="🚫" title="Isolation Status" risk={system.isIsolated ? 'high' : system.status === 'disconnected' ? 'medium' : 'none'}
              main={system.isIsolated ? '⚠ ISOLATED' : 'Not Isolated'}
              sub={[
                `Agent Status: ${online ? '🟢 Online' : '🔴 Offline'}`,
                system.isIsolated && system.isolatedAt ? `Isolated: ${timeAgo(system.isolatedAt)}` : null,
                `Last Seen: ${timeAgo(system.lastSeen)}`,
              ].filter(Boolean).join('  ·  ')} />

            <BigCard icon="👤" title="EDR Security" risk={edrData.counts.edrAlerts > 10 ? 'high' : edrData.counts.edrAlerts > 0 ? 'medium' : 'low'}
              main={edrData.counts.edrAlerts || 0}
              spark={edrAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '👤 EDR Activity', icon: '👤', items: edrAlerts, type: 'alert' })}
              badge={system.edrEnabled ? 'Enabled' : 'Disabled'}
              sub={`Failed Logins (24h): ${edrData.counts.failedLogins || 0} · Priv Esc: ${edrData.counts.privilegeEscalation || 0}`}>
              Suspicious Commands: {edrData.counts.suspiciousCommands || 0}
            </BigCard>

            <BigCard icon="🔌" title="USB Devices" risk={usbData.counts.total > 5 ? 'high' : usbData.counts.total > 0 ? 'medium' : 'low'}
              main={usbData.counts.total || 0}
              spark={usbLogs.slice(0, 12).map((l, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🔌 USB Events', icon: '💾', items: usbLogs, type: 'log' })}
              sub={`Connected: ${usbData.counts.connected || 0} · Disconnected: ${usbData.counts.disconnected || 0} · Blocked: ${usbData.counts.blocked || 0}`} />

            <BigCard icon="🔥" title="Threat Intelligence" risk={threatData.counts.malicious > 0 ? 'high' : threatData.counts.suspicious > 0 ? 'medium' : 'low'}
              main={threatData.counts.total || 0}
              spark={threatAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🔥 Threat Intelligence', icon: '🔥', items: threatAlerts, type: 'alert' })}
              sub={`Malicious: ${threatData.counts.malicious || 0} · Avg Score: ${threatData.counts.avgScore || 0}`}>
              {threatData.counts.highScore || 0} high-risk items detected
            </BigCard>
          </div>

          {/* Row 3 — Network security (Firewall, IPS/IDS, Login) */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 10, flexWrap: 'wrap' }}>
            <BigCard icon="🧱" title="Firewall" risk={firewallData.counts.critical > 0 ? 'high' : firewallData.counts.blocked > 0 ? 'medium' : 'low'}
              main={firewallData.counts.blocked || 0}
              spark={firewallAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🧱 Firewall Events', icon: '🧱', items: [...firewallLogs, ...firewallAlerts], type: 'log' })}
              sub={`Total: ${firewallData.counts.total || 0} · Critical: ${firewallData.counts.critical || 0}`}>
              Inbound: {firewallData.counts.inbound || 0} · Outbound: {firewallData.counts.outbound || 0}
            </BigCard>

            <BigCard icon="🔍" title="IPS/IDS (NSM)" risk={ipsData.counts.critical > 0 ? 'high' : ipsData.counts.high > 0 ? 'medium' : 'low'}
              main={ipsData.counts.detections || 0}
              spark={ipsAlerts.slice(0, 12).map((a, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '🔍 NSM Events (Suricata/Zeek)', icon: '🔍', items: [...ipsLogs, ...ipsAlerts], type: 'log' })}
              sub={`Critical: ${ipsData.counts.critical || 0} · High: ${ipsData.counts.high || 0} · Blocked: ${ipsData.counts.blocked || 0}`}>
              Total Events: {ipsData.counts.total || 0}
            </BigCard>

            <BigCard icon="👤" title="Login Activity" risk={loginData.counts.suspiciousIPCount > 0 || loginData.counts.failed > 10 ? 'high' : loginData.counts.failed > 0 ? 'medium' : 'low'}
              main={loginData.counts.total == null ? 'No Data' : loginData.counts.totalAttempts ?? loginData.counts.total}
              spark={logins.slice(0, 12).map((l, i) => ({ count: i }))}
              onClick={() => setDetailModal({ title: '👤 Login Activity', icon: '👤', items: logins, type: 'login' })}
              sub={[
                `✅ Success: ${loginData.counts.successful ?? 'No Data'}`,
                `❌ Failed: ${loginData.counts.failed ?? 'No Data'}`,
                `🚪 Logouts: ${loginData.counts.logouts ?? 'No Data'}`,
              ].join('  ·  ')}>
              Suspicious IPs: {loginData.counts.suspiciousIPCount ?? 'No Data'} · Off-Hours: {loginData.counts.offHoursCount ?? 'No Data'}
            </BigCard>
          </div>

          {/* Service Status Row */}
          <div style={{ display: 'flex', gap: 10, marginBottom: 22, flexWrap: 'wrap' }}>
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', flex: 1, minWidth: 190 }}>
              <div style={{ fontSize: 11, color: '#1e40af', marginBottom: 8 }}>🛡️ Security Services</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
                {[
                  { label: 'EDR', enabled: system.edrEnabled },
                  { label: 'IPS', enabled: system.ipsEnabled },
                  { label: 'Firewall', enabled: system.firewallEnabled },
                  { label: 'IDS', enabled: system.idsEnabled },
                  { label: 'USB Mon', enabled: system.usbMonitorEnabled },
                  { label: 'Net Mon', enabled: system.networkMonitorEnabled },
                ].map(s => (
                  <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11 }}>
                    <span style={{ width: 8, height: 8, borderRadius: '50%', background: s.enabled ? '#10b981' : '#ef4444', display: 'inline-block', boxShadow: s.enabled ? '0 0 6px #10b981' : 'none' }} />
                    <span style={{ color: s.enabled ? '#34d399' : '#94a3b8' }}>{s.label}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', flex: 1, minWidth: 190 }}>
              <div style={{ fontSize: 11, color: '#1e40af', marginBottom: 8 }}>📊 System Health</div>
              <SystemHealthBar label="CPU Usage" value={32} max={100} color="#3b82f6" />
              <SystemHealthBar label="RAM Usage" value={58} max={100} color="#8b5cf6" />
              <SystemHealthBar label="Disk Usage" value={45} max={100} color="#06b6d4" />
            </div>
          </div>
        </>
      )}

      {/* ── TIMELINE ── */}
      <div className="sm-section">
        <EventTimeline alerts={malwareAlerts.concat(networkAlerts).concat(edrAlerts).concat(fileAlerts)} logs={logs} loginActivity={loginActivity} loadingData={loadingData} />
      </div>

      {/* ── ACTION BUTTONS ── */}
      <div className="sm-actions">
        <button className="sm-btn sm-btn--danger" onClick={handleIsolate} disabled={isolating}>
          🔒 {isolating ? 'Isolating...' : 'Isolate System'}
        </button>
        <button className="sm-btn sm-btn--primary" onClick={handleExportCSV}>📥 Export Logs (CSV)</button>
        <button className="sm-btn sm-btn--primary" onClick={handleExportPDF}>📊 Export Report (PDF)</button>
        <button className="sm-btn sm-btn--primary" onClick={() => setDetailModal({ title: 'All Alerts', icon: '🚨', items: malwareAlerts.concat(networkAlerts).concat(edrAlerts).concat(fileAlerts), type: 'alert' })}>🚨 View All Alerts ({(malwareAlerts.length + networkAlerts.length + edrAlerts.length + fileAlerts.length)})</button>
        <button className="sm-btn sm-btn--primary" onClick={() => setDetailModal({ title: 'All Logs', icon: '📋', items: logs, type: 'log' })}>📋 View All Logs ({logs.length})</button>
      </div>

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
      setAllSystems(Array.isArray(data) ? data : []);
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

    // Real-time logs
    socket.on('log:new', () => {
      // Trigger a lightweight refresh of timeline data (debounced by 30s auto-refresh)
    });

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
        const myDept = departments.find(d => d._id === user.departmentId);
        if (myDept && view === 'departments') {
          setSelectedDept(myDept);
          setView('systems');
          fetchDeptSystems(myDept._id);
        }
      }
      if (isAnalyst && selectedDeptId) {
        const assignedDept = departments.find(d => d._id === selectedDeptId);
        if (assignedDept && view === 'departments' && departments.length === 1) {
          setSelectedDept(assignedDept);
          setView('systems');
          fetchDeptSystems(assignedDept._id);
        }
      }
    }
  }, [loading, departments, isDeptAdmin, isAnalyst, user, selectedDeptId, view, fetchDeptSystems]);

  // Auto-refresh every 30 seconds
  useEffect(() => {
    const interval = setInterval(() => {
      refreshAll();
      if (view === 'systems' && selectedDept) fetchDeptSystems(selectedDept._id);
    }, 30000);
    return () => clearInterval(interval);
  }, [view, selectedDept, refreshAll, fetchDeptSystems]);

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
