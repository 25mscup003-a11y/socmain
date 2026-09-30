import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../../../api/axios';
import { SOCKET_URL, connectSocket, io } from '../../../api/config';
import { useAuth } from '../../../context/AuthContext';
import { ROLE_LABELS, ROLE_MENUS } from '../../../config/menuConfig';

const tone = { critical: '#fb7185', high: '#fb923c', medium: '#facc15', low: '#38bdf8' };

export default function RoleDashboardPage() {
  const { user } = useAuth();
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [dateRange, setDateRange] = useState('today');
  const [liveConnected, setLiveConnected] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const activeRequest = useRef(null);

  const roleKey = user?.role || 'l1_analyst';

  const load = useCallback(async () => {
    activeRequest.current?.abort();
    const controller = new AbortController();
    activeRequest.current = controller;
    setError('');
    setLoading(true);
    const endpoint =
      roleKey === 'soc_manager' ? '/soc-manager/dashboard' :
      roleKey === 'l1_analyst' ? '/l1/dashboard' :
      roleKey === 'l2_analyst' ? '/l2/dashboard' :
      roleKey === 'l3_analyst' ? '/l3/dashboard' : '/soc-dashboard/summary';

    try {
      const response = await api.get(endpoint, {
        params: { range: dateRange, live: 1 },
        signal: controller.signal,
        skipCache: true,
      });
      if (activeRequest.current !== controller) return;
      setData(response.data);
      setLastUpdated(new Date(response.data?.refreshedAt || Date.now()));
    } catch (e) {
      if (e.code === 'ERR_CANCELED' || activeRequest.current !== controller) return;
      setError(e.response?.data?.message || 'Dashboard service unavailable');
    } finally {
      if (activeRequest.current === controller) {
        activeRequest.current = null;
        setLoading(false);
      }
    }
  }, [dateRange, roleKey]);

  useEffect(() => {
    load();
    const socket = io(SOCKET_URL);
    let refreshTimer;
    const scheduleRefresh = () => {
      window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(load, 750);
    };
    const handleConnect = () => {
      setLiveConnected(true);
      if (user?.companyId) socket.emit('join:company', user.companyId);
      scheduleRefresh();
    };
    const handleDisconnect = () => setLiveConnected(false);
    const refreshVisibleDashboard = () => {
      if (document.visibilityState === 'visible') scheduleRefresh();
    };
    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('soc:dashboard:update', scheduleRefresh);
    socket.on('alert:new', scheduleRefresh);
    socket.on('alert:updated', scheduleRefresh);
    socket.on('alert:deleted', scheduleRefresh);
    socket.on('correlation:new', scheduleRefresh);
    socket.on('correlation:updated', scheduleRefresh);
    socket.on('edr:incident:new', scheduleRefresh);
    socket.on('edr:incident:updated', scheduleRefresh);
    socket.on('edr:incident:ai-updated', scheduleRefresh);
    window.addEventListener('focus', scheduleRefresh);
    document.addEventListener('visibilitychange', refreshVisibleDashboard);
    const disconnect = connectSocket(socket);
    if (socket.connected) handleConnect();
    const timer = setInterval(load, roleKey === 'l4_analyst' ? 10000 : 30000);
    return () => {
      clearInterval(timer);
      activeRequest.current?.abort();
      window.clearTimeout(refreshTimer);
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('soc:dashboard:update', scheduleRefresh);
      socket.off('alert:new', scheduleRefresh);
      socket.off('alert:updated', scheduleRefresh);
      socket.off('alert:deleted', scheduleRefresh);
      socket.off('correlation:new', scheduleRefresh);
      socket.off('correlation:updated', scheduleRefresh);
      socket.off('edr:incident:new', scheduleRefresh);
      socket.off('edr:incident:updated', scheduleRefresh);
      socket.off('edr:incident:ai-updated', scheduleRefresh);
      window.removeEventListener('focus', scheduleRefresh);
      document.removeEventListener('visibilitychange', refreshVisibleDashboard);
      disconnect();
    };
  }, [user?.companyId, load]);

  const cards = useMemo(() => {
    const m = data?.metrics || data || {};

    if (roleKey === 'soc_manager') {
      const summary = data?.sidebarSummary || {};
      const colors = ['#67e8f9', '#22d3ee', '#fb7185', '#f97316', '#c084fc', '#818cf8', '#34d399', '#a78bfa', '#f43f5e', '#facc15', '#38bdf8'];
      const rangeLabel = dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 days' : 'Last 30 days';
      const rangeScopedPaths = new Set([
        '/soc-manager/ids', '/soc-manager/ips', '/soc-manager/correlation', '/soc-manager/queue',
        '/soc-manager/escalations', '/soc-manager/alerts', '/soc-manager/tickets', '/soc-manager/incidents',
        '/soc-manager/threat-intelligence', '/soc-manager/contact-support', '/soc-manager/reports',
        '/soc-manager/audit', '/soc-manager/threat-audit',
      ]);
      return (ROLE_MENUS.soc_manager || [])
        .filter(item => !['/soc-manager/dashboard', '/soc-manager/settings'].includes(item.to))
        .map((item, index) => [
          `${item.icon} ${item.label}`,
          summary[item.to] ?? 0,
          colors[index % colors.length],
          item.to,
          rangeScopedPaths.has(item.to) ? rangeLabel : 'Current count',
        ]);
    }

    if (['l1_analyst', 'l2_analyst', 'l3_analyst'].includes(roleKey)) {
      const rangeLabel = dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 Days' : 'Last 30 Days';
      const ROLE_PREFIX = { soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4' };
      const prefix = ROLE_PREFIX[roleKey] || '/l1';
      const baseCards = [
        [`Incidents Received ${rangeLabel}`, m.newIncidentsInRange ?? 0, '#818cf8', `${prefix}/incidents`],
        [`Incidents Closed ${rangeLabel}`, m.closedIncidentsInRange ?? 0, '#22c55e', `${prefix}/incidents?status=resolved`],
        ['Incidents Pending', m.pendingIncidents ?? 0, '#c084fc', `${prefix}/incidents`],
        [`My Tickets Received ${rangeLabel}`, m.newTicketsInRange ?? 0, '#38bdf8', `${prefix}/tickets`],
        [`My Tickets Closed ${rangeLabel}`, m.closedTicketsInRange ?? 0, '#34d399', `${prefix}/tickets?status=resolved`],
        ['My Tickets Pending', m.pendingTickets ?? 0, '#facc15', `${prefix}/tickets`],
        [`Logs Received ${rangeLabel}`, m.logsInRange ?? 0, '#94a3b8', `${prefix}/alerts`],
        ['Completion Rate', `${m.completionRate ?? 0}%`, '#22d3ee', `${prefix}/audit`],
        ['On Shift Now', m.onShiftNow ?? 0, '#2dd4bf', `${prefix}/shifts`]
      ];
      if (['l2_analyst', 'l3_analyst'].includes(roleKey)) {
        const escalationTo = roleKey === 'l2_analyst' ? `${prefix}/escalations?direction=incoming` : `${prefix}/escalate`;
        baseCards.push(
          ['Escalated Assigned to me', m.myAssignedEscalationsIncoming ?? 0, '#38bdf8', escalationTo],
          ['Escalated Pending', m.pendingEscalationsIncoming ?? 0, '#facc15', escalationTo],
          ['Escalated Closed', m.closedEscalationsIncoming ?? 0, '#34d399', escalationTo]
        );
      }
      return baseCards;
    }

    if (roleKey === 'l4_analyst') {
      const rangeLabel = dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 Days' : 'Last 30 Days';
      return [
        [`Assigned Work ${rangeLabel}`, m.assignedWorkInRange ?? 0, '#a78bfa', '/l4/incidents'],
        [`Pending Work ${rangeLabel}`, m.pendingWorkInRange ?? 0, '#facc15', '/l4/incidents'],
        [`Completed Work ${rangeLabel}`, m.completedWorkInRange ?? 0, '#34d399', '/l4/audit'],
        [`Completion Rate ${rangeLabel}`, `${m.completionRateInRange ?? 0}%`, '#22d3ee', '/l4/audit'],
        [
          `TI Incidents ${rangeLabel}`,
          m.newIncidentsInRange ?? 0,
          '#c084fc',
          '/l4/incidents',
          `Active total: ${m.assignedIncidents ?? 0}`,
        ],
        [
          `Assigned Tickets ${rangeLabel}`,
          m.newTicketsInRange ?? 0,
          '#60a5fa',
          '/l4/tickets',
          `Active total: ${m.assignedTickets ?? 0}`,
        ],
        [`Closed Tickets ${rangeLabel}`, m.closedTicketsInRange ?? 0, '#34d399', '/l4/tickets?status=resolved'],
        ['IDS Rules', m.idsRuleCount ?? 0, '#22d3ee', '/l4/ids'],
        ['IDS Policies', m.idsPolicyCount ?? 0, '#38bdf8', '/l4/ids'],
        ['IPS Rules', m.ipsRuleCount ?? 0, '#fb7185', '/l4/ips'],
        ['IPS Policies', m.ipsPolicyCount ?? 0, '#f43f5e', '/l4/ips'],
        ['Firewall Rules', m.firewallRuleCount ?? 0, '#f97316', '/l4/firewall'],
        ['Firewall Active Policies', m.firewallPolicyCount ?? 0, '#facc15', '/l4/firewall'],
        [`Open Work ${rangeLabel}`, m.openWorkInRange ?? 0, '#fb923c', '/l4/incidents?status=open'],
        [`Investigating ${rangeLabel}`, m.investigatingWorkInRange ?? 0, '#38bdf8', '/l4/incidents?status=investigating'],
        [`Critical Pending ${rangeLabel}`, m.criticalPendingInRange ?? 0, '#fb7185', '/l4/incidents?severity=critical'],
        ['On Shift Now', m.onShiftNow ?? 0, '#2dd4bf', '/l4/shifts']
      ];
    }

    // Default company/dept/partner/superadmin fallback
    return [
      ['Open Alerts', m.openAlerts || 0, '#38bdf8', '/alerts?status=open'],
      ['Critical Alerts', m.criticalAlerts || 0, '#fb7185', '/alerts?severity=critical'],
      ['High Severity', m.highAlerts || 0, '#fb923c', '/alerts?severity=high'],
      ['Investigating', m.investigating || 0, '#a78bfa', '/alerts?status=investigating'],
      ['Pending Escalations', m.pendingEscalations || 0, '#facc15', '/soc-workspace/escalations'],
      ['Resolved Today', m.resolvedToday || 0, '#34d399', '/alerts?status=resolved']
    ];
  }, [data, roleKey, dateRange]);

  const recentList = data?.recentAlerts || data?.recentEscalations || data?.criticalQueue || [];
  const ROLE_PREFIX = { soc_manager: '/soc-manager', l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4' };
  const wsBase = ROLE_PREFIX[roleKey] || '/soc-workspace';

  return (
    <div>
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 20 }}>
        <div>
          <h1 style={{ margin: 0, fontSize: 24, color: '#f8fafc' }}>
            {ROLE_LABELS[roleKey] || 'SOC Operations'} Dashboard
          </h1>
          <p style={{ margin: '4px 0 0', color: '#94a3b8', fontSize: 13 }}>
            Backend-verified role scope · Real-time SOC metrics & incident queue
            <span style={{ marginLeft: 10, color: liveConnected ? '#34d399' : '#facc15', fontWeight: 700 }}>
              {liveConnected ? '● Live' : '● Reconnecting'}
            </span>
            {lastUpdated && <span style={{ marginLeft: 8 }}>· Synced {lastUpdated.toLocaleTimeString()}</span>}
          </p>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select
            value={dateRange}
            onChange={(e) => setDateRange(e.target.value)}
            style={{ padding: '8px 12px', background: '#07111f', border: '1px solid #294765', borderRadius: 7, color: '#e2e8f0', fontSize: 12 }}
          >
            <option value="today">Today</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>

          <button onClick={load} style={btn}>↻ Refresh</button>
        </div>
      </div>

      {(loading || error) && (
        <div style={{
          ...card,
          padding: '10px 14px',
          marginBottom: 14,
          color: error ? '#fca5a5' : '#94a3b8',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 12,
        }}>
          <span>{error || 'Refreshing live KPI values…'}</span>
          {error && <button onClick={load} style={btn}>Retry</button>}
        </div>
      )}

      {/* Metrics Cards Grid */}
      <div data-testid="dashboard-kpi-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 12 }}>
        {cards.map(([label, value, color, to, detail]) => (
          <Link key={label} to={to} style={{ ...card, textDecoration: 'none', transition: 'transform 0.15s, border-color 0.15s' }}>
            <small style={{ color: '#94a3b8', fontSize: 12, fontWeight: 600 }}>{label}</small>
            <div style={{ fontSize: 28, fontWeight: 900, color, marginTop: 8 }}>{value ?? 0}</div>
            {detail && <div style={{ color: '#a5b4fc', fontSize: 11, fontWeight: 700, marginTop: 6 }}>{detail}</div>}
          </Link>
        ))}
      </div>

      {['l1_analyst', 'l2_analyst', 'l3_analyst'].includes(roleKey) && (
        <L1WorkSummary
          metrics={data?.metrics || {}}
          shifts={data?.assignedShifts || []}
          dateRange={dateRange}
          basePath={ROLE_PREFIX[roleKey] || '/l1'}
        />
      )}

      {roleKey === 'l4_analyst' && (
        <L4WorkSummary
          metrics={data?.metrics || {}}
          status={data?.status || {}}
          categories={data?.categories || {}}
          networkSecurity={data?.networkSecurity || {}}
          securityConfiguration={data?.securityConfiguration || {}}
          shifts={data?.assignedShifts || []}
          dateRange={dateRange}
        />
      )}

      {roleKey === 'soc_manager' && (
        <section style={{ ...card, marginTop: 16, overflowX: 'auto' }}>
          <Header title="Assigned Company IDS/IPS & Firewall" to="/soc-manager/companies" />
          <table style={{ width: '100%', minWidth: 720, borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ borderBottom: '1px solid #294765', color: '#94a3b8', textAlign: 'left' }}>
                <th style={th}>Company</th><th style={th}>Status</th><th style={th}>IDS/IPS {dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 Days' : 'Last 30 Days'}</th>
                <th style={th}>Active IPS Blocks</th><th style={th}>Firewall {dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 Days' : 'Last 30 Days'}</th><th style={th}>Critical {dateRange === 'today' ? 'Today' : dateRange === '7d' ? 'Last 7 Days' : 'Last 30 Days'}</th>
              </tr>
            </thead>
            <tbody>
              {(data?.companySecurity || []).map(item => (
                <tr key={item.companyId} style={{ borderBottom: '1px solid #15283d' }}>
                  <td style={td}><b style={{ color: '#e2e8f0' }}>{item.companyName}</b></td>
                  <td style={td}><span style={{ color: item.companyStatus === 'active' ? '#34d399' : '#facc15' }}>{item.companyStatus || 'unknown'}</span></td>
                  <td style={{ ...td, color: '#22d3ee', fontWeight: 800 }}>{item.idsIpsEventsToday || 0}</td>
                  <td style={{ ...td, color: '#fb7185', fontWeight: 800 }}>{item.ipsActiveBlocks || 0}</td>
                  <td style={{ ...td, color: '#fb923c', fontWeight: 800 }}>{item.firewallEventsToday || 0}</td>
                  <td style={{ ...td, color: '#f43f5e', fontWeight: 800 }}>{item.criticalAlertsToday || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!data?.companySecurity?.length && <Empty />}
        </section>
      )}

      {/* Charts & Queue Section */}
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,2fr) minmax(280px,1fr)', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header
            title={['l1_analyst', 'l2_analyst', 'l3_analyst'].includes(roleKey) ? 'My Pending Tickets & Incidents' : roleKey === 'l4_analyst' ? 'My Pending Work Queue' : 'Priority Alert Queue'}
            to={['l1_analyst', 'l2_analyst', 'l3_analyst'].includes(roleKey) ? undefined : roleKey === 'l4_analyst' ? '/l4/incidents' : `${wsBase}/alerts`}
          />
          <AlertRows items={recentList} base={wsBase} />
        </section>

        <section style={card}>
          <Header title={['l1_analyst', 'l2_analyst', 'l3_analyst'].includes(roleKey) ? 'Ticket & Incident Severity' : 'Alerts by Severity'} />
          <SeverityBars values={data?.severity || data?.charts?.alertsBySeverity || {}} />
        </section>
      </div>

      {/* Audit activity remains available to roles that do not have the L1/L4 work summaries. */}
      {!['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'].includes(roleKey) && (
        <section style={{ ...card, marginTop: 16 }}>
          <Header title="Recent Audit Activity" to={`${wsBase}/audit`} />
          {data?.recentAudit?.length ? (
            data.recentAudit.map(x => (
              <div key={x._id} style={row}>
                <b style={{ color: '#7dd3fc' }}>{x.action}</b>
                <span style={{ color: '#94a3b8', fontSize: 11 }}>{x.targetType}</span>
                <span style={{ color: '#64748b', marginLeft: 'auto', fontSize: 11 }}>{new Date(x.createdAt).toLocaleString()}</span>
              </div>
            ))
          ) : (
            <Empty />
          )}
        </section>
      )}

      <style>{`
        @media(max-width:850px){.soc-dashboard-grid{grid-template-columns:1fr!important}}
      `}</style>
    </div>
  );
}

function L1WorkSummary({ metrics = {}, shifts = [], dateRange = 'today', basePath = '/l1' }) {
  const completionRate = Math.max(0, Math.min(100, Number(metrics.completionRate || 0)));
  const rangeLabel = dateRange === 'today' ? 'today' : dateRange === '7d' ? 'in the last 7 days' : 'in the last 30 days';
  const nextLevelName = basePath === '/l2' ? 'L3' : basePath === '/l3' ? 'Manager' : 'L2';

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header title="Work Completion" />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 18 }}>
            <strong style={{ color: '#22d3ee', fontSize: 34 }}>{completionRate}%</strong>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>{metrics.completedWork || 0} of {metrics.totalAssignedWork || 0} completed</span>
          </div>
          <div style={{ height: 10, borderRadius: 999, background: '#17243a', overflow: 'hidden', margin: '12px 0 18px' }}>
            <div style={{ width: `${completionRate}%`, height: '100%', borderRadius: 999, background: 'linear-gradient(90deg,#0ea5e9,#22c55e)', transition: 'width .25s ease' }} />
          </div>
          <SummaryPair label="Pending workload" value={metrics.pendingWork || 0} color="#facc15" />
          <SummaryPair label={`New ${rangeLabel}`} value={metrics.newInRange || 0} color="#818cf8" />
          <SummaryPair label={`Completed ${rangeLabel}`} value={metrics.completedInRange || 0} color="#34d399" />
        </section>

        <section style={card}>
          <Header title="Workload by Type" />
          <WorkTypeRow
            label="My Tickets"
            total={metrics.totalTickets || 0}
            pending={metrics.pendingTickets || 0}
            completed={metrics.completedTickets || 0}
            color="#60a5fa"
          />
          <WorkTypeRow
            label="Incidents"
            total={metrics.totalAssignedIncidents || 0}
            pending={metrics.pendingIncidents || 0}
            completed={metrics.completedIncidents || 0}
            color="#c084fc"
          />
          {['/l2', '/l3'].includes(basePath) && (
            <WorkTypeRow
              label="Escalated Alerts"
              total={metrics.totalEscalationsIncoming || 0}
              pending={metrics.pendingEscalationsIncoming || 0}
              completed={metrics.closedEscalationsIncoming || 0}
              color="#fb923c"
            />
          )}
          <SummaryPair label="High-priority pending" value={metrics.highPriorityOpen || 0} color="#fb7185" />
        </section>

        <section style={card}>
          <Header title="Shift Coverage" to={`${basePath}/shifts`} />
          <div style={{ display: 'flex', gap: 10, margin: '14px 0' }}>
            <MiniMetric label="Assigned" value={metrics.activeShifts || 0} color="#60a5fa" />
            <MiniMetric label="Active now" value={metrics.onShiftNow || 0} color="#2dd4bf" />
          </div>
          {shifts.length ? shifts.slice(0, 3).map(shift => (
            <div key={shift._id} style={{ ...row, padding: '9px 2px' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: shift.isCurrent ? '#34d399' : '#475569', flexShrink: 0 }} />
              <span style={{ minWidth: 0, flex: 1 }}>
                <b style={{ color: '#e2e8f0', display: 'block' }}>{shift.name}</b>
                <small style={{ color: '#64748b' }}>{shift.companyId?.name || 'Assigned Company'} · {shift.timezone}</small>
              </span>
              <b style={{ color: shift.isCurrent ? '#34d399' : '#94a3b8', fontSize: 11, whiteSpace: 'nowrap' }}>{shift.startTime}–{shift.endTime}</b>
            </div>
          )) : <Empty />}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header title="Incident Lifecycle" to={`${basePath}/incidents`} />
          <SummaryPair label={`Received ${rangeLabel}`} value={metrics.newIncidentsInRange || 0} color="#818cf8" />
          <SummaryPair label={`Closed ${rangeLabel}`} value={metrics.closedIncidentsInRange || 0} color="#22c55e" />
          <SummaryPair label="Pending now" value={metrics.pendingIncidents || 0} color="#facc15" />
          <SummaryPair label="Total assigned" value={metrics.totalAssignedIncidents || 0} color="#c084fc" />
        </section>

        <section style={card}>
          <Header title="My Ticket Lifecycle" to={`${basePath}/tickets`} />
          <SummaryPair label={`Received ${rangeLabel}`} value={metrics.newTicketsInRange || 0} color="#38bdf8" />
          <SummaryPair label={`Closed ${rangeLabel}`} value={metrics.closedTicketsInRange || 0} color="#22c55e" />
          <SummaryPair label="Pending now" value={metrics.pendingTickets || 0} color="#facc15" />
          <SummaryPair label="Total assigned" value={metrics.totalTickets || 0} color="#60a5fa" />
        </section>

        {['/l2', '/l3'].includes(basePath) ? (
          <section style={card}>
            <Header title="Escalated Alerts" to={basePath === '/l2' ? '/l2/escalations?direction=incoming' : '/l3/escalate'} />
            <SummaryPair label="Assigned to me" value={metrics.myAssignedEscalationsIncoming || 0} color="#38bdf8" />
            <SummaryPair label="Total assigned" value={metrics.assignedEscalationsIncoming || 0} color="#60a5fa" />
            <SummaryPair label="Pending now" value={metrics.pendingEscalationsIncoming || 0} color="#facc15" />
            <SummaryPair label="Closed / Resolved" value={metrics.closedEscalationsIncoming || 0} color="#34d399" />
          </section>
        ) : (
          <section style={card}>
            <Header title="Escalation & Priority" to={`${basePath}/escalations`} />
            <SummaryPair label={`Escalated to ${nextLevelName} ${rangeLabel}`} value={metrics.escalatedToL2 || 0} color="#fb923c" />
            <SummaryPair label={`Pending ${nextLevelName} escalations`} value={metrics.pendingEscalations || 0} color="#facc15" />
            <SummaryPair label="High-priority pending" value={metrics.highPriorityOpen || 0} color="#fb7185" />
            <SummaryPair label="Completed today" value={metrics.resolvedToday || 0} color="#34d399" />
            <SummaryPair label="False positives" value={metrics.falsePositives || 0} color="#94a3b8" />
          </section>
        )}
      </div>
    </>
  );
}

function L4WorkSummary({ metrics = {}, status = {}, categories = {}, networkSecurity = {}, securityConfiguration = {}, shifts = [], dateRange = 'today' }) {
  const completionRate = Math.max(0, Math.min(100, Number(metrics.completionRate || 0)));
  const rangeLabel = dateRange === 'today' ? 'today' : dateRange === '7d' ? 'in the last 7 days' : 'in the last 30 days';
  const statusItems = [
    ['Open', status.open || 0, '#fb923c'],
    ['Investigating', status.investigating || 0, '#38bdf8'],
    ['Contained', status.contained || 0, '#a78bfa'],
    ['Under Observation', status.under_observation || 0, '#facc15'],
    ['Resolved', status.resolved || 0, '#34d399'],
    ['False Positive', status.false_positive || 0, '#94a3b8'],
  ];
  const categoryItems = Object.entries(categories)
    .sort((a, b) => Number(b[1]) - Number(a[1]))
    .slice(0, 6);

  return (
    <>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header title="Work Completion" />
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginTop: 18 }}>
            <strong style={{ color: '#22d3ee', fontSize: 34 }}>{completionRate}%</strong>
            <span style={{ color: '#94a3b8', fontSize: 12 }}>{metrics.completedWork || 0} of {metrics.totalAssignedWork || 0} completed</span>
          </div>
          <div style={{ height: 10, borderRadius: 999, background: '#17243a', overflow: 'hidden', margin: '12px 0 18px' }}>
            <div style={{ width: `${completionRate}%`, height: '100%', borderRadius: 999, background: 'linear-gradient(90deg,#0ea5e9,#22c55e)', transition: 'width .25s ease' }} />
          </div>
          <SummaryPair label="Pending workload" value={metrics.pendingWork || 0} color="#facc15" />
          <SummaryPair label={`New ${rangeLabel}`} value={metrics.newInRange || 0} color="#818cf8" />
          <SummaryPair label={`Completed ${rangeLabel}`} value={metrics.completedInRange || 0} color="#34d399" />
        </section>

        <section style={card}>
          <Header title="Workload by Type" />
          <WorkTypeRow
            label="Threat Intelligence Incidents"
            total={metrics.assignedIncidents || 0}
            pending={metrics.pendingIncidents || 0}
            completed={metrics.completedIncidents || 0}
            color="#c084fc"
          />
          <WorkTypeRow
            label="Tickets"
            total={metrics.assignedTickets || 0}
            pending={metrics.pendingTickets || 0}
            completed={metrics.completedTickets || 0}
            color="#60a5fa"
          />
          <SummaryPair label="Critical pending" value={metrics.criticalPending || 0} color="#fb7185" />
          <SummaryPair label="Completed today" value={metrics.completedToday || 0} color="#22c55e" />
          <SummaryPair label="False positives" value={metrics.falsePositives || 0} color="#94a3b8" />
        </section>

        <section style={card}>
          <Header title="Shift Coverage" to="/l4/shifts" />
          <div style={{ display: 'flex', gap: 10, margin: '14px 0' }}>
            <MiniMetric label="Assigned" value={metrics.activeShifts || 0} color="#60a5fa" />
            <MiniMetric label="Active now" value={metrics.onShiftNow || 0} color="#2dd4bf" />
          </div>
          {shifts.length ? shifts.slice(0, 3).map(shift => (
            <div key={shift._id} style={{ ...row, padding: '9px 2px' }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: shift.isCurrent ? '#34d399' : '#475569', flexShrink: 0 }} />
              <span style={{ minWidth: 0, flex: 1 }}>
                <b style={{ color: '#e2e8f0', display: 'block' }}>{shift.name}</b>
                <small style={{ color: '#64748b' }}>{shift.companyId?.name || 'Assigned Company'} · {shift.timezone}</small>
              </span>
              <b style={{ color: shift.isCurrent ? '#34d399' : '#94a3b8', fontSize: 11, whiteSpace: 'nowrap' }}>{shift.startTime}–{shift.endTime}</b>
            </div>
          )) : <Empty />}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,2fr) minmax(280px,1fr)', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header title="Complete Status Summary" />
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(130px,1fr))', gap: 10 }}>
            {statusItems.map(([label, value, color]) => (
              <div key={label} style={{ border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 12 }}>
                <small style={{ color: '#94a3b8' }}>{label}</small>
                <div style={{ color, fontWeight: 900, fontSize: 22, marginTop: 5 }}>{value}</div>
              </div>
            ))}
          </div>
        </section>

        <section style={card}>
          <Header title="Pending TI Categories" />
          {categoryItems.length ? categoryItems.map(([name, value]) => (
            <SummaryPair key={name} label={humanize(name)} value={value} color="#c084fc" />
          )) : <Empty />}
        </section>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2,minmax(0,1fr))', gap: 14, marginTop: 16 }} className="soc-dashboard-grid">
        <section style={card}>
          <Header title="Live IDS / IPS / Firewall Ticket Summary" to="/l4/tickets" />
          <SummaryPair label="IDS active / received" value={`${networkSecurity.ids?.active || 0} / ${networkSecurity.ids?.newInRange || 0}`} color="#22d3ee" />
          <SummaryPair label="IPS active / received" value={`${networkSecurity.ips?.active || 0} / ${networkSecurity.ips?.newInRange || 0}`} color="#fb7185" />
          <SummaryPair label="Firewall active / received" value={`${networkSecurity.firewall?.active || 0} / ${networkSecurity.firewall?.newInRange || 0}`} color="#fb923c" />
          <SummaryPair label="Closed Tickets" value={metrics.closedTicketsInRange || 0} color="#34d399" />
        </section>

        <section style={card}>
          <Header title="Live IDS / IPS / Firewall Rules & Policies" />
          <SummaryPair label="IDS rules / active policies" value={`${securityConfiguration.ids?.observedRules || 0} / ${securityConfiguration.ids?.activePolicies || 0}`} color="#22d3ee" />
          <SummaryPair label="IPS rules / active policies" value={`${securityConfiguration.ips?.observedRules || 0} / ${securityConfiguration.ips?.activePolicies || 0}`} color="#fb7185" />
          <SummaryPair label="Firewall rules / active policies" value={`${securityConfiguration.firewall?.rules || 0} / ${securityConfiguration.firewall?.activePolicies || 0}`} color="#fb923c" />
        </section>
      </div>
    </>
  );
}

function WorkTypeRow({ label, total, pending, completed, color }) {
  return (
    <div style={{ border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 12, marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
        <b style={{ color: '#e2e8f0', fontSize: 12 }}>{label}</b>
        <b style={{ color, fontSize: 16 }}>{total}</b>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 8, color: '#94a3b8', fontSize: 11 }}>
        <span>Pending <b style={{ color: '#facc15' }}>{pending}</b></span>
        <span>Completed <b style={{ color: '#34d399' }}>{completed}</b></span>
      </div>
    </div>
  );
}

function SummaryPair({ label, value, color }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, padding: '8px 0', borderBottom: '1px solid #17243a', fontSize: 12 }}>
      <span style={{ color: '#94a3b8' }}>{label}</span>
      <b style={{ color }}>{value}</b>
    </div>
  );
}

function MiniMetric({ label, value, color }) {
  return (
    <div style={{ flex: 1, border: '1px solid #1e3a5f', background: '#081426', borderRadius: 9, padding: 10, textAlign: 'center' }}>
      <b style={{ display: 'block', color, fontSize: 22 }}>{value}</b>
      <small style={{ color: '#94a3b8' }}>{label}</small>
    </div>
  );
}

function humanize(value) {
  return String(value || 'Other').replace(/_/g, ' ').replace(/\b\w/g, letter => letter.toUpperCase());
}

function AlertRows({ items = [], base = '/soc-workspace' }) {
  if (!items.length) return <Empty />;
  return items.map(a => {
    const id = a.resourceId || a._id;
    const destination = a.resourceType === 'incident'
      ? `${base}/incidents/${id}`
      : a.resourceType === 'ticket' ? `${base}/tickets/${id}` : `${base}/alerts/${id}`;
    return (
      <Link
        to={destination}
        key={`${a.resourceType || 'alert'}:${id}`}
        style={{ ...row, textDecoration: 'none', color: '#e2e8f0' }}
      >
        <span style={{ width: 10, height: 10, borderRadius: '50%', background: tone[a.severity] || '#38bdf8' }} />
        <span style={{ minWidth: 0, flex: 1 }}>
          <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {a.title || a.signatureName || a.description || a.ruleId || 'Security alert'}
          </b>
          <small style={{ color: '#64748b' }}>
            {a.companyId?.name || 'Assigned Company'} · {a.resourceType === 'incident' ? 'TI Incident' : a.resourceType === 'ticket' ? 'Ticket' : 'Alert'} · {new Date(a.ticketOpenedAt || a.createdAt).toLocaleString()}
          </small>
        </span>
        <span style={{ marginLeft: 'auto', color: tone[a.severity] || '#38bdf8', textTransform: 'uppercase', fontSize: 11, fontWeight: 700 }}>
          {a.severity || 'low'}
        </span>
      </Link>
    );
  });
}

function SeverityBars({ values }) {
  const total = Math.max(1, Object.values(values).reduce((a, b) => a + Number(b || 0), 0));
  return ['critical', 'high', 'medium', 'low'].map(k => (
    <div key={k} style={{ margin: '14px 0' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12, textTransform: 'capitalize', color: '#cbd5e1' }}>
        <span>{k}</span>
        <b>{values[k] || 0}</b>
      </div>
      <div style={{ height: 7, background: '#17243a', borderRadius: 6, marginTop: 6 }}>
        <div style={{ height: '100%', width: `${((values[k] || 0) / total) * 100}%`, background: tone[k], borderRadius: 6 }} />
      </div>
    </div>
  ));
}

function Header({ title, to }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #1e3a5f', paddingBottom: 11, marginBottom: 8 }}>
      <b style={{ color: '#f8fafc', fontSize: 14 }}>{title}</b>
      {to && <Link to={to} style={{ color: '#38bdf8', fontSize: 12, textDecoration: 'none' }}>View all →</Link>}
    </div>
  );
}

function State({ text, error, retry }) {
  return (
    <div style={{ ...card, textAlign: 'center', color: error ? '#fca5a5' : '#94a3b8', padding: 40 }}>
      {text}
      {retry && (
        <div>
          <button onClick={retry} style={{ ...btn, marginTop: 12 }}>Retry</button>
        </div>
      )}
    </div>
  );
}

function Empty() {
  return <div style={{ padding: 24, textAlign: 'center', color: '#64748b', fontSize: 13 }}>No items in your authorized scope.</div>;
}

const card = { background: '#0c192c', border: '1px solid #1e3a5f', borderRadius: 12, padding: 16, boxShadow: '0 12px 30px rgba(0,0,0,.18)' };
const th = { padding: '10px 8px', fontWeight: 700, whiteSpace: 'nowrap' };
const td = { padding: '11px 8px', color: '#94a3b8', whiteSpace: 'nowrap' };
const row = { display: 'flex', alignItems: 'center', gap: 10, padding: '11px 4px', borderBottom: '1px solid #17243a', fontSize: 12 };
const btn = { border: '1px solid #2563eb', background: '#1d4ed8', color: '#fff', borderRadius: 7, padding: '8px 14px', fontWeight: 700, cursor: 'pointer', fontSize: 12 };
