/**
 * DashboardPanels.jsx
 *
 * Shared panel components used by the 35 EDR capability card pages.
 *  - CapabilityVisualDashboardPanel  (generic — used by ~30 cards)
 *  - NetworkActivityDashboardPanel   (Network Activity Monitoring)
 *  - AuthenticationMonitoringDashboardPanel (User & Auth Monitoring)
 */
import React from 'react';

// ── Palette ───────────────────────────────────────────────────────────────────
const C = {
  bg: '#03101d',
  panel: 'linear-gradient(135deg,#071827 0%,#06111f 100%)',
  border: '1px solid #14243a',
  text: '#e5edf7',
  muted: '#8ea0b8',
  sub: '#64748b',
  blue: '#3b82f6',
  cyan: '#22d3ee',
  green: '#22c55e',
  yellow: '#eab308',
  orange: '#f97316',
  red: '#ef4444',
  purple: '#a855f7',
};

const SEV_COLOR = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399', info: '#22d3ee' };
const SEV_BG    = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b', info: '#0c2a3a' };

function sevColor(s = '') { return SEV_COLOR[(s || '').toLowerCase()] || '#64748b'; }
function sevBg(s = '')    { return SEV_BG[(s || '').toLowerCase()]    || '#1e293b'; }

// ── Loading skeleton ──────────────────────────────────────────────────────────
function Skeleton() {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{
          width: 40, height: 40, border: `3px solid ${C.blue}`,
          borderTopColor: 'transparent', borderRadius: '50%',
          animation: 'spin 0.8s linear infinite', margin: '0 auto 12px',
        }} />
        <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
        <p style={{ color: C.muted, fontSize: 13 }}>Loading data…</p>
      </div>
    </div>
  );
}

// ── Empty state ───────────────────────────────────────────────────────────────
function Empty({ label = 'No alerts found' }) {
  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 12 }}>
      <span style={{ fontSize: 40 }}>🛡️</span>
      <p style={{ color: C.muted, fontSize: 14, margin: 0 }}>{label}</p>
    </div>
  );
}

// ── KPI card ──────────────────────────────────────────────────────────────────
function Kpi({ label, value, color = C.blue }) {
  return (
    <div style={{
      background: C.panel, border: C.border, borderRadius: 10,
      padding: '14px 18px', minWidth: 110, flex: '1 1 110px',
    }}>
      <div style={{ fontSize: 22, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 11, color: C.muted, marginTop: 3 }}>{label}</div>
    </div>
  );
}

// ── Alert row ────────────────────────────────────────────────────────────────
function AlertRow({ alert, index }) {
  const sev = alert.severity || alert.level || 'info';
  return (
    <div style={{
      display: 'grid',
      gridTemplateColumns: '32px 80px 1fr 120px',
      gap: 10, alignItems: 'center',
      padding: '9px 14px',
      background: index % 2 === 0 ? 'rgba(255,255,255,.02)' : 'transparent',
      borderBottom: '1px solid rgba(255,255,255,.04)',
      fontSize: 12,
    }}>
      <span style={{ color: C.muted }}>{index + 1}</span>
      <span style={{
        padding: '2px 8px', borderRadius: 5, fontWeight: 700, fontSize: 10,
        color: sevColor(sev), background: `${sevBg(sev)}88`,
        textAlign: 'center', textTransform: 'uppercase',
      }}>{sev}</span>
      <span style={{ color: C.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
        {alert.message || alert.title || alert.description || '—'}
      </span>
      <span style={{ color: C.muted, fontSize: 11, textAlign: 'right' }}>
        {alert.timestamp ? new Date(alert.timestamp).toLocaleTimeString() : '—'}
      </span>
    </div>
  );
}

// ── AdvancedData KPIs (for cards that pass advancedData) ──────────────────────
function AdvancedKpis({ data }) {
  if (!data) return null;
  const items = [
    { label: 'Total Events',   value: data.total       ?? '—', color: C.blue   },
    { label: 'Critical',       value: data.critical    ?? '—', color: C.red    },
    { label: 'High',           value: data.high        ?? '—', color: C.orange },
    { label: 'Agents Active',  value: data.agentCount  ?? '—', color: C.green  },
  ];
  return (
    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '14px 16px 0' }}>
      {items.map(k => <Kpi key={k.label} {...k} />)}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// CapabilityVisualDashboardPanel
// Used by ~30 generic EDR cards.
// Props: capabilityId, alerts, loading, total, advancedData, onRefresh
// ═════════════════════════════════════════════════════════════════════════════
export function CapabilityVisualDashboardPanel({ capabilityId, alerts = [], loading, total, advancedData, onRefresh }) {
  const critCount  = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
  const highCount  = alerts.filter(a => (a.severity || '').toLowerCase() === 'high').length;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: C.bg }}>
      {/* Top KPIs */}
      {advancedData
        ? <AdvancedKpis data={advancedData} />
        : (
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '14px 16px 0' }}>
            <Kpi label="Total Alerts"    value={total}     color={C.blue}   />
            <Kpi label="Critical"        value={critCount} color={C.red}    />
            <Kpi label="High"            value={highCount} color={C.orange} />
            <Kpi label="Capability ID"   value={`#${capabilityId}`} color={C.cyan} />
          </div>
        )
      }

      {/* Refresh */}
      <div style={{ padding: '10px 16px 4px', display: 'flex', justifyContent: 'flex-end' }}>
        <button
          type="button" onClick={onRefresh}
          style={{ background: 'none', border: `1px solid ${C.blue}44`, color: C.blue, borderRadius: 6, padding: '4px 12px', fontSize: 12, cursor: 'pointer' }}
        >↻ Refresh</button>
      </div>

      {/* Alert table */}
      <div style={{ flex: 1, overflow: 'auto', margin: '0 16px 16px' }}>
        {/* Header */}
        <div style={{
          display: 'grid', gridTemplateColumns: '32px 80px 1fr 120px',
          gap: 10, padding: '8px 14px',
          background: 'rgba(59,130,246,.08)', borderRadius: '8px 8px 0 0',
          fontSize: 11, fontWeight: 700, color: C.muted, textTransform: 'uppercase', letterSpacing: 1,
        }}>
          <span>#</span><span>Severity</span><span>Message</span><span style={{ textAlign: 'right' }}>Time</span>
        </div>

        {loading ? <Skeleton /> : alerts.length === 0 ? <Empty /> : alerts.map((a, i) => <AlertRow key={a._id || i} alert={a} index={i} />)}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// NetworkActivityDashboardPanel
// Props: alerts, systems, loading, total
// ═════════════════════════════════════════════════════════════════════════════
export function NetworkActivityDashboardPanel({ alerts = [], systems = [], loading, total }) {
  const inbound  = alerts.filter(a => a.direction === 'inbound'  || a.type === 'inbound').length;
  const outbound = alerts.filter(a => a.direction === 'outbound' || a.type === 'outbound').length;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: C.bg }}>
      {/* KPIs */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '14px 16px 0' }}>
        <Kpi label="Total Events"   value={total}           color={C.blue}   />
        <Kpi label="Inbound"        value={inbound}         color={C.cyan}   />
        <Kpi label="Outbound"       value={outbound}        color={C.orange} />
        <Kpi label="Active Systems" value={systems.length}  color={C.green}  />
      </div>

      {/* Alert table */}
      <div style={{ flex: 1, overflow: 'auto', margin: '12px 16px 16px' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '32px 80px 1fr 120px',
          gap: 10, padding: '8px 14px',
          background: 'rgba(59,130,246,.08)', borderRadius: '8px 8px 0 0',
          fontSize: 11, fontWeight: 700, color: C.muted, textTransform: 'uppercase', letterSpacing: 1,
        }}>
          <span>#</span><span>Severity</span><span>Message</span><span style={{ textAlign: 'right' }}>Time</span>
        </div>

        {loading ? <Skeleton /> : alerts.length === 0 ? <Empty label="No network events found" /> : alerts.map((a, i) => <AlertRow key={a._id || i} alert={a} index={i} />)}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// AuthenticationMonitoringDashboardPanel
// Props: alerts, loading, total
// ═════════════════════════════════════════════════════════════════════════════
export function AuthenticationMonitoringDashboardPanel({ alerts = [], loading, total }) {
  const failedLogins = alerts.filter(a => /fail|denied|reject/i.test(a.message || a.title || '')).length;
  const suspicious   = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical' || (a.severity || '').toLowerCase() === 'high').length;

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: C.bg }}>
      {/* KPIs */}
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', padding: '14px 16px 0' }}>
        <Kpi label="Total Events"    value={total}        color={C.blue}   />
        <Kpi label="Failed Logins"   value={failedLogins} color={C.red}    />
        <Kpi label="Suspicious"      value={suspicious}   color={C.orange} />
        <Kpi label="Monitored"       value={alerts.length} color={C.green} />
      </div>

      {/* Alert table */}
      <div style={{ flex: 1, overflow: 'auto', margin: '12px 16px 16px' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '32px 80px 1fr 120px',
          gap: 10, padding: '8px 14px',
          background: 'rgba(59,130,246,.08)', borderRadius: '8px 8px 0 0',
          fontSize: 11, fontWeight: 700, color: C.muted, textTransform: 'uppercase', letterSpacing: 1,
        }}>
          <span>#</span><span>Severity</span><span>Message</span><span style={{ textAlign: 'right' }}>Time</span>
        </div>

        {loading ? <Skeleton /> : alerts.length === 0 ? <Empty label="No auth events found" /> : alerts.map((a, i) => <AlertRow key={a._id || i} alert={a} index={i} />)}
      </div>
    </div>
  );
}
