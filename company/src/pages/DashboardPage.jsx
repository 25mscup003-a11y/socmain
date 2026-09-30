import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../api/config';
import { useAuth } from '../context/AuthContext';

import CAPABILITY_CONFIG, { getCapability } from '../utils/capabilityMap';

const CANONICAL_EDR_CARDS = CAPABILITY_CONFIG.map(c => ({
  cardId: c.capabilityId,
  backendId: c.backendId,
  name: c.title,
  publicRoute: c.publicRoute,
}));

// Summary cards do not need to rerun the backend's multi-collection overview
// query for every telemetry socket message. Live events may request a refresh,
// but each open dashboard is capped at one request per 30 seconds.
const MIN_SUMMARY_REFRESH_MS = 30000;

const dashboardGridCss = `
  @media (max-width: 1400px) {
    .edr-dashboard-card-grid { grid-template-columns: repeat(3, minmax(0, 1fr)) !important; }
  }
  @media (max-width: 1040px) {
    .edr-dashboard-card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  }
  @media (max-width: 700px) {
    .edr-dashboard-card-grid { grid-template-columns: 1fr !important; }
  }
`;

function statusMeta(status = 'missing') {
  if (status === 'active') return { color: '#34d399', label: 'ACTIVE' };
  return { color: '#f87171', label: 'MISSING' };
}

function capabilityCategory(cap = {}) {
  const id = Number(cap.id);
  const text = `${cap.name || ''} ${cap.description || ''} ${cap.source || ''}`.toLowerCase();
  if ([2, 12, 25, 30].includes(id)) return 'file';
  if ([3, 9, 15, 17, 18, 23, 26, 30, 31].includes(id)) return 'network';
  if ([10].includes(id)) return 'usb';
  if ([4, 11, 13, 14, 16, 29].includes(id)) return 'edr';
  if (/file|fim|hash|sandbox|malware|yara/.test(text)) return 'file';
  if (/network|dns|web|c2|beacon|cloud|exfil|geo/.test(text)) return 'network';
  if (/usb|device/.test(text)) return 'usb';
  return 'edr';
}

function dashboardMetrics(cap = {}) {
  const m = cap.metrics || {};
  const live = cap.live || {};
  return {
    total: Number(live.logs24h ?? m.logs24h ?? cap.logs24h ?? 0),
    suspicious: Number(live.highCritical24h ?? m.highCritical24h ?? cap.highCritical24h ?? 0),
    unauthorized: Number(live.unauthorized24h ?? m.unauthorized24h ?? cap.unauthorized24h ?? 0),
    activeAgents: Number(live.reportingAgents ?? m.reportingAgents ?? cap.reportingAgents ?? 0),
    missing: Number(live.missing ?? (cap.status === 'active' ? 0 : 1)),
    trendPct: Number(live.trendPct ?? m.trendPct ?? cap.trendPct ?? 0),
    timeline: Array.isArray(live.timeline24h) ? live.timeline24h : (m.timeline24h || cap.timeline24h || []),
  };
}

function buildWebDnsLiveMetrics(alerts = []) {
  const rows = Array.isArray(alerts) ? alerts : [];
  const total = rows.length;
  const suspicious = rows.filter(a =>
    a.blocked === true ||
    a.actionTaken === 'Blocked' ||
    a.containmentStatus === 'blocked' ||
    /dns.?tunnel|tunneling|high.?entropy|subdomain.?exfil|beacon|c2.?beac|command.?control|malicious|phishing|malware|ransomware|sql.?inject|sqli|xss|cross.?site|path.?travers|lfi|rfi|waf|web.?attack/i.test(
      `${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''} ${a.threatCategory || ''} ${a.malwareType || ''}`
    )
  ).length;
  const unauthorized = rows.filter(a =>
    a.blocked === true ||
    a.actionTaken === 'Blocked' ||
    /unauthoriz|denied|blocked/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.actionTaken || ''}`)
  ).length;
  const agents = new Set(rows.map(a => a.agentId || a.agentKey || a.agentName || a.systemId?._id || a.systemId).filter(Boolean)).size;
  const timeline = Array.from({ length: 24 }, () => ({ count: 0 }));
  const now = Date.now();
  rows.forEach(a => {
    const time = new Date(a.createdAt || a.timestamp || a.rawEvent?.timestamp || 0).getTime();
    const hoursAgo = Math.floor((now - time) / 3600000);
    if (Number.isFinite(hoursAgo) && hoursAgo >= 0 && hoursAgo < 24) {
      timeline[23 - hoursAgo].count += 1;
    }
  });
  const active = rows.some(a => a.status === 'active') ? 'active' : (rows.length ? 'active' : 'missing');
  const trendPct = total > 0 ? Math.max(0, Math.round(((timeline[23]?.count || total) / Math.max(total, 1)) * 100)) : 0;
  return {
    status: active,
    logs24h: total,
    highCritical24h: suspicious,
    unauthorized24h: unauthorized,
    reportingAgents: agents,
    missing: total ? 0 : 1,
    trendPct,
    timeline24h: timeline,
  };
}

function sparklinePoints(timeline = [], width = 220, height = 68) {
  const values = timeline.map(point => Number(point?.count || 0));
  if (values.length < 2 || !values.some(value => value > 0)) return '';
  const max = Math.max(...values, 1);
  return values.map((value, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - 8 - ((value / max) * (height - 16));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function DashboardEDRCard({ cap, onOpen }) {
  const id = Number(cap.id) || 1;
  const { color, label } = statusMeta(cap.live?.status || cap.status);
  const name = cap.name || 'EDR Module';
  const source = cap.source || cap.evidence || cap.description || 'EDR module dashboard';
  const category = capabilityCategory(cap);
  const metrics = dashboardMetrics(cap);
  const points = sparklinePoints(metrics.timeline);

  return (
    <button
      type="button"
      onClick={() => onOpen(id)}
      style={{
        background: 'linear-gradient(135deg, rgba(12,26,46,.86) 0%, rgba(15,21,53,.64) 100%)',
        border: `1px solid ${color}44`,
        borderRadius: 16,
        padding: '24px 26px',
        minHeight: 460,
        width: '100%',
        cursor: 'pointer',
        overflow: 'hidden',
        position: 'relative',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,.05), 0 1px 3px rgba(0,0,0,.3)',
        outline: 'none',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        textAlign: 'left',
        fontFamily: 'inherit',
      }}
    >
      <span>
        <span style={{ position: 'absolute', top: 0, right: 0, width: 170, height: 170, background: `radial-gradient(circle, ${color}14 0%, transparent 70%)`, pointerEvents: 'none' }} />
        <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, position: 'relative', zIndex: 1 }}>
          <span style={{ display: 'flex', gap: 13, alignItems: 'center', minWidth: 0 }}>
            <span style={{ width: 48, height: 48, borderRadius: 14, display: 'grid', placeItems: 'center', background: `${color}16`, border: `1px solid ${color}55`, color, fontSize: 23, fontWeight: 900 }}>
              ▱
            </span>
            <span style={{ width: 31, height: 31, borderRadius: 8, display: 'grid', placeItems: 'center', background: `${color}20`, color, border: `1px solid ${color}44`, fontSize: 13, fontWeight: 900 }}>
              {id}
            </span>
          </span>
          <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: '#60a5fa', fontSize: 13, fontWeight: 900 }}>↗</span>
            <span style={{ fontSize: 10, padding: '6px 10px', borderRadius: 8, fontWeight: 900, background: `${color}18`, color, border: `1px solid ${color}55` }}>
              {label}
            </span>
          </span>
        </span>

        <span style={{ display: 'block', marginTop: 26, color: '#7dd3fc', fontSize: 10, fontWeight: 900, letterSpacing: 1.2, position: 'relative', zIndex: 1 }}>
          LAST 24H LOG COUNT
        </span>
        <span style={{ display: 'block', marginTop: 7, color: '#e5edf7', fontSize: 36, fontWeight: 950, lineHeight: 1, position: 'relative', zIndex: 1 }}>
          {metrics.total.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: '#60a5fa', fontSize: 16, fontWeight: 900, marginTop: 14, lineHeight: 1.25, position: 'relative', zIndex: 1 }}>
          {name}
        </span>
        <span style={{ display: 'block', color: '#93c5fd', fontSize: 12, lineHeight: 1.45, marginTop: 16, position: 'relative', zIndex: 1 }}>
          High/Critical: {metrics.suspicious.toLocaleString()} · Unauthorized: {metrics.unauthorized.toLocaleString()}
        </span>
        {points ? (
          <svg aria-label="Real logs by hour for the last 24 hours" width="150" height="46" viewBox="0 0 220 68" style={{ display: 'block', marginTop: 18, position: 'relative', zIndex: 1 }}>
            <polyline points={points} fill="none" stroke="#3b82f6" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <span style={{ display: 'block', height: 46, marginTop: 18, color: '#64748b', fontSize: 10, lineHeight: '46px' }}>No live logs in this 24h window</span>
        )}
      </span>

      <span style={{ position: 'relative', zIndex: 1 }}>
        <span style={{ display: 'block', color: '#7dd3fc', fontSize: 12, lineHeight: 1.5, marginBottom: 8 }}>
          Reporting agents: {metrics.activeAgents.toLocaleString()} · Missing: {metrics.missing.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: metrics.trendPct >= 0 ? '#34d399' : '#f87171', fontSize: 11, fontWeight: 900, marginBottom: 16 }}>
          {metrics.trendPct >= 0 ? '↑' : '↓'} {Math.abs(metrics.trendPct)}% vs previous 24h
        </span>
        <span style={{ display: 'block', color: '#1d4ed8', fontSize: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          Monitor: {category} · {source}
        </span>
      </span>
    </button>
  );
}

function DashboardEDRModuleGrid({ data, loading, onOpen }) {
  const apiCaps = Array.isArray(data?.capabilities) ? data.capabilities : [];

  const apiMap = new Map();
  apiCaps.forEach(item => {
    if (item && item.id != null) {
      apiMap.set(Number(item.id), item);
    }
  });

  const cards = CANONICAL_EDR_CARDS.map(def => {
    const apiItem = apiMap.get(def.backendId);
    if (apiItem) {
      return {
        ...apiItem,
        id: def.cardId,
        backendId: def.backendId,
        name: def.name,
      };
    }
    return {
      id: def.cardId,
      backendId: def.backendId,
      name: def.name,
      status: 'missing',
      evidence: 'EDR module dashboard',
    };
  });

  return (
    <section style={{
      background: 'linear-gradient(135deg, rgba(6,13,22,.95), rgba(8,20,36,.88))',
      border: '1px solid rgba(34,211,238,.20)',
      borderRadius: 14,
      padding: 18,
      marginBottom: 22,
    }}>
      {loading && apiCaps.length === 0 && (
        <div style={{ color: '#60a5fa', fontSize: 12, marginBottom: 12 }}>Loading EDR cards...</div>
      )}
      <style>{dashboardGridCss}</style>
      <div className="edr-dashboard-card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 14 }}>
        {cards.map(cap => (
          <DashboardEDRCard
            key={cap.id}
            cap={cap}
            onOpen={onOpen}
          />
        ))}
      </div>
    </section>
  );
}

function SummaryCard({ title, value, subtitle, icon, color, onClick, trend, accent = 'cyan' }) {
  return (
    <button
      type="button"
      onClick={onClick}
      style={{
        minHeight: 168,
        padding: 20,
        border: `1px solid ${color}38`,
        borderRadius: 18,
        background: `radial-gradient(circle at top right, ${color}18, transparent 46%), linear-gradient(145deg, rgba(12,26,46,.98), rgba(7,16,31,.94))`,
        color: '#e2e8f0',
        textAlign: 'left',
        cursor: onClick ? 'pointer' : 'default',
        boxShadow: '0 18px 42px rgba(0,0,0,.24), inset 0 1px 0 rgba(255,255,255,.04)',
        fontFamily: 'inherit',
        position: 'relative',
        overflow: 'hidden',
      }}
    >
      <span style={{ position: 'absolute', inset: 'auto 0 0 0', height: 3, background: `linear-gradient(90deg, transparent, ${color}, transparent)`, opacity: .75 }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'flex-start' }}>
        <div>
          <div style={{ color: '#8fa4bd', fontSize: 11, fontWeight: 950, letterSpacing: '.08em', textTransform: 'uppercase' }}>{title}</div>
          <div style={{ marginTop: 14, color, fontSize: 36, fontWeight: 950, lineHeight: 1 }}>{value}</div>
        </div>
        <div style={{ width: 48, height: 48, borderRadius: 16, display: 'grid', placeItems: 'center', background: `${color}18`, border: `1px solid ${color}44`, fontSize: 23 }}>
          {icon}
        </div>
      </div>
      <div style={{ marginTop: 16, color: '#9fb0c6', fontSize: 13, lineHeight: 1.45 }}>{subtitle}</div>
      {trend && <div style={{ marginTop: 12, color: trend.color || color, fontSize: 12, fontWeight: 900 }}>{trend.text}</div>}
    </button>
  );
}

function PortalMetricCard({ item, navigate }) {
  const values = (item.chart || []).map(value => Math.max(0, Number(value || 0)));
  const chartMax = Math.max(...values, 1);
  return (
    <button
      type="button"
      onClick={() => navigate(item.to)}
      aria-label={`Open ${item.title}`}
      style={{
        minHeight: 226,
        padding: 18,
        border: `1px solid ${item.color}45`,
        borderRadius: 17,
        background: `radial-gradient(circle at 88% 2%, ${item.color}1c, transparent 40%), linear-gradient(155deg, rgba(10,25,44,.98), rgba(5,14,28,.97))`,
        boxShadow: `0 16px 36px rgba(0,0,0,.25), inset 0 1px 0 ${item.color}18`,
        color: '#e2e8f0',
        cursor: 'pointer',
        textAlign: 'left',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: 'inherit',
      }}
    >
      <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
        <span style={{ width: 42, height: 42, borderRadius: 13, display: 'grid', placeItems: 'center', background: `${item.color}18`, border: `1px solid ${item.color}45`, fontSize: 20 }}>{item.icon}</span>
        <span style={{ color: item.color, fontSize: 13, fontWeight: 950 }}>OPEN ↗</span>
      </span>
      <span style={{ display: 'block', marginTop: 14, color: '#f8fafc', fontSize: 15, fontWeight: 900 }}>{item.title}</span>
      <span style={{ display: 'block', marginTop: 8, color: item.color, fontSize: 29, fontWeight: 950, lineHeight: 1 }}>{item.value}</span>
      <span style={{ display: 'block', marginTop: 8, color: '#94a3b8', fontSize: 11, lineHeight: 1.4, minHeight: 31 }}>{item.subtitle}</span>
      <span aria-hidden="true" style={{ height: 42, display: 'flex', alignItems: 'end', gap: 5, marginTop: 14, paddingTop: 5, borderTop: '1px solid rgba(148,163,184,.12)' }}>
        {values.map((value, index) => (
          <span key={`${item.title}-${index}`} style={{ flex: 1, minWidth: 5, height: `${Math.max(12, Math.round((value / chartMax) * 100))}%`, borderRadius: '4px 4px 1px 1px', background: `linear-gradient(180deg, ${item.color}, ${item.color}55)`, boxShadow: `0 0 10px ${item.color}28` }} />
        ))}
      </span>
      <span style={{ display: 'block', marginTop: 7, color: '#526984', fontSize: 9, fontWeight: 800, letterSpacing: '.08em' }}>LIVE COMPANY SNAPSHOT</span>
    </button>
  );
}

function DashboardPortalSection({ title, eyebrow, items, navigate, color }) {
  return (
    <section style={{ border: `1px solid ${color}2f`, borderRadius: 20, padding: 19, background: 'linear-gradient(145deg,rgba(6,15,28,.95),rgba(8,20,36,.86))', boxShadow: '0 18px 42px rgba(0,0,0,.20)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'end', marginBottom: 16 }}>
        <div>
          <div style={{ color, fontSize: 10, fontWeight: 950, letterSpacing: '.12em', textTransform: 'uppercase' }}>{eyebrow}</div>
          <h2 style={{ color: '#f8fafc', fontSize: 20, margin: '5px 0 0' }}>{title}</h2>
        </div>
        <div style={{ color: '#64748b', fontSize: 11 }}>{items.length} live modules</div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(210px,1fr))', gap: 13 }}>
        {items.map(item => <PortalMetricCard key={`${item.to}-${item.title}`} item={item} navigate={navigate} />)}
      </div>
    </section>
  );
}

function SmallMetric({ label, value, sub, color = '#38bdf8' }) {
  return (
    <div style={{
      border: `1px solid ${color}32`,
      borderRadius: 14,
      background: `linear-gradient(145deg, ${color}12, rgba(8,18,34,.76))`,
      padding: 14,
      minHeight: 96,
    }}>
      <div style={{ color: '#94a3b8', fontSize: 10, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ color, fontSize: 25, fontWeight: 950, marginTop: 9, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ color: '#9fb0c6', fontSize: 11, marginTop: 8, lineHeight: 1.35 }}>{sub}</div>}
    </div>
  );
}

function MiniPanel({ title, children, action }) {
  return (
    <section style={{
      border: '1px solid #1e3a5f',
      borderRadius: 18,
      background: 'linear-gradient(145deg, rgba(8,18,34,.96), rgba(9,16,34,.92))',
      boxShadow: '0 16px 38px rgba(0,0,0,.22)',
      overflow: 'hidden',
    }}>
      <div style={{ padding: '15px 18px', borderBottom: '1px solid #1e3a5f', display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <h3 style={{ margin: 0, fontSize: 15, color: '#e2e8f0' }}>{title}</h3>
        {action}
      </div>
      <div style={{ padding: 18 }}>{children}</div>
    </section>
  );
}

function catmullRom2bezier(points) {
  if (!points || points.length === 0) return '';
  if (points.length === 1) return `M ${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
  let d = `M ${points[0].x.toFixed(1)},${points[0].y.toFixed(1)}`;
  for (let i = 0; i < points.length - 1; i++) {
    const p0 = points[Math.max(i - 1, 0)];
    const p1 = points[i];
    const p2 = points[i + 1];
    const p3 = points[Math.min(i + 2, points.length - 1)];

    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;

    d += ` C ${cp1x.toFixed(1)},${cp1y.toFixed(1)} ${cp2x.toFixed(1)},${cp2y.toFixed(1)} ${p2.x.toFixed(1)},${p2.y.toFixed(1)}`;
  }
  return d;
}

function CommandCenterChart({ activity = [], posture = 75, postureColor = '#34d399' }) {
  const [hoverIndex, setHoverIndex] = React.useState(null);
  const [visibleSeries, setVisibleSeries] = React.useState({ critical: true, high: true, investigated: true });
  const rowMap = new Map((Array.isArray(activity) ? activity : []).map(row => [row._id, row]));
  const hour = new Date();
  hour.setUTCMinutes(0, 0, 0);

  const buckets = Array.from({ length: 24 }, (_, index) => {
    const at = new Date(hour.getTime() - ((23 - index) * 3600000));
    const key = at.toISOString();
    return { at, ...(rowMap.get(key) || {}) };
  });

  const totals = buckets.reduce((sum, row) => ({
    critical: sum.critical + Number(row.critical || 0),
    high: sum.high + Number(row.high || 0),
    investigated: sum.investigated + Number(row.investigated || 0),
    mitigated: sum.mitigated + Number(row.mitigated || 0),
  }), { critical: 0, high: 0, investigated: 0, mitigated: 0 });

  const maxVal = Math.max(
    ...buckets.flatMap(row => [
      visibleSeries.critical ? (row.critical || 0) : 0,
      visibleSeries.high ? (row.high || 0) : 0,
      visibleSeries.investigated ? (row.investigated || 0) : 0,
    ]),
    10
  );

  const getPointsArr = (field) => buckets.map((row, index) => {
    const x = 20 + ((index / 23) * 680);
    const val = Number(row[field] || 0);
    const displayVal = val;
    const y = 175 - ((displayVal / maxVal) * 135);
    return { x, y, val, displayVal, row };
  });

  const investigatedArr = getPointsArr('investigated');
  const highArr = getPointsArr('high');
  const criticalArr = getPointsArr('critical');

  const investigatedPath = catmullRom2bezier(investigatedArr);
  const highPath = catmullRom2bezier(highArr);
  const criticalPath = catmullRom2bezier(criticalArr);

  const investigatedArea = investigatedPath ? `${investigatedPath} L 700 185 L 20 185 Z` : '';
  const highArea = highPath ? `${highPath} L 700 185 L 20 185 Z` : '';

  const trend = totals.investigated > 0
    ? Number(((totals.mitigated / totals.investigated) * 100).toFixed(1))
    : 0;

  const handleMouseMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const svgX = (mouseX / rect.width) * 720;
    const idx = Math.round(((svgX - 20) / 680) * 23);
    setHoverIndex(Math.max(0, Math.min(23, idx)));
  };

  const activeHoverBucket = hoverIndex !== null ? buckets[hoverIndex] : null;

  return (
    <div style={{ minWidth: 0, width: '100%', border: '1px solid rgba(34,211,238,.42)', borderRadius: 20, padding: 22, background: 'radial-gradient(circle at 85% 15%,rgba(14,165,233,.09),transparent 33%),linear-gradient(145deg,#061426,#07182d)', boxShadow: '0 22px 54px rgba(0,0,0,.30), inset 0 1px 0 rgba(255,255,255,.04)', position: 'relative' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
        <div>
          <div style={{ color: '#7dd3fc', fontSize: 10, fontWeight: 950, letterSpacing: '.12em', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#22d3ee', boxShadow: '0 0 10px #22d3ee' }} />
            LIVE SECURITY ACTIVITY
          </div>
          <div style={{ color: '#64748b', fontSize: 11, marginTop: 5 }}>Real-time alert telemetry · Last 24 hours</div>
        </div>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, color: '#34d399', fontSize: 10, fontWeight: 900, background: 'rgba(52,211,153,.1)', padding: '4px 10px', borderRadius: 20, border: '1px solid rgba(52,211,153,.3)' }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#34d399', boxShadow: '0 0 12px #34d399' }} /> LIVE TELEMETRY
        </span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) minmax(150px,.22fr)', alignItems: 'stretch', gap: 24, marginTop: 18 }}>
        <div style={{ position: 'relative' }}>
          <div style={{ display: 'flex', gap: 24, marginBottom: 8, color: '#94a3b8', fontSize: 11 }}>
            {[['Critical', '#fb4b68'], ['High', '#f59e0b'], ['Investigated', '#22d3ee']].map(([label, color]) => (
              <span key={label} style={{ display: 'inline-flex', alignItems: 'center', gap: 7 }}>
                <i style={{ width: 8, height: 8, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}` }} />
                {label} ({totals[label.toLowerCase()] || 0})
              </span>
            ))}
          </div>

          {/* SVG Graph */}
          <svg viewBox="0 0 720 220" role="img" aria-label="Critical, high and investigated alerts over the last 24 hours" onMouseMove={handleMouseMove} onMouseLeave={() => setHoverIndex(null)} style={{ width: '100%', minHeight: 240, overflow: 'visible', cursor: 'crosshair' }}>
            <defs>
              <linearGradient id="activityArea" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#22d3ee" stopOpacity=".38" />
                <stop offset="100%" stopColor="#3b82f6" stopOpacity="0" />
              </linearGradient>
              <filter id="neonGlowCyan" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feMerge>
                  <feMergeNode in="blur" />
                  <feMergeNode in="SourceGraphic" />
                </feMerge>
              </filter>
            </defs>
            {[36, 74, 112, 150, 185].map(y => <line key={y} x1="14" y1={y} x2="706" y2={y} stroke="#1e3a5f" strokeWidth="1" strokeDasharray="4 5" />)}
            {[16, 188, 360, 532, 704].map(x => <line key={x} x1={x} y1="34" x2={x} y2="185" stroke="#1e3a5f" strokeWidth="1" strokeDasharray="4 5" />)}
            
            {investigatedArea && <path d={investigatedArea} fill="url(#activityArea)" />}
            {investigatedPath && <path d={investigatedPath} fill="none" stroke="#22d3ee" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" filter="url(#neonGlowCyan)" />}
            {highPath && <path d={highPath} fill="none" stroke="#f59e0b" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />}
            {criticalPath && <path d={criticalPath} fill="none" stroke="#fb4b68" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />}
            
            {/* Live Pulsing Node at Latest Hour */}
            {investigatedArr[23] && (
              <g transform={`translate(${investigatedArr[23].x}, ${investigatedArr[23].y})`}>
                <circle r="7" fill="#22d3ee" opacity=".4">
                  <animate attributeName="r" values="4;10;4" dur="2s" repeatCount="indefinite" />
                  <animate attributeName="opacity" values=".6;.1;.6" dur="2s" repeatCount="indefinite" />
                </circle>
                <circle r="4" fill="#22d3ee" />
              </g>
            )}

            {buckets.filter((_, index) => index % 4 === 0 || index === 23).map((row, index) => {
              const originalIndex = index === 6 ? 23 : index * 4;
              const x = 16 + ((originalIndex / 23) * 688);
              return <text key={row.at.toISOString()} x={x} y="212" fill="#64748b" fontSize="10" textAnchor={originalIndex === 0 ? 'start' : originalIndex === 23 ? 'end' : 'middle'}>{originalIndex === 23 ? 'NOW' : row.at.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</text>;
            })}
          </svg>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 12 }}>
            {[
              ['🛡', 'CRITICAL', totals.critical, '#fb4b68'],
              ['⬡', 'HIGH', totals.high, '#f59e0b'],
              ['⌾', 'MITIGATED', totals.mitigated, '#22d3ee'],
            ].map(([icon, label, value, color]) => <div key={label} style={{ padding: '14px 16px', borderRadius: 12, border: `1px solid ${color}66`, background: `${color}0b`, display: 'flex', alignItems: 'center', gap: 12 }}><span style={{ width: 38, height: 38, borderRadius: 9, display: 'grid', placeItems: 'center', color, background: `${color}18`, fontSize: 19 }}>{icon}</span><span style={{ color, fontSize: 11, fontWeight: 950, letterSpacing: '.12em' }}>{label}</span><strong style={{ color, marginLeft: 'auto', fontSize: 25 }}>{Number(value).toLocaleString()}</strong></div>)}
          </div>
        </div>
        <div style={{ borderLeft: '1px solid #1e3a5f', display: 'grid', placeItems: 'center', paddingLeft: 20 }}>
          <div style={{ width: 78, height: 78, borderRadius: '50%', display: 'grid', placeItems: 'center', background: `conic-gradient(${postureColor} ${posture * 3.6}deg, rgba(30,58,95,.65) 0deg)`, boxShadow: `0 0 28px ${postureColor}28` }}>
            <div style={{ width: 60, height: 60, borderRadius: '50%', background: '#071426', display: 'grid', placeItems: 'center', border: '1px solid #1e3a5f', textAlign: 'center' }}>
              <span><strong style={{ display: 'block', color: postureColor, fontSize: 18 }}>{posture}%</strong><small style={{ color: '#64748b', fontSize: 7, fontWeight: 900 }}>POSTURE</small></span>
            </div>
          </div>
          <div style={{ color: '#34d399', fontSize: 13, fontWeight: 950, marginTop: -35 }}>↗ {trend}%</div>
          <div style={{ color: '#64748b', fontSize: 10, marginTop: -45 }}>mitigation coverage</div>
        </div>
      </div>
    </div>
  );
}

function CompanyAdminSummaryDashboard({ summary, loading, error, navigate, isDeptAdmin = false }) {
  const edr = summary?.edr || {};
  const ids = summary?.ids || {};
  const ips = summary?.ips || {};
  const firewall = summary?.firewall || {};
  const systems = summary?.systems || {};
  const overview = summary?.companyOverview || {};
  const companyInfo = summary?.company || {};
  const incidents = overview.incidents || {};
  const soar = overview.soar || {};
  const soar24h = soar.last24h || {};
  const soarPlaybooks = soar.playbooks || {};
  const tickets = overview.supportTickets || {};
  const forensics = overview.forensics || {};
  const fmt = value => Number(value || 0).toLocaleString();
  const idsHigh = Number(ids.high || ids.severity?.high || 0);
  const idsCritical = Number(ids.critical || ids.severity?.critical || 0);
  const priorityEvents = Number(edr.highCritical || 0) + idsHigh + idsCritical;
  const totalControls = Number(edr.totalCapabilities || 31) + Number(firewall.totalRules || 0);
  const activeControls = Number(edr.activeCapabilities || 0) + Number(firewall.enabledRules || 0);
  const posture = Math.max(0, Math.min(100, Math.round((activeControls / Math.max(totalControls, 1)) * 100)));
  const postureColor = posture >= 80 ? '#34d399' : posture >= 55 ? '#f59e0b' : '#f87171';
  const planActive = overview.planActive !== false;
  const userCount = Number(overview.users || overview.analysts || overview.userCount || 0);
  const totalSecurityEvents = Number(edr.logs || 0) + Number(ids.total || ids.totalAlerts || 0);
  const setupCards = [
    { icon: '🏢', title: 'Departments', to: '/company-admin/departments', color: '#60a5fa', value: fmt(overview.departments), subtitle: 'Configured business units', chart: [overview.departments, userCount, systems.total] },
    { icon: '🖥', title: 'Systems', to: '/company-admin/systems', color: '#38bdf8', value: `${fmt(systems.online)}/${fmt(systems.total)}`, subtitle: `${fmt(systems.offline)} offline or stale endpoints`, chart: [systems.online, systems.offline, systems.total] },
    { icon: '⬇', title: 'Download Agent', to: '/company-admin/download-agent', color: '#a78bfa', value: fmt(systems.total), subtitle: 'Installed/registered endpoint agents', chart: [systems.total, systems.online, overview.systemsRemaining] },
    { icon: '🛡', title: 'EDR Setup', to: '/company-admin/edrsystemstupe', color: '#22d3ee', value: `${fmt(edr.activeCapabilities)}/${fmt(edr.totalCapabilities)}`, subtitle: 'Endpoint controls and DNS Sinkhole policies', chart: [edr.activeCapabilities, edr.totalCapabilities, systems.online] },
    { icon: '👥', title: 'Team', to: '/company-admin/users', color: '#34d399', value: fmt(userCount), subtitle: 'Dept Admins & SOC Managers', chart: [overview.users, overview.departments] },
    { icon: '💳', title: 'Payments', to: '/company-admin/payments', color: '#f59e0b', value: planActive ? 'ACTIVE' : 'INACTIVE', subtitle: `${overview.planType || 'No plan'} · ${fmt(overview.systemsRemaining)} licenses remaining`, chart: [overview.systemsUsed, overview.systemsRemaining, overview.systemLimit] },
    { icon: '⚙', title: 'Settings', to: '/company-admin/settings', color: '#94a3b8', value: `${posture}%`, subtitle: 'Company profile and security posture', chart: [posture, activeControls, totalControls] },
  ];
  const monitoringCards = [
    { icon: '🏬', title: 'Department Monitoring', to: '/company-admin/departments', color: '#818cf8', value: fmt(overview.departments), subtitle: `${fmt(systems.online)} online assets across departments`, chart: [overview.departments, systems.online, systems.total] },
    { icon: '📊', title: 'System Monitoring', to: '/company-admin/system-monitoring', color: '#34d399', value: `${fmt(systems.online)} Online`, subtitle: `${fmt(systems.total)} total monitored assets`, chart: [systems.online, systems.offline, systems.total] },
    { icon: '📡', title: 'SIEM', to: '/company-admin/siem', color: '#60a5fa', value: fmt(totalSecurityEvents), subtitle: 'EDR + IDS events in the live window', chart: [edr.logs, ids.total || ids.totalAlerts, priorityEvents] },
    { icon: '📈', title: 'Log Monitor', to: '/company-admin/log-monitor', color: '#38bdf8', value: fmt(totalSecurityEvents), subtitle: 'Centralized security events available', chart: [edr.logs, ids.total || ids.totalAlerts, incidents.total] },
    { icon: '📊', title: 'Security Score', to: '/company-admin/security-score', color: '#22c55e', value: `${posture}%`, subtitle: `${fmt(activeControls)} of ${fmt(totalControls)} controls active`, chart: [posture, activeControls, totalControls] },
    { icon: '📄', title: 'Reports', to: '/company-admin/reports', color: '#94a3b8', value: fmt(incidents.total), subtitle: `${fmt(incidents.solved)} resolved incidents ready for reporting`, chart: [incidents.open, incidents.solved, incidents.total] },
    { icon: '🎟', title: 'SOAR Tickets', to: '/company-admin/soar', color: '#facc15', value: fmt(soar24h.tickets), subtitle: 'Ticket-linked SOAR executions · Last 24h', chart: [soar24h.tickets, soar24h.completed, soar24h.pending] },
    { icon: '⏳', title: 'SOAR Pending', to: '/company-admin/soar', color: '#fb923c', value: fmt(soar24h.pending), subtitle: `${fmt(soar24h.completed)} completed · ${fmt(soar24h.failed)} failed in 24h`, chart: [soar24h.pending, soar24h.completed, soar24h.failed] },
    { icon: '🤖', title: 'SOAR AI Analysis', to: '/company-admin/soar', color: '#a78bfa', value: fmt(soar24h.aiAnalyzed), subtitle: 'AI-analyzed SOAR executions · Last 24h', chart: [soar24h.aiAnalyzed, soar24h.total, soar24h.completed] },
    { icon: '✅', title: 'Enabled Playbooks', to: '/company-admin/soar', color: '#34d399', value: fmt(soarPlaybooks.enabled), subtitle: `${fmt(soarPlaybooks.total)} total SOAR playbooks`, chart: [soarPlaybooks.enabled, soarPlaybooks.disabled, soarPlaybooks.total] },
    { icon: '⚙', title: 'Automatic Playbooks', to: '/company-admin/soar', color: '#22d3ee', value: fmt(soarPlaybooks.automatic), subtitle: 'Automatic execution mode', chart: [soarPlaybooks.automatic, soarPlaybooks.total] },
    { icon: '✋', title: 'Approval Required', to: '/company-admin/soar', color: '#facc15', value: fmt(soarPlaybooks.approvalRequired), subtitle: 'Human approval gateway playbooks', chart: [soarPlaybooks.approvalRequired, soarPlaybooks.total] },
    { icon: '👤', title: 'Manual Only Playbooks', to: '/company-admin/soar', color: '#c084fc', value: fmt(soarPlaybooks.manualOnly), subtitle: 'Analyst-triggered playbooks only', chart: [soarPlaybooks.manualOnly, soarPlaybooks.total] },
    { icon: '⛔', title: 'Disabled Playbooks', to: '/company-admin/soar', color: '#f87171', value: fmt(soarPlaybooks.modeDisabled), subtitle: `${fmt(soarPlaybooks.disabled)} playbooks disabled by toggle`, chart: [soarPlaybooks.modeDisabled, soarPlaybooks.disabled, soarPlaybooks.total] },
  ];
  const requirementRows = [
    ['Company Profile', companyInfo?.name ? 'Ready' : 'Needs update', companyInfo?.name || 'Open company settings', '/company-admin/settings', companyInfo?.name ? '#34d399' : '#f59e0b'],
    ['Departments', Number(overview.departments || 0) > 0 ? 'Configured' : 'Missing', `${fmt(overview.departments)} active departments`, '/company-admin/departments', Number(overview.departments || 0) > 0 ? '#34d399' : '#f87171'],
    ['Users / Analysts', userCount > 0 ? 'Configured' : 'Review', `${fmt(userCount)} users tracked`, '/company-admin/users', userCount > 0 ? '#34d399' : '#38bdf8'],
    ['Assets / Agents', Number(systems.total || 0) > 0 ? 'Reporting' : 'Missing', `${fmt(systems.online)} online · ${fmt(systems.offline)} offline`, '/company-admin/systems', Number(systems.online || 0) > 0 ? '#34d399' : '#f87171'],
    ['License / Plan', planActive ? 'Active' : 'Inactive', `${overview.planType || 'plan'} · expires ${overview.planExpires ? new Date(overview.planExpires).toLocaleDateString() : '—'}`, '/company-admin/settings', planActive ? '#34d399' : '#f87171'],
    ['Incident Workflow', Number(incidents.total || 0) > 0 ? 'Live' : 'No incidents', `${fmt(incidents.open)} open · ${fmt(incidents.solved)} solved`, '/company-admin/correlation', Number(incidents.open || 0) > 0 ? '#f59e0b' : '#34d399'],
  ];

  return (
    <div style={{ color: '#dbeafe', display: 'grid', gap: 18 }}>
      <section style={{
        padding: 24,
        border: '1px solid #1e3a5f',
        borderRadius: 22,
        background: 'radial-gradient(circle at 82% 18%, rgba(56,189,248,.20), transparent 32%), radial-gradient(circle at 16% 0%, rgba(124,58,237,.18), transparent 34%), linear-gradient(135deg,#071426,#101936)',
        boxShadow: '0 22px 54px rgba(0,0,0,.30)',
      }}>
        <div>
          <div style={{ marginBottom: 18 }}>
            <div style={{ color: '#38bdf8', fontSize: 12, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>{isDeptAdmin ? 'Department Admin Dashboard' : 'Company Admin Dashboard'}</div>
            <h1 style={{ margin: '8px 0 0', fontSize: 'clamp(28px,4vw,42px)', color: '#f8fafc', letterSpacing: '-.04em' }}>Spartan Cyber Defense Center (SCDC)</h1>
          </div>
          <CommandCenterChart activity={summary?.alertActivity} posture={posture} postureColor={postureColor} />
        </div>
      </section>

      {loading && !summary && <div style={{ color: '#60a5fa', marginBottom: 12 }}>Loading dashboard summary…</div>}
      {error && !summary && <div style={{ color: '#fca5a5', border: '1px solid #ef444455', background: '#3f111b66', borderRadius: 12, padding: 13 }}>{error}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 12 }}>
        <SmallMetric label="Departments" value={fmt(overview.departments)} sub="Active business units" color="#22d3ee" />
        <SmallMetric label="Assets Used" value={`${fmt(overview.systemsUsed || systems.total)}/${fmt(overview.systemLimit || systems.total)}`} sub={`${fmt(overview.systemsRemaining)} remaining in plan`} color="#34d399" />
        <SmallMetric label="Open Alerts" value={fmt(overview.openAlerts)} sub={`${fmt(overview.criticalAlerts)} critical open`} color="#f87171" />
        <SmallMetric label="Risk Score" value={fmt(overview.riskScore)} sub={`Company status: ${overview.status || companyInfo?.status || '—'}`} color="#f59e0b" />
        <SmallMetric label="Plan" value={overview.planType || companyInfo?.plan?.type || '—'} sub={planActive ? 'License active' : 'License inactive'} color={planActive ? '#34d399' : '#f87171'} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(230px,1fr))', gap: 16 }}>
        <SummaryCard title="EDR Coverage" icon="🛡️" color="#38bdf8" value={`${fmt(edr.activeCapabilities)}/${fmt(edr.totalCapabilities)}`} subtitle={`${fmt(edr.logs)} endpoint events · ${fmt(edr.highCritical)} high/critical`} trend={{ text: '31-point EDR mapped', color: '#7dd3fc' }} onClick={() => navigate('/company-admin/edr')} />
        <SummaryCard title="IDS / IPS" icon="📡" color="#22d3ee" value={fmt(ids.total || ids.totalAlerts || 0)} subtitle={`${fmt(idsHigh)} high · ${fmt(idsCritical)} critical · ${fmt(ips.activeBlocks)} active blocks`} onClick={() => navigate('/company-admin/ids')} />
        <SummaryCard title="Firewall Controls" icon="🔥" color="#fb923c" value={fmt(firewall.enabledRules || firewall.totalRules || 0)} subtitle={`${fmt(firewall.blockRules)} block · ${fmt(firewall.pendingRules)} pending · ${fmt(firewall.failedRules)} failed`} onClick={() => navigate('/company-admin/firewall')} />
        <SummaryCard title="Agents Online" icon="🟢" color="#34d399" value={`${fmt(systems.online)}/${fmt(systems.total)}`} subtitle={`${fmt(systems.offline)} offline or stale agents`} onClick={() => navigate('/company-admin/systems')} />
        <SummaryCard title="Priority Signals" icon="⚠️" color="#f87171" value={fmt(priorityEvents)} subtitle="Combined high-priority EDR + IDS/IPS workload" onClick={() => navigate('/company-admin/alerts')} />
        <SummaryCard title="Total Incidents" icon="🚨" color="#f87171" value={fmt(incidents.total)} subtitle={`${fmt(incidents.solved)} solved · ${fmt(incidents.open)} open`} onClick={() => navigate('/company-admin/incidents')} />
        <SummaryCard title="EDR Correlation Incidents" icon="⇄" color="#60a5fa" value={fmt(incidents.edrCorrelation?.total)} subtitle={`${fmt(incidents.edrCorrelation?.solved)} solved · ${fmt(incidents.edrCorrelation?.open)} open`} onClick={() => navigate('/company-admin/correlation')} />
        <SummaryCard title="Threat Intel Incidents" icon="⌾" color="#c4b5fd" value={fmt(incidents.threatIntel?.total)} subtitle={`${fmt(incidents.threatIntel?.solved)} solved · ${fmt(incidents.threatIntel?.open)} open`} onClick={() => navigate('/company-admin/threat-intelligence')} />
        <SummaryCard title="Forensics" icon="🔬" color="#2dd4bf" value={fmt(forensics.hunts)} subtitle={`${fmt(forensics.activeHunts)} active hunts · ${fmt(forensics.evidence)} evidence items`} onClick={() => navigate('/company-admin/forensics')} />
        <SummaryCard title="SOAR Activity" icon="⚡" color="#a78bfa" value={fmt(soar.total)} subtitle={`${fmt(soar.solved)} completed · ${fmt(soar.open)} running/pending · ${fmt(soar.failed)} failed`} onClick={() => navigate('/company-admin/soar')} />
        <SummaryCard title="Support Tickets" icon="🎟" color="#facc15" value={fmt(tickets.total)} subtitle={`${fmt(tickets.solved)} solved · ${fmt(tickets.open)} open`} onClick={() => navigate('/company-admin/settings')} />
        <SummaryCard
          title="Platform Health"
          icon="▦"
          color={overview.sourcesDegraded ? '#f59e0b' : '#34d399'}
          value={loading ? 'SYNC' : (overview.sourcesDegraded ? 'PARTIAL' : 'LIVE')}
          subtitle={overview.sourcesDegraded ? 'One or more live sources timed out' : 'All dashboard sources returned real data'}
        />
      </div>

      <DashboardPortalSection title="System Setup" eyebrow="Company Administration" items={setupCards} navigate={navigate} color="#38bdf8" />
      <DashboardPortalSection title="Monitoring" eyebrow="Live SOC Operations" items={monitoringCards} navigate={navigate} color="#34d399" />
    </div>
  );
}

export default function DashboardPage() {
  const { user, company, isDeptAdmin } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [summary, setSummary] = useState(null);
  const [summaryLoading, setSummaryLoading] = useState(true);
  const [summaryError, setSummaryError] = useState('');
  const sockRef = useRef(null);
  const refreshTimerRef = useRef(null);
  const summaryInFlightRef = useRef(false);
  const lastSummaryRequestAtRef = useRef(0);
  const companyId = user?.companyId || company?._id || company?.id;
  const scopedNavigate = useCallback((target, options) => {
    if (!isDeptAdmin || typeof target !== 'string') return navigate(target, options);
    const departmentTarget = target
      .replace(/^\/company-admin\/users/, '/department-admin/team')
      .replace(/^\/company-admin/, '/department-admin');
    return navigate(departmentTarget, options);
  }, [isDeptAdmin, navigate]);

  const loadSummary = useCallback(() => {
    if (summaryInFlightRef.current) return Promise.resolve();
    summaryInFlightRef.current = true;
    lastSummaryRequestAtRef.current = Date.now();
    setSummaryLoading(true);
    setSummaryError('');
    return api.get('/company/overview')
      .then((overviewRes) => {
        const stats = overviewRes.data?.stats || {};
        const sources = stats.sources || {};
        setSummary({
          edr: sources.edr || {},
          ids: sources.ids || {},
          ips: sources.ips || {},
          firewall: sources.firewall || {},
          company: overviewRes.data?.company || {},
          companyOverview: {
            ...stats,
            sourcesUpdatedAt: sources.updatedAt,
            sourcesWindowHours: sources.windowHours,
            sourcesDegraded: Boolean(sources.degraded),
          },
          systems: sources.systems || {},
          alertActivity: sources.alertActivity || [],
        });
      })
      .catch((err) => {
        // Keep the last successful snapshot during a temporary API error.
        setSummaryError(err?.response?.data?.message || err?.message || 'Unable to load live company dashboard data');
      })
      .finally(() => {
        summaryInFlightRef.current = false;
        setSummaryLoading(false);
      });
  }, []);

  const scheduleRefresh = useCallback(() => {
    if (refreshTimerRef.current) return;
    const elapsed = Date.now() - lastSummaryRequestAtRef.current;
    const delay = Math.max(1000, MIN_SUMMARY_REFRESH_MS - elapsed);
    refreshTimerRef.current = setTimeout(() => {
      refreshTimerRef.current = null;
      if (document.visibilityState === 'hidden') return;
      loadSummary();
    }, delay);
  }, [loadSummary]);

  useEffect(() => {
    loadSummary();
    const refreshInterval = setInterval(() => {
      if (document.visibilityState !== 'hidden') loadSummary();
    }, 60000);
    const refreshWhenVisible = () => {
      if (document.visibilityState === 'visible'
        && Date.now() - lastSummaryRequestAtRef.current >= MIN_SUMMARY_REFRESH_MS) {
        scheduleRefresh();
      }
    };
    document.addEventListener('visibilitychange', refreshWhenVisible);
    const sock = io(SOCKET_URL);
    sockRef.current = sock;
    if (companyId) sock.emit('join:company', companyId);
    sock.on('alert:new', scheduleRefresh);
    sock.on('alert:updated', scheduleRefresh);
    sock.on('alert:deleted', scheduleRefresh);
    sock.on('webdns:event', scheduleRefresh);
    sock.on('telemetry:new', scheduleRefresh);
    const disconnectSocket = connectSocket(sock);
    return () => {
      sock.off('alert:new', scheduleRefresh);
      sock.off('alert:updated', scheduleRefresh);
      sock.off('alert:deleted', scheduleRefresh);
      sock.off('webdns:event', scheduleRefresh);
      sock.off('telemetry:new', scheduleRefresh);
      disconnectSocket();
      document.removeEventListener('visibilitychange', refreshWhenVisible);
      clearInterval(refreshInterval);
      if (refreshTimerRef.current) {
        clearTimeout(refreshTimerRef.current);
        refreshTimerRef.current = null;
      }
    };
  }, [companyId, loadSummary, scheduleRefresh]);

  useEffect(() => {
    const rawId = Number(searchParams.get('capabilityId') || searchParams.get('cap'));
    if (!rawId) return;
    const targetCap = getCapability(rawId);
    const capId = targetCap ? targetCap.id : rawId;
    scopedNavigate(`/company-admin/edr?capabilityId=${capId}&from=dashboard`, { replace: true });
  }, [searchParams, scopedNavigate]);

  return (
    <div>
      <CompanyAdminSummaryDashboard summary={summary} loading={summaryLoading} error={summaryError} navigate={scopedNavigate} isDeptAdmin={isDeptAdmin} />
    </div>
  );
}
