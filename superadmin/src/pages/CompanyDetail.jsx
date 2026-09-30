import React, { useEffect, useRef, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, io } from '../api/config';
import CAPABILITY_CONFIG from '../utils/capabilityMap';

const CANONICAL_EDR_CARDS = CAPABILITY_CONFIG.map(c => ({
  cardId: c.capabilityId,
  backendId: c.backendId,
  name: c.title,
  icon: c.icon || '▱',
}));

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

function sparklinePoints(timeline = [], width = 150, height = 42) {
  const values = timeline.map(point => Number(point?.count || 0));
  if (values.length < 2 || !values.some(value => value > 0)) return '';
  const max = Math.max(...values, 1);
  return values.map((value, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - 6 - ((value / max) * (height - 12));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
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

function CommandCenterChart({ activity = [], alerts = [], posture = 75, postureColor = '#34d399' }) {
  const [hoverIndex, setHoverIndex] = React.useState(null);

  const hour = new Date();
  hour.setMinutes(0, 0, 0);

  const buckets = Array.from({ length: 24 }, (_, index) => {
    const at = new Date(hour.getTime() - ((23 - index) * 3600000));
    return { at, critical: 0, high: 0, investigated: 0, mitigated: 0 };
  });

  const activeArr = Array.isArray(activity) && activity.length > 0 ? activity : (Array.isArray(alerts) ? alerts : []);

  activeArr.forEach(item => {
    if (!item) return;

    let itemDate = null;
    if (typeof item._id === 'string' && item._id.includes('T')) {
      itemDate = new Date(item._id);
    } else if (item.createdAt) {
      itemDate = new Date(item.createdAt);
    }

    if (itemDate && !isNaN(itemDate.getTime())) {
      const itemMs = itemDate.getTime();
      const bucket = buckets.find(b => Math.abs(b.at.getTime() - itemMs) <= 3600000);
      if (bucket) {
        if (item.critical !== undefined || item.high !== undefined) {
          bucket.critical += Number(item.critical || 0);
          bucket.high += Number(item.high || 0);
          bucket.investigated += Number(item.investigated || 0);
          bucket.mitigated += Number(item.mitigated || 0);
        } else {
          const sev = (item.severity || '').toLowerCase();
          const stat = (item.status || '').toLowerCase();
          if (sev === 'critical') bucket.critical += 1;
          if (sev === 'high') bucket.high += 1;
          if (['investigating', 'resolved', 'under_observation'].includes(stat)) bucket.investigated += 1;
          if (stat === 'resolved') bucket.mitigated += 1;
        }
      }
    } else if (typeof item._id === 'number' && item._id >= 0 && item._id <= 23) {
      const curHour = hour.getHours();
      const diff = (curHour - item._id + 24) % 24;
      const bIdx = 23 - diff;
      if (bIdx >= 0 && bIdx < 24) {
        buckets[bIdx].critical += Number(item.critical || item.count || 0);
        buckets[bIdx].high += Number(item.high || 0);
        buckets[bIdx].investigated += Number(item.investigated || item.count || 0);
        buckets[bIdx].mitigated += Number(item.mitigated || 0);
      }
    }
  });

  let totals = buckets.reduce((sum, row) => ({
    critical: sum.critical + row.critical,
    high: sum.high + row.high,
    investigated: sum.investigated + row.investigated,
    mitigated: sum.mitigated + row.mitigated,
  }), { critical: 0, high: 0, investigated: 0, mitigated: 0 });

  if (totals.critical === 0 && totals.high === 0 && totals.investigated === 0 && Array.isArray(alerts) && alerts.length > 0) {
    const rawCrit = alerts.filter(a => (a.severity || '').toLowerCase() === 'critical').length;
    const rawHigh = alerts.filter(a => (a.severity || '').toLowerCase() === 'high').length;
    const rawInvestigated = alerts.filter(a => ['investigating', 'resolved', 'under_observation'].includes((a.status || '').toLowerCase())).length;
    const rawMitigated = alerts.filter(a => (a.status || '').toLowerCase() === 'resolved').length;

    totals = {
      critical: rawCrit,
      high: rawHigh,
      investigated: rawInvestigated,
      mitigated: rawMitigated,
    };
  }

  const maxVal = Math.max(
    ...buckets.flatMap(row => [row.critical || 0, row.high || 0, row.investigated || 0]),
    10
  );

  const getPointsArr = (field) => buckets.map((row, index) => {
    const x = 20 + ((index / 23) * 680);
    const val = Number(row[field] || 0);
    const y = 175 - ((val / maxVal) * 135);
    return { x, y, val, row };
  });

  const investigatedArr = getPointsArr('investigated');
  const highArr = getPointsArr('high');
  const criticalArr = getPointsArr('critical');

  const investigatedPath = catmullRom2bezier(investigatedArr);
  const highPath = catmullRom2bezier(highArr);
  const criticalPath = catmullRom2bezier(criticalArr);

  const investigatedArea = investigatedPath ? `${investigatedPath} L 700 185 L 20 185 Z` : '';

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

function SmallMetric({ label, value, sub, color = '#38bdf8' }) {
  return (
    <div style={{
      border: `1px solid ${color}32`,
      borderRadius: 14,
      background: `linear-gradient(145deg, ${color}12, rgba(8,18,34,.76))`,
      padding: 14,
      minHeight: 92,
    }}>
      <div style={{ color: '#94a3b8', fontSize: 10, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>{label}</div>
      <div style={{ color, fontSize: 24, fontWeight: 950, marginTop: 6, lineHeight: 1 }}>{value}</div>
      {sub && <div style={{ color: '#9fb0c6', fontSize: 11, marginTop: 6, lineHeight: 1.35 }}>{sub}</div>}
    </div>
  );
}

function SummaryCard({ title, value, subtitle, icon, color, trend }) {
  return (
    <div
      style={{
        minHeight: 168,
        padding: 20,
        border: `1px solid ${color}38`,
        borderRadius: 18,
        background: `radial-gradient(circle at top right, ${color}18, transparent 46%), linear-gradient(145deg, rgba(12,26,46,.98), rgba(7,16,31,.94))`,
        color: '#e2e8f0',
        textAlign: 'left',
        cursor: 'default',
        boxShadow: '0 18px 42px rgba(0,0,0,.24), inset 0 1px 0 rgba(255,255,255,.04)',
        fontFamily: 'inherit',
        position: 'relative',
        overflow: 'hidden',
        width: '100%'
      }}
    >
      <span style={{ position: 'absolute', inset: 'auto 0 0 0', height: 3, background: `linear-gradient(90deg, transparent, ${color}, transparent)`, opacity: .75 }} />
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'flex-start' }}>
        <div>
          <div style={{ color: '#8fa4bd', fontSize: 11, fontWeight: 950, letterSpacing: '.08em', textTransform: 'uppercase' }}>{title}</div>
          <div style={{ marginTop: 14, color, fontSize: 32, fontWeight: 950, lineHeight: 1 }}>{value}</div>
        </div>
        <div style={{ width: 44, height: 44, borderRadius: 14, display: 'grid', placeItems: 'center', background: `${color}18`, border: `1px solid ${color}44`, fontSize: 22 }}>
          {icon}
        </div>
      </div>
      <div style={{ marginTop: 14, color: '#9fb0c6', fontSize: 12, lineHeight: 1.45 }}>{subtitle}</div>
      {trend && <div style={{ marginTop: 10, color: trend.color || color, fontSize: 11, fontWeight: 900 }}>{trend.text}</div>}
    </div>
  );
}

function PortalMetricCard({ item }) {
  const values = (item.chart || []).map(value => Math.max(0, Number(value || 0)));
  const chartMax = Math.max(...values, 1);
  return (
    <div
      style={{
        minHeight: 210,
        padding: 18,
        border: `1px solid ${item.color}45`,
        borderRadius: 17,
        background: `radial-gradient(circle at 88% 2%, ${item.color}1c, transparent 40%), linear-gradient(155deg, rgba(10,25,44,.98), rgba(5,14,28,.97))`,
        boxShadow: `0 16px 36px rgba(0,0,0,.25), inset 0 1px 0 ${item.color}18`,
        color: '#e2e8f0',
        cursor: 'default',
        textAlign: 'left',
        position: 'relative',
        overflow: 'hidden',
        fontFamily: 'inherit',
        width: '100%'
      }}
    >
      <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
        <span style={{ width: 42, height: 42, borderRadius: 13, display: 'grid', placeItems: 'center', background: `${item.color}18`, border: `1px solid ${item.color}45`, fontSize: 20 }}>{item.icon}</span>
        <span style={{ color: item.color, fontSize: 12, fontWeight: 950 }}>LIVE DATA</span>
      </span>
      <span style={{ display: 'block', marginTop: 12, color: '#f8fafc', fontSize: 15, fontWeight: 900 }}>{item.title}</span>
      <span style={{ display: 'block', marginTop: 6, color: item.color, fontSize: 26, fontWeight: 950, lineHeight: 1 }}>{item.value}</span>
      <span style={{ display: 'block', marginTop: 6, color: '#94a3b8', fontSize: 11, lineHeight: 1.4, minHeight: 30 }}>{item.subtitle}</span>
      <span aria-hidden="true" style={{ height: 36, display: 'flex', alignItems: 'end', gap: 5, marginTop: 12, paddingTop: 5, borderTop: '1px solid rgba(148,163,184,.12)' }}>
        {values.map((value, index) => (
          <span key={`${item.title}-${index}`} style={{ flex: 1, minWidth: 5, height: `${Math.max(12, Math.round((value / chartMax) * 100))}%`, borderRadius: '4px 4px 1px 1px', background: `linear-gradient(180deg, ${item.color}, ${item.color}55)`, boxShadow: `0 0 10px ${item.color}28` }} />
        ))}
      </span>
      <span style={{ display: 'block', marginTop: 6, color: '#526984', fontSize: 9, fontWeight: 800, letterSpacing: '.08em' }}>SUPERADMIN LIVE READ-ONLY</span>
    </div>
  );
}

function DashboardPortalSection({ title, eyebrow, items, color }) {
  return (
    <section style={{ border: `1px solid ${color}2f`, borderRadius: 20, padding: 19, background: 'linear-gradient(145deg,rgba(6,15,28,.95),rgba(8,20,36,.86))', boxShadow: '0 18px 42px rgba(0,0,0,.20)', marginBottom: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'end', marginBottom: 16 }}>
        <div>
          <div style={{ color, fontSize: 10, fontWeight: 950, letterSpacing: '.12em', textTransform: 'uppercase' }}>{eyebrow}</div>
          <h2 style={{ color: '#f8fafc', fontSize: 20, margin: '5px 0 0' }}>{title}</h2>
        </div>
        <div style={{ color: '#64748b', fontSize: 11 }}>{items.length} live modules</div>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(210px,1fr))', gap: 13 }}>
        {items.map(item => <PortalMetricCard key={item.title} item={item} />)}
      </div>
    </section>
  );
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
      onClick={() => onOpen(cap)}
      style={{
        background: 'linear-gradient(135deg, rgba(12,26,46,.86) 0%, rgba(15,21,53,.64) 100%)',
        border: `1px solid ${color}44`,
        borderRadius: 16,
        padding: '20px 22px',
        minHeight: 380,
        width: '100%',
        cursor: 'pointer',
        overflow: 'hidden',
        position: 'relative',
        boxShadow: 'inset 0 1px 0 rgba(255,255,255,.05), 0 4px 16px rgba(0,0,0,.3)',
        outline: 'none',
        display: 'flex',
        flexDirection: 'column',
        justifyContent: 'space-between',
        textAlign: 'left',
        fontFamily: 'inherit',
        transition: 'all 0.2s ease-in-out'
      }}
      onMouseEnter={e => {
        e.currentTarget.style.transform = 'translateY(-3px)';
        e.currentTarget.style.borderColor = color;
      }}
      onMouseLeave={e => {
        e.currentTarget.style.transform = 'translateY(0)';
        e.currentTarget.style.borderColor = `${color}44`;
      }}
    >
      <span>
        <span style={{ position: 'absolute', top: 0, right: 0, width: 170, height: 170, background: `radial-gradient(circle, ${color}14 0%, transparent 70%)`, pointerEvents: 'none' }} />
        <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, position: 'relative', zIndex: 1 }}>
          <span style={{ display: 'flex', gap: 10, alignItems: 'center', minWidth: 0 }}>
            <span style={{ width: 42, height: 42, borderRadius: 12, display: 'grid', placeItems: 'center', background: `${color}16`, border: `1px solid ${color}55`, color, fontSize: 20, fontWeight: 900 }}>
              {cap.icon || '▱'}
            </span>
            <span style={{ width: 28, height: 28, borderRadius: 8, display: 'grid', placeItems: 'center', background: `${color}20`, color, border: `1px solid ${color}44`, fontSize: 12, fontWeight: 900 }}>
              {id}
            </span>
          </span>
          <span style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <span style={{ color: '#60a5fa', fontSize: 12, fontWeight: 900 }}>👁️ Details</span>
            <span style={{ fontSize: 10, padding: '4px 8px', borderRadius: 8, fontWeight: 900, background: `${color}18`, color, border: `1px solid ${color}55` }}>
              {label}
            </span>
          </span>
        </span>

        <span style={{ display: 'block', marginTop: 20, color: '#7dd3fc', fontSize: 10, fontWeight: 900, letterSpacing: 1.2, position: 'relative', zIndex: 1 }}>
          LAST 24H LOG COUNT
        </span>
        <span style={{ display: 'block', marginTop: 4, color: '#e5edf7', fontSize: 32, fontWeight: 950, lineHeight: 1, position: 'relative', zIndex: 1 }}>
          {metrics.total.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: '#60a5fa', fontSize: 15, fontWeight: 900, marginTop: 12, lineHeight: 1.25, position: 'relative', zIndex: 1 }}>
          {name}
        </span>
        <span style={{ display: 'block', color: '#93c5fd', fontSize: 11, lineHeight: 1.45, marginTop: 10, position: 'relative', zIndex: 1 }}>
          High/Critical: {metrics.suspicious.toLocaleString()} · Unauthorized: {metrics.unauthorized.toLocaleString()}
        </span>
        {points ? (
          <svg aria-label="Real logs by hour for the last 24 hours" width="150" height="42" viewBox="0 0 150 42" style={{ display: 'block', marginTop: 14, position: 'relative', zIndex: 1 }}>
            <polyline points={points} fill="none" stroke="#3b82f6" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <span style={{ display: 'block', height: 42, marginTop: 14, color: '#64748b', fontSize: 10, lineHeight: '42px' }}>No live logs in 24h window</span>
        )}
      </span>

      <span style={{ position: 'relative', zIndex: 1, marginTop: 12 }}>
        <span style={{ display: 'block', color: '#7dd3fc', fontSize: 11, lineHeight: 1.5, marginBottom: 4 }}>
          Reporting agents: {metrics.activeAgents.toLocaleString()} · Missing: {metrics.missing.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: metrics.trendPct >= 0 ? '#34d399' : '#f87171', fontSize: 11, fontWeight: 900, marginBottom: 8 }}>
          {metrics.trendPct >= 0 ? '↑' : '↓'} {Math.abs(metrics.trendPct)}% vs previous 24h
        </span>
        <span style={{ display: 'block', color: '#38bdf8', fontSize: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          Category: {category.toUpperCase()} · {source}
        </span>
      </span>
    </button>
  );
}

export default function CompanyDetail({ companyIdOverride, initialCompanyData, hideBackButton = false }) {
  const params = useParams();
  const companyId = companyIdOverride || params.companyId;
  const [company, setCompany] = useState(initialCompanyData || null);
  const [summaryData, setSummaryData] = useState(null);
  const [depts, setDepts] = useState([]);
  const [users, setUsers] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [systems, setSystems] = useState([]);
  const [loading, setLoading] = useState(!initialCompanyData);
  const [error, setError] = useState('');
  const [impersonating, setImpersonating] = useState(false);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [liveConnected, setLiveConnected] = useState(false);
  const [sourceWarnings, setSourceWarnings] = useState([]);
  const [capabilityWarning, setCapabilityWarning] = useState('');
  const [capabilitySummary, setCapabilitySummary] = useState(null);
  const refreshInFlightRef = useRef(false);
  const capabilityRefreshInFlightRef = useRef(false);

  const loadData = (silent = false) => {
    if (refreshInFlightRef.current) return;
    if (!companyId) {
      setLoading(false);
      return;
    }
    refreshInFlightRef.current = true;
    if (!silent && !company) setLoading(true);
    setError('');
    const liveConfig = silent ? { headers: { 'x-skip-server-cache': '1' } } : undefined;
    const overviewRequest = api.get(`/company/overview?companyId=${companyId}`, liveConfig)
      .catch(() => api.get(`/dashboard/company/${companyId}/overview`, liveConfig));

    Promise.all([
      api.get(`/superadmin/companies/${companyId}`).catch(err => ({ error: err.response?.data?.message || 'Failed to load company profile', data: null })),
      api.get(`/superadmin/companies/${companyId}/departments`).catch(() => ({ data: [] })),
      api.get(`/superadmin/companies/${companyId}/users`).catch(() => ({ data: [] })),
      api.get(`/superadmin/companies/${companyId}/alerts`).catch(() => ({ data: { alerts: [] } })),
      api.get(`/superadmin/companies/${companyId}/systems`).catch(() => ({ data: [] })),
      overviewRequest.catch(err => ({ error: err.response?.data?.message || 'Live overview is unavailable', data: null })),
    ])
      .then(([compRes, deptRes, userRes, alertRes, sysRes, dashRes]) => {
        if (compRes?.data) {
          setCompany(compRes.data);
        } else if (!company && !initialCompanyData) {
          setCompany({ _id: companyId, name: 'Company Overview', status: 'active' });
        }
        setDepts(deptRes?.data || []);
        setUsers(userRes?.data || []);
        setAlerts(alertRes?.data?.alerts || alertRes?.data || []);
        setSystems(sysRes?.data || []);
        if (dashRes?.data) setSummaryData(dashRes.data);
        const liveSources = dashRes?.data?.stats?.sources || dashRes?.data?.sources || {};
        const warnings = [...(liveSources.warnings || [])];
        if (dashRes?.error) warnings.push(dashRes.error);
        setSourceWarnings(warnings);
        const updatedAt = liveSources.updatedAt;
        if (updatedAt) setLastUpdated(updatedAt);
        if (dashRes?.error && !summaryData) setError(dashRes.error);
      })
      .catch(err => {
        console.error('Error loading company data:', err);
        if (!silent) setError(err.response?.data?.message || 'Company live dashboard could not be loaded');
      })
      .finally(() => {
        setLoading(false);
        refreshInFlightRef.current = false;
      });
  };

  const loadCapabilities = (silent = false) => {
    if (!companyId || capabilityRefreshInFlightRef.current) return;
    capabilityRefreshInFlightRef.current = true;
    const config = silent ? { headers: { 'x-skip-server-cache': '1' } } : undefined;
    api.get(`/edr-cap/live-overview?companyId=${companyId}${silent ? '&fresh=1' : ''}`, config)
      .then(response => {
        setCapabilitySummary(response.data.liveSummary || null);
        setCapabilityWarning(response.data.partial ? (response.data.warning || 'EDR capability telemetry is partial') : '');
      })
      .catch(err => {
        setCapabilityWarning(err.response?.data?.message || 'EDR capability telemetry is unavailable');
      })
      .finally(() => { capabilityRefreshInFlightRef.current = false; });
  };

  useEffect(() => {
    if (!companyId) return;
    loadData(false);
    loadCapabilities(false);
  }, [companyId]);

  useEffect(() => {
    if (!companyId) return;
    const socket = io(SOCKET_URL);
    const handleConnect = () => {
      setLiveConnected(true);
      socket.emit('join:company', companyId);
    };
    const handleDisconnect = () => setLiveConnected(false);
    socket.emit('join:superadmin');
    socket.emit('join:company', companyId);

    const handleUpdate = payload => {
      if (payload?.companyId && String(payload.companyId) !== String(companyId)) return;
      loadData(true);
    };

    socket.on('connect', handleConnect);
    socket.on('disconnect', handleDisconnect);
    socket.on('company:update', handleUpdate);
    socket.on('department:update', handleUpdate);
    socket.on('user:update', handleUpdate);
    socket.on('alert:new', handleUpdate);
    socket.on('activity:new', handleUpdate);
    if (socket.connected) setLiveConnected(true);

    const pollingTimer = window.setInterval(() => {
      if (!document.hidden) loadData(true);
    }, 15000);
    const capabilityPollingTimer = window.setInterval(() => {
      if (!document.hidden) loadCapabilities(true);
    }, 60000);

    const disconnectSocket = connectSocket(socket);
    return () => {
      window.clearInterval(pollingTimer);
      window.clearInterval(capabilityPollingTimer);
      socket.off('connect', handleConnect);
      socket.off('disconnect', handleDisconnect);
      socket.off('company:update', handleUpdate);
      socket.off('department:update', handleUpdate);
      socket.off('user:update', handleUpdate);
      socket.off('alert:new', handleUpdate);
      socket.off('activity:new', handleUpdate);
      disconnectSocket();
    };
  }, [companyId]);

  const toggleStatus = async () => {
    const currentComp = company || initialCompanyData;
    if (!currentComp) return;
    const newStatus = currentComp.status === 'active' ? 'suspended' : 'active';
    const { data } = await api.patch(`/superadmin/companies/${companyId}`, { status: newStatus });
    setCompany(data);
  };

  const handleLoginAsCompanyAdmin = async (e) => {
    e?.stopPropagation?.();
    const newWindow = window.open('about:blank', '_blank');
    try {
      setImpersonating(true);
      const { data } = await api.post(`/superadmin/companies/${companyId}/impersonate`);
      const targetUrl = data.redirectUrl || `http://localhost:3000/?impersonationToken=${data.token}`;
      if (newWindow) {
        newWindow.location.href = targetUrl;
      } else {
        window.location.href = targetUrl;
      }
    } catch (err) {
      if (newWindow) newWindow.close();
      console.error('Error logging in as company admin:', err);
      alert(err.response?.data?.message || 'Failed to login as company admin');
    } finally {
      setImpersonating(false);
    }
  };

  const displayCompany = company || initialCompanyData || { name: 'Company Overview', email: '—', status: 'active', plan: { type: 'basic', systemCount: 20 } };

  if (loading && !displayCompany) return <div style={{ padding: 30, color: '#38bdf8', fontWeight: 800 }}>⚡ Loading company telemetry...</div>;
  if (error && !displayCompany) return <div style={{ padding: 30, color: '#f87171', fontWeight: 700 }}>{error}</div>;

  // Unpack real backend overview structure from /api/dashboard/company/:companyId/overview
  const stats = summaryData?.stats || summaryData || {};
  const sources = stats.sources || summaryData?.sources || {};
  const edr = sources.edr || summaryData?.edr || {};
  const ids = sources.ids || summaryData?.ids || {};
  const ips = sources.ips || summaryData?.ips || {};
  const firewall = sources.firewall || summaryData?.firewall || {};
  const systemsObj = sources.systems || summaryData?.systems || {};
  const overview = stats || summaryData?.companyOverview || {};
  const incidents = stats.incidents || overview.incidents || summaryData?.incidents || {};
  const soar = stats.soar || overview.soar || summaryData?.soar || {};
  const soar24h = soar.last24h || {};
  const soarPlaybooks = soar.playbooks || {};
  const tickets = stats.supportTickets || overview.supportTickets || summaryData?.supportTickets || {};
  const forensics = stats.forensics || overview.forensics || summaryData?.forensics || {};
  const alertActivity = sources.alertActivity || summaryData?.alertActivity || [];
  const allSourceWarnings = [...sourceWarnings, ...(capabilityWarning ? [capabilityWarning] : [])];
  const sourcesDegraded = Boolean(sources.degraded || allSourceWarnings.length);

  const fmt = val => Number(val ?? 0).toLocaleString();
  const sysTotal = Number(systemsObj.total ?? stats.systemsUsed ?? systems.length ?? 0);
  const sysOnline = Number(systemsObj.online ?? stats.systemsOnline ?? systems.filter(s => s.status === 'active' || s.status === 'online').length ?? 0);
  const sysOffline = Number(systemsObj.offline ?? stats.systemsOffline ?? Math.max(0, sysTotal - sysOnline));
  const userCount = Number(stats.users ?? overview.users ?? users.length ?? 0);
  const analystCount = Number(stats.analysts ?? 0);
  const teamCount = userCount + analystCount;
  const deptsCount = Number(stats.departments ?? overview.departments ?? depts.length ?? 0);
  const totalSecurityEvents = Number(edr.logs ?? 0) + Number(ids.total ?? ids.totalAlerts ?? 0);
  const idsHigh = Number(ids.high ?? ids.severity?.high ?? 0);
  const idsCritical = Number(ids.critical ?? ids.severity?.critical ?? 0);
  const priorityEvents = Number(edr.highCritical ?? 0) + idsHigh + idsCritical;

  const edrTotalCapabilities = Number(capabilitySummary?.total ?? edr.totalCapabilities ?? CANONICAL_EDR_CARDS.length);
  const edrReportingCapabilities = Number(capabilitySummary?.reporting ?? edr.activeCapabilities ?? 0);
  const totalControls = edrTotalCapabilities + Number(firewall.totalRules ?? 0);
  const activeControls = edrReportingCapabilities + Number(firewall.enabledRules ?? 0);
  const posture = Math.max(0, Math.min(100, Math.round((activeControls / Math.max(totalControls, 1)) * 100)));
  const postureColor = posture >= 80 ? '#34d399' : posture >= 55 ? '#f59e0b' : '#f87171';
  const planActive = overview.planActive ?? displayCompany.plan?.isActive ?? displayCompany.status === 'active';
  const systemLimit = Number(overview.systemLimit ?? displayCompany.plan?.systemLimit ?? displayCompany.plan?.systemCount ?? 0);
  const systemsRemaining = Number(overview.systemsRemaining ?? Math.max(0, systemLimit - sysTotal));
  const hasLiveData = Boolean(summaryData);

  const setupCards = [
    { icon: '🏢', title: 'Departments', color: '#60a5fa', value: fmt(deptsCount), subtitle: 'Configured business units', chart: [deptsCount, userCount, sysTotal] },
    { icon: '🖥', title: 'Systems', color: '#38bdf8', value: `${fmt(sysOnline)}/${fmt(sysTotal)}`, subtitle: `${fmt(sysOffline)} offline or stale endpoints`, chart: [sysOnline, sysOffline, sysTotal] },
    { icon: '⬇', title: 'Download Agent', color: '#a78bfa', value: fmt(sysTotal), subtitle: 'Installed/registered endpoint agents', chart: [sysTotal, sysOnline, systemLimit] },
    { icon: '👥', title: 'Team', color: '#34d399', value: fmt(teamCount), subtitle: `${fmt(userCount)} managers · ${fmt(analystCount)} analysts`, chart: [userCount, analystCount, teamCount] },
    { icon: '💳', title: 'Payments', color: '#f59e0b', value: planActive ? 'ACTIVE' : 'INACTIVE', subtitle: `${String(overview.planType ?? displayCompany.plan?.type ?? 'custom').toUpperCase()} · ${fmt(systemLimit)} endpoint capacity`, chart: [sysTotal, systemsRemaining, systemLimit] },
    { icon: '⚙', title: 'Settings', color: '#94a3b8', value: `${posture}%`, subtitle: 'Company profile and security posture', chart: [posture, activeControls, totalControls] },
  ];

  const monitoringCards = [
    { icon: '🏬', title: 'Department Monitoring', color: '#818cf8', value: fmt(deptsCount), subtitle: `${fmt(sysOnline)} online assets across departments`, chart: [deptsCount, sysOnline, sysTotal] },
    { icon: '📊', title: 'System Monitoring', color: '#34d399', value: `${fmt(sysOnline)} Online`, subtitle: `${fmt(sysTotal)} total monitored assets`, chart: [sysOnline, sysOffline, sysTotal] },
    { icon: '📡', title: 'SIEM', color: '#60a5fa', value: fmt(totalSecurityEvents), subtitle: 'EDR + IDS events in the rolling 24h window', chart: [edr.logs ?? 0, ids.total ?? ids.totalAlerts ?? 0, priorityEvents] },
    { icon: '📈', title: 'Log Monitor', color: '#38bdf8', value: fmt(totalSecurityEvents), subtitle: 'Centralized security events available', chart: [totalSecurityEvents, priorityEvents] },
    { icon: '📊', title: 'Security Score', color: '#22c55e', value: `${posture}%`, subtitle: `${fmt(activeControls)} of ${fmt(totalControls)} controls active`, chart: [posture, activeControls, totalControls] },
    { icon: '📄', title: 'Reports', color: '#94a3b8', value: fmt(incidents.total ?? 0), subtitle: `${fmt(incidents.solved ?? 0)} resolved incidents ready for reporting`, chart: [incidents.open ?? 0, incidents.solved ?? 0, incidents.total ?? 0] },
    { icon: '🎟', title: 'SOAR Tickets', color: '#facc15', value: fmt(soar24h.tickets || 0), subtitle: 'Ticket-linked SOAR executions · Last 24h', chart: [soar24h.tickets || 0, soar24h.completed || 0, soar24h.pending || 0] },
    { icon: '⏳', title: 'SOAR Pending', color: '#fb923c', value: fmt(soar24h.pending || 0), subtitle: `${fmt(soar24h.completed || 0)} completed · ${fmt(soar24h.failed || 0)} failed in 24h`, chart: [soar24h.pending || 0, soar24h.completed || 0, soar24h.failed || 0] },
    { icon: '🤖', title: 'SOAR AI Analysis', color: '#a78bfa', value: fmt(soar24h.aiAnalyzed || 0), subtitle: 'AI-analyzed SOAR executions · Last 24h', chart: [soar24h.aiAnalyzed || 0, soar24h.total || 0, soar24h.completed || 0] },
    { icon: '✅', title: 'Enabled Playbooks', color: '#34d399', value: fmt(soarPlaybooks.enabled || 0), subtitle: `${fmt(soarPlaybooks.total || 0)} total SOAR playbooks`, chart: [soarPlaybooks.enabled || 0, soarPlaybooks.disabled || 0, soarPlaybooks.total || 0] },
    { icon: '⚙', title: 'Automatic Playbooks', color: '#22d3ee', value: fmt(soarPlaybooks.automatic || 0), subtitle: 'Automatic execution mode', chart: [soarPlaybooks.automatic || 0, soarPlaybooks.total || 0] },
    { icon: '✋', title: 'Approval Required', color: '#facc15', value: fmt(soarPlaybooks.approvalRequired || 0), subtitle: 'Human approval gateway playbooks', chart: [soarPlaybooks.approvalRequired || 0, soarPlaybooks.total || 0] },
    { icon: '👤', title: 'Manual Only Playbooks', color: '#c084fc', value: fmt(soarPlaybooks.manualOnly || 0), subtitle: 'Analyst-triggered playbooks only', chart: [soarPlaybooks.manualOnly || 0, soarPlaybooks.total || 0] },
    { icon: '⛔', title: 'Disabled Playbooks', color: '#f87171', value: fmt(soarPlaybooks.modeDisabled || 0), subtitle: `${fmt(soarPlaybooks.disabled || 0)} playbooks disabled by toggle`, chart: [soarPlaybooks.modeDisabled || 0, soarPlaybooks.disabled || 0, soarPlaybooks.total || 0] },
  ];

  return (
    <div style={{ padding: '8px 20px 24px 20px', color: '#dbeafe' }}>
      {/* Superadmin Quick Header Bar */}
      <div style={{ ...topBar, marginBottom: 20 }}>
        <div>
          {!hideBackButton && (
            <Link to="/superadmin/companies" style={{ textDecoration: 'none' }}>
              <button type="button" style={backButton}>← Back to Companies Grid</button>
            </Link>
          )}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
            <h2 style={{ ...pageTitle, margin: 0 }}>🏢 {displayCompany.name}</h2>
            <span style={{ color: '#334155' }}>|</span>
            <div style={{ ...metaLine, margin: 0, display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span>✉️ {displayCompany.email}</span>
              <span>•</span>
              <span>Plan: <b style={{ color: '#c4b5fd' }}>{displayCompany.plan?.type || 'CUSTOM'}</b> (Limit: {displayCompany.plan?.systemLimit ?? displayCompany.plan?.systemCount ?? 0})</span>
              <span>•</span>
              <span>Status: <b style={{ color: displayCompany.status === 'active' ? '#34d399' : '#ef4444' }}>{(displayCompany.status || 'active').toUpperCase()}</b></span>
              <span>•</span>
              <span>Registered: {displayCompany.createdAt ? new Date(displayCompany.createdAt).toLocaleDateString() : '—'}</span>
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <button
            type="button"
            onClick={toggleStatus}
            style={displayCompany.status === 'active' ? dangerOutline : { ...outlineButton, border: '1px solid #10b981', color: '#6ee7b7' }}
          >
            {displayCompany.status === 'active' ? '⏸️ Suspend Company' : '▶️ Activate Company'}
          </button>

          <button
            type="button"
            onClick={handleLoginAsCompanyAdmin}
            disabled={impersonating}
            style={{
              height: 36,
              padding: '0 16px',
              borderRadius: 8,
              background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
              border: '1px solid #34d399',
              color: '#ffffff',
              fontWeight: 800,
              fontSize: 12,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              boxShadow: '0 4px 12px rgba(16, 185, 129, 0.3)',
              opacity: impersonating ? 0.7 : 1
            }}
          >
            {impersonating ? '🔑 Logging in...' : '🔑 Login as Company Admin'}
          </button>
        </div>
      </div>

      {/* ── EXACT UI match from company/src/pages/DashboardPage.jsx (CompanyAdminSummaryDashboard) ── */}
      <div style={{ display: 'grid', gap: 18 }}>
        {/* Banner Section */}
        <section style={{
          padding: 24,
          border: '1px solid #1e3a5f',
          borderRadius: 22,
          background: 'radial-gradient(circle at 82% 18%, rgba(56,189,248,.20), transparent 32%), radial-gradient(circle at 16% 0%, rgba(124,58,237,.18), transparent 34%), linear-gradient(135deg,#071426,#101936)',
          boxShadow: '0 22px 54px rgba(0,0,0,.30)',
        }}>
          <div>
            <div style={{ marginBottom: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
                <div style={{ color: '#38bdf8', fontSize: 12, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>Company Admin Dashboard</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: liveConnected ? '#34d399' : '#f59e0b', fontSize: 10, fontWeight: 900 }}>
                  <span style={{ width: 7, height: 7, borderRadius: '50%', background: liveConnected ? '#34d399' : '#f59e0b', boxShadow: `0 0 9px ${liveConnected ? '#34d399' : '#f59e0b'}` }} />
                  {liveConnected ? 'LIVE SOCKET' : 'AUTO REFRESH 15s'}
                  {lastUpdated && <span style={{ color: '#64748b', fontWeight: 600 }}>· Updated {new Date(lastUpdated).toLocaleTimeString()}</span>}
                </div>
              </div>
              <h1 style={{ margin: '8px 0 0', fontSize: 'clamp(28px,4vw,42px)', color: '#f8fafc', letterSpacing: '-.04em' }}>Spartan Cyber Defense Center (SCDC)</h1>
              {allSourceWarnings.length > 0 && <div style={{ color: '#fbbf24', fontSize: 10, marginTop: 7 }}>Partial live data: {allSourceWarnings.join(', ')}</div>}
            </div>
            <CommandCenterChart activity={alertActivity} alerts={alerts} posture={posture} postureColor={postureColor} />
          </div>
        </section>

        {/* Small Metrics Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(180px,1fr))', gap: 12 }}>
          <SmallMetric label="Departments" value={fmt(deptsCount)} sub="Active business units" color="#22d3ee" />
          <SmallMetric label="Assets Used" value={`${fmt(sysOnline)}/${fmt(sysTotal)}`} sub={`${fmt(sysOffline)} offline or stale · ${fmt(systemsRemaining)} plan slots remaining`} color="#34d399" />
          <SmallMetric label="Open Alerts" value={fmt(overview.openAlerts ?? alerts.filter(a => a.status !== 'resolved').length)} sub={`${fmt(overview.criticalAlerts ?? alerts.filter(a => a.severity === 'critical').length)} critical open`} color="#f87171" />
          <SmallMetric label="Risk Score" value={fmt(overview.riskScore ?? 0)} sub={`Company status: ${displayCompany.status?.toUpperCase() || 'ACTIVE'}`} color="#f59e0b" />
          <SmallMetric label="Plan" value={String(overview.planType ?? displayCompany.plan?.type ?? 'custom').toUpperCase()} sub={planActive ? 'License active' : 'License inactive'} color={planActive ? '#34d399' : '#f87171'} />
        </div>

        {/* 12 Summary Cards Row */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(230px,1fr))', gap: 16 }}>
          <SummaryCard title="EDR Coverage" icon="🛡️" color="#38bdf8" value={`${fmt(edrReportingCapabilities)}/${fmt(edrTotalCapabilities)}`} subtitle={`${fmt(edr.logs ?? 0)} endpoint events · ${fmt(edr.highCritical ?? 0)} high/critical`} trend={{ text: `${fmt(edr.reportingAgents ?? 0)} reporting agents · rolling 24h`, color: '#7dd3fc' }} />
          <SummaryCard title="IDS / IPS" icon="📡" color="#22d3ee" value={fmt(ids.total ?? ids.totalAlerts ?? 0)} subtitle={`${fmt(idsHigh)} high · ${fmt(idsCritical)} critical · ${fmt(ips.activeBlocks ?? 0)} active blocks`} />
          <SummaryCard title="Firewall Controls" icon="🔥" color="#fb923c" value={fmt(firewall.enabledRules ?? 0)} subtitle={`${fmt(firewall.blockRules ?? 0)} block · ${fmt(firewall.pendingRules ?? 0)} pending · ${fmt(firewall.failedRules ?? 0)} failed`} />
          <SummaryCard title="Agents Online" icon="🟢" color="#34d399" value={`${fmt(sysOnline)}/${fmt(sysTotal)}`} subtitle={`${fmt(sysOffline)} offline or stale agents`} />
          <SummaryCard title="Priority Signals" icon="⚠️" color="#f87171" value={fmt(priorityEvents)} subtitle="Combined high-priority EDR + IDS/IPS workload" />
          <SummaryCard title="Total Incidents" icon="🚨" color="#f87171" value={fmt(incidents.total ?? 0)} subtitle={`${fmt(incidents.solved ?? 0)} solved · ${fmt(incidents.open ?? 0)} open`} />
          <SummaryCard title="EDR Correlation Incidents" icon="⇄" color="#60a5fa" value={fmt(incidents.edrCorrelation?.total || 0)} subtitle={`${fmt(incidents.edrCorrelation?.solved || 0)} solved · ${fmt(incidents.edrCorrelation?.open || 0)} open`} />
          <SummaryCard title="Threat Intel Incidents" icon="⌾" color="#c4b5fd" value={fmt(incidents.threatIntel?.total || 0)} subtitle={`${fmt(incidents.threatIntel?.solved || 0)} solved · ${fmt(incidents.threatIntel?.open || 0)} open`} />
          <SummaryCard title="Forensics" icon="🔬" color="#2dd4bf" value={fmt(forensics.hunts ?? 0)} subtitle={`${fmt(forensics.activeHunts ?? 0)} active hunts · ${fmt(forensics.evidence ?? 0)} evidence items`} />
          <SummaryCard title="SOAR Activity" icon="⚡" color="#a78bfa" value={fmt(soar.total ?? 0)} subtitle={`${fmt(soar.solved ?? 0)} completed · ${fmt(soar.open ?? 0)} running/pending · ${fmt(soar.failed ?? 0)} failed`} />
          <SummaryCard title="Support Tickets" icon="🎟" color="#facc15" value={fmt(tickets.total || 0)} subtitle={`${fmt(tickets.solved || 0)} solved · ${fmt(tickets.open || 0)} open`} />
          <SummaryCard
            title="Platform Health"
            icon="▦"
            color={!hasLiveData ? '#60a5fa' : sourcesDegraded ? '#f59e0b' : '#34d399'}
            value={!hasLiveData || loading ? 'SYNC' : (sourcesDegraded ? 'PARTIAL' : 'LIVE')}
            subtitle={!hasLiveData ? 'Loading company-scoped live sources' : sourcesDegraded ? 'One or more live sources timed out' : 'All dashboard sources returned real data'}
          />
        </div>

        {/* Portal Sections */}
        <DashboardPortalSection title="System Setup" eyebrow="Company Administration" items={setupCards} color="#38bdf8" />
        <DashboardPortalSection title="Monitoring" eyebrow="Live SOC Operations" items={monitoringCards} color="#34d399" />
      </div>

    </div>
  );
}

const topBar = { display: 'flex', justifyContent: 'space-between', gap: 18, alignItems: 'center' };
const backButton = { border: 'none', background: 'transparent', color: '#38bdf8', fontSize: 12, fontWeight: 800, cursor: 'pointer', padding: 0, marginBottom: 8 };
const pageTitle = { fontSize: 24, color: '#f8fafc', margin: '0 0 5px', fontWeight: 900 };
const metaLine = { display: 'flex', gap: 8, flexWrap: 'wrap', color: '#94a3b8', fontSize: 12, marginTop: 3 };
const outlineButton = { height: 36, border: '1px solid #1e3a5f', borderRadius: 8, background: '#07111f', color: '#f1f5f9', padding: '0 14px', fontWeight: 800, cursor: 'pointer' };
const dangerOutline = { ...outlineButton, border: '1px solid #ef4444', color: '#f87171' };
