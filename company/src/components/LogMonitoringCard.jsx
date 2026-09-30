import { useState, useEffect, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';

// ── palette (matches DashboardPage) ──────────────────────────────────────────
const SEV = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };

/**
 * LogMonitoringCard — reusable informational + status card.
 * Shows the built-in SOC log monitor, live alert counts, and CTA button.
 * Works for ALL roles: superadmin, company_admin, department_admin, analyst.
 *
 * Props:
 *   basePath  — route prefix where log-monitor page lives (default '/')
 *   apiBase   — optional override for API base path
 */
export default function LogMonitoringCard({ basePath = '/', apiBase = '' }) {
  const navigate  = useNavigate();
  const [stats,   setStats]   = useState(null);
  const [loading, setLoading] = useState(true);
  const timerRef  = useRef(null);

  const fetchStats = async () => {
    try {
      const r = await api.get(`/log-monitor/stats?hours=24`);
      setStats(r.data);
    } catch {
      // silently fail — card still useful as informational
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
    // poll every 30 s for live updates
    timerRef.current = setInterval(fetchStats, 30000);
    return () => clearInterval(timerRef.current);
  }, []);

  const tools = [
    {
      id: 'soc-log-monitor',
      name: 'SOC Log Monitor',
      icon: '📋',
      color: '#60a5fa',
      colorBg: 'rgba(96,165,250,.13)',
      colorBorder: 'rgba(96,165,250,.35)',
      badge: 'Built-in · Centralized',
      features: [
        '📥  Multi-source log ingestion',
        '🔎  Centralized log search and filtering',
        '🔔  Real-time monitoring and alerts',
      ],
    },
  ];

  const [expanded, setExpanded] = useState(null);

  const alertBadge = stats?.suspiciousCount > 0 ? stats.suspiciousCount : null;

  return (
    <div
      style={{
        background: '#0c1a2e',
        border: '1px solid #1e3a5f',
        borderRadius: 12,
        padding: '16px 18px',
        flex: '1',
        minWidth: 270,
        maxWidth: 420,
        position: 'relative',
        overflow: 'hidden',
        display: 'flex',
        flexDirection: 'column',
        gap: 12,
        transition: 'box-shadow .2s',
      }}
      onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 0 0 1px #1e40af')}
      onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
    >
      {/* Top gradient bar */}
      <div style={{
        position: 'absolute', top: 0, left: 0, right: 0, height: 3,
        background: 'linear-gradient(90deg, #f59e0b 0%, #3b82f6 55%, #60a5fa 100%)',
        borderRadius: '12px 12px 0 0',
      }} />

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 20 }}>📋</span>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: '#e2e8f0' }}>Log Monitoring Tools</div>
            <div style={{ fontSize: 10, color: '#1e40af', marginTop: 1 }}>Built-in SOC monitoring</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
          {alertBadge && (
            <span style={{
              fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
              background: 'rgba(239,68,68,.18)', color: '#f87171',
              border: '1px solid rgba(239,68,68,.35)',
              animation: 'pulse 2s infinite',
            }}>
              🚨 {alertBadge} alerts
            </span>
          )}
          <span style={{
            fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
            background: 'rgba(96,165,250,.15)', color: '#60a5fa',
            border: '1px solid rgba(96,165,250,.3)',
          }}>OVERVIEW</span>
        </div>
      </div>

      {/* ── Live stat strip ── */}
      {!loading && stats && (
        <div style={{
          display: 'flex', gap: 8, flexWrap: 'wrap',
          background: '#060e1a', borderRadius: 8, padding: '8px 12px',
          border: '1px solid #1e3a5f',
        }}>
          {[
            { label: 'Total (24h)', val: stats.total, color: '#93c5fd' },
            { label: 'Critical',    val: stats.severity?.critical, color: SEV.critical },
            { label: 'High',        val: stats.severity?.high,     color: SEV.high },
            { label: 'Failed logins', val: stats.failedLogins,     color: '#f59e0b' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ flex: '1 0 auto', textAlign: 'center', minWidth: 60 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color }}>{val ?? '–'}</div>
              <div style={{ fontSize: 9, color: '#475569' }}>{label}</div>
            </div>
          ))}
        </div>
      )}
      {loading && (
        <div style={{ background: '#060e1a', borderRadius: 8, padding: '10px 12px',
                      border: '1px solid #1e3a5f', fontSize: 11, color: '#1e40af' }}>
          Loading live stats…
        </div>
      )}

      {/* ── Tool rows ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {tools.map(tool => (
          <div
            key={tool.id}
            onClick={() => setExpanded(expanded === tool.id ? null : tool.id)}
            style={{
              background: expanded === tool.id ? tool.colorBg : 'rgba(255,255,255,.025)',
              border: `1px solid ${expanded === tool.id ? tool.colorBorder : '#1e3a5f'}`,
              borderRadius: 8, padding: '9px 12px', cursor: 'pointer',
              transition: 'background .18s, border-color .18s',
            }}
            onMouseEnter={e => {
              if (expanded !== tool.id) {
                e.currentTarget.style.borderColor = tool.colorBorder;
                e.currentTarget.style.background   = 'rgba(255,255,255,.04)';
              }
            }}
            onMouseLeave={e => {
              if (expanded !== tool.id) {
                e.currentTarget.style.borderColor = '#1e3a5f';
                e.currentTarget.style.background   = 'rgba(255,255,255,.025)';
              }
            }}
          >
            {/* Tool header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  fontSize: 15, width: 28, height: 28, borderRadius: 7,
                  background: tool.colorBg, border: `1px solid ${tool.colorBorder}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>{tool.icon}</span>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: '#e2e8f0' }}>{tool.name}</div>
                  <div style={{ fontSize: 9, color: tool.color }}>{tool.badge}</div>
                </div>
              </div>
              <span style={{
                fontSize: 13, color: '#1e40af',
                transform: expanded === tool.id ? 'rotate(180deg)' : 'none',
                display: 'inline-block', transition: 'transform .2s',
              }}>▾</span>
            </div>

            {/* Feature list */}
            {expanded === tool.id && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${tool.colorBorder}` }}>
                {tool.features.map((f, i) => (
                  <div key={i} style={{
                    fontSize: 11, color: '#94a3b8', lineHeight: 1.6,
                    padding: '3px 0',
                    borderBottom: i < tool.features.length - 1 ? '1px solid rgba(255,255,255,.04)' : 'none',
                  }}>{f}</div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── CTA Button ── */}
      <button
        onClick={() => navigate(`${basePath}log-monitor`)}
        style={{
          marginTop: 'auto',
          padding: '9px 0',
          borderRadius: 8,
          border: 'none',
          background: 'linear-gradient(90deg, #1d4ed8, #3b82f6)',
          color: '#fff',
          fontSize: 12,
          fontWeight: 600,
          cursor: 'pointer',
          letterSpacing: '.3px',
          transition: 'opacity .15s, transform .15s',
          boxShadow: '0 2px 10px rgba(59,130,246,.35)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 6,
          width: '100%',
        }}
        onMouseEnter={e => { e.currentTarget.style.opacity = '.88'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
        onMouseLeave={e => { e.currentTarget.style.opacity = '1';    e.currentTarget.style.transform = 'none'; }}
      >
        🖥️ Open Advanced Dashboard
      </button>

      <div style={{ fontSize: 9, color: '#1e3a5f', textAlign: 'center', marginTop: -4 }}>
        Click a tool to expand · refreshes every 30s
      </div>
    </div>
  );
}
