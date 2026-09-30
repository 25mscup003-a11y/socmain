/**
 * DashboardToolsCard — Centralized, role-aware log monitoring tools card.
 *
 * ✔ Renders the built-in monitor from /api/dashboard/config
 * ✔ Company Admin sees an Edit panel to enable/disable/reorder tools
 * ✔ All other roles see a consistent read-only view
 * ✔ Auto-updates via Socket.IO `dashboard:config_updated` event
 *
 * Props:
 *   config    — from useDashboardConfig()
 *   canEdit   — boolean (company_admin+)
 *   onSave    — async fn(updates) from useDashboardConfig().save
 *   saving    — boolean
 *   stats     — optional { total, severity, failedLogins, suspiciousCount }
 *   basePath  — route prefix for "Open Dashboard" button
 *   navigate  — useNavigate() from caller
 */
import { useState } from 'react';

const SEV = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };

// ── Shared toast element (rendered once, reused) ───────────────────────────────
export function DashboardToast() {
  return (
    <div
      id="__dash_cfg_toast__"
      style={{
        position: 'fixed', bottom: 24, right: 24, zIndex: 9999,
        background: '#1d4ed8', color: '#fff', borderRadius: 8,
        padding: '10px 18px', fontSize: 12, fontWeight: 500,
        boxShadow: '0 4px 20px rgba(0,0,0,.4)',
        opacity: 0, transition: 'opacity .35s',
        pointerEvents: 'none',
      }}
    />
  );
}

export default function DashboardToolsCard({
  config, canEdit = false, onSave, saving = false,
  stats, basePath = '/', navigate,
}) {
  const tools  = (config?.tools || []).filter(t => canEdit || t.enabled).sort((a,b) => a.order-b.order);
  const [expanded, setExpanded] = useState(null);
  const [editing,  setEditing]  = useState(false);
  const [draft,    setDraft]    = useState(null);     // editable copy of tools

  const alertBadge = (stats?.suspiciousCount || 0) > 0 ? stats.suspiciousCount : null;

  // ── Start editing ────────────────────────────────────────────────────────────
  function startEdit() {
    setDraft(JSON.parse(JSON.stringify(tools)));
    setEditing(true);
  }

  function toggleEnabled(idx) {
    setDraft(d => d.map((t, i) => i === idx ? { ...t, enabled: !t.enabled } : t));
  }

  function moveUp(idx) {
    if (idx === 0) return;
    setDraft(d => {
      const arr = [...d];
      [arr[idx-1], arr[idx]] = [arr[idx], arr[idx-1]];
      return arr.map((t, i) => ({ ...t, order: i }));
    });
  }

  function moveDown(idx) {
    setDraft(d => {
      if (idx >= d.length - 1) return d;
      const arr = [...d];
      [arr[idx], arr[idx+1]] = [arr[idx+1], arr[idx]];
      return arr.map((t, i) => ({ ...t, order: i }));
    });
  }

  async function handleSave() {
    if (!onSave) return;
    await onSave({ tools: draft });
    setEditing(false);
  }

  const displayed = editing ? draft : tools;

  return (
    <div style={{
      background: '#0c1a2e',
      border: '1px solid #1e3a5f',
      borderRadius: 12,
      padding: '16px 18px',
      flex: '1',
      minWidth: 270,
      maxWidth: 440,
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
            }}>
              🚨 {alertBadge} alerts
            </span>
          )}
          {canEdit && !editing && (
            <button onClick={startEdit} style={{
              fontSize: 9, padding: '2px 8px', borderRadius: 6, border: '1px solid #1e3a5f',
              background: 'none', color: '#60a5fa', cursor: 'pointer',
            }}>✏️ Edit</button>
          )}
          {editing && (
            <>
              <button onClick={handleSave} disabled={saving} style={{
                fontSize: 9, padding: '2px 8px', borderRadius: 6, border: 'none',
                background: '#1d4ed8', color: '#fff', cursor: 'pointer',
              }}>{saving ? '…' : '💾 Save'}</button>
              <button onClick={() => setEditing(false)} style={{
                fontSize: 9, padding: '2px 8px', borderRadius: 6, border: '1px solid #1e3a5f',
                background: 'none', color: '#94a3b8', cursor: 'pointer',
              }}>✕</button>
            </>
          )}
          <span style={{
            fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
            background: 'rgba(96,165,250,.15)', color: '#60a5fa',
            border: '1px solid rgba(96,165,250,.3)',
          }}>LIVE</span>
        </div>
      </div>

      {/* ── Live stat strip ── */}
      {stats && (
        <div style={{
          display: 'flex', gap: 8, flexWrap: 'wrap',
          background: '#060e1a', borderRadius: 8, padding: '8px 12px',
          border: '1px solid #1e3a5f',
        }}>
          {[
            { label: 'Total (24h)',   val: stats.total,        color: '#93c5fd' },
            { label: 'Critical',      val: stats.severity?.critical, color: SEV.critical },
            { label: 'High',          val: stats.severity?.high,     color: SEV.high },
            { label: 'Failed logins', val: stats.failedLogins,       color: '#f59e0b' },
          ].map(({ label, val, color }) => (
            <div key={label} style={{ flex: '1 0 auto', textAlign: 'center', minWidth: 60 }}>
              <div style={{ fontSize: 16, fontWeight: 700, color }}>{val ?? '–'}</div>
              <div style={{ fontSize: 9, color: '#475569' }}>{label}</div>
            </div>
          ))}
        </div>
      )}

      {/* ── Tools list ── */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
        {displayed.map((tool, idx) => (
          <div
            key={tool.id}
            onClick={() => !editing && setExpanded(expanded === tool.id ? null : tool.id)}
            style={{
              background: expanded === tool.id ? `${tool.color}20` : 'rgba(255,255,255,.025)',
              border: `1px solid ${!tool.enabled && editing ? '#374151' : expanded === tool.id ? (tool.color+'55') : '#1e3a5f'}`,
              borderRadius: 8, padding: '9px 12px',
              cursor: editing ? 'default' : 'pointer',
              transition: 'background .18s, border-color .18s',
              opacity: (!tool.enabled && !editing) ? 0.4 : 1,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{
                  fontSize: 15, width: 28, height: 28, borderRadius: 7,
                  background: `${tool.color}20`, border: `1px solid ${tool.color}44`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>{tool.icon}</span>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 600, color: tool.enabled ? '#e2e8f0' : '#64748b' }}>{tool.name}</div>
                  <div style={{ fontSize: 9, color: tool.color }}>{tool.badge}</div>
                </div>
              </div>

              {/* Edit controls */}
              {editing ? (
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  <button onClick={() => moveUp(idx)} title="Move up" style={{ fontSize: 11, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', padding: '0 3px' }}>▲</button>
                  <button onClick={() => moveDown(idx)} title="Move down" style={{ fontSize: 11, background: 'none', border: 'none', color: '#60a5fa', cursor: 'pointer', padding: '0 3px' }}>▼</button>
                  <button
                    onClick={() => toggleEnabled(idx)}
                    style={{
                      fontSize: 9, padding: '2px 7px', borderRadius: 4, border: 'none', cursor: 'pointer',
                      background: tool.enabled ? '#064e3b' : '#374151',
                      color:      tool.enabled ? '#34d399' : '#9ca3af',
                    }}
                  >{tool.enabled ? 'ON' : 'OFF'}</button>
                </div>
              ) : (
                <span style={{
                  fontSize: 13, color: '#1e40af',
                  transform: expanded === tool.id ? 'rotate(180deg)' : 'none',
                  display: 'inline-block', transition: 'transform .2s',
                }}>▾</span>
              )}
            </div>

            {/* Feature list (expanded, non-edit mode) */}
            {!editing && expanded === tool.id && (
              <div style={{ marginTop: 10, paddingTop: 8, borderTop: `1px solid ${tool.color}33` }}>
                {(tool.features || []).map((f, i) => (
                  <div key={i} style={{
                    fontSize: 11, color: '#94a3b8', lineHeight: 1.6, padding: '3px 0',
                    borderBottom: i < (tool.features.length - 1) ? '1px solid rgba(255,255,255,.04)' : 'none',
                  }}>{f}</div>
                ))}
                {tool.externalUrl && (
                  <a href={tool.externalUrl} target="_blank" rel="noreferrer" style={{
                    display: 'inline-block', marginTop: 8, fontSize: 10, color: '#60a5fa',
                  }}>🔗 Open {tool.name} →</a>
                )}
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ── CTA ── */}
      {navigate && (
        <button
          onClick={() => navigate(`${basePath}log-monitor`)}
          style={{
            marginTop: 'auto', padding: '9px 0', borderRadius: 8, border: 'none',
            background: 'linear-gradient(90deg, #1d4ed8, #3b82f6)',
            color: '#fff', fontSize: 12, fontWeight: 600, cursor: 'pointer',
            letterSpacing: '.3px', transition: 'opacity .15s, transform .15s',
            boxShadow: '0 2px 10px rgba(59,130,246,.35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6, width: '100%',
          }}
          onMouseEnter={e => { e.currentTarget.style.opacity = '.88'; e.currentTarget.style.transform = 'translateY(-1px)'; }}
          onMouseLeave={e => { e.currentTarget.style.opacity = '1';    e.currentTarget.style.transform = 'none'; }}
        >
          🖥️ Open Advanced Dashboard
        </button>
      )}

      <div style={{ fontSize: 9, color: '#1e3a5f', textAlign: 'center', marginTop: -4 }}>
        {editing ? 'Toggle tools on/off · drag to reorder · click Save' : 'Click a tool to expand · auto-syncs across all roles'}
      </div>
    </div>
  );
}
