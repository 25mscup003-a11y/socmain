/**
 * useDashboardConfig — shared React hook for centralized dashboard configuration.
 *
 * Fetches GET /api/dashboard/config on mount.
 * Listens for Socket.IO `dashboard:config_updated` events for real-time sync.
 * Used by ALL roles: company_admin, department_admin, analyst, superadmin (via prop).
 *
 * Usage:
 *   const { config, loading, save } = useDashboardConfig({ socket, companyId });
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios';

const DEFAULT_CONFIG = {
  tools: [
    {
      id: 'soc-log-monitor', name: 'SOC Log Monitor', icon: '📋', enabled: true,
      color: '#60a5fa', badge: 'Built-in · Centralized', order: 0,
      features: [
        '📥  Multi-source log ingestion',
        '🔎  Centralized log search and filtering',
        '🔔  Real-time monitoring and alerts',
      ],
    },
  ],
  cards: [],
  refreshIntervalSecs: 30,
  showLogMonitorCard: true,
  canEdit: false,
};

/**
 * @param {object} opts
 * @param {object}  opts.socket      — Socket.IO client instance (optional)
 * @param {string}  opts.companyId   — for superadmin using company-specific endpoint
 * @param {string}  opts.apiPrefix   — prefix for config API (default '/dashboard/config')
 */
export function useDashboardConfig({ socket, companyId, apiPrefix } = {}) {
  const prefix      = apiPrefix || '/dashboard/config';
  const [config,  setConfig]  = useState(DEFAULT_CONFIG);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [saving,  setSaving]  = useState(false);
  const toastRef = useRef(null);

  const fetch = useCallback(async () => {
    try {
      setLoading(true);
      const url = companyId ? `${prefix}/superadmin/${companyId}` : prefix;
      // superadmin uses GET on same base (config applies to the company)
      const endpoint = companyId ? `/dashboard/config` : prefix;
      const r = await api.get(endpoint, companyId ? { params: { companyId } } : undefined);
      setConfig(r.data || DEFAULT_CONFIG);
      setError('');
    } catch (e) {
      // Fallback silently to defaults — dashboard still works
      setError(e.response?.data?.message || e.message);
      setConfig(DEFAULT_CONFIG);
    } finally {
      setLoading(false);
    }
  }, [prefix, companyId]);

  // Initial load
  useEffect(() => { fetch(); }, [fetch]);

  // ── Real-time sync via Socket.IO ─────────────────────────────────────────────
  useEffect(() => {
    if (!socket) return;

    const handler = (payload) => {
      // Filter by companyId if given (superadmin watching multiple companies)
      if (companyId && payload.companyId !== companyId) return;
      if (payload?.config) {
        setConfig(payload.config);
        showToast(`Dashboard updated by ${payload.updatedBy || 'admin'}`);
      }
    };

    socket.on('dashboard:config_updated', handler);
    return () => socket.off('dashboard:config_updated', handler);
  }, [socket, companyId]);

  // ── Save (company_admin / superadmin only) ───────────────────────────────────
  const save = useCallback(async (updates) => {
    try {
      setSaving(true);
      const endpoint = companyId
        ? `/dashboard/config/superadmin/${companyId}`
        : `/dashboard/config`;
      // For superadmin use POST on their endpoint
      const method = companyId ? 'post' : 'post';
      const r = await api[method](endpoint, updates);
      if (r.data?.config) setConfig(r.data.config);
      setError('');
      return r.data;
    } catch (e) {
      setError(e.response?.data?.message || e.message);
      throw e;
    } finally {
      setSaving(false);
    }
  }, [companyId]);

  function showToast(msg) {
    clearTimeout(toastRef.current);
    const el = document.getElementById('__dash_cfg_toast__');
    if (el) {
      el.textContent = msg;
      el.style.opacity = '1';
      toastRef.current = setTimeout(() => { el.style.opacity = '0'; }, 3000);
    }
  }

  return { config, loading, error, saving, refetch: fetch, save };
}
