import React, { useEffect, useRef, useState } from 'react';
import api from '../../api/axios';
import { useAuth } from '../../context/AuthContext';

export const LOG_RANGES = [
  { value: '24h', label: 'Last 24 hours', hours: 24 },
  { value: '7d', label: 'Last 7 days', hours: 168 },
  { value: '30d', label: 'Last 30 days', hours: 720 },
  { value: '60d', label: 'Last 60 days', hours: 1440 },
  { value: '90d', label: 'Last 90 days', hours: 2160 },
  { value: '180d', label: 'Last 180 days', hours: 4320 },
];

const controlStyle = { background: '#060d16', border: '1px solid #1a3050', color: '#e2e8f0', padding: '7px 10px', borderRadius: 6, fontSize: 11 };
const PAGE_SIZE = 500;

// Keep historical logs independent of the dashboard's rolling 24-hour snapshot.
export default function CapabilityLogsPanel({ capabilityId, children, mergeRows, companyId: requestedCompanyId, systemId, departmentId }) {
  const { company, user } = useAuth();
  const companyId = requestedCompanyId || company?._id || user?.companyId?._id || user?.companyId;
  const [range, setRange] = useState('24h');
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [data, setData] = useState({ rows: [], total: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const windowEnd = useRef(new Date().toISOString());
  const selected = LOG_RANGES.find(option => option.value === range);
  const scopeKey = `${capabilityId}:${companyId || ''}:${systemId || ''}:${departmentId || ''}:${range}`;

  useEffect(() => {
    windowEnd.current = new Date().toISOString();
    setPage(1);
    setData({ rows: [], total: 0 });
  }, [scopeKey]);

  useEffect(() => {
    let cancelled = false;
    const controller = new AbortController();
    setLoading(true);
    setError('');
    const params = {
      range, page, limit: PAGE_SIZE, windowEnd: windowEnd.current,
      ...(companyId ? { companyId } : {}), ...(systemId ? { systemId } : {}), ...(departmentId ? { departmentId } : {}),
    };
    const from = new Date(new Date(windowEnd.current).getTime() - selected.hours * 3600000).toISOString();
    const load = async () => {
      if (capabilityId === 3) {
        const networkParams = { ...params, from, to: windowEnd.current };
        const [connections, alerts] = await Promise.all([
          api.get('/network/connections', { params: networkParams, skipCache: true, signal: controller.signal }),
          api.get('/network/alerts', { params: networkParams, skipCache: true, signal: controller.signal }),
        ]);
        const connectionRows = (connections.data.connections || []).map(row => ({ ...row, _recordType: 'connection' }));
        const alertRows = (alerts.data.alerts || []).map(row => ({ ...row, _recordType: 'alert' }));
        return { rows: mergeRows(connectionRows, alertRows), total: Number(connections.data.total || 0) + Number(alerts.data.total || 0), hasMore: page * PAGE_SIZE < Math.max(connections.data.total || 0, alerts.data.total || 0) };
      }
      const endpoint = capabilityId === 20 ? '/api-monitoring/events'
        : capabilityId === 19 ? '/kernel-monitoring/events'
          : `/dashboard/capabilities/${capabilityId}/logs`;
      const response = await api.get(endpoint, { params: { ...params, from, to: windowEnd.current }, skipCache: true, signal: controller.signal });
      return {
        rows: response.data.alerts || response.data.events || [],
        total: response.data.total == null ? null : Number(response.data.total),
        hasMore: typeof response.data.hasMore === 'boolean'
          ? response.data.hasMore
          : page * PAGE_SIZE < Number(response.data.total || 0),
      };
    };
    load().then(result => {
      if (cancelled) return;
      setData(previous => {
        const combined = page === 1 ? result.rows : [...previous.rows, ...result.rows];
        const rows = [...new Map(combined.map(row => [`${row._recordType || ''}:${row._id}`, row])).values()];
        return { ...result, rows, scopeKey, updatedAt: new Date().toISOString() };
      });
    }).catch(requestError => {
      if (!cancelled) setError(requestError.response?.data?.message || 'Logs could not be loaded. Please retry.');
    }).finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; controller.abort(); };
  }, [scopeKey, page, refresh]);

  const reload = () => {
    windowEnd.current = new Date().toISOString();
    setPage(1);
    setRefresh(value => value + 1);
  };
  // Do not disturb browsing older pages with automatic refreshes.
  useEffect(() => {
    if (page !== 1) return undefined;
    const timer = setInterval(reload, 30000);
    return () => clearInterval(timer);
  }, [scopeKey, page]);

  const rows = data.scopeKey === scopeKey ? data.rows : [];
  const memoryMetrics = (children.props.memoryMetrics || []).filter(row => {
    const timestamp = new Date(row.createdAt || row.eventTimestamp || row.timestamp).getTime();
    const until = new Date(windowEnd.current).getTime();
    return timestamp >= until - selected.hours * 3600000 && timestamp <= until;
  });
  return <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
    <div style={{ background: '#0b1929', border: '1px solid #1a3050', borderRadius: 8, padding: 12, display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
      <label style={{ color: '#8ea0b8', fontSize: 11 }}>📅 Time range{' '}
        <select aria-label="Log time range" value={range} onChange={event => { setPage(1); setRange(event.target.value); }} style={controlStyle}>
          {LOG_RANGES.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </label>
      <span aria-live="polite" style={{ color: '#8ea0b8', fontSize: 11 }}>{loading ? 'Loading logs…' : `${rows.length.toLocaleString()} loaded · ${selected.label}`}</span>
      <button type="button" onClick={reload} disabled={loading} style={{ ...controlStyle, marginLeft: 'auto', cursor: 'pointer' }}>Refresh</button>
    </div>
    {error && <div role="alert" style={{ color: '#f87171', fontSize: 12 }}>{error}</div>}
    {React.cloneElement(children, { key: scopeKey, alerts: rows, total: rows.length, loading, updatedAt: data.updatedAt, onRefresh: reload, onSaved: reload, ...(capabilityId === 5 ? { metrics: [] } : {}), ...(children.props.memoryMetrics ? { memoryMetrics } : {}) })}
    {data.scopeKey === scopeKey && data.hasMore && <div style={{ color: '#8ea0b8', fontSize: 11 }}>
      More logs are available. Search and other filters apply to loaded records.{' '}
      <button type="button" disabled={loading} onClick={() => error ? setRefresh(value => value + 1) : setPage(value => value + 1)} style={{ ...controlStyle, cursor: 'pointer' }}>{loading ? 'Loading…' : error ? 'Retry' : 'Load more logs'}</button>
    </div>}
  </div>;
}
