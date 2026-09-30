import React, { useCallback, useEffect, useMemo, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

const severityColor = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const statusColor = {
  open: '#facc15',
  investigating: '#60a5fa',
  contained: '#a78bfa',
  resolved: '#22c55e',
  closed: '#94a3b8',
  false_positive: '#94a3b8',
};

function Badge({ value, palette }) {
  const key = String(value || '').toLowerCase();
  const color = palette[key] || '#38bdf8';
  return (
    <span style={{
      display: 'inline-flex',
      alignItems: 'center',
      border: `1px solid ${color}55`,
      background: `${color}18`,
      color,
      borderRadius: 999,
      padding: '3px 8px',
      fontSize: 10,
      fontWeight: 800,
      textTransform: 'uppercase',
      whiteSpace: 'nowrap',
    }}>
      {String(value || 'unknown').replace(/_/g, ' ')}
    </span>
  );
}

function fmtDate(value) {
  if (!value) return '-';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '-' : date.toLocaleString();
}

function getReasonOrAnalystNote(incident) {
  const notes = Array.isArray(incident?.notes) ? incident.notes : [];
  const latestNote = [...notes]
    .sort((left, right) => new Date(right?.at || 0) - new Date(left?.at || 0))
    .find(note => String(note?.text || note || '').trim());

  return String(
    latestNote?.text
    || latestNote
    || incident?.managerNote
    || incident?.analystNote
    || ''
  ).trim() || 'No analyst note has been added yet.';
}

export default function CompanyIncidentsPage({ threatIntelligence = false }) {
  const { isDeptAdmin } = useAuth();
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [severity, setSeverity] = useState('');
  const [status, setStatus] = useState('');
  const [search, setSearch] = useState('');
  const [statusCounts, setStatusCounts] = useState(null);
  const [severityCounts, setSeverityCounts] = useState(null);
  const [selected, setSelected] = useState(null);
  const limit = 20;

  const loadIncidents = useCallback(async (isSilent = false) => {
    if (!isSilent) setLoading(true);
    setError('');
    try {
      const q = new URLSearchParams({ page: String(page), limit: String(limit) });
      if (severity) q.set('severity', severity);
      if (status) q.set('status', status);
      if (search.trim()) q.set('search', search.trim());
      const endpoint = threatIntelligence ? '/soc-manager/threat-intelligence' : '/soc-manager/incidents';
      const { data } = await api.get(`${endpoint}?${q}`);
      const nextItems = data.items || [];
      setItems(nextItems);
      setTotal(data.total || 0);
      if (data.statusCounts) {
        setStatusCounts(data.statusCounts);
      }
      if (data.severityCounts) {
        setSeverityCounts(data.severityCounts);
      }
    } catch (err) {
      if (!isSilent) {
        setError(err.response?.data?.message || 'Unable to load incidents');
        setItems([]);
        setTotal(0);
      }
    } finally {
      if (!isSilent) setLoading(false);
    }
  }, [page, severity, status, search, threatIntelligence]);

  useEffect(() => {
    loadIncidents(false);
    const timer = setInterval(() => {
      loadIncidents(true);
    }, 5000);
    return () => clearInterval(timer);
  }, [loadIncidents]);

  const counts = useMemo(() => {
    const critical = severityCounts ? (severityCounts.critical || 0) : items.filter(item => String(item.severity || '').toLowerCase() === 'critical').length;
    const high = severityCounts ? (severityCounts.high || 0) : items.filter(item => String(item.severity || '').toLowerCase() === 'high').length;
    if (statusCounts) {
      const pending = statusCounts.open || 0;
      const investigating = (statusCounts.investigating || 0) + (statusCounts.contained || 0);
      const closed = (statusCounts.closed || 0) + (statusCounts.resolved || 0) + (statusCounts.false_positive || 0);
      return { pending, investigating, closed, critical, high };
    }
    return {
      pending: items.filter(item => String(item.status || '').toLowerCase() === 'open').length,
      investigating: items.filter(item => ['investigating', 'contained'].includes(String(item.status || '').toLowerCase())).length,
      closed: items.filter(item => ['closed', 'resolved', 'false_positive'].includes(String(item.status || '').toLowerCase())).length,
      critical,
      high,
    };
  }, [statusCounts, severityCounts, items]);

  const pageCount = Math.max(1, Math.ceil(total / limit));
  const overallTotal = statusCounts
    ? Object.values(statusCounts).reduce((sum, value) => sum + Number(value || 0), 0)
    : total;

  const openIncidentNote = incident => {
    setSelected(incident);
  };

  return (
    <div style={{ minHeight: 'calc(100vh - 80px)', color: '#e5edf7', display: 'grid', gap: 14 }}>
      <header style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 22, fontWeight: 900 }}>{threatIntelligence ? 'Threat Intelligence Incidents' : 'Incidents'}</h2>
          <p style={{ margin: '5px 0 0', color: '#60a5fa', fontSize: 12 }}>
            {threatIntelligence
              ? `IOC and threat-feed correlated incidents, scoped to your ${isDeptAdmin ? 'department' : 'company'}.`
              : `Same incident queue shown in SOC Manager incidents, scoped to your ${isDeptAdmin ? 'department' : 'company'}.`}
          </p>
        </div>
        <button
          type="button"
          onClick={loadIncidents}
          style={{ border: '1px solid #2563eb66', background: '#1d4ed822', color: '#93c5fd', borderRadius: 7, padding: '8px 13px', cursor: 'pointer', fontWeight: 800 }}
        >
          Refresh
        </button>
      </header>

      <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 10 }}>
        {[
          { label: threatIntelligence ? 'Total TI Incidents' : 'Total Incidents', value: overallTotal, color: '#38bdf8', filterType: 'status', filterKey: '', sub: threatIntelligence ? 'All Threat Intel' : 'All Incidents' },
          { label: 'Pending Incidents', value: counts.pending, color: '#facc15', filterType: 'status', filterKey: 'open', sub: 'Open / Pending' },
          { label: 'In Investigation', value: counts.investigating, color: '#60a5fa', filterType: 'status', filterKey: 'investigation_group', sub: 'Under Analysis' },
          { label: 'Closed Incidents', value: counts.closed, color: '#22c55e', filterType: 'status', filterKey: 'closed_group', sub: 'Resolved & Closed' },
          { label: 'Critical Severity', value: counts.critical, color: '#ef4444', filterType: 'severity', filterKey: 'critical', sub: 'Critical Severity' },
          { label: 'High Severity', value: counts.high, color: '#f97316', filterType: 'severity', filterKey: 'high', sub: 'High Severity' },
        ].map(card => {
          const isActive = card.filterType === 'status'
            ? (status === card.filterKey && (!severity || card.filterKey === ''))
            : (severity === card.filterKey && !status);
          return (
            <div
              key={card.label}
              onClick={() => {
                if (card.filterType === 'status') {
                  if (card.filterKey === '') {
                    setStatus('');
                    setSeverity('');
                  } else if (status === card.filterKey) {
                    setStatus('');
                    setSeverity('');
                  } else {
                    setStatus(card.filterKey);
                    setSeverity('');
                  }
                } else {
                  if (severity === card.filterKey) {
                    setSeverity('');
                    setStatus('');
                  } else {
                    setSeverity(card.filterKey);
                    setStatus('');
                  }
                }
                setPage(1);
              }}
              style={{
                border: isActive ? `1px solid ${card.color}` : '1px solid #17304e',
                borderRadius: 8,
                background: isActive ? `${card.color}10` : 'linear-gradient(135deg,#071827,#06111f)',
                padding: 14,
                cursor: 'pointer',
                transition: 'all 0.15s ease-in-out',
                boxShadow: isActive ? `0 0 10px ${card.color}22` : 'none',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ color: '#8ea0b8', fontSize: 10, fontWeight: 900, textTransform: 'uppercase' }}>{card.label}</div>
                {isActive && <span style={{ width: 6, height: 6, borderRadius: '50%', background: card.color }}></span>}
              </div>
              <div style={{ color: card.color, fontSize: 28, fontWeight: 950, marginTop: 6 }}>{card.value}</div>
              <div style={{ color: '#64748b', fontSize: 10, marginTop: 4 }}>{card.sub}</div>
            </div>
          );
        })}
      </section>

      <section style={{ border: '1px solid #17304e', borderRadius: 8, background: 'linear-gradient(135deg,#071827,#06111f)', overflow: 'hidden' }}>
        <div style={{ display: 'flex', gap: 8, padding: 12, borderBottom: '1px solid #12243d', flexWrap: 'wrap' }}>
          <input
            value={search}
            onChange={event => { setSearch(event.target.value); setPage(1); }}
            placeholder="Search title, endpoint, IOC, correlation ID..."
            style={{ flex: '1 1 260px', background: '#06111f', color: '#e5edf7', border: '1px solid #1e3a5f', borderRadius: 6, padding: '9px 10px', outline: 'none' }}
          />
          {[
            ['Severity', severity, setSeverity, ['', 'critical', 'high', 'medium', 'low']],
            ['Status', status, setStatus, ['', 'open', 'investigation_group', 'investigating', 'contained', 'closed_group', 'resolved', 'false_positive']],
          ].map(([label, value, setter, options]) => (
            <select
              key={label}
              value={value}
              onChange={event => { setter(event.target.value); setPage(1); }}
              style={{ background: '#06111f', color: value ? '#e5edf7' : '#64748b', border: '1px solid #1e3a5f', borderRadius: 6, padding: '9px 10px' }}
            >
              {options.map(option => <option key={option} value={option}>{option ? option.replace(/_/g, ' ') : label}</option>)}
            </select>
          ))}
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', minWidth: 980, borderCollapse: 'collapse', fontSize: 12 }}>
            <thead>
              <tr style={{ color: '#8ea0b8', textAlign: 'left', borderBottom: '1px solid #12243d' }}>
                {['Title / ID', 'Company', 'Endpoint', 'Severity', 'Status', 'Analyst', threatIntelligence ? 'Latest Activity' : 'Created'].map(head => (
                  <th key={head} style={{ padding: '10px 12px', fontSize: 10, textTransform: 'uppercase' }}>{head}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="7" style={{ padding: 24, color: '#60a5fa', textAlign: 'center' }}>Loading incidents...</td></tr>
              ) : error ? (
                <tr><td colSpan="7" style={{ padding: 24, color: '#ef4444', textAlign: 'center' }}>{error}</td></tr>
              ) : items.length === 0 ? (
                <tr><td colSpan="7" style={{ padding: 24, color: '#64748b', textAlign: 'center' }}>No incidents found.</td></tr>
              ) : items.map(item => (
                <tr
                  key={item._id}
                  onClick={() => openIncidentNote(item)}
                  style={{ borderBottom: '1px solid #0f2037', cursor: 'pointer', background: 'transparent' }}
                >
                  <td style={{ padding: '11px 12px', maxWidth: 320 }}>
                    <div style={{ color: '#f3f8ff', fontWeight: 850, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.title || item.description || 'Incident'}</div>
                    <div style={{ color: '#64748b', fontSize: 10, marginTop: 3 }}>{item.incidentId || item._id}</div>
                  </td>
                  <td style={{ padding: '11px 12px', color: '#cbd5e1' }}>{item.companyId?.name || '-'}</td>
                  <td style={{ padding: '11px 12px', color: '#cbd5e1' }}>{item.agentName || item.affectedEndpoint || item.systemId?.name || '-'}</td>
                  <td style={{ padding: '11px 12px' }}><Badge value={item.severity} palette={severityColor} /></td>
                  <td style={{ padding: '11px 12px' }}><Badge value={item.status || 'open'} palette={statusColor} /></td>
                  <td style={{ padding: '11px 12px', color: '#cbd5e1' }}>{item.assignedTo?.name || item.assignedTo?.email || 'Unassigned'}</td>
                  <td style={{ padding: '11px 12px', color: '#94a3b8' }}>
                    {fmtDate(threatIntelligence ? (item.lastEventAt || item.updatedAt || item.createdAt) : item.createdAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', gap: 10, padding: 12, borderTop: '1px solid #12243d' }}>
          <button onClick={() => setPage(value => Math.max(1, value - 1))} disabled={page <= 1} style={{ border: '1px solid #1e3a5f', background: 'transparent', color: page <= 1 ? '#334155' : '#60a5fa', borderRadius: 6, padding: '6px 12px', cursor: page <= 1 ? 'not-allowed' : 'pointer' }}>Previous</button>
          <span style={{ color: '#8ea0b8', fontSize: 12 }}>Page {page} of {pageCount}</span>
          <button onClick={() => setPage(value => value + 1)} disabled={page >= pageCount} style={{ border: '1px solid #1e3a5f', background: 'transparent', color: page >= pageCount ? '#334155' : '#60a5fa', borderRadius: 6, padding: '6px 12px', cursor: page >= pageCount ? 'not-allowed' : 'pointer' }}>Next</button>
        </div>
      </section>

      {selected && (
        <div
          role="presentation"
          onClick={() => setSelected(null)}
          style={{ position: 'fixed', inset: 0, zIndex: 1000, display: 'grid', placeItems: 'center', padding: 20, background: 'rgba(2, 8, 23, 0.78)', backdropFilter: 'blur(4px)' }}
        >
          <section
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-note-title"
            onClick={event => event.stopPropagation()}
            style={{ width: 'min(560px, 100%)', border: '1px solid #1e3a5f', borderRadius: 10, background: 'linear-gradient(145deg, #071827, #06111f)', boxShadow: '0 24px 70px rgba(0, 0, 0, 0.55)', overflow: 'hidden' }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 16px', borderBottom: '1px solid #17304e' }}>
              <h3 id="incident-note-title" style={{ margin: 0, color: '#e5edf7', fontSize: 15, fontWeight: 900 }}>Reason / Analyst Note</h3>
              <button type="button" aria-label="Close" onClick={() => setSelected(null)} style={{ border: 0, background: 'transparent', color: '#94a3b8', fontSize: 22, lineHeight: 1, cursor: 'pointer', padding: 2 }}>×</button>
            </div>
            <div style={{ padding: 16, color: '#cbd5e1', fontSize: 13, lineHeight: 1.65, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>
              <div style={{ color: '#64748b', fontSize: 10, fontWeight: 900, textTransform: 'uppercase', marginBottom: 5 }}>Current Reason / Latest Analyst Note</div>
              <div style={{ padding: 11, border: '1px solid #17304e', borderRadius: 7, background: '#06111f' }}>{getReasonOrAnalystNote(selected)}</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10, marginTop: 16, paddingTop: 14, borderTop: '1px solid #17304e' }}>
                <div>
                  <div style={{ color: '#64748b', fontSize: 10, fontWeight: 900, textTransform: 'uppercase' }}>Created</div>
                  <div style={{ marginTop: 4, color: '#94a3b8', fontSize: 12 }}>{fmtDate(selected.createdAt)}</div>
                </div>
                <div>
                  <div style={{ color: '#64748b', fontSize: 10, fontWeight: 900, textTransform: 'uppercase' }}>Closed Time</div>
                  <div style={{ marginTop: 4, color: '#94a3b8', fontSize: 12 }}>
                    {['resolved', 'false_positive', 'closed'].includes(String(selected.status || '').toLowerCase())
                      ? fmtDate(selected.resolvedAt)
                      : 'Not closed'}
                  </div>
                </div>
              </div>
            </div>
          </section>
        </div>
      )}

    </div>
  );
}
