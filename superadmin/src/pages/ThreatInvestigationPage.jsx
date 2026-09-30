import React, { useState, useEffect, useCallback, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';

const SEV = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
const SEVBG = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b' };
const CAT_ICON = {
  malware: '🦠', network: '🌐', file: '📁', system: '🖥', edr: '👤',
  usb: '🔌', isolation: '🚫', other: '●',
};

function Badge({ text, color = '#1e40af', bg }) {
  return (
    <span style={{
      fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
      background: bg || `${color}22`, color, border: `1px solid ${color}44`
    }}>{text}</span>
  );
}

// ── Timeline event ─────────────────────────────────────────────────────────────
function TimelineEvent({ alert, selected, onClick }) {
  const sevColor = SEV[alert.severity] || '#64748b';
  return (
    <div onClick={onClick} style={{
      display: 'flex', gap: 12, padding: '10px 12px', cursor: 'pointer',
      background: selected ? '#1e3a5f' : 'transparent',
      borderBottom: '1px solid #060e1a',
      borderLeft: `3px solid ${sevColor}`,
      transition: 'background .15s',
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', minWidth: 32 }}>
        <span style={{ fontSize: 18 }}>{CAT_ICON[alert.eventCategory] || '●'}</span>
        <div style={{ width: 1, flex: 1, background: '#1e3a5f', marginTop: 4 }} />
      </div>
      <div style={{ flex: 1, minWidth: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              fontSize: 12, color: '#e2e8f0', overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap'
            }}>
              {alert.description || 'Security event'}
            </div>
            <div style={{ fontSize: 10, color: '#1e40af', marginTop: 2 }}>
              <Badge text={alert.sourceType || alert.module || 'EDR'} color="#22d3ee" /> {' '}
              {alert.companyId?.name || alert.agentName || alert.systemId?.name || '—'}
              {alert.departmentId?.name && ` · ${alert.departmentId.name}`}
            </div>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 3, flexShrink: 0, marginLeft: 8 }}>
            <Badge text={alert.severity?.toUpperCase()} color={sevColor} bg={SEVBG[alert.severity]} />
            <span style={{ fontSize: 9, color: '#64748b' }}>
              {new Date(alert.createdAt).toLocaleTimeString()}
            </span>
          </div>
        </div>
        {(alert.srcip || alert.filePath || alert.processName) && (
          <div style={{
            fontSize: 10, color: '#64748b', marginTop: 4, fontFamily: 'monospace',
            overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'
          }}>
            {alert.srcip && `IP: ${alert.srcip}`}
            {alert.filePath && ` · File: ${alert.filePath.split('/').pop() || alert.filePath}`}
            {alert.processName && ` · Proc: ${alert.processName}`}
          </div>
        )}
        <div style={{ display: 'flex', gap: 5, marginTop: 5 }}>
          {alert.iocMatched && <Badge text="IOC MATCH" color="#f87171" />}
          <Badge text={(alert.action || (alert.blocked ? 'blocked' : 'detected')).toUpperCase()} color={alert.blocked ? '#f87171' : '#a78bfa'} />
        </div>
      </div>
    </div>
  );
}

// ── Alert detail panel ─────────────────────────────────────────────────────────
function AlertDetailPanel({ alert, onAction }) {
  const [tab, setTab] = useState('overview');
  if (!alert) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#1e40af' }}>
      <div style={{ textAlign: 'center' }}>
        <div style={{ fontSize: 32, marginBottom: 8 }}>🔍</div>
        <div style={{ fontSize: 13 }}>Select an event to investigate</div>
      </div>
    </div>
  );

  const fields = [
    ['Source / Vendor', `${alert.sourceType || alert.module || 'EDR'}${alert.sourceVendor ? ` · ${alert.sourceVendor}` : ''}`],
    ['Confidence', alert.confidenceScore != null ? `${alert.confidenceScore}/100` : null],
    ['Risk Score', alert.riskScore != null ? `${alert.riskScore}/100` : null],
    ['Severity', alert.severity],
    ['Category', alert.eventCategory],
    ['Status', alert.status],
    ['Agent/System', alert.agentName || alert.affectedEndpoint || alert.systemId?.name],
    ['Assigned Analyst', alert.assignedTo?.name || alert.assignedTo?.email],
    ['Correlation ID', alert.correlationId],
    ['Source Events', alert.sourceAlertCount],
    ['Hostname', alert.hostname || alert.systemId?.hostname],
    ['Department', alert.departmentId?.name],
    ['Source IP', alert.srcip],
    ['Source Port', alert.sourcePort || alert.srcPort],
    ['Destination IP', alert.destip],
    ['Dest Port', alert.destPort],
    ['Protocol', alert.protocol],
    ['Direction', alert.direction],
    ['File Path', alert.filePath],
    ['File Action', alert.fileAction],
    ['File Hash', alert.fileHash],
    ['Malware Type', alert.malwareType],
    ['YARA Rules', alert.yaraRules?.join(', ')],
    ['Process', alert.processName],
    ['PID', alert.pid],
    ['User', alert.username],
    ['User Action', alert.userAction],
    ['USB Device', alert.device],
    ['VT Verdict', alert.vtVerdict],
    ['VT Detection', alert.vtDetectionRatio],
    ['Rule ID', alert.ruleId],
    ['Signature', alert.signatureName || alert.signatureId],
    ['Action', alert.action || (alert.blocked ? 'blocked' : 'detected')],
    ['MITRE', alert.mitreTechnique || alert.mitreId],
  ].filter(([, v]) => v != null && v !== '');

  return (
    <div style={{ height: '100%', overflowY: 'auto', padding: 18 }}>
      {/* Header */}
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 15, color: '#e2e8f0', fontWeight: 600, marginBottom: 6 }}>
          {CAT_ICON[alert.eventCategory] || '●'} {alert.description || 'Security Event'}
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <Badge text={alert.severity?.toUpperCase()} color={SEV[alert.severity]} bg={SEVBG[alert.severity]} />
          <Badge text={alert.eventCategory?.toUpperCase()} color="#c4b5fd" bg="#1e1060" />
          <Badge text={alert.status?.toUpperCase()} color="#93c5fd" bg="#1e3a5f" />
          {alert.vtVerdict === 'malicious' && <Badge text="🔬 VT MALICIOUS" color="#f87171" />}
          {alert.vtVerdict === 'suspicious' && <Badge text="🔬 VT SUSPICIOUS" color="#f59e0b" />}
          {alert.quarantined && <Badge text="🔒 QUARANTINED" color="#a78bfa" />}
          {alert.isolated && <Badge text="🚫 ISOLATED" color="#f87171" />}
        </div>
        <div style={{ fontSize: 10, color: '#64748b', marginTop: 6 }}>
          {new Date(alert.createdAt).toLocaleString()}
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4, overflowX: 'auto', borderBottom: '1px solid #1e3a5f', marginBottom: 12 }}>
        {[['overview', 'Overview'], ['timeline', 'Timeline'], ['correlated', 'Correlated Events'], ['ioc', 'IOC Intelligence'], ['raw', 'Raw Logs'], ['notes', 'Analyst Notes'], ['response', 'Response Actions']].map(([id, label]) => (
          <button key={id} onClick={() => setTab(id)} style={{ whiteSpace: 'nowrap', padding: '6px 8px', fontSize: 10, border: 'none', borderBottom: tab === id ? '2px solid #60a5fa' : '2px solid transparent', background: 'none', color: tab === id ? '#93c5fd' : '#64748b', cursor: 'pointer' }}>{label}</button>
        ))}
      </div>

      {/* VT Score bar */}
      {tab === 'overview' && alert.vtScore > 0 && (
        <div style={{
          background: '#060e1a', borderRadius: 8, padding: '10px 14px',
          border: '1px solid #1e3a5f', marginBottom: 14
        }}>
          <div style={{ fontSize: 11, color: '#f59e0b', fontWeight: 600, marginBottom: 6 }}>🔬 VirusTotal</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{
              fontSize: 28, fontWeight: 700,
              color: alert.vtScore >= 70 ? '#f87171' : alert.vtScore >= 10 ? '#f59e0b' : '#34d399'
            }}>
              {alert.vtScore}%
            </span>
            <div>
              <div style={{ fontSize: 11, color: '#e2e8f0' }}>Verdict: <strong>{alert.vtVerdict || 'N/A'}</strong></div>
              <div style={{ fontSize: 11, color: '#1e40af' }}>{alert.vtDetections}/{alert.vtTotal} engines</div>
            </div>
          </div>
          <div style={{ height: 6, background: '#1e3a5f', borderRadius: 3, marginTop: 8 }}>
            <div style={{
              height: '100%', width: `${alert.vtScore}%`, borderRadius: 3,
              background: alert.vtScore >= 70 ? '#f87171' : '#f59e0b'
            }} />
          </div>
        </div>
      )}

      {/* Fields table */}
      {tab === 'overview' && <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, marginBottom: 14 }}>
        <tbody>
          {fields.map(([k, v]) => (
            <tr key={k} style={{ borderBottom: '1px solid #0a1220' }}>
              <td style={{ padding: '5px 0', color: '#1e40af', minWidth: 120, verticalAlign: 'top', fontSize: 11 }}>{k}</td>
              <td style={{
                padding: '5px 0 5px 10px', color: '#c4b5fd', wordBreak: 'break-all',
                fontFamily: ['File Hash', 'PID', 'Rule ID'].includes(k) ? 'monospace' : 'inherit', fontSize: 11
              }}>
                {String(v)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>}

      {tab === 'timeline' && <div>{(alert.investigationTimeline || []).length ? alert.investigationTimeline.map((item, i) => <div key={i} style={{ padding: 9, borderLeft: '2px solid #3b82f6', marginBottom: 8, color: '#cbd5e1', fontSize: 11 }}><strong>{item.type}</strong> · {new Date(item.at).toLocaleString()}<div style={{ color: '#64748b' }}>{item.detail}</div></div>) : <div style={{ color: '#64748b' }}>No investigation activity recorded.</div>}</div>}
      {tab === 'correlated' && <div style={{ color: '#94a3b8', fontSize: 11 }}>{alert.correlationIds?.length ? alert.correlationIds.map(String).join(', ') : 'No correlated events linked.'}</div>}
      {tab === 'ioc' && <div>{(alert.iocMatches || []).length ? alert.iocMatches.map((ioc, i) => <div key={i} style={{ background: '#060e1a', padding: 10, borderRadius: 6, marginBottom: 8, fontSize: 11, color: '#cbd5e1' }}><strong>{ioc.indicator || ioc.value}</strong> · {ioc.type} · {ioc.source || 'Threat Intelligence'}<div>{ioc.context || `Reputation: ${ioc.reputation || 'unknown'} · Confidence: ${ioc.confidenceScore ?? '—'}`}</div>{ioc.recommendedResponse && <div style={{ color: '#60a5fa' }}>{ioc.recommendedResponse}</div>}</div>) : <div style={{ color: '#64748b' }}>No IOC match for this detection.</div>}</div>}
      {tab === 'notes' && <div>{(alert.notes || []).length ? alert.notes.map((note, i) => <div key={i} style={{ padding: 9, background: '#060e1a', borderRadius: 6, marginBottom: 6, color: '#cbd5e1', fontSize: 11 }}>{note.text}<div style={{ color: '#64748b' }}>{new Date(note.at).toLocaleString()}</div></div>) : <div style={{ color: '#64748b' }}>No analyst notes.</div>}</div>}

      {/* Actions */}
      {tab === 'response' && alert.resourceType === 'incident' && <div style={{ color: '#94a3b8', fontSize: 11 }}>Incident response and assignment are handled by the SOC Manager and assigned L4 Threat Intelligence analyst.</div>}
      {tab === 'response' && alert.resourceType !== 'incident' && <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
        {[
          alert.eventCategory === 'malware' && !alert.quarantined && { action: 'quarantine', label: '🔒 Quarantine', color: '#f59e0b' },
          !alert.isolationStatus && { action: 'isolate', label: '🚫 Isolate System', color: '#f87171' },
          alert.isolationStatus === 'isolated' && { action: 'reconnect', label: '🔗 Reconnect', color: '#34d399' },
          alert.srcip && { action: 'block_ip', label: '⛔ Block IP', color: '#f87171' },
          alert.eventCategory === 'usb' && { action: 'block_usb', label: '🔌 Block USB', color: '#f59e0b' },
          { action: 'ignore', label: '✓ False Positive', color: '#6b7280' },
        ].filter(Boolean).map(b => (
          <button key={b.action} onClick={() => onAction(alert._id, b.action)}
            style={{
              fontSize: 10, padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
              border: `1px solid ${b.color}44`, background: `${b.color}15`, color: b.color
            }}>
            {b.label}
          </button>
        ))}
      </div>}

      {/* Raw log */}
      {tab === 'raw' && (alert.rawEvent || alert.full_log) && (
        <details>
          <summary style={{ fontSize: 11, color: '#1e40af', cursor: 'pointer', marginBottom: 6 }}>Raw Log</summary>
          <pre style={{
            background: '#020b14', color: '#7dd3fc', fontSize: 10, padding: 10,
            borderRadius: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all'
          }}>
            {typeof alert.rawEvent === 'object' ? JSON.stringify(alert.rawEvent, null, 2) : alert.full_log}
          </pre>
        </details>
      )}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────
export default function ThreatInvestigationPage({ defaultTab, standalone, pageTitle, pageDescription }) {
  const { user } = useAuth();
  const location = useLocation();
  const isStandalone = standalone || location.pathname.includes('correlation');
  const isThreatIntelligence = location.pathname.includes('/company-admin/threat-intelligence');
  const [alerts, setAlerts] = useState([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [selected, setSelected] = useState(null);
  const [page, setPage] = useState(1);
  const [correlation, setCorrelation] = useState([]);
  const [corrStats, setCorrStats] = useState(null);

  // Filters
  const [search, setSearch] = useState('');
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [status, setStatus] = useState('');
  const [from, setFrom] = useState('');
  const [to, setTo] = useState('');
  const [sourceType, setSourceType] = useState('');
  const [eventAction, setEventAction] = useState('');
  const [iocMatch, setIocMatch] = useState('');
  const [username, setUsername] = useState('');
  const [hostname, setHostname] = useState('');
  const [sourceIp, setSourceIp] = useState('');
  const [destinationIp, setDestinationIp] = useState('');
  const [mitreTechnique, setMitreTechnique] = useState('');
  const [activeTab, setActiveTab] = useState(isStandalone ? 'correlation' : (defaultTab || 'timeline'));
  const LIMIT = 30;
  const searchRef = useRef(null);

  const loadAlerts = useCallback(async () => {
    setLoading(true);
    try {
      const q = new URLSearchParams({ page, limit: LIMIT });
      if (!isThreatIntelligence) q.set('mode', 'investigation');
      if (severity) q.set('severity', severity);
      if (status) q.set('status', status);
      if (category) q.set('category', category);
      if (from) q.set('from', new Date(from).toISOString());
      if (to) q.set('to', new Date(to).toISOString());
      if (search) q.set('search', search);
      if (!isThreatIntelligence) {
        if (sourceType) q.set('sourceType', sourceType);
        if (eventAction) q.set('action', eventAction);
        if (iocMatch) q.set('iocMatch', iocMatch);
        if (username) q.set('username', username);
        if (hostname) q.set('hostname', hostname);
        if (sourceIp) q.set('sourceIp', sourceIp);
        if (destinationIp) q.set('destinationIp', destinationIp);
        if (mitreTechnique) q.set('mitreTechnique', mitreTechnique);
      }
      const res = await api.get(`${isThreatIntelligence ? '/soc-manager/threat-intelligence' : '/alerts'}?${q}`);
      const sourceList = isThreatIntelligence ? (res.data.items || []) : (res.data.alerts || []);
      const list = isThreatIntelligence ? sourceList.map(incident => ({
        ...incident,
        resourceType: 'incident',
        description: incident.title || incident.description || 'Threat Intelligence Incident',
        detailDescription: incident.description,
        eventCategory: incident.category || 'threat_intelligence',
        sourceType: 'THREAT_INTELLIGENCE',
        action: incident.status || 'open',
        agentName: incident.agentName || incident.affectedEndpoint,
        iocMatched: Boolean(incident.iocs?.length),
        iocMatches: incident.iocs || [],
        correlationIds: incident.correlationId ? [incident.correlationId] : [],
        createdAt: incident.lastEventAt || incident.createdAt,
      })) : sourceList;
      setAlerts(list);
      setTotal(res.data.total || 0);
      setSelected(current => current && list.find(item => item._id === current._id) || null);
    } catch (err) {
      console.error('[investigation] alerts error:', err.message);
    } finally {
      setLoading(false);
    }
  }, [page, severity, status, category, from, to, search, sourceType, eventAction, iocMatch, username, hostname, sourceIp, destinationIp, mitreTechnique, isThreatIntelligence]);

  const loadCorrelation = useCallback(async () => {
    try {
      const [evRes, stRes] = await Promise.all([
        api.get('/correlation?limit=20'),
        api.get('/correlation/stats'),
      ]);
      setCorrelation(evRes.data.events || []);
      setCorrStats(stRes.data);
    } catch { }
  }, []);

  useEffect(() => { loadAlerts(); }, [loadAlerts]);
  useEffect(() => { if (activeTab === 'correlation') loadCorrelation(); }, [activeTab, loadCorrelation]);

  const doAction = async (alertId, action) => {
    try {
      const disruptive = ['quarantine', 'isolate', 'block_ip', 'block_usb'].includes(action);
      if (disruptive && !window.confirm(`Confirm disruptive response action: ${action.replace('_', ' ')}?`)) return;
      const reason = window.prompt(`Reason for ${action.replace('_', ' ')}:`);
      if (!reason?.trim()) return;
      await api.patch(`/dashboard/alerts/${alertId}/action`, { action, reason, confirmed: disruptive });
      loadAlerts();
      setSelected(prev => prev?._id === alertId
        ? {
          ...prev, status: action === 'ignore' ? 'false_positive' : 'investigating',
          quarantined: action === 'quarantine' ? true : prev.quarantined
        }
        : prev);
    } catch (err) { alert(err.response?.data?.message || 'Action failed'); }
  };

  const assignThreatIncident = async incident => {
    try {
      const reason = window.prompt('Assignment reason:', 'Assign to available L4 Threat Intelligence analyst');
      if (reason === null) return;
      await api.post(`/soc-manager/work-items/incident/${incident.resourceId || incident._id}/assign`, {
        reason: reason.trim() || 'Company admin assignment',
      });
      await loadAlerts();
    } catch (err) {
      alert(err.response?.data?.message || 'Unable to assign this incident');
    }
  };

  const runCorrelation = async () => {
    try {
      const res = await api.post('/correlation/run');
      alert(`✅ Detected ${res.data.detected} new correlation(s)`);
      loadCorrelation();
    } catch { alert('Correlation run failed'); }
  };

  const SEV_FILTER = ['', 'critical', 'high', 'medium', 'low'];
  const CAT_FILTER = ['', 'malware', 'network', 'file', 'edr', 'usb', 'system', 'isolation'];
  const STA_FILTER = ['', 'open', 'investigating', 'resolved', 'false_positive'];

  const CORR_SEV_COLOR = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
  const visibleCritical = alerts.filter(alert => alert.severity === 'critical').length;
  const visibleInvestigating = alerts.filter(alert => alert.status === 'investigating').length;
  const visibleIocMatches = alerts.filter(alert => alert.iocMatched === true).length;

  return (
    <div className="investigation-workspace" style={{ height: 'calc(100vh - 80px)', display: 'flex', flexDirection: 'column' }}>
      {/* Header */}
      <div className="investigation-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12, flexShrink: 0 }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, color: '#e0f2fe' }}>
            {isStandalone ? '🔗 Correlation Engine & Attack Chains' : (isThreatIntelligence ? '⌾ Threat Intelligence Incidents' : (pageTitle || '🔍 Threat Investigation'))}
          </h2>
          <div style={{ fontSize: 11, color: '#1e40af', marginTop: 3 }}>
            {isStandalone
              ? 'Multi-step correlation events, attack chain detection, and automated pattern analysis'
              : (isThreatIntelligence ? 'Threat-intelligence incidents · IOC evidence · L4 analyst assignment' : (pageDescription || 'Security detections · Investigation timeline · Correlation evidence'))}
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8 }}>
          <button onClick={isStandalone ? loadCorrelation : loadAlerts} style={{
            fontSize: 11, padding: '5px 12px', borderRadius: 6,
            border: '1px solid #1e3a5f', background: 'none', color: '#60a5fa', cursor: 'pointer'
          }}>↺</button>
        </div>
      </div>

      {!isStandalone && (
        <div className="investigation-kpis">
          {[
            [isThreatIntelligence ? 'Total TI Incidents' : 'Total Detections', total, '#38bdf8'],
            ['Critical on Page', visibleCritical, '#fb7185'],
            ['Investigating', visibleInvestigating, '#a78bfa'],
            [isThreatIntelligence ? 'With IOC Evidence' : 'IOC Matches', visibleIocMatches, '#f59e0b'],
          ].map(([label, value, color]) => (
            <div key={label} className="investigation-kpi">
              <span>{label}</span><strong style={{ color }}>{value}</strong>
            </div>
          ))}
        </div>
      )}

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 0, marginBottom: 12, borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
        {[['timeline', '📋 Timeline'], ['search', '🔍 Search']].map(([t, l]) => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '8px 16px', fontSize: 12, cursor: 'pointer', border: 'none', background: 'none',
            fontWeight: activeTab === t ? 700 : 400,
            color: activeTab === t ? '#60a5fa' : '#64748b',
            borderBottom: activeTab === t ? '2px solid #3b82f6' : '2px solid transparent', marginBottom: -1,
          }}>{l}</button>
        ))}
      </div>

      {/* Timeline + Search tabs share same 2-panel layout */}
      {!isStandalone && (activeTab === 'timeline' || activeTab === 'search') && (
        <>
          {/* Filters bar */}
          <div className="investigation-filters" style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap', flexShrink: 0 }}>
            {activeTab === 'search' && (
              <input ref={searchRef} value={search} onChange={e => setSearch(e.target.value)}
                placeholder="Search description, IP, file, rule…"
                style={{
                  flex: 1, minWidth: 200, padding: '6px 10px', borderRadius: 6, fontSize: 12,
                  background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0',
                  outline: 'none'
                }} />
            )}
            {[
              ['Severity', severity, setSeverity, SEV_FILTER],
              ['Category', category, setCategory, CAT_FILTER],
              ['Status', status, setStatus, STA_FILTER],
              ...(!isThreatIntelligence ? [
                ['Source', sourceType, setSourceType, ['', 'IAM', 'IDS', 'IPS', 'ZEEK', 'THREAT_FEED']],
                ['Action', eventAction, setEventAction, ['', 'detected', 'allowed', 'blocked', 'dropped', 'rejected', 'quarantined']],
                ['IOC Match', iocMatch, setIocMatch, ['', 'true', 'false']],
              ] : []),
            ].map(([label, val, setter, opts]) => (
              <select key={label} value={val} onChange={e => { setter(e.target.value); setPage(1); }}
                style={{
                  padding: '6px 10px', borderRadius: 6, fontSize: 11,
                  background: '#060e1a', border: '1px solid #1e3a5f', color: val ? '#e2e8f0' : '#64748b'
                }}>
                {opts.map(o => <option key={o} value={o}>{o ? o.charAt(0).toUpperCase() + o.slice(1) : label}</option>)}
              </select>
            ))}
            <input type="date" value={from} onChange={e => setFrom(e.target.value)}
              style={{
                padding: '5px 8px', borderRadius: 6, fontSize: 11, background: '#060e1a',
                border: '1px solid #1e3a5f', color: from ? '#e2e8f0' : '#64748b'
              }} />
            <span style={{ color: '#1e3a5f', lineHeight: '32px' }}>→</span>
            <input type="date" value={to} onChange={e => setTo(e.target.value)}
              style={{
                padding: '5px 8px', borderRadius: 6, fontSize: 11, background: '#060e1a',
                border: '1px solid #1e3a5f', color: to ? '#e2e8f0' : '#64748b'
              }} />
            {!isThreatIntelligence && [['User', username, setUsername], ['Hostname', hostname, setHostname], ['Source IP', sourceIp, setSourceIp], ['Destination IP', destinationIp, setDestinationIp], ['MITRE technique', mitreTechnique, setMitreTechnique]].map(([placeholder, value, setter]) => <input key={placeholder} value={value} onChange={e => { setter(e.target.value); setPage(1); }} placeholder={placeholder} style={{ width: 130, padding: '6px 8px', borderRadius: 6, fontSize: 11, background: '#060e1a', border: '1px solid #1e3a5f', color: '#e2e8f0' }} />)}
            {(search || severity || category || status || from || to || sourceType || eventAction || iocMatch || username || hostname || sourceIp || destinationIp || mitreTechnique) && (
              <button onClick={() => { setSearch(''); setSeverity(''); setCategory(''); setStatus(''); setFrom(''); setTo(''); setSourceType(''); setEventAction(''); setIocMatch(''); setUsername(''); setHostname(''); setSourceIp(''); setDestinationIp(''); setMitreTechnique(''); setPage(1); }}
                style={{
                  fontSize: 11, padding: '5px 10px', borderRadius: 6, border: '1px solid #f87171',
                  background: 'none', color: '#f87171', cursor: 'pointer'
                }}>✕ Clear</button>
            )}
          </div>

          {isThreatIntelligence && (
            <div className="ti-table-wrap">
              <table className="ti-incident-table">
                <thead>
                  <tr>
                    <th>Title / ID</th>
                    <th>Company</th>
                    <th>Severity</th>
                    <th>Status</th>
                    <th>Auto-Assigned Analyst</th>
                    <th>Created Time</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {loading ? (
                    <tr><td colSpan="7" className="ti-empty">Loading threat-intelligence incidents…</td></tr>
                  ) : alerts.length === 0 ? (
                    <tr><td colSpan="7" className="ti-empty">No threat-intelligence incidents found.</td></tr>
                  ) : alerts.map(incident => {
                    const severityColor = SEV[incident.severity] || '#38bdf8';
                    const statusColor = incident.status === 'resolved' ? '#34d399' : incident.status === 'investigating' ? '#60a5fa' : '#facc15';
                    return (
                      <tr key={incident._id}>
                        <td>
                          <button className="ti-title-button" onClick={() => setSelected(incident)}>{incident.description}</button>
                          <div className="ti-description" title={incident.detailDescription || ''}>{incident.detailDescription || incident.correlationId || `Incident ${incident._id}`}</div>
                        </td>
                        <td>{incident.companyId?.name || '—'}</td>
                        <td><Badge text={(incident.severity || 'unknown').toUpperCase()} color={severityColor} bg={`${severityColor}18`} /></td>
                        <td><Badge text={(incident.status || 'open').replace(/_/g, ' ').toUpperCase()} color={statusColor} bg="#071524" /></td>
                        <td>
                          {incident.assignedTo ? (
                            <div><strong className="ti-analyst">{incident.assignedTo.name || incident.assignedTo.email}</strong><span className="ti-role">{String(incident.assignedTo.role || 'l4_analyst').replace(/_/g, ' ').toUpperCase()}</span></div>
                          ) : <span className="ti-unassigned">Pending L4 auto-assignment</span>}
                        </td>
                        <td>
                          <span className="ti-date">{new Date(incident.createdAt).toLocaleDateString()}</span>
                          <span className="ti-time">{new Date(incident.createdAt).toLocaleTimeString()}</span>
                        </td>
                        <td><button className="ti-assign-button" onClick={() => assignThreatIncident(incident)}>Assign / Reassign</button></td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {selected && <div className="ti-selected-detail"><AlertDetailPanel alert={selected} onAction={doAction} /></div>}
              <div className="ti-pagination">
                <button onClick={() => setPage(value => Math.max(1, value - 1))} disabled={page === 1}>Previous</button>
                <span>Page {page} of {Math.ceil(total / LIMIT) || 1}</span>
                <button onClick={() => setPage(value => value + 1)} disabled={page >= Math.ceil(total / LIMIT)}>Next</button>
              </div>
            </div>
          )}

          {/* 2-panel layout */}
          {!isThreatIntelligence && <div className="investigation-panels" style={{ flex: 1, display: 'flex', gap: 12, overflow: 'hidden' }}>
            {/* Left: Event list */}
            <div className="investigation-event-panel" style={{
              width: 380, flexShrink: 0, background: '#0c1a2e', border: '1px solid #294765',
              borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden'
            }}>
              <div style={{
                padding: '10px 14px', borderBottom: '1px solid #1e3a5f', display: 'flex',
                justifyContent: 'space-between', alignItems: 'center', flexShrink: 0
              }}>
                <span style={{ fontSize: 12, color: '#93c5fd', fontWeight: 600 }}>{isThreatIntelligence ? 'Threat Intelligence Incidents' : 'Security Detections'}</span>
                <span style={{ fontSize: 11, color: '#1e40af' }}>{total} total</span>
              </div>
              <div style={{ flex: 1, overflowY: 'auto' }}>
                {loading ? (
                  <div style={{ color: '#1e40af', fontSize: 13, padding: 20, textAlign: 'center' }}>Loading…</div>
                ) : alerts.length === 0 ? (
                  <div style={{ color: '#1e3a5f', fontSize: 13, padding: 20, textAlign: 'center' }}>{isThreatIntelligence ? 'No threat-intelligence incidents found.' : 'No actionable detections found.'}</div>
                ) : alerts.map(a => (
                  <TimelineEvent key={a._id} alert={a} selected={selected?._id === a._id}
                    onClick={() => setSelected(a)} />
                ))}
              </div>
              {/* Pagination */}
              <div style={{
                display: 'flex', justifyContent: 'center', gap: 8, padding: 10,
                borderTop: '1px solid #1e3a5f', flexShrink: 0
              }}>
                <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                  style={{
                    fontSize: 11, padding: '3px 10px', borderRadius: 4, border: '1px solid #1e3a5f',
                    background: 'none', color: page === 1 ? '#1e3a5f' : '#60a5fa', cursor: page === 1 ? 'not-allowed' : 'pointer'
                  }}>←</button>
                <span style={{ fontSize: 11, color: '#1e40af', lineHeight: '24px' }}>{page}/{Math.ceil(total / LIMIT) || 1}</span>
                <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / LIMIT)}
                  style={{
                    fontSize: 11, padding: '3px 10px', borderRadius: 4, border: '1px solid #1e3a5f',
                    background: 'none', color: page >= Math.ceil(total / LIMIT) ? '#1e3a5f' : '#60a5fa',
                    cursor: page >= Math.ceil(total / LIMIT) ? 'not-allowed' : 'pointer'
                  }}>→</button>
              </div>
            </div>

            {/* Right: Detail */}
            <div className="investigation-detail-panel" style={{
              flex: 1, background: '#0c1a2e', border: '1px solid #294765',
              borderRadius: 10, overflow: 'hidden'
            }}>
              <AlertDetailPanel alert={selected} onAction={doAction} />
            </div>
          </div>}
        </>
      )}

      {/* Correlation Tab */}
      {(isStandalone || activeTab === 'correlation') && (
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {/* Stats row */}
          {corrStats && (
            <div style={{ display: 'flex', gap: 10, marginBottom: 16, flexWrap: 'wrap' }}>
              {[
                { label: 'Total (7d)', value: corrStats.total, color: '#60a5fa' },
                { label: 'Open Critical', value: corrStats.openCritical, color: '#f87171' },
                { label: 'Patterns', value: (corrStats.byPattern || []).length, color: '#a78bfa' },
              ].map(c => (
                <div key={c.label} style={{
                  background: '#0c1a2e', border: '1px solid #1e3a5f',
                  borderRadius: 10, padding: '14px 18px', minWidth: 140
                }}>
                  <div style={{ fontSize: 26, fontWeight: 700, color: c.color }}>{c.value ?? '—'}</div>
                  <div style={{ fontSize: 11, color: '#1e40af', marginTop: 2 }}>{c.label}</div>
                </div>
              ))}
              <div style={{ display: 'flex', alignItems: 'center', marginLeft: 'auto' }}>
                <button onClick={runCorrelation} style={{
                  fontSize: 11, padding: '7px 16px',
                  borderRadius: 6, border: '1px solid #1e40af', background: '#1d4ed822',
                  color: '#93c5fd', cursor: 'pointer', fontWeight: 600
                }}>
                  ⚡ Run Correlation Engine
                </button>
              </div>
            </div>
          )}

          {/* Correlation events list */}
          {correlation.length === 0 ? (
            <div style={{
              background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10,
              padding: 40, textAlign: 'center', color: '#1e40af', fontSize: 14
            }}>
              <div style={{ fontSize: 40, marginBottom: 12 }}>🔗</div>
              <div>No multi-step attack chains detected yet.</div>
              <div style={{ fontSize: 12, color: '#64748b', marginTop: 8 }}>
                Run the correlation engine or wait for it to auto-run every 5 minutes.
              </div>
            </div>
          ) : correlation.map(ev => (
            <div key={ev._id} style={{
              background: '#0c1a2e', border: `1px solid ${CORR_SEV_COLOR[ev.severity] || '#1e3a5f'}44`,
              borderRadius: 10, padding: '14px 18px', marginBottom: 10
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 8 }}>
                <div>
                  <div style={{ fontSize: 14, color: '#e0f2fe', fontWeight: 700 }}>{ev.patternName}</div>
                  <div style={{ fontSize: 12, color: '#64748b', marginTop: 4 }}>{ev.description}</div>
                  <div style={{ fontSize: 11, color: '#1e40af', marginTop: 6 }}>
                    System: <span style={{ color: '#e2e8f0' }}>{ev.agentName || '—'}</span>
                    &nbsp;·&nbsp; Confidence: <span style={{ color: '#a78bfa' }}>{ev.confidence}%</span>
                    &nbsp;·&nbsp; Pattern: <span style={{ fontFamily: 'monospace', color: '#f59e0b' }}>{ev.patternId}</span>
                    {ev.alertIds?.length > 0 && ` · Events: ${ev.alertIds.length}`}
                  </div>
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 6 }}>
                  <Badge text={ev.severity?.toUpperCase()}
                    color={CORR_SEV_COLOR[ev.severity] || '#64748b'}
                    bg={SEVBG[ev.severity] || '#1e3a5f'} />
                  <Badge text={ev.status?.toUpperCase()} color="#93c5fd" bg="#1e3a5f" />
                  <span style={{ fontSize: 9, color: '#64748b' }}>{new Date(ev.createdAt).toLocaleString()}</span>
                </div>
              </div>
              {/* Linked alerts */}
              {ev.alertIds?.length > 0 && (
                <div style={{ marginTop: 10, display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {ev.alertIds.slice(0, 5).map((a, i) => (
                    <div key={i} style={{
                      fontSize: 10, padding: '3px 8px', borderRadius: 4,
                      background: '#060e1a', color: '#64748b', border: '1px solid #1e3a5f', cursor: 'pointer'
                    }}
                      onClick={() => { setSelected(a); setActiveTab('timeline'); }}>
                      {a.description ? a.description.slice(0, 40) + '…' : a._id?.slice(0, 8)}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
      <style>{`
        .investigation-workspace{min-width:0;color:#dbeafe}
        .investigation-header{padding:14px 16px;border:1px solid #1e3a5f;border-radius:12px;background:linear-gradient(135deg,#0c1a2e,#101d35);box-shadow:0 12px 28px rgba(0,0,0,.18)}
        .investigation-kpis{display:grid;grid-template-columns:repeat(4,minmax(130px,1fr));gap:10px;margin-bottom:12px}
        .investigation-kpi{padding:10px 13px;border:1px solid #1e3a5f;border-radius:9px;background:#0a1728;display:flex;align-items:center;justify-content:space-between;gap:10px}
        .investigation-kpi span{color:#8fa4bd;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
        .investigation-kpi strong{font-size:21px}
        .investigation-filters{padding:10px;border:1px solid #1e3a5f;border-radius:10px;background:#091624}
        .investigation-event-panel,.investigation-detail-panel{box-shadow:0 14px 30px rgba(0,0,0,.2)}
        .ti-table-wrap{flex:1;min-height:0;overflow:hidden;border:1px solid #294765;border-radius:12px;background:#0c192c;box-shadow:0 16px 34px rgba(0,0,0,.22);max-width:100%}
        .ti-incident-table{width:100%;border-collapse:separate;border-spacing:0;table-layout:fixed}
        .ti-incident-table th{padding:15px 14px;text-align:left;color:#7dd3fc;background:#10233c;font-size:11px;font-weight:900;letter-spacing:.02em;border-bottom:1px solid #294765;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
        .ti-incident-table th:first-child{width:28%}.ti-incident-table th:nth-child(2){width:8%}.ti-incident-table th:nth-child(3){width:8%;text-align:center}.ti-incident-table th:nth-child(4){width:14%;text-align:center}.ti-incident-table th:nth-child(5){width:19%}.ti-incident-table th:nth-child(6){width:12%}.ti-incident-table th:last-child{width:11%;text-align:center}
        .ti-incident-table td{padding:20px 14px;border-bottom:1px solid #1e3a5f;color:#cbd5e1;font-size:13px;vertical-align:middle;min-width:0;overflow:hidden}
        .ti-incident-table td:nth-child(3),.ti-incident-table td:nth-child(4),.ti-incident-table td:last-child{text-align:center}
        .ti-incident-table tbody tr{background:#0c192c;transition:background .15s}.ti-incident-table tbody tr:nth-child(even){background:#0e1d31}.ti-incident-table tbody tr:hover{background:#132842}
        .ti-title-button{display:block;width:100%;padding:0;border:0;background:none;color:#c4b5fd;text-align:left;font-size:13px;line-height:1.35;font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;cursor:pointer}
        .ti-title-button:hover{color:#ddd6fe;text-decoration:underline;text-underline-offset:3px}
        .ti-description{margin-top:8px;color:#8293aa;font-size:12px;line-height:1.45;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}
        .ti-analyst{display:block;color:#67e8f9;font-size:13px;line-height:1.25;font-weight:900;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%}.ti-role{display:block;margin-top:7px;color:#64748b;font-size:10px;letter-spacing:.06em;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.ti-unassigned{color:#f59e0b;font-size:11px}
        .ti-date,.ti-time{display:block;white-space:nowrap}.ti-date{font-size:13px;color:#dbeafe}.ti-time{margin-top:6px;color:#71839b;font-size:11px}
        .ti-assign-button,.ti-pagination button{padding:9px 14px;border:0;border-radius:8px;background:linear-gradient(135deg,#7c3aed,#6d28d9);color:white;font-size:12px;font-weight:900;cursor:pointer;box-shadow:0 8px 20px rgba(124,58,237,.22);white-space:nowrap;max-width:100%;overflow:hidden;text-overflow:ellipsis}.ti-assign-button:hover,.ti-pagination button:hover:not(:disabled){filter:brightness(1.12);transform:translateY(-1px)}.ti-pagination button:disabled{opacity:.35;cursor:not-allowed;transform:none}
        .ti-empty{padding:42px!important;text-align:center;color:#64748b!important}.ti-pagination{display:flex;align-items:center;justify-content:center;gap:12px;padding:14px;color:#94a3b8;font-size:11px}.ti-selected-detail{border-top:1px solid #294765;max-height:420px;overflow:auto;background:#091624}
        @media(max-width:1050px){.investigation-kpis{grid-template-columns:repeat(2,1fr)}.investigation-panels{overflow:auto!important;flex-direction:column}.investigation-event-panel{width:100%!important;min-height:360px}.investigation-detail-panel{min-height:460px;overflow:visible!important}.investigation-workspace{height:auto!important;min-height:calc(100vh - 80px)}}
        @media(max-width:620px){.investigation-kpis{grid-template-columns:1fr}.investigation-header{align-items:flex-start!important}.investigation-filters>input,.investigation-filters>select{width:100%!important;min-width:0!important}}
      `}</style>
    </div>
  );
}
