/**
 * Memory Overflow Detection — canonical capability ID 29
 *
 * 100% Self-Contained Enterprise SOC Memory Overflow Detection Module
 * Linked to the capability 29 API, MongoDB Alert Query, and Socket.io real-time streaming.
 * Architecture & Design System mirror DNS Sinkhole (Capability ID: 38) & DNS Cache Poisoning (Capability ID: 37)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens ──────────────────────────────────────────────────────
const MON = {
  bg: '#060d16',
  card: '#0b1929',
  card2: '#0f233a',
  border: '#1a3050',
  line: '#162942',
  text: '#e2e8f0',
  muted: '#8ea0b8',
  sub: '#64748b',
  blue: '#38bdf8',
  cyan: '#22d3ee',
  green: '#34d399',
  yellow: '#fbbf24',
  orange: '#fb923c',
  red: '#f87171',
  purple: '#a78bfa',
  accent: '#6366f1',
};

const SEV_COLOR = {
  critical: MON.red,
  high: MON.orange,
  medium: MON.yellow,
  low: MON.green,
  info: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
};

function memoryTelemetryValue(row = {}, ...keys) {
  const rawEvent = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nestedRaw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  const raw = row.raw && typeof row.raw === 'object' ? row.raw : {};
  for (const source of [row, rawEvent, nestedRaw, raw]) {
    for (const key of keys) {
      const value = source?.[key];
      if (value !== undefined && value !== null && value !== '') return value;
    }
  }
  return undefined;
}

function isMemoryOverflowEvidence(row = {}) {
  const source = String(memoryTelemetryValue(row, 'source', 'log_source') || '').toLowerCase();
  const category = String(memoryTelemetryValue(row, 'category', 'eventCategory', 'event_category') || '').toLowerCase();
  const subCategory = String(memoryTelemetryValue(row, 'subCategory', 'sub_category') || '').toLowerCase();
  const eventType = String(memoryTelemetryValue(row, 'eventType', 'event_type') || '').toLowerCase();
  const ruleId = String(memoryTelemetryValue(row, 'detectionRuleId', 'detection_rule_id', 'ruleId', 'rule_id') || '').toLowerCase();
  const metricType = memoryTelemetryValue(row, 'memoryMetricType', 'memory_metric_type');
  return source === 'memory_overflow_detector'
    || category === 'memory'
    || /memory[ _-]*(?:overflow|metrics?)/i.test(subCategory)
    || /^memory(?:[._ -]|$)/i.test(eventType)
    || /^(?:mem-|memory_overflow_)/i.test(ruleId)
    || ['host', 'process'].includes(String(metricType || '').toLowerCase());
}

function formatMemorySize(row = {}) {
  const explicit = memoryTelemetryValue(row, 'memorySize', 'memory_size');
  if (explicit !== undefined) return String(explicit);
  const memoryMb = Number(memoryTelemetryValue(row, 'processMemoryMb', 'memory_mb', 'currentMb', 'current_mb', 'allocatedMemoryMb', 'allocated_memory_mb'));
  if (Number.isFinite(memoryMb)) return `${memoryMb.toFixed(memoryMb >= 10 ? 1 : 2)} MB`;
  const rssBytes = Number(memoryTelemetryValue(row, 'processRssBytes', 'process_rss_bytes', 'memoryBytes', 'memory_bytes'));
  return Number.isFinite(rssBytes) ? `${(rssBytes / 1048576).toFixed(1)} MB` : 'Not reported';
}

function normalizeMemoryTelemetry(row = {}) {
  const processValue = memoryTelemetryValue(row, 'processName', 'process_name', 'process', 'executable', 'image');
  const processName = typeof processValue === 'object'
    ? processValue.name || processValue.path
    : processValue;
  const pid = memoryTelemetryValue(row, 'pid', 'processId', 'process_id', 'targetPid', 'target_pid', 'sourcePid', 'source_pid');
  const riskValue = Number(memoryTelemetryValue(row, 'riskScore', 'risk_score', 'score', 'threatScore', 'threat_score'));
  const system = row.systemId && typeof row.systemId === 'object' ? row.systemId : {};
  const severity = String(memoryTelemetryValue(row, 'severity', 'level') || 'info').toLowerCase();
  const memoryMetricType = memoryTelemetryValue(row, 'memoryMetricType', 'memory_metric_type');
  const detectionRule = memoryTelemetryValue(row, 'detectionRuleId', 'detection_rule_id', 'ruleId', 'rule_id', 'ruleName', 'rule_name', 'eventType', 'event_type', 'type') || 'MEMORY_TELEMETRY';

  return {
    ...row,
    processName: processName || 'Unknown process',
    pid: pid ?? '—',
    riskScore: Number.isFinite(riskValue) ? riskValue : 0,
    osType: memoryTelemetryValue(row, 'osType', 'os_type', 'os', 'platform', 'operatingSystem', 'operating_system') || system.osType || system.os || 'Unknown',
    hostname: memoryTelemetryValue(row, 'hostname', 'host', 'system_name', 'agentName') || system.hostname || system.name || 'Unknown endpoint',
    username: memoryTelemetryValue(row, 'username', 'user', 'processUser', 'process_user', 'accountName', 'account_name', 'userName', 'user_name') || 'Not reported by agent',
    eventType: memoryTelemetryValue(row, 'eventType', 'event_type', 'detectionRuleId', 'detection_rule_id', 'ruleId', 'rule_id', 'type') || 'Memory telemetry',
    ruleId: detectionRule,
    detectionRule,
    description: memoryTelemetryValue(row, 'description', 'message', 'full_log') || 'Memory telemetry received from endpoint',
    memorySize: formatMemorySize(row),
    memoryMetricType,
    severity: SEV_COLOR[severity] ? severity : 'info',
    status: memoryTelemetryValue(row, 'status') || (memoryMetricType ? 'telemetry' : 'open'),
    createdAt: memoryTelemetryValue(row, 'createdAt', 'eventTimestamp', 'event_timestamp', 'timestamp') || row.createdAt,
  };
}

function MiniSparkline({ data = [5, 9, 7, 14, 12, 18, 15, 22], color = MON.cyan, height = 30 }) {
  const max = Math.max(...data, 1);
  const min = Math.min(...data, 0);
  const points = data.map((val, idx) => {
    const x = (idx / (data.length - 1)) * 100;
    const y = height - ((val - min) / (max - min || 1)) * (height - 6) - 3;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 100 ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      <polyline fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" points={points} />
    </svg>
  );
}

function DonutChart({ value, maxValue, color, label, size = 110 }) {
  const pct = maxValue > 0 ? Math.min(value / maxValue, 1) : 0;
  const r = 38, cx = 55, cy = 55;
  const circ = 2 * Math.PI * r;
  const dash = pct * circ;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <svg width={size} height={size} viewBox="0 0 110 110">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="#0f233a" strokeWidth="12" />
        <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth="12"
          strokeDasharray={`${dash} ${circ - dash}`} strokeDashoffset={circ * 0.25}
          strokeLinecap="round" style={{ transition: 'stroke-dasharray 0.6s ease' }} />
        <text x="55" y="50" textAnchor="middle" fill="#f1f5f9" fontSize="14" fontWeight="900">
          {value >= 1000 ? `${(value / 1000).toFixed(1)}K` : value}
        </text>
        <text x="55" y="66" textAnchor="middle" fill="#64748b" fontSize="8">Total</text>
      </svg>
      <div style={{ fontSize: 11, color: MON.muted, marginTop: 4, textAlign: 'center' }}>{label}</div>
    </div>
  );
}

function MultiLineChart({ datasets = [], height = 180 }) {
  const all = datasets.flatMap(d => d.data);
  const maxV = Math.max(...all, 1);
  const w = 100, h = height;
  const toPoints = (data) => data.map((v, i) => {
    const x = (i / (data.length - 1)) * w;
    const y = h - (v / maxV) * (h - 8) - 4;
    return `${x},${y}`;
  }).join(' ');
  return (
    <svg viewBox={`0 0 100 ${h}`} width="100%" height={h} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      {[20, 40, 60, 80].map(y => (
        <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="#162942" strokeWidth="0.4" />
      ))}
      {datasets.map((ds, i) => (
        <polyline key={i} fill="none" stroke={ds.color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" points={toPoints(ds.data)} opacity="0.9" />
      ))}
    </svg>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function MemoryOverflowDetailModal({ log, onClose, onUpdated }) {
  const { user } = useAuth();
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState('');
  const [existingNotes, setExistingNotes] = useState(Array.isArray(log?.notes) ? log.notes : []);
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedTo?.name || log?.assignedTo?.email || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [notesSaved, setNotesSaved] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);
  const [savingAction, setSavingAction] = useState(false);

  if (!log) return null;

  const sev = (log.severity || 'high').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.orange;
  const sevBg = SEV_BG[sev] || 'rgba(251, 146, 60, 0.15)';
  const processName = log.processName || log.process || log.rawEvent?.process_name || 'unknown.exe';
  const pid = log.pid || log.processId || '—';
  const hostname = log.hostname || log.agentName || log.systemId?.name || 'endpoint-unknown';
  const memAddr = log.memoryAddress || log.rawEvent?.memory_address || 'Not reported';
  const evidence = log.detectionEvidence || log.rawEvent?.detectionEvidence || log.rawEvent?.raw?.evidence || {};
  const eventTime = log.eventTimestamp || log.createdAt || log.timestamp;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint Profile' },
    { id: 'memory-regions', label: '🧠 4. Memory Regions & RWX' },
    { id: 'process', label: '⚙️ 5. Process & Commands' },
    { id: 'network', label: '🔗 6. Network Context' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'threat-intel', label: '🧠 8. Exploit Analysis' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const handleTerminateProcess = async () => {
    setActionMsg(`Not sent: no terminate-process executor is configured for ${processName} (PID ${pid}) on ${hostname}.`);
  };

  const handleIsolateEndpoint = async () => {
    setActionMsg(`Not sent: no endpoint-isolation executor is configured for ${hostname}.`);
  };

  const canManage = ['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(user?.role);
  const applyEventAction = async (action, body = {}) => {
    if (!log._id) return setActionMsg('This event has no persistent alert ID.');
    setSavingAction(true);
    setActionMsg(null);
    try {
      const response = await api.post(`/memory-overflow/events/${log._id}/${action}`, body);
      const updated = response.data?.event;
      if (updated) {
        setCaseStatus(updated.status || caseStatus);
        setAssignedAnalyst(updated.assignedTo?.name || updated.assignedTo?.email || assignedAnalyst);
        onUpdated?.(updated);
      }
      setActionMsg(action === 'create-incident' ? 'Incident created successfully.' : 'Alert updated successfully.');
    } catch (error) {
      setActionMsg(error.response?.data?.message || 'The requested alert action failed.');
    } finally {
      setSavingAction(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!analystNotes.trim() || !log._id) return;
    setSavingAction(true);
    setNotesSaved(false);
    try {
      const response = await api.post(`/memory-overflow/events/${log._id}/notes`, { text: analystNotes.trim() });
      setExistingNotes(response.data?.event?.notes || existingNotes);
      onUpdated?.(response.data?.event);
      setAnalystNotes('');
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 2000);
    } catch (error) {
      setActionMsg(error.response?.data?.message || 'Case note could not be saved.');
    } finally {
      setSavingAction(false);
    }
  };

  const handleDownload = (format) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(log, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `memory_overflow_${log._id || 'event'}_${processName}.${format.toLowerCase()}`);
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0,0,0,0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>💾</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Memory Overflow Forensic Panel — {processName} (PID {pid})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: `${MON.purple}15`, border: `1px solid ${MON.purple}33` }}>
                  {log.eventType || log.ruleId || 'Buffer Overflow Indicator'}
                </span>
                {(log.isSynthetic || log.isSimulated) && <span style={{ fontSize: 10, fontWeight: 900, color: MON.yellow, border: `1px solid ${MON.yellow}`, borderRadius: 4, padding: '2px 8px' }}>SIMULATED</span>}
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{hostname}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'Not reported'}</strong> | Base Address: <strong style={{ color: MON.red }}>{memAddr}</strong> | Memory Allocated: <strong style={{ color: MON.yellow }}>{log.memorySize || 'Not reported'}</strong>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
          </div>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map((t) => (
            <button key={t.id} type="button" onClick={() => setActiveTab(t.id)} style={{ padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600, color: activeTab === t.id ? MON.cyan : MON.muted, background: activeTab === t.id ? MON.bg : 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Body */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: MON.bg }}>

          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
                {[
                  ['Process Name', processName, MON.cyan],
                  ['Process ID (PID)', pid, MON.blue],
                  ['Detection Category', log.eventType || 'Stack Overflow Indicator', MON.orange],
                  ['Target Memory Address', memAddr, MON.red],
                  ['Memory Size / Growth', log.memorySize || 'Not reported', MON.yellow],
                  ['Protection Status', evidence.protection || evidence.protection_flags || 'Not reported', evidence.protection || evidence.protection_flags ? MON.red : MON.muted],
                  ['Status', caseStatus, MON.green],
                  ['Assigned Analyst', assignedAnalyst, MON.purple],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-all' }}>{val}</div>
                  </div>
                ))}
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Alert Summary & Kernel Exception Telemetry:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.description || 'No normalized event description was reported by the endpoint.'}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                <button type="button" disabled={savingAction || caseStatus === 'investigating'} onClick={() => applyEventAction('acknowledge')} style={{ background: MON.blue, color: '#001018', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  Acknowledge & Assign to Me
                </button>
                {canManage && <button type="button" disabled={savingAction || caseStatus === 'resolved'} onClick={() => applyEventAction('resolve', { reason: 'Resolved from Memory Overflow Detection dashboard' })} style={{ background: MON.green, color: '#00130d', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  Resolve Alert
                </button>}
                {canManage && <button type="button" disabled={savingAction || Boolean(log.incidentId)} onClick={() => applyEventAction('create-incident')} style={{ background: MON.purple, color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  Create Incident
                </button>}
                <button type="button" onClick={handleTerminateProcess} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  🛑 Terminate Malicious Process
                </button>
                <button type="button" onClick={handleIsolateEndpoint} style={{ background: MON.orange, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  🔌 Isolate Endpoint Host
                </button>
                {actionMsg && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700, alignSelf: 'center' }}>{actionMsg}</span>}
              </div>
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Memory Overflow & Process Execution Chronology</div>
              {[
                { type: log.eventType || 'Memory event', time: eventTime ? new Date(eventTime).toLocaleTimeString() : 'Not reported', title: log.ruleId || 'Memory detection', desc: log.description || 'No event description reported.', col: SEV_COLOR[sev] || MON.red },
              ].map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col, background: `${ev.col}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content', whiteSpace: 'nowrap' }}>{ev.type}</span>
                  <div style={{ color: MON.muted, fontWeight: 800, fontSize: 11, minWidth: 90 }}>{ev.time}</div>
                  <div style={{ width: 2, background: ev.col, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{ev.title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{ev.desc}</div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 3: ENDPOINT PROFILE */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Endpoint Memory Profile & Host Telemetry</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', hostname],
                  ['Operating System', log.osType || log.os || 'Not reported'],
                  ['Total Physical RAM', log.memoryTotalBytes ? `${(log.memoryTotalBytes / 1073741824).toFixed(2)} GB` : 'Not reported'],
                  ['RAM In Use', log.processMemoryPercent != null ? `${log.processMemoryPercent}%` : 'Not reported'],
                  ['Available Memory', log.memoryAvailableBytes ? `${(log.memoryAvailableBytes / 1073741824).toFixed(2)} GB` : 'Not reported'],
                  ['Page File / Swap', log.swapPercent != null ? `${log.swapPercent}%` : 'Not reported'],
                  ['Memory Pressure', log.processMemoryPercent != null ? `${log.processMemoryPercent}%` : 'Not reported'],
                  ['Kernel Page Faults', log.pageFaults ?? 'Not reported'],
                  ['DEP (Data Execution Prevention)', log.depStatus || 'Telemetry unavailable'],
                  ['ASLR (Address Space Layout Randomization)', log.aslrStatus || 'Telemetry unavailable'],
                  ['Agent ID', log.agentId || '—'],
                  ['Risk Score', `${log.riskScore ?? 0}/100`],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4, wordBreak: 'break-all' }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: MEMORY REGIONS & RWX */}
          {activeTab === 'memory-regions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Memory Regions & RWX Protection Analysis</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Target Memory Region Metadata</div>
                  {[
                    ['Base Address', memAddr],
                    ['Region Size', log.memorySize || evidence.region_size || 'Not reported'],
                    ['Allocation Type', evidence.allocation_type || 'Not reported'],
                    ['Protection Flags', evidence.protection || 'Not reported'],
                    ['State', evidence.state || 'Not reported'],
                    ['Memory Type', evidence.memory_type || 'Not reported'],
                    ['Executable Regions', log.executableRegionCount ?? evidence.executable_region_count ?? 'Not reported'],
                    ['RWX Regions', log.rwxRegionCount ?? evidence.rwx_region_count ?? 'Not reported'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: k.includes('Protection') || k.includes('W+X') ? MON.red : MON.text }}>{v}</strong>
                    </div>
                  ))}
                </div>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Defensive Region Evidence</div>
                  <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.red, fontFamily: 'monospace', fontSize: 10, margin: 0, maxHeight: 200, overflowY: 'auto' }}>
{JSON.stringify({ address: memAddr, evidence, note: 'Raw process-memory content is not collected by normal monitoring.' }, null, 2)}
                  </pre>
                  <div style={{ marginTop: 10, fontSize: 10, color: MON.red, fontWeight: 800 }}>
                    Evidence is limited to operating-system metadata and appears only when reported by the endpoint.
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Context & Executable Signature</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Process Hierarchy:</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {log.parentProcessName || 'Not reported'} (PPID {log.parentPid || '—'}) ➔ <strong>{processName} (PID {pid})</strong>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.processCmdline || log.commandLine || 'Command line not reported or redacted by the endpoint.'}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK CONTEXT */}
          {activeTab === 'network' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🔗 Network Context & In-Memory Exfiltration</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Source Host IP', log.srcip || log.sourceIp || 'Not reported'],
                  ['Remote Destination', log.destip ? `${log.destip}${log.destPort ? `:${log.destPort}` : ''}` : 'Not reported'],
                  ['Protocol', log.protocol || 'Not reported'],
                  ['Network Connections', log.processNetworkConnectionCount ?? 'Not reported'],
                  ['Bytes Sent', log.bytesSent ?? 'Not reported'],
                  ['Bytes Received', log.bytesReceived ?? 'Not reported'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4 }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🎯 MITRE ATT&CK Matrix Mappings</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[[log.mitreId || log.mitreTechnique || 'Not mapped', log.technique || 'Telemetry mapping', log.description || 'No MITRE explanation was reported.']].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: EXPLOIT ANALYSIS */}
          {activeTab === 'threat-intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Exploit Analysis & Mitigation Guidance</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  { label: 'Detection Rule', value: log.ruleId || 'Not reported', col: MON.red, desc: log.description || 'No description reported.' },
                  { label: 'Executable Trust', value: log.processSignatureStatus || log.processTrustStatus || 'Not reported', col: MON.orange, desc: 'Signature status is shown only when supplied by the endpoint.' },
                  { label: 'Threat Severity', value: `${sev.toUpperCase()} (${log.riskScore ?? 0}/100)`, col: MON.red, desc: `Detection confidence: ${log.confidenceScore ?? 'Not reported'}` },
                  { label: 'Recommended Action', value: 'Analyst review required', col: MON.green, desc: log.recommendedAction || 'Review the process tree and validate the executable before using an approved containment workflow.' },
                ].map((item) => (
                  <div key={item.label} style={{ background: MON.card, border: `1px solid ${item.col}44`, borderRadius: 8, padding: 16 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <div style={{ fontSize: 11, color: MON.muted, fontWeight: 700 }}>{item.label}</div>
                      <span style={{ color: item.col, fontWeight: 800, fontSize: 13 }}>{item.value}</span>
                    </div>
                    <div style={{ fontSize: 11, color: MON.sub }}>{item.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📦 Alert Evidence & Raw Log Payload</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 10, whiteSpace: 'pre-wrap', margin: 0, maxHeight: 400, overflowY: 'auto' }}>
                  {JSON.stringify(log, null, 2)}
                </pre>
              </div>
              <button type="button" onClick={() => handleDownload('json')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 11, width: 'fit-content' }}>Export Evidence JSON</button>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📝 Analyst Investigation Notes</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Assigned Analyst</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>{assignedAnalyst}</div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Case Status</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4, textTransform: 'capitalize' }}>{caseStatus.replace(/_/g, ' ')}</div>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Detection Rule</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>{log.detectionRuleId || log.ruleId || 'Not reported'}</div>
                </div>
              </div>
              {!!existingNotes.length && <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12 }}>
                <div style={{ color: MON.muted, fontSize: 10, fontWeight: 800, marginBottom: 8 }}>Previous notes</div>
                {existingNotes.map((note, index) => <div key={note._id || index} style={{ color: MON.text, fontSize: 11, padding: '6px 0', borderTop: index ? `1px solid ${MON.line}` : 0 }}>{note.text}<small style={{ display: 'block', color: MON.sub, marginTop: 3 }}>{note.user?.name || note.user?.email || 'SOC analyst'} · {note.at ? new Date(note.at).toLocaleString() : ''}</small></div>)}
              </div>}
              <div style={{ fontSize: 12, color: MON.muted, fontWeight: 700 }}>Investigation Notes:</div>
              <textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} rows={6} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, color: MON.text, padding: 14, fontSize: 12, fontFamily: 'inherit', resize: 'vertical' }} />
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="button" disabled={savingAction || !analystNotes.trim()} onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                  Save Case Notes
                </button>
                {notesSaved && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700 }}>✓ Notes saved to case file</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. LOG MONITOR TABLE (REAL-TIME BACKEND LINKED)
// ═════════════════════════════════════════════════════════════════════════════
export function MemoryOverflowLogMonitor({ alerts = [], memoryMetrics = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [ruleFilter, setRuleFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = alerts.length
    ? alerts
    : memoryMetrics.filter(metric => memoryTelemetryValue(metric, 'memoryMetricType', 'memory_metric_type') === 'process');
  const rows = useMemo(() => effectiveAlerts.map(a => ({
    _id: a._id,
    timestamp: a.createdAt || a.eventTimestamp || a.timestamp,
    severity: (a.severity || 'high').toLowerCase(),
    status: a.status || 'telemetry',
    hostname: a.hostname,
    username: a.username,
    processName: a.processName,
    pid: a.pid,
    eventType: a.eventType,
    detectionRule: a.detectionRule || a.ruleId || a.eventType,
    memorySize: a.memorySize,
    riskScore: a.riskScore ?? 0,
    osType: a.osType,
    raw: a,
  })), [effectiveAlerts]);

  const filtered = useMemo(() => rows.filter(r => {
    if (sevFilter !== 'ALL' && r.severity !== sevFilter.toLowerCase()) return false;
    if (ruleFilter !== 'ALL' && r.eventType !== ruleFilter) return false;
    if (!searchTerm) return true;
    const t = searchTerm.toLowerCase();
    return r.processName.toLowerCase().includes(t) || r.hostname.toLowerCase().includes(t) || String(r.pid).includes(t) || r.eventType.toLowerCase().includes(t);
  }), [rows, searchTerm, sevFilter, ruleFilter]);

  const rules = useMemo(() => ['ALL', ...new Set(rows.map(r => r.eventType).filter(Boolean))], [rows]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}`, flexWrap: 'wrap' }}>
        <input type="text" placeholder="🔍 Search memory overflow logs (Process, PID, Host, Rule)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, minWidth: 200, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {['ALL', 'critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={ruleFilter} onChange={(e) => setRuleFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {rules.map(r => <option key={r}>{r}</option>)}
        </select>
        <span style={{ fontSize: 10, color: MON.muted, alignSelf: 'center', padding: '0 8px' }}>{filtered.length} records</span>
      </div>

      <div style={{ overflowX: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Process Name', 'PID', 'Username', 'Detection Rule', 'Allocated Memory', 'OS'].map(h => <th key={h} style={{ padding: 10, whiteSpace: 'nowrap' }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row.raw)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.cyan, fontWeight: 700 }}>{row.processName}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.purple }}>{row.pid}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, color: MON.orange, fontWeight: 700 }}>{row.detectionRule}</td>
                <td style={{ padding: 10, color: MON.yellow }}>{row.memorySize}</td>
                <td style={{ padding: 10, color: MON.muted }}>{row.osType}</td>
              </tr>
            )) : <tr><td colSpan={6} style={{ padding: 40, textAlign: 'center', color: MON.muted }}>No memory overflow logs found</td></tr>}
          </tbody>
        </table>
      </div>
      {selectedLog && <MemoryOverflowDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. EXECUTIVE REPORT GENERATOR
// ═════════════════════════════════════════════════════════════════════════════
function LegacyMemoryOverflowReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [reportGenerated, setReportGenerated] = useState(false);

  const metrics = useMemo(() => ({
    total: alerts.length,
    bufferOverflows: alerts.filter(a => /buffer|stack/i.test(`${a.eventType || ''} ${a.description || ''}`)).length,
    processInjections: alerts.filter(a => /inject|hollow|reflective/i.test(`${a.eventType || ''} ${a.description || ''}`)).length,
    memoryLeaks: alerts.filter(a => /leak|exhaust/i.test(`${a.eventType || ''} ${a.description || ''}`)).length,
    criticalExploits: alerts.filter(a => a.severity === 'critical').length,
    lsassAttempts: alerts.filter(a => /lsass|credential/i.test(`${a.description || ''} ${a.eventType || ''}`)).length,
    uniqueProcesses: new Set(alerts.map(a => a.processName).filter(Boolean)).size,
    uniqueEndpoints: new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size,
  }), [alerts]);

  const handleGenerate = () => { setGenerating(true); setTimeout(() => { setGenerating(false); setReportGenerated(true); }, 1000); };

  const handleDownload = (format) => {
    if (format === 'CSV') {
      const headers = ['Timestamp', 'Process', 'PID', 'Hostname', 'Detection Rule', 'Memory Size', 'Risk Score', 'Severity', 'Status'];
      const rows = alerts.map(a => [
        `"${a.createdAt || ''}"`, `"${a.processName || ''}"`, `"${a.pid || ''}"`, `"${a.hostname || a.agentName || ''}"`,
        `"${a.eventType || ''}"`, `"${a.memorySize || ''}"`, `"${a.riskScore ?? 0}"`, `"${a.severity || ''}"`, `"${a.status || ''}"`
      ]);
      const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `memory_overflow_report_${reportType}.csv`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } else {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ title: 'Memory Overflow Executive SOC Report', reportType, generatedAt: new Date().toISOString(), metrics, alerts }, null, 2));
      const a = document.createElement('a');
      a.setAttribute('href', dataStr); a.setAttribute('download', `memory_overflow_report_${reportType}.json`);
      document.body.appendChild(a); a.click(); a.remove();
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Memory Overflow & Process Exploitation Executive Report Generator</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate Executive Summary, Buffer Overrun Analytics, and Process Injection Threat Audit Reports</div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 14px', borderRadius: 6, fontSize: 12 }}>
            <option value="daily">Daily Report (24 Hours)</option>
            <option value="weekly">Weekly Executive Summary</option>
            <option value="monthly">Monthly Exploitation Threat Audit</option>
          </select>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
            {generating ? 'Generating...' : '⚡ Generate Report'}
          </button>
        </div>
      </div>

      {reportGenerated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>Memory Overflow Executive Summary ({reportType.toUpperCase()})</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={() => handleDownload('CSV')} style={{ background: MON.green, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
              <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
            {[
              ['Total Memory Events', metrics.total, MON.blue],
              ['Buffer Overflow Events', metrics.bufferOverflows, MON.red],
              ['Process Injections', metrics.processInjections, MON.purple],
              ['LSASS Access Attempts', metrics.lsassAttempts, MON.orange],
              ['Critical Exploits', metrics.criticalExploits, MON.red],
              ['Memory Leaks', metrics.memoryLeaks, MON.yellow],
              ['Targeted Processes', metrics.uniqueProcesses, MON.cyan],
              ['Affected Endpoints', metrics.uniqueEndpoints, MON.green],
            ].map(([label, val, col]) => (
              <div key={label} style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}>
                <div style={{ fontSize: 10, color: MON.muted }}>{label}</div>
                <div style={{ fontSize: 18, color: col, fontWeight: 900, marginTop: 4 }}>{val}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function MemoryOverflowReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={29} alerts={alerts} />;
}

export function MemoryDetectionRulesTab() {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const canManage = ['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(user?.role);
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ name: '', description: '', threshold: 1, timeWindowSeconds: 60, minimumSampleCount: 1, cooldownSeconds: 300, severity: 'high' });

  const load = useCallback(() => api.get('/memory-overflow/rules')
    .then(response => { setRules(response.data?.rules || []); setError(''); })
    .catch(requestError => setError(requestError.response?.data?.message || 'Memory rules could not be loaded'))
    .finally(() => setLoading(false)), []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!companyId) return undefined;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => socket.emit('join:company', companyId);
    socket.on('connect', join);
    socket.on('memory:rule-updated', load);
    join();
    const disconnect = connectSocket(socket);
    return () => { socket.off('connect', join); socket.off('memory:rule-updated', load); disconnect(); };
  }, [companyId, load]);

  const updateRule = async (rule, changes) => {
    setSaving(true); setError('');
    try { await api.patch(`/memory-overflow/rules/${rule._id}`, changes); await load(); }
    catch (requestError) { setError(requestError.response?.data?.message || 'Memory rule update failed'); }
    finally { setSaving(false); }
  };

  const createRule = async event => {
    event.preventDefault();
    if (!form.name.trim()) return setError('Rule name is required');
    setSaving(true); setError('');
    try {
      await api.post('/memory-overflow/rules', { ...form, name: form.name.trim(), description: form.description.trim(), operatingSystems: ['windows', 'linux', 'darwin', 'container'] });
      setForm({ name: '', description: '', threshold: 1, timeWindowSeconds: 60, minimumSampleCount: 1, cooldownSeconds: 300, severity: 'high' });
      await load();
    } catch (requestError) { setError(requestError.response?.data?.message || 'Memory rule creation failed'); }
    finally { setSaving(false); }
  };

  return <div style={{ display: 'grid', gridTemplateColumns: canManage ? '330px 1fr' : '1fr', gap: 14 }}>
    {canManage && <form onSubmit={createRule} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 9, alignSelf: 'start' }}>
      <b style={{ color: MON.cyan }}>Create Custom Memory Rule</b>
      <input required maxLength={160} value={form.name} onChange={event => setForm(current => ({ ...current, name: event.target.value }))} placeholder="Rule name" style={{ background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 5, padding: 8 }} />
      <textarea maxLength={1200} value={form.description} onChange={event => setForm(current => ({ ...current, description: event.target.value }))} placeholder="Detection purpose" style={{ background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 5, padding: 8, minHeight: 70 }} />
      {[['Threshold', 'threshold'], ['Window (seconds)', 'timeWindowSeconds'], ['Minimum samples', 'minimumSampleCount'], ['Cooldown (seconds)', 'cooldownSeconds']].map(([label, key]) => <label key={key} style={{ color: MON.muted, fontSize: 10 }}>{label}<input type="number" min={key === 'cooldownSeconds' ? 0 : 1} value={form[key]} onChange={event => setForm(current => ({ ...current, [key]: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 3, background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 5, padding: 7 }} /></label>)}
      <select value={form.severity} onChange={event => setForm(current => ({ ...current, severity: event.target.value }))} style={{ background: MON.bg, color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 5, padding: 8 }}>{['low', 'medium', 'high', 'critical'].map(value => <option key={value}>{value}</option>)}</select>
      <button disabled={saving} style={{ background: MON.cyan, color: '#001018', border: 0, borderRadius: 5, padding: 9, fontWeight: 900 }}>{saving ? 'Saving…' : 'Create Rule'}</button>
    </form>}
    <section style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'auto' }}>
      <div style={{ padding: 12, fontWeight: 900 }}>Detection Rules ({rules.length})</div>
      <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr 90px 90px 90px 90px', gap: 8, padding: 9, background: MON.card2, color: MON.muted, fontSize: 9 }}><span>ID</span><span>Rule</span><span>Threshold</span><span>Window</span><span>Severity</span><span>Status</span></div>
      {rules.map(rule => <div key={rule._id} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 90px 90px 90px 90px', gap: 8, padding: 10, borderTop: `1px solid ${MON.line}`, alignItems: 'center', fontSize: 10 }}><b style={{ color: MON.cyan }}>{rule.ruleId}</b><span><b>{rule.name}</b><small style={{ display: 'block', color: MON.sub }}>{rule.description}</small></span><span>{rule.threshold ?? '—'}</span><span>{rule.timeWindowSeconds}s</span><b style={{ color: SEV_COLOR[rule.severity] || MON.muted, textTransform: 'uppercase' }}>{rule.severity}</b>{canManage ? <button disabled={saving} onClick={() => updateRule(rule, { enabled: !rule.enabled })} style={{ color: rule.enabled ? MON.green : MON.red, background: 'transparent', border: `1px solid ${rule.enabled ? MON.green : MON.red}`, borderRadius: 4, padding: 5 }}>{rule.enabled ? 'Enabled' : 'Disabled'}</button> : <span>{rule.enabled ? 'Enabled' : 'Disabled'}</span>}</div>)}
      {!rules.length && <div style={{ padding: 24, textAlign: 'center', color: MON.muted }}>{loading ? 'Loading rules…' : 'No memory detection rules configured'}</div>}
      {error && <div style={{ padding: 10, color: MON.red }}>{error}</div>}
    </section>
  </div>;
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERVIEW DASHBOARD — MATCHES DNS SINKHOLE ENTERPRISE SOC DESIGN
// ═════════════════════════════════════════════════════════════════════════════
function MemoryOverflowOverviewDashboard({ alerts = [], total = 0, memoryMetrics = [] }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const data = useMemo(() => {
    const now = Date.now();
    const rows = alerts.map(a => {
      const processName = a.processName || 'Unknown process';
      const pid = a.pid ?? '—';
      const time = new Date(a.createdAt || a.timestamp || 0);
      return { ...a, processName, pid, time };
    });

    const totalQ = Array(24).fill(0);
    const bufferHits = Array(24).fill(0);
    const injectHits = Array(24).fill(0);
    rows.forEach(r => {
      const hoursAgo = Math.floor((now - r.time.getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) {
        const idx = 23 - hoursAgo;
        totalQ[idx]++;
        if (/buffer|stack|overflow/i.test(`${r.eventType || ''} ${r.description || ''}`)) bufferHits[idx]++;
        if (/inject|hollow|reflective/i.test(`${r.eventType || ''} ${r.description || ''}`)) injectHits[idx]++;
      }
    });

    const processMap = {}, ruleMap = {}, hostMap = {};
    rows.forEach(r => {
      if (r.processName && r.processName !== 'unknown.exe') {
        processMap[r.processName] = (processMap[r.processName] || { count: 0, level: r.severity || 'info', pid: r.pid, address: r.memoryAddress || 'Not reported', size: r.memorySize || 'Not reported' });
        processMap[r.processName].count++;
      }
      const rule = r.eventType || r.ruleId || 'Memory event'; ruleMap[rule] = (ruleMap[rule] || 0) + 1;
      const host = r.hostname || r.agentName || 'Unknown';
      if (!hostMap[host]) hostMap[host] = { count: 0, ip: r.srcip || r.sourceIp || '—', hits: 0, status: r.systemId?.status || 'Unknown' };
      hostMap[host].count++;
      hostMap[host].hits++;
    });

    const topProcesses = Object.entries(processMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const topRules = Object.entries(ruleMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topHosts = Object.entries(hostMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const recentAlerts = [...rows].sort((a, b) => b.time - a.time).slice(0, 8);
    const overflowSpikeTotal = rows.filter(r => /memory[._ -]?spike|buffer|stack|overflow|segfault|segmentation fault|heap corruption/i.test(`${r.eventType || ''} ${r.ruleId || ''} ${r.description || ''}`)).length;
    const injectTotal = rows.filter(r => /inject|hollow|reflective/i.test(`${r.eventType || ''} ${r.description || ''}`)).length;
    const rwxTotal = rows.filter(r => /rwx|executable/i.test(`${r.eventType || ''} ${r.description || ''}`)).length;
    const lsassTotal = rows.filter(r => /lsass|credential/i.test(`${r.description || ''} ${r.eventType || ''}`)).length;
    const targetedProcesses = Object.keys(processMap).length;
    const affectedEndpoints = Object.keys(hostMap).filter(host => host !== 'Unknown endpoint' && host !== 'Unknown').length;
    const highCritical = rows.filter(r => ['high', 'critical'].includes(String(r.severity || '').toLowerCase())).length;

    const heatmap = Array.from({ length: 60 }, () => ({ count: 0, maxRisk: 0 }));
    rows.forEach(row => {
      const hoursAgo = Math.floor((now - row.time.getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 60) {
        const index = 59 - hoursAgo;
        heatmap[index].count += 1;
        heatmap[index].maxRisk = Math.max(heatmap[index].maxRisk, Number(row.riskScore || 0));
      }
    });
    const hostMetrics = memoryMetrics.filter(metric => memoryTelemetryValue(metric, 'memoryMetricType', 'memory_metric_type') === 'host');
    const processMetrics = memoryMetrics.filter(metric => memoryTelemetryValue(metric, 'memoryMetricType', 'memory_metric_type') === 'process');
    const processRamByHost = processMetrics.reduce((acc, metric) => {
      const host = metric.hostname || metric.agentName || 'Unknown endpoint';
      acc[host] = (acc[host] || 0) + Number(memoryTelemetryValue(metric, 'processMemoryPercent', 'memory_percent') || 0);
      return acc;
    }, {});
    const ramSamples = hostMetrics.length
      ? hostMetrics.map(metric => Number(memoryTelemetryValue(metric, 'memoryPressure', 'memory_pressure', 'processMemoryPercent', 'memory_percent') || 0))
      : Object.values(processRamByHost).map(value => Math.min(100, value));
    const averageRam = ramSamples.length ? ramSamples.reduce((sum, value) => sum + value, 0) / ramSamples.length : 0;
    const pressuredHosts = ramSamples.filter(value => value >= 90).length;
    const reportingHosts = hostMetrics.length || Object.keys(processRamByHost).length;
    const ramSource = hostMetrics.length ? 'Host memory telemetry' : processMetrics.length ? 'Observed process RAM' : 'Awaiting telemetry';
    const exploitCounts = [
      ['Memory Spikes', rows.filter(row => /memory[._ -]?spike|sudden memory spike/i.test(`${row.eventType || ''} ${row.ruleId || ''} ${row.description || ''}`)).length, MON.red, '📈'],
      ['Memory Crashes', rows.filter(row => /segfault|segmentation fault|sigsegv|access violation|application crash/i.test(`${row.eventType || ''} ${row.ruleId || ''} ${row.description || ''}`)).length, MON.orange, '⚠️'],
      ['Buffer / Stack Corruption', rows.filter(row => /buffer overflow|stack overflow|stack smash|heap corruption/i.test(`${row.eventType || ''} ${row.ruleId || ''} ${row.description || ''}`)).length, MON.red, '💥'],
      ['Process Injection', rows.filter(row => /process inject|process hollow|reflective/i.test(`${row.eventType || ''} ${row.ruleId || ''} ${row.description || ''}`)).length, MON.purple, '💉'],
      ['RWX / Executable Memory', rows.filter(row => /rwx|executable memory|protection change/i.test(`${row.eventType || ''} ${row.ruleId || ''} ${row.description || ''}`)).length, MON.yellow, '⚡'],
      ['LSASS Memory Access', rows.filter(row => /lsass/i.test(`${row.eventType || ''} ${row.description || ''}`)).length, MON.orange, '🔑'],
    ];
    const exploitTotal = exploitCounts.reduce((sum, row) => sum + row[1], 0);
    return { rows, totalQ, bufferHits, injectHits, topProcesses, topRules, topHosts, recentAlerts, overflowSpikeTotal, injectTotal, rwxTotal, lsassTotal, targetedProcesses, affectedEndpoints, highCritical, heatmap, hostMetrics, averageRam, pressuredHosts, reportingHosts, ramSource, exploitCounts, exploitTotal };
  }, [alerts, memoryMetrics]);

  const kpiCards = [
    { label: 'TOTAL MEMORY ALERTS', value: total || alerts.length, color: MON.blue, icon: '💾', trend: 'Live 24h telemetry' },
    { label: 'OVERFLOW / MEMORY SPIKES', value: data.overflowSpikeTotal, color: MON.red, icon: '💥', trend: 'Loaded alert sample' },
    { label: 'HIGH & CRITICAL', value: data.highCritical, color: MON.orange, icon: '⚠️', trend: 'Loaded alert sample' },
    { label: 'AFFECTED PROCESSES', value: data.targetedProcesses, color: MON.purple, icon: '🎯', trend: 'Loaded alert sample' },
    { label: 'AFFECTED ENDPOINTS', value: data.affectedEndpoints, color: MON.cyan, icon: '🖥️', trend: 'Loaded alert sample' },
  ];

  const ruleColors = [MON.red, MON.orange, MON.purple, MON.cyan, MON.blue, MON.yellow];
  const fmtNum = n => n >= 1000 ? `${(n / 1000).toFixed(2)}K` : String(n);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── KPI Cards Row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {kpiCards.map((k, i) => (
          <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: '14px 16px', position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: `linear-gradient(90deg, ${k.color}, transparent)` }} />
            <div style={{ fontSize: 9, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1.5 }}>{k.label}</div>
            <div style={{ fontSize: 28, fontWeight: 900, color: k.color, margin: '6px 0 2px', lineHeight: 1 }}>
              {typeof k.value === 'number' && k.value >= 1000 ? `${(k.value / 1000).toFixed(2)}K` : k.value}
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 4 }}>
              <span style={{ fontSize: 9, color: MON.green, fontWeight: 800 }}>
                {k.trend}
              </span>
            </div>
            <div style={{ marginTop: 8, height: 28 }}>
              <MiniSparkline data={data.totalQ} color={k.color} height={28} />
            </div>
          </div>
        ))}
      </div>

      {/* ── Row 2: Activity Chart + Status Matrix + Anomaly Donut ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.1fr 1fr', gap: 14 }}>

        {/* 24hr Multi-line Activity Chart */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📊 Memory Overflow & Process Exploitation Activity (24 Hours)</div>
            <div style={{ display: 'flex', gap: 12 }}>
              {[['Total Events', MON.blue], ['Buffer Overflows', MON.red], ['Process Injections', MON.purple]].map(([l, c]) => (
                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                  <div style={{ width: 20, height: 2, background: c, borderRadius: 2 }} /><span style={{ color: MON.muted }}>{l}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ height: 180, position: 'relative' }}>
            <MultiLineChart height={170} datasets={[
              { data: data.totalQ, color: MON.blue },
              { data: data.bufferHits, color: MON.red },
              { data: data.injectHits, color: MON.purple },
            ]} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.sub, fontSize: 8, marginTop: 6, paddingTop: 4, borderTop: `1px solid ${MON.line}` }}>
            {Array.from({ length: 7 }, (_, i) => {
              const d = new Date(Date.now() - (6 - i) * 4 * 3600000);
              return <span key={i}>{d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>;
            })}
          </div>
        </div>

        {/* Memory Threat Matrix */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🗺️ Memory Overflow Threat Heatmap</div>
          <div style={{ background: '#061220', borderRadius: 8, padding: 10, height: 140, position: 'relative', overflow: 'hidden' }}>
            {data.heatmap.map((cell, index) => {
              const riskColor = cell.maxRisk >= 90 ? MON.red : cell.maxRisk >= 70 ? MON.orange : cell.count ? MON.purple : '#1a3050';
              return <div key={index} title={`${cell.count} event(s), max risk ${cell.maxRisk}`} style={{
                position: 'absolute',
                left: `${(index % 10) * 10 + 3}%`, top: `${Math.floor(index / 10) * 16 + 4}%`,
                width: cell.count ? Math.min(12, 5 + cell.count) : 5,
                height: cell.count ? Math.min(12, 5 + cell.count) : 5,
                borderRadius: '50%', background: riskColor, opacity: cell.count ? 0.95 : 0.5,
                boxShadow: cell.count ? `0 0 ${Math.min(12, 3 + cell.count)}px ${riskColor}` : 'none',
              }} />;
            })}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 10 }}>
            {[['Critical Overrun', MON.red], ['Process Injection', MON.purple], ['RWX Region', MON.orange], ['Normal Memory', MON.line]].map(([l, c]) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
                <span style={{ color: MON.muted }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Memory Anomaly Types Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 8 }}>📡 Anomaly Types</div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <DonutChart value={total || alerts.length} maxValue={Math.max(total || alerts.length, 1)} color={MON.purple} size={120} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {data.topRules.slice(0, 5).map(([rule, cnt], i) => (
              <div key={rule} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: ruleColors[i % 6] }} />
                  <span style={{ color: MON.muted }}>{rule}</span>
                </div>
                <span style={{ color: ruleColors[i % 6], fontWeight: 800 }}>
                  {alerts.length ? ((cnt / alerts.length) * 100).toFixed(1) : 0}%
                </span>
              </div>
            ))}
            {!data.topRules.length && <div style={{ color: MON.muted, fontSize: 9 }}>No anomaly telemetry received.</div>}
          </div>
        </div>
      </div>

      {/* ── Row 3: Suspicious Memory Regions + Recent Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>

        {/* Suspicious Memory Regions & RWX Allocations */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.red }}>💥</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Suspicious Memory Regions & RWX Allocations</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700 }}>Targeted Processes: {data.targetedProcesses}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 60px 110px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Process</span><span>PID</span><span>Memory Address</span><span>Severity</span>
          </div>
          {data.topProcesses.length ? data.topProcesses.map(([proc, info], i) => (
            <div key={proc} style={{ display: 'grid', gridTemplateColumns: '1fr 60px 110px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.cyan, fontFamily: 'monospace', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={proc}>
                <span style={{ color: MON.red, marginRight: 4 }}>●</span>{proc}
              </span>
              <span style={{ color: MON.purple, fontFamily: 'monospace' }}>{info.pid}</span>
              <span style={{ color: MON.red, fontFamily: 'monospace', fontSize: 9 }}>{info.address}</span>
              <span>
                <span style={{
                  background: 'rgba(248,113,113,0.2)', color: MON.red, padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 800
                }}>{(info.level || 'high').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No suspicious memory allocations detected</div>
          )}
        </div>

        {/* Recent Memory Overflow Alerts Stream */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.orange }}>⚠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Recent Memory Overflow Alerts</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '70px 1fr 60px 90px 70px', padding: '6px 10px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Time</span><span>Process</span><span>PID</span><span>Endpoint</span><span>Severity</span>
          </div>
          {data.recentAlerts.length ? data.recentAlerts.map((r, i) => (
            <div key={r._id || i} onClick={() => setSelectedAlert(r)} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 60px 90px 70px', padding: '7px 10px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center', cursor: 'pointer' }}>
              <span style={{ color: MON.cyan, fontWeight: 700 }}>{r.time instanceof Date && !isNaN(r.time) ? r.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}</span>
              <span style={{ color: MON.red, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 4 }} title={r.processName}>{r.processName}</span>
              <span style={{ color: MON.purple }}>{r.pid}</span>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{r.hostname || r.agentName || '—'}</span>
              <span>
                <span style={{
                  color: SEV_COLOR[(r.severity || 'high').toLowerCase()] || MON.yellow,
                  fontWeight: 800, fontSize: 9,
                }}>{(r.severity || 'high').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No recent memory alerts</div>
          )}
        </div>
      </div>

      {/* ── Row 4: Top Targeted Endpoints + Memory Health Donut + Detection Breakdown ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 14 }}>

        {/* Top Endpoints Targeted */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}` }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>🖥️ Top Endpoints Targeted for Exploitation</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Endpoint</span><span>IP Address</span><span>Overflow Hits</span><span>Events</span><span>Status</span>
          </div>
          {data.topHosts.length ? data.topHosts.map(([host, info], i) => (
            <div key={host} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{host}</span>
              <span style={{ color: MON.muted, fontFamily: 'monospace', fontSize: 9 }}>{info.ip}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ flex: 1, height: 5, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min((info.hits / (data.topHosts[0]?.[1]?.hits || 1)) * 100, 100)}%`, background: MON.red, borderRadius: 4 }} />
                </div>
                <span style={{ color: MON.red, fontWeight: 800, fontSize: 9 }}>{info.hits}</span>
              </div>
              <span style={{ color: MON.muted }}>{info.count}</span>
              <span style={{ color: MON.green, fontWeight: 700, fontSize: 9 }}>● {info.status || 'Unknown'}</span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No endpoint data</div>
          )}
        </div>

        {/* Memory Health Status Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 10, alignSelf: 'flex-start' }}>⚖️ Host RAM Health & Pressure</div>
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
            <svg width={140} height={140} viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="52" fill="none" stroke="#0f233a" strokeWidth="18" />
              <circle cx="70" cy="70" r="52" fill="none" stroke={data.averageRam >= 90 ? MON.red : MON.green} strokeWidth="18" strokeDasharray={`${Math.min(327, data.averageRam * 3.27)} 327`} strokeDashoffset={81.75} strokeLinecap="butt" />
              <text x="70" y="64" textAnchor="middle" fill="#f1f5f9" fontSize="18" fontWeight="900">{data.averageRam.toFixed(1)}%</text>
              <text x="70" y="80" textAnchor="middle" fill={MON.muted} fontSize="9">Observed RAM</text>
            </svg>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, width: '100%' }}>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Reporting Hosts</div>
              <div style={{ fontSize: 16, color: MON.green, fontWeight: 900 }}>{data.reportingHosts}</div>
            </div>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>High Pressure / OOM</div>
              <div style={{ fontSize: 16, color: MON.red, fontWeight: 900 }}>{data.pressuredHosts}</div>
            </div>
          </div>
          <div style={{ color: MON.sub, fontSize: 9, marginTop: 9 }}>{data.ramSource} · live 60s refresh</div>
        </div>

        {/* Exploit & Injection Detections */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 14 }}>🎯 Exploit & Injection Detections</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {data.exploitCounts.map(([cat, count, col, icon]) => {
              const pct = data.exploitTotal ? (count / data.exploitTotal) * 100 : 0;
              return (
              <div key={cat}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{icon}</span><span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                  </div>
                  <span style={{ color: col, fontWeight: 800 }}>{count} ({pct.toFixed(1)}%)</span>
                </div>
                <div style={{ height: 6, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: col, borderRadius: 4 }} />
                </div>
              </div>);
            })}
          </div>
        </div>
      </div>

      {/* ── Status Bar ── */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '8px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
        <span style={{ color: MON.cyan }}>🛡️ Memory Overflow Detection continuously monitors process RAM allocations, kernel exception codes (Access Violations), RWX page permissions, and LSASS access in real-time.</span>
        <span style={{ color: MON.sub }}>All times in IST (UTC +05:30)</span>
      </div>

      {selectedAlert && <MemoryOverflowDetailModal log={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD COMPONENT (DEFAULT EXPORT)
// ═════════════════════════════════════════════════════════════════════════════
export default function MemoryOverflowDashboard({ alerts: sourceAlerts = [], loading = false, total: sourceTotal = 0, memoryMetrics: sourceMemoryMetrics = [], systems = [] }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [dnsSystems, setDnsSystems] = useState(systems);
  const alerts = useMemo(
    () => sourceAlerts.filter(isMemoryOverflowEvidence).map(normalizeMemoryTelemetry),
    [sourceAlerts],
  );
  const memoryMetrics = useMemo(
    () => sourceMemoryMetrics.filter(isMemoryOverflowEvidence).map(normalizeMemoryTelemetry),
    [sourceMemoryMetrics],
  );
  const total = alerts.length === sourceAlerts.length ? sourceTotal : alerts.length;

  useEffect(() => {
    if (systems.length) setDnsSystems(systems);
  }, [systems]);

  useEffect(() => {
    let active = true;
    const loadSystems = () => api.get('/system')
      .then(res => {
        if (!active) return;
        const rows = res.data?.systems || res.data?.agents || res.data || [];
        setDnsSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setDnsSystems([]); });
    loadSystems();
    const timer = setInterval(loadSystems, 60000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const liveStats = useMemo(() => {
    const text = a => `${a.type || ''} ${a.ruleId || ''} ${a.source || ''} ${a.description || ''} ${a.eventType || ''}`;
    const bufferOverflows = alerts.filter(a => /buffer|stack|overflow/i.test(text(a))).length;
    const processInjections = alerts.filter(a => /inject|hollow|reflective/i.test(text(a))).length;
    const rwxRegions = alerts.filter(a => /rwx|executable/i.test(text(a))).length;
    const lsassAttempts = alerts.filter(a => /lsass|credential/i.test(text(a))).length;
    const critical = alerts.filter(a => a.severity === 'critical').length;
    const high = alerts.filter(a => a.severity === 'high').length;
    const targetedProcesses = new Set(alerts.map(a => a.processName).filter(Boolean)).size;
    const uniqueEndpoints = new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size;

    const now = Date.now();
    const timeline = Array(18).fill(0);
    const agentMap = {};

    alerts.forEach(a => {
      const created = new Date(a.createdAt || a.timestamp || 0).getTime();
      const daysAgo = Math.floor((now - created) / 86400000);
      if (Number.isFinite(daysAgo) && daysAgo >= 0 && daysAgo < 90) {
        timeline[Math.min(17, Math.max(0, 17 - Math.floor(daysAgo * 18 / 90)))]++;
      }
      const agentKey = a.agentId || a.agentName || a.systemId?._id || a.systemId || 'unknown';
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown', events: 0, bufferHits: 0, injectHits: 0, lastSeen: null });
      agent.events++;
      if (/buffer|stack|overflow/i.test(text(a))) agent.bufferHits++;
      if (/inject|hollow/i.test(text(a))) agent.injectHits++;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
    });

    return {
      totalEvents: total || alerts.length,
      bufferOverflows, processInjections, rwxRegions, lsassAttempts, critical, high,
      targetedProcesses, uniqueEndpoints,
      highCritical: critical + high,
      timeline,
      agentRows: Object.values(agentMap).sort((a, b) => b.events - a.events),
    };
  }, [alerts, total]);

  const kpis = [
    ['Total Memory Events', 'totalEvents', MON.blue, '💾'],
    ['Buffer Overflows', 'bufferOverflows', MON.red, '💥'],
    ['Process Injections', 'processInjections', MON.purple, '💉'],
    ['RWX Memory Regions', 'rwxRegions', MON.orange, '⚡'],
    ['LSASS Access Attempts', 'lsassAttempts', MON.red, '🔑'],
    ['High & Critical Alerts', 'highCritical', MON.red, '⚠️'],
    ['Targeted Processes', 'targetedProcesses', MON.purple, '🎯'],
    ['Affected Endpoints', 'uniqueEndpoints', MON.cyan, '🖥️'],
    ['Critical Severity', 'critical', MON.red, '🔴'],
    ['High Severity', 'high', MON.orange, '🟠'],
    ['Online Agents', () => dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green, '🟢'],
    ['Total Agents', () => dnsSystems.length, MON.blue, '🖥️'],
    ['Offline Agents', () => dnsSystems.filter(s => !['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.muted, '⚫'],
    ['DEP Bypass Indicators', () => alerts.filter(a => /dep bypass|nx violation/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.orange, '🛡️'],
    ['ASLR Bypass Indicators', () => alerts.filter(a => /aslr bypass/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.yellow, '🎲'],
    ['Reflective DLL Loads', () => alerts.filter(a => /reflective dll|reflective load/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.purple, '📦'],
    ['Heap Corruptions', () => alerts.filter(a => /heap corruption|heap overflow/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.red, '☣️'],
    ['Segmentation Faults', () => alerts.filter(a => /segmentation fault|sigsegv/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.orange, '⚡'],
    ['Fileless Malware Signals', () => alerts.filter(a => /fileless|memory execution/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.red, '👻'],
    ['Protected Agent Tampering', () => alerts.filter(a => /agent tamper|protected process tamper/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.green, '✅'],
  ].map(([label, keyOrFn, color, icon]) => ({
    label,
    val: typeof keyOrFn === 'function' ? keyOrFn() : (liveStats[keyOrFn] ?? 0),
    color,
    icon,
    data: liveStats.timeline,
  }));

  const agentStatusRows = dnsSystems.map(sys => {
    const sysKey = String(sys.agentId || sys._id || '');
    const metrics = liveStats.agentRows.find(r => r.key === sysKey || r.name === sys.name || r.name === sys.hostname);
    return {
      key: sys._id || sysKey,
      name: sys.name || sys.hostname || metrics?.name || 'Unknown',
      hostname: sys.hostname || '—',
      status: sys.status || 'unknown',
      memMonitor: sys.memoryMonitorEnabled !== false,
      lastSeen: sys.lastSeen || metrics?.lastSeen,
      events: metrics?.events || 0,
      bufferHits: metrics?.bufferHits || 0,
      injectHits: metrics?.injectHits || 0,
    };
  });
  liveStats.agentRows.forEach(m => {
    if (!agentStatusRows.some(r => r.name === m.name)) {
      agentStatusRows.push({ ...m, hostname: '—', status: 'reporting', memMonitor: true });
    }
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📈', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'log-monitor', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
          { id: 'rules', icon: '⚙️', label: 'Detection Rules', activeColor: MON.orange },
        ].map(item => {
          const selected = activeTab === item.id;
          return (
            <button key={item.id} type="button" onClick={() => setActiveTab(item.id)} aria-current={selected ? 'page' : undefined} style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 10, background: selected ? item.activeColor : 'transparent', color: selected ? '#000' : MON.text, border: selected ? `1px solid ${item.activeColor}` : '1px solid transparent', padding: '10px 12px', borderRadius: 7, fontSize: 12, fontWeight: 800, textAlign: 'left', cursor: 'pointer' }}>
              <span aria-hidden="true">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}

        {/* Live Stats Mini Panel */}
        <div style={{ marginTop: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12 }}>
          <div style={{ fontSize: 9, color: MON.muted, fontWeight: 800, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Live Memory Stats</div>
          {[
            ['Buffer Overflows', liveStats.bufferOverflows, MON.red],
            ['Process Injections', liveStats.processInjections, MON.purple],
            ['RWX Regions', liveStats.rwxRegions, MON.orange],
            ['Agents Online', dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green],
          ].map(([label, val, col]) => (
            <div key={label} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, marginBottom: 6 }}>
              <span style={{ color: MON.muted }}>{label}</span>
              <b style={{ color: col }}>{val}</b>
            </div>
          ))}
        </div>
      </aside>

      {/* Main Content Area */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>

        {activeTab === 'log-monitor' ? (
          <MemoryOverflowLogMonitor alerts={alerts} memoryMetrics={memoryMetrics} />
        ) : activeTab === 'reports' ? (
          <MemoryOverflowReportsTab alerts={alerts} />
        ) : activeTab === 'rules' ? (
          <MemoryDetectionRulesTab />
        ) : activeTab === 'dashboard' ? (
          <MemoryOverflowOverviewDashboard alerts={alerts} total={total} memoryMetrics={memoryMetrics} />
        ) : (
          <>
            {/* 20 KPI Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, lineHeight: 1.3 }}>{kpi.label}</div>
                    <span style={{ fontSize: 14 }}>{kpi.icon}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent-Level Memory Overflow Monitoring Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛡️ Agent-Level Memory Overflow & Process Protection</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(r => ['active', 'reporting', 'online'].includes(r.status)).length} reporting · 15s refresh</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent</span><span>Hostname</span><span>Status</span><span>Memory Monitor</span><span>Events</span><span>Overflow Hits</span><span>Injections</span><span>Last Seen</span>
              </div>
              {agentStatusRows.length ? agentStatusRows.map(row => (
                <div key={row.key || row.name} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b>
                  <span>{row.hostname}</span>
                  <b style={{ color: ['active', 'reporting', 'online'].includes(row.status) ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.status}</b>
                  <span style={{ color: row.memMonitor ? MON.green : MON.red }}>{row.memMonitor ? 'Enabled' : 'Disabled'}</span>
                  <b>{row.events}</b>
                  <b style={{ color: row.bufferHits > 0 ? MON.red : MON.green }}>{row.bufferHits}</b>
                  <b style={{ color: row.injectHits > 0 ? MON.purple : MON.green }}>{row.injectHits}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Never'}</span>
                </div>
              )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading agent data...' : 'No memory-monitoring agents found'}</div>}
            </div>

            {/* Charts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Memory Overflow Activity Timeline (90 Days)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 4, borderBottom: `1px solid ${MON.line}` }}>
                  {liveStats.timeline.map((val, idx) => (
                    <div key={idx} title={`${val} events`} style={{ flex: 1, height: `${val ? Math.max(4, (val / Math.max(...liveStats.timeline, 1)) * 100) : 0}%`, background: val > 0 ? MON.red : '#0f233a', borderRadius: '2px 2px 0 0', opacity: 0.85 }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>☠️ Exploitation Rules Triggered</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Buffer Overflow', liveStats.bufferOverflows, MON.red],
                    ['Process Injection', liveStats.processInjections, MON.purple],
                    ['RWX Allocation', liveStats.rwxRegions, MON.orange],
                    ['LSASS Dumping', liveStats.lsassAttempts, MON.red],
                    ['Heap Corruption', alerts.filter(a => /heap corruption|heap overflow/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.yellow],
                  ].map(([rule, count, col]) => (
                    <div key={rule} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{rule}</span>
                      <b style={{ color: col }}>{count}</b>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🎯 Threat Severity Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Critical', liveStats.critical, MON.red],
                    ['High', liveStats.high, MON.orange],
                    ['Medium', alerts.filter(a => a.severity === 'medium').length, MON.yellow],
                    ['Low', alerts.filter(a => a.severity === 'low').length, MON.green],
                  ].map(([sev, count, col]) => (
                    <div key={sev} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{sev}</span>
                      <b style={{ color: col }}>{count}</b>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. OVERLAY CAPABILITY MODAL EXPORT
// ═════════════════════════════════════════════════════════════════════════════
export function CapabilityPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [memoryMetrics, setMemoryMetrics] = useState([]);
  const [systems, setSystems] = useState([]);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const from = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId: 29, windowHours: 24, from });
      let r = await api.get(`/memory-overflow/overview?${q}`);
      let fetchedAlerts = (r.data?.alerts || []).filter(isMemoryOverflowEvidence).map(normalizeMemoryTelemetry);
      let fetchedTotal = r.data?.total || fetchedAlerts.length;
      setMemoryMetrics((r.data?.metrics || []).map(normalizeMemoryTelemetry));
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/edr?${q}`);
          fetchedAlerts = (r.data?.alerts || []).filter(isMemoryOverflowEvidence).map(normalizeMemoryTelemetry);
          fetchedTotal = r.data?.total || fetchedAlerts.length;
        } catch { /* ignore */ }
      }

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal);
    } catch (err) {
      console.warn('[Memory Overflow fetch warning]', err);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 60000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    if (!companyId) return;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    socket.on('connect', join);
    socket.on('memory:alert', (a) => {
      if (!a || !isMemoryOverflowEvidence(a)) return;
      const normalized = normalizeMemoryTelemetry(a);
      setAlerts(prev => prev.some(row => row._id === normalized._id) ? prev : [normalized, ...prev]);
    });
    socket.on('memory:metric', (metric) => {
      if (!metric) return;
      const normalized = normalizeMemoryTelemetry(metric);
      setMemoryMetrics(prev => [normalized, ...prev.filter(row => !(row.memoryMetricType === normalized.memoryMetricType && String(row.systemId?._id || row.systemId || row.agentId) === String(normalized.systemId?._id || normalized.systemId || normalized.agentId) && String(row.pid || '') === String(normalized.pid || '')))].slice(0, 500));
    });
    socket.on('alert:updated', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('memory:alert');
      socket.off('memory:metric');
      socket.off('alert:updated');
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 29. Memory Overflow Detection</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#60a5fa', background: '#1e3a5f44', border: '1px solid #1e3a5f', padding: '3px 8px', borderRadius: 6, fontWeight: 'bold' }}>
              {Number(total || 0).toLocaleString()} records
            </span>
            <span style={{ fontSize: 10, color: loading ? MON.yellow : MON.green }}>{loading ? '⟳ Loading...' : '● Live'}</span>
            <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
          </div>
        </div>
        <MemoryOverflowDashboard alerts={alerts} loading={loading} total={total} memoryMetrics={memoryMetrics} systems={systems} />
      </div>
    </div>
  );
}

export function MemoryOverflowSubTabPage() {
  return <CapabilitySubTabPage kind="memoryoverflow" />;
}
