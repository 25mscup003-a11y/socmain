import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Beaconing Detection — Capability ID: 26 (Backend ID: 26)
 *
 * 100% Self-Contained Enterprise SOC Beaconing & C2 Traffic Monitoring Module
 * Full Coverage across 15 Beaconing Categories & Policy Engine Specifications
 * Master 10-Tab Forensic Panel Modal (`BeaconingForensicDetailModal`) matching Capability 25 (Hash/Signature Analysis)
 */
import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens (Mirroring Capability 25) ──────────────────────────
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
  pink: '#ec4899',
  accent: '#6366f1',
};

const SEV_COLOR = {
  critical: MON.red,
  high: MON.orange,
  medium: MON.yellow,
  low: MON.green,
  info: MON.cyan,
  clean: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
  clean: 'rgba(34, 211, 238, 0.15)',
};

function MiniSparkline({ data = [12, 18, 14, 22, 19, 28, 24, 32], color = MON.cyan, height = 30 }) {
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

// ── Helper Utilities ────────────────────────────────────────────────────────
function createEventBuffer(callback, delay = 1200) {
  let timer = null;
  return {
    add() {
      clearTimeout(timer);
      timer = setTimeout(callback, delay);
    },
    clear() {
      clearTimeout(timer);
    },
  };
}

function shortNum(n = 0) {
  const val = Number(n) || 0;
  return val >= 1000 ? val.toLocaleString('en-IN') : String(val);
}

function normHost(h) {
  return String(h || 'unknown').trim().toLowerCase();
}

function alertTime(r) {
  return r?.timestamp || r?.createdAt || r?.time || r?.observedAt || r?.updatedAt || new Date().toISOString();
}

function alertHost(r) {
  return r?.hostname || r?.host || r?.agentName || r?.systemId?.hostname || r?.systemId?.name || '—';
}

function alertSeverity(r) {
  const s = String(r?.severity || 'info').toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'info';
}

function beaconRaw(r) {
  const direct = r?.rawEvent && typeof r.rawEvent === 'object' ? r.rawEvent : {};
  const nested = direct.raw && typeof direct.raw === 'object' ? direct.raw : {};
  return { ...direct, ...nested };
}

function beaconField(r, ...keys) {
  const raw = beaconRaw(r);
  for (const key of keys) {
    const value = r?.[key] ?? raw?.[key];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function beaconProcess(r) {
  return beaconField(r, 'processName', 'process_name', 'process', 'processExe', 'process_exe', 'exe') || '—';
}

function beaconC2Target(r) {
  return beaconField(r, 'c2Target', 'destip', 'destIp', 'dst_ip', 'destinationIp', 'remoteIp', 'remote_ip', 'domain', 'destinationDomain') || '—';
}

function beaconProto(r) {
  return beaconField(r, 'protocol', 'proto') || '—';
}

function beaconInterval(r) {
  const seconds = Number(beaconField(r, 'averageInterval', 'average_interval', 'intervalSeconds', 'interval_seconds', 'interval'));
  if (Number.isFinite(seconds) && seconds > 0) return `${seconds.toFixed(seconds < 10 ? 1 : 0)} seconds`;
  return beaconField(r, 'frequency') || '—';
}

function beaconDuration(r) {
  const seconds = Number(beaconField(r, 'observationSeconds', 'observation_seconds'));
  if (Number.isFinite(seconds) && seconds > 0) return seconds >= 3600 ? `${(seconds / 3600).toFixed(1)} hours` : `${Math.round(seconds / 60)} minutes`;
  return beaconField(r, 'duration') || '—';
}

function beaconJitter(r) {
  const seconds = Number(beaconField(r, 'jitterSeconds', 'jitter_seconds'));
  if (Number.isFinite(seconds)) return `${seconds.toFixed(2)} seconds`;
  return beaconField(r, 'jitter', 'jitterPercent', 'jitter_percent') || '—';
}

function beaconCategory(r) {
  return beaconField(r, 'threatCategory', 'threat_category', 'detectionType', 'detection_type', 'eventType', 'event_type', 'ruleName', 'ruleId', 'rule_id', 'category') || '—';
}

function beaconScore(r) {
  const score = Number(beaconField(r, 'riskScore', 'risk_score', 'threatScore', 'reputationScore', 'reputation_score'));
  return Number.isFinite(score) ? Math.max(0, Math.min(100, Math.round(score))) : null;
}

function beaconCommandLine(r) {
  return beaconField(r, 'processCmdline', 'process_cmdline', 'commandLine', 'command_line', 'cmdline') || '—';
}

function beaconText(row) {
  return `${row?.detectionType || ''} ${row?.category || ''} ${row?.ruleName || ''} ${row?.title || ''} ${row?.description || ''} ${row?.status || ''} ${row?.recommendedAction || ''}`.toLowerCase();
}

function countMatching(rows, pattern) {
  return rows.filter(row => pattern.test(beaconText(row))).length;
}

function uniqueCount(rows, picker) {
  return new Set(rows.map(picker).map(value => String(value || '').trim()).filter(value => value && value !== '—')).size;
}

function responseSummary(rows) {
  let attempted = 0;
  let successful = 0;
  rows.forEach(row => {
    const history = Array.isArray(row?.responseHistory) ? row.responseHistory : [];
    const directAction = `${row?.actionTaken || ''} ${row?.containmentStatus || ''} ${row?.isolationStatus || ''}`;
    if (/block|isolat|contain/i.test(directAction) || row?.blocked === true || row?.isolated === true) {
      attempted += 1;
      if (row?.blocked === true || row?.isolated === true || /success|completed|executed|resolved|blocked|isolated/i.test(directAction)) successful += 1;
    }
    history.forEach(action => {
      const name = `${action?.action || ''} ${action?.actionType || ''}`;
      if (!/block|isolat|contain/i.test(name)) return;
      attempted += 1;
      if (/success|completed|executed|resolved/i.test(String(action?.status || ''))) successful += 1;
    });
  });
  return { attempted, successful, rate: attempted ? `${Math.round((successful / attempted) * 100)}%` : 'Not configured' };
}

function buildBuckets(rows = [], bucketCount = 12, hours = 24) {
  const now = Date.now();
  const start = now - hours * 3600000;
  const bucketMs = (hours * 3600000) / bucketCount;
  const buckets = Array(bucketCount).fill(0);
  rows.forEach(row => {
    const t = alertTime(row);
    const ms = t ? new Date(t).getTime() : NaN;
    if (!Number.isFinite(ms) || ms < start || ms > now) return;
    const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((ms - start) / bucketMs)));
    buckets[idx] += 1;
  });
  return buckets;
}

function topCounts(rows = [], picker = () => 'unknown', limit = 5) {
  const counts = new Map();
  rows.forEach(row => {
    const key = String(picker(row) || 'unknown').trim() || 'unknown';
    if (key === 'unknown' || key === '—') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function EvidenceGrid({ rows = [] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
      {rows.map(([label, val]) => (
        <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: 10 }}>
          <div style={{ fontSize: 9, fontWeight: 700, color: MON.muted, textTransform: 'uppercase' }}>{label}</div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#fff', marginTop: 3, fontFamily: 'monospace', wordBreak: 'break-all' }}>{String(val ?? '—')}</div>
        </div>
      ))}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MASTER 10-TAB FORENSIC PANEL MODAL (Capability 25 Architecture)
// ═════════════════════════════════════════════════════════════════════════════
export function BeaconingForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'c2target', label: '🌐 2. C2 Target & IP Intel' },
    { id: 'protocol', label: '📡 3. Transport & TLS Cert' },
    { id: 'freq', label: '⏱️ 4. Frequency & Jitter' },
    { id: 'process', label: '⚙️ 5. Process Correlation' },
    { id: 'dns', label: '🕳️ 6. DNS Tunneling & NRD' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'policy', label: '🛡️ 8. Policy Evaluation' },
    { id: 'timeline', label: '⏱️ 9. Heartbeat Lifecycle' },
    { id: 'actions', label: '📄 10. Reports & SOC Actions' },
  ];

  const handleAction = async (actionType, actionName) => {
    const supportedAction = { isolate_host: 'isolate', block_c2_ip: 'block_ip', kill_process: 'kill_process' }[actionType];
    try {
      if (!supportedAction || typeof onAction !== 'function' || !log?._id) {
        setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
        return;
      }
      const res = await onAction(String(log._id), supportedAction);
      setActionSuccess(res?.message || `Approved action submitted: ${actionName}`);
    } catch (err) {
      setActionSuccess(err?.message || `Failed to submit: ${actionName}`);
    }
    setTimeout(() => setActionSuccess(null), 5000);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Modal Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>📡</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Beaconing & C2 Forensic Panel — {alertHost(log)} ({beaconProcess(log)})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  THREAT SCORE: {beaconScore(log) == null ? '—' : `${beaconScore(log)}/100`}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                C2 Target: <strong style={{ color: MON.cyan, fontFamily: 'monospace' }}>{beaconC2Target(log)}</strong> | Frequency: <strong style={{ color: MON.yellow }}>{beaconInterval(log)}</strong> | Category: <strong style={{ color: MON.green }}>{beaconCategory(log)}</strong>
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              style={{
                padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600,
                color: activeTab === t.id ? MON.cyan : MON.muted,
                background: activeTab === t.id ? MON.bg : 'transparent',
                border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent',
                cursor: 'pointer', whiteSpace: 'nowrap',
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Body Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: MON.bg }}>
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Endpoint Host', alertHost(log), MON.cyan],
                  ['Process Name', beaconProcess(log), MON.text],
                  ['C2 Target', beaconC2Target(log), MON.purple],
                  ['Beacon Frequency', beaconInterval(log), MON.yellow],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>📡 C2 Heartbeat Summary & Threat Analysis</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  Endpoint agent on <strong>{alertHost(log)}</strong> detected repeated outbound callbacks executing via process <code style={{ color: MON.yellow, background: '#000', padding: '2px 6px', borderRadius: 4 }}>{beaconProcess(log)}</code> to remote C2 target <code style={{ color: MON.purple, background: '#000', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>{beaconC2Target(log)}</code> at a fixed interval of <strong>{beaconInterval(log)}</strong>. SOC Category: <strong>{beaconCategory(log)}</strong>.
                </div>
              </div>

              <EvidenceGrid rows={[
                ['Endpoint Hostname', alertHost(log)], ['Process Binary', beaconProcess(log)],
                ['Destination IP / Domain', beaconC2Target(log)], ['Transport Protocol', beaconProto(log)],
                ['Beacon Interval / Frequency', beaconInterval(log)], ['Active Duration', beaconDuration(log)],
                ['Jitter Variance', beaconJitter(log)], ['SOC Threat Category', beaconCategory(log)],
              ]} />
            </div>
          )}

          {/* TAB 2: C2 TARGET & IP INTEL */}
          {activeTab === 'c2target' && (
            <EvidenceGrid rows={[
              ['Remote IP', beaconField(log, 'destip', 'destIp', 'dst_ip', 'destinationIp', 'remoteIp', 'remote_ip') || '—'], ['Destination Domain', beaconField(log, 'domain', 'destinationDomain') || '—'],
              ['ASN / ISP', log.asn || log.isp || '—'], ['Country / Geo', log.country || log.geoLocation || '—'],
              ['Threat Intel Match', log.iocMatch || log.threatIntelMatch || 'No match recorded'], ['TOR Indicator', log.torDetected === true ? 'Detected' : log.torDetected === false ? 'Not detected' : 'No telemetry'],
              ['Reputation Score', log.reputationScore ?? log.threatScore ?? '—'], ['Threat Intel Source', log.iocSource || log.threatIntelSource || '—'],
            ]} />
          )}

          {/* TAB 3: TRANSPORT PROTOCOL & SSL/TLS */}
          {activeTab === 'protocol' && (
            <EvidenceGrid rows={[
              ['Transport Protocol', beaconProto(log)], ['Target Port', log.destPort || log.destinationPort || log.port || '—'],
              ['TLS JA3 Fingerprint', log.ja3 || log.tlsFingerprint || '—'], ['TLS JA3S Response', log.ja3s || '—'],
              ['Certificate Issuer', log.certificate?.issuer || log.certIssuer || '—'], ['Certificate Subject', log.certificate?.subject || log.certSubject || '—'],
              ['SNI', log.sni || '—'], ['HTTP User-Agent', log.userAgent || '—'],
            ]} />
          )}

          {/* TAB 4: BEACON FREQUENCY & JITTER */}
          {activeTab === 'freq' && (
            <EvidenceGrid rows={[
              ['Configured Heartbeat Interval', beaconInterval(log)], ['Measured Jitter Variance', beaconJitter(log)],
              ['Periodicity Score', log.periodicityScore ?? '—'], ['Interval Consistency', log.intervalConsistency ?? '—'],
              ['Connection Count', log.connectionCount ?? '—'], ['Retry Count', log.retryCount ?? '—'],
            ]} />
          )}

          {/* TAB 5: PROCESS CORRELATION */}
          {activeTab === 'process' && (
            <EvidenceGrid rows={[
              ['Process Name', beaconProcess(log)], ['Process ID (PID)', beaconField(log, 'pid', 'processId', 'process_id') || '—'],
              ['Process Command Line', beaconCommandLine(log)], ['Parent Process', beaconField(log, 'parentProcess', 'parentProcessName', 'parent_process_name') || '—'],
              ['Executing User', beaconField(log, 'username', 'user', 'process_user') || '—'], ['Process Launch Path', beaconField(log, 'processPath', 'processExe', 'process_exe', 'executablePath', 'executable') || '—'],
            ]} />
          )}

          {/* TAB 6: DNS TUNNELING & NRD */}
          {activeTab === 'dns' && (
            <EvidenceGrid rows={[
              ['DNS Query Name', log.dnsQuery || log.domain || log.destinationDomain || '—'], ['DNS Record Type', log.queryType || log.dnsQueryType || '—'],
              ['Newly Registered Domain', log.newlyObservedDomain === true ? 'Yes' : log.newlyObservedDomain === false ? 'No' : 'No telemetry'], ['Dynamic DNS Indicator', log.dynamicDns === true ? 'Detected' : log.dynamicDns === false ? 'Not detected' : 'No telemetry'],
              ['DNS Query Count', log.dnsQueryCount ?? '—'], ['NXDOMAIN Rate', log.nxdomainRate ?? '—'],
            ]} />
          )}

          {/* TAB 7: MITRE ATT&CK MAPPING */}
          {activeTab === 'mitre' && (
            <EvidenceGrid rows={[
              ['MITRE ATT&CK Evidence', Array.isArray(log.mitreTechniques) ? log.mitreTechniques.map(item => typeof item === 'string' ? item : `${item.id || item.techniqueId || ''} ${item.name || item.techniqueName || ''}`.trim()).join(', ') || '—' : log.mitreTechnique || '—'],
              ['Detection Evidence', log.detectionReason || log.description || '—'],
              ['Confidence', log.confidence ?? '—'], ['Risk Score', log.riskScore ?? log.score ?? '—'],
            ]} />
          )}

          {/* TAB 8: POLICY EVALUATION */}
          {activeTab === 'policy' && (
            <EvidenceGrid rows={[
              ['Evaluated Policy Rule', log.policyName || log.ruleName || '—'], ['Rule Match Score', log.riskScore ?? log.score ?? '—'],
              ['Recommended Action', log.recommendedAction || '—'], ['Recorded Responses', Array.isArray(log.responseHistory) ? log.responseHistory.length : 0],
            ]} />
          )}

          {/* TAB 9: LIFECYCLE TIMELINE */}
          {activeTab === 'timeline' && (
            <EvidenceGrid rows={[
              ['First Heartbeat Observed', log.firstSeen ? new Date(log.firstSeen).toLocaleString() : '—'],
              ['Latest Callback Observed', new Date(alertTime(log)).toLocaleString()],
              ['Total Monitored Duration', beaconDuration(log)],
              ['Current Channel State', log.status || '—'],
            ]} />
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {actionSuccess && <div style={{ padding: 10, background: `${MON.cyan}18`, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, fontSize: 11 }}>{actionSuccess}</div>}
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ C2 Beaconing SOC Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('isolate_host', `Isolate Host ${alertHost(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛑 Isolate Endpoint Host
                  </button>
                  <button type="button" onClick={() => handleAction('block_c2_ip', `Block Remote C2 IP ${beaconC2Target(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Block Remote C2 IP / Domain
                  </button>
                  <button type="button" onClick={() => handleAction('kill_process', `Kill Process ${beaconProcess(log)}`)} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Terminate Process Execution
                  </button>
                  <button type="button" onClick={() => handleAction('add_ioc', 'Add C2 Target to Tenant IOC Registry')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Add C2 Target to Blacklist IOC
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export function BeaconingLogMonitor({ alerts = [], onAction }) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const rows = Array.isArray(alerts) ? alerts : [];
  const filtered = rows.filter(r => {
    const sMatch = sevFilter === 'all' || alertSeverity(r) === sevFilter;
    const txt = `${alertHost(r)} ${beaconProcess(r)} ${beaconC2Target(r)} ${beaconCategory(r)}`.toLowerCase();
    const qMatch = !search || txt.includes(search.toLowerCase());
    return sMatch && qMatch;
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 900, color: '#fff' }}>📜 Beaconing & C2 Telemetry Logs (SIEM Table View)</h3>
            <div style={{ fontSize: 10, color: MON.muted, marginTop: 2 }}>Click any log row to open SOC Master 10-Tab Forensic Panel</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              placeholder="🔍 Search host, process, IP..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '6px 12px', color: '#fff', fontSize: 11, width: 220 }}
            />
            <select
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
              style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: 11 }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
        </div>

        <div style={{ marginTop: 14, overflowX: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1fr 1.2fr 1.8fr 1fr 1.2fr 1.2fr 0.7fr 0.7fr', gap: 6, borderBottom: `1px solid ${MON.line}`, paddingBottom: 6, fontSize: 9, fontWeight: 800, color: MON.sub }}>
            <span>Time</span><span>Host</span><span>Process</span><span>Destination C2 Target</span><span>Protocol</span><span>Frequency</span><span>Category</span><span>Severity</span><span>Inspect</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {filtered.length ? filtered.map((r, i) => (
              <div
                key={i}
                onClick={() => setSelectedLog(r)}
                style={{ display: 'grid', gridTemplateColumns: '0.9fr 1fr 1.2fr 1.8fr 1fr 1.2fr 1.2fr 0.7fr 0.7fr', gap: 6, alignItems: 'center', fontSize: 8.5, borderTop: `1px solid ${MON.line}44`, paddingTop: 5, paddingBottom: 5, cursor: 'pointer', transition: 'background 0.2s' }}
                onMouseEnter={e => e.currentTarget.style.background = MON.card2}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{ color: MON.muted }}>{new Date(alertTime(r)).toLocaleTimeString()}</span>
                <b style={{ color: MON.cyan }}>{alertHost(r)}</b>
                <span style={{ color: MON.text, fontFamily: 'monospace' }}>{beaconProcess(r)}</span>
                <code style={{ color: MON.purple }}>{beaconC2Target(r)}</code>
                <span style={{ color: MON.text }}>{beaconProto(r)}</span>
                <span style={{ color: MON.yellow, fontWeight: 700 }}>{beaconInterval(r)}</span>
                <span style={{ color: MON.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{beaconCategory(r)}</span>
                <b style={{ color: SEV_COLOR[alertSeverity(r)], textTransform: 'uppercase' }}>{alertSeverity(r)}</b>
                <button type="button" onClick={(e) => { e.stopPropagation(); setSelectedLog(r); }} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '3px 6px', borderRadius: 4, fontSize: 8, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Forensic Panel
                </button>
              </div>
            )) : <div style={{ padding: 20, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No beaconing logs match search filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <BeaconingForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function BeaconingReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={26} alerts={alerts} />;
}

const DEFAULT_BEACONING_CONFIG = {
  enabled: true,
  minimumConnections: 6,
  minimumIntervalSeconds: 5,
  maximumIntervalSeconds: 3600,
  minimumObservationSeconds: 60,
  consistencyThreshold: 75,
  alertThreshold: 70,
  cooldownSeconds: 1800,
};

const EMPTY_BEACON_RULE = {
  name: '', description: '', enabled: true, severity: 'medium', riskScore: 60,
  protocol: 'any', processName: '', minimumConnections: 6,
  minimumIntervalSeconds: 5, maximumIntervalSeconds: 3600,
  consistencyThreshold: 75, cooldownSeconds: 1800,
};

const DEFAULT_C2_CONTAINMENT = {
  enabled: false,
  actionType: 'block_ip',
  minimumRiskScore: 85,
  cooldownMinutes: 30,
  maxExecutionsPerHour: 10,
};

const C2_CONTAINMENT_TAG = 'beaconing-c2-containment';

export function BeaconingConfigurationTab({ systems = [], onContainmentChange }) {
  const [configuration, setConfiguration] = useState(DEFAULT_BEACONING_CONFIG);
  const [rules, setRules] = useState([]);
  const [targetCount, setTargetCount] = useState(systems.length);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [creatingRule, setCreatingRule] = useState(false);
  const [showRuleForm, setShowRuleForm] = useState(false);
  const [newRule, setNewRule] = useState(EMPTY_BEACON_RULE);
  const [editingRuleId, setEditingRuleId] = useState(null);
  const [editingBuiltIn, setEditingBuiltIn] = useState(false);
  const [containment, setContainment] = useState(DEFAULT_C2_CONTAINMENT);
  const [containmentPlaybookId, setContainmentPlaybookId] = useState(null);
  const [containmentSaving, setContainmentSaving] = useState(false);
  const [message, setMessage] = useState('');

  const loadConfiguration = useCallback(async () => {
    setLoading(true);
    setMessage('');
    try {
      const [response, playbookResponse] = await Promise.all([
        api.get('/network/beaconing/configuration', { skipCache: true }),
        api.get('/auto-response/playbooks', { skipCache: true }).catch(() => ({ data: [] })),
      ]);
      setConfiguration({ ...DEFAULT_BEACONING_CONFIG, ...(response.data?.configuration || {}) });
      setRules(Array.isArray(response.data?.rules) ? response.data.rules : []);
      setTargetCount(Number(response.data?.targetCount ?? systems.length));
      const playbooks = Array.isArray(playbookResponse.data) ? playbookResponse.data : [];
      const playbook = playbooks.find(item => Array.isArray(item.tags) && item.tags.includes(C2_CONTAINMENT_TAG));
      if (playbook) {
        const riskCondition = (playbook.conditions || []).find(item => item.field === 'riskScore' && item.operator === 'gte');
        setContainmentPlaybookId(playbook._id);
        setContainment({
          enabled: playbook.enabled !== false && playbook.executionMode !== 'disabled',
          actionType: playbook.steps?.[0]?.actionType || 'block_ip',
          minimumRiskScore: Number(riskCondition?.value ?? 85),
          cooldownMinutes: Number(playbook.cooldownMinutes ?? 30),
          maxExecutionsPerHour: Number(playbook.maxExecutionsPerHour ?? 10),
        });
        onContainmentChange?.(playbook.enabled !== false && playbook.executionMode !== 'disabled');
      } else {
        setContainmentPlaybookId(null);
        setContainment(DEFAULT_C2_CONTAINMENT);
        onContainmentChange?.(false);
      }
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to load Beaconing Detection configuration');
    } finally {
      setLoading(false);
    }
  }, [systems.length, onContainmentChange]);

  useEffect(() => { loadConfiguration(); }, [loadConfiguration]);

  const saveConfiguration = async () => {
    setSaving(true);
    setMessage('');
    try {
      const response = await api.put('/network/beaconing/configuration', configuration);
      setConfiguration({ ...DEFAULT_BEACONING_CONFIG, ...(response.data?.configuration || {}) });
      setTargetCount(Number(response.data?.targetCount ?? targetCount));
      setMessage(response.data?.message || 'Beaconing configuration saved');
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to save Beaconing Detection configuration');
    } finally {
      setSaving(false);
    }
  };

  const createRule = async () => {
    if (String(newRule.name || '').trim().length < 3) {
      setMessage('Rule name must contain at least 3 characters');
      return;
    }
    setCreatingRule(true);
    setMessage('');
    try {
      const response = editingRuleId
        ? await api.patch(`/network/beaconing/configuration/rules/${encodeURIComponent(editingRuleId)}`, newRule)
        : await api.post('/network/beaconing/configuration/rules', newRule);
      setRules(current => editingRuleId
        ? current.map(rule => rule.id === editingRuleId ? response.data.rule : rule)
        : [...current, response.data.rule]);
      setNewRule(EMPTY_BEACON_RULE);
      setEditingRuleId(null);
      setEditingBuiltIn(false);
      setShowRuleForm(false);
      setMessage(response.data?.message || `Beaconing rule ${editingRuleId ? 'updated' : 'added'}`);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to add Beaconing Detection rule');
    } finally {
      setCreatingRule(false);
    }
  };

  const editBeaconRule = rule => {
    const condition = (field, operator, fallback) => {
      const match = (rule.conditions || []).find(item => item.field === field && (!operator || item.operator === operator));
      return match?.value ?? fallback;
    };
    const protocolValue = condition('protocol', null, 'any');
    setNewRule({
      ...EMPTY_BEACON_RULE,
      name: rule.name || '', description: rule.description || '', enabled: rule.enabled !== false,
      severity: rule.severity || 'medium', riskScore: Number(rule.riskScore ?? 60),
      cooldownSeconds: Number(rule.suppressionSeconds ?? 1800),
      protocol: Array.isArray(protocolValue) ? 'web' : protocolValue,
      processName: condition('processName', 'contains', ''),
      minimumConnections: Number(condition('connectionCount', 'gte', 6)),
      minimumIntervalSeconds: Number(condition('averageInterval', 'gte', 5)),
      maximumIntervalSeconds: Number(condition('averageInterval', 'lte', 3600)),
      consistencyThreshold: Number(condition('intervalConsistency', 'gte', 75)),
    });
    setEditingRuleId(rule.id);
    setEditingBuiltIn(rule.builtIn === true);
    setShowRuleForm(true);
  };

  const saveContainment = async () => {
    setContainmentSaving(true);
    setMessage('');
    const payload = {
      name: 'Beaconing Detection - C2 Containment',
      description: 'Approval-gated containment for high-confidence actionable C2 beaconing alerts.',
      enabled: containment.enabled,
      executionMode: containment.enabled ? 'approval_required' : 'disabled',
      requireGlobalApproval: true,
      conditions: [
        { field: 'source', operator: 'eq', value: 'beaconing' },
        { field: 'actionable', operator: 'eq', value: true },
        { field: 'riskScore', operator: 'gte', value: Number(containment.minimumRiskScore) },
      ],
      conditionLogic: 'AND',
      steps: [{
        order: 1,
        actionType: containment.actionType,
        actionParams: {},
        description: 'Contain the C2 destination or affected endpoint after analyst approval.',
        requireApproval: true,
        continueOnFail: false,
      }],
      maxExecutionsPerHour: Number(containment.maxExecutionsPerHour),
      cooldownMinutes: Number(containment.cooldownMinutes),
      rollbackEnabled: true,
      tags: [C2_CONTAINMENT_TAG, 'beaconing-detection', 'c2'],
    };
    try {
      const response = containmentPlaybookId
        ? await api.put(`/auto-response/playbooks/${encodeURIComponent(containmentPlaybookId)}`, payload)
        : await api.post('/auto-response/playbooks', payload);
      setContainmentPlaybookId(response.data?._id || containmentPlaybookId);
      onContainmentChange?.(containment.enabled);
      setMessage(`C2 containment policy ${containment.enabled ? 'enabled' : 'saved as disabled'}; every action requires analyst approval.`);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to save C2 containment policy');
    } finally {
      setContainmentSaving(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ margin: 0, color: '#fff', fontSize: 15 }}>⚙️ Beaconing Detection Configuration</h3>
            <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Policy is synchronized to {targetCount} enrolled agent(s) through the existing heartbeat.</div>
          </div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', color: configuration.enabled ? MON.green : MON.muted, fontSize: 11, fontWeight: 800 }}>
            <input type="checkbox" checked={configuration.enabled !== false} onChange={event => setConfiguration(current => ({ ...current, enabled: event.target.checked }))} />
            Detection {configuration.enabled !== false ? 'Enabled' : 'Disabled'}
          </label>
        </div>
      </div>

      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto' }}>
        <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div><div style={{ color: '#fff', fontSize: 12, fontWeight: 900 }}>Beaconing Detection Rules</div><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>Select Edit to open the same complete rule form used by Add Rule.</div></div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}><span style={{ color: MON.cyan, fontSize: 10, fontWeight: 800 }}>{rules.length} RULES</span><button type="button" onClick={() => { setEditingRuleId(null); setEditingBuiltIn(false); setNewRule(EMPTY_BEACON_RULE); setShowRuleForm(value => !value); }} style={{ border: `1px solid ${MON.green}`, color: '#001018', background: MON.green, borderRadius: 6, padding: '7px 11px', cursor: 'pointer', fontSize: 10, fontWeight: 900 }}>＋ Add Rule</button></div>
        </div>
        {showRuleForm && (
          <div style={{ margin: 12, padding: 14, background: MON.card2, border: `1px solid ${MON.cyan}66`, borderRadius: 8 }}>
            <div style={{ color: '#fff', fontSize: 12, fontWeight: 900, marginBottom: 12 }}>{editingRuleId ? 'Edit Beaconing Rule' : 'Create Custom Beaconing Rule'}</div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(150px, 1fr))', gap: 10 }}>
              <label style={{ color: MON.muted, fontSize: 9 }}>Rule Name<input value={newRule.name} disabled={editingBuiltIn} maxLength={100} onChange={event => setNewRule(current => ({ ...current, name: event.target.value }))} placeholder="Corporate HTTPS callback" style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: editingBuiltIn ? MON.muted : '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Protocol<select value={newRule.protocol} onChange={event => setNewRule(current => ({ ...current, protocol: event.target.value }))} style={{ display: 'block', width: '100%', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }}><option value="any">Any</option><option value="web">HTTP / HTTPS / TLS</option><option value="dns">DNS</option><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Severity<select value={newRule.severity} onChange={event => setNewRule(current => ({ ...current, severity: event.target.value }))} style={{ display: 'block', width: '100%', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }}>{['low', 'medium', 'high', 'critical'].map(level => <option key={level} value={level}>{level}</option>)}</select></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Risk Score<input type="number" min="25" max="100" value={newRule.riskScore} onChange={event => setNewRule(current => ({ ...current, riskScore: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Minimum Connections<input type="number" min="4" max="1000" value={newRule.minimumConnections} onChange={event => setNewRule(current => ({ ...current, minimumConnections: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Minimum Interval (sec)<input type="number" min="1" max="86400" value={newRule.minimumIntervalSeconds} onChange={event => setNewRule(current => ({ ...current, minimumIntervalSeconds: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Maximum Interval (sec)<input type="number" min="1" max="86400" value={newRule.maximumIntervalSeconds} onChange={event => setNewRule(current => ({ ...current, maximumIntervalSeconds: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9 }}>Consistency (%)<input type="number" min="0" max="100" value={newRule.consistencyThreshold} onChange={event => setNewRule(current => ({ ...current, consistencyThreshold: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9, gridColumn: 'span 2' }}>Process Name Contains (optional)<input value={newRule.processName} maxLength={512} onChange={event => setNewRule(current => ({ ...current, processName: event.target.value }))} placeholder="powershell, python, custom-agent" style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
              <label style={{ color: MON.muted, fontSize: 9, gridColumn: 'span 2' }}>Description<input value={newRule.description} maxLength={2000} onChange={event => setNewRule(current => ({ ...current, description: event.target.value }))} placeholder="Explain when this rule should match" style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12 }}><label style={{ color: newRule.enabled ? MON.green : MON.muted, fontSize: 10, fontWeight: 800 }}><input type="checkbox" checked={newRule.enabled} onChange={event => setNewRule(current => ({ ...current, enabled: event.target.checked }))} /> Enabled</label><div style={{ display: 'flex', gap: 7 }}><button type="button" onClick={() => { setShowRuleForm(false); setEditingRuleId(null); setEditingBuiltIn(false); setNewRule(EMPTY_BEACON_RULE); }} disabled={creatingRule} style={{ border: `1px solid ${MON.border}`, color: MON.muted, background: MON.bg, borderRadius: 5, padding: '7px 12px', cursor: 'pointer' }}>Cancel</button><button type="button" onClick={createRule} disabled={creatingRule} style={{ border: 'none', color: '#001018', background: MON.green, borderRadius: 5, padding: '7px 14px', cursor: 'pointer', fontWeight: 900 }}>{creatingRule ? 'Saving…' : editingRuleId ? 'Update & Deploy Rule' : 'Add & Deploy Rule'}</button></div></div>
          </div>
        )}
        <div style={{ minWidth: 840, overflowX: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr .7fr 2fr .7fr .7fr 110px', gap: 10, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
            <span>Rule</span><span>Category</span><span>Description</span><span>Severity</span><span>Status</span><span>Action</span>
          </div>
          {loading ? <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>Loading rules…</div> : rules.map(rule => {
            return (
              <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '1.4fr .7fr 2fr .7fr .7fr 110px', gap: 10, alignItems: 'center', padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}>
                <div><b style={{ color: MON.text }}>{rule.name}</b><div style={{ color: MON.sub, fontFamily: 'monospace', fontSize: 8, marginTop: 2 }}>{rule.id}</div></div>
                <span style={{ color: MON.cyan }}>{rule.category}</span><span style={{ color: MON.muted }}>{rule.description}</span>
                <b style={{ color: SEV_COLOR[rule.severity] || MON.muted, textTransform: 'uppercase' }}>{rule.severity}</b>
                <b style={{ color: rule.enabled !== false ? MON.green : MON.muted }}>{rule.enabled !== false ? 'ENABLED' : 'DISABLED'}</b>
                <button type="button" onClick={() => editBeaconRule(rule)} style={{ border: `1px solid ${MON.cyan}`, color: MON.cyan, background: `${MON.cyan}12`, borderRadius: 5, padding: '5px 10px', cursor: 'pointer', fontSize: 9, fontWeight: 800 }}>✎ Edit</button>
              </div>
            );
          })}
        </div>
      </div>

      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div><div style={{ color: '#fff', fontSize: 12, fontWeight: 900 }}>🛡️ C2 Containment Response</div><div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>Creates approval-gated actions only for actionable Beaconing alerts at or above the selected risk score.</div></div>
          <label style={{ display: 'flex', gap: 7, alignItems: 'center', color: containment.enabled ? MON.green : MON.muted, fontSize: 10, fontWeight: 800 }}><input type="checkbox" checked={containment.enabled} onChange={event => setContainment(current => ({ ...current, enabled: event.target.checked }))} />{containment.enabled ? 'Enabled' : 'Disabled'}</label>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(150px, 1fr))', gap: 10, marginTop: 14 }}>
          <label style={{ color: MON.muted, fontSize: 9 }}>Containment Action<select value={containment.actionType} onChange={event => setContainment(current => ({ ...current, actionType: event.target.value }))} style={{ display: 'block', width: '100%', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }}><option value="block_ip">Block C2 Destination IP</option><option value="isolate">Isolate Endpoint</option><option value="kill_process">Kill Beaconing Process</option></select></label>
          <label style={{ color: MON.muted, fontSize: 9 }}>Minimum Risk Score<input type="number" min="25" max="100" value={containment.minimumRiskScore} onChange={event => setContainment(current => ({ ...current, minimumRiskScore: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
          <label style={{ color: MON.muted, fontSize: 9 }}>Cooldown (minutes)<input type="number" min="1" max="1440" value={containment.cooldownMinutes} onChange={event => setContainment(current => ({ ...current, cooldownMinutes: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
          <label style={{ color: MON.muted, fontSize: 9 }}>Maximum Actions / Hour<input type="number" min="1" max="100" value={containment.maxExecutionsPerHour} onChange={event => setContainment(current => ({ ...current, maxExecutionsPerHour: Number(event.target.value) }))} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 5, background: MON.bg, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 8 }} /></label>
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, gap: 10 }}><span style={{ color: MON.yellow, fontSize: 9 }}>🔐 Analyst approval is always required before containment is sent to an endpoint.</span><button type="button" onClick={saveContainment} disabled={loading || containmentSaving} style={{ background: MON.green, color: '#001018', border: 'none', padding: '8px 15px', borderRadius: 6, cursor: 'pointer', fontWeight: 900 }}>{containmentSaving ? 'Saving…' : 'Save Containment Policy'}</button></div>
      </div>

      {message && <div style={{ color: /unable|invalid|error/i.test(message) ? MON.red : MON.green, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 6, padding: 10, fontSize: 11 }}>{message}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}><button type="button" onClick={loadConfiguration} disabled={loading || saving} style={{ background: MON.card2, color: MON.text, border: `1px solid ${MON.border}`, padding: '9px 15px', borderRadius: 6, cursor: 'pointer', fontWeight: 800 }}>Reload</button><button type="button" onClick={saveConfiguration} disabled={loading || saving} style={{ background: MON.cyan, color: '#001018', border: 'none', padding: '9px 18px', borderRadius: 6, cursor: 'pointer', fontWeight: 900 }}>{saving ? 'Saving…' : 'Save & Deploy'}</button></div>
    </div>
  );
}

function BeaconingOverviewDashboard({ alerts = [], total = 0, onAction }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };
  const rows = Array.isArray(alerts) ? alerts : [];
  const totalEvents = total || rows.length;
  const response = responseSummary(rows);
  const targetCount = uniqueCount(rows, beaconC2Target);
  const lowJitterCount = rows.filter(row => Number(row?.jitterSeconds) >= 0 && Number(row?.jitterSeconds) < 5).length;
  const topTargets = topCounts(rows, beaconC2Target, 4);
  const topProcesses = topCounts(rows, beaconProcess, 4);
  const protocolCounts = topCounts(rows, beaconProto, 4);
  const protocolTotal = protocolCounts.reduce((sum, [, value]) => sum + value, 0);

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);

  const summaryCards = [
    { title: 'Total Beaconing Detections', value: shortNum(totalEvents), delta: 'observed detection records', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'Critical C2 Beaconing', value: shortNum(rows.filter(r => alertSeverity(r) === 'critical').length), delta: 'critical detections', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Observed Remote Targets', value: shortNum(targetCount), delta: 'unique destinations', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Low Jitter (<5s)', value: shortNum(lowJitterCount), delta: 'measured channels', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
    { title: 'Successful Containments', value: shortNum(response.successful), delta: response.attempted ? `${response.attempted} attempted` : 'no response telemetry', color: MON.green, bg: 'linear-gradient(135deg,#064e3b,#09231b)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, background: '#06111f', border: `1px solid ${MON.border}`, borderRadius: 10, padding: 12 }}>
      {/* Top Banner Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '12px 14px', borderRadius: 9, background: 'linear-gradient(100deg,#0c2943,#091725)', border: `1px solid ${MON.cyan}40` }}>
        <div>
          <div style={{ color: '#f8fafc', fontSize: 15, fontWeight: 900 }}>📡 Beaconing & C2 Traffic Intelligence Operations Center</div>
          <div style={{ color: MON.muted, fontSize: 9, marginTop: 4 }}>Real-time heartbeat pulse detection across 15 SOC categories · Capability ID 26</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span style={{ color: MON.green, fontSize: 9, fontWeight: 800, padding: '5px 9px', border: `1px solid ${MON.green}55`, borderRadius: 12 }}>● LIVE INGESTION</span>
          <span style={{ color: MON.cyan, fontSize: 9, fontWeight: 800, padding: '5px 9px', border: `1px solid ${MON.cyan}55`, borderRadius: 12 }}>AUTO REFRESH 15s</span>
        </div>
      </div>

      {/* Top 5 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 10 }}>
        {summaryCards.map(card => (
          <div key={card.title} style={{ background: card.bg, border: `1px solid ${card.color}55`, borderRadius: 7, padding: 14, minHeight: 86, position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: 9, color: '#dbeafe', fontWeight: 900, textTransform: 'uppercase' }}>{card.title}</div>
            <div style={{ marginTop: 8, fontSize: 24, color: '#fff', fontWeight: 900 }}>{card.value}</div>
            <div style={{ marginTop: 7, fontSize: 9, color: card.color }}>↗ {card.delta}</div>
            <div style={{ position: 'absolute', right: 8, bottom: 8, width: 70, opacity: 0.9 }}><MiniSparkline data={timeline} color={card.color} height={26} /></div>
          </div>
        ))}
      </div>

      {/* Middle Grid (4 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        {/* Panel 1: Protocol Distribution */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>C2 Transport Protocol Breakdown</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(protocolCounts.length ? protocolCounts : [['No protocol telemetry', 0]]).map(([label, count], index) => {
              const item = { label, pct: protocolTotal ? Math.round((count / protocolTotal) * 100) : 0, col: [MON.blue, MON.purple, MON.orange, MON.red][index] || MON.cyan };
              return (
              <div key={item.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                  <span style={{ color: MON.text }}>{item.label}</span>
                  <b style={{ color: item.col }}>{item.pct}%</b>
                </div>
                <div style={{ width: '100%', height: 5, background: '#07101b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${item.pct}%`, height: '100%', background: item.col }} />
                </div>
              </div>
            );})}
          </div>
        </div>

        {/* Panel 2: Frequency & Jitter Analysis */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Beacon Frequency & Jitter Analysis</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Up to 30 Seconds:</span> <b style={{ color: MON.red }}>{rows.filter(row => Number(row?.averageInterval) > 0 && Number(row?.averageInterval) <= 30).length}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>31–60 Seconds:</span> <b style={{ color: MON.orange }}>{rows.filter(row => Number(row?.averageInterval) > 30 && Number(row?.averageInterval) <= 60).length}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>1–5 Minutes:</span> <b style={{ color: MON.yellow }}>{rows.filter(row => Number(row?.averageInterval) > 60 && Number(row?.averageInterval) <= 300).length}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Over 5 Minutes:</span> <b style={{ color: MON.green }}>{rows.filter(row => Number(row?.averageInterval) > 300).length}</b></div>
          </div>
        </div>

        {/* Panel 3: Heartbeat Timeline */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>C2 Heartbeat Pulse Timeline (24h)</b>
          <div style={{ height: 100, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.blue}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        {/* Panel 4: Top C2 Targets */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Top Flagged C2 Remote Targets</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topTargets.length ? topTargets : [['No destination telemetry', 0]]).map(([ip, count], index) => (
              <div key={ip} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan, fontFamily: 'monospace' }}>🌐 {ip}</span>
                <b style={{ color: [MON.red, MON.orange, MON.yellow, MON.purple][index] || MON.cyan }}>{count} alerts</b>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Agent-Based Endpoint Inspection Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based C2 Beaconing Inspection (Endpoints & Servers)</div>
          <div style={{ fontSize: 9, color: MON.green }}>● Real-Time Agent Telemetry Stream Active (Click row for Forensic Panel)</div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 1.8fr 1fr 1.2fr 1fr 1fr 1.4fr', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
          <span>Host</span><span>Process</span><span>Destination C2 Target</span><span>Protocol</span><span>Frequency</span><span>Duration</span><span>Risk</span><span>Threat Status</span>
        </div>
        {rows.map((row, idx) => (
          <div
            key={idx}
            onClick={() => setSelectedLog(row)}
            style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 1.8fr 1fr 1.2fr 1fr 1fr 1.4fr', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center', cursor: 'pointer', transition: 'background 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.background = MON.card2}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <b style={{ color: MON.cyan }}>{alertHost(row)}</b>
            <span style={{ color: MON.text, fontFamily: 'monospace' }}>{beaconProcess(row)}</span>
            <code style={{ color: MON.purple }}>{beaconC2Target(row)}</code>
            <span style={{ color: MON.text }}>{beaconProto(row)}</span>
            <span style={{ color: MON.yellow, fontWeight: 700 }}>{beaconInterval(row)}</span>
            <span style={{ color: MON.muted }}>{beaconDuration(row)}</span>
            <b style={{ color: SEV_COLOR[alertSeverity(row)], textTransform: 'uppercase' }}>{alertSeverity(row)}</b>
            <b style={{ color: MON.green }}>{row.status || 'Possible C2 Beaconing'}</b>
          </div>
        ))}
      </div>

      {/* 3 Bottom Analytics Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Beacon Event Wave (24 Hours)</div>
          <div style={{ height: 120, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
            {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
              <div key={idx} title={`${val} beaconing events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Flagged Beaconing Processes</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
            {(topProcesses.length ? topProcesses : [['No process telemetry', 0]]).map(([proc, cnt], index) => (
              <div key={proc} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.text, fontWeight: 700 }}>{proc}</span>
                <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan, fontWeight: 800 }}>{cnt} events</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ C2 Policy Protection Status</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
            {[
              ['C2 containment actions', response.attempted ? `${response.successful}/${response.attempted} successful` : 'Not configured', response.attempted ? MON.green : MON.muted],
              ['DNS beacon telemetry', countMatching(rows, /dns/) ? `${countMatching(rows, /dns/)} observed` : 'No telemetry', countMatching(rows, /dns/) ? MON.cyan : MON.muted],
              ['TLS/HTTPS beacon telemetry', rows.filter(row => /https|tls/i.test(beaconProto(row))).length ? `${rows.filter(row => /https|tls/i.test(beaconProto(row))).length} observed` : 'No telemetry', MON.cyan],
              ['Threat-intelligence matches', countMatching(rows, /ioc|threat intel|malicious destination/) ? `${countMatching(rows, /ioc|threat intel|malicious destination/)} observed` : 'No telemetry', MON.cyan],
            ].map(([lbl, stat, col]) => (
              <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.muted }}>{lbl}</span>
                <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedLog && <BeaconingForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD COMPONENT (`BeaconingDashboardPanel`)
// ═════════════════════════════════════════════════════════════════════════════
export function BeaconingDashboardPanel({ alerts = [], loading = false, total = 0, systems = [], onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [containmentConfigured, setContainmentConfigured] = useState(false);

  useEffect(() => {
    let mounted = true;
    api.get('/auto-response/playbooks', { skipCache: true }).then(response => {
      const playbooks = Array.isArray(response.data) ? response.data : [];
      const configured = playbooks.some(item => Array.isArray(item.tags)
        && item.tags.includes(C2_CONTAINMENT_TAG)
        && item.enabled !== false
        && item.executionMode !== 'disabled');
      if (mounted) setContainmentConfigured(configured);
    }).catch(() => {});
    return () => { mounted = false; };
  }, []);

  const rows = Array.isArray(alerts) ? alerts : [];
  const totalRows = total || rows.length;

  const timeline = buildBuckets(rows, 8, 24);
  const response = responseSummary(rows);
  const periodicCount = rows.filter(row => Number(row?.periodicityScore) > 0 || /periodic|beacon/i.test(beaconText(row))).length;
  const dnsCount = rows.filter(row => /dns/i.test(`${beaconProto(row)} ${beaconText(row)}`)).length;
  const httpCount = rows.filter(row => /https?|tls/i.test(beaconProto(row))).length;
  const retryCount = rows.reduce((sum, row) => sum + (Number(row?.retryCount) || 0), 0);
  const topProcesses = topCounts(rows, beaconProcess, 4);

  // 20 Beaconing & C2 SOC Categories & Metrics
  const kpis = [
    { label: '📡 1. Total Beaconing Detections', val: shortNum(totalRows), trend: 'Detections', color: MON.blue, data: timeline },
    { label: '⏱️ 2. Periodic Outbound Connections (30s/1m/5m)', val: shortNum(periodicCount), trend: 'Periodic', color: MON.green, data: timeline },
    { label: '🌐 3. Observed Destination IPs / Domains', val: shortNum(uniqueCount(rows, beaconC2Target)), trend: 'Destinations', color: MON.red, data: timeline },
    { label: '🔎 4. Domain Beaconing & NRD Requests', val: shortNum(dnsCount), trend: 'DNS Query', color: MON.purple, data: timeline },
    { label: '⚙️ 5. Process-to-Network Correlations', val: shortNum(rows.filter(row => beaconProcess(row) !== '—' && beaconC2Target(row) !== '—').length), trend: 'Correlated', color: MON.orange, data: timeline },
    { label: '⏳ 6. Low & Slow Heartbeat Traffic Detection', val: shortNum(rows.filter(row => Number(row?.averageInterval) >= 600 || /low.{0,3}slow/i.test(beaconText(row))).length), trend: 'Low & Slow', color: MON.yellow, data: timeline },
    { label: '🕳️ 7. DNS Tunneling & Frequency Anomalies', val: shortNum(countMatching(rows, /dns tunn|dns.{0,20}(periodic|frequen|anomal)/)), trend: 'Tunneling', color: MON.red, data: timeline },
    { label: '🌐 8. HTTP/HTTPS Beaconing', val: shortNum(httpCount), trend: 'HTTP C2', color: MON.cyan, data: timeline },
    { label: '🔑 9. Encrypted C2 Traffic', val: shortNum(rows.filter(row => /https|tls/i.test(beaconProto(row)) || /encrypted c2/i.test(beaconText(row))).length), trend: 'TLS Metadata', color: MON.purple, data: timeline },
    { label: '❌ 10. Failed C2 Connection Attempts & Retries', val: shortNum(retryCount || countMatching(rows, /failed|retry|unreachable/)), trend: 'Retries', color: MON.yellow, data: timeline },
    { label: '🔒 11. Process Persistence + Beaconing Launch', val: shortNum(countMatching(rows, /persist|scheduled task|run key|service/)), trend: 'Persistence', color: MON.red, data: timeline },
    { label: '🌙 12. User Idle / After-Hours Beaconing', val: shortNum(countMatching(rows, /after.hours|idle|night/)), trend: 'After-Hours', color: MON.orange, data: timeline },
    { label: '📤 13. Data Exfiltration Beaconing', val: shortNum(countMatching(rows, /exfil|large outbound|periodic chunk/)), trend: 'Exfiltration', color: MON.red, data: timeline },
    { label: '↔️ 14. Lateral Movement Internal Callbacks', val: shortNum(countMatching(rows, /lateral|smb|winrm|psexec|wmi/)), trend: 'Internal C2', color: MON.purple, data: timeline },
    { label: '🚨 15. Threat Intelligence IOC Matches', val: shortNum(countMatching(rows, /ioc|threat intel|malicious destination/)), trend: 'IOC Match', color: MON.red, data: timeline },
    { label: '⚡ 16. Low Jitter (<2s)', val: shortNum(rows.filter(row => Number(row?.jitterSeconds) >= 0 && Number(row?.jitterSeconds) < 2).length), trend: 'Low Jitter', color: MON.cyan, data: timeline },
    { label: '🎲 17. High Jitter (>30s)', val: shortNum(rows.filter(row => Number(row?.jitterSeconds) > 30).length), trend: 'High Jitter', color: MON.yellow, data: timeline },
    { label: '🦠 18. Malware-Associated Callbacks', val: shortNum(countMatching(rows, /malware|cobalt|rat|botnet|backdoor/)), trend: 'Callbacks', color: MON.red, data: timeline },
    { label: '🖥️ 19. Endpoints Reporting Beaconing', val: shortNum(systems.length), trend: 'Endpoints', color: MON.cyan, data: timeline },
    { label: '🛡️ 20. C2 Containment Success Rate', val: response.attempted ? response.rate : containmentConfigured ? 'Ready' : 'Not configured', trend: response.attempted ? 'Response Audit' : containmentConfigured ? 'Approval Gated' : 'No Actions', color: response.attempted || containmentConfigured ? MON.green : MON.muted, data: timeline, configure: true },
  ];

  const agentStatusRows = systems.map(sys => {
    const host = sys.hostname || sys.name || '—';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || '—',
      hostname: host,
      status: sys.status || (sys.agentOk || sys.isOnline ? 'reporting' : 'unknown'),
      events: hostEvents,
      threats,
      platform: sys.platform || sys.os || '—',
      lastSeen: sys.lastSeen || sys.updatedAt || null,
    });
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📊', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'logs', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
          { id: 'configuration', icon: '⚙️', label: 'Configure', activeColor: MON.cyan },
        ].map(item => {
          const selected = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                background: selected ? item.activeColor : 'transparent',
                color: selected ? (item.id === 'reports' ? '#fff' : '#000') : MON.text,
                border: selected ? `1px solid ${item.activeColor}` : '1px solid transparent',
                padding: '10px 12px', borderRadius: 7, fontSize: 12, fontWeight: 800,
                textAlign: 'left', cursor: 'pointer',
              }}
            >
              <span>{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </aside>

      {/* Main Container */}
      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>
        {activeTab === 'logs' ? (
          <CapabilityLogsPanel capabilityId={26}>
            <BeaconingLogMonitor alerts={alerts} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <BeaconingReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <BeaconingOverviewDashboard alerts={alerts} total={total} onAction={onAction} />
        ) : activeTab === 'configuration' ? (
          <BeaconingConfigurationTab systems={systems} onContainmentChange={setContainmentConfigured} />
        ) : (
          <>
            {/* 20 Top KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div
                  key={i}
                  style={{
                    background: 'linear-gradient(135deg, #0b1929 0%, #0d2238 100%)',
                    border: `1px solid ${kpi.color}44`,
                    borderRadius: 9,
                    padding: '12px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    justify: 'space-between',
                    minHeight: 96,
                    boxShadow: `0 4px 14px rgba(0,0,0,0.35), inset 0 0 12px ${kpi.color}0a`,
                    position: 'relative',
                    overflow: 'hidden',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ fontSize: 10, fontWeight: 800, color: '#e2e8f0', lineHeight: 1.35, flex: 1 }}>{kpi.label}</div>
                    <span style={{ fontSize: 8.5, fontWeight: 900, color: kpi.color, background: `${kpi.color}18`, border: `1px solid ${kpi.color}44`, padding: '2px 7px', borderRadius: 10, whiteSpace: 'nowrap', flexShrink: 0 }}>
                      {kpi.trend}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 12 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: '#ffffff', letterSpacing: '-0.5px' }}>{kpi.val}</div>
                    <div style={{ width: 68, opacity: 0.9, flexShrink: 0 }}>
                      <MiniSparkline data={kpi.data} color={kpi.color} height={26} />
                    </div>
                  </div>
                  {kpi.configure && <button type="button" onClick={() => setActiveTab('configuration')} style={{ alignSelf: 'flex-start', marginTop: 8, border: `1px solid ${MON.cyan}`, background: `${MON.cyan}16`, color: MON.cyan, borderRadius: 5, padding: '4px 9px', fontSize: 9, fontWeight: 900, cursor: 'pointer' }}>⚙ Configure</button>}
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Beaconing Inspection (Endpoints & Servers)</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} tenant endpoints loaded · {rows.length} beaconing records observed</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>Beacon Engine</span><span>Total Beacons</span><span>C2 Threat Alerts</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: /online|reporting|active/i.test(String(row.status)) ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.status}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : '—'}</span>
                </div>
              ))}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Beacon Event Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} beaconing events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Flagged Beaconing Processes</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(topProcesses.length ? topProcesses : [['No process telemetry', 0]]).map(([proc, cnt], index) => (
                    <div key={proc} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{proc}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan, fontWeight: 800 }}>{cnt} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ C2 Policy Protection Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['C2 containment actions', response.attempted ? `${response.successful}/${response.attempted} successful` : 'Not configured', response.attempted ? MON.green : MON.muted],
                    ['DNS beacon telemetry', dnsCount ? `${dnsCount} observed` : 'No telemetry', dnsCount ? MON.cyan : MON.muted],
                    ['TLS/HTTPS metadata', httpCount ? `${httpCount} observed` : 'No telemetry', httpCount ? MON.cyan : MON.muted],
                    ['Threat-intelligence matches', countMatching(rows, /ioc|threat intel|malicious destination/) ? `${countMatching(rows, /ioc|threat intel|malicious destination/)} observed` : 'No telemetry', MON.cyan],
                  ].map(([lbl, stat, col]) => (
                    <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{lbl}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
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

export default function BeaconingDetectionPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ page: 1, limit: 1000, capabilityId: 26 });
      const r = await api.get(`/dashboard/alerts/edr?${q}`);
      setAlerts(r.data?.alerts || []);
      setTotal(r.data?.total || 0);
    } catch {
      setAlerts([]);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 15000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refresh = createEventBuffer(() => loadAlerts(true), 500);
    socket.on('connect', join);
    socket.on('alert:new', refresh.add);
    socket.on('alert:updated', refresh.add);
    socket.on('beaconing:event', refresh.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', refresh.add);
      socket.off('alert:updated', refresh.add);
      socket.off('beaconing:event', refresh.add);
      refresh.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            📡 26. Beaconing & C2 Traffic Detection
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>— {Number(total || alerts.length).toLocaleString()} logs</span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <BeaconingDashboardPanel alerts={alerts} loading={loading} total={total} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <BeaconingDetectionPage />;
}

export function BeaconingSubTabPage() {
  return <BeaconingDashboardPanel alerts={[]} />;
}
