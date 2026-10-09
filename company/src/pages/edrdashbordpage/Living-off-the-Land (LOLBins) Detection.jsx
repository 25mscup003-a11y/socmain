import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Living-off-the-Land (LOLBins) Detection — Capability ID: 28
 *
 * 100% Self-Contained Enterprise SOC Living-off-the-Land (LOLBins) Detection Module
 * Linked to the canonical capability-28 live API, MongoDB Alert Query, and
 * authenticated Socket.io real-time stream.
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

function rawLolbin(alert = {}) {
  const rawEvent = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : {};
  const nested = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
  return { ...rawEvent, ...nested };
}

function normalizeLolbinAlert(alert = {}) {
  const raw = rawLolbin(alert);
  const processCmdline = alert.processCmdline || alert.commandLine || raw.process_cmdline || raw.command_line || raw.cmdline || '';
  return {
    ...alert,
    processName: alert.processName || alert.process || raw.process_name || raw.process || '',
    processExe: alert.processExe || raw.process_exe || raw.exe || alert.filePath || raw.file_path || '',
    commandLine: processCmdline,
    processCmdline,
    pid: alert.pid ?? alert.processId ?? raw.pid ?? raw.process_id,
    parentPid: alert.parentPid ?? raw.parent_pid,
    parentProcessName: alert.parentProcessName || raw.parent_process_name || '',
    parentCommandLine: alert.parentCommandLine || raw.parent_command_line || raw.parent_cmdline || '',
    username: alert.username || raw.username || raw.user || '',
    detectionRule: alert.detectionRule || alert.detectionRuleName || alert.technique || raw.technique || alert.ruleId || raw.rule_id || '',
    riskScore: alert.riskScore ?? raw.risk_score ?? 0,
    osType: alert.osType || alert.os || raw.os_type || raw.os || raw.platform || '',
    fileHash: alert.fileHash || alert.processExecutableSha256 || raw.file_hash || raw.executable_sha256 || '',
    fileHashMd5: alert.fileHashMd5 || alert.processExecutableMd5 || raw.file_hash_md5 || raw.executable_md5 || '',
    signatureStatus: alert.processSignatureStatus || raw.signature_status || '',
    publisher: alert.processPublisher || raw.publisher || '',
    processCompany: alert.processFileCompany || raw.company || '',
    processVersion: alert.processFileVersion || raw.version || '',
    processStartTime: alert.processCreateTime || raw.start_time || raw.process_create_time || alert.createdAt,
    processEndTime: alert.processEndTime || raw.end_time || raw.process_end_time || '',
    exitCode: alert.processExitCode ?? raw.exit_code,
    integrityLevel: alert.processIntegrityLevel || raw.integrity_level || '',
    domainName: raw.domain || '',
  };
}

function isLolbinAlert(alert = {}) {
  const ids = [alert.capabilityId, ...(Array.isArray(alert.capabilityIds) ? alert.capabilityIds : [])].map(Number);
  return ids.includes(28) || /^LOLBIN_/i.test(String(alert.ruleId || alert.type || '')) || /^lolbins$/i.test(String(alert.source || ''));
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
export function LolbinsDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState(Array.isArray(log?.matchedPatterns) ? log.matchedPatterns.join(', ') : '');
  const [notesSaved, setNotesSaved] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'high').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.orange;
  const sevBg = SEV_BG[sev] || 'rgba(251, 146, 60, 0.15)';
  const processName = log.processName || log.process || log.rawEvent?.process_name || 'Not reported';
  const pid = log.pid ?? log.processId ?? 'Not reported';
  const hostname = log.hostname || log.agentName || log.systemId?.name || 'Not reported';
  const parentProcess = log.parentProcessName || 'Not reported';
  const eventTime = log.createdAt ? new Date(log.createdAt).toLocaleTimeString() : '—';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint Profile' },
    { id: 'lolbin-details', label: '🧰 4. LOLBin & Arguments' },
    { id: 'process', label: '⚙️ 5. Process Tree' },
    { id: 'network', label: '🔗 6. Network Context' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'threat-intel', label: '🧠 8. Threat Intel' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const handleTerminateProcess = async () => {
    setActionMsg(`Not sent: no terminate-process executor is configured for ${processName} (PID ${pid}) on ${hostname}.`);
  };

  const handleIsolateEndpoint = async () => {
    setActionMsg(`Not sent: no endpoint-isolation executor is configured for ${hostname}.`);
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleDownload = (format) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(log, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `lolbin_${log._id || 'event'}_${processName}.${format.toLowerCase()}`);
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
            <span style={{ fontSize: 24 }}>🧰</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  LOLBin Abuse Forensic Panel — {processName} (PID {pid})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: `${MON.purple}15`, border: `1px solid ${MON.purple}33` }}>
                  {log.detectionRule || log.ruleId || 'Not reported'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{hostname}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'Not reported'}</strong> | Parent: <strong style={{ color: MON.orange }}>{parentProcess}</strong> | Time: <strong style={{ color: MON.text }}>{log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'}</strong>
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
                  ['LOLBin Executable', processName, MON.cyan],
                  ['Process ID (PID)', pid, MON.blue],
                  ['Parent Process', parentProcess, MON.orange],
                  ['Detection Rule', log.detectionRule || log.ruleId || 'Not reported', MON.red],
                  ['Host System', hostname, MON.blue],
                  ['Logged User', log.username || 'Not reported', MON.purple],
                  ['Status', caseStatus, MON.green],
                  ['Assigned Analyst', assignedAnalyst, MON.yellow],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 14, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-all' }}>{val}</div>
                  </div>
                ))}
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Executed Command Line & Arguments:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.commandLine || log.processCmdline || 'Command line not reported by the endpoint'}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <button type="button" onClick={handleTerminateProcess} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  🛑 Terminate Process
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 LOLBin Execution & Payload Chronology</div>
              {[
                { type: 'Process Creation', time: eventTime, title: `${processName} detected`, desc: log.description || log.detectionRule || 'LOLBins detection event', col: SEV_COLOR[sev] || MON.red },
                ...(log.processEndTime ? [{ type: 'Process End', time: new Date(log.processEndTime).toLocaleTimeString(), title: `${processName} exited`, desc: `Exit code: ${log.exitCode ?? 'Not reported'}`, col: MON.blue }] : []),
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
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Endpoint Profile & OS Details</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', hostname],
                  ['Operating System', log.osType || log.os || 'Not reported'],
                  ['Logged-in User', log.username || 'Not reported'],
                  ['User Integrity Level', log.integrityLevel || 'Not reported'],
                  ['Domain / Workgroup', log.domainName || 'Not reported'],
                  ['IP Address', log.srcip || log.sourceIp || 'Not reported'],
                  ['Agent ID', log.agentId || '—'],
                  ['Agent Status', log.systemId?.status || 'Not reported'],
                  ['Digital Signature Status', log.signatureStatus || 'Not reported'],
                  ['Department', log.departmentId?.name || log.departmentId || 'Not reported'],
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

          {/* TAB 4: LOLBIN DETAILS */}
          {activeTab === 'lolbin-details' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧰 LOLBin Binary & Argument Inspection</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Binary Metadata</div>
                  {[
                    ['Executable Name', processName],
                    ['Binary Path', log.processExe || log.filePath || 'Not reported'],
                    ['Publisher', log.publisher || 'Not reported'],
                    ['Digital Signature', log.signatureStatus || 'Not reported'],
                    ['File Hash (SHA256)', log.fileHash || 'Not reported'],
                    ['File Hash (MD5)', log.fileHashMd5 || 'Not reported'],
                    ['Company / Version', [log.processCompany, log.processVersion].filter(Boolean).join(' / ') || 'Not reported'],
                    ['Known Abuse Techniques', (log.matchedPatterns || []).join(', ') || log.technique || 'Not reported'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: MON.text, wordBreak: 'break-all' }}>{v}</strong>
                    </div>
                  ))}
                </div>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Decoded Command Line Arguments</div>
                  <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, margin: 0, whiteSpace: 'pre-wrap' }}>
{log.commandLine || log.processCmdline || 'Command line not reported by the endpoint'}
                  </pre>
                  <div style={{ marginTop: 10, fontSize: 10, color: MON.red, fontWeight: 800 }}>
                    Detection evidence: {log.description || log.detectionRule || log.ruleId || 'Not reported'}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PROCESS TREE */}
          {activeTab === 'process' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Tree Context</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Parent ➔ Child Process Tree:</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {parentProcess} (PPID {log.parentPid ?? 'Not reported'}) ➔ <strong style={{ color: MON.red }}>{processName} (PID {pid})</strong>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Full Command Line:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.commandLine || log.processCmdline || 'Command line not reported by the endpoint'}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK CONTEXT */}
          {activeTab === 'network' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🔗 Network Connections & Remote URLs</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Source Host IP', log.srcip || log.sourceIp || 'Not reported'],
                  ['Destination IP', log.destip || 'Not reported'],
                  ['Protocol', log.protocol || 'Not reported'],
                  ['Remote URL / Domain', log.url || log.domain || 'Not reported'],
                  ['Bytes Downloaded', log.bytesReceived != null ? String(log.bytesReceived) : 'Not reported'],
                  ['Connection Status', log.connectionState || 'Not reported'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4, wordBreak: 'break-all' }}>{v}</div>
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
                {[[log.mitreId || 'Not reported', log.technique || log.detectionRule || 'Detection mapping', log.description || 'No additional evidence reported']].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: THREAT INTEL */}
          {activeTab === 'threat-intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Threat Intelligence & Abuse Patterns</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  { label: 'Abuse Pattern', value: log.technique || log.detectionRule || 'Not reported', col: MON.red, desc: (log.matchedPatterns || []).join(', ') || log.description || 'No pattern details reported.' },
                  { label: 'Parent Process', value: parentProcess, col: MON.orange, desc: log.parentCommandLine || 'Parent command line not reported.' },
                  { label: 'Threat Severity', value: `${sev.toUpperCase()} (${log.riskScore ?? 0}/100)`, col: sevColor, desc: `Calculated from the endpoint evidence captured for this event.` },
                  { label: 'Threat Intelligence', value: log.iocMatched ? 'Match detected' : 'No match reported', col: log.iocMatched ? MON.red : MON.green, desc: log.threatCategory || log.vtVerdict || 'No external threat-intelligence verdict reported.' },
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
                  <select value={assignedAnalyst} onChange={(e) => setAssignedAnalyst(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option>{assignedAnalyst}</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Case Status</div>
                  <select value={caseStatus} onChange={(e) => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option value="open">Open</option>
                    <option value="investigating">Investigating</option>
                    <option value="resolved">Resolved</option>
                    <option value="false_positive">False Positive</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Tags</div>
                  <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }} />
                </div>
              </div>
              <div style={{ fontSize: 12, color: MON.muted, fontWeight: 700 }}>Investigation Notes:</div>
              <textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} rows={6} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, color: MON.text, padding: 14, fontSize: 12, fontFamily: 'inherit', resize: 'vertical' }} />
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                  Save Case Notes
                </button>
                {notesSaved && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700 }}>✓ Draft notes saved in this investigation view</span>}
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
export function LolbinsLogMonitor({ alerts = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [binFilter, setBinFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = alerts;
  const rows = useMemo(() => effectiveAlerts.map(a => ({
    _id: a._id,
    timestamp: a.createdAt || a.timestamp || null,
    severity: (a.severity || 'low').toLowerCase(),
    status: a.status || 'open',
    hostname: a.hostname || a.agentName || a.systemId?.name || '—',
    username: a.username || 'Not reported',
    processName: a.processName || a.process || a.rawEvent?.process_name || 'Not reported',
    parentProcess: a.parentProcessName || 'Not reported',
    pid: a.pid || a.processId || '—',
    commandLine: a.commandLine || a.processCmdline || '—',
    detectionRule: a.detectionRule || a.ruleId || 'LOLBins event',
    riskScore: a.riskScore ?? 0,
    osType: a.osType || a.os || '—',
    raw: a,
  })), [alerts]);

  const filtered = useMemo(() => rows.filter(r => {
    if (sevFilter !== 'ALL' && r.severity !== sevFilter.toLowerCase()) return false;
    if (binFilter !== 'ALL' && !r.processName.toLowerCase().includes(binFilter.toLowerCase())) return false;
    if (!searchTerm) return true;
    const t = searchTerm.toLowerCase();
    return r.processName.toLowerCase().includes(t) || r.hostname.toLowerCase().includes(t) || r.commandLine.toLowerCase().includes(t) || r.parentProcess.toLowerCase().includes(t);
  }), [rows, searchTerm, sevFilter, binFilter]);

  const binaries = useMemo(() => ['ALL', ...new Set(rows.map(row => row.processName).filter(name => name && name !== 'Not reported'))], [rows]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}`, flexWrap: 'wrap' }}>
        <input type="text" placeholder="🔍 Search LOLBin logs (Binary, Command Line, Parent Process, Host)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, minWidth: 200, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {['ALL', 'critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={binFilter} onChange={(e) => setBinFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {binaries.map(b => <option key={b}>{b}</option>)}
        </select>
        <span style={{ fontSize: 10, color: MON.muted, alignSelf: 'center', padding: '0 8px' }}>{filtered.length} records</span>
      </div>

      <div style={{ overflowX: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Time', 'Severity', 'LOLBin Binary', 'PID', 'Parent Process', 'Hostname', 'Username', 'Command Line', 'Detection Rule', 'Risk Score', 'Status', 'OS'].map(h => <th key={h} style={{ padding: 10, whiteSpace: 'nowrap' }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row.raw)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.muted, whiteSpace: 'nowrap' }}>{row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '—'}</td>
                <td style={{ padding: 10 }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                <td style={{ padding: 10, color: MON.cyan, fontWeight: 700 }}>{row.processName}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.purple }}>{row.pid}</td>
                <td style={{ padding: 10, color: MON.orange, fontWeight: 700 }}>{row.parentProcess}</td>
                <td style={{ padding: 10, color: MON.blue, fontWeight: 700 }}>{row.hostname}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, color: MON.yellow, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontFamily: 'monospace' }} title={row.commandLine}>{row.commandLine}</td>
                <td style={{ padding: 10, color: MON.purple }}>{row.detectionRule}</td>
                <td style={{ padding: 10, color: row.riskScore >= 80 ? MON.red : MON.yellow, fontWeight: 800 }}>{row.riskScore}</td>
                <td style={{ padding: 10, color: row.status === 'resolved' ? MON.green : MON.yellow, fontWeight: 700 }}>{row.status}</td>
                <td style={{ padding: 10, color: MON.muted }}>{row.osType}</td>
              </tr>
            )) : <tr><td colSpan={12} style={{ padding: 40, textAlign: 'center', color: MON.muted }}>No LOLBin abuse logs found</td></tr>}
          </tbody>
        </table>
      </div>
      {selectedLog && <LolbinsDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. EXECUTIVE REPORT GENERATOR
// ═════════════════════════════════════════════════════════════════════════════
export function LolbinsReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={28} alerts={alerts} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERVIEW DASHBOARD — MATCHES DNS SINKHOLE ENTERPRISE SOC DESIGN
// ═════════════════════════════════════════════════════════════════════════════
function LolbinsOverviewDashboard({ alerts = [], total = 0 }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const data = useMemo(() => {
    const now = Date.now();
    const rows = alerts.map(a => {
      const processName = a.processName || a.process || a.rawEvent?.process_name || 'Not reported';
      const pid = a.pid || a.processId || '—';
      const time = new Date(a.createdAt || a.timestamp || 0);
      return { ...a, processName, pid, time };
    });

    const totalQ = Array(24).fill(0);
    const cradleHits = Array(24).fill(0);
    const encodedHits = Array(24).fill(0);
    rows.forEach(r => {
      const hoursAgo = Math.floor((now - r.time.getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) {
        const idx = 23 - hoursAgo;
        totalQ[idx]++;
        if (/urlcache|download|bitsadmin|webclient/i.test(`${r.commandLine || ''} ${r.description || ''}`)) cradleHits[idx]++;
        if (/enc|encoded|base64|iex/i.test(`${r.commandLine || ''} ${r.description || ''}`)) encodedHits[idx]++;
      }
    });

    const processMap = {}, parentMap = {}, hostMap = {};
    rows.forEach(r => {
      if (r.processName) {
        processMap[r.processName] = (processMap[r.processName] || { count: 0, level: r.severity || 'info', parent: r.parentProcessName || 'Not reported', cmd: r.commandLine || '—' });
        processMap[r.processName].count++;
      }
      const parent = r.parentProcessName || 'Not reported'; parentMap[parent] = (parentMap[parent] || 0) + 1;
      const host = r.hostname || r.agentName || 'Unknown';
      if (!hostMap[host]) hostMap[host] = { count: 0, ip: r.srcip || r.sourceIp || '—', hits: 0, status: r.systemId?.status || 'Unknown' };
      hostMap[host].count++;
      hostMap[host].hits++;
    });

    const topProcesses = Object.entries(processMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const topParents = Object.entries(parentMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topHosts = Object.entries(hostMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const recentAlerts = [...rows].sort((a, b) => b.time - a.time).slice(0, 8);
    const cradlesTotal = rows.filter(r => /urlcache|download|bitsadmin|webclient/i.test(`${r.commandLine || ''} ${r.description || ''}`)).length;
    const encodedTotal = rows.filter(r => /enc|encoded|base64|iex/i.test(`${r.commandLine || ''} ${r.description || ''}`)).length;
    const officeTotal = rows.filter(r => /winword|excel|outlook|office/i.test(`${r.parentProcessName || ''} ${r.description || ''}`)).length;
    const targetedBinaries = Object.keys(processMap).length;
    const categoryRows = [
      ['Download Cradle', cradlesTotal, MON.red, '📥'],
      ['Encoded Command', encodedTotal, MON.orange, '🔒'],
      ['Office Macro Child', officeTotal, MON.purple, '📄'],
      ['Remote SCT / HTA', rows.filter(r => /regsvr32|mshta|remote sct|remote hta/i.test(`${r.commandLine || ''} ${r.description || ''}`)).length, MON.yellow, '🌐'],
      ['WMI Remote Call', rows.filter(r => /wmic|wmi remote/i.test(`${r.commandLine || ''} ${r.description || ''}`)).length, MON.cyan, '⚙️'],
    ];
    const ruleBreakdown = categoryRows.map(([label, count, color, icon]) => [
      label,
      rows.length ? Number(((count / rows.length) * 100).toFixed(1)) : 0,
      color,
      icon,
    ]);
    const encodedPct = rows.length ? Number(((encodedTotal / rows.length) * 100).toFixed(1)) : 0;

    return { rows, totalQ, cradleHits, encodedHits, topProcesses, topParents, topHosts, recentAlerts, cradlesTotal, encodedTotal, officeTotal, targetedBinaries, encodedPct, ruleBreakdown };
  }, [alerts]);

  const kpiCards = [
    { label: 'TOTAL LOLBIN EVENTS', value: total || alerts.length, color: MON.blue, icon: '🧰', trend: 'Live 24h telemetry' },
    { label: 'DOWNLOAD CRADLES', value: data.cradlesTotal, color: MON.red, icon: '📥', trend: 'Live 24h telemetry' },
    { label: 'ENCODED POWERSHELL', value: data.encodedTotal, color: MON.orange, icon: '🔒', trend: 'Live 24h telemetry' },
    { label: 'OFFICE-PARENT SPAWNS', value: data.officeTotal, color: MON.purple, icon: '📄', trend: 'Live 24h telemetry' },
    { label: 'HIGH RISK HOSTS', value: alerts.length ? new Set(alerts.filter(a => ['high', 'critical'].includes(String(a.severity || '').toLowerCase())).map(a => a.hostname || a.agentName).filter(Boolean)).size : 0, color: MON.red, icon: '🖥️', trend: 'Live 24h telemetry' },
  ];

  const binColors = [MON.cyan, MON.purple, MON.red, MON.orange, MON.yellow, MON.blue];
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

      {/* ── Row 2: Activity Chart + Threat Matrix + LOLBin Types Donut ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.1fr 1fr', gap: 14 }}>

        {/* 24hr Multi-line Activity Chart */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📊 Living-off-the-Land (LOLBins) Execution Activity (24 Hours)</div>
            <div style={{ display: 'flex', gap: 12 }}>
              {[['Total Executions', MON.blue], ['Download Cradles', MON.red], ['Encoded Commands', MON.orange]].map(([l, c]) => (
                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                  <div style={{ width: 20, height: 2, background: c, borderRadius: 2 }} /><span style={{ color: MON.muted }}>{l}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ height: 180, position: 'relative' }}>
            <MultiLineChart height={170} datasets={[
              { data: data.totalQ, color: MON.blue },
              { data: data.cradleHits, color: MON.red },
              { data: data.encodedHits, color: MON.orange },
            ]} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.sub, fontSize: 8, marginTop: 6, paddingTop: 4, borderTop: `1px solid ${MON.line}` }}>
            {Array.from({ length: 7 }, (_, i) => {
              const d = new Date(Date.now() - (6 - i) * 4 * 3600000);
              return <span key={i}>{d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>;
            })}
          </div>
        </div>

        {/* LOLBin Threat Matrix */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🗺️ LOLBin Threat Distribution Heatmap</div>
          <div style={{ background: '#061220', borderRadius: 8, padding: 10, height: 140, position: 'relative', overflow: 'hidden' }}>
            {Array.from({ length: 6 }, (_, row) => Array.from({ length: 10 }, (_, col) => (
              <div key={`${row}-${col}`} style={{
                position: 'absolute',
                left: `${col * 10 + 3}%`, top: `${row * 16 + 4}%`,
                width: 5, height: 5, borderRadius: '50%',
                background: '#1a3050',
                opacity: 0.85,
              }} />
            )))}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 10 }}>
            {[['Download Cradle', MON.red], ['Encoded Command', MON.orange], ['Office Macro Child', MON.purple], ['Normal Execution', MON.line]].map(([l, c]) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
                <span style={{ color: MON.muted }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Abused LOLBin Executables Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 8 }}>📡 Top Abused LOLBins</div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <DonutChart value={total || alerts.length} maxValue={Math.max(total || alerts.length, 1)} color={MON.cyan} size={120} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {data.topProcesses.slice(0, 5).map(([proc, info], i) => (
              <div key={proc} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: binColors[i % 6] }} />
                  <span style={{ color: MON.muted }}>{proc}</span>
                </div>
                <span style={{ color: binColors[i % 6], fontWeight: 800 }}>
                  {alerts.length ? ((info.count / alerts.length) * 100).toFixed(1) : 0}%
                </span>
              </div>
            ))}
            {!data.topProcesses.length && <div style={{ color: MON.muted, fontSize: 9 }}>No LOLBin execution telemetry received.</div>}
          </div>
        </div>
      </div>

      {/* ── Row 3: Top Abused LOLBins Table + Recent Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>

        {/* Top Abused LOLBins & Command Lines */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.red }}>🧰</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Top Abused LOLBins & Command Lines</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700 }}>Abused Binaries: {data.targetedBinaries}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 80px 100px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Executable</span><span>Parent</span><span>Command Line</span><span>Threat Level</span>
          </div>
          {data.topProcesses.length ? data.topProcesses.map(([proc, info], i) => (
            <div key={proc} style={{ display: 'grid', gridTemplateColumns: '1fr 80px 100px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.cyan, fontFamily: 'monospace', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={proc}>
                <span style={{ color: MON.red, marginRight: 4 }}>●</span>{proc}
              </span>
              <span style={{ color: MON.orange, fontFamily: 'monospace', fontSize: 9 }}>{info.parent}</span>
              <span style={{ color: MON.yellow, fontFamily: 'monospace', fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={info.cmd}>{info.cmd}</span>
              <span>
                <span style={{
                  background: 'rgba(248,113,113,0.2)', color: MON.red, padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 800
                }}>{(info.level || 'high').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No LOLBin abuse data yet</div>
          )}
        </div>

        {/* Recent LOLBin Detection Alerts Stream */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.orange }}>⚠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Recent LOLBin Detection Alerts</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '70px 1fr 60px 90px 70px', padding: '6px 10px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Time</span><span>LOLBin</span><span>PID</span><span>Endpoint</span><span>Severity</span>
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
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No recent LOLBin alerts</div>
          )}
        </div>
      </div>

      {/* ── Row 4: Top Targeted Endpoints + Encoded vs Plaintext Donut + Rules Breakdown ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 14 }}>

        {/* Top Endpoints Targeted */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}` }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>🖥️ Top Endpoints Targeted for LOLBin Abuse</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Endpoint</span><span>IP Address</span><span>LOLBin Hits</span><span>Events</span><span>Status</span>
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

        {/* Encoded vs Plaintext Execution Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 10, alignSelf: 'flex-start' }}>⚖️ Plaintext vs Obfuscated Commands</div>
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
            <svg width={140} height={140} viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="52" fill="none" stroke="#0f233a" strokeWidth="18" />
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.blue} strokeWidth="18" strokeDasharray={`${(100 - data.encodedPct) * 3.27} 327`} strokeDashoffset={81.75} strokeLinecap="butt" />
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.orange} strokeWidth="18" strokeDasharray={`${data.encodedPct * 3.27} 327`} strokeDashoffset={81.75 - ((100 - data.encodedPct) * 3.27)} strokeLinecap="butt" />
              <text x="70" y="64" textAnchor="middle" fill="#f1f5f9" fontSize="18" fontWeight="900">{data.encodedPct}%</text>
              <text x="70" y="80" textAnchor="middle" fill={MON.muted} fontSize="9">Encoded / Obfuscated</text>
            </svg>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, width: '100%' }}>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Plaintext</div>
              <div style={{ fontSize: 16, color: MON.blue, fontWeight: 900 }}>{(100 - data.encodedPct).toFixed(1)}%</div>
            </div>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Encoded / IEX</div>
              <div style={{ fontSize: 16, color: MON.orange, fontWeight: 900 }}>{data.encodedPct.toFixed(1)}%</div>
            </div>
          </div>
        </div>

        {/* Detection Rules Breakdown */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 14 }}>🎯 LOLBin Detection Rules</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {data.ruleBreakdown.map(([cat, pct, col, icon]) => (
              <div key={cat}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{icon}</span><span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                  </div>
                  <span style={{ color: col, fontWeight: 800 }}>{pct}%</span>
                </div>
                <div style={{ height: 6, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${pct}%`, background: col, borderRadius: 4 }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Status Bar ── */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '8px 14px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
        <span style={{ color: MON.cyan }}>🛡️ Living-off-the-Land (LOLBins) Detection continuously monitors system process creation, command-line arguments, download cradles, and Office macro child spawns in real-time.</span>
        <span style={{ color: MON.sub }}>All times in IST (UTC +05:30)</span>
      </div>

      {selectedAlert && <LolbinsDetailModal log={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD COMPONENT (DEFAULT EXPORT)
// ═════════════════════════════════════════════════════════════════════════════
export default function LolbinsDashboard({ alerts: incomingAlerts = [], loading = false, total = 0 }) {
  const alerts = useMemo(() => incomingAlerts.map(normalizeLolbinAlert), [incomingAlerts]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [dnsSystems, setDnsSystems] = useState([]);

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
    const text = a => `${a.type || ''} ${a.ruleId || ''} ${a.source || ''} ${a.description || ''} ${a.commandLine || ''}`;
    const cradlesTotal = alerts.filter(a => /urlcache|download|bitsadmin|webclient/i.test(text(a))).length;
    const encodedTotal = alerts.filter(a => /enc|encoded|base64|iex/i.test(text(a))).length;
    const officeTotal = alerts.filter(a => /winword|excel|outlook|office/i.test(`${a.parentProcessName || ''} ${text(a)}`)).length;
    const critical = alerts.filter(a => a.severity === 'critical').length;
    const high = alerts.filter(a => a.severity === 'high').length;
    const medium = alerts.filter(a => a.severity === 'medium').length;
    const low = alerts.filter(a => a.severity === 'low').length;
    const informational = alerts.filter(a => ['info', 'informational'].includes(a.severity)).length;
    const targetedBinaries = new Set(alerts.map(a => a.processName).filter(Boolean)).size;
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
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown', events: 0, cradleHits: 0, encodedHits: 0, lastSeen: null });
      agent.events++;
      if (/urlcache|download|bitsadmin/i.test(text(a))) agent.cradleHits++;
      if (/enc|encoded|base64/i.test(text(a))) agent.encodedHits++;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
    });

    return {
      totalEvents: total || alerts.length,
      cradlesTotal, encodedTotal, officeTotal, critical, high, medium, low, informational,
      targetedBinaries, uniqueEndpoints,
      highCritical: critical + high,
      timeline,
      agentRows: Object.values(agentMap).sort((a, b) => b.events - a.events),
      topBinaries: Object.entries(alerts.reduce((counts, alert) => {
          const name = alert.processName || 'Not reported';
          counts[name] = (counts[name] || 0) + 1;
          return counts;
        }, {})).sort((a, b) => b[1] - a[1]).slice(0, 5),
    };
  }, [alerts, total]);

  const kpis = [
    ['Total LOLBin Events', 'totalEvents', MON.blue, '🧰'],
    ['Download Cradles', 'cradlesTotal', MON.red, '📥'],
    ['Encoded Commands', 'encodedTotal', MON.orange, '🔒'],
    ['Office Macro Spawns', 'officeTotal', MON.purple, '📄'],
    ['Abused LOLBin Binaries', 'targetedBinaries', MON.yellow, '🎯'],
    ['High & Critical Alerts', 'highCritical', MON.red, '⚠️'],
    ['Affected Endpoints', 'uniqueEndpoints', MON.cyan, '🖥️'],
    ['Critical Severity', 'critical', MON.red, '🔴'],
    ['High Severity', 'high', MON.orange, '🟠'],
    ['Online Agents', () => dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green, '🟢'],
    ['Total Agents', () => dnsSystems.length, MON.blue, '🖥️'],
    ['Offline Agents', () => dnsSystems.filter(s => !['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.muted, '⚫'],
    ['Certutil Abuse', () => alerts.filter(a => /certutil/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.red, '📜'],
    ['Mshta Remote HTA', () => alerts.filter(a => /mshta|remote hta/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.orange, '🌐'],
    ['Regsvr32 Remote SCT', () => alerts.filter(a => /regsvr32|remote sct/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.purple, '⚙️'],
    ['Rundll32 Execution', () => alerts.filter(a => /rundll32/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.yellow, '🔄'],
    ['Bitsadmin Transfer', () => alerts.filter(a => /bitsadmin/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.blue, '📦'],
    ['WMI Remote Call', () => alerts.filter(a => /\bwmic?\b|wmi remote/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.cyan, '📡'],
    ['PowerShell IEX', () => alerts.filter(a => /powershell.*\biex\b|invoke-expression/i.test(`${a.processName || ''} ${a.commandLine || ''} ${a.description || ''}`)).length, MON.red, '⚡'],
    ['AppLocker / WDAC Bypass', () => alerts.filter(a => /applocker|wdac|application control bypass/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length, MON.red, '🛡️'],
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
      lolbinMonitor: sys.lolbinMonitorEnabled !== false,
      lastSeen: sys.lastSeen || metrics?.lastSeen,
      events: metrics?.events || 0,
      cradleHits: metrics?.cradleHits || 0,
      encodedHits: metrics?.encodedHits || 0,
    };
  });
  liveStats.agentRows.forEach(m => {
    if (!agentStatusRows.some(r => r.name === m.name)) {
      agentStatusRows.push({ ...m, hostname: '—', status: 'reporting', lolbinMonitor: true });
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
          <div style={{ fontSize: 9, color: MON.muted, fontWeight: 800, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Live LOLBin Stats</div>
          {[
            ['Download Cradles', liveStats.cradlesTotal, MON.red],
            ['Encoded Commands', liveStats.encodedTotal, MON.orange],
            ['Office Spawns', liveStats.officeTotal, MON.purple],
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
          <CapabilityLogsPanel capabilityId={28}>
            <LolbinsLogMonitor alerts={alerts} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <LolbinsReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <LolbinsOverviewDashboard alerts={alerts} total={total} />
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

            {/* Agent-Level LOLBin Monitoring Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛡️ Agent-Level LOLBins & Built-in Command Monitoring</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(r => ['active', 'reporting', 'online'].includes(r.status)).length} reporting · 15s refresh</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent</span><span>Hostname</span><span>Status</span><span>LOLBin Monitor</span><span>Events</span><span>Download Cradles</span><span>Encoded Hits</span><span>Last Seen</span>
              </div>
              {agentStatusRows.length ? agentStatusRows.map(row => (
                <div key={row.key || row.name} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 105px 76px 92px 80px 140px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b>
                  <span>{row.hostname}</span>
                  <b style={{ color: ['active', 'reporting', 'online'].includes(row.status) ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.status}</b>
                  <span style={{ color: row.lolbinMonitor ? MON.green : MON.red }}>{row.lolbinMonitor ? 'Enabled' : 'Disabled'}</span>
                  <b>{row.events}</b>
                  <b style={{ color: row.cradleHits > 0 ? MON.red : MON.green }}>{row.cradleHits}</b>
                  <b style={{ color: row.encodedHits > 0 ? MON.orange : MON.green }}>{row.encodedHits}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Never'}</span>
                </div>
              )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading agent data...' : 'No LOLBin-monitoring agents found'}</div>}
            </div>

            {/* Charts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 LOLBin Abuse Activity Timeline (90 Days)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 4, borderBottom: `1px solid ${MON.line}` }}>
                  {liveStats.timeline.map((val, idx) => (
                    <div key={idx} title={`${val} events`} style={{ flex: 1, height: `${val ? Math.max(4, (val / Math.max(...liveStats.timeline, 1)) * 100) : 0}%`, background: val > 0 ? MON.red : '#0f233a', borderRadius: '2px 2px 0 0', opacity: 0.85 }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>☠️ Top Abused Utilities</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {liveStats.topBinaries.map(([rule, count], index) => {
                    const col = [MON.red, MON.orange, MON.purple, MON.yellow, MON.cyan][index];
                    return (
                    <div key={rule} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{rule}</span>
                      <b style={{ color: col }}>{count}</b>
                    </div>
                    );
                  })}
                  {!liveStats.topBinaries.length && <span style={{ color: MON.muted }}>No live utility data</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🎯 Threat Severity Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Critical', liveStats.critical, MON.red],
                    ['High', liveStats.high, MON.orange],
                    ['Medium', liveStats.medium, MON.yellow],
                    ['Low', liveStats.low, MON.green],
                    ['Info', liveStats.informational, MON.cyan],
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

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId: 28, windowHours: 24 });
      const r = await api.get(`/dashboard/capabilities/28/live?${q}`);
      const fetchedAlerts = r.data?.alerts || [];
      const fetchedTotal = r.data?.total || fetchedAlerts.length;

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal);
    } catch (err) {
      console.warn('[LOLBins fetch warning]', err);
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
    const addLiveAlert = (alert) => {
      if (!alert || !isLolbinAlert(alert)) return;
      setAlerts(prev => prev.some(item => String(item._id || item.eventId) === String(alert._id || alert.eventId)) ? prev : [alert, ...prev]);
    };
    socket.on('connect', join);
    socket.on('alert:new', addLiveAlert);
    socket.on('lolbins:event', addLiveAlert);
    socket.on('alert:updated', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', addLiveAlert);
      socket.off('lolbins:event', addLiveAlert);
      socket.off('alert:updated');
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 28. Living-off-the-Land (LOLBins) Detection</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#60a5fa', background: '#1e3a5f44', border: '1px solid #1e3a5f', padding: '3px 8px', borderRadius: 6, fontWeight: 'bold' }}>
              {Number(total || 0).toLocaleString()} records
            </span>
            <span style={{ fontSize: 10, color: loading ? MON.yellow : MON.green }}>{loading ? '⟳ Loading...' : '● Live'}</span>
            <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
          </div>
        </div>
        <LolbinsDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function LolbinsSubTabPage() {
  return <CapabilitySubTabPage kind="lolbins" />;
}
