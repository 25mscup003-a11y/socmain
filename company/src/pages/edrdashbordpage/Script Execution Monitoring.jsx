import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Script Execution Monitoring — Capability ID: 21
 *
 * 100% Self-Contained Enterprise SOC Script Execution Monitoring & Threat Hunting Module
 * Linked to the dedicated live API (`/api/script-monitoring/overview`), MongoDB alert telemetry, and Socket.IO streaming.
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19), API Call (20)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens ──────────────────────────────────────────────────
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

function MiniSparkline({ data = [], color = MON.cyan, height = 30 }) {
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

function alertTime(row) {
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'Unknown host';
}

function alertUser(row) {
  return row?.username || row?.user || row?.userName || 'Unknown user';
}

function alertStatus(row) {
  return row?.status || row?.state || 'Observed';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'info').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'critical';
}

function processOs(row) {
  const osStr = String(row?.os || row?.platform || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Script Telemetry Field Extractors ──────────────────────────────────────
function scriptRaw(row = {}) {
  const root = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function scriptName(row) {
  const raw = scriptRaw(row);
  return row?.scriptName || raw.script_name || raw.scriptName || row?.fileName || raw.file_name || row?.processName || raw.process_name || 'Unknown script';
}

function scriptInterpreter(row) {
  const raw = scriptRaw(row);
  const name = String(scriptName(row)).toLowerCase();
  return row?.interpreter || raw.interpreter || row?.processName || raw.process_name || (name.endsWith('.ps1') ? 'powershell' : name.endsWith('.py') ? 'python' : name.endsWith('.sh') ? 'shell' : 'Unknown interpreter');
}

function scriptCommandLine(row) {
  const raw = scriptRaw(row);
  return row?.commandLine || row?.processCmdline || row?.cmdline || raw.command_line || raw.process_cmdline || raw.cmdline || 'Not reported';
}

function scriptVerdict(row) {
  return row?.verdict || row?.ruleName || row?.ruleId || row?.detectionReason || 'Observed';
}

function scriptRiskScore(row) {
  const raw = scriptRaw(row);
  const score = Number(row?.riskScore ?? row?.score ?? raw.risk_score);
  return Number.isFinite(score) ? score : 0;
}

function scriptProcessTree(row = {}) {
  const raw = scriptRaw(row);
  const supplied = row.processTree || raw.process_tree || raw.processTree;
  if (Array.isArray(supplied) && supplied.length) return supplied;
  return [
    (row.parentProcessName || raw.parent_process_name) ? {
      pid: row.parentPid ?? raw.parent_pid,
      name: row.parentProcessName || raw.parent_process_name,
      path: raw.parent_exe || raw.parent_path || '',
      cmd: row.parentCommandLine || raw.parent_cmdline || '',
      status: 'Observed',
    } : null,
    (row.processName || raw.process_name) ? {
      pid: row.pid ?? raw.pid,
      name: row.processName || raw.process_name,
      path: row.processExe || raw.exe || raw.process_exe || '',
      cmd: scriptCommandLine(row),
      status: alertSeverity(row) === 'critical' ? 'Critical' : alertSeverity(row) === 'high' ? 'Suspicious' : 'Observed',
    } : null,
  ].filter(Boolean);
}

function scriptTelemetryText(row) {
  const raw = scriptRaw(row);
  return [
    scriptInterpreter(row), scriptName(row), scriptCommandLine(row), row?.ruleId,
    row?.description, row?.evidenceType, row?.telemetryProvider,
    ...(Array.isArray(row?.detectionReasons) ? row.detectionReasons : []),
    raw.evidence_type, raw.telemetry_provider,
  ].filter(Boolean).join(' ').toLowerCase();
}

function scriptType(row) {
  const text = scriptTelemetryText(row);
  if (/powershell|pwsh|\.ps1\b/.test(text)) return 'PowerShell';
  if (/\bbash\b|\bzsh\b|\bdash\b|\/bin\/sh|\.sh\b/.test(text)) return 'Bash';
  if (/python/.test(text)) return 'Python';
  if (/node(?:\.exe|\.js)?|javascript|\.js\b/.test(text)) return 'Node.js';
  if (/cmd\.exe|\.bat\b|\.cmd\b/.test(text)) return 'Batch/CMD';
  if (/wscript|cscript|vbscript|\.vbs\b/.test(text)) return 'JavaScript';
  return 'Others';
}

function containsAny(row, words = []) {
  const haystack = [
    scriptName(row), scriptInterpreter(row), scriptCommandLine(row), scriptVerdict(row), alertHost(row),
    row?.description, row?.message, row?.decodedCommand,
  ].filter(Boolean).join(' ').toLowerCase();
  return words.some(word => haystack.includes(word));
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

function recordId(row) {
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${scriptName(row)}-${scriptInterpreter(row)}`;
}

function csvCell(val) {
  const str = String(val ?? '').replace(/"/g, '""');
  return `"${str}"`;
}

function downloadBlob(content, filename, type = 'text/csv;charset=utf-8;') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. SCRIPT FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function ScriptForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const observedProcessTree = scriptProcessTree(log);
  const raw = scriptRaw(log);
  const detailFields = {
    memory: [['AMSI / provider', log.telemetryProvider || raw.telemetry_provider], ['Decoded payload', log.decodedCommand || raw.decoded_command], ['Integrity level', log.processIntegrityLevel || raw.integrity_level]],
    registry: [['Registry key', log.registryKey || raw.registry_key], ['Files created', log.filesCreated || raw.files_created], ['Files modified', log.filesModified || raw.files_modified], ['Files deleted', log.filesDeleted || raw.files_deleted]],
    network: [['Connections', log.networkConnections || raw.network_connections || log.processRemoteAddresses], ['Destination', log.destip || raw.dest_ip], ['Domain / URL', log.domain || log.url || raw.domain || raw.url], ['Protocol / port', [log.protocol || raw.protocol, log.destPort || raw.dest_port].filter(Boolean).join(' / ')]],
    ioc: [['SHA-256', log.scriptHash || raw.script_hash || log.fileHash || log.sha256], ['SHA-1', log.scriptSha1 || raw.script_sha1 || log.sha1], ['MD5', log.scriptMd5 || raw.script_md5 || log.md5], ['Threat intelligence', log.threatIntel?.reputation || log.reputation || log.vtVerdict || raw.reputation]],
    mitre: [['Technique ID', log.mitreId || raw.mitre_id], ['Technique', log.mitreTechnique || log.technique || raw.technique], ['Tactic', log.mitreTactic || raw.mitre_tactic], ['Evidence', log.description]],
    behavior: [['Detection reasons', log.detectionReasons || raw.detection_reasons || log.matchedPatterns], ['Obfuscation score', log.obfuscationScore ?? raw.obfuscation_score], ['Execution source', log.executionSource || raw.execution_source], ['Signature / publisher', [log.signatureStatus || log.processSignatureStatus, log.signer || log.publisher || log.processPublisher].filter(Boolean).join(' / ')]],
    timeline: [['Observed at', alertTime(log)], ['Process started', log.processCreateTime || raw.process_create_time], ['Related event IDs', log.relatedEvents || raw.related_events], ['Alert status', alertStatus(log)]],
  };

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'processtree', label: '⚙️ 2. Process Tree' },
    { id: 'memory', label: '🧠 3. Memory & AMSI' },
    { id: 'registry', label: '🔧 4. Registry & Disk Diffs' },
    { id: 'network', label: '🌐 5. Network & C2' },
    { id: 'ioc', label: '🎯 6. IOC Extraction' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'behavior', label: '⚡ 8. Behavior Triggers' },
    { id: 'timeline', label: '⏱️ 9. Timeline' },
    { id: 'reports', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionType, actionName) => {
    if (!actionType || typeof onAction !== 'function' || !log?._id) {
      setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
      return;
    }
    try {
      await onAction(String(log._id), actionType);
      setActionSuccess(`Approved action submitted: ${actionName}`);
    } catch (error) {
      setActionSuccess(error?.message || `Failed to submit: ${actionName}`);
    }
    setTimeout(() => setActionSuccess(null), 3500);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>📜</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Script Execution Forensic Panel — {scriptName(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {scriptVerdict(log)}
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {scriptRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Target Host: <strong style={{ color: MON.cyan }}>{alertHost(log)}</strong> | User: <strong>{alertUser(log)}</strong> | Interpreter: <strong>{scriptInterpreter(log)}</strong> | PID: <strong>{log.pid || '—'}</strong>
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map((t) => (
            <button key={t.id} type="button" onClick={() => setActiveTab(t.id)} style={{ padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600, color: activeTab === t.id ? MON.cyan : MON.muted, background: activeTab === t.id ? MON.bg : 'transparent', border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent', cursor: 'pointer', whiteSpace: 'nowrap' }}>
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab Body Content */}
        <div style={{ flex: 1, overflowY: 'auto', padding: 20, background: MON.bg }}>
          {/* TAB 1: OVERVIEW & STATIC ANALYSIS */}
          {activeTab === 'overview' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['Script Verdict', scriptVerdict(log).toUpperCase(), sevColor],
                  ['Risk Score', `${scriptRiskScore(log)} / 100`, MON.red],
                  ['Interpreter', scriptInterpreter(log), MON.purple],
                  ['Publisher Signer', log.signer || 'Not reported', MON.orange],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.yellow, textTransform: 'uppercase' }}>💻 Full Executed Command Line</h4>
                <pre style={{ margin: 0, background: MON.bg, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}`, color: MON.cyan, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                  {scriptCommandLine(log)}
                </pre>
              </div>

              {log.decodedCommand && (
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.green, textTransform: 'uppercase' }}>🔓 AMSI Decoded Script Payload</h4>
                  <pre style={{ margin: 0, background: MON.bg, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}`, color: MON.text, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                    {log.decodedCommand}
                  </pre>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: PROCESS TREE */}
          {activeTab === 'processtree' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 14px 0', fontSize: 13, color: MON.cyan }}>🌳 Parent-Child Process Tree Hierarchy</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {observedProcessTree.map((proc, idx) => (
                  <div key={proc.pid} style={{ padding: '10px 14px', background: MON.bg, border: `1px solid ${proc.status === 'Critical' ? MON.red : proc.status === 'Suspicious' ? MON.orange : MON.border}`, borderRadius: 6, marginLeft: idx * 24 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontWeight: 900, color: proc.status === 'Critical' ? MON.red : MON.cyan, fontSize: 12 }}>
                        {idx > 0 ? '└── ' : ''}{proc.name} (PID: {proc.pid})
                      </span>
                      <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, background: proc.status === 'Critical' ? `${MON.red}20` : `${MON.yellow}20`, color: proc.status === 'Critical' ? MON.red : MON.yellow, fontWeight: 800 }}>
                        {proc.status}
                      </span>
                    </div>
                    <div style={{ fontSize: 10, color: MON.muted, fontFamily: 'monospace', marginTop: 4 }}>Path: {proc.path}</div>
                    <div style={{ fontSize: 10, color: MON.sub, fontFamily: 'monospace', marginTop: 2 }}>Command: {proc.cmd}</div>
                  </div>
                ))}
                {!observedProcessTree.length && <div style={{ color: MON.muted, fontSize: 11 }}>No process-tree telemetry was reported by this agent.</div>}
              </div>
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'reports' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Automated SOC Script Remediation Actions</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('quarantine', 'Quarantine Script & Record Hash')} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Block Script & Blacklist Hash
                  </button>
                  <button type="button" disabled={!log.pid} onClick={() => log.pid && handleAction('kill_process', `Terminate Process PID ${log.pid}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: log.pid ? 'pointer' : 'not-allowed', opacity: log.pid ? 1 : .55 }}>
                    ⚡ Terminate Process PID {log.pid || '—'}
                  </button>
                  <button type="button" onClick={() => handleAction('isolate', 'Isolate Host Endpoint')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Isolate Host ({alertHost(log)})
                  </button>
                  <button type="button" onClick={() => handleAction('ignore', 'Mark Approved / False Positive')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Whitelist Approved Script
                  </button>
                </div>
              </div>
            </div>
          )}

          {['memory', 'registry', 'network', 'ioc', 'mitre', 'behavior', 'timeline'].includes(activeTab) && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 8px', fontSize: 13, color: MON.cyan }}>{activeTab.toUpperCase()} Telemetry Inspection</h4>
              {(detailFields[activeTab] || []).filter(([, value]) => value !== undefined && value !== null && value !== '' && (!Array.isArray(value) || value.length)).map(([label, value]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '180px 1fr', gap: 12, padding: '8px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                  <b style={{ color: MON.muted }}>{label}</b>
                  <span style={{ color: MON.text, wordBreak: 'break-word', fontFamily: typeof value === 'string' && value.length > 80 ? 'monospace' : 'inherit' }}>{Array.isArray(value) || typeof value === 'object' ? JSON.stringify(value) : String(value)}</span>
                </div>
              ))}
              {!(detailFields[activeTab] || []).some(([, value]) => value !== undefined && value !== null && value !== '' && (!Array.isArray(value) || value.length)) && <div style={{ fontSize: 11, color: MON.muted }}>No {activeTab} telemetry was reported by this agent.</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard, Inspector)
// ═════════════════════════════════════════════════════════════════════════════
export function ScriptLogMonitor({ alerts = [], onAction }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${scriptName(a)} ${scriptInterpreter(a)} ${scriptCommandLine(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Script Name, Interpreter, Command Line, Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="clean">Clean</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Script Execution Telemetry Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Script Name</span><span>Target Host</span><span>Interpreter</span><span>Verdict</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1.6fr 100px 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{scriptName(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.purple, fontWeight: 800 }}>{scriptInterpreter(row)}</span>
                <b style={{ color: SEV_COLOR[alertSeverity(row)] || MON.blue, textTransform: 'uppercase' }}>{scriptVerdict(row)}</b>
                <b style={{ color: scriptRiskScore(row) > 75 ? MON.red : MON.orange }}>{scriptRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No script execution logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <ScriptForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

function LegacyScriptReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);

  const getFilteredAlerts = () => {
    const now = Date.now();
    const dayMs = 86400000;
    const windowMap = { daily: 1, weekly: 7, monthly: 30, '90days': 90 };
    const days = windowMap[reportType] || 90;
    const cutoff = now - days * dayMs;
    const filtered = alerts.filter(a => {
      const t = alertTime(a);
      return t ? new Date(t).getTime() >= cutoff : true;
    });
    return filtered.length > 0 ? filtered : alerts;
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const windowMap = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
      const response = await api.get('/script-monitoring/events', {
        params: { page: 1, limit: 2000, windowHours: windowMap[reportType] || 2160 },
        skipCache: true,
      });
      const remoteRows = Array.isArray(response.data?.events) ? response.data.events : [];
      const filtered = remoteRows.length || Number(response.data?.total || 0) ? remoteRows : getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({ alerts: filtered, total: Number(response.data?.total ?? filtered.length), bySev });
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: filtered.length,
        bySev,
      });
    } finally {
      setGenerating(false);
      setGenerated(true);
    }
  };

  const handleExportCSV = async () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    try {
      const windowMap = { daily: 24, weekly: 168, monthly: 720, '90days': 2160 };
      const response = await api.get('/script-monitoring/export/csv', {
        params: { windowHours: windowMap[reportType] || 2160 }, responseType: 'blob', skipCache: true,
      });
      downloadBlob(response.data, `script_execution_${reportType}.csv`, 'text/csv;charset=utf-8;');
    } catch {
      const header = 'Timestamp,Script Name,Interpreter,Target Host,Verdict,Risk Score,Severity,Status';
      const rows = filtered.map(a => [csvCell(alertTime(a)), csvCell(scriptName(a)), csvCell(scriptInterpreter(a)), csvCell(alertHost(a)), csvCell(scriptVerdict(a)), csvCell(scriptRiskScore(a)), csvCell(alertSeverity(a)), csvCell(alertStatus(a))].join(','));
      downloadBlob([header, ...rows].join('\n'), `script_execution_${reportType}_${filtered.length}records.csv`);
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Script Execution Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for PowerShell Empire abuse, AMSI bypasses, Python reverse shells, and CertUtil LOLBins</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Script Report'}
          </button>
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📅 Select Time Window</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              { key: 'daily', label: '24 Hours', icon: '⏱', sub: 'Last 24h' },
              { key: 'weekly', label: '1 Week', icon: '📆', sub: 'Last 7 days' },
              { key: 'monthly', label: '1 Month', icon: '🗓', sub: 'Last 30 days' },
              { key: '90days', label: '3 Months', icon: '📊', sub: 'Last 90 days' },
            ].map(opt => {
              const active = reportType === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => { setReportType(opt.key); setGenerated(false); }}
                  style={{
                    background: active ? MON.cyan : MON.card2,
                    color: active ? '#000' : MON.text,
                    border: `2px solid ${active ? MON.cyan : MON.border}`,
                    borderRadius: 8, padding: '10px 18px', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, minWidth: 100,
                    fontWeight: active ? 900 : 600,
                  }}
                >
                  <span style={{ fontSize: 18 }}>{opt.icon}</span>
                  <span style={{ fontSize: 12, fontWeight: 800 }}>{opt.label}</span>
                  <span style={{ fontSize: 9, opacity: 0.7 }}>{opt.sub}</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Script Execution Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Script Executions: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Script Executions', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Risk Scripts', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Executions', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Clean Maintenance Scripts', val: reportData?.bySev?.low, color: MON.green },
            ].map(c => (
              <div key={c.label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 9, color: MON.muted, fontWeight: 700, textTransform: 'uppercase' }}>{c.label}</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: c.color, marginTop: 6 }}>{c.val}</div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function ScriptReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={21} alerts={alerts} />;
}

// ── Visual Helper Components for Script Execution Monitoring Dashboard ───
function ScriptExecutionsOverTimeChart({ alerts = [] }) {
  const pointsPowerShell = buildBuckets(alerts.filter(row => scriptType(row) === 'PowerShell'), 12, 24);
  const pointsBash = buildBuckets(alerts.filter(row => scriptType(row) === 'Bash'), 12, 24);
  const pointsPython = buildBuckets(alerts.filter(row => scriptType(row) === 'Python'), 12, 24);
  const pointsNode = buildBuckets(alerts.filter(row => scriptType(row) === 'Node.js'), 12, 24);
  const pointsOthers = buildBuckets(alerts.filter(row => !['PowerShell', 'Bash', 'Python', 'Node.js'].includes(scriptType(row))), 12, 24);

  const maxVal = Math.max(...pointsPowerShell, ...pointsBash, ...pointsPython, ...pointsNode, ...pointsOthers, 1);
  const width = 360;
  const height = 110;

  const getSvgPath = (pts) => {
    return pts.map((val, idx) => {
      const x = (idx / (pts.length - 1)) * width;
      const y = height - (val / maxVal) * (height - 10) - 5;
      return `${x},${y}`;
    }).join(' L ');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Script Executions Over Time</span>
          <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>Last 24 Hours v</span>
        </div>

        <div style={{ display: 'flex', gap: 8, fontSize: 7, marginBottom: 4 }}>
          <span style={{ color: '#22c55e', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#22c55e', borderRadius: 1 }} /> PowerShell</span>
          <span style={{ color: '#f97316', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#f97316', borderRadius: 1 }} /> Bash</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#a78bfa', borderRadius: 1 }} /> Python</span>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#38bdf8', borderRadius: 1 }} /> Node.js</span>
          <span style={{ color: '#eab308', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, background: '#eab308', borderRadius: 1 }} /> Others</span>
        </div>

        <div style={{ position: 'relative', width: '100%', height: 100 }}>
          <svg viewBox={`0 0 ${width} ${height}`} width="100%" height="100%" style={{ overflow: 'visible' }}>
            <path d={`M ${getSvgPath(pointsPowerShell)}`} fill="none" stroke="#22c55e" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsBash)}`} fill="none" stroke="#f97316" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsPython)}`} fill="none" stroke="#a78bfa" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsNode)}`} fill="none" stroke="#38bdf8" strokeWidth="1.5" />
            <path d={`M ${getSvgPath(pointsOthers)}`} fill="none" stroke="#eab308" strokeWidth="1.5" />
          </svg>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 7, color: '#64748b', marginTop: 2 }}>
          {['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00'].map(t => (
            <span key={t}>{t}</span>
          ))}
        </div>
      </div>
    </div>
  );
}

function ScriptTypeDistributionDonut({ alerts = [] }) {
  const colors = { Bash: '#f97316', PowerShell: '#22c55e', Python: '#a78bfa', 'Node.js': '#38bdf8', 'Batch/CMD': '#eab308', JavaScript: '#22d3ee', Others: '#64748b' };
  const counts = alerts.reduce((acc, row) => { const key = scriptType(row); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
  const total = alerts.length;
  const items = Object.keys(colors).map(label => ({ label, val: shortNum(counts[label] || 0), pct: total ? Number((((counts[label] || 0) / total) * 100).toFixed(1)) : 0, color: colors[label] }));

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = items.map((s) => {
    const angle = (s.pct / 100) * 360;
    const startAngle = cumAngle;
    const endAngle = cumAngle + angle;
    cumAngle += angle;

    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (endAngle - 90) * (Math.PI / 180);

    const x1 = cx + radius * Math.cos(startRad);
    const y1 = cy + radius * Math.sin(startRad);
    const x2 = cx + radius * Math.cos(endRad);
    const y2 = cy + radius * Math.sin(endRad);

    const largeArcFlag = angle > 180 ? 1 : 0;
    const d = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`;

    return { ...s, d };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Script Type Distribution</span>
          <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>Last 24 Hours v</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 7.5 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 3 }}>
                  <span style={{ width: 4, height: 4, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.val} <span style={{ fontSize: 6.5, color: '#64748b' }}>({it.pct}%)</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 4 }}>View Full Report →</span>
    </div>
  );
}

function ScriptOsDistributionDonut({ alerts = [] }) {
  const definitions = [['Windows', '#38bdf8'], ['Linux', '#22c55e'], ['macOS', '#f97316'], ['Unknown', '#22d3ee']];
  const counts = alerts.reduce((acc, row) => { const key = processOs(row); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
  const total = alerts.length;
  const items = definitions.map(([label, color]) => ({ label, val: shortNum(counts[label] || 0), pct: total ? Number((((counts[label] || 0) / total) * 100).toFixed(1)) : 0, color }));

  let cumAngle = 0;
  const radius = 36;
  const cx = 46;
  const cy = 46;
  const strokeWidth = 12;

  const arcs = items.map((s) => {
    const angle = (s.pct / 100) * 360;
    const startAngle = cumAngle;
    const endAngle = cumAngle + angle;
    cumAngle += angle;

    const startRad = (startAngle - 90) * (Math.PI / 180);
    const endRad = (endAngle - 90) * (Math.PI / 180);

    const x1 = cx + radius * Math.cos(startRad);
    const y1 = cy + radius * Math.sin(startRad);
    const x2 = cx + radius * Math.cos(endRad);
    const y2 = cy + radius * Math.sin(endRad);

    const largeArcFlag = angle > 180 ? 1 : 0;
    const d = `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArcFlag} 1 ${x2} ${y2}`;

    return { ...s, d };
  });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Script Executions by OS</span>
          <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ position: 'relative', width: 92, height: 92, flexShrink: 0 }}>
            <svg viewBox="0 0 92 92" width="92" height="92">
              {arcs.map((arc, i) => (
                <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
              ))}
            </svg>
            <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{shortNum(total)}</span>
              <span style={{ fontSize: 6.5, color: '#8ea0b8' }}>Total</span>
            </div>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8 }}>
            {items.map(it => (
              <div key={it.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ width: 5, height: 5, borderRadius: '50%', background: it.color }} /> {it.label}
                </span>
                <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{it.val} <span style={{ fontSize: 7, color: '#64748b' }}>({it.pct}%)</span></span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

function ScriptOverviewDashboard({ alerts = [], total = 0, summary = {} }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const rows = Array.isArray(alerts) ? alerts : [];
  const traffic = buildBuckets(rows, 6, 24);
  const typeCount = type => rows.filter(row => scriptType(row) === type).length;
  const blockedRows = rows.filter(row => row?.blocked || /block|terminated|quarantin/.test(String(row?.action || row?.status || row?.actionTaken || '').toLowerCase()));
  const severityCounts = rows.reduce((acc, row) => { const severity = alertSeverity(row); acc[severity] = (acc[severity] || 0) + 1; return acc; }, {});
  const metric = (key, fallback) => Number.isFinite(Number(summary?.[key])) ? Number(summary[key]) : fallback;
  const summarySeverity = summary?.bySeverity || severityCounts;
  const topCards = [
    { title: 'Total Scripts Executed', val: shortNum(metric('totalScripts', total || rows.length)), sub: 'Last 24 hours', col: '#38bdf8', icon: '💻', spark: traffic },
    { title: 'PowerShell Executions', val: shortNum(metric('powershellEvents', typeCount('PowerShell'))), sub: 'Observed telemetry', col: '#22c55e', icon: '⚡', spark: buildBuckets(rows.filter(row => scriptType(row) === 'PowerShell'), 6, 24) },
    { title: 'Bash Executions', val: shortNum(metric('linuxShellEvents', typeCount('Bash'))), sub: 'Observed telemetry', col: '#f97316', icon: '🐚', spark: buildBuckets(rows.filter(row => scriptType(row) === 'Bash'), 6, 24) },
    { title: 'Python Executions', val: shortNum(metric('pythonEvents', typeCount('Python'))), sub: 'Observed telemetry', col: '#a78bfa', icon: '🐍', spark: buildBuckets(rows.filter(row => scriptType(row) === 'Python'), 6, 24) },
    { title: 'Node.js Executions', val: shortNum(metric('nodeEvents', typeCount('Node.js'))), sub: 'Observed telemetry', col: '#38bdf8', icon: '🟩', spark: buildBuckets(rows.filter(row => scriptType(row) === 'Node.js'), 6, 24) },
    { title: 'Blocked Scripts', val: shortNum(metric('blockedScripts', blockedRows.length)), sub: 'Policy response telemetry', col: '#ef4444', icon: '🛡️', spark: buildBuckets(blockedRows, 6, 24) },
  ];
  const typeIcon = { PowerShell: '⚡', Bash: '🐚', Python: '🐍', 'Node.js': '🟩', 'Batch/CMD': '⚙️', JavaScript: '📜', Others: '📄' };
  const topSuspicious = [...rows].sort((a, b) => scriptRiskScore(b) - scriptRiskScore(a)).slice(0, 8).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleString() : '—',
    cmd: scriptCommandLine(row), user: alertUser(row), host: alertHost(row),
    type: typeIcon[scriptType(row)] || '📄', typeCol: SEV_COLOR[alertSeverity(row)] || '#38bdf8',
    sev: alertSeverity(row), status: alertStatus(row), statusCol: row?.blocked ? '#ef4444' : '#22c55e',
  }));
  const topHostsList = topCounts(rows, alertHost, 5).map(([host, count]) => ({ host, execs: shortNum(count), spark: buildBuckets(rows.filter(row => alertHost(row) === host), 5, 24) }));
  const topUsersList = topCounts(rows, alertUser, 5).map(([user, count]) => ({ user, execs: shortNum(count), spark: buildBuckets(rows.filter(row => alertUser(row) === user), 5, 24) }));
  const detectionDefs = [
    ['Encoded Commands', /encodedcommand|base64|invoke-expression|\biex\b/, '#ef4444', '🛡️'],
    ['Reverse Shells', /reverse shell|bind shell/, '#ef4444', '🛡️'],
    ['Downloader Scripts', /download|stringfromurl|webclient|curl|wget/, '#ef4444', '⚠️'],
    ['Persistence Scripts', /scheduled task|cron|systemd|startup|persistence/, '#22c55e', '⚡'],
    ['Fileless Attacks', /fileless|memory execution|reflective/, '#f97316', '🔥'],
  ];
  const detectionSummaryKeys = ['encodedCommands', 'reverseShells', 'downloaderScripts', 'persistenceScripts', 'filelessAttacks'];
  const threatDetections = detectionDefs.map(([label, pattern, col, icon], index) => ({ label, val: Number.isFinite(Number(summary?.detections?.[detectionSummaryKeys[index]])) ? Number(summary.detections[detectionSummaryKeys[index]]) : rows.filter(row => pattern.test(scriptTelemetryText(row))).length, sub: 'Last 24 hours', col, icon }));
  const recentAlertTimeline = [...rows].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—',
    msg: row?.description || `${scriptName(row)} observed on ${alertHost(row)}`,
    sev: alertSeverity(row), col: SEV_COLOR[alertSeverity(row)] || '#38bdf8',
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
        {topCards.map(s => (
          <div key={s.title} style={{ ...panelStyle, padding: '10px 10px', display: 'flex', flexDirection: 'column', gap: 4 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: '#8ea0b8', fontWeight: 800 }}>{s.title}</span>
              <span style={{ fontSize: 10 }}>{s.icon}</span>
            </div>
            <div style={{ fontSize: 15, fontWeight: 800, color: '#fff' }}>{s.val}</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 7.5, color: s.col, fontWeight: 700 }}>{s.sub}</span>
              <div style={{ width: 35, height: 12 }}>
                <MiniSparkline data={s.spark} color={s.col} height={12} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <ScriptExecutionsOverTimeChart alerts={rows} />
        </div>

        <div style={panelStyle}>
          <ScriptTypeDistributionDonut alerts={rows} />
        </div>

        {/* Alert Summary */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Alert Summary</span>
              <span style={{ fontSize: 7.5, color: '#64748b', background: '#07101b', border: '1px solid #16273e', padding: '1px 6px', borderRadius: 3 }}>Last 24 Hours v</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {[
                { label: 'Critical', val: summarySeverity.critical || 0, sub: 'Last 24 hours', col: '#ef4444', icon: '🔴' },
                { label: 'High', val: summarySeverity.high || 0, sub: 'Last 24 hours', col: '#f97316', icon: '🟠' },
                { label: 'Medium', val: summarySeverity.medium || 0, sub: 'Last 24 hours', col: '#eab308', icon: '🟡' },
                { label: 'Low', val: summarySeverity.low || 0, sub: 'Last 24 hours', col: '#38bdf8', icon: '🔵' },
              ].map(item => (
                <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span>{item.icon}</span> {item.label}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: '#fff', fontWeight: 800 }}>{item.val}</span>
                    <span style={{ color: item.col, fontSize: 7.5, fontWeight: 700 }}>{item.sub}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ borderTop: '1px solid #16273e', paddingTop: 6, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 8.5 }}>
            <span style={{ color: '#8ea0b8', fontWeight: 800 }}>Total Alerts</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#fff', fontWeight: 900, fontSize: 11 }}>{shortNum(metric('totalScripts', total || rows.length))}</span>
              <span style={{ color: '#22c55e', fontSize: 7.5, fontWeight: 700 }}>Live window</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 1fr', gap: 12 }}>
        {/* Top Suspicious Script Executions */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Suspicious Script Executions</span>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.8fr 0.9fr 0.9fr 0.4fr 0.7fr 0.7fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 7.5, fontWeight: 700, color: '#64748b' }}>
              <span>Time</span>
              <span>Script Name / Command</span>
              <span>User</span>
              <span>Host</span>
              <span>Type</span>
              <span>Severity</span>
              <span>Status</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topSuspicious.map((ts, idx) => (
                <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.8fr 1.8fr 0.9fr 0.9fr 0.4fr 0.7fr 0.7fr', gap: 4, alignItems: 'center', fontSize: 7.5 }}>
                  <span style={{ color: '#64748b' }}>{ts.time}</span>
                  <span style={{ color: '#e2e8f0', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ts.cmd}</span>
                  <span style={{ color: '#8ea0b8' }}>{ts.user}</span>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{ts.host}</span>
                  <span style={{ color: ts.typeCol }}>{ts.type}</span>
                  <span style={{ fontSize: 7, fontWeight: 800, color: ts.statusCol, padding: '1px 3px', background: `${ts.statusCol}15`, borderRadius: 3, border: `1px solid ${ts.statusCol}33`, textAlign: 'center' }}>
                    {ts.sev}
                  </span>
                  <span style={{ fontSize: 7, fontWeight: 800, color: ts.statusCol, padding: '1px 3px', background: `${ts.statusCol}15`, borderRadius: 3, border: `1px solid ${ts.statusCol}33`, textAlign: 'center' }}>
                    {ts.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Top Hosts by Script Executions */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Hosts by Script Executions</span>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>Host</span>
              <span>Executions</span>
              <span>Trend</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topHostsList.map(th => (
                <div key={th.host} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: '#38bdf8', fontFamily: 'monospace' }}>{th.host}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{th.execs}</span>
                  <div style={{ width: 40, height: 10 }}>
                    <MiniSparkline data={th.spark} color="#ef4444" height={10} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Full Report →</span>
        </div>

        {/* Top Users by Script Executions */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Users by Script Executions</span>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8, fontWeight: 700, color: '#64748b' }}>
              <span>User</span>
              <span>Executions</span>
              <span>Trend</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 5 }}>
              {topUsersList.map(tu => (
                <div key={tu.user} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1fr', gap: 4, alignItems: 'center', fontSize: 8 }}>
                  <span style={{ color: '#cbd5e1' }}>{tu.user}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{tu.execs}</span>
                  <div style={{ width: 40, height: 10 }}>
                    <MiniSparkline data={tu.spark} color="#ef4444" height={10} />
                  </div>
                </div>
              ))}
            </div>
          </div>
          <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer', marginTop: 6 }}>View Full Report →</span>
        </div>
      </div>

      {/* 4. BOTTOM GRID (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.2fr 1fr', gap: 12 }}>
        {/* Threat Detections */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Threat Detections</span>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
              {threatDetections.map(td => (
                <div key={td.label} style={{ background: '#07101b', border: '1px solid #16273e', borderRadius: 6, padding: '8px 6px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, textAlign: 'center' }}>
                  <span style={{ fontSize: 16 }}>{td.icon}</span>
                  <span style={{ fontSize: 7, color: '#8ea0b8', fontWeight: 700, height: 16, overflow: 'hidden' }}>{td.label}</span>
                  <span style={{ fontSize: 14, fontWeight: 800, color: '#fff' }}>{td.val}</span>
                  <span style={{ fontSize: 7, color: td.col, fontWeight: 700 }}>{td.sub}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Alert Timeline */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Recent Alert Timeline</span>
              <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {recentAlertTimeline.map((rat, idx) => (
                <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 7.5 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, overflow: 'hidden' }}>
                    <span style={{ color: '#64748b' }}>{rat.time}</span>
                    <span style={{ width: 4, height: 4, borderRadius: '50%', background: rat.col, flexShrink: 0 }} />
                    <span style={{ color: '#e2e8f0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{rat.msg}</span>
                  </div>
                  <span style={{ fontSize: 7, fontWeight: 800, color: rat.col, background: `${rat.col}15`, padding: '1px 4px', borderRadius: 3, border: `1px solid ${rat.col}33`, flexShrink: 0 }}>
                    {rat.sev}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        <div style={panelStyle}>
          <ScriptOsDistributionDonut alerts={rows} />
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`ScriptExecutionDashboardPanel` / `ScriptExecutionDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function ScriptExecutionDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], data = null, onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);

  useEffect(() => {
    if (systems.length) { setBackendSystems(systems); return; }
    let active = true;
    api.get('/system')
      .then(r => {
        if (!active) return;
        const rows = r.data?.systems || r.data?.agents || r.data || [];
        setBackendSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setBackendSystems([]); });
    return () => { active = false; };
  }, [systems]);

  const rows = Array.isArray(alerts) ? alerts : [];
  const totalRows = total || recordsTotal || rows.length;
  const summary = data?.summary || {};
  const metric = (key, fallback) => Number.isFinite(Number(summary?.[key])) ? Number(summary[key]) : fallback;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);
  const eventText = row => `${row?.interpreter || ''} ${row?.processName || ''} ${row?.scriptName || ''} ${row?.commandLine || ''} ${row?.ruleId || ''} ${row?.description || ''}`.toLowerCase();
  const countText = pattern => rows.filter(row => pattern.test(eventText(row))).length;
  const healthScore = rows.length
    ? `${Math.max(0, Math.round(100 - (((sevCounts.critical || 0) * 4 + (sevCounts.high || 0) * 2) / Math.max(rows.length, 1)) * 10))}/100`
    : 'Not reported';
  const amsiCount = countText(/amsi|scriptblock|event\s*4104/);
  const ebpfCount = countText(/ebpf|execve|auditd/);

  // 20 Script Execution Specific SOC Categories & Metrics
  const kpis = [
    { label: '📜 1. Total Script Execution Events (24h)', val: shortNum(metric('totalScripts', totalRows)), trend: 'Executions', color: MON.blue, data: timeline },
    { label: '⚡ 2. PowerShell Script Executions', val: shortNum(metric('powershellEvents', countText(/powershell|pwsh/))), trend: 'PowerShell', color: MON.cyan, data: buildBuckets(rows.filter(row => /powershell|pwsh/.test(eventText(row))), 8, 24) },
    { label: '💻 3. CMD & Batch File Executions', val: shortNum(metric('cmdBatchEvents', countText(/cmd\.exe|\.bat\b|\.cmd\b/))), trend: 'CMD/Batch', color: MON.yellow, data: buildBuckets(rows.filter(row => /cmd\.exe|\.bat\b|\.cmd\b/.test(eventText(row))), 8, 24) },
    { label: '🐍 4. Python Interpreter Executions', val: shortNum(metric('pythonEvents', countText(/python(?:3|\.exe)?/))), trend: 'Python', color: MON.green, data: buildBuckets(rows.filter(row => /python(?:3|\.exe)?/.test(eventText(row))), 8, 24) },
    { label: '🐚 5. Bash & Shell Scripts Executed', val: shortNum(metric('linuxShellEvents', countText(/\bbash\b|\bzsh\b|\bdash\b|shell script|\/bin\/sh/))), trend: 'Shell', color: MON.purple, data: buildBuckets(rows.filter(row => /\bbash\b|\bzsh\b|\bdash\b|shell script|\/bin\/sh/.test(eventText(row))), 8, 24) },
    { label: '📄 6. VBScript & WScript Ingests', val: shortNum(metric('vbscriptEvents', countText(/vbscript|wscript|cscript|\.vbs\b/))), trend: 'VBS/WScript', color: MON.sub, data: buildBuckets(rows.filter(row => /vbscript|wscript|cscript|\.vbs\b/.test(eventText(row))), 8, 24) },
    { label: '🔐 7. Encoded Base64 & IEX Abuse', val: shortNum(metric('encodedCommands', countText(/encodedcommand|base64|invoke-expression|\biex\b/))), trend: 'Encoded IEX', color: MON.red, data: buildBuckets(rows.filter(row => /encodedcommand|base64|invoke-expression|\biex\b/.test(eventText(row))), 8, 24) },
    { label: '🔨 8. LOLBins & CertUtil Abuse', val: shortNum(metric('lolbinEvents', countText(/lolbin|certutil|mshta|regsvr32|rundll32/))), trend: 'LOLBins', color: MON.orange, data: buildBuckets(rows.filter(row => /lolbin|certutil|mshta|regsvr32|rundll32/.test(eventText(row))), 8, 24) },
    { label: '🎯 9. Reverse Shell Attempts Detected', val: shortNum(metric('reverseShellEvents', countText(/reverse shell|bind shell/))), trend: 'Reverse Shell', color: MON.red, data: buildBuckets(rows.filter(row => /reverse shell|bind shell/.test(eventText(row))), 8, 24) },
    { label: '🚨 10. Critical Script Alerts', val: shortNum(summary?.bySeverity?.critical ?? sevCounts.critical ?? 0), trend: 'Critical Risk', color: MON.red, data: buildBuckets(rows.filter(row => alertSeverity(row) === 'critical'), 8, 24) },
    { label: '⚠️ 11. High Severity Script Alerts', val: shortNum(summary?.bySeverity?.high ?? sevCounts.high ?? 0), trend: 'High Risk', color: MON.orange, data: buildBuckets(rows.filter(row => alertSeverity(row) === 'high'), 8, 24) },
    { label: '🛡️ 12. Monitored Enterprise Endpoints', val: shortNum(backendSystems.length), trend: 'Endpoints', color: MON.cyan, data: timeline },
    { label: '💖 13. Script Health Score', val: healthScore, trend: 'Health Score', color: MON.green, data: timeline },
    { label: '🪟 14. Windows AMSI Telemetry', val: shortNum(metric('amsiEvents', amsiCount)), trend: 'AMSI Events', color: metric('amsiEvents', amsiCount) ? MON.green : MON.muted, data: buildBuckets(rows.filter(row => /amsi/.test(eventText(row))), 8, 24) },
    { label: '📜 15. PowerShell ScriptBlock Audit (4104)', val: shortNum(metric('scriptBlockEvents', countText(/scriptblock|event\s*4104/))), trend: 'Event 4104', color: MON.green, data: buildBuckets(rows.filter(row => /scriptblock|event\s*4104/.test(eventText(row))), 8, 24) },
    { label: '🐧 16. Linux eBPF / Execve Telemetry', val: shortNum(metric('ebpfEvents', ebpfCount)), trend: 'Linux Audit', color: metric('ebpfEvents', ebpfCount) ? MON.green : MON.muted, data: buildBuckets(rows.filter(row => /ebpf|execve|auditd/.test(eventText(row))), 8, 24) },
    { label: '🐍 17. Python Analysis Evidence', val: shortNum(metric('pythonAnalysisEvents', countText(/python.*(?:ast|decompil)|(?:ast|decompil).*python/))), trend: 'AST Evidence', color: MON.green, data: buildBuckets(rows.filter(row => /python.*(?:ast|decompil)|(?:ast|decompil).*python/.test(eventText(row))), 8, 24) },
    { label: '🌐 18. Outbound Script Socket Connects', val: shortNum(metric('outboundEvents', countText(/outbound|network connection|socket|destination ip/))), trend: 'Outbound Net', color: MON.cyan, data: buildBuckets(rows.filter(row => /outbound|network connection|socket|destination ip/.test(eventText(row))), 8, 24) },
    { label: '✍️ 19. Unsigned Executable Scripts', val: shortNum(metric('unsignedEvents', countText(/unsigned|signature.*invalid|unknown publisher/))), trend: 'Unsigned Script', color: MON.yellow, data: buildBuckets(rows.filter(row => /unsigned|signature.*invalid|unknown publisher/.test(eventText(row))), 8, 24) },
    { label: '✅ 20. Low-Risk Maintenance Scripts', val: shortNum(metric('lowRiskScripts', rows.filter(row => ['low', 'info'].includes(alertSeverity(row))).length)), trend: 'Low Risk', color: MON.green, data: buildBuckets(rows.filter(row => ['low', 'info'].includes(alertSeverity(row))), 8, 24) },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.agentOk || sys.isOnline || sys.online ? 'reporting' : 'unknown'),
      monitor: hostEvents > 0,
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || sys.lastHeartbeat || null,
    });
  });
  const scriptInspectorRows = [...rows]
    .sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0))
    .slice(0, 50)
    .map(row => ({
      name: scriptName(row),
      path: row?.scriptPath || row?.executablePath || row?.processPath || scriptInterpreter(row),
      host: `${alertHost(row)} (${alertUser(row)})`,
      mode: row?.executionMode || row?.detectionType || row?.ruleId || 'Observed',
      dur: Number.isFinite(Number(row?.durationMs)) ? `${Number(row.durationMs)} ms` : 'Not reported',
      score: `${scriptRiskScore(row)}/100`,
      verdict: scriptVerdict(row),
    }));

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📊', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'log-monitor', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
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
        {activeTab === 'inspector' ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h3 style={{ margin: 0, fontSize: 14, color: MON.cyan, fontWeight: 900 }}>⚙️ Active Script Execution Monitor</h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>AMSI & eBPF inspection engines tracking live script interpreters</div>
            </div>

            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
                <thead>
                  <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
                    <th style={{ padding: 10 }}>Script Name</th>
                    <th style={{ padding: 10 }}>Interpreter Path</th>
                    <th style={{ padding: 10 }}>Host & User</th>
                    <th style={{ padding: 10 }}>Execution Mode</th>
                    <th style={{ padding: 10 }}>Duration</th>
                    <th style={{ padding: 10 }}>Threat Score</th>
                    <th style={{ padding: 10 }}>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {scriptInspectorRows.map(({ name, path, host, mode, dur, score, verdict }, idx) => (
                    <tr key={idx} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 10, color: MON.cyan, fontWeight: 900 }}>{name}</td>
                      <td style={{ padding: 10, fontFamily: 'monospace', color: MON.text }}>{path}</td>
                      <td style={{ padding: 10, color: MON.text }}>{host}</td>
                      <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{mode}</td>
                      <td style={{ padding: 10, color: MON.sub }}>{dur}</td>
                      <td style={{ padding: 10, color: MON.red, fontWeight: 'bold' }}>{score}</td>
                      <td style={{ padding: 10, color: verdict.includes('Clean') ? MON.green : MON.red, fontWeight: 800 }}>{verdict}</td>
                    </tr>
                  ))}
                  {!scriptInspectorRows.length && <tr><td colSpan={7} style={{ padding: 22, textAlign: 'center', color: MON.muted }}>No script execution telemetry received in this window.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        ) : activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={21}>
            <ScriptLogMonitor alerts={alerts} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <ScriptReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <ScriptOverviewDashboard alerts={alerts} total={totalRows} summary={summary} />
        ) : (
          <>
            {/* 20 Top KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: MON.muted }}>{kpi.label}</div>
                    <span style={{ fontSize: 9, fontWeight: 800, color: MON.green, background: 'rgba(0,0,0,0.3)', padding: '2px 6px', borderRadius: 4 }}>{kpi.trend}</span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Script Inspection & AMSI Subsystems</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} tenant endpoints loaded · {rows.length} script telemetry records observed</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>AMSI Filter</span><span>Executions</span><span>Malicious Scripts</span><span>Last Scan</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: /online|reporting|active/i.test(String(row.status)) ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.status}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend script monitoring agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Script Execution Volume Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} script executions`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Script Interpreters & OS Share</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['PowerShell (.ps1)', `${countText(/powershell|pwsh/)} events`, MON.cyan],
                    ['Bash & Shell (.sh)', `${countText(/\bbash\b|\bzsh\b|\bdash\b|shell script|\/bin\/sh/)} events`, MON.purple],
                    ['Python (.py)', `${countText(/python(?:3|\.exe)?/)} events`, MON.green],
                    ['CMD / Batch (.bat)', `${countText(/cmd\.exe|\.bat\b|\.cmd\b/)} events`, MON.yellow],
                  ].map(([interp, pct, col]) => (
                    <div key={interp} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{interp}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{pct}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Script Subsystems Inspection</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Windows AMSI Telemetry', amsiCount ? `${amsiCount} events` : 'No telemetry', amsiCount ? MON.green : MON.muted],
                    ['ScriptBlock Logging (4104)', countText(/scriptblock|event\s*4104/) ? `${countText(/scriptblock|event\s*4104/)} events` : 'No telemetry', countText(/scriptblock|event\s*4104/) ? MON.green : MON.muted],
                    ['Linux eBPF / Execve Audit', ebpfCount ? `${ebpfCount} events` : 'No telemetry', ebpfCount ? MON.green : MON.muted],
                    ['Python AST Analysis', countText(/python.*(?:ast|decompil)|(?:ast|decompil).*python/) ? `${countText(/python.*(?:ast|decompil)|(?:ast|decompil).*python/)} events` : 'No telemetry', countText(/python.*(?:ast|decompil)|(?:ast|decompil).*python/) ? MON.green : MON.muted],
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

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERLAY CAPABILITY MODAL EXPORT (`ScriptExecutionMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function ScriptExecutionMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [liveData, setLiveData] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const r = await api.get('/script-monitoring/overview', { params: { limit: 1000, windowHours: 24 }, skipCache: quiet });
      const next = r.data?.events || r.data?.alerts || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);
      setLiveData(r.data || null);
    } catch {
      setAlerts([]);
      setTotal(0);
      setSystems([]);
      setLiveData(null);
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
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('script:event', buf.add);
    socket.on('script:rule-updated', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('script:event', buf.add);
      socket.off('script:rule-updated', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleAlertAction = useCallback(async (alertId, action) => {
    const disruptive = new Set(['isolate', 'quarantine', 'kill_process', 'block_ip']);
    let reason = '';
    let confirmed = false;
    if (disruptive.has(action)) {
      reason = window.prompt('Enter the reason for this response action:')?.trim() || '';
      if (!reason) throw new Error('Action cancelled: a reason is required');
      confirmed = window.confirm(`Confirm ${action.replaceAll('_', ' ')} for this alert?`);
      if (!confirmed) throw new Error('Action cancelled');
    } else if (action === 'ignore') {
      reason = window.prompt('Enter the reason for approving this script:')?.trim() || '';
      if (!reason) throw new Error('Action cancelled: a reason is required');
    }
    const response = await api.patch(`/dashboard/alerts/${alertId}/action`, { action, reason, confirmed });
    await loadAlerts(true);
    return response.data;
  }, [loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/company-admin/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            📜 21. Script Execution Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <ScriptExecutionDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} data={liveData} onAction={handleAlertAction} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <ScriptExecutionMonitoringPage />;
}

export function ScriptExecutionSocTabPage({ tab }) {
  return <ScriptExecutionDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function ScriptExecutionSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=21" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Script SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=21')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="scriptmonitoring" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <ScriptExecutionDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { ScriptExecutionDashboardPanel as ScriptExecutionDashboard };
