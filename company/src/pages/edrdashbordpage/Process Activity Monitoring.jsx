import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Process Activity Monitoring — Capability ID: 1
 *
 * 100% Self-Contained Enterprise SOC Process Activity Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=1`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Device Control (USB) Monitoring (Capability ID: 10)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
import { useAuth } from '../../context/AuthContext';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

import {
  ProcessActivityDashboardPanel,
  summaryInventoryRows,
  procName,
  procMem,
  SEV,
  SEVBG,
  RISK,
  VtBadge,
  vtIsThreaten,
  processStatusSafe,
  processStatusStyle,
} from './ProcessFileDashboardPanels';

// ── Design System Tokens (Mirroring Capability #10 USB Monitoring) ──────────
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
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
};

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

function processName(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.process || row?.processName || row?.name || row?.executable || row?.command || row?.image ||
    raw.process_name || raw.processName || raw.name || raw.process?.name || 'unknown';
}

function processOs(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  const osStr = String(row?.osType || row?.os || row?.platform || row?.systemId?.osType || row?.systemId?.os || row?.system ||
    raw.osType || raw.os_type || raw.platform || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

function alertTime(row) {
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'unknown';
}

function alertUser(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.user || row?.username || row?.userName || row?.account || raw.username || raw.user || raw.process?.username || 'unknown';
}

function alertStatus(row) {
  return row?.status || row?.processStatus || row?.state || 'open';
}

function alertSeverity(row) {
  return String(row?.severity || 'low').toLowerCase();
}

const PROCESS_REPORT_CATEGORIES = [
  { key: 'all', label: 'All Process Categories' },
  { key: 'started', label: 'Process Started' },
  { key: 'terminated', label: 'Process Terminated' },
  { key: 'threat', label: 'Suspicious / Malicious' },
  { key: 'unauthorized', label: 'Unsigned / Unauthorized' },
  { key: 'resource', label: 'High CPU / Memory / Disk' },
  { key: 'privilege', label: 'Privileged Activity' },
  { key: 'service', label: 'Services / Scheduled Tasks' },
  { key: 'scripts', label: 'Scripts & Runtimes' },
  { key: 'server', label: 'Server / DB / Containers' },
  { key: 'network', label: 'Process Network Activity' },
  { key: 'other', label: 'Other Process Events' },
];

function processClassifications(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  const value = row?.processClassifications || row?.process_classifications || raw?.processClassifications || raw?.process_classifications || raw?.classifications || [];
  return (Array.isArray(value) ? value : [value]).map(item => String(item || '').toLowerCase()).filter(Boolean);
}

function processReportCategory(row) {
  const ruleId = String(row?.ruleId || '');
  const tags = processClassifications(row);
  if (/^(PROC_STARTED|PROC_KERNEL_START|PROC_AUDIT_START|ANDROID_APP_ACTIVITY|android_app_change)$/i.test(ruleId)) return 'started';
  if (/^(PROC_TERMINATED|PROC_KERNEL_TERMINATED|PROC_TERMINATE_REQUESTED)$/i.test(ruleId)) return 'terminated';
  if (/^(PROC_PRIVILEGED_COMMAND|PROC_PRIVILEGE_ESCALATION)$/i.test(ruleId)) return 'privilege';
  if (/^(PROC_SUSPICIOUS|PROC_SUSPICIOUS_CMDLINE|PROC_SECURITY_TOOL_TAMPER|PROC_SECURITY_TOOL_TERMINATED|PROC_SUSPICIOUS_DLL_LOAD|PROC_DLL_INJECTION|PROC_REMOTE_THREAD_INJECTION|PROC_KERNEL_PROCESS_ACCESS|PROC_HOLLOWING|PROC_WEB_ATTACK_ACTIVITY|PROC_DATABASE_SECURITY_ACTIVITY|PROC_CONTAINER_RISK|EDR_MALICIOUS_PROCESS|EDR_SUSPICIOUS_CMDLINE|RANSOMWARE_ENCRYPTION_PROC|RANSOMWARE_BACKUP_TAMPER|RANSOMWARE_SHADOW_DELETE|LOLBIN_DETECTED|MEM_FILELESS_EXEC|MEM_RWX_REGION|MEM_CRED_DUMP|MEM_INJECTION_CMDLINE|MEM_LSASS_ACCESS)$/i.test(ruleId)) return 'threat';
  if (/^(PROC_UNAUTHORIZED_EXECUTION|PROC_UNSIGNED_EXECUTABLE|PROC_UNTRUSTED_EXECUTABLE|PROC_UNKNOWN_EXECUTABLE|PROC_MODIFIED_PACKAGE_EXECUTABLE)$/i.test(ruleId)) return 'unauthorized';
  if (/^(PROC_HIGH_CPU|PROC_HIGH_MEMORY|PROC_HIGH_DISK_IO|EDR_HIGH_MEMORY)$/i.test(ruleId)) return 'resource';
  if (/^(PROC_SERVICE_CREATED|PROC_SERVICE_CONTROL|PROC_SCHEDULED_TASK_CHANGE|PROC_SCHEDULED_TASK_ACTIVITY|PROC_STARTUP_PERSISTENCE_CHANGE|PROC_ASSET_.*)$/i.test(ruleId) || ['service', 'scheduled_task', 'startup'].includes(String(row?.inventoryType || row?.inventory_type || '')) || tags.some(tag => ['service', 'scheduled_task'].includes(tag))) return 'service';
  if (/^PROC_POWERSHELL_SCRIPT_BLOCK$/i.test(ruleId) || tags.some(tag => ['powershell', 'command_shell', 'python', 'java', 'vbscript_javascript'].includes(tag))) return 'scripts';
  if (/^PROC_(?:WORKLOAD|CONTAINER)_/i.test(ruleId) || row?.workloadType || row?.runtimeType || tags.some(tag => ['web_server', 'database', 'active_directory', 'container_cloud'].includes(tag))) return 'server';
  if (/^PROC_(?:INTERNAL_NETWORK_SCAN|NETWORK_CONNECTION|DNS_QUERY|DNS_ATTRIBUTED)$/i.test(ruleId) || tags.some(tag => ['network_enabled', 'outbound_internet', 'remote_access', 'ssh', 'rdp'].includes(tag))) return 'network';
  return 'other';
}

function processReportCategoryLabel(category) {
  return PROCESS_REPORT_CATEGORIES.find(option => option.key === category)?.label || PROCESS_REPORT_CATEGORIES[0].label;
}

function commandLine(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.cmdline || row?.commandLine || row?.cmd || row?.processCmdline || row?.command ||
    raw.cmdline || raw.commandLine || raw.cmd || raw.processCmdline || raw.command ||
    raw.process?.cmdline || raw.process?.commandLine || raw.process?.command || '';
}

function executablePath(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.processExe || row?.exe || row?.path || row?.executablePath || row?.filePath ||
    raw.process_exe || raw.processExe || raw.exe || raw.path || '';
}

function parentProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.parentProcess || row?.parentName || row?.parentProcessName || row?.ppid || row?.parentPid ||
    raw.parentProcess || raw.parentName || raw.parentProcessName || raw.ppid || raw.parentPid ||
    raw.process?.parent || raw.process?.parentName || raw.process?.ppid || '';
}

function parentCommandLine(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  return row?.parentCommandLine || row?.parentCmdline || row?.parentCmd || row?.parentProcessCmdline || row?.processParentCommandLine ||
    raw.parentCommandLine || raw.parentCmdline || raw.parentCmd || raw.parentProcessCmdline || raw.processParentCommandLine ||
    raw.parent_command_line || raw.parent_cmdline || raw.parent_cmd || raw.parent_process_cmdline ||
    raw.process?.parentCommandLine || raw.process?.parentCmdline || raw.process?.parentCmd ||
    raw.parent?.commandLine || raw.parent?.cmdline || raw.parent?.cmd || raw.parent?.command ||
    row?.parent?.commandLine || row?.parent?.cmdline || row?.parent?.cmd || row?.parent?.command || '';
}

function metricNumber(...values) {
  for (const value of values) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return 0;
}

function resourceMetric(row, keys) {
  const sources = [row, row?.rawEvent, row?.rawEvent?.raw];
  sources.push(...sources.map(source => source?.process));
  for (const source of sources) {
    for (const key of keys) {
      const value = key.split('.').reduce((current, part) => current?.[part], source);
      if (typeof value !== 'number' && typeof value !== 'string') continue;
      if (typeof value === 'string' && !value.trim()) continue;
      const number = Number(value);
      if (Number.isFinite(number) && number >= 0) return number;
    }
  }
  return null;
}

function cpuValue(row) {
  return resourceMetric(row, ['processCpuPercent', 'process_cpu_percent', 'cpuPercent', 'cpu_percent', 'cpuUsage', 'processCpu', 'cpu_pct', 'cpu']);
}

function ramValue(row) {
  const mb = resourceMetric(row, ['processMemoryMb', 'processMemoryMB', 'process_memory_mb', 'memoryMb', 'memoryMB', 'memory_mb', 'rssMb', 'rssMB', 'ramMb', 'ram']);
  if (mb !== null) return mb;
  const bytes = resourceMetric(row, ['processRssBytes', 'process_rss_bytes', 'rssBytes', 'rss_bytes', 'memoryRssBytes', 'workingSetBytes', 'privateWorkingSetBytes', 'memory_info.rss', 'memoryInfo.rss', 'memory.rss']);
  return bytes === null ? null : bytes / (1024 * 1024);
}

function ramPercentValue(row) {
  return resourceMetric(row, ['processMemoryPercent', 'process_memory_percent', 'memoryPercent', 'memory_percent', 'ramPercent', 'memory_pct', 'mem']);
}

function formatResource(value, unit) {
  return Number.isFinite(value) ? `${Number(value.toFixed(2))}${unit}` : 'Not reported';
}

function formatCpuRam(row) {
  const cpu = cpuValue(row);
  const ram = ramValue(row);
  const ramPct = ramPercentValue(row);
  const cpuText = formatResource(cpu, '%');
  const ramText = Number.isFinite(ram)
    ? formatResource(ram, ' MB')
    : formatResource(ramPct, '%');
  return `${cpuText} / ${ramText}`;
}

function ProcessResources({ row }) {
  const cpu = cpuValue(row);
  const ram = ramValue(row);
  const ramPercent = ramPercentValue(row);
  const ramText = Number.isFinite(ram) ? formatResource(ram, ' MB') : formatResource(ramPercent, '%');
  return <div aria-label="CPU and RAM usage" style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 10, whiteSpace: 'nowrap' }}>
    <span title={cpu === null ? 'CPU usage was not reported with this event.' : 'CPU usage reported with this event.'}>
      <span style={{ color: MON.muted }}>CPU: </span><b style={{ color: cpu === null ? MON.muted : cpu > 80 ? MON.red : MON.cyan }}>{formatResource(cpu, '%')}</b>
    </span>
    <span title={ram === null && ramPercent === null ? 'RAM usage was not reported with this event.' : 'RAM usage reported with this event.'}>
      <span style={{ color: MON.muted }}>RAM: </span><b style={{ color: ram === null && ramPercent === null ? MON.muted : ramPercent > 80 ? MON.red : MON.green }}>{ramText}</b>
    </span>
  </div>;
}

function processMetric(row, camelKey, snakeKey) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || {};
  const number = Number(row?.[camelKey] ?? row?.[snakeKey] ?? raw?.[camelKey] ?? raw?.[snakeKey]);
  return Number.isFinite(number) ? number : 0;
}

function processEvidence(row, camelKey, snakeKey = camelKey) {
  const rawEvent = row?.rawEvent || {};
  const raw = rawEvent?.raw || {};
  return row?.[camelKey] ?? row?.[snakeKey] ?? rawEvent?.[camelKey] ?? rawEvent?.[snakeKey] ?? raw?.[camelKey] ?? raw?.[snakeKey];
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1073741824) return `${(bytes / 1073741824).toFixed(1)} GB`;
  if (bytes >= 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function containsAny(row, words = []) {
  const haystack = [
    row?.process, row?.processName, row?.name, row?.executable, row?.command, row?.commandLine,
    row?.cmdline, row?.description, row?.message, row?.ruleName, row?.type, row?.category,
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
    if (key === 'unknown') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function recordId(row) {
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${processName(row)}-${row?.pid || row?.processId || ''}`;
}

function isVelociraptorClientId(idStr) {
  return typeof idStr === 'string' && /^C\.[0-9a-fA-F]{16}$/.test(idStr);
}

function systemVelociraptorClientId(sys) {
  if (!sys || typeof sys !== 'object') return '';
  const candidates = [
    sys.velociraptorClientId,
    sys.velociraptorId,
    sys.velociraptor_client_id,
    sys.clientId,
    sys.client_id,
  ];
  return candidates.find(isVelociraptorClientId) || '';
}

function findSystemForProcessLog(log, systems = []) {
  if (!log || !Array.isArray(systems)) return null;
  const systemRef = log.systemId;
  const systemId = String(systemRef?._id || systemRef?.id || systemRef || '');
  const hostname = normHost(alertHost(log));

  return systems.find(system => {
    const candidateId = String(system?._id || system?.id || '');
    if (systemId && candidateId && systemId === candidateId) return true;

    if (hostname === 'unknown') return false;
    return [system?.hostname, system?.name, system?.agentName]
      .some(value => value && normHost(value) === hostname);
  }) || null;
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

function createTablePdf(title, headers, rows) {
  const html = `
    <!DOCTYPE html>
    <html>
      <head>
        <title>${title}</title>
        <style>
          body { font-family: monospace; background: #060d16; color: #e2e8f0; padding: 20px; }
          h2 { color: #38bdf8; border-bottom: 2px solid #1a3050; padding-bottom: 8px; }
          table { width: 100%; border-collapse: collapse; margin-top: 15px; }
          th, td { border: 1px solid #1a3050; padding: 8px; text-align: left; font-size: 11px; }
          th { background: #0b1929; color: #38bdf8; }
          tr:nth-child(even) { background: #0f233a; }
        </style>
      </head>
      <body>
        <h2>${title}</h2>
        <p>Generated: ${new Date().toLocaleString()} | Process Activity Telemetry Report</p>
        <table>
          <thead>
            <tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr>
          </thead>
          <tbody>
            ${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}
          </tbody>
        </table>
        <script>window.print();</script>
      </body>
    </html>
  `;
  const win = window.open('', '_blank');
  if (win) {
    win.document.write(html);
    win.document.close();
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function ProcessLogDetailModal({ log, system, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || '');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState(processClassifications(log || {}).join(', '));
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Sys.Pslist');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux Process Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${alertHost(log || {})} process forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);
  const [huntResults, setHuntResults] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const velociraptorClientId = systemVelociraptorClientId(log)
    || systemVelociraptorClientId(log.systemId)
    || systemVelociraptorClientId(system);
  const raw = log?.rawEvent?.raw || log?.rawEvent || {};
  const remoteAddresses = log.processRemoteAddresses || log.remote_addresses || raw.remote_addresses || [];
  const yaraValue = log.yaraRules || log.yara_rules || raw.yara_rules || [];
  const yaraMatches = Array.isArray(yaraValue) ? yaraValue : [yaraValue].filter(Boolean);
  const mitreId = log.mitreId || log.mitreTechnique || log.mitre || raw.mitre_id || '';
  const endpointStatus = system?.status || log.systemId?.status || 'unknown';
  const evidenceType = processEvidence(log, 'evidenceType', 'evidence_type') || 'agent telemetry';
  const telemetryProvider = processEvidence(log, 'telemetryProvider', 'telemetry_provider') || log.source || 'AJNAT agent';
  const targetProcess = processEvidence(log, 'targetProcessName', 'target_process_name');
  const sourceProcess = processEvidence(log, 'sourceProcessName', 'source_process_name');
  const dnsName = log.domain || processEvidence(log, 'dnsQuery', 'dns_query');

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint' },
    { id: 'process', label: '⚙️ 4. Process & Lineage' },
    { id: 'files', label: '📁 5. Files & Handles' },
    { id: 'network', label: '🌐 6. Network & C2' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Linux Process Triage', desc: 'Linux process list, parent process clues, users, and command context.', artifact: 'Linux.Sys.Pslist' },
    { title: 'Linux Network Connections', desc: 'Active connections, listeners, ports, and remote endpoints.', artifact: 'Linux.Network.Netstat' },
    { title: 'Cron Persistence', desc: 'Cron jobs and scheduled persistence across users and system paths.', artifact: 'Linux.Sys.Crontab' },
    { title: 'Windows Process Tree', desc: 'Windows process list, command lines, hashes and parent lineage.', artifact: 'Windows.System.PSTree' },
    { title: 'Process Memory Dump', desc: 'Acquire process memory dump for deep offline analysis.', artifact: 'Windows.Memory.ProcessDump' },
    { title: 'YARA File Sweep', desc: 'Run IOC/YARA-style sweep across file paths.', artifact: 'Generic.Detection.Yara.Glob' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = async () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setHuntResults(null);
    try {
      const targetSystemId = typeof log.systemId === 'object' ? log.systemId?._id : log.systemId;
      if (!targetSystemId && !velociraptorClientId) throw new Error('This telemetry row is not linked to a Velociraptor endpoint');
      const { data } = await api.post('/edr/velociraptor/hunt', {
        name: huntNameInput,
        artifactName: selectedArtifact,
        systemId: targetSystemId || undefined,
        clientId: targetSystemId ? undefined : velociraptorClientId,
      });
      const hunt = data?.hunt || {};
      const rows = Object.entries(hunt).map(([Field, Value]) => ({
        Field,
        Value: typeof Value === 'object' ? JSON.stringify(Value) : String(Value ?? ''),
      }));
      setHuntResults(rows.length ? rows : [{ Field: 'Status', Value: 'Hunt accepted; results will be stored by Velociraptor.' }]);
      setHuntSuccessMsg(`✓ Forensic hunt "${huntNameInput}" was accepted for ${selectedArtifact}.`);
    } catch (error) {
      setHuntSuccessMsg(`Hunt failed: ${error.response?.data?.message || error.message}`);
    } finally {
      setLaunchingHunt(false);
    }
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleDownload = (format) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(log, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic_evidence_process_${log._id || log.eventId || Date.now()}.${format.toLowerCase()}`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🛡️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Forensic Investigation Panel — {log.process || log.title || 'Process Activity Event'}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  PID: {log.pid || log.processId || '—'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | User: <strong style={{ color: MON.text }}>{alertUser(log)}</strong> | Event Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
          {/* TAB 1: OVERVIEW */}
          {activeTab === 'overview' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
              {[
                ['Incident Summary', log.description || log.type || 'Process Execution & Anomaly Detected', MON.cyan],
                ['Risk Score', `${log.riskScore ?? log.score ?? '—'}/100`, metricNumber(log.riskScore, log.score) > 75 ? MON.red : MON.orange],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', alertHost(log), MON.blue],
                ['User Context', alertUser(log), MON.cyan],
                ['Detection Category', log.category || log.eventCategory || log.type || 'process', MON.purple],
                ['Executable Path', log.path || log.executablePath || log.filePath || log.commandLine || '—', MON.text],
                ['Evidence Type', evidenceType, MON.cyan],
                ['Telemetry Provider', telemetryProvider, MON.green],
                ['Source → Target', sourceProcess || targetProcess ? `${sourceProcess || '—'} → ${targetProcess || '—'}` : '—', MON.orange],
                ['Coverage Status', processEvidence(log, 'coverageStatus', 'coverage_status') || 'reported', MON.yellow],
              ].map(([lbl, val, col]) => (
                <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                  <div style={{ fontSize: 13, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-word' }}>{val}</div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Process Execution Chronology & Lifespan</div>
              {[
                { show: true, type: 'Process Event', time: alertTime(log) || '—', title: log.description || log.ruleId || 'Process telemetry observed', desc: `${processName(log)} (PID ${log.pid || log.processId || 'not reported'})`, col: MON.blue },
                { show: Boolean(parentProcess(log)), type: 'Parent Context', time: alertTime(log) || '—', title: 'Parent process observed', desc: `${parentProcess(log)} (PID ${log.ppid || log.parentPid || 'not reported'})`, col: MON.cyan },
                { show: Boolean(commandLine(log)), type: 'Command Line', time: alertTime(log) || '—', title: 'Command line observed', desc: commandLine(log), col: MON.orange },
                { show: remoteAddresses.length > 0, type: 'Network', time: alertTime(log) || '—', title: 'Process network endpoints observed', desc: remoteAddresses.join(', '), col: MON.yellow },
              ].filter(ev => ev.show).map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col, background: `${ev.col}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content' }}>{ev.type}</span>
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

          {/* TAB 3: ENDPOINT */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Endpoint Host Telemetry</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{log.agentId || log.agentName || '—'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Velociraptor ID:</span> <strong style={{ color: velociraptorClientId ? MON.purple : MON.yellow, fontFamily: 'monospace' }}>{velociraptorClientId || 'Not enrolled'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent Status:</span> <strong style={{ color: ['active', 'online', 'reporting'].includes(String(endpointStatus).toLowerCase()) ? MON.green : MON.yellow }}>● {endpointStatus}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>📡 Endpoint Network Identity</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Primary IP:</span> <b>{system?.ip || log.agentIP || log.srcip || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>MAC Address:</span> <span style={{ fontFamily: 'monospace' }}>{system?.macAddress || log.macAddress || 'Not reported'}</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Domain/Group:</span> <b>{system?.domain || log.domain || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & LINEAGE */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>⚙️ Parent-Child Process Lineage Tree</h4>
              <div style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 16, fontFamily: 'monospace', fontSize: 11, display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ color: MON.muted }}>├─ Parent: {log.parentProcess || log.parentName || 'not reported'}</div>
                <div style={{ color: MON.cyan, paddingLeft: 18 }}>└─ Parent PID: {log.ppid || log.parentPid || '—'}</div>
                <div style={{ color: MON.red, paddingLeft: 36, background: 'rgba(248,113,113,0.15)', padding: '6px 10px', borderRadius: 4 }}>
                  └─ ► [PID {log.pid || log.processId || '—'}] <b>{processName(log)}</b> (Target Monitored Process)
                </div>
                <div style={{ color: MON.muted, paddingLeft: 54 }}>└─ Child processes are shown only when the agent reports child evidence.</div>
              </div>
            </div>
          )}

          {/* TAB 5: FILES & HANDLES */}
          {activeTab === 'files' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>📁 File System Handles & Registry Modification</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                {(log.filePath || log.sourcePath || log.keyPath || log.registryKey) ? (
                  <>
                    {(log.filePath || log.sourcePath) && <div style={{ background: MON.card2, padding: 10, borderRadius: 6, border: `1px solid ${MON.line}` }}><b style={{ color: MON.blue }}>File evidence:</b> <span style={{ fontFamily: 'monospace', color: MON.text }}>{log.filePath || log.sourcePath}</span></div>}
                    {(log.keyPath || log.registryKey) && <div style={{ background: MON.card2, padding: 10, borderRadius: 6, border: `1px solid ${MON.line}` }}><b style={{ color: MON.yellow }}>Registry evidence:</b> <span style={{ fontFamily: 'monospace', color: MON.text }}>{log.keyPath || log.registryKey}</span></div>}
                  </>
                ) : <span style={{ color: MON.muted }}>No file-handle or registry evidence was reported for this event.</span>}
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK */}
          {activeTab === 'network' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>🌐 Outbound Connections & DNS Queries</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10, fontSize: 11, background: MON.card2, padding: 10, borderRadius: 6, fontWeight: 800, color: MON.sub }}>
                <span>Protocol</span><span>Local Socket</span><span>Remote Endpoint</span><span>State</span>
              </div>
              {dnsName && <div style={{ padding: 10, color: MON.cyan, fontSize: 11, borderBottom: `1px solid ${MON.line}` }}>
                DNS: <b>{dnsName}</b> · attribution: <b>{processEvidence(log, 'attributionConfidence', 'attribution_confidence') || 'provider evidence'}</b>
              </div>}
              {remoteAddresses.length ? remoteAddresses.map(address => (
                <div key={address} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10, fontSize: 11, padding: 10, borderBottom: `1px solid ${MON.line}` }}>
                  <b style={{ color: MON.green }}>{log.protocol || 'IP'}</b><span>{log.srcip || 'Not reported'}</span><span style={{ color: MON.red }}>{address}</span><b>{log.processStatus || 'Observed'}</b>
                </div>
              )) : <div style={{ padding: 12, color: MON.muted, fontSize: 11 }}>No process-attributed remote endpoint was reported for this event.</div>}
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Mapping</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {mitreId ? <div style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}><b style={{ color: MON.red }}>{mitreId}{log.technique ? `: ${log.technique}` : ''}</b></div> : <span style={{ color: MON.muted }}>No MITRE mapping reported for this event.</span>}
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🔍 YARA Rule Matches</h4>
                <div style={{ fontSize: 11, color: MON.text }}>
                  {yaraMatches.length ? <><b>Rule Match:</b> <span style={{ color: MON.purple, fontFamily: 'monospace' }}>{yaraMatches.join(', ')}</span></> : <span style={{ color: MON.muted }}>No YARA match reported for this event.</span>}
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Forensic Artifact Hunt Launcher</div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, marginBottom: 14 }}>
                  {forensicHuntCards.map((item) => (
                    <div key={item.artifact} onClick={() => handleSelectArtifactCard(item)} style={{ background: selectedArtifact === item.artifact ? MON.card2 : MON.bg, border: `1px solid ${selectedArtifact === item.artifact ? MON.cyan : MON.border}`, borderRadius: 6, padding: 12, cursor: 'pointer' }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{item.title}</div>
                      <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>{item.desc}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
                  <div style={{ flex: 1 }}>
                    <label style={{ fontSize: 9, color: MON.muted, textTransform: 'uppercase', display: 'block', marginBottom: 4 }}>Hunt Name Description</label>
                    <input type="text" value={huntNameInput} onChange={e => setHuntNameInput(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 4, fontSize: 11, outline: 'none' }} />
                  </div>
                </div>

                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 11, color: MON.cyan }}>Selected VQL: <b>{selectedArtifact}</b></span>
                  <button type="button" onClick={handleLaunchHunt} disabled={launchingHunt} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: launchingHunt ? 'not-allowed' : 'pointer' }}>
                    {launchingHunt ? 'Dispatching Hunt...' : '🚀 Launch VQL Hunt'}
                  </button>
                </div>

                {huntSuccessMsg && (
                  <div style={{ marginTop: 12, padding: 10, background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11 }}>
                    {huntSuccessMsg}
                  </div>
                )}

                {/* VQL Results Output */}
                {huntResults && (
                  <div style={{ marginTop: 16 }}>
                    <div style={{ fontSize: 11, color: MON.cyan, fontWeight: 800, marginBottom: 8 }}>📊 VQL Hunt Output Results (Velociraptor Artifact: {selectedArtifact})</div>
                    <div style={{ overflowX: 'auto', background: MON.bg, border: `1px solid ${MON.line}`, borderRadius: 6 }}>
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
                        <thead>
                          <tr style={{ background: MON.card2, color: MON.muted, textAlign: 'left', borderBottom: `1px solid ${MON.line}` }}>
                            {Object.keys(huntResults[0] || {}).map(k => (
                              <th key={k} style={{ padding: '8px 10px', fontSize: 9, textTransform: 'uppercase', letterSpacing: 0.5 }}>{k}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {huntResults.map((r, i) => (
                            <tr key={i} style={{ borderBottom: i < huntResults.length - 1 ? `1px solid ${MON.line}80` : 'none', color: MON.text }}>
                              {Object.values(r).map((val, j) => (
                                <td key={j} style={{ padding: '8px 10px', fontFamily: 'monospace' }}>
                                  {typeof val === 'string' && val.includes('Potential Reverse Shell') ? (
                                    <span style={{ color: MON.red, fontWeight: 'bold' }}>{val}</span>
                                  ) : typeof val === 'string' && val.includes('SUCCESSFUL') ? (
                                    <span style={{ color: MON.green, fontWeight: 'bold' }}>{val}</span>
                                  ) : (
                                    String(val)
                                  )}
                                </td>
                              ))}
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Persisted Process Evidence</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {JSON.stringify({
                  eventId: log._id || log.eventId,
                  observedAt: alertTime(log),
                  host: alertHost(log),
                  os: processOs(log),
                  process: processName(log),
                  pid: log.pid || log.processId,
                  parent: parentProcess(log),
                  commandLine: commandLine(log),
                  executable: executablePath(log),
                  cpuPercent: cpuValue(log),
                  memoryMb: ramValue(log),
                  rawEvent: log.rawEvent || null,
                }, null, 2)}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Triage Notes & Case Management</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Assigned Analyst</label>
                    <input type="text" value={assignedAnalyst} onChange={e => setAssignedAnalyst(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Case Status</label>
                    <select value={caseStatus} onChange={e => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }}>
                      <option value="In Triage">In Triage</option>
                      <option value="Escalated to L3">Escalated to L3</option>
                      <option value="Contained">Contained</option>
                      <option value="False Positive">False Positive</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Incident Tags</label>
                    <input type="text" value={tags} onChange={e => setTags(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                </div>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end' }}>
                  <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    {notesSaved ? '✓ Saved!' : 'Save Triage Notes'}
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

// ═════════════════════════════════════════════════════════════════════════════
// 2. SUB-PANELS (Log Monitor, Policy Violations, Reports, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
function ProcessLogMonitor({ alerts = [], systems = [] }) {
  const pageSize = 100;
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [status, setStatus] = useState('all');
  const [page, setPage] = useState(1);
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${processName(a)} ${commandLine(a)} ${parentCommandLine(a)} ${alertHost(a)} ${alertUser(a)} ${a.type || ''}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchSt = status === 'all' || alertStatus(a).toLowerCase() === status.toLowerCase();
      return matchQ && matchP && matchS && matchSt;
    });
  }, [alerts, query, platform, severity, status]);

  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visibleRows = filtered.slice((page - 1) * pageSize, page * pageSize);

  useEffect(() => setPage(1), [query, platform, severity, status]);
  useEffect(() => setPage(current => Math.min(current, pageCount)), [pageCount]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Process, PID, Command Line, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={platform} onChange={e => setPlatform(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All OS Platforms</option>
          <option value="win">Windows</option>
          <option value="lin">Linux</option>
          <option value="mac">macOS</option>
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={status} onChange={e => setStatus(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Statuses</option>
          <option value="running">Running</option>
          <option value="suspicious">Suspicious</option>
          <option value="high risk">High Risk</option>
          <option value="terminated">Terminated</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Monitored Process Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Socket live · 30s reconciliation</span>
        </div>
        <div style={{ minWidth: 1280 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.15fr 60px 1fr 0.75fr 0.9fr 1.35fr 125px 70px 80px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Process / Executable</span><span>PID</span><span>Host / OS</span><span>User</span><span>Parent</span><span>Command Line</span><span>CPU / RAM</span><span>Severity</span><span>Status</span><span>Category</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {visibleRows.length ? visibleRows.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.15fr 60px 1fr 0.75fr 0.9fr 1.35fr 125px 70px 80px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{processName(row)}</b>
                  <span title={executablePath(row)} style={{ fontSize: 9, color: MON.sub }}>{String(executablePath(row) || 'OS did not expose executable path').slice(0, 42)}</span>
                </div>
                <span style={{ fontFamily: 'monospace', color: MON.blue }}>{row.pid || row.processId || '—'}</span>
                <div>
                  <b style={{ color: '#fff', display: 'block' }}>{alertHost(row)}</b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{processOs(row)}</span>
                </div>
                <span style={{ color: MON.green }}>{alertUser(row)}</span>
                <span title={parentCommandLine(row) || String(parentProcess(row) || '')} style={{ color: MON.muted, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{parentProcess(row) || 'Not reported'}</span>
                <span title={commandLine(row)} style={{ color: MON.muted, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{commandLine(row) || executablePath(row) || 'OS did not expose command line'}</span>
                <ProcessResources row={row} />
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: /high risk|suspicious|terminated|blocked/i.test(alertStatus(row)) ? MON.red : MON.green, fontWeight: 800 }}>{alertStatus(row)}</span>
                <span style={{ fontSize: 9, color: MON.orange }}>{processReportCategoryLabel(processReportCategory(row))}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No process telemetry logs match filters</div>}
          </div>
        </div>
        {filtered.length > pageSize && (
          <div style={{ padding: '9px 14px', borderTop: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: MON.muted }}>Showing {((page - 1) * pageSize) + 1}–{Math.min(page * pageSize, filtered.length)} of {filtered.length.toLocaleString()} live 24h logs</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button type="button" disabled={page === 1} onClick={() => setPage(value => Math.max(1, value - 1))} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '4px 9px', borderRadius: 4, cursor: page === 1 ? 'not-allowed' : 'pointer', opacity: page === 1 ? 0.5 : 1 }}>Previous</button>
              <span style={{ color: MON.cyan }}>Page {page} / {pageCount}</span>
              <button type="button" disabled={page === pageCount} onClick={() => setPage(value => Math.min(pageCount, value + 1))} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '4px 9px', borderRadius: 4, cursor: page === pageCount ? 'not-allowed' : 'pointer', opacity: page === pageCount ? 0.5 : 1 }}>Next</button>
            </div>
          </div>
        )}
      </div>

      {selectedLog && (
        <ProcessLogDetailModal
          log={selectedLog}
          system={findSystemForProcessLog(selectedLog, systems)}
          onClose={() => setSelectedLog(null)}
        />
      )}
    </div>
  );
}



function ProcessReportsTab({ alerts = [], total = 0 }) {
  const dayMs = 86400000;
  const [reportType, setReportType] = useState('daily');
  const [reportCategory, setReportCategory] = useState('all');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [exportingPdf, setExportingPdf] = useState(false);
  const [reportData, setReportData] = useState(null); // backend-fetched stats

  // Keep the local fallback bound to the exact requested window. Records without
  // a usable timestamp cannot safely be assigned to a time-based report.
  const getFilteredAlerts = (period = reportType, endTime = Date.now(), category = reportCategory) => {
    const windowMap = { daily: 1, weekly: 7, monthly: 30, '90days': 90, '180days': 180 };
    const days = windowMap[period] || 1;
    const cutoff = endTime - days * dayMs;
    return alerts.filter(a => {
      const timestamp = new Date(alertTime(a)).getTime();
      const categoryMatches = category === 'all' || processReportCategory(a) === category;
      return categoryMatches && Number.isFinite(timestamp) && timestamp >= cutoff && timestamp <= endTime;
    });
  };

  const buildLocalReport = (period, endTime = Date.now(), category = reportCategory) => {
    const periodDays = { daily: 1, weekly: 7, monthly: 30, '90days': 90, '180days': 180 }[period] || 1;
    const filteredAlerts = getFilteredAlerts(period, endTime, category);
    const bySev = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const byPlatform = { Windows: 0, Linux: 0, macOS: 0, Other: 0 };
    const byStatus = {};

    filteredAlerts.forEach(a => {
      const severity = alertSeverity(a);
      if (bySev[severity] !== undefined) bySev[severity] += 1;
      else bySev.unknown += 1;

      const platform = processOs(a);
      if (byPlatform[platform] !== undefined) byPlatform[platform] += 1;
      else byPlatform.Other += 1;

      const status = alertStatus(a);
      byStatus[status] = (byStatus[status] || 0) + 1;
    });

    return {
      period,
      category,
      alerts: filteredAlerts,
      total: filteredAlerts.length,
      bySev,
      byPlatform,
      byStatus,
      since: new Date(endTime - periodDays * dayMs).toISOString(),
      until: new Date(endTime).toISOString(),
    };
  };

  // Export PDF — Full Report with Charts + Cards + All Logs (fetched fresh from backend)
  const handleExportPDF = async () => {
    setExportingPdf(true);
    const activeReportType = reportData?.period || reportType;
    const activeReportCategory = reportData?.category || reportCategory;
    const categoryLabel = processReportCategoryLabel(activeReportCategory);
    const period = activeReportType === '180days' ? '6 Month Security Analysis' : activeReportType === '90days' ? '90 Day Security Analysis' : activeReportType === 'daily' ? 'Daily (24 Hours)' : activeReportType === 'weekly' ? 'Weekly Summary' : 'Monthly Report';
    let now = new Date(reportData?.until || Date.now());
    const periodDays = { daily: 1, weekly: 7, monthly: 30, '90days': 90, '180days': 180 }[activeReportType] || 1;
    let start = new Date(reportData?.since || now.getTime() - periodDays * 86400000);

    // Fetch ALL logs using dedicated report API — no limit, single call
    let filtered = reportData?.alerts || [];
    let apiStats = reportData ? { bySeverity: reportData.bySev, byPlatform: reportData.byPlatform, byStatus: reportData.byStatus } : null;
    if (!reportData) {
      try {
        const r = await api.get(`/dashboard/process-activity/report?period=${activeReportType}&category=${activeReportCategory}`);
        filtered = r.data?.alerts || [];
        apiStats = r.data?.stats || null;
        now = new Date(r.data?.until || Date.now());
        start = new Date(r.data?.since || now.getTime() - periodDays * 86400000);
      } catch {
        const localReport = buildLocalReport(activeReportType, Date.now(), activeReportCategory);
        filtered = localReport.alerts;
        apiStats = { bySeverity: localReport.bySev, byPlatform: localReport.byPlatform, byStatus: localReport.byStatus };
        now = new Date(localReport.until);
        start = new Date(localReport.since);
      }
    }

    // Use pre-computed stats from API, or compute locally as fallback
    const total = filtered.length;
    const bySev = apiStats?.bySeverity || { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    const byPlatform = apiStats?.byPlatform || { Windows: 0, Linux: 0, macOS: 0, Other: 0 };
    const byStatus = apiStats?.byStatus || {};
    if (!apiStats) {
      filtered.forEach(a => {
        const s = alertSeverity(a).toLowerCase();
        if (bySev[s] !== undefined) bySev[s]++; else bySev.unknown++;
        const p = (a.platform || a.os || '').toLowerCase();
        if (p.includes('win')) byPlatform.Windows++;
        else if (p.includes('linux')) byPlatform.Linux++;
        else if (p.includes('mac')) byPlatform.macOS++;
        else byPlatform.Other++;
        const st = a.status || 'open';
        byStatus[st] = (byStatus[st] || 0) + 1;
      });
    }

    // Build a timeline covering the complete selected report window.
    const bucketCount = activeReportType === 'daily' ? 24 : activeReportType === 'weekly' ? 7 : 30;
    const rangeMs = Math.max(now.getTime() - start.getTime(), 1);
    const bucketMs = rangeMs / bucketCount;
    const timelineVals = Array(bucketCount).fill(0);
    const timelineLabels = Array.from({ length: bucketCount }, (_, index) => {
      const bucketStart = new Date(start.getTime() + index * bucketMs);
      return activeReportType === 'daily'
        ? bucketStart.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })
        : bucketStart.toLocaleDateString('en-GB', { day: '2-digit', month: 'short' });
    });
    filtered.forEach(a => {
      const timestamp = new Date(alertTime(a)).getTime();
      if (!Number.isFinite(timestamp) || timestamp < start.getTime() || timestamp > now.getTime()) return;
      const bucketIndex = Math.min(bucketCount - 1, Math.floor((timestamp - start.getTime()) / bucketMs));
      timelineVals[bucketIndex] += 1;
    });
    const maxTimeline = Math.max(...timelineVals, 1);

    // SVG Bar chart — Severity Distribution
    const sevColors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', unknown: '#64748b' };
    const sevEntries = Object.entries(bySev).filter(([, v]) => v > 0);
    const maxSev = Math.max(...sevEntries.map(([, v]) => v), 1);
    const barW = 60; const barGap = 20; const chartH = 120;
    const sevSvgW = sevEntries.length * (barW + barGap);
    const sevBars = sevEntries.map(([k, v], i) => {
      const h = Math.max(4, Math.round((v / maxSev) * chartH));
      const x = i * (barW + barGap);
      return `<g>
        <rect x="${x}" y="${chartH - h}" width="${barW}" height="${h}" fill="${sevColors[k]}" rx="4"/>
        <text x="${x + barW / 2}" y="${chartH - h - 5}" text-anchor="middle" font-size="11" fill="${sevColors[k]}" font-weight="bold">${v}</text>
        <text x="${x + barW / 2}" y="${chartH + 16}" text-anchor="middle" font-size="10" fill="#94a3b8" text-transform="capitalize">${k.charAt(0).toUpperCase() + k.slice(1)}</text>
      </g>`;
    }).join('');

    // SVG Donut — Platform Distribution
    const platEntries = Object.entries(byPlatform).filter(([, v]) => v > 0);
    const platColors = { Windows: '#38bdf8', Linux: '#f97316', macOS: '#a78bfa', Other: '#94a3b8' };
    const platTotal = platEntries.reduce((s, [, v]) => s + v, 0) || 1;
    let donutAngle = 0;
    const r = 55; const cx = 70; const cy = 70;
    const donutSlices = platEntries.map(([k, v]) => {
      const angle = (v / platTotal) * 360;
      const startA = donutAngle; donutAngle += angle;
      const toRad = a => (a - 90) * Math.PI / 180;
      const x1 = cx + r * Math.cos(toRad(startA)), y1 = cy + r * Math.sin(toRad(startA));
      const x2 = cx + r * Math.cos(toRad(donutAngle)), y2 = cy + r * Math.sin(toRad(donutAngle));
      const large = angle > 180 ? 1 : 0;
      const ri = 30;
      const xi1 = cx + ri * Math.cos(toRad(startA)), yi1 = cy + ri * Math.sin(toRad(startA));
      const xi2 = cx + ri * Math.cos(toRad(donutAngle)), yi2 = cy + ri * Math.sin(toRad(donutAngle));
      return `<path d="M${x1},${y1} A${r},${r} 0 ${large},1 ${x2},${y2} L${xi2},${yi2} A${ri},${ri} 0 ${large},0 ${xi1},${yi1} Z" fill="${platColors[k] || '#94a3b8'}"/>`;
    }).join('');

    // SVG Timeline bars
    const tlBarW = Math.max(14, Math.floor(580 / timelineLabels.length) - 4);
    const tlBars = timelineLabels.map((lbl, i) => {
      const v = timelineVals[i];
      const h = Math.max(2, Math.round((v / maxTimeline) * 90));
      const x = i * (tlBarW + 4);
      return `<g>
        <rect x="${x}" y="${90 - h}" width="${tlBarW}" height="${h}" fill="#38bdf8" rx="2" opacity="0.85"/>
        ${i % 2 === 0 ? `<text x="${x + tlBarW / 2}" y="108" text-anchor="middle" font-size="8" fill="#94a3b8">${lbl}</text>` : ''}
        ${v > 0 ? `<text x="${x + tlBarW / 2}" y="${90 - h - 3}" text-anchor="middle" font-size="8" fill="#38bdf8">${v}</text>` : ''}
      </g>`;
    }).join('');

    // Logs table rows HTML
    const logsHtml = filtered.map((a, i) => {
      const sev = alertSeverity(a);
      const sc = sevColors[sev] || '#64748b';
      const ts = (alertTime(a) || '').toString().replace('T', ' ').substring(0, 19);
      return `<tr style="background:${i % 2 === 0 ? '#0d1b2a' : '#0a1520'}">
        <td>${i + 1}</td>
        <td style="white-space:nowrap;color:#94a3b8">${ts}</td>
        <td style="font-weight:700;color:#f1f5f9">${processName(a)}</td>
        <td style="color:#94a3b8">${a.pid || '—'}</td>
        <td>${alertHost(a)}</td>
        <td style="color:#94a3b8">${alertUser(a)}</td>
        <td style="color:#94a3b8;max-width:120px;overflow:hidden;text-overflow:ellipsis">${parentProcess(a) || '—'}</td>
        <td style="color:#94a3b8;max-width:150px;overflow:hidden;text-overflow:ellipsis" title="${commandLine(a).replace(/"/g, "'")}">${(commandLine(a) || '—').substring(0, 40)}${commandLine(a).length > 40 ? '…' : ''}</td>
        <td style="color:#94a3b8">${processOs(a)}</td>
        <td><span style="background:${sc}22;color:${sc};border:1px solid ${sc}55;border-radius:4px;padding:2px 6px;font-weight:800;font-size:9px;text-transform:uppercase">${sev}</span></td>
        <td style="color:#94a3b8;text-transform:capitalize">${alertStatus(a)}</td>
        <td style="color:#94a3b8">${a.category || a.type || '—'}</td>
      </tr>`;
    }).join('');

    // Platform legend
    const platLegend = platEntries.map(([k, v]) =>
      `<div style="display:flex;align-items:center;gap:6px;margin-bottom:6px">
        <div style="width:12px;height:12px;border-radius:50%;background:${platColors[k] || '#94a3b8'}"></div>
        <span style="font-size:11px;color:#94a3b8">${k}: <b style="color:#f1f5f9">${v} (${Math.round(v / platTotal * 100)}%)</b></span>
      </div>`
    ).join('');

    const html = `<!DOCTYPE html><html><head><title>Process Activity ${period} Report</title>
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body { font-family: 'Segoe UI', monospace, sans-serif; background: #060d16; color: #e2e8f0; padding: 28px; font-size: 11px; }
      h1 { font-size: 22px; font-weight: 900; color: #38bdf8; margin-bottom: 4px; }
      h2 { font-size: 14px; font-weight: 800; color: #38bdf8; margin-bottom: 12px; border-bottom: 1px solid #1b3854; padding-bottom: 6px; }
      .meta { color: #64748b; font-size: 10px; margin-bottom: 24px; }
      .cards { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
      .card { background: #0d1b2a; border: 1px solid #1b3854; border-radius: 8px; padding: 14px; }
      .card-label { font-size: 9px; text-transform: uppercase; font-weight: 800; letter-spacing: 0.5px; margin-bottom: 6px; }
      .card-val { font-size: 28px; font-weight: 900; line-height: 1; }
      .card-sub { font-size: 9px; color: #64748b; margin-top: 4px; }
      .charts { display: grid; grid-template-columns: 1fr 200px; gap: 16px; margin-bottom: 24px; }
      .chart-box { background: #0d1b2a; border: 1px solid #1b3854; border-radius: 8px; padding: 14px; }
      table { width: 100%; border-collapse: collapse; font-size: 10px; margin-top: 8px; }
      th { background: #0b1929; color: #38bdf8; padding: 7px 8px; text-align: left; border-bottom: 1px solid #1b3854; font-weight: 800; white-space: nowrap; }
      td { padding: 5px 8px; border-bottom: 1px solid #0f2035; vertical-align: middle; }
      .tl-section { background: #0d1b2a; border: 1px solid #1b3854; border-radius: 8px; padding: 14px; margin-bottom: 24px; }
      @media print { body { background: #060d16 !important; } @page { size: A3 landscape; margin: 12mm; } }
    </style></head><body>
    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px">
      <div>
        <div style="font-size:10px;color:#38bdf8;font-weight:800;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px">🛡️ SOC — Process Activity Monitoring</div>
        <h1>📄 ${period} Security Report</h1>
        <div class="meta">Generated: ${now.toLocaleString()} &nbsp;|&nbsp; Coverage: ${start.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} → ${now.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })} &nbsp;|&nbsp; Category: ${categoryLabel} &nbsp;|&nbsp; Total Records: <b style="color:#38bdf8">${total.toLocaleString()}</b></div>
      </div>
      <div style="text-align:right;font-size:9px;color:#64748b">Capability ID: 1<br>Process Activity Monitoring<br>🟢 Confidential — SOC Internal</div>
    </div>

    <h2>📊 Executive Summary</h2>
    <div class="cards">
      <div class="card"><div class="card-label" style="color:#38bdf8">Total Logs</div><div class="card-val" style="color:#38bdf8">${total.toLocaleString()}</div><div class="card-sub">${period}</div></div>
      <div class="card"><div class="card-label" style="color:#ef4444">Critical + High</div><div class="card-val" style="color:#ef4444">${(bySev.critical + bySev.high).toLocaleString()}</div><div class="card-sub">High-severity events</div></div>
      <div class="card"><div class="card-label" style="color:#eab308">Medium Events</div><div class="card-val" style="color:#eab308">${bySev.medium.toLocaleString()}</div><div class="card-sub">Medium severity</div></div>
      <div class="card"><div class="card-label" style="color:#22c55e">Low / Info</div><div class="card-val" style="color:#22c55e">${(bySev.low + (bySev.unknown || 0)).toLocaleString()}</div><div class="card-sub">Low priority events</div></div>
      <div class="card"><div class="card-label" style="color:#38bdf8">Windows</div><div class="card-val" style="color:#38bdf8">${byPlatform.Windows.toLocaleString()}</div><div class="card-sub">Windows endpoints</div></div>
      <div class="card"><div class="card-label" style="color:#f97316">Linux</div><div class="card-val" style="color:#f97316">${byPlatform.Linux.toLocaleString()}</div><div class="card-sub">Linux servers</div></div>
      <div class="card"><div class="card-label" style="color:#a78bfa">macOS</div><div class="card-val" style="color:#a78bfa">${byPlatform.macOS.toLocaleString()}</div><div class="card-sub">macOS devices</div></div>
      <div class="card"><div class="card-label" style="color:#f97316">Open Cases</div><div class="card-val" style="color:#f97316">${(byStatus['open'] || 0).toLocaleString()}</div><div class="card-sub">Pending triage</div></div>
    </div>

    <div class="tl-section">
      <h2 style="border:none;margin-bottom:10px">📈 Activity Timeline (${period})</h2>
      <svg width="100%" height="120" viewBox="0 0 ${timelineLabels.length * (tlBarW + 4)} 120" preserveAspectRatio="none">${tlBars}</svg>
    </div>

    <div class="charts">
      <div class="chart-box">
        <h2 style="border:none;margin-bottom:10px">📊 Severity Distribution</h2>
        <svg width="${Math.max(320, sevSvgW)}" height="${chartH + 30}" viewBox="0 0 ${Math.max(320, sevSvgW)} ${chartH + 30}">${sevBars}</svg>
      </div>
      <div class="chart-box">
        <h2 style="border:none;margin-bottom:10px">🖥 Platform Split</h2>
        <svg width="140" height="140" viewBox="0 0 140 140">${donutSlices}<circle cx="${cx}" cy="${cy}" r="28" fill="#0d1b2a"/><text x="${cx}" y="${cy + 4}" text-anchor="middle" font-size="11" fill="#38bdf8" font-weight="800">${total}</text></svg>
        <div style="margin-top:8px">${platLegend}</div>
      </div>
    </div>

    <h2>📋 Full Process Activity Logs — ${total.toLocaleString()} Records</h2>
    <table>
      <thead><tr><th>#</th><th>Timestamp</th><th>Process</th><th>PID</th><th>Hostname</th><th>User</th><th>Parent</th><th>Command Line</th><th>Platform</th><th>Severity</th><th>Status</th><th>Category</th></tr></thead>
      <tbody>${logsHtml}</tbody>
    </table>

    <div style="margin-top:24px;border-top:1px solid #1b3854;padding-top:12px;display:flex;justify-content:space-between;font-size:9px;color:#475569">
      <span>🛡️ SOC Process Activity Monitoring — Capability ID: 1</span>
      <span>Generated: ${now.toLocaleString()} | CONFIDENTIAL</span>
    </div>
    <script>window.onload = () => window.print();</script>
    </body></html>`;

    const win = window.open('', '_blank');
    if (win) { win.document.write(html); win.document.close(); }
    setExportingPdf(false);
  };


  // Export CSV with ALL log columns from dedicated report API
  const handleExportCSV = async () => {
    const activeReportType = reportData?.period || reportType;
    const activeReportCategory = reportData?.category || reportCategory;
    let filtered = reportData?.alerts || [];
    if (!reportData) {
      try {
        const r = await api.get(`/dashboard/process-activity/report?period=${activeReportType}&category=${activeReportCategory}`);
        filtered = r.data?.alerts || [];
      } catch {
        filtered = getFilteredAlerts(activeReportType, Date.now(), activeReportCategory);
      }
    }

    const header = 'Timestamp,Process,PID,Hostname,User,Parent Process,Command Line,Platform,Severity,Status,Category,SHA256';
    const rows = filtered.map(a => [
      `"${alertTime(a) || ''}"`,
      `"${processName(a)}"`,
      `"${a.pid || ''}"`,
      `"${alertHost(a)}"`,
      `"${alertUser(a)}"`,
      `"${parentProcess(a).toString().replace(/"/g, "'")}"`,
      `"${commandLine(a).replace(/"/g, "'")}"`,
      `"${processOs(a)}"`,
      `"${alertSeverity(a)}"`,
      `"${alertStatus(a)}"`,
      `"${a.category || a.type || ''}"`,
      `"${a.sha256 || a.hash || ''}"`,
    ].join(','));
    const period = activeReportType === '90days' ? '90day' : activeReportType;
    downloadBlob([header, ...rows].join('\n'), `process_activity_${period}_${activeReportCategory}_${filtered.length}records_${Date.now()}.csv`);
  };

  const handleGenerate = async () => {
    const requestedPeriod = reportType;
    const requestedCategory = reportCategory;
    setGenerating(true);
    setGenerated(false);
    setReportData(null);
    try {
      const r = await api.get(`/dashboard/process-activity/report?period=${requestedPeriod}&category=${requestedCategory}`);
      const fetchedAlerts = r.data?.alerts || [];
      setReportData({
        period: requestedPeriod,
        category: requestedCategory,
        alerts: fetchedAlerts,
        total: Number.isFinite(Number(r.data?.total)) ? Number(r.data.total) : fetchedAlerts.length,
        bySev: r.data?.stats?.bySeverity || { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 },
        byPlatform: r.data?.stats?.byPlatform || { Windows: 0, Linux: 0, macOS: 0, Other: 0 },
        byStatus: r.data?.stats?.byStatus || {},
        since: r.data?.since || null,
        until: r.data?.until || new Date().toISOString(),
      });
    } catch {
      setReportData(buildLocalReport(requestedPeriod, Date.now(), requestedCategory));
    }
    setGenerating(false);
    setGenerated(true);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* ── Header ── */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Process Activity &amp; Threat Security Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive-level summaries with full log export for the selected time range</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer', flexShrink: 0 }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Report'}
          </button>
        </div>

        {/* ── Time Range Selector ── */}
        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📅 Select Time Range</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              { key: 'daily', label: '24 Hours', icon: '⏱', sub: 'Last 24h' },
              { key: 'weekly', label: '1 Week', icon: '📆', sub: 'Last 7 days' },
              { key: 'monthly', label: '1 Month', icon: '🗓', sub: 'Last 30 days' },
              { key: '90days', label: '3 Months', icon: '📊', sub: 'Last 90 days' },
              { key: '180days', label: '6 Months', icon: '📅', sub: 'Last 180 days' },
            ].map(opt => {
              const active = reportType === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  disabled={generating}
                  onClick={() => { setReportType(opt.key); setGenerated(false); setReportData(null); }}
                  style={{
                    background: active ? MON.cyan : MON.card2,
                    color: active ? '#000' : MON.text,
                    border: `2px solid ${active ? MON.cyan : MON.border}`,
                    borderRadius: 8, padding: '10px 18px', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, minWidth: 100,
                    fontWeight: active ? 900 : 600, transition: 'all 0.15s', opacity: generating ? 0.65 : 1,
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

        <div style={{ marginTop: 14, maxWidth: 320 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📂 Report Category</div>
          <select
            value={reportCategory}
            disabled={generating}
            onChange={event => { setReportCategory(event.target.value); setGenerated(false); setReportData(null); }}
            style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.cyan}`, color: MON.text, padding: '9px 11px', borderRadius: 6, fontSize: 11, opacity: generating ? 0.65 : 1 }}
          >
            {PROCESS_REPORT_CATEGORIES.map(option => <option key={option.key} value={option.key}>{option.label}</option>)}
          </select>
        </div>
      </div>

      {/* ── Generated Report Section ── */}
      {generated && (() => {
        const generatedPeriod = reportData?.period || reportType;
        const generatedCategory = reportData?.category || reportCategory;
        const generatedCategoryLabel = processReportCategoryLabel(generatedCategory);
        const periodDays = { daily: 1, weekly: 7, monthly: 30, '90days': 90, '180days': 180 }[generatedPeriod] || 1;
        const periodLabel = { daily: 'Last 24 Hours', weekly: 'Last 7 Days', monthly: 'Last 30 Days', '90days': 'Last 90 Days', '180days': 'Last 180 Days' }[generatedPeriod];
        const sinceMs = reportData?.since ? new Date(reportData.since).getTime() : Date.now() - periodDays * 86400000;
        const untilMs = reportData?.until ? new Date(reportData.until).getTime() : Date.now();
        const reportAlerts = reportData?.alerts || getFilteredAlerts(generatedPeriod, untilMs, generatedCategory);
        const fLen = Number.isFinite(Number(reportData?.total)) ? Number(reportData.total) : reportAlerts.length;
        const rawSev = reportData?.bySev || buildLocalReport(generatedPeriod, untilMs, generatedCategory).bySev;
        const bySev = {
          critical: Number(rawSev.critical) || 0,
          high: Number(rawSev.high) || 0,
          medium: Number(rawSev.medium) || 0,
          low: (Number(rawSev.low) || 0) + (Number(rawSev.unknown) || 0),
        };

        const coverStart = new Date(sinceMs).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });
        const coverEnd = new Date(untilMs).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' });

        return (
          <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Report header row */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
              <div>
                <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>
                  📄 Process Activity Executive Report — {periodLabel} · {generatedCategoryLabel}
                </div>
                <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>
                  📅 Coverage: {coverStart} → {coverEnd} &nbsp;|&nbsp; Total Logs: <b style={{ color: MON.cyan }}>{fLen.toLocaleString()}</b> &nbsp;|&nbsp; Generated: {new Date(untilMs).toLocaleString()}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10 }}>
                <button type="button" onClick={handleExportPDF} disabled={exportingPdf} style={{ background: exportingPdf ? '#555' : MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: exportingPdf ? 'wait' : 'pointer', opacity: exportingPdf ? 0.7 : 1 }}>
                  {exportingPdf ? '⏳ Fetching...' : '🖨 Export PDF'}
                </button>
                <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
                  📥 Export CSV
                </button>
              </div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
              {[
                { label: 'Total Logs', val: fLen.toLocaleString(), color: MON.cyan, icon: '📋' },
                { label: 'Critical + High', val: (bySev.critical + bySev.high).toLocaleString(), color: MON.red, icon: '🚨' },
                { label: 'Medium Alerts', val: bySev.medium.toLocaleString(), color: MON.orange, icon: '⚠️' },
                { label: 'Low / Info', val: bySev.low.toLocaleString(), color: MON.green, icon: '✅' },
              ].map(c => (
                <div key={c.label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '14px 16px' }}>
                  <div style={{ fontSize: 9, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', marginBottom: 6 }}>{c.icon} {c.label}</div>
                  <div style={{ fontSize: 26, fontWeight: 900, color: c.color, lineHeight: 1 }}>{c.val}</div>
                  <div style={{ fontSize: 9, color: MON.muted, marginTop: 4 }}>{periodLabel}</div>
                </div>
              ))}
            </div>

            <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 11, fontWeight: 800, color: MON.text, marginBottom: 10 }}>📊 Severity Breakdown — {periodLabel}</div>
              <div style={{ display: 'flex', height: 28, borderRadius: 6, overflow: 'hidden', gap: 2 }}>
                {[['Critical', '#ef4444', bySev.critical], ['High', '#f97316', bySev.high], ['Medium', '#eab308', bySev.medium], ['Low', '#22c55e', bySev.low]].map(([l, c, v]) => {
                  const pct = fLen > 0 ? Math.max(v / fLen * 100, v > 0 ? 2 : 0) : 25;
                  return v > 0 ? <div key={l} title={`${l}: ${v}`} style={{ width: `${pct}%`, background: c, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 9, color: '#000', fontWeight: 800 }}>{pct > 8 ? v : ''}</div> : null;
                })}
              </div>
              <div style={{ display: 'flex', gap: 16, marginTop: 8 }}>
                {[['Critical', '#ef4444', bySev.critical], ['High', '#f97316', bySev.high], ['Medium', '#eab308', bySev.medium], ['Low', '#22c55e', bySev.low]].map(([l, c, v]) => (
                  <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <div style={{ width: 10, height: 10, borderRadius: 2, background: c }} />
                    <span style={{ fontSize: 10, color: MON.muted }}>{l}: <b style={{ color: c }}>{v}</b></span>
                  </div>
                ))}
              </div>
            </div>


          </div>
        );
      })()}

    </div>
  );
}

function ProcessOverviewDashboard({ alerts = [], systems = [] }) {
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };

  // The parent API already returns the canonical rolling 24-hour window.
  const rows = alerts;
  const displayTotal = rows.length;
  const pct = value => Math.round((value / Math.max(displayTotal, 1)) * 100);

  const rawSev = rows.reduce((acc, r) => {
    const s = alertSeverity(r).toLowerCase();
    if (acc[s] !== undefined) acc[s]++; else acc.low++;
    return acc;
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  const rawOs = rows.reduce((acc, r) => {
    const os = processOs(r);
    if (acc[os] !== undefined) acc[os]++; else acc.Other++;
    return acc;
  }, { Windows: 0, Linux: 0, macOS: 0, Other: 0 });

  const taggedCount = tags => rows.filter(row => processClassifications(row).some(tag => tags.includes(tag))).length;

  // A generic status such as "open" describes alert triage, not a newly
  // started process. Count only lifecycle events that prove a process start.
  const rawNew = rows.filter(r => processReportCategory(r) === 'started').length;
  const rawRunning = rows.filter(r => /running|sleeping|idle/i.test(String(r.processStatus || r.rawEvent?.process_status || ''))).length;
  const rawTerminated = rows.filter(r => /^(PROC_TERMINATED|PROC_TERMINATE_REQUESTED)$/i.test(String(r.ruleId || ''))).length;
  const rawHighRisk = rawSev.critical + rawSev.high;
  const rawSuspicious = rawSev.critical + rawSev.high + rawSev.medium;

  const newProcessesCount = rawNew;
  const activeRunningCount = rawRunning;
  const terminatedCount = rawTerminated;
  const highRiskCount = rawHighRisk;
  const suspiciousCount = rawSuspicious;
  const statusStoppedCount = terminatedCount;

  const winServersCount = rawOs.Windows;
  const linServersCount = rawOs.Linux;
  const webServersCount = rows.filter(row => processClassifications(row).includes('web_server') || ['apache', 'nginx', 'iis', 'tomcat', 'application_server'].includes(String(processEvidence(row, 'workloadType', 'workload_type') || ''))).length;
  const dbServersCount = rows.filter(row => processClassifications(row).includes('database') || ['mysql', 'mssql', 'postgresql', 'oracle', 'mongodb', 'redis'].includes(String(processEvidence(row, 'workloadType', 'workload_type') || ''))).length;
  const dcServersCount = taggedCount(['active_directory']);

  const serverRows = [
    ['Windows Servers', winServersCount, MON.blue],
    ['Linux Servers', linServersCount, MON.green],
    ['Web Servers', webServersCount, MON.red],
    ['Database Servers', dbServersCount, MON.purple],
    ['Domain Controllers', dcServersCount, MON.yellow],
  ];

  const uniqueProcesses = topCounts(rows, processName, 10000).length;
  const topSuspicious = topCounts(rows.filter(r => ['medium', 'high', 'critical'].includes(alertSeverity(r)) || containsAny(r, ['suspicious', 'encoded', 'malicious', 'injection'])), processName, 6);
  const recentAlerts = rows.slice(0, 5);
  const liveSystems = systems.filter(system => {
    const status = String(system.status || '').toLowerCase();
    return system.isOnline === true || system.agentOk === true || ['active', 'online', 'reporting'].includes(status);
  });
  const endpointCounts = liveSystems.map(system => {
    const count = rows.filter(row => findSystemForProcessLog(row, [system])).length;
    return [system.hostname || system.name || system.agentName || 'unknown', count];
  }).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const topExecutables = topCounts(rows, processName, 5);
  const scriptRows = [
    ['PowerShell', taggedCount(['powershell']), MON.blue],
    ['CMD / Shell', taggedCount(['command_shell']), MON.green],
    ['Python', taggedCount(['python']), MON.purple],
    ['Java', taggedCount(['java']), MON.orange],
    ['VBScript / JScript', taggedCount(['vbscript_javascript']), MON.yellow],
  ];
  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);
  const processTypeRows = [
    ['Privileged', taggedCount(['privileged_user']), MON.blue],
    ['User Context', rows.filter(r => !['root', 'system', 'nt authority\\system', 'unknown'].includes(alertUser(r).toLowerCase())).length, MON.green],
    ['Services', taggedCount(['service']), MON.orange],
  ];
  const processTypeTotal = processTypeRows.reduce((sum, row) => sum + row[1], 0);
  const countRules = pattern => rows.filter(row => pattern.test(String(row.ruleId || ''))).length;
  const latestSensorHealth = rows.find(row => String(row.ruleId || '') === 'PROC_TELEMETRY_HEALTH');
  const heartbeatSensor = systems.map(system => system.advancedProcessSensorStatus).find(status => status?.sysmonInstalled)
    || systems.map(system => system.advancedProcessSensorStatus).find(Boolean) || {};
  const sensorStatus = processEvidence(latestSensorHealth, 'sensorStatus', 'sensor_status') || heartbeatSensor;
  const sysmonReady = Boolean(sensorStatus.sysmon ?? sensorStatus.sysmonConfigured);
  const advancedCoverage = [
    { label: 'DLL Injection', value: countRules(/^PROC_(?:DLL_INJECTION|SUSPICIOUS_DLL_LOAD)$/i), ready: sysmonReady, source: 'Sysmon 7/8' },
    { label: 'Process Hollowing', value: countRules(/^PROC_HOLLOWING$/i), ready: sysmonReady, source: 'Sysmon 25' },
    { label: 'Kernel Process Access', value: countRules(/^PROC_(?:REMOTE_THREAD_INJECTION|KERNEL_PROCESS_ACCESS)$/i), ready: sysmonReady, source: 'Sysmon 8/10' },
    { label: 'Process DNS', value: countRules(/^PROC_DNS_(?:QUERY|ATTRIBUTED)$/i), ready: sysmonReady || countRules(/^PROC_DNS_ATTRIBUTED$/i) > 0, source: sysmonReady ? 'Exact' : 'Correlated' },
    { label: 'Services / Tasks / Startup', value: countRules(/^PROC_(?:ASSET_|SERVICE_|SCHEDULED_TASK_|STARTUP_)/i), ready: true, source: 'Native inventory' },
    { label: 'Application / Database', value: countRules(/^PROC_(?:WORKLOAD_|WEB_ATTACK_ACTIVITY|DATABASE_SECURITY_ACTIVITY|APPLICATION_ERROR_ACTIVITY)/i), ready: true, source: 'Process + logs' },
    { label: 'Containers / Kubernetes', value: countRules(/^PROC_CONTAINER_/i), ready: rows.some(row => processEvidence(row, 'runtimeType', 'runtime_type')), source: 'Runtime API' },
  ];

  const donut = (segments, center, sub = 'Total') => (
    <div style={{ width: 118, height: 118, borderRadius: '50%', background: `conic-gradient(${segments.map(s => `${s.color} ${s.from}% ${s.to}%`).join(', ')})`, display: 'grid', placeItems: 'center', boxShadow: '0 0 25px rgba(0,0,0,0.25)' }}>
      <div style={{ width: 70, height: 70, borderRadius: '50%', background: '#071522', display: 'grid', placeItems: 'center', textAlign: 'center', border: '1px solid #173252' }}>
        <div>
          <div style={{ fontSize: 16, color: '#fff', fontWeight: 900 }}>{center}</div>
          <div style={{ fontSize: 8, color: MON.muted }}>{sub}</div>
        </div>
      </div>
    </div>
  );

  const summaryCards = [
    { title: 'Total Process Events (24h)', value: displayTotal.toLocaleString(), delta: 'live 24h process logs', color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'New Process Events (24h)', value: newProcessesCount.toLocaleString(), delta: `${uniqueProcesses} unique executables`, color: MON.green, bg: 'linear-gradient(135deg,#0b6b3a,#0b2d26)' },
    { title: 'Killed Processes', value: terminatedCount.toLocaleString(), delta: 'terminated / isolated', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'High Risk Processes', value: highRiskCount.toLocaleString(), delta: 'critical + high alerts', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Suspicious Alerts', value: suspiciousCount.toLocaleString(), delta: 'anomaly & behavioral alerts', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
  ];

  const critCount = rawSev.critical;
  const highCount = rawSev.high;
  const medCount = rawSev.medium;
  const lowCount = Math.max(0, displayTotal - critCount - highCount - medCount);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10, background: '#06111f', border: `1px solid ${MON.border}`, borderRadius: 10, padding: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'flex-end', color: MON.green, fontSize: 9, fontWeight: 800 }}>● Auto Refresh: On</div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0,1fr))', gap: 10 }}>
        {summaryCards.map(card => (
          <div key={card.title} style={{ background: card.bg, border: `1px solid ${card.color}55`, borderRadius: 7, padding: 14, minHeight: 86, position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: 9, color: '#dbeafe', fontWeight: 900, textTransform: 'uppercase' }}>{card.title}</div>
            <div style={{ marginTop: 8, fontSize: 24, color: '#fff', fontWeight: 900 }}>{card.value}</div>
            <div style={{ marginTop: 7, fontSize: 9, color: card.color }}>↗ {card.delta}</div>
            <div style={{ position: 'absolute', right: 8, bottom: 8, width: 70, opacity: 0.9 }}><MiniSparkline data={timeline} color={card.color} height={26} /></div>
          </div>
        ))}
      </div>

      <div style={panel}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
          <b style={{ fontSize: 12 }}>Advanced Process Telemetry Coverage</b>
          <span style={{ color: sensorStatus.sysmon ? MON.green : MON.yellow, fontSize: 9, fontWeight: 900 }}>
            {sensorStatus.sysmon ? '● SYSMON KERNEL TELEMETRY ACTIVE' : '● SYSMON STATUS NOT REPORTED / DEGRADED'}
          </span>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(120px, 1fr))', gap: 8 }}>
          {advancedCoverage.map(item => (
            <div key={item.label} style={{ background: MON.card2, border: `1px solid ${item.ready ? MON.green : MON.yellow}44`, borderRadius: 7, padding: 10 }}>
              <div style={{ color: MON.muted, fontSize: 9, minHeight: 24 }}>{item.label}</div>
              <div style={{ color: item.value ? MON.red : MON.text, fontSize: 20, fontWeight: 900 }}>{item.value}</div>
              <div style={{ color: item.ready ? MON.green : MON.yellow, fontSize: 8, fontWeight: 800 }}>{item.ready ? 'READY' : 'DEGRADED'} · {item.source}</div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1.05fr 1.05fr 1.2fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12 }}>Process Status</b>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 12 }}>
            {donut([
              { color: MON.green, from: 0, to: pct(activeRunningCount) },
              { color: MON.blue, from: pct(activeRunningCount), to: pct(activeRunningCount + statusStoppedCount) },
              { color: MON.red, from: pct(activeRunningCount + statusStoppedCount), to: 100 },
            ], displayTotal.toLocaleString())}
            <div style={{ flex: 1, display: 'grid', gap: 8, fontSize: 10 }}>
              {[['Running', activeRunningCount, MON.green], ['Stopped', statusStoppedCount, MON.blue], ['Suspicious', suspiciousCount, MON.red]].map(([label, value, color]) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}><span><span style={{ color }}>●</span> {label}</span><b>{shortNum(value)}</b></div>
              ))}
            </div>
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12 }}>Process Types</b>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 12 }}>
            {donut([
              { color: MON.blue, from: 0, to: Math.round((processTypeRows[0][1] / Math.max(processTypeTotal, 1)) * 100) },
              { color: MON.green, from: Math.round((processTypeRows[0][1] / Math.max(processTypeTotal, 1)) * 100), to: Math.round(((processTypeRows[0][1] + processTypeRows[1][1]) / Math.max(processTypeTotal, 1)) * 100) },
              { color: MON.orange, from: Math.round(((processTypeRows[0][1] + processTypeRows[1][1]) / Math.max(processTypeTotal, 1)) * 100), to: 100 },
            ], uniqueProcesses.toLocaleString(), 'Types')}
            <div style={{ flex: 1, display: 'grid', gap: 8, fontSize: 10 }}>
              {processTypeRows.map(([label, value, color]) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}><span><span style={{ color }}>●</span> {label}</span><b>{shortNum(value)}</b></div>
              ))}
            </div>
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12 }}>Risk Distribution</b>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginTop: 12 }}>
            {donut([
              { color: MON.red, from: 0, to: pct(critCount) },
              { color: MON.orange, from: pct(critCount), to: pct(critCount + highCount) },
              { color: MON.yellow, from: pct(critCount + highCount), to: pct(critCount + highCount + medCount) },
              { color: MON.green, from: pct(critCount + highCount + medCount), to: 100 },
            ], highRiskCount.toLocaleString(), 'Risk')}
            <div style={{ flex: 1, display: 'grid', gap: 7, fontSize: 10 }}>
              {[['Critical', critCount, MON.red], ['High', highCount, MON.orange], ['Medium', medCount, MON.yellow], ['Low', lowCount, MON.green]].map(([label, value, color]) => (
                <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}><span><span style={{ color }}>●</span> {label}</span><b>{shortNum(value)}</b></div>
              ))}
            </div>
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>Top Suspicious Processes</b>
          <div style={{ display: 'grid', gap: 7 }}>
            {!(topSuspicious.length || topExecutables.length) ? (
              <span style={{ color: MON.muted, fontSize: 11 }}>No suspicious processes detected.</span>
            ) : (topSuspicious.length ? topSuspicious : topExecutables).slice(0, 6).map(([name, count], idx) => (
              <div key={name} style={{ display: 'grid', gridTemplateColumns: '20px 1fr 34px', alignItems: 'center', gap: 8, fontSize: 10 }}>
                <span style={{ width: 18, height: 18, borderRadius: 4, background: '#13375a', display: 'grid', placeItems: 'center' }}>{['▣', '⌁', '◫', '◇', '●', '▸'][idx]}</span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{name}</span>
                <b style={{ background: '#6f1d1d', color: '#fff', borderRadius: 4, textAlign: 'center', padding: '2px 0' }}>{count}</b>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.35fr 0.95fr 1.25fr 0.95fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12 }}>Process Activity Over Time</b>
          <div style={{ height: 132, display: 'flex', alignItems: 'flex-end', gap: 5, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(5, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.blue}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>Process Tree (Live)</b>
          <div style={{ fontSize: 10, display: 'grid', gap: 7, fontFamily: 'monospace' }}>
            {(topExecutables.length ? topExecutables : [['No process data', 0]]).slice(0, 5).map(([name, count], idx) => (
              <div key={name} style={{ paddingLeft: idx * 10, color: idx > 2 ? MON.red : MON.text }}>└─ {name} <span style={{ color: MON.muted }}>({count})</span></div>
            ))}
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12 }}>Network Activity by Processes</b>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px', gap: 12, alignItems: 'center', marginTop: 12 }}>
            <div style={{ fontSize: 10, display: 'grid', gap: 7 }}>
              <div>Total Connections<br /><b style={{ color: MON.blue, fontSize: 16 }}>{shortNum(rows.reduce((sum, row) => sum + processMetric(row, 'processNetworkConnectionCount', 'network_connection_count'), 0))}</b></div>
              <div>External Connections<br /><b style={{ color: MON.red, fontSize: 16 }}>{shortNum(rows.reduce((sum, row) => sum + processMetric(row, 'processExternalConnectionCount', 'external_connection_count'), 0))}</b></div>
              <div>Per-process DNS<br /><b style={{ color: countRules(/^PROC_DNS_(?:QUERY|ATTRIBUTED)$/i) ? MON.green : MON.muted, fontSize: 12 }}>{shortNum(countRules(/^PROC_DNS_(?:QUERY|ATTRIBUTED)$/i))} events</b></div>
            </div>
            <div style={{ width: 90, height: 90, borderRadius: '50%', background: 'radial-gradient(circle at 30% 40%, #1d4ed8 0 2px, transparent 3px), radial-gradient(circle at 70% 55%, #ef4444 0 3px, transparent 4px), radial-gradient(circle at 45% 70%, #38bdf8 0 2px, transparent 3px), linear-gradient(135deg,#071827,#0b2740)', border: `1px solid ${MON.border}`, position: 'relative', flexShrink: 0 }}>
              <div style={{ position: 'absolute', inset: 12, border: `1px dashed ${MON.blue}55`, borderRadius: '50%' }} />
              <div style={{ position: 'absolute', left: '50%', top: '50%', width: 40, height: 1.5, background: MON.red, transform: 'rotate(-45deg)', transformOrigin: 'left' }} />
            </div>
          </div>
        </div>

        <div style={panel}>
          <b style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>Recent Alerts</b>
          <div style={{ display: 'grid', gap: 8, fontSize: 10 }}>
            {(recentAlerts.length ? recentAlerts : []).map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '10px 1fr auto', gap: 7, alignItems: 'center' }}>
                <span style={{ width: 8, height: 8, borderRadius: '50%', background: SEV_COLOR[alertSeverity(row)] || MON.green }} />
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{processName(row)} — {row.description || row.type || 'Process event'}</span>
                <span style={{ color: MON.muted }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
              </div>
            ))}
            {!recentAlerts.length && <span style={{ color: MON.muted }}>No recent process alerts returned.</span>}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12 }}>Resource Usage (Top 5 Processes)</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 12, fontSize: 10 }}>
            {rows.slice().sort((a, b) => (cpuValue(b) || 0) - (cpuValue(a) || 0)).slice(0, 5).map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 80px 40px', gap: 8, alignItems: 'center' }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }} title={processName(row)}>{processName(row)}</span>
                <span style={{ height: 6, background: '#10263b', borderRadius: 99, overflow: 'hidden' }}><span style={{ display: 'block', height: '100%', width: `${Math.min(cpuValue(row) || 0, 100)}%`, background: MON.blue }} /></span>
                <b>{(() => {
                  const val = cpuValue(row);
                  return Number.isFinite(val) ? `${val.toFixed(val % 1 ? 1 : 0)}%` : '0%';
                })()}</b>
              </div>
            ))}
          </div>
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12, display: 'block', marginBottom: 8 }}>Top Endpoints by Process Count</b>
          <div style={{ display: 'grid', gap: 8, fontSize: 10 }}>
            {(endpointCounts.length ? endpointCounts : [['No endpoint data', 0]]).map(([host, count]) => (
              <div key={host} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) 50px', gap: 8 }}>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }} title={host}>{host}</span>
                <b style={{ color: MON.cyan }}>{shortNum(count)}</b>
              </div>
            ))}
          </div>
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12 }}>Server Process Overview</b>
          <div style={{ display: 'grid', gap: 8, marginTop: 10, fontSize: 10 }}>
            {serverRows.map(([label, value, color]) => (
              <div key={label} style={{ display: 'grid', gridTemplateColumns: '22px 1fr 38px', alignItems: 'center' }}><span style={{ color }}>▦</span><span>{label}</span><b style={{ color, textAlign: 'right' }}>{shortNum(value)}</b></div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`ProcessActivityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export default function ProcessActivityDashboard({ alerts = [], loading = false, total = 0, onAction }) {
  const telemetryRows = useMemo(() => {
    const sourceRows = Array.isArray(alerts) ? alerts : [];
    const inventory = summaryInventoryRows(sourceRows);
    const events = sourceRows.filter(row => row?.ruleId !== 'PROC_INVENTORY_SUMMARY');
    return [...inventory, ...events];
  }, [alerts]);
  const [activeTab, setActiveTab] = useState('dashboard');
  const [systems, setSystems] = useState([]);

  useEffect(() => {
    let active = true;
    api.get('/system')
      .then(r => {
        if (!active) return;
        const rows = r.data?.systems || r.data?.agents || r.data || [];
        setSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setSystems([]); });
    return () => { active = false; };
  }, []);

  const rows = telemetryRows;
  const totalRows = rows.length;
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});
  const osCounts = rows.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});
  const linuxSignalsCount = osCounts.Linux || 0;
  const windowsSignalsCount = osCounts.Windows || 0;
  const macosSignalsCount = osCounts.macOS || 0;
  const suspicious = rows.filter(r => ['medium', 'high', 'critical'].includes(alertSeverity(r)) || /suspicious|encoded|powershell|lolbin|yara|vt|malicious|unauthorized|injection/i.test(`${r.ruleId || ''} ${r.type || ''} ${r.description || ''} ${r.action || ''}`)).length;
  const highRisk = rows.filter(r => ['high', 'critical'].includes(alertSeverity(r)) || /high|critical|malicious|exploit|injection|mimikatz|unauthorized/i.test(`${r.ruleId || ''} ${r.type || ''} ${r.description || ''}`)).length;
  const terminated = rows.filter(r => /^(PROC_TERMINATED|PROC_TERMINATE_REQUESTED)$/i.test(String(r.ruleId || ''))).length;
  const uniqueProcesses = topCounts(rows, processName, 10000).length;
  const highCpu = rows.filter(r => /^PROC_HIGH_CPU$/i.test(String(r.ruleId || ''))).length;
  const highMem = rows.filter(r => /^(PROC_HIGH_MEMORY|EDR_HIGH_MEMORY)$/i.test(String(r.ruleId || ''))).length;
  const highDisk = rows.filter(r => /^PROC_HIGH_DISK_IO$/i.test(String(r.ruleId || ''))).length;
  const timeline = buildBuckets(rows, 8, 24);
  const taggedCount = tags => rows.filter(row => processClassifications(row).some(tag => tags.includes(tag))).length;
  const ruleCount = pattern => rows.filter(row => pattern.test(String(row.ruleId || ''))).length;
  const scriptSignals = taggedCount(['powershell', 'command_shell', 'python', 'java', 'vbscript_javascript', 'scheduled_task']);
  const serverDb = rows.filter(row => processClassifications(row).some(tag => ['web_server', 'database', 'active_directory', 'container_cloud'].includes(tag)) || processEvidence(row, 'workloadType', 'workload_type') || processEvidence(row, 'runtimeType', 'runtime_type')).length;
  const encodedPowerShell = taggedCount(['encoded_command']);

  // Generate KPI cards from real process telemetry only.
  const kpis = [
    { label: 'Total Process Signals', val: totalRows.toLocaleString(), trend: 'LIVE API', color: MON.blue, data: timeline },
    { label: 'Unique Process Names', val: shortNum(uniqueProcesses), trend: 'Observed', color: MON.green, data: timeline },
    { label: 'Suspicious Executions', val: shortNum(suspicious), trend: 'Evidence', color: MON.yellow, data: timeline },
    { label: 'High / Critical Detections', val: shortNum(highRisk), trend: 'Alert', color: MON.red, data: timeline },
    { label: 'Terminated / Isolated', val: shortNum(terminated), trend: 'Enforced', color: MON.purple, data: timeline },
    { label: 'Windows Signals', val: shortNum(windowsSignalsCount), trend: processOs({ os: 'Windows' }), color: MON.cyan, data: timeline },
    { label: 'Linux Signals', val: shortNum(linuxSignalsCount), trend: 'Linux', color: MON.orange, data: timeline },
    { label: 'macOS Signals', val: shortNum(macosSignalsCount), trend: 'macOS', color: MON.purple, data: timeline },
    { label: 'Unknown Platform Signals', val: shortNum(osCounts.Unknown || 0), trend: 'Needs OS field', color: MON.muted, data: timeline },
    { label: 'Unsigned / Untrusted Executables', val: shortNum(ruleCount(/^PROC_(?:UNSIGNED|UNTRUSTED|UNKNOWN|MODIFIED_PACKAGE)_EXECUTABLE$/i)), trend: 'Trust check', color: MON.red, data: timeline },
    { label: 'Encoded PowerShell Executions', val: shortNum(encodedPowerShell), trend: 'Agent tag', color: MON.yellow, data: timeline },
    { label: 'Script & Task Signals', val: shortNum(scriptSignals), trend: 'Agent tag', color: MON.purple, data: timeline },
    { label: 'Server / DB / Containers', val: shortNum(serverDb), trend: 'Agent tag', color: MON.green, data: timeline },
    { label: 'High CPU Abusers (>80%)', val: shortNum(highCpu), trend: 'CPU Field', color: MON.red, data: timeline },
    { label: 'High Memory Abusers', val: shortNum(highMem), trend: 'Memory Field', color: MON.orange, data: timeline },
    { label: 'High Disk I/O Abusers', val: shortNum(highDisk), trend: 'I/O rate', color: MON.orange, data: timeline },
    { label: 'Privilege Escalation Attempts', val: shortNum(ruleCount(/^PROC_PRIVILEGE_ESCALATION$/i)), trend: 'Rule match', color: MON.red, data: timeline },
    { label: 'Process Injection Evidence', val: shortNum(ruleCount(/^(MEM_RWX_REGION|MEM_INJECTION_CMDLINE|PROC_DLL_INJECTION|PROC_REMOTE_THREAD_INJECTION|PROC_KERNEL_PROCESS_ACCESS)$/i)), trend: 'Sysmon / memory', color: MON.red, data: timeline },
    { label: 'Process Hollowing', val: shortNum(ruleCount(/^PROC_HOLLOWING$/i)), trend: 'Sysmon Event 25', color: MON.red, data: timeline },
    { label: 'DLL Load / Injection', val: shortNum(ruleCount(/^PROC_(?:SUSPICIOUS_DLL_LOAD|DLL_INJECTION)$/i)), trend: 'Sysmon Event 7/8', color: MON.orange, data: timeline },
    { label: 'Per-process DNS', val: shortNum(ruleCount(/^PROC_DNS_(?:QUERY|ATTRIBUTED)$/i)), trend: 'Exact / correlated', color: MON.cyan, data: timeline },
    { label: 'Inventory Changes', val: shortNum(ruleCount(/^PROC_(?:ASSET_|SERVICE_|SCHEDULED_TASK_|STARTUP_)/i)), trend: 'Service / task / startup', color: MON.yellow, data: timeline },
    { label: 'Container Security', val: shortNum(ruleCount(/^PROC_CONTAINER_/i)), trend: 'Docker / Podman / K8s', color: MON.purple, data: timeline },
    { label: 'Fileless Execution', val: shortNum(ruleCount(/^MEM_FILELESS_EXEC$/i)), trend: 'Memory evidence', color: MON.purple, data: timeline },
    { label: 'Ransomware / Cred Dumping', val: shortNum(ruleCount(/^(RANSOMWARE_|MEM_CRED_DUMP|MEM_LSASS_ACCESS)/i)), trend: 'Rule match', color: MON.red, data: timeline },
    { label: 'Remote Access Tools', val: shortNum(taggedCount(['remote_access', 'ssh', 'rdp'])), trend: 'Agent tag', color: MON.orange, data: timeline },
    { label: 'Process Network Threats', val: shortNum(ruleCount(/^(PROC_INTERNAL_NETWORK_SCAN|PROC_SECURITY_TOOL_TAMPER)$/i)), trend: 'Rule match', color: MON.red, data: timeline },
  ];

  const agentStatusRows = systems.filter(sys => {
    const status = String(sys.status || '').toLowerCase();
    return sys.isOnline === true || sys.agentOk === true || ['active', 'online', 'reporting'].includes(status);
  }).map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const scriptEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host) && containsAny(r, ['script', 'powershell', 'bash', 'python', 'cmd'])).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'unknown'),
      monitor: sys.processMonitorEnabled !== false,
      advancedMonitor: sys.advancedProcessMonitorEnabled !== false,
      containerMonitor: sys.containerMonitorEnabled !== false,
      sensorStatus: sys.advancedProcessSensorStatus || {},
      events: hostEvents,
      scripts: scriptEvents,
      cpuRam: formatCpuRam(sys),
      threats,
      lastSeen: sys.lastSeen || null,
    });
  });

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
        {activeTab === 'log-monitor' ? (
          <CapabilityLogsPanel capabilityId={1}>
            <ProcessLogMonitor alerts={telemetryRows} systems={systems} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <ProcessReportsTab alerts={telemetryRows} total={total || telemetryRows.length} />
        ) : activeTab === 'dashboard' ? (
          <ProcessOverviewDashboard alerts={telemetryRows} systems={systems} />
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Level Process Activity Monitoring</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} backend agents · 30s refresh</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 92px 76px 76px 110px 80px 120px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent</span><span>Hostname</span><span>Status</span><span>Core / Advanced</span><span>Events</span><span>Scripts</span><span>CPU / RAM</span><span>Threats</span><span>Last Seen</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 92px 76px 76px 110px 80px 120px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <b style={{ color: MON.green, textTransform: 'uppercase' }}>{row.status}</b>
                  <span title={`Sysmon: ${row.sensorStatus?.sysmonInstalled ? 'active' : 'not reported'}; containers: ${row.containerMonitor ? 'enabled' : 'disabled'}`} style={{ color: row.monitor && row.advancedMonitor ? MON.green : MON.orange }}>{row.monitor ? 'On' : 'Off'} / {row.advancedMonitor ? 'On' : 'Off'}</span>
                  <b>{row.events}</b><b>{row.scripts}</b><span>{row.cpuRam}</span>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Not reported'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No agents returned by backend.
                </div>
              )}
            </div>

            {/* 3 Bottom Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Process Activity Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} process signals`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔌 Top Monitored Executables</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(topCounts(rows, processName, 5).length ? topCounts(rows, processName, 5) : [['No process data', 0]]).map(([dev, count], index) => (
                    <div key={dev} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{dev}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Process Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['System & Shell', taggedCount(['service', 'command_shell', 'powershell'])],
                    ['Server & DB', serverDb],
                    ['Scripts & Automation', scriptSignals],
                    ['Security & Threats', suspicious],
                  ].map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.cyan, MON.blue, MON.purple, MON.red][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`ProcessActivityMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export function ProcessActivityMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '1';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ period: 'daily', category: 'all' });
      const r = await api.get(`/dashboard/process-activity/report?${q}`, { skipCache: quiet });
      const next = r.data?.alerts || [];
      setAlerts(next);
      setTotal(Number.isFinite(Number(r.data?.total)) ? Number(r.data.total) : next.length);
    } catch {
      setAlerts([]);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 30000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const refreshBuffer = createEventBuffer(() => loadAlerts(true), 3000);
    socket.on('connect', join);
    socket.on('alert:new', refreshBuffer.add);
    socket.on('process:event', refreshBuffer.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', refreshBuffer.add);
      socket.off('process:event', refreshBuffer.add);
      refreshBuffer.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 1. Process Activity Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <ProcessActivityDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <ProcessActivityMonitoringPage />;
}

export function ProcessSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/?capabilityId=1" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Process Monitoring SubTab - {tab}</h3>
        <button type="button" onClick={() => navigate('/')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="process" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <ProcessActivityDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Re-export Primitives ─────────────────────────────────────────────────────
export {
  ProcessActivityDashboardPanel,
  summaryInventoryRows,
  procName,
  procMem,
  SEV,
  SEVBG,
  RISK,
  VtBadge,
  vtIsThreaten,
  processStatusSafe,
  processStatusStyle,
  createEventBuffer,
  shortNum,
  normHost,
  processName,
  processOs,
  recordId,
  isVelociraptorClientId,
  systemVelociraptorClientId,
  csvCell,
  downloadBlob,
  createTablePdf,
};
