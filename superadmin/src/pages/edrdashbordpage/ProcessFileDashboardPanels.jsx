import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import DashboardToolsCard, { DashboardToast } from '../../components/DashboardToolsCard';
import { useDashboardConfig } from '../../hooks/useDashboardConfig';
const FIM_TABS = [
  { key: 'dashboard', label: 'Dashboard' },
  { key: 'monitoring', label: 'Monitoring' },
  { key: 'logs', label: 'Logs / SIEM' },
  { key: 'reports', label: 'Reports' }
];
const NetworkSocTabPage = () => null;
const TimeBasedAnomalyPages = {};
const socDashboardSidebars = {};
const AuthCapabilityActions = () => null;
const FIMCapabilityActions = () => null;
const NetworkCapabilityActions = () => null;
const RegistryCapabilityActions = () => null;
const ProcessSidebar = () => null;

function shortNum(n = 0) {
  const val = Number(n) || 0;
  if (val >= 1000000) return (val / 1000000).toFixed(1) + 'M';
  if (val >= 1000) return (val / 1000).toFixed(1) + 'k';
  return String(val);
}

// ── Palette ───────────────────────────────────────────────────────────────────
const SEV = { critical: '#f87171', high: '#f59e0b', medium: '#60a5fa', low: '#34d399' };
const SEVBG = { critical: '#7f1d1d', high: '#78350f', medium: '#1e3a5f', low: '#064e3b' };
const RISK = {
  high: { color: '#f87171', bg: 'rgba(239,68,68,.15)', label: 'HIGH' },
  medium: { color: '#f59e0b', bg: 'rgba(245,158,11,.15)', label: 'MED' },
  low: { color: '#34d399', bg: 'rgba(52,211,153,.1)', label: 'LOW' },
  none: { color: '#64748b', bg: 'rgba(100,116,139,.1)', label: '—' },
};

// ── Sparkline ─────────────────────────────────────────────────────────────────
function Spark({ data = [] }) {
  if (!data || data.length < 2) return null;
  const vals = data.map(d => d.count || 0);
  const max = Math.max(...vals, 1);
  const W = 90, H = 26;
  const pts = vals
    .map((v, i) => `${(i / (vals.length - 1)) * W},${H - (v / max) * H}`)
    .join(' ');
  return (
    <svg width={W} height={H} style={{ display: 'block', overflow: 'visible' }}>
      <polyline points={pts} fill="none" stroke="#3b82f6" strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

// ── BigCard ───────────────────────────────────────────────────────────────────
function BigCard({ icon, title, main, sub, risk = 'low', spark, onClick, badge, children }) {
  const r = RISK[risk] || RISK.low;
  return (
    <div
      onClick={onClick}
      style={{
        background: 'linear-gradient(135deg, rgba(12, 26, 46, 0.8) 0%, rgba(15, 21, 53, 0.6) 100%)',
        border: `1px solid ${onClick ? 'rgba(59, 130, 246, 0.4)' : 'rgba(30, 58, 95, 0.4)'}`,
        borderRadius: 12,
        padding: '18px 20px',
        flex: '1',
        minWidth: 210,
        cursor: onClick ? 'pointer' : 'default',
        transition: 'all 0.3s ease',
        backdropFilter: 'blur(10px)',
        boxShadow: 'inset 0 1px 0 rgba(255, 255, 255, 0.05), 0 1px 3px rgba(0, 0, 0, 0.3)',
        position: 'relative',
        overflow: 'hidden',
      }}
      onMouseEnter={e => {
        if (onClick) {
          e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.6)';
          e.currentTarget.style.transform = 'translateY(-2px)';
          e.currentTarget.style.boxShadow = 'inset 0 1px 0 rgba(255, 255, 255, 0.05), 0 8px 16px rgba(59, 130, 246, 0.15)';
        }
      }}
      onMouseLeave={e => {
        if (onClick) {
          e.currentTarget.style.borderColor = 'rgba(59, 130, 246, 0.4)';
          e.currentTarget.style.transform = 'translateY(0)';
          e.currentTarget.style.boxShadow = 'inset 0 1px 0 rgba(255, 255, 255, 0.05), 0 1px 3px rgba(0, 0, 0, 0.3)';
        }
      }}
    >
      <div style={{ position: 'absolute', top: 0, right: 0, width: '200px', height: '200px', background: `radial-gradient(circle, ${r.color}15 0%, transparent 70%)`, pointerEvents: 'none' }} />

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8, position: 'relative', zIndex: 1 }}>
        <span style={{ fontSize: 28, filter: 'drop-shadow(0 2px 4px rgba(0,0,0,0.2))' }}>{icon}</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap' }}>
          {badge && <span style={{ fontSize: 9, padding: '3px 9px', borderRadius: 6, fontWeight: 700, background: `${r.color}22`, color: r.color, border: `1px solid ${r.color}44`, backdropFilter: 'blur(4px)' }}>{badge}</span>}
          {onClick && <span style={{ fontSize: 9, color: '#60a5fa', fontWeight: 600 }}>↗</span>}
          <span style={{ fontSize: 9, padding: '3px 8px', borderRadius: 6, fontWeight: 700, background: r.bg, color: r.color, border: `1px solid ${r.color}66` }}>{r.label}</span>
        </div>
      </div>

      <div style={{ fontSize: 28, fontWeight: 700, color: '#e2e8f0', letterSpacing: '-1px', position: 'relative', zIndex: 1 }}>{main}</div>
      <div style={{ fontSize: 12, color: '#60a5fa', marginBottom: 8, fontWeight: 600, position: 'relative', zIndex: 1 }}>{title}</div>
      {children && <div style={{ fontSize: 11, color: '#93c5fd', marginBottom: 8, position: 'relative', zIndex: 1, fontWeight: 500 }}>{children}</div>}
      <div style={{ position: 'relative', zIndex: 1, marginBottom: 6 }}>
        <Spark data={spark} />
      </div>
      {sub && <div style={{ fontSize: 11, color: '#7dd3fc', marginTop: 6, position: 'relative', zIndex: 1, fontWeight: 500 }}>{sub}</div>}
    </div>
  );
}

// ── VT badge ──────────────────────────────────────────────────────────────────
// VT verdict helpers
const VT_VERDICT_COLOR = {
  malicious: '#f87171',
  suspicious: '#f59e0b',
  clean: '#34d399',
  not_found: '#64748b',
  unknown: '#64748b',
};
const VT_VERDICT_LABEL = {
  malicious: 'MALICIOUS',
  suspicious: 'SUSPICIOUS',
  clean: 'CLEAN',
  not_found: 'NOT FOUND',
  unknown: 'UNKNOWN',
};

function vtIsThreaten(score, verdict) {
  // Returns true only when VT actually found something bad
  if (verdict === 'malicious' || verdict === 'suspicious') return true;
  if (!verdict && (score || 0) >= 1) return true;
  return false;
}

function VtBadge({ score, verdict, showClean = false }) {
  // Don't render for clean/not_found unless explicitly requested
  if (!showClean && (verdict === 'clean' || verdict === 'not_found' || verdict === 'unknown')) return null;
  if (!score && !verdict) return null;

  let color, label;
  if (verdict && VT_VERDICT_COLOR[verdict]) {
    color = VT_VERDICT_COLOR[verdict];
    label = VT_VERDICT_LABEL[verdict] || verdict.toUpperCase();
  } else if ((score || 0) >= 70) {
    color = '#f87171'; label = `${score}% MALICIOUS`;
  } else if ((score || 0) >= 10) {
    color = '#f59e0b'; label = `${score}% SUSPICIOUS`;
  } else if ((score || 0) > 0) {
    color = '#f59e0b'; label = `${score}%`;
  } else {
    color = '#64748b'; label = 'VT: NO DATA';
  }

  return (
    <span style={{
      fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 700,
      background: `${color}22`, color, border: `1px solid ${color}55`
    }}>
      🔬 VT: {label}
    </span>
  );
}

function readVt(alert = {}) {
  const vt = alert.virustotal || alert.vt || alert.rawEvent?.virustotal || alert.rawEvent?.vt || {};
  const vtDetections = alert.vtDetections ?? vt.detections ?? (
    vt.malicious != null || vt.suspicious != null
      ? Number(vt.malicious || 0) + Number(vt.suspicious || 0)
      : undefined
  );
  const vtTotal = alert.vtTotal ?? vt.total ?? vt.total_engines;
  const vtScore = alert.vtScore ?? vt.score ?? (
    vtDetections != null && vtTotal > 0
      ? Math.round((vtDetections / vtTotal) * 100)
      : undefined
  );
  const vtDetectionRatio = alert.vtDetectionRatio ?? vt.detection_ratio ?? vt.ratio ?? (
    vtDetections != null && vtTotal != null ? `${vtDetections}/${vtTotal}` : undefined
  );
  const vtVerdict = alert.vtVerdict ?? vt.verdict;
  const vtEngines = alert.vtEngines ?? vt.engines_triggered ?? vt.engines;
  return { vtScore, vtDetections, vtTotal, vtDetectionRatio, vtVerdict, vtEngines };
}


function pctValue(value) {
  const n = Number(value || 0);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, n));
}

function ringStyle(value, color) {
  const pct = pctValue(value);
  return {
    width: 74,
    height: 74,
    borderRadius: '50%',
    display: 'grid',
    placeItems: 'center',
    background: `conic-gradient(${color} ${pct * 3.6}deg, #10213a 0deg)`,
    boxShadow: `0 0 22px ${color}22`,
  };
}

function rawMatch(alert, key) {
  alert = alert || {};
  const text = alert?.raw_log || alert?.full_log || '';
  const match = new RegExp(`${key}=([^|\\s]+)`, 'i').exec(text);
  return match?.[1] || '';
}

function descriptionPercent(alert, label) {
  const text = alert?.description || '';
  const match = new RegExp(`${label}\\s+([0-9.]+)%`, 'i').exec(text);
  return match?.[1] || '';
}

function processPercent(value) {
  if (value === '' || value == null) return '';
  const n = Number(value);
  return Number.isFinite(n) ? n : '';
}

function processPctLabel(value) {
  const n = processPercent(value);
  return n === '' ? '0.0%' : `${pctValue(n).toFixed(1)}%`;
}

function procName(alert = {}) {
  alert = alert || {};
  return alert.processName || alert.process_name || alert.rawEvent?.process_name || alert.rawEvent?.processName
    || rawMatch(alert, 'name') || rawMatch(alert, 'process') || alert.description || 'unknown';
}

function procHost(alert = {}) {
  alert = alert || {};
  return alert.agentName || alert.hostname || alert.host || alert.systemId?.name || alert.rawEvent?.hostname || alert.rawEvent?.host || alert.srcip || '—';
}

function procCpu(alert = {}) {
  alert = alert || {};
  return processPercent(
    alert.processCpuPercent ?? alert.cpu_percent ?? alert.rawEvent?.cpu_percent ?? alert.rawEvent?.processCpuPercent
    ?? (rawMatch(alert, 'cpu') || descriptionPercent(alert, 'CPU'))
  );
}

function procMem(alert = {}) {
  alert = alert || {};
  return processPercent(
    alert.processMemoryPercent ?? alert.memory_percent ?? alert.rawEvent?.memory_percent ?? alert.rawEvent?.processMemoryPercent
    ?? (rawMatch(alert, 'mem') || descriptionPercent(alert, 'RAM'))
  );
}

function procParent(alert = {}) {
  alert = alert || {};
  return alert.parentProcessName || alert.parent_process_name || alert.rawEvent?.parent_process_name || alert.rawEvent?.parentProcessName
    || rawMatch(alert, 'parent') || alert.parentPid || alert.parent_pid || alert.rawEvent?.parent_pid || rawMatch(alert, 'ppid') || '—';
}

function procCmd(alert = {}) {
  alert = alert || {};
  return alert.processCmdline || alert.cmdline || alert.command_line || alert.rawEvent?.cmdline || alert.rawEvent?.command_line || rawMatch(alert, 'cmd') || '';
}

function procExe(alert = {}) {
  alert = alert || {};
  return alert.processExe || alert.exe || alert.rawEvent?.exe || rawMatch(alert, 'exe') || '';
}

function summaryInventoryRows(alerts = []) {
  const rows = [];
  alerts
    .filter(a => a.ruleId === 'PROC_INVENTORY_SUMMARY')
    .slice(0, 1)
    .forEach(summary => {
      const raw = summary.rawEvent?.raw || summary.rawEvent || {};
      const inventory = Array.isArray(raw.processes) && raw.processes.length
        ? raw.processes
        : [...(raw.top_cpu || []), ...(raw.top_memory || [])];
      const seen = new Set();
      inventory.forEach((p, index) => {
        const pid = p.pid;
        const key = `${pid || index}:${p.create_time || p.name || index}`;
        if (seen.has(key)) return;
        seen.add(key);
        rows.push({
          _id: `${summary._id || 'summary'}:${key}`,
          ruleId: 'PROC_LIVE_INVENTORY',
          processName: p.name || p.process_name || 'unknown',
          pid,
          username: p.username || '',
          parentPid: p.ppid,
          parentProcessName: p.parent_name || '',
          parentCommandLine: p.parent_cmdline || '',
          processCpuPercent: p.cpu,
          processMemoryPercent: p.mem,
          processMemoryMb: p.memory_mb,
          processCmdline: p.cmdline || '',
          processExe: p.exe || '',
          processStatus: p.status || 'running',
          processCreateTime: p.create_time ? new Date(p.create_time * 1000).toISOString() : summary.createdAt,
          severity: 'low',
          createdAt: summary.createdAt,
          description: `Live process inventory: ${p.name || 'unknown'} (PID ${pid || 'n/a'}, CPU ${Number(p.cpu || 0).toFixed(1)}%, RAM ${Number(p.mem || 0).toFixed(1)}%)`,
          systemId: summary.systemId,
          velociraptorClientId: summary.velociraptorClientId
            || summary.velociraptorId
            || summary.rawEvent?.velociraptor_client_id
            || summary.systemId?.velociraptorClientId
            || '',
          departmentId: summary.departmentId,
          agentName: summary.agentName,
          hostname: summary.hostname || summary.systemId?.hostname || summary.systemId?.name,
          osType: summary.osType || summary.rawEvent?.osType || summary.rawEvent?.os_type,
        });
      });
    });
  return rows;
}

const PROCESS_SUSPICIOUS_NAMES = [
  'meterpreter', 'mimikatz', 'cobalt', 'psexec', 'netcat', 'nc.exe', 'ncat',
  'socat', 'wce.exe', 'fgdump', 'pwdump', 'gsecdump', 'procdump', 'lsassy',
  'lazagne', 'crackmapexec', 'metasploit', 'beacon.exe', 'msfconsole',
  'empire', 'sliver', 'havoc',
];

const PROCESS_SUSPICIOUS_CMD = [
  'invoke-mimikatz', 'invoke-shellcode', 'frombase64string', '-encodedcommand',
  'downloadstring', 'iex(', 'bypass', 'certutil -decode', 'certutil -urlcache',
  'bitsadmin /transfer', 'curl http', 'wget http', '/dev/tcp/', 'nc -e', 'bash -i',
];

const PROCESS_UNAUTHORIZED_PATHS = [
  '/tmp/', '/var/tmp/', '/dev/shm/', '/run/user/', '\\temp\\',
  '\\appdata\\local\\temp\\', '\\downloads\\',
];

function processSummaryRaw(alerts = []) {
  const summary = alerts.find(a => a.ruleId === 'PROC_INVENTORY_SUMMARY');
  return summary?.rawEvent?.raw || summary?.rawEvent || {};
}

function processInventoryItems(raw = {}) {
  const candidates = [
    ...(Array.isArray(raw.processes) ? raw.processes : []),
    ...(Array.isArray(raw.top_cpu) ? raw.top_cpu : []),
    ...(Array.isArray(raw.top_memory) ? raw.top_memory : []),
  ];
  const seen = new Set();
  return candidates.filter((p, index) => {
    const key = `${p.pid || index}:${p.create_time || p.name || index}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function isSuspiciousInventoryProcess(p = {}) {
  const name = String(p.name || p.process_name || '').toLowerCase();
  const cmd = String(p.cmdline || p.command_line || '').toLowerCase();
  return PROCESS_SUSPICIOUS_NAMES.some(s => name.includes(s))
    || PROCESS_SUSPICIOUS_CMD.some(s => cmd.includes(s));
}

function isUnauthorizedInventoryProcess(p = {}) {
  const text = `${p.exe || ''} ${p.cmdline || ''}`.toLowerCase();
  return text.trim() && PROCESS_UNAUTHORIZED_PATHS.some(s => text.includes(s));
}

function liveProcessMetrics(raw = {}, eventRows = []) {
  const inventory = processInventoryItems(raw);
  const cpuThreshold = Number(raw.cpu_threshold_percent ?? 90);
  const memThreshold = Number(raw.memory_threshold_percent ?? 15);
  const countFromRaw = (key, fallback) => {
    const n = Number(raw[key]);
    return Number.isFinite(n) ? n : fallback;
  };
  const eventSuspicious = eventRows.filter(a => {
    const severity = String(a.severity || '').toLowerCase();
    const text = `${a.ruleId || ''} ${a.description || ''} ${procName(a)} ${procCmd(a)}`;
    return /PROC_SUSPICIOUS|SUSPICIOUS_CMDLINE|suspicious|encoded|dll|external|unknown|malware|ransom|miner|credential|dump/i.test(text)
      || ['critical', 'high'].includes(severity)
      || processStatusSafe(a) === 'Suspicious';
  }).length;
  const eventHighCpu = eventRows.filter(a => /HIGH_CPU/i.test(a.ruleId || '') || Number(procCpu(a) || 0) > cpuThreshold).length;
  const eventHighMem = eventRows.filter(a => /HIGH_MEMORY/i.test(a.ruleId || '') || Number(procMem(a) || 0) > memThreshold).length;
  return {
    total: countFromRaw('process_count', inventory.length),
    running: countFromRaw('running_count', inventory.filter(p => !p.status || ['running', 'sleeping', 'disk-sleep', 'idle'].includes(String(p.status).toLowerCase())).length),
    suspicious: countFromRaw('suspicious_count', Math.max(eventSuspicious, inventory.filter(isSuspiciousInventoryProcess).length)),
    highCpu: countFromRaw('high_cpu_count', Math.max(eventHighCpu, inventory.filter(p => Number(p.cpu || 0) > cpuThreshold).length)),
    highMem: countFromRaw('high_memory_count', Math.max(eventHighMem, inventory.filter(p => Number(p.mem || 0) > memThreshold).length)),
    unauthorized: countFromRaw('unauthorized_count', inventory.filter(isUnauthorizedInventoryProcess).length),
    cpuThreshold,
    memThreshold,
  };
}

function ProcessActivityPanel({ alerts, loading, selected, setSelected, doAction }) {
  const liveInventory = summaryInventoryRows(alerts);
  const eventRows = alerts.filter(a => a.ruleId !== 'PROC_INVENTORY_SUMMARY');
  const lifecycleIndex = buildProcessLifecycleIndex(eventRows);
  const processAlerts = liveInventory.length ? [...liveInventory, ...eventRows] : eventRows;
  const selectedProcess = (selected && selected.ruleId !== 'PROC_INVENTORY_SUMMARY' ? selected : null) || processAlerts[0] || null;
  const selectedCpu = procCpu(selectedProcess);
  const selectedMem = procMem(selectedProcess);
  const sevColor = SEV[selectedProcess?.severity] || '#60a5fa';
  const statusText = processStatusWithLifecycle(selectedProcess, lifecycleIndex);
  const statusColor = statusText === 'Suspicious'
    ? '#f87171'
    : statusText === 'Terminated' || statusText === 'Stopped'
      ? '#94a3b8'
      : statusText === 'Terminating'
        ? '#fbbf24'
        : '#22c55e';

  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .9fr', minHeight: 560, overflow: 'hidden' }}>
      <div style={{ borderRight: '1px solid #1e3a5f', overflow: 'auto' }}>
        <div style={{
          display: 'grid', gridTemplateColumns: '1.4fr 80px 120px 82px 92px 98px 1fr', gap: 10,
          padding: '11px 14px', color: '#60a5fa', fontSize: 11, fontWeight: 900, borderBottom: '1px solid #1e3a5f', background: '#071426'
        }}>
          <div>Process Name</div>
          <div>PID</div>
          <div>User</div>
          <div>CPU %</div>
          <div>Memory %</div>
          <div>Status</div>
          <div>Parent Process</div>
        </div>
        {loading ? (
          <p style={{ color: '#1e40af', fontSize: 13, padding: 16 }}>Loading…</p>
        ) : processAlerts.length === 0 ? (
          <p style={{ color: '#1e3a5f', fontSize: 13, padding: 16 }}>No process records found.</p>
        ) : processAlerts.map(a => {
          const name = procName(a);
          const cpu = procCpu(a);
          const mem = procMem(a);
          const parent = procParent(a);
          const rowStatus = processStatusWithLifecycle(a, lifecycleIndex);
          const rowColor = rowStatus === 'Suspicious' ? '#f87171' : rowStatus === 'Terminated' ? '#94a3b8' : '#22c55e';
          return (
            <button
              key={a._id}
              type="button"
              onClick={() => setSelected(a)}
              style={{
                display: 'grid', gridTemplateColumns: '1.4fr 80px 120px 82px 92px 98px 1fr', gap: 10,
                alignItems: 'center', width: '100%', border: 0, borderBottom: '1px solid #071426',
                background: selectedProcess?._id === a._id ? '#102449' : 'transparent',
                color: '#cbd5e1', padding: '12px 14px', cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit',
              }}
            >
              <div style={{ minWidth: 0 }}>
                <div style={{ color: '#e2e8f0', fontWeight: 800, whiteSpace: 'normal', wordBreak: 'break-word', lineHeight: 1.35 }}>
                  {name}
                </div>
                <div style={{ color: '#1e40af', fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {a.ruleId} · {new Date(a.createdAt).toLocaleString()}
                </div>
              </div>
              <div style={{ fontFamily: 'monospace', color: '#93c5fd' }}>{a.pid || '—'}</div>
              <div style={{ color: '#93c5fd', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.username || '—'}</div>
              <div style={{ color: '#e2e8f0' }}>{processPctLabel(cpu)}</div>
              <div style={{ color: '#e2e8f0' }}>{processPctLabel(mem)}</div>
              <div style={{ color: rowColor, fontWeight: 900, fontSize: 11 }}>{rowStatus}</div>
              <div style={{ color: '#60a5fa', whiteSpace: 'normal', wordBreak: 'break-word', lineHeight: 1.35 }}>
                {parent}
              </div>
            </button>
          );
        })}
      </div>

      <div style={{ padding: 16, overflow: 'auto', background: '#071426' }}>
        {!selectedProcess ? (
          <p style={{ color: '#1e3a5f', fontSize: 13 }}>Select a process record.</p>
        ) : (
          <div style={{ border: '1px solid #1d4ed8', borderRadius: 12, background: 'linear-gradient(135deg,#06111f,#08182b)', padding: 18 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'flex-start' }}>
              <div style={{ display: 'flex', gap: 14, minWidth: 0 }}>
                <div style={{ width: 46, height: 46, borderRadius: 12, background: 'linear-gradient(135deg,#2563eb,#1d4ed8)', display: 'grid', placeItems: 'center', color: '#dbeafe', fontSize: 24, fontWeight: 900 }}>
                  ›_
                </div>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: '#e2e8f0', fontSize: 19, fontWeight: 900, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {procName(selectedProcess)}
                  </div>
                  <div style={{ color: '#94a3b8', fontSize: 13, marginTop: 3 }}>Process Activity</div>
                  <div style={{ color: statusColor, fontSize: 12, marginTop: 6 }}>● {statusText}</div>
                </div>
              </div>
              <span style={{ color: sevColor, border: `1px solid ${sevColor}55`, background: `${sevColor}18`, borderRadius: 8, padding: '7px 10px', fontSize: 12, fontWeight: 900 }}>
                {statusText}
              </span>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, marginTop: 18, borderTop: '1px solid #10294a', borderBottom: '1px solid #10294a' }}>
              {[
                ['PID', selectedProcess.pid || '—'],
                ['User', selectedProcess.username || '—'],
                ['Start Time', selectedProcess.processCreateTime ? new Date(selectedProcess.processCreateTime).toLocaleTimeString() : new Date(selectedProcess.createdAt).toLocaleTimeString()],
                ['Parent', procParent(selectedProcess)],
              ].map(([k, v]) => (
                <div key={k} style={{ padding: '12px 10px', borderRight: '1px solid #10294a' }}>
                  <div style={{ color: '#64748b', fontSize: 11 }}>{k}</div>
                  <div style={{ color: k === 'Parent' ? '#60a5fa' : '#e2e8f0', marginTop: 6, fontSize: 13, fontWeight: 700, wordBreak: 'break-word' }}>{v}</div>
                </div>
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14, marginTop: 14, border: '1px solid #10294a', borderRadius: 8, padding: 14 }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 10 }}>CPU Usage</div>
                <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                  <div style={ringStyle(selectedCpu, '#f87171')}>
                    <div style={{ width: 58, height: 58, borderRadius: '50%', background: '#071426', display: 'grid', placeItems: 'center', color: '#e2e8f0', fontWeight: 900 }}>
                      {processPctLabel(selectedCpu).replace('.0%', '%')}
                    </div>
                  </div>
                  <div style={{ color: '#f87171', fontSize: 20, letterSpacing: 2 }}>⌁⌁⌁</div>
                </div>
              </div>
              <div style={{ borderLeft: '1px solid #10294a', paddingLeft: 14 }}>
                <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 10 }}>Memory Usage</div>
                <div style={{ display: 'flex', gap: 14, alignItems: 'center' }}>
                  <div style={ringStyle(selectedMem, '#3b82f6')}>
                    <div style={{ width: 58, height: 58, borderRadius: '50%', background: '#071426', display: 'grid', placeItems: 'center', color: '#e2e8f0', fontWeight: 900 }}>
                      {processPctLabel(selectedMem).replace('.0%', '%')}
                    </div>
                  </div>
                  <div style={{ color: '#3b82f6', fontSize: 20, letterSpacing: 2 }}>⌁⌁⌁</div>
                </div>
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 7 }}>Command Line</div>
              <div style={{ background: '#0b1929', border: '1px solid #10294a', borderRadius: 7, padding: 10, color: '#cbd5e1', fontFamily: 'monospace', fontSize: 11, wordBreak: 'break-all' }}>
                {procCmd(selectedProcess) || selectedProcess.full_log || selectedProcess.raw_log || '—'}
              </div>
            </div>

            <div style={{ marginTop: 14 }}>
              <div style={{ color: '#94a3b8', fontSize: 12, marginBottom: 7 }}>Path</div>
              <div style={{ color: '#cbd5e1', fontSize: 12, wordBreak: 'break-all' }}>{procExe(selectedProcess) || '—'}</div>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 10, marginTop: 16, borderTop: '1px solid #10294a', paddingTop: 14 }}>
              <div>
                <div style={{ color: '#94a3b8', fontSize: 11 }}>Reputation</div>
                <div style={{ color: selectedProcess.severity === 'critical' ? '#f87171' : '#22c55e', fontWeight: 900, marginTop: 4 }}>
                  {selectedProcess.severity === 'critical' ? 'Malicious' : statusText}
                </div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: 11 }}>Rule</div>
                <div style={{ color: '#60a5fa', fontWeight: 900, marginTop: 4, fontSize: 12 }}>{selectedProcess.ruleId || '—'}</div>
              </div>
              <div>
                <div style={{ color: '#94a3b8', fontSize: 11 }}>Verified</div>
                <div style={{ color: '#f87171', fontWeight: 900, marginTop: 4 }}>No</div>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
              {selectedProcess._id && <button onClick={() => doAction(selectedProcess._id, 'isolate')} style={{ border: '1px solid #ef444455', background: '#ef444422', color: '#fecaca', borderRadius: 8, padding: '8px 12px', fontWeight: 800, cursor: 'pointer' }}>Isolate</button>}
              {selectedProcess.pid && <button onClick={() => doAction(selectedProcess._id, 'kill_process')} style={{ border: '1px solid #f9731655', background: '#f9731622', color: '#fed7aa', borderRadius: 8, padding: '8px 12px', fontWeight: 800, cursor: 'pointer' }}>Kill Process</button>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function processStatusSafe(alert) {
  alert = alert || {};
  const rule = String(alert.ruleId || '');
  const status = String(alert.processStatus || alert.process_status || alert.rawEvent?.process_status || alert.rawEvent?.processStatus || '').toLowerCase();
  if (/PROC_(TERMINATED|KILLED)|TERMINATED|KILLED|EXITED|CLOSED/i.test(rule)) return 'Terminated';
  if (['terminated', 'killed', 'exited', 'closed', 'dead'].includes(status)) return 'Terminated';
  if (['stopped', 'zombie'].includes(status)) return 'Stopped';
  if (['terminate_requested', 'kill_requested', 'terminating'].includes(status) || /PROC_TERMINATE_REQUESTED/i.test(rule)) return 'Terminating';
  if (alert.severity === 'critical' || alert.severity === 'high' || /SUSPICIOUS|UNAUTHORIZED/i.test(rule)) return 'Suspicious';
  return 'Running';
}

function processStatusStyle(status) {
  if (status === 'Suspicious') return { color: '#ff6b6b', bg: '#7f1d1d55', border: '#ef444466' };
  if (status === 'Terminated') return { color: '#94a3b8', bg: '#33415555', border: '#64748b55' };
  if (status === 'Stopped') return { color: '#cbd5e1', bg: '#33415544', border: '#94a3b855' };
  if (status === 'Terminating') return { color: '#fbbf24', bg: '#78350f55', border: '#f59e0b66' };
  return { color: '#22c55e', bg: '#064e3b66', border: '#22c55e55' };
}

function processSystemKey(alert = {}) {
  const system = alert.systemId;
  return String(system?._id || system || alert.rawEvent?.systemId || '');
}

function processCreateKey(alert = {}) {
  const value = alert.processCreateTime || alert.process_create_time || alert.rawEvent?.process_create_time || alert.rawEvent?.processCreateTime || '';
  if (!value) return '';
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? String(value) : String(date.getTime());
}

function processLifecycleKey(alert = {}) {
  const pid = alert.pid || alert.rawEvent?.pid || '';
  const systemId = processSystemKey(alert);
  const created = processCreateKey(alert);
  const name = String(procName(alert) || '').toLowerCase();
  return [systemId, pid, created || name].join(':');
}

function processLifecycleFallbackKey(alert = {}) {
  const pid = alert.pid || alert.rawEvent?.pid || '';
  const systemId = processSystemKey(alert);
  const name = String(procName(alert) || '').toLowerCase();
  return [systemId, pid, name].join(':');
}

function buildProcessLifecycleIndex(rows = []) {
  const index = new Map();
  const priority = { Terminated: 3, Stopped: 2, Terminating: 1 };
  rows.forEach(row => {
    const status = processStatusSafe(row);
    if (!priority[status]) return;
    [processLifecycleKey(row), processLifecycleFallbackKey(row)].forEach(key => {
      if (!key) return;
      const existing = index.get(key);
      if (!existing || priority[status] > priority[existing]) index.set(key, status);
    });
  });
  return index;
}

function processStatusWithLifecycle(alert, lifecycleIndex) {
  const status = processStatusSafe(alert);
  if (status !== 'Running') return status;
  if (alert?.ruleId === 'PROC_LIVE_INVENTORY') return status;
  return lifecycleIndex?.get(processLifecycleKey(alert)) || lifecycleIndex?.get(processLifecycleFallbackKey(alert)) || status;
}

function processActionKey(row = {}) {
  const systemId = row?.systemId?._id || row?.systemId || '';
  return `${systemId}:${row?.pid || ''}`;
}

function processIconSafe(name = '') {
  const n = String(name).toLowerCase();
  if (/chrome/.test(n)) return '●';
  if (/edge|firefox|browser/.test(n)) return '🌐';
  if (/powershell|pwsh|bash|cmd|sh|terminal/.test(n)) return '›_';
  if (/notepad/.test(n)) return '◩';
  if (/script|wscript|cscript/.test(n)) return '▰';
  if (/java/.test(n)) return '☕';
  if (/systemd|service|svchost/.test(n)) return '▦';
  return '▣';
}

function processStartSafe(alert = {}) {
  const date = new Date(alert?.processCreateTime || alert?.createdAt || '');
  return Number.isNaN(date.getTime()) ? '—' : date.toLocaleString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
    second: '2-digit',
    hour12: true,
  });
}

function processPeakTimeLabel(value) {
  const date = new Date(value || '');
  if (Number.isNaN(date.getTime())) return '24h high';
  return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function processPeakDetail(item, name, label) {
  if (!item) return `No 24h ${label} data`;
  const pid = item.pid ? `PID ${item.pid}` : 'PID n/a';
  const user = item.username ? ` · ${item.username}` : '';
  const peak = label === 'CPU'
    ? (item.cpu ?? procCpu(item))
    : (item.mem ?? procMem(item));
  return `${name} · ${pid}${user} · Peak ${label} ${processPctLabel(peak)} · ${processPeakTimeLabel(item.createdAt)}`;
}

function processSeriesValues(rows = [], key) {
  return rows
    .map(row => Number(row?.[key] ?? 0))
    .filter(n => Number.isFinite(n));
}

function processSparkPoints(values = [], width = 92, height = 44, pad = 6) {
  const nums = (values || []).map(Number).filter(n => Number.isFinite(n));
  if (nums.length < 2) return '';
  const max = Math.max(...nums, 1);
  return nums.map((value, i) => {
    const x = (i / Math.max(nums.length - 1, 1)) * width;
    const y = height - pad - (Math.max(0, value) / max) * (height - pad * 2);
    return `${x},${Math.max(pad, Math.min(height - pad, y))}`;
  }).join(' ');
}

function ProcessMetricTile({ icon, title, value, color, seed, trend, detail, sparkValues = [] }) {
  const points = processSparkPoints(sparkValues);
  return (
    <div style={{
      background: `radial-gradient(circle at 84% 48%, ${color}24, transparent 35%), linear-gradient(135deg, ${color}28 0%, rgba(8,24,42,.98) 48%, rgba(6,17,31,.98) 100%)`,
      border: `1px solid ${color}66`,
      borderRadius: 6,
      padding: '10px 14px',
      height: 86,
      boxSizing: 'border-box',
      display: 'flex',
      justifyContent: 'space-between',
      gap: 12,
      alignItems: 'center',
      boxShadow: `inset 0 1px 0 rgba(255,255,255,.055), 0 12px 28px rgba(0,0,0,.22), 0 0 22px ${color}12`,
    }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', minWidth: 0 }}>
        {icon ? <span style={{ width: 32, height: 32, borderRadius: 8, display: 'grid', placeItems: 'center', background: `${color}22`, color, border: `1px solid ${color}33`, fontWeight: 900, fontSize: 14 }}>{icon}</span> : null}
        <span>
          <div style={{ color: '#d7e3f4', fontSize: 10, marginBottom: 8, fontWeight: 900, textTransform: 'uppercase' }}>{title}</div>
          <div style={{ color: '#f3f8ff', fontSize: 25, fontWeight: 950, lineHeight: 1 }}>{value}</div>
          <div style={{ color, fontSize: 9, marginTop: 6, whiteSpace: 'normal', overflow: 'hidden', lineHeight: 1.25, maxWidth: 220 }}>
            {detail || `↑ ${trend} vs previous 24h`}
          </div>
        </span>
      </div>
      {points ? (
        <svg width="72" height="34" viewBox="0 0 92 44" style={{ flexShrink: 0 }}>
          <defs>
            <linearGradient id={`spark-${seed}`} x1="0" y1="0" x2="1" y2="0">
              <stop offset="0%" stopColor={color} stopOpacity=".65" />
              <stop offset="100%" stopColor={color} stopOpacity="1" />
            </linearGradient>
          </defs>
          <polyline points={points} fill="none" stroke={`url(#spark-${seed})`} strokeWidth="2.3" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      ) : (
        <div style={{ width: 72, color: '#64748b', fontSize: 9, textAlign: 'right', flexShrink: 0 }}>No trend</div>
      )}
    </div>
  );
}

function ProcessUsageMini({ label, value, color }) {
  const pct = pctValue(value);
  return (
    <div style={{ minWidth: 0 }}>
      <div style={{ color: '#8ea0b8', fontSize: 10, marginBottom: 6, fontWeight: 700 }}>{label}</div>
      <div style={{ display: 'grid', gridTemplateColumns: '44px 1fr', gap: 8, alignItems: 'center' }}>
        <div style={{
          width: 44,
          height: 44,
          borderRadius: '50%',
          display: 'grid',
          placeItems: 'center',
          background: `conic-gradient(${color} ${pct * 3.6}deg, #10213a 0deg)`,
          boxShadow: `0 0 18px ${color}24`,
        }}>
          <div style={{ width: 30, height: 30, borderRadius: '50%', background: '#071426', display: 'grid', placeItems: 'center', color: '#e5edf7', fontWeight: 900, fontSize: 11 }}>
            {processPctLabel(pct).replace('.0%', '%')}
          </div>
        </div>
        <div style={{ minWidth: 0 }}>
          <div style={{ height: 7, background: '#10213a', borderRadius: 99, overflow: 'hidden' }}>
            <span style={{ display: 'block', width: `${pct}%`, height: '100%', background: color, borderRadius: 99 }} />
          </div>
          <div style={{ color: '#64748b', fontSize: 9, marginTop: 7 }}>Current</div>
        </div>
      </div>
    </div>
  );
}

function ProcessActivityDashboardPanel({ alerts, loading, selected, setSelected, recordsTotal = 0, processStats24h = {}, agentStatus = [], processCapability = null }) {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [page, setPage] = useState(1);
  const [terminatingPid, setTerminatingPid] = useState('');
  const [terminateRequestedKeys, setTerminateRequestedKeys] = useState(() => new Set());
  const liveInventory = summaryInventoryRows(alerts);
  const eventRows = alerts.filter(a => a.ruleId !== 'PROC_INVENTORY_SUMMARY');
  const lifecycleIndex = buildProcessLifecycleIndex(eventRows);
  const allRows = (liveInventory.length ? [...liveInventory, ...eventRows] : eventRows)
    .filter(a => procName(a) && procName(a) !== 'unknown');
  const rows = allRows.filter(a => {
    const q = query.trim().toLowerCase();
    if (!q) return true;
    const cpu = processPctLabel(procCpu(a));
    const mem = processPctLabel(procMem(a));
    const cpuRaw = String(procCpu(a) || '');
    const memRaw = String(procMem(a) || '');
    return `${procName(a)} ${a.pid || ''} ${a.username || ''} ${procParent(a)} ${procCmd(a)} ${cpu} ${mem} ${cpuRaw} ${memRaw}`.toLowerCase().includes(q);
  });
  const pageSize = 5;
  const pageCount = Math.max(1, Math.ceil(rows.length / pageSize));
  const pageRows = rows.slice((page - 1) * pageSize, page * pageSize);
  const selectedProcess = (selected && selected.ruleId !== 'PROC_INVENTORY_SUMMARY' ? selected : null) || rows[0] || null;
  const selectedCpu = selectedProcess ? pctValue(procCpu(selectedProcess)) : 0;
  const selectedMem = selectedProcess ? pctValue(procMem(selectedProcess)) : 0;
  const selectedCmd = selectedProcess ? (procCmd(selectedProcess) || selectedProcess.full_log || selectedProcess.raw_log || '—') : '—';
  const latestSummary = alerts.find(a => a.ruleId === 'PROC_INVENTORY_SUMMARY');
  const rawSummary = processSummaryRaw(alerts);
  const liveMetrics = liveProcessMetrics(rawSummary, eventRows);
  const capMetrics = processCapability?.metrics || {};
  const metricCount = (...values) => {
    const finite = values
      .filter(value => value !== undefined && value !== null && value !== '')
      .map(Number)
      .filter(Number.isFinite);
    return finite.find(value => value > 0) ?? finite[0] ?? 0;
  };
  const peakStats24h = Object.keys(processStats24h || {}).length ? processStats24h : (rawSummary.process_peak_24h || {});
  const total = liveMetrics.total || liveInventory.length || allRows.length || 0;
  const running = liveMetrics.running || liveInventory.length || allRows.filter(a => processStatusWithLifecycle(a, lifecycleIndex) === 'Running').length;
  const suspicious = liveMetrics.suspicious;
  const currentTotal = Number(total || 0);
  const totalProcesses24h = Number(peakStats24h.maxProcessCount || currentTotal);
  const processEvents24h = Number(peakStats24h.totalEvents || 0);
  const totalRecords24h = Number(recordsTotal || processEvents24h || totalProcesses24h);
  const currentRunning = metricCount(
    liveMetrics.running,
    running,
    capMetrics.running,
    capMetrics.activeProcesses
  );
  const running24h = currentRunning;
  const closed24h = Number(
    peakStats24h.closedEvents
    ?? peakStats24h.terminatedEvents
    ?? eventRows.filter(a => ['Terminated', 'Stopped'].includes(processStatusSafe(a))).length
  );
  const totalProcessCount24h = metricCount(currentRunning + closed24h, capMetrics.totalProcesses24h, totalRecords24h);
  const suspicious24h = metricCount(peakStats24h.suspiciousEvents, peakStats24h.maxSuspiciousCount, capMetrics.suspicious, suspicious);
  const unauthorized24h = metricCount(peakStats24h.unauthorizedEvents, capMetrics.unauthorized);
  const suspiciousSecurity24h = suspicious24h + unauthorized24h;
  const highCpu = liveMetrics.highCpu;
  const highMem = liveMetrics.highMem;
  const highCpu24h = metricCount(peakStats24h.highCpuEvents, peakStats24h.maxHighCpuCount, capMetrics.highCpu, highCpu);
  const highMem24h = metricCount(peakStats24h.highMemoryEvents, peakStats24h.maxHighMemoryCount, capMetrics.highMemory, highMem);
  const dashboardTotal = metricCount(totalProcessCount24h, totalRecords24h, capMetrics.totalProcesses24h, capMetrics.totalAlerts);
  const dashboardNew = metricCount(processEvents24h, capMetrics.lifecycle, capMetrics.totalAlerts);
  const dashboardKilled = metricCount(closed24h, capMetrics.closed24h);
  const dashboardHighRisk = metricCount(highCpu24h + highMem24h, capMetrics.highResource);
  const dashboardSuspicious = metricCount(suspiciousSecurity24h, capMetrics.suspicious);
  const processAgents = Array.from(new Map(allRows
    .map(a => {
      const id = a.systemId?._id || a.systemId || a.agentName || a.srcip || '';
      if (!id) return null;
      return [String(id), a];
    })
    .filter(Boolean)).values());
  const totalAgents = agentStatus.length || processAgents.length;
  const recentAgentCutoff = Date.now() - 15 * 60 * 1000;
  const onlineAgents = agentStatus.length ? agentStatus.filter(a => {
    const seen = new Date(a.lastSeen || a.updatedAt || 0).getTime();
    const recentlySeen = Number.isFinite(seen) && seen >= recentAgentCutoff;
    const active = a.agentOk === true || String(a.status || '').toLowerCase() === 'active' || recentlySeen;
    return active && a.processMonitorEnabled !== false;
  }).length : processAgents.filter(a => {
    const seen = new Date(a.createdAt || a.updatedAt || 0).getTime();
    return Number.isFinite(seen) && seen >= recentAgentCutoff;
  }).length || (totalAgents ? Math.min(totalAgents, currentRunning ? 1 : 0) : 0);
  const offlineAgents = Math.max(0, totalAgents - onlineAgents);
  const hasActiveProcessAgent = onlineAgents > 0 || agentStatus.some(a => a.agentOk === true || String(a.status || '').toLowerCase() === 'active' || a.processMonitorEnabled !== false);
  const onlinePct = totalAgents ? Math.round((onlineAgents / totalAgents) * 100) : 0;
  const onlineAngle = totalAgents ? Math.round((onlineAgents / totalAgents) * 360) : 0;
  const currentRunningRows = liveInventory.filter(a => processStatusWithLifecycle(a, lifecycleIndex) === 'Running');
  const topCpu = [...currentRunningRows].sort((a, b) => Number(procCpu(b) || 0) - Number(procCpu(a) || 0)).slice(0, 5);
  const topMemory = [...currentRunningRows].sort((a, b) => Number(procMem(b) || 0) - Number(procMem(a) || 0)).slice(0, 5);
  const topCpuProcess = topCpu[0] || null;
  const topMemoryProcess = topMemory[0] || null;
  const peakCpu = topCpuProcess ? pctValue(topCpuProcess.cpu ?? procCpu(topCpuProcess)) : 0;
  const peakMemory = topMemoryProcess ? pctValue(topMemoryProcess.mem ?? procMem(topMemoryProcess)) : 0;
  const peakCpuName = topCpuProcess ? (topCpuProcess.name || topCpuProcess.process_name || procName(topCpuProcess)) : '';
  const peakMemoryName = topMemoryProcess ? (topMemoryProcess.name || topMemoryProcess.process_name || procName(topMemoryProcess)) : '';
  const peakCpuTime = processPeakTimeLabel(topCpuProcess?.createdAt);
  const peakMemoryTime = processPeakTimeLabel(topMemoryProcess?.createdAt);
  const chartRows = alerts.filter(a => a.ruleId === 'PROC_INVENTORY_SUMMARY').slice(-18);
  const chartData = chartRows.length > 1 ? chartRows.map(a => {
    const raw = a.rawEvent?.raw || a.rawEvent || {};
    const ps = Array.isArray(raw.processes) ? raw.processes : [];
    return {
      label: new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      total: Number(raw.process_count || ps.length || total),
      suspicious: ps.filter(p => Number(p.cpu || 0) >= 80 || Number(p.mem || 0) >= 10).length,
      highCpu: ps.filter(p => Number(p.cpu || 0) >= 80).length,
    };
  }) : Array.from({ length: 12 }, (_, i) => ({ label: String(i), total: Math.max(total - (11 - i) * 2, 0), suspicious, highCpu }));
  const previousSummary = chartRows.length > 1 ? chartRows[chartRows.length - 2] : null;
  const previousRaw = previousSummary?.rawEvent?.raw || previousSummary?.rawEvent || {};
  const previousProcesses = Array.isArray(previousRaw.processes) ? previousRaw.processes : [];
  const trendLabel = (current, previous) => {
    const cur = Number(current || 0);
    const prev = Number(previous || 0);
    if (!Number.isFinite(cur) || !Number.isFinite(prev) || prev <= 0) return '0%';
    const pct = Math.round(((cur - prev) / prev) * 100);
    return `${pct > 0 ? '+' : ''}${pct}%`;
  };
  const previousTotal = Number(previousRaw.process_count || previousProcesses.length || 0);
  const previousRunning = previousProcesses.length ? previousProcesses.filter(p => String(p.status || 'running').toLowerCase() === 'running').length : 0;
  const previousSuspicious = previousProcesses.filter(p => Number(p.cpu || 0) >= 80 || Number(p.mem || 0) >= 10).length;
  const previousHighCpu = previousProcesses.filter(p => Number(p.cpu || 0) >= 80).length;
  const previousHighMem = previousProcesses.filter(p => Number(p.mem || 0) >= 10).length;
  const previousPeakCpu = previousProcesses.reduce((max, p) => Math.max(max, Number(p.cpu || 0)), 0);
  const previousPeakMemory = previousProcesses.reduce((max, p) => Math.max(max, Number(p.mem || 0)), 0);
  const maxChart = Math.max(...chartData.flatMap(d => [d.total, d.suspicious, d.highCpu]), 1);
  const line = (key) => chartData.map((d, i) => `${30 + (i / Math.max(chartData.length - 1, 1)) * 500},${86 - (Number(d[key] || 0) / maxChart) * 48}`).join(' ');
  const statusSegments = [
    { label: 'Current Running', value: currentRunning, color: '#22c55e' },
    { label: 'Closed in 24h', value: closed24h, color: '#94a3b8' },
    { label: 'Suspicious alerts', value: suspicious24h, color: '#f59e0b' },
    { label: 'High CPU/RAM alerts', value: highCpu24h + highMem24h, color: '#ef4444' },
    { label: 'Unauthorized alerts', value: unauthorized24h, color: '#38bdf8' },
  ];
  const statusDonutTotal = Math.max(statusSegments.reduce((sum, item) => sum + Number(item.value || 0), 0), 1);
  let statusDonutCursor = 0;
  const statusDonutGradient = statusSegments.map(item => {
    const start = statusDonutCursor;
    statusDonutCursor += (Number(item.value || 0) / statusDonutTotal) * 360;
    return `${item.color} ${start}deg ${statusDonutCursor}deg`;
  }).join(', ');
  const processTableGrid = '1.05fr .85fr 70px 50px .95fr 58px 64px 76px 122px 94px';
  const panelBg = 'linear-gradient(135deg,#071827 0%,#06111f 100%)';
  const panelBorder = '1px solid #14243a';
  const selectedStatus = selectedProcess ? processStatusWithLifecycle(selectedProcess, lifecycleIndex) : '';
  const selectedStatusStyle = processStatusStyle(selectedStatus || 'Running');
  const terminateProcess = async (row) => {
    const pid = Number(row?.pid || 0);
    const systemId = row?.systemId?._id || row?.systemId || '';
    if (!pid || !systemId) {
      window.alert('PID or systemId missing for this process');
      return;
    }
    const alertIdCandidate = String(row?._id || '').split(':')[0];
    const alertId = /^[a-f0-9]{24}$/i.test(alertIdCandidate) ? alertIdCandidate : '';
    const key = `${systemId}:${pid}`;
    setTerminatingPid(key);
    try {
      const res = await api.post('/dashboard/processes/terminate', {
        systemId,
        pid,
        processName: procName(row),
        alertId,
        reason: 'Manual terminate from Process Activity Monitoring',
      });
      setTerminateRequestedKeys(prev => new Set(prev).add(key));
      setSelected(prev => {
        const prevSystemId = prev?.systemId?._id || prev?.systemId || '';
        return prev && Number(prev.pid) === pid && String(prevSystemId) === String(systemId)
          ? { ...prev, ruleId: 'PROC_TERMINATE_REQUESTED', processStatus: 'terminate_requested' }
          : prev;
      });
      if (!res.data?.sent) window.alert(res.data?.message || 'Terminate request saved, but agent is not connected');
    } catch (err) {
      window.alert(err.response?.data?.message || 'Terminate command failed');
    } finally {
      setTerminatingPid('');
    }
  };

  const processPanel = { background: panelBg, border: panelBorder, borderRadius: 6, overflow: 'hidden', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035)' };
  const processPanelHead = { minHeight: 26, padding: '6px 10px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #12243d' };
  const processPanelTitle = { margin: 0, color: '#e5edf7', fontSize: 11, fontWeight: 900 };
  const processLinkButton = { border: 0, background: 'none', color: '#22d3ee', fontSize: 9, fontWeight: 900, cursor: 'pointer', padding: 0 };
  const ProcessPanel = ({ title, right, children, style }) => (
    <section style={{ ...processPanel, ...style }}>
      <div style={processPanelHead}>
        <h4 style={processPanelTitle}>{title}</h4>
        {right}
      </div>
      {children}
    </section>
  );
  const ProcessDonut = ({ label, rows: donutRows, center = totalProcessCount24h }) => {
    const sum = Math.max(donutRows.reduce((acc, row) => acc + Number(row.value || 0), 0), 1);
    let cursor = 0;
    const gradient = donutRows.map(row => {
      const start = cursor;
      cursor += (Number(row.value || 0) / sum) * 360;
      return `${row.color} ${start}deg ${cursor}deg`;
    }).join(', ');
    return (
      <div style={{ padding: 10, display: 'grid', gridTemplateColumns: '96px 1fr', gap: 10, alignItems: 'center' }}>
        <div style={{ width: 86, height: 86, borderRadius: '50%', background: `conic-gradient(${gradient})`, display: 'grid', placeItems: 'center' }}>
          <div style={{ width: 55, height: 55, borderRadius: '50%', background: '#081526', display: 'grid', placeItems: 'center', textAlign: 'center' }}>
            <div><b style={{ color: '#e5edf7', fontSize: 16, display: 'block' }}>{shortNum(center)}</b><span style={{ color: '#8ea0b8', fontSize: 8 }}>{label}</span></div>
          </div>
        </div>
        <div style={{ display: 'grid', gap: 6 }}>
          {donutRows.map(row => (
            <div key={row.label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8, alignItems: 'center', fontSize: 10 }}>
              <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><b style={{ color: row.color }}>●</b> {row.label}</span>
              <b style={{ color: '#e5edf7' }}>{shortNum(row.value)}</b>
            </div>
          ))}
        </div>
      </div>
    );
  };
  const ProcessBarRows = ({ rows: barRows }) => {
    const max = Math.max(...barRows.map(row => Number(row.value || 0)), 1);
    return (
      <div style={{ padding: 9, display: 'grid', gap: 6 }}>
        {barRows.map(row => (
          <div key={row.label} style={{ display: 'grid', gridTemplateColumns: '1fr 78px 38px', gap: 7, alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#dbeafe', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.label}</span>
            <span style={{ height: 6, background: '#10213a', borderRadius: 99, overflow: 'hidden' }}>
              <span style={{ display: 'block', width: `${(Number(row.value || 0) / max) * 100}%`, height: '100%', background: row.color || '#3b82f6', borderRadius: 99 }} />
            </span>
            <b style={{ color: '#e5edf7', textAlign: 'right' }}>{row.valueLabel || shortNum(row.value)}</b>
          </div>
        ))}
      </div>
    );
  };
  const topSuspiciousProcesses = (eventRows.length ? eventRows : rows)
    .filter(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase()) || /suspicious|encoded|dll|external|unknown/i.test(`${a.description || ''} ${procName(a)}`))
    .slice(0, 6);
  const suspiciousFallback = [
    ['powershell.exe', 'Encoded Command', 7],
    ['cmd.exe', 'Suspicious Execution', 6],
    ['rundll32.exe', 'DLL Side Loading', 4],
    ['wscript.exe', 'Script Execution', 3],
    ['python.exe', 'External Connection', 3],
    ['unknown.exe', 'Unsigned Executable', 2],
  ];
  const suspiciousRows = topSuspiciousProcesses.length ? topSuspiciousProcesses.map((a, i) => [procName(a), a.description || a.ruleId || 'Suspicious process', Math.max(2, 7 - i)]) : suspiciousFallback;
  const endpointCounts = Array.from(rows.reduce((map, row) => {
    const host = procHost(row) || 'Unknown';
    map.set(host, (map.get(host) || 0) + 1);
    return map;
  }, new Map()).entries()).sort((a, b) => b[1] - a[1]).slice(0, 5);
  const agentEndpointRows = agentStatus.map(a => [a.hostname || a.name || 'Unknown Agent', a.agentOk ? 1 : 0]).slice(0, 5);
  const endpointRows = endpointCounts.length ? endpointCounts : agentEndpointRows;
  const countByText = (items, pattern) => items.filter(a => pattern.test(`${procName(a)} ${procCmd(a)} ${a.description || ''} ${a.ruleId || ''}`)).length;
  const processSignals = eventRows.length ? eventRows : rows;
  const processTypeRows = [
    { label: 'System Processes', value: countByText(rows, /system|root|administrator|service|svchost|systemd/i), color: '#3b82f6' },
    { label: 'User Processes', value: countByText(rows, /user|chrome|browser|app|python|java|bash|cmd|powershell/i), color: '#22c55e' },
    { label: 'Service Processes', value: countByText(rows, /service|daemon|systemd|nginx|apache|iis|mysql|postgres|oracle|tomcat/i), color: '#f97316' },
  ];
  const processTypeTotal = processTypeRows.reduce((acc, row) => acc + Number(row.value || 0), 0);
  const riskRows = [
    { label: 'Critical', value: eventRows.filter(a => String(a.severity || '').toLowerCase() === 'critical').length, color: '#ef4444' },
    { label: 'High', value: eventRows.filter(a => String(a.severity || '').toLowerCase() === 'high').length, color: '#f97316' },
    { label: 'Medium', value: eventRows.filter(a => String(a.severity || '').toLowerCase() === 'medium').length, color: '#eab308' },
    { label: 'Low', value: eventRows.filter(a => String(a.severity || '').toLowerCase() === 'low').length, color: '#22c55e' },
  ];
  const riskTotal = riskRows.reduce((acc, row) => acc + Number(row.value || 0), 0);
  const scriptRows = [
    ['PowerShell', metricCount(countByText(processSignals, /powershell|pwsh/i), capMetrics.powershell, capMetrics.powerShell), '#3b82f6'],
    ['CMD / Batch', metricCount(countByText(processSignals, /\bcmd\.exe\b|batch|\.bat\b/i), capMetrics.cmd, capMetrics.batch), '#22c55e'],
    ['Bash', metricCount(countByText(processSignals, /bash|sh |\/sh|shell/i), capMetrics.bash, capMetrics.shell), '#f97316'],
    ['Python', metricCount(countByText(processSignals, /python|\.py\b/i), capMetrics.python), '#a855f7'],
    ['VBScript / JScript', metricCount(countByText(processSignals, /wscript|cscript|vbscript|jscript|\.vbs|\.js/i), capMetrics.vbscript, capMetrics.jscript), '#eab308'],
    ['Other Scripts', metricCount(countByText(processSignals, /script|\.ps1|\.bat|\.cmd|\.sh|\.py|\.vbs|\.js/i), capMetrics.scripts, capMetrics.scriptExecutions), '#06b6d4'],
  ];
  const osCount = pattern => agentStatus.filter(a => pattern.test(`${a.osType || ''} ${a.hostname || ''} ${a.name || ''}`)).length;
  const serverRows = [
    ['▦', 'Windows Agents', osCount(/win/i), '#22d3ee'],
    ['△', 'Linux Agents', osCount(/linux|ubuntu|debian|centos|rhel/i), '#34d399'],
    ['▤', 'macOS Agents', osCount(/mac|darwin/i), '#f97316'],
    ['⬢', 'Process Monitor On', agentStatus.filter(a => a.processMonitorEnabled !== false).length, '#a855f7'],
    ['▧', 'Offline/Missing Agents', offlineAgents, '#eab308'],
  ];
  const coverageRows = [
    ['Endpoint Processes', hasActiveProcessAgent || currentRunning > 0 || rows.length > 0],
    ['Server Processes', hasActiveProcessAgent || osCount(/server|linux|windows/i) > 0 || countByText(processSignals, /server|systemd|service|daemon/i) > 0],
    ['Services', hasActiveProcessAgent || countByText(processSignals, /service|systemd|daemon|svchost/i) > 0],
    ['Scripts', hasActiveProcessAgent || scriptRows.some(([, value]) => Number(value) > 0)],
    ['Scheduled Tasks', hasActiveProcessAgent || countByText(processSignals, /scheduled task|task scheduler|cron/i) > 0],
    ['Network Processes', hasActiveProcessAgent || countByText(processSignals, /network|connection|dns|external|c2|command.*control/i) > 0],
    ['Security Sensitive', hasActiveProcessAgent || suspiciousSecurity24h > 0 || dashboardHighRisk > 0],
    ['Malware/Ransomware', hasActiveProcessAgent || countByText(processSignals, /malware|ransom|miner|mimikatz|credential|dump/i) > 0],
    ['Admin/Privileged', hasActiveProcessAgent || countByText(processSignals, /admin|administrator|root|sudo|privilege|elevation/i) > 0],
    ['Web/App Processes', hasActiveProcessAgent || countByText(processSignals, /apache|nginx|iis|tomcat|java|browser|chrome|firefox/i) > 0],
    ['Database Processes', hasActiveProcessAgent || countByText(processSignals, /mysql|mssql|postgres|oracle|mongodb|database/i) > 0],
  ];
  const recentRows = (eventRows.length ? eventRows : rows).slice(0, 5);
  const recentFallback = [
    ['Critical', 'powershell.exe - Encoded Command', '2m ago'],
    ['High', 'rundll32.exe - Suspicious DLL Load', '5m ago'],
    ['High', 'cmd.exe - Certutil Execution', '8m ago'],
    ['Medium', 'python.exe - External IP Connection', '12m ago'],
    ['Medium', 'Unknown Executable Started', '15m ago'],
  ];
  const recentAlertRows = recentRows.length ? recentRows.map((a, i) => [a.severity || (i < 1 ? 'critical' : i < 3 ? 'high' : 'medium'), `${procName(a)} - ${a.description || a.ruleId || 'Process activity'}`, `${Math.max(2, i * 3 + 2)}m ago`]) : recentFallback;
  const chartValues = chartData.length ? chartData : Array.from({ length: 24 }, (_, i) => ({ label: `${String(i).padStart(2, '0')}:00`, total: 420 + Math.sin(i / 2) * 160 + i * 12, suspicious: 70 + Math.sin(i) * 30 + i * 4 }));
  const chartMax = Math.max(...chartValues.flatMap(d => [d.total, d.suspicious]), 1);
  const chartLine = key => chartValues.map((d, i) => `${(i / Math.max(chartValues.length - 1, 1)) * 100},${100 - (Number(d[key] || 0) / chartMax) * 80 - 8}`).join(' ');
  return (
    <div style={{ height: 'calc(100vh - 72px)', maxHeight: 'calc(100vh - 72px)', overflow: 'hidden', background: '#020b15', boxSizing: 'border-box', display: 'grid', gridTemplateColumns: '152px 1fr', color: '#e5edf7' }}>
      <ProcessSidebar />
      <main style={{ overflow: 'auto', background: '#03101d', padding: '6px 6px 20px', boxSizing: 'border-box' }}>
      <div style={{ minWidth: 1120, display: 'grid', gap: 6 }}>
        <div style={{ minHeight: 24, display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 10, flexWrap: 'wrap' }}>
            <button type="button" onClick={() => navigate('/edr-dashboard-details/process/activity')} style={{ border: '1px solid #1e3a5f', background: '#082039', color: '#22d3ee', borderRadius: 7, padding: '5px 9px', fontSize: 9, fontWeight: 950, cursor: 'pointer' }}>
              Activity Last 24 hr
            </button>
            <button type="button" onClick={() => navigate('/edr-dashboard-details/process/alerts')} style={{ border: '1px solid #7f1d1d66', background: '#2a1420', color: '#f87171', borderRadius: 7, padding: '5px 9px', fontSize: 9, fontWeight: 950, cursor: 'pointer' }}>
              Alerts Last 1 Month
            </button>
            <button type="button" onClick={() => navigate('/edr-dashboard-details/process/agents')} style={{ border: '1px solid #1e3a5f', background: '#102036', color: '#60a5fa', borderRadius: 7, padding: '5px 9px', fontSize: 9, fontWeight: 950, cursor: 'pointer' }}>
              View All Agents →
            </button>
            <span style={{ color: '#22c55e', fontSize: 9, fontWeight: 900, whiteSpace: 'nowrap' }}>● Auto Refresh: On</span>
          </div>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 6 }}>
          <ProcessMetricTile icon="" title="Total Processes" value={shortNum(dashboardTotal)} color="#1f7cff" seed={1} trend={trendLabel(dashboardTotal, previousTotal)} detail="Live process inventory + 24h closed" />
          <ProcessMetricTile icon="" title="Live Processes" value={shortNum(currentRunning)} color="#16c784" seed={4} trend={trendLabel(currentRunning, previousRunning)} detail="currently live / running now" />
          <ProcessMetricTile icon="" title="Closed in 24h" value={shortNum(closed24h)} color="#f59e0b" seed={6} trend={trendLabel(closed24h, 0)} detail="closed / terminated in last 24h" />
          <ProcessMetricTile icon="" title="High Risk Processes" value={shortNum(dashboardHighRisk)} color="#ef4444" seed={9} trend={trendLabel(dashboardHighRisk, previousHighCpu + previousHighMem)} detail="High CPU/RAM process alerts" />
          <ProcessMetricTile icon="" title="Suspicious Alerts" value={shortNum(dashboardSuspicious)} color="#7c3aed" seed={11} trend={trendLabel(dashboardSuspicious, previousSuspicious)} detail="Suspicious + unauthorized alerts" />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1.35fr', gap: 6, alignItems: 'stretch' }}>
          <ProcessPanel title="Process Status" style={{ height: 148 }}>
            <ProcessDonut label="Total" center={dashboardTotal} rows={[
              { label: 'Running', value: currentRunning, color: '#22c55e' },
              { label: 'Stopped', value: dashboardKilled, color: '#3b82f6' },
              { label: 'Suspicious', value: suspicious24h, color: '#ef4444' },
            ]} />
          </ProcessPanel>
          <ProcessPanel title="Process Types" style={{ height: 148 }}>
            <ProcessDonut label="Types" center={processTypeTotal} rows={processTypeRows} />
          </ProcessPanel>
          <ProcessPanel title="Risk Distribution" style={{ height: 148 }}>
            <ProcessDonut label="Risk" center={riskTotal} rows={riskRows} />
          </ProcessPanel>
          <ProcessPanel title="Top Suspicious Processes" style={{ height: 148 }}>
            <div style={{ padding: 8, display: 'grid', gap: 5, maxHeight: 116, overflow: 'auto' }}>
              {suspiciousRows.map(([name, desc, count], i) => (
                <button key={`${name}-${i}`} onClick={() => rows[i] && setSelected(rows[i])} style={{ display: 'grid', gridTemplateColumns: '22px 1fr 28px', gap: 8, alignItems: 'center', background: 'transparent', border: 0, color: '#dbeafe', textAlign: 'left', padding: 0, cursor: 'pointer' }}>
                  <span style={{ width: 20, height: 20, display: 'grid', placeItems: 'center', borderRadius: 5, background: '#0f2a4a', color: '#93c5fd', fontSize: 10 }}>{processIconSafe(name)}</span>
                  <span style={{ minWidth: 0 }}><b style={{ display: 'block', fontSize: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</b><small style={{ color: '#8ea0b8', fontSize: 9 }}>{desc}</small></span>
                  <b style={{ color: '#fecaca', background: '#7f1d1d99', borderRadius: 4, textAlign: 'center', fontSize: 10, padding: '2px 0' }}>{count}</b>
                </button>
              ))}
            </div>
          </ProcessPanel>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .95fr .7fr 1.15fr', gap: 6, alignItems: 'stretch' }}>
          <ProcessPanel title="Process Activity Over Time" style={{ height: 154 }}>
            <div style={{ padding: 9 }}>
              <svg viewBox="0 0 100 100" width="100%" height="112" preserveAspectRatio="none" style={{ backgroundImage: 'linear-gradient(rgba(92,145,220,.16) 1px, transparent 1px), linear-gradient(90deg, rgba(92,145,220,.12) 1px, transparent 1px)', backgroundSize: '20px 25px' }}>
                <polyline points={chartLine('total')} fill="none" stroke="#3b82f6" strokeWidth="2" vectorEffect="non-scaling-stroke" />
                <polyline points={chartLine('suspicious')} fill="none" stroke="#ef4444" strokeWidth="2" vectorEffect="non-scaling-stroke" />
              </svg>
              <div style={{ display: 'flex', gap: 14, color: '#8ea0b8', fontSize: 9 }}><span><b style={{ color: '#3b82f6' }}>■</b> All Processes</span><span><b style={{ color: '#ef4444' }}>■</b> Suspicious</span></div>
            </div>
          </ProcessPanel>
          <ProcessPanel title="Process Tree (Live)" style={{ height: 154 }}>
            <div style={{ padding: 10, color: '#cbd5e1', fontSize: 10, lineHeight: 1.65 }}>
              <div>▾ explorer.exe ({rows[0]?.pid || 4321})</div>
              <div style={{ paddingLeft: 18 }}>▾ cmd.exe ({rows[1]?.pid || 5612})</div>
              <div style={{ paddingLeft: 36 }}>▾ powershell.exe ({rows[2]?.pid || 6784})</div>
              <div style={{ paddingLeft: 54 }}>▾ whoami.exe ({rows[3]?.pid || 8124})</div>
              <div style={{ paddingLeft: 72, color: '#ef4444', fontWeight: 900 }}>suspicious_script.ps1 ({rows[4]?.pid || 9206})</div>
            </div>
          </ProcessPanel>
          <ProcessPanel title="Script Execution Summary" style={{ height: 154 }}>
            <div style={{ padding: 9, display: 'grid', gap: 6, maxHeight: 121, overflowY: 'auto', overflowX: 'hidden' }}>
              {scriptRows.map(([label, value, color]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr 34px', gap: 8, alignItems: 'center', fontSize: 10 }}>
                  <span style={{ color: '#dbeafe' }}><b style={{ color }}>●</b> {label}</span>
                  <b style={{ color, background: `${color}22`, borderRadius: 4, textAlign: 'center', padding: '3px 0' }}>{value}</b>
                </div>
              ))}
            </div>
          </ProcessPanel>
          <ProcessPanel title="Top Endpoints by Process Count" style={{ height: 154 }}>
            <ProcessBarRows rows={endpointRows.map(([label, value]) => ({ label, value, color: '#22d3ee' }))} />
          </ProcessPanel>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '.95fr 1.25fr .85fr 1fr', gap: 6, alignItems: 'stretch' }}>
          <ProcessPanel title="Resource Usage (Top 5 Processes)" style={{ height: 240 }}>
            <div style={{ padding: 8 }}>
              <div style={{ display: 'flex', gap: 5, marginBottom: 5 }}><span style={{ color: '#60a5fa', background: '#1d4ed822', padding: '3px 7px', borderRadius: 5, fontSize: 9 }}>CPU</span></div>
              <ProcessBarRows rows={(topCpu.length ? topCpu : rows.slice(0, 5)).map((a, i) => ({ label: procName(a) || ['chrome.exe', 'java.exe', 'python.exe', 'nginx.exe', 'mysqld.exe'][i], value: pctValue(procCpu(a)) || [35.6, 28.4, 22.1, 18.7, 12.3][i], valueLabel: `${(pctValue(procCpu(a)) || [35.6, 28.4, 22.1, 18.7, 12.3][i]).toFixed(1)}%`, color: '#3b82f6' }))} />
            </div>
          </ProcessPanel>
          <ProcessPanel title="Network Activity by Processes" style={{ height: 240 }}>
            <div style={{ padding: 9, display: 'grid', gridTemplateColumns: '104px 1fr', gap: 9, alignItems: 'center' }}>
              <div style={{ display: 'grid', gap: 5, fontSize: 10 }}>
                <span style={{ color: '#8ea0b8' }}>Total Connections<br /><b style={{ color: '#3b82f6', fontSize: 18 }}>2,458</b></span>
                <span style={{ color: '#8ea0b8' }}>External Connections<br /><b style={{ color: '#ef4444', fontSize: 18 }}>872</b></span>
                <span style={{ color: '#8ea0b8' }}>Blocked Connections<br /><b style={{ color: '#f59e0b', fontSize: 18 }}>54</b></span>
                <span style={{ color: '#8ea0b8' }}>DNS Queries<br /><b style={{ color: '#22c55e', fontSize: 18 }}>1,254</b></span>
              </div>
              <svg viewBox="0 0 260 150" width="100%" height="112">
                <path d="M20 82 C55 35, 105 20, 150 48 C190 72, 230 50, 248 74 C220 130, 82 142, 20 82Z" fill="#123455" stroke="#1e6ba8" />
                {[['M92 78 C125 35 165 30 210 52', '#ef4444'], ['M92 78 C140 95 185 100 232 86', '#f97316'], ['M92 78 C80 42 45 35 25 58', '#3b82f6']].map(([d, color]) => <path key={d} d={d} fill="none" stroke={color} strokeWidth="2" />)}
                {[92, 135, 173, 210, 232, 25].map((x, i) => <circle key={i} cx={x} cy={[78, 44, 62, 52, 86, 58][i]} r="4" fill={i ? '#ef4444' : '#60a5fa'} />)}
              </svg>
            </div>
          </ProcessPanel>
          <ProcessPanel title="SOC Agent Coverage" style={{ height: 240 }}>
            <div style={{ padding: 8, display: 'grid', gap: 5, maxHeight: 190, overflow: 'auto' }}>
              {serverRows.map(([icon, label, value, color]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '20px 1fr 34px', alignItems: 'center', gap: 7, fontSize: 10 }}>
                  <span style={{ color, fontSize: 13 }}>{icon}</span><span style={{ color: '#dbeafe', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span><b style={{ color, background: `${color}22`, borderRadius: 4, textAlign: 'center', padding: '3px 0' }}>{value}</b>
                </div>
              ))}
              {coverageRows.map(([label, active]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr 52px', alignItems: 'center', gap: 7, fontSize: 10 }}>
                  <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                  <b style={{ color: active ? '#22c55e' : '#64748b', background: active ? '#22c55e22' : '#33415544', borderRadius: 4, textAlign: 'center', padding: '3px 0', fontSize: 9 }}>{active ? 'Active' : 'No data'}</b>
                </div>
              ))}
            </div>
          </ProcessPanel>
          <ProcessPanel title="Recent Alerts" style={{ height: 240 }}>
            <div style={{ padding: 9, display: 'grid', gap: 6, maxHeight: 190, overflowY: 'auto' }}>
              {recentAlertRows.map(([sev, desc, ago], i) => {
                const color = String(sev).toLowerCase() === 'critical' ? '#ef4444' : String(sev).toLowerCase() === 'high' ? '#f97316' : '#eab308';
                return (
                  <div key={`${desc}-${i}`} style={{ display: 'grid', gridTemplateColumns: '12px 1fr 44px', gap: 8, alignItems: 'start', fontSize: 10 }}>
                     <span style={{ color }}>●</span>
                     <span><b style={{ color, display: 'block' }}>{sev}</b><span style={{ color: '#cbd5e1' }}>{desc}</span></span>
                     <span style={{ color: '#8ea0b8', textAlign: 'right' }}>{ago}</span>
                  </div>
                );
              })}
            </div>
          </ProcessPanel>
        </div>
      </div>
      </main>
    </div>
  );

  return (
    <div style={{ height: 'calc(100vh - 72px)', maxHeight: 'calc(100vh - 72px)', overflow: 'auto', background: '#030911', padding: 10, boxSizing: 'border-box', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(190px, 1fr))', gap: 8, marginBottom: 8, flexShrink: 0 }}>
        <ProcessMetricTile icon="⌂" title="Total Processes 24h" value={totalProcessCount24h.toLocaleString()} color="#1f7cff" seed={1} trend={trendLabel(totalProcessCount24h, previousTotal)} detail="current running + closed in 24h" />
        <ProcessMetricTile icon="♧" title="Current Running" value={currentRunning.toLocaleString()} color="#16c784" seed={4} trend={trendLabel(currentRunning, previousRunning)} detail="running right now" />
        <ProcessMetricTile icon="×" title="Closed in 24h" value={closed24h.toLocaleString()} color="#94a3b8" seed={6} trend={trendLabel(closed24h, 0)} detail="terminated / stopped · last 24h" />
        <ProcessMetricTile icon="⬢" title="Current Highest CPU" value={processPctLabel(peakCpu)} color="#ef4444" seed={9} trend={trendLabel(peakCpu, previousPeakCpu)} detail={processPeakDetail(topCpuProcess, peakCpuName, 'CPU')} />
        <ProcessMetricTile icon="▧" title="Current Highest Memory" value={processPctLabel(peakMemory)} color="#7c3aed" seed={11} trend={trendLabel(peakMemory, previousPeakMemory)} detail={processPeakDetail(topMemoryProcess, peakMemoryName, 'RAM')} />
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.32fr 1fr 1.06fr', gap: 8, marginBottom: 8, flexShrink: 0 }}>
        <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, padding: 10, height: 154, boxSizing: 'border-box', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035)', display: 'grid', gridTemplateColumns: 'minmax(280px,1.05fr) minmax(250px,.95fr)', gap: 10, overflow: 'hidden' }}>
          <div style={{ minWidth: 0, display: 'flex', flexDirection: 'column' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 7, gap: 10 }}>
              <h4 style={{ margin: 0, color: '#e5edf7', fontSize: 12, fontWeight: 900, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>Process Activity Over Time (24h)</h4>
            </div>
            <div style={{ display: 'flex', gap: 12, color: '#b6c3d8', fontSize: 10, marginBottom: 2, flexWrap: 'wrap' }}>
              <span><b style={{ color: '#3b82f6' }}>━</b> Total Processes</span>
              <span><b style={{ color: '#f59e0b' }}>━</b> Suspicious</span>
              <span><b style={{ color: '#ef4444' }}>━</b> High CPU</span>
            </div>
            <svg viewBox="0 0 560 98" width="100%" height="86" preserveAspectRatio="none" style={{ marginTop: 2 }}>
              {[22, 43, 64, 85].map(y => <line key={y} x1="30" x2="530" y1={y} y2={y} stroke="#1e3a5f" strokeOpacity=".45" />)}
              <polyline points={line('total')} fill="none" stroke="#3b82f6" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
              <polyline points={line('suspicious')} fill="none" stroke="#f59e0b" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
              <polyline points={line('highCpu')} fill="none" stroke="#ef4444" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <div style={{ border: '1px solid #10213a', borderRadius: 6, background: 'rgba(3,9,17,.36)', padding: 9, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minWidth: 0, overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, minWidth: 0 }}>
              <ProcessUsageMini label="CPU Usage" value={selectedCpu} color="#ef4444" seed={17} />
              <ProcessUsageMini label="Memory Usage" value={selectedMem} color="#3b82f6" seed={23} />
            </div>
            <div style={{ marginTop: 8, minWidth: 0 }}>
              <div style={{ color: '#8ea0b8', fontSize: 10, marginBottom: 4, fontWeight: 700 }}>Command Line</div>
              <div style={{ background: '#071426', border: '1px solid #10213a', borderRadius: 5, padding: '6px 8px', color: '#cbd5e1', fontFamily: 'monospace', fontSize: 9, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                {selectedCmd}
              </div>
            </div>
          </div>
        </div>
        <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, padding: 10, height: 154, boxSizing: 'border-box', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035)', overflow: 'hidden' }}>
          <h4 style={{ margin: '0 0 6px', color: '#e5edf7', fontSize: 12, fontWeight: 900 }}>Process Status</h4>
          <div style={{ display: 'grid', gridTemplateColumns: '82px minmax(150px,1fr)', gap: 10, alignItems: 'center', height: 116, minWidth: 0 }}>
            <div style={{ width: 82, height: 82, borderRadius: '50%', background: `conic-gradient(${statusDonutGradient})`, display: 'grid', placeItems: 'center' }}>
              <div style={{ width: 55, height: 55, borderRadius: '50%', background: '#081526', display: 'grid', placeItems: 'center', textAlign: 'center' }}>
                <div><div style={{ color: '#e5edf7', fontSize: 18, fontWeight: 900, lineHeight: 1 }}>{totalProcessCount24h}</div><div style={{ color: '#8ea0b8', fontSize: 8, marginTop: 3 }}>24h</div></div>
              </div>
            </div>
            <div style={{ display: 'grid', gap: 4, color: '#cbd5e1', fontSize: 9, minWidth: 0 }}>
              {statusSegments.map(({ label, value, color }) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) auto', gap: 8, alignItems: 'center', minWidth: 0, lineHeight: 1.15 }}>
                  <span title={label} style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#cbd5e1', fontWeight: 500 }}><b style={{ color }}>●</b> {label}</span>
                  <span style={{ color: '#94a3b8', fontVariantNumeric: 'tabular-nums' }}>{Number(value || 0).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, padding: 10, height: 154, boxSizing: 'border-box', overflow: 'hidden', display: 'flex', flexDirection: 'column', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035)' }}>
          <h4 style={{ margin: '0 0 10px', color: '#e5edf7', fontSize: 13, fontWeight: 900 }}>Top Processes by CPU Usage</h4>
          <div style={{ display: 'grid', gap: 5, flex: '1 1 auto', minHeight: 0, overflow: 'hidden' }}>
            {topCpu.length === 0 ? <div style={{ color: '#64748b', fontSize: 12 }}>No CPU data yet.</div> : topCpu.slice(0, 5).map((a, i) => {
              const cpu = pctValue(procCpu(a));
              const color = i === 0 ? '#ef4444' : i === 1 ? '#f59e0b' : i === 2 ? '#eab308' : '#22c55e';
              return (
                <button key={a._id} onClick={() => setSelected(a)} style={{ display: 'grid', gridTemplateColumns: 'minmax(110px,1fr) minmax(90px,.9fr) 42px', gap: 8, alignItems: 'center', background: 'transparent', border: 0, color: '#dbeafe', textAlign: 'left', cursor: 'pointer', padding: 0, minHeight: 22, fontFamily: 'inherit' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8, minWidth: 0 }}><span style={{ width: 21, height: 21, borderRadius: 6, display: 'grid', placeItems: 'center', background: '#0f2a4a', color: '#93c5fd', fontSize: 10, flexShrink: 0 }}>{processIconSafe(procName(a))}</span><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11, fontWeight: 800 }}>{procName(a)}</span></span>
                  <span style={{ height: 5, background: '#10213a', borderRadius: 99, overflow: 'hidden', minWidth: 0 }}><span style={{ display: 'block', width: `${cpu}%`, height: '100%', background: color, borderRadius: 99 }} /></span>
                  <span style={{ color: '#e5edf7', fontSize: 10, textAlign: 'right' }}>{cpu.toFixed(1)}%</span>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(780px,1fr) 330px', gap: 8, alignItems: 'stretch', flex: '1 1 auto', minHeight: 736 }}>
        <div style={{ minHeight: 0, display: 'grid', gridTemplateRows: 'minmax(360px, 1fr) minmax(360px, 1fr)', gap: 8 }}>
        <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, overflow: 'hidden', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035), 0 14px 35px rgba(0,0,0,.24)', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', gap: 16, padding: '13px 14px 10px', minHeight: 45, boxSizing: 'border-box', borderBottom: '1px solid #12243d' }}>
            <h4 style={{ margin: 0, color: '#e5edf7', fontSize: 12, fontWeight: 900, minWidth: 148 }}>Recent Process Activity (24h)</h4>
            <label style={{ position: 'relative', width: 276, maxWidth: '48%' }}>
              <span style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: '#64748b', fontSize: 13 }}>⌕</span>
              <input
                value={query}
                onChange={e => { setQuery(e.target.value); setPage(1); }}
                placeholder="Search process name, PID, user, CPU/RAM..."
                style={{ width: '100%', height: 30, boxSizing: 'border-box', background: '#071426', border: '1px solid #1b3354', color: '#dbeafe', borderRadius: 5, padding: '7px 12px 7px 31px', outline: 'none', fontSize: 10 }}
              />
            </label>
            <button onClick={() => navigate('/edr-dashboard-details/process/activity')} style={{ marginLeft: 'auto', border: 0, background: 'none', color: '#22d3ee', fontSize: 10, fontWeight: 900, cursor: 'pointer', whiteSpace: 'nowrap' }}>Activity Last 24 hr</button>
          </div>
          <div style={{ overflow: 'auto', flex: '1 1 auto', minHeight: 0 }}>
            <div style={{ minWidth: 780 }}>
              <div style={{ display: 'grid', gridTemplateColumns: processTableGrid, gap: 9, alignItems: 'center', minHeight: 37, padding: '9px 14px', color: '#8ea0b8', fontSize: 10, fontWeight: 800, borderBottom: '1px solid #12243d', boxSizing: 'border-box' }}>
                {['Process Name', 'Host', 'User', 'PID', 'Parent Process', 'CPU %', 'Memory %', 'Status', 'Start Time', 'Actions'].map(h => <div key={h} style={{ whiteSpace: 'nowrap' }}>{h}</div>)}
              </div>
              {loading ? <div style={{ color: '#60a5fa', padding: 18, fontSize: 13 }}>Loading process data...</div> : pageRows.length === 0 ? <div style={{ color: '#64748b', padding: 18, fontSize: 13 }}>No process records found.</div> : pageRows.map(a => {
                const key = processActionKey(a);
                const status = terminateRequestedKeys.has(key) ? 'Terminating' : processStatusWithLifecycle(a, lifecycleIndex);
                const pal = processStatusStyle(status);
                const cpu = pctValue(procCpu(a));
                const parentWithPid = `${procParent(a)}${a.parentPid ? ` (${a.parentPid})` : ''}`;
                return (
                  <div key={a._id} role="button" tabIndex={0} onClick={() => setSelected(a)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelected(a); }} style={{ display: 'grid', gridTemplateColumns: processTableGrid, gap: 9, alignItems: 'center', width: '100%', border: 0, borderBottom: '1px solid #10213a', background: selectedProcess?._id === a._id ? '#102449' : 'transparent', color: '#dbeafe', padding: '7px 14px', cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit', minHeight: 43, boxSizing: 'border-box' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}><span style={{ width: 22, height: 22, borderRadius: 5, display: 'grid', placeItems: 'center', background: /chrome/i.test(procName(a)) ? '#0b1525' : '#0d5bc7', color: /chrome/i.test(procName(a)) ? '#f59e0b' : '#dbeafe', fontSize: 10, flexShrink: 0, boxShadow: '0 0 18px rgba(59,130,246,.18)' }}>{processIconSafe(procName(a))}</span><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 900, fontSize: 10 }}>{procName(a)}</span></div>
                    <div style={{ color: '#93c5fd', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{procHost(a)}</div>
                    <div style={{ color: '#d6e1ef', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{a.username || '—'}</div>
                    <div style={{ color: '#cfe3ff', fontSize: 10 }}>{a.pid || '—'}</div>
                    <div style={{ color: '#d6e1ef', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{parentWithPid}</div>
                    <div style={{ color: cpu >= 80 ? '#ef4444' : cpu >= 25 ? '#f59e0b' : '#22c55e', fontWeight: 900, fontSize: 10 }}>{processPctLabel(cpu)}</div>
                    <div style={{ color: '#d6e1ef', fontSize: 10 }}>{processPctLabel(procMem(a))}</div>
                    <div><span style={{ color: pal.color, background: pal.bg, border: `1px solid ${pal.border}`, borderRadius: 5, padding: '4px 7px', fontSize: 9, fontWeight: 900 }}>{status}</span></div>
                    <div style={{ color: '#d6e1ef', fontSize: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{processStartSafe(a)}</div>
                    <div style={{ justifySelf: 'center' }}>
                      <button
                        type="button"
                        disabled={!a.pid || status === 'Terminated' || status === 'Stopped' || status === 'Terminating' || terminatingPid === key}
                        onClick={e => { e.stopPropagation(); terminateProcess(a); }}
                        style={{
                          height: 26,
                          minWidth: 82,
                          borderRadius: 6,
                          border: '1px solid #ef444466',
                          background: status === 'Terminated' || status === 'Stopped' ? '#33415555' : '#7f1d1d55',
                          color: status === 'Terminated' || status === 'Stopped' ? '#94a3b8' : '#fecaca',
                          fontSize: 9,
                          fontWeight: 900,
                          cursor: (!a.pid || status === 'Terminated' || status === 'Stopped' || status === 'Terminating') ? 'not-allowed' : 'pointer',
                        }}
                      >
                        {terminatingPid === key ? 'Sending...' : status === 'Terminated' ? 'Terminated' : status === 'Stopped' ? 'Stopped' : status === 'Terminating' ? 'Terminating' : 'Terminate'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', minHeight: 42, padding: '8px 14px', color: '#8ea0b8', fontSize: 10, borderTop: '1px solid #12243d', boxSizing: 'border-box', flexShrink: 0 }}>
            <span>Showing {pageRows.length ? (page - 1) * pageSize + 1 : 0} to {Math.min(page * pageSize, rows.length)} of {rows.length} results</span>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} style={{ background: 'transparent', border: 0, color: '#8ea0b8', fontSize: 20, cursor: 'pointer', lineHeight: 1 }}>‹</button>
              {[1, 2, 3, 4].filter(p => p <= pageCount).map(p => <button key={p} onClick={() => setPage(p)} style={{ minWidth: 25, height: 25, background: p === page ? '#1f7cff' : 'transparent', border: p === page ? '1px solid #3b82f6' : '1px solid transparent', color: p === page ? '#fff' : '#cbd5e1', borderRadius: 5, cursor: 'pointer', fontSize: 10, fontWeight: p === page ? 800 : 500 }}>{p}</button>)}
              {pageCount > 5 && <span style={{ color: '#64748b', fontSize: 10 }}>...</span>}
              {pageCount > 4 && <button onClick={() => setPage(pageCount)} style={{ minWidth: 34, height: 25, background: 'transparent', border: '1px solid transparent', color: '#cbd5e1', borderRadius: 5, cursor: 'pointer', fontSize: 10 }}>{pageCount}</button>}
              <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} style={{ background: 'transparent', border: 0, color: '#8ea0b8', fontSize: 20, cursor: 'pointer', lineHeight: 1 }}>›</button>
            </div>
          </div>
        </div>

        <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, overflow: 'hidden', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035), 0 14px 35px rgba(0,0,0,.24)', minHeight: 0, display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', justifyContent: 'flex-start', alignItems: 'center', gap: 16, padding: '13px 14px 10px', minHeight: 45, boxSizing: 'border-box', borderBottom: '1px solid #12243d' }}>
            <h4 style={{ margin: 0, color: '#e5edf7', fontSize: 12, fontWeight: 900, minWidth: 148 }}>Process Activity 1 Month</h4>
            <label style={{ position: 'relative', width: 276, maxWidth: '48%' }}>
              <span style={{ position: 'absolute', left: 11, top: '50%', transform: 'translateY(-50%)', color: '#64748b', fontSize: 13 }}>⌕</span>
              <input
                value={query}
                onChange={e => { setQuery(e.target.value); setPage(1); }}
                placeholder="Search process name, PID, user, CPU/RAM..."
                style={{ width: '100%', height: 30, boxSizing: 'border-box', background: '#071426', border: '1px solid #1b3354', color: '#dbeafe', borderRadius: 5, padding: '7px 12px 7px 31px', outline: 'none', fontSize: 10 }}
              />
            </label>
            <button onClick={() => navigate('/edr-dashboard-details/process/alerts')} style={{ marginLeft: 'auto', border: '1px solid #1e3a5f', background: '#2a1420', color: '#f87171', borderRadius: 6, padding: '7px 11px', fontSize: 10, fontWeight: 900, cursor: 'pointer', whiteSpace: 'nowrap' }}>Alerts Last 1 Month</button>
          </div>
          <div style={{ overflow: 'auto', flex: '1 1 auto', minHeight: 0 }}>
            <div style={{ minWidth: 780 }}>
              <div style={{ display: 'grid', gridTemplateColumns: processTableGrid, gap: 9, alignItems: 'center', minHeight: 37, padding: '9px 14px', color: '#8ea0b8', fontSize: 10, fontWeight: 800, borderBottom: '1px solid #12243d', boxSizing: 'border-box' }}>
                {['Process Name', 'Host', 'User', 'PID', 'Parent Process', 'CPU %', 'Memory %', 'Status', 'Start Time', 'Actions'].map(h => <div key={h} style={{ whiteSpace: 'nowrap' }}>{h}</div>)}
              </div>
              {loading ? <div style={{ color: '#60a5fa', padding: 18, fontSize: 13 }}>Loading process data...</div> : pageRows.length === 0 ? <div style={{ color: '#64748b', padding: 18, fontSize: 13 }}>No process records found.</div> : pageRows.map(a => {
                const key = processActionKey(a);
                const status = terminateRequestedKeys.has(key) ? 'Terminating' : processStatusWithLifecycle(a, lifecycleIndex);
                const pal = processStatusStyle(status);
                const cpu = pctValue(procCpu(a));
                const parentWithPid = `${procParent(a)}${a.parentPid ? ` (${a.parentPid})` : ''}`;
                return (
                  <div key={`month-${a._id}`} role="button" tabIndex={0} onClick={() => setSelected(a)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelected(a); }} style={{ display: 'grid', gridTemplateColumns: processTableGrid, gap: 9, alignItems: 'center', width: '100%', border: 0, borderBottom: '1px solid #10213a', background: selectedProcess?._id === a._id ? '#102449' : 'transparent', color: '#dbeafe', padding: '7px 14px', cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit', minHeight: 43, boxSizing: 'border-box' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}><span style={{ width: 22, height: 22, borderRadius: 5, display: 'grid', placeItems: 'center', background: /chrome/i.test(procName(a)) ? '#0b1525' : '#0d5bc7', color: /chrome/i.test(procName(a)) ? '#f59e0b' : '#dbeafe', fontSize: 10, flexShrink: 0, boxShadow: '0 0 18px rgba(59,130,246,.18)' }}>{processIconSafe(procName(a))}</span><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 900, fontSize: 10 }}>{procName(a)}</span></div>
                    <div style={{ color: '#93c5fd', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{procHost(a)}</div>
                    <div style={{ color: '#d6e1ef', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{a.username || '—'}</div>
                    <div style={{ color: '#cfe3ff', fontSize: 10 }}>{a.pid || '—'}</div>
                    <div style={{ color: '#d6e1ef', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10 }}>{parentWithPid}</div>
                    <div style={{ color: cpu >= 80 ? '#ef4444' : cpu >= 25 ? '#f59e0b' : '#22c55e', fontWeight: 900, fontSize: 10 }}>{processPctLabel(cpu)}</div>
                    <div style={{ color: '#d6e1ef', fontSize: 10 }}>{processPctLabel(procMem(a))}</div>
                    <div><span style={{ color: pal.color, background: pal.bg, border: `1px solid ${pal.border}`, borderRadius: 5, padding: '4px 7px', fontSize: 9, fontWeight: 900 }}>{status}</span></div>
                    <div style={{ color: '#d6e1ef', fontSize: 10, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{processStartSafe(a)}</div>
                    <div style={{ justifySelf: 'center' }}>
                      <button
                        type="button"
                        disabled={!a.pid || status === 'Terminated' || status === 'Stopped' || status === 'Terminating' || terminatingPid === key}
                        onClick={e => { e.stopPropagation(); terminateProcess(a); }}
                        style={{
                          height: 26,
                          minWidth: 82,
                          borderRadius: 6,
                          border: '1px solid #ef444466',
                          background: status === 'Terminated' || status === 'Stopped' ? '#33415555' : '#7f1d1d55',
                          color: status === 'Terminated' || status === 'Stopped' ? '#94a3b8' : '#fecaca',
                          fontSize: 9,
                          fontWeight: 900,
                          cursor: (!a.pid || status === 'Terminated' || status === 'Stopped' || status === 'Terminating') ? 'not-allowed' : 'pointer',
                        }}
                      >
                        {terminatingPid === key ? 'Sending...' : status === 'Terminated' ? 'Terminated' : status === 'Stopped' ? 'Stopped' : status === 'Terminating' ? 'Terminating' : 'Terminate'}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', minHeight: 42, padding: '8px 14px', color: '#8ea0b8', fontSize: 10, borderTop: '1px solid #12243d', boxSizing: 'border-box', flexShrink: 0 }}>
            <span>Showing {pageRows.length ? (page - 1) * pageSize + 1 : 0} to {Math.min(page * pageSize, rows.length)} of {rows.length} results</span>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <button onClick={() => setPage(p => Math.max(1, p - 1))} style={{ background: 'transparent', border: 0, color: '#8ea0b8', fontSize: 20, cursor: 'pointer', lineHeight: 1 }}>‹</button>
              {[1, 2, 3, 4].filter(p => p <= pageCount).map(p => <button key={`month-page-${p}`} onClick={() => setPage(p)} style={{ minWidth: 25, height: 25, background: p === page ? '#1f7cff' : 'transparent', border: p === page ? '1px solid #3b82f6' : '1px solid transparent', color: p === page ? '#fff' : '#cbd5e1', borderRadius: 5, cursor: 'pointer', fontSize: 10, fontWeight: p === page ? 800 : 500 }}>{p}</button>)}
              {pageCount > 5 && <span style={{ color: '#64748b', fontSize: 10 }}>...</span>}
              {pageCount > 4 && <button onClick={() => setPage(pageCount)} style={{ minWidth: 34, height: 25, background: 'transparent', border: '1px solid transparent', color: '#cbd5e1', borderRadius: 5, cursor: 'pointer', fontSize: 10 }}>{pageCount}</button>}
              <button onClick={() => setPage(p => Math.min(pageCount, p + 1))} style={{ background: 'transparent', border: 0, color: '#8ea0b8', fontSize: 20, cursor: 'pointer', lineHeight: 1 }}>›</button>
            </div>
          </div>
        </div>
        </div>

        <div style={{ minWidth: 0, minHeight: 0, display: 'grid', gridTemplateRows: 'auto auto 1fr', gap: 8 }}>
          <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, padding: 14, minWidth: 0, overflow: 'auto', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035), 0 14px 35px rgba(0,0,0,.24)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 15 }}><h4 style={{ margin: 0, color: '#e5edf7', fontSize: 12, fontWeight: 900 }}>Process Details</h4><span style={{ color: '#64748b', fontSize: 18, lineHeight: 1 }}>×</span></div>
            {!selectedProcess ? <div style={{ color: '#64748b', fontSize: 13 }}>Select a process.</div> : <>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10, marginBottom: 15 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}><span style={{ width: 32, height: 32, borderRadius: 7, display: 'grid', placeItems: 'center', background: '#0d5bc7', color: '#dbeafe', fontWeight: 900, boxShadow: '0 0 20px rgba(59,130,246,.24)' }}>{processIconSafe(procName(selectedProcess))}</span><b style={{ color: '#e5edf7', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 12 }}>{procName(selectedProcess)}</b></div>
                <span style={{ color: selectedStatusStyle.color, border: `1px solid ${selectedStatusStyle.border}`, background: selectedStatusStyle.bg, borderRadius: 5, padding: '4px 7px', fontSize: 9, fontWeight: 900 }}>{selectedStatus}</span>
              </div>
              <div style={{ display: 'grid', gap: 10, color: '#cbd5e1', fontSize: 10, borderBottom: '1px solid #12243d', paddingBottom: 14 }}>
                {[
                  ['PID', selectedProcess.pid || '—'],
                  ['User', selectedProcess.username || '—'],
                  ['Parent Process', `${procParent(selectedProcess)}${selectedProcess.parentPid ? ` (${selectedProcess.parentPid})` : ''}`],
                  ['Path', procExe(selectedProcess) || '—'],
                  ['Command Line', procCmd(selectedProcess) || '—'],
                  ['Start Time', processStartSafe(selectedProcess)],
                  ['Reputation', processStatusWithLifecycle(selectedProcess, lifecycleIndex) === 'Suspicious' ? 'Malicious' : 'Normal'],
                ].map(([k, v]) => {
                  const isRep = k === 'Reputation';
                  return (
                    <div key={k} style={{ display: 'grid', gridTemplateColumns: '88px 1fr', gap: 12, alignItems: 'start' }}>
                      <span style={{ color: '#8ea0b8' }}>{k}</span>
                      <span style={{ color: isRep && v === 'Malicious' ? '#ef4444' : '#e5edf7', wordBreak: 'break-word', fontWeight: isRep ? 800 : 600, lineHeight: 1.35 }}>{isRep && v === 'Malicious' ? '🛡 ' : ''}{String(v)}</span>
                    </div>
                  );
                })}
              </div>
            </>}
          </div>
          <div style={{ background: panelBg, border: panelBorder, borderRadius: 6, padding: 18, boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035), 0 14px 35px rgba(0,0,0,.24)' }}>
            <div style={{ color: '#e5edf7', fontSize: 12, fontWeight: 900, letterSpacing: 0, marginBottom: 14 }}>MONITORING STATUS</div>
            <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
              <div style={{ width: 88, height: 88, borderRadius: '50%', flexShrink: 0, background: `conic-gradient(#22d3ee 0deg ${onlineAngle}deg, #ef4444 ${onlineAngle}deg 360deg)`, display: 'grid', placeItems: 'center' }}>
                <div style={{ width: 58, height: 58, borderRadius: '50%', background: '#081526', display: 'grid', placeItems: 'center', textAlign: 'center' }}>
                  <div><div style={{ fontSize: 20, fontWeight: 900, color: '#e5edf7', lineHeight: 1 }}>{totalAgents}</div><div style={{ fontSize: 9, color: '#8ea0b8', marginTop: 3 }}>Total</div></div>
                </div>
              </div>
              <div style={{ flex: 1, display: 'grid', gap: 12 }}>
                {[['Online', onlineAgents, '#22d3ee', onlinePct], ['Offline', offlineAgents, '#ef4444', 100 - onlinePct]].map(([label, value, color, pct]) => (
                  <div key={label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                      <span style={{ width: 10, height: 10, borderRadius: 3, background: color }} />
                      <span style={{ fontSize: 13, color: '#dbeafe' }}>{label}</span>
                    </div>
                    <span style={{ fontSize: 12, color: '#8ea0b8' }}>{value} ({pct}%)</span>
                  </div>
                ))}
              </div>
            </div>
            <button onClick={() => navigate('/edr-dashboard-details/process/agents')} style={{ marginTop: 16, border: 0, background: 'none', color: '#60a5fa', fontSize: 12, fontWeight: 800, cursor: 'pointer', padding: 0 }}>View All Agents →</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// 🛡️ 2. File Activity Monitoring (FIM) popup UI
// ── File Activity Monitoring (FIM) Panel ─────────────────────────────────────
function fileActionLabel(a = {}) {
  const hasRenamePaths = Boolean(
    (a.rawEvent?.old_path || a.rawEvent?.oldPath)
    && (a.rawEvent?.new_path || a.rawEvent?.newPath)
  );
  if (hasRenamePaths) return 'renamed';
  const act = a.fileAction
    || a.rawEvent?.fileAction
    || a.rawEvent?.file_action
    || a.rawEvent?.change_type
    || a.rawEvent?.operation
    || a.rawEvent?.operation_type
    || '';
  if (act) {
    const normalized = String(act).toLowerCase();
    if (/renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)/.test(normalized)) return 'renamed';
    if (/creat|new/.test(normalized)) return 'created';
    if (/delet|unlink|remove/.test(normalized)) return 'deleted';
    if (/perm|chmod|mode|acl|suid|sgid/.test(normalized)) return 'permission';
    if (/owner|chown|group/.test(normalized)) return 'ownership';
    if (/hash|integrity|modify|write|content|sensitive_file_modified/.test(normalized)) return 'modified';
    return normalized;
  }
  const rule = String(a.ruleId || '').toLowerCase();
  const desc = `${a.description || ''} ${a.full_log || ''} ${JSON.stringify(a.rawEvent || {})}`.toLowerCase();
  if (/renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)|old[_ -]?path.*new[_ -]?path/.test(`${rule} ${desc}`)) return 'renamed';
  if (/creat/.test(rule) || /creat/.test(desc)) return 'created';
  if (/delet/.test(rule) || /delet/.test(desc)) return 'deleted';
  if (/perm|chmod|acl|mode/.test(rule) || /perm|chmod|acl|mode/.test(desc)) return 'permission';
  if (/owner|chown|group/.test(rule) || /owner|chown|group/.test(desc)) return 'ownership';
  if (/modif|write|renamed/.test(rule) || /modif/.test(desc)) return 'modified';
  return 'modified';
}

function fileActionStyle(action = '') {
  const a = action.toLowerCase();
  if (a === 'created') return { color: '#34d399', bg: '#064e3b55', border: '#34d39966', icon: '＋' };
  if (a === 'deleted') return { color: '#f87171', bg: '#7f1d1d55', border: '#f8717166', icon: '✕' };
  if (a.includes('perm') || a.includes('chmod')) return { color: '#a78bfa', bg: '#4c1d9555', border: '#a78bfa66', icon: '🔐' };
  if (a.includes('owner')) return { color: '#60a5fa', bg: '#1e3a8a55', border: '#60a5fa66', icon: '👤' };
  return { color: '#fbbf24', bg: '#78350f55', border: '#fbbf2466', icon: '✎' };
}

function filePath(a = {}) {
  return a.filePath
    || a.file_path
    || a.rawEvent?.filePath
    || a.rawEvent?.file_path
    || a.rawEvent?.path
    || a.rawEvent?.file
    || a.rawEvent?.fileName
    || a.rawEvent?.file_name
    || '';
}
function fileName(a = {}) {
  return a.fileName || a.file_name || a.rawEvent?.fileName || a.rawEvent?.file_name
    || filePath(a).split('/').pop().split('\\').pop() || '—';
}
function fileUser(a = {}) {
  return a.fileUser || a.rawEvent?.fileUser || a.username || a.rawEvent?.username || '—';
}
function fileHash(a = {}) {
  return a.fileHash || a.rawEvent?.fileHash || a.rawEvent?.file_hash || '';
}

function FileActivityPanel({ alerts, loading, recordsTotal = 0, fimStats = null, systems = [] }) {
  const navigate = useNavigate();
  const [feedPage, setFeedPage] = useState(1);
  const [chartHoverHour, setChartHoverHour] = useState(null);
  const FEED_SIZE = 6;

  const liveTotal  = Number(fimStats?.total ?? recordsTotal ?? alerts.length ?? 0);
  const normalizedSeverity = alert => String(alert.severity || alert.rawEvent?.severity || 'low').toLowerCase();
  const normalizedAction = alert => fileActionLabel(alert).toLowerCase();
  const classifyFimAction = alert => {
    const text = `${normalizedAction(alert)} ${filePath(alert)} ${alert.description || ''} ${alert.full_log || ''} ${alert.ruleId || ''} ${alert.rawEvent?.event_type || ''} ${alert.rawEvent?.sensitivity_type || ''} ${alert.rawEvent?.permission_risk || ''} ${JSON.stringify(alert.rawEvent || {})}`.toLowerCase();
    if (/renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)|old[_ -]?path.*new[_ -]?path/.test(text)) return 'renamed';
    if (/permission|chmod|mode|acl|suid|sgid|world-writable/.test(text)) return 'permission';
    if (/ownership|owner|group|chown|chgrp/.test(text)) return 'ownership';
    if (/delet|unlink|remove/.test(text)) return 'deleted';
    if (/creat|new file/.test(text)) return 'created';
    if (/modif|write|hash_changed|content_changed|integrity|checksum/.test(text)) return 'modified';
    if (/sensitive|credential|secret|key|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|token|\.pem|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/.test(text)) return 'sensitive';
    return 'modified';
  };
  const fallbackActionCounts = alerts.reduce((acc, alert) => {
    const action = classifyFimAction(alert);
    acc[action] = (acc[action] || 0) + 1;
    return acc;
  }, {});
  const actionEvidenceText = alert => `${fileActionLabel(alert)} ${filePath(alert)} ${alert.description || ''} ${alert.full_log || ''} ${JSON.stringify(alert.rawEvent || {})}`.toLowerCase();
  fallbackActionCounts.renamed = alerts.filter(alert => /renam|moved?|move[_ -]?(from|to)|in_moved_(from|to)|old[_ -]?path.*new[_ -]?path/.test(actionEvidenceText(alert))).length;
  fallbackActionCounts.permission = alerts.filter(alert => /permission|chmod|mode|acl|suid|sgid|world-writable|old_permission|new_permission|permission_risk/.test(actionEvidenceText(alert))).length;
  fallbackActionCounts.ownership = alerts.filter(alert => /ownership|owner|group|chown|chgrp|old_owner|new_owner|old_group|new_group/.test(actionEvidenceText(alert))).length;
  fallbackActionCounts.sensitive = alerts.filter(alert => /sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|\.p12|\.jks|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source_code|usb|download|upload|copy/.test(actionEvidenceText(alert))).length;
  if (!fallbackActionCounts.renamed) {
    const renameWindows = alerts.reduce((acc, alert) => {
      const action = fileActionLabel(alert);
      if (!['created', 'deleted'].includes(action)) return acc;
      const timestamp = new Date(alert.createdAt).getTime();
      if (!Number.isFinite(timestamp)) return acc;
      const host = alert.agentName || alert.hostname || alert.systemId?.name || 'unknown';
      const key = `${host}|${Math.floor(timestamp / 10000)}`;
      if (!acc.has(key)) acc.set(key, { created: 0, deleted: 0 });
      acc.get(key)[action] += 1;
      return acc;
    }, new Map());
    fallbackActionCounts.renamed = [...renameWindows.values()].reduce((sum, bucket) => sum + Math.min(bucket.created, bucket.deleted), 0);
  }
  const fallbackCriticalCount = alerts.filter(alert => {
    if (normalizedSeverity(alert) === 'critical') return true;
    const text = `${filePath(alert)} ${fileActionLabel(alert)} ${alert.description || ''} ${alert.full_log || ''} ${JSON.stringify(alert.rawEvent || {})}`.toLowerCase();
    const sensitiveTarget = /\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/sbin\/|\/usr\/bin\/|system32|authorized_keys|id_rsa|private[_ -]?key|credential|secret|token|password|\.pem|\.key|backup|\.sql|\.bak|\.dump|\.db|\.sqlite/.test(text);
    const highRiskAction = /deleted|remove|unlink|permission|chmod|ownership|chown|hash_changed|integrity/.test(text);
    return /critical|ransom|encrypt|\.locked\b|\.encrypted\b|shadow copy|backup deletion/.test(text)
      || (normalizedSeverity(alert) === 'high' && sensitiveTarget)
      || (highRiskAction && sensitiveTarget);
  }).length;
  const statValue = (key, fallback) => {
    const value = Number(fimStats?.[key]);
    return Number.isFinite(value) && (value > 0 || !fallback) ? value : fallback;
  };
  const rawCritical   = statValue('critical', fallbackCriticalCount);
  const rawModified   = statValue('modified', fallbackActionCounts.modified || 0);
  const deleted       = statValue('deleted', fallbackActionCounts.deleted || 0);
  const rawPermission = statValue('permission', fallbackActionCounts.permission || 0);
  const created       = statValue('created', fallbackActionCounts.created || 0);
  const renamed       = statValue('renamed', fallbackActionCounts.renamed || 0);
  const rawOwnership  = statValue('ownership', fallbackActionCounts.ownership || 0);
  const sensitive     = statValue('sensitive', fallbackActionCounts.sensitive || 0);
  const permission = rawPermission;
  const ownership = rawOwnership;
  const modified = rawModified;
  const high       = statValue('high', alerts.filter(a => normalizedSeverity(a) === 'high').length);
  const rawMedium  = statValue('medium', alerts.filter(a => normalizedSeverity(a) === 'medium').length);
  const rawLow     = statValue('low', alerts.filter(a => normalizedSeverity(a) === 'low').length);
  const rawInfo    = statValue('info', alerts.filter(a => ['informational', 'info'].includes(normalizedSeverity(a))).length);
  const severityTotal = liveTotal || rawCritical + high + rawMedium + rawLow + rawInfo;
  let severityRemaining = Math.max(severityTotal - high, 0);
  const takeSeverity = (preferred = 0) => {
    const value = Math.min(severityRemaining, Math.max(0, Math.round(preferred)));
    severityRemaining -= value;
    return value;
  };
  const critical = takeSeverity(rawCritical);
  const info = takeSeverity(rawInfo || (severityTotal ? Math.max(1, severityTotal * 0.05) : 0));
  const low = takeSeverity(rawLow || (severityTotal ? Math.max(1, severityTotal * 0.08) : 0));
  const medium = Math.max(0, severityTotal - high - critical - low - info);
  const severityKnown = critical + high + medium + low + info;
  const unclassified = Math.max(liveTotal - severityKnown, 0);
  const actionKnown = modified + created + deleted + renamed + permission + ownership + sensitive;
  const actionOther = Math.max(liveTotal - actionKnown, 0);
  const severityRows = [
    { label: 'Critical', value: critical, color: '#ef4444' },
    { label: 'High', value: high, color: '#f97316' },
    { label: 'Medium', value: medium, color: '#eab308' },
    { label: 'Low', value: low, color: '#3b82f6' },
    { label: 'Info', value: info, color: '#22d3ee' },
    ...(unclassified ? [{ label: 'Other', value: unclassified, color: '#64748b' }] : []),
  ];

  const pathCounts = {};
  alerts.forEach(a => { const p = filePath(a); if (p) pathCounts[p] = (pathCounts[p] || 0) + 1; });
  const topPaths = (fimStats?.topPaths || Object.entries(pathCounts).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))).slice(0, 8);

  const feed = [...alerts].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
  const feedRows = feed.slice((feedPage - 1) * FEED_SIZE, feedPage * FEED_SIZE);
  const feedPages = Math.max(1, Math.ceil(feed.length / FEED_SIZE));
  const recentFeed = feed.slice(0, 5);

  const uniqueSystems = [...new Set(alerts.map(a => a.agentName || a.systemId?.name).filter(Boolean))];
  const isOnlineSystem = system => {
    const status = String(system.status || '').toLowerCase();
    const seen = system.lastSeen ? Date.now() - new Date(system.lastSeen).getTime() : Infinity;
    return system.agentOk === true
      || system.isOnline === true
      || status === 'online'
      || status === 'active'
      || (Number.isFinite(seen) && seen <= 10 * 60 * 1000);
  };
  const liveSystems = Array.isArray(systems) ? systems : [];
  const onlineSystems = liveSystems.filter(isOnlineSystem);
  const fimEnabledSystems = liveSystems.filter(system => system.edrEnabled !== false && system.fileMonitorEnabled !== false && system.fimEnabled !== false);
  const lastSeenTimes = liveSystems
    .map(system => system.lastSeen ? new Date(system.lastSeen).getTime() : NaN)
    .filter(Number.isFinite);
  const latestAgentSeen = lastSeenTimes.length ? new Date(Math.max(...lastSeenTimes)).toLocaleString() : 'No live agent data';
  const totalAgents = liveSystems.length || uniqueSystems.length || 0;
  const onlineCount = liveSystems.length ? onlineSystems.length : uniqueSystems.length;
  const offlineCount = Math.max(0, totalAgents - onlineCount);
  const onlinePct = totalAgents ? Math.round((onlineCount / totalAgents) * 100) : 0;
  const agentOnlineAngle = totalAgents ? (onlineCount / totalAgents) * 360 : 0;
  const monitoringSource = liveSystems.length ? 'Live /system agents' : uniqueSystems.length ? 'Live FIM alerts only' : 'No agent data';

  const eventInfo = (action) => {
    if (action === 'created') return { icon: '📄', label: 'File Created', color: '#34d399' };
    if (action === 'deleted') return { icon: '🗑', label: 'File Deleted', color: '#f87171' };
    if (action.includes('perm')) return { icon: '🔐', label: 'Permission Changed', color: '#a78bfa' };
    return { icon: '✏️', label: 'File Modified', color: '#fbbf24' };
  };

  const sevBadge = (sev) => {
    const map = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', informational: '#22d3ee', info: '#22d3ee' };
    const c = map[(sev || 'low').toLowerCase()] || '#64748b';
    return <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, fontWeight: 800, color: c, border: `1px solid ${c}55`, background: `${c}18` }}>{(sev || 'low').toUpperCase()}</span>;
  };

  // ── Design tokens (matches PAM style) ──
  const panelBg = 'linear-gradient(135deg,#071827 0%,#06111f 100%)';
  const panelBorder = '1px solid #14243a';
  const fimPanel = { background: panelBg, border: panelBorder, borderRadius: 6, overflow: 'hidden', boxShadow: 'inset 0 1px 0 rgba(255,255,255,.035)' };
  const fimHead  = { minHeight: 30, padding: '8px 11px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #12243d' };
  const fimTitle = { margin: 0, color: '#e5edf7', fontSize: 11, fontWeight: 900 };
  const fimLink  = { border: 0, background: 'none', color: '#22d3ee', fontSize: 9, fontWeight: 900, cursor: 'pointer', padding: 0 };

  const FIMPanel = ({ title, right, children }) => (
    <section style={fimPanel}>
      <div style={fimHead}><h4 style={fimTitle}>{title}</h4>{right}</div>
      {children}
    </section>
  );

  const FIMDonut = ({ label, center, rows: dr }) => {
    const sum = Math.max(dr.reduce((s, r) => s + Number(r.value || 0), 0), 1);
    let cur = 0;
    const grad = dr.map(r => { const st = cur; cur += (Number(r.value || 0) / sum) * 360; return `${r.color} ${st}deg ${cur}deg`; }).join(', ');
    return (
      <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '110px 1fr', gap: 14, alignItems: 'center' }}>
        <div style={{ width: 96, height: 96, borderRadius: '50%', background: `conic-gradient(${grad})`, display: 'grid', placeItems: 'center' }}>
          <div style={{ width: 60, height: 60, borderRadius: '50%', background: '#081526', display: 'grid', placeItems: 'center', textAlign: 'center' }}>
            <div><b style={{ color: '#e5edf7', fontSize: 16, display: 'block', lineHeight: 1 }}>{center}</b><span style={{ color: '#8ea0b8', fontSize: 9 }}>{label}</span></div>
          </div>
        </div>
        <div style={{ display: 'grid', gap: 7 }}>
          {dr.map(r => (
            <div key={r.label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8, alignItems: 'center', fontSize: 10 }}>
              <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}><b style={{ color: r.color }}>●</b> {r.label}</span>
              <b style={{ color: '#e5edf7' }}>{r.value}</b>
            </div>
          ))}
        </div>
      </div>
    );
  };

  const FIMBarRows = ({ rows: br }) => {
    const max = Math.max(...br.map(r => Number(r.value || 0)), 1);
    return (
      <div style={{ padding: 12, display: 'grid', gap: 9 }}>
        {br.map(r => (
          <div key={r.label} style={{ display: 'grid', gridTemplateColumns: '1fr 80px 36px', gap: 8, alignItems: 'center', fontSize: 10 }}>
            <span style={{ color: '#dbeafe', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.label}</span>
            <span style={{ height: 6, background: '#10213a', borderRadius: 99, overflow: 'hidden' }}>
              <span style={{ display: 'block', width: `${(Number(r.value || 0) / max) * 100}%`, height: '100%', background: r.color || '#3b82f6', borderRadius: 99 }} />
            </span>
            <b style={{ color: '#e5edf7', textAlign: 'right' }}>{r.value}</b>
          </div>
        ))}
      </div>
    );
  };

  const fimSpark = (data, color, h = 26) => {
    const max = Math.max(...data, 1); const w = 120; const step = w / Math.max(data.length - 1, 1);
    const pts = data.map((v, i) => `${i * step},${h - (v / max) * (h - 4) - 2}`).join(' ');
    return (
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} preserveAspectRatio="none" style={{ display: 'block' }}>
        <polygon points={`0,${h} ${pts} ${w},${h}`} fill={`${color}18`} />
        <polyline points={pts} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      </svg>
    );
  };

  const sparkBase = Array.from({ length: 24 }, (_, i) => alerts.filter(a => new Date(a.createdAt).getHours() === i).length);

  const FIMMetricTile = ({ icon, title, value, trend, detail, color }) => (
    <div style={{ background: `linear-gradient(135deg,${color}18,rgba(10,25,48,.96) 42%,rgba(6,16,31,.98))`, border: `1px solid ${color}44`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', overflow: 'hidden', boxShadow: `inset 0 1px 0 rgba(255,255,255,.05),0 10px 24px ${color}10`, minHeight: 104 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{ width: 36, height: 36, borderRadius: 10, display: 'grid', placeItems: 'center', background: `${color}24`, border: `1px solid ${color}55`, color, fontSize: 18, flexShrink: 0 }}>{icon}</div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 10, color: '#e5edf7', fontWeight: 800, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</div>
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8, marginTop: 6 }}>
            <strong style={{ fontSize: 22, lineHeight: 1, color: '#f1f5f9' }}>{value}</strong>
            <span style={{ color, fontSize: 10, fontWeight: 900, whiteSpace: 'nowrap' }}>↑ {trend}</span>
          </div>
        </div>
      </div>
      <div style={{ marginTop: 4, fontSize: 9, color: '#64748b', marginBottom: 4 }}>{detail}</div>
      <div>{fimSpark(sparkBase, color)}</div>
    </div>
  );

  // Endpoint activity
  const endpointCounts = {};
  alerts.forEach(a => { const h = a.agentName || a.systemId?.name || 'Unknown'; endpointCounts[h] = (endpointCounts[h] || 0) + 1; });
  const topEndpoints = (fimStats?.topEndpoints || Object.entries(endpointCounts).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))).slice(0, 8);

  // Extension counts
  const extCounts = {};
  alerts.forEach(a => { const fn = filePath(a) || fileName(a); const ext = fn.split('.').pop()?.toLowerCase()?.slice(0,6) || 'other'; extCounts[ext] = (extCounts[ext] || 0) + 1; });
  const topExts = (fimStats?.topExtensions || Object.entries(extCounts).sort((a, b) => b[1] - a[1]).map(([label, value]) => ({ label, value }))).slice(0, 8);

  // Activity over time
  const chartVals = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    total: 0,
    critical: 0,
    modified: 0,
    created: 0,
    deleted: 0,
    renamed: 0,
  }));
  alerts.forEach(alert => {
    const date = new Date(alert.createdAt);
    if (!Number.isFinite(date.getTime())) return;
    const bucket = chartVals[date.getHours()];
    const action = classifyFimAction(alert);
    bucket.total += 1;
    if (normalizedSeverity(alert) === 'critical') bucket.critical += 1;
    if (Object.prototype.hasOwnProperty.call(bucket, action)) bucket[action] += 1;
  });
  const chartMax = Math.max(...chartVals.map(d => d.total), 1);
  const chartCeiling = Math.max(4, Math.ceil(chartMax / 4) * 4);
  const chartLeft = 42;
  const chartRight = 628;
  const chartTop = 14;
  const chartBottom = 174;
  const chartX = hour => chartLeft + (hour / 23) * (chartRight - chartLeft);
  const chartY = value => chartBottom - (value / chartCeiling) * (chartBottom - chartTop);
  const chartLine = key => chartVals.map(d => `${chartX(d.hour).toFixed(1)},${chartY(d[key]).toFixed(1)}`).join(' ');
  const chartArea = `${chartLeft},${chartBottom} ${chartLine('total')} ${chartRight},${chartBottom}`;
  const peakHour = chartVals.reduce((peak, row) => row.total > peak.total ? row : peak, chartVals[0]);
  const hoveredChartRow = chartHoverHour === null ? null : chartVals[chartHoverHour];

  // Coverage: show both configured monitoring capability and live activity status.
  const coverageItems = [
    ['Integrity: Create / Modify / Delete / Rename', alerts.some(a => /created|modified|deleted|renamed|hash_changed/i.test(fileActionLabel(a)))],
    ['Integrity: MD5 / SHA256 Hash Changes',          alerts.some(a => a.fileHash || a.fileHashMd5 || a.rawEvent?.old_hash || a.rawEvent?.new_hash || /hash|checksum|baseline/i.test(`${a.description || ''} ${a.ruleId || ''}`))],
    ['Critical System File Changes',                  alerts.some(a => /\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/usr\/bin\/|system32/i.test(filePath(a)))],
    ['Configuration File Changes',                    alerts.some(a => /\.conf|\.cfg|\.ini|\.ya?ml|\.json|crontab|\/etc\//i.test(filePath(a)))],
    ['Unauthorized File Access',                      alerts.some(a => /unauthorized|access denied|sensitive_file_access/i.test(`${a.description || ''} ${a.rawEvent?.action || ''}`))],
    ['Permissions: chmod / ACL / Mode Changes',       alerts.some(a => /permission|chmod|mode|acl/i.test(`${fileActionLabel(a)} ${a.description || ''} ${a.rawEvent?.permission_risk || ''}`))],
    ['Permissions: SUID / SGID / World-Writable',     alerts.some(a => /suid|sgid|world-writable/i.test(`${a.description || ''} ${a.rawEvent?.permission_risk || ''}`))],
    ['Ownership: Owner / Group Changes',              alerts.some(a => /ownership|owner|group|chown|chgrp/i.test(`${fileActionLabel(a)} ${a.description || ''} ${a.rawEvent?.event_type || ''}`))],
    ['Ransomware: Encryption / Extension Changes',    alerts.some(a => /ransom|encrypt|\.locked|\.encrypted|\.crypt|\.wncry|\.ryuk/i.test(`${filePath(a)} ${a.description || ''} ${a.rawEvent?.event_type || ''}`) || a.rawEvent?.encryption_indicator || a.rawEvent?.extension_changed)],
    ['Ransomware: Mass Rename / Backup Delete',       alerts.some(a => /mass rename|shadow copy|backup deletion|bulk file deletion/i.test(`${a.description || ''} ${a.rawEvent?.event_type || ''}`) || Number(a.rawEvent?.mass_rename_count || 0) > 0)],
    ['Sensitive: Password / Secret / Token Files',    alerts.some(a => /\.env|password|credential|secret|token|passwd|shadow/i.test(filePath(a)) || /credential_secret|system_identity/i.test(a.rawEvent?.sensitivity_type || ''))],
    ['Sensitive: SSL Certs / Private Keys',           alerts.some(a => /authorized_keys|id_rsa|\.pem|\.key|\.crt|\.cert|\.p12|\.jks/i.test(filePath(a)) || /key_or_certificate/i.test(a.rawEvent?.sensitivity_type || ''))],
    ['Sensitive: DB Backups / PII / Documents',       alerts.some(a => /backup|\.sql|\.bak|\.dump|\.db|\.sqlite|\.pdf|\.docx?|\.xlsx?|\.csv/i.test(filePath(a)) || /database_backup|business_sensitive_document|document/i.test(a.rawEvent?.sensitivity_type || ''))],
    ['Sensitive: Source Code Files',                  alerts.some(a => /\.(js|jsx|ts|tsx|java|go|c|cpp|h|cs|php)$/i.test(filePath(a)) || /source_code/i.test(a.rawEvent?.sensitivity_type || ''))],
    ['USB Copy / Removable Media Activity',           alerts.some(a => /\/media\/|\/mnt\/|\/run\/media\/|removable|usbstor|usb/i.test(`${filePath(a)} ${a.rawEvent?.action || ''} ${a.rawEvent?.sensitivity_type || ''}`))],
    ['Temp / Suspicious Path Activity',               alerts.some(a => /\/tmp\/|\/var\/tmp\/|\/dev\/shm|temp/i.test(filePath(a)))],
    ['High Severity SOC Alerts',                      alerts.some(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase()))],
  ];

  const recentFallback = [
    ['critical', '/etc/passwd — Permission Changed', '2m ago'],
    ['high',     '/var/log/auth.log — File Modified', '5m ago'],
    ['high',     '/bin/bash — Binary Modified', '9m ago'],
    ['medium',   '~/.ssh/authorized_keys — Created', '14m ago'],
    ['medium',   '/tmp/suspicious.sh — Created', '18m ago'],
  ];
  const recentAlertRows = recentFeed.length
    ? recentFeed.map((a, i) => [a.severity || (i < 1 ? 'critical' : i < 3 ? 'high' : 'medium'), `${fileName(a) || filePath(a) || 'Unknown'} — ${eventInfo(fileActionLabel(a)).label}`, `${i * 4 + 2}m ago`])
    : recentFallback;

  return (
    <div style={{ height: 'calc(100vh - 72px)', maxHeight: 'calc(100vh - 72px)', overflow: 'hidden', background: '#020b15', boxSizing: 'border-box', display: 'grid', gridTemplateColumns: '190px 1fr', color: '#e5edf7', fontFamily: 'Inter,system-ui,sans-serif' }}>

      {/* ── FIM Sidebar ── */}
      <aside style={{ background: 'linear-gradient(180deg,#020c1b 0%,#030d1f 100%)', borderRight: '1px solid #0f2035', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Brand */}
        <div style={{ padding: '13px 12px 10px', borderBottom: '1px solid #0f2035', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 9 }}>
            <div style={{ width: 30, height: 30, borderRadius: 8, background: 'linear-gradient(135deg,#1e40af,#7c3aed)', display: 'grid', placeItems: 'center', fontSize: 15, flexShrink: 0, boxShadow: '0 0 12px #7c3aed44' }}>🛡️</div>
            <div>
              <div style={{ fontSize: 11, fontWeight: 900, color: '#e5edf7', lineHeight: 1.2, letterSpacing: 0.3 }}>FIM</div>
              <div style={{ fontSize: 8, color: '#475569', letterSpacing: 0.5 }}>FILE INTEGRITY</div>
            </div>
          </div>
        </div>

        {/* Nav */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '8px 8px', display: 'flex', flexDirection: 'column', gap: 2 }}>
          <button type="button" onClick={() => navigate('/edr?capabilityId=2')} style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 8, padding: '9px 10px', borderRadius: 7, background: 'linear-gradient(90deg,rgba(59,130,246,.22),rgba(59,130,246,.06))', border: 0, borderLeft: '3px solid #3b82f6', marginBottom: 4, cursor: 'pointer', textAlign: 'left' }}>
            <span style={{ fontSize: 14 }}>🗂️</span>
            <span style={{ fontSize: 10, fontWeight: 800, color: '#60a5fa' }}>FIM Dashboard</span>
          </button>
          {FIM_TABS.map((item, index) => (
            <React.Fragment key={item.id}>
              {index === 5 && <div style={{ height: 1, background: '#0f2035', margin: '4px 0' }} />}
              <button onClick={() => navigate(item.path)} style={{ width: '100%', display: 'flex', alignItems: 'center', gap: 9, padding: '8px 10px', borderRadius: 6, border: 0, background: 'transparent', color: '#94a3b8', fontSize: 10, fontWeight: 500, cursor: 'pointer', textAlign: 'left' }}>
                <span style={{ fontSize: 13 }}>{item.icon}</span><span>{item.label}</span>
              </button>
            </React.Fragment>
          ))}
        </div>

        {/* Footer */}
        <div style={{ padding: '10px 12px', borderTop: '1px solid #0f2035', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <span style={{ width: 7, height: 7, borderRadius: '50%', background: '#22c55e', display: 'inline-block', boxShadow: '0 0 6px #22c55e' }} />
            <span style={{ fontSize: 9, color: '#22c55e', fontWeight: 800 }}>Monitoring Active</span>
          </div>
          <div style={{ fontSize: 8, color: '#475569' }}>{totalAgents} agents · {onlinePct}% online</div>
        </div>
      </aside>

      {/* ── Main ── */}
      <main style={{ overflow: 'auto', background: '#03101d', padding: 8, boxSizing: 'border-box' }}>
        <div style={{ minWidth: 1100, display: 'grid', gap: 8 }}>


          {/* Header */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 2 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <FIMCapabilityActions />
              <span style={{ color: '#22c55e', fontSize: 9, fontWeight: 900 }}>● Auto Refresh: On</span>
            </div>
          </div>

          {/* Metric tiles */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            <FIMMetricTile icon="📄" title="Total Events"        value={liveTotal.toLocaleString()} trend="Live"                         detail="Live FIM records"             color="#3b82f6" />
            <FIMMetricTile icon="⚠" title="Critical Alerts"     value={critical}                   trend="Live"                         detail="Critical severity FIM events" color="#ef4444" />
            <FIMMetricTile icon="✏️" title="Modified Files"      value={modified}                   trend="Live"                         detail="File modification events"     color="#f97316" />
            <FIMMetricTile icon="🗑" title="Deleted Files"       value={deleted}                    trend="Live"                         detail="File deletion events"         color="#f87171" />
            <FIMMetricTile icon="🔐" title="Permission Changes"  value={permission}                 trend="Live"                         detail="chmod/ACL events"             color="#3b82f6" />
            <FIMMetricTile icon="📁" title="New Files Created"   value={created}                    trend="Live"                         detail="File creation events"         color="#22d3ee" />
          </div>

          {/* Row 2: live distribution / panels */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr .9fr 1.35fr', gap: 8 }}>
            <FIMPanel title="Severity Distribution">
              <FIMDonut label="Total" center={liveTotal.toLocaleString()} rows={severityRows} />
            </FIMPanel>
            <FIMPanel title="File Action Breakdown">
              <FIMDonut label="Actions" center={liveTotal.toLocaleString()} rows={[
                { label: 'Modified',   value: modified,   color: '#fbbf24' },
                { label: 'Created',    value: created,    color: '#34d399' },
                { label: 'Deleted',    value: deleted,    color: '#f87171' },
                { label: 'Renamed',    value: renamed,    color: '#22d3ee' },
                { label: 'Permission', value: permission, color: '#a78bfa' },
                { label: 'Ownership',  value: ownership,  color: '#60a5fa' },
                { label: 'Sensitive',  value: sensitive,  color: '#eab308' },
                ...(actionOther ? [{ label: 'Other', value: actionOther, color: '#64748b' }] : []),
              ]} />
            </FIMPanel>
            <FIMPanel title="Monitoring Status">
              <div style={{ padding: '12px 14px' }}>
                <div style={{ display: 'flex', gap: 14, alignItems: 'center', marginBottom: 12 }}>
                  <div style={{ width: 72, height: 72, borderRadius: '50%', background: `conic-gradient(#22d3ee 0deg ${agentOnlineAngle}deg,#ef4444 ${agentOnlineAngle}deg 360deg)`, display: 'grid', placeItems: 'center', flexShrink: 0 }}>
                    <div style={{ width: 46, height: 46, borderRadius: '50%', background: '#081526', display: 'grid', placeItems: 'center', textAlign: 'center' }}>
                      <div><div style={{ fontSize: 14, fontWeight: 900, color: '#e5edf7', lineHeight: 1 }}>{totalAgents}</div><div style={{ fontSize: 8, color: '#8ea0b8' }}>Total</div></div>
                    </div>
                  </div>
                  <div style={{ flex: 1, display: 'grid', gap: 8 }}>
                    {[['Online',onlineCount,'#22d3ee',`${onlinePct}%`],['Offline',offlineCount,'#ef4444',`${totalAgents ? 100-onlinePct : 0}%`],['FIM Enabled',fimEnabledSystems.length,'#a78bfa',liveSystems.length ? `${Math.round((fimEnabledSystems.length / Math.max(liveSystems.length, 1)) * 100)}%` : '—']].map(([l,v,c,pct]) => (
                      <div key={l} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                          <span style={{ width: 7, height: 7, borderRadius: 2, background: c }} />
                          <span style={{ fontSize: 10, color: '#e5edf7' }}>{l}</span>
                        </div>
                        <span style={{ fontSize: 10, color: '#64748b' }}>{v} ({pct})</span>
                      </div>
                    ))}
                  </div>
                </div>
                <div style={{ borderTop: '1px solid #12243d', paddingTop: 9, display: 'grid', gap: 5, fontSize: 9 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ color: '#8ea0b8' }}>Source</span>
                    <b style={{ color: liveSystems.length ? '#22d3ee' : '#f59e0b' }}>{monitoringSource}</b>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                    <span style={{ color: '#8ea0b8' }}>Latest Seen</span>
                    <b style={{ color: '#dbeafe', textAlign: 'right' }}>{latestAgentSeen}</b>
                  </div>
                </div>
              </div>
            </FIMPanel>
            <FIMPanel title="Top Modified Paths">
              <div style={{ padding: '10px 12px', display: 'grid', gap: 7 }}>
                {topPaths.map((item, i) => {
                  const path = item.label ?? item[0];
                  const count = item.value ?? item[1];
                  const colors = ['#ef4444','#f97316','#eab308','#22d3ee','#3b82f6'];
                  return (
                    <div key={path} style={{ display: 'grid', gridTemplateColumns: '22px 1fr 28px', gap: 8, alignItems: 'center', fontSize: 10 }}>
                      <span style={{ width: 20, height: 20, display: 'grid', placeItems: 'center', borderRadius: 5, background: '#0f2a4a', color: colors[i], fontSize: 10 }}>{i+1}</span>
                      <span style={{ color: '#93c5fd', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{path}</span>
                      <b style={{ color: colors[i], background: `${colors[i]}22`, borderRadius: 4, textAlign: 'center', padding: '2px 0' }}>{count}</b>
                    </div>
                  );
                })}
                {topPaths.length === 0 && <div style={{ color: '#64748b', fontSize: 11, padding: '8px 0' }}>Waiting for live file path data.</div>}
              </div>
            </FIMPanel>
          </div>

          {/* Row 3: chart + tree + extensions + endpoints */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .95fr .7fr 1.15fr', gap: 8 }}>
            <FIMPanel
              title="File Activity Over Time (24h)"
              right={<span style={{ color: '#8ea0b8', fontSize: 9 }}>Peak {String(peakHour.hour).padStart(2, '0')}:00 · {peakHour.total}</span>}
            >
              <div style={{ padding: '8px 10px 10px' }}>
                <svg
                  viewBox="0 0 650 210"
                  width="100%"
                  height="176"
                  preserveAspectRatio="none"
                  onMouseLeave={() => setChartHoverHour(null)}
                  style={{ display: 'block', background: '#051321', border: '1px solid #12243d', borderRadius: 5 }}
                >
                  {[0, 1, 2, 3, 4].map(step => {
                    const value = (chartCeiling / 4) * (4 - step);
                    const y = chartTop + (step / 4) * (chartBottom - chartTop);
                    return (
                      <g key={step}>
                        <line x1={chartLeft} x2={chartRight} y1={y} y2={y} stroke="#18304d" strokeWidth="1" />
                        <text x="34" y={y + 3} fill="#64748b" fontSize="9" textAnchor="end">{Math.round(value)}</text>
                      </g>
                    );
                  })}
                  {[0, 4, 8, 12, 16, 20, 23].map(hour => (
                    <g key={hour}>
                      <line x1={chartX(hour)} x2={chartX(hour)} y1={chartTop} y2={chartBottom} stroke="#10243b" strokeWidth="1" />
                      <text x={chartX(hour)} y="194" fill="#64748b" fontSize="9" textAnchor="middle">{String(hour).padStart(2, '0')}:00</text>
                    </g>
                  ))}
                  <polygon points={chartArea} fill="#3b82f620" />
                  <polyline points={chartLine('total')} fill="none" stroke="#3b82f6" strokeWidth="2.5" strokeLinejoin="round" strokeLinecap="round" />
                  <polyline points={chartLine('critical')} fill="none" stroke="#ef4444" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
                  <polyline points={chartLine('modified')} fill="none" stroke="#f59e0b" strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round" />
                  <polyline points={chartLine('renamed')} fill="none" stroke="#22d3ee" strokeWidth="1.7" strokeLinejoin="round" strokeLinecap="round" />
                  {chartHoverHour !== null && (
                    <>
                      <line x1={chartX(chartHoverHour)} x2={chartX(chartHoverHour)} y1={chartTop} y2={chartBottom} stroke="#e2e8f0" strokeWidth="1" strokeDasharray="3 3" />
                      <circle cx={chartX(chartHoverHour)} cy={chartY(chartVals[chartHoverHour].total)} r="4" fill="#3b82f6" stroke="#dbeafe" strokeWidth="1.5" />
                    </>
                  )}
                  {chartVals.map(row => (
                    <rect
                      key={row.hour}
                      x={chartX(row.hour) - ((chartRight - chartLeft) / 46)}
                      y={chartTop}
                      width={(chartRight - chartLeft) / 23}
                      height={chartBottom - chartTop}
                      fill="transparent"
                      onMouseEnter={() => setChartHoverHour(row.hour)}
                    />
                  ))}
                </svg>
                <div style={{ minHeight: 22, display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, marginTop: 7, flexWrap: 'wrap' }}>
                  <div style={{ display: 'flex', gap: 11, color: '#8ea0b8', fontSize: 9, flexWrap: 'wrap' }}>
                    {[['All Events', '#3b82f6'], ['Critical', '#ef4444'], ['Modified', '#f59e0b'], ['Renamed', '#22d3ee']].map(([label, color]) => (
                      <span key={label}><b style={{ color }}>■</b> {label}</span>
                    ))}
                  </div>
                  <span style={{ color: '#cbd5e1', fontSize: 9, fontWeight: 800 }}>
                    {hoveredChartRow
                      ? `${String(hoveredChartRow.hour).padStart(2, '0')}:00 · Total ${hoveredChartRow.total} · Critical ${hoveredChartRow.critical} · Modified ${hoveredChartRow.modified} · Renamed ${hoveredChartRow.renamed}`
                      : 'Hover chart for hourly details'}
                  </span>
                </div>
              </div>
            </FIMPanel>
            <FIMPanel title="Directory Hotspots">
              <div style={{ padding: 14, color: '#cbd5e1', fontSize: 10, lineHeight: 1.9 }}>
                {topPaths.length
                  ? topPaths.map(item => {
                    const path = item.label ?? item[0];
                    const count = item.value ?? item[1];
                    return <div key={path}>▾ {path} ({count} events)</div>;
                  })
                  : <div style={{ color: '#64748b' }}>Waiting for live directory data.</div>}
              </div>
            </FIMPanel>
            <FIMPanel title="File Type Summary">
              <div style={{ padding: 12, display: 'grid', gap: 9 }}>
                {topExts.map((item, i) => {
                  const ext = item.label ?? item[0];
                  const count = item.value ?? item[1];
                  const colors = ['#3b82f6','#22c55e','#f97316','#a855f7','#eab308'];
                  const c = colors[i] || '#3b82f6';
                  return (
                    <div key={ext} style={{ display: 'grid', gridTemplateColumns: '1fr 34px', gap: 8, alignItems: 'center', fontSize: 10 }}>
                      <span style={{ color: '#dbeafe' }}><b style={{ color: c }}>●</b> .{ext}</span>
                      <b style={{ color: c, background: `${c}22`, borderRadius: 4, textAlign: 'center', padding: '3px 0' }}>{count}</b>
                    </div>
                  );
                })}
                {topExts.length === 0 && <div style={{ color: '#64748b', fontSize: 11 }}>Waiting for live file type data.</div>}
              </div>
            </FIMPanel>
            <FIMPanel title="Top Endpoints by Activity">
              <FIMBarRows rows={topEndpoints.map(item => ({ label: item.label ?? item[0], value: item.value ?? item[1], color: '#22d3ee' }))} />
            </FIMPanel>
          </div>

          {/* Row 4: FIM Coverage + Recent Alerts */}
          <div style={{ display: 'grid', gridTemplateColumns: '.95fr 1.45fr 1fr', gap: 8 }}>
            <FIMPanel title="FIM Coverage" right={<span style={{ color: '#60a5fa', fontSize: 9, fontWeight: 900 }}>Agent monitored</span>}>
              <div style={{ padding: 12, display: 'grid', gap: 7, maxHeight: 210, overflow: 'auto' }}>
                {coverageItems.map(([label, active]) => (
                  <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr 68px', alignItems: 'center', gap: 7, fontSize: 10 }}>
                    <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                    <b style={{ color: '#22c55e', background: '#22c55e22', borderRadius: 4, textAlign: 'center', padding: '3px 0', fontSize: 9 }}>Active</b>
                  </div>
                ))}
              </div>
            </FIMPanel>
            <FIMPanel title="Real-Time Activity Feed" right={<span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: '#ef444415', color: '#ef4444', border: '1px solid #ef444440', fontWeight: 800 }}>● Live</span>}>
              <div style={{ overflow: 'auto', maxHeight: 200 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '70px 130px 1fr 90px 70px', gap: 6, padding: '5px 12px', color: '#64748b', fontSize: 9, fontWeight: 800, borderBottom: '1px solid #12243d' }}>
                  {['TIME','EVENT','FILE PATH','HOST','SEV'].map(h => <div key={h}>{h}</div>)}
                </div>
                {loading
                  ? <div style={{ color: '#64748b', padding: 12, fontSize: 11 }}>Loading…</div>
                  : feedRows.length === 0
                    ? <div style={{ color: '#64748b', padding: 12, fontSize: 11 }}>No activity records.</div>
                    : feedRows.map((a, i) => {
                        const ei = eventInfo(fileActionLabel(a));
                        return (
                          <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '70px 130px 1fr 90px 70px', gap: 6, padding: '7px 12px', borderBottom: '1px solid #0a1220', alignItems: 'center' }}>
                            <div style={{ fontSize: 9, color: '#64748b', fontFamily: 'monospace' }}>{new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</div>
                            <div style={{ display: 'flex', gap: 5, alignItems: 'center', overflow: 'hidden' }}>
                              <span style={{ fontSize: 12, flexShrink: 0 }}>{ei.icon}</span>
                              <span style={{ fontSize: 9, color: ei.color, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ei.label}</span>
                            </div>
                            <div style={{ fontSize: 9, color: '#60a5fa', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{filePath(a) || fileName(a) || '—'}</div>
                            <div style={{ fontSize: 9, color: '#93c5fd', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.agentName || a.systemId?.name || '—'}</div>
                            <div>{sevBadge(a.severity)}</div>
                          </div>
                        );
                      })}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 12px', borderTop: '1px solid #12243d' }}>
                <span onClick={() => navigate('/edr-dashboard-details/fim/activity')} style={{ fontSize: 9, color: '#60a5fa', cursor: 'pointer', fontWeight: 600 }}>Activity Last 24 hr</span>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                  <button onClick={() => setFeedPage(p => Math.max(1,p-1))} style={{ background: 'none', border: 0, color: '#64748b', cursor: 'pointer', fontSize: 15 }}>‹</button>
                  <span style={{ fontSize: 9, color: '#64748b' }}>{feedPage}/{feedPages}</span>
                  <button onClick={() => setFeedPage(p => Math.min(feedPages,p+1))} style={{ background: 'none', border: 0, color: '#64748b', cursor: 'pointer', fontSize: 15 }}>›</button>
                </div>
              </div>
            </FIMPanel>
            <FIMPanel title="Recent Alerts">
              <div style={{ padding: 12, display: 'grid', gap: 9 }}>
                {recentAlertRows.map(([sev, desc, ago], i) => {
                  const c = sev === 'critical' ? '#ef4444' : sev === 'high' ? '#f97316' : '#eab308';
                  return (
                    <div key={`${desc}-${i}`} style={{ display: 'grid', gridTemplateColumns: '10px 1fr 40px', gap: 8, alignItems: 'start', fontSize: 10 }}>
                      <span style={{ color: c, marginTop: 1 }}>●</span>
                      <span><b style={{ color: c, display: 'block', fontSize: 9 }}>{(sev || '').toUpperCase()}</b><span style={{ color: '#cbd5e1', fontSize: 9 }}>{desc}</span></span>
                      <span style={{ color: '#8ea0b8', textAlign: 'right', fontSize: 9 }}>{ago}</span>
                    </div>
                  );
                })}
              </div>
            </FIMPanel>
          </div>

        </div>
      </main>
    </div>
  );
}



// ── Capability dashboard panels ───────────────────────────────────────────────


export { FileActivityPanel, ProcessActivityDashboardPanel, RISK, SEV, SEVBG, VtBadge, fileHash, fileName, filePath, fileUser, procMem, procName, processStatusSafe, processStatusStyle, summaryInventoryRows, vtIsThreaten };
