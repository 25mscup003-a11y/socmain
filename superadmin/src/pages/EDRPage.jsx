import React, { useEffect, useState, useCallback, useRef } from 'react';
import { useNavigate, useSearchParams, useLocation } from 'react-router-dom';
import api from '../api/axios';
import { useToast, Spinner, PageLoader } from '../components/Toast';
import { EDRCapabilityDashboardModal } from './EDRDashboardDetails';
import { getCapability, getCapabilityByCardId, getCapabilityByBackendId, getCapabilityTitle } from '../utils/capabilityMap';

/* ─── palette ────────────────────────────────────────────── */
const C = {
  bg: '#060d16',
  card: '#0b1929',
  border: '#1a3050',
  accent: '#3b82f6',
  cyan: '#22d3ee',
  green: '#22c55e',
  yellow: '#f59e0b',
  orange: '#f97316',
  red: '#ef4444',
  purple: '#a78bfa',
  muted: '#94a3b8',
  faint: '#1e3a5f',
};

const SEV_COLOR = { critical: C.red, high: C.orange, medium: C.yellow, low: C.green };
const SEV_BG = { critical: '#ef444420', high: '#f9731620', medium: '#f59e0b20', low: '#22c55e20' };

/* ─── tiny helpers ───────────────────────────────────────── */
const Badge = ({ text = '—', color = C.muted }) => (
  <span style={{
    fontSize: 9, padding: '2px 8px', borderRadius: 20, fontWeight: 700,
    color, background: `${color}18`, border: `1px solid ${color}33`,
    textTransform: 'uppercase', letterSpacing: 1,
  }}>{text}</span>
);

const statCard = (icon, label, value, color, sub = null) => (
  <div key={label} style={{
    background: C.card, border: `1px solid ${color}33`, borderRadius: 12,
    padding: '18px 20px', flex: 1, minWidth: 130, position: 'relative', overflow: 'hidden',
  }}>
    <div style={{ position: 'absolute', right: 14, top: 12, fontSize: 28, opacity: 0.13 }}>{icon}</div>
    <div style={{ fontSize: 11, color: C.muted, marginBottom: 6, fontWeight: 600 }}>{icon} {label}</div>
    <div style={{ fontSize: 30, fontWeight: 900, color, lineHeight: 1 }}>{value ?? '—'}</div>
    {sub && <div style={{ fontSize: 10, color: C.faint, marginTop: 4 }}>{sub}</div>}
  </div>
);

const SectionTitle = ({ children }) => (
  <div style={{
    fontSize: 12, fontWeight: 700, color: C.muted, textTransform: 'uppercase',
    letterSpacing: 2, marginBottom: 12, paddingBottom: 6, borderBottom: `1px solid ${C.border}`
  }}>
    {children}
  </div>
);

function timeAgo(ts) {
  if (!ts) return '—';
  const s = Math.floor((Date.now() - new Date(ts)) / 1000);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

function getCapabilityCardNumber(id) {
  return Number(id);
}

const CAPABILITY_UI_NAMES = {
  1: 'Process Activity Monitoring',
  2: 'File Activity Monitoring (FIM)',
  3: 'Network Activity Monitoring',
  4: 'User & Authentication Monitoring',
  5: 'Memory Activity Monitoring',
  6: 'Registry Monitoring',
  7: 'System Changes Monitoring',
  8: 'Persistence Mechanism Detection',
  9: 'Web & DNS Monitoring',
  10: 'Device Control (USB) Monitoring',
  11: 'Behavioral Analytics (UEBA)',
  12: 'Data Security Monitoring',
  13: 'Credential Security Monitoring',
  14: 'Lateral Movement Detection',
  15: 'Email Threat Monitoring',
  16: 'Insider Threat Detection',
  17: 'Patch & Vulnerability Monitoring',
  18: 'Sandbox Analysis',
  19: 'Kernel-Level Monitoring',
  20: 'API Call Monitoring',
  21: 'Script Execution Monitoring',
  22: 'Time-Based Anomaly Detection',
  23: 'Geolocation Anomaly Detection',
  24: 'Service Monitoring',
  25: 'Hash/Signature Analysis',
  26: 'Beaconing Detection',
  27: 'Encryption / Ransomware Detection',
  28: 'Living-off-the-Land (LOLBins) Detection',
  29: 'Memory Overflow Detection',
  30: 'DNS Cache Poisoning Detection',
  31: 'DNS Sinkhole',
};

function capabilityDisplayName(cap = {}) {
  return CAPABILITY_UI_NAMES[Number(cap.id)] || cap.name || 'Monitoring Capability';
}

function categoryForCapability(cap = {}) {
  const text = `${cap.name || ''} ${cap.description || ''} ${cap.source || ''}`.toLowerCase();
  const id = Number(cap.id);
  if (id === 1) return 'edr';
  if (id === 6) return 'registry';
  if ([5, 7, 8, 12, 15, 20, 22, 23, 24, 26, 27, 28].includes(id)) return 'system';
  if ([9, 17, 18, 21, 29, 31, 37, 38].includes(id)) return 'network';
  if (id === 10) return 'usb';
  if ([11, 14, 16, 19].includes(id)) return 'edr';
  if ([13, 18, 21].includes(id)) return 'file';
  if (/geo|geolocation|location|impossible travel/.test(text)) return 'edr';
  if (/usb|device control/.test(text)) return 'usb';
  if (/file|fim|hash|signature|ransomware|encryption|sandbox|malware|yara|script|exe|dll/.test(text)) return 'file';
  if (/network|dns|web|c2|beacon|sinkhole|threat intelligence|geo|cloud|email|exfil/.test(text)) return 'network';
  if (/auth|user|credential|insider|login|lateral|psexec|rdp/.test(text)) return 'edr';
  if (/service|kernel|memory|registry|system|process|api|patch|vulnerab|time|persistence|lolbin/.test(text)) return 'system';
  if (/soar|response|isolate|quarantine|block/.test(text)) return 'isolation';
  return 'edr';
}

const edrOverviewGridCss = `
  @media (max-width: 1400px) {
    .edr-overview-card-grid { grid-template-columns: repeat(3, minmax(0, 1fr)) !important; }
  }
  @media (max-width: 1040px) {
    .edr-overview-card-grid { grid-template-columns: repeat(2, minmax(0, 1fr)) !important; }
  }
  @media (max-width: 700px) {
    .edr-overview-card-grid { grid-template-columns: 1fr !important; }
  }
`;

function overviewCardMetrics(cap = {}) {
  if (!cap) cap = {};
  const m = cap.metrics || {};
  const live = cap.live || {};

  return {
    total: Number(live.logs24h ?? m.logs24h ?? cap.logs24h ?? 0),
    previous: Number(live.previous24h ?? m.previousLogs24h ?? 0),
    suspicious: Number(live.highCritical24h ?? m.highCritical24h ?? 0),
    unauthorized: Number(live.unauthorized24h ?? m.unauthorized24h ?? 0),
    activeAgents: Number(live.reportingAgents ?? m.reportingAgents ?? 0),
    missing: Number(live.missing ?? 0),
    trendPct: Number(live.trendPct ?? 0),
    lastSeenAt: live.lastSeenAt || null,
    timeline: Array.isArray(live.timeline24h) ? live.timeline24h : (m.timeline24h || []),
  };
}

function sparklinePoints(timeline = [], width = 220, height = 68) {
  if (!Array.isArray(timeline)) return '';
  const values = timeline.map(point => Number(point?.count || 0));
  if (values.length < 2 || !values.some(value => value > 0)) return '';
  const max = Math.max(...values, 1);
  return values.map((value, index) => {
    const x = (index / (values.length - 1)) * width;
    const y = height - 8 - ((value / max) * (height - 16));
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
}

function EDROverviewMetricCard({ cap = {}, onOpen, countLabel = 'LAST 24H LOG COUNT' }) {
  if (!cap) return null;
  const cardConfig = (cap.cardNumber ? getCapabilityByCardId(cap.cardNumber) : null) || getCapabilityByBackendId(cap.id) || getCapability(cap.id);
  const id = Number(cardConfig ? cardConfig.id : (cap.cardNumber ?? getCapabilityCardNumber(cap.id)));
  const reporting = cap.live?.telemetryStatus === 'reporting' || Number(cap.live?.logs24h || 0) > 0;
  const label = reporting ? 'REPORTING' : 'NO EVENTS';
  const color = reporting ? '#10d987' : '#f59e0b';
  const capabilityName = cardConfig ? cardConfig.title : capabilityDisplayName(cap);
  const source = cap.source || cap.evidence || cap.description || 'EDR module dashboard';
  const category = categoryForCapability(cap);
  const metrics = overviewCardMetrics(cap);
  const points = sparklinePoints(metrics.timeline);
  const open = () => onOpen?.({ ...cap, cardNumber: id, cardConfig }, categoryForCapability(cap));

  const totalVal = Number(metrics?.total || 0);
  const suspiciousVal = Number(metrics?.suspicious || 0);
  const unauthorizedVal = Number(metrics?.unauthorized || 0);
  const activeAgentsVal = Number(metrics?.activeAgents || 0);
  const missingVal = Number(metrics?.missing || 0);
  const trendVal = Number(metrics?.trendPct || 0);

  return (
    <button type="button" onClick={open} onKeyDown={e => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        open();
      }
    }} style={{
      background: 'linear-gradient(135deg, rgba(12,26,46,.86) 0%, rgba(15,21,53,.64) 100%)',
      border: `1px solid ${color}44`,
      borderRadius: 16,
      padding: '24px 26px',
      minHeight: 340,
      width: '100%',
      cursor: 'pointer',
      overflow: 'hidden',
      position: 'relative',
      boxShadow: 'inset 0 1px 0 rgba(255,255,255,.05), 0 2px 8px rgba(0,0,0,.4)',
      outline: 'none',
      display: 'flex',
      flexDirection: 'column',
      justifyContent: 'space-between',
      textAlign: 'left',
      fontFamily: 'inherit',
    }}>
      <span>
        <span style={{ position: 'absolute', top: 0, right: 0, width: 220, height: 220, background: `radial-gradient(circle, ${color}14 0%, transparent 70%)`, pointerEvents: 'none' }} />
        <span style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 10, position: 'relative', zIndex: 1 }}>
          <span style={{ display: 'flex', gap: 14, alignItems: 'center', minWidth: 0 }}>
            <span style={{ width: 54, height: 54, borderRadius: 14, display: 'grid', placeItems: 'center', background: `${color}16`, border: `1px solid ${color}55`, color, fontSize: 26, fontWeight: 900 }}>
              ▱
            </span>
            <span style={{ width: 36, height: 36, borderRadius: 10, display: 'grid', placeItems: 'center', background: `${color}20`, color, border: `1px solid ${color}44`, fontSize: 15, fontWeight: 900 }}>
              {id}
            </span>
          </span>
          <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span style={{ color: '#60a5fa', fontSize: 15, fontWeight: 900 }}>↗</span>
            <span style={{ fontSize: 11, padding: '7px 12px', borderRadius: 8, fontWeight: 900, background: `${color}18`, color, border: `1px solid ${color}55` }}>
              {label}
            </span>
          </span>
        </span>

        <span style={{ display: 'block', marginTop: 28, color: '#7dd3fc', fontSize: 11, fontWeight: 900, letterSpacing: 1.2, position: 'relative', zIndex: 1 }}>
          {countLabel}
        </span>
        <span style={{ display: 'block', marginTop: 8, color: '#e5edf7', fontSize: 42, fontWeight: 950, lineHeight: 1, position: 'relative', zIndex: 1 }}>
          {totalVal.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: '#60a5fa', fontSize: 19, fontWeight: 900, marginTop: 16, lineHeight: 1.25, position: 'relative', zIndex: 1 }}>
          {capabilityName}
        </span>
        <span style={{ display: 'block', color: '#93c5fd', fontSize: 13, lineHeight: 1.45, marginTop: 18, position: 'relative', zIndex: 1 }}>
          High/Critical: {suspiciousVal.toLocaleString()} · Unauthorized: {unauthorizedVal.toLocaleString()}
        </span>
        {points ? (
          <svg aria-label="Real logs by hour for the last 24 hours" width="180" height="54" viewBox="0 0 220 68" style={{ display: 'block', marginTop: 20, position: 'relative', zIndex: 1 }}>
            <polyline points={points} fill="none" stroke="#3b82f6" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        ) : (
          <span style={{ display: 'block', height: 54, marginTop: 20, color: '#64748b', fontSize: 11, lineHeight: '54px' }}>No live logs in this 24h window</span>
        )}
      </span>

      <span style={{ position: 'relative', zIndex: 1, marginTop: 16 }}>
        <span style={{ display: 'block', color: '#7dd3fc', fontSize: 13, lineHeight: 1.5, marginBottom: 8 }}>
          Reporting agents: {activeAgentsVal.toLocaleString()} · Missing: {missingVal.toLocaleString()}
        </span>
        <span style={{ display: 'block', color: trendVal >= 0 ? '#34d399' : '#f87171', fontSize: 12, fontWeight: 900, marginBottom: 16 }}>
          {trendVal >= 0 ? '↑' : '↓'} {Math.abs(trendVal)}% vs previous 24h
        </span>
        <span style={{ display: 'block', color: '#1d4ed8', fontSize: 11, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
          Monitor: {category} · {source}
        </span>
      </span>
    </button>
  );
}

function EDRCapabilityCard({ cap, onOpen }) {
  const countLabel = Number(cap.id) === 1
    ? 'PROCESS ACTIVITY EVENTS (LAST 24H)'
    : Number(cap.id) === 6
      ? 'REGISTRY / CONFIG EVENTS (LAST 24H)'
      : 'LAST 24H EVENT COUNT';
  return <EDROverviewMetricCard cap={cap} onOpen={onOpen} countLabel={countLabel} />;
}

function EDRCapabilitiesDashboard({ data, loading, onOpenCapability }) {
  const summary = data?.liveSummary || {};
  const caps = data?.capabilities || [];
  const isInitialLoad = loading && caps.length === 0;

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(6,13,22,.95), rgba(8,20,36,.9))',
      border: '1px solid rgba(34,211,238,.22)',
      borderRadius: 14,
      padding: 18,
      marginBottom: 22,
    }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12, marginBottom: 14 }}>
        <div>
          <div style={{ fontSize: 16, color: '#e0f2fe', fontWeight: 900 }}>All 31 EDR Monitoring Capabilities</div>
          <div style={{ fontSize: 11, color: '#60a5fa', marginTop: 3 }}>
            Real tenant telemetry · last 24 hours · demo/synthetic rows excluded
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          {loading && caps.length > 0 && (
            <span style={{
              fontSize: 10, padding: '5px 9px', borderRadius: 7,
              color: '#60a5fa', background: 'rgba(96,165,250,.12)', border: '1px solid rgba(96,165,250,.3)',
              fontWeight: 800,
            }}>Refreshing</span>
          )}
          {[
            ['Reporting', summary.reporting ?? 0, '#34d399'],
            ['No Events', summary.idle ?? 0, '#f59e0b'],
            ['24h Reporting', `${summary.reporting ?? 0}/${summary.total ?? 31}`, '#22d3ee'],
          ].map(([label, value, color]) => (
            <span key={label} style={{
              fontSize: 10, padding: '5px 9px', borderRadius: 7,
              color, background: `${color}14`, border: `1px solid ${color}35`,
              fontWeight: 800,
            }}>{label}: {value}</span>
          ))}
        </div>
      </div>

      {isInitialLoad ? (
        <div style={{ color: '#60a5fa', fontSize: 12, padding: '18px 0' }}>Loading EDR capability status…</div>
      ) : caps.length === 0 ? (
        <div style={{ color: '#f59e0b', fontSize: 12, padding: '18px 0' }}>No EDR capability data available.</div>
      ) : (
        <>
          <style>{edrOverviewGridCss}</style>
          <div className="edr-overview-card-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 14 }}>
            {caps.map((cap, idx) => (
              <EDRCapabilityCard key={cap.id || cap.name} cap={{ ...cap, cardNumber: idx + 1 }} onOpen={onOpenCapability} />
            ))}
          </div>
        </>
      )}
    </div>
  );
}

const TABS = [
  { id: 'overview', label: '📊 Overview' },
  { id: 'endpoints', label: '🖥 Endpoints' },
];

const COMMON_FORENSIC_ARTIFACTS = {
  Windows: [
    ['Windows.System.Processes', 'Running processes snapshot'],
    ['Windows.Network.Netstat', 'Active network connections'],
    ['Windows.Forensics.Prefetch', 'Prefetch execution evidence'],
    ['Windows.Registry.Sysinternals.Autoruns', 'Startup persistence'],
    ['Windows.Detection.Yara.Process', 'YARA scan running processes'],
    ['Windows.EventLogs.Evtx', 'Security, System, Application, PowerShell and Sysmon logs'],
  ],
  Linux: [
    ['Linux.Sys.Pslist', 'Linux process list'],
    ['Linux.Network.Netstat', 'Linux network connections'],
    ['Linux.Sys.Crontab', 'Cron jobs and scheduled persistence'],
    ['Linux.Sys.LogHunter', 'Auth, syslog and service log search'],
  ],
  macOS: [
    ['MacOS.System.Pslist', 'macOS process list'],
    ['MacOS.Network.Netstat', 'macOS active network connections'],
    ['MacOS.System.LaunchAgents', 'Launch agents and startup persistence'],
    ['MacOS.Search.FileFinder', 'macOS file search and hashing'],
  ],
};

const FORENSIC_AREAS = [
  ['Endpoint Visibility', 'Windows.System.Processes', ['Running processes dekhna', 'Parent-child process tree', 'Command line arguments', 'Services & drivers inspect', 'Installed software inventory', 'Open handles & mutexes', 'Active user sessions', 'Logged-in users', 'Startup entries', 'Scheduled tasks', 'Environment variables', 'Mounted drives', 'Network shares', 'ARP cache', 'DNS cache']],
  ['File System Investigation', 'Windows.Search.FileFinder', ['File search', 'Hidden files detect', 'Suspicious extensions hunt', 'Recently modified files', 'Deleted file traces', 'Alternate Data Streams (ADS)', 'Temp directories analysis', 'Downloads folder analysis', 'ZIP/RAR extraction artifacts', 'Large file identification', 'Duplicate file detection', 'File hashing', 'Timeline creation', 'File entropy checks', 'File permission audit', 'EXE/DLL analysis', 'Script file detection']],
  ['Windows Registry Analysis', 'Windows.Registry.Sysinternals.Autoruns', ['Run/RunOnce keys', 'Persistence entries', 'Installed applications', 'USB history', 'RDP history', 'UserAssist', 'Shellbags', 'BAM/DAM', 'Typed URLs', 'RecentDocs', 'MRU lists', 'MountedDevices', 'SAM information', 'Security policies', 'Firewall rules', 'PowerShell history traces', 'Autoruns registry locations']],
  ['Event Log Analysis', 'Windows.EventLogs.Evtx', ['Security logs', 'System logs', 'Application logs', 'PowerShell logs', 'Sysmon logs', 'RDP login events', 'Failed logins', 'Account lockouts', 'Privilege escalation events', 'Service creation events', 'Scheduled task events', 'USB insertion events', 'WMI events', 'Defender alerts', 'Log clearing detection']],
  ['Threat Hunting', 'Windows.Detection.Yara.Process', ['IOC sweeping', 'Hash hunting', 'Domain hunting', 'IP hunting', 'Filename hunting', 'Registry IOC search', 'Mutex hunting', 'YARA scanning', 'Sigma rule usage', 'LOLBins detection', 'PowerShell abuse detection', 'Encoded command detection', 'Living-off-the-land activity', 'Suspicious persistence', 'Lateral movement detection', 'Beaconing detection', 'C2 indicators']],
  ['Malware Analysis Support', 'Windows.Forensics.Prefetch', ['Malware artifact collection', 'DLL injection detection', 'Reflective loading detection', 'Packed binaries detect', 'Persistence tracing', 'Dropped payload detection', 'Encoded scripts', 'Suspicious temp files', 'Macro malware traces', 'Browser credential theft indicators', 'RAT behavior indicators', 'Crypto miner detection', 'Ransomware indicators']],
  ['Memory & Process Analysis', 'Windows.System.Processes', ['Process memory dump', 'DLL listing', 'Injected modules', 'Handle inspection', 'Token inspection', 'Process ancestry', 'Suspicious child processes', 'Thread analysis', 'LSASS access detection', 'Credential dumping traces', 'In-memory malware indicators']],
  ['Browser Forensics', 'Windows.Applications.Chrome.History', ['Chrome history', 'Firefox history', 'Edge history', 'Downloads history', 'Cookies', 'Saved logins traces', 'Autofill data', 'Extensions audit', 'Bookmark extraction', 'Session recovery', 'Cache analysis']],
  ['User Activity Tracking', 'Windows.Forensics.UserAccessLogs', ['Recent files', 'Login history', 'Clipboard artifacts', 'Command history', 'PowerShell history', 'Remote desktop usage', 'USB usage', 'Print history', 'Search history', 'File access timeline']],
  ['Network Investigation', 'Windows.Network.Netstat', ['Active connections', 'Listening ports', 'DNS requests', 'Firewall configuration', 'Proxy settings', 'VPN traces', 'SMB sessions', 'Netstat collection', 'Wi-Fi profiles', 'ARP entries', 'Routing table', 'Suspicious outbound traffic']],
  ['Persistence Detection', 'Windows.Registry.Sysinternals.Autoruns', ['Autoruns', 'Services', 'Scheduled tasks', 'WMI persistence', 'Registry run keys', 'Startup folders', 'Browser extensions', 'DLL hijacking', 'COM hijacking', 'LNK abuse', 'IFEO abuse']],
  ['Lateral Movement Detection', 'Windows.EventLogs.Evtx', ['PsExec traces', 'RDP activity', 'SMB usage', 'WMI execution', 'WinRM activity', 'Remote services', 'Admin shares', 'Pass-the-hash indicators', 'Credential reuse traces']],
  ['Cloud & Enterprise Monitoring', 'Generic.Client.Info', ['Large-scale endpoint collection', 'Centralized investigations', 'Multi-host hunting', 'Enterprise telemetry', 'Fleet visibility', 'Remote triage', 'Compliance checks', 'Asset inventory', 'User/device mapping']],
  ['DFIR Operations', 'Windows.KapeFiles.Targets', ['Evidence collection', 'Live response', 'Triage collection', 'Timeline reconstruction', 'Case investigation', 'Host isolation support', 'Artifact acquisition', 'Forensic reporting', 'IOC extraction']],
  ['Automation Features', 'Generic.Detection.Yara.Glob', ['Automated hunts', 'Scheduled collections', 'Custom artifacts', 'Artifact sharing', 'Alert workflows', 'Scripted response', 'Bulk endpoint querying', 'Mass IOC scans']],
  ['VQL (Velociraptor Query Language)', 'Generic.Client.Info', ['SQL-like queries run', 'File parsing', 'Registry reading', 'Log parsing', 'Memory inspection', 'JSON processing', 'CSV parsing', 'Custom detections', 'Threat hunting queries', 'Artifact development']],
];

const ADVANCED_FORENSICS = [
  ['Ransomware Investigation', ['Encryption timeline', 'Initial infection trace', 'Privilege escalation path', 'Lateral movement path', 'Persistence mechanism', 'Data exfiltration indicators']],
  ['Insider Threat Detection', ['Unusual downloads', 'USB copying', 'Mass file access', 'Off-hours activity', 'Suspicious uploads', 'Unauthorized tools']],
  ['Red Team Detection', ['Cobalt Strike indicators', 'Mimikatz traces', 'BloodHound usage', 'PowerShell Empire artifacts', 'Sliver C2 traces', 'LOLBins abuse']],
];

const CAPABILITY_ARTIFACT_BY_OS = {
  Linux: {
    'Endpoint Visibility': 'Linux.Sys.Pslist',
    'File System Investigation': 'Linux.Search.FileFinder',
    'Windows Registry Analysis': 'Linux.Sys.Users',
    'Event Log Analysis': 'Linux.Sys.LogHunter',
    'Threat Hunting': 'Generic.Detection.Yara.Glob',
    'Malware Analysis Support': 'Generic.Detection.Yara.Glob',
    'Memory & Process Analysis': 'Linux.Sys.Pslist',
    'Browser Forensics': 'Linux.Search.FileFinder',
    'User Activity Tracking': 'Linux.Sys.LogHunter',
    'Network Investigation': 'Linux.Network.Netstat',
    'Persistence Detection': 'Linux.Sys.Crontab',
    'Lateral Movement Detection': 'Linux.Sys.LogHunter',
    'Cloud & Enterprise Monitoring': 'Generic.Client.Info',
    'DFIR Operations': 'Linux.Search.FileFinder',
    'Automation Features': 'Generic.Detection.Yara.Glob',
    'VQL (Velociraptor Query Language)': 'Generic.Client.Info',
  },
  macOS: {
    'Endpoint Visibility': 'MacOS.System.Pslist',
    'File System Investigation': 'MacOS.Search.FileFinder',
    'Windows Registry Analysis': 'MacOS.System.LaunchAgents',
    'Event Log Analysis': 'MacOS.System.QuarantineEvents',
    'Threat Hunting': 'Generic.Detection.Yara.Glob',
    'Malware Analysis Support': 'Generic.Detection.Yara.Glob',
    'Memory & Process Analysis': 'MacOS.System.Pslist',
    'Browser Forensics': 'MacOS.Search.FileFinder',
    'User Activity Tracking': 'MacOS.System.Users',
    'Network Investigation': 'MacOS.Network.Netstat',
    'Persistence Detection': 'MacOS.System.LaunchAgents',
    'Lateral Movement Detection': 'MacOS.System.QuarantineEvents',
    'Cloud & Enterprise Monitoring': 'Generic.Client.Info',
    'DFIR Operations': 'MacOS.Search.FileFinder',
    'Automation Features': 'Generic.Detection.Yara.Glob',
    'VQL (Velociraptor Query Language)': 'Generic.Client.Info',
  },
};

const EDR_CAPABILITY_NAMES = {
  1: 'Process Activity Monitoring',
  2: 'File Activity Monitoring (FIM)',
  3: 'Network Activity Monitoring',
  4: 'User & Authentication Monitoring',
  5: 'Memory Activity Monitoring',
  6: 'Registry Monitoring',
  7: 'System Changes Monitoring',
  8: 'Persistence Mechanism Detection',
  9: 'Web & DNS Monitoring',
  10: 'Device Control (USB) Monitoring',
  11: 'Behavioral Analytics (UEBA)',
  12: 'Data Security Monitoring',
  13: 'Credential Security Monitoring',
  14: 'Lateral Movement Detection',
  15: 'Email Threat Monitoring',
  16: 'Insider Threat Detection',
  17: 'Patch & Vulnerability Monitoring',
  18: 'Sandbox Analysis',
  19: 'Kernel-Level Monitoring',
  20: 'API Call Monitoring',
  21: 'Script Execution Monitoring',
  22: 'Time-Based Anomaly Detection',
  23: 'Geolocation Anomaly Detection',
  24: 'Service Monitoring',
  25: 'Hash/Signature Analysis',
  26: 'Beaconing Detection',
  27: 'Encryption / Ransomware Detection',
  28: 'Living-off-the-Land (LOLBins) Detection',
  29: 'Memory Overflow Detection',
  30: 'DNS Cache Poisoning Detection',
  31: 'DNS Sinkhole',
};

/* ══════════════════════════════════════════════════════════ */
export default function EDRPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams, setSearchParams] = useSearchParams();
  const rawCap = Number(searchParams.get('capabilityId') || searchParams.get('cap') || 0);
  const searchCapObj = rawCap ? (getCapabilityByCardId(rawCap) || getCapability(rawCap)) : null;
  const routeCapabilityId = searchCapObj ? searchCapObj.id : (rawCap || null);
  const routeBackendCapabilityId = searchCapObj ? searchCapObj.backendId : routeCapabilityId;

  // Capability dashboards are rolling live 24-hour views. Remove old snapshot
  // timestamps so bookmarked/card URLs cannot leave any dashboard on a stale day.
  useEffect(() => {
    if (!routeBackendCapabilityId || !searchParams.has('windowEnd')) return;
    const next = new URLSearchParams(searchParams);
    next.delete('windowEnd');
    setSearchParams(next, { replace: true });
  }, [routeBackendCapabilityId, searchParams, setSearchParams]);

  /* state */
  const [tab, setTab] = useState('overview');
  const [loading, setLoading] = useState(true);
  const [dash, setDash] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [incTotal, setIncTotal] = useState(0);
  const [incPage, setIncPage] = useState(1);
  const [incFilter, setIncFilter] = useState({ severity: '', status: '', category: '' });
  const [endpoints, setEndpoints] = useState([]);
  const [hunt, setHunt] = useState(null);
  const [hunting, setHunting] = useState(false);
  const [forensicLaunching, setForensicLaunching] = useState(false);
  const [mitre, setMitre] = useState(null);
  const [telemetry, setTelemetry] = useState([]);
  const [systems, setSystems] = useState([]);
  const [selInc, setSelInc] = useState(null);
  const [actionPending, setAction] = useState(false);
  const [aiPending, setAiPending] = useState(false);
  const pollRef = useRef(null);
  /* new capability tabs */
  const [coverage, setCoverage] = useState(null);
  const [liveCoverage, setLiveCoverage] = useState(null);
  const [newSvcs, setNewSvcs] = useState(null);
  const [svcStatus, setSvcStatus] = useState(null);
  const [capLoading, setCapLoading] = useState(false);
  const [geoPolicyActive, setGeoPolicyActive] = useState(false);
  const [selectedCap, setSelectedCap] = useState(null);
  const [forensicOs, setForensicOs] = useState('Windows');
  const [forensicForm, setForensicForm] = useState({
    capability: 'Endpoint Visibility',
    huntName: 'Endpoint Visibility Collection',
    artifactName: 'Windows.System.Processes',
    systemId: '',
    clientId: '',
    covers: 'Running processes dekhna, Parent-child process tree, Command line arguments',
  });

  const applyForensicCapability = useCallback((title, artifact, items, osOverride = forensicOs) => {
    const osArtifact = CAPABILITY_ARTIFACT_BY_OS[osOverride]?.[title] || artifact;
    setForensicForm(f => ({
      ...f,
      capability: title,
      huntName: `${osOverride} ${title} Collection`,
      artifactName: osArtifact,
      covers: items.slice(0, 6).join(', '),
    }));
  }, [forensicOs]);

  const applyForensicOs = useCallback((os) => {
    setForensicOs(os);
    const current = FORENSIC_AREAS.find(([title]) => title === forensicForm.capability) || FORENSIC_AREAS[0];
    applyForensicCapability(current[0], current[1], current[2], os);
  }, [applyForensicCapability, forensicForm.capability]);

  const applyForensicItem = useCallback((title, artifact, item) => {
    const osArtifact = CAPABILITY_ARTIFACT_BY_OS[forensicOs]?.[title] || artifact;
    setForensicForm(f => ({
      ...f,
      capability: title,
      huntName: `${forensicOs} ${item}`,
      artifactName: osArtifact,
      covers: item,
    }));
  }, [forensicOs]);

  const applyCommonArtifact = useCallback((os, name, desc) => {
    setForensicOs(os);
    setForensicForm(f => ({
      ...f,
      huntName: `${os} ${desc}`,
      artifactName: name,
      covers: desc,
    }));
  }, []);

  /* ── fetch helpers ─────────────────────────────────────── */
  const fetchDash = useCallback(async () => {
    try {
      const r = await api.get('/soc-edr/dashboard');
      setDash(r.data);
    } catch { /* silent */ }
  }, []);

  const fetchIncidents = useCallback(async (page = 1, filter = incFilter) => {
    try {
      const params = { page, limit: 15, ...filter };
      Object.keys(params).forEach(k => !params[k] && delete params[k]);
      const r = await api.get('/soc-edr/incidents', { params });
      setIncidents(r.data.incidents || []);
      setIncTotal(r.data.total || 0);
    } catch { /* silent */ }
  }, [incFilter]);

  const fetchEndpoints = useCallback(async () => {
    try {
      const r = await api.get('/soc-edr/endpoint-risk');
      setEndpoints(r.data.endpoints || []);
    } catch { /* silent */ }
  }, []);

  const fetchMitre = useCallback(async () => {
    try {
      const r = await api.get('/soc-edr/mitre-coverage');
      setMitre(r.data);
    } catch { /* silent */ }
  }, []);

  const fetchTelemetry = useCallback(async () => {
    try {
      const r = await api.get('/soc-edr/live-telemetry');
      setTelemetry(r.data.alerts || []);
    } catch { /* silent */ }
  }, []);

  const fetchSystems = useCallback(async () => {
    try {
      const r = await api.get('/system');
      const list = Array.isArray(r.data) ? r.data : (r.data?.systems || []);
      setSystems(list);
    } catch { /* silent */ }
  }, []);

  const fetchCoverage = useCallback(async () => {
    try {
      const r = await api.get('/edr-cap/status');
      setCoverage(r.data);
    } catch { /* live overview remains the primary card data source */ }
  }, []);

  const fetchLiveCoverage = useCallback(async () => {
    try {
      const r = await api.get('/edr-cap/live-overview');
      setLiveCoverage(r.data);
    } catch { /* retain the most recent successful live snapshot */ }
  }, []);

  const fetchGeoPolicyState = useCallback(async () => {
    try {
      const r = await api.get('/geolocation/policies', { skipCache: true });
      setGeoPolicyActive((r.data?.policies || []).some(policy => policy.enabled));
    } catch {
      setGeoPolicyActive(false); // fail closed: never display geo counts without policy proof
    }
  }, []);

  const fetchNewSvcs = useCallback(async () => {
    try {
      const r = await api.get('/edr-cap/new-services');
      setNewSvcs(r.data);
    } catch { /* silent */ }
  }, []);

  const fetchSvcStatus = useCallback(async () => {
    try {
      const r = await api.get('/edr-cap/service-status');
      setSvcStatus(r.data);
    } catch { /* silent */ }
  }, []);

  const withLoadTimeout = useCallback((promise, ms = 1500) => (
    Promise.race([
      promise,
      new Promise(resolve => setTimeout(resolve, ms)),
    ])
  ), []);

  const loadAll = useCallback(() => {
    setLoading(true);
    fetchLiveCoverage().finally(() => setLoading(false));
    fetchDash();
    fetchCoverage();
    fetchIncidents(1);
    fetchEndpoints();
    fetchSystems();
    fetchGeoPolicyState();
  }, [fetchDash, fetchIncidents, fetchEndpoints, fetchSystems, fetchCoverage, fetchLiveCoverage, fetchGeoPolicyState]);

  useEffect(() => { loadAll(); }, [loadAll]);

  useEffect(() => {
    const timer = setInterval(fetchLiveCoverage, 60000);
    return () => clearInterval(timer);
  }, [fetchLiveCoverage]);

  useEffect(() => {
    const timer = setInterval(fetchCoverage, 60000);
    return () => clearInterval(timer);
  }, [fetchCoverage]);

  /* lazy-load per tab */
  useEffect(() => {
    clearInterval(pollRef.current);
    if (tab === 'mitre') fetchMitre();
    if (tab === 'telemetry') { fetchTelemetry(); pollRef.current = setInterval(fetchTelemetry, 60000); }
    if (tab === 'incidents') fetchIncidents(incPage, incFilter);
    if (tab === 'endpoints') { fetchEndpoints(); pollRef.current = setInterval(fetchEndpoints, 60000); }
    if (tab === 'forensic') fetchSystems();
    if (tab === 'coverage') { setCapLoading(true); fetchCoverage().finally(() => setCapLoading(false)); }
    if (tab === 'services') fetchNewSvcs();
    if (tab === 'svcstatus') fetchSvcStatus();
    return () => clearInterval(pollRef.current);
  }, [tab]); // eslint-disable-line


  const runHunt = async () => {
    setHunting(true);
    const tid = toast.loading('Running threat hunt…');
    try {
      const r = await api.get('/soc-edr/hunt');
      setHunt(r.data);
      toast.dismiss(tid);
      toast.success(`Hunt complete — ${r.data.hunts?.length || 0} findings`);
    } catch (e) {
      toast.dismiss(tid);
      toast.error(e.response?.data?.message || 'Hunt failed');
    } finally { setHunting(false); }
  };

  const launchForensicHunt = async () => {
    setForensicLaunching(true);
    const tid = toast.loading('Launching Velociraptor hunt…');
    try {
      const r = await api.post('/edr/velociraptor/hunt', {
        name: forensicForm.huntName,
        artifactName: forensicForm.artifactName,
        systemId: forensicForm.systemId,
        clientId: forensicForm.clientId,
      });
      toast.dismiss(tid);
      toast.success('Forensic hunt launched and sent to SIEM');
      setHunt({
        hunts: [],
        totalAlerts: 0,
        scannedAt: new Date().toISOString(),
        velociraptor: r.data.hunt,
      });
    } catch (e) {
      toast.dismiss(tid);
      toast.error(e.response?.data?.message || 'Forensic hunt failed');
    } finally {
      setForensicLaunching(false);
    }
  };

  /* ── incident action ───────────────────────────────────── */
  const takeAction = async (incidentId, action, target = null) => {
    setAction(true);
    try {
      const r = await api.post(`/soc-edr/incidents/${incidentId}/action`, { action, target });
      toast.success(r.data.result);
      fetchIncidents(incPage, incFilter);
      if (selInc?._id === incidentId) {
        const updated = await api.get(`/soc-edr/incidents/${incidentId}`);
        setSelInc(updated.data);
      }
    } catch (e) {
      toast.error(e.response?.data?.message || 'Action failed');
    } finally { setAction(false); }
  };

  const updateStatus = async (id, status) => {
    try {
      await api.patch(`/soc-edr/incidents/${id}`, { status });
      toast.success(`Status → ${status}`);
      fetchIncidents(incPage, incFilter);
      if (selInc?._id === id) setSelInc(p => ({ ...p, status }));
    } catch (e) { toast.error(e.response?.data?.message || 'Update failed'); }
  };

  const analyseIncident = async (incident) => {
    setAiPending(true);
    try {
      const { data } = await api.post(`/ai/edr-incidents/${incident._id}/analyze`);
      const jobId = data?.job?._id;
      const queued = { ...incident.aiInvestigation, status: 'queued', jobId };
      setSelInc(current => current?._id === incident._id ? { ...current, aiInvestigation: queued } : current);
      setIncidents(current => current.map(item => item._id === incident._id ? { ...item, aiInvestigation: queued } : item));
      if (!jobId) return;

      for (let attempt = 0; attempt < 80; attempt += 1) {
        await new Promise(resolve => setTimeout(resolve, 1500));
        const { data: job } = await api.get(`/ai/jobs/${jobId}`);
        if (job.status === 'failed') throw new Error(job.error || 'AI analysis failed');
        if (job.status !== 'completed') {
          setSelInc(current => current?._id === incident._id
            ? { ...current, aiInvestigation: { ...current.aiInvestigation, status: job.status || 'processing' } }
            : current);
          continue;
        }
        const output = job.output || {};
        const result = {
          status: 'completed', jobId,
          summary: output.summary || '',
          rootCause: output.rootCause || '',
          confidence: job.confidence ?? output.confidence ?? 0,
          reasoning: output.reasoning || '',
          recommendedSteps: output.recommendedInvestigationSteps || [],
        };
        setSelInc(current => current?._id === incident._id ? { ...current, aiInvestigation: result } : current);
        setIncidents(current => current.map(item => item._id === incident._id ? { ...item, aiInvestigation: result } : item));
        toast.success('EDR AI investigation completed');
        return;
      }
      toast.error('AI analysis is still processing. Reopen the incident to see the result.');
    } catch (e) {
      setSelInc(current => current?._id === incident._id
        ? { ...current, aiInvestigation: { ...current.aiInvestigation, status: 'failed' } }
        : current);
      toast.error(e.response?.data?.message || e.message || 'AI analysis failed');
    } finally {
      setAiPending(false);
    }
  };

  const openCapabilityCard = useCallback((cap) => {
    const cardId = cap?.cardNumber || cap?.cardConfig?.id || (cap?.id ? (getCapabilityByCardId(cap.id)?.id || getCapabilityByBackendId(cap.id)?.id) : null);
    const targetCap = cardId ? getCapabilityByCardId(cardId) : (cap?.id ? getCapability(cap.id) : null);
    const idToUse = targetCap ? targetCap.id : (cardId || cap?.id);
    if (!idToUse) return;
    const next = new URLSearchParams({ capabilityId: String(idToUse) });
    if (targetCap?.title) {
      const slug = targetCap.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');
      next.set('capability', slug);
    }
    const basePath = location.pathname.startsWith('/company-admin') ? '/company-admin/edr' : (location.pathname === '/' ? '/company-admin/edr' : location.pathname);
    navigate(`${basePath}?${next}`);
  }, [navigate, location.pathname]);

  const closeRouteCapability = useCallback(() => {
    if (searchParams.get('from') === 'dashboard') {
      const target = location.pathname.startsWith('/company-admin') ? '/company-admin' : '/';
      navigate(target, { replace: true });
      return;
    }
    const next = new URLSearchParams(searchParams);
    next.delete('capabilityId');
    next.delete('cap');
    next.delete('from');
    setSearchParams(next, { replace: true });
  }, [navigate, searchParams, setSearchParams, location.pathname]);

  if (loading) return <PageLoader text="Loading EDR data…" />;

  const kpis = dash?.kpis || {};
  const selectedForensicSystem = systems.find(s => s._id === forensicForm.systemId);
  const coverageSummary = coverage?.summary || {};
  const coverageById = new Map((coverage?.capabilities || []).map(cap => [Number(cap.id), cap]));
  const overviewCoverage = (() => {
    if (!liveCoverage?.capabilities?.length) return coverage;
    return {
      ...(coverage || {}),
      ...liveCoverage,
      capabilities: liveCoverage.capabilities.map(liveCap => {
        const merged = {
          ...(coverageById.get(Number(liveCap.id)) || {
          id: Number(liveCap.id),
          name: CAPABILITY_UI_NAMES[Number(liveCap.id)] || `Capability ${liveCap.id}`,
          source: 'Live agent telemetry',
        }),
        ...liveCap,
        };
        if (Number(liveCap.id) !== 23 || geoPolicyActive) return merged;
        return {
          ...merged,
          live: { ...(merged.live || {}), telemetryStatus: 'idle', logs24h: 0, previous24h: 0, highCritical24h: 0, unauthorized24h: 0, reportingAgents: 0, trendPct: 0, lastSeenAt: null, timeline24h: [] },
          metrics: { ...(merged.metrics || {}), logs24h: 0, previousLogs24h: 0, highCritical24h: 0, unauthorized24h: 0, reportingAgents: 0, timeline24h: [] },
        };
      }),
    };
  })();
  const routeCapability = coverageById.get(routeCapabilityId) || null;
  const activeCapConfig = routeCapabilityId ? getCapability(routeCapabilityId) : null;
  const routeCapabilityCategory = (() => {
    if (routeCapabilityId === 1) return 'edr';
    if ([2, 12, 18, 25, 27].includes(routeCapabilityId)) return 'file';
    if ([3, 9, 15, 20, 23, 26, 30, 31].includes(routeCapabilityId)) return 'network';
    if ([4, 11, 13, 14, 16].includes(routeCapabilityId)) return 'edr';
    if (routeCapabilityId === 5) return 'memory';
    if (routeCapabilityId === 6) return 'registry';
    if (routeCapabilityId === 7) return 'systemchanges';
    if (routeCapabilityId === 8) return 'persistence';
    if (routeCapabilityId === 10) return 'usb';
    return 'system';
  })();
  const routeCapabilityTitle = activeCapConfig
    ? `🛡️ ${activeCapConfig.id}. ${activeCapConfig.title}`
    : routeCapabilityId
      ? `🛡️ ${routeCapabilityId}. ${getCapabilityTitle(routeCapabilityId)}`
      : '';
  const normalizeCapabilityStatus = (status) => (
    status === 'implemented' ? 'active' : status === 'partial' ? 'partial' : 'missing'
  );

  /* ══════════════════════════════════════════════════════════
     RENDER
  ══════════════════════════════════════════════════════════ */
  return (
    <div style={{ fontFamily: 'Inter, sans-serif', color: '#e2e8f0' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <h2 style={{
            margin: 0, fontSize: 22, fontWeight: 800, color: '#e0f2fe',
            display: 'flex', alignItems: 'center', gap: 10
          }}>
            <span>🛡️</span> SOC AI — Endpoint Detection &amp; Response
          </h2>
          <div style={{ fontSize: 11, color: C.faint, marginTop: 4 }}>
            Correlation Engine · MITRE ATT&amp;CK · Threat Hunting · Incident Response
          </div>
        </div>
        <button onClick={loadAll} style={{
          fontSize: 11, padding: '7px 16px', borderRadius: 8, border: `1px solid ${C.faint}`,
          background: 'none', color: C.accent, cursor: 'pointer', display: 'flex', gap: 6, alignItems: 'center',
        }}>↺ Refresh</button>
      </div>

      {routeCapabilityId ? (
        <EDRCapabilityDashboardModal
          title={routeCapabilityTitle}
          category={routeCapabilityCategory}
          capabilityId={routeCapabilityId}
          backendId={routeBackendCapabilityId}
          overviewData={overviewCoverage}
          onClose={closeRouteCapability}
          processCapability={routeCapability}
        />
      ) : null}

      {/* ── Tabs ── */}
      <div style={{ display: 'flex', borderBottom: `1px solid ${C.border}`, marginBottom: 20, gap: 2 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: '9px 16px', fontSize: 12, cursor: 'pointer', border: 'none',
            background: tab === t.id ? `${C.accent}18` : 'none',
            color: tab === t.id ? C.accent : C.muted,
            fontWeight: tab === t.id ? 700 : 400,
            borderBottom: tab === t.id ? `2px solid ${C.accent}` : '2px solid transparent',
            borderRadius: '6px 6px 0 0', marginBottom: -1, transition: 'all .15s',
          }}>{t.label}</button>
        ))}
      </div>

      {/* ══ OVERVIEW ══════════════════════════════════════════ */}

      {tab === 'overview' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <EDRCapabilitiesDashboard
            data={overviewCoverage}
            loading={capLoading}
            onOpenCapability={openCapabilityCard}
          />

          {/* ── 35 Monitoring Capabilities Card ── */}
          {false && <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: 24 }}>
            {/* Card header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{
                  width: 44, height: 44, borderRadius: 10, display: 'flex', alignItems: 'center',
                  justifyContent: 'center', fontSize: 22,
                  background: `linear-gradient(135deg, ${C.accent}22, ${C.cyan}22)`,
                  border: `1px solid ${C.accent}33`,
                }}>🛡️</div>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 800, color: '#e0f2fe' }}>All 31 EDR Monitoring Capabilities</div>
                  <div style={{ fontSize: 11, color: C.faint, marginTop: 2 }}>
                    SOC Agent · Correlation Engine · MITRE ATT&CK · YARA · VT · IPS · SOAR
                  </div>
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: 22, fontWeight: 900, color: C.green }}>{coverageSummary.implemented ?? '—'}/{coverageSummary.total ?? 31}</div>
                <div style={{ fontSize: 9, color: C.muted, fontWeight: 600 }}>CAPABILITIES</div>
              </div>
            </div>

            {/* Legend */}
            <div style={{ display: 'flex', gap: 16, marginBottom: 16, fontSize: 10, color: C.muted }}>
              <span><span style={{ color: C.green }}>●</span> Active (Implemented)</span>
              <span><span style={{ color: C.yellow }}>◐</span> Partial Coverage</span>
              <span><span style={{ color: C.red }}>○</span> Needs Integration</span>
            </div>

            {/* 31 capabilities grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 8 }}>
              {[
                { id: 1, icon: '⚙️', name: 'Process Activity Monitoring', status: 'active', source: 'collectors/processes.py + core/edr.py' },
                { id: 2, icon: '📁', name: 'File Activity Monitoring (FIM)', status: 'active', source: 'collectors/file_monitor.py + watchdog' },
                { id: 3, icon: '🌐', name: 'Network Activity Monitoring', status: 'active', source: 'collectors/network.py + VT enrichment' },
                { id: 4, icon: '🔐', name: 'User & Authentication Monitoring', status: 'active', source: 'detectors/rules.py AUTH_* rules' },
                { id: 5, icon: '🧠', name: 'Memory Activity Monitoring', status: 'active', source: 'core/memory_scanner.py + WIN_MIMIKATZ + CR-006' },
                { id: 6, icon: '🗝️', name: 'Registry Monitoring', status: 'active', source: 'core/registry_monitor.py + WIN_REG_PERSIST' },
                { id: 7, icon: '🖥️', name: 'System Changes Monitoring', status: 'active', source: 'rules.py SYS_* + anomaly.py' },
                { id: 8, icon: '🔄', name: 'Persistence Mechanism Detection', status: 'active', source: 'CR-007 + T1053/T1547/T1543' },
                { id: 9, icon: '🌍', name: 'Web & DNS Monitoring', status: 'active', source: 'core/dns_monitor.py + NET_DNS_TUNNEL + NET_TOR' },
                { id: 10, icon: '💾', name: 'Device Control (USB) Monitoring', status: 'active', source: 'collectors/usb.py + YARA + VT' },
                { id: 11, icon: '📊', name: 'Behavioral Analytics (UEBA)', status: 'active', source: 'anomaly.py + UEBA baseline + Hunt-3 geo anomaly' },
                { id: 13, icon: '🔒', name: 'Data Security Monitoring', status: 'active', source: 'FILE_SENSITIVE + NET_EXFIL + CR-011 + DLP rules' },
                { id: 14, icon: '🗝️', name: 'Credential Security Monitoring', status: 'active', source: 'WIN_MIMIKATZ + CR-002 + T1003' },
                { id: 16, icon: '↔️', name: 'Lateral Movement Detection', status: 'active', source: 'WIN_PSEXEC + CR-005 + T1021' },
                { id: 18, icon: '📧', name: 'Email Threat Monitoring', status: 'active', source: '/api/edr-cap/email-threats + Postfix log parser' },
                { id: 19, icon: '🕵️', name: 'Insider Threat Detection', status: 'active', source: 'CR-013 + impossible travel + UEBA per-user baseline' },
                { id: 20, icon: '🔧', name: 'Patch & Vulnerability Monitoring', status: 'active', source: '/api/edr-cap/patch-status + CVE alert correlation' },
                { id: 21, icon: '🧪', name: 'Sandbox Analysis', status: 'active', source: 'VT multi-engine + YARA + /api/edr-cap/sandbox' },
                { id: 22, icon: '⚡', name: 'Kernel-Level Monitoring', status: 'active', source: 'SYS_MODULE_LOAD + CR-014 + auditd syscall rules' },
                { id: 23, icon: '📡', name: 'API Call Monitoring', status: 'active', source: 'WIN_WMIC_EXEC + /api/edr-cap/api-calls + auditd' },
                { id: 24, icon: '📜', name: 'Script Execution Monitoring', status: 'active', source: 'WIN_POWERSHELL + WIN_LOLBIN + T1059' },
                { id: 26, icon: '⏰', name: 'Time-Based Anomaly Detection', status: 'active', source: 'anomaly.py baseline + Hunt-5 surge + hourly profiling' },
                { id: 23, icon: '🗺️', name: 'Geolocation Anomaly Detection', status: 'active', source: '/api/edr-cap/geo-anomalies + core/geo_enrichment.py' },
                { id: 28, icon: '🔌', name: 'Service Monitoring', status: 'active', source: 'SYS_SERVICE_FAIL + /api/edr-cap/service-status + psutil' },
                { id: 30, icon: '🔬', name: 'Hash / Signature Analysis', status: 'active', source: 'file_monitor.py + yara_scanner.py + VT' },
                { id: 31, icon: '📶', name: 'Beaconing Detection', status: 'active', source: 'Hunt-1 C2 + CR-004 + T1071.001' },
                { id: 32, icon: '🔐', name: 'Encryption / Ransomware Detection', status: 'active', source: 'RANSOMWARE_* rules + CR-001 + T1486' },
                { id: 33, icon: '🪝', name: 'LOLBins Detection', status: 'active', source: 'WIN_LOLBIN + CR-008 + T1218' },
                { id: 36, icon: '💥', name: 'Memory Overflow Detection', status: 'active', source: 'core/memory_overflow.py + SIGSEGV + heap spray + ASAN' },
                { id: 37, icon: '🔍', name: 'DNS Cache Poisoning Detection', status: 'active', source: 'core/cache_poison_detector.py + TTL drop + IP change' },
                { id: 38, icon: '🌀', name: 'DNS Sinkhole', status: 'active', source: 'core/dns_sinkhole.py + /api/advanced/sinkhole' },
              ].map((baseCap, index) => {
                const liveCap = coverageById.get(baseCap.id);
                const cap = liveCap ? {
                  ...baseCap,
                  ...liveCap,
                  status: normalizeCapabilityStatus(liveCap.status),
                  source: liveCap.source || baseCap.source,
                } : baseCap;
                const col = cap.status === 'active' ? C.green
                  : cap.status === 'partial' ? C.yellow : C.red;
                const dot = cap.status === 'active' ? '●'
                  : cap.status === 'partial' ? '◐' : '○';
                return (
                  <div key={cap.id}
                    onClick={() => openCapabilityCard(cap)}
                    role="button"
                    tabIndex={0}
                    onKeyDown={e => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault();
                        openCapabilityCard(cap);
                      }
                    }}
                    style={{
                      display: 'flex', alignItems: 'flex-start', gap: 10,
                      padding: '9px 12px', borderRadius: 8,
                      background: `${col}08`,
                      border: `1px solid ${col}22`,
                      cursor: 'pointer',
                      transition: 'all .15s',
                    }}
                    onMouseEnter={e => {
                      e.currentTarget.style.background = `${col}18`;
                      e.currentTarget.style.borderColor = `${col}55`;
                      e.currentTarget.style.transform = 'translateY(-1px)';
                      e.currentTarget.style.boxShadow = `0 4px 16px ${col}22`;
                    }}
                    onMouseLeave={e => {
                      e.currentTarget.style.background = `${col}08`;
                      e.currentTarget.style.borderColor = `${col}22`;
                      e.currentTarget.style.transform = 'translateY(0)';
                      e.currentTarget.style.boxShadow = 'none';
                    }}
                  >
                    {/* number badge */}
                    <div style={{
                      minWidth: 22, height: 22, borderRadius: 6, fontSize: 9, fontWeight: 800,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: `${col}22`, color: col, flexShrink: 0, marginTop: 1,
                    }}>{index + 1}</div>

                    {/* icon */}
                    <div style={{ fontSize: 14, flexShrink: 0, marginTop: 1 }}>{cap.icon}</div>

                    {/* text */}
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 6 }}>
                        <div style={{ fontSize: 11, fontWeight: 700, color: '#e2e8f0', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {cap.name}
                        </div>
                        <span style={{ fontSize: 8, color: '#38bdf8', fontWeight: 900, background: 'rgba(56,189,248,0.12)', border: '1px solid rgba(56,189,248,0.3)', padding: '1px 5px', borderRadius: 4, flexShrink: 0 }}>
                          {Number(cap.live?.logs24h ?? cap.metrics?.logs24h ?? cap.logs24h ?? 0).toLocaleString()} 24h
                        </span>
                      </div>
                      <div style={{ fontSize: 9, color: C.faint, marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {cap.source}
                      </div>
                      {cap.evidence && (
                        <div style={{ fontSize: 9, color: C.cyan, marginTop: 2, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {cap.evidence}
                        </div>
                      )}
                    </div>

                    {/* status dot + click hint */}
                    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, flexShrink: 0 }}>
                      <div style={{ fontSize: 14, color: col, fontWeight: 900 }}>{dot}</div>
                      <div style={{ fontSize: 7, color: C.faint, opacity: 0.7 }}>details</div>
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Bottom summary bar */}
            <div style={{
              display: 'flex', gap: 20, marginTop: 18, paddingTop: 16,
              borderTop: `1px solid ${C.border}`, fontSize: 11,
            }}>
              <span style={{ color: C.green, fontWeight: 700 }}>✅ {coverageSummary.implemented ?? 0} Active</span>
              <span style={{ color: C.yellow, fontWeight: 700 }}>⚠️ {coverageSummary.partial ?? 0} Partial</span>
              <span style={{ color: C.red, fontWeight: 700 }}>❌ {coverageSummary.missing ?? 0} Missing</span>
              <span style={{ marginLeft: 'auto', color: C.cyan, fontWeight: 700 }}>
                Coverage: <span style={{ fontSize: 14 }}>{coverageSummary.score ?? 0}%</span>
              </span>
            </div>
          </div>}

        </div>
      )}

      {/* ── Capability Detail Modal ── */}
      {selectedCap && <CapabilityModal cap={selectedCap} onClose={() => setSelectedCap(null)} />}


      {/* ══ INCIDENTS ═════════════════════════════════════════ */}
      {tab === 'incidents' && (
        <div style={{ display: 'grid', gridTemplateColumns: selInc ? '1fr 380px' : '1fr', gap: 16 }}>

          {/* List panel */}
          <div>
            {/* Filters */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
              {[
                { key: 'severity', opts: ['', 'critical', 'high', 'medium', 'low'], label: 'Severity' },
                { key: 'status', opts: ['', 'open', 'investigating', 'resolved', 'false_positive'], label: 'Status' },
                { key: 'category', opts: ['', 'ransomware', 'credential_dumping', 'c2_communication', 'lateral_movement', 'malware', 'persistence', 'data_exfiltration', 'zero_day', 'usb_threat'], label: 'Category' },
              ].map(f => (
                <select key={f.key} value={incFilter[f.key]}
                  onChange={e => {
                    const next = { ...incFilter, [f.key]: e.target.value };
                    setIncFilter(next); setIncPage(1); fetchIncidents(1, next);
                  }}
                  style={{
                    padding: '6px 10px', borderRadius: 7, fontSize: 11, border: `1px solid ${C.border}`,
                    background: C.card, color: C.muted, cursor: 'pointer'
                  }}>
                  <option value="">{f.label}: All</option>
                  {f.opts.slice(1).map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ))}
              <div style={{ marginLeft: 'auto', fontSize: 11, color: C.faint, alignSelf: 'center' }}>
                {incTotal} total
              </div>
            </div>

            {/* Table */}
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: 'hidden' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                <thead>
                  <tr style={{ background: C.bg, borderBottom: `1px solid ${C.border}` }}>
                    {['Incident', 'Sev', 'Status', 'Confidence', 'Alerts', 'Endpoint', 'Created'].map(h =>
                      <th key={h} style={{ textAlign: 'left', padding: '9px 12px', color: C.faint, fontSize: 10, fontWeight: 700 }}>{h}</th>
                    )}
                  </tr>
                </thead>
                <tbody>
                  {incidents.length === 0
                    ? <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: C.faint }}>No incidents match the filters</td></tr>
                    : incidents.map(inc => (
                      <tr key={inc._id} onClick={() => setSelInc(inc)}
                        style={{
                          borderBottom: `1px solid ${C.border}`, cursor: 'pointer',
                          background: selInc?._id === inc._id ? `${C.accent}18` : 'transparent',
                        }}
                        onMouseEnter={e => { if (selInc?._id !== inc._id) e.currentTarget.style.background = `${C.accent}08`; }}
                        onMouseLeave={e => { if (selInc?._id !== inc._id) e.currentTarget.style.background = 'transparent'; }}>
                        <td style={{ padding: '9px 12px', fontWeight: 600, maxWidth: 240 }}>
                          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: '#e2e8f0' }}>{inc.title}</div>
                          <div style={{ fontSize: 10, color: C.muted, marginTop: 2, fontFamily: 'monospace' }}>{inc.mitreTechnique} · {(inc.category || '').replace(/_/g, ' ')}</div>
                        </td>
                        <td style={{ padding: '9px 12px' }}><Badge text={inc.severity} color={SEV_COLOR[inc.severity]} /></td>
                        <td style={{ padding: '9px 12px' }}><Badge text={inc.status} color={inc.status === 'open' ? C.red : inc.status === 'resolved' ? C.green : C.yellow} /></td>
                        <td style={{ padding: '9px 12px', color: C.cyan, fontWeight: 700 }}>{inc.confidenceScore}%</td>
                        <td style={{ padding: '9px 12px', color: C.muted, textAlign: 'center' }}>{inc.sourceAlertCount}</td>
                        <td style={{ padding: '9px 12px', color: C.muted, fontSize: 11, maxWidth: 120 }}>
                          <div style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {inc.affectedEndpoint || inc.agentName || '—'}
                          </div>
                        </td>
                        <td style={{ padding: '9px 12px', color: C.faint, fontSize: 11 }}>{timeAgo(inc.createdAt)}</td>
                      </tr>
                    ))
                  }
                </tbody>
              </table>

              {/* Pagination */}
              {incTotal > 15 && (
                <div style={{ display: 'flex', justifyContent: 'center', gap: 6, padding: 12, borderTop: `1px solid ${C.border}` }}>
                  {[...Array(Math.ceil(incTotal / 15))].slice(0, 8).map((_, i) => (
                    <button key={i} onClick={() => { setIncPage(i + 1); fetchIncidents(i + 1, incFilter); }}
                      style={{
                        width: 28, height: 28, borderRadius: 6, border: `1px solid ${i + 1 === incPage ? C.accent : C.border}`,
                        background: i + 1 === incPage ? `${C.accent}22` : 'none', color: i + 1 === incPage ? C.accent : C.muted,
                        cursor: 'pointer', fontSize: 11, fontWeight: 600
                      }}>
                      {i + 1}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Detail panel */}
          {selInc && <IncidentDetail inc={selInc} onClose={() => setSelInc(null)}
            onAction={takeAction} onStatus={updateStatus} pending={actionPending}
            onAiAnalyze={analyseIncident} aiPending={aiPending} />}
        </div>
      )}

      {/* ══ ENDPOINTS ═════════════════════════════════════════ */}
      {tab === 'endpoints' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {endpoints.length === 0
            ? <div style={{ textAlign: 'center', color: C.faint, padding: 60, fontSize: 14 }}>
              No active endpoints. Install the SOC Agent on endpoints to monitor them.
            </div>
            : (
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
                  <thead>
                    <tr style={{ background: C.bg, borderBottom: `1px solid ${C.border}` }}>
                      {['Endpoint', 'Risk', 'Score', 'Critical', 'High', 'Medium', 'Open Incidents', 'Last Seen', 'Status'].map(h =>
                        <th key={h} style={{ textAlign: 'left', padding: '9px 12px', color: C.faint, fontSize: 10, fontWeight: 700 }}>{h}</th>
                      )}
                    </tr>
                  </thead>
                  <tbody>
                    {endpoints.map(ep => {
                      const rc = SEV_COLOR[ep.riskLevel] || C.muted;
                      return (
                        <tr key={ep.systemId} style={{ borderBottom: `1px solid ${C.border}` }}>
                          <td style={{ padding: '10px 12px' }}>
                            <div style={{ fontWeight: 700, color: '#e2e8f0' }}>🖥 {ep.name || ep.hostname}</div>
                            <div style={{ fontSize: 10, color: C.faint, marginTop: 1 }}>{ep.hostname} · {ep.ip}</div>
                            <div style={{ fontSize: 10, color: C.muted, marginTop: 1 }}>{ep.os}</div>
                          </td>
                          <td style={{ padding: '10px 12px' }}><Badge text={ep.riskLevel} color={rc} /></td>
                          <td style={{ padding: '10px 12px', fontWeight: 900, fontSize: 18, color: rc }}>{ep.riskScore}</td>
                          <td style={{ padding: '10px 12px', color: C.red, fontWeight: 700, textAlign: 'center' }}>{ep.alerts?.critical ?? 0}</td>
                          <td style={{ padding: '10px 12px', color: C.orange, textAlign: 'center' }}>{ep.alerts?.high ?? 0}</td>
                          <td style={{ padding: '10px 12px', color: C.yellow, textAlign: 'center' }}>{ep.alerts?.medium ?? 0}</td>
                          <td style={{ padding: '10px 12px', color: ep.openIncidents > 0 ? C.red : C.green, textAlign: 'center', fontWeight: 700 }}>{ep.openIncidents}</td>
                          <td style={{ padding: '10px 12px', color: C.faint, fontSize: 11 }}>{timeAgo(ep.lastSeen)}</td>
                          <td style={{ padding: '10px 12px' }}>
                            {ep.isIsolated
                              ? <Badge text="ISOLATED" color={C.orange} />
                              : <Badge text={ep.status || 'active'} color={ep.status === 'active' ? C.green : C.muted} />
                            }
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          }
        </div>
      )}

      {/* ══ THREAT HUNT ═══════════════════════════════════════ */}
      {tab === 'hunt' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 24 }}>
            <SectionTitle>Proactive Threat Hunt — Last 24h Telemetry</SectionTitle>
            <div style={{ fontSize: 12, color: C.muted, marginBottom: 16 }}>
              Runs pattern analysis across 24h of alerts looking for beaconing, malware clusters, impossible travel, brute force surges, and VT gaps.
            </div>
            <button onClick={runHunt} disabled={hunting}
              style={{
                padding: '10px 24px', borderRadius: 8, fontSize: 13, fontWeight: 700,
                background: hunting ? C.border : `linear-gradient(135deg, #1d4ed8, #7c3aed)`,
                border: 'none', color: '#fff', cursor: hunting ? 'not-allowed' : 'pointer',
                display: 'flex', alignItems: 'center', gap: 8
              }}>
              {hunting ? <><Spinner size={14} /> Running Hunt…</> : '🔍 Run Threat Hunt Now'}
            </button>
          </div>

          {hunt && (
            <>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {statCard('🔍', 'Findings', hunt.hunts?.length, C.red)}
                {statCard('📊', 'Alerts Scanned', hunt.totalAlerts, C.accent)}
                {statCard('🕐', 'Scanned At', new Date(hunt.scannedAt).toLocaleTimeString(), C.cyan)}
              </div>

              {hunt.hunts && hunt.hunts.length === 0 && (
                <div style={{
                  background: C.card, border: `1px solid ${C.green}33`, borderRadius: 12, padding: 24,
                  textAlign: 'center', color: C.green, fontSize: 14, fontWeight: 700
                }}>
                  ✅ No threats found in latest 24h scan
                </div>
              )}

              {(hunt.hunts || []).map((h, i) => (
                <div key={i} style={{
                  background: C.card, border: `1px solid ${SEV_COLOR[h.severity]}44`,
                  borderRadius: 12, padding: 20,
                  borderLeft: `4px solid ${SEV_COLOR[h.severity]}`,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <Badge text={h.severity} color={SEV_COLOR[h.severity]} />
                    <span style={{ fontSize: 14, fontWeight: 800, color: SEV_COLOR[h.severity] }}>{h.title}</span>
                    <span style={{ marginLeft: 'auto', fontFamily: 'monospace', fontSize: 11, color: C.purple }}>{h.mitre}</span>
                  </div>
                  <div style={{ fontSize: 12, color: C.muted, lineHeight: 1.7 }}>{h.details}</div>
                  <div style={{ marginTop: 8, fontSize: 11, color: C.faint }}>
                    {h.affectedAlerts} alert(s) involved · Type: <span style={{ color: C.cyan }}>{h.type}</span>
                  </div>
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* ══ FORENSIC HUNT ═══════════════════════════════════ */}
      {tab === 'forensic' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 24, alignItems: 'stretch' }}>
            {/* Left: Launch Forensic Hunt */}
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 18, padding: 32, minWidth: 0, display: 'flex', flexDirection: 'column', justifyContent: 'flex-start' }}>
              <SectionTitle><span style={{ fontSize: 22, marginRight: 10 }}>⚡</span> Launch Forensic Hunt</SectionTitle>
              <form>
                <div style={{ marginBottom: 22 }}>
                  <label style={{ fontSize: 15, color: C.cyan, fontWeight: 600 }}>Hunt Name *</label>
                  <input type="text" value={forensicForm.huntName} onChange={e => setForensicForm(f => ({ ...f, huntName: e.target.value }))} placeholder="Ransomware Investigation" style={{ width: '100%', padding: 13, borderRadius: 7, border: `1px solid ${C.border}`, background: C.bg, color: '#fff', marginTop: 7, fontSize: 16, boxSizing: 'border-box' }} />
                </div>
                <div style={{ marginBottom: 22 }}>
                  <label style={{ fontSize: 15, color: C.cyan, fontWeight: 600 }}>Artifact Name</label>
                  <input type="text" value={forensicForm.artifactName} onChange={e => setForensicForm(f => ({ ...f, artifactName: e.target.value }))} placeholder="Windows.System.Processes" style={{ width: '100%', padding: 13, borderRadius: 7, border: `1px solid ${C.border}`, background: C.bg, color: '#fff', marginTop: 7, fontSize: 16, boxSizing: 'border-box' }} />
                </div>
                <div style={{ marginBottom: 14 }}>
                  <label style={{ fontSize: 15, color: C.cyan, fontWeight: 600 }}>Company System</label>
                  <select
                    value={forensicForm.systemId}
                    onChange={e => {
                      const systemId = e.target.value;
                      const sys = systems.find(s => s._id === systemId);
                      setForensicForm(f => ({
                        ...f,
                        systemId,
                        clientId: sys?.velociraptorClientId || '',
                      }));
                    }}
                    style={{ width: '100%', padding: 13, borderRadius: 7, border: `1px solid ${C.border}`, background: C.bg, color: '#fff', marginTop: 7, fontSize: 16, boxSizing: 'border-box' }}
                  >
                    <option value="">All endpoints / no system selected</option>
                    {systems.map(sys => (
                      <option key={sys._id} value={sys._id} disabled={!sys.velociraptorClientId}>
                        {sys.name || sys.hostname || sys._id} {sys.departmentId?.name ? `- ${sys.departmentId.name}` : ''} {sys.velociraptorClientId ? `- ${sys.velociraptorClientId}` : '- no Velociraptor ID'}
                      </option>
                    ))}
                  </select>
                  {selectedForensicSystem && (
                    <div style={{ marginTop: 8, padding: '9px 11px', borderRadius: 8, border: `1px solid ${selectedForensicSystem.velociraptorClientId ? C.green : C.yellow}33`, background: `${selectedForensicSystem.velociraptorClientId ? C.green : C.yellow}08`, color: C.muted, fontSize: 12, lineHeight: 1.5 }}>
                      <span style={{ color: C.cyan, fontWeight: 800 }}>system_id:</span> {selectedForensicSystem._id}
                      <br />
                      <span style={{ color: C.cyan, fontWeight: 800 }}>velociraptorClientId:</span> {selectedForensicSystem.velociraptorClientId || 'not configured'}
                    </div>
                  )}
                </div>
                <div style={{ marginBottom: 28 }}>
                  <label style={{ fontSize: 15, color: C.cyan, fontWeight: 600 }}>Velociraptor Client ID</label>
                  <input type="text" value={forensicForm.clientId} onChange={e => setForensicForm(f => ({ ...f, clientId: e.target.value, systemId: '' }))} placeholder="C.xxxx (blank = all endpoints)" style={{ width: '100%', padding: 13, borderRadius: 7, border: `1px solid ${C.border}`, background: C.bg, color: '#fff', marginTop: 7, fontSize: 16, boxSizing: 'border-box' }} />
                </div>
                <div style={{ marginBottom: 22, padding: '10px 12px', borderRadius: 8, border: `1px solid ${C.cyan}33`, background: `${C.cyan}08`, color: C.muted, fontSize: 12, lineHeight: 1.5 }}>
                  <span style={{ color: C.cyan, fontWeight: 700 }}>Covers: </span>{forensicForm.covers}
                </div>
                <button type="button" onClick={launchForensicHunt} disabled={forensicLaunching} style={{ width: '100%', padding: '13px 0', borderRadius: 8, fontSize: 18, fontWeight: 700, background: forensicLaunching ? C.border : `linear-gradient(90deg, #1d4ed8, #7c3aed)`, border: 'none', color: '#fff', cursor: forensicLaunching ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 10, marginTop: 8 }}>
                  {forensicLaunching ? <><Spinner size={16} /> Launching…</> : <><span style={{ fontSize: 20 }}>⚡</span> Launch Hunt</>}
                </button>
              </form>
            </div>
            {/* Right: Common Artifacts */}
            <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 18, padding: 32, minWidth: 0, display: 'flex', flexDirection: 'column' }}>
              <SectionTitle><span style={{ fontSize: 20, marginRight: 10 }}>📚</span> Common Artifacts <span style={{ fontSize: 14, color: C.muted, fontWeight: 400, marginLeft: 8 }}>(click to use)</span></SectionTitle>
              <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
                {Object.keys(COMMON_FORENSIC_ARTIFACTS).map(os => (
                  <button key={os} type="button" onClick={() => applyForensicOs(os)} style={{ padding: '7px 14px', borderRadius: 8, border: `1px solid ${forensicOs === os ? C.accent : C.border}`, background: forensicOs === os ? `${C.accent}22` : C.bg, color: forensicOs === os ? C.cyan : C.muted, cursor: 'pointer', fontSize: 12, fontWeight: 800 }}>
                    {os}
                  </button>
                ))}
              </div>
              <div style={{ flex: 1, overflowY: 'auto', marginTop: 8, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 10 }}>
                {(COMMON_FORENSIC_ARTIFACTS[forensicOs] || []).map(([name, desc]) => {
                  const selected = forensicForm.artifactName === name;
                  return (
                    <button key={name} type="button" onClick={() => applyCommonArtifact(forensicOs, name, desc)} style={{ minHeight: 92, textAlign: 'left', background: selected ? '#1d3f68' : C.bg, borderRadius: 8, margin: 0, padding: 18, color: C.cyan, cursor: 'pointer', border: `1px solid ${selected ? C.accent : C.border}`, fontSize: 16, fontWeight: 700, display: 'flex', flexDirection: 'column', gap: 8, boxShadow: selected ? `0 0 0 1px ${C.accent}44` : 'none' }}>
                      <span style={{ overflowWrap: 'anywhere', lineHeight: 1.25 }}>{name}</span>
                      <span style={{ color: C.muted, fontSize: 13, fontWeight: 400, lineHeight: 1.45 }}>{desc}</span>
                    </button>
                  );
                })}
              </div>
            </div>
          </div>
          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 14, padding: 20 }}>
            <SectionTitle>Velociraptor DFIR Capabilities</SectionTitle>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 10 }}>
              {FORENSIC_AREAS.map(([title, artifact, items]) => {
                const selected = forensicForm.capability === title;
                return (
                  <div key={title}
                    style={{ textAlign: 'left', background: C.bg, border: `1px solid ${C.border}`, borderRadius: 10, padding: 14 }}>
                    <div style={{ color: C.cyan, fontSize: 13, fontWeight: 800, marginBottom: 8 }}>{title}</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {items.map(item => {
                        const itemSelected = selected && forensicForm.covers === item;
                        return (
                          <button
                            key={`${title}-${item}`}
                            type="button"
                            onClick={e => {
                              e.stopPropagation();
                              applyForensicItem(title, artifact, item);
                            }}
                            style={{ fontSize: 10, color: itemSelected ? C.cyan : C.muted, border: `1px solid ${itemSelected ? C.cyan : C.border}`, borderRadius: 999, padding: '3px 7px', background: itemSelected ? `${C.cyan}18` : `${C.accent}08`, cursor: 'pointer' }}
                          >
                            {item}
                          </button>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: 12 }}>
            {ADVANCED_FORENSICS.map(([title, items]) => (
              <div key={title} style={{ background: C.card, border: `1px solid ${C.purple}33`, borderRadius: 12, padding: 16 }}>
                <div style={{ color: C.purple, fontSize: 14, fontWeight: 800, marginBottom: 10 }}>{title}</div>
                {items.map(item => <div key={item} style={{ color: C.muted, fontSize: 12, marginBottom: 6 }}>→ {item}</div>)}
              </div>
            ))}
          </div>
        </div>
      )}
      {tab === 'mitre' && (

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {!mitre
            ? <div style={{ textAlign: 'center', padding: 40 }}><Spinner size={24} /></div>
            : (
              <>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {statCard('🗂', 'Techniques Detected', mitre.totalDetected, C.accent)}
                  {statCard('🛡', 'Detectable Rules', mitre.detectableRules?.length, C.green)}
                  {statCard('📅', 'Period', mitre.period, C.muted)}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                  {/* Detected techniques */}
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
                    <SectionTitle>Detected Techniques (30d)</SectionTitle>
                    {mitre.detectedTechniques?.length === 0
                      ? <div style={{ color: C.faint, fontSize: 12, textAlign: 'center', padding: 20 }}>No technique data yet</div>
                      : (mitre.detectedTechniques || []).map(t => (
                        <div key={t.id} style={{
                          marginBottom: 12, padding: '10px 14px', borderRadius: 8,
                          background: SEV_BG[t.severityMax], border: `1px solid ${SEV_COLOR[t.severityMax]}33`
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontFamily: 'monospace', fontSize: 12, color: C.purple, fontWeight: 700 }}>{t.id}</span>
                            <Badge text={t.severityMax} color={SEV_COLOR[t.severityMax]} />
                          </div>
                          <div style={{ fontSize: 12, color: '#e2e8f0', fontWeight: 600, marginTop: 4 }}>{t.name}</div>
                          <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
                            {(t.tactics || []).join(' · ')} · <span style={{ color: C.cyan }}>{t.count} incidents</span>
                          </div>
                        </div>
                      ))
                    }
                  </div>

                  {/* Detectable rules */}
                  <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
                    <SectionTitle>Correlation Rules Coverage</SectionTitle>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 460, overflowY: 'auto' }}>
                      {(mitre.detectableRules || []).map(r => (
                        <div key={r.ruleId} style={{
                          display: 'flex', alignItems: 'center', gap: 10,
                          padding: '8px 12px', borderRadius: 8, background: C.bg, border: `1px solid ${C.border}`
                        }}>
                          <span style={{ fontFamily: 'monospace', fontSize: 10, color: C.accent, fontWeight: 700, minWidth: 54 }}>{r.ruleId}</span>
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 11, color: '#e2e8f0', fontWeight: 600 }}>{r.name}</div>
                            <div style={{ fontSize: 10, color: C.muted }}>{(r.category || '').replace(/_/g, ' ')}</div>
                          </div>
                          <span style={{ fontSize: 9, color: C.green }}>✓ active</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </>
            )
          }
        </div>
      )}

      {/* ══ LIVE TELEMETRY ════════════════════════════════════ */}
      {tab === 'telemetry' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
            <div style={{ fontSize: 12, color: C.muted }}>
              <span style={{
                display: 'inline-block', width: 8, height: 8, borderRadius: '50%',
                background: C.green, marginRight: 6, boxShadow: `0 0 6px ${C.green}`
              }} />
              Live · auto-refreshing every 15s · Last 1h alerts ({telemetry.length})
            </div>
            <button onClick={fetchTelemetry} style={{
              fontSize: 11, padding: '5px 12px', borderRadius: 6,
              border: `1px solid ${C.border}`, background: 'none', color: C.accent, cursor: 'pointer'
            }}>
              ↺ Refresh
            </button>
          </div>

          <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, overflow: 'hidden' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: C.bg, borderBottom: `1px solid ${C.border}` }}>
                  {['Time', 'Severity', 'Category', 'Rule / Description', 'Agent', 'Source IP', 'User'].map(h =>
                    <th key={h} style={{ textAlign: 'left', padding: '9px 12px', color: C.faint, fontSize: 10, fontWeight: 700 }}>{h}</th>
                  )}
                </tr>
              </thead>
              <tbody>
                {telemetry.length === 0
                  ? <tr><td colSpan={7} style={{ padding: 40, textAlign: 'center', color: C.faint }}>No alerts in the last hour</td></tr>
                  : telemetry.map((a, i) => (
                    <tr key={a._id || i} style={{ borderBottom: `1px solid ${C.border}` }}
                      onMouseEnter={e => e.currentTarget.style.background = `${C.accent}08`}
                      onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                      <td style={{ padding: '7px 12px', color: C.faint, fontSize: 10, whiteSpace: 'nowrap' }}>
                        {timeAgo(a.createdAt)}
                      </td>
                      <td style={{ padding: '7px 12px' }}><Badge text={a.severity} color={SEV_COLOR[a.severity]} /></td>
                      <td style={{ padding: '7px 12px', color: C.cyan, fontSize: 11 }}>{a.eventCategory}</td>
                      <td style={{ padding: '7px 12px', maxWidth: 280 }}>
                        <div style={{ fontFamily: 'monospace', fontSize: 10, color: C.purple }}>{a.ruleId}</div>
                        <div style={{ fontSize: 11, color: C.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {a.description}
                        </div>
                      </td>
                      <td style={{ padding: '7px 12px', color: '#e2e8f0', fontSize: 11 }}>{a.agentName || '—'}</td>
                      <td style={{ padding: '7px 12px', fontFamily: 'monospace', fontSize: 10, color: C.orange }}>{a.srcip || '—'}</td>
                      <td style={{ padding: '7px 12px', color: C.muted, fontSize: 11 }}>{a.username || '—'}</td>
                    </tr>
                  ))
                }
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ══ 35-CAP COVERAGE AUDIT ═════════════════════════════ */}
      {tab === 'coverage' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {capLoading && <div style={{ textAlign: 'center', padding: 40 }}><Spinner size={24} /></div>}
          {!capLoading && coverage && (
            <>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {statCard('✅', 'Implemented', coverage.summary?.implemented, C.green)}
                {statCard('⚠️', 'Partial', coverage.summary?.partial, C.yellow)}
                {statCard('❌', 'Missing', coverage.summary?.missing, C.red)}
                {statCard('📊', 'Coverage Score', `${coverage.summary?.score}%`, C.cyan)}
              </div>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
                <SectionTitle>Overall EDR Coverage — {coverage.summary?.score}% of 35 Capabilities</SectionTitle>
                <div style={{ height: 12, borderRadius: 8, background: C.border, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 8, transition: 'width .6s',
                    width: `${coverage.summary?.score}%`,
                    background: coverage.summary?.score >= 80 ? C.green : coverage.summary?.score >= 60 ? C.yellow : C.red,
                  }} />
                </div>
                <div style={{ marginTop: 10, display: 'flex', gap: 16, fontSize: 11, color: C.muted }}>
                  <span><span style={{ color: C.green }}>●</span> Implemented: {coverage.summary?.implemented}</span>
                  <span><span style={{ color: C.yellow }}>●</span> Partial: {coverage.summary?.partial}</span>
                  <span><span style={{ color: C.red }}>●</span> Missing: {coverage.summary?.missing}</span>
                </div>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {(coverage.capabilities || []).map(cap => {
                  const col = cap.status === 'implemented' ? C.green : cap.status === 'partial' ? C.yellow : C.red;
                  const icon = cap.status === 'implemented' ? '✅' : cap.status === 'partial' ? '⚠️' : '❌';
                  return (
                    <div key={cap.id} style={{
                      background: C.card, border: `1px solid ${col}33`,
                      borderLeft: `4px solid ${col}`, borderRadius: 10, padding: '14px 18px',
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                            <span style={{ fontSize: 13, fontWeight: 800, color: col }}>
                              {icon} #{cap.cardNumber || getCapabilityCardNumber(cap.id)} — {cap.name}
                            </span>
                            {cap.newService && <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 10, background: `${C.cyan}22`, color: C.cyan, fontWeight: 700 }}>NEW</span>}
                          </div>
                          <div style={{ fontSize: 11, color: C.muted, marginBottom: 4 }}>{cap.description}</div>
                          <div style={{ fontSize: 10, color: C.faint, fontFamily: 'monospace' }}>Source: {cap.source}</div>
                          {cap.evidence && <div style={{ fontSize: 10, color: C.cyan, marginTop: 3 }}>📊 {cap.evidence}</div>}
                          {cap.gap && <div style={{ fontSize: 10, color: C.orange, marginTop: 4 }}>🔧 Gap: {cap.gap}</div>}
                        </div>
                        <div style={{ marginLeft: 12, display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 4 }}>
                          <Badge text={cap.status} color={col} />
                          <Badge text={cap.priority} color={cap.priority === 'critical' ? C.red : cap.priority === 'high' ? C.orange : C.muted} />
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </>
          )}
          {!capLoading && !coverage && (
            <div style={{ textAlign: 'center', color: C.faint, padding: 60 }}>Loading capability audit…</div>
          )}
        </div>
      )}

      {/* ══ NEW SERVICES ══════════════════════════════════════ */}
      {tab === 'services' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ background: C.card, border: `1px solid ${C.cyan}33`, borderRadius: 12, padding: 20 }}>
            <SectionTitle>🆕 Newly Added Detection Services (8 Capabilities)</SectionTitle>
            <div style={{ fontSize: 12, color: C.muted }}>Capabilities identified as gaps and now implemented or have integration endpoints.</div>
          </div>
          {(newSvcs?.services || []).map(svc => (
            <div key={svc.id} style={{ background: C.card, border: `1px solid ${C.cyan}33`, borderLeft: `4px solid ${C.cyan}`, borderRadius: 10, padding: '16px 20px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                <div style={{ fontSize: 14, fontWeight: 800, color: C.cyan }}>{svc.name}</div>
                <div style={{ display: 'flex', gap: 6 }}>
                  <Badge text="NEW" color={C.cyan} />
                  <Badge text={svc.priority} color={svc.priority === 'high' ? C.orange : C.muted} />
                </div>
              </div>
              <div style={{ fontSize: 12, color: C.muted, marginBottom: 8 }}>{svc.description}</div>
              <div style={{ fontSize: 11, fontFamily: 'monospace', color: C.purple, marginBottom: 8 }}>📡 {svc.implementation}</div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {(svc.mitreIds || []).map(m => (
                  <span key={m} style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: `${C.purple}18`, color: C.purple, fontFamily: 'monospace' }}>{m}</span>
                ))}
              </div>
            </div>
          ))}
          {!newSvcs && <div style={{ textAlign: 'center', padding: 40 }}><Spinner size={20} /></div>}
        </div>
      )}

      {/* ══ SERVICE STATUS ════════════════════════════════════ */}
      {tab === 'svcstatus' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {svcStatus ? (
            <>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                {statCard('🔌', 'Services', svcStatus.summary?.totalServices, C.cyan)}
                {statCard('✅', 'Running', svcStatus.summary?.running, C.green)}
                {statCard('🤖', 'Active Agents', svcStatus.summary?.activeAgents, C.accent)}
                {statCard('⚠️', 'Offline Agents', svcStatus.summary?.offlineAgents, C.orange)}
              </div>
              <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
                <SectionTitle>Security Services Health</SectionTitle>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 10 }}>
                  {(svcStatus.services || []).map(svc => {
                    const ok = svc.status === 'running' || svc.status === 'configured';
                    return (
                      <div key={svc.name} style={{ padding: '12px 16px', borderRadius: 8, border: `1px solid ${ok ? C.green : C.orange}33`, background: ok ? `${C.green}08` : `${C.orange}08` }}>
                        <div style={{ fontSize: 18, marginBottom: 4 }}>{svc.icon}</div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: ok ? C.green : C.orange }}>{svc.name}</div>
                        <div style={{ fontSize: 10, color: C.muted, marginTop: 2 }}>{svc.status}{svc.count != null ? ` (${svc.count})` : ''}</div>
                      </div>
                    );
                  })}
                </div>
              </div>
              {(svcStatus.activeEndpoints || []).length > 0 && (
                <div style={{ background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 20 }}>
                  <SectionTitle>Active Endpoints (24h)</SectionTitle>
                  {svcStatus.activeEndpoints.map(ep => (
                    <div key={ep._id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: `1px solid ${C.border}` }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: '#e2e8f0' }}>🖥 {ep.name}</div>
                        <div style={{ fontSize: 10, color: C.faint }}>{ep.hostname}</div>
                      </div>
                      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                        <Badge text={ep.status || 'active'} color={C.green} />
                        <span style={{ fontSize: 10, color: C.faint }}>{timeAgo(ep.lastSeen)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              )}
              {(svcStatus.offlineEndpoints || []).length > 0 && (
                <div style={{ background: C.card, border: `1px solid ${C.orange}33`, borderRadius: 12, padding: 20 }}>
                  <SectionTitle>⚠️ Offline Agents (&gt;24h)</SectionTitle>
                  {svcStatus.offlineEndpoints.map(ep => (
                    <div key={ep._id} style={{ display: 'flex', justifyContent: 'space-between', padding: '8px 0', borderBottom: `1px solid ${C.border}` }}>
                      <div>
                        <div style={{ fontSize: 12, fontWeight: 700, color: C.orange }}>🖥 {ep.name}</div>
                        <div style={{ fontSize: 10, color: C.faint }}>{ep.hostname}</div>
                      </div>
                      <span style={{ fontSize: 10, color: C.orange }}>{timeAgo(ep.lastSeen)}</span>
                    </div>
                  ))}
                </div>
              )}
              {(svcStatus.disabledAlerts || []).length > 0 && (
                <div style={{ background: C.card, border: `1px solid ${C.red}33`, borderRadius: 12, padding: 20 }}>
                  <SectionTitle>🔴 Security Service Disabled Alerts (24h)</SectionTitle>
                  {svcStatus.disabledAlerts.map((a, i) => (
                    <div key={i} style={{ padding: '8px 0', borderBottom: `1px solid ${C.border}`, fontSize: 11 }}>
                      <div style={{ color: C.red, fontWeight: 700 }}>{a.ruleId}</div>
                      <div style={{ color: C.muted }}>{a.description}</div>
                      <div style={{ color: C.faint, fontSize: 10 }}>{a.agentName} · {timeAgo(a.createdAt)}</div>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <div style={{ textAlign: 'center', padding: 40 }}><Spinner size={24} /></div>
          )}
        </div>
      )}

    </div>
  );
}


/* ══════════════════════════════════════════════════════════
   Capability Detail Modal
══════════════════════════════════════════════════════════ */

const CAP_DETAILS = {
  1: { mitre: ['T1057', 'T1059'], tactics: ['Execution', 'Discovery'], desc: 'Monitors running processes, CPU/RAM usage, process start/termination, PID, parent-child relationship, command line, suspicious/unauthorized execution, and high resource consumption.', steps: ['Agent polls psutil every 30s', 'PROC_STARTED / PROC_TERMINATED track lifecycle after baseline', 'PROC_INVENTORY_SUMMARY reports running process count and top CPU/RAM', 'Suspicious process name/cmdline and unauthorized path rules raise high/critical alerts', 'Alerts sent to /api/alerts; SOAR can auto-kill malicious PIDs'] },
  2: { mitre: ['T1565', 'T1083'], tactics: ['Impact', 'Discovery'], desc: 'Real-time file system event monitoring using inotify on Linux and FSEvents on macOS. Detects creates, modifies, deletes on sensitive paths.', steps: ['watchdog library monitors filesystem', 'SHA-256 hash computed on change', 'Alerts include old/new path, hash, user'] },
  3: { mitre: ['T1071', 'T1090'], tactics: ['C2', 'Exfiltration'], desc: 'Captures all network connections including source/dest IP, port, protocol, and process. VT enriches external IPs automatically.', steps: ['psutil.net_connections() polled', 'Outbound IPs sent to VirusTotal', 'C2 beaconing detected via Hunt-1'] },
  4: { mitre: ['T1078', 'T1110'], tactics: ['Persistence', 'Credential Access'], desc: 'Monitors authentication events including failed logins, privilege escalation, new accounts, and sudo usage.', steps: ['Auth log parsed (auth.log/Security.evtx)', 'Brute-force threshold: 5 fails/60s', 'New user creation triggers HIGH alert'] },
  5: { mitre: ['T1055', 'T1003'], tactics: ['Defense Evasion', 'Credential Access'], desc: 'Detects memory injection, process hollowing, and credential dumping tools like Mimikatz via signature rules.', steps: ['WIN_MIMIKATZ rule matches process name', 'CR-006 detects dump + lateral movement', 'Requires Velociraptor for deep memory scan'] },
  6: { mitre: ['T1547', 'T1060'], tactics: ['Persistence', 'Boot/Logon'], desc: 'Monitors Windows registry for persistence keys. Partial — covers Run/RunOnce keys via WIN_REG_PERSIST rule.', steps: ['WIN_REG_PERSIST detects registry writes', 'Only covers known persistence paths', 'Full registry stream requires Sysmon/EDR'] },
  7: { mitre: ['T1082', 'T1047'], tactics: ['Discovery'], desc: 'Detects system configuration changes, service failures, kernel module loads, and WMI activity.', steps: ['SYS_* rules match system events', 'SYS_MODULE_LOAD detects rootkit installs', 'anomaly.py detects baseline deviations'] },
  8: { mitre: ['T1053', 'T1547', 'T1543'], tactics: ['Persistence', 'Privilege Escalation'], desc: 'Detects scheduled tasks, startup items, services, and cron jobs created for persistence.', steps: ['CR-007 correlates persistence indicators', 'T1053 scheduled task creation detected', 'Agent checks /etc/cron.* and Task Scheduler'] },
  9: { mitre: ['T1071', 'T1568'], tactics: ['C2', 'Exfiltration'], desc: 'Monitors DNS queries for tunneling and suspicious domain lookups. Partial — relies on network log parsing.', steps: ['NET_DNS_TUNNEL detects long subdomains', 'NET_TOR detects Tor exit node traffic', 'Full DNS logging requires dedicated capture'] },
  10: { mitre: ['T1052', 'T1091'], tactics: ['Exfiltration', 'Lateral Movement'], desc: 'Real-time USB device event monitoring. All connected devices are logged, hashed, and scanned via YARA and VirusTotal.', steps: ['pyudev monitors udev events (Linux)', 'WMI Win32_USBHub on Windows', 'Files copied from USB auto-scanned with YARA'] },
  11: { mitre: ['T1078', 'T1133'], tactics: ['Defense Evasion', 'Persistence'], desc: 'Baseline behavioral analytics. Detects anomalies in login patterns, process counts, and network volume.', steps: ['anomaly.py builds 7-day baseline', 'Deviations >2σ trigger alerts', 'Hunt-3 detects impossible travel (geo)'] },
  12: { mitre: ['T1005', 'T1119'], tactics: ['Collection'], desc: 'Central log collection and correlation engine. 40+ detection rules, 14 correlation rules, 15-minute sliding window.', steps: ['Logs streamed from agent collectors', 'correlateAlerts() groups related events', '5-minute CORRELATION_INTERVAL in .env'] },
  13: { mitre: ['T1048', 'T1567'], tactics: ['Exfiltration'], desc: 'Monitors data movement including large file transfers, cloud uploads, and sensitive file access.', steps: ['FILE_SENSITIVE detects access to /etc/passwd etc.', 'NET_EXFIL detects large outbound transfers', 'CR-011 correlates exfiltration indicators'] },
  14: { mitre: ['T1003', 'T1555'], tactics: ['Credential Access'], desc: 'Detects credential theft attempts including Mimikatz, hash dumps, keyloggers, and pass-the-hash attacks.', steps: ['WIN_MIMIKATZ matches process signatures', 'CR-002 correlates credential + lateral move', 'T1003 OS Credential Dumping detection active'] },
  15: { mitre: ['T1190', 'T1203'], tactics: ['Initial Access'], desc: 'Detects exploitation attempts including zero-day patterns, buffer overflows, and shellcode injection.', steps: ['CR-012 detects zero-day pattern signatures', 'Anomaly baseline detects exploit artifacts', 'Full coverage needs sandbox + memory analysis'] },
  16: { mitre: ['T1021', 'T1076'], tactics: ['Lateral Movement'], desc: 'Detects lateral movement via PsExec, RDP, WMI, SMB, and pass-the-hash techniques.', steps: ['WIN_PSEXEC detects PsExec usage', 'CR-005 correlates lateral movement chain', 'T1021.002 SMB admin share access detected'] },
  17: { mitre: ['T1537', 'T1530'], tactics: ['Exfiltration'], desc: 'Cloud activity monitoring is not currently implemented. Requires cloud provider API integration (AWS CloudTrail, Azure Monitor).', steps: ['No cloud log ingestion implemented', '/api/edr-cap/cloud-events endpoint planned', 'Recommendation: Integrate AWS CloudTrail'] },
  18: { mitre: ['T1566', 'T1598'], tactics: ['Initial Access'], desc: 'Email threat monitoring is not implemented. Requires mail gateway integration (Exchange, Google Workspace, Postfix logs).', steps: ['No email log parsing implemented', '/api/edr-cap/email-threats endpoint planned', 'Recommendation: Integrate mail gateway syslog'] },
  19: { mitre: ['T1078', 'T1133'], tactics: ['Defense Evasion'], desc: 'Insider threat detection via behavioral anomalies, after-hours access, and impossible travel detection.', steps: ['CR-013 correlates insider indicators', 'Hunt-5 detects impossible travel', 'Needs user role/access baseline enrichment'] },
  20: { mitre: ['T1190', 'T1068'], tactics: ['Privilege Escalation'], desc: 'Vulnerability monitoring via OS package scan. Partial — patch status tracking not fully implemented.', steps: ['Basic OS version info collected by agent', 'Full CVE scan needs dedicated vuln scanner', 'Recommendation: Integrate OpenVAS or Trivy'] },
  21: { mitre: ['T1204', 'T1027'], tactics: ['Execution'], desc: 'Multi-engine sandbox analysis via VirusTotal (70+ AV engines). Local YARA scanning on all new/modified files.', steps: ['VirusTotal API active (500 req/day free)', 'yara_scanner.py scans file system', '/api/edr-cap/sandbox endpoint for manual submit'] },
  22: { mitre: ['T1014', 'T1215'], tactics: ['Defense Evasion'], desc: 'Detects kernel-level threats including rootkit installs, suspicious kernel module loads, and privilege escalation.', steps: ['SYS_MODULE_LOAD detects modprobe/insmod', 'CR-014 correlates rootkit indicators', 'Full kernel monitoring requires eBPF/Sysmon'] },
  23: { mitre: ['T1106', 'T1059'], tactics: ['Execution'], desc: 'API call monitoring via WMI and PowerShell execution logging. Partial coverage.', steps: ['WIN_WMIC_EXEC detects WMI abuse', 'Script execution logs captured', 'Full API monitoring needs ETW/eBPF tracing'] },
  24: { mitre: ['T1059', 'T1064'], tactics: ['Execution'], desc: 'Detects malicious script execution including PowerShell, cmd.exe, bash, Python, VBScript, and LOLBins.', steps: ['WIN_POWERSHELL detects encoded PS commands', 'WIN_LOLBIN covers 15+ LOLBin binaries', 'T1059.001-.007 sub-techniques covered'] },
  25: { mitre: ['T1565', 'T1070'], tactics: ['Impact', 'Defense Evasion'], desc: 'Real-time File Integrity Monitoring. Detects file creates, modifies, deletes, and renames on monitored paths.', steps: ['watchdog library with inotify/FSEvents', 'SHA-256 hash on every change', 'Critical paths: /etc, /bin, Windows System32'] },
  26: { mitre: ['T1078', 'T1110'], tactics: ['Defense Evasion'], desc: 'Time-based behavioral anomaly detection. Detects after-hours access, login surges, and traffic spikes.', steps: ['anomaly.py builds hourly/daily baseline', 'Hunt-5 detects alert surges (>3x baseline)', 'After-hours login triggers investigation alert'] },
  27: { mitre: ['T1078', 'T1133'], tactics: ['Defense Evasion'], desc: 'Geolocation anomaly detection for impossible travel and unusual login locations.', steps: ['Hunt-3 detects impossible travel', 'IP geolocation via MaxMind/IP-API', '/api/edr-cap/geo-anomalies endpoint planned'] },
  28: { mitre: ['T1489', 'T1543'], tactics: ['Impact', 'Persistence'], desc: 'Monitors security service health and detects unexpected service stops or configuration changes.', steps: ['SYS_SERVICE_FAIL detects service crashes', 'heartbeatSweeper monitors agent uptime', '/api/edr-cap/svc-status shows live status'] },
  29: { mitre: ['T1071', 'T1566'], tactics: ['C2'], desc: 'Threat intelligence enrichment via VirusTotal for IPs, hashes, and URLs found in alerts.', steps: ['VirusTotal API enriches every alert with srcip/hash', '70+ AV engine verdict cached 24h', '/api/edr-cap/threat-intel endpoint planned'] },
  30: { mitre: ['T1027', 'T1140'], tactics: ['Defense Evasion'], desc: 'File hash computation and signature-based malware detection using YARA rules and VirusTotal.', steps: ['file_monitor.py computes SHA-256 on every change', 'yara_scanner.py matches 3 YARA rule sets', 'VT hash lookup confirms malware classification'] },
  31: { mitre: ['T1071', 'T1008'], tactics: ['C2'], desc: 'Detects C2 beaconing patterns using time-interval analysis and frequency correlation.', steps: ['Hunt-1 groups alerts by srcip in 24h window', 'Regular interval pattern = C2 beaconing', 'CR-004 correlates C2 + data exfiltration'] },
  32: { mitre: ['T1486', 'T1490'], tactics: ['Impact'], desc: 'Ransomware detection via file extension changes, mass encryption patterns, shadow copy deletion, and known ransom signatures.', steps: ['RANSOMWARE_FILE_EXT detects .locked/.crypto etc.', 'RANSOMWARE_SHADOW detects vssadmin delete', 'CR-001 correlates ransomware kill chain'] },
  33: { mitre: ['T1218', 'T1127'], tactics: ['Defense Evasion'], desc: 'Living-off-the-Land Binary (LOLBin) detection covering 15+ Windows built-in tools abused by attackers.', steps: ['WIN_LOLBIN covers: certutil, regsvr32, mshta etc.', 'CR-008 detects LOLBin + network activity chain', 'T1218 sub-techniques .001-.015 covered'] },
  34: { mitre: ['T1005', 'T1071'], tactics: ['Collection', 'C2'], desc: 'Automatic alert correlation using a 15-minute sliding window to group related alerts into incidents.', steps: ['correlateAlerts() groups by srcip + agentId', 'EdrIncident created when threshold met', 'Confidence score calculated from alert count/severity'] },
  35: { mitre: ['T1562', 'T1489'], tactics: ['Impact'], desc: 'SOAR automated response including endpoint isolation, process kill, file quarantine, IP block, and user disable.', steps: ['SOAR rules trigger on alert conditions', 'Actions: isolate / kill / quarantine / block IP / disable user', 'runSoarForAlert() called on every new alert'] },
};

function CapabilityModal({ cap, onClose }) {
  const col = cap.status === 'active' ? C.green
    : cap.status === 'partial' ? C.yellow : C.red;
  const label = cap.status === 'active' ? 'ACTIVE'
    : cap.status === 'partial' ? 'PARTIAL' : 'MISSING';
  const detail = CAP_DETAILS[cap.id] || {};

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: 'rgba(6,13,22,0.85)', backdropFilter: 'blur(6px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        padding: 24,
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: C.card, border: `1px solid ${col}44`,
          borderTop: `4px solid ${col}`,
          borderRadius: 18, width: '100%', maxWidth: 680,
          maxHeight: '88vh', overflowY: 'auto',
          boxShadow: `0 24px 80px ${col}22, 0 4px 32px rgba(0,0,0,0.6)`,
        }}
      >
        {/* Header */}
        <div style={{ padding: '24px 28px 18px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
              <div style={{
                width: 52, height: 52, borderRadius: 14, fontSize: 26,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: `linear-gradient(135deg, ${col}22, ${col}11)`,
                border: `1px solid ${col}44`, flexShrink: 0,
              }}>{cap.icon}</div>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                  <span style={{
                    fontSize: 9, padding: '2px 8px', borderRadius: 20, fontWeight: 800,
                    color: '#060d16', background: col, letterSpacing: 1
                  }}>{label}</span>
                  <span style={{ fontSize: 11, color: C.muted, fontFamily: 'monospace' }}>CAP #{cap.cardNumber || getCapabilityCardNumber(cap.id)}</span>
                </div>
                <div style={{ fontSize: 17, fontWeight: 800, color: '#e0f2fe', lineHeight: 1.3 }}>{cap.name}</div>
              </div>
            </div>
            <button onClick={onClose} style={{
              background: `${C.border}66`, border: `1px solid ${C.border}`,
              color: C.muted, cursor: 'pointer', fontSize: 16,
              width: 32, height: 32, borderRadius: 8,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>✕</button>
          </div>
        </div>

        {/* Body */}
        <div style={{ padding: '20px 28px', display: 'flex', flexDirection: 'column', gap: 20 }}>

          {/* Description */}
          <div>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, letterSpacing: 1, marginBottom: 8, textTransform: 'uppercase' }}>Description</div>
            <div style={{ fontSize: 13, color: '#cbd5e1', lineHeight: 1.7 }}>
              {detail.desc || cap.source}
            </div>
          </div>

          {/* Status + Source row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div style={{ background: C.bg, border: `1px solid ${col}33`, borderRadius: 12, padding: '14px 16px' }}>
              <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Status</div>
              <div style={{ fontSize: 22, fontWeight: 900, color: col }}>{label}</div>
              <div style={{ fontSize: 10, color: C.muted, marginTop: 4 }}>
                {cap.status === 'active' ? 'Fully operational — alerts firing' :
                  cap.status === 'partial' ? 'Partially implemented — gaps exist' :
                    'Not implemented — needs integration'}
              </div>
            </div>
            <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 12, padding: '14px 16px' }}>
              <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Coverage</div>
              <div style={{
                height: 6, borderRadius: 4, background: C.border, overflow: 'hidden', marginBottom: 6,
              }}>
                <div style={{
                  height: '100%', borderRadius: 4,
                  background: col,
                  width: cap.status === 'active' ? '100%' : cap.status === 'partial' ? '55%' : '5%',
                  transition: 'width .6s',
                }} />
              </div>
              <div style={{ fontSize: 13, fontWeight: 800, color: col }}>
                {cap.status === 'active' ? '100%' : cap.status === 'partial' ? '55%' : '0%'}
              </div>
            </div>
          </div>

          {/* MITRE ATT&CK */}
          {detail.mitre && (
            <div style={{ background: C.bg, border: `1px solid ${C.purple}33`, borderRadius: 12, padding: '16px 18px' }}>
              <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>🎯 MITRE ATT&CK Mapping</div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                {detail.mitre.map(m => (
                  <span key={m} style={{
                    fontSize: 11, padding: '4px 10px', borderRadius: 8, fontWeight: 700,
                    fontFamily: 'monospace', background: `${C.purple}18`,
                    color: C.purple, border: `1px solid ${C.purple}33`,
                  }}>{m}</span>
                ))}
              </div>
              {detail.tactics && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {detail.tactics.map(t => (
                    <span key={t} style={{
                      fontSize: 10, padding: '2px 8px', borderRadius: 20,
                      background: `${C.cyan}18`, color: C.cyan, fontWeight: 600,
                    }}>{t}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Source Components */}
          <div>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>⚙️ Source Components</div>
            <div style={{
              background: C.bg, border: `1px solid ${C.border}`, borderRadius: 10,
              padding: '12px 14px', fontFamily: 'monospace', fontSize: 11,
              color: C.cyan, lineHeight: 1.8,
            }}>
              {cap.source}
            </div>
          </div>

          {/* How it works */}
          {detail.steps && (
            <div>
              <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>🔄 How It Works</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {detail.steps.map((step, i) => (
                  <div key={i} style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                    <div style={{
                      minWidth: 22, height: 22, borderRadius: 6, fontSize: 10, fontWeight: 800,
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: `${col}22`, color: col, flexShrink: 0,
                    }}>{i + 1}</div>
                    <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.6, paddingTop: 2 }}>{step}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Gap / Recommendation */}
          {cap.status !== 'active' && (
            <div style={{
              background: `${C.orange}0d`, border: `1px solid ${C.orange}33`,
              borderRadius: 12, padding: '14px 18px',
            }}>
              <div style={{ fontSize: 10, color: C.orange, fontWeight: 700, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>🔧 Gap & Recommendation</div>
              <div style={{ fontSize: 12, color: '#cbd5e1', lineHeight: 1.7 }}>
                {cap.status === 'partial'
                  ? `This capability is partially implemented. To reach full coverage: integrate dedicated tooling or extend the current agent rules to cover the remaining attack vectors mapped to ${(detail.mitre || []).join(', ')}.`
                  : `This capability is not yet implemented. Priority action: create an integration endpoint and connect a data source (e.g. cloud provider API, email gateway, or dedicated scanner) to provide coverage for ${(detail.mitre || []).join(', ')}.`
                }
              </div>
            </div>
          )}

        </div>

        {/* Footer */}
        <div style={{ padding: '14px 28px', borderTop: `1px solid ${C.border}`, display: 'flex', justifyContent: 'flex-end' }}>
          <button onClick={onClose} style={{
            padding: '8px 20px', borderRadius: 8, fontSize: 12, fontWeight: 700,
            background: `${col}18`, border: `1px solid ${col}44`,
            color: col, cursor: 'pointer',
          }}>Close</button>
        </div>
      </div>
    </div>
  );
}

function IncidentDetail({ inc, onClose, onAction, onStatus, pending, onAiAnalyze, aiPending }) {
  const sc = SEV_COLOR[inc.severity] || '#94a3b8';

  const ACTIONS = [
    { id: 'isolate_endpoint', label: '🔒 Isolate Endpoint', color: C.orange },
    { id: 'kill_process', label: '💀 Kill Process', color: C.red },
    { id: 'quarantine_file', label: '🗂 Quarantine File', color: C.yellow },
    { id: 'block_ip', label: '🚫 Block IP', color: C.red },
    { id: 'disable_user', label: '🔐 Disable User', color: C.orange },
    { id: 'escalate', label: '⬆ Escalate', color: C.purple },
    { id: 'resolve', label: '✅ Resolve', color: C.green },
    { id: 'mark_false_positive', label: '❌ False Positive', color: C.muted },
  ];

  return (
    <div style={{
      background: C.card, border: `1px solid ${sc}44`, borderRadius: 12,
      display: 'flex', flexDirection: 'column', gap: 0, overflow: 'hidden',
      borderTop: `3px solid ${sc}`
    }}>

      {/* Header */}
      <div style={{ padding: '16px 18px', borderBottom: `1px solid ${C.border}` }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
          <div style={{ flex: 1, marginRight: 8 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: sc, lineHeight: 1.3 }}>{inc.title}</div>
            <div style={{ fontSize: 11, color: C.muted, marginTop: 4 }}>{inc.description}</div>
          </div>
          <button onClick={onClose} style={{
            background: 'none', border: 'none', color: C.muted,
            cursor: 'pointer', fontSize: 16, padding: '2px 4px'
          }}>✕</button>
        </div>
        <div style={{ display: 'flex', gap: 6, marginTop: 10, flexWrap: 'wrap' }}>
          <Badge text={inc.severity} color={SEV_COLOR[inc.severity]} />
          <Badge text={inc.status} color={inc.status === 'open' ? C.red : inc.status === 'resolved' ? C.green : C.yellow} />
          <Badge text={`${inc.confidenceScore}% confidence`} color={C.cyan} />
        </div>
      </div>

      {/* Body */}
      <div style={{ overflowY: 'auto', flex: 1, maxHeight: 600 }}>

        {/* MITRE */}
        <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 6 }}>MITRE ATT&CK</div>
          <div style={{ fontFamily: 'monospace', fontSize: 12, color: C.purple, fontWeight: 700 }}>
            {inc.mitreTechnique} — {inc.mitreTechniqueName}
          </div>
          <div style={{ fontSize: 11, color: C.muted, marginTop: 2 }}>
            {(inc.mitreTactics || []).join(' · ')}
          </div>
        </div>

        {/* Details */}
        <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8 }}>DETAILS</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px', fontSize: 11 }}>
            {[
              ['Endpoint', inc.affectedEndpoint || inc.agentName || '—'],
              ['User', inc.affectedUser || '—'],
              ['Alerts', inc.sourceAlertCount],
              ['Category', (inc.category || '').replace(/_/g, ' ')],
              ['Created', inc.createdAt ? new Date(inc.createdAt).toLocaleString() : '—'],
              ['Last Event', inc.lastEventAt ? new Date(inc.lastEventAt).toLocaleString() : '—'],
            ].map(([k, v]) => (
              <div key={k}>
                <div style={{ color: C.faint, marginBottom: 1 }}>{k}</div>
                <div style={{ color: '#e2e8f0', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</div>
              </div>
            ))}
          </div>
        </div>

        {/* IOCs */}
        {inc.iocs && inc.iocs.length > 0 && (
          <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8 }}>IOCs ({inc.iocs.length})</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {inc.iocs.slice(0, 8).map((ioc, i) => (
                <div key={i} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', fontSize: 11 }}>
                  <Badge text={ioc.type} color={ioc.type === 'ip' ? C.red : ioc.type === 'hash' ? C.orange : C.muted} />
                  <span style={{ fontFamily: 'monospace', fontSize: 10, color: C.cyan, wordBreak: 'break-all' }}>{ioc.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Recommended actions */}
        {inc.recommendedActions && inc.recommendedActions.length > 0 && (
          <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8 }}>RECOMMENDED ACTIONS</div>
            {inc.recommendedActions.slice(0, 5).map((a, i) => (
              <div key={i} style={{ display: 'flex', gap: 6, marginBottom: 5, fontSize: 11, color: C.muted }}>
                <span style={{ color: C.yellow, flexShrink: 0 }}>→</span> {a}
              </div>
            ))}
          </div>
        )}

        {/* On-demand Azure AI investigation */}
        <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center', marginBottom: 8 }}>
            <div style={{ fontSize: 10, color: C.purple, fontWeight: 800 }}>✦ AZURE AI INVESTIGATION</div>
            <button
              disabled={aiPending || ['queued', 'processing'].includes(inc.aiInvestigation?.status)}
              onClick={() => onAiAnalyze(inc)}
              style={{
                padding: '6px 10px', borderRadius: 7, fontSize: 10, fontWeight: 800,
                border: `1px solid ${C.purple}55`, background: `${C.purple}18`,
                color: C.purple, cursor: aiPending ? 'not-allowed' : 'pointer',
              }}
            >
              {aiPending || ['queued', 'processing'].includes(inc.aiInvestigation?.status)
                ? `✦ ${inc.aiInvestigation?.status || 'Analysing'}…`
                : inc.aiInvestigation?.status === 'completed' ? '✦ Analyse Again' : '✦ AI Analyse Incident'}
            </button>
          </div>
          {inc.aiInvestigation?.status === 'completed' ? (
            <div style={{ color: C.muted, fontSize: 11, lineHeight: 1.6 }}>
              <div style={{ color: '#e2e8f0' }}>{inc.aiInvestigation.summary}</div>
              {inc.aiInvestigation.rootCause && <div><b style={{ color: C.purple }}>Root cause:</b> {inc.aiInvestigation.rootCause}</div>}
              <div><b style={{ color: C.cyan }}>Confidence:</b> {inc.aiInvestigation.confidence}%</div>
              {(inc.aiInvestigation.recommendedSteps || []).slice(0, 5).map((step, index) => (
                <div key={index}>→ {step}</div>
              ))}
            </div>
          ) : inc.aiInvestigation?.status === 'failed' ? (
            <div style={{ color: C.red, fontSize: 11 }}>AI investigation failed. Click Analyse Again to retry.</div>
          ) : (
            <div style={{ color: C.faint, fontSize: 11 }}>
              {['queued', 'processing'].includes(inc.aiInvestigation?.status)
                ? `AI investigation ${inc.aiInvestigation.status}. Result will appear automatically.`
                : 'Click AI Analyse Incident for an on-demand investigation.'}
            </div>
          )}
        </div>

        {/* Existing deterministic correlation analysis */}
        {inc.aiAnalysis && (
          <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8 }}>CORRELATION ANALYSIS</div>
            <pre style={{
              fontSize: 10, color: C.muted, whiteSpace: 'pre-wrap', fontFamily: 'monospace',
              lineHeight: 1.6, maxHeight: 200, overflowY: 'auto', margin: 0
            }}>
              {inc.aiAnalysis}
            </pre>
          </div>
        )}

        {/* Response actions */}
        {inc.status !== 'resolved' && inc.status !== 'false_positive' && (
          <div style={{ padding: '12px 18px', borderBottom: `1px solid ${C.border}` }}>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 10 }}>RESPONSE ACTIONS</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 6 }}>
              {ACTIONS.map(a => (
                <button key={a.id} disabled={pending}
                  onClick={() => onAction(inc._id, a.id)}
                  style={{
                    padding: '7px 10px', borderRadius: 7, fontSize: 10, fontWeight: 700,
                    border: `1px solid ${a.color}44`, background: `${a.color}12`,
                    color: a.color, cursor: pending ? 'not-allowed' : 'pointer', textAlign: 'left'
                  }}>
                  {pending ? '…' : a.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Action log */}
        {inc.actionsLog && inc.actionsLog.length > 0 && (
          <div style={{ padding: '12px 18px' }}>
            <div style={{ fontSize: 10, color: C.faint, fontWeight: 700, marginBottom: 8 }}>ACTION LOG</div>
            {inc.actionsLog.slice(-5).reverse().map((log, i) => (
              <div key={i} style={{ fontSize: 10, color: C.muted, marginBottom: 6, lineHeight: 1.5 }}>
                <span style={{ color: C.accent }}>{log.action}</span> ·{' '}
                <span style={{ color: '#e2e8f0' }}>{log.result}</span> ·{' '}
                <span style={{ color: C.faint }}>{log.takenAt ? new Date(log.takenAt).toLocaleString() : ''}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
