/**
 * Device Control (USB) Monitoring — Capability ID: 10
 * 
 * 100% Self-Contained Enterprise SOC Device Control (USB) Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=10`), MongoDB Alert Query, and Socket.io Real-Time Streaming
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

function MiniSparkline({ data = [], color = MON.cyan, height = 30 }) {
  const values = data.length ? data : [0, 0];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values.map((val, idx) => {
    const x = (idx / (values.length - 1)) * 100;
    const y = height - ((val - min) / (max - min || 1)) * (height - 6) - 3;
    return `${x},${y}`;
  }).join(' ');

  return (
    <svg viewBox={`0 0 100 ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible' }}>
      <polyline fill="none" stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" points={points} />
    </svg>
  );
}

const usbValue = (event, camel, snake) => event?.[camel] ?? event?.rawEvent?.[camel]
  ?? event?.rawEvent?.[snake] ?? event?.[snake];

function usbEventFacts(event = {}) {
  const rule = String(event.ruleId || event.rule_id || event.type || '').toUpperCase();
  const action = String(event.userAction || event.user_action || event.fileAction || event.file_action || event.eventType || '').toLowerCase();
  const description = String(event.description || '').toLowerCase();
  const deviceType = String(event.deviceType || event.rawEvent?.device_type || '').toLowerCase();
  const enforcement = String(event.usbEnforcementStatus || event.enforcement_status || event.rawEvent?.enforcement_status || '').toLowerCase();
  const policyRuleType = String(event.usbPolicyRuleType || event.policy_rule_type || event.rawEvent?.policy_rule_type || '').toLowerCase();
  const connected = rule === 'USB_DEVICE_EVENT' && action === 'connected';
  const disconnected = rule === 'USB_DEVICE_EVENT' && action === 'disconnected';
  const copiedTo = (['USB_FILE_COPIED', 'USB_SENSITIVE_FILE_COPIED'].includes(rule) || /^USB_POLICY_/.test(rule))
    && /copied_to_usb|file_copied_to_usb/.test(action);
  const readFrom = rule === 'USB_FILE_READ' || /read_from_usb|file_read_from_usb/.test(action);
  const policyViolation = /^USB_(?:POLICY_|WRITE_BLOCKED)/.test(rule) || Boolean(event.policyName || event.rawEvent?.policy_name);
  const enforced = event.blocked === true || enforcement === 'enforced' || event.actionTaken === 'Blocked';
  const malware = (Number(event.vtDetections || event.rawEvent?.virustotal?.malicious || 0) > 0)
    || /malicious|malware/.test(String(event.vtVerdict || event.malwareType || event.eventCategory || '').toLowerCase());
  return {
    rule, action, description, deviceType, connected, disconnected, copiedTo, readFrom,
    policyViolation, enforced, enforcementFailed: enforcement === 'failed' || event.actionTaken === 'Enforcement Failed',
    unauthorizedDevice: policyViolation && (
      ['allow_serials', 'block_serials', 'block_vendor', 'block_device_type'].includes(policyRuleType)
      || (!policyRuleType && !copiedTo && !readFrom && rule !== 'USB_WRITE_BLOCKED' && !/file|read-only/.test(description))
    ),
    deviceBlocked: enforced && (
      ['allow_serials', 'block_serials', 'block_vendor', 'block_device_type', 'read_only'].includes(policyRuleType)
      || (!policyRuleType && !copiedTo)
    ),
    sensitive: rule === 'USB_SENSITIVE_FILE_COPIED' || event.sensitivityType === 'sensitive',
    malware,
    hidThreat: rule === 'USB_HID_ANOMALY' || rule === 'USB_RUBBER_DUCKY_SUSPECTED',
    rubberDucky: rule === 'USB_RUBBER_DUCKY_SUSPECTED',
    driverLoaded: rule === 'USB_DRIVER_LOADED' || action === 'driver_loaded',
    writeBlocked: rule === 'USB_WRITE_BLOCKED' || (enforced && copiedTo),
    storageMounted: rule === 'USB_STORAGE_MOUNTED' || (connected && (Boolean(event.mountPath || event.rawEvent?.mount_path) || /storage|mass|disk|flash/.test(deviceType))),
    externalDisk: connected && /external|hdd|ssd|hard.?drive/.test(`${deviceType} ${description}`),
    mobile: connected && /mobile|phone|mtp|android|iphone/.test(`${deviceType} ${description}`),
    networkAdapter: connected && /network.?adapter|ethernet|rndis|wifi|wireless/.test(`${deviceType} ${description}`),
  };
}

function usbDeviceKey(event = {}) {
  return String(event.serialNumber || event.rawEvent?.serial_number
    || `${event.usbVendorId || event.rawEvent?.vid || ''}:${event.usbProductId || event.rawEvent?.product_id || ''}:${event.device || event.deviceName || event.rawEvent?.device_name || ''}`
  ).trim().toLowerCase();
}

function usbTimeline(events = [], buckets = 18, hours = 24) {
  const result = Array(buckets).fill(0);
  const now = Date.now();
  events.forEach(event => {
    const created = new Date(event.createdAt || event.timestamp || 0).getTime();
    const age = (now - created) / 3600000;
    if (!Number.isFinite(age) || age < 0 || age > hours) return;
    result[Math.min(buckets - 1, Math.max(0, buckets - 1 - Math.floor(age * buckets / hours)))] += 1;
  });
  return result;
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function UsbLogDetailModal({ log, onClose }) {
  const eventOs = String(log?.osType || log?.os || log?.raw?.osType || log?.raw?.os || '').toLowerCase();
  const forensicPlatform = eventOs.includes('win') ? 'windows' : eventOs.includes('mac') || eventOs.includes('darwin') ? 'macos' : 'linux';
  const defaultArtifact = forensicPlatform === 'windows' ? 'Windows.System.Pslist' : forensicPlatform === 'macos' ? 'MacOS.Sys.Pslist' : 'Linux.Sys.Pslist';
  const defaultArtifactTitle = forensicPlatform === 'windows' ? 'Windows Process Triage' : forensicPlatform === 'macos' ? 'macOS Process Triage' : 'Linux Process Triage';
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState('');
  const assignedAnalyst = log?.assignedTo?.name || log?.assignedTo?.email || 'Unassigned';
  const caseStatus = log?.status || 'open';
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState(defaultArtifact);
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState(defaultArtifactTitle);
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || log?.agentName || 'endpoint'} USB forensic hunt`);
  const [systemIdInput, setSystemIdInput] = useState(log?.systemId?._id || log?.systemId || '');
  const [clientIdInput] = useState(log?.velociraptorClientId || log?.systemId?.velociraptorClientId || log?.raw?.systemId?.velociraptorClientId || '');
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint' },
    { id: 'process', label: '⚙️ 4. Process & Commands' },
    { id: 'files', label: '📁 5. Files & Registry' },
    { id: 'network', label: '🌐 6. Network' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = forensicPlatform === 'windows' ? [
    {
      title: 'Windows Process Triage',
      desc: 'Windows process list, parent relationships, users, and execution context.',
      artifact: 'Windows.System.Pslist',
    },
    {
      title: 'Windows Network Connections',
      desc: 'Active connections, listeners, ports, and owning processes.',
      artifact: 'Windows.Network.Netstat',
    },
    {
      title: 'Windows Event Log Hunt',
      desc: 'Acquire relevant Windows event logs for endpoint investigation.',
      artifact: 'Windows.EventLogs.Evtx',
    },
    {
      title: 'Windows Persistence',
      desc: 'Inspect services and common service-based persistence evidence.',
      artifact: 'Windows.System.Services',
    },
    {
      title: 'Windows File Finder',
      desc: 'Find suspicious scripts, binaries, and recently modified artifacts.',
      artifact: 'Windows.Search.FileFinder',
    },
    {
      title: 'YARA File Sweep',
      desc: 'Run an approved YARA file sweep without acquiring a memory dump.',
      artifact: 'Generic.Detection.Yara.Glob',
    },
  ] : forensicPlatform === 'macos' ? [
    {
      title: 'macOS Process Triage',
      desc: 'macOS process list, parent relationships, users, and command context.',
      artifact: 'MacOS.Sys.Pslist',
    },
    {
      title: 'macOS Network Connections',
      desc: 'Active connections, listeners, ports, and owning processes.',
      artifact: 'MacOS.Network.Netstat',
    },
    {
      title: 'macOS Persistence',
      desc: 'Inspect supported macOS autorun and persistence metadata.',
      artifact: 'MacOS.Detection.Autoruns',
    },
    {
      title: 'macOS File Finder',
      desc: 'Find suspicious scripts, binaries, and modified artifacts.',
      artifact: 'MacOS.Search.FileFinder',
    },
    {
      title: 'macOS Quarantine Events',
      desc: 'Review supported quarantine and download provenance events.',
      artifact: 'MacOS.System.QuarantineEvents',
    },
    {
      title: 'YARA File Sweep',
      desc: 'Run an approved YARA file sweep without acquiring a memory dump.',
      artifact: 'MacOS.Detection.Yara.Glob',
    },
  ] : [
    {
      title: 'Linux Process Triage',
      desc: 'Linux process list, parent process clues, users, and command context.',
      artifact: 'Linux.Sys.Pslist',
    },
    {
      title: 'Linux Network Connections',
      desc: 'Active connections, listeners, ports, and remote endpoints.',
      artifact: 'Linux.Network.Netstat',
    },
    {
      title: 'Cron Persistence',
      desc: 'Cron jobs and scheduled persistence across users and system paths.',
      artifact: 'Linux.Sys.Crontab',
    },
    {
      title: 'Linux Log Hunt',
      desc: 'Auth, syslog, service logs, sudo, SSH, and execution indicators.',
      artifact: 'Linux.Sys.LogHunter',
    },
    {
      title: 'Linux File Finder',
      desc: 'Find suspicious scripts, binaries, temp files, and modified artifacts.',
      artifact: 'Linux.Search.FileFinder',
    },
    {
      title: 'YARA File Sweep',
      desc: 'Run IOC/YARA-style sweep across Linux file paths.',
      artifact: 'Generic.Detection.Yara.Glob',
    },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = async () => {
    const targetSystemId = systemIdInput || log.raw?.systemId?._id || log.raw?.systemId;
    if (!targetSystemId) {
      setHuntSuccessMsg('Hunt not sent: this event has no tenant-scoped endpoint ID.');
      return;
    }
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    try {
      const response = await api.post('/forensics/hunts', {
        name: huntNameInput.trim() || selectedArtifactTitle,
        artifacts: [selectedArtifact],
        systemId: targetSystemId,
      });
      setHuntSuccessMsg(`Real forensic hunt queued: ${response.data?.hunt?._id || 'request accepted'}`);
    } catch (error) {
      setHuntSuccessMsg(error.response?.data?.message || 'Unable to launch the forensic hunt.');
    } finally {
      setLaunchingHunt(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!log._id || !analystNotes.trim()) return;
    try {
      await api.post(`/alerts/${log._id}/notes`, { text: analystNotes.trim() });
      setAnalystNotes('');
      setNotesSaved(true);
      setTimeout(() => setNotesSaved(false), 2000);
    } catch (error) {
      setHuntSuccessMsg(error.response?.data?.message || 'Case note could not be saved.');
    }
  };

  const handleDownload = (format) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(log, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `usb_event_${log._id || 'event'}_${log.serialNumber || 'device'}.${format.toLowerCase()}`);
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
                  Forensic Investigation Panel — {log.deviceName || log.device || 'USB Device Event'}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Case ID: {log.caseId || log.incidentId || 'Not assigned'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{log.hostname || log.agentName || 'Not reported'}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'Not reported'}</strong> | Event Time: <strong style={{ color: MON.text }}>{log.timestamp || log.createdAt || 'Not reported'}</strong>
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
                ['Incident Summary', log.action || log.description || 'USB telemetry event', MON.cyan],
                ['Risk Score', `${log.riskScore ?? 0}/100`, log.riskScore > 75 ? MON.red : MON.orange],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', log.hostname || log.agentName || 'Not reported', MON.blue],
                ['User Context', log.username || 'Not reported', MON.cyan],
                ['Detection Source', log.detectionEngine || log.source || log.telemetryProvider || 'Not reported', MON.purple],
                ['Detection Time', log.timestamp || log.createdAt || 'Not reported', MON.text],
              ].map(([lbl, val, col]) => (
                <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                  <div style={{ fontSize: 14, fontWeight: 800, color: col, marginTop: 6, wordBreak: 'break-word' }}>{val}</div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Multi-Category Forensic Event Chronology</div>
              {[
                { type: log.eventType || log.ruleId || 'USB Event', time: log.timestamp || log.createdAt ? new Date(log.timestamp || log.createdAt).toLocaleTimeString() : 'Not reported', title: log.ruleId || 'USB telemetry', desc: log.description || 'No event description was reported by the endpoint.', col: sevColor },
              ].map((ev, i) => (
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
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Endpoint & USB Hardware Profile</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Device Name', log.deviceName || log.device || 'Not reported'],
                  ['Vendor ID (VID)', log.usbVendorId || log.vid || 'Not reported'],
                  ['Product ID (PID)', log.usbProductId || log.productId || 'Not reported'],
                  ['Serial Number', log.serialNumber || 'Not reported'],
                  ['USB Device Type', log.deviceType || 'Not reported'],
                  ['Mount Path', log.mountPath || 'Not reported'],
                  ['System Hostname', log.hostname || log.agentName || 'Not reported'],
                  ['Operating System', log.osType || log.os || 'Not reported'],
                  ['Logged-in User', log.username || 'Not reported'],
                  ['Agent ID', log.agentId || 'Not reported'],
                  ['Policy', log.policyName || 'Not reported'],
                  ['USB Driver Loaded', log.usbDriver || 'Not reported'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4 }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Activity, Command Line & Script Execution</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Process Tree (Parent ➔ Child):</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {log.parentProcessName || 'Parent not reported'} (PPID {log.parentPid ?? '—'}) ➔ <strong>{log.processName || 'Process not reported'} (PID {log.pid ?? '—'})</strong>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line History:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.processCmdline || log.commandLine || 'Command line not reported or redacted by the endpoint.'}
                </pre>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>PowerShell Script Block Logging (Event ID 4104):</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.powershellCommand || log.rawEvent?.script_content || 'No PowerShell script-block telemetry is attached to this event.'}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 5: FILES & REGISTRY */}
          {activeTab === 'files' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📁 File Transfer & Registry Persistence Artifacts</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Modified Registry Keys & Persistence:</div>
                <div style={{ fontFamily: 'monospace', fontSize: 11, color: log.registryKey ? MON.cyan : MON.muted }}>
                  {log.registryKey || 'No registry artifact was reported with this USB event.'}
                </div>
              </div>

              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead>
                  <tr style={{ background: MON.card2, color: MON.muted, textAlign: 'left' }}>
                    <th style={{ padding: 8 }}>File Name</th>
                    <th style={{ padding: 8 }}>Source Path</th>
                    <th style={{ padding: 8 }}>Destination Path</th>
                    <th style={{ padding: 8 }}>Size</th>
                    <th style={{ padding: 8 }}>Tag</th>
                  </tr>
                </thead>
                <tbody>
                  {(log.fileName || log.filePath || log.sourcePath) ? [[
                    log.fileName || String(log.filePath || log.sourcePath).split(/[\\/]/).pop(),
                    log.sourcePath || 'Not reported', log.mountPath || log.destinationPath || 'Not reported',
                    log.fileSize != null ? `${log.fileSize} bytes` : 'Not reported', log.sensitivityType || 'standard',
                  ]].map((r, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 8, color: MON.cyan, fontWeight: 700 }}>{r[0]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[1]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[2]}</td>
                      <td style={{ padding: 8 }}>{r[3]}</td>
                      <td style={{ padding: 8 }}><span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 6px', borderRadius: 4, fontWeight: 800 }}>{r[4]}</span></td>
                    </tr>
                  )) : <tr><td colSpan={5} style={{ padding: 18, textAlign: 'center', color: MON.muted }}>No file activity was attached to this event.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 6: NETWORK */}
          {activeTab === 'network' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                ['Destination IP', log.destip || log.destinationIp || 'Not reported'],
                ['Source IP', log.srcip || log.sourceIp || 'Not reported'],
                ['Country / ASN', [log.destCountry, log.destAsn].filter(Boolean).join(' / ') || 'Not reported'],
                ['Protocol / Port', [log.protocol, log.destPort || log.port].filter(Boolean).join(' / ') || 'Not reported'],
                ['DNS Lookup', log.domain || 'Not reported'],
                ['Transferred Bytes', log.bytesTransferred ?? 'Not reported'],
              ].map(([k, v]) => (
                <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                  <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4 }}>{v}</div>
                </div>
              ))}
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🎯 Indicators of Compromise & MITRE ATT&CK Matrix</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {(log.mitreId || log.mitreTechnique) ? [[log.mitreId || log.mitreTechnique, log.technique || 'Mapped technique', log.description || 'No mapping explanation reported.']].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                )) : <div style={{ color: MON.muted, fontSize: 11 }}>No MITRE ATT&CK mapping was reported for this event.</div>}
              </div>
            </div>
          )}

          {/* TAB 8: FORENSIC HUNT (EXACT VELOCIRAPTOR INTERFACE) */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              {/* Header Title */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span>⚡</span> Forensic Hunt
                </h3>
                <span style={{ fontSize: 11, color: MON.muted, background: MON.card2, border: `1px solid ${MON.border}`, padding: '4px 10px', borderRadius: 6 }}>
                  Velociraptor Artifact Dispatcher Engine
                </span>
              </div>

              {/* Artifact Selector Grid Cards */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {forensicHuntCards.map((card) => {
                  const isSelected = selectedArtifact === card.artifact;
                  return (
                    <div
                      key={card.artifact}
                      onClick={() => handleSelectArtifactCard(card)}
                      style={{
                        background: isSelected ? 'rgba(56, 189, 248, 0.08)' : MON.card,
                        border: isSelected ? `2px solid ${MON.blue}` : `1px solid ${MON.border}`,
                        borderRadius: 8,
                        padding: 16,
                        cursor: 'pointer',
                        transition: 'all 0.15s ease',
                      }}
                    >
                      <div style={{ fontSize: 14, fontWeight: 800, color: isSelected ? MON.blue : '#f8fafc' }}>
                        {card.title}
                      </div>
                      <div style={{ fontSize: 12, color: MON.muted, marginTop: 6, lineHeight: 1.4 }}>
                        {card.desc}
                      </div>
                      <div style={{ fontFamily: 'monospace', fontSize: 11, color: isSelected ? MON.cyan : MON.blue, marginTop: 10 }}>
                        {card.artifact}
                      </div>
                    </div>
                  );
                })}
              </div>

              {/* Inputs Form Row 1 */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 8 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Hunt Name</div>
                  <input
                    type="text"
                    value={huntNameInput}
                    onChange={(e) => setHuntNameInput(e.target.value)}
                    style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'sans-serif' }}
                  />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Artifact Name</div>
                  <input
                    type="text"
                    readOnly
                    value={selectedArtifact}
                    style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace', fontWeight: 700 }}
                  />
                </div>
              </div>

              {/* Inputs Form Row 2 */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>System ID / Velociraptor ID</div>
                  <input
                    type="text"
                    value={systemIdInput}
                    onChange={(e) => setSystemIdInput(e.target.value)}
                    style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }}
                  />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Velociraptor Client ID</div>
                  <input
                    type="text"
                    readOnly
                    value={clientIdInput}
                    placeholder="Resolved securely by the backend"
                    style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }}
                  />
                </div>
              </div>

              {/* Target Banner */}
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: MON.muted }}>
                <span>Target:</span>
                <strong style={{ color: '#fff' }}>{log.hostname || log.agentName || 'Not reported'}</strong>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>OS: <strong style={{ color: '#fff' }}>{log.osType || log.os || 'Not reported'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>User: <strong style={{ color: '#fff' }}>{log.username || 'Not reported'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>PID: <strong style={{ color: '#fff' }}>{log.pid ?? 'Not reported'}</strong></span>
              </div>

              {/* Launch Action Button */}
              <button
                type="button"
                onClick={handleLaunchHunt}
                disabled={launchingHunt}
                style={{
                  width: '100%',
                  background: MON.accent,
                  color: '#ffffff',
                  border: 'none',
                  borderRadius: 8,
                  padding: '14px 20px',
                  fontSize: 14,
                  fontWeight: 800,
                  cursor: launchingHunt ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 14px rgba(99, 102, 241, 0.4)',
                  transition: 'all 0.15s ease',
                  marginTop: 4,
                }}
              >
                {launchingHunt ? '⚡ Dispatching Hunt Artifacts to Velociraptor Server...' : 'Launch Forensic Hunt'}
              </button>

              {/* Success Notification */}
              {huntSuccessMsg && (
                <div style={{ background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, padding: 12, borderRadius: 8, fontSize: 12, fontWeight: 700, textAlign: 'center' }}>
                  {huntSuccessMsg}
                </div>
              )}
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
              {['Forensic JSON Export'].map((name) => (
                <div key={name} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📦 {name}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Normalized event and redacted raw telemetry received by the SOC.</div>
                  </div>
                  <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 12px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    Download Evidence
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Assign Analyst</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>{assignedAnalyst}</div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Case Status</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4, textTransform: 'capitalize' }}>{caseStatus.replace(/_/g, ' ')}</div>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Detection Rule</div>
                  <div style={{ width: '100%', boxSizing: 'border-box', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>{log.ruleId || 'Not reported'}</div>
                </div>
              </div>

              <div style={{ fontSize: 12, color: MON.muted, fontWeight: 700 }}>Investigation Notes:</div>
              <textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} rows={6} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, color: MON.text, padding: 14, fontSize: 12, fontFamily: 'inherit' }} />
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="button" disabled={!analystNotes.trim()} onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                  Save Case Notes & Escalation
                </button>
                {notesSaved && <span style={{ color: MON.green, fontSize: 12, fontWeight: 700 }}>✓ Notes saved to investigation case</span>}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. LOG MONITOR TABLE COMPONENT (REAL-TIME BACKEND LINKED)
// ═════════════════════════════════════════════════════════════════════════════
export function UsbLogMonitor({ alerts = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const eventRows = useMemo(() => {
      return alerts.map(a => ({
        ...a,
        _id: a._id || a.id,
        timestamp: a.createdAt || a.timestamp || new Date().toISOString(),
        severity: (a.severity || 'medium').toLowerCase(),
        status: a.status || (a.blocked ? 'Blocked' : 'Observed'),
        hostname: a.hostname || a.agentName || a.systemId?.name || '—',
        username: a.username || a.user || '—',
        deviceName: a.deviceName || a.device || a.rawEvent?.device_name || '—',
        vendor: a.deviceVendor || a.vendor || a.rawEvent?.vendor || '—',
        serialNumber: a.serialNumber || a.rawEvent?.serial_number || '—',
        vid: a.usbVendorId || a.vid || a.rawEvent?.vid || '—',
        pid: a.usbProductId || a.rawEvent?.product_id || '—',
        deviceType: a.deviceType || a.rawEvent?.device_type || '—',
        os: a.os || a.osType || '—',
        action: a.action || a.actionTaken || a.description || '—',
        fileName: a.fileName || a.filePath || a.rawEvent?.file_name || '—',
        policyName: a.policyName || a.rawEvent?.policy_name || '—',
        mitreAttack: a.mitreAttack || a.mitreId || '—',
        riskScore: a.riskScore ?? a.threatScore ?? '—',
        caseId: a.caseId || a.incidentId || '—',
        raw: a,
      }));
  }, [alerts]);

  const filtered = useMemo(() => {
    return eventRows.filter(r => {
      if (sevFilter !== 'ALL' && (r.severity || '').toLowerCase() !== sevFilter.toLowerCase()) return false;
      if (!searchTerm) return true;
      const t = searchTerm.toLowerCase();
      return (r.hostname || '').toLowerCase().includes(t) || (r.username || '').toLowerCase().includes(t) || (r.deviceName || '').toLowerCase().includes(t);
    });
  }, [eventRows, searchTerm, sevFilter]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}` }}>
        <input type="text" placeholder="🔍 Search USB logs (Hostname, User, Device, Serial)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          <option value="ALL">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
        </select>
      </div>

      <div style={{ overflowX: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Timestamp', 'Severity', 'Status', 'Hostname', 'Username', 'Device Name', 'Vendor', 'Action', 'File Name', 'Policy Name', 'MITRE ATT&CK', 'Risk Score', 'Case ID'].map(h => <th key={h} style={{ padding: 10 }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.muted }}>{row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '—'}</td>
                <td style={{ padding: 10 }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                <td style={{ padding: 10, color: row.status === 'Blocked' ? MON.red : MON.green, fontWeight: 700 }}>{row.status}</td>
                <td style={{ padding: 10, color: MON.blue, fontWeight: 700 }}>{row.hostname}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, color: MON.cyan, fontWeight: 700 }}>{row.deviceName}</td>
                <td style={{ padding: 10 }}>{row.vendor}</td>
                <td style={{ padding: 10, color: MON.orange, fontWeight: 700 }}>{row.action}</td>
                <td style={{ padding: 10, color: MON.text }}>{row.fileName}</td>
                <td style={{ padding: 10, color: MON.purple }}>{row.policyName}</td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 800 }}>{row.mitreAttack}</td>
                <td style={{ padding: 10, color: row.riskScore > 70 ? MON.red : MON.green, fontWeight: 800 }}>{row.riskScore}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{row.caseId}</td>
              </tr>
            )) : <tr><td colSpan={13} style={{padding:40,textAlign:'center',color:MON.muted}}>No live USB SIEM logs found</td></tr>}
          </tbody>
        </table>
      </div>

      {selectedLog && <UsbLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3.5 EXECUTIVE SOC REPORT GENERATOR COMPONENT FOR USB DEVICE CONTROL
// ═════════════════════════════════════════════════════════════════════════════
export function UsbReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [reportGenerated, setReportGenerated] = useState(false);
  const reportMetrics = useMemo(() => {
    const text = a => `${a.type || ''} ${a.eventType || ''} ${a.category || ''} ${a.description || ''} ${a.actionTaken || ''} ${a.deviceName || ''}`;
    return {
      connections: alerts.length,
      unauthorized: alerts.filter(a => a.blocked === true || /block|denied|unauthor/i.test(text(a))).length,
      fileCopies: alerts.filter(a => /file.?cop|transfer|write|upload|download/i.test(text(a))).length,
      hidAttacks: alerts.filter(a => /hid|rubber.?ducky|keystrok/i.test(text(a))).length,
    };
  }, [alerts]);
  const reportRowsHtml = alerts.slice(0, 25).map(a => `<tr><td>${a.deviceName || a.device || '—'}</td><td>${a.hostname || a.agentName || '—'}</td><td>${a.username || a.user || '—'}</td><td class="${/critical/i.test(a.severity || '') ? 'sev-critical' : 'sev-high'}">${(a.severity || 'unknown').toUpperCase()}</td><td>${a.actionTaken || a.action || a.description || '—'}</td></tr>`).join('');

  const handleGenerate = () => {
    setGenerating(true);
    setTimeout(() => {
      setGenerating(false);
      setReportGenerated(true);
    }, 1000);
  };

  const handleDownloadReport = (format) => {
    if (format === 'PDF') {
      const printWindow = window.open('', '_blank');
      if (!printWindow) {
        alert('Please allow popups to generate PDF reports.');
        return;
      }
      const htmlContent = `
        <!DOCTYPE html>
        <html>
        <head>
          <title>Device Control (USB) & Peripheral Security Executive SOC Report (${reportType.toUpperCase()})</title>
          <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 30px; background: #fff; color: #1e293b; line-height: 1.5; }
            .header { border-bottom: 3px solid #0284c7; padding-bottom: 12px; margin-bottom: 24px; display: flex; justify-space-between: space-between; align-items: center; }
            h1 { margin: 0; color: #0f172a; font-size: 24px; }
            .meta { color: #64748b; font-size: 12px; margin-top: 6px; }
            .badge { background: #e0f2fe; color: #0369a1; padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; }
            .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 24px 0; }
            .metric-card { background: #f8fafc; border: 1px solid #cbd5e1; padding: 14px; border-radius: 8px; }
            .metric-title { font-size: 11px; text-transform: uppercase; color: #64748b; font-weight: bold; }
            .metric-val { font-size: 22px; font-weight: 800; color: #0284c7; margin-top: 6px; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; font-size: 12px; }
            th, td { border: 1px solid #cbd5e1; padding: 10px; text-align: left; }
            th { background: #f1f5f9; color: #334155; font-weight: bold; }
            .sev-critical { color: #dc2626; font-weight: bold; }
            .sev-high { color: #ea580c; font-weight: bold; }
            .footer { margin-top: 40px; padding-top: 12px; border-top: 1px solid #e2e8f0; font-size: 11px; color: #94a3b8; text-align: center; }
          </style>
        </head>
        <body>
          <div class="header">
            <div>
              <h1>🛡️ Device Control (USB) & Peripheral Security Executive SOC Report</h1>
              <div class="meta">Generated: ${new Date().toLocaleString()} | Scope: ${reportType.toUpperCase()} | Classification: CONFIDENTIAL</div>
            </div>
            <span class="badge">SECURITY VERIFIED</span>
          </div>

          <div class="metrics-grid">
            <div class="metric-card"><div class="metric-title">USB Connections Monitored</div><div class="metric-val">${reportMetrics.connections}</div></div>
            <div class="metric-card"><div class="metric-title">Unauthorized USB Devices</div><div class="metric-val">${reportMetrics.unauthorized}</div></div>
            <div class="metric-card"><div class="metric-title">File Copies</div><div class="metric-val">${reportMetrics.fileCopies}</div></div>
            <div class="metric-card"><div class="metric-title">HID / Rubber Ducky Attacks</div><div class="metric-val">${reportMetrics.hidAttacks}</div></div>
          </div>

          <h2>Summary of Prevented Peripheral & USB Incidents</h2>
          <table>
            <thead>
              <tr>
                <th>Device Name</th>
                <th>Host Machine</th>
                <th>User Account</th>
                <th>Severity</th>
                <th>Mitigation Applied</th>
              </tr>
            </thead>
            <tbody>
              ${reportRowsHtml || '<tr><td colspan="5">No live USB events available for this report window.</td></tr>'}
            </tbody>
          </table>

          <div class="footer">
            Confidential — Generated by Enterprise SOC Platform | Device Control (USB) Module
          </div>

          <script>
            window.onload = function() { window.print(); }
          </script>
        </body>
        </html>
      `;
      printWindow.document.write(htmlContent);
      printWindow.document.close();
      return;
    }

    if (format === 'CSV') {
      const headers = ["Timestamp", "Hostname", "Username", "Device Name", "VID/PID", "Vendor", "Action Taken", "Severity", "Risk Score"];
      const rows = alerts.length > 0 ? alerts.map(a => [
        `"${a.createdAt || a.timestamp || new Date().toISOString()}"`,
        `"${a.hostname || a.agentName || '—'}"`,
        `"${a.username || a.user || '—'}"`,
        `"${a.deviceName || a.device || '—'}"`,
        `"${a.vidPid || `${a.vid || '—'}:${a.pid || '—'}`}"`,
        `"${a.vendor || '—'}"`,
        `"${a.actionTaken || a.action || '—'}"`,
        `"${a.severity || 'unknown'}"`,
        `"${a.riskScore ?? a.threatScore ?? '—'}"`
      ]) : [];

      const csvData = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
      const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", `usb_device_control_report_${reportType}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      return;
    }

    // JSON Export
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify({ title: "Device Control (USB) Executive SOC Report", reportType, generatedAt: new Date().toISOString(), metrics: reportMetrics, alerts }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `usb_device_control_report_${reportType}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Device Control & Peripheral Security Executive Report Generator</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate Executive Summary, USB File Copy Analytics, HID Threat Reports & Policy Audit Summary</div>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 14px', borderRadius: 6, fontSize: 12 }}>
            <option value="daily">Daily Report (24 Hours)</option>
            <option value="weekly">Weekly Executive Summary</option>
            <option value="monthly">Monthly Peripheral Threat Report</option>
            <option value="custom">Custom Scope</option>
          </select>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
            {generating ? 'Generating...' : '⚡ Generate Report'}
          </button>
        </div>
      </div>

      {reportGenerated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>Device Control Executive Summary Preview ({reportType.toUpperCase()})</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={() => handleDownloadReport('PDF')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export PDF</button>
              <button type="button" onClick={() => handleDownloadReport('CSV')} style={{ background: MON.green, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
              <button type="button" onClick={() => handleDownloadReport('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>USB Connections</div><div style={{ fontSize: 18, color: MON.cyan, fontWeight: 900 }}>{reportMetrics.connections.toLocaleString()} Connections</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>Unauthorized Devices</div><div style={{ fontSize: 18, color: MON.red, fontWeight: 900 }}>{reportMetrics.unauthorized.toLocaleString()} Devices</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>File Copies</div><div style={{ fontSize: 18, color: MON.orange, fontWeight: 900 }}>{reportMetrics.fileCopies.toLocaleString()} Files</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>HID Attack Attempts</div><div style={{ fontSize: 18, color: MON.red, fontWeight: 900 }}>{reportMetrics.hidAttacks.toLocaleString()} Attacks</div></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. MAIN DASHBOARD PANEL COMPONENT
// ═════════════════════════════════════════════════════════════════════════════
// ── Visual Helper Components for Device Control (USB) Dashboard ─────────────
function UsbActivityTimelineChart({ alerts = [] }) {
  const times = ['00:00', '03:00', '06:00', '09:00', '12:00', '15:00', '18:00', '21:00', '24:00'];
  const yLabels = ['50', '40', '30', '20', '10', '0'];

  const bucketCount = 13;
  const connData = Array(bucketCount).fill(0);
  const discData = Array(bucketCount).fill(0);
  const violData = Array(bucketCount).fill(0);
  const now = Date.now();
  alerts.forEach(alert => {
    const created = new Date(alert.createdAt || alert.timestamp || 0).getTime();
    const ageHours = (now - created) / 3600000;
    if (!Number.isFinite(ageHours) || ageHours < 0 || ageHours > 24) return;
    const index = Math.min(bucketCount - 1, Math.max(0, bucketCount - 1 - Math.floor(ageHours / 2)));
    const value = `${alert.ruleId || ''} ${alert.eventType || ''} ${alert.userAction || ''} ${alert.description || ''}`;
    if (/disconnect|remove|unmount/i.test(value)) discData[index] += 1;
    else if (/connect|insert|mount|device.?add/i.test(value)) connData[index] += 1;
    if (alert.policyName || alert.blocked || /policy|violation|block|denied|unauthor/i.test(value)) violData[index] += 1;
  });

  const chartW = 420;
  const chartH = 150;
  const padLeft = 28;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const makePath = (data) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / (data.length - 1)) * innerW,
      y: padTop + innerH - (v / Math.max(1, ...connData, ...discData, ...violData)) * innerH,
    }));
    let d = `M ${pts[0].x},${pts[0].y}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p1 = pts[i];
      const p2 = pts[i + 1];
      const cx1 = p1.x + (p2.x - p1.x) / 2;
      const cy1 = p1.y;
      const cx2 = p1.x + (p2.x - p1.x) / 2;
      const cy2 = p2.y;
      d += ` C ${cx1},${cy1} ${cx2},${cy2} ${p2.x},${p2.y}`;
    }
    return { d, pts };
  };

  const connRes = makePath(connData);
  const discRes = makePath(discData);
  const violRes = makePath(violData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>USB Activity Timeline</span>
        <div style={{ display: 'flex', gap: 12, fontSize: 9 }}>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#38bdf8' }} /> Connections</span>
          <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#34d399' }} /> Disconnections</span>
          <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 4 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: '#f87171' }} /> Policy Violations</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={lbl}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="8" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / (times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{t}</text>;
          })}
          <path d={connRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          <path d={discRes.d} fill="none" stroke="#34d399" strokeWidth="2" />
          <path d={violRes.d} fill="none" stroke="#f87171" strokeWidth="2" />
          {connRes.pts.map((p, i) => <circle key={`c-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#38bdf8" />)}
          {discRes.pts.map((p, i) => <circle key={`d-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#34d399" />)}
          {violRes.pts.map((p, i) => <circle key={`v-${i}`} cx={p.x} cy={p.y} r="2.5" fill="#f87171" />)}
        </svg>
      </div>
    </div>
  );
}

function DeviceConnectionStatusDonut({ alerts = [] }) {
  const connected = alerts.filter(alert => /connect|insert|mount|device.?add/i.test(`${alert.eventType || ''} ${alert.userAction || ''} ${alert.description || ''}`));
  const blockedCount = connected.filter(alert => alert.blocked || /block|denied/i.test(`${alert.actionTaken || ''} ${alert.description || ''}`)).length;
  const unauthorizedCount = connected.filter(alert => !alert.blocked && /unauthor|policy.?violation/i.test(`${alert.ruleId || ''} ${alert.description || ''}`)).length;
  const authorizedCount = Math.max(0, connected.length - blockedCount - unauthorizedCount);
  const otherCount = alerts.filter(alert => !connected.includes(alert)).length;
  const totalCount = authorizedCount + unauthorizedCount + blockedCount + otherCount;
  const statuses = [
    { label: 'Authorized', count: authorizedCount, color: '#34d399' },
    { label: 'Unauthorized', count: unauthorizedCount, color: '#fb923c' },
    { label: 'Blocked', count: blockedCount, color: '#f87171' },
    { label: 'Others', count: otherCount, color: '#38bdf8' },
  ].map(status => ({ ...status, pct: totalCount ? (status.count / totalCount) * 100 : 0 }));

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = statuses.map((s) => {
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
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Device Connection Status</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{totalCount}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 9 }}>
          {statuses.map(s => (
            <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: s.color }} /> {s.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{s.count} ({s.pct.toFixed(1)}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function UsbHeatmapMatrix({ alerts = [] }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00', '24:00'];

  const heatmap = Array.from({ length: 7 }, () => Array(24).fill(0));
  alerts.forEach(alert => {
    const date = new Date(alert.createdAt || alert.timestamp || 0);
    if (Number.isNaN(date.getTime())) return;
    heatmap[(date.getDay() + 6) % 7][date.getHours()] += 1;
  });
  const maxCell = Math.max(1, ...heatmap.flat());
  const getCellColor = (dayIdx, hour) => {
    const count = heatmap[dayIdx][hour];
    if (!count) return 'rgba(52, 211, 153, 0.12)';
    const ratio = count / maxCell;
    return ratio > 0.7 ? '#ef4444' : ratio > 0.35 ? '#f97316' : '#34d399';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>USB Activity Heatmap</span>
      <div style={{ display: 'flex', gap: 6, flex: 1 }}>
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'space-around', fontSize: 8, color: '#64748b', fontWeight: 700, width: 22 }}>
          {days.map(d => <span key={d}>{d}</span>)}
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 2 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: '#64748b', marginBottom: 2 }}>
            {times.map(t => <span key={t}>{t}</span>)}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, flex: 1 }}>
            {days.map((d, dIdx) => (
              <div key={d} style={{ display: 'grid', gridTemplateColumns: 'repeat(24, 1fr)', gap: 2, flex: 1 }}>
                {Array.from({ length: 24 }).map((_, hIdx) => (
                  <div key={hIdx} title={`${heatmap[dIdx][hIdx]} event(s)`} style={{ background: getCellColor(dIdx, hIdx), borderRadius: 1 }} />
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 4, fontSize: 8, color: '#64748b' }}>
        <span>Low Activity</span>
        <div style={{ height: 4, width: 80, background: 'linear-gradient(90deg, rgba(52,211,153,0.3), #34d399, #f97316, #ef4444)', borderRadius: 2 }} />
        <span>High Activity</span>
      </div>
    </div>
  );
}

function UsbOverviewDashboard({ alerts = [], total = 0 }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const overview = useMemo(() => {
    const text = alert => `${alert.ruleId || ''} ${alert.eventType || ''} ${alert.userAction || ''} ${alert.description || ''} ${alert.actionTaken || ''}`;
    const bytes = value => Number(value || 0);
    const formatBytes = value => value >= 1073741824 ? `${(value / 1073741824).toFixed(1)} GB` : value >= 1048576 ? `${(value / 1048576).toFixed(1)} MB` : value >= 1024 ? `${(value / 1024).toFixed(1)} KB` : `${value} B`;
    const facts = alert => usbEventFacts(alert);
    const connections = alerts.filter(alert => facts(alert).connected);
    const blocked = alerts.filter(alert => facts(alert).deviceBlocked);
    const unauthorized = alerts.filter(alert => facts(alert).unauthorizedDevice);
    const policyRows = alerts.filter(alert => facts(alert).policyViolation);
    const connectedKeys = new Set(connections.map(usbDeviceKey).filter(Boolean));
    const unauthorizedKeys = new Set(unauthorized.map(usbDeviceKey).filter(Boolean));
    const authorizedDeviceCount = [...connectedKeys].filter(key => !unauthorizedKeys.has(key)).length;
    const copiedBytes = alerts.reduce((sum, alert) => sum + (facts(alert).copiedTo ? bytes(alert.bytesTransferred || alert.fileSize || alert.rawEvent?.bytes_transferred) : 0), 0);
    const deviceMap = new Map();
    const userMap = new Map();
    const fileMap = new Map();
    const policyMap = new Map();
    alerts.forEach(alert => {
      const device = alert.device || alert.deviceName || alert.rawEvent?.device_name || 'Unknown device';
      const current = deviceMap.get(device) || { name: device, type: alert.deviceType || alert.rawEvent?.device_type || 'USB Device', conn: 0, bytes: 0 };
      if (facts(alert).connected) current.conn += 1;
      if (facts(alert).copiedTo || facts(alert).readFrom) current.bytes += bytes(alert.bytesTransferred || alert.fileSize || alert.rawEvent?.bytes_transferred);
      deviceMap.set(device, current);
      const user = alert.username || 'Not reported';
      userMap.set(user, (userMap.get(user) || 0) + 1);
      if (alert.fileName || alert.filePath || alert.fileAction) {
        const extension = String(alert.fileName || alert.filePath || '').split('.').pop().toLowerCase();
        const group = ['doc', 'docx', 'pdf', 'txt'].includes(extension) ? 'Documents' : ['xls', 'xlsx', 'csv'].includes(extension) ? 'Spreadsheets' : ['ppt', 'pptx'].includes(extension) ? 'Presentations' : ['zip', 'rar', '7z', 'tar', 'gz'].includes(extension) ? 'Archives' : 'Others';
        const file = fileMap.get(group) || { count: 0, bytes: 0 };
        file.count += 1; file.bytes += bytes(alert.bytesTransferred || alert.fileSize); fileMap.set(group, file);
      }
      if (facts(alert).policyViolation) {
        const policy = alert.policyName || alert.ruleId || 'USB policy';
        policyMap.set(policy, (policyMap.get(policy) || 0) + 1);
      }
    });
    const maxDevice = Math.max(1, ...[...deviceMap.values()].map(item => item.conn));
    const topDevices = [...deviceMap.values()].sort((a, b) => b.conn - a.conn || b.bytes - a.bytes).slice(0, 5).map(item => ({ ...item, data: formatBytes(item.bytes), pct: (item.conn / maxDevice) * 100 }));
    const maxUser = Math.max(1, ...userMap.values());
    const userActivity = [...userMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, conn]) => ({ name, conn, pct: (conn / maxUser) * 100 }));
    const icons = { Documents: '📄', Spreadsheets: '📊', Presentations: '🎨', Archives: '📦', Others: '📁' };
    const colors = { Documents: '#38bdf8', Spreadsheets: '#34d399', Presentations: '#fb923c', Archives: '#a78bfa', Others: '#64748b' };
    const maxFiles = Math.max(1, ...[...fileMap.values()].map(item => item.count));
    const topFileActivities = [...fileMap.entries()].map(([type, item]) => ({ type, icon: icons[type], count: item.count, size: formatBytes(item.bytes), pct: (item.count / maxFiles) * 100, col: colors[type] }));
    const recentEvents = alerts.slice(0, 5).map(alert => {
      const isBlocked = alert.blocked || /block|denied/i.test(text(alert));
      const isWarning = !isBlocked && /policy|sensitive|malware/i.test(text(alert));
      return { time: new Date(alert.createdAt || alert.timestamp).toLocaleTimeString(), user: alert.username || 'Not reported', device: alert.device || alert.deviceName || 'Unknown device', event: alert.eventType || alert.userAction || alert.ruleId, status: isBlocked ? 'Blocked' : isWarning ? 'Warning' : 'Authorized', statusBg: isBlocked ? 'rgba(248,113,113,.15)' : isWarning ? 'rgba(251,191,36,.15)' : 'rgba(52,211,153,.15)', statusCol: isBlocked ? '#f87171' : isWarning ? '#fbbf24' : '#34d399', details: alert.description || `VID: ${alert.usbVendorId || '—'} PID: ${alert.usbProductId || '—'}` };
    });
    const sevColors = { critical: '#f87171', high: '#f87171', medium: '#fbbf24', low: '#38bdf8' };
    const alertsStream = alerts.filter(alert => ['critical', 'high', 'medium'].includes(String(alert.severity).toLowerCase())).slice(0, 5).map(alert => ({ time: new Date(alert.createdAt || alert.timestamp).toLocaleTimeString(), sev: alert.severity || 'low', sevCol: sevColors[alert.severity] || '#38bdf8', title: alert.description || alert.ruleId, details: `${alert.device || 'Unknown device'} · ${alert.agentName || alert.hostname || 'Unknown endpoint'}` }));
    return {
      topCards: [
        { title: 'USB CONNECTIONS', val: connections.length, sub: 'Live telemetry', subCol: '#38bdf8', icon: '🔱', iconBg: 'rgba(56,189,248,.15)' },
        { title: 'AUTHORIZED DEVICES', val: authorizedDeviceCount, sub: 'Live telemetry', subCol: '#34d399', icon: '🛡️', iconBg: 'rgba(52,211,153,.15)' },
        { title: 'UNAUTHORIZED DEVICES', val: unauthorizedKeys.size, sub: 'Live telemetry', subCol: '#fb923c', icon: '⚠️', iconBg: 'rgba(251,146,60,.15)' },
        { title: 'POLICY VIOLATIONS', val: policyRows.length, sub: 'Live telemetry', subCol: '#f87171', icon: '🛑', iconBg: 'rgba(248,113,113,.15)' },
        { title: 'DATA COPIED TO USB', val: formatBytes(copiedBytes), sub: 'Live telemetry', subCol: '#a78bfa', icon: '📄', iconBg: 'rgba(167,139,250,.15)' },
      ], topDevices, recentEvents, alertsStream, topFileActivities, userActivity,
      policyViolations: [...policyMap.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, count })),
      blocked: blocked.length,
    };
  }, [alerts]);
  const { topCards, topDevices, recentEvents, alertsStream, topFileActivities, userActivity, policyViolations } = overview;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (5 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', alignItems: 'center', gap: 12 }}>
            <div style={{ width: 38, height: 38, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 18, flexShrink: 0 }}>
              {c.icon}
            </div>

            <div style={{ display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontSize: 9.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px' }}>
                {c.title}
              </span>
              <span style={{ fontSize: 22, fontWeight: 800, color: '#ffffff', margin: '2px 0' }}>
                {c.val}
              </span>
              <span style={{ fontSize: 9.5, fontWeight: 700, color: c.subCol }}>
                {c.sub}
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.4fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <UsbActivityTimelineChart alerts={alerts} />
        </div>
        {/* Top USB Devices */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Top USB Devices (by Usage)</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 0.6fr 1.2fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Device</span>
              <span>Type</span>
              <span>Connections</span>
              <span>Data Transferred</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topDevices.map(d => (
                <div key={d.name} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 0.6fr 1.2fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>💾 {d.name}</span>
                  <span style={{ color: '#8ea0b8', fontSize: 9 }}>{d.type}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{d.conn}</span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <div style={{ flex: 1, height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${d.pct}%`, height: '100%', background: '#38bdf8', borderRadius: 3 }} />
                    </div>
                    <span style={{ color: '#34d399', fontWeight: 700, fontSize: 8.5 }}>{d.data}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Devices →</span>
          </div>
        </div>

        <div style={panelStyle}>
          <DeviceConnectionStatusDonut alerts={alerts} />
        </div>
      </div>

      {/* 3. MIDDLE SECTION (3 Columns Layout) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1fr', gap: 12 }}>
        {/* Column 1: Recent USB Events & Alerts */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent USB Events</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '0.8fr 1fr 1.3fr 1.2fr 0.9fr 1.1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
                <span>Time</span>
                <span>User</span>
                <span>Device</span>
                <span>Event</span>
                <span>Status</span>
                <span>Details</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {recentEvents.map((re, idx) => (
                  <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.8fr 1fr 1.3fr 1.2fr 0.9fr 1.1fr', gap: 4, alignItems: 'center', fontSize: 9 }}>
                    <span style={{ color: '#64748b', fontSize: 8.5 }}>{re.time}</span>
                    <span style={{ color: '#8ea0b8' }}>{re.user}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{re.device}</span>
                    <span style={{ color: '#e2e8f0' }}>{re.event}</span>
                    <span style={{ fontSize: 8, fontWeight: 800, padding: '1px 5px', borderRadius: 8, background: re.statusBg, color: re.statusCol, border: `1px solid ${re.statusCol}44`, display: 'inline-block', textAlign: 'center' }}>
                      {re.status}
                    </span>
                    <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 8.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{re.details}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Events →</span>
            </div>
          </div>

          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Alerts</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {alertsStream.map((al, idx) => (
                  <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.8fr 0.8fr 2.5fr 1.2fr', gap: 6, alignItems: 'center', fontSize: 9, padding: '4px 6px', background: '#07101b', borderRadius: 4, border: '1px solid #16273e' }}>
                    <span style={{ color: '#64748b', fontSize: 8.5 }}>{al.time}</span>
                    <span style={{ fontSize: 8, fontWeight: 800, color: al.sevCol }}>{al.sev}</span>
                    <span style={{ color: '#cbd5e1', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{al.title}</span>
                    <span style={{ color: '#8ea0b8', fontSize: 8.5, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{al.details}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts →</span>
            </div>
          </div>
        </div>

        {/* Column 2: Top File Activities & User Activity */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>Top File Activities (To USB)</span>
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.5fr 1fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
                <span>File Type</span>
                <span>Files</span>
                <span>Size Progress</span>
                <span>Total Size</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {topFileActivities.map(fa => (
                  <div key={fa.type} style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr 1.5fr 1fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                    <span style={{ color: '#cbd5e1', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>{fa.icon}</span> {fa.type}
                    </span>
                    <span style={{ color: '#8ea0b8' }}>{fa.count}</span>
                    <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${fa.pct}%`, height: '100%', background: fa.col, borderRadius: 3 }} />
                    </div>
                    <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{fa.size}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>User Activity (USB Usage)</span>
              <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr 0.6fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
                <span>User</span>
                <span>Activity Progress</span>
                <span>Connections</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {userActivity.map(ua => (
                  <div key={ua.name} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.8fr 0.6fr', gap: 6, alignItems: 'center', fontSize: 9.5 }}>
                    <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{ua.name}</span>
                    <div style={{ height: 6, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${ua.pct}%`, height: '100%', background: '#38bdf8', borderRadius: 3 }} />
                    </div>
                    <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{ua.conn}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Users →</span>
            </div>
          </div>
        </div>

        {/* Column 3: Policy Violations & USB Heatmap */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Policy Violations</span>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '2fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
                <span>Policy</span>
                <span style={{ textAlign: 'right' }}>Violations</span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
                {policyViolations.map(pv => (
                  <div key={pv.name} style={{ display: 'grid', gridTemplateColumns: '2fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                    <span style={{ color: '#cbd5e1' }}>{pv.name}</span>
                    <span style={{ color: '#f87171', fontWeight: 800, textAlign: 'right' }}>{pv.count}</span>
                  </div>
                ))}
              </div>
            </div>
            <div style={{ marginTop: 8 }}>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Violations →</span>
            </div>
          </div>

          <div style={panelStyle}>
            <UsbHeatmapMatrix alerts={alerts} />
          </div>
        </div>
      </div>
    </div>
  );
}

function UsbPolicyViolationsTab() {
  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const [policies, setPolicies] = useState([]);
  const [violations, setViolations] = useState([]);
  const [total, setTotal] = useState(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [form, setForm] = useState({ name: '', description: '', ruleType: 'allow_serials', action: 'audit', values: '', maxMb: '' });
  const load = useCallback(() => Promise.all([
    api.get('/usb-policies'),
    api.get('/usb-policies/violations?days=90&limit=250'),
  ]).then(([policyRes, violationRes]) => {
    setPolicies(policyRes.data?.policies || []);
    setViolations(violationRes.data?.violations || []);
    setTotal(Number(violationRes.data?.total || 0));
    setError('');
  }).catch(err => setError(err.response?.data?.message || 'USB policies could not be loaded')), []);

  useEffect(() => { load(); const timer = setInterval(load, 30000); return () => clearInterval(timer); }, [load]);

  useEffect(() => {
    if (!companyId) return undefined;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => socket.emit('join:company', companyId);
    let refreshTimer;
    const refresh = () => {
      window.clearTimeout(refreshTimer);
      refreshTimer = window.setTimeout(load, 400);
    };
    const refreshViolation = event => {
      if (usbEventFacts(event).policyViolation) refresh();
    };
    socket.on('connect', join);
    socket.on('usb-policy:updated', refresh);
    socket.on('usb:event', refreshViolation);
    join();
    const disconnect = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('usb-policy:updated', refresh);
      socket.off('usb:event', refreshViolation);
      window.clearTimeout(refreshTimer);
      disconnect();
    };
  }, [companyId, load]);

  const createPolicy = async event => {
    event.preventDefault();
    if (!form.name.trim()) return setError('Rule name is required');
    setSaving(true);
    try {
      await api.post('/usb-policies', {
        name: form.name.trim(), description: form.description.trim(), ruleType: form.ruleType,
        action: form.action, values: form.values.split(',').map(value => value.trim()).filter(Boolean),
        maxBytes: form.ruleType === 'max_file_size' ? Math.max(0, Number(form.maxMb) || 0) * 1048576 : 0,
      });
      setForm({ name: '', description: '', ruleType: 'allow_serials', action: 'audit', values: '', maxMb: '' });
      await load();
    } catch (err) { setError(err.response?.data?.message || 'Rule creation failed'); }
    finally { setSaving(false); }
  };

  const updatePolicy = async (policy, update) => {
    try { await api.patch(`/usb-policies/${policy._id}`, update); await load(); }
    catch (err) { setError(err.response?.data?.message || 'Rule update failed'); }
  };
  const deletePolicy = async policy => {
    if (!window.confirm(`Delete USB rule "${policy.name}"?`)) return;
    try { await api.delete(`/usb-policies/${policy._id}`); await load(); }
    catch (err) { setError(err.response?.data?.message || 'Rule deletion failed'); }
  };
  const needsValues = ['allow_serials', 'block_serials', 'block_vendor', 'block_device_type', 'block_extensions'].includes(form.ruleType);
  const inputStyle = { background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 10px', borderRadius: 6, fontSize: 11, width: '100%' };
  const ruleLabels = { allow_serials: 'Allow only serial numbers', block_serials: 'Block serial numbers', block_vendor: 'Block vendor', block_device_type: 'Block device type', block_sensitive_files: 'Block sensitive files', block_extensions: 'Block file extensions', max_file_size: 'Maximum file size', read_only: 'Force read-only USB' };

  return <div style={{display:'grid',gridTemplateColumns:'360px 1fr',gap:14,color:MON.text}}>
    <form onSubmit={createPolicy} style={{background:MON.card,border:`1px solid ${MON.border}`,borderRadius:8,padding:16,display:'flex',flexDirection:'column',gap:11,alignSelf:'start'}}>
      <div><b style={{fontSize:14}}>＋ Create USB Enforcement Rule</b><div style={{fontSize:9,color:MON.sub,marginTop:4}}>Rules sync to active agents on their next heartbeat.</div></div>
      <input style={inputStyle} placeholder="Rule name" value={form.name} onChange={e=>setForm({...form,name:e.target.value})} />
      <textarea style={{...inputStyle,minHeight:65}} placeholder="Description" value={form.description} onChange={e=>setForm({...form,description:e.target.value})} />
      <select style={inputStyle} value={form.ruleType} onChange={e=>setForm({...form,ruleType:e.target.value})}>{Object.entries(ruleLabels).map(([value,label])=><option key={value} value={value}>{label}</option>)}</select>
      <select style={inputStyle} value={form.action} onChange={e=>setForm({...form,action:e.target.value})}><option value="audit">Audit only</option><option value="block">Block and enforce</option></select>
      {needsValues && <input style={inputStyle} placeholder="Comma-separated values" value={form.values} onChange={e=>setForm({...form,values:e.target.value})} />}
      {form.ruleType === 'max_file_size' && <input style={inputStyle} type="number" min="0" placeholder="Maximum size (MB)" value={form.maxMb} onChange={e=>setForm({...form,maxMb:e.target.value})} />}
      <button disabled={saving} style={{background:MON.cyan,border:0,borderRadius:6,padding:10,fontWeight:900,cursor:'pointer'}}>{saving?'Creating…':'Create & Sync Rule'}</button>
      {error && <div style={{color:MON.red,fontSize:10}}>{error}</div>}
    </form>
    <div style={{display:'flex',flexDirection:'column',gap:14,minWidth:0}}>
      <section style={{background:MON.card,border:`1px solid ${MON.border}`,borderRadius:8,overflow:'hidden'}}>
        <div style={{padding:12,fontWeight:900,borderBottom:`1px solid ${MON.line}`}}>USB Policies ({policies.length})</div>
        {policies.length ? policies.map(policy=><div key={policy._id} style={{display:'grid',gridTemplateColumns:'1.2fr 1fr 80px 72px 70px',gap:10,padding:11,borderTop:`1px solid ${MON.line}`,alignItems:'center',fontSize:10}}><span><b>{policy.name}</b><small style={{display:'block',color:MON.sub,marginTop:3}}>{ruleLabels[policy.ruleType] || policy.ruleType}{policy.values?.length?` · ${policy.values.join(', ')}`:''}</small></span><span style={{color:MON.sub}}>{policy.description || '—'}</span><b style={{color:policy.action==='block'?MON.red:MON.yellow,textTransform:'uppercase'}}>{policy.action}</b><button onClick={()=>updatePolicy(policy,{enabled:!policy.enabled})} style={{background:policy.enabled?`${MON.green}22`:`${MON.red}22`,color:policy.enabled?MON.green:MON.red,border:`1px solid ${policy.enabled?MON.green:MON.red}55`,borderRadius:5,padding:5,cursor:'pointer'}}>{policy.enabled?'Enabled':'Disabled'}</button><button onClick={()=>deletePolicy(policy)} style={{background:'transparent',color:MON.red,border:`1px solid ${MON.red}55`,borderRadius:5,padding:5,cursor:'pointer'}}>Delete</button></div>) : <div style={{padding:24,textAlign:'center',color:MON.sub}}>No USB policies created</div>}
      </section>
      <section style={{background:MON.card,border:`1px solid ${MON.border}`,borderRadius:8,overflow:'auto'}}>
        <div style={{padding:12,fontWeight:900,borderBottom:`1px solid ${MON.line}`}}>Policy Violations — Last 90 Days ({total})</div>
        <div style={{display:'grid',gridTemplateColumns:'130px 1fr 1fr 1fr 80px',gap:10,padding:9,fontSize:9,color:MON.sub,background:MON.card2}}><span>Time</span><span>Policy</span><span>Agent / User</span><span>Device / Details</span><span>Action</span></div>
        {violations.length ? violations.map(row=>{ const status=row.blocked||row.usbEnforcementStatus==='enforced'||row.actionTaken==='Blocked'?'BLOCKED':row.usbEnforcementStatus==='failed'||row.actionTaken==='Enforcement Failed'?'FAILED':'AUDIT'; return <div key={row._id} title={row.usbEnforcementError || ''} style={{display:'grid',gridTemplateColumns:'130px 1fr 1fr 1fr 80px',gap:10,padding:10,borderTop:`1px solid ${MON.line}`,fontSize:10}}><span>{new Date(row.createdAt).toLocaleString()}</span><b style={{color:MON.orange}}>{row.policyName || row.ruleId}</b><span>{row.agentName || row.hostname || '—'} / {row.username || '—'}</span><span>{row.device || row.description || '—'}</span><b style={{color:status==='BLOCKED'?MON.red:status==='FAILED'?MON.orange:MON.yellow}}>{status}</b></div>; }) : <div style={{padding:24,textAlign:'center',color:MON.sub}}>No policy violations detected</div>}
      </section>
    </div>
  </div>;
}

export default function UsbDeviceControlDashboard({ alerts = [], loading = false, total = 0 }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [usbSystems, setUsbSystems] = useState([]);

  useEffect(() => {
    let active = true;
    const loadAgentStatus = () => api.get('/system')
      .then(response => {
        if (!active) return;
        const rows = response.data?.systems || response.data?.agents || response.data || [];
        setUsbSystems(Array.isArray(rows) ? rows.filter(system => system.usbMonitorEnabled !== false) : []);
      })
      .catch(() => { if (active) setUsbSystems([]); });
    loadAgentStatus();
    const timer = setInterval(loadAgentStatus, 60000);
    return () => { active = false; clearInterval(timer); };
  }, []);

  const liveStats = useMemo(() => {
    const rows = alerts.map(event => ({ event, facts: usbEventFacts(event) }));
    const eventsFor = predicate => rows.filter(row => predicate(row.facts, row.event)).map(row => row.event);
    const connectionAlerts = eventsFor(facts => facts.connected);
    const policyEvents = eventsFor(facts => facts.policyViolation);
    const copiedToEvents = eventsFor(facts => facts.copiedTo);
    const readEvents = eventsFor(facts => facts.readFrom);
    const todayStart = new Date();
    todayStart.setHours(0, 0, 0, 0);
    const fileCopyEventsToday = copiedToEvents.filter(event => new Date(event.createdAt || event.timestamp || 0) >= todayStart);
    const bytesOf = event => Number(usbValue(event, 'bytesTransferred', 'bytes_transferred') || usbValue(event, 'fileSize', 'file_size') || 0);
    const bytesTo = copiedToEvents.reduce((sum, event) => sum + bytesOf(event), 0);
    const bytesFrom = readEvents.reduce((sum, event) => sum + bytesOf(event), 0);
    const formatBytes = n => n >= 1073741824 ? `${(n / 1073741824).toFixed(1)} GB` : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;

    const latestDeviceState = new Map();
    rows.filter(row => row.facts.connected || row.facts.disconnected)
      .sort((a, b) => new Date(a.event.createdAt || a.event.timestamp || 0) - new Date(b.event.createdAt || b.event.timestamp || 0))
      .forEach(row => latestDeviceState.set(usbDeviceKey(row.event), row.facts.connected));
    const unauthorizedEvents = eventsFor(facts => facts.unauthorizedDevice);
    const unauthorizedKeys = new Set(unauthorizedEvents.map(usbDeviceKey).filter(Boolean));
    const blockedEvents = eventsFor(facts => facts.deviceBlocked);
    const blockedKeys = new Set(blockedEvents.map(usbDeviceKey).filter(Boolean));
    const connectedKeys = new Set(connectionAlerts.map(usbDeviceKey).filter(Boolean));

    const devices = {};
    const types = {};
    const agentMap = {};
    rows.forEach(({ event: a, facts }) => {
      const created = new Date(a.createdAt || a.timestamp || 0).getTime();
      const name = a.deviceName || a.device || a.rawEvent?.device_name || 'Unknown device';
      if (facts.connected) devices[name] = (devices[name] || 0) + 1;
      const typeEvidence = `${facts.deviceType} ${facts.description}`;
      const type = a.deviceType || a.rawEvent?.device_type || (/mobile|phone|mtp/i.test(typeEvidence) ? 'Mobile Device' : /hdd|ssd/i.test(typeEvidence) ? 'External HDD/SSD' : /hid|keyboard/i.test(typeEvidence) ? 'HID Device' : 'USB Storage Drive');
      if (facts.connected) types[type] = (types[type] || 0) + 1;
      const agentKey = a.agentId || a.agentName || a.systemId?._id || a.systemId || 'unknown';
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown agent', events: 0, files: 0, bytes: 0, violations: 0, malware: 0, lastSeen: null });
      agent.events += 1;
      if (facts.copiedTo || facts.readFrom) agent.files += 1;
      if (facts.copiedTo || facts.readFrom) agent.bytes += bytesOf(a);
      if (facts.policyViolation) agent.violations += 1;
      if (facts.malware) agent.malware += 1;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
    });

    const eventGroups = {
      connected: connectionAlerts,
      activeDevices: eventsFor(facts => facts.connected || facts.disconnected),
      authorized: connectionAlerts.filter(event => !unauthorizedKeys.has(usbDeviceKey(event))),
      unauthorized: unauthorizedEvents,
      blocked: blockedEvents,
      fileCopies: fileCopyEventsToday,
      copiedToUsb: copiedToEvents,
      copiedFromUsb: readEvents,
      sensitiveCopies: eventsFor(facts => facts.sensitive),
      malwareDetected: eventsFor(facts => facts.malware),
      hidAttacks: eventsFor(facts => facts.hidThreat),
      duckyCount: eventsFor(facts => facts.rubberDucky),
      driversInstalled: eventsFor(facts => facts.driverLoaded),
      policyViolations: policyEvents,
      writeBlockEvents: eventsFor(facts => facts.writeBlocked),
      readEvents,
      storageMounted: eventsFor(facts => facts.storageMounted),
      extHDDConnected: eventsFor(facts => facts.externalDisk),
      mobileConnected: eventsFor(facts => facts.mobile),
      networkAdapters: eventsFor(facts => facts.networkAdapter),
    };

    return {
      connected: connectionAlerts.length,
      activeDevices: [...latestDeviceState.values()].filter(Boolean).length,
      authorized: [...connectedKeys].filter(key => !unauthorizedKeys.has(key)).length,
      unauthorized: unauthorizedKeys.size,
      blocked: blockedKeys.size,
      fileCopies: fileCopyEventsToday.length,
      copiedToUsb: formatBytes(bytesTo), copiedFromUsb: formatBytes(bytesFrom),
      sensitiveCopies: eventGroups.sensitiveCopies.length, malwareDetected: eventGroups.malwareDetected.length,
      hidAttacks: eventGroups.hidAttacks.length, duckyCount: eventGroups.duckyCount.length,
      driversInstalled: eventGroups.driversInstalled.length,
      policyViolations: policyEvents.length, writeBlockEvents: eventGroups.writeBlockEvents.length,
      readEvents: readEvents.length, storageMounted: eventGroups.storageMounted.length,
      extHDDConnected: eventGroups.extHDDConnected.length, mobileConnected: eventGroups.mobileConnected.length,
      networkAdapters: eventGroups.networkAdapters.length,
      timeline: usbTimeline(alerts, 18, 24),
      series: Object.fromEntries(Object.entries(eventGroups).map(([key, events]) => [key, usbTimeline(events, 18, 24)])),
      topDevices: Object.entries(devices).sort((a,b) => b[1] - a[1]).slice(0,5),
      topTypes: Object.entries(types).sort((a,b) => b[1] - a[1]).slice(0,5),
      agentRows: Object.values(agentMap).sort((a,b) => b.events - a.events),
    };
  }, [alerts]);

  const kpis = [
    ['Total USB Devices Connected', 'connected', MON.blue], ['Active USB Devices', 'activeDevices', MON.cyan],
    ['Authorized Devices', 'authorized', MON.green], ['Unauthorized Devices', 'unauthorized', MON.orange],
    ['Blocked Devices', 'blocked', MON.red], ['File Copies Today', 'fileCopies', MON.purple],
    ['Data Copied to USB', 'copiedToUsb', MON.yellow], ['Data Copied from USB', 'copiedFromUsb', MON.blue],
    ['Sensitive File Copies', 'sensitiveCopies', MON.red], ['Malware Detected from USB', 'malwareDetected', MON.red],
    ['HID Attack Attempts', 'hidAttacks', MON.orange], ['Rubber Ducky Detection', 'duckyCount', MON.red],
    ['Driver Installations', 'driversInstalled', MON.yellow], ['Policy Violations', 'policyViolations', MON.orange],
    ['USB Write Block Events', 'writeBlockEvents', MON.yellow], ['USB Read Events', 'readEvents', MON.cyan],
    ['USB Storage Mounted', 'storageMounted', MON.blue], ['External HDD Connected', 'extHDDConnected', MON.purple],
    ['Mobile Devices Connected', 'mobileConnected', MON.orange], ['USB Network Adapter Detection', 'networkAdapters', MON.red],
  ].map(([label, key, color]) => ({ label, val: liveStats[key], trend: 'LIVE', color, data: liveStats.series[key] || liveStats.timeline }));
  const agentStatusRows = usbSystems.map(system => {
    const systemKey = String(system.agentKey || system.agentId || system._id || '');
    const metrics = liveStats.agentRows.find(row => row.key === systemKey || systemKey.startsWith(row.key) || row.key.startsWith(systemKey) || row.name === system.name || row.name === system.hostname);
    return {
      key: system._id || systemKey,
      name: system.name || system.hostname || metrics?.name || 'Unknown agent',
      hostname: system.hostname || '—',
      status: system.status || 'unknown',
      monitor: system.usbMonitorEnabled !== false,
      lastSeen: system.lastSeen || metrics?.lastSeen,
      events: metrics?.events || 0,
      files: metrics?.files || 0,
      bytes: metrics?.bytes || 0,
      violations: metrics?.violations || 0,
      malware: metrics?.malware || 0,
    };
  });
  liveStats.agentRows.forEach(metrics => {
    if (!agentStatusRows.some(row => row.name === metrics.name || String(row.key).startsWith(metrics.key))) {
      agentStatusRows.push({ ...metrics, hostname: '—', status: 'reporting', monitor: true });
    }
  });
  const formatAgentBytes = n => n >= 1073741824 ? `${(n / 1073741824).toFixed(1)} GB` : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${Number(n || 0)} B`;

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.blue },
          { id: 'monitoring', icon: '📊', label: 'Monitoring', activeColor: MON.cyan },
          { id: 'policy-violations', icon: '⚖', label: 'Policy Violations', activeColor: MON.orange },
          { id: 'log-monitor', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.cyan },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
        ].map(item => {
          const selected = activeTab === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => setActiveTab(item.id)}
              aria-current={selected ? 'page' : undefined}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                background: selected ? item.activeColor : 'transparent',
                color: selected ? (item.id === 'reports' ? '#fff' : '#000') : MON.text,
                border: selected ? `1px solid ${item.activeColor}` : '1px solid transparent',
                padding: '10px 12px', borderRadius: 7, fontSize: 12, fontWeight: 800,
                textAlign: 'left', cursor: 'pointer',
              }}
            >
              <span aria-hidden="true">{item.icon}</span>
              <span>{item.label}</span>
            </button>
          );
        })}
      </aside>

      <main style={{ flex: 1, minWidth: 0, padding: 16, display: 'flex', flexDirection: 'column', gap: 16, overflowY: 'auto' }}>

      {activeTab === 'log-monitor' ? (
        <UsbLogMonitor alerts={alerts} />
      ) : activeTab === 'policy-violations' ? (
        <UsbPolicyViolationsTab />
      ) : activeTab === 'reports' ? (
        <CapabilityReportsPanel capabilityId={10} alerts={alerts} />
      ) : activeTab === 'dashboard' ? (
        <UsbOverviewDashboard alerts={alerts} total={total} />
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

          <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
            <div style={{padding:'11px 14px',borderBottom:`1px solid ${MON.line}`,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
              <div style={{fontSize:12,fontWeight:900,color:'#fff'}}>🛰 Agent-Level USB Monitoring</div>
              <div style={{fontSize:9,color:MON.green}}>● {agentStatusRows.filter(row => row.status === 'active' || row.status === 'reporting').length} reporting · 15s refresh</div>
            </div>
            <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 80px 82px 76px 76px 92px 80px 120px',gap:8,padding:'9px 12px',background:MON.card2,color:MON.muted,fontSize:9,fontWeight:800}}>
              <span>Agent</span><span>Hostname</span><span>Status</span><span>USB Monitor</span><span>Events</span><span>Files</span><span>Transferred</span><span>Threats</span><span>Last Seen</span>
            </div>
            {agentStatusRows.length ? agentStatusRows.map(row => (
              <div key={row.key || row.name} style={{display:'grid',gridTemplateColumns:'1fr 1fr 80px 82px 76px 76px 92px 80px 120px',gap:8,padding:'10px 12px',borderTop:`1px solid ${MON.line}`,fontSize:10,alignItems:'center'}}>
                <b style={{color:MON.cyan}}>{row.name}</b><span>{row.hostname}</span>
                <b style={{color:row.status === 'active' || row.status === 'reporting' ? MON.green : MON.red,textTransform:'uppercase'}}>{row.status}</b>
                <span style={{color:row.monitor ? MON.green : MON.red}}>{row.monitor ? 'Enabled' : 'Disabled'}</span>
                <b>{row.events}</b><b>{row.files}</b><b>{formatAgentBytes(row.bytes)}</b>
                <b style={{color:row.malware || row.violations ? MON.red : MON.green}}>{Number(row.malware || 0) + Number(row.violations || 0)}</b>
                <span style={{color:MON.sub}}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Never'}</span>
              </div>
            )) : <div style={{padding:24,textAlign:'center',color:MON.muted,fontSize:11}}>No USB-enabled agents found</div>}
          </div>

          {/* Charts Row */}
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 USB Activity & Connection Timeline (90 Days)</div>
              <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                {liveStats.timeline.map((val, idx) => (
                  <div key={idx} title={`${val} events`} style={{ flex: 1, height: `${val ? Math.max(4, (val / Math.max(...liveStats.timeline, 1)) * 100) : 0}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                ))}
              </div>
            </div>

            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔌 Top Connected Devices</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                {liveStats.topDevices.map(([dev, count], index) => (
                  <div key={dev} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: MON.text, fontWeight: 700 }}>{dev}</span>
                    <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} events</span>
                  </div>
                ))}
                {!liveStats.topDevices.length && <div style={{color:MON.muted}}>No live device data</div>}
              </div>
            </div>

            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Device Type Distribution</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                {liveStats.topTypes.map(([type, count], index) => (
                  <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: MON.muted }}>{type}</span>
                    <span style={{ color: [MON.cyan, MON.blue, MON.purple][index % 3], fontWeight: 800 }}>{alerts.length ? Math.round((count / alerts.length) * 100) : 0}%</span>
                  </div>
                ))}
                {!liveStats.topTypes.length && <div style={{color:MON.muted}}>No live type data</div>}
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
// 4. OVERLAY CAPABILITY MODAL EXPORT
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
      const capabilityId = 10;
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId, windowHours: 24 });

      // The USB endpoint is the canonical live source. It includes USB events
      // plus USB-originated file/malware/EDR findings under one DB count.
      let r = await api.get(`/dashboard/alerts/usb?${q}`);
      let fetchedAlerts = r.data?.alerts || [];
      let fetchedTotal = r.data?.total || fetchedAlerts.length;

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/edr?${q}`);
          fetchedAlerts = r.data?.alerts || [];
          fetchedTotal = r.data?.total || fetchedAlerts.length;
        } catch (e) { /* ignore */ }
      }

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/all?${q}`);
          const allAlerts = r.data?.alerts || [];
          fetchedAlerts = allAlerts.filter(a => /usb|device|removable|storage/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.device || ''}`));
          fetchedTotal = fetchedAlerts.length;
        } catch (e) { /* ignore */ }
      }

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal);
    } catch (err) {
      console.warn('[USB Realtime Fetch Warning]', err);
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
    socket.on('connect', join);
    socket.on('alert:new', (newAlert) => {
      const capabilities = [newAlert?.capabilityId, ...(newAlert?.capabilityIds || [])].map(Number);
      if (newAlert && (capabilities.includes(10) || newAlert.eventCategory === 'usb')) {
        setAlerts(prev => prev.some(row => row._id === newAlert._id) ? prev : [newAlert, ...prev]);
      }
    });
    socket.on('usb:event', (newAlert) => {
      if (newAlert) {
        setAlerts(prev => prev.some(row => row._id === newAlert._id) ? prev : [newAlert, ...prev]);
      }
    });
    socket.on('telemetry:new', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new');
      socket.off('usb:event');
      socket.off('telemetry:new');
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 10. Device Control (USB) Monitoring</h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <UsbDeviceControlDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function UsbSubTabPage() {
  return <CapabilitySubTabPage kind="usb" />;
}
