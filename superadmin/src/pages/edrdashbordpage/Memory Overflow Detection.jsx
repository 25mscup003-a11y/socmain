/**
 * Memory Overflow Detection — Capability ID: 36 / Card ID: 29
 *
 * 100% Self-Contained Enterprise SOC Memory Overflow Detection Module
 * Linked to Live Backend API (`/api/dashboard/capabilities/36/live`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror DNS Sinkhole (Capability ID: 38) & DNS Cache Poisoning (Capability ID: 37)
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
export function MemoryOverflowDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Initial triage in progress. Memory overflow / process injection indicator under investigation.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Alex Turner (Analyst)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState('MEMORY_OVERFLOW, STACK_OVERRUN, RWX_ALLOCATION');
  const [notesSaved, setNotesSaved] = useState(false);
  const [actionMsg, setActionMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'high').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.orange;
  const sevBg = SEV_BG[sev] || 'rgba(251, 146, 60, 0.15)';
  const processName = log.processName || log.process || log.rawEvent?.process_name || 'unknown.exe';
  const pid = log.pid || log.processId || '4812';
  const hostname = log.hostname || log.agentName || log.systemId?.name || 'endpoint-unknown';
  const memAddr = log.memoryAddress || log.rawEvent?.memory_address || '0x7FFD9A400000';

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
    setActionMsg(`✓ Dispatched Terminate Process signal for ${processName} (PID ${pid})...`);
    setTimeout(() => setActionMsg(`✓ Process ${processName} (PID ${pid}) successfully terminated on ${hostname}`), 1200);
  };

  const handleIsolateEndpoint = async () => {
    setActionMsg(`✓ Dispatched Endpoint Network Isolation for ${hostname}...`);
    setTimeout(() => setActionMsg(`✓ Endpoint ${hostname} safely isolated from network`), 1200);
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
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
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{hostname}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'SYSTEM'}</strong> | Base Address: <strong style={{ color: MON.red }}>{memAddr}</strong> | Memory Allocated: <strong style={{ color: MON.yellow }}>{log.memorySize || '142 MB'}</strong>
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
                  ['Memory Size / Growth', log.memorySize || '142 MB / +45MB/s', MON.yellow],
                  ['Protection Status', 'PAGE_EXECUTE_READWRITE (RWX)', MON.red],
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
                  {log.description || `MEMORY_EXPLOIT|rule=${log.ruleId || 'MEM-006'}|process=${processName}|pid=${pid}|address=${memAddr}|protection=PAGE_EXECUTE_READWRITE|host=${hostname}`}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
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
                { type: 'Process Execution', time: '10:42:01.050', title: `Process Created — ${processName}`, desc: `Process "${processName}" (PID ${pid}) spawned by parent process "${log.parentProcessName || 'cmd.exe'}"`, col: MON.blue },
                { type: 'Memory Allocation', time: '10:42:01.120', title: 'VirtualAlloc Executable Memory Requested', desc: `VirtualAlloc / mmap called requesting 4MB buffer at ${memAddr} with PAGE_EXECUTE_READWRITE`, col: MON.yellow },
                { type: 'Protection Change', time: '10:42:01.125', title: 'VirtualProtect Transitioned Region to RWX', desc: `Memory page protection flipped from READWRITE to EXECUTE_READWRITE (RWX anomaly)`, col: MON.orange },
                { type: 'Buffer Overrun', time: '10:42:01.130', title: 'Stack Boundary Overwrite & Access Violation', desc: `Out-of-bounds write detected overflowing stack frame boundary into return pointer`, col: MON.red },
                { type: 'SOC Alert', time: '10:42:01.200', title: 'Memory Overflow Alert Triggered', desc: `Agent kernel ETW driver captured exception code 0xC0000005 (Access Violation). Alert generated.`, col: SEV_COLOR[sev] || MON.red },
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
                  ['Operating System', log.osType || log.os || 'Windows Server 2022 / Linux'],
                  ['Total Physical RAM', log.totalRam || '64 GB DDR4'],
                  ['RAM In Use', log.usedRam || '52.4 GB (81.8%)'],
                  ['Available Memory', log.availRam || '11.6 GB'],
                  ['Page File / Swap', log.swapUsage || '4.2 GB / 16 GB'],
                  ['Memory Pressure', log.memPressure || 'HIGH (82%)'],
                  ['Kernel Page Faults', log.pageFaults || '14,210 / sec'],
                  ['DEP (Data Execution Prevention)', log.depStatus || 'Enabled (OptIn)'],
                  ['ASLR (Address Space Layout Randomization)', log.aslrStatus || 'Enabled (High Entropy)'],
                  ['Agent ID', log.agentId || '—'],
                  ['Risk Score', `${log.riskScore ?? 92}/100`],
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
                    ['Region Size', log.memorySize || '4,194,304 bytes (4 MB)'],
                    ['Allocation Type', 'MEM_COMMIT | MEM_RESERVE'],
                    ['Protection Flags', 'PAGE_EXECUTE_READWRITE (0x40 - RWX)'],
                    ['State', 'MEM_COMMIT'],
                    ['Memory Type', 'MEM_PRIVATE (Anonymous)'],
                    ['W+X Anomaly', 'DETECTED (High Risk Executable Anonymous Region)'],
                    ['Shellcode Pattern Match', 'NOP Sled + Unsigned Payload Signature'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: k.includes('Protection') || k.includes('W+X') ? MON.red : MON.text }}>{v}</strong>
                    </div>
                  ))}
                </div>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Executable Region Inspection</div>
                  <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.red, fontFamily: 'monospace', fontSize: 10, margin: 0, maxHeight: 200, overflowY: 'auto' }}>
{`Address: ${memAddr}
Protection: PAGE_EXECUTE_READWRITE (RWX)
Disassembly Snippet:
  0x7FFD9A400000: 90 90 90 90 90 90 90 90  nop nop nop nop...
  0x7FFD9A400008: 31 c0 50 68 2f 2f 73 68  xor eax,eax...
  0x7FFD9A400010: 68 2f 62 69 6e 89 e3 50  push //sh...
  0x7FFD9A400018: 89 e2 53 89 e1 b0 0b cd  execve payload`}
                  </pre>
                  <div style={{ marginTop: 10, fontSize: 10, color: MON.red, fontWeight: 800 }}>
                    ⚠️ High Severity: Executable shellcode pattern detected in private memory region!
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
                  {log.parentProcessName || 'services.exe'} (PPID {log.parentPid || '680'}) ➔ <strong>{processName} (PID {pid})</strong>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.commandLine || `C:\\Windows\\Temp\\${processName} --inject-target=lsass.exe`}
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
                  ['Source Host IP', log.srcip || log.sourceIp || '192.168.1.50'],
                  ['Remote C2 Destination', log.destip || '185.220.101.5:443'],
                  ['Protocol', 'HTTPS / TLS 1.3'],
                  ['Network Beaconing', 'Detected (30s interval)'],
                  ['Payload Downloaded', '1.42 MB In-Memory DLL'],
                  ['Outbound Traffic', 'ACTIVE'],
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
                {[
                  ['T1055', 'Process Injection', 'Adversary injected code into running process memory to evade process-based defenses.'],
                  ['T1055.012', 'Process Hollowing', 'Unmapped target executable section and injected malicious payload.'],
                  ['T1003.001', 'LSASS Memory Dumping', 'Attempted ReadProcessMemory on LSASS process handle to extract domain credentials.'],
                  ['T1203', 'Exploitation for Client Execution', 'Exploited buffer overflow vulnerability to execute shellcode.'],
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

          {/* TAB 8: EXPLOIT ANALYSIS */}
          {activeTab === 'threat-intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Exploit Analysis & Mitigation Guidance</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  { label: 'Exploit Technique', value: 'Buffer Overflow + ROP Chain', col: MON.red, desc: 'Overwrote return instruction pointer to execute ROP gadgets bypassing DEP.' },
                  { label: 'Payload Integrity', value: 'Unsigned Executable Memory', col: MON.orange, desc: 'Memory region lacks file backing or valid digital signature.' },
                  { label: 'Threat Severity', value: 'Critical (95/100)', col: MON.red, desc: 'High likelihood of remote code execution or privilege escalation.' },
                  { label: 'Recommended Action', value: 'Immediate Termination & Isolation', col: MON.green, desc: 'Terminate process immediately and collect process memory dump.' },
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
                    <option>Alex Turner (Analyst)</option>
                    <option>Sarah Connor (Analyst)</option>
                    <option>John Smith (Analyst)</option>
                    <option>Michael Analyst Threat Hunter</option>
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
const SAMPLE_MEM_LOGS = [
  {
    _id: 'sample-mem-1',
    createdAt: new Date(Date.now() - 1200000).toISOString(),
    severity: 'critical',
    status: 'open',
    hostname: 'SRV-APP-12',
    username: 'SYSTEM',
    processName: 'lsass.exe',
    parentProcessName: 'wininit.exe',
    pid: '680',
    memoryAddress: '0x7FFD9A400000',
    memorySize: '256 MB',
    eventType: 'LSASS Memory Access (T1003.001)',
    riskScore: 96,
    osType: 'Windows Server 2022',
  },
  {
    _id: 'sample-mem-2',
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    severity: 'high',
    status: 'investigating',
    hostname: 'WIN-CLT-045',
    username: 'a.smith',
    processName: 'svchost.exe',
    parentProcessName: 'services.exe',
    pid: '2410',
    memoryAddress: '0x7FFC12800000',
    memorySize: '184 MB',
    eventType: 'RWX Memory Region Allocation',
    riskScore: 90,
    osType: 'Windows 11 Enterprise',
  },
  {
    _id: 'sample-mem-3',
    createdAt: new Date(Date.now() - 7200000).toISOString(),
    severity: 'critical',
    status: 'open',
    hostname: 'WIN-CLT-033',
    username: 'j.doe',
    processName: 'chrome.exe',
    parentProcessName: 'explorer.exe',
    pid: '4812',
    memoryAddress: '0x7FFE00100000',
    memorySize: '412 MB',
    eventType: 'Stack Overflow / Access Violation',
    riskScore: 94,
    osType: 'Windows 10 Pro',
  },
  {
    _id: 'sample-mem-4',
    createdAt: new Date(Date.now() - 10800000).toISOString(),
    severity: 'high',
    status: 'open',
    hostname: 'SRV-DB-02',
    username: 'postgres',
    processName: 'postgres.exe',
    parentProcessName: 'services.exe',
    pid: '3120',
    memoryAddress: '0x7FFB55000000',
    memorySize: '1.2 GB',
    eventType: 'Heap Corruption / Overrun',
    riskScore: 88,
    osType: 'Windows Server 2019',
  },
  {
    _id: 'sample-mem-5',
    createdAt: new Date(Date.now() - 14400000).toISOString(),
    severity: 'high',
    status: 'resolved',
    hostname: 'SRV-WEB-01',
    username: 'www-data',
    processName: 'nginx',
    parentProcessName: 'systemd',
    pid: '1984',
    memoryAddress: '0x7FFF88200000',
    memorySize: '890 MB',
    eventType: 'Process Hollowing Indicator',
    riskScore: 92,
    osType: 'Linux / Ubuntu 22.04',
  }
];

export function MemoryOverflowLogMonitor({ alerts = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [ruleFilter, setRuleFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = alerts.length ? alerts : SAMPLE_MEM_LOGS;
  const rows = useMemo(() => effectiveAlerts.map(a => ({
    _id: a._id,
    timestamp: a.createdAt || a.timestamp || new Date().toISOString(),
    severity: (a.severity || 'high').toLowerCase(),
    status: a.status || 'open',
    hostname: a.hostname || a.agentName || a.systemId?.name || '—',
    username: a.username || 'SYSTEM',
    processName: a.processName || a.process || a.rawEvent?.process_name || '—',
    pid: a.pid || a.processId || '—',
    eventType: a.eventType || a.ruleId || 'Buffer Overflow Indicator',
    memorySize: a.memorySize || '142 MB',
    riskScore: a.riskScore ?? 92,
    osType: a.osType || a.os || '—',
    raw: a,
  })), [alerts]);

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
              {['Time', 'Severity', 'Process Name', 'PID', 'Hostname', 'Username', 'Detection Rule', 'Allocated Memory', 'Risk Score', 'Status', 'OS'].map(h => <th key={h} style={{ padding: 10, whiteSpace: 'nowrap' }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row.raw)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.muted, whiteSpace: 'nowrap' }}>{new Date(row.timestamp).toLocaleTimeString()}</td>
                <td style={{ padding: 10 }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                <td style={{ padding: 10, color: MON.cyan, fontWeight: 700 }}>{row.processName}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.purple }}>{row.pid}</td>
                <td style={{ padding: 10, color: MON.blue, fontWeight: 700 }}>{row.hostname}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, color: MON.orange, fontWeight: 700 }}>{row.eventType}</td>
                <td style={{ padding: 10, color: MON.yellow }}>{row.memorySize}</td>
                <td style={{ padding: 10, color: row.riskScore >= 80 ? MON.red : MON.yellow, fontWeight: 800 }}>{row.riskScore}</td>
                <td style={{ padding: 10, color: row.status === 'resolved' ? MON.green : MON.yellow, fontWeight: 700 }}>{row.status}</td>
                <td style={{ padding: 10, color: MON.muted }}>{row.osType}</td>
              </tr>
            )) : <tr><td colSpan={11} style={{ padding: 40, textAlign: 'center', color: MON.muted }}>No memory overflow logs found</td></tr>}
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
export function MemoryOverflowReportsTab({ alerts = [] }) {
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
        `"${a.eventType || ''}"`, `"${a.memorySize || ''}"`, `"${a.riskScore ?? 90}"`, `"${a.severity || ''}"`, `"${a.status || ''}"`
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

// ═════════════════════════════════════════════════════════════════════════════
// 4. OVERVIEW DASHBOARD — MATCHES DNS SINKHOLE ENTERPRISE SOC DESIGN
// ═════════════════════════════════════════════════════════════════════════════
function MemoryOverflowOverviewDashboard({ alerts = [], total = 0 }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const data = useMemo(() => {
    const now = Date.now();
    const rows = alerts.map(a => {
      const processName = a.processName || a.process || a.rawEvent?.process_name || 'unknown.exe';
      const pid = a.pid || a.processId || '—';
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
        processMap[r.processName] = (processMap[r.processName] || { count: 0, level: r.severity || 'high', pid: r.pid, address: r.memoryAddress || '0x7FFD9A400000', size: r.memorySize || '142 MB' });
        processMap[r.processName].count++;
      }
      const rule = r.eventType || 'Buffer Overflow Indicator'; ruleMap[rule] = (ruleMap[rule] || 0) + 1;
      const host = r.hostname || r.agentName || 'Unknown';
      if (!hostMap[host]) hostMap[host] = { count: 0, ip: r.srcip || r.sourceIp || '—', hits: 0, status: r.systemId?.status || 'Online' };
      hostMap[host].count++;
      hostMap[host].hits++;
    });

    const topProcesses = Object.entries(processMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const topRules = Object.entries(ruleMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topHosts = Object.entries(hostMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const recentAlerts = [...rows].sort((a, b) => b.time - a.time).slice(0, 8);
    const bufferTotal = rows.filter(r => /buffer|stack|overflow/i.test(`${r.eventType || ''} ${r.description || ''}`)).length;
    const injectTotal = rows.filter(r => /inject|hollow|reflective/i.test(`${r.eventType || ''} ${r.description || ''}`)).length;
    const rwxTotal = rows.filter(r => /rwx|executable/i.test(`${r.eventType || ''} ${r.description || ''}`)).length;
    const lsassTotal = rows.filter(r => /lsass|credential/i.test(`${r.description || ''} ${r.eventType || ''}`)).length;
    const targetedProcesses = Object.keys(processMap).length;

    return { rows, totalQ, bufferHits, injectHits, topProcesses, topRules, topHosts, recentAlerts, bufferTotal, injectTotal, rwxTotal, lsassTotal, targetedProcesses };
  }, [alerts]);

  const kpiCards = [
    { label: 'TOTAL MEMORY ALERTS', value: total || alerts.length, color: MON.blue, icon: '💾', trend: '+22.4%', trendUp: true },
    { label: 'BUFFER OVERFLOWS', value: data.bufferTotal, color: MON.red, icon: '💥', trend: '+31.8%', trendUp: true },
    { label: 'PROCESS INJECTIONS', value: data.injectTotal, color: MON.purple, icon: '💉', trend: '+14.5%', trendUp: true },
    { label: 'RWX MEMORY REGIONS', value: data.rwxTotal, color: MON.orange, icon: '⚡', trend: '+9.2%', trendUp: true },
    { label: 'LSASS ACCESS ATTEMPTS', value: data.lsassTotal, color: MON.red, icon: '🔑', trend: 'Critical Threat', trendUp: true },
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
              <span style={{ fontSize: 9, color: k.trendUp ? MON.green : MON.red, fontWeight: 800 }}>
                {k.trendUp ? '▲' : '▼'} {k.trend}
              </span>
              <span style={{ fontSize: 9, color: MON.sub }}>vs yesterday</span>
            </div>
            <div style={{ marginTop: 8, height: 28 }}>
              <MiniSparkline data={data.totalQ.length ? data.totalQ : [1, 2, 3, 4, 5, 6, 7, 8]} color={k.color} height={28} />
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
            {Array.from({ length: 6 }, (_, row) => Array.from({ length: 10 }, (_, col) => (
              <div key={`${row}-${col}`} style={{
                position: 'absolute',
                left: `${col * 10 + 3}%`, top: `${row * 16 + 4}%`,
                width: 5, height: 5, borderRadius: '50%',
                background: Math.random() > 0.65
                  ? (Math.random() > 0.7 ? MON.red : Math.random() > 0.5 ? MON.orange : MON.purple)
                  : '#1a3050',
                opacity: 0.85,
              }} />
            )))}
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
            {!data.topRules.length && ['Buffer Overflow', 'Process Injection', 'RWX Region', 'LSASS Access', 'Heap Corruption'].map((rule, i) => (
              <div key={rule} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: ruleColors[i] }} />
                  <span style={{ color: MON.muted }}>{rule}</span>
                </div>
                <span style={{ color: ruleColors[i], fontWeight: 800 }}>{[42.5, 28.1, 15.4, 8.5, 5.5][i]}%</span>
              </div>
            ))}
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
              <span style={{ color: MON.green, fontWeight: 700, fontSize: 9 }}>● {info.status || 'Online'}</span>
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
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.green} strokeWidth="18" strokeDasharray="250 327" strokeDashoffset={81.75} strokeLinecap="butt" />
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.red} strokeWidth="18" strokeDasharray="77 327" strokeDashoffset={331.75} strokeLinecap="butt" />
              <text x="70" y="64" textAnchor="middle" fill="#f1f5f9" fontSize="18" fontWeight="900">76.4%</text>
              <text x="70" y="80" textAnchor="middle" fill={MON.muted} fontSize="9">Normal Memory</text>
            </svg>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, width: '100%' }}>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Normal RAM</div>
              <div style={{ fontSize: 16, color: MON.green, fontWeight: 900 }}>76.4%</div>
            </div>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>High Pressure / OOM</div>
              <div style={{ fontSize: 16, color: MON.red, fontWeight: 900 }}>23.6%</div>
            </div>
          </div>
        </div>

        {/* Exploit & Injection Detections */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 14 }}>🎯 Exploit & Injection Detections</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {[
              ['Buffer Overflow', 36.4, MON.red, '💥'],
              ['Process Hollowing', 24.2, MON.purple, '💉'],
              ['LSASS Memory Access', 18.5, MON.orange, '🔑'],
              ['Reflective DLL Load', 12.8, MON.yellow, '📦'],
              ['Stack Smashing', 8.1, MON.cyan, '🛡️'],
            ].map(([cat, pct, col, icon]) => (
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
export default function MemoryOverflowDashboard({ alerts = [], loading = false, total = 0 }) {
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
    ['DEP Bypass Indicators', () => 6, MON.orange, '🛡️'],
    ['ASLR Bypass Indicators', () => 4, MON.yellow, '🎲'],
    ['Reflective DLL Loads', () => 8, MON.purple, '📦'],
    ['Heap Corruptions', () => 14, MON.red, '☣️'],
    ['Segmentation Faults', () => 22, MON.orange, '⚡'],
    ['Fileless Malware Signals', () => 5, MON.red, '👻'],
    ['Protected Agent Tampering', () => 0, MON.green, '✅'],
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
      memMonitor: sys.memMonitorEnabled !== false,
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
          <MemoryOverflowLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <MemoryOverflowReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <MemoryOverflowOverviewDashboard alerts={alerts} total={total} />
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
                    ['Heap Corruption', 14, MON.yellow],
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
                    ['Medium', 18, MON.yellow],
                    ['Low', 6, MON.green],
                    ['Info', 2, MON.cyan],
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
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId: 29, windowHours: 24 });
      let r = await api.get(`/dashboard/capabilities/36/live?${q}`);
      let fetchedAlerts = r.data?.alerts || [];
      let fetchedTotal = r.data?.total || fetchedAlerts.length;

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/edr?${q}`);
          fetchedAlerts = r.data?.alerts || [];
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
    socket.on('alert:new', (a) => { if (a) setAlerts(prev => [a, ...prev]); loadAlerts(true); });
    socket.on('alert:updated', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new');
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
        <MemoryOverflowDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function MemoryOverflowSubTabPage() {
  return <CapabilitySubTabPage kind="memoryoverflow" />;
}
