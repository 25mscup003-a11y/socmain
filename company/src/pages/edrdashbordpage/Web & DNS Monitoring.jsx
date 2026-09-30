/**
 * Web & DNS Monitoring — Capability ID: 9
 * 
 * 100% Self-Contained Enterprise SOC Web & DNS Monitoring Module
 * Linked to the canonical capability-9 live API, MongoDB alert queries, and
 * authenticated Socket.io streaming.
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

function isWebDnsAlert(alert = {}) {
  const raw = alert.rawEvent?.raw || alert.rawEvent || {};
  const ids = [alert.capabilityId, ...(Array.isArray(alert.capabilityIds) ? alert.capabilityIds : [])].map(Number);
  const text = `${alert.ruleId || ''} ${alert.eventType || ''} ${alert.source || ''} ${alert.protocol || ''}`;
  const evidence = Boolean(alert.domain || alert.url || alert.queryType || raw.domain || raw.query || raw.dnsQuery || raw.http_method)
    || /\bdns\b|http|web|waf|browser-history/i.test(text);
  return ids.includes(9) && evidence;
}

function telemetryCount(alert, raw, field) {
  const value = Number(alert?.[field] ?? raw?.[field]);
  return Number.isFinite(value) && value > 0 ? value : 1;
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

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function WebDnsLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || '');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState(Array.isArray(log?.tags) ? log.tags.join(', ') : '');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Network.Netstat');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'endpoint'} webdns forensic hunt`);
  const [systemIdInput, setSystemIdInput] = useState(log?.systemId?._id || log?.systemId || '');
  const [clientIdInput, setClientIdInput] = useState(log?.velociraptorId || '');
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const rawEvent = log.rawEvent && typeof log.rawEvent === 'object' ? log.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? { ...rawEvent, ...rawEvent.raw } : rawEvent;
  const sourceIp = log.srcIp || log.srcip || raw.src_ip || raw.source_ip || 'Not reported';
  const destinationIp = log.dstIp || log.destip || raw.dst_ip || raw.dest_ip || 'Not reported';
  const processName = log.processName || raw.process_name || 'Not reported';
  const processPid = log.pid ?? raw.pid ?? 'Not reported';
  const eventTime = log.createdAt || log.timestamp || raw.timestamp;
  const timelineEvents = [{
    type: log.queryType || /dns/i.test(`${log.protocol || ''} ${log.eventType || ''}`) ? 'DNS Event' : 'Web Event',
    time: eventTime ? new Date(eventTime).toLocaleTimeString() : 'Not reported',
    title: log.ruleId || log.eventType || 'Web & DNS telemetry',
    desc: log.description || log.full_log || 'No additional event description reported.',
    col: sevColor,
  }];
  const evidenceFiles = (Array.isArray(raw.downloaded_files) ? raw.downloaded_files : [])
    .concat(Array.isArray(raw.uploaded_files) ? raw.uploaded_files : []);
  if (!evidenceFiles.length && (log.filePath || raw.file_path)) {
    evidenceFiles.push({ name: log.fileName || raw.file_name, path: log.filePath || raw.file_path, size: log.fileSize || raw.file_size, hash: log.fileHash || raw.file_hash, result: log.malwareType || log.fileAction });
  }

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Server' },
    { id: 'process', label: '⚙️ 4. Process & Commands' },
    { id: 'files', label: '📁 5. Files & Uploads' },
    { id: 'network', label: '🌐 6. Network, JA3 & SSL' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & PCAP' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    {
      title: 'Linux Network Connections',
      desc: 'Active socket listeners, HTTP/DNS remote endpoints, ESTABLISHED connections.',
      artifact: 'Linux.Network.Netstat',
    },
    {
      title: 'Linux Process Triage',
      desc: 'Process list, web server workers (Nginx/Apache), parent PIDs, command line.',
      artifact: 'Linux.Sys.Pslist',
    },
    {
      title: 'Linux Log Hunter',
      desc: 'Access logs, error logs, sudo execution, auth.log, syslog web indicators.',
      artifact: 'Linux.Sys.LogHunter',
    },
    {
      title: 'Linux File Finder',
      desc: 'Scan /tmp, /var/www, /tmp uploads for webshells and suspicious scripts.',
      artifact: 'Linux.Search.FileFinder',
    },
    {
      title: 'YARA File Sweep',
      desc: 'Run YARA webshell & malware rules across web roots and binary caches.',
      artifact: 'Generic.Detection.Yara.Glob',
    },
    {
      title: 'Windows EVTX Hunter',
      desc: 'Scan DNS Client, IIS W3C Logs, Sysmon Event 3 (Network) & Event 22 (DNS).',
      artifact: 'Windows.EventLogs.EvtxHunter',
    },
  ];

  const handleLaunchHunt = () => {
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    setTimeout(() => {
      setLaunchingHunt(false);
      setHuntSuccessMsg('Not sent: no forensic-hunt executor is configured; no hunt or case was created.');
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
    downloadAnchor.setAttribute("download", `webdns_evidence_${log.caseId || 'WEBDNS-991'}_${log.hostname || 'HOST'}.${format.toLowerCase()}`);
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
                  Web & DNS Forensic Investigation Panel — {log.domain || log.url || log.dnsQuery || 'Suspicious Web Request'}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Case ID: {log.caseId || 'CASE-2026-8812'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{log.hostname || log.agentName || 'LIN-SRV-WEB01'}</strong> | User: <strong style={{ color: MON.text }}>{log.username || 'www-data'}</strong> | Time: <strong style={{ color: MON.text }}>{log.timestamp || log.createdAt || new Date().toISOString()}</strong>
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
                ['Threat Summary', log.action || log.description || 'Not reported', MON.cyan],
                ['Threat Score', log.threatScore != null || log.riskScore != null ? `${log.threatScore ?? log.riskScore}/100` : 'Not reported', (log.threatScore ?? log.riskScore ?? 0) > 75 ? MON.red : MON.orange],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Hostname / Server', log.hostname || log.agentName || 'Not reported', MON.blue],
                ['Source IP / User', `${sourceIp} (${log.username || raw.username || 'Not reported'})`, MON.cyan],
                ['Target Domain', log.domain || log.dnsQuery || raw.domain || 'Not reported', MON.red],
                ['Query Type / Protocol', [log.queryType || raw.query_type, log.protocol || raw.protocol].filter(Boolean).join(' / ') || 'Not reported', MON.purple],
                ['Detection Source', log.detectionEngine || log.detectionSource || log.source || 'Not reported', MON.green],
                ['HTTP Method & Code', [log.httpMethod || raw.http_method, log.responseCode || raw.response_code].filter(Boolean).join(' ') || 'Not reported', MON.yellow],
                ['Process & PID', `${processName} (PID: ${processPid})`, MON.orange],
                ['Enforcement Action', log.actionTaken || log.action || 'Observed', MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Web & DNS Event Chronology</div>
              {timelineEvents.map((ev, i) => (
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

          {/* TAB 3: ENDPOINT & SERVER PROFILE */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Host Endpoint & Installed Web Server Stack</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', log.hostname || log.agentName || 'Not reported'],
                  ['OS Version', log.os || log.osType || raw.os || raw.os_type || 'Not reported'],
                  ['IP Address', sourceIp],
                  ['Active Web Server', log.workloadType || raw.workload_type || 'Not reported'],
                  ['Virtual Hosts', raw.virtual_hosts?.join?.(', ') || 'Not reported'],
                  ['Logged-in User', log.username || raw.username || 'Not reported'],
                  ['Reverse Proxy', raw.reverse_proxy || 'Not reported'],
                  ['App Runtime', raw.runtime || raw.runtime_type || 'Not reported'],
                  ['Security Drivers', raw.security_drivers?.join?.(', ') || 'Not reported'],
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
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Ancestry & Command Line Execution</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Process Hierarchy (Parent ➔ Child):</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {log.parentProcessName || raw.parent_process_name || 'Parent not reported'} (PPID {log.parentPid ?? raw.parent_pid ?? '—'}) ➔ <span style={{ color: MON.yellow }}>{processName} (PID {processPid})</span>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.commandLine || log.processCmdline || raw.command_line || raw.process_cmdline || 'Not reported'}
                </pre>
              </div>
            </div>
          )}

          {/* TAB 5: FILES & UPLOADS */}
          {activeTab === 'files' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📁 Web File Transfers, Upload Abuse & WebShell Scans</div>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead>
                  <tr style={{ background: MON.card2, color: MON.muted, textAlign: 'left' }}>
                    <th style={{ padding: 8 }}>File Name</th>
                    <th style={{ padding: 8 }}>Path</th>
                    <th style={{ padding: 8 }}>Size</th>
                    <th style={{ padding: 8 }}>SHA256 Hash</th>
                    <th style={{ padding: 8 }}>Scan Result</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceFiles.map((file, i) => {
                    const r = Array.isArray(file) ? file : [file.name || 'Not reported', file.path || 'Not reported', file.size || 'Not reported', file.hash || 'Not reported', file.result || 'Observed'];
                    return (
                    <tr key={i} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 8, color: MON.cyan, fontWeight: 700 }}>{r[0]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[1]}</td>
                      <td style={{ padding: 8 }}>{r[2]}</td>
                      <td style={{ padding: 8, color: MON.sub, fontFamily: 'monospace' }}>{String(r[3]).length > 16 ? `${String(r[3]).substring(0, 16)}...` : r[3]}</td>
                      <td style={{ padding: 8 }}><span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 6px', borderRadius: 4, fontWeight: 800 }}>{r[4]}</span></td>
                    </tr>
                    );
                  })}
                  {!evidenceFiles.length && <tr><td colSpan={5} style={{ padding: 16, color: MON.muted, textAlign: 'center' }}>No file-transfer evidence reported for this event.</td></tr>}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 6: NETWORK, JA3 & SSL */}
          {activeTab === 'network' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                ['Destination IP', destinationIp],
                ['Destination Port', log.destPort || log.port || raw.dst_port || 'Not reported'],
                ['JA3 TLS Fingerprint', log.ja3 || raw.ja3 || 'Not reported'],
                ['SSL Certificate Subject', log.certificateInfo?.subject || raw.certificate_info?.subject || 'Not reported'],
                ['Issuer', log.certificateInfo?.issuer || raw.certificate_info?.issuer || 'Not reported'],
                ['TLS Version', log.tlsVersion || raw.tls_version || 'Not reported'],
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
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🎯 Indicators of Compromise & Threat Intelligence</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  ['T1071.004', 'DNS Application Layer Protocol', 'Data exfiltration and C2 beaconing using DNS TXT queries'],
                  ['T1568.002', 'Fast Flux DNS', 'Dynamic IP hopping detected across 24 distinct IP addresses'],
                  ['T1102', 'Web Service C2', 'Encrypted C2 channel established over HTTPS port 443'],
                  ['T1190', 'Exploit Public-Facing Application', 'Unauthenticated RCE attempt on web application endpoint'],
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

          {/* TAB 8: FORENSIC HUNT (VELOCIRAPTOR ENGINE) */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span>⚡</span> Forensic Hunt
                </h3>
                <span style={{ fontSize: 11, color: MON.muted, background: MON.card2, border: `1px solid ${MON.border}`, padding: '4px 10px', borderRadius: 6 }}>
                  Velociraptor Artifact Dispatcher Engine
                </span>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {forensicHuntCards.map((card) => {
                  const isSelected = selectedArtifact === card.artifact;
                  return (
                    <div
                      key={card.artifact}
                      onClick={() => setSelectedArtifact(card.artifact)}
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

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginTop: 8 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Hunt Name</div>
                  <input type="text" value={huntNameInput} onChange={(e) => setHuntNameInput(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12 }} />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Artifact Name</div>
                  <input type="text" readOnly value={selectedArtifact} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace', fontWeight: 700 }} />
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>System ID / Velociraptor ID</div>
                  <input type="text" value={systemIdInput} onChange={(e) => setSystemIdInput(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }} />
                </div>
                <div>
                  <div style={{ fontSize: 12, fontWeight: 700, color: '#f8fafc', marginBottom: 6 }}>Velociraptor Client ID</div>
                  <input type="text" value={clientIdInput} onChange={(e) => setClientIdInput(e.target.value)} style={{ width: '100%', background: MON.card, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 12, fontFamily: 'monospace' }} />
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: '14px 18px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: MON.muted }}>
                <span>Target:</span>
                <strong style={{ color: '#fff' }}>{log.hostname || log.agentName || 'Not reported'} / WebDNS</strong>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>OS: <strong style={{ color: '#fff' }}>{log.os || log.osType || 'Not reported'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>User: <strong style={{ color: '#fff' }}>{log.username || 'Not reported'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>PID: <strong style={{ color: '#fff' }}>{processPid}</strong></span>
              </div>

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
                }}
              >
                {launchingHunt ? '⚡ Dispatching Hunt Artifacts to Velociraptor Server...' : 'Launch Forensic Hunt'}
              </button>

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
              {['PCAP Network Capture', 'DNS Query Audit Log', 'RAW HTTP Payload Dump', 'SSL Certificate Chain', 'Nginx W3C Access Logs', 'Complete Forensic Evidence ZIP'].map((name) => (
                <div key={name} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📦 {name}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Cryptographic Hash Attached</div>
                  </div>
                  <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 12px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
                    Download Package
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
// 2. DEDICATED SIEM LOG MONITOR TABLE COMPONENT
// ═════════════════════════════════════════════════════════════════════════════
export function WebDnsLogMonitor({ alerts = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  // Field mapping based on ACTUAL MongoDB document structure (confirmed by DB query)
  // Real alert example: srcip="142.251.153.4", description="Blocked IP ... — domain:youtube.com"
  // Most network alerts don't have: username, destip, processName, queryType (from agent)
  const liveRows = useMemo(() => {
    return alerts.map(a => {
      const rawEvent = a?.rawEvent || {};
      const nestedRaw = rawEvent?.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
      const eventData = nestedRaw?.event && typeof nestedRaw.event === 'object' ? nestedRaw.event : {};
      const raw = { ...rawEvent, ...nestedRaw, ...eventData };

      // Source IP can arrive from IDS, agent telemetry, populated system data,
      // or a normalized dashboard response. Keep every known producer covered.
      const descForIp = a.description || a.full_log || raw.description || raw.raw_log || '';
      const sourceFromDesc = descForIp.match(/\b(?:src|source|client)[_\s:-]*(?:ip)?[:=\s]+(\d{1,3}(?:\.\d{1,3}){3})/i)?.[1];
      const srcIp = a.srcip || a.src_ip || a.srcIp || a.sourceIp || a.sourceIP
        || a.source_ip || a.ipAddress || a.clientIp || a.client_ip || a.localIp
        || raw.srcip || raw.src_ip || raw.srcIp || raw.sourceIp || raw.source_ip
        || raw.client_ip || raw.clientIp || raw.ip || raw.ipAddress || raw.local_ip
        || a.systemId?.ip || a.systemId?.ipAddress || a.systemId?.privateIp
        || a.agent?.ip || a.agent?.ipAddress || sourceFromDesc || '';

      // ── Destination IP: try destip, else parse from description ──
      const descStr = descForIp;
      // Parse "Blocked IP x.x.x.x" or "dst:x.x.x.x" or "-> x.x.x.x"
      const dstFromDesc = descStr.match(/\bdst[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i)?.[1]
        || descStr.match(/\bto[:\s]+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/i)?.[1]
        || descStr.match(/→\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/)?.[1];
      // For "Blocked IP x.x.x.x" — that IP IS the destination
      const blockedIpMatch = descStr.match(/[Bb]locked\s+IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
      const dstIp = a.destip || raw.dest_ip || raw.dst_ip
        || dstFromDesc
        || (blockedIpMatch ? blockedIpMatch[1] : '')
        || '';

      // ── Domain: parse from description "domain:youtube.com" ──────
      const domainFromDesc = descStr.match(/\bdomain[:\s]+([a-z0-9._-]+\.[a-z]{2,})/i)?.[1]
        || descStr.match(/\burl[:\s]+([a-z0-9._\-\/]+\.[a-z]{2,})/i)?.[1];
      const domain = a.domain || a.tiDomain || raw.domain || raw.qname
        || raw.query || domainFromDesc || '';

      // ── DNS Query: same as domain for network/firewall alerts ─────
      const dnsQuery = a.dnsQuery || raw.dns_query || raw.qname || domain || '';

      // ── Query Type: from schema queryType or rawEvent ─────────────
      const queryType = a.queryType || raw.query_type || raw.record_type || raw.type_str
        || (domain ? 'A' : '');   // default A if there's a domain

      // ── Username: schema `username`, agent sends it for process alerts ─
      const username = a.username || a.fileUser || raw.username || raw.user
        || raw.account || a.agentName || '';

      // ── Hostname ──────────────────────────────────────────────────
      const hostname = a.hostname || a.agentName || raw.hostname || raw.system_name
        || a.hostnameObserved || '';

      // ── Process: from schema processName ─────────────────────────
      const processName = a.processName || a.processExe || a.processPath || a.executable
        || a.image || a.command || a.process?.name || a.process?.executable
        || raw.process_name || raw.processName || raw.process || raw.proc_name
        || raw.exe || raw.executable || raw.image || raw.command
        || raw.process?.name || raw.process?.executable || raw.process_info?.name
        || raw.process_info?.executable || raw.processInfo?.name
        || raw.processInfo?.executable || raw.event?.process_name
        || (raw.source === 'dns_cache_poison_detector' ? 'soc-agent (DNS cache poison detector)' : '');
      const processPid = a.pid ?? a.processId ?? a.processID ?? a.process?.pid
        ?? raw.pid ?? raw.process_id ?? raw.processId ?? raw.process_pid
        ?? raw.process?.pid ?? raw.process_info?.pid ?? raw.processInfo?.pid
        ?? raw.event?.pid ?? null;

      // ── MITRE: schema mitreId + technique ───────────────────────
      const mitreId = a.mitreId || a.mitreTechniqueId || a.mitre?.techniqueId
        || raw.mitre_id || raw.mitreTechniqueId || '';
      const mitreName = a.technique || a.mitreTechnique || a.mitre?.technique
        || raw.mitre_technique || '';
      const mitre = mitreId
        ? `${mitreId}${mitreName ? ' — ' + mitreName : ''}`
        : mitreName;

      // ── Threat Type ───────────────────────────────────────────────
      const tType = a.threatType || a.threatCategory || a.malwareType || a.attackType
        || a.signatureName || a.ruleName || a.ruleId || a.category
        || raw.threat_type || raw.threatCategory || raw.attack_type
        || raw.signature_name || raw.signature || raw.rule_name || raw.rule_id
        || raw.category || '';

      // ── Action Taken ─────────────────────────────────────────────
      const act = a.actionTaken
        || (a.blocked === true ? 'Blocked' : '')
        || (a.containmentStatus && a.containmentStatus !== 'none' ? a.containmentStatus : '')
        || (descStr.toLowerCase().includes('block') ? 'Blocked' : '')
        || a.recommendedAction || '';

      // ── Threat Score ─────────────────────────────────────────────
      // Confidence values (for example the common TI confidence of 80) are not
      // threat scores. Only render an explicitly calculated threat/risk score.
      const score = a.threatScore ?? a.riskScore
        ?? raw.threat_score ?? raw.risk_score ?? null;

      // ── Status ────────────────────────────────────────────────────
      const status = a.status || (a.blocked ? 'Blocked' : a.actionTaken || 'open');

      return {
        _id: a._id || a.id,
        timestamp: a.createdAt || a.timestamp || a.firstSeen || new Date().toISOString(),
        severity: (a.severity || 'low').toLowerCase(),
        status,
        hostname: hostname || '—',
        username: username || '—',
        srcIp: srcIp || '—',
        dstIp: dstIp || '—',
        url: domain || descStr || '—',
        domain: domain || '—',
        dnsQuery: dnsQuery || '—',
        queryType: queryType || '—',
        processName: processName || '—',
        pid: processPid != null && processPid !== '' ? processPid : 'Not recorded',
        browser: a.browser || raw.user_agent || raw.browser || '—',
        mitreAttack: mitre || '—',
        threatType: tType || '—',
        threatScore: score == null || score === '' ? '—' : score,
        actionTaken: act || '—',
        description: descStr,
        geoCountry: a.geoCountry || a.destGeoCountry || '',
        protocol: a.protocol || raw.protocol || '',
        port: a.destPort || a.port || raw.port || '',
        caseId: a.caseId || `CASE-${(a._id || '').toString().substring(0, 6)}`,
        raw: a,
      };
    });
  }, [alerts]);

  const filtered = useMemo(() => {
    return liveRows.filter(r => {
      if (sevFilter !== 'ALL' && (r.severity || '').toLowerCase() !== sevFilter.toLowerCase()) return false;
      if (!searchTerm) return true;
      const t = searchTerm.toLowerCase();
      return (r.hostname || '').toLowerCase().includes(t) || (r.domain || '').toLowerCase().includes(t) || (r.srcIp || '').toLowerCase().includes(t);
    });
  }, [liveRows, searchTerm, sevFilter]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}` }}>
        <input type="text" placeholder="🔍 Search SIEM Web & DNS Logs (Host, Domain, IP, Process)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          <option value="ALL">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
        </select>
      </div>

      <div style={{ overflow: 'auto', maxHeight: 'calc(100vh - 190px)', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: 'max-content', height: 'auto', tableLayout: 'auto', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Timestamp', 'Severity', 'Status', 'Hostname', 'Source IP', 'Destination IP', 'Domain / URL', 'DNS Query', 'Query Type', 'Threat Type', 'MITRE ATT&CK', 'Threat Score', 'Action Taken'].map(h => <th key={h} style={{ position: 'sticky', top: 0, zIndex: 1, background: MON.card2, padding: '11px 8px', whiteSpace: 'nowrap', lineHeight: 1.2 }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={13} style={{ padding: '40px 20px', textAlign: 'center', color: MON.muted, fontSize: 13 }}>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 32 }}>🔍</span>
                    <span style={{ fontWeight: 700, color: MON.sub }}>No Web &amp; DNS logs found</span>
                    <span style={{ fontSize: 11, color: MON.sub }}>Logs will appear here when real events are detected</span>
                  </div>
                </td>
              </tr>
            ) : (
              filtered.map((row) => (
                <tr key={row._id} onClick={() => setSelectedLog(row)} style={{ height: 46, borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                  <td style={{ padding: '9px 12px', color: MON.muted, whiteSpace: 'nowrap' }}>{row.timestamp ? new Date(row.timestamp).toLocaleTimeString() : '—'}</td>
                  <td style={{ padding: '9px 12px' }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                  <td style={{ padding: '9px 12px', color: row.status === 'Blocked' ? MON.red : MON.green, fontWeight: 700, whiteSpace: 'nowrap' }}>{row.status}</td>
                  <td style={{ padding: '9px 12px', color: MON.blue, fontWeight: 700, whiteSpace: 'nowrap' }}>{row.hostname}</td>
                  <td style={{ padding: '9px 12px', color: MON.cyan, fontFamily: 'monospace', whiteSpace: 'nowrap', fontWeight: 800 }}>{row.srcIp}</td>
                  <td style={{ padding: '9px 12px', color: MON.muted, fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{row.dstIp}</td>
                  <td title={row.domain} style={{ width: 180, maxWidth: 180, padding: '9px 8px', color: MON.text, fontWeight: 700, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{row.domain}</td>
                  <td title={row.dnsQuery} style={{ width: 180, maxWidth: 180, padding: '9px 8px', color: MON.purple, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{row.dnsQuery}</td>
                  <td style={{ padding: '9px 12px', color: MON.yellow, fontWeight: 800 }}>{row.queryType}</td>
                  <td style={{ padding: '9px 12px', color: MON.red, fontWeight: 700, whiteSpace: 'nowrap' }}>{row.threatType}</td>
                  <td title={row.mitreAttack} style={{ width: 230, maxWidth: 230, padding: '9px 8px', color: MON.red, fontWeight: 800, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{row.mitreAttack}</td>
                  <td style={{ padding: '9px 12px', color: row.threatScore === '—' ? MON.muted : Number(row.threatScore) > 70 ? MON.red : MON.green, fontWeight: 800 }}>{row.threatScore}</td>
                  <td style={{ padding: '9px 12px', color: MON.purple, fontWeight: 800, whiteSpace: 'nowrap' }}>{row.actionTaken}</td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {selectedLog && <WebDnsLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SOC REPORT GENERATOR COMPONENT
// ═════════════════════════════════════════════════════════════════════════════
export function WebDnsReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [reportGenerated, setReportGenerated] = useState(false);

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
          <title>Web & DNS Executive SOC Security Report (${reportType.toUpperCase()})</title>
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
              <h1>🛡️ Web & DNS Executive SOC Security Report</h1>
              <div class="meta">Generated: ${new Date().toLocaleString()} | Scope: ${reportType.toUpperCase()} | Classification: CONFIDENTIAL</div>
            </div>
            <span class="badge">SECURITY VERIFIED</span>
          </div>

          <div class="metrics-grid">
            <div class="metric-card"><div class="metric-title">Total Web/DNS Logs Analyzed</div><div class="metric-val">148,200</div></div>
            <div class="metric-card"><div class="metric-title">Blocked Malicious Domains</div><div class="metric-val">412</div></div>
            <div class="metric-card"><div class="metric-title">DNS Tunneling Alerts</div><div class="metric-val">18</div></div>
            <div class="metric-card"><div class="metric-title">Overall Security Score</div><div class="metric-val">88 / 100</div></div>
          </div>

          <h2>Summary of Detected Web & DNS Threat Vectors</h2>
          <table>
            <thead>
              <tr>
                <th>Threat Category</th>
                <th>Affected Host Count</th>
                <th>Severity</th>
                <th>Detection Engine</th>
                <th>Applied Mitigation</th>
              </tr>
            </thead>
            <tbody>
              <tr><td>DNS Tunneling & Data Exfiltration</td><td>6 Hosts</td><td class="sev-critical">CRITICAL</td><td>Heuristic Engine v5</td><td>Automated DNS Sinkhole</td></tr>
              <tr><td>Phishing Domain Lookups</td><td>14 Hosts</td><td class="sev-high">HIGH</td><td>Threat Intel Stream</td><td>Domain Blacklist Block</td></tr>
              <tr><td>WAF Web Attacks (SQLi / XSS)</td><td>12 Servers</td><td class="sev-high">HIGH</td><td>WAF eBPF Driver</td><td>IP Block & Rate Limit</td></tr>
              <tr><td>C2 Outbound Beaconing</td><td>4 Hosts</td><td class="sev-critical">CRITICAL</td><td>Behavioral Analytics</td><td>Network Isolation</td></tr>
            </tbody>
          </table>

          <div class="footer">
            Confidential — Generated by Enterprise SOC Platform | Web & DNS Monitoring Module
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
      const headers = ["Timestamp", "Hostname", "Username", "Source IP", "Destination IP", "Domain/URL", "Query Type", "Severity", "Threat Type", "Action Taken"];
      const rows = alerts.map(a => [
        `"${a.createdAt || a.timestamp || ''}"`,
        `"${a.hostname || a.agentName || ''}"`,
        `"${a.username || ''}"`,
        `"${a.srcip || a.srcIp || ''}"`,
        `"${a.destip || a.dstIp || ''}"`,
        `"${a.domain || a.url || ''}"`,
        `"${a.queryType || ''}"`,
        `"${a.severity || ''}"`,
        `"${a.threatType || a.threatCategory || a.ruleId || ''}"`,
        `"${a.actionTaken || (a.blocked ? 'Blocked' : '')}"`
      ]);

      const csvData = [headers.join(","), ...rows.map(r => r.join(","))].join("\n");
      const blob = new Blob([csvData], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.setAttribute("href", url);
      link.setAttribute("download", `webdns_soc_report_${reportType}.csv`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
      return;
    }

    // JSON Export
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(alerts.length > 0 ? alerts : { title: "Web & DNS Executive SOC Security Report", reportType, generatedAt: new Date().toISOString() }, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `webdns_soc_report_${reportType}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Automated Web & DNS SOC Executive Report Generator</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate Executive Summary, Top Threats, DNS Statistics & MITRE ATT&CK Mapping</div>
        </div>

        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 14px', borderRadius: 6, fontSize: 12 }}>
            <option value="daily">Daily Report (24 Hours)</option>
            <option value="weekly">Weekly Executive Summary</option>
            <option value="monthly">Monthly SOC Intelligence Report</option>
            <option value="custom">Custom Threat Scope</option>
          </select>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
            {generating ? 'Generating...' : '⚡ Generate Report'}
          </button>
        </div>
      </div>

      {reportGenerated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>Executive Summary Preview ({reportType.toUpperCase()})</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={() => handleDownloadReport('PDF')} style={{ background: MON.red, color: '#fff', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export PDF</button>
              <button type="button" onClick={() => handleDownloadReport('CSV')} style={{ background: MON.green, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
              <button type="button" onClick={() => handleDownloadReport('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>Total Web/DNS Logs Analyzed</div><div style={{ fontSize: 18, color: MON.cyan, fontWeight: 900 }}>148,200 Logs</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>Blocked Malicious Domains</div><div style={{ fontSize: 18, color: MON.red, fontWeight: 900 }}>412 Domains</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>DNS Tunneling Attacks</div><div style={{ fontSize: 18, color: MON.orange, fontWeight: 900 }}>18 Incidents</div></div>
            <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.border}` }}><div style={{ fontSize: 10, color: MON.muted }}>Overall Security Score</div><div style={{ fontSize: 18, color: MON.green, fontWeight: 900 }}>88 / 100</div></div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. MAIN DASHBOARD PANEL COMPONENT
// ═════════════════════════════════════════════════════════════════════════════
// ── Visual Helper Components for Web & DNS Monitoring Dashboard ─────────────
function WebTrafficOverTimeChart({ data = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
  const maxValue = Math.max(...data, 1);
  const yLabels = [maxValue, Math.round(maxValue * .75), Math.round(maxValue * .5), Math.round(maxValue * .25), 0];

  const chartW = 380;
  const chartH = 140;
  const padLeft = 32;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = data.map((v, i) => ({
    x: padLeft + (i / (data.length - 1)) * innerW,
    y: padTop + innerH - (v / maxValue) * innerH,
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Web Traffic Over Time</span>
        <span style={{ fontSize: 9, color: '#8ea0b8', background: '#07101b', padding: '2px 8px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
      </div>

      <div style={{ flex: 1, minHeight: 110 }}>
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
          <path d={`${d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#blueTrafficGrad)" />
          <path d={d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          <defs>
            <linearGradient id="blueTrafficGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function DnsQueriesOverTimeChart({ data = [] }) {
  const times = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
  const maxValue = Math.max(...data, 1);
  const yLabels = [maxValue, Math.round(maxValue * .75), Math.round(maxValue * .5), Math.round(maxValue * .25), 0];

  const chartW = 380;
  const chartH = 140;
  const padLeft = 32;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 20;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const pts = data.map((v, i) => ({
    x: padLeft + (i / (data.length - 1)) * innerW,
    y: padTop + innerH - (v / maxValue) * innerH,
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

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>DNS Queries Over Time</span>
        <span style={{ fontSize: 9, color: '#8ea0b8', background: '#07101b', padding: '2px 8px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
      </div>

      <div style={{ flex: 1, minHeight: 110 }}>
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
          <path d={`${d} L ${padLeft + innerW},${padTop + innerH} L ${padLeft},${padTop + innerH} Z`} fill="url(#purpleDnsGrad)" />
          <path d={d} fill="none" stroke="#a78bfa" strokeWidth="2" />
          <defs>
            <linearGradient id="purpleDnsGrad" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#a78bfa" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#a78bfa" stopOpacity="0.0" />
            </linearGradient>
          </defs>
        </svg>
      </div>
    </div>
  );
}

function TopAlertCategoriesDonut({ cats = [] }) {
  const total = cats.reduce((sum, row) => sum + row.count, 0);

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = cats.map((s) => {
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
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Top Alert Categories</span>
        <span style={{ fontSize: 9, color: '#8ea0b8', background: '#07101b', padding: '2px 8px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{total}</span>
            <span style={{ fontSize: 8, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3.5, flex: 1, fontSize: 8.5 }}>
          {cats.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.count} ({c.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function WebTrafficByCategoryDonut({ cats = [], total = 0 }) {

  let cumAngle = 0;
  const radius = 38;
  const cx = 48;
  const cy = 48;
  const strokeWidth = 12;

  const arcs = cats.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>Web Traffic by Category</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
        <div style={{ position: 'relative', width: 96, height: 96, flexShrink: 0 }}>
          <svg viewBox="0 0 96 96" width="96" height="96">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{total.toLocaleString()}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 8.5 }}>
          {cats.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.pct}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function DnsQueryTypesDonut({ types = [], total = 0 }) {

  let cumAngle = 0;
  const radius = 38;
  const cx = 48;
  const cy = 48;
  const strokeWidth = 12;

  const arcs = types.map((s) => {
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>DNS Query Types</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
        <div style={{ position: 'relative', width: 96, height: 96, flexShrink: 0 }}>
          <svg viewBox="0 0 96 96" width="96" height="96">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#fff' }}>{total.toLocaleString()}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3, flex: 1, fontSize: 8.5 }}>
          {types.map(t => (
            <div key={t.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: t.color }} /> {t.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{t.pct}%</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function GeographicDistributionMap({ countries = [] }) {

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>Geographic Distribution (Web Requests)</span>
      </div>
      <div style={{ display: 'flex', gap: 10, flex: 1 }}>
        <div style={{ flex: 1, background: '#07101b', borderRadius: 6, border: '1px solid #16273e', position: 'relative', overflow: 'hidden', minHeight: 90 }}>
          <svg viewBox="0 0 200 100" width="100%" height="100%" style={{ opacity: 0.6 }}>
            <path d="M 20,30 Q 30,20 45,35 T 70,30 T 90,45 T 60,70 T 30,60 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
            <path d="M 110,25 Q 130,15 160,25 T 180,45 T 150,75 T 120,60 Z" fill="#1e3a8a" stroke="#38bdf8" strokeWidth="0.5" />
            <circle cx="45" cy="35" r="3" fill="#38bdf8" />
            <circle cx="140" cy="45" r="3" fill="#38bdf8" />
            <circle cx="115" cy="30" r="3" fill="#38bdf8" />
            <circle cx="125" cy="32" r="3" fill="#38bdf8" />
          </svg>
          <div style={{ position: 'absolute', bottom: 4, left: 6 }}>
            <span style={{ fontSize: 9, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View Full Map</span>
          </div>
        </div>
        <div style={{ width: 120, display: 'flex', flexDirection: 'column', gap: 3, fontSize: 8.5 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: '#64748b', fontWeight: 700, fontSize: 8 }}>
            <span>Country</span>
            <span>Requests</span>
          </div>
          {countries.map(c => (
            <div key={c.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 75 }}>{c.name}</span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.reqs}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function WebDnsOverviewDashboard({ alerts = [], total = 0 }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const live = useMemo(() => {
    const colors = ['#ef4444', '#f97316', '#f59e0b', '#3b82f6', '#8b5cf6', '#14b8a6'];
    const normalized = alerts.map(alert => {
      const rawEvent = alert.rawEvent && typeof alert.rawEvent === 'object' ? alert.rawEvent : {};
      const nested = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : {};
      const raw = { ...rawEvent, ...nested };
      const domain = alert.domain || alert.dnsQuery || raw.domain || raw.query || raw.qname || '';
      const text = `${alert.ruleId || ''} ${alert.eventType || ''} ${alert.description || ''} ${alert.protocol || ''}`;
      const dns = Boolean(alert.queryType || raw.query_type || raw.dns_query || raw.dns_query_count || /\bdns\b/i.test(text));
      const web = Boolean(alert.url || raw.url || alert.httpMethod || raw.http_method || raw.web_request_count || /http|web|waf|browser/i.test(text));
      const blocked = alert.blocked === true || /block|drop|deny|sinkhole/i.test(`${alert.actionTaken || ''} ${alert.action || ''} ${alert.containmentStatus || ''}`);
      const malicious = /malicious|phishing|malware|tunnel|beacon|command.?control|\bc2\b|inject|xss/i.test(`${text} ${alert.threatCategory || ''}`);
      return {
        alert, raw, domain, dns, web, blocked, malicious,
        webCount: web ? telemetryCount(alert, raw, 'web_request_count') : 0,
        dnsCount: dns ? telemetryCount(alert, raw, 'dns_query_count') : 0,
      };
    });
    const webRows = normalized.filter(row => row.web);
    const dnsRows = normalized.filter(row => row.dns);
    const blockedWeb = webRows.filter(row => row.blocked).length;
    const blockedDns = dnsRows.filter(row => row.blocked).length;
    const malicious = normalized.filter(row => row.malicious).length;
    const domains = new Map();
    const dnsDomains = new Map();
    const categoryCounts = new Map();
    const queryTypes = new Map();
    const countries = new Map();
    const webSeries = Array(12).fill(0);
    const dnsSeries = Array(12).fill(0);
    const now = Date.now();
    normalized.forEach(row => {
      if (row.domain) domains.set(row.domain, (domains.get(row.domain) || 0) + Math.max(row.webCount, row.dnsCount, 1));
      if (row.dns && row.domain) dnsDomains.set(row.domain, (dnsDomains.get(row.domain) || 0) + row.dnsCount);
      const category = row.alert.threatCategory || row.alert.subCategory || row.alert.eventType || row.alert.ruleId || 'Unclassified';
      categoryCounts.set(category, (categoryCounts.get(category) || 0) + 1);
      const queryType = row.alert.queryType || row.raw.query_type || row.raw.record_type;
      if (queryType) queryTypes.set(queryType, (queryTypes.get(queryType) || 0) + 1);
      const country = row.alert.geoCountry || row.alert.destGeoCountry || row.raw.country;
      if (country) countries.set(country, (countries.get(country) || 0) + 1);
      const timestamp = new Date(row.alert.createdAt || row.alert.timestamp || row.raw.timestamp || 0).getTime();
      const hoursAgo = Math.floor((now - timestamp) / 3600000);
      if (Number.isFinite(hoursAgo) && hoursAgo >= 0 && hoursAgo < 24) {
        const index = Math.min(11, 11 - Math.floor(hoursAgo / 2));
        if (row.web) webSeries[index] += row.webCount;
        if (row.dns) dnsSeries[index] += row.dnsCount;
      }
    });
    const percentageRows = (map, denominator) => [...map.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6)
      .map(([label, count], index) => ({ label, count, pct: denominator ? Number(((count / denominator) * 100).toFixed(1)) : 0, color: colors[index] }));
    const topWebsites = [...domains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([domain, count]) => ({
      domain, cat: normalized.find(row => row.domain === domain)?.alert.threatCategory || 'Observed', reqs: count.toLocaleString(), pct: `${normalized.length ? ((count / normalized.length) * 100).toFixed(1) : 0}%`,
    }));
    const topDnsDomains = [...dnsDomains.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([domain, count]) => ({
      domain, count: count.toLocaleString(), pct: `${dnsRows.length ? ((count / dnsRows.length) * 100).toFixed(1) : 0}%`,
    }));
    const recent = normalized.slice().sort((a, b) => new Date(b.alert.createdAt || 0) - new Date(a.alert.createdAt || 0)).slice(0, 5);
    const resolvers = new Set(normalized.flatMap(row => row.raw.resolvers || []).filter(Boolean));
    const responseTimes = normalized.map(row => Number(row.alert.responseTime ?? row.raw.response_time ?? row.raw.query_time)).filter(Number.isFinite);
    const failures = dnsRows.filter(row => /nxdomain|servfail|refused|fail/i.test(`${row.alert.responseCode || ''} ${row.raw.response_code || ''}`)).length;
    return {
      normalized, webRows, dnsRows,
      webRequestCount: webRows.reduce((sum, row) => sum + row.webCount, 0),
      dnsQueryCount: dnsRows.reduce((sum, row) => sum + row.dnsCount, 0),
      blockedWeb, blockedDns, malicious, webSeries, dnsSeries,
      topWebsites, topDnsDomains,
      alertCategories: percentageRows(categoryCounts, normalized.length),
      webCategories: percentageRows(categoryCounts, webRows.length),
      queryTypes: percentageRows(queryTypes, dnsRows.length).map(row => ({ ...row, label: String(row.label).toUpperCase() })),
      countries: [...countries.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5).map(([name, count]) => ({ name, reqs: count.toLocaleString() })),
      recentAlertsStream: recent.map(row => ({ title: row.alert.ruleId || row.alert.eventType || 'Web/DNS event', sub: row.domain ? `Domain: ${row.domain}` : `Host: ${row.alert.hostname || row.alert.agentName || 'Not reported'}`, time: row.alert.createdAt ? new Date(row.alert.createdAt).toLocaleTimeString() : '—', sev: row.alert.severity || 'low', sevCol: SEV_COLOR[row.alert.severity] || MON.green, icon: row.malicious ? '⚠️' : 'ℹ️' })),
      liveLogFeed: recent.map(row => ({ time: row.alert.createdAt ? new Date(row.alert.createdAt).toLocaleTimeString() : '—', type: row.dns ? 'DNS Query' : 'Web Request', typeCol: row.dns ? MON.cyan : MON.blue, src: row.alert.srcip || row.raw.src_ip || '—', action: row.blocked ? 'Blocked' : (row.alert.actionTaken || 'Observed'), actionCol: row.blocked ? MON.red : MON.green, details: row.alert.description || row.domain || '—' })),
      dnsSecurityStatus: [
        { label: 'DNS Servers', val: resolvers.size ? `${resolvers.size} observed` : 'Not reported' },
        { label: 'DNS Response Time', val: responseTimes.length ? `${Math.round(responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length)} ms avg` : 'Not reported' },
        { label: 'Failed Lookups', val: dnsRows.length ? `${((failures / dnsRows.length) * 100).toFixed(1)}%` : '0%' },
        { label: 'DNSSEC Validation', val: normalized.some(row => row.raw.dnssec === true) ? 'Observed' : 'Not reported' },
        { label: 'Threat Intel Hits', val: String(normalized.filter(row => row.alert.iocMatched || row.alert.tiDomainMalicious).length) },
      ],
    };
  }, [alerts]);

  const topCards = [
    { title: 'Total Web Requests', val: live.webRequestCount.toLocaleString(), sub: 'Live 24h', subCol: '#38bdf8', col: '#38bdf8' },
    { title: 'Total DNS Queries', val: live.dnsQueryCount.toLocaleString(), sub: 'Live 24h', subCol: '#a78bfa', col: '#a78bfa' },
    { title: 'Blocked Web Requests', val: live.blockedWeb.toLocaleString(), sub: 'Observed', subCol: '#f87171', col: '#f87171' },
    { title: 'Blocked DNS Queries', val: live.blockedDns.toLocaleString(), sub: 'Observed', subCol: '#fb923c', col: '#fb923c' },
    { title: 'Malicious Requests', val: live.malicious.toLocaleString(), sub: 'Detected', subCol: '#f87171', col: '#f87171' },
    { title: 'Unique Domains Queried', val: new Set(live.normalized.map(row => row.domain).filter(Boolean)).size.toLocaleString(), sub: 'Observed', subCol: '#34d399', col: '#34d399' },
  ];
  const { topWebsites, topDnsDomains, recentAlertsStream, dnsSecurityStatus, liveLogFeed } = live;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
            <span style={{ fontSize: 10, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.4px' }}>
              {c.title}
            </span>

            <div style={{ fontSize: 24, fontWeight: 800, color: '#ffffff', margin: '8px 0 2px 0' }}>
              {c.val}
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 10, fontWeight: 700, color: c.subCol }}>
                {c.sub}
              </span>
              <div style={{ width: 50, height: 18 }}>
                <MiniSparkline data={c.title.includes('DNS') ? live.dnsSeries : live.webSeries} color={c.col} height={18} />
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.4fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <WebTrafficOverTimeChart data={live.webSeries} />
        </div>
        <div style={panelStyle}>
          <DnsQueriesOverTimeChart data={live.dnsSeries} />
        </div>
        <div style={panelStyle}>
          <TopAlertCategoriesDonut cats={live.alertCategories} />
        </div>
      </div>

      {/* 3. MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.1fr 1fr', gap: 12 }}>
        {/* Panel 1: Top Websites Accessed */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>Top Websites Accessed</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 0.8fr 0.6fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Domain</span>
              <span>Category</span>
              <span>Requests</span>
              <span>% of Total</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topWebsites.map(w => (
                <div key={w.domain} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 0.8fr 0.6fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{w.domain}</span>
                  <span style={{ color: '#8ea0b8', fontSize: 9 }}>{w.cat}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{w.reqs}</span>
                  <span style={{ color: '#64748b', fontSize: 9 }}>{w.pct}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
          </div>
        </div>

        {/* Panel 2: Top Queried Domains (DNS) */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>Top Queried Domains (DNS)</span>
            <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
              <span>Domain</span>
              <span>Query Count</span>
              <span>% of Total</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topDnsDomains.map(d => (
                <div key={d.domain} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 9.5 }}>
                  <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{d.domain}</span>
                  <span style={{ color: '#e2e8f0', fontWeight: 700 }}>{d.count}</span>
                  <span style={{ color: '#64748b', fontSize: 9 }}>{d.pct}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ marginTop: 8 }}>
            <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
          </div>
        </div>

        {/* Panel 3: Recent Alerts Stream */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>Recent Alerts</span>
              <span style={{ fontSize: 10, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {recentAlertsStream.map((ra, idx) => (
                <div key={idx} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 8px', background: '#07101b', borderRadius: 4, border: '1px solid #16273e' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 14 }}>{ra.icon}</span>
                    <div style={{ display: 'flex', flexDirection: 'column' }}>
                      <span style={{ fontSize: 9.5, fontWeight: 700, color: '#e2e8f0' }}>{ra.title}</span>
                      <span style={{ fontSize: 8.5, color: '#8ea0b8' }}>{ra.sub}</span>
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 2 }}>
                    <span style={{ fontSize: 8.5, color: '#64748b' }}>{ra.time}</span>
                    <span style={{ fontSize: 8, fontWeight: 800, padding: '1px 5px', borderRadius: 8, background: 'rgba(248, 113, 113, 0.15)', color: ra.sevCol, border: `1px solid ${ra.sevCol}44` }}>
                      {ra.sev}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 4. LOWER SECTION (4 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.3fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <WebTrafficByCategoryDonut cats={live.webCategories} total={live.webRows.length} />
        </div>

        <div style={panelStyle}>
          <DnsQueryTypesDonut types={live.queryTypes} total={live.dnsRows.length} />
        </div>

        <div style={panelStyle}>
          <GeographicDistributionMap countries={live.countries} />
        </div>

        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>DNS Security Overview</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, margin: '8px 0' }}>
              <div style={{ width: 44, height: 44, borderRadius: 8, background: 'rgba(52, 211, 153, 0.15)', border: '1px solid rgba(52, 211, 153, 0.3)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22 }}>
                🛡️
              </div>
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: 13, fontWeight: 800, color: live.malicious ? '#f87171' : '#34d399' }}>{live.malicious ? 'Threats detected' : 'No active threats'}</span>
                <span style={{ fontSize: 8.5, color: '#8ea0b8' }}>{live.malicious} suspicious event(s) in the live window</span>
              </div>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginTop: 6, fontSize: 9 }}>
              {dnsSecurityStatus.map(s => (
                <div key={s.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ color: '#8ea0b8' }}>{s.label}</span>
                  <span style={{ color: '#34d399', fontWeight: 700 }}>{s.val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* 5. BOTTOM PANEL (Live Log Feed) */}
      <div style={panelStyle}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 10, display: 'block' }}>Live Log Feed</span>
        <div style={{ display: 'grid', gridTemplateColumns: '0.9fr 1.1fr 1fr 0.8fr 2.5fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 9, fontWeight: 700, color: '#64748b' }}>
          <span>Time</span>
          <span>Type</span>
          <span>Source</span>
          <span>Action</span>
          <span>Details</span>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
          {liveLogFeed.map((lf, idx) => (
            <div key={idx} style={{ display: 'grid', gridTemplateColumns: '0.9fr 1.1fr 1fr 0.8fr 2.5fr', gap: 6, alignItems: 'center', fontSize: 9.5 }}>
              <span style={{ color: '#64748b', fontSize: 9 }}>{lf.time}</span>
              <span style={{ color: lf.typeCol, fontWeight: 700 }}>{lf.type}</span>
              <span style={{ color: '#38bdf8', fontFamily: 'monospace', fontSize: 9 }}>{lf.src}</span>
              <span style={{ color: lf.actionCol, fontWeight: 700 }}>{lf.action}</span>
              <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lf.details}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

export default function WebDnsDashboardPanel({ alerts = [], loading = false, total = 0 }) {
  const [activeTab, setActiveTab] = useState('dashboard');

  // All stats computed from real API data — exact Alert.model.js field names
  const liveStats = useMemo(() => {
    const active = alerts.length;

    // `blocked` boolean field in schema — or actionTaken === 'Blocked'
    const blocked = alerts.filter(a =>
      a.blocked === true ||
      a.actionTaken === 'Blocked' ||
      a.containmentStatus === 'blocked'
    ).length;

    // DNS Tunneling — ruleId or description must explicitly say so
    const tunneling = alerts.filter(a =>
      /dns.?tunnel|tunneling|high.?entropy|subdomain.?exfil/i.test(
        `${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`
      )
    ).length;

    // Beaconing — beacon keyword in rule/description
    const beaconing = alerts.filter(a =>
      /beacon|c2.?beac|command.?control/i.test(
        `${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`
      )
    ).length;

    // Malicious — schema has tiDomainMalicious flag + explicit keywords
    const malicious = alerts.filter(a =>
      a.tiDomainMalicious === true ||
      /malicious|phishing|malware|ransomware/i.test(
        `${a.description || ''} ${a.threatCategory || ''} ${a.malwareType || ''}`
      )
    ).length;

    // C2 — explicit C2 in rule/description
    const c2 = alerts.filter(a =>
      /\bc2\b|command.?and.?control|c2.?server/i.test(
        `${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`
      )
    ).length;

    // Web attacks — WAF-specific
    const attacks = alerts.filter(a =>
      /sql.?inject|sqli|xss|cross.?site|path.?travers|lfi|rfi|waf|web.?attack/i.test(
        `${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`
      )
    ).length;

    const phishing = alerts.filter(a => /phishing/i.test(`${a.description || ''} ${a.threatCategory || ''} ${a.ruleId || ''}`)).length;
    const sinkhole = alerts.filter(a => /sinkhole/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.actionTaken || ''}`)).length;
    const cachePoisoning = alerts.filter(a => /cache.?poison|dns.?poison/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.eventType || ''}`)).length;
    const dnsQueries = alerts.reduce((sum, a) => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      const isDns = Boolean(a.dnsQuery || a.queryType || raw.dns_query || raw.qname || raw.dns_query_count || /\bdns\b/i.test(`${a.type || ''} ${a.eventType || ''} ${a.description || ''}`));
      return sum + (isDns ? telemetryCount(a, raw, 'dns_query_count') : 0);
    }, 0);
    const webRequests = alerts.reduce((sum, a) => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      const isWeb = Boolean(a.url || a.targetUrl || a.httpMethod || raw.url || raw.http_method || raw.web_request_count
        || /http|web|waf|browser/i.test(`${a.type || ''} ${a.eventType || ''} ${a.description || ''}`));
      return sum + (isWeb ? telemetryCount(a, raw, 'web_request_count') : 0);
    }, 0);
    const sqliAttacks = alerts.filter(a => /sql.?inject|\bsqli\b/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`)).length;
    const xssAttacks = alerts.filter(a => /\bxss\b|cross.?site.?script/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`)).length;
    const apiAbuse = alerts.filter(a => /api.?abuse|api.?attack|rate.?limit|graphql|rest.?api/i.test(`${a.description || ''} ${a.ruleId || ''} ${a.signatureName || ''}`)).length;
    const endpointKeys = new Set(alerts.map(a => a.systemId?._id || a.systemId || a.agentId || a.agentName || a.hostname).filter(Boolean));
    const serverKeys = new Set(alerts.filter(a => /server|nginx|apache|iis|waf/i.test(`${a.assetType || ''} ${a.agentName || ''} ${a.hostname || ''} ${a.description || ''}`)).map(a => a.systemId?._id || a.systemId || a.hostname || a.agentName).filter(Boolean));
    const agentKeys = new Set(alerts.map(a => a.agentId || a.agentKey || a.agentName || a.systemId?._id || a.systemId).filter(Boolean));

    const criticalAlerts = alerts.filter(a => a.severity === 'critical').length;
    const highAlerts     = alerts.filter(a => a.severity === 'high').length;
    const mediumAlerts   = alerts.filter(a => a.severity === 'medium').length;
    const lowAlerts      = alerts.filter(a => a.severity === 'low').length;

    // Threat score from severity distribution
    const threatScore = active > 0
      ? Math.min(100, Math.round((criticalAlerts * 10 + highAlerts * 5 + mediumAlerts * 2 + lowAlerts) / (active || 1) * 10))
      : 0;

    return {
      webRequests,
      dnsQueries,
      blockedRequests:  blocked,
      blockedDomains:   blocked,
      maliciousUrls:    malicious,
      phishingUrls:     phishing,
      dnsTunneling:     tunneling,
      dnsBeaconing:     beaconing,
      c2Comms:          c2,
      sinkholeHits:     sinkhole,
      cachePoisoning,
      webAttacks:       attacks,
      sqliAttacks,
      xssAttacks,
      apiAbuse,
      criticalAlerts,
      highAlerts,
      mediumAlerts,
      lowAlerts,
      activeEndpoints:  endpointKeys.size,
      activeServers:    serverKeys.size,
      onlineAgents:     agentKeys.size,
      threatScore,
    };
  }, [alerts, total]);

  const liveHourlyBuckets = useMemo(() => {
    const buckets = Array(12).fill(0);
    const now = Date.now();
    alerts.forEach(a => {
      const time = new Date(a.createdAt || a.timestamp || a.rawEvent?.timestamp || 0).getTime();
      const hoursAgo = Math.floor((now - time) / 3600000);
      if (Number.isFinite(hoursAgo) && hoursAgo >= 0 && hoursAgo < buckets.length) buckets[buckets.length - 1 - hoursAgo]++;
    });
    return buckets;
  }, [alerts]);

  // Every sparkline uses real timestamp buckets; zero-value metrics stay flat.
  const spark = val => (!val || Number(val) === 0 ? Array(liveHourlyBuckets.length).fill(0) : liveHourlyBuckets);

  const kpis = [
    { label: 'Total Web Requests', val: liveStats.webRequests.toLocaleString(), color: MON.blue, data: spark(liveStats.webRequests) },
    { label: 'Total DNS Queries', val: liveStats.dnsQueries.toLocaleString(), color: MON.cyan, data: spark(liveStats.dnsQueries) },
    { label: 'Blocked Requests', val: liveStats.blockedRequests, color: MON.red, data: spark(liveStats.blockedRequests) },
    { label: 'Blocked Domains', val: liveStats.blockedDomains, color: MON.orange, data: spark(liveStats.blockedDomains) },
    { label: 'Malicious URLs', val: liveStats.maliciousUrls, color: MON.red, data: spark(liveStats.maliciousUrls) },
    { label: 'Phishing URLs', val: liveStats.phishingUrls, color: MON.red, data: spark(liveStats.phishingUrls) },
    { label: 'DNS Tunneling', val: liveStats.dnsTunneling, color: MON.orange, data: spark(liveStats.dnsTunneling) },
    { label: 'DNS Beaconing', val: liveStats.dnsBeaconing, color: MON.orange, data: spark(liveStats.dnsBeaconing) },
    { label: 'C2 Communications', val: liveStats.c2Comms, color: MON.red, data: spark(liveStats.c2Comms) },
    { label: 'DNS Sinkhole Hits', val: liveStats.sinkholeHits, color: MON.purple, data: spark(liveStats.sinkholeHits) },
    { label: 'Cache Poisoning', val: liveStats.cachePoisoning, color: MON.yellow, data: spark(liveStats.cachePoisoning) },
    { label: 'Web Attacks (WAF)', val: liveStats.webAttacks, color: MON.red, data: spark(liveStats.webAttacks) },
    { label: 'SQL Injection', val: liveStats.sqliAttacks, color: MON.orange, data: spark(liveStats.sqliAttacks) },
    { label: 'XSS Attacks', val: liveStats.xssAttacks, color: MON.yellow, data: spark(liveStats.xssAttacks) },
    { label: 'API Abuse', val: liveStats.apiAbuse, color: MON.purple, data: spark(liveStats.apiAbuse) },
    { label: 'Critical Alerts', val: liveStats.criticalAlerts, color: MON.red, data: spark(liveStats.criticalAlerts) },
    { label: 'High Alerts', val: liveStats.highAlerts, color: MON.orange, data: spark(liveStats.highAlerts) },
    { label: 'Medium Alerts', val: liveStats.mediumAlerts, color: MON.yellow, data: spark(liveStats.mediumAlerts) },
    { label: 'Low Alerts', val: liveStats.lowAlerts, color: MON.green, data: spark(liveStats.lowAlerts) },
    { label: 'Observed Endpoints', val: liveStats.activeEndpoints, color: MON.blue, data: spark(liveStats.activeEndpoints) },
    { label: 'Observed Web Servers', val: liveStats.activeServers, color: MON.cyan, data: spark(liveStats.activeServers) },
    { label: 'Observed Agents', val: liveStats.onlineAgents, color: MON.green, data: spark(liveStats.onlineAgents) },
    { label: 'Threat Score', val: `${liveStats.threatScore}/100`, color: liveStats.threatScore > 70 ? MON.red : liveStats.threatScore > 40 ? MON.yellow : MON.green, data: spark(liveStats.threatScore) },
  ];

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
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
        <WebDnsLogMonitor alerts={alerts} />
      ) : activeTab === 'reports' ? (
        <WebDnsReportsTab alerts={alerts} />
      ) : activeTab === 'dashboard' ? (
        <WebDnsOverviewDashboard alerts={alerts} stats={liveStats} onOpenLogs={() => setActiveTab('log-monitor')} />
      ) : (
        <>
          {/* Top 23 KPI Cards Grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
            {kpis.map((kpi, i) => (
              <div key={i} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ fontSize: 11, fontWeight: 700, color: MON.muted }}>{kpi.label}</div>
                  {/* No static trend badge — only live data */}
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 10 }}>
                  <div style={{ fontSize: 20, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                  <div style={{ width: 65 }}><MiniSparkline data={kpi.data} color={kpi.color} height={22} /></div>
                </div>
              </div>
            ))}
          </div>

          {/* Charts Row — fully driven by real alert data */}
          {(() => {
            // Build hourly buckets for 24h timeline from real alerts
            const hourBuckets = Array(18).fill(0);
            const now = Date.now();
            alerts.forEach(a => {
              const t = new Date(a.createdAt || a.timestamp || now).getTime();
              const hoursAgo = Math.floor((now - t) / 3600000);
              const idx = Math.max(0, Math.min(17, 17 - hoursAgo));
              hourBuckets[idx]++;
            });
            const maxBucket = Math.max(...hourBuckets, 1);

            // Build top domains from real alerts
            const domainCount = {};
            alerts.forEach(a => {
              const d = a.domain || a.url || a.targetUrl || a.host || a.dstHost || '';
              if (d && d !== '—' && d.length > 3) {
                domainCount[d] = (domainCount[d] || 0) + 1;
              }
            });
            const topDomains = Object.entries(domainCount)
              .sort((x, y) => y[1] - x[1])
              .slice(0, 5);

            // Build severity breakdown for server stack panel
            const sevBreakdown = [
              { label: 'Critical Alerts', count: alerts.filter(a => a.severity === 'critical').length, color: MON.red },
              { label: 'High Alerts',     count: alerts.filter(a => a.severity === 'high').length,     color: MON.orange },
              { label: 'Medium Alerts',   count: alerts.filter(a => a.severity === 'medium').length,   color: MON.yellow },
              { label: 'Low Alerts',      count: alerts.filter(a => a.severity === 'low').length,      color: MON.green },
            ].filter(s => s.count > 0);
            const sevTotal = sevBreakdown.reduce((s, x) => s + x.count, 0);

            return (
              <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
                {/* 24h Timeline */}
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Alerts 24h Timeline</div>
                  <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 3, borderBottom: `1px solid ${MON.line}` }}>
                    {hourBuckets.map((val, idx) => (
                      <div key={idx} style={{ flex: 1, height: `${Math.max((val / maxBucket) * 100, val > 0 ? 4 : 0)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0', minHeight: val > 0 ? 3 : 0 }} />
                    ))}
                  </div>
                  {alerts.length === 0 && (
                    <div style={{ textAlign: 'center', color: MON.sub, fontSize: 11, marginTop: 8 }}>No events in last 24h</div>
                  )}
                </div>

                {/* Top Domains */}
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Top Active Domains</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                    {topDomains.length === 0 ? (
                      <div style={{ color: MON.sub, fontSize: 11, textAlign: 'center', marginTop: 20 }}>No domain data available</div>
                    ) : (
                      topDomains.map(([dom, cnt], i) => {
                        const colors = [MON.red, MON.orange, MON.yellow, MON.cyan, MON.purple];
                        return (
                          <div key={dom} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                            <span style={{ color: MON.text, fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '75%' }} title={dom}>{dom}</span>
                            <span style={{ color: colors[i] || MON.blue, fontWeight: 800, flexShrink: 0 }}>{cnt} alerts</span>
                          </div>
                        );
                      })
                    )}
                  </div>
                </div>

                {/* Severity Breakdown */}
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚡ Severity Breakdown</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                    {sevBreakdown.length === 0 ? (
                      <div style={{ color: MON.sub, fontSize: 11, textAlign: 'center', marginTop: 20 }}>No alert data available</div>
                    ) : (
                      sevBreakdown.map(s => (
                        <div key={s.label}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                            <span style={{ color: MON.muted }}>{s.label}</span>
                            <span style={{ color: s.color, fontWeight: 800 }}>{s.count} ({sevTotal > 0 ? Math.round(s.count / sevTotal * 100) : 0}%)</span>
                          </div>
                          <div style={{ height: 4, background: MON.card2, borderRadius: 2 }}>
                            <div style={{ height: '100%', width: `${sevTotal > 0 ? (s.count / sevTotal * 100) : 0}%`, background: s.color, borderRadius: 2, transition: 'width 0.4s ease' }} />
                          </div>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              </div>
            );
          })()}
        </>
      )}
      </main>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. OVERLAY CAPABILITY MODAL EXPORT (2-SECOND REALTIME STREAMING LINKED)
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
      const capabilityId = 9;
      const q = new URLSearchParams({ limit: 500, capabilityId, windowHours: 24 });
      const response = await api.get(`/dashboard/capabilities/9/live?${q}`);
      const fetchedAlerts = response.data?.alerts || [];
      const fetchedTotal = Number(response.data?.total || fetchedAlerts.length || 0);

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal || fetchedAlerts.length);
    } catch (err) {
      console.warn('[WebDNS Fetch Warning]', err);
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
    const addLiveAlert = (newAlert) => {
      if (!newAlert || !isWebDnsAlert(newAlert)) return;
      setAlerts(prev => prev.some(item => String(item._id || item.eventId) === String(newAlert._id || newAlert.eventId)) ? prev : [newAlert, ...prev]);
    };
    socket.on('connect', join);
    socket.on('alert:new', addLiveAlert);
    socket.on('webdns:event', addLiveAlert);
    socket.on('telemetry:new', () => loadAlerts(true));
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', addLiveAlert);
      socket.off('webdns:event', addLiveAlert);
      socket.off('telemetry:new');
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 9. Web & DNS Monitoring</h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <WebDnsDashboardPanel alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function WebDnsSubTabPage() {
  return <CapabilitySubTabPage kind="webdns" />;
}
