/**
 * Network Activity Monitoring — Capability ID: 3
 *
 * 100% Self-Contained Enterprise SOC Network Activity Monitoring Module
 * Linked to Live Backend API (`/api/dashboard/alerts/network?capabilityId=3`), MongoDB Alert Query, and Socket.io Real-Time Streaming
 * Architecture & Design System mirror Process Activity Monitoring (Capability ID: 1) & File Activity Monitoring (Capability ID: 2)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import NetworkConnectionMap from '../../components/NetworkConnectionMap';
import useLiveNetworkMap from '../../hooks/useLiveNetworkMap';


// ── Design System Tokens (Mirroring Capability #1 Process Activity & #2 FIM) ──
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
  elevated: MON.orange,
  medium: MON.yellow,
  low: MON.green,
  info: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  elevated: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
};

const NETWORK_SUMMARY_RULES = new Set([
  'NET_CONNECTION_SUMMARY',
  'NET_DNS_SUMMARY',
  'NET_EXPOSURE_SUMMARY',
  'NET_THREAT_INTEL_SUMMARY',
  'WAF_AGENT_STATUS',
  'IDS_TELEMETRY',
  'NETWORK_TELEMETRY',
  'SURICATA_2200003',
  'SURICATA_2210045',
  'SURICATA_2210046',
  'ZEEK_truncated_tcp_payload',
]);

export function isNetworkLogRow(row) {
  if (NETWORK_SUMMARY_RULES.has(row?.ruleId)) return false;
  return !(String(row?.source || '').toLowerCase() === 'zeek'
    && row?.ruleId === 'ZEEK_weird'
    && /^truncated_tcp_payload$/i.test(String(row?.signatureName || '')));
}

export function mergeNetworkLogRows(connections = [], alerts = []) {
  const attributionRows = alerts
    .filter(row => row?.ruleId === 'PROC_DNS_ATTRIBUTED')
    .map(row => ({ ...row, destinationIps: [...netDestinationIps(row)] }));
  const attributedById = new Map(attributionRows.map(row => [String(row?._id || row?.eventId || ''), row]));
  const dnsAttributionKeys = new Map();
  const processAttributionKeys = new Map();
  const identity = row => [
    String(row?.agentId || alertHost(row)).toLowerCase(),
    String(netProcess(row)).toLowerCase(), String(netPid(row) || ''),
    String(netDstPort(row) || ''),
  ].join('|');
  attributionRows.forEach(row => {
    const rowId = String(row?._id || row?.eventId || '');
    const processKey = identity(row);
    const candidates = processAttributionKeys.get(processKey) || [];
    candidates.push(rowId);
    processAttributionKeys.set(processKey, candidates);
    const ips = Array.isArray(row.destinationIps) && row.destinationIps.length
      ? row.destinationIps
      : [netDstIp(row)];
    ips.filter(Boolean).forEach(ip => dnsAttributionKeys.set(`${processKey}|${String(ip)}`, rowId));
  });
  const unmatchedConnections = connections.filter(row => {
    const processKey = identity(row);
    let matchId = dnsAttributionKeys.get(`${processKey}|${String(netDstIp(row))}`);
    // A socket snapshot may not carry its DNS name after a CDN rotates to a
    // sibling address. Correlate only outbound, domain-empty rows from the
    // same endpoint/process/PID/service and a nearby attribution event.
    if (!matchId && !netDnsQuery(row) && String(row?.direction || '').toLowerCase() === 'outbound') {
      const observed = new Date(alertTime(row) || 0).getTime();
      matchId = (processAttributionKeys.get(processKey) || [])
        .map(id => ({ id, delta: Math.abs(observed - new Date(alertTime(attributedById.get(id)) || 0).getTime()) }))
        .filter(item => Number.isFinite(item.delta) && item.delta <= 15 * 60 * 1000)
        .sort((a, b) => a.delta - b.delta)[0]?.id;
    }
    if (!matchId) return true;
    const attribution = attributedById.get(matchId);
    const destinationIp = netDstIp(row);
    if (attribution && destinationIp && !attribution.destinationIps.includes(destinationIp)) {
      attribution.destinationIps.push(destinationIp);
    }
    return false;
  });
  const mergedAlerts = alerts.map(row => (
    row?.ruleId === 'PROC_DNS_ATTRIBUTED'
      ? attributedById.get(String(row?._id || row?.eventId || '')) || row
      : row
  ));
  return [...unmatchedConnections, ...mergedAlerts].filter(isNetworkLogRow);
}

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

function formatBytes(bytes = 0) {
  const b = Number(bytes) || 0;
  if (b >= 1073741824) return `${(b / 1073741824).toFixed(2)} GB`;
  if (b >= 1048576) return `${(b / 1048576).toFixed(1)} MB`;
  if (b >= 1024) return `${(b / 1024).toFixed(0)} KB`;
  return `${b} B`;
}

function normHost(h) {
  return String(h || 'unknown').trim().toLowerCase();
}

function alertTime(row) {
  return row?.observedAt || row?.timestamp || row?.createdAt || row?.time || row?.updatedAt
    || row?.correlatedConnection?.observedAt;
}

function alertHost(row) {
  const endpoint = row?.liveContext?.endpoint || {};
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name
    || row?.correlatedConnection?.hostname || endpoint.hostname || endpoint.name || 'unknown';
}

function alertUser(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.user || row?.username || row?.userName || row?.account || row?.correlatedConnection?.username
    || raw.username || raw.user || 'Not reported';
}

function alertStatus(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.status || row?.connectionState || row?.processStatus || row?.state
    || row?.correlatedConnection?.state || raw.connection_state || raw.state || 'unknown';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'elevated', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const endpoint = row?.liveContext?.endpoint || {};
  const osStr = String(row?.osType || row?.os || row?.platform || row?.systemId?.osType || row?.systemId?.os
    || row?.correlatedConnection?.osType || endpoint.osType || endpoint.os || endpoint.platform || row?.system || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  if (osStr.includes('android')) return 'Android';
  return 'Unknown';
}

// ── Network Specific Telemetry Field Extractors ─────────────────────────────
function netSrcIp(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.srcip || row?.src_ip || row?.sourceIp || row?.localIp || row?.local_address || row?.srcIp || row?.correlatedConnection?.sourceIp ||
    raw.srcip || raw.src_ip || raw.sourceIp || raw.localIp || raw.local_address || connection.local_ip || connection.localIp || '';
}

function netDstIp(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.destip || row?.dstip || row?.dst_ip || row?.destinationIp || row?.remoteIp || row?.remote_address || row?.dstIp || row?.net || row?.correlatedConnection?.destinationIp ||
    raw.destip || raw.dstip || raw.dst_ip || raw.destinationIp || raw.remoteIp || raw.remote_address || raw.net || connection.remote_ip || connection.remoteIp || '';
}

function netDestinationIps(row) {
  const values = Array.isArray(row?.destinationIps) ? row.destinationIps : [];
  return [...new Set([netDstIp(row), ...values].filter(Boolean))];
}

function netSrcPort(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.srcPort || row?.srcport || row?.src_port || row?.sourcePort || row?.localPort || row?.local_port || row?.correlatedConnection?.sourcePort || raw.srcPort || raw.srcport || raw.src_port || raw.sourcePort || raw.localPort || raw.local_port || connection.local_port || connection.localPort || '';
}

function netDstPort(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.destPort || row?.dstPort || row?.dstport || row?.dst_port || row?.destinationPort || row?.remotePort || row?.remote_port || row?.port || row?.correlatedConnection?.destinationPort || raw.destPort || raw.dstPort || raw.dstport || raw.dst_port || raw.destinationPort || raw.remotePort || raw.remote_port || raw.port || connection.remote_port || connection.remotePort || '';
}

function netProto(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return String(row?.protocol || row?.networkProtocol || row?.proto || row?.correlatedConnection?.protocol || raw.protocol || raw.networkProtocol || raw.proto || connection.protocol || 'UNKNOWN').toUpperCase();
}

function netProcess(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.process || row?.processName || row?.process_name || row?.executable || row?.command || row?.correlatedConnection?.processName ||
    raw.process || raw.processName || raw.process_name || raw.processExe || raw.process_exe || raw.executable || connection.process_name || connection.processName || 'unknown';
}

function netPid(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const connection = raw?.connection || {};
  return row?.pid || row?.processId || row?.process_id || row?.correlatedConnection?.pid || raw.pid || raw.processId || raw.process_id || connection.pid || '';
}

// Detection alerts such as NET_SCAN_BEHAVIOR describe a group of sockets at
// the top level. The agent's exact socket fields live in raw.new_connections,
// so expand that evidence instead of showing empty alert-level placeholders.
function suspiciousConnectionEvidence(row) {
  const rawEvent = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : (row?.raw || rawEvent);
  const candidates = [
    raw?.new_connections,
    raw?.newConnections,
    raw?.connections,
    raw?.external_peers,
    raw?.externalPeers,
  ].find(value => Array.isArray(value) && value.length) || [];

  return candidates.map((connection, index) => {
    const destinationIp = netDstIp(connection);
    const destinationPort = netDstPort(connection);
    const protocol = netProto(connection);
    const processName = netProcess(connection);
    const observedAt = connection?.observed_at || connection?.observedAt || connection?.timestamp || alertTime(row);
    const completeness = (destinationIp ? 4 : 0)
      + (destinationPort !== '' && destinationPort !== null && destinationPort !== undefined ? 2 : 0)
      + (protocol !== 'UNKNOWN' ? 1 : 0)
      + (processName && processName !== 'unknown' ? 4 : 0);
    return {
      ...row,
      ...connection,
      _recordType: 'connection-evidence',
      _evidenceIndex: index,
      _completeness: completeness,
      hostname: connection?.hostname || alertHost(row),
      destinationIp,
      destinationPort,
      protocol,
      process: processName,
      processName,
      pid: netPid(connection) || netPid(row),
      observedAt,
      description: row?.description || row?.message || 'Suspicious connection',
      severity: row?.severity,
      riskScore: row?.riskScore,
    };
  }).filter(connection => netDstIp(connection));
}

function netBytesSent(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return Number(row?.bytesSent ?? row?.bytes_sent ?? row?.sentBytes ?? row?.sent ?? row?.correlatedConnection?.bytesSent ?? raw.bytesSent ?? raw.bytes_sent ?? raw.sentBytes ?? 0);
}

function netBytesRecv(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return Number(row?.bytesRecv ?? row?.bytesReceived ?? row?.bytes_recv ?? row?.receivedBytes ?? row?.recv ?? row?.correlatedConnection?.bytesReceived ?? raw.bytesRecv ?? raw.bytesReceived ?? raw.bytes_recv ?? raw.receivedBytes ?? 0);
}

function netDnsQuery(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  return row?.dnsQuery || row?.dns_query || row?.domain || row?.query || row?.correlatedConnection?.domain || raw.dnsQuery || raw.dns_query || raw.domain || raw.query || '';
}

function netDetail(row, ...keys) {
  const rawEvent = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const raw = rawEvent.raw && typeof rawEvent.raw === 'object' ? rawEvent.raw : (row?.raw || rawEvent);
  const connection = raw?.connection && typeof raw.connection === 'object' ? raw.connection : {};
  const correlated = row?.correlatedConnection || {};
  const endpoint = row?.liveContext?.endpoint || {};
  const snapshot = row?.liveContext?.networkSnapshot || {};
  for (const key of keys) {
    for (const source of [row, correlated, rawEvent, raw, connection, endpoint, snapshot]) {
      const value = source?.[key];
      if (value !== undefined && value !== null && value !== '') return value;
    }
  }
  return '';
}

function netGeo(row) {
  const raw = row?.rawEvent?.raw || row?.rawEvent || row?.raw || {};
  const correlated = row?.correlatedConnection || {};
  const city = row?.geoCity || correlated?.geo?.city || raw.geoCity || raw.city || '';
  const country = row?.geoCountry || row?.country || correlated?.geo?.country || raw.geoCountry || raw.country || '';
  const geo = row?.geo || correlated.geo || raw.geo;
  if (city || country) return [city, country].filter(Boolean).join(', ');
  if (typeof row?.geoLoc === 'string') return row.geoLoc;
  if (typeof raw.geoLoc === 'string') return raw.geoLoc;
  if (geo && typeof geo === 'object') return [geo.city, geo.region, geo.country].filter(Boolean).join(', ');
  return typeof geo === 'string' ? geo : '';
}

function containsAny(row, words = []) {
  const haystack = [
    netSrcIp(row), netDstIp(row), netProcess(row), netDnsQuery(row), alertHost(row), alertUser(row),
    row?.description, row?.message, row?.ruleName, row?.type, row?.category,
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

function buildValueBuckets(rows = [], picker = () => 0, bucketCount = 12, hours = 24) {
  const now = Date.now();
  const start = now - hours * 3600000;
  const bucketMs = (hours * 3600000) / bucketCount;
  const buckets = Array(bucketCount).fill(0);
  rows.forEach(row => {
    const ms = new Date(alertTime(row)).getTime();
    if (!Number.isFinite(ms) || ms < start || ms > now) return;
    const index = Math.min(bucketCount - 1, Math.max(0, Math.floor((ms - start) / bucketMs)));
    buckets[index] += Math.max(0, Number(picker(row)) || 0);
  });
  return buckets;
}

function topCounts(rows = [], picker = () => 'unknown', limit = 5) {
  const counts = new Map();
  rows.forEach(row => {
    const key = String(picker(row) || 'unknown').trim() || 'unknown';
    if (key === 'unknown' || key === '—') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return Array.from(counts.entries()).sort((a, b) => b[1] - a[1]).slice(0, limit);
}

function recordId(row) {
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${netDstIp(row)}-${netDstPort(row)}`;
}

function csvCell(val) {
  const str = String(val ?? '').replace(/"/g, '""');
  return `"${str}"`;
}

function safeRawEvent(row) {
  const value = row?.rawEvent || row?.rawMetadata || row?.raw || row || {};
  try {
    return JSON.stringify(value, (key, item) => (
      /secret|token|password|authorization|agent_?key/i.test(key) ? '[REDACTED]' : item
    ), 2);
  } catch {
    return 'Raw metadata is not serializable.';
  }
}

function networkTimeline(row) {
  const items = [];
  const add = (type, value, title, description, color) => {
    if (!value) return;
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) return;
    items.push({ type, time: parsed.toLocaleString(), title, description, col: color });
  };
  add('Started', row?.startTime || row?.connectionStartTime || row?.firstSeen, 'Connection first observed', `${netProcess(row)} opened a ${netProto(row)} connection.`, MON.blue);
  add('Observed', row?.observedAt || row?.eventTimestamp || row?.timestamp || row?.createdAt, 'Telemetry received', `${netSrcIp(row) || '—'}:${netSrcPort(row) || '—'} → ${netDstIp(row) || '—'}:${netDstPort(row) || '—'} (${alertStatus(row)}).`, MON.cyan);
  add('Closed', row?.endTime || row?.connectionEndTime, 'Connection closed', `Reported duration: ${Number(row?.durationSeconds ?? row?.connectionDuration ?? 0)} seconds.`, MON.muted);
  const reason = Array.isArray(row?.detectionReasons) ? row.detectionReasons.join('; ') : (row?.description || row?.message || '');
  if (reason && row?._recordType === 'alert') {
    add('Detection', row?.createdAt || row?.timestamp, row?.ruleId || row?.eventName || 'Network detection', reason, MON.red);
  }
  return items.sort((a, b) => new Date(a.time) - new Date(b.time));
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

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function NetworkLogDetailModal({ log: initialLog, onClose, onSaved }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [liveLog, setLiveLog] = useState(initialLog);
  const [analystNotes, setAnalystNotes] = useState(initialLog?.analystNotes || '');
  const [assignedAnalyst] = useState(initialLog?.assignedTo?.name || initialLog?.assignedTo?.email || initialLog?.assignedAnalyst || 'Unassigned');
  const [caseStatus, setCaseStatus] = useState(initialLog?.status || 'open');
  const [notesSaved, setNotesSaved] = useState('');
  const [savingNotes, setSavingNotes] = useState(false);
  const log = liveLog || initialLog;
  const tags = Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || 'None');
  const mitreMappings = [...new Set([
    log?.mitreId,
    log?.mitreTechnique,
    ...(Array.isArray(log?.mitre) ? log.mitre : []),
  ].filter(Boolean))];

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Network.Connections');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Network Connections & Listeners');
  const [huntNameInput, setHuntNameInput] = useState(`${initialLog?.hostname || 'endpoint'} network forensic hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  useEffect(() => {
    setLiveLog(initialLog);
    if (!initialLog?._id) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const response = await api.get(`/network/forensics/${initialLog._id}`, { skipCache: true });
        if (active && response.data?.record) {
          setLiveLog({ ...initialLog, ...response.data.record, _recordType: initialLog._recordType });
        }
      } catch {
        // Keep the selected live-list row visible if a refresh races retention.
      }
    };
    refresh();
    const timer = setInterval(refresh, 15000);
    return () => { active = false; clearInterval(timer); };
  }, [initialLog?._id]);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const sevBg = SEV_BG[sev] || 'rgba(56, 189, 248, 0.15)';
  const timelineEvents = networkTimeline(log);
  const systemId = log?.systemId?._id || log?.systemId || '';
  const companyId = log?.companyId?._id || log?.companyId || '';
  const isAlertRecord = log?._recordType === 'alert';
  const perFlowBytesAvailable = log?.rawMetadata?.bytesScope !== 'not_available';

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Endpoint & Agent' },
    { id: 'socket', label: '🔌 4. Connection & Socket' },
    { id: 'process', label: '⚙️ 5. Process Correlation' },
    { id: 'dns', label: '🔍 6. DNS & Web Inspection' },
    { id: 'ioc', label: '🎯 7. IOC, Geo & MITRE' },
    { id: 'forensics', label: '🔬 8. Forensics' },
    { id: 'evidence', label: '📦 9. Evidence & NetFlow' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Linux Active Connections', desc: 'Acquire active netstat connections, listening ports, and socket inodes.', artifact: 'Linux.Network.Netstat' },
    { title: 'Windows Network Connections', desc: 'Inspect active sockets, connected PIDs, and remote endpoints.', artifact: 'Windows.Network.Netstat' },
    { title: 'Windows ARP Cache Sweep', desc: 'Dump ARP table to detect internal host discovery & man-in-the-middle.', artifact: 'Windows.Network.Arp' },
    { title: 'Linux Log Hunter (Auth & Net)', desc: 'Search auth.log and syslog for SSH/RDP and network service events.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'YARA Network Memory Sweep', desc: 'Scan process memory for C2 beacons and YARA signatures.', artifact: 'Generic.Detection.Yara.Glob' },
    { title: 'KAPE Network & Log Triage', desc: 'Collect event logs, firewall rules, and network configuration targets.', artifact: 'Windows.KapeFiles.Targets' },
  ];

  const handleSelectArtifactCard = (item) => {
    setSelectedArtifact(item.artifact);
    setSelectedArtifactTitle(item.title);
  };

  const handleLaunchHunt = async () => {
    if (!systemId) {
      setHuntSuccessMsg('Hunt not sent: this event has no tenant-scoped endpoint ID.');
      return;
    }
    setLaunchingHunt(true);
    setHuntSuccessMsg(null);
    try {
      const response = await api.post('/forensics/hunts', {
        name: huntNameInput.trim() || selectedArtifactTitle,
        artifacts: [selectedArtifact],
        systemId,
        ...(companyId ? { companyId } : {}),
      });
      setHuntSuccessMsg(`Hunt queued: ${response.data?.hunt?._id || 'request accepted'}`);
    } catch (error) {
      setHuntSuccessMsg(error.response?.data?.message || 'Unable to launch the forensic hunt.');
    } finally {
      setLaunchingHunt(false);
    }
  };

  const handleSaveNotes = async () => {
    if (!isAlertRecord || !log?._id) {
      setNotesSaved('This connection row has no alert case to update. Open a network alert to save triage notes.');
      return;
    }
    setSavingNotes(true);
    setNotesSaved('');
    try {
      const requests = [api.patch(`/alerts/${log._id}`, { status: caseStatus })];
      if (analystNotes.trim()) requests.push(api.post(`/alerts/${log._id}/notes`, { text: analystNotes.trim() }));
      await Promise.all(requests);
      setNotesSaved('Saved to the live alert record.');
      onSaved?.();
    } catch (error) {
      setNotesSaved(error.response?.data?.message || 'Unable to save this alert update.');
    } finally {
      setSavingNotes(false);
    }
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🌐</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Network Forensic Investigation — {netSrcIp(log)}:{netSrcPort(log)} → {netDstIp(log)}:{netDstPort(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Protocol: {netProto(log)}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Process: <strong style={{ color: MON.cyan }}>{netProcess(log)} (PID {netPid(log)})</strong> | Geo: <strong style={{ color: MON.yellow }}>{netGeo(log)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
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
                ['Event Summary', log.description || log.message || log.eventName || 'Network connection telemetry', MON.cyan],
                ['Risk Score', log.riskScore !== undefined || log.score !== undefined ? `${log.riskScore ?? log.score}/100` : 'Not scored', MON.red],
                ['Status', caseStatus, MON.yellow],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['Host System', alertHost(log), MON.blue],
                ['User Account', alertUser(log), MON.cyan],
                ['Modifying Process', `${netProcess(log)} (PID ${netPid(log)})`, MON.purple],
                ['Remote Destination', `${netDstIp(log) || '—'}:${netDstPort(log) || '—'}${netGeo(log) ? ` (${netGeo(log)})` : ''}`, MON.text],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Socket Life Cycle & Connection Chronology</div>
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
              {!timelineEvents.length && <div style={{ color: MON.muted, fontSize: 11 }}>No valid lifecycle timestamps were reported for this event.</div>}
            </div>
          )}

          {/* TAB 3: ENDPOINT & AGENT */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Endpoint Host Telemetry</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Agent ID:</span> <strong style={{ color: MON.cyan }}>{netDetail(log, 'agentId', 'endpointId') || 'Not reported'}</strong></div>
                  <div><span style={{ color: MON.sub }}>Telemetry Source:</span> <strong>{netDetail(log, 'detectionSource', 'source', 'dataOrigin') || 'Not reported'}</strong></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>📡 Active Network Adapters</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Local IP Address:</span> <b style={{ color: MON.cyan }}>{netSrcIp(log) || 'Not reported'}</b></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Interface:</span> <span style={{ fontFamily: 'monospace' }}>{netDetail(log, 'interfaceName', 'networkInterface', 'interface') || 'Not reported'}</span></div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Adapter:</span> <b>{netDetail(log, 'networkAdapter', 'network_adapter', 'adapter', 'interface') || 'Not reported'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: CONNECTION & SOCKET */}
          {activeTab === 'socket' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>🔌 Connection Tuple & Protocol Info</h4>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Source IP:</span> <span style={{ fontFamily: 'monospace', color: MON.green }}>{netSrcIp(log) || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Source Port:</span> <span style={{ fontFamily: 'monospace', color: MON.text }}>{netSrcPort(log) || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Destination IPs:</span> <span style={{ fontFamily: 'monospace', color: MON.red }}>{netDestinationIps(log).join(', ') || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Destination Port:</span> <span style={{ fontFamily: 'monospace', color: MON.yellow }}>{netDstPort(log) || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>IP Version:</span> <span>{netDetail(log, 'ipVersion', 'ip_version') ? `IPv${netDetail(log, 'ipVersion', 'ip_version')}` : 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Started:</span> <span>{netDetail(log, 'startTime', 'connectionStartTime', 'connection_start_time', 'start_time') || 'Not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Ended:</span> <span>{netDetail(log, 'endTime', 'connectionEndTime', 'connection_end_time', 'end_time') || 'Active / not reported'}</span></div>
                  <div><span style={{ color: MON.sub }}>Duration:</span> <span>{netDetail(log, 'durationSeconds', 'connectionDuration', 'connection_duration', 'duration') || 'Not reported'}</span></div>
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.orange }}>📊 Bandwidth & Traffic Volume</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, fontSize: 11 }}>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.green }}>Bytes Sent (Upload):</span>
                    <div style={{ fontSize: 18, fontWeight: 900, color: MON.green, marginTop: 4 }}>{perFlowBytesAvailable ? formatBytes(netBytesSent(log)) : 'Not reported by OS'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.cyan }}>Bytes Recv (Download):</span>
                    <div style={{ fontSize: 18, fontWeight: 900, color: MON.cyan, marginTop: 4 }}>{perFlowBytesAvailable ? formatBytes(netBytesRecv(log)) : 'Not reported by OS'}</div>
                  </div>
                  <div style={{ background: MON.card2, padding: 12, borderRadius: 6, border: `1px solid ${MON.line}` }}>
                    <span style={{ color: MON.yellow }}>Connection State:</span>
                    <div style={{ fontSize: 18, fontWeight: 900, color: MON.yellow, marginTop: 4 }}>{alertStatus(log)}</div>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 5: PROCESS CORRELATION */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🖥️ Process-to-Network Correlation</h4>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Communicating Process:</span> <b style={{ color: MON.cyan }}>{netProcess(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Process ID (PID):</span> <b style={{ color: MON.yellow }}>{netPid(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Executing User:</span> <b style={{ color: MON.green }}>{alertUser(log)}</b></div>
                <div><span style={{ color: MON.sub }}>Executable Path:</span> <span style={{ fontFamily: 'monospace' }}>{netDetail(log, 'executablePath', 'processExe', 'process_exe', 'executable') || 'Not reported by agent'}</span></div>
                <div><span style={{ color: MON.sub }}>Parent Process:</span> <span>{netDetail(log, 'parentProcessName', 'parentProcess', 'parent_process_name', 'parent_process') || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Parent PID:</span> <span>{netDetail(log, 'parentPid', 'parent_pid') || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Process Hash:</span> <span style={{ fontFamily: 'monospace' }}>{netDetail(log, 'processHash', 'processExecutableSha256', 'executable_sha256', 'process_hash') || 'Not reported'}</span></div>
                <div><span style={{ color: MON.sub }}>Signature:</span> <span>{netDetail(log, 'signatureStatus', 'signature_status') || 'Not reported'}</span></div>
              </div>
            </div>
          )}

          {/* TAB 6: DNS & WEB INSPECTION */}
          {activeTab === 'dns' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>🔍 DNS Query Details</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Queried Domain:</span> <b style={{ color: MON.cyan, fontFamily: 'monospace' }}>{netDnsQuery(log) || 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>Query Type:</span> <b>{netDetail(log, 'queryType', 'dnsQueryType', 'query_type') || 'Not reported'}</b></div>
                  <div><span style={{ color: MON.sub }}>Resolved Addresses:</span> <span style={{ fontFamily: 'monospace', color: MON.green }}>{netDestinationIps(log).join(', ') || 'Not reported'}</span></div>
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>🌍 HTTP / HTTPS Request Inspection</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>HTTP Method:</span> <b style={{ color: MON.green }}>{netDetail(log, 'method', 'httpMethod', 'http_method') || 'Not collected'}</b></div>
                  <div><span style={{ color: MON.sub }}>User-Agent:</span> <span style={{ fontFamily: 'monospace' }}>{netDetail(log, 'userAgent', 'user_agent') || 'Not collected'}</span></div>
                  <div><span style={{ color: MON.sub }}>SSL/TLS Version:</span> <b>{netDetail(log, 'tlsVersion', 'tls_version') || 'Not collected'}</b></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC, GEO & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🎯 MITRE ATT&CK Mapping</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {mitreMappings.map(value => (
                    <div key={value} style={{ background: 'rgba(248, 113, 113, 0.1)', padding: 8, borderRadius: 6, border: `1px solid ${MON.red}` }}>
                      <b style={{ color: MON.red }}>{value}</b>
                    </div>
                  ))}
                  {!mitreMappings.length && <span style={{ color: MON.muted }}>No MITRE mapping reported for this event.</span>}
                </div>
              </div>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🌐 Threat Intel & Geo Location</h4>
                <div style={{ fontSize: 11, color: MON.text, display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div><b>Geo Location:</b> <span style={{ color: MON.yellow }}>{netGeo(log) || 'Not reported'}</span></div>
                  <div><b>Threat Intel:</b> <span style={{ color: netDetail(log, 'vtVerdict', 'tiSummary') === 'malicious' || log?.threatIntel?.verdict === 'malicious' || log?.correlatedConnection?.threatIntel?.verdict === 'malicious' ? MON.red : MON.muted, fontWeight: 800 }}>{log?.threatIntel?.verdict || log?.correlatedConnection?.threatIntel?.verdict || netDetail(log, 'vtVerdict', 'tiSummary') || 'No threat-intelligence match reported'}</span></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Network Artifact Hunt Launcher</div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
                  {forensicHuntCards.map((item) => (
                    <div key={item.artifact} onClick={() => handleSelectArtifactCard(item)} style={{ background: selectedArtifact === item.artifact ? MON.card2 : MON.bg, border: `1px solid ${selectedArtifact === item.artifact ? MON.cyan : MON.border}`, borderRadius: 6, padding: 12, cursor: 'pointer' }}>
                      <div style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{item.title}</div>
                      <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>{item.desc}</div>
                    </div>
                  ))}
                </div>
                <div style={{ marginTop: 14, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 11, color: MON.cyan }}>Selected VQL Artifact: <b>{selectedArtifact}</b></span>
                  <button type="button" onClick={handleLaunchHunt} disabled={launchingHunt || !systemId} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: launchingHunt || !systemId ? 'not-allowed' : 'pointer', opacity: systemId ? 1 : 0.55 }}>
                    {launchingHunt ? 'Dispatching Hunt...' : '🚀 Launch VQL Hunt'}
                  </button>
                </div>
                {huntSuccessMsg && (
                  <div style={{ marginTop: 12, padding: 10, background: 'rgba(56, 189, 248, 0.12)', border: `1px solid ${MON.blue}`, color: MON.text, borderRadius: 6, fontSize: 11 }}>
                    {huntSuccessMsg}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Raw Network Metadata (payload excluded)</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {safeRawEvent(log)}
              </pre>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Network Triage & Case Management</h4>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 12 }}>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Assigned Analyst</label>
                    <input type="text" value={assignedAnalyst} readOnly style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Case Status</label>
                    <select value={caseStatus} onChange={e => setCaseStatus(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }}>
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="under_observation">Under observation</option>
                      <option value="resolved">Resolved</option>
                      <option value="false_positive">False positive</option>
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize: 10, color: MON.sub, display: 'block', marginBottom: 4 }}>Incident Tags</label>
                    <input type="text" value={tags} readOnly style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 8, borderRadius: 6, fontSize: 11 }} />
                  </div>
                </div>
                <textarea rows={4} value={analystNotes} onChange={e => setAnalystNotes(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: 10, borderRadius: 6, fontSize: 11, outline: 'none' }} />
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end' }}>
                  {notesSaved && <span style={{ marginRight: 10, color: MON.yellow, fontSize: 10 }}>{notesSaved}</span>}
                  <button type="button" onClick={handleSaveNotes} disabled={savingNotes || !isAlertRecord} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: savingNotes || !isAlertRecord ? 'not-allowed' : 'pointer', opacity: isAlertRecord ? 1 : 0.55 }}>
                    {savingNotes ? 'Saving…' : 'Save Triage Notes'}
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
// 2. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
function NetworkLogMonitor({ alerts = [], total = 0, onSaved }) {
  const [query, setQuery] = useState('');
  const [platform, setPlatform] = useState('all');
  const [severity, setSeverity] = useState('all');
  const [protoFilter, setProtoFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      // Summary envelopes feed charts and normalized connection storage. They
      // are not individual SIEM rows and have no single socket tuple/process.
      if (!isNetworkLogRow(a)) return false;
      const matchQ = !query || `${netSrcIp(a)} ${netDstIp(a)} ${netProcess(a)} ${netDnsQuery(a)} ${alertHost(a)} ${alertUser(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchP = platform === 'all' || processOs(a).toLowerCase().includes(platform.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchPr = protoFilter === 'all' || netProto(a).toLowerCase() === protoFilter.toLowerCase();
      return matchQ && matchP && matchS && matchPr;
    });
  }, [alerts, query, platform, severity, protoFilter]);
  const filtersActive = Boolean(query) || platform !== 'all' || severity !== 'all' || protoFilter !== 'all';
  const exactTotal = filtered.length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search IP, Port, Domain, Process, Host, User..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={platform} onChange={e => setPlatform(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All OS Platforms</option>
          <option value="win">Windows</option>
          <option value="lin">Linux</option>
          <option value="mac">macOS</option>
          <option value="android">Android</option>
        </select>
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select value={protoFilter} onChange={e => setProtoFilter(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Protocols</option>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="dns">DNS</option>
          <option value="http">HTTP/HTTPS</option>
          <option value="smb">SMB</option>
          <option value="rdp">RDP</option>
          <option value="ssh">SSH</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <b style={{ fontSize: 12, color: '#fff' }}>📜 Change-only Network Events ({filtersActive ? `${filtered.length} filtered from ${exactTotal.toLocaleString()}` : exactTotal.toLocaleString()})</b>
            <div style={{ marginTop: 3, fontSize: 9, color: MON.muted }}>Stable snapshots, heartbeats and local sensor diagnostics are hidden; rows change only for connection, port, process, DNS, VPN or security events.</div>
          </div>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1550 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.4fr 80px 1fr 1fr 1fr 90px 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Source IP / Host</span><span>Destination IP : Port</span><span>Proto</span><span>Process (PID)</span><span>User</span><span>DNS / Geo</span><span>Traffic</span><span>Severity</span><span>Status</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.4fr 80px 1fr 1fr 1fr 90px 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{netSrcIp(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{alertHost(row)}</span>
                </div>
                <div>
                  <b style={{ color: MON.red, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>
                    {netDstIp(row)}:{netDstPort(row)}{netDestinationIps(row).length > 1 ? ` (+${netDestinationIps(row).length - 1} IPs)` : ''}
                  </b>
                  <span style={{ fontSize: 9, color: MON.muted }}>{netGeo(row)}</span>
                </div>
                <span style={{ color: MON.green, fontWeight: 800 }}>{netProto(row)}</span>
                <div>
                  <b style={{ color: netProcess(row) === 'unknown' ? MON.muted : MON.purple, display: 'block' }}>{netProcess(row) === 'unknown' ? 'Not reported' : netProcess(row)}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{netPid(row) ? `PID: ${netPid(row)}` : 'PID unavailable'}</span>
                </div>
                <span style={{ color: MON.text }}>{alertUser(row)}</span>
                <div style={{ minWidth: 0 }}>
                  <span title={netDnsQuery(row)} style={{ color: MON.yellow, fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{netDnsQuery(row) || 'DNS/SNI unavailable'}</span>
                  <span title={netGeo(row)} style={{ color: MON.sub, fontSize: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', display: 'block' }}>{netGeo(row) || 'Geo unavailable'}</span>
                </div>
                <span style={{ color: MON.cyan, fontSize: 9 }}>{formatBytes(netBytesSent(row) + netBytesRecv(row))}</span>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: /suspicious|blocked|critical/i.test(alertStatus(row)) ? MON.red : MON.green, fontWeight: 800 }}>{alertStatus(row)}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No network telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <NetworkLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onSaved={onSaved} />}
    </div>
  );
}

function NetworkReportsTab({ alerts = [], companyId = '' }) {
  // Match the FIM report workflow: start at 24 hours and fetch only after the
  // user explicitly presses Generate Network Report.
  const [reportType, setReportType] = useState('daily');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);
  const reportWindows = [
    { key: 'daily', label: '24 Hours', icon: '⏱', sub: 'Last 24h', days: 1 },
    { key: 'weekly', label: '1 Week', icon: '📆', sub: 'Last 7 days', days: 7 },
    { key: 'monthly', label: '1 Month', icon: '🗓', sub: 'Last 30 days', days: 30 },
    { key: 'quarterly', label: '3 Months', icon: '📊', sub: 'Last 90 days', days: 90 },
  ];
  const selectedWindow = reportWindows.find(option => option.key === reportType) || reportWindows[0];

  const getFilteredAlerts = () => {
    const now = Date.now();
    const dayMs = 86400000;
    const days = selectedWindow.days;
    const cutoff = now - days * dayMs;
    const filtered = alerts.filter(a => {
      const t = alertTime(a);
      return t ? new Date(t).getTime() >= cutoff : true;
    });
    return filtered.length > 0 ? filtered : alerts;
  };

  const handleGenerate = async () => {
    setGenerating(true);
    setGenerated(false);
    try {
      const days = selectedWindow.days;
      const to = new Date();
      const from = new Date(to.getTime() - days * 86400000);
      const response = await api.get('/reports', {
        params: {
          from: from.toISOString(),
          to: to.toISOString(),
          type: 'network',
          capabilityId: 3,
          ...(companyId ? { companyId: String(companyId) } : {}),
        },
        skipCache: true,
      });
      const payload = response.data || {};
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      (payload.bySeverity || []).forEach(item => {
        const severity = String(item.severity || '').toLowerCase();
        if (bySev[severity] !== undefined) bySev[severity] += Number(item.count || 0);
      });
      setReportData({
        alerts: payload.logsSnapshot || [],
        total: Number(payload.summary?.totalAlerts || 0),
        bySev,
        window: { hours: days * 24, from: from.toISOString(), to: to.toISOString() },
      });
    } catch {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => { const s = alertSeverity(a); if (bySev[s] !== undefined) bySev[s]++; });
      setReportData({ alerts: filtered, total: filtered.length, bySev, window: null });
    } finally {
      setGenerating(false);
      setGenerated(true);
    }
  };

  const handleExportCSV = async () => {
    const days = selectedWindow.days;
    const to = new Date().toISOString();
    const from = new Date(Date.now() - days * 86400000).toISOString();
    try {
      const response = await api.get(`/reports/csv?from=${from}&to=${to}&type=network&capabilityId=3${companyId ? `&companyId=${encodeURIComponent(companyId)}` : ''}`, { responseType: 'blob' });
      downloadBlob(response.data, `network_activity_${reportType}_all_records.csv`);
      return;
    } catch {
      // Use the currently generated rows if the full export service is unavailable.
    }
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Source IP,Source Port,Destination IP,Destination Port,Protocol,Process,PID,Host,User,Severity,Bytes Sent,Bytes Recv';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(netSrcIp(a)),
      csvCell(netSrcPort(a)),
      csvCell(netDstIp(a)),
      csvCell(netDstPort(a)),
      csvCell(netProto(a)),
      csvCell(netProcess(a)),
      csvCell(netPid(a)),
      csvCell(alertHost(a)),
      csvCell(alertUser(a)),
      csvCell(alertSeverity(a)),
      csvCell(netBytesSent(a)),
      csvCell(netBytesRecv(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `network_activity_${reportType}_${filtered.length}records.csv`);
  };

  const handleExportPDF = async () => {
    const days = selectedWindow.days;
    const to = new Date().toISOString();
    const from = new Date(Date.now() - days * 86400000).toISOString();
    try {
      const response = await api.get(`/reports/pdf?from=${from}&to=${to}&type=network&capabilityId=3${companyId ? `&companyId=${encodeURIComponent(companyId)}` : ''}`, { responseType: 'blob' });
      const url = URL.createObjectURL(response.data);
      const reportWindow = window.open(url, '_blank');
      window.setTimeout(() => URL.revokeObjectURL(url), reportWindow ? 120000 : 1000);
      if (!reportWindow) throw new Error('Popup blocked');
    } catch {
      window.alert('PDF report open nahi hua. Browser popups allow karke dobara try karein.');
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Network Activity Monitoring Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate compliance-ready network activity and threat summaries</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Network Report'}
          </button>
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📅 Select Time Window</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {reportWindows.map(opt => {
              const active = reportType === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => { setReportType(opt.key); setGenerated(false); setReportData(null); }}
                  style={{
                    background: active ? MON.cyan : MON.card2,
                    color: active ? '#000' : MON.text,
                    border: `2px solid ${active ? MON.cyan : MON.border}`,
                    borderRadius: 8, padding: '10px 18px', cursor: 'pointer',
                    display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2, minWidth: 100,
                    fontWeight: active ? 900 : 600,
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
      </div>

      {generated && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Network Activity Executive Security & Compliance Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>
                Total Monitored Network Events: <b style={{ color: MON.cyan }}>{reportData?.total}</b>
                {reportData?.window?.from && <> | Window: <b style={{ color: MON.yellow }}>{new Date(reportData.window.from).toLocaleString()} → {new Date(reportData.window.to).toLocaleString()}</b></>}
                {' '}| Generated: {new Date().toLocaleString()}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
                📥 Export CSV
              </button>
              <button type="button" onClick={handleExportPDF} style={{ background: '#ef4444', color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
                📕 Export PDF
              </button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Network Events', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Network Threats', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Connections', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Low / Normal Traffic', val: Math.max(0, Number(reportData?.total || 0) - Number(reportData?.bySev?.critical || 0) - Number(reportData?.bySev?.high || 0)), color: MON.green },
            ].map(c => (
              <div key={c.label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 9, color: MON.muted, fontWeight: 700, textTransform: 'uppercase' }}>{c.label}</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: c.color, marginTop: 6 }}>{c.val}</div>
              </div>
            ))}
          </div>

        </div>
      )}
    </div>
  );
}

// ── SVG Area/Line Sparkline Component for KPI Cards ──
function CardSparkline({ data = [], color = MON.cyan, height = 30 }) {
  const values = data.length ? data : [0, 0];
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const points = values.map((val, idx) => {
    const x = (idx / (values.length - 1)) * 100;
    const y = height - ((val - min) / (max - min || 1)) * (height - 6) - 3;
    return `${x},${y}`;
  });

  const linePath = `M ${points.map(p => p.split(',').join(' ')).join(' L ')}`;
  const areaPath = `${linePath} L 100 ${height} L 0 ${height} Z`;

  return (
    <svg viewBox={`0 0 100 ${height}`} width="100%" height={height} preserveAspectRatio="none" style={{ overflow: 'visible', display: 'block' }}>
      <defs>
        <linearGradient id={`grad-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.45" />
          <stop offset="100%" stopColor={color} stopOpacity="0.0" />
        </linearGradient>
      </defs>
      <path d={areaPath} fill={`url(#grad-${color.replace('#', '')})`} />
      <path d={linePath} fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Flag Emoji Helper ──
function getFlagEmoji(countryCode) {
  const code = String(countryCode || '').toUpperCase();
  if (code === 'US') return '🇺🇸';
  if (code === 'CA') return '🇨🇦';
  if (code === 'SG') return '🇸🇬';
  if (code === 'TW') return '🇹🇼';
  if (code === 'NL') return '🇳🇱';
  if (code === 'IN') return '🇮🇳';
  if (code === 'GB') return '🇬🇧';
  if (code === 'DE') return '🇩🇪';
  return '🌐';
}

// ── Donut Chart Component ──
function DonutChart({ data = [], strokeWidth = 10, size = 110, totalValue }) {
  const total = totalValue !== undefined ? totalValue : data.reduce((sum, item) => sum + item.value, 0);
  let accumulatedPercent = 0;
  const radius = (size - strokeWidth - 6) / 2;
  const circumference = 2 * Math.PI * radius;

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ position: 'relative', width: size, height: size, flexShrink: 0 }}>
        <svg width="100%" height="100%" viewBox={`0 0 ${size} ${size}`}>
          {data.map((item, idx) => {
            const percent = item.value / (total || 1);
            const strokeLength = percent * circumference;
            const strokeOffset = circumference - (accumulatedPercent * circumference);
            accumulatedPercent += percent;

            return (
              <circle
                key={idx}
                cx={size / 2}
                cy={size / 2}
                r={radius}
                fill="transparent"
                stroke={item.color}
                strokeWidth={strokeWidth}
                strokeDasharray={`${strokeLength} ${circumference}`}
                strokeDashoffset={strokeOffset}
                transform={`rotate(-90 ${size / 2} ${size / 2})`}
                style={{ transition: 'stroke-dashoffset 0.5s ease-in-out' }}
              />
            );
          })}
          <text x="50%" y="46%" textAnchor="middle" dominantBaseline="middle" fill="#fff" fontSize="12" fontWeight="900">
            {shortNum(total)}
          </text>
          <text x="50%" y="58%" textAnchor="middle" dominantBaseline="middle" fill={MON.muted} fontSize="7" fontWeight="800" letterSpacing="0.4">
            Total
          </text>
        </svg>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1 }}>
        {data.map((item, idx) => (
          <div key={idx} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 5, color: MON.muted }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: item.color, display: 'inline-block' }} />
              {item.name}
            </span>
            <b style={{ color: MON.text }}>{item.percent}%</b>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Data Transfer Area Chart ──
function DataTransferChart({ upload = [], download = [] }) {
  const height = 90;
  const width = 280;
  const maxVal = Math.max(...upload, ...download, 10);

  const getPoints = (data) => {
    return data.map((val, idx) => {
      const x = (idx / (data.length - 1)) * width;
      const y = height - (val / maxVal) * (height - 12) - 6;
      return { x, y };
    });
  };

  const upPoints = getPoints(upload);
  const downPoints = getPoints(download);

  const upLine = `M ${upPoints.map(p => `${p.x} ${p.y}`).join(' L ')}`;
  const downLine = `M ${downPoints.map(p => `${p.x} ${p.y}`).join(' L ')}`;

  const upArea = `${upLine} L ${width} ${height} L 0 ${height} Z`;
  const downArea = `${downLine} L ${width} ${height} L 0 ${height} Z`;

  return (
    <div style={{ width: '100%' }}>
      <svg viewBox={`0 0 ${width} ${height}`} width="100%" height={height} style={{ overflow: 'visible', display: 'block' }}>
        <defs>
          <linearGradient id="up-area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={MON.green} stopOpacity="0.25" />
            <stop offset="100%" stopColor={MON.green} stopOpacity="0.0" />
          </linearGradient>
          <linearGradient id="down-area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={MON.blue} stopOpacity="0.25" />
            <stop offset="100%" stopColor={MON.blue} stopOpacity="0.0" />
          </linearGradient>
        </defs>

        <path d={downArea} fill="url(#down-area-grad)" />
        <path d={upArea} fill="url(#up-area-grad)" />

        <path d={downLine} fill="none" stroke={MON.blue} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        <path d={upLine} fill="none" stroke={MON.green} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />

        <line x1="0" y1={height} x2={width} y2={height} stroke={MON.border} strokeWidth="1" />
      </svg>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 8, color: MON.muted, marginTop: 4 }}>
        <span>12 AM</span>
        <span>6 AM</span>
        <span>12 PM</span>
        <span>6 PM</span>
        <span>12 AM</span>
      </div>
    </div>
  );
}

function NetworkOverviewDashboard({ alerts = [], total = 0, systems = [], statistics = {} }) {
  const panel = { 
    background: '#0a1424', 
    border: `1px solid ${MON.border}`, 
    borderRadius: 8, 
    padding: 14, 
    boxShadow: '0 4px 6px -1px rgba(0,0,0,0.2)' 
  };

  const { company, user } = useAuth();
  const companyId = company?._id || user?.companyId?._id || user?.companyId;
  const liveMap = useLiveNetworkMap(companyId);

  const stats = useMemo(() => {
    const peers = [];
    const dnsQueries = [];
    const suspiciousConns = [];
    const lateralConns = [];

    let totalEst = 0;
    let totalExt = 0;
    let totalInt = 0;

    const uniqueHosts = new Set();
    const uniqueServers = new Set();

    alerts.forEach(a => {
      const host = alertHost(a);
      uniqueHosts.add(host.toUpperCase());
      
      if (host.toLowerCase().includes('server') || host.toLowerCase().includes('gw') || host.toLowerCase().includes('dc')) {
        uniqueServers.add(host.toUpperCase());
      }

      const raw = a.rawEvent?.raw || {};

      if (a.connectionId || a.destinationIp || a.remoteIp) {
        const destination = netDstIp(a);
        const internal = /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.|::1|fe80:|fc|fd)/i.test(destination);
        if (String(a.state || '').toUpperCase() !== 'CLOSED') totalEst += 1;
        if (internal) totalInt += 1;
        else if (destination) totalExt += 1;
        peers.push({
          host,
          remote_ip: destination,
          remote_port: netDstPort(a) || null,
          local_ip: netSrcIp(a),
          local_port: netSrcPort(a) || null,
          pid: netPid(a) || null,
          process: netProcess(a),
          protocol: netProto(a),
          country: a.geo?.country || a.geoCountry || 'Unknown',
          countryCode: a.geo?.countryCode || a.geoCountryCode || '',
          isp: a.geo?.isp || a.geoISP || '',
          sent: netBytesSent(a),
          recv: netBytesRecv(a),
          connections: 1,
        });
      }

      if (a.ruleId === 'NET_CONNECTION_SUMMARY') {
        totalEst += Number(raw.established_count || 0);
        totalExt += Number(raw.external_count || 0);
        totalInt += Number(raw.internal_count || 0);

        const extPeers = raw.external_peers || [];
        extPeers.forEach(p => {
          const cc = p.countryCode || '';
          const country = p.country || 'Unknown';
          peers.push({
            host,
            remote_ip: p.remote_ip,
            remote_port: p.remote_port ?? null,
            local_ip: p.local_ip || '',
            local_port: p.local_port ?? null,
            pid: p.pid ?? null,
            process: p.processName || p.process || 'unknown',
            country,
            countryCode: cc,
            isp: p.isp || '',
            sent: Number(p.bytes_sent || p.sent_bytes || 0),
            recv: Number(p.bytes_received || p.recv_bytes || 0),
            connections: Number(p.connections || p.count || 1)
          });
        });
      }

      if (a.ruleId === 'NET_DNS_SUMMARY') {
        const queries = raw.dns_queries || [];
        queries.forEach(q => {
          dnsQueries.push(q);
        });
      }

      const isSuspicious = ['elevated', 'high', 'critical'].includes(alertSeverity(a)) ||
                           Number(a.riskScore || a.risk_score || 0) >= 41 ||
                           (Array.isArray(a.detectionReasons) && a.detectionReasons.length > 0) ||
                           a.beaconing === true || a.scanning === true ||
                           a.lateralMovement === true || a.transferAnomaly === true ||
                           a.ruleId === 'NET_THREAT_INTEL_SUMMARY' || 
                           a.ruleId === 'IDS_PORT_SCAN' || 
                           a.ruleId === 'NET_SCAN';

      const observedAt = alertTime(a);
      const timeStr = new Date(observedAt).toLocaleTimeString('en-IN', { hour12: false });

      if (isSuspicious) {
        const expandedEvidence = a?._recordType === 'alert' ? suspiciousConnectionEvidence(a) : [];
        const hasDirectConnection = Boolean(netDstIp(a))
          && netDstPort(a) !== '' && netDstPort(a) !== null && netDstPort(a) !== undefined;
        const evidenceRows = expandedEvidence.length ? expandedEvidence : (hasDirectConnection ? [a] : []);
        evidenceRows.forEach((connection) => {
          const evidenceTime = alertTime(connection) || observedAt;
          suspiciousConns.push({
            time: new Date(evidenceTime).toLocaleTimeString('en-IN', { hour12: false }),
            observedAt: evidenceTime,
            endpoint: alertHost(connection) || host,
            destIp: netDstIp(connection),
            port: netDstPort(connection),
            protocol: netProto(connection),
            process: netProcess(connection),
            threatInfo: a.description || a.message || (Array.isArray(a.detectionReasons) ? a.detectionReasons.join('; ') : '') || 'Suspicious Connection',
            severity: alertSeverity(a),
            completeness: Number(connection?._completeness || 0),
          });
        });
      }

      const port = Number(netDstPort(a));
      const lateralEvidence = a.lateralMovement === true
        || /lateral[ _-]?movement/i.test(`${a.ruleId || ''} ${a.subCategory || ''} ${a.detectionType || ''} ${a.description || ''}`);
      if (lateralEvidence) {
        lateralConns.push({
          source: host || netSrcIp(a) || 'unknown',
          destination: netDstIp(a) || 'unknown',
          protocol: port === 445 ? 'SMB' : port === 3389 ? 'RDP' : port === 22 ? 'SSH' : netProto(a),
          time: timeStr,
          status: a.description || 'Threshold crossed'
        });
      }
    });

    // This card and the modal header describe the same complete 24-hour
    // dataset (logical connections + change/detection events).
    const totalConns = Number(total ?? alerts.length);
    const finalEndpoints = Number(statistics.endpointsMonitored ?? uniqueHosts.size);
    const finalServers = Number(statistics.serversMonitored ?? uniqueServers.size);
    const finalSuspicious = Number(statistics.suspiciousConnections ?? suspiciousConns.length);

    // Group Top Talking Hosts
    const hostMap = {};
    peers.forEach(p => {
      const h = p.host;
      if (!hostMap[h]) {
        hostMap[h] = {
          name: h,
          type: (h.toLowerCase().includes('server') || h.toLowerCase().includes('gw') || h.toLowerCase().includes('linux')) ? 'Server' : 'Endpoint',
          connections: 0,
          sent: 0,
          received: 0
        };
      }
      hostMap[h].connections += p.connections;
      hostMap[h].sent += p.sent;
      hostMap[h].received += p.recv;
    });
    
    const talkingHosts = Object.values(hostMap).sort((a,b) => b.connections - a.connections).slice(0, 5);

    // Group Top External IPs
    const ipMap = {};
    peers.forEach(p => {
      const ip = p.remote_ip;
      if (!ipMap[ip]) {
        ipMap[ip] = { ip, country: p.country, countryCode: p.countryCode, connections: 0 };
      }
      ipMap[ip].connections += p.connections;
    });
    const externalIPs = Object.values(ipMap).sort((a,b) => b.connections - a.connections).slice(0, 5);

    // Protocol distribution
    let tcpCount = 0, udpCount = 0, dnsCount = 0, icmpCount = 0, otherCount = 0;
    alerts.forEach(a => {
      const p = String(a.protocol || '').toLowerCase();
      if (p === 'tcp') tcpCount++;
      else if (p === 'udp') udpCount++;
      else if (p === 'dns' || a.ruleId === 'NET_DNS_SUMMARY') dnsCount++;
      else if (p === 'icmp') icmpCount++;
      else otherCount++;
    });
    const protoTotal = tcpCount + udpCount + dnsCount + icmpCount + otherCount;
    const protoData = [
      { name: 'TCP', value: tcpCount, percent: ((tcpCount/protoTotal)*100).toFixed(1), color: MON.blue },
      { name: 'UDP', value: udpCount, percent: ((udpCount/protoTotal)*100).toFixed(1), color: MON.green },
      { name: 'DNS', value: dnsCount, percent: ((dnsCount/protoTotal)*100).toFixed(1), color: MON.yellow },
      { name: 'ICMP', value: icmpCount, percent: ((icmpCount/protoTotal)*100).toFixed(1), color: MON.red },
      { name: 'Others', value: otherCount, percent: ((otherCount/protoTotal)*100).toFixed(1), color: MON.purple }
    ].map(item => ({ ...item, percent: protoTotal ? item.percent : '0.0' }));

    // Connection Status
    let est = 0, listen = 0, tw = 0, cw = 0, otherStatus = 0;
    alerts.forEach(a => {
      const s = String(alertStatus(a)).toLowerCase();
      if (s === 'established' || s === 'active' || s === 'open') est++;
      else if (s === 'listening' || s === 'listen') listen++;
      else if (s === 'time_wait' || s === 'time wait') tw++;
      else if (s === 'close_wait' || s === 'close wait') cw++;
      else otherStatus++;
    });
    const statusTotal = est + listen + tw + cw + otherStatus;
    const statusData = [
      { name: 'Established', value: est, percent: ((est/statusTotal)*100).toFixed(1), color: MON.green },
      { name: 'Listening', value: listen, percent: ((listen/statusTotal)*100).toFixed(1), color: MON.blue },
      { name: 'Time Wait', value: tw, percent: ((tw/statusTotal)*100).toFixed(1), color: MON.yellow },
      { name: 'Close Wait', value: cw, percent: ((cw/statusTotal)*100).toFixed(1), color: MON.orange },
      { name: 'Other', value: otherStatus, percent: ((otherStatus/statusTotal)*100).toFixed(1), color: MON.purple }
    ].map(item => ({ ...item, percent: statusTotal ? item.percent : '0.0' }));

    // DNS queries donut
    let successDns = 0, failedDns = 0, nxdomainDns = 0;
    alerts.forEach(a => {
      const desc = String(a.description || '').toLowerCase();
      if (a.ruleId === 'DNS_CACHE_POISON_IP_CHANGE') failedDns++;
      else if (desc.includes('failed') || desc.includes('nxdomain')) nxdomainDns++;
      else successDns++;
    });
    const dnsTotal = successDns + failedDns + nxdomainDns;
    const dnsData = [
      { name: 'Successful', value: successDns, percent: ((successDns/dnsTotal)*100).toFixed(1), color: MON.green },
      { name: 'Failed', value: failedDns, percent: ((failedDns/dnsTotal)*100).toFixed(1), color: MON.red },
      { name: 'NXDOMAIN', value: nxdomainDns, percent: ((nxdomainDns/dnsTotal)*100).toFixed(1), color: MON.orange }
    ].map(item => ({ ...item, percent: dnsTotal ? item.percent : '0.0' }));
    const totalDnsQueries = dnsTotal;

    // Process Network Activity
    const procMap = {};
    peers.forEach(p => {
      const name = p.process;
      if (!procMap[name]) {
        procMap[name] = { process: name, connections: 0, sent: 0, received: 0 };
      }
      procMap[name].connections += p.connections;
      procMap[name].sent += p.sent;
      procMap[name].received += p.recv;
    });
    const finalProcesses = Object.values(procMap).sort((a,b) => b.connections - a.connections).slice(0, 5);

    // Port Activity is based only on agent socket records. Alert rows can be
    // aggregate detections without a single destination port and must not
    // create blank or inflated entries here.
    const portMap = new Map();
    alerts.filter(row => row?._recordType === 'connection').forEach(row => {
      const port = Number(netDstPort(row));
      if (!Number.isInteger(port) || port < 1 || port > 65535) return;
      const protocol = netProto(row);
      const key = `${port}/${protocol}`;
      if (!portMap.has(key)) {
        portMap.set(key, { port, protocol, connections: 0, rows: [] });
      }
      const entry = portMap.get(key);
      entry.connections += 1;
      entry.rows.push(row);
    });
    const finalPorts = Array.from(portMap.values())
      .map(entry => ({
        port: entry.port,
        protocol: entry.protocol,
        connections: entry.connections,
        trend: buildBuckets(entry.rows, 7, 24),
      }))
      .sort((left, right) => right.connections - left.connections || left.port - right.port)
      .slice(0, 5);

    return {
      totalConnections: totalConns,
      activeEndpoints: finalEndpoints,
      activeServers: finalServers,
      externalConnections: totalExt,
      suspiciousConnectionsCount: finalSuspicious,
      peers,
      dnsQueries,
      suspiciousConns: suspiciousConns
        .sort((left, right) => {
          const timeDelta = new Date(right.observedAt || 0).getTime() - new Date(left.observedAt || 0).getTime();
          return timeDelta || right.completeness - left.completeness;
        })
        .slice(0, 5),
      lateralConns: lateralConns.slice(0, 5),
      talkingHosts,
      externalIPs,
      protoData,
      statusData,
      dnsData,
      totalDnsQueries,
      finalProcesses,
      finalPorts
    };
  }, [alerts, total, statistics]);

  const jitterTotal = stats.totalConnections;
  const jitterEndpoints = stats.activeEndpoints;
  const jitterServers = stats.activeServers;
  const jitterExt = stats.externalConnections;
  const jitterSusp = stats.suspiciousConnectionsCount;
  // Mini sparkline data trends
  const connTrend = buildBuckets(alerts, 7, 24);
  const endptTrend = [jitterEndpoints, jitterEndpoints, jitterEndpoints, jitterEndpoints, jitterEndpoints, jitterEndpoints, jitterEndpoints];
  const servTrend = [jitterServers, jitterServers, jitterServers, jitterServers, jitterServers, jitterServers, jitterServers];
  const extTrend = connTrend;
  const suspTrend = buildBuckets(alerts.filter(a => ['high', 'critical'].includes(alertSeverity(a))), 7, 24);
  const uploadTrend = buildValueBuckets(alerts, netBytesSent, 12, 24);
  const downloadTrend = buildValueBuckets(alerts, netBytesRecv, 12, 24);

  const mappedAttacks = liveMap.connections;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* 1. Top KPI Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 12 }}>
        {[
          { title: 'Network Logs', value: jitterTotal, delta: 'Selected 24h window', trend: connTrend, color: MON.blue },
          { title: 'Active Endpoints', value: jitterEndpoints, delta: 'Observed hosts', trend: endptTrend, color: MON.green },
          { title: 'Active Servers', value: jitterServers, delta: 'Observed servers', trend: servTrend, color: MON.purple },
          { title: 'External Connections', value: jitterExt, delta: 'Observed external', trend: extTrend, color: MON.orange },
          { title: 'Suspicious Connections', value: jitterSusp, delta: 'High / critical', trend: suspTrend, color: MON.red }
        ].map((card, idx) => (
          <div key={idx} style={{ 
            background: 'radial-gradient(circle at 10% 10%, rgba(26,48,80,0.2) 0%, rgba(10,20,36,0.95) 100%)', 
            border: `1px solid ${card.color}40`, 
            borderRadius: 8, 
            padding: '12px 14px', 
            position: 'relative', 
            overflow: 'hidden',
            boxShadow: `0 4px 20px -2px rgba(0, 0, 0, 0.4)`
          }}>
            <div style={{ fontSize: 9, color: MON.muted, fontWeight: 800, textTransform: 'uppercase', letterSpacing: '0.5px' }}>{card.title}</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginTop: 8 }}>
              <div style={{ fontSize: 22, fontWeight: 900, color: '#f8fafc', fontFamily: 'monospace' }}>
                {idx === 0 ? Number(card.value || 0).toLocaleString('en-IN') : shortNum(card.value)}
              </div>
              <span style={{ fontSize: 9, fontWeight: 700, color: MON.muted }}>
                {card.delta}
              </span>
            </div>
            <div style={{ fontSize: 8, color: MON.sub, marginTop: 4 }}>Live database telemetry</div>
            
            {/* Sparkline overlay */}
            <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: 28, pointerEvents: 'none' }}>
              <CardSparkline data={card.trend} color={card.color} height={28} />
            </div>
          </div>
        ))}
      </div>

      {/* 2. Middle Row: Live Map, Top External IPs */}
      <div style={{ display: 'grid', gridTemplateColumns: '2.5fr 1fr', gap: 12 }}>
        {/* Live Network Connections */}
        <div style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Network Connections</span>
              <span style={{ color: MON.cyan, fontSize: 9, fontWeight: 800, border: `1px solid ${MON.cyan}66`, borderRadius: 3, padding: '2px 6px', background: 'rgba(0, 240, 255, 0.08)' }}>
                {Number(liveMap.total || 0).toLocaleString('en-IN')} ACTIVE • REAL TIME
              </span>
              <a href="/live-network-map" target="_blank" rel="noopener noreferrer" style={{ color: MON.cyan, fontSize: 9, textDecoration: 'none', fontWeight: 800, border: `1px solid ${MON.cyan}`, borderRadius: 3, padding: '2px 6px', background: 'rgba(0, 240, 255, 0.1)', cursor: 'pointer', transition: 'all 0.2s' }} onMouseEnter={(e) => { e.currentTarget.style.background = 'rgba(0, 240, 255, 0.25)' }} onMouseLeave={(e) => { e.currentTarget.style.background = 'rgba(0, 240, 255, 0.1)' }}>
                🗺️ Open Interactive Map in New Tab →
              </a>
            </div>
            <div style={{ display: 'flex', gap: 8, fontSize: 8 }}>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: MON.green }}>● Internal: <b>{shortNum(Math.max(0, jitterTotal - jitterExt))}</b></span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: MON.cyan }}>● Inbound: <b>{shortNum(liveMap.directionCounts.inbound)}</b></span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 4, color: MON.green }}>● Outbound: <b>{shortNum(liveMap.directionCounts.outbound)}</b></span>
            </div>
          </div>
          <NetworkConnectionMap
            height={320}
            connections={mappedAttacks}
            agents={liveMap.agents}
            total={liveMap.total}
            directionCounts={liveMap.directionCounts}
          />
        </div>

        {/* Top External IPs */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Top External IPs</div>
          <div style={{ display: 'grid', gap: 8 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 0.8fr', fontSize: 8, fontWeight: 800, color: MON.sub, textTransform: 'uppercase', borderBottom: `1px solid ${MON.line}`, paddingBottom: 6 }}>
              <span>IP Address</span><span>Country</span><span style={{ textAlign: 'right' }}>Connections</span>
            </div>
            {stats.externalIPs.map((ip, i) => {
              const maxConns = Math.max(...stats.externalIPs.map(x => x.connections), 1);
              const percent = (ip.connections / maxConns) * 100;
              return (
                <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 0.8fr', fontSize: 10, alignItems: 'center' }}>
                    <span style={{ color: MON.red, fontFamily: 'monospace', fontWeight: 800, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ip.ip}</span>
                    <span style={{ color: MON.text, fontSize: 9, display: 'flex', alignItems: 'center', gap: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      <span>{getFlagEmoji(ip.countryCode)}</span>
                      <span>{ip.country}</span>
                    </span>
                    <b style={{ color: MON.yellow, textAlign: 'right', fontFamily: 'monospace' }}>{ip.connections}</b>
                  </div>
                  {/* Performance bar */}
                  <div style={{ width: '100%', height: 3, background: MON.line, borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${percent}%`, height: '100%', background: `linear-gradient(90deg, ${MON.orange}, ${MON.red})`, borderRadius: 2 }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* 3. Row 3: Protocol, Status, Data Transfer, DNS Donut */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1.2fr 1.4fr 1.1fr', gap: 12 }}>
        <div style={panel}>
          <div style={{ fontSize: 10, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Protocol Distribution</div>
          <DonutChart data={stats.protoData} size={88} strokeWidth={8} totalValue={jitterTotal} />
        </div>
        <div style={panel}>
          <div style={{ fontSize: 10, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Connection Status</div>
          <DonutChart data={stats.statusData} size={88} strokeWidth={8} totalValue={jitterTotal} />
        </div>
        <div style={panel}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <span style={{ fontSize: 10, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Data Transfer (Total)</span>
            <div style={{ display: 'flex', gap: 6, fontSize: 8 }}>
              <span style={{ color: MON.green }}>● Upload: <b>{formatBytes(alerts.reduce((s, r) => s + netBytesSent(r), 0))}</b></span>
              <span style={{ color: MON.blue }}>● Download: <b>{formatBytes(alerts.reduce((s, r) => s + netBytesRecv(r), 0))}</b></span>
            </div>
          </div>
          <DataTransferChart upload={uploadTrend} download={downloadTrend} />
        </div>
        <div style={panel}>
          <div style={{ fontSize: 10, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>DNS Queries</div>
          <DonutChart data={stats.dnsData} size={88} strokeWidth={8} totalValue={stats.totalDnsQueries} />
        </div>
      </div>

      {/* 4. Row 4: Suspicious Connections */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr', gap: 12 }}>
        {/* Suspicious Connections */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Suspicious Connections</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
              <thead>
                <tr style={{ color: MON.sub, borderBottom: `1px solid ${MON.line}`, textAlign: 'left' }}>
                  <th style={{ padding: '6px 4px' }}>Time</th>
                  <th style={{ padding: '6px 4px' }}>Endpoint</th>
                  <th style={{ padding: '6px 4px' }}>Destination IP</th>
                  <th style={{ padding: '6px 4px' }}>Port</th>
                  <th style={{ padding: '6px 4px' }}>Proto</th>
                  <th style={{ padding: '6px 4px' }}>Process</th>
                  <th style={{ padding: '6px 4px', textAlign: 'right' }}>Threat Info</th>
                </tr>
              </thead>
              <tbody>
                {stats.suspiciousConns.map((row, i) => (
                  <tr key={i} style={{ borderBottom: i < stats.suspiciousConns.length - 1 ? `1px solid ${MON.line}80` : 'none', color: MON.text }}>
                    <td style={{ padding: '7px 4px', fontFamily: 'monospace', color: MON.muted }}>{row.time}</td>
                    <td style={{ padding: '7px 4px', fontWeight: 700 }}>{row.endpoint}</td>
                    <td style={{ padding: '7px 4px', fontFamily: 'monospace', color: MON.red }}>{row.destIp}</td>
                    <td style={{ padding: '7px 4px', fontFamily: 'monospace' }}>{row.port}</td>
                    <td style={{ padding: '7px 4px', fontWeight: 800, color: MON.green }}>{row.protocol}</td>
                    <td style={{ padding: '7px 4px', color: MON.purple }}>{row.process}</td>
                    <td style={{ padding: '7px 4px', textAlign: 'right', color: MON.red, fontWeight: 800 }}>{row.threatInfo}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: 9, color: MON.cyan, textAlign: 'right', marginTop: 10, cursor: 'pointer' }}>
            View All Suspicious Connections →
          </div>
        </div>

      </div>

      {/* 5. Row 5: Process activity, Port activity, Lateral movement */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.1fr', gap: 12 }}>
        {/* Process network activity */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Process Network Activity (Top 5)</div>
          <div style={{ display: 'grid', gap: 8 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr 1fr', fontSize: 8, fontWeight: 800, color: MON.sub, textTransform: 'uppercase', borderBottom: `1px solid ${MON.line}`, paddingBottom: 6 }}>
              <span>Process</span><span>Conns</span><span>Sent</span><span>Received</span>
            </div>
            {stats.finalProcesses.map((p, i) => {
              const psum = p.sent + p.received;
              const maxsum = Math.max(...stats.finalProcesses.map(x => x.sent + x.received), 1);
              const barPercent = (psum / maxsum) * 100;
              return (
                <div key={i} style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: '1.5fr 1fr 1fr 1fr', fontSize: 10, alignItems: 'center' }}>
                    <span style={{ color: MON.cyan, fontWeight: 800, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {p.process === 'chrome.exe' ? '🌐 ' : p.process === 'powershell.exe' ? '🐚 ' : '⚙️ '}
                      {p.process}
                    </span>
                    <span style={{ fontFamily: 'monospace' }}>{shortNum(p.connections)}</span>
                    <span style={{ color: MON.muted, fontFamily: 'monospace' }}>{formatBytes(p.sent).split(' ')[0]}</span>
                    <span style={{ color: MON.text, fontFamily: 'monospace' }}>{formatBytes(p.received)}</span>
                  </div>
                  {/* visual progress bar */}
                  <div style={{ width: '100%', height: 3, background: MON.line, borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${barPercent}%`, height: '100%', background: MON.blue, borderRadius: 2 }} />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Port activity */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Port Activity (Top 5)</div>
          <div style={{ display: 'grid', gap: 8 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr 1fr', fontSize: 8, fontWeight: 800, color: MON.sub, textTransform: 'uppercase', borderBottom: `1px solid ${MON.line}`, paddingBottom: 6 }}>
              <span>Port</span><span>Protocol</span><span>Connections</span><span style={{ textAlign: 'right' }}>Trend</span>
            </div>
            {stats.finalPorts.map((p, i) => (
              <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1.2fr 1fr', fontSize: 10, alignItems: 'center', height: 26 }}>
                <b style={{ color: MON.yellow, fontFamily: 'monospace' }}>{p.port}</b>
                <span style={{ color: MON.muted, fontWeight: 700 }}>{p.protocol}</span>
                <span style={{ fontFamily: 'monospace' }}>{shortNum(p.connections)}</span>
                <div style={{ width: 44, height: 18, justifySelf: 'end' }}>
                  <CardSparkline data={p.trend || []} color={p.port === 22 || p.port === 3389 ? MON.orange : MON.green} height={18} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Lateral Movement Detection */}
        <div style={panel}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#f1f5f9', textTransform: 'uppercase', letterSpacing: '0.5px', marginBottom: 12 }}>Lateral Movement Detection</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10 }}>
              <thead>
                <tr style={{ color: MON.sub, borderBottom: `1px solid ${MON.line}`, textAlign: 'left' }}>
                  <th style={{ padding: '6px 4px' }}>Source</th>
                  <th style={{ padding: '6px 4px' }}>Destination</th>
                  <th style={{ padding: '6px 4px' }}>Proto</th>
                  <th style={{ padding: '6px 4px' }}>Time</th>
                  <th style={{ padding: '6px 4px', textAlign: 'right' }}>Status</th>
                </tr>
              </thead>
              <tbody>
                {stats.lateralConns.map((row, i) => (
                  <tr key={i} style={{ borderBottom: i < stats.lateralConns.length - 1 ? `1px solid ${MON.line}80` : 'none', color: MON.text }}>
                    <td style={{ padding: '7px 4px', fontWeight: 800, color: MON.cyan }}>{row.source}</td>
                    <td style={{ padding: '7px 4px', fontFamily: 'monospace', color: MON.red }}>{row.destination}</td>
                    <td style={{ padding: '7px 4px', fontWeight: 800, color: MON.green }}>{row.protocol}</td>
                    <td style={{ padding: '7px 4px', fontFamily: 'monospace', color: MON.muted }}>{row.time}</td>
                    <td style={{ padding: '7px 4px', textAlign: 'right', color: MON.red, fontWeight: 800 }}>
                      <span style={{ marginRight: 4, animation: 'pulse 1s infinite', color: MON.red }}>●</span>
                      {row.status}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ fontSize: 9, color: MON.cyan, textAlign: 'right', marginTop: 10, cursor: 'pointer' }}>
            View All Lateral Movement Alerts →
          </div>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. MAIN DASHBOARD COMPONENT (`NetworkActivityDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function NetworkActivityDashboard({ alerts = [], loading = false, total = 0, recordsTotal = 0, networkLogTotal, systems = [], statistics = {}, loadError = '', companyId = '', onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);

  useEffect(() => {
    if (systems.length) { setBackendSystems(systems); return; }
    let active = true;
    api.get('/system')
      .then(r => {
        if (!active) return;
        const rows = r.data?.systems || r.data?.agents || r.data || [];
        setBackendSystems(Array.isArray(rows) ? rows : []);
      })
      .catch(() => { if (active) setBackendSystems([]); });
    return () => { active = false; };
  }, [systems]);

  const cutoff24h = Date.now() - 24 * 3600000;
  const rows = (Array.isArray(alerts) ? alerts : []).filter(row => {
    const timestamp = alertTime(row);
    if (!timestamp) return false;
    const parsed = new Date(timestamp).getTime();
    return Number.isFinite(parsed) && parsed >= cutoff24h && parsed <= Date.now();
  });
  const selected24hLogTotal = rows.filter(isNetworkLogRow).length;
  const connectionRows = rows.filter(row => row?._recordType === 'connection');
  const detectionRows = rows.filter(row => row?._recordType === 'alert');
  const osCounts = connectionRows.reduce((acc, row) => {
    const os = processOs(row);
    acc[os] = (acc[os] || 0) + 1;
    return acc;
  }, {});

  const timeline = buildBuckets(rows, 8, 24);

  // Monitoring KPIs use server-side aggregates when present. Fallbacks are
  // deliberately split between connection inventory and alert detections so
  // a single event is never counted as both a socket and an alert.
  const metric = (key, fallback = 0) => Object.prototype.hasOwnProperty.call(statistics || {}, key)
    ? Number(statistics[key] || 0)
    : fallback;
  const activeConnCount = connectionRows.filter(r => /established|active|open/i.test(alertStatus(r))).length;
  const listeningPortCount = connectionRows.filter(r => /listen/i.test(alertStatus(r))).length;
  const c2BeaconCount = detectionRows.filter(r => containsAny(r, ['c2', 'beacon', 'callback', 'periodic'])).length;
  const torVpnCount = detectionRows.filter(r => r.geoVpn === true || r.geoTor === true || r.geoProxy === true
    || containsAny(r, ['tor', 'vpn', 'proxy', 'exit node'])).length;
  const dnsQueryCount = detectionRows.filter(r => netProto(r) === 'DNS' || containsAny(r, ['dns', 'domain', 'nxdomain'])).length;
  const failedDnsCount = detectionRows.filter(r => /nxdomain|servfail|refused/i.test(String(r.responseCode || ''))
    || containsAny(r, ['failed dns', 'nxdomain', 'dns fail', 'servfail'])).length;
  const webTrafficCount = connectionRows.filter(r => [80, 443, 8080, 8443].includes(Number(netDstPort(r)))).length;
  const uploadBytesTotal = metric('bytesSent', connectionRows.reduce((sum, r) => sum + netBytesSent(r), 0));
  const downloadBytesTotal = metric('bytesReceived', connectionRows.reduce((sum, r) => sum + netBytesRecv(r), 0));
  const exfilCount = detectionRows.filter(r => containsAny(r, ['exfil', 'large upload', 'transfer anomaly', 'archive staging'])).length;
  const processCorrCount = connectionRows.filter(r => !['', 'unknown', '—'].includes(String(netProcess(r)).trim().toLowerCase())).length;
  const portScanCount = detectionRows.filter(r => containsAny(r, ['port scan', 'recon', 'sweep', 'nmap', 'network scan'])).length;
  const lateralCount = detectionRows.filter(r => r.lateralMovement === true
    || /lateral[ _-]?movement/i.test(`${r.ruleId || ''} ${r.subCategory || ''} ${r.detectionType || ''} ${r.description || ''}`)).length;
  const remoteToolsCount = connectionRows.filter(r => [22, 3389, 5900, 5938].includes(Number(netDstPort(r)))
    || containsAny(r, ['anydesk', 'teamviewer', 'logmein', 'vnc', 'remote desktop'])).length;
  const eastWestCount = connectionRows.filter(r => String(r.direction || '').toLowerCase() === 'internal').length;
  const cloudCount = connectionRows.filter(r => containsAny(r, ['aws', 'amazonaws', 'azure', 'microsoftonline', 'googleapis', 'cloudflare', 'dropbox', 'slack', 'salesforce'])).length;
  const endpointCount = new Set(rows.map(alertHost).filter(host => host && host !== 'unknown')).size;
  const serverCount = new Set(connectionRows.filter(row => String(row.assetType || '').toLowerCase() === 'server').map(alertHost)).size;
  const suspiciousConnectionCount = connectionRows.filter(row => Number(row.riskScore || 0) >= 41).length;
  const vpnRows = connectionRows.filter(r => [500, 1701, 1723, 4500, 51820, 1194].includes(Number(netDstPort(r)))
    || containsAny(r, ['wireguard', 'openvpn', 'proton', 'nordvpn', 'expressvpn', 'surfshark', 'mullvad', 'anyconnect', 'globalprotect', 'tun0', 'tap0', 'wg0']));
  const vpnDataUsed = metric('vpnDataTransferred', vpnRows.reduce((sum, row) => sum + netBytesSent(row) + netBytesRecv(row), 0));
  const hasConnectionTelemetry = Object.prototype.hasOwnProperty.call(statistics || {}, 'totalConnections') || connectionRows.length > 0;
  const connectionValue = hasConnectionTelemetry ? shortNum(metric('totalConnections', connectionRows.length)) : 'No telemetry';
  const activeConnectionValue = hasConnectionTelemetry ? shortNum(metric('activeConnections', activeConnCount)) : 'No telemetry';

  const kpis = [
    { label: '🌐 Total Connections (24h)', val: connectionValue, trend: hasConnectionTelemetry ? 'Rolling 24h' : 'Collector silent', color: MON.green, data: timeline },
    { label: '🔗 Active Connections', val: activeConnectionValue, trend: hasConnectionTelemetry ? 'Live state' : 'Collector silent', color: MON.blue, data: timeline },
    { label: '💻 Endpoints Monitored', val: shortNum(metric('endpointsMonitored', endpointCount)), trend: 'Reporting ≤24h', color: MON.cyan, data: timeline },
    { label: '🏢 Servers Monitored', val: shortNum(metric('serversMonitored', serverCount)), trend: 'Reporting ≤24h', color: MON.purple, data: timeline },
    { label: '⚠️ Suspicious Connections', val: shortNum(metric('suspiciousConnections', suspiciousConnectionCount)), trend: 'Risk ≥41', color: MON.red, data: timeline },
    { label: '🚨 Network Alerts', val: shortNum(metric('networkAlerts', detectionRows.length)), trend: 'Rolling 24h', color: MON.orange, data: timeline },
    { label: '🔍 DNS Queries', val: shortNum(metric('dnsQueries', dnsQueryCount)), trend: 'Rolling 24h', color: MON.cyan, data: timeline },
    { label: '📦 Data Transferred', val: formatBytes(metric('dataTransferred', uploadBytesTotal + downloadBytesTotal)), trend: 'Observed bytes', color: MON.green, data: timeline },
    { label: '🔌 Listening Services & Ports', val: hasConnectionTelemetry ? shortNum(metric('listeningServices', listeningPortCount)) : 'No telemetry', trend: hasConnectionTelemetry ? 'Observed evidence' : 'Collector silent', color: MON.blue, data: timeline },
    { label: '🚨 C2 & Beaconing Detections', val: shortNum(metric('c2BeaconDetections', c2BeaconCount)), trend: 'Risk-scored', color: MON.red, data: timeline },
    { label: '🔒 TOR & VPN Anonymizers', val: shortNum(metric('torVpnAnonymizers', torVpnCount)), trend: 'Observed evidence', color: MON.purple, data: timeline },
    { label: '🔐 VPN Data Used', val: formatBytes(vpnDataUsed), trend: metric('vpnActiveEndpoints') > 0 ? `${metric('vpnActiveEndpoints')} active endpoint(s)` : metric('vpnEndpointsUsed') > 0 ? `${metric('vpnEndpointsUsed')} used VPN in 24h${statistics.vpnUsageEstimated ? ' • host estimate' : ''}` : 'VPN not observed', color: MON.pink, data: timeline },
    { label: '⚠️ Failed DNS (NXDOMAIN)', val: shortNum(metric('failedDns', failedDnsCount)), trend: 'Observed evidence', color: MON.yellow, data: timeline },
    { label: '🌍 Web Requests (HTTP/HTTPS)', val: shortNum(metric('webRequests', webTrafficCount)), trend: 'Observed evidence', color: MON.green, data: timeline },
    { label: '📤 Upload Traffic (Outbound)', val: formatBytes(uploadBytesTotal), trend: 'Observed bytes', color: MON.orange, data: timeline },
    { label: '📥 Download Traffic (Inbound)', val: formatBytes(downloadBytesTotal), trend: 'Observed bytes', color: MON.cyan, data: timeline },
    { label: '🚨 Large Exfiltration Alerts', val: shortNum(metric('exfiltrationAlerts', exfilCount)), trend: 'Risk-scored', color: MON.red, data: timeline },
    { label: '🖥️ Process-to-Network Mappings', val: shortNum(metric('processMappings', processCorrCount)), trend: 'Correlated', color: MON.purple, data: timeline },
    { label: '📡 Port Scan / Recon Detection', val: shortNum(metric('portScanDetections', portScanCount)), trend: 'Threshold-based', color: MON.red, data: timeline },
    { label: '↔️ Lateral Movement (SMB/RDP)', val: shortNum(metric('lateralMovement', lateralCount)), trend: 'Threshold-based', color: MON.orange, data: timeline },
    { label: '🖥️ Remote Admin Tools', val: shortNum(metric('remoteAdminTools', remoteToolsCount)), trend: 'Observed evidence', color: MON.yellow, data: timeline },
    { label: '🏢 East-West Internal Traffic', val: shortNum(metric('eastWestTraffic', eastWestCount)), trend: 'Observed evidence', color: MON.blue, data: timeline },
    { label: '☁️ Cloud & SaaS Connections', val: shortNum(metric('cloudSaasConnections', cloudCount)), trend: 'Observed evidence', color: MON.cyan, data: timeline },
    { label: '💻 Windows Endpoint Signals', val: shortNum(metric('windowsSignals', osCounts.Windows || 0)), trend: 'Real telemetry', color: MON.cyan, data: timeline },
    { label: '🐧 Linux Server Signals', val: shortNum(metric('linuxSignals', osCounts.Linux || 0)), trend: 'Real telemetry', color: MON.orange, data: timeline },
    { label: '🌐 Web Server Traffic', val: shortNum(metric('webServerTraffic', connectionRows.filter(r => containsAny(r, ['nginx', 'apache', 'httpd', 'iis'])).length)), trend: 'Observed evidence', color: MON.green, data: timeline },
    { label: '🗄️ Database Connection Traffic', val: shortNum(metric('databaseTraffic', connectionRows.filter(r => [1433, 1521, 3306, 5432, 6379, 27017].includes(Number(netDstPort(r))) || containsAny(r, ['mysql', 'postgres', 'mongo', 'oracle', 'redis', 'sqlserver'])).length)), trend: 'Observed evidence', color: MON.purple, data: timeline },
  ];

  const agentStatusRows = backendSystems.filter(sys => {
    const seen = sys.lastSeen ? new Date(sys.lastSeen).getTime() : 0;
    const host = sys.hostname || sys.name || 'unknown';
    return seen >= cutoff24h || rows.some(row => normHost(alertHost(row)) === normHost(host));
  }).map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'unknown'),
      monitor: hostEvents > 0,
      events: hostEvents,
      threats,
      platform: processOs(sys),
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
        {loadError && (
          <div role="alert" style={{ background: 'rgba(248,113,113,.12)', border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 7, padding: '10px 12px', fontSize: 11 }}>
            {loadError}
          </div>
        )}
        {activeTab === 'log-monitor' ? (
          <NetworkLogMonitor alerts={alerts} total={selected24hLogTotal} onSaved={onRefresh} />
        ) : activeTab === 'reports' ? (
          <NetworkReportsTab alerts={alerts} companyId={companyId} />
        ) : activeTab === 'dashboard' ? (
          <NetworkOverviewDashboard alerts={alerts} total={selected24hLogTotal} systems={backendSystems} statistics={statistics} />
        ) : (
          <>
            {/* Live KPI Cards Grid */}
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
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Monitored Infrastructure (Network Telemetry Active)</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints with real network telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Telemetry State</span><span>Events</span><span>Threat Alerts</span><span>Last Seen</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.monitor ? 'Reporting' : 'Idle'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : 'Never'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend network agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Network Traffic & Socket Trend (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(connectionRows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} network events`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🌐 Top Remote Destination IPs</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(connectionRows, netDstIp, 5).map(([ip, count], index) => (
                    <div key={ip} style={{ display: 'flex', justifyContent: 'space-between', fontFamily: 'monospace' }}>
                      <span style={{ color: MON.red, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{ip}</span>
                      <span style={{ color: [MON.blue, MON.cyan, MON.purple][index % 3], fontWeight: 800 }}>{count} connections</span>
                    </div>
                  ))}
                  {!topCounts(connectionRows, netDstIp, 5).length && <div style={{ color: MON.muted }}>No destination telemetry</div>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📦 Network Traffic Category Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['Established TCP/UDP', metric('activeConnections', activeConnCount)],
                    ['C2, TOR & Beaconing', metric('c2BeaconDetections', c2BeaconCount) + metric('torVpnAnonymizers', torVpnCount)],
                    ['DNS & Web Activity', metric('dnsQueries', dnsQueryCount) + metric('webRequests', webTrafficCount)],
                    ['Exfiltration & Lateral', metric('exfiltrationAlerts', exfilCount) + metric('lateralMovement', lateralCount)],
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
// 4. OVERLAY CAPABILITY MODAL EXPORT (`NetworkActivityMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function NetworkActivityMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '3';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [loadError, setLoadError] = useState('');

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    setLoadError('');
    try {
      const params = {
        page: 1,
        limit: 0,
        hours: 24,
        ...(companyId ? { companyId: String(companyId) } : {}),
      };
      const [connectionsResult, alertsResult, statisticsResult] = await Promise.allSettled([
        api.get('/network/connections', { params, skipCache: true }),
        api.get('/network/alerts', { params, skipCache: true }),
        api.get('/network/statistics', {
          params: { hours: 24, ...(companyId ? { companyId: String(companyId) } : {}) },
          skipCache: true,
        }),
      ]);
      if (connectionsResult.status === 'rejected' && alertsResult.status === 'rejected') {
        throw connectionsResult.reason || alertsResult.reason;
      }
      const connections = connectionsResult.status === 'fulfilled'
        ? (connectionsResult.value.data?.connections || []).map(row => ({ ...row, _recordType: 'connection' }))
        : [];
      const networkAlerts = alertsResult.status === 'fulfilled'
        ? (alertsResult.value.data?.alerts || []).map(row => ({ ...row, _recordType: 'alert' }))
        : [];
      const cutoff = Date.now() - 24 * 3600000;
      const next = mergeNetworkLogRows(connections, networkAlerts)
        .filter(row => {
          const timestamp = alertTime(row);
          const parsed = timestamp ? new Date(timestamp).getTime() : NaN;
          return Number.isFinite(parsed) && parsed >= cutoff && parsed <= Date.now();
        })
        .sort((a, b) => new Date(alertTime(b)).getTime() - new Date(alertTime(a)).getTime());
      const nextStats = statisticsResult.status === 'fulfilled' ? (statisticsResult.value.data || {}) : {};
      setAlerts(next);
      setStatistics(nextStats);
      setTotal(next.length);
      if ([connectionsResult, alertsResult, statisticsResult].some(result => result.status === 'rejected')) {
        setLoadError('Partial network data loaded. One or more 24-hour telemetry services are temporarily unavailable.');
      }
    } catch (error) {
      setAlerts([]);
      setStatistics({});
      setTotal(0);
      const status = error?.response?.status;
      setLoadError(status === 401 || status === 403
        ? 'You do not have permission to view this company network telemetry.'
        : 'Live 24-hour network telemetry could not be loaded. Verify backend and agent connectivity.');
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [capabilityId, companyId]);

  const loadSystems = useCallback(async () => {
    try {
      const r = await api.get('/system');
      setSystems(Array.isArray(r.data?.systems || r.data) ? (r.data?.systems || r.data) : []);
    } catch {
      setSystems([]);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    loadSystems();
    const interval = setInterval(() => loadAlerts(true), 15000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('network:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('network:event', buf.add);
      buf.clear();
      disc();
    };
  }, [companyId, loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🛡️ 3. Network Activity Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(alerts.filter(isNetworkLogRow).length || total || 0).toLocaleString('en-IN')} loaded logs (rolling 24H)
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <NetworkActivityDashboard alerts={alerts} loading={loading} total={total} systems={systems} statistics={statistics} loadError={loadError} companyId={companyId} onRefresh={() => loadAlerts(true)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <NetworkActivityMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function NetworkSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=3" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Network Monitoring SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=3')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="network" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <NetworkActivityDashboard />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { NetworkActivityDashboard as NetworkActivityDashboardPanel };
