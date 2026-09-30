/**
 * Email Threat Monitoring — Capability ID: 15
 *
 * 100% Self-Contained Enterprise SOC Email Threat & Phishing Protection Module
 * Linked to endpoint-agent webmail/mail-application telemetry, MongoDB alert queries, and Socket.io real-time streaming.
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13) & Lateral Movement (14)
 */
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions , io} from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens ──────────────────────────────────────────────────
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

function normHost(h) {
  return String(h || 'unknown').trim().toLowerCase();
}

function alertTime(row) {
  return row?.timestamp || row?.createdAt || row?.time || row?.observedAt || row?.updatedAt;
}

function alertHost(row) {
  return row?.hostname || row?.host || row?.agentName || row?.systemId?.hostname || row?.systemId?.name || 'unknown';
}

function alertUser(row) {
  return row?.username || row?.user || row?.emailRecipient || row?.recipient || row?.userName || '—';
}

function alertStatus(row) {
  return row?.status || row?.emailStatus || row?.state || 'open';
}

function alertSeverity(row) {
  const s = String(row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const osStr = String(row?.osType || row?.os || row?.platform || row?.systemId?.osType || row?.systemId?.os || row?.system || row?.hostname || row?.host || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS';
  return 'Unknown';
}

// ── Email Threat Telemetry Field Extractors ────────────────────────────────
function emailSubject(row) {
  return row?.emailSubject || row?.subject || row?.title || row?.description || '—';
}

function emailSender(row) {
  const actualSender = row?.emailSender || row?.sender || row?.from;
  if (actualSender) return actualSender;
  const metadata = row?.rawEvent?.raw || row?.raw || {};
  const source = metadata?.webmail_provider || metadata?.mail_source_label || metadata?.provider
    || (isAttachmentDownload(row) ? 'Webmail / Mail Client' : '');
  return source ? `${source} (source; address unavailable)` : '—';
}

function emailRecipient(row) {
  const actualRecipient = row?.emailRecipient || row?.recipient;
  if (actualRecipient) return actualRecipient;
  const monitoredUser = row?.username || row?.user || row?.rawEvent?.username
    || row?.rawEvent?.raw?.monitored_user || row?.raw?.monitored_user;
  if (monitoredUser) return `${monitoredUser} (monitored user)`;
  if (isAttachmentDownload(row)) return `Endpoint: ${alertHost(row)}`;
  return '—';
}

function emailThreatType(row) {
  const rule = String(row?.ruleId || row?.eventType || '').toUpperCase();
  if (/WEBMAIL_SESSION/.test(rule)) return 'Webmail Activity';
  if (/WEBMAIL_LINK_OPEN|EMAIL_LINK_OPEN/.test(rule)) return row?.actionable ? 'Suspicious Email URL' : 'Email URL Opened';
  if (/ATTACHMENT_DOWNLOAD/.test(rule)) return row?.actionable ? 'Suspicious Attachment' : 'Email Attachment Download';
  if (/ATTACHMENT_EXECUT|PAYLOAD|SUSPICIOUS_CHILD/.test(rule)) return 'Email Attachment Execution';
  if (/MAIL_COMPONENT/.test(rule)) return 'Mail Application Activity';
  const value = row?.threatCategory || row?.threatType || row?.ruleId || row?.eventType || row?.action;
  return value ? String(value).replace(/[_-]+/g, ' ').replace(/\b\w/g, char => char.toUpperCase()) : 'Not reported';
}

function emailUrl(row) {
  const value = row?.url || row?.targetUrl || row?.target_url || row?.rawEvent?.url
    || row?.rawEvent?.targetUrl || row?.rawEvent?.target_url || row?.rawEvent?.raw?.url
    || row?.raw?.url || '';
  if (/(?:\/\/localhost(?::\d+)?|\/\/127\.0\.0\.1(?::\d+)?|\/company-admin\/edr)/i.test(String(value))) return '';
  return value;
}

function emailUrlDisplay(row) {
  const value = emailUrl(row);
  if (value) return value;
  return /mail_component/i.test(String(row?.ruleId || row?.eventType || '')) ? 'Not applicable (desktop mail app)' : 'Not reported';
}

function emailRiskScore(row) {
  return Number(row?.riskScore ?? row?.score ?? 0);
}

function emailDirection(row) {
  return String(row?.emailDirection || row?.rawEvent?.emailDirection || row?.rawEvent?.email_direction || 'unknown').toLowerCase();
}

function containsAny(row, words = []) {
  const haystack = [
    emailSubject(row), emailSender(row), emailRecipient(row), emailThreatType(row), alertHost(row),
    row?.description, row?.message, row?.attachment, row?.fileName, row?.filePath, emailUrl(row),
  ].filter(Boolean).join(' ').toLowerCase();
  return words.some(word => haystack.includes(word));
}

function buildBuckets(rows = [], bucketCount = 12, hours = 24, predicate = () => true) {
  const now = Date.now();
  const start = now - hours * 3600000;
  const bucketMs = (hours * 3600000) / bucketCount;
  const buckets = Array(bucketCount).fill(0);
  rows.forEach(row => {
    if (!predicate(row)) return;
    const t = alertTime(row);
    const ms = t ? new Date(t).getTime() : NaN;
    if (!Number.isFinite(ms) || ms < start || ms > now) return;
    const idx = Math.min(bucketCount - 1, Math.max(0, Math.floor((ms - start) / bucketMs)));
    buckets[idx] += 1;
  });
  return buckets;
}

function emailAuthValue(row, method) {
  return String(row?.emailAuth?.[method] || row?.rawEvent?.email_auth?.[method] || row?.rawEvent?.emailAuth?.[method] || '').toLowerCase();
}

function isQuarantined(row) {
  return row?.quarantined === true || /quarantin/i.test(`${row?.containmentStatus || ''} ${row?.actionTaken || ''} ${row?.action || ''}`);
}

function isAttachmentDownload(row) {
  return /(?:email_)?attachment_download(?:ed)?/i.test(`${row?.eventType || ''} ${row?.ruleId || ''}`);
}

function emailCategoryKey(row) {
  if (containsAny(row, ['credential', 'harvest', 'fake login'])) return 'credential';
  if (containsAny(row, ['business email compromise', 'bec', 'wire fraud', 'ceo fraud'])) return 'bec';
  if (containsAny(row, ['suspicious_attachment', 'attachment_malware', 'malicious attachment', 'macro', 'payload', 'emotet', 'qakbot', 'agenttesla'])) return 'malware';
  if (containsAny(row, ['spam', 'bulk mail', 'unsolicited'])) return 'spam';
  if (containsAny(row, ['phish', 'spoof', 'typosquat', 'suspicious_url', 'link_open'])) return 'phishing';
  return 'other';
}

function percentItems(definitions, total) {
  return definitions.map(item => ({
    ...item,
    count: Number(item.count || 0),
    pct: total ? Number((Number(item.count || 0) / total * 100).toFixed(1)) : 0,
  }));
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${emailSender(row)}-${emailSubject(row)}`;
}

function csvCell(val) {
  const str = String(val ?? '').replace(/"/g, '""');
  return `"${str}"`;
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

function reported(value, fallback = 'Not reported') {
  if (value === undefined || value === null || value === '') return fallback;
  return value;
}

function emailAuthSummary(row) {
  const auth = row?.emailAuth || row?.rawEvent?.emailAuth || row?.rawEvent?.email_auth || {};
  const entries = ['spf', 'dkim', 'dmarc']
    .filter(key => auth?.[key])
    .map(key => `${key.toUpperCase()}: ${String(auth[key]).toUpperCase()}`);
  return entries.length ? entries.join(' | ') : 'Not reported by mail provider';
}

function emailTimeline(row) {
  const items = [];
  const add = (type, at, title, description, col = MON.cyan) => {
    if (!at) return;
    const parsed = new Date(at);
    if (Number.isNaN(parsed.getTime())) return;
    items.push({ type, at: parsed, title, description: description || 'No additional detail reported.', col });
  };
  add('Detection', alertTime(row), row?.ruleId || row?.eventType || 'Email telemetry received', row?.description || row?.message, SEV_COLOR[alertSeverity(row)] || MON.cyan);
  (Array.isArray(row?.investigationTimeline) ? row.investigationTimeline : []).forEach(item => {
    add(item?.type || 'Investigation', item?.at, item?.type || 'Investigation update', item?.detail, MON.blue);
  });
  (Array.isArray(row?.auditHistory) ? row.auditHistory : []).forEach(item => {
    add('Audit', item?.at, item?.action || 'Alert updated', item?.metadata ? JSON.stringify(item.metadata) : '', MON.purple);
  });
  add('Containment', row?.isolatedAt || row?.tiBlockedAt || row?.resolvedAt,
    row?.resolvedAt ? 'Alert resolved' : reported(row?.actionTaken || row?.containmentStatus, 'Containment updated'),
    row?.isolationReason || row?.recommendedAction || row?.containmentStatus, MON.green);
  return items.sort((a, b) => a.at - b.at);
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function EmailThreatLogDetailModal({ log: initialLog, onClose, onSaved }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [liveLog, setLiveLog] = useState(initialLog);
  const [analystNotes, setAnalystNotes] = useState('');
  const [caseStatus, setCaseStatus] = useState(initialLog?.status || 'open');
  const [actionMessage, setActionMessage] = useState('');
  const [savingNotes, setSavingNotes] = useState(false);
  const [quarantining, setQuarantining] = useState(false);
  const log = liveLog || initialLog;

  // Forensic Hunt Specific State
  const [selectedArtifact, setSelectedArtifact] = useState('Windows.EventLogs.EvtxHunter');
  const [selectedArtifactTitle, setSelectedArtifactTitle] = useState('Windows Security EVTX Hunter');
  const [huntNameInput, setHuntNameInput] = useState(`${initialLog?.hostname || 'endpoint'} email threat hunt`);
  const [launchingHunt, setLaunchingHunt] = useState(false);
  const [huntSuccessMsg, setHuntSuccessMsg] = useState(null);

  useEffect(() => {
    setLiveLog(initialLog);
    setCaseStatus(initialLog?.status || 'open');
    if (!initialLog?._id) return undefined;
    let active = true;
    const refresh = async () => {
      try {
        const response = await api.get(`/email-threat/log/${initialLog._id}`, { skipCache: true });
        if (active && response.data?.event) setLiveLog({ ...initialLog, ...response.data.event });
      } catch {
        // Keep the selected socket/list row visible if retention races refresh.
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
  const timelineEvents = emailTimeline(log);
  const systemId = log?.systemId?._id || log?.systemId || '';
  const companyId = log?.companyId?._id || log?.companyId || '';
  const assignedAnalyst = log?.assignedTo?.name || log?.assignedTo?.email || log?.assignedAnalyst || 'Unassigned';
  const tags = Array.isArray(log?.tags) ? log.tags.join(', ') : (log?.tags || 'None reported');
  const mitreMappings = [...new Set([
    log?.mitreId, log?.mitreTechnique, log?.technique,
    ...(Array.isArray(log?.mitreTechniques) ? log.mitreTechniques : []),
  ].filter(Boolean))];

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'timeline', label: '🕒 2. Timeline' },
    { id: 'endpoint', label: '💻 3. Host & Mailbox' },
    { id: 'process', label: '⚙️ 4. Process & LOLBins' },
    { id: 'attachment', label: '📎 5. Attachment & Sandbox' },
    { id: 'url', label: '🌐 6. URL & Domain Intel' },
    { id: 'ioc', label: '🎯 7. IOC & MITRE ATT&CK' },
    { id: 'forensics', label: '🔬 8. Forensics (Velociraptor)' },
    { id: 'evidence', label: '📦 9. Evidence & Quarantine' },
    { id: 'notes', label: '📝 10. Analyst Notes' },
  ];

  const forensicHuntCards = [
    { title: 'Mail Client Process & EVTX Hunter', desc: 'Scan Event Logs & Process Trees for Outlook/Thunderbird spawning PowerShell or CMD.', artifact: 'Windows.EventLogs.EvtxHunter' },
    { title: 'Memory & RAM Dump', desc: 'Dump process RAM of Outlook.exe, WINWORD.exe, and injected DLLs.', artifact: 'Windows.Memory.Acquisition' },
    { title: 'Linux Mail & Auth Log Hunter', desc: 'Inspect mail.log, postfix, sendmail, and user mailbox forward rules.', artifact: 'Linux.Sys.LogHunter' },
    { title: 'Active Mail Client Processes', desc: 'Audit processes holding open network connections to external SMTP/IMAP servers.', artifact: 'Linux.Sys.Pslist' },
    { title: 'YARA Phishing & Macro Sweep', desc: 'Run YARA sweeps for Emotet, Qakbot, AgentTesla, and credential harvesting kits.', artifact: 'Generic.Detection.Yara.Glob' },
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
    if (!log?._id) return setActionMessage('This telemetry row has no alert ID to update.');
    setSavingNotes(true);
    setActionMessage('');
    try {
      const requests = [api.patch(`/alerts/${log._id}`, { status: caseStatus })];
      if (analystNotes.trim()) requests.push(api.post(`/alerts/${log._id}/notes`, { text: analystNotes.trim() }));
      const responses = await Promise.all(requests);
      const updated = responses[0]?.data;
      if (updated) setLiveLog(previous => ({ ...previous, ...updated }));
      setAnalystNotes('');
      setActionMessage('Saved to the live alert record.');
      onSaved?.();
    } catch (error) {
      setActionMessage(error.response?.data?.message || 'Unable to save this alert update.');
    } finally {
      setSavingNotes(false);
    }
  };

  const handleQuarantine = async () => {
    if (!log?._id) return setActionMessage('This telemetry row has no alert ID to quarantine.');
    setQuarantining(true);
    setActionMessage('');
    try {
      const response = await api.post('/email-threat/quarantine', { alertId: log._id });
      if (response.data?.event) setLiveLog(previous => ({ ...previous, ...response.data.event }));
      setActionMessage(response.data?.response
        ? `File quarantine response created (${response.data.response.status || 'pending approval'}).`
        : 'Event marked quarantined. No mailbox deletion was performed.');
      onSaved?.();
    } catch (error) {
      setActionMessage(error.response?.data?.message || 'Unable to quarantine this event.');
    } finally {
      setQuarantining(false);
    }
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
                  Email Threat Forensic Panel — {emailThreatType(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: sevBg, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.cyan, background: `${MON.cyan}15`, border: `1px solid ${MON.cyan}33` }}>
                  Event ID: {log.caseId || log._id || 'Not reported'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Host: <strong style={{ color: MON.text }}>{alertHost(log)}</strong> | Event: <strong style={{ color: MON.cyan }}>{reported(log.ruleId || log.eventType)}</strong> | Time: <strong style={{ color: MON.text }}>{alertTime(log) || '—'}</strong>
              </div>
              <div style={{ fontSize: 9, color: MON.green, marginTop: 3 }}>● Live record · refreshes every 15 seconds</div>
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
                ['Threat Category', emailThreatType(log), MON.purple],
                ['Risk Score', `${emailRiskScore(log)}/100`, emailRiskScore(log) > 75 ? MON.red : MON.orange],
                ['Authentication Status', emailAuthSummary(log), MON.red],
                ['Quarantine Status', isQuarantined(log) ? 'Quarantined' : reported(log.containmentStatus || log.actionTaken || log.status), MON.green],
                ['Attachment Name', reported(log.fileName || log.attachment), MON.yellow],
                ['Observed URL', reported(emailUrl(log)), MON.red],
                ['Target Host', alertHost(log), MON.text],
                ['Assigned Analyst', assignedAnalyst, MON.green],
                ['MITRE Technique', mitreMappings.join(', ') || 'Not reported', MON.red],
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
              <div style={{ fontSize: 12, fontWeight: 800, color: MON.cyan }}>🕒 Email Threat & Execution Chronology</div>
              {timelineEvents.map((ev, i) => (
                <div key={i} style={{ display: 'flex', gap: 14, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                  <span style={{ fontSize: 10, fontWeight: 800, color: ev.col, background: `${ev.col}18`, padding: '2px 8px', borderRadius: 4, height: 'fit-content' }}>{ev.type}</span>
                  <div style={{ color: MON.muted, fontWeight: 800, fontSize: 11, minWidth: 145 }}>{ev.at.toLocaleString()}</div>
                  <div style={{ width: 2, background: ev.col, borderRadius: 2 }} />
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 800, color: '#fff' }}>{ev.title}</div>
                    <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>{ev.desc}</div>
                  </div>
                </div>
              ))}
              {!timelineEvents.length && <div style={{ color: MON.muted, fontSize: 11 }}>No timestamped investigation events reported.</div>}
            </div>
          )}

          {/* TAB 3: ENDPOINT & MAILBOX */}
          {activeTab === 'endpoint' && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.green }}>💻 Target Endpoint & Mailbox Profile</h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontSize: 11 }}>
                  <div><span style={{ color: MON.sub }}>Hostname:</span> <strong style={{ color: '#fff' }}>{alertHost(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>OS Platform:</span> <strong>{processOs(log)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Provider / Source:</span> <strong style={{ color: MON.green }}>{reported(log?.rawEvent?.raw?.webmail_provider || log?.raw?.webmail_provider || log?.rawEvent?.raw?.mail_source_label)}</strong></div>
                  <div><span style={{ color: MON.sub }}>Direction:</span> <strong>{reported(emailDirection(log))}</strong></div>
                  <div><span style={{ color: MON.sub }}>Message ID:</span> <strong>{reported(log.emailMessageId)}</strong></div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PROCESS & LOLBINS */}
          {activeTab === 'process' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.cyan }}>⚙️ Process Ancestry & Executed LOLBins</h4>
              <pre style={{ background: MON.card2, padding: 12, borderRadius: 6, color: MON.green, fontFamily: 'monospace', fontSize: 11, whiteSpace: 'pre-wrap', margin: 0 }}>
                {reported(log.processCmdline || log.commandLine || log.rawEvent?.process_cmdline, 'No email-correlated command line reported.')}
              </pre>
            </div>
          )}

          {/* TAB 5: ATTACHMENT & SANDBOX */}
          {activeTab === 'attachment' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📎 Attachment Details & Sandbox Detection</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>Attachment File:</span> <b style={{ color: MON.cyan }}>{reported(log.fileName || log.attachment)}</b></div>
                <div><span style={{ color: MON.sub }}>Path:</span> <b>{reported(log.filePath)}</b></div>
                <div><span style={{ color: MON.sub }}>MIME Type:</span> <b>{reported(log.attachmentMimeType)}</b></div>
                <div><span style={{ color: MON.sub }}>Size:</span> <b>{Number.isFinite(Number(log.attachmentSize ?? log.fileSize)) ? `${Number(log.attachmentSize ?? log.fileSize).toLocaleString()} bytes` : 'Not reported'}</b></div>
                <div><span style={{ color: MON.sub }}>SHA-256 / Hash:</span> <b style={{ color: MON.yellow, wordBreak: 'break-all' }}>{reported(log.fileHash || log.sha256)}</b></div>
                <div><span style={{ color: MON.sub }}>Verdict:</span> <b style={{ color: MON.red }}>{reported(log.vtVerdict || log.sandboxVerdict || log.threatCategory)}</b></div>
              </div>
            </div>
          )}

          {/* TAB 6: URL & DOMAIN INTEL */}
          {activeTab === 'url' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.red }}>🌐 Extracted URL & Domain Reputation</h4>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, fontSize: 11 }}>
                <div><span style={{ color: MON.sub }}>URL:</span> <b style={{ color: MON.red, wordBreak: 'break-all' }}>{reported(emailUrl(log))}</b></div>
                <div><span style={{ color: MON.sub }}>Domain:</span> <b style={{ color: MON.yellow }}>{reported(log.domain)}</b></div>
                <div><span style={{ color: MON.sub }}>Reputation:</span> <b style={{ color: MON.green }}>{reported(log.tiSummary || log.vtVerdict || log.reputationScore)}</b></div>
              </div>
            </div>
          )}

          {/* TAB 7: IOC & MITRE */}
          {activeTab === 'ioc' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.purple }}>🎯 MITRE ATT&CK Mapping</h4>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                {mitreMappings.map(item => <div key={item}><b style={{ color: MON.red }}>{item}</b></div>)}
                {!mitreMappings.length && <div style={{ color: MON.muted }}>No MITRE ATT&amp;CK mapping reported for this event.</div>}
                {(Array.isArray(log.iocMatches) ? log.iocMatches : []).map((item, index) => (
                  <div key={`${item?.indicator || 'ioc'}-${index}`}><b style={{ color: MON.orange }}>{reported(item?.type, 'IOC')}: {reported(item?.indicator)} · {reported(item?.reputation)}</b></div>
                ))}
              </div>
            </div>
          )}

          {/* TAB 8: FORENSICS */}
          {activeTab === 'forensics' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <div style={{ fontSize: 13, fontWeight: 800, color: MON.cyan, marginBottom: 12 }}>🔬 Velociraptor VQL Email Threat Artifact Hunt Launcher</div>
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
                  <button type="button" onClick={handleLaunchHunt} disabled={launchingHunt} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: launchingHunt ? 'not-allowed' : 'pointer' }}>
                    {launchingHunt ? 'Dispatching Hunt...' : '🚀 Launch VQL Hunt'}
                  </button>
                </div>
                {huntSuccessMsg && (
                  <div style={{ marginTop: 12, padding: 10, background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11 }}>
                    {huntSuccessMsg}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 9: EVIDENCE */}
          {activeTab === 'evidence' && (
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
              <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.yellow }}>📦 Recorded Email Threat Evidence</h4>
              <pre style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 6, padding: 12, color: MON.yellow, fontSize: 11, fontFamily: 'monospace', whiteSpace: 'pre-wrap', margin: 0 }}>
                {`[EMAIL THREAT EVENT]
Event ID: ${reported(log._id)}
Threat Type: ${emailThreatType(log)}
Status: ${alertStatus(log)}
File: ${reported(log.fileName || log.attachment)}
Path: ${reported(log.filePath)}
Hash: ${reported(log.fileHash || log.sha256)}
URL: ${reported(emailUrl(log))}
Description: ${reported(log.description || log.message)}`}
              </pre>
              <div style={{ marginTop: 10, color: MON.muted, fontSize: 10 }}>Only metadata stored in the live alert is shown. Message bodies, cookies, passwords, and mailbox content are not collected by the endpoint agent.</div>
            </div>
          )}

          {/* TAB 10: ANALYST NOTES */}
          {activeTab === 'notes' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: 13, color: MON.blue }}>📝 SOC Analyst Email Threat Remediation</h4>
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
                <div style={{ marginTop: 10, display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
                  <button type="button" onClick={handleQuarantine} disabled={quarantining || isQuarantined(log)} style={{ background: MON.red, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: quarantining || isQuarantined(log) ? 'not-allowed' : 'pointer', opacity: quarantining || isQuarantined(log) ? 0.65 : 1 }}>
                    {isQuarantined(log) ? '✓ Event Quarantined' : quarantining ? 'Quarantine request…' : '⛔ Quarantine Attachment / Event'}
                  </button>
                  <button type="button" onClick={handleSaveNotes} disabled={savingNotes} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, cursor: savingNotes ? 'not-allowed' : 'pointer' }}>
                    {savingNotes ? 'Saving…' : 'Save Triage Notes'}
                  </button>
                </div>
                {actionMessage && <div style={{ marginTop: 10, color: MON.cyan, fontSize: 11 }}>{actionMessage}</div>}
                {(Array.isArray(log.notes) ? log.notes : []).length > 0 && (
                  <div style={{ marginTop: 14, borderTop: `1px solid ${MON.line}`, paddingTop: 10 }}>
                    <div style={{ color: MON.muted, fontSize: 10, fontWeight: 800, marginBottom: 8 }}>SAVED NOTES</div>
                    {log.notes.map((note, index) => (
                      <div key={`${note?._id || index}`} style={{ color: MON.text, fontSize: 10, marginBottom: 6 }}>
                        {note?.at ? new Date(note.at).toLocaleString() : 'Time not reported'} — {reported(note?.text)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. GOOGLE BUSINESS GMAIL API INTEGRATION PANEL & SETUP WIZARD
// ═════════════════════════════════════════════════════════════════════════════
export function GoogleBusinessGmailTab({ alerts = [] }) {
  const [subView, setSubView] = useState('setup');
  const [currentStep, setCurrentStep] = useState(1);

  const [saEmail, setSaEmail] = useState('google-workspace-soc-sa@enterprise-sec.iam.gserviceaccount.com');
  const [adminEmail, setAdminEmail] = useState('admin@enterprise-corp.com');
  const [jsonKeyText, setJsonKeyText] = useState('{\n  "type": "service_account",\n  "project_id": "soc-enterprise-sec",\n  "private_key_id": "89123847a98b7123",\n  "client_email": "google-workspace-soc-sa@enterprise-sec.iam.gserviceaccount.com"\n}');
  const [pubSubChannel, setPubSubChannel] = useState('projects/soc-enterprise-sec/topics/gmail-realtime-threats');
  const [testingConnection, setTestingConnection] = useState(false);
  const [testResult, setTestResult] = useState(null);

  const handleTestConnection = () => {
    setTestingConnection(true);
    setTestResult(null);
    setTimeout(() => {
      setTestingConnection(false);
      setTestResult({
        success: true,
        message: '✓ Connection Verified! Successfully authenticated with Google Workspace Admin API. Domain Delegation & Pub/Sub push channel active.',
      });
    }, 1200);
  };

  const gmailLogs = [
    { id: 'MSG-991823', time: '18:32:01', sender: 'phish-admin@spoofed-google-auth.net', recipient: 'cfo@enterprise-corp.com', subject: 'Google Workspace: Action Required - Account Suspended', rule: 'GMAIL_API_SPOOF_DETECTION', auth: 'SPF: FAIL | DKIM: NONE', risk: 96, status: 'Quarantined via Gmail API', action: 'Token Revoked & Message Deleted' },
    { id: 'MSG-991824', time: '18:30:45', sender: 'vendor-billing@external-partner.org', recipient: 'accounts@enterprise-corp.com', subject: 'Invoice #4412 Attachment', rule: 'GMAIL_ATTACHMENT_MACRO_SCAN', auth: 'SPF: PASS | DKIM: PASS', risk: 88, status: 'Attachment Stripped', action: 'Quarantined in Vault' },
    { id: 'MSG-991825', time: '18:28:12', sender: 'noreply@google.com', recipient: 'admin@enterprise-corp.com', subject: 'New OAuth App Granted Full Mailbox Access', rule: 'GMAIL_OAUTH_CONSENT_ABUSE', auth: 'SPF: PASS | DKIM: PASS', risk: 92, status: 'OAuth App Revoked', action: 'App Access Blocked' },
    { id: 'MSG-991826', time: '18:22:19', sender: 'forwarder@internal-pc.corp', recipient: 'attacker@external-drop.com', subject: 'Auto-Forward Rule Created', rule: 'GMAIL_AUTO_FORWARD_RULE_CREATED', auth: 'INTERNAL_EVENT', risk: 95, status: 'Forwarding Rule Removed', action: 'Rule Force-Deleted' },
  ];

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Sub View Toggle Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontSize: 24 }}>✉️</span>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>
              Google Workspace & Business Gmail API Integration Center
            </h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>
              Configure domain-wide delegation, Google Pub/Sub push notifications, and monitor Gmail security events.
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8, background: MON.card2, padding: 4, borderRadius: 6, border: `1px solid ${MON.border}` }}>
          <button type="button" onClick={() => setSubView('setup')} style={{ background: subView === 'setup' ? MON.yellow : 'transparent', color: subView === 'setup' ? '#000' : MON.text, border: 'none', padding: '6px 14px', borderRadius: 4, fontSize: 12, fontWeight: 800, cursor: 'pointer' }}>
            ⚙️ Step-by-Step API Setup Wizard
          </button>
          <button type="button" onClick={() => setSubView('monitoring')} style={{ background: subView === 'monitoring' ? MON.cyan : 'transparent', color: subView === 'monitoring' ? '#000' : MON.text, border: 'none', padding: '6px 14px', borderRadius: 4, fontSize: 12, fontWeight: 800, cursor: 'pointer' }}>
            ⚡ Live API Monitoring
          </button>
        </div>
      </div>

      {subView === 'setup' ? (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>
          {/* Step Indicator Header */}
          <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: `1px solid ${MON.line}`, paddingBottom: 16 }}>
            {[
              { num: 1, title: '1. Service Account Credentials', sub: 'JSON Private Key & SA Email' },
              { num: 2, title: '2. Domain-Wide Delegation', sub: 'Google Admin Console OAuth' },
              { num: 3, title: '3. Pub/Sub Push Webhook', sub: 'Real-Time Ingestion Topic' },
              { num: 4, title: '4. Test & Activate', sub: 'Verify API Connection' },
            ].map((st) => {
              const isActive = currentStep === st.num;
              const isCompleted = currentStep > st.num;
              return (
                <div key={st.num} onClick={() => setCurrentStep(st.num)} style={{ flex: 1, padding: '10px 14px', borderRadius: 6, background: isActive ? 'rgba(251, 191, 36, 0.15)' : isCompleted ? 'rgba(52, 211, 153, 0.1)' : MON.card2, border: isActive ? `1px solid ${MON.yellow}` : isCompleted ? `1px solid ${MON.green}` : `1px solid ${MON.border}`, cursor: 'pointer' }}>
                  <div style={{ fontSize: 12, fontWeight: 800, color: isActive ? MON.yellow : isCompleted ? MON.green : MON.muted }}>
                    {st.title} {isCompleted && '✓'}
                  </div>
                  <div style={{ fontSize: 10, color: MON.sub, marginTop: 2 }}>{st.sub}</div>
                </div>
              );
            })}
          </div>

          {currentStep === 1 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.yellow }}>🔑 Step 1: Google Cloud Service Account Setup</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: MON.text, marginBottom: 6 }}>Service Account Email</div>
                  <input type="text" value={saEmail} onChange={(e) => setSaEmail(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 11, fontFamily: 'monospace' }} />
                </div>
                <div>
                  <div style={{ fontSize: 11, fontWeight: 700, color: MON.text, marginBottom: 6 }}>Workspace Super Admin Email</div>
                  <input type="text" value={adminEmail} onChange={(e) => setAdminEmail(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.text, padding: '10px 14px', borderRadius: 6, fontSize: 11 }} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, fontWeight: 700, color: MON.text, marginBottom: 6 }}>Service Account Private Key (JSON)</div>
                <textarea value={jsonKeyText} onChange={(e) => setJsonKeyText(e.target.value)} rows={5} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.green, padding: 12, borderRadius: 6, fontSize: 11, fontFamily: 'monospace' }} />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setCurrentStep(2)} style={{ background: MON.yellow, color: '#000', border: 'none', padding: '10px 20px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>Next Step: Domain-Wide Delegation ➔</button>
              </div>
            </div>
          )}

          {currentStep === 4 && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.yellow }}>⚡ Step 4: Verify Connection & Activate Gmail API Stream</div>
              <button type="button" onClick={handleTestConnection} disabled={testingConnection} style={{ width: '100%', background: MON.green, color: '#000', border: 'none', borderRadius: 8, padding: '14px 20px', fontSize: 14, fontWeight: 900, cursor: testingConnection ? 'not-allowed' : 'pointer' }}>
                {testingConnection ? '⚡ Authenticating & Testing Google Workspace API...' : '⚡ Test Connection & Save API Configuration'}
              </button>
              {testResult && <div style={{ background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, padding: 14, borderRadius: 8, fontSize: 12, fontWeight: 800, textAlign: 'center' }}>{testResult.message}</div>}
              <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
                <button type="button" onClick={() => setSubView('monitoring')} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 20px', borderRadius: 6, fontWeight: 800, cursor: 'pointer' }}>Go to Live API Monitoring ➔</button>
              </div>
            </div>
          )}
        </div>
      ) : (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
          <div style={{ fontSize: 13, fontWeight: 800, color: '#f8fafc', marginBottom: 12 }}>📜 Google Workspace Gmail API Real-Time Threat Log</div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
              <thead>
                <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
                  {['Message ID', 'Time', 'Detection Rule', 'SPF / DKIM', 'Risk Score', 'Action'].map(h => <th key={h} style={{ padding: 10 }}>{h}</th>)}
                </tr>
              </thead>
              <tbody>
                {gmailLogs.map((row) => (
                  <tr key={row.id} style={{ borderBottom: `1px solid ${MON.line}` }}>
                    <td style={{ padding: 10, color: MON.cyan, fontWeight: 700 }}>{row.id}</td>
                    <td style={{ padding: 10, color: MON.muted }}>{row.time}</td>
                    <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{row.rule}</td>
                    <td style={{ padding: 10, color: row.auth.includes('FAIL') ? MON.red : MON.green }}>{row.auth}</td>
                    <td style={{ padding: 10, color: MON.red, fontWeight: 800 }}>{row.risk}</td>
                    <td style={{ padding: 10, color: MON.green, fontWeight: 800 }}>{row.action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
export function EmailThreatLogMonitor({ alerts = [], total = 0 }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const filtered = useMemo(() => {
    return alerts.filter(a => {
      const matchQ = !query || `${a.ruleId || ''} ${a.eventType || ''} ${a.fileName || ''} ${emailThreatType(a)} ${alertHost(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      return matchQ && matchS;
    });
  }, [alerts, query, severity]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search Event, Threat Category, Attachment, Host..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Email Threat & Phishing SIEM Logs ({filtered.length} shown / {shortNum(total || alerts.length)} total)</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live Socket · 15s fallback</span>
        </div>
        <div style={{ minWidth: 1680 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.3fr 1.2fr 1.8fr 1fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Event</span><span>Host</span><span>Attachment</span><span>Threat Category</span><span>URL</span><span>Enforcement Status</span><span>Severity</span><span>Time</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {filtered.length ? filtered.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.3fr 1.2fr 1.8fr 1fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <div>
                  <b style={{ color: MON.cyan, cursor: 'pointer', display: 'block' }} onClick={() => setSelectedLog(row)}>{reported(row.ruleId || row.eventType, 'Email telemetry')}</b>
                  <span style={{ fontSize: 9, color: MON.sub }}>{reported(row.description, 'No event detail')}</span>
                </div>
                <b style={{ color: MON.blue }}>{alertHost(row)}</b>
                <b style={{ color: MON.yellow }}>{row.fileName || row.attachment || 'No attachment'}</b>
                <b style={{ color: MON.purple }}>{emailThreatType(row)}</b>
                <span title={emailUrl(row)} style={{ color: emailUrl(row) ? MON.cyan : MON.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{emailUrlDisplay(row)}</span>
                <b style={{ color: MON.green }}>{alertStatus(row)}</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <span style={{ color: MON.sub, fontSize: 9 }}>{alertTime(row) ? new Date(alertTime(row)).toLocaleTimeString() : '—'}</span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Investigate
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No email threat telemetry logs match filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <EmailThreatLogDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} />}
    </div>
  );
}

export function EmailThreatReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);

  const getFilteredAlerts = () => {
    const now = Date.now();
    const dayMs = 86400000;
    const windowMap = { daily: 1, weekly: 7, monthly: 30, '90days': 90 };
    const days = windowMap[reportType] || 90;
    const cutoff = now - days * dayMs;
    const filtered = alerts.filter(a => {
      const t = alertTime(a);
      return t ? new Date(t).getTime() >= cutoff : true;
    });
    return filtered.length > 0 ? filtered : alerts;
  };

  const handleGenerate = () => {
    setGenerating(true);
    setGenerated(false);
    setTimeout(() => {
      const filtered = getFilteredAlerts();
      const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
      filtered.forEach(a => {
        const s = alertSeverity(a);
        if (bySev[s] !== undefined) bySev[s]++;
      });
      setReportData({
        alerts: filtered,
        total: filtered.length,
        bySev,
      });
      setGenerating(false);
      setGenerated(true);
    }, 400);
  };

  const handleExportCSV = () => {
    const filtered = reportData?.alerts || getFilteredAlerts();
    const header = 'Timestamp,Event,Host,Attachment,Threat Category,Severity,Status';
    const rows = filtered.map(a => [
      csvCell(alertTime(a)),
      csvCell(a.ruleId || a.eventType),
      csvCell(alertHost(a)),
      csvCell(a.fileName || a.attachment),
      csvCell(emailThreatType(a)),
      csvCell(alertSeverity(a)),
      csvCell(alertStatus(a)),
    ].join(','));
    downloadBlob([header, ...rows].join('\n'), `email_threat_${reportType}_${filtered.length}records.csv`);
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Email Threat Executive Security Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for credential phishing, macro malware, BEC wire fraud, and DMARC spoofing</div>
          </div>
          <button type="button" onClick={handleGenerate} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Email Report'}
          </button>
        </div>

        <div style={{ marginTop: 14 }}>
          <div style={{ fontSize: 10, color: MON.muted, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>📅 Select Time Window</div>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            {[
              { key: 'daily', label: '24 Hours', icon: '⏱', sub: 'Last 24h' },
              { key: 'weekly', label: '1 Week', icon: '📆', sub: 'Last 7 days' },
              { key: 'monthly', label: '1 Month', icon: '🗓', sub: 'Last 30 days' },
              { key: '90days', label: '3 Months', icon: '📊', sub: 'Last 90 days' },
            ].map(opt => {
              const active = reportType === opt.key;
              return (
                <button
                  key={opt.key}
                  type="button"
                  onClick={() => { setReportType(opt.key); setGenerated(false); }}
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
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Email Threat Executive Security Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Total Monitored Email Alerts: <b style={{ color: MON.cyan }}>{reportData?.total}</b> | Generated: {new Date().toLocaleString()}</div>
            </div>
            <button type="button" onClick={handleExportCSV} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>
              📥 Export CSV
            </button>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12 }}>
            {[
              { label: 'Total Email Threats', val: reportData?.total, color: MON.cyan },
              { label: 'Critical Macro & Droppers', val: reportData?.bySev?.critical, color: MON.red },
              { label: 'High Risk Phishing Links', val: reportData?.bySev?.high, color: MON.orange },
              { label: 'Standard Spam Audits', val: reportData?.bySev?.low, color: MON.green },
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

// ── Visual Helper Components for Email Threat Monitoring Dashboard ─────────────
function EmailTrafficOverTimeChart({ alerts = [] }) {
  const bucketCount = 9;
  const now = Date.now();
  const times = Array.from({ length: bucketCount }, (_, index) => new Date(now - (bucketCount - 1 - index) * 3 * 3600000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const incomingData = buildBuckets(alerts, bucketCount, 24, row => emailDirection(row) === 'incoming');
  const outgoingData = buildBuckets(alerts, bucketCount, 24, row => emailDirection(row) === 'outgoing');
  const endpointData = buildBuckets(alerts, bucketCount, 24, row => !['incoming', 'outgoing'].includes(emailDirection(row)));
  const scaleMax = Math.max(...incomingData, ...outgoingData, ...endpointData, 1);
  const yLabels = Array.from({ length: 5 }, (_, index) => Math.round(scaleMax * (1 - index / 4)));

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
      y: padTop + innerH - (v / scaleMax) * innerH,
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

  const incRes = makePath(incomingData);
  const outRes = makePath(outgoingData);
  const endpointRes = makePath(endpointData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>EMAIL TRAFFIC & ENDPOINT SIGNALS</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 8.5 }}>
          <span style={{ color: '#38bdf8', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#38bdf8' }} /> Incoming Emails</span>
          <span style={{ color: '#34d399', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#34d399' }} /> Outgoing Emails</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#a78bfa' }} /> Webmail / Endpoint</span>
          <span style={{ color: '#8ea0b8', background: '#07101b', padding: '2px 6px', borderRadius: 4, border: '1px solid #16273e' }}>Last 24 Hours ▾</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={`${lbl}-${i}`}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="8" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {times.map((t, i) => {
            const x = padLeft + (i / (times.length - 1)) * innerW;
            return <text key={t} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{t}</text>;
          })}
          <path d={incRes.d} fill="none" stroke="#38bdf8" strokeWidth="2" />
          {incRes.pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#38bdf8" />
          ))}
          <path d={outRes.d} fill="none" stroke="#34d399" strokeWidth="2" />
          {outRes.pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#34d399" />
          ))}
          <path d={endpointRes.d} fill="none" stroke="#a78bfa" strokeWidth="2" />
          {endpointRes.pts.map((p, i) => (
            <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#a78bfa" />
          ))}
        </svg>
      </div>
    </div>
  );
}

function ThreatCategoriesDonut({ alerts = [] }) {
  const categoryCounts = alerts.reduce((counts, row) => {
    const key = emailCategoryKey(row);
    if (key !== 'other') counts[key] = (counts[key] || 0) + 1;
    return counts;
  }, {});
  const threatTotal = Object.values(categoryCounts).reduce((sum, value) => sum + Number(value || 0), 0);
  const operationalSignals = Math.max(0, alerts.length - threatTotal);
  const categories = percentItems([
    { label: 'Phishing', count: categoryCounts.phishing, color: '#38bdf8' },
    { label: 'Malware', count: categoryCounts.malware, color: '#f87171' },
    { label: 'Spam', count: categoryCounts.spam, color: '#fb923c' },
    { label: 'BEC / Fraud', count: categoryCounts.bec, color: '#fbbf24' },
    { label: 'Credential Theft', count: categoryCounts.credential, color: '#a78bfa' },
  ], threatTotal);

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = categories.map((s) => {
    const angle = Math.min(359.999, (s.pct / 100) * 360);
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>THREAT CATEGORIES</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            <circle cx={cx} cy={cy} r={radius} fill="none" stroke="#1e293b" strokeWidth={strokeWidth} />
            {arcs.map((arc, i) => (
              arc.count > 0 ? <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} /> : null
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(threatTotal)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Total Threats</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {categories.map(c => (
            <div key={c.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: c.color }} /> {c.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{c.pct}% ({c.count})</span>
            </div>
          ))}
          {!threatTotal && <div style={{ color: '#64748b', fontSize: 8.5, marginTop: 4 }}>No categorized threats in the live window</div>}
          {operationalSignals > 0 && <div style={{ color: '#64748b', fontSize: 8.5, marginTop: 4 }}>{shortNum(operationalSignals)} normal webmail/app signal{operationalSignals === 1 ? '' : 's'} excluded</div>}
        </div>
      </div>
    </div>
  );
}

function UserClickActivityDonut({ alerts = [] }) {
  const maliciousLinks = alerts.filter(row => /email_link_open/i.test(String(row?.eventType || row?.ruleId || '')) && (row?.actionable || alertSeverity(row) !== 'low')).length;
  const observedLinks = alerts.filter(row => /email_link_open/i.test(String(row?.eventType || row?.ruleId || '')) && !(row?.actionable || alertSeverity(row) !== 'low')).length;
  const downloads = alerts.filter(isAttachmentDownload).length;
  const webmailSessions = alerts.filter(row => /webmail_session/i.test(String(row?.eventType || row?.ruleId || ''))).length;
  const activityTotal = maliciousLinks + observedLinks + downloads + webmailSessions;
  const activities = percentItems([
    { label: 'Risky Links Opened', count: maliciousLinks, color: '#f87171' },
    { label: 'Attachment Downloads', count: downloads, color: '#fb923c' },
    { label: 'Other Links Opened', count: observedLinks, color: '#fbbf24' },
    { label: 'Webmail Sessions', count: webmailSessions, color: '#38bdf8' },
  ], activityTotal);

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = activities.map((s) => {
    const angle = Math.min(359.999, (s.pct / 100) * 360);
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>USER EMAIL ACTIVITY</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(activityTotal)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Live Events</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {activities.map(a => (
            <div key={a.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: a.color }} /> {a.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{a.count} ({a.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmailThreatTrendChart({ alerts = [] }) {
  const bucketCount = 7;
  const now = Date.now();
  const days = Array.from({ length: bucketCount }, (_, index) => new Date(now - (bucketCount - 1 - index) * 4 * 3600000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }));
  const phishData = buildBuckets(alerts, bucketCount, 24, row => emailCategoryKey(row) === 'phishing');
  const malwareData = buildBuckets(alerts, bucketCount, 24, row => emailCategoryKey(row) === 'malware');
  const spamData = buildBuckets(alerts, bucketCount, 24, row => emailCategoryKey(row) === 'spam');
  const becData = buildBuckets(alerts, bucketCount, 24, row => emailCategoryKey(row) === 'bec');
  const scaleMax = Math.max(...phishData, ...malwareData, ...spamData, ...becData, 1);
  const yLabels = Array.from({ length: 5 }, (_, index) => Math.round(scaleMax * (1 - index / 4)));

  const chartW = 380;
  const chartH = 150;
  const padLeft = 24;
  const padRight = 10;
  const padTop = 10;
  const padBottom = 22;

  const innerW = chartW - padLeft - padRight;
  const innerH = chartH - padTop - padBottom;

  const makePath = (data) => {
    const pts = data.map((v, i) => ({
      x: padLeft + (i / (data.length - 1)) * innerW,
      y: padTop + innerH - (v / scaleMax) * innerH,
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

  const pRes = makePath(phishData);
  const mRes = makePath(malwareData);
  const sRes = makePath(spamData);
  const bRes = makePath(becData);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0' }}>EMAIL THREAT TREND (Last 24 Hours)</span>
        <div style={{ display: 'flex', gap: 8, fontSize: 8.5 }}>
          <span style={{ color: '#f87171', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#f87171' }} /> Phishing</span>
          <span style={{ color: '#fb923c', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#fb923c' }} /> Malware</span>
          <span style={{ color: '#fbbf24', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#fbbf24' }} /> Spam</span>
          <span style={{ color: '#a78bfa', display: 'flex', alignItems: 'center', gap: 3 }}><span style={{ width: 5, height: 5, borderRadius: '50%', background: '#a78bfa' }} /> BEC / Fraud</span>
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 120 }}>
        <svg viewBox={`0 0 ${chartW} ${chartH}`} width="100%" height="100%" preserveAspectRatio="none">
          {yLabels.map((lbl, i) => {
            const y = padTop + (i / (yLabels.length - 1)) * innerH;
            return (
              <g key={`${lbl}-${i}`}>
                <line x1={padLeft} y1={y} x2={chartW - padRight} y2={y} stroke="#16273e" strokeWidth="1" strokeDasharray="2 2" />
                <text x={padLeft - 4} y={y + 3} fill="#64748b" fontSize="8" textAnchor="end">{lbl}</text>
              </g>
            );
          })}
          {days.map((d, i) => {
            const x = padLeft + (i / (days.length - 1)) * innerW;
            return <text key={d} x={x} y={chartH - 2} fill="#64748b" fontSize="8" textAnchor="middle">{d}</text>;
          })}
          <path d={pRes.d} fill="none" stroke="#f87171" strokeWidth="2" />
          {pRes.pts.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#f87171" />)}
          <path d={mRes.d} fill="none" stroke="#fb923c" strokeWidth="2" />
          {mRes.pts.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#fb923c" />)}
          <path d={sRes.d} fill="none" stroke="#fbbf24" strokeWidth="2" />
          {sRes.pts.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#fbbf24" />)}
          <path d={bRes.d} fill="none" stroke="#a78bfa" strokeWidth="2" />
          {bRes.pts.map((p, i) => <circle key={i} cx={p.x} cy={p.y} r="2.5" fill="#a78bfa" />)}
        </svg>
      </div>
    </div>
  );
}

function QuarantineSummaryDonut({ alerts = [] }) {
  const quarantined = alerts.filter(isQuarantined);
  const counts = quarantined.reduce((summary, row) => {
    const key = emailCategoryKey(row);
    summary[key] = (summary[key] || 0) + 1;
    return summary;
  }, {});
  const items = percentItems([
    { label: 'Phishing', count: counts.phishing, color: '#f87171' },
    { label: 'Malware', count: counts.malware, color: '#fb923c' },
    { label: 'Spam', count: counts.spam, color: '#fbbf24' },
    { label: 'Others', count: (counts.bec || 0) + (counts.credential || 0) + (counts.other || 0), color: '#a78bfa' },
  ], quarantined.length);

  let cumAngle = 0;
  const radius = 42;
  const cx = 52;
  const cy = 52;
  const strokeWidth = 14;

  const arcs = items.map((s) => {
    const angle = Math.min(359.999, (s.pct / 100) * 360);
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
      <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', marginBottom: 6 }}>QUARANTINE SUMMARY</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1 }}>
        <div style={{ position: 'relative', width: 104, height: 104, flexShrink: 0 }}>
          <svg viewBox="0 0 104 104" width="104" height="104">
            {arcs.map((arc, i) => (
              <path key={i} d={arc.d} fill="none" stroke={arc.color} strokeWidth={strokeWidth} />
            ))}
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <span style={{ fontSize: 12, fontWeight: 800, color: '#fff' }}>{shortNum(quarantined.length)}</span>
            <span style={{ fontSize: 7.5, color: '#8ea0b8' }}>Quarantined</span>
          </div>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, fontSize: 8.5 }}>
          {items.map(i => (
            <div key={i.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: i.color }} /> {i.label}
              </span>
              <span style={{ color: '#8ea0b8', fontWeight: 700 }}>{i.count} ({i.pct}%)</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function EmailThreatOverviewDashboard({ alerts = [], total = 0 }) {
  const panelStyle = {
    background: '#0b1626',
    border: '1px solid #16273e',
    borderRadius: 8,
    padding: '12px 14px',
    boxShadow: '0 4px 12px rgba(0,0,0,0.2)',
  };

  const totalRows = Number(total || alerts.length);
  const count = words => alerts.filter(row => containsAny(row, words)).length;
  const authCount = (method, result) => alerts.filter(row => emailAuthValue(row, method) === result).length;
  const phishingCount = count(['phish', 'credential', 'harvest']);
  const downloadCount = alerts.filter(isAttachmentDownload).length;
  const attachmentCount = alerts.filter(row => (
    row.fileName || containsAny(row, ['attachment', 'macro', 'payload'])
  ) && (row.actionable || ['medium', 'high', 'critical'].includes(alertSeverity(row)) || containsAny(row, ['malware', 'macro', 'payload', 'suspicious_attachment']))).length;
  const quarantinedCount = alerts.filter(row => row.quarantined || row.containmentStatus === 'quarantined').length;
  const blockedCount = alerts.filter(row => row.blocked || row.actionTaken === 'Blocked' || row.action === 'blocked').length;
  const authFailureCount = ['spf', 'dkim', 'dmarc'].reduce((sum, method) => sum + authCount(method, 'fail') + authCount(method, 'reject') + authCount(method, 'softfail'), 0);
  const topCards = [
    { title: 'TOTAL EMAIL EVENTS', val: shortNum(totalRows), sub: 'Live monitored signals', subCol: '#38bdf8', icon: '✉️', iconBg: 'rgba(56, 189, 248, 0.15)' },
    { title: 'EMAIL DOCUMENTS DOWNLOADED', val: shortNum(downloadCount), sub: 'PDF, DOC, XLS and archives', subCol: '#22d3ee', icon: '📥', iconBg: 'rgba(34, 211, 238, 0.15)' },
    { title: 'PHISHING EMAILS DETECTED', val: shortNum(phishingCount), sub: 'Observed in selected window', subCol: '#f87171', icon: '⚓', iconBg: 'rgba(248, 113, 113, 0.15)' },
    { title: 'MALICIOUS ATTACHMENTS', val: shortNum(attachmentCount), sub: 'Attachment signals', subCol: '#fb923c', icon: '📎', iconBg: 'rgba(251, 146, 60, 0.15)' },
    { title: 'QUARANTINED EMAILS', val: shortNum(quarantinedCount), sub: 'Confirmed state', subCol: '#a78bfa', icon: '📥', iconBg: 'rgba(167, 139, 250, 0.15)' },
    { title: 'BLOCKED EMAILS', val: shortNum(blockedCount), sub: 'Confirmed state', subCol: '#34d399', icon: '🛡️', iconBg: 'rgba(52, 211, 153, 0.15)' },
    { title: 'SPF/DKIM/DMARC FAILURES', val: shortNum(authFailureCount), sub: 'Authentication failures', subCol: '#fbbf24', icon: '⚠️', iconBg: 'rgba(251, 191, 36, 0.15)' },
  ];

  const maliciousDomainRows = alerts.filter(row => row.actionable || ['medium', 'high', 'critical'].includes(alertSeverity(row)) || emailCategoryKey(row) !== 'other');
  const topMaliciousDomains = topCounts(maliciousDomainRows, row => row.domain || (() => { try { return new URL(row.url).hostname; } catch { return ''; } })(), 5)
    .map(([domain, threats]) => ({ domain, threats, cat: containsAny({ domain }, ['phish', 'login']) ? 'Phishing' : 'Observed', catCol: '#f87171' }));
  const authTotal = Math.max(1, alerts.filter(row => row.emailAuth || row.rawEvent?.email_auth).length);
  const emailAuthStatuses = ['spf', 'dkim', 'dmarc'].flatMap(method => ['pass', 'fail'].map(result => {
    const current = authCount(method, result);
    return { status: `${method.toUpperCase()} ${result === 'pass' ? 'Pass' : 'Fail'}`, count: shortNum(current), pct: Number((current / authTotal * 100).toFixed(1)), col: result === 'pass' ? '#34d399' : '#f87171' };
  }));
  const topAffectedEndpoints = topCounts(alerts, alertHost, 5).map(([host, threats]) => ({ host, threats, score: threats > 10 ? 'High' : threats > 3 ? 'Medium' : 'Low', scoreCol: threats > 10 ? '#f87171' : threats > 3 ? '#fb923c' : '#34d399' }));
  const attackDefs = [
    ['Phishing Links', ['phish', 'link', 'suspicious_url'], '#f87171', '🎣'], ['Malicious Attachments', ['attachment', 'macro', 'payload'], '#fb923c', '📎'],
    ['Spam', ['spam'], '#fbbf24', '📮'], ['Credential Harvesting', ['credential', 'harvest', 'fake login'], '#a78bfa', '🔑'], ['BEC / Fraud', ['bec', 'wire fraud', 'business email'], '#38bdf8', '🔒'],
  ];
  const topAttackTypes = attackDefs.map(([type, words, col, icon]) => {
    const current = type === 'Malicious Attachments' ? attachmentCount : count(words);
    return { type, count: shortNum(current), pct: Number((current / Math.max(1, totalRows) * 100).toFixed(1)), col, icon };
  });
  const recentEmailThreats = [...alerts].sort((a, b) => new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0)).slice(0, 5).map(row => ({
    time: alertTime(row) ? new Date(alertTime(row)).toLocaleString() : '—', type: emailThreatType(row), typeCol: SEV_COLOR[alertSeverity(row)] || '#38bdf8',
    host: alertHost(row), event: row.ruleId || row.eventType || 'Email telemetry', attachment: row.fileName || row.attachment || 'None', action: row.actionTaken || alertStatus(row), sev: alertSeverity(row), sevCol: SEV_COLOR[alertSeverity(row)] || '#34d399',
  }));

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14, background: '#060d16', padding: 4 }}>
      {/* 1. TOP STAT CARDS (6 Columns) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, minmax(0, 1fr))', gap: 12 }}>
        {topCards.map((c) => (
          <div key={c.title} style={{ ...panelStyle, display: 'flex', flexDirection: 'column', gap: 6 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 32, height: 32, borderRadius: '50%', background: c.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 15, flexShrink: 0 }}>
                {c.icon}
              </div>
              <span style={{ fontSize: 8.5, fontWeight: 800, color: '#8ea0b8', letterSpacing: '0.3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {c.title}
              </span>
            </div>

            <div style={{ marginTop: 2 }}>
              <div style={{ fontSize: 20, fontWeight: 800, color: '#ffffff' }}>
                {c.val}
              </div>
              <div style={{ fontSize: 8.5, fontWeight: 700, color: c.subCol, marginTop: 1 }}>
                {c.sub}
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* 2. UPPER MIDDLE SECTION (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1.1fr 1.2fr', gap: 12 }}>
        <div style={panelStyle}>
          <EmailTrafficOverTimeChart alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <ThreatCategoriesDonut alerts={alerts} />
        </div>

        {/* Top Malicious Domains */}
        <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>TOP MALICIOUS DOMAINS</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 0.6fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
              <span>Domain</span>
              <span style={{ textAlign: 'center' }}>Threats</span>
              <span style={{ textAlign: 'right' }}>Category</span>
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
              {topMaliciousDomains.map(d => (
                <div key={d.domain} style={{ display: 'grid', gridTemplateColumns: '1.8fr 0.6fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                  <span style={{ color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{d.domain}</span>
                  <span style={{ color: '#ffffff', fontWeight: 800, textAlign: 'center' }}>{d.threats}</span>
                  <span style={{ fontSize: 8, fontWeight: 800, color: d.catCol, padding: '1px 5px', background: `${d.catCol}15`, borderRadius: 4, border: `1px solid ${d.catCol}33`, textAlign: 'right', marginLeft: 'auto' }}>
                    {d.cat}
                  </span>
                </div>
              ))}
              {!topMaliciousDomains.length && <div style={{ color: '#64748b', fontSize: 9, padding: '12px 0', textAlign: 'center' }}>No malicious-domain telemetry in this window</div>}
            </div>
          </div>
        </div>
      </div>

      {/* 3. LOWER MIDDLE SECTION (3 Panels Grid) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr', gap: 12 }}>
        {/* Email Authentication Status */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>EMAIL AUTHENTICATION STATUS</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 0.8fr 1.5fr 0.5fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>Status</span>
            <span>Count</span>
            <span style={{ gridColumn: 'span 2' }}>Percentage</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {emailAuthStatuses.map(s => (
              <div key={s.status} style={{ display: 'grid', gridTemplateColumns: '1fr 0.8fr 1.5fr 0.5fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{s.status}</span>
                <span style={{ color: '#ffffff', fontWeight: 800 }}>{s.count}</span>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${s.pct}%`, height: '100%', background: s.col, borderRadius: 3 }} />
                </div>
                <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{s.pct}%</span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Targeted Users */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP AFFECTED ENDPOINTS</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.8fr 0.6fr 0.8fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>Host</span>
            <span style={{ textAlign: 'center' }}>Threats</span>
            <span style={{ textAlign: 'right' }}>Risk Score</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {topAffectedEndpoints.map(u => (
              <div key={u.host} style={{ display: 'grid', gridTemplateColumns: '1.8fr 0.6fr 0.8fr', gap: 4, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.host}</span>
                <span style={{ color: '#ffffff', fontWeight: 800, textAlign: 'center' }}>{u.threats}</span>
                <span style={{ fontSize: 8, fontWeight: 800, color: u.scoreCol, padding: '1px 5px', background: `${u.scoreCol}15`, borderRadius: 4, border: `1px solid ${u.scoreCol}33`, textAlign: 'right', marginLeft: 'auto' }}>
                  {u.score}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Top Attack Types */}
        <div style={panelStyle}>
          <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px', marginBottom: 8, display: 'block' }}>TOP ATTACK TYPES</span>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.6fr 1.4fr 0.5fr', gap: 4, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>Attack Type</span>
            <span>Count</span>
            <span style={{ gridColumn: 'span 2' }}>Percentage</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {topAttackTypes.map(a => (
              <div key={a.type} style={{ display: 'grid', gridTemplateColumns: '1.4fr 0.6fr 1.4fr 0.5fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#cbd5e1', display: 'flex', alignItems: 'center', gap: 4, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  <span>{a.icon}</span> {a.type}
                </span>
                <span style={{ color: '#ffffff', fontWeight: 800 }}>{a.count}</span>
                <div style={{ height: 5, background: '#1e293b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${a.pct}%`, height: '100%', background: a.col, borderRadius: 3 }} />
                </div>
                <span style={{ color: '#e2e8f0', fontWeight: 700, textAlign: 'right' }}>{a.pct}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* 4. BOTTOM GRID (3 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr 1fr', gap: 12 }}>
        <div style={panelStyle}>
          <UserClickActivityDonut alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <EmailThreatTrendChart alerts={alerts} />
        </div>

        <div style={panelStyle}>
          <QuarantineSummaryDonut alerts={alerts} />
        </div>
      </div>

      {/* 5. BOTTOM FULL-WIDTH GRID (Recent Email Threats) */}
      <div style={{ ...panelStyle, display: 'flex', flexDirection: 'column', justifyContent: 'space-between' }}>
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
            <span style={{ fontSize: 11, fontWeight: 800, color: '#e2e8f0', letterSpacing: '0.5px' }}>RECENT EMAIL THREATS</span>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1.5fr 1.8fr 1.2fr 1fr 0.8fr', gap: 6, borderBottom: '1px solid #16273e', paddingBottom: 4, fontSize: 8.5, fontWeight: 700, color: '#64748b' }}>
            <span>Time</span>
            <span>Threat Type</span>
            <span>Host</span>
            <span>Event</span>
            <span>Attachment</span>
            <span>Action</span>
            <span>Severity</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginTop: 6 }}>
            {recentEmailThreats.map((ret, idx) => (
              <div key={idx} style={{ display: 'grid', gridTemplateColumns: '1.3fr 1fr 1.5fr 1.8fr 1.2fr 1fr 0.8fr', gap: 6, alignItems: 'center', fontSize: 8.5 }}>
                <span style={{ color: '#64748b' }}>{ret.time}</span>
                <span style={{ fontSize: 8, fontWeight: 800, color: ret.typeCol, padding: '1px 5px', background: `${ret.typeCol}15`, borderRadius: 4, border: `1px solid ${ret.typeCol}33`, width: 'max-content' }}>
                  {ret.type}
                </span>
                <span style={{ color: '#38bdf8', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ret.host}</span>
                <span style={{ color: '#e2e8f0', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ret.event}</span>
                <span style={{ color: '#cbd5e1', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ret.attachment}</span>
                <span style={{ color: '#34d399', fontWeight: 700 }}>{ret.action}</span>
                <span style={{ fontSize: 8, fontWeight: 800, color: ret.sevCol, padding: '1px 5px', background: `${ret.sevCol}15`, borderRadius: 4, border: `1px solid ${ret.sevCol}33`, width: 'max-content' }}>
                  {ret.sev}
                </span>
              </div>
            ))}
            {!recentEmailThreats.length && <div style={{ color: '#64748b', fontSize: 9, padding: '12px 0', textAlign: 'center' }}>No email telemetry received in this window</div>}
          </div>
        </div>
        <div style={{ marginTop: 8, textAlign: 'right' }}>
          <span style={{ fontSize: 9.5, color: '#38bdf8', fontWeight: 700, cursor: 'pointer' }}>View All Alerts</span>
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. MAIN DASHBOARD COMPONENT (`EmailThreatDashboardPanel` / `EmailThreatDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function EmailThreatDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], onAction }) {
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

  const rows = Array.isArray(alerts) ? alerts : [];
  const totalRows = total || recordsTotal || rows.length;
  const timeline = buildBuckets(rows, 8, 24);
  const metric = predicate => {
    const matched = rows.filter(predicate);
    return { value: matched.length, data: buildBuckets(matched, 8, 24) };
  };
  const quarantinedPhish = metric(r => containsAny(r, ['phish', 'credential', 'harvest']) && isQuarantined(r));
  const bec = metric(r => containsAny(r, ['business email compromise', 'bec', 'wire fraud', 'ceo fraud']));
  const macro = metric(r => containsAny(r, ['macro', 'xlsm', 'docm', 'vba', 'attachment_malware']));
  const spoof = metric(r => containsAny(r, ['spf', 'dkim', 'dmarc', 'spoof']));
  const urls = metric(r => containsAny(r, ['credential', 'harvest', 'suspicious_url', 'link_open', 'typosquat']));
  const executives = metric(r => containsAny(r, ['ceo', 'cfo', 'cto', 'vp', 'director', 'executive']));
  const archives = metric(r => containsAny(r, ['.zip', '.iso', '.7z', '.rar', 'archive', 'dropper']));
  const forwarding = metric(r => containsAny(r, ['forwarding rule', 'auto-forward', 'mailbox rule', 'inbox rule']));
  const oauth = metric(r => containsAny(r, ['oauth', 'consent grant', 'app consent']));
  const typosquat = metric(r => containsAny(r, ['typosquat', 'punycode-domain', 'spoofed domain']));
  const malwareFamilies = metric(r => containsAny(r, ['emotet', 'qakbot', 'agenttesla']));
  const attachmentDownloads = metric(isAttachmentDownload);
  const mailApps = metric(r => /mail_component_(?:running|started|stopped)/i.test(String(r.eventType || r.ruleId || '')) && r.rawEvent?.raw?.component_type !== 'server' && r.rawEvent?.component_type !== 'server');
  const webmailSessions = metric(r => /webmail_session/i.test(String(r.eventType || r.ruleId || '')));
  const critical = metric(r => alertSeverity(r) === 'critical');
  const high = metric(r => alertSeverity(r) === 'high');
  const mailServers = metric(r => /mail_component_(?:running|started|stopped)/i.test(String(r.eventType || r.ruleId || '')) && (r.rawEvent?.raw?.component_type === 'server' || r.rawEvent?.component_type === 'server'));
  const uniqueEndpointCount = platform => new Set(rows.filter(row => processOs(row) === platform).map(row => normHost(alertHost(row))).filter(host => host !== 'unknown')).size;

  const kpis = [
    { label: '🛡️ 1. Total Email Threat Signals', val: shortNum(totalRows), trend: 'Mail Ingestion', color: MON.blue, data: timeline },
    { label: '📧 2. Quarantined Phishing Emails', val: shortNum(quarantinedPhish.value), trend: 'Quarantined', color: MON.red, data: quarantinedPhish.data },
    { label: '📎 3. Malicious Macro Attachments (XLSM/DOCM)', val: shortNum(macro.value), trend: 'Macro Malware', color: MON.orange, data: macro.data },
    { label: '👔 4. BEC & Executive Wire Fraud Attacks', val: shortNum(bec.value), trend: 'BEC Fraud', color: MON.purple, data: bec.data },
    { label: '🌐 5. SPF / DKIM / DMARC Spoofing Attempts', val: shortNum(spoof.value), trend: 'Spoofing', color: MON.yellow, data: spoof.data },
    { label: '🔗 6. Credential Harvesting Links Extracted', val: shortNum(urls.value), trend: 'Phish Links', color: MON.red, data: urls.data },
    { label: '👑 7. Targeted Executive Mailboxes', val: shortNum(executives.value), trend: 'Exec Target', color: MON.cyan, data: executives.data },
    { label: '📦 8. Suspicious ZIP / ISO Dropper Archives', val: shortNum(archives.value), trend: 'Archive Drop', color: MON.orange, data: archives.data },
    { label: '📋 9. External Auto-Forward Mailbox Rules', val: shortNum(forwarding.value), trend: 'Forward Rule', color: MON.pink, data: forwarding.data },
    { label: '🔑 10. OAuth App Consent Abuse Alerts', val: shortNum(oauth.value), trend: 'OAuth Abuse', color: MON.red, data: oauth.data },
    { label: '🎯 11. Typosquatted Domain Phishing Links', val: shortNum(typosquat.value), trend: 'Typosquatting', color: MON.yellow, data: typosquat.data },
    { label: '🦠 12. Emotet / Qakbot Mail Droppers', val: shortNum(malwareFamilies.value), trend: 'Malware Family', color: MON.red, data: malwareFamilies.data },
    { label: '💻 13. Mail Application Lifecycle Events', val: shortNum(mailApps.value), trend: 'Mail Client', color: MON.cyan, data: mailApps.data },
    { label: '🌐 14. Webmail Sessions Observed by Agent', val: shortNum(webmailSessions.value), trend: 'Agent Webmail', color: MON.blue, data: webmailSessions.data },
    { label: '🪟 15. Windows Monitored Mail Endpoints', val: shortNum(uniqueEndpointCount('Windows')), trend: 'Windows Mail', color: MON.cyan, data: buildBuckets(rows, 8, 24, r => processOs(r) === 'Windows') },
    { label: '🐧 16. Linux Monitored Mail Endpoints', val: shortNum(uniqueEndpointCount('Linux')), trend: 'Linux Postfix', color: MON.orange, data: buildBuckets(rows, 8, 24, r => processOs(r) === 'Linux') },
    { label: '🍎 17. macOS Monitored Mail Endpoints', val: shortNum(uniqueEndpointCount('macOS')), trend: 'macOS Mail', color: MON.purple, data: buildBuckets(rows, 8, 24, r => processOs(r) === 'macOS') },
    { label: '🚨 18. Critical Email Phishing Alerts', val: shortNum(critical.value), trend: 'Critical Risk', color: MON.red, data: critical.data },
    { label: '⚠️ 19. High Risk Email Anomaly Alerts', val: shortNum(high.value), trend: 'High Risk', color: MON.orange, data: high.data },
    { label: '📨 20. Mail Server Lifecycle Events', val: shortNum(mailServers.value), trend: 'Mail Server', color: MON.green, data: mailServers.data },
    { label: '📥 21. Email Documents Downloaded', val: shortNum(attachmentDownloads.value), trend: 'PDF / DOC / XLS', color: MON.cyan, data: attachmentDownloads.data },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'offline'),
      monitor: sys.edrEnabled !== false,
      events: hostEvents,
      threats,
      platform: processOs(sys),
      lastSeen: sys.lastSeen || sys.lastHeartbeat || null,
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
        {activeTab === 'log-monitor' ? (
          <EmailThreatLogMonitor alerts={rows} total={totalRows} />
        ) : activeTab === 'reports' ? (
          <CapabilityReportsPanel capabilityId={15} alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <EmailThreatOverviewDashboard alerts={alerts} total={totalRows} />
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

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Email Security & Mail Gateway Infrastructure</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · Mail Sentinel telemetry</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Name</span><span>Hostname</span><span>Platform Type</span><span>Mail Sentinel</span><span>Signals</span><span>Email Threats</span><span>Last Audit</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: row.monitor ? MON.green : MON.red, textTransform: 'uppercase' }}>{row.monitor ? 'Enabled' : 'Disabled'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : '—'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend email agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📊 Inbound Email Threat Timeline (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} email threats`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🚨 Top Malicious Attachment Types</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['XLSM / DOCM (VBA Macros)', rows.filter(r => containsAny(r, ['xlsm', 'docm', 'vba', 'macro'])).length],
                    ['ZIP / RAR / 7Z Archives', rows.filter(r => containsAny(r, ['zip', 'rar', '7z'])).length],
                    ['ISO / LNK Droppers', rows.filter(r => containsAny(r, ['iso', 'lnk'])).length],
                    ['PDF Credential Harvester', rows.filter(r => containsAny(r, ['pdf', 'credential'])).length],
                  ].map(([att, count], index) => (
                    <div key={att} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 180 }}>{att}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index % 4], fontWeight: 800 }}>{count} files</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Email Auth Distribution</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['SPF Failures (Bad Sender IP)', rows.filter(r => /fail|softfail/i.test(r.emailAuth?.spf || '')).length],
                    ['DKIM Missing / Invalid Signature', rows.filter(r => /fail|none|missing/i.test(r.emailAuth?.dkim || '')).length],
                    ['DMARC Alignment Rejection', rows.filter(r => /fail|reject/i.test(r.emailAuth?.dmarc || '')).length],
                    ['Valid Authenticated Email', rows.filter(r => ['pass', 'passed'].includes(String(r.emailAuth?.spf || '').toLowerCase()) && ['pass', 'passed'].includes(String(r.emailAuth?.dkim || '').toLowerCase())).length],
                  ].map(([type, count], index) => (
                    <div key={type} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{type}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.green][index % 4], fontWeight: 800 }}>{shortNum(count)}</span>
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
// 5. OVERLAY CAPABILITY MODAL EXPORT (`EmailThreatMonitoringPage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function EmailThreatMonitoringPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '15';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({
        page: 1,
        limit: 1000,
        capabilityId,
        capability: 'email-threat-monitoring',
        windowHours: 24,
      });
      const r = await api.get(`/email-threat/logs?${q}`);
      const next = r.data?.events || [];
      setAlerts(next);
      setTotal(r.data?.total || next.length);
    } catch {
      setAlerts([]);
      setTotal(0);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, [capabilityId]);

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
    socket.on('email:event', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('email:event', buf.add);
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
            🛡️ 15. Email Threat Monitoring
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <EmailThreatDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <EmailThreatMonitoringPage />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 6. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function EmailThreatSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=15" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Email Threat SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=15')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="emailthreat" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <EmailThreatDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias export for backward compatibility ──
export { EmailThreatDashboardPanel as EmailThreatDashboard };
