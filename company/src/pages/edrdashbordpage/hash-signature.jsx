/**
 * Hash & Digital Signature Analysis — canonical UI/backend capability ID: 25
 *
 * 100% Self-Contained Enterprise SOC Hash & Signature Analysis & Threat Intelligence Module
 * Full Coverage across 8 Core Hash Categories & 15 Policy Engine Specifications (File Hash Verification, MD5/SHA1/SHA256, Digital Signature Validation, VirusTotal Threat Intel, Unsigned Executables, Malware Signatures, etc.)
 * Linked to the dedicated live backend APIs (`/api/hash-signature/events`,
 * `/api/hash-signature/statistics`, and `/api/hash-signature/report`) plus
 * tenant-scoped Socket.io real-time streaming.
 * Architecture & Design System mirror User & Auth (4), Process (1), FIM (2), Network (3), Memory (5), Registry (6), System Changes (7), Persistence (8), UEBA (11), Data Security (12), Credential Security (13), Lateral Movement (14), Email Threat (15), Insider Threat (16), Patch (17), Sandbox (18), Kernel (19), API Call (20), Script (21), Time Anomaly (22), Geolocation (23), Service (24)
 */
import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
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
  clean: MON.cyan,
};

const SEV_BG = {
  critical: 'rgba(248, 113, 113, 0.15)',
  high: 'rgba(251, 146, 60, 0.15)',
  medium: 'rgba(251, 191, 36, 0.15)',
  low: 'rgba(52, 211, 153, 0.15)',
  info: 'rgba(34, 211, 238, 0.15)',
  clean: 'rgba(34, 211, 238, 0.15)',
};

function MiniSparkline({ data = [8, 14, 10, 18, 16, 24, 20, 28], color = MON.cyan, height = 30 }) {
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

function rawTelemetry(row = {}) {
  const root = row?.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = root.raw && typeof root.raw === 'object' ? root.raw : {};
  return { ...nested, ...root };
}

function telemetryValue(row, ...keys) {
  const raw = rawTelemetry(row);
  for (const key of keys) {
    const value = row?.[key] ?? raw?.[key];
    if (value !== undefined && value !== null && value !== '') return value;
  }
  return undefined;
}

function alertTime(row) {
  return telemetryValue(row, 'timestamp', 'createdAt', 'time', 'observedAt', 'updatedAt');
}

function alertHost(row) {
  return telemetryValue(row, 'hostname', 'host', 'system_name', 'agentName', 'endpointId', 'endpoint_id', 'system_id') || row?.systemId?.hostname || row?.systemId?.name || '—';
}

function alertUser(row) {
  return telemetryValue(row, 'username', 'user', 'userName', 'file_user', 'changed_by_user') || 'Not linked';
}

function alertSeverity(row) {
  const s = String(row?.hashSignatureSeverity || row?.severity || 'low').toLowerCase();
  if (['critical', 'high', 'medium', 'low', 'info', 'clean'].includes(s)) return s;
  return 'low';
}

function processOs(row) {
  const osStr = String(telemetryValue(row, 'os', 'osType', 'os_type', 'platform', 'system', 'hostname', 'host') || row?.systemId?.os || row?.systemId?.osType || '').toLowerCase();
  if (osStr.includes('win')) return 'Windows PE';
  if (osStr.includes('lin') || osStr.includes('ubuntu')) return 'Linux ELF';
  if (osStr.includes('mac') || osStr.includes('darwin')) return 'macOS Mach-O';
  return 'Unknown';
}

// ── Hash & Signature Telemetry Extractors ──────────────────────────────────
function fileName(row) {
  const explicit = telemetryValue(row, 'fileName', 'file_name', 'file', 'processName', 'process_name');
  if (explicit) return explicit;
  const pathValue = filePath(row);
  return pathValue && pathValue !== '—' ? String(pathValue).split(/[\\/]/).pop() : 'Unidentified file';
}

function filePath(row) {
  return telemetryValue(row, 'filePath', 'file_path', 'sourcePath', 'source_path', 'path', 'processExe', 'process_exe', 'exe') || '—';
}

function fileHash(row) {
  return telemetryValue(row, 'sha256', 'fileHash', 'file_hash', 'currentHash', 'current_hash', 'newHash', 'new_hash', 'hash') || '';
}

function signatureStatus(row) {
  return String(telemetryValue(row, 'signatureStatus', 'signature_status', 'signature') || 'UNKNOWN').toUpperCase();
}

function publisher(row) {
  return telemetryValue(row, 'publisher', 'signer', 'packageOwner', 'package_owner') || (processOs(row) === 'Linux ELF' ? 'Linux package metadata unavailable' : 'Not signed / not collected');
}

function vtScore(row) {
  const raw = rawTelemetry(row);
  const vt = raw.virustotal && typeof raw.virustotal === 'object' ? raw.virustotal : {};
  const detections = telemetryValue(row, 'vtDetections') ?? vt.malicious ?? vt.detections;
  const total = telemetryValue(row, 'vtTotal') ?? vt.total_engines ?? vt.total;
  const verdict = telemetryValue(row, 'vtVerdict', 'vt_verdict', 'reputation') || vt.verdict || 'UNKNOWN';
  if (detections != null || total != null) return `${detections || 0}/${total || 0} · ${verdict}`;
  return verdict;
}

function hashRule(row) {
  return telemetryValue(row, 'hashSignatureRule', 'ruleName', 'ruleId', 'rule_id', 'eventType', 'event_type') || 'HASH_SIGNATURE_OBSERVED';
}

function hashRiskScore(row) {
  return Number(telemetryValue(row, 'hashSignatureRiskScore', 'riskScore', 'risk_score') ?? 0);
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
  return row?._id || row?.id || row?.key || `${alertTime(row) || ''}-${alertHost(row)}-${fileHash(row)}`;
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

function EvidenceGrid({ rows = [] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 10 }}>
      {rows.map(([label, value]) => (
        <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.line}`, borderRadius: 7, padding: 12, minWidth: 0 }}>
          <div style={{ color: MON.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{label}</div>
          <div style={{ color: MON.text, fontSize: 11, marginTop: 6, overflowWrap: 'anywhere', fontFamily: /hash|thumbprint|serial|command/i.test(label) ? 'monospace' : 'inherit' }}>{value ?? '—'}</div>
        </div>
      ))}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. HASH FORENSIC INVESTIGATION POPUP MODAL (10 Grouped Master Tabs)
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignatureForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.blue;
  const forensicRaw = rawTelemetry(log);
  const forensicVt = forensicRaw.virustotal && typeof forensicRaw.virustotal === 'object' ? forensicRaw.virustotal : {};

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'hashes', label: '🔑 2. Cryptographic Hashes' },
    { id: 'cert', label: '🔐 3. Digital Certificate' },
    { id: 'vt', label: '🦠 4. Threat Intel & VT' },
    { id: 'process', label: '⚙️ 5. Process & Memory' },
    { id: 'baseline', label: '🖥️ 6. System Baseline' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'policy', label: '🛡️ 8. Policy Evaluation' },
    { id: 'timeline', label: '⏱️ 9. Lifecycle Timeline' },
    { id: 'actions', label: '📄 10. Reports & Actions' },
  ];

  const handleAction = async (actionType, actionName) => {
    try {
      if (typeof onAction !== 'function') throw new Error('Authorized response workflow is unavailable');
      const result = await onAction(actionType, log);
      setActionSuccess(result?.message || `Authorized response request submitted: ${actionName}`);
    } catch (error) {
      setActionSuccess(error?.response?.data?.message || error?.message || `${actionName} was not submitted`);
    }
    setTimeout(() => setActionSuccess(null), 5000);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🔑</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Hash & Signature Forensic Panel — {fileName(log)}
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {hashRiskScore(log)}/100
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                SHA-256: <strong style={{ color: MON.yellow, fontFamily: 'monospace' }}>{fileHash(log) ? `${fileHash(log).substring(0, 24)}...` : '—'}</strong> | Signature: <strong style={{ color: MON.red }}>{signatureStatus(log)}</strong> | Publisher: <strong>{publisher(log)}</strong>
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
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 16 }}>
                {[
                  ['File Name', fileName(log), MON.cyan],
                  ['Digital Signature', signatureStatus(log), MON.red],
                  ['Publisher Signer', publisher(log), MON.yellow],
                  ['VirusTotal Verdict', vtScore(log), MON.red],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>🔑 Cryptographic Hash & Path Verification</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  The endpoint agent observed <strong>{fileName(log)}</strong> at <code style={{ color: MON.yellow, background: '#000', padding: '2px 6px', borderRadius: 4 }}>{filePath(log)}</code>. SHA-256: <code style={{ color: MON.cyan, background: '#000', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>{fileHash(log) || 'not collected'}</code>. Threat intelligence verdict: <strong>{vtScore(log)}</strong>. An unknown hash is retained as telemetry and is not treated as malware without supporting evidence.
                </div>
              </div>
              <EvidenceGrid rows={[
                ['Full File Path', filePath(log)], ['File Size', telemetryValue(log, 'fileSize', 'file_size') ?? 'Not supplied'],
                ['Created', telemetryValue(log, 'fileCreatedAt', 'file_created_at', 'created_time', 'ctime') || 'Not collected'], ['Modified', telemetryValue(log, 'fileModifiedAt', 'file_modified_at', 'modified_time', 'mtime') || 'Not collected'],
                ['Accessed', telemetryValue(log, 'fileAccessedAt', 'file_accessed_at', 'accessed_time', 'atime') || 'Not collected'], ['Owner / Group', `${telemetryValue(log, 'fileOwner', 'file_owner', 'owner') || 'Not collected'} / ${telemetryValue(log, 'fileGroup', 'file_group', 'group') || 'Not collected'}`],
                ['Permissions', telemetryValue(log, 'filePermissions', 'file_permissions', 'permissions', 'mode') || 'Not collected'], ['Endpoint', alertHost(log)],
              ]} />
            </div>
          )}

          {/* TAB 10: REPORTS & SOC ACTIONS */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {actionSuccess && <div style={{ padding: 10, background: `${MON.cyan}18`, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, fontSize: 11 }}>{actionSuccess}</div>}
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Hash Security Engine Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('block_hash', `Block SHA-256 ${fileHash(log).substring(0, 16)}...`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛑 Blacklist SHA-256 Hash
                  </button>
                  <button type="button" onClick={() => handleAction('quarantine_file', `Quarantine ${filePath(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Quarantine File
                  </button>
                  <button type="button" onClick={() => handleAction('kill_process', 'Kill process and terminate execution')} style={{ padding: '8px 14px', background: `${MON.yellow}25`, border: `1px solid ${MON.yellow}`, color: MON.yellow, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🚫 Kill Process & Terminate
                  </button>
                  <button type="button" onClick={() => handleAction('add_ioc', 'Add SHA-256 to tenant IOC registry')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Add Hash IOC
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'hashes' && <EvidenceGrid rows={[
            ['SHA-256', fileHash(log) || 'Not collected'], ['SHA-1', telemetryValue(log, 'sha1', 'file_hash_sha1') || 'Disabled / not collected'], ['MD5 (compatibility)', telemetryValue(log, 'md5', 'fileHashMd5', 'file_hash_md5') || 'Disabled / not collected'],
            ['Baseline SHA-256', telemetryValue(log, 'baselineHash', 'baseline_hash', 'oldHash', 'old_hash') || 'Not baselined'], ['Current SHA-256', telemetryValue(log, 'currentHash', 'current_hash', 'newHash', 'new_hash') || fileHash(log) || 'Not collected'], ['Match Status', telemetryValue(log, 'baselineHash', 'oldHash', 'old_hash') ? (log.hashMismatch ? 'MISMATCH' : 'MATCH') : 'NOT BASELINED'],
          ]} />}
          {activeTab === 'cert' && <EvidenceGrid rows={[
            ['Signature Status', signatureStatus(log)], ['Publisher', publisher(log)], ['Subject', telemetryValue(log, 'certificateSubject', 'certificate_subject') || 'No certificate attached'], ['Issuer', telemetryValue(log, 'certificateIssuer', 'certificate_issuer') || 'No certificate attached'],
            ['Certificate Serial', telemetryValue(log, 'certificateSerial', 'certificate_serial') || 'Not available'], ['Thumbprint', telemetryValue(log, 'certificateThumbprint', 'certificate_thumbprint') || 'Not available'], ['Valid From', telemetryValue(log, 'certificateValidFrom', 'certificate_valid_from') || 'Not available'], ['Valid Until', telemetryValue(log, 'certificateValidUntil', 'certificate_valid_until') || 'Not available'],
            ['Revocation', telemetryValue(log, 'certificateRevocationStatus', 'revocation_status') || 'NOT CHECKED'], ['Trust', telemetryValue(log, 'trustStatus', 'trust_status') || 'UNKNOWN'], ['Linux Package', telemetryValue(log, 'packageOwner', 'package_owner') || 'Not package-managed'], ['Package Verification', telemetryValue(log, 'packageVerificationStatus', 'package_verification_status') || 'Not evaluated'],
          ]} />}
          {activeTab === 'vt' && <EvidenceGrid rows={[
            ['IOC Match', log.threatIntelMatch || log.iocMatched ? 'MATCH' : 'NO CONFIRMED MATCH'], ['Source', telemetryValue(log, 'threatIntelSource', 'threat_intel_source') || log.tiFeeds?.feedSource || (vtScore(log) !== 'UNKNOWN' ? 'VirusTotal' : 'No source')],
            ['Malware Family', telemetryValue(log, 'malwareFamily', 'malware_family', 'malwareType', 'malware_type') || forensicVt.malware_family || 'Unclassified'], ['Reputation', telemetryValue(log, 'reputation', 'vtVerdict', 'vt_verdict') || forensicVt.verdict || 'UNKNOWN'], ['Confidence', telemetryValue(log, 'confidenceScore', 'confidence_score', 'tiConfidence') ?? forensicVt.score ?? 'Not supplied'], ['VT Result', vtScore(log)],
          ]} />}
          {activeTab === 'process' && <EvidenceGrid rows={[
            ['Process', telemetryValue(log, 'processName', 'process_name') || 'No process linked to this file event'], ['PID', telemetryValue(log, 'pid') ?? 'Not linked'], ['Parent PID', telemetryValue(log, 'parentPid', 'parent_pid') ?? 'Not linked'], ['Parent Process', telemetryValue(log, 'parentProcessName', 'parent_process_name') || 'Not linked'],
            ['Command Line', telemetryValue(log, 'processCmdline', 'process_cmdline', 'cmdline', 'command_line') || 'Not collected for this event'], ['User', alertUser(log)], ['Executable', telemetryValue(log, 'processExe', 'process_exe', 'exe') || filePath(log)], ['Start Time', telemetryValue(log, 'processCreateTime', 'process_create_time') || 'Not supplied'],
          ]} />}
          {activeTab === 'baseline' && <EvidenceGrid rows={[
            ['Endpoint', telemetryValue(log, 'endpointId', 'endpoint_id', 'system_id') || alertHost(log)], ['File Path', filePath(log)], ['Baseline Hash', telemetryValue(log, 'baselineHash', 'baseline_hash', 'oldHash', 'old_hash') || 'Not baselined'], ['Current Hash', telemetryValue(log, 'currentHash', 'current_hash', 'newHash', 'new_hash') || fileHash(log) || 'Not collected'],
            ['Hash Mismatch', telemetryValue(log, 'baselineHash', 'oldHash', 'old_hash') ? (log.hashMismatch ? 'YES' : 'NO') : 'NOT EVALUATED'], ['File Size', telemetryValue(log, 'fileSize', 'file_size') ?? 'Not supplied'], ['First Seen', telemetryValue(log, 'firstSeen', 'first_seen') || 'Not supplied'], ['Last Seen', telemetryValue(log, 'lastSeen', 'last_seen') || alertTime(log) || 'Not supplied'],
          ]} />}
          {activeTab === 'mitre' && <EvidenceGrid rows={[
            ['MITRE Technique', log.mitreTechnique || log.mitreId || '—'], ['Tactic', log.mitreTactic || '—'], ['Detection Rule', hashRule(log)], ['Risk Score', `${hashRiskScore(log)}/100`], ['Severity', alertSeverity(log).toUpperCase()], ['Reason', (log.riskReasons || []).join('; ') || log.description || '—'],
          ]} />}
          {activeTab === 'policy' && <EvidenceGrid rows={[
            ['Detection Rule', hashRule(log)], ['Policy', log.policyName || 'Default tenant hash policy'], ['Decision', log.actionTaken || log.recommendedAction || 'MONITOR'], ['Risk Threshold Result', `${hashRiskScore(log)}/100`],
            ['Allowlisted', log.allowlisted ? 'YES' : 'NO'], ['Evaluation Reasons', (log.riskReasons || []).join('; ') || 'No elevated signal'],
          ]} />}
          {activeTab === 'timeline' && <EvidenceGrid rows={[
            ['Observed', alertTime(log) || 'Not supplied'], ['First Seen', telemetryValue(log, 'firstSeen', 'first_seen') || 'Not supplied'], ['Last Seen', telemetryValue(log, 'lastSeen', 'last_seen') || 'Not supplied'], ['File Action', telemetryValue(log, 'fileAction', 'file_action', 'eventType', 'event_type', 'change_type') || 'Observed'],
            ['Status', telemetryValue(log, 'status') || 'open'], ['Containment', telemetryValue(log, 'containmentStatus', 'containment_status') || 'none'], ['Endpoint', alertHost(log)], ['Event ID', telemetryValue(log, 'eventId', 'event_id') || log._id || 'Not supplied'],
          ]} />}
        </div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 2. POLICY RULE CREATOR WIZARD MODAL (`HashSignaturePolicyWizardModal`)
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignaturePolicyWizardModal({ onClose, onSave }) {
  const [name, setName] = useState('');
  const [category, setCategory] = useState('Unsigned Executable Control');
  const [severity, setSeverity] = useState('Critical');
  const [action, setAction] = useState('QUARANTINE & BLOCK');
  const [blacklistedHash, setBlacklistedHash] = useState('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  const [vtCutoff, setVtCutoff] = useState('5');

  const categories = [
    'Unsigned Executable Control', 'Blacklisted SHA-256 IOC Hash', 'Invalid / Revoked Certificate',
    'Critical System Binary Shift', 'Fake Vendor & Masqueraded Cert', 'Known Ransomware & Trojan Hashes',
    'Memory-Loaded Unsigned DLL', 'PowerShell & Script Hashes', 'VirusTotal Feed Correlation',
    'Duplicate Malicious Files', 'File-Less Malware Indicators', 'Web Server Binary Integrity',
    'Rootkit & Kernel Driver Hashes', 'Untrusted Publisher Enforcement', 'EDR Hash Baseline Sync'
  ];

  const actions = [
    'LOG & MONITOR', 'ALERT & NOTIFY SOC', 'QUARANTINE & BLOCK',
    'KILL PROCESS & TERMINATE', 'ISOLATE ENDPOINT', 'CRITICAL BLOCK & SOC ESCALATION'
  ];

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!name.trim()) return;
    onSave({
      id: `hash-pol-${Date.now()}`,
      name: name.trim(),
      cat: category,
      action,
      severity,
      status: 'Active',
      details: { blacklistedHash, vtCutoff }
    });
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: 'min(720px, 95vw)', background: MON.bg, border: `1px solid ${MON.cyan}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.85)', overflow: 'hidden' }}>
        {/* Header */}
        <div style={{ padding: '16px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ fontSize: 22 }}>🔑</span>
            <div>
              <h3 style={{ margin: 0, fontSize: 16, fontWeight: 900, color: MON.cyan }}>
                Hash & Signature Policy Wizard
              </h3>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 2 }}>
                Construct custom SHA-256 hash blacklists & digital signature enforcement rules
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer' }}>✕</button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Policy Rule Title *
            </label>
            <input
              type="text"
              required
              placeholder="e.g. Block Unsigned Executables in Temp Directory & Blacklist IOC Hashes"
              value={name}
              onChange={e => setName(e.target.value)}
              style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 12, outline: 'none', boxSizing: 'border-box' }}
            />
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Policy Category
              </label>
              <select value={category} onChange={e => setCategory(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                {categories.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
            </div>
            <div>
              <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
                Rule Severity
              </label>
              <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.text, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: 10, fontWeight: 800, color: MON.muted, textTransform: 'uppercase', marginBottom: 6 }}>
              Action Engine Response
            </label>
            <select value={action} onChange={e => setAction(e.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, color: MON.red, fontWeight: 800, padding: '9px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }}>
              {actions.map(a => <option key={a} value={a}>{a}</option>)}
            </select>
          </div>

          <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 10 }}>
            <div style={{ fontSize: 11, fontWeight: 800, color: MON.cyan }}>⚙️ Advanced Hash Thresholds & Blacklist Signatures</div>

            <div>
              <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>Target Blacklist SHA-256 Hash Pattern</label>
              <input type="text" value={blacklistedHash} onChange={e => setBlacklistedHash(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.yellow, padding: '7px 10px', borderRadius: 4, fontSize: 11, fontFamily: 'monospace', boxSizing: 'border-box' }} />
            </div>

            <div>
              <label style={{ display: 'block', fontSize: 9, color: MON.muted, marginBottom: 4 }}>VirusTotal Detections Cutoff Threshold</label>
              <input type="number" value={vtCutoff} onChange={e => setVtCutoff(e.target.value)} style={{ width: '100%', background: MON.bg, border: `1px solid ${MON.border}`, color: MON.cyan, padding: '7px 10px', borderRadius: 4, fontSize: 11, boxSizing: 'border-box' }} />
            </div>
          </div>

          {/* Footer Actions */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 8 }}>
            <button type="button" onClick={onClose} style={{ padding: '9px 18px', background: 'transparent', border: `1px solid ${MON.border}`, color: MON.muted, borderRadius: 6, fontSize: 11, fontWeight: 700, cursor: 'pointer' }}>
              Cancel
            </button>
            <button type="submit" style={{ padding: '9px 22px', background: MON.cyan, border: 'none', color: '#000', borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
              ⚡ Deploy Hash Policy
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 3. POLICY ENGINE MANAGEMENT PANEL (`HashSignaturePolicyEngine`)
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignaturePolicyEngine() {
  const [isWizardOpen, setIsWizardOpen] = useState(false);
  const [policies, setPolicies] = useState([
    { id: 'hash-pol-1', name: 'Unsigned Executable Execution Block in Temp & AppData', cat: 'Unsigned Executable Control', action: 'BLOCK & TERMINATE', status: 'Active', severity: 'Critical' },
    { id: 'hash-pol-2', name: 'Blacklisted SHA-256 IOC Hash Instant Quarantine', cat: 'Blacklisted SHA-256 IOC Hash', action: 'QUARANTINE & ISOLATE', status: 'Active', severity: 'Critical' },
    { id: 'hash-pol-3', name: 'Expired or Revoked Digital Certificate Guard', cat: 'Invalid / Revoked Certificate', action: 'BLOCK & ALERT', status: 'Active', severity: 'High' },
    { id: 'hash-pol-4', name: 'System Binary Hash Baseline Deviation Shield', cat: 'Critical System Binary Shift', action: 'CRITICAL ALERT & RESTORE', status: 'Active', severity: 'Critical' },
    { id: 'hash-pol-5', name: 'Impersonated Vendor Signature (Fake Microsoft Cert)', cat: 'Fake Vendor & Masqueraded Cert', action: 'BLOCK & QUARANTINE', status: 'Active', severity: 'Critical' },
    { id: 'hash-pol-6', name: 'VirusTotal High Detection Hash (>5 Positive engines)', cat: 'VirusTotal Feed Correlation', action: 'KILL PROCESS & ALERT', status: 'Active', severity: 'High' },
    { id: 'hash-pol-7', name: 'Unsigned Memory-Loaded DLL Module Enforcement', cat: 'Memory-Loaded Unsigned DLL', action: 'UNLOAD & ALERT', status: 'Active', severity: 'High' },
    { id: 'hash-pol-8', name: 'Known Ransomware & Trojan Binary Signatures', cat: 'Known Ransomware & Trojan Hashes', action: 'ISOLATE ENDPOINT', status: 'Active', severity: 'Critical' },
  ]);
  const [successMsg, setSuccessMsg] = useState(null);

  const togglePolicy = (id) => {
    setPolicies(prev => prev.map(p => p.id === id ? { ...p, status: p.status === 'Active' ? 'Disabled' : 'Active' } : p));
  };

  const handleAddPolicy = (newPolicy) => {
    setPolicies(prev => [newPolicy, ...prev]);
    setIsWizardOpen(false);
    setSuccessMsg(`Hash Policy "${newPolicy.name}" successfully deployed to Security Engine!`);
    setTimeout(() => setSuccessMsg(null), 4000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* Header */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 16, color: MON.cyan, fontWeight: 900 }}>🛡️ Hash & Signature Analysis — Policy Engine</h3>
          <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Configure 15 Hash & Signature Categories: MD5/SHA256 Blacklists, Authenticode Certs, VirusTotal IOC Detections, and Action Engines</div>
        </div>
        <button type="button" onClick={() => setIsWizardOpen(true)} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '8px 18px', borderRadius: 6, fontWeight: 900, cursor: 'pointer', fontSize: 12 }}>
          ➕ Create New Policy Rule
        </button>
      </div>

      {successMsg && (
        <div style={{ padding: '10px 14px', background: 'rgba(52, 211, 153, 0.15)', border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 800 }}>
          ✅ {successMsg}
        </div>
      )}

      {/* Policy Rules Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11, textAlign: 'left' }}>
          <thead>
            <tr style={{ background: MON.card2, color: MON.muted, borderBottom: `1px solid ${MON.border}` }}>
              <th style={{ padding: 10 }}>Policy Name</th>
              <th style={{ padding: 10 }}>Policy Category</th>
              <th style={{ padding: 10 }}>Action Engine Rule</th>
              <th style={{ padding: 10 }}>Severity</th>
              <th style={{ padding: 10 }}>Status</th>
              <th style={{ padding: 10 }}>Toggle</th>
            </tr>
          </thead>
          <tbody>
            {policies.map(p => (
              <tr key={p.id} style={{ borderBottom: `1px solid ${MON.line}` }}>
                <td style={{ padding: 10, color: MON.text, fontWeight: 900 }}>{p.name}</td>
                <td style={{ padding: 10, color: MON.purple, fontWeight: 800 }}>{p.cat}</td>
                <td style={{ padding: 10, color: MON.red, fontWeight: 900 }}>{p.action}</td>
                <td style={{ padding: 10, color: p.severity === 'Critical' ? MON.red : MON.orange, fontWeight: 800 }}>{p.severity}</td>
                <td style={{ padding: 10, color: p.status === 'Active' ? MON.green : MON.sub, fontWeight: 900 }}>{p.status}</td>
                <td style={{ padding: 10 }}>
                  <button type="button" onClick={() => togglePolicy(p.id)} style={{ padding: '3px 10px', background: p.status === 'Active' ? `${MON.green}20` : `${MON.red}20`, border: `1px solid ${p.status === 'Active' ? MON.green : MON.red}55`, color: p.status === 'Active' ? MON.green : MON.red, borderRadius: 4, fontSize: 10, fontWeight: 800, cursor: 'pointer' }}>
                    {p.status === 'Active' ? 'Disable' : 'Enable'}
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {isWizardOpen && <HashSignaturePolicyWizardModal onClose={() => setIsWizardOpen(false)} onSave={handleAddPolicy} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 4. SUB-PANELS (SIEM Log Monitor, Reports Generator, Overview Dashboard)
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignatureLogMonitor({ alerts = [], onResponse }) {
  const [query, setQuery] = useState('');
  const [severity, setSeverity] = useState('all');
  const [signature, setSignature] = useState('all');
  const [endpoint, setEndpoint] = useState('all');
  const [hours, setHours] = useState('24');
  const [sort, setSort] = useState('newest');
  const [page, setPage] = useState(1);
  const [selectedLog, setSelectedLog] = useState(null);
  const pageSize = 25;
  const endpoints = useMemo(() => [...new Set(alerts.map(alertHost).filter(value => value && value !== '—'))].sort(), [alerts]);

  const filtered = useMemo(() => {
    const cutoff = Date.now() - Number(hours) * 3600000;
    return alerts.filter(a => {
      const matchQ = !query || `${fileName(a)} ${filePath(a)} ${fileHash(a)} ${hashRule(a)} ${alertHost(a)} ${publisher(a)}`.toLowerCase().includes(query.toLowerCase());
      const matchS = severity === 'all' || alertSeverity(a) === severity.toLowerCase();
      const matchSignature = signature === 'all' || signatureStatus(a) === signature;
      const matchEndpoint = endpoint === 'all' || alertHost(a) === endpoint;
      const time = new Date(alertTime(a) || 0).getTime();
      return matchQ && matchS && matchSignature && matchEndpoint && (!Number.isFinite(time) || time >= cutoff);
    }).sort((a, b) => sort === 'risk'
      ? hashRiskScore(b) - hashRiskScore(a)
      : new Date(alertTime(b) || 0) - new Date(alertTime(a) || 0));
  }, [alerts, query, severity, signature, endpoint, hours, sort]);
  const pageCount = Math.max(1, Math.ceil(filtered.length / pageSize));
  const visible = filtered.slice((page - 1) * pageSize, page * pageSize);
  useEffect(() => setPage(1), [query, severity, signature, endpoint, hours, sort]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Filter Bar */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 12, display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <input type="text" placeholder="Search File Name, SHA-256 Hash, Detection Rule, Target Host, Signer..." value={query} onChange={e => setQuery(e.target.value)} style={{ flex: 1, minWidth: 220, background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 12px', borderRadius: 6, fontSize: 11, outline: 'none' }} />
        <select value={severity} onChange={e => setSeverity(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="clean">Clean</option>
        </select>
        <select value={signature} onChange={e => setSignature(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}><option value="all">All Signatures</option>{['VALID', 'INVALID', 'UNSIGNED', 'EXPIRED', 'REVOKED', 'UNKNOWN'].map(value => <option key={value}>{value}</option>)}</select>
        <select value={endpoint} onChange={e => setEndpoint(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}><option value="all">All Endpoints</option>{endpoints.map(value => <option key={value}>{value}</option>)}</select>
        <select value={hours} onChange={e => setHours(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}><option value="1">Last hour</option><option value="6">Last 6 hours</option><option value="24">Last 24 hours</option></select>
        <select value={sort} onChange={e => setSort(e.target.value)} style={{ background: MON.bg, border: `1px solid ${MON.line}`, color: MON.text, padding: '7px 10px', borderRadius: 6, fontSize: 11 }}><option value="newest">Newest first</option><option value="risk">Highest risk</option></select>
      </div>

      {/* SIEM Logs Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto', overflowY: 'hidden' }}>
        <div style={{ padding: '10px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📜 Hash & Signature Analysis Telemetry SIEM Logs ({filtered.length})</b>
          <span style={{ fontSize: 10, color: MON.green }}>● Live 15s Refresh</span>
        </div>
        <div style={{ minWidth: 1400 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.1fr 1.2fr 1.3fr 90px 90px 90px', gap: 8, padding: '8px 12px', background: MON.card2, color: MON.muted, fontSize: 10, fontWeight: 800 }}>
            <span>Detection Rule / Event</span><span>Target Host</span><span>File Name</span><span>SHA-256 Hash</span><span>Risk Score</span><span>Severity</span><span>Actions</span>
          </div>
          <div style={{ maxHeight: 440, overflowY: 'auto' }}>
            {visible.length ? visible.map(row => (
              <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '1.6fr 1.1fr 1.2fr 1.3fr 90px 90px 90px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                <b style={{ color: MON.cyan, cursor: 'pointer' }} onClick={() => setSelectedLog(row)}>{hashRule(row)}</b>
                <span style={{ color: MON.text }}>{alertHost(row)}</span>
                <span style={{ color: MON.yellow }}>{fileName(row)}</span>
                <span style={{ color: MON.purple, fontFamily: 'monospace', fontSize: 9 }}>{fileHash(row).substring(0, 18)}...</span>
                <b style={{ color: hashRiskScore(row) > 75 ? MON.red : MON.orange }}>{hashRiskScore(row)}/100</b>
                <span style={{ background: SEV_BG[alertSeverity(row)] || SEV_BG.low, color: SEV_COLOR[alertSeverity(row)] || MON.green, padding: '2px 6px', borderRadius: 4, fontWeight: 900, textTransform: 'uppercase', textAlign: 'center' }}>
                  {alertSeverity(row)}
                </span>
                <button type="button" onClick={() => setSelectedLog(row)} style={{ background: MON.card2, border: `1px solid ${MON.cyan}`, color: MON.cyan, padding: '4px 8px', borderRadius: 4, fontSize: 9, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Inspect
                </button>
              </div>
            )) : <div style={{ padding: 24, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No hash & signature logs match filters</div>}
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: 10, borderTop: `1px solid ${MON.line}`, color: MON.muted, fontSize: 10 }}>
            <span>Page {page} of {pageCount} · {filtered.length} events</span>
            <div style={{ display: 'flex', gap: 6 }}><button type="button" disabled={page <= 1} onClick={() => setPage(value => value - 1)}>Previous</button><button type="button" disabled={page >= pageCount} onClick={() => setPage(value => value + 1)}>Next</button></div>
          </div>
        </div>
      </div>

      {selectedLog && <HashSignatureForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onResponse} />}
    </div>
  );
}

function LegacyHashSignatureReportsTab({ alerts = [] }) {
  const [reportType, setReportType] = useState('90days');
  const [generating, setGenerating] = useState(false);
  const [generated, setGenerated] = useState(false);
  const [reportData, setReportData] = useState(null);
  const [reportError, setReportError] = useState('');
  const reportRequestRef = useRef(0);

  const selectedWindow = useCallback((type = reportType) => {
    const days = { daily: 1, weekly: 7, monthly: 30, '90days': 90 }[type] || 90;
    const to = new Date();
    return { from: new Date(to.getTime() - days * 86400000).toISOString(), to: to.toISOString() };
  }, [reportType]);

  const handleGenerate = useCallback(async (type = reportType) => {
    const requestId = reportRequestRef.current + 1;
    reportRequestRef.current = requestId;
    setGenerating(true);
    setGenerated(false);
    setReportError('');
    try {
      const response = await api.get('/hash-signature/report', { params: selectedWindow(type), skipCache: true });
      if (requestId !== reportRequestRef.current) return;
      setReportData(response.data);
      setGenerated(true);
    } catch (error) {
      if (requestId !== reportRequestRef.current) return;
      setReportData(null);
      setReportError(error?.response?.data?.message || 'Hash report generation failed');
    } finally {
      if (requestId === reportRequestRef.current) setGenerating(false);
    }
  }, [reportType, selectedWindow]);

  const liveReportSignal = `${alerts.length}:${recordId(alerts[0])}:${alertTime(alerts[0]) || ''}`;
  useEffect(() => {
    const timer = window.setTimeout(() => handleGenerate(reportType), 400);
    return () => window.clearTimeout(timer);
  }, [handleGenerate, reportType, liveReportSignal]);

  const handleExport = async (format) => {
    try {
      const response = await api.get(`/hash-signature/report/${format}`, { params: selectedWindow(), responseType: 'blob', skipCache: true });
      const blob = response.data instanceof Blob ? response.data : new Blob([response.data]);
      const url = URL.createObjectURL(blob);
      if (format === 'pdf') {
        window.open(url, '_blank', 'noopener,noreferrer');
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      } else {
        const anchor = document.createElement('a');
        anchor.href = url;
        anchor.download = `hash-signature-${reportType}.csv`;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(url);
      }
    } catch (error) {
      setReportError(error?.response?.data?.message || `${format.toUpperCase()} export failed`);
    }
  };

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 16, fontWeight: 800, color: '#f8fafc' }}>📄 Hash & Signature Analysis Executive Report Generator</h3>
            <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>Generate executive summaries for file hash verification, VirusTotal IOC matches, unsigned executables, and certificate tampering</div>
          </div>
          <button type="button" onClick={() => handleGenerate(reportType)} disabled={generating} style={{ background: MON.cyan, color: '#000', border: 'none', padding: '10px 22px', borderRadius: 6, fontWeight: 900, fontSize: 13, cursor: 'pointer' }}>
            {generating ? '⏳ Generating...' : '⚡ Generate Hash Report'}
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
                  onClick={() => {
                    if (opt.key === reportType) return;
                    reportRequestRef.current += 1;
                    setReportType(opt.key);
                    setGenerating(false);
                    setGenerated(false);
                    setReportData(null);
                    setReportError('');
                  }}
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

      {reportError && <div style={{ padding: 12, borderRadius: 7, border: `1px solid ${MON.red}`, background: `${MON.red}18`, color: MON.red, fontSize: 11 }}>{reportError}</div>}

      {(generated || generating) && (
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: `1px solid ${MON.line}`, paddingBottom: 12 }}>
            <div>
              <div style={{ fontSize: 14, fontWeight: 800, color: MON.cyan }}>📄 Hash & Signature Security Executive Report</div>
              <div style={{ fontSize: 10, color: MON.muted, marginTop: 4 }}>Selected data window: <b>{new Date(reportData?.meta?.from).toLocaleString()}</b> → <b>{new Date(reportData?.meta?.to).toLocaleString()}</b> · Report ID {reportData?.meta?.reportId}</div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button type="button" onClick={() => handleExport('csv')} style={{ background: MON.green, color: '#000', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>📥 Export Complete CSV</button>
              <button type="button" onClick={() => handleExport('pdf')} style={{ background: MON.purple, color: '#fff', border: 'none', padding: '8px 16px', borderRadius: 6, fontWeight: 800, fontSize: 12, cursor: 'pointer' }}>🖨 Print Complete Report</button>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
            {[
              { label: 'Total Hash Events', val: reportData?.summary?.total ?? 0, color: MON.cyan },
              { label: 'Malicious IOC Hashes', val: reportData?.summary?.malicious ?? 0, color: MON.red },
              { label: 'Hash Mismatches', val: reportData?.summary?.mismatches ?? 0, color: MON.orange },
              { label: 'Signature Failures', val: reportData?.summary?.signatureFailures ?? 0, color: MON.yellow },
              { label: 'Signature Validation', val: `${reportData?.summary?.signatureValidationPercent ?? 0}%`, color: MON.green },
              { label: 'Unsigned Binaries', val: reportData?.summary?.unsigned ?? 0, color: MON.orange },
              { label: 'Critical Findings', val: reportData?.summary?.critical ?? 0, color: MON.red },
              { label: 'High Findings', val: reportData?.summary?.high ?? 0, color: MON.orange },
              { label: 'On-screen Evidence Preview', val: reportData?.rows?.length ?? 0, color: MON.purple },
            ].map(c => (
              <div key={c.label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 9, color: MON.muted, fontWeight: 700, textTransform: 'uppercase' }}>{c.label}</div>
                <div style={{ fontSize: 24, fontWeight: 900, color: c.color, marginTop: 6 }}>{generating && !generated ? '…' : c.val}</div>
              </div>
            ))}
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1.1fr 1fr', gap: 12 }}>
            <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ color: MON.muted, fontSize: 10, fontWeight: 800, marginBottom: 10 }}>DETECTIONS BY RULE</div>
              {(reportData?.byRule || []).map(row => <div key={row.rule} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: `1px solid ${MON.line}`, fontSize: 10 }}><span>{row.rule}</span><b style={{ color: MON.cyan }}>{row.count}</b></div>)}
              {!reportData?.byRule?.length && <div style={{ color: MON.muted, fontSize: 10 }}>No hash/signature events in the selected window.</div>}
            </div>
            <div style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
              <div style={{ color: MON.muted, fontSize: 10, fontWeight: 800, marginBottom: 10 }}>EXECUTIVE RISK POSTURE</div>
              {[
                ['Critical', reportData?.summary?.critical || 0, MON.red],
                ['High', reportData?.summary?.high || 0, MON.orange],
                ['Medium', reportData?.summary?.medium || 0, MON.yellow],
                ['Low / Informational', reportData?.summary?.low || 0, MON.green],
              ].map(([label, value, color]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '110px 1fr 45px', gap: 8, alignItems: 'center', padding: '6px 0', fontSize: 10 }}>
                  <span>{label}</span><span style={{ height: 6, background: MON.bg, borderRadius: 4, overflow: 'hidden' }}><span style={{ display: 'block', height: '100%', width: `${Math.min(100, (Number(value) / Math.max(1, Number(reportData?.summary?.total || 0))) * 100)}%`, background: color }} /></span><b style={{ color }}>{value}</b>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export function HashSignatureReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={25} alerts={alerts} />;
}

function HashSignatureOverviewDashboard({ alerts = [], total = 0, stats = null, onResponse }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 10, padding: 14, boxShadow: 'inset 0 0 20px rgba(56,189,248,0.05)' };
  const rows = Array.isArray(alerts) ? alerts : [];
  const totals = stats?.totals || {};
  const totalEvents = Number(totals.total ?? total ?? rows.length);
  const sampleSignature = rows.reduce((acc, row) => { const key = signatureStatus(row); acc[key] = (acc[key] || 0) + 1; return acc; }, {});
  const signatureRows = stats?.signature?.length ? stats.signature : Object.entries(sampleSignature).map(([key, count]) => ({ _id: key, count }));
  const signatureCounts = Object.fromEntries(signatureRows.map(row => [String(row._id || 'UNKNOWN').toUpperCase(), Number(row.count || 0)]));
  const maliciousCount = Number(totals.malicious ?? rows.filter(row => row.threatIntelMatch || /malicious/i.test(row.reputation || row.vtVerdict || '')).length);
  const unsignedCount = Number(totals.unsigned ?? signatureCounts.UNSIGNED ?? 0);
  const validSignatureCount = Number(totals.valid ?? signatureCounts.VALID ?? 0);
  const evaluatedSignatureCount = Number(totals.signedEvaluated ?? signatureRows
    .filter(row => !['', 'UNKNOWN'].includes(String(row._id || '').toUpperCase()))
    .reduce((sum, row) => sum + Number(row.count || 0), 0));
  const validationPercent = Number(totals.signatureValidationPercent ?? (evaluatedSignatureCount ? Math.round((validSignatureCount / evaluatedSignatureCount) * 100) : 0));
  const mismatchCount = Number(totals.mismatches ?? rows.filter(row => row.hashMismatch).length);
  const reputationRows = stats?.reputation?.length ? stats.reputation : [
    { _id: 'Malicious / Threat Intel Match', count: maliciousCount },
    { _id: 'Verified & Trusted Publisher', count: signatureCounts.VALID || 0 },
    { _id: 'Unknown / Unverified Hashes', count: Math.max(0, totalEvents - maliciousCount - (signatureCounts.VALID || 0)) },
  ];
  const categoryRows = stats?.categories?.length ? stats.categories.slice(0, 6) : topCounts(rows, hashRule, 6).map(([key, count]) => ({ _id: key, count }));
  const timelineRows = stats?.timeline?.length
    ? stats.timeline.map(point => ({ label: point.hour, count: Number(point.count || 0) }))
    : buildBuckets(rows, 12, 24).map((count, index) => ({ label: `${index + 1}`, count }));
  const maxTimeline = Math.max(...timelineRows.map(point => point.count), 1);
  const changedRows = stats?.changed?.length ? stats.changed : rows.filter(row => row.hashMismatch).slice(0, 10);
  const recentRows = stats?.recent?.length ? stats.recent : rows.slice(0, 8);
  const coverage = stats?.fieldCoverage || {};
  const windowFrom = stats?.window?.from ? new Date(stats.window.from) : null;
  const windowTo = stats?.window?.to ? new Date(stats.window.to) : null;

  const distribution = (items, colorFor) => {
    const maximum = Math.max(...items.map(item => Number(item.count || 0)), 1);
    return items.map(item => {
      const label = String(item._id || 'Unknown');
      const color = colorFor(label);
      return (
        <div key={label} style={{ display: 'grid', gridTemplateColumns: '130px 1fr 54px', gap: 8, alignItems: 'center', fontSize: 10 }}>
          <span style={{ color: MON.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 600 }}>{label}</span>
          <span style={{ height: 7, borderRadius: 8, background: '#07121e', overflow: 'hidden' }}><span style={{ display: 'block', width: `${Number(item.count || 0) > 0 ? Math.max(2, (Number(item.count || 0) / maximum) * 100) : 0}%`, height: '100%', background: color }} /></span>
          <b style={{ color, textAlign: 'right' }}>{shortNum(item.count)}</b>
        </div>
      );
    });
  };

  const summaryCards = [
    { title: 'Total Hash Events (24h)', value: shortNum(totalEvents), delta: `${shortNum(totals.endpoints || 0)} endpoints`, color: MON.blue, bg: 'linear-gradient(135deg,#0b3b78,#102846)' },
    { title: 'Known Malware IOC Hashes', value: shortNum(maliciousCount), delta: 'TI matches', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Unsigned Executables', value: shortNum(unsignedCount), delta: 'unsigned binaries', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Digital Signature Validation', value: `${validationPercent}%`, delta: `${shortNum(validSignatureCount)} valid / ${shortNum(evaluatedSignatureCount)} evaluated`, color: MON.green, bg: 'linear-gradient(135deg,#064e3b,#09231b)' },
    { title: 'Hash Baseline Mismatches', value: shortNum(mismatchCount), delta: 'system deviations', color: MON.cyan, bg: 'linear-gradient(135deg,#0e4f6d,#062334)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, background: '#06111f', border: `1px solid ${MON.border}`, borderRadius: 10, padding: 12 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '14px 18px', borderRadius: 9, background: 'linear-gradient(100deg,#092745,#061524)', border: `1px solid ${MON.cyan}50`, boxShadow: '0 4px 20px rgba(0,0,0,0.4)' }}>
        <div>
          <div style={{ color: '#f8fafc', fontSize: 16, fontWeight: 900, letterSpacing: 0.5 }}>🔑 Hash & Digital Signature Intelligence Operations Center</div>
          <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>
            {windowFrom && windowTo ? `${windowFrom.toLocaleString()} → ${windowTo.toLocaleString()}` : 'Real-Time SHA-256 Verification & Certificate Trust Engine'} · Capability ID 25
          </div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span style={{ color: MON.green, fontSize: 9, fontWeight: 900, padding: '6px 10px', border: `1px solid ${MON.green}66`, borderRadius: 14, background: 'rgba(52, 211, 153, 0.1)' }}>● LIVE INGESTION</span>
          <span style={{ color: MON.cyan, fontSize: 9, fontWeight: 900, padding: '6px 10px', border: `1px solid ${MON.cyan}66`, borderRadius: 14, background: 'rgba(34, 211, 238, 0.1)' }}>AUTO REFRESH 60s</span>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 10 }}>
        {summaryCards.map(card => (
          <div key={card.title} style={{ background: card.bg, border: `1px solid ${card.color}55`, borderRadius: 8, padding: 14, minHeight: 90, position: 'relative', overflow: 'hidden', boxShadow: '0 4px 12px rgba(0,0,0,0.3)' }}>
            <div style={{ fontSize: 9, color: '#dbeafe', fontWeight: 900, textTransform: 'uppercase' }}>{card.title}</div>
            <div style={{ marginTop: 8, fontSize: 24, color: '#fff', fontWeight: 900 }}>{card.value}</div>
            <div style={{ marginTop: 7, fontSize: 9, color: card.color, fontWeight: 800 }}>↗ {card.delta}</div>
            <div style={{ position: 'absolute', right: 8, bottom: 8, width: 70, opacity: 0.9 }}>
              <MiniSparkline data={timelineRows.map(point => point.count)} color={card.color} height={26} />
            </div>
          </div>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.2fr 1fr 1fr', gap: 10 }}>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Hash Reputation Breakdown</b>
          <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
            {distribution(reputationRows, label => /malicious/i.test(label) ? MON.red : /suspicious/i.test(label) ? MON.orange : /verified|trusted/i.test(label) ? MON.green : MON.muted)}
          </div>
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Digital Signature Verification Status</b>
          <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
            {distribution(signatureRows.slice(0, 7), label => /valid|verified/i.test(label) ? MON.green : /unknown/i.test(label) ? MON.muted : /unsigned/i.test(label) ? MON.orange : MON.red)}
          </div>
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Detection Category Distribution</b>
          <div style={{ display: 'grid', gap: 10, marginTop: 12 }}>
            {distribution(categoryRows, () => MON.purple)}
          </div>
        </div>
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Evidence Collection Ratios</b>
          <div style={{ display: 'grid', gap: 9, marginTop: 12, fontSize: 10 }}>
            {[
              ['SHA-256 Hash', coverage.sha256],
              ['Signature / Certificate', coverage.signature],
              ['Publisher Signer', coverage.publisher],
              ['Process Parent Link', coverage.process],
              ['System Baseline', coverage.baseline],
            ].map(([label, value]) => (
              <div key={label} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.muted }}>{label}</span>
                <b style={{ color: Number(value) ? MON.cyan : MON.muted }}>{shortNum(value || 0)} / {shortNum(totalEvents)}</b>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={panel}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
          <b style={{ fontSize: 12, color: '#fff' }}>📈 Real-Time Hash & Signature Telemetry Event Wave (24 Hours)</b>
          <span style={{ fontSize: 9, color: MON.cyan }}>Showing hourly telemetry pulse</span>
        </div>
        <div style={{ height: 110, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 10, borderBottom: `1px solid ${MON.line}` }}>
          {timelineRows.map((point, idx) => (
            <div key={`${point.label}-${idx}`} title={`${point.label}: ${point.count} events`} style={{ flex: 1, minWidth: 3, height: `${point.count > 0 ? Math.max(6, (point.count / maxTimeline) * 100) : 0}%`, background: `linear-gradient(180deg, ${MON.cyan}, #0f4c81)`, borderRadius: '3px 3px 0 0' }} />
          ))}
        </div>
      </div>

      <div style={{ ...panel, padding: 0, overflow: 'hidden' }}>
        <div style={{ overflowX: 'auto' }}><div style={{ minWidth: 820 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '145px 145px 1fr 1.25fr 110px 70px', gap: 8, padding: '8px 12px', color: MON.muted, fontSize: 9, fontWeight: 800 }}><span>Time</span><span>Endpoint</span><span>File</span><span>SHA-256</span><span>Signature</span><span>Risk</span></div>
          {recentRows.slice(0, 8).map(row => <div key={recordId(row)} style={{ display: 'grid', gridTemplateColumns: '145px 145px 1fr 1.25fr 110px 70px', gap: 8, padding: '9px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 9 }}><span>{alertTime(row) ? new Date(alertTime(row)).toLocaleString() : 'Not collected'}</span><span style={{ color: MON.cyan }}>{alertHost(row)}</span><span>{fileName(row)}</span><code style={{ color: MON.purple, overflow: 'hidden', textOverflow: 'ellipsis' }}>{fileHash(row) || 'Not collected'}</code><span>{signatureStatus(row)}</span><b style={{ color: hashRiskScore(row) >= 60 ? MON.red : MON.orange }}>{hashRiskScore(row)}</b></div>)}
          {!recentRows.length && <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 10 }}>No forensic evidence returned for this window.</div>}
        </div></div>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// 5. MAIN DASHBOARD COMPONENT (`HashSignatureDashboardPanel` / `HashSignatureDashboard`)
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignatureDashboardPanel({ alerts = [], loading = false, total = 0, recordsTotal = 0, systems = [], stats = null, onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [backendSystems, setBackendSystems] = useState(systems);

  const queueResponse = useCallback(async (actionType, event) => {
    const systemId = event?.systemId?._id || event?.systemId;
    if (!systemId) throw new Error('This event is not linked to an endpoint');
    const reason = window.prompt('Enter the SOC reason for this response action:');
    if (!reason?.trim()) throw new Error('A response reason is required');
    if (!window.confirm(`Submit ${actionType.replaceAll('_', ' ')} for ${fileName(event)}? High-risk actions require approval.`)) {
      throw new Error('Response cancelled');
    }
    const actionParams = {
      reason: reason.trim(),
      sha256: fileHash(event) || undefined,
      filePath: filePath(event) !== '—' ? filePath(event) : undefined,
      pid: event?.pid || undefined,
      publisher: publisher(event) !== '—' ? publisher(event) : undefined,
    };
    const response = await api.post('/auto-response/execute', {
      systemId, actionType, actionParams, alertId: event?._id,
      threatName: fileName(event), severity: alertSeverity(event),
    });
    return response.data;
  }, []);

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
  const totals = stats?.totals || {};
  const sevCounts = rows.reduce((acc, row) => {
    const sev = alertSeverity(row);
    acc[sev] = (acc[sev] || 0) + 1;
    return acc;
  }, {});

  const timeline = stats?.timeline?.length ? stats.timeline.map(point => Number(point.count || 0)) : buildBuckets(rows, 8, 24);
  const countWhere = predicate => rows.filter(predicate).length;
  const signedEvaluated = countWhere(row => signatureStatus(row) !== 'UNKNOWN');
  const validSigned = countWhere(row => signatureStatus(row) === 'VALID');
  const integrityScore = Number(totals.signatureValidationPercent ?? (signedEvaluated ? Math.round((validSigned / signedEvaluated) * 100) : 0));
  const metric = (key, fallback) => Number(totals[key] ?? fallback ?? 0);

  // 20 Hash & Signature Specific SOC Categories & Metrics
  const kpis = [
    { label: '🔑 1. Total Files & Executables Scanned', val: shortNum(metric('total', totalRows)), trend: 'Files Scanned', color: MON.blue, data: timeline },
    { label: '🦠 2. Known Malware SHA-256 IOC Hashes', val: shortNum(metric('malicious', countWhere(row => row.threatIntelMatch || /malicious/i.test(row.reputation || row.vtVerdict || '')))), trend: 'Malware IOCs', color: MON.red, data: timeline },
    { label: '🔐 3. Unsigned Executables Detected', val: shortNum(metric('unsigned', countWhere(row => signatureStatus(row) === 'UNSIGNED'))), trend: 'Unsigned EXEs', color: MON.orange, data: timeline },
    { label: '🚫 4. Invalid & Expired Certificate Violations', val: shortNum(metric('invalidCertificates', countWhere(row => ['INVALID', 'EXPIRED', 'REVOKED', 'CERTIFICATE_CHAIN_FAILURE'].includes(signatureStatus(row))))), trend: 'Invalid Certs', color: MON.red, data: timeline },
    { label: '🎭 5. Impersonated & Fake Vendor Signatures', val: shortNum(metric('untrustedPublishers', countWhere(row => signatureStatus(row) === 'UNTRUSTED_PUBLISHER'))), trend: 'Fake Certs', color: MON.red, data: timeline },
    { label: '⚙️ 6. Process Memory Tampering & Module Hashes', val: shortNum(metric('moduleMemory', countWhere(row => /module|memory|dll/i.test(`${hashRule(row)} ${fileName(row)}`)))), trend: 'Memory Tamper', color: MON.purple, data: timeline },
    { label: '🖥️ 7. System Binary Hash Baseline Shift', val: shortNum(metric('mismatches', countWhere(row => row.hashMismatch))), trend: 'System Shift', color: MON.red, data: timeline },
    { label: '📜 8. PowerShell & Script Execution Hashes', val: shortNum(metric('scripts', countWhere(row => /\.(ps1|bat|cmd|vbs|js|sh|py)$/i.test(fileName(row))))), trend: 'Script Hashes', color: MON.purple, data: timeline },
    { label: '🌐 9. VirusTotal Threat Feed IOC Matches', val: shortNum(metric('threatFeedMatches', countWhere(row => row.vtVerdict || row.threatIntelSource))), trend: 'VT Detections', color: MON.red, data: timeline },
    { label: '🔒 10. Auto-Quarantined Malicious Binaries', val: shortNum(metric('quarantined', countWhere(row => row.quarantined || row.containmentStatus === 'quarantined'))), trend: 'Quarantined', color: MON.green, data: timeline },
    { label: '💻 11. Windows PE Binaries Verified', val: shortNum(metric('windowsVerified', countWhere(row => processOs(row) === 'Windows PE' && signatureStatus(row) === 'VALID'))), trend: 'Windows PE', color: MON.cyan, data: timeline },
    { label: '🐧 12. Linux ELF Binaries Verified', val: shortNum(metric('linuxVerified', countWhere(row => processOs(row) === 'Linux ELF' && row.packageVerificationStatus === 'VERIFIED'))), trend: 'Linux ELF', color: MON.purple, data: timeline },
    { label: '🚨 13. Critical Hash Security Alerts', val: shortNum(metric('critical', sevCounts.critical)), trend: 'Critical Risk', color: MON.red, data: timeline },
    { label: '⚠️ 14. High Severity Signature Anomalies', val: shortNum(metric('high', sevCounts.high)), trend: 'High Risk', color: MON.orange, data: timeline },
    { label: '🖥️ 15. Endpoints Syncing Hash Engine', val: shortNum(metric('endpoints', backendSystems.length)), trend: 'Endpoints', color: MON.cyan, data: timeline },
    { label: '💖 16. System Hash Integrity Score', val: `${integrityScore}/100`, trend: 'Integrity Score', color: MON.green, data: timeline },
    { label: '🔗 17. Memory-Loaded Unsigned DLLs', val: shortNum(metric('unsignedDlls', countWhere(row => /\.dll$/i.test(fileName(row)) && signatureStatus(row) === 'UNSIGNED'))), trend: 'Unsigned DLL', color: MON.yellow, data: timeline },
    { label: '📑 18. Duplicate Malicious File Hashes', val: shortNum(metric('duplicateMalicious', Array.from(rows.reduce((map, row) => { const value = fileHash(row); if (value && row.threatIntelMatch) map.set(value, (map.get(value) || 0) + 1); return map; }, new Map()).values()).filter(count => count > 1).length)), trend: 'Duplicate IOC', color: MON.orange, data: timeline },
    { label: '⚙️ 19. Web Server Binary & Config Hashes', val: shortNum(metric('webIntegrity', countWhere(row => /(?:var[\\/]www|wwwroot|htdocs)/i.test(filePath(row))))), trend: 'Web Integrity', color: MON.cyan, data: timeline },
    { label: '✅ 20. Trusted Corporate Certificate Allowlist', val: shortNum(metric('trustedCertificates', countWhere(row => signatureStatus(row) === 'VALID' && publisher(row) !== '—'))), trend: 'Trusted Certs', color: MON.green, data: timeline },
  ];

  const agentStatusRows = backendSystems.map(sys => {
    const host = sys.hostname || sys.name || 'unknown';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || 'unknown',
      hostname: host,
      status: sys.status || (sys.online ? 'reporting' : 'active'),
      monitor: true,
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
          <HashSignatureLogMonitor alerts={alerts} onResponse={queueResponse} />
        ) : activeTab === 'reports' ? (
          <HashSignatureReportsTab alerts={alerts} />
        ) : activeTab === 'dashboard' ? (
          <HashSignatureOverviewDashboard alerts={alerts} total={totalRows} stats={stats} onResponse={queueResponse} />
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
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'end', marginTop: 10 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: kpi.color }}>{kpi.val}</div>
                    <div style={{ width: 70 }}><MiniSparkline data={kpi.data} color={kpi.color} height={24} /></div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Hash & Signature Verification Engine</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} endpoints reporting · VirusTotal & IOC Engine Active</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>Hash Engine</span><span>Scanned Files</span><span>Hash Anomalies</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: MON.green, textTransform: 'uppercase' }}>Active</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleString() : '—'}</span>
                </div>
              ))}
              {!agentStatusRows.length && (
                <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>
                  No backend agents returned.
                </div>
              )}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Hash & Signature Event Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} hash anomalies`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.cyan, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🔑 Top Flagged Hashes</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {topCounts(rows, fileName, 5).map(([fName, cnt]) => (
                    <div key={fName} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{fName}</span>
                      <span style={{ color: MON.red, fontWeight: 800 }}>{cnt} Matches</span>
                    </div>
                  ))}
                  {!topCounts(rows, fileName, 5).length && <span style={{ color: MON.muted }}>No flagged files.</span>}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Collected Security Evidence</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['SHA-256', rows.some(row => fileHash(row)) ? 'Reporting' : 'No data', rows.some(row => fileHash(row)) ? MON.green : MON.muted],
                    ['Digital Signature', rows.some(row => signatureStatus(row) !== 'UNKNOWN') ? 'Reporting' : 'No data', rows.some(row => signatureStatus(row) !== 'UNKNOWN') ? MON.green : MON.muted],
                    ['Threat Intelligence', rows.some(row => row.threatIntelMatch || row.vtVerdict) ? 'Correlated' : 'No match', MON.cyan],
                    ['Baseline Comparison', rows.some(row => row.baselineHash || row.hashMismatch) ? 'Reporting' : 'No data', rows.some(row => row.baselineHash || row.hashMismatch) ? MON.green : MON.muted],
                  ].map(([lbl, stat, col]) => (
                    <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.muted }}>{lbl}</span>
                      <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
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
// 6. OVERLAY CAPABILITY MODAL EXPORT (`HashSignaturePage` & `CapabilityPage`)
// ═════════════════════════════════════════════════════════════════════════════
export default function HashSignaturePage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const capabilityId = searchParams.get('capabilityId') || '25';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const [stats, setStats] = useState(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const to = new Date();
      const params = { page: 1, limit: 250, from: new Date(to.getTime() - 86400000).toISOString(), to: to.toISOString() };
      const [eventsResult, statisticsResult] = await Promise.allSettled([
        api.get('/hash-signature/events', { params, skipCache: quiet }),
        api.get('/hash-signature/statistics', { params: { from: params.from, to: params.to }, skipCache: quiet }),
      ]);
      if (eventsResult.status === 'fulfilled') {
        const next = eventsResult.value.data?.events || [];
        setAlerts(next);
        setTotal(eventsResult.value.data?.total || next.length);
      }
      if (statisticsResult.status === 'fulfilled') setStats(statisticsResult.value.data || null);
      if (eventsResult.status === 'rejected' && statisticsResult.status === 'rejected') {
        setAlerts([]);
        setStats(null);
      }
    } catch {
      setAlerts([]);
      setStats(null);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

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
    const interval = setInterval(() => loadAlerts(true), 60000);
    return () => clearInterval(interval);
  }, [loadAlerts, loadSystems]);

  useEffect(() => {
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const buf = createEventBuffer(() => loadAlerts(true), 1200);
    socket.on('connect', join);
    socket.on('alert:new', buf.add);
    socket.on('hash:alert', buf.add);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('alert:new', buf.add);
      socket.off('hash:alert', buf.add);
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
            🔑 25. Hash & Signature Analysis (Threat Intelligence)
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>
              — {Number(total || 0).toLocaleString()} logs
            </span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <HashSignatureDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} stats={stats} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <HashSignaturePage />;
}

export function HashSignatureSocTabPage({ tab }) {
  return <HashSignatureDashboardPanel alerts={[]} />;
}

// ═════════════════════════════════════════════════════════════════════════════
// 7. SUB-TAB PAGE ROUTE & EXPORTS FOR ROUTING
// ═════════════════════════════════════════════════════════════════════════════
export function HashSignatureSubTabPage() {
  const navigate = useNavigate();
  const { tab = 'overview' } = useParams();

  if (tab === 'overview') return <Navigate to="/company-admin/edr?capabilityId=25" replace />;

  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: MON.bg, display: 'grid', gridTemplateRows: '54px 1fr', color: '#e5edf7' }}>
      <header style={{ borderBottom: `1px solid ${MON.line}`, background: MON.card, display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '0 28px' }}>
        <h3 style={{ margin: 0, fontSize: 14, color: MON.blue }}>Hash & Signature Analysis SubTab — {tab}</h3>
        <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=25')} style={{ border: 0, background: 'transparent', color: '#60a5fa', fontSize: 26, cursor: 'pointer' }}>×</button>
      </header>
      <div style={{ display: 'grid', gridTemplateColumns: '196px minmax(0, 1fr)', overflow: 'hidden' }}>
        <ProcessSidebar kind="hashsignature" activeKey={tab} />
        <main style={{ overflow: 'auto', background: MON.bg, padding: 16 }}>
          <HashSignatureDashboardPanel />
        </main>
      </div>
    </div>
  );
}

// ── Alias exports for backward compatibility & index.js ──
export { HashSignatureDashboardPanel as HashSignatureDashboard };
export { HashSignatureSubTabPage as HashSignatureAnalysisSubTabPage };
