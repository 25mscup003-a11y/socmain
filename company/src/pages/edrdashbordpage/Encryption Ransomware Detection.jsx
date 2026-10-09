import CapabilityLogsPanel from './CapabilityLogsPanel';
/**
 * Encryption & Ransomware Detection — Capability ID: 27 (Backend ID: 27)
 *
 * 100% Self-Contained Enterprise SOC Ransomware & Rapid File Encryption Detection Module
 * Full Coverage across Ransomware Specifications: Mass File Encryption, High Entropy Detection, Extension Anomalies, Ransom Note Detection, Shadow Copy & Backup Tampering, Disk/CPU/Memory Spikes, Process Persistence, MITRE ATT&CK (TA0001, TA0002, TA0003, TA0005, TA0040 / T1486, T1490), Automated Containment Controls.
 * Designed mirroring Capability 26 (Beaconing Detection) & Capability 25 (Hash/Signature Analysis) Architecture & Master 10-Tab Forensic Panel Modal.
 */
import React, { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useNavigate, useSearchParams, useParams, Navigate, Link } from 'react-router-dom';
import api from '../../api/axios';
import { SOCKET_URL, connectSocket, socketOptions, io } from '../../api/config';
import { useAuth } from '../../context/AuthContext';
import CapabilityReportsPanel from './CapabilityReportsPanel';

const CapabilityDataPage = () => null; const CapabilityAgentsPage = () => null;
const ProcessSidebar = () => null; const processSubTabPages = {}; const CapabilitySubTabPage = () => null;

// ── Design System Tokens (Mirroring Capability 25 & 26) ─────────────────────
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

function MiniSparkline({ data = [12, 18, 14, 22, 19, 28, 24, 32], color = MON.cyan, height = 30 }) {
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

function rawRansomware(row = {}) {
  const direct = row.rawEvent && typeof row.rawEvent === 'object' ? row.rawEvent : {};
  const nested = direct.raw && typeof direct.raw === 'object' ? direct.raw : {};
  return { ...direct, ...nested };
}

function firstRansomwareValue(...values) {
  return values.find(value => value !== undefined && value !== null && value !== '');
}

function ransomwareFileMetrics(row = {}, raw = rawRansomware(row)) {
  const text = `${row.full_log || ''} ${raw.raw_log || ''} ${row.description || ''}`;
  const modified = Number(text.match(/modified=(\d+)/i)?.[1] || 0);
  const renamed = Number(text.match(/renamed=(\d+)/i)?.[1] || 0);
  const deleted = Number(text.match(/deleted=(\d+)/i)?.[1] || 0);
  const count = Number(text.match(/(?:count|files?)=(\d+)/i)?.[1] || 0);
  const windowSeconds = Number(text.match(/window=(\d+)s/i)?.[1] || 0);
  const affectedFiles = modified + renamed || deleted || count || undefined;
  const entropy = Number(text.match(/(?:avg_entropy|entropy)=([0-9.]+)/i)?.[1]);
  const commandLine = text.match(/(?:^|\|)cmd=(.+)$/i)?.[1]?.trim();
  const processName = text.match(/(?:^|\|)proc=([^|]+)/i)?.[1]?.trim();
  const pid = Number(text.match(/(?:^|\|)pid=(\d+)/i)?.[1]);
  const filePath = text.match(/(?:^|\|)path=([^|]+)/i)?.[1]?.trim();
  const canary = text.match(/(?:^|\|)(?:canary|honeytoken)=([^|]+)/i)?.[1]?.trim();
  return {
    affectedFiles,
    entropy: Number.isFinite(entropy) ? entropy : undefined,
    encryptionSpeed: affectedFiles && windowSeconds ? affectedFiles / windowSeconds : undefined,
    modifiedFilesPerSecond: modified && windowSeconds ? modified / windowSeconds : undefined,
    renamedFilesPerSecond: renamed && windowSeconds ? renamed / windowSeconds : undefined,
    deletedFilesPerSecond: deleted && windowSeconds ? deleted / windowSeconds : undefined,
    commandLine,
    processName,
    pid: Number.isFinite(pid) ? pid : undefined,
    filePath,
    canary,
  };
}

function normalizeRansomwareAlert(row = {}) {
  const raw = rawRansomware(row);
  const parsed = ransomwareFileMetrics(row, raw);
  return {
    ...row,
    processName: firstRansomwareValue(row.processName, row.process, raw.processName, raw.process_name, parsed.processName),
    pid: firstRansomwareValue(row.pid, row.processId, raw.pid, raw.processId, raw.process_id, parsed.pid),
    processCmdline: firstRansomwareValue(row.processCmdline, row.commandLine, raw.processCmdline, raw.process_cmdline, raw.commandLine, raw.command_line, raw.cmdline, parsed.commandLine),
    commandLine: firstRansomwareValue(row.commandLine, row.processCmdline, raw.commandLine, raw.command_line, raw.process_cmdline, raw.cmdline, parsed.commandLine),
    parentProcessName: firstRansomwareValue(row.parentProcessName, row.parentProcess, raw.parentProcessName, raw.parent_process_name),
    parentPid: firstRansomwareValue(row.parentPid, raw.parentPid, raw.parent_pid),
    username: firstRansomwareValue(row.username, raw.username, raw.user),
    malwareType: firstRansomwareValue(row.malwareType, raw.malwareType, raw.malware_type),
    threatFamily: firstRansomwareValue(row.threatFamily, row.malwareFamily, row.family, row.variant, raw.threatFamily, raw.threat_family, raw.malwareFamily, raw.malware_family, raw.family, raw.variant),
    canary: firstRansomwareValue(row.canary, row.honeytoken, row.canaryStatus, raw.canary, raw.honeytoken, raw.canary_status, parsed.canary),
    filePath: firstRansomwareValue(row.filePath, row.path, raw.filePath, raw.file_path, parsed.filePath),
    affectedFiles: firstRansomwareValue(row.affectedFiles, raw.affectedFiles, raw.affected_files, parsed.affectedFiles),
    affectedDirectory: firstRansomwareValue(row.affectedDirectory, raw.affectedDirectory, raw.affected_directory),
    encryptionSpeed: firstRansomwareValue(row.encryptionSpeed, row.fileRate, raw.encryptionSpeed, raw.encryption_speed, parsed.encryptionSpeed),
    entropy: firstRansomwareValue(row.entropy, raw.entropy, parsed.entropy),
    extension: firstRansomwareValue(row.extension, raw.extension),
    riskScore: firstRansomwareValue(row.riskScore, raw.riskScore, raw.risk_score),
    mitreId: firstRansomwareValue(row.mitreId, raw.mitreId, raw.mitre_id),
    mitreTechnique: firstRansomwareValue(row.mitreTechnique, row.technique, raw.mitreTechnique, raw.mitre_technique, raw.technique),
    recommendedAction: firstRansomwareValue(row.recommendedAction, raw.recommendedAction, raw.recommended_action),
    processCpuPercent: firstRansomwareValue(row.processCpuPercent, raw.processCpuPercent, raw.cpu_percent),
    processMemoryPercent: firstRansomwareValue(row.processMemoryPercent, raw.processMemoryPercent, raw.memory_percent),
    processDiskWriteBytesPerSecond: firstRansomwareValue(row.processDiskWriteBytesPerSecond, raw.processDiskWriteBytesPerSecond, raw.disk_write_bytes_per_second),
    processExecutableSha256: firstRansomwareValue(row.processExecutableSha256, row.fileHash, raw.processExecutableSha256, raw.executable_sha256, raw.file_hash),
    processExecutableMd5: firstRansomwareValue(row.processExecutableMd5, row.fileHashMd5, raw.processExecutableMd5, raw.executable_md5, raw.file_hash_md5),
    processSignatureStatus: firstRansomwareValue(row.processSignatureStatus, row.signatureStatus, raw.processSignatureStatus, raw.signature_status),
    processPublisher: firstRansomwareValue(row.processPublisher, row.publisher, raw.processPublisher, raw.publisher),
    deletedFilesPerSecond: firstRansomwareValue(row.deletedFilesPerSecond, raw.deletedFilesPerSecond, raw.deleted_files_per_second, parsed.deletedFilesPerSecond),
    modifiedFilesPerSecond: firstRansomwareValue(row.modifiedFilesPerSecond, raw.modifiedFilesPerSecond, raw.modified_files_per_second, parsed.modifiedFilesPerSecond),
    renamedFilesPerSecond: firstRansomwareValue(row.renamedFilesPerSecond, raw.renamedFilesPerSecond, raw.renamed_files_per_second, parsed.renamedFilesPerSecond),
  };
}

function alertTime(r) {
  return r?.timestamp || r?.createdAt || r?.time || r?.observedAt || r?.updatedAt || new Date().toISOString();
}

function alertHost(r) {
  return r?.hostname || r?.host || r?.agentName || r?.systemId?.hostname || r?.systemId?.name || '—';
}

function alertSeverity(r) {
  const s = String(r?.severity || 'info').toLowerCase();
  return ['critical', 'high', 'medium', 'low', 'info'].includes(s) ? s : 'info';
}

function ransomwareProcess(r) {
  const raw = rawRansomware(r);
  return r?.processName || r?.process || r?.command || raw.processName || raw.process_name || '—';
}

function ransomwareFamily(r) {
  const normalized = normalizeRansomwareAlert(r);
  return normalized.threatFamily || normalized.malwareType || 'Unknown';
}

function ransomwareRate(r) {
  const normalized = normalizeRansomwareAlert(r);
  const rate = Number(normalized.encryptionSpeed);
  if (Number.isFinite(rate)) return `${rate.toFixed(rate < 10 ? 1 : 0)} files/sec`;
  return r?.rate || '—';
}

function ransomwareCanary(r) {
  return normalizeRansomwareAlert(r).canary || 'No telemetry';
}

function ransomwareFileLocation(r) {
  const normalized = normalizeRansomwareAlert(r);
  return normalized.filePath || normalized.affectedDirectory || '—';
}

function ransomwareProcessDisplay(r) {
  const value = ransomwareProcess(r);
  return value === '—' ? 'Not captured' : value;
}

function ransomwarePidDisplay(r) {
  return normalizeRansomwareAlert(r).pid ?? 'Not captured';
}

function ransomwareCommandDisplay(r) {
  return normalizeRansomwareAlert(r).commandLine || 'Not captured for filesystem-only event';
}

function ransomwareCategory(r) {
  return r?.category || r?.ruleName || r?.detectionType || '—';
}

function ransomwareText(row) {
  const normalized = normalizeRansomwareAlert(row);
  return `${normalized.detectionType || ''} ${normalized.category || ''} ${normalized.ruleId || ''} ${normalized.ruleName || ''} ${normalized.title || ''} ${normalized.description || ''} ${normalized.status || ''} ${normalized.commandLine || ''} ${normalized.mitreId || ''} ${normalized.mitreTechnique || ''} ${normalized.recommendedAction || ''}`.toLowerCase();
}

function countMatching(rows, pattern) {
  return rows.filter(row => pattern.test(ransomwareText(row))).length;
}

function responseSummary(rows) {
  let attempted = 0;
  let successful = 0;
  rows.forEach(row => {
    const history = Array.isArray(row?.responseHistory) ? row.responseHistory : [];
    history.forEach(action => {
      const name = `${action?.action || ''} ${action?.actionType || ''}`;
      if (!/kill|isolat|contain|quarant|block/i.test(name)) return;
      attempted += 1;
      if (/success|completed|executed|resolved/i.test(String(action?.status || ''))) successful += 1;
    });
  });
  return { attempted, successful, rate: attempted ? `${Math.round((successful / attempted) * 100)}%` : 'Not configured' };
}

function extensionValue(row) {
  const normalized = normalizeRansomwareAlert(row);
  if (normalized.extension) return String(normalized.extension).toLowerCase();
  const path = String(normalized.filePath || '');
  const match = path.match(/(\.[a-z0-9]{1,12})$/i);
  return match?.[1]?.toLowerCase() || '—';
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

function EvidenceGrid({ rows = [] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 10 }}>
      {rows.map(([label, val]) => (
        <div key={label} style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: 10 }}>
          <div style={{ fontSize: 9, fontWeight: 700, color: MON.muted, textTransform: 'uppercase' }}>{label}</div>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#fff', marginTop: 3, fontFamily: 'monospace', wordBreak: 'break-all' }}>{String(val ?? '—')}</div>
        </div>
      ))}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MASTER 10-TAB RANSOMWARE FORENSIC PANEL MODAL (Capability 25 & 26 Architecture)
// ═════════════════════════════════════════════════════════════════════════════
export function RansomwareForensicDetailModal({ log, onClose, onAction }) {
  const [activeTab, setActiveTab] = useState('overview');
  const [actionSuccess, setActionSuccess] = useState(null);

  if (!log) return null;

  const evidence = normalizeRansomwareAlert(log);

  const sev = alertSeverity(log);
  const sevColor = SEV_COLOR[sev] || MON.red;

  const masterTabs = [
    { id: 'overview', label: '📊 1. Overview' },
    { id: 'file', label: '📁 2. File & Extension' },
    { id: 'ransomnote', label: '📄 3. Ransom Note' },
    { id: 'vss', label: '🛡️ 4. Shadow Copy & Backup' },
    { id: 'entropy', label: '⚡ 5. High Entropy & Disk IO' },
    { id: 'process', label: '⚙️ 6. Process & Memory' },
    { id: 'mitre', label: '🗺️ 7. MITRE ATT&CK' },
    { id: 'policy', label: '🛡️ 8. Defense Policy' },
    { id: 'timeline', label: '⏱️ 9. Incident Lifecycle' },
    { id: 'actions', label: '📄 10. Reports & Response' },
  ];

  const handleAction = async (actionType, actionName) => {
    const supportedAction = { isolate_host: 'isolate', kill_process: 'kill_process', block_hash: 'quarantine' }[actionType];
    try {
      if (!supportedAction || typeof onAction !== 'function' || !log?._id) {
        setActionSuccess(`Not sent: ${actionName} has no configured response executor for this alert.`);
        return;
      }
      const res = await onAction(String(log._id), supportedAction);
      setActionSuccess(res?.message || `Approved action submitted: ${actionName}`);
    } catch (err) {
      setActionSuccess(err?.message || `Failed to submit: ${actionName}`);
    }
    setTimeout(() => setActionSuccess(null), 5000);
  };

  return (
    <div style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(3, 8, 16, 0.88)', backdropFilter: 'blur(8px)', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 16 }}>
      <div style={{ width: '98vw', height: '94vh', background: MON.bg, border: `1px solid ${MON.border}`, borderRadius: 12, display: 'flex', flexDirection: 'column', boxShadow: '0 25px 50px -12px rgba(0, 0, 0, 0.75)', overflow: 'hidden' }}>
        {/* Modal Header */}
        <div style={{ padding: '14px 20px', background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
            <span style={{ fontSize: 24 }}>🔐</span>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <h3 style={{ margin: 0, fontSize: 18, fontWeight: 800, color: '#f8fafc' }}>
                  Encryption & Ransomware Forensic Panel — {alertHost(log)} ({ransomwareProcess(log)})
                </h3>
                <span style={{ fontSize: 10, fontWeight: 800, padding: '2px 8px', borderRadius: 4, color: sevColor, background: `${sevColor}22`, border: `1px solid ${sevColor}44`, textTransform: 'uppercase' }}>
                  {sev} Severity
                </span>
                <span style={{ fontSize: 11, fontWeight: 700, padding: '2px 8px', borderRadius: 4, color: MON.purple, background: 'rgba(167, 139, 250, 0.15)', border: `1px solid ${MON.purple}44` }}>
                  RISK SCORE: {Number.isFinite(Number(evidence.riskScore)) ? `${Math.max(0, Math.min(100, Number(evidence.riskScore)))}/100` : '—'}
                </span>
              </div>
              <div style={{ fontSize: 11, color: MON.muted, marginTop: 4 }}>
                Variant: <strong style={{ color: MON.purple, fontFamily: 'monospace' }}>{ransomwareFamily(log)}</strong> | Encryption Rate: <strong style={{ color: MON.red }}>{ransomwareRate(log)}</strong> | Canary Status: <strong style={{ color: MON.yellow }}>{ransomwareCanary(log)}</strong>
              </div>
            </div>
          </div>
          <button type="button" onClick={onClose} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: MON.muted, fontSize: 18, borderRadius: 6, width: 34, height: 34, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>✕</button>
        </div>

        {/* 10 Master Tabs Header */}
        <div style={{ background: MON.card, borderBottom: `1px solid ${MON.border}`, display: 'flex', gap: 2, overflowX: 'auto', padding: '0 12px' }}>
          {masterTabs.map(t => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveTab(t.id)}
              style={{
                padding: '10px 14px', fontSize: 11, fontWeight: activeTab === t.id ? 800 : 600,
                color: activeTab === t.id ? MON.cyan : MON.muted,
                background: activeTab === t.id ? MON.bg : 'transparent',
                border: 'none', borderBottom: activeTab === t.id ? `2px solid ${MON.cyan}` : '2px solid transparent',
                cursor: 'pointer', whiteSpace: 'nowrap',
              }}
            >
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
                  ['Endpoint Host', alertHost(log), MON.cyan],
                  ['Process Name', ransomwareProcess(log), MON.text],
                  ['Ransomware Family', ransomwareFamily(log), MON.purple],
                  ['Encryption Rate', ransomwareRate(log), MON.red],
                ].map(([lbl, val, col]) => (
                  <div key={lbl} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                    <div style={{ fontSize: 10, fontWeight: 700, color: MON.muted, textTransform: 'uppercase', letterSpacing: 1 }}>{lbl}</div>
                    <div style={{ fontSize: 16, fontWeight: 800, color: col, marginTop: 6 }}>{val}</div>
                  </div>
                ))}
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 12, color: MON.cyan, textTransform: 'uppercase' }}>🔐 Mass Encryption Threat Summary & Forensic Analysis</h4>
                <div style={{ fontSize: 11, color: MON.text, lineHeight: 1.6 }}>
                  Endpoint agent on <strong>{alertHost(log)}</strong> detected high-velocity file modification and entropy spike caused by process <code style={{ color: MON.yellow, background: '#000', padding: '2px 6px', borderRadius: 4 }}>{ransomwareProcess(log)}</code>. Variant identified: <code style={{ color: MON.purple, background: '#000', padding: '2px 6px', borderRadius: 4 }}>{ransomwareFamily(log)}</code> at velocity <strong>{ransomwareRate(log)}</strong>. Canary Honeytoken Status: <strong>{ransomwareCanary(log)}</strong>.
                </div>
              </div>

              <EvidenceGrid rows={[
                ['Endpoint Hostname', alertHost(log)], ['Ransomware Process', ransomwareProcess(log)],
                ['Threat Family / Variant', ransomwareFamily(log)], ['Encryption Velocity Rate', ransomwareRate(log)],
                ['Canary Honeytoken Status', ransomwareCanary(log)], ['VSS Backup Status', log.vss || log.shadowCopyStatus || 'No telemetry'],
                ['Entropy Score', evidence.entropy ?? '—'], ['SOC Protection Category', ransomwareCategory(log)],
              ]} />
            </div>
          )}

          {/* TAB 2: FILE & EXTENSION */}
          {activeTab === 'file' && (
            <EvidenceGrid rows={[
              ['Detected Extension', extensionValue(evidence)], ['Custom Rule Match', evidence.ruleName || evidence.ruleId || '—'],
              ['Affected Files', evidence.affectedFiles ?? '—'], ['Affected Directory', evidence.affectedDirectory || evidence.directory || '—'],
              ['File Entropy', evidence.entropy ?? '—'], ['File Path', evidence.filePath || '—'],
            ]} />
          )}

          {/* TAB 3: RANSOM NOTE & WALLPAPER */}
          {activeTab === 'ransomnote' && (
            <EvidenceGrid rows={[
              ['Detected Ransom Note File', log.ransomNoteFile || (/ransom note/i.test(ransomwareText(log)) ? log.filePath || log.path || 'Detected' : '—')],
              ['Desktop Wallpaper Replacement', log.wallpaperChanged === true ? 'Detected' : log.wallpaperChanged === false ? 'Not detected' : 'No telemetry'],
              ['HTML Decryption Page', log.ransomPage || '—'],
              ['Detection Evidence', log.detectionReason || log.description || '—'],
            ]} />
          )}

          {/* TAB 4: SHADOW COPY & BACKUP */}
          {activeTab === 'vss' && (
            <EvidenceGrid rows={[
              ['Observed Command', evidence.commandLine || '—'],
              ['Shadow Copy Status', log.shadowCopyStatus || log.vss || '—'],
              ['Recovery Status', log.recoveryStatus || '—'],
              ['Backup Service Status', log.backupStatus || '—'],
            ]} />
          )}

          {/* TAB 5: HIGH ENTROPY & DISK IO */}
          {activeTab === 'entropy' && (
            <EvidenceGrid rows={[
              ['File Entropy Score', evidence.entropy ?? '—'], ['Disk Write Bytes/sec', evidence.processDiskWriteBytesPerSecond ?? '—'],
              ['Encryption Speed', ransomwareRate(evidence)], ['Deleted Files/sec', evidence.deletedFilesPerSecond ?? '—'],
              ['CPU Usage', evidence.processCpuPercent != null ? `${evidence.processCpuPercent}%` : '—'], ['Memory Usage', evidence.processMemoryPercent != null ? `${evidence.processMemoryPercent}%` : '—'],
            ]} />
          )}

          {/* TAB 6: PROCESS & MEMORY */}
          {activeTab === 'process' && (
            <EvidenceGrid rows={[
              ['Ransomware Process Name', ransomwareProcess(log)], ['PID', log.pid || '—'],
              ['Execution Command Line', evidence.commandLine || '—'],
              ['Parent Process', evidence.parentProcessName || '—'], ['Memory Evidence', evidence.memoryEvidence || '—'],
              ['Executable Signature', evidence.processSignatureStatus || evidence.processPublisher || '—'],
              ['SHA256 / MD5', evidence.processExecutableSha256 || evidence.processExecutableMd5 || '—'],
            ]} />
          )}

          {/* TAB 7: MITRE ATT&CK MAPPING */}
          {activeTab === 'mitre' && (
            <EvidenceGrid rows={[
              ['MITRE ATT&CK Evidence', Array.isArray(log.mitreTechniques) ? log.mitreTechniques.map(item => typeof item === 'string' ? item : `${item.id || item.techniqueId || ''} ${item.name || item.techniqueName || ''}`.trim()).join(', ') || '—' : log.mitreTechnique || '—'],
              ['Detection Evidence', log.detectionReason || log.description || '—'],
              ['Confidence', log.confidence ?? '—'], ['Risk Score', log.riskScore ?? log.score ?? '—'],
            ]} />
          )}

          {/* TAB 8: DEFENSE POLICY */}
          {activeTab === 'policy' && (
            <EvidenceGrid rows={[
              ['Evaluated Ransomware Rule', log.policyName || log.ruleName || '—'],
              ['Risk Score', log.riskScore ?? log.score ?? '—'],
              ['Recommended Action', log.recommendedAction || '—'],
              ['Recorded Responses', Array.isArray(log.responseHistory) ? log.responseHistory.length : 0],
            ]} />
          )}

          {/* TAB 9: INCIDENT LIFECYCLE */}
          {activeTab === 'timeline' && (
            <EvidenceGrid rows={[
              ['First Seen', log.firstSeen ? new Date(log.firstSeen).toLocaleString() : '—'],
              ['Detection Time', new Date(alertTime(log)).toLocaleString()],
              ['Last Seen', log.lastSeen ? new Date(log.lastSeen).toLocaleString() : '—'],
              ['Current Status', log.status || '—'],
            ]} />
          )}

          {/* TAB 10: REPORTS & SOC RESPONSE */}
          {activeTab === 'actions' && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {actionSuccess && <div style={{ padding: 10, background: `${MON.cyan}18`, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, fontSize: 11 }}>{actionSuccess}</div>}
              <div style={{ background: MON.card, border: `1px solid ${MON.red}55`, borderRadius: 8, padding: 16 }}>
                <h4 style={{ margin: '0 0 12px 0', fontSize: 13, color: MON.red }}>⚡ Ransomware Immediate Containment & Remediation Controls</h4>
                <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  <button type="button" onClick={() => handleAction('isolate_host', `Isolate Host ${alertHost(log)}`)} style={{ padding: '8px 14px', background: `${MON.red}25`, border: `1px solid ${MON.red}`, color: MON.red, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛑 Isolate Endpoint Host
                  </button>
                  <button type="button" onClick={() => handleAction('kill_process', `Kill Process ${ransomwareProcess(log)}`)} style={{ padding: '8px 14px', background: `${MON.orange}25`, border: `1px solid ${MON.orange}`, color: MON.orange, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🔒 Kill Process & Terminate Execution
                  </button>
                  <button type="button" onClick={() => handleAction('rollback_vss', `Rollback Shadow Copy & Restore Backup`)} style={{ padding: '8px 14px', background: `${MON.cyan}25`, border: `1px solid ${MON.cyan}`, color: MON.cyan, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    🛡️ Rollback VSS / Restore Backup
                  </button>
                  <button type="button" onClick={() => handleAction('block_hash', 'Blacklist Ransomware File Hash')} style={{ padding: '8px 14px', background: `${MON.green}25`, border: `1px solid ${MON.green}`, color: MON.green, borderRadius: 6, fontSize: 11, fontWeight: 900, cursor: 'pointer' }}>
                    ✅ Blacklist File Hash IOC
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

export function RansomwareLogsTab({ alerts = [], onAction }) {
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [selectedLog, setSelectedLog] = useState(null);

  const rows = useMemo(() => (Array.isArray(alerts) ? alerts.map(normalizeRansomwareAlert) : []), [alerts]);
  const filtered = rows.filter(r => {
    const sMatch = sevFilter === 'all' || alertSeverity(r) === sevFilter;
    const txt = `${alertHost(r)} ${ransomwareProcess(r)} ${ransomwareFamily(r)} ${ransomwareCategory(r)}`.toLowerCase();
    const qMatch = !search || txt.includes(search.toLowerCase());
    return sMatch && qMatch;
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, padding: 16, display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 15, fontWeight: 900, color: '#fff' }}>📜 Encryption & Ransomware Telemetry Logs (SIEM Table View)</h3>
            <div style={{ fontSize: 10, color: MON.muted, marginTop: 2 }}>Click any log row to open SOC Master 10-Tab Ransomware Forensic Panel</div>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              type="text"
              placeholder="🔍 Search host, process, variant..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '6px 12px', color: '#fff', fontSize: 11, width: 220 }}
            />
            <select
              value={sevFilter}
              onChange={e => setSevFilter(e.target.value)}
              style={{ background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, padding: '6px 10px', color: '#fff', fontSize: 11 }}
            >
              <option value="all">All Severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
            </select>
          </div>
        </div>

        <div style={{ marginTop: 14, overflowX: 'auto' }}>
          <div style={{ minWidth: 1280, display: 'grid', gridTemplateColumns: '100px 130px 150px 65px 2fr 1.4fr 130px 110px 90px 105px', gap: 8, borderBottom: `1px solid ${MON.line}`, paddingBottom: 6, fontSize: 9, fontWeight: 800, color: MON.sub }}>
            <span>Time</span><span>Host</span><span>Suspicious Process</span><span>PID</span><span>Command Line</span><span>File / Directory</span><span>Variant / Family</span><span>Canary Status</span><span>Severity</span><span>Inspect</span>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginTop: 6 }}>
            {filtered.length ? filtered.map((r, i) => (
              <div
                key={i}
                onClick={() => setSelectedLog(r)}
                style={{ minWidth: 1280, display: 'grid', gridTemplateColumns: '100px 130px 150px 65px 2fr 1.4fr 130px 110px 90px 105px', gap: 8, alignItems: 'center', fontSize: 8.5, borderTop: `1px solid ${MON.line}44`, paddingTop: 5, paddingBottom: 5, cursor: 'pointer', transition: 'background 0.2s' }}
                onMouseEnter={e => e.currentTarget.style.background = MON.card2}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                <span style={{ color: MON.muted }}>{new Date(alertTime(r)).toLocaleTimeString()}</span>
                <b style={{ color: MON.cyan }}>{alertHost(r)}</b>
                <code style={{ color: MON.text }}>{ransomwareProcessDisplay(r)}</code>
                <span style={{ color: MON.text }}>{ransomwarePidDisplay(r)}</span>
                <code title={ransomwareCommandDisplay(r)} style={{ color: MON.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ransomwareCommandDisplay(r)}</code>
                <span title={ransomwareFileLocation(r)} style={{ color: MON.cyan, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ransomwareFileLocation(r)}</span>
                <span style={{ color: MON.purple }}>{ransomwareFamily(r)}</span>
                <span style={{ color: ransomwareCanary(r).includes('Triggered') ? MON.red : MON.green }}>{ransomwareCanary(r)}</span>
                <b style={{ color: SEV_COLOR[alertSeverity(r)], textTransform: 'uppercase' }}>{alertSeverity(r)}</b>
                <button type="button" onClick={(e) => { e.stopPropagation(); setSelectedLog(r); }} style={{ background: MON.card2, border: `1px solid ${MON.red}`, color: MON.red, padding: '3px 6px', borderRadius: 4, fontSize: 8, fontWeight: 800, cursor: 'pointer' }}>
                  🔍 Forensic Panel
                </button>
              </div>
            )) : <div style={{ padding: 20, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No ransomware logs match search filters</div>}
          </div>
        </div>
      </div>

      {selectedLog && <RansomwareForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

export function RansomwareReportsTab({ alerts = [] }) {
  return <CapabilityReportsPanel capabilityId={27} alerts={alerts} />;
}

const DEFAULT_RANSOMWARE_CONFIG = {
  enabled: true,
  windowSeconds: 30,
  massModificationThreshold: 50,
  massDeletionThreshold: 30,
  entropyThreshold: 7,
  entropyFileTrigger: 10,
  alertCooldownSeconds: 120,
  customExtensions: [],
  protectedDirectories: [],
};

export function RansomwareConfigurationTab({ systems = [] }) {
  const [configuration, setConfiguration] = useState(DEFAULT_RANSOMWARE_CONFIG);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [ruleSaving, setRuleSaving] = useState(false);
  const [message, setMessage] = useState('');
  const [targetCount, setTargetCount] = useState(systems.length);
  const [rules, setRules] = useState([]);
  const [editingRule, setEditingRule] = useState(null);

  const loadConfiguration = useCallback(async () => {
    setLoading(true);
    setMessage('');
    try {
      const response = await api.get('/ransomware/configuration');
      setConfiguration({ ...DEFAULT_RANSOMWARE_CONFIG, ...(response.data?.configuration || {}) });
      setRules(Array.isArray(response.data?.rules) ? response.data.rules : []);
      setTargetCount(Number(response.data?.targetCount ?? systems.length));
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to load ransomware configuration');
    } finally {
      setLoading(false);
    }
  }, [systems.length]);

  useEffect(() => { loadConfiguration(); }, [loadConfiguration]);

  const setNumber = (key, value) => setConfiguration(current => ({ ...current, [key]: Number(value) }));
  const saveRule = async () => {
    if (!editingRule?.id) return;
    setRuleSaving(true);
    setMessage('');
    try {
      const response = await api.patch(`/ransomware/configuration/rules/${encodeURIComponent(editingRule.id)}`, {
        enabled: editingRule.enabled !== false,
        severity: editingRule.severity,
      });
      setRules(current => current.map(rule => rule.id === editingRule.id ? response.data.rule : rule));
      setMessage(response.data?.message || 'Ransomware rule updated');
      setEditingRule(null);
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to update ransomware rule');
    } finally {
      setRuleSaving(false);
    }
  };
  const save = async () => {
    setSaving(true);
    setMessage('');
    try {
      const response = await api.put('/ransomware/configuration', {
        ...configuration,
        customExtensions: Array.isArray(configuration.customExtensions)
          ? configuration.customExtensions
          : String(configuration.customExtensions || '').split(/[\n,]/),
        protectedDirectories: Array.isArray(configuration.protectedDirectories)
          ? configuration.protectedDirectories
          : String(configuration.protectedDirectories || '').split('\n'),
      });
      setConfiguration({ ...DEFAULT_RANSOMWARE_CONFIG, ...(response.data?.configuration || {}) });
      setTargetCount(Number(response.data?.targetCount ?? targetCount));
      setMessage(response.data?.message || 'Ransomware configuration saved');
    } catch (error) {
      setMessage(error.response?.data?.message || 'Unable to save ransomware configuration');
    } finally {
      setSaving(false);
    }
  };

  const numericFields = [
    ['Detection Window', 'windowSeconds', 'seconds', 5, 300],
    ['Mass Modification Threshold', 'massModificationThreshold', 'files', 2, 10000],
    ['Mass Deletion Threshold', 'massDeletionThreshold', 'files', 2, 10000],
    ['Entropy Threshold', 'entropyThreshold', '0–8', 0, 8],
    ['High-Entropy File Trigger', 'entropyFileTrigger', 'files', 1, 1000],
    ['Alert Cooldown', 'alertCooldownSeconds', 'seconds', 10, 86400],
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 16 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <div>
            <h3 style={{ margin: 0, color: '#fff', fontSize: 15 }}>⚙️ Ransomware Detection Configuration</h3>
            <div style={{ color: MON.muted, fontSize: 10, marginTop: 4 }}>Policy is securely synchronized to {targetCount} enrolled agent(s) on heartbeat.</div>
          </div>
          <label style={{ display: 'flex', gap: 8, alignItems: 'center', color: configuration.enabled ? MON.green : MON.muted, fontSize: 11, fontWeight: 800 }}>
            <input type="checkbox" checked={configuration.enabled !== false} onChange={event => setConfiguration(current => ({ ...current, enabled: event.target.checked }))} />
            Detection {configuration.enabled !== false ? 'Enabled' : 'Disabled'}
          </label>
        </div>
      </div>

      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto' }}>
        <div style={{ padding: '12px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            <div style={{ color: '#fff', fontSize: 12, fontWeight: 900 }}>Ransomware Detection Rules</div>
            <div style={{ color: MON.muted, fontSize: 9, marginTop: 3 }}>Built-in rules deployed to endpoint agents. Select Edit to change status or severity.</div>
          </div>
          <span style={{ color: MON.cyan, fontSize: 10, fontWeight: 800 }}>{rules.length} RULES</span>
        </div>
        <div style={{ minWidth: 820, overflowX: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1.4fr .7fr 2fr .7fr .7fr 110px', gap: 10, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
            <span>Rule</span><span>Category</span><span>Description</span><span>Severity</span><span>Status</span><span>Action</span>
          </div>
          {loading ? (
            <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>Loading rules…</div>
          ) : rules.length ? rules.map(rule => {
            const editing = editingRule?.id === rule.id;
            const displayed = editing ? editingRule : rule;
            const severityColor = SEV_COLOR[String(displayed.severity || '').toLowerCase()] || MON.muted;
            return (
              <div key={rule.id} style={{ display: 'grid', gridTemplateColumns: '1.4fr .7fr 2fr .7fr .7fr 110px', gap: 10, alignItems: 'center', padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10 }}>
                <div><b style={{ color: MON.text }}>{rule.name}</b><div style={{ color: MON.sub, fontFamily: 'monospace', fontSize: 8, marginTop: 2 }}>{rule.id}</div></div>
                <span style={{ color: MON.cyan }}>{rule.category}</span>
                <span style={{ color: MON.muted }}>{rule.description}</span>
                {editing ? (
                  <select value={displayed.severity} onChange={event => setEditingRule(current => ({ ...current, severity: event.target.value }))} style={{ background: MON.card2, border: `1px solid ${MON.border}`, color: '#fff', borderRadius: 5, padding: 6, fontSize: 10 }}>
                    {['low', 'medium', 'high', 'critical'].map(level => <option key={level} value={level}>{level}</option>)}
                  </select>
                ) : <b style={{ color: severityColor, textTransform: 'uppercase' }}>{displayed.severity}</b>}
                {editing ? (
                  <label style={{ color: displayed.enabled !== false ? MON.green : MON.muted, display: 'flex', gap: 5, alignItems: 'center' }}><input type="checkbox" checked={displayed.enabled !== false} onChange={event => setEditingRule(current => ({ ...current, enabled: event.target.checked }))} />{displayed.enabled !== false ? 'Enabled' : 'Disabled'}</label>
                ) : <b style={{ color: displayed.enabled !== false ? MON.green : MON.muted }}>{displayed.enabled !== false ? 'ENABLED' : 'DISABLED'}</b>}
                {editing ? (
                  <div style={{ display: 'flex', gap: 5 }}>
                    <button type="button" disabled={ruleSaving} onClick={saveRule} style={{ border: `1px solid ${MON.green}`, color: MON.green, background: `${MON.green}18`, borderRadius: 5, padding: '5px 7px', cursor: 'pointer', fontSize: 9, fontWeight: 800 }}>Save</button>
                    <button type="button" disabled={ruleSaving} onClick={() => setEditingRule(null)} style={{ border: `1px solid ${MON.border}`, color: MON.muted, background: MON.card2, borderRadius: 5, padding: '5px 7px', cursor: 'pointer', fontSize: 9 }}>Cancel</button>
                  </div>
                ) : (
                  <button type="button" onClick={() => setEditingRule({ ...rule })} style={{ border: `1px solid ${MON.cyan}`, color: MON.cyan, background: `${MON.cyan}12`, borderRadius: 5, padding: '5px 10px', cursor: 'pointer', fontSize: 9, fontWeight: 800 }}>✎ Edit</button>
                )}
              </div>
            );
          }) : <div style={{ padding: 18, textAlign: 'center', color: MON.muted, fontSize: 11 }}>No ransomware rules configured</div>}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, minmax(180px, 1fr))', gap: 12 }}>
        {numericFields.map(([label, key, suffix, min, max]) => (
          <label key={key} style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14, display: 'flex', flexDirection: 'column', gap: 7 }}>
            <span style={{ color: MON.text, fontSize: 10, fontWeight: 800 }}>{label}</span>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <input type="number" min={min} max={max} step={key === 'entropyThreshold' ? 0.1 : 1} value={configuration[key]} onChange={event => setNumber(key, event.target.value)} style={{ width: '100%', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, color: '#fff', padding: '8px 10px', fontSize: 12 }} />
              <span style={{ color: MON.muted, fontSize: 9 }}>{suffix}</span>
            </div>
          </label>
        ))}
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <label style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <span style={{ color: MON.text, fontSize: 10, fontWeight: 800 }}>Custom Ransomware Extensions</span>
          <textarea value={(configuration.customExtensions || []).join('\n')} onChange={event => setConfiguration(current => ({ ...current, customExtensions: event.target.value.split('\n') }))} placeholder={'.companylocked\n.customcrypt'} rows={7} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 8, resize: 'vertical', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, color: '#fff', padding: 10, fontFamily: 'monospace', fontSize: 11 }} />
          <div style={{ color: MON.muted, fontSize: 9, marginTop: 6 }}>One extension per line. Leading dot is added automatically.</div>
        </label>
        <label style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <span style={{ color: MON.text, fontSize: 10, fontWeight: 800 }}>Additional Protected Directories</span>
          <textarea value={(configuration.protectedDirectories || []).join('\n')} onChange={event => setConfiguration(current => ({ ...current, protectedDirectories: event.target.value.split('\n') }))} placeholder={'C:\\CorporateData\n/srv/company-data'} rows={7} style={{ display: 'block', width: '100%', boxSizing: 'border-box', marginTop: 8, resize: 'vertical', background: MON.card2, border: `1px solid ${MON.border}`, borderRadius: 6, color: '#fff', padding: 10, fontFamily: 'monospace', fontSize: 11 }} />
          <div style={{ color: MON.muted, fontSize: 9, marginTop: 6 }}>One absolute path per line. New watch roots take effect when the agent service restarts.</div>
        </label>
      </div>

      {message && <div style={{ color: /unable|invalid|error/i.test(message) ? MON.red : MON.green, background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 6, padding: 10, fontSize: 11 }}>{message}</div>}
      <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
        <button type="button" onClick={loadConfiguration} disabled={loading || saving} style={{ background: MON.card2, color: MON.text, border: `1px solid ${MON.border}`, padding: '9px 15px', borderRadius: 6, cursor: 'pointer', fontWeight: 800 }}>Reload</button>
        <button type="button" onClick={save} disabled={loading || saving} style={{ background: MON.red, color: '#fff', border: 'none', padding: '9px 18px', borderRadius: 6, cursor: 'pointer', fontWeight: 900 }}>{saving ? 'Saving…' : 'Save & Deploy'}</button>
      </div>
    </div>
  );
}

function RansomwareOverviewDashboard({ alerts = [], total = 0, onAction }) {
  const [selectedLog, setSelectedLog] = useState(null);
  const panel = { background: 'linear-gradient(180deg, #0c2136 0%, #081827 100%)', border: '1px solid #1b3854', borderRadius: 8, padding: 12, boxShadow: 'inset 0 0 18px rgba(56,189,248,0.04)' };
  const rows = useMemo(() => (Array.isArray(alerts) ? alerts.map(normalizeRansomwareAlert) : []), [alerts]);
  const totalEvents = total || rows.length;
  const response = responseSummary(rows);
  const signatureCount = rows.filter(row => ransomwareFamily(row) !== 'Unknown').length;
  const vssEvents = countMatching(rows, /shadow|vss|recovery/);
  const canaryEvents = countMatching(rows, /canary|honeytoken/);
  const topFamilies = topCounts(rows, ransomwareFamily, 4);
  const familyTotal = topFamilies.reduce((sum, [, count]) => sum + count, 0);
  const topExtensions = topCounts(rows, extensionValue, 4);
  const topProcesses = topCounts(rows, ransomwareProcess, 4);

  const timeline = buildBuckets(rows, 12, 24);
  const maxTimeline = Math.max(...timeline, 1);

  const summaryCards = [
    { title: 'Encryption Detections', value: shortNum(totalEvents), delta: 'observed detection records', color: MON.red, bg: 'linear-gradient(135deg,#7f1d1d,#2b1116)' },
    { title: 'Known Ransomware Families', value: shortNum(signatureCount), delta: 'classified detections', color: MON.orange, bg: 'linear-gradient(135deg,#7a3e00,#2a1b09)' },
    { title: 'Canary Events', value: shortNum(canaryEvents), delta: canaryEvents ? 'observed telemetry' : 'no canary telemetry', color: MON.green, bg: 'linear-gradient(135deg,#064e3b,#09231b)' },
    { title: 'VSS / Recovery Tamper', value: shortNum(vssEvents), delta: vssEvents ? 'observed attempts' : 'no tamper telemetry', color: MON.cyan, bg: 'linear-gradient(135deg,#0e4f6d,#062334)' },
    { title: 'Successful Containments', value: shortNum(response.successful), delta: response.attempted ? `${response.attempted} attempted` : 'no response telemetry', color: MON.purple, bg: 'linear-gradient(135deg,#4c1d95,#24103a)' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, background: '#06111f', border: `1px solid ${MON.border}`, borderRadius: 10, padding: 12 }}>
      {/* Top Banner Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, padding: '12px 14px', borderRadius: 9, background: 'linear-gradient(100deg,#3b0764,#091725)', border: `1px solid ${MON.red}40` }}>
        <div>
          <div style={{ color: '#f8fafc', fontSize: 15, fontWeight: 900 }}>🔐 Encryption & Ransomware Threat Intelligence Operations Center</div>
          <div style={{ color: MON.muted, fontSize: 9, marginTop: 4 }}>Real-time mass file encryption detection, honeytoken canary file shielding, and VSS Volume Shadow Copy anti-tamper · Capability ID 27</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <span style={{ color: MON.red, fontSize: 9, fontWeight: 800, padding: '5px 9px', border: `1px solid ${MON.red}55`, borderRadius: 12 }}>● CRITICAL SHIELD ACTIVE</span>
          <span style={{ color: MON.cyan, fontSize: 9, fontWeight: 800, padding: '5px 9px', border: `1px solid ${MON.cyan}55`, borderRadius: 12 }}>AUTO REFRESH 15s</span>
        </div>
      </div>

      {/* Top 5 Summary Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 10 }}>
        {summaryCards.map(card => (
          <div key={card.title} style={{ background: card.bg, border: `1px solid ${card.color}55`, borderRadius: 7, padding: 14, minHeight: 86, position: 'relative', overflow: 'hidden' }}>
            <div style={{ fontSize: 9, color: '#dbeafe', fontWeight: 900, textTransform: 'uppercase' }}>{card.title}</div>
            <div style={{ marginTop: 8, fontSize: 24, color: '#fff', fontWeight: 900 }}>{card.value}</div>
            <div style={{ marginTop: 7, fontSize: 9, color: card.color }}>↗ {card.delta}</div>
            <div style={{ position: 'absolute', right: 8, bottom: 8, width: 70, opacity: 0.9 }}><MiniSparkline data={timeline} color={card.color} height={26} /></div>
          </div>
        ))}
      </div>

      {/* Middle Grid (4 Panels) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1fr 1.2fr 1fr', gap: 10 }}>
        {/* Panel 1: Variant Breakdown */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Ransomware Threat Variant Breakdown</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            {(topFamilies.length ? topFamilies : [['No family classification', 0]]).map(([family, count], index) => {
              const item = { family, pct: familyTotal ? Math.round((count / familyTotal) * 100) : 0, col: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan };
              return (
              <div key={item.family}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 2 }}>
                  <span style={{ color: MON.text }}>{item.family}</span>
                  <b style={{ color: item.col }}>{item.pct}%</b>
                </div>
                <div style={{ width: '100%', height: 5, background: '#07101b', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${item.pct}%`, height: '100%', background: item.col }} />
                </div>
              </div>
            );})}
          </div>
        </div>

        {/* Panel 2: VSS & Canary Protection */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>VSS & Canary Shield Integrity</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 10, fontSize: 10 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>VSS / Recovery telemetry:</span> <b style={{ color: vssEvents ? MON.red : MON.muted }}>{vssEvents ? `${vssEvents} events` : 'No telemetry'}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Backup tamper telemetry:</span> <b style={{ color: countMatching(rows, /backup/) ? MON.red : MON.muted }}>{countMatching(rows, /backup/) ? `${countMatching(rows, /backup/)} events` : 'No telemetry'}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Canary honeytokens:</span> <b style={{ color: canaryEvents ? MON.red : MON.muted }}>{canaryEvents ? `${canaryEvents} events` : 'No telemetry'}</b></div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>Containment actions:</span> <b style={{ color: response.attempted ? MON.green : MON.muted }}>{response.rate}</b></div>
          </div>
        </div>

        {/* Panel 3: File Modification Velocity */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>File Modification Velocity (Files / Sec)</b>
          <div style={{ height: 100, display: 'flex', alignItems: 'flex-end', gap: 6, marginTop: 12, borderBottom: `1px solid ${MON.line}` }}>
            {timeline.map((val, idx) => (
              <div key={idx} style={{ flex: 1, height: `${Math.max(6, (val / maxTimeline) * 100)}%`, background: `linear-gradient(180deg, ${MON.red}, #7f1d1d)`, borderRadius: '3px 3px 0 0' }} />
            ))}
          </div>
        </div>

        {/* Panel 4: Affected Extensions */}
        <div style={panel}>
          <b style={{ fontSize: 12, color: '#fff' }}>Targeted File Extensions & Damage Radius</b>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, marginTop: 10, fontSize: 10 }}>
            {(topExtensions.length ? topExtensions : [['No extension telemetry', 0]]).map(([ext, count], index) => (
              <div key={ext} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.cyan, fontFamily: 'monospace' }}>📄 {ext}</span>
                <b style={{ color: [MON.red, MON.orange, MON.yellow, MON.purple][index] || MON.cyan }}>{count} events</b>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Agent-Based Endpoint Inspection Table */}
      <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflowX: 'auto' }}>
        <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Ransomware Inspection (Endpoints & Servers)</div>
          <div style={{ fontSize: 9, color: MON.green }}>● Real-Time Agent Telemetry Stream Active (Click row for Forensic Panel)</div>
        </div>
        <div style={{ minWidth: 1250, display: 'grid', gridTemplateColumns: '120px 145px 60px 2fr 1.3fr 120px 105px 85px 1.2fr', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
          <span>Host</span><span>Suspicious Process</span><span>PID</span><span>Command Line</span><span>File / Directory</span><span>Variant / Family</span><span>Canary Status</span><span>Severity</span><span>Mitigation Action</span>
        </div>
        {rows.map((row, idx) => (
          <div
            key={idx}
            onClick={() => setSelectedLog(row)}
            style={{ minWidth: 1250, display: 'grid', gridTemplateColumns: '120px 145px 60px 2fr 1.3fr 120px 105px 85px 1.2fr', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center', cursor: 'pointer', transition: 'background 0.2s' }}
            onMouseEnter={e => e.currentTarget.style.background = MON.card2}
            onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          >
            <b style={{ color: MON.cyan }}>{alertHost(row)}</b>
            <code style={{ color: MON.text }}>{ransomwareProcessDisplay(row)}</code>
            <span>{ransomwarePidDisplay(row)}</span>
            <code title={ransomwareCommandDisplay(row)} style={{ color: MON.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ransomwareCommandDisplay(row)}</code>
            <span title={ransomwareFileLocation(row)} style={{ color: MON.cyan, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ransomwareFileLocation(row)}</span>
            <span style={{ color: MON.purple }}>{ransomwareFamily(row)}</span>
            <span style={{ color: ransomwareCanary(row).includes('Triggered') ? MON.red : MON.green }}>{ransomwareCanary(row)}</span>
            <b style={{ color: SEV_COLOR[alertSeverity(row)], textTransform: 'uppercase' }}>{alertSeverity(row)}</b>
            <b style={{ color: row.action ? MON.green : MON.muted }}>{row.action || row.recommendedAction || 'No action recorded'}</b>
          </div>
        ))}
      </div>

      {/* 3 Bottom Analytics Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Encryption Event Burst Wave (24 Hours)</div>
          <div style={{ height: 120, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
            {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
              <div key={idx} title={`${val} ransomware bursts`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.red, borderRadius: '2px 2px 0 0' }} />
            ))}
          </div>
        </div>

        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Flagged Ransomware Binaries</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
            {(topProcesses.length ? topProcesses : [['No process telemetry', 0]]).map(([proc, cnt], index) => (
              <div key={proc} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.text, fontWeight: 700 }}>{proc}</span>
                <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan, fontWeight: 800 }}>{cnt} events</span>
              </div>
            ))}
          </div>
        </div>

        <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
          <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Ransomware Shield Status</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
            {[
              ['VSS / recovery telemetry', vssEvents ? `${vssEvents} events` : 'No telemetry', vssEvents ? MON.red : MON.muted],
              ['Canary honeytoken telemetry', canaryEvents ? `${canaryEvents} events` : 'No telemetry', canaryEvents ? MON.red : MON.muted],
              ['Containment actions', response.attempted ? `${response.successful}/${response.attempted} successful` : 'Not configured', response.attempted ? MON.green : MON.muted],
              ['MITRE T1486 / T1490 evidence', countMatching(rows, /t1486|t1490/) ? `${countMatching(rows, /t1486|t1490/)} events` : 'No telemetry', MON.cyan],
            ].map(([lbl, stat, col]) => (
              <div key={lbl} style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: MON.muted }}>{lbl}</span>
                <span style={{ color: col, fontWeight: 800 }}>{stat}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {selectedLog && <RansomwareForensicDetailModal log={selectedLog} onClose={() => setSelectedLog(null)} onAction={onAction} />}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// MAIN DASHBOARD COMPONENT (`RansomwareDashboardPanel`)
// ═════════════════════════════════════════════════════════════════════════════
export function RansomwareDashboardPanel({ alerts = [], loading = false, total = 0, systems = [], onAction, onRefresh }) {
  const [activeTab, setActiveTab] = useState('dashboard');

  const rows = useMemo(() => (Array.isArray(alerts) ? alerts.map(normalizeRansomwareAlert) : []), [alerts]);
  const totalRows = total || rows.length;

  const timeline = buildBuckets(rows, 8, 24);
  const response = responseSummary(rows);
  const affectedFileCount = rows.reduce((sum, row) => sum + (Number(row?.affectedFiles) || 0), 0);
  const vssCount = countMatching(rows, /shadow|vss|recovery/);
  const backupCount = countMatching(rows, /backup/);
  const topProcesses = topCounts(rows, ransomwareProcess, 4);

  // 20 Ransomware & Encryption SOC Categories & Metrics
  const kpis = [
    { label: '⚡ 1. Encryption / Ransomware Detections', val: shortNum(totalRows), trend: 'Detections', color: MON.red, data: timeline },
    { label: '🏷️ 2. File Extension Anomalies (.locked/.crypto)', val: shortNum(rows.filter(row => extensionValue(row) !== '—' || /extension|\.locked|\.encrypted|\.crypt/i.test(ransomwareText(row))).length), trend: 'Extensions', color: MON.orange, data: timeline },
    { label: '📄 3. Ransom Note File Detections', val: shortNum(countMatching(rows, /ransom note|recover.files|decrypt.instructions|readme\.txt/)), trend: 'Ransom Notes', color: MON.yellow, data: timeline },
    { label: '📂 4. Affected Files / Mass Operations', val: shortNum(affectedFileCount || countMatching(rows, /mass file|bulk|recursive|rapid file/)), trend: 'Affected Files', color: MON.purple, data: timeline },
    { label: '📊 5. High Entropy Events (> 7.8/8.0)', val: shortNum(rows.filter(row => Number(row?.entropy) > 7.8).length), trend: 'Entropy', color: MON.red, data: timeline },
    { label: '📁 6. Sensitive Directory Events', val: shortNum(rows.filter(row => row?.affectedDirectory || /desktop|documents|downloads|share|database|nas/i.test(ransomwareText(row))).length), trend: 'Directories', color: MON.cyan, data: timeline },
    { label: '🛡️ 7. Volume Shadow Copy / Recovery Tamper', val: shortNum(vssCount), trend: 'VSS', color: MON.green, data: timeline },
    { label: '💾 8. Backup Service & Software Tamper', val: shortNum(backupCount), trend: 'Backup', color: MON.green, data: timeline },
    { label: '⚡ 9. Disk Write / Encryption Speed Events', val: shortNum(rows.filter(row => Number(row?.encryptionSpeed) > 0 || Number(row?.diskWriteRate) > 0).length), trend: 'Disk Activity', color: MON.orange, data: timeline },
    { label: '🔥 10. CPU Encryption Spikes', val: shortNum(countMatching(rows, /cpu|multi.core/)), trend: 'CPU', color: MON.red, data: timeline },
    { label: '🧠 11. Memory Injection / RWX Events', val: shortNum(countMatching(rows, /rwx|reflective|inject|shellcode/)), trend: 'Memory', color: MON.purple, data: timeline },
    { label: '⚙️ 12. Suspicious Encryption Processes', val: shortNum(rows.filter(row => ransomwareProcess(row) !== '—').length), trend: 'Processes', color: MON.red, data: timeline },
    { label: '🔒 13. Registry / Persistence Events', val: shortNum(countMatching(rows, /registry|run key|persist|scheduled task|startup/)), trend: 'Persistence', color: MON.yellow, data: timeline },
    { label: '🔑 14. Credential Access Events', val: shortNum(countMatching(rows, /lsass|credential|mimikatz|sam|ntds|dpapi/)), trend: 'Credential', color: MON.red, data: timeline },
    { label: '↔️ 15. Lateral Movement Correlations', val: shortNum(countMatching(rows, /psexec|smb|rdp|winrm|lateral|pass.the/)), trend: 'Lateral', color: MON.purple, data: timeline },
    { label: '📡 16. C2 / Exfiltration Correlations', val: shortNum(countMatching(rows, /c2|command.{0,5}control|exfil|tor|beacon/)), trend: 'Network', color: MON.orange, data: timeline },
    { label: '🛡️ 17. Security Tool Tampering', val: shortNum(countMatching(rows, /defender|firewall|edr|antivirus|sysmon|event log|security tool/)), trend: 'Tamper', color: MON.green, data: timeline },
    { label: '🦠 18. Malware IOC & YARA Rule Matches', val: shortNum(countMatching(rows, /ioc|yara|malware family|hash match/)), trend: 'IOC', color: MON.red, data: timeline },
    { label: '🗺️ 19. MITRE ATT&CK T1486 / T1490 Mappings', val: shortNum(countMatching(rows, /t1486|t1490/)), trend: 'MITRE', color: MON.cyan, data: timeline },
    { label: '🛑 20. Containment Success Rate', val: response.rate, trend: response.attempted ? 'Response Audit' : 'No Actions', color: response.attempted ? MON.green : MON.muted, data: timeline },
  ];

  const agentStatusRows = systems.map(sys => {
    const host = sys.hostname || sys.name || '—';
    const hostEvents = rows.filter(r => normHost(alertHost(r)) === normHost(host)).length;
    const threats = rows.filter(r => normHost(alertHost(r)) === normHost(host) && ['medium', 'high', 'critical'].includes(alertSeverity(r))).length;
    return ({
      key: sys._id || sys.name,
      name: sys.name || sys.hostname || '—',
      hostname: host,
      status: sys.status || (sys.agentOk || sys.isOnline ? 'reporting' : 'unknown'),
      events: hostEvents,
      threats,
      platform: sys.platform || sys.os || '—',
      lastSeen: sys.lastSeen || sys.updatedAt || null,
    });
  });

  return (
    <div style={{ background: MON.bg, color: MON.text, display: 'flex', height: '100%', minHeight: 0, overflow: 'hidden' }}>
      {/* Sidebar Navigation */}
      <aside style={{ width: 235, flexShrink: 0, background: MON.card2, borderRight: `1px solid ${MON.border}`, padding: 14, display: 'flex', flexDirection: 'column', gap: 8 }}>
        {[
          { id: 'dashboard', icon: '📊', label: 'Dashboard', activeColor: MON.red },
          { id: 'monitoring', icon: '📊', label: 'Monitoring', activeColor: MON.orange },
          { id: 'logs', icon: '📜', label: 'Logs (SIEM Table)', activeColor: MON.orange },
          { id: 'reports', icon: '📄', label: 'Reports', activeColor: MON.purple },
          { id: 'configuration', icon: '⚙️', label: 'Configure', activeColor: MON.cyan },
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
                color: selected ? '#fff' : MON.text,
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
        {activeTab === 'logs' ? (
          <CapabilityLogsPanel capabilityId={27}>
            <RansomwareLogsTab alerts={rows} onAction={onAction} />
          </CapabilityLogsPanel>
        ) : activeTab === 'reports' ? (
          <RansomwareReportsTab alerts={rows} />
        ) : activeTab === 'dashboard' ? (
          <RansomwareOverviewDashboard alerts={rows} total={total} onAction={onAction} />
        ) : activeTab === 'configuration' ? (
          <RansomwareConfigurationTab systems={systems} />
        ) : (
          <>
            {/* 20 Top KPI Cards Grid */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 12 }}>
              {kpis.map((kpi, i) => (
                <div
                  key={i}
                  style={{
                    background: 'linear-gradient(135deg, #0b1929 0%, #0d2238 100%)',
                    border: `1px solid ${kpi.color}44`,
                    borderRadius: 9,
                    padding: '12px 14px',
                    display: 'flex',
                    flexDirection: 'column',
                    justify: 'space-between',
                    minHeight: 96,
                    boxShadow: `0 4px 14px rgba(0,0,0,0.35), inset 0 0 12px ${kpi.color}0a`,
                    position: 'relative',
                    overflow: 'hidden',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 8 }}>
                    <div style={{ fontSize: 10, fontWeight: 800, color: '#e2e8f0', lineHeight: 1.35, flex: 1 }}>{kpi.label}</div>
                    <span style={{ fontSize: 8.5, fontWeight: 900, color: kpi.color, background: `${kpi.color}18`, border: `1px solid ${kpi.color}44`, padding: '2px 7px', borderRadius: 10, whiteSpace: 'nowrap', flexShrink: 0 }}>
                      {kpi.trend}
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', marginTop: 12 }}>
                    <div style={{ fontSize: 22, fontWeight: 900, color: '#ffffff', letterSpacing: '-0.5px' }}>{kpi.val}</div>
                    <div style={{ width: 68, opacity: 0.9, flexShrink: 0 }}>
                      <MiniSparkline data={kpi.data} color={kpi.color} height={26} />
                    </div>
                  </div>
                </div>
              ))}
            </div>

            {/* Agent Level Table */}
            <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, overflow: 'hidden' }}>
              <div style={{ padding: '11px 14px', borderBottom: `1px solid ${MON.line}`, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 12, fontWeight: 900, color: '#fff' }}>🛰 Agent-Based Ransomware Detection Engine (Endpoints & Servers)</div>
                <div style={{ fontSize: 9, color: MON.green }}>● {agentStatusRows.length} tenant endpoints loaded · {rows.length} ransomware records observed</div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '9px 12px', background: MON.card2, color: MON.muted, fontSize: 9, fontWeight: 800 }}>
                <span>Agent Host</span><span>Hostname</span><span>Platform Type</span><span>Ransomware Shield</span><span>File Events</span><span>Ransomware Threats</span><span>Last Sync</span>
              </div>
              {agentStatusRows.map(row => (
                <div key={row.key} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 110px 90px 90px 130px', gap: 8, padding: '10px 12px', borderTop: `1px solid ${MON.line}`, fontSize: 10, alignItems: 'center' }}>
                  <b style={{ color: MON.cyan }}>{row.name}</b><span>{row.hostname}</span>
                  <span style={{ color: MON.text }}>{row.platform}</span>
                  <b style={{ color: /online|reporting|active/i.test(String(row.status)) ? MON.green : MON.muted, textTransform: 'uppercase' }}>{row.status || 'unknown'}</b>
                  <b>{row.events}</b>
                  <b style={{ color: row.threats > 0 ? MON.red : MON.green }}>{row.threats}</b>
                  <span style={{ color: MON.sub }}>{row.lastSeen ? new Date(row.lastSeen).toLocaleTimeString() : '—'}</span>
                </div>
              ))}
            </div>

            {/* 3 Bottom Analytics Charts */}
            <div style={{ display: 'grid', gridTemplateColumns: '1.4fr 1fr 1fr', gap: 14 }}>
              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>📈 Real-Time Encryption Event Burst Wave (24 Hours)</div>
                <div style={{ height: 140, display: 'flex', alignItems: 'flex-end', gap: 8, borderBottom: `1px solid ${MON.line}` }}>
                  {buildBuckets(rows, 15, 24).map((val, idx, arr) => (
                    <div key={idx} title={`${val} ransomware bursts`} style={{ flex: 1, height: `${Math.max(4, (val / Math.max(...arr, 1)) * 100)}%`, background: MON.red, borderRadius: '2px 2px 0 0' }} />
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>⚙️ Top Flagged Ransomware Binaries</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {(topProcesses.length ? topProcesses : [['No process telemetry', 0]]).map(([proc, cnt], index) => (
                    <div key={proc} style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span style={{ color: MON.text, fontWeight: 700 }}>{proc}</span>
                      <span style={{ color: [MON.red, MON.orange, MON.purple, MON.yellow][index] || MON.cyan, fontWeight: 800 }}>{cnt} events</span>
                    </div>
                  ))}
                </div>
              </div>

              <div style={{ background: MON.card, border: `1px solid ${MON.border}`, borderRadius: 8, padding: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 800, color: '#fff', marginBottom: 12 }}>🛡️ Ransomware Shield Status</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, fontSize: 11 }}>
                  {[
                    ['VSS / recovery telemetry', vssCount ? `${vssCount} events` : 'No telemetry', vssCount ? MON.red : MON.muted],
                    ['Backup tamper telemetry', backupCount ? `${backupCount} events` : 'No telemetry', backupCount ? MON.red : MON.muted],
                    ['Containment actions', response.attempted ? `${response.successful}/${response.attempted} successful` : 'Not configured', response.attempted ? MON.green : MON.muted],
                    ['MITRE T1486 / T1490 evidence', countMatching(rows, /t1486|t1490/) ? `${countMatching(rows, /t1486|t1490/)} events` : 'No telemetry', MON.cyan],
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

export default function RansomwareDetectionPage() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const { company, user } = useAuth();
  const fromDashboard = searchParams.get('from') === 'dashboard';
  const companyId = company?._id || user?.companyId?._id || user?.companyId;

  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [total, setTotal] = useState(0);
  const [systems, setSystems] = useState([]);
  const refreshBufferRef = useRef(null);

  const loadAlerts = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const q = new URLSearchParams({ windowHours: 24, limit: 500 });
      const r = await api.get(`/dashboard/capabilities/27/live?${q}`);
      setAlerts((r.data?.alerts || []).map(normalizeRansomwareAlert));
      setTotal(r.data?.total || 0);
      setSystems(Array.isArray(r.data?.systems) ? r.data.systems : []);
    } catch (err) {
      console.warn('[Ransomware capability fetch warning]', err);
    } finally {
      if (!quiet) setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadAlerts(false);
    const interval = setInterval(() => loadAlerts(true), 15000);
    return () => clearInterval(interval);
  }, [loadAlerts]);

  useEffect(() => {
    if (!companyId) return undefined;
    const socket = io(SOCKET_URL, { ...socketOptions, transports: ['polling', 'websocket'] });
    const join = () => { if (companyId) socket.emit('join:company', companyId); };
    const scheduleRefresh = () => refreshBufferRef.current?.add();
    const scheduleDeletedRefresh = payload => {
      if (payload?.alertId) setAlerts(prev => prev.filter(row => String(row._id) !== String(payload.alertId)));
      scheduleRefresh();
    };
    refreshBufferRef.current = createEventBuffer(() => loadAlerts(true), 900);
    socket.on('connect', join);
    socket.on('ransomware:event', scheduleRefresh);
    socket.on('alert:new', scheduleRefresh);
    socket.on('alert:updated', scheduleRefresh);
    socket.on('alert:deleted', scheduleDeletedRefresh);
    join();
    const disc = connectSocket(socket);
    return () => {
      socket.off('connect', join);
      socket.off('ransomware:event', scheduleRefresh);
      socket.off('alert:new', scheduleRefresh);
      socket.off('alert:updated', scheduleRefresh);
      socket.off('alert:deleted', scheduleDeletedRefresh);
      refreshBufferRef.current?.clear();
      refreshBufferRef.current = null;
      disc();
    };
  }, [companyId, loadAlerts]);

  const doAction = useCallback(async (alertId, action) => {
    if (!alertId) throw new Error('A persisted alert ID is required');
    const reason = window.prompt(`Enter the reason for ${action.replaceAll('_', ' ')}:`)?.trim() || '';
    if (!reason) throw new Error('Containment cancelled: a reason is required');
    if (!window.confirm(`Confirm ${action.replaceAll('_', ' ')} for this alert?`)) throw new Error('Containment cancelled');
    const response = await api.patch(`/dashboard/alerts/${alertId}/action`, { action, reason, confirmed: true });
    await loadAlerts(true);
    return response.data;
  }, [loadAlerts]);

  const handleClose = () => navigate(fromDashboard ? '/' : '/edr', { replace: true });

  return (
    <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.75)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }} onClick={e => { if (e.target === e.currentTarget) handleClose(); }}>
      <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 12, width: 'calc(100vw - 8px)', height: 'calc(100vh - 8px)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '14px 18px', borderBottom: '1px solid #1e3a5f', flexShrink: 0 }}>
          <h3 style={{ margin: 0, fontSize: 15, color: '#e0f2fe' }}>
            🔐 27. Encryption & Ransomware Detection
            <span style={{ marginLeft: 10, color: MON.cyan, fontWeight: 900 }}>— {Number(total || alerts.length).toLocaleString()} logs</span>
          </h3>
          <button type="button" onClick={handleClose} style={{ background: 'none', border: 'none', color: '#60a5fa', fontSize: 20, cursor: 'pointer' }}>✕</button>
        </div>
        <RansomwareDashboardPanel alerts={alerts} loading={loading} total={total} systems={systems} onAction={doAction} onRefresh={() => loadAlerts(false)} />
      </div>
    </div>
  );
}

export function CapabilityPage() {
  return <RansomwareDetectionPage />;
}

export function RansomwareSubTabPage() {
  return <RansomwareDashboardPanel alerts={[]} />;
}
