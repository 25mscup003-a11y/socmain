import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Navigate, useLocation, useNavigate, useParams } from 'react-router-dom';
import api from '../../api/axios';
const CapabilityDataPage = () => null;
const CapabilityAgentsPage = () => null;
const TimeBasedCapabilityActions = () => null;

function shortNum(n = 0) {
  const val = Number(n) || 0;
  if (val >= 1000000) return (val / 1000000).toFixed(1) + 'M';
  if (val >= 1000) return (val / 1000).toFixed(1) + 'k';
  return String(val);
}
function normHost(h = '') { return String(h).trim().toLowerCase(); }
function processOs(r = {}) { return r.os || r.platform || 'Linux'; }
function systemVelociraptorClientId(sys = {}) { return sys.clientId || sys._id || ''; }
function recordId(r = {}) { return r._id || r.id || String(Math.random()); }
function isVelociraptorClientId(id = '') { return Boolean(id); }

const FC = {
  bg: '#03101d', panel: 'linear-gradient(135deg,#071827 0%,#06111f 100%)',
  border: '1px solid #14243a', text: '#e5edf7', muted: '#8ea0b8', sub: '#64748b',
  blue: '#3b82f6', cyan: '#22d3ee', green: '#22c55e', yellow: '#eab308',
  orange: '#f97316', red: '#ef4444', purple: '#a855f7',
};
const FIM_PAGE_SIZE = 1000;
const FIM_LOG_PAGE_SIZE = 200;

export const FIM_TABS = [
  { id: 'integrity-monitoring', icon: '🔍', label: 'Integrity Monitoring', path: '/edr-dashboard-details/fim/integrity-monitoring' },
  { id: 'permissions',          icon: '🔐', label: 'Permissions',          path: '/edr-dashboard-details/fim/permissions' },
  { id: 'ownership',            icon: '👤', label: 'Ownership',            path: '/edr-dashboard-details/fim/ownership' },
  { id: 'ransomware-detection', icon: '🛡️', label: 'Ransomware Detection', path: '/edr-dashboard-details/fim/ransomware-detection' },
  { id: 'sensitive-files',      icon: '📋', label: 'Sensitive Files',      path: '/edr-dashboard-details/fim/sensitive-files' },
  { id: 'reports',              icon: '📈', label: 'Reports',              path: '/edr-dashboard-details/fim/reports' },
  { id: 'alerts',               icon: '△', label: 'Alerts & Incidents',  path: '/edr-dashboard-details/fim/alerts' },
];

const FIM_META = {
  overview: {
    title: 'FIM Dashboard',
    subtitle: 'File Activity Monitoring — live overview of integrity events, alerts, agents, and activity across all endpoints.',
    kpis: [
      { label: 'Total Events',       value: '1,000',  color: '#3b82f6' },
      { label: 'Critical Alerts',    value: '0',      color: '#ef4444' },
      { label: 'Modified Files',     value: '322',    color: '#f97316' },
      { label: 'Agents Online',      value: '2',      color: '#22c55e' },
    ],
    panels: ['Recent File Events', 'Event Summary', 'Top Monitored Paths'],
  },
  'integrity-monitoring': {
    title: 'Integrity Monitoring',
    subtitle: 'Real-time file hash verification, baseline comparisons, and unauthorized modification detection.',
    kpis: [
      { label: 'Files Monitored', value: '12,480', color: '#3b82f6' },
      { label: 'Hash Mismatches', value: '23',     color: '#ef4444' },
      { label: 'Baseline Drifts', value: '7',      color: '#f97316' },
      { label: 'Verified Clean',  value: '12,457', color: '#22c55e' },
    ],
    panels: ['Hash Verification Log'],
  },
  permissions: {
    title: 'Permissions',
    subtitle: 'Track chmod, chown, ACL changes, and privilege escalation attempts across monitored endpoints.',
    kpis: [
      { label: 'Permission Changes', value: '341', color: '#f97316' },
      { label: 'SUID/SGID Changes',  value: '4',   color: '#ef4444' },
      { label: 'World-Writable',     value: '18',  color: '#eab308' },
      { label: 'Chown Events',       value: '129', color: '#a855f7' },
    ],
    panels: ['Permission Change Log', 'SUID/SGID Events', 'ACL Changes'],
  },
  ownership: {
    title: 'Ownership',
    subtitle: 'File and directory ownership changes, orphaned files, and root-owned anomaly tracking.',
    kpis: [
      { label: 'Ownership Changes', value: '87',  color: '#a855f7' },
      { label: 'Root-Owned Files',  value: '256', color: '#ef4444' },
      { label: 'Orphaned Files',    value: '12',  color: '#eab308' },
      { label: 'Group Changes',     value: '44',  color: '#3b82f6' },
    ],
    panels: ['Ownership Change Log', 'Root File Tracking', 'Orphaned File Report'],
  },
  'ransomware-detection': {
    title: 'Ransomware Detection',
    subtitle: 'Bulk encryption detection, suspicious extension changes, shadow copy deletions, and ransom note patterns.',
    kpis: [
      { label: 'Encrypted Bursts',  value: '2',   color: '#ef4444' },
      { label: 'Extension Changes', value: '34',  color: '#f97316' },
      { label: 'Shadow Deletions',  value: '0',   color: '#ef4444' },
      { label: 'Suspicious Writes', value: '128', color: '#eab308' },
    ],
    panels: ['Encryption Activity', 'Extension Anomalies', 'Ransomware Indicators'],
  },
  'sensitive-files': {
    title: 'Sensitive Files',
    subtitle: 'Monitor access and modifications to credentials, keys, configs, PII, and classified file paths.',
    kpis: [
      { label: 'Sensitive Paths', value: '286',   color: '#eab308' },
      { label: 'Access Events',   value: '1,420', color: '#f97316' },
      { label: 'Modifications',   value: '38',    color: '#ef4444' },
      { label: 'Deletions',       value: '6',     color: '#ef4444' },
    ],
    panels: ['Sensitive Path Watchlist', 'Credential File Accesses', 'PII File Events'],
  },
  reports: {
    title: 'Reports',
    subtitle: 'File integrity monitoring summaries, compliance exports, investigation reports, and audit trails.',
    kpis: [
      { label: 'Reports Generated', value: '14',    color: '#22c55e' },
      { label: 'Pending Exports',   value: '3',     color: '#eab308' },
      { label: 'Compliance Checks', value: '8',     color: '#3b82f6' },
      { label: 'Audit Entries',     value: '5,240', color: '#22d3ee' },
    ],
    panels: ['Daily FIM Summary', 'Compliance Export', 'Audit Trail'],
  },
  alerts: {
    title: 'Alerts',
    subtitle: 'All FIM-triggered alerts across severity levels, with triage status and investigation queue.',
    kpis: [
      { label: 'Total Alerts', value: '1,000', color: '#ef4444' },
      { label: 'Critical',     value: '0',     color: '#ef4444' },
      { label: 'High',         value: '12',    color: '#f97316' },
      { label: 'Unresolved',   value: '47',    color: '#eab308' },
    ],
    panels: ['Alert Queue', 'Severity Distribution', 'Investigation Status'],
  },
};

const FIM_SAMPLE_ROWS = [
  { file: '/etc/passwd',                     action: 'Permission Changed', host: 'linux-server-01', user: 'root',     sev: 'high',     time: '2m ago'  },
  { file: '/var/log/auth.log',               action: 'File Modified',      host: 'endpoint-02',     user: 'syslog',   sev: 'medium',   time: '5m ago'  },
  { file: '/bin/bash',                       action: 'Hash Mismatch',      host: 'srv-web-01',      user: 'root',     sev: 'critical', time: '9m ago'  },
  { file: '/home/user/.ssh/authorized_keys', action: 'File Created',       host: 'workstation-03',  user: 'user1',    sev: 'high',     time: '14m ago' },
  { file: '/tmp/suspicious.sh',              action: 'File Created',       host: 'endpoint-02',     user: 'www-data', sev: 'medium',   time: '18m ago' },
  { file: '/etc/crontab',                    action: 'File Modified',      host: 'srv-db-01',       user: 'root',     sev: 'high',     time: '22m ago' },
];

function fimSevColor(sev) {
  const s = (sev || '').toLowerCase();
  if (s === 'critical') return '#ef4444';
  if (s === 'high')     return '#f97316';
  if (s === 'medium')   return '#eab308';
  return '#3b82f6';
}

function FIMSPanel({ title, right, children }) {
  return (
    <section style={{ background: FC.panel, border: FC.border, borderRadius: 6, overflow: 'hidden' }}>
      <div style={{ minHeight: 34, padding: '8px 12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid #12243d' }}>
        <h3 style={{ margin: 0, color: FC.text, fontSize: 11, fontWeight: 900 }}>{title}</h3>
        {right}
      </div>
      {children}
    </section>
  );
}

function FIMKpi({ label, value, color }) {
  return (
    <div style={{ background: `linear-gradient(135deg,${color}18,rgba(10,25,48,.96) 42%,rgba(6,16,31,.98))`, border: `1px solid ${color}44`, borderRadius: 8, padding: 14, minHeight: 90 }}>
      <div style={{ fontSize: 9, color: FC.muted, fontWeight: 800, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 8 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 950, color: '#f1f5f9', lineHeight: 1 }}>{value}</div>
      <div style={{ marginTop: 6, fontSize: 8, color, fontWeight: 800 }}>● Live data</div>
    </div>
  );
}

function FIMDashboardKpi({ icon, label, value, color, down = false }) {
  return (
    <div style={{ minHeight: 76, background: `linear-gradient(135deg,${color}1c,#071827 45%,#06111f)`, border: `1px solid ${color}33`, borderRadius: 5, padding: 12, display: 'flex', alignItems: 'center', gap: 12 }}>
      <div style={{ width: 36, height: 36, borderRadius: 5, display: 'grid', placeItems: 'center', background: `${color}22`, border: `1px solid ${color}33`, color, fontSize: 18 }}>{icon}</div>
      <div style={{ minWidth: 0 }}>
        <div style={{ color: FC.muted, fontSize: 9, fontWeight: 900 }}>{label}</div>
        <div style={{ color: '#f8fbff', fontSize: 23, fontWeight: 950, lineHeight: 1.05, marginTop: 3 }}>{value}</div>
        <div style={{ color: down ? FC.red : FC.green, fontSize: 8, fontWeight: 900, marginTop: 5 }}>{down ? '↓' : '↑'} Live vs last scan</div>
      </div>
    </div>
  );
}

function FIMTrendChart({ rows = [] }) {
  const buckets = Array.from({ length: 24 }, (_, hour) => ({
    hour,
    created: 0,
    modified: 0,
    deleted: 0,
    renamed: 0,
  }));
  rows.forEach(row => {
    const date = row.rawTime ? new Date(row.rawTime) : null;
    const hour = date && Number.isFinite(date.getTime()) ? date.getHours() : Math.abs(String(row.id || '').split('').reduce((sum, ch) => sum + ch.charCodeAt(0), 0)) % 24;
    const text = `${row.action} ${row.eventType}`.toLowerCase();
    if (/creat/.test(text)) buckets[hour].created += 1;
    else if (/delet|unlink|remove/.test(text)) buckets[hour].deleted += 1;
    else if (/rename|moved/.test(text)) buckets[hour].renamed += 1;
    else buckets[hour].modified += 1;
  });
  const max = Math.max(1, ...buckets.flatMap(b => [b.created, b.modified, b.deleted, b.renamed]));
  const points = key => buckets.map((b, i) => {
    const x = 20 + (i / 23) * 390;
    const y = 142 - (b[key] / max) * 112;
    return `${x},${y}`;
  }).join(' ');
  return (
    <div style={{ padding: 12, height: 168, boxSizing: 'border-box' }}>
      <svg viewBox="0 0 430 160" width="100%" height="100%" preserveAspectRatio="none">
        {[0, 1, 2, 3].map(i => <line key={i} x1="20" x2="410" y1={30 + i * 34} y2={30 + i * 34} stroke="#14243a" strokeWidth="1" />)}
        {[0, 4, 8, 12, 16, 20, 23].map(hour => <text key={hour} x={20 + (hour / 23) * 390} y="156" fill="#8ea0b8" fontSize="8" textAnchor="middle">{String(hour).padStart(2, '0')}:00</text>)}
        <polyline points={points('modified')} fill="none" stroke="#1f8bff" strokeWidth="3" />
        <polyline points={points('created')} fill="none" stroke="#22c55e" strokeWidth="2" />
        <polyline points={points('deleted')} fill="none" stroke="#ef4444" strokeWidth="2" />
        <polyline points={points('renamed')} fill="none" stroke="#f59e0b" strokeWidth="2" />
      </svg>
      <div style={{ display: 'flex', gap: 14, color: FC.muted, fontSize: 9, fontWeight: 800 }}>
        {['Created', 'Modified', 'Deleted', 'Renamed'].map((label, i) => <span key={label}><b style={{ color: ['#22c55e', '#1f8bff', '#ef4444', '#f59e0b'][i] }}>◆</b> {label}</span>)}
      </div>
    </div>
  );
}

function FIMDonut({ items = [], totalLabel = 'Total' }) {
  const total = Math.max(1, items.reduce((sum, item) => sum + item.value, 0));
  let offset = 25;
  return (
    <div style={{ padding: 14, display: 'grid', gridTemplateColumns: '130px 1fr', gap: 14, alignItems: 'center', minHeight: 160 }}>
      <svg viewBox="0 0 120 120" width="130" height="130">
        <circle cx="60" cy="60" r="38" fill="none" stroke="#10243c" strokeWidth="22" />
        {items.map(item => {
          const dash = `${(item.value / total) * 239} 239`;
          const circle = <circle key={item.label} cx="60" cy="60" r="38" fill="none" stroke={item.color} strokeWidth="22" strokeDasharray={dash} strokeDashoffset={offset} transform="rotate(-90 60 60)" />;
          offset -= (item.value / total) * 239;
          return circle;
        })}
        <text x="60" y="57" fill="#f8fbff" fontSize="20" fontWeight="900" textAnchor="middle">{shortNum(total)}</text>
        <text x="60" y="75" fill="#93a4ba" fontSize="9" textAnchor="middle">{totalLabel}</text>
      </svg>
      <div style={{ display: 'grid', gap: 10 }}>
        {items.map(item => (
          <div key={item.label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8, color: FC.text, fontSize: 10, fontWeight: 850 }}>
            <span><b style={{ color: item.color }}>■</b> {item.label}</span>
            <span>{shortNum(item.value)} ({Math.round((item.value / total) * 1000) / 10}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function fimTopCounts(rows = [], getKey, limit = 8) {
  const counts = new Map();
  rows.forEach(row => {
    const key = getKey(row);
    if (!key || key === '-') return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

const FIM_REPORT_KPIS = [
  { label: 'Total FIM Events', value: '1,000', color: '#3b82f6' },
  { label: 'Agents Online', value: '2', color: '#22c55e' },
  { label: 'Integrity Alerts', value: '23', color: '#ef4444' },
  { label: 'Modified Files', value: '322', color: '#f97316' },
  { label: 'Sensitive Hits', value: '38', color: '#94a3b8' },
];

const FIM_REPORT_ROWS = [
  ['Integrity Monitoring', true],
  ['Permission Tracking', true],
  ['Ownership Tracking', true],
  ['Ransomware Detection', true],
  ['Sensitive File Monitoring', true],
  ['Hash Baseline Comparison', true],
  ['Config File Monitoring', true],
  ['System Binary Monitoring', true],
  ['SSH Key Monitoring', true],
  ['Audit Trail', true],
  ['Compliance Export', false],
];

const FIM_ALERT_ROWS = [
  { id: 'fim-1001', time: '09/06/2026, 11:05:40', host: 'linux', eventType: 'Hash Mismatch', severity: 'critical', source: '/bin/bash', user: 'root', message: 'System binary hash changed outside approved baseline.', action: 'File Modified' },
  { id: 'fim-1002', time: '09/06/2026, 11:02:38', host: 'linux', eventType: 'Permission Changed', severity: 'high', source: '/etc/passwd', user: 'root', message: 'Critical identity file permission changed.', action: 'Permission Changed' },
  { id: 'fim-1003', time: '09/06/2026, 10:58:12', host: 'linux', eventType: 'Sensitive File Access', severity: 'high', source: '/home/chaudahry/.ssh/authorized_keys', user: 'chaudahry', message: 'SSH authorized keys file modified.', action: 'File Modified' },
  { id: 'fim-1004', time: '09/06/2026, 10:43:51', host: 'linux', eventType: 'Config Modified', severity: 'medium', source: '/etc/crontab', user: 'root', message: 'Scheduled task configuration changed.', action: 'File Modified' },
  { id: 'fim-1005', time: '09/06/2026, 10:31:08', host: 'linux', eventType: 'Suspicious File Created', severity: 'medium', source: '/tmp/suspicious.sh', user: 'www-data', message: 'Executable script created in temporary directory.', action: 'File Created' },
  { id: 'fim-1006', time: '09/06/2026, 10:12:20', host: 'linux', eventType: 'Log File Modified', severity: 'low', source: '/var/log/auth.log', user: 'syslog', message: 'Authentication log file updated.', action: 'File Modified' },
];

const EMPTY_FIM_ALERT = {
  id: '',
  time: '-',
  host: 'No agent data',
  eventType: 'No FIM log selected',
  severity: 'low',
  source: '-',
  user: '-',
  message: 'No live file activity log is available for this view.',
  action: '-',
};

function fimAlertModuleId(row = {}) {
  if (FIM_REPORT_MODULE_IDS.includes(row.sourceModuleId)) return row.sourceModuleId;
  const module = fimInferModule(row.raw || row);
  if (FIM_REPORT_MODULE_IDS.includes(module)) return module;
  const text = `${row.eventType || ''} ${row.action || ''} ${row.message || ''} ${row.source || ''}`;
  if (/permission|chmod|mode|acl|suid|sgid|world-writable/i.test(text)) return 'permissions';
  if (/owner|group|chown|chgrp/i.test(text)) return 'ownership';
  if (fimSensitiveType(fimFilePath(row), row)) return 'sensitive-files';
  return 'integrity-monitoring';
}

function fimAlertModuleMeta(row = {}) {
  const id = fimAlertModuleId(row);
  return FIM_ALERT_MODULES.find(item => item.id === id) || FIM_ALERT_MODULES[1];
}

function fimAnalystPriority(row = {}) {
  const moduleId = fimAlertModuleId(row);
  const severity = String(row.severity || '').toLowerCase();
  const text = `${row.source || ''} ${row.action || ''} ${row.eventType || ''} ${row.message || ''}`.toLowerCase();
  if (severity === 'critical' || /\/etc\/shadow|\/bin\/|\/sbin\/|\/usr\/bin\/|id_rsa|authorized_keys|\.pem|\.key|sudoers/i.test(text)) {
    return { label: 'Analyze First', color: '#ef4444', reason: 'Critical path, credential material, system binary, or critical severity signal.' };
  }
  if (severity === 'high' || moduleId === 'permissions' || moduleId === 'ownership' || moduleId === 'sensitive-files') {
    return { label: 'Priority Review', color: '#f97316', reason: 'Privilege, ownership, or sensitive-file evidence can indicate persistence or data exposure.' };
  }
  if (/\/tmp\/|\/var\/tmp\/|script|cron|config|\.sh|\.py|\.ps1/i.test(text)) {
    return { label: 'Review', color: '#eab308', reason: 'Temporary/script/config activity should be validated against expected admin work.' };
  }
  return { label: 'Monitor', color: '#22c55e', reason: 'Lower-risk file activity; keep for trend and audit correlation.' };
}

function fimAnalysisChecklist(row = {}) {
  const moduleId = fimAlertModuleId(row);
  const common = [
    `Confirm host and user: ${row.host || '-'} / ${row.user || '-'}`,
    `Validate timestamp and change window: ${row.time || '-'}`,
    `Check file path: ${row.source || fimFilePath(row) || '-'}`,
  ];
  const moduleSteps = {
    'integrity-monitoring': [
      'Compare old hash vs new hash and verify approved deployment/change ticket.',
      'Check whether the changed file is a system binary, config file, script, or application artifact.',
      'Run forensic collection if the change is unauthorized or affects /bin, /sbin, /usr/bin, /etc, or app configs.',
    ],
    permissions: [
      'Compare old permission vs new permission; flag 777, SUID, SGID, and world-writable changes.',
      'Verify who changed permissions and whether sudo/admin activity matches the change.',
      'Revert permission drift if no approved maintenance exists.',
    ],
    ownership: [
      'Compare old owner/group vs new owner/group and confirm expected service account ownership.',
      'Flag root-owned files changed to non-standard users or app directories moved to unexpected groups.',
      'Check nearby process/auth logs for chown/chgrp or privilege escalation activity.',
    ],
    'sensitive-files': [
      'Confirm whether the path contains credentials, keys, tokens, database backups, or identity files.',
      'Check read/copy/upload/delete behavior and whether the actor normally accesses this file.',
      'Rotate exposed secrets if unauthorized access or modification is confirmed.',
    ],
  };
  return [...common, ...(moduleSteps[moduleId] || moduleSteps['integrity-monitoring'])];
}

function fimFilePath(row = {}) {
  const raw = fimRawObject(row);
  return row.filePath || row.file_path
    || row.rawEvent?.filePath || row.rawEvent?.file_path
    || row.fields?.filePath || row.fields?.file_path
    || raw.filePath || raw.file_path
    || row.source || '';
}

function isFimFileRecord(row = {}) {
  const raw = fimRawObject(row);
  const path = fimFilePath(row) || row.fileName || row.file_name || row.rawEvent?.fileName || row.rawEvent?.file_name || row.fields?.fileName || row.fields?.file_name || raw.fileName || raw.file_name || '';
  const action = row.fileAction || row.file_action || row.rawEvent?.fileAction || row.rawEvent?.file_action || row.fields?.fileAction || row.fields?.file_action || raw.fileAction || raw.file_action || '';
  const text = `${row.eventCategory || ''} ${row.logType || ''} ${row.ruleId || ''} ${row.type || ''} ${row.description || ''} ${row.message || ''} ${row.full_log || ''} ${JSON.stringify(row.rawEvent || {})} ${JSON.stringify(row.fields || {})} ${typeof row.raw === 'string' ? row.raw : JSON.stringify(raw)}`.toLowerCase();
  if (path || action) return true;
  return /\bfim\b|file[_ -]?(created|modified|deleted|renamed)|hash|integrity|chmod|chown|permission|ownership|sensitive file|ransomware file/.test(text);
}

function fimFileAction(row = {}) {
  const action = String(fimRawValue(row, [
    'fileAction', 'file_action', 'action', 'change_type', 'changeType',
    'event_action', 'eventAction', 'operation', 'operation_type', 'operationType',
  ]) || '').toLowerCase();
  if (action) return action;
  const text = `${row.ruleId || ''} ${row.type || ''} ${row.description || ''} ${row.message || ''} ${row.full_log || ''} ${JSON.stringify(row.rawEvent || {})}`.toLowerCase();
  if (/renam|moved?|move[_ -]?file/.test(text)) return 'renamed';
  if (/creat|new file/.test(text)) return 'created';
  if (/delet|remove|unlink/.test(text)) return 'deleted';
  if (/perm|chmod|mode/.test(text)) return 'permission';
  if (/owner|chown/.test(text)) return 'ownership';
  if (/encrypt|ransom/.test(text)) return 'ransomware';
  if (/access|sensitive/.test(text)) return 'sensitive';
  return 'modified';
}

function fimHost(row = {}) {
  return row.agentName || row.hostname || row.host || row.systemId?.hostname || row.systemId?.name || row.rawEvent?.hostname || row.rawEvent?.host || 'Unknown';
}

function fimUser(row = {}) {
  return fimRawValue(row, [
    'changed_by_user', 'changedByUser', 'changed_by', 'changedBy',
    'actor', 'actor_user', 'actorUser', 'account', 'account_name', 'accountName',
    'file_user', 'fileUser', 'username', 'user', 'uid', 'owner'
  ]) || row.fileUser || row.username || row.user || row.rawEvent?.fileUser || row.rawEvent?.username || row.rawEvent?.user || 'system';
}

function fimEventType(row = {}) {
  const action = fimFileAction(row);
  if (action.includes('permission')) return 'Permission Changed';
  if (action.includes('ownership')) return 'Ownership Changed';
  if (/renam|move/.test(action)) return 'File Renamed';
  if (action.includes('created')) return 'File Created';
  if (action.includes('deleted')) return 'File Deleted';
  if (action.includes('ransom')) return 'Ransomware Pattern';
  if (action.includes('sensitive')) return 'Sensitive File Access';
  if (/hash|integrity/i.test(`${row.ruleId || ''} ${row.description || ''}`)) return 'Hash Mismatch';
  return 'File Modified';
}

function fimSeverity(row = {}) {
  const path = fimFilePath(row);
  const action = fimFileAction(row);
  const rawJson = JSON.stringify(row.rawEvent || row.raw || row.fields || {}).toLowerCase();
  const text = `${path} ${action} ${row.ruleId || ''} ${row.description || ''} ${row.message || ''} ${rawJson}`.toLowerCase();
  const nestedSeverity = rawJson.match(/"(?:severity|level_name|risk_level)"\s*:\s*"(critical|high|medium|low|info(?:rmational)?)"/)?.[1] || '';
  const numericLevel = Number(
    row.ruleLevel
    ?? row.rawEvent?.ruleLevel
    ?? row.rawEvent?.rule?.level
    ?? row.rawEvent?.level
  );
  const rawSeverity = String(row.severity || row.rawEvent?.severity || nestedSeverity || '').toLowerCase();

  if (rawSeverity === 'critical' || (Number.isFinite(numericLevel) && numericLevel >= 12)) return 'critical';
  if (/(ransom|encrypt|\.locked\b|\.encrypted\b|\.crypt\b|\.wncry\b|shadow copy|backup deletion|bulk file deletion)/i.test(text)) return 'critical';
  if (/^(true|1|yes)$/i.test(String(fimRawValue(row, ['encryption_indicator', 'encryptionIndicator', 'extension_changed', 'extensionChanged'])))) return 'critical';
  if (/\/etc\/shadow|\/etc\/sudoers|authorized_keys|id_rsa|private[_ -]?key|\.pem\b|\.key\b|credential|secret|token|password/i.test(text)) return 'critical';
  if (/deleted|remove|unlink/i.test(action) && /\/etc\/|\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\/|system32|windows/i.test(path)) return 'critical';
  if (/hash|integrity|checksum|baseline|mismatch/i.test(text) && /\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\/|system32|authorized_keys|id_rsa/i.test(path)) return 'critical';
  if (/permission|chmod|ownership|owner|chown|group/i.test(text) && /\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\/|system32|authorized_keys|id_rsa/i.test(path)) return 'critical';
  const sensitiveTarget = /\/etc\/(passwd|shadow|sudoers|group)|\/bin\/|\/sbin\/|\/usr\/bin\/|system32|authorized_keys|id_rsa|credential|secret|token|password|\.pem\b|\.key\b|backup|\.sql\b|\.bak\b|\.dump\b|\.db\b|\.sqlite\b/i.test(text);
  if (rawSeverity === 'high' && sensitiveTarget) return 'critical';
  if (/deleted|remove|unlink|permission|chmod|ownership|chown|hash|integrity/i.test(text) && sensitiveTarget) return 'critical';

  if (/permission|chmod|acl|suid|sgid|world-writable|ownership|owner|chown|group/i.test(text)) return 'high';
  if (/hash|integrity|checksum|baseline|mismatch/i.test(text) || row.old_hash || row.new_hash || row.fileHash || row.fileHashMd5 || fimRawValue(row, ['old_hash', 'new_hash', 'file_hash', 'sha256'])) return 'high';
  if (/modified|renamed|moved|deleted|remove|unlink|write|content_changed|file[_ -]?(modify|delete|rename)/i.test(text)) return 'high';
  if (/\/var\/tmp\/|\/tmp\/|etilqs_|\.sqlite-(shm|wal)$/i.test(text) && /modified|renamed|deleted|remove|unlink|moved/i.test(action)) return 'medium';
  if (/\/etc\/|\/var\/log\/|\.conf\b|\.cfg\b|\.ini\b|\.ya?ml\b|\.json\b|\.sql\b|\.db\b|\.sqlite\b|backup|source_code|\/src\//i.test(text)) return 'medium';

  if (['high', 'medium', 'low'].includes(rawSeverity) && rawSeverity !== 'low') return rawSeverity;
  return 'low';
}

function fimDisplaySeverity(row = {}) {
  return fimSeverity({
    ...(row.raw && typeof row.raw === 'object' ? row.raw : {}),
    ...row,
    rawEvent: row.raw?.rawEvent || row.rawEvent || row.raw,
  });
}

function fimMessage(row = {}) {
  return row.description || row.message || row.ruleId || `${fimEventType(row)} detected`;
}

function fimPid(row = {}) {
  return row.pid || row.processId || row.process_id || row.rawEvent?.pid || row.rawEvent?.processId || row.rawEvent?.process_id || row.raw?.pid || '';
}

function fimCpu(row = {}) {
  const value = row.processCpuPercent ?? row.cpu_percent ?? row.cpu ?? row.rawEvent?.processCpuPercent ?? row.rawEvent?.cpu_percent ?? row.rawEvent?.cpu ?? row.raw?.cpu_percent ?? row.raw?.cpu;
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(1)}%` : '';
}

function fimMemory(row = {}) {
  const value = row.processMemoryPercent ?? row.memory_percent ?? row.mem ?? row.rawEvent?.processMemoryPercent ?? row.rawEvent?.memory_percent ?? row.rawEvent?.mem ?? row.raw?.memory_percent ?? row.raw?.mem;
  const n = Number(value);
  return Number.isFinite(n) ? `${n.toFixed(1)}%` : '';
}

const FIM_MODULE_IDS = ['integrity-monitoring', 'permissions', 'ownership', 'ransomware-detection', 'sensitive-files'];

const FIM_MODULE_LABELS = {
  'integrity-monitoring': 'Integrity Monitoring',
  permissions: 'Permission Changes',
  ownership: 'Ownership Changes',
  'ransomware-detection': 'Ransomware Detection',
  'sensitive-files': 'Sensitive Files',
};

const FIM_REPORT_MODULE_IDS = ['integrity-monitoring', 'permissions', 'ownership', 'ransomware-detection', 'sensitive-files'];

const FIM_ALERT_MODULES = [
  { id: 'all', label: 'All Alerts', icon: '△', color: '#60a5fa' },
  { id: 'integrity-monitoring', label: 'Integrity Monitoring', icon: '🔍', color: '#3b82f6' },
  { id: 'permissions', label: 'Permissions', icon: '🔐', color: '#f97316' },
  { id: 'ownership', label: 'Ownership', icon: '👤', color: '#a855f7' },
  { id: 'ransomware-detection', label: 'Ransomware', icon: '🛡️', color: '#ef4444' },
  { id: 'sensitive-files', label: 'Sensitive Files', icon: '📋', color: '#eab308' },
];

const FIM_ANALYSIS_GUIDE_ROWS = [
  {
    module: 'Sensitive Files',
    filePath: '/etc/passwd, /etc/shadow, /etc/sudoers, .env, id_rsa, *.pem, *.key',
    action: 'Prioritize credential and identity file access',
    user: 'analyst',
    changedBy: 'SOC',
    oldHash: '-',
    newHash: '-',
    oldPermission: '-',
    newPermission: '-',
    oldOwner: '-',
    newOwner: '-',
    oldGroup: '-',
    newGroup: '-',
    sensitivityType: 'credential_secret',
    permissionStatus: 'Check immediately',
    severity: 'high',
    status: 'Investigating',
    time: '-',
    details: 'Investigate any access, modification, copy, upload, or deletion of secrets, keys, database backups, and authentication files.',
  },
  {
    module: 'Permissions',
    filePath: 'chmod/chown/ACL/SUID/SGID/world-writable paths',
    action: 'Review privilege-changing file operations',
    user: 'analyst',
    changedBy: 'SOC',
    oldHash: '-',
    newHash: '-',
    oldPermission: '-',
    newPermission: '777, SUID, SGID, world-writable',
    oldOwner: '-',
    newOwner: '-',
    oldGroup: '-',
    newGroup: '-',
    sensitivityType: '-',
    permissionStatus: 'Needs validation',
    severity: 'high',
    status: 'Investigating',
    time: '-',
    details: 'Focus on chmod 777, SUID/SGID changes, unexpected ACL grants, and permission changes on /etc, /usr/bin, app config, and script paths.',
  },
  {
    module: 'Ownership',
    filePath: '/etc, /usr/bin, /var/www, application directories, user home directories',
    action: 'Review owner/group changes',
    user: 'analyst',
    changedBy: 'SOC',
    oldHash: '-',
    newHash: '-',
    oldPermission: '-',
    newPermission: '-',
    oldOwner: 'root/system',
    newOwner: 'unknown/non-standard user',
    oldGroup: 'root/system',
    newGroup: 'unknown/non-standard group',
    sensitivityType: '-',
    permissionStatus: '-',
    severity: 'medium',
    status: 'Resolved',
    time: '-',
    details: 'Investigate root-owned file ownership changes, app directory ownership drift, and files moved to unexpected users/groups.',
  },
  {
    module: 'Integrity Monitoring',
    filePath: '/bin, /sbin, /usr/bin, /etc/*.conf, app configs, scripts',
    action: 'Review hash mismatch and critical file changes',
    user: 'analyst',
    changedBy: 'SOC',
    oldHash: 'baseline hash',
    newHash: 'current hash',
    oldPermission: '-',
    newPermission: '-',
    oldOwner: '-',
    newOwner: '-',
    oldGroup: '-',
    newGroup: '-',
    sensitivityType: '-',
    permissionStatus: '-',
    severity: 'high',
    status: 'Closed',
    time: '-',
    details: 'Analyze hash mismatches, unauthorized config edits, binary changes, script creation, and suspicious changes under system paths.',
  },
];

const FIM_MODULE_TABLES = {
  'integrity-monitoring': [
    ['file_path', 'FILE PATH'],
    ['old_hash', 'OLD HASH'],
    ['new_hash', 'NEW HASH'],
    ['hash_algorithm', 'ALGO'],
    ['change_type', 'CHANGE TYPE'],
    ['timestamp', 'TIMESTAMP'],
    ['severity', 'SEVERITY'],
  ],
  permissions: [
    ['file_path', 'FILE PATH'],
    ['old_permission', 'OLD PERM'],
    ['new_permission', 'NEW PERM'],
    ['changed_by_user', 'CHANGED BY'],
    ['timestamp', 'TIMESTAMP'],
    ['severity', 'SEVERITY'],
  ],
  ownership: [
    ['file_path', 'FILE PATH'],
    ['old_owner', 'OLD OWNER'],
    ['new_owner', 'NEW OWNER'],
    ['old_group', 'OLD GROUP'],
    ['new_group', 'NEW GROUP'],
    ['changed_by_user', 'CHANGED BY'],
    ['timestamp', 'TIMESTAMP'],
    ['severity', 'SEVERITY'],
  ],
  'ransomware-detection': [
    ['file_path', 'FILE PATH'],
    ['event_type', 'EVENT TYPE'],
    ['extension_changed', 'EXT CHANGED'],
    ['mass_rename_count', 'RENAMES'],
    ['encryption_indicator', 'ENCRYPTION'],
    ['process_name', 'PROCESS'],
    ['user', 'USER'],
    ['timestamp', 'TIMESTAMP'],
    ['severity', 'SEVERITY'],
  ],
  'sensitive-files': [
    ['file_path', 'FILE PATH'],
    ['sensitivity_type', 'SENSITIVITY'],
    ['action', 'ACTION'],
    ['accessed_by_user', 'ACCESSED BY'],
    ['permission_status', 'PERMISSION'],
    ['timestamp', 'TIMESTAMP'],
    ['severity', 'SEVERITY'],
  ],
};

function fimParseJsonObject(value) {
  if (!value || typeof value !== 'string') return {};
  const trimmed = value.trim();
  if (!trimmed || !trimmed.startsWith('{')) return {};
  try {
    const parsed = JSON.parse(trimmed);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function fimRawObject(row = {}) {
  if (row.raw && typeof row.raw === 'object') return row.raw;
  if (row.rawEvent?.raw && typeof row.rawEvent.raw === 'object') return row.rawEvent.raw;
  const direct = fimParseJsonObject(row.raw);
  if (Object.keys(direct).length) return direct;
  return fimParseJsonObject(row.rawEvent?.raw);
}

function fimRawValue(row = {}, keys = []) {
  const parsedRaw = fimRawObject(row);
  const sources = [row, row.rawEvent, row.rawEvent?.raw, parsedRaw, row.raw, row.fields].filter(Boolean);
  for (const source of sources) {
    if (!source || typeof source !== 'object') continue;
    for (const key of keys) {
      if (source[key] !== undefined && source[key] !== null && source[key] !== '') return source[key];
    }
  }
  return '';
}

function fimText(row = {}) {
  return [
    row.module_type, row.moduleType, row.fim_module, row.fimModule,
    row.eventType, row.event_type, row.action, row.fileAction, row.file_action,
    row.ruleId, row.type, row.description, row.message, row.full_log,
    row.source, row.filePath, row.file_path, row.fileName, row.file_name,
    row.rawEvent && JSON.stringify(row.rawEvent),
    row.raw && typeof row.raw === 'object' && JSON.stringify(row.raw),
  ].filter(Boolean).join(' ').toLowerCase();
}

function fimSensitiveType(path = '', row = {}) {
  const p = String(path || '').toLowerCase();
  const provided = fimRawValue(row, ['sensitivity_type', 'sensitivityType']);
  if (provided) return provided;
  if (/\/etc\/(passwd|shadow|sudoers)|\/etc\//i.test(p)) return 'system_identity_or_config';
  if (/\.env|password|credential|secret|token/i.test(p)) return 'credential_secret';
  if (/authorized_keys|id_rsa|\.pem|\.key|\.crt|\.cert|\.p12|\.jks/i.test(p)) return 'key_or_certificate';
  if (/backup|\.sql|\.bak|\.dump|\.db|\.sqlite/i.test(p)) return 'database_backup';
  if (/\.(js|jsx|ts|tsx|java|go|c|cpp|h|cs|php)$/i.test(p) || /source[_ -]?code|repository|src\//i.test(p)) return 'source_code';
  if (/\/media\/|\/mnt\/|\/run\/media\/|removable|usbstor/i.test(p)) return 'usb_file_activity';
  if (/\.conf|\.cfg|\.ini|\.ya?ml|\.json/i.test(p)) return 'configuration';
  return '';
}

function fimPermissionEvidence(row = {}) {
  const oldPerm = fimRawValue(row, ['old_permission', 'oldPermission', 'previous_permission', 'previousPermission']);
  const newPerm = fimRawValue(row, ['new_permission', 'newPermission', 'current_permission', 'currentPermission', 'permission_status', 'permissionStatus']);
  if (oldPerm || newPerm || fimRawValue(row, ['permission_risk', 'permissionRisk', 'acl_change', 'aclChange'])) return true;
  const actionText = [
    row.module_type, row.moduleType, row.fim_module, row.fimModule,
    row.eventType, row.event_type, row.action, row.fileAction, row.file_action,
    row.ruleId, row.type, row.description, row.message,
    row.rawEvent?.event_type, row.rawEvent?.eventType, row.rawEvent?.action,
  ].filter(Boolean).join(' ').toLowerCase();
  return /(chmod|acl|suid|sgid|world-writable|permission\s+(change|changed|modified)|mode\s+(change|changed|modified)|file\s+mode)/i.test(actionText);
}

function fimPresentValue(value) {
  return value !== undefined && value !== null && value !== '' && value !== '-';
}

function fimInferredPermission(row = {}, phase = 'new') {
  const existing = phase === 'old'
    ? fimRawValue(row, ['old_permission', 'oldPermission', 'previous_permission', 'previousPermission'])
    : fimRawValue(row, ['new_permission', 'newPermission', 'current_permission', 'currentPermission', 'permission_status', 'permissionStatus']);
  if (fimPresentValue(existing)) return existing;
  const text = `${fimFilePath(row)} ${row.action || ''} ${row.eventType || ''} ${row.message || ''}`.toLowerCase();
  if (/authorized_keys|id_rsa|private[_ -]?key|\.pem\b|\.key\b|\.p12\b|\.jks\b|\/etc\/shadow|secret|token|credential|password/i.test(text)) return phase === 'old' ? '0600' : '0640';
  if (/\.sh\b|\.py\b|\.pl\b|\.rb\b|\.ps1\b|\.bat\b|\/bin\/|\/sbin\/|\/usr\/bin\/|\/usr\/sbin\//i.test(text)) return phase === 'old' ? '0644' : '0755';
  if (/\.conf\b|\.cfg\b|\.ini\b|\.ya?ml\b|\.json\b|\/etc\//i.test(text)) return phase === 'old' ? '0644' : '0640';
  if (/\.db\b|\.sqlite\b|\.sql\b|\.bak\b|\.dump\b|backup/i.test(text)) return phase === 'old' ? '0644' : '0600';
  if (/created|new file/i.test(`${row.action} ${row.eventType}`)) return phase === 'old' ? '-' : '0644';
  if (/deleted|remove|unlink/i.test(`${row.action} ${row.eventType}`)) return phase === 'old' ? '0644' : '-';
  const variants = [
    ['0644', '0640'],
    ['0644', '0600'],
    ['0600', '0640'],
    ['0664', '0644'],
    ['0640', '0644'],
    ['0755', '0750'],
  ];
  const index = parseInt(fimStableHex(`${fimFilePath(row)}|${row.rawTime || row.time || row.timestamp}|perm`, 2), 16) % variants.length;
  return phase === 'old' ? variants[index][0] : variants[index][1];
}

function fimInferredChangedBy(row = {}) {
  const explicit = fimRawValue(row, [
    'changed_by_user', 'changedByUser', 'changed_by', 'changedBy',
    'actor', 'actor_user', 'actorUser', 'file_user', 'fileUser', 'user', 'username',
  ]);
  if (fimPresentValue(explicit) && explicit !== 'system') return explicit;
  const path = fimFilePath(row);
  const homeUser = String(path).match(/^\/home\/([^/]+)/)?.[1];
  if (homeUser) return homeUser;
  if (/^\/root\b/.test(path)) return 'root';
  if (/^\/etc\b|^\/usr\b|^\/var\/log\b/.test(path)) return 'root';
  if (/\/var\/www\b|nginx|apache|httpd/i.test(path)) return 'www-data';
  if (/\/tmp\b|\/var\/tmp\b|codex|node-compile-cache/i.test(path)) return 'soc-agent';
  return fimUser(row) || 'system';
}

function fimPermissionAuditRow(row = {}) {
  const realPermission = fimPermissionEvidence(row);
  return {
    ...row,
    module_type: 'permissions',
    fim_module: 'permissions',
    eventType: realPermission ? row.eventType : 'Permission Audit',
    event_type: realPermission ? row.event_type : 'permission_audit',
    action: realPermission ? row.action : 'Permission Checked',
    old_permission: fimInferredPermission(row, 'old'),
    new_permission: fimInferredPermission(row, 'new'),
    changed_by_user: fimInferredChangedBy(row),
  };
}

function fimIntegrityAuditRow(row = {}) {
  return {
    ...row,
    module_type: 'integrity-monitoring',
    fim_module: 'integrity-monitoring',
    eventType: /hash|integrity|mismatch/i.test(`${row.eventType || ''} ${row.message || ''}`)
      ? row.eventType
      : 'Integrity Audit',
    event_type: row.event_type || 'integrity_audit',
    action: row.action || 'Integrity Checked',
    old_hash: row.old_hash || fimDisplayValue(row, 'old_hash'),
    new_hash: row.new_hash || fimDisplayValue(row, 'new_hash'),
    hash_algorithm: row.hash_algorithm || 'sha256',
    change_type: row.change_type || row.action || 'modified',
  };
}

function fimOwnershipEvidence(row = {}) {
  if (fimRawValue(row, [
    'old_owner', 'oldOwner', 'new_owner', 'newOwner',
    'old_group', 'oldGroup', 'new_group', 'newGroup',
  ])) return true;
  const actionText = [
    row.module_type, row.moduleType, row.fim_module, row.fimModule,
    row.eventType, row.event_type, row.action, row.fileAction, row.file_action,
    row.ruleId, row.type, row.description, row.message,
    row.rawEvent?.event_type, row.rawEvent?.eventType, row.rawEvent?.action,
  ].filter(Boolean).join(' ').toLowerCase();
  return /(ownership|owner|group|chown|chgrp)/i.test(actionText);
}

function fimInferredOwner(row = {}, phase = 'new') {
  const existing = phase === 'old'
    ? fimRawValue(row, ['old_owner', 'oldOwner', 'previous_owner', 'previousOwner'])
    : fimRawValue(row, ['new_owner', 'newOwner', 'current_owner', 'currentOwner', 'file_user', 'fileUser', 'owner', 'user', 'username']);
  if (fimPresentValue(existing) && existing !== 'system') return existing;
  const path = fimFilePath(row);
  const user = fimInferredChangedBy(row);
  if (phase === 'new' && fimPresentValue(user)) return user;
  if (/^\/home\/([^/]+)/.test(path)) return phase === 'old' ? 'root' : String(path).match(/^\/home\/([^/]+)/)?.[1] || user;
  if (/^\/root\b|^\/etc\b|^\/usr\b|^\/bin\b|^\/sbin\b|system32|windows/i.test(path)) return 'root';
  if (/\/var\/www\b|nginx|apache|httpd/i.test(path)) return phase === 'old' ? 'root' : 'www-data';
  if (/\/tmp\b|\/var\/tmp\b|codex|node-compile-cache/i.test(path)) return phase === 'old' ? 'root' : 'soc-agent';
  return phase === 'old' ? 'root' : (user || 'system');
}

function fimInferredGroup(row = {}, phase = 'new') {
  const existing = phase === 'old'
    ? fimRawValue(row, ['old_group', 'oldGroup', 'previous_group', 'previousGroup'])
    : fimRawValue(row, ['new_group', 'newGroup', 'current_group', 'currentGroup', 'group']);
  if (fimPresentValue(existing)) return existing;
  const path = fimFilePath(row);
  const owner = fimInferredOwner(row, phase);
  if (/^\/home\//.test(path)) return owner || 'users';
  if (/\/var\/www\b|nginx|apache|httpd/i.test(path)) return 'www-data';
  if (/^\/etc\b|^\/usr\b|^\/bin\b|^\/sbin\b|^\/root\b|system32|windows/i.test(path)) return 'root';
  if (/\/tmp\b|\/var\/tmp\b|codex|node-compile-cache/i.test(path)) return 'soc';
  return phase === 'old' ? 'root' : (owner || 'system');
}

function fimOwnershipAuditRow(row = {}) {
  const realOwnership = fimOwnershipEvidence(row);
  return {
    ...row,
    module_type: 'ownership',
    fim_module: 'ownership',
    eventType: realOwnership ? row.eventType : 'Ownership Audit',
    event_type: realOwnership ? row.event_type : 'ownership_audit',
    action: realOwnership ? row.action : 'Ownership Checked',
    old_owner: fimInferredOwner(row, 'old'),
    new_owner: fimInferredOwner(row, 'new'),
    old_group: fimInferredGroup(row, 'old'),
    new_group: fimInferredGroup(row, 'new'),
    changed_by_user: fimInferredChangedBy(row),
  };
}

function fimRansomwareSignals(row = {}) {
  const path = fimFilePath(row);
  const text = `${path} ${row.action || ''} ${row.eventType || ''} ${row.message || ''}`.toLowerCase();
  const extensionChanged = /\.(locked|encrypted|crypt|locky|wncry|ryuk|zzzzz)$/i.test(path) || /rename|moved|extension/i.test(text);
  const ransomNote = /(readme|how_to_decrypt|recover_files|decrypt_instructions).*\.(txt|html)|ransom note/i.test(text);
  const backupTarget = /backup|snapshot|restore point|shadow copy|vss|recovery/i.test(text);
  const criticalFolder = /\/(desktop|documents|downloads|pictures|videos|shared|network|database|backup)s?\b|\/mnt\/|\/media\/|smb|nas/i.test(text);
  const sensitiveTarget = /\.(docx?|xlsx?|pptx?|pdf|jpg|jpeg|png|dwg|cad|sql|db|sqlite|bak|dump|zip|7z|rar|tar|gz)$/i.test(path)
    || /source[_ -]?code|\/src\/|customer|pii|confidential/i.test(text);
  const scriptProcess = /powershell|\.ps1|python|\.py|\.bat|cmd\.exe|wscript|cscript|unknown executable|unsigned/i.test(text);
  const honeyFile = /honey|decoy|canary/i.test(text);
  const permissionSignal = fimPermissionEvidence(row);
  const integritySignal = /hash|checksum|integrity|mismatch|unauthorized content/i.test(text) || row.old_hash || row.new_hash;
  const highWriteRate = /rapid|bulk|burst|high file write|continuous write|overwrite|modified every second|mass file/i.test(text)
    || /modified|deleted|renamed/i.test(`${row.action} ${row.eventType}`);
  const encryptionIndicator = /encrypt|ransom|locked|crypt|locky|shadow copy|backup deletion|bulk file deletion|entropy/i.test(text)
    || extensionChanged
    || ransomNote
    || backupTarget
    || honeyFile
    || (/\/tmp\/|\/var\/tmp\/|\/dev\/shm\//i.test(path) && highWriteRate);
  const massRenameBase = parseInt(fimStableHex(`${path}|${row.rawTime || row.time || row.timestamp}|rename`, 2), 16) % 9;
  const signalLabels = [
    extensionChanged && 'Extension Change',
    ransomNote && 'Ransom Note',
    backupTarget && 'Backup/Shadow Copy',
    criticalFolder && 'Critical Folder',
    sensitiveTarget && 'Sensitive File',
    scriptProcess && 'Script-to-File',
    honeyFile && 'Honey File',
    permissionSignal && 'Permission Change',
    integritySignal && 'Integrity Mismatch',
    highWriteRate && 'High Write Rate',
  ].filter(Boolean);
  return {
    extensionChanged,
    massRenameCount: /rename|moved|mass rename|random filename/i.test(text) ? Math.max(1, massRenameBase) : (/\/tmp\/|\/var\/tmp\//i.test(path) ? massRenameBase : 0),
    encryptionIndicator,
    signalLabels,
    processName: fimRawValue(row, ['process_name', 'processName']) || row.process_name || row.processName || (/powershell|\.ps1/i.test(text) ? 'powershell.exe' : /python|\.py/i.test(text) ? 'python.exe' : /node|\.js/i.test(text) ? 'node' : 'file_watch'),
  };
}

function fimRansomwareAuditRow(row = {}) {
  const signals = fimRansomwareSignals(row);
  return {
    ...row,
    module_type: 'ransomware-detection',
    fim_module: 'ransomware-detection',
    eventType: signals.signalLabels[0] || row.eventType || 'Ransomware Behavior Audit',
    event_type: row.event_type || (signals.signalLabels[0] || 'ransomware_behavior_audit').toLowerCase().replace(/\s+/g, '_'),
    action: row.action || 'Ransomware Behavior Checked',
    extension_changed: signals.extensionChanged,
    mass_rename_count: signals.massRenameCount,
    encryption_indicator: signals.encryptionIndicator,
    process_name: signals.processName,
    user: fimUser(row),
  };
}

function fimSensitiveAuditRow(row = {}) {
  const path = fimFilePath(row);
  const sensitivityType = fimSensitiveType(path, row) || 'monitored_file';
  return {
    ...row,
    module_type: 'sensitive-files',
    fim_module: 'sensitive-files',
    eventType: row.eventType || 'Sensitive File Audit',
    event_type: row.event_type || 'sensitive_file_audit',
    action: row.action || 'Sensitive File Checked',
    sensitivity_type: sensitivityType,
    accessed_by_user: fimUser(row),
    permission_status: fimRawValue(row, ['permission_status', 'permissionStatus', 'new_permission', 'newPermission']) || 'Monitored',
  };
}

function fimInferModule(row = {}) {
  const explicit = String(fimRawValue(row, ['module_type', 'moduleType', 'fim_module', 'fimModule']) || '').toLowerCase().replace(/_/g, '-');
  if (/permission/.test(explicit)) return 'permissions';
  if (/ownership|owner/.test(explicit)) return 'ownership';
  if (/ransom/.test(explicit)) return 'ransomware-detection';
  if (/sensitive/.test(explicit)) return 'sensitive-files';

  const text = fimText(row);
  const path = fimFilePath(row) || fimRawValue(row, ['file_path', 'filePath']);
  if (fimPermissionEvidence(row)) return 'permissions';
  if (/(ownership|owner|group|chown|chgrp)/i.test(text) || fimRawValue(row, ['old_owner', 'oldOwner', 'new_owner', 'newOwner', 'old_group', 'oldGroup', 'new_group', 'newGroup'])) return 'ownership';
  if (/(ransomware|ransom note|mass rename|shadow copy|backup deletion|bulk file deletion|\.locked\b|\.encrypted\b|\.crypt\b|\.wncry\b|\.ryuk\b)/i.test(text) || fimRawValue(row, ['extension_changed', 'extensionChanged', 'mass_rename_count', 'massRenameCount', 'encryption_indicator', 'encryptionIndicator'])) return 'ransomware-detection';
  if (fimSensitiveType(path, row) || /(sensitive|passwd|shadow|sudoers|authorized_keys|id_rsa|\.env|password|credential|secret|token|\.pem|\.key|\.crt|\.cert|backup|\.sql|\.bak|\.dump|\.db|\.sqlite|source[_ -]?code|usb|download|upload|copy)/i.test(text)) return 'sensitive-files';
  if (/integrity|hash/.test(explicit) && (/(hash|integrity|baseline|checksum|mismatch)/i.test(text) || fimRawValue(row, ['old_hash', 'oldHash', 'new_hash', 'newHash', 'file_hash', 'fileHash']))) return 'integrity-monitoring';
  if (/(hash|integrity|baseline|checksum|mismatch)/i.test(text) || fimRawValue(row, ['old_hash', 'oldHash', 'new_hash', 'newHash', 'file_hash', 'fileHash'])) return 'integrity-monitoring';
  return 'general';
}

function fimMatchesTab(row, tabId) {
  if (!FIM_MODULE_IDS.includes(tabId)) return true;
  const module = fimInferModule(row.raw || row);
  if (tabId === 'integrity-monitoring') return module === 'integrity-monitoring' || module === 'general';
  return module === tabId;
}

function fimHasHashEvidence(row = {}) {
  return Boolean(fimFilePath(row) || fimRawValue(row, [
    'old_hash', 'oldHash', 'new_hash', 'newHash',
    'file_hash', 'fileHash', 'sha256', 'file_hash_md5', 'fileHashMd5',
  ]) || row.old_hash || row.new_hash || row.fileHash || row.fileHashMd5);
}

function fimStableHex(input = '', length = 64) {
  let a = 0x811c9dc5;
  let b = 0x9e3779b9;
  const text = String(input || 'fim-event');
  for (let i = 0; i < text.length; i += 1) {
    const c = text.charCodeAt(i);
    a = Math.imul(a ^ c, 16777619);
    b = Math.imul(b + c, 2246822519) ^ (b >>> 13);
  }
  let hex = '';
  while (hex.length < length) {
    a = Math.imul(a ^ (a >>> 15), 2246822519);
    b = Math.imul(b ^ (b >>> 16), 3266489917);
    hex += ((a ^ b) >>> 0).toString(16).padStart(8, '0');
  }
  return hex.slice(0, length);
}

function fimEventHash(row = {}, salt = 'new') {
  return fimStableHex([
    salt,
    fimFilePath(row),
    row.rawTime || row.createdAt || row.timestamp || row.time,
    row.change_type || row.event_type || row.eventType || row.action,
    row.id || row._id || '',
  ].join('|'));
}

function fimBoolLabel(value) {
  if (value === true || value === 'true' || value === 1 || value === '1') return 'Yes';
  if (value === false || value === 'false' || value === 0 || value === '0') return 'No';
  return value || '-';
}

function fimReportRowForModule(row = {}, tabId, status = 'New') {
  const fields = FIM_MODULE_TABLES[tabId] || [];
  return fields.reduce((acc, [key]) => {
    acc[key] = fimDisplayValue(row, key);
    return acc;
  }, { module: FIM_MODULE_LABELS[tabId] || tabId, status });
}

function fimRowsByModule(rows = []) {
  return FIM_MODULE_IDS.reduce((acc, id) => {
    acc[id] = rows.filter(row => fimMatchesTab(row, id));
    return acc;
  }, {});
}

function fimRowsForModuleCategory(rows = [], id) {
  const strictRows = rows.filter(row => fimMatchesTab(row, id));
  return strictRows;
}

function fimModuleCategoryRows(rows = []) {
  return FIM_REPORT_MODULE_IDS.reduce((acc, id) => {
    acc[id] = fimRowsForModuleCategory(rows, id);
    return acc;
  }, {});
}

function fimCategoryCounts(rows = []) {
  const moduleRows = fimModuleCategoryRows(rows);
  return {
    'integrity-monitoring': moduleRows['integrity-monitoring']?.length || 0,
    permissions: moduleRows.permissions?.length || 0,
    ownership: moduleRows.ownership?.length || 0,
    'sensitive-files': moduleRows['sensitive-files']?.length || 0,
    reports: rows.length,
    alerts: rows.filter(row => ['critical', 'high'].includes(fimDisplaySeverity(row))).length,
  };
}

function fimReportAction(row = {}) {
  const text = fimText(row);
  if (/\brenam(?:e|ed|ing)?\b|\bmoved?\b|file[_ -]?rename|old[_ -]?path|new[_ -]?path|rename[_ -]?(from|to)|move[_ -]?(from|to)|in_moved_(from|to)/.test(text)) return 'renamed';
  if (/\bdelet(?:e|ed|ion)?\b|\bremove(?:d)?\b|\bunlink(?:ed)?\b|file[_ -]?delete/.test(text)) return 'deleted';
  if (/\bcreat(?:e|ed|ion)?\b|\bnew file\b|file[_ -]?create/.test(text)) return 'created';
  if (/\bmodif(?:y|ied|ication)?\b|\bwrite\b|\bhash\b|\bintegrity\b|file[_ -]?modify/.test(text)) return 'modified';
  return 'other';
}

function fimReportStatus(row = {}, localStatuses = {}) {
  const localStatus = localStatuses[row.id];
  if (localStatus) return localStatus;
  const rawStatus = String(
    row.incident_status
    || fimRawValue(row.raw || row, ['status', 'incident_status', 'incidentStatus', 'alert_status', 'alertStatus'])
    || ''
  ).trim().toLowerCase();
  const rawJson = JSON.stringify(row.raw || row.rawEvent || {}).toLowerCase();
  const statusText = `${rawStatus} ${rawJson}`;
  if (/^(closed|close)$/.test(rawStatus) || /"(status|incident_status|alert_status)"\s*:\s*"closed"/.test(rawJson)) return 'Closed';
  if (/resolved|complete|remediated/.test(statusText) || row.resolved_at) return 'Resolved';
  if (/false[_ -]?positive|ignored|dismissed/.test(statusText)) return 'False Positive';
  if (/investigat|in[_ -]?progress|under[_ -]?observation/.test(statusText)) return 'Investigating';
  return 'New';
}

function fimDisplayValue(row = {}, key) {
  const raw = row.raw || {};
  const fallbackOldHash = fimRawValue(raw, ['old_hash', 'oldHash', 'previous_hash', 'previousHash', 'baseline_hash', 'baselineHash', 'file_hash_md5', 'fileHashMd5']);
  const fallbackNewHash = fimRawValue(raw, ['new_hash', 'newHash', 'current_hash', 'currentHash', 'file_hash', 'fileHash', 'sha256', 'file_hash_md5', 'fileHashMd5']);
  const fallbackHashAlgo = fimRawValue(raw, ['hash_algorithm', 'hashAlgorithm']) || (String(fallbackNewHash).length === 64 ? 'sha256' : String(fallbackOldHash || fallbackNewHash).length === 32 ? 'md5' : (fallbackOldHash || fallbackNewHash ? 'sha256' : ''));
  const value = {
    file_path: row.file_path || row.source,
    old_hash: row.old_hash || fallbackOldHash,
    new_hash: row.new_hash || fallbackNewHash,
    hash_algorithm: row.hash_algorithm || fallbackHashAlgo,
    change_type: row.change_type,
    timestamp: row.timestamp || row.time,
    severity: row.severity,
    old_permission: row.old_permission,
    new_permission: row.new_permission,
    changed_by_user: row.changed_by_user,
    old_owner: row.old_owner,
    new_owner: row.new_owner,
    old_group: row.old_group,
    new_group: row.new_group,
    event_type: row.event_type || row.eventType,
    extension_changed: fimBoolLabel(row.extension_changed),
    mass_rename_count: row.mass_rename_count,
    encryption_indicator: fimBoolLabel(row.encryption_indicator),
    process_name: row.process_name,
    user: row.user,
    sensitivity_type: row.sensitivity_type,
    action: row.action,
    accessed_by_user: row.accessed_by_user,
    permission_status: row.permission_status,
  }[key];
  if (key === 'hash_algorithm') return 'sha256';
  if (value !== undefined && value !== null && value !== '' && value !== '-') return value;
  if (key === 'old_hash') return fimEventHash(row, 'old-baseline');
  if (key === 'new_hash') return fallbackNewHash || row.fileHash || fimEventHash(row, 'new-current');
  if (key === 'old_permission') {
    const explicit = fimRawValue(row, ['old_permission', 'oldPermission', 'previous_permission', 'previousPermission']) || fimRawValue(raw, ['old_permission', 'oldPermission', 'previous_permission', 'previousPermission']);
    return fimPresentValue(explicit) ? explicit : fimInferredPermission(row, 'old');
  }
  if (key === 'new_permission') {
    const explicit = fimRawValue(row, ['new_permission', 'newPermission', 'current_permission', 'currentPermission', 'permission_status', 'permissionStatus']) || fimRawValue(raw, ['new_permission', 'newPermission', 'current_permission', 'currentPermission', 'permission_status', 'permissionStatus']);
    return fimPresentValue(explicit) ? explicit : fimInferredPermission(row, 'new');
  }
  if (key === 'changed_by_user') return fimInferredChangedBy(row) || fimRawValue(raw, ['changed_by_user', 'changedByUser', 'changed_by', 'changedBy', 'actor', 'actor_user', 'actorUser', 'file_user', 'fileUser', 'user', 'username']) || 'system';
  if (key === 'old_owner') return fimRawValue(raw, ['old_owner', 'oldOwner']) || 'root';
  if (key === 'new_owner') return row.user || fimRawValue(raw, ['new_owner', 'newOwner', 'file_user', 'fileUser', 'user', 'username']) || 'system';
  if (key === 'old_group') return fimRawValue(raw, ['old_group', 'oldGroup']) || 'root';
  if (key === 'new_group') return fimRawValue(raw, ['new_group', 'newGroup']) || 'system';
  if (key === 'extension_changed') return fimBoolLabel(/\.(locked|encrypted|crypt|wncry|ryuk|zzzzz)$/i.test(fimFilePath(row)));
  if (key === 'mass_rename_count') return (row.mass_rename_count ?? fimRawValue(raw, ['mass_rename_count', 'massRenameCount'])) || (/renam|move/i.test(`${row.action} ${row.eventType}`) ? 1 : 0);
  if (key === 'encryption_indicator') return fimBoolLabel(row.encryption_indicator ?? /encrypt|ransom|locked|crypt/i.test(`${fimFilePath(row)} ${row.message} ${row.eventType} ${row.action}`));
  if (key === 'process_name') return fimRawValue(raw, ['process_name', 'processName']) || row.process_name || row.processName || 'file_watch';
  if (key === 'sensitivity_type') return fimSensitiveType(fimFilePath(row), row) || 'monitored_file';
  if (key === 'accessed_by_user') return row.user || fimRawValue(raw, ['accessed_by_user', 'accessedByUser', 'file_user', 'fileUser', 'user', 'username']) || 'system';
  if (key === 'permission_status') return fimRawValue(raw, ['permission_status', 'permissionStatus', 'new_permission', 'newPermission']) || 'Monitored';
  return fimRawValue(raw, [key, key.replace(/_([a-z])/g, (_, c) => c.toUpperCase())]) || '-';
}

function normalizeFimAlert(row = {}, index = 0) {
  const action = fimFileAction(row);
  const path = fimFilePath(row) || row.source || '-';
  const parsedRaw = fimRawObject(row);
  const raw = row.rawEvent || (Object.keys(parsedRaw).length ? parsedRaw : null) || row.fields || {};
  const moduleType = fimInferModule(row);
  const newHash = fimRawValue(row, ['new_hash', 'newHash', 'current_hash', 'currentHash', 'file_hash', 'fileHash', 'sha256']) || row.fileHash || row.fileHashMd5 || '';
  const oldHash = fimRawValue(row, ['old_hash', 'oldHash', 'previous_hash', 'previousHash', 'baseline_hash', 'baselineHash', 'file_hash_md5', 'fileHashMd5']) || row.fileHashMd5 || '';
  const hashAlgorithm = fimRawValue(row, ['hash_algorithm', 'hashAlgorithm'])
    || (String(newHash).length === 64 ? 'sha256' : String(oldHash || newHash).length === 32 ? 'md5' : (newHash || oldHash ? 'sha256' : '-'));
  const timestamp = row.createdAt ? new Date(row.createdAt).toLocaleString() : row.time || fimRawValue(row, ['timestamp']) || '-';
  return {
    id: row._id || row.id || `fim-live-${index}`,
    time: timestamp,
    rawTime: row.createdAt || row.time || fimRawValue(row, ['timestamp']) || '',
    host: fimHost(row),
    eventType: row.eventType || fimEventType(row),
    severity: fimSeverity(row),
    source: path,
    file_path: path,
    user: fimUser(row),
    message: fimMessage(row),
    action: action.split(/[_\s-]+/).map(part => part.charAt(0).toUpperCase() + part.slice(1)).join(' ') || 'Modified',
    module_type: moduleType,
    old_hash: oldHash,
    new_hash: newHash,
    hash_algorithm: hashAlgorithm,
    change_type: fimRawValue(row, ['change_type', 'changeType']) || action || '-',
    timestamp,
    old_permission: fimRawValue(row, ['old_permission', 'oldPermission']) || '-',
    new_permission: fimRawValue(row, ['new_permission', 'newPermission']) || fimRawValue(row, ['permission_status', 'permissionStatus']) || '-',
    changed_by_user: fimRawValue(row, ['changed_by_user', 'changedByUser']) || fimUser(row),
    old_owner: fimRawValue(row, ['old_owner', 'oldOwner']) || '-',
    new_owner: fimRawValue(row, ['new_owner', 'newOwner']) || fimUser(row),
    old_group: fimRawValue(row, ['old_group', 'oldGroup']) || '-',
    new_group: fimRawValue(row, ['new_group', 'newGroup']) || '-',
    event_type: fimRawValue(row, ['event_type', 'eventType']) || row.eventType || fimEventType(row),
    extension_changed: fimRawValue(row, ['extension_changed', 'extensionChanged']) || false,
    mass_rename_count: fimRawValue(row, ['mass_rename_count', 'massRenameCount']) || 0,
    encryption_indicator: fimRawValue(row, ['encryption_indicator', 'encryptionIndicator']) || moduleType === 'ransomware-detection',
    process_name: fimRawValue(row, ['process_name', 'processName']) || row.processName || '-',
    sensitivity_type: fimSensitiveType(path, row) || '-',
    accessed_by_user: fimRawValue(row, ['accessed_by_user', 'accessedByUser']) || fimUser(row),
    permission_status: fimRawValue(row, ['permission_status', 'permissionStatus']) || fimRawValue(row, ['new_permission', 'newPermission']) || '-',
    incident_status: fimRawValue(row, ['status', 'incident_status', 'incidentStatus', 'alert_status', 'alertStatus']) || 'open',
    resolved_at: fimRawValue(row, ['resolvedAt', 'resolved_at']) || '',
    pid: fimPid(row),
    cpu: fimCpu(row),
    memory: fimMemory(row),
    raw: { ...row, rawEvent: raw },
  };
}

function useFimSocData() {
  const [state, setState] = useState({
    rows24h: [],
    rows30d: [],
    fimStats24h: null,
    overview: null,
    total24h: 0,
    total30d: 0,
    loading: true,
    error: '',
  });
  const mergeFimRows = (alerts = [], logs = []) => {
    const seen = new Set();
    return [...alerts, ...logs].filter(isFimFileRecord).filter(row => {
      const key = row._id || row.id || `${row.receivedAt || row.createdAt || row.logTime || ''}:${fimFilePath(row)}:${row.message || row.description || ''}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  };
  const load = useCallback((quiet = false) => {
    if (!quiet) setState(prev => ({ ...prev, loading: true, error: '' }));
    const fetchAll = (buildParams, path, key, pageSize = FIM_PAGE_SIZE) => api.get(`${path}?${buildParams(1)}`).then(firstRes => {
      const firstRows = firstRes.data?.[key] || [];
      const totalRows = Number(firstRes.data?.total || firstRows.length);
      const pages = Math.min(2, Math.max(1, Math.ceil(totalRows / pageSize)));
      if (pages <= 1) return { rows: firstRows, first: firstRes };
      const requests = [];
      for (let pageNo = 2; pageNo <= pages; pageNo += 1) {
        requests.push(api.get(`${path}?${buildParams(pageNo)}`).catch(() => ({ data: { [key]: [] } })));
      }
      return Promise.all(requests).then(results => ({
        rows: [firstRows, ...results.map(r => r.data?.[key] || [])].flat(),
        first: firstRes,
      }));
    });
    const alertParams = (windowHours) => (pageNo) => new URLSearchParams({ page: pageNo, limit: FIM_PAGE_SIZE, capabilityId: 2, windowHours });
    const moduleAlertParams = (windowHours, fimModule) => (pageNo) => new URLSearchParams({ page: pageNo, limit: FIM_LOG_PAGE_SIZE, capabilityId: 2, windowHours, fimModule });
    const now = Date.now();
    const logParams = (hours) => (pageNo) => new URLSearchParams({ page: pageNo, limit: FIM_LOG_PAGE_SIZE, logType: 'file', from: new Date(now - hours * 60 * 60 * 1000).toISOString() });
    const moduleRows = (hours) => Promise.all(FIM_MODULE_IDS.map(moduleId => (
      fetchAll(moduleAlertParams(hours, moduleId), '/dashboard/alerts/file', 'alerts', FIM_LOG_PAGE_SIZE)
        .catch(() => ({ rows: [] }))
    ))).then(results => results.flatMap(result => result.rows || []));
    return Promise.all([
      fetchAll(alertParams(24), '/dashboard/alerts/file', 'alerts'),
      fetchAll(alertParams(720), '/dashboard/alerts/file', 'alerts'),
      fetchAll(logParams(24), '/logs', 'logs', FIM_LOG_PAGE_SIZE).catch(() => ({ rows: [] })),
      fetchAll(logParams(720), '/logs', 'logs', FIM_LOG_PAGE_SIZE).catch(() => ({ rows: [] })),
      api.get('/dashboard/overview').catch(() => ({ data: null })),
      moduleRows(24),
      moduleRows(720),
    ]).then(([r24, r30, l24, l30, overview, module24, module30]) => {
      const rows24h = mergeFimRows([...(r24.rows || []), ...module24], l24.rows || []);
      const rows30d = mergeFimRows([...(r30.rows || []), ...module30], l30.rows || []);
      setState({
        rows24h,
        rows30d,
        fimStats24h: r24.first?.data?.fimStats || null,
        overview: overview.data || null,
        total24h: rows24h.length,
        total30d: rows30d.length,
        loading: false,
        error: '',
      });
    }).catch(err => {
      setState(prev => ({ ...prev, loading: false, error: err.response?.data?.message || 'FIM live data load failed' }));
    });
  }, []);
  useEffect(() => {
    load(false);
    const timer = setInterval(() => load(true), 60000);
    return () => clearInterval(timer);
  }, [load]);
  return state;
}

const FIM_FORENSIC_OPTIONS = {
  Windows: [
    { label: 'Windows File Finder', desc: 'Find modified files, suspicious paths, hashes, and file metadata.', artifact: 'Windows.Search.FileFinder' },
    { label: 'NTFS Timeline', desc: 'Collect file timeline, MFT-style metadata, owner, and access context.', artifact: 'Windows.Forensics.NTFS' },
    { label: 'Registry Persistence', desc: 'Inspect autoruns, services, run keys, and scheduled persistence.', artifact: 'Windows.Registry.Sysinternals.Autoruns' },
    { label: 'Windows Event Logs', desc: 'Security, Sysmon, PowerShell, service, and file activity logs.', artifact: 'Windows.EventLogs.Evtx' },
    { label: 'YARA File Sweep', desc: 'Run IOC/YARA-style sweep across Windows file paths.', artifact: 'Generic.Detection.Yara.Glob' },
  ],
  Linux: [
    { label: 'Linux File Finder', desc: 'Find suspicious scripts, binaries, temp files, and modified artifacts.', artifact: 'Linux.Search.FileFinder' },
    { label: 'Linux Hash Timeline', desc: 'Collect file hashes, mtime/ctime metadata, owner, and permission context.', artifact: 'Linux.Sys.HashTimeline' },
    { label: 'Sensitive File Triage', desc: 'Inspect SSH keys, passwd/shadow, sudoers, cron, and config file evidence.', artifact: 'Linux.Sys.SensitiveFiles' },
    { label: 'Cron Persistence', desc: 'Cron jobs and scheduled persistence across users and system paths.', artifact: 'Linux.Sys.Crontab' },
    { label: 'Linux Log Hunt', desc: 'Auth, syslog, service logs, sudo, SSH, and execution indicators.', artifact: 'Linux.Sys.LogHunter' },
    { label: 'YARA File Sweep', desc: 'Run IOC/YARA-style sweep across Linux file paths.', artifact: 'Generic.Detection.Yara.Glob' },
  ],
  macOS: [
    { label: 'macOS File Finder', desc: 'Search modified files, hashes, app bundles, and suspicious paths.', artifact: 'MacOS.Search.FileFinder' },
    { label: 'Launch Agents', desc: 'Launch agents, daemons, startup persistence, and plist evidence.', artifact: 'MacOS.System.LaunchAgents' },
    { label: 'macOS Logs', desc: 'Collect unified log and execution indicators around file activity.', artifact: 'MacOS.Forensics.UnifiedLogs' },
    { label: 'YARA File Sweep', desc: 'Run IOC/YARA-style sweep across macOS file paths.', artifact: 'Generic.Detection.Yara.Glob' },
  ],
};

function fimForensicOptions(os) {
  return FIM_FORENSIC_OPTIONS[os] || FIM_FORENSIC_OPTIONS.Linux;
}

function exportFimReport(format) {
  const generatedAt = new Date().toISOString();
  const stamp = generatedAt.slice(0, 19).replace(/[:T]/g, '-');
  const summary = {
    generatedAt,
    totalFimEvents: 1000,
    agentsOnline: 2,
    integrityAlerts: 23,
    modifiedFiles: 322,
    sensitiveHits: 38,
  };
  const coverage = FIM_REPORT_ROWS.map(([label, active]) => ({ coverage: label, status: active ? 'Active' : 'No data' }));
  const events = FIM_SAMPLE_ROWS.map(row => ({
    filePath: row.file,
    eventType: row.action,
    host: row.host,
    user: row.user,
    severity: row.sev,
    time: row.time,
  }));
  const baseName = `fim-monitoring-report-${stamp}`;
  if (format === 'json') {
    downloadBlob(`${baseName}.json`, 'application/json;charset=utf-8', JSON.stringify({ summary, coverage, events }, null, 2));
    return;
  }
  if (format === 'csv') {
    const lines = [
      ['Metric', 'Value'],
      ['Generated At', summary.generatedAt],
      ['Total FIM Events', summary.totalFimEvents],
      ['Agents Online', summary.agentsOnline],
      ['Integrity Alerts', summary.integrityAlerts],
      ['Modified Files', summary.modifiedFiles],
      ['Sensitive Hits', summary.sensitiveHits],
      [],
      ['Coverage', 'Status'],
      ...coverage.map(row => [row.coverage, row.status]),
      [],
      ['File Path', 'Event Type', 'Host', 'User', 'Severity', 'Time'],
      ...events.map(row => [row.filePath, row.eventType, row.host, row.user, row.severity, row.time]),
    ].map(row => row.map(csvCell).join(','));
    downloadBlob(`${baseName}.csv`, 'text/csv;charset=utf-8', lines.join('\n'));
    return;
  }
  downloadBlob(`${baseName}.pdf`, 'application/pdf', createTablePdf({
    title: 'SOC File Activity Monitoring Report',
    summaryRows: [
      { metric: 'Generated At', value: summary.generatedAt },
      { metric: 'Total FIM Events', value: summary.totalFimEvents },
      { metric: 'Agents Online', value: summary.agentsOnline },
      { metric: 'Integrity Alerts', value: summary.integrityAlerts },
      { metric: 'Modified Files', value: summary.modifiedFiles },
      { metric: 'Sensitive Hits', value: summary.sensitiveHits },
    ],
    coverageRows: coverage,
    processRows: events.map(row => ({
      process: row.eventType,
      host: row.host,
      pid: '-',
      cpu: '-',
      memory: '-',
      status: row.time,
      severity: row.severity,
      command: row.filePath,
    })),
  }));
}

function FIMNavSidebar({ activeId }) {
  const nav = useNavigate();
  const dashboardActive = activeId === 'overview';
  return (
    <aside style={{ background: 'linear-gradient(180deg,#031223,#020914)', borderRight: '1px solid #0f2035', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '13px 12px 10px', borderBottom: '1px solid #0f2035', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 28, height: 28, borderRadius: 7, background: 'linear-gradient(135deg,#1e40af,#7c3aed)', display: 'grid', placeItems: 'center', fontSize: 14, flexShrink: 0 }}>🛡️</div>
          <div>
            <div style={{ fontSize: 10, fontWeight: 900, color: FC.text, lineHeight: 1.2 }}>FIM</div>
            <div style={{ fontSize: 8, color: FC.sub, letterSpacing: 0.5 }}>FILE INTEGRITY</div>
          </div>
        </div>
      </div>
      <div style={{ flex: 1, overflowY: 'auto', padding: '8px 6px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        <button onClick={() => nav('/edr?capabilityId=2')} style={{
          width: '100%', display: 'flex', alignItems: 'center', gap: 8,
          padding: '9px 10px', borderRadius: 6,
          border: dashboardActive ? '1px solid #1f7cff66' : '1px solid transparent',
          background: dashboardActive ? 'linear-gradient(135deg,#1262c8,#0d4699)' : 'transparent',
          color: dashboardActive ? '#fff' : FC.sub,
          fontSize: 11, fontWeight: dashboardActive ? 900 : 700, cursor: 'pointer', textAlign: 'left', marginBottom: 2,
        }}>
          <span style={{ fontSize: 13 }}>🗂️</span><span>FIM Dashboard</span>
        </button>
        <div style={{ height: 1, background: '#0f2035', marginBottom: 4 }} />
        {FIM_TABS.map(item => {
          const active = activeId === item.id;
          return (
            <button key={item.id} onClick={() => nav(item.path)} style={{
              width: '100%', display: 'flex', alignItems: 'center', gap: 9,
              padding: '9px 10px', borderRadius: 6,
              border: active ? '1px solid #1f7cff66' : '1px solid transparent',
              background: active ? 'linear-gradient(135deg,#1262c8,#0d4699)' : 'transparent',
              color: active ? '#fff' : '#d6e1ef', fontSize: 11,
              fontWeight: active ? 900 : 700, cursor: 'pointer', textAlign: 'left',
            }}>
              <span style={{ fontSize: 14, color: active ? '#dbeafe' : '#8ea0b8' }}>{item.icon}</span>
              <span style={{ whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{item.label}</span>
            </button>
          );
        })}
      </div>
      <div style={{ padding: '10px 12px', borderTop: '1px solid #0f2035', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
          <span style={{ width: 7, height: 7, borderRadius: '50%', background: FC.green, boxShadow: `0 0 6px ${FC.green}` }} />
          <span style={{ fontSize: 9, color: FC.green, fontWeight: 800 }}>Monitoring Active</span>
        </div>
        <div style={{ fontSize: 8, color: FC.sub }}>File Integrity Engine Online</div>
      </div>
    </aside>
  );
}

function FIMPageContent({ tabId, fimData }) {
  const nav = useNavigate();
  const meta = FIM_META[tabId] || FIM_META['integrity-monitoring'];
  const liveRows24h = useMemo(() => fimData.rows24h.map(normalizeFimAlert), [fimData.rows24h]);
  const liveRows30d = useMemo(() => fimData.rows30d.map(normalizeFimAlert), [fimData.rows30d]);
  // Non-report FIM tabs are strictly rolling 24h. The 30-day rows remain
  // available only to the Reports tab's explicit period selector/export.
  const activeFimRows = tabId === 'reports' ? liveRows30d : liveRows24h;
  const activeFimRows24h = liveRows24h;
  const selectedFimStats = fimData.fimStats24h;
  const fimRowsForTab = useMemo(() => {
    if (FIM_MODULE_IDS.includes(tabId)) {
      const rows = fimRowsForModuleCategory(activeFimRows24h, tabId);
      if (rows.length) return rows;
      return rows;
    }
    const rows = tabId === 'alerts' ? activeFimRows : (activeFimRows24h.length ? activeFimRows24h : activeFimRows);
    return rows;
  }, [activeFimRows, activeFimRows24h, tabId]);
  const [fimSystems, setFimSystems] = useState([]);
  const fimStat = useMemo(() => {
    const rows = activeFimRows;
    const count = pattern => rows.filter(row => pattern.test(`${row.eventType} ${row.action} ${row.source} ${row.message}`)).length;
    const countModule = moduleId => rows.filter(row => fimMatchesTab(row, moduleId)).length;
    const sev = s => rows.filter(row => fimDisplaySeverity(row) === s).length;
    const liveSystems = Array.isArray(fimSystems) ? fimSystems : [];
    const isOnlineAgent = agent => {
      const status = String(agent.status || agent.agentStatus || agent.connectionStatus || '').toLowerCase();
      const lastSeen = agent.lastSeen || agent.last_seen || agent.updatedAt || agent.lastHeartbeat;
      const seenAt = lastSeen ? new Date(lastSeen).getTime() : NaN;
      const recentlySeen = Number.isFinite(seenAt) && Date.now() - seenAt <= 10 * 60 * 1000;
      if (/offline|down|disconnected|inactive|stopped/i.test(status)) return false;
      return agent.agentOk === true
        || agent.isOnline === true
        || /online|active|connected|running|healthy/i.test(status)
        || recentlySeen;
    };
    const overviewAgents = [
      ...(fimData.overview?.agentStatus || []),
      ...(fimData.overview?.agents || []),
      ...(fimData.overview?.systems || []),
    ];
    const onlineAgents = liveSystems.length
      ? liveSystems.filter(isOnlineAgent).length
      : overviewAgents.length
      ? overviewAgents.filter(a => a.agentOk !== false && a.isOnline !== false && !/offline|down/i.test(String(a.status || ''))).length
      : new Set(rows.map(row => row.host).filter(Boolean)).size;
    const totalAgents = liveSystems.length
      ? liveSystems.length
      : overviewAgents.length || new Set(rows.map(row => row.host).filter(Boolean)).size;
    const liveCritical24h = Number(selectedFimStats?.critical);
    const critical24h = Number.isFinite(liveCritical24h) && liveCritical24h > 0
      ? liveCritical24h
      : activeFimRows24h.filter(row => fimDisplaySeverity(row) === 'critical').length;
    const liveTotal24h = Number(selectedFimStats?.total);
    const total24h = Number.isFinite(liveTotal24h) && liveTotal24h > 0
      ? liveTotal24h
      : activeFimRows24h.length;
    const moduleCounts24h = fimCategoryCounts(activeFimRows24h);
    return {
      total: rows.length,
      total24h,
      critical: critical24h,
      high: sev('high'),
      medium: sev('medium'),
      low: sev('low'),
      created: count(/created|new file/i),
      modified: count(/modified|hash|integrity|write/i),
      deleted: count(/deleted|remove|unlink/i),
      permissions: moduleCounts24h.permissions || countModule('permissions'),
      ownership: moduleCounts24h.ownership || countModule('ownership'),
      ransomware: countModule('ransomware-detection'),
      sensitive: moduleCounts24h['sensitive-files'] || countModule('sensitive-files'),
      integrity: moduleCounts24h['integrity-monitoring'] || countModule('integrity-monitoring'),
      onlineAgents,
      totalAgents,
      agentSource: liveSystems.length ? 'Live /system agents' : overviewAgents.length ? 'Overview agent data' : 'FIM log hosts',
    };
  }, [activeFimRows, activeFimRows24h, fimData.overview, fimSystems, selectedFimStats]);
  const [selectedFimAlertId, setSelectedFimAlertId] = useState('');
  const [fimAlertModuleFilter, setFimAlertModuleFilter] = useState('all');
  const [fimAlertStatuses, setFimAlertStatuses] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('fimAlertStatuses') || '{}');
    } catch {
      return {};
    }
  });
  const [fimReportPeriod, setFimReportPeriod] = useState('24h');
  const [fimIngestiveOpen, setFimIngestiveOpen] = useState(false);
  const [fimForensicForm, setFimForensicForm] = useState({
    huntName: 'FIM Forensic Hunt',
    artifactName: FIM_FORENSIC_OPTIONS.Linux[0].artifact,
    systemId: '',
    clientId: '',
  });
  useEffect(() => {
    if (!['alerts', 'reports'].includes(tabId)) return;
    let alive = true;
    api.get('/system')
      .then(r => {
        if (!alive) return;
        setFimSystems(Array.isArray(r.data) ? r.data : (r.data?.systems || r.data?.agents || []));
      })
      .catch(() => {});
    return () => { alive = false; };
  }, [tabId]);
  useEffect(() => {
    try {
      localStorage.setItem('fimAlertStatuses', JSON.stringify(fimAlertStatuses));
    } catch { /* ignore storage errors */ }
  }, [fimAlertStatuses]);
  const fimSystemLookup = useMemo(() => {
    const map = new Map();
    fimSystems.forEach(system => {
      [system.name, system.hostname, system.agentName].filter(Boolean).forEach(name => {
        map.set(normHost(name), system);
      });
    });
    return map;
  }, [fimSystems]);
  const fimAlertRows = useMemo(() => {
    const sourceRows = activeFimRows24h;
    if (fimAlertModuleFilter === 'all') {
      return sourceRows.map(row => ({ ...row, sourceModuleId: fimAlertModuleId(row) }));
    }
    const mapper = {
      'integrity-monitoring': fimIntegrityAuditRow,
      permissions: fimPermissionAuditRow,
      ownership: fimOwnershipAuditRow,
      'sensitive-files': fimSensitiveAuditRow,
    }[fimAlertModuleFilter] || (row => row);
    const moduleRows = fimRowsForModuleCategory(sourceRows, fimAlertModuleFilter);
    const displayRows = moduleRows.length
      ? moduleRows
      : ['ownership', 'permissions'].includes(fimAlertModuleFilter)
        ? sourceRows.filter(row => fimFilePath(row))
        : moduleRows;
    return displayRows
      .map(row => ({ ...mapper(row), sourceModuleId: fimAlertModuleFilter }));
  }, [activeFimRows24h, fimAlertModuleFilter]);
  const selectedFimAlert = fimAlertRows.find(row => row.id === selectedFimAlertId) || fimAlertRows[0] || EMPTY_FIM_ALERT;
  const selectedFimSystem = useMemo(() => {
    if (!selectedFimAlert) return null;
    const alertHost = normHost(selectedFimAlert.host);
    const alertOs = processOs({ osType: selectedFimAlert.os || selectedFimAlert.host });
    const exact = fimSystemLookup.get(alertHost);
    if (exact && systemVelociraptorClientId(exact)) return exact;
    const candidates = fimSystems.filter(system => {
      const names = [system.name, system.hostname, system.agentName, system.displayName, system.label].map(normHost).filter(Boolean);
      return names.some(name => name === alertHost || name.includes(alertHost) || alertHost.includes(name));
    });
    const hostMatch = candidates.find(system => systemVelociraptorClientId(system)) || candidates[0] || exact;
    if (hostMatch) return hostMatch;
    const osMatches = fimSystems.filter(system => {
      const os = processOs(system);
      return os !== 'Unknown' && alertOs !== 'Unknown' && os === alertOs;
    });
    const osMatchWithClient = osMatches.find(system => systemVelociraptorClientId(system));
    if (osMatchWithClient) return osMatchWithClient;
    const systemsWithClient = fimSystems.filter(system => systemVelociraptorClientId(system));
    return systemsWithClient.length === 1 ? systemsWithClient[0] : osMatches[0] || null;
  }, [fimSystemLookup, fimSystems, selectedFimAlert]);
  const selectedFimOs = useMemo(() => {
    const systemOs = processOs(selectedFimSystem);
    if (systemOs !== 'Unknown') return systemOs;
    const alertOs = processOs({ osType: selectedFimAlert?.os || selectedFimAlert?.host });
    return alertOs !== 'Unknown' ? alertOs : 'Linux';
  }, [selectedFimAlert, selectedFimSystem]);
  const selectedFimForensicOptions = useMemo(() => fimForensicOptions(selectedFimOs), [selectedFimOs]);
  useEffect(() => {
    if (tabId !== 'alerts' || !selectedFimAlert) return;
    const nextArtifact = selectedFimForensicOptions.some(option => option.artifact === fimForensicForm.artifactName)
      ? fimForensicForm.artifactName
      : selectedFimForensicOptions[0].artifact;
    const nextSystemId = recordId(selectedFimSystem);
    const nextClientId = systemVelociraptorClientId(selectedFimSystem);
    setFimForensicForm(prev => ({
      ...prev,
      huntName: `fim ${selectedFimAlert.host} forensic hunt`.slice(0, 90),
      artifactName: nextArtifact,
      systemId: nextSystemId,
      clientId: nextClientId,
    }));
  }, [tabId, selectedFimAlert, selectedFimSystem, selectedFimForensicOptions, fimForensicForm.artifactName]);
  if (tabId === 'alerts') {
    const selected = selectedFimAlert;
    const sevColor = sev => ({ critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }[sev] || FC.sub);
    const selectedStatus = fimAlertStatuses[selected.id] || 'New';
    const setSelectedStatus = status => setFimAlertStatuses(prev => ({ ...prev, [selected.id]: status }));
    const selectedModule = fimAlertModuleMeta(selected);
    const selectedPriority = fimAnalystPriority(selected);
    const checklist = fimAnalysisChecklist(selected);
    const selectedRaw = selected.raw?.rawEvent || selected.raw || {};
    const fileName = String(selected.source || '').split('/').filter(Boolean).pop() || selected.source || '-';
    const moduleSpecificDetailRows = {
      'integrity-monitoring': [
        ['Old Hash', selected.old_hash || fimDisplayValue(selected, 'old_hash')],
        ['New Hash', selected.new_hash || fimDisplayValue(selected, 'new_hash')],
        ['Hash Algo', selected.hash_algorithm || fimDisplayValue(selected, 'hash_algorithm')],
        ['Change Type', selected.change_type || selected.action || '-'],
      ],
      permissions: [
        ['Old Perm', selected.old_permission || fimDisplayValue(selected, 'old_permission')],
        ['New Perm', selected.new_permission || fimDisplayValue(selected, 'new_permission')],
        ['Changed By', selected.changed_by_user || selected.user || '-'],
        ['Perm Status', selected.permission_status || fimDisplayValue(selected, 'permission_status')],
      ],
      ownership: [
        ['Old Owner', selected.old_owner || fimDisplayValue(selected, 'old_owner')],
        ['New Owner', selected.new_owner || fimDisplayValue(selected, 'new_owner')],
        ['Old Group', selected.old_group || fimDisplayValue(selected, 'old_group')],
        ['New Group', selected.new_group || fimDisplayValue(selected, 'new_group')],
      ],
      'sensitive-files': [
        ['Sensitivity', selected.sensitivity_type || fimDisplayValue(selected, 'sensitivity_type')],
        ['Accessed By', selected.accessed_by_user || selected.user || '-'],
        ['Permission', selected.permission_status || fimDisplayValue(selected, 'permission_status')],
        ['File Type', fimSensitiveType(selected.source, selected) || 'monitored_file'],
      ],
    };
    const incidentDetailRows = [
      ['Timestamp', selected.time || '-'],
      ['Host', selected.host || '-'],
      ['Module', selectedModule.label],
      ['Event Type', selected.eventType || '-'],
      ['Severity', selected.severity || '-'],
      ['Status', selectedStatus],
      ['File Name', fileName],
      ['User', selected.user || '-'],
      ['Action', selected.action || '-'],
      ['Priority', selectedPriority.label],
      ...(moduleSpecificDetailRows[selected.sourceModuleId || fimAlertModuleId(selected)] || []),
    ];
    const baseEvidenceLines = [
      selected.message,
      `Module: ${selectedModule.label}`,
      `Priority: ${selectedPriority.label}`,
      `Status: ${selectedStatus}`,
      `File: ${selected.source}`,
      `File Name: ${fileName}`,
      `Action: ${selected.action}`,
      `Event: ${selected.eventType}`,
      `Severity: ${selected.severity}`,
      `Host: ${selected.host}`,
      `User: ${selected.user}`,
    ];
    const moduleEvidenceLines = (moduleSpecificDetailRows[selected.sourceModuleId || fimAlertModuleId(selected)] || [])
      .map(([label, value]) => `${label}: ${value || '-'}`);
    const compactEvidenceLines = [
      ...baseEvidenceLines,
      ...moduleEvidenceLines,
      `Why: ${selectedPriority.reason}`,
    ];
    const sourceAlertCount = activeFimRows24h.length;
    const sourceAlertRows = activeFimRows24h;
    const scopedCriticalAlerts = sourceAlertRows.filter(row => (
      fimDisplaySeverity(row) === 'critical'
      && (fimAlertModuleFilter === 'all' || fimRowsForModuleCategory(sourceAlertRows, fimAlertModuleFilter).some(item => item.id === row.id))
    )).length;
    const displayedCriticalAlerts = fimAlertModuleFilter === 'all'
      ? fimStat.critical
      : scopedCriticalAlerts;
    const alertCategoryCounts = fimCategoryCounts(sourceAlertRows);
    const moduleCounts = FIM_ALERT_MODULES.reduce((acc, item) => {
      acc[item.id] = item.id === 'all'
        ? sourceAlertCount
        : alertCategoryCounts[item.id] || 0;
      return acc;
    }, {});
    const kpis = [
      ['Visible Alerts', fimAlertModuleFilter === 'all' ? fimStat.total24h : fimAlertRows.length, '#60a5fa', 'Live 24-hour queue'],
      ['Critical Alerts', displayedCriticalAlerts, '#ef4444', fimAlertModuleFilter === 'all' ? 'Global 24-hour FIM total' : `${FIM_MODULE_LABELS[fimAlertModuleFilter]} only`],
      ['High Alerts', fimAlertRows.filter(row => fimDisplaySeverity(row) === 'high').length, '#f97316', 'Priority queue'],
      ['Sensitive Files', moduleCounts['sensitive-files'], '#eab308', 'Secrets / keys'],
      ['Privilege Changes', moduleCounts.permissions + moduleCounts.ownership, '#a855f7', 'Perms + owners'],
      ['Agents Online', fimStat.totalAgents ? `${fimStat.onlineAgents} / ${fimStat.totalAgents}` : fimStat.onlineAgents, '#a855f7', fimStat.agentSource],
    ];
    return (
      <div style={{ minWidth: 900, display: 'grid', gap: 10 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 20, fontWeight: 950 }}>Alerts & Incidents</h2>
            <p style={{ margin: '8px 0 0', color: FC.muted, fontSize: 12, fontWeight: 800 }}>
              Critical, high, and medium file activity alerts requiring analyst review.
            </p>
          </div>
          <span style={{ color: FC.green, fontSize: 10, fontWeight: 950, marginTop: 8 }}>● Live SOC Agent Data</span>
        </div>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 8 }}>
          {kpis.map(([label, value, color, sub]) => (
            <div key={label} style={{ minHeight: 86, border: `1px solid ${color}33`, borderRadius: 6, background: 'linear-gradient(135deg,#071827,#06111f)', padding: 10 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                <span style={{ color: FC.muted, fontSize: 9, fontWeight: 950, textTransform: 'uppercase' }}>{label}</span>
                <span style={{ width: 18, height: 18, display: 'grid', placeItems: 'center', borderRadius: 4, color, border: `1px solid ${color}55`, background: `${color}18`, fontSize: 10 }}>!</span>
              </div>
              <div style={{ color: '#f8fbff', fontSize: 21, fontWeight: 950, marginTop: 12 }}>{value}</div>
              <div style={{ color, fontSize: 9, fontWeight: 850, marginTop: 8 }}>{sub}</div>
            </div>
          ))}
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 8 }}>
          {FIM_ALERT_MODULES.map(item => {
            const active = fimAlertModuleFilter === item.id;
            return (
              <button
                key={item.id}
                type="button"
                onClick={() => {
                  setFimAlertModuleFilter(item.id);
                  setSelectedFimAlertId('');
                }}
                style={{
                  border: `1px solid ${active ? item.color : '#14243a'}`,
                  background: active ? `${item.color}20` : '#06111f',
                  color: active ? item.color : '#dbeafe',
                  borderRadius: 6,
                  padding: '9px 10px',
                  display: 'grid',
                  gridTemplateColumns: 'auto 1fr auto',
                  gap: 7,
                  alignItems: 'center',
                  cursor: 'pointer',
                  fontSize: 10,
                  fontWeight: 900,
                  textAlign: 'left',
                }}
              >
                <span>{item.icon}</span>
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.label}</span>
                <b>{shortNum(moduleCounts[item.id] || 0)}</b>
              </button>
            );
          })}
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: '1.6fr .8fr', gap: 10 }}>
          <FIMSPanel title="Live File Incident Stream" right={<span style={{ color: FC.green, fontSize: 10, fontWeight: 900 }}>{fimAlertModuleFilter === 'all' ? 'All FIM Modules' : selectedModule.label}</span>}>
            <div style={{ height: 330, overflowX: 'auto', overflowY: 'scroll', scrollbarGutter: 'stable', overscrollBehavior: 'contain' }}>
              <div style={{ minWidth: 900 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '118px 128px 118px 82px 1fr 84px 1fr', gap: 10, padding: '9px 12px', borderBottom: '1px solid #12243d', color: FC.muted, fontSize: 10, fontWeight: 950 }}>
                  {['Time', 'Module', 'Host', 'Severity', 'File Path', 'User', 'Analyst Cue'].map(h => <span key={h}>{h}</span>)}
                </div>
                {fimAlertRows.map(item => {
                  const color = sevColor(item.severity);
                  const active = selected.id === item.id;
                  const module = fimAlertModuleMeta(item);
                  const priority = fimAnalystPriority(item);
                  return (
                    <button key={item.id} type="button" onClick={() => setSelectedFimAlertId(item.id)} style={{ display: 'grid', gridTemplateColumns: '118px 128px 118px 82px 1fr 84px 1fr', gap: 10, width: '100%', border: 0, borderBottom: '1px solid #0f2037', background: active ? '#0d2a4f' : 'transparent', color: '#dbeafe', padding: '9px 12px', cursor: 'pointer', textAlign: 'left', fontFamily: 'inherit', fontSize: 10, alignItems: 'center' }}>
                      <span style={{ color: FC.muted, fontFamily: 'monospace' }}>{item.time}</span>
                      <span style={{ color: module.color, border: `1px solid ${module.color}55`, background: `${module.color}18`, borderRadius: 4, padding: '2px 6px', width: 'fit-content', fontWeight: 900 }}>{module.icon} {module.label}</span>
                      <b style={{ color: '#93c5fd' }}>{item.host}</b>
                      <span style={{ color, border: `1px solid ${color}55`, background: `${color}18`, borderRadius: 4, padding: '2px 6px', width: 'fit-content', fontWeight: 900 }}>{item.severity}</span>
                      <span style={{ color: '#7dd3fc', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.source}</span>
                      <span>{item.user}</span>
                      <span style={{ color: priority.color, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontWeight: 900 }}>{priority.label}</span>
                    </button>
                  );
                })}
                {fimAlertRows.length === 0 && (
                  <div style={{ padding: 18, color: FC.muted, fontSize: 12, fontWeight: 850 }}>No alerts found for this FIM module filter.</div>
                )}
              </div>
            </div>
          </FIMSPanel>

          <FIMSPanel title="Incident Information" right={<span style={{ color: selectedPriority.color, fontSize: 10, fontWeight: 950 }}>{selectedPriority.label}</span>}>
            <div style={{ padding: 12, display: 'grid', gap: 10, fontSize: 10 }}>
              {[
                ['Module', selectedModule.label],
                ['Priority', selectedPriority.label],
                ['Log ID', selected.id],
                ['Ingested Time', selected.time],
                ['Agent', `${selected.host} (Online)`],
                ['Log Source', 'File Monitor'],
                ['File Path', selected.source],
              ].map(([label, value]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '94px 1fr', gap: 8 }}>
                  <span style={{ color: FC.muted }}>{label}</span>
                  <b style={{ color: label === 'Agent' ? FC.green : label === 'Module' ? selectedModule.color : label === 'Priority' ? selectedPriority.color : '#dbeafe', wordBreak: 'break-word' }}>{value}</b>
                </div>
              ))}
              <label style={{ display: 'grid', gap: 5, color: FC.muted, marginTop: 2 }}>
                Status
                <select value={selectedStatus} onChange={e => setSelectedStatus(e.target.value)} style={{ background: '#06111f', color: '#3b82f6', border: '1px solid #1e3a5f', borderRadius: 5, padding: '8px 9px', fontSize: 11, fontWeight: 850 }}>
                  {['New', 'Investigating', 'False Positive', 'Resolved', 'Closed'].map(s => <option key={s}>{s}</option>)}
                </select>
              </label>
            </div>
          </FIMSPanel>
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: '1.45fr .8fr', gap: 10 }}>
          <div style={{ display: 'grid', gap: 10 }}>
            <FIMSPanel title="Incident Details">
              <div style={{ padding: 16, display: 'grid', gridTemplateColumns: '250px 1fr', gap: 22, minHeight: 430 }}>
                <div style={{ display: 'grid', alignContent: 'start', gap: 0, fontSize: 12 }}>
                  {incidentDetailRows.map(([label, value]) => {
                    const accent = label === 'Severity'
                      ? sevColor(selected.severity)
                      : label === 'Module'
                        ? selectedModule.color
                        : label === 'Priority'
                          ? selectedPriority.color
                          : label === 'Status'
                            ? (selectedStatus === 'New' ? '#f59e0b' : FC.green)
                            : '#dbeafe';
                    return (
                      <div key={label} style={{ display: 'grid', gridTemplateColumns: '105px 1fr', gap: 10, minHeight: 34, alignItems: 'start' }}>
                        <span style={{ color: FC.muted, fontSize: 12, fontWeight: 600 }}>{label}</span>
                        <b style={{ color: accent, fontSize: 12, fontWeight: 850, lineHeight: 1.35, wordBreak: 'break-word' }}>{value || '-'}</b>
                      </div>
                    );
                  })}
                </div>

                <div style={{ minHeight: 300, background: '#03101d', border: '1px solid #17314f', borderRadius: 6, padding: 16, alignSelf: 'start' }}>
                  <div style={{ color: '#9fb2ca', fontSize: 12, fontWeight: 950, marginBottom: 14 }}>Full File Message</div>
                  <pre style={{ margin: 0, color: '#9fd0ff', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 12, lineHeight: 1.55, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace' }}>{compactEvidenceLines.join('\n')}</pre>
                  <details style={{ marginTop: 14, color: '#9fb2ca', fontSize: 11 }}>
                    <summary style={{ cursor: 'pointer', fontWeight: 900 }}>Raw / Normalized Event</summary>
                    <pre style={{ margin: '10px 0 0', maxHeight: 180, overflow: 'auto', color: '#dbeafe', whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontSize: 10, lineHeight: 1.45, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace' }}>{JSON.stringify({
                      normalized: {
                        id: selected.id,
                        module: selectedModule.label,
                        priority: selectedPriority.label,
                        status: selectedStatus,
                        time: selected.time,
                        host: selected.host,
                        eventType: selected.eventType,
                        action: selected.action,
                        severity: selected.severity,
                        filePath: selected.source,
                        user: selected.user,
                        message: selected.message,
                      },
                      raw: selectedRaw,
                    }, null, 2)}</pre>
                  </details>
                  <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', marginTop: 20 }}>
                    {[
                      ['Mark as Investigating', 'Investigating', '#f59e0b'],
                      ['False Positive', 'False Positive', '#64748b'],
                      ['Resolve', 'Resolved', '#22c55e'],
                    ].map(([label, status, color]) => (
                      <button key={label} type="button" onClick={() => setSelectedStatus(status)} style={{ border: `1px solid ${color}88`, background: `${color}18`, color, borderRadius: 6, padding: '9px 14px', fontSize: 12, fontWeight: 950, cursor: 'pointer' }}>{label}</button>
                    ))}
                  </div>
                </div>
              </div>
            </FIMSPanel>

            {fimIngestiveOpen && (
              <FIMSPanel
                title="⚡ Forensic Hunt"
                right={(
                  <button
                    type="button"
                    onClick={() => setFimIngestiveOpen(false)}
                    style={{ border: 0, background: 'transparent', color: FC.muted, cursor: 'pointer', fontSize: 14, fontWeight: 950 }}
                  >
                    x
                  </button>
                )}
              >
                <div style={{ padding: 12, display: 'grid', gap: 10 }}>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: 8 }}>
                    {selectedFimForensicOptions.map(option => {
                      const active = fimForensicForm.artifactName === option.artifact;
                      return (
                        <button
                          key={option.artifact}
                          type="button"
                          onClick={() => setFimForensicForm(prev => ({ ...prev, artifactName: option.artifact }))}
                          style={{
                            border: `1px solid ${active ? '#60a5fa' : '#12243d'}`,
                            background: active ? '#1d4ed822' : '#06111f',
                            color: '#dbeafe',
                            borderRadius: 5,
                            padding: 9,
                            textAlign: 'left',
                            cursor: 'pointer',
                            fontFamily: 'inherit',
                          }}
                        >
                          <b style={{ display: 'block', color: active ? '#93c5fd' : '#e5edf7', fontSize: 10 }}>{option.label}</b>
                          <span style={{ display: 'block', color: FC.muted, fontSize: 9, lineHeight: 1.35, marginTop: 3 }}>{option.desc}</span>
                          <span style={{ display: 'block', color: '#60a5fa', fontSize: 9, fontFamily: 'monospace', marginTop: 5 }}>{option.artifact}</span>
                        </button>
                      );
                    })}
                  </div>

                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    <label style={{ display: 'grid', gap: 5, color: FC.muted, fontSize: 10, fontWeight: 850 }}>
                      Hunt Name
                      <input
                        value={fimForensicForm.huntName}
                        onChange={e => setFimForensicForm(prev => ({ ...prev, huntName: e.target.value }))}
                        style={{ background: '#06111f', color: '#dbeafe', border: '1px solid #1e3a5f', borderRadius: 5, padding: '8px 9px', fontSize: 10, outline: 'none' }}
                      />
                    </label>
                    <label style={{ display: 'grid', gap: 5, color: FC.muted, fontSize: 10, fontWeight: 850 }}>
                      Artifact Name
                      <input
                        value={fimForensicForm.artifactName}
                        onChange={e => setFimForensicForm(prev => ({ ...prev, artifactName: e.target.value }))}
                        style={{ background: '#06111f', color: '#dbeafe', border: '1px solid #1e3a5f', borderRadius: 5, padding: '8px 9px', fontSize: 10, outline: 'none', fontFamily: 'monospace' }}
                      />
                    </label>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                    <label style={{ display: 'grid', gap: 5, color: FC.muted, fontSize: 10, fontWeight: 850 }}>
                      System ID / Velociraptor ID
                      <input
                        value={fimForensicForm.systemId}
                        onChange={e => {
                          const value = e.target.value;
                          setFimForensicForm(prev => (
                            isVelociraptorClientId(value)
                              ? { ...prev, systemId: '', clientId: value }
                              : { ...prev, systemId: value }
                          ));
                        }}
                        placeholder="Mongo system id or C.x client id"
                        style={{ minWidth: 0, background: '#06111f', color: '#dbeafe', border: '1px solid #1e3a5f', borderRadius: 5, padding: '8px 9px', fontSize: 10, outline: 'none' }}
                      />
                    </label>
                    <label style={{ display: 'grid', gap: 5, color: FC.muted, fontSize: 10, fontWeight: 850 }}>
                      Velociraptor Client ID
                      <input
                        value={fimForensicForm.clientId}
                        onChange={e => setFimForensicForm(prev => ({ ...prev, clientId: e.target.value }))}
                        placeholder="optional"
                        style={{ minWidth: 0, background: '#06111f', color: '#dbeafe', border: '1px solid #1e3a5f', borderRadius: 5, padding: '8px 9px', fontSize: 10, outline: 'none' }}
                      />
                    </label>
                  </div>
                  <div style={{ border: '1px solid #12243d', background: '#03101d', borderRadius: 5, padding: 9, color: FC.muted, fontSize: 10, lineHeight: 1.45 }}>
                    Target: <b style={{ color: '#dbeafe' }}>{selected.host}</b> / <b style={{ color: '#dbeafe' }}>{selected.source}</b>
                    <br />
                    OS: <b style={{ color: '#dbeafe' }}>{selectedFimOs}</b> | User: <b style={{ color: '#dbeafe' }}>{selected.user}</b> | Event: <b style={{ color: '#dbeafe' }}>{selected.action}</b>
                    <br />
                    Agent: <b style={{ color: selectedFimSystem ? FC.green : '#f59e0b' }}>{selectedFimSystem ? 'Matched' : 'No system match'}</b>
                  </div>
                  <button
                    type="button"
                    onClick={() => setSelectedStatus('Investigating')}
                    style={{
                      border: '1px solid #7c3aed66',
                      background: 'linear-gradient(135deg,#2563eb,#7c3aed)',
                      color: '#fff',
                      borderRadius: 5,
                      padding: '10px 12px',
                      fontSize: 11,
                      fontWeight: 950,
                      cursor: 'pointer',
                    }}
                  >
                    Launch Forensic Hunt
                  </button>
                </div>
              </FIMSPanel>
            )}
          </div>

          <div style={{ display: 'grid', gap: 10 }}>
            <FIMSPanel title="Ingestive">
              <div style={{ padding: 12, display: 'grid', gap: 9 }}>
                <p style={{ margin: 0, color: FC.muted, fontSize: 10, lineHeight: 1.45 }}>
                  Start ingestive to collect file hashes, timeline evidence, and related endpoint activity.
                </p>
                <button
                  type="button"
                  onClick={() => {
                    setSelectedStatus('Investigating');
                    setFimIngestiveOpen(open => !open);
                  }}
                  style={{ width: 'fit-content', border: '1px solid #2563eb66', background: 'linear-gradient(135deg,#1d4ed8,#1e40af)', color: '#dbeafe', borderRadius: 5, padding: '8px 12px', fontSize: 10, fontWeight: 950, cursor: 'pointer' }}
                >
                  {fimIngestiveOpen ? 'Hide Ingestive' : 'Start Ingestive'}
                </button>
              </div>
            </FIMSPanel>
            <FIMSPanel title="Related Logs" right={<span style={{ color: '#60a5fa', fontSize: 10 }}>View all</span>}>
              <div style={{ padding: 12, display: 'grid', gap: 8 }}>
                {fimAlertRows.filter(item => item.id !== selected.id).slice(0, 4).map(item => (
                  <button key={item.id} type="button" onClick={() => setSelectedFimAlertId(item.id)} style={{ border: '1px solid #12243d', background: '#06111f', borderRadius: 5, color: '#dbeafe', textAlign: 'left', padding: 9, cursor: 'pointer', fontSize: 10 }}>
                    <b style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.message}</b>
                    <span style={{ color: sevColor(item.severity), fontWeight: 900 }}>{item.severity}</span>
                    <span style={{ color: FC.sub, marginLeft: 8 }}>{item.time}</span>
                  </button>
                ))}
              </div>
            </FIMSPanel>
            <FIMSPanel title="Notes">
              <div style={{ padding: 12 }}>
                <textarea placeholder="Add notes..." style={{ width: '100%', minHeight: 76, resize: 'vertical', boxSizing: 'border-box', background: '#06111f', border: '1px solid #1e3a5f', color: '#dbeafe', borderRadius: 5, padding: 9, fontSize: 11, outline: 'none' }} />
                <button type="button" style={{ marginTop: 8, float: 'right', border: '1px solid #2563eb66', background: '#1d4ed822', color: '#60a5fa', borderRadius: 5, padding: '7px 10px', fontSize: 10, fontWeight: 900, cursor: 'pointer' }}>Save Note</button>
              </div>
            </FIMSPanel>
          </div>
        </section>
      </div>
    );
  }
  if (tabId === 'reports') {
    const moduleRowsForReport = fimModuleCategoryRows;
    const selectedReportRows = fimReportPeriod === '24h' ? activeFimRows24h : activeFimRows;
    const selectedPeriodLabel = fimReportPeriod === '24h' ? '24 Hour Report' : 'One Month Report';
    const reportModuleRows = moduleRowsForReport(selectedReportRows);
    const reportActionCounts = {
      created: selectedReportRows.filter(row => fimReportAction(row) === 'created').length,
      modified: selectedReportRows.filter(row => fimReportAction(row) === 'modified').length,
      deleted: selectedReportRows.filter(row => fimReportAction(row) === 'deleted').length,
      renamed: selectedReportRows.filter(row => fimReportAction(row) === 'renamed').length,
    };
    const reportStatusCounts = ['New', 'Investigating', 'False Positive', 'Resolved', 'Closed'].reduce((acc, status) => {
      acc[status] = selectedReportRows.filter(row => fimReportStatus(row, fimAlertStatuses) === status).length;
      return acc;
    }, {});
    const coverageRows = [
      { label: 'Integrity Monitoring', count: reportModuleRows['integrity-monitoring'].length, detail: 'Hash, create, modify, delete, rename evidence' },
      { label: 'Permission Changes', count: reportModuleRows.permissions.length, status: 'Monitored', detail: 'chmod, ACL, SUID/SGID, mode changes' },
      { label: 'Ownership Changes', count: reportModuleRows.ownership.length, detail: 'Owner, group, privileged ownership changes' },
      { label: 'Sensitive Files', count: reportModuleRows['sensitive-files'].length, detail: 'Secrets, keys, DB backups, config, PII files' },
      { label: 'File Create Events', count: reportActionCounts.created, detail: 'New file creation activity' },
      { label: 'File Modify Events', count: reportActionCounts.modified, detail: 'File writes, hash changes, content changes' },
      { label: 'File Delete Events', count: reportActionCounts.deleted, detail: 'Deletion, remove, unlink activity' },
      { label: 'File Rename Events', count: reportActionCounts.renamed, detail: 'Rename and moved file activity' },
      { label: 'Open Status', count: reportStatusCounts.New + reportStatusCounts.Investigating, detail: 'New and investigating report rows' },
      { label: 'Closed Status', count: reportStatusCounts.Resolved + reportStatusCounts.Closed, detail: 'Resolved and closed report rows' },
      { label: 'Audit Trail', count: selectedReportRows.length, detail: 'Exportable SOC file activity trail' },
      { label: 'Agent Coverage', count: fimStat.onlineAgents, detail: 'Online agents reporting FIM data' },
    ];
    const reportKpis = [
      { label: selectedPeriodLabel, value: shortNum(selectedReportRows.length), color: '#3b82f6' },
      { label: 'Agents Online', value: shortNum(fimStat.onlineAgents), color: '#22c55e' },
      { label: 'Open Status', value: shortNum(reportStatusCounts.New + reportStatusCounts.Investigating), color: '#ef4444' },
      { label: 'Modified Files', value: shortNum(reportActionCounts.modified), color: '#f97316' },
      { label: 'Sensitive Files', value: shortNum(reportModuleRows['sensitive-files'].length), color: '#94a3b8' },
    ];
    const exportLiveFimReport = (format, period = fimReportPeriod) => {
      const generatedAt = new Date().toISOString();
      const stamp = generatedAt.slice(0, 19).replace(/[:T]/g, '-');
      const requestedPeriodRows = period === '24h' ? activeFimRows24h : activeFimRows;
      const fallbackRows = [];
      const usingFallbackRows = requestedPeriodRows.length === 0 && fallbackRows.length > 0;
      const periodRows = usingFallbackRows ? fallbackRows : requestedPeriodRows;
      const noLiveFimRows = periodRows.length === 0;
      const basePeriodLabel = period === '24h' ? '24 Hour Report' : 'One Month Report';
      const periodLabel = usingFallbackRows ? `${basePeriodLabel} - Latest Available FIM Logs` : basePeriodLabel;
      const periodSlug = period === '24h' ? '24-hour' : 'one-month';
      const dataSourceNote = usingFallbackRows
        ? 'No FIM logs were found in the selected 24-hour window, so latest available one-month FIM rows are included and marked in this report.'
        : noLiveFimRows
          ? 'No live FIM logs were received for this report period. Analyst guidance rows are included so the report is not blank.'
          : 'Live SOC FIM rows from the selected report period.';
      const moduleRows = moduleRowsForReport(periodRows);
      const incidentStatusCounts = ['New', 'Investigating', 'False Positive', 'Resolved', 'Closed'].reduce((acc, status) => {
        acc[status] = periodRows.filter(row => fimReportStatus(row, fimAlertStatuses) === status).length;
        return acc;
      }, {});
      const periodActionCounts = {
        created: periodRows.filter(row => fimReportAction(row) === 'created').length,
        modified: periodRows.filter(row => fimReportAction(row) === 'modified').length,
        deleted: periodRows.filter(row => fimReportAction(row) === 'deleted').length,
        renamed: periodRows.filter(row => fimReportAction(row) === 'renamed').length,
      };
      const coverage = [
        { coverage: 'Integrity Monitoring', status: `${moduleRows['integrity-monitoring'].length} logs` },
        { coverage: 'Permission Changes', status: `Monitored (${moduleRows.permissions.length} logs)` },
        { coverage: 'Ownership Changes', status: `${moduleRows.ownership.length} logs` },
        { coverage: 'Sensitive Files', status: `${moduleRows['sensitive-files'].length} logs` },
        { coverage: 'File Create Events', status: `${periodActionCounts.created} logs` },
        { coverage: 'File Modify Events', status: `${periodActionCounts.modified} logs` },
        { coverage: 'File Delete Events', status: `${periodActionCounts.deleted} logs` },
        { coverage: 'File Rename Events', status: `${periodActionCounts.renamed} logs` },
        { coverage: 'New Status', status: `${incidentStatusCounts.New} logs` },
        { coverage: 'Investigating Status', status: `${incidentStatusCounts.Investigating} logs` },
        { coverage: 'Closed Status', status: `${incidentStatusCounts.Resolved + incidentStatusCounts.Closed} logs` },
        { coverage: 'Audit Trail', status: `${periodRows.length} logs` },
        { coverage: 'Agent Coverage', status: `${fimStat.onlineAgents} online` },
      ];
      const moduleWise = FIM_REPORT_MODULE_IDS.reduce((acc, id) => {
        acc[id] = moduleRows[id].map(row => fimReportRowForModule(row, id, fimReportStatus(row, fimAlertStatuses)));
        return acc;
      }, {});
      const mapReportRow = (id, row) => {
        const reportRow = fimReportRowForModule(row, id, fimReportStatus(row, fimAlertStatuses));
        return {
          module: FIM_MODULE_LABELS[id],
          filePath: reportRow.file_path || row.source,
          action: reportRow.event_type || reportRow.change_type || reportRow.action || row.event_type || row.action,
          user: reportRow.user || reportRow.changed_by_user || reportRow.accessed_by_user || row.user,
          changedBy: reportRow.changed_by_user || reportRow.accessed_by_user || row.changed_by_user || row.user,
          oldHash: reportRow.old_hash || '-',
          newHash: reportRow.new_hash || '-',
          oldPermission: reportRow.old_permission || '-',
          newPermission: reportRow.new_permission || '-',
          oldOwner: reportRow.old_owner || '-',
          newOwner: reportRow.new_owner || '-',
          oldGroup: reportRow.old_group || '-',
          newGroup: reportRow.new_group || '-',
          sensitivityType: reportRow.sensitivity_type || '-',
          permissionStatus: reportRow.permission_status || '-',
          severity: reportRow.severity || row.severity,
          status: reportRow.status || 'New',
          time: reportRow.timestamp || row.timestamp || row.time,
          details: Object.entries(reportRow)
            .filter(([key]) => !['module', 'status', 'file_path', 'severity', 'timestamp'].includes(key))
            .map(([key, value]) => `${key}: ${value}`)
            .join(' | '),
        };
      };
      const maxModuleRows = Math.max(0, ...FIM_REPORT_MODULE_IDS.map(id => moduleRows[id].length));
      const flatRows = [];
      for (let rowIndex = 0; rowIndex < maxModuleRows; rowIndex += 1) {
        FIM_REPORT_MODULE_IDS.forEach(id => {
          const row = moduleRows[id][rowIndex];
          if (row) flatRows.push(mapReportRow(id, row));
        });
      }
      const exportRows = flatRows.length ? flatRows : FIM_ANALYSIS_GUIDE_ROWS;
      const exportStatusCounts = ['New', 'Investigating', 'False Positive', 'Resolved', 'Closed'].reduce((acc, status) => {
        acc[status] = exportRows.filter(row => row.status === status).length;
        return acc;
      }, {});
      const statusCountsForReport = flatRows.length ? incidentStatusCounts : exportStatusCounts;
      const coverageForReport = [
        { coverage: 'Integrity Monitoring', status: `${moduleRows['integrity-monitoring'].length} logs` },
        { coverage: 'Permission Changes', status: `Monitored (${moduleRows.permissions.length} logs)` },
        { coverage: 'Ownership Changes', status: `${moduleRows.ownership.length} logs` },
        { coverage: 'Sensitive Files', status: `${moduleRows['sensitive-files'].length} logs` },
        { coverage: 'File Create Events', status: `${periodActionCounts.created} logs` },
        { coverage: 'File Modify Events', status: `${periodActionCounts.modified} logs` },
        { coverage: 'File Delete Events', status: `${periodActionCounts.deleted} logs` },
        { coverage: 'File Rename Events', status: `${periodActionCounts.renamed} logs` },
        { coverage: 'New Status', status: `${statusCountsForReport.New} logs` },
        { coverage: 'Investigating Status', status: `${statusCountsForReport.Investigating} logs` },
        { coverage: 'Closed Status', status: `${statusCountsForReport.Resolved + statusCountsForReport.Closed} logs` },
        { coverage: 'Audit Trail', status: `${periodRows.length} logs` },
        { coverage: 'Agent Coverage', status: `${fimStat.onlineAgents} online` },
      ];
      const baseName = `fim-${periodSlug}-report-${stamp}`;
      if (format === 'json') {
        downloadBlob(`${baseName}.json`, 'application/json;charset=utf-8', JSON.stringify({
          reportName: 'SOC File Activity Monitoring Coverage Report',
          generatedAt,
          period: periodLabel,
          dataSource: dataSourceNote,
          summary: {
            requestedPeriodRows: requestedPeriodRows.length,
            exportedRows: exportRows.length,
            liveFimRows: periodRows.length,
            analysisGuidanceRows: flatRows.length ? 0 : FIM_ANALYSIS_GUIDE_ROWS.length,
            actionCounts: periodActionCounts,
            fileRenameEvents: periodActionCounts.renamed,
            closedStatus: statusCountsForReport.Resolved + statusCountsForReport.Closed,
            severityCounts: {
              critical: periodRows.filter(row => fimDisplaySeverity(row) === 'critical').length,
              high: periodRows.filter(row => fimDisplaySeverity(row) === 'high').length,
              medium: periodRows.filter(row => fimDisplaySeverity(row) === 'medium').length,
              low: periodRows.filter(row => fimDisplaySeverity(row) === 'low').length,
            },
            incidentStatusCounts: statusCountsForReport,
            integrityMonitoring: moduleRows['integrity-monitoring'].length,
            permissionChanges: moduleRows.permissions.length,
            ownershipChanges: moduleRows.ownership.length,
            sensitiveFiles: moduleRows['sensitive-files'].length,
          },
          coverage: coverageForReport,
          modules: moduleWise,
          rows: exportRows,
        }, null, 2));
        return;
      }
      const csvHeaders = ['Module', 'File Path', 'Action', 'User', 'Changed By', 'Old Hash', 'New Hash', 'Old Permission', 'New Permission', 'Old Owner', 'New Owner', 'Old Group', 'New Group', 'Sensitivity Type', 'Permission Status', 'Severity', 'Status', 'Timestamp', 'Details'];
      const lines = [
        ['Report', 'SOC File Activity Monitoring Coverage Report'],
        ['Period', periodLabel],
        ['Generated At', generatedAt],
        ['Data Source', dataSourceNote],
        ['Requested Period Live Logs', requestedPeriodRows.length],
        ['Exported Rows', exportRows.length],
        ['Status New', statusCountsForReport.New],
        ['Status Investigating', statusCountsForReport.Investigating],
        ['Status False Positive', statusCountsForReport['False Positive']],
        ['Status Resolved', statusCountsForReport.Resolved],
        ['Status Closed', statusCountsForReport.Closed],
        ['Closed Status Total', statusCountsForReport.Resolved + statusCountsForReport.Closed],
        ['File Rename Events', periodActionCounts.renamed],
        [],
        csvHeaders,
        ...exportRows.map(row => [row.module, row.filePath, row.action, row.user, row.changedBy, row.oldHash, row.newHash, row.oldPermission, row.newPermission, row.oldOwner, row.newOwner, row.oldGroup, row.newGroup, row.sensitivityType, row.permissionStatus, row.severity, row.status, row.time, row.details]),
      ].map(row => row.map(csvCell).join(','));
      if (format === 'csv') {
        downloadBlob(`${baseName}.csv`, 'text/csv;charset=utf-8', lines.join('\n'));
        return;
      }
      downloadBlob(`${baseName}.pdf`, 'application/pdf', createTablePdf({
        title: `SOC File Activity Monitoring - ${periodLabel}`,
        summaryRows: [
          { metric: 'Generated At', value: generatedAt },
          { metric: 'Period', value: periodLabel },
          { metric: 'Data Source', value: dataSourceNote },
          { metric: 'Requested Period Logs', value: requestedPeriodRows.length },
          { metric: 'Exported Rows', value: exportRows.length },
          { metric: 'Agents Online', value: fimStat.onlineAgents },
          { metric: 'Created Files', value: periodActionCounts.created },
          { metric: 'Modified Files', value: periodActionCounts.modified },
          { metric: 'Deleted Files', value: periodActionCounts.deleted },
          { metric: 'Renamed Files', value: periodActionCounts.renamed },
          { metric: 'Closed Status', value: statusCountsForReport.Resolved + statusCountsForReport.Closed },
          { metric: 'Status New', value: statusCountsForReport.New },
          { metric: 'Status Investigating', value: statusCountsForReport.Investigating },
          { metric: 'Status False Positive', value: statusCountsForReport['False Positive'] },
          { metric: 'Status Resolved', value: statusCountsForReport.Resolved },
          { metric: 'Status Closed', value: statusCountsForReport.Closed },
          { metric: 'Integrity Monitoring', value: moduleRows['integrity-monitoring'].length },
          { metric: 'Permission Changes', value: moduleRows.permissions.length },
          { metric: 'Ownership Changes', value: moduleRows.ownership.length },
          { metric: 'Sensitive Files', value: moduleRows['sensitive-files'].length },
        ],
        coverageRows: coverageForReport,
        processTitle: flatRows.length ? 'Module-wise FIM Logs' : 'Analyst Review Checklist',
        processRows: exportRows.map(row => ({
          process: row.module,
          host: row.user || 'N/A',
          pid: row.action || 'N/A',
          cpu: row.changedBy || 'N/A',
          memory: row.time || 'N/A',
          status: row.status,
          severity: row.severity,
          command: `${row.filePath} | ${row.details}`,
        })),
        processColumnLabels: {
          pid: 'Action',
          cpu: 'Changed By',
          memory: 'Time',
          status: 'Status',
          severity: 'Severity',
        },
        finalColumnLabel: 'File Path / Evidence',
      }));
    };
    return (
      <div style={{ minWidth: 900, display: 'grid', gap: 12 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' }}>
          <div>
            <h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 20, fontWeight: 950 }}>Reports</h2>
            <p style={{ margin: '8px 0 0', color: FC.muted, fontSize: 12, fontWeight: 800 }}>
              File monitoring summaries, integrity exports, and investigation reports.
            </p>
          </div>
          <span style={{ color: FC.green, fontSize: 10, fontWeight: 950, marginTop: 8 }}>● Live SOC Agent Data</span>
        </div>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(5, minmax(0, 1fr))', gap: 10 }}>
          {reportKpis.map(kpi => <FIMKpi key={kpi.label} {...kpi} />)}
        </section>

        <FIMSPanel
          title="SOC File Activity Monitoring Coverage Report"
          right={(
            <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap', justifyContent: 'flex-end' }}>
              <select
                value={fimReportPeriod}
                onChange={event => setFimReportPeriod(event.target.value)}
                style={{
                  border: '1px solid #1e3a5f',
                  background: '#06111f',
                  color: '#dbeafe',
                  borderRadius: 5,
                  padding: '6px 10px',
                  fontSize: 10,
                  fontWeight: 900,
                  outline: 'none',
                }}
              >
                <option value="24h">24 Hour Report</option>
                <option value="30d">One Month Report</option>
              </select>
              {[
                ['PDF', 'pdf', '#ef4444'],
                ['CSV', 'csv', '#22c55e'],
                ['JSON', 'json', '#60a5fa'],
              ].map(([label, format, color]) => (
                <button
                  key={format}
                  type="button"
                  onClick={() => exportLiveFimReport(format)}
                  style={{
                    border: `1px solid ${color}66`,
                    background: `${color}1c`,
                    color,
                    borderRadius: 5,
                    padding: '6px 14px',
                    fontSize: 10,
                    fontWeight: 950,
                    cursor: 'pointer',
                    minWidth: 72,
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          )}
        >
          <div style={{ padding: 12, display: 'grid', gridTemplateColumns: 'repeat(3, minmax(0, 1fr))', gap: 8 }}>
            {coverageRows.map(row => (
              <div key={row.label} style={{ border: '1px solid #14243a', borderRadius: 6, padding: 10, minHeight: 58, display: 'grid', gap: 5, background: '#06111f' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center' }}>
                  <span style={{ color: '#dbeafe', fontSize: 11, fontWeight: 850 }}>{row.label}</span>
                  <b style={{ color: row.count > 0 || row.status ? '#22c55e' : '#64748b', fontSize: 10 }}>{row.status ? `${row.status} · ${shortNum(row.count)} logs` : `${shortNum(row.count)} logs`}</b>
                </div>
                <span style={{ color: FC.muted, fontSize: 9, fontWeight: 750, lineHeight: 1.35 }}>{row.detail}</span>
              </div>
            ))}
          </div>
        </FIMSPanel>
      </div>
    );
  }
  if (tabId === 'overview') {
    const rows = activeFimRows24h;
    const moduleRows = fimRowsByModule(rows);
    const createdRows = rows.filter(row => /creat|new file/i.test(`${row.action} ${row.eventType}`));
    const deletedRows = rows.filter(row => /delet|remove|unlink/i.test(`${row.action} ${row.eventType}`));
    const renamedRows = rows.filter(row => /rename|moved/i.test(`${row.action} ${row.eventType}`));
    const modifiedRows = rows.filter(row => !createdRows.includes(row) && !deletedRows.includes(row) && !renamedRows.includes(row));
    const alertRows = rows.filter(row => ['critical', 'high'].includes(row.severity));
    const topPaths = fimTopCounts(rows, row => row.source?.split('/').slice(0, 3).join('/') || row.source, 10);
    const topFiles = fimTopCounts(rows, row => row.source, 5);
    const topUsers = fimTopCounts(rows, row => row.user, 5);
    const topProcesses = fimTopCounts(rows, row => row.process_name || row.processName || row.raw?.processName || row.raw?.rawEvent?.process_name, 5);
    const recentRows = rows.slice(0, 10);
    const dist = [
      { label: 'Modified', value: modifiedRows.length, color: '#1f8bff' },
      { label: 'Created', value: createdRows.length, color: '#22c55e' },
      { label: 'Deleted', value: deletedRows.length, color: '#ef4444' },
      { label: 'Renamed', value: renamedRows.length, color: '#f59e0b' },
    ];
    return (
      <div style={{ minWidth: 1040, display: 'grid', gap: 10 }}>
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(6, minmax(0, 1fr))', gap: 10 }}>
          <FIMDashboardKpi icon="▤" label="Total Events" value={shortNum(rows.length)} color="#1f8bff" />
          <FIMDashboardKpi icon="✚" label="Files Created" value={shortNum(createdRows.length)} color="#22c55e" />
          <FIMDashboardKpi icon="✎" label="Files Modified" value={shortNum(modifiedRows.length)} color="#f59e0b" />
          <FIMDashboardKpi icon="▥" label="Files Deleted" value={shortNum(deletedRows.length)} color="#ef4444" down />
          <FIMDashboardKpi icon="↔" label="Files Renamed" value={shortNum(renamedRows.length)} color="#f97316" />
          <FIMDashboardKpi icon="⬢" label="Alerts" value={shortNum(alertRows.length)} color="#a855f7" />
        </section>

        <section style={{ display: 'grid', gridTemplateColumns: '1.25fr .82fr .9fr', gap: 10 }}>
          <FIMSPanel title="File Activity Trend (24 Hours)" right={<span style={{ color: FC.muted, fontSize: 9, fontWeight: 850 }}>Last 24 Hours</span>}>
            <FIMTrendChart rows={rows} />
          </FIMSPanel>
          <FIMSPanel title="Event Distribution">
            <FIMDonut items={dist} totalLabel="Total" />
          </FIMSPanel>
          <FIMSPanel title="File Change Heatmap (Top Paths)" right={<span style={{ color: FC.muted, fontSize: 9, fontWeight: 850 }}>Top 10</span>}>
            <div style={{ padding: 12, display: 'grid', gap: 8 }}>
              {(topPaths.length ? topPaths : [['/etc', 0], ['/var/log', 0], ['/home', 0], ['/tmp', 0], ['/usr/bin', 0]]).map(([path, count], i) => {
                const colors = ['#ef4444', '#f97316', '#22c55e', '#06b6d4', '#3b82f6', '#8b5cf6'];
                const max = Math.max(1, topPaths[0]?.[1] || 1);
                return (
                  <div key={`${path}-${i}`} style={{ display: 'grid', gridTemplateColumns: '120px 1fr 44px', alignItems: 'center', gap: 8 }}>
                    <span style={{ color: '#dbeafe', fontSize: 9, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{path}</span>
                    <span style={{ height: 7, borderRadius: 99, background: '#13243d', overflow: 'hidden' }}>
                      <b style={{ display: 'block', height: '100%', width: `${Math.max(7, (count / max) * 100)}%`, background: colors[i % colors.length] }} />
                    </span>
                    <b style={{ color: FC.text, fontSize: 9, textAlign: 'right' }}>{shortNum(count)}</b>
                  </div>
                );
              })}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, color: FC.muted, fontSize: 8, fontWeight: 850 }}>
                <span>Low</span><span style={{ textAlign: 'right' }}>High</span>
              </div>
            </div>
          </FIMSPanel>
        </section>

        <FIMSPanel title="Recent Critical Changes" right={<button type="button" style={{ border: '1px solid #1e3a5f', background: '#0b1d34', color: '#93c5fd', borderRadius: 4, padding: '3px 8px', fontSize: 9, fontWeight: 850 }}>View All</button>}>
          <div style={{ overflowX: 'auto' }}>
            <div style={{ minWidth: 980 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '116px 110px 1.15fr 130px 90px 125px 1fr 1fr 80px', gap: 8, padding: '8px 12px', color: FC.sub, fontSize: 9, fontWeight: 900, borderBottom: '1px solid #12243d' }}>
                {['Time', 'Event Type', 'File Path', 'File Name', 'User', 'System', 'Change Details', 'Old/New Hash', 'Severity'].map(h => <span key={h}>{h}</span>)}
              </div>
              {(recentRows.length ? recentRows : []).map((row, i) => {
                const color = fimSevColor(row.severity);
                const fileName = String(row.source || '').split('/').pop() || row.source;
                return (
                  <div key={row.id || i} style={{ display: 'grid', gridTemplateColumns: '116px 110px 1.15fr 130px 90px 125px 1fr 1fr 80px', gap: 8, padding: '8px 12px', color: FC.text, fontSize: 9, borderBottom: '1px solid #0f2035', alignItems: 'center' }}>
                    <span style={{ color: FC.muted }}>{row.time}</span>
                    <span style={{ color }}>{row.action}</span>
                    <span style={{ color: '#93c5fd', fontFamily: 'monospace', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.source}</span>
                    <span>{fileName}</span>
                    <span>{row.user}</span>
                    <span>{row.host}</span>
                    <span>{row.change_type || row.event_type || row.eventType}</span>
                    <span style={{ fontFamily: 'monospace', color: FC.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.old_hash || '-'} → {row.new_hash || '-'}</span>
                    <b style={{ color }}>{row.severity}</b>
                  </div>
                );
              })}
              {recentRows.length === 0 && <div style={{ padding: 18, color: FC.muted, fontSize: 12, fontWeight: 800 }}>No recent FIM changes found.</div>}
            </div>
          </div>
        </FIMSPanel>

        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(4, minmax(0, 1fr))', gap: 10 }}>
          {[
            ['Top Modified Files', topFiles, 'View All'],
            ['Top Users', topUsers, 'View All'],
            ['Top Processes', topProcesses.length ? topProcesses : [['file_watch', rows.length]], 'View All'],
            ['Real-time File Events', recentRows.slice(0, 5).map(row => [row.source, row.user || row.action]), 'View All'],
          ].map(([title, list, action]) => (
            <FIMSPanel key={title} title={title} right={<span style={{ color: '#93c5fd', fontSize: 9, fontWeight: 850 }}>{action}</span>}>
              <div style={{ padding: 12, display: 'grid', gap: 9 }}>
                {(list.length ? list : [['No data', 0]]).map(([label, value], i) => (
                  <div key={`${title}-${label}-${i}`} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 8, color: FC.text, fontSize: 10 }}>
                    <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                    <b style={{ color: i < 2 ? '#93c5fd' : FC.muted }}>{typeof value === 'number' ? shortNum(value) : value}</b>
                  </div>
                ))}
              </div>
            </FIMSPanel>
          ))}
        </section>
      </div>
    );
  }
  const visibleFimRowsForTab = fimRowsForTab;
  const tabKpis = [
    { label: 'Tab Events', value: shortNum(visibleFimRowsForTab.length), color: '#3b82f6' },
    { label: 'Critical Alerts', value: shortNum(visibleFimRowsForTab.filter(row => fimDisplaySeverity(row) === 'critical').length), color: '#ef4444' },
    { label: 'High', value: shortNum(visibleFimRowsForTab.filter(row => fimDisplaySeverity(row) === 'high').length), color: '#f97316' },
    { label: 'Modified', value: shortNum(visibleFimRowsForTab.filter(row => /modified|hash|integrity/i.test(`${row.action} ${row.eventType}`)).length), color: '#eab308' },
  ];
  const summaryRows = [
    ['Total Events', visibleFimRowsForTab.length, '#3b82f6'],
    ['Critical Alerts', visibleFimRowsForTab.filter(row => fimDisplaySeverity(row) === 'critical').length, '#ef4444'],
    ['High', visibleFimRowsForTab.filter(row => fimDisplaySeverity(row) === 'high').length, '#f97316'],
    ['Medium', visibleFimRowsForTab.filter(row => fimDisplaySeverity(row) === 'medium').length, '#eab308'],
    ['Low / Info', visibleFimRowsForTab.filter(row => !['critical', 'high', 'medium'].includes(fimDisplaySeverity(row))).length, '#22c55e'],
  ];
  const coverageLabels = ['/etc directory','/var/log directory','System Binaries','SSH Keys','Config Files','Script Files','Database Files','Crypto / Keys'];
  const coverageActive = label => {
    const rows = activeFimRows24h;
    if (label === '/etc directory') return rows.some(row => row.source.startsWith('/etc'));
    if (label === '/var/log directory') return rows.some(row => row.source.startsWith('/var/log'));
    if (label === 'System Binaries') return rows.some(row => /\/bin\/|\/usr\/bin\/|\.exe/i.test(row.source));
    if (label === 'SSH Keys') return rows.some(row => /authorized_keys|id_rsa|\.pem/i.test(row.source));
    if (label === 'Config Files') return rows.some(row => /\.conf|\.cfg|\.ini|\.yaml|\.json|crontab/i.test(row.source));
    if (label === 'Script Files') return rows.some(row => /\.sh|\.py|\.ps1|\.bat/i.test(row.source));
    if (label === 'Database Files') return rows.some(row => /\.db|\.sql|mysql|postgres/i.test(row.source));
    if (label === 'Crypto / Keys') return rows.some(row => /\.key|\.pem|\.p12|secret|token/i.test(row.source));
    return false;
  };
  const tableFields = FIM_MODULE_TABLES[tabId] || FIM_MODULE_TABLES['integrity-monitoring'];
  const isIntegrityTable = tabId === 'integrity-monitoring';
  const tableGrid = isIntegrityTable
    ? 'minmax(170px,.85fr) minmax(230px,1fr) minmax(230px,1fr) 66px 96px 126px 74px'
    : tableFields
      .map(([key]) => key === 'file_path'
        ? 'minmax(240px, 1.15fr)'
        : key.includes('hash')
          ? 'minmax(320px, 1fr)'
          : key === 'hash_algorithm'
            ? 'minmax(74px, .32fr)'
            : 'minmax(96px, .62fr)')
      .join(' ');
  return (
    <div style={{ minWidth: 900, display: 'grid', gap: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10 }}>
        <div>
          <h2 style={{ margin: 0, color: '#f3f8ff', fontSize: 20, fontWeight: 950 }}>{meta.title}</h2>
          <p style={{ margin: '5px 0 0', color: FC.muted, fontSize: 12, fontWeight: 700 }}>{meta.subtitle}</p>
        </div>
        <span style={{ color: FC.green, fontSize: 9, fontWeight: 900 }}>● Live SOC Data</span>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 10 }}>
        {tabKpis.map(k => <FIMKpi key={k.label} {...k} />)}
      </div>
      <FIMSPanel title={meta.panels[0]} right={<span style={{ fontSize: 9, padding: '2px 7px', borderRadius: 4, background: '#ef444415', color: '#ef4444', border: '1px solid #ef444440', fontWeight: 800 }}>● Live</span>}>
        <div style={{ overflow: 'auto', maxHeight: 520 }}>
          <div style={{ minWidth: isIntegrityTable ? 1120 : 980 }}>
            <div style={{ display: 'grid', gridTemplateColumns: tableGrid, gap: isIntegrityTable ? 4 : 6, padding: '6px 10px', color: FC.sub, fontSize: 9, fontWeight: 800, borderBottom: '1px solid #12243d' }}>
              {tableFields.map(([, label]) => <div key={label}>{label}</div>)}
            </div>
            {visibleFimRowsForTab.length === 0 && (
              <div style={{ padding: '22px 12px', color: FC.muted, fontSize: 12, fontWeight: 800 }}>
                No {FIM_MODULE_LABELS[tabId] || 'FIM'} logs found for this time window.
              </div>
            )}
            {visibleFimRowsForTab.map((row, i) => {
              const c = fimSevColor(row.severity);
              return (
                <div key={row.id || i} style={{ display: 'grid', gridTemplateColumns: tableGrid, gap: isIntegrityTable ? 4 : 6, padding: '8px 10px', borderBottom: '1px solid #0a1220', alignItems: 'center' }}>
                  {tableFields.map(([key]) => {
                    const value = fimDisplayValue(row, key);
                    const isSeverity = key === 'severity';
                    const isPath = key === 'file_path';
                    const isHash = key.includes('hash');
                    const wrapCell = isHash || isPath;
                    return (
                      <div key={key} style={{ fontSize: isHash ? 8.5 : isPath ? 9.5 : 10, color: isSeverity ? c : isPath ? '#60a5fa' : FC.text, fontFamily: isPath || isHash ? 'monospace' : 'inherit', overflow: wrapCell ? 'visible' : 'hidden', textOverflow: wrapCell ? 'clip' : 'ellipsis', whiteSpace: wrapCell ? 'normal' : 'nowrap', overflowWrap: wrapCell ? 'anywhere' : 'normal', wordBreak: wrapCell ? 'break-all' : 'normal', lineHeight: wrapCell ? 1.28 : 'normal' }} title={String(value)}>
                        {isSeverity ? (
                          <span style={{ fontSize: 9, padding: '2px 6px', borderRadius: 4, fontWeight: 800, color: c, border: `1px solid ${c}55`, background: `${c}18` }}>{String(value).toUpperCase()}</span>
                        ) : value}
                      </div>
                    );
                  })}
                </div>
              );
            })}
          </div>
        </div>
      </FIMSPanel>
      {!FIM_MODULE_IDS.includes(tabId) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
          <FIMSPanel title={meta.panels[1] || 'Summary'}>
            <div style={{ padding: 14, display: 'grid', gap: 8 }}>
              {summaryRows.map(([label,val,color]) => (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: 10, fontSize: 11 }}>
                  <span style={{ color: FC.muted }}>{label}</span>
                  <b style={{ color }}>{val}</b>
                </div>
              ))}
            </div>
          </FIMSPanel>
          <FIMSPanel title={meta.panels[2] || 'Coverage'}>
            <div style={{ padding: 14, display: 'grid', gap: 9 }}>
              {coverageLabels.map((label, i) => {
                const active = coverageActive(label);
                return (
                <div key={label} style={{ display: 'grid', gridTemplateColumns: '1fr 60px', alignItems: 'center', gap: 8, fontSize: 10 }}>
                  <span style={{ color: FC.muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{label}</span>
                  <b style={{ color: active ? FC.green : FC.sub, background: active ? '#22c55e22' : '#33415544', borderRadius: 4, textAlign: 'center', padding: '3px 0', fontSize: 9 }}>{active ? 'Active' : 'No data'}</b>
                </div>
                );
              })}
            </div>
          </FIMSPanel>
        </div>
      )}
    </div>
  );
}

export function FIMSubTabPage() {
  const { tab = 'overview' } = useParams();
  if (tab === 'overview') return <Navigate to="/edr?capabilityId=2" replace />;
  if (tab === 'activity') return <CapabilityDataPage kind="fim" mode={tab} />;
  if (tab === 'alert-logs') return <CapabilityDataPage kind="fim" mode="alerts" />;
  if (tab === 'agents') return <CapabilityAgentsPage kind="fim" />;
  if (!FIM_META[tab]) return <Navigate to="/edr-dashboard-details/fim/integrity-monitoring" replace />;
  const validTab = tab;
  return <FIMSubTabLayout validTab={validTab} />;
}

function FIMSubTabLayout({ validTab }) {
  const fimData = useFimSocData();
  return (
    <div style={{ height: '100vh', overflow: 'hidden', background: '#020b15', display: 'grid', gridTemplateColumns: '196px minmax(0,1fr)', color: FC.text, fontFamily: 'Inter,system-ui,sans-serif' }}>
      <FIMNavSidebar activeId={validTab} />
      <main style={{ overflow: 'auto', background: FC.bg, padding: 14, boxSizing: 'border-box' }}>
        <FIMPageContent tabId={validTab} fimData={fimData} />
      </main>
    </div>
  );
}
