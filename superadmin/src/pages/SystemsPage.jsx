import { useEffect, useState } from 'react';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import { validateSystemName } from '../utils/validate';

// ── Constants ─────────────────────────────────────────────────────────────────
const ONLINE_THRESHOLD_MS = 10 * 60 * 1000; // 10 minutes — matches backend heartbeat window
const AGENT_TYPES = [
  { value: 'system', label: 'System', icon: '🖥' },
  { value: 'server', label: 'Server', icon: '🖧' },
  { value: 'phone',  label: 'Phone',  icon: '📱' },
];
const FILTER_TYPES = {
  system: [
    { value: 'all', label: 'All' },
    { value: 'system-linux', label: 'Linux' },
    { value: 'system-mac', label: 'Mac' },
    { value: 'system-windows', label: 'Windows' },
  ],
  server: [
    { value: 'all', label: 'All' },
    { value: 'server-linux', label: 'Linux Server' },
    { value: 'server-windows', label: 'Windows Server' },
    { value: 'server-solaris', label: 'Solaris Server' },
  ],
  phone: [
    { value: 'phone-android', label: 'Android' },
  ],
};

function isOnline(lastSeen) {
  if (!lastSeen) return false;
  return Date.now() - new Date(lastSeen).getTime() < ONLINE_THRESHOLD_MS;
}

function fmtDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString();
}

function fmtShortDate(d) {
  if (!d) return '—';
  return new Date(d).toLocaleString([], {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function safeDownloadName(system) {
  const raw = system?.hostname || system?.name || 'soc-agent';
  return String(raw).trim().replace(/[^a-zA-Z0-9._-]+/g, '_').replace(/^_+|_+$/g, '') || 'soc-agent';
}

function filterTypeToSystemFields(filterType) {
  const map = {
    'system-linux': { os: 'Linux', osType: 'Linux' },
    'system-mac': { os: 'macOS', osType: 'Darwin' },
    'system-windows': { os: 'Windows', osType: 'Windows' },
    'server-linux': { os: 'Linux Server', osType: 'Linux' },
    'server-windows': { os: 'Windows Server', osType: 'Windows' },
    'server-solaris': { os: 'Solaris Server', osType: 'Solaris' },
    'phone-android': { os: 'Android', osType: 'Android' },
    'phone-iphone': { os: 'iPhone', osType: 'iOS' },
  };
  return map[filterType] || {};
}

function getAgentType(system) {
  return ['system', 'server', 'phone'].includes(system?.agentType) ? system.agentType : 'system';
}

function normalizeVersion(value) {
  return String(value || '').trim().replace(/^v/i, '');
}

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>'"]/g, character => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;',
  }[character]));
}

function compareVersions(left, right) {
  const parts = value => normalizeVersion(value).split(/[+-]/)[0].split('.')
    .map(part => Number.parseInt(part, 10) || 0);
  const a = parts(left);
  const b = parts(right);
  const length = Math.max(a.length, b.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (a[index] || 0) - (b[index] || 0);
    if (difference !== 0) return difference > 0 ? 1 : -1;
  }
  return 0;
}

const isAgentUpdateAvailable = (installed, current) => (
  Boolean(installed && current) && compareVersions(installed, current) < 0
);

const targetAgentVersion = (system, fallbackVersion) => (
  system?.currentVersion || fallbackVersion || ''
);

function calculateDepartmentUsage(systems, departments, fallbackLimit = 0) {
  const limit = (departments || []).reduce((sum, dept) => (
    sum +
    (Number(dept.assignedSystemCount) || 0) +
    (Number(dept.assignedServerCount) || 0) +
    (Number(dept.assignedPhoneCount) || 0)
  ), 0) || fallbackLimit;
  const used = (systems || []).length;

  return {
    used,
    limit,
    remaining: Math.max(0, limit - used),
  };
}

function packageOptionsForSystem(system) {
  const text = `${system.os || ''} ${system.osType || ''} ${system.name || ''} ${system.hostname || ''}`.toLowerCase();
  if (/android/.test(text)) {
    return [
      { type: 'apk', label: '.apk', suffix: 'android', ext: 'apk' },
    ];
  }
  if (/solaris|sunos/.test(text)) {
    return [
      { type: 'solaris', label: '.sh', suffix: 'solaris-zfs', ext: 'sh' },
    ];
  }
  if (/mac|darwin|osx/.test(text)) {
    return [
      { type: 'macpkg', label: '.pkg', suffix: 'macos', ext: 'pkg' },
      { type: 'dmg', label: '.dmg', suffix: 'macos', ext: 'dmg' },
    ];
  }
  if (/win|windows/.test(text)) {
    return [
      { type: 'exe', label: '.exe', suffix: 'windows-exe', ext: 'exe' },
      { type: 'msi', label: '.msi', suffix: 'windows-msi', ext: 'msi' },
    ];
  }
  if (/linux|ubuntu|debian|centos|rhel|fedora|rocky|alma|kali/.test(text)) {
    return [
      { type: 'deb', label: '.deb', suffix: 'linux', ext: 'deb' },
      { type: 'rpm', label: '.rpm', suffix: 'linux', ext: 'rpm' },
    ];
  }
  return [];
}

function agentUpdateButtonState(system, currentVersion) {
  if (!system?.agentVersion) {
    return {
      label: 'Not installed',
      disabled: true,
      background: '#111827',
      color: '#64748b',
      border: '1px solid #334155',
      title: 'Install the agent first',
    };
  }
  if (['pending', 'downloading', 'installing'].includes(system.updateStatus)) {
    return {
      label: 'Updating…',
      disabled: true,
      background: '#1e3a5f',
      color: '#60a5fa',
      border: '1px solid #3b82f655',
      title: 'Agent update in progress — waiting for the agent to install and report back',
    };
  }
  if (!isAgentUpdateAvailable(system.agentVersion, currentVersion)) {
    return {
      label: currentVersion ? 'Updated' : 'Version unavailable',
      disabled: true,
      background: '#064e3b',
      color: '#34d399',
      border: '1px solid #10b98155',
      title: currentVersion
        ? `Agent is updated to v${system.agentVersion}`
        : 'The server release version is unavailable',
    };
  }
  return {
    label: 'Update',
    disabled: false,
    background: '#78350f',
    color: '#fcd34d',
    border: '1px solid #f59e0b66',
    title: currentVersion
      ? `Update agent from v${system.agentVersion} to v${currentVersion}`
      : 'Download latest agent update package',
  };
}

// ── Badge components ──────────────────────────────────────────────────────────
function OnlineBadge({ system }) {
  const uninstalled = system?.status === 'disconnected' && !system?.agentVersion;
  const online = !uninstalled && system?.status === 'active' &&
    (system?.isOnline ?? isOnline(system?.lastSeen));
  const label = uninstalled ? 'Uninstalled' : online ? 'Online' : 'Offline';
  const background = uninstalled ? '#7f1d1d' : online ? '#064e3b' : '#1f2937';
  const color = uninstalled ? '#fca5a5' : online ? '#34d399' : '#6b7280';
  return (
    <span style={{
      fontSize: 10, padding: '2px 8px', borderRadius: 10, fontWeight: 700,
      background,
      color,
    }}>
      {uninstalled ? '×' : online ? '●' : '○'} {label}
    </span>
  );
}

function StatusBadge({ status }) {
  const MAP = {
    active:       ['#064e3b', '#34d399'],
    pending:      ['#78350f', '#fcd34d'],
    inactive:     ['#7f1d1d', '#fca5a5'],
    disconnected: ['#1f2937', '#6b7280'],
  };
  const [bg, color] = MAP[status] || MAP.disconnected;
  return (
    <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 10, background: bg, color }}>
      {status}
    </span>
  );
}

function EDRBadge({ enabled }) {
  return (
    <span style={{
      fontSize: 10, padding: '2px 8px', borderRadius: 10,
      background: enabled ? '#1e3a5f' : '#1f2937',
      color:      enabled ? '#60a5fa' : '#4b5563',
      border:     `1px solid ${enabled ? '#3b82f6' : '#374151'}`,
    }}>
      EDR {enabled ? '✓' : '✗'}
    </span>
  );
}

function AgentTypeBadge({ type = 'system' }) {
  const cfg = AGENT_TYPES.find(t => t.value === type) || AGENT_TYPES[0];
  return (
    <span style={{
      fontSize: 10,
      padding: '2px 8px',
      borderRadius: 10,
      background: type === 'server' ? '#14b8a622' : type === 'phone' ? '#a78bfa22' : '#1e3a5f',
      color: type === 'server' ? '#5eead4' : type === 'phone' ? '#c4b5fd' : '#93c5fd',
      border: `1px solid ${type === 'server' ? '#14b8a655' : type === 'phone' ? '#a78bfa55' : '#3b82f655'}`,
      fontWeight: 700,
    }}>
      {cfg.label}
    </span>
  );
}

// ── Info chip ─────────────────────────────────────────────────────────────────
function Chip({ label, value, color = '#1e40af', mono = false }) {
  if (!value) return null;
  return (
    <span style={{ fontSize: 11, color: '#475569' }}>
      <span style={{ color: '#1e40af' }}>{label}: </span>
      <span style={{ color, fontFamily: mono ? 'monospace' : 'inherit' }}>{value}</span>
    </span>
  );
}

// ── Inline mini-form for adding a system under a dept card ──
function AddSystemUnderDept({ dept, onAdded, canAddSystems }) {
  const [open, setOpen]   = useState(false);
  const [name, setName]   = useState('');
  const [agentType, setAgentType] = useState('system');
  const [filterType, setFilterType] = useState('all');
  const [err,  setErr]    = useState('');
  const [busy, setBusy]   = useState(false);
  const allocationLimit = {
    system: Number(dept.assignedSystemCount) || 0,
    server: Number(dept.assignedServerCount) || 0,
    phone: Number(dept.assignedPhoneCount) || 0,
  }[agentType] || 0;
  const allocationUsed = Number(dept[`${agentType}UsedCount`]) || 0;
  const allocationRemaining = Math.max(0, allocationLimit - allocationUsed);

  const submit = async (e) => {
    e.preventDefault();
    const ve = validateSystemName(name);
    if (ve) { setErr(ve); return; }
    if (!canAddSystems) { setErr('No active system license. Add systems from Payments first.'); return; }

    setBusy(true); setErr('');
    try {
      const { data } = await api.post('/system', {
        name: name.trim(),
        departmentId: dept._id,
        agentType,
        filterType,
        ...filterTypeToSystemFields(filterType),
      });
      onAdded(data);
      setName(''); setAgentType('system'); setOpen(false);
    } catch (e2) {
      setErr(e2.response?.data?.message || 'Failed to add system');
    } finally { setBusy(false); }
  };

  return (
    <div style={{ marginTop: 10, paddingTop: 10, borderTop: '1px solid #1e3a5f' }}>
      {!open
        ? (
          <button onClick={() => setOpen(true)} style={{
            fontSize: 12, padding: '5px 14px', borderRadius: 4,
            border: '1px dashed #1e3a5f', background: 'transparent',
            color: '#60a5fa', cursor: 'pointer',
          }}>+ Add system to {dept.name}</button>
        )
        : (
          <form onSubmit={submit} noValidate style={{
            background: '#081426',
            border: '1px solid #1e3a5f',
            borderRadius: 8,
            padding: 12,
          }}>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'minmax(180px, 340px) 150px 150px auto auto',
              gap: 10,
              alignItems: 'end',
            }}>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 10, marginBottom: 4, fontWeight: 700 }}>
                  Host name
                </label>
                <input
                  autoFocus
                  type="text"
                  placeholder="Host name e.g. web-server-01"
                  value={name}
                  onChange={e => { setName(e.target.value); setErr(''); }}
                  style={{
                    width: '100%', padding: '9px 11px', borderRadius: 6, boxSizing: 'border-box',
                    background: '#060e1a', color: '#e2e8f0', fontSize: 12,
                    border: `1px solid ${err ? '#f87171' : '#1e3a5f'}`,
                    outline: 'none',
                  }} />
                {err && <div style={{ fontSize: 11, color: '#f87171', marginTop: 3 }}>{err}</div>}
              </div>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 10, marginBottom: 4, fontWeight: 700 }}>
                  Agent type
                </label>
                <select
                  value={agentType}
                  onChange={e => {
                    const nextType = e.target.value;
                    setAgentType(nextType);
                    setFilterType(nextType === 'phone' ? 'phone-android' : 'all');
                  }}
                  style={{
                    width: '100%',
                    padding: '9px 11px',
                    borderRadius: 6,
                    boxSizing: 'border-box',
                    background: '#060e1a',
                    color: '#93c5fd',
                    fontSize: 12,
                    cursor: 'pointer',
                    border: '1px solid #1e3a5f',
                  }}>
                  {AGENT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              <div>
                <label style={{ display: 'block', color: '#60a5fa', fontSize: 10, marginBottom: 4, fontWeight: 700 }}>
                  Filter type
                </label>
                <select
                  value={filterType}
                  onChange={e => setFilterType(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '9px 11px',
                    borderRadius: 6,
                    boxSizing: 'border-box',
                    background: '#060e1a',
                    color: '#93c5fd',
                    fontSize: 12,
                    cursor: 'pointer',
                    border: '1px solid #1e3a5f',
                  }}>
                  {(FILTER_TYPES[agentType] || FILTER_TYPES.system).map(t => (
                    <option key={t.value} value={t.value}>{t.label}</option>
                  ))}
                </select>
              </div>
              <button type="submit" disabled={busy} style={{
                fontSize: 12, padding: '9px 16px', borderRadius: 6, border: 'none',
                background: busy ? '#1e3a5f' : '#2563eb', color: '#fff', cursor: 'pointer',
                fontWeight: 700,
              }}>{busy ? 'Adding…' : 'Add'}</button>
              <button type="button" onClick={() => { setOpen(false); setName(''); setAgentType('system'); setErr(''); }} style={{
                fontSize: 12, padding: '9px 12px', borderRadius: 6,
                border: '1px solid #1e3a5f', background: 'none', color: '#60a5fa', cursor: 'pointer',
              }}>Cancel</button>
            </div>
            <div style={{ fontSize: 10, color: allocationRemaining > 0 ? '#34d399' : '#f59e0b', marginTop: 8 }}>
              {agentType} allocation: {allocationUsed}/{allocationLimit} used
              {allocationLimit === 0 ? ' — edit department allocation first' : ` · ${allocationRemaining} remaining`}
            </div>
          </form>
        )
      }
    </div>
  );
}

// ── Expanded system detail card ───────────────────────────────────────────────
function SystemCard({ s, isAdmin, downloading, currentAgentVersion, onDownload, onDownloadPackage, onUpdate }) {
  const online = s.status === 'active' && (s.isOnline ?? isOnline(s.lastSeen));
  const isAndroid = /android/i.test(`${s.os || ''} ${s.osType || ''}`);
  const packageOptions = packageOptionsForSystem(s);
  const packageDownloadBlocked = Boolean(s.agentVersion) || (Number(s.downloadCount) || 0) > 0;
  const updateButton = agentUpdateButtonState(s, targetAgentVersion(s, currentAgentVersion));
  return (
    <div style={{
      background: '#060e1a',
      border: `1px solid ${online ? '#1e3a5f' : '#1f2937'}`,
      borderLeft: `3px solid ${online ? '#34d399' : '#4b5563'}`,
      borderRadius: 8,
      padding: '12px 14px',
      marginBottom: 8,
    }}>
      {/* Row 1: Name + status badges */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', flex: 1, minWidth: 0 }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: '#e2e8f0' }}>🖥 {s.name}</span>
          <AgentTypeBadge type={s.agentType || 'system'} />
          {s.hostname && <span style={{ fontSize: 11, color: '#1e40af' }}>({s.hostname})</span>}
          <OnlineBadge system={s} />
          <StatusBadge status={s.status} />
          <EDRBadge enabled={s.edrEnabled} />
          {s.idsEnabled    && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 8, background: '#1e3a5f', color: '#a78bfa', border: '1px solid #7c3aed' }}>IDS ✓</span>}
          {s.ipsEnabled    && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 8, background: '#1e3a5f', color: '#f59e0b', border: '1px solid #d97706' }}>IPS ✓</span>}
          {s.firewallEnabled && <span style={{ fontSize: 10, padding: '2px 6px', borderRadius: 8, background: '#1e3a5f', color: '#34d399', border: '1px solid #065f46' }}>FW ✓</span>}
        </div>
        {isAdmin && (
          <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
            <button
              onClick={() => onDownload(s)}
              disabled={downloading === s._id}
              style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 4, border: 'none',
                background: '#064e3b', color: '#34d399', cursor: 'pointer',
              }}>
              {downloading === s._id ? '…' : '↓ Config'}
            </button>
            {packageDownloadBlocked ? (
              <span style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 4,
                border: '1px solid #334155',
                background: '#111827',
                color: '#64748b',
                fontWeight: 700,
              }}>
                {s.agentVersion ? 'Agent installed' : 'Downloaded'}
              </span>
            ) : packageOptions.map(pkg => {
                  const key = `${s._id}:${pkg.type}`;
              return (
                <button key={pkg.type}
                  onClick={() => onDownloadPackage(s, pkg)}
                  disabled={downloading === key}
                  style={{
                    fontSize: 11, padding: '4px 10px', borderRadius: 4,
                    border: '1px solid #10b98155',
                    background: '#064e3b66', color: '#34d399', cursor: 'pointer',
                  }}>
                  {downloading === key ? '…' : `↓ ${pkg.label}`}
                </button>
              );
            })}
            <button
              onClick={() => onUpdate(s)}
              disabled={updateButton.disabled || downloading === `${s._id}:update`}
              title={updateButton.title}
              style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 4,
                border: updateButton.border,
                background: updateButton.background,
                color: updateButton.color,
                cursor: updateButton.disabled ? 'not-allowed' : 'pointer',
                fontWeight: 700,
              }}>
              {downloading === `${s._id}:update` ? '…' : updateButton.label}
            </button>
          </div>
        )}
      </div>

      {/* Row 2: Detailed info grid */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))',
        gap: '4px 16px',
        fontSize: 11,
      }}>
        {s.ip         && <Chip label="IP Address"     value={s.ip}          color="#7dd3fc" mono />}
        {s.macAddress && <Chip label="MAC Address"    value={s.macAddress}  color="#c084fc" mono />}
        {s.os         && <Chip label="OS"             value={s.os}          color="#94a3b8" />}
        {s.osVersion  && <Chip label="OS Version"     value={s.osVersion}   color="#64748b" />}
        {s.arch       && <Chip label="Arch"           value={s.arch}        color="#64748b" />}
        {s.agentVersion && <Chip label="Agent Version" value={`v${s.agentVersion}`} color="#34d399" />}
        {!s.agentVersion && <span style={{ fontSize: 11, color: '#4b5563' }}>Agent: not installed</span>}
        {s.departmentId?.name && <Chip label="Department" value={s.departmentId.name} color="#93c5fd" />}
        {s.installDate && <Chip label="Installed" value={fmtDate(s.installDate)} color="#34d399" />}
        {s.lastSeen   && <Chip label="Last Seen"     value={fmtDate(s.lastSeen)}   color={online ? '#34d399' : '#6b7280'} />}
        {s.agentId    && <Chip label="Agent ID"      value={s.agentId}     color="#475569" mono />}
        {s.velociraptorClientId
          ? <Chip label="Velociraptor Client ID" value={s.velociraptorClientId} color="#22d3ee" mono />
          : <Chip label="Velociraptor" value={isAndroid ? 'Not supported on Android' : 'Not enrolled'} color={isAndroid ? '#64748b' : '#f59e0b'} />}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function SystemsPage({ companyId: propCompanyId }) {
  const { isAdmin, company } = useAuth();
  const activeCompanyId = propCompanyId || localStorage.getItem('sa_active_company_id');
  const [systems,  setSystems]  = useState([]);
  const [depts,    setDepts]    = useState([]);
  const [usage,    setUsage]    = useState(null);
  const [loading,  setLoading]  = useState(true);
  const [apiErr,   setApiErr]   = useState('');
  const [viewMode, setViewMode] = useState('grouped'); // 'grouped' | 'table'
  const [currentAgentVersion, setCurrentAgentVersion] = useState('');

  // Global add form
  const [showForm, setShowForm] = useState(false);
  const [form,     setForm]     = useState({ name: '', departmentId: '', agentType: 'system', filterType: 'all' });
  const [formErrs, setFormErrs] = useState({});
  const [formErr,  setFormErr]  = useState('');
  const [busy,     setBusy]     = useState(false);

  const [downloading, setDownloading] = useState(null);
  // systemId -> { startedAt, target } for OTA updates awaiting a success/fail result
  const [updatingIds, setUpdatingIds] = useState({});
  const UPDATE_RESULT_TIMEOUT_MS = 5 * 60 * 1000;

  const planLimit = Number(
    company?.plan?.systemLimit ||
    ((company?.plan?.systemCount || 0) + (company?.plan?.serverCount || 0) + (company?.plan?.phoneCount || 0))
  );
  const planActive = company?.plan?.isActive;
  const canAddSystems = Boolean(planActive || company?.entitlement?.batchActive || planLimit > 0);

  const load = (silent = false) => {
    if (!silent) setLoading(true);
    const q = activeCompanyId ? `?companyId=${activeCompanyId}` : '';
    Promise.all([
      api.get(`/system${q}`),
      api.get(`/department${q}`).catch(() => ({ data: [] })),
      api.get(`/agent/stats${q}`).catch(() => ({ data: null })),
      api.get(`/agent/version${q}`).catch(() => ({ data: null })),
    ])
    .then(([sysRes, deptRes, agentStatsRes, agentVersionRes]) => {
      // Handle both array and object responses from /system endpoint
      const sysArray = Array.isArray(sysRes.data)
        ? sysRes.data
        : (sysRes.data?.systems || []);
      // Merge OTA update state from /agent/stats (carries the lazy-timeout-adjusted status).
      const statsById = {};
      (agentStatsRes.data?.systems || []).forEach(st => { statsById[String(st._id)] = st; });
      const merged = sysArray.map(s => {
        const st = statsById[String(s._id)];
        return st
          ? {
            ...s,
            currentVersion: st.currentVersion,
            updateStatus: st.updateStatus,
            updateError: st.updateError,
            updateAvailable: st.updateAvailable,
          }
          : s;
      });
      setSystems(merged);
      setCurrentAgentVersion(agentStatsRes.data?.currentVersion || agentVersionRes.data?.version || '');
      // Handle both array and object responses from /department endpoint
      const deptArray = Array.isArray(deptRes.data)
        ? deptRes.data
        : (deptRes.data?.departments || []);
      setDepts(deptArray);
      setUsage(sysRes.data?.usage || calculateDepartmentUsage(sysArray, deptArray, planLimit));
    })
    .catch(err => {
      const errMsg = err.response?.data?.message || err.message || 'Failed to load systems';
      setApiErr(errMsg);
    })
    .finally(() => {
      if (!silent) setLoading(false);
    });
  };

  useEffect(() => {
    load();
    const refresh = () => load(true);
    const timer = window.setInterval(refresh, 60000);
    window.addEventListener('focus', refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener('focus', refresh);
    };
  }, []);

  // While any OTA update is in flight, poll faster so the result surfaces promptly.
  const hasPendingUpdates = Object.keys(updatingIds).length > 0;
  useEffect(() => {
    if (!hasPendingUpdates) return;
    const timer = window.setInterval(() => load(true), 30000);
    return () => window.clearInterval(timer);
  }, [hasPendingUpdates]);

  // Resolve in-flight updates to success/failure whenever systems refresh.
  useEffect(() => {
    const ids = Object.keys(updatingIds);
    if (ids.length === 0) return;
    const finished = [];
    ids.forEach(id => {
      const sys = systems.find(s => String(s._id) === String(id));
      if (!sys) return;
      const info = updatingIds[id];
      const name = sys.name || sys.hostname || 'system';
      if (sys.updateStatus === 'success') {
        finished.push({ id, ok: true, name, target: info.target });
      } else if (sys.updateStatus === 'failed' || (Date.now() - info.startedAt) > UPDATE_RESULT_TIMEOUT_MS) {
        finished.push({ id, ok: false, name, error: sys.updateError });
      }
    });
    if (!finished.length) return;
    finished.forEach(f => {
      if (f.ok) {
        Swal.fire({
          icon: 'success',
          title: 'Agent Updated Successfully',
          html: `<b>${escapeHtml(f.name)}</b> is now running agent <b>v${escapeHtml(f.target || currentAgentVersion)}</b>.`,
          confirmButtonText: 'Done',
          background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#2563eb',
        });
      } else {
        Swal.fire({
          icon: 'error',
          title: 'Agent Update Failed',
          html: `<b>${escapeHtml(f.name)}</b> could not be updated.${f.error ? `<br><small>${escapeHtml(f.error)}</small>` : ''}`,
          confirmButtonText: 'Close',
          background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#dc2626',
        });
      }
    });
    setUpdatingIds(prev => {
      const next = { ...prev };
      finished.forEach(f => delete next[f.id]);
      return next;
    });
  }, [systems, currentAgentVersion, updatingIds]);

  const addSystem = async (e) => {
    e.preventDefault();
    const errs = {
      name:         validateSystemName(form.name),
      departmentId: !form.departmentId ? 'Please select a department' : null,
      agentType:    !['system', 'server', 'phone'].includes(form.agentType) ? 'Please choose agent type' : null,
    };
    setFormErrs(errs);
    if (Object.values(errs).some(Boolean)) return;

    if (!canAddSystems) {
      setFormErr('No active system license. Go to Payments and add systems first.');
      return;
    }

    setBusy(true); setFormErr('');
    try {
      const { data } = await api.post('/system', {
        name:         form.name.trim(),
        departmentId: form.departmentId,
        agentType:    form.agentType,
        filterType:   form.filterType,
        ...filterTypeToSystemFields(form.filterType),
      });
      setSystems(prev => [data, ...prev]);
      setUsage(u => u ? { ...u, used: u.used + 1, remaining: u.remaining - 1 } : u);
      setDepts(prev => prev.map(dept => (
        dept._id === form.departmentId
          ? { ...dept, [`${form.agentType}UsedCount`]: (Number(dept[`${form.agentType}UsedCount`]) || 0) + 1 }
          : dept
      )));
      setShowForm(false);
      setForm({ name: '', departmentId: '', agentType: 'system', filterType: 'all' });
      setFormErrs({});
    } catch (err) {
      setFormErr(err.response?.data?.message || 'Failed to add system');
    } finally { setBusy(false); }
  };

  const updateSystemAgent = async (system) => {
    const targetVersion = targetAgentVersion(system, currentAgentVersion);
    if (!system.agentVersion) {
      await Swal.fire({ icon: 'warning', title: 'Agent Not Installed', text: 'Download and install the agent before requesting an update.', background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#2563eb' });
      return;
    }
    if (!targetVersion || compareVersions(system.agentVersion, targetVersion) >= 0) {
      await Swal.fire({ icon: 'info', title: 'Already Up to Date', text: `This agent is already running v${system.agentVersion}. A new Update button will become available when the server release is newer.`, background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#2563eb' });
      return;
    }

    const systemName = system.name || system.hostname || 'Unknown';
    const result = await Swal.fire({
      icon: 'question',
      title: 'Update Security Agent?',
      html: `
        <div style="text-align:left;background:#07111f;border:1px solid #1e3a5f;border-radius:10px;padding:14px 16px;margin:8px 0 14px">
          <div style="display:flex;justify-content:space-between;gap:16px;margin-bottom:8px"><span style="color:#94a3b8">System</span><b>${escapeHtml(systemName)}</b></div>
          <div style="display:flex;justify-content:space-between;gap:16px;margin-bottom:8px"><span style="color:#94a3b8">Current version</span><b>v${escapeHtml(system.agentVersion)}</b></div>
          <div style="display:flex;justify-content:space-between;gap:16px"><span style="color:#94a3b8">New version</span><b style="color:#4ade80">v${escapeHtml(targetVersion || 'latest')}</b></div>
        </div>
        <p style="color:#cbd5e1;font-size:13px;line-height:1.55;margin:0">The update will download securely and install automatically on the agent's next heartbeat. Monitoring may pause briefly while the service restarts.</p>`,
      showCancelButton: true,
      confirmButtonText: 'Start Update',
      cancelButtonText: 'Cancel',
      reverseButtons: true,
      focusCancel: true,
      background: '#0b1728',
      color: '#e2e8f0',
      confirmButtonColor: '#2563eb',
      cancelButtonColor: '#334155',
    });
    if (!result.isConfirmed) return;

    setDownloading(`${system._id}:update`);
    try {
      await api.post(`/agent/${system._id}/update`);
      // Optimistically flip the button to "Updating…" and start watching for the result.
      setSystems(prev => prev.map(s => (
        s._id === system._id ? { ...s, updateStatus: 'pending', updateError: null } : s
      )));
      setUpdatingIds(prev => ({
        ...prev,
        [system._id]: { startedAt: Date.now(), target: targetVersion },
      }));
      await Swal.fire({
        icon: 'success',
        title: 'Update Command Sent',
        text: `${systemName} will download and install v${targetVersion} on its next heartbeat.`,
        timer: 2600,
        timerProgressBar: true,
        showConfirmButton: false,
        background: '#0b1728', color: '#e2e8f0',
      });
    } catch (err) {
      await Swal.fire({ icon: 'error', title: 'Unable to Start Update', text: err.response?.data?.message || err.message, background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#dc2626' });
    } finally {
      setDownloading(null);
    }
  };

  const downloadConfig = async (system) => {
    setDownloading(system._id);
    try {
      const resp = await api.get(`/agent/config/${system._id}`, { responseType: 'blob' });
      const url  = URL.createObjectURL(resp.data);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = `${safeDownloadName(system)}_config.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (err) {
      alert('Download failed: ' + (err.response?.data?.message || err.message));
    } finally { setDownloading(null); }
  };

  const downloadErrorMessage = async (err) => {
    const data = err.response?.data;
    if (data instanceof Blob) {
      try {
        const text = await data.text();
        const parsed = JSON.parse(text);
        return parsed.message || text;
      } catch {
        return err.message;
      }
    }
    return data?.message || err.message;
  };

  const downloadPackage = async (system, pkg, options = {}) => {
    const isUpdate = Boolean(options.isUpdate);
    if (!isUpdate && (system.agentVersion || (Number(system.downloadCount) || 0) > 0)) {
      alert('Agent package already downloaded for this system. One-time download only.');
      return;
    }

    const pkgType = typeof pkg === 'string' ? pkg : pkg.type;
    const key = isUpdate ? `${system._id}:update` : `${system._id}:${pkgType}`;
    setDownloading(key);
    try {
      const query = `category=${encodeURIComponent(system.agentType || 'system')}${isUpdate ? '&update=1' : ''}`;
      const resp = await api.get(`/agent/package/${system._id}/${pkgType}?${query}`, { responseType: 'blob' });
      const url  = URL.createObjectURL(resp.data);
      const a    = document.createElement('a');
      const ext = pkg.ext || {
        deb: 'deb',
        rpm: 'rpm',
        exe: 'exe',
        msi: 'msi',
        macpkg: 'pkg',
        dmg: 'dmg',
        apk: 'apk',
        solaris: 'sh',
      }[pkgType] || 'zip';
      const suffix = pkg.suffix || pkgType;
      const releaseVersion = String(targetAgentVersion(system, currentAgentVersion) || currentAgentVersion || 'latest')
        .replace(/[^0-9A-Za-z._-]/g, '_');
      a.href     = url;
      a.download = `soc-agent_v${releaseVersion}_${isUpdate ? 'update_' : ''}${safeDownloadName(system)}_${suffix}.${ext}`;
      a.click();
      URL.revokeObjectURL(url);
      if (['exe', 'msi'].includes(pkgType)) {
        await Swal.fire({
          icon: 'success',
          title: `AJNAT v${releaseVersion} Downloaded`,
          text: `Double-click the downloaded .${ext} file and select Yes on the Windows UAC prompt. No PowerShell command is required.`,
          background: '#0b1728', color: '#e2e8f0', confirmButtonColor: '#2563eb',
        });
      }
      if (!isUpdate) {
        setSystems(prev => prev.map(s => (
          s._id === system._id
            ? { ...s, downloadCount: (Number(s.downloadCount) || 0) + 1 }
            : s
        )));
      }
    } catch (err) {
      alert('Download failed: ' + await downloadErrorMessage(err));
    } finally { setDownloading(null); }
  };

  const handleInlineAdded = (newSystem) => {
    setSystems(prev => [newSystem, ...prev]);
    setUsage(u => u ? { ...u, used: u.used + 1, remaining: u.remaining - 1 } : u);
    const deptId = newSystem?.departmentId?._id || newSystem?.departmentId;
    const type = getAgentType(newSystem);
    setDepts(prev => prev.map(dept => (
      dept._id === deptId
        ? { ...dept, [`${type}UsedCount`]: (Number(dept[`${type}UsedCount`]) || 0) + 1 }
        : dept
    )));
  };

  // ── Stats bar ─────────────────────────────────────────────────────────────
  const filteredSystems = systems;
  const onlineCount   = filteredSystems.filter(s => isOnline(s.lastSeen)).length;
  const offlineCount  = filteredSystems.length - onlineCount;
  const edrCount      = filteredSystems.filter(s => s.edrEnabled).length;
  const idsCount      = filteredSystems.filter(s => s.idsEnabled).length;
  const ipsCount      = filteredSystems.filter(s => s.ipsEnabled).length;
  const fwCount       = filteredSystems.filter(s => s.firewallEnabled).length;
  const withIp        = filteredSystems.filter(s => s.ip).length;
  const withMac       = filteredSystems.filter(s => s.macAddress).length;
  const systemTypeCount = filteredSystems.filter(s => !s.agentType || s.agentType === 'system').length;
  const serverTypeCount = filteredSystems.filter(s => s.agentType === 'server').length;
  const phoneTypeCount  = filteredSystems.filter(s => s.agentType === 'phone').length;

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 16 }}>
        <div>
          <h2 style={{ fontSize: 20, color: '#e0f2fe', margin: 0 }}>🖥 Systems</h2>
          {usage && (
            <div style={{ fontSize: 11, color: '#1e40af', marginTop: 2 }}>
              {usage.used} / {usage.limit} used · {usage.remaining} remaining
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {/* View toggle */}
          <div style={{ display: 'flex', gap: 0, border: '1px solid #1e3a5f', borderRadius: 6, overflow: 'hidden' }}>
            {[['grouped', '⊞ Grouped'], ['table', '☰ Table']].map(([mode, label]) => (
              <button key={mode} onClick={() => setViewMode(mode)} style={{
                fontSize: 11, padding: '5px 12px', border: 'none', cursor: 'pointer',
                background: viewMode === mode ? '#1e3a5f' : 'transparent',
                color:      viewMode === mode ? '#e2e8f0'  : '#60a5fa',
              }}>{label}</button>
            ))}
          </div>
          <button onClick={load} style={{
            fontSize: 11, padding: '5px 12px', borderRadius: 6,
            border: '1px solid #1e3a5f', background: 'none', color: '#60a5fa', cursor: 'pointer',
          }}>↺ Refresh</button>
          {isAdmin && (
            <button onClick={() => setShowForm(v => !v)} style={{
              fontSize: 13, padding: '7px 16px', borderRadius: 6, border: 'none',
              background: showForm ? '#1e3a5f' : '#2563eb', color: '#fff', cursor: 'pointer',
            }}>
              {showForm ? '✕ Cancel' : '+ Add system'}
            </button>
          )}
        </div>
      </div>

      {/* Error Display - CRITICAL: Always show if there's an error */}
      {apiErr && (
        <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '14px 16px', borderRadius: 6, marginBottom: 16, fontSize: 13, border: '2px solid #f87171' }}>
          <strong>⚠️ Error:</strong> {apiErr}
        </div>
      )}

      {/*Loading State*/}
      {loading && (
        <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 6, padding: 16, marginBottom: 16, fontSize: 13, color: '#60a5fa' }}>
          ⏳ Loading systems...
        </div>
      )}

      {/* Plan inactive warning */}
      {!canAddSystems && (
        <div style={{ background: '#78350f', border: '1px solid #92400e', borderRadius: 8, padding: '10px 14px', marginBottom: 16, fontSize: 13, color: '#fcd34d' }}>
          ⚠ No active system license — add systems from Payments first.{' '}
          <a href="/payments" style={{ color: '#f59e0b', textDecoration: 'none', fontWeight: 500 }}>Open Payments →</a>
        </div>
      )}

      {/* Live stats row */}
      {systems.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
          {[
            { label: 'Total', value: filteredSystems.length, color: '#60a5fa' },
            { label: 'Systems',  value: systemTypeCount, color: '#38bdf8' },
            { label: 'Servers',  value: serverTypeCount, color: '#14b8a6' },
            { label: 'Phones',   value: phoneTypeCount, color: '#a78bfa' },
            { label: 'Online',   value: onlineCount,    color: '#34d399' },
            { label: 'Offline',  value: offlineCount,   color: '#6b7280' },
            { label: 'EDR On',   value: edrCount,       color: '#93c5fd' },
            { label: 'IDS On',   value: idsCount,       color: '#a78bfa' },
            { label: 'IPS On',   value: ipsCount,       color: '#f59e0b' },
            { label: 'FW On',    value: fwCount,        color: '#34d399' },
            { label: 'IP Known', value: withIp,         color: '#7dd3fc' },
            { label: 'MAC Known',value: withMac,        color: '#c084fc' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              background: '#0c1a2e', borderRadius: 8, padding: '8px 14px',
              border: `1px solid ${color}22`, textAlign: 'center', minWidth: 70,
            }}>
              <div style={{ fontSize: 20, fontWeight: 700, color }}>{value}</div>
              <div style={{ fontSize: 10, color: '#475569' }}>{label}</div>
            </div>
          ))}
          {usage && usage.limit > 0 && (
            <div style={{ flex: 1, minWidth: 200, background: '#0c1a2e', borderRadius: 8, padding: '8px 14px', border: '1px solid #1e3a5f', display: 'flex', alignItems: 'center', gap: 10 }}>
              <div style={{ flex: 1 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 10, color: '#1e40af' }}>Plan usage</span>
                  <span style={{ fontSize: 10, color: '#1e40af' }}>{usage.used}/{usage.limit}</span>
                </div>
                <div style={{ background: '#060e1a', borderRadius: 4, height: 6, overflow: 'hidden' }}>
                  <div style={{
                    height: '100%', borderRadius: 4, transition: 'width .5s',
                    width: `${Math.min((usage.used / usage.limit) * 100, 100)}%`,
                    background: usage.remaining === 0 ? '#f87171' : usage.remaining <= 3 ? '#f59e0b' : '#2563eb',
                  }} />
                </div>
                {usage.remaining === 0 && (
                  <p style={{ fontSize: 10, color: '#f87171', marginTop: 3, marginBottom: 0 }}>
                    Limit reached. <a href="/payments" style={{ color: '#f59e0b', textDecoration: 'none' }}>Upgrade plan →</a>
                  </p>
                )}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Global add form */}
      {showForm && (
        <form onSubmit={addSystem} noValidate style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '18px 20px', marginBottom: 20 }}>
          <h3 style={{ fontSize: 14, color: '#60a5fa', marginBottom: 14 }}>Add new system</h3>
          {formErr && (
            <div style={{ background: '#1c0a0a', color: '#fca5a5', padding: '7px 12px', borderRadius: 6, marginBottom: 12, fontSize: 13 }}>{formErr}</div>
          )}
          {!canAddSystems && (
            <div style={{ background: '#78350f', color: '#fcd34d', padding: '7px 12px', borderRadius: 6, marginBottom: 12, fontSize: 13 }}>
              ⚠️ No active system license. <a href="/payments" style={{ color: '#f59e0b', textDecoration: 'none', fontWeight: 500 }}>Add systems</a> from Payments first.
            </div>
          )}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 12, marginBottom: 14 }}>
            <div>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 11, marginBottom: 3 }}>Host name *</label>
              <input
                value={form.name}
                onChange={e => { setForm(f => ({ ...f, name: e.target.value })); setFormErrs(er => ({ ...er, name: null })); }}
                placeholder="e.g. Web Server 01"
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#e2e8f0', fontSize: 13, outline: 'none', border: `1px solid ${formErrs.name ? '#f87171' : '#1e3a5f'}` }} />
              {formErrs.name && <div style={{ fontSize: 11, color: '#f87171', marginTop: 2 }}>{formErrs.name}</div>}
            </div>
            <div>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 11, marginBottom: 3 }}>Department *</label>
              <select
                value={form.departmentId}
                onChange={e => { setForm(f => ({ ...f, departmentId: e.target.value })); setFormErrs(er => ({ ...er, departmentId: null })); }}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#93c5fd', fontSize: 13, cursor: 'pointer', border: `1px solid ${formErrs.departmentId ? '#f87171' : '#1e3a5f'}` }}>
                <option value="">Select department</option>
                {(Array.isArray(depts) ? depts : []).map(d => <option key={d._id} value={d._id}>{d.name}</option>)}
              </select>
              {formErrs.departmentId && <div style={{ fontSize: 11, color: '#f87171', marginTop: 2 }}>{formErrs.departmentId}</div>}
            </div>
            <div>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 11, marginBottom: 3 }}>Choose agent type *</label>
              <select
                value={form.agentType}
                onChange={e => {
                  const nextType = e.target.value;
                  setForm(f => ({ ...f, agentType: nextType, filterType: nextType === 'phone' ? 'phone-android' : 'all' }));
                  setFormErrs(er => ({ ...er, agentType: null }));
                }}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#93c5fd', fontSize: 13, cursor: 'pointer', border: `1px solid ${formErrs.agentType ? '#f87171' : '#1e3a5f'}` }}>
                {AGENT_TYPES.map(t => <option key={t.value} value={t.value}>{t.icon} {t.label}</option>)}
              </select>
              {formErrs.agentType && <div style={{ fontSize: 11, color: '#f87171', marginTop: 2 }}>{formErrs.agentType}</div>}
            </div>
            <div>
              <label style={{ display: 'block', color: '#60a5fa', fontSize: 11, marginBottom: 3 }}>Filter type *</label>
              <select
                value={form.filterType}
                onChange={e => setForm(f => ({ ...f, filterType: e.target.value }))}
                style={{ width: '100%', padding: '8px 10px', borderRadius: 6, boxSizing: 'border-box', background: '#060e1a', color: '#93c5fd', fontSize: 13, cursor: 'pointer', border: '1px solid #1e3a5f' }}>
                {(FILTER_TYPES[form.agentType] || FILTER_TYPES.system).map(t => (
                  <option key={t.value} value={t.value}>{t.label}</option>
                ))}
              </select>
            </div>
          </div>
          {Array.isArray(depts) && depts.length === 0 && <p style={{ fontSize: 11, color: '#f59e0b', marginBottom: 10 }}>⚠ No departments yet. Create a department first.</p>}
          <button type="submit" disabled={busy || !canAddSystems} style={{ padding: '8px 20px', borderRadius: 6, border: 'none', background: busy || !canAddSystems ? '#1e3a5f' : '#2563eb', color: busy || !canAddSystems ? '#6b7280' : '#fff', fontSize: 13, cursor: busy || !canAddSystems ? 'not-allowed' : 'pointer' }}>
            {busy ? 'Adding…' : 'Add system'}
          </button>
        </form>
      )}

      {/* ── Systems list ── */}
      {loading
        ? <p style={{ color: '#1e40af', fontSize: 13 }}>Loading…</p>
        : (Array.isArray(depts) ? depts.length : 0) === 0 && filteredSystems.length === 0
          ? (
            <div style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: 32, textAlign: 'center' }}>
              <p style={{ color: '#1e40af', fontSize: 13, marginBottom: 4 }}>No systems added yet.</p>
              <p style={{ color: '#1e3a5f', fontSize: 12 }}>Add a system, download its config file, install the SOC Agent — it connects automatically.</p>
            </div>
          )
          : viewMode === 'table'
            ? (
              /* ── Flat Table View ── */
              <div style={{
                background: 'linear-gradient(135deg, rgba(12,26,46,.96), rgba(8,18,34,.96))',
                border: '1px solid rgba(30,58,95,.85)',
                borderRadius: 12,
                overflow: 'auto',
                boxShadow: '0 14px 34px rgba(0,0,0,.18)',
              }}>
                <div style={{ display:'flex', alignItems:'center', justifyContent:'space-between', gap:12, padding:'12px 14px', borderBottom:'1px solid #1e3a5f' }}>
                  <div>
                    <div style={{ fontSize:14, color:'#e0f2fe', fontWeight:800 }}>Systems table</div>
                    <div style={{ fontSize:11, color:'#60a5fa', marginTop:2 }}>
                      {filteredSystems.length} shown of {systems.length} registered asset{systems.length !== 1 ? 's' : ''}
                    </div>
                  </div>
                  <button onClick={load} style={{
                    fontSize:11, padding:'6px 12px', borderRadius:6,
                    border:'1px solid #1e3a5f', background:'#060e1a', color:'#60a5fa', cursor:'pointer',
                  }}>↺ Refresh</button>
                </div>
                <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: 0, fontSize: 12, minWidth: 1180, tableLayout:'fixed' }}>
                  <colgroup>
                    <col style={{ width: 150 }} />
                    <col style={{ width: 90 }} />
                    <col style={{ width: 95 }} />
                    <col style={{ width: 120 }} />
                    <col style={{ width: 120 }} />
                    <col style={{ width: 150 }} />
                    <col style={{ width: 90 }} />
                    <col style={{ width: 115 }} />
                    <col style={{ width: 80 }} />
                    <col style={{ width: 120 }} />
                    <col style={{ width: 115 }} />
                    <col style={{ width: 115 }} />
                    {isAdmin && <col style={{ width: 150 }} />}
                  </colgroup>
                  <thead>
                    <tr>
                      {['System', 'Type', 'Status', 'Hostname', 'IP Address', 'MAC Address', 'OS', 'Agent Version', 'EDR', 'Department', 'Install Date', 'Last Seen'].map(h => (
                        <th key={h} style={{
                          position:'sticky', top:0, zIndex:1,
                          textAlign: 'left', padding: '11px 12px',
                          color: '#60a5fa', fontSize: 10, fontWeight: 800,
                          whiteSpace: 'nowrap', textTransform:'uppercase', letterSpacing:'.4px',
                          background:'#060e1a', borderBottom:'1px solid #1e3a5f',
                        }}>{h}</th>
                      ))}
                      {isAdmin && <th style={{
                        position:'sticky', top:0, zIndex:1,
                        right:0,
                        textAlign: 'left', padding: '11px 12px',
                        color: '#60a5fa', fontSize: 10, fontWeight: 800,
                        textTransform:'uppercase', letterSpacing:'.4px',
                        background:'#060e1a', borderBottom:'1px solid #1e3a5f',
                      }}>Actions</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {filteredSystems.length === 0
                      ? <tr><td colSpan={13} style={{ textAlign: 'center', padding: 28, color: '#1e40af' }}>No systems found</td></tr>
                      : filteredSystems.map((s, idx) => {
                        const packageOptions = packageOptionsForSystem(s);
                        const packageDownloadBlocked = Boolean(s.agentVersion) || (Number(s.downloadCount) || 0) > 0;
                        const updateButton = agentUpdateButtonState(s, targetAgentVersion(s, currentAgentVersion));
                        return (
                        <tr key={s._id} style={{ background: idx % 2 ? 'rgba(6,14,26,.45)' : 'transparent' }}>
                          <td style={{ padding: '10px 12px', color: '#e2e8f0', fontWeight: 700, borderBottom:'1px solid #0b1728' }}>
                            <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                              <span style={{ color:'#60a5fa' }}>🖥</span>
                              <span style={{ overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.name}</span>
                            </div>
                          </td>
                          <td style={{ padding: '10px 12px', borderBottom:'1px solid #0b1728' }}><AgentTypeBadge type={s.agentType || 'system'} /></td>
                          <td style={{ padding: '10px 12px', borderBottom:'1px solid #0b1728' }}><OnlineBadge system={s} /></td>
                          <td title={s.hostname || ''} style={{ padding: '10px 12px', color: s.hostname ? '#94a3b8' : '#334155', fontFamily: 'monospace', fontSize: 11, borderBottom:'1px solid #0b1728', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.hostname || '—'}</td>
                          <td style={{ padding: '10px 12px', color: s.ip ? '#7dd3fc' : '#334155', fontFamily: 'monospace', fontSize: 11, borderBottom:'1px solid #0b1728', whiteSpace:'nowrap' }}>{s.ip || '—'}</td>
                          <td title={s.macAddress || ''} style={{ padding: '10px 12px', color: s.macAddress ? '#c084fc' : '#334155', fontFamily: 'monospace', fontSize: 10, borderBottom:'1px solid #0b1728', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.macAddress || '—'}</td>
                          <td title={s.os || ''} style={{ padding: '10px 12px', color: s.os ? '#94a3b8' : '#334155', fontSize: 11, borderBottom:'1px solid #0b1728', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.os || '—'}</td>
                          <td style={{ padding: '10px 12px', color: s.agentVersion ? '#34d399' : '#334155', fontSize: 11, fontWeight:700, borderBottom:'1px solid #0b1728' }}>{s.agentVersion ? `v${s.agentVersion}` : '—'}</td>
                          <td style={{ padding: '10px 12px', borderBottom:'1px solid #0b1728' }}><EDRBadge enabled={s.edrEnabled} /></td>
                          <td title={s.departmentId?.name || ''} style={{ padding: '10px 12px', color: '#93c5fd', fontSize: 11, borderBottom:'1px solid #0b1728', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{s.departmentId?.name || '—'}</td>
                          <td title={s.installDate ? fmtDate(s.installDate) : ''} style={{ padding: '10px 12px', color: s.installDate ? '#34d399' : '#334155', fontSize: 11, whiteSpace:'nowrap', borderBottom:'1px solid #0b1728' }}>{s.installDate ? fmtShortDate(s.installDate) : '—'}</td>
                          <td title={s.lastSeen ? fmtDate(s.lastSeen) : ''} style={{ padding: '10px 12px', color: s.lastSeen ? '#64748b' : '#334155', fontSize: 11, whiteSpace:'nowrap', borderBottom:'1px solid #0b1728' }}>{s.lastSeen ? fmtShortDate(s.lastSeen) : '—'}</td>
                          {isAdmin && (
                            <td style={{ position:'sticky', right:0, background: idx % 2 ? '#081426' : '#0a1628', padding: '10px 12px', borderBottom:'1px solid #0b1728', boxShadow:'-8px 0 12px rgba(0,0,0,.18)' }}>
                              <div style={{ display: 'flex', gap: 6 }}>
                                <button onClick={() => downloadConfig(s)} disabled={downloading === s._id} style={{
                                  fontSize: 10, padding: '5px 9px', borderRadius: 6,
                                  border: '1px solid #10b98155', background: '#064e3b66',
                                  color: '#34d399', cursor: 'pointer', fontWeight:700,
                                }}>{downloading === s._id ? '…' : '↓ Config'}</button>
                                {packageDownloadBlocked ? (
                                  <span style={{
                                    fontSize: 10,
                                    padding: '5px 9px',
                                    borderRadius: 6,
                                    border: '1px solid #334155',
                                    background: '#111827',
                                    color: '#64748b',
                                    fontWeight: 700,
                                    whiteSpace: 'nowrap',
                                  }}>
                                    {s.agentVersion ? 'Installed' : 'Downloaded'}
                                  </span>
                                ) : packageOptions.map(pkg => {
                                  const key = `${s._id}:${pkg.type}`;
                                  return (
                                    <button key={pkg.type}
                                      onClick={() => downloadPackage(s, pkg)}
                                      disabled={downloading === key}
                                      style={{
                                        fontSize: 10, padding: '5px 9px', borderRadius: 6,
                                        border: '1px solid #10b98155', background: '#064e3b66',
                                        color: '#34d399', cursor: 'pointer', fontWeight:700,
                                      }}>
                                      {downloading === key ? '…' : `↓ ${pkg.label}`}
                                    </button>
                                  );
                                })}
                                <button
                                  onClick={() => updateSystemAgent(s)}
                                  disabled={updateButton.disabled || downloading === `${s._id}:update`}
                                  title={updateButton.title}
                                  style={{
                                  fontSize: 10, padding: '5px 9px', borderRadius: 6,
                                  border: updateButton.border,
                                  background: updateButton.background,
                                  color: updateButton.color,
                                  cursor: updateButton.disabled ? 'not-allowed' : 'pointer',
                                  fontWeight:700,
                                }}>{downloading === `${s._id}:update` ? '…' : updateButton.label}</button>
                              </div>
                            </td>
                          )}
                        </tr>
                        );
                      })
                    }
                  </tbody>
                </table>
              </div>
            )
            : Array.isArray(depts) && depts.length > 0
              ? (
                /* ── Grouped by Department ── */
                depts.map(dept => {
                  const deptSystems = filteredSystems.filter(s =>
                    (s.departmentId?._id || s.departmentId) === dept._id
                  );
                  return (
                    <div key={dept._id} style={{ background: '#0c1a2e', border: '1px solid #1e3a5f', borderRadius: 10, padding: '14px 16px', marginBottom: 14 }}>
                      {/* Dept header */}
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                        <div>
                          <div style={{ fontSize: 14, fontWeight: 500, color: '#e2e8f0' }}>
                            📁 {dept.name}
                            <span style={{ fontSize: 11, color: '#1e40af', marginLeft: 8, fontWeight: 400 }}>
                              {deptSystems.length} system{deptSystems.length !== 1 ? 's' : ''}
                            </span>
                            {deptSystems.filter(s => isOnline(s.lastSeen)).length > 0 && (
                              <span style={{ fontSize: 10, marginLeft: 6, color: '#34d399' }}>
                                ● {deptSystems.filter(s => isOnline(s.lastSeen)).length} online
                              </span>
                            )}
                          </div>
                          {dept.description && <div style={{ fontSize: 11, color: '#1e3a5f', marginTop: 2 }}>{dept.description}</div>}
                        </div>
                      </div>

                      {/* Systems under this dept */}
                      {deptSystems.length === 0
                        ? <p style={{ fontSize: 12, color: '#1e3a5f', marginBottom: 8 }}>No systems in this department.</p>
                        : deptSystems.map(s => (
                          <SystemCard
                            key={s._id}
                            s={s}
                            isAdmin={isAdmin}
                            downloading={downloading}
                            currentAgentVersion={currentAgentVersion}
                            onDownload={downloadConfig}
                            onDownloadPackage={downloadPackage}
                            onUpdate={updateSystemAgent}
                          />
                        ))
                      }

                      {isAdmin && (
                        <AddSystemUnderDept
                          dept={dept}
                          canAddSystems={canAddSystems}
                          onAdded={handleInlineAdded}
                        />
                      )}
                    </div>
                  );
                })
              )
              : (
                /* ── No depts but have systems — flat list ── */
                filteredSystems.map(s => (
                  <SystemCard
                    key={s._id}
                    s={s}
                    isAdmin={isAdmin}
                    downloading={downloading}
                    currentAgentVersion={currentAgentVersion}
                    onDownload={downloadConfig}
                    onDownloadPackage={downloadPackage}
                    onUpdate={updateSystemAgent}
                  />
                ))
              )
      }
    </div>
  );
}
