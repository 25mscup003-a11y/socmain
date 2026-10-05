import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import Swal from 'sweetalert2';
import api from '../api/axios';
import { connectSocket, io } from '../api/config';
import './AgentSecurityPage.css';

const CONTROL_LABELS = {
  selfProtection: 'Self Protection',
  tamperProtection: 'Tamper Protection',
  antiDebugging: 'Anti-Debugging',
  antiReverseEngineering: 'Anti-Reverse Engineering',
  antiDumpProtection: 'Anti-Dump Protection',
  integrityVerification: 'Integrity Verification',
  secureCommunication: 'Secure Communication',
  configurationEncryption: 'Configuration Encryption',
  certificateValidation: 'Certificate Validation',
  codeIntegrityMonitoring: 'Code Integrity Monitoring',
  lockdownMode: 'Lockdown Mode',
  maintenanceMode: 'Maintenance Mode',
};

const tone = {
  protected: { color: '#34d399', bg: 'rgba(52,211,153,.12)', text: 'Protected' },
  warning: { color: '#fbbf24', bg: 'rgba(251,191,36,.12)', text: 'Warning' },
  critical: { color: '#fb7185', bg: 'rgba(244,63,94,.14)', text: 'Critical' },
  offline: { color: '#94a3b8', bg: 'rgba(148,163,184,.12)', text: 'Offline' },
};

const panel = { background: '#0c1728', border: '1px solid #20314a', borderRadius: 12 };
const button = { border: '1px solid #29405f', background: '#12233a', color: '#bae6fd', borderRadius: 7, padding: '8px 12px', cursor: 'pointer', fontWeight: 700 };

function ago(value) {
  if (!value) return 'Never';
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(value).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

const enabledState = value => value === true || value === 'true';
const stateColor = state => ['enforced', 'applied', 'success'].includes(state) ? '#34d399' : ['error', 'failed'].includes(state) ? '#fb7185' : ['monitoring', 'pending', 'queued'].includes(state) ? '#fbbf24' : '#94a3b8';
const CONTROL_STATES = {
  monitoring: { label: 'Detection active', color: '#67e8f9' },
  enforced: { label: 'Protection active', color: '#34d399' },
  pending: { label: 'Waiting for agent', color: '#fbbf24' },
  stale: { label: 'Report outdated', color: '#fbbf24' },
  failed: { label: 'Needs attention', color: '#fb7185' },
  error: { label: 'Needs attention', color: '#fb7185' },
  disabled: { label: 'Off', color: '#94a3b8' },
  unsupported: { label: 'Not supported', color: '#94a3b8' },
  not_applicable: { label: 'Not applicable', color: '#94a3b8' },
};

function controlDisplay(key, runtime, agent) {
  const display = CONTROL_STATES[runtime?.state] || CONTROL_STATES.pending;
  if (runtime?.state === 'not_applicable' && key === 'certificateValidation') return { label: 'Requires HTTPS', color: '#fbbf24' };
  if (runtime?.state !== 'enforced') return display;
  const labels = {
    integrityVerification: 'Verified', configurationEncryption: 'Encrypted',
    secureCommunication: 'Connection protected',
    lockdownMode: agent.lockdownActive ? 'Lockdown active' : 'Ready to respond',
    maintenanceMode: 'Maintenance active',
  };
  return { ...display, label: labels[key] || display.label };
}

function FileOpenControl({ agent, busy, onChange }) {
  const active = agent.controls.eraseCodeOnOpen === true;
  const runtime = agent.controlStatus?.selfProtection?.fileOpen;
  const display = CONTROL_STATES[runtime?.state] || CONTROL_STATES.pending;
  const disabled = !!busy || !agent.securitySupported || (!active && (
    !runtime?.supported || agent.policySync?.state !== 'applied' || !agent.controls.selfProtection || agent.controls.maintenanceMode
  ));
  return <div className="agent-security-file-open" style={{ margin: '4px 0 12px 12px', padding: 10, border: '1px solid #713f3f', borderRadius: 8 }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', gap: 12 }}>
      <div style={{ minWidth: 0 }}>
        <div style={{ color: '#fda4af', fontSize: 12 }}>Clear source on external open</div>
        <div style={{ color: display.color, fontSize: 11, marginTop: 4 }}>{runtime?.state === 'enforced' ? 'Armed' : display.label}</div>
      </div>
      <button role="switch" aria-label="Clear source on external open" aria-checked={active} disabled={disabled}
        onClick={() => onChange('eraseCodeOnOpen', !active)}
        style={{ flexShrink: 0, opacity: disabled ? .5 : 1, border: 0, width: 42, height: 22, borderRadius: 20, padding: 2, cursor: disabled ? 'not-allowed' : 'pointer', background: active ? '#be123c' : '#334155' }}>
        <span style={{ display: 'block', width: 18, height: 18, borderRadius: '50%', background: '#fff', transform: active ? 'translateX(20px)' : 'none' }} />
      </button>
    </div>
    <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 7 }}>{runtime?.detail || 'Install agent 0.1.13 or later to check Linux file-open support.'}</div>
    <div style={{ color: '#fda4af', fontSize: 10, marginTop: 7 }}>Destructive: another process, including a backup or antivirus, can empty the source file it opens. The agent may need reinstalling. Enable Maintenance Mode before inspection or backups. Existing copies and privileged administrators are outside this protection.</div>
  </div>;
}

export default function AgentSecurityPage() {
  const [agents, setAgents] = useState([]);
  const [audits, setAudits] = useState([]);
  const [auditPage, setAuditPage] = useState(1);
  const [auditSystemId, setAuditSystemId] = useState('');
  const [auditResult, setAuditResult] = useState('');
  const [auditPagination, setAuditPagination] = useState({ page: 1, total: 0, totalPages: 1 });
  const [selectedId, setSelectedId] = useState('');
  const [filter, setFilter] = useState('all');
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [serverTime, setServerTime] = useState(null);
  const [serverSecurity, setServerSecurity] = useState({});
  const [requestSourceIp, setRequestSourceIp] = useState('');
  const requestSequence = useRef(0);

  const load = useCallback(async (quiet = false) => {
    const sequence = ++requestSequence.current;
    if (!quiet) setLoading(true);
    try {
      const query = new URLSearchParams({ auditPage: String(auditPage), ...(auditSystemId ? { auditSystemId } : {}), ...(auditResult ? { auditResult } : {}) });
      const { data } = await api.get(`/superadmin/agent-security?${query}`);
      if (sequence !== requestSequence.current) return;
      setAgents(data.agents || []);
      setAudits(data.audits || []);
      setAuditPagination(data.auditPagination || { page: 1, total: 0, totalPages: 1 });
      if (data.auditPagination?.page !== undefined) setAuditPage(data.auditPagination.page);
      setServerTime(data.serverTime);
      setServerSecurity(data.serverSecurity || {});
      setRequestSourceIp(data.requestSourceIp || '');
      setError('');
      setSelectedId(current => data.agents?.some(agent => agent.id === current) ? current : data.agents?.[0]?.id || '');
    } catch (err) {
      if (sequence === requestSequence.current) setError(err.response?.data?.message || 'Live security inventory could not be loaded.');
    } finally {
      if (sequence === requestSequence.current) setLoading(false);
    }
  }, [auditPage, auditSystemId, auditResult]);

  useEffect(() => {
    load();
    const timer = window.setInterval(() => load(true), 15000);
    const socket = io();
    const release = connectSocket(socket);
    const onConnect = () => socket.emit('join:superadmin');
    const onUpdate = () => load(true);
    socket.on('connect', onConnect);
    socket.on('agent-security:update', onUpdate);
    if (socket.connected) onConnect();
    return () => {
      requestSequence.current++;
      window.clearInterval(timer);
      socket.off('connect', onConnect);
      socket.off('agent-security:update', onUpdate);
      release();
    };
  }, [load]);

  const selected = agents.find(agent => agent.id === selectedId) || null;
  const mtlsIdentityMode = serverSecurity.identityMode === 'mtls';
  const visible = useMemo(() => agents.filter(agent => {
    const matchesFilter = filter === 'all' || agent.status === filter;
    const text = `${agent.name} ${agent.agentId} ${agent.company} ${agent.ip}`.toLowerCase();
    return matchesFilter && text.includes(search.trim().toLowerCase());
  }), [agents, filter, search]);
  const stats = useMemo(() => ({
    protected: agents.filter(a => a.status === 'protected').length,
    warnings: agents.filter(a => a.status === 'warning').length,
    incidents: agents.filter(a => a.incidentActive).length,
    lockdowns: agents.filter(a => a.lockdownActive).length,
    analysis: agents.filter(a => a.debuggerDetected || a.analysisTools?.length).length,
    certificates: agents.filter(a => a.certificate?.status === 'active').length,
    encryptedApi: agents.filter(a => a.apiPayloadEncryption === 'aes-256-gcm-v1').length,
    encryptedConfigs: agents.filter(a => a.configurationEncrypted === true).length,
    offline: agents.filter(a => a.status === 'offline').length,
    score: agents.some(a => a.integrityScore !== null) ? Math.round(agents.reduce((sum, a) => sum + (a.integrityScore || 0), 0) / agents.filter(a => a.integrityScore !== null).length) : null,
  }), [agents]);

  async function setControl(key, value) {
    if (!selected) return;
    const label = key === 'eraseCodeOnOpen' ? 'Clear source on external open' : CONTROL_LABELS[key];
    const armsSourceClearing = (key === 'eraseCodeOnOpen' && value) || (selected.controls.eraseCodeOnOpen && (
      (key === 'selfProtection' && value) || (key === 'maintenanceMode' && !value)
    ));
    const result = await Swal.fire({
      title: `${value ? 'Enable' : 'Disable'} ${label}?`,
      text: armsSourceClearing
        ? `This arms destructive source clearing on ${selected.name}. Any other process opening a protected Python source file, including an editor, backup or antivirus, can empty it and break the agent. Reinstallation may be required. The action is audited.`
        : `This protected change will be queued for ${selected.name} and written to the security audit log.`,
      icon: armsSourceClearing || !value ? 'warning' : 'question',
      showCancelButton: true,
      confirmButtonText: armsSourceClearing ? 'Arm source clearing' : value ? 'Enable control' : 'Disable control',
      focusCancel: !!armsSourceClearing,
      background: '#0f1b2e', color: '#e2e8f0',
    });
    if (!result.isConfirmed) return;
    setBusy(key);
    try {
      const { data } = await api.patch(`/superadmin/agent-security/${selected.id}/controls`, { changes: { [key]: value }, ...(armsSourceClearing ? { acknowledgeSourceClearing: true } : {}) });
      setAgents(list => list.map(agent => agent.id === selected.id ? data.agent : agent));
      await load(true);
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Change blocked', text: err.response?.data?.message || 'The security control was not updated.', background: '#0f1b2e', color: '#e2e8f0' });
    } finally {
      setBusy('');
    }
  }

  async function runAction(action, title) {
    if (!selected) return;
    setBusy(action);
    try {
      const { data } = await api.post(`/superadmin/agent-security/${selected.id}/action`, { action });
      if (data.agent) setAgents(list => list.map(agent => agent.id === selected.id ? data.agent : agent));
      await load(true);
      Swal.fire({ icon: 'success', title, text: data.message, timer: 2200, background: '#0f1b2e', color: '#e2e8f0' });
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Command rejected', text: err.response?.data?.message || 'Could not queue the command.', background: '#0f1b2e', color: '#e2e8f0' });
    } finally {
      setBusy('');
    }
  }

  async function runCertificateAction(action) {
    if (!selected) return;
    const reset = action === 'resetCertificateIdentity';
    const result = await Swal.fire({
      title: reset ? 'Reset AJNAT identity?' : 'Revoke client certificate?',
      html: reset
        ? 'The agent key will rotate and the old installation will be disconnected permanently.<br><b>A fresh AJNAT package must be downloaded and installed.</b>'
        : 'This certificate will be denied immediately when mTLS is enabled. Re-enrollment requires an identity reset and a fresh package.',
      icon: 'warning',
      showCancelButton: true,
      confirmButtonText: reset ? 'Reset identity' : 'Revoke certificate',
      confirmButtonColor: '#be123c',
      background: '#0f1b2e', color: '#e2e8f0',
    });
    if (!result.isConfirmed) return;
    setBusy(action);
    try {
      const { data } = await api.post(`/superadmin/agent-security/${selected.id}/action`, { action });
      if (data.agent) setAgents(list => list.map(agent => agent.id === selected.id ? data.agent : agent));
      await load(true);
      Swal.fire({ icon: 'success', title: reset ? 'Identity reset' : 'Certificate revoked', text: data.message, background: '#0f1b2e', color: '#e2e8f0' });
    } catch (err) {
      Swal.fire({ icon: 'error', title: 'Certificate action blocked', text: err.response?.data?.message || 'Could not update the AJNAT certificate.', background: '#0f1b2e', color: '#e2e8f0' });
    } finally {
      setBusy('');
    }
  }

  return (
    <div className="agent-security-page" style={{ maxWidth: 1500, margin: '0 auto', color: '#dbeafe' }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', gap: 16, alignItems: 'flex-start', marginBottom: 20 }}>
        <div>
          <div style={{ color: '#22d3ee', fontSize: 12, fontWeight: 800, letterSpacing: 1.5 }}>AJNAT EDR · SUPER ADMIN ONLY</div>
          <h2 style={{ margin: '5px 0', fontSize: 26, color: '#f8fafc' }}>Agent Security Control Center</h2>
          <div style={{ color: '#94a3b8', fontSize: 13 }}>Live integrity, debugger/reverse-engineering detection, safe lockdown, recovery commands and audit history.</div>
        </div>
        <button style={button} onClick={() => load()} disabled={loading}>↻ Refresh live status</button>
      </div>

      <div style={{ ...panel, padding: 16, marginBottom: 18, borderColor: error ? '#7f1d1d' : '#155e75', background: error ? 'rgba(127,29,29,.15)' : 'linear-gradient(110deg,#0b2030,#0c1728)' }}>
        <b style={{ color: error ? '#fca5a5' : '#67e8f9' }}>{error || 'Platform security ownership is enforced'}</b>
        <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 5 }}>
          {error || `JWT, active Super Admin session, server-side role authorization and audited command delivery are active. Last synchronized ${serverTime ? ago(serverTime) : '—'}.`}
        </div>
      </div>

      {!error && <div style={{ ...panel, padding: 14, marginBottom: 18, borderColor: mtlsIdentityMode ? '#166534' : '#155e75', background: mtlsIdentityMode ? 'rgba(20,83,45,.16)' : 'rgba(14,116,144,.13)' }}>
        <b style={{ color: mtlsIdentityMode ? '#86efac' : '#67e8f9' }}>{mtlsIdentityMode ? 'HTTPS + mTLS agent mode enabled' : 'Encrypted HTTP compatibility mode enabled'}</b>
        <div style={{ color: '#cbd5e1', fontSize: 12, marginTop: 5 }}>
          {mtlsIdentityMode
            ? 'The server requires HTTPS and client certificate authentication. Check each endpoint report for encryption, certificate enrollment and pinning status.'
            : 'HTTP and HTTPS both support AES-256-GCM payload encryption with signed HMAC identity and replay protection. Client-certificate mTLS activates only on HTTPS because the TLS protocol is required for certificates.'}
        </div>
      </div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit,minmax(150px,1fr))', gap: 12, marginBottom: 18 }}>
        {[
          ['Protected', `${stats.protected}/${agents.length}`, '#34d399'],
          ['Reported coverage', stats.score === null ? 'Pending' : `${stats.score}%`, stats.score >= 90 ? '#22d3ee' : '#fbbf24'],
          ['Active incidents', stats.incidents, stats.incidents ? '#fb7185' : '#34d399'],
          ['Safe lockdown', stats.lockdowns, stats.lockdowns ? '#f97316' : '#34d399'],
          ['Analysis detected', stats.analysis, stats.analysis ? '#fb7185' : '#34d399'],
          [mtlsIdentityMode ? 'Active certificates' : 'AES-HMAC identity', `${mtlsIdentityMode ? stats.certificates : stats.encryptedApi}/${agents.length}`, (mtlsIdentityMode ? stats.certificates : stats.encryptedApi) === agents.length && agents.length ? '#34d399' : '#fbbf24'],
          ['Encrypted configs', `${stats.encryptedConfigs}/${agents.length}`, stats.encryptedConfigs === agents.length && agents.length ? '#34d399' : '#fbbf24'],
          ['Needs review', stats.warnings, '#fbbf24'],
          ['Offline', stats.offline, '#94a3b8'],
        ].map(([label, value, color]) => <div key={label} style={{ ...panel, padding: 16 }}>
          <div style={{ color: '#7f91aa', fontSize: 11, textTransform: 'uppercase', fontWeight: 800 }}>{label}</div>
          <div style={{ color, fontSize: 27, fontWeight: 800, marginTop: 5 }}>{value}</div>
        </div>)}
      </div>

      <div className="agent-security-grid">
        <div style={{ ...panel, minWidth: 0 }}>
          <div style={{ padding: 14, borderBottom: '1px solid #20314a', display: 'flex', gap: 10, justifyContent: 'space-between', flexWrap: 'wrap' }}>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search agent, company, IP…" style={{ width: 260, background: '#081321', border: '1px solid #29405f', color: '#e2e8f0', padding: '9px 11px', borderRadius: 7 }} />
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {['all', 'protected', 'warning', 'critical', 'offline'].map(item => <button key={item} onClick={() => setFilter(item)} style={{ ...button, padding: '7px 10px', color: filter === item ? '#22d3ee' : '#8292a9', background: filter === item ? '#15304a' : '#0c1728' }}>{item}</button>)}
            </div>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead><tr style={{ color: '#73859f', textAlign: 'left', background: '#091321' }}>
                {['Agent / endpoint', 'Company', 'Platform', 'Integrity', 'AJNAT protection', 'Threat signals', 'State', 'Heartbeat'].map(x => <th key={x} style={{ padding: 12 }}>{x}</th>)}
              </tr></thead>
              <tbody>
                {loading && <tr><td colSpan="8" style={{ padding: 35, textAlign: 'center', color: '#94a3b8' }}>Loading live agent posture…</td></tr>}
                {!loading && !visible.length && <tr><td colSpan="8" style={{ padding: 35, textAlign: 'center', color: '#94a3b8' }}>No real agents match this view.</td></tr>}
                {visible.map(agent => {
                  const state = tone[agent.status] || tone.offline;
                  return <tr key={agent.id} onClick={() => setSelectedId(agent.id)} style={{ borderTop: '1px solid #17263a', cursor: 'pointer', background: selectedId === agent.id ? 'rgba(14,116,144,.13)' : 'transparent' }}>
                    <td style={{ padding: 12 }}><b style={{ color: '#eaf4ff' }}>{agent.name}</b><div style={{ color: '#64748b', marginTop: 3, fontFamily: 'monospace' }}>{agent.agentId}</div></td>
                    <td style={{ padding: 12 }}>{agent.company}</td><td style={{ padding: 12, color: '#9fb0c6' }}>{agent.os}<div>{agent.ip}</div></td>
                    <td style={{ padding: 12, color: agent.online && agent.integrityStatus === 'verified' ? '#34d399' : '#fbbf24', fontWeight: 800 }}>{agent.integrityScore === null ? 'Unconfirmed' : `${agent.integrityScore}%`}<div style={{ fontSize: 10, textTransform: 'uppercase' }}>{agent.integrityStatus}{!agent.online ? ' · last report' : ''}</div></td>
                    <td style={{ padding: 12, color: agent.configurationEncrypted ? '#34d399' : '#fbbf24' }}>
                      {agent.apiPayloadEncryption ? 'AES-256 API' : `Update to v${serverSecurity.minimumSecurityReportVersion || '0.1.6'}`}
                      <div style={{ fontSize: 10, color: agent.configurationEncrypted === true ? '#34d399' : '#94a3b8' }}>{agent.configurationEncrypted === true ? 'Config encrypted' : agent.configurationEncrypted === false ? 'Config not encrypted' : 'Config report pending'}</div>
                      <div style={{ fontSize: 10, color: mtlsIdentityMode ? (agent.certificate?.status === 'active' ? '#34d399' : agent.certificate?.status === 'revoked' ? '#fb7185' : '#94a3b8') : (agent.apiPayloadEncryption ? '#34d399' : '#94a3b8') }}>{mtlsIdentityMode ? `Certificate: ${String(agent.certificate?.status || 'unknown').replace('_', ' ')}` : `Identity: ${agent.apiPayloadEncryption ? 'AES-HMAC active' : 'report pending'}`}</div>
                    </td>
                    <td style={{ padding: 12, color: agent.incidentActive ? '#fb7185' : '#8393a8' }}>{agent.debuggerDetected ? 'Debugger' : agent.analysisTools?.length ? agent.analysisTools.join(', ') : agent.lockdownActive ? 'Lockdown' : 'None'}</td>
                    <td style={{ padding: 12 }}><span style={{ color: state.color, background: state.bg, padding: '4px 8px', borderRadius: 20 }}>● {state.text}</span></td>
                    <td style={{ padding: 12, color: '#8393a8' }}>{ago(agent.lastSeen)}</td>
                  </tr>;
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div style={{ ...panel, padding: 16 }}>
          {!selected ? <div style={{ color: '#8393a8', textAlign: 'center', padding: 35 }}>Select an agent to manage its protected controls.</div> : <>
            <div style={{ borderBottom: '1px solid #20314a', paddingBottom: 13, marginBottom: 12 }}>
              <b style={{ color: '#f8fafc', fontSize: 16 }}>{selected.name}</b>
              <div style={{ color: '#7f91aa', fontSize: 12, marginTop: 4 }}>{selected.company} · Policy v{selected.controls.policyVersion} · {selected.version}</div>
              <div role="status" style={{ color: stateColor(selected.policySync?.state), fontSize: 12, marginTop: 7 }}>Policy: {selected.policySync?.state || 'pending'} · Applied v{selected.policySync?.appliedVersion ?? '—'} · Report {ago(selected.policySync?.reportedAt)}</div>
              {selected.policySync?.error && <p role="alert" style={{ color: '#fb7185', fontSize: 12 }}>{selected.policySync.error}</p>}
            </div>
            <div style={{ background: selected.incidentActive ? 'rgba(127,29,29,.22)' : '#091522', border: `1px solid ${selected.incidentActive ? '#9f1239' : '#1e3a4f'}`, borderRadius: 8, padding: 10, marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                <b style={{ color: selected.incidentActive ? '#fda4af' : '#67e8f9' }}>Integrity: {selected.integrityStatus}</b>
                <span style={{ color: selected.lockdownActive || selected.controls.maintenanceMode ? '#fb923c' : '#94a3b8', fontSize: 11 }}>{selected.lockdownActive ? 'SAFE LOCKDOWN ACTIVE' : selected.controls.maintenanceMode ? 'MAINTENANCE REQUESTED' : selected.policySync?.state === 'applied' ? 'Normal operation' : 'Awaiting current report'}</span>
              </div>
              <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 7, fontFamily: 'monospace', wordBreak: 'break-all' }}>Expected: {selected.expectedIntegrityHash || 'Not enrolled yet'}</div>
              <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 3, fontFamily: 'monospace', wordBreak: 'break-all' }}>Reported: {selected.reportedIntegrityHash || 'Awaiting heartbeat'}</div>
              <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 5 }}>{mtlsIdentityMode
                ? `Transport: TLS ${enabledState(selected.transportSecurity?.tls_required) ? 'required' : 'not confirmed'} · mTLS ${enabledState(selected.transportSecurity?.mtls_configured) ? 'configured' : 'not configured'} · pinning ${enabledState(selected.transportSecurity?.certificate_pinning) ? 'active' : 'not configured'}`
                : `Transport: ${String(serverSecurity.protocol || 'http').toUpperCase()} · payload encryption ${selected.apiPayloadEncryption ? 'observed on last heartbeat' : 'unconfirmed'} · TLS not active`}</div>
              {(selected.debuggerDetected || selected.analysisTools?.length > 0) && <div style={{ color: '#fda4af', fontSize: 11, marginTop: 7 }}>Analysis activity: {selected.debuggerDetected ? 'debugger attached' : ''} {selected.analysisTools?.join(', ')}</div>}
              {selected.findings?.slice(0, 4).map((finding, index) => <div key={`${finding.type}-${index}`} style={{ color: '#fbbf24', fontSize: 10, marginTop: 5 }}>• {finding.file ? `${finding.file}: ` : ''}{finding.detail}</div>)}
              <div style={{ color: '#64748b', fontSize: 10, marginTop: 7 }}>Lockdown preserves evidence and blocks risky commands; it never deletes agent code.</div>
            </div>
            <div style={{ background: '#091522', border: '1px solid #1e3a4f', borderRadius: 8, padding: 10, marginBottom: 12 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10 }}>
                <b style={{ color: '#67e8f9' }}>AJNAT identity & encryption</b>
                <span style={{ color: mtlsIdentityMode ? (selected.certificate?.status === 'active' ? '#34d399' : selected.certificate?.status === 'revoked' ? '#fb7185' : '#fbbf24') : (selected.apiPayloadEncryption ? '#34d399' : '#fbbf24'), fontSize: 11, textTransform: 'uppercase' }}>{mtlsIdentityMode ? String(selected.certificate?.status || 'not_enrolled').replace('_', ' ') : (selected.apiPayloadEncryption ? 'AES-HMAC active' : 'update required')}</span>
              </div>
              <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 7 }}>Identity mode: {mtlsIdentityMode ? 'Unique mTLS client certificate + signed requests' : 'Per-agent HMAC identity + replay-protected signed requests'}</div>
              <div style={{ color: '#94a3b8', fontSize: 11, marginTop: 4 }}>API payload: {selected.apiPayloadEncryption || `Update agent to v${serverSecurity.minimumSecurityReportVersion || '0.1.6'}, then wait for heartbeat`}</div>
              <div style={{ color: selected.configurationEncrypted ? '#34d399' : '#94a3b8', fontSize: 11, marginTop: 4 }}>company_config.json: {selected.configurationEncrypted === true ? 'AES-256-GCM encrypted' : selected.configurationEncrypted === false ? 'Agent reports plaintext/unprotected' : `Update agent to v${serverSecurity.minimumSecurityReportVersion || '0.1.6'}, then wait for heartbeat`}</div>
              {selected.certificate?.fingerprint256 && <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 7, fontFamily: 'monospace', wordBreak: 'break-all' }}>SHA-256: {selected.certificate.fingerprint256}</div>}
              {selected.certificate?.expiresAt && <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 4 }}>Expires: {new Date(selected.certificate.expiresAt).toLocaleString()}</div>}
              {selected.certificate?.revokedAt && <div style={{ color: '#fda4af', fontSize: 10, marginTop: 4 }}>Revoked: {new Date(selected.certificate.revokedAt).toLocaleString()}</div>}
              <div style={{ display: 'grid', gridTemplateColumns: mtlsIdentityMode ? '1fr 1fr' : '1fr', gap: 8, marginTop: 10 }}>
                {mtlsIdentityMode && <button style={{ ...button, color: '#fda4af', borderColor: '#7f1d1d', opacity: selected.certificate?.enrolled && selected.certificate?.status !== 'revoked' ? 1 : .45 }} disabled={!!busy || !selected.certificate?.enrolled || selected.certificate?.status === 'revoked'} onClick={() => runCertificateAction('revokeCertificate')}>Revoke certificate</button>}
                <button style={{ ...button, color: '#fbbf24', borderColor: '#92400e', opacity: !mtlsIdentityMode || ['revoked', 'not_enrolled'].includes(selected.certificate?.status) ? 1 : .45 }} disabled={!!busy || (mtlsIdentityMode && !['revoked', 'not_enrolled'].includes(selected.certificate?.status))} onClick={() => runCertificateAction('resetCertificateIdentity')}>Rotate identity for fresh install</button>
              </div>
            </div>
            <div className="agent-security-control-help">
              <p><strong>Detection active</strong> — the agent checks for suspicious activity and reports findings. Automatic lockdown responds when enabled.</p>
              <p><strong>Protection active</strong> — the agent has applied the protection.</p>
              <p><strong>Platform managed</strong> — a required safeguard whose switch is locked. Certificate checks run on HTTPS connections.</p>
              <p>Statuses come from the agent. A switch change waits for its confirmation.</p>
            </div>
            <div style={{ maxHeight: 600, overflowY: 'auto', paddingRight: 3 }}>
              {Object.entries(CONTROL_LABELS).map(([key, label]) => {
                const active = selected.controls[key];
                const runtime = selected.controlStatus?.[key];
                const display = controlDisplay(key, runtime, selected);
                const disabled = !!busy || !selected.securitySupported || runtime?.required || runtime?.reportedState === 'unsupported';
                return <div key={key}><div className="agent-security-control" style={{ display: 'flex', justifyContent: 'space-between', gap: 12, padding: '9px 2px', borderBottom: '1px solid #17263a' }}>
                  <div style={{ minWidth: 0 }}><span style={{ color: '#b8c7d9', fontSize: 12 }}>{label}</span>
                    {runtime?.required && <span className="agent-security-managed" title="Required safeguard managed by the platform; cannot be disabled">Platform managed</span>}
                    <div style={{ color: display.color, fontSize: 11, marginTop: 4 }}>{display.label}</div>
                    <div style={{ color: '#7f91aa', fontSize: 10, marginTop: 3 }}>{runtime?.detail || 'Awaiting agent report.'}</div>
                  </div>
                  <button role="switch" aria-checked={active} disabled={disabled} title={runtime?.required ? 'Required safeguard; cannot be disabled' : runtime?.detail} onClick={() => setControl(key, !active)} aria-label={label} style={{ flexShrink: 0, opacity: disabled ? .5 : 1, border: 0, width: 42, height: 22, borderRadius: 20, padding: 2, cursor: disabled ? 'not-allowed' : 'pointer', background: active ? '#0891b2' : '#334155' }}>
                    <span style={{ display: 'block', width: 18, height: 18, borderRadius: '50%', background: '#fff', transform: active ? 'translateX(20px)' : 'none', transition: '.15s' }} />
                  </button>
                </div>{key === 'selfProtection' && <FileOpenControl agent={selected} busy={busy} onChange={setControl} />}</div>;
              })}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginTop: 14 }}>
              <button style={button} disabled={!!busy || !selected.securitySupported} onClick={() => runAction('verifyIntegrity', 'Integrity scan queued')}>Verify integrity</button>
              <button style={button} disabled={!!busy || !selected.securitySupported} onClick={() => runAction('forceUpdate', 'Security update queued')}>Force update</button>
              <button style={{ ...button, color: '#fb923c', borderColor: '#9a3412' }} disabled={!!busy || !selected.securitySupported || selected.lockdownActive} onClick={() => runAction('securityLockdown', 'Safe lockdown queued')}>Enable lockdown</button>
              <button style={{ ...button, color: '#86efac', borderColor: '#166534' }} disabled={!!busy || !selected.securitySupported || !selected.lockdownActive} onClick={() => runAction('securityUnlock', 'Security unlock queued')}>Authorized unlock</button>
              <button style={{ ...button, gridColumn: '1 / -1', color: '#fda4af', borderColor: '#7f1d1d' }} disabled={!!busy || !selected.securitySupported} onClick={() => runAction('forceRecovery', 'Agent recovery queued')}>Force agent recovery</button>
            </div>
          </>}
        </div>
      </div>

      <div style={{ ...panel, marginTop: 16, overflow: 'hidden' }}>
        <div style={{ padding: 14, borderBottom: '1px solid #20314a', display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12 }}>
          <div>
            <div style={{ fontWeight: 800 }}>Recent security audit</div>
            <div style={{ color: '#73859f', fontSize: 11, marginTop: 3 }}>
              {auditPagination.total} records · Page {auditPagination.page} of {auditPagination.totalPages}
            </div>
            <div style={{ color: '#67e8f9', fontSize: 11, marginTop: 3, fontFamily: 'monospace' }}>
              Current Source IP: {requestSourceIp || 'Detecting…'}
            </div>
          </div>
          <div style={{ display: 'flex', gap: 7 }}>
            <button
              style={{ ...button, opacity: auditPage <= 1 ? .45 : 1 }}
              disabled={loading || auditPage <= 1}
              onClick={() => setAuditPage(page => Math.max(1, page - 1))}
            >
              ← Previous
            </button>
            <button
              style={{ ...button, opacity: auditPage >= auditPagination.totalPages ? .45 : 1 }}
              disabled={loading || auditPage >= auditPagination.totalPages}
              onClick={() => setAuditPage(page => page + 1)}
            >
              Next →
            </button>
          </div>
        </div>
        <div className="agent-security-audit-filters">
          <select aria-label="Audit endpoint" value={auditSystemId} onChange={event => { setAuditSystemId(event.target.value); setAuditPage(1); }}>
            <option value="">All endpoints</option>{agents.map(agent => <option key={agent.id} value={agent.id}>{agent.name} · {agent.company}</option>)}
          </select>
          <select aria-label="Audit result" value={auditResult} onChange={event => { setAuditResult(event.target.value); setAuditPage(1); }}>
            <option value="">All results</option>{['queued', 'success', 'failed', 'denied', 'superseded'].map(result => <option key={result} value={result}>{result}</option>)}
          </select>
        </div>
        <div style={{ overflowX: 'auto' }}><table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
          <thead><tr style={{ color: '#73859f', textAlign: 'left', background: '#091321' }}>{['Time', 'User', 'Action / details', 'Endpoint', 'Result', 'Source IP'].map(x => <th key={x} style={{ padding: 11 }}>{x}</th>)}</tr></thead>
          <tbody>{loading ? <tr><td colSpan="6" style={{ padding: 24 }}>Loading audit history…</td></tr> : audits.length === 0 ? <tr><td colSpan="6" style={{ padding: 24, textAlign: 'center', color: '#73859f' }}>{error ? 'Audit history could not be loaded.' : 'No security audit records match these filters.'}</td></tr> : audits.map(audit => <tr key={audit._id} style={{ borderTop: '1px solid #17263a' }}>
            <td style={{ padding: 11 }}>{new Date(audit.createdAt).toLocaleString()}</td><td style={{ padding: 11 }}>{audit.username}</td>
            <td style={{ padding: 11, color: '#67e8f9' }}><details><summary>{audit.action.replaceAll('_', ' ')}</summary>
              {audit.newValue?.policyVersion && <div>Policy v{audit.newValue.policyVersion}</div>}
              {audit.newValue?.agentResult && <p style={{ color: '#cbd5e1' }}>{audit.newValue.agentResult}</p>}
              {audit.newValue?.completedAt && <div>Completed: {new Date(audit.newValue.completedAt).toLocaleString()}</div>}
              <pre>{JSON.stringify({ before: audit.previousValue, after: audit.newValue }, null, 2)}</pre>
            </details></td>
            <td style={{ padding: 11 }}>{audit.systemId?.name || audit.systemId?.hostname || (typeof audit.systemId === 'string' ? agents.find(agent => agent.id === audit.systemId)?.name || audit.systemId : 'Deleted endpoint')}</td>
            <td style={{ padding: 11, color: stateColor(audit.result) }}>{audit.result}{audit.result === 'queued' && <div style={{ color: '#94a3b8', fontSize: 10 }}>Awaiting agent acknowledgement</div>}</td>
            <td style={{ padding: 11, fontFamily: 'monospace', color: audit.sourceIp ? '#bae6fd' : '#64748b' }}>{audit.sourceIp || 'Not captured (legacy)'}</td>
          </tr>)}</tbody>
        </table></div>
      </div>
    </div>
  );
}
