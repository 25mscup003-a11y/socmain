import { useCallback, useEffect, useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';

const C = {
  bg: '#050d18', card: '#0b1929', card2: '#0f233a', border: '#1d3655',
  text: '#e2e8f0', muted: '#8ea0b8', sub: '#64748b', cyan: '#22d3ee',
  green: '#34d399', yellow: '#fbbf24', orange: '#fb923c', red: '#f87171', purple: '#a78bfa',
};

const severityColor = severity => ({ critical: C.red, high: C.orange, medium: C.yellow, low: C.green }[severity] || C.cyan);
const validIpv4 = value => {
  const parts = String(value || '').trim().split('.');
  return parts.length === 4 && parts.every(part => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
};

export function DnsSinkholeSetupContent({ embedded = false }) {
  const navigate = useNavigate();
  const [data, setData] = useState({ configuration: {}, rules: [], builtInRules: [], systems: [] });
  const [configDraft, setConfigDraft] = useState({ enabled: true, sinkholeIp: '0.0.0.0', enforcementMode: 'both', telemetryEnabled: true, reportIntervalSeconds: 300, syncBlocklist: true, targetMode: 'all', targetSystemIds: [] });
  const [selectedBuiltIns, setSelectedBuiltIns] = useState([]);
  const [newRule, setNewRule] = useState({ type: 'blocklist', domain: '', sinkholeIp: '', reason: '' });
  const [loading, setLoading] = useState(true);
  const [working, setWorking] = useState('');
  const [message, setMessage] = useState(null);
  const [editingRule, setEditingRule] = useState(null);
  const [editingBuiltIn, setEditingBuiltIn] = useState(null);
  const [addingRule, setAddingRule] = useState(false);

  const load = useCallback(async (quiet = false) => {
    if (!quiet) setLoading(true);
    try {
      const response = await api.get('/dns-sinkhole/configuration', { skipCache: true });
      const payload = response.data || {};
      setData({
        configuration: payload.configuration || {},
        rules: Array.isArray(payload.rules) ? payload.rules : [],
        builtInRules: Array.isArray(payload.builtInRules) ? payload.builtInRules : [],
        systems: Array.isArray(payload.systems) ? payload.systems : [],
      });
      setConfigDraft(current => ({ ...current, ...(payload.configuration || {}), targetSystemIds: (payload.configuration?.targetSystemIds || []).map(String) }));
      setSelectedBuiltIns(Array.isArray(payload.configuration?.builtInRuleIds) ? payload.configuration.builtInRuleIds : []);
      if (!quiet) setMessage(null);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'DNS Sinkhole rules could not be loaded.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggleBuiltIn = id => setSelectedBuiltIns(current => current.includes(id)
    ? current.filter(value => value !== id)
    : [...current, id]);

  const updateConfig = (key, value) => setConfigDraft(current => ({ ...current, [key]: value }));
  const selectedSystemIds = (configDraft.targetSystemIds || []).map(String);
  const newRuleIpValid = newRule.type === 'allowlist' || (validIpv4(newRule.sinkholeIp) && (newRule.type !== 'redirect' || String(newRule.sinkholeIp).trim() !== '0.0.0.0'));
  const editingRuleIpValid = !editingRule || editingRule.type === 'allowlist' || (validIpv4(editingRule.sinkholeIp) && (editingRule.type !== 'redirect' || String(editingRule.sinkholeIp).trim() !== '0.0.0.0'));
  const toggleTargetSystem = id => updateConfig('targetSystemIds', selectedSystemIds.includes(String(id))
    ? selectedSystemIds.filter(value => value !== String(id))
    : [...selectedSystemIds, String(id)]);

  const saveConfiguration = async () => {
    const target = configDraft.targetMode === 'all' ? 'all agents' : `${selectedSystemIds.length} selected agent(s)`;
    if (!window.confirm(`Save and apply this DNS Sinkhole configuration to ${target}?`)) return;
    setWorking('configuration'); setMessage(null);
    try {
      const response = await api.put('/dns-sinkhole/configuration', configDraft);
      setMessage({ type: 'success', text: response.data?.message || 'DNS Sinkhole configuration saved.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'DNS Sinkhole configuration could not be saved.' });
    } finally {
      setWorking('');
    }
  };

  const createCompanyRule = async event => {
    event?.preventDefault();
    if (!newRule.domain.trim() || !window.confirm(`Create ${newRule.type} rule for ${newRule.domain.trim()}?`)) return;
    setWorking('new-rule'); setMessage(null);
    try {
      const response = await api.post(`/dns-sinkhole/${newRule.type}`, { domain: newRule.domain, sinkholeIp: newRule.sinkholeIp, reason: newRule.reason });
      setNewRule(current => ({ ...current, domain: '', sinkholeIp: configDraft.sinkholeIp || '0.0.0.0', reason: '' }));
      setAddingRule(false);
      setMessage({ type: 'success', text: response.data?.message || 'Company DNS rule created.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'Company DNS rule could not be created.' });
    } finally {
      setWorking('');
    }
  };

  const applyBuiltIns = async () => {
    if (!window.confirm(`Apply ${selectedBuiltIns.length} selected built-in DNS rule(s) to the configured SOC agents?`)) return;
    setWorking('built-in'); setMessage(null);
    try {
      const response = await api.post('/dns-sinkhole/configuration/apply-built-in', { ruleIds: selectedBuiltIns });
      setMessage({ type: 'success', text: response.data?.message || 'Built-in rules queued successfully.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'Built-in rules could not be applied.' });
    } finally {
      setWorking('');
    }
  };

  const saveBuiltInRule = async event => {
    event.preventDefault();
    if (!editingBuiltIn?.id) return;
    setWorking(`built-in-${editingBuiltIn.id}`); setMessage(null);
    try {
      const response = await api.patch(`/dns-sinkhole/configuration/built-in/${editingBuiltIn.id}`, { settings: editingBuiltIn.settings });
      setEditingBuiltIn(null);
      setMessage({ type: 'success', text: response.data?.message || 'Built-in rule settings saved.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'Built-in rule settings could not be saved.' });
    } finally {
      setWorking('');
    }
  };

  const applyCompanyRule = async rule => {
    if (!window.confirm(`Apply ${rule.type} rule for ${rule.domain} to configured agents?`)) return;
    setWorking(String(rule._id)); setMessage(null);
    try {
      const response = await api.post(`/dns-sinkhole/rules/${rule._id}/apply`);
      setMessage({ type: 'success', text: response.data?.message || 'Company rule queued successfully.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'Company rule could not be applied.' });
    } finally {
      setWorking('');
    }
  };

  const saveEditedRule = async event => {
    event.preventDefault();
    if (!editingRule?._id || !editingRule.domain?.trim()) return;
    if (!window.confirm(`Save changes to the DNS rule for ${editingRule.domain.trim()} and update configured agents?`)) return;
    setWorking(`edit-${editingRule._id}`); setMessage(null);
    try {
      const response = await api.patch(`/dns-sinkhole/rules/${editingRule._id}`, {
        type: editingRule.type,
        domain: editingRule.domain,
        sinkholeIp: editingRule.sinkholeIp,
        reason: editingRule.reason,
      });
      setEditingRule(null);
      setMessage({ type: 'success', text: response.data?.message || 'Company rule updated successfully.' });
      await load(true);
    } catch (error) {
      setMessage({ type: 'error', text: error.response?.data?.message || 'Company rule could not be updated.' });
    } finally {
      setWorking('');
    }
  };

  const stats = useMemo(() => {
    const block = data.rules.filter(rule => rule.type === 'blocklist').length;
    const redirect = data.rules.filter(rule => rule.type === 'redirect').length;
    const allow = data.rules.filter(rule => rule.type === 'allowlist').length;
    const applied = data.systems.filter(system => Number(system.appliedVersion || 0) >= Number(data.configuration.version || 1)).length;
    const queued = data.systems.filter(system => system.pending).length;
    return { block, redirect, allow, applied, queued };
  }, [data]);

  const card = { background: C.card, border: `1px solid ${C.border}`, borderRadius: 12, padding: 16 };
  const button = { border: 0, borderRadius: 7, padding: '8px 13px', fontSize: 11, fontWeight: 900, cursor: 'pointer' };

  return (
    <div style={{ color: C.text, display: 'grid', gap: 15, minWidth: 0 }}>
      {!embedded && <header style={{ ...card, background: 'linear-gradient(135deg, rgba(8,28,48,.98), rgba(12,22,45,.98))', display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 14, flexWrap: 'wrap' }}>
        <div>
          <div style={{ color: C.cyan, fontSize: 11, fontWeight: 900, letterSpacing: '.08em', textTransform: 'uppercase' }}>EDR System Setup</div>
          <h2 style={{ color: '#f8fafc', fontSize: 22, margin: '5px 0' }}>🌐 DNS Sinkhole</h2>
          <div style={{ color: C.muted, fontSize: 11 }}>Choose built-in controls or apply an existing company rule to configured agent endpoints.</div>
        </div>
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
          <button type="button" onClick={() => navigate(-1)} style={{ ...button, color: C.text, background: C.card2, border: `1px solid ${C.border}` }}>← EDR Setup</button>
          <button type="button" onClick={() => navigate('/company-admin/edr?capabilityId=31&capability=dns-sinkhole')} style={{ ...button, color: '#001018', background: C.cyan }}>Open Monitoring</button>
        </div>
      </header>}

      {message && <div role="status" style={{ padding: '10px 12px', borderRadius: 8, color: message.type === 'success' ? C.green : C.red, background: `${message.type === 'success' ? C.green : C.red}12`, border: `1px solid ${message.type === 'success' ? C.green : C.red}55`, fontSize: 11 }}>{message.text}</div>}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(170px, 1fr))', gap: 10 }}>
        {[
          ['Service', data.configuration.enabled === false ? 'Disabled' : 'Enabled', data.configuration.enabled === false ? C.red : C.green],
          ['Company Blocklist', stats.block, C.red],
          ['Safe Redirects', stats.redirect, C.purple],
          ['Company Allowlist', stats.allow, C.green],
          ['Selected Built-ins', selectedBuiltIns.length, C.purple],
          ['Agents Applied', `${stats.applied}/${data.systems.length}`, C.cyan],
          ['Commands Queued', stats.queued, C.yellow],
        ].map(([label, value, color]) => <div key={label} style={card}><div style={{ color: C.muted, fontSize: 9, fontWeight: 800, textTransform: 'uppercase' }}>{label}</div><div style={{ color, fontSize: 22, fontWeight: 900, marginTop: 6 }}>{loading ? '—' : value}</div></div>)}
      </div>

      <section style={card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 13 }}>
          <div><h3 style={{ color: '#fff', fontSize: 14, margin: 0 }}>Built-in DNS Rules</h3><div style={{ color: C.muted, fontSize: 10, marginTop: 4 }}>Select only the controls required for this company, then apply once.</div></div>
          <button type="button" onClick={applyBuiltIns} disabled={loading || working === 'built-in'} style={{ ...button, background: C.purple, color: '#0c0618', opacity: working ? .65 : 1 }}>{working === 'built-in' ? 'Applying…' : `Apply Selected (${selectedBuiltIns.length})`}</button>
        </div>
        {editingBuiltIn && <div style={{ padding: 13, marginBottom: 12, borderRadius: 8, background: C.card2, border: `1px solid ${C.purple}66` }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', gap: 10, alignItems: 'center', marginBottom: 10 }}><div><b style={{ color: C.purple, fontSize: 12 }}>Edit: {editingBuiltIn.name}</b><div style={{ color: C.sub, fontSize: 9, marginTop: 3 }}>Company-specific values. Save first, then use Apply Selected.</div></div><button type="button" onClick={() => setEditingBuiltIn(null)} style={{ ...button, padding: '5px 9px', background: 'transparent', color: C.muted, border: `1px solid ${C.border}` }}>Cancel</button></div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: 9 }}>
            {Object.entries(editingBuiltIn.settings || {}).map(([key, value]) => <label key={key} style={{ color: C.muted, fontSize: 9, textTransform: 'uppercase' }}>
              {({ defaultSeverity: 'Default Severity', alertThreshold: 'Alert Threshold', cooldownSeconds: 'Cooldown (seconds)', minimumConnections: 'Minimum Connections', consistencyThreshold: 'Consistency Threshold', reportIntervalSeconds: 'Report Interval (seconds)' })[key] || key}
              {key === 'defaultSeverity'
                ? <select value={value} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, [key]: event.target.value } }))} style={{ width: '100%', marginTop: 5, padding: 8, borderRadius: 6, border: `1px solid ${C.border}`, background: C.bg, color: C.text }}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select>
                : <input type="number" value={value} onChange={event => setEditingBuiltIn(current => ({ ...current, settings: { ...current.settings, [key]: Number(event.target.value) } }))} style={{ width: '100%', boxSizing: 'border-box', marginTop: 5, padding: 8, borderRadius: 6, border: `1px solid ${C.border}`, background: C.bg, color: C.text }} />}
            </label>)}
          </div>
          <button type="button" onClick={saveBuiltInRule} disabled={Boolean(working)} style={{ ...button, marginTop: 11, background: C.purple, color: '#0c0618' }}>{working === `built-in-${editingBuiltIn.id}` ? 'Saving…' : 'Save Rule Settings'}</button>
          <div style={{ borderTop: `1px solid ${C.border}`, marginTop: 14, paddingTop: 13 }}>
            <div style={{ color: C.text, fontSize: 11, fontWeight: 900 }}>Add DNS Rule</div>
            <div style={{ color: C.sub, fontSize: 9, marginTop: 3, marginBottom: 9 }}>Add a complete company domain policy while configuring this built-in detector.</div>
            <div style={{ display: 'grid', gridTemplateColumns: '130px repeat(3, minmax(160px, 1fr)) auto', gap: 8 }}>
              <select value={newRule.type} onChange={event => setNewRule(current => ({ ...current, type: event.target.value }))} aria-label="Built-in editor rule type" style={{ background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }}><option value="blocklist">Block</option><option value="redirect">Redirect to Safe Server</option><option value="allowlist">Allow</option></select>
              <input value={newRule.domain} onChange={event => setNewRule(current => ({ ...current, domain: event.target.value }))} placeholder="domain.example" aria-label="Built-in editor domain" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
              <input value={newRule.sinkholeIp} onChange={event => setNewRule(current => ({ ...current, sinkholeIp: event.target.value }))} required={newRule.type !== 'allowlist'} disabled={newRule.type === 'allowlist'} placeholder={newRule.type === 'redirect' ? 'Safe server IPv4' : (configDraft.sinkholeIp || '0.0.0.0')} aria-label="Built-in editor sinkhole server IP" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${newRuleIpValid ? C.border : C.red}`, borderRadius: 6, padding: 8, fontFamily: 'monospace', opacity: newRule.type === 'allowlist' ? .55 : 1 }} />
              <input value={newRule.reason} onChange={event => setNewRule(current => ({ ...current, reason: event.target.value }))} maxLength={500} placeholder="Reason / ticket reference" aria-label="Built-in editor rule reason" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
              <button type="button" onClick={createCompanyRule} disabled={Boolean(working) || !newRule.domain.trim() || !newRuleIpValid} style={{ ...button, background: newRule.type === 'blocklist' ? C.red : newRule.type === 'redirect' ? C.purple : C.green, color: newRule.type === 'blocklist' ? '#fff' : '#00150c' }}>{working === 'new-rule' ? 'Adding…' : 'Add Rule'}</button>
            </div>
          </div>
        </div>}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: 10 }}>
          {data.builtInRules.map(rule => {
            const selected = selectedBuiltIns.includes(rule.id);
            const color = severityColor(rule.severity);
            return <div key={rule.id} style={{ padding: 13, borderRadius: 9, background: selected ? `${C.purple}12` : C.card2, border: `1px solid ${selected ? C.purple : C.border}` }}>
              <label style={{ display: 'grid', gridTemplateColumns: '22px minmax(0, 1fr)', gap: 10, cursor: 'pointer' }}>
                <input type="checkbox" checked={selected} onChange={() => toggleBuiltIn(rule.id)} style={{ width: 17, height: 17, accentColor: C.purple }} />
                <span><span style={{ color: C.text, fontSize: 12, fontWeight: 900 }}>{rule.name}</span><span style={{ display: 'block', color: C.muted, fontSize: 10, lineHeight: 1.45, marginTop: 5 }}>{rule.description}</span></span>
              </label>
              <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8, alignItems: 'center', marginTop: 10 }}><span style={{ display: 'inline-block', color, border: `1px solid ${color}55`, borderRadius: 5, padding: '2px 6px', fontSize: 8, fontWeight: 900 }}>{rule.category} · {rule.severity}</span><button type="button" onClick={() => setEditingBuiltIn({ ...rule, settings: { ...(rule.settings || {}) } })} disabled={Boolean(working)} style={{ ...button, padding: '5px 9px', background: C.card, color: C.purple, border: `1px solid ${C.purple}66` }}>Edit</button></div>
            </div>;
          })}
          {!loading && !data.builtInRules.length && <div style={{ color: C.muted, fontSize: 11 }}>No built-in rules available.</div>}
        </div>
      </section>

      <section style={card}>
        <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div><h3 style={{ color: '#fff', fontSize: 14, margin: 0 }}>Company DNS Rules</h3><div style={{ color: C.muted, fontSize: 10, marginTop: 4 }}>Block a domain, redirect it to a safe server, or allow normal DNS resolution.</div></div>
          <button
            type="button"
            onClick={() => {
              setAddingRule(current => !current);
              setEditingRule(null);
              setEditingBuiltIn(null);
              setMessage(null);
              setNewRule(current => ({ ...current, sinkholeIp: current.sinkholeIp || configDraft.sinkholeIp || '0.0.0.0' }));
            }}
            disabled={Boolean(working)}
            style={{ ...button, background: addingRule ? C.card2 : C.cyan, color: addingRule ? C.muted : '#001018', border: addingRule ? `1px solid ${C.border}` : 0 }}
          >
            {addingRule ? 'Cancel' : '＋ Add New Rule'}
          </button>
        </div>
        {addingRule && <form onSubmit={createCompanyRule} style={{ display: 'grid', gridTemplateColumns: '130px repeat(3, minmax(160px, 1fr)) auto', gap: 8, padding: 12, marginBottom: 12, borderRadius: 8, background: C.card2, border: `1px solid ${C.cyan}66` }}>
          <select value={newRule.type} onChange={event => setNewRule(current => ({ ...current, type: event.target.value }))} aria-label="New DNS rule type" style={{ background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }}><option value="blocklist">Block</option><option value="redirect">Redirect to Safe Server</option><option value="allowlist">Allow</option></select>
          <input value={newRule.domain} onChange={event => setNewRule(current => ({ ...current, domain: event.target.value }))} required autoFocus placeholder="domain.example" aria-label="New DNS rule domain" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
          <input value={newRule.sinkholeIp} onChange={event => setNewRule(current => ({ ...current, sinkholeIp: event.target.value }))} required={newRule.type !== 'allowlist'} disabled={newRule.type === 'allowlist'} placeholder={newRule.type === 'redirect' ? 'Safe server IPv4' : 'Blocking IPv4 (0.0.0.0)'} aria-label="New DNS rule sinkhole server IP" aria-invalid={!newRuleIpValid} style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${newRuleIpValid ? C.border : C.red}`, borderRadius: 6, padding: 8, fontFamily: 'monospace', opacity: newRule.type === 'allowlist' ? .55 : 1 }} />
          <input value={newRule.reason} onChange={event => setNewRule(current => ({ ...current, reason: event.target.value }))} maxLength={500} placeholder="Reason / ticket reference" aria-label="New DNS rule reason" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
          <button type="submit" disabled={Boolean(working) || !newRule.domain.trim() || !newRuleIpValid} style={{ ...button, background: newRule.type === 'blocklist' ? C.red : newRule.type === 'redirect' ? C.purple : C.green, color: newRule.type === 'blocklist' ? '#fff' : '#00150c' }}>{working === 'new-rule' ? 'Adding…' : 'Create Rule'}</button>
        </form>}
        {editingRule && <form onSubmit={saveEditedRule} style={{ display: 'grid', gridTemplateColumns: '130px repeat(3, minmax(150px, 1fr)) auto auto', gap: 8, padding: 12, marginBottom: 12, borderRadius: 8, background: C.card2, border: `1px solid ${C.purple}66` }}>
          <select value={editingRule.type} onChange={event => setEditingRule(current => ({ ...current, type: event.target.value }))} style={{ background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }}><option value="blocklist">Block</option><option value="redirect">Redirect to Safe Server</option><option value="allowlist">Allow</option></select>
          <input value={editingRule.domain} onChange={event => setEditingRule(current => ({ ...current, domain: event.target.value }))} required aria-label="Rule domain" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
          <input value={editingRule.sinkholeIp || ''} onChange={event => setEditingRule(current => ({ ...current, sinkholeIp: event.target.value }))} required={editingRule.type !== 'allowlist'} disabled={editingRule.type === 'allowlist'} placeholder={editingRule.type === 'redirect' ? 'Safe server IPv4' : (configDraft.sinkholeIp || '0.0.0.0')} aria-label="Rule sinkhole server IP" aria-invalid={!editingRuleIpValid} style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${editingRuleIpValid ? C.border : C.red}`, borderRadius: 6, padding: 8, fontFamily: 'monospace', opacity: editingRule.type === 'allowlist' ? .55 : 1 }} />
          <input value={editingRule.reason || ''} onChange={event => setEditingRule(current => ({ ...current, reason: event.target.value }))} maxLength={500} placeholder="Reason" aria-label="Rule reason" style={{ minWidth: 0, background: C.bg, color: C.text, border: `1px solid ${C.border}`, borderRadius: 6, padding: 8 }} />
          <button type="submit" disabled={Boolean(working) || !editingRuleIpValid} style={{ ...button, background: C.purple, color: '#0c0618' }}>{working === `edit-${editingRule._id}` ? 'Saving…' : 'Save'}</button>
          <button type="button" onClick={() => setEditingRule(null)} disabled={Boolean(working)} style={{ ...button, background: C.card, color: C.muted, border: `1px solid ${C.border}` }}>Cancel</button>
        </form>}
        <div style={{ overflowX: 'auto', border: `1px solid ${C.border}`, borderRadius: 8 }}>
          <div style={{ minWidth: 900 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '100px minmax(170px, 1.2fr) 145px minmax(170px, 1fr) 140px 160px', gap: 10, padding: '9px 12px', background: C.card2, color: C.muted, fontSize: 9, fontWeight: 900 }}><span>TYPE</span><span>DOMAIN</span><span>SERVER IP</span><span>REASON</span><span>UPDATED</span><span>ACTIONS</span></div>
            {data.rules.map(rule => <div key={rule._id} style={{ display: 'grid', gridTemplateColumns: '100px minmax(170px, 1.2fr) 145px minmax(170px, 1fr) 140px 160px', gap: 10, alignItems: 'center', padding: '10px 12px', borderTop: `1px solid ${C.border}`, fontSize: 10 }}>
              <span style={{ color: rule.type === 'blocklist' ? C.red : rule.type === 'redirect' ? C.purple : C.green, textTransform: 'uppercase', fontWeight: 900 }}>{rule.type}</span>
              <span style={{ color: C.text, fontFamily: 'monospace', fontWeight: 800 }}>{rule.domain}</span>
              <span style={{ color: rule.type !== 'allowlist' ? C.cyan : C.sub, fontFamily: 'monospace' }}>{rule.type !== 'allowlist' ? (rule.sinkholeIp || configDraft.sinkholeIp || '0.0.0.0') : 'Original DNS'}</span>
              <span style={{ color: C.muted }}>{rule.reason || 'No reason provided'}</span>
              <span style={{ color: C.sub }}>{rule.updatedAt ? new Date(rule.updatedAt).toLocaleString() : '—'}</span>
              <span style={{ display: 'flex', gap: 6 }}>
                <button type="button" onClick={() => setEditingRule({ ...rule, sinkholeIp: rule.sinkholeIp || configDraft.sinkholeIp || '0.0.0.0' })} disabled={Boolean(working)} style={{ ...button, padding: '6px 10px', background: C.card2, color: C.purple, border: `1px solid ${C.purple}66` }}>Edit</button>
                <button type="button" onClick={() => applyCompanyRule(rule)} disabled={Boolean(working)} style={{ ...button, padding: '6px 10px', background: rule.type === 'blocklist' ? C.red : rule.type === 'redirect' ? C.purple : C.green, color: rule.type === 'blocklist' ? '#fff' : '#00150c' }}>{working === String(rule._id) ? 'Applying…' : 'Apply'}</button>
              </span>
            </div>)}
            {!loading && !data.rules.length && <div style={{ padding: 26, color: C.muted, textAlign: 'center', fontSize: 11 }}>No company DNS rules yet. Select Add New Rule to create one.</div>}
          </div>
        </div>
      </section>

      <section style={card}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12, flexWrap: 'wrap', marginBottom: 12 }}>
          <div><h3 style={{ color: '#fff', fontSize: 14, margin: 0 }}>Agent Targets</h3><div style={{ color: C.muted, fontSize: 10, marginTop: 4 }}>Choose the endpoints that receive the selected built-in and company DNS rules.</div></div>
          <button type="button" onClick={saveConfiguration} disabled={Boolean(working) || (configDraft.targetMode === 'selected' && !selectedSystemIds.length)} style={{ ...button, background: C.cyan, color: '#001018', opacity: working ? .65 : 1 }}>{working === 'configuration' ? 'Saving & Applying…' : 'Save & Apply Targets'}</button>
        </div>
        <div style={{ display: 'flex', gap: 14, color: C.muted, fontSize: 10, marginBottom: 10 }}><label><input type="radio" name="setup-dns-target" checked={configDraft.targetMode === 'all'} onChange={() => updateConfig('targetMode', 'all')} style={{ accentColor: C.cyan }} /> All agents</label><label><input type="radio" name="setup-dns-target" checked={configDraft.targetMode === 'selected'} onChange={() => updateConfig('targetMode', 'selected')} style={{ accentColor: C.cyan }} /> Selected</label></div>
        <div style={{ maxHeight: 220, overflowY: 'auto', border: `1px solid ${C.border}`, borderRadius: 6 }}>
          {data.systems.map(system => <label key={system._id} style={{ display: 'grid', gridTemplateColumns: '20px minmax(0,1fr) auto', gap: 7, padding: 9, borderTop: `1px solid ${C.border}`, alignItems: 'center', fontSize: 9 }}><input type="checkbox" disabled={configDraft.targetMode === 'all'} checked={configDraft.targetMode === 'all' || selectedSystemIds.includes(String(system._id))} onChange={() => toggleTargetSystem(system._id)} style={{ accentColor: C.cyan }} /><span style={{ color: C.text }}>{system.name || system.hostname || 'Unnamed agent'}</span><span style={{ color: system.pending ? C.yellow : C.sub }}>{system.pending ? 'Queued' : system.status || 'unknown'}</span></label>)}
          {!data.systems.length && <div style={{ padding: 14, color: C.sub, fontSize: 9 }}>No agents found.</div>}
        </div>
      </section>

      <div style={{ color: C.yellow, fontSize: 10, lineHeight: 1.5, padding: '10px 12px', border: `1px solid ${C.yellow}44`, borderRadius: 8, background: `${C.yellow}0d` }}>
        Applying rules changes endpoint DNS policy files. Offline agents keep the command queued and apply it after their next heartbeat. An updated SOC agent build is required for this feature.
      </div>
    </div>
  );
}

export default function DnsSinkholeSetupPage() {
  return <DnsSinkholeSetupContent />;
}
