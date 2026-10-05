import React, { useCallback, useEffect, useState } from 'react';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import './CountryBlockTab.css';

const freshForm = () => ({ countryCode: '', direction: 'both', scope: 'department', departmentId: '', systemId: '', reason: '', enabled: true });
const directions = { both: 'Inbound & outbound', inbound: 'Inbound only', outbound: 'Outbound only' };
const states = { applied: 'Applied', pending: 'Pending sync', failed: 'Failed', offline: 'Offline', unsupported: 'Unsupported' };
const connections = { online: 'Online', offline: 'Offline', not_connected: 'Not connected yet' };
const countryBlockingUnsupported = system => system.agentType === 'phone' || /android|ios|solaris/i.test(system.osType || '');
const lastSeenLabel = value => value && Number.isFinite(new Date(value).getTime()) ? new Date(value).toLocaleString() : 'No heartbeat received';

function synchronizationDetail(system) {
  if (system.syncState === 'unsupported') return 'Requires a supported desktop or server agent';
  if (system.connectionState === 'not_connected') return 'Waiting for the first agent heartbeat';
  if (system.syncState === 'offline') return 'Waiting for the system to reconnect before confirming its country policy';
  if (system.syncState === 'failed') return system.countryBlockStatus?.error || 'Country policy could not be applied';
  if (system.connectionState !== 'online') return 'Waiting for a connection status refresh';
  if (!system.countryBlockStatus) return 'Online; waiting for an updated agent to report country blocking support';
  if (system.syncState === 'pending') return 'Online; waiting for confirmation of the current country policy';
  return 'Current country policy confirmed';
}

export default function CountryBlockTab({ onRulesChange, autoRefresh = true }) {
  const { user, company } = useAuth();
  const canManage = ['superadmin', 'partner_admin', 'company_admin', 'department_admin', 'soc_manager'].includes(user?.role);
  const [data, setData] = useState({ countries: [], departments: [], systems: [], rules: [] });
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [form, setForm] = useState(freshForm);
  const [editing, setEditing] = useState(null);
  const [countrySearch, setCountrySearch] = useState('');
  const [ruleSearch, setRuleSearch] = useState('');
  const [deleting, setDeleting] = useState(null);
  const [lookupTarget, setLookupTarget] = useState('');
  const [lookup, setLookup] = useState(null);
  const [lookupBusy, setLookupBusy] = useState(false);
  const [lookupError, setLookupError] = useState('');
  const canManageCompany = canManage && data.canManageCompany === true;

  const refresh = useCallback(async () => {
    try {
      const response = await api.get('/ips/country-blocks', { skipCache: true });
      setData(response.data);
      onRulesChange?.(response.data.rules.filter(rule => rule.enabled).length);
      setError('');
    } catch (err) {
      setError(err.response?.data?.message || 'Could not load country blocking rules. Please retry.');
    } finally { setLoading(false); }
  }, [onRulesChange]);

  useEffect(() => {
    refresh();
    if (!autoRefresh) return undefined;
    const timer = setInterval(refresh, 15000);
    window.addEventListener('focus', refresh);
    return () => { clearInterval(timer); window.removeEventListener('focus', refresh); };
  }, [refresh, autoRefresh]);

  const change = (key, value) => setForm(current => ({ ...current, [key]: value }));
  const reset = () => { setForm(freshForm()); setEditing(null); setCountrySearch(''); };
  const countryName = code => data.countries.find(country => country.code === code)?.name || code;
  const departmentName = id => data.departments.find(department => department._id === id)?.name || 'Unavailable department';
  const systemName = id => { const system = data.systems.find(item => item._id === id); return system?.name || system?.hostname || 'Unavailable system'; };
  const systems = data.systems.filter(system => !form.departmentId || system.departmentId === form.departmentId);
  const availableSystems = systems.filter(system => !countryBlockingUnsupported(system));
  const countries = data.countries.filter(country => `${country.name} ${country.code}`.toLowerCase().includes(countrySearch.toLowerCase()) || country.code === form.countryCode);
  const visibleRules = data.rules.filter(rule => `${countryName(rule.countryCode)} ${rule.countryCode} ${rule.scope === 'company' ? `Company ${company?.name || ''}` : departmentName(rule.departmentId)} ${rule.scope === 'system' ? systemName(rule.systemId) : ''}`.toLowerCase().includes(ruleSearch.toLowerCase()));

  const mutate = async (operation, onSuccess) => {
    setBusy(true); setError(''); setNotice('');
    try {
      const response = await operation();
      setNotice(response.data.message);
      onSuccess?.();
      await refresh();
    } catch (err) { setError(err.response?.data?.message || 'Could not update the rule. Please retry.'); }
    finally { setBusy(false); }
  };

  const save = event => {
    event.preventDefault();
    const payload = { ...form, departmentId: form.scope === 'company' ? null : form.departmentId, systemId: form.scope === 'system' ? form.systemId : null };
    mutate(() => editing ? api.patch(`/ips/country-blocks/${editing}`, payload) : api.post('/ips/country-blocks', payload), reset);
  };

  const edit = rule => {
    setEditing(rule._id);
    setForm({ countryCode: rule.countryCode, direction: rule.direction, scope: rule.scope, departmentId: rule.departmentId || '', systemId: rule.systemId || '', reason: rule.reason || '', enabled: rule.enabled });
    setCountrySearch(''); setNotice('');
    document.getElementById('country-block-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const checkCountry = async event => {
    event.preventDefault();
    setLookupBusy(true); setLookupError(''); setLookup(null);
    try {
      const response = await api.get('/ips/country-blocks/lookup', { params: { target: lookupTarget.trim() }, skipCache: true });
      setLookup(response.data);
    } catch (err) { setLookupError(err.response?.data?.message || 'Country lookup unavailable. Please retry.'); }
    finally { setLookupBusy(false); }
  };

  return <section className="country-block">
    <div className="country-block-heading">
      <div><h2>🌐 Block Country</h2><p>Block traffic from or to a country across your company, a department or a system.</p></div>
      <button type="button" onClick={refresh} disabled={busy || loading}>↻ Refresh</button>
    </div>
    {error && <div className="country-block-message error" role="alert">{error}</div>}
    {notice && <div className="country-block-message success" role="status">{notice}</div>}
    {canManage && <form className="country-block-panel" id="country-block-form" onSubmit={save}>
      <h3>{editing ? 'Edit country rule' : 'Create country rule'}</h3>
      <fieldset disabled={busy || loading}>
        <div className="country-block-grid">
          <div className="country-block-field"><label htmlFor="country-search">Country</label>
            <input id="country-search" type="search" value={countrySearch} onChange={event => setCountrySearch(event.target.value)} placeholder="Search country name or code…" />
            <select aria-label="Country to block" required value={form.countryCode} onChange={event => change('countryCode', event.target.value)}>
              <option value="">Select a country</option>
              {countries.map(country => <option key={country.code} value={country.code}>{country.name} ({country.code})</option>)}
            </select>
          </div>
          <div className="country-block-field"><span className="country-block-label" id="country-direction-label">Traffic direction</span>
            <div className="country-block-choices" role="radiogroup" aria-labelledby="country-direction-label">
              {Object.entries(directions).map(([value, label]) => <label key={value} className={form.direction === value ? 'selected' : ''}>
                <input type="radio" name="country-direction" value={value} checked={form.direction === value} onChange={() => change('direction', value)} />
                <span>{label}<small>{value === 'both' ? 'Block traffic in both directions' : value === 'inbound' ? 'Block incoming source IPs' : 'Block outgoing destination IPs'}</small></span>
              </label>)}
            </div>
          </div>
          <div className="country-block-field"><span className="country-block-label" id="country-scope-label">Rule level</span>
            <div className="country-block-choices scope" role="radiogroup" aria-labelledby="country-scope-label">
              {(canManageCompany ? ['company', 'department', 'system'] : ['department', 'system']).map(scope => <label key={scope} className={form.scope === scope ? 'selected' : ''}>
                <input type="radio" name="country-scope" value={scope} checked={form.scope === scope} onChange={() => setForm(current => ({ ...current, scope, departmentId: scope === 'company' ? '' : current.departmentId, systemId: '' }))} />
                <span>{scope === 'company' ? 'Company' : scope === 'department' ? 'Department' : 'System'}</span>
              </label>)}
            </div>
            {form.scope === 'company' ? <strong>{company?.name || 'Entire company'}</strong> : <><label htmlFor="country-department">Department</label>
            <select id="country-department" required value={form.departmentId} onChange={event => setForm(current => ({ ...current, departmentId: event.target.value, systemId: '' }))}>
              <option value="">Select a department</option>
              {data.departments.map(department => <option key={department._id} value={department._id}>{department.name}</option>)}
            </select></>}
            {form.scope === 'system' && <><label htmlFor="country-system">System</label><select id="country-system" required disabled={!form.departmentId} value={form.systemId} onChange={event => change('systemId', event.target.value)}>
              <option value="">Select a system</option>
              {systems.map(system => <option key={system._id} value={system._id} disabled={countryBlockingUnsupported(system)}>{system.name || system.hostname} · {system.osType || 'OS pending'}{countryBlockingUnsupported(system) ? ' · Country blocking unsupported' : ''}</option>)}
            </select>
            {form.departmentId && <small>{systems.length} {systems.length === 1 ? 'device' : 'devices'} in this department · {availableSystems.length} available for country blocking.</small>}
            {form.departmentId && availableSystems.length < systems.length && <small>Android, iOS and Solaris devices are listed, but country blocking is not available for them yet.</small>}
            </>}
            <small>{form.scope === 'company' ? 'Applies to all departments and all current and future supported systems in this company.' : form.scope === 'department' ? 'Applies to current and future supported systems in this department.' : 'Applies only to the selected system.'}</small>
          </div>
        </div>
        <div className="country-block-footer">
          <label className="country-block-reason" htmlFor="country-reason">Reason (optional)<input id="country-reason" maxLength={500} value={form.reason} onChange={event => change('reason', event.target.value)} placeholder="Why is this country being blocked?" /></label>
          <div className="country-block-buttons">{editing && <button type="button" onClick={reset}>Cancel edit</button>}<button className="primary" type="submit">{busy ? 'Saving…' : editing ? 'Save changes' : 'Block Country'}</button></div>
        </div>
      </fieldset>
      <p className="country-block-help">Uses IPdeny IPv4 and IPv6 country ranges, refreshed daily. Updated Linux, Windows or macOS agents apply changes on their next heartbeat. SOC server IPs remain reachable for management.</p>
    </form>}

    <div className="country-block-panel">
      <h3>Check IP / domain country</h3>
      <p>Check a public IP with IPinfo, or resolve a domain and check each IPv4 and IPv6 address.</p>
      <form onSubmit={checkCountry} className="country-lookup-form">
        <label htmlFor="country-lookup-target">IP address or domain
          <input id="country-lookup-target" required maxLength={253} value={lookupTarget} disabled={lookupBusy} onChange={event => { setLookupTarget(event.target.value); setLookup(null); setLookupError(''); }} placeholder="8.8.8.8 or example.com" autoCapitalize="none" spellCheck={false} />
        </label>
        <button type="submit" disabled={lookupBusy || !lookupTarget.trim()}>{lookupBusy ? 'Checking…' : 'Check country'}</button>
      </form>
      {lookupError && <div className="country-block-message error" role="alert">{lookupError}</div>}
      {lookup && <div aria-live="polite">
        <p className="country-block-help"><strong>{lookup.target}</strong> · {lookup.basis}{lookup.status === 'partial' ? ' · Partial result' : ''}</p>
        {lookup.message && <p role="status">{lookup.message}</p>}
        {lookup.addresses.length > 0 && <div className="country-block-table"><table><thead><tr><th>Resolved IP</th><th>Country</th><th>Source / status</th><th>Network</th></tr></thead><tbody>
          {lookup.addresses.map(address => <tr key={address.ip}>
            <td><strong>{address.ip}</strong><small>IPv{address.family}{address.ttl != null ? ` · DNS TTL ${address.ttl}s` : ''}</small></td>
            <td>{address.country ? `${address.country} (${address.countryCode})` : address.status === 'not_public' ? 'Non-public address' : 'Country unavailable'}</td>
            <td>{address.source || address.message}<small>{address.checkedAt ? `Checked ${lastSeenLabel(address.checkedAt)}` : ''}</small></td>
            <td>{address.asn || '—'}<small>{address.organization || ''}</small></td>
          </tr>)}
        </tbody></table></div>}
        {lookup.truncated && <p className="country-block-help">Showing the first {lookup.addresses.length} of {lookup.resolvedAddressCount} resolved addresses.</p>}
        {Object.entries(lookup.dnsStatus).filter(([, status]) => status === 'unavailable').map(([type]) => <p key={type} className="country-block-help">{type} DNS lookup unavailable; these results may be incomplete.</p>)}
      </div>}
      <p className="country-block-help">Domain country follows its resolved IPs, not its .com / .in suffix. CDN, VPN and DNS location can change the result. IPinfo results are cached for up to 30 minutes. Firewall blocking uses IPdeny country ranges, which can differ from IPinfo; this check does not confirm that traffic is blocked.</p>
    </div>

    <div className="country-block-panel">
      <div className="country-block-heading"><h3>Country rules <span className="country-block-count">{data.rules.length}</span></h3><input aria-label="Search country rules" type="search" value={ruleSearch} onChange={event => setRuleSearch(event.target.value)} placeholder="Search country or target…" /></div>
      <div className="country-block-table"><table><thead><tr><th>Country</th><th>Direction</th><th>Applies to</th><th>Enforcement</th>{canManage && <th>Actions</th>}</tr></thead><tbody>
        {visibleRules.map(rule => <tr key={rule._id}>
          <td><strong>{countryName(rule.countryCode)}</strong><small>{rule.countryCode}{rule.reason ? ` · ${rule.reason}` : ''}</small></td>
          <td>{directions[rule.direction]}</td>
          <td><strong>{rule.scope === 'company' ? company?.name || 'Entire company' : rule.scope === 'department' ? departmentName(rule.departmentId) : systemName(rule.systemId)}</strong><small>{rule.scope === 'company' ? 'Company · all departments and systems' : rule.scope === 'department' ? 'Department · all systems' : `System · ${departmentName(rule.departmentId)}`}</small></td>
          <td><span className={`country-block-badge ${!rule.enabled ? 'disabled' : rule.enforcement.failed ? 'failed' : rule.enforcement.total && rule.enforcement.applied === rule.enforcement.total ? 'applied' : 'pending'}`}>{!rule.enabled ? 'Disabled' : rule.enforcement.total && rule.enforcement.applied === rule.enforcement.total ? 'Applied' : 'Awaiting enforcement'}</span>
            <small>{rule.enforcement.total ? `${rule.enforcement.applied}/${rule.enforcement.total} systems ${rule.enabled ? 'applied' : 'synced'}` : 'No systems in this scope'}</small>
            {['pending', 'failed', 'offline', 'unsupported'].filter(state => rule.enforcement[state] > 0).map(state => <small key={state}>{rule.enforcement[state]} {state === 'pending' && !rule.enabled ? 'pending removal' : states[state].toLowerCase()}</small>)}
          </td>
          {canManage && <td>{rule.canEdit === false ? <small>Company rule · read only</small> : <div className="country-block-buttons"><button type="button" disabled={busy} onClick={() => edit(rule)}>Edit</button><button type="button" disabled={busy} onClick={() => mutate(() => api.patch(`/ips/country-blocks/${rule._id}`, { enabled: !rule.enabled }))}>{rule.enabled ? 'Disable' : 'Enable'}</button><button type="button" className="danger" disabled={busy} onClick={() => setDeleting(rule)}>Delete</button></div>}</td>}
        </tr>)}
        {!visibleRules.length && <tr><td colSpan={canManage ? 5 : 4} className="country-block-empty">{loading ? 'Loading country rules…' : ruleSearch ? 'No matching rules.' : 'No country rules yet. Choose a country, direction and target above.'}</td></tr>}
      </tbody></table></div>
    </div>

    <div className="country-block-panel"><h3>System synchronization</h3><p className="country-block-help">Connection shows whether the agent is online, using the same check as the Systems page. Policy sync shows whether the current country rules are confirmed; an online system can still be pending. Offline systems retain their last applied rules until they reconnect. Counts reflect systems you can access.</p>
      <div className="country-block-table"><table><thead><tr><th>System</th><th>Department</th><th>Connection</th><th>Last heartbeat</th><th>Policy sync</th><th>Details</th></tr></thead><tbody>
        {data.systems.map(system => <tr key={system._id}><td><strong>{system.name || system.hostname}</strong><small>{system.osType || 'OS not reported'}</small></td><td>{departmentName(system.departmentId)}</td><td><span className={`country-block-badge ${system.connectionState || 'unknown'}`}>{connections[system.connectionState] || 'Unknown'}</span></td><td>{lastSeenLabel(system.lastSeen)}</td><td><span className={`country-block-badge ${system.syncState}`}>{system.syncState === 'offline' ? 'Waiting for connection' : states[system.syncState]}</span></td><td>{synchronizationDetail(system)}</td></tr>)}
        {!data.systems.length && <tr><td colSpan={6} className="country-block-empty">{loading ? 'Loading systems…' : 'No systems available.'}</td></tr>}
      </tbody></table></div>
    </div>
    {deleting && <div className="country-block-dialog-backdrop"><div className="country-block-dialog" role="dialog" aria-modal="true" aria-labelledby="country-delete-title"><h3 id="country-delete-title">Delete {countryName(deleting.countryCode)} rule?</h3><p>The block from this rule will be removed when the target systems next synchronize. Other matching rules still apply.</p><div className="country-block-buttons"><button type="button" autoFocus disabled={busy} onClick={() => setDeleting(null)}>Cancel</button><button type="button" className="danger" disabled={busy} onClick={() => mutate(() => api.delete(`/ips/country-blocks/${deleting._id}`), () => { if (editing === deleting._id) reset(); setDeleting(null); })}>{busy ? 'Deleting…' : 'Delete rule'}</button></div></div></div>}
  </section>;
}
