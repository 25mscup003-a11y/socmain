import { useEffect, useState } from 'react';
import api from '../api/axios';
import './EnterpriseManagement.css';

const blank = { systemCount: 10, serverCount: 0, phoneCount: 0, billingCycle: 'monthly', amountInr: '', notes: '' };
const money = value => `₹${Number(value || 0).toLocaleString('en-IN')}`;

export default function EnterpriseManagement({ baseUrl, initialCompanyId }) {
  const [companies, setCompanies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [reload, setReload] = useState(0);
  const [selected, setSelected] = useState(null);
  const [form, setForm] = useState(blank);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [search, setSearch] = useState('');
  const [page, setPage] = useState(1);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setLoadError('');
    api.get(baseUrl, { signal: controller.signal, skipCache: true }).then(({ data }) => {
      if (!controller.signal.aborted) {
        setCompanies(data);
        const linkedCompany = data.find(company => String(company._id) === initialCompanyId);
        if (linkedCompany) select(linkedCompany); else setSelected(null);
      }
    }).catch(err => { if (!controller.signal.aborted) setLoadError(err.response?.data?.message || 'Unable to load Enterprise plans.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [baseUrl, reload, initialCompanyId]);

  const select = company => {
    setSelected(company); setError(''); setSuccess('');
    setForm(company.quote ? {
      systemCount: company.quote.systemCount, serverCount: company.quote.serverCount, phoneCount: company.quote.phoneCount,
      billingCycle: company.quote.billingCycle, amountInr: company.quote.amountInr ?? '', notes: company.quote.notes || '',
    } : blank);
  };
  const save = async event => {
    event.preventDefault();
    if (!selected || saving) return;
    setSaving(true); setError(''); setSuccess('');
    try {
      const { data } = await api.put(`${baseUrl}/${selected._id}`, { ...form, revision: selected.quote?.revision || 0 });
      setCompanies(rows => rows.map(company => company._id === selected._id ? { ...company, quote: data } : company));
      setSelected(company => ({ ...company, quote: data }));
      setSuccess(`Enterprise quote saved for ${selected.name}.`);
    } catch (err) { setError(err.response?.data?.message || 'Unable to save Enterprise quote.'); }
    finally { setSaving(false); }
  };
  const filtered = companies.filter(company => `${company.name} ${company.email || ''}`.toLowerCase().includes(search.toLowerCase()));
  const currentPage = Math.min(page, Math.max(1, Math.ceil(filtered.length / 6)));
  const locked = saving || selected?.quote?.status === 'checkout';

  return <section className="enterprise-manager">
    <header><div><h2>Enterprise</h2><p>Set a custom license package and price for each company. Saved quotes apply to its next purchase.</p></div>
      <button type="button" disabled={loading || saving} onClick={() => setReload(value => value + 1)}>Refresh</button></header>
    {success && <p className="em-success" role="status">{success}</p>}
    {loadError ? <p className="em-error" role="alert">{loadError}</p> : loading ? <p role="status">Loading Enterprise plans…</p> : <div className="em-layout">
      <div className="em-card">
        <input aria-label="Search Enterprise companies" placeholder="Search company or email…" value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} />
        <div className="em-scroll"><table><thead><tr><th>Company / account</th><th>Enterprise price</th><th>Status</th><th>Action</th></tr></thead><tbody>
          {filtered.slice((currentPage - 1) * 6, currentPage * 6).map(company => <tr key={company._id}>
            <td><strong>{company.name}</strong><small>{company.email}</small></td>
            <td>{company.quote?.amountInr != null ? <>{money(company.quote.amountInr)}<small>{company.quote.billingCycle} · before taxes and fees</small></> : 'Not quoted'}</td>
            <td>{company.quote?.status || 'Not configured'}</td>
            <td><button type="button" disabled={saving} onClick={() => select(company)}>{company.quote ? 'Edit quote' : 'Set price'}</button></td>
          </tr>)}
        </tbody></table></div>
        {!filtered.length && <p>{companies.length ? 'No matching companies.' : 'No companies available.'}</p>}
        {filtered.length > 0 && <nav aria-label="Enterprise company pagination" className="em-pagination">
          <button type="button" disabled={currentPage === 1} onClick={() => setPage(currentPage - 1)}>Previous</button>
          <span>Page {currentPage} / {Math.max(1, Math.ceil(filtered.length / 6))} · 6 per page</span>
          <button type="button" disabled={currentPage * 6 >= filtered.length} onClick={() => setPage(currentPage + 1)}>Next</button>
        </nav>}
      </div>
      <div className="em-card">
        {selected ? <form onSubmit={save}>
          <h3>{selected.name}</h3><p>{selected.email}</p>
          <div className="em-fields">{[['systemCount', 'Systems'], ['serverCount', 'Servers'], ['phoneCount', 'Phones']].map(([key, label]) => <label key={key}>{label}
            <input type="number" min="0" max="1000000" step="1" required disabled={locked} value={form[key]} onChange={event => setForm(prev => ({ ...prev, [key]: event.target.value }))} /></label>)}</div>
          <label>Billing period<select value={form.billingCycle} disabled={locked} onChange={event => setForm(prev => ({ ...prev, billingCycle: event.target.value }))}><option value="monthly">Monthly</option><option value="yearly">Yearly</option></select></label>
          <label>Total Enterprise price (₹)<input type="number" min="1" max="100000000" step="0.01" required disabled={locked} value={form.amountInr} onChange={event => setForm(prev => ({ ...prev, amountInr: event.target.value }))} /></label>
          <p>Price covers all quoted licenses for the selected period. GST and payment fees are added at checkout.</p>
          <label>Notes for the company<textarea maxLength={2000} disabled={locked} value={form.notes} onChange={event => setForm(prev => ({ ...prev, notes: event.target.value }))} /></label>
          {selected.quote?.status === 'checkout' && <p>A checkout is pending. These terms remain locked until payment completes.</p>}
          {error && <p className="em-error" role="alert">{error}</p>}
          <button className="em-primary" disabled={locked}>{saving ? 'Saving…' : 'Save Enterprise quote'}</button>
        </form> : <p>Select a company to set its Enterprise price and license counts.</p>}
      </div>
    </div>}
  </section>;
}
