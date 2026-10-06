import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import './EnterpriseManagement.css';

const initial = { systemCount: 10, serverCount: 0, phoneCount: 0, billingCycle: 'monthly', notes: '' };
const money = value => `₹${Number(value || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

export default function EnterprisePurchase() {
  const navigate = useNavigate();
  const [quote, setQuote] = useState(null);
  const [approver, setApprover] = useState('Admin');
  const [form, setForm] = useState(initial);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [reload, setReload] = useState(0);
  const [editing, setEditing] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setLoadError('');
    api.get('/payment/enterprise', { signal: controller.signal, skipCache: true }).then(({ data }) => {
      if (controller.signal.aborted) return;
      setQuote(data.quote); setApprover(data.approver);
      setEditing(false); setSuccess('');
      if (data.quote) setForm({ systemCount: data.quote.systemCount, serverCount: data.quote.serverCount, phoneCount: data.quote.phoneCount, billingCycle: data.quote.billingCycle, notes: data.quote.notes || '' });
    }).catch(err => { if (!controller.signal.aborted) setLoadError(err.response?.data?.message || 'Unable to load Enterprise plan.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [reload]);

  // Pick up admin setup while the company is waiting on this page.
  useEffect(() => {
    if (loading || saving || editing || quote?.status === 'paid') return;
    const controller = new AbortController();
    const refresh = async () => {
      if (document.visibilityState === 'hidden') return;
      try {
        const { data } = await api.get('/payment/enterprise', { signal: controller.signal, skipCache: true });
        if (controller.signal.aborted || !data.quote
          || data.quote.revision < (quote?.revision || 0)
          || (data.quote.revision === quote?.revision && data.quote.status === quote?.status)) return;
        setQuote(data.quote); setApprover(data.approver); setSuccess('');
        setForm({ systemCount: data.quote.systemCount, serverCount: data.quote.serverCount, phoneCount: data.quote.phoneCount,
          billingCycle: data.quote.billingCycle, notes: data.quote.notes || '' });
      } catch { /* Keep the current form usable; manual refresh reports errors. */ }
    };
    const timer = window.setInterval(refresh, 15000);
    window.addEventListener('focus', refresh);
    return () => { controller.abort(); window.clearInterval(timer); window.removeEventListener('focus', refresh); };
  }, [loading, saving, editing, quote?.revision, quote?.status]);

  const request = async event => {
    event.preventDefault(); if (saving) return;
    if (payable && !editing) { checkout(); return; }
    setSaving(true); setError(''); setSuccess('');
    try {
      const { data } = await api.post('/payment/enterprise/request', { ...form, revision: quote?.revision || 0 });
      setQuote(data.quote); setEditing(false); setSuccess(`Your requirements have been sent to ${approver}.`);
    } catch (err) { setError(err.response?.data?.message || 'Unable to send requirements.'); }
    finally { setSaving(false); }
  };
  const checkout = () => navigate('/checkout', { state: { checkout: {
    mode: 'enterprise', planName: 'Enterprise', description: 'Enterprise plan', quoteId: quote._id, revision: quote.revision,
    counts: { systemCount: quote.systemCount, serverCount: quote.serverCount, phoneCount: quote.phoneCount },
    billingCycle: quote.billingCycle, amountInr: quote.amountInr, totals: quote.totals, returnTo: '/payments?tab=enterprise',
  } } });
  const payable = ['quoted', 'checkout'].includes(quote?.status);
  const paymentReady = payable && !editing;
  const locked = saving || quote?.status === 'checkout' || paymentReady;
  const statusMessage = paymentReady ? 'Your Enterprise plan is ready. Complete your payment.'
    : quote?.status === 'requested' ? `Your requirements have been sent to ${approver}.` : success;

  return <section className="enterprise-manager enterprise-purchase">
    <header><div><h2>Enterprise Plan</h2><p>A custom license package and price for your company, set by your {approver}.</p></div>
      <button type="button" disabled={loading || saving} onClick={() => setReload(value => value + 1)}>Refresh quote</button></header>
    {loadError ? <p className="em-error" role="alert">{loadError}</p> : loading ? <p role="status">Loading Enterprise plan…</p> : <div className="em-layout">
      <div className="em-card">
        <h3>{payable ? 'Your Enterprise quote' : quote?.status === 'paid' ? 'Enterprise payment completed' : 'Request an Enterprise quote'}</h3>
        {payable ? <>
          <p>{quote.systemCount} Systems · {quote.serverCount} Servers · {quote.phoneCount} Phones</p>
          <h2>{money(quote.amountInr)} / {quote.billingCycle === 'yearly' ? 'year' : 'month'}</h2>
          {quote.notes && <p>{quote.notes}</p>}
          <p>GST: {money(quote.totals.gstInr)} · Payment fees: {money(quote.totals.feeInr)}</p>
          <h3>Total: {money(quote.totals.totalInr)}</h3>
          <p>These licenses are added to your existing plan. Your current licenses and expiry stay unchanged; this Enterprise purchase has its own validity period.</p>
        </> : <p>{quote?.status === 'requested' ? `Your requirements are awaiting a quote from ${approver}.` : quote?.status === 'paid' ? 'View your active licenses in Subscription. Send new requirements below when you need a new quote.' : 'Send your license requirements to receive your custom Enterprise price.'}</p>}
      </div>
      <form className="em-card" onSubmit={request}>
        <h3>License requirements</h3>
        <div className="em-fields">{[['systemCount', 'Systems'], ['serverCount', 'Servers'], ['phoneCount', 'Phones']].map(([key, label]) => <label key={key}>{label}
          <input type="number" min="0" max="1000000" step="1" required disabled={locked} value={form[key]} onChange={event => { setEditing(true); setForm(prev => ({ ...prev, [key]: event.target.value })); }} /></label>)}</div>
        <label>Billing period<select value={form.billingCycle} disabled={locked} onChange={event => { setEditing(true); setForm(prev => ({ ...prev, billingCycle: event.target.value })); }}><option value="monthly">Monthly</option><option value="yearly">Yearly</option></select></label>
        <label>Requirement notes<textarea maxLength={2000} disabled={locked} value={form.notes} onChange={event => { setEditing(true); setForm(prev => ({ ...prev, notes: event.target.value })); }} /></label>
        {payable && editing && <p>Changing requirements will request a new quote.</p>}
        {error && <p className="em-error" role="alert">{error}</p>}
        {statusMessage && <p className="em-success" role="status">{statusMessage}</p>}
        <button className={paymentReady ? 'em-primary' : undefined} type="submit" disabled={saving || (!paymentReady && locked)}>{saving ? 'Sending…' : paymentReady ? 'Complete your payment' : 'Request Enterprise quote'}</button>
        {paymentReady && quote.status !== 'checkout' && <button type="button" onClick={() => { setEditing(true); setSuccess(''); }} style={{ marginLeft: 8 }}>Change requirements</button>}
      </form>
    </div>}
  </section>;
}
