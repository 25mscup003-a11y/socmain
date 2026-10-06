import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/axios';
import './EnterpriseRenewal.css';

const money = value => `₹${Number(value || 0).toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
const date = value => value ? new Date(value).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' }) : '—';

function EnterprisePlan({ purchased }) {
  const navigate = useNavigate();
  const [calculation, setCalculation] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [reload, setReload] = useState(0);
  const [now, setNow] = useState(Date.now);
  const expiresAt = new Date(calculation?.renewFrom || purchased.endDate).getTime();
  const expired = Number.isFinite(expiresAt) && expiresAt <= now;
  const active = purchased.status === 'active' && !expired;
  const daysLeft = Math.max(0, Math.ceil((expiresAt - now) / 86400000));

  useEffect(() => {
    const refreshTime = () => setNow(Date.now());
    // Keep an open tab in sync, including the exact expiry boundary.
    const timer = Number.isFinite(expiresAt) && now < expiresAt
      ? window.setTimeout(refreshTime, Math.max(0, Math.min(expiresAt - Date.now(), 60000))) : null;
    window.addEventListener('focus', refreshTime);
    return () => { window.clearTimeout(timer); window.removeEventListener('focus', refreshTime); };
  }, [expiresAt, now]);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(''); setCalculation(null);
    api.post('/payment/enterprise/renewal/calculate', { batchId: purchased._id }, { signal: controller.signal })
      .then(({ data }) => { if (!controller.signal.aborted) setCalculation(data); })
      .catch(err => { if (!controller.signal.aborted) setError(err.response?.data?.message || 'Unable to load your Enterprise renewal price. Please retry.'); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [purchased._id, purchased.endDate, reload]);

  const renew = async () => {
    if (busy || !calculation || !expired) return;
    setBusy(true); setError('');
    try {
      const { data } = await api.post('/payment/enterprise/renewal/calculate', { batchId: purchased._id });
      setCalculation(data);
      if (data.renewalAvailable === false || new Date(data.renewFrom) > new Date()) {
        setError('Renewal will be available after your Enterprise plan expires.');
        return;
      }
      if (data.priceKey !== calculation.priceKey) {
        setError('Your renewal details changed. Review the updated amount and dates, then select Renew again.');
        return;
      }
      navigate('/checkout', { state: { checkout: {
        mode: 'enterprise-renewal', planName: 'Enterprise Renewal', description: 'Renew your Enterprise subscription',
        batchId: purchased._id, priceKey: data.priceKey,
        counts: { systemCount: data.systemCount, serverCount: data.serverCount, phoneCount: data.phoneCount },
        billingCycle: data.billingCycle, amountInr: data.totals.baseInr, totals: data.totals,
        periodStart: data.periodStart, periodEnd: data.periodEnd,
        returnTo: '/payments?tab=renewal&mode=enterprise', cancelTo: '/payments?tab=renewal&mode=enterprise',
      } } });
    } catch (err) { setError(err.response?.data?.message || 'Unable to prepare Enterprise renewal. Please retry.'); }
    finally { setBusy(false); }
  };

  return <article className="er-plan">
    <div className="er-details">
      <header className="er-plan-header">
        <span className="er-plan-icon" aria-hidden="true">🏢</span>
        <div className="er-plan-heading">
          <h4>{purchased.priceType === 'enterprise_addition' ? 'Enterprise Add Systems' : 'Enterprise'}</h4>
          <p>{purchased.billingCycle === 'yearly' ? 'Yearly' : 'Monthly'} subscription</p>
        </div>
        <span className={`er-badge ${active ? 'er-active' : 'er-expired'}`}><span aria-hidden="true">●</span> {active ? 'Active' : 'Expired'}</span>
      </header>
      <p className="er-counts">{purchased.addedSystemCount || 0} Systems · {purchased.addedServerCount || 0} Servers · {purchased.addedPhoneCount || 0} Phones</p>
      <dl className="er-plan-facts">
        <div><dt>Start date</dt><dd>{date(purchased.startDate)}</dd></div>
        <div><dt>Valid until</dt><dd>{date(purchased.endDate)}</dd></div>
        <div><dt>Last paid</dt><dd>{money(purchased.amountPaid)}</dd></div>
      </dl>
      <div className={`er-due ${active ? '' : 'er-due-overdue'}`}>
        <div><span className="er-label">{active ? 'Renew by' : 'Renewal overdue since'}</span><strong>{date(purchased.endDate)}</strong></div>
        <span className="er-remaining">{active ? `${daysLeft} days remaining` : 'Renew to restore access'}</span>
      </div>
      {active && <p className="er-note">Renewal will be available after your plan expires.</p>}
    </div>
    <div className="er-checkout">
      <span className="er-label">Renewal total</span>
      {loading && <p role="status" className="er-loading">Loading renewal amount…</p>}
      {calculation && <>
        <div className="er-total"><strong>{money(calculation.totals.totalInr)}</strong><span>/ {purchased.billingCycle === 'yearly' ? 'year' : 'month'}</span></div>
        <dl className="er-price-lines">
          <div><dt>{calculation.pricingSource === 'dynamic' ? 'Dynamic Pricing' : 'Admin-set plan price'}</dt><dd>{money(calculation.totals.baseInr)}</dd></div>
          <div><dt>GST (18%)</dt><dd>{money(calculation.totals.gstInr)}</dd></div>
          <div><dt>Payment fees (2%)</dt><dd>{money(calculation.totals.feeInr)}</dd></div>
        </dl>
        <div className="er-period"><span className="er-label">Renewal period</span><strong>{date(calculation.periodStart)} <span aria-hidden="true">→</span> {date(calculation.periodEnd)}</strong></div>
      </>}
      {error && <div role="alert" className="er-error"><p>{error}</p><button type="button" onClick={() => setReload(value => value + 1)} disabled={busy || loading}>Refresh details</button></div>}
      <button className="er-renew-button" type="button" onClick={renew} disabled={busy || loading || !calculation || !expired} title={!expired ? `Available after ${date(expiresAt)}` : undefined}>
        {busy ? 'Preparing renewal…' : `Renew Enterprise${calculation ? ` — ${money(calculation.totals.totalInr)}` : ''}`}
        {!busy && <span aria-hidden="true">→</span>}
      </button>
    </div>
  </article>;
}

export default function EnterpriseRenewal({ plans }) {
  return <section className="er-renewals" aria-label="Purchased Enterprise subscriptions">
    <h3>Your Enterprise subscriptions</h3>
    {plans.length ? plans.map(plan => <EnterprisePlan key={plan._id} purchased={plan} />) : <p className="er-empty">No purchased Enterprise subscriptions to renew.</p>}
  </section>;
}
