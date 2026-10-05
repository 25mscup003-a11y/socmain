import { ArrowUpRight } from 'lucide-react';

const number = value => Number(value || 0).toLocaleString('en-IN');
const money = value => `₹${number(value)}`;
const label = value => value ? String(value).replaceAll('_', ' ').replace(/\b\w/g, char => char.toUpperCase()) : '—';
const date = value => {
  const parsed = value ? new Date(value) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleDateString('en-IN') : '—';
};
const enabled = value => value ? 'Enabled' : 'Disabled';

function Status({ value }) {
  const normalized = String(value || '').toLowerCase();
  const tone = ['active', 'paid', 'verified', 'uploaded', 'enabled', 'allowed'].includes(normalized) ? 'good'
    : ['rejected', 'suspended', 'failed', 'expired'].includes(normalized) ? 'danger' : 'neutral';
  return <span className={`partner-summary-status partner-summary-status--${tone}`}>{label(value)}</span>;
}

function Details({ rows }) {
  return <dl className="partner-summary-details">{rows.map(([name, value]) => (
    <div key={name}><dt>{name}</dt><dd>{value ?? '—'}</dd></div>
  ))}</dl>;
}

export default function PartnerOverviewSummaries({ detail, tabs, onOpenTab, displayFileName }) {
  const partner = detail.partner || {};
  const summary = detail.summary || {};
  const profile = partner.profile || {};
  const plan = partner.plan || {};
  const licenses = partner.agentLicenseSummary || {};
  const purchases = partner.agentLicensePurchases || [];
  const payments = detail.payments || [];
  const activity = detail.activity || [];
  const tickets = detail.supportTickets || [];
  const autoPay = partner.agentLicenseAutoPay || {};
  const agentAutoPayEnabled = Boolean(autoPay.enabled) || purchases.some(purchase => purchase.autoPay);
  const autoPayFee = autoPay.feeInr ?? purchases.find(purchase => purchase.autoPayFeeInr)?.autoPayFeeInr;
  const latestAutoPayPayment = payments.filter(payment => payment.autoPay || payment.notes?.autoPay || payment.source === 'agent_license_autopay')
    .sort((a, b) => new Date(b.paidAt || b.createdAt || 0) - new Date(a.paidAt || a.createdAt || 0))[0];
  const paidPlan = plan.paymentStatus === 'paid' && plan.isActive === true;
  const latestPartnerPayment = payments.filter(payment => payment.source === 'partner_checkout' || payment.planType === 'partner_enterprise')
    .sort((a, b) => new Date(b.paidAt || b.createdAt || 0) - new Date(a.paidAt || a.createdAt || 0))[0];
  const planAmount = paidPlan ? plan.amountPaid || latestPartnerPayment?.amountInr || 0 : plan.quote?.amountInr || 0;
  const lastSeen = (detail.agents || []).map(agent => agent.lastSeen).filter(value => value && !Number.isNaN(new Date(value).getTime()))
    .sort((a, b) => new Date(b) - new Date(a))[0];
  const kycFiles = ['gstCertificate', 'panCard', 'businessRegistration'].filter(type => (
    profile.kycDocuments?.[`${type}FilePath`] || profile.kycDocuments?.[`${type}DataUrl`]
  )).length;
  const agreementStatus = partner.agreementFilePath ? 'Uploaded' : partner.agreementFileName ? 'Re-upload required'
    : partner.agreementDetails ? 'Added' : 'Not uploaded';
  const recentActivity = [...activity].sort((a, b) => new Date(b.date || 0) - new Date(a.date || 0)).slice(0, 2);
  const countTickets = status => number(tickets.filter(ticket => ticket.status === status).length);

  const content = {
    edit: <Details rows={[
      ['Partner', partner.name],
      ['Admin', partner.ownerUserId?.name],
      ['Email', partner.ownerUserId?.email],
      ['Phone', partner.ownerUserId?.phone || partner.mobile || '—'],
      ['Status', <Status value={partner.status} />],
      ['Pricing plan', label(plan.type)],
      ['Razorpay account', profile.razorpayKeyId ? 'Connected' : 'Not connected'],
    ]} />,
    companies: <Details rows={[
      ['Total companies', number(summary.companyCount)],
      ['Active', number(summary.activeCompanies)],
      ['Inactive', number(summary.inactiveCompanies)],
      ['Active company plans', number(summary.activePlans)],
    ]} />,
    agents: <Details rows={[
      ['Total agents', number(summary.totalAgents)],
      ['Online', number(summary.activeAgents)],
      ['Offline', number(summary.offlineAgents)],
      ['Last seen', date(lastSeen)],
    ]} />,
    requests: <Details rows={[
      ['Purchased agents', number(licenses.totalPurchased)],
      ['Consumed licenses', number(licenses.consumedLicenses)],
      ['Available licenses', number(licenses.activeLicenses)],
      ['Remaining licenses', number(licenses.remainingLicenses)],
      ['Purchase records', number(purchases.length)],
      ['License expiry', date(licenses.lastExpiryAt)],
    ]} />,
    agentAutoPay: <>
      <Details rows={[
        ['Agent license Auto Pay', <Status value={enabled(agentAutoPayEnabled)} />],
        ['Subscription Auto Pay', <Status value={enabled(plan.autoPay)} />],
        ['Auto Pay fee', autoPayFee == null ? '—' : money(autoPayFee)],
        ['Last Auto Pay payment', date(latestAutoPayPayment?.paidAt || latestAutoPayPayment?.createdAt)],
      ]} />
      {!latestAutoPayPayment && <p className="partner-summary-note">No Auto Pay payments recorded.</p>}
    </>,
    approvedRequests: <>
      <table className="partner-summary-pricing">
        <caption>Price per agent</caption>
        <thead><tr><th>Agent</th><th>Monthly</th><th>Yearly</th></tr></thead>
        <tbody>{['system', 'server', 'android'].map(type => <tr key={type}>
          <th scope="row">{label(type)}</th>
          {['monthly', 'yearly'].map(period => <td key={period}>{money(partner.agentPricing?.[type]?.[period] ?? partner.agentPricing?.[period] ?? 0)}</td>)}
        </tr>)}</tbody>
      </table>
      <Details rows={[
        ['Payment control', <Status value={paidPlan || partner.capabilities?.subscriptionPurchase ? 'Allowed' : 'Pending'} />],
        ['System control', <Status value={partner.capabilities?.createCompany ? 'Allowed' : 'Pending'} />],
      ]} />
    </>,
    subscriptions: <Details rows={[
      ['Partner plan', label(plan.type)],
      ['Billing cycle', label(plan.billingCycle)],
      ['Subscription', <Status value={paidPlan ? 'Active' : planAmount ? 'Pending payment' : 'Pending amount'} />],
      ['Payment', <Status value={plan.paymentStatus || 'unpaid'} />],
      [paidPlan ? 'Amount paid' : 'Quoted amount', money(planAmount)],
      ['Expires', date(plan.expiresAt || latestPartnerPayment?.periodEnd)],
      ['Active company plans', number(summary.activePlans)],
      ['Expiring within 15 days', number(summary.expiringPlans)],
    ]} />,
    documents: <>
      <Details rows={[
        ['KYC status', <Status value={profile.kycStatus || 'not_submitted'} />],
        ['KYC files available', `${kycFiles} / 3`],
        ['Agreement PDF', <Status value={agreementStatus} />],
        ['Bank details', profile.accountNumber || profile.bankAccount ? 'Submitted' : 'Not submitted'],
      ]} />
      <p className="partner-summary-note">Reference</p>
      <p className="partner-summary-reference">{partner.agreementFileName ? displayFileName(partner.agreementFileName) : partner.agreementDetails || 'No agreement uploaded'}</p>
    </>,
    activity: recentActivity.length ? <ul className="partner-summary-activity">{recentActivity.map((event, index) => (
      <li key={`${event.type}-${index}`}>
        <div><strong>{label(event.type)}</strong><time>{date(event.date)}</time></div>
        <p>{event.detail || '—'}</p>
      </li>
    ))}</ul> : <p className="partner-summary-note">No recent activity.</p>,
    support: <Details rows={[
      ['Total tickets', number(tickets.length)],
      ['Open', countTickets('Open')],
      ['In progress', countTickets('In Progress')],
      ['Resolved', countTickets('Resolved')],
      ['Closed', countTickets('Closed')],
    ]} />,
  };

  return <div className="partner-summary-grid">
    {tabs.filter(([id]) => id !== 'overview').map(([id, title, Icon]) => (
      <section className="partner-summary-card" data-summary-tab={id} aria-labelledby={`partner-summary-${id}`} key={id}>
        <header>
          <h3 id={`partner-summary-${id}`}><Icon size={17} aria-hidden="true" />{title}</h3>
          <button type="button" onClick={() => onOpenTab(id)} aria-label={`Open ${title} tab`}>Open <ArrowUpRight size={14} aria-hidden="true" /></button>
        </header>
        {content[id]}
      </section>
    ))}
  </div>;
}
