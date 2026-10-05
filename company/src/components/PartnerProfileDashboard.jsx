import { API_BASE_URL } from '../api/config';

const number = value => Number(value || 0).toLocaleString('en-IN');
const money = value => `₹${number(value)}`;
const label = value => String(value || 'pending').replaceAll('_', ' ');
const date = value => value ? new Date(value).toLocaleDateString('en-IN') : 'No expiry set';
const displayFileName = value => {
  let name = String(value || '');
  if (/[ÃÂâðï]/.test(name)) {
    try {
      name = decodeURIComponent([...name].map(char => `%${char.charCodeAt(0).toString(16).padStart(2, '0')}`).join(''));
    } catch {}
  }
  return name
    .replace(/^(?:[\s"'`*_.,:;|/\\-]|[^\x20-\x7E]|[^\p{L}\p{N}._-])+/u, '')
    .replace(/^(?:ðŸ|ï¸|¿|¢|â|Ã|Â|[^\p{L}\p{N}._-])+/u, '')
    .trim() || 'Uploaded document';
};

export default function PartnerProfileDashboard({ stats, loading, available, onNavigate, onCompanies }) {
  const partner = stats?.partner || {};
  const licenses = stats?.agentLicenseSummary || partner.agentLicenseSummary || {};
  const plan = partner.plan || {};
  const planActive = plan.isActive === true && plan.paymentStatus === 'paid'
    && (!plan.expiresAt || new Date(plan.expiresAt).getTime() > Date.now());
  const agreementUrl = available && partner.agreementFilePath
    ? `${API_BASE_URL.replace(/\/api\/?$/, '')}/uploads/${partner.agreementFilePath}` : '';
  const agreementStatus = !available ? (loading ? 'Loading…' : 'Data unavailable')
    : partner.agreementFilePath ? 'Uploaded' : partner.agreementFileName ? 'Re-upload required'
      : partner.agreementDetails ? 'Added' : 'Not uploaded';
  const agreementReference = !available ? '—' : partner.agreementFileName
    ? displayFileName(partner.agreementFileName) : partner.agreementDetails || '-';
  const metrics = [
    ['Total Agents', stats?.totalAgents, `${number(stats?.activeAgents)} online · ${number(stats?.offlineAgents)} offline`, () => onNavigate('agents')],
    ['Available Licenses', licenses.remainingLicenses, `${number(licenses.totalPurchased)} purchased`, () => onNavigate('requests')],
    ['Total Collection', money(stats?.paidRevenue), 'Company payments received', () => onNavigate('subscription')],
    ['Total Due', money(stats?.pendingRevenue), 'Pending company payments', () => onNavigate('subscription')],
    ['Active Subscriptions', stats?.activePlans, `${number(stats?.expiringPlans)} expiring within 15 days`, onCompanies],
  ];
  const links = [
    ['subscription', 'Subscription & Payments', planActive ? 'Active' : label(plan.paymentStatus || 'unpaid'), planActive ? date(plan.expiresAt) : 'Review your partner plan'],
    ['requests', 'Buy Agent License', `${number(licenses.remainingLicenses)} available`, 'Purchase and review agent licenses'],
    ['kyc', 'KYC Documents', label(partner.profile?.kycStatus || 'not_submitted'), 'Manage verification documents'],
    ['bank', 'Bank & Payout Details', partner.partner_linked_account_id ? 'Payout account linked' : 'Payout account not linked', partner.profile?.bankName || 'Review bank details'],
    ['profile', 'My Profile', partner.ownerUserId?.name || 'Partner Admin', partner.ownerUserId?.email || 'Manage your contact details'],
    ['company', 'Company Information', partner.name || 'Partner company', 'Manage company information'],
    ['users', 'Users & Permissions', `${number(stats?.users)} users`, 'Review team access'],
    ['security', 'Security', 'Account security', 'Password and two-factor authentication'],
    ['notifications', 'Notifications', 'Updates and alerts', 'Review account notifications'],
    ['activity', 'Activity Log', 'Account history', 'Review recent changes'],
    ['support', 'Support', 'Support tickets', 'View conversations and request help'],
  ];
  return (
    <div className="partner-profile-dashboard" aria-busy={loading}>
      <header className="partner-profile-heading">
        <div><span>Partner Dashboard</span><h1>{partner.name || 'Your partner account'}</h1></div>
        <span className="partner-profile-status">{available ? label(partner.status) : 'Loading account'}</span>
      </header>
      <div className="partner-profile-metrics">
        <button
          type="button"
          className="partner-profile-metric partner-profile-agreement"
          disabled={!agreementUrl}
          onClick={() => window.open(agreementUrl, '_blank', 'noopener,noreferrer')}
          title={agreementUrl ? 'Open Agreement PDF' : agreementStatus}
        >
          <div className="partner-profile-agreement-heading">
            <span>Agreement PDF</span>
            <small data-available={available && Boolean(partner.agreementFilePath || partner.agreementDetails)}>{agreementStatus}</small>
          </div>
          <span>Reference</span>
          <strong>{agreementReference}</strong>
        </button>
        {metrics.map(([title, value, subtitle, onClick]) => (
          <button type="button" className="partner-profile-metric" key={title} onClick={onClick}>
            <span>{title}</span>
            <strong>{available ? (typeof value === 'string' ? value : number(value)) : '—'}</strong>
            <small>{available ? subtitle : loading ? 'Loading…' : 'Data unavailable'}</small>
          </button>
        ))}
      </div>
      <section className="partner-profile-overview">
        <div className="partner-profile-section-heading"><h2>Account & services</h2><span>Manage your partner account</span></div>
        <div className="partner-profile-services">
          {links.map(([id, title, value, subtitle]) => (
            <button type="button" className="partner-profile-service" key={id} onClick={() => onNavigate(id)}>
              <span className="partner-profile-service-title">{title}<span aria-hidden="true">↗</span></span>
              <strong>{available ? value : '—'}</strong><small>{subtitle}</small>
            </button>
          ))}
        </div>
      </section>
    </div>
  );
}
