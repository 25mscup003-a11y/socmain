import { useState } from 'react';
import { Link } from 'react-router-dom';
import { summarizePartnerCompanies } from '../utils/partnerCompanySummary';
import './PartnerCompaniesSummary.css';

const number = value => value == null ? '—' : Number(value).toLocaleString('en-IN');
const money = value => value == null ? '—' : new Intl.NumberFormat('en-IN', {
  style: 'currency', currency: 'INR', maximumFractionDigits: 0,
}).format(value);
const date = value => {
  const parsed = value ? new Date(value) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleDateString('en-IN', {
    day: '2-digit', month: 'short', year: 'numeric',
  }) : '—';
};
const label = value => String(value || 'Not available').replaceAll('_', ' ');

const paths = {
  shield: 'M12 3l9 4v5c0 5-9 9-9 9s-9-4-9-9V7z M8 12l3 3 5-6',
  company: 'M4 21V3h12v18 M16 9h4v12 M2 21h20 M8 7h4 M8 11h4 M8 15h4 M9 21v-3h2v3',
  users: 'M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2 M16 3a4 4 0 0 1 0 8 M22 21v-2a4 4 0 0 0-3-3.87 M13 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0',
  agents: 'M3 3h18v14H3z M8 21h8 M12 17v4 M7 8h10 M7 12h5',
  plan: 'M3 4h18v16H3z M3 9h18 M7 15h4',
  revenue: 'M3 3v18h18 M7 16v-5 M12 16V7 M17 16V4',
  refresh: 'M20 7v5h-5 M4 17v-5h5 M6 6a8 8 0 0 1 14 6 M18 18a8 8 0 0 1-14-6',
  arrow: 'M7 17 17 7 M7 7h10v10',
};

function Icon({ name }) {
  return <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><path d={paths[name]} /></svg>;
}

function Status({ value }) {
  const state = String(value || '').toLowerCase();
  const tone = ['active', 'approved', 'paid', 'verified', 'completed', 'settled', 'processed'].includes(state)
    ? 'success' : ['inactive', 'suspended', 'rejected', 'failed', 'expired'].includes(state) ? 'danger' : 'pending';
  return <span className={`partner-summary__badge partner-summary__badge--${tone}`}>{label(value)}</span>;
}

function Details({ rows }) {
  return <dl className="partner-summary__details">{rows.map(([name, value]) => (
    <div key={name}><dt>{name}</dt><dd>{value ?? '—'}</dd></div>
  ))}</dl>;
}

function More({ to, children }) {
  return <Link className="partner-summary__link" to={to}>{children}<Icon name="arrow" /></Link>;
}

export default function PartnerCompaniesSummary({ partner, companies, companiesLoaded, loading, error, companiesError, onRefresh }) {
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const data = companiesLoaded ? summarizePartnerCompanies(companies) : {};
  const query = search.trim().toLowerCase();
  const filteredCompanies = companies.filter(company => (
    (!query || [company.name, company.email].some(value => String(value || '').toLowerCase().includes(query)))
    && (statusFilter === 'all' || company.status === statusFilter)
  ));
  const statuses = [...new Set(companies.map(company => company.status).filter(Boolean))].sort();
  const metrics = [
    ['Total Companies', number(data.companies), 'company', '#00f2fe', `${number(data.inactiveCompanies)} inactive companies`],
    ['Active Companies', number(data.activeCompanies), 'shield', '#34d399', 'Currently active companies'],
    ['Total Agents', number(data.totalAgents), 'agents', '#60a5fa', 'Across your companies'],
    ['Active Agents', number(data.activeAgents), 'agents', '#a78bfa', `${number(data.inactiveAgents)} inactive agents`],
    ['Active Company Plans', number(data.activePlans), 'plan', '#38bdf8', `${number(data.expiringPlans)} expiring within 15 days`],
    ['Total Collection', money(data.totalCollection), 'revenue', '#fbbf24', `${money(data.pendingRevenue)} pending revenue`],
  ];

  return <div className="partner-summary" aria-busy={loading}>
    <header className="partner-summary__header">
      <div className="partner-summary__heading">
        <span className="partner-summary__mark"><Icon name="company" /></span>
        <div><span className="partner-summary__eyebrow">PARTNER COMPANIES</span><h1>Partner Companies Summary</h1><p>{partner.name || 'Your partner account'} · Company status, agents, subscriptions &amp; revenue</p></div>
      </div>
      <div className="partner-summary__controls">
        <More to="/partner/companies">Manage companies</More>
        <button type="button" className="partner-summary__button" onClick={onRefresh} disabled={loading}><Icon name="refresh" />{loading ? 'Syncing…' : 'Sync'}</button>
      </div>
    </header>

    {error && <div className="partner-summary__error" role="alert">{error}</div>}

    <div className="partner-summary__metrics">
      {metrics.map(([title, value, icon, color, note]) => <div key={title} className="partner-summary__metric" style={{ '--metric-color': color }}>
        <div className="partner-summary__metric-label"><span>{title}</span><span className="partner-summary__metric-icon"><Icon name={icon} /></span></div>
        <strong>{value}</strong><small>{note}</small>
      </div>)}
    </div>

    <section className="partner-summary__companies" aria-labelledby="partner-company-overview">
      <div className="partner-summary__toolbar">
        <div><h2 id="partner-company-overview">Company Overview</h2><p>{companiesError ? 'Company list could not be refreshed' : `${filteredCompanies.length} of ${companies.length} companies`} · Open a company to view its full dashboard</p></div>
        <div className="partner-summary__filters">
          <label className="partner-summary__search"><span className="partner-summary__sr-only">Search companies</span><input type="search" placeholder="Search company name or email…" value={search} onChange={event => setSearch(event.target.value)} /></label>
          <label><span className="partner-summary__sr-only">Company status</span><select aria-label="Company status" value={statusFilter} onChange={event => setStatusFilter(event.target.value)}><option value="all">All statuses</option>{statuses.map(status => <option key={status} value={status}>{label(status)}</option>)}</select></label>
        </div>
      </div>

      {companiesError && <p className="partner-summary__error" role="alert">{companiesError}</p>}
      {filteredCompanies.length ? <div className="partner-summary__company-grid">
        {filteredCompanies.map(company => {
          const plan = company.plan || {};
          const companyPlan = plan.type || plan.planName;
          return <article className="partner-summary__company-card" key={company._id} aria-label={`${company.name || 'Unnamed company'} summary`}>
            <div className="partner-summary__company-heading">
              <span className="partner-summary__company-mark"><Icon name="company" /></span>
              <div><h3><Link to={`/partner/companies/${company._id}`}>{company.name || 'Unnamed company'}</Link></h3><p>{company.email || 'Email unavailable'}</p></div>
              <Status value={company.status} />
            </div>
            <div className="partner-summary__company-agents">{[
              ['Total agents', company.totalAgents, '#60a5fa'],
              ['Active agents', company.activeAgents, '#34d399'],
              ['Inactive agents', company.inactiveAgents, '#fbbf24'],
            ].map(([title, value, color]) => <div key={title}><strong style={{ color }}>{number(value)}</strong><span>{title}</span></div>)}</div>
            <Details rows={[
              ['Subscription', <span className="partner-summary__capitalize">{label(companyPlan)}</span>],
              ['Plan status', <Status value={plan.isActive == null ? null : plan.isActive ? 'active' : 'inactive'} />],
              ['Payment status', <Status value={plan.paymentStatus} />], ['Plan expiry', date(plan.expiresAt)],
            ]} />
            <div className="partner-summary__company-revenue"><div><span>Collected revenue</span><strong>{money(company.revenue)}</strong></div><div><span>Pending revenue</span><strong>{money(company.pendingRevenue)}</strong></div></div>
            <div className="partner-summary__company-footer"><span>Joined {date(company.createdAt)}</span><More to={`/partner/companies/${company._id}`}>View dashboard</More></div>
          </article>;
        })}
      </div> : !companiesError && <div className="partner-summary__empty">
        <Icon name="company" />
        <p>{loading ? 'Loading companies…' : companies.length ? 'No companies match your search or status filter.' : 'No companies linked to your partner account yet.'}</p>
        {!loading && (companies.length ? <button type="button" className="partner-summary__button" onClick={() => { setSearch(''); setStatusFilter('all'); }}>Clear filters</button> : <More to="/partner/companies?invite=company">Invite a company</More>)}
      </div>}
    </section>
  </div>;
}
