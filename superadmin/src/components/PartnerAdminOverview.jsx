import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowUpRight, Building2, Handshake, Users } from 'lucide-react';
import api from '../api/axios';

const number = value => value == null ? '—' : Number(value).toLocaleString('en-IN');
const money = value => value == null ? '—' : new Intl.NumberFormat('en-IN', {
  style: 'currency', currency: 'INR', maximumFractionDigits: 0,
}).format(value);
const date = value => {
  const parsed = value ? new Date(value) : null;
  return parsed && !Number.isNaN(parsed.getTime()) ? parsed.toLocaleDateString('en-IN') : '—';
};
const label = value => String(value || 'Not available').replaceAll('_', ' ');

function Status({ value }) {
  const normalized = String(value || '').toLowerCase();
  const tone = ['active', 'approved', 'paid', 'captured', 'verified', 'resolved', 'closed'].includes(normalized)
    ? 'success' : ['suspended', 'rejected', 'failed', 'inactive', 'disconnected'].includes(normalized) ? 'danger' : 'pending';
  return <span className={`admin-dashboard__badge admin-dashboard__badge--${tone}`}>{label(value)}</span>;
}

function Panel({ title, children, action }) {
  return <div className="admin-dashboard__panel soc-glass-panel">
    <div className="admin-dashboard__panel-heading"><h3>{title}</h3>{action}</div>
    {children}
  </div>;
}

function Details({ rows }) {
  return <dl className="admin-dashboard__details">{rows.map(([name, value]) => (
    <div key={name}><dt>{name}</dt><dd>{value ?? '—'}</dd></div>
  ))}</dl>;
}

function Empty({ children }) {
  return <p className="admin-dashboard__empty">{children}</p>;
}

function Records({ columns, rows, empty }) {
  if (!rows.length) return <Empty>{empty}</Empty>;
  return <div className="admin-dashboard__table-scroll" tabIndex={0} role="region" aria-label="Partner records">
    <table className="admin-dashboard__table">
      <thead><tr>{columns.map(column => <th key={column}>{column}</th>)}</tr></thead>
      <tbody>{rows.map((cells, index) => <tr key={index}>{cells.map((cell, cellIndex) => <td key={cellIndex}>{cell ?? '—'}</td>)}</tr>)}</tbody>
    </table>
  </div>;
}

export default function PartnerAdminOverview({ stats, refreshVersion }) {
  const [partners, setPartners] = useState([]);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState(null);
  const [listLoading, setListLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listError, setListError] = useState('');
  const [detailError, setDetailError] = useState('');
  const [retryVersion, setRetryVersion] = useState(0);
  const [tab, setTab] = useState('companies');

  useEffect(() => {
    const controller = new AbortController();
    setListLoading(true);
    setListError('');
    api.get('/superadmin/partners', { signal: controller.signal, timeout: 20000 })
      .then(({ data }) => {
        if (controller.signal.aborted) return;
        const list = Array.isArray(data) ? data : [];
        setPartners(list);
        setSelectedId(current => list.some(partner => partner._id === current) ? current : list[0]?._id || '');
      })
      .catch(() => {
        if (!controller.signal.aborted) setListError('Could not refresh the partner list. Any previous list is still shown.');
      })
      .finally(() => { if (!controller.signal.aborted) setListLoading(false); });
    return () => controller.abort();
  }, [refreshVersion, retryVersion]);

  useEffect(() => {
    const controller = new AbortController();
    setDetail(null);
    setDetailError('');
    setDetailLoading(Boolean(selectedId));
    if (selectedId) {
      api.get(`/superadmin/partners/${selectedId}/overview`, { signal: controller.signal, timeout: 25000 })
        .then(({ data }) => { if (!controller.signal.aborted) setDetail(data); })
        .catch(() => {
          if (!controller.signal.aborted) setDetailError('Could not load this partner’s details. Please retry.');
        })
        .finally(() => { if (!controller.signal.aborted) setDetailLoading(false); });
    }
    return () => controller.abort();
  }, [selectedId, refreshVersion, retryVersion]);

  // Only display details that belong to the current selection, including during rapid switches.
  const currentDetail = detail?.partner?._id === selectedId ? detail : null;
  const partner = currentDetail?.partner;
  const summary = currentDetail?.summary || {};
  const plan = partner?.plan || {};
  const licenses = partner?.agentLicenseSummary || {};
  const tabs = [
    ['companies', 'Companies'], ['agents', 'Agents'], ['payments', 'Payments'],
    ['requests', 'Resource Requests'], ['support', 'Support'], ['activity', 'Activity'],
  ];
  const retry = <button className="admin-dashboard__button" onClick={() => setRetryVersion(value => value + 1)} disabled={listLoading || detailLoading}>Retry</button>;

  return <section className="admin-dashboard__column admin-dashboard__column--partner" aria-labelledby="partneradmin-section-title">
    <div className="admin-dashboard__section-heading">
      <div className="admin-dashboard__section-icon"><Handshake size={24} /></div>
      <div>
        <span className="admin-dashboard__eyebrow">PARTNER OPERATIONS</span>
        <h2 id="partneradmin-section-title">Partner Admin</h2>
        <p>Partner accounts, companies, agents & billing</p>
      </div>
    </div>

    <div className="admin-dashboard__metrics admin-dashboard__metrics--network">
      {[
        ['Partners', stats?.partners, Handshake],
        ['Partner Admins', stats?.partnerAdmins, Users],
        ['Partner Companies', stats?.partnerCompanies, Building2],
      ].map(([title, value, Icon]) => <div className="admin-dashboard__metric" key={title}>
        <span><Icon size={14} />{title}</span><strong>{number(value)}</strong>
      </div>)}
    </div>

    <Panel title="Choose Partner Admin" action={<Link className="admin-dashboard__link" to="/superadmin/partners">Manage Partners <ArrowUpRight size={13} /></Link>}>
      <label className="admin-dashboard__field">
        <span>Partner account</span>
        <select value={selectedId} disabled={listLoading || !partners.length} onChange={event => { setSelectedId(event.target.value); setTab('companies'); }}>
          {!partners.length && <option value="">{listLoading ? 'Loading partners…' : 'No partners available'}</option>}
          {partners.map(item => <option value={item._id} key={item._id}>{item.name} · {item.ownerUserId?.email || item.slug}</option>)}
        </select>
      </label>
      {listError && <div className="admin-dashboard__error" role="alert"><span>{listError}</span>{retry}</div>}
      {!listLoading && !listError && !partners.length && <Empty>No partner admins yet. Add a partner from Manage Partners to see their details here.</Empty>}
    </Panel>

    {detailLoading && <div className="admin-dashboard__panel" role="status">Loading selected partner details…</div>}
    {detailError && <div className="admin-dashboard__error" role="alert"><span>{detailError}</span>{retry}</div>}

    {partner && <>
      <Panel title="Partner Admin Profile" action={<Status value={partner.status} />}>
        <div className="admin-dashboard__account">
          <div><strong>{partner.name}</strong><p>{partner.ownerUserId?.name || 'Admin name unavailable'}</p></div>
          <Link className="admin-dashboard__link" to={`/superadmin/partner-dashboard?partnerId=${selectedId}`}>Full Dashboard <ArrowUpRight size={13} /></Link>
        </div>
        <Details rows={[
          ['Admin email', partner.ownerUserId?.email || '—'],
          ['Phone', partner.ownerUserId?.phone || partner.mobile || '—'],
          ['Tenant', partner.tenantId?.name || '—'],
          ['Workspace', partner.tenantId?.subdomain || partner.slug || '—'],
          ['Joined', date(partner.createdAt)], ['Approved', date(partner.approvedAt)],
          ['KYC status', <Status value={partner.profile?.kycStatus} />],
          ['Commission setting', partner.commissionPercent == null ? '—' : `${partner.commissionPercent}%`],
        ]} />
        {partner.notes && <p className="admin-dashboard__note">{partner.notes}</p>}
        {partner.rejectionReason && <p className="admin-dashboard__note">Rejection reason: {partner.rejectionReason}</p>}
      </Panel>

      <Panel title="Selected Partner Overview">
        <div className="admin-dashboard__metrics">
          {[
            ['Total Companies', summary.companyCount], ['Active Companies', summary.activeCompanies],
            ['Inactive Companies', summary.inactiveCompanies], ['Total Agents', summary.totalAgents],
            ['Active Agents', summary.activeAgents], ['Offline Agents', summary.offlineAgents],
            ['Active Company Plans', summary.activePlans], ['Plans Expiring ≤15 Days', summary.expiringPlans],
          ].map(([title, value]) => <div className="admin-dashboard__metric" key={title}><span>{title}</span><strong>{number(value)}</strong></div>)}
        </div>
      </Panel>

      <Panel title="Revenue & Settlement">
        <div className="admin-dashboard__metrics">
          {[
            ['Collected Revenue', summary.paidRevenue], ['Pending Revenue', summary.pendingRevenue],
            ['Platform Commission', summary.platformCommission], ['Partner Profit', summary.partnerProfit],
          ].map(([title, value]) => <div className="admin-dashboard__metric" key={title}><span>{title}</span><strong>{money(value)}</strong></div>)}
        </div>
        <p className="admin-dashboard__note">Company collections and settlement totals reported for this partner. Platform subscription purchases are excluded.</p>
      </Panel>

      <Panel title="Subscription, Licenses & Permissions">
        <Details rows={[
          ['Plan', label(plan.type)], ['Billing cycle', label(plan.billingCycle)],
          ['Subscription', <Status value={plan.isActive ? 'active' : 'inactive'} />],
          ['Payment status', <Status value={plan.paymentStatus} />],
          ['Amount paid', money(plan.amountPaid)], ['AutoPay', plan.autoPay ? 'Enabled' : 'Disabled'],
          ['Starts', date(plan.startDate)], ['Expires', date(plan.expiresAt)],
          ['Purchased licenses', number(licenses.totalPurchased)], ['Used licenses', number(licenses.consumedLicenses)],
          ['Remaining licenses', number(licenses.remainingLicenses)], ['Active licenses', number(licenses.activeLicenses)],
          ['License expiry', date(licenses.lastExpiryAt)], ['License AutoPay', partner.agentLicenseAutoPay?.enabled ? 'Enabled' : 'Disabled'],
          ['Create company', partner.capabilities?.createCompany ? 'Allowed' : 'Disabled'],
          ['Download agent', partner.capabilities?.downloadAgent ? 'Allowed' : 'Disabled'],
          ['Buy subscription', partner.capabilities?.subscriptionPurchase ? 'Allowed' : 'Disabled'],
          ['Agreement', partner.agreementFileName || 'Not uploaded'],
        ]} />
        {partner.agreementDetails && <p className="admin-dashboard__note">{partner.agreementDetails}</p>}
      </Panel>

      <Panel title="Partner Records">
        <div className="admin-dashboard__tabs" aria-label="Partner record categories">
          {tabs.map(([id, title]) => <button key={id} aria-pressed={tab === id} onClick={() => setTab(id)}>{title}</button>)}
        </div>

        {tab === 'companies' && <>
          <p className="admin-dashboard__note">Latest {currentDetail.companies?.length || 0} of {number(summary.companyCount)} companies</p>
          <Records columns={['Company', 'Status', 'Plan', 'Expires']} empty="No companies linked to this partner." rows={(currentDetail.companies || []).map(company => [
            <Link className="admin-dashboard__link" to={`/superadmin/companies/${company._id}/dashboard`}>{company.name}</Link>,
            <Status value={company.status} />, label(company.plan?.type), date(company.plan?.expiresAt),
          ])} />
        </>}
        {tab === 'agents' && <>
          <p className="admin-dashboard__note">Latest {currentDetail.agents?.length || 0} of {number(summary.totalAgents)} agents</p>
          <Records columns={['Agent', 'Company', 'Status', 'Last Seen']} empty="No agents linked to this partner." rows={(currentDetail.agents || []).map(agent => [
            <div>{agent.name || agent.hostname || 'Unnamed agent'}<small>{[agent.os, agent.ip].filter(Boolean).join(' · ')}</small></div>,
            agent.companyId?.name || '—', <Status value={agent.status} />, date(agent.lastSeen),
          ])} />
        </>}
        {tab === 'payments' && <>
          <p className="admin-dashboard__note">Latest payments, including platform subscription purchases</p>
          <Records columns={['Company / Plan', 'Amount', 'Status', 'Date']} empty="No payment records for this partner." rows={(currentDetail.payments || []).map(payment => [
            <div>{payment.companyId?.name || label(payment.planType)}<small>{payment.invoiceId || payment.razorpayPaymentId || ''}</small></div>,
            money(payment.amountInr), <Status value={payment.status} />, date(payment.paidAt || payment.createdAt),
          ])} />
        </>}
        {tab === 'requests' && <Records columns={['Request', 'Resources', 'Status', 'Date']} empty="No resource requests for this partner." rows={(currentDetail.resourceRequests || []).map(request => [
          <div>{request.requestId || 'Resource request'}<small>{request.adminNote || request.additionalNotes}</small></div>,
          <div>{number(request.numberOfCompanies)} companies<small>{number(request.numberOfAgents)} agents · {number(request.proposedCommission)}% commission</small></div>,
          <Status value={request.status} />, date(request.requestedAt),
        ])} />}
        {tab === 'support' && <Records columns={['Ticket', 'Subject', 'Status', 'Updated']} empty="No support tickets for this partner." rows={(currentDetail.supportTickets || []).map(ticket => [
          ticket.ticketId, ticket.subject || ticket.category, <Status value={ticket.status} />, date(ticket.updatedAt || ticket.createdAt),
        ])} />}
        {tab === 'activity' && <Records columns={['Activity', 'Details', 'Date']} empty="No recent activity for this partner." rows={(currentDetail.activity || []).map(event => [
          label(event.type), event.detail, date(event.date),
        ])} />}
      </Panel>
    </>}
  </section>;
}
