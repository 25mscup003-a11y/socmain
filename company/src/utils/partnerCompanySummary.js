// Use the same partner-scoped company records for both cards and summary totals.
// Missing numeric data stays unavailable instead of becoming a misleading zero.
export function summarizePartnerCompanies(companies, now = Date.now()) {
  const sum = field => companies.reduce((total, company) => {
    const value = company[field];
    if (total == null || value == null || value === '' || !Number.isFinite(Number(value))) return null;
    return total + Number(value);
  }, 0);
  const renewalCutoff = now + 15 * 24 * 60 * 60 * 1000;
  const activeCompanies = companies.filter(company => company.status === 'active').length;
  return {
    companies: companies.length,
    activeCompanies,
    inactiveCompanies: companies.length - activeCompanies,
    totalAgents: sum('totalAgents'),
    activeAgents: sum('activeAgents'),
    inactiveAgents: sum('inactiveAgents'),
    activePlans: companies.filter(company => company.plan?.isActive === true).length,
    expiringPlans: companies.filter(company => {
      const expiry = Date.parse(company.plan?.expiresAt);
      return company.plan?.isActive === true && expiry >= now && expiry <= renewalCutoff;
    }).length,
    totalCollection: sum('revenue'),
    pendingRevenue: sum('pendingRevenue'),
  };
}
