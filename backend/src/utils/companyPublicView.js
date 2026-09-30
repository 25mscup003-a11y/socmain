function dashboardCompanySummary(company) {
  const plan = company?.plan || {};
  return {
    _id: company?._id,
    name: company?.name || '',
    status: company?.status || '',
    riskScore: Number(company?.riskScore || 0),
    tenantId: company?.tenantId || null,
    partnerId: company?.partnerId || null,
    company_type: company?.company_type || '',
    plan: {
      type: plan.type || 'none',
      isActive: plan.isActive === true,
      billingCycle: plan.billingCycle || '',
      expiresAt: plan.expiresAt || null,
      systemCount: Number(plan.systemCount || 0),
      serverCount: Number(plan.serverCount || 0),
      phoneCount: Number(plan.phoneCount || 0),
      systemLimit: Number(plan.systemLimit || 0),
    },
  };
}

module.exports = { dashboardCompanySummary };
