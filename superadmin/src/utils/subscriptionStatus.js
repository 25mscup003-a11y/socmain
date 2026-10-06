export function subscriptionStatus(company, now = Date.now()) {
  const plan = company.plan || {};
  const entitlement = company.entitlement;
  const baseActive = entitlement?.baseActive
    ?? (plan.isActive === true && (!plan.expiresAt || new Date(plan.expiresAt).getTime() > now));
  const batchActive = entitlement?.batchActive === true;
  const active = baseActive || batchActive;
  const pending = !active && company.status === 'pending_payment';
  const dates = [baseActive && plan.expiresAt, batchActive && entitlement.batchExpiresAt]
    .filter(Boolean).map(value => new Date(value).getTime()).filter(Number.isFinite);
  const expiresAt = baseActive && !plan.expiresAt ? null
    : dates.length ? new Date(Math.max(...dates)).toISOString() : plan.expiresAt || null;
  return { active, pending, expiresAt };
}
