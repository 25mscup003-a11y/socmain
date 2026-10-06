// Calendar periods start on the payment date. Clamp month-end purchases to
// the last day of the destination month (Jan 31 -> Feb 28/29).
function getPeriodEnd(billingCycle, from = new Date()) {
  const end = new Date(from);
  const day = end.getUTCDate();
  end.setUTCDate(1);
  end.setUTCMonth(end.getUTCMonth() + (billingCycle === 'yearly' ? 12 : 1));
  const lastDay = new Date(Date.UTC(end.getUTCFullYear(), end.getUTCMonth() + 1, 0)).getUTCDate();
  end.setUTCDate(Math.min(day, lastDay));
  return end;
}

module.exports = { getPeriodEnd };
