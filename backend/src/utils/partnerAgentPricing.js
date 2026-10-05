const AGENT_TYPES = ['system', 'server', 'android'];
const BILLING_PERIODS = ['monthly', 'yearly'];

function agentPriceForPlan(partner, planType, agentType = 'system') {
  if (!AGENT_TYPES.includes(agentType) || !BILLING_PERIODS.includes(planType)) return 0;
  const pricing = partner.agentPricing || {};
  const value = pricing[agentType]?.[planType] ?? pricing[planType] ?? 0;
  const price = Number(value);
  return Number.isFinite(price) && price >= 0 ? price : 0;
}

function normalizeAgentPricingUpdate(input) {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new Error('Invalid agent pricing');
  const result = {};
  const amount = (value, name) => {
    if (!['number', 'string'].includes(typeof value) || String(value).trim() === '') throw new Error(`${name} price is required`);
    const number = Number(value);
    if (!Number.isFinite(number) || number < 0 || !Number.isSafeInteger(Math.round(number * 100))) throw new Error(`${name} price must be a valid non-negative amount`);
    return Math.round(number * 100) / 100;
  };
  // Retain support for older clients without removing saved six-month history.
  for (const period of ['monthly', 'sixMonthly', 'yearly']) {
    if (input[period] !== undefined) result[period] = amount(input[period], period);
  }
  for (const type of AGENT_TYPES) {
    if (input[type] === undefined) continue;
    if (!input[type] || typeof input[type] !== 'object' || Array.isArray(input[type])) throw new Error(`Invalid ${type} pricing`);
    result[type] = {};
    for (const period of BILLING_PERIODS) {
      if (input[type][period] !== undefined) result[type][period] = amount(input[type][period], `${type} ${period}`);
    }
  }
  return result;
}

function licenseOrderDetails(order, partnerId) {
  const notes = order?.notes || {};
  const agentType = notes.agentType || 'system';
  const agentQuantity = Number(notes.agentQuantity);
  const pricePerAgent = Number(notes.pricePerAgent);
  if (String(notes.partnerId) !== String(partnerId) || !AGENT_TYPES.includes(agentType)
    || !['monthly', 'six_monthly', 'yearly'].includes(notes.planType)
    || !Number.isSafeInteger(agentQuantity) || agentQuantity < 1
    || !Number.isFinite(pricePerAgent) || pricePerAgent <= 0
    || order.currency !== 'INR' || !Number.isSafeInteger(order.amount) || order.amount < 1) {
    throw new Error('Invalid agent license order');
  }
  return { agentType, agentQuantity, pricePerAgent, planType: notes.planType,
    autoPay: notes.autoPay === 'true', autoPayFeeInr: Number(notes.autoPayFeeInr || 0),
    checkoutFees: notes.checkoutFees !== 'false', totalPaise: order.amount, totalInr: order.amount / 100 };
}

module.exports = { AGENT_TYPES, BILLING_PERIODS, agentPriceForPlan, normalizeAgentPricingUpdate, licenseOrderDetails };
