const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const System = require('../models/System.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const { ONLINE_THRESHOLD_MS } = require('../utils/systemPresence');

// Aggregate pipelines do not cast IDs the way Mongoose find queries do.
function partnerScope(partnerId) {
  if (!mongoose.isValidObjectId(partnerId)) throw new Error('Invalid partner scope');
  return { partnerId: new mongoose.Types.ObjectId(String(partnerId)) };
}

function companyPaymentScope(partnerId, companyIds) {
  return {
    ...partnerScope(partnerId), companyId: { $in: companyIds },
    source: { $nin: ['partner_checkout', 'partner_agent_license'] },
    planType: { $ne: 'partner_enterprise' },
  };
}

function onlineExpression(now) {
  return { $and: [
    { $ne: ['$isActive', false] },
    { $in: ['$status', ['active', 'online']] },
    { $ne: [{ $ifNull: ['$agentVersion', ''] }, ''] },
    { $gt: ['$lastSeen', new Date(now - ONLINE_THRESHOLD_MS)] },
    { $lte: ['$lastSeen', new Date(now)] },
  ] };
}

async function getPartnerCompanies(partnerId, now = Date.now()) {
  const companies = await Company.find(partnerScope(partnerId)).sort({ createdAt: -1 }).lean();
  const companyIds = companies.map(company => company._id);
  if (!companyIds.length) return [];
  const [systemStats, paymentStats] = await Promise.all([
    System.aggregate([
      { $match: { companyId: { $in: companyIds } } },
      { $group: {
        _id: '$companyId', totalAgents: { $sum: 1 },
        systems: { $sum: { $cond: [{ $eq: [{ $ifNull: ['$agentType', 'system'] }, 'system'] }, 1, 0] } },
        servers: { $sum: { $cond: [{ $eq: ['$agentType', 'server'] }, 1, 0] } },
        phones: { $sum: { $cond: [{ $eq: ['$agentType', 'phone'] }, 1, 0] } },
        active: { $sum: { $cond: [onlineExpression(now), 1, 0] } },
        osTypes: { $addToSet: { $ifNull: ['$osType', '$os'] } },
      } },
    ]),
    PaymentHistory.aggregate([
      { $match: companyPaymentScope(partnerId, companyIds) },
      { $sort: { createdAt: -1, _id: -1 } },
      { $group: {
        _id: '$companyId',
        ledgerCount: { $sum: 1 },
        totalCollection: { $sum: { $cond: [{ $eq: ['$status', 'captured'] }, '$amountInr', 0] } },
        pendingCollection: { $sum: { $cond: [{ $eq: ['$status', 'created'] }, '$amountInr', 0] } },
        paymentCount: { $sum: { $cond: [{ $eq: ['$status', 'captured'] }, 1, 0] } },
        platformCommission: { $sum: { $cond: [{ $eq: ['$status', 'captured'] }, '$platformCommissionInr', 0] } },
        partnerPayout: { $sum: { $cond: [{ $eq: ['$status', 'captured'] }, '$partnerPayoutInr', 0] } },
        lastPaidAt: { $max: { $cond: [{ $eq: ['$status', 'captured'] }, '$paidAt', null] } },
        latestPayment: { $first: {
          paymentId: '$paymentId', orderId: '$orderId', amountInr: '$amountInr', status: '$status',
          paidAt: '$paidAt', createdAt: '$createdAt', source: '$source', planType: '$planType',
          autoPay: '$autoPay', billingCycle: '$billingCycle', periodEnd: '$periodEnd',
        } },
      } },
    ]),
  ]);
  const systemsByCompany = new Map(systemStats.map(row => [String(row._id), row]));
  const paymentsByCompany = new Map(paymentStats.map(row => [String(row._id), row]));
  return companies.map(company => {
    const systems = systemsByCompany.get(String(company._id)) || {};
    const payments = paymentsByCompany.get(String(company._id)) || {};
    const totalAgents = Number(systems.totalAgents || 0);
    const activeAgents = Number(systems.active || 0);
    const planAmount = company.plan?.paymentStatus === 'paid' ? Number(company.plan?.amountPaid || 0) : 0;
    const revenue = payments.ledgerCount > 0 || payments.paymentCount > 0 ? Number(payments.totalCollection || 0) : planAmount;
    const planActive = company.plan?.isActive === true
      && (!company.plan?.expiresAt || new Date(company.plan.expiresAt).getTime() > now);
    return {
      ...company, totalAgents, activeAgents, inactiveAgents: Math.max(totalAgents - activeAgents, 0),
      allocatedLicenses: Number(company.agentLicenseAllocation || 0),
      systemCount: systems.systems || 0, serverCount: systems.servers || 0, phoneCount: systems.phones || 0,
      osTypes: (systems.osTypes || []).filter(Boolean), revenue,
      pendingRevenue: Number(payments.pendingCollection || 0),
      platformCommission: Number(payments.platformCommission || 0),
      partnerPayout: Number(payments.partnerPayout || 0),
      paymentCount: Number(payments.paymentCount || (planAmount > 0 ? 1 : 0)),
      lastPaidAt: payments.lastPaidAt || company.razorpay?.paidAt || null,
      latestPayment: payments.latestPayment || (planAmount > 0 ? {
        amountInr: planAmount, status: 'captured', paidAt: company.razorpay?.paidAt || company.plan?.startDate,
        paymentId: company.razorpay?.paymentId || '', orderId: company.razorpay?.orderId || '',
        billingCycle: company.plan?.billingCycle || 'monthly', periodEnd: company.plan?.expiresAt || null,
      } : null),
      userPaymentType: planAmount > 0 || payments.paymentCount > 0 ? 'existing' : 'new',
      paymentStatus: company.plan?.paymentStatus || payments.latestPayment?.status || 'unpaid',
      subscriptionStatus: planActive ? 'active' : company.plan?.paymentStatus === 'paid' ? 'expired' : 'pending',
      autoKeyEnabled: Boolean(company.plan?.autoPay),
      state: activeAgents > 0 ? 'Active' : 'Inactive',
    };
  });
}

function summarizePartnerCompanies(companies, now = Date.now()) {
  const sum = key => companies.reduce((total, company) => total + Number(company[key] || 0), 0);
  const activePlans = companies.filter(company => company.subscriptionStatus === 'active');
  const paidRevenue = sum('revenue');
  const pendingRevenue = sum('pendingRevenue');
  return {
    companyCount: companies.length,
    activeCompanies: companies.filter(company => company.status === 'active').length,
    inactiveCompanies: companies.filter(company => company.status !== 'active').length,
    totalAgents: sum('totalAgents'), activeAgents: sum('activeAgents'), offlineAgents: sum('inactiveAgents'),
    paidRevenue, pendingRevenue, totalRevenue: paidRevenue, totalCollected: paidRevenue, totalDue: pendingRevenue,
    platformCommission: sum('platformCommission'), partnerProfit: sum('partnerPayout'),
    activePlans: activePlans.length,
    expiringPlans: activePlans.filter(company => {
      const expiry = new Date(company.plan.expiresAt).getTime();
      return expiry >= now && expiry <= now + 15 * 24 * 60 * 60 * 1000;
    }).length,
  };
}

async function getPartnerDirectoryRevenue(partnerIds) {
  const companies = await Company.find({ partnerId: { $in: partnerIds } }).select('_id partnerId plan').lean();
  const payments = await PaymentHistory.aggregate([
    { $match: {
      partnerId: { $in: partnerIds }, companyId: { $in: companies.map(company => company._id) },
      source: { $nin: ['partner_checkout', 'partner_agent_license'] }, planType: { $ne: 'partner_enterprise' },
    } },
    { $group: { _id: { companyId: '$companyId', partnerId: '$partnerId' },
      total: { $sum: { $cond: [{ $eq: ['$status', 'captured'] }, '$amountInr', 0] } },
    } },
  ]);
  const byCompany = new Map(payments.map(row => [`${row._id.partnerId}:${row._id.companyId}`, row.total]));
  const totals = new Map();
  for (const company of companies) {
    const partnerId = String(company.partnerId);
    const revenue = byCompany.get(`${partnerId}:${company._id}`)
      ?? (company.plan?.paymentStatus === 'paid' ? Number(company.plan?.amountPaid || 0) : 0);
    totals.set(partnerId, (totals.get(partnerId) || 0) + revenue);
  }
  return totals;
}

module.exports = { getPartnerCompanies, summarizePartnerCompanies, partnerScope, companyPaymentScope, onlineExpression, getPartnerDirectoryRevenue };
