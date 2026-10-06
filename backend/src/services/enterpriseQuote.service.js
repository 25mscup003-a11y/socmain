const mongoose = require('mongoose');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const EnterpriseQuote = require('../models/EnterpriseQuote.model');
const notifications = require('./enterpriseNotification.service');

const failure = (message, status = 400) => Object.assign(new Error(message), { status });
const same = (a, b) => String(a?._id || a || '') === String(b?._id || b || '');

function requirements(body = {}) {
  const result = {};
  for (const key of ['systemCount', 'serverCount', 'phoneCount']) {
    const value = body[key];
    if (!['number', 'string'].includes(typeof value) || value === '') throw failure(`Enter a valid ${key}.`);
    result[key] = Number(value);
    if (!Number.isSafeInteger(result[key]) || result[key] < 0 || result[key] > 1000000) throw failure('License counts must be whole numbers from 0 to 1,000,000.');
  }
  if (!Object.values(result).some(value => value > 0)) throw failure('At least one license is required.');
  if (!['monthly', 'yearly'].includes(body.billingCycle)) throw failure('Choose monthly or yearly billing.');
  if (body.notes !== undefined && (typeof body.notes !== 'string' || body.notes.length > 2000)) throw failure('Notes must be at most 2,000 characters.');
  return { ...result, billingCycle: body.billingCycle, notes: body.notes?.trim() || '' };
}

function quoteAmount(value) {
  if (!['number', 'string'].includes(typeof value) || value === '') throw failure('Enter the Enterprise price.');
  const amount = Number(value);
  if (!Number.isFinite(amount) || amount < 1 || amount > 100000000 || Math.abs(amount * 100 - Math.round(amount * 100)) > 0.000001) {
    throw failure('Enterprise price must be ₹1–₹100,000,000 with at most two decimal places.');
  }
  return amount;
}

function enterpriseTotals(amountInr) {
  const base = Math.round(Number(amountInr) * 100);
  const gst = Math.round(base * 0.18), fee = Math.round(base * 0.02);
  return { baseInr: base / 100, gstInr: gst / 100, feeInr: fee / 100, totalInr: (base + gst + fee) / 100, totalPaise: base + gst + fee };
}

function quoteView(quote) {
  if (!quote) return null;
  return {
    _id: quote._id, revision: quote.revision, status: quote.status,
    systemCount: quote.systemCount, serverCount: quote.serverCount, phoneCount: quote.phoneCount,
    billingCycle: quote.billingCycle, amountInr: quote.amountInr, notes: quote.notes,
    updatedAt: quote.updatedAt, quotedAt: quote.quotedAt,
    totals: quote.amountInr == null ? null : enterpriseTotals(quote.amountInr),
  };
}

async function companyForEnterprise(claims) {
  if (claims?.role !== 'company_admin' || claims.impersonatedBy) throw failure('Use your Company Admin session to manage Enterprise plans.', 403);
  if (!mongoose.isObjectIdOrHexString(claims.id)) throw failure('Invalid company session.', 401);
  const actor = await User.findById(claims.id).select('role companyId isActive accountStatus passwordChangedAt').lean();
  if (!actor || actor.role !== 'company_admin' || actor.isActive !== true || (actor.accountStatus && actor.accountStatus !== 'active')
    || (actor.passwordChangedAt && new Date(actor.passwordChangedAt).getTime() > Number(claims.iat) * 1000)) throw failure('Company Admin session is no longer active.', 401);
  // Derive company from the live user; never trust request scope overrides.
  const company = await Company.findById(actor.companyId);
  if (!company) throw failure('Company not found.', 404);
  return company;
}

async function saveEnterpriseQuote(company, body, actorId, isManager) {
  const revision = Number(body.revision);
  if (!Number.isSafeInteger(revision) || revision < 0) throw failure('Refresh the Enterprise plan and try again.');
  const current = await EnterpriseQuote.findOne({ companyId: company._id });
  if ((current?.revision || 0) !== revision) throw failure('This Enterprise plan has changed. Refresh before saving.', 409);
  if (current?.status === 'checkout') throw failure('A checkout is pending. Its quoted terms are locked until payment is completed.', 409);
  const update = {
    ...requirements(body), partnerId: company.partnerId || null,
    status: isManager ? 'quoted' : 'requested', amountInr: isManager ? quoteAmount(body.amountInr) : null,
    notification: { kind: isManager ? 'ready' : 'request', status: 'pending', attempts: 0, sentTo: [], nextAttemptAt: new Date() },
    ...(isManager ? { quotedBy: actorId, quotedAt: new Date() } : { requestedBy: actorId, quotedBy: null, quotedAt: null }),
  };
  if (current) {
    const saved = await EnterpriseQuote.findOneAndUpdate({ _id: current._id, revision, status: { $ne: 'checkout' } },
      { $set: update, $inc: { revision: 1 } }, { new: true, runValidators: true });
    if (!saved) throw failure('This Enterprise plan has changed. Refresh before saving.', 409);
    void notifications.deliver(saved._id, saved.revision).catch(() => console.warn('[enterprise] Notification queued for retry'));
    return saved;
  }
  try {
    const saved = await EnterpriseQuote.create({ companyId: company._id, ...update, revision: 1 });
    void notifications.deliver(saved._id, saved.revision).catch(() => console.warn('[enterprise] Notification queued for retry'));
    return saved;
  }
  catch (error) { if (error.code === 11000) throw failure('This Enterprise plan has changed. Refresh before saving.', 409); throw error; }
}

module.exports = { failure, same, requirements, enterpriseTotals, quoteView, companyForEnterprise, saveEnterpriseQuote };
