const crypto = require('crypto');
const Company = require('../models/Company.model');
const User = require('../models/User.model');
const Tenant = require('../models/Tenant.model');
const Quote = require('../models/EnterpriseQuote.model');
const email = require('../utils/email');
const { buildDashboardUrl } = require('../utils/tenant');

const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char]));
const same = (a, b) => String(a || '') === String(b || '');
const active = { isActive: true, $or: [{ accountStatus: 'active' }, { accountStatus: { $exists: false } }] };

async function recipientsFor(company, kind) {
  const scope = kind === 'ready' ? { role: 'company_admin', companyId: company._id }
    : company.partnerId ? { role: 'partner_admin', partnerId: company.partnerId } : { role: 'superadmin' };
  const users = await User.find({ ...scope, ...active }).select('_id name email role tenantId').lean();
  return [...new Map(users.filter(user => user.email).map(user => [user.email.toLowerCase(), user])).values()];
}

async function notificationMessage(company, quote, recipient) {
  const ready = quote.notification.kind === 'ready';
  const tenant = recipient.tenantId ? await Tenant.findById(recipient.tenantId).select('subdomain').lean() : null;
  const base = buildDashboardUrl(recipient, tenant);
  const path = ready ? '/company-admin/payments' : company.partnerId ? '/partner/payment-control' : '/superadmin/payment-management';
  const url = new URL(path, base);
  url.searchParams.set('tab', 'enterprise');
  if (!ready) url.searchParams.set('companyId', String(company._id));
  const title = ready ? 'Your Enterprise plan is ready' : 'Set up Enterprise for this company';
  const action = ready ? 'Complete your payment' : 'Set up Enterprise';
  const summary = ready ? `Enterprise setup is complete for ${company.name}. Log in to review your quote and complete your payment.`
    : `${company.name} has requested an Enterprise plan. Please set up its license package and price.`;
  const licenses = `${quote.systemCount} Systems · ${quote.serverCount} Servers · ${quote.phoneCount} Phones · ${quote.billingCycle}`;
  const price = ready ? `Quoted price: ₹${Number(quote.amountInr).toLocaleString('en-IN')} before taxes and payment fees.` : '';
  const text = [title, summary, `Company: ${company.name}`, `Company email: ${company.email || ''}`, licenses, price,
    quote.notes ? `Notes: ${quote.notes}` : '', `${action}: ${url.href}`].filter(Boolean).join('\n\n');
  return {
    to: recipient.email,
    subject: `Enterprise ${ready ? 'ready' : 'setup requested'} — ${String(company.name).replace(/[\r\n]/g, ' ')}`,
    text,
    html: `<div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:28px;color:#172033"><h2>🏢 ${escapeHtml(title)}</h2><p>${escapeHtml(summary)}</p><p><strong>${escapeHtml(company.name)}</strong><br>${escapeHtml(company.email)}<br>${escapeHtml(licenses)}</p>${price ? `<p>${escapeHtml(price)}</p>` : ''}${quote.notes ? `<p style="white-space:pre-wrap">${escapeHtml(quote.notes)}</p>` : ''}<a href="${escapeHtml(url.href)}" style="display:inline-block;background:#2563eb;color:white;padding:12px 20px;border-radius:8px;text-decoration:none">${action}</a></div>`,
  };
}

function createEnterpriseNotifications({ sendMail = message => email.sendMail(message) } = {}) {
  async function deliver(quoteId, revision) {
    const now = new Date(), leaseId = crypto.randomUUID();
    const quote = await Quote.findOneAndUpdate({ _id: quoteId, revision, $or: [
      { 'notification.status': 'pending', 'notification.nextAttemptAt': { $lte: now } },
      { 'notification.status': 'sending', 'notification.leaseUntil': { $lte: now } },
    ] }, { $set: { 'notification.status': 'sending', 'notification.leaseId': leaseId,
      'notification.leaseUntil': new Date(Date.now() + 5 * 60000) }, $inc: { 'notification.attempts': 1 } }, { new: true });
    if (!quote) return;
    const claim = { _id: quote._id, revision, 'notification.leaseId': leaseId };
    try {
      const company = await Company.findById(quote.companyId).select('_id name email partnerId').lean();
      if (!company || !same(company.partnerId, quote.partnerId)) throw new Error('Company ownership changed');
      const recipients = await recipientsFor(company, quote.notification.kind);
      if (!recipients.length) throw new Error('No active notification recipient');
      for (const recipient of recipients) {
        if (quote.notification.sentTo.includes(recipient.email.toLowerCase())) continue;
        if (!await Quote.exists(claim)) return; // A newer quote replaces stale mail.
        const result = await sendMail(await notificationMessage(company, quote, recipient));
        if (result?.rejected?.length) throw new Error('Recipient rejected by email service');
        await Quote.updateOne(claim, { $addToSet: { 'notification.sentTo': recipient.email.toLowerCase() } });
      }
      await Quote.updateOne(claim, { $set: { 'notification.status': 'sent', 'notification.sentAt': new Date(), 'notification.leaseUntil': null } });
    } catch {
      const delay = Math.min(3600000, 30000 * 2 ** Math.min(quote.notification.attempts || 1, 7));
      await Quote.updateOne(claim, { $set: { 'notification.status': 'pending',
        'notification.nextAttemptAt': new Date(Date.now() + delay), 'notification.leaseUntil': null } });
      console.warn('[enterprise] Notification queued for retry');
    }
  }

  async function runPending() {
    const now = new Date();
    const quotes = await Quote.find({ $or: [
      { 'notification.status': 'pending', 'notification.nextAttemptAt': { $lte: now } },
      { 'notification.status': 'sending', 'notification.leaseUntil': { $lte: now } },
    ] }).select('_id revision').sort({ 'notification.nextAttemptAt': 1 }).limit(20).lean();
    for (const quote of quotes) await deliver(quote._id, quote.revision);
  }
  return { deliver, runPending };
}

const notifications = createEnterpriseNotifications();
let timer, running = false;
function startScheduler() {
  if (timer) return;
  const tick = async () => {
    if (running) return;
    running = true;
    try { await notifications.runPending(); }
    catch { console.warn('[enterprise] Notification worker will retry'); }
    finally { running = false; }
  };
  timer = setInterval(tick, 30000); timer.unref();
  void tick();
}

module.exports = { ...notifications, startScheduler, createEnterpriseNotifications, recipientsFor, notificationMessage };
