const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const CompanySupportTicket = require('../models/CompanySupportTicket.model');

const SUPPORT_COMPANY_FIELDS = '_id name email partnerId tenantId source company_type';

function isDirectSupportCompany(company) {
  return Boolean(company)
    && !company.partnerId
    && company.source !== 'partner_referral'
    && company.company_type !== 'PARTNER_MANAGED'
    && company.tenantId?.type !== 'partner';
}

function validSupportId(value) {
  return typeof value === 'string' && /^[a-f\d]{24}$/i.test(value);
}

async function loadSupportCompany(id) {
  if (!id || !mongoose.isValidObjectId(id)) return null;
  return Company.findById(id).select(SUPPORT_COMPANY_FIELDS).populate('tenantId', 'type').lean();
}

async function directSupportCompanies() {
  const companies = await Company.find({
    partnerId: null,
    source: { $ne: 'partner_referral' },
    company_type: { $ne: 'PARTNER_MANAGED' },
  }).select(SUPPORT_COMPANY_FIELDS).populate('tenantId', 'type').sort({ name: 1 }).lean();
  return companies.filter(isDirectSupportCompany);
}

async function requireDirectSupportCompany(req, res, next) {
  try {
    if (!validSupportId(req.params.id)) return res.status(400).json({ message: 'Invalid company ID' });
    const company = await loadSupportCompany(req.params.id);
    if (!company) return res.status(404).json({ message: 'Company not found' });
    if (!isDirectSupportCompany(company)) return res.status(403).json({ message: 'Super Admin support is available only for direct companies.' });
    req.supportCompany = company;
    next();
  } catch (error) { next(error); }
}

async function requireCompanySupportAccess(req, res, next) {
  try {
    const company = await loadSupportCompany(req.user.companyId);
    if (!company) return res.status(403).json({ message: 'A registered company is required for support.' });
    // Elevated roles can override companyId through request headers. Check the
    // actual owner before allowing these alternate company-side endpoints.
    if (req.user.role === 'superadmin' && !isDirectSupportCompany(company)) {
      return res.status(403).json({ message: 'Super Admin support is available only for direct companies.' });
    }
    if (req.user.role === 'partner_admin' && (!req.user.partnerId || String(company.partnerId) !== String(req.user.partnerId))) {
      return res.status(403).json({ message: 'Company is outside your partner account.' });
    }
    req.supportCompany = company;
    next();
  } catch (error) { next(error); }
}

function emitCompanySupport(req, company, event, ticket) {
  const io = req.app.get('io');
  if (!io) return;
  const companyId = String(company._id);
  const payload = { companyId, ticketId: ticket.ticketId, ticket };
  io.to(`company:${companyId}`).emit(event, payload);
  if (isDirectSupportCompany(company)) io.to('superadmin').emit(event, payload);
  else if (company.partnerId) io.to(`partner:${company.partnerId}`).emit(event, payload);
}

function supportText(value, maxLength) {
  return typeof value === 'string' && value.trim().length > 0 && value.trim().length <= maxLength
    ? value.trim() : null;
}

async function markCompanySupportRead(req, res, ticketId, company) {
  if (!validSupportId(ticketId)) return res.status(400).json({ message: 'Invalid ticket ID' });
  const messageIds = req.body.messageIds;
  if (!Array.isArray(messageIds) || !messageIds.length || messageIds.length > 200 || !messageIds.every(validSupportId)) {
    return res.status(400).json({ message: 'Provide between 1 and 200 valid message IDs.' });
  }
  const ticket = await CompanySupportTicket.findOne({ _id: ticketId, companyId: company._id });
  if (!ticket) return res.status(404).json({ message: 'Ticket not found' });
  const staffRoles = ['superadmin', 'partner_admin'];
  const readerIsStaff = staffRoles.includes(req.user.role);
  const requested = new Set(messageIds);
  // A viewer can acknowledge only messages from the other side, and only
  // those in the conversation snapshot actually displayed by their client.
  const unreadIds = ticket.messages.filter(message =>
    requested.has(String(message._id)) && !message.readAt
    && staffRoles.includes(message.senderRole) !== readerIsStaff
  ).map(message => message._id);
  if (!unreadIds.length) return res.json(ticket);
  const updated = await CompanySupportTicket.findOneAndUpdate(
    { _id: ticketId, companyId: company._id },
    { $set: { 'messages.$[message].readAt': new Date() } },
    {
      new: true, runValidators: true, timestamps: false,
      arrayFilters: [{ 'message._id': { $in: unreadIds }, 'message.readAt': null }],
    },
  );
  if (!updated) return res.status(404).json({ message: 'Ticket not found' });
  emitCompanySupport(req, company, 'support:messages_read', updated);
  return res.json(updated);
}

module.exports = {
  isDirectSupportCompany, validSupportId, loadSupportCompany, directSupportCompanies,
  requireDirectSupportCompany, requireCompanySupportAccess, emitCompanySupport, supportText,
  markCompanySupportRead,
};
