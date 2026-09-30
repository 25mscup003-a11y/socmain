const router = require('express').Router();
const mongoose = require('mongoose');
const { authenticate } = require('../middleware/auth.middleware');
const User = require('../models/User.model');
const Company = require('../models/Company.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocDepartmentAssignment = require('../models/SocDepartmentAssignment.model');
const SocChatThread = require('../models/SocChatThread.model');
const SocChatMessage = require('../models/SocChatMessage.model');
const { notifyChatMessage, markChatThreadRead } = require('../services/socNotification.service');

const ANALYST_ROLES = ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const CHAT_ROLES = ['superadmin', 'company_admin', 'department_admin', 'soc_manager', ...ANALYST_ROLES];
const activeAccount = { isActive: true, accountStatus: { $nin: ['disabled', 'suspended', 'expired'] } };

router.use(authenticate);
router.use(async (req, res, next) => {
  if (!CHAT_ROLES.includes(req.user?.role)) return res.status(403).json({ message: 'SOC chat access required' });
  const account = await User.findById(req.user.id).select('_id role name email tenantId companyId departmentId socManagerId isActive accountStatus').lean();
  if (!account || !account.isActive || ['disabled', 'suspended', 'expired'].includes(account.accountStatus)) {
    return res.status(403).json({ message: 'Active chat account required' });
  }
  req.chatAccount = account;
  next();
});

const participantKey = (a, b) => [String(a), String(b)].sort().join(':');

async function assignedCompanyIds(userId) {
  return SocCompanyAssignment.find({ userId, active: true }).distinct('companyId');
}

async function allowedContacts(account, req) {
  const role = account.role;
  const targetCompanyId = req?.headers?.['x-company-id'] || req?.query?.companyId;
  let query;
  if (role === 'superadmin') {
    if (targetCompanyId) {
      const managerIds = await SocCompanyAssignment.find({ companyId: targetCompanyId, active: true }).distinct('userId');
      query = {
        role: 'soc_manager',
        $or: [
          { companyId: targetCompanyId },
          { _id: { $in: managerIds } },
        ],
      };
    } else {
      query = { role: 'soc_manager' };
    }
  } else if (role === 'company_admin') {
    const legacyCompanies = await Company.find({ email: String(account.email || '').trim().toLowerCase() }).distinct('_id');
    const companyIds = [...new Set([account.companyId, ...legacyCompanies].filter(Boolean).map(String))];
    if (!companyIds.length) return [];
    const managerIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true }).distinct('userId');
    query = { _id: { $in: managerIds }, role: 'soc_manager' };
  } else if (role === 'department_admin') {
    if (!account.companyId || !account.departmentId) return [];
    const [departmentManagerIds, companyManagerIds] = await Promise.all([
      SocDepartmentAssignment.find({
        companyId: account.companyId,
        departmentId: account.departmentId,
        active: true,
      }).distinct('userId'),
      SocCompanyAssignment.find({
        companyId: account.companyId,
        active: true,
      }).distinct('userId'),
    ]);
    const departmentScopedManagerIds = await SocDepartmentAssignment.find({
      companyId: account.companyId,
      userId: { $in: companyManagerIds },
      active: true,
    }).distinct('userId');
    const scopedManagerSet = new Set(departmentScopedManagerIds.map(String));
    const companyWideManagerIds = companyManagerIds.filter(id => !scopedManagerSet.has(String(id)));
    const managerIds = [...new Set([...departmentManagerIds, ...companyWideManagerIds].map(String))];
    query = { _id: { $in: managerIds }, role: 'soc_manager' };
  } else if (role === 'soc_manager') {
    const companyIds = await assignedCompanyIds(account._id);
    const departmentIds = await SocDepartmentAssignment.find({
      userId: account._id,
      companyId: { $in: companyIds },
      active: true,
    }).distinct('departmentId');
    const assignedCompanies = await Company.find({ _id: { $in: companyIds } }).select('_id email').lean().maxTimeMS(5000);
    const assignedCompanyEmails = assignedCompanies.map(company => String(company.email || '').trim().toLowerCase()).filter(Boolean);
    const managedAnalystIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true, userId: { $ne: account._id } }).distinct('userId');
    // A company-level SOC assignment grants company-wide support coverage when
    // no narrower department assignments exist. If departments are assigned,
    // keep Department Admin contacts restricted to those departments.
    const departmentAdminScope = departmentIds.length
      ? { role: 'department_admin', companyId: { $in: companyIds }, departmentId: { $in: departmentIds } }
      : { role: 'department_admin', companyId: { $in: companyIds } };
    query = { $or: [
      { role: { $in: ANALYST_ROLES }, $or: [
        { socManagerId: account._id },
        { _id: { $in: managedAnalystIds }, socManagerId: null },
      ] },
      { role: 'company_admin', $or: [
        { companyId: { $in: companyIds } },
        { _id: { $in: managedAnalystIds } },
        { email: { $in: assignedCompanyEmails } },
      ] },
      departmentAdminScope,
      { role: 'superadmin' },
    ] };
  } else {
    let managerIds = account.socManagerId ? [account.socManagerId] : [];
    if (!managerIds.length) {
      const companyIds = await assignedCompanyIds(account._id);
      managerIds = await SocCompanyAssignment.find({ companyId: { $in: companyIds }, active: true, userId: { $ne: account._id } }).distinct('userId');
      const managers = await User.find({ _id: { $in: managerIds }, role: 'soc_manager' }).distinct('_id');
      managerIds = managers;
    }
    const teamCompanyIds = await SocCompanyAssignment.find({ userId: { $in: managerIds }, active: true }).distinct('companyId');
    const teamAnalystIds = await SocCompanyAssignment.find({ companyId: { $in: teamCompanyIds }, active: true }).distinct('userId');
    query = { $or: [
      { _id: { $in: managerIds }, role: 'soc_manager' },
      { role: { $in: ANALYST_ROLES }, $or: [
        { socManagerId: { $in: managerIds } },
        { _id: { $in: teamAnalystIds }, socManagerId: null },
      ] },
    ] };
  }
  return User.find({ ...activeAccount, _id: { $ne: account._id }, ...query })
    .select('_id name email role tenantId companyId socManagerId lastLogin')
    .sort({ role: 1, name: 1 }).lean().maxTimeMS(5000);
}

async function authorizedRecipient(req, res) {
  if (!mongoose.isValidObjectId(req.params.recipientId)) {
    res.status(400).json({ message: 'Invalid chat recipient' });
    return null;
  }
  const contacts = await allowedContacts(req.chatAccount, req);
  const recipient = contacts.find(item => String(item._id) === String(req.params.recipientId));
  if (!recipient) res.status(403).json({ message: 'This contact is outside your authorized SOC support scope' });
  return recipient || null;
}

router.get('/contacts', async (req, res) => {
  try {
    const contacts = await allowedContacts(req.chatAccount, req);
    const contactIds = contacts.map(item => item._id);
    const [threads, unread] = await Promise.all([
      SocChatThread.find({ participants: req.chatAccount._id }).sort({ lastMessageAt: -1 }).lean().maxTimeMS(5000),
      SocChatMessage.aggregate([
        { $match: { recipientId: req.chatAccount._id, senderId: { $in: contactIds }, readAt: null } },
        { $group: { _id: '$senderId', count: { $sum: 1 } } },
      ]).option({ maxTimeMS: 5000 }),
    ]);
    const threadByContact = new Map();
    threads.forEach(thread => {
      const otherId = thread.participants.find(id => String(id) !== String(req.chatAccount._id));
      if (otherId) threadByContact.set(String(otherId), thread);
    });
    const unreadByContact = Object.fromEntries(unread.map(row => [String(row._id), row.count]));
    res.json({
      contacts: contacts.map(contact => {
        const thread = threadByContact.get(String(contact._id));
        return { ...contact, threadId: thread?._id || null, lastMessage: thread?.lastMessage || '', lastMessageAt: thread?.lastMessageAt || null, unread: unreadByContact[String(contact._id)] || 0 };
      }).sort((a, b) => new Date(b.lastMessageAt || 0) - new Date(a.lastMessageAt || 0) || a.name.localeCompare(b.name)),
    });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.get('/thread/:recipientId', async (req, res) => {
  try {
    const recipient = await authorizedRecipient(req, res);
    if (!recipient) return;
    const key = participantKey(req.chatAccount._id, recipient._id);
    const thread = await SocChatThread.findOne({ participantKey: key }).lean();
    const messages = thread ? await SocChatMessage.find({ threadId: thread._id })
      .sort({ createdAt: -1 }).limit(100).populate('senderId', 'name role').lean().maxTimeMS(5000) : [];
    if (thread) {
      const readAt = new Date();
      const result = await SocChatMessage.updateMany(
        { threadId: thread._id, recipientId: req.chatAccount._id, readAt: null },
        { $set: { readAt } },
      );
      if (result.modifiedCount > 0) {
        req.app.get('io')?.to(`user:${recipient._id}`).emit('soc-chat:read', {
          threadId: thread._id,
          readerId: req.chatAccount._id,
          readAt,
        });
      }
      await markChatThreadRead(req.chatAccount._id, thread._id);
    }
    res.json({ thread, recipient, messages: messages.reverse() });
  } catch (error) { res.status(500).json({ message: error.message }); }
});

router.post('/thread/:recipientId/messages', async (req, res) => {
  try {
    const recipient = await authorizedRecipient(req, res);
    if (!recipient) return;
    const messageText = String(req.body.message || '').trim();
    if (!messageText) return res.status(400).json({ message: 'Message is required' });
    if (messageText.length > 4000) return res.status(400).json({ message: 'Message must be 4000 characters or less' });
    const key = participantKey(req.chatAccount._id, recipient._id);
    const thread = await SocChatThread.findOneAndUpdate(
      { participantKey: key },
      { $setOnInsert: { participants: [req.chatAccount._id, recipient._id] }, $set: { lastMessage: messageText, lastMessageAt: new Date(), lastSenderId: req.chatAccount._id } },
      { new: true, upsert: true, setDefaultsOnInsert: true },
    );
    const message = await SocChatMessage.create({ threadId: thread._id, senderId: req.chatAccount._id, recipientId: recipient._id, message: messageText });
    const populated = await message.populate('senderId', 'name role');
    const payload = { threadId: thread._id, message: populated };
    await notifyChatMessage({ message, thread, sender: req.chatAccount, recipient });
    req.app.get('io')?.to(`user:${recipient._id}`).emit('soc-chat:message', payload);
    req.app.get('io')?.to(`user:${req.chatAccount._id}`).emit('soc-chat:message', payload);
    res.status(201).json(payload);
  } catch (error) { res.status(500).json({ message: error.message }); }
});

module.exports = router;
