const mongoose = require('mongoose');
const SocNotification = require('../models/SocNotification.model');
const User = require('../models/User.model');
const SocCompanyAssignment = require('../models/SocCompanyAssignment.model');
const SocShift = require('../models/SocShift.model');

const ANALYST_ROLES = ['l1_analyst', 'l2_analyst', 'l3_analyst', 'l4_analyst'];
const ADMIN_ROLES = ['superadmin', 'soc_manager'];
let socketServer = null;

function attachIO(io) {
  socketServer = io || null;
}

function rolePrefix(role) {
  return {
    l1_analyst: '/l1', l2_analyst: '/l2', l3_analyst: '/l3', l4_analyst: '/l4', soc_manager: '/soc-manager',
  }[role] || '';
}

function humanize(value) {
  return String(value || 'configuration updated')
    .replace(/[._-]+/g, ' ')
    .replace(/\b\w/g, character => character.toUpperCase());
}

function notificationLink(role, targetType, targetId) {
  const prefix = rolePrefix(role);
  if (!prefix) return '';
  if (targetType === 'SocShift') return `${prefix}/shifts`;
  if (targetType === 'EdrIncident' && targetId) return `${prefix}/incidents/${targetId}`;
  if (targetType === 'Alert' && targetId) {
    return role === 'l4_analyst' ? `${prefix}/tickets/${targetId}` : `${prefix}/alerts/${targetId}`;
  }
  return `${prefix}/settings?section=notifications`;
}

async function createSocNotification(input) {
  if (!input?.userId || !input?.type || !input?.title || !input?.message) return null;
  const dedupeKey = input.dedupeKey || `${input.sourceType || input.type}:${input.sourceId || ''}`;
  const identity = dedupeKey
    ? { userId: input.userId, dedupeKey }
    : { userId: input.userId, ticketId: input.ticketId, type: input.type };
  const result = await SocNotification.updateOne(identity, { $setOnInsert: {
    tenantId: input.tenantId || null,
    companyId: input.companyId || null,
    userId: input.userId,
    ticketId: input.ticketId || null,
    chatThreadId: input.chatThreadId || null,
    actorId: input.actorId || null,
    type: input.type,
    sourceType: input.sourceType || 'audit',
    sourceId: String(input.sourceId || ''),
    dedupeKey,
    title: String(input.title).slice(0, 200),
    message: String(input.message).slice(0, 1000),
    link: String(input.link || '').slice(0, 500),
    read: false,
    readAt: null,
  } }, { upsert: true });
  if (!result.upsertedCount) return null;
  const notification = await SocNotification.findOne(identity)
    .populate('companyId', 'name')
    .populate('actorId', 'name email role')
    .lean();
  if (notification) socketServer?.to(`user:${input.userId}`).emit('soc:notification', notification);
  return notification;
}

async function companyAnalystIds(companyId) {
  if (!companyId) return [];
  const assignedIds = await SocCompanyAssignment.find({ companyId, active: true }).distinct('userId');
  return User.find({
    _id: { $in: assignedIds }, role: { $in: ANALYST_ROLES }, isActive: true,
    accountStatus: { $nin: ['disabled', 'suspended', 'expired'] },
  }).distinct('_id');
}

async function recipientsForAuditEvent(event, actor) {
  const recipientIds = new Set();
  const addAnalyst = user => {
    if (user && ANALYST_ROLES.includes(user.role)) recipientIds.add(String(user._id));
  };

  const metadataAssigneeId = event.metadata?.assigneeId;
  if (metadataAssigneeId && mongoose.isValidObjectId(metadataAssigneeId)) {
    addAnalyst(await User.findById(metadataAssigneeId).select('_id role').lean());
  }

  let target = null;
  if (event.targetType === 'User' && mongoose.isValidObjectId(event.targetId)) {
    target = await User.findById(event.targetId).select('_id role socManagerId').lean();
    addAnalyst(target);
  }

  if (event.targetType === 'SocShift' && mongoose.isValidObjectId(event.targetId)) {
    const shift = await SocShift.findById(event.targetId).select('analystIds').lean();
    (shift?.analystIds || []).forEach(id => recipientIds.add(String(id)));
  }

  let companyIds = event.companyId ? [event.companyId] : [];
  if (!companyIds.length && target?.role === 'soc_manager') {
    companyIds = await SocCompanyAssignment.find({ userId: target._id, active: true }).distinct('companyId');
  }
  if (!companyIds.length && actor.role === 'soc_manager') {
    companyIds = await SocCompanyAssignment.find({ userId: actor._id, active: true }).distinct('companyId');
  }

  // Company-wide administrative/security changes are visible to every active
  // analyst in that authorized company scope. Explicit assignees remain
  // included even when an optional company mapping is absent.
  for (const companyId of companyIds) {
    (await companyAnalystIds(companyId)).forEach(id => recipientIds.add(String(id)));
  }
  recipientIds.delete(String(actor._id));
  return [...recipientIds];
}

async function notifyAuditEvent(event) {
  if (!event?.actorId) return [];
  const actor = await User.findById(event.actorId).select('_id name email role tenantId').lean();
  if (!actor || !ADMIN_ROLES.includes(actor.role)) return [];
  const recipientIds = await recipientsForAuditEvent(event, actor);
  if (!recipientIds.length) return [];
  const recipients = await User.find({ _id: { $in: recipientIds }, role: { $in: ANALYST_ROLES } })
    .select('_id role tenantId companyId').lean();
  const actorLabel = actor.role === 'superadmin' ? 'Super Admin' : 'SOC Manager';
  const actionLabel = humanize(event.action);
  return Promise.all(recipients.map(recipient => createSocNotification({
    tenantId: event.tenantId || recipient.tenantId,
    companyId: event.companyId || recipient.companyId || null,
    userId: recipient._id,
    actorId: actor._id,
    type: 'admin_change',
    sourceType: 'audit',
    sourceId: event._id,
    dedupeKey: `audit:${event._id}`,
    title: `${actorLabel} update`,
    message: `${actor.name || actorLabel} performed: ${actionLabel}.`,
    link: notificationLink(recipient.role, event.targetType, event.targetId),
  })));
}

async function notifyChatMessage({ message, thread, sender, recipient }) {
  if (!message?._id || !recipient?._id) return null;
  const companyIds = await SocCompanyAssignment.find({ userId: recipient._id, active: true }).distinct('companyId');
  const prefix = rolePrefix(recipient.role);
  return createSocNotification({
    tenantId: recipient.tenantId || sender?.tenantId || null,
    companyId: recipient.companyId || companyIds[0] || sender?.companyId || null,
    userId: recipient._id,
    actorId: sender?._id || message.senderId,
    chatThreadId: thread?._id || message.threadId,
    type: 'chat_message',
    sourceType: 'chat',
    sourceId: message._id,
    dedupeKey: `chat:${message._id}`,
    title: `New message from ${sender?.name || 'SOC contact'}`,
    message: String(message.message || 'You received a new SOC chat message.').slice(0, 300),
    link: prefix ? `${prefix}/contact-support?contact=${sender?._id || message.senderId}` : '',
  });
}

async function markChatThreadRead(userId, threadId) {
  if (!userId || !threadId) return 0;
  const readAt = new Date();
  await SocNotification.updateMany(
    { userId, chatThreadId: threadId, type: 'chat_message', read: false },
    { $set: { read: true, readAt } },
  );
  const unread = await SocNotification.countDocuments({ userId, read: false });
  socketServer?.to(`user:${userId}`).emit('soc:notifications:read', { unread });
  return unread;
}

async function ensureIndexes() {
  const legacyName = 'userId_1_ticketId_1_type_1';
  const indexes = await SocNotification.collection.indexes().catch(error => {
    if (error.codeName === 'NamespaceNotFound') return [];
    throw error;
  });
  const legacy = indexes.find(index => index.name === legacyName);
  if (legacy && !legacy.partialFilterExpression) {
    await SocNotification.collection.dropIndex(legacyName).catch(error => {
      if (error.codeName !== 'IndexNotFound') throw error;
    });
  }
  await SocNotification.createIndexes();
}

module.exports = {
  attachIO,
  createSocNotification,
  notifyAuditEvent,
  notifyChatMessage,
  markChatThreadRead,
  ensureIndexes,
};
