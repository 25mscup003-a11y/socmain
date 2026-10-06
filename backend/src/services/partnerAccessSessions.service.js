const mongoose = require('mongoose');
const LoginActivity = require('../models/LoginActivity.model');
const User = require('../models/User.model');
const Partner = require('../models/Partner.model');
const Company = require('../models/Company.model');

const stringId = value => String(value?._id || value || '');
const validIds = values => [...new Set(values.map(stringId).filter(value => mongoose.isObjectIdOrHexString(value)))];
const byId = records => new Map(records.map(record => [stringId(record._id), record]));

function accessIdentity(event) {
  const snapshot = event.partnerAccess || {};
  const marker = /^partner:([a-f0-9]{24});user:([a-f0-9]{24})(?:;|$)/i.exec(event.failReason || '');
  return {
    actorId: stringId(event.userId),
    partnerId: stringId(snapshot.partnerId || marker?.[1]),
    targetId: stringId(snapshot.targetUserId || marker?.[2]),
  };
}

// Pair by the issued support session, actor, target and historical partner.
// Never infer a logout from another login, token expiry or a browser closing.
function sessionKey(event) {
  if (!event.sessionId) return null;
  const { actorId, partnerId, targetId } = accessIdentity(event);
  if (!actorId || !partnerId || !targetId) return null;
  return JSON.stringify([event.sessionId, actorId, partnerId, targetId]);
}

async function partnerAccessSessions(query = {}) {
  const requestedPage = query.page === undefined ? 1 : Number(query.page);
  if (!Number.isSafeInteger(requestedPage) || requestedPage < 1) {
    throw Object.assign(new Error('Invalid access history page.'), { status: 400 });
  }
  const filter = { action: 'partner_impersonation_started', success: true };
  const pageSize = 6;
  const total = await LoginActivity.countDocuments(filter);
  const page = Math.min(requestedPage, Math.max(1, Math.ceil(total / pageSize)));
  const starts = await LoginActivity.find(filter)
    .select('_id userId email companyId partnerAccess failReason sessionId createdAt ipAddress')
    .sort({ createdAt: -1, _id: -1 }).skip((page - 1) * pageSize).limit(pageSize).lean();

  const identities = starts.map(accessIdentity);
  const sessionIds = [...new Set(starts.map(event => event.sessionId).filter(Boolean))];
  const userIds = validIds(identities.flatMap(identity => [identity.actorId, identity.targetId]));
  const partnerIds = validIds(identities.map(identity => identity.partnerId));
  const companyIds = validIds(starts.map(event => event.companyId));
  const [ends, users, partners, companies] = await Promise.all([
    sessionIds.length ? LoginActivity.find({
      action: 'partner_impersonation_ended', success: true,
      userId: { $in: validIds(identities.map(identity => identity.actorId)) }, sessionId: { $in: sessionIds },
    }).select('userId partnerAccess failReason sessionId createdAt').sort({ createdAt: 1, _id: 1 }).lean() : [],
    userIds.length ? User.find({ _id: { $in: userIds } }).select('_id name email role').lean() : [],
    partnerIds.length ? Partner.find({ _id: { $in: partnerIds } }).select('_id name').lean() : [],
    companyIds.length ? Company.find({ _id: { $in: companyIds } }).select('_id name').lean() : [],
  ]);
  const usersById = byId(users), partnersById = byId(partners), companiesById = byId(companies);
  const endsBySession = new Map();
  for (const end of ends) {
    const key = sessionKey(end);
    if (!key) continue;
    if (!endsBySession.has(key)) endsBySession.set(key, []);
    endsBySession.get(key).push(end);
  }
  return {
    page, pageSize, total,
    entries: starts.map((start, index) => {
      const { actorId, partnerId, targetId } = identities[index];
      const snapshot = start.partnerAccess || {};
      const actor = usersById.get(actorId), target = usersById.get(targetId);
      const companyId = stringId(start.companyId);
      const end = (endsBySession.get(sessionKey(start)) || [])
        .find(event => new Date(event.createdAt) >= new Date(start.createdAt));
      return {
        _id: start._id,
        partnerId, partnerName: snapshot.partnerName || partnersById.get(partnerId)?.name || '',
        actorId, actorName: snapshot.actorName || actor?.name || '', actorEmail: start.email || '',
        targetUserId: targetId, targetName: snapshot.targetName || target?.name || '',
        targetEmail: snapshot.targetEmail || target?.email || '', targetRole: snapshot.targetRole || target?.role || '',
        companyId, companyName: snapshot.companyName || companiesById.get(companyId)?.name || '',
        loginAt: start.createdAt, logoutAt: end?.createdAt || null, ipAddress: start.ipAddress || '',
      };
    }),
  };
}

module.exports = { partnerAccessSessions };
