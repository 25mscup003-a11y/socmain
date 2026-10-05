function buildSuperadminAuditEvents(audits, activity, superadmins) {
  const adminsById = new Map(superadmins.map(admin => [String(admin._id), admin]));
  const sessions = new Map();
  const seen = new Set();
  for (const event of activity) {
    if (seen.has(String(event._id)) || !adminsById.has(String(event.userId))) continue;
    if (!['login_success', 'logout', 'auto_logout'].includes(event.action) || event.success === false) continue;
    seen.add(String(event._id));
    // Old entries without a session ID stay separate; do not guess which of
    // several simultaneous logins a historical logout belongs to.
    const key = event.sessionId ? `${event.userId}:${event.sessionId}` : `event:${event._id}`;
    if (!sessions.has(key)) sessions.set(key, []);
    sessions.get(key).push(event);
  }

  const events = audits.map(audit => ({
    ...audit, eventType: 'user_login', loginAt: audit.createdAt, logoutAt: audit.logoutAt || null,
  }));
  for (const records of sessions.values()) {
    records.sort((left, right) => new Date(left.createdAt) - new Date(right.createdAt));
    const login = records.find(event => event.action === 'login_success');
    const logout = records.find(event => ['logout', 'auto_logout'].includes(event.action)
      && (!login || new Date(event.createdAt) >= new Date(login.createdAt)));
    const source = login || logout;
    const admin = adminsById.get(String(source.userId));
    events.push({
      _id: source._id, eventType: login ? 'superadmin_login' : 'superadmin_logout',
      actorId: source.userId, actorName: admin.name || source.email, actorEmail: source.email,
      targetUserId: source.userId, targetName: admin.name || source.email,
      targetEmail: source.email, targetRole: 'superadmin',
      createdAt: source.createdAt, loginAt: login?.createdAt || null, logoutAt: logout?.createdAt || null,
      ipAddress: source.ipAddress, userAgent: source.userAgent,
    });
  }
  return events.sort((left, right) => new Date(right.logoutAt || right.loginAt || right.createdAt)
    - new Date(left.logoutAt || left.loginAt || left.createdAt)).slice(0, 50);
}

function legacySuperadminLoginAudits(activity, superadmins) {
  const adminsById = new Map(superadmins.map(admin => [String(admin._id), admin]));
  return activity.flatMap(event => {
    if (!['superadmin_impersonation_started', 'superadmin_company_impersonation_started'].includes(event.action)
      || event.success === false) return [];
    const actorId = String(event.failReason || '').match(/^by:([a-f0-9]{24})(?:;|$)/i)?.[1];
    if (!actorId) return [];
    const actor = adminsById.get(actorId);
    const target = event.userId;
    return [{
      _id: `legacy:${event._id}`, actorId,
      actorName: actor?.name || 'Superadmin', actorEmail: actor?.email || 'Not recorded',
      targetUserId: target?._id || target || null,
      targetName: target?.name || event.email, targetEmail: event.email,
      targetRole: target?.role || 'Unknown',
      createdAt: event.createdAt, logoutAt: null, ipAddress: event.ipAddress, userAgent: event.userAgent,
    }];
  });
}

module.exports = { buildSuperadminAuditEvents, legacySuperadminLoginAudits };
