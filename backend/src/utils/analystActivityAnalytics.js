const { normalizeIpAddress } = require('./clientIp');

const LOGIN_ACTIONS = new Set(['login_success', 'session_resumed']);
const LOGOUT_ACTIONS = new Set(['logout', 'auto_logout']);

function asDate(value) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function overlapMs(start, end, windows = []) {
  const from = asDate(start)?.getTime();
  const to = asDate(end)?.getTime();
  if (!Number.isFinite(from) || !Number.isFinite(to) || to <= from) return 0;
  const intersections = windows.map(window => {
    const windowStart = asDate(window.start)?.getTime();
    const windowEnd = asDate(window.end)?.getTime();
    if (!Number.isFinite(windowStart) || !Number.isFinite(windowEnd)) return null;
    const overlapStart = Math.max(from, windowStart);
    const overlapEnd = Math.min(to, windowEnd);
    return overlapEnd > overlapStart ? { start: overlapStart, end: overlapEnd } : null;
  }).filter(Boolean).sort((a, b) => a.start - b.start);
  let total = 0;
  let current = null;
  for (const interval of intersections) {
    if (!current || interval.start > current.end) {
      if (current) total += current.end - current.start;
      current = { ...interval };
    } else if (interval.end > current.end) {
      current.end = interval.end;
    }
  }
  return total + (current ? current.end - current.start : 0);
}

function mergeIntervals(intervals = []) {
  const ordered = intervals
    .map(item => ({ ...item, start: asDate(item.start), end: asDate(item.end) }))
    .filter(item => item.start && item.end && item.end > item.start)
    .sort((a, b) => a.start - b.start);
  const merged = [];
  for (const item of ordered) {
    const previous = merged[merged.length - 1];
    if (!previous || item.start > previous.end) {
      merged.push({ ...item, reasons: [item.reason].filter(Boolean) });
      continue;
    }
    if (item.end > previous.end) previous.end = item.end;
    previous.reasons = [...new Set([...(previous.reasons || []), item.reason].filter(Boolean))];
  }
  return merged;
}

function buildSessions(events = [], rangeEnd = new Date()) {
  const ordered = events
    .filter(item => LOGIN_ACTIONS.has(item.action) || LOGOUT_ACTIONS.has(item.action))
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const sessions = [];
  let open = null;
  for (const event of ordered) {
    const at = asDate(event.createdAt);
    if (!at) continue;
    if (LOGIN_ACTIONS.has(event.action) && event.success !== false) {
      if (!open) open = event;
      else if (event.action === 'login_success') {
        sessions.push({ login: open, logout: null, start: new Date(open.createdAt), end: at, inferredLogout: true });
        open = event;
      }
      continue;
    }
    if (LOGOUT_ACTIONS.has(event.action) && open) {
      sessions.push({ login: open, logout: event, start: new Date(open.createdAt), end: at, inferredLogout: false });
      open = null;
    }
  }
  if (open) {
    const start = new Date(open.createdAt);
    const end = new Date(Math.min(asDate(rangeEnd)?.getTime() || Date.now(), start.getTime() + 24 * 60 * 60 * 1000));
    sessions.push({ login: open, logout: null, start, end, active: end.getTime() === (asDate(rangeEnd)?.getTime() || 0), inferredLogout: true });
  }
  return sessions;
}

function buildLockIntervals(loginEvents = [], auditEvents = [], rangeEnd = new Date()) {
  const endAt = asDate(rangeEnd) || new Date();
  const accountIntervals = [];
  const otpLocks = loginEvents.filter(item => item.failReason === 'account_locked').sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  const successfulLogins = loginEvents.filter(item => LOGIN_ACTIONS.has(item.action) && item.success !== false);
  for (const lock of otpLocks) {
    const start = asDate(lock.createdAt);
    const unlock = successfulLogins.find(item => new Date(item.createdAt) > start);
    accountIntervals.push({
      start, end: unlock ? new Date(unlock.createdAt) : endAt,
      reason: 'Authentication lock', type: 'authentication_lock',
    });
  }

  const suspendActions = ['ANALYST_SUSPENDED', 'SOC_MANAGER_SUSPENDED'];
  const reactivateActions = ['ANALYST_REACTIVATED', 'SOC_MANAGER_REACTIVATED'];
  const manualEvents = auditEvents
    .filter(item => [...suspendActions, ...reactivateActions].includes(item.action))
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  let manualLock = null;
  for (const event of manualEvents) {
    if (suspendActions.includes(event.action) && !manualLock) manualLock = event;
    if (reactivateActions.includes(event.action) && manualLock) {
      accountIntervals.push({
        start: new Date(manualLock.createdAt), end: new Date(event.createdAt),
        reason: manualLock.metadata?.reason || 'Manager suspension', type: 'manager_suspension',
      });
      manualLock = null;
    }
  }
  if (manualLock) accountIntervals.push({
    start: new Date(manualLock.createdAt), end: endAt,
    reason: manualLock.metadata?.reason || 'Manager suspension', type: 'manager_suspension',
  });

  const screenIntervals = [];
  const sessionEvents = loginEvents
    .filter(item => ['screen_locked', 'screen_unlocked', 'logout', 'auto_logout'].includes(item.action))
    .sort((a, b) => new Date(a.createdAt) - new Date(b.createdAt));
  let screenLock = null;
  for (const event of sessionEvents) {
    if (event.action === 'screen_locked' && !screenLock) screenLock = event;
    if (['screen_unlocked', 'logout', 'auto_logout'].includes(event.action) && screenLock) {
      screenIntervals.push({
        start: new Date(screenLock.createdAt), end: new Date(event.createdAt),
        reason: screenLock.failReason || '10-minute inactivity screen lock', type: 'screen_lock',
      });
      screenLock = null;
    }
  }
  if (screenLock) screenIntervals.push({
    start: new Date(screenLock.createdAt), end: endAt,
    reason: screenLock.failReason || '10-minute inactivity screen lock', type: 'screen_lock',
  });
  return [...mergeIntervals(accountIntervals), ...mergeIntervals(screenIntervals)].sort((a, b) => a.start - b.start);
}

function analyzeAnalystActivity({ loginEvents = [], auditEvents = [], shiftWindows = [], rangeStart, rangeEnd = new Date() } = {}) {
  const from = asDate(rangeStart) || new Date(0);
  const to = asDate(rangeEnd) || new Date();
  const events = loginEvents.filter(item => {
    const at = asDate(item.createdAt);
    return at && at >= from && at <= to;
  });
  const sessions = buildSessions(loginEvents.filter(item => {
    const at = asDate(item.createdAt);
    return at && at <= to;
  }), to).filter(item => item.end > from && item.start < to).map(item => {
    const measuredStart = item.start < from ? from : item.start;
    const measuredEnd = item.end > to ? to : item.end;
    const durationMs = Math.max(0, measuredEnd - measuredStart);
    const workingMs = overlapMs(measuredStart, measuredEnd, shiftWindows);
    return {
      loginAt: item.start,
      logoutAt: item.logout ? item.end : null,
      durationMinutes: Math.round(durationMs / 60000),
      workingMinutes: Math.round(workingMs / 60000),
      outsideShiftMinutes: Math.max(0, Math.round((durationMs - workingMs) / 60000)),
      active: Boolean(item.active),
      inferredLogout: Boolean(item.inferredLogout),
      logoutAction: item.logout?.action || '',
      ipAddress: normalizeIpAddress(item.login.ipAddress),
      userAgent: item.login.userAgent || '',
    };
  });
  const locks = buildLockIntervals(loginEvents, auditEvents, to)
    .map(item => ({
      start: item.start < from ? from : item.start,
      end: item.end > to ? to : item.end,
      type: item.type || 'authentication_lock',
      reason: (item.reasons || [item.reason]).filter(Boolean).join(', '),
    }))
    .filter(item => item.end > item.start)
    .map(item => ({
      ...item,
      durationMinutes: Math.round((item.end - item.start) / 60000),
      workingMinutes: Math.round(overlapMs(item.start, item.end, shiftWindows) / 60000),
    }));
  const inShift = at => shiftWindows.some(window => at >= new Date(window.start) && at <= new Date(window.end));
  const successfulEvents = events.filter(item => item.action === 'login_success' && item.success !== false);
  const logoutEvents = events.filter(item => LOGOUT_ACTIONS.has(item.action));
  const screenLockEvents = events.filter(item => item.action === 'screen_locked');
  const screenUnlockEvents = events.filter(item => item.action === 'screen_unlocked');
  const autoLogoutEvents = events.filter(item => item.action === 'auto_logout');
  const failedEvents = events.filter(item => item.action === 'login_failed' || item.action === 'otp_failed');
  const totalSessionMinutes = sessions.reduce((sum, item) => sum + item.durationMinutes, 0);
  const workingSessionMinutes = sessions.reduce((sum, item) => sum + item.workingMinutes, 0);
  const totalLockedMinutes = locks.reduce((sum, item) => sum + item.durationMinutes, 0);
  const lockedWorkingMinutes = locks.reduce((sum, item) => sum + item.workingMinutes, 0);
  const screenLocks = locks.filter(item => item.type === 'screen_lock');
  const accountLocks = locks.filter(item => item.type !== 'screen_lock');

  return {
    metrics: {
      loginCount: successfulEvents.length,
      logoutCount: logoutEvents.length,
      manualLogoutCount: logoutEvents.length - autoLogoutEvents.length,
      autoLogoutCount: autoLogoutEvents.length,
      failedLoginCount: failedEvents.length,
      accountLockCount: accountLocks.length,
      screenLockCount: screenLockEvents.length,
      screenUnlockCount: screenUnlockEvents.length,
      totalSessionMinutes,
      workingSessionMinutes,
      outsideShiftMinutes: Math.max(0, totalSessionMinutes - workingSessionMinutes),
      totalLockedMinutes,
      lockedWorkingMinutes,
      accountLockedMinutes: accountLocks.reduce((sum, item) => sum + item.durationMinutes, 0),
      screenLockedMinutes: screenLocks.reduce((sum, item) => sum + item.durationMinutes, 0),
      screenLockedWorkingMinutes: screenLocks.reduce((sum, item) => sum + item.workingMinutes, 0),
      afterHoursLoginCount: successfulEvents.filter(item => !inShift(new Date(item.createdAt))).length,
      activeSessionCount: sessions.filter(item => item.active).length,
      lastLoginAt: successfulEvents.at(-1)?.createdAt || null,
      lastLogoutAt: logoutEvents.at(-1)?.createdAt || null,
    },
    sessions: sessions.reverse(),
    locks: locks.reverse(),
    activityTimeline: [
      ...events.map(item => ({
        source: 'authentication', action: item.action, at: item.createdAt, success: item.success,
        reason: item.failReason || '', ipAddress: normalizeIpAddress(item.ipAddress), userAgent: item.userAgent || '',
      })),
      ...auditEvents.filter(item => new Date(item.createdAt) >= from && new Date(item.createdAt) <= to).map(item => ({
        source: 'soc_audit', action: item.action, at: item.createdAt, success: true,
        reason: item.metadata?.reason || '', ipAddress: normalizeIpAddress(item.ipAddress), actor: item.actorId || null,
      })),
    ].sort((a, b) => new Date(b.at) - new Date(a.at)).slice(0, 100),
  };
}

module.exports = { overlapMs, buildSessions, buildLockIntervals, analyzeAnalystActivity };
