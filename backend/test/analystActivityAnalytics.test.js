const test = require('node:test');
const assert = require('node:assert/strict');

const {
  overlapMs,
  analyzeAnalystActivity,
} = require('../src/utils/analystActivityAnalytics');

const at = value => new Date(`2026-08-19T${value}:00.000Z`);

test('analyst activity builds real login/logout sessions and shift adherence', () => {
  const result = analyzeAnalystActivity({
    rangeStart: at('08:00'),
    rangeEnd: at('20:00'),
    shiftWindows: [{ start: at('09:00'), end: at('17:00') }],
    loginEvents: [
      { action: 'login_success', success: true, createdAt: at('08:00'), ipAddress: '10.0.0.8' },
      { action: 'session_resumed', success: true, createdAt: at('12:00'), ipAddress: '10.0.0.8' },
      { action: 'logout', success: true, createdAt: at('18:00'), ipAddress: '10.0.0.8' },
    ],
  });

  assert.equal(result.sessions.length, 1, 'session heartbeats must not split one login session');
  assert.equal(result.sessions[0].durationMinutes, 600);
  assert.equal(result.sessions[0].workingMinutes, 480);
  assert.equal(result.sessions[0].outsideShiftMinutes, 120);
  assert.equal(result.metrics.loginCount, 1);
  assert.equal(result.metrics.logoutCount, 1);
  assert.equal(result.metrics.afterHoursLoginCount, 1);
});

test('analyst activity reports account lock and working-hours lock duration', () => {
  const result = analyzeAnalystActivity({
    rangeStart: at('08:00'),
    rangeEnd: at('18:00'),
    shiftWindows: [{ start: at('09:00'), end: at('17:00') }],
    loginEvents: [
      { action: 'otp_failed', success: false, failReason: 'account_locked', createdAt: at('10:00') },
      { action: 'login_success', success: true, createdAt: at('11:15') },
    ],
    auditEvents: [
      { action: 'ANALYST_SUSPENDED', createdAt: at('14:00'), metadata: { reason: 'SOC review' } },
      { action: 'ANALYST_REACTIVATED', createdAt: at('14:30') },
    ],
  });

  assert.equal(result.metrics.accountLockCount, 2);
  assert.equal(result.metrics.totalLockedMinutes, 105);
  assert.equal(result.metrics.lockedWorkingMinutes, 105);
  assert.equal(result.metrics.failedLoginCount, 1);
});

test('activity audit recognizes SOC Manager suspension windows', () => {
  const result = analyzeAnalystActivity({
    rangeStart: at('08:00'),
    rangeEnd: at('18:00'),
    shiftWindows: [{ start: at('09:00'), end: at('17:00') }],
    auditEvents: [
      { action: 'SOC_MANAGER_SUSPENDED', createdAt: at('13:00'), metadata: { reason: 'Security review' } },
      { action: 'SOC_MANAGER_REACTIVATED', createdAt: at('13:45') },
    ],
  });

  assert.equal(result.metrics.accountLockCount, 1);
  assert.equal(result.metrics.lockedWorkingMinutes, 45);
  assert.equal(result.locks[0].reason, 'Security review');
});

test('shift overlap counts overlapping shift windows only once', () => {
  const value = overlapMs(at('09:00'), at('13:00'), [
    { start: at('08:00'), end: at('11:00') },
    { start: at('10:00'), end: at('12:00') },
  ]);
  assert.equal(value, 3 * 60 * 60 * 1000);
});

test('screen inactivity locks and automatic logout are counted in the live audit', () => {
  const result = analyzeAnalystActivity({
    rangeStart: at('08:00'),
    rangeEnd: at('12:00'),
    shiftWindows: [{ start: at('09:00'), end: at('17:00') }],
    loginEvents: [
      { action: 'login_success', success: true, createdAt: at('09:00') },
      { action: 'screen_locked', success: true, failReason: 'idle_timeout_10m', createdAt: at('10:00') },
      { action: 'auto_logout', success: true, failReason: 'idle_timeout_30m', createdAt: at('10:20') },
    ],
  });

  assert.equal(result.metrics.screenLockCount, 1);
  assert.equal(result.metrics.screenLockedMinutes, 20);
  assert.equal(result.metrics.screenLockedWorkingMinutes, 20);
  assert.equal(result.metrics.autoLogoutCount, 1);
  assert.equal(result.metrics.logoutCount, 1);
  assert.equal(result.metrics.accountLockCount, 0);
  assert.equal(result.sessions[0].logoutAction, 'auto_logout');
  assert.equal(result.sessions[0].durationMinutes, 80);
});
