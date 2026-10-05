const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSuperadminAuditEvents } = require('../src/utils/superadminAudit');

const admins = [{ _id: 'admin', name: 'Superadmin', email: 'admin@example.test' }];
const event = (_id, action, hour, sessionId) => ({
  _id, action, createdAt: `2026-10-05T${hour}:00:00Z`, sessionId,
  userId: 'admin', email: 'admin@example.test', success: true,
});

test('simultaneous logins are paired by session, not by account or timestamp proximity', () => {
  const events = buildSuperadminAuditEvents([], [
    event('one', 'login_success', '10', 'session-one'),
    event('two', 'login_success', '11', 'session-two'),
    event('close-one', 'logout', '12', 'session-one'),
    event('close-two', 'auto_logout', '13', 'session-two'),
  ], admins);
  assert.equal(events.length, 2);
  assert.equal(events[0]._id, 'two');
  assert.equal(events[0].loginAt, '2026-10-05T11:00:00Z');
  assert.equal(events[0].logoutAt, '2026-10-05T13:00:00Z');
  assert.equal(events[1].loginAt, '2026-10-05T10:00:00Z');
  assert.equal(events[1].logoutAt, '2026-10-05T12:00:00Z');
});

test('legacy events without session IDs retain only the timestamps actually recorded', () => {
  const events = buildSuperadminAuditEvents([], [
    event('one', 'login_success', '10'), event('two', 'logout', '11'),
  ], admins);
  assert.equal(events.length, 2);
  assert.equal(events[0].eventType, 'superadmin_logout');
  assert.equal(events[0].loginAt, null);
  assert.equal(events[0].logoutAt, '2026-10-05T11:00:00Z');
  assert.equal(events[1].logoutAt, null);
});

test('active sessions have no fabricated logout and unrelated activity is excluded', () => {
  const login = event('one', 'login_success', '10', 'session-one');
  const events = buildSuperadminAuditEvents([], [login, login,
    event('otp', 'otp_required', '09', 'session-one'),
    { ...event('failed', 'login_success', '11'), success: false },
    { ...event('other', 'login_success', '12'), userId: 'company-user' },
  ], admins);
  assert.equal(events.length, 1);
  assert.equal(events[0].logoutAt, null);
});

test('support sessions keep their recorded login and logout times and latest entries come first', () => {
  const events = buildSuperadminAuditEvents([
    { _id: 'support', createdAt: '2026-10-05T10:00:00Z', logoutAt: '2026-10-05T12:00:00Z' },
  ], [event('self', 'login_success', '11', 'self-session')], admins);
  assert.equal(events[0]._id, 'support');
  assert.equal(events[0].eventType, 'user_login');
  assert.equal(events[0].loginAt, '2026-10-05T10:00:00Z');
  assert.equal(events[0].logoutAt, '2026-10-05T12:00:00Z');
});
