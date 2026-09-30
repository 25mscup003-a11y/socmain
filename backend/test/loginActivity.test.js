const test = require('node:test');
const assert = require('node:assert/strict');
const LoginActivity = require('../src/models/LoginActivity.model');
const { companyLoginScope, transformLoginActionCounts } = require('../src/utils/loginAnalytics');

test('login activity schema accepts canonical password and MFA lifecycle actions', () => {
  const actions = new Set(LoginActivity.schema.path('action').enumValues);
  for (const action of ['login_success', 'login_failed', 'otp_required', 'otp_verified', 'otp_failed', 'screen_locked', 'screen_unlocked', 'auto_logout', 'superadmin_impersonation_started', 'superadmin_company_impersonation_started']) {
    assert.equal(actions.has(action), true, `${action} must be persisted`);
  }
  assert.equal(actions.has('login_2fa_failed'), false);
  assert.equal(actions.has('login_blocked'), false);
});

test('login analytics never falls back to a cross-tenant query', () => {
  assert.equal(companyLoginScope(null), null);
  assert.equal(companyLoginScope('not-an-object-id'), null);

  const companyId = '6a1b19818ddb7deaa10bfe2c';
  const scope = companyLoginScope(companyId);
  assert.equal(String(scope.companyId), companyId);
});

test('login action counts keep zero-value dashboard categories', () => {
  const counts = transformLoginActionCounts([
    { _id: 'login_success', count: 12 },
    { _id: 'password_changed', count: 2 },
  ]);

  assert.equal(counts.login_success, 12);
  assert.equal(counts.login_failed, 0);
  assert.equal(counts.otp_failed, 0);
  assert.equal(counts.password_changed, 2);
});
