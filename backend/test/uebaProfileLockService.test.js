const test = require('node:test');
const assert = require('node:assert/strict');

const {
  isProfileMismatch,
  safeInteractiveUsername,
  isSafeLocalUsername,
  responseEventStatus,
  responseActionState,
  deriveProtectionStatus,
  geolocationPolicyResponse,
} = require('../src/services/uebaProfileLock.service');

test('profile mismatch lock requires a completed 30-day profile', () => {
  assert.equal(isProfileMismatch({ ruleId: 'UEBA_INPUT_PROFILE_MISMATCH', inputProfileMismatch: true, inputBaselineDays: 30 }), true);
  assert.equal(isProfileMismatch({ ruleId: 'UEBA_INPUT_PROFILE_MISMATCH', inputProfileMismatch: true, inputBaselineDays: 29 }), false);
  assert.equal(isProfileMismatch({ ruleId: 'UEBA_INPUT_ACTIVITY_SUMMARY', inputProfileMismatch: true, inputBaselineDays: 30 }), false);
});

test('geolocation identity actions validate local usernames and preserve safe status semantics', () => {
  assert.equal(isSafeLocalUsername('alice.local'), true);
  assert.equal(isSafeLocalUsername('DOMAIN\\alice'), false);
  assert.equal(isSafeLocalUsername('root'), false);
  assert.equal(responseActionState({ status: 'waiting_approval' }), 'pending');
  assert.equal(responseActionState({ status: 'successful' }), 'successful');
  assert.equal(responseActionState({ status: 'cancelled' }), 'failed');
  assert.equal(deriveProtectionStatus({ status: 'detected', responseActions: [{ actionType: 'force_logoff', status: 'pending' }] }), 'response_pending');
  assert.equal(deriveProtectionStatus({ status: 'detected', responseActions: [{ actionType: 'isolate', status: 'successful' }] }), 'response_success');
  assert.equal(deriveProtectionStatus({ status: 'detected', responseActions: [{ actionType: 'lock_account', status: 'successful' }] }), 'locked');
  assert.deepEqual(
    geolocationPolicyResponse({ containmentStatus: 'logged_out', rawEvent: { systemLogoutRequested: true, sessionResponse: { action: 'SYSTEM_LOGOUT' } } }),
    { actionType: 'force_logoff', status: 'successful', result: 'SYSTEM_LOGOUT' },
  );
  assert.deepEqual(
    geolocationPolicyResponse({ containmentStatus: 'blocked', rawEvent: { raw: { ipBlockRequested: true } }, description: 'Source IP blocked' }),
    { actionType: 'block_ip', status: 'successful', result: 'Source IP blocked' },
  );
  assert.deepEqual(
    geolocationPolicyResponse({ containmentStatus: 'block_failed', rawEvent: { raw: { ipBlockRequested: true, ipBlockError: 'firewall unavailable' } } }),
    { actionType: 'block_ip', status: 'failed', result: 'firewall unavailable' },
  );
  assert.equal(geolocationPolicyResponse({ containmentStatus: 'none', rawEvent: {} }), null);
});

test('auto-lock accepts one verified local user and rejects unsafe identities', () => {
  const base = { inputUserVerified: true, inputSessionCount: 1 };
  assert.equal(safeInteractiveUsername({ ...base, username: 'alice' }), true);
  assert.equal(safeInteractiveUsername({ ...base, username: 'SYSTEM' }), false);
  assert.equal(safeInteractiveUsername({ ...base, username: 'root' }), false);
  assert.equal(safeInteractiveUsername({ ...base, username: 'DOMAIN\\alice' }), false);
  assert.equal(safeInteractiveUsername({ ...base, username: 'alice@example.com' }), false);
  assert.equal(safeInteractiveUsername({ ...base, username: 'alice', inputSessionCount: 2 }), false);
  assert.equal(safeInteractiveUsername({ ...base, username: 'alice', inputUserVerified: false }), false);
});

test('endpoint response statuses map to lock workflow status', () => {
  assert.equal(responseEventStatus({ status: 'sent_to_agent' }, 'lock'), 'lock_pending');
  assert.equal(responseEventStatus({ status: 'successful' }, 'lock'), 'locked');
  assert.equal(responseEventStatus({ status: 'failed' }, 'lock'), 'lock_failed');
  assert.equal(responseEventStatus({ status: 'successful' }, 'unlock'), 'unlocked');
});
