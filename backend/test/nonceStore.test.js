const test = require('node:test');
const assert = require('node:assert/strict');
const { claimNonce } = require('../src/infrastructure/nonceStore');

test('local nonce fallback rejects replay and permits a key after expiry', async () => {
  const previous = process.env.REDIS_URL;
  delete process.env.REDIS_URL;
  const key = `test-${Date.now()}`;
  assert.equal(await claimNonce(key, 10, 100), true);
  assert.equal(await claimNonce(key, 10, 105), false);
  assert.equal(await claimNonce(key, 10, 111), true);
  if (previous !== undefined) process.env.REDIS_URL = previous;
});
