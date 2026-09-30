const { createClient } = require('redis');

const local = new Map();
let client;

function cleanup(now) {
  for (const [key, expiresAt] of local.entries()) if (expiresAt <= now) local.delete(key);
}

async function getClient() {
  if (!process.env.REDIS_URL) return null;
  if (!client) {
    client = createClient({ url: process.env.REDIS_URL });
    client.on('error', error => console.error(JSON.stringify({ level: 'error', event: 'redis_nonce_error', message: error.message })));
    await client.connect();
  }
  return client;
}

async function claimNonce(key, ttlMs, now = Date.now()) {
  const redis = await getClient();
  if (redis) return (await redis.set(`soc:agent-nonce:${key}`, '1', { NX: true, PX: ttlMs })) === 'OK';
  cleanup(now);
  if (local.has(key)) return false;
  local.set(key, now + ttlMs);
  return true;
}

async function closeNonceStore() {
  if (client) await client.quit().catch(() => {});
  client = null;
}

module.exports = { claimNonce, closeNonceStore };
