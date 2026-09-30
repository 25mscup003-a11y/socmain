const { createClient } = require('redis');
const { createAdapter } = require('@socket.io/redis-adapter');

let pubClient;
let subClient;

function redisSocketEnabled() {
  return process.env.SOCKET_ADAPTER === 'redis';
}

async function configureSocketAdapter(io) {
  if (!redisSocketEnabled()) return { adapter: 'process' };
  const url = process.env.SOCKET_REDIS_URL || process.env.REDIS_URL;
  if (!url) throw new Error('SOCKET_REDIS_URL or REDIS_URL is required for the Redis socket adapter');
  pubClient = createClient({ url });
  subClient = pubClient.duplicate();
  pubClient.on('error', error => console.error(JSON.stringify({ level: 'error', event: 'redis_socket_error', message: error.message })));
  subClient.on('error', error => console.error(JSON.stringify({ level: 'error', event: 'redis_socket_error', message: error.message })));
  await Promise.all([pubClient.connect(), subClient.connect()]);
  io.adapter(createAdapter(pubClient, subClient));
  return { adapter: 'redis' };
}

async function closeSocketAdapter() {
  await Promise.all([
    pubClient?.quit().catch(() => {}),
    subClient?.quit().catch(() => {}),
  ]);
  pubClient = null;
  subClient = null;
}

module.exports = { redisSocketEnabled, configureSocketAdapter, closeSocketAdapter };
