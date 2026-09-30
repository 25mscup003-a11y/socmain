'use strict';

const http = require('node:http');

const port = Number(process.env.AJNAT_MOCK_PORT || 18787);
const storageKey = Buffer.alloc(32, 7).toString('base64');

function json(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json',
    'cache-control': 'no-store',
  });
  response.end(JSON.stringify(body));
}

const server = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', chunk => chunks.push(chunk));
  request.on('end', () => {
    const pathname = new URL(request.url, `http://127.0.0.1:${port}`).pathname;
    if (request.method === 'GET' && pathname === '/health') {
      return json(response, 200, { ok: true });
    }
    if (request.method === 'POST' && pathname === '/api/agent/storage-key') {
      return json(response, 200, {
        algorithm: 'AES-256-GCM',
        purpose: 'durable-spool-v1',
        key: storageKey,
      });
    }
    if (request.method === 'POST' && pathname === '/api/system/heartbeat') {
      return json(response, 200, {
        systemId: 'windows-live-test',
        status: 'active',
        intervalSeconds: 30,
        commands: [],
      });
    }
    if (request.method === 'POST' && (pathname === '/api/alerts' || pathname === '/api/alerts/batch')) {
      return json(response, 201, { accepted: true });
    }
    return json(response, 404, { message: 'mock route not configured' });
  });
});

server.listen(port, '127.0.0.1', () => {
  process.stdout.write(`AJNAT Windows installer mock listening on ${port}\n`);
});

function shutdown() {
  server.close(() => process.exit(0));
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
