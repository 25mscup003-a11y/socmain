/**
 * Webhook API Tests
 * Tests for the webhook endpoints
 */

const http = require('http');
process.env.IPS_FIREWALL_MODE = 'log-only';
const { createServer } = require('../src/app');

describe('Webhook API', () => {
  let server;
  let port;
  const company_id = '507f1f77bcf86cd799439011';

  beforeAll(async () => {
    server = createServer();
    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    port = server.address().port;
  });

  afterAll(async () => {
    await new Promise(resolve => server.close(resolve));
  });

  const makeRequest = (method, path, body = null, headers = {}) => {
    return new Promise((resolve, reject) => {
      const options = {
        hostname: '127.0.0.1',
        port,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          'X-Company-ID': company_id,
          ...headers,
        },
      };

      const req = http.request(options, (res) => {
        let data = '';
        res.on('data', chunk => { data += chunk; });
        res.on('end', () => {
          resolve({
            status: res.statusCode,
            body: data ? JSON.parse(data) : null,
          });
        });
      });

      req.on('error', reject);

      if (body) {
        req.write(JSON.stringify(body));
      }
      req.end();
    });
  };

  test('GET / should return status', async () => {
    const res = await makeRequest('GET', '/');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.status).toBe('running');
  });

  test('GET /health should return health check', async () => {
    const res = await makeRequest('GET', '/health');
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
  });

  test('POST /webhook should block IP', async () => {
    const res = await makeRequest('POST', '/webhook', {
      action: 'block',
      company_id,
      ip: '192.168.1.100',
      reason: 'Test blocking',
    });
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.action).toBe('block');
    expect(res.body.ip).toBe('192.168.1.100');
  });

  test('POST /webhook should unblock IP', async () => {
    // First block
    await makeRequest('POST', '/webhook', {
      action: 'block',
      company_id,
      ip: '192.168.1.101',
      reason: 'Test',
    });

    // Then unblock
    const res = await makeRequest('POST', '/webhook', {
      action: 'unblock',
      company_id,
      ip: '192.168.1.101',
    });
    
    expect(res.status).toBe(200);
    expect(res.body.ok).toBe(true);
    expect(res.body.action).toBe('unblock');
    expect(res.body.enforced).toBe(false);
    expect(res.body.method).toBe('log-only');
  });

  test('POST /webhook should validate required fields', async () => {
    const res = await makeRequest('POST', '/webhook', {
      action: 'block',
      company_id,
      // missing 'ip' field
    });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('POST /webhook should validate action', async () => {
    const res = await makeRequest('POST', '/webhook', {
      action: 'invalid',
      company_id,
      ip: '192.168.1.100',
    });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('POST /webhook should reject invalid IP', async () => {
    const res = await makeRequest('POST', '/webhook', {
      action: 'block',
      company_id,
      ip: 'invalid-ip',
    });
    expect(res.status).toBe(400);
    expect(res.body.ok).toBe(false);
  });

  test('404 for unknown routes', async () => {
    const res = await makeRequest('GET', '/unknown');
    expect(res.status).toBe(404);
    expect(res.body.ok).toBe(false);
  });
});
