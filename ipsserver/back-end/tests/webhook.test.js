/**
 * Webhook API Tests
 * Tests for the webhook endpoints
 */

const http = require('http');
process.env.IPS_FIREWALL_MODE = 'log-only';
process.env.IPS_WEBHOOK_SECRET = 'ips-test-secret';
const { createServer } = require('../src/app');

describe('Webhook API', () => {
  let server;
  let port;
  const company_id = '507f1f77bcf86cd799439011';

  beforeAll(async () => {
    server = createServer();
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(0, '127.0.0.1', resolve);
    });
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
          'X-Webhook-Secret': process.env.IPS_WEBHOOK_SECRET || '',
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

  test.each(['/status', '/blocklist', '/whitelist', '/logs', '/companies', '/audit-logs'])('protects GET %s', async path => {
    expect((await makeRequest('GET', path, null, { 'X-Webhook-Secret': '' })).status).toBe(401);
  });

  test.each(['/webhook', '/', '/whitelist', '/isolate', '/consent', '/waf/report'])('protects POST %s', async path => {
    expect((await makeRequest('POST', path, {}, { 'X-Webhook-Secret': 'wrong' })).status).toBe(401);
    expect((await makeRequest('POST', path, {}, { 'X-Company-ID': '' })).status).toBe(400);
  });

  test('health stays public and missing service credentials fail closed', async () => {
    const saved = process.env.IPS_WEBHOOK_SECRET;
    delete process.env.IPS_WEBHOOK_SECRET;
    try {
      expect((await makeRequest('GET', '/health')).status).toBe(200);
      expect((await makeRequest('GET', '/status')).status).toBe(503);
    } finally { process.env.IPS_WEBHOOK_SECRET = saved; }
  });

  test('forged JWT claims cannot replace the service credential or tenant context', async () => {
    const token = `e30.${Buffer.from(JSON.stringify({ companyId: company_id, role: 'superadmin' })).toString('base64url')}.fake`;
    expect((await makeRequest('GET', '/whitelist', null, { Authorization: `Bearer ${token}`, 'X-Webhook-Secret': '' })).status).toBe(401);
    expect((await makeRequest('POST', '/webhook', { action: 'block', ip: '203.0.113.1' }, { Authorization: `Bearer ${token}`, 'X-Company-ID': '' })).status).toBe(400);
  });

  test('repeated blocks preserve enforcement status and allow permanent TTL', async () => {
    const input = { action: 'block', ip: '203.0.113.20', ttlHours: 1 };
    await makeRequest('POST', '/webhook', input);
    const result = await makeRequest('POST', '/webhook', { ...input, ttlHours: 0 });
    expect(result.body).toMatchObject({ method: 'log-only', enforced: false, delegated: false, ttlHours: 0, expiresAt: null });
  });

  test('rawBlockKey unblocks precisely the selected port range', async () => {
    const block = await makeRequest('POST', '/webhook', { action: 'block', ip: '203.0.113.21', port: '80-90', protocol: 'tcp' });
    const result = await makeRequest('POST', '/webhook', { action: 'unblock', rawBlockKey: block.body.blockKey });
    expect(result.status).toBe(200);
    expect(result.body.blockKey).toBe(block.body.blockKey);
    const list = await makeRequest('GET', '/blocklist');
    expect(list.body.blocklist.some(entry => entry.blockKey === block.body.blockKey)).toBe(false);
  });

  test('memory-only whitelist persists within the process and is tenant scoped', async () => {
    expect((await makeRequest('POST', '/whitelist', { value: '203.0.113.30', type: 'IP' })).status).toBe(200);
    const blocked = await makeRequest('POST', '/webhook', { action: 'block', ip: '203.0.113.30' });
    expect(blocked.body).toMatchObject({ skipped: true, enforced: false });
    const other = await makeRequest('POST', '/webhook', { action: 'block', ip: '203.0.113.30' }, { 'X-Company-ID': '507f1f77bcf86cd799439012' });
    expect(other.body.skipped).not.toBe(true);
    expect((await makeRequest('DELETE', '/whitelist/203.0.113.30')).status).toBe(200);
  });

  test('invalid inputs return errors without crashing the server', async () => {
    for (const fields of [{ ip: '1:2:3' }, { port: 0 }, { port: '80x' }, { port: '90-80' }, { port: '1-65536' }, { direction: false }, { direction: 'sideways' }, { ttlHours: -1 }, { ttlHours: true }]) {
      expect((await makeRequest('POST', '/webhook', { action: 'block', ip: '203.0.113.40', ...fields })).status).toBe(400);
    }
    expect((await makeRequest('POST', '/analyze', { payload: 'x'.repeat(1024 * 1024) })).status).toBe(413);
    expect((await makeRequest('GET', '/health')).status).toBe(200);
  });

  test('standalone isolation cannot report success without an endpoint command', async () => {
    expect((await makeRequest('POST', '/isolate', { srcIp: '203.0.113.50' })).status).toBe(501);
    expect((await makeRequest('POST', '/unisolate', { srcIp: '203.0.113.50', consentId: 'anything' })).status).toBe(501);
  });
});
