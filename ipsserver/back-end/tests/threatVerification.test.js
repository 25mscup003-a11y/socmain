const { EventEmitter } = require('events');
const http = require('http');
const { verifyAutomaticBlock } = require('../src/services/threatVerificationService');

const input = { ip: '45.77.1.23', company: '507f1f77bcf86cd799439011' };
const oldSecret = process.env.IPS_WEBHOOK_SECRET;
const oldUrl = process.env.SOC_BACKEND_URL;
beforeEach(() => {
  process.env.IPS_WEBHOOK_SECRET = 'unit-test-secret';
  process.env.SOC_BACKEND_URL = 'http://soc.example.test:5000';
});
afterEach(() => {
  jest.restoreAllMocks();
  if (oldSecret === undefined) delete process.env.IPS_WEBHOOK_SECRET;
  else process.env.IPS_WEBHOOK_SECRET = oldSecret;
  if (oldUrl === undefined) delete process.env.SOC_BACKEND_URL;
  else process.env.SOC_BACKEND_URL = oldUrl;
});

function approval(patch = {}) {
  return { allowed: true, verification: { version: 2, policy: 'two-of-four', ip: input.ip,
    companyId: input.company, action: 'block_ip', matchedProviders: ['abuseipdb', 'otx'],
    checkedAt: new Date(Date.now() - 1000).toISOString(), expiresAt: new Date(Date.now() + 29000).toISOString(),
    ...patch } };
}

function reply(result, statusCode = 200) {
  return jest.spyOn(http, 'request').mockImplementation((url, options, callback) => {
    expect(url.pathname).toBe('/api/ips/verify-automatic');
    expect(options.headers['X-Company-ID']).toBe(input.company);
    expect(options.headers['X-Webhook-Secret']).toBe('unit-test-secret');
    const request = new EventEmitter();
    request.setTimeout = jest.fn();
    request.destroy = error => request.emit('error', error);
    request.end = body => {
      expect(JSON.parse(body)).toEqual({ ip: input.ip });
      const response = new EventEmitter();
      response.statusCode = statusCode;
      callback(response);
      response.emit('data', JSON.stringify(result));
      response.emit('end');
    };
    return request;
  });
}

test.each([
  ['abuseipdb', 'otx'], ['virustotal', 'otx'], ['abuseipdb', 'virustotal'],
])('backend approval accepts two distinct providers: %s and %s', async (first, second) => {
  reply(approval({ matchedProviders: [first, second] }));
  expect((await verifyAutomaticBlock(input)).allowed).toBe(true);
});

test.each([
  { version: 1 }, { policy: 'all-seven' }, { companyId: 'foreign' }, { action: 'isolate' },
  { ip: '45.77.1.24' }, { matchedProviders: ['abuseipdb'] },
  { matchedProviders: ['otx', 'otx'] }, { matchedProviders: ['otx', 'feodo'] },
  { matchedProviders: 'otx,abuseipdb' }, { expiresAt: new Date(0).toISOString() },
  { checkedAt: new Date(Date.now() + 600000).toISOString() },
])('rejects malformed, expired or mismatched quorum approval %j', async patch => {
  reply(approval(patch));
  expect((await verifyAutomaticBlock(input)).allowed).toBe(false);
});

test('an explicit denial or HTTP failure cannot authorize a block', async () => {
  const request = reply({ ...approval(), allowed: false });
  expect((await verifyAutomaticBlock(input)).allowed).toBe(false);
  request.mockRestore();
  reply(approval(), 503);
  expect((await verifyAutomaticBlock(input)).allowed).toBe(false);
});

test('timeout destroys the request with an error and settles denial', async () => {
  jest.spyOn(http, 'request').mockImplementation(() => {
    const request = new EventEmitter();
    let timeout;
    request.setTimeout = (ms, callback) => { timeout = callback; };
    request.destroy = error => { expect(error).toBeInstanceOf(Error); request.emit('error', error); };
    request.end = () => timeout();
    return request;
  });
  expect((await verifyAutomaticBlock(input)).allowed).toBe(false);
});
