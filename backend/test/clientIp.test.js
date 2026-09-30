const test = require('node:test');
const assert = require('node:assert/strict');
const { getClientIp, normalizeIpAddress } = require('../src/utils/clientIp');

test('normalizes local and IPv4-mapped addresses', () => {
  assert.equal(normalizeIpAddress('::1'), '127.0.0.1');
  assert.equal(normalizeIpAddress('::ffff:192.168.1.20'), '192.168.1.20');
  assert.equal(normalizeIpAddress('10.1.2.3, 127.0.0.1'), '10.1.2.3');
});

test('uses forwarded client IP only behind a local proxy', () => {
  assert.equal(getClientIp({
    ip: '::1', socket: { remoteAddress: '::1' },
    headers: { 'x-forwarded-for': '192.168.1.44, 127.0.0.1' },
  }), '192.168.1.44');

  assert.equal(getClientIp({
    ip: '203.0.113.7', socket: { remoteAddress: '203.0.113.7' },
    headers: { 'x-forwarded-for': '198.51.100.9' },
  }), '203.0.113.7');
});
