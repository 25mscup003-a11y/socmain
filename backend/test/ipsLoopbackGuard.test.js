const test = require('node:test');
const assert = require('node:assert/strict');
const { normalizeIP, isPrivateIP, isLoopbackIP } = require('../src/services/ips.service');

test('IPS normalizes IPv4-mapped IPv6 loopback before evaluating block eligibility', () => {
  assert.equal(normalizeIP('::ffff:127.0.0.1'), '127.0.0.1');
  assert.equal(isPrivateIP('::ffff:127.0.0.1'), true);
  assert.equal(isLoopbackIP('::ffff:127.0.0.1'), true);
});

test('IPS preserves public IPv4 addresses represented as IPv4-mapped IPv6', () => {
  assert.equal(normalizeIP('::ffff:8.8.8.8'), '8.8.8.8');
  assert.equal(isPrivateIP('::ffff:8.8.8.8'), false);
});