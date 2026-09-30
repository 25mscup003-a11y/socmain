const test = require('node:test');
const assert = require('node:assert/strict');

const { matchesAllowedIp, matchesAllowedDomain, _test } = require('../src/services/ips.service');

test('IPS whitelist matches exact IPv4 and CIDR ranges', () => {
  assert.equal(matchesAllowedIp('203.0.113.10', '203.0.113.10'), true);
  assert.equal(matchesAllowedIp('203.0.113.10', '203.0.113.0/24'), true);
  assert.equal(matchesAllowedIp('203.0.114.10', '203.0.113.0/24'), false);
  assert.equal(matchesAllowedIp('2001:db8::42', '2001:db8::/32'), true);
  assert.equal(matchesAllowedIp('2001:db9::42', '2001:db8::/32'), false);
});

test('IPS whitelist matches a domain and its subdomains only', () => {
  assert.equal(matchesAllowedDomain('api.trusted.example', 'trusted.example'), true);
  assert.equal(matchesAllowedDomain('https://trusted.example/path', '*.trusted.example'), true);
  assert.equal(matchesAllowedDomain('nottrusted.example', 'trusted.example'), false);
});

test('latest endpoint enforcement intent supersedes its queued inverse', () => {
  assert.equal(_test.inverseEndpointCommand('unblock_ip'), 'block_ip');
  assert.equal(_test.inverseEndpointCommand('block_domain'), 'unblock_domain');
  assert.equal(_test.inverseEndpointCommand('update'), '');
  assert.equal(_test.commandMatches(
    { command: 'block_ip', ip: '203.0.113.10', port: 443 },
    _test.inverseEndpointCommand('unblock_ip'),
    { ip: '203.0.113.10' },
  ), true);
  assert.equal(_test.commandMatches(
    { command: 'block_ip', ip: '203.0.113.11' },
    _test.inverseEndpointCommand('unblock_ip'),
    { ip: '203.0.113.10' },
  ), false);
});
