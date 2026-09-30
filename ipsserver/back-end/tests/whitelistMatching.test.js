const { _test } = require('../src/services/mongoService');

describe('whitelist matching', () => {
  test('matches exact IP and IPv4 CIDR', () => {
    expect(_test.whitelistEntryMatches('203.0.113.9', { type: 'ip', value: '203.0.113.9' })).toBe(true);
    expect(_test.whitelistEntryMatches('203.0.113.9', { type: 'cidr', value: '203.0.113.0/24' })).toBe(true);
    expect(_test.whitelistEntryMatches('203.0.114.9', { type: 'cidr', value: '203.0.113.0/24' })).toBe(false);
  });

  test('matches IPv6 CIDR', () => {
    expect(_test.whitelistEntryMatches('2001:db8::42', { type: 'cidr', value: '2001:db8::/32' })).toBe(true);
    expect(_test.whitelistEntryMatches('2001:db9::42', { type: 'cidr', value: '2001:db8::/32' })).toBe(false);
  });

  test('matches domains without allowing suffix confusion', () => {
    expect(_test.whitelistEntryMatches('api.trusted.example', { type: 'domain', value: 'trusted.example' })).toBe(true);
    expect(_test.whitelistEntryMatches('nottrusted.example', { type: 'domain', value: 'trusted.example' })).toBe(false);
  });
});
