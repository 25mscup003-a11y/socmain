const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('node:dns').promises;
const config = require('../src/config/ipinfo');

function freshIpinfo(t) {
  const previous = config.token;
  config.token = 'test-only-token';
  t.after(() => { config.token = previous; });
  delete require.cache[require.resolve('../src/services/ipinfo.service')];
  return require('../src/services/ipinfo.service');
}

function freshLookup() {
  delete require.cache[require.resolve('../src/services/countryLookup.service')];
  return require('../src/services/countryLookup.service');
}

const response = (data, status = 200) => ({ ok: status === 200, status, json: async () => data });
const countryData = (ip, code = 'IN') => ({ ip, country_code: code, country: code === 'IN' ? 'India' : 'United States', asn: 'AS64500', as_name: 'Example network' });

test('normalization excludes private/reserved addresses including expanded and mapped IPv6', t => {
  const service = freshIpinfo(t);
  for (const ip of ['10.1.2.3', '127.0.0.1', '100.64.0.1', '192.0.2.1', '198.18.0.1', '203.0.113.1',
    '0:0:0:0:0:0:0:1', '2001:0db8::1', 'fd00::1', 'fe80::1', '::ffff:192.168.1.1']) {
    assert.equal(service.isPrivateIp(ip), true, ip);
  }
  for (const ip of ['8.8.8.8', '2606:4700:4700::1111', '::ffff:808:808']) assert.equal(service.isPrivateIp(ip), false, ip);
  assert.equal(service.normalizeIp('::ffff:8.8.8.8'), '8.8.8.8');
  assert.equal(service.normalizeIp('2001:4860:4860:0000::8888'), '2001:4860:4860::8888');
  assert.throws(() => service.normalizeIp('fe80::1%eth0'), { status: 400 });
  assert.throws(() => service.normalizeIp('8.8.8.8/path'), { status: 400 });
});

test('IPinfo uses the backend token in a header and provider values replace formerly hardcoded IP data', async t => {
  const service = freshIpinfo(t);
  let calls = 0;
  t.mock.method(global, 'fetch', async (url, options) => {
    calls += 1;
    assert.equal(new URL(url).origin, 'https://api.ipinfo.io');
    assert.equal(new URL(url).search, '');
    assert.equal(options.headers.Authorization, 'Bearer test-only-token');
    assert.equal(options.redirect, 'error');
    return response(countryData(decodeURIComponent(new URL(url).pathname.split('/').pop())));
  });
  for (const ip of ['8.8.8.8', '8.8.4.4', '1.1.1.1', '208.95.112.1']) {
    const result = await service.lookupIpInfo(ip);
    assert.equal(result.countryCode, 'IN');
    assert.equal(result.countrySource, 'ipinfo');
    assert.equal(result.city, '');
    assert.equal(result.anycast, null);
    assert.equal(result.abuse, null);
    assert.equal(result.asnRoute, '');
    assert.equal(result.domainsCount, null);
    assert.ok(Number.isFinite(Date.parse(result.countryCheckedAt)));
  }
  assert.equal(calls, 4);
});

test('concurrent lookups share one request and cached checks retain observation time', async t => {
  const service = freshIpinfo(t);
  const fetch = t.mock.method(global, 'fetch', async () => response(countryData('8.8.8.8')));
  const [first, second] = await Promise.all([service.lookupIpInfo('8.8.8.8'), service.lookupIpInfo('8.8.8.8')]);
  const cached = await service.lookupIpInfo('8.8.8.8');
  assert.equal(fetch.mock.callCount(), 1);
  assert.deepEqual(first, second);
  assert.equal(first.countryCheckedAt, cached.countryCheckedAt);
});

test('missing token and non-public addresses never reach an external provider', async t => {
  const service = freshIpinfo(t);
  const fetch = t.mock.method(global, 'fetch', () => { throw new Error('unexpected request'); });
  config.token = '';
  await assert.rejects(service.lookupIpInfo('8.8.8.8'), { code: 'not_configured' });
  await assert.rejects(service.lookupIpInfo('127.0.0.1'), { code: 'not_public' });
  assert.equal(fetch.mock.callCount(), 0);
});

test('provider failures remain unavailable without guessed countries or exposed request details', async t => {
  for (const status of [401, 403, 429, 500]) {
    await t.test(`HTTP ${status}`, async sub => {
      const service = freshIpinfo(sub);
      const fetch = sub.mock.method(global, 'fetch', async () => response({}, status));
      await assert.rejects(service.lookupIpInfo('8.8.8.8'), error => error.status === 503 && !error.message.includes(config.token));
      await assert.rejects(service.lookupIpInfo('1.1.1.1'), { status: 503 });
      assert.equal(fetch.mock.callCount(), 1);
    });
  }
  await t.test('network error', async sub => {
    const service = freshIpinfo(sub);
    sub.mock.method(global, 'fetch', async () => { throw new Error(`request included ${config.token}`); });
    await assert.rejects(service.lookupIpInfo('8.8.8.8'), error => !error.message.includes(config.token));
  });
  await t.test('missing country', async sub => {
    const service = freshIpinfo(sub);
    sub.mock.method(global, 'fetch', async () => response({ ip: '8.8.8.8', asn: 'AS15169' }));
    await assert.rejects(service.lookupIpInfo('8.8.8.8'), { code: 'country_unavailable' });
  });
});

test('domain parsing accepts IDNs but rejects URLs, credentials, ports and malformed IPs', t => {
  freshIpinfo(t);
  const { parseTarget } = freshLookup();
  assert.deepEqual(parseTarget(' EXAMPLE.COM. '), { target: 'example.com', type: 'domain' });
  assert.equal(parseTarget('bücher.de').target, 'xn--bcher-kva.de');
  for (const value of ['https://example.com', 'user@example.com', 'example.com:80', 'example.com/a',
    '1.2.3.999', 'localhost', 'bad..com', '-bad.com', 'example.com?x', 'fe80::1%eth0', {}, ['example.com']]) {
    assert.throws(() => parseTarget(value), { status: 400 });
  }
});

test('domain checks use all A/AAAA addresses and preserve different countries instead of using the suffix', async t => {
  const service = freshIpinfo(t);
  t.mock.method(dns.Resolver.prototype, 'resolve4', async (name, options) => {
    assert.equal(name, 'example.in'); assert.equal(options.ttl, true);
    return [{ address: '8.8.8.8', ttl: 60 }, { address: '10.0.0.1', ttl: 60 }];
  });
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => [{ address: '2606:4700:4700::1111', ttl: 120 }]);
  const lookup = t.mock.method(service, 'lookupIpInfo', async ip => ({
    ip, countryCode: ip === '8.8.8.8' ? 'US' : 'DE', country: ip === '8.8.8.8' ? 'United States' : 'Germany',
    countryCheckedAt: '2026-10-05T00:00:00Z',
  }));
  const result = await freshLookup().lookupCountry('example.in');
  assert.equal(result.status, 'partial');
  assert.equal(result.addresses.length, 3);
  assert.deepEqual(result.countries, ['US', 'DE']);
  assert.equal(result.addresses[1].status, 'not_public');
  assert.equal(result.addresses[2].family, 6);
  assert.equal(result.addresses[2].ttl, 120);
  assert.equal(lookup.mock.callCount(), 2);
});

test('DNS timeouts produce partial results, while missing AAAA alone is normal', async t => {
  const service = freshIpinfo(t);
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => [{ address: '8.8.8.8', ttl: 60 }]);
  let code = 'ETIMEOUT';
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => { throw Object.assign(new Error('dns'), { code }); });
  t.mock.method(service, 'lookupIpInfo', async ip => ({ ip, country: 'United States', countryCode: 'US' }));
  const { lookupCountry } = freshLookup();
  assert.equal((await lookupCountry('example.com')).status, 'partial');
  code = 'ENODATA';
  assert.equal((await lookupCountry('example.com')).status, 'resolved');
});

test('large DNS responses are bounded, deduplicated and explicitly marked incomplete', async t => {
  const service = freshIpinfo(t);
  const records = Array.from({ length: 20 }, (_, i) => ({ address: `8.8.8.${i + 1}`, ttl: 60 }));
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => [...records, ...records]);
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => []);
  const lookup = t.mock.method(service, 'lookupIpInfo', async ip => ({ ip, country: 'United States', countryCode: 'US' }));
  const result = await freshLookup().lookupCountry('example.com');
  assert.equal(result.resolvedAddressCount, 20);
  assert.equal(result.addresses.length, 16);
  assert.equal(result.truncated, true);
  assert.equal(result.status, 'partial');
  assert.equal(lookup.mock.callCount(), 16);
});

test('country checker exposes provider failure and no-DNS results without substituting country guesses', async t => {
  const service = freshIpinfo(t);
  t.mock.method(service, 'lookupIpInfo', async () => { throw Object.assign(new Error('IPinfo denied access'), { status: 503 }); });
  const { lookupCountry } = freshLookup();
  const ip = await lookupCountry('8.8.8.8');
  assert.equal(ip.status, 'unavailable');
  assert.deepEqual(ip.countries, []);
  assert.equal(ip.addresses[0].source, null);
  t.mock.method(dns.Resolver.prototype, 'resolve4', async () => { throw Object.assign(new Error('dns'), { code: 'ENOTFOUND' }); });
  t.mock.method(dns.Resolver.prototype, 'resolve6', async () => { throw Object.assign(new Error('dns'), { code: 'ENOTFOUND' }); });
  const domain = await lookupCountry('example.com');
  assert.equal(domain.status, 'unavailable');
  assert.equal(domain.addresses.length, 0);
  assert.match(domain.message, /No A or AAAA/);
});

test('existing enrichment uses IPinfo country and labels an ip-api fallback truthfully', async t => {
  freshIpinfo(t);
  delete require.cache[require.resolve('../src/services/ipEnrichmentService')];
  const { enrichIp } = require('../src/services/ipEnrichmentService');
  t.mock.method(dns.Resolver.prototype, 'reverse', async () => []);
  t.mock.method(global, 'fetch', async url => {
    const parsed = new URL(url);
    if (parsed.hostname === 'api.ipinfo.io') {
      return parsed.pathname.endsWith('/8.8.8.8') ? response(countryData('8.8.8.8')) : response({}, 401);
    }
    if (parsed.hostname === 'ip-api.com') return response({ status: 'success', country: 'Germany', countryCode: 'DE', lat: 0, lon: 0, city: 'Example city' });
    return response({}, 500);
  });
  const primary = await enrichIp('8.8.8.8');
  assert.equal(primary.countryCode, 'IN');
  assert.equal(primary.countrySource, 'ipinfo');
  assert.equal(primary.city, 'Example city');
  assert.equal(primary.loc, '0,0');
  const fallback = await enrichIp('1.1.1.1');
  assert.equal(fallback.countryCode, 'DE');
  assert.equal(fallback.countrySource, 'ip-api');
  assert.equal(fallback.abuse, null);
  assert.equal(fallback.asnRoute, '');
});
