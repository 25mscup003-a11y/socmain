const net = require('node:net');
const dns = require('node:dns').promises;
const { domainToASCII } = require('node:url');
const ipinfo = require('./ipinfo.service');

const MAX_ADDRESSES = 16;
const invalidInput = () => Object.assign(new Error('Enter a public IP or domain name without a URL path or port'), { status: 400 });

function parseTarget(value) {
  if (typeof value !== 'string' || !value.trim() || value.length > 253) throw invalidInput();
  const target = value.trim();
  if (net.isIP(target)) return { type: 'ip', target: ipinfo.normalizeIp(target) };
  // Parse a DNS name only. The lookup never makes an HTTP request to this host.
  if (/[\s:/?#@\\%]/.test(target)) throw invalidInput();
  const domain = domainToASCII(target.replace(/\.$/, '').toLowerCase());
  if (!domain || domain.length > 253 || !/^(?:[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?\.)+[a-z](?:[a-z\d-]{0,61}[a-z\d])?$/.test(domain)) throw invalidInput();
  return { type: 'domain', target: domain };
}

async function lookupCountry(value) {
  const input = parseTarget(value);
  const dnsStatus = {};
  let records;
  if (input.type === 'ip') {
    records = [{ ip: input.target, family: net.isIP(input.target) }];
  } else {
    const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
    const timer = setTimeout(() => resolver.cancel(), 3000);
    try {
      const results = await Promise.allSettled([
        resolver.resolve4(input.target, { ttl: true }),
        resolver.resolve6(input.target, { ttl: true }),
      ]);
      records = [];
      for (let index = 0; index < results.length; index += 1) {
        const result = results[index];
        const type = index === 0 ? 'A' : 'AAAA';
        dnsStatus[type] = result.status === 'fulfilled' ? 'resolved'
          : ['ENODATA', 'ENOTFOUND'].includes(result.reason?.code) ? 'no_records' : 'unavailable';
        if (result.status === 'fulfilled') {
          records.push(...result.value.map(record => ({
            ip: ipinfo.normalizeIp(record.address), family: index === 0 ? 4 : 6, ttl: record.ttl,
          })));
        }
      }
    } finally { clearTimeout(timer); }
  }
  const unique = [...new Map(records.map(record => [record.ip, record])).values()];
  const addresses = [];
  for (let start = 0; start < Math.min(unique.length, MAX_ADDRESSES); start += 4) {
    addresses.push(...await Promise.all(unique.slice(start, Math.min(start + 4, MAX_ADDRESSES)).map(async record => {
      if (ipinfo.isPrivateIp(record.ip)) {
        return { ...record, status: 'not_public', source: null, message: 'Private or reserved address; no public country' };
      }
      try {
        const result = await ipinfo.lookupIpInfo(record.ip);
        return { ...record, status: 'resolved', source: 'IPinfo Lite',
          country: result.country, countryCode: result.countryCode,
          asn: result.asn, organization: result.organization, checkedAt: result.countryCheckedAt };
      } catch (error) {
        return { ...record, status: 'unavailable', source: null, message: error.status === 503 ? error.message : 'Country lookup unavailable' };
      }
    })));
  }
  const resolved = addresses.filter(address => address.status === 'resolved');
  const truncated = unique.length > MAX_ADDRESSES;
  const partial = truncated || Object.values(dnsStatus).includes('unavailable') || addresses.some(address => address.status !== 'resolved');
  return {
    ...input, checkedAt: new Date().toISOString(),
    basis: input.type === 'domain' ? 'DNS A/AAAA addresses → IPinfo Lite country' : 'IPinfo Lite country database',
    status: !resolved.length ? 'unavailable' : partial ? 'partial' : 'resolved',
    dnsStatus, resolvedAddressCount: unique.length, truncated, addresses,
    countries: [...new Set(resolved.map(address => address.countryCode))],
    ...(addresses.length ? {} : { message: Object.values(dnsStatus).includes('unavailable')
      ? 'DNS lookup is unavailable; retry shortly' : 'No A or AAAA records found for this domain' }),
  };
}

module.exports = { lookupCountry, parseTarget };
