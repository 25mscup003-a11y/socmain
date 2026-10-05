const net = require('node:net');
const config = require('../config/ipinfo');
const countries = new Map(require('../constants/countries.json').map(country => [country.code, country.name]));

// Non-public addresses have no meaningful Internet country. BlockList also
// handles expanded IPv6 spellings and IPv4-mapped addresses consistently.
const nonPublic = new net.BlockList();
for (const cidr of [
  '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8',
  '169.254.0.0/16', '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24',
  '192.168.0.0/16', '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24',
  '224.0.0.0/4', '240.0.0.0/4',
  '::/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
  '2001::/32', '2001:2::/48', '2001:db8::/32', '2002::/16',
  '3fff::/20', 'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8',
]) {
  const [address, prefix] = cidr.split('/');
  nonPublic.addSubnet(address, Number(prefix), net.isIP(address) === 6 ? 'ipv6' : 'ipv4');
}

function normalizeIp(value) {
  if (typeof value !== 'string' || value.includes('%') || !net.isIP(value.trim())) {
    throw Object.assign(new Error('Enter a valid IPv4 or IPv6 address'), { status: 400 });
  }
  const ip = value.trim();
  if (net.isIP(ip) === 4) return ip;
  const canonical = new URL(`http://[${ip}]/`).hostname.slice(1, -1);
  const mapped = canonical.match(/^::ffff:([a-f\d]+):([a-f\d]+)$/);
  if (!mapped) return canonical;
  const high = parseInt(mapped[1], 16);
  const low = parseInt(mapped[2], 16);
  return [high >> 8, high & 255, low >> 8, low & 255].join('.');
}

function isPrivateIp(value) {
  try {
    const ip = normalizeIp(value);
    return nonPublic.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4');
  } catch { return true; }
}

const cache = new Map();
const inFlight = new Map();
const CACHE_TTL = 30 * 60 * 1000;
const MAX_CACHE_ENTRIES = 2000;
let retryAt = 0;
let providerError;

function unavailable(message, code = 'provider_unavailable') {
  return Object.assign(new Error(message), { code, status: 503 });
}

async function lookupIpInfo(value) {
  const ip = normalizeIp(value);
  if (isPrivateIp(ip)) throw unavailable('Private or reserved IPs have no public country', 'not_public');
  if (!config.token) throw unavailable('IPINFO_TOKEN is not configured on the backend', 'not_configured');
  const hit = cache.get(ip);
  if (hit?.expires > Date.now()) return hit.result;
  if (Date.now() < retryAt) throw providerError;
  if (inFlight.has(ip)) return inFlight.get(ip);

  const request = (async () => {
    let response;
    try {
      response = await fetch(`${config.endpoint}/${encodeURIComponent(ip)}`, {
        headers: { Authorization: `Bearer ${config.token}`, Accept: 'application/json' },
        signal: AbortSignal.timeout(5000),
        redirect: 'error',
      });
    } catch {
      // Never expose a fetch error's URL, headers or request config to clients.
      throw unavailable('IPinfo could not be reached; retry shortly');
    }
    if (!response.ok) {
      const messages = {
        401: 'IPinfo rejected the backend token',
        403: 'IPinfo denied access; check the backend token and plan',
        429: 'IPinfo request limit reached; retry shortly',
      };
      throw unavailable(messages[response.status] || `IPinfo returned HTTP ${response.status}`);
    }
    let data;
    try { data = await response.json(); } catch { throw unavailable('IPinfo returned an invalid response'); }
    const code = typeof data?.country_code === 'string' ? data.country_code.toUpperCase() : '';
    if (data?.bogon || !countries.has(code)) throw unavailable('IPinfo did not report a country for this IP', 'country_unavailable');
    if (data.ip && normalizeIp(data.ip) !== ip) throw unavailable('IPinfo returned a different IP address');
    const result = {
      ip, country: data.country || countries.get(code), countryCode: code,
      countrySource: 'ipinfo', countryLookupStatus: 'resolved', countryCheckedAt: new Date().toISOString(),
      continent: data.continent || '', continentCode: data.continent_code || '',
      asn: data.asn?.asn || data.asn || '', organization: data.company?.name || data.as_name || data.org || '',
      domain: data.company?.domain || data.as_domain || '',
      city: data.city || '', region: data.region || '', postal: data.postal || '',
      timezone: data.timezone || '', loc: data.loc || '', hostname: data.hostname || '',
      anycast: typeof data.anycast === 'boolean' ? data.anycast : null,
      privacy: data.privacy || null, abuse: data.abuse || null,
      domainsCount: data.domains?.total ?? null, asnRoute: data.asn?.route || '',
    };
    if (cache.size >= MAX_CACHE_ENTRIES) cache.delete(cache.keys().next().value);
    cache.set(ip, { result, expires: Date.now() + CACHE_TTL });
    return result;
  })();
  inFlight.set(ip, request);
  try { return await request; }
  catch (error) {
    if (error.code === 'provider_unavailable') {
      retryAt = Date.now() + 60 * 1000;
      providerError = error;
    }
    throw error;
  } finally { inFlight.delete(ip); }
}

module.exports = { lookupIpInfo, normalizeIp, isPrivateIp };
