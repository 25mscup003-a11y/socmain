const { lookupIpInfo, normalizeIp, isPrivateIp } = require('./ipinfo.service');

// Caching in memory
const _cache = new Map();
const CACHE_TTL = 30 * 60 * 1000; // 30 minutes cache for IPinfo
const FAILURE_CACHE_TTL = 5 * 60 * 1000;
const DEBUG_IP_ENRICHMENT = process.env.DEBUG_IP_ENRICHMENT === 'true';
const providerState = {
  ipApi: { unavailableUntil: 0, lastWarningAt: 0 },
  proxycheck: { unavailableUntil: 0, lastWarningAt: 0 },
};

function markProviderUnavailable(provider, message) {
  const state = providerState[provider];
  state.unavailableUntil = Date.now() + FAILURE_CACHE_TTL;
  if (Date.now() - state.lastWarningAt >= FAILURE_CACHE_TTL) {
    if (DEBUG_IP_ENRICHMENT) {
      console.warn(`[IP Enrichment] ${provider} temporarily unavailable (${message}); suppressing retries for 5 minutes`);
    }
    state.lastWarningAt = Date.now();
  }
}

/**
 * Fetch enrichment data from IPinfo Lite API
 * @param {string} ip
 * @returns {Promise<object>}
 */
async function enrichIp(ip) {
  ip = normalizeIp(ip);

  if (isPrivateIp(ip)) {
    return {
      ip,
      countrySource: 'local',
      countryLookupStatus: 'not_public',
      country: 'Non-public address',
      countryCode: 'LAN',
      continent: 'Local Network',
      continentCode: 'LAN',
      asn: 'Internal',
      organization: 'Private or reserved address',
      domain: 'local',
      city: 'Local',
      region: 'Local',
      postal: 'Local',
      timezone: 'Local',
      loc: 'Local',
      anycast: false,
      hostname: 'local',
      privacy: { vpn: false, proxy: false, tor: false, relay: false, hosting: false },
      abuse: null,
      domainsCount: 0,
      asnRoute: ''
    };
  }

  const cachedResult = _cache.get(ip);
  if (cachedResult && Date.now() < cachedResult.expires) {
    return cachedResult.data;
  }

  const fetchIpApi = async (targetIp) => {
    if (Date.now() < providerState.ipApi.unavailableUntil) return null;
    try {
      const response = await fetch(`http://ip-api.com/json/${targetIp}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,reverse`, {
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) return null;
      const data = await response.json();
      if (data && data.status === 'success') {
        return data;
      }
    } catch (err) {
      markProviderUnavailable('ipApi', err.name === 'TimeoutError' ? 'timeout' : err.message);
    }
    return null;
  };

  const fetchProxyCheck = async (targetIp) => {
    if (Date.now() < providerState.proxycheck.unavailableUntil) return null;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1500);
      const response = await fetch(`https://proxycheck.io/v2/${targetIp}?vpn=1&asn=1`, { signal: controller.signal });
      clearTimeout(timeout);
      if (!response.ok) return null;
      const data = await response.json();
      if (data && data.status === 'ok' && data[targetIp]) {
        return data[targetIp];
      }
    } catch (err) {
      markProviderUnavailable('proxycheck', err.name === 'AbortError' ? 'timeout' : err.message);
    }
    return null;
  };

  try {
    const result = { ...await lookupIpInfo(ip) };

    // If city, region, timezone, or coordinates are missing (common with IPinfo Lite), complement them via ip-api.com
    if (!result.city || !result.region || !result.loc || !result.timezone) {
      try {
        const geo = await fetchIpApi(ip);
        if (geo) {
          if (!result.city) result.city = geo.city || '';
          if (!result.region) result.region = geo.regionName || '';
          if (!result.postal) result.postal = geo.zip || '';
          if (!result.timezone) result.timezone = geo.timezone || '';
          if (!result.loc && Number.isFinite(geo.lat) && Number.isFinite(geo.lon)) result.loc = `${geo.lat},${geo.lon}`;
          if (!result.hostname) result.hostname = geo.reverse || '';
          if (!result.organization) result.organization = geo.org || geo.isp || '';
          if (!result.asn && geo.as) {
            const match = geo.as.match(/^AS(\d+)/);
            if (match) result.asn = `AS${match[1]}`;
          }
        }
      } catch (err) {
        console.warn(`[IPinfo-Lite Supplement] Fallback supplement failed for ${ip}:`, err.message);
      }
    }

    // If privacy is missing/empty, complement it via proxycheck.io
    if (!result.privacy || Object.values(result.privacy).every(v => v === false || v === null)) {
      try {
        const pc = await fetchProxyCheck(ip);
        if (pc) {
          result.privacy = {
            vpn: pc.type === 'vpn',
            proxy: pc.proxy === 'yes' && pc.type !== 'vpn',
            tor: pc.type === 'tor',
            relay: pc.type === 'relay',
            hosting: pc.type === 'hosting'
          };
          if (!result.asn && pc.asn) {
            const match = pc.asn.match(/^AS(\d+)/);
            if (match) result.asn = `AS${match[1]}`;
          }
          if (!result.organization && pc.provider) {
            result.organization = pc.provider;
          }
        }
      } catch (err) {
        console.warn(`[IPinfo-Lite Privacy Supplement] Failed for ${ip}:`, err.message);
      }
    }

    // Fallback hostname resolution
    if (!result.hostname) {
      const resolver = new (require('dns').promises.Resolver)({ timeout: 1500, tries: 1 });
      const timer = setTimeout(() => resolver.cancel(), 2000);
      try {
        const hostnames = await resolver.reverse(ip);
        if (hostnames && hostnames.length > 0) {
          result.hostname = hostnames[0];
        }
      } catch (e) {} finally { clearTimeout(timer); }
    }

    _cache.set(ip, {
      data: result,
      expires: Date.now() + CACHE_TTL
    });

    return result;
  } catch (error) {
    // Attempt complete lookup using ip-api.com as primary fallback if IPinfo fails
    try {
      const geo = await fetchIpApi(ip);
      if (geo) {
        const result = {
          ip,
          countrySource: 'ip-api',
          countryLookupStatus: 'resolved',
          countryCheckedAt: new Date().toISOString(),
          country: geo.country || '',
          countryCode: geo.countryCode || '',
          continent: '',
          continentCode: '',
          asn: '',
          organization: geo.org || geo.isp || '',
          domain: '',
          city: geo.city || '',
          region: geo.regionName || '',
          postal: geo.zip || '',
          timezone: geo.timezone || '',
          loc: (Number.isFinite(geo.lat) && Number.isFinite(geo.lon)) ? `${geo.lat},${geo.lon}` : '',
          anycast: null,
          hostname: geo.reverse || '',
          privacy: null,
          abuse: null,
          domainsCount: null,
          asnRoute: ''
        };
        if (geo.as) {
          const match = geo.as.match(/^AS(\d+)/);
          if (match) result.asn = `AS${match[1]}`;
        }

        // Fetch privacy details via proxycheck
        try {
          const pc = await fetchProxyCheck(ip);
          if (pc) {
            result.privacy = {
              vpn: pc.type === 'vpn',
              proxy: pc.proxy === 'yes' && pc.type !== 'vpn',
              tor: pc.type === 'tor',
              relay: pc.type === 'relay',
              hosting: pc.type === 'hosting'
            };
            if (!result.asn && pc.asn) {
              const match = pc.asn.match(/^AS(\d+)/);
              if (match) result.asn = `AS${match[1]}`;
            }
            if (!result.organization && pc.provider) {
              result.organization = pc.provider;
            }
          }
        } catch (err) {
          console.warn(`[IPinfo-Lite Fallback Privacy Supplement] Failed for ${ip}:`, err.message);
        }

        _cache.set(ip, {
          data: result,
          expires: Date.now() + CACHE_TTL
        });
        return result;
      }
    } catch (fallbackErr) {
      markProviderUnavailable('ipApi', fallbackErr.message);
    }

    // Return a graceful fallback instead of failing completely if both fail
    const unavailableResult = {
      ip,
      countrySource: null,
      countryLookupStatus: 'unavailable',
      country: '',
      countryCode: '',
      continent: '',
      continentCode: '',
      asn: '',
      organization: '',
      domain: '',
      city: '',
      region: '',
      postal: '',
      timezone: '',
      loc: '',
      anycast: false,
      hostname: '',
      privacy: null,
      abuse: null,
      domainsCount: 0,
      asnRoute: '',
      error: error.message
    };
    _cache.set(ip, { data: unavailableResult, expires: Date.now() + FAILURE_CACHE_TTL });
    return unavailableResult;
  }
}

/**
 * Check if the IP organization or domain is trusted/whitelisted
 * @param {object} ipinfoData
 * @returns {boolean}
 */
function isWhitelisted(ipinfoData) {
  if (!ipinfoData) return false;

  const org = String(ipinfoData.organization || '').toLowerCase();
  const dom = String(ipinfoData.domain || '').toLowerCase();

  // Trusted patterns for cloud providers, CDNs, major search engines, and critical services
  const trustedOrgs = [
    'google', 'cloudflare', 'amazon', 'aws', 'microsoft', 'akamai',
    'ip-api', 'github', 'facebook', 'twitter', 'linkedin', 'adnxs',
    'fastly', 'edgecast', 'limelight', 'level3', 'safaricom', 'verizon',
    'comcast', 'att', 'charter', 'deutsche telekom', 'orange', 'bt',
    'telefónica', 'sprint', 't-mobile', 'apple', 'oracle', 'digitalocean',
    'linode', 'ovh', 'leaseweb', 'hetzner', 'godaddy', 'cloudflare, inc.'
  ];

  const trustedDomains = [
    'google.com', 'cloudflare.com', 'amazon.com', 'amazonaws.com',
    'microsoft.com', 'akamai.net', 'ip-api.com', 'github.com',
    'fastly.net', 'facebook.com', 'twitter.com', 'linkedin.com',
    'apple.com', 'digitalocean.com', 'oracle.com', 'office.com',
    'live.com', 'bing.com', 'yahoo.com', 'msn.com', 'githubusercontent.com'
  ];

  const orgMatches = trustedOrgs.some(t => org.includes(t));
  const domMatches = trustedDomains.some(t => dom.includes(t) || dom.endsWith('.' + t));

  return orgMatches || domMatches;
}

module.exports = {
  enrichIp,
  isWhitelisted
};
