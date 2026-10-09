/**
 * threat-intel.service.js
 *
 * Unified Threat Intelligence enrichment for IDS/IPS pipeline.
 * Sources:
 *   1. AbuseIPDB    — IP reputation (confidence score, abuse reports)
 *   2. OTX AlienVault — IP + domain indicators (pulses, malware families)
 *   3. Feodo Tracker  — C2 botnet IPs (no key needed)
 *   4. Emerging Threats — compromised hosts (no key needed)
 *   5. Tor Exit Nodes   — Tor network IPs (no key needed)
 *
 * Integration:
 *   - Called by IDS alert pipeline → enriches srcip before saving
 *   - Called by IPS → auto-blocks IPs with confidence >= threshold
 *   - Exposes enrichIp(ip) and enrichDomain(domain) for any service
 */

const axios = require('axios');
const dns = require('dns');
const http = require('http');
const https = require('https');
const net = require('net');
const { normalizeThreatLabels } = require('../utils/threatIntelLabels');
const Alert = require('../models/Alert.model');

const ABUSEIPDB_KEY = process.env.ABUSEIPDB_KEY;
const OTX_KEY       = process.env.OTX_API_KEY;
const VT_KEY        = process.env.VIRUSTOTAL_API_KEY;

// Auto-block threshold: AbuseIPDB confidence >= this % → IPS blocks
const AUTO_BLOCK_THRESHOLD = 75;

// In-memory cache — avoid hammering APIs (TTL: 10 min)
const _cache = new Map(); // key → { data, expires }
const CACHE_TTL = 10 * 60 * 1000;
const NEGATIVE_CACHE_TTL = 5 * 60 * 1000;
let otxDomainUnavailableUntil = 0;
let otxDomainLastWarningAt = 0;
let abuseIpdbUnavailableUntil = 0;
let abuseIpdbLastWarningAt = 0;

function cached(key) {
  const e = _cache.get(key);
  if (e && Date.now() < e.expires) return e.data;
  return null;
}
function setCache(key, data) {
  _cache.set(key, { data, expires: Date.now() + CACHE_TTL });
}
function setNegativeCache(key, data = null) {
  _cache.set(key, { data, expires: Date.now() + NEGATIVE_CACHE_TTL });
}

function normalizeIp(value = '') {
  let ip = String(value || '').trim();
  if (!ip || ip === '-' || ip === '—' || /^unknown|null|undefined$/i.test(ip)) return '';
  const bracketed = ip.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (bracketed) ip = bracketed[1];
  else ip = ip.replace(/^\[|\]$/g, '');
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  if (ip.includes('/') && net.isIP(ip.split('/')[0])) ip = ip.split('/')[0];
  if (ip.includes(':') && ip.includes('.') && !net.isIP(ip)) {
    const maybe = ip.replace(/:\d+$/, '');
    if (net.isIP(maybe)) ip = maybe;
  }
  return ip;
}

function isReservedIp(value = '') {
  const ip = normalizeIp(value);
  const version = net.isIP(ip);
  if (!version) return true;

  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 10) return true;                         // Private IPv4 (RFC1918)
    if (a === 172 && b >= 16 && b <= 31) return true;  // Private IPv4 (RFC1918)
    if (a === 192 && b === 168) return true;           // Private IPv4 (RFC1918)
    if (a === 127) return true;                        // Loopback
    if (a === 169 && b === 254) return true;           // Link Local (APIPA)
    if (a === 100 && b >= 64 && b <= 127) return true; // Carrier Grade NAT (CGNAT)
    if (a >= 224 && a <= 239) return true;             // Multicast
    if (a >= 240 && a <= 255) return true;             // Reserved / Future Use / Broadcast
    if (a === 0) return true;                          // Unspecified
    return false;
  }

  // IPv6
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return true;  // Loopback / Unspecified
  if (lower.startsWith('fc') || lower.startsWith('fd')) return true; // Private IPv6 (ULA)

  // Link Local (fe80::/10)
  const firstHex = parseInt(lower.split(':')[0], 16);
  if (!isNaN(firstHex) && firstHex >= 0xfe80 && firstHex <= 0xfebf) return true;

  if (lower.startsWith('ff')) return true; // Multicast (ff00::/8)
  if (lower.startsWith('2001:db8:')) return true; // Documentation (2001:db8::/32)
  if (lower.startsWith('::ffff:')) return true; // IPv4-Mapped IPv6
  if (lower.startsWith('64:ff9b:')) return true; // NAT64
  if (lower.startsWith('2002:')) return true; // 6to4
  if (lower.startsWith('2001:0:') || lower.startsWith('2001:0000:')) return true; // Teredo

  return false;
}

function isTrustedCDN(value = '') {
  const ip = normalizeIp(value);
  const version = net.isIP(ip);
  if (version !== 4) return false;

  const parts = ip.split('.').map(Number);
  const [a, b] = parts;

  // ── Major CDN / Cloud providers — skip TI (false-positive block prevention)
  // Google LLC (172.217.x.x, 172.253.x.x, 142.250.x.x, 74.125.x.x, 108.177.x.x, 216.58.x.x, 216.239.x.x, 8.8.x.x)
  if (a === 172 && (b === 217 || b === 253)) return true; // 172.253.124.94 fix
  if (a === 142 && b === 250) return true;
  if (a === 74  && b === 125) return true;
  if (a === 108 && b === 177) return true;
  if (a === 216 && (b === 58 || b === 239))  return true;
  if (a === 8   && b === 8)    return true; // Google DNS (8.8.8.8, 8.8.4.4)

  // ip-api.com Geolocation API (208.95.112.x)
  if (a === 208 && b === 95 && parts[2] === 112) return true;

  // Cloudflare (104.16–104.31, 172.64–172.68, 1.1.1.1, 1.0.0.1)
  if (a === 104 && b >= 16 && b <= 31) return true;
  if (a === 172 && b >= 64 && b <= 68) return true;
  if (a === 1   && (b === 1 || b === 0)) return true;

  // Akamai CDN (23.32–23.223)
  if (a === 23 && b >= 32 && b <= 223) return true;

  return false;
}

function isPublicIp(value = '') {
  const ip = normalizeIp(value);
  if (isReservedIp(ip)) return false;
  if (isTrustedCDN(ip)) return false;
  return true;
}


function negativeOtxIpResult(ip, reason) {
  return {
    source: 'otx',
    ip,
    pulseCount: 0,
    malwareFamilies: [],
    tags: [],
    reputation: 0,
    isMalicious: false,
    skipped: true,
    skipReason: reason,
  };
}

/* ── 1. AbuseIPDB ─────────────────────────────────────────────────────────── */
async function queryAbuseIPDB(ip) {
  if (!ABUSEIPDB_KEY) return null;
  ip = normalizeIp(ip);
  if (!isPublicIp(ip)) return null;
  const cKey = `abuse:${ip}`;
  const hit   = cached(cKey);
  if (hit) return hit;
  if (Date.now() < abuseIpdbUnavailableUntil) return null;

  try {
    const r = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: { ipAddress: ip, maxAgeInDays: 30, verbose: true },
      headers: { Key: ABUSEIPDB_KEY, Accept: 'application/json' },
      timeout: 10000,
    });
    const d = r.data?.data || {};
    if (!Number.isFinite(d.abuseConfidenceScore) || d.abuseConfidenceScore < 0 || d.abuseConfidenceScore > 100) {
      throw new Error('invalid AbuseIPDB reputation response');
    }
    const result = {
      source:           'abuseipdb',
      ip,
      abuseScore:       d.abuseConfidenceScore || 0,
      totalReports:     d.totalReports || 0,
      countryCode:      d.countryCode || '',
      isp:              d.isp || '',
      domain:           d.domain || '',
      usageType:        d.usageType || '',
      lastReportedAt:   d.lastReportedAt || null,
      isWhitelisted:    d.isWhitelisted || false,
      isTorNode:        d.usageType === 'Tor Exit Node',
      isMalicious:      (d.abuseConfidenceScore || 0) >= AUTO_BLOCK_THRESHOLD,
      checkedAt:        new Date().toISOString(),
    };
    setCache(cKey, result);
    return result;
  } catch (e) {
    const status = e.response?.status;
    const transient = e.code === 'ECONNABORTED' || status === 429 || !status || status >= 500;
    if (transient) abuseIpdbUnavailableUntil = Date.now() + NEGATIVE_CACHE_TTL;
    setNegativeCache(cKey, {
      source: 'abuseipdb', ip, abuseScore: 0, totalReports: 0,
      isMalicious: false, skipped: true,
      skipReason: status === 429 ? 'rate_limited' : transient ? 'provider_unavailable' : `http_${status}`,
    });
    if (Date.now() - abuseIpdbLastWarningAt >= NEGATIVE_CACHE_TTL) {
      console.warn(`[ThreatIntel] AbuseIPDB temporarily unavailable (${status || e.code || 'network'}); suppressing retries for 5 minutes`);
      abuseIpdbLastWarningAt = Date.now();
    }
    return null;
  }
}

/* ── 2. OTX AlienVault ────────────────────────────────────────────────────── */
async function queryOTX_IP(ip) {
  if (!OTX_KEY) return null;
  ip = normalizeIp(ip);
  if (!isPublicIp(ip)) return null;
  const cKey = `otx:ip:${ip}`;
  const hit   = cached(cKey);
  if (hit) return hit;
  const version = net.isIP(ip);

  try {
    const indicatorType = version === 6 ? 'IPv6' : 'IPv4';
    const encodedIp = encodeURIComponent(ip);
    const r = await axios.get(`https://otx.alienvault.com/api/v1/indicators/${indicatorType}/${encodedIp}/general`, {
      headers: { 'X-OTX-API-KEY': OTX_KEY },
      timeout: 15000,  // OTX can be slow — increased timeout
    });
    const d = r.data || {};
    if (!Number.isInteger(d.pulse_info?.count) || d.pulse_info.count < 0) throw new Error('invalid OTX pulse response');
    const result = {
      source:          'otx',
      ip,
      pulseCount:      d.pulse_info?.count || 0,
      malwareFamilies: normalizeThreatLabels((d.pulse_info?.pulses || []).flatMap(p => p.malware_families || []), { limit: 5 }),
      tags:            normalizeThreatLabels((d.pulse_info?.pulses || []).flatMap(p => p.tags || []), { limit: 10 }),
      reputation:      d.reputation || 0,
      countryCode:     d.country_code || '',
      asn:             d.asn || '',
      isMalicious:     (d.pulse_info?.count || 0) > 0,
      checkedAt:       new Date().toISOString(),
    };
    setCache(cKey, result);
    return result;
  } catch (e) {
    const reason = e.code === 'ECONNABORTED' ? 'timeout (OTX slow)' : e.message;
    if (e.response?.status === 400) {
      console.warn('[ThreatIntel] OTX IP skipped:', `invalid indicator rejected (${ip})`);
      setNegativeCache(cKey, negativeOtxIpResult(ip, 'invalid_indicator'));
      return null;
    }
    if (e.code === 'ECONNABORTED') setNegativeCache(cKey, negativeOtxIpResult(ip, 'timeout'));
    console.warn('[ThreatIntel] OTX IP error:', reason);
    return null;  // graceful fallback — AbuseIPDB + public feeds still work
  }
}

async function queryOTX_Domain(domain) {
  if (!OTX_KEY) return null;
  domain = String(domain || '').trim().toLowerCase().replace(/\.$/, '');
  if (!/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(domain)) return null;
  const cKey = `otx:domain:${domain}`;
  const hit   = cached(cKey);
  if (hit) return hit;
  if (Date.now() < otxDomainUnavailableUntil) return null;

  try {
    const r = await axios.get(`https://otx.alienvault.com/api/v1/indicators/domain/${domain}/general`, {
      headers: { 'X-OTX-API-KEY': OTX_KEY },
      timeout: 5000,
    });
    const d = r.data || {};
    const result = {
      source:          'otx',
      domain,
      pulseCount:      d.pulse_info?.count || 0,
      malwareFamilies: normalizeThreatLabels((d.pulse_info?.pulses || []).flatMap(p => p.malware_families || []), { limit: 5 }),
      tags:            normalizeThreatLabels((d.pulse_info?.pulses || []).flatMap(p => p.tags || []), { limit: 10 }),
      isMalicious:     (d.pulse_info?.count || 0) > 0,
      alexa:           d.alexa || null,
    };
    setCache(cKey, result);
    return result;
  } catch (e) {
    const status = e.response?.status;
    const transient = e.code === 'ECONNABORTED' || !status || status === 429 || status >= 500;
    if (transient) otxDomainUnavailableUntil = Date.now() + NEGATIVE_CACHE_TTL;
    setNegativeCache(cKey, {
      source: 'otx', domain, pulseCount: 0, malwareFamilies: [], tags: [],
      isMalicious: false, skipped: true, skipReason: transient ? 'provider_unavailable' : `http_${status}`,
    });
    if (Date.now() - otxDomainLastWarningAt >= NEGATIVE_CACHE_TTL) {
      console.warn(`[ThreatIntel] OTX Domain temporarily unavailable (${status || e.code || 'network'}); suppressing retries for 5 minutes`);
      otxDomainLastWarningAt = Date.now();
    }
    return null;
  }
}

/* ── 3. Public Feeds (no key) ─────────────────────────────────────────────── */
let _feodoIps  = new Set();
let _etIps     = new Set();
let _torIps    = new Set();
let _feedsLoaded = false;
let _feedsLoading = false;
let _feedLoadPromise = null;
let _feedRefreshTimer = null;
let _feedFailureWarningAt = 0;
const FEED_FAILURE_WARNING_INTERVAL_MS = 30 * 60 * 1000;

const PUBLIC_FEEDS = Object.freeze([
  { name: 'feodo', url: process.env.THREAT_FEED_FEODO_URL || 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt' },
  { name: 'emergingThreats', url: process.env.THREAT_FEED_EMERGING_THREATS_URL || 'https://rules.emergingthreats.net/blockrules/compromised-ips.txt' },
  { name: 'tor', url: process.env.THREAT_FEED_TOR_URL || 'https://check.torproject.org/torbulkexitlist' },
]);
const _feedReady = { feodo: false, emergingThreats: false, tor: false };
const _feedCheckedAt = { feodo: null, emergingThreats: null, tor: null };
const _feedFailed = { feodo: false, emergingThreats: false, tor: false };

function isDnsFailure(error) {
  const root = error?.cause || error;
  return root?.code === 'EAI_AGAIN' || root?.code === 'ENOTFOUND';
}

function threatFeedDnsServers(value = process.env.THREAT_FEED_DNS_SERVERS) {
  const configured = value === undefined ? '1.1.1.1,8.8.8.8' : String(value);
  return configured
    .split(',')
    .map(server => server.trim())
    .filter(Boolean);
}

function createThreatFeedLookup(servers = threatFeedDnsServers()) {
  if (!servers.length) return null;
  const resolver = new dns.Resolver();
  try {
    resolver.setServers(servers);
  } catch (error) {
    console.warn(`[ThreatIntel] Ignoring invalid THREAT_FEED_DNS_SERVERS: ${error.message}`);
    return null;
  }

  return (hostname, options, callback) => {
    const lookupOptions = typeof options === 'object' && options !== null ? options : {};
    const family = Number(lookupOptions.family) === 6 ? 6 : 4;
    const resolve = family === 6 ? resolver.resolve6.bind(resolver) : resolver.resolve4.bind(resolver);
    resolve(hostname, (error, addresses) => {
      if (error) return callback(error);
      const results = (addresses || []).map(address => ({ address, family }));
      if (!results.length) {
        const noAddressError = Object.assign(new Error(`No DNS records found for ${hostname}`), { code: 'ENOTFOUND' });
        return callback(noAddressError);
      }
      return lookupOptions.all
        ? callback(null, results)
        : callback(null, results[0].address, results[0].family);
    });
  };
}

function threatFeedFallbackRequestConfig(timeout) {
  const lookup = createThreatFeedLookup();
  if (!lookup) return null;
  return {
    timeout,
    httpAgent: new http.Agent({ lookup }),
    httpsAgent: new https.Agent({ lookup }),
  };
}

function feedFailureDetails(reason) {
  const root = reason?.cause || reason;
  return {
    code: root?.code || '',
    message: reason?.message || root?.message || 'feed request failed',
  };
}

function boundedFeedNumber(value, fallback, min, max) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.min(max, Math.max(min, parsed)) : fallback;
}

function parsePublicFeed(data) {
  const ips = new Set();
  String(data || '').split(/\r?\n/).forEach(line => {
    const value = normalizeIp(line.trim());
    if (value && !line.trim().startsWith('#') && net.isIP(value)) ips.add(value);
  });
  return ips;
}

const wait = ms => new Promise(resolve => setTimeout(resolve, ms));

async function fetchPublicFeed(definition, {
  client = axios,
  timeoutMs = boundedFeedNumber(process.env.THREAT_FEED_TIMEOUT_MS, 15000, 1000, 60000),
  retries = boundedFeedNumber(process.env.THREAT_FEED_RETRIES, 2, 0, 5),
  retryDelayMs = boundedFeedNumber(process.env.THREAT_FEED_RETRY_DELAY_MS, 1000, 0, 30000),
  waitFn = wait,
} = {}) {
  let lastError;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      let response;
      try {
        response = await client.get(definition.url, { timeout: timeoutMs });
      } catch (error) {
        const fallbackConfig = isDnsFailure(error) && threatFeedFallbackRequestConfig(timeoutMs);
        if (!fallbackConfig) throw error;
        response = await client.get(definition.url, fallbackConfig);
      }
      const ips = parsePublicFeed(response.data);
      if (!ips.size) throw new Error('feed returned no valid IP addresses');
      return { name: definition.name, ips, attempts: attempt + 1 };
    } catch (error) {
      lastError = error;
      if (attempt < retries) await waitFn(retryDelayMs * (2 ** attempt));
    }
  }
  const failure = new Error(`${definition.name}: ${lastError?.message || 'feed request failed'}`);
  failure.cause = lastError;
  throw failure;
}

function replacePublicFeed(name, ips) {
  if (name === 'feodo') _feodoIps = ips;
  if (name === 'emergingThreats') _etIps = ips;
  if (name === 'tor') _torIps = ips;
  _feedReady[name] = true;
  _feedCheckedAt[name] = new Date().toISOString();
  _feedFailed[name] = false;
}

function schedulePublicFeedRefresh(delayMs) {
  if (_feedRefreshTimer) clearTimeout(_feedRefreshTimer);
  _feedRefreshTimer = setTimeout(() => loadPublicFeeds().catch(() => {}), delayMs);
  _feedRefreshTimer.unref?.();
}

function loadPublicFeeds(options = {}) {
  if (_feedLoadPromise) return _feedLoadPromise;
  _feedLoadPromise = performPublicFeedLoad(options).finally(() => { _feedLoadPromise = null; });
  return _feedLoadPromise;
}

async function performPublicFeedLoad({ client = axios, schedule = true, waitFn = wait } = {}) {
  if (process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED === 'false') {
    return { disabled: true, loaded: false, feeds: { ..._feedReady } };
  }
  if (_feedsLoading) return { skipped: 'already_loading', loaded: _feedsLoaded, feeds: { ..._feedReady } };
  _feedsLoading = true;
  try {
    const results = await Promise.allSettled(PUBLIC_FEEDS.map(definition => (
      fetchPublicFeed(definition, { client, waitFn })
    )));
    const failures = [];
    const failureDetails = [];
    results.forEach((result, index) => {
      const definition = PUBLIC_FEEDS[index];
      if (result.status === 'fulfilled') replacePublicFeed(definition.name, result.value.ips);
      else {
        _feedFailed[definition.name] = true;
        failures.push(definition.name);
        failureDetails.push({ name: definition.name, ...feedFailureDetails(result.reason) });
      }
    });
    if (failureDetails.length && Date.now() - _feedFailureWarningAt >= FEED_FAILURE_WARNING_INTERVAL_MS) {
      _feedFailureWarningAt = Date.now();
      const dnsUnavailable = failureDetails.every(({ code }) => code === 'EAI_AGAIN' || code === 'ENOTFOUND');
      if (dnsUnavailable) {
        console.warn(
          `[ThreatIntel] Public feeds unavailable: system DNS lookup failed for ${failures.join(', ')}; `
          + 'keeping previous data. Check the host/container DNS configuration.',
        );
      } else {
        failureDetails.forEach(({ name, message }) => {
          console.warn(`[ThreatIntel] Feed ${name} unavailable; keeping previous data: ${message}`);
        });
      }
    }
    _feedsLoaded = Object.values(_feedReady).every(Boolean);
    const summary = {
      loaded: _feedsLoaded,
      failures,
      feeds: { ..._feedReady },
      counts: { feodo: _feodoIps.size, emergingThreats: _etIps.size, tor: _torIps.size },
    };
    console.log(`[ThreatIntel] Feeds ready: Feodo=${_feodoIps.size} ET=${_etIps.size} Tor=${_torIps.size}`);
    if (schedule) {
      const delay = failures.length
        ? boundedFeedNumber(process.env.THREAT_FEED_FAILED_RETRY_MS, 900000, 10000, 3600000)
        : boundedFeedNumber(process.env.THREAT_FEED_REFRESH_MS, 21600000, 60000, 86400000);
      schedulePublicFeedRefresh(delay);
    }
    return summary;
  } finally {
    _feedsLoading = false;
  }
}

function publicFeedVerification(ip, now = Date.now()) {
  const maxAge = boundedFeedNumber(process.env.THREAT_FEED_REFRESH_MS, 21600000, 60000, 86400000);
  const matched = checkPublicFeeds(ip);
  return PUBLIC_FEEDS.map(({ name }) => ({
    provider: name,
    status: process.env.THREAT_INTEL_PUBLIC_FEEDS_ENABLED === 'false' ? 'disabled'
      : !_feedReady[name] ? 'unavailable'
        : _feedFailed[name] ? 'unavailable'
          : now < Date.parse(_feedCheckedAt[name]) || now - Date.parse(_feedCheckedAt[name]) >= maxAge ? 'stale' : 'checked',
    checkedAt: _feedCheckedAt[name],
    expiresAt: _feedCheckedAt[name] ? new Date(Date.parse(_feedCheckedAt[name]) + maxAge).toISOString() : null,
    matched: name === 'feodo' ? matched.isFeodo : name === 'emergingThreats' ? matched.isET : matched.isTor,
  }));
}

async function verifyPublicFeeds(ip) {
  // Join startup/refresh instead of interpreting an empty, still-loading set as clean.
  if (_feedLoadPromise) await _feedLoadPromise;
  let checks = publicFeedVerification(ip);
  if (checks.some(check => check.status === 'stale') || (!_feedsLoaded && !_feedRefreshTimer)) {
    await loadPublicFeeds();
    checks = publicFeedVerification(ip);
  }
  return checks;
}

function checkPublicFeeds(ip) {
  ip = normalizeIp(ip);
  if (!isPublicIp(ip)) {
    return {
      source: 'public_feeds',
      isFeodo: false,
      isET: false,
      isTor: false,
      isMalicious: false,
      feedSource: 'skipped_non_public_ip',
    };
  }
  return {
    source:    'public_feeds',
    isFeodo:   _feodoIps.has(ip),
    isET:      _etIps.has(ip),
    isTor:     _torIps.has(ip),
    isMalicious: _feodoIps.has(ip) || _etIps.has(ip) || _torIps.has(ip),
    feedSource: _feodoIps.has(ip) ? 'Feodo Tracker C2'
              : _etIps.has(ip)    ? 'Emerging Threats'
              : _torIps.has(ip)   ? 'Tor Exit Node'
              : 'clean',
  };
}

/* ── Master: enrichIp ─────────────────────────────────────────────────────── */
async function enrichIp(ip) {
  ip = normalizeIp(ip);
  if (!isPublicIp(ip)) {
    return {
      ip: ip || String(arguments[0] || ''),
      isMalicious: false,
      confidence: 0,
      shouldBlock: false,
      summary: 'Skipped threat intel lookup: non-public/invalid IP',
      abuseipdb: null,
      otx: null,
      publicFeeds: {
        source: 'public_feeds',
        isMalicious: false,
        feedSource: 'skipped_non_public_ip',
      },
      skipped: true,
      skipReason: 'non_public_or_invalid_ip',
      enrichedAt: new Date().toISOString(),
    };
  }

  // IPinfo Lite lookup & whitelist check
  let ipinfo = null;
  try {
    const ipEnrichmentService = require('./ipEnrichmentService');
    ipinfo = await ipEnrichmentService.enrichIp(ip);
    if (ipinfo && ipEnrichmentService.isWhitelisted(ipinfo)) {
      return {
        ip,
        isMalicious: false,
        confidence: 0,
        shouldBlock: false,
        summary: `Block bypassed: IP belongs to trusted organization/domain (${ipinfo.organization || ipinfo.domain || ipinfo.asn})`,
        ipinfo,
        abuseipdb: null,
        otx: null,
        publicFeeds: {
          source: 'public_feeds',
          isMalicious: false,
          feedSource: 'clean_trusted_org',
        },
        skipped: true,
        skipReason: 'trusted_organization',
        enrichedAt: new Date().toISOString(),
      };
    }
  } catch (err) {
    console.warn('[ThreatIntel→IPinfo] Whitelist check error:', err.message);
  }

  const [abuse, otx] = await Promise.all([
    queryAbuseIPDB(ip),
    queryOTX_IP(ip),
  ]);
  const feeds = checkPublicFeeds(ip);

  const isMalicious = !!(
    abuse?.isMalicious ||
    otx?.isMalicious   ||
    feeds.isMalicious
  );

  const confidence = Math.max(
    abuse?.abuseScore || 0,
    otx?.pulseCount   ? Math.min(otx.pulseCount * 10, 100) : 0,
    feeds.isMalicious ? 90 : 0,
  );

  return {
    ip,
    isMalicious,
    confidence,
    shouldBlock: confidence >= AUTO_BLOCK_THRESHOLD,
    summary: isMalicious
      ? `Malicious IP — confidence ${confidence}% [${
          [abuse?.isMalicious ? 'AbuseIPDB' : '',
           otx?.isMalicious   ? 'OTX' : '',
           feeds.feedSource !== 'clean' ? feeds.feedSource : '']
          .filter(Boolean).join(', ')}]`
      : 'IP appears clean across all feeds',
    abuseipdb: abuse,
    otx,
    ipinfo,
    publicFeeds: feeds,
    enrichedAt: new Date().toISOString(),
  };
}

/* ── Master: enrichDomain ─────────────────────────────────────────────────── */
async function enrichDomain(domain) {
  if (!domain) return null;
  const otx = await queryOTX_Domain(domain);
  return {
    domain,
    isMalicious: otx?.isMalicious || false,
    pulseCount:  otx?.pulseCount  || 0,
    tags:        otx?.tags        || [],
    malwareFamilies: otx?.malwareFamilies || [],
    summary: otx?.isMalicious
      ? `Malicious domain — ${otx.pulseCount} OTX pulses`
      : 'Domain appears clean',
    otx,
    enrichedAt: new Date().toISOString(),
  };
}

/* ── IPS Auto-block Integration ──────────────────────────────────────────── */
async function enrichAndMaybeBlock(ip, companyId, alertId, io) {
  try {
    const intel = await enrichIp(ip);
    if (!intel) return intel;

    // Persist enrichment for clean and malicious public indicators alike so
    // threat-feed rows retain their country/ASN metadata.
    if (alertId) {
      const indicatorType = net.isIP(ip) ? 'ip' : 'domain';
      const iocMatch = intel.isMalicious ? {
        indicator: ip,
        type: indicatorType,
        source: intel.publicFeeds?.feedSource !== 'clean' ? intel.publicFeeds?.feedSource
          : intel.abuseipdb?.isMalicious ? 'AbuseIPDB'
            : intel.otx?.isMalicious ? 'AlienVault OTX' : 'Threat Intelligence',
        reputation: intel.shouldBlock ? 'malicious' : 'suspicious',
        confidenceScore: intel.confidence,
        lastSeen: new Date(),
        malware: intel.otx?.malwareFamilies || [],
        recommendedResponse: intel.shouldBlock ? 'Block indicator and investigate affected endpoint' : 'Investigate and monitor indicator',
      } : null;
      await Alert.findByIdAndUpdate(alertId, {
        $set: {
          tiEnriched:    !intel.skipped,
          tiConfidence:  intel.confidence,
          tiSummary:     intel.summary,
          geoCountry:    intel.ipinfo?.country,
          geoCountryCode: intel.ipinfo?.countryCode,
          geoCity:       intel.ipinfo?.city,
          asn:           intel.ipinfo?.asn,
          asnOrg:        intel.ipinfo?.organization,
          tiFeeds:       {
            abuseScore:  intel.abuseipdb?.abuseScore,
            otxPulses:   intel.otx?.pulseCount,
            feedSource:  intel.publicFeeds?.feedSource,
          },
          iocMatched: Boolean(intel.isMalicious),
        },
        ...(intel.isMalicious ? { $addToSet: { iocMatches: iocMatch } } : {}),
      });
    }

    if (!intel.isMalicious) return intel;

    // Auto-block via IPS if threshold exceeded
    if (intel.shouldBlock && process.env.IPS_AUTO_BLOCK === 'true') {
      try {
        const IpsService = require('./ips.service');
        const blockResult = await IpsService.blockIP({
          ip,
          reason:    `TI auto-block: ${intel.summary}`,
          companyId,
          alertId,
          blockedBy: 'auto',
          ttlHours:  parseInt(process.env.IPS_BLOCK_TTL_HOURS || '24', 10),
          // Pass TI metadata so the Blocklist UI shows exact reason
          abuseScore:      intel.abuseipdb?.abuseScore     ?? null,
          otxPulses:       intel.otx?.pulseCount           ?? null,
          malwareFamilies: intel.otx?.malwareFamilies      ?? [],
          feedSource:      intel.publicFeeds?.feedSource !== 'clean' ? intel.publicFeeds?.feedSource
                         : intel.abuseipdb?.isMalicious ? 'AbuseIPDB'
                         : intel.otx?.isMalicious ? 'OTX AlienVault' : null,
          geoCountry:      intel.abuseipdb?.countryCode    ?? intel.otx?.countryCode ?? null,
        });

        // Real-time socket notification
        if (io && companyId && (blockResult?.agentConfirmed || blockResult?.webhookOk)) {
          io.to(`company:${companyId}`).emit('ips:block', {
            ip, srcIp: ip, attackType: 'Threat Intelligence Auto-Block',
            severity: 'high', reason: intel.summary, source: 'threat_intel',
          });
        }
        if (blockResult?.ok) {
          console.log(`[ThreatIntel] Auto-blocked ${ip} (confidence ${intel.confidence}%)`);
        } else {
          console.warn(`[ThreatIntel] Block recorded but enforcement failed for ${ip}: ${blockResult?.reason || blockResult?.webhook?.error || 'firewall/webhook unavailable'}`);
        }
      } catch (ipsErr) {
        console.warn('[ThreatIntel] IPS block failed:', ipsErr.message);
      }
    }

    return intel;
  } catch (e) {
    console.error('[ThreatIntel] enrichAndMaybeBlock error:', e.message);
    return null;
  }
}

// Load public feeds on startup (non-blocking)
loadPublicFeeds().catch(() => {});

module.exports = {
  enrichIp,
  enrichDomain,
  enrichAndMaybeBlock,
  queryAbuseIPDB,
  queryOTX_IP,
  queryOTX_Domain,
  checkPublicFeeds,
  verifyPublicFeeds,
  publicFeedVerification,
  loadPublicFeeds,
  fetchPublicFeed,
  parsePublicFeed,
  PUBLIC_FEEDS,
  normalizeIp,
  isPublicIp,
  isReservedIp,
  isTrustedCDN,
  normalizeThreatLabels,
  AUTO_BLOCK_THRESHOLD,
};
