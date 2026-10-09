const axios = require('axios');
const net = require('net');

const VT_BASE = 'https://www.virustotal.com/api/v3';

// Simple in-process cache — 24h TTL
const _cache = new Map();
const CACHE_TTL = 24 * 60 * 60 * 1000;
const RATE_LIMIT_COOLDOWN_MS = 5 * 60 * 1000;
let rateLimitedUntil = 0;
let lastRateLimitWarningAt = 0;

function rateLimitActive() {
  return Date.now() < rateLimitedUntil;
}

function noteRateLimit() {
  rateLimitedUntil = Date.now() + RATE_LIMIT_COOLDOWN_MS;
  if (Date.now() - lastRateLimitWarningAt >= RATE_LIMIT_COOLDOWN_MS) {
    console.warn('[VT] Rate limit reached; suppressing external lookups for 5 minutes');
    lastRateLimitWarningAt = Date.now();
  }
}

function getKey() {
  return process.env.VIRUSTOTAL_API_KEY || '';
}

function isEnabled() {
  return !!getKey();
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

function isPublicIp(value = '') {
  const ip = normalizeIp(value);
  const version = net.isIP(ip);
  if (!version) return false;
  if (version === 4) {
    const parts = ip.split('.').map(Number);
    const [a, b] = parts;
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 192 && b === 0) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    if (a === 198 && b === 51 && parts[2] === 100) return false;
    if (a === 203 && b === 0 && parts[2] === 113) return false;
    return true;
  }
  const lower = ip.toLowerCase();
  if (lower === '::1' || lower === '::') return false;
  if (lower.startsWith('fc') || lower.startsWith('fd')) return false;
  if (lower.startsWith('fe80:')) return false;
  if (lower.startsWith('2001:db8:')) return false;
  return true;
}

function calcScore(stats) {
  if (!stats) return 0;
  const mal = (stats.malicious || 0) + (stats.suspicious || 0);
  const tot = Object.values(stats).reduce((a, b) => a + b, 0);
  if (tot === 0) return 0;
  return Math.round((mal / tot) * 100);
}

// Convert VT score → alert severity string
function vtScoreToSeverity(score) {
  if (score >= 70) return 'critical';
  if (score >= 40) return 'high';
  if (score >= 10) return 'medium';
  return null; // don't downgrade
}

function _parseResponse(data) {
  const attrs   = data.data?.attributes || {};
  const stats   = attrs.last_analysis_stats || {};
  const results = attrs.last_analysis_results || {};

  const engines = Object.entries(results)
    .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
    .slice(0, 10)
    .map(([name, v]) => ({ name, result: v.result || v.category }));

  const malicious   = stats.malicious || 0;
  const suspicious  = stats.suspicious || 0;
  const total       = Object.values(stats).reduce((a, b) => a + b, 0);
  const score       = calcScore(stats);
  const detections  = malicious + suspicious;

  // If VT returned data but no engines scanned (total=0), treat as not_found
  const verdict = total === 0
    ? 'not_found'
    : malicious > 0  ? 'malicious'
    : suspicious > 0 ? 'suspicious'
    :                  'clean';

  return {
    score,
    detections,
    total,
    ratio:            `${detections}/${total}`,
    detection_ratio:  `${detections}/${total}`,
    verdict,
    engines,
    scannedAt: new Date(),
  };
}

/**
 * Scan a file hash (MD5, SHA1, or SHA256) against VirusTotal.
 * Returns { score, detections, total, ratio, engines[], scannedAt } or null.
 */
async function scanHash(hash) {
  const key = getKey();
  if (!key || !hash || rateLimitActive()) return null;

  const cacheKey = `hash:${hash}`;
  const cached = _cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;

  try {
    const { data } = await axios.get(`${VT_BASE}/files/${hash}`, {
      headers: { 'x-apikey': key },
      timeout: 10000,
    });
    const result = _parseResponse(data);
    _cache.set(cacheKey, { data: result, ts: Date.now() });
    return result;
  } catch (err) {
    if (err.response?.status === 404) {
      // Hash not in VT database — not_found, NOT clean
      const r = { score: 0, detections: 0, total: 0, ratio: '0/0', detection_ratio: '0/0',
                  verdict: 'not_found', engines: [], scannedAt: new Date(), notFound: true };
      _cache.set(cacheKey, { data: r, ts: Date.now() });
      return r;
    }
    if (err.response?.status === 429) { noteRateLimit(); return null; }
    console.error('[VT] scanHash error:', err.message);
    return null;
  }
}

/**
 * Scan an IP address against VirusTotal.
 * Returns { score, detections, total, ratio, engines[], scannedAt } or null.
 */
async function scanIp(ip, { maxCacheAgeMs = CACHE_TTL } = {}) {
  const key = getKey();
  ip = normalizeIp(ip);
  if (!key || !isPublicIp(ip) || rateLimitActive()) return null;

  const cacheKey = `ip:${ip}`;
  const cached = _cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < Math.min(CACHE_TTL, maxCacheAgeMs)) return cached.data;

  try {
    const { data } = await axios.get(`${VT_BASE}/ip_addresses/${ip}`, {
      headers: { 'x-apikey': key },
      timeout: 10000,
    });
    if (!data?.data?.attributes?.last_analysis_stats) throw new Error('invalid VirusTotal IP response');
    const result = _parseResponse(data);
    _cache.set(cacheKey, { data: result, ts: Date.now() });
    return result;
  } catch (err) {
    if (err.response?.status === 404) {
      const result = { verdict: 'not_found', detections: 0, score: 0, total: 0, notFound: true, scannedAt: new Date() };
      _cache.set(cacheKey, { data: result, ts: Date.now() });
      return result;
    }
    if (err.response?.status === 429) { noteRateLimit(); return null; }
    console.error('[VT] scanIp error:', err.message);
    return null;
  }
}

/**
 * Scan a URL against VirusTotal.
 */
async function scanUrl(url) {
  const key = getKey();
  if (!key || !url || rateLimitActive()) return null;

  const cacheKey = `url:${Buffer.from(url).toString('base64')}`;
  const cached = _cache.get(cacheKey);
  if (cached && Date.now() - cached.ts < CACHE_TTL) return cached.data;

  try {
    const form = new URLSearchParams();
    form.append('url', url);
    const { data: sub } = await axios.post(`${VT_BASE}/urls`, form, {
      headers: { 'x-apikey': key, 'Content-Type': 'application/x-www-form-urlencoded' },
      timeout: 10000,
    });
    const analysisId = sub.data?.id;
    if (!analysisId) return null;

    await new Promise(r => setTimeout(r, 3000));
    const { data: res } = await axios.get(`${VT_BASE}/analyses/${analysisId}`, {
      headers: { 'x-apikey': key },
      timeout: 10000,
    });
    const stats   = res.data?.attributes?.stats || {};
    const results = res.data?.attributes?.results || {};
    const engines = Object.entries(results)
      .filter(([, v]) => v.category === 'malicious' || v.category === 'suspicious')
      .slice(0, 10)
      .map(([name, v]) => ({ name, result: v.result || v.category }));
    const score = calcScore(stats);
    const result = {
      score,
      detections: (stats.malicious||0) + (stats.suspicious||0),
      total: Object.values(stats).reduce((a, b) => a + b, 0),
      ratio: `${(stats.malicious||0)+(stats.suspicious||0)}/${Object.values(stats).reduce((a,b)=>a+b,0)}`,
      engines,
      scannedAt: new Date(),
    };
    _cache.set(cacheKey, { data: result, ts: Date.now() });
    return result;
  } catch (err) {
    if (err.response?.status === 429) { noteRateLimit(); return null; }
    console.error('[VT] scanUrl error:', err.message);
    return null;
  }
}

module.exports = { isEnabled, scanHash, scanIp, scanUrl, vtScoreToSeverity };
