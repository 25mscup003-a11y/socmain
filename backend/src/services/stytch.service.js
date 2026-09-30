/**
 * Stytch Service
 * Calls the Stytch Telemetry API to look up device fingerprint data.
 * Falls back to realistic simulation when credentials are not configured.
 */
const axios = require('axios');
const crypto = require('crypto');
const stytchConfig = require('../config/stytch.config');
let unavailableUntil = 0;
let lastFailureLogAt = 0;
const FAILURE_COOLDOWN_MS = 15 * 60 * 1000;

function unavailableError(message) {
  const error = new Error(message);
  error.code = 'STYTCH_UNAVAILABLE';
  return error;
}

// ── Country pools for simulation ──────────────────────────────────────────────
const COUNTRIES = ['US', 'IN', 'GB', 'DE', 'CA', 'AU', 'FR', 'SG', 'BR', 'JP', 'NL', 'PK', 'RU', 'CN'];
const ISPS = ['Cloudflare', 'AWS', 'Google Cloud', 'DigitalOcean', 'BSNL', 'Jio', 'Comcast', 'AT&T', 'Vodafone', 'Verizon'];
const ASNS = ['AS13335', 'AS16509', 'AS15169', 'AS14061', 'AS17813', 'AS45609', 'AS7018', 'AS22394'];
const BROWSERS = ['Chrome 125', 'Firefox 127', 'Safari 17', 'Edge 124', 'Opera 110', 'Brave 1.67'];
const OSS = ['Windows 11', 'macOS 14.5', 'Ubuntu 22.04', 'iOS 17', 'Android 14', 'Windows 10'];

function randomElement(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
function randomHex(len) { return crypto.randomBytes(len).toString('hex'); }
function randomInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }

/**
 * Generates a deterministic-ish fingerprint from telemetry_id.
 * Same telemetry_id always produces the same fingerprint set in the same process
 * (uses the ID as seed for consistent simulation per device session).
 */
function generateSimulatedTelemetry(telemetryId, ip) {
  // Use hash of telemetry_id to make results consistent per device
  const seed = telemetryId ? parseInt(crypto.createHash('md5').update(telemetryId).digest('hex').slice(0, 8), 16) : Math.random() * 1e9;
  const seededRand = (n) => ((seed * 9301 + 49297) % 233280 / 233280) * n; // simple LCG

  const isVpn    = seededRand(100) < 12;  // 12% chance of VPN
  const isTor    = seededRand(100) < 3;   // 3% chance of TOR
  const isProxy  = seededRand(100) < 8;   // 8% chance of Proxy
  const isBot    = seededRand(100) < 2;   // 2% chance of Bot

  const countryIdx = Math.floor(seededRand(COUNTRIES.length));
  const country = COUNTRIES[countryIdx];

  // VPN/TOR inflates risk
  let baseRisk = Math.floor(seededRand(60));           // 0–59 base
  if (isVpn)   baseRisk = Math.min(100, baseRisk + 20);
  if (isTor)   baseRisk = Math.min(100, baseRisk + 45);
  if (isProxy) baseRisk = Math.min(100, baseRisk + 15);
  if (isBot)   baseRisk = Math.min(100, baseRisk + 35);

  return {
    visitorId:          `visitor_${randomHex(16)}`,
    browserId:          `browser_${randomHex(16)}`,
    deviceFingerprint:  `df_${randomHex(20)}`,
    browserFingerprint: `bf_${randomHex(20)}`,
    hardwareFingerprint:`hf_${randomHex(20)}`,
    networkFingerprint: `nf_${randomHex(12)}`,

    ip:      ip || `${randomInt(1, 254)}.${randomInt(0, 254)}.${randomInt(0, 254)}.${randomInt(1, 254)}`,
    country,
    region:  'Region-' + country,
    city:    'City-' + country,
    asn:     randomElement(ASNS),
    isp:     randomElement(ISPS),
    lat:     (seededRand(160) - 80).toFixed(4),
    lon:     (seededRand(360) - 180).toFixed(4),

    browser: randomElement(BROWSERS),
    os:      randomElement(OSS),
    device:  seededRand(10) > 3 ? 'desktop' : 'mobile',

    isVpn,
    isTor,
    isProxy,
    isBot,

    riskScore: Math.min(100, Math.max(0, baseRisk)),
    simulated: true,
    raw: { source: 'simulation', telemetryId },
  };
}

/**
 * lookupTelemetry
 * @param {string} telemetryId - ID from Stytch JS SDK (or mock)
 * @param {string} ipAddress   - Requesting client IP
 * @returns {Promise<Object>}  - Normalized telemetry object
 */
async function lookupTelemetry(telemetryId, ipAddress) {
  // ── Simulation Mode ──────────────────────────────────────────────────────────
  if (stytchConfig.simulationMode) {
    const data = generateSimulatedTelemetry(telemetryId, ipAddress);
    console.log(`[Stytch][SIM] Fingerprint generated for telemetry_id=${telemetryId?.slice(0, 12)}... risk=${data.riskScore}`);
    return data;
  }
  if (!telemetryId || typeof telemetryId !== 'string') {
    const error = unavailableError('A genuine Stytch telemetry ID is required');
    error.code = 'STYTCH_TELEMETRY_MISSING';
    throw error;
  }
  if (!stytchConfig.projectId || !stytchConfig.secret) {
    throw unavailableError('Stytch credentials are not configured');
  }
  if (Date.now() < unavailableUntil) {
    throw unavailableError('Stytch telemetry is temporarily unavailable');
  }

  // ── Real Stytch API Mode ─────────────────────────────────────────────────────
  try {
    const credentials = Buffer.from(`${stytchConfig.projectId}:${stytchConfig.secret}`).toString('base64');
    const response = await axios.post(
      stytchConfig.lookupUrl,
      { telemetry_id: telemetryId },
      {
        headers: {
          'Authorization': `Basic ${credentials}`,
          'Content-Type':  'application/json',
        },
        timeout: 5000,
      }
    );

    const r = response.data;
    const fp = r.fingerprints || {};
    const network = r.network || {};
    const geo = r.geo_location || {};
    const threat = r.threat_signals || {};
    const verdict = r.verdict || {};
    const verdictAction = String(verdict.action || 'CHALLENGE').toUpperCase();
    const verdictRisk = verdictAction === 'BLOCK' ? 100 : verdictAction === 'CHALLENGE' ? 60 : 0;

    return {
      visitorId:          fp.visitor_id || r.visitor_id,
      browserId:          fp.browser_id,
      deviceFingerprint:  fp.visitor_fingerprint,
      browserFingerprint: fp.browser_fingerprint,
      hardwareFingerprint:fp.hardware_fingerprint,
      networkFingerprint: fp.network_fingerprint,

      ip:      network.ip_address || ipAddress,
      country: geo.country_code,
      region:  geo.region,
      city:    geo.city,
      asn:     network.asn,
      isp:     network.isp,
      lat:     geo.latitude,
      lon:     geo.longitude,

      browser: r.browser_type,
      os:      r.os_type,
      device:  r.device_type,

      isVpn:   threat.vpn_detected   || false,
      isTor:   threat.tor_detected   || false,
      isProxy: threat.proxy_detected || false,
      isBot:   threat.bot_detected || verdict.is_authentic_device === false,

      riskScore: Number.isFinite(Number(r.risk_score)) ? Number(r.risk_score) : verdictRisk,
      stytchVerdict: verdictAction,
      verdictReasons: Array.isArray(verdict.reasons) ? verdict.reasons : [],
      simulated: false,
      raw: r,
    };
  } catch (err) {
    unavailableUntil = Date.now() + FAILURE_COOLDOWN_MS;
    if (Date.now() - lastFailureLogAt >= FAILURE_COOLDOWN_MS) {
      console.warn(`[Stytch][API] Lookup unavailable (${err.response?.status || err.code || 'network'}); fraud check will fail open without fabricated telemetry`);
      lastFailureLogAt = Date.now();
    }
    throw unavailableError('Stytch telemetry lookup unavailable');
  }
}

module.exports = { lookupTelemetry, generateSimulatedTelemetry };
