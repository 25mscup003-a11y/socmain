const crypto = require('crypto');
const MAX_API_AGE_MS = 10 * 60 * 1000;
const PROOF_TTL_MS = 60000;
const PROVIDERS = Object.freeze(['ipinfo', 'abuseipdb', 'otx', 'virustotal']);
const REQUIRED_MATCHES = 2;
const PROOF_VERSION = 2;
const POLICY = 'two-of-four';
const inFlight = new Map();

function apiCheck(provider, result, checkedAt, detail = {}) {
  const timestamp = new Date(checkedAt || NaN).getTime();
  const valid = result && !result.skipped && !result.error && Number.isFinite(timestamp)
    && timestamp <= Date.now() && Date.now() - timestamp < MAX_API_AGE_MS;
  return { provider, status: valid ? 'checked' : 'unavailable',
    checkedAt: Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : null,
    expiresAt: valid ? new Date(timestamp + MAX_API_AGE_MS).toISOString() : null, ...detail };
}

async function evaluate(ip) {
  const intel = require('./threat-intel.service');
  if (!intel.isPublicIp(ip)) return { allowed: false, status: 'rejected', checks: [], reason: 'IP is invalid, reserved or protected infrastructure' };
  const ipinfo = require('./ipinfo.service');
  const vt = require('./virustotal.service');
  // Query each requested provider independently. Failed lookups are abstentions,
  // not vetoes. Do not attribute fallback geolocation/privacy data to IPinfo.
  const outcomes = await Promise.allSettled([
    ipinfo.lookupIpInfo(ip, { maxCacheAgeMs: MAX_API_AGE_MS }),
    intel.queryAbuseIPDB(ip), intel.queryOTX_IP(ip),
    vt.scanIp(ip, { maxCacheAgeMs: MAX_API_AGE_MS }),
  ]);
  const [info, abuse, otx, virus] = outcomes.map(result => result.status === 'fulfilled' ? result.value : null);
  const checks = [
    apiCheck('ipinfo', info?.countrySource === 'ipinfo' ? info : null, info?.countryCheckedAt,
      { country: info?.countryCode || null, asn: info?.asn || null,
        signal: null, note: 'IPinfo Lite provides geolocation/organization, not a malicious-IP verdict' }),
    apiCheck('abuseipdb', abuse, abuse?.checkedAt, { score: abuse?.abuseScore ?? null }),
    apiCheck('otx', otx, otx?.checkedAt, { pulses: otx?.pulseCount ?? null }),
    apiCheck('virustotal', virus, virus?.scannedAt, { verdict: virus?.verdict || null,
      detections: virus?.detections ?? null, score: virus?.score ?? null }),
  ];
  const signals = {
    // A successful country/ASN lookup, abuse-contact record or VPN/hosting flag
    // is not evidence of abuse. The configured Lite API has no threat verdict.
    ipinfo: null,
    abuseipdb: abuse?.abuseScore >= 75 ? 'AbuseIPDB score >= 75' : null,
    otx: otx?.pulseCount > 0 ? 'OTX pulse match' : null,
    virustotal: ['malicious', 'suspicious'].includes(virus?.verdict) || virus?.detections > 0 || virus?.score >= 10
      ? 'VirusTotal threat match' : null,
  };
  for (const check of checks) {
    check.matched = check.status === 'checked' && Date.parse(check.expiresAt) > Date.now() && Boolean(signals[check.provider]);
    check.signal = check.matched ? signals[check.provider] : null;
  }
  // Public feeds remain informational; their refresh/availability cannot delay
  // this decision or contribute votes to the four-provider quorum.
  let publicFeeds = [];
  try { publicFeeds = intel.publicFeedVerification(ip); } catch { /* Optional enrichment. */ }
  const matched = checks.filter(check => check.matched);
  const matchedProviders = matched.map(check => check.provider);
  const evidence = { checks, publicFeeds, matchedProviders, requiredMatches: REQUIRED_MATCHES, policy: POLICY };
  if (require('./ipEnrichmentService').isWhitelisted(info) || abuse?.isWhitelisted === true) {
    return { ...evidence, allowed: false, status: 'rejected', reason: 'IPinfo trusted organization or AbuseIPDB allowlist matched' };
  }
  const allowed = matched.length >= REQUIRED_MATCHES;
  return { ...evidence, allowed, status: allowed ? 'verified' : 'deferred',
    reason: allowed ? `${matched.length}/4 providers matched; ${matched.map(check => check.signal).join('; ')}`
      : `Only ${matched.length}/4 providers matched; at least ${REQUIRED_MATCHES} distinct threat matches required`,
    ...(allowed ? { expiresAt: new Date(Math.min(Date.now() + PROOF_TTL_MS,
      ...matched.map(check => Date.parse(check.expiresAt)))).toISOString() } : {}) };
}

async function verifyAutomaticNetworkAction({ ip, companyId, systemId = null, action = 'block_ip', alertId = null }) {
  ip = require('./ips.service').normalizeIP(ip);
  let result;
  if (!companyId || !ip) result = { allowed: false, status: 'rejected', checks: [], reason: 'Company and exact source IP are required' };
  else {
    let pending = inFlight.get(ip);
    if (!pending) {
      pending = evaluate(ip).catch(() => ({ allowed: false, status: 'deferred', checks: [], reason: 'Threat verification is unavailable' }))
        .finally(() => inFlight.delete(ip));
      inFlight.set(ip, pending);
    }
    result = { ...await pending };
  }
  const checkedAt = new Date().toISOString();
  result = { ...result, ip, companyId: String(companyId || ''), action, checkedAt };
  if (result.allowed) result.verification = { version: PROOF_VERSION, policy: POLICY, ip, companyId: String(companyId), action,
    checkedAt, expiresAt: result.expiresAt, providers: [...PROVIDERS], matchedProviders: [...result.matchedProviders] };
  if (companyId) {
    const audit = { eventId: crypto.randomUUID(), companyId, systemId,
      action: result.allowed ? 'Threat Verification Passed' : 'Threat Verification Deferred',
      severity: result.allowed ? 'high' : 'info', actor: 'IPS Threat Gate', target: ip,
      detail: result.reason, metadata: { ...result, verification: undefined }, ts: new Date() };
    try {
      await require('../models/IpsAuditEvent.model').updateOne({ eventId: audit.eventId }, { $setOnInsert: audit }, { upsert: true });
      if (alertId) await require('../models/Alert.model').updateOne({ _id: alertId, companyId }, {
        $set: { 'metadata.automaticThreatVerification': result,
          tiEnriched: result.checks.some(check => check.status === 'checked'),
          tiSummary: result.reason,
          'tiFeeds.abuseScore': result.checks.find(check => check.provider === 'abuseipdb')?.score ?? null,
          'tiFeeds.otxPulses': result.checks.find(check => check.provider === 'otx')?.pulses ?? null,
          'tiFeeds.vtDetections': result.checks.find(check => check.provider === 'virustotal')?.detections ?? null,
          'tiFeeds.vtScore': result.checks.find(check => check.provider === 'virustotal')?.score ?? null,
          'tiFeeds.vtVerdict': result.checks.find(check => check.provider === 'virustotal')?.verdict ?? 'unavailable',
        },
      });
      global._ipsEngineIO?.to(`company:${companyId}`).emit('ips:audit', { ...audit, id: audit.eventId });
    } catch {
      return { ...result, allowed: false, verification: undefined, status: 'deferred', reason: 'Threat verification audit could not be saved' };
    }
  }
  if (result.allowed && Date.parse(result.expiresAt) <= Date.now()) {
    return { ...result, allowed: false, verification: undefined, status: 'deferred', reason: 'Threat verification expired before delivery' };
  }
  return result;
}

function automaticNetworkCommand(command) {
  return ['block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint'].includes(command?.command)
    && (command.automatic === true || command.threatVerification != null || command.autoIsolation != null
      || /^(IPS Auto-block|TI auto-block|Automatic IPS isolation|Severity auto-block)/i.test(String(command.reason || '')));
}

function commandVerificationError(command, companyId) {
  if (!automaticNetworkCommand(command)) return null;
  const proof = command.threatVerification;
  const action = command.command === 'block_ip' ? 'block_ip' : 'isolate';
  const ip = command.ip || command.srcIp || command.params?.ip;
  if (proof?.version !== PROOF_VERSION || proof.policy !== POLICY || proof.action !== action || proof.ip !== ip || String(proof.companyId) !== String(companyId)
      || !Array.isArray(proof.matchedProviders) || proof.matchedProviders.length < REQUIRED_MATCHES
      || new Set(proof.matchedProviders).size !== proof.matchedProviders.length
      || !proof.matchedProviders.every(name => PROVIDERS.includes(name))
      || !Number.isFinite(Date.parse(proof.checkedAt)) || !Number.isFinite(Date.parse(proof.expiresAt))
      || Date.parse(proof.checkedAt) > Date.now() || Date.parse(proof.expiresAt) <= Date.now()
      || Date.parse(proof.expiresAt) <= Date.parse(proof.checkedAt)
      || Date.parse(proof.expiresAt) - Date.parse(proof.checkedAt) > PROOF_TTL_MS) {
    return 'automatic network action has missing, expired or mismatched two-of-four threat verification';
  }
  return null;
}

async function filterNetworkCommands({ companyId, systemId, commands }) {
  const output = [];
  for (const command of commands || []) {
    let automatic = automaticNetworkCommand(command);
    if (!automatic && command.responseId && ['block_ip', 'isolate', 'isolate_agent', 'quarantine_endpoint'].includes(command.command)) {
      // Old signed SOAR envelopes predate the automatic marker. Look up their
      // origin without modifying signed fields; only an explicit manual origin
      // can bypass the quorum. Unknown/deleted records cannot authorize action.
      const response = await require('../models/AutomatedResponse.model').findOne({
        _id: command.responseId, companyId, systemId,
      }).select('trigger').lean().catch(() => null);
      automatic = response?.trigger !== 'manual';
    }
    if (!automatic) { output.push(command); continue; }
    let error = commandVerificationError({ ...command, automatic: true }, companyId);
    if (!error && !command.autoIsolation) {
      const ip = command.ip || command.srcIp || command.params?.ip;
      if (await require('./ips.service').isWhitelistedForCompany(ip, companyId, { requireRemote: true }).catch(() => true)) {
        error = 'source IP whitelist check did not allow automatic response';
      } else {
        const result = await verifyAutomaticNetworkAction({ ip, companyId, systemId,
          action: command.command === 'block_ip' ? 'block_ip' : 'isolate' });
        error = result.allowed ? commandVerificationError(command, companyId) : result.reason;
      }
    }
    if (!error) { output.push(command); continue; }
    try {
      if (command.responseId) {
        await require('./automatedResponse.service').recordAgentResult({ companyId, systemId,
          responseId: command.responseId, commandId: command.commandId, ok: false, result: `Threat verification deferred: ${error}` });
        await require('../models/System.model').updateOne({ _id: systemId, companyId }, {
          $pull: { pendingCommands: { responseId: command.responseId, commandId: command.commandId } },
        });
      }
      else await require('./ips.service').recordAgentCommandResult({ systemId,
        commandId: command.id || command.commandId, command: command.command, ok: false,
        message: command.command === 'isolate' ? `Automatic isolation deferred: ${error}` : `Threat verification deferred: ${error}` });
    } catch { /* Never deliver an unverified command if cancellation persistence failed. */ }
  }
  return output;
}

module.exports = { verifyAutomaticNetworkAction, automaticNetworkCommand, commandVerificationError,
  filterNetworkCommands, PROVIDERS, REQUIRED_MATCHES, PROOF_VERSION, POLICY, MAX_API_AGE_MS, PROOF_TTL_MS };
