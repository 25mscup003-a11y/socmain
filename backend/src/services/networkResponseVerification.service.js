async function checkNetworkResponse({ ip, companyId, system = null, action, startedAt }) {
  const service = require('./ips.service');
  ip = service.normalizeIP(ip);
  if (!['block_ip', 'isolate'].includes(action) || !companyId || !ip || service.isPrivateIP(ip)) {
    return { allowed: false, reason: 'Exact public IP, company and supported action required' };
  }
  if (system && (!system.isActive || system.ipsEnabled === false || system.responseEnabled === false)) {
    return { allowed: false, reason: 'Endpoint IPS/response is disabled or inactive' };
  }
  if (await service.isWhitelistedForCompany(ip, companyId, { requireRemote: true }).catch(() => true)) {
    return { allowed: false, reason: 'Whitelist matched or whitelist verification unavailable' };
  }
  if (action === 'isolate') {
    if (!system) return { allowed: false, reason: 'Exact endpoint required for automatic isolation' };
    const decision = await require('./ipsIsolationGuard.service').checkAutoIsolation({
      companyId, systemId: system._id, srcIp: ip,
      startedAt: startedAt || Date.now() - 120000,
      requireUnconfirmedBlock: process.env.IPS_ISOLATE_AFTER_SUCCESSFUL_BLOCK !== 'true',
    });
    return { ...decision, verification: decision.threatVerification
      ? { ...decision.threatVerification, expiresAt: decision.autoIsolation?.expiresAt } : undefined,
      expiresAt: decision.autoIsolation?.expiresAt };
  }
  return require('./ipsThreatGate.service').verifyAutomaticNetworkAction({ ip, companyId, systemId: system?._id, action });
}

module.exports = { checkNetworkResponse };
