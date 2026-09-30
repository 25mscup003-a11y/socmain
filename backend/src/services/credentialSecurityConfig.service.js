const CredentialSecurityConfig = require('../models/CredentialSecurityConfig.model');

const CACHE_TTL_MS = Math.max(5000, Number(process.env.CREDENTIAL_CONFIG_CACHE_MS) || 30000);
const CACHE_MAX = Math.max(100, Number(process.env.CREDENTIAL_CONFIG_CACHE_MAX) || 2000);
const cache = new Map();
const inFlight = new Map();

function put(key, value) {
  cache.delete(key);
  cache.set(key, { value, expiresAt: Date.now() + CACHE_TTL_MS });
  while (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
  return value;
}

async function getCredentialSecurityConfig(companyId) {
  const key = String(companyId || '');
  if (!key) return null;
  const cached = cache.get(key);
  if (cached?.expiresAt > Date.now()) return cached.value;
  cache.delete(key);
  if (inFlight.has(key)) return inFlight.get(key);
  const request = CredentialSecurityConfig.findOne({ companyId })
    .select('tenantId companyId enabled monitorProcesses monitorCredentialStores monitorLockScreen scanIntervalSeconds minimumRiskScore builtInRuleOverrides manualPolicies version lastDeployedAt lastDeployedBy createdAt updatedAt')
    .lean()
    .then(value => put(key, value))
    .finally(() => inFlight.delete(key));
  inFlight.set(key, request);
  return request;
}

function setCredentialSecurityConfig(companyId, configuration) {
  return put(String(companyId || ''), configuration || null);
}

module.exports = { getCredentialSecurityConfig, setCredentialSecurityConfig };
