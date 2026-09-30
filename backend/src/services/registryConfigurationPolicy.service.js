const RegistryConfigurationControl = require('../models/RegistryConfigurationControl.model');

const CACHE_TTL_MS = Math.max(5000, Number(process.env.REGISTRY_POLICY_CACHE_TTL_MS) || 30000);
const CACHE_LIMIT = Math.max(100, Number(process.env.REGISTRY_POLICY_CACHE_MAX) || 2000);
const cache = new Map();

const BUILTIN_POLICIES = Object.freeze([
  { policyId: 'REG-CRITICAL-KEYS', name: 'Monitor Critical Registry Keys', category: 'registry_integrity', riskThreshold: 60, severity: 'high', enabled: true },
  { policyId: 'REG-SECURITY-CONFIG', name: 'Monitor Security Configuration', category: 'security_configuration', riskThreshold: 60, severity: 'high', enabled: true },
  { policyId: 'REG-PERSISTENCE', name: 'Alert on Unauthorized Persistence', category: 'persistence', riskThreshold: 60, severity: 'high', enabled: true },
  { policyId: 'REG-AUTH-CONFIG', name: 'Monitor Authentication Configuration', category: 'user_authentication', riskThreshold: 60, severity: 'high', enabled: true },
  { policyId: 'REG-NETWORK-CONFIG', name: 'Monitor Network Configuration', category: 'network_configuration', riskThreshold: 50, severity: 'medium', enabled: true },
  { policyId: 'REG-SERVICE-CONFIG', name: 'Monitor Service Configuration', category: 'service_configuration', riskThreshold: 60, severity: 'high', enabled: true },
  { policyId: 'REG-LINUX-CONFIG', name: 'Monitor Linux Critical Files', category: 'configuration_integrity', riskThreshold: 50, severity: 'medium', enabled: true },
  { policyId: 'REG-SOLARIS-CONFIG', name: 'Monitor Solaris Critical Files', category: 'configuration_integrity', riskThreshold: 50, severity: 'medium', enabled: true },
]);

const normalize = value => String(value ?? '').trim().toLowerCase().replace(/\\/g, '/');

function globMatch(pattern, value) {
  const expected = normalize(pattern || '*');
  const actual = normalize(value);
  if (expected === '*') return true;
  if (!expected.includes('*')) return expected === actual;
  const source = expected.split('*').map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*');
  return new RegExp(`^${source}$`, 'i').test(actual);
}

function listMatch(values, actual) {
  return Array.isArray(values) && values.some(value => globMatch(value, actual));
}

function controlMatches(control, event) {
  if (!control || !event) return false;
  if (control.category && control.category !== 'all' && normalize(control.category) !== normalize(event.configurationCategory)) return false;
  if (control.operation && normalize(control.operation) !== normalize(event.configurationOperation)) return false;
  if (!globMatch(control.target || '*', event.configurationObject)) return false;
  if (control.expectedState !== null && control.expectedState !== undefined
    && normalize(JSON.stringify(control.expectedState)) !== normalize(JSON.stringify(event.newValue ?? event.newState))) return false;
  return true;
}

function isExcluded(policy, event) {
  return listMatch(policy.excludedHosts, event.hostname || event.agentName)
    || listMatch(policy.excludedUsers, event.username)
    || listMatch(policy.excludedProcesses, event.processName || event.processExe)
    || listMatch(policy.excludedPaths, event.configurationObject)
    || listMatch(policy.allowedChanges, event.configurationOperation);
}

function key(companyId, departmentId) {
  return `${String(companyId)}:${departmentId ? String(departmentId) : 'company'}`;
}

async function loadControls(companyId, departmentId) {
  const cacheKey = key(companyId, departmentId);
  const existing = cache.get(cacheKey);
  if (existing?.controls && existing.expiresAt > Date.now()) return existing.controls;
  if (existing?.promise) return existing.promise;
  const departmentScope = departmentId
    ? [{ departmentId: null }, { departmentId }]
    : [{ departmentId: null }, { departmentId: { $exists: false } }];
  const promise = RegistryConfigurationControl.find({
    companyId, enabled: true,
    $and: [{ $or: departmentScope }, { $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] }],
  }).sort({ kind: -1, createdAt: -1 }).limit(CACHE_LIMIT).maxTimeMS(2000).lean()
    .then(controls => {
      cache.set(cacheKey, { controls, expiresAt: Date.now() + CACHE_TTL_MS });
      if (cache.size > CACHE_LIMIT) cache.delete(cache.keys().next().value);
      return controls;
    })
    .catch(error => {
      console.warn('[registry policies] lookup failed; ingesting with built-in policies:', error.message);
      cache.set(cacheKey, { controls: [], expiresAt: Date.now() + 5000 });
      return [];
    });
  cache.set(cacheKey, { promise, expiresAt: Date.now() + CACHE_TTL_MS });
  return promise;
}

function severityRank(value) {
  return ({ low: 0, medium: 1, high: 2, critical: 3 })[String(value || '').toLowerCase()] ?? 0;
}

function severityFromRisk(value) {
  const score = Number(value || 0);
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 30) return 'medium';
  return 'low';
}

async function applyRegistryConfigurationPolicies(event) {
  if (!event?.companyId || !event.configurationCategory) return event;
  const controls = await loadControls(event.companyId, event.departmentId);
  const systemId = String(event.systemId || '');
  const scoped = controls.filter(control => !control.systemId || String(control.systemId) === systemId);
  const approval = scoped.find(control => ['exception', 'baseline'].includes(control.kind) && controlMatches(control, event));
  if (approval) {
    const isException = approval.kind === 'exception';
    event.riskScore = Math.min(Number(event.riskScore || 0), isException ? 19 : 29);
    event.severity = severityFromRisk(event.riskScore);
    event.configurationBaselineStatus = isException ? 'exception' : 'approved';
    event.configurationPolicyViolation = false;
    event.configurationPolicyId = String(approval._id);
    event.changeTicket = approval.ticketReference || event.changeTicket;
    return event;
  }

  const overrides = new Map(scoped.filter(control => control.kind === 'policy' && control.policyId).map(control => [control.policyId, control]));
  const policies = BUILTIN_POLICIES.map(policy => ({ ...policy, ...(overrides.get(policy.policyId) || {}) }))
    .concat(scoped.filter(control => control.kind === 'policy' && !BUILTIN_POLICIES.some(policy => policy.policyId === control.policyId)));
  const policy = policies.find(item => item.enabled !== false && controlMatches({ ...item, target: item.target || '*' }, event) && !isExcluded(item, event));
  if (!policy) return event;
  const currentRisk = Number(event.riskScore || 0);
  const threshold = Number(policy.riskThreshold ?? 50);
  event.configurationPolicyId = policy.policyId || String(policy._id);
  event.configurationPolicyViolation = currentRisk >= threshold;
  if (event.configurationPolicyViolation) {
    const configuredSeverity = String(policy.severity || 'medium').toLowerCase();
    const riskSeverity = severityFromRisk(currentRisk);
    event.severity = severityRank(configuredSeverity) > severityRank(riskSeverity) ? configuredSeverity : riskSeverity;
    event.configurationRiskFactors = [...new Set([...(event.configurationRiskFactors || []), `policy:${event.configurationPolicyId}`])];
  }
  return event;
}

function invalidateRegistryPolicyCache(companyId) {
  const prefix = `${String(companyId)}:`;
  [...cache.keys()].filter(item => item.startsWith(prefix)).forEach(item => cache.delete(item));
}

module.exports = {
  BUILTIN_POLICIES,
  applyRegistryConfigurationPolicies,
  controlMatches,
  invalidateRegistryPolicyCache,
};
