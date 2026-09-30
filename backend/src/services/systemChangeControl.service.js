const SystemChangeControl = require('../models/SystemChangeControl.model');

const CONTROL_CACHE_TTL_MS = Math.max(5000, Number(process.env.SYSTEM_CHANGE_CONTROL_CACHE_TTL_MS) || 30000);
const CONTROL_CACHE_MAX = Math.max(100, Number(process.env.SYSTEM_CHANGE_CONTROL_CACHE_MAX) || 2000);
const controlCache = new Map();

function normalized(value) {
  if (value === null || value === undefined) return '';
  const text = typeof value === 'object' ? JSON.stringify(value) : String(value);
  return text.trim().toLowerCase().replace(/\\/g, '/');
}

function globMatches(pattern, value) {
  const expected = normalized(pattern);
  const actual = normalized(value);
  if (!expected) return true;
  if (!expected.includes('*')) return expected === actual;
  const expression = expected
    .split('*')
    .map(part => part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'))
    .join('.*');
  return new RegExp(`^${expression}$`, 'i').test(actual);
}

function statesMatch(expectedState, newState) {
  if (expectedState === null || expectedState === undefined || expectedState === '') return true;
  return normalized(expectedState) === normalized(newState);
}

function controlMatches(control, event) {
  if (!control || !event) return false;
  if (control.category && normalized(control.category) !== normalized(event.systemChangeCategory)) return false;
  if (control.changeType && normalized(control.changeType) !== normalized(event.systemChangeType)) return false;
  if (control.processName && !globMatches(control.processName, event.processName || event.processExe)) return false;
  if (!globMatches(control.target, event.systemChangeTarget)) return false;
  return statesMatch(control.expectedState, event.newState);
}

function cacheKey(companyId, departmentId) {
  return `${String(companyId)}:${departmentId ? String(departmentId) : 'company'}`;
}

function trimCache() {
  if (controlCache.size <= CONTROL_CACHE_MAX) return;
  const oldest = [...controlCache.entries()]
    .sort((left, right) => Number(left[1].expiresAt || 0) - Number(right[1].expiresAt || 0))
    .slice(0, controlCache.size - CONTROL_CACHE_MAX);
  oldest.forEach(([key]) => controlCache.delete(key));
}

async function loadControls(companyId, departmentId) {
  const key = cacheKey(companyId, departmentId);
  const cached = controlCache.get(key);
  if (cached?.controls && cached.expiresAt > Date.now()) return cached.controls;
  if (cached?.promise) return cached.promise;

  const departmentScope = departmentId
    ? [{ departmentId: null }, { departmentId }]
    : [{ departmentId: null }, { departmentId: { $exists: false } }];
  const promise = SystemChangeControl.find({
    companyId,
    enabled: true,
    kind: { $in: ['baseline', 'exception'] },
    $and: [
      { $or: departmentScope },
      { $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }] },
    ],
  }).select('systemId kind category changeType target processName expectedState ticketReference createdAt')
    .sort({ kind: -1, createdAt: -1 })
    .limit(CONTROL_CACHE_MAX)
    .maxTimeMS(2000)
    .lean()
    .then(controls => {
      controlCache.set(key, { controls, expiresAt: Date.now() + CONTROL_CACHE_TTL_MS });
      trimCache();
      return controls;
    })
    .catch(error => {
      // Control-plane degradation must never stop endpoint telemetry ingestion.
      console.warn('[system-change controls] lookup failed; ingesting without control match:', error.message);
      controlCache.set(key, { controls: [], expiresAt: Date.now() + 5000 });
      return [];
    });
  controlCache.set(key, { promise, expiresAt: Date.now() + CONTROL_CACHE_TTL_MS });
  return promise;
}

function severityFromRisk(riskScore) {
  const score = Number(riskScore || 0);
  if (score >= 80) return 'critical';
  if (score >= 60) return 'high';
  if (score >= 40) return 'medium';
  return 'low';
}

async function applySystemChangeControls(event) {
  if (!event?.companyId || !event.systemChangeCategory) return event;
  const controls = await loadControls(event.companyId, event.departmentId);
  const systemId = event.systemId ? String(event.systemId) : '';
  const applicable = controls.filter(control => !control.systemId || String(control.systemId) === systemId);
  const match = applicable.find(control => control.kind === 'exception' && controlMatches(control, event))
    || applicable.find(control => control.kind === 'baseline' && controlMatches(control, event));
  if (!match) return event;

  const indicators = Array.isArray(event.systemChangeIndicators) ? event.systemChangeIndicators : [];
  const isException = match.kind === 'exception';
  const riskScore = Math.min(Number(event.riskScore || 0), isException ? 19 : 39);
  event.riskScore = riskScore;
  event.severity = severityFromRisk(riskScore);
  event.baselineStatus = isException ? 'exception' : 'approved';
  event.maintenanceApproved = true;
  event.changeTicket = match.ticketReference || event.changeTicket;
  event.systemChangeIndicators = [...new Set([...indicators, isException ? 'approved_exception' : 'approved_baseline'])];
  return event;
}

function invalidateSystemChangeControlCache(companyId) {
  const prefix = `${String(companyId)}:`;
  [...controlCache.keys()].filter(key => key.startsWith(prefix)).forEach(key => controlCache.delete(key));
}

module.exports = {
  applySystemChangeControls,
  controlMatches,
  invalidateSystemChangeControlCache,
};
