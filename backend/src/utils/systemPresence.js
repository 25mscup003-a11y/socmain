// Shared by the Systems inventory and country-policy synchronization views.
const ONLINE_THRESHOLD_MS = 10 * 60 * 1000;

function isSystemOnline(system, now = Date.now()) {
  const lastSeen = system.lastSeen ? new Date(system.lastSeen).getTime() : NaN;
  const age = now - lastSeen;
  return Boolean(system.isActive !== false
    && ['active', 'online'].includes(String(system.status || '').toLowerCase())
    && system.agentVersion
    && Number.isFinite(age) && age >= 0 && age < ONLINE_THRESHOLD_MS);
}

function systemConnectionState(system, now = Date.now()) {
  if (isSystemOnline(system, now)) return 'online';
  return !system.lastSeen && system.status === 'pending' ? 'not_connected' : 'offline';
}

module.exports = { ONLINE_THRESHOLD_MS, isSystemOnline, systemConnectionState };
