'use strict';

const net = require('net');

function coordinate(value, minimum, maximum) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) && number >= minimum && number <= maximum ? number : null;
}

function isPublicRoutableIp(value) {
  let ip = String(value || '').trim().toLowerCase();
  if (ip.startsWith('::ffff:') && net.isIP(ip.slice(7)) === 4) ip = ip.slice(7);
  const version = net.isIP(ip);
  if (version === 4) {
    const octets = ip.split('.').map(Number);
    return !(octets[0] === 0 || octets[0] === 10 || octets[0] === 127 || octets[0] >= 224
      || (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127)
      || (octets[0] === 169 && octets[1] === 254)
      || (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31)
      || (octets[0] === 192 && octets[1] === 168));
  }
  if (version === 6) {
    return !(ip === '::' || ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd') || ip.startsWith('fe8') || ip.startsWith('fe9') || ip.startsWith('fea') || ip.startsWith('feb'));
  }
  return false;
}

function isMapEligibleAttack(alert = {}) {
  // This is an IDS/IPS/WAF monitor, so a public source observed by an IDS
  // sensor remains useful map evidence even when Zeek classified it as a
  // protocol anomaly. The UI labels it as monitored activity, not as a
  // confirmed attack. Private/local addresses still must not be geolocated.
  return isPublicRoutableIp(alert.srcip || alert.srcIp);
}

function buildGpsDestinationMap(rows = [], maximumAccuracyMeters = 50) {
  const positions = new Map();
  for (const row of rows) {
    const latitude = coordinate(row.gpsLat, -90, 90);
    const longitude = coordinate(row.gpsLon, -180, 180);
    const systemId = row.systemId || row._id ? String(row.systemId || row._id) : '';
    const accuracy = Number(row.gpsAccuracyMeters);
    if (!systemId || positions.has(systemId) || latitude === null || longitude === null
      || !Number.isFinite(accuracy) || accuracy < 0 || accuracy > maximumAccuracyMeters) continue;
    positions.set(systemId, {
      dstSystemId: systemId,
      dstLat: latitude,
      dstLon: longitude,
      dstName: row.agentName || row.name || row.hostname || 'Unnamed endpoint',
      dstLocationSource: row.gpsProvider
        ? `AJNAT ${row.gpsProvider}${Number.isFinite(accuracy) ? ` (±${Math.round(accuracy)} m)` : ''}`
        : 'AJNAT native location',
      dstLocationPrecision: accuracy <= 50 ? 'precise' : 'approximate',
      dstGpsAccuracyMeters: accuracy,
      dstGpsObservedAt: row.gpsObservedAt || row.createdAt || null,
    });
  }
  return positions;
}

function buildAgentFlowSummary(systems = [], counts = [], totals = {}, positions = new Map()) {
  const countsBySystem = new Map(counts.map(item => [String(item._id || ''), Number(item.count || 0)]));
  const agents = systems.map(system => {
    const systemId = String(system._id || system.systemId || '');
    const name = system.name || system.hostname || 'Unnamed endpoint';
    const sensors = [];
    if (system.idsEnabled !== false || system.endpointIdsEnabled === true) sensors.push('IDS');
    if (system.ipsEnabled === true) sensors.push('IPS');
    if (system.wafEnabled === true) sensors.push('WAF');
    if (system.packetSensorAvailable === true) sensors.push('Packet sensor');
    const eventCount = countsBySystem.get(systemId) || 0;
    const location = positions.get(systemId) || {};
    return {
      systemId,
      agentId: system.agentId || null,
      name,
      label: `AJNAT Agent — ${name}`,
      hostname: system.hostname || name,
      ip: system.ip || null,
      status: system.status || 'unknown',
      lastSeen: system.lastSeen || null,
      sensors,
      inputEvents: eventCount,
      outputEvents: eventCount,
      ...location,
    };
  });
  const totalEvents = Math.max(0, Number(totals.totalEvents || 0));
  const assignedEvents = agents.reduce((sum, agent) => sum + agent.inputEvents, 0);
  const activeAgentCount = agents.filter(agent => ['active', 'online'].includes(String(agent.status || '').toLowerCase())).length;
  return {
    windowHours: Math.max(1, Number(totals.hours || 24)),
    totalEvents,
    mappedEvents: Math.max(0, Number(totals.mappedEvents || 0)),
    idsIpsEvents: Math.max(0, Number(totals.idsIpsEvents || 0)),
    idsDetectedEvents: Math.max(0, Number(totals.idsDetectedEvents || 0)),
    ipsBlockedEvents: Math.max(0, Number(totals.ipsBlockedEvents || 0)),
    wafEvents: Math.max(0, Number(totals.wafEvents || 0)),
    activeBlockEvents: Math.max(0, Number(totals.activeBlockEvents || 0)),
    monitoredAgentCount: agents.length,
    activeAgentCount,
    assignedAgentEvents: assignedEvents,
    unassignedSensorEvents: Math.max(0, totalEvents - assignedEvents),
    inputEvents: totalEvents,
    outputEvents: totalEvents,
    flow: ['Network / sensor input', 'AJNAT security agent', 'SOC database output'],
    agents,
  };
}

function destinationForAlert(alert = {}, positions = new Map()) {
  const systemId = alert.systemId ? String(alert.systemId) : '';
  if (systemId && positions.has(systemId)) return positions.get(systemId);
  // Legacy IDS/WAF events may not carry systemId. Reuse a company destination
  // only when there is exactly one GPS-reporting endpoint, avoiding a wrong
  // cross-agent location in multi-endpoint tenants.
  if (positions.size === 1) return positions.values().next().value;
  return null;
}

module.exports = {
  buildGpsDestinationMap,
  destinationForAlert,
  buildAgentFlowSummary,
  isPublicRoutableIp,
  isMapEligibleAttack,
};
