'use strict';

function resolveIdsHeartbeat(body = {}, system = {}) {
  const result = {};
  const os = String(body.osType || body.os || system.osType || system.os || '').toLowerCase();

  if (body.endpointIdsEnabled != null) {
    result.endpointIdsEnabled = Boolean(body.endpointIdsEnabled);
    result.idsEnabled = result.endpointIdsEnabled;
  } else {
    const legacyWindowsEndpointIds = os === 'windows'
      && body.idsEnabled === false
      && body.packetSensorAvailable === false
      && body.networkMonitorEnabled === true;
    if (legacyWindowsEndpointIds) {
      // Older Windows agents reported only full-packet sensor availability as
      // idsEnabled, despite their built-in Python endpoint IDS being active.
      result.endpointIdsEnabled = true;
      result.idsEnabled = true;
    } else if (body.idsEnabled != null) {
      result.idsEnabled = Boolean(body.idsEnabled);
      result.endpointIdsEnabled = result.idsEnabled;
    }
  }

  if (body.packetSensorAvailable != null) {
    result.packetSensorAvailable = Boolean(body.packetSensorAvailable);
  }
  return result;
}

module.exports = { resolveIdsHeartbeat };
