function normalizeMac(mac) {
  const normalized = String(mac || '').trim().replace(/-/g, ':').toUpperCase();
  if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(normalized)) return '';
  const octets = normalized.split(':').map(value => parseInt(value, 16));
  if (octets.every(value => value === 0) || (octets[0] & 1) === 1) return '';
  return normalized;
}

function heartbeatMacAddress(body = {}) {
  return normalizeMac(body.macAddress || body.mac_address);
}

function identityParts(system = {}, body = {}) {
  return {
    incomingAgentId: String(body.agentId || body.agent_id || '').trim(),
    incomingMac: normalizeMac(body.macAddress || body.mac_address),
    incomingHostname: String(body.hostname || '').trim().toLowerCase(),
    incomingOsType: String(body.osType || body.os_type || body.os || '').trim().toLowerCase(),
    storedAgentId: String(system.agentId || '').trim(),
    storedHostname: String(system.hostname || '').trim().toLowerCase(),
    storedOsType: String(system.osType || system.os || '').trim().toLowerCase(),
  };
}

function isTrustedMacRotation(system, body = {}) {
  const identity = identityParts(system, body);
  const sameAgentId = Boolean(identity.storedAgentId && identity.incomingAgentId
    && identity.storedAgentId === identity.incomingAgentId);
  const sameDesktopIdentity = Boolean(
    !identity.incomingAgentId
    && identity.storedHostname
    && identity.incomingHostname
    && identity.storedHostname === identity.incomingHostname
    && identity.storedOsType
    && identity.incomingOsType
    && identity.storedOsType === identity.incomingOsType
  );
  if (!sameAgentId && !sameDesktopIdentity) return false;
  if (identity.storedHostname && identity.incomingHostname && identity.storedHostname !== identity.incomingHostname) return false;
  if (identity.storedOsType && identity.incomingOsType && identity.storedOsType !== identity.incomingOsType) return false;
  return true;
}

function identityMismatch(system, body = {}) {
  const identity = identityParts(system, body);
  const legacyAndroidIdentityUpgrade = identity.incomingOsType === 'android'
    && identity.storedAgentId.startsWith('android-')
    && !identity.storedAgentId.startsWith('android-device-')
    && identity.incomingAgentId.startsWith('android-device-');

  if (identity.storedAgentId && identity.incomingAgentId
    && identity.storedAgentId !== identity.incomingAgentId
    && !legacyAndroidIdentityUpgrade) {
    return 'agentId mismatch: this agent key is already bound to another machine';
  }
  if (system.macAddress && identity.incomingMac
    && normalizeMac(system.macAddress) !== identity.incomingMac
    && !isTrustedMacRotation(system, body)) {
    return 'MAC mismatch: this agent key is already installed on another machine';
  }
  if (
    system.installDate
    && identity.storedHostname
    && identity.incomingHostname
    && identity.storedHostname !== identity.incomingHostname
    && identity.storedOsType
    && identity.incomingOsType
    && identity.storedOsType !== identity.incomingOsType
  ) {
    return 'hostname/OS mismatch: this agent key is already installed on another machine';
  }
  return null;
}

module.exports = { heartbeatMacAddress, identityMismatch, isTrustedMacRotation, normalizeMac };
