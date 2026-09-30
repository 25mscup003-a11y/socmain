/**
 * Constants and Configuration
 */

const os = require('os');

const PLATFORM = os.platform();
const IS_LINUX = PLATFORM === 'linux';
const IS_WIN = PLATFORM === 'win32';
const IS_MAC = PLATFORM === 'darwin';

const ACTIONS = {
  BLOCK: 'block',
  UNBLOCK: 'unblock',
};

const ENFORCEMENT_METHODS = {
  HOST_FIREWALL: 'host-firewall (nftables/windows-defender)',
  LOG_ONLY: 'log-only',
};

const getEnforcementMethod = () => {
  // IPS Webhook Server enforces locally through the host firewall where supported.
  return ENFORCEMENT_METHODS.HOST_FIREWALL;
};

module.exports = {
  PLATFORM,
  IS_LINUX,
  IS_WIN,
  IS_MAC,
  ACTIONS,
  ENFORCEMENT_METHODS,
  getEnforcementMethod,
};
