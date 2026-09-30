/**
 * Package prebuild utility
 *
 * Agent packages contain per-system config/secrets. We intentionally do not
 * prebuild/cache finished packages because company_config.json is injected at
 * download time.
 */

const AGENT_VERSION = process.env.AGENT_VERSION || '0.1.10';
const PACKAGE_TYPES = ['deb', 'rpm', 'exe', 'msi', 'pkg', 'macpkg', 'dmg', 'zip', 'apk', 'solaris'];

function arePackagesCached(companyId) {
  return {
    cached: false,
    missing: PACKAGE_TYPES,
    reason: 'Packages are built at download time and are not stored on the server.',
  };
}

// Log with formatting
function log(msg, icon = 'ℹ️') {
  const ts = new Date().toISOString().split('T')[1].split('.')[0];
  console.log(`${icon} [${ts}] ${msg}`);
}

/**
 * Build all packages for a company
 * @param {Object} company - Company document
 * @param {Object} system - System document
 * @param {Function} buildDeb - Builder function
 * @param {Function} buildRpm - Builder function
 * @param {Function} buildExe - Builder function
 * @param {Function} buildPkg - Builder function
 * @param {Function} buildConfig - Config builder function (from agent.routes)
 * @returns {Promise<Object>} { built: [], failed: [], stats: {...} }
 */
async function prebuildPackages(company) {
  const skipped = PACKAGE_TYPES.map(type => ({
    type,
    reason: 'download_time_config_injection',
  }));
  log(`Package builders ready for ${company?.name || 'company'}: company_config.json will be injected at download time.`, '🔐');

  return {
    built: [],
    failed: [],
    skipped,
    stats: {
      totalSize: 0,
      timestamp: new Date().toISOString(),
    },
  };
}

module.exports = {
  arePackagesCached,
  prebuildPackages,
  PACKAGE_TYPES,
  log,
  AGENT_VERSION,
};
