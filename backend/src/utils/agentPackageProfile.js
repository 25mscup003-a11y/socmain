'use strict';

const PACKAGE_META = Object.freeze({
  deb: { buildFn: 'deb', ext: 'linux.deb', platform: 'linux', suffix: 'linux-deb' },
  rpm: { buildFn: 'rpm', ext: 'linux.rpm', platform: 'linux', suffix: 'linux-rpm' },
  exe: { buildFn: 'exe', ext: 'windows-exe.exe', platform: 'windows', suffix: 'windows-exe' },
  msi: { buildFn: 'msi', ext: 'windows-msi.msi', platform: 'windows', suffix: 'windows-msi' },
  macpkg: { buildFn: 'macpkg', ext: 'macos.pkg', platform: 'macos', suffix: 'macos-pkg' },
  dmg: { buildFn: 'dmg', ext: 'macos.dmg', platform: 'macos', suffix: 'macos-dmg' },
  apk: { buildFn: 'apk', ext: 'android.apk', platform: 'android', suffix: 'android' },
  solaris: { buildFn: 'solaris', ext: 'solaris-zfs.sh', platform: 'solaris', suffix: 'solaris-zfs' },
});

const PACKAGE_ALIASES = Object.freeze({ pkg: 'macpkg' });

function normalizePackageType(value) {
  const type = String(value || '').trim().toLowerCase();
  return PACKAGE_ALIASES[type] || type;
}

function platformForSystem(system = {}) {
  const role = String(system.agentType || 'system').toLowerCase();
  const text = `${system.os || ''} ${system.osType || ''}`.toLowerCase();
  if (/iphone|ipad|ios|ipados/.test(text)) return 'ios';
  if (/android/.test(text) || (role === 'phone' && !text.trim())) return 'android';
  if (/windows|\bwin(?:32|64)?\b/.test(text)) return 'windows';
  if (/darwin|macos|mac os|osx/.test(text)) return 'macos';
  if (/solaris|sunos/.test(text)) return 'solaris';
  if (/linux|ubuntu|debian|mint|kali|rhel|red hat|centos|fedora|rocky|alma|suse/.test(text)) return 'linux';
  return '';
}

function allowedPackagesForSystem(system = {}) {
  switch (platformForSystem(system)) {
    case 'windows': return ['exe', 'msi'];
    case 'linux': return ['deb', 'rpm'];
    case 'macos': return ['macpkg', 'dmg'];
    case 'android': return ['apk'];
    case 'solaris': return ['solaris'];
    default: return [];
  }
}

function defaultPackageForSystem(system = {}) {
  const allowed = allowedPackagesForSystem(system);
  const preferred = normalizePackageType(system.preferredPackageType);
  if (allowed.includes(preferred)) return preferred;
  const text = `${system.os || ''} ${system.osType || ''}`.toLowerCase();
  if (allowed.includes('rpm') && /rhel|red hat|centos|fedora|rocky|alma|suse|rpm/.test(text)) return 'rpm';
  return allowed[0] || '';
}

function resolvePackageForSystem(system = {}, requestedType = 'auto') {
  const platform = platformForSystem(system);
  const allowed = allowedPackagesForSystem(system);
  if (!platform || platform === 'ios' || !allowed.length) {
    const error = new Error(platform === 'ios'
      ? 'iOS agent packages are not available yet.'
      : 'This system has no supported OS category. Edit/recreate it with Windows, Linux, macOS, Android, or Solaris selected.');
    error.code = 'AGENT_PLATFORM_REQUIRED';
    error.status = 400;
    throw error;
  }
  const requested = normalizePackageType(requestedType);
  const type = !requested || requested === 'auto' ? defaultPackageForSystem(system) : requested;
  if (!allowed.includes(type)) {
    const error = new Error(`Package ${requestedType} is not valid for ${platform}. Allowed: ${allowed.join(', ')}.`);
    error.code = 'AGENT_PACKAGE_OS_MISMATCH';
    error.status = 400;
    throw error;
  }
  return { type, ...PACKAGE_META[type], platform, allowed };
}

module.exports = {
  PACKAGE_META,
  normalizePackageType,
  platformForSystem,
  allowedPackagesForSystem,
  defaultPackageForSystem,
  resolvePackageForSystem,
};
