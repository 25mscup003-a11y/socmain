'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const {
  platformForSystem,
  resolvePackageForSystem,
} = require('../src/utils/agentPackageProfile');

test('auto package uses the system OS and saved package preference', () => {
  const windows = resolvePackageForSystem({
    agentType: 'system', osType: 'Windows', preferredPackageType: 'msi',
  }, 'auto');
  assert.equal(windows.platform, 'windows');
  assert.equal(windows.type, 'msi');
  assert.equal(windows.buildFn, 'msi');

  const linux = resolvePackageForSystem({
    agentType: 'server', os: 'RHEL / Rocky Linux Server', osType: 'Linux', preferredPackageType: 'rpm',
  }, 'auto');
  assert.equal(linux.platform, 'linux');
  assert.equal(linux.type, 'rpm');
});

test('package resolver rejects cross-OS downloads', () => {
  assert.throws(
    () => resolvePackageForSystem({ agentType: 'system', osType: 'Windows' }, 'deb'),
    error => error.code === 'AGENT_PACKAGE_OS_MISMATCH' && error.status === 400,
  );
});

test('package resolver requires a supported system category', () => {
  assert.throws(
    () => resolvePackageForSystem({ agentType: 'system' }, 'auto'),
    error => error.code === 'AGENT_PLATFORM_REQUIRED',
  );
  assert.equal(platformForSystem({ agentType: 'phone', osType: 'iOS' }), 'ios');
});
