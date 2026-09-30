const test = require('node:test');
const assert = require('node:assert/strict');
const {
  DESKTOP_CAPABILITIES,
  capabilityRuntimeState,
  desktopOs,
} = require('../src/utils/desktopCapabilities');

test('desktop matrix exposes each canonical capability exactly once', () => {
  assert.equal(DESKTOP_CAPABILITIES.length, 31);
  assert.deepEqual(DESKTOP_CAPABILITIES.map(item => item.id), Array.from({ length: 31 }, (_, index) => index + 1));
});

test('runtime state never claims reporting without telemetry', () => {
  const linux = { osType: 'Linux', edrEnabled: true, networkMonitorEnabled: true };
  const process = DESKTOP_CAPABILITIES.find(item => item.id === 1);
  const email = DESKTOP_CAPABILITIES.find(item => item.id === 15);
  assert.equal(desktopOs(linux), 'linux');
  assert.equal(capabilityRuntimeState(linux, process, 0, 0).status, 'enabled_no_telemetry');
  assert.equal(capabilityRuntimeState(linux, process, 4, 4).status, 'reporting');
  assert.equal(capabilityRuntimeState(linux, process, 0, 4).status, 'stale');
  assert.equal(capabilityRuntimeState(linux, email, 0, 0).status, 'dependency_required');
});

test('Windows kernel card requires an approved platform sensor when silent', () => {
  const windows = { os: 'Windows 10', edrEnabled: true };
  const kernel = DESKTOP_CAPABILITIES.find(item => item.id === 19);
  assert.equal(capabilityRuntimeState(windows, kernel, 0, 0).status, 'dependency_required');
});
