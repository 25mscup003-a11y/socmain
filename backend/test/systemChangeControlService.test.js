const test = require('node:test');
const assert = require('node:assert/strict');

const { controlMatches } = require('../src/services/systemChangeControl.service');

test('system-change controls require matching target and optional dimensions', () => {
  const event = {
    systemChangeCategory: 'critical_system_files',
    systemChangeType: 'modified',
    systemChangeTarget: 'C:\\Windows\\System32\\drivers\\etc\\hosts',
    processName: 'powershell.exe',
    newState: { hash: 'abc123' },
  };

  assert.equal(controlMatches({
    target: 'c:/windows/system32/*',
    category: 'critical_system_files',
    changeType: 'modified',
    processName: 'power*.exe',
  }, event), true);
  assert.equal(controlMatches({ target: '/etc/shadow' }, event), false);
  assert.equal(controlMatches({ target: 'c:/windows/system32/*', expectedState: { hash: 'different' } }, event), false);
});
