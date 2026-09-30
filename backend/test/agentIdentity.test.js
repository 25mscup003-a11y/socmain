const test = require('node:test');
const assert = require('node:assert/strict');
const {
  heartbeatMacAddress, identityMismatch, isTrustedMacRotation, normalizeMac,
} = require('../src/utils/agentIdentity');

const installed = {
  agentId: 'agent-windows-01',
  macAddress: 'AA:BB:CC:DD:EE:01',
  hostname: 'WIN-ENDPOINT',
  osType: 'Windows',
  installDate: new Date(),
};

test('accepts a NIC change for the same stable endpoint identity', () => {
  const heartbeat = {
    agentId: 'agent-windows-01',
    macAddress: 'AA:BB:CC:DD:EE:02',
    hostname: 'win-endpoint',
    osType: 'Windows',
  };
  assert.equal(isTrustedMacRotation(installed, heartbeat), true);
  assert.equal(identityMismatch(installed, heartbeat), null);
});

test('accepts a legacy desktop NIC change when signed-key hostname and OS still match', () => {
  assert.equal(identityMismatch(installed, {
    macAddress: 'AA:BB:CC:DD:EE:03',
    hostname: 'WIN-ENDPOINT',
    os: 'Windows',
  }), null);
});

test('still blocks a copied key from a different endpoint identity', () => {
  assert.match(identityMismatch(installed, {
    agentId: 'agent-windows-02',
    macAddress: 'AA:BB:CC:DD:EE:02',
    hostname: 'OTHER-PC',
    osType: 'Windows',
  }), /agentId mismatch/);
});

test('normalizes physical unicast MAC addresses and rejects multicast values', () => {
  assert.equal(normalizeMac('aa-bb-cc-dd-ee-01'), 'AA:BB:CC:DD:EE:01');
  assert.equal(normalizeMac('01:00:5e:00:00:01'), '');
});

test('normalizes both heartbeat MAC field names before identity persistence', () => {
  assert.equal(heartbeatMacAddress({ macAddress: 'aa-bb-cc-dd-ee-04' }), 'AA:BB:CC:DD:EE:04');
  assert.equal(heartbeatMacAddress({ mac_address: 'aa-bb-cc-dd-ee-05' }), 'AA:BB:CC:DD:EE:05');
});
