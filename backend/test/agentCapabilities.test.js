'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { resolveIdsHeartbeat } = require('../src/utils/agentCapabilities');

test('legacy Windows heartbeat reports built-in endpoint IDS independently of packet sensors', () => {
  assert.deepEqual(resolveIdsHeartbeat({
    osType: 'Windows',
    idsEnabled: false,
    packetSensorAvailable: false,
    networkMonitorEnabled: true,
  }), {
    idsEnabled: true,
    endpointIdsEnabled: true,
    packetSensorAvailable: false,
  });
});

test('explicit endpoint IDS status from current agents is authoritative', () => {
  assert.deepEqual(resolveIdsHeartbeat({
    osType: 'Windows',
    idsEnabled: true,
    endpointIdsEnabled: false,
    packetSensorAvailable: false,
  }), {
    idsEnabled: false,
    endpointIdsEnabled: false,
    packetSensorAvailable: false,
  });
});

test('non-Windows legacy IDS status is preserved', () => {
  assert.deepEqual(resolveIdsHeartbeat({ osType: 'Linux', idsEnabled: false }), {
    idsEnabled: false,
    endpointIdsEnabled: false,
  });
});
