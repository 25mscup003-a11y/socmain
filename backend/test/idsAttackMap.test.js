const test = require('node:test');
const assert = require('node:assert/strict');

const {
  buildGpsDestinationMap,
  destinationForAlert,
  buildAgentFlowSummary,
  isPublicRoutableIp,
  isMapEligibleAttack,
} = require('../src/services/idsAttackMap.service');

test('IDS attack map uses the newest sufficiently accurate GPS position for the matching agent', () => {
  const positions = buildGpsDestinationMap([
    { systemId: 'agent-1', agentName: 'linux1', gpsLat: 27.0519, gpsLon: 82.2296, gpsAccuracyMeters: 25, gpsProvider: 'geoclue' },
    { systemId: 'agent-1', agentName: 'linux1', gpsLat: 28.4601, gpsLon: 77.0263, gpsAccuracyMeters: 10 },
  ]);
  assert.deepEqual(destinationForAlert({ systemId: 'agent-1' }, positions), {
    dstSystemId: 'agent-1',
    dstLat: 27.0519,
    dstLon: 82.2296,
    dstName: 'linux1',
    dstLocationSource: 'AJNAT geoclue (±25 m)',
    dstLocationPrecision: 'precise',
    dstGpsAccuracyMeters: 25,
    dstGpsObservedAt: null,
  });
});

test('IDS map summary links live sensor input through named AJNAT agents to SOC output', () => {
  const positions = buildGpsDestinationMap([
    { systemId: 'agent-1', gpsLat: 28.6, gpsLon: 77.2, gpsAccuracyMeters: 10 },
  ]);
  const summary = buildAgentFlowSummary([
    {
      _id: 'agent-1', agentId: 'device-1', name: 'CHAUDHARY', hostname: 'linux1',
      ip: '10.0.0.5', status: 'active', idsEnabled: true, ipsEnabled: true,
      wafEnabled: true, packetSensorAvailable: true,
    },
  ], [{ _id: 'agent-1', count: 42 }], {
    hours: 24, totalEvents: 50, mappedEvents: 20, idsIpsEvents: 45,
    idsDetectedEvents: 35, ipsBlockedEvents: 10, wafEvents: 5,
  }, positions);
  assert.equal(summary.monitoredAgentCount, 1);
  assert.equal(summary.activeAgentCount, 1);
  assert.equal(summary.inputEvents, 50);
  assert.equal(summary.outputEvents, 50);
  assert.equal(summary.idsDetectedEvents, 35);
  assert.equal(summary.ipsBlockedEvents, 10);
  assert.equal(summary.unassignedSensorEvents, 8);
  assert.equal(summary.agents[0].label, 'AJNAT Agent — CHAUDHARY');
  assert.deepEqual(summary.agents[0].sensors, ['IDS', 'IPS', 'WAF', 'Packet sensor']);
  assert.equal(summary.agents[0].dstLat, 28.6);
});

test('IDS attack map never invents a destination when no GPS telemetry exists', () => {
  assert.equal(destinationForAlert({ systemId: 'agent-1' }, new Map()), null);
});

test('IDS attack map rejects coarse location instead of showing a wrong agent position', () => {
  const positions = buildGpsDestinationMap([
    { systemId: 'agent-1', gpsLat: 27.0519, gpsLon: 82.2296, gpsAccuracyMeters: 25000 },
  ], 50);
  assert.equal(destinationForAlert({ systemId: 'agent-1' }, positions), null);
});

test('IDS attack map can explicitly display an approximate current agent location', () => {
  const positions = buildGpsDestinationMap([
    { _id: 'agent-1', name: 'linux1', gpsLat: 25.6952, gpsLon: 81.9234, gpsAccuracyMeters: 25000, gpsProvider: 'geoclue' },
  ], 50000);
  assert.deepEqual(destinationForAlert({ systemId: 'agent-1' }, positions), {
    dstSystemId: 'agent-1',
    dstLat: 25.6952,
    dstLon: 81.9234,
    dstName: 'linux1',
    dstLocationSource: 'AJNAT geoclue (±25000 m)',
    dstLocationPrecision: 'approximate',
    dstGpsAccuracyMeters: 25000,
    dstGpsObservedAt: null,
  });
});

test('legacy event without systemId uses GPS only for an unambiguous single agent', () => {
  const one = buildGpsDestinationMap([{ systemId: 'agent-1', gpsLat: 0, gpsLon: 0, gpsAccuracyMeters: 10 }]);
  assert.equal(destinationForAlert({}, one).dstLat, 0);
  const two = buildGpsDestinationMap([
    { systemId: 'agent-1', gpsLat: 0, gpsLon: 0, gpsAccuracyMeters: 10 },
    { systemId: 'agent-2', gpsLat: 1, gpsLon: 1, gpsAccuracyMeters: 10 },
  ]);
  assert.equal(destinationForAlert({}, two), null);
});

test('IDS monitor map accepts public sensor origins and rejects local sources', () => {
  assert.equal(isPublicRoutableIp('8.8.8.8'), true);
  assert.equal(isPublicRoutableIp('10.126.148.104'), false);
  assert.equal(isPublicRoutableIp('::ffff:10.126.148.104'), false);
  assert.equal(isMapEligibleAttack({ srcip: '8.8.8.8', source: 'suricata', ruleId: 'ET_EXPLOIT' }), true);
  assert.equal(isMapEligibleAttack({ srcip: '8.8.8.8', source: 'zeek', ruleId: 'ZEEK_weird' }), true);
  assert.equal(isMapEligibleAttack({ srcip: '192.168.1.5', source: 'suricata', ruleId: 'ET_SCAN' }), false);
});
