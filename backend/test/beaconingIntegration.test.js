const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');
const {
  BEACON_BUILTIN_RULES,
  calculateBeaconMetrics,
  observeBeaconSnapshot,
} = require('../src/services/networkMonitoring.service');

test('beaconing telemetry is connected from agent policy to tenant websocket and reports', () => {
  const heartbeat = read('backend/src/routes/agent.routes.js');
  const alerts = read('backend/src/routes/alert.routes.js');
  const reports = read('backend/src/routes/dashboard.routes.js');
  const dashboard = read('company/src/pages/edrdashbordpage/Beaconing Detection.jsx');
  const collector = read('backend/soc-agent/collectors/network.py');

  for (const setting of [
    'beacon_detection_enabled', 'beacon_min_connections',
    'beacon_min_interval_seconds', 'beacon_max_interval_seconds',
    'beacon_min_observation_seconds', 'beacon_consistency_threshold',
    'beacon_alert_threshold', 'beacon_alert_cooldown_seconds',
    'beacon_enabled_rule_ids', 'beacon_custom_rules',
  ]) assert.match(heartbeat, new RegExp(setting), `heartbeat missing ${setting}`);

  assert.match(heartbeat, /NetworkPolicy\.find\(/);
  assert.match(alerts, /company:\$\{a\.companyId\}`\)\.emit\('beaconing:event'/);
  assert.match(reports, /26:\s*\{[\s\S]*low_slow:/);
  assert.match(dashboard, /socket\.on\('beaconing:event', refresh\.add\)/);
  assert.match(collector, /def _matching_beacon_rules/);
  assert.match(collector, /'matched_patterns': matched_rules/);
  assert.doesNotMatch(dashboard, /THREAT SCORE: 92\/100/);
});

test('beaconing destination intelligence evaluates the remote endpoint, not the local source', () => {
  const alerts = read('backend/src/routes/alert.routes.js');
  const intel = read('backend/src/services/threat-intel.service.js');
  assert.match(alerts, /const reputationIp = alert\.destip \|\| srcip/);
  assert.doesNotMatch(intel, /capabilityIds:\s*29/);
});

test('beaconing configure and report tabs use existing policy, heartbeat and report pipelines', () => {
  const networkRoutes = read('backend/src/routes/network.routes.js');
  const heartbeat = read('backend/src/routes/agent.routes.js');
  const dashboard = read('company/src/pages/edrdashbordpage/Beaconing Detection.jsx');
  assert.ok(BEACON_BUILTIN_RULES.length >= 6);
  assert.match(networkRoutes, /router\.get\('\/beaconing\/configuration'/);
  assert.match(networkRoutes, /router\.put\('\/beaconing\/configuration'/);
  assert.match(networkRoutes, /router\.post\('\/beaconing\/configuration\/rules'/);
  assert.match(networkRoutes, /router\.patch\('\/beaconing\/configuration\/rules\/:ruleId'/);
  assert.match(heartbeat, /beaconBaselinePolicy/);
  assert.match(heartbeat, /beacon_detection_enabled: beaconDetectionEnabled/);
  assert.match(dashboard, /label: 'Configure'/);
  assert.match(dashboard, /api\.post\('\/network\/beaconing\/configuration\/rules'/);
  assert.match(dashboard, /Add & Deploy Rule/);
  assert.match(dashboard, /CapabilityReportsPanel capabilityId=\{26\}/);
  assert.match(dashboard, /configuration\/rules\/\$\{encodeURIComponent\(editingRuleId\)\}/);
  assert.match(dashboard, /onClick=\{\(\) => editBeaconRule\(rule\)\}/);
  assert.match(dashboard, /C2 Containment Response/);
  assert.match(dashboard, /beaconing-c2-containment/);
});

test('backend fallback correlates real new-socket callbacks without treating one long-lived socket as a beacon', () => {
  const config = {
    minimumConnections: 6,
    minimumInterval: 5,
    maximumInterval: 3600,
    minimumObservation: 60,
    consistencyThreshold: 75,
    alertThreshold: 70,
    cooldownSeconds: 1800,
  };
  const base = Date.parse('2026-08-30T00:00:00.000Z');
  const alert = offset => ({
    companyId: 'company-periodic-test',
    systemId: 'system-periodic-test',
    agentId: 'agent-periodic-test',
    createdAt: new Date(base + offset * 1000),
  });
  const peer = localPort => ({
    pid: 4242,
    local_ip: '10.0.0.2',
    local_port: localPort,
    remote_ip: '203.0.113.44',
    remote_port: 443,
    protocol: 'https',
  });

  // Re-observing the same socket only establishes/maintains a baseline.
  for (let index = 0; index < 8; index += 1) {
    assert.equal(observeBeaconSnapshot(alert(index * 60), [peer(50000)], config).length, 0);
  }

  let candidates = [];
  for (let index = 8; index < 15; index += 1) {
    candidates = observeBeaconSnapshot(alert(index * 60), [peer(50000 + index)], config);
  }
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].metrics.count, 7);
  assert.equal(Math.round(candidates[0].metrics.averageInterval), 60);
  assert.ok(candidates[0].metrics.intervalConsistency >= 99);
});

test('beacon interval metrics retain jitter instead of requiring exact timing', () => {
  const base = Date.parse('2026-08-30T00:00:00.000Z');
  const metrics = calculateBeaconMetrics([0, 60, 123, 180, 241, 300, 364].map(seconds => new Date(base + seconds * 1000)));
  assert.equal(metrics.count, 7);
  assert.ok(metrics.averageInterval >= 59 && metrics.averageInterval <= 61);
  assert.ok(metrics.jitterSeconds > 1);
  assert.ok(metrics.intervalConsistency > 90);
});
