const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('memory overflow API is tenant scoped, RBAC protected, and realtime enabled', () => {
  const route = read('backend/src/routes/memory-overflow.routes.js');
  const ingestion = read('backend/src/routes/alert.routes.js');
  const server = read('backend/src/server.js');
  assert.match(server, /app\.use\('\/api\/memory-overflow'/);
  assert.match(route, /router\.use\(authenticate, requireAnalyst\)/);
  assert.match(route, /router\.post\('\/rules', requireManager/);
  assert.match(route, /router\.post\('\/events\/:id\/notes'/);
  assert.match(route, /companyScope\(req\)/);
  assert.match(route, /source: 'memory_overflow_detector'/);
  assert.match(route, /ruleId: \/\^\(\?:MEM-/);
  assert.match(route, /MEM_TOP_CONSUMER/);
  assert.match(route, /activityMetrics/);
  assert.match(ingestion, /memory:metric/);
  assert.match(route, /memory:alert-updated/);
  assert.match(route, /MEMORY_SIMULATION_ENABLED/);
});

test('memory dashboard uses live API/metrics and contains no fabricated analyst identity', () => {
  const source = read('company/src/pages/edrdashbordpage/Memory Overflow Detection.jsx');
  assert.match(source, /\/memory-overflow\/overview/);
  assert.match(source, /filter\(isMemoryOverflowEvidence\)/);
  assert.match(source, /sourceAlerts\.filter\(isMemoryOverflowEvidence\)/);
  assert.match(source, /memory:metric/);
  assert.match(source, /memoryMetrics/);
  assert.match(source, /\/memory-overflow\/events\/\$\{log\._id\}\/notes/);
  assert.doesNotMatch(source, /Alex Turner|Sarah Connor|SAMPLE_MEM_LOGS|PAGE_EXECUTE_READWRITE \(RWX\)/);
});

test('USB policy API validates input, audits mutations, and synchronizes in realtime', () => {
  const route = read('backend/src/routes/usb-policy.routes.js');
  const ui = read('company/src/pages/edrdashbordpage/Device Control (USB) Monitoring.jsx');
  const heartbeat = read('backend/src/routes/agent.routes.js');
  assert.match(route, /RULE_TYPES/);
  assert.match(route, /requireManager/);
  assert.match(route, /usb\.policy\.created/);
  assert.match(route, /usb\.policy\.updated/);
  assert.match(route, /usb\.policy\.deleted/);
  assert.match(route, /usb-policy:updated/);
  assert.match(ui, /socket\.on\('usb-policy:updated'/);
  assert.match(heartbeat, /usb_policies:/);
});

test('USB investigation uses real scoped hunts and contains no fabricated evidence identities', () => {
  const ui = read('company/src/pages/edrdashbordpage/Device Control (USB) Monitoring.jsx');
  const collector = read('backend/soc-agent/collectors/usb.py');
  assert.match(ui, /api\.post\('\/forensics\/hunts'/);
  assert.match(ui, /Hunt not sent: this event has no tenant-scoped endpoint ID/);
  assert.doesNotMatch(ui, /Alex Turner|Michael Scott|Sarah Connor|WIN-FIN|WIN-SOC|john\.doe|CASE-2026|c2-beacon|Passwords\.txt/);
  assert.doesNotMatch(ui, /`CASE-\$\{/);
  assert.match(collector, /self\._watched_mounts/);
  assert.match(collector, /def _start_mount_watch/);
});

test('memory migration provisions query indexes and retention uses expiresAt', () => {
  const migration = read('backend/migrations/013-memory-overflow-indexes.js');
  const alerts = read('backend/src/models/Alert.model.js');
  assert.match(migration, /memory_event_triage/);
  assert.match(migration, /memory_metric_host_time/);
  assert.match(alerts, /expires_at_ttl/);
  assert.match(alerts, /detectionRuleId/);
});

test('normal memory monitoring never recommends automatic memory dumps', () => {
  const scanner = read('backend/soc-agent/core/memory_scanner.py');
  const detector = read('backend/soc-agent/core/memory_overflow.py');
  assert.doesNotMatch(scanner, /capture memory dump/i);
  assert.doesNotMatch(detector, /capture memory dump/i);
});
