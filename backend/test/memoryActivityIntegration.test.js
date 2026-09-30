const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('memory activity API is mounted, authenticated and tenant scoped', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/memory-activity.routes.js');
  assert.match(server, /app\.use\('\/api\/memory-activity', require\('\.\/routes\/memory-activity\.routes'\)\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  assert.match(routes, /resolveCapabilityDepartmentScope/);
  assert.match(routes, /isSynthetic:\s*\{ \$ne: true \}/);
  for (const endpoint of ['dashboard', 'events', 'metrics', 'timeline']) {
    assert.match(routes, new RegExp(`router\\.get\\('\\/${endpoint}`));
  }
  assert.match(routes, /router\.post\('\/events\/:id\/notes'/);
});

test('capability 5 telemetry is normalized and streamed through the existing pipeline', () => {
  const sender = read('soc-agent/core/sender.py');
  const scanner = read('soc-agent/core/memory_scanner.py');
  const windows = read('soc-agent/collectors/windows_process_events.py');
  const ingestion = read('src/routes/alert.routes.js');
  assert.match(scanner, /'memory_metric_type': 'host'/);
  assert.match(scanner, /'memory_metric_type': 'process'/);
  assert.match(scanner, /'capabilityIds': \[CAPABILITY_ID, 29\]/);
  assert.match(windows, /'capabilityIds': \[1, 5, 29\]/);
  assert.match(sender, /'source_process_name'/);
  assert.match(sender, /'memory_protection'/);
  assert.match(ingestion, /hasCapability\(alert, 5\) \|\| hasCapability\(alert, 29\)/);
});

test('memory UI uses dedicated live data and has no fabricated forensic defaults', () => {
  const page = read('../company/src/pages/edrdashbordpage/Memory Activity Monitoring.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(page, /api\.get\('\/memory-activity\/dashboard'/);
  assert.match(page, /socket\.on\('memory:metric'/);
  assert.match(dashboard, /api\.get\('\/memory-activity\/dashboard'/);
  assert.doesNotMatch(page, /SOC-MEM-AGENT-05|MEM_CobaltStrike|Michael Chang|0x00400000|22\.4 GB|mimikatz-like access/);
});

test('historical capability report supports memory categories and excludes metrics', () => {
  const routes = read('src/routes/dashboard.routes.js');
  assert.match(routes, /allowedCapabilities\.add\(5\)/);
  for (const category of ['injection', 'credential_theft', 'fileless', 'executable_memory', 'corruption', 'kernel_dll', 'critical']) {
    assert.match(routes, new RegExp(`\\b${category}:`));
  }
  assert.match(routes, /capabilityId === 5/);
  assert.match(routes, /eventType: 'memory\.metric'/);
});
