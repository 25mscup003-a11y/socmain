const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('persistence APIs are authenticated, tenant scoped and mounted', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/persistence.routes.js');
  assert.match(server, /app\.use\('\/api\/persistence', persistenceRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['events', 'events/:id', 'alerts', 'hosts', 'techniques', 'statistics', 'timeline', 'export/csv', 'export/pdf']) {
    assert.match(routes, new RegExp(`router\\.get\\\('\\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /companyScope\(req/);
  assert.match(routes, /capabilityIds: 8/);
  assert.match(routes, /maxTimeMS\(5000\)/);
});

test('agent collectors emit persistence metadata for all supported OS families', () => {
  const assets = read('soc-agent/collectors/process_assets.py');
  const registry = read('soc-agent/core/registry_monitor.py');
  const kernel = read('soc-agent/collectors/kernel_monitor.py');
  const files = read('soc-agent/collectors/file_monitor.py');
  const sender = read('soc-agent/core/sender.py');
  assert.match(assets, /def _ssh_keys/);
  assert.match(assets, /def _wmi_subscriptions/);
  assert.match(assets, /def _browser_extensions/);
  assert.match(assets, /def _boot_configuration/);
  assert.match(assets, /T1546\.003/);
  assert.match(registry, /'capabilityIds':\s*\[6, 7\] \+ \(\[8\] if f\.get\('configuration_category'\) == 'persistence' else \[\]\)/);
  assert.match(kernel, /\[8, 19\] if persistence_change/);
  assert.match(files, /capability_ids\.add\(8\)/);
  assert.match(sender, /'persistenceType'/);
});

test('persistence events are normalized, indexed and streamed in direct and batch ingestion', () => {
  const model = read('src/models/Alert.model.js');
  const ingestion = read('src/routes/alert.routes.js');
  const migration = read('migrations/024-persistence-monitoring-indexes.js');
  const correlation = read('src/services/correlation.service.js');
  assert.match(model, /persistenceType:\s*\{ type: String, index: true \}/);
  assert.match(migration, /persistence_type_time/);
  assert.match(ingestion, /persistenceType: pickFirst/);
  assert.equal((ingestion.match(/emit\('persistence:event'/g) || []).length, 2);
  assert.match(migration, /\$addToSet:\s*\{ capabilityIds: 8 \}/);
  assert.match(correlation, /PERSISTENCE_MULTI_MECHANISM/);
});

test('capability 8 UI uses exact APIs and contains no fabricated persistence records', () => {
  const page = read('../company/src/pages/edrdashbordpage/Persistence Mechanism Detection.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('src/routes/dashboard.routes.js');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(page, /\/persistence\/events/);
  assert.match(page, /\/persistence\/export\/\$\{format\}/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{8\} alerts=\{alerts\}/);
  assert.match(reports, /title: 'Persistence Mechanism Detection'/);
  assert.match(reports, /socket\.on\('persistence:event'/);
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(8\)/);
  assert.match(dashboardRoutes, /scheduled_tasks:/);
  assert.match(dashboard, /api\.get\('\/persistence\/events'/);
  assert.match(dashboard, /socket\.on\('persistence:event'/);
  assert.match(dashboard, /import \{ PersistenceMechanismDashboard \}/);
  assert.doesNotMatch(page, /WIN-10-23-45|SystemUpdateChecker|backdoor\.exe|May 19, 2024|aW52b2tl/);
});
