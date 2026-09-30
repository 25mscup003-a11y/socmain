const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('registry monitoring APIs are authenticated, tenant scoped and mounted', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/registry-monitoring.routes.js');
  assert.match(server, /app\.use\('\/api\/registry-monitoring', registryMonitoringRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  assert.match(routes, /resolveCapabilityDepartmentScope/);
  assert.match(routes, /isSynthetic:\s*\{ \$ne: true \}/);
  assert.match(routes, /requireCompanyAdmin/);
  for (const route of ['dashboard', 'events', 'statistics', 'timeline', 'policies', 'baselines']) {
    assert.match(routes, new RegExp(`router\\.get\\('\\/${route}`));
  }
  for (const route of ['policies', 'baselines/approve', 'exceptions', 'acknowledge', 'investigate', 'resolve', 'export']) {
    assert.match(routes, new RegExp(`router\\.post\\('\\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /signals:\s*\[\{ \$group:/);
  for (const signal of ['runKeys', 'services', 'defender', 'firewall', 'uac', 'rdp', 'sudoers', 'cron', 'ssh', 'dnsProxy', 'packages', 'auditTampering', 'solarisSmf', 'solarisZfs']) {
    assert.match(routes, new RegExp(`${signal}:\\s*\\{ \\$sum:`));
  }
});

test('capability 6 telemetry is normalized, policy evaluated, indexed and streamed', () => {
  const model = read('src/models/Alert.model.js');
  const ingestion = read('src/routes/alert.routes.js');
  const migration = read('migrations/026-registry-monitoring-indexes.js');
  const agentRoutes = read('src/routes/agent.routes.js');
  const sender = read('soc-agent/core/sender.py');
  const windowsEvents = read('soc-agent/collectors/windows_process_events.py');
  assert.match(model, /configurationCategory:\s*\{ type: String, index: true \}/);
  assert.match(model, /configurationPolicyViolation:\s*\{ type: Boolean/);
  assert.match(ingestion, /normalizeRegistryConfigurationTelemetry/);
  assert.match(ingestion, /applyRegistryConfigurationPolicies/);
  assert.equal((ingestion.match(/emit\('registry:event'/g) || []).length, 2);
  assert.match(migration, /registry_configuration_category_time/);
  assert.match(migration, /\$addToSet:\s*\{ capabilityIds: 6 \}/);
  assert.match(agentRoutes, /registry_monitor_paths: configuredMonitorPaths/);
  assert.match(agentRoutes, /configuration_monitor_paths: configuredMonitorPaths/);
  assert.match(sender, /'configurationCategory': alert\.get\('configurationCategory'\)/);
  assert.match(sender, /'processAttribution': alert\.get\('processAttribution'\)/);
  assert.match(windowsEvents, /capabilityIds=\[1, 6, 7\] \+ \(\[8\] if config_category == 'persistence' else \[\]\)/);
  assert.match(windowsEvents, /process_attribution='sysmon_exact'/);
});

test('registry policy matching is narrow and supports approved baselines', () => {
  const service = require('../src/services/registryConfigurationPolicy.service');
  const event = { configurationCategory: 'persistence', configurationOperation: 'modify', configurationObject: 'HKLM\\Software\\AJNAT\\Run' };
  assert.equal(service.controlMatches({ category: 'persistence', operation: 'modify', target: 'HKLM\\Software\\*' }, event), true);
  assert.equal(service.controlMatches({ category: 'security_configuration', target: '*' }, event), false);
  assert.equal(service.controlMatches({ category: 'persistence', operation: 'delete', target: '*' }, event), false);
});

test('registry UI consumes dedicated live APIs and contains no fabricated evidence', () => {
  const page = read('../company/src/pages/edrdashbordpage/Registry Monitoring.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(page, /\/registry-monitoring\/dashboard/);
  assert.match(page, /\/registry-monitoring\/export/);
  assert.match(page, /socket\.on\('registry:event'/);
  assert.match(dashboard, /api\.get\('\/registry-monitoring\/dashboard'/);
  assert.match(dashboard, /socket\.on\('registry:event-updated'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{6\} alerts=\{alerts\} \/>/);
  assert.match(reports, /title: 'Registry & System Configuration Monitoring'/);
  assert.match(reports, /\['Registry Key \/ Configuration Path'/);
  assert.match(reports, /socket\.on\('registry:policy-updated', scheduleDeletedRefresh\)/);
  assert.doesNotMatch(page, /1,248|WIN-SRV-DC01|LIN-SRV-WEB01|SOL-SRV-APP01|SecurityHealthService|a8f09b/);
});

test('unified capability report supports registry categories and forensic fields', () => {
  const dashboardRoutes = read('src/routes/dashboard.routes.js');
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(6\)/);
  for (const category of ['persistence', 'security', 'identity', 'network', 'permissions', 'policy', 'critical']) {
    assert.match(dashboardRoutes, new RegExp(`\\b${category}:`));
  }
  assert.match(dashboardRoutes, /configurationCategory configurationOperation configurationObject configurationPlatform/);
  assert.match(dashboardRoutes, /configurationPolicyViolation configurationRiskFactors/);
});
