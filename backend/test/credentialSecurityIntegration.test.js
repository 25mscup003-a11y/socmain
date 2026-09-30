const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('credential security APIs are mounted, authenticated, tenant scoped and actionable', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/credential-security.routes.js');
  assert.match(server, /app\.use\('\/api\/credential-security', credentialSecurityRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['dashboard', 'live', 'logs', 'log/:id', 'reports']) {
    assert.match(routes, new RegExp(`router\\.get\\('\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /router\.get\('\/configuration'/);
  assert.match(routes, /router\.put\('\/configuration', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/configuration\/policies', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/configuration\/policies\/:policyId\/apply', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/respond', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/export'/);
  assert.match(routes, /companyScope\(req/);
  assert.match(routes, /maxTimeMS: 15000/);
});

test('agent and ingestion preserve capability 13 evidence and realtime events', () => {
  const agent = read('soc-agent/agent.py');
  const credentialCollector = read('soc-agent/collectors/credential_security.py');
  const rules = read('soc-agent/detectors/rules.py');
  const sender = read('soc-agent/core/sender.py');
  const ingestion = read('src/routes/alert.routes.js');
  const model = read('src/models/Alert.model.js');
  const configurationModel = read('src/models/CredentialSecurityConfig.model.js');
  const agentRoutes = read('src/routes/agent.routes.js');
  assert.match(agent, /collectors\.credential_security/);
  assert.match(credentialCollector, /credential_security_monitoring_enabled/);
  assert.match(rules, /ids\.update\(\(4, 13\)\)/);
  assert.match(sender, /'credentialEventType'/);
  assert.match(ingestion, /normalizeCredentialTelemetry/);
  assert.match(ingestion, /emit\('credential:event'/);
  assert.match(model, /credentialEventType:/);
  assert.match(model, /authResult:/);
  assert.match(configurationModel, /scanIntervalSeconds:/);
  assert.match(configurationModel, /monitorLockScreen:/);
  assert.match(configurationModel, /manualPolicies:/);
  assert.match(agentRoutes, /credential_enabled_rule_ids:/);
  assert.match(agentRoutes, /credential_monitor_lock_screen_enabled:/);
  assert.match(agentRoutes, /credential_monitor_processes_enabled: true/);
  assert.match(agentRoutes, /credential_monitor_stores_enabled: true/);
  assert.match(agentRoutes, /credential_monitor_lock_screen_enabled: true/);
  assert.doesNotMatch(agentRoutes, /getCredentialSecurityConfig/);
  assert.match(agentRoutes, /credential_policy_version:/);
});

test('capability 13 UI uses dedicated realtime data without credential demo fallbacks', () => {
  const page = read('../company/src/pages/edrdashbordpage/Credential Security Monitoring.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('src/routes/dashboard.routes.js');
  assert.match(page, /\/credential-security\/dashboard/);
  assert.match(page, /\/credential-security\/reports/);
  assert.match(page, /socket\.on\('credential:event'/);
  assert.doesNotMatch(page, /id: 'configure'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{13\} alerts=\{rows\}/);
  assert.match(reports, /13:\s*\{/);
  assert.match(reports, /credential:event/);
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(13\)/);
  assert.match(dashboardRoutes, /lock_screen:/);
  assert.match(page, /\/configuration\/policies\/\$\{policyId\}\/apply/);
  assert.match(dashboard, /\/credential-security\/dashboard/);
  assert.match(dashboard, /import \{ CredentialSecurityDashboardPanel \} from '\.\/edrdashbordpage\/Credential Security Monitoring'/);
  assert.match(dashboard, /socket\.on\('credential:event'/);
  assert.doesNotMatch(page, /185\.220\.101\.5|203\.0\.113\.45|S-1-5-21-3623811015/);
});

test('credential dashboard uses one bounded faceted snapshot and 60 second polling', () => {
  const routes = read('src/routes/credential-security.routes.js');
  const page = read('../company/src/pages/edrdashbordpage/Credential Security Monitoring.jsx');
  assert.match(routes, /\$facet:\s*\{/);
  assert.match(routes, /const eventLimit = integer\(req\.query\.limit, 250, 1, 500\)/);
  assert.match(page, /setInterval\(\(\) => loadAlerts\(true\), 60000\)/);
  assert.doesNotMatch(page, /setInterval\(\(\) => loadAlerts\(true\), 15000\)/);
});
