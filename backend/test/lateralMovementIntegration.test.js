const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('lateral movement APIs are mounted, authenticated, scoped and actionable', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/lateral-movement.routes.js');
  assert.match(server, /app\.use\('\/api\/lateral-movement', lateralMovementRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['dashboard', 'live', 'logs', 'log/:id', 'reports']) {
    assert.match(routes, new RegExp(`router\\.get\\('\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /router\.post\('\/respond', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/export'/);
  assert.match(routes, /companyScope\(req\)/);
});

test('agent and ingestion preserve capability 14 fields and realtime events', () => {
  const agent = read('soc-agent/agent.py');
  const sender = read('soc-agent/core/sender.py');
  const ingestion = read('src/routes/alert.routes.js');
  const network = read('soc-agent/collectors/network.py');
  assert.match(agent, /collectors\.lateral_movement/);
  assert.match(sender, /'lateralVector'/);
  assert.match(ingestion, /normalizeLateralTelemetry/);
  assert.match(ingestion, /emit\('lateral:event'/);
  assert.match(network, /'capabilityIds': \[3, 14\]/);
});

test('capability 14 UI uses live feature APIs without demo incident data', () => {
  const page = read('../company/src/pages/edrdashbordpage/Lateral Movement Detection.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('src/routes/dashboard.routes.js');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(page, /\/lateral-movement\/dashboard/);
  assert.match(page, /\/lateral-movement\/reports/);
  assert.match(page, /\/lateral-movement\/log\/\$\{row\._id\}/);
  assert.match(page, /socket\.on\('lateral:event'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{14\} alerts=\{rows\}/);
  assert.match(reports, /14:\s*\{[\s\S]*?title:\s*'Lateral Movement Detection'/);
  assert.match(reports, /socket\.on\('lateral:event', scheduleRefresh\)/);
  assert.match(reports, /socket\.off\('lateral:event', scheduleRefresh\)/);
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(14\)/);
  assert.match(dashboardRoutes, /14:\s*\{[\s\S]*?remote_services:/);
  assert.match(dashboard, /socket\.on\('lateral:event'/);
  assert.doesNotMatch(page, /185\.220\.101\.45|10\.0\.1\.25|1,248|mimikatz\.exe sekurlsa/);
});

test('lateral dashboard uses one bounded faceted snapshot instead of query fan-out', () => {
  const routes = read('src/routes/lateral-movement.routes.js');
  const page = read('../company/src/pages/edrdashbordpage/Lateral Movement Detection.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(routes, /\$facet:\s*\{/);
  assert.match(routes, /const eventLimit = integer\(req\.query\.limit, 250, 1, 500\)/);
  assert.match(routes, /maxTimeMS: 15000/);
  assert.doesNotMatch(page, /Promise\.all\(\[\s*api\.get\(`\/lateral-movement\/logs/);
  assert.doesNotMatch(dashboard, /api\.get\('\/lateral-movement\/logs'.+api\.get\('\/lateral-movement\/dashboard/s);
});

test('lateral movement indexes and correlation chains are registered', () => {
  const migration = read('migrations/021-lateral-movement-indexes.js');
  const correlation = read('src/services/correlation.service.js');
  assert.match(migration, /lateral_capability_time/);
  assert.match(migration, /Reusing index/);
  assert.match(correlation, /LATERAL_AUTH_REMOTE_EXEC/);
  assert.match(correlation, /LATERAL_ADMIN_SHARE_PSEXEC/);
  assert.match(correlation, /LATERAL_KERBEROS_CREDENTIAL/);
});
