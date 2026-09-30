const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('data-security APIs are mounted, authenticated, scoped and actionable', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/data-security.routes.js');
  assert.match(server, /app\.use\('\/api\/data-security', dataSecurityRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['dashboard', 'live', 'logs', 'log/:id', 'reports']) {
    assert.match(routes, new RegExp(`router\\.get\\('\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /router\.post\('\/respond', requireCompanyAdmin/);
  assert.match(routes, /router\.post\('\/export'/);
  assert.match(routes, /companyScope\(req/);
  assert.match(routes, /\$facet:\s*\{/);
  assert.match(routes, /maxTimeMS: 15000/);
});

test('agent and ingestion preserve privacy-safe capability 12 telemetry', () => {
  const agent = read('soc-agent/agent.py');
  const collector = read('soc-agent/collectors/data_security.py');
  const sender = read('soc-agent/core/sender.py');
  const ingestion = read('src/routes/alert.routes.js');
  const model = read('src/models/Alert.model.js');
  const usb = read('soc-agent/collectors/usb.py');
  assert.match(agent, /collectors\.data_security/);
  assert.match(collector, /data_security_monitoring_enabled/);
  assert.match(collector, /no file, clipboard, email or credential contents collected/);
  assert.match(sender, /'dataEventType'/);
  assert.match(sender, /'dataClassification'/);
  assert.match(ingestion, /normalizeDataSecurityTelemetry/);
  assert.match(ingestion, /emit\('data-security:event'/);
  assert.match(model, /dataEventType:/);
  assert.match(model, /dataClassification:/);
  assert.match(usb, /'capabilityIds': \[10, 12\]/);
});

test('generic alerts with only the Unknown classification default do not become capability 12 events', () => {
  const { deriveCapabilityIds } = require('../src/utils/capabilityTelemetry');
  const genericNetwork = deriveCapabilityIds({
    capabilityId: 3,
    source: 'suricata',
    eventCategory: 'network',
    ruleId: 'SURICATA_STREAM_EVENT',
    description: 'Generic protocol decode event',
    dataClassification: 'Unknown',
  });
  assert.equal(genericNetwork.includes(12), false);
  assert.equal(deriveCapabilityIds({ capabilityId: 12, source: 'data_security', dataEventType: 'cloud_upload' }).includes(12), true);
});

test('capability 12 UI uses dedicated live APIs and shared enterprise reports', () => {
  const page = read('../company/src/pages/edrdashbordpage/Data Security Monitoring.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboardRoutes = read('src/routes/dashboard.routes.js');
  assert.match(page, /\/data-security\/dashboard/);
  assert.match(page, /\/data-security\/log\/\$\{row\._id\}/);
  assert.match(page, /socket\.on\('data-security:event'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{12\} alerts=\{alerts\}/);
  assert.match(reports, /12:\s*\{[\s\S]*?title:\s*'Data Security Monitoring'/);
  assert.match(reports, /\['Sensitive File Name', dataSensitiveFileName\]/);
  assert.match(reports, /\['Destination \/ Channel', dataDestinationChannel\]/);
  assert.match(reports, /\['Action Executed', dataActionExecuted\]/);
  assert.match(reports, /data-security:event/);
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(12\)/);
  assert.match(dashboard, /import \{ DataSecurityDashboardPanel \} from '\.\/edrdashbordpage\/Data Security Monitoring'/);
  assert.match(dashboard, /\/data-security\/dashboard/);
  assert.doesNotMatch(page, /sarah\.connor|john\.doe|Q4_Payroll|24\.7K|48\.2 TB/);
});

test('capability 12 dashboard uses bounded snapshot and 60-second fallback polling', () => {
  const routes = read('src/routes/data-security.routes.js');
  const page = read('../company/src/pages/edrdashbordpage/Data Security Monitoring.jsx');
  assert.match(routes, /const eventLimit = integer\(req\.query\.limit, 250, 1, 500\)/);
  assert.match(page, /setInterval\(\(\) => loadAlerts\(true\), 60000\)/);
  assert.doesNotMatch(page, /setInterval\(\(\) => loadAlerts\(true\), 15000\)/);
});
