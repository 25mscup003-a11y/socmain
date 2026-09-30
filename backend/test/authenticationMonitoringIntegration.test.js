const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('authentication monitoring API is mounted, authenticated and tenant scoped', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/authentication-monitoring.routes.js');
  assert.match(server, /app\.use\('\/api\/authentication-monitoring', require\('\.\/routes\/authentication-monitoring\.routes'\)\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  assert.match(routes, /companyScope\(req/);
  assert.match(routes, /resolveCapabilityDepartmentScope/);
  assert.match(routes, /isSynthetic:\s*\{ \$ne: true \}/);
  assert.match(read('src/utils/authCapability.js'), /\{ capabilityIds: 4 \}/);
  assert.match(read('src/utils/authCapability.js'), /source: 'file_watch'/);
  for (const endpoint of ['dashboard', 'statistics', 'events', 'timeline', 'risky-users']) {
    assert.match(routes, new RegExp(`router\\.get\\('\/${endpoint}`));
  }
  assert.match(routes, /router\.post\('\/events\/:id\/notes'/);
  assert.match(routes, /allowedStatuses = new Set\(\['open', 'investigating', 'under_observation', 'resolved', 'false_positive'\]\)/);
});

test('authentication events use the shared ingestion and websocket pipeline', () => {
  const ingestion = read('src/routes/alert.routes.js');
  const sender = read('soc-agent/core/sender.py');
  const collector = read('soc-agent/collectors/logs.py');
  assert.match(ingestion, /hasCapability\(alert, 4\)/);
  assert.match(ingestion, /emit\('auth:event', alert\)/);
  assert.match(ingestion, /emit\('authentication_event', alert\)/);
  assert.match(ingestion, /emit\('authentication_alert', alert\)/);
  assert.match(sender, /'authResult': alert\.get\('authResult'\) or alert\.get\('auth_result'\)/);
  assert.match(sender, /'logonType': alert\.get\('logonType'\) or alert\.get\('logon_type'\)/);
  assert.match(collector, /_start_linux_auth_journal/);
  assert.match(collector, /macos-log-stream/);
  assert.match(collector, /'Security'/);
});

test('capability 4 report supports evidence-based authentication categories', () => {
  const routes = read('src/routes/dashboard.routes.js');
  assert.match(routes, /allowedCapabilities\.add\(4\)/);
  for (const category of ['successful', 'failed', 'brute_force', 'privileged', 'account_changes', 'remote', 'anomaly', 'critical']) {
    assert.match(routes, new RegExp(`\\b${category}:`));
  }
});

test('existing authentication UI consumes dedicated live data without fabricated forensic defaults', () => {
  const page = read('../company/src/pages/edrdashbordpage/User & Authentication Monitoring.jsx');
  const memory = read('../company/src/pages/edrdashbordpage/Memory Activity Monitoring.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  assert.match(page, /api\.get\('\/authentication-monitoring\/dashboard'/);
  assert.match(page, /socket\.on\('auth:event'/);
  assert.match(page, /api\.get\(`\/authentication-monitoring\/events\/\$\{initialLog\._id\}`/);
  assert.match(page, /api\.get\('\/forensics\/endpoint'/);
  assert.match(page, /api\.post\('\/forensics\/hunts'/);
  assert.match(page, /row\?\.srcip \|\| row\?\.src_ip/);
  assert.match(dashboard, /api\.get\('\/authentication-monitoring\/dashboard'/);
  assert.match(dashboard, /socket\.on\('authentication_event'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{4\} alerts=\{alerts\} \/>/);
  assert.match(memory, /<CapabilityReportsPanel capabilityId=\{5\} alerts=\{alerts\} \/>/);
  assert.match(reports, /4:\s*\{[\s\S]*title: 'User & Authentication Monitoring'/);
  assert.match(reports, /5:\s*\{[\s\S]*title: 'Memory Activity Monitoring'/);
  assert.match(reports, /socket\.on\('authentication_alert'/);
  assert.match(reports, /socket\.on\('memory:alert'/);
  assert.doesNotMatch(page, /SOC-AUTH-8841|10\.10\.5\.21|attacker@evil\.com|powershell\.exe -enc SQBFAFgA/);
  assert.doesNotMatch(page, /no forensic-hunt executor is configured/);
});
