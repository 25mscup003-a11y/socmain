const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');

test('email threat REST API is mounted and tenant authenticated', () => {
  const server = fs.readFileSync(path.join(root, 'src/server.js'), 'utf8');
  const routes = fs.readFileSync(path.join(root, 'src/routes/email-threat.routes.js'), 'utf8');
  assert.match(server, /app\.use\('\/api\/email-threat', emailThreatRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['dashboard', 'live', 'logs', 'attachments', 'urls', 'authentication', 'mailbox', 'threat-intelligence', 'reports', 'quarantine', 'alerts', 'settings']) {
    assert.match(routes, new RegExp(`router\\.get\\('\\/${route.replace('-', '\\-')}`));
  }
});

test('agent and ingestion preserve capability 15 email fields and realtime events', () => {
  const agent = fs.readFileSync(path.join(root, 'soc-agent/agent.py'), 'utf8');
  const sender = fs.readFileSync(path.join(root, 'soc-agent/core/sender.py'), 'utf8');
  const ingestion = fs.readFileSync(path.join(root, 'src/routes/alert.routes.js'), 'utf8');
  assert.match(agent, /collectors\.email_threat/);
  assert.match(sender, /'emailSender'/);
  assert.match(ingestion, /normalizeEmailTelemetry/);
  assert.match(ingestion, /emit\('email:event'/);
});

test('email threat UI preserves the established design while using feature APIs', () => {
  const page = fs.readFileSync(path.join(root, '../company/src/pages/edrdashbordpage/Email Threat Monitoring.jsx'), 'utf8');
  const details = fs.readFileSync(path.join(root, '../company/src/pages/EDRDashboardDetails.jsx'), 'utf8');
  const sharedReports = fs.readFileSync(path.join(root, '../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx'), 'utf8');
  const dashboardRoutes = fs.readFileSync(path.join(root, 'src/routes/dashboard.routes.js'), 'utf8');
  const emailRoutes = fs.readFileSync(path.join(root, 'src/routes/email-threat.routes.js'), 'utf8');
  assert.match(page, /\/email-threat\/logs/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{15\}/);
  assert.match(sharedReports, /15:\s*\{[\s\S]*?title: 'Email Threat Monitoring'/);
  assert.match(dashboardRoutes, /allowedCapabilities\.add\(15\)/);
  assert.match(page, /Email Threat & Phishing SIEM Logs/);
  assert.match(page, /Agent-Based Email Security & Mail Gateway Infrastructure/);
  assert.match(page, /function EmailTrafficOverTimeChart\(\{ alerts = \[\] \}\)/);
  assert.match(page, /function ThreatCategoriesDonut\(\{ alerts = \[\] \}\)/);
  assert.match(page, /function UserClickActivityDonut\(\{ alerts = \[\] \}\)/);
  assert.match(page, /function EmailThreatTrendChart\(\{ alerts = \[\] \}\)/);
  assert.match(page, /function QuarantineSummaryDonut\(\{ alerts = \[\] \}\)/);
  assert.match(page, /EMAIL DOCUMENTS DOWNLOADED/);
  assert.match(page, /Email Documents Downloaded/);
  assert.match(page, /Webmail \/ Mail Client/);
  assert.match(page, /monitored user/);
  assert.match(emailRoutes, /attachmentDownloads/);
  assert.doesNotMatch(page, /const incomingData = \[4500/);
  assert.doesNotMatch(page, />3,753</);
  assert.doesNotMatch(page, />1,562</);
  assert.match(details, /queryBackendId\) === 15\) socket\.on\('email:event'/);
  assert.match(details, /Number\(queryBackendId\) === 15[\s\S]*?Number\(total \|\| alerts\.length\)/);
  assert.doesNotMatch(page, /payroll\.lead|spoofed-domain/);
});
