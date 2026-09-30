const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('USB policy API is authenticated, scoped, audited, and delivered to agents', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/usb-policy.routes.js');
  const heartbeat = read('src/routes/agent.routes.js');
  assert.match(server, /app\.use\('\/api\/usb-policies', require\('\.\/routes\/usb-policy\.routes'\)\)/);
  assert.match(routes, /router\.use\(authenticate\)/);
  assert.match(routes, /router\.post\('\/', requireManager/);
  assert.match(routes, /router\.patch\('\/:id', requireManager/);
  assert.match(routes, /router\.delete\('\/:id', requireManager/);
  assert.match(routes, /usb\.policy\.(?:created|updated|deleted)/);
  assert.match(heartbeat, /usb_policies: usbPolicies\.map/);
  assert.match(heartbeat, /usb_policy_version:/);
});

test('USB enforcement result survives agent, ingestion, schema and UI layers', () => {
  const collector = read('soc-agent/collectors/usb.py');
  const sender = read('soc-agent/core/sender.py');
  const ingestion = read('src/routes/alert.routes.js');
  const model = read('src/models/Alert.model.js');
  const page = read('../company/src/pages/edrdashbordpage/Device Control (USB) Monitoring.jsx');
  assert.match(collector, /USB_POLICY_ENFORCEMENT_FAILED/);
  assert.match(collector, /'enforcement_status': enforcement_status/);
  assert.match(sender, /'enforcement_status': alert\.get\('enforcement_status'\)/);
  assert.match(ingestion, /usbEnforcementStatus: body\.usbEnforcementStatus \|\| body\.enforcement_status/);
  assert.match(model, /usbEnforcementStatus:/);
  assert.match(page, /usbEnforcementStatus==='failed'/);
});

test('monitoring KPIs use canonical USB event rules and per-KPI timelines', () => {
  const page = read('../company/src/pages/edrdashbordpage/Device Control (USB) Monitoring.jsx');
  assert.match(page, /function usbEventFacts/);
  assert.match(page, /rule === 'USB_DRIVER_LOADED'/);
  assert.match(page, /rule === 'USB_FILE_READ'/);
  assert.match(page, /USB_RUBBER_DUCKY_SUSPECTED/);
  assert.match(page, /series: Object\.fromEntries/);
  assert.match(page, /data: liveStats\.series\[key\]/);
  assert.doesNotMatch(page, /driversInstalled: matches\(\/driver\.\*install/i);
});

test('USB capability query keeps enriched USB evidence in capability scope', () => {
  const dashboard = read('src/routes/dashboard.routes.js');
  assert.match(dashboard, /Number\(capabilityId\) === 10 && category === 'usb'/);
  assert.match(dashboard, /capabilityAlertFilter\(capabilityId\)/);
});

test('USB report uses the shared live report format and backend report feed', () => {
  const page = read('../company/src/pages/edrdashbordpage/Device Control (USB) Monitoring.jsx');
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const dashboard = read('src/routes/dashboard.routes.js');
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{10\} alerts=\{alerts\} \/>/);
  assert.match(reports, /10:\s*\{[\s\S]*?title:\s*'Device Control \(USB\) Monitoring'/);
  assert.match(reports, /socket\.on\('usb:event', scheduleRefresh\)/);
  assert.match(dashboard, /allowedCapabilities\.add\(10\)/);
  assert.match(dashboard, /10:\s*\{[\s\S]*?transfers:/);
  assert.match(dashboard, /usbEnforcementStatus usbEnforcementError/);
});
