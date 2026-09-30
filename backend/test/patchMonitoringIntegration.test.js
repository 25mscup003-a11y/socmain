const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const workspace = path.resolve(__dirname, '..', '..');
const read = relativePath => fs.readFileSync(path.join(workspace, relativePath), 'utf8');

test('patch monitoring collector emits separated, batched capability-17 snapshots', () => {
  const collector = read('backend/soc-agent/collectors/patch_inventory.py');
  assert.match(collector, /'PATCH_SOFTWARE_INVENTORY'/);
  assert.match(collector, /'PATCH_INSTALLED_UPDATES'/);
  assert.match(collector, /'PATCH_PENDING_UPDATES'/);
  assert.match(collector, /inventory_snapshot_id=snapshot_id/);
  assert.match(collector, /IsInstalled=0 and IsHidden=0/);
  assert.match(collector, /capabilityId': 17/);
});

test('patch monitoring backend uses indexed tenant scope, reports, and live events', () => {
  const overview = read('backend/src/utils/capabilityOverview.js');
  const dashboard = read('backend/src/routes/dashboard.routes.js');
  const ingestion = read('backend/src/routes/alert.routes.js');
  assert.match(overview, /if \(id === 17\)[\s\S]*?capabilityId: 17[\s\S]*?capabilityIds: 17/);
  assert.match(dashboard, /allowedCapabilities\.add\(17\)/);
  assert.match(dashboard, /17:\s*\{[\s\S]*?pending_updates[\s\S]*?installed_patches/);
  assert.match(dashboard, /inventorySnapshotId inventoryBatchIndex inventoryBatchCount inventoryItems/);
  assert.match(ingestion, /hasCapability\(alert, 17\)[\s\S]*?emit\('patch:event'/);
  assert.match(ingestion, /hasCapability\(a, 17\)[\s\S]*?emit\('patch:event'/);
});

test('patch monitoring UI expands real inventory and contains no known sample dataset', () => {
  const dashboard = read('company/src/pages/edrdashbordpage/Patch & Vulnerability Monitoring.jsx');
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  assert.match(dashboard, /expandLatestPatchTelemetry/);
  assert.match(dashboard, /inventorySnapshotId/);
  assert.match(dashboard, /\/dashboard\/capability-report\/17/);
  assert.match(dashboard, /CapabilityReportsPanel capabilityId=\{17\}/);
  const sharedReport = read('company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  assert.match(sharedReport, /17:\s*\{[\s\S]*?title: 'Patch & Vulnerability Monitoring'/);
  assert.match(sharedReport, /socket\.on\('patch:event', scheduleRefresh\)/);
  assert.match(details, /\[1, 2, 3, 4, 17, 18, 25\]/);
  assert.match(details, /socket\.on\('patch:event', liveAlertBuffer\.add\)/);
  assert.match(dashboard, /socket\.on\('patch:event', buf\.add\)/);
  assert.match(dashboard, /api\.get\('\/system', \{ skipCache: true \}\)/);
  assert.doesNotMatch(dashboard, /KB5034441|CVE-2024-27956|SRV-DB-01|3,882|1,245/);
});
