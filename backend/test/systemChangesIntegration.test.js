const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.join(__dirname, '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('system-change APIs are authenticated, tenant scoped and mounted', () => {
  const server = read('src/server.js');
  const routes = read('src/routes/system-changes.routes.js');
  assert.match(server, /app\.use\('\/api\/system-changes', systemChangesRoutes\)/);
  assert.match(routes, /router\.use\(authenticate, requireAnalyst\)/);
  for (const route of ['summary', 'timeline', 'categories', 'hosts', 'critical', 'risk', 'baseline']) {
    assert.match(routes, new RegExp(`router\\.get\\('\\/${route}`));
  }
  for (const route of ['baseline/approve', 'exception', 'acknowledge', 'investigate', 'export']) {
    assert.match(routes, new RegExp(`router\\.post\\('\\/${route.replace('/', '\\/')}`));
  }
  assert.match(routes, /resolveCapabilityDepartmentScope/);
  assert.match(routes, /isSynthetic:\s*\{ \$ne: true \}/);
  assert.match(routes, /requireCompanyAdmin/);
});

test('system-change telemetry is normalized, indexed and streamed for direct and batch ingestion', () => {
  const model = read('src/models/Alert.model.js');
  const ingestion = read('src/routes/alert.routes.js');
  const migration = read('migrations/025-system-changes-indexes.js');
  assert.match(model, /systemChangeCategory:\s*\{ type: String, index: true \}/);
  assert.match(ingestion, /normalizeSystemChangeTelemetry/);
  assert.match(ingestion, /applySystemChangeControls\(alertData\)/);
  assert.match(ingestion, /docs\.map\(async doc => \{[\s\S]*await applySystemChangeControls\(doc\)/);
  assert.equal((ingestion.match(/emit\('system-change:event'/g) || []).length, 2);
  assert.match(migration, /system_change_category_time/);
  assert.match(migration, /\$addToSet:\s*\{ capabilityIds: 7 \}/);
});

test('system-change report and UI consume real capability data', () => {
  const reports = read('../company/src/pages/edrdashbordpage/CapabilityReportsPanel.jsx');
  const page = read('../company/src/pages/edrdashbordpage/System Changes Monitoring.jsx');
  const dashboard = read('../company/src/pages/EDRDashboardDetails.jsx');
  assert.match(reports, /title: 'System Changes Monitoring'/);
  assert.match(page, /<CapabilityReportsPanel capabilityId=\{7\} alerts=\{alerts\}/);
  assert.match(page, /\/system-changes\/summary/);
  assert.match(dashboard, /api\.get\('\/system-changes\/summary'/);
  assert.match(dashboard, /socket\.on\('system-change:event'/);
  assert.doesNotMatch(page, /2,847|backup_admin|malwared|system32_updater\.exe/);
});

test('system-change correlation chains cover identity, defense evasion and task persistence', () => {
  const correlation = read('src/services/correlation.service.js');
  for (const id of ['SYSTEM_ACCOUNT_SERVICE_CHAIN', 'SYSTEM_DEFENSE_EVASION_CHAIN', 'SYSTEM_TASK_PERSISTENCE_CHAIN']) {
    assert.match(correlation, new RegExp(id));
  }
});
