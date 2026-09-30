const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { deriveCapabilityIds } = require('../src/utils/capabilityTelemetry');

const workspace = path.resolve(__dirname, '..', '..');
const read = relativePath => fs.readFileSync(path.join(workspace, relativePath), 'utf8');

test('verified insider-risk telemetry derives capability 16', () => {
  for (const ruleId of [
    'PROC_PRIVILEGE_ESCALATION', 'PROC_SECURITY_LOG_CLEARED',
    'NET_OUTBOUND_TRANSFER_ANOMALY', 'USB_SENSITIVE_FILE_COPIED',
  ]) {
    assert.ok(deriveCapabilityIds({ ruleId, severity: 'high' }).includes(16), ruleId);
  }
  assert.equal(deriveCapabilityIds({ ruleId: 'PROC_STARTED', processName: 'node' }).includes(16), false);
});

test('capability 16 uses indexed live scope and dedicated websocket event', () => {
  const overview = read('backend/src/utils/capabilityOverview.js');
  const dashboard = read('backend/src/routes/dashboard.routes.js');
  const ingestion = read('backend/src/routes/alert.routes.js');
  assert.match(overview, /if \(id === 16\)/);
  assert.match(dashboard, /case 16: return \{ \$or: exact\(\) \};/);
  assert.match(ingestion, /hasCapability\(alert, 16\)[\s\S]*?emit\('insider:event'/);
  assert.match(ingestion, /hasCapability\(a, 16\)[\s\S]*?emit\('insider:event'/);
});

test('insider signal classification is persisted as normalized telemetry', () => {
  const ingestion = read('backend/src/routes/alert.routes.js');
  const schema = read('backend/src/models/Alert.model.js');
  const sender = read('backend/soc-agent/core/sender.py');
  assert.match(sender, /'insiderSignalType':/);
  assert.match(ingestion, /insiderSignalType = pickFirst/);
  assert.match(schema, /insiderSignalType:\s*\{\s*type:\s*String/);
});

test('insider migration backfills only verified real rule evidence', () => {
  const migration = read('backend/migrations/019-insider-threat-backfill.js');
  const packageJson = read('backend/package.json');
  assert.match(migration, /ruleId:\s*\{\s*\$in:\s*ALL_RULES\s*\}/);
  assert.match(migration, /\$addToSet:\s*\{\s*capabilityIds:\s*16\s*\}/);
  assert.match(migration, /isSynthetic:\s*\{\s*\$ne:\s*true\s*\}/);
  assert.doesNotMatch(migration, /insertMany|create\(/);
  assert.match(packageJson, /"migrate:insider-threat":\s*"node migrations\/019-insider-threat-backfill\.js"/);
});

test('insider UI listens for live events and has no known sample identities', () => {
  const dashboard = read('company/src/pages/edrdashbordpage/Insider Threat Detection.jsx');
  const details = read('company/src/pages/EDRDashboardDetails.jsx');
  assert.match(dashboard, /socket\.on\('insider:event', buf\.add\)/);
  assert.match(details, /socket\.on\('insider:event', liveAlertBuffer\.add\)/);
  assert.doesNotMatch(dashboard, /Rohit Sharma|Ankit Verma|Neha Singh|WIN-FIN-04|1,248|sarah\.connor/);
});
