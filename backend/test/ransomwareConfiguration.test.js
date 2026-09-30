const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const mongoose = require('mongoose');
const RansomwareConfig = require('../src/models/RansomwareConfig.model');

test('ransomware configuration enforces safe operational ranges', () => {
  const config = new RansomwareConfig({
    companyId: new mongoose.Types.ObjectId(),
    windowSeconds: 4,
    entropyThreshold: 9,
    massModificationThreshold: 1,
  });
  const validation = config.validateSync();
  assert.ok(validation.errors.windowSeconds);
  assert.ok(validation.errors.entropyThreshold);
  assert.ok(validation.errors.massModificationThreshold);
});

test('ransomware configuration is connected to API, heartbeat and sidebar', () => {
  const root = path.resolve(__dirname, '..', '..');
  const route = fs.readFileSync(path.join(root, 'backend/src/routes/ransomware.routes.js'), 'utf8');
  const heartbeat = fs.readFileSync(path.join(root, 'backend/src/routes/agent.routes.js'), 'utf8');
  const page = fs.readFileSync(path.join(root, 'company/src/pages/edrdashbordpage/Encryption Ransomware Detection.jsx'), 'utf8');
  assert.match(route, /router\.get\('\/configuration'/);
  assert.match(route, /router\.put\('\/configuration'/);
  assert.match(route, /router\.patch\('\/configuration\/rules\/:ruleId'/);
  assert.match(route, /ransomware\.configuration\.updated/);
  assert.match(heartbeat, /ransomware_window_secs/);
  assert.match(heartbeat, /ransomware_protected_dirs/);
  assert.match(heartbeat, /ransomware_rule_overrides/);
  assert.match(page, /label: 'Configure'/);
  assert.match(page, /api\.put\('\/ransomware\/configuration'/);
  assert.match(page, /Ransomware Detection Rules/);
  assert.match(page, /configuration\/rules\/\$\{encodeURIComponent\(editingRule\.id\)\}/);
});
