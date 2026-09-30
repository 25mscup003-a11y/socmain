const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('DNS cache-poisoning UI uses live configuration and exposes PDF export', () => {
  const source = read('company/src/pages/edrdashbordpage/DNS Cache Poisoning Detection.jsx');
  assert.match(source, /label: 'Configure'/);
  assert.match(source, /api\.get\('\/dns-cache-poisoning\/configuration'/);
  assert.match(source, /api\.put\('\/dns-cache-poisoning\/configuration'/);
  assert.match(source, /api\.post\('\/dns-cache-poisoning\/configuration\/sync'/);
  assert.match(source, /\[editingBuiltIn\.id\]: settings/);
  assert.match(source, /customRules:/);
  assert.match(source, /Add New Rule/);
  assert.match(source, /EXPECTED IP ADDRESSES/);
  assert.match(source, /Unified DNS Cache-Poisoning Policy/);
  assert.match(source, /Apply All Changes/);
  assert.match(source, /Custom rule changes staged/);
  assert.doesNotMatch(source, />1 · Detector Settings</);
  assert.match(source, /heatmapRows/);
  assert.match(source, /threat event\(s\) in the last 24 hours/);
  assert.match(source, /application\/pdf/);
  assert.doesNotMatch(source, /SAMPLE_DNS_CACHE_LOGS/);
  assert.doesNotMatch(source, /82\.5%/);
});

test('DNS cache-poisoning API is tenant scoped, authorized and queues durable commands', () => {
  const source = read('backend/src/routes/dns-cache-poisoning.routes.js');
  assert.match(source, /router\.put\('\/configuration', requireManager/);
  assert.match(source, /router\.post\('\/configuration\/sync', requireManager/);
  assert.match(source, /router\.patch\('\/configuration\/built-in\/:ruleId', requireManager/);
  assert.match(source, /router\.post\('\/configuration\/rules', requireManager/);
  assert.match(source, /router\.patch\('\/configuration\/rules\/:ruleId', requireManager/);
  assert.match(source, /router\.delete\('\/configuration\/rules\/:ruleId', requireManager/);
  assert.match(source, /builtInRuleOverrides/);
  assert.match(source, /customRules/);
  assert.match(source, /companyId: id/);
  assert.match(source, /pendingCommands/);
  assert.match(source, /configure_dns_cache_poisoning/);
  assert.match(source, /flush_dns_cache/);
  assert.match(source, /restore_dns_resolver/);
});

test('EDR System Setup exposes the DNS cache-poisoning configuration card and route', () => {
  const setup = read('company/src/pages/EDRSystemSetupPage.jsx');
  const app = read('company/src/App.jsx');
  const page = read('company/src/pages/DnsCachePoisoningSetupPage.jsx');
  assert.match(setup, /DNS Cache Poisoning/);
  assert.match(setup, /\$\{setupBase\}\/dns-cache-poisoning/);
  assert.match(app, /DnsCachePoisoningSetupPage/);
  assert.match(page, /DnsCachePoisoningConfigureTab/);
});

test('SOC agent applies and reports DNS cache-poisoning policy', () => {
  const heartbeat = read('backend/soc-agent/core/heartbeat.py');
  const detector = read('backend/soc-agent/core/cache_poison_detector.py');
  assert.match(heartbeat, /command == 'configure_dns_cache_poisoning'/);
  assert.match(heartbeat, /dnsCachePoisonStatus/);
  assert.match(detector, /def configure\(/);
  assert.match(detector, /def flush_dns_cache\(/);
  assert.match(detector, /def restore_resolver\(/);
  assert.match(detector, /'queryType':\s+f\.get\('query_type'\)/);
  assert.match(detector, /def _check_custom_rule\(/);
  const sender = read('backend/soc-agent/core/sender.py');
  assert.match(sender, /'responseIp': alert\.get\('responseIp'\)/);
  assert.match(sender, /'expectedIp': alert\.get\('expectedIp'\)/);
});
