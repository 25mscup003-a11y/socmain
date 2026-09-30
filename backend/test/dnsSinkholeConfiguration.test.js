const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('DNS Sinkhole dashboard exposes agent-backed configuration controls', () => {
  const source = read('company/src/pages/edrdashbordpage/DNS Sinkhole.jsx');
  assert.match(source, /label: 'Configure Sinkhole'/);
  assert.match(source, /api\.get\('\/dns-sinkhole\/configuration'/);
  assert.match(source, /api\.put\('\/dns-sinkhole\/configuration'/);
  assert.match(source, /api\.post\('\/dns-sinkhole\/configuration\/sync'/);
  assert.match(source, /api\.post\('\/dns-sinkhole\/configuration\/apply-built-in'/);
  assert.match(source, /api\.patch\(`\/dns-sinkhole\/configuration\/built-in\/\$\{editingBuiltIn\.id\}`/);
  assert.match(source, /api\.patch\(`\/dns-sinkhole\/rules\/\$\{editingRule\._id\}`/);
  assert.match(source, /aria-label={`Edit \$\{rule\.domain\}`}/);
  assert.doesNotMatch(source, />Sinkhole Service<\/div>/);
  assert.doesNotMatch(source, /Windows agents use the hosts-file backend/);
  assert.match(source, /Save & Apply to Agents/);
});

test('DNS Sinkhole configuration API is tenant scoped, authorized, and durable', () => {
  const source = read('backend/src/routes/dns-sinkhole.routes.js');
  const model = read('backend/src/models/DnsSinkholeRule.model.js');
  assert.match(source, /router\.get\('\/configuration'/);
  assert.match(source, /router\.put\('\/configuration', requireManager/);
  assert.match(source, /router\.post\('\/configuration\/sync', requireManager/);
  assert.match(source, /router\.post\('\/configuration\/apply-built-in', requireManager/);
  assert.match(source, /router\.post\('\/redirect', requireManager/);
  assert.match(source, /router\.patch\('\/configuration\/built-in\/:ruleId', requireManager/);
  assert.match(source, /router\.patch\('\/rules\/:id', requireManager/);
  assert.match(source, /router\.post\('\/rules\/:id\/apply', requireManager/);
  assert.match(source, /companyId = validCompanyId\(req\)/);
  assert.match(source, /pendingCommands/);
  assert.match(source, /configure_dns_sinkhole/);
  assert.match(source, /sinkholeTargets/);
  assert.match(source, /normalizeSinkholeIp/);
  assert.match(source, /Redirect Domain to Safe Server/);
  assert.match(model, /sinkholeIp/);
  assert.match(model, /'blocklist', 'redirect', 'allowlist'/);
  assert.doesNotMatch(source, /prevQuery\.createdAt\.\$lte/);
  assert.match(source, /\{ createdAt: \{ \$lt: prevUntil \} \}/);
});

test('Company System Setup opens the dedicated DNS Sinkhole configuration workflow', () => {
  const layout = read('company/src/components/Layout.jsx');
  const edrSetup = read('company/src/pages/EDRSystemSetupPage.jsx');
  const sinkholeSetup = read('company/src/pages/DnsSinkholeSetupPage.jsx');
  const sinkholeDashboard = read('company/src/pages/edrdashbordpage/DNS Sinkhole.jsx');
  const app = read('company/src/App.jsx');
  assert.match(layout, /label: '🛡 EDR Setup'/);
  assert.match(edrSetup, /DNS Sinkhole/);
  assert.match(edrSetup, /\$\{setupBase\}\/dns-sinkhole/);
  assert.match(sinkholeSetup, /Built-in DNS Rules/);
  assert.match(sinkholeSetup, /Company DNS Rules/);
  assert.match(sinkholeSetup, /New DNS rule sinkhole server IP/);
  assert.match(sinkholeSetup, /capabilityId=31&capability=dns-sinkhole/);
  assert.match(sinkholeDashboard, /import \{ DnsSinkholeSetupContent \}/);
  assert.match(sinkholeDashboard, /<DnsSinkholeSetupContent embedded \/>/);
  assert.match(sinkholeDashboard, /onClick=\{\(\) => setActiveTab\(item\.id\)\}/);
  assert.match(app, /edrsystemstupe\/dns-sinkhole[\s\S]{0,140}DnsSinkholeSetupPage/);
});

test('SOC agent consumes both live and heartbeat DNS policy commands', () => {
  const listener = read('backend/soc-agent/core/command_listener.py');
  const heartbeat = read('backend/soc-agent/core/heartbeat.py');
  assert.match(listener, /@sio\.on\('agent:policy_sync'\)/);
  assert.match(listener, /'configure_dns_sinkhole': self\._configure_dns_sinkhole/);
  assert.match(heartbeat, /command == 'configure_dns_sinkhole'/);
  assert.match(heartbeat, /self\._dns_sinkhole\.configure/);
  assert.match(heartbeat, /sinkhole_targets=item\.get\('sinkholeTargets'\)/);
  assert.match(listener, /sinkhole_ip=data\.get\('sinkholeIp'\)/);
});
