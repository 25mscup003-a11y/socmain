const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..', '..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('department admin sidebar exposes department-scoped operational tools', () => {
  const layout = read('company/src/components/Layout.jsx');
  const app = read('company/src/App.jsx');

  for (const route of ['/soc-manager', '/profile-locks', '/edrsystemstupe', '/systems', '/soar', '/threat-intelligence', '/incidents']) {
    assert.match(
      layout,
      new RegExp(`to: '${route.replaceAll('/', '\\/')}'[^\n]+department_admin`),
      `${route} must be available to department admins`,
    );
  }

  assert.match(layout, /to: '\/department-admin\/dashboard'[^\n]+department_admin/);
  assert.match(layout, /user\?\.role === 'department_admin'[\s\S]+`\/department-admin\$\{n\.to\}`/);
  assert.match(app, /path="incidents" element=\{<AdminOnly role="department_admin">/);
  assert.match(app, /path="threat-intelligence" element=\{<AdminOnly role="department_admin">/);
  for (const route of ['soc-manager', 'profile-locks', 'edrsystemstupe', 'departments', 'systems', 'download-agent', 'team', 'payments', 'system-monitoring', 'alerts', 'siem', 'soar', 'correlation', 'edr', 'ids', 'ips', 'firewall', 'incidents', 'threat-intelligence', 'forensics', 'security-score', 'reports']) {
    assert.match(app, new RegExp(`path="department-admin/${route}"`));
  }

  const menuBlock = layout.slice(layout.indexOf('const navSections = ['), layout.indexOf('].map(section => ({', layout.indexOf('const navSections = [')));
  const items = [...menuBlock.matchAll(/label: '([^']+)', roles: \[([^\]]+)\]/g)]
    .map(match => ({ label: match[1].replace(/^\S+\s/, ''), roles: match[2] }));
  const labelsFor = role => items.filter(item => item.roles.includes(`'${role}'`)).map(item => item.label);
  const companyOnly = new Set(['Departments', 'Download Agent', 'Team', 'Payments']);
  assert.deepEqual(labelsFor('department_admin'), labelsFor('company_admin').filter(label => !companyOnly.has(label)));
});

test('department incident APIs enforce a department id in authorization and queries', () => {
  const source = read('backend/src/routes/soc-manager.routes.js');

  assert.match(source, /departmentIncidentRead[\s\S]+Department assignment required/);
  assert.match(source, /router\.get\('\/incidents'[\s\S]+role === 'department_admin'[\s\S]+departmentId: req\.user\.departmentId/);
  assert.match(source, /router\.get\('\/threat-intelligence'[\s\S]+role === 'department_admin'[\s\S]+departmentId: req\.user\.departmentId/);
});

test('new parity tabs remain department-scoped instead of inheriting company administration', () => {
  const users = read('backend/src/routes/user.routes.js');
  const agents = read('backend/src/routes/agent.routes.js');
  const chat = read('backend/src/routes/soc-chat.routes.js');
  const payments = read('company/src/pages/PaymentsPage.jsx');

  assert.match(users, /req\.user\.role === 'department_admin'[\s\S]+departmentIds: req\.user\.departmentId/);
  assert.match(agents, /departmentScoped[\s\S]+departmentId: req\.user\.departmentId/);
  assert.match(chat, /const SocDepartmentAssignment = require\('\.\.\/models\/SocDepartmentAssignment\.model'\)/);
  assert.match(chat, /role === 'department_admin'[\s\S]+SocDepartmentAssignment\.find/);
  assert.match(chat, /companyWideManagerIds[\s\S]+query = \{ _id: \{ \$in: managerIds \}, role: 'soc_manager' \}/);
  assert.match(chat, /role: 'department_admin'[\s\S]+departmentId: \{ \$in: departmentIds \}/);
  assert.match(chat, /departmentIds\.length[\s\S]+role: 'department_admin', companyId: \{ \$in: companyIds \}[\s\S]+departmentAdminScope/);
  assert.match(payments, /isDeptAdmin \? <DepartmentPaymentsPage \/> : <CompanyPaymentsPage \/>/);
});

test('department firewall shows and authorizes department and system rules only', () => {
  const page = read('company/src/pages/FirewallPage.jsx');
  const routes = read('backend/src/routes/firewall.routes.js');

  assert.match(page, /departmentAdmin = user\?\.role === 'department_admin'/);
  assert.match(page, /!departmentAdmin && <CompanyLevelRules/);
  assert.match(page, /!departmentAdmin \? \[\['🏢', 'Company Level'/);
  assert.match(page, /<DepartmentLevelRules[\s\S]+<SystemLevelRules/);
  assert.match(page, /<FirewallDeviceCards \/>[\s\S]+fw-kpis/);

  assert.match(routes, /departmentFirewallScope[\s\S]+level: 'department'[\s\S]+level: 'system'/);
  assert.match(routes, /level === 'company'[\s\S]+Company-level firewall access denied/);
  assert.match(routes, /canManageFirewallRule[\s\S]+Firewall rule is outside your department scope/);
});

test('department admin settings expose only personal account controls', () => {
  const settings = read('company/src/pages/SettingsPage.jsx');
  const companyRoutes = read('backend/src/routes/company.routes.js');

  const allowedTabs = settings.slice(
    settings.indexOf('const departmentAdminSettingsTabIds'),
    settings.indexOf(']);', settings.indexOf('const departmentAdminSettingsTabIds')) + 3,
  );
  for (const tab of ['profile', 'security', 'notifications', 'activity']) {
    assert.match(allowedTabs, new RegExp(`'${tab}'`));
  }
  for (const tab of ['support', 'agents', 'subscription', 'requests', 'company', 'kyc', 'users']) {
    assert.doesNotMatch(allowedTabs, new RegExp(`'${tab}'`));
  }

  assert.match(companyRoutes, /role === 'department_admin'[\s\S]+source: \{ \$ne: 'superadmin' \}/);
  assert.match(companyRoutes, /isDepartmentAdmin[\s\S]+ownIdentity[\s\S]+activityIdentityFilter/);
});
