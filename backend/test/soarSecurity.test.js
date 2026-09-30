const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const SoarApproval = require('../src/models/SoarApproval.model');
const SoarRule = require('../src/models/SoarRule.model');
const AutomatedResponse = require('../src/models/AutomatedResponse.model');
const ResponsePlaybook = require('../src/models/ResponsePlaybook.model');
const {
  evalCondition, ruleMatches, actionRequiresApproval, departmentScopeFilter,
  inferAlertTriggerTypes, ipv4CidrContains,
} = require('../src/services/soar.service');
const { evalSimulatorCondition } = require('../src/services/soarSimulator.service');
const { DEFAULT_SOAR_PLAYBOOKS } = require('../src/services/defaultSoarPlaybooks.service');
const { SUPPORTED_ACTIONS } = require('../src/services/automatedResponse.service');

test('SOAR conditions evaluate deterministically without executing actions', () => {
  assert.equal(evalCondition({ severity: 'critical' }, { field: 'severity', operator: 'eq', value: 'critical' }), true);
  assert.equal(evalCondition({ srcip: '10.0.0.4' }, { field: 'srcip', operator: 'matches_regex', value: '^10\\.' }), true);
  assert.equal(ruleMatches(
    { severity: 'high', source: 'suricata' },
    { conditionLogic: 'AND', conditions: [
      { field: 'severity', operator: 'in', value: ['high', 'critical'] },
      { field: 'source', operator: 'eq', value: 'suricata' },
    ] },
  ), true);
  assert.equal(evalSimulatorCondition(
    { severity: 'low' },
    { field: 'severity', operator: 'eq', value: 'critical' },
  ), false);
});

test('automatic SOAR rules execute without an approval pause', () => {
  assert.equal(actionRequiresApproval(
    { executionMode: 'automatic' },
    { type: 'block_ip', requireApproval: true },
  ), false);
  assert.equal(actionRequiresApproval(
    { executionMode: 'approval_required' },
    { type: 'block_ip', requireApproval: false },
  ), true);
});

test('SOAR approvals enforce one pending item per company, rule and target', () => {
  const index = SoarApproval.schema.indexes().find(([, options]) => options.name === 'one_pending_approval_per_rule_target');
  assert.ok(index, 'pending approval dedupe index must exist');
  assert.equal(index[1].unique, true);
  assert.deepEqual(index[1].partialFilterExpression, { status: 'pending' });
});

test('SOAR action identifiers are stable strings', () => {
  const action = new SoarRule({ name: 'test', actions: [{ type: 'notify_soc_manager' }] }).actions[0];
  assert.match(action.id, /^[a-f0-9]{24}$/);
  assert.notEqual(action.id, '[object Object]');
});

test('automated responses expose approval state for the unified SOAR queue', () => {
  assert.ok(AutomatedResponse.schema.path('approvalStatus').enumValues.includes('pending'));
  assert.ok(AutomatedResponse.schema.path('approvalStatus').enumValues.includes('expired'));
  assert.ok(AutomatedResponse.schema.path('status').enumValues.includes('waiting_approval'));
  assert.ok(AutomatedResponse.schema.path('systemId'));
  assert.ok(AutomatedResponse.schema.path('departmentId'));
  assert.ok(ResponsePlaybook.schema.path('departmentId'));
  assert.ok(ResponsePlaybook.schema.path('builtInKey'));
  assert.ok(ResponsePlaybook.schema.path('isBuiltIn'));
});

test('every company receives ten unique approval-gated built-in response playbooks', () => {
  assert.equal(DEFAULT_SOAR_PLAYBOOKS.length, 10);
  assert.equal(new Set(DEFAULT_SOAR_PLAYBOOKS.map(playbook => playbook.builtInKey)).size, 10);
  for (const playbook of DEFAULT_SOAR_PLAYBOOKS) {
    assert.equal(playbook.isBuiltIn, true);
    assert.equal(playbook.enabled, true);
    assert.equal(playbook.executionMode, 'approval_required');
    assert.equal(playbook.requireGlobalApproval, true);
    assert.ok(playbook.conditions.length > 0);
    assert.ok(playbook.steps.length > 0);
    for (const action of playbook.steps) assert.ok(SUPPORTED_ACTIONS.has(action.actionType));
  }

  const uniqueIndex = ResponsePlaybook.schema.indexes().find(([fields, options]) => (
    fields.companyId === 1 && fields.builtInKey === 1 && options.unique
  ));
  assert.ok(uniqueIndex, 'built-in playbooks require a per-company uniqueness index');

  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/soar.routes.js'), 'utf8');
  assert.match(routes, /router\.get\('\/playbooks'[\s\S]+ensureDefaultSoarPlaybooks/);
  assert.match(routes, /if \(pb\.isBuiltIn\)[\s\S]+Built-in playbooks cannot be deleted/);
});

test('SOAR department scope includes global and matching rules but not other departments', () => {
  const filter = departmentScopeFilter('department-a');
  assert.deepEqual(filter.$or, [
    { departmentId: 'department-a' },
    { departmentId: null },
    { departmentId: { $exists: false } },
  ]);
});

test('SOAR rule wizard passes a validated department id with its trigger source', () => {
  const routes = fs.readFileSync(path.join(__dirname, '../src/routes/soar.routes.js'), 'utf8');
  const page = fs.readFileSync(path.join(__dirname, '../../company/src/pages/SoarPage.jsx'), 'utf8');
  assert.match(page, /Department \*<\/label>[\s\S]+value=\{ruleForm\.departmentId \|\| ''\}/);
  assert.match(page, /<option value="">All Departments<\/option>/);
  assert.match(routes, /resolveRuleDepartment[\s\S]+Department\.findOne\(\{ _id: departmentId, companyId \}\)/);
  assert.match(routes, /departmentId = await resolveRuleDepartment\(req, companyId, req\.body\.departmentId\)/);
});

test('SOAR trigger inference honors sensor-specific automation rules', () => {
  assert.deepEqual(inferAlertTriggerTypes({ sourceType: 'IDS', sourceVendor: 'Suricata' }), ['new_alert', 'suricata_alert', 'ids_alert']);
  assert.deepEqual(inferAlertTriggerTypes({ sourceType: 'ZEEK' }), ['new_alert', 'zeek_event']);
  assert.deepEqual(inferAlertTriggerTypes({ sourceType: 'IPS' }), ['new_alert', 'ips_alert', 'firewall_alert']);
});

test('CIDR conditions use actual IPv4 network membership', () => {
  assert.equal(ipv4CidrContains('10.0.0.0/8', '10.24.6.7'), true);
  assert.equal(ipv4CidrContains('10.0.0.0/8', '11.0.0.1'), false);
});
