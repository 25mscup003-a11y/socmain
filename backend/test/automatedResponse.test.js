const test = require('node:test');
const assert = require('node:assert/strict');
const {
  SUPPORTED_ACTIONS, isHighRisk, requiresApprovalForAction, conditionMatches, playbookMatches,
  departmentScopeFilter,
} = require('../src/services/automatedResponse.service');

test('automated response policy conditions support exact, numeric, and list matches', () => {
  const alert = { severity: 'critical', confidenceScore: 95, tags: ['ransomware'], source: 'agent' };
  assert.equal(conditionMatches(alert, { field: 'severity', operator: 'eq', value: 'critical' }), true);
  assert.equal(conditionMatches(alert, { field: 'confidenceScore', operator: 'gte', value: 90 }), true);
  assert.equal(conditionMatches(alert, { field: 'severity', operator: 'neq', value: 'high' }), true);
  assert.equal(conditionMatches(alert, { field: 'source', operator: 'in', value: ['agent', 'sensor'] }), true);
});

test('response playbooks are scoped to the alert department plus company-wide policies', () => {
  assert.deepEqual(departmentScopeFilter('department-b').$or, [
    { departmentId: 'department-b' },
    { departmentId: null },
    { departmentId: { $exists: false } },
  ]);
});

test('automated response policy honors AND and OR condition logic', () => {
  const alert = { severity: 'high', category: 'malware' };
  assert.equal(playbookMatches(alert, { conditionLogic: 'AND', conditions: [
    { field: 'severity', operator: 'eq', value: 'high' },
    { field: 'category', operator: 'contains', value: 'mal' },
  ] }), true);
  assert.equal(playbookMatches(alert, { conditionLogic: 'OR', conditions: [
    { field: 'severity', operator: 'eq', value: 'critical' },
    { field: 'category', operator: 'eq', value: 'malware' },
  ] }), true);
});

test('automated response action allowlist excludes arbitrary command execution', () => {
  assert.equal(SUPPORTED_ACTIONS.has('kill_process'), true);
  assert.equal(SUPPORTED_ACTIONS.has('run_command'), false);
  assert.equal(isHighRisk('isolate'), true);
  assert.equal(isHighRisk('kill_process'), false);
});

test('approval is per action unless the playbook explicitly enables a global gate', () => {
  const playbook = { executionMode: 'approval_required', requireGlobalApproval: false };
  assert.equal(requiresApprovalForAction('send_email', playbook, false), false);
  assert.equal(requiresApprovalForAction('create_ticket', playbook, false), false);
  assert.equal(requiresApprovalForAction('disable_user', playbook, false), true);
  assert.equal(requiresApprovalForAction('send_email', { requireGlobalApproval: true }, false), true);
  assert.equal(requiresApprovalForAction('send_email', playbook, true), true);
});
