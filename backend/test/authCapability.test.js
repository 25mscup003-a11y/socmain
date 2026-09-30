const test = require('node:test');
const assert = require('node:assert/strict');
const { authCapabilityFilter, isAuthCapabilityTelemetry } = require('../src/utils/authCapability');

test('auth classifier accepts real authentication telemetry', () => {
  assert.equal(isAuthCapabilityTelemetry({ rule_id: 'AUTH_SUCCESS', user_action: 'login' }), true);
  assert.equal(isAuthCapabilityTelemetry({ event_type: 'mfa_challenge' }), true);
  assert.equal(isAuthCapabilityTelemetry({ description: 'Failed password for invalid user from 10.0.0.1' }), true);
});

test('auth classifier rejects process inventory and unauthorized process events', () => {
  assert.equal(isAuthCapabilityTelemetry({ rule_id: 'PROC_INVENTORY_SUMMARY', description: 'Running process inventory: 399 processes' }), false);
  assert.equal(isAuthCapabilityTelemetry({ rule_id: 'PROC_UNAUTHORIZED_EXECUTION', description: 'Unauthorized process location: bwrap' }), false);
});

test('dashboard auth query has explicit capability and auth evidence without broad full-log matching', () => {
  const query = authCapabilityFilter();
  const evidence = query.$and.find(clause => Array.isArray(clause.$or)).$or;
  assert.ok(evidence.some(clause => clause.capabilityId === 4));
  assert.equal(evidence.some(clause => Object.hasOwn(clause, 'full_log')), false);
  assert.equal(evidence.some(clause => Object.hasOwn(clause, 'processName')), false);
  assert.ok(query.$and.some(clause => Array.isArray(clause.$nor)));
});
