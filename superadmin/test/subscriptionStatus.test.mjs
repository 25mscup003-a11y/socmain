import test from 'node:test';
import assert from 'node:assert/strict';
import { subscriptionStatus } from '../src/utils/subscriptionStatus.js';

const now = Date.parse('2026-10-06T18:00:00Z');

test('paid Enterprise subscription is active even though the base plan is unpaid', () => {
  assert.deepEqual(subscriptionStatus({
    status: 'active', plan: { isActive: false, paymentStatus: 'unpaid' },
    entitlement: { baseActive: false, batchActive: true, batchExpiresAt: '2027-10-06T18:04:48.000Z' },
  }, now), { active: true, pending: false, expiresAt: '2027-10-06T18:04:48.000Z' });
});

test('expired base plans stay active when a paid independent batch is still valid', () => {
  const result = subscriptionStatus({ status: 'active', plan: { isActive: true, expiresAt: '2026-10-01' },
    entitlement: { baseActive: false, batchActive: true, batchExpiresAt: '2026-11-01' } }, now);
  assert.equal(result.active, true);
  assert.equal(result.expiresAt, '2026-11-01T00:00:00.000Z');
});

test('company account status alone does not make an expired or unpaid subscription active', () => {
  assert.equal(subscriptionStatus({ status: 'active', plan: { isActive: true, expiresAt: '2026-10-01' },
    entitlement: { baseActive: false, batchActive: false } }, now).active, false);
  assert.equal(subscriptionStatus({ status: 'pending_payment', plan: { isActive: false } }, now).pending, true);
});

test('active base plans without an expiry remain active, and combined plans show the last active expiry', () => {
  assert.deepEqual(subscriptionStatus({ plan: { isActive: true } }, now), { active: true, pending: false, expiresAt: null });
  const result = subscriptionStatus({ plan: { isActive: true, expiresAt: '2026-12-01' },
    entitlement: { baseActive: true, batchActive: true, batchExpiresAt: '2026-11-01' } }, now);
  assert.equal(result.expiresAt, '2026-12-01T00:00:00.000Z');
});
