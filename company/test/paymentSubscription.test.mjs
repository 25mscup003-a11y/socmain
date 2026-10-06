import test from 'node:test';
import assert from 'node:assert/strict';
import { paymentSubscription, hasSubscriptionExpired, canRenewBatch } from '../src/utils/paymentSubscription.js';

const now = new Date('2026-10-06T18:30:00Z');
const primary = { _id: 'enterprise-primary', status: 'active', paymentStatus: 'paid',
  addedSystemCount: 1, addedServerCount: 2, addedPhoneCount: 3, endDate: '2027-10-06' };
const company = { enterpriseSubscriptionId: primary._id, primaryEnterpriseSubscription: primary,
  plan: { isActive: false, paymentStatus: 'unpaid', baseSystemCount: 0, baseServerCount: 0, basePhoneCount: 0 } };

test('renewal buttons unlock at each expiry and never for cancelled, unpaid or undated purchases', () => {
  assert.equal(hasSubscriptionExpired(now, new Date(+now - 1)), false);
  assert.equal(hasSubscriptionExpired(now, now), true);
  for (const value of [undefined, null, '', 'invalid']) assert.equal(hasSubscriptionExpired(value, now), false);
  const expiring = { ...primary, endDate: now };
  assert.equal(canRenewBatch(expiring, now), true);
  assert.equal(canRenewBatch(primary, now), false);
  assert.equal(canRenewBatch({ ...expiring, status: 'cancelled' }, now), false);
  assert.equal(canRenewBatch({ ...expiring, paymentStatus: 'unpaid' }, now), false);
});

test('Enterprise registration counts load from payment status without waiting for purchase history', () => {
  const summary = paymentSubscription(company, [], now);
  assert.equal(summary.enterpriseRegistration, true);
  assert.equal(summary.planActive, true);
  assert.equal(summary.currentPlanSystems, 1);
  assert.equal(summary.currentPlanServers, 2);
  assert.equal(summary.currentPlanPhones, 3);
  assert.equal(summary.totalSystemCount, 1);
  assert.equal(summary.totalServerCount, 2);
  assert.equal(summary.totalPhoneCount, 3);
  assert.equal(summary.additionalBatches.length, 0);
});

test('primary Enterprise purchase counts once when it appears in both responses', () => {
  const addition = { ...primary, _id: 'addition', addedSystemCount: '4', addedServerCount: '0', addedPhoneCount: '1' };
  const summary = paymentSubscription(company, [primary, addition], now);
  assert.equal(summary.currentPlanSystems, 1);
  assert.equal(summary.addedSystemCount, 4);
  assert.equal(summary.totalSystemCount, 5);
  assert.equal(summary.totalServerCount, 2);
  assert.equal(summary.totalPhoneCount, 4);
  assert.equal(summary.additionalBatches.length, 1);
});

test('server totals stay available from entitlement while additional purchases are still loading', () => {
  const summary = paymentSubscription({ ...company, entitlement: { batchSystemCount: 5, batchServerCount: 6, batchPhoneCount: 7 } }, [], now);
  assert.equal(summary.currentPlanSystems, 1);
  assert.equal(summary.totalSystemCount, 5);
  assert.equal(summary.totalServerCount, 6);
  assert.equal(summary.totalPhoneCount, 7);
});

test('paid dynamic base and Enterprise additions keep separate counts and renew only base quantities', () => {
  const summary = paymentSubscription({ plan: { paymentStatus: 'paid', isActive: true, expiresAt: '2027-01-01',
    baseSystemCount: 10, baseServerCount: 0, basePhoneCount: 0, systemCount: 11, serverCount: 2, phoneCount: 3 } }, [primary], now);
  assert.equal(summary.enterpriseRegistration, false);
  assert.equal(summary.baseSystemCount, 10);
  assert.equal(summary.baseServerCount, 0);
  assert.equal(summary.basePhoneCount, 0);
  assert.equal(summary.totalSystemCount, 11);
  assert.equal(summary.totalServerCount, 2);
  assert.equal(summary.totalPhoneCount, 3);
});

test('expired, cancelled and unpaid purchases do not inflate active counts', () => {
  const expired = { ...primary, endDate: '2026-10-01', status: 'active' };
  const summary = paymentSubscription({ ...company, primaryEnterpriseSubscription: expired }, [
    expired, { ...primary, _id: 'cancelled', status: 'cancelled' },
    { ...primary, _id: 'unpaid', paymentStatus: 'unpaid' },
  ], now);
  assert.equal(summary.currentPlanSystems, 1);
  assert.equal(summary.planActive, false);
  assert.equal(summary.totalSystemCount, 0);
  assert.equal(summary.totalServerCount, 0);
  assert.equal(summary.totalPhoneCount, 0);
});

test('expired dynamic base counts remain available for renewal but are excluded from total active usage', () => {
  const summary = paymentSubscription({ plan: { isActive: true, expiresAt: '2026-10-01', paymentStatus: 'paid',
    baseSystemCount: 10, baseServerCount: 0, basePhoneCount: 0 } }, [primary], now);
  assert.equal(summary.baseSystemCount, 10);
  assert.equal(summary.totalSystemCount, 1);
});

test('older responses use the referenced batch and never substitute a different Enterprise purchase', () => {
  assert.equal(paymentSubscription({ ...company, primaryEnterpriseSubscription: null }, [primary], now).currentPlanSystems, 1);
  const wrong = { ...primary, _id: 'different-purchase', addedSystemCount: 99 };
  assert.equal(paymentSubscription({ ...company, primaryEnterpriseSubscription: wrong }, [], now).currentPlanSystems, 0);
});

test('Enterprise renewal details include the purchased registration plan, including after expiry', () => {
  const active = paymentSubscription(company, [primary], now);
  assert.equal(active.enterpriseRenewalPlans[0]._id, primary._id);
  assert.equal(active.enterpriseRenewalPlans.length, 1);
  const expired = { ...primary, status: 'expired', endDate: '2026-10-01' };
  assert.equal(paymentSubscription({ ...company, primaryEnterpriseSubscription: expired }, [expired], now).enterpriseRenewalPlans[0].status, 'expired');
});

test('Enterprise renewal shows plans while all added licenses stay in Add-System batches', () => {
  const addition = { ...primary, _id: 'enterprise-addition', priceType: 'enterprise_addition' };
  const ordinary = { ...primary, _id: 'ordinary-batch', priceType: 'renewal' };
  const summary = paymentSubscription(company, [primary, addition, ordinary], now);
  assert.deepEqual(summary.enterpriseRenewalPlans.map(plan => plan._id), [primary._id]);
  assert.deepEqual(summary.additionalHistory.map(plan => plan._id), [addition._id, ordinary._id]);
});

test('both registration choices preserve base counts when Dynamic Pricing licenses are added', () => {
  const added = { ...primary, _id: 'dynamic-addition', addedSystemCount: 5, addedServerCount: 0, addedPhoneCount: 0, priceType: 'renewal' };
  const enterpriseBase = { ...primary, addedSystemCount: 10, addedServerCount: 0, addedPhoneCount: 0, priceType: 'enterprise' };
  const enterprise = paymentSubscription({ ...company, primaryEnterpriseSubscription: enterpriseBase }, [enterpriseBase, added], now);
  const dynamic = paymentSubscription({ plan: { paymentStatus: 'paid', isActive: true, baseSystemCount: 10, baseServerCount: 0, basePhoneCount: 0, expiresAt: primary.endDate } }, [added], now);
  for (const summary of [enterprise, dynamic]) {
    assert.equal(summary.currentPlanSystems, 10);
    assert.equal(summary.addedSystemCount, 5);
    assert.equal(summary.totalSystemCount, 15);
    assert.deepEqual(summary.additionalHistory.map(batch => batch._id), [added._id]);
  }
  assert.deepEqual(enterprise.enterpriseRenewalPlans.map(batch => batch._id), [primary._id]);
});

test('Enterprise details show only purchased Enterprise plans', () => {
  const base = { plan: { isActive: false, paymentStatus: 'paid', expiresAt: '2026-10-01', baseSystemCount: 10 } };
  assert.deepEqual(paymentSubscription(base, [], now).enterpriseRenewalPlans, []);
  const enterprise = { ...primary, priceType: 'enterprise' };
  assert.equal(paymentSubscription(base, [enterprise], now).enterpriseRenewalPlans[0]._id, primary._id);
});

test('unpaid configurations and cancelled purchases are excluded from Enterprise details', () => {
  const unpaid = { plan: { isActive: false, paymentStatus: 'unpaid', baseSystemCount: 10 } };
  assert.deepEqual(paymentSubscription(unpaid, [
    { ...primary, priceType: 'enterprise', paymentStatus: 'unpaid' },
    { ...primary, _id: 'cancelled', status: 'cancelled' },
  ], now).enterpriseRenewalPlans, []);
});
