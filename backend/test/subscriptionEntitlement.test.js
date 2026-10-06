const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const AddSystemSubscription = require('../src/models/AddSystemSubscription.model');
const {
  getSubscriptionEntitlement,
  withSubscriptionEntitlements,
  invalidateSubscriptionEntitlement,
} = require('../src/utils/subscriptionEntitlement');

test('subscription entitlement coalesces repeated company lookups', async () => {
  const originalUpdateMany = AddSystemSubscription.updateMany;
  const originalAggregate = AddSystemSubscription.aggregate;
  let updates = 0;
  let aggregates = 0;
  AddSystemSubscription.updateMany = async () => { updates += 1; return { modifiedCount: 0 }; };
  AddSystemSubscription.aggregate = async () => {
    aggregates += 1;
    return [{ batchCount: 1, systemCount: 5, expiresAt: new Date(Date.now() + 60000) }];
  };
  const company = {
    _id: new mongoose.Types.ObjectId(),
    plan: { isActive: true, expiresAt: new Date(Date.now() + 60000) },
  };

  try {
    const [first, second] = await Promise.all([
      getSubscriptionEntitlement(company),
      getSubscriptionEntitlement(company),
    ]);
    assert.equal(first.licenseActive, true);
    assert.deepEqual(second, first);
    assert.equal(updates, 1);
    assert.equal(aggregates, 1);

    invalidateSubscriptionEntitlement(company._id);
    await getSubscriptionEntitlement(company);
    assert.equal(aggregates, 2);
  } finally {
    invalidateSubscriptionEntitlement(company._id);
    AddSystemSubscription.updateMany = originalUpdateMany;
    AddSystemSubscription.aggregate = originalAggregate;
  }
});

test('subscription list includes paid Enterprise batches without activating the unpaid base plan', async t => {
  const now = new Date('2026-10-06T18:00:00Z');
  const enterprise = { _id: new mongoose.Types.ObjectId(), status: 'active', plan: { isActive: false, paymentStatus: 'unpaid' } };
  const pending = { _id: new mongoose.Types.ObjectId(), status: 'pending_payment', plan: { isActive: false } };
  const base = { _id: new mongoose.Types.ObjectId(), status: 'active', plan: { isActive: true, expiresAt: new Date('2026-11-01') } };
  const expired = { _id: new mongoose.Types.ObjectId(), status: 'active', plan: { isActive: true, expiresAt: new Date('2026-10-01') } };
  const companies = [enterprise, pending, base, expired];
  let queries = 0;
  t.mock.method(AddSystemSubscription, 'aggregate', async pipeline => {
    queries++;
    assert.deepEqual(pipeline[0].$match.companyId.$in, companies.map(company => company._id));
    assert.equal(pipeline[0].$match.status, 'active');
    assert.deepEqual(pipeline[0].$match.endDate, { $gt: now });
    assert.deepEqual(pipeline[0].$match.$or, [{ paymentStatus: 'paid' }, { paymentStatus: { $exists: false } }]);
    assert.equal(pipeline[1].$group._id, '$companyId');
    return [{ _id: enterprise._id, batchCount: 1, systemCount: 1, expiresAt: new Date('2027-10-06') }];
  });
  t.mock.method(AddSystemSubscription, 'updateMany', () => { throw new Error('List reads must not modify payments'); });
  const result = await withSubscriptionEntitlements(companies, now);
  assert.equal(queries, 1);
  assert.equal(result[0].entitlement.licenseActive, true);
  assert.equal(result[0].entitlement.baseActive, false);
  assert.equal(result[0].entitlement.batchActive, true);
  assert.equal(result[0].entitlement.batchExpiresAt.toISOString(), '2027-10-06T00:00:00.000Z');
  assert.equal(result[0].plan.isActive, false);
  assert.equal(result[0].plan.paymentStatus, 'unpaid');
  assert.equal(result[1].entitlement.licenseActive, false);
  assert.equal(result[2].entitlement.licenseActive, true);
  assert.equal(result[3].entitlement.licenseActive, false);
  assert.equal(enterprise.entitlement, undefined);
});

test('empty subscription lists skip the batch query', async t => {
  t.mock.method(AddSystemSubscription, 'aggregate', () => { throw new Error('Unexpected query'); });
  assert.deepEqual(await withSubscriptionEntitlements([]), []);
});
