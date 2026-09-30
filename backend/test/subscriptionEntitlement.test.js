const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const AddSystemSubscription = require('../src/models/AddSystemSubscription.model');
const {
  getSubscriptionEntitlement,
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
