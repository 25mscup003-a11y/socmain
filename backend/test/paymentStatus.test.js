const test = require('node:test');
const assert = require('node:assert/strict');
const mongoose = require('mongoose');
const Company = require('../src/models/Company.model');
const Batch = require('../src/models/AddSystemSubscription.model');
const { invalidateSubscriptionEntitlement } = require('../src/utils/subscriptionEntitlement');
const router = require('../src/routes/payment.routes');

test('payment status includes the company-scoped primary Enterprise purchase without altering its base plan', async t => {
  const companyId = new mongoose.Types.ObjectId();
  const primaryId = new mongoose.Types.ObjectId();
  const primary = { _id: primaryId, addedSystemCount: 1, addedServerCount: 2, addedPhoneCount: 3,
    status: 'active', paymentStatus: 'paid', billingCycle: 'yearly', endDate: new Date(Date.now() + 86400000) };
  const company = { _id: companyId, status: 'active', enterpriseSubscriptionId: primaryId,
    plan: { isActive: false, paymentStatus: 'unpaid' }, toObject() { return { ...this }; } };
  t.after(() => invalidateSubscriptionEntitlement(companyId));
  t.mock.method(Company, 'findById', () => ({ select: async () => company }));
  t.mock.method(Batch, 'updateMany', async () => ({}));
  t.mock.method(Batch, 'aggregate', async () => [{ batchCount: 1, systemCount: 1, serverCount: 2, phoneCount: 3, expiresAt: primary.endDate }]);
  t.mock.method(Batch, 'findOne', filter => {
    assert.deepEqual(filter, { _id: primaryId, companyId });
    return { select: () => ({ lean: async () => primary }) };
  });
  const handler = router.stack.find(layer => layer.route?.path === '/status').route.stack.at(-1).handle;
  const res = { status(code) { throw new Error(`Unexpected HTTP ${code}`); }, json(data) { this.body = data; } };
  await handler({ headers: {}, query: {}, user: { companyId } }, res);
  assert.equal(res.body.primaryEnterpriseSubscription.addedSystemCount, 1);
  assert.equal(res.body.primaryEnterpriseSubscription.addedServerCount, 2);
  assert.equal(res.body.primaryEnterpriseSubscription.addedPhoneCount, 3);
  assert.equal(res.body.primaryEnterpriseSubscription.billingCycle, 'yearly');
  assert.equal(res.body.plan.isActive, false);
  assert.equal(res.body.entitlement.licenseActive, true);
});
