const test = require('node:test');
const assert = require('node:assert/strict');
const { dashboardCompanySummary } = require('../src/utils/companyPublicView');

test('company dashboard summary excludes credentials and payment identifiers', () => {
  const summary = dashboardCompanySummary({
    _id: 'company-1', name: 'Example', status: 'active', riskScore: 2,
    email: 'private@example.test', phone: '9999999999', agentKey: 'secret-agent-key',
    twoFactorSecret: 'secret-2fa',
    razorpay: { paymentId: 'pay_secret', signature: 'payment-signature' },
    plan: {
      type: 'custom', isActive: true, systemLimit: 5, billingCycle: 'monthly',
      amountPaid: 100, autoPayMethod: 'pay_secret', expiresAt: new Date('2026-09-26T00:00:00Z'),
    },
  });

  assert.equal(summary.name, 'Example');
  assert.equal(summary.plan.systemLimit, 5);
  assert.equal(summary.agentKey, undefined);
  assert.equal(summary.twoFactorSecret, undefined);
  assert.equal(summary.razorpay, undefined);
  assert.equal(summary.email, undefined);
  assert.equal(summary.phone, undefined);
  assert.equal(summary.plan.amountPaid, undefined);
  assert.equal(summary.plan.autoPayMethod, undefined);
});
