import test from 'node:test';
import assert from 'node:assert/strict';
import { requiresRegistrationPayment, registrationPaymentRedirect } from '../src/utils/registrationPayment.js';

const user = { role: 'company_admin' };
const pending = { status: 'pending_payment', plan: { paymentStatus: 'unpaid' } };
const redirect = location => registrationPaymentRedirect(user, pending, location);

test('unpaid registration cannot enter a dashboard, subscription page, or unknown route', () => {
  for (const pathname of ['/', '/dashboard', '/company-admin/dashboard', '/payments', '/settings', '/unknown']) {
    assert.equal(redirect({ pathname }), '/register');
  }
  assert.equal(redirect({ pathname: '/payments', search: '?tab=enterprise' }), '/register?plan=enterprise');
});

test('registration, referral registration, and valid registration checkout stay reachable', () => {
  for (const pathname of ['/register', '/register/partner-referral', '/login', '/reset-password']) {
    assert.equal(redirect({ pathname }), null);
  }
  for (const mode of ['base', 'enterprise']) {
    assert.equal(redirect({ pathname: '/checkout', state: { checkout: { mode } } }), null);
  }
  assert.equal(redirect({ pathname: '/checkout' }), '/register');
  assert.equal(redirect({ pathname: '/checkout', state: { checkout: { mode: 'add-system' } } }), '/register');
});

test('paid accounts, including expired subscriptions, do not repeat initial registration', () => {
  for (const company of [
    { status: 'active', plan: { paymentStatus: 'paid', isActive: true } },
    { status: 'active', plan: { paymentStatus: 'paid', isActive: false, expiresAt: '2020-01-01' } },
    { status: 'active', enterpriseSubscriptionId: 'paid-enterprise-batch' },
    { status: 'trial' }, { status: 'suspended' },
  ]) {
    assert.equal(requiresRegistrationPayment(user, company), false);
    assert.equal(registrationPaymentRedirect(user, company, { pathname: '/' }), null);
  }
});

test('anonymous visitors and other portal roles keep their existing flow', () => {
  for (const account of [null, { role: 'partner_admin' }, { role: 'analyst' }, { role: 'superadmin' }]) {
    assert.equal(requiresRegistrationPayment(account, pending), false);
  }
});
