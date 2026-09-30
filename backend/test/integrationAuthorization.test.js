const test = require('node:test');
const assert = require('node:assert/strict');
const {
  deriveCompanyIntegrationKey,
  verifyCompanyIntegrationKey,
} = require('../src/security/integrationAuthorization');

test('company integration keys are tenant-bound', () => {
  const secret = 'a-production-secret-with-enough-entropy';
  const companyAKey = deriveCompanyIntegrationKey('company-a', secret);
  assert.equal(verifyCompanyIntegrationKey('company-a', companyAKey, secret), true);
  assert.equal(verifyCompanyIntegrationKey('company-b', companyAKey, secret), false);
});

test('missing integration credentials fail closed', () => {
  assert.equal(verifyCompanyIntegrationKey('company-a', '', 'secret'), false);
  assert.equal(verifyCompanyIntegrationKey('', 'key', 'secret'), false);
});
