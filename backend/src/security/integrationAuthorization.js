const crypto = require('crypto');

function deriveCompanyIntegrationKey(companyId, secret) {
  if (!companyId || !secret) return '';
  return crypto.createHmac('sha256', secret).update(String(companyId)).digest('hex');
}

function safeEqual(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function verifyCompanyIntegrationKey(companyId, key, secret) {
  return Boolean(key && safeEqual(key, deriveCompanyIntegrationKey(companyId, secret)));
}

module.exports = { deriveCompanyIntegrationKey, verifyCompanyIntegrationKey };
