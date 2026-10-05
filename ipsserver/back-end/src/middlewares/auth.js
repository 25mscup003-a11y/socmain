const crypto = require('crypto');
const { sendError } = require('../utils/response');

// The SOC backend verifies user JWTs and forwards the authorized company scope
// with a server-to-server credential. Unverified JWT claims are never trusted.
function validSecret(provided) {
  const expected = process.env.IPS_WEBHOOK_SECRET;
  if (!expected || typeof provided !== 'string') return false;
  const actual = Buffer.from(provided);
  const secret = Buffer.from(expected);
  return actual.length === secret.length && crypto.timingSafeEqual(actual, secret);
}

function validCompany(company) {
  return typeof company === 'string' && /^[a-f\d]{24}$/i.test(company);
}

function authMiddleware(req, res, next) {
  const path = (req.url || '/').split('?')[0];
  if (req.method === 'GET' && path === '/health') return next();
  if (!process.env.IPS_WEBHOOK_SECRET) {
    return sendError(res, 'IPS_WEBHOOK_SECRET is not configured', 503);
  }
  if (!validSecret(req.headers['x-webhook-secret'])) return sendError(res, 'Unauthorized', 401);

  const url = new URL(req.url, 'http://localhost');
  const company = req.headers['x-company-id'] || req.headers['x-company']
    || url.searchParams.get('company') || url.searchParams.get('companyId');
  if (company && !validCompany(company)) return sendError(res, 'Invalid company_id', 400);
  req.company = company ? company.toLowerCase() : undefined;

  // Global reads are available to the authenticated backend. Mutations always
  // require a concrete tenant, including the legacy POST / alias.
  if (!['GET', 'HEAD'].includes(req.method) && !req.company) {
    return sendError(res, 'company_id is required — request rejected (multi-tenant policy)', 400);
  }
  return next();
}

module.exports = authMiddleware;
module.exports.validSecret = validSecret;
module.exports.validCompany = validCompany;
