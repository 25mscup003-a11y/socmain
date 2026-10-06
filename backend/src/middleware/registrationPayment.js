const Company = require('../models/Company.model');

// Only initial registration is gated. Renewal/expiry keeps its existing flow.
async function requireRegistrationPayment(req, res, next) {
  if (req.user?.role !== 'company_admin' || !req.user.companyId) return next();
  const path = (req.originalUrl || `${req.baseUrl || ''}${req.path || req.url || ''}`).split('?')[0];
  if (/^\/api\/(auth|payment|pricing|2fa)(\/|$)/.test(path)) return next();
  try {
    const company = await Company.findById(req.user.companyId).select('status').lean();
    if (!company) return res.status(404).json({ message: 'Company not found' });
    if (company.status === 'pending_payment') {
      return res.status(402).json({
        code: 'REGISTRATION_PAYMENT_REQUIRED',
        message: 'Complete your plan payment to finish registration.',
        redirectUrl: '/register',
      });
    }
  } catch {
    return res.status(503).json({ message: 'Unable to check registration payment. Please retry.' });
  }
  return next();
}

module.exports = { requireRegistrationPayment };
