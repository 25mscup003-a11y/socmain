const { authenticate } = require('../middleware/auth.middleware');
const EnterpriseQuote = require('../models/EnterpriseQuote.model');
const { companyForEnterprise, quoteView, saveEnterpriseQuote } = require('../services/enterpriseQuote.service');
const { emitCompanyPartnerUpdate } = require('../utils/partnerRealtime');
const { calculateAddition } = require('../services/enterpriseAddition.service');

module.exports = function enterprisePaymentRouter(payments) {
  const router = require('express').Router();
  router.use(authenticate, async (req, res, next) => {
    try {
      req.enterpriseCompany = await companyForEnterprise(req.user);
      res.set('Cache-Control', 'no-store'); next();
    } catch (error) { res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to verify Enterprise access.' }); }
  });
  const handle = fn => async (req, res) => {
    try { res.json(await fn(req)); }
    catch (error) { res.status(error.status || 503).json({ message: error.status ? error.message : 'Enterprise plan could not be processed. Please retry.' }); }
  };
  router.get('/', handle(async req => ({
    quote: quoteView(await EnterpriseQuote.findOne({ companyId: req.enterpriseCompany._id })),
    approver: req.enterpriseCompany.partnerId ? 'Partner Admin' : 'Superadmin',
  })));
  router.post('/request', handle(async req => ({ quote: quoteView(await saveEnterpriseQuote(req.enterpriseCompany, req.body, req.user.id, false)) })));
  router.post('/create-order', handle(req => payments.createOrder(req.enterpriseCompany, req.body)));
  router.post('/addition/calculate', handle(req => calculateAddition(req.enterpriseCompany, req.body)));
  router.post('/addition/create-order', handle(req => payments.createAdditionOrder(req.enterpriseCompany, req.body)));
  router.post('/confirm', handle(async req => {
    const result = await payments.confirm(req.enterpriseCompany, req.body);
    void emitCompanyPartnerUpdate(req.app?.get?.('io'), req.enterpriseCompany._id, 'company_payment');
    return result;
  }));
  return router;
};
