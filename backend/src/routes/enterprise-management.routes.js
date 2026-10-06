const mongoose = require('mongoose');
const Company = require('../models/Company.model');
const EnterpriseQuote = require('../models/EnterpriseQuote.model');
const { activePartnerActor } = require('../services/partnerUserAccess.service');
const { quoteView, saveEnterpriseQuote } = require('../services/enterpriseQuote.service');

module.exports = function enterpriseManagementRouter(role) {
  const router = require('express').Router();
  router.use(async (req, res, next) => {
    try {
      if (role === 'partner') req.enterpriseActor = await activePartnerActor(req.user);
      else req.enterpriseActor = req.activeUser;
      req.enterpriseScope = role === 'partner' ? { partnerId: req.enterpriseActor.partnerId } : {};
      res.set('Cache-Control', 'no-store');
      next();
    } catch (error) { res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to verify Enterprise access.' }); }
  });
  router.get('/', async (req, res) => {
    try {
      const companies = await Company.find(req.enterpriseScope).select('_id name email partnerId').sort({ name: 1 }).lean();
      const quotes = await EnterpriseQuote.find({ companyId: { $in: companies.map(company => company._id) } }).lean();
      const byCompany = new Map(quotes.map(quote => [String(quote.companyId), quote]));
      res.json(companies.map(company => ({ _id: company._id, name: company.name, email: company.email, quote: quoteView(byCompany.get(String(company._id))) })));
    } catch { res.status(503).json({ message: 'Unable to load Enterprise plans. Please retry.' }); }
  });
  router.put('/:companyId', async (req, res) => {
    if (!mongoose.isObjectIdOrHexString(req.params.companyId)) return res.status(400).json({ message: 'Invalid company ID.' });
    try {
      const company = await Company.findOne({ _id: req.params.companyId, ...req.enterpriseScope }).select('_id partnerId');
      if (!company) return res.status(404).json({ message: 'Company not found in your scope.' });
      res.json(quoteView(await saveEnterpriseQuote(company, req.body, req.enterpriseActor._id, true)));
    } catch (error) { res.status(error.status || 503).json({ message: error.status ? error.message : 'Unable to save the Enterprise quote.' }); }
  });
  return router;
};
