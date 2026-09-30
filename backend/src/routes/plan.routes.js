/**
 * plan.routes.js — Dynamic plan API (no predefined plans)
 * 
 * All pricing is controlled by Super Admin via /api/pricing
 * GET /api/plans/my — Current company's active plan
 */
const router  = require('express').Router();
const Company = require('../models/Company.model');
const Pricing = require('../models/Pricing.model');
const { authenticate, requireCompanyAdmin } = require('../middleware/auth.middleware');

// GET /api/plans — redirect to dynamic pricing info
router.get('/', async (req, res) => {
  try {
    let pricing = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 });
    if (!pricing) {
      pricing = {
	        pricePerSystemMonthly: 200,
	        pricePerSystemYearly:  2000,
	        pricePerPhoneMonthly:  200,
	        pricePerPhoneYearly:   2000,
	        pricePerServerMonthly: 500,
        pricePerServerYearly:  5000,
      };
    }
    res.json({
      message: 'Pricing is dynamic. Configure systems and servers based on your needs.',
      pricing: {
	        pricePerSystemMonthly: pricing.pricePerSystemMonthly,
	        pricePerSystemYearly:  pricing.pricePerSystemYearly,
	        pricePerPhoneMonthly:  pricing.pricePerPhoneMonthly,
	        pricePerPhoneYearly:   pricing.pricePerPhoneYearly,
	        pricePerServerMonthly: pricing.pricePerServerMonthly,
        pricePerServerYearly:  pricing.pricePerServerYearly,
      },
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// GET /api/plans/my — authenticated company's current plan
router.get('/my', authenticate, requireCompanyAdmin, async (req, res) => {
  try {
    const company = await Company.findById(req.user.companyId)
      .select('plan status razorpay name').lean();
    if (!company) return res.status(404).json({ message: 'Company not found' });
    res.json({
      plan: {
	        systemCount:  company.plan?.systemCount || 0,
	        serverCount:  company.plan?.serverCount || 0,
	        phoneCount:   company.plan?.phoneCount || 0,
        billingCycle: company.plan?.billingCycle || 'monthly',
        isActive:     company.plan?.isActive || false,
        expiresAt:    company.plan?.expiresAt,
        startDate:    company.plan?.startDate,
        amountPaid:   company.plan?.amountPaid,
        autoPay:      company.plan?.autoPay,
      },
      status: company.status,
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
