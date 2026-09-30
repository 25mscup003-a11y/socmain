const router = require('express').Router();
const Tenant = require('../models/Tenant.model');
const Referral = require('../models/Referral.model');
const { tenantResolver } = require('../middleware/tenant.middleware');
const { getOrCreateMainTenant } = require('../utils/tenant');

router.get('/current', tenantResolver, async (req, res) => {
  const tenant = req.tenant || await getOrCreateMainTenant();
  res.json({ tenant });
});

router.get('/referral/:slug', async (req, res) => {
  try {
    const referral = await Referral.findOne({
      slug: req.params.slug.toLowerCase(),
      status: 'active',
      $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
    }).populate('partnerId', 'name slug').lean();

    if (!referral) return res.status(404).json({ message: 'Invalid or expired referral link' });

    const tenant = await Tenant.findById(referral.tenantId).lean();
    res.json({ referral, tenant, partner: referral.partnerId });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

module.exports = router;
