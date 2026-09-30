const Tenant = require('../models/Tenant.model');
const Partner = require('../models/Partner.model');
const User = require('../models/User.model');
const Referral = require('../models/Referral.model');
const { buildRegistrationUrl, normalizeSlug } = require('../utils/tenant');

async function registerPartner(req, res) {
  const { name, slug, adminName, adminEmail, adminPassword, confirmPassword, phone, mobile } = req.body;
  const cleanName = String(name || '').trim();
  const cleanState = normalizeSlug(slug);
  const cleanSlug = normalizeSlug(cleanState ? `${cleanName}-${cleanState}` : cleanName);
  const cleanEmail = String(adminEmail || '').trim().toLowerCase();
  const password = String(adminPassword || '').trim();
  const cleanMobile = String(mobile || phone || '').trim();

  if (!cleanName || !cleanSlug || !cleanEmail || !password) {
    return res.status(400).json({ message: 'Partner company name, state, admin email and password are required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ message: 'Password must be at least 8 characters' });
  }
  if (confirmPassword !== undefined && password !== String(confirmPassword || '').trim()) {
    return res.status(400).json({ message: 'Password and confirm password do not match' });
  }

  try {
    const existing = await Promise.all([
      Tenant.findOne({ $or: [{ slug: cleanSlug }, { subdomain: cleanSlug }] }),
      Partner.findOne({ slug: cleanSlug }),
      User.findOne({ email: cleanEmail }),
    ]);
    if (existing[0] || existing[1]) return res.status(400).json({ message: 'Partner slug/subdomain already exists' });
    if (existing[2]) return res.status(400).json({ message: 'Admin email already registered' });

    const tenant = await Tenant.create({
      name: cleanName,
      slug: cleanSlug,
      type: 'partner',
      subdomain: cleanSlug,
      status: 'active',
      settings: { publicRegistration: true, phone: cleanMobile },
    });

    const partner = await Partner.create({
      tenantId: tenant._id,
      name: cleanName,
      slug: cleanSlug,
      mobile: cleanMobile,
      status: 'pending_request',
      plan: {
        type: 'enterprise',
        paymentStatus: 'unpaid',
        isActive: false,
        requestStatus: 'none',
      },
    });

    const referral = await Referral.create({
      tenantId: tenant._id,
      partnerId: partner._id,
      slug: cleanSlug,
      url: buildRegistrationUrl(cleanSlug),
    });

    const partnerAdmin = await User.create({
      name: String(adminName || `${cleanName} Admin`).trim(),
      email: cleanEmail,
      password,
      phone: cleanMobile,
      role: 'partner_admin',
      tenantId: tenant._id,
      partnerId: partner._id,
      isActive: false,
      isEmailVerified: true,
    });

    partner.ownerUserId = partnerAdmin._id;
    await partner.save();

    res.status(201).json({
      message: 'Partner registration submitted',
      tenant: { id: tenant._id, name: tenant.name, subdomain: tenant.subdomain },
      partner: { id: partner._id, name: partner.name, slug: partner.slug, status: partner.status },
      referral: { id: referral._id, url: referral.url },
      partnerAdmin: { id: partnerAdmin._id, name: partnerAdmin.name, email: partnerAdmin.email },
    });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
}

module.exports = { registerPartner };
