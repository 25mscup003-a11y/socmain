const Tenant = require('../models/Tenant.model');
const Referral = require('../models/Referral.model');

const ROOT_DOMAIN = process.env.ROOT_DOMAIN;
const APP_PROTO = process.env.APP_PROTO;
const COMPANY_APP_URL = process.env.COMPANY_ORIGIN || 'http://localhost:3000';
const SUPERADMIN_APP_URL = process.env.SUPERADMIN_ORIGIN || 'http://localhost:3001';

function normalizeSlug(value) {
  return String(value || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
}

async function getOrCreateMainTenant(createdBy = null) {
  let tenant = await Tenant.findOne({ type: 'main' });
  if (tenant) return tenant;

  tenant = await Tenant.create({
    name: process.env.MAIN_TENANT_NAME || 'Main Admin',
    slug: process.env.MAIN_TENANT_SLUG || 'main',
    type: 'main',
    subdomain: process.env.MAIN_TENANT_SUBDOMAIN,
    status: 'active',
    createdBy,
  });
  return tenant;
}

async function resolveReferralTenant(slug) {
  const cleanSlug = normalizeSlug(slug);
  if (!cleanSlug) return { tenant: await getOrCreateMainTenant(), partner: null, referral: null };

  const referral = await Referral.findOne({
    slug: cleanSlug,
    status: 'active',
    $or: [{ expiresAt: null }, { expiresAt: { $gt: new Date() } }],
  }).populate('partnerId');

  if (!referral) {
    const err = new Error('Invalid or expired referral link');
    err.statusCode = 404;
    throw err;
  }

  await Referral.updateOne({ _id: referral._id }, { $inc: { clicks: 1 } });
  const tenant = await Tenant.findById(referral.tenantId);
  if (!tenant || tenant.status !== 'active') {
    const err = new Error('Partner tenant is not active');
    err.statusCode = 400;
    throw err;
  }

  return { tenant, partner: referral.partnerId || null, referral };
}

function buildRegistrationUrl(slug) {
  return `${COMPANY_APP_URL}/register/${normalizeSlug(slug)}`;
}

function buildDashboardUrl(user, tenant) {
  if (user.role === 'superadmin') return SUPERADMIN_APP_URL;

  const subdomain = user.role === 'superadmin'
    ? process.env.MAIN_TENANT_SUBDOMAIN
    : tenant?.subdomain;

  if (!subdomain || ROOT_DOMAIN === 'localhost') return COMPANY_APP_URL;
  return `${APP_PROTO}://${subdomain}.${ROOT_DOMAIN}`;
}

module.exports = {
  ROOT_DOMAIN,
  normalizeSlug,
  getOrCreateMainTenant,
  resolveReferralTenant,
  buildRegistrationUrl,
  buildDashboardUrl,
};
