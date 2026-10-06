const Pricing = require('../models/Pricing.model');
const Company = require('../models/Company.model');
const Partner = require('../models/Partner.model');

// All Add Systems purchases use Dynamic Pricing's existing-user rates.
async function getCurrentPricing() {
  let pricing = await Pricing.findOne({ isActive: true }).sort({ updatedAt: -1 });
  if (!pricing) pricing = await Pricing.create({});
  let dirty = false;
  if (!pricing.renewal_pricePerSystemMonthly) {
    pricing.renewal_pricePerSystemMonthly = pricing.pricePerSystemMonthly || 200;
    pricing.renewal_pricePerSystemYearly = pricing.pricePerSystemYearly || 2000;
    pricing.renewal_pricePerPhoneMonthly = pricing.pricePerPhoneMonthly || pricing.pricePerSystemMonthly || 200;
    pricing.renewal_pricePerPhoneYearly = pricing.pricePerPhoneYearly || pricing.pricePerSystemYearly || 2000;
    pricing.renewal_pricePerServerMonthly = pricing.pricePerServerMonthly || 500;
    pricing.renewal_pricePerServerYearly = pricing.pricePerServerYearly || 5000;
    dirty = true;
  }
  if (!pricing.renewal_pricePerPhoneMonthly) {
    pricing.renewal_pricePerPhoneMonthly = pricing.pricePerPhoneMonthly || pricing.renewal_pricePerSystemMonthly || 200;
    pricing.renewal_pricePerPhoneYearly = pricing.pricePerPhoneYearly || pricing.renewal_pricePerSystemYearly || 2000;
    dirty = true;
  }
  if (dirty) await pricing.save();
  return pricing;
}

const pricingKeys = ['pricePerSystemMonthly', 'pricePerSystemYearly', 'pricePerPhoneMonthly', 'pricePerPhoneYearly', 'pricePerServerMonthly', 'pricePerServerYearly'];

async function getEffectiveRenewalPriceSet(companyId) {
  const pricing = await getCurrentPricing();
  const globalSet = Object.fromEntries(pricingKeys.map(key => [key, pricing[`renewal_${key}`]]));
  if (!companyId) return globalSet;
  const company = await Company.findById(companyId).select('partnerId').lean();
  if (!company?.partnerId) return globalSet;
  const partner = await Partner.findById(company.partnerId).select('companyPricing').lean();
  const partnerSet = partner?.companyPricing?.renewal;
  if (!pricingKeys.some(key => Number(partnerSet?.[key] || 0) > 0)) return globalSet;
  return Object.fromEntries(pricingKeys.map(key => [key, Number(partnerSet[key] || globalSet[key] || 0)]));
}

function licenseSubtotals(pricing, counts, billingCycle) {
  const cycle = billingCycle === 'yearly' ? 'Yearly' : 'Monthly';
  const subtotal = (type, key) => Math.round(Number(counts[key] || 0) * Number(pricing[`pricePer${type}${cycle}`] || 0) * 100) / 100;
  const subtotalSystems = subtotal('System', 'systemCount');
  const subtotalServers = subtotal('Server', 'serverCount');
  const subtotalPhones = subtotal('Phone', 'phoneCount');
  return { subtotalSystems, subtotalServers, subtotalPhones, totalInr: Math.round((subtotalSystems + subtotalServers + subtotalPhones) * 100) / 100 };
}

module.exports = { getEffectiveRenewalPriceSet, licenseSubtotals };
