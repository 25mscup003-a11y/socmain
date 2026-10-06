const mongoose = require('mongoose');
const AddSystemSubscription = require('../models/AddSystemSubscription.model');
const Company = require('../models/Company.model');
const PaymentHistory = require('../models/PaymentHistory.model');
const { isBasePlanActive } = require('../utils/subscriptionEntitlement');

async function recalculateTotals(companyId) {
  // ✅ Convert to ObjectId FIRST — critical for aggregate $match
  const oid = new mongoose.Types.ObjectId(companyId.toString());
  const now = new Date();

  // Expire stale batches using ObjectId
  await AddSystemSubscription.updateMany(
    { companyId: oid, status: 'active', endDate: { $lt: now } },
    { $set: { status: 'expired' } }
  );

  // Sum all still-active add-system batches
  const result = await AddSystemSubscription.aggregate([
    { $match: { companyId: oid, status: 'active' } },   // ✅ ObjectId, not string
    { $group: {
	      _id: null,
	      totalSys: { $sum: '$addedSystemCount' },
	      totalSrv: { $sum: '$addedServerCount' },
	      totalPhn: { $sum: '$addedPhoneCount' },
	    }},
	  ]);
	  const addedSys = result[0]?.totalSys || 0;
	  const addedSrv = result[0]?.totalSrv || 0;
	  const addedPhn = result[0]?.totalPhn || 0;

	  console.log(`[recalc] aggregate result: addedSys=${addedSys}, addedSrv=${addedSrv}, addedPhn=${addedPhn}`);

  // Load current company to get baseSystemCount
  const company = await Company.findById(oid);
  if (!company) return null;

  const hasPaidBasePlan = isBasePlanActive(company.plan, now);
	  let storedBaseSys = Number(company.plan?.baseSystemCount) || 0;
	  let storedBaseSrv = Number(company.plan?.baseServerCount) || 0;
	  let storedBasePhn = Number(company.plan?.basePhoneCount) || 0;
	  const currentTotalSys = Number(company.plan?.systemCount) || 0;
	  const currentTotalSrv = Number(company.plan?.serverCount) || 0;
	  const currentTotalPhn = Number(company.plan?.phoneCount) || 0;

  // Older recalculations could erase expired base counts. Recover the original
  // registration quantities from payment history, then preserve them forever.
  if (storedBaseSys + storedBaseSrv + storedBasePhn === 0) {
    const originalBasePayment = await PaymentHistory.findOne({
      companyId: oid,
      status: 'captured',
      isUpgrade: false,
      planType: { $ne: 'add_system' },
    }).sort({ paidAt: -1, createdAt: -1 }).lean();
    storedBaseSys = Number(originalBasePayment?.systemCount) || 0;
    storedBaseSrv = Number(originalBasePayment?.serverCount) || 0;
    storedBasePhn = Number(originalBasePayment?.phoneCount) || 0;
  }

  // Base registration plan is independent from add-system batches.
  // If the base plan is unpaid/inactive, active add-system batches still count,
  // but its stored quantities remain available for display and renewal.
  const enterpriseOnly = company.enterpriseSubscriptionId && company.plan?.paymentStatus !== 'paid';
  const configuredBaseSys = enterpriseOnly ? 0 : storedBaseSys > 0 ? storedBaseSys : Math.max(0, currentTotalSys - addedSys);
  const configuredBaseSrv = enterpriseOnly ? 0 : storedBaseSrv > 0 ? storedBaseSrv : Math.max(0, currentTotalSrv - addedSrv);
  const configuredBasePhn = enterpriseOnly ? 0 : storedBasePhn > 0 ? storedBasePhn : Math.max(0, currentTotalPhn - addedPhn);
  const baseSys = hasPaidBasePlan
    ? configuredBaseSys
    : 0;
	  const baseSrv = hasPaidBasePlan
	    ? configuredBaseSrv
	    : 0;
	  const basePhn = hasPaidBasePlan
	    ? configuredBasePhn
	    : 0;

	  const totalSys = baseSys + addedSys;
	  const totalSrv = baseSrv + addedSrv;
	  const totalPhn = basePhn + addedPhn;

  // ✅ Update plan.systemCount = total (what every page reads)
  const updated = await Company.findByIdAndUpdate(
    oid,
    {
	      'plan.baseSystemCount': configuredBaseSys,
	      'plan.baseServerCount': configuredBaseSrv,
	      'plan.basePhoneCount':  configuredBasePhn,
	      'plan.systemCount':     totalSys,
	      'plan.serverCount':     totalSrv,
	      'plan.phoneCount':      totalPhn,
	      'plan.systemLimit':     totalSys + totalSrv + totalPhn,   // legacy compat
    },
    { new: true }
  );

	  console.log(`[recalc] ✅ activeBase=${baseSys}+${baseSrv}+${basePhn} | storedBase=${configuredBaseSys}+${configuredBaseSrv}+${configuredBasePhn} | added=${addedSys}+${addedSrv}+${addedPhn} | total=${totalSys}+${totalSrv}+${totalPhn}`);
  return updated;
}

module.exports = recalculateTotals;
