const mongoose = require('mongoose');
const Alert = require('../models/Alert.model');

const UEBA_BASELINE_DAYS = 30;

async function readyUebaSystemIds({ companyId, departmentId, now = new Date() }) {
  if (!mongoose.isValidObjectId(companyId)) return [];
  const from = new Date(now.getTime() - UEBA_BASELINE_DAYS * 86400000);
  const match = {
    companyId: new mongoose.Types.ObjectId(String(companyId)),
    systemId: { $ne: null },
    isSynthetic: { $ne: true },
    createdAt: { $gte: from, $lte: now },
    capabilityIds: 11,
  };
  if (departmentId && mongoose.isValidObjectId(departmentId)) {
    match.departmentId = new mongoose.Types.ObjectId(String(departmentId));
  }

  const rows = await Alert.aggregate([
    { $match: match },
    { $group: {
      _id: '$systemId',
      observedDates: { $addToSet: { $dateToString: { date: '$createdAt', format: '%Y-%m-%d', timezone: 'UTC' } } },
      inputBaselineDays: { $max: { $convert: { input: '$inputBaselineDays', to: 'int', onError: 0, onNull: 0 } } },
    } },
  ]).option({
    allowDiskUse: true,
    maxTimeMS: 12000,
    hint: { companyId: 1, capabilityIds: 1, createdAt: -1 },
  });

  return rows.filter(row => {
    const observedDays = Math.min(
      UEBA_BASELINE_DAYS,
      Array.isArray(row.observedDates) ? row.observedDates.length : 0,
    );
    const learnedInputDays = Math.min(UEBA_BASELINE_DAYS, Math.max(0, Number(row.inputBaselineDays || 0)));
    return Math.max(observedDays, learnedInputDays) >= UEBA_BASELINE_DAYS;
  }).map(row => row._id).filter(Boolean);
}

module.exports = { UEBA_BASELINE_DAYS, readyUebaSystemIds };
