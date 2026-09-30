const mongoose = require('mongoose');
const System = require('../models/System.model');

async function backfillFimBaselines(options = {}) {
  const connection = options.connection || mongoose.connection;
  if (connection.readyState !== 1) {
    return { ok: false, skipped: true, reason: 'database_not_ready', matched: 0, modified: 0 };
  }

  const updateMany = options.updateMany || ((filter, update) => (
    System.updateMany(filter, update).setOptions({ maxTimeMS: Number(process.env.FIM_BACKFILL_MAX_TIME_MS || 15000) })
  ));
  const result = await updateMany(
    { fimStartAt: null, installDate: { $ne: null }, isActive: true },
    [{ $set: { fimStartAt: '$installDate' } }],
  );
  return {
    ok: true,
    skipped: false,
    matched: Number(result?.matchedCount || 0),
    modified: Number(result?.modifiedCount || 0),
  };
}

module.exports = { backfillFimBaselines };
