require('dotenv').config();
const mongoose = require('mongoose');
const connectDB = require('../src/config/db');
const Alert = require('../src/models/Alert.model');
const { inferSecurityModule } = require('../src/utils/securityEventNormalizer');

const BATCH_SIZE = 500;

async function backfillSecurityModules() {
  await connectDB();
  const cursor = Alert.collection.find({
    $or: [
      { module: { $exists: false } },
      { module: null },
      { module: '' },
      { sourceType: { $exists: false } },
      { sourceType: null },
      { sourceType: '' },
    ],
  }, {
    projection: {
      module: 1, sourceType: 1, source_type: 1, source: 1, sensor: 1,
      ruleId: 1, type: 1, eventType: 1, normalizedEventType: 1,
      eventCategory: 1, category: 1, action: 1, actionTaken: 1, blocked: 1,
    },
  });

  let scanned = 0;
  let updated = 0;
  let operations = [];

  const flush = async () => {
    if (!operations.length) return;
    const result = await Alert.collection.bulkWrite(operations, { ordered: false });
    updated += result.modifiedCount || 0;
    operations = [];
  };

  for await (const alert of cursor) {
    scanned += 1;
    const module = inferSecurityModule(alert, alert.eventCategory || alert.category);
    if (!module) continue;

    const set = {};
    if (!alert.module) set.module = module;
    if (!alert.sourceType && ['IDS', 'IPS'].includes(module)) set.sourceType = module;
    if (!Object.keys(set).length) continue;

    operations.push({ updateOne: { filter: { _id: alert._id }, update: { $set: set } } });
    if (operations.length >= BATCH_SIZE) await flush();
  }
  await flush();
  return { scanned, updated };
}

if (require.main === module) {
  backfillSecurityModules()
    .then(result => console.log(JSON.stringify(result)))
    .catch(error => {
      console.error(error);
      process.exitCode = 1;
    })
    .finally(() => mongoose.disconnect());
}

module.exports = { backfillSecurityModules };
